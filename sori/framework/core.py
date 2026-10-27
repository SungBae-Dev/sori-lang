"""SORI 런타임 코어: 타입, 레코드, 안전 문자열(sql/html), Secret, 내장 함수."""
import contextvars
import copy as _copy
import hmac
import html as _html
import json
import math
import re

# ---------------------------------------------------------------- 예외
class SecurityError(BaseException):
    """보안 정책 위반. BaseException 이라 SORI 의 try/catch 로 삼킬 수 없다(권한 탐지 시도 차단)."""
    code = "R200"


class ExpectFailed(BaseException):
    code = "R900"


class SoriTypeError(Exception):
    code = "R100"


class SoriInputError(Exception):
    """외부 입력(요청/JSON/AI 출력)이 선언된 타입과 맞지 않음 → HTTP 400"""
    code = "R110"


class SoriUpstreamError(Exception):
    """워커/AI 등 상류 시스템 실패 또는 선언 타입과 다른 응답 → HTTP 502"""
    code = "R500"


class SoriUserError(Exception):
    code = "R400"

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


# JSON 경계(요청 본문, 워커/AI 응답)에서는 엄격 타입: "5"→5, 1→true 같은 암묵 변환을 하지 않는다
STRICT = contextvars.ContextVar("sori_strict_json", default=False)


class _NoDefault:
    def __repr__(self):
        return "NODEF"


NODEF = _NoDefault()


# ---------------------------------------------------------------- 값 표현
class Secret:
    """비밀값. 출력·로그·JSON·문자열 보간 어디서든 *** 로 보인다. 꺼내려면 .reveal() 을 명시적으로 호출."""
    __slots__ = ("_v", "_name")

    def __init__(self, value, name="secret"):
        object.__setattr__(self, "_v", "" if value is None else str(value))
        object.__setattr__(self, "_name", name)

    def __setattr__(self, k, v):
        raise SoriTypeError("Secret 은 불변이에요")

    def reveal(self):
        return self._v

    def __str__(self):
        return "***"

    __repr__ = __str__

    def __format__(self, spec):
        return "***"

    def __eq__(self, other):  # 타이밍 공격 방지 비교
        o = other._v if isinstance(other, Secret) else other
        if not isinstance(o, str):
            return False
        return hmac.compare_digest(self._v.encode(), o.encode())

    def __hash__(self):
        return hash(("secret", self._name))

    def __bool__(self):
        return bool(self._v)

    def __reduce__(self):
        raise SecurityError("Secret 은 직렬화할 수 없어요")


class SafeHtml:
    __slots__ = ("_v",)

    def __init__(self, v):
        object.__setattr__(self, "_v", v)

    def __str__(self):
        return self._v

    def __repr__(self):
        return f"Html({self._v[:40]!r}...)" if len(self._v) > 40 else f"Html({self._v!r})"

    def __add__(self, other):
        if isinstance(other, SafeHtml):
            return SafeHtml(self._v + other._v)
        return SafeHtml(self._v + _html.escape(tostr(other), quote=True))

    def __eq__(self, other):
        return isinstance(other, SafeHtml) and other._v == self._v

    def __hash__(self):
        return hash(self._v)

    def __len__(self):
        return len(self._v)

    def __contains__(self, x):
        return str(x) in self._v


class Query:
    """sql"..." 리터럴만 만들 수 있는 파라미터화 쿼리. 문자열 조합으로는 절대 생성되지 않는다."""
    __slots__ = ("text", "params")

    def __init__(self, text, params):
        object.__setattr__(self, "text", text)
        object.__setattr__(self, "params", tuple(params))

    def __setattr__(self, k, v):
        raise SoriTypeError("Query 는 불변이에요")

    def __str__(self):
        return self.text

    def __repr__(self):
        return f"Query({self.text!r}, {len(self.params)} params)"


class Row:
    """DB 결과 행: 읽기 전용, 속성/인덱스 접근."""
    __slots__ = ("_d",)

    def __init__(self, d):
        object.__setattr__(self, "_d", dict(d))

    def __getattr__(self, k):
        d = object.__getattribute__(self, "_d")
        if k in d:
            return d[k]
        raise SoriTypeError(f"행에 '{k}' 컬럼이 없어요 (있는 컬럼: {', '.join(d)})")

    def __setattr__(self, k, v):
        raise SoriTypeError("DB 행은 읽기 전용이에요")

    def __getitem__(self, k):
        return self._d[k]

    def get(self, k, default=None):
        return self._d.get(k, default)

    def keys(self):
        return list(self._d)

    def to_json(self):
        return dict(self._d)

    def __repr__(self):
        return "Row(" + ", ".join(f"{k}={fmt(v, True)}" for k, v in self._d.items()) + ")"

    def __eq__(self, o):
        return isinstance(o, Row) and o._d == self._d


# ---------------------------------------------------------------- 문자열화
def fmt(v, nested=False):
    if v is None:
        return "none"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False) if nested else v
    if isinstance(v, float):
        if v.is_integer() and abs(v) < 1e16:
            return f"{v:.1f}"
        return repr(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(fmt(x, True) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{fmt(k, True)}: {fmt(x, True)}" for k, x in v.items()) + "}"
    return str(v)


def tostr(v):
    return fmt(v, False)


def cat(lits, exprs):
    out = [lits[0]]
    for e, lit in zip(exprs, lits[1:]):
        out.append(tostr(e))
        out.append(lit)
    return "".join(out)


def _sql_param(v):
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, Secret):
        return v.reveal()
    if isinstance(v, SafeHtml):
        return str(v)
    if v is None or isinstance(v, (int, float, str, bytes)):
        return v
    raise SoriTypeError(f"SQL 파라미터로 {type_name(v)} 을(를) 쓸 수 없어요")


def sql(lits, exprs):
    text, params = [lits[0]], []
    for e, lit in zip(exprs, lits[1:]):
        if isinstance(e, (list, tuple)):  # IN ({ids}) → IN (?, ?, ?)
            if not e:
                text.append("NULL")
            else:
                text.append(", ".join("?" * len(e)))
                params.extend(_sql_param(x) for x in e)
        else:
            text.append("?")
            params.append(_sql_param(e))
        text.append(lit)
    return Query("".join(text), params)


_SAFE_SCHEMES = {"http", "https", "mailto", "tel"}


def sanitize_url(s):
    t = re.sub(r"[\x00-\x20\x7f]", "", s)
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):", t)
    if m and m.group(1).lower() not in _SAFE_SCHEMES:
        return "#blocked-unsafe-url"
    return s


def _render_html(v, ctx):
    if isinstance(v, SafeHtml):
        return v._v if ctx == "text" else _html.escape(v._v, quote=True)
    if isinstance(v, (list, tuple)) and ctx == "text":
        return "".join(_render_html(x, "text") for x in v)
    s = tostr(v)
    if ctx == "url":
        s = sanitize_url(s)
    return _html.escape(s, quote=True)


def html(lits, exprs, ctxs):
    out = [lits[0]]
    for e, c, lit in zip(exprs, ctxs, lits[1:]):
        out.append(_render_html(e, c))
        out.append(lit)
    return SafeHtml("".join(out))


def unsafe_html(s):
    return SafeHtml(tostr(s))


# ---------------------------------------------------------------- 타입
TYPES = {}  # 레코드 레지스트리


def type_name(v):
    if v is None:
        return "none"
    if isinstance(v, bool):
        return "Bool"
    if isinstance(v, int):
        return "Int"
    if isinstance(v, float):
        return "Float"
    if isinstance(v, str):
        return "Str"
    if isinstance(v, list):
        return "List"
    if isinstance(v, dict):
        return "Map"
    if isinstance(v, SafeHtml):
        return "Html"
    if isinstance(v, Secret):
        return "Secret"
    if isinstance(v, RecordBase):
        return type(v).__name__
    if isinstance(v, Row):
        return "Row"
    if callable(v):
        return "Fn"
    return "Py:" + type(v).__name__


def _short(v):
    s = fmt(v, True)
    return s if len(s) <= 40 else s[:37] + "..."


def _num(x):
    return str(int(x)) if isinstance(x, float) and x.is_integer() else str(x)


class _T:
    name = "?"
    MAX_STR = 1_000_000
    lo = hi = None
    unit = "value"  # value | length | count

    def bounded(self, lo, hi):
        t = _copy.copy(self)
        t.lo, t.hi = lo, hi
        t.name = f"{self.name}({_num(lo)}, {_num(hi)})"
        return t

    def _measure(self, v):
        return v

    def _bound(self, v, label, exc):
        if self.lo is None:
            return
        m = self._measure(v)
        if not (self.lo <= m <= self.hi):
            if self.unit == "length":
                raise exc(f"'{label}' 길이는 {_num(self.lo)}~{_num(self.hi)}자여야 해요 (현재 {m}자)")
            if self.unit == "count":
                raise exc(f"'{label}' 개수는 {_num(self.lo)}~{_num(self.hi)}개여야 해요 (현재 {m}개)")
            raise exc(f"'{label}' 값은 {_num(self.lo)}~{_num(self.hi)} 범위여야 해요")

    def _schema_bounds(self, s):
        if self.lo is not None:
            keys = {"length": ("minLength", "maxLength"), "count": ("minItems", "maxItems")}.get(self.unit, ("minimum", "maximum"))
            s[keys[0]], s[keys[1]] = self.lo, self.hi
        return s

    def check(self, v, label):
        if not self.ok(v):
            raise SoriTypeError(f"'{label}' 은(는) {self.name} 이어야 하는데 {type_name(v)} {_short(v)} 이에요")
        self._bound(v, label, SoriTypeError)
        return v

    def ok(self, v):
        return True

    def coerce(self, v, label):
        v = self._coerce(v, label)
        if v is not None:
            self._bound(v, label, SoriInputError)
        return v

    def _coerce(self, v, label):
        if self.ok(v):
            return v
        raise SoriInputError(f"'{label}' 은(는) {self.name} 이어야 해요")

    def schema(self):
        return {}

    def __repr__(self):
        return self.name


class _Int(_T):
    name = "Int"

    def ok(self, v):
        return isinstance(v, int) and not isinstance(v, bool)

    def _coerce(self, v, label):
        if isinstance(v, str) and not STRICT.get() and re.fullmatch(r"-?\d{1,18}", v.strip()):
            return int(v.strip())
        if self.ok(v) and abs(v) < 10 ** 18:
            return v
        raise SoriInputError(f"'{label}' 은(는) 정수(Int)여야 해요")

    def schema(self):
        return self._schema_bounds({"type": "integer"})


class _Float(_T):
    name = "Float"

    def ok(self, v):
        return isinstance(v, (int, float)) and not isinstance(v, bool)

    def _coerce(self, v, label):
        try:
            if isinstance(v, str):
                if STRICT.get():
                    raise ValueError
                v = float(v.strip())
            if self.ok(v) and math.isfinite(v):
                return float(v)
        except ValueError:
            pass
        raise SoriInputError(f"'{label}' 은(는) 숫자(Float)여야 해요")

    def schema(self):
        return self._schema_bounds({"type": "number"})


class _Str(_T):
    name = "Str"
    unit = "length"

    def _measure(self, v):
        return len(v)

    def ok(self, v):
        return isinstance(v, str)

    def _coerce(self, v, label):
        if isinstance(v, str):
            if len(v) > self.MAX_STR:
                raise SoriInputError(f"'{label}' 문자열이 너무 길어요")
            return v
        raise SoriInputError(f"'{label}' 은(는) 문자열(Str)이어야 해요")

    def schema(self):
        return self._schema_bounds({"type": "string"})


class _Bool(_T):
    name = "Bool"

    def ok(self, v):
        return isinstance(v, bool)

    def _coerce(self, v, label):
        if isinstance(v, bool):
            return v
        if STRICT.get():
            raise SoriInputError(f"'{label}' 은(는) true/false 여야 해요")
        if isinstance(v, int) and v in (0, 1):
            return bool(v)
        if isinstance(v, str) and v.lower() in ("true", "false", "1", "0", "on", "off"):
            return v.lower() in ("true", "1", "on")
        raise SoriInputError(f"'{label}' 은(는) true/false 여야 해요")

    def schema(self):
        return {"type": "boolean"}


class _Json(_T):
    name = "Json"

    def ok(self, v):
        return v is None or isinstance(v, (bool, int, float, str, list, dict))

    def schema(self):
        return {}


class _Any(_T):
    name = "Any"


class _Html(_T):
    name = "Html"

    def ok(self, v):
        return isinstance(v, SafeHtml)

    def _coerce(self, v, label):
        raise SoriInputError(f"'{label}': 외부 입력은 Html 이 될 수 없어요")


class _Secret(_T):
    name = "Secret"
    unit = "length"

    def _measure(self, v):
        return len(v.reveal())

    def ok(self, v):
        return isinstance(v, Secret)

    def _coerce(self, v, label):
        if isinstance(v, Secret):
            return v
        if isinstance(v, str):
            return Secret(v, label)
        raise SoriInputError(f"'{label}' 은(는) 문자열이어야 해요")

    def schema(self):
        return self._schema_bounds({"type": "string", "format": "password"})


class List(_T):
    MAX = 10_000
    unit = "count"

    def _measure(self, v):
        return len(v)

    def __init__(self, item):
        self.item = item
        self.name = f"List[{item!r}]"

    def check(self, v, label):
        if not isinstance(v, list):
            raise SoriTypeError(f"'{label}' 은(는) {self.name} 이어야 하는데 {type_name(v)} 이에요")
        for i, x in enumerate(v):
            self.item.check(x, f"{label}[{i}]")
        self._bound(v, label, SoriTypeError)
        return v

    def ok(self, v):
        return isinstance(v, list)

    def _coerce(self, v, label):
        if not isinstance(v, list):
            raise SoriInputError(f"'{label}' 은(는) 목록이어야 해요")
        if len(v) > self.MAX:
            raise SoriInputError(f"'{label}' 목록이 너무 길어요 (최대 {self.MAX}개)")
        return [self.item.coerce(x, f"{label}[{i}]") for i, x in enumerate(v)]

    def schema(self):
        return self._schema_bounds({"type": "array", "items": self.item.schema(), "maxItems": self.MAX})


class Map(_T):
    MAX = 10_000

    def __init__(self, value):
        self.value = value
        self.name = f"Map[{value!r}]"

    def check(self, v, label):
        if not isinstance(v, dict):
            raise SoriTypeError(f"'{label}' 은(는) {self.name} 이어야 하는데 {type_name(v)} 이에요")
        for k, x in v.items():
            if not isinstance(k, str):
                raise SoriTypeError(f"'{label}' 의 키는 Str 이어야 해요")
            self.value.check(x, f"{label}.{k}")
        return v

    def _coerce(self, v, label):
        if not isinstance(v, dict) or len(v) > self.MAX:
            raise SoriInputError(f"'{label}' 은(는) 맵이어야 해요")
        return {k: self.value.coerce(x, f"{label}.{k}") for k, x in v.items()}

    def schema(self):
        return {"type": "object", "additionalProperties": self.value.schema()}


class Opt(_T):
    def __init__(self, inner):
        self.inner = inner
        self.name = f"{inner!r}?"

    def check(self, v, label):
        return None if v is None else self.inner.check(v, label)

    def _coerce(self, v, label):
        return None if v is None or v == "" else self.inner.coerce(v, label)

    def schema(self):
        s = dict(self.inner.schema())
        s["nullable"] = True
        return s


class Ref(_T):
    def __init__(self, name):
        self.ref = name
        self.name = name

    @property
    def cls(self):
        return TYPES[self.ref]

    def check(self, v, label):
        if not isinstance(v, self.cls):
            raise SoriTypeError(f"'{label}' 은(는) {self.ref} 이어야 하는데 {type_name(v)} 이에요")
        return v

    def _coerce(self, v, label):
        if isinstance(v, self.cls):
            return v
        return self.cls.parse(v, label)

    def schema(self):
        return self.cls.schema()


class T:
    Int, Float, Str, Bool = _Int(), _Float(), _Str(), _Bool()
    Json, Any, Html, Secret = _Json(), _Any(), _Html(), _Secret()
    List, Map, Opt, Ref = List, Map, Opt, Ref


# ---------------------------------------------------------------- 레코드
RESERVED_FIELDS = {"copy", "to_json", "parse", "schema", "fields"}


class RecordBase:
    __slots__ = ()
    _fields = ()
    _doc = None

    def __init__(self, *args, **kw):
        cls = type(self)
        names = [f[0] for f in cls._fields]
        if len(args) > len(names):
            raise SoriTypeError(f"{cls.__name__} 은(는) 필드가 {len(names)}개인데 값이 {len(args)}개예요")
        values = dict(zip(names, args))
        for k, v in kw.items():
            if k not in names:
                raise SoriTypeError(f"{cls.__name__} 에는 '{k}' 필드가 없어요 (필드: {', '.join(names)})")
            if k in values:
                raise SoriTypeError(f"'{k}' 값이 두 번 주어졌어요")
            values[k] = v
        for name, t, d in cls._fields:
            if name not in values:
                if d is NODEF:
                    raise SoriTypeError(f"{cls.__name__} 을(를) 만들려면 '{name}' 이(가) 필요해요")
                values[name] = _copy.deepcopy(d)
            object.__setattr__(self, name, t.check(values[name], f"{cls.__name__}.{name}"))

    def __setattr__(self, k, v):
        raise SoriTypeError(f"{type(self).__name__} 은(는) 불변이에요. x.copy({k}=값) 으로 새 값을 만드세요")

    def copy(self, **kw):
        d = {f[0]: getattr(self, f[0]) for f in self._fields}
        d.update(kw)
        return type(self)(**d)

    def to_json(self):
        return {f[0]: getattr(self, f[0]) for f in self._fields}

    def __eq__(self, o):
        return type(o) is type(self) and o.to_json() == self.to_json()

    def __hash__(self):
        return hash((type(self).__name__, tuple(fmt(v, True) for v in self.to_json().values())))

    def __repr__(self):
        return f"{type(self).__name__}(" + ", ".join(f"{k}={fmt(v, True)}" for k, v in self.to_json().items()) + ")"

    @classmethod
    def parse(cls, data, label=None):
        """외부 입력 → 레코드. 선언되지 않은 필드는 거부(mass assignment 차단)."""
        label = label or cls.__name__
        if isinstance(data, Row):
            data = data.to_json()
        if not isinstance(data, dict):
            raise SoriInputError(f"'{label}' 은(는) {cls.__name__} 객체여야 해요")
        names = {f[0] for f in cls._fields}
        extra = [k for k in data if k not in names]
        if extra:
            raise SoriInputError(f"{cls.__name__} 에 없는 필드는 받을 수 없어요: {', '.join(map(str, extra[:5]))}")
        vals = {}
        for name, t, d in cls._fields:
            if name in data:
                vals[name] = t.coerce(data[name], f"{label}.{name}")
            elif d is NODEF and not isinstance(t, Opt):
                raise SoriInputError(f"'{label}.{name}' 이(가) 필요해요")
        return cls(**vals)

    @classmethod
    def schema(cls):
        props, req = {}, []
        for name, t, d in cls._fields:
            props[name] = t.schema()
            if d is NODEF and not isinstance(t, Opt):
                req.append(name)
        s = {"type": "object", "properties": props, "required": req, "additionalProperties": False}
        if cls._doc:
            s["description"] = cls._doc
        return s


def record(name, fields, doc=None):
    for f in fields:
        if f[0] in RESERVED_FIELDS:
            raise SoriTypeError(f"필드 이름 '{f[0]}' 은(는) 예약돼 있어요")
    cls = type(name, (RecordBase,), {"__slots__": tuple(f[0] for f in fields), "_fields": tuple(fields), "_doc": doc})
    TYPES[name] = cls
    return cls


def check(v, t, label):
    return t.check(v, label)


# ---------------------------------------------------------------- 안전 JSON
def json_loads(text, max_depth=32):
    def hook(pairs):
        seen = {}
        for k, v in pairs:
            if k in seen:
                raise SoriInputError(f"JSON 에 중복 키 '{k}' 가 있어요 (해석 충돌 공격 방지)")
            seen[k] = v
        return seen

    def bad_const(c):
        raise SoriInputError(f"JSON 에 {c} 는 허용되지 않아요")

    try:
        obj = json.loads(text, object_pairs_hook=hook, parse_constant=bad_const)
    except SoriInputError:
        raise
    except (ValueError, RecursionError) as e:
        raise SoriInputError(f"잘못된 JSON: {str(e)[:80]}")
    stack = [(obj, 1)]
    while stack:
        o, d = stack.pop()
        if d > max_depth:
            raise SoriInputError(f"JSON 중첩이 너무 깊어요 (최대 {max_depth})")
        if isinstance(o, dict):
            stack.extend((v, d + 1) for v in o.values())
        elif isinstance(o, list):
            stack.extend((v, d + 1) for v in o)
    return obj


def _json_default(o):
    if isinstance(o, (RecordBase, Row)):
        return o.to_json()
    if isinstance(o, Secret):
        return "***"
    if isinstance(o, SafeHtml):
        return str(o)
    if isinstance(o, tuple):
        return list(o)
    if hasattr(o, "tolist"):  # numpy 배열/스칼라
        return o.tolist()
    raise SoriTypeError(f"{type_name(o)} 은(는) JSON 으로 바꿀 수 없어요")


def json_dumps(o, pretty=False):
    return json.dumps(o, ensure_ascii=False, default=_json_default, indent=2 if pretty else None,
                      separators=None if pretty else (",", ":"))


# ---------------------------------------------------------------- 오류 값 (catch 변수)
class ErrorValue:
    __slots__ = ("message", "code", "kind")

    def __init__(self, exc):
        object.__setattr__(self, "message", str(exc) or type(exc).__name__)
        object.__setattr__(self, "code", getattr(exc, "code", "R000"))
        object.__setattr__(self, "kind", type(exc).__name__)

    def __setattr__(self, k, v):
        raise SoriTypeError("오류 값은 불변이에요")

    def __str__(self):
        return self.message

    __repr__ = __str__


def err(exc):
    return ErrorValue(exc)


# ---------------------------------------------------------------- 응답
class Response:
    __slots__ = ("status", "body", "headers", "content_type")

    def __init__(self, status=200, body=None, headers=None, content_type=None):
        self.status, self.body, self.headers, self.content_type = int(status), body, dict(headers or {}), content_type

    def __repr__(self):
        return f"Response({self.status})"


def respond(status, body=None, headers=None, content_type=None):
    if not (100 <= int(status) <= 599):
        raise SoriTypeError("HTTP 상태 코드는 100~599 여야 해요")
    for k, v in (headers or {}).items():
        if re.search(r"[\r\n]", str(k) + str(v)):
            raise SecurityError("헤더에 줄바꿈 문자가 있어요 (CRLF 인젝션 차단)")
    return Response(status, body, headers, content_type)


def redirect(url, status=303, external=False):
    url = tostr(url)
    if not external and (not url.startswith("/") or url.startswith("//") or url.startswith("/\\")):
        raise SecurityError(f"외부 주소로의 리다이렉트는 external=true 가 필요해요: {url[:60]} (오픈 리다이렉트 차단)")
    if re.search(r"[\r\n]", url):
        raise SecurityError("리다이렉트 주소에 줄바꿈 문자가 있어요")
    return Response(status, None, {"Location": url})


def error(message, status=400):
    raise SoriUserError(tostr(message), int(status))


def expect(cond, message=""):
    if not cond:
        raise ExpectFailed(tostr(message) or "expect 실패")


# ---------------------------------------------------------------- 내장 함수
def _int(v):
    if isinstance(v, str):
        return _Int().coerce(v, "int()")
    if isinstance(v, float):
        return int(v)
    return int(v)


def _map(a, b):
    if callable(a) and not callable(b):
        a, b = b, a
    return [b(x) for x in a]


def _filter(a, b):
    if callable(a) and not callable(b):
        a, b = b, a
    return [x for x in a if b(x)]


def _print(*args):
    print(" ".join(tostr(a) for a in args), flush=True)


def _sorted(xs, key=None, reverse=False):
    return sorted(xs, key=key, reverse=reverse)


BUILTINS = {
    "print": _print, "len": len, "str": tostr, "int": _int, "float": float, "bool": bool,
    "range": lambda *a: list(range(*a)), "list": list, "sorted": _sorted, "reversed": lambda xs: list(reversed(xs)),
    "sum": sum, "min": min, "max": max, "abs": abs, "round": round,
    "enumerate": lambda xs, start=0: list(enumerate(xs, start)), "zip": lambda *a: list(zip(*a)),
    "any": any, "all": all, "map": _map, "filter": _filter, "type_of": type_name,
    "respond": respond, "redirect": redirect, "unsafe_html": unsafe_html, "error": error, "expect": expect,
}



