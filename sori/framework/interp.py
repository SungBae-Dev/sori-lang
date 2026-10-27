"""SORI IR v2 해석기 — Python Backend.

- 입력은 같은 프로세스의 컴파일러가 방금 만든 IR 뿐이다(외부 IR 파일을 신뢰된 코드로 실행하지 않는다).
- 파이썬 코드를 생성하거나 eval/exec/compile 하지 않는다. 모든 연산은 이 파일의 분기로만 수행된다.
- 속성 접근은 sori.lang.surface 의 화이트리스트만 허용한다(컴파일러 검사와 이중 방어).
- 단계 수·호출 깊이·실행 시간 상한을 둔다(무한 루프 DoS 방지). 상한 초과와 보안 위반은 catch 로 잡히지 않는다.

주의: 이 해석기는 '언어 의미론을 실행하는 백엔드'이지 OS 수준 격리가 아니다. 신뢰할 수 없는 코드를
운영 환경에서 돌리는 보안 경계로 쓰지 말 것 (docs/SECURITY.ko.md 참고).
"""
import importlib
import threading
import time

from ..lang.surface import (CLIENT_RESPONSE_SURFACE, ERROR_SURFACE, FORBIDDEN_ATTRS, HTTP_RESPONSE_SURFACE,
                            LIST_METHODS, MAP_METHODS, QUERY_SURFACE, RECORD_METHODS, REQUEST_SURFACE,
                            RESPONSE_SURFACE, ROW_SURFACE, SECRET_SURFACE, STD_METHODS, STR_METHODS,
                            TEST_CLIENT_SURFACE)
from ..lang.ir import validate
from . import core
from .core import (ErrorValue, NODEF, RecordBase, Response, Row, SafeHtml, Secret, SecurityError, SoriTypeError,
                   Query, T, type_name)


class ResourceLimit(BaseException):
    """실행 상한 초과 — BaseException 이라 사용자 try/catch 로 삼킬 수 없다."""
    code = "R300"


class _Return(BaseException):
    def __init__(self, value):
        self.value = value


class _Break(BaseException):
    pass


class _Continue(BaseException):
    pass


class Budget:
    __slots__ = ("steps", "max_steps", "deadline", "depth", "max_depth")

    def __init__(self, max_steps, seconds, max_depth):
        self.steps, self.max_steps = 0, max_steps
        self.deadline = time.monotonic() + seconds if seconds else None
        self.depth, self.max_depth = 0, max_depth


class Env:
    __slots__ = ("vars", "parent")

    def __init__(self, parent=None):
        self.vars, self.parent = {}, parent


def rt_type(t):
    """타입 IR → 런타임 타입 객체 (sori.framework.core.T)"""
    if t is None:
        return T.Any
    k = t["k"]
    if k == "Opt":
        return T.Opt(rt_type(t["of"]))
    if k == "List":
        base = T.List(rt_type(t["of"]))
    elif k == "Map":
        base = T.Map(rt_type(t["of"]))
    elif k == "Ref":
        base = T.Ref(t["name"])
    else:
        base = getattr(T, k)
    if "lo" in t:
        base = base.bounded(t["lo"], t["hi"])
    return base


class SoriFunction:
    """사용자 함수/guard — 파이썬 쪽(map, sorted 등)에서도 호출 가능하지만 실행은 해석기가 한다."""

    def __init__(self, interp, decl, kind):
        self._interp, self._decl, self._kind = interp, decl, kind
        self._params = [(p["name"], rt_type(p["type"]) if p.get("type") else None, p.get("default"))
                        for p in decl["params"]]
        self._ret = rt_type(decl["ret"]) if decl.get("ret") else None
        self.__name__ = decl["name"]

    def __call__(self, *args, **kwargs):
        return self._interp.invoke(self, args, kwargs)

    def __repr__(self):
        return f"<fn {self.__name__}>"


class SoriLambda:
    def __init__(self, interp, node, env):
        self._interp, self._node, self._env = interp, node, env
        self.__name__ = "lambda"

    def __call__(self, *args, **kwargs):
        return self._interp.invoke_lambda(self, args, kwargs)

    def __repr__(self):
        return "<lambda>"


class PyRef:
    """개발용 'use py' 객체 래퍼 — 속성 접근은 '_' 시작/금지 이름을 거부한다."""
    __slots__ = ("_obj",)

    def __init__(self, obj):
        self._obj = obj


def _unwrap(v):
    return v._obj if isinstance(v, PyRef) else v


class Interpreter:
    def __init__(self, app, ir):
        problems = validate(ir)
        if problems:  # 구조가 어긋난 IR 은 실행하지 않는다 (출처 증명은 아님)
            raise SecurityError("IR 구조 검증 실패: " + "; ".join(problems[:5]))
        self.app, self.ir = app, ir
        self.files = ir["files"]
        lim = app.config.get("limits", {})
        self.max_steps = int(lim.get("max_steps", 2_000_000))
        self.request_s = float(lim.get("request_ms", 2000)) / 1000
        self.task_s = float(lim.get("task_ms", 1000)) / 1000
        self.test_s = float(lim.get("test_ms", 30000)) / 1000
        # 한 단계 SORI 호출 ≈ 파이썬 프레임 8개 → 기본 64 (CPython 재귀 한도 1000 안쪽)
        self.max_depth = min(int(lim.get("max_depth", 64)), 100)
        self.globals = {}
        self.builtins = dict(core.BUILTINS)
        self._local = threading.local()
        self.std_types = tuple(app.std_classes())

    # ---------------------------------------------------------------- 로딩
    def load(self, test_client=None):
        if test_client is not None:
            self.builtins["client"] = test_client
        app = self.app
        for u in self.ir["uses"]:
            mod = u["module"]
            if mod.startswith("std."):
                self.globals[u["alias"]] = app.std_module(mod[4:])
            else:
                name = mod[3:]
                if name.split(".")[0] not in app.caps.python or not app.config.get("dev", {}).get("in_process_python"):
                    raise SecurityError(f"파이썬 패키지 '{name}' 를 같은 프로세스에서 쓸 권한이 없어요")
                self.globals[u["alias"]] = PyRef(importlib.import_module(name))
        with self.budget(self.max_steps, None):
            for t in self.ir["types"]:
                fields = []
                for f in t["fields"]:
                    d = self.eval(f["default"], None) if f["default"] is not None else NODEF
                    fields.append((f["name"], rt_type(f["type"]), d))
                self.globals[t["name"]] = core.record(t["name"], fields, t.get("doc"))
            for f in self.ir["functions"]:
                self.globals[f["name"]] = SoriFunction(self, f, "fn")
            for g in self.ir["guards"]:
                self.globals[g["name"]] = SoriFunction(self, g, "guard")
            for st in self.ir["init"]:
                self.exec(st, None)
        from .web import Route
        for r in self.ir["routes"]:
            specs = []
            with self.budget(self.max_steps, None):
                for p in r["params"]:
                    d = self.eval(p["default"], None) if p.get("default") is not None else NODEF
                    specs.append((p["name"], None if p["source"] == "req" else rt_type(p["type"]), d, p["source"]))
            acc = r["access"]
            access = {"public": ("public",), "bearer": ("bearer",), "deny": ("deny",)}.get(acc["kind"]) or \
                ("guard", self.guarded(self.globals[acc["guard"]]))
            route = Route(r["method"], r["path"], self.handler(r), specs, access, r.get("doc"))
            route.body_types = tuple(app.config.get("security", {}).get("body_types", ("json", "form")))
            app.router.add(route)
        for t in self.ir["tasks"]:
            app.tasks.append((t["name"], t["period_ms"] / 1000, self.body_runner(t["body"], self.task_s)))
        for t in self.ir["tests"]:
            f, l = self.where(t["at"])
            app.tests.append((t["name"], self.body_runner(t["body"], self.test_s), f, l))
        return self

    def where(self, at):
        if not at:
            return None, 0
        return (self.files[at[0]] if 0 <= at[0] < len(self.files) else None), at[1]

    # ---------------------------------------------------------------- 실행 예산
    class _BudgetCtx:
        def __init__(self, interp, b):
            self.i, self.b, self.prev = interp, b, None

        def __enter__(self):
            self.prev = getattr(self.i._local, "b", None)
            self.i._local.b = self.b

        def __exit__(self, *a):
            self.i._local.b = self.prev

    def budget(self, steps, seconds):
        return self._BudgetCtx(self, Budget(steps, seconds, self.max_depth))

    def _tick(self):
        b = getattr(self._local, "b", None)
        if b is None:
            return
        b.steps += 1
        if b.steps > b.max_steps:
            raise ResourceLimit(f"실행 단계 상한({b.max_steps})을 넘었어요 (무한 루프 방지)")
        if b.deadline is not None and (b.steps & 255) == 0 and time.monotonic() > b.deadline:
            raise ResourceLimit("실행 시간 상한을 넘었어요 ([limits] request_ms / task_ms)")

    def handler(self, route):
        body = route["body"]

        def run(**kwargs):
            outer = getattr(self._local, "b", None)
            ctx = self.budget(self.max_steps, self.request_s) if outer is None else _Null()
            with ctx:
                env = Env()
                env.vars.update(kwargs)
                try:
                    self.exec_block(body, env)
                except _Return as r:
                    return r.value
                return None
        return run

    def guarded(self, fn):
        def run(req):
            outer = getattr(self._local, "b", None)
            ctx = self.budget(self.max_steps, self.request_s) if outer is None else _Null()
            with ctx:
                return bool(fn(req))
        return run

    def body_runner(self, body, seconds):
        def run():
            with self.budget(self.max_steps, seconds):
                env = Env()
                try:
                    self.exec_block(body, env)
                except _Return:
                    pass
        return run

    # ---------------------------------------------------------------- 호출
    def _enter(self):
        b = getattr(self._local, "b", None)
        if b is not None:
            b.depth += 1
            if b.depth > b.max_depth:
                b.depth -= 1
                raise ResourceLimit(f"호출 깊이 상한({b.max_depth})을 넘었어요 (무한 재귀 방지)")
        return b

    def _bind(self, params, args, kwargs, label):
        env = Env()
        names = [p[0] for p in params]
        if len(args) > len(params):
            raise SoriTypeError(f"{label} 은(는) 인자를 {len(params)}개 받아요 ({len(args)}개 줬어요)")
        vals = dict(zip(names, args))
        for k, v in kwargs.items():
            if k not in names:
                raise SoriTypeError(f"{label} 에는 '{k}' 파라미터가 없어요")
            if k in vals:
                raise SoriTypeError(f"{label} 의 '{k}' 값이 두 번 주어졌어요")
            vals[k] = v
        for name, typ, default in params:
            if name not in vals:
                if default is None:
                    raise SoriTypeError(f"{label} 호출에 '{name}' 인자가 빠졌어요")
                vals[name] = self.eval(default, None)
            if typ is not None:
                typ.check(vals[name], name)
            env.vars[name] = vals[name]
        return env

    def invoke(self, fn, args, kwargs):
        b = self._enter()
        try:
            return self._invoke(fn, args, kwargs)
        except RecursionError:
            raise ResourceLimit("호출 깊이 상한을 넘었어요 (무한 재귀 방지)")
        finally:
            if b is not None:
                b.depth -= 1

    def _invoke(self, fn, args, kwargs):
        if True:
            env = self._bind(fn._params, args, kwargs, fn.__name__)
            try:
                self.exec_block(fn._decl["body"], env)
                result = None
            except _Return as r:
                result = r.value
            if fn._ret is not None:
                fn._ret.check(result, "반환값")
            return result

    def invoke_lambda(self, lam, args, kwargs):
        b = self._enter()
        try:
            params = [(p["name"], None, p.get("default")) for p in lam._node["params"]]
            env = self._bind(params, args, kwargs, "lambda")
            env.parent = lam._env
            return self.eval(lam._node["body"], env)
        finally:
            if b is not None:
                b.depth -= 1

    # ---------------------------------------------------------------- 문장
    def exec_block(self, body, env):
        for st in body:
            self.exec(st, env)

    def _annotate(self, exc, node):
        if not hasattr(exc, "_sori_at"):
            try:
                exc._sori_at = node.get("at")
            except AttributeError:
                pass

    def exec(self, st, env):
        self._tick()
        op = st["op"]
        try:
            if op == "expr":
                self.eval(st["x"], env)
            elif op == "let":
                v = self.eval(st["value"], env)
                if st.get("type"):
                    rt_type(st["type"]).check(v, st["name"])
                if st["scope"] == "global" or env is None:
                    self.globals[st["name"]] = v
                else:
                    env.vars[st["name"]] = v
            elif op == "assign":
                self.assign(st, env)
            elif op == "if":
                for cond, body in st["branches"]:
                    if self.truthy(self.eval(cond, env)):
                        self.exec_block(body, env)
                        break
                else:
                    if st.get("else") is not None:
                        self.exec_block(st["else"], env)
            elif op == "while":
                while self.truthy(self.eval(st["c"], env)):
                    self._tick()
                    try:
                        self.exec_block(st["body"], env)
                    except _Break:
                        break
                    except _Continue:
                        continue
            elif op == "for":
                it = self.eval(st["iter"], env)
                if isinstance(it, dict):
                    it = list(it.keys())
                elif isinstance(it, (str, list, tuple)):
                    it = list(it)
                else:
                    raise SoriTypeError(f"{type_name(it)} 은(는) 반복할 수 없어요")
                names = st["names"]
                for item in it:
                    self._tick()
                    if len(names) == 1:
                        self._set_name(names[0], item, st["scope"], env)
                    else:
                        try:
                            a, b = item
                        except (TypeError, ValueError):
                            raise SoriTypeError("두 개로 나눌 수 없는 값이에요 (for a, b in ...)")
                        self._set_name(names[0], a, st["scope"], env)
                        self._set_name(names[1], b, st["scope"], env)
                    try:
                        self.exec_block(st["body"], env)
                    except _Break:
                        break
                    except _Continue:
                        continue
            elif op == "return":
                raise _Return(self.eval(st["x"], env) if st.get("x") is not None else None)
            elif op == "break":
                raise _Break()
            elif op == "continue":
                raise _Continue()
            elif op == "pass":
                pass
            elif op == "try":
                try:
                    self.exec_block(st["body"], env)
                except Exception as e:  # SecurityError/ResourceLimit/ExpectFailed 는 BaseException 이라 여기 안 옴
                    self._set_name(st["name"], ErrorValue(e), st["scope"], env)
                    self.exec_block(st["handler"], env)
            else:
                raise SecurityError(f"알 수 없는 IR 문장 '{op}' (검증되지 않은 IR)")
        except (_Return, _Break, _Continue):
            raise
        except BaseException as e:
            self._annotate(e, st)
            raise

    def _set_name(self, name, value, scope, env):
        if scope == "global" or env is None:
            self.globals[name] = value
        else:
            env.vars[name] = value

    def _find_env(self, name, env):
        e = env
        while e is not None:
            if name in e.vars:
                return e
            e = e.parent
        return None

    def assign(self, st, env):
        t, o = st["target"], st["o"]
        value = self.eval(st["value"], env)
        if t["op"] == "var":
            name = t["name"]
            if t["scope"] == "global" or env is None:
                holder = self.globals
            else:
                e = self._find_env(name, env)
                holder = (e or env).vars
            if o != "=":
                value = self.binop(o[0], holder[name], value)
            holder[name] = value
        elif t["op"] == "index":
            obj = self.eval(t["obj"], env)
            idx = self.eval(t["index"], env)
            if not isinstance(obj, (list, dict)):
                raise SoriTypeError(f"{type_name(obj)} 에는 인덱스로 대입할 수 없어요")
            if isinstance(obj, list) and (not isinstance(idx, int) or isinstance(idx, bool)):
                raise SoriTypeError("목록 인덱스는 Int 여야 해요")
            if isinstance(obj, dict) and not isinstance(idx, str):
                raise SoriTypeError("맵 키는 Str 이어야 해요")
            if o != "=":
                value = self.binop(o[0], obj[idx], value)
            obj[idx] = value
        elif t["op"] == "field":
            obj = self.eval(t["obj"], env)
            if isinstance(obj, PyRef):
                self._py_name(t["name"])
                if o != "=":
                    value = self.binop(o[0], getattr(obj._obj, t["name"]), value)
                setattr(obj._obj, t["name"], _unwrap(value))
            elif isinstance(obj, RecordBase):
                raise SoriTypeError(f"{type(obj).__name__} 은(는) 불변이에요. x.copy({t['name']}=값) 으로 새 값을 만드세요")
            else:
                raise SoriTypeError(f"{type_name(obj)} 의 속성은 바꿀 수 없어요")
        else:
            raise SecurityError("허용되지 않는 대입 대상 (검증되지 않은 IR)")

    # ---------------------------------------------------------------- 식
    @staticmethod
    def truthy(v):
        if isinstance(v, Secret):
            return bool(v)
        return bool(_unwrap(v))

    def lookup(self, node, env):
        name, scope = node["name"], node["scope"]
        if scope == "local":
            e = self._find_env(name, env)
            if e is not None:
                return e.vars[name]
            if name in self.globals:
                return self.globals[name]
        elif scope == "global":
            if name in self.globals:
                return self.globals[name]
        elif scope == "builtin":
            if name in self.builtins:
                return self.builtins[name]
        raise SoriTypeError(f"'{name}' 이(가) 아직 정의되지 않았어요")

    def eval(self, n, env):
        op = n["op"]
        if op == "lit":
            return n["v"]
        if op == "var":
            return self.lookup(n, env)
        if op == "call":
            fn = self.eval(n["fn"], env)
            args = [self.eval(a, env) for a in n["args"]]
            kwargs = {k: self.eval(v, env) for k, v in n["kwargs"]}
            return self.call(fn, args, kwargs, n)
        if op == "field":
            return self.get_field(self.eval(n["obj"], env), n["name"])
        if op == "std":
            mod = self.eval(n["obj"], env)
            if n["name"] not in STD_METHODS.get(n["module"], {}) or not isinstance(mod, self.std_types):
                raise SecurityError("허용되지 않는 표준 모듈 접근 (검증되지 않은 IR)")
            return getattr(mod, n["name"])
        if op == "binop":
            return self.binop(n["o"], self.eval(n["l"], env), self.eval(n["r"], env))
        if op == "compare":
            left = self.eval(n["l"], env)
            for o, rn in zip(n["ops"], n["rs"]):
                right = self.eval(rn, env)
                if not self.compare(o, left, right):
                    return False
                left = right
            return True
        if op == "logic":
            left = self.eval(n["l"], env)
            if n["o"] == "and":
                return self.eval(n["r"], env) if self.truthy(left) else left
            return left if self.truthy(left) else self.eval(n["r"], env)
        if op == "not":
            return not self.truthy(self.eval(n["x"], env))
        if op == "unop":
            x = _unwrap(self.eval(n["x"], env))
            if isinstance(x, bool) or not isinstance(x, (int, float)):
                raise SoriTypeError(f"단항 {n['o']} 는 숫자에만 쓸 수 있어요 ({type_name(x)})")
            return -x if n["o"] == "-" else x
        if op == "cond":
            return self.eval(n["then"], env) if self.truthy(self.eval(n["c"], env)) else self.eval(n["orelse"], env)
        if op == "list":
            return [self.eval(x, env) for x in n["items"]]
        if op == "map":
            out = {}
            for k, v in n["pairs"]:
                key = self.eval(k, env)
                if not isinstance(key, str):
                    raise SoriTypeError("맵 키는 Str 이어야 해요")
                out[key] = self.eval(v, env)
            return out
        if op == "index":
            return self.index(self.eval(n["obj"], env), self.eval(n["index"], env))
        if op == "slice":
            obj = self.eval(n["obj"], env)
            lo = self.eval(n["lo"], env) if n.get("lo") is not None else None
            hi = self.eval(n["hi"], env) if n.get("hi") is not None else None
            if not isinstance(obj, (list, str)):
                raise SoriTypeError(f"{type_name(obj)} 은(는) 잘라낼 수 없어요")
            for b in (lo, hi):
                if b is not None and (isinstance(b, bool) or not isinstance(b, int)):
                    raise SoriTypeError("슬라이스 범위는 Int 여야 해요")
            return obj[lo:hi]
        if op == "cat":
            return core.cat(n["lits"], [self.eval(a, env) for a in n["args"]])
        if op == "sql":
            return core.sql(n["lits"], [self.eval(a, env) for a in n["args"]])
        if op == "html":
            return core.html(n["lits"], [self.eval(a, env) for a in n["args"]], n["ctx"])
        if op == "lambda":
            return SoriLambda(self, n, env)
        raise SecurityError(f"알 수 없는 IR 식 '{op}' (검증되지 않은 IR)")

    def call(self, fn, args, kwargs, node):
        self._tick()
        if isinstance(fn, PyRef):
            if not callable(fn._obj):
                raise SoriTypeError("호출할 수 없는 파이썬 값이에요")
            res = fn._obj(*[_unwrap(a) for a in args], **{k: _unwrap(v) for k, v in kwargs.items()})
            return res if isinstance(res, (bool, int, float, str, list, dict, type(None))) else PyRef(res)
        if not callable(fn):
            raise SoriTypeError(f"{type_name(fn)} 은(는) 호출할 수 없어요")
        return fn(*args, **kwargs)

    # 허용 표면 — 런타임 타입별 화이트리스트
    def get_field(self, obj, name):
        if name.startswith("_") or name in FORBIDDEN_ATTRS:
            raise SecurityError(f"속성 '{name}' 접근은 허용되지 않아요")
        if isinstance(obj, PyRef):
            return PyRef(getattr(obj._obj, name)) if not isinstance(getattr(obj._obj, name), (bool, int, float, str)) \
                else getattr(obj._obj, name)
        allowed = None
        if isinstance(obj, RecordBase):
            allowed = {f[0] for f in obj._fields} | set(RECORD_METHODS)
        elif isinstance(obj, Row):
            if name in ROW_SURFACE:
                return getattr(obj, name)
            return getattr(obj, name)  # Row.__getattr__ 가 컬럼만 허용
        elif isinstance(obj, str):
            allowed = STR_METHODS
        elif isinstance(obj, list):
            allowed = LIST_METHODS
        elif isinstance(obj, dict):
            allowed = MAP_METHODS
        elif isinstance(obj, Secret):
            allowed = SECRET_SURFACE
        elif isinstance(obj, ErrorValue):
            allowed = ERROR_SURFACE
        elif isinstance(obj, Query):
            allowed = QUERY_SURFACE
        elif isinstance(obj, Response):
            allowed = RESPONSE_SURFACE
        else:
            cname = type(obj).__name__
            allowed = {"Request": REQUEST_SURFACE, "HttpResponse": HTTP_RESPONSE_SURFACE,
                       "ClientResponse": CLIENT_RESPONSE_SURFACE, "TestClient": TEST_CLIENT_SURFACE}.get(cname)
            if allowed is None and isinstance(obj, self.std_types):
                allowed = {m for m in dir(type(obj)) if not m.startswith("_")}
        if allowed is None or name not in allowed:
            raise SoriTypeError(f"{type_name(obj)} 에는 '{name}' 이(가) 없어요")
        return getattr(obj, name)

    @staticmethod
    def _py_name(name):
        if name.startswith("_") or name in FORBIDDEN_ATTRS:
            raise SecurityError(f"속성 '{name}' 접근은 허용되지 않아요")

    @staticmethod
    def index(obj, idx):
        obj, idx = _unwrap(obj), _unwrap(idx)
        if isinstance(obj, (list, str)):
            if isinstance(idx, bool) or not isinstance(idx, int):
                raise SoriTypeError("인덱스는 Int 여야 해요")
            return obj[idx]
        if isinstance(obj, dict):
            if not isinstance(idx, str):
                raise SoriTypeError("맵 키는 Str 이어야 해요")
            return obj[idx]
        if isinstance(obj, Row):
            return obj[idx]
        if hasattr(obj, "__getitem__") and type(obj).__module__.split(".")[0] in ("numpy",):
            return obj[idx]
        raise SoriTypeError(f"{type_name(obj)} 은(는) 인덱스로 접근할 수 없어요")

    MAX_SEQ = 10_000_000

    def binop(self, o, a, b):
        a, b = _unwrap(a), _unwrap(b)
        if isinstance(a, bool) or isinstance(b, bool):
            raise SoriTypeError(f"Bool 은 숫자 연산({o})에 쓸 수 없어요")
        if o == "+":
            if isinstance(a, SafeHtml):
                return a + b
            if isinstance(a, str) and isinstance(b, str):
                return a + b
            if isinstance(a, list) and isinstance(b, list):
                return a + b
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                return a + b
            raise SoriTypeError(f"{type_name(a)} + {type_name(b)} 연산은 할 수 없어요")
        if o == "*" and ((isinstance(a, (str, list)) and isinstance(b, int)) or (isinstance(b, (str, list)) and isinstance(a, int))):
            seq, n = (a, b) if isinstance(a, (str, list)) else (b, a)
            if len(seq) * max(n, 0) > self.MAX_SEQ:
                raise ResourceLimit("반복으로 만드는 값이 너무 커요")
            return seq * n
        if not (isinstance(a, (int, float)) and isinstance(b, (int, float))):
            if hasattr(a, "__array__") or hasattr(b, "__array__"):  # 개발용 numpy 값
                return {"-": lambda: a - b, "*": lambda: a * b, "/": lambda: a / b, "//": lambda: a // b,
                        "%": lambda: a % b}[o]()
            raise SoriTypeError(f"{type_name(a)} {o} {type_name(b)} 연산은 할 수 없어요 (숫자 연산만 가능)")
        if o == "-":
            return a - b
        if o == "*":
            return a * b
        if o == "/":
            return a / b
        if o == "//":
            return a // b
        if o == "%":
            return a % b
        raise SecurityError(f"알 수 없는 연산자 '{o}'")

    @staticmethod
    def compare(o, a, b):
        a, b = _unwrap(a), _unwrap(b)
        if o == "==":
            return a == b
        if o == "!=":
            return a != b
        if o in ("in", "not in"):
            if not isinstance(b, (list, dict, str, SafeHtml, tuple)):
                raise SoriTypeError(f"'{o}' 오른쪽은 목록/맵/문자열이어야 해요")
            r = a in b
            return r if o == "in" else not r
        num = lambda x: isinstance(x, (int, float)) and not isinstance(x, bool)
        if not ((num(a) and num(b)) or (isinstance(a, str) and isinstance(b, str))):
            raise SoriTypeError(f"{type_name(a)} {o} {type_name(b)} 크기 비교는 할 수 없어요")
        return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[o]


class _Null:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False
