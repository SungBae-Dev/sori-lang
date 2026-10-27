"""SORI IR v2 실행기 — Python Backend (클로저 사전 변환 방식).

- 입력은 같은 프로세스의 컴파일러가 방금 만든 IR 뿐이다(외부 IR 파일을 신뢰된 코드로 실행하지 않는다).
- 파이썬 코드를 생성하거나 eval/exec/compile 하지 않는다. 로드 시점에 IR 노드마다 '미리 만들어 둔 파이썬
  클로저'를 골라 조립할 뿐이다 (IR → 클로저 트리). 실행할 때는 노드 dict 를 다시 읽거나 op 문자열로 분기하지 않는다.
- 속성 접근은 sori.lang.surface 의 화이트리스트만 허용한다(컴파일러 검사와 이중 방어).
- 단계 수·호출 깊이·실행 시간 상한을 둔다(무한 루프 DoS 방지). 상한 초과와 보안 위반은 catch 로 잡히지 않는다.
  '단계'는 반복문 한 바퀴와 함수/람다 호출 한 번이다 — 끝나지 않는 실행은 반드시 둘 중 하나를 거친다.
- return/break/continue 는 예외가 아니라 반환 신호(RET/BRK/CNT)로 전달한다 (정상 흐름에서 예외 비용 없음).

주의: 이 실행기는 '언어 의미론을 실행하는 백엔드'이지 OS 수준 격리가 아니다. 신뢰할 수 없는 코드를
운영 환경에서 돌리는 보안 경계로 쓰지 말 것 (docs/SECURITY.ko.md 참고).
"""
import importlib
import operator as _op
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

_monotonic = time.monotonic
MISSING = object()


# ResourceLimit 은 core 에 있다 (내장 함수 range 등도 같은 예외를 쓰도록). 이전 import 경로 호환용 재노출.
ResourceLimit = core.ResourceLimit


class _Signal:
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return self.name


RET, BRK, CNT = _Signal("RET"), _Signal("BRK"), _Signal("CNT")
CHECK_EVERY = 256  # 이 단계마다 한 번 시간 상한을 본다


class Budget:
    __slots__ = ("steps", "max_steps", "deadline", "depth", "max_depth", "next")

    def __init__(self, max_steps, seconds, max_depth):
        self.steps, self.max_steps = 0, max_steps
        self.deadline = _monotonic() + seconds if seconds else None
        self.depth, self.max_depth = 0, max_depth
        self.next = min(max_steps + 1, CHECK_EVERY)

    def check(self):
        """steps 가 next 에 닿았을 때만 불린다 (빠른 경로는 정수 비교 하나)."""
        if self.steps > self.max_steps:
            raise ResourceLimit(f"실행 단계 상한({self.max_steps})을 넘었어요 (무한 루프 방지)")
        if self.deadline is not None and _monotonic() > self.deadline:
            raise ResourceLimit("실행 시간 상한을 넘었어요 ([limits] request_ms / task_ms)")
        self.next = min(self.max_steps + 1, self.steps + CHECK_EVERY)


class _Unlimited(Budget):
    """예산 밖(파이썬 쪽에서 직접 부른 경우)의 자리표시 — 이전 동작과 같이 상한 없음."""

    def __init__(self):
        super().__init__(float("inf"), None, 10 ** 9)
        self.next = float("inf")

    def check(self):
        self.next = float("inf")


NOBUDGET = _Unlimited()


# 프레임 = [지역변수 dict, 위 프레임(람다가 만들어진 곳), 예산, 반환값]
# 리스트로 두는 이유: 호출마다 만드는 객체라서 클래스 인스턴스 생성(__init__ 호출)보다 리스트 리터럴이 5배쯤 싸다.
FV, FUP, FB, FRET = 0, 1, 2, 3


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


def _check_spec(t):
    """(빠른 통과 타입 집합 | None, T.check) — 호출 클로저 안에서 함수 호출 없이 type 비교만 하도록."""
    if t is None or (type(t) is type(T.Any) and t.lo is None):
        return None
    fast = None
    if t.lo is None:
        fast = {type(T.Int): frozenset((int,)), type(T.Float): frozenset((int, float)), type(T.Str): frozenset((str,)),
                type(T.Bool): frozenset((bool,))}.get(type(t))
    return fast, t.check


def _checker(t, label):
    """런타임 타입 검사 클로저. 범위 없는 기본 스칼라는 type() 비교 한 번으로 통과시키고 나머지는 T.check."""
    if t is None:
        return None
    if type(t) is type(T.Any) and t.lo is None:
        return None
    fast = None
    if t.lo is None:
        fast = {type(T.Int): (int,), type(T.Float): (int, float), type(T.Str): (str,),
                type(T.Bool): (bool,)}.get(type(t))
    check = t.check
    if fast is not None:
        fast = frozenset(fast)

        def chk(v):
            if type(v) not in fast:
                check(v, label)
        return chk

    def chk(v):
        check(v, label)
    return chk


class SoriFunction:
    """사용자 함수/guard — 파이썬 쪽(map, sorted 등)에서도 호출 가능하지만 실행은 해석기가 한다."""

    def __init__(self, interp, decl, kind):
        self._interp, self._decl, self._kind = interp, decl, kind
        self._params = [(p["name"], rt_type(p["type"]) if p.get("type") else None, p.get("default"))
                        for p in decl["params"]]
        self._names = tuple(p[0] for p in self._params)
        self._n = len(self._names)
        self._checks = tuple((name,) + _check_spec(t) for name, t, _ in self._params if _check_spec(t) is not None)
        self._defaults = {}
        self._ret = rt_type(decl["ret"]) if decl.get("ret") else None
        self._ret_chk = _check_spec(self._ret) if self._ret is not None else None
        self._call = None  # 로드 후 _compile 이 함수 전용 호출 클로저로 채움
        self.__name__ = decl["name"]

    def __call__(self, *args, **kwargs):
        b = getattr(self._interp._local, "b", None) or NOBUDGET
        return self._call(b, args, kwargs or None)

    def _compile(self, body_ir):
        """본문을 클로저로 바꾸고, 이 함수 전용 호출 클로저(_call)를 만든다."""
        interp = self._interp
        self._defaults = {name: interp.cexpr(d) for name, _, d in self._params if d is not None}
        # 본문이 'return 식' 한 줄이면 블록·신호를 거치지 않고 식을 바로 계산
        single = body_ir[0] if len(body_ir) == 1 and body_ir[0]["op"] == "return" else None
        if single is not None:
            expr = interp.cexpr(single["x"]) if single.get("x") is not None else (lambda fr: None)
            self._call = _make_call(self, expr, None, single.get("at"))
        else:
            self._call = _make_call(self, None, interp.cblock(body_ir), None)

    def __repr__(self):
        return f"<fn {self.__name__}>"


class SoriLambda:
    __slots__ = ("_interp", "_names", "_defaults", "_body", "_frame", "__name__")

    def __init__(self, interp, names, defaults, body, frame):
        self._interp, self._names, self._defaults, self._body, self._frame = interp, names, defaults, body, frame
        self.__name__ = "lambda"

    def __call__(self, *args, **kwargs):
        b = getattr(self._interp._local, "b", None) or NOBUDGET
        return self._call(b, args, kwargs or None)

    def _call(self, b, args, kwargs):
        b.steps += 1
        if b.steps >= b.next:
            b.check()
        b.depth += 1
        try:
            if b.depth > b.max_depth:
                raise ResourceLimit(f"호출 깊이 상한({b.max_depth})을 넘었어요 (무한 재귀 방지)")
            if not kwargs and len(args) == len(self._names):
                v = dict(zip(self._names, args))
            else:
                v = self._interp._bind_lambda(self, args, kwargs)
            # 예산은 '부른 쪽' 것을 쓴다 (만든 요청의 예산은 이미 끝났을 수 있음)
            return self._body([v, self._frame, b, None])
        except RecursionError:
            raise ResourceLimit("호출 깊이 상한을 넘었어요 (무한 재귀 방지)") from None
        finally:
            b.depth -= 1

    def __repr__(self):
        return "<lambda>"


def _make_call(fn, expr, block, at):
    """함수 하나 전용 호출 클로저. expr 가 있으면 'return 식' 한 줄짜리 본문, 아니면 block."""
    names, checks, interp = fn._names, fn._checks, fn._interp
    ret_fast, ret_check = fn._ret_chk if fn._ret_chk is not None else (None, None)
    n = len(names)
    n0 = names[0] if n > 0 else None
    n1 = names[1] if n > 1 else None
    n2 = names[2] if n > 2 else None

    def call(b, args, kwargs):
        s = b.steps = b.steps + 1
        if s >= b.next:
            b.check()
        d = b.depth = b.depth + 1
        try:
            if d > b.max_depth:
                raise ResourceLimit(f"호출 깊이 상한({b.max_depth})을 넘었어요 (무한 재귀 방지)")
            if kwargs is None and len(args) == n:
                if n == 1:
                    v = {n0: args[0]}
                elif n == 2:
                    v = {n0: args[0], n1: args[1]}
                elif n == 0:
                    v = {}
                elif n == 3:
                    v = {n0: args[0], n1: args[1], n2: args[2]}
                else:
                    v = dict(zip(names, args))
                for name, fast, check in checks:
                    x = v[name]
                    if fast is None or type(x) not in fast:
                        check(x, name)
            else:
                v = interp._bind(fn, args, kwargs)
            fr = [v, None, b, None]
            if expr is not None:
                try:
                    result = expr(fr)
                except BaseException as e:
                    _annotate(e, at)
                    raise
            else:
                result = fr[3] if block(fr) is RET else None
            if ret_check is not None and (ret_fast is None or type(result) not in ret_fast):
                ret_check(result, "반환값")
            return result
        except RecursionError:
            raise ResourceLimit("호출 깊이 상한을 넘었어요 (무한 재귀 방지)") from None
        finally:
            b.depth -= 1
    return call


class PyRef:
    """개발용 'use py' 객체 래퍼 — 속성 접근은 '_' 시작/금지 이름을 거부한다."""
    __slots__ = ("_obj",)

    def __init__(self, obj):
        self._obj = obj


def _unwrap(v):
    return v._obj if type(v) is PyRef else v


def _annotate(exc, at):
    if not hasattr(exc, "_sori_at"):
        try:
            exc._sori_at = at
        except AttributeError:
            pass


def _truthy(v):
    tv = type(v)
    if tv is bool:
        return v
    if tv is PyRef:
        return bool(v._obj)
    return bool(v)


_NUM = frozenset((int, float))
_ARITH = {"+": _op.add, "-": _op.sub, "*": _op.mul, "/": _op.truediv, "//": _op.floordiv, "%": _op.mod}
_ORDER = {"<": _op.lt, ">": _op.gt, "<=": _op.le, ">=": _op.ge}


class Interpreter:
    MAX_SEQ = core.MAX_SEQ

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
        # 한 단계 SORI 호출 ≈ 파이썬 프레임 여러 개 → 기본 64 (CPython 재귀 한도 1000 안쪽)
        self.max_depth = min(int(lim.get("max_depth", 64)), 100)
        self.globals = {}
        self.builtins = dict(core.BUILTINS)
        self._local = threading.local()
        self.std_types = tuple(app.std_classes())
        self._field_cache = {}
        self._lam = []  # 컴파일 중인 람다 파라미터 이름 스택 (지역 변수 깊이 계산용)

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
                    d = self._const(f["default"]) if f["default"] is not None else NODEF
                    fields.append((f["name"], rt_type(f["type"]), d))
                self.globals[t["name"]] = core.record(t["name"], fields, t.get("doc"))
            fns = []
            for f in self.ir["functions"]:
                fns.append(SoriFunction(self, f, "fn"))
            for g in self.ir["guards"]:
                fns.append(SoriFunction(self, g, "guard"))
            for fn in fns:
                self.globals[fn.__name__] = fn
            for fn in fns:  # 상호 재귀가 있어도 되도록 등록 후 컴파일
                fn._compile(fn._decl["body"])
            init = self.cblock(self.ir["init"])
            init(self._module_frame())
        from .web import Route
        for r in self.ir["routes"]:
            specs = []
            with self.budget(self.max_steps, None):
                for p in r["params"]:
                    d = self._const(p["default"]) if p.get("default") is not None else NODEF
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

    def _module_frame(self):
        # 모듈 수준(init·기본값)에서는 '지역 변수' 가 곧 전역이다 (env=None 이면 전역 이었던 이전 의미론과 같음)
        return [self.globals, None, getattr(self._local, "b", None) or NOBUDGET, None]

    def _const(self, node):
        return self.cexpr(node)(self._module_frame())

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
            return self.b

        def __exit__(self, *a):
            self.i._local.b = self.prev

    def budget(self, steps, seconds):
        return self._BudgetCtx(self, Budget(steps, seconds, self.max_depth))

    def handler(self, route):
        body = self.cblock(route["body"])
        local = self._local

        def run(**kwargs):
            outer = getattr(local, "b", None)
            if outer is not None:
                fr = [kwargs, None, outer, None]
                return fr[3] if body(fr) is RET else None
            b = Budget(self.max_steps, self.request_s, self.max_depth)
            local.b = b
            try:
                fr = [kwargs, None, b, None]
                return fr[3] if body(fr) is RET else None
            finally:
                local.b = None
        return run

    def guarded(self, fn):
        local = self._local

        def run(req):
            outer = getattr(local, "b", None)
            if outer is not None:
                return bool(fn._call(outer, (req,), None))
            b = Budget(self.max_steps, self.request_s, self.max_depth)
            local.b = b
            try:
                return bool(fn._call(b, (req,), None))
            finally:
                local.b = None
        return run

    def body_runner(self, body_ir, seconds):
        body = self.cblock(body_ir)

        def run():
            with self.budget(self.max_steps, seconds) as b:
                body([{}, None, b, None])
        return run

    # ---------------------------------------------------------------- 인자 바인딩 (느린 경로)
    def _bind(self, fn, args, kwargs):
        label, params = fn.__name__, fn._params
        names = fn._names
        if len(args) > len(params):
            raise SoriTypeError(f"{label} 은(는) 인자를 {len(params)}개 받아요 ({len(args)}개 줬어요)")
        vals = dict(zip(names, args))
        for k, v in (kwargs or {}).items():
            if k not in names:
                raise SoriTypeError(f"{label} 에는 '{k}' 파라미터가 없어요")
            if k in vals:
                raise SoriTypeError(f"{label} 의 '{k}' 값이 두 번 주어졌어요")
            vals[k] = v
        for name, typ, default in params:
            if name not in vals:
                if default is None:
                    raise SoriTypeError(f"{label} 호출에 '{name}' 인자가 빠졌어요")
                vals[name] = fn._defaults[name](self._module_frame())
            if typ is not None:
                typ.check(vals[name], name)
        return vals

    def _bind_lambda(self, lam, args, kwargs):
        names = lam._names
        if len(args) > len(names):
            raise SoriTypeError(f"lambda 은(는) 인자를 {len(names)}개 받아요 ({len(args)}개 줬어요)")
        vals = dict(zip(names, args))
        for k, v in (kwargs or {}).items():
            if k not in names:
                raise SoriTypeError(f"lambda 에는 '{k}' 파라미터가 없어요")
            if k in vals:
                raise SoriTypeError(f"lambda 의 '{k}' 값이 두 번 주어졌어요")
            vals[k] = v
        for name in names:
            if name not in vals:
                d = lam._defaults.get(name)
                if d is None:
                    raise SoriTypeError(f"lambda 호출에 '{name}' 인자가 빠졌어요")
                vals[name] = d(self._module_frame())
        return vals

    # ================================================================ 문장 → 클로저
    def cblock(self, body):
        """문장 목록 → 블록 클로저. 반환값: None(계속) | RET | BRK | CNT."""
        items = tuple((self.cstmt(st), st.get("at")) for st in body)
        if not items:
            return lambda fr: None
        if len(items) == 1:
            s0, at0 = items[0]

            def one(fr):
                try:
                    return s0(fr)
                except BaseException as e:
                    _annotate(e, at0)
                    raise
            return one
        if len(items) == 2:
            (s0, at0), (s1, at1) = items

            def two(fr):
                try:
                    r = s0(fr)
                except BaseException as e:
                    _annotate(e, at0)
                    raise
                if r is not None:
                    return r
                try:
                    return s1(fr)
                except BaseException as e:
                    _annotate(e, at1)
                    raise
            return two

        def block(fr):
            for s, at in items:
                try:
                    r = s(fr)
                except BaseException as e:
                    _annotate(e, at)
                    raise
                if r is not None:
                    return r
            return None
        return block

    def cstmt(self, st):
        op = st["op"]
        G = self.globals
        if op == "expr":
            x = self.cexpr(st["x"])

            def s_expr(fr):
                x(fr)
            return s_expr
        if op == "let":
            val, name = self.cexpr(st["value"]), st["name"]
            chk = _checker(rt_type(st["type"]), name) if st.get("type") else None
            if st["scope"] == "global":
                if chk is None:
                    def s_let_g(fr):
                        G[name] = val(fr)
                    return s_let_g

                def s_let_gc(fr):
                    v = val(fr)
                    chk(v)
                    G[name] = v
                return s_let_gc
            if chk is None:
                def s_let(fr):
                    fr[0][name] = val(fr)
                return s_let

            def s_letc(fr):
                v = val(fr)
                chk(v)
                fr[0][name] = v
            return s_letc
        if op == "assign":
            return self._cassign(st)
        if op == "if":
            branches = tuple((self.cexpr(c), self.cblock(b)) for c, b in st["branches"])
            orelse = self.cblock(st["else"]) if st.get("else") is not None else None
            if len(branches) == 1:
                (c0, b0), = branches

                def s_if1(fr):
                    v = c0(fr)
                    if v is True or (v is not False and _truthy(v)):
                        return b0(fr)
                    if orelse is not None:
                        return orelse(fr)
                return s_if1

            def s_if(fr):
                for c, b in branches:
                    v = c(fr)
                    if v is True or (v is not False and _truthy(v)):
                        return b(fr)
                if orelse is not None:
                    return orelse(fr)
            return s_if
        if op == "while":
            c, body = self.cexpr(st["c"]), self.cblock(st["body"])

            def s_while(fr):
                b = fr[2]
                while True:
                    v = c(fr)
                    if not (v is True or (v is not False and _truthy(v))):
                        return None
                    b.steps += 1
                    if b.steps >= b.next:
                        b.check()
                    r = body(fr)
                    if r is not None:
                        if r is BRK:
                            return None
                        if r is RET:
                            return r
            return s_while
        if op == "for":
            return self._cfor(st)
        if op == "return":
            if st.get("x") is None:
                def s_ret0(fr):
                    fr[3] = None
                    return RET
                return s_ret0
            x = self.cexpr(st["x"])

            def s_ret(fr):
                fr[3] = x(fr)
                return RET
            return s_ret
        if op == "break":
            return lambda fr: BRK
        if op == "continue":
            return lambda fr: CNT
        if op == "pass":
            return lambda fr: None
        if op == "try":
            body, handler, name = self.cblock(st["body"]), self.cblock(st["handler"]), st["name"]
            glob = st["scope"] == "global"

            def s_try(fr):
                try:
                    return body(fr)
                except Exception as e:  # SecurityError/ResourceLimit/ExpectFailed 는 BaseException 이라 여기 안 옴
                    (G if glob else fr[0])[name] = ErrorValue(e)
                    return handler(fr)
            return s_try

        def s_bad(fr):
            raise SecurityError(f"알 수 없는 IR 문장 '{op}' (검증되지 않은 IR)")
        return s_bad

    def _cfor(self, st):
        it_c, body, names = self.cexpr(st["iter"]), self.cblock(st["body"]), st["names"]
        G = self.globals
        glob = st["scope"] == "global"

        def items_of(it):
            if isinstance(it, dict):
                return list(it.keys())
            if isinstance(it, (str, list, tuple)):
                return list(it)
            raise SoriTypeError(f"{type_name(it)} 은(는) 반복할 수 없어요")

        if len(names) == 1:
            name = names[0]

            def s_for1(fr):
                b = fr[2]
                holder = G if glob else fr[0]
                for item in items_of(it_c(fr)):
                    b.steps += 1
                    if b.steps >= b.next:
                        b.check()
                    holder[name] = item
                    r = body(fr)
                    if r is not None:
                        if r is BRK:
                            return None
                        if r is RET:
                            return r
                return None
            return s_for1
        n0, n1 = names[0], names[1]

        def s_for2(fr):
            b = fr[2]
            holder = G if glob else fr[0]
            for item in items_of(it_c(fr)):
                b.steps += 1
                if b.steps >= b.next:
                    b.check()
                try:
                    x, y = item
                except (TypeError, ValueError):
                    raise SoriTypeError("두 개로 나눌 수 없는 값이에요 (for a, b in ...)") from None
                holder[n0] = x
                holder[n1] = y
                r = body(fr)
                if r is not None:
                    if r is BRK:
                        return None
                    if r is RET:
                        return r
            return None
        return s_for2

    def _cassign(self, st):
        t, o = st["target"], st["o"]
        val = self.cexpr(st["value"])
        G = self.globals
        binop = self._binop_fn(o[0]) if o != "=" else None
        top = t["op"]
        if top == "var":
            name = t["name"]
            glob = t["scope"] == "global"

            if binop is None:
                if glob:
                    def s_set_g(fr):
                        G[name] = val(fr)
                    return s_set_g

                def s_set(fr):
                    v = val(fr)
                    fv = fr[0]
                    if name in fv:
                        fv[name] = v
                    else:
                        self._holder(name, fr)[name] = v
                return s_set

            fast = self._fast_arith(o[0])
            num = _NUM
            vnode = st["value"]
            if fast is not None and vnode["op"] == "lit" and type(vnode["v"]) in num:
                c = vnode["v"]  # i += 1, total -= 1 같은 상수 갱신
                if glob:
                    def s_aug_gc(fr):
                        cur = G[name]
                        G[name] = fast(cur, c) if type(cur) in num else binop(cur, c)
                    return s_aug_gc

                def s_aug_c(fr):
                    fv = fr[0]
                    holder = fv if name in fv else self._holder(name, fr)
                    cur = holder[name]
                    holder[name] = fast(cur, c) if type(cur) in num else binop(cur, c)
                return s_aug_c

            if glob:
                def s_aug_g(fr):
                    v = val(fr)
                    cur = G[name]
                    if fast is not None and type(cur) in num and type(v) in num:
                        G[name] = fast(cur, v)
                    else:
                        G[name] = binop(cur, v)
                return s_aug_g

            def s_aug(fr):
                v = val(fr)
                holder = fr[0] if name in fr[0] else self._holder(name, fr)
                cur = holder[name]
                if fast is not None and type(cur) in num and type(v) in num:
                    holder[name] = fast(cur, v)
                else:
                    holder[name] = binop(cur, v)
            return s_aug
        if top == "index":
            obj_c, idx_c = self.cexpr(t["obj"]), self.cexpr(t["index"])

            def s_set_index(fr):
                value = val(fr)
                obj = obj_c(fr)
                idx = idx_c(fr)
                if not isinstance(obj, (list, dict)):
                    raise SoriTypeError(f"{type_name(obj)} 에는 인덱스로 대입할 수 없어요")
                if isinstance(obj, list) and (not isinstance(idx, int) or isinstance(idx, bool)):
                    raise SoriTypeError("목록 인덱스는 Int 여야 해요")
                if isinstance(obj, dict) and not isinstance(idx, str):
                    raise SoriTypeError("맵 키는 Str 이어야 해요")
                if binop is not None:
                    value = binop(obj[idx], value)
                obj[idx] = value
            return s_set_index
        if top == "field":
            obj_c, fname = self.cexpr(t["obj"]), t["name"]

            def s_set_field(fr):
                value = val(fr)
                obj = obj_c(fr)
                if isinstance(obj, PyRef):
                    self._py_name(fname)
                    if binop is not None:
                        value = binop(getattr(obj._obj, fname), value)
                    setattr(obj._obj, fname, _unwrap(value))
                elif isinstance(obj, RecordBase):
                    raise SoriTypeError(f"{type(obj).__name__} 은(는) 불변이에요. x.copy({fname}=값) 으로 새 값을 만드세요")
                else:
                    raise SoriTypeError(f"{type_name(obj)} 의 속성은 바꿀 수 없어요")
            return s_set_field

        def s_bad(fr):
            raise SecurityError("허용되지 않는 대입 대상 (검증되지 않은 IR)")
        return s_bad

    @staticmethod
    def _holder(name, fr):
        # 대입은 함수 프레임에서만 일어난다(람다 안에는 문장이 없음). 이전 의미론: 변수가 있는 프레임, 없으면 현재 프레임
        f = fr
        while f is not None:
            if name in f[0]:
                return f[0]
            f = f[1]
        return fr[0]

    # ================================================================ 식 → 클로저
    def cexpr(self, n):
        op = n["op"]
        m = getattr(self, "_e_" + op, None) if op in _EXPR_OPS else None
        if m is None:
            def e_bad(fr):
                raise SecurityError(f"알 수 없는 IR 식 '{op}' (검증되지 않은 IR)")
            return e_bad
        return m(n)

    def _e_lit(self, n):
        v = n["v"]
        return lambda fr: v

    def _e_var(self, n):
        name, scope = n["name"], n["scope"]
        G, B = self.globals, self.builtins
        undefined = f"'{name}' 이(가) 아직 정의되지 않았어요"
        if scope == "builtin":
            def e_builtin(fr):
                try:
                    return B[name]
                except KeyError:
                    raise SoriTypeError(undefined) from None
            return e_builtin
        if scope == "global":
            def e_global(fr):
                try:
                    return G[name]
                except KeyError:
                    raise SoriTypeError(undefined) from None
            return e_global

        def slow(fr):
            f = fr
            while f is not None:
                if name in f[0]:
                    return f[0][name]
                f = f[1]
            if name in G:
                return G[name]
            raise SoriTypeError(undefined)

        # 람다 중첩 깊이: 가장 안쪽 람다 파라미터부터 찾고, 없으면 함수 프레임(가장 바깥)
        depth = len(self._lam)
        for i in range(len(self._lam) - 1, -1, -1):
            if name in self._lam[i]:
                depth = len(self._lam) - 1 - i
                break
        if depth == 0:
            def e_local(fr):
                try:
                    return fr[0][name]
                except KeyError:
                    return slow(fr)
            return e_local
        if depth == 1:
            def e_local1(fr):
                try:
                    return fr[1][0][name]
                except (KeyError, TypeError):
                    return slow(fr)
            return e_local1

        def e_localn(fr):
            f = fr
            for _ in range(depth):
                f = f[1] if f is not None else None
            try:
                return f[0][name]
            except (KeyError, TypeError):
                return slow(fr)
        return e_localn

    def _e_field(self, n):
        name = n["name"]
        obj_c = self.cexpr(n["obj"])
        if name.startswith("_") or name in FORBIDDEN_ATTRS:
            def e_forbidden(fr):
                raise SecurityError(f"속성 '{name}' 접근은 허용되지 않아요")
            return e_forbidden
        get = self._get_field_checked_name
        return lambda fr: get(obj_c(fr), name)

    def _e_std(self, n):
        def e_std_value(fr):
            raise SecurityError("std 함수는 호출 위치에서만 쓸 수 있어요 (검증되지 않은 IR)")
        return e_std_value

    def _e_call(self, n):
        args = tuple(self.cexpr(a) for a in n["args"])
        kwargs = tuple((k, self.cexpr(v)) for k, v in n["kwargs"])
        fnode = n["fn"]
        call = self._do_call
        if fnode["op"] == "std":
            return self._std_call(fnode, args, kwargs)
        fn_c = self.cexpr(fnode)
        SF = SoriFunction
        if not kwargs:
            if len(args) == 0:
                def e_call0(fr):
                    f = fn_c(fr)
                    if type(f) is SF:
                        return f._call(fr[2], (), None)
                    return call(f, (), None, fr[2])
                return e_call0
            if len(args) == 1:
                a0, = args

                def e_call1(fr):
                    f = fn_c(fr)
                    x = a0(fr)
                    if type(f) is SF:
                        return f._call(fr[2], (x,), None)
                    return call(f, (x,), None, fr[2])
                return e_call1
            if len(args) == 2:
                a0, a1 = args

                def e_call2(fr):
                    f = fn_c(fr)
                    x = a0(fr)
                    y = a1(fr)
                    if type(f) is SF:
                        return f._call(fr[2], (x, y), None)
                    return call(f, (x, y), None, fr[2])
                return e_call2
            if len(args) == 3:
                a0, a1, a2 = args

                def e_call3(fr):
                    f = fn_c(fr)
                    av = (a0(fr), a1(fr), a2(fr))
                    if type(f) is SF:
                        return f._call(fr[2], av, None)
                    return call(f, av, None, fr[2])
                return e_call3

        def e_call(fr):
            f = fn_c(fr)
            av = tuple(a(fr) for a in args)
            kv = {k: v(fr) for k, v in kwargs} if kwargs else None
            return call(f, av, kv, fr[2])
        return e_call

    def _std_call(self, fnode, args, kwargs):
        mod_name, meth = fnode["module"], fnode["name"]
        obj_c = self.cexpr(fnode["obj"])
        std_types = self.std_types
        if meth not in STD_METHODS.get(mod_name, {}) or meth.startswith("_"):
            def e_bad(fr):
                raise SecurityError("허용되지 않는 표준 모듈 접근 (검증되지 않은 IR)")
            return e_bad

        def e_std(fr):
            mod = obj_c(fr)
            if not isinstance(mod, std_types):
                raise SecurityError("허용되지 않는 표준 모듈 접근 (검증되지 않은 IR)")
            f = getattr(mod, meth)
            av = [a(fr) for a in args]
            if kwargs:
                return f(*av, **{k: v(fr) for k, v in kwargs})
            return f(*av)
        return e_std

    @staticmethod
    def _do_call(f, args, kwargs, b):
        tf = type(f)
        if tf is SoriFunction or tf is SoriLambda:
            return f._call(b, args, kwargs)
        if tf is PyRef:
            if not callable(f._obj):
                raise SoriTypeError("호출할 수 없는 파이썬 값이에요")
            res = f._obj(*[_unwrap(a) for a in args], **{k: _unwrap(v) for k, v in (kwargs or {}).items()})
            return res if isinstance(res, (bool, int, float, str, list, dict, type(None))) else PyRef(res)
        if not callable(f):
            raise SoriTypeError(f"{type_name(f)} 은(는) 호출할 수 없어요")
        if kwargs:
            return f(*args, **kwargs)
        return f(*args)

    @staticmethod
    def _fast_arith(o):
        """두 피연산자가 정확히 int/float 일 때 쓰는 연산 (C 구현 operator 함수). bool 은 type 비교에서 빠진다."""
        return _ARITH.get(o)

    def _operand(self, node):
        """피연산자 접근 방식: ('c', 상수) | ('g', 전역 이름) | ('l', 지역 이름) | ('e', None) + 일반 클로저.
        전역·지역·상수는 부모 클로저 안에서 바로 읽어 호출 하나를 줄인다 (실패하면 일반 클로저로 오류 처리)."""
        op = node["op"]
        clo = self.cexpr(node)
        if op == "lit":
            return "c", node["v"], clo
        if op == "var" and node["scope"] == "global":
            return "g", node["name"], clo
        if op == "var" and node["scope"] == "local" and not any(node["name"] in ps for ps in self._lam) and not self._lam:
            return "l", node["name"], clo
        return "e", None, clo

    @staticmethod
    def _inline_fetch(kind, val, clo):
        """비교식 등에서 쓰는 피연산자 읽기. 상수는 상수 함수, 그 외는 일반 클로저 (지역·전역 읽기는 이미 빠름)."""
        if kind == "c":
            return lambda fr: val
        return clo

    def _e_binop(self, n):
        o = n["o"]
        slow = self._binop_fn(o)
        opf = self._fast_arith(o)
        num = _NUM
        lk, lv, l = self._operand(n["l"])
        rk, rv, r = self._operand(n["r"])
        G = self.globals
        if opf is None:
            return lambda fr: slow(l(fr), r(fr))
        if lk == "c":
            lk = "e"
        # ---- 왼쪽: 전역
        if lk == "g":
            if rk == "c":
                def e_gc(fr):
                    try:
                        a = G[lv]
                    except KeyError:
                        a = l(fr)
                    if type(a) in num and type(rv) in num:
                        return opf(a, rv)
                    return slow(a, rv)
                return e_gc
            if rk == "g":
                def e_gg(fr):
                    try:
                        a = G[lv]
                        b = G[rv]
                    except KeyError:
                        a, b = l(fr), r(fr)
                    if type(a) in num and type(b) in num:
                        return opf(a, b)
                    return slow(a, b)
                return e_gg
            if rk == "l":
                def e_gl(fr):
                    try:
                        a = G[lv]
                    except KeyError:
                        a = l(fr)
                    try:
                        b = fr[0][rv]
                    except KeyError:
                        b = r(fr)
                    if type(a) in num and type(b) in num:
                        return opf(a, b)
                    return slow(a, b)
                return e_gl

            def e_ge(fr):
                try:
                    a = G[lv]
                except KeyError:
                    a = l(fr)
                b = r(fr)
                if type(a) in num and type(b) in num:
                    return opf(a, b)
                return slow(a, b)
            return e_ge
        # ---- 왼쪽: 지역
        if lk == "l":
            if rk == "c":
                def e_lc(fr):
                    try:
                        a = fr[0][lv]
                    except KeyError:
                        a = l(fr)
                    if type(a) in num and type(rv) in num:
                        return opf(a, rv)
                    return slow(a, rv)
                return e_lc
            if rk == "g":
                def e_lg(fr):
                    try:
                        a = fr[0][lv]
                    except KeyError:
                        a = l(fr)
                    try:
                        b = G[rv]
                    except KeyError:
                        b = r(fr)
                    if type(a) in num and type(b) in num:
                        return opf(a, b)
                    return slow(a, b)
                return e_lg
            if rk == "l":
                def e_ll(fr):
                    v = fr[0]
                    try:
                        a = v[lv]
                        b = v[rv]
                    except KeyError:
                        a, b = l(fr), r(fr)
                    if type(a) in num and type(b) in num:
                        return opf(a, b)
                    return slow(a, b)
                return e_ll

            def e_le(fr):
                try:
                    a = fr[0][lv]
                except KeyError:
                    a = l(fr)
                b = r(fr)
                if type(a) in num and type(b) in num:
                    return opf(a, b)
                return slow(a, b)
            return e_le
        # ---- 왼쪽: 일반 식
        if rk == "c":
            def e_ec(fr):
                a = l(fr)
                if type(a) in num and type(rv) in num:
                    return opf(a, rv)
                return slow(a, rv)
            return e_ec
        if rk == "g":
            def e_eg(fr):
                a = l(fr)
                try:
                    b = G[rv]
                except KeyError:
                    b = r(fr)
                if type(a) in num and type(b) in num:
                    return opf(a, b)
                return slow(a, b)
            return e_eg
        if rk == "l":
            def e_el(fr):
                a = l(fr)
                try:
                    b = fr[0][rv]
                except KeyError:
                    b = r(fr)
                if type(a) in num and type(b) in num:
                    return opf(a, b)
                return slow(a, b)
            return e_el

        def e_ee(fr):
            a = l(fr)
            b = r(fr)
            if type(a) in num and type(b) in num:
                return opf(a, b)
            return slow(a, b)
        return e_ee

    def _binop_fn(self, o):
        max_seq = self.MAX_SEQ

        def binop(a, b):
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
            if o == "*" and ((isinstance(a, (str, list)) and isinstance(b, int)) or
                             (isinstance(b, (str, list)) and isinstance(a, int))):
                seq, k = (a, b) if isinstance(a, (str, list)) else (b, a)
                if len(seq) * max(k, 0) > max_seq:
                    raise ResourceLimit("반복으로 만드는 값이 너무 커요")
                return seq * k
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
        return binop

    # 이전 API 호환 (stdlib/테스트에서 쓸 수 있음)
    def binop(self, o, a, b):
        return self._binop_fn(o)(a, b)

    def _e_compare(self, n):
        compare = self.compare
        num = _NUM
        G = self.globals
        if len(n["ops"]) == 1:
            o = n["ops"][0]
            lk, lv, l = self._operand(n["l"])
            rk, rv, r = self._operand(n["rs"][0])
            fa = self._inline_fetch(lk, lv, l)
            fb = self._inline_fetch(rk, rv, r)
            if o in ("==", "!="):
                eq = o == "=="
                if rk == "c" and type(rv) in (int, float, str, bool, type(None)):
                    def e_eq_c(fr):
                        a = fa(fr)
                        if type(a) is PyRef:
                            return compare(o, a, rv)
                        return (a == rv) if eq else (a != rv)
                    return e_eq_c

                def e_eq(fr):
                    a = fa(fr)
                    b = fb(fr)
                    if type(a) is PyRef or type(b) is PyRef:
                        return compare(o, a, b)
                    return (a == b) if eq else (a != b)
                return e_eq
            opf = _ORDER.get(o)
            if opf is None:
                return lambda fr: compare(o, l(fr), r(fr))
            if lk in ("g", "l") and rk in ("g", "l", "c"):
                # 변수 대 변수/상수 크기 비교: 둘 다 부모 클로저 안에서 바로 읽는다
                lglob, rconst, rglob = lk == "g", rk == "c", rk == "g"

                def e_ord_vv(fr):
                    try:
                        a = G[lv] if lglob else fr[0][lv]
                    except KeyError:
                        a = l(fr)
                    if rconst:
                        b = rv
                    else:
                        try:
                            b = G[rv] if rglob else fr[0][rv]
                        except KeyError:
                            b = r(fr)
                    ta, tb = type(a), type(b)
                    if (ta in num and tb in num) or (ta is str and tb is str):
                        return opf(a, b)
                    return compare(o, a, b)
                return e_ord_vv
            if rk == "c" and type(rv) in num:
                def e_ord_c(fr):
                    a = l(fr)
                    if type(a) in num:
                        return opf(a, rv)
                    return compare(o, a, rv)
                return e_ord_c

            def e_ord(fr):
                a = l(fr)
                b = r(fr)
                ta, tb = type(a), type(b)
                if (ta in num and tb in num) or (ta is str and tb is str):
                    return opf(a, b)
                return compare(o, a, b)
            return e_ord
        l = self.cexpr(n["l"])
        pairs = tuple((o, self.cexpr(r)) for o, r in zip(n["ops"], n["rs"]))

        def e_chain(fr):
            left = l(fr)
            for o, rc in pairs:
                right = rc(fr)
                if not compare(o, left, right):
                    return False
                left = right
            return True
        return e_chain

    def _e_logic(self, n):
        l, r = self.cexpr(n["l"]), self.cexpr(n["r"])
        if n["o"] == "and":
            def e_and(fr):
                left = l(fr)
                return r(fr) if _truthy(left) else left
            return e_and

        def e_or(fr):
            left = l(fr)
            return left if _truthy(left) else r(fr)
        return e_or

    def _e_not(self, n):
        x = self.cexpr(n["x"])
        return lambda fr: not _truthy(x(fr))

    def _e_unop(self, n):
        x_c, o = self.cexpr(n["x"]), n["o"]

        def e_unop(fr):
            x = _unwrap(x_c(fr))
            if isinstance(x, bool) or not isinstance(x, (int, float)):
                raise SoriTypeError(f"단항 {o} 는 숫자에만 쓸 수 있어요 ({type_name(x)})")
            return -x if o == "-" else x
        return e_unop

    def _e_cond(self, n):
        c, a, b = self.cexpr(n["c"]), self.cexpr(n["then"]), self.cexpr(n["orelse"])

        def e_cond(fr):
            v = c(fr)
            return a(fr) if (v is True or (v is not False and _truthy(v))) else b(fr)
        return e_cond

    def _e_list(self, n):
        items = tuple(self.cexpr(x) for x in n["items"])
        return lambda fr: [i(fr) for i in items]

    def _e_map(self, n):
        pairs = tuple((self.cexpr(k), self.cexpr(v)) for k, v in n["pairs"])

        def e_map(fr):
            out = {}
            for kc, vc in pairs:
                key = kc(fr)
                if not isinstance(key, str):
                    raise SoriTypeError("맵 키는 Str 이어야 해요")
                out[key] = vc(fr)
            return out
        return e_map

    def _e_index(self, n):
        obj_c, idx_c = self.cexpr(n["obj"]), self.cexpr(n["index"])
        index = self.index

        def e_index(fr):
            obj = obj_c(fr)
            idx = idx_c(fr)
            to, ti = type(obj), type(idx)
            if (to is list and ti is int) or (to is dict and ti is str):
                return obj[idx]
            return index(obj, idx)
        return e_index

    def _e_slice(self, n):
        obj_c = self.cexpr(n["obj"])
        lo_c = self.cexpr(n["lo"]) if n.get("lo") is not None else None
        hi_c = self.cexpr(n["hi"]) if n.get("hi") is not None else None

        def e_slice(fr):
            obj = obj_c(fr)
            lo = lo_c(fr) if lo_c is not None else None
            hi = hi_c(fr) if hi_c is not None else None
            if not isinstance(obj, (list, str)):
                raise SoriTypeError(f"{type_name(obj)} 은(는) 잘라낼 수 없어요")
            for bnd in (lo, hi):
                if bnd is not None and (isinstance(bnd, bool) or not isinstance(bnd, int)):
                    raise SoriTypeError("슬라이스 범위는 Int 여야 해요")
            return obj[lo:hi]
        return e_slice

    def _e_cat(self, n):
        lits, args = n["lits"], tuple(self.cexpr(a) for a in n["args"])
        cat = core.cat
        return lambda fr: cat(lits, [a(fr) for a in args])

    def _e_sql(self, n):
        lits, args = n["lits"], tuple(self.cexpr(a) for a in n["args"])
        sql = core.sql
        return lambda fr: sql(lits, [a(fr) for a in args])

    def _e_html(self, n):
        lits, args, ctx = n["lits"], tuple(self.cexpr(a) for a in n["args"]), n["ctx"]
        html = core.html
        return lambda fr: html(lits, [a(fr) for a in args], ctx)

    def _e_lambda(self, n):
        names = tuple(p["name"] for p in n["params"])
        defaults = {p["name"]: self.cexpr(p["default"]) for p in n["params"] if p.get("default") is not None}
        self._lam.append(set(names))
        try:
            body = self.cexpr(n["body"])
        finally:
            self._lam.pop()
        return lambda fr: SoriLambda(self, names, defaults, body, fr)

    # ================================================================ 허용 표면 — 런타임 타입별 화이트리스트
    _ROW, _STD, _PY = object(), object(), object()

    def _allowed_for(self, tp):
        if issubclass(tp, PyRef):
            return self._PY
        if issubclass(tp, RecordBase):
            return frozenset(f[0] for f in tp._fields) | frozenset(RECORD_METHODS)
        if issubclass(tp, Row):
            return self._ROW
        if issubclass(tp, str):
            return frozenset(STR_METHODS)
        if issubclass(tp, list):
            return frozenset(LIST_METHODS)
        if issubclass(tp, dict):
            return frozenset(MAP_METHODS)
        if issubclass(tp, Secret):
            return frozenset(SECRET_SURFACE)
        if issubclass(tp, ErrorValue):
            return frozenset(ERROR_SURFACE)
        if issubclass(tp, Query):
            return frozenset(QUERY_SURFACE)
        if issubclass(tp, Response):
            return frozenset(RESPONSE_SURFACE)
        if issubclass(tp, self.std_types):
            # 표준 모듈은 IR 의 std 연산(호출 위치)으로만 접근한다 — 효과·권한 분석을 우회하는 경로 차단
            return self._STD
        allowed = {"Request": REQUEST_SURFACE, "HttpResponse": HTTP_RESPONSE_SURFACE,
                   "ClientResponse": CLIENT_RESPONSE_SURFACE, "TestClient": TEST_CLIENT_SURFACE}.get(tp.__name__)
        return frozenset(allowed) if allowed is not None else None

    def get_field(self, obj, name):
        if name.startswith("_") or name in FORBIDDEN_ATTRS:
            raise SecurityError(f"속성 '{name}' 접근은 허용되지 않아요")
        return self._get_field_checked_name(obj, name)

    def _get_field_checked_name(self, obj, name):
        """이름 검사(_ 시작·금지 속성)는 컴파일 시점에 끝난 경우에만 쓴다."""
        tp = type(obj)
        try:
            allowed = self._field_cache[tp]
        except KeyError:
            allowed = self._field_cache[tp] = self._allowed_for(tp)
        if allowed is self._PY:
            v = getattr(obj._obj, name)
            return v if isinstance(v, (bool, int, float, str)) else PyRef(v)
        if allowed is self._ROW:
            return getattr(obj, name)  # Row.__getattr__ 가 컬럼만 허용 (ROW_SURFACE 메서드 포함)
        if allowed is self._STD:
            raise SecurityError("표준 모듈은 값으로 다룰 수 없어요 (검증되지 않은 IR)")
        if allowed is None or name not in allowed:
            raise SoriTypeError(f"{type_name(obj)} 에는 '{name}' 이(가) 없어요")
        return getattr(obj, name)

    @staticmethod
    def _py_name(name):
        if name.startswith("_") or name in FORBIDDEN_ATTRS:
            raise SecurityError(f"속성 '{name}' 접근은 허용되지 않아요")

    @staticmethod
    def truthy(v):
        return _truthy(v)

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


_EXPR_OPS = frozenset(("lit", "var", "field", "std", "call", "binop", "compare", "logic", "not", "unop", "cond",
                       "list", "map", "index", "slice", "cat", "sql", "html", "lambda"))
