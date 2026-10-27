"""SORI 통합 컴파일러: 파싱 → 정적 검사(스코프·불변성·타입·권한·Effect·라우트 정책·HTML 문맥) → Typed IR v2.

출력은 실행 불가능한 JSON 데이터(IR)이며 파이썬 코드를 생성하지 않는다.
IR 은 Python Backend(sori.framework.interp) 와 Rust Backend(runtime-rs) 가 같은 의미론으로 실행한다.
"""
import hashlib
import re

from . import types as ty
from .diagnostics import SoriError, did_you_mean
from .parser import parse
from .surface import (BUILTIN_RET, CLIENT_RESPONSE_SURFACE, ERROR_SURFACE, FORBIDDEN_ATTRS,
                      HTTP_RESPONSE_SURFACE, LIST_METHODS, MAP_METHODS, QUERY_SURFACE, RECORD_METHODS,
                      REQUEST_SURFACE, RESPONSE_SURFACE, ROW_SURFACE, SECRET_SURFACE, STD_EFFECTS, STD_METHODS,
                      STR_METHODS, TEST_CLIENT_SURFACE)
from ..framework.policy import worker_problems
from .ir import IR_VERSION

BUILTIN_TYPES = {"Int": 0, "Float": 0, "Str": 0, "Bool": 0, "Json": 0, "Html": 0, "Secret": 0, "Any": 0,
                 "List": 1, "Map": (1, 2)}
BOUNDABLE = {"Str", "Int", "Float", "List", "Secret"}
INPUT_SCALARS = {"Str", "Int", "Float", "List", "Secret"}
STD_MODULES = set(STD_METHODS)
STD_NEEDS = {
    "db": ("db", "[permissions] db = [\"sqlite:./data/app.db\"]"),
    "http": ("net", "[permissions] net = [\"api.example.com\"]"),
    "fs": ("fs", "[permissions] fs_read = [\"./data\"] 또는 fs_write = [\"./data\"]"),
    "env": ("env", "[permissions] env = [\"API_KEY\"]"),
    "ai": ("ai", "[permissions] net = [\"api.anthropic.com\"]"),
    "worker": ("worker", "[workers.이름] url = \"http://127.0.0.1:9010/invoke\""),
}
BUILTINS = set(BUILTIN_RET)
URL_ATTRS = {"href", "src", "action", "formaction", "poster", "cite", "background", "xlink:href", "data"}
PATH_PARAM = re.compile(r"\{([^/{}]+)\}")
MAX_LITERAL = 10 ** 12  # B1 규칙 계승: ±1e12 밖 숫자 상수 거부


class Scope:
    def __init__(self, parent=None, kind="fn"):
        self.names, self.parent, self.kind = {}, parent, kind  # name -> (kind, static_type)

    def lookup(self, name):
        s = self
        while s:
            if name in s.names:
                return s.names[name], s
            s = s.parent
        return None, None

    def all_names(self):
        out, s = set(), self
        while s:
            out |= set(s.names)
            s = s.parent
        return out


class Ctx:
    def __init__(self, in_fn=False, ret=None, kind="module"):
        self.in_fn, self.ret, self.loop, self.kind = in_fn, ret, 0, kind
        self.effects, self.calls, self.returns = set(), set(), []
        self.dynamic = False  # 정적으로 대상을 알 수 없는 호출(함수값·람다·Dyn)이 있는가


class Project:
    """여러 .sori 파일이 하나의 네임스페이스(Go 패키지처럼)를 공유한다."""

    def __init__(self, files, config):
        self.files = files  # {path: src}
        self.file_index = {p: i for i, p in enumerate(files)}
        self.config = config
        self.perms = config.get("permissions", {})
        self.workers = config.get("workers", {})
        sec = config.get("security", {})
        self.strict_inputs = bool(sec.get("strict_inputs", True))  # v0.3 기본값: 켜짐
        self.dev_py = bool(config.get("dev", {}).get("in_process_python", False))
        self.uses_bearer = False
        self.diags = []
        self.symbols = {}  # name -> (kind, file, line)
        self.types, self.fns, self.guards, self.globals_t = {}, {}, {}, {}
        self.routes, self.tasks, self.tests = [], [], []
        self.uses = []
        self.ir = {"types": [], "functions": [], "guards": [], "init": [], "routes": [], "tasks": [], "tests": [],
                   "uses": []}
        self.fn_effects, self.fn_calls, self.fn_dynamic = {}, {}, {}
        # 값으로 빠져나간 호출 가능 객체: 함수 이름(호출 위치가 아닌 곳에서 참조됨)과 람다 본문
        self.escaped_fns, self.lambda_pool = set(), []

    def error(self, code, msg, file, line, col, hint=None, length=1, severity="error"):
        self.diags.append(SoriError(code, msg, file, line, col, hint, severity, length))

    def warn(self, code, msg, file, line, col, hint=None, length=1):
        self.error(code, msg, file, line, col, hint, length, "warning")

    def build(self):
        progs = {}
        for wname, wcfg in self.workers.items():
            for msg in worker_problems(wname, wcfg):
                self.error("E203", msg, "sori.toml", 0, 0, "워커는 같은 파드 안 사이드카로 두고 루프백으로만 호출해요")
        for path, src in self.files.items():
            try:
                progs[path] = parse(src, path)
            except SoriError as e:
                self.diags.append(e)
        for path, prog in progs.items():
            for st in prog:
                self._collect(st, path)
        for path, prog in progs.items():
            for st in prog:
                self._pretype(st)
        for path, prog in progs.items():
            FileCompiler(self, path, prog).compile()
        self._finish_effects()
        self._check_routes()
        return self

    def _declare(self, name, kind, file, line, col):
        if name.startswith("_"):
            self.error("E105", f"이름 '{name}' 은(는) '_' 로 시작할 수 없어요", file, line, col, "내부 런타임 이름과 구분하기 위한 규칙이에요")
            return
        if name in self.symbols:
            k, f, l = self.symbols[name]
            self.error("E103", f"'{name}' 이(가) 이미 선언되어 있어요 ({f}:{l})", file, line, col, length=len(name))
            return
        self.symbols[name] = (kind, file, line)

    def _collect(self, st, path):
        k = st.kind
        if k == "TypeDecl":
            self._declare(st.name, "type", path, st.line, st.ncol)
            self.types[st.name] = st
        elif k == "FnDecl":
            self._declare(st.name, "fn", path, st.line, st.ncol)
            self.fns[st.name] = st
        elif k == "GuardDecl":
            self._declare(st.name, "guard", path, st.line, st.ncol)
            self.guards[st.name] = st
        elif k in ("Let", "Var"):
            self._declare(st.name, "let" if k == "Let" else "var", path, st.line, st.ncol)
        elif k == "If":
            for _, body in st.branches:
                for s in body:
                    self._collect(s, path)
            for s in st.orelse or []:
                self._collect(s, path)
        elif k in ("For", "While", "Try"):
            for s in st.body:
                self._collect(s, path)
            for s in getattr(st, "handler", []) or []:
                self._collect(s, path)

    def _pretype(self, st):
        """최상위 let/var 의 정적 타입을 미리 정해 둔다 (함수가 앞에서 참조할 수 있도록)."""
        if st.kind in ("Let", "Var"):
            if st.typ is not None:
                self.globals_t[st.name] = static_of(st.typ, self)
            else:
                self.globals_t[st.name] = literal_type(st.value)

    def _finish_effects(self):
        """효과를 호출 그래프로 전이한다 (fixpoint).

        건전성(soundness) 규칙 — 효과를 놓치느니 과하게 잡는다:
        - 직접 호출 f(x) 와 Fn 타입 별칭 호출은 f 로 가는 간선.
        - 함수가 호출 위치가 아닌 곳에서 참조되면(값으로 저장·전달) '빠져나간 함수' 가 된다.
        - 람다 본문의 효과는 람다를 만든 곳에 더하고, 람다 풀에도 등록한다.
        - 대상을 정적으로 알 수 없는 호출(함수값·람다·Dyn·인덱스 결과 호출)은
          빠져나간 모든 함수와 모든 람다의 효과를 받는다 (POOL).
        - std 모듈 함수/모듈 자체는 값으로 쓸 수 없다 (E110) — 별칭으로 효과를 숨길 수 없다.
        """
        pool = set()
        changed = True
        while changed:
            changed = False
            for name, calls in self.fn_calls.items():
                eff = self.fn_effects.setdefault(name, set())
                add = set()
                for c in calls:
                    add |= self.fn_effects.get(c, set())
                if self.fn_dynamic.get(name):
                    add |= pool
                if add - eff:
                    eff |= add
                    changed = True
            new_pool = set()
            for name in self.escaped_fns:
                new_pool |= self.fn_effects.get(name, set())
            for lam in self.lambda_pool:
                new_pool |= lam["effects"]
                for c in lam["calls"]:
                    new_pool |= self.fn_effects.get(c, set())
                if lam["dynamic"]:
                    new_pool |= pool
            if new_pool - pool:
                pool |= new_pool
                changed = True
        self.dynamic_pool = pool
        for fn in self.ir["functions"] + self.ir["guards"]:
            fn["effects"] = sorted(self.fn_effects.get(fn["name"], set()))
        for kind in ("routes", "tasks", "tests"):
            for x in getattr(self, "_pending_" + kind, []):
                eff = set(x["own"])
                for c in x["calls"]:
                    eff |= self.fn_effects.get(c, set())
                if x.get("dynamic"):
                    eff |= pool
                x["ir"]["effects"] = sorted(eff)
        for r in getattr(self, "_pending_routes", []):
            ir, meta = r["ir"], r["meta"]
            meta["effects"] = ir["effects"]
            if ir["access"]["kind"] == "public":
                if "worker" in ir["effects"]:
                    self.error("E306", f"{ir['method']} {ir['path']} 는 public 인데 워커를 호출해요 (B1 규칙: 워커는 인증된 라우트에서만)",
                               meta["file"], meta["line"], 1, "guard bearer 또는 사용자 guard 를 붙이세요")
                if "ai" in ir["effects"]:
                    self.warn("W305", f"{ir['method']} {ir['path']} 는 인증 없이 AI 를 호출해요 (비용·남용 위험)",
                              meta["file"], meta["line"], 1, "의도했다면 레이트 리밋을 낮추거나 guard 를 붙이세요")

    def _check_routes(self):
        seen = {}
        for r in self.routes:
            key = (r["method"], re.sub(PATH_PARAM, "{}", r["path"]))
            if key in seen:
                f, l = seen[key]
                self.error("E304", f"같은 라우트가 두 번 선언됐어요: {r['method']} {r['path']} (먼저: {f}:{l})",
                           r["file"], r["line"], 1)
            seen[key] = (r["file"], r["line"])

    # ---------- 출력 ----------
    def to_ir(self, app_name="sori-app"):
        workers = [{"name": n, "timeout_ms": int(c.get("timeout_ms", 1000))} for n, c in sorted(self.workers.items())
                   if isinstance(c, dict)]
        return {
            "ir_version": IR_VERSION,
            "app": app_name,
            "files": list(self.files),
            "source_digest": {p: hashlib.sha256(s.encode()).hexdigest() for p, s in self.files.items()},
            "permissions": {k: v for k, v in sorted(self.perms.items())},
            "workers": workers,
            **self.ir,
        }


def literal_type(e):
    if e is None:
        return ty.DYN
    if e.kind == "Num":
        return "Float" if isinstance(e.value, float) else "Int"
    if e.kind == "Str":
        return {"": "Str", "sql": "Query", "html": "Html"}[e.tag]
    if e.kind == "Const":
        return {True: "Bool", False: "Bool", None: "None"}[e.value] if isinstance(e.value, bool) or e.value is None else ty.DYN
    if e.kind == "List":
        return ty.list_of(ty.DYN)
    if e.kind == "Map":
        return ty.map_of(ty.DYN)
    return ty.DYN


def static_of(t, project):
    """TypeRef → 정적 타입 문자열"""
    if t is None:
        return ty.DYN
    if t.name == "List":
        s = ty.list_of(static_of(t.args[0], project) if t.args else ty.DYN)
    elif t.name == "Map":
        s = ty.map_of(static_of(t.args[-1], project) if t.args else ty.DYN)
    elif t.name == "Any":
        s = ty.DYN
    else:
        s = t.name
    return ty.opt(s) if t.optional else s


class FileCompiler:
    def __init__(self, project, path, prog):
        self.p, self.file, self.prog = project, path, prog
        self.fi = project.file_index[path]
        self.builtins = Scope(None, "builtin")
        for b in BUILTINS:
            self.builtins.names[b] = ("builtin", "Builtin:" + b)
        self.module = Scope(self.builtins, "module")
        for name, (kind, _, _) in project.symbols.items():
            if kind == "type":
                self.module.names[name] = ("type", "Type:" + name)
            elif kind in ("fn", "guard"):
                self.module.names[name] = (kind, "Fn:" + name)
            else:
                self.module.names[name] = (kind, project.globals_t.get(name, ty.DYN))
        self.std_alias = {}

    # ---------- 유틸 ----------
    def at(self, node):
        return [self.fi, node.line, node.col]

    def N(self, op, node, t, **kw):
        d = {"op": op, "t": t, "at": self.at(node)}
        d.update(kw)
        return d

    def err(self, code, msg, node, hint=None, length=None, col=None):
        self.p.error(code, msg, self.file, node.line, col or node.col, hint, length or getattr(node, "length", 1))

    def warn(self, code, msg, node, hint=None):
        self.p.warn(code, msg, self.file, node.line, node.col, hint, getattr(node, "length", 1))

    def type_err(self, node, msg, hint=None):
        self.err("E107", msg, node, hint)

    # ---------- 최상위 ----------
    def compile(self):
        for st in self.prog:
            if st.kind == "Use":
                self.c_use(st)
        for st in self.prog:
            k = st.kind
            if k == "Use":
                continue
            if k == "TypeDecl":
                self.c_type(st)
            elif k == "FnDecl":
                self.c_fn(st)
            elif k == "GuardDecl":
                self.c_guard(st)
            elif k == "RouteDecl":
                self.c_route(st)
            elif k == "TaskDecl":
                self.c_task(st)
            elif k == "TestDecl":
                self.c_test(st)
            else:
                ctx = Ctx(kind="module")
                node = self.stmt(st, self.module, ctx)
                if node:
                    self.p.ir["init"].append(node)

    def c_use(self, st):
        perms = self.p.perms
        if st.py:
            root = st.path.split(".")[0]
            alias = st.alias or st.path.split(".")[-1]
            if root not in perms.get("python", []):
                self.err("E201", f"파이썬 패키지 '{root}' 사용 권한이 선언되지 않았어요", st,
                         f"sori.toml 의 [permissions] python = [\"{root}\"] 에 추가하세요", len("use py " + st.path), 1)
            if not self.p.dev_py:
                self.err("E201", "같은 프로세스 파이썬 실행(use py)은 개발용 실험 기능이에요", st,
                         "운영 기본 정책은 격리 워커(std.worker)예요. 개발 중에만 쓰려면 sori.toml [dev] in_process_python = true",
                         len("use py " + st.path), 1)
            else:
                self.warn("W306", "use py 는 개발 전용이에요 — 운영(SORI_ENV=production)에서는 기동이 거부돼요", st,
                          "운영에서는 [workers] 로 분리하세요")
            self.p.ir["uses"].append({"alias": alias, "module": "py:" + st.path, "at": self.at(st)})
            self.p.uses.append(("py", st.path, self.file, st.line))
            self.module.names[alias] = ("module", "Py")
        else:
            parts = st.path.split(".")
            if len(parts) != 2 or parts[0] != "std" or parts[1] not in STD_MODULES:
                self.err("E202", f"'{st.path}' 라는 모듈은 없어요", st,
                         "표준 모듈: " + ", ".join("std." + m for m in sorted(STD_MODULES)) + " / 워커는 std.worker")
                return
            mod = parts[1]
            alias = st.alias or mod
            need = STD_NEEDS.get(mod)
            if need:
                key, example = need
                ok = {"db": bool(perms.get("db")), "net": bool(perms.get("net")),
                      "fs": bool(perms.get("fs_read") or perms.get("fs_write")), "env": bool(perms.get("env")),
                      "ai": bool(perms.get("net")) or perms.get("ai_mock", False), "worker": bool(self.p.workers)}[key]
                if not ok:
                    self.err("E201", f"std.{mod} 를 쓰려면 권한 선언이 필요해요", st, f"sori.toml 에 {example} 를 추가하세요")
            self.p.ir["uses"].append({"alias": alias, "module": "std." + mod, "at": self.at(st)})
            self.p.uses.append(("std", mod, self.file, st.line))
            self.std_alias[alias] = mod
            self.module.names[alias] = ("module", "Module:" + mod)
        if alias.startswith("_"):
            self.err("E105", "별칭은 '_' 로 시작할 수 없어요", st)

    def tyir(self, t):
        """TypeRef → 런타임 타입 IR"""
        if t is None:
            return {"k": "Any"}
        name = t.name
        out = None
        if name in BUILTIN_TYPES:
            arity = BUILTIN_TYPES[name]
            lo, hi = (arity, arity) if isinstance(arity, int) else arity
            if not (lo <= len(t.args) <= hi):
                self.err("E002", f"{name} 타입 인자 개수가 맞지 않아요", t,
                         {"List": "List[Str] 처럼 1개", "Map": "Map[Int] 또는 Map[Str, Int]"}.get(name, "인자 없이 사용"))
            if name == "Any":
                self.warn("W302", "Any 타입은 입력 검증을 건너뛰어요", t, "가능하면 구체 타입이나 Json 을 쓰세요")
            if name == "List":
                out = {"k": "List", "of": self.tyir(t.args[0])} if t.args else {"k": "Any"}
            elif name == "Map":
                out = {"k": "Map", "of": self.tyir(t.args[-1])} if t.args else {"k": "Any"}
            else:
                out = {"k": name}
        elif name in self.p.types:
            if t.args:
                self.err("E002", f"{name} 은(는) 타입 인자를 받지 않아요", t)
            out = {"k": "Ref", "name": name}
        else:
            cands = set(BUILTIN_TYPES) | set(self.p.types)
            self.err("E101", f"알 수 없는 타입 '{name}'", t,
                     did_you_mean(name, cands) or "기본 타입: Int Float Str Bool List Map Json Html Secret", len(name))
            out = {"k": "Any"}
        if getattr(t, "bounds", None):
            lo, hi = t.bounds
            if name not in BOUNDABLE:
                self.err("E002", f"{name} 에는 범위 (최소, 최대) 를 붙일 수 없어요", t, "범위는 Str·Int·Float·List·Secret 에만 붙여요")
            elif lo > hi:
                self.err("E002", f"범위의 최소({lo})가 최대({hi})보다 커요", t)
            elif name in ("Str", "List", "Secret") and (lo < 0 or not isinstance(lo, int) or not isinstance(hi, int)):
                self.err("E002", f"{name} 범위는 0 이상의 정수 길이/개수예요", t)
            elif name == "Int" and not (isinstance(lo, int) and isinstance(hi, int)):
                self.err("E002", "Int 범위는 정수여야 해요", t)
            else:
                out = dict(out, lo=lo, hi=hi)
        if t.optional:
            out = {"k": "Opt", "of": out}
        return out

    def unbounded(self, t, path, depth=0, seen=None):
        seen = seen or set()
        if t is None or depth > 6:
            return []
        if t.name in INPUT_SCALARS:
            out = [] if getattr(t, "bounds", None) else [(path, t.name)]
            if t.name == "List" and t.args:
                out += self.unbounded(t.args[0], path + "[]", depth + 1, seen)
            return out
        if t.name == "Map" and t.args:
            return self.unbounded(t.args[-1], path + ".*", depth + 1, seen)
        if t.name in self.p.types and t.name not in seen:
            seen = seen | {t.name}
            out = []
            for f in self.p.types[t.name].fields:
                out += self.unbounded(f.typ, f"{path}.{f.name}", depth + 1, seen)
            return out
        return []

    def c_type(self, st):
        fields, seen = [], set()
        for f in st.fields:
            if f.name.startswith("_"):
                self.err("E105", "필드 이름은 '_' 로 시작할 수 없어요", f)
            if f.name in seen:
                self.err("E103", f"필드 '{f.name}' 이(가) 중복됐어요", f)
            if f.name in RECORD_METHODS:
                self.err("E103", f"필드 이름 '{f.name}' 은(는) 예약돼 있어요", f)
            seen.add(f.name)
            default = None
            if f.default is not None:
                ctx = Ctx(kind="module")
                default = self.expr(f.default, self.module, ctx)
                if not ty.compat(static_of(f.typ, self.p), default["t"]):
                    self.type_err(f.default, f"필드 {st.name}.{f.name} 의 기본값 타입({default['t']})이 선언({static_of(f.typ, self.p)})과 달라요")
            fields.append({"name": f.name, "type": self.tyir(f.typ), "default": default})
        self.p.ir["types"].append({"name": st.name, "doc": st.doc, "fields": fields, "at": self.at(st)})

    def _params(self, params, scope, ctx, typed=True):
        out, checks = [], []
        for prm in params:
            if prm.name.startswith("_"):
                self.err("E105", "파라미터 이름은 '_' 로 시작할 수 없어요", prm)
            if prm.name in scope.names:
                self.err("E103", f"파라미터 '{prm.name}' 이(가) 중복됐어요", prm)
            st = static_of(prm.typ, self.p) if (prm.typ is not None and typed) else ty.DYN
            scope.names[prm.name] = ("param", st)
            default = self.expr(prm.default, self.module, ctx) if prm.default is not None else None
            if default is not None and prm.typ is not None and not ty.compat(st, default["t"]):
                self.type_err(prm.default, f"파라미터 '{prm.name}' 기본값 타입({default['t']})이 {st} 와 달라요")
            out.append({"name": prm.name, "type": self.tyir(prm.typ) if (prm.typ is not None and typed) else None,
                        "default": default})
        return out

    def _fn_common(self, st, kind):
        scope = Scope(self.module, "fn")
        ctx = Ctx(True, static_of(st.ret, self.p) if getattr(st, "ret", None) is not None else None, kind=kind)
        params = self._params(st.params, scope, ctx)
        if kind == "guard" and st.params:
            scope.names[st.params[0].name] = ("param", "Request")
        body = self.block(st.body, scope, ctx)
        self.p.fn_effects[st.name] = set(ctx.effects)
        self.p.fn_calls[st.name] = set(ctx.calls)
        self.p.fn_dynamic[st.name] = ctx.dynamic
        return params, body, ctx

    def c_fn(self, st):
        params, body, ctx = self._fn_common(st, "fn")
        self.p.ir["functions"].append({
            "name": st.name, "params": params, "ret": self.tyir(st.ret) if st.ret is not None else None,
            "ret_t": ctx.ret, "body": body, "doc": st.doc, "effects": [], "at": self.at(st)})

    def c_guard(self, st):
        if len(st.params) != 1:
            self.err("E302", "guard 는 요청 하나(req)만 받아요", st, "guard 이름(req): ...")
        params, body, ctx = self._fn_common(st, "guard")
        self.p.ir["guards"].append({"name": st.name, "params": params, "body": body, "doc": st.doc, "effects": [],
                                    "at": self.at(st)})

    def c_route(self, st):
        path = st.path
        if not path.startswith("/"):
            self.err("E303", "경로는 '/' 로 시작해야 해요", st, col=st.pcol)
        path_params = []
        for seg in path.split("/"):
            m = PATH_PARAM.search(seg)
            if m:
                if m.group(0) != seg:
                    self.err("E303", f"경로 파라미터는 세그먼트 전체여야 해요: '{seg}'", st, "예: /users/{id}", col=st.pcol)
                path_params.append(m.group(1))
        declared = {p.name: p for p in st.params}
        for pp in path_params:
            if pp not in declared:
                self.err("E303", f"경로의 {{{pp}}} 가 파라미터로 선언되지 않았어요", st,
                         f"route {st.method} \"{path}\" ({pp}: Int(1, 1000000)) 처럼 타입과 함께 선언하세요", col=st.pcol)
        for prm in st.params:
            if prm.name != "req" and prm.typ is None:
                self.err("E303", f"라우트 파라미터 '{prm.name}' 에 타입이 없어요 (입력 검증 불가)", prm,
                         f"{prm.name}: Str(1, 100) 처럼 타입과 범위를 적으세요")
            elif prm.name != "req":
                loose = self.unbounded(prm.typ, prm.name)
                if loose:
                    where = ", ".join(f"{p} ({k})" for p, k in loose[:4]) + (" …" if len(loose) > 4 else "")
                    msg = f"범위가 선언되지 않은 입력: {where}"
                    hint = "Str(1, 80) · Int(0, 1000) · List[Str](0, 20) 처럼 최소/최대를 적으세요"
                    if self.p.strict_inputs:
                        self.err("E305", msg, prm, hint + " (strict_inputs 기본값: 켜짐)")
                    else:
                        self.p.warn("W304", msg, self.file, prm.line, prm.col, hint)
        if st.access is None:
            self.err("E301", f"{st.method} {path} 에 접근 정책이 없어요 (기본 거부)", st,
                     "경로 뒤에 'public' 또는 'guard <이름>' 을 붙이세요. 미들웨어가 아니라 라우트마다 명시해요")
            access = {"kind": "deny"}
        elif st.access[0] == "public":
            access = {"kind": "public"}
            if st.method != "GET":
                self.warn("W303", f"{st.method} {path} 는 인증 없이 데이터를 바꿀 수 있어요", st, "의도한 게 아니라면 guard 를 붙이세요")
        elif st.access[1] == "bearer" and "bearer" not in self.p.guards:
            access = {"kind": "bearer"}
            self.p.uses_bearer = True
        else:
            gname = st.access[1]
            if gname not in self.p.guards:
                kind = self.p.symbols.get(gname, (None,))[0]
                msg = f"'{gname}' 은(는) guard 가 아니에요 ({kind})" if kind else f"guard '{gname}' 이(가) 없어요"
                self.p.error("E302", msg, self.file, st.access[2], st.access[3],
                             did_you_mean(gname, self.p.guards) or "guard 이름(req): 로 먼저 선언하세요", len(gname))
                access = {"kind": "deny"}
            else:
                access = {"kind": "guard", "guard": gname}
        scope = Scope(self.module, "fn")
        ctx = Ctx(True, None, kind="route")
        params = []
        for prm in st.params:
            if prm.name.startswith("_"):
                self.err("E105", "파라미터 이름은 '_' 로 시작할 수 없어요", prm)
            src = "path" if prm.name in path_params else ("req" if prm.name == "req" else ("body" if prm.name == "body" else "query"))
            st_t = "Request" if src == "req" else static_of(prm.typ, self.p)
            scope.names[prm.name] = ("param", st_t)
            default = self.expr(prm.default, self.module, ctx) if prm.default is not None else None
            params.append({"name": prm.name, "source": src, "type": None if src == "req" else self.tyir(prm.typ),
                           "default": default})
        body = self.block(st.body, scope, ctx)
        if access["kind"] == "guard":
            ctx.calls.add(access["guard"])
        ret_t = ty.NEVER
        for t in ctx.returns:
            ret_t = ty.join(ret_t, t)
        route_ir = {"method": st.method, "path": path, "params": params, "access": access, "body": body,
                    "doc": st.doc, "returns": ret_t if ctx.returns else "None", "effects": [], "at": self.at(st)}
        self.p.ir["routes"].append(route_ir)
        meta = {"method": st.method, "path": path, "file": self.file, "line": st.line, "doc": st.doc,
                "access": access["kind"], "guard": access.get("guard"),
                "params": [(p.name, p.typ, p.name in path_params) for p in st.params]}
        self.p.routes.append(meta)
        self.p.__dict__.setdefault("_pending_routes", []).append(
            {"ir": route_ir, "own": ctx.effects, "calls": ctx.calls, "dynamic": ctx.dynamic, "meta": meta})

    def c_task(self, st):
        scope = Scope(self.module, "fn")
        ctx = Ctx(True, kind="task")
        body = self.block(st.body, scope, ctx)
        item = {"name": st.name, "period_ms": round(st.period * 1000, 3), "body": body, "doc": st.doc,
                "effects": [], "at": self.at(st)}
        self.p.ir["tasks"].append(item)
        self.p.tasks.append({"name": st.name, "period": st.period, "file": self.file, "line": st.line, "doc": st.doc})
        self.p.__dict__.setdefault("_pending_tasks", []).append({"ir": item, "own": ctx.effects, "calls": ctx.calls,
                                                                 "dynamic": ctx.dynamic})

    def c_test(self, st):
        scope = Scope(self.module, "fn")
        scope.names["client"] = ("builtin", "TestClient")
        ctx = Ctx(True, kind="test")
        body = self.block(st.body, scope, ctx)
        item = {"name": st.name, "body": body, "effects": [], "at": self.at(st)}
        self.p.ir["tests"].append(item)
        self.p.tests.append({"name": st.name, "file": self.file, "line": st.line})
        self.p.__dict__.setdefault("_pending_tests", []).append({"ir": item, "own": ctx.effects, "calls": ctx.calls,
                                                                 "dynamic": ctx.dynamic})

    # ---------- 문장 ----------
    def block(self, body, scope, ctx):
        out = []
        for s in body:
            n = self.stmt(s, scope, ctx)
            if n:
                out.append(n)
        return out

    def stmt(self, s, scope, ctx):
        k = s.kind
        A = self.at(s)
        if k in ("Let", "Var"):
            if s.name.startswith("_"):
                self.err("E105", f"이름 '{s.name}' 은(는) '_' 로 시작할 수 없어요", s, col=s.ncol)
            value = self.expr(s.value, scope, ctx)
            decl_t = static_of(s.typ, self.p) if s.typ is not None else value["t"]
            if s.typ is not None and not ty.compat(decl_t, value["t"]):
                self.type_err(s.value, f"'{s.name}' 은(는) {decl_t} 로 선언됐는데 값은 {value['t']} 예요")
            if value["t"] == "None" and s.typ is None:
                decl_t = ty.DYN
            if scope.kind == "module":
                scope.names[s.name] = ("let" if k == "Let" else "var", decl_t)
                where = "global"
            else:
                if s.name in scope.names and scope.names[s.name][0] not in ("loop",):
                    self.err("E103", f"'{s.name}' 이(가) 이 함수 안에서 이미 선언됐어요", s, col=s.ncol,
                             hint="값을 바꾸려면 처음에 var 로 선언하고 '이름 = 값' 으로 대입하세요")
                scope.names[s.name] = ("let" if k == "Let" else "var", decl_t)
                where = "local"
            return {"op": "let", "at": A, "name": s.name, "mutable": k == "Var", "scope": where,
                    "type": self.tyir(s.typ) if s.typ is not None else None, "value": value}
        if k == "Assign":
            value = self.expr(s.value, scope, ctx)
            t = s.target
            if t.kind == "Name":
                info, owner = scope.lookup(t.id)
                target = {"op": "var", "t": ty.DYN, "at": self.at(t), "name": t.id, "scope": "local"}
                if info is None:
                    self.err("E101", f"선언되지 않은 이름 '{t.id}' 에 대입했어요", t, f"새 변수는 'var {t.id} = 값' 으로 선언하세요")
                else:
                    kind, cur_t = info
                    if kind != "var":
                        if kind == "let":
                            self.err("E102", f"'{t.id}' 은(는) let 으로 선언된 불변 값이라 바꿀 수 없어요", t,
                                     "바꿔야 하는 값이면 'var' 로 선언하세요")
                        else:
                            label = {"param": "파라미터", "loop": "반복 변수", "fn": "함수", "type": "타입", "guard": "guard",
                                     "module": "모듈", "builtin": "내장 함수", "catch": "오류 변수"}.get(kind, kind)
                            self.err("E102", f"{label} '{t.id}' 에는 대입할 수 없어요", t, f"'var 새이름 = {t.id}' 처럼 복사해서 쓰세요")
                    else:
                        res_t = value["t"] if s.op == "=" else self.arith(s.op[0], {"t": cur_t}, value, s)
                        if not ty.compat(cur_t, res_t):
                            self.type_err(s.value, f"'{t.id}' 은(는) {cur_t} 인데 {res_t} 값을 넣으려 해요")
                    target["scope"] = "global" if owner is not None and owner.kind == "module" else "local"
                    target["t"] = info[1]
            else:
                target = self.expr(t, scope, ctx)
            return {"op": "assign", "at": A, "target": target, "o": s.op, "value": value}
        if k == "ExprStmt":
            return {"op": "expr", "at": A, "x": self.expr(s.expr, scope, ctx)}
        if k == "Return":
            if not ctx.in_fn:
                self.err("E002", "함수 밖에서는 return 할 수 없어요", s)
            v = self.expr(s.value, scope, ctx) if s.value is not None else None
            vt = v["t"] if v is not None else "None"
            ctx.returns.append(vt)
            if ctx.ret and not ty.compat(ctx.ret, vt):
                self.type_err(s, f"반환 타입은 {ctx.ret} 인데 {vt} 를 돌려주고 있어요")
            return {"op": "return", "at": A, "x": v}
        if k in ("Break", "Continue"):
            if ctx.loop == 0:
                self.err("E002", f"반복문 밖에서는 {k.lower()} 할 수 없어요", s)
            return {"op": k.lower(), "at": A}
        if k == "Pass":
            return {"op": "pass", "at": A}
        if k == "If":
            branches = [[self.expr(c, scope, ctx), self.block(b, scope, ctx)] for c, b in s.branches]
            return {"op": "if", "at": A, "branches": branches,
                    "else": self.block(s.orelse, scope, ctx) if s.orelse is not None else None}
        if k == "While":
            c = self.expr(s.cond, scope, ctx)
            ctx.loop += 1
            body = self.block(s.body, scope, ctx)
            ctx.loop -= 1
            return {"op": "while", "at": A, "c": c, "body": body}
        if k == "For":
            it = self.expr(s.iter, scope, ctx)
            elem = ty.inner(it["t"]) if ty.is_list(it["t"]) else ("Str" if ty.strip(it["t"]) == "Str" else
                                                                  ("Str" if ty.is_map(it["t"]) else ty.DYN))
            if ty.known(it["t"]) and not (ty.is_list(it["t"]) or ty.is_map(it["t"]) or ty.strip(it["t"]) == "Str"):
                self.type_err(s.iter, f"{it['t']} 은(는) 반복할 수 없어요")
            for i, nm in enumerate(s.names):
                if nm.startswith("_"):
                    self.err("E105", "반복 변수는 '_' 로 시작할 수 없어요", s)
                prev = scope.names.get(nm)
                if prev is not None and prev[0] != "loop" and scope.kind != "module":
                    self.err("E103", f"'{nm}' 이(가) 이미 선언된 이름이라 반복 변수로 쓸 수 없어요", s)
                scope.names[nm] = ("loop", elem if len(s.names) == 1 else ty.DYN)
            ctx.loop += 1
            body = self.block(s.body, scope, ctx)
            ctx.loop -= 1
            return {"op": "for", "at": A, "names": s.names, "scope": "global" if scope.kind == "module" else "local",
                    "iter": it, "body": body}
        if k == "Try":
            body = self.block(s.body, scope, ctx)
            scope.names[s.name] = ("catch", "Error")
            handler = self.block(s.handler, scope, ctx)
            return {"op": "try", "at": A, "body": body, "name": s.name,
                    "scope": "global" if scope.kind == "module" else "local", "handler": handler}
        self.err("E002", f"여기에 {k} 는 올 수 없어요", s)
        return None

    # ---------- 표현식 ----------
    def ref(self, node, scope, ctx, callee=False, module_ok=False):
        name = node.id
        if name.startswith("_"):
            self.err("E105", f"'{name}' 처럼 '_' 로 시작하는 이름은 쓸 수 없어요", node, "샌드박스 보호 규칙이에요")
            return self.N("lit", node, "None", v=None)
        info, owner = scope.lookup(name)
        if info is None:
            hint = did_you_mean(name, scope.all_names())
            if not hint and name in STD_MODULES:
                hint = f"파일 위에 'use std.{name}' 을 추가하세요"
            elif not hint and name == "client":
                hint = "client 는 test 블록 안에서만 쓸 수 있어요"
            self.err("E101", f"선언되지 않은 이름 '{name}'", node, hint)
            return self.N("lit", node, ty.DYN, v=None)
        kind, t = info
        if name == "unsafe_html":
            self.warn("W301", "unsafe_html 은 이스케이프를 끄고 HTML 을 그대로 넣어요 (XSS 위험)", node,
                      "신뢰할 수 있는 고정 문자열에만 쓰세요. sori audit 에 기록돼요")
        if kind in ("fn", "guard"):
            ctx.calls.add(name)
            if not callee:
                self.p.escaped_fns.add(name)  # 값으로 저장·전달됨 → 어디서 호출될지 정적으로 모름
        if kind == "module" and t.startswith("Module:") and not module_ok:
            self.err("E110", f"표준 모듈 '{name}' 은(는) 값으로 저장하거나 넘길 수 없어요", node,
                     f"{name}.함수(...) 처럼 직접 호출하세요 (효과·권한 분석이 호출 위치를 볼 수 있어야 해요)")
            return self.N("lit", node, ty.DYN, v=None)
        if kind == "builtin" or owner is self.builtins or (owner is not None and owner.kind == "builtin"):
            scope_kind = "builtin"
        elif owner is not None and owner.kind == "module":
            scope_kind = "global"
        else:
            scope_kind = "local"
        return self.N("var", node, t, name=name, scope=scope_kind)

    def arith(self, op, l, r, node):
        lt, rt = ty.strip(l["t"]), ty.strip(r["t"])
        if op == "+":
            if lt == rt == "Str":
                return "Str"
            if lt == "Html" or rt == "Html":
                return "Html"
            if ty.is_list(lt) and ty.is_list(rt):
                return lt if lt == rt else ty.list_of(ty.DYN)
        if "Bool" in (lt, rt) and ty.known(lt) and ty.known(rt):
            self.type_err(node, f"Bool 은 숫자 연산({op})에 쓸 수 없어요", "true/false 를 숫자처럼 쓰지 마세요 (B1 규칙)")
            return ty.DYN
        if lt in ty.NUMERIC and rt in ty.NUMERIC:
            if op == "/":
                return "Float"
            return "Float" if "Float" in (lt, rt) else "Int"
        if not ty.known(lt) or not ty.known(rt):
            if op == "/" and (lt in ty.NUMERIC or rt in ty.NUMERIC):
                return "Float"
            return ty.DYN if op == "+" else (lt if lt in ty.NUMERIC else (rt if rt in ty.NUMERIC else ty.DYN))
        hint = "문자열에 숫자를 붙이려면 \"{값}\" 보간이나 str(값) 을 쓰세요" if "Str" in (lt, rt) else None
        self.type_err(node, f"{l['t']} {op} {r['t']} 연산은 할 수 없어요", hint)
        return ty.DYN

    def expr(self, e, scope, ctx):
        if e is None:
            return {"op": "lit", "t": "None", "v": None, "at": [self.fi, 0, 0]}
        k = e.kind
        if k == "Num":
            if abs(e.value) > MAX_LITERAL or (isinstance(e.value, float) and e.value != e.value):
                self.err("E002", f"숫자 상수가 너무 커요 (±1e12 이내)", e, "B1 규칙: 비유한/과대 상수 거부")
            return self.N("lit", e, "Float" if isinstance(e.value, float) else "Int", v=e.value)
        if k == "Const":
            return self.N("lit", e, "None" if e.value is None else "Bool", v=e.value)
        if k == "Name":
            return self.ref(e, scope, ctx)
        if k == "Str":
            return self.string(e, scope, ctx)
        if k == "List":
            items = [self.expr(x, scope, ctx) for x in e.items]
            et = ty.NEVER
            for it in items:
                et = ty.join(et, it["t"])
            return self.N("list", e, ty.list_of(et if items else ty.DYN), items=items)
        if k == "Map":
            pairs, vt = [], ty.NEVER
            keys = set()
            for a, b in e.pairs:
                ka, kb = self.expr(a, scope, ctx), self.expr(b, scope, ctx)
                if ka["op"] == "lit":
                    if ka["v"] in keys:
                        self.err("E103", f"맵 키 '{ka['v']}' 가 중복됐어요", a)
                    keys.add(ka["v"])
                if ty.known(ka["t"]) and ty.strip(ka["t"]) != "Str":
                    self.type_err(a, f"맵 키는 Str 이어야 해요 ({ka['t']})")
                pairs.append([ka, kb])
                vt = ty.join(vt, kb["t"])
            return self.N("map", e, ty.map_of(vt if pairs else ty.DYN), pairs=pairs)
        if k == "Attr":
            node = self.attr(e, scope, ctx)
            if node["op"] == "std":
                self.err("E110", f"std.{node['module']}.{node['name']} 은(는) 값으로 저장하거나 넘길 수 없어요", e,
                         f"{node['module']}.{node['name']}(...) 처럼 직접 호출하세요 (별칭으로 워커·AI 호출을 숨길 수 없게 하는 규칙)")
                return self.N("lit", e, ty.DYN, v=None)
            return node
        if k == "Index":
            obj = self.expr(e.obj, scope, ctx)
            ot = ty.strip(obj["t"])
            if e.slice:
                lo = self.expr(e.index, scope, ctx) if e.index is not None else None
                hi = self.expr(e.hi, scope, ctx) if e.hi is not None else None
                for b in (lo, hi):
                    if b is not None and ty.known(b["t"]) and ty.strip(b["t"]) != "Int":
                        self.type_err(e, "슬라이스 범위는 Int 여야 해요")
                return self.N("slice", e, ot if (ty.is_list(ot) or ot == "Str") else ty.DYN, obj=obj, lo=lo, hi=hi)
            idx = self.expr(e.index, scope, ctx)
            it = ty.strip(idx["t"])
            if ty.is_list(ot):
                if ty.known(it) and it != "Int":
                    self.type_err(e, f"목록 인덱스는 Int 여야 해요 ({idx['t']})")
                rt = ty.inner(ot)
            elif ty.is_map(ot):
                if ty.known(it) and it != "Str":
                    self.type_err(e, f"맵 키는 Str 이어야 해요 ({idx['t']})")
                rt = ty.inner(ot)
            elif ot == "Str":
                rt = "Str"
            elif ot in self.p.types or ot in ("Int", "Float", "Bool", "Html", "Secret"):
                self.type_err(e, f"{obj['t']} 은(는) 인덱스로 접근할 수 없어요", "레코드는 .필드 로 접근하세요" if ot in self.p.types else None)
                rt = ty.DYN
            else:
                rt = ty.DYN
            return self.N("index", e, rt, obj=obj, index=idx)
        if k == "Call":
            return self.call(e, scope, ctx)
        if k == "BinOp":
            l, r = self.expr(e.left, scope, ctx), self.expr(e.right, scope, ctx)
            return self.N("binop", e, self.arith(e.op, l, r, e), o=e.op, l=l, r=r)
        if k == "Unary":
            x = self.expr(e.operand, scope, ctx)
            if ty.known(x["t"]) and ty.strip(x["t"]) not in ty.NUMERIC:
                self.type_err(e, f"단항 {e.op} 는 숫자에만 쓸 수 있어요 ({x['t']})")
            return self.N("unop", e, x["t"] if ty.strip(x["t"]) in ty.NUMERIC else ty.DYN, o=e.op, x=x)
        if k == "Not":
            return self.N("not", e, "Bool", x=self.expr(e.operand, scope, ctx))
        if k == "BoolOp":
            l, r = self.expr(e.left, scope, ctx), self.expr(e.right, scope, ctx)
            return self.N("logic", e, ty.join(l["t"], r["t"]), o=e.op, l=l, r=r)
        if k == "Compare":
            left = self.expr(e.left, scope, ctx)
            rights = [self.expr(r, scope, ctx) for r in e.rights]
            prev = left
            for op, r in zip(e.ops, rights):
                a, b = ty.strip(prev["t"]), ty.strip(r["t"])
                if op in ("<", ">", "<=", ">="):
                    if ty.known(a) and ty.known(b) and not ((a in ty.NUMERIC and b in ty.NUMERIC) or a == b == "Str"):
                        self.type_err(e, f"{prev['t']} {op} {r['t']} 크기 비교는 할 수 없어요", "크기 비교는 숫자끼리 또는 문자열끼리만 돼요")
                elif op in ("in", "not in"):
                    if ty.known(b) and not (ty.is_list(b) or ty.is_map(b) or b in ("Str", "Html")):
                        self.type_err(e, f"'{op}' 오른쪽은 목록/맵/문자열이어야 해요 ({r['t']})")
                prev = r
            return self.N("compare", e, "Bool", l=left, ops=e.ops, rs=rights)
        if k == "IfExp":
            c = self.expr(e.cond, scope, ctx)
            a, b = self.expr(e.then, scope, ctx), self.expr(e.orelse, scope, ctx)
            return self.N("cond", e, ty.join(a["t"], b["t"]), c=c, then=a, orelse=b)
        if k == "Lambda":
            ls = Scope(scope, "lambda")
            lctx = Ctx(ctx.in_fn, kind="lambda")
            params = self._params(e.params, ls, lctx, typed=False)
            body = self.expr(e.body, ls, lctx)
            # 만든 곳은 람다를 바로 부를 수 있으니(map 등) 효과를 그대로 받고, 값으로 빠져나갈 수 있으니 풀에도 등록
            ctx.effects |= lctx.effects
            ctx.calls |= lctx.calls
            ctx.dynamic = ctx.dynamic or lctx.dynamic
            self.p.lambda_pool.append({"effects": lctx.effects, "calls": lctx.calls, "dynamic": lctx.dynamic})
            return self.N("lambda", e, "Lambda:" + body["t"], params=params, body=body)
        self.err("E002", f"알 수 없는 식 {k}", e)
        return self.N("lit", e, ty.DYN, v=None)

    def member_type(self, ot, name, node):
        """수신 객체 정적 타입 + 속성 이름 → 정적 타입 (None 이면 알 수 없음/허용, '!' 이면 오류)"""
        base = ty.strip(ot)
        table = None
        if base == "Str":
            table = {m: "Method:" + r for m, r in STR_METHODS.items()}
        elif ty.is_list(base):
            table = {m: "Method:" + r.replace("<E>", ty.inner(base)).replace("<S>", base) for m, r in LIST_METHODS.items()}
        elif ty.is_map(base):
            el = ty.inner(base)
            table = {m: "Method:" + r.replace("<E>", el).replace("<S>", base) for m, r in MAP_METHODS.items()}
        elif base in self.p.types:
            decl = self.p.types[base]
            table = {f.name: static_of(f.typ, self.p) for f in decl.fields}
            table.update({m: "Method:" + r.replace("<S>", base) for m, r in RECORD_METHODS.items()})
        else:
            table = {"Request": REQUEST_SURFACE, "HttpResponse": HTTP_RESPONSE_SURFACE,
                     "ClientResponse": CLIENT_RESPONSE_SURFACE, "Error": ERROR_SURFACE, "Secret": SECRET_SURFACE,
                     "Query": QUERY_SURFACE, "Response": RESPONSE_SURFACE, "TestClient": TEST_CLIENT_SURFACE,
                     "Int": {}, "Float": {}, "Bool": {}, "Html": {}, "None": {}}.get(base)
            if base == "Row":
                return ROW_SURFACE.get(name, ty.DYN)
        if table is None:
            return ty.DYN
        if name in table:
            return table[name]
        self.err("E108", f"{ot} 에는 '{name}' 이(가) 없어요", node,
                 did_you_mean(name, table) or (f"있는 것: {', '.join(sorted(table))}" if table else None))
        return ty.DYN

    def attr(self, e, scope, ctx):
        obj = self.ref(e.obj, scope, ctx, module_ok=True) if e.obj.kind == "Name" else self.expr(e.obj, scope, ctx)
        if e.name.startswith("_"):
            self.err("E105", f"'_' 로 시작하는 속성 '{e.name}' 에는 접근할 수 없어요", e,
                     "파이썬 내부 객체(__class__, __globals__ 등)로의 탈출을 막는 규칙이에요")
            return self.N("lit", e, ty.DYN, v=None)
        if e.name in FORBIDDEN_ATTRS:
            self.err("E106", f"속성 '{e.name}' 은(는) 샌드박스 보호를 위해 막혀 있어요", e,
                     "문자열 조합은 \"...{값}...\" 보간을 쓰세요" if e.name in ("format", "format_map") else None)
            return self.N("lit", e, ty.DYN, v=None)
        ot = obj["t"]
        if ot.startswith("Module:"):
            mod = ot.split(":", 1)[1]
            methods = STD_METHODS[mod]
            if e.name not in methods:
                self.err("E108", f"std.{mod} 에는 '{e.name}' 이(가) 없어요", e,
                         did_you_mean(e.name, methods) or "있는 것: " + ", ".join(sorted(methods)))
                return self.N("lit", e, ty.DYN, v=None)
            eff = STD_EFFECTS.get(mod, {})
            effect = eff.get(e.name, eff.get("*"))
            if effect:
                ctx.effects.add(effect)
                if mod == "ai":
                    ctx.effects.add("net")
            return self.N("std", e, f"Std:{mod}.{e.name}", obj=obj, module=mod, name=e.name)
        if ot == "Py":
            ctx.effects.add("py")
            return self.N("field", e, "Py", obj=obj, name=e.name)
        t = self.member_type(ot, e.name, e)
        return self.N("field", e, t, obj=obj, name=e.name)

    def call(self, e, scope, ctx):
        direct = False
        if e.func.kind == "Name":
            fn = self.ref(e.func, scope, ctx, callee=True)
            info, _ = scope.lookup(e.func.id)
            direct = info is not None and info[0] in ("fn", "guard")
        elif e.func.kind == "Attr":
            fn = self.attr(e.func, scope, ctx)
        else:
            fn = self.expr(e.func, scope, ctx)
        args = [self.expr(a, scope, ctx) for a in e.args]
        kwargs = []
        for name, v, line, col in e.kwargs:
            if name.startswith("_"):
                self.p.error("E105", "인자 이름은 '_' 로 시작할 수 없어요", self.file, line, col)
            kwargs.append([name, self.expr(v, scope, ctx)])
        ft = fn["t"]
        rt = ty.DYN
        if ft.startswith("Std:"):
            mod, meth = ft[4:].split(".", 1)
            rt = STD_METHODS[mod][meth]
            tparam = lambda i: (args[i]["t"][5:] if len(args) > i and args[i]["t"].startswith("Type:") else None)
            kw = dict(kwargs)
            if "type" in kw and kw["type"]["t"].startswith("Type:"):
                tname = kw["type"]["t"][5:]
            else:
                tname = None
            if mod == "db" and meth in ("all", "one"):
                tn = tparam(1) or tname
                if tn:
                    rt = ty.list_of(tn) if meth == "all" else ty.opt(tn)
                if args and ty.known(args[0]["t"]) and args[0]["t"] != "Query":
                    self.err("E109", "db 에는 sql\"...\" 리터럴만 넣을 수 있어요 (SQL 인젝션 차단)", e.args[0],
                             "문자열 조합 대신 sql\"SELECT ... WHERE id = {id}\" 처럼 보간하세요")
            elif mod == "db" and meth == "exec" and args and ty.known(args[0]["t"]) and args[0]["t"] != "Query":
                self.err("E109", "db 에는 sql\"...\" 리터럴만 넣을 수 있어요 (SQL 인젝션 차단)", e.args[0])
            elif mod == "ai" and meth == "extract":
                tn = tparam(0)
                rt = tn or ty.DYN
            elif mod == "json" and meth == "parse":
                tn = tparam(1) or tname
                rt = tn or "Json"
            elif mod == "worker" and meth == "call":
                tn = tparam(2) or tname
                rt = tn or "Map[Json]"
                if args and e.args[0].kind == "Str" and len(e.args[0].parts) == 1 and e.args[0].parts[0][0] == "lit":
                    wname = e.args[0].parts[0][1]
                    if wname not in self.p.workers:
                        self.err("E201", f"워커 '{wname}' 이(가) sori.toml 에 선언되지 않았어요", e.args[0],
                                 did_you_mean(wname, self.p.workers) or f"[workers.{wname}] url = \"http://127.0.0.1:9010/invoke\" 를 추가하세요")
                else:
                    self.err("E201", "워커 이름은 고정 문자열이어야 해요 (사용자 입력으로 호출 대상이 바뀌면 안 돼요)", e)
        elif ft.startswith("Method:"):
            rt = ft[7:]
        elif ft.startswith("Type:"):
            tname = ft[5:]
            rt = tname
            decl = self.p.types.get(tname)
            if decl:
                fields = {f.name: f for f in decl.fields}
                if len(args) > len(decl.fields):
                    self.type_err(e, f"{tname} 은(는) 필드가 {len(decl.fields)}개인데 값이 {len(args)}개예요")
                given = set()
                for f, a in zip(decl.fields, args):
                    given.add(f.name)
                    self._arg_check(static_of(f.typ, self.p), a, f"{tname}.{f.name}", e)
                for name, v in kwargs:
                    if name not in fields:
                        self.err("E108", f"{tname} 에는 '{name}' 필드가 없어요", e,
                                 did_you_mean(name, fields) or "필드: " + ", ".join(fields))
                        continue
                    given.add(name)
                    self._arg_check(static_of(fields[name].typ, self.p), v, f"{tname}.{name}", e)
                missing = [f.name for f in decl.fields if f.default is None and not f.typ.optional and f.name not in given]
                if missing:
                    self.type_err(e, f"{tname} 을(를) 만들려면 {', '.join(missing)} 이(가) 필요해요")
        elif ft.startswith("Fn:"):
            fname = ft[3:]
            ctx.calls.add(fname)
            if not direct:
                ctx.dynamic = True  # 별칭(let h = f)으로 부름 — 점진적 타입이라 다른 함수가 들어 있을 수 있어 보수적으로
            decl = self.p.fns.get(fname) or self.p.guards.get(fname)
            if decl is not None:
                params = decl.params
                pmap = {p.name: p for p in params}
                if len(args) > len(params):
                    self.type_err(e, f"{fname} 은(는) 인자를 {len(params)}개 받아요 ({len(args)}개 줬어요)")
                given = set()
                for p, a in zip(params, args):
                    given.add(p.name)
                    if p.typ is not None:
                        self._arg_check(static_of(p.typ, self.p), a, f"{fname}({p.name})", e)
                for name, v in kwargs:
                    if name not in pmap:
                        self.err("E108", f"{fname} 에는 '{name}' 파라미터가 없어요", e, did_you_mean(name, pmap))
                        continue
                    given.add(name)
                    if pmap[name].typ is not None:
                        self._arg_check(static_of(pmap[name].typ, self.p), v, f"{fname}({name})", e)
                missing = [p.name for p in params if p.default is None and p.name not in given]
                if missing:
                    self.type_err(e, f"{fname} 호출에 {', '.join(missing)} 인자가 빠졌어요")
                rt = static_of(decl.ret, self.p) if getattr(decl, "ret", None) is not None else (
                    "Bool" if fname in self.p.guards else ty.DYN)
        elif ft.startswith("Lambda:"):
            rt = ft[7:]
            ctx.dynamic = True
        elif ft.startswith("Builtin:"):
            b = ft[8:]
            spec = BUILTIN_RET[b]
            a0 = args[0]["t"] if args else ty.DYN
            if spec == "<A0>":
                rt = a0 if (b != "abs" or ty.strip(a0) in ty.NUMERIC) else ty.DYN
            elif spec == "<E0>":
                rt = ty.inner(a0) if ty.is_list(a0) else ty.DYN
            else:
                rt = spec
            if b == "map" and len(args) == 2:
                f_t = next((a["t"] for a in args if a["t"].startswith(("Fn:", "Lambda:"))), "")
                if f_t.startswith("Fn:"):
                    d = self.p.fns.get(f_t[3:])
                    if d is not None and d.ret is not None:
                        rt = ty.list_of(static_of(d.ret, self.p))
                elif f_t.startswith("Lambda:"):
                    rt = ty.list_of(f_t[7:])
            if b == "len" and args and ty.known(a0) and not (ty.is_list(a0) or ty.is_map(a0) or ty.strip(a0) in ("Str", "Html")):
                self.type_err(e, f"len() 은 목록/맵/문자열에만 쓸 수 있어요 ({a0})")
        elif ft != "Py" and not ft.startswith(("Std:", "Method:", "Type:")):
            ctx.dynamic = True  # Dyn·인덱스 결과·함수 반환값 호출: 대상을 정적으로 모름
        return self.N("call", e, rt, fn=fn, args=args, kwargs=kwargs)

    def _arg_check(self, expected, arg, label, node):
        if not ty.compat(expected, arg["t"]):
            self.type_err(node, f"'{label}' 은(는) {expected} 인데 {arg['t']} 값을 넘겼어요")

    def string(self, e, scope, ctx):
        lits, args, ctxs = [], [], []
        acc, pending = "", ""
        for part in e.parts:
            if part[0] == "lit":
                pending += part[1]
            else:
                lits.append(pending)
                acc += pending
                pending = ""
                if e.tag == "html":
                    ctxs.append(self.html_context(acc, part[1]))
                args.append(self.expr(part[1], scope, ctx))
        lits.append(pending)
        if e.tag == "" and not args:
            return self.N("lit", e, "Str", v=lits[0])
        if e.tag == "sql":
            return self.N("sql", e, "Query", lits=lits, args=args)
        if e.tag == "html":
            return self.N("html", e, "Html", lits=lits, args=args, ctx=ctxs)
        return self.N("cat", e, "Str", lits=lits, args=args)

    def html_context(self, before, node):
        low = before.lower()
        if low.rfind("<script") > low.rfind("</script"):
            self.err("E401", "<script> 안에 값을 보간할 수 없어요 (스크립트 인젝션 위험)", node,
                     "데이터는 data-* 속성이나 JSON API 로 넘기고, 스크립트는 별도 정적 파일로 두세요")
            return "text"
        if low.rfind("<style") > low.rfind("</style"):
            self.err("E401", "<style> 안에 값을 보간할 수 없어요 (CSS 인젝션 위험)", node)
            return "text"
        if low.rfind("<!--") > low.rfind("-->"):
            self.err("E401", "HTML 주석 안에는 보간할 수 없어요", node)
            return "text"
        lt, gt = before.rfind("<"), before.rfind(">")
        if lt > gt:
            seg = before[lt:]
            m = re.search(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*([\"'])[^\"']*$", seg)
            if m:
                attr = m.group(1).lower()
                if attr.startswith("on"):
                    self.err("E401", f"이벤트 핸들러 속성 '{attr}' 에는 값을 보간할 수 없어요", node,
                             "이벤트는 정적 JS 파일에서 addEventListener 로 연결하세요")
                if attr in ("style", "srcdoc"):
                    self.err("E401", f"'{attr}' 속성에는 값을 보간할 수 없어요", node)
                return "url" if attr in URL_ATTRS else "attr"
            if re.search(r"=\s*$", seg):
                self.err("E401", "따옴표 없는 속성값에는 보간할 수 없어요", node, "속성값을 \"...\" 로 감싸세요")
                return "attr"
            self.err("E401", "태그 안(속성 이름 자리)에는 값을 보간할 수 없어요", node, "<div class=\"{값}\"> 처럼 속성값 안에 넣으세요")
            return "attr"
        return "text"


def compile_project(files, config):
    return Project(files, config).build()
