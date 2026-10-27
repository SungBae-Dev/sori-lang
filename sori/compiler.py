"""SORI 컴파일러: 정적 검사(스코프·불변성·권한·라우트 정책·HTML 문맥) + 파이썬 코드 생성.

생성된 코드는 제한된 __builtins__ 위에서 실행되며, SORI 소스에는 동적 속성 접근(getattr),
eval/exec, '_' 로 시작하는 이름이 존재하지 않으므로 파이썬 샌드박스 탈출 경로가 원천 차단된다.
"""
import re

from .diagnostics import SoriError, did_you_mean
from .parser import parse
from .policy import worker_problems

BUILTIN_TYPES = {"Int": 0, "Float": 0, "Str": 0, "Bool": 0, "Json": 0, "Html": 0, "Secret": 0, "Any": 0,
                 "List": 1, "Map": (1, 2)}
STD_MODULES = {"db", "http", "fs", "env", "ai", "json", "time", "log", "crypto", "worker"}
BOUNDABLE = {"Str", "Int", "Float", "List", "Secret"}
NUMERIC_INPUT = {"Str", "Int", "Float", "List", "Secret"}
STD_NEEDS = {  # 모듈 → 필요한 권한
    "db": ("db", "[permissions] db = [\"sqlite:./data/app.db\"]"),
    "http": ("net", "[permissions] net = [\"api.example.com\"]"),
    "fs": ("fs", "[permissions] fs_read = [\"./data\"] 또는 fs_write = [\"./data\"]"),
    "env": ("env", "[permissions] env = [\"API_KEY\"]"),
    "ai": ("ai", "[permissions] net = [\"api.anthropic.com\"]"),
    "worker": ("worker", "[workers.이름] url = \"http://127.0.0.1:9010/invoke\""),
}
BUILTINS = {
    "print", "len", "str", "int", "float", "bool", "range", "list", "sorted", "reversed", "sum", "min", "max",
    "abs", "round", "enumerate", "zip", "any", "all", "map", "filter", "type_of", "respond", "redirect",
    "unsafe_html", "error", "expect",
}
# 파이썬 객체 그래프를 타고 샌드박스를 탈출하는 데 쓰이는 속성들 (컴파일 타임 차단)
FORBIDDEN_ATTRS = {
    "format", "format_map", "mro", "gi_frame", "gi_code", "f_globals", "f_locals", "f_back", "f_builtins",
    "f_code", "tb_frame", "tb_next", "cr_frame", "ag_frame", "func_globals", "func_code", "im_func", "co_code",
}
URL_ATTRS = {"href", "src", "action", "formaction", "poster", "cite", "background", "xlink:href", "data"}
PATH_PARAM = re.compile(r"\{([^/{}]+)\}")


class Scope:
    def __init__(self, parent=None, kind="fn"):
        self.names, self.parent, self.kind = {}, parent, kind

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


class Emitter:
    def __init__(self):
        self.lines = []  # (indent, text, file, line)

    def emit(self, indent, text, file, line):
        self.lines.append((indent, text, file, line))


class Ctx:
    def __init__(self, in_fn=False, ret=None, loop=0, fn_globals=None, kind="module"):
        self.in_fn, self.ret, self.loop, self.kind = in_fn, ret, loop, kind
        self.fn_globals = fn_globals if fn_globals is not None else set()


class Project:
    """여러 .sori 파일이 하나의 네임스페이스(Go 패키지처럼)를 공유한다."""

    def __init__(self, files, config):
        self.files = files  # {path: src}
        self.config = config
        self.perms = config.get("permissions", {})
        self.workers = config.get("workers", {})
        self.strict_inputs = bool(config.get("security", {}).get("strict_inputs", False))
        self.uses_bearer = False
        self.diags = []
        self.symbols = {}  # name -> (kind, file, line)
        self.types, self.fns, self.guards = {}, {}, {}
        self.routes, self.tasks, self.tests = [], [], []
        self.uses = []
        self.phases = {p: Emitter() for p in range(5)}
        self.counter = 0

    def uid(self):
        self.counter += 1
        return self.counter

    def error(self, code, msg, file, line, col, hint=None, length=1, severity="error"):
        self.diags.append(SoriError(code, msg, file, line, col, hint, severity, length))

    def warn(self, code, msg, file, line, col, hint=None, length=1):
        self.error(code, msg, file, line, col, hint, length, "warning")

    # ---------- 1단계: 파싱 + 최상위 심볼 수집 ----------
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
                self._collect(st, path, top=True)
        for path, prog in progs.items():
            FileCompiler(self, path, prog).compile()
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

    def _collect(self, st, path, top):
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
                    self._collect(s, path, False)
            for s in st.orelse or []:
                self._collect(s, path, False)
        elif k in ("For", "While", "Try"):
            for s in st.body:
                self._collect(s, path, False)
            for s in getattr(st, "handler", []) or []:
                self._collect(s, path, False)

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
    def python_source(self):
        out = ["# SORI 가 생성한 코드입니다. 직접 수정하지 마세요."]
        linemap = [(None, 0)]
        for p in range(5):
            for indent, text, file, line in self.phases[p].lines:
                out.append("    " * indent + text)
                linemap.append((file, line))
        return "\n".join(out) + "\n", linemap


class FileCompiler:
    def __init__(self, project, path, prog):
        self.p, self.file, self.prog = project, path, prog
        self.builtins = Scope(None, "builtin")
        for b in BUILTINS:
            self.builtins.names[b] = "builtin"
        self.module = Scope(self.builtins, "module")
        self.std_alias = {}
        for name, (kind, _, _) in project.symbols.items():
            self.module.names[name] = kind

    def err(self, code, msg, node, hint=None, length=None, col=None):
        self.p.error(code, msg, self.file, node.line, col or node.col, hint, length or getattr(node, "length", 1))

    def warn(self, code, msg, node, hint=None):
        self.p.warn(code, msg, self.file, node.line, node.col, hint, getattr(node, "length", 1))

    def emit(self, phase, indent, text, line):
        self.p.phases[phase].emit(indent, text, self.file, line)

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
                em = Emitter()
                self.stmt(st, self.module, em, 0, Ctx())
                for ind, text, f, l in em.lines:
                    self.p.phases[3].emit(ind, text, f, l)

    def c_use(self, st):
        perms = self.p.perms
        if st.py:
            root = st.path.split(".")[0]
            alias = st.alias or st.path.split(".")[-1]
            if root not in perms.get("python", []):
                self.err("E201", f"파이썬 패키지 '{root}' 사용 권한이 선언되지 않았어요", st,
                         f"sori.toml 의 [permissions] python = [\"{root}\"] 에 추가하세요", len("use py " + st.path), 1)
            self.emit(0, 0, f"{alias} = _R.use_py({st.path!r})", st.line)
            self.p.uses.append(("py", st.path, self.file, st.line))
        else:
            parts = st.path.split(".")
            if len(parts) != 2 or parts[0] != "std" or parts[1] not in STD_MODULES:
                self.err("E202", f"'{st.path}' 라는 모듈은 없어요", st,
                         "표준 모듈: " + ", ".join("std." + m for m in sorted(STD_MODULES)) + " / 파이썬 패키지는 'use py 이름'")
                return
            mod = parts[1]
            alias = st.alias or mod
            need = STD_NEEDS.get(mod)
            if need:
                key, example = need
                ok = {
                    "db": bool(perms.get("db")),
                    "net": bool(perms.get("net")),
                    "fs": bool(perms.get("fs_read") or perms.get("fs_write")),
                    "env": bool(perms.get("env")),
                    "ai": bool(perms.get("net")) or perms.get("ai_mock", False),
                    "worker": bool(self.p.workers),
                }[key]
                if not ok:
                    self.err("E201", f"std.{mod} 를 쓰려면 권한 선언이 필요해요", st, f"sori.toml 에 {example} 를 추가하세요")
            self.emit(0, 0, f"{alias} = _R.use_std({mod!r})", st.line)
            self.std_alias[alias] = mod
            self.p.uses.append(("std", mod, self.file, st.line))
        if alias.startswith("_"):
            self.err("E105", "별칭은 '_' 로 시작할 수 없어요", st)
        self.module.names[alias] = "module"

    def ty(self, t):
        if t is None:
            return "_R.T.Any"
        name = t.name
        if name in BUILTIN_TYPES:
            arity = BUILTIN_TYPES[name]
            lo, hi = (arity, arity) if isinstance(arity, int) else arity
            if not (lo <= len(t.args) <= hi):
                self.err("E002", f"{name} 타입 인자 개수가 맞지 않아요", t,
                         {"List": "List[Str] 처럼 1개", "Map": "Map[Int] 또는 Map[Str, Int]"}.get(name, "인자 없이 사용"))
            if name == "Any":
                self.warn("W302", "Any 타입은 입력 검증을 건너뛰어요", t, "가능하면 구체 타입이나 Json 을 쓰세요")
            if name == "List":
                base = f"_R.T.List({self.ty(t.args[0])})" if t.args else "_R.T.Any"
            elif name == "Map":
                base = f"_R.T.Map({self.ty(t.args[-1])})" if t.args else "_R.T.Any"
            else:
                base = f"_R.T.{name}"
        elif name in self.p.types:
            if t.args:
                self.err("E002", f"{name} 은(는) 타입 인자를 받지 않아요", t)
            base = f"_R.T.Ref({name!r})"
        else:
            cands = set(BUILTIN_TYPES) | set(self.p.types)
            self.err("E101", f"알 수 없는 타입 '{name}'", t, did_you_mean(name, cands) or "기본 타입: Int Float Str Bool List Map Json Html Secret", len(name))
            base = "_R.T.Any"
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
                base = f"{base}.bounded({lo!r}, {hi!r})"
        return f"_R.T.Opt({base})" if t.optional else base

    def unbounded(self, t, path, depth=0, seen=None):
        """외부 입력 타입에서 범위가 없는 Str/Int/Float/List 위치를 찾는다 (SORI v0.1: 모든 입력은 범위 필수)."""
        seen = seen or set()
        if t is None or depth > 6:
            return []
        if t.name in NUMERIC_INPUT:
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
            seen.add(f.name)
            default = self.expr(f.default, self.module) if f.default is not None else "_R.NODEF"
            fields.append(f"({f.name!r}, {self.ty(f.typ)}, {default})")
        self.emit(1, 0, f"{st.name} = _R.record({st.name!r}, [{', '.join(fields)}], {st.doc!r})", st.line)

    def _params(self, params, scope, allow_types=True):
        names, checks = [], []
        for prm in params:
            if prm.name.startswith("_"):
                self.err("E105", "파라미터 이름은 '_' 로 시작할 수 없어요", prm)
            if prm.name in scope.names:
                self.err("E103", f"파라미터 '{prm.name}' 이(가) 중복됐어요", prm)
            scope.names[prm.name] = "param"
            d = f"={self.expr(prm.default, self.module)}" if prm.default is not None else ""
            names.append(prm.name + d)
            if prm.typ is not None and allow_types:
                checks.append((prm, f"_R.check({prm.name}, {self.ty(prm.typ)}, {prm.name!r})"))
        return names, checks

    def _body(self, phase, header, body, scope, ctx, line, checks=()):
        em = Emitter()
        for prm, chk in checks:
            em.emit(1, chk, self.file, prm.line)
        for s in body:
            self.stmt(s, scope, em, 1, ctx)
        self.emit(phase, 0, header, line)
        if ctx.fn_globals:
            self.emit(phase, 1, "global " + ", ".join(sorted(ctx.fn_globals)), line)
        if not em.lines:
            self.emit(phase, 1, "pass", line)
        for ind, text, f, l in em.lines:
            self.p.phases[phase].emit(ind, text, f, l)

    def c_fn(self, st):
        scope = Scope(self.module, "fn")
        names, checks = self._params(st.params, scope)
        ret = self.ty(st.ret) if st.ret is not None else None
        self._body(2, f"def {st.name}({', '.join(names)}):", st.body, scope, Ctx(True, ret, kind="fn"), st.line, checks)

    def c_guard(self, st):
        scope = Scope(self.module, "fn")
        names, checks = self._params(st.params, scope)
        if len(st.params) != 1:
            self.err("E302", "guard 는 요청 하나(req)만 받아요", st, "guard 이름(req): ...")
        self._body(2, f"def {st.name}({', '.join(names)}):", st.body, scope, Ctx(True, None, kind="guard"), st.line, checks)
        self.emit(2, 0, f"_R.guard({st.name}, {st.name!r})", st.line)

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
                         f"route {st.method} \"{path}\" ({pp}: Int) 처럼 타입과 함께 선언하세요", col=st.pcol)
        for prm in st.params:
            if prm.name != "req" and prm.typ is None:
                self.err("E303", f"라우트 파라미터 '{prm.name}' 에 타입이 없어요 (입력 검증 불가)", prm,
                         f"{prm.name}: Str 처럼 타입을 적으세요")
            elif prm.name != "req":
                loose = self.unbounded(prm.typ, prm.name)
                if loose:
                    where = ", ".join(f"{p} ({k})" for p, k in loose[:4]) + (" …" if len(loose) > 4 else "")
                    msg = f"범위가 선언되지 않은 입력: {where}"
                    hint = "Str(1, 80) · Int(0, 1000) · List[Str](0, 20) 처럼 최소/최대를 적으세요"
                    if self.p.strict_inputs:
                        self.err("E305", msg, prm, hint)
                    else:
                        self.p.warn("W304", msg, self.file, prm.line, prm.col, hint + " (기본 상한만 적용 중)")
        if st.access is None:
            self.err("E301", f"{st.method} {path} 에 접근 정책이 없어요 (기본 거부)", st,
                     "경로 뒤에 'public' 또는 'guard <이름>' 을 붙이세요. 미들웨어가 아니라 라우트마다 명시해요")
            access = "('deny',)"
        elif st.access[0] == "public":
            access = "('public',)"
            if st.method != "GET":
                self.warn("W303", f"{st.method} {path} 는 인증 없이 데이터를 바꿀 수 있어요", st, "의도한 게 아니라면 guard 를 붙이세요")
        elif st.access[1] == "bearer" and "bearer" not in self.p.guards:
            access = "('guard', _R.bearer)"
            self.p.uses_bearer = True
        else:
            gname = st.access[1]
            if gname not in self.p.guards:
                kind = self.p.symbols.get(gname, (None,))[0]
                msg = f"'{gname}' 은(는) guard 가 아니에요 ({kind})" if kind else f"guard '{gname}' 이(가) 없어요"
                self.p.error("E302", msg, self.file, st.access[2], st.access[3],
                             did_you_mean(gname, self.p.guards) or "guard 이름(req): 로 먼저 선언하세요", len(gname))
            access = f"('guard', {gname})" if gname in self.p.guards else "('deny',)"
        n = self.p.uid()
        fname = f"_route_{n}"
        scope = Scope(self.module, "fn")
        names = []
        specs = []
        for prm in st.params:
            if prm.name.startswith("_"):
                self.err("E105", "파라미터 이름은 '_' 로 시작할 수 없어요", prm)
            scope.names[prm.name] = "param"
            names.append(prm.name)
            default = self.expr(prm.default, self.module) if prm.default is not None else "_R.NODEF"
            src = "path" if prm.name in path_params else ("req" if prm.name == "req" else ("body" if prm.name == "body" else "query"))
            t = "None" if prm.name == "req" else self.ty(prm.typ)
            specs.append(f"({prm.name!r}, {t}, {default}, {src!r})")
        self._body(4, f"def {fname}({', '.join(names)}):", st.body, scope, Ctx(True, None, kind="route"), st.line)
        self.emit(4, 0, f"_R.route({st.method!r}, {path!r}, {fname}, [{', '.join(specs)}], {access}, {st.doc!r})", st.line)
        self.p.routes.append({"method": st.method, "path": path, "file": self.file, "line": st.line, "doc": st.doc,
                              "access": st.access[0] if st.access else "deny",
                              "guard": st.access[1] if st.access and st.access[0] == "guard" else None,
                              "params": [(p.name, p.typ, p.name in path_params) for p in st.params]})

    def c_task(self, st):
        n = self.p.uid()
        scope = Scope(self.module, "fn")
        self._body(4, f"def _task_{n}():", st.body, scope, Ctx(True, kind="task"), st.line)
        self.emit(4, 0, f"_R.task({st.name!r}, {st.period!r}, _task_{n})", st.line)
        self.p.tasks.append({"name": st.name, "period": st.period, "file": self.file, "line": st.line, "doc": st.doc})

    def c_test(self, st):
        n = self.p.uid()
        scope = Scope(self.module, "fn")
        scope.names["client"] = "builtin"
        self._body(4, f"def _test_{n}():", st.body, scope, Ctx(True, kind="test"), st.line)
        self.emit(4, 0, f"_R.test({st.name!r}, _test_{n}, {self.file!r}, {st.line})", st.line)
        self.p.tests.append({"name": st.name, "file": self.file, "line": st.line})

    # ---------- 문장 ----------
    def stmt(self, s, scope, em, ind, ctx):
        k = s.kind
        E = lambda text, line=None: em.emit(ind, text, self.file, line or s.line)
        if k in ("Let", "Var"):
            if s.name.startswith("_"):
                self.err("E105", f"이름 '{s.name}' 은(는) '_' 로 시작할 수 없어요", s, col=s.ncol)
            value = self.expr(s.value, scope)
            if scope.kind == "module":
                pass  # 사전 수집됨
            else:
                if s.name in scope.names and scope.names[s.name] not in ("loop",):
                    self.err("E103", f"'{s.name}' 이(가) 이 함수 안에서 이미 선언됐어요", s, col=s.ncol,
                             hint="값을 바꾸려면 처음에 var 로 선언하고 '이름 = 값' 으로 대입하세요")
                scope.names[s.name] = "let" if k == "Let" else "var"
            if s.typ is not None:
                value = f"_R.check({value}, {self.ty(s.typ)}, {s.name!r})"
            E(f"{s.name} = {value}")
        elif k == "Assign":
            value = self.expr(s.value, scope)
            t = s.target
            if t.kind == "Name":
                kind, owner = scope.lookup(t.id)
                if kind is None:
                    self.err("E101", f"선언되지 않은 이름 '{t.id}' 에 대입했어요", t,
                             f"새 변수는 'var {t.id} = 값' 으로 선언하세요")
                elif kind != "var":
                    if kind == "let":
                        self.err("E102", f"'{t.id}' 은(는) let 으로 선언된 불변 값이라 바꿀 수 없어요", t,
                                 "바꿔야 하는 값이면 'var' 로 선언하세요")
                    else:
                        self.err("E102", f"{ {'param': '파라미터', 'loop': '반복 변수', 'fn': '함수', 'type': '타입', 'guard': 'guard', 'module': '모듈', 'builtin': '내장 함수', 'catch': '오류 변수'}.get(kind, kind)} '{t.id}' 에는 대입할 수 없어요", t,
                                 f"'var 새이름 = {t.id}' 처럼 복사해서 쓰세요")
                elif owner.kind == "module" and scope.kind != "module":
                    ctx.fn_globals.add(t.id)
                target = t.id
            else:
                target = self.expr(t, scope)
            E(f"{target} {s.op} {value}")
        elif k == "ExprStmt":
            E(self.expr(s.expr, scope))
        elif k == "Return":
            if not ctx.in_fn:
                self.err("E002", "함수 밖에서는 return 할 수 없어요", s)
            v = self.expr(s.value, scope) if s.value is not None else "None"
            if ctx.ret:
                v = f"_R.check({v}, {ctx.ret}, '반환값')"
            E(f"return {v}")
        elif k in ("Break", "Continue"):
            if ctx.loop == 0:
                self.err("E002", f"반복문 밖에서는 {k.lower()} 할 수 없어요", s)
            E(k.lower())
        elif k == "Pass":
            E("pass")
        elif k == "If":
            for i, (cond, body) in enumerate(s.branches):
                E(("if " if i == 0 else "elif ") + self.expr(cond, scope) + ":", cond.line)
                self.block(body, scope, em, ind + 1, ctx, s.line)
            if s.orelse is not None:
                E("else:")
                self.block(s.orelse, scope, em, ind + 1, ctx, s.line)
        elif k == "While":
            E(f"while {self.expr(s.cond, scope)}:")
            ctx.loop += 1
            self.block(s.body, scope, em, ind + 1, ctx, s.line)
            ctx.loop -= 1
        elif k == "For":
            it = self.expr(s.iter, scope)
            for nm in s.names:
                if nm.startswith("_"):
                    self.err("E105", "반복 변수는 '_' 로 시작할 수 없어요", s)
                prev = scope.names.get(nm)
                if prev not in (None, "loop") and scope.kind != "module":
                    self.err("E103", f"'{nm}' 이(가) 이미 선언된 이름이라 반복 변수로 쓸 수 없어요", s)
                scope.names[nm] = "loop"
            E(f"for {', '.join(s.names)} in {it}:")
            ctx.loop += 1
            self.block(s.body, scope, em, ind + 1, ctx, s.line)
            ctx.loop -= 1
        elif k == "Try":
            E("try:")
            self.block(s.body, scope, em, ind + 1, ctx, s.line)
            n = self.p.uid()
            em.emit(ind, f"except Exception as _exc_{n}:", self.file, s.cline)
            scope.names[s.name] = "catch"
            em.emit(ind + 1, f"{s.name} = _R.err(_exc_{n})", self.file, s.cline)
            self.block(s.handler, scope, em, ind + 1, ctx, s.cline)
        else:
            self.err("E002", f"여기에 {k} 는 올 수 없어요", s)

    def block(self, body, scope, em, ind, ctx, line):
        before = len(em.lines)
        for s in body:
            self.stmt(s, scope, em, ind, ctx)
        if len(em.lines) == before:
            em.emit(ind, "pass", self.file, line)

    # ---------- 표현식 ----------
    def ref(self, node, scope):
        name = node.id
        if name.startswith("_"):
            self.err("E105", f"'{name}' 처럼 '_' 로 시작하는 이름은 쓸 수 없어요", node, "샌드박스 보호 규칙이에요")
            return "None"
        kind, _ = scope.lookup(name)
        if kind is None:
            hint = did_you_mean(name, scope.all_names())
            if not hint and name in STD_MODULES:
                hint = f"파일 위에 'use std.{name}' 을 추가하세요"
            elif not hint and name == "client":
                hint = "client 는 test 블록 안에서만 쓸 수 있어요"
            self.err("E101", f"선언되지 않은 이름 '{name}'", node, hint)
            return "None"
        if name == "unsafe_html":
            self.warn("W301", "unsafe_html 은 이스케이프를 끄고 HTML 을 그대로 넣어요 (XSS 위험)", node,
                      "신뢰할 수 있는 고정 문자열에만 쓰세요. sori audit 에 기록돼요")
        return name

    def expr(self, e, scope):
        if e is None:
            return "None"
        k = e.kind
        if k == "Num":
            return repr(e.value)
        if k == "Const":
            return repr(e.value)
        if k == "Name":
            return self.ref(e, scope)
        if k == "Str":
            return self.string(e, scope)
        if k == "List":
            return "[" + ", ".join(self.expr(x, scope) for x in e.items) + "]"
        if k == "Map":
            return "{" + ", ".join(f"{self.expr(a, scope)}: {self.expr(b, scope)}" for a, b in e.pairs) + "}"
        if k == "Attr":
            obj = self.expr(e.obj, scope)
            if e.name.startswith("_"):
                self.err("E105", f"'_' 로 시작하는 속성 '{e.name}' 에는 접근할 수 없어요", e,
                         "파이썬 내부 객체(__class__, __globals__ 등)로의 샌드박스 탈출을 막는 규칙이에요")
            elif e.name in FORBIDDEN_ATTRS:
                self.err("E106", f"속성 '{e.name}' 은(는) 샌드박스 보호를 위해 막혀 있어요", e,
                         "문자열 조합은 \"...{값}...\" 보간을 쓰세요" if e.name in ("format", "format_map") else None)
            return f"{obj}.{e.name}"
        if k == "Index":
            obj = self.expr(e.obj, scope)
            if e.slice:
                lo = self.expr(e.index, scope) if e.index is not None else ""
                hi = self.expr(e.hi, scope) if e.hi is not None else ""
                return f"{obj}[{lo}:{hi}]"
            return f"{obj}[{self.expr(e.index, scope)}]"
        if k == "Call":
            f = e.func
            if (f.kind == "Attr" and f.name == "call" and f.obj.kind == "Name" and self.std_alias.get(f.obj.id) == "worker"
                    and e.args and e.args[0].kind == "Str" and len(e.args[0].parts) == 1 and e.args[0].parts[0][0] == "lit"):
                wname = e.args[0].parts[0][1]
                if wname not in self.p.workers:
                    self.err("E201", f"워커 '{wname}' 이(가) sori.toml 에 선언되지 않았어요", e.args[0],
                             did_you_mean(wname, self.p.workers) or f"[workers.{wname}] url = \"http://127.0.0.1:9010/invoke\" 를 추가하세요")
            fn = self.expr(e.func, scope)
            args = [self.expr(a, scope) for a in e.args]
            for name, v, line, col in e.kwargs:
                if name.startswith("_"):
                    self.p.error("E105", "인자 이름은 '_' 로 시작할 수 없어요", self.file, line, col)
                args.append(f"{name}={self.expr(v, scope)}")
            return f"{fn}({', '.join(args)})"
        if k == "BinOp":
            return f"({self.expr(e.left, scope)} {e.op} {self.expr(e.right, scope)})"
        if k == "Unary":
            return f"({e.op}{self.expr(e.operand, scope)})"
        if k == "Not":
            return f"(not {self.expr(e.operand, scope)})"
        if k == "BoolOp":
            return f"({self.expr(e.left, scope)} {e.op} {self.expr(e.right, scope)})"
        if k == "Compare":
            s = self.expr(e.left, scope)
            for op, r in zip(e.ops, e.rights):
                s += f" {op} {self.expr(r, scope)}"
            return f"({s})"
        if k == "IfExp":
            return f"({self.expr(e.then, scope)} if {self.expr(e.cond, scope)} else {self.expr(e.orelse, scope)})"
        if k == "Lambda":
            ls = Scope(scope, "lambda")
            names, _ = self._params(e.params, ls, allow_types=False)
            return f"(lambda {', '.join(names)}: {self.expr(e.body, ls)})"
        self.err("E002", f"알 수 없는 식 {k}", e)
        return "None"

    def string(self, e, scope):
        lits, exprs, ctxs = [], [], []
        acc = ""
        pending = ""
        for part in e.parts:
            if part[0] == "lit":
                pending += part[1]
            else:
                lits.append(pending)
                acc += pending
                pending = ""
                if e.tag == "html":
                    ctxs.append(self.html_context(acc, part[1]))
                exprs.append(self.expr(part[1], scope))
        lits.append(pending)
        if e.tag == "" and not exprs:
            return repr(lits[0])
        L = "(" + ", ".join(repr(x) for x in lits) + ",)"
        X = "(" + ", ".join(exprs) + ("," if exprs else "") + ")"
        if e.tag == "sql":
            return f"_R.sql({L}, {X})"
        if e.tag == "html":
            C = "(" + ", ".join(repr(c) for c in ctxs) + ("," if ctxs else "") + ")"
            return f"_R.html({L}, {X}, {C})"
        return f"_R.cat({L}, {X})"

    def html_context(self, before, node):
        """정적 텍스트만 보고 보간 위치의 HTML 문맥을 결정 (Go html/template 방식의 단순화)."""
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
        if lt > gt:  # 태그 내부
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
    proj = Project(files, config).build()
    return proj
