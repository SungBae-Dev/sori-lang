"""SORI Typed IR v2 — 구조 정의·검증·정규화.

IR 은 실행 가능한 코드가 아니라 데이터다. 백엔드(Python 해석기, Rust 해석기)는 이 모듈이 정의한
문장/식 종류만 실행해야 하며, 모르는 op 를 만나면 실행을 거부한다.
서명되지 않은 외부 IR 파일을 신뢰된 코드로 취급하지 말 것 — 검증은 구조 검사일 뿐 출처 증명이 아니다.
"""
import json

IR_VERSION = "sori/ir/v2"

STMT_FIELDS = {
    "let": {"name", "mutable", "scope", "type", "value"},
    "assign": {"target", "o", "value"},
    "expr": {"x"},
    "if": {"branches", "else"},
    "while": {"c", "body"},
    "for": {"names", "scope", "iter", "body"},
    "return": {"x"},
    "break": set(), "continue": set(), "pass": set(),
    "try": {"body", "name", "scope", "handler"},
}
EXPR_FIELDS = {
    "lit": {"v"}, "var": {"name", "scope"}, "list": {"items"}, "map": {"pairs"},
    "field": {"obj", "name"}, "std": {"obj", "module", "name"}, "index": {"obj", "index"},
    "slice": {"obj", "lo", "hi"}, "call": {"fn", "args", "kwargs"}, "binop": {"o", "l", "r"},
    "unop": {"o", "x"}, "not": {"x"}, "logic": {"o", "l", "r"}, "compare": {"l", "ops", "rs"},
    "cond": {"c", "then", "orelse"}, "lambda": {"params", "body"},
    "cat": {"lits", "args"}, "sql": {"lits", "args"}, "html": {"lits", "args", "ctx"},
}
BINOPS = {"+", "-", "*", "/", "//", "%"}
CMPOPS = {"==", "!=", "<", ">", "<=", ">=", "in", "not in"}
ASSIGN_OPS = {"=", "+=", "-=", "*=", "/="}
SCOPES = {"local", "global", "builtin"}
TYPE_KINDS = {"Int", "Float", "Str", "Bool", "Json", "Html", "Secret", "Any", "List", "Map", "Opt", "Ref"}
HTML_CTX = {"text", "attr", "url"}
TOP_KEYS = {"ir_version", "app", "files", "source_digest", "permissions", "workers", "types", "functions",
            "guards", "init", "routes", "tasks", "tests", "uses"}
ACCESS = {"public", "bearer", "guard", "deny"}
SOURCES = {"path", "query", "body", "req"}


def canonical(ir):
    """결정적 직렬화 (같은 소스 → 바이트 단위로 같은 JSON)."""
    return json.dumps(ir, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


class _V:
    def __init__(self):
        self.problems = []

    def bad(self, path, msg):
        if len(self.problems) < 50:
            self.problems.append(f"{path}: {msg}")

    def ty(self, t, path):
        if t is None:
            return
        if not isinstance(t, dict) or t.get("k") not in TYPE_KINDS:
            return self.bad(path, "잘못된 타입 노드")
        if t["k"] in ("List", "Map", "Opt"):
            self.ty(t.get("of"), path + ".of")
        if t["k"] == "Ref" and not isinstance(t.get("name"), str):
            self.bad(path, "Ref 에 name 이 없어요")
        if ("lo" in t) != ("hi" in t):
            self.bad(path, "범위는 lo/hi 둘 다 있어야 해요")

    def expr(self, n, path, depth=0, callee=False):
        if depth > 200:
            return self.bad(path, "식이 너무 깊어요")
        if not isinstance(n, dict) or n.get("op") not in EXPR_FIELDS:
            return self.bad(path, f"알 수 없는 식 op {n.get('op') if isinstance(n, dict) else n!r}")
        op = n["op"]
        missing = EXPR_FIELDS[op] - set(n)
        if missing:
            self.bad(path, f"{op} 에 필드 누락: {sorted(missing)}")
        if not isinstance(n.get("t"), str):
            self.bad(path, f"{op} 에 정적 타입(t)이 없어요")
        if op == "var" and n.get("scope") not in SCOPES:
            self.bad(path, "var.scope 오류")
        if op == "binop" and n.get("o") not in BINOPS:
            self.bad(path, f"허용되지 않는 연산자 {n.get('o')}")
        if op == "compare" and any(o not in CMPOPS for o in n.get("ops", [])):
            self.bad(path, "허용되지 않는 비교 연산자")
        if op == "logic" and n.get("o") not in ("and", "or"):
            self.bad(path, "logic.o 오류")
        if op == "unop" and n.get("o") not in ("-", "+"):
            self.bad(path, "unop.o 오류")
        if op == "std" and not callee:
            self.bad(path, "std 함수는 호출 위치(call.fn)에만 올 수 있어요 — 값으로 저장·전달 불가")
        if op in ("field", "std") and (not isinstance(n.get("name"), str) or n["name"].startswith("_")):
            self.bad(path, "'_' 로 시작하는 속성은 IR 에 있을 수 없어요")
        if op == "html" and any(c not in HTML_CTX for c in n.get("ctx", [])):
            self.bad(path, "html.ctx 오류")
        if op in ("cat", "sql", "html") and len(n.get("lits", [])) != len(n.get("args", [])) + 1:
            self.bad(path, f"{op}: lits 는 args 보다 1개 많아야 해요")
        if op == "lit" and not (n.get("v") is None or isinstance(n.get("v"), (bool, int, float, str))):
            self.bad(path, "lit 은 스칼라만")
        for key in ("obj", "index", "l", "r", "x", "c", "then", "orelse", "fn", "body"):
            if isinstance(n.get(key), dict):
                self.expr(n[key], f"{path}.{key}", depth + 1, callee=(op == "call" and key == "fn"))
        for key in ("items", "args", "rs"):
            for i, x in enumerate(n.get(key, []) or []):
                self.expr(x, f"{path}.{key}[{i}]", depth + 1)
        for key in ("lo", "hi"):
            if op == "slice" and n.get(key) is not None:
                self.expr(n[key], f"{path}.{key}", depth + 1)
        for i, pair in enumerate(n.get("pairs", []) or []):
            self.expr(pair[0], f"{path}.pairs[{i}].k", depth + 1)
            self.expr(pair[1], f"{path}.pairs[{i}].v", depth + 1)
        for i, kv in enumerate(n.get("kwargs", []) or []):
            if not isinstance(kv[0], str) or kv[0].startswith("_"):
                self.bad(path, "kwargs 이름 오류")
            self.expr(kv[1], f"{path}.kwargs[{i}]", depth + 1)
        if op == "lambda":
            self.params(n.get("params", []), path + ".params")

    def params(self, ps, path):
        for i, p in enumerate(ps):
            if not isinstance(p.get("name"), str) or p["name"].startswith("_"):
                self.bad(f"{path}[{i}]", "파라미터 이름 오류")
            self.ty(p.get("type"), f"{path}[{i}].type")
            if p.get("default") is not None:
                self.expr(p["default"], f"{path}[{i}].default")

    def stmts(self, body, path, depth=0):
        if not isinstance(body, list):
            return self.bad(path, "문장 목록이 아니에요")
        for i, s in enumerate(body):
            p = f"{path}[{i}]"
            if not isinstance(s, dict) or s.get("op") not in STMT_FIELDS:
                self.bad(p, f"알 수 없는 문장 op {s.get('op') if isinstance(s, dict) else s!r}")
                continue
            op = s["op"]
            missing = STMT_FIELDS[op] - set(s)
            if missing:
                self.bad(p, f"{op} 에 필드 누락: {sorted(missing)}")
            if op == "let":
                self.ty(s.get("type"), p + ".type")
                self.expr(s["value"], p + ".value")
            elif op == "assign":
                if s.get("o") not in ASSIGN_OPS:
                    self.bad(p, "대입 연산자 오류")
                if s.get("target", {}).get("op") not in ("var", "field", "index"):
                    self.bad(p, "대입 대상 오류")
                self.expr(s["target"], p + ".target")
                self.expr(s["value"], p + ".value")
            elif op == "expr":
                self.expr(s["x"], p + ".x")
            elif op == "return" and s.get("x") is not None:
                self.expr(s["x"], p + ".x")
            elif op == "if":
                for j, (c, b) in enumerate(s["branches"]):
                    self.expr(c, f"{p}.branches[{j}].c")
                    self.stmts(b, f"{p}.branches[{j}].body", depth + 1)
                if s.get("else") is not None:
                    self.stmts(s["else"], p + ".else", depth + 1)
            elif op == "while":
                self.expr(s["c"], p + ".c")
                self.stmts(s["body"], p + ".body", depth + 1)
            elif op == "for":
                self.expr(s["iter"], p + ".iter")
                self.stmts(s["body"], p + ".body", depth + 1)
            elif op == "try":
                self.stmts(s["body"], p + ".body", depth + 1)
                self.stmts(s["handler"], p + ".handler", depth + 1)


def validate(ir):
    """구조 검증. 문제 목록을 돌려준다 (빈 목록 = 통과). 출처/서명 검증이 아니다."""
    v = _V()
    if not isinstance(ir, dict):
        return ["IR 이 객체가 아니에요"]
    if ir.get("ir_version") != IR_VERSION:
        v.bad("ir_version", f"{IR_VERSION} 이 아니에요 ({ir.get('ir_version')!r})")
    extra = set(ir) - TOP_KEYS
    if extra:
        v.bad("$", f"알 수 없는 최상위 키 {sorted(extra)}")
    for k in TOP_KEYS - set(ir):
        v.bad("$", f"최상위 키 누락 {k}")
    for i, w in enumerate(ir.get("workers", [])):
        if set(w) - {"name", "timeout_ms"}:
            v.bad(f"workers[{i}]", "워커에는 이름·타임아웃만 (URL 은 IR 에 넣지 않음)")
    for i, t in enumerate(ir.get("types", [])):
        for j, f in enumerate(t.get("fields", [])):
            v.ty(f.get("type"), f"types[{i}].fields[{j}].type")
            if f.get("default") is not None:
                v.expr(f["default"], f"types[{i}].fields[{j}].default")
    for key in ("functions", "guards"):
        for i, f in enumerate(ir.get(key, [])):
            v.params(f.get("params", []), f"{key}[{i}].params")
            v.stmts(f.get("body"), f"{key}[{i}].body")
    v.stmts(ir.get("init", []), "init")
    for i, r in enumerate(ir.get("routes", [])):
        if r.get("access", {}).get("kind") not in ACCESS:
            v.bad(f"routes[{i}]", "접근 정책 오류")
        for j, p in enumerate(r.get("params", [])):
            if p.get("source") not in SOURCES:
                v.bad(f"routes[{i}].params[{j}]", "파라미터 출처 오류")
            v.ty(p.get("type"), f"routes[{i}].params[{j}].type")
        v.stmts(r.get("body"), f"routes[{i}].body")
    for key in ("tasks", "tests"):
        for i, t in enumerate(ir.get(key, [])):
            v.stmts(t.get("body"), f"{key}[{i}].body")
    return v.problems


def json_schema():
    """IR v2 의 JSON Schema (docs/ir-v2.schema.json 과 동기화 — 테스트로 확인)."""
    expr_ops = sorted(EXPR_FIELDS)
    stmt_ops = sorted(STMT_FIELDS)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/SungBae-Dev/sori-lang/docs/ir-v2.schema.json",
        "title": "SORI Typed IR v2",
        "type": "object",
        "required": sorted(TOP_KEYS),
        "additionalProperties": False,
        "properties": {
            "ir_version": {"const": IR_VERSION},
            "app": {"type": "string"},
            "files": {"type": "array", "items": {"type": "string"}},
            "source_digest": {"type": "object", "additionalProperties": {"type": "string", "pattern": "^[0-9a-f]{64}$"}},
            "permissions": {"type": "object"},
            "workers": {"type": "array", "items": {"type": "object", "required": ["name", "timeout_ms"],
                                                   "additionalProperties": False,
                                                   "properties": {"name": {"type": "string"},
                                                                  "timeout_ms": {"type": "integer"}}}},
            "uses": {"type": "array"}, "types": {"type": "array"}, "functions": {"type": "array"},
            "guards": {"type": "array"}, "init": {"type": "array", "items": {"$ref": "#/$defs/stmt"}},
            "routes": {"type": "array", "items": {"$ref": "#/$defs/route"}},
            "tasks": {"type": "array"}, "tests": {"type": "array"},
        },
        "$defs": {
            "stmt": {"type": "object", "required": ["op", "at"], "properties": {"op": {"enum": stmt_ops}}},
            "expr": {"type": "object", "required": ["op", "t", "at"], "properties": {"op": {"enum": expr_ops},
                                                                                     "t": {"type": "string"}}},
            "type": {"type": "object", "required": ["k"], "properties": {"k": {"enum": sorted(TYPE_KINDS)}}},
            "route": {"type": "object",
                      "required": ["method", "path", "params", "access", "body", "effects", "returns", "at"],
                      "properties": {"method": {"enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
                                     "access": {"type": "object", "required": ["kind"],
                                                "properties": {"kind": {"enum": sorted(ACCESS)}}},
                                     "effects": {"type": "array", "items": {"type": "string"}}}},
        },
    }
