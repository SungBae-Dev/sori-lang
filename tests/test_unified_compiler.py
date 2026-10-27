"""통합 컴파일러: 컴파일 타임 보안 차단, 정적 타입, Effect 정책, IR v2 생성·결정성·구조 검증."""
import ast
import json
import shutil
import unittest
from pathlib import Path

from sori.lang.ir import IR_VERSION, canonical, json_schema, validate
from sori_util import ROOT, build, codes


class CompileTimeSecurity(unittest.TestCase):
    CASES = [
        ("샌드박스 탈출: __class__ 접근", 'let x = (1).__class__\n', "E105"),
        ("샌드박스 탈출: format 문자열 공격", 'let s = "{{0}}".format(1)\n', "E106"),
        ("런타임 내부 이름 접근", 'let x = _R\n', "E105"),
        ("미선언 파이썬 패키지", 'use py os\n', "E201"),
        ("net 권한 없이 std.http", 'use std.http\n', "E201"),
        ("접근 정책 없는 라우트", 'route GET "/admin":\n    return "x"\n', "E301"),
        ("guard 자리에 일반 함수", 'fn f(req):\n    return true\nroute GET "/a" guard f:\n    return "x"\n', "E302"),
        ("경로 파라미터 미선언", 'route GET "/u/{id}" public:\n    return "x"\n', "E303"),
        ("타입 없는 라우트 파라미터", 'route GET "/u" (q) public:\n    return q\n', "E303"),
        ("중복 라우트", 'route GET "/a" public:\n    return "1"\nroute GET "/a" public:\n    return "2"\n', "E304"),
        ("<script> 안 보간", 'let v = "x"\nlet h = html"<script>var a = {v}</script>"\n', "E401"),
        ("onclick 속성 보간", 'let v = "x"\nlet h = html"<b onclick=\\"{v}\\">x</b>"\n', "E401"),
        ("따옴표 없는 속성 보간", 'let v = "x"\nlet h = html"<a href={v}>x</a>"\n', "E401"),
        ("let 재할당", 'let a = 1\na = 2\n', "E102"),
        ("오타 (did-you-mean)", 'let count = 1\nprint(cuont)\n', "E101"),
        ("파이썬 예약어를 이름으로", 'let class = 1\n', "E104"),
        ("범위 없는 입력은 기본으로 오류 (strict_inputs)", 'route GET "/s" (q: Str) public:\n    return q\n', "E305"),
        ("unsafe_html 경고", 'let h = unsafe_html("<b>x</b>")\n', "W301"),
        ("인증 없는 공개 쓰기 경고", 'route POST "/x" public:\n    return "ok"\n', "W303"),
        # 정적 타입 (B1 typed IR 규칙 계승 + 확장)
        ("Str + Int", 'let n = "a" + 1\n', "E107"),
        ("Bool 을 숫자처럼", 'let n = true - 1\n', "E107"),
        ("문자열 크기 비교 vs 숫자", 'let b = "a" > 3\n', "E107"),
        ("선언 타입 불일치", 'let x: Int = "a"\n', "E107"),
        ("반환 타입 불일치", 'fn f() -> Int:\n    return "x"\n', "E107"),
        ("함수 인자 타입 불일치", 'fn f(x: Int) -> Int:\n    return x\nlet y = f("a")\n', "E107"),
        ("레코드 없는 필드", 'type P:\n    a: Int\nlet p = P(a=1)\nlet q = p.b\n', "E108"),
        ("레코드 생성자 없는 필드", 'type P:\n    a: Int\nlet p = P(a=1, z=2)\n', "E108"),
        ("std 모듈에 없는 기능", 'use std.json\nlet x = json.eval("1")\n', "E108"),
        ("과대 숫자 상수", 'let x = 10000000000000\n', "E002"),
        ("문자열 SQL", 'use std.db\nlet q = "SELECT 1"\nlet r = db.all(q)\n', "E109"),
    ]

    def test_cases(self):
        for name, src, code in self.CASES:
            with self.subTest(name=name):
                toml = '[permissions]\ndb = ["sqlite::memory:"]\n' if "std.db" in src else "[permissions]\n"
                d, app, diags = build(src, toml)
                try:
                    self.assertIn(code, codes(diags), [x.render(app.sources) for x in diags])
                finally:
                    shutil.rmtree(d)

    def test_public_route_cannot_reach_worker_even_through_function(self):
        src = ('use std.worker\nfn helper() -> Json:\n    return worker.call("m", {})\n'
               'route POST "/x" public:\n    return helper()\n')
        toml = '[permissions]\n[workers.m]\nurl = "http://127.0.0.1:9010/invoke"\ntimeout_ms = 500\n'
        d, app, diags = build(src, toml)
        try:
            self.assertIn("E306", codes(diags))
        finally:
            shutil.rmtree(d)

    def test_indirect_worker_paths_are_blocked(self):
        """PR #3 리뷰 P1: 별칭·함수값·고차함수·람다·컬렉션 저장으로 public 라우트가 워커에 닿으면 안 된다."""
        toml = '[permissions]\n[workers.m]\nurl = "http://127.0.0.1:9010/invoke"\ntimeout_ms = 500\n'
        head = 'use std.worker\nfn call_it(b: Json) -> Json:\n    return worker.call("m", b)\n'
        cases = {
            "std 함수 별칭": ('use std.worker\nlet invoke_model = worker.call\n'
                          'route POST "/p" public:\n    return invoke_model("m", {})\n', "E110"),
            "std 모듈 별칭": ('use std.worker\nlet w = worker\nroute POST "/p" public:\n    return w.call("m", {})\n', "E110"),
            "std 함수를 인자로": ('use std.worker\nfn apply(f, x):\n    return f("m", x)\n'
                           'route POST "/p" public:\n    return apply(worker.call, {})\n', "E110"),
            "전역 함수 별칭": (head + 'let h = call_it\nroute POST "/p" public:\n    return h({})\n', "E306"),
            "맵에 저장": (head + 'let table = {go: call_it}\nroute POST "/p" public:\n    return table["go"]({})\n', "E306"),
            "목록에 저장": (head + 'let fs = [call_it]\nroute POST "/p" public:\n    return fs[0]({})\n', "E306"),
            "함수가 함수를 반환": (head + 'fn pick():\n    return call_it\nroute POST "/p" public:\n    return pick()({})\n', "E306"),
            "고차 함수 파라미터": (head + 'fn apply(f, x):\n    return f(x)\nroute POST "/p" public:\n    return apply(call_it, {})\n', "E306"),
            "다른 라우트가 람다 교체": ('use std.worker\nvar cb = fn(b) => b\nfn arm():\n    cb = fn(b) => worker.call("m", b)\n'
                              'route POST "/arm" guard bearer:\n    arm()\n    return {ok: true}\n'
                              'route POST "/p" public:\n    return cb({})\n', "E306"),
            "람다가 함수 호출": (head + 'let g = fn(x) => call_it(x)\nroute POST "/p" public:\n    return g({})\n', "E306"),
            "레코드 필드에 저장": (head + 'type Box:\n    f: Any\nlet box = Box(f=call_it)\n'
                            'route POST "/p" public:\n    return box.f({})\n', "E306"),
        }
        for name, (src, code) in cases.items():
            with self.subTest(name):
                d, app, diags = build(src, toml)
                try:
                    self.assertIn(code, codes(diags), [x.render(app.sources) for x in diags])
                finally:
                    shutil.rmtree(d)

    def test_indirect_ai_call_warns_on_public_route(self):
        toml = '[permissions]\nnet = ["api.anthropic.com"]\n[ai]\nmock = true\n'
        src = ('use std.ai\ntype T:\n    a: Str(1, 5)\nfn ask(x: Str) -> T:\n    return ai.extract(T, x)\n'
               'let f = ask\nroute GET "/p" (q: Str(1, 10)) public:\n    return f(q)\n')
        d, app, diags = build(src, toml)
        try:
            self.assertIn("W305", codes(diags))
        finally:
            shutil.rmtree(d)

    def test_dynamic_calls_without_effectful_escapes_are_not_flagged(self):
        """보수적 분석이지만, 값으로 빠져나간 함수에 워커 효과가 없으면 public 라우트를 막지 않는다."""
        toml = '[permissions]\n[workers.m]\nurl = "http://127.0.0.1:9010/invoke"\ntimeout_ms = 500\n'
        src = ('use std.worker\nfn double(x: Int) -> Int:\n    return x * 2\nlet ops = {d: double}\n'
               'fn guarded_call() -> Json:\n    return worker.call("m", {})\n'
               'route GET "/p" (n: Int(0, 10)) public:\n    return {v: ops["d"](n), w: map([1, 2], fn(x) => x + 1)}\n'
               'route POST "/w" guard bearer:\n    return guarded_call()\n')
        d, app, diags = build(src, toml)
        try:
            self.assertNotIn("E306", codes(diags), [x.render(app.sources) for x in diags])
            self.assertFalse([x for x in diags if x.severity == "error"])
        finally:
            shutil.rmtree(d)

    def test_tampered_ir_cannot_use_std_function_as_value(self):
        from sori.lang.ir import validate
        toml = '[permissions]\n[workers.m]\nurl = "http://127.0.0.1:9010/invoke"\ntimeout_ms = 500\n'
        src = 'use std.worker\nroute POST "/p" guard bearer:\n    return worker.call("m", {})\n'
        d, app, diags = build(src, toml)
        try:
            ir = json.loads(json.dumps(app.ir))
            call = ir["routes"][0]["body"][0]["x"]
            self.assertEqual(call["fn"]["op"], "std")
            ir["routes"][0]["body"][0]["x"] = call["fn"]  # 호출하지 않고 std 함수 자체를 반환하도록 변조
            self.assertTrue(any("std" in p for p in validate(ir)))
        finally:
            shutil.rmtree(d)

    def test_worker_name_must_be_literal_and_declared(self):
        toml = '[permissions]\n[workers.m]\nurl = "http://127.0.0.1:9010/invoke"\n'
        for src in ('use std.worker\nlet n = "m"\nroute POST "/x" guard bearer:\n    return worker.call(n, {})\n',
                    'use std.worker\nroute POST "/x" guard bearer:\n    return worker.call("other", {})\n'):
            d, app, diags = build(src, toml)
            try:
                self.assertIn("E201", codes(diags))
            finally:
                shutil.rmtree(d)

    def test_worker_url_policy_is_loopback_only(self):
        for url in ("http://example.com/invoke", "http://169.254.169.254/x", "https://127.0.0.1:9010/x",
                    "http://127.0.0.1:9010/x?u=evil", "http://127.0.0.1:80/x"):
            d, app, diags = build('let x = 1\n', f'[workers.m]\nurl = "{url}"\n')
            try:
                self.assertIn("E203", codes(diags), url)
            finally:
                shutil.rmtree(d)

    def test_use_py_requires_explicit_dev_flag(self):
        d, app, diags = build('use py json\n', '[permissions]\npython = ["json"]\n')
        try:
            self.assertIn("E201", codes(diags))
        finally:
            shutil.rmtree(d)
        d, app, diags = build('use py json\n', '[permissions]\npython = ["json"]\n[dev]\nin_process_python = true\n')
        try:
            self.assertNotIn("E201", codes(diags))
            self.assertIn("W306", codes(diags))
        finally:
            shutil.rmtree(d)

    def test_diagnostic_has_fix_hint_for_ai(self):
        d, app, diags = build('let count = 1\nprint(cuont)\n')
        try:
            j = diags[0].to_dict()
            self.assertEqual(j["code"], "SORI-E101")
            self.assertIn("count", j["hint"])
            self.assertEqual((j["line"], j["col"]), (2, 7))
        finally:
            shutil.rmtree(d)

    def test_valid_program_has_no_false_positives(self):
        for ex in ("todo", "robot", "secure-api"):
            from sori.framework.app import build_app
            app, diags = build_app(ROOT / "examples" / ex)
            self.assertEqual([x.render(app.sources) for x in diags if x.severity == "error"], [], ex)


class TypedIRv2(unittest.TestCase):
    def _ir(self, ex):
        from sori.framework.app import build_app
        app, _ = build_app(ROOT / "examples" / ex)
        return app.ir

    def test_ir_is_valid_versioned_and_deterministic(self):
        for ex in ("todo", "robot", "secure-api"):
            with self.subTest(ex=ex):
                a, b = self._ir(ex), self._ir(ex)
                self.assertEqual(a["ir_version"], IR_VERSION)
                self.assertEqual(validate(a), [])
                self.assertEqual(canonical(a), canonical(b))

    def test_ir_has_no_worker_urls_or_secrets(self):
        enc = canonical(self._ir("secure-api"))
        self.assertNotIn("127.0.0.1:9010", enc)
        self.assertIn('"workers":[{"name":"risk_model","timeout_ms":1200}]', enc)

    def test_ir_carries_types_access_effects_and_contracts(self):
        ir = self._ir("todo")
        routes = {(r["method"], r["path"]): r for r in ir["routes"]}
        post = routes[("POST", "/api/todos")]
        self.assertEqual(post["access"], {"kind": "guard", "guard": "admin"})
        self.assertEqual(post["params"][0]["type"], {"k": "Ref", "name": "NewTodo"})
        self.assertIn("db", post["effects"])
        self.assertIn("env", post["effects"])  # guard 의 효과도 라우트에 전이
        get_one = routes[("GET", "/api/todos/{id}")]
        self.assertEqual(get_one["params"][0]["type"], {"k": "Int", "lo": 1, "hi": 1000000000})
        self.assertEqual(get_one["returns"], "Todo?")
        rec = {t["name"]: t for t in ir["types"]}["NewTodo"]
        self.assertEqual(rec["fields"][0]["type"], {"k": "Str", "lo": 1, "hi": 200})

    def test_validator_rejects_tampered_ir(self):
        ir = self._ir("secure-api")
        bad = json.loads(canonical(ir))
        bad["routes"][0]["body"].append({"op": "exec", "at": [0, 1, 1], "code": "import os"})
        self.assertTrue(validate(bad))
        bad2 = json.loads(canonical(ir))
        bad2["routes"][0]["body"][0]["x"] = {"op": "field", "t": "Dyn", "at": [0, 1, 1], "name": "__class__",
                                             "obj": {"op": "lit", "t": "Int", "v": 1, "at": [0, 1, 1]}}
        self.assertTrue(validate(bad2))
        bad3 = json.loads(canonical(ir))
        bad3["workers"][0]["url"] = "http://evil"
        self.assertTrue(validate(bad3))

    def test_tampered_ir_is_refused_by_interpreter(self):
        from sori.framework.app import build_app
        from sori.framework.core import SecurityError
        app, _ = build_app(ROOT / "examples" / "secure-api")
        app.ir["routes"][0]["body"].append({"op": "exec", "at": [0, 1, 1]})
        with self.assertRaises(SecurityError):
            app.load()

    def test_tampered_ir_field_access_on_std_module_is_refused_at_runtime(self):
        """구조상 유효한 IR 이라도 std 모듈을 field 로 꺼내 쓰면 런타임이 거부한다 (심층 방어)."""
        import os
        from sori.framework.app import build_app
        from sori.framework.web import dispatch
        os.environ["SORI_API_TOKEN"] = "t" * 40
        app, _ = build_app(ROOT / "examples" / "secure-api")
        app.access_log = False
        self.assertEqual(app.startup_problems("serve"), [])
        route = next(r for r in app.ir["routes"] if r["path"] == "/risk")
        call = route["body"][0]["x"]
        self.assertEqual(call["fn"]["op"], "std")
        call["fn"] = {"op": "field", "t": "Dyn", "at": call["fn"]["at"], "obj": call["fn"]["obj"], "name": "call"}
        app.load()
        status, _, body = dispatch(app, "POST", "/risk", {"host": "localhost", "content-type": "application/json",
                                                           "authorization": "Bearer " + "t" * 40},
                                   b'{"signal": 0.5}', "127.0.0.1")
        self.assertEqual(status, 403, body)  # SecurityError → 403 (SORI-R200), 워커 호출까지 가지 않음
        self.assertIn(b"SORI-R200", body)

    def test_schema_document_in_sync(self):
        on_disk = json.loads((ROOT / "docs" / "ir-v2.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(on_disk, json_schema())


class NoDynamicExecution(unittest.TestCase):
    """런타임 경로에 eval/exec/compile 이 없음을 AST 로 확인 (문자열 grep 보다 엄격)."""

    def test_no_eval_exec_compile(self):
        offenders = []
        for py in (ROOT / "sori").rglob("*.py"):
            tree = ast.parse(py.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    f = node.func
                    name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) and
                                                                 isinstance(f.value, ast.Name) and f.value.id == "builtins" else None)
                    if name in ("eval", "exec", "compile", "__import__"):
                        offenders.append(f"{py.relative_to(ROOT)}:{node.lineno} {name}()")
        self.assertEqual(offenders, [])

    def test_import_module_only_in_dev_python_path(self):
        hits = []
        for py in (ROOT / "sori").rglob("*.py"):
            for i, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
                if "import_module(" in line:
                    hits.append(str(py.relative_to(ROOT)))
        self.assertEqual(sorted(set(hits)), [str(Path("sori/framework/interp.py"))])


if __name__ == "__main__":
    unittest.main()
