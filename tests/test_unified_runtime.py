"""Python Backend(IR 해석기) 런타임 보안: 권한·SSRF·SQL·비밀값·불변성·실행 상한·입력 하드닝."""
import json
import os
import shutil
import unittest

from sori.framework.core import SecurityError, SoriTypeError, Secret, html, json_dumps, respond
from sori.framework.interp import ResourceLimit
from sori.framework.web import TestClient, dispatch, _to_http
from sori_util import loaded

SRC = '''
use std.db
use std.http
use std.env
use std.fs

type Item:
    name: Str(1, 20)

type Strict:
    title: Str(1, 50)
    tags: List[Str(1, 10)](0, 100) = []
    count: Int(0, 10) = 0
    flag: Bool = false

fn raw_sql():
    let q = sql"SELECT 1"
    return db.all(json_text())

fn json_text() -> Json:
    return "SELECT 1"

fn ssrf_metadata():
    return http.get("http://169.254.169.254/latest/meta-data/")

fn ssrf_loopback():
    return http.get("https://localhost:9999/")

fn ssrf_trick_host():
    return http.get("https://0x7f.0.0.1/")

fn not_allowed_host():
    return http.get("https://evil.example.com/")

fn env_undeclared():
    return env.get("PATH")

fn catch_security():
    try:
        return fs.read("/etc/passwd")
    catch e:
        return "삼켜짐"

fn mutate():
    let t = Item(name="a")
    let u = t.copy(name="b")
    return u.name

fn open_redirect():
    return redirect("https://evil.example/")

fn secret_text():
    let s = env.secret("TOKEN")
    return "토큰={s}"

fn forever():
    var i = 0
    while true:
        i += 1

fn deep(n: Int) -> Int:
    return deep(n + 1)

fn dyn_attr(x: Json):
    return x.secret_field

fn dyn_str_mul(x: Json):
    return x * 100000000

route POST "/strict" (body: Strict) public:
    return body

route GET "/boom" public:
    let xs = [1, 2]
    return xs[10]

route GET "/loop" public:
    forever()
    return "never"
'''
TOML = '''[permissions]
db = ["sqlite::memory:"]
net = ["localhost:9999", "api.example.com"]
env = ["TOKEN"]
fs_read = ["./data"]

[limits]
request_ms = 300
max_steps = 200000
'''


class RuntimeSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["TOKEN"] = "super-secret-value"
        cls.dir, cls.app = loaded(SRC, TOML)
        cls.g = cls.app.interp.globals

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def call(self, name, *a):
        with self.app.interp.budget(200000, 1.0):
            return self.g[name](*a)

    def raises(self, name, exc, contains="", *args):
        with self.assertRaises(exc) as cm:
            self.call(name, *args)
        self.assertIn(contains, str(cm.exception))

    def test_string_sql_rejected_at_runtime(self):
        self.raises("raw_sql", SecurityError, "sql")

    def test_ssrf(self):
        self.raises("ssrf_metadata", SecurityError, "권한")
        self.raises("ssrf_loopback", SecurityError, "내부망")
        self.raises("ssrf_trick_host", SecurityError)
        self.raises("not_allowed_host", SecurityError, "권한")

    def test_env_permission(self):
        self.raises("env_undeclared", SecurityError, "환경변수")

    def test_security_error_cannot_be_caught(self):
        self.raises("catch_security", SecurityError)

    def test_records_are_immutable_copy_works(self):
        self.assertEqual(self.call("mutate"), "b")

    def test_open_redirect(self):
        self.raises("open_redirect", SecurityError, "리다이렉트")

    def test_secret_masking(self):
        out = self.call("secret_text")
        self.assertNotIn("super-secret", out)
        self.assertIn("***", out)
        self.assertNotIn("super", str(html(("", ""), (Secret("super"),), ("text",))))
        self.assertNotIn("super", json_dumps({"k": Secret("super")}))

    def test_resource_limits_are_uncatchable(self):
        self.raises("forever", ResourceLimit)
        with self.assertRaises(ResourceLimit):
            self.call("deep", 0)

    def test_runtime_whitelist_blocks_dynamic_attribute(self):
        self.raises("dyn_attr", SoriTypeError, "없어요", {"a": 1})

    def test_huge_repetition_blocked(self):
        self.raises("dyn_str_mul", ResourceLimit, "", "aaaa")

    def test_internal_error_is_sanitized(self):
        r = TestClient(self.app)._do("GET", "/boom")
        self.assertEqual(r.status, 500)
        self.assertNotIn("Traceback", r.text)
        self.assertIn("request_id", r.text)

    def test_infinite_loop_request_is_stopped(self):
        r = TestClient(self.app)._do("GET", "/loop")
        self.assertEqual(r.status, 500)

    def post(self, body, ctype="application/json", extra=None):
        h = {"host": "localhost", "content-type": ctype}
        h.update(extra or {})
        return dispatch(self.app, "POST", "/strict", h, body, "127.0.0.1")[0]

    def test_input_hardening(self):
        self.assertEqual(self.post(b'{"title":"a","tags":["x"]}'), 200)
        cases = {
            "중복 JSON 키": b'{"title":"a","title":"b"}',
            "NaN": b'{"title":"a","count":NaN}',
            "선언 외 필드 (mass assignment)": b'{"title":"a","is_admin":true}',
            "과도한 중첩": ("[" * 100 + "]" * 100).encode(),
            "목록 개수 범위 초과": json.dumps({"title": "a", "tags": ["x"] * 101}).encode(),
            "원소 길이 범위 초과": json.dumps({"title": "a", "tags": ["x" * 11]}).encode(),
            "타입 불일치": b'{"title":123}',
            "엄격 JSON: 문자열 숫자": b'{"title":"a","count":"5"}',
            "엄격 JSON: 1 을 Bool 로": b'{"title":"a","flag":1}',
            "엄격 JSON: Bool 을 Int 로": b'{"title":"a","count":true}',
            "범위 초과": b'{"title":"a","count":11}',
            "빈 문자열(최소 길이)": b'{"title":""}',
        }
        for name, body in cases.items():
            with self.subTest(name=name):
                self.assertEqual(self.post(body), 400)
        self.assertEqual(self.post(b"\x8b\x00", extra={"content-encoding": "br"}), 415)
        self.assertEqual(self.post(b"--x", ctype="multipart/form-data; boundary=x"), 415)
        self.assertEqual(dispatch(self.app, "GET", "/a%2f..%2fetc", {"host": "localhost"}, b"", "1.1.1.1")[0], 400)

    def test_html_response_requires_html_value(self):
        with self.assertRaises(SecurityError):
            _to_http(respond(200, "<script>x</script>", content_type="text/html"))


class AuthOrdering(unittest.TestCase):
    """인증은 본문 파싱보다 먼저 — 인증 전에는 JSON 파서 공격면에 닿지 않는다."""

    def test_unauthenticated_invalid_body_gets_401_not_400(self):
        d, app = loaded('type B:\n    a: Int(0, 5)\nroute POST "/x" (body: B) guard bearer:\n    return body\n')
        try:
            h = {"host": "localhost", "content-type": "application/json"}
            self.assertEqual(dispatch(app, "POST", "/x", h, b'{"a":"broken', "1.1.1.1")[0], 401)
            h["authorization"] = "Bearer " + app.api_token
            self.assertEqual(dispatch(app, "POST", "/x", h, b'{"a":"broken', "1.1.1.1")[0], 400)
            self.assertEqual(dispatch(app, "POST", "/x", h, b'{"a":3}', "1.1.1.1")[0], 200)
        finally:
            shutil.rmtree(d)

    def test_custom_guard_is_403_and_bearer_is_401(self):
        src = ('guard never(req):\n    return false\nroute GET "/g" guard never:\n    return "x"\n'
               'route GET "/b" guard bearer:\n    return "x"\n')
        d, app = loaded(src)
        try:
            c = TestClient(app)
            self.assertEqual(c.get("/g").status, 403)
            r = c.get("/b")
            self.assertEqual(r.status, 401)
            self.assertEqual(r.header("www-authenticate"), "Bearer")
            self.assertEqual(c.get("/b", auth=True).status, 200)
        finally:
            shutil.rmtree(d)


class FailClosed(unittest.TestCase):
    def test_bearer_requires_token_at_serve(self):
        from sori_util import build
        d, app, diags = build('route GET "/b" guard bearer:\n    return "x"\n')
        try:
            old = os.environ.pop("SORI_API_TOKEN", None)
            self.assertTrue(app.startup_problems("serve"))
            os.environ["SORI_API_TOKEN"] = "short"
            self.assertTrue(app.startup_problems("serve"))
            os.environ["SORI_API_TOKEN"] = "x" * 40
            self.assertEqual(app.startup_problems("serve"), [])
        finally:
            os.environ.pop("SORI_API_TOKEN", None)
            if old:
                os.environ["SORI_API_TOKEN"] = old
            shutil.rmtree(d)

    def test_production_refuses_unsafe_configuration(self):
        from sori_util import build
        cases = [
            ('[security]\nstrict_inputs = false\n[app]\nallow_unlocked = true\n', "strict_inputs"),
            ('[permissions]\npython = ["json"]\n[dev]\nin_process_python = true\n[app]\nallow_unlocked = true\n', "파이썬"),
            ('[permissions]\n', "sori.lock"),
        ]
        for toml, needle in cases:
            d, app, _ = build('let x = 1\n', toml)
            old = os.environ.get("SORI_ENV")
            os.environ["SORI_ENV"] = "production"
            try:
                app.env = "production"
                probs = " / ".join(app.startup_problems("serve"))
                self.assertIn(needle, probs, toml)
            finally:
                if old is None:
                    os.environ.pop("SORI_ENV", None)
                else:
                    os.environ["SORI_ENV"] = old
                shutil.rmtree(d)

    def test_production_has_no_bypass_switches(self):
        """PR #3 리뷰 P2: allow_unlocked 같은 설정으로 운영 lock 검사를 끌 수 없고, 운영에서 내장 서버는 거부."""
        from sori_util import build
        d, app, _ = build('route GET "/" public:\n    return "ok"\n', '[app]\nallow_unlocked = true\n')
        try:
            app.env = "production"
            self.assertIn("sori.lock", " / ".join(app.startup_problems("serve")))
            from sori.tools.deploy import write_lock
            write_lock(app)
            self.assertEqual(app.startup_problems("serve", server="uvicorn"), [])
            self.assertIn("내장 서버", " / ".join(app.startup_problems("serve", server="builtin")))
            app.env = "development"
            self.assertEqual(app.startup_problems("serve", server="builtin"), [])
        finally:
            shutil.rmtree(d)

    def test_lock_covers_static_and_fs_read_files(self):
        """PR #3 리뷰 P2: 이미지에 들어가는 정적/읽기 파일을 바꾸면 운영 기동이 거부된다."""
        from sori_util import build
        from sori.tools.deploy import write_lock
        toml = '[app]\nstatic = "./static"\n[permissions]\nfs_read = ["./content"]\n'
        d, app, _ = build('route GET "/" public:\n    return "ok"\n', toml,
                          extra={"static/app.js": "console.log(1)\n", "content/a.txt": "hello\n",
                                 "notes/private.txt": "not deployed\n"})
        try:
            self.assertEqual(app.deploy_files(), ["app.sori", "content/a.txt", "sori.toml", "static/app.js"])
            write_lock(app)
            app.env = "production"
            self.assertEqual(app.startup_problems("serve", server="uvicorn"), [])
            for rel, content in (("static/app.js", "steal()\n"), ("content/a.txt", "changed\n")):
                with open(os.path.join(d, rel), encoding="utf-8") as fh:
                    orig = fh.read()
                with open(os.path.join(d, rel), "w") as f:
                    f.write(content)
                probs = " / ".join(app.startup_problems("serve", server="uvicorn"))
                self.assertIn("무결성", probs)
                self.assertIn(rel, probs)
                with open(os.path.join(d, rel), "w") as f:
                    f.write(orig)
            with open(os.path.join(d, "static", "new.js"), "w") as f:
                f.write("added()\n")
            self.assertIn("static/new.js", " / ".join(app.startup_problems("serve", server="uvicorn")))
        finally:
            shutil.rmtree(d)


class MemoryLimits(unittest.TestCase):
    def test_huge_range_is_refused_and_uncatchable(self):
        """range(10억) 같은 내장 호출로 메모리를 고갈시키지 못한다 (catch 로도 못 삼킴)."""
        from sori_util import loaded
        d, app = loaded('fn big() -> Int:\n    try:\n        return len(range(1000000000))\n    catch e:\n        return -1\n'
                        'fn ok() -> Int:\n    return len(range(1000))\n')
        try:
            with app.interp.budget(100000, 2.0):
                self.assertEqual(app.interp.globals["ok"](), 1000)
                with self.assertRaises(ResourceLimit):
                    app.interp.globals["big"]()
        finally:
            shutil.rmtree(d)


class MetricsPolicy(unittest.TestCase):
    def _app(self, toml):
        from sori_util import build
        d, app, _ = build('route GET "/" public:\n    return "ok"\n', toml)
        self.addCleanup(shutil.rmtree, d)
        return app

    def _get(self, app, auth=None):
        from sori.framework.web import dispatch
        h = {"host": "localhost"}
        if auth:
            h["authorization"] = auth
        return dispatch(app, "GET", "/metrics", h, b"", "127.0.0.1")[0]

    def test_default_is_token_and_disabled_without_token(self):
        app = self._app("[permissions]\n")
        os.environ.pop("SORI_METRICS_TOKEN", None)
        self.assertEqual(app.startup_problems("serve"), [])
        app.access_log = False
        app.load()
        self.assertEqual(self._get(app), 404)

    def test_token_mode(self):
        app = self._app("[permissions]\n")
        app.access_log = False
        os.environ["SORI_METRICS_TOKEN"] = "short"
        try:
            self.assertTrue(app.startup_problems("serve"))
            os.environ["SORI_METRICS_TOKEN"] = "k" * 40
            self.assertEqual(app.startup_problems("serve"), [])
        finally:
            os.environ.pop("SORI_METRICS_TOKEN", None)
        app.load()
        self.assertEqual(self._get(app), 401)
        self.assertEqual(self._get(app, "Bearer " + "x" * 40), 401)
        self.assertEqual(self._get(app, "Bearer " + "k" * 40), 200)

    def test_public_and_off_are_explicit(self):
        for mode, want in (("public", 200), ("off", 404)):
            app = self._app(f'[security]\nmetrics = "{mode}"\n')
            app.access_log = False
            self.assertEqual(app.startup_problems("serve"), [])
            app.load()
            self.assertEqual(self._get(app), want, mode)
        app = self._app('[security]\nmetrics = "everyone"\n')
        self.assertTrue(app.startup_problems("serve"))


if __name__ == "__main__":
    unittest.main()
