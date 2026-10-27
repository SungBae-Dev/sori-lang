"""v0.1 DSL → v0.3 마이그레이션: 변환 결과가 컴파일되고, 같은 요청에 같은 상태코드·성공 응답·접근 정책을 내는지."""
import os
import shutil
import tempfile
import threading
import unittest
from http.server import HTTPServer
from pathlib import Path

from edge.worker import Handler
from sori.compiler import parse
from sori.runtime import create_app as legacy_app
from sori.tools.migrate import migrate_file, migrate_source
from sori_util import ROOT, asgi_request, run

TOKEN = "k" * 48


def _matrix():
    """(method, path, body, token, content_type, headers)"""
    big = b"a" * (64 * 1024 + 1)
    return [
        ("GET", "/health", None, None, "application/json", None),
        ("POST", "/greet", {"name": "Kim"}, None, "application/json", None),
        ("POST", "/greet", {"name": "Kim"}, "bad", "application/json", None),
        ("POST", "/greet", {"name": "Kim"}, TOKEN, "application/json", None),
        ("POST", "/greet", {"name": ""}, TOKEN, "application/json", None),
        ("POST", "/greet", {"name": "x" * 81}, TOKEN, "application/json", None),
        ("POST", "/greet", {"name": "Kim"}, TOKEN, "application/json", [(b"authorization", ("Bearer " + TOKEN).encode())]),
        ("POST", "/add", {"a": 15, "b": -2}, TOKEN, "application/json", None),
        ("POST", "/add", {"a": True, "b": 1}, TOKEN, "application/json", None),
        ("POST", "/add", {"a": 1, "b": 1001}, TOKEN, "application/json", None),
        ("POST", "/add", {"a": 1, "b": 2, "is_admin": True}, TOKEN, "application/json", None),
        ("POST", "/add", {"a": 1}, TOKEN, "application/json", None),
        ("POST", "/add", b'{"a":1,"a":2,"b":3}', TOKEN, "application/json", None),
        ("POST", "/add", b'{"a": NaN, "b": 2}', TOKEN, "application/json", None),
        ("POST", "/add", big, TOKEN, "application/json", None),
        ("POST", "/add", {"a": 1, "b": 2}, TOKEN, "text/plain", None),
        ("POST", "/add", {"a": "1", "b": 2}, TOKEN, "application/json", None),
        ("GET", "/other", None, None, "application/json", None),
        ("GET", "/greet", None, None, "application/json", None),
        ("POST", "/risk", {"signal": 0.91}, TOKEN, "application/json", None),
        ("POST", "/risk", {"signal": 0.2}, TOKEN, "application/json", None),
        ("POST", "/risk", {"signal": 1.5}, TOKEN, "application/json", None),
        ("POST", "/risk", {"signal": 0.5}, None, "application/json", None),
    ]


class MigrationEquivalence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.worker = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=cls.worker.serve_forever, daemon=True).start()
        port = cls.worker.server_address[1]
        src = (ROOT / "examples" / "hello.sori").read_text(encoding="utf-8").replace(
            "http://127.0.0.1:9010/invoke", f"http://127.0.0.1:{port}/invoke")
        cls.tmp = tempfile.mkdtemp(prefix="sori_mig_")
        Path(cls.tmp, "hello.sori").write_text(src, encoding="utf-8")
        cls.legacy = staticmethod(legacy_app(parse(src), token=TOKEN))
        out = Path(cls.tmp, "v03")
        cls.files, cls.report = migrate_file(str(Path(cls.tmp, "hello.sori")), str(out))
        from sori.framework.app import build_app
        from sori.framework.asgi import create_asgi
        os.environ["SORI_API_TOKEN"] = TOKEN
        app, diags = build_app(out)
        cls.diags = diags
        app.access_log = False
        assert not app.startup_problems("serve"), app.startup_problems("serve")
        cls.new = staticmethod(create_asgi(app.load()))

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("SORI_API_TOKEN", None)
        cls.worker.shutdown()
        cls.worker.server_close()
        shutil.rmtree(cls.tmp)

    def test_migrated_program_compiles_without_errors(self):
        self.assertEqual([d.code for d in self.diags if d.severity == "error"], [])
        self.assertIn("guard bearer", self.files["app.sori"])
        self.assertIn("Str(1, 80)", self.files["app.sori"])

    def test_same_status_and_success_bodies(self):
        for method, path, body, token, ctype, headers in _matrix():
            with self.subTest(method=method, path=path, body=str(body)[:40], token=bool(token), ctype=ctype):
                a = run(asgi_request(self.legacy, method, path, body, token, ctype, headers))
                b = run(asgi_request(self.new, method, path, body, token, ctype, headers))
                self.assertEqual(a[0], b[0], f"legacy={a[1]} new={b[1]}")
                if a[0] == 200:
                    self.assertEqual(a[1], b[1])

    def test_access_policy_preserved(self):
        from sori.compiler import parse_file
        legacy = {(r.method, r.path): r.access for r in parse(Path(self.tmp, "hello.sori").read_text()).routes}
        app_src = self.files["app.sori"]
        for (method, path), access in legacy.items():
            line = next(l for l in app_src.splitlines() if l.startswith(f'route {method} "{path}"'))
            self.assertTrue(line.endswith("public:") if access == "public" else line.endswith("guard bearer:"), line)

    def test_unconvertible_parts_are_reported(self):
        files, report = migrate_source('app "x"\nroute POST "/ping" protected:\n  return {"ok": True}\n')
        self.assertTrue(any("동작 차이" in r and "/ping" in r for r in report))


if __name__ == "__main__":
    unittest.main()
