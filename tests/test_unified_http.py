"""실제 HTTP 서버(개발용 내장)와 ASGI 어댑터(운영용 uvicorn 경로)에 대한 공격 시나리오."""
import os
import shutil
import socket
import threading
import time
import unittest

from sori.framework.asgi import create_asgi
from sori.framework.web import serve
from sori_util import ROOT, asgi_request, free_port, loaded, run

TODO = ROOT / "examples" / "todo"


def _load_todo():
    from sori.framework.app import build_app
    shutil.rmtree(TODO / "data", ignore_errors=True)
    app, diags = build_app(TODO)
    app.access_log = False
    assert not app.startup_problems("test")
    return app.load()


class BuiltinServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = _load_todo()
        cls.port = free_port()
        threading.Thread(target=serve, args=(cls.app, "127.0.0.1", cls.port), daemon=True).start()
        for _ in range(100):
            if cls.app.ready:
                break
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(TODO / "data", ignore_errors=True)

    def raw(self, req: bytes):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(req)
        data = b""
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
        s.close()
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        return int(head.split(" ")[1]), head, data

    def test_normal_request_and_headers(self):
        st, head, _ = self.raw(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertEqual(st, 200)
        self.assertIn("Server: sori\r", head + "\r")
        self.assertNotIn("Python", head)
        self.assertIn("Content-Security-Policy", head)
        self.assertIn("X-Frame-Options: DENY", head)

    def test_smuggling_and_ambiguity(self):
        cases = {
            "Transfer-Encoding": b"POST /todos HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n",
            "중복 Content-Length": b"POST /todos HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 50\r\n\r\nhello",
            "인코딩된 ..": b"GET /api/todos/%2e%2e/x HTTP/1.1\r\nHost: localhost\r\n\r\n",
        }
        for name, req in cases.items():
            with self.subTest(name=name):
                self.assertEqual(self.raw(req)[0], 400)

    def test_size_and_encoding(self):
        self.assertEqual(self.raw(b"POST /todos HTTP/1.1\r\nHost: localhost\r\nContent-Length: 99999999\r\n\r\n")[0], 413)
        st, _, _ = self.raw(b"POST /todos HTTP/1.1\r\nHost: localhost\r\nContent-Encoding: br\r\nContent-Length: 2\r\n"
                            b"Content-Type: application/json\r\n\r\n{}")
        self.assertEqual(st, 415)

    def test_method_and_probes(self):
        st, head, _ = self.raw(b"DELETE /api/todos HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertEqual(st, 405)
        self.assertIn("Allow:", head)
        self.assertTrue(self.raw(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")[2].endswith(b"ok"))
        self.assertEqual(self.raw(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n")[0], 200)
        self.raw(b"POST /todos HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        body = self.raw(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")[2]
        self.assertIn(b'sori_security_events_total{kind="transfer_encoding"}', body)


class AsgiAdapter(unittest.TestCase):
    """운영 경로(uvicorn 등 ASGI 서버) — 같은 dispatch 를 쓰는지, 서버 앞단 검사가 동일한지."""

    @classmethod
    def setUpClass(cls):
        os.environ["SORI_API_TOKEN"] = "t" * 40
        src = ('type B:\n    a: Int(0, 5)\nroute POST "/x" (body: B) guard bearer:\n    return {v: body.a}\n'
               'route GET "/h" public:\n    return {ok: true}\n')
        cls.dir, cls.app = loaded(src, '[security]\nmax_body_kb = 1\n', mode="serve")
        cls.asgi = staticmethod(create_asgi(cls.app))

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("SORI_API_TOKEN", None)
        shutil.rmtree(cls.dir)

    def req(self, *a, **k):
        return run(asgi_request(self.asgi, *a, **k))

    def test_basic_and_auth(self):
        tok = "t" * 40
        self.assertEqual(self.req("GET", "/h")[0], 200)
        self.assertEqual(self.req("POST", "/x", {"a": 3})[0], 401)
        self.assertEqual(self.req("POST", "/x", {"a": 3}, "wrong")[0], 401)
        st, body, headers = self.req("POST", "/x", {"a": 3}, tok)
        self.assertEqual((st, body), (200, {"v": 3}))
        self.assertEqual(headers[b"x-content-type-options"], b"nosniff")
        dup = [(b"authorization", ("Bearer " + tok).encode())]
        self.assertEqual(self.req("POST", "/x", {"a": 3}, tok, headers=dup)[0], 401)

    def test_limits_and_parsing(self):
        tok = "t" * 40
        self.assertEqual(self.req("POST", "/x", b"a" * 2048, tok)[0], 413)
        self.assertEqual(self.req("POST", "/x", {"a": 9}, tok)[0], 400)
        self.assertEqual(self.req("POST", "/x", {"a": 1}, tok, content_type="text/plain")[0], 415)
        self.assertEqual(self.req("GET", "/a%2f..", raw_path=b"/a%2f..")[0], 400)

    @unittest.skipUnless(__import__("importlib").util.find_spec("uvicorn"), "uvicorn 미설치 — 운영 서버 통합 테스트 생략")
    def test_uvicorn_end_to_end(self):
        import urllib.request
        import uvicorn
        port = free_port()
        cfg = uvicorn.Config(create_asgi(self.app), host="127.0.0.1", port=port, server_header=False,
                             proxy_headers=False, log_level="error", lifespan="on")
        srv = uvicorn.Server(cfg)
        t = threading.Thread(target=srv.run, daemon=True)
        t.start()
        try:
            for _ in range(100):
                if srv.started:
                    break
                time.sleep(0.05)
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/h", timeout=3) as r:
                self.assertEqual(r.status, 200)
                self.assertIsNone(r.headers.get("server"))
                self.assertEqual(r.headers.get("x-frame-options"), "DENY")
        finally:
            srv.should_exit = True
            t.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
