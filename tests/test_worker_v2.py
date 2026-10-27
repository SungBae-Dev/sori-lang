"""std.worker: 루프백 격리 워커 호출 — 응답 타입 검증, 실패 은닉 금지(502), public 라우트 금지."""
import json
import os
import shutil
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from sori.framework.web import TestClient
from sori_util import loaded


class _Handler(BaseHTTPRequestHandler):
    reply = {"risk": "low", "kind": "demo"}

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        data = json.loads(self.rfile.read(n) or b"{}")
        out = dict(type(self).reply, echo=data.get("signal")) if type(self).reply.get("echo") else type(self).reply
        raw = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


SRC = '''use std.worker
type In:
    signal: Float(0, 1)
type Out:
    risk: Str(1, 8)
    kind: Str(1, 16)
route POST "/typed" (body: In) guard bearer:
    return worker.call("m", body, Out)
route POST "/raw" (body: In) guard bearer:
    return worker.call("m", body)
'''


class WorkerV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        port = cls.srv.server_address[1]
        toml = f'[permissions]\n[workers.m]\nurl = "http://127.0.0.1:{port}/invoke"\ntimeout_ms = 800\n'
        cls.dir, cls.app = loaded(SRC, toml)
        cls.c = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.dir)

    def test_typed_response(self):
        _Handler.reply = {"risk": "low", "kind": "demo"}
        r = self.c.post("/typed", json={"signal": 0.3}, auth=True)
        self.assertEqual((r.status, r.json()), (200, {"risk": "low", "kind": "demo"}))

    def test_worker_output_violating_type_is_502(self):
        for bad in ({"risk": "low"}, {"risk": "low", "kind": "demo", "admin": True}, {"risk": "x" * 20, "kind": "d"},
                    {"risk": 1, "kind": "d"}):
            with self.subTest(bad=bad):
                _Handler.reply = bad
                self.assertEqual(self.c.post("/typed", json={"signal": 0.3}, auth=True).status, 502)

    def test_unauthenticated_cannot_reach_worker(self):
        self.assertEqual(self.c.post("/raw", json={"signal": 0.3}).status, 401)

    def test_offline_worker_is_502_not_hidden(self):
        toml = '[permissions]\n[workers.m]\nurl = "http://127.0.0.1:65534/invoke"\ntimeout_ms = 100\n'
        d, app = loaded(SRC, toml)
        try:
            r = TestClient(app).post("/raw", json={"signal": 0.3}, auth=True)
            self.assertEqual(r.status, 502)
            self.assertEqual(r.json()["error"], "upstream unavailable")
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
