"""백엔드 동등성: 같은 Typed IR v2 를 Python Backend 와 Rust Backend(B2 슬라이스)가 같은 의미론으로 실행하는가.

테스트 벡터: tests/vectors/<이름>/{sori.toml, app.sori, cases.json}
- Python Backend 는 항상 검증한다.
- Rust Backend 는 runtime-rs 를 빌드한 바이너리가 있을 때만 검증한다(없으면 skip — 성공으로 기록하지 않음).
  CI 는 cargo build 후 이 테스트를 돌린다. 바이너리 경로: SORI_RT_BIN 또는 runtime-rs/target/{release,debug}/sori-rt
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from sori.framework.web import dispatch
from sori_util import ROOT

VECTORS = sorted(p for p in (ROOT / "tests" / "vectors").iterdir() if p.is_dir())
TOKEN = "v" * 40


def rust_bin():
    cands = [os.environ.get("SORI_RT_BIN", "")] + [str(ROOT / "runtime-rs" / "target" / k / "sori-rt") for k in ("release", "debug")]
    return next((c for c in cands if c and os.path.isfile(c) and os.access(c, os.X_OK)), None)


def strict_equal(a, b):
    """int/float/bool 을 구분하는 비교 (1 과 1.0 은 다르다)."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(strict_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(strict_equal(x, y) for x, y in zip(a, b))
    return a == b


def _app(vec):
    from sori.framework.app import build_app
    os.environ["SORI_API_TOKEN"] = TOKEN
    app, diags = build_app(vec)
    assert not [d for d in diags if d.severity == "error"], [d.render(app.sources) for d in diags]
    app.access_log = False
    assert app.startup_problems("serve") == []
    return app.load()


def python_call(app, case):
    h = {"host": "localhost"}
    body = b""
    if "json" in case or "raw" in case:
        body = case["raw"].encode() if "raw" in case else json.dumps(case["json"]).encode()
        h["content-type"] = case.get("content_type", "application/json")
    if case.get("auth"):
        h["authorization"] = "Bearer " + TOKEN
    status, _, out = dispatch(app, case["method"], case["path"], h, body, "127.0.0.1")
    return status, (json.loads(out) if out else None)


def rust_call(binary, ir_path, case):
    args = [binary, ir_path, case["method"], case["path"]]
    if "json" in case or "raw" in case:
        args += ["--json", case["raw"] if "raw" in case else json.dumps(case["json"], ensure_ascii=False)]
    if case.get("auth"):
        args += ["--auth"]
    r = subprocess.run(args, capture_output=True, text=True, timeout=20, env=dict(os.environ, SORI_API_TOKEN=TOKEN))
    assert r.returncode == 0, r.stderr
    resp = json.loads(r.stdout)
    return resp["status"], resp["body"]


class PythonBackendVectors(unittest.TestCase):
    def test_vectors(self):
        for vec in VECTORS:
            app = _app(vec)
            for case in json.loads((vec / "cases.json").read_text(encoding="utf-8")):
                with self.subTest(vector=vec.name, method=case["method"], path=case["path"], case=str(case.get("json", case.get("raw")))[:40]):
                    status, body = python_call(app, case)
                    self.assertEqual(status, case["status"], body)
                    if "body" in case:
                        self.assertTrue(strict_equal(body, case["body"]), f"{body} != {case['body']}")


@unittest.skipUnless(rust_bin(), "Rust 백엔드 바이너리 없음 (cd runtime-rs && cargo build --release) — 실행하지 않음")
class RustBackendVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin = rust_bin()
        cls.tmp = tempfile.mkdtemp(prefix="sori_rs_")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def _ir_file(self, app, name):
        p = Path(self.tmp, name + ".json")
        p.write_text(json.dumps(app.ir, ensure_ascii=False), encoding="utf-8")
        return str(p)

    def test_vectors_match_expected_and_python_backend(self):
        for vec in VECTORS:
            app = _app(vec)
            ir_path = self._ir_file(app, vec.name)
            check = subprocess.run([self.bin, ir_path, "--check"], capture_output=True, text=True, timeout=20)
            self.assertNotIn("unsupported", check.stdout, f"벡터 {vec.name} 는 슬라이스 범위 안이어야 해요")
            for case in json.loads((vec / "cases.json").read_text(encoding="utf-8")):
                with self.subTest(vector=vec.name, method=case["method"], path=case["path"], case=str(case.get("json", case.get("raw")))[:40]):
                    rs, rbody = rust_call(self.bin, ir_path, case)
                    ps, pbody = python_call(app, case)
                    self.assertEqual(rs, case["status"], rbody)
                    self.assertEqual(rs, ps)
                    if "body" in case:
                        self.assertTrue(strict_equal(rbody, case["body"]), f"rust {rbody} != {case['body']}")
                    if rs == 200:
                        self.assertTrue(strict_equal(rbody, pbody), f"rust {rbody} != python {pbody}")

    def test_unsupported_features_are_refused_not_guessed(self):
        from sori.framework.app import build_app
        app, _ = build_app(ROOT / "examples" / "todo")
        ir_path = self._ir_file(app, "todo")
        r = subprocess.run([self.bin, ir_path, "GET", "/api/todos"], capture_output=True, text=True, timeout=20)
        resp = json.loads(r.stdout)
        self.assertEqual(resp["status"], 501)
        self.assertIn("reason", resp["body"])

    def test_bearer_fails_closed_without_token(self):
        vec = ROOT / "tests" / "vectors" / "calc"
        ir_path = self._ir_file(_app(vec), "calc2")
        env = {k: v for k, v in os.environ.items() if k != "SORI_API_TOKEN"}
        r = subprocess.run([self.bin, ir_path, "GET", "/health"], capture_output=True, text=True, timeout=20, env=env)
        self.assertEqual(r.returncode, 3)
        self.assertIn("SORI_API_TOKEN", r.stderr)

    def test_tampered_or_wrong_version_ir_is_refused(self):
        bad = Path(self.tmp, "bad.json")
        bad.write_text(json.dumps({"ir_version": "sori/ir/v1", "routes": []}), encoding="utf-8")
        r = subprocess.run([self.bin, str(bad), "--check"], capture_output=True, text=True, timeout=20)
        self.assertEqual(r.returncode, 3)
        bad.write_text('{"ir_version": "sori/ir/v2", "a": 1, "a": 2}', encoding="utf-8")
        r = subprocess.run([self.bin, str(bad), "--check"], capture_output=True, text=True, timeout=20)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
