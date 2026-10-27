"""예제 test 블록, CLI 하위 호환·신규 명령, 배포 산출물 정적 검증."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from sori_util import ROOT

EXAMPLES = ("todo", "robot", "secure-api")


def cli(*args, env=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "sori", *map(str, args)], cwd=ROOT, text=True,
                          capture_output=True, timeout=60, env=e)


class ExampleTests(unittest.TestCase):
    def test_example_test_blocks_pass(self):
        from sori.framework.app import build_app
        for ex in EXAMPLES:
            with self.subTest(ex=ex):
                shutil.rmtree(ROOT / "examples" / ex / "data", ignore_errors=True)
                app, diags = build_app(ROOT / "examples" / ex)
                self.assertFalse([d for d in diags if d.severity == "error"])
                app.access_log = False
                os.environ["ADMIN_KEY"] = "admin-key-for-tests"
                self.assertEqual(app.startup_problems("test"), [])
                app.load()
                failures = []
                for name, fn, f, l in app.tests:
                    try:
                        fn()
                    except BaseException as e:  # noqa: BLE001 — 실패 사유를 모아서 보고
                        failures.append((name, app.describe(e)))
                self.assertEqual(failures, [])
                self.assertGreater(len(app.tests), 0)
                shutil.rmtree(ROOT / "examples" / ex / "data", ignore_errors=True)


class CLICompat(unittest.TestCase):
    """B1 명령은 v0.1 파일에서 그대로, 새 명령은 v0.3 프로젝트에서."""

    def test_legacy_commands_unchanged(self):
        for cmd, key in (("ir", "ir_version"), ("openapi", "openapi"), ("manifest", "routes")):
            r = cli(cmd, "examples/hello.sori")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(key, json.loads(r.stdout))
        self.assertEqual(json.loads(cli("ir", "examples/hello.sori").stdout)["ir_version"], "sori/ir/v1")
        self.assertIn("OK: SORI Secure API", cli("check", "examples/hello.sori").stdout)

    def test_unified_spec_commands(self):
        ir = json.loads(cli("ir", "examples/todo").stdout)
        self.assertEqual(ir["ir_version"], "sori/ir/v2")
        self.assertEqual(json.loads(cli("openapi", "examples/secure-api").stdout)["openapi"], "3.1.0")
        self.assertTrue(json.loads(cli("tools", "examples/todo").stdout))
        r = cli("check", "examples/todo", "--json")
        self.assertEqual(r.returncode, 0)
        self.assertTrue(all(d["severity"] == "warning" for d in json.loads(r.stdout)))

    def test_check_json_reports_errors_for_ai(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.sori").write_text('let count = 1\nprint(cuont)\n', encoding="utf-8")
            r = cli("check", tmp, "--json")
            self.assertEqual(r.returncode, 1)
            d = json.loads(r.stdout)[0]
            self.assertEqual((d["code"], d["line"]), ("SORI-E101", 2))
            self.assertIn("count", d["hint"])

    def test_build_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = cli("build", "examples/secure-api", "--out", Path(tmp, "spec"))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("no native binary generated", r.stdout)
            for name in ("manifest.json", "typed-ir.json", "openapi.json", "tools.json"):
                json.loads(Path(tmp, "spec", name).read_text(encoding="utf-8"))
            legacy = cli("build", "examples/hello.sori", "--out", Path(tmp, "legacy"))
            self.assertIn("no native binary generated", legacy.stdout)
            proj = Path(tmp, "proj")
            shutil.copytree(ROOT / "examples" / "secure-api", proj)
            r = cli("build", proj, "--target", "oci")
            self.assertEqual(r.returncode, 0, r.stderr)
            ctx = proj / ".sori" / "build"
            self.assertTrue((ctx / "Dockerfile").exists() and (ctx / "app" / "sori.lock").exists())
            self.assertTrue((ctx / "app" / "worker.py").exists())

    def test_new_migrate_and_test_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp, "svc")
            self.assertEqual(cli("new", target).returncode, 0)
            self.assertTrue((target / "app.sori").exists() and (target / "sori.toml").exists())
            self.assertEqual(cli("check", target / "app.sori").returncode, 0)
            self.assertNotEqual(cli("new", target).returncode, 0)
            r = cli("test", target)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("통과 1", r.stdout)
            m = cli("migrate", "examples/hello.sori", "--out", Path(tmp, "mig"))
            self.assertEqual(m.returncode, 0, m.stderr)
            self.assertEqual(cli("check", Path(tmp, "mig")).returncode, 0)
            self.assertNotEqual(cli("migrate", "examples/hello.sori", "--out", Path(tmp, "mig")).returncode, 0)

    def test_run_fails_closed_without_token(self):
        env = {k: v for k, v in os.environ.items() if k != "SORI_API_TOKEN"}
        r = subprocess.run([sys.executable, "-m", "sori", "run", "examples/secure-api"], cwd=ROOT, text=True,
                           capture_output=True, timeout=30, env=env)
        self.assertEqual(r.returncode, 3)
        self.assertIn("SORI_API_TOKEN", r.stderr)


class DeployStatic(unittest.TestCase):
    def _app(self, ex):
        from sori.framework.app import build_app
        app, _ = build_app(ROOT / "examples" / ex)
        return app

    def test_k8s_least_privilege(self):
        from sori.tools.deploy import k8s
        text = k8s(self._app("secure-api"), "registry.local/sori:0.3")
        for needle in ("runAsNonRoot: true", "readOnlyRootFilesystem: true", 'drop: ["ALL"]', "seccompProfile",
                       "automountServiceAccountToken: false", "allowPrivilegeEscalation: false", "kind: NetworkPolicy",
                       "worker-risk-model", "SORI_API_TOKEN"):
            self.assertIn(needle, text)
        self.assertNotIn("privileged: true", text)
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML 없음 — YAML 파싱 검증은 CI 에서 수행")
        docs = [d for d in yaml.safe_load_all(text) if d]
        kinds = [d["kind"] for d in docs]
        self.assertEqual(kinds, ["Deployment", "Service", "NetworkPolicy"])
        pod = docs[0]["spec"]["template"]["spec"]
        self.assertEqual([c["name"] for c in pod["containers"]], ["app", "worker-risk-model"])
        for c in pod["containers"]:
            self.assertTrue(c["securityContext"]["readOnlyRootFilesystem"])
            self.assertEqual(c["securityContext"]["capabilities"]["drop"], ["ALL"])

    def test_compose_and_dockerfile(self):
        from sori.tools.deploy import DOCKERFILE, compose
        text = compose(self._app("secure-api"))
        for needle in ('network_mode: "service:app"', "read_only: true", "no-new-privileges:true", "cap_drop",
                       '127.0.0.1:8000:8000'):
            self.assertIn(needle, text)
        self.assertIn("USER 10001:10001", DOCKERFILE)
        self.assertIn("SORI_ENV=production", DOCKERFILE)
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML 없음")
        self.assertIn("worker-risk-model", yaml.safe_load(text)["services"])


def _uvicorn_available():
    try:
        import uvicorn  # noqa: F401
        return True
    except ImportError:
        return False


class OciContextE2E(unittest.TestCase):
    """PR #3 리뷰 P1: OCI 빌드 컨텍스트만으로(저장소 없이) 모듈 임포트와 운영 기동이 되는가.

    Docker 데몬 없이 컨테이너 레이아웃을 그대로 흉내 낸다: WORKDIR=app/, PYTHONPATH=runtime/, SORI_ENV=production.
    실제 docker build/run 은 CI 의 별도 단계에서 수행한다.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sori_oci_")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.procs = []
        self.addCleanup(self._stop)

    def _stop(self):
        for p in self.procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()

    def _context(self, example):
        proj = Path(self.tmp, example)
        shutil.copytree(ROOT / "examples" / example, proj, ignore=shutil.ignore_patterns("data", "sori.lock", ".sori"))
        r = cli("build", proj, "--target", "oci", "--out", Path(self.tmp, example + "-ctx"))
        self.assertEqual(r.returncode, 0, r.stderr)
        return Path(self.tmp, example + "-ctx")

    def _env(self, ctx, **extra):
        e = {k: v for k, v in os.environ.items() if not k.startswith("SORI_")}
        e.update(PYTHONPATH=str(ctx / "runtime"), SORI_ENV="production", PYTHONDONTWRITEBYTECODE="1", **extra)
        return e

    def _py(self, ctx, *args, **extra):
        return subprocess.run([sys.executable, *args], cwd=ctx / "app", env=self._env(ctx, **extra), text=True,
                              capture_output=True, timeout=60)

    def test_context_contains_whole_package_and_hashed_files_only(self):
        ctx = self._context("todo")
        for rel in ("__init__.py", "__main__.py", "lang/compiler.py", "lang/parser.py", "framework/interp.py",
                    "framework/asgi.py", "tools/deploy.py"):
            self.assertTrue((ctx / "runtime" / "sori" / rel).is_file(), rel)
        lock = json.loads((ctx / "app" / "sori.lock").read_text(encoding="utf-8"))
        shipped = sorted(str(p.relative_to(ctx / "app")) for p in (ctx / "app").rglob("*") if p.is_file())
        self.assertEqual(shipped, sorted(list(lock["files"]) + ["sori.lock"]))
        self.assertIn("static/app.css", lock["files"])
        self.assertIn("content/readme.txt", lock["files"])
        df = (ctx / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("mkdir -p /app/data && chown 10001:10001 /app/data", df)
        self.assertIn('"--server", "uvicorn"', df)
        self.assertIn("uvicorn", (ctx / "requirements.txt").read_text(encoding="utf-8"))

    def test_runtime_imports_from_context_not_repository(self):
        ctx = self._context("todo")
        r = self._py(ctx, "-c", "import sori, sori.lang.compiler, sori.framework.interp, sori.framework.asgi; print(sori.__file__)")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.strip().startswith(str(ctx / "runtime")), r.stdout)
        r = self._py(ctx, "-m", "sori", "check", str(ctx / "app"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_production_refuses_builtin_server_and_tampered_files(self):
        ctx = self._context("todo")
        r = self._py(ctx, "-m", "sori", "run", str(ctx / "app"), "--server", "builtin", "--port", "1")
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("내장 서버", r.stderr)
        (ctx / "app" / "static" / "app.css").write_text("body{background:url(//evil)}\n", encoding="utf-8")
        r = self._py(ctx, "-m", "sori", "run", str(ctx / "app"), "--server", "uvicorn", "--port", "1")
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("static/app.css", r.stderr)

    @unittest.skipUnless(_uvicorn_available(), "uvicorn 미설치 — 운영 기동 E2E 를 실행하지 않음 (CI 에서 실행)")
    def test_production_start_from_context(self):
        import urllib.request
        from sori_util import free_port
        token = "e" * 40
        for example, probe in (("todo", "/api/todos"), ("secure-api", "/health")):
            with self.subTest(example):
                ctx = self._context(example)
                port = free_port()
                p = subprocess.Popen([sys.executable, "-m", "sori", "run", str(ctx / "app"), "--host", "127.0.0.1",
                                      "--port", str(port), "--server", "uvicorn"], cwd=ctx / "app",
                                     env=self._env(ctx, SORI_API_TOKEN=token), stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE, text=True)
                self.procs.append(p)
                base = f"http://127.0.0.1:{port}"
                for _ in range(100):
                    if p.poll() is not None:
                        self.fail(f"{example} 기동 실패 (exit {p.returncode}): {p.stderr.read()}")
                    try:
                        with urllib.request.urlopen(base + "/healthz", timeout=1) as resp:
                            if resp.status == 200:
                                break
                    except OSError:
                        time.sleep(0.1)
                else:
                    self.fail(f"{example}: /healthz 응답 없음")
                with urllib.request.urlopen(base + probe, timeout=3) as resp:
                    self.assertEqual(resp.status, 200)
                    json.loads(resp.read())
                if example == "secure-api":
                    req = urllib.request.Request(base + "/greet", data=b'{"name":"oci"}', method="POST",
                                                 headers={"Content-Type": "application/json",
                                                          "Authorization": "Bearer " + token})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        self.assertEqual(json.loads(resp.read())["message"], "안녕하세요, oci")
                p.terminate()
                p.wait(10)


if __name__ == "__main__":
    unittest.main()
