"""예제 test 블록, CLI 하위 호환·신규 명령, 배포 산출물 정적 검증."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
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


if __name__ == "__main__":
    unittest.main()
