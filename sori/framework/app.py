"""SORI 애플리케이션 로더: sori.toml → 통합 컴파일러 → Typed IR v2 → IR 해석기(Python Backend).

파이썬 코드 생성·exec 없음. 런타임이 실행하는 것은 같은 프로세스의 컴파일러가 방금 만든 IR 뿐이다.
"""
import glob
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import tomllib
import traceback

from .. import __version__
from ..lang.compiler import compile_project
from ..lang.diagnostics import SoriError
from . import core
from .core import ExpectFailed, SecurityError, SoriInputError, SoriTypeError, SoriUpstreamError, SoriUserError
from .interp import Interpreter, ResourceLimit
from .policy import TOKEN_ENV, token_problem
from .stdlib import STD, Caps
from .web import Metrics, RateLimiter, Router, TaskRunner, TestClient

VERSION = __version__

_PY_ERRORS = {
    ZeroDivisionError: "0 으로 나눌 수 없어요",
    IndexError: "목록 범위를 벗어났어요",
    KeyError: "맵에 해당 키가 없어요",
    RecursionError: "재귀가 너무 깊어요",
}


def friendly(exc):
    if isinstance(exc, (SecurityError, SoriTypeError, SoriInputError, SoriUserError, SoriUpstreamError, ExpectFailed,
                        ResourceLimit)):
        return getattr(exc, "code", "R000"), str(exc)
    for t, msg in _PY_ERRORS.items():
        if isinstance(exc, t):
            return "R101", f"{msg}: {exc}"
    if isinstance(exc, TypeError):
        return "R102", f"타입이 맞지 않는 연산/호출이에요: {exc}"
    if isinstance(exc, AttributeError):
        return "R103", f"없는 속성이에요: {exc}"
    if isinstance(exc, ValueError):
        return "R104", f"잘못된 값이에요: {exc}"
    return "R199", f"{type(exc).__name__}: {exc}"


METRICS_TOKEN_ENV = "SORI_METRICS_TOKEN"
_SKIP_DIRS = {"__pycache__", ".git", ".sori", ".sori-build", "node_modules"}


def metrics_mode(config):
    """[security] metrics = "token"(기본) | "public" | "off".  예전 불리언: true → "token", false → "off"."""
    v = config.get("security", {}).get("metrics", "token")
    if v is True:
        return "token"
    if v is False:
        return "off"
    return v if v in ("token", "public", "off") else "invalid"


def is_legacy_source(text):
    """SORI v0.1/B1 선언형 DSL 인지 (첫 유효 줄이 app "..." 선언)."""
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        return s.startswith('app "') or s.startswith("app\t") or s == "app"
    return False


def load_config(path):
    path = os.path.abspath(path)
    if os.path.isfile(path):
        root, files = os.path.dirname(path), [path]
    else:
        root = path
        files = sorted(glob.glob(os.path.join(root, "*.sori"))) + \
            sorted(glob.glob(os.path.join(root, "src", "**", "*.sori"), recursive=True))
    cfg_path = os.path.join(root, "sori.toml")
    config = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "rb") as f:
            config = tomllib.load(f)
    return root, config, files


class App:
    def __init__(self, path):
        self.root, self.config, self.files = load_config(path)
        self.sources = {}
        for f in self.files:
            with open(f, encoding="utf-8") as fh:
                self.sources[os.path.relpath(f, self.root)] = fh.read()
        self.legacy_files = [f for f, s in self.sources.items() if is_legacy_source(s)]
        self.perms = self.config.get("permissions", {})
        self.caps = Caps(self.perms, self.root)
        self.env = os.environ.get("SORI_ENV", self.config.get("app", {}).get("env", "development"))
        self.router, self.tasks, self.tests = Router(), [], []
        self.metrics = Metrics()
        self.rate = RateLimiter(int(self.config.get("security", {}).get("rate_limit_per_min", 600)))
        self.access_log = bool(self.config.get("app", {}).get("access_log", True))
        self.ready = False
        self._std = {}
        self._lock = threading.Lock()
        self.project = None
        self.ir = None
        self.interp = None
        self.api_token = ""
        self.metrics_token = ""
        self.metrics_mode = metrics_mode(self.config)

    @property
    def name(self):
        return self.config.get("app", {}).get("name", os.path.basename(self.root) or "sori-app")

    # ---------- 컴파일 ----------
    def compile(self):
        self.project = compile_project(self.sources, self.config)
        self.ir = self.project.to_ir(self.name)
        seen = {d.message for d in self.project.diags}
        for msg in self.caps.problems:  # 파일 시스템을 봐야 알 수 있는 권한 문제 (심볼릭 링크 탈출 등)
            if msg in seen:
                continue
            self.project.diags.append(SoriError("E204", msg, "sori.toml", 0, 0,
                                                "파일 권한은 프로젝트 폴더 안의 상대 경로만 허용돼요"))
        return self.project.diags

    def errors(self):
        return [d for d in self.project.diags if d.severity == "error"]

    def load(self):
        if self.errors():
            raise SecurityError("컴파일 오류가 있는 프로그램은 실행할 수 없어요")
        self.interp = Interpreter(self, self.ir).load(TestClient(self))
        return self

    def std_classes(self):
        return list(STD.values())

    def std_module(self, name):
        with self._lock:
            if name not in self._std:
                self._std[name] = STD[name](self)
            return self._std[name]

    def start_tasks(self):
        runners = []
        for name, period, fn in self.tasks:
            r = TaskRunner(self, name, period, fn)
            threading.Thread(target=r.run, name=f"sori-task-{name}", daemon=True).start()
            runners.append(r)
        return runners

    def check_bearer(self, req):
        """내장 guard bearer: Authorization: Bearer <SORI_API_TOKEN> 상수 시간 비교 (v0.1 protected 계승)."""
        auth = req.header("authorization", "")
        if not auth.startswith("Bearer "):
            return False
        token = self.api_token
        return bool(token) and hmac.compare_digest(auth[7:].encode(), token.encode())

    # ---------- 실패 시 기동 거부 (fail-closed) ----------
    def startup_problems(self, mode, server=None):
        """mode: 'serve' 면 엄격 검사, 'test' 면 테스트용 임시 토큰 발급.
        server: 실제로 띄울 HTTP 서버 ('uvicorn' | 'builtin' | None=검사 안 함).

        운영(SORI_ENV=production)에는 우회 스위치가 없다: lock 누락, 내장 서버, strict_inputs=false,
        같은 프로세스 파이썬은 설정으로 허용할 수 없다."""
        problems = list(self.caps.problems)
        if self.metrics_mode == "invalid":
            problems.append('[security] metrics 는 "token" · "public" · "off" 중 하나여야 해요')
        mtok = os.environ.get(METRICS_TOKEN_ENV, "")
        if self.metrics_mode == "token" and mtok:
            if len(mtok) < 32 or any(c in mtok for c in "\r\n"):
                problems.append(f"{METRICS_TOKEN_ENV} 는 32자 이상, 줄바꿈 없이 설정해야 해요")
            else:
                self.metrics_token = mtok
        if self.project.uses_bearer:
            tok = os.environ.get(TOKEN_ENV, "")
            if mode == "test" and not tok:
                tok = secrets.token_urlsafe(32)
            p = token_problem(tok)
            if p:
                problems.append(p)
            else:
                self.api_token = tok
        if mode == "serve":
            for name, rule in self.config.get("secrets", {}).items():
                need = rule.get("min_length", 1) if isinstance(rule, dict) else int(rule)
                if len(os.environ.get(name, "")) < need:
                    problems.append(f"필수 비밀값 {name} 이(가) 없거나 {need}자 미만이에요 ([secrets] 규칙)")
            if self.env == "production":
                bad = self.verify_lock()
                if bad is None:
                    problems.append("프로덕션인데 sori.lock 이 없어요 — 'sori build --target oci' 로 생성하세요 (우회 설정 없음)")
                elif bad:
                    problems.append("소스 무결성 검증 실패 (sori.lock 과 다름): " + ", ".join(sorted(bad)))
                if not self.project.strict_inputs:
                    problems.append("프로덕션에서는 strict_inputs = false 로 입력 범위 검사를 끌 수 없어요")
                if any(u["module"].startswith("py:") for u in self.ir["uses"]) or \
                        self.config.get("dev", {}).get("in_process_python"):
                    problems.append("프로덕션에서는 같은 프로세스 파이썬(use py / [dev] in_process_python)을 쓸 수 없어요 — [workers] 로 분리하세요")
                if server is not None and server != "uvicorn":
                    problems.append(f"프로덕션에서는 내장 서버({server})를 쓸 수 없어요 — server = \"uvicorn\" (내장 서버는 개발 전용)")
        return problems

    def extra_files(self):
        out = []
        for cfg in self.config.get("workers", {}).values():
            for arg in cfg.get("command", []) if isinstance(cfg, dict) else []:
                full = os.path.realpath(os.path.join(self.root, arg))
                if full.startswith(os.path.realpath(self.root) + os.sep) and os.path.isfile(full):
                    out.append(os.path.relpath(full, self.root))
        return sorted(set(out))

    def _tree_files(self, rel_dir):
        """프로젝트 루트 안의 디렉터리(또는 파일)에 속한 일반 파일 목록. 루트 밖을 가리키는 링크는 제외."""
        root = os.path.realpath(self.root)
        start = os.path.realpath(os.path.join(self.root, rel_dir))
        if not (start == root or start.startswith(root + os.sep)):
            return []
        if os.path.isfile(start):
            return [os.path.relpath(start, root)]
        out = []
        for dirpath, dirnames, filenames in os.walk(start):
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS and not d.startswith("."))
            for fn in sorted(filenames):
                full = os.path.realpath(os.path.join(dirpath, fn))
                if fn.endswith((".pyc", ".pyo")) or fn == "sori.lock" or not os.path.isfile(full):
                    continue
                if full.startswith(root + os.sep):
                    out.append(os.path.relpath(full, root))
        return out

    def deploy_files(self):
        """배포 이미지에 들어가는 프로젝트 파일 전체 (= sori.lock 이 검증하는 범위).
        .sori 소스, sori.toml, 워커 command 파일, [app] static 디렉터리, [permissions] fs_read 경로."""
        files = set(self.sources) | set(self.extra_files())
        if os.path.exists(os.path.join(self.root, "sori.toml")):
            files.add("sori.toml")
        static = self.config.get("app", {}).get("static")
        dirs = [static] if static else []
        dirs += [d for d in self.perms.get("fs_read", []) if isinstance(d, str)]
        for d in dirs:
            files.update(self._tree_files(d))
        return sorted(files)

    # ---------- 무결성(공급망) ----------
    def lock_digest(self):
        h = {}
        for rel in self.deploy_files():
            if rel in self.sources:
                h[rel] = hashlib.sha256(self.sources[rel].encode()).hexdigest()  # 실제로 컴파일된 소스
            else:
                with open(os.path.join(self.root, rel), "rb") as f:
                    h[rel] = hashlib.sha256(f.read()).hexdigest()
        return h

    def verify_lock(self):
        p = os.path.join(self.root, "sori.lock")
        if not os.path.exists(p):
            return None
        with open(p, encoding="utf-8") as f:
            lock = json.load(f)
        cur = self.lock_digest()
        files = lock.get("files", {})
        return [k for k in set(cur) | set(files) if cur.get(k) != files.get(k)]

    # ---------- 로그 / 오류 위치 ----------
    def log(self, rec):
        sys.stdout.write(core.json_dumps(rec) + "\n")
        sys.stdout.flush()

    def locate(self, exc):
        at = getattr(exc, "_sori_at", None)
        if not at or self.interp is None:
            return None
        return self.interp.where(at)

    def describe(self, exc):
        code, msg = friendly(exc)
        loc = self.locate(exc)
        where = f"{loc[0]}:{loc[1]}" if loc and loc[0] else "?"
        return code, msg, where

    def log_exception(self, exc, rid, where_label, security=False):
        code, msg, where = self.describe(exc)
        rec = {"level": "error", "msg": "security policy violation" if security else "runtime error",
               "code": "SORI-" + code, "error": msg, "at": where, "route": where_label, "request_id": rid}
        if self.env != "production" and not isinstance(exc, (SecurityError, SoriTypeError, ExpectFailed, ResourceLimit)):
            rec["py_trace"] = traceback.format_exception_only(type(exc), exc)[-1].strip()
        self.log(rec)

    def dev_detail(self, exc):
        if self.env == "production":
            return None
        code, msg, where = self.describe(exc)
        return {"code": "SORI-" + code, "detail": msg, "at": where, "note": "개발 모드에서만 보이는 정보예요"}


def build_app(path):
    app = App(path)
    diags = app.compile()
    return app, diags
