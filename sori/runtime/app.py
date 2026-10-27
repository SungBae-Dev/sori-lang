"""SORI 애플리케이션 로더: sori.toml → 컴파일 → 제한된 네임스페이스에서 실행."""
import glob
import hashlib
import hmac
import secrets
import importlib
import json
import os
import sys
import threading
import tomllib
import traceback

from ..compiler import compile_project
from ..diagnostics import SoriError
from ..policy import TOKEN_ENV, token_problem
from . import core
from .core import SecurityError, ExpectFailed, SoriTypeError, SoriInputError, SoriUserError
from .stdlib import STD, Caps
from .web import Metrics, RateLimiter, Route, Router, TaskRunner, TestClient

VERSION = "0.1.0"
APP_FILENAME = "<sori-app>"

_PY_ERRORS = {
    ZeroDivisionError: "0 으로 나눌 수 없어요",
    IndexError: "목록 범위를 벗어났어요",
    KeyError: "맵에 해당 키가 없어요",
    RecursionError: "재귀가 너무 깊어요",
}


def friendly(exc):
    if isinstance(exc, (SecurityError, SoriTypeError, SoriInputError, SoriUserError, ExpectFailed)):
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


def load_config(path):
    path = os.path.abspath(path)
    if os.path.isfile(path):
        root, files = os.path.dirname(path), [path]
    else:
        root = path
        files = sorted(glob.glob(os.path.join(root, "*.sori"))) + sorted(glob.glob(os.path.join(root, "src", "**", "*.sori"), recursive=True))
    cfg_path = os.path.join(root, "sori.toml")
    config = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "rb") as f:
            config = tomllib.load(f)
    return root, config, files


class RuntimeAPI:
    """생성 코드가 '_R' 로 접근하는 유일한 통로."""

    def __init__(self, app):
        self._app = app
        self.T, self.NODEF = core.T, core.NODEF
        self.record, self.check, self.cat, self.sql, self.html, self.err = core.record, core.check, core.cat, core.sql, core.html, core.err

    def use_std(self, name):
        return self._app.std_module(name)

    def use_py(self, name):
        root = name.split(".")[0]
        if root not in self._app.caps.python:
            raise SecurityError(f"파이썬 패키지 '{root}' 권한이 없어요")
        return importlib.import_module(name)

    def route(self, method, path, fn, specs, access, doc):
        self._app.router.add(Route(method, path, fn, specs, access, doc))

    def guard(self, fn, name):
        self._app.guards[name] = fn

    def task(self, name, period, fn):
        self._app.tasks.append((name, period, fn))

    def test(self, name, fn, file, line):
        self._app.tests.append((name, fn, file, line))

    def bearer(self, req):
        """내장 guard: Authorization: Bearer <SORI_API_TOKEN> 상수 시간 비교 (SORI v0.1 protected 계승)."""
        auth = req.header("authorization", "")
        if not auth.startswith("Bearer "):
            return False
        token = self._app.api_token
        return bool(token) and hmac.compare_digest(auth[7:].encode(), token.encode())


class App:
    def __init__(self, path):
        self.root, self.config, self.files = load_config(path)
        self.sources = {}
        for f in self.files:
            with open(f, encoding="utf-8") as fh:
                self.sources[os.path.relpath(f, self.root)] = fh.read()
        self.perms = self.config.get("permissions", {})
        self.caps = Caps(self.perms, self.root)
        self.env = os.environ.get("SORI_ENV", self.config.get("app", {}).get("env", "development"))
        self.router, self.guards, self.tasks, self.tests = Router(), {}, [], []
        self.metrics = Metrics()
        self.rate = RateLimiter(int(self.config.get("security", {}).get("rate_limit_per_min", 600)))
        self.access_log = bool(self.config.get("app", {}).get("access_log", True))
        self.ready = False
        self._std = {}
        self._lock = threading.Lock()
        self.project = None
        self.linemap = []
        self.pysrc = ""
        self.api_token = ""

    # ---------- 컴파일 ----------
    def compile(self):
        self.project = compile_project(self.sources, self.config)
        self.pysrc, self.linemap = self.project.python_source()
        return self.project.diags

    def errors(self):
        return [d for d in self.project.diags if d.severity == "error"]

    def load(self):
        code = compile(self.pysrc, APP_FILENAME, "exec")
        g = dict(core.BUILTINS)
        g["client"] = TestClient(self)
        g["_R"] = RuntimeAPI(self)
        g["__builtins__"] = core.SAFE_PY_BUILTINS
        g["__name__"] = "sori_app"
        exec(code, g)
        return self

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

    # ---------- 실패 시 기동 거부 (fail-closed) ----------
    def startup_problems(self, mode):
        """mode: 'serve' 면 엄격 검사, 'test' 면 테스트용 임시 토큰 발급."""
        problems = []
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
                val = os.environ.get(name, "")
                if len(val) < need:
                    problems.append(f"필수 비밀값 {name} 이(가) 없거나 {need}자 미만이에요 ([secrets] 규칙)")
            if self.env == "production":
                bad = self.verify_lock()
                if bad is None and not self.config.get("app", {}).get("allow_unlocked", False):
                    problems.append("프로덕션인데 sori.lock 이 없어요 — 'sori build' 로 생성하세요")
                elif bad:
                    problems.append("소스 무결성 검증 실패 (sori.lock 과 다름): " + ", ".join(sorted(bad)))
        return problems

    def extra_files(self):
        """워커 사이드카 스크립트 등 앱 폴더 안의 추가 파일 (빌드 복사 + 무결성 해시 대상)."""
        out = []
        for cfg in self.config.get("workers", {}).values():
            for arg in cfg.get("command", []) if isinstance(cfg, dict) else []:
                full = os.path.realpath(os.path.join(self.root, arg))
                if full.startswith(os.path.realpath(self.root) + os.sep) and os.path.isfile(full):
                    out.append(os.path.relpath(full, self.root))
        return sorted(set(out))

    # ---------- 무결성(공급망) ----------
    def lock_digest(self):
        h = {}
        for rel, src in sorted(self.sources.items()):
            h[rel] = hashlib.sha256(src.encode()).hexdigest()
        for rel in self.extra_files():
            with open(os.path.join(self.root, rel), "rb") as f:
                h[rel] = hashlib.sha256(f.read()).hexdigest()
        cfg = os.path.join(self.root, "sori.toml")
        if os.path.exists(cfg):
            with open(cfg, "rb") as f:
                h["sori.toml"] = hashlib.sha256(f.read()).hexdigest()
        return h

    def verify_lock(self):
        p = os.path.join(self.root, "sori.lock")
        if not os.path.exists(p):
            return None
        with open(p, encoding="utf-8") as f:
            lock = json.load(f)
        cur = self.lock_digest()
        bad = [k for k in set(cur) | set(lock.get("files", {})) if cur.get(k) != lock.get("files", {}).get(k)]
        return bad

    # ---------- 로그 / 오류 위치 ----------
    def log(self, rec):
        sys.stdout.write(core.json_dumps(rec) + "\n")
        sys.stdout.flush()

    def locate(self, exc):
        tb = exc.__traceback__
        loc = None
        while tb:
            if tb.tb_frame.f_code.co_filename == APP_FILENAME:
                ln = tb.tb_lineno
                if 0 < ln <= len(self.linemap):
                    loc = self.linemap[ln - 1]
            tb = tb.tb_next
        return loc

    def describe(self, exc):
        code, msg = friendly(exc)
        loc = self.locate(exc)
        where = f"{loc[0]}:{loc[1]}" if loc and loc[0] else "?"
        return code, msg, where

    def log_exception(self, exc, rid, where_label, security=False):
        code, msg, where = self.describe(exc)
        rec = {"level": "error", "msg": "security policy violation" if security else "runtime error",
               "code": "SORI-" + code, "error": msg, "at": where, "route": where_label, "request_id": rid}
        if self.env != "production" and not isinstance(exc, (SecurityError, SoriTypeError, ExpectFailed)):
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
