"""SORI 웹 런타임: 라우팅, 입력 검증, 기본 보안 헤더, CSRF/스머글링/압축폭탄 방어, 메트릭."""
import json as _json
import mimetypes
import os
import re
import secrets
import signal
import threading
import time
import urllib.parse
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .core import (SoriInputError, SoriUserError, SoriUpstreamError, ExpectFailed, NODEF, Response, SafeHtml, SecurityError,
                   json_dumps, json_loads, tostr, List as TList, Opt)

DEFAULT_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
               "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SENSITIVE_DUP_HEADERS = {"host", "content-length", "transfer-encoding", "origin", "authorization", "content-type", "cookie"}


class Request:
    __slots__ = ("method", "path", "headers", "query_params", "body", "ip", "id", "_form", "_json")

    def __init__(self, method, path, headers, query_params, body, ip, rid):
        self.method, self.path, self.headers = method, path, headers
        self.query_params, self.body, self.ip, self.id = query_params, body, ip, rid
        self._form = self._json = None

    def header(self, name, default=None):
        return self.headers.get(tostr(name).lower(), default)

    def query(self, name, default=None):
        v = self.query_params.get(tostr(name))
        return v[0] if v else default

    def cookie(self, name, default=None):
        for part in self.headers.get("cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return urllib.parse.unquote(v)
        return default

    def json(self):
        if self._json is None:
            self._json = json_loads(self.body.decode("utf-8", errors="strict")) if self.body else None
        return self._json

    def form(self):
        if self._form is None:
            pairs = urllib.parse.parse_qs(self.body.decode("utf-8", errors="strict"), keep_blank_values=True,
                                          max_num_fields=1000, strict_parsing=False)
            self._form = {k: (v[0] if len(v) == 1 else v) for k, v in pairs.items()}
        return self._form

    def __repr__(self):
        return f"Request({self.method} {self.path})"


class Route:
    def __init__(self, method, path, fn, specs, access, doc):
        self.method, self.path, self.fn, self.specs, self.access, self.doc = method, path, fn, specs, access, doc
        self.segments = []
        for seg in path.strip("/").split("/") if path != "/" else []:
            m = re.fullmatch(r"\{([^/{}]+)\}", seg)
            self.segments.append(("param", m.group(1)) if m else ("lit", seg))


class Router:
    def __init__(self):
        self.routes = []

    def add(self, r):
        self.routes.append(r)

    def match(self, method, segs):
        allowed = []
        for r in self.routes:
            if len(r.segments) != len(segs):
                continue
            params, ok = {}, True
            for (kind, v), s in zip(r.segments, segs):
                if kind == "lit":
                    if v != s:
                        ok = False
                        break
                else:
                    params[v] = s
            if ok:
                if r.method == method or (method == "HEAD" and r.method == "GET"):
                    return r, params, []
                allowed.append(r.method)
        return None, None, allowed


class RateLimiter:
    def __init__(self, per_min):
        self.rate = per_min / 60.0
        self.cap = max(1.0, per_min / 6.0)
        self.buckets = {}
        self.lock = threading.Lock()

    def allow(self, key):
        if self.rate <= 0:
            return True
        now = time.monotonic()
        with self.lock:
            tokens, last = self.buckets.get(key, (self.cap, now))
            tokens = min(self.cap, tokens + (now - last) * self.rate)
            if tokens < 1:
                self.buckets[key] = (tokens, now)
                return False
            self.buckets[key] = (tokens - 1, now)
            if len(self.buckets) > 50_000:
                self.buckets.clear()
            return True


class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.req = defaultdict(int)
        self.dur = defaultdict(float)
        self.sec = defaultdict(int)
        self.tasks = {}

    def observe(self, method, route, status, ms):
        with self.lock:
            self.req[(method, route, status)] += 1
            self.dur[(method, route)] += ms

    def security(self, kind):
        with self.lock:
            self.sec[kind] += 1

    def text(self):
        L = ["# TYPE sori_http_requests_total counter"]
        with self.lock:
            for (m, r, s), n in sorted(self.req.items()):
                L.append(f'sori_http_requests_total{{method="{m}",route="{r}",status="{s}"}} {n}')
            L.append("# TYPE sori_http_request_duration_ms_sum counter")
            for (m, r), v in sorted(self.dur.items()):
                L.append(f'sori_http_request_duration_ms_sum{{method="{m}",route="{r}"}} {v:.3f}')
            L.append("# TYPE sori_security_events_total counter")
            for k, n in sorted(self.sec.items()):
                L.append(f'sori_security_events_total{{kind="{k}"}} {n}')
            for name, st in sorted(self.tasks.items()):
                L.append(f'sori_task_runs_total{{task="{name}"}} {st["runs"]}')
                L.append(f'sori_task_overruns_total{{task="{name}"}} {st["overruns"]}')
                L.append(f'sori_task_errors_total{{task="{name}"}} {st["errors"]}')
                L.append(f'sori_task_last_ms{{task="{name}"}} {st["last_ms"]:.3f}')
                L.append(f'sori_task_max_jitter_ms{{task="{name}"}} {st["max_jitter_ms"]:.3f}')
        return "\n".join(L) + "\n"


def _security_headers(app, h):
    sec = app.config.get("security", {})
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    h.setdefault("Content-Security-Policy", sec.get("csp", DEFAULT_CSP))
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    h.setdefault("Cache-Control", "no-store")
    if sec.get("hsts", app.env == "production"):
        h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return h


def _err(status, message, rid, extra=None):
    body = {"error": message, "request_id": rid}
    if extra:
        body.update(extra)
    return status, {"Content-Type": "application/json; charset=utf-8"}, json_dumps(body).encode()


def _to_http(result):
    if isinstance(result, Response):
        status, body, headers, ct = result.status, result.body, dict(result.headers), result.content_type
    else:
        status, body, headers, ct = 200, result, {}, None
    if body is None:
        if not isinstance(result, Response):
            status = 204
        return status, headers, b""
    if ct and "html" in ct.lower() and not isinstance(body, SafeHtml):
        raise SecurityError("HTML 응답 본문은 html\"...\" 로 만든 값이어야 해요 (XSS 차단)")
    if isinstance(body, SafeHtml):
        headers.setdefault("Content-Type", ct or "text/html; charset=utf-8")
        return status, headers, str(body).encode()
    if isinstance(body, str):
        headers.setdefault("Content-Type", ct or "text/plain; charset=utf-8")
        return status, headers, body.encode()
    if isinstance(body, bytes):
        headers.setdefault("Content-Type", ct or "application/octet-stream")
        return status, headers, body
    headers.setdefault("Content-Type", ct or "application/json; charset=utf-8")
    return status, headers, json_dumps(body).encode()


def _split_path(path):
    if "\x00" in path or "\\" in path:
        raise SoriInputError("잘못된 경로 문자")
    if re.search(r"%2f|%5c|%00|%2e%2e", path, re.I):
        raise SoriInputError("인코딩된 경로 구분자는 허용되지 않아요 (경로 혼동 공격 차단)")
    segs = [s for s in path.split("/")]
    segs = segs[1:] if segs and segs[0] == "" else segs
    if segs and segs[-1] == "":
        segs = segs[:-1]
    out = []
    for s in segs:
        if s == "" or s in (".", ".."):
            raise SoriInputError("경로에 빈 세그먼트나 '..' 를 쓸 수 없어요")
        out.append(urllib.parse.unquote(s))
    return out


def _static(app, path):
    sdir = app.config.get("app", {}).get("static")
    if not sdir or not path.startswith("/static/"):
        return None
    base = os.path.realpath(os.path.join(app.root, sdir))
    full = os.path.realpath(os.path.join(base, path[len("/static/"):]))
    if not full.startswith(base + os.sep) or not os.path.isfile(full):
        return None
    ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
    with open(full, "rb") as f:
        return 200, {"Content-Type": ctype, "Cache-Control": "public, max-age=300"}, f.read()


def dispatch(app, method, target, headers, body, ip):
    """순수 함수형 요청 처리기 — HTTP 서버와 테스트 클라이언트가 공유한다."""
    rid = secrets.token_hex(6)
    t0 = time.perf_counter()
    route_label = "-"
    try:
        status, h, out, route_label = _dispatch(app, method, target, headers, body, ip, rid)
    except BaseException as e:  # 마지막 방어선
        if isinstance(e, (KeyboardInterrupt, SystemExit)):
            raise
        status, h, out = _err(500, "internal error", rid)
        app.log_exception(e, rid, "dispatch")
    h = _security_headers(app, dict(h))
    h["X-Request-Id"] = rid
    ms = (time.perf_counter() - t0) * 1000
    app.metrics.observe(method, route_label, status, ms)
    if app.access_log:
        app.log({"level": "info", "msg": "request", "method": method, "path": target.split("?")[0][:200],
                 "route": route_label, "status": status, "ms": round(ms, 2), "ip": ip, "request_id": rid})
    return status, h, out


def _dispatch(app, method, target, headers, body, ip, rid):
    sec = app.config.get("security", {})
    if len(target) > 8192:
        return (*_err(414, "URL 이 너무 길어요", rid), "-")
    u = urllib.parse.urlsplit(target)
    path = u.path or "/"
    if method == "GET" and path == "/healthz":
        return 200, {"Content-Type": "text/plain"}, b"ok", "/healthz"
    if method == "GET" and path == "/readyz":
        return (200 if app.ready else 503), {"Content-Type": "text/plain"}, (b"ready" if app.ready else b"starting"), "/readyz"
    if method == "GET" and path == "/metrics" and sec.get("metrics", True):
        return 200, {"Content-Type": "text/plain; version=0.0.4"}, app.metrics.text().encode(), "/metrics"
    if headers.get("transfer-encoding"):
        app.metrics.security("transfer_encoding")
        return (*_err(400, "Transfer-Encoding 요청은 받지 않아요 (요청 스머글링 차단)", rid), "-")
    enc = headers.get("content-encoding", "identity").lower()
    if enc not in ("identity", ""):
        app.metrics.security("compressed_body")
        return (*_err(415, f"압축된 요청 본문({enc})은 받지 않아요 (압축 해제기 취약점·압축폭탄 차단)", rid), "-")
    if method in UNSAFE_METHODS:
        origin = headers.get("origin")
        host = headers.get("host", "")
        allowed = set(sec.get("allowed_origins", [])) | {f"http://{host}", f"https://{host}"}
        if (origin and origin not in allowed) or headers.get("sec-fetch-site") == "cross-site":
            app.metrics.security("csrf")
            return (*_err(403, "다른 출처에서 온 상태 변경 요청이에요 (CSRF 차단)", rid), "-")
    if not app.rate.allow(ip):
        app.metrics.security("rate_limit")
        return (*_err(429, "요청이 너무 많아요", rid), "-")
    if method == "GET":
        st = _static(app, path)
        if st:
            return (*st, "/static")
    try:
        segs = _split_path(path)
    except SoriInputError as e:
        app.metrics.security("path")
        return (*_err(400, str(e), rid), "-")
    route, pparams, allowed = app.router.match(method, segs)
    if route is None:
        if allowed:
            s, h, b = _err(405, "허용되지 않는 메서드", rid)
            h["Allow"] = ", ".join(sorted(set(allowed)))
            return s, h, b, "-"
        return (*_err(404, "not found", rid), "-")
    label = route.path
    qs = urllib.parse.parse_qs(u.query, keep_blank_values=True, max_num_fields=200) if u.query else {}
    req = Request(method, path, headers, qs, body, ip, rid)
    try:
        kwargs = _bind(route, pparams, qs, req)
        if route.access[0] == "deny":
            return (*_err(403, "forbidden", rid), label)
        if route.access[0] == "guard":
            if not route.access[1](req):
                app.metrics.security("guard_denied")
                return (*_err(403, "forbidden", rid), label)
        result = route.fn(**kwargs)
        return (*_to_http(result), label)
    except SoriInputError as e:
        return (*_err(400, str(e), rid), label)
    except SoriUserError as e:
        return (*_err(e.status, str(e), rid), label)
    except SoriUpstreamError as e:
        app.log_exception(e, rid, label)
        return (*_err(502, "upstream unavailable", rid, app.dev_detail(e)), label)
    except SecurityError as e:
        app.metrics.security("policy_violation")
        app.log_exception(e, rid, label, security=True)
        return (*_err(403, "forbidden: 보안 정책 위반", rid, app.dev_detail(e)), label)
    except ExpectFailed as e:
        app.log_exception(e, rid, label)
        return (*_err(500, "internal error", rid, app.dev_detail(e)), label)
    except Exception as e:
        app.log_exception(e, rid, label)
        return (*_err(500, "internal error", rid, app.dev_detail(e)), label)


def _bind(route, pparams, qs, req):
    kwargs = {}
    ctype = req.headers.get("content-type", "").split(";")[0].strip().lower()
    for name, typ, default, src in route.specs:
        if src == "req":
            kwargs[name] = req
            continue
        if src == "path":
            kwargs[name] = typ.coerce(pparams[name], name)
            continue
        if src == "body":
            if not req.body:
                if default is not NODEF:
                    kwargs[name] = default
                    continue
                raise SoriInputError("요청 본문(body)이 필요해요")
            if ctype == "application/json":
                data = req.json()
            elif ctype == "application/x-www-form-urlencoded":
                data = req.form()
            else:
                raise SoriInputError("본문은 application/json 또는 form 이어야 해요 (multipart 는 지원하지 않아요)")
            kwargs[name] = typ.coerce(data, "body")
            continue
        vals = qs.get(name)
        if not vals:
            if default is not NODEF:
                kwargs[name] = default
            elif isinstance(typ, Opt):
                kwargs[name] = None
            else:
                raise SoriInputError(f"쿼리 파라미터 '{name}' 이(가) 필요해요")
            continue
        base = typ.inner if isinstance(typ, Opt) else typ
        if isinstance(base, TList):
            kwargs[name] = typ.coerce(vals, name)
        else:
            if len(vals) > 1:
                raise SoriInputError(f"쿼리 파라미터 '{name}' 이(가) 여러 번 왔어요 (파라미터 오염 차단)")
            kwargs[name] = typ.coerce(vals[0], name)
    return kwargs


# ---------------------------------------------------------------- HTTP 서버
def make_handler(app):
    max_body = int(app.config.get("security", {}).get("max_body_kb", 1024)) * 1024

    class Handler(BaseHTTPRequestHandler):
        server_version = "sori"
        sys_version = ""

        def version_string(self):  # 런타임/버전 정보 비노출
            return "sori"
        protocol_version = "HTTP/1.1"
        timeout = 15

        def _handle(self):
            raw = self.headers
            for h in SENSITIVE_DUP_HEADERS:
                if len(raw.get_all(h) or []) > 1:
                    return self._send(*_err(400, f"중복된 {h} 헤더 (해석 충돌 차단)", "-"))
            if raw.get("Transfer-Encoding"):
                app.metrics.security("transfer_encoding")
                return self._send(*_err(400, "Transfer-Encoding 요청은 받지 않아요 (요청 스머글링 차단)", "-"))
            cl = raw.get("Content-Length", "0") or "0"
            if not re.fullmatch(r"\d{1,10}", cl.strip()):
                return self._send(*_err(400, "잘못된 Content-Length", "-"))
            n = int(cl)
            if n > max_body:
                app.metrics.security("body_too_large")
                return self._send(*_err(413, f"본문이 너무 커요 (최대 {max_body // 1024}KB)", "-"))
            body = self.rfile.read(n) if n else b""
            headers = {k.lower(): v for k, v in raw.items()}
            ip = self.client_address[0]
            status, h, out = dispatch(app, self.command, self.path, headers, body, ip)
            self._send(status, h, out)

        def _send(self, status, headers, out):
            self.send_response(status)
            headers = _security_headers(app, dict(headers))
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(out)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(out)
            self.close_connection = True

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _handle

        def do_OPTIONS(self):
            self._send(204, {"Allow": "GET, POST, PUT, PATCH, DELETE"}, b"")

        def log_message(self, *a):
            pass

    return Handler


class TaskRunner:
    def __init__(self, app, name, period, fn):
        self.app, self.name, self.period, self.fn = app, name, period, fn
        self.stop = threading.Event()
        app.metrics.tasks[name] = {"runs": 0, "overruns": 0, "errors": 0, "last_ms": 0.0, "max_jitter_ms": 0.0}

    def run(self):
        st = self.app.metrics.tasks[self.name]
        start = time.perf_counter()
        k = 0
        while not self.stop.is_set():
            scheduled = start + k * self.period
            now = time.perf_counter()
            if scheduled > now:
                if self.stop.wait(scheduled - now):
                    break
            begin = time.perf_counter()
            jitter = (begin - scheduled) * 1000
            try:
                self.fn()
            except SecurityError as e:
                st["errors"] += 1
                self.app.log_exception(e, "-", f"task:{self.name}", security=True)
            except Exception as e:
                st["errors"] += 1
                self.app.log_exception(e, "-", f"task:{self.name}")
            dur = time.perf_counter() - begin
            st["runs"] += 1
            st["last_ms"] = dur * 1000
            st["max_jitter_ms"] = max(st["max_jitter_ms"], jitter)
            k += 1
            if dur > self.period:  # 마감 초과: 놓친 주기는 건너뛰고 다음 정시로
                st["overruns"] += 1
                k = int((time.perf_counter() - start) / self.period) + 1


def serve(app, host, port):
    server = ThreadingHTTPServer((host, port), make_handler(app))
    server.daemon_threads = True
    runners = app.start_tasks()

    def shutdown(*_):
        app.ready = False
        for r in runners:
            r.stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    try:
        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)
    except ValueError:
        pass
    app.ready = True
    app.log({"level": "info", "msg": "sori server started", "host": host, "port": port,
             "routes": len(app.router.routes), "tasks": len(runners), "env": app.env})
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        app.log({"level": "info", "msg": "sori server stopped"})


class ClientResponse:
    __slots__ = ("status", "headers", "text")

    def __init__(self, status, headers, body):
        self.status, self.headers, self.text = status, {k.lower(): v for k, v in headers.items()}, body.decode("utf-8", "replace")

    def json(self):
        return json_loads(self.text)

    def header(self, name):
        return self.headers.get(name.lower())

    def __repr__(self):
        return f"ClientResponse({self.status})"


class TestClient:
    """test 블록에서 쓰는 in-process 클라이언트 (네트워크 없이 dispatch 직접 호출)."""

    def __init__(self, app):
        self._app = app

    def _do(self, method, path, json=None, form=None, headers=None, auth=False):
        h = {"host": "localhost"}
        if auth:  # guard bearer 라우트 테스트용: 앱 토큰을 자동으로 붙임
            h["authorization"] = "Bearer " + self._app.api_token
        body = b""
        if json is not None:
            body = json_dumps(json).encode()
            h["content-type"] = "application/json"
        elif form is not None:
            body = urllib.parse.urlencode(form).encode()
            h["content-type"] = "application/x-www-form-urlencoded"
        for k, v in (headers or {}).items():
            h[k.lower()] = v.reveal() if hasattr(v, "reveal") else tostr(v)
        s, hd, out = dispatch(self._app, method, path, h, body, "127.0.0.1")
        return ClientResponse(s, _security_headers(self._app, dict(hd)), out)

    def get(self, path, headers=None, auth=False):
        return self._do("GET", path, headers=headers, auth=auth)

    def post(self, path, json=None, form=None, headers=None, auth=False):
        return self._do("POST", path, json, form, headers, auth)

    def put(self, path, json=None, headers=None, auth=False):
        return self._do("PUT", path, json, None, headers, auth)

    def patch(self, path, json=None, headers=None, auth=False):
        return self._do("PATCH", path, json, None, headers, auth)

    def delete(self, path, headers=None, auth=False):
        return self._do("DELETE", path, headers=headers, auth=auth)
