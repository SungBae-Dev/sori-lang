"""통합 테스트 공용 도구."""
import asyncio
import json
import os
import shutil
import socket
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def project(src, toml="[permissions]\n", extra=None):
    """임시 v0.3 프로젝트 폴더 생성 → 경로 반환 (호출 측에서 shutil.rmtree)."""
    d = tempfile.mkdtemp(prefix="sori_t_")
    Path(d, "sori.toml").write_text(toml, encoding="utf-8")
    Path(d, "app.sori").write_text(src, encoding="utf-8")
    for name, content in (extra or {}).items():
        p = Path(d, name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


def build(src, toml="[permissions]\n", extra=None):
    from sori.framework.app import build_app
    d = project(src, toml, extra)
    app, diags = build_app(d)
    return d, app, diags


def codes(diags):
    return [d.code for d in diags]


def loaded(src, toml="[permissions]\n", extra=None, mode="test"):
    d, app, diags = build(src, toml, extra)
    errs = [x for x in diags if x.severity == "error"]
    if errs:
        shutil.rmtree(d)
        raise AssertionError("\n".join(e.render(app.sources) for e in errs))
    app.access_log = False
    probs = app.startup_problems(mode)
    if probs:
        shutil.rmtree(d)
        raise AssertionError(probs)
    app.load()
    return d, app


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def asgi_request(app, method, path, data=None, token=None, content_type="application/json", headers=None,
                       raw_path=None):
    """B1 tests/test_runtime.py 와 같은 방식으로 ASGI 앱을 직접 호출."""
    sent = []
    all_headers = list(headers or [])
    if token is not None:
        all_headers.append((b"authorization", ("Bearer " + token).encode()))
    if data is not None:
        all_headers.append((b"content-type", content_type.encode()))
    body = data if isinstance(data, bytes) else json.dumps(data).encode() if data is not None else b""
    received = False

    async def receive():
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": method, "path": path, "headers": all_headers, "query_string": b""}
    if raw_path is not None:
        scope["raw_path"] = raw_path
    await app(scope, receive, send)
    status = sent[0]["status"]
    raw = sent[1]["body"] if len(sent) > 1 else b""
    try:
        payload = json.loads(raw) if raw else None
    except ValueError:
        payload = raw.decode("utf-8", "replace")
    return status, payload, dict(sent[0]["headers"])


def run(coro):
    return asyncio.run(coro)
