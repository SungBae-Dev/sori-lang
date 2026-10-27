"""ASGI 어댑터 — 운영 환경에서는 검증된 ASGI 서버(uvicorn 등) 위에서 같은 dispatch 를 실행한다.

내장 http.server 는 개발용이고, 운영에서는 `[app] server = "uvicorn"` 을 권장한다.
요청 스머글링/중복 헤더/본문 크기 검사는 내장 서버와 동일하게 적용된다.
"""
import asyncio
import re

from .web import SENSITIVE_DUP_HEADERS, _err, _security_headers, dispatch


def create_asgi(app):
    max_body = int(app.config.get("security", {}).get("max_body_kb", 1024)) * 1024
    state = {"runners": []}

    async def send_json(send, status, headers, out):
        headers = _security_headers(app, dict(headers))
        raw = [(k.lower().encode("latin-1"), str(v).encode("latin-1")) for k, v in headers.items()]
        raw.append((b"content-length", str(len(out)).encode()))
        await send({"type": "http.response.start", "status": status, "headers": raw})
        await send({"type": "http.response.body", "body": out})

    async def asgi(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    state["runners"] = app.start_tasks()
                    app.ready = True
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    app.ready = False
                    for r in state["runners"]:
                        r.stop.set()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        counts, headers = {}, {}
        for k, v in scope.get("headers", []):
            name = k.decode("latin-1").lower()
            counts[name] = counts.get(name, 0) + 1
            headers[name] = v.decode("latin-1")
        for h in SENSITIVE_DUP_HEADERS:
            if counts.get(h, 0) > 1:
                return await send_json(send, *_err(400, f"중복된 {h} 헤더 (해석 충돌 차단)", "-"))
        cl = headers.get("content-length", "0") or "0"
        if not re.fullmatch(r"\d{1,10}", cl.strip()):
            return await send_json(send, *_err(400, "잘못된 Content-Length", "-"))
        if int(cl) > max_body:
            app.metrics.security("body_too_large")
            return await send_json(send, *_err(413, f"본문이 너무 커요 (최대 {max_body // 1024}KB)", "-"))
        body = bytearray()
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            body.extend(msg.get("body", b""))
            if len(body) > max_body:
                app.metrics.security("body_too_large")
                return await send_json(send, *_err(413, f"본문이 너무 커요 (최대 {max_body // 1024}KB)", "-"))
            if not msg.get("more_body", False):
                break
        raw_path = scope.get("raw_path") or scope.get("path", "/").encode()
        target = raw_path.decode("latin-1")
        if scope.get("query_string"):
            target += "?" + scope["query_string"].decode("latin-1")
        client = scope.get("client") or ("-", 0)
        status, h, out = await asyncio.to_thread(dispatch, app, scope["method"], target, headers, bytes(body), client[0])
        await send_json(send, status, h, out)

    return asgi


def serve_uvicorn(app, host, port):
    try:
        import uvicorn
    except ImportError:
        raise SystemExit("uvicorn 이 없어요: pip install 'sori-lang[server]' (또는 [app] server = \"builtin\")")
    app.log({"level": "info", "msg": "sori server started", "server": "uvicorn", "host": host, "port": port,
             "routes": len(app.router.routes), "tasks": len(app.tasks), "env": app.env})
    uvicorn.run(create_asgi(app), host=host, port=port, proxy_headers=False, server_header=False,
                date_header=True, limit_concurrency=200, timeout_keep_alive=5, log_level="warning", lifespan="on")
