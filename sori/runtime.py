"""ASGI runtime for SORI. Prototype API only; relies on a maintained ASGI server."""
from __future__ import annotations

import ast
import asyncio
import hmac
import json
import math
import os
import urllib.request
from typing import Any

from .compiler import Field, Program, Route, Worker

MAX_BODY = 64 * 1024
MAX_RESULT = 64 * 1024
HEADERS = [
    (b'content-type', b'application/json; charset=utf-8'),
    (b'x-content-type-options', b'nosniff'),
    (b'cache-control', b'no-store'),
    (b'referrer-policy', b'no-referrer'),
    (b'x-frame-options', b'DENY'),
    (b'content-security-policy', b"default-src 'none'; frame-ancestors 'none'"),
]


class InvalidInput(ValueError):
    pass


class UpstreamError(Exception):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    out = {}
    for k, v in pairs:
        if k in out:
            raise InvalidInput('duplicate JSON key')
        out[k] = v
    return out


def _bad_constant(value: str) -> None:
    raise InvalidInput(f'invalid JSON constant: {value}')


def parse_json(data: bytes) -> Any:
    try:
        value = json.loads(data.decode('utf-8', errors='strict'), object_pairs_hook=_no_duplicates, parse_constant=_bad_constant)
        stack = [(value, 0)]
        examined = 0
        while stack:
            node, depth = stack.pop()
            examined += 1
            if depth > 32 or examined > 8192:
                raise InvalidInput('JSON nesting or size limit exceeded')
            if isinstance(node, dict):
                stack.extend((v, depth + 1) for v in node.values())
            elif isinstance(node, list):
                stack.extend((v, depth + 1) for v in node)
        return value
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise InvalidInput('malformed JSON') from exc


def validate_input(fields: tuple[Field, ...], body: Any) -> dict:
    if not isinstance(body, dict):
        raise InvalidInput('request body must be an object')
    expected = {f.name for f in fields}
    if body.keys() != expected:
        raise InvalidInput('input keys differ from declared schema')
    checked: dict[str, Any] = {}
    for field in fields:
        value = body[field.name]
        if field.kind == 'str':
            valid = type(value) is str and field.minimum <= len(value) <= field.maximum
        elif field.kind == 'int':
            valid = type(value) is int and field.minimum <= value <= field.maximum
        elif field.kind == 'float':
            valid = type(value) in (int, float) and math.isfinite(value) and field.minimum <= value <= field.maximum
            if valid:
                value = float(value)
        else:
            valid = type(value) is bool
        if not valid:
            raise InvalidInput(f'invalid value for {field.name}')
        checked[field.name] = value
    return checked


def evaluate(node: ast.AST, data: dict[str, Any], depth: int = 0) -> Any:
    """Explicit AST interpreter; no Python eval/exec/import/call from SORI."""
    if depth > 12:
        raise ValueError('expression depth exceeded')
    if isinstance(node, ast.Dict):
        return {k.value: evaluate(v, data, depth + 1) for k, v in zip(node.keys, node.values)}
    if isinstance(node, (ast.List, ast.Tuple)):
        return [evaluate(v, data, depth + 1) for v in node.elts]
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Attribute):
        return data[node.attr]
    if isinstance(node, ast.BinOp):
        a = evaluate(node.left, data, depth + 1)
        b = evaluate(node.right, data, depth + 1)
        if isinstance(node.op, ast.Add) and ((type(a) is str and type(b) is str) or (type(a) in (int, float) and type(b) in (int, float))):
            return a + b
        if isinstance(node.op, ast.Sub) and type(a) in (int, float) and type(b) in (int, float):
            return a - b
        raise ValueError('invalid operand types')
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        value = evaluate(node.operand, data, depth + 1)
        if type(value) in (int, float):
            return -value
        raise ValueError('invalid unary operator')
    if isinstance(node, ast.Compare):
        a = evaluate(node.left, data, depth + 1)
        b = evaluate(node.comparators[0], data, depth + 1)
        op = node.ops[0]
        if isinstance(op, ast.Eq):
            return type(a) is type(b) and a == b
        if isinstance(op, ast.NotEq):
            return type(a) is not type(b) or a != b
        if type(a) not in (int, float) or type(b) not in (int, float):
            raise ValueError('comparison requires numbers')
        return (a > b if isinstance(op, ast.Gt) else
                a >= b if isinstance(op, ast.GtE) else
                a < b if isinstance(op, ast.Lt) else a <= b)
    raise ValueError('unsupported expression')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _invoke_worker(worker: Worker, payload: dict) -> dict:
    """Only fixed, compiler-checked loopback URLs. Do not follow redirects or proxies."""
    data = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode('utf-8')
    if len(data) > MAX_BODY:
        raise UpstreamError('payload too large')
    req = urllib.request.Request(worker.url, data=data, method='POST', headers={'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(req, timeout=worker.timeout_ms / 1000) as result:
            if result.status != 200 or result.headers.get_content_type() != 'application/json':
                raise UpstreamError('invalid upstream response')
            body = result.read(MAX_RESULT + 1)
            if len(body) > MAX_RESULT:
                raise UpstreamError('upstream response too large')
        response = parse_json(body)
        if not isinstance(response, dict):
            raise UpstreamError('upstream response must be object')
        return response
    except (OSError, ValueError, InvalidInput) as exc:
        raise UpstreamError('worker failed') from exc


async def _json_response(send, status: int, payload: dict) -> None:
    try:
        body = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')
        if len(body) > MAX_RESULT:
            raise ValueError('response too large')
    except (ValueError, TypeError, OverflowError):
        status = 500
        body = b'{"error":"internal server error"}'
    await send({'type': 'http.response.start', 'status': status, 'headers': HEADERS})
    await send({'type': 'http.response.body', 'body': body})


async def _read_body(receive) -> bytes:
    data = bytearray()
    while True:
        message = await receive()
        if message['type'] == 'http.disconnect':
            raise ConnectionError('client disconnected')
        if message['type'] != 'http.request':
            raise InvalidInput('invalid request event')
        chunk = message.get('body', b'')
        if len(data) + len(chunk) > MAX_BODY:
            raise OverflowError('request too large')
        data.extend(chunk)
        if not message.get('more_body', False):
            return bytes(data)


def create_app(program: Program, token: str | None = None):
    """Create a standards-compliant ASGI callable. Proxy/TLS/network policy are deployment concerns."""
    protected = any(r.access == 'protected' for r in program.routes)
    if token is None:
        token = os.getenv('SORI_API_TOKEN', '')
    if protected and (len(token) < 32 or len(token) > 4096 or '\n' in token or '\r' in token):
        raise ValueError('protected routes require SORI_API_TOKEN of at least 32 characters')
    route_map = {(r.method, r.path): r for r in program.routes}
    worker_map = {w.name: w for w in program.workers}
    all_paths = {r.path for r in program.routes}

    async def app(scope, receive, send):
        if scope['type'] == 'lifespan':
            while True:
                message = await receive()
                if message['type'] == 'lifespan.startup':
                    await send({'type': 'lifespan.startup.complete'})
                elif message['type'] == 'lifespan.shutdown':
                    await send({'type': 'lifespan.shutdown.complete'})
                    return
        if scope['type'] != 'http':
            return
        method, path = scope.get('method', ''), scope.get('path', '')
        route = route_map.get((method, path))
        if route is None:
            status = 405 if path in all_paths else 404
            return await _json_response(send, status, {'error': 'method not allowed' if status == 405 else 'not found'})
        headers = scope.get('headers', [])
        header_map: dict[bytes, list[bytes]] = {}
        for key, value in headers:
            header_map.setdefault(key.lower(), []).append(value)
        if route.access == 'protected':
            auth = header_map.get(b'authorization', [])
            if len(auth) != 1 or not auth[0].startswith(b'Bearer '):
                return await _json_response(send, 401, {'error': 'unauthorized'})
            try:
                supplied = auth[0][7:].decode('ascii')
            except UnicodeError:
                return await _json_response(send, 401, {'error': 'unauthorized'})
            if not hmac.compare_digest(supplied, token):
                return await _json_response(send, 401, {'error': 'unauthorized'})
        data = {}
        if method == 'POST':
            content_type = header_map.get(b'content-type', [])
            if len(content_type) != 1 or content_type[0].lower().split(b';')[0].strip() != b'application/json':
                return await _json_response(send, 415, {'error': 'application/json required'})
            try:
                raw = await _read_body(receive)
                data = validate_input(route.fields, parse_json(raw))
            except ConnectionError:
                return
            except OverflowError:
                return await _json_response(send, 413, {'error': 'request too large'})
            except InvalidInput as exc:
                return await _json_response(send, 400, {'error': str(exc)})
        try:
            if route.worker_name:
                answer = await asyncio.to_thread(_invoke_worker, worker_map[route.worker_name], data)
            else:
                answer = evaluate(route.expression, data)
            await _json_response(send, 200, answer)
        except UpstreamError:
            await _json_response(send, 502, {'error': 'worker unavailable'})
        except (ValueError, TypeError, OverflowError, KeyError):
            await _json_response(send, 500, {'error': 'internal server error'})
    return app
