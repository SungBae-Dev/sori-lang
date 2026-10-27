"""SORI v0.1: intentionally small, auditable language parser and validator.

This is a purpose-built declarative API language, not a general-purpose compiler.
No Python code from .sori files is compiled, exec'd, or eval'd.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import re
from pathlib import Path
from urllib.parse import urlsplit


class SoriSyntaxError(ValueError):
    pass


@dataclass(frozen=True)
class Field:
    name: str
    kind: str
    minimum: int | float | None = None
    maximum: int | float | None = None


@dataclass(frozen=True)
class Worker:
    name: str
    url: str
    timeout_ms: int


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    access: str
    fields: tuple[Field, ...]
    expression: ast.AST | None
    worker_name: str | None


@dataclass(frozen=True)
class Program:
    name: str
    routes: tuple[Route, ...]
    workers: tuple[Worker, ...]


APP = re.compile(r'app\s+"([^"\n]{1,80})"\s*')
WORKER = re.compile(r'worker\s+"([a-z][a-z0-9_-]{0,39})"\s+"([^"\n]+)"\s+timeout\s+(\d+)\s*')
ROUTE = re.compile(r'route\s+(GET|POST)\s+"([^"\n]+)"\s+(public|protected)\s*:\s*')
FIELD = re.compile(r'input\s+([a-z][a-z0-9_]*)\s*:\s*(str|int|float|bool)(?:\(\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*\))?\s*')
RETURN = re.compile(r'return\s+(.+)')
INVOKE = re.compile(r'invoke\s+"([a-z][a-z0-9_-]{0,39})"\s*')
PATH = re.compile(r'/(?:[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*)?')


def _error(line: int, message: str) -> SoriSyntaxError:
    return SoriSyntaxError(f'line {line}: {message}')


def _check_worker_url(url: str, line: int) -> None:
    parts = urlsplit(url)
    if (parts.scheme != 'http' or parts.hostname not in {'127.0.0.1', '::1'}
            or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment or not parts.path.startswith('/')):
        raise _error(line, 'worker URLs must be fixed HTTP loopback URLs without credentials/query/fragment')
    try:
        port = parts.port
    except ValueError:
        raise _error(line, 'invalid worker port') from None
    if port is None or not 1024 <= port <= 65535:
        raise _error(line, 'worker port must be 1024..65535')


def _field(text: str, line: int) -> Field:
    m = FIELD.fullmatch(text)
    if not m:
        raise _error(line, 'invalid input declaration')
    name, kind, lo, hi = m.groups()
    if kind == 'bool':
        if lo is not None:
            raise _error(line, 'bool must not have limits')
        return Field(name, kind)
    if lo is None or hi is None:
        raise _error(line, 'str/int/float must declare bounds')
    if kind != 'float' and ('.' in lo or '.' in hi):
        raise _error(line, 'str/int bounds must be integers')
    lower = float(lo) if kind == 'float' else int(lo)
    upper = float(hi) if kind == 'float' else int(hi)
    if lower > upper:
        raise _error(line, 'minimum exceeds maximum')
    if kind == 'str' and (lower < 0 or upper > 2048):
        raise _error(line, 'string length limit must be in 0..2048')
    if kind in {'int', 'float'} and (lower < -1_000_000 or upper > 1_000_000):
        raise _error(line, 'numeric bounds must be within +/-1,000,000')
    return Field(name, kind, lower, upper)


def _validate_expr(node: ast.AST, names: set[str], depth: int = 0) -> None:
    if depth > 12:
        raise SoriSyntaxError('expression nesting too deep')
    if isinstance(node, ast.Dict):
        seen_keys = set()
        for key, value in zip(node.keys, node.values):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                raise SoriSyntaxError('dictionary keys must be literal strings')
            if key.value in seen_keys:
                raise SoriSyntaxError('duplicate object key')
            seen_keys.add(key.value)
            _validate_expr(value, names, depth + 1)
    elif isinstance(node, (ast.List, ast.Tuple)):
        for item in node.elts:
            _validate_expr(item, names, depth + 1)
    elif isinstance(node, ast.Constant):
        if not (node.value is None or type(node.value) in (str, bool, int, float)):
            raise SoriSyntaxError('unsupported literal')
        if type(node.value) is str and len(node.value) > 2048:
            raise SoriSyntaxError('literal string too large')
    elif isinstance(node, ast.Attribute):
        if not isinstance(node.value, ast.Name) or node.value.id != 'input' or node.attr not in names:
            raise SoriSyntaxError('only declared input.<name> access is allowed')
    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
        _validate_expr(node.left, names, depth + 1)
        _validate_expr(node.right, names, depth + 1)
    elif isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq, ast.Gt, ast.GtE, ast.Lt, ast.LtE)):
        _validate_expr(node.left, names, depth + 1)
        _validate_expr(node.comparators[0], names, depth + 1)
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        _validate_expr(node.operand, names, depth + 1)
    else:
        raise SoriSyntaxError(f'disallowed expression: {type(node).__name__}')


def _parse_expression(text: str, names: set[str], line: int) -> ast.AST:
    if len(text) > 4096:
        raise _error(line, 'expression too long')
    try:
        tree = ast.parse(text, mode='eval')
    except SyntaxError:
        raise _error(line, 'invalid return expression') from None
    if sum(1 for _ in ast.walk(tree)) > 128:
        raise _error(line, 'expression too complex')
    if not isinstance(tree.body, ast.Dict):
        raise _error(line, 'return must be a JSON object literal')
    try:
        _validate_expr(tree.body, names)
    except SoriSyntaxError as exc:
        raise _error(line, str(exc)) from None
    return tree.body


def parse(source: str) -> Program:
    if len(source.encode('utf-8')) > 128 * 1024:
        raise SoriSyntaxError('source exceeds 128 KiB')
    lines = [(n, s) for n, s in enumerate(source.splitlines(), 1) if s.strip() and not s.lstrip().startswith('#')]
    app_name = None
    workers: dict[str, Worker] = {}
    routes: list[Route] = []
    i = 0
    while i < len(lines):
        n, line = lines[i]
        if line != line.lstrip():
            raise _error(n, 'top-level declarations cannot be indented')
        if (m := APP.fullmatch(line)):
            if app_name is not None:
                raise _error(n, 'duplicate app declaration')
            app_name = m.group(1)
            i += 1
            continue
        if (m := WORKER.fullmatch(line)):
            name, url, timeout_str = m.groups()
            if name in workers:
                raise _error(n, 'duplicate worker')
            _check_worker_url(url, n)
            timeout = int(timeout_str)
            if not 100 <= timeout <= 5000:
                raise _error(n, 'worker timeout must be 100..5000 milliseconds')
            workers[name] = Worker(name, url, timeout)
            i += 1
            continue
        m = ROUTE.fullmatch(line)
        if not m:
            raise _error(n, 'expected app, worker or route declaration')
        method, path, access = m.groups()
        if not PATH.fullmatch(path):
            raise _error(n, 'invalid route path')
        if any(route.path == path and route.method == method for route in routes):
            raise _error(n, 'duplicate route')
        i += 1
        fields: list[Field] = []
        expr = None
        worker_name = None
        terminated = False
        while i < len(lines) and lines[i][1].startswith(' '):
            body_line, body = lines[i]
            if not body.startswith('  ') or body.startswith('   ') or '\t' in body:
                raise _error(body_line, 'route body must use exactly two spaces')
            body = body[2:]
            if (matched := FIELD.fullmatch(body)):
                if terminated:
                    raise _error(body_line, 'input must precede return/invoke')
                fld = _field(body, body_line)
                if any(f.name == fld.name for f in fields):
                    raise _error(body_line, 'duplicate input')
                if len(fields) >= 32:
                    raise _error(body_line, 'maximum 32 fields per route')
                fields.append(fld)
            elif (matched := RETURN.fullmatch(body)):
                if terminated:
                    raise _error(body_line, 'only one return/invoke per route')
                expr = _parse_expression(matched.group(1), {f.name for f in fields}, body_line)
                terminated = True
            elif (matched := INVOKE.fullmatch(body)):
                if terminated:
                    raise _error(body_line, 'only one return/invoke per route')
                worker_name = matched.group(1)
                terminated = True
            else:
                raise _error(body_line, 'expected input, return or invoke')
            i += 1
        if not terminated:
            raise _error(n, 'route requires return or invoke')
        if method == 'GET' and (fields or worker_name):
            raise _error(n, 'GET routes cannot accept input or invoke workers')
        if worker_name is not None and method != 'POST':
            raise _error(n, 'worker routes must be POST')
        routes.append(Route(method, path, access, tuple(fields), expr, worker_name))
        if len(routes) > 128:
            raise _error(n, 'maximum 128 routes')
    if app_name is None:
        raise SoriSyntaxError('missing app declaration')
    if not routes:
        raise SoriSyntaxError('at least one route is required')
    for r in routes:
        if r.worker_name and r.worker_name not in workers:
            raise SoriSyntaxError(f'unknown worker: {r.worker_name}')
    return Program(app_name, tuple(routes), tuple(workers.values()))


def parse_file(path: str | Path) -> Program:
    return parse(Path(path).read_text(encoding='utf-8'))


def manifest(program: Program) -> dict:
    """Machine-readable surface for AI coding agents; no worker URLs or secrets."""
    return {
        'schema_version': 'sori/v0.1',
        'app': program.name,
        'routes': [{
            'method': r.method, 'path': r.path, 'auth': r.access,
            'inputs': [f.__dict__ for f in r.fields],
            'worker': r.worker_name,
        } for r in program.routes],
    }
