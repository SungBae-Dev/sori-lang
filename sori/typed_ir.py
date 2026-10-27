"""Statically typed, JSON-safe intermediate representation (experimental v1).

The compiler can produce this data without evaluating user code. It is intentionally
NOT a native executable or a wire protocol for a privileged worker.
"""
from __future__ import annotations

import ast
from typing import Any

IR_VERSION = 'sori/ir/v1'
_NUMERIC = {'int', 'float'}


class SoriTypeError(ValueError):
    """An expression was syntactically allowed but has invalid operand types."""


def _literal_type(value: Any) -> str:
    if value is None:
        return 'null'
    # bool is a subclass of int in Python: always use exact types.
    if type(value) is bool:
        return 'bool'
    if type(value) is int:
        return 'int'
    if type(value) is float:
        return 'float'
    if type(value) is str:
        return 'str'
    raise SoriTypeError('unsupported constant type')


def lower_expr(node: ast.AST, fields: dict[str, str]) -> dict[str, Any]:
    """Lower a validated AST and statically reject invalid arithmetic/comparisons."""
    if isinstance(node, ast.Constant):
        return {'op': 'literal', 'type': _literal_type(node.value), 'value': node.value}
    if isinstance(node, ast.Attribute):
        # Attribute shape was already checked by _validate_expr in compiler.
        if not isinstance(node.value, ast.Name) or node.value.id != 'input' or node.attr not in fields:
            raise SoriTypeError('undeclared input reference')
        return {'op': 'input', 'type': fields[node.attr], 'field': node.attr}
    if isinstance(node, ast.Dict):
        members: list[dict[str, Any]] = []
        for key, value in zip(node.keys, node.values):
            if not isinstance(key, ast.Constant) or type(key.value) is not str:
                raise SoriTypeError('object keys must be strings')
            members.append({'name': key.value, 'value': lower_expr(value, fields)})
        return {'op': 'object', 'type': 'object', 'members': members}
    if isinstance(node, (ast.List, ast.Tuple)):
        return {'op': 'array', 'type': 'array', 'items': [lower_expr(v, fields) for v in node.elts]}
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        operand = lower_expr(node.operand, fields)
        if operand['type'] not in _NUMERIC:
            raise SoriTypeError('unary minus requires a number')
        return {'op': 'neg', 'type': operand['type'], 'operand': operand}
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
        left, right = lower_expr(node.left, fields), lower_expr(node.right, fields)
        lt, rt = left['type'], right['type']
        operation = 'add' if isinstance(node.op, ast.Add) else 'subtract'
        if operation == 'add' and lt == rt == 'str':
            kind = 'str'
        elif lt in _NUMERIC and rt in _NUMERIC:
            kind = 'float' if 'float' in {lt, rt} else 'int'
        else:
            raise SoriTypeError(f'{operation} requires compatible numbers' +
                                (' or strings' if operation == 'add' else ''))
        return {'op': operation, 'type': kind, 'left': left, 'right': right}
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, right = lower_expr(node.left, fields), lower_expr(node.comparators[0], fields)
        op = node.ops[0]
        if isinstance(op, (ast.Eq, ast.NotEq)):
            name = 'equal' if isinstance(op, ast.Eq) else 'not_equal'
        elif isinstance(op, (ast.Gt, ast.GtE, ast.Lt, ast.LtE)):
            if left['type'] not in _NUMERIC or right['type'] not in _NUMERIC:
                raise SoriTypeError('ordered comparison requires numeric operands')
            name = ('greater' if isinstance(op, ast.Gt) else
                    'greater_or_equal' if isinstance(op, ast.GtE) else
                    'less' if isinstance(op, ast.Lt) else 'less_or_equal')
        else:
            raise SoriTypeError('unsupported comparison')
        return {'op': name, 'type': 'bool', 'left': left, 'right': right}
    raise SoriTypeError(f'unsupported expression node: {type(node).__name__}')


def typed_ir(program: Any) -> dict[str, Any]:
    """Deterministic typed IR. Loopback worker URLs deliberately excluded."""
    routes = []
    for r in program.routes:
        fields = {f.name: f.kind for f in r.fields}
        routes.append({
            'method': r.method, 'path': r.path, 'access': r.access,
            'inputs': [{'name': f.name, 'type': f.kind,
                        'minimum': f.minimum, 'maximum': f.maximum} for f in r.fields],
            'action': ({'op': 'invoke', 'worker': r.worker_name, 'type': 'object'}
                       if r.worker_name else lower_expr(r.expression, fields)),
        })
    return {
        'ir_version': IR_VERSION, 'app': program.name,
        'workers': [{'name': w.name, 'timeout_ms': w.timeout_ms} for w in program.workers],
        'routes': routes,
    }