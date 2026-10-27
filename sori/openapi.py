"""Generate an OpenAPI 3.1 document from the checked SORI program.

Schema generation is conservative: worker outputs are unknown objects, not a
claim that a particular ML schema or authentication backend exists.
"""
from __future__ import annotations

from typing import Any

from .typed_ir import lower_expr

_TYPES = {
    'str': {'type': 'string'}, 'int': {'type': 'integer'},
    'float': {'type': 'number'}, 'bool': {'type': 'boolean'},
    'null': {'type': 'null'},
}


def field_schema(field: Any) -> dict:
    result = dict(_TYPES[field.kind])
    if field.kind == 'str':
        result.update(minLength=int(field.minimum), maxLength=int(field.maximum))
    elif field.kind in ('int', 'float'):
        result.update(minimum=field.minimum, maximum=field.maximum)
    return result


def expression_schema(expr: dict) -> dict:
    kind = expr['type']
    if kind == 'object':
        props = {m['name']: expression_schema(m['value']) for m in expr['members']}
        return {'type': 'object', 'properties': props, 'required': list(props),
                'additionalProperties': False}
    if kind == 'array':
        types = [expression_schema(e) for e in expr['items']]
        # An exact fixed tuple schema is supported by OpenAPI 3.1/JSON Schema 2020-12.
        return {'type': 'array', 'prefixItems': types, 'minItems': len(types),
                'maxItems': len(types), 'items': False}
    if kind in _TYPES:
        return dict(_TYPES[kind])
    raise ValueError(f'unsupported expression type: {kind}')


def openapi(program: Any) -> dict:
    paths: dict[str, dict] = {}
    for route in program.routes:
        responses: dict[str, dict] = {'200': {'description': 'Successful response'}}
        if route.worker_name:
            schema = {'type': 'object', 'additionalProperties': True}
            responses['502'] = {'description': 'Worker unavailable'}
        else:
            schema = expression_schema(lower_expr(route.expression, {f.name: f.kind for f in route.fields}))
        responses['200']['content'] = {'application/json': {'schema': schema}}
        if route.access == 'protected':
            responses['401'] = {'description': 'Missing or invalid bearer token'}
        operation: dict = {
            'operationId': f'{route.method.lower()}_{route.path.strip("/").replace("/", "_") or "root"}',
            'responses': responses,
            'security': ([{'bearerAuth': []}] if route.access == 'protected' else []),
        }
        if route.method == 'POST':
            props = {f.name: field_schema(f) for f in route.fields}
            operation['requestBody'] = {
                'required': True,
                'content': {'application/json': {
                    'schema': {'type': 'object', 'properties': props,
                               'required': list(props), 'additionalProperties': False}}},
            }
            operation['responses']['400'] = {'description': 'Invalid JSON or input schema'}
            operation['responses']['413'] = {'description': 'Request too large'}
            operation['responses']['415'] = {'description': 'Expected application/json'}
        paths.setdefault(route.path, {})[route.method.lower()] = operation
    return {
        'openapi': '3.1.0', 'info': {'title': program.name, 'version': '0.2.0-alpha.1'},
        'paths': paths,
        'components': {'securitySchemes': {'bearerAuth': {'type': 'http', 'scheme': 'bearer'}}},
    }