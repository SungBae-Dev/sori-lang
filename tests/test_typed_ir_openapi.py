"""Static typing, artifact generation, and CLI acceptance checks."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sori.compiler import SoriSyntaxError, parse, parse_file
from sori.openapi import openapi
from sori.typed_ir import typed_ir

ROOT = Path(__file__).resolve().parents[1]


class TypedIRTests(unittest.TestCase):
    def test_ir_is_stable_and_contains_no_worker_urls(self):
        prog = parse_file(ROOT / 'examples/hello.sori')
        obj = typed_ir(prog)
        self.assertEqual(obj['ir_version'], 'sori/ir/v1')
        self.assertEqual(len(obj['routes']), len(prog.routes))
        encoded = json.dumps(obj, sort_keys=True, ensure_ascii=False, allow_nan=False)
        self.assertEqual(encoded, json.dumps(typed_ir(prog), sort_keys=True, ensure_ascii=False))
        self.assertNotIn('http://127.0.0.1:9010', encoded)
        self.assertEqual(obj['routes'][1]['action']['op'], 'object')

    def test_static_reject_invalid_operand_pairs(self):
        for expr in ('input.name + 1', 'input.name - input.name',
                     'input.name > 4', '-input.name', '1 + True', 'False - 1'):
            with self.subTest(expr=expr):
                with self.assertRaisesRegex(SoriSyntaxError, 'type error'):
                    parse('''app "demo"
route POST "/bad" protected:
  input name: str(1, 10)
  return {"bad": ''' + expr + '}')

    def test_reject_nonfinite_or_excessive_literals(self):
        for expression in ('1e309', '-1e309', '1000000000000000'):
            with self.subTest(expression=expression):
                with self.assertRaises(SoriSyntaxError):
                    parse(f'app "demo"\nroute GET "/bad" public:\n  return {{"n": {expression}}}')

    def test_public_worker_invoke_rejected(self):
        with self.assertRaisesRegex(SoriSyntaxError, 'protected access'):
            parse('''app "demo"
worker "risk" "http://127.0.0.1:9010/invoke" timeout 900
route POST "/risk" public:
  invoke "risk"''')

    def test_valid_numeric_mix(self):
        prog = parse('''app "mixed"
route POST "/calc" protected:
  input x: int(0, 20)
  input y: float(0, 5)
  return {"value": input.x + input.y, "flag": input.x > input.y}
''')
        body = typed_ir(prog)['routes'][0]['action']
        self.assertEqual(body['members'][0]['value']['type'], 'float')
        self.assertEqual(body['members'][1]['value']['type'], 'bool')


class OpenAPITests(unittest.TestCase):
    def test_openapi_schema_and_security(self):
        spec = openapi(parse_file(ROOT / 'examples/hello.sori'))
        self.assertEqual(spec['openapi'], '3.1.0')
        self.assertEqual(spec['paths']['/health']['get']['security'], [])
        greet = spec['paths']['/greet']['post']
        self.assertEqual(greet['security'], [{'bearerAuth': []}])
        req = greet['requestBody']['content']['application/json']['schema']
        self.assertEqual(req['additionalProperties'], False)
        self.assertEqual(req['properties']['name']['maxLength'], 80)
        self.assertIn('401', greet['responses'])
        worker = spec['paths']['/risk']['post']
        response = worker['responses']['200']['content']['application/json']['schema']
        self.assertEqual(response, {'type': 'object', 'additionalProperties': True})
        self.assertIn('502', worker['responses'])

    def test_nested_response_schema(self):
        prog = parse('''app "nested"
route GET "/ok" public:
  return {"ready": True, "list": [1, "a"], "inner": {"v": None}}
''')
        schema = openapi(prog)['paths']['/ok']['get']['responses']['200']['content']['application/json']['schema']
        self.assertEqual(schema['properties']['ready']['type'], 'boolean')
        self.assertEqual(schema['properties']['list']['prefixItems'][1]['type'], 'string')
        self.assertEqual(schema['properties']['inner']['properties']['v']['type'], 'null')


class CLITests(unittest.TestCase):
    def _cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'sori', *map(str, args)],
                              cwd=ROOT, text=True, capture_output=True, timeout=15)

    def test_cli_artifact_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'build'
            result = self._cli('build', ROOT / 'examples/hello.sori', '--out', output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('no native binary generated', result.stdout)
            for name in ('manifest.json', 'typed-ir.json', 'openapi.json'):
                self.assertTrue((output / name).exists())
                json.loads((output / name).read_text(encoding='utf-8'))

    def test_cli_new_and_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'newproject'
            result = self._cli('new', target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((target / 'app.sori').exists())
            self.assertEqual(self._cli('check', target / 'app.sori').returncode, 0)
            self.assertNotEqual(self._cli('new', target).returncode, 0)

    def test_cli_openapi_and_ir(self):
        for command, key in (('openapi', 'openapi'), ('ir', 'ir_version')):
            with self.subTest(command=command):
                result = self._cli(command, ROOT / 'examples/hello.sori')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(key, json.loads(result.stdout))


if __name__ == '__main__':
    unittest.main()