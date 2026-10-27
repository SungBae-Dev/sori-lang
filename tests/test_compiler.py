import unittest
from sori.compiler import SoriSyntaxError, parse, manifest
from sori.runtime import evaluate, validate_input, InvalidInput


class CompilerTests(unittest.TestCase):
    def test_parse_and_interpret(self):
        program = parse('''app "demo"
route POST "/v1" protected:
  input name: str(1, 10)
  input count: int(0, 3)
  return {"hello": "hi " + input.name, "plus": input.count + 2, "ok": input.count > 1}
''')
        route = program.routes[0]
        self.assertEqual(evaluate(route.expression, {'name': 'Kim', 'count': 2}),
                         {'hello': 'hi Kim', 'plus': 4, 'ok': True})
        self.assertEqual(manifest(program)['routes'][0]['auth'], 'protected')

    def test_forbidden_code_and_attributes(self):
        for expression in ('__import__("os").system("id")', 'input.name.__class__',
                           'open("/etc/passwd")', '(lambda x: x)(1)',
                           '[i for i in [1]]', 'input.__class__'):
            with self.subTest(expression=expression):
                with self.assertRaises(SoriSyntaxError):
                    parse(f'''app "demo"
route POST "/x" protected:
  input name: str(0, 8)
  return {{"v": {expression}}}
''')

    def test_duplicate_return_object_key(self):
        with self.assertRaises(SoriSyntaxError):
            parse('app "demo"\nroute GET "/x" public:\n  return {"v": 1, "v": 2}')

    def test_access_policy_mandatory(self):
        with self.assertRaises(SoriSyntaxError):
            parse('app "demo"\nroute GET "/admin":\n  return {"x": 1}')

    def test_declared_field_mandatory(self):
        with self.assertRaises(SoriSyntaxError):
            parse('app "demo"\nroute POST "/x" public:\n  return {"x": input.secret}')

    def test_worker_must_be_fixed_loopback(self):
        for url in ('http://example.com/invoke', 'http://169.254.169.254/latest/meta-data',
                    'http://127.0.0.1:9010/invoke?url=evil', 'https://127.0.0.1:9010/invoke'):
            with self.subTest(url=url):
                with self.assertRaises(SoriSyntaxError):
                    parse(f'''app "demo"
worker "x" "{url}" timeout 1000
route POST "/x" protected:
  invoke "x"
''')

    def test_reject_undeclared_fields_and_bool_as_int(self):
        field = parse('app "demo"\nroute POST "/x" protected:\n  input count: int(0, 5)\n  return {"x": input.count}').routes[0].fields
        with self.assertRaises(InvalidInput):
            validate_input(field, {'count': True})
        with self.assertRaises(InvalidInput):
            validate_input(field, {'count': 2, 'admin': True})

    def test_cannot_do_get_with_worker(self):
        with self.assertRaises(SoriSyntaxError):
            parse('''app "demo"
worker "model" "http://127.0.0.1:9010/invoke" timeout 1000
route GET "/risk" protected:
  invoke "model"
''')

    def test_duplicate_route_is_error(self):
        with self.assertRaises(SoriSyntaxError):
            parse('''app "demo"
route GET "/h" public:
  return {"ok": true}
route GET "/h" protected:
  return {"ok": 1}
''')


if __name__ == '__main__':
    unittest.main()
