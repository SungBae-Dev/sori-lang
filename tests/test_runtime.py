import asyncio
import json
import unittest
from sori.compiler import parse, parse_file
from sori.runtime import create_app, parse_json, InvalidInput

TOKEN = 'a' * 48


async def request(app, method, path, data=None, token=None, content_type='application/json', headers=None):
    sent = []
    all_headers = list(headers or [])
    if token is not None:
        all_headers.append((b'authorization', ('Bearer ' + token).encode()))
    if data is not None:
        all_headers.append((b'content-type', content_type.encode()))
    body = data if isinstance(data, bytes) else json.dumps(data).encode() if data is not None else b''
    received = False

    async def receive():
        nonlocal received
        if received:
            return {'type': 'http.disconnect'}
        received = True
        return {'type': 'http.request', 'body': body, 'more_body': False}

    async def send(message):
        sent.append(message)

    await app({'type': 'http', 'method': method, 'path': path, 'headers': all_headers}, receive, send)
    return sent[0]['status'], json.loads(sent[1]['body']), dict(sent[0]['headers'])


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = parse_file('examples/hello.sori')
        cls.app = create_app(cls.program, token=TOKEN)

    def check(self, method, path, data=None, token=None, **kwargs):
        return asyncio.run(request(type(self).app, method, path, data, token, **kwargs))

    def test_public_health(self):
        status, payload, headers = self.check('GET', '/health')
        self.assertEqual(status, 200)
        self.assertEqual(payload['status'], 'ok')
        self.assertEqual(headers[b'x-content-type-options'], b'nosniff')

    def test_auth_denied_and_valid(self):
        self.assertEqual(self.check('POST', '/greet', {'name': 'Kim'})[0], 401)
        self.assertEqual(self.check('POST', '/greet', {'name': 'Kim'}, 'bad')[0], 401)
        self.assertEqual(self.check('POST', '/greet', {'name': 'Kim'}, TOKEN)[1]['message'], '안녕하세요, Kim')

    def test_invalid_payload(self):
        self.assertEqual(self.check('POST', '/add', {'a': True, 'b': 1}, TOKEN)[0], 400)
        self.assertEqual(self.check('POST', '/add', {'a': 1, 'b': 1001}, TOKEN)[0], 400)
        self.assertEqual(self.check('POST', '/add', {'a': 1, 'b': 2, 'is_admin': True}, TOKEN)[0], 400)
        self.assertEqual(self.check('POST', '/add', b'{"a":1,"a":2,"b":3}', TOKEN)[0], 400)
        self.assertEqual(self.check('POST', '/add', b'{"a": NaN, "b": 2}', TOKEN)[0], 400)
        self.assertEqual(self.check('POST', '/add', b'a' * (64 * 1024 + 1), TOKEN)[0], 413)
        self.assertEqual(self.check('POST', '/add', {'a': 1, 'b': 2}, TOKEN, content_type='text/plain')[0], 415)

    def test_arithmetic(self):
        self.assertEqual(self.check('POST', '/add', {'a': 15, 'b': -2}, TOKEN)[1]['result'], 13)

    def test_missing_token_fails_closed(self):
        with self.assertRaises(ValueError):
            create_app(self.program, token='')

    def test_no_duplicates_or_nan(self):
        for value in (b'{"x": 1, "x": 2}', b'{"x": NaN}', b'\xff', b'[' * 2000 + b']' * 2000):
            with self.assertRaises(InvalidInput):
                parse_json(value)

    def test_duplicate_auth_header(self):
        status, _, _ = self.check('POST', '/greet', {'name': 'hi'}, TOKEN,
                                  headers=[(b'authorization', b'Bearer ' + TOKEN.encode())])
        self.assertEqual(status, 401)

    def test_route_not_found(self):
        self.assertEqual(self.check('GET', '/other')[0], 404)
        self.assertEqual(self.check('GET', '/greet')[0], 405)


if __name__ == '__main__':
    unittest.main()
