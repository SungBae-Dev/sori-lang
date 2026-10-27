import asyncio
import threading
import unittest
from http.server import HTTPServer
from edge.worker import Handler
from sori.compiler import parse
from sori.runtime import create_app
from test_runtime import request, TOKEN


class WorkerTests(unittest.TestCase):
    def test_python_bridge_end_to_end(self):
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            app = create_app(parse(f'''app "worker bridge"
worker "demo" "http://127.0.0.1:{port}/invoke" timeout 1500
route POST "/risk" protected:
  input signal: float(0, 1)
  invoke "demo"
'''), token=TOKEN)
            status, result, _ = asyncio.run(request(app, 'POST', '/risk', {'signal': 0.91}, TOKEN))
            self.assertEqual(status, 200)
            self.assertEqual(result['risk'], 'high')
            self.assertEqual(result['kind'], 'demo_threshold_not_ai')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_worker_unavailable_is_sanitized(self):
        app = create_app(parse('''app "demo"
worker "offline" "http://127.0.0.1:65534/invoke" timeout 100
route POST "/risk" protected:
  input signal: float(0, 1)
  invoke "offline"
'''), token=TOKEN)
        status, result, _ = asyncio.run(request(app, 'POST', '/risk', {'signal': 0.91}, TOKEN))
        self.assertEqual(status, 502)
        self.assertEqual(result, {'error': 'worker unavailable'})


if __name__ == '__main__':
    unittest.main()
