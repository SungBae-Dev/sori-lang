"""Demonstration Python sidecar using the SORI worker protocol (std.worker).

Replace the scoring logic with a trusted ONNX, PyTorch, or ROS 2 adapter.
This stdlib HTTP server is strictly for demo/development; bind loopback only.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != '/invoke':
            self.send_error(404)
            return
        try:
            size = int(self.headers.get('Content-Length', '-1'))
            if size < 1 or size > 8192:
                self.send_error(413)
                return
            data = json.loads(self.rfile.read(size))
            if set(data) != {'signal'} or type(data['signal']) not in (int, float) or not 0 <= data['signal'] <= 1:
                self.send_error(400)
                return
            # Example only: substitute a real model in the worker process.
            output = json.dumps({'risk': 'high' if data['signal'] >= 0.8 else 'low',
                                 'kind': 'demo_threshold_not_ai'}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(output)))
            self.end_headers()
            self.wfile.write(output)
        except (ValueError, KeyError, TypeError):
            self.send_error(400)


if __name__ == '__main__':
    HTTPServer(('127.0.0.1', int(os.environ.get('SORI_WORKER_PORT', '9010'))), Handler).serve_forever()
