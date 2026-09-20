#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Hello from Unikraft')

    def log_message(self, *args):
        pass

HTTPServer(('0.0.0.0', 3000), H).serve_forever()
