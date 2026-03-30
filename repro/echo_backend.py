#!/usr/bin/env python3
"""
Simple HTTP echo backend for Finding 1 PoC.

Reads the request body and returns it in the response body.
This lets us detect whether pingora leaked uninitialized memory
in the body it forwarded.

Usage: python3 repro/echo_backend.py
Listens on: 127.0.0.1:6191
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import sys


class EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = self.headers.get('Content-Length')
        transfer_encoding = self.headers.get('Transfer-Encoding', '')

        body = b""
        if 'chunked' in transfer_encoding.lower():
            # Read chunked body
            while True:
                line = self.rfile.readline().strip()
                chunk_size = int(line, 16)
                if chunk_size == 0:
                    self.rfile.readline()  # trailing \r\n
                    break
                body += self.rfile.read(chunk_size)
                self.rfile.readline()  # trailing \r\n after chunk
        elif content_length:
            body = self.rfile.read(int(content_length))

        print(f"[echo] Received {len(body)} bytes: {body[:64]}...", file=sys.stderr)
        print(f"[echo] Hex: {body.hex()[:128]}...", file=sys.stderr)

        # Echo back the body with hex dump
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, format, *args):
        print(f"[echo] {args[0]}", file=sys.stderr)


if __name__ == '__main__':
    port = 6191
    server = HTTPServer(('127.0.0.1', port), EchoHandler)
    print(f"[echo] Echo backend listening on 127.0.0.1:{port}", file=sys.stderr)
    server.serve_forever()
