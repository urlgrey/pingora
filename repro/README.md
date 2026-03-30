# Finding 10: No Keepalive Request Limit (Header Amplification DoS)

## Severity
Medium

## Bug Class
Denial of Service — unbounded resource consumption per connection

## Affected Code
- File: `pingora-core/src/protocols/http/v1/server.rs`
- Lines: 118 (keepalive loop — no request count limit)
- File: `pingora-core/src/protocols/http/v1/common.rs`
- Lines: 22 (MAX_HEADERS = 256, MAX_HEADER_SIZE ~1MB)

## Description
While individual HTTP/1.1 requests are limited to 256 headers and approximately 1MB total header size (`MAX_HEADERS_BUF_SIZE`), there is no limit on the **number of requests** a single keep-alive TCP connection can send. Each request forces the allocation of up to 1MB of header buffer space.

A single TCP connection can therefore force repeated allocation and processing of maximum-size header buffers. Combined with slow sending (Slowloris-style), the default 60-second read timeout, and the fact that header buffers may not be immediately freed, a small number of TCP connections can consume significant server memory.

The attack is particularly effective because:
1. Each request can contain 256 headers at maximum size (~4KB each)
2. The keepalive connection persists indefinitely with no request count limit
3. Slow sending (1 byte at a time with delays) keeps the connection alive while maximizing memory holding time
4. No per-connection memory accounting or backpressure exists

## Reproduction Steps

1. Start a pingora proxy instance with default configuration
2. Run the DoS simulation:
   ```bash
   # Basic test: single connection, many large-header requests
   python3 repro/repro_keepalive_dos.py --target 127.0.0.1 --port 6188

   # Stress test: multiple connections with memory measurement
   python3 repro/repro_keepalive_dos.py --target 127.0.0.1 --port 6188 --stress --connections 10 --requests 100
   ```
3. Monitor pingora's memory usage (e.g., `ps aux | grep pingora` or `/proc/<pid>/status`)

## Expected vs Actual Behavior
- **Expected:** The server should limit the number of requests per keep-alive connection (e.g., Apache's `MaxKeepAliveRequests`, nginx's `keepalive_requests`) and/or impose per-connection memory limits.
- **Actual:** A single keep-alive connection can send unlimited requests, each forcing allocation of up to ~1MB of header buffer, with no per-connection memory accounting or request count limit.

## Impact
An attacker can:
- **Exhaust server memory** with a small number of TCP connections, each sending endless large-header requests
- **Slowloris variant:** By sending headers slowly (within the 60s timeout), maximize the time each allocation is held, amplifying memory pressure
- **Bypass connection limits:** Since a single connection can do unlimited work, connection-count rate limiting is ineffective
- **Asymmetric attack:** The attacker uses minimal bandwidth (slow sends) while the server allocates megabytes per request

## References
- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- [Slowloris attack](https://en.wikipedia.org/wiki/Slowloris_(computer_security))
- [nginx keepalive_requests directive](https://nginx.org/en/docs/http/ngx_http_core_module.html#keepalive_requests) — limits requests per connection (default: 1000)
- [Apache MaxKeepAliveRequests](https://httpd.apache.org/docs/current/mod/core.html#maxkeepaliverequests) — limits requests per connection (default: 100)
