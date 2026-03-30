# Finding 8: Invalid Content-Length Response Confusion

## Severity
Medium

## Bug Class
Response splitting — close-delimited fallback on invalid Content-Length

## Affected Code
- File: `pingora-core/src/protocols/http/v1/client.rs`
- Lines: 428-432 (Content-Length parsing), 180 (body reader selection)

## Description
When the `allow_h1_response_invalid_content_length` option is enabled and an upstream server sends a response with a non-numeric `Content-Length` header (e.g., `Content-Length: abc`), the Content-Length parsing fails silently and the body reader falls through to **close-delimited mode**. In close-delimited mode, the proxy reads the entire response until the TCP connection is closed.

On a **pooled (keep-alive) connection**, this creates a dangerous situation: the proxy expects to read until connection close, but the upstream may send a properly framed response followed by more data (the next response on the pooled connection). The proxy then reads data from the next response as if it were part of the current response body, causing:

1. **Response data leakage** — the current client receives data intended for a different request
2. **Connection desynchronization** — the proxy and upstream disagree on message boundaries
3. **Response splitting** — an attacker controlling the upstream can inject arbitrary responses

The `allow_h1_response_invalid_content_length` option exists for compatibility with broken upstreams, but its use creates a significant security risk when combined with connection pooling.

## Reproduction Steps

### Python Script (Mock Upstream PoC)
1. Start the mock upstream server that sends invalid Content-Length:
   ```bash
   python3 repro/repro_invalid_cl.py --mode upstream --port 8081
   ```

2. Configure pingora with:
   - `allow_h1_response_invalid_content_length: true`
   - Upstream pointing to `127.0.0.1:8081`

3. Send requests through the proxy:
   ```bash
   python3 repro/repro_invalid_cl.py --mode client --proxy-port 6188
   ```

4. Observe that the proxy reads beyond the intended response boundary

### Rust Test
1. Build and run the test:
   ```bash
   cd repro/rust_test
   cargo test -- --nocapture
   ```
2. The test demonstrates the Content-Length parsing fallback behavior

## Expected vs Actual Behavior
- **Expected:** When Content-Length is invalid (non-numeric), the response should be rejected with an error, or at minimum the connection should NOT be returned to the pool after the response is read.
- **Actual:** The invalid Content-Length causes a silent fallback to close-delimited mode. If the upstream connection is keep-alive, the proxy reads data from subsequent responses as part of the current response body.

## Impact
An attacker who controls or can influence an upstream server can:
- **Leak responses** intended for other clients by exploiting the close-delimited fallback on pooled connections
- **Inject arbitrary response content** by manipulating the boundary between responses
- **Desynchronize the connection pool** causing widespread response corruption
- **Cache poison** if the leaked/injected content is cached by downstream CDN layers

## References
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)
- [RFC 9112 §6.3 — Message Body Length](https://www.rfc-editor.org/rfc/rfc9112#section-6.3) — Content-Length must be a valid integer
- [HTTP Desync Attacks (PortSwigger)](https://portswigger.net/research/http-desync-attacks)
