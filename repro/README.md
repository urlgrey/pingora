# Finding 5: Hop-by-Hop Headers Not Stripped in H1→H1 Proxying

## Severity
Medium

## Bug Class
RFC violation — proxy logic error

## Affected Code
- File: `pingora-proxy/src/proxy_h1.rs`
- Lines: 46-62 (`proxy_1to1` function)

## Description
When pingora proxies HTTP/1.1 requests to an HTTP/1.1 upstream (`proxy_1to1`), hop-by-hop headers from the client are forwarded **verbatim** to the upstream server. Per RFC 9110 §7.6.1, a proxy MUST remove hop-by-hop headers before forwarding a message, as these headers are intended only for the immediate connection and not for downstream communication.

The affected headers include `Connection`, `Keep-Alive`, `Proxy-Connection`, `TE`, `Transfer-Encoding`, and `Upgrade`. Additionally, any header nominated in the `Connection` header field (e.g., `Connection: keep-alive, X-Secret-Internal`) should also be stripped.

Header stripping is correctly implemented for H2→H1 conversion paths, but the H1→H1 path (`proxy_1to1`) does not perform this stripping. This means internal headers, connection management directives, and other hop-by-hop metadata leak through to upstream servers.

## Reproduction Steps

1. Start the test backend that logs all received headers:
   ```bash
   python3 repro/repro_hop_by_hop.py --mode backend --backend-port 8081
   ```

2. Configure pingora to proxy to `127.0.0.1:8081`

3. In another terminal, run the test client:
   ```bash
   python3 repro/repro_hop_by_hop.py --mode client --target 127.0.0.1 --port 6188
   ```

4. Or run the all-in-one test (starts backend, sends through proxy, checks results):
   ```bash
   python3 repro/repro_hop_by_hop.py --mode test --proxy-port 6188 --backend-port 8081
   ```

5. Observe the backend logs showing that hop-by-hop headers were received

## Expected vs Actual Behavior
- **Expected:** Hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-Connection`, `TE`, `Upgrade`) and any headers nominated in the `Connection` field should be stripped before forwarding to the upstream.
- **Actual:** All hop-by-hop headers are forwarded verbatim to the upstream server in H1→H1 proxy mode.

## Impact
- **Information leakage:** Internal proxy headers and connection metadata reach upstream servers
- **Connection confusion:** Upstream may misinterpret `Keep-Alive` or `Connection` headers intended for the proxy
- **Header smuggling:** Headers nominated in `Connection` (which should be stripped) reach the upstream, potentially exposing internal routing or authentication headers
- **Proxy-Connection abuse:** Non-standard `Proxy-Connection` header reaches upstream, revealing the presence of a proxy

## References
- [RFC 9110 §7.6.1 — Connection](https://www.rfc-editor.org/rfc/rfc9110#section-7.6.1) — "A proxy MUST remove any connection option fields..."
- [RFC 9110 §7.6.1 — Hop-by-Hop Headers](https://www.rfc-editor.org/rfc/rfc9110#section-7.6.1)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
