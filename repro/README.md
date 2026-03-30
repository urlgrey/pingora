# Finding 4: Header Validation Bypass via `from_maybe_shared_unchecked`

## Severity
Medium

## Bug Class
Header injection — input validation bypass

## Affected Code
- File: `pingora-core/src/protocols/http/v1/server.rs`
- Lines: 255 (`HeaderValue::from_maybe_shared_unchecked()`)
- File: `pingora-core/src/protocols/http/v1/client.rs`
- Lines: 346 (`HeaderValue::from_maybe_shared_unchecked()`)

## Description
Both the HTTP/1.1 request parser (server.rs) and response parser (client.rs) use `http::HeaderValue::from_maybe_shared_unchecked()` to construct header values from parsed bytes. This function bypasses the `http` crate's validation, which normally rejects header values containing bytes outside the visible-ASCII + SP + HTAB range.

Combined with the `patched_http1` feature flag (which uses `httparse`'s unchecked parsing via `req.parse_unchecked(buf)`), headers containing arbitrary binary content — including null bytes (`\x00`), carriage returns (`\r`), and line feeds (`\n`) — pass through without rejection.

If these headers are forwarded to an upstream server that interprets bare `\n` as a header delimiter (which some HTTP implementations do), an attacker can inject arbitrary headers into the proxied request. This enables cache poisoning, request smuggling, and authentication bypass attacks.

## Reproduction Steps

### Python Script (Network-level PoC)
1. Start a pingora instance with `patched_http1` feature enabled
2. Run the injection script:
   ```bash
   python3 repro/repro_header_injection.py --target 127.0.0.1 --port 6188
   ```
3. The script sends requests with null bytes and CRLF sequences embedded in header values
4. Observe that the proxy forwards them to the upstream without rejection

### Rust Unit Test
1. Build and run the test:
   ```bash
   cd repro/rust_test
   cargo test -- --nocapture
   ```
2. The test demonstrates that `from_maybe_shared_unchecked` accepts bytes that `from_maybe_shared` (the safe version) would reject

## Expected vs Actual Behavior
- **Expected:** Header values containing control characters (null bytes, CR, LF) should be rejected by the parser, or at minimum sanitized before forwarding to upstream servers.
- **Actual:** `from_maybe_shared_unchecked` accepts any byte sequence, allowing arbitrary binary content in header values that gets forwarded verbatim to upstream servers.

## Impact
An attacker can:
- **Inject arbitrary headers** into proxied requests by embedding `\r\n` sequences in header values
- **Poison HTTP caches** by injecting headers that alter cache keys
- **Smuggle requests** if the upstream interprets injected headers as request boundaries
- **Bypass authentication** by injecting authorization headers

## References
- [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html)
- [RFC 9110 §5.5 — Field Values](https://www.rfc-editor.org/rfc/rfc9110#section-5.5) — defines valid field-value characters
- [`http` crate HeaderValue validation](https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.from_bytes)
