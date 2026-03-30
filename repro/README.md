# Finding 6: Missing `Connection: Upgrade` Check in `is_upgrade_req()`

## Severity
Medium

## Bug Class
Protocol confusion — incomplete RFC compliance

## Affected Code
- File: `pingora-core/src/protocols/http/v1/common.rs`
- Lines: 153 (`is_upgrade_req()` function)

## Description
The `is_upgrade_req()` function only checks for the presence of an `Upgrade` header, without verifying that the `Connection` header also contains `upgrade` as required by RFC 9110 §7.8. Per the RFC, a client MUST send `Connection: upgrade` alongside the `Upgrade` header for the upgrade mechanism to be valid — the `Upgrade` header alone is insufficient.

Because pingora treats any request with an `Upgrade` header as an upgrade request (regardless of the `Connection` header), several downstream behaviors are affected:
- **Body handling** switches to close-delimited mode instead of Content-Length or chunked
- **Connection reuse** is disabled (keepalive turned off)
- **Upstream routing** may change if upgrade-specific backends are configured

The test at `server.rs:757` explicitly documents this behavior with the comment "matches nginx", but this diverges from the RFC specification and creates a protocol confusion vector.

## Reproduction Steps

### Rust Unit Test
1. Build and run the test:
   ```bash
   cd repro/rust_test
   cargo test -- --nocapture
   ```
2. The test creates HTTP requests with `Upgrade: websocket` but no `Connection: upgrade` header and verifies that `is_upgrade_req()` incorrectly returns `true`

### Python Script (Protocol Confusion PoC)
1. Start a pingora proxy instance
2. Run the confusion script:
   ```bash
   python3 repro/repro_upgrade_confusion.py --target 127.0.0.1 --port 6188
   ```
3. The script sends a POST request with `Upgrade: websocket`, `Content-Length`, and a body — demonstrating that the proxy may misinterpret body framing

## Expected vs Actual Behavior
- **Expected:** `is_upgrade_req()` should return `true` ONLY when both `Upgrade: <protocol>` AND `Connection: upgrade` headers are present, per RFC 9110 §7.8.
- **Actual:** `is_upgrade_req()` returns `true` whenever an `Upgrade` header is present, regardless of the `Connection` header. This causes the proxy to enter upgrade mode for requests that the upstream (following the RFC) would treat as normal HTTP requests.

## Impact
- **Request smuggling:** The proxy and upstream disagree on body framing — the proxy treats the request as an upgrade (close-delimited body) while the upstream treats it as a normal POST with Content-Length
- **Body theft:** Data after the Content-Length boundary may be interpreted differently by proxy vs upstream
- **Connection state confusion:** The proxy disables keepalive for what the upstream considers a normal request
- **DoS via upgrade confusion:** Forcing the proxy into upgrade mode unnecessarily can waste resources and connections

## References
- [RFC 9110 §7.8 — Upgrade](https://www.rfc-editor.org/rfc/rfc9110#section-7.8) — "A client that sends `Upgrade` MUST also send a `Connection` header field that contains an `upgrade` connection option"
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)
