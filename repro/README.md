# Finding 1: Uninitialized Memory Exposure in Body Buffer

## Severity
High

## Bug Class
Memory safety — use of uninitialized memory

## Affected Code
- File: `pingora-core/src/protocols/http/v1/body.rs`
- Lines: 183 (`prepare_buf()` → `unsafe { body_buf.set_len(self.body_buf_size) }`)

## Description
In `BodyReader::prepare_buf()`, a body buffer is allocated with `BytesMut::with_capacity()` and immediately extended via `unsafe { body_buf.set_len(self.body_buf_size) }`. This sets the logical length of the buffer beyond initialized data, creating a region of uninitialized heap memory that the buffer now claims is valid.

The buffer is used as the target for `stream.read()`, which normally writes data before it's returned. However, in `do_read_chunked_body()`, when a chunk-size header is split across multiple TCP reads, the `partial_chunk_head` + `copy_within` logic can leave gaps of uninitialized memory between the copied data and new data.

Specifically, if `read()` returns fewer bytes than the gap between the `copy_within` source and destination positions, uninitialized heap memory is included in the returned `BufRef`. This can leak sensitive data from previous allocations (other requests' headers, bodies, authentication tokens, etc.) to the client.

## Reproduction Steps

### Python Script (Network-level PoC)
1. Start a pingora instance configured as a reverse proxy
2. Run `repro_chunked_split.py` which sends a chunked HTTP request with the chunk-size line split across TCP segments:
   ```bash
   python3 repro/repro_chunked_split.py --target 127.0.0.1 --port 6188
   ```
3. The script uses raw sockets with `TCP_NODELAY` and deliberate delays between segments to force partial reads in the body parser

### Rust Test (Unit-level PoC)
1. Build and run the Rust test:
   ```bash
   cd repro/rust_test
   cargo test -- --nocapture
   ```
2. The test constructs a mock `AsyncRead` that returns partial data simulating the split chunk-size scenario

## Expected vs Actual Behavior
- **Expected:** All bytes returned in the response body should be data that was actually received from the client/upstream. The buffer should be zero-initialized or only expose written bytes.
- **Actual:** Uninitialized heap memory (from previous allocations) can leak into the body buffer when chunk-size headers are split across TCP reads, potentially exposing sensitive data from other connections.

## Impact
An attacker can extract sensitive data from the proxy's heap memory, including:
- Authentication tokens and cookies from other clients' requests
- Request/response bodies from other connections
- Internal headers and routing information

This is similar to Heartbleed (CVE-2014-0160) in that it leaks server memory contents to a remote attacker, though the trigger condition is more specific.

## References
- [CWE-908: Use of Uninitialized Resource](https://cwe.mitre.org/data/definitions/908.html)
- [Heartbleed (CVE-2014-0160)](https://heartbleed.com/) — similar class of uninitialized memory leak
- [Rust `set_len()` safety requirements](https://doc.rust-lang.org/std/vec/struct.Vec.html#safety-1)
