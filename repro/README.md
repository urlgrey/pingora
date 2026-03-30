# Finding 1: Uninitialized Memory Exposure in Body Buffer

## Severity
High

## Bug Class
Memory safety — use of uninitialized memory

## Affected Code
- File: `pingora-core/src/protocols/http/v1/body.rs`
- Lines: 183-184 (`prepare_buf()` → `unsafe { body_buf.set_len(self.body_buf_size) }`)

## Description

In `BodyReader::prepare_buf()`, a body buffer is allocated with `BytesMut::with_capacity()` and immediately extended via:

```rust
// body.rs:182-185
if self.body_buf_size > buf_to_rewind.len() {
    //body_buf.resize(self.body_buf_size, 0);  // <-- SAFE version (commented out!)
    unsafe {
        body_buf.set_len(self.body_buf_size);   // <-- UNSAFE: exposes uninitialized memory
    }
}
```

Note the commented-out safe alternative (`resize` zero-fills) directly above the unsafe `set_len`. The `set_len` call extends the buffer's logical length without initializing the memory, meaning the region between `buf_to_rewind.len()` and `body_buf_size` contains whatever was previously on the heap.

When the chunked body parser encounters a chunk-size line split across TCP segments, the `partial_chunk_head` + `copy_within` reconstruction logic can leave gaps of uninitialized memory in the returned body data. This can leak sensitive heap data (other requests' headers, bodies, auth tokens) to clients.

## Client-Triggerable?
**YES** — A client controls TCP segmentation via `TCP_NODELAY` + small `send()` calls with delays. The client can reliably force the chunk-size line to split across reads.

## Reproduction Steps

### Prerequisites
- Rust toolchain (`rustup`)
- Python 3.6+
- Three terminal windows

### Step 1: Start the echo backend
This simple Python server receives forwarded requests and echoes the body back, letting us inspect what pingora forwarded.

```bash
cd /tmp/pingora
python3 repro/echo_backend.py
```

You should see:
```
[echo] Echo backend listening on 127.0.0.1:6191
```

### Step 2: Build and start pingora proxy
In a second terminal:

```bash
cd /tmp/pingora

# Build (first time takes a few minutes)
cargo build --example load_balancer

# We need to modify the upstream to point to our echo backend.
# Instead, use the minimal echo_proxy example:
# First, copy echo_proxy.rs to the examples dir:
cp repro/echo_proxy.rs pingora-proxy/examples/echo_proxy.rs

# Build the echo proxy
cargo build --example echo_proxy

# Run it (listens on port 6190, forwards to echo backend on 6191)
RUST_LOG=debug ./target/debug/examples/echo_proxy
```

Alternatively, if you don't want to build, you can use any HTTP reverse proxy that forwards to `127.0.0.1:6191`. The bug is in pingora's body parser, so you need pingora specifically.

### Step 3: Run the PoC
In a third terminal:

```bash
cd /tmp/pingora

# Single request with detailed analysis
python3 repro/repro_chunked_split.py --target 127.0.0.1 --port 6190

# Stress test (50 iterations with varied timing)
python3 repro/repro_chunked_split.py --target 127.0.0.1 --port 6190 --stress

# More iterations for higher confidence
python3 repro/repro_chunked_split.py --target 127.0.0.1 --port 6190 --stress --iterations 200
```

### What to look for

The PoC sends requests with known body content (`Hello` + `B`×10 + `C`×16 = 31 bytes). If the response body contains:
- **Extra bytes** beyond the expected 31
- **Null bytes** (`\x00`) — common in uninitialized memory
- **Unexpected byte values** not in the set `{H, e, l, o, B, C}`
- **Different body length** than expected

...then uninitialized heap memory has been leaked.

## Expected vs Actual Behavior

- **Expected:** `prepare_buf()` should use `body_buf.resize(self.body_buf_size, 0)` (the commented-out line) to zero-fill the buffer, ensuring no uninitialized memory can leak.
- **Actual:** `unsafe { body_buf.set_len(self.body_buf_size) }` extends the buffer without initialization. When partial chunk reads trigger `copy_within`, gaps of uninitialized heap memory can be included in the body data returned to the application.

## Impact

- **Information disclosure:** Heap data from other requests (headers, bodies, cookies, auth tokens) can leak to clients
- **Cross-request data leak:** On a shared proxy, one user's data can appear in another user's response
- **Reliable trigger:** The attacker controls TCP segmentation, making the timing-dependent path reliably reachable

## Fix

Replace line 184:
```rust
// Before (UNSAFE):
unsafe { body_buf.set_len(self.body_buf_size); }

// After (SAFE):
body_buf.resize(self.body_buf_size, 0);
```

The safe version is already in the code as a comment on line 182. The performance cost of zero-filling is negligible compared to the security risk.

## References
- `pingora-core/src/protocols/http/v1/body.rs:182-185`
- [Rust docs: `set_len` safety](https://doc.rust-lang.org/std/vec/struct.Vec.html#method.set_len) — "The elements at `old_len..new_len` must be initialized"
- [CWE-908: Use of Uninitialized Resource](https://cwe.mitre.org/data/definitions/908.html)
