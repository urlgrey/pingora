# Finding 12: Connection Pool GroupKey Hash Collision

## Severity
Low

## Bug Class
Connection pooling / Cross-origin data leak

## Affected Code
- File: `pingora-pool/src/connection.rs`
- Lines: 27-28

## Description

The pingora connection pool uses a `u64` value as its `GroupKey` type:

```rust
type GroupKey = u64;
```

Connections are stored and retrieved by this key. The `get()` method returns **any** idle connection matching the key:

```rust
pub fn get(&self, key: &GroupKey) -> Option<S> {
    // ...
    if let Some((id, connection)) = pool_node.get_any() {
```

If two different upstream backends (e.g., `backend-a.example.com:443` and `backend-b.example.com:443`) produce the same `GroupKey` via the hash function used upstream, a request intended for backend A could be sent over a pooled connection to backend B. The response from the wrong backend would be served to the client.

The 64-bit key space makes deliberate collisions difficult, but birthday-attack collisions become feasible at scale. With ~2^32 distinct upstream destinations (plausible for a multi-tenant CDN), there's a ~50% probability of at least one collision pair. The actual risk depends on how the `GroupKey` is computed from the upstream address and TLS configuration — the pool crate itself is agnostic to this.

In a multi-tenant CDN scenario where different customers share the same proxy infrastructure, a collision could cause one customer's response to be served to another customer's users — a cross-origin data leak.

## Reproduction Steps

### Birthday Attack Probability Analysis

1. Run the included Python script to compute collision probabilities:
   ```bash
   python3 repro/birthday_analysis.py
   ```

2. The script computes:
   - P(collision) for N upstreams in a 64-bit key space
   - The number of upstreams needed for 1%, 10%, 50% collision probability

### Rust Test: Demonstrating Pool Behavior on Collision

1. The included Rust test shows that if two different "backends" happen to produce the same `GroupKey`, the pool returns the wrong connection:

   ```bash
   cd pingora-pool
   cargo test --test pool_collision_test
   ```

   Or copy `repro/pool_collision_test.rs` into `pingora-pool/tests/`.

## Expected vs Actual Behavior

- **Expected:** Each upstream backend has a unique pool key. Connections are never reused across different backends.
- **Actual:** The `u64` key space permits hash collisions. If two backends produce the same key, their connections are interchangeable in the pool, causing cross-origin response delivery.

## Impact

- **Multi-tenant CDN:** Customer A's response served to Customer B's users
- **Internal microservices:** Response from service A delivered as if it came from service B
- **TLS context mismatch:** If TLS session info is not part of the key, a plaintext connection could be reused where TLS is expected (or vice versa)

The practical exploitability depends on the hash function quality and whether an attacker can control or enumerate upstream destinations to find collisions.

## References

- [Birthday attack](https://en.wikipedia.org/wiki/Birthday_attack) — collision probability in finite key spaces
- `pingora-pool/src/connection.rs` — pool implementation
- `pingora-core/src/connectors/` — upstream connector that generates GroupKey values
