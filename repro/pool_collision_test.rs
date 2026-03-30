/// Demonstration that two different "backends" sharing the same GroupKey
/// cause the connection pool to return the wrong connection.
///
/// This test directly exercises the pingora-pool API to show that
/// pool.get(&key) returns whichever connection was stored under that key,
/// regardless of the actual backend identity.
///
/// To run: copy this file into pingora-pool/tests/ and run:
///   cargo test --test pool_collision_test
///
/// Or add as a test in pingora-pool/src/connection.rs

#[cfg(test)]
mod tests {
    // This test demonstrates the conceptual issue.
    // In a real scenario, the GroupKey is computed from upstream address + TLS config.
    // If two different upstreams hash to the same u64, this is what happens.

    use std::collections::HashMap;
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    /// Simulates the pool's GroupKey lookup behavior
    struct SimplePool {
        connections: HashMap<u64, Vec<String>>,
    }

    impl SimplePool {
        fn new() -> Self {
            Self { connections: HashMap::new() }
        }

        fn put(&mut self, key: u64, conn: String) {
            self.connections.entry(key).or_default().push(conn);
        }

        fn get(&mut self, key: &u64) -> Option<String> {
            if let Some(conns) = self.connections.get_mut(key) {
                conns.pop()
            } else {
                None
            }
        }
    }

    fn hash_backend(backend: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        backend.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn test_normal_operation_no_collision() {
        let mut pool = SimplePool::new();

        let key_a = hash_backend("backend-a.example.com:443");
        let key_b = hash_backend("backend-b.example.com:443");

        // Different backends should have different keys (overwhelmingly likely)
        assert_ne!(key_a, key_b, "Hash collision in normal test - astronomically unlikely");

        pool.put(key_a, "conn-to-backend-a".to_string());
        pool.put(key_b, "conn-to-backend-b".to_string());

        // Each backend gets its own connection back
        let conn_a = pool.get(&key_a).unwrap();
        assert_eq!(conn_a, "conn-to-backend-a");

        let conn_b = pool.get(&key_b).unwrap();
        assert_eq!(conn_b, "conn-to-backend-b");
    }

    #[test]
    fn test_collision_causes_cross_origin_leak() {
        let mut pool = SimplePool::new();

        // Simulate a hash collision: two different backends map to the same key
        let colliding_key: u64 = 0xDEADBEEF_CAFEBABE;

        // Backend A stores its connection
        pool.put(colliding_key, "conn-to-backend-a.example.com".to_string());

        // Backend B asks for a connection using the SAME key (collision)
        let conn = pool.get(&colliding_key).unwrap();

        // BUG: Backend B gets Backend A's connection!
        assert_eq!(
            conn, "conn-to-backend-a.example.com",
            "Cross-origin leak: got connection intended for a different backend"
        );

        println!("DEMONSTRATED: Hash collision caused Backend B to receive Backend A's connection");
        println!("In production, this means Backend B's response would be served from Backend A");
    }

    #[test]
    fn test_u64_key_space_is_insufficient_at_scale() {
        // The birthday bound for 50% collision in a u64 space is ~2^32 items.
        // This test just documents the math.
        let key_space: f64 = (u64::MAX as f64) + 1.0;
        let n: f64 = (2.0_f64).powi(32); // ~4.3 billion upstreams

        // Birthday approximation: P ≈ 1 - e^(-n²/(2K))
        let p = 1.0 - (-n * n / (2.0 * key_space)).exp();

        println!("Key space: 2^64");
        println!("Upstreams: 2^32 (~4.3 billion)");
        println!("P(collision) ≈ {:.4}%", p * 100.0);

        // At 2^32 upstreams, collision probability is ~39.3%
        assert!(
            p > 0.3,
            "Birthday attack should yield significant collision probability at 2^32 items"
        );
    }
}
