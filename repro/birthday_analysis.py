#!/usr/bin/env python3
"""
Birthday attack probability analysis for pingora's u64 GroupKey connection pool.

Computes the probability of at least one hash collision among N upstream
backends in a 64-bit key space.
"""

import math

KEY_SPACE = 2**64

def collision_probability(n: int) -> float:
    """
    Approximate probability of at least one collision among n items
    in a key space of size KEY_SPACE, using the birthday approximation:
    
    P(collision) ≈ 1 - e^(-n*(n-1)/(2*KEY_SPACE))
    """
    if n < 2:
        return 0.0
    exponent = -n * (n - 1) / (2.0 * KEY_SPACE)
    return 1.0 - math.exp(exponent)

def upstreams_for_probability(target_p: float) -> int:
    """
    Number of upstreams needed to reach target collision probability.
    
    From: P ≈ 1 - e^(-n^2/(2*K))
    Solving: n ≈ sqrt(2*K*ln(1/(1-P)))
    """
    return int(math.ceil(math.sqrt(2.0 * KEY_SPACE * math.log(1.0 / (1.0 - target_p)))))

def main():
    print("=" * 70)
    print("Birthday Attack Analysis: pingora u64 GroupKey")
    print(f"Key space: 2^64 = {KEY_SPACE:,}")
    print("=" * 70)
    
    print("\n--- Collision probability for N upstreams ---\n")
    test_counts = [
        1_000,
        10_000,
        100_000,
        1_000_000,
        10_000_000,
        100_000_000,
        1_000_000_000,
        2**32,  # ~4.3 billion
    ]
    
    for n in test_counts:
        p = collision_probability(n)
        print(f"  N = {n:>15,}  →  P(collision) = {p:.6e}  ({p*100:.4f}%)")
    
    print("\n--- Upstreams needed for target collision probability ---\n")
    targets = [0.001, 0.01, 0.1, 0.25, 0.5, 0.75, 0.99]
    for t in targets:
        n = upstreams_for_probability(t)
        print(f"  P = {t*100:5.1f}%  →  N ≈ {n:,}")
    
    print("\n--- Key observations ---\n")
    n50 = upstreams_for_probability(0.5)
    print(f"  • 50% collision probability at ~{n50:,} upstreams")
    print(f"  • That's ~2^{math.log2(n50):.1f} upstreams")
    print(f"  • A large CDN with millions of origins: P ≈ {collision_probability(10_000_000)*100:.6f}%")
    print(f"  • Cloudflare-scale (~30M+ domains): P ≈ {collision_probability(30_000_000)*100:.4f}%")
    print()
    print("  While individual collision probability is low, the impact is high")
    print("  (cross-origin data leak). A 128-bit or 256-bit key would make")
    print("  birthday collisions computationally infeasible.")

if __name__ == "__main__":
    main()
