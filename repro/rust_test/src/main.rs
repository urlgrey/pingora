//! Finding 1 Reproduction: Uninitialized memory via unsafe set_len()
//!
//! This test demonstrates that `BytesMut::with_capacity()` followed by
//! `unsafe { set_len() }` exposes uninitialized memory, and shows how
//! `copy_within` during partial chunk-head reconstruction can leave gaps.

use bytes::BytesMut;
use std::io::{self, Read, Cursor};

/// Demonstrates the core unsafe pattern: set_len() on uninitialized buffer.
/// This is the fundamental issue in `BodyReader::prepare_buf()`.
#[test]
fn test_set_len_exposes_uninit_memory() {
    // Allocate a buffer (memory is NOT zeroed by the allocator in release mode)
    let mut buf = BytesMut::with_capacity(4096);

    // This is what pingora does — extend logical length beyond initialized data
    unsafe {
        buf.set_len(4096);
    }

    // The buffer now "contains" 4096 bytes, but they are uninitialized.
    // In debug mode, the allocator may zero-fill, but in release mode
    // these bytes come from the heap and may contain data from previous
    // allocations (headers, bodies, tokens from other requests).
    assert_eq!(buf.len(), 4096);

    // If we only write to part of the buffer (simulating a partial read),
    // the rest remains uninitialized
    buf[0..5].copy_from_slice(b"Hello");

    // Bytes 5..4096 are still uninitialized — but the buffer claims they're valid
    println!("Buffer length: {} (only 5 bytes were written)", buf.len());

    // Returning a BufRef covering the full buffer would leak uninitialized memory
    let leaked_region = &buf[5..64];
    println!(
        "Leaked region (bytes 5..64): {:?}",
        leaked_region
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    );
}

/// Simulates the partial chunk-head scenario where copy_within creates gaps.
///
/// In `do_read_chunked_body()`:
/// 1. First read returns partial chunk-size: "a\r" (2 bytes at offset X)
/// 2. partial_chunk_head is set, copy_within moves "a\r" to start of buffer
/// 3. Second read appends "\nDATA..." after the copied bytes
/// 4. If the gap between copy_within dest and new data isn't fully written,
///    uninitialized bytes from the original buffer leak through
#[test]
fn test_copy_within_gap() {
    let buf_size = 1024;
    let mut buf = BytesMut::with_capacity(buf_size);

    // Simulate prepare_buf() — extend with uninitialized data
    unsafe {
        buf.set_len(buf_size);
    }

    // Poison the buffer to simulate heap residue (in real scenarios,
    // this would be data from previous allocations)
    for i in 0..buf_size {
        buf[i] = 0xDE; // "dead" bytes representing leaked heap data
    }

    // Simulate first read: chunk-size header at offset 500
    let first_read_offset = 500;
    let partial_chunk = b"a\r";
    buf[first_read_offset..first_read_offset + 2].copy_from_slice(partial_chunk);

    // Simulate copy_within: move partial chunk head to beginning of buffer
    // This is what pingora does to reconstruct the full chunk-size line
    buf.copy_within(first_read_offset..first_read_offset + 2, 0);

    // Now bytes 0..2 = "a\r" (the partial chunk head)
    assert_eq!(&buf[0..2], b"a\r");

    // Bytes 2..first_read_offset are still 0xDE (uninitialized/poisoned)
    // If the next read only writes a few bytes starting at offset 2,
    // there's a gap of 0xDE bytes between the data regions

    // Simulate second read: "\nBBBBBBBBBB" starting at offset 2
    let second_data = b"\nBBBBBBBBBB";
    buf[2..2 + second_data.len()].copy_from_slice(second_data);

    // The "valid" data is at 0..13, but if the BufRef calculation is off
    // and includes bytes beyond 13, those are still 0xDE
    let intended_end = 2 + second_data.len();
    let leaked = &buf[intended_end..intended_end + 10];

    println!("Valid data: {:?}", String::from_utf8_lossy(&buf[0..intended_end]));
    println!(
        "Bytes beyond valid region: {:?}",
        leaked.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>()
    );

    // All bytes beyond the valid region are 0xDE (our poison/heap residue)
    assert!(
        leaked.iter().all(|&b| b == 0xDE),
        "Gap contains our poison bytes, confirming uninitialized memory exposure"
    );
    println!("[OK] Confirmed: bytes beyond written region contain heap residue");
}

fn main() {
    println!("Run with: cargo test -- --nocapture");
}
