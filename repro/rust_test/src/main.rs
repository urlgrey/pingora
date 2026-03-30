//! Finding 8 Reproduction: Invalid Content-Length causes close-delimited fallback
//!
//! Demonstrates the body reader selection logic when Content-Length is invalid
//! and `allow_h1_response_invalid_content_length` is enabled.

/// Simulates pingora's Content-Length parsing logic from client.rs:428-432
/// When the option is enabled, invalid Content-Length doesn't cause an error;
/// instead, the body reader falls through to close-delimited mode.
fn parse_content_length(value: &str, allow_invalid: bool) -> ContentLengthResult {
    match value.parse::<u64>() {
        Ok(len) => ContentLengthResult::Valid(len),
        Err(_) => {
            if allow_invalid {
                // This is the dangerous path: silently ignore invalid CL
                // and fall through to close-delimited mode
                ContentLengthResult::InvalidAllowed
            } else {
                ContentLengthResult::InvalidRejected
            }
        }
    }
}

#[derive(Debug, PartialEq)]
enum ContentLengthResult {
    Valid(u64),
    InvalidAllowed,   // Falls through to close-delimited
    InvalidRejected,  // Returns error
}

#[derive(Debug, PartialEq)]
enum BodyReaderMode {
    ContentLength(u64),
    CloseDelimited,  // Reads until connection close — dangerous on pooled connections
    Chunked,
    NoBody,
    Error,
}

/// Simulates body reader selection with the invalid CL option
fn select_body_reader(
    content_length: Option<&str>,
    transfer_encoding: Option<&str>,
    allow_invalid_cl: bool,
) -> BodyReaderMode {
    // Check Transfer-Encoding first
    if let Some(te) = transfer_encoding {
        if te.eq_ignore_ascii_case("chunked") {
            return BodyReaderMode::Chunked;
        }
    }

    // Check Content-Length
    if let Some(cl) = content_length {
        match parse_content_length(cl, allow_invalid_cl) {
            ContentLengthResult::Valid(len) => return BodyReaderMode::ContentLength(len),
            ContentLengthResult::InvalidRejected => return BodyReaderMode::Error,
            ContentLengthResult::InvalidAllowed => {
                // FALL THROUGH to close-delimited — this is the bug
                // On a pooled connection, we'll read the NEXT response as body
            }
        }
    }

    // Default: close-delimited
    BodyReaderMode::CloseDelimited
}

#[test]
fn test_valid_content_length() {
    let mode = select_body_reader(Some("1234"), None, false);
    assert_eq!(mode, BodyReaderMode::ContentLength(1234));
    println!("[OK] Valid Content-Length: 1234 → ContentLength(1234)");
}

#[test]
fn test_invalid_cl_rejected_by_default() {
    let mode = select_body_reader(Some("abc"), None, false);
    assert_eq!(mode, BodyReaderMode::Error);
    println!("[OK] Invalid CL 'abc' rejected when option disabled → Error");
}

#[test]
fn test_invalid_cl_allowed_falls_to_close_delimited() {
    // THIS IS THE VULNERABILITY:
    // When allow_h1_response_invalid_content_length is true,
    // invalid CL silently falls through to close-delimited mode
    let mode = select_body_reader(Some("abc"), None, true);
    assert_eq!(mode, BodyReaderMode::CloseDelimited);
    println!("[!!] Invalid CL 'abc' with allow_invalid=true → CloseDelimited!");
    println!("     On pooled connections, this reads across response boundaries!");
}

#[test]
fn test_various_invalid_cl_values() {
    let invalid_values = vec![
        "abc",
        "",
        "-1",
        "12abc",
        "12 34",
        "12,34",
        "99999999999999999999",
        "Content-Length",
        "\x00",
    ];

    println!("\nInvalid Content-Length values with allow_invalid=true:");
    for value in invalid_values {
        let mode = select_body_reader(Some(value), None, true);
        println!(
            "  Content-Length: {:30} → {:?}",
            format!("{:?}", value),
            mode
        );
        assert_eq!(
            mode,
            BodyReaderMode::CloseDelimited,
            "All invalid CL values should fall through to CloseDelimited"
        );
    }
    println!("[!!] All invalid values silently fall through to close-delimited mode!");
}

#[test]
fn test_pooled_connection_scenario() {
    println!("\n=== Pooled Connection Attack Scenario ===");
    println!();
    println!("Timeline on a single pooled TCP connection:");
    println!();
    
    // Request 1 (attacker's request)
    println!("1. Attacker's request → proxy reads response");
    let mode = select_body_reader(Some("abc"), None, true);
    println!("   Content-Length: abc → body mode: {:?}", mode);
    println!("   Proxy will read until connection CLOSE");
    println!();
    
    // But the connection is keep-alive, so...
    println!("2. Connection is keep-alive — upstream sends next response");
    println!("   Victim's response: HTTP/1.1 200 OK\\r\\nContent-Length: 42\\r\\n...");
    println!();
    
    println!("3. Proxy (still in close-delimited mode) reads victim's response");
    println!("   as continuation of attacker's body!");
    println!();
    println!("4. Attacker receives: [own response body] + [victim's full HTTP response]");
    println!("   Including victim's headers, cookies, tokens, and body data!");
    println!();
    println!("[!!] Cross-client response data leaked via pooled connection confusion!");
}

fn main() {
    println!("Run with: cargo test -- --nocapture");
}
