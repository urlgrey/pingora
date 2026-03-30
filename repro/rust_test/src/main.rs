//! Finding 6 Reproduction: is_upgrade_req() missing Connection: upgrade check
//!
//! Demonstrates that checking only for the Upgrade header (without requiring
//! Connection: upgrade) incorrectly identifies non-upgrade requests as upgrades.

use http::{Request, header};

/// Replicates pingora's is_upgrade_req() logic from common.rs:153
/// This only checks for the Upgrade header, NOT Connection: upgrade
fn is_upgrade_req_pingora(req: &Request<()>) -> bool {
    // This is what pingora does — only checks Upgrade header
    req.headers().get(header::UPGRADE).is_some()
}

/// RFC 9110 §7.8 compliant check: requires BOTH Upgrade AND Connection: upgrade
fn is_upgrade_req_rfc_compliant(req: &Request<()>) -> bool {
    let has_upgrade = req.headers().get(header::UPGRADE).is_some();
    let has_connection_upgrade = req.headers()
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    
    has_upgrade && has_connection_upgrade
}

/// Test: Upgrade header WITHOUT Connection: upgrade
/// Pingora says YES (bug), RFC says NO
#[test]
fn test_upgrade_without_connection_header() {
    let req = Request::builder()
        .uri("/ws")
        .header("Upgrade", "websocket")
        .header("Connection", "close")  // NOT "upgrade"
        .body(())
        .unwrap();
    
    let pingora_result = is_upgrade_req_pingora(&req);
    let rfc_result = is_upgrade_req_rfc_compliant(&req);
    
    println!("Request: Upgrade: websocket, Connection: close");
    println!("  Pingora is_upgrade_req: {}", pingora_result);
    println!("  RFC 9110 compliant:     {}", rfc_result);
    
    assert!(pingora_result, "Pingora incorrectly treats this as an upgrade");
    assert!(!rfc_result, "RFC correctly says this is NOT an upgrade");
    println!("[!!] MISMATCH: Pingora sees upgrade, RFC does not");
}

/// Test: Upgrade header with NO Connection header at all
/// Pingora says YES (bug), RFC says NO
#[test]
fn test_upgrade_without_any_connection_header() {
    let req = Request::builder()
        .uri("/ws")
        .header("Upgrade", "websocket")
        // No Connection header at all
        .body(())
        .unwrap();
    
    let pingora_result = is_upgrade_req_pingora(&req);
    let rfc_result = is_upgrade_req_rfc_compliant(&req);
    
    println!("Request: Upgrade: websocket (no Connection header)");
    println!("  Pingora is_upgrade_req: {}", pingora_result);
    println!("  RFC 9110 compliant:     {}", rfc_result);
    
    assert!(pingora_result, "Pingora incorrectly treats this as an upgrade");
    assert!(!rfc_result, "RFC correctly says this is NOT an upgrade");
    println!("[!!] MISMATCH: Pingora sees upgrade, RFC does not");
}

/// Test: Upgrade header with Connection: keep-alive (not upgrade)
/// Common in real-world requests that include Upgrade speculatively
#[test]
fn test_upgrade_with_keepalive_connection() {
    let req = Request::builder()
        .uri("/api")
        .method("POST")
        .header("Upgrade", "websocket")
        .header("Connection", "keep-alive")
        .header("Content-Length", "10")
        .body(())
        .unwrap();
    
    let pingora_result = is_upgrade_req_pingora(&req);
    let rfc_result = is_upgrade_req_rfc_compliant(&req);
    
    println!("Request: POST /api, Upgrade: websocket, Connection: keep-alive, Content-Length: 10");
    println!("  Pingora is_upgrade_req: {}", pingora_result);
    println!("  RFC 9110 compliant:     {}", rfc_result);
    
    assert!(pingora_result, "Pingora treats POST with Upgrade as upgrade request");
    assert!(!rfc_result, "RFC says this is a normal POST, not an upgrade");
    println!("[!!] CRITICAL: Pingora would switch body to close-delimited mode");
    println!("     but upstream reads Content-Length bytes → body framing mismatch!");
}

/// Control test: Proper upgrade request with Connection: upgrade
/// Both implementations should agree
#[test]
fn test_proper_upgrade_request() {
    let req = Request::builder()
        .uri("/ws")
        .header("Upgrade", "websocket")
        .header("Connection", "upgrade")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("Sec-WebSocket-Version", "13")
        .body(())
        .unwrap();
    
    let pingora_result = is_upgrade_req_pingora(&req);
    let rfc_result = is_upgrade_req_rfc_compliant(&req);
    
    println!("Request: Upgrade: websocket, Connection: upgrade (RFC-compliant)");
    println!("  Pingora is_upgrade_req: {}", pingora_result);
    println!("  RFC 9110 compliant:     {}", rfc_result);
    
    assert!(pingora_result, "Both should agree this IS an upgrade");
    assert!(rfc_result, "Both should agree this IS an upgrade");
    println!("[OK] Both agree: valid upgrade request");
}

/// Control test: Normal request without Upgrade header
/// Both should say NO
#[test]
fn test_normal_request() {
    let req = Request::builder()
        .uri("/api")
        .header("Connection", "keep-alive")
        .body(())
        .unwrap();
    
    let pingora_result = is_upgrade_req_pingora(&req);
    let rfc_result = is_upgrade_req_rfc_compliant(&req);
    
    println!("Request: GET /api, Connection: keep-alive (normal request)");
    println!("  Pingora is_upgrade_req: {}", pingora_result);
    println!("  RFC 9110 compliant:     {}", rfc_result);
    
    assert!(!pingora_result);
    assert!(!rfc_result);
    println!("[OK] Both agree: not an upgrade request");
}

fn main() {
    println!("Run with: cargo test -- --nocapture");
}
