// Minimal pingora proxy that forwards requests to a simple echo backend.
// The echo backend returns the request body in the response, allowing us
// to detect if uninitialized memory was included.
//
// Build: cargo build --example echo_proxy
// Run:   RUST_LOG=debug cargo run --example echo_proxy
// Test:  python3 repro/repro_chunked_split.py --target 127.0.0.1 --port 6190

use async_trait::async_trait;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_proxy::{ProxyHttp, Session};

pub struct EchoProxy;

#[async_trait]
impl ProxyHttp for EchoProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self, _session: &mut Session, _ctx: &mut (),
    ) -> Result<Box<HttpPeer>> {
        // Forward to our simple echo backend on port 6191
        let peer = Box::new(HttpPeer::new("127.0.0.1:6191", false, String::new()));
        Ok(peer)
    }
}

fn main() {
    env_logger::init();
    let opt = Opt::parse_args();
    let mut server = Server::new(Some(opt)).unwrap();
    server.bootstrap();

    let mut proxy = pingora_proxy::http_proxy_service(&server.configuration, EchoProxy);
    proxy.add_tcp("0.0.0.0:6190");

    server.add_service(proxy);
    server.run_forever();
}
