//! `ipfs.start`'s `network` member takes effect, through the binary (design
//! 0007, "Modes"): an instance runs under the policy it was started with.
//!
//! - **`direct`** ignores the environment's proxy variables (deviation
//!   `env-proxy`): its router is reached directly, and a proxy the
//!   environment names sees nothing.
//! - **`socks5`** sends everything through the proxy: the proxy sees the
//!   instance's connections, and the router none.
//!
//! Each instance is a private one, with delegated routing to a router on
//! loopback; it is asked for a block nobody has.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};

/// A listener that counts its connections and, when `answer` is set,
/// answers every request on them with an empty provider list (a delegated
/// router); otherwise it drops them (a canary, or a proxy that refuses).
struct Listener {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

impl Listener {
    fn start(answer: bool) -> Listener {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = accepted.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                counted.fetch_add(1, Ordering::SeqCst);
                let Ok(mut stream) = stream else { continue };
                if !answer {
                    continue;
                }
                std::thread::spawn(move || {
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let body = r#"{"Providers":[]}"#;
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                });
            }
        });
        Listener { addr, accepted }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

fn wait_for(timeout: Duration, done: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while !done() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

/// A private instance with delegated routing to `router`, under `network`.
fn instance(id: &str, router: &Listener, network: Value) -> Value {
    let mut params = memory(id);
    params["routing"]["mode"] = json!("delegated");
    params["routing"]["delegated_routers"] = json!([format!("http://{}/routing/v1", router.addr)]);
    params["network"] = network;
    params
}

/// A block nobody has: its lookup goes to the router.
const ABSENT: &str = "/ipfs/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy";

#[test]
fn direct_ignores_the_environments_proxy() {
    let router = Listener::start(true);
    let env_proxy = Listener::start(false);
    let proxy = format!("http://{}", env_proxy.addr);
    let mut ipfsd = Ipfsd::ephemeral(&[
        ("HTTP_PROXY", &proxy),
        ("HTTPS_PROXY", &proxy),
        ("ALL_PROXY", &proxy),
        ("http_proxy", &proxy),
        ("https_proxy", &proxy),
        ("all_proxy", &proxy),
        ("NO_PROXY", ""),
        ("no_proxy", ""),
    ]);
    ipfsd.hello();
    let started = ipfsd.start(instance("e-1", &router, json!({ "mode": "direct" })));
    assert_eq!(started["result"]["instance"], "e-1", "{started}");
    let id = ipfsd.request("ipfs.request", get("e-1", ABSENT));
    let reply = ipfsd.reply(id);
    assert!(reply["result"]["status"].is_number(), "{reply}");
    assert!(router.accepted() > 0, "the router was never asked");
    assert_eq!(env_proxy.accepted(), 0, "the environment's proxy was used");
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}

#[test]
fn socks5_sends_everything_through_the_proxy() {
    let router = Listener::start(true);
    let proxy = Listener::start(false);
    let mut ipfsd = Ipfsd::ephemeral(&[]);
    ipfsd.hello();
    let started = ipfsd.start(instance(
        "e-1",
        &router,
        json!({ "mode": "socks5", "ip": "127.0.0.1", "port": proxy.addr.port() }),
    ));
    assert_eq!(started["result"]["instance"], "e-1", "{started}");
    let id = ipfsd.request("ipfs.request", get("e-1", ABSENT));
    let reply = ipfsd.reply(id);
    // The proxy drops every connection: the lookup fails, upstream's 502
    // or 504.
    let status = reply["result"]["status"].as_u64().unwrap_or(0);
    assert!(matches!(status, 502 | 504), "{reply}");
    assert!(
        wait_for(Duration::from_secs(5), || proxy.accepted() > 0),
        "the proxy was never asked"
    );
    assert_eq!(router.accepted(), 0, "the router was reached directly");
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}
