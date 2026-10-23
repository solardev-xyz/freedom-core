//! Ant's gateway, built as antd builds it, over the memory node loop.

use crate::node::{self, Unhandled};
use crate::store::MemFetcher;
use ant_control::{
    GatewayActivity, IdentityInfo, PROTOCOL_VERSION, PeerConnectionInfo, PeerInfo, RetrievalInfo,
    RoutingInfo, StatusSnapshot,
};
use ant_gateway::testkit::{GatewayHandle, build_router};
use ant_gateway::{CorsConfig, GatewayChainState, GatewayIdentity, TagRegistry};
use axum::Router;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use std::sync::Arc;
use tokio::sync::watch;
use tower::ServiceExt;

/// One answer, whole.
pub struct Answer {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// The gateway over one chunk set.
pub struct Ant {
    router: Router,
    unhandled: Arc<Unhandled>,
    // Kept so the status channel stays open for the router's life.
    _status: watch::Sender<StatusSnapshot>,
}

impl Ant {
    pub fn new(fetcher: Arc<MemFetcher>) -> Self {
        let (status_tx, status_rx) = watch::channel(status_snapshot());
        let unhandled = Arc::new(Unhandled::default());
        let commands = node::spawn(fetcher, unhandled.clone());
        let handle = GatewayHandle {
            agent: Arc::new("antd/0.5.71".to_string()),
            api_version: Arc::new("7.2.0".to_string()),
            identity: Arc::new(identity()),
            status: status_rx,
            commands,
            activity: GatewayActivity::new(),
            tags: Arc::new(TagRegistry::new()),
            // Freedom configures no `cors-allowed-origins`, so the gateway
            // sends no CORS headers (freedom-browser `ant-manager.js`).
            cors: Arc::new(CorsConfig::default()),
            chain_state: GatewayChainState {
                light_mode: true,
                chain: None,
            }
            .preset(),
            act_secret: Arc::new([0xa7; 32]),
            on_batch_bought: None,
            on_chequebook_refused: None,
            cache: None,
        };
        Self {
            router: build_router(handle),
            unhandled,
            _status: status_tx,
        }
    }

    /// Sends one request through the router and reads the whole answer.
    pub async fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Result<Answer, String> {
        let mut req = Request::builder().method(method).uri(path);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let req = req.body(Body::empty()).map_err(|e| e.to_string())?;
        let resp = self
            .router
            .clone()
            .oneshot(req)
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("body: {e}"))?
            .to_bytes()
            .to_vec();
        if let Ok(seen) = self.unhandled.0.lock()
            && !seen.is_empty()
        {
            return Err(format!("the node loop doesn't model {seen:?}"));
        }
        Ok(Answer {
            status,
            headers,
            body,
        })
    }
}

/// A node with one connected peer, so the gateway serves retrievals.
fn status_snapshot() -> StatusSnapshot {
    StatusSnapshot {
        agent: "antd/0.5.71".to_string(),
        protocol_version: PROTOCOL_VERSION,
        network_id: 1,
        pid: 0,
        started_at_unix: 1_760_000_000,
        identity: IdentityInfo {
            eth_address: "0x0102030405060708090a0b0c0d0e0f1011121314".to_string(),
            overlay: format!("0x{}", "aa".repeat(32)),
            peer_id: "12D3KooWGeneratorPeer".to_string(),
        },
        peers: PeerInfo {
            connected: 1,
            node_limit: 16,
            connected_peers: vec![PeerConnectionInfo {
                peer_id: "12D3KooWGeneratorPeerOne".to_string(),
                direction: "Outbound".to_string(),
                address: "/ip4/127.0.0.1/tcp/1634".to_string(),
                connected_at_unix: 1_760_000_001,
                agent_version: "bee/2.8.2".to_string(),
                bzz_overlay: Some(format!("0x{}", "bb".repeat(32))),
                full_node: Some(true),
                last_bzz_at_unix: Some(1_760_000_002),
                stale: false,
            }],
            peer_pipeline: Vec::new(),
            last_handshake: None,
            time_to_first_peer_s: Some(0.5),
            time_to_node_limit_s: None,
            routing: RoutingInfo {
                base_overlay: format!("0x{}", "aa".repeat(32)),
                size: 1,
                bins: {
                    let mut bins = vec![0u32; 32];
                    bins[1] = 1;
                    bins
                },
                serving: 1,
                ..Default::default()
            },
        },
        listeners: vec!["/ip4/127.0.0.1/tcp/1634".to_string()],
        external_addresses: Vec::new(),
        control_socket: String::new(),
        retrieval: RetrievalInfo::default(),
        chain_ready: true,
        settlement: ant_control::SettlementInfo::default(),
    }
}

fn identity() -> GatewayIdentity {
    GatewayIdentity {
        overlay_hex: "aa".repeat(32),
        ethereum_hex: "0x0102030405060708090a0b0c0d0e0f1011121314".to_string(),
        public_key_hex: format!("02{}", "01".repeat(32)),
        peer_id: "12D3KooWGeneratorPeer".to_string(),
    }
}
