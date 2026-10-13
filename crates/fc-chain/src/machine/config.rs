//! `chain.configure` (design 0005, Configuration): each chain's snapshot as
//! main sends it, and the same snapshot as the machine runs it, with
//! today's defaults and clamps and the core's bounds applied.

use fc_json::index::{Index, Kind};

use super::bounds::Bounds;
use super::io::Endpoint;
use crate::js::{JsString, js_string_of, string_to_number};

/// One configured RPC endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcEndpoint {
    pub endpoint: Endpoint,
    /// `isUserConfiguredRpc`: Direct's trust is `user-configured` for it.
    pub user_configured: bool,
}

/// The Colibri prover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prover {
    pub endpoint: Endpoint,
    /// `network.zkProof !== false`.
    pub zk: bool,
}

/// `network.quorum`, raw, as the registry merges it: each value's JSON
/// text, `None` when absent. The core coerces them as the router does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuorumConfig {
    pub k: Option<String>,
    pub m: Option<String>,
    pub timeout_ms: Option<String>,
}

/// One chain's snapshot, as main computes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainConfig {
    pub chain_id: u64,
    /// Myotis's error texts name the chain.
    pub display_name: String,
    /// `access.readOrder`, or main's default.
    pub read_order: Vec<String>,
    /// `access.broadcastOrder`, or main's default.
    pub broadcast_order: Vec<String>,
    pub quorum: QuorumConfig,
    /// `getEndpoints(chainId, 'rpc')`, in registry order.
    pub rpc: Vec<RpcEndpoint>,
    /// The first prover.
    pub prover: Option<Prover>,
    /// Myotis serves this chain.
    pub myotis: bool,
    /// The Ant profile's log index.
    pub blockscout: Option<Endpoint>,
}

/// The sources the router knows. Anything else is dropped from an order
/// (deviation `order-validation`).
pub(crate) const SOURCES: [&str; 5] = ["myotis", "colibri", "quorum", "direct", "blockscout"];

/// A chain as the machine runs it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Chain {
    pub chain_id: u64,
    pub display_name: String,
    pub read_order: Vec<&'static str>,
    pub broadcast_order: Vec<&'static str>,
    /// `max(1, Number(k) || 3)`, at most the core's bound.
    pub k: f64,
    /// `max(1, min(k, Number(m) || 2))`.
    pub m: f64,
    /// `max(500, Number(timeoutMs) || 5000)`, at most the core's bound: the
    /// configured timeout every source budget starts from.
    pub timeout: f64,
    pub rpc: Vec<RpcEndpoint>,
    pub prover: Option<Prover>,
    pub myotis: bool,
    pub blockscout: Option<Endpoint>,
}

/// `Number(value)` for a JSON value's text; `None` is `undefined` (NaN).
pub(crate) fn js_number(text: Option<&str>) -> f64 {
    let Some(index) = text.and_then(|t| Index::new(t).ok()) else {
        return f64::NAN;
    };
    let value = index.root();
    match value.kind() {
        Kind::Null | Kind::False => 0.0,
        Kind::True => 1.0,
        Kind::Number => value.number(),
        Kind::String | Kind::Array => match js_string_of(value) {
            Ok(string) => string_to_number(&string.to_string_lossy()),
            Err(_) => f64::NAN,
        },
        Kind::Object => match js_string_of(value) {
            // `[object Object]`.
            Ok(_) | Err(_) => f64::NAN,
        },
    }
}

/// `Number(x) || fallback`: 0 and NaN take the fallback.
fn or(number: f64, fallback: f64) -> f64 {
    if number == 0.0 || number.is_nan() {
        fallback
    } else {
        number
    }
}

/// An order with duplicates and unknown sources dropped.
fn cleaned(order: &[String]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for name in order {
        if let Some(source) = SOURCES.iter().find(|s| **s == name.as_str())
            && !out.contains(source)
        {
            out.push(source);
        }
    }
    out
}

impl Chain {
    /// The snapshot with today's defaults and clamps (`boundary-quorum-
    /// clamps`) and the core's bounds (deviation `quorum-clamps`), and its
    /// orders cleaned (deviation `order-validation`).
    pub(crate) fn new(config: &ChainConfig, bounds: &Bounds) -> Self {
        #[allow(clippy::cast_precision_loss)]
        let k_bound = bounds.quorum_k as f64;
        #[allow(clippy::cast_precision_loss)]
        let timeout_bound = bounds.quorum_timeout_ms as f64;
        let k = or(js_number(config.quorum.k.as_deref()), 3.0)
            .max(1.0)
            .min(k_bound);
        let m = k
            .min(or(js_number(config.quorum.m.as_deref()), 2.0))
            .max(1.0);
        let timeout = or(js_number(config.quorum.timeout_ms.as_deref()), 5000.0)
            .max(500.0)
            .min(timeout_bound);
        Self {
            chain_id: config.chain_id,
            display_name: config.display_name.clone(),
            read_order: cleaned(&config.read_order),
            broadcast_order: cleaned(&config.broadcast_order),
            k,
            m,
            timeout,
            rpc: config.rpc.iter().take(bounds.endpoints).cloned().collect(),
            prover: config.prover.clone(),
            myotis: config.myotis,
            blockscout: config.blockscout.clone(),
        }
    }

    /// The endpoints' references, in registry order.
    pub(crate) fn urls(&self) -> Vec<Endpoint> {
        self.rpc.iter().map(|e| e.endpoint.clone()).collect()
    }

    /// `endpoints.slice(0, k)`.
    pub(crate) fn members(&self) -> Vec<Endpoint> {
        self.urls().into_iter().take(slice_end(self.k)).collect()
    }

    pub(crate) fn user_configured(&self, endpoint: &str) -> bool {
        self.rpc
            .iter()
            .any(|e| e.endpoint == endpoint && e.user_configured)
    }
}

/// A timer's milliseconds from a JavaScript number of them.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(crate) fn ms(number: f64) -> u64 {
    if number.is_nan() || number <= 0.0 {
        0
    } else {
        number.min(1e15).trunc() as u64
    }
}

/// `slice(0, n)`'s end for a number `n` of at least 1.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(crate) fn slice_end(n: f64) -> usize {
    if n.is_nan() || n <= 0.0 {
        0
    } else {
        n.min(1e9).trunc() as usize
    }
}

/// A JavaScript number as the router prints it.
pub(crate) fn number_text(number: f64) -> String {
    fc_json::number_to_string(number)
}

/// A JSON string's text.
pub(crate) fn quote(text: &str) -> String {
    JsString::from(text).to_json()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(k: Option<&str>, m: Option<&str>, timeout: Option<&str>, order: &[&str]) -> Chain {
        let config = ChainConfig {
            chain_id: 1,
            display_name: "Ethereum".into(),
            read_order: order.iter().map(|s| (*s).to_owned()).collect(),
            broadcast_order: Vec::new(),
            quorum: QuorumConfig {
                k: k.map(str::to_owned),
                m: m.map(str::to_owned),
                timeout_ms: timeout.map(str::to_owned),
            },
            rpc: Vec::new(),
            prover: None,
            myotis: true,
            blockscout: None,
        };
        Chain::new(&config, &Bounds::default())
    }

    #[test]
    fn todays_defaults_and_clamps() {
        // `boundary-quorum-clamps`: k=0 is 3, m=5 is k, 100 ms is 500.
        let c = chain(Some("0"), Some("5"), Some("100"), &[]);
        assert_eq!((c.k, c.m, c.timeout), (3.0, 3.0, 500.0));
        // Strings count as their numbers; a non-number takes the default.
        let c = chain(Some("\"2\""), Some("\"x\""), Some("\"abc\""), &[]);
        assert_eq!((c.k, c.m, c.timeout), (2.0, 2.0, 5000.0));
        let c = chain(None, None, None, &[]);
        assert_eq!((c.k, c.m, c.timeout), (3.0, 2.0, 5000.0));
        let c = chain(Some("true"), Some("null"), Some("[700]"), &[]);
        assert_eq!((c.k, c.m, c.timeout), (1.0, 1.0, 700.0));
    }

    #[test]
    fn the_cores_bounds() {
        // Deviation `quorum-clamps`: k at most 9, the timeout at most 60 s,
        // and m at most the clamped k.
        let c = chain(Some("50"), Some("40"), Some("1e9"), &[]);
        assert_eq!((c.k, c.m, c.timeout), (9.0, 9.0, 60_000.0));
        let c = chain(Some("1e400"), Some("2"), Some("1e400"), &[]);
        assert_eq!((c.k, c.m, ms(c.timeout)), (9.0, 2.0, 60_000));
        let endpoints = ChainConfig {
            rpc: (0..100)
                .map(|i| RpcEndpoint {
                    endpoint: format!("e{i}"),
                    user_configured: false,
                })
                .collect(),
            ..ChainConfig {
                chain_id: 1,
                display_name: String::new(),
                read_order: Vec::new(),
                broadcast_order: Vec::new(),
                quorum: QuorumConfig::default(),
                rpc: Vec::new(),
                prover: None,
                myotis: false,
                blockscout: None,
            }
        };
        let c = Chain::new(&endpoints, &Bounds::default());
        assert_eq!(c.rpc.len(), 64);
        assert_eq!(c.rpc[63].endpoint, "e63");
    }

    #[test]
    fn orders_are_cleaned() {
        // Deviation `order-validation`: duplicates and unknown names go.
        let c = chain(None, None, None, &["colibri", "nope", "colibri", "direct"]);
        assert_eq!(c.read_order, ["colibri", "direct"]);
        let c = chain(None, None, None, &["quorum", "Myotis", "quorum", "myotis"]);
        assert_eq!(c.read_order, ["quorum", "myotis"]);
    }
}
