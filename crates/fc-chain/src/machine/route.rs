//! The adaptive bypass (design 0005, Adaptive bypass): routes, their keys,
//! and the table of slow and capacity-limited routes.

use fc_json::index::{Index, Kind, Value};

use super::config::{number_text, quote};
use super::error::FailureKind;
use super::io::Ms;
use crate::js::{Element, element, trim};

/// `SOURCE_TIMEOUT_COOLDOWNS_MS`.
pub(crate) const TIMEOUT_COOLDOWNS_MS: [Ms; 3] = [15_000, 30_000, 60_000];

/// `normalizeRoutingOrigin`: the caller's origin trimmed, when it is a
/// non-empty string of at most 2048 UTF-16 units without control
/// characters. Only such a read is interactive.
pub(crate) fn routing_origin(origin: Option<&str>) -> Option<String> {
    let units: Vec<u16> = origin?.encode_utf16().collect();
    let trimmed = trim(&units);
    let control = trimmed.iter().any(|&u| u <= 31 || u == 127);
    if trimmed.is_empty() || trimmed.len() > 2048 || control {
        return None;
    }
    Some(String::from_utf16_lossy(trimmed))
}

const CALL_OBJECT_METHODS: [&str; 2] = ["eth_call", "eth_estimateGas"];
const ACCOUNT_METHODS: [&str; 4] = [
    "eth_getBalance",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_getTransactionCount",
];

/// `/^0x[0-9a-f]{40}$/i`.
fn is_address(text: &[u16]) -> bool {
    matches!(text, [0x30, 0x78 | 0x58, digits @ ..]
        if digits.len() == 40 && digits.iter().all(|&u| u < 128 && (u as u8).is_ascii_hexdigit()))
}

fn lower(units: &[u16]) -> String {
    String::from_utf16_lossy(units).to_ascii_lowercase()
}

/// `requestTarget(method, params)`: the contract or account a request is
/// about, lowercased; a list of them sorted and joined; `*` for none.
///
/// A list of more than one is kept as its digest, [`list_target`]: the
/// adaptive table outlives its requests, and its keys are bounded in bytes
/// (`memory-budgets`).
pub(crate) fn request_target(method: &str, params: &str) -> String {
    let Ok(index) = Index::new(params) else {
        return "*".into();
    };
    let first = element(index.root(), 0);
    let member = |key: &str| match first {
        Some(Element::Value(value)) if value.kind() == Kind::Object => {
            value.get(key).map(Element::Value)
        }
        _ => None,
    };
    let target: Option<Element<'_, '_>> = if CALL_OBJECT_METHODS.contains(&method) {
        member("to")
    } else if ACCOUNT_METHODS.contains(&method) {
        first
    } else if method == "eth_getLogs" {
        member("address")
    } else {
        None
    };
    match target {
        Some(Element::Value(value)) if value.kind() == Kind::Array => {
            let mut addresses: Vec<String> = value
                .children()
                .filter(|item| item.kind() == Kind::String)
                .map(|item| item.units().collect::<Vec<u16>>())
                .filter(|units| is_address(units))
                .map(|units| lower(&units))
                .collect();
            addresses.sort();
            match addresses.as_slice() {
                [] => "*".into(),
                [one] => one.clone(),
                _ => list_target(&addresses.join(",")),
            }
        }
        Some(Element::Value(value)) if value.kind() == Kind::String => string_target(value),
        _ => "*".into(),
    }
}

/// A list target's identity: `sha256:` and the SHA-256 of the reference's
/// joined text, in hex. Two lists share a route exactly when the reference's
/// joined texts are equal (to SHA-256's collision resistance), and a key
/// holds 71 bytes of target however long the list.
pub(crate) fn list_target(joined: &str) -> String {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(joined.as_bytes());
    let mut text = String::with_capacity(7 + 64);
    text.push_str("sha256:");
    for byte in digest {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn string_target(value: Value<'_, '_>) -> String {
    let units: Vec<u16> = value.units().collect();
    let trimmed = trim(&units);
    if is_address(trimmed) {
        lower(trimmed)
    } else {
        "*".into()
    }
}

/// `adaptiveRouteKey`: `JSON.stringify([source, chain, origin, method,
/// target])`.
pub(crate) fn route_key(
    source: &str,
    chain_id: u64,
    origin: &str,
    method: &str,
    target: &str,
) -> String {
    #[allow(clippy::cast_precision_loss)]
    let chain = number_text(chain_id as f64);
    format!(
        "[{},{chain},{},{},{}]",
        quote(source),
        quote(origin),
        quote(method),
        quote(target)
    )
}

/// Colibri's in-flight key for a request without a route:
/// `JSON.stringify(['colibri', chain, method, target])`.
pub(crate) fn colibri_key(chain_id: u64, method: &str, target: &str) -> String {
    #[allow(clippy::cast_precision_loss)]
    let chain = number_text(chain_id as f64);
    format!("[\"colibri\",{chain},{},{}]", quote(method), quote(target))
}

/// One route's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RouteState {
    pub timeout_count: u32,
    /// Until when the route is bypassed.
    pub open_until: Ms,
    /// A capacity failure: bypassed for the process's life.
    pub session_blocked: bool,
}

/// The adaptive table, in insertion order (a JavaScript `Map`).
#[derive(Debug, Default)]
pub(crate) struct Adaptive {
    routes: Vec<(String, RouteState)>,
}

impl Adaptive {
    /// `adaptiveSourceUnavailable`.
    pub(crate) fn unavailable(&self, key: &str, now: Ms) -> bool {
        self.get(key)
            .is_some_and(|state| state.session_blocked || state.open_until > now)
    }

    fn get(&self, key: &str) -> Option<&RouteState> {
        self.routes.iter().find(|(k, _)| k == key).map(|(_, s)| s)
    }

    /// `recordAdaptiveSuccess`: clears the route unless it is blocked.
    pub(crate) fn success(&mut self, key: &str) {
        if self.get(key).is_some_and(|s| s.session_blocked) {
            return;
        }
        self.routes.retain(|(k, _)| k != key);
    }

    /// `setAdaptiveSourceState`: a new route past the limit evicts the
    /// oldest; an update keeps its place.
    fn set(&mut self, key: &str, state: RouteState, limit: usize) {
        if let Some(entry) = self.routes.iter_mut().find(|(k, _)| k == key) {
            entry.1 = state;
            return;
        }
        if self.routes.len() >= limit && !self.routes.is_empty() {
            self.routes.remove(0);
        }
        self.routes.push((key.to_owned(), state));
    }

    /// `recordAdaptiveFailure`: a timeout opens the route for 15, 30 and
    /// then 60 s; a capacity failure blocks it.
    pub(crate) fn failure(&mut self, key: &str, kind: Option<FailureKind>, now: Ms, limit: usize) {
        let Some(kind) = kind else { return };
        let previous = self.get(key).copied().unwrap_or_default();
        match kind {
            FailureKind::Capacity => self.set(
                key,
                RouteState {
                    session_blocked: true,
                    ..previous
                },
                limit,
            ),
            FailureKind::Timeout => {
                let timeout_count = previous.timeout_count.saturating_add(1);
                let step = (timeout_count as usize - 1).min(TIMEOUT_COOLDOWNS_MS.len() - 1);
                self.set(
                    key,
                    RouteState {
                        timeout_count,
                        open_until: now.saturating_add(TIMEOUT_COOLDOWNS_MS[step]),
                        ..previous
                    },
                    limit,
                );
            }
        }
    }

    pub(crate) fn routes(&self) -> &[(String, RouteState)] {
        &self.routes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        let addr = "0x".to_owned() + &"AB".repeat(20);
        assert_eq!(
            request_target("eth_call", &format!(r#"[{{"to":" {addr} "}}]"#)),
            "0x".to_owned() + &"ab".repeat(20)
        );
        assert_eq!(request_target("eth_call", r#"[{"to":"0xabc"}]"#), "*");
        assert_eq!(
            request_target(
                "eth_getLogs",
                &format!(
                    r#"[{{"address":["{}","x","{}"]}}]"#,
                    "0x".to_owned() + &"b".repeat(40),
                    addr
                )
            ),
            // SHA-256 of `0xabab…ab,0xbbbb…bb`, the reference's joined text.
            "sha256:8a0b71b5b46abc57a3c4d254d7d67228a909121d4fef526805a0a9d2edc825b3"
        );
        // One address is itself; a list of any length is 71 bytes, the
        // same for the same set in any order or case.
        assert_eq!(
            request_target("eth_getLogs", &format!(r#"[{{"address":["{addr}"]}}]"#)),
            "0x".to_owned() + &"ab".repeat(20)
        );
        let list = |order: &mut dyn Iterator<Item = usize>| {
            let items: Vec<String> = order.map(|n| format!("\"0x{n:040X}\"")).collect();
            request_target(
                "eth_getLogs",
                &format!(r#"[{{"address":[{}]}}]"#, items.join(",")),
            )
        };
        let forward = list(&mut (0..100));
        assert_eq!(forward.len(), 71);
        assert_eq!(forward, list(&mut (0..100).rev()));
        assert_ne!(forward, list(&mut (0..99)));
        assert_eq!(
            request_target("eth_getBalance", &format!(r#"["{addr}"]"#)).len(),
            42
        );
        assert_eq!(request_target("eth_blockNumber", "[]"), "*");
        assert_eq!(request_target("eth_call", "null"), "*");
    }

    #[test]
    fn origins() {
        assert_eq!(
            routing_origin(Some("  https://swap.example  ")).as_deref(),
            Some("https://swap.example")
        );
        assert_eq!(routing_origin(Some("https://swap.example\u{1}")), None);
        assert_eq!(routing_origin(Some("   ")), None);
        assert_eq!(routing_origin(Some(&"x".repeat(2049))), None);
        assert_eq!(routing_origin(None), None);
        assert_eq!(
            route_key("quorum", 1, "https://swap.example", "eth_call", "*"),
            r#"["quorum",1,"https://swap.example","eth_call","*"]"#
        );
    }

    #[test]
    fn cooldowns_escalate_and_capacity_blocks() {
        let mut table = Adaptive::default();
        table.failure("r", Some(FailureKind::Timeout), 0, 1024);
        assert!(table.unavailable("r", 14_999) && !table.unavailable("r", 15_000));
        table.failure("r", Some(FailureKind::Timeout), 15_000, 1024);
        assert!(table.unavailable("r", 44_999) && !table.unavailable("r", 45_000));
        table.failure("r", Some(FailureKind::Timeout), 45_000, 1024);
        table.failure("r", Some(FailureKind::Timeout), 105_000, 1024);
        assert!(table.unavailable("r", 164_999) && !table.unavailable("r", 165_000));
        table.success("r");
        assert!(table.routes().is_empty());
        table.failure("r", Some(FailureKind::Capacity), 0, 1024);
        table.success("r");
        assert!(table.unavailable("r", u64::MAX));
        table.failure("s", None, 0, 1024);
        assert_eq!(table.routes().len(), 1);
    }

    #[test]
    fn the_oldest_route_is_evicted() {
        let mut table = Adaptive::default();
        for i in 0..3 {
            table.failure(&format!("r{i}"), Some(FailureKind::Capacity), 0, 2);
        }
        let keys: Vec<&str> = table.routes().iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["r1", "r2"]);
        // An update keeps its place.
        table.failure("r1", Some(FailureKind::Timeout), 0, 2);
        assert_eq!(table.routes()[0].0, "r1");
    }
}
