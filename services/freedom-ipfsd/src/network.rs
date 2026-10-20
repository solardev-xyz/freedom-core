//! The network policy an instance runs under (design 0007, "Network
//! policy").
//!
//! Only `direct` exists yet: today's transports, as the add-on has them.
//! The gate, the address policy and `socks5` are implementation step 8,
//! which needs upstream item 3 (a `NetworkPolicy` threaded through the
//! builder). Until then `socks5` is refused, never approximated: a proxy
//! setting that silently connected directly would fail open.
//!
//! The policy is parsed here, apart from the rest of `ipfs.start`, so it can
//! move as a unit if it becomes a spawn argument (`--network`) rather than
//! a member of `ipfs.start`: only the caller of [`parse`] would change.

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// Direct connections: the default.
    Direct,
}

/// Parses `ipfs.start`'s `network` member, `{ "mode": "direct" }`. The
/// error is a fixed message for `invalid_argument`.
pub fn parse(network: &Value) -> Result<NetworkPolicy, &'static str> {
    let Some(members) = network.as_object() else {
        return Err("network must be an object");
    };
    match members.get("mode").and_then(Value::as_str) {
        Some("direct") if members.len() == 1 => Ok(NetworkPolicy::Direct),
        Some("direct") => Err("network mode direct takes no other members"),
        Some("socks5") => Err(
            "network mode socks5 is not supported yet (design 0007, implementation step 8): only direct",
        ),
        Some(_) => Err("unknown network mode: only direct is supported"),
        None => Err("network.mode must be a string"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_direct_is_accepted() {
        assert_eq!(
            parse(&json!({ "mode": "direct" })),
            Ok(NetworkPolicy::Direct)
        );
        for refused in [
            json!({ "mode": "socks5", "ip": "127.0.0.1", "port": 9150 }),
            json!({ "mode": "socks5" }),
            json!({ "mode": "direct", "ip": "127.0.0.1" }),
            json!({ "mode": "tor" }),
            json!({ "mode": 1 }),
            json!({}),
            json!("direct"),
            Value::Null,
        ] {
            assert!(parse(&refused).is_err(), "{refused}");
        }
        assert!(
            parse(&json!({ "mode": "socks5", "ip": "127.0.0.1", "port": 9150 }))
                .is_err_and(|message| message.contains("socks5"))
        );
    }
}
