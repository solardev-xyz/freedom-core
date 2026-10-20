//! `ipfs.start` and `ipfs.stop` parameters (design 0007, "Methods").
//!
//! Every member is required and checked, and unknown members are refused:
//! main sends today's values explicitly (0007: "the values above are
//! exactly today's ... sent explicitly"). A refusal is `invalid_argument`
//! with a fixed message, which never quotes the input.

use std::time::Duration;

use freedom_ipfs_gateway::RoutingMode;
use serde::Deserialize;
use serde_json::Value;
use serde_json::value::RawValue;

use crate::network::{self, NetworkPolicy};

/// The longest instance ID.
pub const MAX_INSTANCE_ID: usize = 64;
/// A memory store's most block data (0007, "Private windows": a 32 MiB
/// block target).
pub const MAX_MEMORY_STORE: u64 = 32 << 20;
/// A disk store's most block data: a target for LRU eviction, not a hard
/// bound (0007, "Budgets"); this only refuses nonsense.
pub const MAX_DISK_STORE: u64 = 1 << 40;
/// The most delegated routers, and the longest one.
pub const MAX_ROUTERS: usize = 8;
pub const MAX_ROUTER_LEN: usize = 2048;

/// A checked `ipfs.start`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Start {
    pub instance: String,
    pub store: Store,
    pub routing: Routing,
    pub gateway: Gateway,
    pub network: NetworkPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Store {
    /// The persistent process's store, `<data-dir>/freedom-ipfs.sqlite3`.
    Disk { max_bytes: u64 },
    /// A private instance's store, in memory.
    Memory { max_bytes: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routing {
    pub mode: RoutingMode,
    pub delegated_routers: Vec<String>,
    pub dht_query_timeout: Duration,
    pub dht_max_providers: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gateway {
    pub max_concurrent_requests: usize,
    pub request_queue_timeout: Duration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartWire {
    instance: String,
    store: StoreWire,
    routing: RoutingWire,
    gateway: GatewayWire,
    network: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreWire {
    kind: String,
    max_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutingWire {
    mode: String,
    delegated_routers: Vec<String>,
    dht_query_timeout_s: u64,
    dht_max_providers: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayWire {
    max_concurrent_requests: u64,
    request_queue_timeout_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StopWire {
    instance: String,
}

fn object<'a, T: Deserialize<'a>>(params: Option<&'a RawValue>) -> Result<T, &'static str> {
    let raw = params.ok_or("params are missing")?;
    if !raw.get().trim_start().starts_with('{') {
        return Err("params must be an object");
    }
    serde_json::from_str(raw.get())
        .map_err(|_| "params are malformed: a member is missing, unknown or of the wrong type")
}

/// Parses and checks `ipfs.start`'s params.
pub fn start(params: Option<&RawValue>) -> Result<Start, &'static str> {
    let wire: StartWire = object(params)?;
    check_instance(&wire.instance)?;
    let store = match wire.store.kind.as_str() {
        "disk" if (1..=MAX_DISK_STORE).contains(&wire.store.max_bytes) => Store::Disk {
            max_bytes: wire.store.max_bytes,
        },
        "disk" => return Err("store.max_bytes must be between 1 and 2^40"),
        "memory" if (1..=MAX_MEMORY_STORE).contains(&wire.store.max_bytes) => Store::Memory {
            max_bytes: wire.store.max_bytes,
        },
        "memory" => return Err("store.max_bytes must be between 1 and 32 MiB for a memory store"),
        _ => return Err("store.kind must be disk or memory"),
    };
    let mode = match wire.routing.mode.as_str() {
        "auto" => RoutingMode::Auto,
        "delegated" => RoutingMode::Delegated,
        "light_dht" => RoutingMode::LightDht,
        "offline" => RoutingMode::Offline,
        _ => return Err("routing.mode must be auto, delegated, light_dht or offline"),
    };
    if wire.routing.delegated_routers.len() > MAX_ROUTERS {
        return Err("routing.delegated_routers has more than 8 entries");
    }
    if !wire
        .routing
        .delegated_routers
        .iter()
        .all(|router| router_ok(router))
    {
        return Err("routing.delegated_routers must be http or https URLs");
    }
    if !(1..=60).contains(&wire.routing.dht_query_timeout_s) {
        return Err("routing.dht_query_timeout_s must be between 1 and 60");
    }
    let dht_max_providers = match wire.routing.dht_max_providers {
        max @ 1..=256 => usize::try_from(max).map_err(|_| "routing.dht_max_providers")?,
        _ => return Err("routing.dht_max_providers must be between 1 and 256"),
    };
    let max_concurrent_requests = match wire.gateway.max_concurrent_requests {
        max @ 1..=64 => usize::try_from(max).map_err(|_| "gateway.max_concurrent_requests")?,
        _ => return Err("gateway.max_concurrent_requests must be between 1 and 64"),
    };
    if !(1..=60_000).contains(&wire.gateway.request_queue_timeout_ms) {
        return Err("gateway.request_queue_timeout_ms must be between 1 and 60000");
    }
    Ok(Start {
        instance: wire.instance,
        store,
        routing: Routing {
            mode,
            delegated_routers: wire.routing.delegated_routers,
            dht_query_timeout: Duration::from_secs(wire.routing.dht_query_timeout_s),
            dht_max_providers,
        },
        gateway: Gateway {
            max_concurrent_requests,
            request_queue_timeout: Duration::from_millis(wire.gateway.request_queue_timeout_ms),
        },
        network: network::parse(&wire.network)?,
    })
}

/// Parses `ipfs.stop`'s params: the instance ID.
pub fn stop(params: Option<&RawValue>) -> Result<String, &'static str> {
    let wire: StopWire = object(params)?;
    check_instance(&wire.instance)?;
    Ok(wire.instance)
}

/// Instance IDs are main's labels (`p-1`, `e-1`, …): short, and safe to log.
fn check_instance(instance: &str) -> Result<(), &'static str> {
    let ok = (1..=MAX_INSTANCE_ID).contains(&instance.len())
        && instance
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if ok {
        Ok(())
    } else {
        Err("instance must be 1 to 64 characters of A-Z, a-z, 0-9, '-', '_' and '.'")
    }
}

/// A delegated router is configuration main sends, not page input: this
/// only refuses what can't be one. Userinfo, the gate and every later check
/// on configured endpoints come with the network policy (0007, step 8).
fn router_ok(router: &str) -> bool {
    let rest = router
        .strip_prefix("https://")
        .or_else(|| router.strip_prefix("http://"));
    router.len() <= MAX_ROUTER_LEN
        && rest.is_some_and(|rest| !rest.is_empty())
        && router.bytes().all(|b| b.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Today's values (0007, "Methods"), with a disk store.
    fn todays() -> Value {
        json!({
            "instance": "p-1",
            "store": { "kind": "disk", "max_bytes": 268435456 },
            "routing": { "mode": "auto",
                "delegated_routers": ["https://delegated-ipfs.dev/routing/v1", "https://cid.contact/routing/v1"],
                "dht_query_timeout_s": 3, "dht_max_providers": 32 },
            "gateway": { "max_concurrent_requests": 8, "request_queue_timeout_ms": 15000 },
            "network": { "mode": "direct" }
        })
    }

    fn parse(value: &Value) -> Result<Start, &'static str> {
        let raw = serde_json::value::to_raw_value(value).unwrap();
        start(Some(&raw))
    }

    #[test]
    fn todays_values_parse() {
        let start = parse(&todays()).unwrap();
        assert_eq!(
            start,
            Start {
                instance: "p-1".into(),
                store: Store::Disk {
                    max_bytes: 256 << 20
                },
                routing: Routing {
                    mode: RoutingMode::Auto,
                    delegated_routers: vec![
                        "https://delegated-ipfs.dev/routing/v1".into(),
                        "https://cid.contact/routing/v1".into()
                    ],
                    dht_query_timeout: Duration::from_secs(3),
                    dht_max_providers: 32,
                },
                gateway: Gateway {
                    max_concurrent_requests: 8,
                    request_queue_timeout: Duration::from_secs(15),
                },
                network: NetworkPolicy::Direct,
            }
        );
        let mut memory = todays();
        memory["store"] = json!({ "kind": "memory", "max_bytes": 33554432 });
        assert_eq!(
            parse(&memory).unwrap().store,
            Store::Memory {
                max_bytes: 32 << 20
            }
        );
        for (mode, expected) in [
            ("delegated", RoutingMode::Delegated),
            ("light_dht", RoutingMode::LightDht),
            ("offline", RoutingMode::Offline),
        ] {
            let mut other = todays();
            other["routing"]["mode"] = mode.into();
            assert_eq!(parse(&other).unwrap().routing.mode, expected);
        }
    }

    #[test]
    fn refusals() {
        let cases: Vec<(&str, Value)> = vec![
            ("/instance", json!("")),
            ("/instance", json!("p 1")),
            ("/instance", json!("p/1")),
            ("/instance", json!("x".repeat(65))),
            ("/instance", json!(1)),
            ("/store/kind", json!("file")),
            ("/store/max_bytes", json!(0)),
            ("/store/max_bytes", json!(-1)),
            ("/store/max_bytes", json!((1u64 << 40) + 1)),
            ("/routing/mode", json!("AUTO")),
            ("/routing/delegated_routers", json!(["ftp://x"])),
            ("/routing/delegated_routers", json!(["https://"])),
            ("/routing/delegated_routers", json!(["https://a b"])),
            ("/routing/delegated_routers", json!(vec!["https://a"; 9])),
            ("/routing/dht_query_timeout_s", json!(0)),
            ("/routing/dht_query_timeout_s", json!(61)),
            ("/routing/dht_max_providers", json!(0)),
            ("/routing/dht_max_providers", json!(257)),
            ("/gateway/max_concurrent_requests", json!(0)),
            ("/gateway/max_concurrent_requests", json!(65)),
            ("/gateway/request_queue_timeout_ms", json!(0)),
            ("/gateway/request_queue_timeout_ms", json!(60_001)),
            (
                "/network",
                json!({ "mode": "socks5", "ip": "127.0.0.1", "port": 9150 }),
            ),
            ("/network/mode", json!("tor")),
            ("/extra", json!(1)),
            ("/routing/extra", json!(1)),
        ];
        for (pointer, value) in cases {
            let mut params = todays();
            let (parent, member) = pointer.rsplit_once('/').unwrap();
            let target = if parent.is_empty() {
                &mut params
            } else {
                params.pointer_mut(parent).unwrap()
            };
            target[member] = value.clone();
            assert!(parse(&params).is_err(), "{pointer} = {value}");
        }
        let mut memory = todays();
        memory["store"] = json!({ "kind": "memory", "max_bytes": (32 << 20) + 1 });
        assert!(parse(&memory).is_err());
        for missing in ["instance", "store", "routing", "gateway", "network"] {
            let mut params = todays();
            params.as_object_mut().unwrap().remove(missing);
            assert!(parse(&params).is_err(), "{missing}");
        }
        assert!(start(None).is_err());
        let array = serde_json::value::to_raw_value(&json!([1])).unwrap();
        assert!(start(Some(&array)).is_err());
    }

    #[test]
    fn stop_takes_an_instance() {
        let raw = serde_json::value::to_raw_value(&json!({ "instance": "e-3" })).unwrap();
        assert_eq!(stop(Some(&raw)), Ok("e-3".into()));
        for refused in [
            json!({}),
            json!({ "instance": "" }),
            json!({ "instance": "e-3", "x": 1 }),
        ] {
            let raw = serde_json::value::to_raw_value(&refused).unwrap();
            assert!(stop(Some(&raw)).is_err(), "{refused}");
        }
    }
}
