//! `ipfs.start`, `ipfs.stop` and `ipfs.request` parameters (design 0007,
//! "Methods").
//!
//! Every member is required and checked, and unknown members are refused:
//! main sends today's values explicitly (0007: "the values above are
//! exactly today's ... sent explicitly"). A refusal is `invalid_argument`
//! with a fixed message, which never quotes the input.

use std::time::Duration;

use freedom_ipfs_gateway::{NativeRequestHeader, RoutingMode};
use serde::Deserialize;
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
/// The longest `headers_ms`: the plan's head deadline is at most 30 s (0007,
/// "Bounds").
pub const MAX_HEADERS_MS: u64 = 30_000;
/// The most delegated routers.
pub const MAX_ROUTERS: usize = 8;

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
    /// The DoH endpoint DNSLink and `/dnsaddr` expansion ask (0007, "The
    /// gate": a configured target, as the routers are).
    pub doh_endpoint: String,
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
    doh_endpoint: String,
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

/// A checked `ipfs.request`: what upstream's native-request parser is
/// given, and the head's deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub instance: String,
    /// Passed through to the parser, which takes `GET` or `HEAD`.
    pub method: String,
    /// The plan's path, passed through.
    pub path: String,
    /// The plan's headers, passed through.
    pub headers: Vec<NativeRequestHeader>,
    /// The head's deadline, from admission.
    pub headers_ms: Duration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    instance: String,
    method: String,
    path: String,
    /// `[name, value]` pairs, as main sends them; upstream's header type
    /// takes that form (and `{ name, value }`, as the add-on's JSON does).
    headers: Vec<NativeRequestHeader>,
    headers_ms: u64,
}

fn object<'a, T: Deserialize<'a>>(params: Option<&'a RawValue>) -> Result<T, &'static str> {
    let raw = params.ok_or("params are missing")?;
    if !raw.get().trim_start().starts_with('{') {
        return Err("params must be an object");
    }
    serde_json::from_str(raw.get())
        .map_err(|_| "params are malformed: a member is missing, unknown or of the wrong type")
}

/// Parses and checks `ipfs.start`'s params, under the process's network
/// policy (`--network`, which `ipfs.start` no longer carries: a `network`
/// member is unknown, so refused).
pub fn start(params: Option<&RawValue>, network: NetworkPolicy) -> Result<Start, &'static str> {
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
        .all(|router| network::endpoint_ok(router))
    {
        return Err(
            "routing.delegated_routers must be http or https URLs, without userinfo or a fragment",
        );
    }
    if !network::endpoint_ok(&wire.routing.doh_endpoint) {
        return Err(
            "routing.doh_endpoint must be an http or https URL, without userinfo or a fragment",
        );
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
    match network {
        // `direct` has no route to an onion (0007, "The onion route").
        NetworkPolicy::Direct
            if wire
                .routing
                .delegated_routers
                .iter()
                .chain([&wire.routing.doh_endpoint])
                .any(|endpoint| network::is_onion(endpoint)) =>
        {
            return Err("an onion router or DoH endpoint needs network mode socks5");
        }
        // The light DHT dials dozens of peers per query, each through the
        // proxy, and can't bootstrap without a local lookup (0007, "Modes":
        // routing is delegated under a proxy; decision D6).
        NetworkPolicy::Socks5 { .. }
            if !matches!(mode, RoutingMode::Delegated | RoutingMode::Offline) =>
        {
            return Err("network mode socks5 takes routing mode delegated or offline");
        }
        NetworkPolicy::Direct | NetworkPolicy::Socks5 { .. } => {}
    }
    Ok(Start {
        instance: wire.instance,
        store,
        routing: Routing {
            mode,
            delegated_routers: wire.routing.delegated_routers,
            doh_endpoint: wire.routing.doh_endpoint,
            dht_query_timeout: Duration::from_secs(wire.routing.dht_query_timeout_s),
            dht_max_providers,
        },
        gateway: Gateway {
            max_concurrent_requests,
            request_queue_timeout: Duration::from_millis(wire.gateway.request_queue_timeout_ms),
        },
        network,
    })
}

/// Parses `ipfs.stop`'s params: the instance ID.
pub fn stop(params: Option<&RawValue>) -> Result<String, &'static str> {
    let wire: StopWire = object(params)?;
    check_instance(&wire.instance)?;
    Ok(wire.instance)
}

/// Parses and checks `ipfs.request`'s params. The method, path and headers
/// are upstream's parser's to judge; here only their types.
pub fn request(params: Option<&RawValue>) -> Result<Request, &'static str> {
    let wire: RequestWire = object(params)?;
    check_instance(&wire.instance)?;
    if !(1..=MAX_HEADERS_MS).contains(&wire.headers_ms) {
        return Err("headers_ms must be between 1 and 30000");
    }
    Ok(Request {
        instance: wire.instance,
        method: wire.method,
        path: wire.path,
        headers: wire.headers,
        headers_ms: Duration::from_millis(wire.headers_ms),
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use serde_json::json;

    /// Today's values (0007, "Methods"), with a disk store.
    fn todays() -> Value {
        json!({
            "instance": "p-1",
            "store": { "kind": "disk", "max_bytes": 268435456 },
            "routing": { "mode": "auto",
                "delegated_routers": ["https://delegated-ipfs.dev/routing/v1", "https://cid.contact/routing/v1"],
                "doh_endpoint": "https://cloudflare-dns.com/dns-query",
                "dht_query_timeout_s": 3, "dht_max_providers": 32 },
            "gateway": { "max_concurrent_requests": 8, "request_queue_timeout_ms": 15000 }
        })
    }

    /// `ipfs.start` in a `direct` process.
    fn parse(value: &Value) -> Result<Start, &'static str> {
        parse_under(value, NetworkPolicy::Direct)
    }

    fn parse_under(value: &Value, network: NetworkPolicy) -> Result<Start, &'static str> {
        let raw = serde_json::value::to_raw_value(value).unwrap();
        start(Some(&raw), network)
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
                    doh_endpoint: "https://cloudflare-dns.com/dns-query".into(),
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
            (
                "/routing/delegated_routers",
                json!(["https://u:p@delegated-ipfs.dev/"]),
            ),
            (
                "/routing/delegated_routers",
                json!(["https://delegated-ipfs.dev/#f"]),
            ),
            ("/routing/delegated_routers", json!(["https://.example/"])),
            ("/routing/doh_endpoint", json!("ftp://cloudflare-dns.com/")),
            (
                "/routing/doh_endpoint",
                json!("https://u@cloudflare-dns.com/"),
            ),
            (
                "/routing/doh_endpoint",
                json!("https://cloudflare-dns.com/#f"),
            ),
            ("/routing/doh_endpoint", json!("")),
            ("/routing/doh_endpoint", json!(1)),
            // `direct` reaches no onion.
            (
                "/routing/delegated_routers",
                json!(["https://router.onion/routing/v1"]),
            ),
            (
                "/routing/doh_endpoint",
                json!("https://dns.onion/dns-query"),
            ),
            ("/routing/dht_query_timeout_s", json!(0)),
            ("/routing/dht_query_timeout_s", json!(61)),
            ("/routing/dht_max_providers", json!(0)),
            ("/routing/dht_max_providers", json!(257)),
            ("/gateway/max_concurrent_requests", json!(0)),
            ("/gateway/max_concurrent_requests", json!(65)),
            ("/gateway/request_queue_timeout_ms", json!(0)),
            ("/gateway/request_queue_timeout_ms", json!(60_001)),
            // The policy is `--network`'s now: `ipfs.start` can't carry it.
            ("/network", json!({ "mode": "direct" })),
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
        for missing in ["instance", "store", "routing", "gateway"] {
            let mut params = todays();
            params.as_object_mut().unwrap().remove(missing);
            assert!(parse(&params).is_err(), "{missing}");
        }
        let mut no_doh = todays();
        no_doh["routing"]
            .as_object_mut()
            .unwrap()
            .remove("doh_endpoint");
        assert!(parse(&no_doh).is_err());
        assert!(start(None, NetworkPolicy::Direct).is_err());
        let array = serde_json::value::to_raw_value(&json!([1])).unwrap();
        assert!(start(Some(&array), NetworkPolicy::Direct).is_err());
    }

    /// In a `socks5` process, delegated or offline routing: an onion router
    /// or DoH endpoint is accepted there, where `direct` refuses it; every
    /// other routing mode is refused (decision D6).
    #[test]
    fn socks5_takes_delegated_or_offline_routing_and_reaches_onions() {
        let policy = NetworkPolicy::Socks5 {
            proxy: "127.0.0.1:9150".parse().unwrap(),
        };
        let socks5 = |mode: &str| {
            let mut params = todays();
            params["routing"]["mode"] = mode.into();
            params["routing"]["delegated_routers"] = json!(["https://router.onion/routing/v1"]);
            params["routing"]["doh_endpoint"] = json!("https://dns.onion/dns-query");
            parse_under(&params, policy)
        };
        for (mode, expected) in [
            ("delegated", RoutingMode::Delegated),
            ("offline", RoutingMode::Offline),
        ] {
            let start = socks5(mode).unwrap();
            assert_eq!(start.routing.mode, expected);
            assert_eq!(start.network, policy);
        }
        for mode in ["auto", "light_dht"] {
            assert_eq!(
                socks5(mode),
                Err("network mode socks5 takes routing mode delegated or offline")
            );
        }
    }

    fn request_params() -> Value {
        json!({ "instance": "p-1", "method": "GET", "path": "/ipfs/bafy/app.js",
            "headers": [["range", "bytes=0-"]], "headers_ms": 30000 })
    }

    #[test]
    fn a_request_takes_its_five_members() {
        let raw = serde_json::value::to_raw_value(&request_params()).unwrap();
        assert_eq!(
            request(Some(&raw)),
            Ok(Request {
                instance: "p-1".into(),
                method: "GET".into(),
                path: "/ipfs/bafy/app.js".into(),
                headers: vec![NativeRequestHeader {
                    name: "range".into(),
                    value: "bytes=0-".into()
                }],
                headers_ms: Duration::from_secs(30),
            })
        );
        let cases: Vec<(&str, Value)> = vec![
            ("instance", json!("p 1")),
            ("instance", json!(1)),
            ("method", json!(1)),
            ("path", json!(null)),
            ("headers", json!("range")),
            ("headers", json!([["range"]])),
            ("headers", json!([["range", 1]])),
            ("headers_ms", json!(0)),
            ("headers_ms", json!(30_001)),
            ("headers_ms", json!(-1)),
            ("headers_ms", json!(1.5)),
            ("extra", json!(1)),
        ];
        for (member, value) in cases {
            let mut params = request_params();
            params[member] = value.clone();
            let raw = serde_json::value::to_raw_value(&params).unwrap();
            assert!(request(Some(&raw)).is_err(), "{member} = {value}");
        }
        for missing in ["instance", "method", "path", "headers", "headers_ms"] {
            let mut params = request_params();
            params.as_object_mut().unwrap().remove(missing);
            let raw = serde_json::value::to_raw_value(&params).unwrap();
            assert!(request(Some(&raw)).is_err(), "{missing}");
        }
        assert!(request(None).is_err());
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
