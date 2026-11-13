//! A profile's node configuration and ports: `getManagedPorts`,
//! `buildNodeConfig`, `rebaseNodeConfig`, `fillMissingNodeConfig`,
//! `normalizeIpfsMode` and `allocateSlot`, as `profile-catalog.js` has them.
//! Values stay JavaScript values: a record keeps whatever its file holds, in
//! its order.

use fc_json::JsValue;

use crate::ids::{DEFAULT_PROFILE_ID, dev_port_offset};
use crate::js::{self, is_integer, is_str, nullish, object, or, prop, spread, string};

/// The first port of each kind, before a profile's slot is added.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PortBase {
    pub bee_api: f64,
    pub bee_p2p: f64,
    pub tor_socks: f64,
}

/// A packaged build's bases.
pub const PACKAGED_PORT_BASE: PortBase = PortBase {
    bee_api: 11633.0,
    bee_p2p: 12633.0,
    tor_socks: 19150.0,
};

/// A dev build's bases, before the checkout's offset.
pub const DEV_PORT_BASE: PortBase = PortBase {
    bee_api: 21633.0,
    bee_p2p: 22633.0,
    tor_socks: 29150.0,
};

/// A profile's managed ports. Doubles, as in JavaScript: a slot read from a
/// file can be any integer, and a dev offset `NaN`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ports {
    pub bee_api: f64,
    pub bee_p2p: f64,
    pub tor_socks: f64,
}

/// `getManagedPorts(slot, { dev, checkoutHash })`.
pub fn managed_ports(slot: f64, dev: bool, checkout_hash: Option<&str>) -> Ports {
    let (base, offset) = if dev {
        let hash = checkout_hash
            .filter(|h| !h.is_empty())
            .unwrap_or("00000000");
        (DEV_PORT_BASE, dev_port_offset(hash))
    } else {
        (PACKAGED_PORT_BASE, 0.0)
    };
    Ports {
        bee_api: base.bee_api + offset + slot,
        bee_p2p: base.bee_p2p + offset + slot,
        tor_socks: base.tor_socks + offset + slot,
    }
}

/// `getRecordManagedPorts(record, options)`: by the record's slot, 0 when it
/// has no integer one.
pub(crate) fn record_ports(record: &JsValue, dev: bool, checkout_hash: Option<&str>) -> Ports {
    let slot = match prop(record, "slot") {
        JsValue::Number(n) if is_integer(&JsValue::Number(n)) => n,
        _ => 0.0,
    };
    managed_ports(slot, dev, checkout_hash)
}

fn obj(entries: Vec<(&str, JsValue)>) -> JsValue {
    let mut out = object();
    for (key, value) in entries {
        out.set(key, value);
    }
    out
}

/// `buildNodeConfig(ports)`.
pub fn build_node_config(ports: &Ports) -> JsValue {
    obj(vec![
        (
            "bee",
            obj(vec![
                ("mode", string("managed")),
                ("apiPort", JsValue::Number(ports.bee_api)),
                ("p2pPort", JsValue::Number(ports.bee_p2p)),
                ("externalApi", JsValue::Null),
            ]),
        ),
        (
            "ipfs",
            obj(vec![
                ("mode", string("managed")),
                ("backend", string("freedom-ipfs")),
            ]),
        ),
        (
            "myotis",
            obj(vec![
                ("mode", string("managed")),
                ("backend", string("myotis-native")),
            ]),
        ),
        ("radicle", obj(vec![("mode", string("managed"))])),
        (
            "tor",
            obj(vec![
                ("mode", string("managed")),
                ("socksPort", JsValue::Number(ports.tor_socks)),
                ("externalSocks", JsValue::Null),
            ]),
        ),
    ])
}

/// `normalizeIpfsMode(mode, fallback)`: a kept `disabled` or `external`,
/// anything else the fallback.
pub fn normalize_ipfs_mode(mode: &JsValue, fallback: &JsValue) -> JsValue {
    if is_str(mode, "disabled") {
        string("disabled")
    } else if is_str(mode, "external") {
        string("external")
    } else {
        fallback.clone()
    }
}

/// `nodes?.[a]?.[b]`.
fn at(nodes: &JsValue, a: &str, b: &str) -> JsValue {
    let block = prop(nodes, a);
    if nullish(&block) {
        JsValue::Undefined
    } else {
        prop(&block, b)
    }
}

/// `keptVerifySetting(config)`, spread onto `target`.
fn keep_verify(target: &mut JsValue, config: &JsValue) {
    if let JsValue::Bool(b) = prop(config, "verify") {
        target.set("verify", JsValue::Bool(b));
    }
}

/// `myotis` and `radicle`, which both functions build alike.
fn native_blocks(out: &mut JsValue, nodes: &JsValue, defaults: &JsValue) {
    let mut myotis = prop(defaults, "myotis");
    let mode = if is_str(&at(nodes, "myotis", "mode"), "disabled") {
        string("disabled")
    } else {
        at(defaults, "myotis", "mode")
    };
    myotis.set("mode", mode);
    myotis.set("backend", string("myotis-native"));
    out.set("myotis", myotis);
    let radicle_mode = if is_str(&at(nodes, "radicle", "mode"), "disabled") {
        string("disabled")
    } else {
        at(defaults, "radicle", "mode")
    };
    out.set("radicle", obj(vec![("mode", radicle_mode)]));
}

/// `rebaseNodeConfig(nodes, ports)`: the ports' defaults, with the modes,
/// external endpoints and verify settings `nodes` chose.
pub fn rebase_node_config(nodes: &JsValue, ports: &Ports) -> JsValue {
    let defaults = build_node_config(ports);
    let mut out = object();

    let mut bee = prop(&defaults, "bee");
    bee.set(
        "mode",
        or(at(nodes, "bee", "mode"), || at(&defaults, "bee", "mode")),
    );
    bee.set(
        "externalApi",
        or(at(nodes, "bee", "externalApi"), || JsValue::Null),
    );
    keep_verify(&mut bee, &prop(nodes, "bee"));
    out.set("bee", bee);

    let mut ipfs = prop(&defaults, "ipfs");
    ipfs.set(
        "mode",
        normalize_ipfs_mode(&at(nodes, "ipfs", "mode"), &at(&defaults, "ipfs", "mode")),
    );
    ipfs.set(
        "externalGateway",
        or(at(nodes, "ipfs", "externalGateway"), || JsValue::Null),
    );
    keep_verify(&mut ipfs, &prop(nodes, "ipfs"));
    ipfs.set("backend", string("freedom-ipfs"));
    out.set("ipfs", ipfs);

    native_blocks(&mut out, nodes, &defaults);

    let mut tor = prop(&defaults, "tor");
    tor.set(
        "mode",
        or(at(nodes, "tor", "mode"), || at(&defaults, "tor", "mode")),
    );
    tor.set(
        "externalSocks",
        or(at(nodes, "tor", "externalSocks"), || JsValue::Null),
    );
    out.set("tor", tor);
    out
}

/// `{ ...defaults[name], ...(nodes[name] || {}) }`.
fn merged(defaults: &JsValue, nodes: &JsValue, name: &str) -> JsValue {
    let mut block = prop(defaults, name);
    let own = prop(nodes, name);
    if own.truthy() {
        spread(&mut block, &own);
    }
    block
}

/// An integer port `nodes` holds, or the default's.
fn port(nodes: &JsValue, defaults: &JsValue, name: &str, key: &str) -> JsValue {
    let own = at(nodes, name, key);
    if is_integer(&own) {
        own
    } else {
        at(defaults, name, key)
    }
}

/// `fillMissingNodeConfig(nodes, ports)`: what `nodes` holds, each field it
/// lacks (or holds out of form) from the ports' defaults.
pub fn fill_missing_node_config(nodes: &JsValue, ports: &Ports) -> JsValue {
    let defaults = build_node_config(ports);
    let mut out = object();

    let mut bee = merged(&defaults, nodes, "bee");
    bee.set(
        "mode",
        or(at(nodes, "bee", "mode"), || at(&defaults, "bee", "mode")),
    );
    bee.set("apiPort", port(nodes, &defaults, "bee", "apiPort"));
    bee.set("p2pPort", port(nodes, &defaults, "bee", "p2pPort"));
    bee.set(
        "externalApi",
        or(at(nodes, "bee", "externalApi"), || JsValue::Null),
    );
    out.set("bee", bee);

    let mut ipfs = merged(&defaults, nodes, "ipfs");
    ipfs.set(
        "mode",
        normalize_ipfs_mode(&at(nodes, "ipfs", "mode"), &at(&defaults, "ipfs", "mode")),
    );
    ipfs.set(
        "externalGateway",
        or(at(nodes, "ipfs", "externalGateway"), || JsValue::Null),
    );
    ipfs.set("backend", string("freedom-ipfs"));
    out.set("ipfs", ipfs);

    native_blocks(&mut out, nodes, &defaults);

    let mut tor = merged(&defaults, nodes, "tor");
    tor.set(
        "mode",
        or(at(nodes, "tor", "mode"), || at(&defaults, "tor", "mode")),
    );
    tor.set("socksPort", port(nodes, &defaults, "tor", "socksPort"));
    tor.set(
        "externalSocks",
        or(at(nodes, "tor", "externalSocks"), || JsValue::Null),
    );
    out.set("tor", tor);
    out
}

/// The slots `catalog.profiles` holds: integers from 0 up.
pub(crate) fn used_slots(profiles: &[JsValue]) -> Vec<f64> {
    profiles
        .iter()
        .filter_map(|record| match prop(record, "slot") {
            JsValue::Number(n) if js::is_integer(&JsValue::Number(n)) && n >= 0.0 => Some(n),
            _ => None,
        })
        .collect()
}

/// `allocateSlot(catalog, id)`: 0 for `default`, otherwise the lowest slot
/// from 1 that no record holds.
pub fn allocate_slot(profiles: &[JsValue], id: &str) -> f64 {
    if id == DEFAULT_PROFILE_ID {
        return 0.0;
    }
    let used = used_slots(profiles);
    let mut slot = 1.0;
    while used.contains(&slot) {
        slot += 1.0;
    }
    slot
}
