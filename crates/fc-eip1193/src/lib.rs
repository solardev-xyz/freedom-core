//! The Ethereum dispatcher in the core (design 0012, "fc-eip1193 and
//! approval.request"): a page's EIP-1193 request, run by the core rather
//! than by main's `src/main/page/` (design 0011).
//!
//! A logic crate: a sans-I/O machine like `fc-chain`'s, with time passed in
//! (AGENTS rule 2). The daemon (`freedom-cored`) reads the grant files, runs
//! the chain reads on its own chain machine (design 0005) and writes the
//! replies; this crate decides what each request asks and answers.
//!
//! **APR-5b, the reads:** `eth_chainId`, `net_version`, `eth_accounts` and
//! the 23 read-only methods, as the approvals reference's `page-ethereum.js`
//! (`7f85551d`) answers them, recorded in `vectors/eip1193.json`:
//!
//! - **Every method** answers `4900` (`Disconnected`) while the Identity &
//!   Wallet switch is off.
//! - **`eth_chainId` and `net_version`:** an onchain app's own chain, or
//!   else the chain its window selected, or else Gnosis.
//! - **`eth_accounts`:** the account the key's dApp grant exposes, from
//!   main's wallet list, or `[]`. A document with no key gets `[]` and
//!   reads no grant.
//! - **The other reads:** one read through the core's chain machine, on the
//!   same chain, with the key as its routing hint (`origin`). Its failure
//!   answers as the reference's `readError` makes it: the error's own
//!   `code`, or `-32603` for none or a falsy one (a node's code `0`
//!   included); its own message, or `All chain sources failed for chain
//!   <id>` for none or an empty one; its `data` when it has one; and for a
//!   chain the registry has no source for, the chrome's text instead.
//!
//! The later APR-5 steps add the prompts, connects and chain switches
//! (APR-5c), signatures (APR-5d), the prepared send (APR-5e) and names over
//! IPNS (APR-5f). Until then, those methods answer as a dispatcher without
//! their route does (`4200`, `Method not supported`), but `4900` while the
//! switch is off.

mod answer;
mod deadline;
mod methods;
mod request;

pub use answer::{Answer, Failure, Read, ReadOutcome};
pub use deadline::{Budget, OVERALL_MS};
pub use methods::{Class, METHODS, Method, RPC_READS, method};
pub use request::{Invalid, Request, World};

use fc_json::JsValue;

/// What the chrome's `getCurrentChainId` falls back to: Gnosis.
pub const FALLBACK_CHAIN_ID: u64 = 100;

/// What a request does next.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// It is answered: `{ result }` or `{ error }`.
    Answer(Answer),
    /// It reads through the core's chain machine, and [`Read::answer`]
    /// answers it from the read's outcome.
    Read(Read),
}

/// Runs `request` for the document keyed `key` (`PageContext.origin`;
/// `None` for a document with no key). `grant` gives the key's entry in
/// the dApp store (`getPermission`), as its file holds it; it is asked only
/// by a method that reads it.
pub fn start(
    request: &Request,
    key: Option<&str>,
    grant: impl FnOnce(&str) -> Option<JsValue>,
) -> Step {
    let Some(row) = method(&request.method) else {
        return Step::Answer(Answer::unsupported());
    };
    if let Some(refusal) = row.refusal {
        return Step::Answer(Answer::error(refusal.0, refusal.1));
    }
    let world = &request.world;
    if !world.enabled {
        return Step::Answer(Answer::disconnected());
    }
    let chain_id = world.chain_id();
    match row.name {
        "eth_chainId" => Step::Answer(Answer::result(&JsValue::string(format!("0x{chain_id:x}")))),
        "net_version" => Step::Answer(Answer::result(&JsValue::string(chain_id.to_string()))),
        "eth_accounts" => Step::Answer(Answer::result(&accounts(world, key, grant))),
        name if RPC_READS.contains(&name) => Step::Read(Read::new(
            chain_id,
            row.name,
            request.read_params(),
            key,
            world,
        )),
        // APR-5c to APR-5e serve the rest.
        _ => Step::Answer(Answer::unsupported()),
    }
}

/// `eth_accounts`: the account the key's grant exposes, as main's wallet
/// list gives its address, or `[]`.
fn accounts(
    world: &World,
    key: Option<&str>,
    grant: impl FnOnce(&str) -> Option<JsValue>,
) -> JsValue {
    let none = || JsValue::Array(Vec::new());
    let Some(key) = key else {
        return none();
    };
    // `getPermission(key)`: `permissions[key] || null`.
    let Some(permission) = grant(key).filter(JsValue::truthy) else {
        return none();
    };
    let undefined = JsValue::Undefined;
    let wanted = permission.get("walletIndex").unwrap_or(&undefined);
    // `wallets.find((candidate) => candidate?.index === permission.walletIndex)`.
    let found = world.wallets().iter().find(|candidate| {
        let index = match candidate {
            JsValue::Null | JsValue::Undefined => &undefined,
            candidate => candidate.get("index").unwrap_or(&undefined),
        };
        strictly_equal(index, wanted)
    });
    match found {
        // `if (!wallet) return []`: a nullish candidate found by an absent
        // `walletIndex` is no wallet.
        Some(wallet) if wallet.truthy() => {
            let address = wallet.get("address").cloned().unwrap_or(JsValue::Undefined);
            // `[undefined]` is written `[null]`, as JSON.stringify writes it.
            JsValue::Array(vec![address])
        }
        _ => none(),
    }
}

/// JS's `a === b` for parsed JSON: primitives by value, and an object or
/// array never equal to anything else (no two are the same object).
fn strictly_equal(a: &JsValue, b: &JsValue) -> bool {
    match (a, b) {
        (JsValue::Undefined, JsValue::Undefined) | (JsValue::Null, JsValue::Null) => true,
        (JsValue::Bool(a), JsValue::Bool(b)) => a == b,
        (JsValue::Number(a), JsValue::Number(b)) => a == b,
        (JsValue::String(a), JsValue::String(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_equality_is_javascripts() {
        let n = |v: f64| JsValue::Number(v);
        assert!(strictly_equal(&n(0.0), &n(-0.0)));
        assert!(!strictly_equal(&n(0.0), &JsValue::string("0")));
        assert!(strictly_equal(&JsValue::Undefined, &JsValue::Undefined));
        assert!(!strictly_equal(&JsValue::Null, &JsValue::Undefined));
        assert!(!strictly_equal(
            &JsValue::Array(Vec::new()),
            &JsValue::Array(Vec::new())
        ));
    }
}
