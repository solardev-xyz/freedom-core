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
//! **APR-5c, the prompts** ([`prompt`]): the core asks main for each
//! prompt with its own `approval.request`, under an id it never reuses, and
//! takes only main's decision on that prompt, on a handle no earlier answer
//! named. `eth_requestAccounts` goes through it ([`connect`]): a document
//! with no key gets `4100` before any of it, and a grant is written only
//! from an approve's `choices`.
//!
//! **APR-5c-2, the chain switch** ([`switch`]): `wallet_switchEthereumChain`
//! opens no prompt, as in the reference. Past its checks, main rechecks the
//! document, the key's grant takes the chain, and main selects it for the
//! window. `wallet_addEthereumChain` isn't in main's table: `4200`.
//!
//! **APR-5d-1, signatures** ([`sign`]): `personal_sign` and
//! `eth_signTypedData_v4` for a vault account, through `eth.sign`. A
//! document with no key gets `4100` first. On an approve the daemon mints
//! the page-kind token itself, for that answer's page and handle, and
//! spends it on the signature at once: the token never leaves the core.
//! Standing rules, Q9 and devices' `{ device }` results are APR-5d-2's.
//!
//! **APR-5f, names over IPNS** ([`names`]): for a document whose key is a
//! DNS name served over IPNS (`PageContext.transport_key`), the daemon
//! resolves the name with the core's own naming at each of the reference's
//! checks of a name-revalidated method, and a name that no longer answers
//! its IPNS key ends the binding: the request, and the document's later
//! ones, answer as a keyless document's would.
//!
//! The prepared send (APR-5e) comes later. Until then, `eth_sendTransaction`
//! answers as a dispatcher without its route does (`4200`, `Method not
//! supported`), but `4900` while the switch is off.

mod answer;
pub mod connect;
mod deadline;
mod methods;
pub mod names;
pub mod prompt;
mod request;
pub mod sign;
pub mod switch;
mod v8json;

pub use answer::{Answer, Failure, Read, ReadOutcome};
pub use connect::Connect;
pub use deadline::{Budget, OVERALL_MS};
pub use methods::{Class, METHODS, Method, RPC_READS, method};
pub use prompt::{Crossed, Decision, PromptId, Prompts, Recheck};
pub use request::{Invalid, Request, World};
pub use sign::Sign;
pub use switch::Switch;

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
    /// A connect (`eth_requestAccounts`) for a document with a key: a
    /// recheck or a prompt to main first.
    Connect(Connect),
    /// A chain switch past its checks (`wallet_switchEthereumChain`):
    /// main's recheck, the grant's chain, and main's selection.
    Switch(Switch),
    /// A signature (`personal_sign`, `eth_signTypedData_v4`) for a document
    /// with a key: [`Sign::ask`] runs it up to its prompt.
    Sign(Sign),
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
        // A document with no key: before any grant, recheck or prompt.
        "eth_requestAccounts" => match key {
            None => Step::Answer(Answer::error(connect::NO_ADDRESS.0, connect::NO_ADDRESS.1)),
            Some(key) => Step::Connect(connect::start(world, key, grant)),
        },
        "wallet_switchEthereumChain" => match key {
            None => Step::Answer(Answer::error(connect::NO_ADDRESS.0, connect::NO_ADDRESS.1)),
            Some(_) => match switch::start(request) {
                Ok(switch) => Step::Switch(switch),
                Err(answer) => Step::Answer(answer),
            },
        },
        name if sign::Method::of(name).is_some() => match (key, sign::Method::of(name)) {
            (Some(key), Some(method)) => Step::Sign(Sign::new(request, method, key)),
            _ => Step::Answer(Answer::error(connect::NO_ADDRESS.0, connect::NO_ADDRESS.1)),
        },
        name if RPC_READS.contains(&name) => Step::Read(Read::new(
            chain_id,
            row.name,
            request.read_params(),
            key,
            world,
        )),
        // APR-5e serves the rest.
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
pub(crate) fn strictly_equal(a: &JsValue, b: &JsValue) -> bool {
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
