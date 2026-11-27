//! `ledger.accounts` and `ledger.add` (design 0016, "Accounts" and API;
//! LDG-2's L3), each one operation on the device lane ([`super::lane`]),
//! for the chrome or main.
//!
//! - **`ledger.accounts { scheme, start, count }`** → `{ accounts: [{ path,
//!   address }], mismatched: [{ index, name, address, path }] }`, as
//!   `ledger:get-accounts` today: 1 to 20 of the scheme's paths, display
//!   off, each address checked against its key (fc-ledger). Discovery
//!   doesn't wait: while an operation runs or waits it is `LEDGER_BUSY` at
//!   once (deviation `discovery-busy`).
//! - **Its check** (D1, decided 2026-11-26): after its discovery APDUs, in
//!   the same operation, `E0 02 00 00` at the path of each Ledger record no
//!   device has matched, as `account-checks.js` does: the core's own
//!   records ([`crate::accounts::Records::ledger_checks`], the loop's
//!   snapshot), at a scheme's path only (`path-strict`), at most 20, in the
//!   wallet list's order (`check-bound`). The core keeps each result on its
//!   record itself, through the accounts store on the vault's queue
//!   ([`crate::accounts::Op::LedgerChecked`]), and the records the device
//!   doesn't hold come back in `mismatched`. A failed check is logged and
//!   leaves `mismatched` empty; it never fails discovery (`ipc.js:24–33`):
//!   a status, main's `{ failed }` or refusal, or an answer the core can't
//!   read at one of its APDUs, the lane's own end of one (no answer by the
//!   core's timer, or an APDU that couldn't go), or a result the core can't
//!   keep. A cancel still ends it `cancelled`. Before `vault_meta` is moved
//!   the core keeps no result (D9: a Ledger record needs the store moved),
//!   so it reads none: discovery's APDUs alone, and `mismatched` empty.
//! - **`ledger.add { scheme, index, name? }`**: the address at that path,
//!   read with the display (`E0 02 01 00`, question 3), for the user to
//!   confirm on the device (deviation `address-from-device`). The address
//!   stored is the device's, never a caller's: the chrome sends none. Once
//!   `vault_meta` is moved the core writes the record through the accounts
//!   store (`addLedgerWallet`'s, `matched`) and answers `{ path, address,
//!   wallet }`, with `durable: false` where the write wasn't flushed; until
//!   then it answers `{ path, address }`, and main writes exactly those.
//! - **A device's failure** is `device_failed` with `data.ledger`, its
//!   `LEDGER_*` code (0016's API); a request the lane or fc-ledger refuses
//!   before its first APDU is `invalid_argument`. The parent's cancel ends
//!   it `cancelled`, wherever it is, its pending `shell.ledger_apdu`
//!   cancelled (the lane), or its write still queued (the vault).

use fc_evm::checksum_address;
use fc_json::JsValue;
use fc_ledger::{Account, Discovered, LedgerPath, Operation, Scheme, Signed};
use fc_protocol::error::{ErrorBody, ErrorCode};
use serde::Deserialize;
use serde_json::json;

use super::lane::{Ended, Outcome, Turn};
use crate::accounts::{LedgerCheck, Op};

/// The methods, in `core.hello`'s capability order.
pub const METHODS: &[&str] = &["ledger.accounts", "ledger.add"];

pub fn handles(method: &str) -> bool {
    METHODS.contains(&method)
}

/// What a parent does with its operation's end: the lane's `T`.
#[derive(Debug)]
pub enum Then {
    /// `ledger.accounts`: the records its check reads, in the order their
    /// paths go to the device; none when it reads none.
    Accounts { checks: Vec<LedgerCheck> },
    /// `ledger.add`: the record's name, and whether the core writes the
    /// record (`vault_meta` moved).
    Add { name: JsValue, moved: bool },
}

/// What the event loop does with an operation's end.
pub enum Finish {
    /// The parent's answer, now.
    Answer(u64, Result<serde_json::Value, ErrorBody>),
    /// The parent's answer once the accounts store has kept its result, on
    /// the vault's queue ([`crate::vault::Vault::ledger_end`]).
    Store(u64, Op),
}

/// Where the records discovery's check reads stand: none before
/// `vault_meta` is moved; the snapshot's, or why it can't be read.
pub type Records = Option<Result<Vec<LedgerCheck>, ErrorBody>>;

fn invalid() -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters")
}

/// `device_failed`, its code in `data.ledger` (design 0016, API).
pub fn device_failed(code: fc_ledger::LedgerCode) -> ErrorBody {
    ErrorBody::new(ErrorCode::DeviceFailed, "Ledger device failed")
        .with_data(json!({ "ledger": code.as_str() }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountsParams {
    scheme: String,
    start: u64,
    count: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddParams {
    scheme: String,
    index: u64,
    #[serde(default)]
    name: Option<String>,
}

/// A request's params, read strictly: an object of exactly its members.
fn params<'a, T: Deserialize<'a>>(raw: Option<&'a str>) -> Result<T, ErrorBody> {
    let raw = raw.unwrap_or("{}");
    // serde's derived structs would also take an array of the members.
    if !raw.trim_start().starts_with('{') {
        return Err(invalid());
    }
    serde_json::from_str(raw).map_err(|_| invalid())
}

fn scheme(text: &str) -> Result<Scheme, ErrorBody> {
    Scheme::parse(text).ok_or_else(invalid)
}

/// Request `method`'s operation, what its parent does with its end, and
/// how it takes its turn; or its refusal before any APDU. `records` is
/// where the records discovery checks stand, `moved` whether `vault_meta`
/// is.
pub fn start(
    method: &str,
    raw: Option<&str>,
    records: impl FnOnce() -> Records,
    moved: bool,
) -> Result<(Operation, Then, Turn), ErrorBody> {
    match method {
        "ledger.accounts" => {
            let p: AccountsParams = params(raw)?;
            // 1 to 20 of the scheme's paths (fc-ledger: `path-strict`).
            let operation =
                Operation::accounts(scheme(&p.scheme)?, p.start, p.count).map_err(|_| invalid())?;
            let checks = match records() {
                None => {
                    crate::log::info(
                        "discovery checks no Ledger record: vault_meta isn't moved",
                        json!({ "store": crate::accounts::STORE }),
                    );
                    Vec::new()
                }
                Some(Err(error)) => {
                    crate::log::warn(
                        "discovery checks no Ledger record: the records can't be read",
                        json!({ "code": error.code }),
                    );
                    Vec::new()
                }
                Some(Ok(checks)) => checks,
            };
            let paths = checks.iter().map(|check| check.at.clone()).collect();
            let operation = operation.checking(paths).map_err(|_| invalid())?;
            Ok((operation, Then::Accounts { checks }, Turn::Now))
        }
        "ledger.add" => {
            let p: AddParams = params(raw)?;
            let path = LedgerPath::new(scheme(&p.scheme)?, p.index).map_err(|_| invalid())?;
            let name = p.name.map_or(JsValue::Undefined, JsValue::string);
            Ok((Operation::add(path), Then::Add { name, moved }, Turn::Wait))
        }
        _ => Err(crate::vault::internal()),
    }
}

/// `{ path, address }`: the path as the schemes write it, the address
/// EIP-55-checksummed, as the device and `getAddress` give it.
fn account(account: &Account) -> serde_json::Value {
    json!({
        "path": account.path.to_string(),
        "address": checksum_address(&account.address),
    })
}

/// What an operation's end does for its parent.
pub fn finish(ended: Ended<Then>) -> Finish {
    let Ended {
        parent,
        then,
        outcome,
    } = ended;
    let signed = match outcome {
        Outcome::Cancelled => {
            return Finish::Answer(
                parent,
                Err(ErrorBody::new(ErrorCode::Cancelled, "Cancelled")),
            );
        }
        Outcome::Done(Ok(signed)) => signed,
        outcome => {
            if let Outcome::Done(Err(failure)) = &outcome {
                crate::log::warn(
                    "ledger operation failed",
                    json!({ "code": failure.code.as_str(), "cause": failure.cause.to_string() }),
                );
            }
            let code = outcome.code().unwrap_or(fc_ledger::LedgerCode::Unknown);
            return Finish::Answer(parent, Err(device_failed(code)));
        }
    };
    match (then, signed) {
        (Then::Accounts { checks }, Signed::Accounts(found)) => discovered(parent, checks, found),
        (Then::Add { name, moved }, Signed::Added(added)) => {
            let path = added.path.to_string();
            let address = checksum_address(&added.address);
            if moved {
                Finish::Store(
                    parent,
                    Op::LedgerAdd {
                        name,
                        path,
                        address,
                    },
                )
            } else {
                Finish::Answer(parent, Ok(json!({ "path": path, "address": address })))
            }
        }
        // An operation ends with its own kind of result.
        _ => Finish::Answer(parent, Err(crate::vault::internal())),
    }
}

/// Discovery's end: its accounts, and its check's results for the store
/// to keep; none to keep when it checked nothing or the check failed.
fn discovered(parent: u64, checks: Vec<LedgerCheck>, found: Discovered) -> Finish {
    let accounts: Vec<serde_json::Value> = found.accounts.iter().map(account).collect();
    let empty = || {
        Finish::Answer(
            parent,
            Ok(json!({ "accounts": accounts, "mismatched": [] })),
        )
    };
    if checks.is_empty() {
        return empty();
    }
    let held = match found.checks {
        Ok(held) if held.len() == checks.len() => held,
        Ok(_) => return empty(),
        Err(failure) => {
            crate::log::warn(
                "the Ledger record check failed: mismatched is empty",
                json!({ "code": failure.code.as_str(), "cause": failure.cause.to_string() }),
            );
            return empty();
        }
    };
    let listed = found
        .accounts
        .iter()
        .map(|a| {
            let mut out = JsValue::Object(Vec::new());
            out.set("path", JsValue::string(a.path.to_string()));
            out.set("address", JsValue::string(checksum_address(&a.address)));
            out
        })
        .collect();
    Finish::Store(
        parent,
        Op::LedgerChecked {
            accounts: JsValue::Array(listed),
            checks: checks.into_iter().zip(held).collect(),
        },
    )
}
