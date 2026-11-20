//! `vault-meta.json`'s methods, `accounts.*` (design 0013,
//! "`vault-meta.json`"; PRF-5c-1): one per change `identity-manager.js`
//! makes, each through `fc-wallet-state`'s codec, in the identity
//! directory beside the vault.
//!
//! - **One writer per store.** Until `core.hello` names `vault_meta` in
//!   `store_moved`, main writes the file. The reads are served from it as
//!   main left it: an unreadable file reads as missing and stays where it
//!   is, and `accounts.list`'s first-list default is answered but not
//!   written. Every write answers `not_moved` (`data.store`) at admission,
//!   and nothing is written, renamed or removed.
//! - **Once moved** the core writes it alone, by 0001's single-file write
//!   (`fc_store::file::write_file`; a test build fails a step with
//!   `vault_meta:<step>` in `FREEDOM_CORED_TEST_GRANT_WRITE_FAIL`). It is
//!   read at each request. An unreadable file is renamed aside
//!   (`vault-meta.json.unreadable`) and logged, and the store reads as no
//!   file (`vault-meta-unreadable`); if the rename fails, the request fails
//!   `storage` and nothing writes the file. The core's temp files a crash
//!   left are removed when the store is named.
//! - **The vault queue.** Each request queues behind the vault's jobs, so it
//!   serializes with `vault.create` and `vault.import`, and runs on the
//!   event loop once it reaches the head: the loop holds the lock state the
//!   addresses are derived from, and the Safe approvals and dApp grants
//!   `accounts.remove` ends. The file's reads and writes run there, as 0012's
//!   grant files' do.
//! - **Refusals** are the reference's: `invalid_argument` with its message,
//!   and its `err.code` as `data.code` where it sets one.
//! - **A failed write** (the temp file's write, its fsync, the rename) is
//!   `storage` (`data.file: "vault_meta"`), and the file is as it was. A
//!   failed directory flush after the rename answers the change with
//!   `durable: false`.
//! - **`accounts.remove`:** the refusals, a Swarm feed's among them from
//!   main's `swarm_references`; for a Safe, every open Safe approval for
//!   its address ended (its `safe-pending.json` entry is main's until
//!   `safe_pending` moves, PRF-5f); the account's dApp grants forgotten, as
//!   `approval.forget_account` forgets them; then the record removed. The
//!   forget comes before the record, where the reference forgets after and
//!   logs a failure (0013's `accounts-remove-forget-first`): a removed index
//!   is handed out again, so a grant left in the file would be the next
//!   account's after a restart. A forget that fails, `not_moved` for the
//!   dApp file included, refuses the removal with the account still there.
//!   The answer is `durable: false` if either write wasn't.

use std::path::PathBuf;

use fc_json::JsValue;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_store::file::{Read, read_file, set_aside, write_file};
use fc_store::fsx::{self, Done};
use fc_vault::state::VaultState;
use fc_wallet_state::vault_meta::{self, Device, Failed, Refusal, SafeParams, VaultMeta};
use serde_json::json;

use crate::approvals::Approvals;
use crate::testhooks::GrantWrite;

/// The store's name in `store_moved`, `not_moved`'s `data.store`, a
/// storage error's `data.file`, and the write hook's.
pub const STORE: &str = "vault_meta";

/// The methods, in `core.hello`'s capability order.
pub const METHODS: &[&str] = &[
    "accounts.list",
    "accounts.meta",
    "accounts.active",
    "accounts.add_mnemonic",
    "accounts.add_ledger",
    "accounts.add_remote",
    "accounts.record_address_check",
    "accounts.add_safe",
    "accounts.mark_safe_deployed",
    "accounts.set_active",
    "accounts.rename",
    "accounts.remove",
];

/// The methods served before the store is named: reads that write nothing
/// then.
const READS: &[&str] = &["accounts.list", "accounts.meta", "accounts.active"];

/// What a request asks, its parameters checked at admission.
pub enum Op {
    List,
    Meta,
    Active,
    AddMnemonic {
        name: JsValue,
    },
    AddLedger {
        name: JsValue,
        address: JsValue,
        path: JsValue,
    },
    AddRemote {
        name: JsValue,
        address: JsValue,
    },
    RecordAddressCheck {
        device: Device,
        index: f64,
        matched: bool,
    },
    AddSafe {
        name: JsValue,
        address: JsValue,
        owners: JsValue,
        threshold: JsValue,
        salt_nonce: JsValue,
    },
    MarkSafeDeployed {
        index: f64,
        chain_id: f64,
    },
    SetActive {
        index: f64,
    },
    Rename {
        index: f64,
        name: JsValue,
    },
    Remove {
        index: f64,
        /// The origins of the Swarm feeds main found naming the account.
        swarm_origins: Vec<String>,
    },
}

impl Op {
    fn writes(&self) -> bool {
        !matches!(self, Op::List | Op::Meta | Op::Active)
    }
}

/// `vault-meta.json` in the identity directory, and whether it is moved.
pub struct Store {
    dir: PathBuf,
    moved: bool,
}

fn invalid() -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters")
}

fn not_moved() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::NotMoved,
        "main still writes vault-meta.json (vault_meta isn't in store_moved)",
    )
    .with_data(json!({ "store": STORE }))
}

pub(crate) fn storage(kind: &str) -> ErrorBody {
    ErrorBody::new(ErrorCode::Storage, "Storage error")
        .with_data(json!({ "kind": kind, "file": STORE }))
}

/// The reference's error: its message, and its code where it sets one.
fn refused(refusal: Refusal) -> ErrorBody {
    let body = ErrorBody::new(ErrorCode::InvalidArgument, refusal.message);
    match refusal.code {
        Some(code) => body.with_data(json!({ "code": code })),
        None => body,
    }
}

/// The request's members: an object holding only `allowed`, each with any
/// JSON value.
fn members(raw: Option<&str>, allowed: &[&str]) -> Result<JsValue, ErrorBody> {
    let value = fc_json::parse(raw.unwrap_or("{}")).map_err(|_| invalid())?;
    match &value {
        JsValue::Object(props) if props.iter().all(|(k, _)| allowed.iter().any(|a| k == *a)) => {
            Ok(value)
        }
        _ => Err(invalid()),
    }
}

/// A member as given, `undefined` when absent (`createDerivedWallet(name)`
/// called without one): the codec refuses what the reference refuses
/// (a missing address or path, a Safe's owners).
fn any(params: &JsValue, key: &str) -> JsValue {
    params.get(key).cloned().unwrap_or(JsValue::Undefined)
}

fn number(params: &JsValue, key: &str) -> Result<f64, ErrorBody> {
    match params.get(key) {
        Some(JsValue::Number(n)) => Ok(*n),
        _ => Err(invalid()),
    }
}

/// `swarm_references`: the references main's feed store found, each an
/// object with its `origin`.
fn origins(params: &JsValue) -> Result<Vec<String>, ErrorBody> {
    let references = params
        .get("swarm_references")
        .and_then(JsValue::as_array)
        .ok_or_else(invalid)?;
    references
        .iter()
        .map(|reference| {
            reference
                .get("origin")
                .and_then(JsValue::as_js_string)
                .map(|origin| origin.to_string())
                .ok_or_else(invalid)
        })
        .collect()
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Store { dir, moved: false }
    }

    /// The hello's `store_moved` named `vault_meta`: the core writes the
    /// file from now on. The core's temp files a crash left are removed.
    pub fn configure_moved(&mut self) {
        self.moved = true;
        if let Err(e) = fsx::remove_temps(&self.dir, vault_meta::FILE_NAME) {
            crate::log::warn(
                "cannot remove vault-meta.json's temp files",
                json!({ "kind": crate::secrets::io_kind(&e) }),
            );
        }
    }

    /// Whether the hello named `vault_meta`.
    pub fn moved(&self) -> bool {
        self.moved
    }

    /// `afterUnlock`'s migration, once moved: a file without `addresses`
    /// gains the unlock's (design 0013, "The unlock's migration"). A failed
    /// write doesn't fail the unlock: it is logged, and the next unlock
    /// tries again (`vault-meta-unlock-migration`).
    pub fn migrate_unlock(&self, addresses: &crate::vault::Addresses) {
        if !self.moved {
            return;
        }
        let migrated = self.load().and_then(|mut meta| {
            let changed = meta.migrate_addresses(&addresses.user_wallet, &addresses.bee_wallet);
            if changed.wrote {
                self.save(&meta).map(|_| ())
            } else {
                Ok(())
            }
        });
        if let Err(error) = migrated {
            crate::log::warn(
                "the unlock's vault-meta.json migration failed; the next unlock tries again",
                json!({ "error": error.message }),
            );
        }
    }

    /// A request's operation, at admission: every write `not_moved` until
    /// the store is named, the parameters checked.
    pub fn op(&self, method: &str, raw: Option<&str>) -> Result<Op, ErrorBody> {
        if !self.moved && !READS.contains(&method) {
            return Err(not_moved());
        }
        Ok(match method {
            "accounts.list" | "accounts.meta" | "accounts.active" => {
                members(raw, &[])?;
                match method {
                    "accounts.list" => Op::List,
                    "accounts.meta" => Op::Meta,
                    _ => Op::Active,
                }
            }
            "accounts.add_mnemonic" => {
                let p = members(raw, &["name"])?;
                Op::AddMnemonic {
                    name: any(&p, "name"),
                }
            }
            "accounts.add_ledger" => {
                let p = members(raw, &["name", "address", "path"])?;
                Op::AddLedger {
                    name: any(&p, "name"),
                    address: any(&p, "address"),
                    path: any(&p, "path"),
                }
            }
            "accounts.add_remote" => {
                let p = members(raw, &["name", "address"])?;
                Op::AddRemote {
                    name: any(&p, "name"),
                    address: any(&p, "address"),
                }
            }
            "accounts.record_address_check" => {
                let p = members(raw, &["type", "index", "matched"])?;
                let device = match p.get("type").and_then(JsValue::as_str) {
                    Some("ledger") => Device::Ledger,
                    Some("remote") => Device::Remote,
                    _ => return Err(invalid()),
                };
                let matched = match p.get("matched") {
                    Some(JsValue::Bool(matched)) => *matched,
                    _ => return Err(invalid()),
                };
                Op::RecordAddressCheck {
                    device,
                    index: number(&p, "index")?,
                    matched,
                }
            }
            "accounts.add_safe" => {
                let p = members(
                    raw,
                    &["name", "address", "owners", "threshold", "salt_nonce"],
                )?;
                Op::AddSafe {
                    name: any(&p, "name"),
                    address: any(&p, "address"),
                    owners: any(&p, "owners"),
                    threshold: any(&p, "threshold"),
                    salt_nonce: any(&p, "salt_nonce"),
                }
            }
            "accounts.mark_safe_deployed" => {
                let p = members(raw, &["index", "chain_id"])?;
                Op::MarkSafeDeployed {
                    index: number(&p, "index")?,
                    chain_id: number(&p, "chain_id")?,
                }
            }
            "accounts.set_active" => {
                let p = members(raw, &["index"])?;
                Op::SetActive {
                    index: number(&p, "index")?,
                }
            }
            "accounts.rename" => {
                let p = members(raw, &["index", "name"])?;
                Op::Rename {
                    index: number(&p, "index")?,
                    name: any(&p, "name"),
                }
            }
            "accounts.remove" => {
                let p = members(raw, &["index", "swarm_references"])?;
                Op::Remove {
                    index: number(&p, "index")?,
                    swarm_origins: origins(&p)?,
                }
            }
            _ => return Err(crate::vault::internal()),
        })
    }

    fn path(&self) -> PathBuf {
        self.dir.join(vault_meta::FILE_NAME)
    }

    /// The file as it stands. An unreadable one reads as no file; once
    /// moved it is renamed aside first, and a failed rename fails the
    /// request.
    fn load(&self) -> Result<VaultMeta, ErrorBody> {
        let reason = match read_file(&self.path(), vault_meta::MAX_FILE_BYTES) {
            Read::Missing => return Ok(VaultMeta::none()),
            Read::Bytes(bytes) => match VaultMeta::load(&bytes) {
                Ok(meta) => return Ok(meta),
                Err(unreadable) => unreadable.reason(),
            },
            Read::Unreadable => "unreadable_file",
        };
        if !self.moved {
            return Ok(VaultMeta::none());
        }
        let renamed = set_aside(&self.dir, vault_meta::FILE_NAME);
        crate::log::warn(
            "vault-meta.json can't be read: renamed aside",
            json!({ "reason": reason, "renamed": renamed.is_ok() }),
        );
        match renamed {
            Ok(_) => Ok(VaultMeta::none()),
            Err(e) => Err(storage(crate::secrets::io_kind(&e))),
        }
    }

    /// Writes the file: whether the change is durable.
    fn save(&self, meta: &VaultMeta) -> Result<bool, ErrorBody> {
        if !self.moved {
            return Err(not_moved());
        }
        let text = meta.text().ok_or_else(crate::vault::internal)?;
        match write_file(&self.path(), text.as_bytes(), &GrantWrite(STORE)) {
            Ok(Done::Durable) => Ok(true),
            Ok(Done::NotDurable) => {
                crate::log::warn("vault-meta.json isn't flushed", json!({}));
                Ok(false)
            }
            Err(e) => {
                crate::log::error(
                    "vault-meta.json's write failed",
                    json!({ "kind": crate::secrets::io_kind(&e) }),
                );
                Err(storage(crate::secrets::io_kind(&e)))
            }
        }
    }

    /// Runs `op` on the event loop: its answer, an object. `state` is the
    /// vault's lock state; `approvals` holds the Safe approvals and the
    /// dApp grants `accounts.remove` ends.
    pub fn run(
        &self,
        op: Op,
        state: &VaultState,
        approvals: &mut Approvals,
    ) -> Result<JsValue, ErrorBody> {
        if op.writes() && !self.moved {
            return Err(not_moved());
        }
        let mut meta = self.load()?;
        let mut answer = JsValue::Object(Vec::new());
        let wrote = match op {
            Op::Meta => {
                answer.set("meta", meta.value().cloned().unwrap_or(JsValue::Null));
                false
            }
            Op::Active => {
                answer.set("index", JsValue::Number(meta.active_index()));
                false
            }
            Op::List => {
                let listed = meta.list(|indices| derive_all(state, indices))?;
                answer.set("wallets", JsValue::Array(listed.value));
                // Before the move the default is answered, not written.
                listed.wrote && self.moved
            }
            Op::AddMnemonic { name } => {
                let changed = meta
                    .add_mnemonic(state.is_unlocked(), &name, |index| derive_one(state, index))
                    .map_err(|failed| match failed {
                        Failed::Refused(refusal) => refused(refusal),
                        Failed::Derive(body) => body,
                    })?;
                answer.set("wallet", changed.value);
                changed.wrote
            }
            Op::AddLedger {
                name,
                address,
                path,
            } => {
                let changed = meta.add_ledger(&name, &address, &path).map_err(refused)?;
                answer.set("wallet", changed.value);
                changed.wrote
            }
            Op::AddRemote { name, address } => {
                let changed = meta.add_remote(&name, &address).map_err(refused)?;
                answer.set("wallet", changed.value);
                changed.wrote
            }
            Op::RecordAddressCheck {
                device,
                index,
                matched,
            } => {
                let changed = meta.record_address_check(device, index, matched);
                answer.set(
                    "address_check",
                    changed.value.map_or(JsValue::Null, JsValue::string),
                );
                changed.wrote
            }
            Op::AddSafe {
                name,
                address,
                owners,
                threshold,
                salt_nonce,
            } => {
                let params = SafeParams {
                    address: &address,
                    owners: &owners,
                    threshold: &threshold,
                    salt_nonce: &salt_nonce,
                };
                let changed = meta.add_safe(&name, params).map_err(refused)?;
                answer.set("wallet", changed.value);
                changed.wrote
            }
            Op::MarkSafeDeployed { index, chain_id } => {
                meta.mark_safe_deployed(index, chain_id)
                    .map_err(refused)?
                    .wrote
            }
            Op::SetActive { index } => meta.set_active(index).map_err(refused)?.wrote,
            Op::Rename { index, name } => meta.rename(index, &name).map_err(refused)?.wrote,
            Op::Remove {
                index,
                swarm_origins,
            } => return self.remove(meta, index, &swarm_origins, approvals),
        };
        if wrote && !self.save(&meta)? {
            answer.set("durable", JsValue::Bool(false));
        }
        Ok(answer)
    }

    /// `accounts.remove`: the refusals; a Safe's approvals ended before
    /// its record goes ("cleanup precedes the meta write"); the account's
    /// dApp grants forgotten, a failure refusing the removal; the record
    /// removed. `durable: false` if either write wasn't.
    fn remove(
        &self,
        mut meta: VaultMeta,
        index: f64,
        swarm_origins: &[String],
        approvals: &mut Approvals,
    ) -> Result<JsValue, ErrorBody> {
        let removal = meta.check_remove(index, swarm_origins).map_err(refused)?;
        if removal.safe {
            let address = meta
                .record(index)
                .and_then(|record| record.get("address").and_then(address_bytes));
            match address {
                Some(safe) => {
                    approvals.end_safe_approvals(&safe);
                }
                None => crate::log::warn(
                    "a removed Safe's address isn't hex: no approval ended",
                    json!({}),
                ),
            }
        }
        // The grants before the record (`accounts-remove-forget-first`): a
        // forget that didn't reach the file refuses the removal, so no
        // grant outlives its account to be the next one's at that index. A
        // later failed write leaves the account there, disconnected. An
        // index past `u32` is none a grant can name (`approval.connect`'s
        // account), and has nothing to forget.
        let mut durable = match account_index(index) {
            Some(account) => approvals.forget_removed_account(account)?,
            None => true,
        };
        let changed = meta.remove(index, swarm_origins).map_err(refused)?;
        if changed.wrote {
            durable &= self.save(&meta)?;
        }
        let mut answer = JsValue::Object(Vec::new());
        if !durable {
            answer.set("durable", JsValue::Bool(false));
        }
        Ok(answer)
    }
}

/// An index as an account number: a non-negative integer that fits.
fn account_index(index: f64) -> Option<u32> {
    (index.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&index)).then_some(index as u32)
}

/// A record's address as 20 bytes: `0x` and 40 hex digits, or the 40
/// digits alone (an address `isAddress` took without its prefix).
fn address_bytes(address: &JsValue) -> Option<[u8; 20]> {
    let text = address.as_str()?;
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    if digits.len() != 40 {
        return None;
    }
    let mut bytes = [0u8; 20];
    for (byte, pair) in bytes.iter_mut().zip(digits.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(bytes)
}

/// User wallet `index`'s address, as `keys.addresses` answers it.
fn address_of(state: &VaultState, index: f64) -> Result<String, ErrorBody> {
    // An index `keys.addresses` wouldn't take is its `invalid_argument`.
    let account = account_index(index).ok_or_else(invalid)?;
    let key = state
        .user_wallet(account)
        .map_err(|_| crate::vault::internal())?;
    Ok(key.address().to_string())
}

/// `deriveAddresses({ accounts })`: none while the vault is locked.
fn derive_all(
    state: &VaultState,
    indices: &[f64],
) -> Result<Option<Vec<(f64, String)>>, ErrorBody> {
    if !state.is_unlocked() {
        return Ok(None);
    }
    indices
        .iter()
        .map(|index| Ok((*index, address_of(state, *index)?)))
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// One index's address, or none while the vault is locked.
fn derive_one(state: &VaultState, index: f64) -> Result<Option<String>, ErrorBody> {
    if !state.is_unlocked() {
        return Ok(None);
    }
    address_of(state, index).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_index_is_an_account_only_when_it_fits() {
        assert_eq!(account_index(0.0), Some(0));
        assert_eq!(account_index(1_000_000.0), Some(1_000_000));
        assert_eq!(account_index(f64::from(u32::MAX)), Some(u32::MAX));
        assert_eq!(account_index(f64::from(u32::MAX) + 1.0), None);
        assert_eq!(account_index(-1.0), None);
        assert_eq!(account_index(0.5), None);
    }

    #[test]
    fn a_records_address_as_bytes() {
        let mut expected = [0u8; 20];
        expected[19] = 0xab;
        let hex = "000000000000000000000000000000000000aB";
        for text in [
            format!("0x00{hex}"),
            format!("0X00{hex}"),
            format!("00{hex}"),
        ] {
            assert_eq!(
                address_bytes(&JsValue::string(text.as_str())),
                Some(expected)
            );
        }
        for bad in [
            "0x12",
            "XE26QURMT0JTHRKRVCUYL99VJZODRSZWBMT",
            "0xzz00000000000000000000000000000000000000",
        ] {
            assert_eq!(address_bytes(&JsValue::string(bad)), None, "{bad}");
        }
        assert_eq!(address_bytes(&JsValue::Number(1.0)), None);
    }
}
