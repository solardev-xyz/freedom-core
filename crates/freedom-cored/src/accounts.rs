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
//!   its address ended, then its `safe-pending.json` entry cleared once
//!   `safe_pending` is moved (main's until then, which clears it after the
//!   answer); the account's dApp grants forgotten, as
//!   `approval.forget_account` forgets them; then the record removed. The
//!   forget comes before the record, where the reference forgets after and
//!   logs a failure (0013's `accounts-remove-forget-first`): a removed index
//!   is handed out again, so a grant left in the file would be the next
//!   account's after a restart. A forget that fails, `not_moved` for the
//!   dApp file included, refuses the removal with the account still there,
//!   and so does a clear that fails once `safe_pending` is moved. The
//!   answer is `durable: false` if any of the writes wasn't.
//! - **The core's own checks** (G20; 0013's "the core's own checks (0012)
//!   need to know an account's type"): once moved, [`Records`], the
//!   loop's snapshot of the file, gives an account's kind and address for
//!   `approval.issue`'s `phone`,
//!   `approval.check`'s `account_kind`, `x402.authorize`'s `device` and
//!   `phone.job`'s `address`, which refuse a claim that disagrees. Before
//!   the move main owns the file, and its word stands there, as before.

use std::path::PathBuf;

use fc_approval::standing::AccountKind;
use fc_json::JsValue;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_store::file::{Read, read_file, set_aside, write_file};
use fc_store::fsx::{self, Done};
use fc_vault::state::VaultState;
use fc_wallet_state::value_address_bytes;
use fc_wallet_state::vault_meta::{self, Device, Failed, Refusal, SafeParams, VaultMeta};
use serde_json::json;

use crate::approvals::Approvals;
use crate::safe_pending::{self, SafePending};
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

    /// The records' snapshot for the core's own checks (G20), once moved:
    /// the file as it stands, read and never written. The loop takes it
    /// where no vault job is running ([`Records`]).
    pub fn snapshot(&self) -> Option<Records> {
        if !self.moved {
            return None;
        }
        // While a vault journal remains the file may be a replaced vault's.
        if !matches!(crate::vault_meta_journal::remaining(&self.dir), Ok(false)) {
            return Some(Records::Pending);
        }
        let meta = match read_file(&self.path(), vault_meta::MAX_FILE_BYTES) {
            Read::Bytes(bytes) => VaultMeta::load(&bytes).unwrap_or_else(|_| VaultMeta::none()),
            Read::Missing | Read::Unreadable => VaultMeta::none(),
        };
        Some(Records::Read(meta))
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
    /// dApp grants `accounts.remove` ends, and `pending` the Safe entries
    /// it clears.
    pub fn run(
        &self,
        op: Op,
        state: &VaultState,
        approvals: &mut Approvals,
        pending: &SafePending,
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
            } => return self.remove(meta, index, &swarm_origins, approvals, pending),
        };
        if wrote && !self.save(&meta)? {
            answer.set("durable", JsValue::Bool(false));
        }
        Ok(answer)
    }

    /// `accounts.remove`: the refusals; a Safe's approvals ended and its
    /// pending entry cleared before its record goes ("cleanup precedes the
    /// meta write"); the account's dApp grants forgotten; the record
    /// removed. A failed clear or forget refuses the removal.
    /// `durable: false` if any write wasn't.
    fn remove(
        &self,
        mut meta: VaultMeta,
        index: f64,
        swarm_origins: &[String],
        approvals: &mut Approvals,
        pending: &SafePending,
    ) -> Result<JsValue, ErrorBody> {
        let removal = meta.check_remove(index, swarm_origins).map_err(refused)?;
        let mut durable = true;
        if removal.safe {
            let address = meta
                .record(index)
                .and_then(|record| record.get("address").and_then(value_address_bytes));
            match address {
                Some(safe) => {
                    approvals.end_safe_approvals(&safe);
                }
                // No Safe approval names an address of more than 20 bytes
                // (an ICAP past 2^160): there is none to end, as the
                // reference's lookup by address finds none.
                None => crate::log::warn(
                    "a removed Safe's address isn't one of 20 bytes: no approval ended",
                    json!({}),
                ),
            }
            durable &= clear_pending(pending, index)?;
        }
        // The grants before the record (`accounts-remove-forget-first`): a
        // forget that didn't reach the file refuses the removal, so no
        // grant outlives its account to be the next one's at that index. A
        // later failed write leaves the account there, disconnected. An
        // index past `u32` is none a grant can name (`approval.connect`'s
        // account), and has nothing to forget.
        durable &= match account_index(index) {
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

/// What the core's own record says account `index` is (G20), for the
/// checks that took main's word on it while main owned `vault-meta.json`:
/// the reference's `getSigner` and `paymentDevice` read the same record.
/// The kind is the record's `type` alone, as theirs is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Account {
    /// A mnemonic record, or no record below the hardware range: the
    /// vault's key at the index, as `getSigner` falls through to it.
    Vault,
    /// A Ledger's record, and its address as ethers' `getAddress` gives it
    /// ([`fc_wallet_state::normalize_address`]); none if it isn't one, and
    /// then no claimed address agrees with it.
    Ledger(Option<String>),
    /// A phone's (`remote`) record, and its address, as a Ledger's.
    Phone(Option<String>),
    /// A Safe's record: it has no key of its own.
    Safe,
    /// None the core can name: no record at a hardware index (a deleted
    /// device's, where the vault would derive a key the user never saw), or
    /// a type the core doesn't know. Every check refuses it.
    Unknown,
}

impl Account {
    /// `approval.check`'s `account_kind` for it (main's `ACCOUNT_KINDS`),
    /// or none.
    pub fn kind(&self) -> Option<AccountKind> {
        match self {
            Account::Vault => Some(AccountKind::Vault),
            Account::Ledger(_) => Some(AccountKind::Ledger),
            Account::Phone(_) => Some(AccountKind::Phone),
            Account::Safe => Some(AccountKind::Safe),
            Account::Unknown => None,
        }
    }
}

/// Account `index` as `meta` records it (`getWalletRecord(index)`,
/// normalized: index 0's address falls back to `addresses.userWallet`).
pub fn account_of(meta: &VaultMeta, index: u32) -> Account {
    let index = f64::from(index);
    let Some(record) = meta.record(index) else {
        return if index >= vault_meta::HARDWARE_INDEX_BASE {
            Account::Unknown
        } else {
            Account::Vault
        };
    };
    // Any form `isAddress` took when the record was added, as `getAddress`
    // reads it.
    let address = || {
        record
            .get("address")
            .and_then(fc_wallet_state::value_normalize_address)
    };
    match record.get("type").and_then(JsValue::as_str) {
        Some("mnemonic") => Account::Vault,
        Some("ledger") => Account::Ledger(address()),
        Some("remote") => Account::Phone(address()),
        Some("safe") => Account::Safe,
        _ => Account::Unknown,
    }
}

/// `vault-meta.json`'s records for the core's own checks (G20), once
/// `vault_meta` is moved: a snapshot the event loop takes where the files
/// and the vault state the checks run against change together, never read
/// at check time. A vault create or import installs the vault, then the
/// metadata, on the worker, and the loop installs its new state only at the
/// job's end: a check must see the records of the vault it signs with, the
/// old pair until then and the new pair after, never one of each. So the
/// loop takes it when the hello names the store, when startup recovery has
/// settled (before a pending hello is answered), at the end of every vault
/// job (after the state it installs), and after every `accounts.*` request,
/// each at a point where no vault job is running.
#[derive(Debug, Clone)]
pub enum Records {
    /// A vault journal remained when it was taken: the files may be a
    /// replaced vault's. Every check answers `storage`, as the vault's
    /// reads do, until recovery finishes it and the next snapshot is taken.
    Pending,
    /// The file as it stood. An unreadable one reads as no file and stays
    /// where it is: the store's next request sets it aside.
    Read(VaultMeta),
}

impl Records {
    /// Account `index` as the snapshot records it.
    pub fn account(&self, index: u32) -> Result<Account, ErrorBody> {
        match self {
            Records::Pending => Err(storage("other")),
            Records::Read(meta) => Ok(account_of(meta, index)),
        }
    }

    /// The wallet list and active index a page request's world reads once
    /// `vault_meta` is moved (G20b), as main would send them:
    /// `getDerivedWallets()`, which is `accounts.list` read only (the
    /// first list's default answered, not written), its mnemonic accounts'
    /// addresses derived against `state`, the vault state this snapshot
    /// belongs to (the stored ones while locked); and `getActiveWalletIndex()`
    /// (`meta?.activeWalletIndex ?? 0`). A list that fails, or one a vault
    /// journal holds back ([`Records::Pending`]), is empty with no active
    /// index, as main's `walletList` reads a list that throws.
    pub fn wallets(&self, state: &VaultState) -> (Vec<JsValue>, Option<JsValue>) {
        let Records::Read(meta) = self else {
            return (Vec::new(), None);
        };
        let listed = meta
            .listed(|indices| derive_all(state, indices))
            .unwrap_or_default();
        // The codec loads no file whose `activeWalletIndex` isn't an
        // integer, so `?? 0` is `active_index`'s number.
        (listed, Some(JsValue::Number(meta.active_index())))
    }

    /// Whether the vault signs for account `index` ([`vault_signs`]): the
    /// reference's refusal, `invalid_argument` with its message, if not.
    pub fn vault_signs(&self, index: u32) -> Result<(), ErrorBody> {
        match self {
            Records::Pending => Err(storage("other")),
            Records::Read(meta) => vault_signs(meta, index)
                .map_err(|message| ErrorBody::new(ErrorCode::InvalidArgument, message)),
        }
    }
}

/// `getSigner`'s refusal of no record at a hardware index: a deleted
/// device's (a phone's too).
pub const DEVICE_GONE: &str = "Device account no longer exists; reconnect the device";
/// `getSigner`'s refusal of a Safe: it has no key of its own.
pub const SAFE_SIGNS: &str = "Safe accounts cannot sign directly — execute through the Safe flow";
/// `withVaultAccount`'s refusal of a device's index, or any hardware index.
pub const ON_DEVICE: &str =
    "This account keeps its key on another device; sign via its device signer";

/// Whether the vault signs for account `index` as `meta` records it (G20b),
/// as the reference decides before its vault backend touches the key:
/// `getSigner` refuses no record at a hardware index ([`DEVICE_GONE`]) and
/// a Safe ([`SAFE_SIGNS`]), sends a Ledger or a phone to its device, and
/// `withVaultAccount` refuses any other hardware index or a `type` other
/// than `mnemonic` ([`ON_DEVICE`]). So the vault signs for an index below
/// the hardware range with a mnemonic record or none; the core refuses a
/// device's index with `withVaultAccount`'s text, the vault's refusal of it.
pub fn vault_signs(meta: &VaultMeta, index: u32) -> Result<(), &'static str> {
    let at = f64::from(index);
    let hardware = at >= vault_meta::HARDWARE_INDEX_BASE;
    let record = meta.record(at);
    // The type normalized (`record.type || 'mnemonic'`), compared with
    // `===`: a type that isn't a string is none of the named ones.
    let kind = record
        .as_ref()
        .map(|record| record.get("type").and_then(JsValue::as_str));
    match kind {
        None if hardware => Err(DEVICE_GONE),
        Some(Some("safe")) => Err(SAFE_SIGNS),
        _ if hardware => Err(ON_DEVICE),
        None | Some(Some("mnemonic")) => Ok(()),
        Some(_) => Err(ON_DEVICE),
    }
}

/// A removed Safe's `safe-pending.json` entry, cleared once `safe_pending`
/// is moved (0013, "`accounts.remove`"): whether the clear was durable.
/// Before the move main writes the file and clears the entry after the
/// answer. A clear that fails refuses the removal, the record still there,
/// as a failed forget does (`accounts-remove-forget-first`): a later
/// account given the index must not inherit the entry. An index no key
/// of the file can name (not an integer from 0 to 2^53 − 1) has none.
fn clear_pending(pending: &SafePending, index: f64) -> Result<bool, ErrorBody> {
    let max = fc_wallet_state::safe_pending::MAX_INDEX as f64;
    if index.fract() != 0.0 || !(0.0..=max).contains(&index) {
        return Ok(true);
    }
    match pending.clear(index as u64) {
        Ok(cleared) => Ok(cleared.durable),
        Err(safe_pending::Failure::NotMoved) => Ok(true),
        Err(failure) => Err(failure.error()),
    }
}

/// An index as an account number: a non-negative integer that fits.
fn account_index(index: f64) -> Option<u32> {
    (index.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&index)).then_some(index as u32)
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
    fn an_account_is_what_its_record_says() {
        let ledger = format!("0x{}", "a1".repeat(20));
        let phone = format!("0x{}", "b2".repeat(20));
        let main = format!("0x{}", "c3".repeat(20));
        let text = json!({
            "addresses": { "userWallet": main },
            "derivedWallets": [
                { "index": 0, "name": "Main" },
                { "index": 1, "name": "Spare", "address": phone },
                { "index": 1_000_000, "name": "Ledger", "address": ledger, "type": "ledger", "path": "m" },
                { "index": 1_000_001, "name": "Phone", "address": phone, "type": "remote" },
                { "index": 1_000_002, "name": "Safe", "address": ledger, "type": "safe", "owners": [0] },
                { "index": 1_000_003, "name": "Odd", "address": phone, "type": "other" },
                { "index": 1_000_004, "name": "Bad", "address": "0x12", "type": "remote" },
                { "index": 1_000_005, "name": "Typed", "address": phone, "type": "mnemonic" },
            ],
        })
        .to_string();
        let meta = VaultMeta::load(text.as_bytes()).unwrap();
        let norm = |text: &str| fc_wallet_state::normalize_address(text);
        // A mnemonic record is the vault's, whatever address it stores.
        assert_eq!(account_of(&meta, 0), Account::Vault);
        assert_eq!(account_of(&meta, 1), Account::Vault);
        assert_eq!(account_of(&meta, 1_000_005), Account::Vault);
        assert_eq!(account_of(&meta, 1_000_000), Account::Ledger(norm(&ledger)));
        assert_eq!(account_of(&meta, 1_000_001), Account::Phone(norm(&phone)));
        assert_eq!(account_of(&meta, 1_000_002), Account::Safe);
        assert_eq!(account_of(&meta, 1_000_003), Account::Unknown);
        // The kind is the type's alone: an address that isn't one leaves a
        // phone a phone, with no address any claim agrees with.
        assert_eq!(account_of(&meta, 1_000_004), Account::Phone(None));
        // No record: the vault's below the hardware range, none above.
        assert_eq!(account_of(&meta, 2), Account::Vault);
        assert_eq!(account_of(&meta, 999_999), Account::Vault);
        assert_eq!(account_of(&meta, 1_000_006), Account::Unknown);
        assert_eq!(account_of(&VaultMeta::none(), 0), Account::Vault);
        assert_eq!(account_of(&VaultMeta::none(), 1_000_000), Account::Unknown);
        assert_eq!(
            Account::Phone(norm(&phone)).kind(),
            Some(AccountKind::Phone)
        );
        assert_eq!(Account::Unknown.kind(), None);
    }

    /// A page request's wallets: `accounts.list`'s, the stored addresses
    /// while locked, the default list unwritten; the active index, 0 when
    /// none is stored; none while a journal remains.
    #[test]
    fn a_request_s_wallets_are_the_records_list() {
        let stored = format!("0x{}", "d4".repeat(20));
        let locked = VaultState::new();
        let records = |text: serde_json::Value| {
            Records::Read(VaultMeta::load(text.to_string().as_bytes()).unwrap())
        };
        let (wallets, active) = records(json!({
            "addresses": { "userWallet": stored },
            "derivedWallets": [{ "index": 0, "name": "Main" }, { "index": 1, "address": stored }],
            "activeWalletIndex": 1,
        }))
        .wallets(&locked);
        let addresses: Vec<_> = wallets.iter().map(|w| w.get("address")).collect();
        assert_eq!(addresses, [Some(&JsValue::string(&stored)); 2]);
        assert_eq!(active, Some(JsValue::Number(1.0)));
        let (wallets, active) = records(json!({ "addresses": {} })).wallets(&locked);
        assert_eq!(wallets.len(), 1, "the default list");
        assert_eq!(active, Some(JsValue::Number(0.0)));
        assert_eq!(
            Records::Read(VaultMeta::none()).wallets(&locked),
            (Vec::new(), Some(JsValue::Number(0.0)))
        );
        assert_eq!(Records::Pending.wallets(&locked), (Vec::new(), None));
    }

    /// The vault signs for an index below the hardware range with a
    /// mnemonic record or none, and for nothing else.
    #[test]
    fn the_vault_signs_for_its_own_records_alone() {
        let device = format!("0x{}", "a1".repeat(20));
        let text = json!({
            "derivedWallets": [
                { "index": 0, "name": "Main" },
                { "index": 1, "name": "Typed", "type": "mnemonic" },
                { "index": 2, "name": "Empty type", "type": "" },
                { "index": 3, "name": "Odd", "type": "other" },
                { "index": 4, "name": "Numbered", "type": 7 },
                { "index": 5, "name": "Low Safe", "address": device, "type": "safe" },
                { "index": 1_000_000, "name": "Ledger", "address": device, "type": "ledger" },
                { "index": 1_000_001, "name": "Phone", "address": device, "type": "remote" },
                { "index": 1_000_002, "name": "Safe", "address": device, "type": "safe" },
                { "index": 1_000_003, "name": "High", "type": "mnemonic" },
                { "index": 1_000_004, "name": "High odd", "type": "other" },
            ],
        })
        .to_string();
        let meta = VaultMeta::load(text.as_bytes()).unwrap();
        for index in [0, 1, 2, 6, 999_999] {
            assert_eq!(vault_signs(&meta, index), Ok(()), "{index}");
        }
        for (index, refusal) in [
            (3, ON_DEVICE),
            (4, ON_DEVICE),
            (5, SAFE_SIGNS),
            (1_000_000, ON_DEVICE),
            (1_000_001, ON_DEVICE),
            (1_000_002, SAFE_SIGNS),
            (1_000_003, ON_DEVICE),
            (1_000_004, ON_DEVICE),
            (1_000_005, DEVICE_GONE),
            (u32::MAX, DEVICE_GONE),
        ] {
            assert_eq!(vault_signs(&meta, index), Err(refusal), "{index}");
        }
        // No file: the vault's below the hardware range, gone above.
        assert_eq!(vault_signs(&VaultMeta::none(), 7), Ok(()));
        assert_eq!(vault_signs(&VaultMeta::none(), 1_000_000), Err(DEVICE_GONE));
    }

    /// A device record in any form `isAddress` took (`stores.json`'s
    /// `vault_meta` forms among them) is its device at the address
    /// `getAddress` gives, an ICAP past 20 bytes included (41 digits); one
    /// that isn't an address is its device with none.
    #[test]
    fn a_device_record_in_any_accepted_form() {
        let checksummed = "0xA1A1a1a1A1A1A1A1A1a1a1a1a1a1A1A1a1A1a1a1";
        let expected = Some(checksummed.to_lowercase());
        let icap = "XE26QURMT0JTHRKRVCUYL99VJZODRSZWBMT";
        let icap_form = fc_wallet_state::normalize_address(icap);
        let overflow = "XE54ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
        let overflow_form = Some("0x1343093195196b9fcca7c68ce3fffffffffffffff".to_owned());
        let record = |address: &str| {
            let text = json!({ "derivedWallets": [
                { "index": 0, "name": "Main" },
                { "index": 1_000_000, "name": "Phone", "address": address, "type": "remote" },
                { "index": 1_000_001, "name": "Ledger", "address": address, "type": "ledger" },
            ] })
            .to_string();
            let meta = VaultMeta::load(text.as_bytes()).unwrap();
            (account_of(&meta, 1_000_000), account_of(&meta, 1_000_001))
        };
        for form in [
            checksummed.to_owned(),
            checksummed[2..].to_owned(),
            checksummed.to_lowercase(),
            checksummed[2..].to_lowercase(),
            format!("0x{}", checksummed[2..].to_uppercase()),
            checksummed[2..].to_uppercase(),
        ] {
            assert_eq!(
                record(&form),
                (
                    Account::Phone(expected.clone()),
                    Account::Ledger(expected.clone())
                ),
                "{form}"
            );
        }
        assert!(icap_form.is_some());
        assert_eq!(
            record(icap),
            (
                Account::Phone(icap_form.clone()),
                Account::Ledger(icap_form)
            )
        );
        assert_eq!(
            record(overflow),
            (
                Account::Phone(overflow_form.clone()),
                Account::Ledger(overflow_form)
            )
        );
        for bad in [
            "0xa1A1a1a1A1A1A1A1A1a1a1a1a1a1A1A1a1A1a1a1",
            "0Xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "XE27QURMT0JTHRKRVCUYL99VJZODRSZWBMT",
        ] {
            assert_eq!(
                record(bad),
                (Account::Phone(None), Account::Ledger(None)),
                "{bad}"
            );
        }
    }
}
