//! The vault and key methods (design 0001: "Phase 1 API", "Parity
//! contract", "Concurrency, epochs and revocation", "Deadlines, cancellation
//! and commit").
//!
//! - **Inline methods** run on the event loop and never wait: `vault.lock`,
//!   `vault.touch`, `vault.status`, `keys.*`, `compat.*`.
//! - **KDF methods** go through one serialized queue to the worker thread:
//!   unlock, verify, change_password, delete, create, import and both
//!   exports. That covers the 900k-round PBKDF2 and the durable write.
//! - **Throttle:** an attempt is reserved when its job starts and settled
//!   with the real outcome when the KDF actually ends, even if the request
//!   was already answered. Every job that checks a password reserves one,
//!   `vault.reconcile` included unless it reconciles a delete (#78). While
//!   the throttle refuses, the job still checks the file, with no password:
//!   a missing, unsupported or corrupt vault is reported before `throttled`,
//!   as design 0001's parity table orders them (#82).
//! - **Commit point:** each job shares a [`JobControl`] with the loop. The
//!   commit point is the worker's atomic claim immediately before the rename
//!   or unlink. Until then the loop can abandon the job and answer at once
//!   (`cancelled`, `deadline`, `vault_locked`); an abandoned job writes
//!   nothing and its late result is discarded. After the claim, cancel,
//!   deadline and locks no longer apply: the reply is the real outcome of
//!   the rename or unlink (success, or an error if it failed and nothing
//!   changed). Each request gets exactly one terminal reply.
//! - **Locks** (manual, auto, delete, shutdown) revoke all admitted vault
//!   work that hasn't reached its commit point, queued or running: nothing
//!   admitted before a lock acknowledgement runs after it. Unlock also
//!   installs only with a ticket taken at its start.
//! - **Deadlines** (30 s from admission) are enforced by the loop's wakeup,
//!   for queued and running work alike, independently of the worker.
//! - **The auto-lock counts sleep** ([`Clock`], #80): a vault left unlocked
//!   locks on waking once its time has passed, however long the machine
//!   slept. While unlocked, the loop wakes at least every
//!   [`SUSPEND_CHECK`], since its own timed wait may sleep through a
//!   suspend.
//! - **The file snapshot** follows the core's own commits (the fingerprint
//!   of the bytes written, or none after a delete); the worker never re-reads
//!   the file after a job.
//!
//! Error codes come with the exact JS message for the method, so main can
//! pass them through (design 0001's parity table).

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fc_keys::freedom::{self, FreedomKeys};
use fc_keys::{Mnemonic, WordCount, multiformats};
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::message::{self, CallerKind};
use fc_protocol::secret::{SecretBytes, SecretResponse};
use fc_vault::format::{self, SealParams};
use fc_vault::state::{LockReason, Locked, Prepared, Ticket, VaultState};
use fc_vault::throttle::{Attempt, Outcome, Throttle};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use zeroize::{Zeroize, Zeroizing};

use crate::clock::Clock;
use crate::fsx::{self, Done};
use crate::journal;
use crate::nodes::{self, NodeSpec};
use crate::rng::OsRng;
use crate::worker::Job;

/// The vault file inside the identity directory.
pub const VAULT_FILE: &str = "identity-vault.json";
/// The largest vault file read. Real vaults are about 1 KB.
const MAX_VAULT_BYTES: u64 = 1 << 20;
/// Total budget for a KDF method, from admission (design 0001).
const KDF_DEADLINE: Duration = Duration::from_secs(30);
/// Queued KDF requests before `busy`.
const MAX_QUEUED: usize = 32;
/// Most indices per `keys.addresses` request.
const MAX_INDICES: usize = 64;
/// While the auto-lock runs, the loop wakes at least this often (#80). Its
/// timed wait runs on a clock that stops while the machine sleeps, so after
/// a suspend it could otherwise wait out the rest of the auto-lock delay
/// before it looks at [`Clock`] again.
pub const SUSPEND_CHECK: Duration = Duration::from_secs(1);

const MSG_NO_VAULT: &str = "No vault found. Create one first.";
const MSG_NO_VAULT_SHORT: &str = "No vault found";
const MSG_INCORRECT: &str = "Incorrect password";
const MSG_LOCKED: &str = "Vault is locked";
const MSG_WEAK: &str = "Password must be at least 8 characters";
const MSG_INVALID_MNEMONIC: &str = "Invalid mnemonic";
const MSG_EXISTS_CREATE: &str = "Vault already exists. Use importVault to replace.";
const MSG_EXISTS_IMPORT: &str = "Vault already exists. Set overwrite=true to replace.";
const MSG_DECRYPTED_INVALID: &str = "Decrypted data is not a valid mnemonic";

/// What the vault asks the event loop to do.
pub enum Out {
    /// A JSON payload to frame and send (a response or an event).
    Send(Zeroizing<Vec<u8>>),
    /// A job for the worker, with its ID.
    Job(u64, Job),
}

/// Why a vault operation failed. Mapped to a code and the method's JS
/// message by [`OpError::body`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpError {
    NoVault,
    Unsupported(String),
    Corrupt,
    Incorrect,
    DecryptedInvalid,
    Weak,
    /// create, or import without overwrite, found a vault at job time.
    Exists {
        import: bool,
    },
    Storage(&'static str),
    /// The loop abandoned the job before its commit point (it already
    /// answered the request).
    Abandoned,
    /// A request the core can't act on (`invalid_argument`).
    Invalid(&'static str),
    Internal,
}

impl OpError {
    fn from_vault(error: fc_vault::Error) -> Self {
        match error {
            fc_vault::Error::IncorrectPassword => OpError::Incorrect,
            fc_vault::Error::UnsupportedVersion(v) => OpError::Unsupported(v),
            fc_vault::Error::Corrupt(_) => OpError::Corrupt,
            fc_vault::Error::InvalidDecryptedMnemonic => OpError::DecryptedInvalid,
            _ => OpError::Internal,
        }
    }

    /// `short_no_vault`: verify and the exports say "No vault found".
    fn body(&self, short_no_vault: bool) -> ErrorBody {
        match self {
            OpError::NoVault if short_no_vault => {
                ErrorBody::new(ErrorCode::NoVault, MSG_NO_VAULT_SHORT)
            }
            OpError::NoVault => ErrorBody::new(ErrorCode::NoVault, MSG_NO_VAULT),
            OpError::Unsupported(version) => ErrorBody::new(
                ErrorCode::UnsupportedVaultVersion,
                format!("Unsupported vault version: {version}"),
            ),
            OpError::Corrupt => ErrorBody::new(ErrorCode::CorruptVault, "Corrupt vault file"),
            OpError::Incorrect => ErrorBody::new(ErrorCode::IncorrectPassword, MSG_INCORRECT),
            OpError::DecryptedInvalid => {
                ErrorBody::new(ErrorCode::CorruptVault, MSG_DECRYPTED_INVALID)
            }
            OpError::Weak => ErrorBody::new(ErrorCode::WeakPassword, MSG_WEAK),
            OpError::Exists { import: false } => {
                ErrorBody::new(ErrorCode::VaultExists, MSG_EXISTS_CREATE)
            }
            OpError::Exists { import: true } => {
                ErrorBody::new(ErrorCode::VaultExists, MSG_EXISTS_IMPORT)
            }
            OpError::Storage(kind) => ErrorBody::new(ErrorCode::Storage, "Storage error")
                .with_data(serde_json::json!({ "kind": kind })),
            OpError::Invalid(message) => ErrorBody::new(ErrorCode::InvalidArgument, *message),
            OpError::Abandoned | OpError::Internal => {
                ErrorBody::new(ErrorCode::Internal, "Internal error")
            }
        }
    }

    fn throttle_outcome(&self) -> Outcome {
        match self {
            OpError::Incorrect => Outcome::Failure,
            _ => Outcome::NotTried,
        }
    }
}

/// Public addresses, returned by create, import and unlock.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Addresses {
    pub user_wallet: String,
    pub bee_wallet: String,
}

/// The vault file as last seen: its SHA-256 if it exists. Read once at
/// startup on its own thread ([`startup_snapshot`]); after that it follows
/// the core's own successful commits (the fingerprint of the bytes written,
/// none after a delete), so the loop never touches storage.
pub type FileSnapshot = Result<Option<String>, OpError>;

/// A finished worker job.
pub struct Finished(JobOutput);

/// A committed change: whether its directory flush succeeded, and the vault
/// file's fingerprint afterwards (`None` after a delete).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    done: Done,
    file: Option<String>,
}

/// What a worker job produced.
pub enum JobOutput {
    /// unlock: the prepared secrets and public addresses.
    Unlocked(Result<(Prepared, Addresses), OpError>),
    /// verify, the export password checks, delete (`commit` = file
    /// removed).
    Checked {
        result: Result<(), OpError>,
        commit: Option<Commit>,
    },
    /// create and import: the new vault was written (`commit`), and is ready
    /// to install. `phrase` is returned for create's backup display.
    Written {
        result: Result<(Prepared, Addresses, Option<Mnemonic>), OpError>,
        commit: Option<Commit>,
    },
    /// change_password: written (`commit`) or not.
    Changed {
        result: Result<(), OpError>,
        commit: Option<Commit>,
    },
    /// reconcile: `None` when the operation didn't commit. `tried` is the
    /// throttle outcome of its decrypt (`NotTried` when it decrypted
    /// nothing).
    Reconciled {
        result: Result<Option<Reconciled>, OpError>,
        tried: Outcome,
    },
    /// nodes.write_identity: the journal outcome and the public identity.
    NodeWritten(Result<(journal::Outcome, serde_json::Map<String, serde_json::Value>), OpError>),
    /// nodes.op_status.
    OpStatus(Result<journal::OpStatus, OpError>),
    /// A password check the throttle refused: what the file says, before
    /// `throttled` (#82).
    Prechecked(Result<(), OpError>),
}

/// What `vault.reconcile` found for a committed create or import.
#[derive(Default)]
pub struct Reconciled {
    addresses: Option<Addresses>,
    /// create: the phrase for the onboarding display.
    phrase: Option<Mnemonic>,
    /// The secrets to install, only when `install` was asked for.
    prepared: Option<Prepared>,
}

/// The mutation `vault.reconcile` checks (design 0001, "Reconciliation").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReconcileOp {
    Create,
    Import,
    ChangePassword,
    Delete,
}

impl JobOutput {
    /// The vault file after a committed change, if this job made one.
    fn committed_file(&self) -> Option<Option<String>> {
        match self {
            JobOutput::Checked { commit, .. }
            | JobOutput::Written { commit, .. }
            | JobOutput::Changed { commit, .. } => commit.as_ref().map(|c| c.file.clone()),
            // Unlock and reconcile are read-only; node writes don't touch the
            // vault file.
            JobOutput::Unlocked(_)
            | JobOutput::Reconciled { .. }
            | JobOutput::NodeWritten(_)
            | JobOutput::OpStatus(_)
            | JobOutput::Prechecked(_) => None,
        }
    }
}

enum Kind {
    Unlock {
        password: SecretBytes,
    },
    Verify {
        password: SecretBytes,
    },
    ChangePassword {
        current: SecretBytes,
        new: SecretBytes,
    },
    Delete {
        password: SecretBytes,
    },
    ExportMnemonic {
        password: SecretBytes,
    },
    ExportPrivateKey {
        password: SecretBytes,
        account: u32,
    },
    Create {
        password: SecretBytes,
        words: WordCount,
    },
    Import {
        password: SecretBytes,
        mnemonic: Mnemonic,
        overwrite: bool,
    },
    Reconcile {
        op: ReconcileOp,
        before: Option<String>,
        /// change_password: the new password.
        password: SecretBytes,
        /// import: the requested mnemonic.
        mnemonic: Option<Mnemonic>,
        install: bool,
    },
    NodeWrite {
        op_id: String,
        spec: NodeSpec,
        /// Taken from the unlocked state when the job starts, never while
        /// queued.
        keys: Option<Box<FreedomKeys>>,
    },
    OpStatus {
        op_id: String,
    },
}

impl Kind {
    /// What a password check the throttle refuses still checks, without the
    /// password, before it answers `throttled` (design 0001's parity table,
    /// #82): `Some(true)` for the file's existence, structure and version
    /// (unlock, change_password, delete), `Some(false)` for existence and
    /// structure (verify and the exports, which check no version, as JS
    /// `verifyPassword`). `None`: `throttled` at once (reconcile among
    /// them: an honest one never meets the throttle, #78).
    fn precheck(&self) -> Option<bool> {
        match self {
            Kind::Unlock { .. } | Kind::ChangePassword { .. } | Kind::Delete { .. } => Some(true),
            Kind::Verify { .. } | Kind::ExportMnemonic { .. } | Kind::ExportPrivateKey { .. } => {
                Some(false)
            }
            Kind::Create { .. }
            | Kind::Import { .. }
            | Kind::Reconcile { .. }
            | Kind::NodeWrite { .. }
            | Kind::OpStatus { .. } => None,
        }
    }

    /// verify and the exports say "No vault found".
    fn short_no_vault(&self) -> bool {
        matches!(
            self,
            Kind::Verify { .. } | Kind::ExportMnemonic { .. } | Kind::ExportPrivateKey { .. }
        )
    }

    /// Whether the job checks a password, and so reserves a throttle attempt
    /// first.
    ///
    /// `vault.reconcile` does (#78): the core can't tell main's own
    /// reconciliation from a later call with a made-up `fingerprint_before`,
    /// and unthrottled it would be a password oracle (and, for `create`, a
    /// way to the phrase while locked). An honest reconcile loses nothing:
    /// it follows a restart, so the counter starts at zero, and it sends the
    /// right password. A delete's reconcile decrypts nothing.
    fn throttled(&self) -> bool {
        match self {
            Kind::Unlock { .. }
            | Kind::Verify { .. }
            | Kind::ChangePassword { .. }
            | Kind::Delete { .. }
            | Kind::ExportMnemonic { .. }
            | Kind::ExportPrivateKey { .. } => true,
            Kind::Reconcile { op, .. } => *op != ReconcileOp::Delete,
            Kind::Create { .. }
            | Kind::Import { .. }
            | Kind::NodeWrite { .. }
            | Kind::OpStatus { .. } => false,
        }
    }
}

struct Pending {
    id: u64,
    kind: Kind,
    deadline: Instant,
}

/// Shared by the loop and the worker for one job: who wins the race between
/// abandoning it and committing it.
pub struct JobControl(AtomicU8);

const JOB_RUNNING: u8 = 0;
const JOB_ABANDONED: u8 = 1;
const JOB_COMMITTED: u8 = 2;

impl JobControl {
    fn new() -> Arc<Self> {
        Arc::new(JobControl(AtomicU8::new(JOB_RUNNING)))
    }

    /// Loop: stops the job unless it already committed. True if stopped.
    fn abandon(&self) -> bool {
        self.0
            .compare_exchange(
                JOB_RUNNING,
                JOB_ABANDONED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Worker: claims the commit point. False if the job was abandoned.
    fn commit(&self) -> bool {
        self.0
            .compare_exchange(
                JOB_RUNNING,
                JOB_COMMITTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Whether the worker claimed the commit point (deadlines and revocation
    /// no longer apply).
    fn committed(&self) -> bool {
        self.0.load(Ordering::Acquire) == JOB_COMMITTED
    }

    /// Worker: whether to stop early (skip the KDF).
    fn abandoned(&self) -> bool {
        self.0.load(Ordering::Acquire) == JOB_ABANDONED
    }
}

/// What the loop must remember about the running job.
enum RunningKind {
    Unlock,
    Verify,
    ChangePassword,
    Delete,
    ExportMnemonic,
    ExportPrivateKey(u32),
    Create,
    Import,
    Reconcile {
        install: bool,
    },
    NodeWrite,
    OpStatus,
    /// A password check the throttle refused, checking the file first.
    /// `ready_at`: when the throttle allows the next attempt (clock ms).
    Precheck {
        short: bool,
        ready_at: u64,
    },
}

struct Running {
    job: u64,
    request: u64,
    kind: RunningKind,
    attempt: Option<Attempt>,
    ticket: Ticket,
    deadline: Instant,
    control: Arc<JobControl>,
    /// The request already got its terminal reply (abandoned); the job's
    /// result will only settle the throttle.
    answered: bool,
}

pub struct Vault {
    dir: PathBuf,
    file: FileSnapshot,
    state: VaultState,
    throttle: Throttle,
    auto_lock_ms: u64,
    /// The auto-lock's and the throttle's time, sleep included.
    clock: Clock,
    queue: VecDeque<Pending>,
    running: Option<Running>,
    next_job: u64,
    kdf_deadline: Duration,
}

#[derive(Deserialize)]
struct PasswordParams<'a> {
    #[serde(borrow)]
    password_b64: &'a RawValue,
}

#[derive(Deserialize)]
struct ChangeParams<'a> {
    #[serde(borrow)]
    password_b64: &'a RawValue,
    #[serde(borrow)]
    new_password_b64: &'a RawValue,
}

#[derive(Deserialize)]
struct ExportKeyParams<'a> {
    #[serde(borrow)]
    password_b64: &'a RawValue,
    account: u32,
}

#[derive(Deserialize)]
struct CreateParams<'a> {
    #[serde(borrow)]
    password_b64: &'a RawValue,
    words: u8,
    #[allow(dead_code)]
    #[serde(default)]
    user_knows_password: bool,
}

#[derive(Deserialize)]
struct ImportParams<'a> {
    #[serde(borrow)]
    password_b64: &'a RawValue,
    #[serde(borrow)]
    mnemonic_b64: &'a RawValue,
    #[serde(default)]
    overwrite: bool,
}

#[derive(Deserialize)]
struct ReconcileParams<'a> {
    op: ReconcileOp,
    /// Required: `null` means main observed no vault before; a missing field
    /// is unknown pre-state, never evidence of absence.
    #[serde(default, deserialize_with = "present")]
    fingerprint_before: Option<Option<String>>,
    #[serde(borrow)]
    password_b64: &'a RawValue,
    #[serde(borrow, default)]
    mnemonic_b64: Option<&'a RawValue>,
    #[serde(default)]
    install: bool,
}

#[derive(Deserialize)]
struct NodeWriteParams {
    op_id: String,
    node: String,
    data_dir: Option<String>,
    api_port: Option<u16>,
    p2p_port: Option<u16>,
    home: Option<String>,
    alias: Option<String>,
}

#[derive(Deserialize)]
struct OpStatusParams {
    op_id: String,
}

fn node_spec(p: NodeWriteParams) -> Option<NodeSpec> {
    let absolute = |dir: Option<String>| dir.map(PathBuf::from).filter(|path| path.is_absolute());
    match p.node.as_str() {
        "bee" => Some(NodeSpec::Bee {
            data_dir: absolute(p.data_dir)?,
            api_port: p.api_port.filter(|&port| port > 0)?,
            p2p_port: p.p2p_port.filter(|&port| port > 0)?,
        }),
        "radicle" => {
            // The alias goes into the key comment and the .pub line.
            let alias = p
                .alias
                .filter(|a| (1..=64).contains(&a.len()) && !a.chars().any(char::is_control))?;
            Some(NodeSpec::Radicle {
                home: absolute(p.home)?,
                alias,
            })
        }
        _ => None,
    }
}

#[derive(Deserialize)]
struct WordsParams {
    words: u8,
}

#[derive(Deserialize)]
struct MnemonicParams<'a> {
    #[serde(borrow)]
    mnemonic_b64: &'a RawValue,
}

#[derive(Deserialize)]
struct AddressesParams {
    #[serde(default)]
    accounts: Vec<u32>,
    #[serde(default)]
    publishers: Vec<u32>,
}

#[derive(Deserialize)]
struct AccountParams {
    account: u32,
}

#[derive(Deserialize)]
struct OriginParams {
    origin_index: u32,
}

#[derive(Deserialize)]
struct PublicKeyParams {
    public_key: String,
}

#[derive(Serialize)]
struct Status {
    exists: bool,
    unlocked: bool,
    epoch: Option<u64>,
    fingerprint: Option<String>,
}

fn word_count(words: u8) -> Option<WordCount> {
    match words {
        12 => Some(WordCount::W12),
        15 => Some(WordCount::W15),
        18 => Some(WordCount::W18),
        21 => Some(WordCount::W21),
        24 => Some(WordCount::W24),
        _ => None,
    }
}

/// A secret field from its borrowed raw token (fc-protocol's only secret
/// decoding path).
fn secret(raw: &RawValue) -> Result<SecretBytes, ErrorBody> {
    SecretBytes::from_raw(raw)
        .map_err(|_| ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters"))
}

/// Parses method params from the frame's slice; a missing params object
/// counts as `{}`.
fn params<'a, T: Deserialize<'a>>(raw: Option<&'a str>) -> Result<T, ErrorBody> {
    serde_json::from_str(raw.unwrap_or("{}"))
        .map_err(|_| ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters"))
}

impl Vault {
    pub fn new(dir: PathBuf, auto_lock_ms: u64) -> Self {
        Vault {
            // Replaced by the startup snapshot before core.hello is answered,
            // and no vault request is accepted before that.
            file: Err(OpError::Storage("not_ready")),
            dir,
            state: VaultState::new(),
            throttle: Throttle::new(),
            auto_lock_ms,
            clock: Clock::new(),
            queue: VecDeque::new(),
            running: None,
            next_job: 1,
            kdf_deadline: crate::testhooks::kdf_deadline(KDF_DEADLINE),
        }
    }

    /// Installs the startup snapshot.
    pub fn set_snapshot(&mut self, file: FileSnapshot) {
        self.file = file;
    }

    pub fn set_auto_lock_ms(&mut self, auto_lock_ms: u64) {
        self.auto_lock_ms = auto_lock_ms;
    }

    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Whether this module handles `method`.
    pub fn handles(method: &str) -> bool {
        matches!(
            method,
            "vault.status"
                | "vault.lock"
                | "vault.touch"
                | "vault.unlock"
                | "vault.verify_password"
                | "vault.change_password"
                | "vault.delete"
                | "vault.export_mnemonic"
                | "vault.export_private_key"
                | "vault.create"
                | "vault.import"
                | "vault.reconcile"
                | "nodes.write_identity"
                | "nodes.op_status"
                | "keys.generate_mnemonic"
                | "keys.validate_mnemonic"
                | "keys.addresses"
                | "keys.radicle_did"
                | "compat.private_key"
                | "compat.bee_wallet_key"
                | "compat.publisher_key"
        ) || crate::signing::METHODS.contains(&method)
    }

    /// Handles a request. Inline methods reply at once; KDF methods are
    /// queued and reply when their job finishes.
    pub fn request(
        &mut self,
        id: u64,
        method: &str,
        raw: Option<&str>,
        caller: CallerKind,
    ) -> Vec<Out> {
        let mut out = Vec::new();
        // compat.* and vault.reconcile are main-internal (design 0001).
        let internal_only = method.starts_with("compat.")
            || method == "vault.reconcile"
            || method == "nodes.op_status";
        if internal_only && caller != CallerKind::Shell {
            self.reply_error(
                &mut out,
                id,
                ErrorBody::new(ErrorCode::Forbidden, "main-internal only"),
            );
            return out;
        }
        let result = match method {
            "vault.status" => self.status(id),
            "vault.lock" => {
                self.lock_now(LockReason::Manual, &mut out);
                Ok(json_result(id, &serde_json::json!({})))
            }
            "vault.touch" => {
                let now = self.now_ms();
                self.state.touch(now);
                Ok(json_result(id, &serde_json::json!({})))
            }
            "keys.generate_mnemonic" => self.generate(id, raw),
            "keys.validate_mnemonic" => params::<MnemonicParams>(raw).and_then(|p| {
                let mnemonic = secret(p.mnemonic_b64)?;
                let valid = mnemonic.as_str().is_ok_and(fc_keys::is_valid_mnemonic);
                Ok(json_result(id, &serde_json::json!({ "valid": valid })))
            }),
            "keys.addresses" => self.addresses(id, raw),
            "keys.radicle_did" => {
                params::<PublicKeyParams>(raw).and_then(|p| radicle_did(id, &p.public_key))
            }
            "compat.private_key" => params::<AccountParams>(raw).and_then(|p| {
                let key = self
                    .state
                    .user_wallet(p.account)
                    .map_err(locked_or_internal)?;
                private_key_result(id, key.to_secret_bytes().as_slice())
            }),
            "compat.bee_wallet_key" => self
                .state
                .freedom_keys()
                .map_err(locked_or_internal)
                .and_then(|keys| {
                    private_key_result(id, keys.bee_wallet.to_secret_bytes().as_slice())
                }),
            "compat.publisher_key" => params::<OriginParams>(raw).and_then(|p| {
                let key = self
                    .state
                    .publisher(p.origin_index)
                    .map_err(locked_or_internal)?;
                private_key_result(id, key.to_secret_bytes().as_slice())
            }),
            _ if crate::signing::METHODS.contains(&method) => {
                crate::signing::handle(&self.state, method, raw)
                    .map(|result| json_result(id, &result))
            }
            _ => match self.enqueue(id, method, raw) {
                Ok(()) => {
                    self.start_next(&mut out);
                    return out;
                }
                Err(error) => Err(error),
            },
        };
        match result {
            Ok(Some(payload)) => out.push(Out::Send(payload)),
            Ok(None) => out.push(Out::Send(error_payload(
                id,
                &ErrorBody::new(ErrorCode::Internal, "Internal error"),
            ))),
            Err(error) => self.reply_error(&mut out, id, error),
        }
        out
    }

    /// Cancels a queued request, or abandons the running one if it hasn't
    /// committed. A committed one replies with its success.
    pub fn cancel(&mut self, id: u64) -> Vec<Out> {
        let mut out = Vec::new();
        if let Some(position) = self.queue.iter().position(|p| p.id == id) {
            self.queue.remove(position);
            self.reply_error(&mut out, id, cancelled());
        } else if let Some(running) = &mut self.running
            && running.request == id
            && !running.answered
            && running.control.abandon()
        {
            running.answered = true;
            out.push(Out::Send(error_payload(id, &cancelled())));
        }
        out
    }

    /// Applies what is due: the auto-lock (which revokes), then the
    /// deadlines of queued and running work. The loop calls this before it
    /// handles each event, so a busy queue can't postpone either.
    pub fn tick(&mut self) -> Vec<Out> {
        let mut out = Vec::new();
        let now = self.now_ms();
        if let Some(locked) = self.state.tick(now) {
            out.push(Out::Send(locked_event(locked)));
            self.revoke(&mut out);
        }
        // In admission order: the running job, then the queue.
        let instant = Instant::now();
        if let Some(running) = &mut self.running
            && !running.answered
            && instant >= running.deadline
            && running.control.abandon()
        {
            running.answered = true;
            out.push(Out::Send(error_payload(
                running.request,
                &deadline_exceeded(),
            )));
        }
        while self.queue.front().is_some_and(|p| instant >= p.deadline) {
            if let Some(pending) = self.queue.pop_front() {
                self.reply_error(&mut out, pending.id, deadline_exceeded());
            }
        }
        out
    }

    /// When the loop must wake: the auto-lock, or the earliest deadline.
    /// While the auto-lock runs, that is at most [`SUSPEND_CHECK`] away.
    pub fn next_wakeup(&self) -> Option<Instant> {
        let auto_lock = self.state.auto_lock_deadline().map(|deadline| {
            let left = Duration::from_millis(deadline.saturating_sub(self.now_ms()));
            Instant::now() + left.min(SUSPEND_CHECK)
        });
        // A committed job's deadline no longer applies.
        let running = self
            .running
            .as_ref()
            .filter(|r| !r.answered && !r.control.committed())
            .map(|r| r.deadline);
        // The queue is in admission order, so its front expires first.
        let queued = self.queue.front().map(|p| p.deadline);
        [auto_lock, running, queued].into_iter().flatten().min()
    }

    /// Locks for shutdown: wipes everything and revokes all work that
    /// hasn't committed, with a reply. Committed work may still be running
    /// ([`Vault::committing`]); the loop waits for its reply.
    pub fn shutdown(&mut self) -> Vec<Out> {
        let mut out = Vec::new();
        self.lock_now(LockReason::Shutdown, &mut out);
        out
    }

    /// Locks for a `vault.lock` that waits for its turn behind replies main
    /// hasn't read (design 0001, Transport and framing): the secrets are
    /// wiped and admitted work revoked now, as by the auto-lock, and again
    /// after each request handled before that turn. The turn itself locks
    /// once more, and acknowledges it.
    pub fn lock(&mut self) -> Vec<Out> {
        let mut out = Vec::new();
        self.lock_now(LockReason::Manual, &mut out);
        out
    }

    /// Whether a job past its commit point is still running (its reply is
    /// still to come).
    pub fn committing(&self) -> bool {
        self.running
            .as_ref()
            .is_some_and(|r| !r.answered && r.control.committed())
    }

    fn lock_now(&mut self, reason: LockReason, out: &mut Vec<Out>) {
        if let Some(locked) = self.state.lock(reason) {
            out.push(Out::Send(locked_event(locked)));
        }
        // Every lock request revokes, even while already locked.
        self.revoke(out);
    }

    /// Revokes all admitted vault work that hasn't reached its commit
    /// point: the running job is abandoned unless it committed, and queued
    /// requests are dropped (their secrets wiped). Each gets `vault_locked`,
    /// in admission order.
    fn revoke(&mut self, out: &mut Vec<Out>) {
        if let Some(running) = &mut self.running
            && !running.answered
            && running.control.abandon()
        {
            running.answered = true;
            out.push(Out::Send(error_payload(running.request, &locked())));
        }
        for pending in std::mem::take(&mut self.queue) {
            self.reply_error(out, pending.id, locked());
        }
    }

    fn status(&self, id: u64) -> Result<Option<Zeroizing<Vec<u8>>>, ErrorBody> {
        let fingerprint = self.file.as_ref().map_err(|e| e.body(false))?.clone();
        let exists = fingerprint.is_some();
        Ok(json_result(
            id,
            &Status {
                exists,
                unlocked: self.state.is_unlocked(),
                epoch: self.state.epoch().map(|e| e.get()),
                fingerprint,
            },
        ))
    }

    fn generate(
        &mut self,
        id: u64,
        raw: Option<&str>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ErrorBody> {
        let p = params::<WordsParams>(raw)?;
        let words = word_count(p.words)
            .ok_or_else(|| ErrorBody::new(ErrorCode::InvalidArgument, "Invalid word count"))?;
        let mnemonic = Mnemonic::generate(&mut OsRng, words)
            .map_err(|_| ErrorBody::new(ErrorCode::Internal, "Internal error"))?;
        secret_result(id, "mnemonic_b64", mnemonic.phrase().as_bytes())
    }

    fn addresses(
        &mut self,
        id: u64,
        raw: Option<&str>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ErrorBody> {
        let p = params::<AddressesParams>(raw)?;
        if p.accounts.len() > MAX_INDICES || p.publishers.len() > MAX_INDICES {
            return Err(ErrorBody::new(
                ErrorCode::InvalidArgument,
                "Too many indices",
            ));
        }
        let keys = self.state.freedom_keys().map_err(locked_or_internal)?;
        let radicle = keys.radicle.public_key();
        let bee_wallet = keys.bee_wallet.address().to_string();
        drop(keys);
        let mut user_wallets = Vec::with_capacity(p.accounts.len());
        for account in p.accounts {
            let key = self
                .state
                .user_wallet(account)
                .map_err(locked_or_internal)?;
            user_wallets.push(
                serde_json::json!({ "account": account, "address": key.address().to_string() }),
            );
        }
        let mut publishers = Vec::with_capacity(p.publishers.len());
        for origin in p.publishers {
            let key = self.state.publisher(origin).map_err(locked_or_internal)?;
            publishers.push(
                serde_json::json!({ "origin_index": origin, "address": key.address().to_string() }),
            );
        }
        Ok(json_result(
            id,
            &serde_json::json!({
                "user_wallets": user_wallets,
                "bee_wallet": bee_wallet,
                "publishers": publishers,
                "radicle": {
                    "public_key": hex(&radicle),
                    "did": multiformats::did_key(&radicle),
                    "node_id": multiformats::radicle_node_id(&radicle),
                },
            }),
        ))
    }

    /// Validates a KDF request's parameters and pre-checks, then queues it.
    fn enqueue(&mut self, id: u64, method: &str, raw: Option<&str>) -> Result<(), ErrorBody> {
        let kind = match method {
            "vault.unlock" => Kind::Unlock {
                password: secret(params::<PasswordParams>(raw)?.password_b64)?,
            },
            "vault.verify_password" => Kind::Verify {
                password: secret(params::<PasswordParams>(raw)?.password_b64)?,
            },
            "vault.delete" => Kind::Delete {
                password: secret(params::<PasswordParams>(raw)?.password_b64)?,
            },
            "vault.export_mnemonic" => Kind::ExportMnemonic {
                password: secret(params::<PasswordParams>(raw)?.password_b64)?,
            },
            "vault.export_private_key" => {
                let p = params::<ExportKeyParams>(raw)?;
                Kind::ExportPrivateKey {
                    password: secret(p.password_b64)?,
                    account: p.account,
                }
            }
            "vault.change_password" => {
                let p = params::<ChangeParams>(raw)?;
                Kind::ChangePassword {
                    current: secret(p.password_b64)?,
                    new: secret(p.new_password_b64)?,
                }
            }
            "vault.create" => {
                let p = params::<CreateParams>(raw)?;
                let words = word_count(p.words).ok_or_else(|| {
                    ErrorBody::new(ErrorCode::InvalidArgument, "Invalid word count")
                })?;
                // JS order: exists, then password strength.
                if self.vault_exists()? {
                    return Err(ErrorBody::new(ErrorCode::VaultExists, MSG_EXISTS_CREATE));
                }
                let password = secret(p.password_b64)?;
                check_strength(&password)?;
                Kind::Create { password, words }
            }
            "vault.import" => {
                let p = params::<ImportParams>(raw)?;
                // JS order: mnemonic, exists, then password strength.
                let phrase = secret(p.mnemonic_b64)?;
                let mnemonic = phrase
                    .as_str()
                    .ok()
                    .and_then(|m| Mnemonic::parse(m).ok())
                    .ok_or_else(|| {
                        ErrorBody::new(ErrorCode::InvalidMnemonic, MSG_INVALID_MNEMONIC)
                    })?;
                if self.vault_exists()? && !p.overwrite {
                    return Err(ErrorBody::new(ErrorCode::VaultExists, MSG_EXISTS_IMPORT));
                }
                let password = secret(p.password_b64)?;
                check_strength(&password)?;
                Kind::Import {
                    password,
                    mnemonic,
                    overwrite: p.overwrite,
                }
            }
            "vault.reconcile" => {
                let invalid = || ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters");
                let p = params::<ReconcileParams>(raw)?;
                let before = p.fingerprint_before.ok_or_else(invalid)?;
                if before.as_deref().is_some_and(|f| !is_fingerprint(f)) {
                    return Err(invalid());
                }
                // A password change needs a vault before it.
                if p.op == ReconcileOp::ChangePassword && before.is_none() {
                    return Err(invalid());
                }
                let password = secret(p.password_b64)?;
                let mnemonic = match (p.op, p.mnemonic_b64) {
                    (ReconcileOp::Import, Some(raw)) => {
                        let phrase = secret(raw)?;
                        let parsed = phrase.as_str().ok().and_then(|m| Mnemonic::parse(m).ok());
                        Some(parsed.ok_or_else(invalid)?)
                    }
                    (ReconcileOp::Import, None) => return Err(invalid()),
                    _ => None,
                };
                Kind::Reconcile {
                    op: p.op,
                    before,
                    password,
                    mnemonic,
                    install: p.install,
                }
            }
            "nodes.write_identity" => {
                let invalid = || ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters");
                let p = params::<NodeWriteParams>(raw)?;
                if !journal::valid_op_id(&p.op_id) {
                    return Err(invalid());
                }
                let op_id = p.op_id.clone();
                let spec = node_spec(p).ok_or_else(invalid)?;
                // Admitted against the current epoch (design 0001).
                if !self.state.is_unlocked() {
                    return Err(locked());
                }
                Kind::NodeWrite {
                    op_id,
                    spec,
                    keys: None,
                }
            }
            "nodes.op_status" => {
                let p = params::<OpStatusParams>(raw)?;
                if !journal::valid_op_id(&p.op_id) {
                    return Err(ErrorBody::new(
                        ErrorCode::InvalidArgument,
                        "Invalid parameters",
                    ));
                }
                Kind::OpStatus { op_id: p.op_id }
            }
            _ => return Err(ErrorBody::new(ErrorCode::UnknownMethod, "Unknown method")),
        };
        if self.queue.len() >= MAX_QUEUED {
            return Err(ErrorBody::new(ErrorCode::Busy, "Busy"));
        }
        self.queue.push_back(Pending {
            id,
            kind,
            deadline: Instant::now() + self.kdf_deadline,
        });
        Ok(())
    }

    /// Admission check from the snapshot; the job checks again at run time.
    fn vault_exists(&self) -> Result<bool, ErrorBody> {
        self.file
            .as_ref()
            .map(Option::is_some)
            .map_err(|e| e.body(false))
    }

    /// Starts the next queued job if none is running.
    fn start_next(&mut self, out: &mut Vec<Out>) {
        while self.running.is_none() {
            let Some(pending) = self.queue.pop_front() else {
                return;
            };
            let mut pending = pending;
            if Instant::now() >= pending.deadline {
                self.reply_error(out, pending.id, deadline_exceeded());
                continue;
            }
            if let Kind::NodeWrite { keys, .. } = &mut pending.kind {
                match self.state.freedom_keys() {
                    Ok(derived) => *keys = Some(Box::new(derived)),
                    Err(_) => {
                        self.reply_error(out, pending.id, locked());
                        continue;
                    }
                }
            }
            let now = self.now_ms();
            let mut precheck = None;
            let attempt = if pending.kind.throttled() {
                match self.throttle.reserve(now) {
                    Ok(attempt) => Some(attempt),
                    Err(throttled) => match pending.kind.precheck() {
                        // The file first, with no password (design 0001's
                        // parity table): its errors come before `throttled`.
                        Some(version) => {
                            precheck = Some((
                                RunningKind::Precheck {
                                    short: pending.kind.short_no_vault(),
                                    ready_at: now.saturating_add(throttled.retry_after_ms),
                                },
                                version,
                            ));
                            None
                        }
                        None => {
                            self.reply_error(
                                out,
                                pending.id,
                                throttled_error(throttled.retry_after_ms),
                            );
                            continue;
                        }
                    },
                }
            } else {
                None
            };
            let job_id = self.next_job;
            self.next_job += 1;
            let control = JobControl::new();
            let (kind, job) = match precheck {
                // The request's secrets are dropped (wiped) here, unused.
                Some((kind, version)) => (kind, self.precheck_job(version, Arc::clone(&control))),
                None => self.job_for(pending.kind, Arc::clone(&control)),
            };
            self.running = Some(Running {
                job: job_id,
                request: pending.id,
                kind,
                attempt,
                ticket: self.state.ticket(),
                deadline: pending.deadline,
                control,
                answered: false,
            });
            out.push(Out::Job(job_id, job));
        }
    }

    /// The job of a password check the throttle refused: it reads the file,
    /// and holds no password.
    fn precheck_job(&self, version: bool, control: Arc<JobControl>) -> Job {
        let dir = self.dir.clone();
        Box::new(move || Finished(JobOutput::Prechecked(job_precheck(&dir, version, &control))))
    }

    fn job_for(&self, kind: Kind, control: Arc<JobControl>) -> (RunningKind, Job) {
        type Run = Box<dyn FnOnce(&Path, &JobControl) -> JobOutput + Send>;
        let (kind, run): (RunningKind, Run) = match kind {
            Kind::Unlock { password } => (
                RunningKind::Unlock,
                Box::new(move |dir, control| {
                    JobOutput::Unlocked(job_unlock(dir, &password, control))
                }),
            ),
            Kind::Verify { password } => (
                RunningKind::Verify,
                Box::new(move |dir, control| JobOutput::Checked {
                    result: job_verify(dir, &password, control),
                    commit: None,
                }),
            ),
            Kind::ExportMnemonic { password } => (
                RunningKind::ExportMnemonic,
                Box::new(move |dir, control| JobOutput::Checked {
                    result: job_verify(dir, &password, control),
                    commit: None,
                }),
            ),
            Kind::ExportPrivateKey { password, account } => (
                RunningKind::ExportPrivateKey(account),
                Box::new(move |dir, control| JobOutput::Checked {
                    result: job_verify(dir, &password, control),
                    commit: None,
                }),
            ),
            Kind::Delete { password } => (
                RunningKind::Delete,
                Box::new(move |dir, control| job_delete(dir, &password, control)),
            ),
            Kind::ChangePassword { current, new } => (
                RunningKind::ChangePassword,
                Box::new(move |dir, control| job_change(dir, &current, &new, control)),
            ),
            Kind::Create { password, words } => (
                RunningKind::Create,
                Box::new(move |dir, control| job_create(dir, &password, words, control)),
            ),
            Kind::Import {
                password,
                mnemonic,
                overwrite,
            } => (
                RunningKind::Import,
                Box::new(move |dir, control| {
                    job_import(dir, &password, mnemonic, overwrite, control)
                }),
            ),
            Kind::Reconcile {
                op,
                before,
                password,
                mnemonic,
                install,
            } => (
                RunningKind::Reconcile { install },
                Box::new(move |dir, control| {
                    let (result, tried) = job_reconcile(
                        dir,
                        op,
                        before.as_deref(),
                        &password,
                        mnemonic.as_ref(),
                        install,
                        control,
                    );
                    JobOutput::Reconciled { result, tried }
                }),
            ),
            Kind::NodeWrite { op_id, spec, keys } => (
                RunningKind::NodeWrite,
                Box::new(move |dir, control| {
                    JobOutput::NodeWritten(job_node_write(dir, &op_id, &spec, keys, control))
                }),
            ),
            Kind::OpStatus { op_id } => (
                RunningKind::OpStatus,
                Box::new(move |dir, control| {
                    JobOutput::OpStatus(if control.abandoned() {
                        Err(OpError::Abandoned)
                    } else {
                        journal::op_status(dir, &op_id).map_err(|e| storage(&e))
                    })
                }),
            ),
        };
        let dir = self.dir.clone();
        let job: Job = Box::new(move || Finished(run(&dir, &control)));
        (kind, job)
    }

    /// A worker job finished.
    pub fn job_done(&mut self, job: u64, finished: Finished) -> Vec<Out> {
        let mut out = Vec::new();
        let output = finished.0;
        // The snapshot follows our own commits.
        if let Some(file) = output.committed_file() {
            self.file = Ok(file);
        }
        let Some(mut running) = self.running.take_if(|r| r.job == job) else {
            return out;
        };
        let now = self.now_ms();
        let request = running.request;
        // A result after the deadline is abandoned, unless it committed.
        if !running.answered && Instant::now() >= running.deadline && running.control.abandon() {
            running.answered = true;
            self.reply_error(&mut out, request, deadline_exceeded());
        }
        if running.answered {
            // Already answered: only the throttle learns the real outcome.
            if let Some(attempt) = running.attempt {
                self.throttle
                    .settle(attempt, throttle_outcome(&output), now);
            }
            drop(output);
            self.start_next(&mut out);
            return out;
        }
        let short = matches!(
            running.kind,
            RunningKind::Verify | RunningKind::ExportMnemonic | RunningKind::ExportPrivateKey(_)
        );
        let outcome = match (&running.kind, output) {
            (RunningKind::Unlock, JobOutput::Unlocked(result)) => {
                let throttle = match &result {
                    Ok(_) => Outcome::Success,
                    Err(e) => e.throttle_outcome(),
                };
                let reply = match result {
                    Err(error) => Err(error.body(false)),
                    Ok((prepared, addresses)) => {
                        match self
                            .state
                            .install(running.ticket, prepared, self.auto_lock_ms, now)
                        {
                            Ok(epoch) => {
                                out.push(Out::Send(event_payload(
                                    "vault.unlocked",
                                    &serde_json::json!({ "epoch": epoch.get() }),
                                )));
                                Ok(json_result(
                                    request,
                                    &serde_json::json!({ "addresses": addresses }),
                                ))
                            }
                            // Design 0001: a result from a revoked epoch is
                            // wiped, never installed, and returns vault_locked.
                            Err(_) => Err(locked()),
                        }
                    }
                };
                (throttle, reply)
            }
            (kind, JobOutput::Checked { result, commit }) => {
                let throttle = match &result {
                    Ok(()) => Outcome::Success,
                    Err(e) => e.throttle_outcome(),
                };
                let reply = match result {
                    Err(error) => Err(error.body(short)),
                    Ok(()) => self.after_check(kind, request, commit, &mut out),
                };
                (throttle, reply)
            }
            (RunningKind::ChangePassword, JobOutput::Changed { result, commit }) => {
                let throttle = match &result {
                    Ok(()) => Outcome::Success,
                    // A weak new password still proved the current one.
                    Err(OpError::Weak) => Outcome::Success,
                    Err(e) => e.throttle_outcome(),
                };
                let reply = match result {
                    Err(error) => Err(error.body(false)),
                    Ok(()) => Ok(json_result(
                        request,
                        &durability(serde_json::json!({}), commit.as_ref()),
                    )),
                };
                (throttle, reply)
            }
            (kind, JobOutput::Written { result, commit }) => {
                let reply = match result {
                    Err(error) => Err(error.body(false)),
                    Ok((prepared, addresses, phrase)) => {
                        // Create and import unlock, as in JS, unless a lock
                        // happened meanwhile; the vault is written either way.
                        if let Ok(epoch) =
                            self.state
                                .install(running.ticket, prepared, self.auto_lock_ms, now)
                        {
                            out.push(Out::Send(event_payload(
                                "vault.unlocked",
                                &serde_json::json!({ "epoch": epoch.get() }),
                            )));
                        }
                        let durable = !commit.as_ref().is_some_and(|c| c.done == Done::NotDurable);
                        match (kind, phrase) {
                            (RunningKind::Create, Some(phrase)) => {
                                create_reply(request, &addresses, &phrase, durable)
                            }
                            _ => Ok(json_result(
                                request,
                                &durability(
                                    serde_json::json!({ "addresses": addresses }),
                                    commit.as_ref(),
                                ),
                            )),
                        }
                    }
                };
                (Outcome::NotTried, reply)
            }
            (RunningKind::NodeWrite, JobOutput::NodeWritten(result)) => {
                let reply = match result {
                    Err(error) => Err(error.body(false)),
                    Ok((outcome, mut public)) => {
                        let status = match outcome {
                            journal::Outcome::Installed => "installed",
                            journal::Outcome::PendingRecovery => "pending_recovery",
                            journal::Outcome::Corrupt => "corrupt",
                            // Abandoned jobs were already answered.
                            journal::Outcome::Abandoned => {
                                return self.internal_reply(out, request);
                            }
                        };
                        public.insert("status".into(), serde_json::Value::String(status.into()));
                        Ok(json_result(request, &public))
                    }
                };
                (Outcome::NotTried, reply)
            }
            (RunningKind::OpStatus, JobOutput::OpStatus(result)) => {
                let reply = result
                    .map(|status| json_result(request, &serde_json::json!({ "status": status })))
                    .map_err(|e| e.body(false));
                (Outcome::NotTried, reply)
            }
            (RunningKind::Precheck { short, ready_at }, JobOutput::Prechecked(result)) => {
                let reply = match result {
                    Err(error) => Err(error.body(*short)),
                    // The file is fine: the attempt itself has to wait.
                    Ok(()) => Err(throttled_error(ready_at.saturating_sub(now).max(1))),
                };
                (Outcome::NotTried, reply)
            }
            (RunningKind::Reconcile { install }, JobOutput::Reconciled { result, tried }) => {
                let reply = match result {
                    Err(error) => Err(error.body(false)),
                    Ok(None) => Ok(json_result(
                        request,
                        &serde_json::json!({ "status": "not_committed" }),
                    )),
                    Ok(Some(found)) => {
                        // Installs only if main asked (no lock since the
                        // mutation started) and no lock happened here since.
                        if *install
                            && let Some(prepared) = found.prepared
                            && let Ok(epoch) =
                                self.state
                                    .install(running.ticket, prepared, self.auto_lock_ms, now)
                        {
                            out.push(Out::Send(event_payload(
                                "vault.unlocked",
                                &serde_json::json!({ "epoch": epoch.get() }),
                            )));
                        }
                        reconcile_reply(request, found.addresses.as_ref(), found.phrase.as_ref())
                    }
                };
                (tried, reply)
            }
            _ => (Outcome::NotTried, Err(internal())),
        };
        let (throttle, reply) = outcome;
        if let Some(attempt) = running.attempt {
            self.throttle.settle(attempt, throttle, now);
        }
        match reply {
            Ok(Some(payload)) => out.push(Out::Send(payload)),
            Ok(None) => out.push(Out::Send(error_payload(request, &internal()))),
            Err(error) => self.reply_error(&mut out, request, error),
        }
        self.start_next(&mut out);
        out
    }

    /// The second half of verify, delete and the exports, after the password
    /// checked out.
    fn after_check(
        &mut self,
        kind: &RunningKind,
        request: u64,
        commit: Option<Commit>,
        out: &mut Vec<Out>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ErrorBody> {
        match kind {
            RunningKind::Verify => Ok(json_result(request, &serde_json::json!({}))),
            RunningKind::Delete => {
                self.lock_now(LockReason::Delete, out);
                Ok(json_result(
                    request,
                    &durability(serde_json::json!({}), commit.as_ref()),
                ))
            }
            RunningKind::ExportMnemonic => {
                let mnemonic = self.state.mnemonic().map_err(|_| locked())?;
                secret_result(request, "mnemonic_b64", mnemonic.phrase().as_bytes())
            }
            RunningKind::ExportPrivateKey(account) => {
                let key = self
                    .state
                    .user_wallet(*account)
                    .map_err(locked_or_internal)?;
                private_key_result(request, key.to_secret_bytes().as_slice())
            }
            _ => Err(internal()),
        }
    }

    /// An internal error for a request that shouldn't have reached here;
    /// keeps the worker slot moving.
    fn internal_reply(&mut self, mut out: Vec<Out>, request: u64) -> Vec<Out> {
        self.reply_error(&mut out, request, internal());
        self.start_next(&mut out);
        out
    }

    fn reply_error(&self, out: &mut Vec<Out>, id: u64, error: ErrorBody) {
        out.push(Out::Send(error_payload(id, &error)));
    }
}

/// A committed reconcile: `status`, the addresses (create, import) and the
/// onboarding phrase (create).
fn reconcile_reply(
    request: u64,
    addresses: Option<&Addresses>,
    phrase: Option<&Mnemonic>,
) -> Result<Option<Zeroizing<Vec<u8>>>, ErrorBody> {
    let mut response = SecretResponse::new(request)
        .public("status", &"committed")
        .map_err(|_| internal())?;
    if let Some(addresses) = addresses {
        response = response
            .public("addresses", addresses)
            .map_err(|_| internal())?;
    }
    if let Some(phrase) = phrase {
        response = response.secret("mnemonic_b64", phrase.phrase().as_bytes());
    }
    response.finish().map(Some).map_err(|_| internal())
}

/// Distinguishes a present field (even `null`) from a missing one: with
/// `#[serde(default)]`, missing is `None` and `null` is `Some(None)`.
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

/// A vault fingerprint: 64 lowercase hex digits (SHA-256).
fn is_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// create's reply: the addresses, and the phrase for backup display.
fn create_reply(
    request: u64,
    addresses: &Addresses,
    phrase: &Mnemonic,
    durable: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>, ErrorBody> {
    let mut response = SecretResponse::new(request)
        .public("addresses", addresses)
        .map_err(|_| internal())?;
    if !durable {
        response = response.public("durable", &false).map_err(|_| internal())?;
    }
    response
        .secret("mnemonic_b64", phrase.phrase().as_bytes())
        .finish()
        .map(Some)
        .map_err(|_| internal())
}

/// Adds `"durable": false` to a committed result whose directory flush
/// failed (design 0001: committed changes are never reported as errors).
fn durability(mut result: serde_json::Value, commit: Option<&Commit>) -> serde_json::Value {
    if commit.is_some_and(|c| c.done == Done::NotDurable)
        && let Some(object) = result.as_object_mut()
    {
        object.insert("durable".into(), serde_json::Value::Bool(false));
    }
    result
}

/// The throttle outcome of a job, whether or not its request was answered.
fn throttle_outcome(output: &JobOutput) -> Outcome {
    let result = match output {
        JobOutput::Unlocked(result) => result.as_ref().map(|_| ()),
        JobOutput::Checked { result, .. } | JobOutput::Changed { result, .. } => {
            result.as_ref().map(|_| ())
        }
        JobOutput::Reconciled { tried, .. } => return *tried,
        JobOutput::Written { .. }
        | JobOutput::NodeWritten(_)
        | JobOutput::OpStatus(_)
        | JobOutput::Prechecked(_) => return Outcome::NotTried,
    };
    match result {
        Ok(_) => Outcome::Success,
        // A weak new password still proved the current one.
        Err(OpError::Weak) => Outcome::Success,
        Err(error) => error.throttle_outcome(),
    }
}

/// `throttled`, with the wait (design 0001, Throttling).
fn throttled_error(retry_after_ms: u64) -> ErrorBody {
    let seconds = retry_after_ms.div_ceil(1000);
    ErrorBody::new(
        ErrorCode::Throttled,
        format!("Too many attempts. Try again in {seconds} seconds."),
    )
    .with_data(serde_json::json!({ "retry_after_ms": retry_after_ms }))
}

fn cancelled() -> ErrorBody {
    ErrorBody::new(ErrorCode::Cancelled, "Cancelled")
}

fn deadline_exceeded() -> ErrorBody {
    ErrorBody::new(ErrorCode::Deadline, "Deadline exceeded")
}

fn locked() -> ErrorBody {
    ErrorBody::new(ErrorCode::VaultLocked, MSG_LOCKED)
}

pub(crate) fn internal() -> ErrorBody {
    ErrorBody::new(ErrorCode::Internal, "Internal error")
}

pub(crate) fn locked_or_internal(error: fc_vault::Error) -> ErrorBody {
    match error {
        fc_vault::Error::Locked => ErrorBody::new(ErrorCode::VaultLocked, MSG_LOCKED),
        fc_vault::Error::Keys(fc_keys::Error::IndexOutOfRange(_)) => {
            ErrorBody::new(ErrorCode::InvalidArgument, "Index out of range")
        }
        _ => internal(),
    }
}

fn check_strength(password: &SecretBytes) -> Result<(), ErrorBody> {
    let strong = password.as_str().is_ok_and(format::is_strong_enough);
    if strong {
        Ok(())
    } else {
        Err(ErrorBody::new(ErrorCode::WeakPassword, MSG_WEAK))
    }
}

/// `keys.radicle_did { public_key }`: the 32-byte Ed25519 key as hex, with
/// or without `0x`. Parsed as bytes, so no input can split a character.
fn radicle_did(id: u64, public_key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ErrorBody> {
    let invalid = || ErrorBody::new(ErrorCode::InvalidArgument, "Invalid public key");
    let digits = public_key.as_bytes();
    let digits = digits.strip_prefix(b"0x").unwrap_or(digits);
    if digits.len() != 64 {
        return Err(invalid());
    }
    let nibble = |digit: u8| {
        char::from(digit)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    let mut key = [0u8; 32];
    let (pairs, _) = digits.as_chunks::<2>();
    for (byte, &[high, low]) in key.iter_mut().zip(pairs) {
        let (Some(high), Some(low)) = (nibble(high), nibble(low)) else {
            return Err(invalid());
        };
        *byte = high << 4 | low;
    }
    Ok(json_result(
        id,
        &serde_json::json!({ "did": multiformats::did_key(&key) }),
    ))
}

fn json_result<R: Serialize>(id: u64, result: &R) -> Option<Zeroizing<Vec<u8>>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(512));
    message::write_result(&mut *payload, id, result).ok()?;
    Some(payload)
}

fn secret_result(
    id: u64,
    field: &'static str,
    secret: &[u8],
) -> Result<Option<Zeroizing<Vec<u8>>>, ErrorBody> {
    SecretResponse::new(id)
        .secret(field, secret)
        .finish()
        .map(Some)
        .map_err(|_| internal())
}

/// A private key as `private_key_hex` (`0x` + hex, like ethers'
/// `wallet.privateKey`; design 0001, "Secret fields").
fn private_key_result(id: u64, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, ErrorBody> {
    SecretResponse::new(id)
        .secret_hex("private_key_hex", key)
        .finish()
        .map(Some)
        .map_err(|_| internal())
}

/// An error reply. One that wouldn't fit a frame, say a message quoting
/// input past fc-evm's bounds, would end the core when framed (#86): its code
/// stays, its message becomes a fixed one, and its data goes.
fn error_payload(id: u64, error: &ErrorBody) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(256));
    let written = message::write_error(&mut *payload, id, error);
    if written.is_err() || payload.len() > fc_protocol::frame::MAX_PAYLOAD {
        payload.zeroize();
        let fixed = ErrorBody::new(error.code, "Error too large to report");
        let _ = message::write_error(&mut *payload, id, &fixed);
    }
    payload
}

fn event_payload<D: Serialize>(event: &str, data: &D) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(128));
    let _ = message::write_event(&mut *payload, event, data);
    payload
}

fn locked_event(locked: Locked) -> Zeroizing<Vec<u8>> {
    let reason = match locked.reason {
        LockReason::Manual => "manual",
        LockReason::Auto => "auto",
        LockReason::Delete => "delete",
        LockReason::Shutdown => "shutdown",
    };
    event_payload(
        "vault.locked",
        &serde_json::json!({ "reason": reason, "epoch": locked.epoch.get() }),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Startup work that touches storage, run off the event loop: adoption
/// tightens an existing vault file to 0600 in place (metadata only; quick
/// unlock's content fingerprint is unaffected), then the file is snapshot.
pub fn startup_snapshot(dir: &Path) -> (FileSnapshot, NodeRecovery) {
    // Finish an interrupted node identity write before anything else
    // (design 0001: before core.hello is answered and before any node write).
    let recovery = startup_recovery(dir);
    match fsx::tighten(&dir.join(VAULT_FILE)) {
        Ok(true) => crate::log::info("tightened the vault file to 0600", serde_json::json!({})),
        Ok(false) => {}
        Err(e) => crate::log::warn(
            "could not tighten the vault file",
            serde_json::json!({ "error": e.kind().to_string() }),
        ),
    }
    (snapshot(dir), recovery)
}

/// What startup recovery leaves for main to act on, in `core.hello`'s
/// `node_recovery`: `None` when every node identity is consistent; otherwise
/// `{ status: "pending_recovery" | "corrupt", op_id?, node? }`, and main keeps
/// that node stopped (design 0001: main starts a node only on `installed`).
pub type NodeRecovery = Option<serde_json::Value>;

fn startup_recovery(dir: &Path) -> NodeRecovery {
    // Every affected node, and whether any is pending (rather than corrupt).
    let mut affected: Vec<String> = Vec::new();
    let mut pending = None;
    match journal::recover(dir) {
        Ok(outcome) => {
            if outcome != journal::Recovered::Nothing {
                crate::log::info(
                    "node identity recovery",
                    serde_json::json!({ "outcome": format!("{outcome:?}") }),
                );
            }
        }
        Err(e) => {
            crate::log::error(
                "node identity recovery failed",
                serde_json::json!({ "error": e.kind().to_string() }),
            );
            match journal::pending(dir) {
                Some((op_id, node)) => {
                    affected.push(node);
                    pending = Some(op_id);
                }
                // The outstanding journal's node is unknown: every node.
                None => {
                    affected.extend(["bee".to_owned(), "radicle".to_owned()]);
                    pending = Some(String::new());
                }
            }
        }
    }
    // Nodes known to be broken stay reported on every start, until a write
    // installs them again; unreadable means every node.
    match journal::unresolved(dir) {
        Ok(nodes) => affected.extend(nodes),
        Err(_) => affected.extend(["bee".to_owned(), "radicle".to_owned()]),
    }
    affected.sort();
    affected.dedup();
    let status = if pending.is_some() {
        "pending_recovery"
    } else {
        "corrupt"
    };
    match affected.as_slice() {
        [] => None,
        // One node: name it (and the pending op, if that's what it is).
        [node] => {
            let mut report = serde_json::json!({ "status": status, "node": node });
            if let Some(op_id) = pending.filter(|id| !id.is_empty()) {
                report["op_id"] = op_id.into();
            }
            Some(report)
        }
        // Several: a report without a node covers every node.
        _ => Some(serde_json::json!({ "status": status })),
    }
}

/// The vault file's SHA-256 (quick unlock binds to it), or `None` if
/// missing. Never called on the event loop.
fn snapshot(dir: &Path) -> FileSnapshot {
    read_vault(dir).map(|contents| contents.map(|c| sha256_hex(c.as_bytes())))
}

/// Reads the vault file: `None` if missing. Only a regular file of bounded
/// size is read, so a FIFO or a huge file can't stall anything.
fn read_vault(dir: &Path) -> Result<Option<String>, OpError> {
    let path = dir.join(VAULT_FILE);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(storage(&e)),
    };
    if !metadata.is_file() {
        return Err(OpError::Storage("not_regular"));
    }
    if metadata.len() > MAX_VAULT_BYTES {
        return Err(OpError::Storage("too_large"));
    }
    match std::fs::read_to_string(&path) {
        Ok(contents) => Ok(Some(contents)),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => Err(OpError::Corrupt),
        Err(e) => Err(storage(&e)),
    }
}

fn storage(error: &std::io::Error) -> OpError {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => OpError::Storage("permission"),
        std::io::ErrorKind::StorageFull => OpError::Storage("no_space"),
        _ => OpError::Storage("other"),
    }
}

fn open(dir: &Path, password: &SecretBytes) -> Result<format::Opened, OpError> {
    let contents = read_vault(dir)?.ok_or(OpError::NoVault)?;
    format::open(&contents, password.as_bytes()).map_err(OpError::from_vault)
}

fn addresses_of(prepared_from: &Mnemonic) -> Result<Addresses, OpError> {
    let keys = freedom::derive_all(&prepared_from.to_seed()).map_err(|_| OpError::Internal)?;
    Ok(Addresses {
        user_wallet: keys.user_wallet.address().to_string(),
        bee_wallet: keys.bee_wallet.address().to_string(),
    })
}

fn job_unlock(
    dir: &Path,
    password: &SecretBytes,
    control: &JobControl,
) -> Result<(Prepared, Addresses), OpError> {
    if control.abandoned() {
        return Err(OpError::Abandoned);
    }
    let opened = open(dir, password)?;
    let addresses = addresses_of(&opened.mnemonic)?;
    Ok((Prepared::new(opened.mnemonic), addresses))
}

/// verify and the exports' password check: JS `vault.verifyPassword`, which
/// only decrypts (no version or mnemonic checks).
fn job_verify(dir: &Path, password: &SecretBytes, control: &JobControl) -> Result<(), OpError> {
    if control.abandoned() {
        return Err(OpError::Abandoned);
    }
    let contents = read_vault(dir)?.ok_or(OpError::NoVault)?;
    format::verify_password(&contents, password.as_bytes()).map_err(OpError::from_vault)
}

/// A password check the throttle refused (#82): what the file says without
/// the password, in design 0001's order (`no_vault`, then
/// `unsupported_vault_version` if `version`, or a corrupt file). `Ok`: the
/// answer is `throttled`.
fn job_precheck(dir: &Path, version: bool, control: &JobControl) -> Result<(), OpError> {
    if control.abandoned() {
        return Err(OpError::Abandoned);
    }
    let contents = read_vault(dir)?.ok_or(OpError::NoVault)?;
    format::check_structure(&contents, version).map_err(OpError::from_vault)
}

/// The worker's commit claim, right before the rename or unlink. After it,
/// the job can no longer be abandoned.
fn claim(control: &JobControl) -> bool {
    let claimed = control.commit();
    if claimed {
        crate::testhooks::commit_delay();
    }
    claimed
}

fn job_delete(dir: &Path, password: &SecretBytes, control: &JobControl) -> JobOutput {
    let not_committed = |error| JobOutput::Checked {
        result: Err(error),
        commit: None,
    };
    if control.abandoned() {
        return not_committed(OpError::Abandoned);
    }
    if let Err(error) = open(dir, password) {
        return not_committed(error);
    }
    match fsx::remove(&dir.join(VAULT_FILE), || claim(control)) {
        Ok(Some(done)) => JobOutput::Checked {
            result: Ok(()),
            commit: Some(Commit { done, file: None }),
        },
        Ok(None) => not_committed(OpError::Abandoned),
        Err(e) => not_committed(storage(&e)),
    }
}

/// Seals `mnemonic` under `password` and writes it durably, after checking
/// that the staged file decrypts to the same mnemonic.
fn write_vault(
    dir: &Path,
    mnemonic: &Mnemonic,
    password: &[u8],
    control: &JobControl,
) -> Result<Commit, OpError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let created_at =
        format::iso_timestamp(u64::try_from(millis).unwrap_or(0)).map_err(|_| OpError::Internal)?;
    let params = SealParams::random(&mut OsRng, created_at).map_err(|_| OpError::Internal)?;
    let contents = format::seal(mnemonic, password, &params).map_err(|_| OpError::Internal)?;
    std::fs::create_dir_all(dir).map_err(|e| storage(&e))?;
    let expected = mnemonic.phrase().to_owned();
    let expected = Zeroizing::new(expected);
    fsx::replace(
        &dir.join(VAULT_FILE),
        contents.as_bytes(),
        |staged| {
            let staged = std::fs::read_to_string(staged).map_err(|e| e.kind().to_string())?;
            let opened = format::open(&staged, password).map_err(|e| e.to_string())?;
            if opened.mnemonic.phrase() == expected.as_str() {
                Ok(())
            } else {
                Err("staged vault decrypts to a different mnemonic".into())
            }
        },
        || claim(control),
    )
    .map(|done| Commit {
        done,
        file: Some(sha256_hex(contents.as_bytes())),
    })
    .map_err(|e| match e {
        fsx::WriteError::Io(e) => storage(&e),
        fsx::WriteError::Abandoned => OpError::Abandoned,
        fsx::WriteError::Check(reason) => {
            crate::log::error(
                "the staged vault failed its check",
                serde_json::json!({ "reason": reason }),
            );
            OpError::Internal
        }
    })
}

fn job_change(
    dir: &Path,
    current: &SecretBytes,
    new: &SecretBytes,
    control: &JobControl,
) -> JobOutput {
    if control.abandoned() {
        return JobOutput::Changed {
            result: Err(OpError::Abandoned),
            commit: None,
        };
    }
    let opened = match open(dir, current) {
        Ok(opened) => opened,
        Err(error) => {
            return JobOutput::Changed {
                result: Err(error),
                commit: None,
            };
        }
    };
    if !new.as_str().is_ok_and(format::is_strong_enough) {
        return JobOutput::Changed {
            result: Err(OpError::Weak),
            commit: None,
        };
    }
    match write_vault(dir, &opened.mnemonic, new.as_bytes(), control) {
        Ok(commit) => JobOutput::Changed {
            result: Ok(()),
            commit: Some(commit),
        },
        Err(error) => JobOutput::Changed {
            result: Err(error),
            commit: None,
        },
    }
}

fn job_create(
    dir: &Path,
    password: &SecretBytes,
    words: WordCount,
    control: &JobControl,
) -> JobOutput {
    written((|| {
        if control.abandoned() {
            return Err(OpError::Abandoned);
        }
        // Checked again here: another create or import may have run since
        // admission.
        if read_vault(dir)?.is_some() {
            return Err(OpError::Exists { import: false });
        }
        let mnemonic = Mnemonic::generate(&mut OsRng, words).map_err(|_| OpError::Internal)?;
        let phrase = Mnemonic::parse(mnemonic.phrase()).map_err(|_| OpError::Internal)?;
        let addresses = addresses_of(&mnemonic)?;
        let done = write_vault(dir, &mnemonic, password.as_bytes(), control)?;
        Ok(((Prepared::new(mnemonic), addresses, Some(phrase)), done))
    })())
}

fn job_import(
    dir: &Path,
    password: &SecretBytes,
    mnemonic: Mnemonic,
    overwrite: bool,
    control: &JobControl,
) -> JobOutput {
    written((|| {
        if control.abandoned() {
            return Err(OpError::Abandoned);
        }
        if !overwrite && read_vault(dir)?.is_some() {
            return Err(OpError::Exists { import: true });
        }
        let addresses = addresses_of(&mnemonic)?;
        let done = write_vault(dir, &mnemonic, password.as_bytes(), control)?;
        Ok(((Prepared::new(mnemonic), addresses, None), done))
    })())
}

/// A written vault's secrets, its addresses, and create's phrase.
type NewVault = (Prepared, Addresses, Option<Mnemonic>);

/// `vault.reconcile` (design 0001, "Reconciliation"): whether `op` actually
/// committed, judged from the vault file as it is now. `before` is the
/// fingerprint main recorded before the mutation.
///
/// | op | committed when |
/// |---|---|
/// | create | no vault before, one now, and it decrypts with `password` |
/// | import | the fingerprint changed, and it decrypts to `requested` |
/// | change_password | the fingerprint changed, and it decrypts with the new `password` |
/// | delete | a vault before, none now |
///
/// A wrong password or a mismatch is `Ok(None)` (not committed); only
/// storage errors are errors. The second value is the decrypt's throttle
/// outcome: the job decrypts only when the file has the committed shape, so
/// only then does it settle the attempt the loop reserved as anything but
/// `NotTried` (#78).
fn job_reconcile(
    dir: &Path,
    op: ReconcileOp,
    before: Option<&str>,
    password: &SecretBytes,
    requested: Option<&Mnemonic>,
    install: bool,
    control: &JobControl,
) -> (Result<Option<Reconciled>, OpError>, Outcome) {
    let untried = |result| (result, Outcome::NotTried);
    if control.abandoned() {
        return untried(Err(OpError::Abandoned));
    }
    let contents = match read_vault(dir) {
        Ok(contents) => contents,
        Err(error) => return untried(Err(error)),
    };
    let now = contents.as_deref().map(|c| sha256_hex(c.as_bytes()));
    let changed = now.as_deref() != before;
    let Some(contents) = contents else {
        let deleted = op == ReconcileOp::Delete && before.is_some();
        return untried(Ok(deleted.then(Reconciled::default)));
    };
    let committed_shape = match op {
        ReconcileOp::Delete => false,
        ReconcileOp::Create => before.is_none(),
        ReconcileOp::Import | ReconcileOp::ChangePassword => changed,
    };
    if !committed_shape {
        return untried(Ok(None));
    }
    let opened = match format::open(&contents, password.as_bytes()) {
        Ok(opened) => opened,
        // A wrong password counts as a failed attempt, as for unlock.
        Err(error) => return (Ok(None), OpError::from_vault(error).throttle_outcome()),
    };
    // The password checked out, whatever the rest decides.
    let tried = Outcome::Success;
    let result = match op {
        ReconcileOp::ChangePassword => Ok(Some(Reconciled::default())),
        ReconcileOp::Import
            if requested.map(Mnemonic::phrase) != Some(opened.mnemonic.phrase()) =>
        {
            Ok(None)
        }
        _ => (|| {
            let addresses = addresses_of(&opened.mnemonic)?;
            let phrase = if op == ReconcileOp::Create {
                Some(Mnemonic::parse(opened.mnemonic.phrase()).map_err(|_| OpError::Internal)?)
            } else {
                None
            };
            Ok(Some(Reconciled {
                addresses: Some(addresses),
                phrase,
                prepared: install.then(|| Prepared::new(opened.mnemonic)),
            }))
        })(),
    };
    (result, tried)
}

/// `nodes.write_identity`: builds the node's files from keys taken at job
/// start, then commits them through the journal. The commit point is the
/// journal write; after it, the reply is `installed` or `pending_recovery`.
fn job_node_write(
    identity_dir: &Path,
    op_id: &str,
    spec: &NodeSpec,
    keys: Option<Box<FreedomKeys>>,
    control: &JobControl,
) -> Result<(journal::Outcome, serde_json::Map<String, serde_json::Value>), OpError> {
    if control.abandoned() {
        return Err(OpError::Abandoned);
    }
    let keys = keys.ok_or(OpError::Internal)?;
    let built = nodes::build(spec, &keys, &mut OsRng).map_err(|e| match e {
        nodes::BuildError::Io(e) => storage(&e),
        nodes::BuildError::Config(kind) => OpError::Storage(kind),
        nodes::BuildError::Keys | nodes::BuildError::Path => OpError::Internal,
    })?;
    drop(keys);
    let files: Vec<journal::FileSpec<'_>> = built
        .files
        .iter()
        .map(|(target, contents)| journal::FileSpec {
            target: target.clone(),
            contents: contents.as_slice(),
        })
        .collect();
    let outcome = journal::write(
        identity_dir,
        op_id,
        spec.name(),
        spec.root(),
        &files,
        || claim(control),
    )
    .map_err(|e| match e {
        journal::WriteError::Io(e) => storage(&e),
        journal::WriteError::DuplicateOpId => OpError::Invalid("op_id already used"),
        journal::WriteError::TooLarge => OpError::Storage("too_large"),
        journal::WriteError::Layout => OpError::Internal,
    })?;
    if outcome == journal::Outcome::Abandoned {
        return Err(OpError::Abandoned);
    }
    Ok((outcome, built.public))
}

/// Create and import do every fallible step before the write, so nothing
/// can fail once the vault is committed.
fn written(result: Result<(NewVault, Commit), OpError>) -> JobOutput {
    match result {
        Ok((value, commit)) => JobOutput::Written {
            result: Ok(value),
            commit: Some(commit),
        },
        Err(error) => JobOutput::Written {
            result: Err(error),
            commit: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #86: an error reply too large for a frame ended the core (exit 70)
    /// once framed. It is replaced by its code with a fixed message.
    #[test]
    fn an_error_too_large_for_a_frame_still_frames() {
        let huge = ErrorBody::new(
            ErrorCode::InvalidArgument,
            "\"".repeat(fc_protocol::frame::MAX_PAYLOAD),
        )
        .with_data(serde_json::json!({ "kind": "x" }));
        let payload = error_payload(7, &huge);
        assert!(crate::transport::frame(&payload).is_some());
        let reply: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(
            reply,
            serde_json::json!({
                "type": "response", "id": 7,
                "error": { "code": "invalid_argument", "message": "Error too large to report" },
            })
        );
        // Others are unchanged.
        let small = ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters");
        let reply: serde_json::Value = serde_json::from_slice(&error_payload(8, &small)).unwrap();
        assert_eq!(reply["error"]["message"], "Invalid parameters");
    }

    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// A vault unlocked now, with a 15-minute auto-lock.
    fn unlocked() -> Vault {
        let mut vault = Vault::new(PathBuf::from("/nonexistent"), 15 * 60 * 1000);
        let prepared = Prepared::new(Mnemonic::parse(ABANDON).unwrap());
        let now = vault.now_ms();
        let ticket = vault.state.ticket();
        vault
            .state
            .install(ticket, prepared, vault.auto_lock_ms, now)
            .unwrap();
        vault
    }

    fn locked_auto(outs: &[Out]) -> bool {
        outs.iter().any(|out| {
            matches!(out, Out::Send(payload)
            if serde_json::from_slice::<serde_json::Value>(payload).is_ok_and(|m| {
                m["event"] == "vault.locked" && m["data"]["reason"] == "auto"
            }))
        })
    }

    /// #80: the lid closes with 14 minutes left; three days later the vault
    /// locks on waking, not 14 minutes after it.
    #[test]
    fn the_auto_lock_counts_time_asleep() {
        let mut vault = unlocked();
        vault.clock.sleep(Duration::from_secs(60));
        assert!(!locked_auto(&vault.tick()), "one minute in: still unlocked");
        assert!(vault.state.is_unlocked());
        vault.clock.sleep(Duration::from_secs(3 * 24 * 60 * 60));
        assert!(locked_auto(&vault.tick()));
        assert!(!vault.state.is_unlocked());
    }

    /// #80: while unlocked, the loop never waits longer than SUSPEND_CHECK,
    /// so it sees a suspend within that much of waking, however much of the
    /// auto-lock delay is left.
    #[test]
    fn the_loop_looks_at_the_clock_while_unlocked() {
        let vault = unlocked();
        let wake = vault.next_wakeup().unwrap();
        assert!(wake <= Instant::now() + SUSPEND_CHECK, "{wake:?}");
        // Locked, nothing to wait for.
        let mut vault = vault;
        vault.lock();
        assert_eq!(vault.next_wakeup(), None);
    }
}
