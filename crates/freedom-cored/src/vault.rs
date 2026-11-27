//! The vault and key methods (design 0001: "Phase 1 API", "Parity
//! contract", "Concurrency, epochs and revocation", "Deadlines, cancellation
//! and commit").
//!
//! - **Inline methods** run on the event loop and never wait: `vault.lock`,
//!   `vault.touch`, `vault.status`, `keys.*`.
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
//!   for queued and running work alike, independently of the worker. A job
//!   may claim its commit point only in the first two thirds of its
//!   deadline. A later claim stops it uncommitted, answered `deadline`, so
//!   what follows a claim has at least 10 s plus main's 15 s margin (#127).
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
use fc_protocol::message::{self, Context};
use fc_protocol::secret::{SecretBytes, SecretResponse};
use fc_store::fsx::{self, Done};
use fc_vault::format::{self, SealParams};
use fc_vault::state::{LockReason, Locked, Prepared, Ticket, VaultState};
use fc_vault::throttle::{Attempt, Outcome, Throttle};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use zeroize::{Zeroize, Zeroizing};

use crate::approvals::{Approvals, Clocks};
use crate::clock::Clock;
use crate::journal;
use crate::nodes::{self, Custody, NodeSpec};
use crate::rng::OsRng;
use crate::secrets::{self, Secrets};
use crate::worker::Job;

/// The vault file inside the identity directory.
pub const VAULT_FILE: &str = "identity-vault.json";
/// The largest vault file read. Real vaults are about 1 KB.
pub(crate) const MAX_VAULT_BYTES: u64 = 1 << 20;
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
/// What a page's SOC reads when D15's check refuses it at the vault (design
/// 0015): the text `swarm.sign_soc` gives the same refusal.
const SOC_NOT_COVERED: &str = "the page's Swarm grant doesn't cover this SOC";
const MSG_WEAK: &str = "Password must be at least 8 characters";
const MSG_INVALID_MNEMONIC: &str = "Invalid mnemonic";
const MSG_EXISTS_CREATE: &str = "Vault already exists. Use importVault to replace.";
const MSG_EXISTS_IMPORT: &str = "Vault already exists. Set overwrite=true to replace.";
const MSG_DECRYPTED_INVALID: &str = "Decrypted data is not a valid mnemonic";

/// What the vault asks the event loop to do.
pub enum Out {
    /// A JSON payload to frame and send (a response or an event).
    Send(Zeroizing<Vec<u8>>),
    /// The reply to request `id`, valid only under the vault's `epoch`
    /// (design 0008, "The sealed release"): checked again when it is handed
    /// to the writer, and sent as `vault_locked` if that epoch has ended.
    SendUnder {
        payload: Zeroizing<Vec<u8>>,
        id: u64,
        epoch: u64,
    },
    /// A job for the worker, with its ID.
    Job(u64, Job),
    /// One of the core's own chain reads (design 0012, "Phone jobs"), for
    /// the chain thread.
    ChainRead(crate::phone::ChainRead),
    /// A page request's name check (design 0012, APR-5f), for the naming
    /// thread.
    NameCheck(crate::eip1193::NameCheck),
    /// The name check of page request `tag` is no longer wanted.
    NameCancel(u64),
    /// A user's change of a Swarm grant (design 0015, D17), for the swarm
    /// thread, which detaches what a permission manifest managed of it.
    SwarmChange(crate::approvals::SwarmChange),
    /// Request `id`'s Ledger signature (design 0016, L4), authorized, for
    /// the device lane: [`Vault::ledger_signed`] answers it once signed.
    Ledger(u64, Box<crate::signing::Device>),
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
    /// Quick unlock's secrets file or key store (design 0013, PRF-1c).
    Secrets(secrets::Error),
    /// The loop abandoned the job before its commit point (it already
    /// answered the request).
    Abandoned,
    /// A request the core can't act on (`invalid_argument`).
    Invalid(&'static str),
    /// A Radicle home's gate is held (design 0008, "Identity changes").
    LockHeld,
    /// The switch can't name the identity whose key file it would remove.
    IdentityCorrupt,
    Internal,
}

impl OpError {
    fn from_secrets(error: secrets::Error) -> Self {
        match error {
            secrets::Error::Abandoned => OpError::Abandoned,
            secrets::Error::VaultStorage(kind) => OpError::Storage(kind),
            error => OpError::Secrets(error),
        }
    }

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
            OpError::Secrets(error) => secrets_body(*error),
            OpError::LockHeld => ErrorBody::new(ErrorCode::LockHeld, "The Radicle home is in use"),
            OpError::IdentityCorrupt => ErrorBody::new(
                ErrorCode::NodeIdentityCorrupt,
                "The Radicle key file names no readable identity",
            ),
            OpError::Abandoned | OpError::Internal => {
                ErrorBody::new(ErrorCode::Internal, "Internal error")
            }
        }
    }

    fn throttle_outcome(&self) -> Outcome {
        match self {
            OpError::Incorrect => Outcome::Failure,
            // An enroll or a delete reaches the secrets file with an
            // attempt reserved only once its password checked out.
            OpError::Secrets(_) => Outcome::Success,
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
    /// An RPC-key method's answer (design 0013, "RPC API keys").
    RpcKeys(Result<RpcAnswer, ErrorBody>),
}

/// What `vault.reconcile` found for a committed create or import.
#[derive(Default)]
pub struct Reconciled {
    addresses: Option<Addresses>,
    /// create: the phrase for the onboarding display.
    phrase: Option<Mnemonic>,
    /// The secrets to install, only when `install` was asked for.
    prepared: Option<Prepared>,
    /// With `vault_meta` moved: `written` once the metadata journal is
    /// gone, `pending` while it remains (design 0013).
    meta: Option<&'static str>,
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
            | JobOutput::Prechecked(_)
            | JobOutput::RpcKeys(_) => None,
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
        /// `quick_unlock: true`: the credential before the vault commits.
        quick: bool,
        /// With `vault_meta` moved, `user_knows_password`: the vault and
        /// its metadata are written as one (design 0013).
        meta: Option<bool>,
    },
    Import {
        password: SecretBytes,
        mnemonic: Mnemonic,
        overwrite: bool,
        quick: bool,
        meta: Option<bool>,
    },
    Reconcile {
        op: ReconcileOp,
        before: Option<String>,
        /// change_password: the new password.
        password: SecretBytes,
        /// import: the requested mnemonic.
        mnemonic: Option<Mnemonic>,
        install: bool,
        /// A create or an import with `vault_meta` moved: committed, it says
        /// whether its metadata is written. False for every other kind.
        meta: bool,
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
    /// `quick_unlock.enroll` (design 0013, "The re-wrap").
    QuickEnroll {
        password: SecretBytes,
    },
    QuickUnlock,
    QuickExportMnemonic,
    QuickExportPrivateKey {
        account: u32,
    },
    QuickDisable,
    /// A `secrets.*` RPC-key method (design 0013, "RPC API keys").
    RpcKeys(RpcJob),
    /// An `accounts.*` method (design 0013, "`vault-meta.json`"): run on
    /// the event loop when it reaches the queue's head ([`Vault::start_next`]).
    Accounts(crate::accounts::Op),
}

/// What an RPC-key job does.
enum RpcJob {
    Keys,
    Status,
    Change(crate::rpc_keys::Op),
}

/// What an RPC-key job found.
pub enum RpcAnswer {
    /// The providers with a key; a set's or a remove's provider is listed
    /// with its presence after it, and whether its change is durable.
    Providers(Vec<String>, Option<(String, bool)>, bool),
    /// `secrets.rpc_api_keys`: each provider's key.
    Keys(std::collections::BTreeMap<String, Zeroizing<String>>),
}

/// The RPC-key methods (design 0013, "RPC API keys").
pub const RPC_KEY_METHODS: &[&str] = &[
    "secrets.rpc_api_keys",
    "secrets.rpc_api_key_status",
    "secrets.set_rpc_api_key",
    "secrets.remove_rpc_api_key",
];

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
            Kind::Verify { .. }
            | Kind::ExportMnemonic { .. }
            | Kind::ExportPrivateKey { .. }
            | Kind::QuickEnroll { .. } => Some(false),
            Kind::Create { .. }
            | Kind::Import { .. }
            | Kind::Reconcile { .. }
            | Kind::NodeWrite { .. }
            | Kind::OpStatus { .. }
            | Kind::QuickUnlock
            | Kind::QuickExportMnemonic
            | Kind::QuickExportPrivateKey { .. }
            | Kind::QuickDisable
            | Kind::RpcKeys(_)
            | Kind::Accounts(_) => None,
        }
    }

    /// verify and the exports say "No vault found", and so does
    /// quick unlock's enroll, whose check is verify's.
    fn short_no_vault(&self) -> bool {
        matches!(
            self,
            Kind::Verify { .. }
                | Kind::ExportMnemonic { .. }
                | Kind::ExportPrivateKey { .. }
                | Kind::QuickEnroll { .. }
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
    ///
    /// Quick unlock's enroll checks the caller's password, so it shares the
    /// counter (design 0013). Its unlock and exports check none: they
    /// decrypt with the password the key store holds, which no caller
    /// supplies or learns, so they are no oracle and reserve nothing.
    fn throttled(&self) -> bool {
        match self {
            Kind::Unlock { .. }
            | Kind::Verify { .. }
            | Kind::ChangePassword { .. }
            | Kind::Delete { .. }
            | Kind::ExportMnemonic { .. }
            | Kind::ExportPrivateKey { .. }
            | Kind::QuickEnroll { .. } => true,
            Kind::Reconcile { op, .. } => *op != ReconcileOp::Delete,
            Kind::Create { .. }
            | Kind::Import { .. }
            | Kind::NodeWrite { .. }
            | Kind::OpStatus { .. }
            | Kind::QuickUnlock
            | Kind::QuickExportMnemonic
            | Kind::QuickExportPrivateKey { .. }
            | Kind::QuickDisable
            | Kind::RpcKeys(_)
            | Kind::Accounts(_) => false,
        }
    }
}

struct Pending {
    id: u64,
    kind: Kind,
    deadline: Instant,
}

/// Shared by the loop and the worker for one job: who wins the race between
/// abandoning it and committing it, and until when it may commit.
pub struct JobControl {
    state: AtomicU8,
    /// The last moment the worker may claim the commit point: two thirds
    /// into the job's deadline. What follows a claim (a rename and a
    /// directory flush, or a node write's fsyncs) then has the last third
    /// and main's watchdog margin, 25 s by default, however late it came
    /// (#127).
    claim_by: Instant,
}

const JOB_RUNNING: u8 = 0;
const JOB_ABANDONED: u8 = 1;
const JOB_COMMITTED: u8 = 2;

impl JobControl {
    fn new(claim_by: Instant) -> Arc<Self> {
        Arc::new(JobControl {
            state: AtomicU8::new(JOB_RUNNING),
            claim_by,
        })
    }

    /// Stops the job unless it already committed. True if it is stopped:
    /// by this call, or already by the worker, past its claim time. So the
    /// loop answers a job the worker stopped as it would one it stopped,
    /// without waiting for the worker's cleanup to finish.
    fn abandon(&self) -> bool {
        match self.state.compare_exchange(
            JOB_RUNNING,
            JOB_ABANDONED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => true,
            Err(state) => state == JOB_ABANDONED,
        }
    }

    /// Worker: claims the commit point. False if the job was abandoned, or
    /// if it is past its claim time: it then stops as if abandoned, and the
    /// loop answers `deadline`.
    fn commit(&self) -> bool {
        if Instant::now() >= self.claim_by {
            self.abandon();
            return false;
        }
        self.state
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
        self.state.load(Ordering::Acquire) == JOB_COMMITTED
    }

    /// Worker: whether to stop early (skip the KDF).
    fn abandoned(&self) -> bool {
        self.state.load(Ordering::Acquire) == JOB_ABANDONED
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
    QuickEnroll,
    QuickUnlock,
    QuickExportMnemonic,
    QuickExportPrivateKey(u32),
    QuickDisable,
    RpcKeys,
    /// A password check the throttle refused, checking the file first.
    /// `ready_at`: when the throttle allows the next attempt (clock ms).
    Precheck {
        short: bool,
        ready_at: u64,
    },
}

impl RunningKind {
    /// The job's answer when recovery first fails
    /// ([`recover_first`]): `storage`, for every job that reads the vault or
    /// the secrets file. `None`: the job runs anyway. Reconcile decides from
    /// the journaled vault while a metadata journal alone remains (design
    /// 0013, "`vault.reconcile`"); a node write and an op status touch
    /// neither file. An RPC-key job reads `rpc-api-keys.json`, or, backed by
    /// the key store, the secrets file through `Secrets`, which takes the
    /// secrets lock and settles the journals itself (`Secrets::load`): it
    /// never reads either file outside that lock.
    fn unrecovered(&self) -> Option<fn(OpError) -> JobOutput> {
        let answer: fn(OpError) -> JobOutput = match self {
            RunningKind::Unlock
            | RunningKind::QuickUnlock
            | RunningKind::QuickExportMnemonic
            | RunningKind::QuickExportPrivateKey(_) => |error| JobOutput::Unlocked(Err(error)),
            RunningKind::Verify
            | RunningKind::ExportMnemonic
            | RunningKind::ExportPrivateKey(_)
            | RunningKind::Delete
            | RunningKind::QuickEnroll
            | RunningKind::QuickDisable => |error| JobOutput::Checked {
                result: Err(error),
                commit: None,
            },
            RunningKind::ChangePassword => |error| JobOutput::Changed {
                result: Err(error),
                commit: None,
            },
            RunningKind::Create | RunningKind::Import => |error| JobOutput::Written {
                result: Err(error),
                commit: None,
            },
            RunningKind::Precheck { .. } => |error| JobOutput::Prechecked(Err(error)),
            RunningKind::Reconcile { .. }
            | RunningKind::NodeWrite
            | RunningKind::OpStatus
            | RunningKind::RpcKeys => return None,
        };
        Some(answer)
    }
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
    /// The lock directory main and the service processes share: Radicle
    /// homes' gates are there (design 0008).
    lock_dir: PathBuf,
    /// The node directories `serve`'s arguments name (design 0017, C1):
    /// `nodes.write_identity` writes only those, when given.
    node_roots: nodes::NodeRootArgs,
    /// The Radicle homes' gate files `serve` opened ahead (design 0017,
    /// C3): a node write's gate is taken through them when they have its
    /// home.
    radicle_gates: journal::RadicleGates,
    file: FileSnapshot,
    state: VaultState,
    throttle: Throttle,
    auto_lock_ms: u64,
    /// The auto-lock's and the throttle's time, sleep included; the
    /// approvals' too (design 0012, "Crates and clocks").
    clock: Clock,
    /// Approval tokens, Safe approvals and the fee evidence (design 0012):
    /// `sign.*` checks an authorization against them inline. A lock leaves
    /// them: a token presented while locked is burnt, as today.
    approvals: Approvals,
    /// Phone jobs and the payments' records (design 0012, PHN-1).
    phone: crate::phone::Phone,
    /// The `safe.*` requests in flight and the Safes reported deployed for
    /// the session (design 0016, SAFE-2).
    safes: crate::safe::methods::Safes,
    queue: VecDeque<Pending>,
    running: Option<Running>,
    next_job: u64,
    kdf_deadline: Duration,
    /// The secrets file and the key store, for quick unlock (design 0013):
    /// `None` until serve sets it.
    secrets: Option<Arc<Secrets>>,
    /// The RPC API keys, once `core.hello` names `rpc_api_keys` in
    /// `store_moved` (design 0013, "RPC API keys"): `None` before, and every
    /// `secrets.*` RPC-key method answers `not_moved`.
    rpc_keys: Option<Arc<crate::rpc_keys::RpcKeys>>,
    /// `safe-pending.json` (design 0013, "Pending Safe transactions"):
    /// configured at the hello; its writes `not_moved` until `store_moved`
    /// names `safe_pending`. Shared, for `accounts.remove`'s clear.
    safe_pending: Arc<crate::safe_pending::SafePending>,
    /// `wallet-intents.jsonl` (design 0013, "The intent journal"):
    /// configured at the hello; its writes `not_moved` until `store_moved`
    /// names `intents`.
    intents: crate::intents::IntentStore,
    /// `vault-meta.json` (design 0013): read until `core.hello` names
    /// `vault_meta` in `store_moved`, written once it does.
    accounts: crate::accounts::Store,
    /// `payment-history.sqlite` (design 0013, "Payment history"): every
    /// `payments.*` method answers `not_moved`, and the database stays
    /// unopened, until `store_moved` names `payments`.
    payments: crate::payments_store::Store,
}

#[derive(Deserialize)]
struct RpcKeyParams<'a> {
    id: String,
    /// Read by [`crate::rpc_keys::key_param`], never into `serde_json`'s
    /// growing buffer.
    #[serde(borrow, default)]
    api_key: Option<&'a RawValue>,
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
struct AccountParams {
    account: u32,
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
    /// Required once `vault_meta` is moved, ignored before (design 0013,
    /// "`user_knows_password`").
    #[serde(default)]
    user_knows_password: Option<bool>,
    /// Writes quick unlock's credential before the vault commits (design
    /// 0013, "The re-wrap").
    #[serde(default)]
    quick_unlock: bool,
}

#[derive(Deserialize)]
struct ImportParams<'a> {
    #[serde(borrow)]
    password_b64: &'a RawValue,
    #[serde(borrow)]
    mnemonic_b64: &'a RawValue,
    #[serde(default)]
    overwrite: bool,
    /// As create's.
    #[serde(default)]
    quick_unlock: bool,
    /// As create's.
    #[serde(default)]
    user_knows_password: Option<bool>,
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
    /// Design 0008's form of the Radicle write: `"sealed"`. Absent, today's
    /// form, which the add-on needs (the transitional selector).
    custody: Option<String>,
    /// With `custody: "sealed"`: wipe the home's state too.
    wipe: Option<bool>,
}

#[derive(Deserialize)]
struct OpStatusParams {
    op_id: String,
}

/// Whether the write derives a key: every form but 0008's sealed Radicle
/// form, which writes none.
fn needs_keys(spec: &NodeSpec) -> bool {
    !matches!(
        spec,
        NodeSpec::Radicle {
            custody: Custody::Sealed { .. },
            ..
        }
    )
}

fn node_spec(p: NodeWriteParams) -> Option<NodeSpec> {
    let absolute = |dir: Option<String>| dir.map(PathBuf::from).filter(|path| path.is_absolute());
    match p.node.as_str() {
        "bee" if p.custody.is_some() || p.wipe.is_some() => None,
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
            let custody = match (p.custody.as_deref(), p.wipe) {
                (None, None) => Custody::KeyFile,
                (Some("sealed"), wipe) => Custody::Sealed {
                    wipe: wipe.unwrap_or(false),
                },
                _ => return None,
            };
            Some(NodeSpec::Radicle {
                home: absolute(p.home)?,
                alias,
                custody,
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
struct PublicKeyParams {
    public_key: String,
}

#[derive(Deserialize)]
struct RecipientParams {
    recipient: String,
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
    pub fn new(dir: PathBuf, lock_dir: PathBuf, auto_lock_ms: u64) -> Self {
        Vault {
            // Replaced by the startup snapshot before core.hello is answered,
            // and no vault request is accepted before that.
            file: Err(OpError::Storage("not_ready")),
            accounts: crate::accounts::Store::new(dir.clone()),
            dir,
            lock_dir,
            node_roots: nodes::NodeRootArgs::default(),
            radicle_gates: journal::RadicleGates::default(),
            state: VaultState::new(),
            throttle: Throttle::new(),
            auto_lock_ms,
            clock: Clock::new(),
            approvals: Approvals::new(),
            phone: crate::phone::Phone::new(),
            safes: crate::safe::methods::Safes::new(),
            queue: VecDeque::new(),
            running: None,
            next_job: 1,
            kdf_deadline: crate::testhooks::kdf_deadline(KDF_DEADLINE),
            secrets: None,
            rpc_keys: None,
            safe_pending: Arc::new(crate::safe_pending::SafePending::new()),
            intents: crate::intents::IntentStore::new(),
            payments: crate::payments_store::Store::new(),
        }
    }

    /// The secrets file and key store quick unlock uses.
    pub fn set_secrets(&mut self, secrets: Arc<Secrets>) {
        self.secrets = Some(secrets);
    }

    /// The node directories `serve`'s arguments name (design 0017, C1).
    pub fn set_node_roots(&mut self, roots: nodes::NodeRootArgs) {
        self.node_roots = roots;
    }

    /// The Radicle gate files `serve` opened ahead (design 0017, C3).
    pub fn set_radicle_gates(&mut self, gates: journal::RadicleGates) {
        self.radicle_gates = gates;
    }

    /// Installs the startup snapshot.
    pub fn set_snapshot(&mut self, file: FileSnapshot) {
        self.file = file;
        // Startup recovery has settled the vault and metadata journal: the
        // records as it left it (G20), taken before a pending hello is
        // answered. A hello before it took them `Pending` while the journal
        // was there; one after takes them again.
        self.refresh_records();
    }

    /// The vault's epoch: `None` while locked.
    pub fn epoch(&self) -> Option<u64> {
        self.state.epoch().map(|epoch| epoch.get())
    }

    pub fn set_auto_lock_ms(&mut self, auto_lock_ms: u64) {
        self.auto_lock_ms = auto_lock_ms;
    }

    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// The vault's clock as the approvals read it: the clock's own, or with
    /// the `testhooks` feature a test's (`FREEDOM_CORED_TEST_APPROVAL_CLOCK`).
    fn approval_ms(&self) -> u64 {
        crate::testhooks::approval_clock(self.now_ms())
    }

    /// The vault's clock and the wall clock, for the approvals.
    fn clocks(&self) -> Clocks {
        let wall_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            });
        let wall_ms = crate::testhooks::wall_clock(wall_ms);
        Clocks {
            vault_ms: self.approval_ms(),
            wall_ms,
        }
    }

    /// The hello's `grant_root` and `grant_moved` (design 0012, "The
    /// files"): the moved files are loaded now.
    pub fn configure_grants(&mut self, root: PathBuf, moved: Vec<fc_approval::stores::StoreKind>) {
        let wall_ms = self.clocks().wall_ms;
        self.phone.configure(root.clone());
        self.approvals.configure_grants(root, moved, wall_ms);
    }

    /// The hello's `store_moved` named `rpc_api_keys`: the core serves the
    /// RPC-key methods, with `rpc-api-keys.json` under `root` (design 0013,
    /// "RPC API keys"). Whether it took the store.
    pub fn configure_rpc_keys(&mut self, root: PathBuf) -> bool {
        match &self.secrets {
            Some(secrets) => {
                self.rpc_keys = Some(crate::rpc_keys::RpcKeys::new(root, secrets.clone()));
                true
            }
            None => false,
        }
    }

    /// The hello's `grant_root`, where `safe-pending.json` is, and whether
    /// `store_moved` names `safe_pending` (design 0013, "Pending Safe
    /// transactions").
    pub fn configure_safe_pending(&mut self, root: PathBuf, moved: bool) {
        self.safe_pending.configure(root, moved);
    }

    /// The hello's `grant_root`, where `wallet-intents.jsonl` is, and
    /// whether `store_moved` names `intents` (design 0013, "The intent
    /// journal").
    pub fn configure_intents(&mut self, root: PathBuf, moved: bool) {
        self.intents.configure(root, moved);
    }

    /// The hello's `store_moved` named `payments`: the core serves the
    /// `payments.*` methods over `payment-history.sqlite` under `root`,
    /// opened at the first of them, which imports `x402-receipts.json` as
    /// `import` says (design 0013, "Payment history"; design 0017, C5).
    pub fn configure_payments(&mut self, root: PathBuf, import: crate::payments_store::Import) {
        self.payments.configure(root, import);
    }

    /// The hello's `store_moved` named `vault_meta`: the core writes
    /// `vault-meta.json` from now on (design 0013, "One writer per store").
    /// Whether it took the store.
    pub fn configure_vault_meta(&mut self) -> bool {
        self.accounts.configure_moved();
        // The core's own checks read the account records from now on (G20).
        self.refresh_records();
        true
    }

    /// The account records' snapshot the core's own checks read (G20),
    /// taken where no vault job is running: at the hello, when startup
    /// recovery has settled, at the end of every vault job, after the state
    /// it installs, and after every `accounts.*` request. So a check sees the records of the vault state
    /// it runs against, the old pair while a create or import runs and the
    /// new one once the loop has installed its result
    /// ([`crate::accounts::Records`]).
    fn refresh_records(&mut self) {
        self.approvals.set_records(self.accounts.snapshot());
        // The Safes' session reports follow the records (design 0016, D4).
        self.safes.records_changed(self.approvals.account_records());
    }

    /// An RPC-key request's job, at admission: `not_moved` until the store
    /// is named (and `rpc-api-keys.json` never opened), the parameters
    /// checked.
    fn rpc_job(&self, method: &str, raw: Option<&str>) -> Result<RpcJob, ErrorBody> {
        if self.rpc_keys.is_none() {
            return Err(ErrorBody::new(
                ErrorCode::NotMoved,
                "main still writes the RPC API keys (rpc_api_keys isn't in store_moved)",
            )
            .with_data(serde_json::json!({ "store": "rpc_api_keys" })));
        }
        let invalid = || ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters");
        Ok(match method {
            "secrets.rpc_api_keys" => RpcJob::Keys,
            "secrets.rpc_api_key_status" => RpcJob::Status,
            "secrets.set_rpc_api_key" => {
                let p = params::<RpcKeyParams>(raw)?;
                let key = p
                    .api_key
                    .and_then(|raw| crate::rpc_keys::key_param(raw.get()))
                    .ok_or_else(invalid)?;
                RpcJob::Change(crate::rpc_keys::Op::Set {
                    id: p.id,
                    key,
                    at_ms: self.clocks().wall_ms,
                })
            }
            "secrets.remove_rpc_api_key" => {
                let p = params::<RpcKeyParams>(raw)?;
                if p.id.is_empty() || p.id.len() > crate::rpc_keys::MAX_FILE_BYTES {
                    return Err(invalid());
                }
                RpcJob::Change(crate::rpc_keys::Op::Remove { id: p.id })
            }
            _ => return Err(internal()),
        })
    }

    /// The key's entry in the dApp store, for a page's `eth_accounts`
    /// (design 0012, APR-5b).
    pub fn dapp_entry(&self, key: &str) -> Option<fc_json::JsValue> {
        self.approvals.dapp_entry(key, self.clocks().wall_ms)
    }

    /// The core's own wallet list and active index for a page request's
    /// world once `vault_meta` is moved (G20b), from the records' snapshot
    /// and the vault state it belongs to
    /// ([`crate::accounts::Records::wallets`]); none before, when main's
    /// stand.
    pub fn own_wallets(&self) -> Option<(Vec<fc_json::JsValue>, Option<fc_json::JsValue>)> {
        self.approvals
            .account_records()
            .map(|records| records.wallets(&self.state))
    }

    /// Whether the dApp store has moved (design 0012, APR-5c).
    pub fn dapp_moved(&self) -> bool {
        self.approvals.dapp_moved()
    }

    /// The Swarm grants' shared handle and, once they have moved, their
    /// file (design 0015's D2), for the swarm thread the hello starts.
    pub fn swarm_grants(
        &self,
    ) -> (
        std::sync::Arc<std::sync::Mutex<fc_approval::stores::SwarmStore>>,
        Option<crate::grants::SwarmFile>,
    ) {
        self.approvals.swarm_grants()
    }

    /// A page's approved connect (design 0012, APR-5c): whether the grant
    /// was written, and its `approval.changed`, to send after the reply.
    pub fn eip1193_connect(&mut self, key: &str, account: u32, chain_id: u64) -> (bool, Vec<Out>) {
        let wall_ms = self.clocks().wall_ms;
        let written = self.approvals.page_connect(key, account, chain_id, wall_ms);
        let events = self
            .approvals
            .take_events()
            .into_iter()
            .map(Out::Send)
            .collect();
        (written, events)
    }

    /// A connected key's last use, and a switch's chain (design 0012,
    /// APR-5c).
    pub fn eip1193_touch(&mut self, key: &str, chain_id: Option<u64>) -> Vec<Out> {
        let wall_ms = self.clocks().wall_ms;
        self.approvals.page_touch(key, chain_id, wall_ms);
        self.approvals
            .take_events()
            .into_iter()
            .map(Out::Send)
            .collect()
    }

    /// Whether the vault is unlocked: a rule's signature asks main for the
    /// unlock first while it isn't (design 0012, APR-5d-2).
    pub fn unlocked(&self) -> bool {
        self.state.is_unlocked()
    }

    /// Whether the site's standing rule answers a page's signature now,
    /// judged with the core's own grant and `agent` as main read it,
    /// counting nothing (design 0012, APR-5d-2).
    pub fn eip1193_rule(
        &self,
        key: &str,
        agent: Option<bool>,
        query: &fc_eip1193::sign::RuleQuery<'_>,
    ) -> fc_eip1193::sign::RuleNow {
        self.approvals.page_rule(key, agent, query, self.clocks())
    }

    /// Whether the site's transaction rule answers a page's send now,
    /// judged with the core's own grant and `agent` as main read it,
    /// counting nothing (design 0012, APR-5e-2).
    pub fn eip1193_send_rule(
        &self,
        agent: Option<bool>,
        query: &fc_eip1193::send::RuleQuery<'_>,
    ) -> fc_eip1193::send::RuleNow {
        self.approvals.page_send_rule(agent, query, self.clocks())
    }

    /// "Always allow" ticked on a page's signature the core signed (design
    /// 0012, APR-5d-2): Q9's limited rule, and its `approval.changed`.
    pub fn eip1193_allow_signing(&mut self, key: &str, account: u32) -> Vec<Out> {
        let wall_ms = self.clocks().wall_ms;
        self.approvals.page_allow_signing(key, account, wall_ms);
        self.approvals
            .take_events()
            .into_iter()
            .map(Out::Send)
            .collect()
    }

    /// The token for a device's signature or send the user approved on the
    /// core's own prompt (design 0012, APR-5d-2, APR-5e-2; until 0016),
    /// binding what [`fc_eip1193::sign::DeviceApproval::binds`] gives: minted for the
    /// request's document and the handle of main's answer, as for a vault
    /// account's, and returned to main in the `{ device }` answer, since
    /// the device signs through main. The token, or the refusal's message.
    pub fn eip1193_device(
        &mut self,
        page: &message::PageContext,
        approved: &fc_eip1193::sign::DeviceApproval,
    ) -> Result<Zeroizing<String>, String> {
        let kind = fc_approval::Kind::from_name(approved.token_kind())
            .ok_or_else(|| internal().message)?;
        let payload = fc_evm::parse_json(approved.binds()).map_err(|_| internal().message)?;
        let clocks = self.clocks();
        self.approvals
            .page_token(
                page,
                approved.handle(),
                kind,
                approved.account(),
                &payload,
                clocks,
            )
            .map_err(|body| body.message)
    }

    /// Whether the chain's fee evidence is young enough for a page's send
    /// to be judged on it (design 0012, APR-5e-1).
    pub fn eip1193_fee_fresh(&self, chain_id: u64) -> bool {
        self.approvals.fee_fresh(chain_id, self.clocks().vault_ms)
    }

    /// The fee check on a page's prepared send: before its prompt, or at
    /// its approval with `acknowledged` (design 0012, APR-5e-1).
    pub fn eip1193_fee_check(&self, tx: &str, acknowledged: Option<bool>) -> (String, bool) {
        self.approvals
            .page_fee_check(tx, acknowledged, self.clocks())
    }

    /// The `dapp-send` token for a page's send the user approved on the
    /// core's own prompt (design 0012, APR-5e-1): minted for the request's
    /// document and the handle of main's answer, binding the prepared
    /// transaction without its nonce and "Always allow", and returned to
    /// main in the `{ send }` answer, which `sign.transaction` spends. The
    /// token, or the refusal's message.
    pub fn eip1193_send_token(
        &mut self,
        page: &message::PageContext,
        prepared: &fc_eip1193::send::Prepared,
    ) -> Result<Zeroizing<String>, String> {
        let payload = fc_evm::parse_json(&prepared.payload()).map_err(|_| internal().message)?;
        let clocks = self.clocks();
        self.approvals
            .page_token(
                page,
                prepared.handle(),
                fc_approval::Kind::DappSend,
                prepared.account(),
                &payload,
                clocks,
            )
            .map_err(|body| body.message)
    }

    /// A page's signature the user approved on the core's own prompt, or
    /// one the site's standing rule answers (design 0012, APR-5d). For an
    /// approve, the page-kind token is minted here for the request's
    /// document and the handle of main's answer, and spent at once on the
    /// signature; for a rule's, the signature goes under `{ standing }`,
    /// which `sign.*` decides again with the core's own grant and counts in
    /// Q9's rate. Either way `sign.message` or `sign.typed_data` checks it
    /// under `page` as it checks a page's own. The token never leaves the
    /// core. The signature, or whether the vault was locked and the
    /// refusal's message.
    pub fn eip1193_sign(
        &mut self,
        page: &message::PageContext,
        approved: &fc_eip1193::sign::Approved,
    ) -> Result<String, (bool, String)> {
        let failed = |body: ErrorBody| (body.code == ErrorCode::VaultLocked, body.message);
        let internal = || failed(internal());
        let method = approved.method();
        let Ok(serde_json::Value::Object(mut params)) = fc_evm::parse_json(approved.payload())
        else {
            return Err(internal());
        };
        let clocks = self.clocks();
        let token = match approved.handle() {
            Some(handle) => {
                let kind =
                    fc_approval::Kind::from_name(method.token_kind()).ok_or_else(internal)?;
                Some(
                    self.approvals
                        .page_token(
                            page,
                            handle,
                            kind,
                            approved.account(),
                            &serde_json::Value::Object(params.clone()),
                            clocks,
                        )
                        .map_err(failed)?,
                )
            }
            None => None,
        };
        params.insert(
            "key".to_owned(),
            serde_json::json!({ "kind": "account", "index": approved.account() }),
        );
        if let Some(hash) = approved.expected_hash() {
            params.insert("expected_hash".to_owned(), serde_json::json!(hash));
        }
        let authorization = match (&token, approved.handle()) {
            (Some(token), Some(handle)) => {
                serde_json::json!({ "token": token.as_str(), "handle": handle })
            }
            _ => serde_json::json!({ "standing": {} }),
        };
        params.insert("authorization".to_owned(), authorization);
        let text = Zeroizing::new(
            serde_json::to_string(&serde_json::Value::Object(params)).map_err(|_| internal())?,
        );
        drop(token);
        let context = Context {
            caller: message::CallerKind::Page,
            page: Some(page.clone()),
        };
        let mut checks = crate::signing::Checks {
            approvals: &mut self.approvals,
            context: &context,
            clocks,
        };
        let result =
            crate::signing::handle(&self.state, &mut checks, method.core_method(), Some(&text))
                .map_err(failed)?;
        let result: serde_json::Value =
            serde_json::from_str(result.get()).map_err(|_| internal())?;
        result["signature"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(internal)
    }

    /// The swarm thread's ask of the vault (design 0015, SWM-4; D15), on
    /// this thread, which holds it: [`Vault::swarm_owner`],
    /// [`Vault::swarm_sign`], [`Vault::swarm_own_sign`] or
    /// [`Vault::swarm_accounts`].
    pub fn swarm_vault(
        &mut self,
        ask: &crate::swarm::engine::VaultAsk,
    ) -> crate::swarm::engine::VaultAnswer {
        use crate::swarm::engine::{VaultAnswer, VaultAsk};
        use fc_swarm_provider::machine::Event;
        match ask {
            VaultAsk::Owner(key) => VaultAnswer::Event(Event::Owner(self.swarm_owner(*key))),
            VaultAsk::Sign(sign) => VaultAnswer::Event(Event::Signed(self.swarm_sign(sign))),
            VaultAsk::OwnSign(own) => VaultAnswer::Event(Event::Signed(self.swarm_own_sign(own))),
            VaultAsk::Accounts => VaultAnswer::Accounts(self.swarm_accounts()),
        }
    }

    /// A SOC's signature and its key's owner, unless its request has ended
    /// (main's cancel read before this ask, or the request answered: design
    /// 0015, "Deadlines and cancel"). The check and the signature hold the
    /// request's state ([`crate::swarm::engine::Cancelled::unless_ended`]),
    /// which its end takes too, so the end comes wholly before the
    /// signature (nothing signed) or after it. The key is derived for the
    /// one digest and its address, and wiped.
    fn swarm_soc_signature(
        &self,
        soc: &fc_swarm_provider::machine::SignSoc,
        cancelled: &crate::swarm::engine::Cancelled,
    ) -> Result<fc_swarm_provider::machine::Signed, fc_json::JsString> {
        crate::testhooks::swarm_sign_hold("presign");
        let signed = cancelled.unless_ended(|| {
            crate::testhooks::swarm_sign_hold("signing");
            let signed = crate::signing::chunk_signature(
                &self.state,
                soc.key,
                &soc.identifier,
                soc.span,
                &soc.payload,
            );
            if signed.is_ok() {
                crate::testhooks::swarm_signed();
            }
            signed
        });
        let Some(signed) = signed else {
            return Err(fc_json::JsString::from("Cancelled"));
        };
        let (signature, owner) =
            signed.map_err(|body| fc_json::JsString::from(body.message.as_str()))?;
        Ok(fc_swarm_provider::machine::Signed { signature, owner })
    }

    /// Main's own SOC (`swarm.feed`'s update: no page, so 0012's page-SOC
    /// decision doesn't apply): signed only with the Bee wallet key, as
    /// `swarm.feed` takes no other (SW-1), unless its request has ended
    /// ([`Vault::swarm_soc_signature`]).
    pub fn swarm_own_sign(
        &self,
        own: &crate::swarm::engine::OwnSignAsk,
    ) -> Result<fc_swarm_provider::machine::Signed, fc_json::JsString> {
        use fc_swarm_provider::machine::SignKey;
        let soc = &own.soc;
        if soc.key != SignKey::BeeWallet || soc.hold.is_some() {
            crate::log::warn(
                "swarm: main's own SOC under a key swarm.feed doesn't take",
                serde_json::json!({}),
            );
            return Err(fc_json::JsString::from(SOC_NOT_COVERED));
        }
        self.swarm_soc_signature(soc, &own.cancelled)
    }

    /// The user's accounts for a store op (`getDerivedWallets`, which is
    /// `accounts.list` for main): the core's own records once `vault_meta`
    /// has moved, else main's file as it stands, read and never written,
    /// each mnemonic account's address derived against the vault's state
    /// (the stored ones while locked).
    pub fn swarm_accounts(&self) -> Result<Vec<fc_json::JsValue>, fc_json::JsString> {
        if let Some((wallets, _)) = self.own_wallets() {
            return Ok(wallets);
        }
        self.accounts
            .listed(&self.state)
            .map_err(|body| fc_json::JsString::from(body.message.as_str()))
    }

    /// A chunk key's owner (swarm-signer.js's `resolveSwarmSigner`): `None`
    /// while the vault is locked, for which the machine gives the
    /// reference's text for each key; another failure's text. The key is
    /// derived for its address alone, and wiped.
    pub fn swarm_owner(
        &self,
        key: fc_swarm_provider::machine::SignKey,
    ) -> Result<Option<[u8; 20]>, fc_json::JsString> {
        match crate::signing::chunk_owner(&self.state, key) {
            Ok(owner) => Ok(Some(owner)),
            Err(body) if body.code == ErrorCode::VaultLocked => Ok(None),
            Err(body) => Err(fc_json::JsString::from(body.message.as_str())),
        }
    }

    /// A page's SOC's signature and its key's owner. It signs only once
    /// 0012's page-SOC decision, run again over the Swarm grants as they
    /// stand, covers it, though the machine already checked (D15): the
    /// decision's floor, which every page SOC needs whatever approved it,
    /// the site connected and holding its feed grant (which the swarm
    /// thread reads from its feed store as it asks). The rule and custody
    /// that an `auto` request also needs are the upload's guard's, in the
    /// reference's order (design 0015, "SW-1 in the core":
    /// `write-feed-rule-custody-before-write` and
    /// `write-feed-rule-off-before-write` sign after they changed, and
    /// refuse at the upload). A refusal, a locked vault or a failure is the
    /// text the machine reads. It then signs unless its request has ended
    /// ([`Vault::swarm_soc_signature`]).
    pub fn swarm_sign(
        &self,
        sign: &crate::swarm::engine::SignAsk,
    ) -> Result<fc_swarm_provider::machine::Signed, fc_json::JsString> {
        use fc_approval::standing::{SocApproval, SocAsk, SocRequest};
        use fc_swarm_provider::machine::SocKind;
        let decision = SocAsk {
            key: &sign.key,
            agent: None,
            approval: SocApproval::User,
            request: match sign.soc.kind {
                SocKind::Feed => SocRequest::Feed,
                SocKind::Raw => SocRequest::Raw,
            },
            feed_grant: sign.feed_grant,
        };
        if let Err(reason) = self.approvals.swarm_soc_covered(&decision, self.clocks()) {
            crate::log::warn(
                "swarm: a page SOC the grants don't cover reached the vault",
                serde_json::json!({ "reason": reason }),
            );
            return Err(fc_json::JsString::from(SOC_NOT_COVERED));
        }
        self.swarm_soc_signature(&sign.soc, &sign.cancelled)
    }

    /// Main asked for `chain.fee_reference`: its reply is the chain's fee
    /// evidence (design 0012, "The fee check").
    pub fn fee_asked(&mut self, id: u64, params: Option<&str>) {
        let now = self.approval_ms();
        self.approvals.fee_asked(id, params, now);
    }

    /// The chain thread served `chain.fee_reference`'s reply to `id`.
    pub fn fee_answered(&mut self, id: u64, payload: &[u8]) {
        self.approvals.fee_answered(id, payload);
    }

    /// The chain thread answered one of the core's own reads: a Safe
    /// method's (design 0016, SAFE-2), by its tag's bit, or a phone
    /// payment's (design 0012, "Phone jobs"). `past_due`: it failed at or
    /// after its deadline.
    pub fn chain_read(&mut self, tag: u64, payload: &[u8], past_due: bool) -> Vec<Out> {
        let clocks = self.clocks();
        if crate::safe::evidence::is_safe_tag(tag) {
            let mut ctx = crate::safe::methods::Ctx {
                approvals: &mut self.approvals,
                pending: &self.safe_pending,
                clocks,
                now: Instant::now(),
            };
            let mut out = self.safes.chain_read(tag, payload, past_due, &mut ctx);
            self.run_safe_marks(&mut out);
            return out;
        }
        let mut out = self
            .phone
            .chain_read(tag, payload, &mut self.approvals, clocks);
        out.extend(self.approvals.take_events().into_iter().map(Out::Send));
        out.extend(self.phone.take_events().into_iter().map(Out::Send));
        out
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
                | "quick_unlock.enroll"
                | "quick_unlock.unlock"
                | "quick_unlock.export_mnemonic"
                | "quick_unlock.export_private_key"
                | "quick_unlock.status"
                | "quick_unlock.disable"
                | "nodes.write_identity"
                | "nodes.op_status"
                | "nodes.seal_radicle_key"
                | "keys.generate_mnemonic"
                | "keys.validate_mnemonic"
                | "keys.addresses"
                | "keys.radicle_did"
        ) || RPC_KEY_METHODS.contains(&method)
            || crate::accounts::METHODS.contains(&method)
            || crate::signing::METHODS.contains(&method)
            || Approvals::handles(method)
            || crate::phone::Phone::handles(method)
            || crate::approvals::x402::METHODS.contains(&method)
            || crate::safe_pending::METHODS.contains(&method)
            || crate::intents::METHODS.contains(&method)
            || crate::payments_store::METHODS.contains(&method)
            || crate::safe::methods::METHODS.contains(&method)
    }

    /// Handles a request. Inline methods reply at once; KDF methods are
    /// queued and reply when their job finishes. The caller was checked
    /// against fc-protocol's method table before this (#101):
    /// `vault.reconcile` and `nodes.op_status` are main's own; the signing
    /// and approval methods check what each caller may do (design 0012).
    pub fn request(
        &mut self,
        id: u64,
        method: &str,
        raw: Option<&str>,
        context: &Context,
    ) -> Vec<Out> {
        let mut out = Vec::new();
        let result = match method {
            "vault.status" => self.status(id),
            "quick_unlock.status" => self.quick_status(id),
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
            "nodes.seal_radicle_key" => {
                match self.seal_radicle_key(id, raw) {
                    Ok((payload, epoch)) => out.push(Out::SendUnder { payload, id, epoch }),
                    Err(error) => self.reply_error(&mut out, id, error),
                }
                return out;
            }
            "keys.radicle_did" => {
                params::<PublicKeyParams>(raw).and_then(|p| radicle_did(id, &p.public_key))
            }
            // A Ledger key's goes on to the device lane, authorized (design
            // 0016, L4); a vault key's signs now.
            _ if crate::signing::METHODS.contains(&method) => {
                let clocks = self.clocks();
                let mut checks = crate::signing::Checks {
                    approvals: &mut self.approvals,
                    context,
                    clocks,
                };
                match crate::signing::prepare(&self.state, &mut checks, method, raw) {
                    crate::signing::Prepared::Now(result) => {
                        result.map(|result| json_result(id, &result))
                    }
                    crate::signing::Prepared::Device(device) => {
                        out.push(Out::Ledger(id, device));
                        self.after_request(&mut out);
                        return out;
                    }
                }
            }
            _ if crate::phone::Phone::handles(method) => {
                let clocks = self.clocks();
                out.extend(self.phone.request(
                    id,
                    method,
                    raw,
                    context,
                    &mut self.approvals,
                    clocks,
                ));
                out.extend(self.approvals.take_events().into_iter().map(Out::Send));
                out.extend(self.phone.take_events().into_iter().map(Out::Send));
                return out;
            }
            // Design 0013, "Payment history" (PRF-5g-2): answered at once
            // from the database, opened at the first after the name.
            _ if crate::payments_store::METHODS.contains(&method) => {
                let wall_ms = self.clocks().wall_ms;
                self.payments
                    .request(method, raw, wall_ms)
                    .map(|result| json_result(id, &result))
            }
            // x402's payments (X402-1): the caps, the token and the
            // authorization the core signs itself.
            _ if crate::approvals::x402::METHODS.contains(&method) => {
                let clocks = self.clocks();
                fc_evm::parse_json(raw.unwrap_or("{}"))
                    .map_err(|_| ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters"))
                    .and_then(|params| {
                        self.approvals
                            .x402_request(&self.state, id, method, &params, clocks)
                    })
                    .map(Some)
            }
            // Design 0013, "Pending Safe transactions" (PRF-5f): main's
            // own, answered at once from the file.
            _ if crate::safe_pending::METHODS.contains(&method) => self
                .safe_pending
                .request(method, raw)
                .map(|result| json_result(id, &result)),
            // Design 0013, "The intent journal" (PRF-5e-3): main's own,
            // answered at once; a line's time is the wall clock's.
            _ if crate::intents::METHODS.contains(&method) => {
                let wall_ms = self.clocks().wall_ms;
                self.intents
                    .request(method, raw, wall_ms)
                    .map(|result| json_result(id, &result))
            }
            _ if Approvals::handles(method) => {
                let clocks = self.clocks();
                fc_evm::parse_json(raw.unwrap_or("{}"))
                    .map_err(|_| ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters"))
                    .and_then(|params| self.approvals.request(id, method, &params, context, clocks))
                    .map(Some)
            }
            // Design 0016, SAFE-2: the Safe methods that read the chain or
            // the pending store run here; `safe.create` writes the record on
            // the vault queue, as `accounts.add_safe`.
            _ if crate::safe::methods::Safes::handles(method) => {
                let clocks = self.clocks();
                let mut ctx = crate::safe::methods::Ctx {
                    approvals: &mut self.approvals,
                    pending: &self.safe_pending,
                    clocks,
                    now: Instant::now(),
                };
                out.extend(self.safes.request(id, method, raw, context, &mut ctx));
                self.run_safe_marks(&mut out);
                return out;
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
        self.after_request(&mut out);
        out
    }

    /// What follows a request's reply: the events and changes its
    /// approvals made.
    fn after_request(&mut self, out: &mut Vec<Out>) {
        // Design 0012: one `approval.changed` per grant change, after the
        // reply that made it.
        out.extend(self.approvals.take_events().into_iter().map(Out::Send));
        // Design 0015's D17: a user's Swarm grant change goes to the swarm
        // thread after them, in order.
        out.extend(
            self.approvals
                .take_swarm_changes()
                .into_iter()
                .map(Out::SwarmChange),
        );
        // A dApp revoke or a deleted account: the phone payments' waiting
        // rules it names go.
        for narrowed in self.approvals.take_narrowed() {
            self.phone.narrowed(&narrowed);
        }
    }

    /// Request `id`'s Ledger signature came back, checked by fc-ledger
    /// (design 0016, L4): what its authorization does on a signature, then
    /// its reply ([`crate::signing::finish`]), and the events that follow.
    pub fn ledger_signed(
        &mut self,
        id: u64,
        pending: crate::signing::Pending,
        signed: fc_ledger::Signed,
    ) -> Vec<Out> {
        let mut out = Vec::new();
        let clocks = self.clocks();
        match crate::signing::finish(&mut self.approvals, clocks, pending, signed) {
            Ok(result) => match json_result(id, &result) {
                Some(payload) => out.push(Out::Send(payload)),
                None => self.reply_error(&mut out, id, internal()),
            },
            Err(error) => self.reply_error(&mut out, id, error),
        }
        self.after_request(&mut out);
        out
    }

    /// Cancels a queued request, or abandons the running one if it hasn't
    /// committed. A committed one replies with its success.
    pub fn cancel(&mut self, id: u64) -> Vec<Out> {
        let mut out = self.safes.cancel(id);
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
                self.refuse_queued(&mut out, pending, deadline_exceeded());
            }
        }
        // The Safe methods' bounds.
        out.extend(self.safes.tick(instant));
        // Phone payments' rechecks, and the events a start left.
        let clocks = self.clocks();
        out.extend(self.phone.tick(instant, clocks));
        out.extend(self.phone.take_events().into_iter().map(Out::Send));
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
        let phone = self.phone.next_wakeup();
        let safes = self.safes.next_wakeup();
        [auto_lock, running, queued, phone, safes]
            .into_iter()
            .flatten()
            .min()
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
            self.refuse_queued(out, pending, locked());
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

    /// `quick_unlock.status`, from what the loop knows: `enabled` when a
    /// quick-unlock entry (either name, design 0013, "The re-wrap") is bound
    /// to the vault file as it stands, `policy` its key's, and `available`
    /// when the key store offers a policy to enroll under.
    fn quick_status(&self, id: u64) -> Result<Option<Zeroizing<Vec<u8>>>, ErrorBody> {
        let secrets = self.secrets.as_ref().ok_or_else(internal)?;
        let view = secrets.view();
        let caps = secrets.capabilities();
        let fingerprint = self.file.as_ref().ok().and_then(Option::as_deref);
        let policy = view
            .quick_unlock
            .iter()
            .find(|(_, bound)| Some(bound.as_str()) == fingerprint)
            .map(|(policy, _)| policy.name());
        Ok(json_result(
            id,
            &serde_json::json!({
                "enabled": policy.is_some(),
                "policy": policy,
                "available": caps.offers(fc_keystore::Policy::Unattended)
                    || caps.offers(fc_keystore::Policy::UserPresence),
            }),
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

    /// `nodes.seal_radicle_key` (design 0008, "The sealed release"): the
    /// Radicle node key at `m/44'/73404'/0'/0'/0'`, sealed to the service's
    /// key for this start, `recipient`. Only the 32-byte Ed25519 secret seed
    /// is sealed: never a chain code, the seed, or another key, and no
    /// parameter selects another.
    ///
    /// - **No vault** is `no_vault`, the one answer that leads main to a
    ///   throwaway key, so it is given only when the vault file is absent.
    ///   A locked vault is `vault_locked`; a file that can't be read is its
    ///   own error.
    /// - **The recipient is checked first,** whole: 32 bytes of base64, and
    ///   not a low-order point (whose shared secret is all zero). So a
    ///   broken recipient is `invalid_argument` whatever the vault's state,
    ///   and never reads as `no_vault`.
    /// - **The epoch:** the reply carries the epoch it was sealed under
    ///   ([`Out::SendUnder`]). It is checked again when the loop hands it to
    ///   the writer, which is 0008's boundary for the start: if a lock,
    ///   manual or automatic, came while it waited for room, it goes as
    ///   `vault_locked` instead, in its place.
    /// - The derived key is wiped once sealed. The method's name is logged,
    ///   never the recipient or the ciphertext.
    fn seal_radicle_key(
        &mut self,
        id: u64,
        raw: Option<&str>,
    ) -> Result<(Zeroizing<Vec<u8>>, u64), ErrorBody> {
        use base64::Engine as _;
        let p = params::<RecipientParams>(raw)?;
        let invalid = || ErrorBody::new(ErrorCode::InvalidArgument, "Invalid recipient");
        let recipient: [u8; fc_seal::PUBLIC_KEY_LEN] = base64::engine::general_purpose::STANDARD
            .decode(p.recipient.as_bytes())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(invalid)?;
        if !fc_seal::valid_recipient(&recipient) {
            return Err(invalid());
        }
        if self.file.as_ref().map_err(|e| e.body(false))?.is_none() {
            return Err(ErrorBody::new(ErrorCode::NoVault, MSG_NO_VAULT));
        }
        let epoch = self.epoch().ok_or_else(locked)?;
        let keys = self.state.freedom_keys().map_err(locked_or_internal)?;
        let key = keys.radicle.to_secret_bytes();
        drop(keys);
        let sealed = fc_seal::seal(&recipient, &key, &mut OsRng).map_err(|e| match e {
            fc_seal::SealError::InvalidRecipient => invalid(),
            fc_seal::SealError::Rng => internal(),
        })?;
        drop(key);
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = json_result(
            id,
            &serde_json::json!({
                "enc": b64(&sealed.enc),
                "ciphertext": b64(&sealed.ciphertext),
            }),
        )
        .ok_or_else(internal)?;
        Ok((payload, epoch))
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
                if p.quick_unlock {
                    self.quick_offered()?;
                }
                Kind::Create {
                    password,
                    words,
                    quick: p.quick_unlock,
                    meta: self.knows_password(p.user_knows_password)?,
                }
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
                if p.quick_unlock {
                    self.quick_offered()?;
                }
                Kind::Import {
                    password,
                    mnemonic,
                    overwrite: p.overwrite,
                    quick: p.quick_unlock,
                    meta: self.knows_password(p.user_knows_password)?,
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
                    // Only a create or an import writes the metadata.
                    meta: self.accounts.moved()
                        && matches!(p.op, ReconcileOp::Create | ReconcileOp::Import),
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
                // Only the directory `serve`'s `--node-root` names for the
                // node, when given (design 0017, C1): refused before any
                // write or gate.
                if !self.node_roots.admit(&spec) {
                    return Err(ErrorBody::new(
                        ErrorCode::InvalidArgument,
                        "nodes.write_identity's directory isn't serve's --node-root",
                    ));
                }
                // Admitted against the current epoch (design 0001). The
                // sealed Radicle form writes no key, so needs no vault
                // (0008, "Identity changes").
                if needs_keys(&spec) && !self.state.is_unlocked() {
                    return Err(locked());
                }
                Kind::NodeWrite {
                    op_id,
                    spec,
                    keys: None,
                }
            }
            "quick_unlock.enroll" => Kind::QuickEnroll {
                password: secret(params::<PasswordParams>(raw)?.password_b64)?,
            },
            "quick_unlock.unlock" => Kind::QuickUnlock,
            "quick_unlock.export_mnemonic" => Kind::QuickExportMnemonic,
            "quick_unlock.export_private_key" => Kind::QuickExportPrivateKey {
                account: params::<AccountParams>(raw)?.account,
            },
            "quick_unlock.disable" => Kind::QuickDisable,
            _ if RPC_KEY_METHODS.contains(&method) => Kind::RpcKeys(self.rpc_job(method, raw)?),
            _ if crate::accounts::METHODS.contains(&method) => {
                Kind::Accounts(self.accounts.op(method, raw)?)
            }
            "safe.create" => Kind::Accounts(self.accounts.create_safe_op(raw)?),
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

    /// `quick_unlock: true` on create or import, at admission: refused
    /// before any work where the key store offers no policy to write the
    /// credential under (design 0013, "The re-wrap"). The job checks again.
    /// `user_knows_password` once `vault_meta` is moved: required, since
    /// the core writes it (design 0013). Before, ignored: `None`.
    fn knows_password(&self, given: Option<bool>) -> Result<Option<bool>, ErrorBody> {
        if !self.accounts.moved() {
            return Ok(None);
        }
        given.map(Some).ok_or_else(|| {
            ErrorBody::new(
                ErrorCode::InvalidArgument,
                "user_knows_password is required once vault_meta is moved",
            )
        })
    }

    fn quick_offered(&self) -> Result<(), ErrorBody> {
        let secrets = self.secrets.as_ref().ok_or_else(internal)?;
        let caps = secrets.capabilities();
        if caps.offers(fc_keystore::Policy::UserPresence)
            || caps.offers(fc_keystore::Policy::Unattended)
        {
            Ok(())
        } else {
            Err(secrets_body(secrets::Error::KeyStore(
                crate::keystore::unavailable("unsupported"),
            )))
        }
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
            if Instant::now() >= pending.deadline {
                self.refuse_queued(out, pending, deadline_exceeded());
                continue;
            }
            // `accounts.*` runs here, on the loop, behind the jobs queued
            // before it (design 0013, "`vault-meta.json`").
            let pending = match pending.kind {
                Kind::Accounts(op) => {
                    self.run_accounts(out, pending.id, op);
                    continue;
                }
                kind => Pending { kind, ..pending },
            };
            let mut pending = pending;
            if let Kind::NodeWrite { keys, spec, .. } = &mut pending.kind
                && needs_keys(spec)
            {
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
            let control = JobControl::new(pending.deadline - self.kdf_deadline / 3);
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

    /// An `accounts.*` request at the queue's head: run, answered, and its
    /// grant events and narrowings passed on, as an approval method's are.
    fn run_accounts(&mut self, out: &mut Vec<Out>, id: u64, op: crate::accounts::Op) {
        // A vault write's metadata journal is finished first: while it
        // can't be, the call fails `storage` (design 0013, "Recovery"), and
        // discovery's check keeps nothing (design 0016, D1).
        let fallback = op.fallback();
        let recovered = crate::vault_meta_journal::recover(&self.dir, self.secrets.as_deref())
            .map_err(|e| crate::accounts::storage(crate::secrets::io_kind(&e)));
        let answer = match (recovered, fallback) {
            (Ok(()), _) => {
                self.accounts
                    .run(op, &self.state, &mut self.approvals, &self.safe_pending)
            }
            (Err(error), Some(fallback)) => {
                crate::log::warn(
                    "the Ledger record check can't be kept: mismatched is empty",
                    serde_json::json!({ "code": error.code }),
                );
                Ok(fallback)
            }
            (Err(error), None) => Err(error),
        };
        let answer = answer.and_then(|answer| {
            let raw = serde_json::value::RawValue::from_string(answer.stringify())
                .map_err(|_| internal())?;
            json_result(id, &raw).ok_or_else(internal)
        });
        match answer {
            Ok(payload) => out.push(Out::Send(payload)),
            Err(error) => self.reply_error(out, id, error),
        }
        // Whatever the request wrote, or the recovery it ran (G20).
        self.refresh_records();
        out.extend(self.approvals.take_events().into_iter().map(Out::Send));
        for narrowed in self.approvals.take_narrowed() {
            self.phone.narrowed(&narrowed);
        }
    }

    /// The job of a password check the throttle refused: it reads the file,
    /// and holds no password. Recovery first, as in every job that reads
    /// the vault ([`Vault::job_for`]).
    fn precheck_job(&self, version: bool, control: Arc<JobControl>) -> Job {
        let dir = self.dir.clone();
        let secrets = self.secrets.clone();
        Box::new(move || {
            let result = recover_first(&dir, secrets.as_deref())
                .and_then(|()| job_precheck(&dir, version, &control));
            Finished(JobOutput::Prechecked(result))
        })
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
            Kind::Delete { password } => {
                let secrets = self.secrets.clone();
                (
                    RunningKind::Delete,
                    Box::new(move |dir, control| {
                        job_delete(dir, &password, secrets.as_deref(), control)
                    }),
                )
            }
            Kind::ChangePassword { current, new } => {
                let secrets = self.secrets.clone();
                (
                    RunningKind::ChangePassword,
                    Box::new(move |dir, control| {
                        job_change(dir, &current, &new, secrets.as_deref(), control)
                    }),
                )
            }
            Kind::Create {
                password,
                words,
                quick,
                meta,
            } => {
                let secrets = self.secrets.clone();
                let quick = quick.then_some(secrets);
                (
                    RunningKind::Create,
                    Box::new(move |dir, control| {
                        let quick = quick.as_ref().map(Option::as_deref);
                        let new = NewPair {
                            password: &password,
                            quick,
                            meta,
                        };
                        job_create(dir, words, &new, control)
                    }),
                )
            }
            Kind::Import {
                password,
                mnemonic,
                overwrite,
                quick,
                meta,
            } => {
                let secrets = self.secrets.clone();
                let quick = quick.then_some(secrets);
                (
                    RunningKind::Import,
                    Box::new(move |dir, control| {
                        let quick = quick.as_ref().map(Option::as_deref);
                        let new = NewPair {
                            password: &password,
                            quick,
                            meta,
                        };
                        job_import(dir, mnemonic, overwrite, &new, control)
                    }),
                )
            }
            Kind::Reconcile {
                op,
                before,
                password,
                mnemonic,
                install,
                meta,
            } => (
                RunningKind::Reconcile { install },
                Box::new(move |dir, control| {
                    let (result, tried) = job_reconcile(
                        dir,
                        op,
                        before.as_deref(),
                        &password,
                        mnemonic.as_ref(),
                        (install, meta),
                        control,
                    );
                    JobOutput::Reconciled { result, tried }
                }),
            ),
            Kind::NodeWrite { op_id, spec, keys } => {
                let lock_dir = self.lock_dir.clone();
                let gates = self.radicle_gates.clone();
                (
                    RunningKind::NodeWrite,
                    Box::new(move |dir, control| {
                        JobOutput::NodeWritten(job_node_write(
                            dir,
                            (&lock_dir, &gates),
                            &op_id,
                            &spec,
                            keys,
                            control,
                        ))
                    }),
                )
            }
            Kind::QuickEnroll { password } => {
                let secrets = self.secrets.clone();
                (
                    RunningKind::QuickEnroll,
                    Box::new(move |dir, control| JobOutput::Checked {
                        result: job_quick_enroll(dir, secrets.as_deref(), &password, control),
                        commit: None,
                    }),
                )
            }
            Kind::QuickUnlock | Kind::QuickExportMnemonic | Kind::QuickExportPrivateKey { .. } => {
                let (running, reason) = match kind {
                    Kind::QuickExportMnemonic => (
                        RunningKind::QuickExportMnemonic,
                        fc_keystore::Reason::Export,
                    ),
                    Kind::QuickExportPrivateKey { account } => (
                        RunningKind::QuickExportPrivateKey(account),
                        fc_keystore::Reason::Export,
                    ),
                    _ => (RunningKind::QuickUnlock, fc_keystore::Reason::QuickUnlock),
                };
                let secrets = self.secrets.clone();
                (
                    running,
                    Box::new(move |dir, control| {
                        JobOutput::Unlocked(job_quick_unlock(
                            dir,
                            secrets.as_deref(),
                            reason,
                            control,
                        ))
                    }),
                )
            }
            // Run on the loop before it would get here.
            Kind::Accounts(_) => (
                RunningKind::RpcKeys,
                Box::new(|_dir, _control| JobOutput::RpcKeys(Err(internal()))),
            ),
            Kind::RpcKeys(job) => {
                let rpc_keys = self.rpc_keys.clone();
                (
                    RunningKind::RpcKeys,
                    Box::new(move |_dir, control| {
                        JobOutput::RpcKeys(job_rpc_keys(rpc_keys.as_deref(), job, control))
                    }),
                )
            }
            Kind::QuickDisable => {
                let secrets = self.secrets.clone();
                (
                    RunningKind::QuickDisable,
                    Box::new(move |_dir, control| JobOutput::Checked {
                        result: job_quick_disable(secrets.as_deref(), control),
                        commit: None,
                    }),
                )
            }
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
        let secrets = self.secrets.clone();
        let unrecovered = kind.unrecovered();
        let job: Job = Box::new(move || {
            // The vault journals are finished first, under the secrets
            // file's lock (design 0013, "Recovery"). While one can't be, a
            // job that reads the vault or the secrets file answers that
            // `storage` without running: no read settles a journal itself.
            match (recover_first(&dir, secrets.as_deref()), unrecovered) {
                (Err(error), Some(unrecovered)) => Finished(unrecovered(error)),
                _ => Finished(run(&dir, &control)),
            }
        });
        (kind, job)
    }

    /// A worker job finished.
    pub fn job_done(&mut self, job: u64, finished: Finished) -> Vec<Out> {
        let mut out = self.job_finished(job, finished);
        // The job's files and the state the loop installed for it, one pair
        // (G20). The next job, if one started, hasn't run yet: its
        // `Out::Job` is in `out`.
        self.refresh_records();
        // A Safe's mark that waited for the job (design 0016, SAFE-2).
        self.run_safe_marks(&mut out);
        out
    }

    /// The Safe methods' marks that are due, written where no vault job is
    /// running, as an `accounts.*` write runs at the queue's head: each only
    /// while the record at its index is still that Safe, after the vault
    /// write's metadata journal is finished. Each request then goes on.
    /// Then the proposals whose signing and write are due (design 0016,
    /// SAFE-2's S3), each with the vault's state as it stands, against the
    /// records' snapshot of that state.
    fn run_safe_marks(&mut self, out: &mut Vec<Out>) {
        if self.running.is_some() {
            return;
        }
        for id in self.safes.take_writes() {
            let clocks = self.clocks();
            let mut ctx = crate::safe::methods::Ctx {
                approvals: &mut self.approvals,
                pending: &self.safe_pending,
                clocks,
                now: Instant::now(),
            };
            out.extend(self.safes.write(id, &self.state, &mut ctx));
            out.extend(self.approvals.take_events().into_iter().map(Out::Send));
        }
        for (id, index, address) in self.safes.take_marks() {
            let written = crate::vault_meta_journal::recover(&self.dir, self.secrets.as_deref())
                .map_err(|e| crate::accounts::storage(crate::secrets::io_kind(&e)))
                .and_then(|()| {
                    let same = self
                        .accounts
                        .snapshot()
                        .map(|records| records.record(index as f64))
                        .transpose()?
                        .flatten()
                        .is_some_and(|record| {
                            record.get("type").and_then(fc_json::JsValue::as_str) == Some("safe")
                                && record
                                    .get("address")
                                    .and_then(fc_wallet_state::value_address_bytes)
                                    == Some(address)
                        });
                    if !same {
                        return Err(ErrorBody::new(
                            ErrorCode::InvalidArgument,
                            format!("Wallet {index} is not a Safe account"),
                        ));
                    }
                    self.accounts
                        .run(
                            crate::accounts::Op::MarkSafeDeployed {
                                index: index as f64,
                                chain_id: fc_safe::constants::CHAIN_ID as f64,
                            },
                            &self.state,
                            &mut self.approvals,
                            &self.safe_pending,
                        )
                        .map(|_| ())
                });
            self.refresh_records();
            let clocks = self.clocks();
            let mut ctx = crate::safe::methods::Ctx {
                approvals: &mut self.approvals,
                pending: &self.safe_pending,
                clocks,
                now: Instant::now(),
            };
            out.extend(self.safes.marked(id, written, &mut ctx));
        }
    }

    fn job_finished(&mut self, job: u64, finished: Finished) -> Vec<Out> {
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
        // The worker stopped itself, past its claim time: the deadline's
        // answer, a little early. (The loop answers whenever it abandons.)
        if !running.answered && running.control.abandoned() {
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
            RunningKind::Verify
                | RunningKind::ExportMnemonic
                | RunningKind::ExportPrivateKey(_)
                | RunningKind::QuickEnroll
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
                                // `afterUnlock`'s migration (design 0013).
                                self.accounts.migrate_unlock(&addresses);
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
            (
                kind @ (RunningKind::QuickUnlock
                | RunningKind::QuickExportMnemonic
                | RunningKind::QuickExportPrivateKey(_)),
                JobOutput::Unlocked(result),
            ) => {
                // Quick unlock unlocks, as `vault.unlock` does, and an
                // export unlocks first, as the Touch ID path does today
                // (`quick-unlock.js`): a lock meanwhile wins.
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
                                match kind {
                                    RunningKind::QuickExportMnemonic => {
                                        self.state.mnemonic().map_err(|_| locked()).and_then(
                                            |mnemonic| {
                                                secret_result(
                                                    request,
                                                    "mnemonic_b64",
                                                    mnemonic.phrase().as_bytes(),
                                                )
                                            },
                                        )
                                    }
                                    RunningKind::QuickExportPrivateKey(account) => self
                                        .state
                                        .user_wallet(*account)
                                        .map_err(locked_or_internal)
                                        .and_then(|key| {
                                            private_key_result(
                                                request,
                                                key.to_secret_bytes().as_slice(),
                                            )
                                        }),
                                    _ => {
                                        // `afterUnlock`'s migration; the
                                        // exports migrate nothing.
                                        self.accounts.migrate_unlock(&addresses);
                                        Ok(json_result(
                                            request,
                                            &serde_json::json!({ "addresses": addresses }),
                                        ))
                                    }
                                }
                            }
                            Err(_) => Err(locked()),
                        }
                    }
                };
                (Outcome::NotTried, reply)
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
            (RunningKind::RpcKeys, JobOutput::RpcKeys(answer)) => {
                (Outcome::NotTried, answer.map(|a| rpc_reply(request, &a)))
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
                    Ok(Some(mut found)) => {
                        // Installs only if main asked (no lock since the
                        // mutation started) and no lock happened here since.
                        if *install
                            && let Some(prepared) = found.prepared.take()
                            && let Ok(epoch) =
                                self.state
                                    .install(running.ticket, prepared, self.auto_lock_ms, now)
                        {
                            out.push(Out::Send(event_payload(
                                "vault.unlocked",
                                &serde_json::json!({ "epoch": epoch.get() }),
                            )));
                        }
                        reconcile_reply(request, &found)
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
            RunningKind::Verify | RunningKind::QuickEnroll | RunningKind::QuickDisable => {
                Ok(json_result(request, &serde_json::json!({})))
            }
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

    /// A queued request that won't run (the lock, its deadline): its error,
    /// but for one whose end has an answer of its own when the store can't
    /// keep its result (discovery's check, design 0016's D1: its accounts,
    /// `mismatched` empty).
    fn refuse_queued(&self, out: &mut Vec<Out>, pending: Pending, error: ErrorBody) {
        match &pending.kind {
            Kind::Accounts(op) => match op
                .fallback()
                .and_then(|answer| answered(pending.id, &answer))
            {
                Some(payload) => {
                    crate::log::warn(
                        "the Ledger record check can't be kept: mismatched is empty",
                        serde_json::json!({ "code": error.code }),
                    );
                    out.push(Out::Send(payload));
                }
                None => self.reply_error(out, pending.id, error),
            },
            _ => self.reply_error(out, pending.id, error),
        }
    }

    /// Whether `vault_meta` is in `store_moved`: the core writes the wallet
    /// list (design 0013).
    pub fn accounts_moved(&self) -> bool {
        self.accounts.moved()
    }

    /// The Ledger records `ledger.accounts`' check reads (design 0016, D1),
    /// from the loop's snapshot of the records: none before `vault_meta` is
    /// moved.
    pub fn ledger_checks(&self) -> Option<Result<Vec<crate::accounts::LedgerCheck>, ErrorBody>> {
        self.approvals
            .account_records()
            .map(crate::accounts::Records::ledger_checks)
    }

    /// A Ledger operation's end for the accounts store (design 0016,
    /// "Accounts"): queued as an `accounts.*` request is, behind the jobs
    /// before it, and answered when it runs. A full queue refuses it
    /// `busy`, but discovery's check, which then keeps nothing.
    pub fn ledger_end(&mut self, id: u64, op: crate::accounts::Op) -> Vec<Out> {
        let mut out = Vec::new();
        let pending = Pending {
            id,
            kind: Kind::Accounts(op),
            deadline: Instant::now() + self.kdf_deadline,
        };
        if self.queue.len() >= MAX_QUEUED {
            self.refuse_queued(&mut out, pending, ErrorBody::new(ErrorCode::Busy, "Busy"));
            return out;
        }
        self.queue.push_back(pending);
        self.start_next(&mut out);
        out
    }
}

/// A committed reconcile: `status`, the addresses (create, import) and the
/// onboarding phrase (create).
fn reconcile_reply(
    request: u64,
    found: &Reconciled,
) -> Result<Option<Zeroizing<Vec<u8>>>, ErrorBody> {
    let mut response = SecretResponse::new(request)
        .public("status", &"committed")
        .map_err(|_| internal())?;
    if let Some(addresses) = &found.addresses {
        response = response
            .public("addresses", addresses)
            .map_err(|_| internal())?;
    }
    if let Some(meta) = found.meta {
        response = response.public("meta", &meta).map_err(|_| internal())?;
    }
    if let Some(phrase) = &found.phrase {
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
        | JobOutput::Prechecked(_)
        | JobOutput::RpcKeys(_) => return Outcome::NotTried,
    };
    match result {
        Ok(_) => Outcome::Success,
        // A weak new password still proved the current one.
        Err(OpError::Weak) => Outcome::Success,
        Err(error) => error.throttle_outcome(),
    }
}

/// `throttled`, with the wait (design 0001, Throttling).
/// Quick unlock's errors (design 0013, API): `key_store_unavailable` with
/// `data.reason`, `key_store_cancelled`, `not_found` with
/// `quick-unlock.js`'s message when there is no entry for this vault, and
/// `storage` for the secrets file.
fn secrets_body(error: secrets::Error) -> ErrorBody {
    use fc_keystore::KeyStoreError;
    let unavailable = |reason: &str| {
        ErrorBody::new(
            ErrorCode::KeyStoreUnavailable,
            "The key store is unavailable",
        )
        .with_data(serde_json::json!({ "reason": reason }))
    };
    match error {
        secrets::Error::KeyStore(KeyStoreError::Cancelled) => {
            ErrorBody::new(ErrorCode::KeyStoreCancelled, "Cancelled")
        }
        secrets::Error::KeyStore(KeyStoreError::Unavailable(why)) => unavailable(why.reason()),
        secrets::Error::KeyStore(KeyStoreError::Backend(backend)) => ErrorBody::new(
            ErrorCode::KeyStoreUnavailable,
            "The key store is unavailable",
        )
        .with_data(serde_json::json!({ "reason": "backend", "backend": backend.reason() })),
        secrets::Error::KeyStore(other) => unavailable(other.code()),
        secrets::Error::ForgetBacklog => unavailable("forget_backlog"),
        secrets::Error::EntryRefused => unavailable("entry_refused"),
        secrets::Error::NotEnabled => {
            ErrorBody::new(ErrorCode::NotFound, "Quick unlock not enabled")
        }
        secrets::Error::TooLong => ErrorBody::new(
            ErrorCode::InvalidArgument,
            "The password is too long for quick unlock",
        ),
        secrets::Error::Unreadable(kind) | secrets::Error::Write(kind) => {
            ErrorBody::new(ErrorCode::Storage, "Storage error")
                .with_data(serde_json::json!({ "kind": kind, "file": "secrets" }))
        }
        secrets::Error::VaultStorage(kind) => OpError::Storage(kind).body(false),
        secrets::Error::Abandoned | secrets::Error::Internal => internal(),
    }
}

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

pub(crate) fn locked() -> ErrorBody {
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

/// A request's answer from its JS value.
fn answered(id: u64, answer: &fc_json::JsValue) -> Option<Zeroizing<Vec<u8>>> {
    let raw = serde_json::value::RawValue::from_string(answer.stringify()).ok()?;
    json_result(id, &raw)
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
pub(crate) fn error_payload(id: u64, error: &ErrorBody) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(256));
    let written = message::write_error(&mut *payload, id, error);
    if written.is_err() || payload.len() > fc_protocol::frame::MAX_PAYLOAD {
        payload.zeroize();
        let fixed = ErrorBody::new(error.code, "Error too large to report");
        let _ = message::write_error(&mut *payload, id, &fixed);
    }
    payload
}

pub(crate) fn event_payload<D: Serialize>(event: &str, data: &D) -> Zeroizing<Vec<u8>> {
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
/// unlock's content fingerprint is unaffected), temp files a killed write
/// left are removed, then the file is snapshot.
/// A Radicle journal's gate is taken through `gates`, the gate files
/// `serve` opened ahead (design 0017, C3), when they have its home.
pub fn startup_snapshot(
    dir: &Path,
    lock_dir: &Path,
    gates: &journal::RadicleGates,
) -> (FileSnapshot, NodeRecovery) {
    // Finish an interrupted node identity write before anything else
    // (design 0001: before core.hello is answered and before any node write).
    let recovery = startup_recovery(dir, lock_dir, gates);
    // Then a vault delete's journal (design 0013, "Forgetting an item"):
    // committed, it is finished; never committed, its staged secrets file
    // goes. Left pending, the vault isn't read: recovery, first in every
    // job under the secrets file's lock, tries it again.
    match crate::delete_journal::startup(dir) {
        Ok(crate::delete_journal::Settled::Nothing) => {}
        Ok(settled) => crate::log::info(
            "a vault delete's journal at start",
            serde_json::json!({ "outcome": format!("{settled:?}") }),
        ),
        Err(e) => crate::log::error(
            "could not finish a vault delete's journal",
            serde_json::json!({ "error": e.kind().to_string() }),
        ),
    }
    // Then a vault write's metadata journal, before the snapshot reads the
    // vault and before the re-wrap's start rule (design 0013, "Recovery").
    // While the delete's journal above is still there, it isn't touched.
    match crate::vault_meta_journal::startup(dir) {
        Ok(crate::vault_meta_journal::Settled::Nothing) => {}
        Ok(settled) => crate::log::info(
            "a vault write's metadata journal at start",
            serde_json::json!({ "outcome": format!("{settled:?}") }),
        ),
        Err(e) => crate::log::error(
            "could not finish a vault write's metadata journal",
            serde_json::json!({ "error": e.kind().to_string() }),
        ),
    }
    match fsx::tighten(&dir.join(VAULT_FILE)) {
        Ok(true) => crate::log::info("tightened the vault file to 0600", serde_json::json!({})),
        Ok(false) => {}
        Err(e) => crate::log::warn(
            "could not tighten the vault file",
            serde_json::json!({ "error": e.kind().to_string() }),
        ),
    }
    remove_leftover_temps(dir);
    (snapshot(dir), recovery)
}

/// The files the core replaces atomically in the identity directory, whose
/// temp files a killed write can leave (#81). The vault's is an encrypted
/// copy of the mnemonic; the journal's records hold no secret, but are
/// litter all the same, and so is a vault delete's journal (design 0013)
/// killed before its rename.
const REPLACED: [&str; 7] = [
    VAULT_FILE,
    journal::JOURNAL,
    journal::DONE,
    journal::STAGING,
    journal::UNRESOLVED,
    crate::delete_journal::JOURNAL,
    crate::vault_meta_journal::JOURNAL,
];

/// Removes the temp files writes killed before their rename left (#81).
/// Startup only: the gate is held and no job runs yet, so none is live.
fn remove_leftover_temps(dir: &Path) {
    for name in REPLACED {
        match fsx::remove_temps(dir, name) {
            Ok(0) => {}
            Ok(count) => crate::log::info(
                "removed temp files a killed write left",
                serde_json::json!({ "count": count }),
            ),
            Err(e) => crate::log::warn(
                "could not remove temp files a killed write left",
                serde_json::json!({ "error": e.kind().to_string() }),
            ),
        }
    }
}

/// What startup recovery leaves for main to act on, in `core.hello`'s
/// `node_recovery`: `None` when every node identity is consistent; otherwise
/// `{ status: "pending_recovery" | "corrupt", op_id?, node? }`, and main keeps
/// that node stopped (design 0001: main starts a node only on `installed`).
pub type NodeRecovery = Option<serde_json::Value>;

fn startup_recovery(dir: &Path, lock_dir: &Path, files: &journal::RadicleGates) -> NodeRecovery {
    // Every affected node, and whether any is pending (rather than corrupt).
    let mut affected: Vec<String> = Vec::new();
    let mut pending = None;
    // A Radicle home's gate isn't waited for here: held, its journal stays,
    // and the node is reported pending without holding up core.hello (0008).
    let gates = journal::Gates {
        lock_dir: lock_dir.to_owned(),
        retry: Duration::ZERO,
        held: None,
        held_identity: None,
        files: files.clone(),
    };
    match journal::recover(dir, &gates) {
        Ok(journal::Recovered::Waiting { op_id, node }) => {
            crate::log::info(
                "node identity recovery waits for the node's gate",
                serde_json::json!({ "node": node }),
            );
            affected.push(node);
            pending = Some(op_id);
        }
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

/// Reads the vault file: `None` if missing. It is opened once and judged on
/// the open handle (#83): only a regular file is read, never through a
/// symlink, and at most [`MAX_VAULT_BYTES`], so nothing swapped in between a
/// check and the read (a FIFO, a symlink, a growing file) can stall the
/// worker or be read whole.
///
/// While a vault delete's journal ([`crate::delete_journal`]) or a vault
/// write's ([`crate::vault_meta_journal`]) is still there, the vault isn't
/// read ([`no_journal`]), so no job sees the vault the delete removed or the
/// one the write replaced.
fn read_vault(dir: &Path) -> Result<Option<String>, OpError> {
    no_journal(dir)?;
    read_bounded(&dir.join(VAULT_FILE))
}

/// `storage` while a vault journal, the delete's or the metadata's, is still
/// there. A read never settles one itself: only recovery under the secrets
/// file's lock does, first in every job ([`recover_first`]) and every
/// `accounts.*` call, and at start before any job (design 0013,
/// "Recovery"). So no install, delete or credential check runs outside that
/// lock, racing a secrets-file operation or skipping the replaced vault's
/// entry's removal.
fn no_journal(dir: &Path) -> Result<(), OpError> {
    match crate::vault_meta_journal::remaining(dir) {
        Ok(false) => Ok(()),
        Ok(true) => Err(OpError::Storage("other")),
        Err(e) => Err(storage(&e)),
    }
}

/// Recovery first, for a job: a vault delete's journal, then a vault
/// write's, under the secrets file's lock
/// ([`crate::vault_meta_journal::recover`]). `Err`: one stays.
fn recover_first(dir: &Path, secrets: Option<&Secrets>) -> Result<(), OpError> {
    crate::vault_meta_journal::recover(dir, secrets).map_err(|e| storage(&e))
}

/// The vault file's SHA-256, over its bytes as they are (`None` if
/// missing), read as [`read_vault`] reads it: what quick unlock's entry for
/// it is bound to.
fn vault_digest(dir: &Path) -> Result<Option<String>, OpError> {
    no_journal(dir)?;
    let file = match fsx::open_regular(&dir.join(VAULT_FILE), false) {
        Ok(fsx::Regular::Missing) => return Ok(None),
        Ok(fsx::Regular::Other) => return Err(OpError::Storage("not_regular")),
        Ok(fsx::Regular::File(file)) => file,
        Err(e) => return Err(storage(&e)),
    };
    match fsx::read_at_most(&file, MAX_VAULT_BYTES) {
        Ok(Some(bytes)) => Ok(Some(sha256_hex(&bytes))),
        Ok(None) => Err(OpError::Storage("too_large")),
        Err(e) => Err(storage(&e)),
    }
}

/// [`read_vault`] for any path.
fn read_bounded(path: &Path) -> Result<Option<String>, OpError> {
    let file = match fsx::open_regular(path, false) {
        Ok(fsx::Regular::Missing) => return Ok(None),
        Ok(fsx::Regular::Other) => return Err(OpError::Storage("not_regular")),
        Ok(fsx::Regular::File(file)) => file,
        Err(e) => return Err(storage(&e)),
    };
    read_handle(&file).map(Some)
}

/// A vault file's text through an open handle, at most [`MAX_VAULT_BYTES`].
fn read_handle(file: &std::fs::File) -> Result<String, OpError> {
    match fsx::read_at_most(file, MAX_VAULT_BYTES) {
        Ok(Some(bytes)) => String::from_utf8(bytes).map_err(|_| OpError::Corrupt),
        Ok(None) => Err(OpError::Storage("too_large")),
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

/// `quick_unlock.enroll` (design 0013, "The re-wrap"): the password is
/// checked as `vault.verify_password` checks it, then written as quick
/// unlock's entry, bound to the digest of the vault file it opened.
fn job_quick_enroll(
    dir: &Path,
    secrets: Option<&Secrets>,
    password: &SecretBytes,
    control: &JobControl,
) -> Result<(), OpError> {
    if control.abandoned() {
        return Err(OpError::Abandoned);
    }
    let secrets = secrets.ok_or(OpError::Internal)?;
    let contents = read_vault(dir)?.ok_or(OpError::NoVault)?;
    format::verify_password(&contents, password.as_bytes()).map_err(OpError::from_vault)?;
    let fingerprint = sha256_hex(contents.as_bytes());
    let abandoned = || control.abandoned();
    let claim = || claim(control);
    secrets
        .enroll(
            password.as_bytes(),
            &fingerprint,
            &secrets::Gate {
                abandoned: &abandoned,
                claim: &claim,
            },
        )
        .map_err(OpError::from_secrets)
}

/// `quick_unlock.unlock` and the exports: the vault opened with the
/// password quick unlock holds for it, which stays in the core.
fn job_quick_unlock(
    dir: &Path,
    secrets: Option<&Secrets>,
    reason: fc_keystore::Reason,
    control: &JobControl,
) -> Result<(Prepared, Addresses), OpError> {
    if control.abandoned() {
        return Err(OpError::Abandoned);
    }
    let secrets = secrets.ok_or(OpError::Internal)?;
    let contents = read_vault(dir)?.ok_or(OpError::NoVault)?;
    let fingerprint = sha256_hex(contents.as_bytes());
    let password = secrets
        .password(&fingerprint, reason)
        .map_err(OpError::from_secrets)?;
    if control.abandoned() {
        return Err(OpError::Abandoned);
    }
    let opened = format::open(&contents, password.expose()).map_err(OpError::from_vault)?;
    let addresses = addresses_of(&opened.mnemonic)?;
    Ok((Prepared::new(opened.mnemonic), addresses))
}

/// `quick_unlock.disable`: the entry removed, its key into `forget`.
/// An RPC-key method, on the worker (design 0013, "RPC API keys").
fn job_rpc_keys(
    rpc_keys: Option<&crate::rpc_keys::RpcKeys>,
    job: RpcJob,
    control: &JobControl,
) -> Result<RpcAnswer, ErrorBody> {
    use crate::rpc_keys::{Commit, Failure, Op};
    let rpc_keys = rpc_keys.ok_or_else(internal)?;
    if control.abandoned() {
        return Err(deadline_exceeded());
    }
    let body = |failure: Failure| match failure {
        Failure::Invalid(rule) => ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters")
            .with_data(serde_json::json!({ "rule": rule })),
        // The loop has answered already.
        Failure::Secrets(secrets::Error::Abandoned) => deadline_exceeded(),
        Failure::Secrets(error) => secrets_body(error),
        Failure::File(kind) => ErrorBody::new(ErrorCode::Storage, "Storage error")
            .with_data(serde_json::json!({ "kind": kind, "file": "rpc_api_keys" })),
        Failure::NotDurable => ErrorBody::new(ErrorCode::Storage, "Storage error")
            .with_data(serde_json::json!({ "kind": "not_durable", "file": "secrets" })),
    };
    // Every write that changes an answer is claimed through the job's
    // commit, at the first (design 0001; [`Commit`]).
    let abandoned = || control.abandoned();
    let claim = || claim(control);
    let commit = Commit::new(&abandoned, &claim);
    match job {
        RpcJob::Keys => rpc_keys.keys(&commit).map(RpcAnswer::Keys).map_err(body),
        RpcJob::Status => rpc_keys
            .status(&commit)
            .map(|ids| RpcAnswer::Providers(ids, None, true))
            .map_err(body),
        RpcJob::Change(op) => {
            let done = rpc_keys.change(&op, &commit).map_err(body)?;
            let touched = match &op {
                Op::Set { id, .. } => (id.clone(), true),
                Op::Remove { id } => (id.clone(), false),
            };
            let ids = rpc_keys.status(&commit).map_err(body)?;
            Ok(RpcAnswer::Providers(
                ids,
                Some(touched),
                done == fc_store::fsx::Done::Durable,
            ))
        }
    }
}

/// Counts what a writer is given.
struct Counted(usize);

impl std::io::Write for Counted {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// An RPC-key job's answer: `{ providers: [{ id, present }] }`, never a key,
/// with `durable: false` when a set's or a remove's change isn't durable;
/// `secrets.rpc_api_keys`'s `{ keys: [{ id, api_key }] }`, written straight
/// into the zeroized payload. That payload's size is counted first, by the
/// same writer, so its buffer is allocated once, exactly, and never grows
/// (a grown buffer would leave the keys in the allocation it freed).
fn rpc_reply(id: u64, answer: &RpcAnswer) -> Option<Zeroizing<Vec<u8>>> {
    #[derive(Serialize)]
    struct Provider<'a> {
        id: &'a str,
        present: bool,
    }
    #[derive(Serialize)]
    struct Key<'a> {
        id: &'a str,
        api_key: &'a str,
    }
    match answer {
        RpcAnswer::Providers(ids, touched, durable) => {
            let mut providers: Vec<Provider<'_>> = ids
                .iter()
                .map(|id| Provider { id, present: true })
                .collect();
            if let Some((touched, false)) = touched
                && !ids.contains(touched)
            {
                providers.push(Provider {
                    id: touched,
                    present: false,
                });
            }
            let mut result = serde_json::json!({ "providers": providers });
            if !durable {
                result["durable"] = serde_json::Value::Bool(false);
            }
            json_result(id, &result)
        }
        RpcAnswer::Keys(keys) => {
            let keys: Vec<Key<'_>> = keys
                .iter()
                .map(|(id, key)| Key {
                    id,
                    api_key: key.as_str(),
                })
                .collect();
            #[derive(Serialize)]
            struct Keys<'a> {
                keys: &'a [Key<'a>],
            }
            let keys = Keys { keys: &keys };
            let mut size = Counted(0);
            message::write_result(&mut size, id, &keys).ok()?;
            let mut payload = Zeroizing::new(Vec::with_capacity(size.0));
            message::write_result(&mut *payload, id, &keys).ok()?;
            Some(payload)
        }
    }
}

fn job_quick_disable(secrets: Option<&Secrets>, control: &JobControl) -> Result<(), OpError> {
    if control.abandoned() {
        return Err(OpError::Abandoned);
    }
    let secrets = secrets.ok_or(OpError::Internal)?;
    let abandoned = || control.abandoned();
    let claim = || claim(control);
    secrets
        .disable(&secrets::Gate {
            abandoned: &abandoned,
            claim: &claim,
        })
        .map_err(OpError::from_secrets)
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
    } else {
        crate::testhooks::refused_claim_hold();
    }
    claimed
}

/// `vault.delete`: the password checked, then the vault removed. With quick
/// unlock's entry, its removal joins the delete's journal (design 0013,
/// "Forgetting an item"; [`Secrets::delete_vault`]): a secrets file that
/// can't be read or written refuses the delete, with the vault intact.
/// Without [`Secrets`] (the unit tests' vault), the plain unlink of 0001.
fn job_delete(
    dir: &Path,
    password: &SecretBytes,
    secrets: Option<&Secrets>,
    control: &JobControl,
) -> JobOutput {
    let not_committed = |error| JobOutput::Checked {
        result: Err(error),
        commit: None,
    };
    if control.abandoned() {
        return not_committed(OpError::Abandoned);
    }
    let contents = match read_vault(dir) {
        Ok(Some(contents)) => contents,
        Ok(None) => return not_committed(OpError::NoVault),
        Err(error) => return not_committed(error),
    };
    if let Err(error) = format::open(&contents, password.as_bytes()) {
        return not_committed(OpError::from_vault(error));
    }
    let removed = match secrets {
        Some(secrets) => secrets
            .delete_vault(&sha256_hex(contents.as_bytes()), &|| claim(control))
            .map_err(OpError::from_secrets),
        None => match fsx::remove(&dir.join(VAULT_FILE), || claim(control)) {
            Ok(Some(done)) => Ok(done),
            Ok(None) => Err(OpError::Abandoned),
            Err(e) => Err(storage(&e)),
        },
    };
    match removed {
        Ok(done) => {
            // Copies a killed write left go with the vault (#81). No other
            // job runs, so none of them is live. The delete has committed:
            // a failure here is only logged.
            if let Err(e) = fsx::remove_temps(dir, VAULT_FILE) {
                crate::log::warn(
                    "could not remove the vault's leftover temp files",
                    serde_json::json!({ "error": e.kind().to_string() }),
                );
            }
            JobOutput::Checked {
                result: Ok(()),
                commit: Some(Commit { done, file: None }),
            }
        }
        Err(error) => not_committed(error),
    }
}

/// Seals `mnemonic` under `password` in the JS envelope: the vault file's
/// contents, not yet written.
fn seal_vault(mnemonic: &Mnemonic, password: &[u8]) -> Result<String, OpError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let created_at =
        format::iso_timestamp(u64::try_from(millis).unwrap_or(0)).map_err(|_| OpError::Internal)?;
    let params = SealParams::random(&mut OsRng, created_at).map_err(|_| OpError::Internal)?;
    format::seal(mnemonic, password, &params).map_err(|_| OpError::Internal)
}

/// Writes the vault file `contents` (sealing `mnemonic` under `password`)
/// durably, after checking that the staged file decrypts to the same
/// mnemonic. The job's claim, right before the rename, is the commit point.
///
/// With a re-wrap's credential `staged` ([`Secrets::stage`], written before
/// this), the vault's commit folds it in, and a failure takes it back: the
/// vault on disk keeps its own credential throughout (design 0013, "The
/// re-wrap").
fn write_vault(
    dir: &Path,
    contents: &str,
    mnemonic: &Mnemonic,
    password: &[u8],
    staged: Option<secrets::Staged<'_>>,
    control: &JobControl,
) -> Result<Commit, OpError> {
    let written = install_vault(dir, contents, mnemonic, password, control);
    if let Some(staged) = staged {
        match written {
            Ok(_) => staged.committed(password),
            Err(_) => staged.rolled_back(),
        }
    }
    written
}

fn install_vault(
    dir: &Path,
    contents: &str,
    mnemonic: &Mnemonic,
    password: &[u8],
    control: &JobControl,
) -> Result<Commit, OpError> {
    std::fs::create_dir_all(dir).map_err(|e| storage(&e))?;
    let expected = mnemonic.phrase().to_owned();
    let expected = Zeroizing::new(expected);
    let claimed = std::cell::Cell::new(false);
    let written = fsx::replace(
        &dir.join(VAULT_FILE),
        contents.as_bytes(),
        |staged| {
            // Read back through the handle that wrote it.
            let staged = read_handle(staged)
                .map_err(|e| format!("the staged vault can't be read: {e:?}"))?;
            let opened = format::open(&staged, password).map_err(|e| e.to_string())?;
            if opened.mnemonic.phrase() == expected.as_str() {
                Ok(())
            } else {
                Err("staged vault decrypts to a different mnemonic".into())
            }
        },
        || {
            if crate::testhooks::secrets_fails("vault-claim") {
                // As if the claim came past its time (#127).
                control.abandon();
                return false;
            }
            claimed.set(claim(control));
            if claimed.get() {
                // The temp file written and checked, not yet renamed.
                crate::testhooks::secrets_step("before-vault-rename");
            }
            // As if the rename failed, after the claim.
            claimed.get() && !crate::testhooks::secrets_fails("vault-rename")
        },
        &crate::testhooks::Swap,
    );
    match written {
        Ok(done) => {
            crate::testhooks::secrets_step("after-vault-rename");
            Ok(Commit {
                done,
                file: Some(sha256_hex(contents.as_bytes())),
            })
        }
        Err(fsx::WriteError::Abandoned) if claimed.get() => Err(OpError::Storage("other")),
        Err(fsx::WriteError::Abandoned) => Err(OpError::Abandoned),
        Err(fsx::WriteError::Io(e)) => Err(storage(&e)),
        Err(fsx::WriteError::Check(reason)) => {
            crate::log::error(
                "the staged vault failed its check",
                serde_json::json!({ "reason": reason }),
            );
            Err(OpError::Internal)
        }
    }
}

/// The re-wrap's first half for a job with `secrets`: see
/// [`Secrets::stage`].
fn stage<'a>(
    secrets: Option<&'a Secrets>,
    password: &SecretBytes,
    before: Option<&str>,
    contents: &str,
    required: bool,
    control: &JobControl,
) -> Result<Option<secrets::Staged<'a>>, OpError> {
    let Some(secrets) = secrets else {
        return if required {
            Err(OpError::Internal)
        } else {
            Ok(None)
        };
    };
    secrets
        .stage(
            password.as_bytes(),
            before,
            &sha256_hex(contents.as_bytes()),
            required,
            &|| control.abandoned(),
        )
        .map_err(OpError::from_secrets)
}

/// `vault.change_password`. With quick unlock's credential for the vault
/// the current password opened, the new vault's credential is written
/// first and the two commit as one operation, at the vault's rename (design
/// 0013, "The re-wrap"): a secrets file that doesn't read, or a key-store
/// refusal, refuses the change with nothing written.
fn job_change(
    dir: &Path,
    current: &SecretBytes,
    new: &SecretBytes,
    secrets: Option<&Secrets>,
    control: &JobControl,
) -> JobOutput {
    let result = (|| {
        if control.abandoned() {
            return Err(OpError::Abandoned);
        }
        let before = read_vault(dir)?.ok_or(OpError::NoVault)?;
        let opened = format::open(&before, current.as_bytes()).map_err(OpError::from_vault)?;
        if !new.as_str().is_ok_and(format::is_strong_enough) {
            return Err(OpError::Weak);
        }
        let contents = seal_vault(&opened.mnemonic, new.as_bytes())?;
        let before = sha256_hex(before.as_bytes());
        let staged = stage(secrets, new, Some(&before), &contents, false, control)?;
        write_vault(
            dir,
            &contents,
            &opened.mnemonic,
            new.as_bytes(),
            staged,
            control,
        )
    })();
    match result {
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

/// What `vault.create` and `vault.import` write: under `password`; with
/// `quick` (`quick_unlock: true`, with the job's secrets file) the
/// credential written before the vault commits; with `meta` (`vault_meta`
/// moved, `user_knows_password`) the vault and its metadata as one write
/// ([`crate::vault_meta_journal`]).
struct NewPair<'a> {
    password: &'a SecretBytes,
    quick: Option<Option<&'a Secrets>>,
    meta: Option<bool>,
}

impl NewPair<'_> {
    /// Writes the vault sealing `mnemonic` (its addresses `addresses`),
    /// which replaces the vault with digest `before`.
    fn write(
        &self,
        dir: &Path,
        op: crate::vault_meta_journal::Op,
        mnemonic: &Mnemonic,
        addresses: &Addresses,
        control: &JobControl,
    ) -> Result<Commit, OpError> {
        let contents = seal_vault(mnemonic, self.password.as_bytes())?;
        let staged = match self.quick {
            Some(secrets) => {
                let before = match op {
                    crate::vault_meta_journal::Op::Create => None,
                    crate::vault_meta_journal::Op::Import => vault_digest(dir)?,
                };
                stage(
                    secrets,
                    self.password,
                    before.as_deref(),
                    &contents,
                    true,
                    control,
                )?
            }
            None => None,
        };
        let password = self.password.as_bytes();
        match self.meta {
            Some(knows) => {
                let meta = new_meta(knows, addresses)?;
                write_pair(
                    dir, op, &contents, mnemonic, password, &meta, staged, control,
                )
            }
            None => write_vault(dir, &contents, mnemonic, password, staged, control),
        }
    }
}

/// `saveNewVaultMeta`'s file: `userKnowsPassword`, `createdAt` (the
/// core's clock) and the new vault's addresses.
fn new_meta(user_knows_password: bool, addresses: &Addresses) -> Result<String, OpError> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        });
    let now_ms =
        i64::try_from(crate::testhooks::wall_clock(now_ms)).map_err(|_| OpError::Internal)?;
    let mut meta = fc_wallet_state::vault_meta::VaultMeta::none();
    meta.new_vault(
        user_knows_password,
        now_ms,
        &addresses.user_wallet,
        &addresses.bee_wallet,
    )
    .map_err(|_| OpError::Internal)?;
    meta.text().ok_or(OpError::Internal)
}

/// The vault and its metadata through one journal (design 0013, "The vault
/// and its metadata, one write"). The journal's write is the commit point,
/// the job's claim right before it. A re-wrap's credential `staged` is
/// folded in once the journal is gone, and taken back on a failure before
/// the commit. After the commit, an install or a finish that fails answers
/// the committed result, not durable: the journal stays for recovery, and
/// so does the credential as staged, which recovery keeps for the vault it
/// installs.
#[allow(clippy::too_many_arguments)]
fn write_pair(
    dir: &Path,
    op: crate::vault_meta_journal::Op,
    contents: &str,
    mnemonic: &Mnemonic,
    password: &[u8],
    meta: &str,
    staged: Option<secrets::Staged<'_>>,
    control: &JobControl,
) -> Result<Commit, OpError> {
    use crate::vault_meta_journal::{self as mj, Written};
    let written = std::fs::create_dir_all(dir)
        .map_err(mj::Error::Io)
        .and_then(|()| {
            let expected = Zeroizing::new(mnemonic.phrase().to_owned());
            let check = |bytes: &[u8]| {
                std::str::from_utf8(bytes)
                    .ok()
                    .and_then(|text| format::open(text, password).ok())
                    .is_some_and(|opened| opened.mnemonic.phrase() == expected.as_str())
            };
            let pair = mj::Pair {
                op,
                quick_unlock: staged.is_some(),
                vault: contents.as_bytes(),
                check: &check,
                meta: meta.as_bytes(),
            };
            mj::write(dir, &pair, &|| {
                if crate::testhooks::secrets_fails("vault-claim") {
                    control.abandon();
                    return false;
                }
                claim(control)
            })
        });
    let file = Some(sha256_hex(contents.as_bytes()));
    match written {
        Ok(Written::Finished(done)) => {
            if let Some(staged) = staged {
                staged.committed(password);
            }
            Ok(Commit { done, file })
        }
        Ok(Written::Pending) => {
            drop(staged);
            Ok(Commit {
                done: Done::NotDurable,
                file,
            })
        }
        Err(error) => {
            if let Some(staged) = staged {
                staged.rolled_back();
            }
            Err(match error {
                mj::Error::Abandoned => OpError::Abandoned,
                mj::Error::NotWritten => OpError::Storage("other"),
                mj::Error::Io(e) => storage(&e),
                mj::Error::Check => {
                    crate::log::error(
                        "a staged vault file failed its check",
                        serde_json::json!({}),
                    );
                    OpError::Internal
                }
            })
        }
    }
}

/// `vault.create`.
fn job_create(dir: &Path, words: WordCount, new: &NewPair<'_>, control: &JobControl) -> JobOutput {
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
        let done = new.write(
            dir,
            crate::vault_meta_journal::Op::Create,
            &mnemonic,
            &addresses,
            control,
        )?;
        Ok(((Prepared::new(mnemonic), addresses, Some(phrase)), done))
    })())
}

/// `vault.import`. Over a vault with quick unlock, that vault keeps its
/// credential until the new one commits.
fn job_import(
    dir: &Path,
    mnemonic: Mnemonic,
    overwrite: bool,
    new: &NewPair<'_>,
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
        let done = new.write(
            dir,
            crate::vault_meta_journal::Op::Import,
            &mnemonic,
            &addresses,
            control,
        )?;
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
    (install, meta): (bool, bool),
    control: &JobControl,
) -> (Result<Option<Reconciled>, OpError>, Outcome) {
    let untried = |result| (result, Outcome::NotTried);
    if control.abandoned() {
        return untried(Err(OpError::Abandoned));
    }
    // Recovery ran first, in the job's wrapper. While a metadata journal
    // remains, the read refuses and the decision is the journaled vault's:
    // installed, or still staged (design 0013, "`vault.reconcile`"). Not
    // while a delete journal remains too: that answers the read's `storage`.
    let (contents, pending) = match read_vault(dir) {
        Ok(contents) => (contents, false),
        Err(error) => match crate::vault_meta_journal::journaled_vault(dir) {
            Ok(Some(contents)) => (Some(contents), true),
            _ => return untried(Err(error)),
        },
    };
    let meta = meta.then_some(if pending { "pending" } else { "written" });
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
                meta,
            }))
        })(),
    };
    (result, tried)
}

/// `nodes.write_identity`: builds the node's files from keys taken at job
/// start, then commits them through the journal. The commit point is the
/// journal write; after it, the reply is `installed` or `pending_recovery`.
/// Radicle homes' gates are taken in `lock_dir`, or through the gate files
/// `serve` opened ahead (`files`, design 0017, C3) when they have the home.
fn job_node_write(
    identity_dir: &Path,
    (lock_dir, files): (&Path, &journal::RadicleGates),
    op_id: &str,
    spec: &NodeSpec,
    keys: Option<Box<FreedomKeys>>,
    control: &JobControl,
) -> Result<(journal::Outcome, serde_json::Map<String, serde_json::Value>), OpError> {
    if control.abandoned() {
        return Err(OpError::Abandoned);
    }
    // Design 0001: recovery runs before any node write, and here before
    // anything of the requested node is made, taken or read: an outstanding
    // journal (for this root or another) is finished first, under its own
    // home's gate if it is a Radicle one, so the plan sees what it
    // installed. If it can't be finished, nothing is made or written, not
    // even the requested Radicle home, which taking its gate would create
    // (review of #177, round 3).
    let recovering = journal::Gates {
        lock_dir: lock_dir.to_owned(),
        retry: fc_service::gate::CONTENTION_RETRY,
        held: None,
        held_identity: None,
        files: files.clone(),
    };
    match journal::recover(identity_dir, &recovering) {
        Ok(journal::Recovered::Waiting { .. }) => return Err(OpError::LockHeld),
        Ok(_) => {}
        Err(e) => return Err(storage(&e)),
    }
    // A Radicle write holds the home's gate for its whole length, from
    // before it reads anything of the home (design 0008, "Identity changes"):
    // a running Radicle service holds it, so the write answers `lock_held`
    // after 5 s and touches nothing. Through the home's gate file when
    // `serve` opened one (design 0017, C3), with the same retry; otherwise
    // by its path, made if missing, as before.
    let home_gate = match spec {
        NodeSpec::Radicle { home, .. } => Some(
            journal::home_gate(home, &recovering, true).map_err(|e| match e {
                fc_service::gate::GateError::Held => OpError::LockHeld,
                fc_service::gate::GateError::Storage(e) => storage(&e),
                _ => OpError::Storage("gate"),
            })?,
        ),
        NodeSpec::Bee { .. } => None,
    };
    let gates = journal::Gates {
        held: home_gate.as_ref().map(|gate| gate.data_dir.clone()),
        held_identity: home_gate.as_ref().and_then(|gate| gate.identity),
        ..recovering
    };
    let write_error = |e: journal::WriteError| match e {
        journal::WriteError::Io(e) => storage(&e),
        journal::WriteError::DuplicateOpId => OpError::Invalid("op_id already used"),
        journal::WriteError::TooLarge => OpError::Storage("too_large"),
        journal::WriteError::Layout => OpError::Internal,
        journal::WriteError::LockHeld => OpError::LockHeld,
    };
    let build_error = |e: nodes::BuildError| match e {
        nodes::BuildError::Io(e) => storage(&e),
        nodes::BuildError::Config(kind) => OpError::Storage(kind),
        nodes::BuildError::IdentityCorrupt => OpError::IdentityCorrupt,
        nodes::BuildError::Keys | nodes::BuildError::Path => OpError::Internal,
    };
    // A Radicle write works under the gate's canonical home, never the path
    // main named: the plan and the journal's root are both that path, so a
    // symlink retargeted after the gate was taken redirects nothing (review
    // of #177).
    let canonical;
    let spec = match (spec, &home_gate) {
        (NodeSpec::Radicle { alias, custody, .. }, Some(gate)) => {
            canonical = NodeSpec::Radicle {
                home: gate.data_dir.clone(),
                alias: alias.clone(),
                custody: *custody,
            };
            &canonical
        }
        _ => spec,
    };
    // The node's root, opened once, now: a Radicle home after its gate was
    // taken, before anything of it is read. The plan, the staging, the
    // install and the cleanup all reach what is below it from this handle,
    // never by its path again, so a home renamed or replaced after the open
    // redirects nothing (review of #177, round 2).
    // A Radicle home must be the very directory its gate was taken for (the
    // identity the gate recorded, Unix): one moved into its path since is
    // refused (review of #177, round 3).
    let top = journal::write_root(spec.name(), spec.root(), gates.held_identity)
        .map_err(|e| storage(&e))?;
    if let NodeSpec::Radicle {
        alias,
        custody: Custody::Sealed { wipe },
        ..
    } = spec
    {
        drop(keys);
        let built = nodes::radicle_sealed(&top, alias, *wipe).map_err(build_error)?;
        let plan = journal::Plan {
            entries: built
                .entries
                .iter()
                .map(|entry| match entry {
                    nodes::SealedEntry::Install(target, contents) => {
                        journal::Entry::Install(journal::FileSpec {
                            target: target.clone(),
                            contents: contents.as_slice(),
                        })
                    }
                    nodes::SealedEntry::Remove(target) => journal::Entry::Remove(target.clone()),
                })
                .collect(),
            wipe: built.wipe.clone(),
        };
        let outcome = journal::write(
            identity_dir,
            op_id,
            spec.name(),
            &top,
            &plan,
            &gates,
            || claim(control),
        )
        .map_err(write_error)?;
        drop(top);
        drop(home_gate);
        if outcome == journal::Outcome::Abandoned {
            return Err(OpError::Abandoned);
        }
        // No DID: the node's identity arrives sealed at each start (0008).
        return Ok((outcome, serde_json::Map::new()));
    }
    let keys = keys.ok_or(OpError::Internal)?;
    let built = nodes::build(spec, &top, &keys, &mut OsRng).map_err(build_error)?;
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
        &top,
        &journal::Plan::install(&files),
        &gates,
        || claim(control),
    )
    .map_err(write_error)?;
    drop(top);
    drop(home_gate);
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

    /// `secrets.rpc_api_keys`' payload is counted before it is written, so
    /// its zeroizing buffer never grows: a control character, six bytes
    /// escaped, in every byte of a 1,024-byte key, and an id that needs
    /// escaping too.
    #[test]
    fn the_rpc_keys_reply_is_sized_exactly() {
        let key = "\u{1}".repeat(1024);
        let mut keys = std::collections::BTreeMap::new();
        keys.insert("alchemy".to_owned(), Zeroizing::new(key.clone()));
        keys.insert("a\u{1f}\"".to_owned(), Zeroizing::new("k\\".to_owned()));
        let payload = rpc_reply(7, &RpcAnswer::Keys(keys)).unwrap();
        assert!(payload.len() > 6 * 1024);
        assert_eq!(payload.capacity(), payload.len());
        let reply: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(reply["result"]["keys"][1]["api_key"], key.as_str());
        assert_eq!(reply["result"]["keys"][0]["id"], "a\u{1f}\"");
    }

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

    /// Design 0013, "Forgetting an item": a vault delete whose journal
    /// committed is finished before the vault is read, so no job sees the
    /// vault it removes (an install that failed after the commit). The read
    /// itself refuses while the journal is there and changes nothing: only
    /// recovery finishes it (under the secrets file's lock, when there is
    /// one).
    #[test]
    fn a_committed_delete_is_finished_before_the_vault_is_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(VAULT_FILE), b"the vault").unwrap();
        std::fs::write(dir.path().join(secrets::SECRETS_FILE), b"before").unwrap();
        std::fs::write(dir.path().join(crate::delete_journal::STAGED), b"after").unwrap();
        let journal = serde_json::json!({ "op": "vault.delete", "files": [
            { "target": secrets::SECRETS_FILE, "staged": crate::delete_journal::STAGED,
              "sha256": sha256_hex(b"after") },
            { "target": VAULT_FILE, "sha256": sha256_hex(b"the vault"), "remove": true },
        ] });
        std::fs::write(
            dir.path().join(crate::delete_journal::JOURNAL),
            journal.to_string(),
        )
        .unwrap();
        assert!(matches!(read_vault(dir.path()), Err(OpError::Storage(_))));
        assert!(matches!(vault_digest(dir.path()), Err(OpError::Storage(_))));
        assert!(dir.path().join(VAULT_FILE).exists());
        assert!(dir.path().join(crate::delete_journal::JOURNAL).exists());
        assert_eq!(
            std::fs::read(dir.path().join(secrets::SECRETS_FILE)).unwrap(),
            b"before"
        );
        assert!(recover_first(dir.path(), None).is_ok());
        assert!(matches!(read_vault(dir.path()), Ok(None)));
        assert!(!dir.path().join(VAULT_FILE).exists());
        assert!(!dir.path().join(crate::delete_journal::JOURNAL).exists());
        assert_eq!(
            std::fs::read(dir.path().join(secrets::SECRETS_FILE)).unwrap(),
            b"after"
        );
    }

    /// A vault unlocked now, with a 15-minute auto-lock.
    fn unlocked() -> Vault {
        let mut vault = Vault::new(
            PathBuf::from("/nonexistent"),
            PathBuf::from("/nonexistent-locks"),
            15 * 60 * 1000,
        );
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

    /// The one payload a request answered with.
    fn sent(outs: Vec<Out>) -> Vec<u8> {
        match outs.as_slice() {
            [Out::Send(payload)] => payload.to_vec(),
            _ => panic!("expected one reply"),
        }
    }

    /// Typed data for the size bound: `count` zeros (each `"0"` in the view)
    /// and a string of `len` bytes.
    fn sized_typed_data(count: usize, len: usize) -> serde_json::Value {
        serde_json::json!({
            "domain": {},
            "types": { "M": [{ "name": "v", "type": "uint8[]" }, { "name": "s", "type": "string" }] },
            "message": { "v": vec![0; count], "s": "x".repeat(len) },
        })
    }

    /// #88, test 3: the length both typed-data methods measure is the
    /// signing response's, written at ID 2^53 - 1, across the vectors and
    /// at the boundary, where that response fills the frame exactly.
    #[test]
    fn the_view_bound_is_the_signing_reply_at_the_largest_id() {
        use fc_protocol::frame::MAX_PAYLOAD;
        use fc_protocol::message::MAX_ID;
        let mut vault = unlocked();
        let overhead = MAX_PAYLOAD - crate::signing::max_view_len();
        let view_of = |data: &serde_json::Value| {
            let request = fc_evm::ViewRequest {
                primary_type: None,
                chain_id: None,
                max_len: usize::MAX,
            };
            fc_evm::typed_data_view(&data["domain"], &data["types"], &data["message"], &request)
                .unwrap()
        };
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/signing.json");
        let vectors: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let mut checked = 0;
        for case in vectors["typedData"].as_array().unwrap() {
            if case["keyId"] != "account-0" || case["result"].get("payload").is_none() {
                continue;
            }
            let data = &case["typed_data"];
            let hashed = view_of(data);
            let params = serde_json::json!({
                "key": { "kind": "account", "index": 0 },
                "typed_data": data,
                "expected_hash": case["result"]["hash"],
            })
            .to_string();
            let mut payload =
                sent(vault.request(MAX_ID, "sign.typed_data", Some(&params), &Context::shell()));
            // A Safe's typed data isn't main's to sign without its Safe
            // approval (design 0012, APR-4b): it signs as a page's own
            // `eth_signTypedData_v4`, under its `sign-typed-data` token.
            if fc_approval::safe::is_safe_typed_data(data) {
                let reply: serde_json::Value = serde_json::from_slice(&payload).unwrap();
                assert_eq!(reply["error"]["code"], "not_authorized", "{reply}");
                const HANDLE: &str =
                    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
                let page = Context {
                    caller: fc_protocol::message::CallerKind::Page,
                    page: Some(fc_protocol::message::PageContext {
                        origin: "https://safe.example".to_owned(),
                        top_origin: "https://safe.example".to_owned(),
                        frame: 1,
                        navigation: 1,
                        agent: Some(false),
                        transport_key: None,
                    }),
                };
                let issue = serde_json::json!({
                    "kind": "sign-typed-data", "account": 0, "handle": HANDLE,
                    "payload": { "typed_data": data },
                })
                .to_string();
                let minted: serde_json::Value = serde_json::from_slice(&sent(vault.request(
                    1,
                    "approval.issue",
                    Some(&issue),
                    &page,
                )))
                .unwrap();
                let mut params: serde_json::Value = serde_json::from_str(&params).unwrap();
                params["authorization"] =
                    serde_json::json!({ "token": minted["result"]["token"], "handle": HANDLE });
                let params = params.to_string();
                payload = sent(vault.request(MAX_ID, "sign.typed_data", Some(&params), &page));
            }
            assert_eq!(
                payload.len(),
                overhead + hashed.view.len(),
                "{}",
                case["id"]
            );
            let reply: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(reply["result"]["signature"], case["result"]["signature"]);
            checked += 1;
        }
        assert!(checked >= 60, "{checked}");
        // At the boundary: a view of exactly the bound's length makes a
        // signing response that fills the frame; one byte more is refused.
        let probe = view_of(&sized_typed_data(90_000, 0)).view.len();
        let exact = crate::signing::max_view_len() - probe;
        for (len, fits) in [(exact, true), (exact + 1, false)] {
            let data = sized_typed_data(90_000, len);
            let hash =
                fc_evm::typed_data_hash(&data["domain"], &data["types"], &data["message"]).unwrap();
            let params = serde_json::json!({
                "key": { "kind": "account", "index": 0 },
                "typed_data": data,
                "expected_hash": fc_evm::to_hex(&hash),
            })
            .to_string();
            let payload =
                sent(vault.request(MAX_ID, "sign.typed_data", Some(&params), &Context::shell()));
            let reply: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            if fits {
                assert_eq!(payload.len(), MAX_PAYLOAD);
                assert!(reply["result"]["signature"].is_string());
            } else {
                assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
            }
        }
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
