//! `freedom-cored serve`: the event loop (design 0001, "Process model").
//!
//! One thread owns all state and handles every message in order. Reading
//! stdin, writing stdout, logging and watching the parent happen on their own
//! threads behind bounded queues, so neither a slow peer nor a slow job can
//! keep the loop from handling EOF, shutdown or lock. KDF work will run on
//! worker threads and report back here.
//!
//! **Backpressure** (design 0001, Transport and framing). The loop's
//! replies and events go to the writer within its allowance
//! ([`transport::MAX_QUEUED_REPLIES`] frames). Past it they wait here, in
//! order ([`Outbox`]), and the loop takes no new request until they have
//! gone:
//!
//! - **Requests wait** in order, each with its reader credit, so once the
//!   credits are spent the reader stops reading stdin. Main's writes back
//!   up, not the core's memory.
//! - **The loop never blocks on the writer, nor polls it.** Freed room
//!   wakes it ([`Event::Room`]). Meanwhile it runs its timers and handles
//!   its worker's results, lifecycle events, and whatever else main sends:
//!   responses (for naming, chain and dweb), stream frames, cancels and
//!   events.
//! - **The auto-lock fires on time,** whatever the room: it wipes the
//!   secrets and revokes admitted work at once. Only its event and the
//!   revoked requests' replies wait, and they carry no secret.
//! - **Requests that waited go one per turn of the loop** once there is
//!   room, each as if it had just been read: after the timers, so an
//!   auto-lock that comes due while they drain locks before the next one,
//!   and before a `vault.touch` could postpone it; and with whatever main
//!   sends meanwhile handled between them. The loop doesn't wait while one
//!   can go.
//! - **Control requests don't wait:**
//!   - **`core.shutdown`** among the waiting requests is handled at once.
//!     The requests before it are dropped: none of them ran, and main is
//!     closing the core.
//!   - **A `vault.lock`** locks at once and keeps its place, where it is
//!     handled again and acknowledged. Until then, whatever the requests
//!     before it admit is revoked at once, so nothing main sent before a
//!     lock outlives it.
//!   - **A `cancel`** reaches queued and running work at once, or waits
//!     behind its request if that request waits too.
//! - **What waits is bounded** by the work admitted before the wait: for
//!   each vault request (one running, 32 queued), its reply and at most one
//!   event. Lock events don't pile up: after a lock nothing can unlock
//!   until requests are taken again.
//! - **A stall ends the core:** once frames have waited [`STALL`] with the
//!   writer writing nothing, main has stopped reading, and the core exits.
//!   The swarm thread watches its own frames the same way, with the same
//!   bound ([`transport::Watchdog`]), as it too holds new requests while
//!   they wait.

use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError, Sender, TryRecvError};
use std::time::{Duration, Instant};

use fc_approval::stores::StoreKind;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::frame::{Frame, KIND_JSON};
use fc_protocol::message::{self, CallerKind, Context, Message, MessageError};
use fc_protocol::methods::{self, Admission};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use crate::dweb::thread as dweb;
use crate::eip1193::Connects;
use crate::exit::Exit;
use crate::keystore::client::DesktopKeyStore;
use crate::ledger::lane::{Ended, Lane, Turn};
use crate::ledger::methods::{self as ledger, Finish, Then};
use crate::requests::{self, Owner, Requests};
use crate::secrets::Secrets;
use crate::swarm::thread as swarm;
use crate::transport::{self, Allowance, Credits, Link, Pending, Route, StreamKey, Watchdog};
use crate::vault::{FileSnapshot, Finished, NodeRecovery, Out, Vault};
use crate::worker::Worker;
use crate::{chain, gate, hardening, journal, log, naming};
#[cfg(feature = "testhooks")]
use crate::{testhooks, testmethods};

/// How long the writer may take to flush on exit.
const EXIT_DRAIN: Duration = Duration::from_secs(2);
/// How long exiting waits for a vault job past its commit point to finish
/// and reply: inside main's 3 s shutdown grace, so the core exits on its
/// own (#127). A commit is a rename or unlink plus a directory flush, or a
/// node write's few fsyncs; the next start's recovery covers anything
/// slower, as it would a kill.
const COMMIT_DRAIN: Duration = Duration::from_secs(2);
/// How long the loop's frames may wait with the writer writing nothing
/// before the core decides main has stopped reading, and exits (design
/// 0001, Transport and framing):
/// - **Far above a healthy main's pauses:** a GC pause or a busy main
///   thread lasts milliseconds to seconds. Waiting costs nothing meanwhile:
///   no buffer grows, and the auto-lock still fires.
/// - **Between main's hang watchdogs** (deadline + 15 s): it is the longest
///   deadline the core gives a request (the KDF methods'), whose reply main
///   waits 45 s for. The core never gives up sooner than main does on a
///   short request (20 s), and a main that can no longer run its timers
///   keeps it waiting no longer than main would wait for a KDF reply.
const STALL: Duration = Duration::from_secs(30);

pub struct Options {
    pub data_dir: PathBuf,
    pub lock_dir: PathBuf,
    pub parent_pid: Option<u32>,
    pub hello_timeout: Duration,
    /// When the process started: the hello deadline counts from here, not
    /// from after the gate is taken.
    pub started: Instant,
    /// `--grant-root` (design 0017, C1): the Freedom root, granted (C2).
    /// The hello's `grant_root` must equal it.
    pub grant_root: PathBuf,
    /// `--user-data-dir` (C1): the profile's root, whose legacy receipts
    /// are handed over before `confine` (C5), and which isn't granted. The
    /// hello's `user_data_dir` must equal it, both absent or both given.
    pub user_data_dir: Option<PathBuf>,
    /// `--node-root bee=` and `radicle=` (C1): `nodes.write_identity` must
    /// name these, exactly.
    pub node_roots: crate::nodes::NodeRootArgs,
}

/// What the loop reacts to.
pub enum Event {
    /// A frame, and its place in the reader's credits.
    Frame(Frame, transport::Credit),
    /// A fragmented response, reassembled (design 0005, Frames), and the
    /// credit whose drop returns main's bulk credit.
    Response {
        id: u64,
        payload: Zeroizing<Vec<u8>>,
        credit: transport::Credit,
    },
    Eof {
        at_boundary: bool,
        /// A fragmented response was in reassembly; it is discarded.
        in_response: bool,
    },
    /// A framing error, as a fixed category (never input text).
    ProtocolError(&'static str),
    WriterFailed,
    /// A thread's frames waited past its allowance for the stall bound
    /// with the writer writing nothing ([`Watchdog`]): main has stopped
    /// reading.
    NotReading {
        waited: Duration,
        thread: &'static str,
    },
    ThreadDied(&'static str),
    ParentGone,
    /// The startup read of the vault file finished.
    Snapshot(FileSnapshot, NodeRecovery),
    /// A vault worker job finished.
    JobDone(u64, Finished),
    /// The writer has room again in the loop's share: the frames waiting
    /// here can go, then the requests that waited for them.
    Room,
    /// A stream's entry of frames (design 0009, Streams in the core), read
    /// after the hello, for its stream's owner ([`transport::StreamRoutes`],
    /// the dweb thread by default): outside the frame credits, under the
    /// reader's stream cap.
    Stream(transport::StreamMark),
    /// One of the core's requests to main was cancelled and is watched
    /// (design 0015, D13): the loop's timer takes its answer's bound in.
    Watch,
    /// The chain thread served `chain.fee_reference`'s reply to main's
    /// request `id` (its payload): the chain's fee evidence for the
    /// approvals (design 0012, "The fee check").
    FeeReference {
        id: u64,
        payload: Box<[u8]>,
    },
    /// A page's `approval.request`, `approval.recheck` or
    /// `eip1193.select_chain` that waited for room may go (design 0012,
    /// APR-5c).
    Eip1193Room,
    /// A `shell.ledger_apdu`, or a cancel of one, that waited for room may
    /// go (design 0016, the device lane).
    LedgerRoom,
    /// The chain thread answered one of the core's own reads (design
    /// 0012, "Phone jobs"): its tag, the reply's payload, and whether it
    /// failed at or after the deadline it was given, by the chain thread's
    /// clock.
    ChainRead {
        tag: u64,
        payload: Box<[u8]>,
        past_due: bool,
    },
    /// The naming thread checked a page request's name (design 0012,
    /// APR-5f): whether it still serves the document's IPNS key, or the
    /// lookup's deadline passed first.
    NameChecked {
        tag: u64,
        verdict: crate::eip1193::Verdict,
    },
    /// The swarm thread's ask of the vault under `tag` (design 0015, D15):
    /// a key's owner or a page's SOC's signature, answered back to it.
    SwarmVault {
        tag: u64,
        ask: Box<crate::swarm::engine::VaultAsk>,
    },
}

// A stream mark's slot here is within what the reader charges its entry.
const _: () = assert!(transport::stream_slot_fits(std::mem::size_of::<Event>()));

/// The methods `core.hello`'s capabilities name: every method this build
/// implements but the `chain.*` methods (design 0006's `chain.html`
/// included), which design 0005 doesn't add to them (it adds features
/// only). Every method, these and the chain methods, is a row of
/// fc-protocol's method table, which says who may call it (#101); a test
/// keeps the two in step. Only the table's names, and with the `testhooks`
/// feature the test methods', are ever logged; anything else is logged as `<unknown>`.
const CAPABILITIES: &[&str] = &[
    "core.hello",
    "core.shutdown",
    "vault.status",
    "vault.lock",
    "vault.touch",
    "vault.unlock",
    "vault.verify_password",
    "vault.change_password",
    "vault.delete",
    "vault.export_mnemonic",
    "vault.export_private_key",
    "vault.create",
    "vault.import",
    "vault.reconcile",
    // Design 0013: quick unlock in the core's key store (PRF-1c).
    "quick_unlock.enroll",
    "quick_unlock.unlock",
    "quick_unlock.export_mnemonic",
    "quick_unlock.export_private_key",
    "quick_unlock.status",
    "quick_unlock.disable",
    // Design 0013: RPC API keys in the core's secrets file (PRF-5h).
    "secrets.rpc_api_keys",
    "secrets.rpc_api_key_status",
    "secrets.set_rpc_api_key",
    "secrets.remove_rpc_api_key",
    // Design 0013, "`vault-meta.json`" (PRF-5c-1): the wallet list. Reads
    // before `vault_meta` is in `store_moved`; writes from then on.
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
    "nodes.write_identity",
    "nodes.op_status",
    "nodes.seal_radicle_key",
    "keys.generate_mnemonic",
    "keys.validate_mnemonic",
    "keys.addresses",
    "keys.radicle_did",
    "sign.transaction",
    "sign.message",
    "sign.typed_data",
    // Design 0016: a Ledger's discovery and adding, on the device lane
    // (LDG-2's L3).
    "ledger.accounts",
    "ledger.add",
    "swarm.sign_soc",
    "typed_data.hash",
    "naming.configure",
    "naming.availability",
    "naming.resolve_content",
    "naming.resolve_address",
    "naming.resolve_reverse",
    "naming.resolve_tezos",
    "naming.invalidate_content",
    "naming.invalidate_tezos",
    // Design 0012: approval tokens and Safe approvals (APR-3).
    "approval.issue",
    "approval.discard",
    "approval.spend",
    "approval.end",
    // Design 0012: the grant stores (APR-3b).
    "approval.check",
    "approval.grant",
    "approval.revoke",
    "approval.touch",
    // Design 0012: a page's Radicle write, counted in R-6 (#372).
    "approval.radicle_write",
    "approval.grants",
    "approval.forget_account",
    // Design 0012: a device send's "Always allow" (#373).
    "approval.remember",
    // Design 0012: phone jobs (PHN-1).
    "phone.job",
    "phone.sent",
    "phone.result",
    // Design 0012: x402's payments (X402-1), and a cap's narrowing (#392).
    "x402.authorize",
    "x402.settle",
    "x402.update",
    // Design 0013: the pending Safe transactions (PRF-5f).
    "safe_pending.get",
    "safe_pending.set",
    "safe_pending.clear",
    "safe_pending.list",
    // Design 0016: the Safe methods (SAFE-2's S2).
    "safe.create",
    "safe.status",
    "safe.deploy",
    "safe.deployed",
    "safe.pending",
    "safe.discard",
    // Design 0016: a Safe transaction prepared and proposed (SAFE-2's S3).
    "safe.prepare",
    "safe.propose",
    // Design 0016: the pending SafeTx executed (SAFE-2's S4).
    "safe.execute",
    "safe.executed",
    // Design 0016: a page's Safe message, its owners' session (SAFE-2's S5).
    "safe.message_start",
    "safe.message_sign",
    "safe.message_state",
    "safe.message_cancel",
    "safe.message_complete",
    // Design 0016: owners who sign after a proposal (SAFE-2's S6).
    "safe.sign_owner",
    // Design 0013: the payment history (PRF-5g-2).
    "payments.append",
    "payments.update",
    "payments.mark_confirmed",
    "payments.mark_failed",
    "payments.mark_dropped",
    "payments.set_dropped_seen",
    "payments.pending",
    "payments.get_recent",
    "payments.get_by_id",
    "payments.get_count",
    "payments.clear",
    // Design 0013: the wallet's intent records (PRF-5e-3).
    "intents.commit",
    "intents.handoff",
    "intents.outcome",
    "intents.settle",
    "intents.void",
    "intents.retire",
    "intents.track",
    "intents.withdraw_origin",
    "intents.compact",
    "intents.get",
    "intents.by_key",
    "intents.held",
    "intents.list",
    "intents.held_nonces",
    "intents.usage",
    "intents.void_refusal",
    // Design 0012: a page's EIP-1193 request, run by the core (APR-5).
    "eip1193.request",
    "dweb.open",
    // Design 0009: verified fetches, whose bodies stream.
    "dweb.verify",
    "dweb.forget",
    // Design 0015: a page's `window.swarm` request, on the swarm thread,
    // and main's ask for the body of one of its calls.
    "swarm.request",
    "swarm.body",
    // Design 0015 (SWM-4, D5): main's own Swarm methods, on the swarm
    // thread: its node calls, then the stores' ops.
    "swarm.publish",
    "swarm.feed",
    "swarm.stamps",
    "swarm.upload_status",
    "swarm.identities",
    "swarm.history",
    "swarm.manifest",
];

/// The features in `core.hello`'s capabilities, after the methods (design
/// 0005):
/// - `fragments`: fragmented responses with bulk credit (Frames). The core
///   always offers them; it sends them only to a main whose hello offered
///   `frames: ["fragment"]`.
/// - `myotis_refusal_codes`: the core reads a Myotis broadcast's `{
///   rejected: { reason, code: -32602 } }` (The rest). Main sends that form
///   only to a core that offers it.
/// - `exclude_sources`: the core reads `chain.request`'s `exclude_sources`
///   (Methods main calls). Main sends it only to a core that offers it.
/// - `colibri_faults`: the core reads Colibri's `fault: true` beside a
///   failure or a revert, for its verifier-fault backoff (Colibri). Main
///   sends it only to a core that offers it.
/// - `streams`: stream frames in both directions (design 0009, Streams in
///   the core), on every connection: the core speaks only protocol 2.
const FEATURES: &[&str] = &[
    "fragments",
    "myotis_refusal_codes",
    "exclude_sources",
    "colibri_faults",
    "streams",
];

/// `serve`, in 0017's order ("The order in serve"), from step 3: the
/// entry's `clean_entry` and the arguments are `main`'s. Until `confine`
/// the process is one thread, and its log lines are written directly.
pub fn run(options: &Options) -> Exit {
    // 3. Hardening (0001), then the parent's death signal and its check.
    hardening::harden();
    if !hardening::request_parent_death_signal(options.parent_pid) {
        log::error("parent is already gone", serde_json::json!({}));
        return Exit::Ok;
    }
    // The Freedom root, made durably if missing, before the gate: main's
    // identity directory is inside it, and the gate makes a missing one
    // with its ancestors, flushing none of them. One that can't be made
    // durably is exit 74, before anything else.
    if let Err(e) = journal::create_private_dirs(&options.grant_root) {
        log::error(
            "cannot make the Freedom root",
            serde_json::json!({ "error": e.kind().to_string() }),
        );
        return Exit::Storage;
    }
    // 4. The gate, taken and held.
    let gate = match gate::acquire(&options.data_dir, &options.lock_dir) {
        Ok(gate) => {
            log::info(
                "gate taken",
                serde_json::json!({ "lock": gate.lock_path.display().to_string() }),
            );
            gate
        }
        Err(e) => {
            log::error(
                "cannot take the gate",
                serde_json::json!({ "error": e.to_string() }),
            );
            return Exit::from(&e);
        }
    };
    // The identity directory's entry in its parent (the Freedom root, by
    // default), flushed at every start: the gate makes a missing one and
    // flushes nothing, and the vault's commits flush only the directory
    // itself. One that can't be flushed is exit 74, tried again next start.
    if let Err(e) = journal::sync_parent(&gate.identity_dir) {
        log::error(
            "cannot flush the identity directory in its parent",
            serde_json::json!({ "error": e.kind().to_string() }),
        );
        return Exit::Storage;
    }
    // 5. The setup that confinement would refuse, or that needs what it
    //    doesn't grant.
    let setup = match setup(options, &gate) {
        Ok(setup) => setup,
        Err(exit) => return exit,
    };
    // 6. Confined, while this is the only thread (C2).
    let mut descriptors = gate.descriptors();
    descriptors.extend(setup.prepared.gates.descriptors());
    let policy = crate::confine::policy(setup.read_write, descriptors);
    let report = match crate::confine::apply(&policy, "serve confined") {
        Ok(report) => report,
        Err(exit) => return exit,
    };
    // 7. The logging thread, then everything else.
    log::init();
    let prepared = setup.prepared;

    let (events_tx, events) = mpsc::channel();
    let credits = Arc::new(Credits::default());
    let link = Link::new();
    // The core's requests to main still waiting for their answers: the
    // reader's set, and the gate naming and chain send them through.
    let pending = Arc::new(Pending::default());
    let requests = Requests::new(requests::MAX_OUTSTANDING, Arc::clone(&pending));
    // A watched cancel's bound joins the loop's timers at once, however
    // long the loop would have waited.
    let watch = events_tx.clone();
    requests.on_cancel(move || {
        let _ = watch.send(Event::Watch);
    });
    let writer = match transport::spawn_writer(events_tx.clone(), Arc::clone(&link)) {
        Ok(writer) => writer,
        Err(_) => return Exit::Internal,
    };
    // The loop's own share of the writer: room freed after a refusal wakes
    // the loop to send what waits.
    let allowance = Allowance::new(transport::MAX_QUEUED_REPLIES, usize::MAX);
    let room = events_tx.clone();
    allowance.on_room(move || {
        let _ = room.send(Event::Room);
    });
    let Ok(worker) = Worker::spawn(events_tx.clone()) else {
        return Exit::Internal;
    };
    // Naming runs on its own thread and writes its own frames (design 0004,
    // Admission: vault control traffic never waits on naming work).
    let Ok(naming) = naming::spawn(
        writer.queue.clone(),
        events_tx.clone(),
        Arc::clone(&requests),
    ) else {
        return Exit::Internal;
    };
    // Chain data runs on its own thread too (design 0005), and fragments
    // its large replies for a main that offered fragments.
    let Ok(chain) = chain::spawn(
        writer.queue.clone(),
        events_tx.clone(),
        Arc::clone(&link),
        Arc::clone(&requests),
    ) else {
        return Exit::Internal;
    };
    // The key store (design 0013): its calls go to main as `shell.keystore`
    // from the threads that make them, never from this loop, which only
    // routes main's answers back.
    let keystore = DesktopKeyStore::new(Arc::clone(&requests), writer.queue.clone());
    // The profile's secrets file over that key store (design 0013): quick
    // unlock's jobs run on the vault worker, its drain on a thread of its
    // own once the hello is answered.
    let secrets = Secrets::new(
        gate.identity_dir.clone(),
        Arc::clone(&keystore) as Arc<dyn fc_keystore::KeyStore + Send + Sync>,
    );
    #[cfg(feature = "testhooks")]
    let test = if testhooks::test_methods() {
        match testmethods::spawn(
            writer.queue.clone(),
            Arc::clone(&link),
            events_tx.clone(),
            Arc::clone(&keystore),
        ) {
            Ok(test) => Some(test),
            Err(_) => return Exit::Internal,
        }
    } else {
        None
    };
    // The status snapshot is read once, on its own thread: the gate makes
    // this process the only writer, so it never needs re-reading, and slow
    // storage can't hold up the loop (deadline, EOF, parent exit). core.hello
    // is answered once the snapshot is ready.
    if transport::spawn_reader(
        events_tx.clone(),
        Arc::clone(&credits),
        Arc::clone(&link),
        pending,
    )
    .is_err()
        || !spawn_snapshot(
            gate.identity_dir.clone(),
            options.lock_dir.clone(),
            prepared.gates.clone(),
            Arc::clone(&secrets),
            events_tx.clone(),
        )
        || !spawn_parent_watch(options.parent_pid, events_tx.clone())
    {
        log::error("cannot start a thread", serde_json::json!({}));
        return Exit::Internal;
    }

    // The dweb thread's share of the writer, for the hello. The writer's
    // own handle goes to the outbox: once the producers' handles are gone,
    // the writer ends.
    let dweb_out = writer.queue.clone();
    // A page's connects (design 0012, APR-5c): their requests to main go
    // from this loop, through the gate.
    let connects = {
        let room = events_tx.clone();
        Connects::new(Arc::clone(&requests), writer.queue.clone(), move || {
            let _ = room.send(Event::Eip1193Room);
        })
    };
    // The device lane (design 0016): a Ledger operation's APDUs go to main
    // from this loop, through the gate, one at a time.
    let ledger = {
        let room = events_tx.clone();
        Lane::new(Arc::clone(&requests), writer.queue.clone(), move || {
            let _ = room.send(Event::LedgerRoom);
        })
    };
    let mut core = Core {
        snapshot_ready: false,
        node_recovery: None,
        pending_hello: None,
        stores_echo: Vec::new(),
        outbox: Outbox::new(
            writer.queue,
            allowance,
            Arc::clone(&link),
            crate::testhooks::stall(STALL),
        ),
        parked: VecDeque::new(),
        locks_ahead: 0,
        link: Arc::clone(&link),
        credit: None,
        hello_done: false,
        last_request_id: 0,
        vault: {
            let mut vault = Vault::new(
                gate.identity_dir.clone(),
                options.lock_dir.clone(),
                fc_vault::state::DEFAULT_AUTO_LOCK_MS,
            );
            vault.set_secrets(Arc::clone(&secrets));
            vault.set_node_roots(options.node_roots.clone());
            vault.set_radicle_gates(prepared.gates.clone());
            vault
        },
        grant_root_arg: options.grant_root.clone(),
        user_data_dir_arg: options.user_data_dir.clone(),
        handover: setup.handover,
        history_handover: setup.history_handover,
        confinement: report.to_json(),
        secrets,
        worker,
        requests,
        keystore,
        naming,
        chain,
        connects,
        ledger,
        dweb: None,
        dweb_start: Some(DwebStart {
            out: dweb_out,
            events: events_tx,
        }),
        swarm: None,
        swarm_cancels: BTreeMap::new(),
        #[cfg(feature = "testhooks")]
        parked_asks: VecDeque::new(),
        #[cfg(feature = "testhooks")]
        test,
    };
    let hello_deadline = options.started + options.hello_timeout;
    let exit = loop {
        if !core.hello_done && Instant::now() >= hello_deadline {
            log::error("no core.hello within the deadline", serde_json::json!({}));
            break Exit::Protocol;
        }
        let timeout = if core.hello_done {
            // The vault's timers, and the stall bound while frames wait.
            [
                core.vault.next_wakeup(),
                core.outbox.deadline(),
                core.connects.next_wakeup(),
                core.ledger.next_wakeup(),
                core.requests.next_overdue(),
            ]
            .into_iter()
            .flatten()
            .min()
            .map_or(Duration::from_secs(3600), |at| {
                at.saturating_duration_since(Instant::now())
            })
        } else {
            hello_deadline.saturating_duration_since(Instant::now())
        };
        // A held signature ask is polled for its release (test hooks).
        #[cfg(feature = "testhooks")]
        let timeout = if core.parked_asks.is_empty() {
            timeout
        } else {
            timeout.min(Duration::from_millis(10))
        };
        // While a request that waited can go, the loop doesn't wait: it
        // takes an event if one is there, then that request (`resume`).
        let received = if core.resumable() {
            events.try_recv().map_err(|e| match e {
                TryRecvError::Empty => RecvTimeoutError::Timeout,
                TryRecvError::Disconnected => RecvTimeoutError::Disconnected,
            })
        } else {
            events.recv_timeout(timeout)
        };
        // The test hooks' held signature asks, once released.
        #[cfg(feature = "testhooks")]
        if !core.parked_asks.is_empty() && crate::testhooks::swarm_hold_released() {
            let mut gone = false;
            while let Some((tag, ask)) = core.parked_asks.pop_front() {
                gone |= !core.swarm_vault(tag, &ask);
            }
            if gone {
                break Exit::Internal;
            }
        }
        // Whatever arrived, first apply what is due (auto-lock, deadlines):
        // a busy queue must not postpone either, nor a writer without room.
        if core.hello_done {
            let mut outs = core.vault.tick();
            outs.extend(core.connects.tick());
            if let Flow::Exit(exit) = core.dispatch(outs) {
                break exit;
            }
            let ended = core.ledger.tick(Instant::now());
            if let Flow::Exit(exit) = core.ledger_ended(ended) {
                break exit;
            }
        }
        match received {
            Ok(Event::Frame(frame, credit)) => {
                if let Flow::Exit(exit) = core.arrived(frame, credit) {
                    break exit;
                }
            }
            Ok(Event::Response {
                id,
                payload,
                credit,
            }) => {
                // As a frame's: forwarded with the message, or dropped once
                // it is handled, which returns main's bulk credit.
                core.credit = Some(credit);
                let flow = core.handle_fragmented(id, payload);
                core.credit = None;
                if let Flow::Exit(exit) = flow {
                    break exit;
                }
            }
            Ok(Event::Eof {
                at_boundary,
                in_response,
            }) => {
                if in_response {
                    log::warn(
                        "stdin closed in the middle of a fragmented response",
                        serde_json::json!({}),
                    );
                } else if !at_boundary {
                    log::warn(
                        "stdin closed in the middle of a frame",
                        serde_json::json!({}),
                    );
                }
                break Exit::Ok;
            }
            Ok(Event::ProtocolError(category)) => {
                log::error(
                    "protocol error",
                    serde_json::json!({ "category": category }),
                );
                break Exit::Protocol;
            }
            Ok(Event::WriterFailed) => {
                log::error("stdout closed", serde_json::json!({}));
                break Exit::Protocol;
            }
            Ok(Event::NotReading { waited, thread }) => break not_reading(waited, thread),
            Ok(Event::ThreadDied(name)) => {
                log::error("a thread died", serde_json::json!({ "thread": name }));
                break Exit::Internal;
            }
            Ok(Event::ParentGone) => {
                log::info("parent exited", serde_json::json!({}));
                break Exit::Ok;
            }
            Ok(Event::Snapshot(snapshot, recovery)) => {
                core.vault.set_snapshot(snapshot);
                core.node_recovery = recovery;
                core.snapshot_ready = true;
                if let Some(id) = core.pending_hello.take()
                    && let Flow::Exit(exit) = core.hello_reply(id)
                {
                    break exit;
                }
            }
            Ok(Event::JobDone(job, output)) => {
                let outs = core.vault.job_done(job, output);
                if let Flow::Exit(exit) = core.dispatch(outs) {
                    break exit;
                }
            }
            Ok(Event::Room) => {
                let epoch = core.vault.epoch();
                if let Flow::Exit(exit) = core.outbox.pump(Instant::now(), epoch) {
                    break exit;
                }
            }
            // On to the stream's owner at once, in the order read, so a
            // piece's data follows its head there (design 0015, D4). Its
            // route is read in one step: its owner, or closed.
            Ok(Event::Stream(mark)) => match core.requests.routes().route(mark.key()) {
                // A frame for a body whose route the swarm thread closed:
                // main sent it after answering the body's call, or
                // cancelling it (design 0015, D4).
                Route::Closed => {
                    log::error(
                        "protocol error",
                        serde_json::json!({ "category": "stream_closed" }),
                    );
                    break Exit::Protocol;
                }
                Route::Owner(Owner::Dweb) => {
                    let Some(thread) = core.dweb.as_ref() else {
                        // The reader takes stream frames only after the
                        // hello, which starts the thread.
                        break Exit::Internal;
                    };
                    if !thread.send(dweb::In::Stream(mark), None) {
                        break Exit::Internal;
                    }
                }
                // Its parts, node bodies and `swarm.body` credit (design
                // 0015, D4).
                Route::Owner(Owner::Swarm) => {
                    let Some(thread) = core.swarm.as_ref() else {
                        break Exit::Internal;
                    };
                    if !thread.send(swarm::In::Stream(mark), None) {
                        break Exit::Internal;
                    }
                }
                // No other owner registers a route: a Ledger's replies
                // never stream (design 0016).
                Route::Owner(
                    Owner::Naming | Owner::Chain | Owner::KeyStore | Owner::Eip1193 | Owner::Ledger,
                ) => {
                    break Exit::Internal;
                }
            },
            // The timer is reckoned again at the top of the loop.
            Ok(Event::Watch) => {}
            Ok(Event::FeeReference { id, payload }) => {
                core.vault.fee_answered(id, &payload);
            }
            Ok(Event::Eip1193Room) => {
                let outs = core.connects.pump();
                if let Flow::Exit(exit) = core.dispatch(outs) {
                    break exit;
                }
            }
            // An APDU or a cancel waited for room: the lane sends it now.
            Ok(Event::LedgerRoom) => {
                let ended = core.ledger.tick(Instant::now());
                if let Flow::Exit(exit) = core.ledger_ended(ended) {
                    break exit;
                }
            }
            Ok(Event::ChainRead {
                tag,
                payload,
                past_due,
            }) => {
                // A page send's reads (APR-5e-1); a Safe method's (design
                // 0016, SAFE-2), by their tag's bit; or a phone payment's,
                // whose fixed deadline is no request's.
                let outs = if tag & crate::eip1193::SEND_TAG != 0 {
                    core.connects
                        .chain_read_done(tag, &payload, past_due, &mut core.vault)
                } else {
                    core.vault.chain_read(tag, &payload, past_due)
                };
                if let Flow::Exit(exit) = core.dispatch(outs) {
                    break exit;
                }
            }
            // The swarm thread's own checks (design 0015's D1), by their
            // tag's bit.
            Ok(Event::NameChecked { tag, verdict })
                if tag & crate::swarm::engine::NAME_TAG != 0 =>
            {
                let sent = core
                    .swarm
                    .as_ref()
                    .is_some_and(|thread| thread.send(swarm::In::Name { tag, verdict }, None));
                if !sent {
                    break Exit::Internal;
                }
            }
            Ok(Event::NameChecked { tag, verdict }) => {
                let outs = core.connects.name_checked(tag, verdict, &mut core.vault);
                if let Flow::Exit(exit) = core.dispatch(outs) {
                    break exit;
                }
            }
            // The vault answers at once, on this thread, which holds it;
            // with the test hooks, a signature's ask may wait for their
            // release first (`FREEDOM_CORED_TEST_SWARM_HOLD=ask=…`), as one
            // behind a cancel waits on this loop's queue.
            Ok(Event::SwarmVault { tag, ask }) => {
                if !core.swarm_ask(tag, ask) {
                    break Exit::Internal;
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break Exit::Ok,
        }
        // Then the next request that waited, if the loop's frames have room;
        // and a writer that has written nothing for the stall bound means
        // main has stopped reading.
        if let Flow::Exit(exit) = core.resume() {
            break exit;
        }
        if let Flow::Exit(exit) = core.outbox.check(Instant::now()) {
            break exit;
        }
        // A request the core cancelled and watches, unanswered past its
        // bound: main broke 0001's one answer per request (design 0015,
        // D13).
        if core.requests.overdue(Instant::now()).is_some() {
            log::error(
                "protocol error",
                serde_json::json!({ "category": "cancel_unanswered" }),
            );
            break Exit::Protocol;
        }
    };
    // No more requests to main, whatever ended the loop; a key-store call
    // still waiting is Unavailable, and lets the writer go.
    core.requests.close();
    core.keystore.close();
    // The dweb thread stops: it hands the writer the frames it made, drops
    // the bodies still queued (main fails them as it closes), and joins its
    // hashing pool.
    drop(core.dweb.take());
    core.dweb_start = None;
    // The swarm thread stops too, handing the writer what it made.
    drop(core.swarm.take());
    // Wipe the vault and revoke pre-commit work. Work past its commit point
    // finishes and replies before exit (bounded). Then let the writer flush
    // what's queued, but never wait on a peer that stopped reading: exiting
    // releases the gate. Requests still waiting their turn are dropped with
    // the loop: none of them ran.
    crate::testhooks::exiting();
    let outs = core.vault.shutdown();
    let _ = core.dispatch(outs);
    let draining = Instant::now();
    let until = draining + COMMIT_DRAIN;
    while core.vault.committing() {
        let Some(left) = until.checked_duration_since(Instant::now()) else {
            break;
        };
        match events.recv_timeout(left) {
            Ok(Event::JobDone(job, finished)) => {
                let outs = core.vault.job_done(job, finished);
                let _ = core.dispatch(outs);
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    // However the wait ended: past the drain, or the wait itself timing out.
    if core.vault.committing() {
        log::error(
            "a committed vault job did not finish before exit",
            serde_json::json!({ "waited_ms": draining.elapsed().as_millis() }),
        );
    }
    // What waits for room goes past the allowance: the drain below bounds it
    // by time instead.
    let epoch = core.vault.epoch();
    core.outbox.drain(epoch);
    // The writer ends once the producers' queues close; the transport's own
    // frames (main's credit) stop here.
    link.detach();
    drop(core);
    let _ = writer.done.recv_timeout(EXIT_DRAIN);
    drop(gate);
    exit
}

/// What `serve` sets up on its only thread before `confine` (design 0017,
/// "The order in serve", step 5).
struct Setup {
    /// The records' plan and the Radicle gate files (C3, C6).
    prepared: journal::Prepared,
    /// The legacy receipts' hand-over, with `--user-data-dir` (C5).
    handover: Option<crate::payments_store::Handover>,
    /// The legacy publish history's, beside it (design 0015, D10).
    history_handover: Option<crate::payments_store::Handover>,
    /// C2's `read_write`.
    read_write: Vec<PathBuf>,
}

/// Step 5, in order (the Freedom root was made before the gate: [`run`]):
/// - **Each missing `--node-root`** made with its ancestors (C2): Bee's
///   private, as the Freedom root is, and one that can't be made (a
///   regular file there, an ancestor that can't hold it, a parent whose
///   sync fails) is exit 74; Radicle's home by its gate file's creating
///   open below, as fc-service's gate makes it, where a failure is logged
///   and the home, if it isn't a directory then, left out of the grant.
/// - **The records planned** and the Radicle gate files opened (C6, C3).
/// - **The legacy receipts handed over** (C5) when `--user-data-dir` is
///   given, whatever the hello's `store_moved` will say: the profile's
///   root is out of reach once confined. Nothing is done when it is the
///   Freedom root (the old layout). The legacy `publish-history.json` the
///   same way (design 0015, D10), for the Swarm stores.
///
/// The vault's tightening at start stays on the snapshot thread, after the
/// node, delete and metadata journals' recovery that may replace the vault
/// file, as the intent journal's and the node layout's stay after the
/// hello: C4's `modes` lets each narrowing to owner-only through.
fn setup(options: &Options, gate: &gate::Gate) -> Result<Setup, Exit> {
    if let Some(bee) = &options.node_roots.bee
        && let Err(e) = journal::create_private_dirs(bee)
    {
        log::error(
            "cannot make a node root",
            serde_json::json!({ "node": "bee", "error": e.kind().to_string() }),
        );
        return Err(Exit::Storage);
    }
    let prepared = journal::prepare(
        &gate.identity_dir,
        &options.lock_dir,
        options.node_roots.radicle.as_deref(),
    );
    if !prepared.grant.is_empty() || prepared.gates.count() > 0 {
        log::info(
            "node records planned",
            serde_json::json!({
                "roots": prepared.grant.len(),
                "gate_files": prepared.gates.count(),
            }),
        );
    }
    let handover = options
        .user_data_dir
        .as_deref()
        .map(|dir| crate::payments_store::hand_over_legacy(dir, &options.grant_root));
    let history_handover = options.user_data_dir.as_deref().map(|dir| {
        crate::payments_store::hand_over_file(
            &crate::payments_store::PUBLISH_HISTORY,
            dir,
            &options.grant_root,
        )
    });
    let mut read_write = vec![gate.identity_dir.clone(), options.grant_root.clone()];
    for (node, root) in [
        ("bee", &options.node_roots.bee),
        ("radicle", &options.node_roots.radicle),
    ] {
        match root {
            Some(root) if root.is_dir() => read_write.push(root.clone()),
            Some(_) => log::error(
                "a node root isn't a directory: not granted",
                serde_json::json!({ "node": node }),
            ),
            None => {}
        }
    }
    read_write.extend(prepared.grant.iter().cloned());
    Ok(Setup {
        prepared,
        handover,
        history_handover,
        read_write,
    })
}

/// Reads the status snapshot on its own thread. False if the thread can't be
/// created. If the read never finishes, the hello deadline ends the process.
fn spawn_snapshot(
    identity_dir: PathBuf,
    lock_dir: PathBuf,
    radicle_gates: journal::RadicleGates,
    secrets: Arc<Secrets>,
    events: Sender<Event>,
) -> bool {
    std::thread::Builder::new()
        .name("snapshot".into())
        .spawn(move || {
            crate::testhooks::snapshot_delay();
            let (snapshot, recovery) =
                crate::vault::startup_snapshot(&identity_dir, &lock_dir, &radicle_gates);
            // The secrets file settles against the vault as it stands, before
            // the hello is answered and any job runs (design 0013).
            secrets.startup(
                snapshot
                    .as_ref()
                    .map(|fingerprint| fingerprint.as_deref())
                    .map_err(|_| ()),
            );
            let _ = events.send(Event::Snapshot(snapshot, recovery));
        })
        .is_ok()
}

/// Starts the parent watcher. False if the thread can't be created.
fn spawn_parent_watch(parent_pid: Option<u32>, events: Sender<Event>) -> bool {
    if parent_pid.is_none() {
        return true;
    }
    std::thread::Builder::new()
        .name("parent".into())
        .spawn(move || {
            while hardening::parent_alive(parent_pid) {
                std::thread::sleep(Duration::from_secs(2));
            }
            let _ = events.send(Event::ParentGone);
        })
        .is_ok()
}

enum Flow {
    Continue,
    Exit(Exit),
}

struct Core {
    /// Whether the startup snapshot has arrived.
    snapshot_ready: bool,
    /// Startup's node identity recovery outcome, for core.hello.
    node_recovery: NodeRecovery,
    /// A valid core.hello received before the snapshot was ready.
    pending_hello: Option<u64>,
    /// The hello's `store_moved` this core took, for its answer.
    stores_echo: Vec<&'static str>,
    /// The loop's share of the writer, and its frames waiting past it.
    outbox: Outbox,
    /// Requests from main waiting, in order, for the loop's frames to go.
    parked: VecDeque<Parked>,
    /// The `vault.lock`s among them, applied already and still to come.
    locks_ahead: usize,
    /// Bulk credit: main's hello says whether it takes fragments.
    link: Arc<Link>,
    /// The credit of the frame being handled.
    credit: Option<transport::Credit>,
    hello_done: bool,
    last_request_id: u64,
    vault: Vault,
    /// `serve`'s `--grant-root` and `--user-data-dir`, which the hello must
    /// match (design 0017, C1).
    grant_root_arg: PathBuf,
    user_data_dir_arg: Option<PathBuf>,
    /// The legacy receipts' hand-over before `confine` (design 0017, C5),
    /// with `--user-data-dir`: where the payments import reads.
    handover: Option<crate::payments_store::Handover>,
    /// The legacy `publish-history.json`'s hand-over beside it (design
    /// 0015, D10): where the publish history's import reads.
    history_handover: Option<crate::payments_store::Handover>,
    /// What `confine` reported (design 0017): the hello's `confinement`.
    confinement: serde_json::Value,
    worker: Worker,
    /// The core's requests to main: where main's responses go back to.
    requests: Arc<Requests>,
    /// The secrets file (design 0013): its drain starts with the hello's
    /// reply.
    secrets: Arc<Secrets>,
    /// The key store over `shell.keystore` (design 0013), whose answers
    /// this loop routes.
    keystore: Arc<DesktopKeyStore>,
    naming: naming::Handle,
    chain: chain::Handle,
    /// A page's connects waiting on main (design 0012, APR-5c).
    connects: Connects,
    /// The device lane (design 0016): the Ledger operations of `ledger.*`
    /// and of `sign.*` with a Ledger key, and their `shell.ledger_apdu`s.
    ledger: Lane<Then>,
    /// The dweb thread, once the hello has settled (design 0009).
    dweb: Option<dweb::Handle>,
    /// What starts it; taken when it starts.
    dweb_start: Option<DwebStart>,
    /// The swarm thread, once the hello has settled (design 0015).
    swarm: Option<swarm::Handle>,
    /// The Swarm requests' cancellations (design 0015), which a cancel from
    /// main sets: held weakly, each going with its request.
    swarm_cancels: BTreeMap<u64, crate::swarm::engine::CancelWatch>,
    /// The swarm thread's signature asks the test hooks hold before the
    /// vault runs them (`FREEDOM_CORED_TEST_SWARM_HOLD=ask=…`), in order.
    #[cfg(feature = "testhooks")]
    parked_asks: VecDeque<(u64, Box<crate::swarm::engine::VaultAsk>)>,
    /// The `test.*` methods' thread, when the test hooks enable it (debug
    /// builds only).
    #[cfg(feature = "testhooks")]
    test: Option<testmethods::Handle>,
}

/// What the dweb thread starts with: the writer, and the loop's events.
struct DwebStart {
    out: Sender<transport::Out>,
    events: Sender<Event>,
}

#[derive(Deserialize)]
struct HelloParams {
    protocol: u32,
    #[allow(dead_code)]
    shell_version: String,
    auto_lock_ms: u64,
    /// The frame kinds main takes beyond whole messages: `"fragment"` for
    /// fragmented responses with bulk credit (design 0005, Frames). Other
    /// names are ignored.
    #[serde(default)]
    frames: Vec<String>,
    /// Where main keeps each node's identity (`data_dir` for Bee, `home` for
    /// Radicle), as absolute paths: their files, which JS wrote under the
    /// umask, are tightened to 0600 (design 0001, "Writes and durability";
    /// #85). Optional.
    #[serde(default)]
    node_roots: Option<NodeRoots>,
    /// The Freedom root, as an absolute path: where the four permission
    /// files (design 0012, "The files") and the set-A stores live. It
    /// equals the profile's `userData` until 0013's move (PRF-9), and is
    /// `<userData>/freedom/` after it. Required.
    #[serde(default)]
    grant_root: Option<String>,
    /// The profile's `userData`, as an absolute path: where the reference
    /// keeps `x402-receipts.json` (`app.getPath('userData')`), which the
    /// payment history imports once (design 0013, "Payment history"). It
    /// stays at the profile's root after the move, where the core copies it
    /// into `grant_root` to import it (design 0017, C5). Optional: absent
    /// means `grant_root`, which equals it before PRF-9. A core before
    /// PRF-8-lite ignores it, as it ignores every hello member it doesn't
    /// know.
    #[serde(default)]
    user_data_dir: Option<String>,
    /// The permission files main has handed to the core (`dapp`, `swarm`,
    /// `radicle`, `x402`): the core writes these, and only reads the
    /// others.
    #[serde(default)]
    grant_moved: Vec<String>,
    /// The set-A stores main has handed to the core (design 0013, "One
    /// writer per store: `store_moved`"): [`STORES`]. Absent means none.
    #[serde(default)]
    store_moved: Vec<String>,
}

/// The names `store_moved` may give (design 0013): all known from the
/// first core that reads the field, whatever it serves.
const STORES: &[&str] = &[
    "vault_meta",
    "intents",
    "payments",
    "safe_pending",
    "rpc_api_keys",
    crate::swarm::stores::STORE,
];

/// The stores this core serves once named: the echo holds only these.
const STORES_SERVED: &[&str] = &[
    "vault_meta",
    "intents",
    "safe_pending",
    "payments",
    "rpc_api_keys",
    crate::swarm::stores::STORE,
];

/// The hello's `store_moved`, each name once, in the hello's order. A name
/// [`STORES`] doesn't list makes the hello malformed.
fn stores_moved(params: &HelloParams) -> Result<Vec<&'static str>, &'static str> {
    let mut moved = Vec::new();
    for name in &params.store_moved {
        let known = STORES
            .iter()
            .find(|known| **known == name)
            .ok_or("core.hello's store_moved names an unknown store")?;
        if !moved.contains(known) {
            moved.push(*known);
        }
    }
    Ok(moved)
}

/// The hello's grant files: `grant_root`, an absolute path, and the stores
/// in `grant_moved`. A hello without the root, with a relative one, or
/// naming a store the core doesn't know, is malformed (design 0012, APR-3).
fn grant_files(params: &HelloParams) -> Result<(PathBuf, Vec<StoreKind>), &'static str> {
    let root = params
        .grant_root
        .as_deref()
        .map(PathBuf::from)
        .filter(|root| crate::journal::normalized_absolute(root))
        .ok_or("core.hello needs grant_root, an absolute path")?;
    let mut moved = Vec::new();
    for name in &params.grant_moved {
        let kind =
            StoreKind::from_name(name).ok_or("core.hello's grant_moved names an unknown store")?;
        if !moved.contains(&kind) {
            moved.push(kind);
        }
    }
    Ok((root, moved))
}

/// The hello's `user_data_dir`, an absolute, normalized path, or `None`
/// when absent. A relative one, or one with `..` in it, makes the hello
/// malformed, as for `grant_root` (design 0013, PRF-8-lite).
fn user_data_dir(params: &HelloParams) -> Result<Option<PathBuf>, &'static str> {
    params
        .user_data_dir
        .as_deref()
        .map(|dir| {
            Some(PathBuf::from(dir))
                .filter(|dir| crate::journal::normalized_absolute(dir))
                .ok_or("core.hello's user_data_dir must be an absolute path")
        })
        .transpose()
}

/// Whether the hello names the directories `serve`'s arguments gave (design
/// 0017, C1), compared by components as [`Path`] compares them, after both
/// passed the same check ([`crate::journal::normalized_absolute`]):
/// `grant_root` equal to `--grant-root`, and `user_data_dir` equal to
/// `--user-data-dir`, both given or both absent. Confined, `serve` reaches
/// the profile's root only through the hand-over before `confine` (C5),
/// so a hello can't name one its arguments didn't.
fn hello_matches_args(
    grant_root: &Path,
    user_data_dir: Option<&Path>,
    grant_root_arg: &Path,
    user_data_dir_arg: Option<&Path>,
) -> Result<(), &'static str> {
    if grant_root_arg != grant_root {
        return Err("core.hello's grant_root isn't serve's --grant-root");
    }
    if user_data_dir_arg != user_data_dir {
        return Err("core.hello's user_data_dir isn't serve's --user-data-dir");
    }
    Ok(())
}

#[derive(Deserialize)]
struct NodeRoots {
    #[serde(default)]
    bee: Option<String>,
    #[serde(default)]
    radicle: Option<String>,
}

impl NodeRoots {
    /// The roots given, as absolute, normalized paths. Others are logged
    /// and skipped: tightening is hardening, not worth failing a handshake.
    fn valid(self) -> Vec<(&'static str, PathBuf)> {
        [("bee", self.bee), ("radicle", self.radicle)]
            .into_iter()
            .filter_map(|(node, root)| {
                let root = PathBuf::from(root?);
                if crate::journal::normalized_absolute(&root) {
                    Some((node, root))
                } else {
                    log::warn(
                        "ignoring a node root that isn't an absolute path",
                        serde_json::json!({ "node": node }),
                    );
                    None
                }
            })
            .collect()
    }
}

/// Tightens existing node identity files on their own thread, so slow
/// storage can't hold up the handshake or the loop. Main starts nodes only
/// after the handshake, and a node reading its files meanwhile is
/// unaffected by a mode change.
fn spawn_adoption(roots: Vec<(&'static str, PathBuf)>) {
    if roots.is_empty() {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("adopt".into())
        .spawn(move || {
            for (node, root) in roots {
                let changed = crate::nodes::tighten_existing(node, &root);
                if changed > 0 {
                    log::info(
                        "tightened node identity files to 0600",
                        serde_json::json!({ "node": node, "count": changed }),
                    );
                }
            }
        });
    if spawned.is_err() {
        log::warn(
            "cannot start the thread that tightens node identity files",
            serde_json::json!({}),
        );
    }
}

#[derive(Serialize)]
struct HelloResult<'a> {
    protocol: u32,
    core_version: &'static str,
    /// The methods, then the transport features.
    capabilities: Vec<&'static str>,
    /// A node identity write that startup recovery couldn't finish
    /// (`pending_recovery`) or found broken (`corrupt`); `null` otherwise.
    /// Main keeps that node stopped.
    node_recovery: &'a NodeRecovery,
    /// The names in the hello's `store_moved` whose store this core serves,
    /// each once (design 0013, "One writer per store").
    store_moved: &'a [&'static str],
    /// The confinement `serve` got (design 0017): `fc_service`'s report,
    /// as the services' ready lines carry it. Main logs it.
    confinement: &'a serde_json::Value,
}

/// Where `text`, borrowed from `payload`, lies in it.
fn span(payload: &[u8], text: &RawValue) -> Range<usize> {
    let start = (text.get().as_ptr() as usize).wrapping_sub(payload.as_ptr() as usize);
    start..start.saturating_add(text.get().len())
}

/// A method name that is safe to log: known names only.
fn loggable(method: &str) -> &'static str {
    if let Some(row) = methods::method(method) {
        return row.name;
    }
    #[cfg(feature = "testhooks")]
    if let Some(name) = testmethods::METHODS
        .iter()
        .chain(swarm::TEST_METHODS)
        .find(|m| **m == method)
    {
        return name;
    }
    "<unknown>"
}

/// Whether `caller` may call `method` (#101): fc-protocol's method table,
/// checked once for every request before anything is dispatched, and with
/// the `testhooks` feature the test methods, when their hook enables them,
/// and a page's `approval.issue`, when its hook does (`testhooks::mains_word`).
/// `Err` is the refusal: a method the table doesn't list is unknown; one it
/// lists, but not for this caller, is forbidden. The core speaks only
/// protocol 2, at which the table serves every row.
fn admitted(method: &str, caller: CallerKind, test_methods: bool) -> Result<(), ErrorBody> {
    match methods::admit(method, caller, fc_protocol::PROTOCOL_VERSION_STREAMS) {
        Admission::Allowed(_) => Ok(()),
        Admission::Forbidden => {
            if method == "approval.issue"
                && caller == CallerKind::Page
                && crate::testhooks::mains_word()
            {
                return Ok(());
            }
            Err(ErrorBody::new(
                ErrorCode::Forbidden,
                "not callable by this caller",
            ))
        }
        Admission::Unknown => {
            #[cfg(feature = "testhooks")]
            if test_methods
                && (testmethods::handles(method) || swarm::TEST_METHODS.contains(&method))
                && caller != CallerKind::Page
            {
                return Ok(());
            }
            let _ = test_methods;
            Err(ErrorBody::new(ErrorCode::UnknownMethod, "Unknown method"))
        }
    }
}

/// A fixed category for a malformed message; the parser's own text can quote
/// input and is never logged.
fn message_category(error: &MessageError) -> &'static str {
    match error {
        MessageError::Malformed(_) => "malformed",
        MessageError::UnknownType(_) => "unknown_type",
        MessageError::Missing(field) => field,
        MessageError::BadId(_) => "bad_id",
        MessageError::ResultAndError => "result_and_error",
    }
}

/// A message from main that waits, with its reader credit, for the loop's
/// frames to go.
struct Parked {
    frame: Frame,
    credit: transport::Credit,
    /// Its request ID; `None` for a cancel waiting behind its request.
    request: Option<u64>,
    /// A `vault.lock` the loop has applied already; its turn acknowledges
    /// it.
    lock: bool,
}

/// What a message that arrives while requests wait asks of the loop before
/// its turn.
enum Ahead {
    /// `core.shutdown`: handled at once.
    Shutdown,
    /// `vault.lock`: locks at once, and waits for its turn.
    Lock(u64),
    /// Any other request: waits for its turn.
    Request(u64),
    /// A cancel: reaches admitted work at once, unless its request waits.
    Cancel(u64),
    /// Anything else is handled at once, as it adds nothing to the loop's
    /// frames: responses go to naming and chain, events are ignored, and a
    /// malformed message ends the connection.
    Other,
}

impl Ahead {
    fn of(frame: &Frame) -> Self {
        if frame.kind != KIND_JSON {
            return Ahead::Other;
        }
        match Message::decode(&frame.payload) {
            // Refused in its turn: web content can't lock or shut down.
            // Refused in its turn: a caller the method table doesn't allow
            // for it (web content, or the browser UI for `core.shutdown`)
            // can't shut down or lock ahead of the requests that wait.
            Ok(Message::Request {
                id,
                method,
                context,
                ..
            }) if !matches!(
                // Read ahead of the hello: every method this build serves.
                methods::admit(
                    &method,
                    context.caller,
                    fc_protocol::PROTOCOL_VERSION_STREAMS
                ),
                Admission::Allowed(_)
            ) =>
            {
                Ahead::Request(id)
            }
            Ok(Message::Request { id, method, .. }) => match &*method {
                "core.shutdown" => Ahead::Shutdown,
                "vault.lock" => Ahead::Lock(id),
                _ => Ahead::Request(id),
            },
            Ok(Message::Cancel { id }) => Ahead::Cancel(id),
            _ => Ahead::Other,
        }
    }
}

impl Core {
    /// The swarm thread's ask of the vault under `tag`: answered now, or,
    /// with the test hooks, a signature's held until their release. False
    /// once the thread has gone.
    fn swarm_ask(&mut self, tag: u64, ask: Box<crate::swarm::engine::VaultAsk>) -> bool {
        #[cfg(feature = "testhooks")]
        if matches!(
            *ask,
            crate::swarm::engine::VaultAsk::Sign(_) | crate::swarm::engine::VaultAsk::OwnSign(_)
        ) && (!self.parked_asks.is_empty() || crate::testhooks::swarm_hold_parks("ask"))
        {
            self.parked_asks.push_back((tag, ask));
            return true;
        }
        self.swarm_vault(tag, &ask)
    }

    /// The vault's answer to the swarm thread's ask under `tag`, sent to
    /// it: false once the thread has gone.
    fn swarm_vault(&mut self, tag: u64, ask: &crate::swarm::engine::VaultAsk) -> bool {
        let answer = Box::new(self.vault.swarm_vault(ask));
        self.swarm
            .as_ref()
            .is_some_and(|thread| thread.send(swarm::In::Vault { tag, answer }, None))
    }

    /// A new Swarm request's cancellation, kept (weakly) for main's cancel
    /// of it; those whose request has gone are let go of as more come.
    fn swarm_cancellable(&mut self, id: u64) -> crate::swarm::engine::Cancelled {
        let cancelled = crate::swarm::engine::Cancelled::default();
        if self.swarm_cancels.len() >= 1024 {
            self.swarm_cancels.retain(|_, watch| !watch.gone());
        }
        self.swarm_cancels.insert(id, cancelled.watch());
        cancelled
    }

    /// A frame from main. While requests wait (the loop's frames have no
    /// room in the writer), requests wait too, in order, and keep their
    /// credits: once those are spent, the reader stops reading stdin.
    /// Control traffic doesn't wait ([`Ahead`]).
    fn arrived(&mut self, frame: Frame, credit: transport::Credit) -> Flow {
        if self.waiting() {
            match Ahead::of(&frame) {
                // What waits before it never ran, and main is closing the
                // core: dropped.
                Ahead::Shutdown => {
                    self.parked.clear();
                    self.locks_ahead = 0;
                }
                // Locks now, as the auto-lock would: the secrets go and
                // admitted work is revoked. Its acknowledgement waits for its
                // turn, and until then holds the lock (`resume`).
                Ahead::Lock(id) => {
                    self.park(frame, credit, Some(id), true);
                    let outs = self.vault.lock();
                    return self.dispatch(outs);
                }
                Ahead::Request(id) => {
                    self.park(frame, credit, Some(id), false);
                    return Flow::Continue;
                }
                // Its request hasn't been handled yet: it follows it.
                Ahead::Cancel(id) if self.parked.iter().any(|p| p.request == Some(id)) => {
                    self.park(frame, credit, None, false);
                    return Flow::Continue;
                }
                Ahead::Cancel(_) | Ahead::Other => {}
            }
        }
        self.handle(frame, credit)
    }

    /// Whether requests wait: the loop's frames wait for room, or requests
    /// taken meanwhile still wait for their turn.
    fn waiting(&self) -> bool {
        self.outbox.is_waiting() || !self.parked.is_empty()
    }

    fn park(&mut self, frame: Frame, credit: transport::Credit, request: Option<u64>, lock: bool) {
        if lock {
            self.locks_ahead += 1;
        }
        self.parked.push_back(Parked {
            frame,
            credit,
            request,
            lock,
        });
    }

    /// Whether a request that waited can go: the loop's frames have room.
    fn resumable(&self) -> bool {
        !self.parked.is_empty() && !self.outbox.is_waiting()
    }

    /// Handles the next request that waited, if it can go: one per turn of
    /// the loop, as if it had just been read, so whatever main sends
    /// meanwhile (a cancel, a shutdown) and the loop's timers come between
    /// them.
    fn resume(&mut self) -> Flow {
        if !self.resumable() {
            return Flow::Continue;
        }
        // What is due first, right before the request: an auto-lock that
        // came due while the backlog drained locks before it, and before a
        // `vault.touch` could postpone it.
        let outs = self.vault.tick();
        if let Flow::Exit(exit) = self.dispatch(outs) {
            return Flow::Exit(exit);
        }
        if self.outbox.is_waiting() {
            return Flow::Continue;
        }
        let Some(parked) = self.parked.pop_front() else {
            return Flow::Continue;
        };
        if parked.lock {
            self.locks_ahead = self.locks_ahead.saturating_sub(1);
        }
        if let Flow::Exit(exit) = self.handle(parked.frame, parked.credit) {
            return Flow::Exit(exit);
        }
        // A lock still to come holds meanwhile: what this request admitted
        // is revoked, as that lock's turn would have done.
        if self.locks_ahead > 0 {
            let outs = self.vault.lock();
            return self.dispatch(outs);
        }
        Flow::Continue
    }

    /// Handles a frame. A message forwarded to another thread takes its
    /// credit along; otherwise the credit goes once the frame is handled.
    fn handle(&mut self, frame: Frame, credit: transport::Credit) -> Flow {
        self.credit = Some(credit);
        let flow = self.handle_frame(frame);
        self.credit = None;
        flow
    }

    fn handle_frame(&mut self, frame: Frame) -> Flow {
        if frame.kind != KIND_JSON {
            log::error(
                "protocol error",
                serde_json::json!({ "category": "frame_kind" }),
            );
            return Flow::Exit(Exit::Protocol);
        }
        let message = match Message::decode(&frame.payload) {
            Ok(message) => message,
            Err(e) => {
                log::error(
                    "protocol error",
                    serde_json::json!({ "category": message_category(&e) }),
                );
                return Flow::Exit(Exit::Protocol);
            }
        };
        match message {
            Message::Request {
                id,
                method,
                params,
                context,
            } => {
                if !self.hello_done && method != "core.hello" {
                    log::error(
                        "protocol error",
                        serde_json::json!({ "category": "not_hello_first" }),
                    );
                    return Flow::Exit(Exit::Protocol);
                }
                // IDs come from main's counter: strictly increasing, never
                // reused.
                if id <= self.last_request_id {
                    log::error(
                        "protocol error",
                        serde_json::json!({ "category": "reused_id", "id": id }),
                    );
                    return Flow::Exit(Exit::Protocol);
                }
                self.last_request_id = id;
                self.handle_request(id, &method, params.map(|p| p.get()), &context)
            }
            _ if !self.hello_done => {
                log::error(
                    "protocol error",
                    serde_json::json!({ "category": "not_hello_first" }),
                );
                Flow::Exit(Exit::Protocol)
            }
            // A cancel names a vault request, a naming one, a chain one, a
            // dweb one or a swarm one; each ignores IDs it doesn't hold.
            Message::Cancel { id } => {
                // A Swarm request's vault asks still on this loop's queue,
                // behind this cancel, sign nothing (design 0015, "Deadlines
                // and cancel").
                if let Some(cancelled) = self.swarm_cancels.remove(&id) {
                    cancelled.set();
                }
                if !self.chain.send(chain::In::Cancel { id }, None)
                    || self
                        .dweb
                        .as_ref()
                        .is_some_and(|thread| !thread.send(dweb::In::Cancel { id }, None))
                    || self
                        .swarm
                        .as_ref()
                        .is_some_and(|thread| !thread.send(swarm::In::Cancel { id }, None))
                    || !self
                        .naming
                        .send(naming::In::Cancel { id }, self.credit.take())
                {
                    return Flow::Exit(Exit::Internal);
                }
                // A Ledger operation ends wherever it is (design 0016).
                let ended = self.ledger.cancel(id, Instant::now());
                if let Flow::Exit(exit) = self.ledger_ended(ended) {
                    return Flow::Exit(exit);
                }
                let mut outs = self.vault.cancel(id);
                outs.extend(self.connects.cancel(id));
                self.dispatch(outs)
            }
            Message::Response { id, outcome } => {
                let outcome = match outcome {
                    Ok(result) => Ok(span(&frame.payload, result)),
                    Err(error) => Err(span(&frame.payload, error.raw())),
                };
                self.response(id, outcome, frame.payload)
            }
            Message::Event { .. } => {
                log::warn("ignoring an event from main", serde_json::json!({}));
                Flow::Continue
            }
        }
    }

    /// A fragmented response, reassembled: it must be the response its begin
    /// named.
    fn handle_fragmented(&mut self, id: u64, payload: Zeroizing<Vec<u8>>) -> Flow {
        let category = match Message::decode(&payload) {
            Ok(Message::Response {
                id: answered,
                outcome,
            }) if answered == id && self.hello_done => {
                let outcome = match outcome {
                    Ok(result) => Ok(span(&payload, result)),
                    Err(error) => Err(span(&payload, error.raw())),
                };
                return self.response(id, outcome, payload);
            }
            Ok(_) if !self.hello_done => "not_hello_first",
            Ok(_) => "fragmented_not_its_response",
            Err(e) => message_category(&e),
        };
        log::error(
            "protocol error",
            serde_json::json!({ "category": category }),
        );
        Flow::Exit(Exit::Protocol)
    }

    /// Main's response to one of the core's requests (`shell.*`), routed
    /// to the thread that made it: the span of its `result` or its `error`
    /// in `message`, the response as it was read. One that answers no
    /// request is unsolicited, a protocol error (0001).
    fn response(
        &mut self,
        id: u64,
        outcome: Result<Range<usize>, Range<usize>>,
        message: Zeroizing<Vec<u8>>,
    ) -> Flow {
        let Some(owner) = self.requests.answered(id) else {
            log::error(
                "protocol error",
                serde_json::json!({ "category": "unsolicited_response" }),
            );
            return Flow::Exit(Exit::Protocol);
        };
        if owner == Owner::Eip1193 {
            let outs = self
                .connects
                .answered(id, outcome, &message, &mut self.vault);
            return self.dispatch(outs);
        }
        // The device lane reads its answer strictly (design 0016): a reply
        // that breaks `shell.ledger_apdu`'s rules ends the connection.
        if owner == Owner::Ledger {
            let span = match &outcome {
                Ok(span) | Err(span) => span.clone(),
            };
            let Some(text) = message
                .get(span)
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
            else {
                return Flow::Exit(Exit::Internal);
            };
            let outcome = match outcome {
                Ok(_) => Ok(text),
                Err(_) => Err(text),
            };
            return match self.ledger.answered(id, outcome, Instant::now()) {
                Ok(ended) => self.ledger_ended(ended),
                Err(protocol) => {
                    log::error(
                        "protocol error",
                        serde_json::json!({ "category": protocol.category() }),
                    );
                    Flow::Exit(Exit::Protocol)
                }
            };
        }
        let sent = match (owner, outcome) {
            // Naming copies its result out of the message, and reads its
            // error whole.
            (Owner::Naming, outcome) => {
                let span = match &outcome {
                    Ok(span) | Err(span) => span.clone(),
                };
                let Some(text) = message
                    .get(span)
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                else {
                    return Flow::Exit(Exit::Internal);
                };
                let outcome = match outcome {
                    Ok(_) => match RawValue::from_string(text.to_owned()) {
                        Ok(result) => Ok(result),
                        Err(_) => return Flow::Exit(Exit::Internal),
                    },
                    Err(_) => {
                        let error = serde_json::from_str::<&RawValue>(text)
                            .map_err(|e| MessageError::Malformed(e.to_string()))
                            .and_then(ErrorBody::from_raw);
                        match error {
                            Ok(error) => Err(error),
                            Err(e) => {
                                log::error(
                                    "protocol error",
                                    serde_json::json!({ "category": message_category(&e) }),
                                );
                                return Flow::Exit(Exit::Protocol);
                            }
                        }
                    }
                };
                self.naming
                    .send(naming::In::Response { id, outcome }, self.credit.take())
            }
            // The chain thread takes the message itself, uncopied, and
            // charges it to the request that asked before reading any of it,
            // its result or its error (57-M4; round 2).
            (Owner::Chain, Ok(result)) => self.chain.send(
                chain::In::Response {
                    id,
                    reply: chain::Shell::Result { message, result },
                },
                self.credit.take(),
            ),
            (Owner::Chain, Err(error)) => self.chain.send(
                chain::In::Response {
                    id,
                    reply: chain::Shell::Failed { message, error },
                },
                self.credit.take(),
            ),
            // The key store copies its answer out, at most its cap, for the
            // call waiting on it.
            (Owner::KeyStore, outcome) => {
                self.keystore.deliver(id, outcome, &message);
                true
            }
            // Answered above.
            (Owner::Eip1193, _) => true,
            // The swarm thread reads its answer where it lies, as the dweb
            // thread does (design 0015).
            (Owner::Swarm, outcome) => self.swarm.as_ref().is_some_and(|thread| {
                thread.send(
                    swarm::In::Response {
                        id,
                        message,
                        outcome,
                    },
                    self.credit.take(),
                )
            }),
            // Answered above.
            (Owner::Ledger, _) => true,
            // The dweb thread reads its piece's reply where it lies, as the
            // chain thread does.
            (Owner::Dweb, outcome) => self.dweb.as_ref().is_some_and(|thread| {
                thread.send(
                    dweb::In::Response {
                        id,
                        message,
                        outcome,
                    },
                    self.credit.take(),
                )
            }),
        };
        if sent {
            Flow::Continue
        } else {
            Flow::Exit(Exit::Internal)
        }
    }

    fn handle_request(
        &mut self,
        id: u64,
        method: &str,
        params: Option<&str>,
        context: &Context,
    ) -> Flow {
        let started = Instant::now();
        #[cfg(feature = "testhooks")]
        let test_methods = self.test.is_some();
        #[cfg(not(feature = "testhooks"))]
        let test_methods = false;
        if let Err(refusal) = admitted(method, context.caller, test_methods) {
            return self.error(id, refusal);
        }
        let flow = match method {
            "core.hello" => self.hello(id, params),
            "core.shutdown" => {
                // No request to main goes after the acknowledgement.
                self.requests.close();
                match self.result(id, &serde_json::json!({})) {
                    Flow::Continue => Flow::Exit(Exit::Ok),
                    exit => exit,
                }
            }
            "eip1193.request" => self.eip1193(id, params, context),
            method if ledger::handles(method) => self.ledger_request(id, method, params),
            method if Vault::handles(method) => {
                let outs = self.vault.request(id, method, params, context);
                self.dispatch(outs)
            }
            method if naming::handles(method) => {
                let params = match params.map(|p| RawValue::from_string(p.to_owned())) {
                    Some(Ok(params)) => Some(params),
                    Some(Err(_)) => return Flow::Exit(Exit::Internal),
                    None => None,
                };
                if self.naming.send(
                    naming::In::Request {
                        id,
                        method: loggable(method),
                        params,
                    },
                    self.credit.take(),
                ) {
                    Flow::Continue
                } else {
                    Flow::Exit(Exit::Internal)
                }
            }
            method if chain::handles(method) => {
                if method == "chain.fee_reference" {
                    self.vault.fee_asked(id, params);
                }
                let params = match params.map(|p| RawValue::from_string(p.to_owned())) {
                    Some(Ok(params)) => Some(params),
                    Some(Err(_)) => return Flow::Exit(Exit::Internal),
                    None => None,
                };
                if self.chain.send(
                    chain::In::Request {
                        id,
                        method: loggable(method),
                        params,
                    },
                    self.credit.take(),
                ) {
                    Flow::Continue
                } else {
                    Flow::Exit(Exit::Internal)
                }
            }
            // Admitted only after the hello, which started the thread.
            method if dweb::handles(method) => {
                let params = match params.map(|p| RawValue::from_string(p.to_owned())) {
                    Some(Ok(params)) => Some(params),
                    Some(Err(_)) => return Flow::Exit(Exit::Internal),
                    None => None,
                };
                let sent = self.dweb.as_ref().is_some_and(|thread| {
                    thread.send(
                        dweb::In::Request {
                            id,
                            method: loggable(method),
                            params,
                        },
                        self.credit.take(),
                    )
                });
                if sent {
                    Flow::Continue
                } else {
                    Flow::Exit(Exit::Internal)
                }
            }
            // Admitted only after the hello, which started the thread: a
            // page's, with its `PageContext` (design 0015); or main's ask for
            // a body, whose credit is the thread's from now on, routed
            // before the thread can open the body (D4).
            method if swarm::handles(method) => {
                let params = match params.map(|p| RawValue::from_string(p.to_owned())) {
                    Some(Ok(params)) => Some(params),
                    Some(Err(_)) => return Flow::Exit(Exit::Internal),
                    None => None,
                };
                let message = match method {
                    "swarm.body" => {
                        self.requests
                            .routes()
                            .register(StreamKey::Body(id), Owner::Swarm);
                        swarm::In::Body { id, params }
                    }
                    "swarm.request" => swarm::In::Request {
                        id,
                        params,
                        page: context.page.clone(),
                        cancelled: self.swarm_cancellable(id),
                    },
                    // Main's own Swarm methods, and the chrome's (D5).
                    _ => swarm::In::Own {
                        id,
                        method: loggable(method),
                        params,
                        caller: context.caller,
                        cancelled: self.swarm_cancellable(id),
                    },
                };
                let sent = self
                    .swarm
                    .as_ref()
                    .is_some_and(|thread| thread.send(message, self.credit.take()));
                if sent {
                    Flow::Continue
                } else {
                    Flow::Exit(Exit::Internal)
                }
            }
            #[cfg(feature = "testhooks")]
            method if swarm::TEST_METHODS.contains(&method) && self.test.is_some() => {
                let params = match params.map(|p| RawValue::from_string(p.to_owned())) {
                    Some(Ok(params)) => Some(params),
                    Some(Err(_)) => return Flow::Exit(Exit::Internal),
                    None => None,
                };
                let message = if method == "test.swarm_feed_change" {
                    swarm::In::FeedChange { id, params }
                } else {
                    swarm::In::World { id, params }
                };
                let sent = self
                    .swarm
                    .as_ref()
                    .is_some_and(|thread| thread.send(message, self.credit.take()));
                if sent {
                    Flow::Continue
                } else {
                    Flow::Exit(Exit::Internal)
                }
            }
            #[cfg(feature = "testhooks")]
            method if testmethods::handles(method) && self.test.is_some() => {
                let params = match params.map(|p| RawValue::from_string(p.to_owned())) {
                    Some(Ok(params)) => Some(params),
                    Some(Err(_)) => return Flow::Exit(Exit::Internal),
                    None => None,
                };
                let sent = self.test.as_ref().is_some_and(|test| {
                    test.send(
                        testmethods::In::Request {
                            id,
                            method: method.to_owned(),
                            params,
                        },
                        self.credit.take(),
                    )
                });
                if sent {
                    Flow::Continue
                } else {
                    Flow::Exit(Exit::Internal)
                }
            }
            _ => self.error(
                id,
                ErrorBody::new(ErrorCode::UnknownMethod, "Unknown method"),
            ),
        };
        log::info(
            "request",
            serde_json::json!({ "id": id, "method": loggable(method), "ms": started.elapsed().as_millis() as u64 }),
        );
        flow
    }

    /// A page's `eip1193.request` (design 0012, "fc-eip1193 and
    /// approval.request"; APR-5b, the reads; APR-5c, connects and chain
    /// switches; APR-5d, signatures; APR-5e, sends; APR-5f, names over
    /// IPNS):
    /// fc-eip1193's dispatcher, with the page's key (`PageContext.origin`;
    /// empty for a document with no key) and the dApp store. An answer goes
    /// now; a read goes to the chain thread, which answers from its
    /// outcome; a connect, a switch or a signature waits on main's recheck,
    /// prompt or selection, and a name-keyed document's on its name checks.
    fn eip1193(&mut self, id: u64, params: Option<&str>, context: &Context) -> Flow {
        // Its 120 s run from here (`Deadline::Steps`).
        let received = Instant::now();
        let invalid = || ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters");
        let Some(page) = context.page.as_ref() else {
            return self.error(id, invalid());
        };
        let Ok(mut request) = fc_eip1193::Request::parse(params.unwrap_or("{}")) else {
            return self.error(id, invalid());
        };
        let key = (!page.origin.is_empty()).then_some(page.origin.as_str());
        // Names over IPNS (APR-5f): a name-revalidated method of a document
        // whose key is a DNS name over IPNS checks the name before it first
        // reads the key's grant (`not_moved` first, for one that writes the
        // dApp store). A chain switch checks once its params pass.
        let binding = fc_eip1193::names::Binding::of(&page.origin, page.transport_key.as_deref());
        let first = fc_eip1193::names::checks_first(&request.method);
        if let (Some(binding), Some(left), Some(_), true) =
            (binding, first, key, request.world.enabled)
        {
            if request.method != "eth_accounts"
                && let Some(refused) = self.dapp_unmoved(id)
            {
                return refused;
            }
            let page = page.clone();
            let outs =
                self.connects
                    .named(id, request, &page, binding, left, received, &mut self.vault);
            return self.dispatch(outs);
        }
        // Once `vault_meta` is moved the wallet list is the core's own, read
        // where the dispatcher reads it (G20b): here for the methods whose
        // start reads it, at a name-keyed document's start after its checks,
        // and at a send's prepare.
        if fc_eip1193::reads_wallets(&request.method) {
            crate::eip1193::own_wallets(&mut request.world, &self.vault);
        }
        let vault = &self.vault;
        match fc_eip1193::start(&request, key, |key| vault.dapp_entry(key)) {
            fc_eip1193::Step::Answer(answer) => match RawValue::from_string(answer.into_string()) {
                Ok(answer) => self.result(id, &answer),
                Err(_) => Flow::Exit(Exit::Internal),
            },
            fc_eip1193::Step::Read(read) => {
                if self.chain.send(
                    chain::In::Eip1193 { id, read, received },
                    self.credit.take(),
                ) {
                    Flow::Continue
                } else {
                    Flow::Exit(Exit::Internal)
                }
            }
            // A send for a document with a key (APR-5e): `not_moved`
            // first, as for a signature (*inferred*), then its form, before
            // any name check (APR-5f-2), as the reference's `txOf`. Then the
            // name's checks, the grant, the account and the Safe's chain,
            // the rule, and the quote, which the core's own chain machine
            // gives.
            fc_eip1193::Step::Send(send) => {
                if let Some(refused) = self.dapp_unmoved(id) {
                    return refused;
                }
                if let Err(answer) = send.form() {
                    return match RawValue::from_string(answer.into_string()) {
                        Ok(answer) => self.result(id, &answer),
                        Err(_) => Flow::Exit(Exit::Internal),
                    };
                }
                let page = page.clone();
                let outs = self
                    .connects
                    .send(id, send, &page, received, &mut self.vault);
                self.dispatch(outs)
            }
            // A connect, a chain switch or a signature for a document with
            // a key (APR-5c, APR-5d): before the dApp store moves, main
            // writes its grants, so the core takes none (*inferred*). Then
            // main's recheck, its prompt, or the signature's grant, account,
            // view and rule, up to its prompt or its rule.
            step => {
                let page = page.clone();
                let outs =
                    self.connects
                        .run(id, &request.method, step, &page, received, &mut self.vault);
                self.dispatch(outs)
            }
        }
    }

    /// `ledger.accounts` or `ledger.add` (design 0016, "Accounts"): its
    /// operation onto the device lane, or its refusal before any APDU.
    fn ledger_request(&mut self, id: u64, method: &str, params: Option<&str>) -> Flow {
        let vault = &self.vault;
        let started = ledger::start(
            method,
            params,
            || vault.ledger_checks(),
            vault.accounts_moved(),
        );
        match started {
            Ok((operation, then, turn)) => {
                let ended = self
                    .ledger
                    .submit(id, operation, then, turn, Instant::now());
                self.ledger_ended(ended)
            }
            Err(error) => self.error(id, error),
        }
    }

    /// The Ledger operations that ended: each parent answered, or its
    /// result handed to the accounts store first, or a signature to its
    /// authorization's end (design 0016, L4).
    fn ledger_ended(&mut self, ended: Vec<Ended<Then>>) -> Flow {
        for ended in ended {
            let flow = match ledger::finish(ended) {
                Finish::Answer(id, Ok(answer)) => self.result(id, &answer),
                Finish::Answer(id, Err(error)) => self.error(id, error),
                Finish::Store(id, op) => {
                    let outs = self.vault.ledger_end(id, op);
                    self.dispatch(outs)
                }
                Finish::Signed(id, pending, signed) => {
                    let outs = self.vault.ledger_signed(id, *pending, signed);
                    self.dispatch(outs)
                }
                Finish::X402(id, settling, ended) => {
                    let outs = self.vault.x402_ledger_ended(id, *settling, ended);
                    self.dispatch(outs)
                }
                Finish::Safe(id, ended) => {
                    let outs = self.vault.safe_ledger_ended(id, ended);
                    self.dispatch(outs)
                }
            };
            if let Flow::Exit(exit) = flow {
                return Flow::Exit(exit);
            }
        }
        Flow::Continue
    }

    /// `not_moved` for a page request that would write the dApp store
    /// before it moves.
    fn dapp_unmoved(&mut self, id: u64) -> Option<Flow> {
        if self.vault.dapp_moved() {
            return None;
        }
        Some(self.dispatch(vec![crate::eip1193::not_moved(id)]))
    }

    fn hello(&mut self, id: u64, params: Option<&str>) -> Flow {
        let params: Option<HelloParams> = params.and_then(|p| serde_json::from_str(p).ok());
        let Some(params) = params else {
            let _ = self.error(
                id,
                ErrorBody::new(ErrorCode::InvalidArgument, "Invalid core.hello parameters"),
            );
            return Flow::Exit(Exit::Protocol);
        };
        // Protocol 2 only, the streams' version (design 0009, Streams in the
        // core). Protocol 1 is gone: its hello is a mismatch like any other.
        if params.protocol != fc_protocol::PROTOCOL_VERSION_STREAMS {
            let _ = self.error(
                id,
                ErrorBody::new(ErrorCode::ProtocolMismatch, "Protocol mismatch").with_data(
                    serde_json::json!({ "core": fc_protocol::PROTOCOL_VERSION_STREAMS }),
                ),
            );
            return Flow::Exit(Exit::Protocol);
        }
        // Main takes stream frames: its hello says so.
        if !params.frames.iter().any(|kind| kind == "stream") {
            let _ = self.error(
                id,
                ErrorBody::new(
                    ErrorCode::InvalidArgument,
                    "core.hello at protocol 2 offers no stream frames",
                ),
            );
            return Flow::Exit(Exit::Protocol);
        }
        let grants = match grant_files(&params) {
            Ok(grants) => grants,
            Err(message) => {
                let _ = self.error(id, ErrorBody::new(ErrorCode::InvalidArgument, message));
                return Flow::Exit(Exit::Protocol);
            }
        };
        let stores = match stores_moved(&params) {
            Ok(stores) => stores,
            Err(message) => {
                let _ = self.error(id, ErrorBody::new(ErrorCode::InvalidArgument, message));
                return Flow::Exit(Exit::Protocol);
            }
        };
        let user_data_dir = match user_data_dir(&params) {
            Ok(dir) => dir,
            Err(message) => {
                let _ = self.error(id, ErrorBody::new(ErrorCode::InvalidArgument, message));
                return Flow::Exit(Exit::Protocol);
            }
        };
        // The same directories as `serve`'s arguments (design 0017, C1): a
        // mismatch is answered as a malformed `grant_root` is.
        if let Err(message) = hello_matches_args(
            &grants.0,
            user_data_dir.as_deref(),
            &self.grant_root_arg,
            self.user_data_dir_arg.as_deref(),
        ) {
            let _ = self.error(id, ErrorBody::new(ErrorCode::InvalidArgument, message));
            return Flow::Exit(Exit::Protocol);
        }
        if self.hello_done || self.pending_hello.is_some() {
            return self.error(
                id,
                ErrorBody::new(ErrorCode::InvalidArgument, "core.hello was already sent"),
            );
        }
        let root = grants.0.clone();
        self.vault.configure_grants(grants.0, grants.1);
        self.vault
            .configure_safe_pending(root.clone(), stores.contains(&"safe_pending"));
        self.vault
            .configure_intents(root.clone(), stores.contains(&"intents"));
        self.stores_echo = stores
            .into_iter()
            .filter(|name| STORES_SERVED.contains(name))
            .filter(|name| match *name {
                "vault_meta" => self.vault.configure_vault_meta(),
                "rpc_api_keys" => self.vault.configure_rpc_keys(root.clone()),
                "safe_pending" | "intents" => true,
                // Opened at its first request, never before the name. The
                // database under the Freedom root. A moved profile's
                // `x402-receipts.json` was copied there from `userData`
                // before `confine`, and is imported from the copy (design
                // 0017, C5); the old layout imports at its root, and a
                // `serve` without `--user-data-dir` at the Freedom root, as
                // before.
                "payments" => {
                    let import = match (self.handover, user_data_dir.as_deref()) {
                        (Some(handover), Some(dir)) => handover.import(dir, &root),
                        _ => crate::payments_store::Import::at(root.clone()),
                    };
                    self.vault.configure_payments(root.clone(), import);
                    true
                }
                // The swarm thread loads them as it starts, below (design
                // 0015, D3).
                crate::swarm::stores::STORE => true,
                _ => false,
            })
            .collect();
        // The Swarm stores under the Freedom root; the legacy history's
        // import where its hand-over left it (design 0015, D10), as the
        // receipts' is.
        let swarm_stores = self
            .stores_echo
            .contains(&crate::swarm::stores::STORE)
            .then(|| crate::swarm::stores::Place {
                root: root.clone(),
                history_import: match (self.history_handover, user_data_dir.as_deref()) {
                    (Some(handover), Some(dir)) => handover.import(dir, &root),
                    _ => crate::payments_store::Import::at(root.clone()),
                },
            });
        // The dweb thread, and stream frames from now on: before the reply,
        // so nothing main sends after reading it is refused.
        let Some(start) = self.dweb_start.take() else {
            return Flow::Exit(Exit::Internal);
        };
        let swarm_start = {
            let (grants, grants_file) = self.vault.swarm_grants();
            swarm::Spawn {
                out: start.out.clone(),
                events: start.events.clone(),
                requests: Arc::clone(&self.requests),
                link: Arc::clone(&self.link),
                stall: crate::testhooks::stall(STALL),
                naming: self.naming.clone(),
                grants,
                grants_file,
                bindings: self.connects.bindings(),
                stores: swarm_stores,
            }
        };
        match dweb::spawn(start.out, start.events, Arc::clone(&self.requests)) {
            Ok(handle) => self.dweb = Some(handle),
            Err(_) => {
                log::error("cannot start a thread", serde_json::json!({}));
                return Flow::Exit(Exit::Internal);
            }
        }
        // The swarm thread, beside it, once the grants are configured: it
        // reads the Swarm grants through their shared handle (design 0015,
        // D2).
        match swarm::spawn(swarm_start) {
            Ok(handle) => self.swarm = Some(handle),
            Err(_) => {
                log::error("cannot start a thread", serde_json::json!({}));
                return Flow::Exit(Exit::Internal);
            }
        }
        self.link.enable_streams();
        self.vault.set_auto_lock_ms(params.auto_lock_ms);
        spawn_adoption(params.node_roots.map(NodeRoots::valid).unwrap_or_default());
        // Granted with the handshake: main holds the core's credit from now
        // on, and the core main's if main takes fragments.
        if params.frames.iter().any(|kind| kind == "fragment") {
            self.link.offer();
        }
        if !self.snapshot_ready {
            self.pending_hello = Some(id);
            return Flow::Continue;
        }
        self.hello_reply(id)
    }

    fn hello_reply(&mut self, id: u64) -> Flow {
        self.hello_done = true;
        let mut payload = Zeroizing::new(Vec::with_capacity(1024));
        let written = message::write_result(
            &mut *payload,
            id,
            &HelloResult {
                protocol: fc_protocol::PROTOCOL_VERSION_STREAMS,
                core_version: env!("CARGO_PKG_VERSION"),
                capabilities: CAPABILITIES.iter().chain(FEATURES).copied().collect(),
                node_recovery: &self.node_recovery,
                store_moved: &self.stores_echo,
                confinement: &self.confinement,
            },
        );
        let flow = match written {
            Ok(()) => self.send(&payload),
            Err(_) => return Flow::Exit(Exit::Internal),
        };
        // Main runs `shell.keystore` from now on: the records the start
        // left are forgotten (design 0013, "Forgetting an item").
        if self.secrets.start_drain().is_err() {
            log::error("cannot start a thread", serde_json::json!({}));
            return Flow::Exit(Exit::Internal);
        }
        flow
    }

    /// Sends the vault's payloads and submits its jobs.
    fn dispatch(&mut self, outs: Vec<Out>) -> Flow {
        for out in outs {
            let flow = match out {
                Out::Send(payload) => self.send(&payload),
                Out::SendUnder { payload, id, epoch } => self.send_under(&payload, id, epoch),
                Out::Job(id, job) => {
                    if self.worker.submit(id, job) {
                        Flow::Continue
                    } else {
                        Flow::Exit(Exit::Internal)
                    }
                }
                // A page request's name check (APR-5f), and its cancel.
                Out::NameCheck(check) => {
                    if self.naming.send(
                        naming::In::Check {
                            tag: check.tag,
                            binding: check.binding,
                            deadline_ms: check.deadline_ms,
                        },
                        None,
                    ) {
                        Flow::Continue
                    } else {
                        Flow::Exit(Exit::Internal)
                    }
                }
                Out::NameCancel(tag) => {
                    if self.naming.send(naming::In::CancelCheck { tag }, None) {
                        Flow::Continue
                    } else {
                        Flow::Exit(Exit::Internal)
                    }
                }
                // A Ledger key's signature, authorized (design 0016, L4): its
                // operation waits its turn on the device lane.
                Out::Ledger(id, device) => {
                    let crate::signing::Device { operation, pending } = *device;
                    let ended = self.ledger.submit(
                        id,
                        operation,
                        Then::Sign(Box::new(pending)),
                        Turn::Wait,
                        Instant::now(),
                    );
                    self.ledger_ended(ended)
                }
                // A Ledger's x402 payment (design 0016, L5): its signature
                // over the reserved authorization waits its turn on the
                // device lane, the reservation with it.
                Out::X402Ledger(id, payment) => {
                    let crate::approvals::x402::LedgerPayment {
                        operation,
                        settling,
                    } = *payment;
                    let ended = self.ledger.submit(
                        id,
                        operation,
                        Then::X402(Box::new(settling)),
                        Turn::Wait,
                        Instant::now(),
                    );
                    self.ledger_ended(ended)
                }
                // A Safe's Ledger owner (design 0016, S6): its signature over
                // the pending SafeTx or the session's SafeMessage waits its
                // turn on the device lane, the Safe held meanwhile.
                Out::SafeLedger(id, operation) => {
                    let ended =
                        self.ledger
                            .submit(id, *operation, Then::Safe, Turn::Wait, Instant::now());
                    self.ledger_ended(ended)
                }
                // A user's Swarm grant change (design 0015, D17), after the
                // reply and the events that made it: the swarm thread, which
                // holds the manifest store, detaches it. With no thread
                // (protocol 1) the core holds no manifest store.
                Out::SwarmChange(change) => match self.swarm.as_ref() {
                    Some(thread)
                        if !thread.send(
                            swarm::In::GrantChanged {
                                key: change.key,
                                projection: change.projection,
                            },
                            None,
                        ) =>
                    {
                        Flow::Exit(Exit::Internal)
                    }
                    _ => Flow::Continue,
                },
                Out::ChainRead(read) => {
                    if self.chain.send(
                        chain::In::Internal {
                            tag: read.tag,
                            chain_id: read.chain_id,
                            method: read.method,
                            params: read.params,
                            deadline_ms: read.deadline_ms,
                        },
                        None,
                    ) {
                        Flow::Continue
                    } else {
                        Flow::Exit(Exit::Internal)
                    }
                }
            };
            if let Flow::Exit(exit) = flow {
                return Flow::Exit(exit);
            }
        }
        Flow::Continue
    }

    fn result<R: Serialize>(&mut self, id: u64, result: &R) -> Flow {
        let mut payload = Zeroizing::new(Vec::with_capacity(256));
        match message::write_result(&mut *payload, id, result) {
            Ok(()) => self.send(&payload),
            Err(_) => Flow::Exit(Exit::Internal),
        }
    }

    fn error(&mut self, id: u64, error: ErrorBody) -> Flow {
        let mut payload = Zeroizing::new(Vec::with_capacity(256));
        match message::write_error(&mut *payload, id, &error) {
            Ok(()) => self.send(&payload),
            Err(_) => Flow::Exit(Exit::Internal),
        }
    }

    /// Queues a reply or an event: one frame, as every vault reply fits
    /// one. Past the loop's allowance it waits in the outbox, and requests
    /// wait with it.
    fn send(&mut self, payload: &[u8]) -> Flow {
        let Some(frame) = transport::frame(payload) else {
            return Flow::Exit(Exit::Internal);
        };
        self.outbox.send(frame, Instant::now(), self.vault.epoch())
    }

    /// Queues the reply to request `id`, valid only under the vault's
    /// `epoch` (design 0008, "The sealed release": the epoch is checked at
    /// the handoff to the writer). If that epoch has ended by the time it
    /// would go, it goes as `vault_locked` instead, in its place.
    fn send_under(&mut self, payload: &[u8], id: u64, epoch: u64) -> Flow {
        let Some(frame) = transport::frame(payload) else {
            return Flow::Exit(Exit::Internal);
        };
        let waiting = Waiting {
            frame,
            under: Some(Under { id, epoch }),
        };
        if crate::testhooks::hold_reply(id) {
            return self.outbox.hold(waiting, Instant::now());
        }
        self.outbox
            .push(waiting, Instant::now(), self.vault.epoch())
    }
}

/// A frame waiting for the writer.
struct Waiting {
    frame: Zeroizing<Vec<u8>>,
    under: Option<Under>,
}

/// The epoch a reply is valid under: the sealed release's (design 0008).
#[derive(Clone, Copy)]
struct Under {
    id: u64,
    epoch: u64,
}

impl Waiting {
    /// What goes to the writer now, under the vault's epoch `now`: the
    /// frame, or, for a reply whose epoch has ended (a lock, manual or
    /// automatic, since its admission), `vault_locked` in its place. The
    /// replaced frame is wiped. `None` if the error can't be framed.
    fn current(self, now: Option<u64>) -> Option<Zeroizing<Vec<u8>>> {
        match self.under {
            Some(under) if now != Some(under.epoch) => {
                drop(self.frame);
                let mut payload = Zeroizing::new(Vec::with_capacity(128));
                message::write_error(&mut *payload, under.id, &crate::vault::locked()).ok()?;
                transport::frame(&payload)
            }
            _ => Some(self.frame),
        }
    }
}

/// The loop's share of the writer (0001's reserved capacity, which naming
/// and chain traffic can't take), and its frames waiting past it, in the
/// order they were made. It never blocks, and never buffers past the work
/// the loop has taken (see the module documentation).
struct Outbox {
    out: Sender<transport::Out>,
    allowance: Arc<Allowance>,
    waiting: VecDeque<Waiting>,
    /// The writer's progress while frames wait, against [`STALL`] or a
    /// test's bound.
    watchdog: Watchdog,
}

impl Outbox {
    fn new(
        out: Sender<transport::Out>,
        allowance: Arc<Allowance>,
        link: Arc<Link>,
        stall: Duration,
    ) -> Self {
        Outbox {
            out,
            allowance,
            waiting: VecDeque::new(),
            watchdog: Watchdog::new(link, stall),
        }
    }

    /// Queues `frame` behind the frames that wait, and hands the writer
    /// what fits. `epoch` is the vault's now.
    fn send(&mut self, frame: Zeroizing<Vec<u8>>, now: Instant, epoch: Option<u64>) -> Flow {
        self.push(Waiting { frame, under: None }, now, epoch)
    }

    fn push(&mut self, waiting: Waiting, now: Instant, epoch: Option<u64>) -> Flow {
        self.waiting.push_back(waiting);
        self.pump(now, epoch)
    }

    /// A test's: queues `waiting` without handing anything over, as if the
    /// allowance had no room.
    fn hold(&mut self, waiting: Waiting, now: Instant) -> Flow {
        self.waiting.push_back(waiting);
        self.watchdog.waiting(true, now);
        Flow::Continue
    }

    /// Hands waiting frames to the writer, in order, while the allowance
    /// has room. A refusal arms the allowance's wake-up ([`Event::Room`]).
    /// Each frame is judged at its handoff, under the vault's epoch now
    /// (`epoch`): a reply valid only under an epoch that has ended goes as
    /// `vault_locked` ([`Waiting::current`]).
    fn pump(&mut self, now: Instant, epoch: Option<u64>) -> Flow {
        while let Some(front) = self.waiting.front_mut() {
            if front.under.is_some_and(|under| epoch != Some(under.epoch)) {
                let stale = std::mem::replace(
                    front,
                    Waiting {
                        frame: Zeroizing::new(Vec::new()),
                        under: None,
                    },
                );
                let Some(frame) = stale.current(epoch) else {
                    return Flow::Exit(Exit::Internal);
                };
                front.frame = frame;
            }
            let Some(hold) = self.allowance.take(front.frame.len()) else {
                break;
            };
            let Some(waiting) = self.waiting.pop_front() else {
                break;
            };
            if self
                .out
                .send(transport::Out::Frame {
                    frame: waiting.frame,
                    hold,
                })
                .is_err()
            {
                return Flow::Exit(Exit::Protocol);
            }
        }
        self.watchdog.waiting(!self.waiting.is_empty(), now);
        Flow::Continue
    }

    /// Whether frames wait for room.
    fn is_waiting(&self) -> bool {
        !self.waiting.is_empty()
    }

    /// When the stall bound passes unless the writer moves: the loop wakes
    /// then to look.
    fn deadline(&self) -> Option<Instant> {
        self.watchdog.deadline()
    }

    /// Ends the core once frames have waited for the stall bound with the
    /// writer writing nothing: main has stopped reading.
    fn check(&self, now: Instant) -> Flow {
        match self.watchdog.stalled(now) {
            Some(waited) => Flow::Exit(not_reading(waited, "loop")),
            None => Flow::Continue,
        }
    }

    /// Hands every waiting frame to the writer, past the allowance: on
    /// exit, where the writer's drain is bounded by time instead. Each is
    /// judged under the vault's epoch then, as [`Outbox::pump`] judges it.
    fn drain(&mut self, epoch: Option<u64>) {
        for waiting in self.waiting.drain(..) {
            let Some(frame) = waiting.current(epoch) else {
                continue;
            };
            let hold = self.allowance.force(frame.len());
            let _ = self.out.send(transport::Out::Frame { frame, hold });
        }
        self.watchdog.waiting(false, Instant::now());
    }
}

/// The core's end once `producer`'s frames waited `waited`, the stall
/// bound or more, with the writer writing nothing: main has stopped
/// reading.
fn not_reading(waited: Duration, producer: &'static str) -> Exit {
    log::error(
        "main is not reading replies",
        serde_json::json!({
            "ms": u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
            "frames": producer,
        }),
    );
    Exit::Protocol
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::mpsc::Receiver;

    /// An outbox with room for `frames` frames in the writer, the writer's
    /// end of its queue, the link whose count the writer moves, and how
    /// often freed room woke the loop.
    fn outbox(
        frames: usize,
    ) -> (
        Outbox,
        Receiver<transport::Out>,
        Arc<Link>,
        Arc<Mutex<usize>>,
    ) {
        let (out, queue) = mpsc::channel();
        let allowance = Allowance::new(frames, usize::MAX);
        let woken = Arc::new(Mutex::new(0));
        let count = Arc::clone(&woken);
        allowance.on_room(move || *count.lock().unwrap() += 1);
        let link = Link::new();
        let outbox = Outbox::new(out, allowance, Arc::clone(&link), STALL);
        (outbox, queue, link, woken)
    }

    fn reply(id: u64) -> Zeroizing<Vec<u8>> {
        let json = format!(r#"{{"type":"response","id":{id},"result":{{}}}}"#);
        transport::frame(json.as_bytes()).unwrap()
    }

    /// The writer writes the next frame queued `at` then, which frees its
    /// place: the ID of the response it was.
    fn write_one(queue: &Receiver<transport::Out>, link: &Link, at: Instant) -> u64 {
        let Ok(transport::Out::Frame { frame, hold }) = queue.try_recv() else {
            panic!("nothing for the writer");
        };
        link.wrote(at);
        drop(hold);
        let message: serde_json::Value = serde_json::from_slice(&frame[5..]).unwrap();
        message["id"].as_u64().unwrap()
    }

    #[test]
    fn frames_past_the_allowance_wait_in_order_and_go_as_room_frees() {
        let (mut outbox, queue, link, woken) = outbox(2);
        let now = Instant::now();
        for id in 1..=5 {
            assert!(matches!(outbox.send(reply(id), now, None), Flow::Continue));
        }
        // Two went to the writer; three wait here.
        assert_eq!(outbox.waiting.len(), 3);
        // Each frame written wakes the loop, which sends the next, in order.
        let mut written = Vec::new();
        while outbox.is_waiting() || written.len() < 5 {
            written.push(write_one(&queue, &link, now));
            assert!(matches!(outbox.pump(now, None), Flow::Continue));
        }
        assert_eq!(written, [1, 2, 3, 4, 5]);
        assert_eq!(*woken.lock().unwrap(), 3);
        // Nothing waits: no stall clock runs, however long.
        assert_eq!(outbox.deadline(), None);
        assert!(matches!(outbox.check(now + 10 * STALL), Flow::Continue));
    }

    #[test]
    fn a_stall_exits_only_after_the_bound_without_writer_progress() {
        // The clock is injected: the bound passes without a 30 s wait.
        let (mut outbox, queue, link, _) = outbox(1);
        let start = Instant::now();
        for id in 1..=3 {
            assert!(matches!(
                outbox.send(reply(id), start, None),
                Flow::Continue
            ));
        }
        assert_eq!(outbox.deadline(), Some(start + STALL));
        let short = STALL - Duration::from_millis(1);
        assert!(matches!(outbox.check(start + short), Flow::Continue));
        // Main reads one of the loop's frames 20 s in: room wakes the loop,
        // the next frame goes, and the bound counts from that write.
        let read = start + Duration::from_secs(20);
        assert_eq!(write_one(&queue, &link, read), 1);
        assert!(matches!(outbox.pump(read, None), Flow::Continue));
        assert!(outbox.is_waiting());
        assert_eq!(outbox.deadline(), Some(read + STALL));
        // Then it reads only other producers' frames (naming's, chain's),
        // which wake nothing here: the writer still moved, and the bound
        // counts from there too.
        let other = read + Duration::from_secs(25);
        link.wrote(other);
        assert_eq!(outbox.deadline(), Some(other + STALL));
        assert!(matches!(outbox.check(other + short), Flow::Continue));
        // Then nothing for the whole bound: main has stopped reading, and
        // the core exits 76.
        let Flow::Exit(exit) = outbox.check(other + STALL) else {
            panic!("no exit once the bound passed");
        };
        assert_eq!(exit, Exit::Protocol);
        assert_eq!(exit.code(), 76);
    }

    /// The next frame queued for the writer, whole, after the writer wrote
    /// it.
    fn take_one(queue: &Receiver<transport::Out>, link: &Link, at: Instant) -> serde_json::Value {
        let Ok(transport::Out::Frame { frame, hold }) = queue.try_recv() else {
            panic!("nothing for the writer");
        };
        link.wrote(at);
        drop(hold);
        serde_json::from_slice(&frame[5..]).unwrap()
    }

    fn sealed(id: u64, epoch: u64) -> Waiting {
        Waiting {
            frame: reply(id),
            under: Some(Under { id, epoch }),
        }
    }

    /// Design 0008, "The sealed release": a reply valid only under an epoch
    /// is judged when it is handed to the writer, not when it was made. In
    /// its place in the queue, it goes as it is under that epoch, and as
    /// `vault_locked` once a lock ended it, a later unlock included; the
    /// frames around it are untouched (review of #175).
    #[test]
    fn a_reply_under_an_epoch_is_judged_at_its_handoff() {
        let now = Instant::now();
        for (at_handoff, sealed_goes) in [(Some(7), true), (None, false), (Some(8), false)] {
            // Room for one frame: 1 goes, the seal (2) and 3 wait.
            let (mut outbox, queue, link, _) = outbox(1);
            assert!(matches!(
                outbox.send(reply(1), now, Some(7)),
                Flow::Continue
            ));
            assert!(matches!(
                outbox.push(sealed(2, 7), now, Some(7)),
                Flow::Continue
            ));
            assert!(matches!(
                outbox.send(reply(3), now, Some(7)),
                Flow::Continue
            ));
            assert_eq!(outbox.waiting.len(), 2);
            // The epoch the handoffs happen under: unchanged, locked, or a
            // new one after an unlock.
            let mut written = vec![take_one(&queue, &link, now)];
            while written.len() < 3 {
                assert!(matches!(outbox.pump(now, at_handoff), Flow::Continue));
                written.push(take_one(&queue, &link, now));
            }
            let ids: Vec<u64> = written.iter().map(|m| m["id"].as_u64().unwrap()).collect();
            assert_eq!(ids, [1, 2, 3], "{at_handoff:?}");
            if sealed_goes {
                assert_eq!(
                    written[1]["result"],
                    serde_json::json!({}),
                    "{at_handoff:?}"
                );
            } else {
                assert_eq!(
                    written[1]["error"]["code"], "vault_locked",
                    "{at_handoff:?}"
                );
                assert!(written[1].get("result").is_none());
            }
            assert_eq!(written[2]["result"], serde_json::json!({}));
        }
    }

    /// On exit, what waits is judged the same way before it goes.
    #[test]
    fn exiting_judges_a_waiting_reply_under_its_epoch() {
        // Room for one, taken: the seal waits.
        let (mut outbox, queue, link, _) = outbox(1);
        let now = Instant::now();
        assert!(matches!(
            outbox.send(reply(1), now, Some(7)),
            Flow::Continue
        ));
        assert!(matches!(
            outbox.push(sealed(2, 7), now, Some(7)),
            Flow::Continue
        ));
        assert!(outbox.is_waiting());
        outbox.drain(None);
        assert_eq!(take_one(&queue, &link, now)["id"], 1);
        let message = take_one(&queue, &link, now);
        assert_eq!(message["id"], 2);
        assert_eq!(message["error"]["code"], "vault_locked");
    }

    #[test]
    fn exiting_hands_the_writer_what_waits() {
        let (mut outbox, queue, _link, _) = outbox(1);
        let now = Instant::now();
        for id in 1..=3 {
            assert!(matches!(outbox.send(reply(id), now, None), Flow::Continue));
        }
        outbox.drain(None);
        assert!(!outbox.is_waiting());
        assert_eq!(outbox.deadline(), None);
        let ids: Vec<u64> = std::iter::from_fn(|| match queue.try_recv() {
            Ok(transport::Out::Frame { frame, .. }) => {
                let message: serde_json::Value = serde_json::from_slice(&frame[5..]).unwrap();
                message["id"].as_u64()
            }
            _ => None,
        })
        .collect();
        assert_eq!(ids, [1, 2, 3]);
    }

    /// #101: every method served is a row of fc-protocol's method table,
    /// and every row is served: the capabilities, then the chain methods.
    #[test]
    fn every_method_has_a_row_and_every_row_a_handler() {
        let rows: Vec<&str> = methods::METHODS.iter().map(|m| m.name).collect();
        let served: Vec<&str> = CAPABILITIES.iter().chain(chain::METHODS).copied().collect();
        assert_eq!(rows, served);
        for name in rows {
            assert!(
                matches!(name, "core.hello" | "core.shutdown")
                    || Vault::handles(name)
                    || naming::handles(name)
                    || chain::handles(name)
                    || dweb::handles(name)
                    || swarm::handles(name)
                    || ledger::handles(name)
                    || name == "eip1193.request",
                "{name}"
            );
            assert_eq!(loggable(name), name);
        }
        assert_eq!(loggable("keys.root_key"), "<unknown>");
    }

    #[test]
    fn only_requests_wait_and_shutdown_and_lock_are_seen_ahead() {
        let ahead = |message: serde_json::Value| {
            Ahead::of(&Frame {
                kind: KIND_JSON,
                payload: Zeroizing::new(message.to_string().into_bytes()),
            })
        };
        let request = |id: u64, method: &str, caller: &str| {
            serde_json::json!({
                "type": "request", "id": id, "method": method, "context": { "caller": caller },
            })
        };
        assert!(matches!(
            ahead(request(7, "core.shutdown", "shell")),
            Ahead::Shutdown
        ));
        // #101: main's own; from the browser UI it waits, to be refused.
        assert!(matches!(
            ahead(request(7, "core.shutdown", "chrome")),
            Ahead::Request(7)
        ));
        assert!(matches!(
            ahead(request(7, "vault.lock", "chrome")),
            Ahead::Lock(7)
        ));
        assert!(matches!(
            ahead(request(7, "vault.status", "chrome")),
            Ahead::Request(7)
        ));
        // Web content can't lock or shut down: refused in its turn.
        let page = serde_json::json!({
            "type": "request", "id": 8, "method": "vault.lock",
            "context": { "caller": "page", "page": {
                "origin": "https://a.example", "top_origin": "https://a.example",
                "frame": 1, "navigation": 1,
            } },
        });
        assert!(matches!(ahead(page), Ahead::Request(8)));
        assert!(matches!(
            ahead(serde_json::json!({ "type": "cancel", "id": 9 })),
            Ahead::Cancel(9)
        ));
        // Handled at once: a response, an event, a malformed message.
        assert!(matches!(
            ahead(serde_json::json!({ "type": "response", "id": 9, "result": {} })),
            Ahead::Other
        ));
        assert!(matches!(
            ahead(serde_json::json!({ "type": "event", "event": "x" })),
            Ahead::Other
        ));
        assert!(matches!(ahead(serde_json::json!([1])), Ahead::Other));
    }
}
