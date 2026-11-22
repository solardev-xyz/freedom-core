//! Fault injection for the integration tests. **Only with the `testhooks`
//! feature,** which build.rs refuses outside debug and test builds: without
//! it every hook is a no-op and no variable is read.
//!
//! - `FREEDOM_CORED_TEST_SNAPSHOT_DELAY_MS` stalls the startup snapshot read.
//! - `FREEDOM_CORED_TEST_JOB_DELAY_MS` stalls each vault job before it does
//!   anything (so before its commit point).
//! - `FREEDOM_CORED_TEST_KDF_DEADLINE_MS` replaces the 30 s KDF deadline.
//! - `FREEDOM_CORED_TEST_STALL_MS` replaces the 30 s the vault loop's
//!   replies may wait on a writer that writes nothing before the core
//!   exits.
//! - `FREEDOM_CORED_TEST_COMMIT_DELAY_MS` stalls a job right after it claims
//!   its commit point, before the rename or unlink.
//! - `FREEDOM_CORED_TEST_COMMIT_MARKER` names a file created the moment a job
//!   claims its commit point (before that stall), so tests can wait for it.
//! - `FREEDOM_CORED_TEST_COMMIT_HOLD` names a file: after that stall, a job
//!   waits until the file exists or the core begins to exit (at most 120 s).
//!   So a test holds a committed job as long as it needs, or until the
//!   exit drain, without racing the core's clock.
//! - `FREEDOM_CORED_TEST_REFUSED_CLAIM_HOLD` names a file: a job whose claim
//!   was refused waits, before it cleans up, until that file exists (at
//!   most 120 s). It stands for a slow disk under that cleanup, held for as
//!   long as the test needs.
//! - `FREEDOM_CORED_TEST_CHAIN_TOTAL_BYTES` replaces the chain total's
//!   256 MiB (design 0005, Bounds), so a test can bring it near full.
//! - `FREEDOM_CORED_TEST_DWEB_GRANTS_BYTES` replaces the dweb thread's
//!   101 MiB of grants, `FREEDOM_CORED_TEST_DWEB_STREAMS` its 128
//!   streamed pieces, and `FREEDOM_CORED_TEST_DWEB_RUNNING` its 64 running
//!   requests (design 0009, Bounds). The grants alone keep the running
//!   requests below the 64 admission allows, their streams below 128 and
//!   their pieces below main's 256, so a test that pins one of those
//!   bounds lifts the ones in front of it. 64 bodies' windows are the
//!   writer's 8 MiB, so a test that presses on that cap runs more.
//! - `FREEDOM_CORED_TEST_DWEB_WRITER_MARKER` names a file the dweb thread
//!   rewrites with the most verified-body bytes its writer has held queued
//!   at once (the duplex sender's `held`, capped at 0009's 8 MiB), each
//!   time that grows, so a test can read the high-water mark.
//! - `FREEDOM_CORED_TEST_NAMING_MARKER` names a file the naming thread
//!   appends a line to for each reply it makes (`reply`), and at its end
//!   for the waiting frames it hands to the writer (`drain <count>`), so
//!   tests can wait for both while main isn't reading.
//! - `FREEDOM_CORED_TEST_SWAP` (`<stage>=<path>`) renames the file at
//!   `<path>` over the file the core is about to use at `<stage>`, once (the
//!   rename consumes it): `journal` right after recovery read the journal,
//!   `checked` right after a staged or temp file was checked and before its
//!   identity is compared, `renaming` right before a staged node file, or a
//!   staged vault or metadata file, is renamed. It stands for a same-user process winning a race.
//! - `FREEDOM_CORED_TEST_GRANT_WRITE_FAIL` names a file: while it holds
//!   `<store>:<step>` lines (`dapp`, `swarm`, `radicle`, `x402`, `phone`
//!   for `phone-payments.json`, `vault_meta` for `vault-meta.json`,
//!   `safe_pending` for `safe-pending.json`, and `receipts` for the copy
//!   of a moved profile's `x402-receipts.json` into the Freedom root,
//!   whose `flush` also fails the Freedom root's sync before the original
//!   is dropped (design 0017, C5); `write`, `fsync`, `rename`,
//!   `flush`), each write of that store's permission
//!   file fails at that step as if the OS had failed it (design 0012, "The
//!   files": a failed write). Read at each write, so a test turns it on
//!   and off while the core runs. `intents` fails `wallet-intents.jsonl`'s
//!   journal steps: an append's `write` (half the line written), `fsync`,
//!   `truncate` (its cut back) and `flush`, a compaction's `write`,
//!   `fsync`, `rename` and `flush`, and the open's `flush`.
//!   `vault_meta_journal:<step>` fails a step
//!   after the commit of the vault and metadata journal (design 0013, "The
//!   vault and its metadata, one write"), in the write and in recovery
//!   alike: `vault-rename`, `vault-flush`, `meta-rename`, `meta-flush`,
//!   `unlink` (each a returned failure, the journal kept), `finish-flush`
//!   (after the real unlink: not durable), and `journal-flush`: the
//!   directory flush after the journal's own rename, and its retry, and
//!   recovery's flush before it installs (nothing installed, the journal
//!   kept). `delete_journal:install` fails a vault delete's install, in the
//!   delete and in its recovery alike, as `delete-install` below does once.
//!   `delete_journal:journal-flush` fails the directory flush after a vault
//!   delete's journal rename, its retry, and recovery's flush before it
//!   installs (nothing installed, the journal kept).
//!   `vault_meta_journal:settle-once` fails the first recovery of the
//!   journal in the process that reads the line, before it renames
//!   anything (the journal kept), and none after it: a transient failure,
//!   which a test arms once the core is serving.
//! - `FREEDOM_CORED_TEST_INTENT_IDS` names a file: while it holds lines,
//!   each id the intent store names (an original's, a handoff's; the
//!   reference's `crypto.randomUUID()`) is its first line, which is
//!   removed, so a test replays the vectors' ids.
//! - `FREEDOM_CORED_TEST_INTENT_LIMITS` names a file holding a JSON object
//!   of the intent store's `LIMITS` in the reference's names
//!   (`heldPerAccount`, `held`, `hashesPerIntent`, `openHandoffsPerIntent`,
//!   `tombstones`, `rawBytes`, `journalBytes`, `readBytes`): those replace
//!   the store's at each load, as the reference's `createIntentStore({
//!   limits })` does.
//! - `FREEDOM_CORED_TEST_X402_SIGN_MARKER` names a file `x402.authorize`
//!   appends a line to (`sign`) each time it is about to sign a payment's
//!   digest, so a test counts the signatures: none for a cap's charge the
//!   file lacks (design 0012, `x402-at-sign`).
//! - `FREEDOM_CORED_TEST_KEYSTORE_DEADLINE_MS` replaces how long the core
//!   waits for main's answer to a `shell.keystore` request (design 0013:
//!   main's 60 s or 10 s, and 5 s more).
//! - `FREEDOM_CORED_TEST_KEYSTORE_EXIT_AFTER_STORE` set: the key-store
//!   helper exits after the OS stored a `create`'s item and before it
//!   answers, as one killed there would (design 0013, "The failure
//!   contract").
//! - `FREEDOM_CORED_TEST_KEYSTORE_SPAWN_PROBE` set: the key-store helper,
//!   once it has refused child processes and checked the request, tries to
//!   start `/usr/bin/true` instead of calling the OS, and answers
//!   `backend` with `reason` `spawned` or `no_spawn`.
//! - `FREEDOM_CORED_TEST_KEYSTORE_BACKEND=macos-keychain`: the core's key
//!   store offers the macOS Keychain's `Unattended` on any OS, as macOS
//!   does, so a test playing main answers its `shell.keystore` requests
//!   from a keychain of its own (design 0013, PRF-1c's forgetting tests).
//!   The helper is unchanged: it still has no backend off macOS. `=none`:
//!   the key store offers nothing, on any OS (macOS's own Keychain
//!   included), as on Linux and Windows until PRF-7.
//! - `FREEDOM_CORED_TEST_SECRETS_CRASH` names a step of a secrets-file
//!   change (`before-pending`, `after-pending`, `before-commit`,
//!   `after-commit`, `before-remove`, `after-remove`, `before-forgotten`,
//!   `after-forgotten`, and `before-startup`, `after-startup` for the start's
//!   settling write), or of a journaled vault delete (`before-delete-stage`,
//!   `before-delete-journal`, `before-delete-journal-rename` (its temp file
//!   written, the claim taken), `after-delete-journal`, `after-delete-secrets`,
//!   `after-delete-vault`, `after-delete-done`), or of a re-wrap (design
//!   0013, "The re-wrap": `before-stage-pending`, `after-stage-pending`,
//!   `before-stage`, `after-stage` for the writes of the new vault's
//!   credential; `before-vault-rename` (the vault's temp file written and
//!   checked, the claim taken), `after-vault-rename`; `before-fold`,
//!   `after-fold` after the commit; `before-rollback`, `after-rollback`
//!   after a failure), or of the vault and metadata journal
//!   (`before-meta-stage`, `before-meta-journal`,
//!   `before-meta-journal-rename` (its temp file written, the claim taken),
//!   `after-meta-journal`, `after-meta-install-vault`,
//!   `after-meta-install-meta`, `after-meta-done`, and `before-journal-finish`,
//!   `after-journal-finish` for recovery's secrets-file write): there the
//!   core exits at once with 99, as if killed,
//!   the files as that step left them (design 0013, PRF-1: "a crash hook
//!   before and after each write"). The vault's two steps are those of
//!   every vault write.
//! - `FREEDOM_CORED_TEST_STEP_HOLD` names a file: at a step of
//!   `FREEDOM_CORED_TEST_SECRETS_CRASH`'s list whose name the file holds,
//!   the job writes `<file>.held` and waits until `<file>.release` exists
//!   or the core begins to exit (at most 120 s), the files as that step
//!   left them. Read at each step, so a test moves it while the core runs,
//!   and holds a vault and metadata install at each of its steps while it
//!   sends the loop other requests (G20).
//! - `FREEDOM_CORED_TEST_SECRETS_FAIL` lists, comma-separated, writes that
//!   fail: a journaled vault delete's (`delete-stage`, the staged secrets
//!   file; `delete-journal`, the journal's rename, after the commit claim;
//!   `delete-journal-flush`, the directory flush after that rename, which
//!   is then tried once more; `delete-install`, the staged file's rename
//!   over the secrets file, after the commit), any secrets-file write by its step (`pending`,
//!   `commit`, `remove`, `stage-pending`, `stage`, `fold`, `rollback`, …:
//!   before its rename), or a vault write's (`vault-claim`, its claim
//!   refused as if past its time; `vault-rename`, its rename, after the
//!   claim), the vault and metadata journal's (`meta-stage`, a staged
//!   file's write; `meta-journal`, the journal's rename, after the claim;
//!   `meta-journal-flush`, the directory flush after that rename, which is
//!   then tried once more),
//!   or the directory flush after a secrets-file write's rename
//!   (`<step>-flush`, `rpc-set-flush`, `rpc-file-flush`, …: the change in
//!   place and reported not durable). The first attempt in the process of
//!   each listed write fails as if the OS had failed it.
//! - `FREEDOM_CORED_TEST_RECEIPT_TTL_MS` replaces a device send's receipt's
//!   10-minute life (design 0012, "A device send's rule"), so a test sees
//!   one expire over the wire, which has no clock to inject. Read once, as
//!   the core starts.
//! - `FREEDOM_CORED_TEST_EIP1193_DEQUEUE_DELAY_MS` stalls the chain thread
//!   as it takes a page's EIP-1193 read, as if the read waited behind other
//!   chain mail; `FREEDOM_CORED_TEST_EIP1193_OVERALL_MS` replaces the
//!   read's 120 s in all.
//! - `FREEDOM_CORED_TEST_EIP1193_CHECK_EARLY_MS` takes that many
//!   milliseconds off a page request's name check's lookup deadline (APR-5f),
//!   so that the lookup's timeout reaches the event loop while the
//!   request's own clock still shows time left, as the naming thread's
//!   clock and the event loop's, each counting milliseconds from its own
//!   start, can order them by a millisecond.
//! - `FREEDOM_CORED_TEST_EIP1193_READ_EARLY_MS` does the same for a page
//!   send's chain reads that have all the request's time left (APR-5e-1:
//!   its estimate and its quote, and fee evidence when less than its own
//!   15 s is left), as the chain thread's clock can read the request's
//!   deadline first.
//! - `FREEDOM_CORED_TEST_METHODS` enables the `test.*` methods
//!   (`testmethods`), which make responses of any size. Builds without the
//!   feature don't compile them, nor this hook.
//! - `FREEDOM_CORED_TEST_MAINS_WORD` set: a page's `approval.issue`, and
//!   its `approval.grant` in the dApp store, are admitted again on main's
//!   word, as before APR-7 (design 0012), so the tests of what a page's
//!   token or grant then allows (`sign.*`, `approval.spend`, `phone.job`, a
//!   Safe approval, the dApp file's writes) can make one directly. Without
//!   it, as in every build without the feature, both are refused
//!   (`forbidden`), and the core mints a page kind and writes a dApp grant
//!   only on an approve answer to its own prompt, which `eip1193.request`'s
//!   tests drive.
//! - `FREEDOM_CORED_TEST_HOLD_REPLY` names a request ID: its reply, if it
//!   is one valid only under the vault's epoch (`nodes.seal_radicle_key`),
//!   waits in the loop's outbox as if the writer had no room, until the
//!   loop's next frame or room moves it.
//! - `FREEDOM_CORED_TEST_APPROVAL_CLOCK` names a file: while it holds a
//!   number, the approvals read it as the vault's clock, in milliseconds
//!   (token lives, the fee evidence's age, R-6's and Q9's buckets), in
//!   place of the clock's own reading; the vault's auto-lock and throttle
//!   keep the clock's. Read at each request, so a test moves the time while
//!   the core runs, to the millisecond. A missing file, or one that holds
//!   no number, leaves the clock's reading.
//! - `FREEDOM_CORED_TEST_WALL_CLOCK` names a file: while it holds a
//!   number, the approvals read it as the wall clock, in milliseconds (a
//!   phone payment's `answeredAt` and its 24 hours, Q9's `grantedAt`, the
//!   fee evidence's header), as `FREEDOM_CORED_TEST_APPROVAL_CLOCK` does
//!   the vault's.
//! - `FREEDOM_CORED_TEST_PHONE_RECHECK_MS` replaces a phone payment's
//!   first recheck, 5 s after its answer or a start (design 0012,
//!   "Unverified payments"); later ones still double, up to 10 minutes.
//! - `FREEDOM_CORED_TEST_PROFILE_HOLD` (`<marker>=<release>`): a profile
//!   subcommand that holds the catalog's write lock (or `migrate`, the
//!   profile lock) creates the file `<marker>` once it has the lock, then
//!   waits, before it changes anything, until the file `<release>` exists
//!   (at most 120 s). So a test holds the lock as long as it needs.
//!   The directories holding both files are added to the subcommand's
//!   read-write grant (`profile/confine.rs`), so the hook works confined;
//!   nothing else is.
//! - `FREEDOM_CORED_TEST_PROFILE_DELETE_CRASH` names a step of `profile
//!   delete` (`before-keep`, confined, before its lock is kept;
//!   `before-record`, `after-record`, `after-catalog`, `mid-removal`,
//!   `before-result`): there the process exits at once with
//!   99, as if killed, its locks and files left as they are.
//! - `FREEDOM_CORED_TEST_PROFILE_DELETE_PAUSE` (`<step>=<marker>=<release>`):
//!   at that step `profile delete` creates the file `<marker>`, then waits,
//!   its locks and gates held, until the file `<release>` exists (at most
//!   120 s). So a test acts between two steps. Like
//!   `FREEDOM_CORED_TEST_PROFILE_HOLD`'s, its files' directories are in the
//!   delete's grant.
//! - `FREEDOM_CORED_TEST_PROFILE_MIGRATE_CRASH` names a step of `profile
//!   migrate`: `before-keep` (confined, before its lock is kept), its
//!   recovery's (`after-exclusion`, `mid-recovery`,
//!   `before-journal-removed`), and a starting move's (`after-exclusion`,
//!   `after-freedom-dir`, `after-journal`, `mid-move` after each entry's
//!   rename or copy, `after-renames`, `after-marker`, `after-placeholder`,
//!   `before-journal-removed`), with a copied entry's (PRF-9c):
//!   `before-copy` once the journal names it in `copied`, `mid-copy` after
//!   each entry its copy makes in `<name>.moving`, `after-copy` once that
//!   is renamed to its name, and after the marker `mid-cleanup` after each
//!   entry of its source removed and `after-cleanup`; and on Windows after
//!   a refused try of a rename (`rename-retry`) or a rollback's rename back
//!   (`rename-back-retry`). There the process exits at once with 99.
//! - `FREEDOM_CORED_TEST_PROFILE_MIGRATE_PAUSE` (`<step>=<marker>=<release>`):
//!   at that step (one of the crash hook's) `profile migrate` creates the
//!   file `<marker>`, then waits, its locks and gates held and its lock
//!   refreshed, until the file `<release>` exists (at most 120 s). Like
//!   `FREEDOM_CORED_TEST_PROFILE_HOLD`'s, its files' directories are in the
//!   run's grant.
//! - `FREEDOM_CORED_TEST_PROFILE_MIGRATE_EXDEV` lists entries of the move,
//!   comma-separated (`*` for all): a starting move treats each as on
//!   another device than `freedom/`, as when `freedom/` is a volume of its
//!   own. Its preconditions survey it for a copy, and its rename fails with
//!   `CrossesDevices` without being tried, so it is copied (PRF-9c) on one
//!   file system.
//! - `FREEDOM_CORED_TEST_PROFILE_MIGRATE_FREE` names a file: while it holds
//!   a number, that many bytes are what the move reads as free on
//!   `freedom/`'s volume, in the preconditions and at each copy. Read at
//!   each check, so a test changes it while a run is paused; its directory
//!   is in the run's grant.
//! - `FREEDOM_CORED_TEST_PROFILE_MIGRATE_ENOSPC` (a number `n`): a copy
//!   fails as on a full volume (`StorageFull`) once it has made `n`
//!   entries in `<name>.moving`.
//! - `FREEDOM_CORED_TEST_PROFILE_MIGRATE_LOOKUP` (Linux): `walk` makes a
//!   starting move's node-lock lookups take the walk, as where `openat2` is
//!   missing (before 5.6) or refused, and a Myotis generation's mount
//!   unprovable by `openat2`; `walk-no-mount-id` also hides the mount IDs
//!   the walk and a generation's check read (`STATX_MNT_ID`), as before
//!   Linux 5.8, so only devices are compared.
//! - `FREEDOM_CORED_TEST_PROFILE_CONFINED` lists paths (the OS's path-list
//!   separator): right after a profile subcommand confines itself, it reads
//!   each (a file's bytes, a directory's entries) and logs one line on
//!   stderr, `test: confined`, with its confinement report and, for each
//!   path, whether the read worked. So a test sees what the confined
//!   process can and can't read.
//! - `FREEDOM_CORED_TEST_CORE_CONFINED` does the same for `serve`,
//!   `hold-lock` and `recover` (design 0017), right after each confines
//!   itself, before its logging thread starts.
//! - **The hooks' files, confined** (design 0017): `serve`, `hold-lock` and
//!   `recover` add to their read-write grant the directory of each file a
//!   hook above names (`COMMIT_MARKER`, `COMMIT_HOLD`, `REFUSED_CLAIM_HOLD`,
//!   `STEP_HOLD`, `DWEB_WRITER_MARKER`, `NAMING_MARKER`, `X402_SIGN_MARKER`,
//!   `EIP1193_RETAINED_MARKER`, `GRANT_WRITE_FAIL`, `INTENT_IDS`,
//!   `INTENT_LIMITS`, `APPROVAL_CLOCK`, `WALL_CLOCK`, and `SWAP`'s
//!   replacement), and with `SWAP` renames across directories (`refer`),
//!   since its replacement is renamed in from elsewhere. So every hook
//!   works confined; without these variables, nothing is added.

use std::time::Duration;

/// Set as the core begins to exit; it releases a held commit.
#[cfg(feature = "testhooks")]
static EXITING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The core is about to wait for committed work and exit.
#[cfg(feature = "testhooks")]
pub fn exiting() {
    EXITING.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Waits until `release` exists, `also` holds, or 120 s pass.
#[cfg(feature = "testhooks")]
fn hold(release: &std::ffi::OsStr, also: impl Fn() -> bool) {
    let until = std::time::Instant::now() + Duration::from_secs(120);
    while !std::path::Path::new(release).exists() && !also() && std::time::Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(feature = "testhooks")]
fn millis(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

#[cfg(feature = "testhooks")]
pub fn snapshot_delay() {
    if let Some(ms) = millis("FREEDOM_CORED_TEST_SNAPSHOT_DELAY_MS") {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

#[cfg(feature = "testhooks")]
pub fn eip1193_dequeue_delay() {
    if let Some(ms) = millis("FREEDOM_CORED_TEST_EIP1193_DEQUEUE_DELAY_MS") {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

/// `eip1193::Connects` keeps `live` prompt ids, `handles` and `ended`
/// tombstones: written to the marker file, when the test names one.
#[cfg(feature = "testhooks")]
pub fn eip1193_retained(live: usize, handles: usize, ended: usize) {
    if let Some(marker) = std::env::var_os("FREEDOM_CORED_TEST_EIP1193_RETAINED_MARKER") {
        let _ = std::fs::write(marker, format!("{live} {handles} {ended}"));
    }
}

#[cfg(not(feature = "testhooks"))]
pub fn eip1193_retained(_live: usize, _handles: usize, _ended: usize) {}

/// Whether each of a page request's name checks (design 0012, APR-5f)
/// evicts the name from naming's cache first, so that a test plays every
/// check's resolution through main, as it scripts it.
#[cfg(feature = "testhooks")]
pub fn eip1193_names_uncached() -> bool {
    std::env::var_os("FREEDOM_CORED_TEST_EIP1193_NAMES_UNCACHED").is_some()
}

#[cfg(not(feature = "testhooks"))]
pub fn eip1193_names_uncached() -> bool {
    false
}

#[cfg(feature = "testhooks")]
pub fn eip1193_overall(overall: u64) -> u64 {
    millis("FREEDOM_CORED_TEST_EIP1193_OVERALL_MS").unwrap_or(overall)
}

/// A name check's lookup deadline: the request's time `left`, less the
/// hook's milliseconds (never under one).
#[cfg(feature = "testhooks")]
pub fn eip1193_check_ms(left: u64) -> u64 {
    millis("FREEDOM_CORED_TEST_EIP1193_CHECK_EARLY_MS")
        .map_or(left, |early| left.saturating_sub(early).max(1))
}

/// A page send's chain read's deadline, all the request's time `left`:
/// less the hook's milliseconds (never under one).
#[cfg(feature = "testhooks")]
pub fn eip1193_read_ms(left: u64) -> u64 {
    millis("FREEDOM_CORED_TEST_EIP1193_READ_EARLY_MS")
        .map_or(left, |early| left.saturating_sub(early).max(1))
}

#[cfg(feature = "testhooks")]
pub fn job_delay() {
    if let Some(ms) = millis("FREEDOM_CORED_TEST_JOB_DELAY_MS") {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

#[cfg(feature = "testhooks")]
pub fn refused_claim_hold() {
    if let Some(release) = std::env::var_os("FREEDOM_CORED_TEST_REFUSED_CLAIM_HOLD") {
        hold(&release, || false);
    }
}

#[cfg(feature = "testhooks")]
pub fn commit_delay() {
    if let Ok(marker) = std::env::var("FREEDOM_CORED_TEST_COMMIT_MARKER") {
        let _ = std::fs::write(marker, b"claimed");
    }
    if let Some(ms) = millis("FREEDOM_CORED_TEST_COMMIT_DELAY_MS") {
        std::thread::sleep(Duration::from_millis(ms));
    }
    if let Some(release) = std::env::var_os("FREEDOM_CORED_TEST_COMMIT_HOLD") {
        hold(&release, || {
            EXITING.load(std::sync::atomic::Ordering::SeqCst)
        });
    }
}

#[cfg(feature = "testhooks")]
pub fn keystore_deadline(default: Duration) -> Duration {
    millis("FREEDOM_CORED_TEST_KEYSTORE_DEADLINE_MS").map_or(default, Duration::from_millis)
}

#[cfg(feature = "testhooks")]
pub fn keystore_exit_after_store() -> bool {
    std::env::var_os("FREEDOM_CORED_TEST_KEYSTORE_EXIT_AFTER_STORE").is_some()
}

#[cfg(feature = "testhooks")]
pub fn keystore_spawn_probe() -> Option<bool> {
    std::env::var_os("FREEDOM_CORED_TEST_KEYSTORE_SPAWN_PROBE")?;
    Some(
        std::process::Command::new("/usr/bin/true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok(),
    )
}

#[cfg(feature = "testhooks")]
pub fn keystore_capabilities(native: fc_keystore::Capabilities) -> fc_keystore::Capabilities {
    match std::env::var("FREEDOM_CORED_TEST_KEYSTORE_BACKEND").as_deref() {
        Ok("macos-keychain") => fc_keystore::Capabilities {
            backend: Some(fc_keystore::Backend::MacosKeychain),
            unattended: true,
            user_presence: false,
        },
        Ok("none") => fc_keystore::Capabilities {
            backend: None,
            unattended: false,
            user_presence: false,
        },
        _ => native,
    }
}

#[cfg(feature = "testhooks")]
pub fn secrets_step(step: &str) {
    if std::env::var("FREEDOM_CORED_TEST_SECRETS_CRASH").is_ok_and(|s| s == step) {
        std::process::exit(99);
    }
    if let Some(file) = std::env::var_os("FREEDOM_CORED_TEST_STEP_HOLD")
        && std::fs::read_to_string(&file).is_ok_and(|held| held.trim() == step)
    {
        let mut held = file.clone();
        held.push(".held");
        let _ = std::fs::write(&held, step);
        let mut release = file;
        release.push(".release");
        hold(&release, || {
            EXITING.load(std::sync::atomic::Ordering::SeqCst)
        });
    }
}

/// Whether this write fails: once per process for each step the variable
/// lists.
#[cfg(feature = "testhooks")]
pub fn secrets_fails(step: &str) -> bool {
    static FAILED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    let listed = std::env::var("FREEDOM_CORED_TEST_SECRETS_FAIL")
        .is_ok_and(|steps| steps.split(',').any(|s| s == step));
    if !listed {
        return false;
    }
    let Ok(mut failed) = FAILED.lock() else {
        return false;
    };
    if failed.iter().any(|s| s == step) {
        return false;
    }
    failed.push(step.to_owned());
    true
}

#[cfg(feature = "testhooks")]
pub fn kdf_deadline(default: Duration) -> Duration {
    millis("FREEDOM_CORED_TEST_KDF_DEADLINE_MS").map_or(default, Duration::from_millis)
}

#[cfg(feature = "testhooks")]
pub fn stall(default: Duration) -> Duration {
    millis("FREEDOM_CORED_TEST_STALL_MS").map_or(default, Duration::from_millis)
}

#[cfg(feature = "testhooks")]
pub fn chain_bounds(mut bounds: fc_chain::machine::Bounds) -> fc_chain::machine::Bounds {
    if let Some(total) = millis("FREEDOM_CORED_TEST_CHAIN_TOTAL_BYTES") {
        bounds.total_bytes = usize::try_from(total).unwrap_or(usize::MAX);
    }
    bounds
}

#[cfg(feature = "testhooks")]
pub fn dweb_bounds(mut bounds: crate::dweb::engine::Bounds) -> crate::dweb::engine::Bounds {
    if let Some(grants) = millis("FREEDOM_CORED_TEST_DWEB_GRANTS_BYTES") {
        bounds.grants = usize::try_from(grants).unwrap_or(usize::MAX);
    }
    if let Some(streams) = millis("FREEDOM_CORED_TEST_DWEB_STREAMS") {
        bounds.streams = usize::try_from(streams).unwrap_or(usize::MAX);
    }
    if let Some(running) = millis("FREEDOM_CORED_TEST_DWEB_RUNNING") {
        bounds.running = usize::try_from(running).unwrap_or(usize::MAX);
    }
    bounds
}

/// The most verified-body bytes the dweb writer has held at once.
#[cfg(feature = "testhooks")]
static DWEB_WRITER_MOST: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The dweb writer holds `held` queued body bytes: a new high-water mark
/// goes to the marker file.
#[cfg(feature = "testhooks")]
pub fn dweb_writer_held(held: usize) {
    static MARKER: std::sync::OnceLock<Option<std::ffi::OsString>> = std::sync::OnceLock::new();
    let Some(marker) =
        MARKER.get_or_init(|| std::env::var_os("FREEDOM_CORED_TEST_DWEB_WRITER_MARKER"))
    else {
        return;
    };
    let most = DWEB_WRITER_MOST.fetch_max(held, std::sync::atomic::Ordering::SeqCst);
    if held > most {
        // Written whole, then renamed over the marker: a test reading it
        // meanwhile sees the old mark or the new one.
        let mut next = marker.clone();
        next.push(".next");
        if std::fs::write(&next, held.to_string()).is_ok() {
            let _ = std::fs::rename(&next, marker);
        }
    }
}

#[cfg(feature = "testhooks")]
fn naming_mark(line: &str) {
    use std::io::Write as _;
    if let Some(marker) = std::env::var_os("FREEDOM_CORED_TEST_NAMING_MARKER") {
        // One write per line: the test reads the file while this appends.
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(marker)
            .and_then(|mut file| file.write_all(format!("{line}\n").as_bytes()));
    }
}

#[cfg(feature = "testhooks")]
pub fn naming_reply() {
    naming_mark("reply");
}

#[cfg(feature = "testhooks")]
pub fn naming_drain(frames: usize) {
    naming_mark(&format!("drain {frames}"));
}

#[cfg(feature = "testhooks")]
pub fn x402_signing() {
    use std::io::Write as _;
    if let Some(marker) = std::env::var_os("FREEDOM_CORED_TEST_X402_SIGN_MARKER") {
        // One write per line: the test reads the file between requests.
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(marker)
            .and_then(|mut file| file.write_all(b"sign\n"));
    }
}

#[cfg(feature = "testhooks")]
pub fn swap(stage: &str, path: &std::path::Path) {
    let Ok(spec) = std::env::var("FREEDOM_CORED_TEST_SWAP") else {
        return;
    };
    if let Some((wanted, replacement)) = spec.split_once('=')
        && wanted == stage
    {
        let _ = std::fs::rename(replacement, path);
    }
}

#[cfg(feature = "testhooks")]
pub fn receipt_ttl_ms(default: u64) -> u64 {
    millis("FREEDOM_CORED_TEST_RECEIPT_TTL_MS").unwrap_or(default)
}

#[cfg(not(feature = "testhooks"))]
pub fn receipt_ttl_ms(default: u64) -> u64 {
    default
}

#[cfg(feature = "testhooks")]
pub fn grant_write_fails(store: &str, step: &str) -> bool {
    let Some(path) = std::env::var_os("FREEDOM_CORED_TEST_GRANT_WRITE_FAIL") else {
        return false;
    };
    std::fs::read_to_string(path).is_ok_and(|spec| {
        spec.lines()
            .any(|line| line.trim().split_once(':') == Some((store, step)))
    })
}

#[cfg(not(feature = "testhooks"))]
pub fn grant_write_fails(_store: &str, _step: &str) -> bool {
    false
}

/// [`grant_write_fails`], but true only the first time in the process that
/// the file lists the step.
#[cfg(feature = "testhooks")]
pub fn grant_write_fails_once(store: &str, step: &str) -> bool {
    static FAILED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    if !grant_write_fails(store, step) {
        return false;
    }
    let Ok(mut failed) = FAILED.lock() else {
        return false;
    };
    let key = format!("{store}:{step}");
    if failed.contains(&key) {
        return false;
    }
    failed.push(key);
    true
}

#[cfg(not(feature = "testhooks"))]
pub fn grant_write_fails_once(_store: &str, _step: &str) -> bool {
    false
}

/// The hooks of every durable write but a store file's
/// (`fc_store::fsx::replace`): `FREEDOM_CORED_TEST_SWAP`'s `checked` stage.
/// No step fails.
pub struct Swap;

impl fc_store::Hooks for Swap {
    fn checked(&self, temp: &std::path::Path) {
        swap("checked", temp);
    }
}

/// The hooks of a secrets-file write, and of `rpc-api-keys.json`'s, named
/// by its step: [`Swap`]'s, and the directory flush after the rename fails
/// when `FREEDOM_CORED_TEST_SECRETS_FAIL` lists `<step>-flush` (once per
/// process), the change in place and reported not durable.
pub struct SecretsWrite<'a>(pub &'a str);

impl fc_store::Hooks for SecretsWrite<'_> {
    fn fails(&self, step: fc_store::Step) -> bool {
        step == fc_store::Step::Flush && secrets_fails(&format!("{}-flush", self.0))
    }

    fn checked(&self, temp: &std::path::Path) {
        swap("checked", temp);
    }
}

/// The hooks of a store file's write (`fc_store::file::write_file`): the
/// steps `FREEDOM_CORED_TEST_GRANT_WRITE_FAIL` names for this store
/// (`dapp`, `swarm`, `radicle`, `x402`, `phone`, `vault_meta`,
/// `safe_pending`, `receipts`), and of `wallet-intents.jsonl`'s journal
/// (`intents`), read at each write.
pub struct GrantWrite<'a>(pub &'a str);

impl fc_store::Hooks for GrantWrite<'_> {
    fn fails(&self, step: fc_store::Step) -> bool {
        grant_write_fails(self.0, step.name())
    }
}

#[cfg(feature = "testhooks")]
pub fn hold_reply(id: u64) -> bool {
    std::env::var("FREEDOM_CORED_TEST_HOLD_REPLY")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        == Some(id)
}

#[cfg(not(feature = "testhooks"))]
pub fn hold_reply(_id: u64) -> bool {
    false
}

#[cfg(feature = "testhooks")]
pub fn wall_clock(now_ms: u64) -> u64 {
    std::env::var_os("FREEDOM_CORED_TEST_WALL_CLOCK")
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(now_ms)
}

#[cfg(not(feature = "testhooks"))]
pub fn wall_clock(now_ms: u64) -> u64 {
    now_ms
}

#[cfg(feature = "testhooks")]
pub fn intent_id() -> Option<String> {
    let path = std::env::var_os("FREEDOM_CORED_TEST_INTENT_IDS")?;
    let text = std::fs::read_to_string(&path).ok()?;
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let first = lines.next()?.trim().to_owned();
    let rest: Vec<&str> = lines.collect();
    std::fs::write(&path, rest.join("\n")).ok()?;
    Some(first)
}

#[cfg(not(feature = "testhooks"))]
pub fn intent_id() -> Option<String> {
    None
}

#[cfg(feature = "testhooks")]
pub fn intent_limits(
    default: fc_wallet_state::intents::Limits,
) -> fc_wallet_state::intents::Limits {
    let Some(text) = std::env::var_os("FREEDOM_CORED_TEST_INTENT_LIMITS")
        .and_then(|path| std::fs::read_to_string(path).ok())
    else {
        return default;
    };
    let Ok(over) = fc_json::parse(&text) else {
        return default;
    };
    let n = |key: &str| match over.get(key) {
        Some(fc_json::JsValue::Number(n)) if *n >= 0.0 => Some(*n as u64),
        _ => None,
    };
    let mut limits = default;
    let size = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
    if let Some(v) = n("heldPerAccount") {
        limits.held_per_account = size(v);
    }
    if let Some(v) = n("held") {
        limits.held = size(v);
    }
    if let Some(v) = n("hashesPerIntent") {
        limits.hashes_per_intent = size(v);
    }
    if let Some(v) = n("openHandoffsPerIntent") {
        limits.open_handoffs_per_intent = size(v);
    }
    if let Some(v) = n("tombstones") {
        limits.tombstones = size(v);
    }
    if let Some(v) = n("rawBytes") {
        limits.raw_bytes = size(v);
    }
    if let Some(v) = n("journalBytes") {
        limits.journal_bytes = v;
    }
    if let Some(v) = n("readBytes") {
        limits.read_bytes = v;
    }
    limits
}

#[cfg(not(feature = "testhooks"))]
pub fn intent_limits(
    default: fc_wallet_state::intents::Limits,
) -> fc_wallet_state::intents::Limits {
    default
}

#[cfg(feature = "testhooks")]
pub fn phone_recheck_ms(default: u64) -> u64 {
    millis("FREEDOM_CORED_TEST_PHONE_RECHECK_MS").unwrap_or(default)
}

#[cfg(not(feature = "testhooks"))]
pub fn phone_recheck_ms(default: u64) -> u64 {
    default
}

#[cfg(feature = "testhooks")]
pub fn approval_clock(now_ms: u64) -> u64 {
    std::env::var_os("FREEDOM_CORED_TEST_APPROVAL_CLOCK")
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(now_ms)
}

#[cfg(not(feature = "testhooks"))]
pub fn approval_clock(now_ms: u64) -> u64 {
    now_ms
}

#[cfg(feature = "testhooks")]
pub fn mains_word() -> bool {
    std::env::var_os("FREEDOM_CORED_TEST_MAINS_WORD").is_some()
}

#[cfg(not(feature = "testhooks"))]
pub fn mains_word() -> bool {
    false
}

#[cfg(feature = "testhooks")]
pub fn test_methods() -> bool {
    std::env::var_os("FREEDOM_CORED_TEST_METHODS").is_some()
}

#[cfg(feature = "testhooks")]
pub fn profile_hold() {
    let Ok(spec) = std::env::var("FREEDOM_CORED_TEST_PROFILE_HOLD") else {
        return;
    };
    if let Some((marker, release)) = spec.split_once('=') {
        let _ = std::fs::write(marker, b"held");
        hold(std::ffi::OsStr::new(release), || false);
    }
}

#[cfg(feature = "testhooks")]
pub fn profile_delete_step(step: &str) {
    if std::env::var("FREEDOM_CORED_TEST_PROFILE_DELETE_CRASH").is_ok_and(|s| s == step) {
        std::process::exit(99);
    }
    if let Ok(spec) = std::env::var("FREEDOM_CORED_TEST_PROFILE_DELETE_PAUSE")
        && let Some((at, files)) = spec.split_once('=')
        && at == step
        && let Some((marker, release)) = files.split_once('=')
    {
        let _ = std::fs::write(marker, b"paused");
        hold(std::ffi::OsStr::new(release), || false);
    }
}

#[cfg(feature = "testhooks")]
pub fn profile_migrate_step(step: &str) {
    if std::env::var("FREEDOM_CORED_TEST_PROFILE_MIGRATE_CRASH").is_ok_and(|s| s == step) {
        std::process::exit(99);
    }
    if let Ok(spec) = std::env::var("FREEDOM_CORED_TEST_PROFILE_MIGRATE_PAUSE")
        && let Some((at, files)) = spec.split_once('=')
        && at == step
        && let Some((marker, release)) = files.split_once('=')
    {
        let _ = std::fs::write(marker, b"paused");
        hold(std::ffi::OsStr::new(release), || false);
    }
}

#[cfg(feature = "testhooks")]
pub fn profile_migrate_exdev(name: &str) -> bool {
    std::env::var("FREEDOM_CORED_TEST_PROFILE_MIGRATE_EXDEV").is_ok_and(|list| {
        list.split(',')
            .any(|listed| listed == "*" || listed == name)
    })
}

#[cfg(feature = "testhooks")]
pub fn profile_migrate_free() -> Option<u64> {
    let file = std::env::var_os("FREEDOM_CORED_TEST_PROFILE_MIGRATE_FREE")?;
    std::fs::read_to_string(file).ok()?.trim().parse().ok()
}

#[cfg(feature = "testhooks")]
pub fn profile_migrate_full(made: u64) -> bool {
    millis("FREEDOM_CORED_TEST_PROFILE_MIGRATE_ENOSPC").is_some_and(|n| made > n)
}

#[cfg(feature = "testhooks")]
#[cfg(target_os = "linux")]
pub fn profile_migrate_walk() -> bool {
    std::env::var("FREEDOM_CORED_TEST_PROFILE_MIGRATE_LOOKUP")
        .is_ok_and(|lookup| lookup == "walk" || lookup == "walk-no-mount-id")
}

#[cfg(feature = "testhooks")]
pub fn profile_migrate_no_mount_id() -> bool {
    std::env::var("FREEDOM_CORED_TEST_PROFILE_MIGRATE_LOOKUP")
        .is_ok_and(|lookup| lookup == "walk-no-mount-id")
}

/// The directories `FREEDOM_CORED_TEST_PROFILE_HOLD`'s,
/// `FREEDOM_CORED_TEST_PROFILE_DELETE_PAUSE`'s,
/// `FREEDOM_CORED_TEST_PROFILE_MIGRATE_PAUSE`'s and
/// `FREEDOM_CORED_TEST_PROFILE_MIGRATE_FREE`'s files live in, which a
/// confined subcommand's grant takes so the hooks still work.
#[cfg(feature = "testhooks")]
pub fn profile_hook_dirs() -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if let Ok(free) = std::env::var("FREEDOM_CORED_TEST_PROFILE_MIGRATE_FREE") {
        files.push(free);
    }
    if let Ok(spec) = std::env::var("FREEDOM_CORED_TEST_PROFILE_HOLD")
        && let Some((marker, release)) = spec.split_once('=')
    {
        files.extend([marker.to_owned(), release.to_owned()]);
    }
    for pause in [
        "FREEDOM_CORED_TEST_PROFILE_DELETE_PAUSE",
        "FREEDOM_CORED_TEST_PROFILE_MIGRATE_PAUSE",
    ] {
        if let Ok(spec) = std::env::var(pause)
            && let Some((_, rest)) = spec.split_once('=')
            && let Some((marker, release)) = rest.split_once('=')
        {
            files.extend([marker.to_owned(), release.to_owned()]);
        }
    }
    files
        .iter()
        .filter_map(|file| std::path::Path::new(file).parent())
        .filter(|dir| dir.is_dir())
        .map(std::path::Path::to_path_buf)
        .collect()
}

#[cfg(feature = "testhooks")]
pub fn profile_confined(report: &fc_service::confine::Report) {
    confined_reads("FREEDOM_CORED_TEST_PROFILE_CONFINED", report);
}

/// Reads each path `variable` lists, and logs `test: confined` with the
/// report and whether each read worked.
#[cfg(feature = "testhooks")]
fn confined_reads(variable: &str, report: &fc_service::confine::Report) {
    let Some(list) = std::env::var_os(variable) else {
        return;
    };
    let reads: Vec<serde_json::Value> = std::env::split_paths(&list)
        .map(|path| {
            let read = if path.is_dir() {
                std::fs::read_dir(&path).map(|_| ())
            } else {
                std::fs::read(&path).map(|_| ())
            };
            serde_json::json!({
                "path": path.to_string_lossy(),
                "ok": read.is_ok(),
            })
        })
        .collect();
    crate::log::info(
        "test: confined",
        serde_json::json!({ "confinement": report.to_json(), "reads": reads }),
    );
}

/// The hooks whose variable names a file `serve`, `hold-lock` or
/// `recover` reads or writes.
#[cfg(feature = "testhooks")]
const CORE_HOOK_FILES: &[&str] = &[
    "FREEDOM_CORED_TEST_COMMIT_MARKER",
    "FREEDOM_CORED_TEST_COMMIT_HOLD",
    "FREEDOM_CORED_TEST_REFUSED_CLAIM_HOLD",
    "FREEDOM_CORED_TEST_STEP_HOLD",
    "FREEDOM_CORED_TEST_DWEB_WRITER_MARKER",
    "FREEDOM_CORED_TEST_NAMING_MARKER",
    "FREEDOM_CORED_TEST_X402_SIGN_MARKER",
    "FREEDOM_CORED_TEST_EIP1193_RETAINED_MARKER",
    "FREEDOM_CORED_TEST_GRANT_WRITE_FAIL",
    "FREEDOM_CORED_TEST_INTENT_IDS",
    "FREEDOM_CORED_TEST_INTENT_LIMITS",
    "FREEDOM_CORED_TEST_APPROVAL_CLOCK",
    "FREEDOM_CORED_TEST_WALL_CLOCK",
];

/// What a confined `serve`, `hold-lock` or `recover` adds to its grant so
/// the hooks still work (design 0017): the directory of each hook file
/// named, that is a directory now, and whether `FREEDOM_CORED_TEST_SWAP`
/// is set, whose replacement is renamed in from another directory
/// (`refer`).
#[cfg(feature = "testhooks")]
pub fn core_hook_grant() -> (Vec<std::path::PathBuf>, bool) {
    let mut files: Vec<std::path::PathBuf> = CORE_HOOK_FILES
        .iter()
        .filter_map(std::env::var_os)
        .map(std::path::PathBuf::from)
        .collect();
    let swap = std::env::var("FREEDOM_CORED_TEST_SWAP").ok();
    if let Some((_, replacement)) = swap.as_deref().and_then(|spec| spec.split_once('=')) {
        files.push(replacement.into());
    }
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    for dir in files
        .iter()
        .filter_map(|file| file.parent())
        .filter(|dir| dir.is_dir())
    {
        if !dirs.iter().any(|known| known == dir) {
            dirs.push(dir.to_path_buf());
        }
    }
    (dirs, swap.is_some())
}

#[cfg(not(feature = "testhooks"))]
pub fn core_hook_grant() -> (Vec<std::path::PathBuf>, bool) {
    (Vec::new(), false)
}

#[cfg(feature = "testhooks")]
pub fn core_confined(report: &fc_service::confine::Report) {
    confined_reads("FREEDOM_CORED_TEST_CORE_CONFINED", report);
}

#[cfg(not(feature = "testhooks"))]
pub fn core_confined(_report: &fc_service::confine::Report) {}

#[cfg(not(feature = "testhooks"))]
pub fn profile_migrate_step(_step: &str) {}

#[cfg(not(feature = "testhooks"))]
pub fn profile_migrate_exdev(_name: &str) -> bool {
    false
}

#[cfg(not(feature = "testhooks"))]
pub fn profile_migrate_free() -> Option<u64> {
    None
}

#[cfg(not(feature = "testhooks"))]
pub fn profile_migrate_full(_made: u64) -> bool {
    false
}

#[cfg(not(feature = "testhooks"))]
#[cfg(target_os = "linux")]
pub fn profile_migrate_walk() -> bool {
    false
}

#[cfg(not(feature = "testhooks"))]
pub fn profile_migrate_no_mount_id() -> bool {
    false
}

#[cfg(not(feature = "testhooks"))]
pub fn profile_hook_dirs() -> Vec<std::path::PathBuf> {
    Vec::new()
}

#[cfg(not(feature = "testhooks"))]
pub fn profile_confined(_report: &fc_service::confine::Report) {}

#[cfg(not(feature = "testhooks"))]
pub fn profile_delete_step(_step: &str) {}

#[cfg(not(feature = "testhooks"))]
pub fn profile_hold() {}

#[cfg(not(feature = "testhooks"))]
pub fn snapshot_delay() {}

#[cfg(not(feature = "testhooks"))]
pub fn job_delay() {}

#[cfg(not(feature = "testhooks"))]
pub fn commit_delay() {}

#[cfg(not(feature = "testhooks"))]
pub fn refused_claim_hold() {}

#[cfg(not(feature = "testhooks"))]
pub fn exiting() {}

#[cfg(not(feature = "testhooks"))]
pub fn kdf_deadline(default: Duration) -> Duration {
    default
}

#[cfg(not(feature = "testhooks"))]
pub fn keystore_deadline(default: Duration) -> Duration {
    default
}

#[cfg(not(feature = "testhooks"))]
pub fn keystore_exit_after_store() -> bool {
    false
}

#[cfg(not(feature = "testhooks"))]
pub fn keystore_spawn_probe() -> Option<bool> {
    None
}

#[cfg(not(feature = "testhooks"))]
pub fn keystore_capabilities(native: fc_keystore::Capabilities) -> fc_keystore::Capabilities {
    native
}

#[cfg(not(feature = "testhooks"))]
pub fn secrets_step(_step: &str) {}

#[cfg(not(feature = "testhooks"))]
pub fn secrets_fails(_step: &str) -> bool {
    false
}

#[cfg(not(feature = "testhooks"))]
pub fn stall(default: Duration) -> Duration {
    default
}

#[cfg(not(feature = "testhooks"))]
pub fn swap(_stage: &str, _path: &std::path::Path) {}

#[cfg(not(feature = "testhooks"))]
pub fn x402_signing() {}

#[cfg(not(feature = "testhooks"))]
pub fn naming_reply() {}

#[cfg(not(feature = "testhooks"))]
pub fn naming_drain(_frames: usize) {}

#[cfg(not(feature = "testhooks"))]
pub fn eip1193_dequeue_delay() {}

#[cfg(not(feature = "testhooks"))]
pub fn eip1193_overall(overall: u64) -> u64 {
    overall
}

#[cfg(not(feature = "testhooks"))]
pub fn eip1193_check_ms(left: u64) -> u64 {
    left
}

#[cfg(not(feature = "testhooks"))]
pub fn eip1193_read_ms(left: u64) -> u64 {
    left
}

#[cfg(not(feature = "testhooks"))]
pub fn chain_bounds(bounds: fc_chain::machine::Bounds) -> fc_chain::machine::Bounds {
    bounds
}

#[cfg(not(feature = "testhooks"))]
pub fn dweb_bounds(bounds: crate::dweb::engine::Bounds) -> crate::dweb::engine::Bounds {
    bounds
}

#[cfg(not(feature = "testhooks"))]
pub fn dweb_writer_held(_held: usize) {}
