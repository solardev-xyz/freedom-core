//! `profile migrate --finish-only` (design 0013, 5.4b, "The move" and
//! "Readers, and the downgrade"; step PRF-3): the move's recovery, which
//! starts no move. Main runs it when `profile open` reports `layout:
//! "pending"`, before `hold-profile` and before it takes its own lock.
//!
//! ```text
//! freedom-cored profile migrate --profile-dir <dir> --lock-dir <dir> [--dev] --finish-only
//! ```
//!
//! Starting a move is PRF-9's: without `--finish-only` the arguments are
//! refused (64).
//!
//! 1. **Where it may act:** by a delete's overlap rule
//!    (`fc_profile::delete::overlaps`, against every catalog at or above
//!    the profile's directory), the directory is no shared entry of the app
//!    root (`Profiles`, `R`, `locks`, …, or inside one but the profiles
//!    root), and is neither at, above nor inside another record's
//!    directory. The packaged default profile's, the app root itself, holds
//!    no other record among its entries but the shared ones. Refused with
//!    `overlap` (74) before anything is taken. Below it, it acts on the
//!    journal's names alone, each one of `fc_profile::layout`'s list, which
//!    holds no shared entry of the app root.
//! 2. **The move's own exclusion,** for the whole run, each held by another
//!    process ending it with `busy` (75) and nothing changed:
//!    - the profile gate first, so a new build sees the profile open;
//!    - then the profile lock, `profile-open.lock` in today's format
//!      (`lock.rs`, with the profile's timings: 30 s and 10 s, or a dev
//!      build's 5 s and 1 s). Its target file is made if missing, as
//!      `profile-lock.js` makes it, so an older build's `isProfileLocked`
//!      sees the lock. A stale lock is taken over: the gate shows no live
//!      new build has the profile. A fresh one is another's;
//!    - the core's identity gate and freedom-ipfsd's, each on its old path
//!      and its new one (`freedom/identity`, `freedom/ipfs-data/
//!      freedom-ipfs`). A missing directory is gated at the path it would
//!      have, and nothing is made but the lock files.
//!
//!    Each gate's lock is tried for a second: a probe (`profile status`)
//!    holds one for a moment, and can't make the run busy.
//! 3. **Confinement** (`confine.rs`): read-write on the profile's
//!    directory, renames across directories, the gates' descriptors; no
//!    network, no process. Then the lock's refresher starts.
//! 4. **The journal,** `freedom/.move.json` (`fc_profile::layout`): none is
//!    `nothing`. One that can't be read or is out of form is `corrupt`
//!    (74): the core doesn't guess which entries moved.
//! 5. **Every entry's state first,** then the changes, so an entry that
//!    can't be settled without a guess changes nothing (`corrupt`):
//!    - **before the marker** (`freedom/layout.json`), each entry is put
//!      back, in reverse order: a cross-device copy cut short is removed
//!      while its source is at the root; the placeholder file at `identity`
//!      is removed and the directory renamed back; a moved entry renamed
//!      back (on Windows, a rename refused while another handle holds the
//!      entry is tried again, 10 times, 100 ms apart). Then the directories
//!      are flushed, the journal removed, and `freedom/` too if it is
//!      empty: `rolled_back`;
//!    - **after the marker,** every entry must be in `freedom/`; nothing at
//!      the root is removed (see `fc_profile::layout::roll_forward`), and
//!      the journal is removed: `migrated`.
//!
//!    Before each change the profile lock must still be this run's: lost
//!    (the run was frozen past the stale time and another build took it
//!    over), it changes nothing more, keeps the journal, and ends with
//!    `lock_lost` (74).
//!
//! **stdout:** one word, `migrated`, `nothing`, `rolled_back`, `busy`,
//! `lock_lost` or `corrupt`. Any other failure is a storage one, as the
//! other subcommands': `{ "error": <kind> }`, exit 74 (an unqualified
//! filesystem, a directory that isn't the user's, `overlap`, an I/O error
//! with the journal kept).

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fc_profile::layout::{self, EntryState, Found, Unsettled};
use fc_service::gate::{Gate, GateError, PROFILE_NAMESPACE};

use super::confine::{self, Grant};
use super::lock::{Lock, LockError, Timing};
use super::{Flags, storage};
use crate::anchor::{Dir, Kind, Resolve};
use crate::exit::Exit;
use crate::fsx::Regular;
use crate::log;
use crate::testhooks::profile_migrate_step as step;

/// How long each gate's lock is tried.
const GATE_RETRY: Duration = Duration::from_secs(1);

pub fn run(args: impl Iterator<Item = std::ffi::OsString>) -> Result<Exit, ()> {
    let flags = Flags::parse(
        args,
        &["--profile-dir", "--lock-dir", "--dev", "--finish-only"],
    )?;
    if !flags.has("--finish-only") {
        return Err(());
    }
    let profile_dir = PathBuf::from(flags.path("--profile-dir")?);
    let lock_dir = PathBuf::from(flags.path("--lock-dir")?);
    Ok(migrate(&profile_dir, &lock_dir, flags.has("--dev")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Migrated,
    Nothing,
    RolledBack,
    Busy,
    LockLost,
    Corrupt,
}

impl Outcome {
    fn word(self) -> &'static str {
        match self {
            Outcome::Migrated => "migrated",
            Outcome::Nothing => "nothing",
            Outcome::RolledBack => "rolled_back",
            Outcome::Busy => "busy",
            Outcome::LockLost => "lock_lost",
            Outcome::Corrupt => "corrupt",
        }
    }

    fn exit(self) -> Exit {
        match self {
            Outcome::Migrated | Outcome::Nothing | Outcome::RolledBack => Exit::Ok,
            Outcome::Busy => Exit::LockHeld,
            Outcome::LockLost | Outcome::Corrupt => Exit::Storage,
        }
    }
}

/// The outcome's word on stdout, and its exit.
fn say(outcome: Outcome) -> Exit {
    let mut stdout = std::io::stdout().lock();
    match stdout
        .write_all(format!("{}\n", outcome.word()).as_bytes())
        .and_then(|()| stdout.flush())
    {
        Ok(()) => outcome.exit(),
        Err(_) => Exit::Internal,
    }
}

/// The gates the move holds.
#[derive(Clone, Copy)]
enum Which {
    Profile,
    Core,
    Ipfs,
}

impl Which {
    fn name(self) -> &'static str {
        match self {
            Which::Profile => "profile",
            Which::Core => "core",
            Which::Ipfs => "ipfs",
        }
    }

    fn lock_file_name(self, canonical: &Path) -> String {
        match self {
            Which::Profile => fc_service::gate::lock_file_name(PROFILE_NAMESPACE, canonical),
            Which::Core => crate::gate::lock_file_name(canonical),
            Which::Ipfs => fc_service::gate::lock_file_name("ipfs", canonical),
        }
    }
}

/// Takes `which`'s gate on `dir`: held by another, the run is `busy`.
fn take(which: Which, dir: &Path, lock_dir: &Path) -> Result<Gate, Exit> {
    let name = |canonical: &Path| which.lock_file_name(canonical);
    let inside = matches!(which, Which::Profile);
    match fc_service::gate::acquire_for_delete(dir, lock_dir, &name, inside, GATE_RETRY) {
        Ok(gate) => Ok(gate),
        Err(GateError::Held) => {
            log::error(
                "a gate of the profile is held: it is in use",
                serde_json::json!({ "gate": which.name() }),
            );
            Err(say(Outcome::Busy))
        }
        Err(e) => Err(storage("gate", &e.to_string())),
    }
}

/// The profile lock, taken (not yet kept): its target made if missing, as
/// `ensureLockTarget` makes it, with no retry.
fn take_profile_lock(canonical: &Path, dev: bool) -> Result<Lock, Exit> {
    let target = canonical.join(fc_profile::PROFILE_LOCK_TARGET);
    if std::fs::symlink_metadata(&target).is_err() {
        let text = format!(
            "Freedom profile lock target\nprofileId=\ncreatedAt={}",
            super::now_iso()
        );
        // Without it an older build's `isProfileLocked` reads the profile
        // closed; the lock still excludes its `acquireProfileLock`.
        if let Err(e) = std::fs::write(&target, text) {
            log::warn(
                "cannot make the profile lock's target",
                serde_json::json!({ "error": e.kind().to_string() }),
            );
        }
    }
    match Lock::take(
        &canonical.join(fc_profile::PROFILE_LOCK_DIR),
        Timing::profile(dev),
        0,
        |_| 0,
    ) {
        Ok(lock) => Ok(lock),
        Err(LockError::Held) => {
            log::error(
                "the profile's lock is fresh: it is in use",
                serde_json::json!({}),
            );
            Err(say(Outcome::Busy))
        }
        Err(LockError::Io(e)) => Err(storage("io", &e.kind().to_string())),
    }
}

/// Why the profile's directory isn't one the move may act on: by a
/// delete's rule (`fc_profile::delete::overlaps`), against each catalog at
/// or above it, the directory is the profiles root or another shared entry
/// of the app root (or inside one but the profiles root), or at, above or
/// inside another record's directory; for the packaged default profile, the
/// app root, another record among its entries but the shared ones. A
/// directory under no catalog is checked against none. `Err` for a catalog
/// that can't be read: nothing proves the directory overlaps nothing.
fn overlap(canonical: &Path) -> Result<Option<String>, Exit> {
    let style = fc_profile::Style::native();
    for app_root in canonical.ancestors() {
        let catalog = app_root.join(fc_profile::PROFILE_REGISTRY_FILE);
        if !std::fs::symlink_metadata(&catalog).is_ok_and(|m| m.is_file()) {
            continue;
        }
        let (Some(app), Some(target)) = (app_root.to_str(), canonical.to_str()) else {
            return Err(storage(
                "overlap",
                "a path that isn't text below an app root",
            ));
        };
        let records = read_records(&catalog)
            .ok_or_else(|| storage("unreadable", fc_profile::PROFILE_REGISTRY_FILE))?;
        // Every other record's directory, resolved; those naming this very
        // directory are the profile's own.
        let others: Vec<String> = records
            .iter()
            .filter_map(|dir| {
                let resolved = std::fs::canonicalize(dir)
                    .or_else(|_| std::path::absolute(dir))
                    .ok()?;
                (resolved != canonical).then(|| resolved.to_string_lossy().into_owned())
            })
            .collect();
        let shares_app_root = app_root == canonical;
        if fc_profile::delete::overlaps(style, app, target, shares_app_root, &others) {
            return Ok(Some(format!(
                "the profile's directory overlaps another profile's or the app's own data ({})",
                if shares_app_root {
                    "the app root"
                } else {
                    "below an app root"
                }
            )));
        }
    }
    Ok(None)
}

/// The directories a catalog's records name, or `None` for a catalog that
/// can't be read or isn't one.
fn read_records(catalog: &Path) -> Option<Vec<String>> {
    let file = std::fs::File::open(catalog).ok()?;
    let mut text = String::new();
    file.take(super::store::MAX_FILE + 1)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() as u64 > super::store::MAX_FILE {
        return None;
    }
    let parsed = fc_json::parse(&text).ok()?;
    let records = parsed.get("profiles")?.as_array()?;
    Some(
        records
            .iter()
            .filter_map(|record| record.get("dir").and_then(fc_json::JsValue::as_str))
            .map(str::to_owned)
            .collect(),
    )
}

fn migrate(profile_dir: &Path, lock_dir: &Path, dev: bool) -> Exit {
    let canonical = match std::fs::canonicalize(profile_dir) {
        Ok(path) => path,
        // No profile directory holds no journal.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return say(Outcome::Nothing),
        Err(e) => return storage("io", &e.kind().to_string()),
    };
    if !canonical.is_dir() {
        return storage("io", "the profile's directory isn't a directory");
    }
    match overlap(&canonical) {
        Ok(None) => {}
        Ok(Some(why)) => return storage("overlap", &why),
        Err(exit) => return exit,
    }
    // The move's exclusion, in its order.
    let mut gates = match take(Which::Profile, &canonical, lock_dir) {
        Ok(gate) => vec![gate],
        Err(exit) => return exit,
    };
    let lock = match take_profile_lock(&canonical, dev) {
        Ok(lock) => lock,
        Err(exit) => return exit,
    };
    let freedom = canonical.join(layout::FREEDOM_DIR);
    for (which, dir) in [
        (Which::Core, canonical.join("identity")),
        (Which::Core, freedom.join("identity")),
        (
            Which::Ipfs,
            canonical.join("ipfs-data").join("freedom-ipfs"),
        ),
        (Which::Ipfs, freedom.join("ipfs-data").join("freedom-ipfs")),
    ] {
        match take(which, &dir, lock_dir) {
            Ok(gate) => gates.push(gate),
            Err(exit) => return exit,
        }
    }
    let grant = Grant::locking()
        .refer()
        .read_write(&canonical)
        .descriptors(gates.iter().flat_map(Gate::descriptors));
    if let Err(exit) = confine::confine(grant) {
        return exit;
    }
    if let Err(e) = lock.keep() {
        return match e {
            LockError::Held => say(Outcome::Busy),
            LockError::Io(e) => storage("io", &e.kind().to_string()),
        };
    }
    crate::testhooks::profile_hold();
    step("after-exclusion");
    let identity = gates.first().and_then(|gate| gate.identity);
    let result = recover(&canonical, identity, &|| lock.held());
    let released = lock.release();
    drop(gates);
    match result {
        Ok(outcome) => {
            if !released && outcome != Outcome::LockLost {
                log::warn(
                    "the profile's lock was taken over after the recovery",
                    serde_json::json!({}),
                );
            }
            say(outcome)
        }
        Err(e) => storage("io", &e.kind().to_string()),
    }
}

/// What is at `name` in `dir`.
fn found(dir: &Dir, name: &str) -> std::io::Result<Found> {
    Ok(match dir.kind(OsStr::new(name))? {
        Kind::Missing => Found::Missing,
        Kind::File => Found::File,
        Kind::Dir => Found::Dir,
        Kind::Other => Found::Other,
    })
}

/// The journal's text, or `None` for one that can't be read as text within
/// the bound.
fn read_journal(freedom: &Dir) -> std::io::Result<Option<Option<String>>> {
    let file = match freedom.open_regular(OsStr::new(layout::MOVE_JOURNAL), false)? {
        Regular::Missing => return Ok(None),
        Regular::Other => return Ok(Some(None)),
        Regular::File(file) => file,
    };
    let mut bytes = Vec::new();
    file.take(layout::MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > layout::MAX_JOURNAL_BYTES {
        return Ok(Some(None));
    }
    Ok(Some(String::from_utf8(bytes).ok()))
}

fn unsettled(name: &str, why: Unsettled) -> Outcome {
    log::error(
        "the move can't be settled without a guess; nothing was changed",
        serde_json::json!({ "entry": name, "why": format!("{why:?}") }),
    );
    Outcome::Corrupt
}

/// Lost: nothing more may change.
fn lost() -> Outcome {
    log::error(
        "the profile's lock was taken over; the journal stays for the next start",
        serde_json::json!({}),
    );
    Outcome::LockLost
}

fn recover(
    canonical: &Path,
    identity: Option<fc_service::gate::DirIdentity>,
    held: &dyn Fn() -> bool,
) -> std::io::Result<Outcome> {
    let root = Dir::open_root(canonical, Resolve::Canonical(identity))?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    let Some(freedom) = root.child(OsStr::new(layout::FREEDOM_DIR), false)? else {
        return Ok(Outcome::Nothing);
    };
    let entries = match read_journal(&freedom)? {
        None => return Ok(Outcome::Nothing),
        Some(text) => match text.as_deref().and_then(layout::parse_journal) {
            Some(entries) => entries,
            None => {
                log::error(
                    "the move's journal can't be read: the profile stays closed",
                    serde_json::json!({}),
                );
                return Ok(Outcome::Corrupt);
            }
        },
    };
    let marked = match found(&freedom, layout::LAYOUT_MARKER)? {
        Found::File => true,
        Found::Missing => false,
        Found::Dir | Found::Other => {
            log::error(
                "the move's marker isn't a file: the profile stays closed",
                serde_json::json!({}),
            );
            return Ok(Outcome::Corrupt);
        }
    };
    let mut states = Vec::with_capacity(entries.len());
    for name in &entries {
        let moving = format!("{name}{}", layout::MOVING_SUFFIX);
        states.push(EntryState {
            at_root: found(&root, name)?,
            moved: found(&freedom, name)?,
            moving: found(&freedom, &moving)?,
        });
    }
    let journal = OsStr::new(layout::MOVE_JOURNAL);

    if marked {
        for (name, state) in entries.iter().zip(&states) {
            if let Err(why) = layout::roll_forward(*state) {
                return Ok(unsettled(name, why));
            }
        }
        step("before-journal-removed");
        if !held() {
            return Ok(lost());
        }
        freedom.unlink(journal)?;
        freedom.sync()?;
        return Ok(Outcome::Migrated);
    }

    let mut plans = Vec::with_capacity(entries.len());
    for (name, state) in entries.iter().zip(&states) {
        match layout::rollback(name, *state) {
            Ok(steps) => plans.push((name, steps)),
            Err(why) => return Ok(unsettled(name, why)),
        }
    }
    for (name, steps) in plans.iter().rev() {
        let name = OsStr::new(name.as_str());
        if steps.remove_moving {
            if !held() {
                return Ok(lost());
            }
            let mut moving = name.to_owned();
            moving.push(layout::MOVING_SUFFIX);
            freedom.remove_tree(&moving)?;
            step("mid-recovery");
        }
        if steps.remove_placeholder {
            if !held() {
                return Ok(lost());
            }
            root.unlink(name)?;
            step("mid-recovery");
        }
        if steps.rename_back {
            if !held() {
                return Ok(lost());
            }
            rename_back(&freedom, name, &root)?;
            step("mid-recovery");
        }
    }
    root.sync()?;
    freedom.sync()?;
    step("before-journal-removed");
    if !held() {
        return Ok(lost());
    }
    freedom.unlink(journal)?;
    freedom.sync()?;
    drop(freedom);
    if held() && root.remove_empty(OsStr::new(layout::FREEDOM_DIR))? {
        root.sync()?;
    }
    Ok(Outcome::RolledBack)
}

/// `freedom/<name>` back to the root. On Windows, a rename refused while an
/// indexer or another handle holds the entry is tried again, as
/// `profile-catalog.js` tries its fence: 10 times, 100 ms apart.
fn rename_back(freedom: &Dir, name: &OsStr, root: &Dir) -> std::io::Result<()> {
    let mut tries = 0;
    loop {
        match freedom.rename_into(name, root, name) {
            Ok(()) => return Ok(()),
            Err(e) if cfg!(windows) && tries < 10 && held_by_another(&e) => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e),
        }
    }
}

/// `EPERM`, `EACCES` or `EBUSY` as Windows reports them: access denied, or a
/// sharing or lock violation.
fn held_by_another(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ResourceBusy
    ) || matches!(error.raw_os_error(), Some(32 | 33))
}
