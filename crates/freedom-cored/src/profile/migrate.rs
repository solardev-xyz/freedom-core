//! `profile migrate` (design 0013, 5.4b, "The move" and "Readers, and the
//! downgrade"; steps PRF-3 and PRF-9b): the move of a profile's Freedom
//! data into `<profile>/freedom/`, and its recovery. Main runs it before
//! `hold-profile` and before it takes its own lock: with `--finish-only`
//! when `profile open` reports `layout: "pending"`, and without it when
//! `profile open` reports `"root"` and the profile is idle.
//!
//! ```text
//! freedom-cored profile migrate --profile-dir <dir> --lock-dir <dir> [--dev] [--finish-only]
//! ```
//!
//! 1. **Where it may act:** by a delete's rules (`fc_profile::delete`'s
//!    `overlaps`, `fold` and `home_slot`, against every catalog at or above
//!    the profile's directory), the directory is no shared entry of the app
//!    root (`Profiles`, `R`, `locks`, …, or inside one but the profiles
//!    root), and is neither at, above nor inside another record's
//!    directory; the packaged default profile's, the app root itself, holds
//!    no other record among its entries but the shared ones; and its record
//!    shares its Radicle slot with no other. Refused with `overlap` (74)
//!    before anything is taken. Below it, it acts on `fc_profile::layout`'s
//!    list alone, which holds no shared entry of the app root.
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
//! 3. **A starting run's preconditions** (without `--finish-only`;
//!    `preconditions.rs`), before confinement: a journal or the marker in
//!    `freedom/` is settled below as `--finish-only` settles it (the
//!    marker alone: `nothing`). Otherwise `fc_profile::layout::plan_start`
//!    decides from what the core observed (a node identity journal in
//!    `identity/`, a `freedom/` the move didn't make, a mount point among
//!    the entries), then a link among the entries whose target is
//!    relative or inside the profile, and then the nodes' OS locks are
//!    tried (arti's, Myotis's). With `freedom/` already on another mount,
//!    every entry is surveyed for its copy and the room for them checked
//!    (`copy.rs`). Any of them ends the run with `deferred` (0), nothing
//!    changed. A `freedom` that is anything but a real directory defers
//!    before the new paths' gates are named. Then the lock is refreshed
//!    once from this thread (`Lock::touch`), so the refresher's first
//!    period starts fresh however long the checks took; taken over
//!    meanwhile, `lock_lost` with nothing changed.
//! 4. **Confinement** (`confine.rs`): read-write on the profile's
//!    directory, renames across directories, the gates' descriptors; no
//!    network, no process. Then the lock's refresher starts.
//! 5. **A starting move,** on the entries present, in the list's order:
//!    - `freedom/` made; the journal (`freedom/.move.json`, version 2,
//!      `fc_profile::layout::Journal`) written to a temporary name, synced
//!      and renamed into place, the directory flushed;
//!    - each entry renamed into `freedom/` (a symlink as the link). On
//!      Windows a rename refused while another handle holds the entry is
//!      tried again, 30 times, 100 ms apart (MD3);
//!    - **an entry on another device** than `freedom/` (the rename's
//!      `EXDEV`, Windows's `ERROR_NOT_SAME_DEVICE`; PRF-9c) is copied
//!      instead: surveyed, the copies' total checked against the 2 GiB cap
//!      and the room for it checked (`copy.rs`), named in
//!      the journal's `copied` (written again, whole and durably), copied
//!      to `freedom/<name>.moving` (fc-store's `copy_tree`: files synced,
//!      directories flushed, symlinks as links, never past the profile's
//!      mount, the lock checked after each entry made), and that renamed to
//!      its name. Its source stays at the root;
//!    - both directories flushed, then the marker (`freedom/layout.json`)
//!      written and flushed;
//!    - cleanup: each copied entry's source removed from the root, never
//!      past the profile's mount (a mount point found inside it stops the
//!      removal, which would empty the mounted volume), the lock checked
//!      after each entry removed. Each goes only while
//!      `fc_profile::layout::roll_forward` calls for it, from the entry's
//!      state read right before: something of another kind at its name
//!      isn't its source, and stays;
//!    - the placeholder at the root's `identity`, where nothing is
//!      (`needs_placeholder`), and the root flushed;
//!    - the journal removed and `freedom/` flushed: `migrated`.
//!
//!    A new profile, with none of the entries, takes the empty move (MD5):
//!    `freedom/`, the marker and the placeholder, and no journal. A failure
//!    is settled at once as the next run would settle it: before the
//!    marker, rolled back (`rolled_back`); after it, rolled forward
//!    (`migrated`).
//! 6. **Recovery** (`--finish-only`, and a starting run that finds a
//!    journal): the journal (`fc_profile::layout`) is read. None is
//!    `nothing` (with the marker, the placeholder written where nothing is,
//!    MD9). One that can't be read or is out of form is `corrupt` (74):
//!    the core doesn't guess which entries moved.
//! 7. **Every entry's state first,** then the changes, so an entry that
//!    can't be settled without a guess changes nothing (`corrupt`):
//!    - **before the marker** (`freedom/layout.json`), each entry is put
//!      back, in reverse order (`fc_profile::layout::rollback`): a
//!      cross-device copy cut short is removed while its source is at the
//!      root; a copied entry's finished copy (the journal's `copied`) is
//!      removed while its source is at the root; the placeholder file at
//!      `identity` is removed and the directory renamed back; a moved entry
//!      renamed back (on Windows, a rename refused while another handle
//!      holds the entry is tried again, 10 times, 100 ms apart). Then the
//!      directories are flushed, the journal removed, and `freedom/` too if
//!      it is empty and on the profile's own mount (a volume mounted there
//!      before the move stays): `rolled_back`;
//!    - **after the marker,** every entry must be in `freedom/`
//!      (`fc_profile::layout::roll_forward`): a copied entry's source still
//!      at the root, of its copy's kind, is removed, and nothing else at
//!      the root is. Then the placeholder is written at the root's
//!      `identity` if nothing is there (`needs_placeholder`), the root
//!      flushed, and the journal removed: `migrated`;
//!    - **either way,** an entry the journal names but found in no place
//!      (not at the root, in `freedom/` or as its `.moving` copy) is
//!      `corrupt`, with the journal kept: the journal lists the entries
//!      present, and no step of the move removes every copy of one. A
//!      removal, of a copy or of a source, never goes past the mount of the
//!      directory it is in.
//!
//! Before each change the profile lock must still be this run's: lost (the
//! run was frozen past the stale time and another build took it over), it
//! changes nothing more, keeps the journal, and ends with `lock_lost` (74).
//!
//! **stdout:** one word, `migrated`, `nothing`, `rolled_back`, `deferred`,
//! `busy`, `lock_lost` or `corrupt`. Any other failure is a storage one, as
//! the other subcommands': `{ "error": <kind> }`, exit 74 (an unqualified
//! filesystem, a directory that isn't the user's, `overlap`, an I/O error
//! with the journal kept).

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fc_profile::layout::{self, EntryState, Found, Journal, Unsettled};
use fc_service::gate::{Gate, GateError, PROFILE_NAMESPACE};
use fc_store::anchor::{Dir, Kind, Resolve};
use fc_store::fsx::Regular;

use super::confine::{self, Grant};
use super::copy;
use super::lock::{Lock, LockError, Timing};
use super::preconditions::{self, Check};
use super::{Flags, storage};
use crate::exit::Exit;
use crate::log;
use crate::testhooks::profile_migrate_step as step;

/// How long each gate's lock is tried.
const GATE_RETRY: Duration = Duration::from_secs(1);

pub fn run(args: impl Iterator<Item = std::ffi::OsString>) -> Result<Exit, ()> {
    let flags = Flags::parse(
        args,
        &["--profile-dir", "--lock-dir", "--dev", "--finish-only"],
    )?;
    let profile_dir = PathBuf::from(flags.path("--profile-dir")?);
    let lock_dir = PathBuf::from(flags.path("--lock-dir")?);
    let mode = if flags.has("--finish-only") {
        Mode::FinishOnly
    } else {
        Mode::Start
    };
    Ok(migrate(&profile_dir, &lock_dir, flags.has("--dev"), mode))
}

/// Whether a run may start the move, or only settles one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    FinishOnly,
    Start,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Migrated,
    Nothing,
    RolledBack,
    Deferred,
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
            Outcome::Deferred => "deferred",
            Outcome::Busy => "busy",
            Outcome::LockLost => "lock_lost",
            Outcome::Corrupt => "corrupt",
        }
    }

    fn exit(self) -> Exit {
        match self {
            Outcome::Migrated | Outcome::Nothing | Outcome::RolledBack | Outcome::Deferred => {
                Exit::Ok
            }
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
        Err(LockError::Io(e)) => Err(storage("io", &e.to_string())),
        Err(LockError::Lost) => Err(say(lost())),
    }
}

/// Why the profile's directory isn't one the move may act on, by a
/// delete's rules against each catalog at or above it:
/// - **overlap** (`fc_profile::delete::overlaps`): the directory is the
///   profiles root or another shared entry of the app root (or inside one
///   but the profiles root), or at, above or inside another record's
///   directory; for the packaged default profile, the app root, another
///   record among its entries but the shared ones;
/// - **a shared slot** (`home_slot`): the profile's record has a Radicle
///   slot another record has too.
///
/// Names compare through `fc_profile::delete::fold`, so a record naming
/// this directory in another spelling or case is the profile's own. A
/// directory under no catalog is checked against none, and only a missing
/// catalog is none. `Err` (`unreadable`) for a catalog that can't be read,
/// and for anything but a regular file at a catalog's name (a symlink, a
/// directory, a name that can't be looked at): nothing proves the
/// directory overlaps nothing.
fn overlap(canonical: &Path) -> Result<Option<String>, Exit> {
    use fc_profile::delete::{fold, home_slot};
    let style = fc_profile::Style::native();
    for app_root in canonical.ancestors() {
        let catalog = app_root.join(fc_profile::PROFILE_REGISTRY_FILE);
        match std::fs::symlink_metadata(&catalog) {
            Ok(meta) if meta.is_file() => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Ok(_) | Err(_) => {
                return Err(storage("unreadable", fc_profile::PROFILE_REGISTRY_FILE));
            }
        }
        let (Some(app), Some(target)) = (app_root.to_str(), canonical.to_str()) else {
            return Err(storage(
                "overlap",
                "a path that isn't text below an app root",
            ));
        };
        let records = read_records(&catalog)
            .ok_or_else(|| storage("unreadable", fc_profile::PROFILE_REGISTRY_FILE))?;
        let target_key = fold(target);
        // Each record's directory, resolved, and whether it is this one.
        let mut own_slots = Vec::new();
        let mut others = Vec::new();
        let mut other_slots = Vec::new();
        for record in &records {
            let resolved = record
                .get("dir")
                .and_then(fc_json::JsValue::as_str)
                .and_then(|dir| {
                    std::fs::canonicalize(dir)
                        .or_else(|_| std::path::absolute(dir))
                        .ok()
                })
                .map(|path| path.to_string_lossy().into_owned());
            let slot = home_slot(record);
            match resolved {
                Some(dir) if fold(&dir) == target_key => own_slots.extend(slot),
                Some(dir) => {
                    others.push(dir);
                    other_slots.extend(slot);
                }
                None => other_slots.extend(slot),
            }
        }
        // Two records at this one directory: another record's directory.
        if own_slots.len() > 1 || records_at(&records, &target_key) > 1 {
            return Ok(Some("another record names this directory too".to_owned()));
        }
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
        if own_slots.iter().any(|slot| other_slots.contains(slot)) {
            return Ok(Some(
                "the profile's Radicle slot is another profile's too".to_owned(),
            ));
        }
    }
    Ok(None)
}

/// How many records name the directory whose folded path is `key`.
fn records_at(records: &[fc_json::JsValue], key: &str) -> usize {
    records
        .iter()
        .filter_map(|record| record.get("dir").and_then(fc_json::JsValue::as_str))
        .filter_map(|dir| {
            std::fs::canonicalize(dir)
                .or_else(|_| std::path::absolute(dir))
                .ok()
        })
        .filter(|path| fc_profile::delete::fold(&path.to_string_lossy()) == key)
        .count()
}

/// A catalog's records, or `None` for a catalog that can't be read or
/// isn't one.
fn read_records(catalog: &Path) -> Option<Vec<fc_json::JsValue>> {
    let file = std::fs::File::open(catalog).ok()?;
    let mut text = String::new();
    file.take(super::store::MAX_FILE + 1)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() as u64 > super::store::MAX_FILE {
        return None;
    }
    let parsed = fc_json::parse(&text).ok()?;
    Some(parsed.get("profiles")?.as_array()?.to_vec())
}

fn migrate(profile_dir: &Path, lock_dir: &Path, dev: bool, mode: Mode) -> Exit {
    let canonical = match std::fs::canonicalize(profile_dir) {
        Ok(path) => path,
        // No profile directory holds no journal, and nothing to move: its
        // first open makes it, and moves it at the next start.
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
    // A starting run with anything but a real directory at `freedom` (a
    // file, a symlink or a junction, looked at itself): the move doesn't
    // start (`plan_start`'s `FreedomNotDir`), so it is deferred here, under
    // the profile gate and lock, before a gate is named below it: none is
    // taken, and no directory a link names is touched.
    if mode == Mode::Start
        && std::fs::symlink_metadata(&freedom)
            .is_ok_and(|meta| !meta.is_dir() || preconditions::is_link(&meta))
    {
        return defer(
            lock,
            gates,
            fc_profile::layout::Deferral::FreedomNotDir.word(),
            "",
        );
    }
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
    let identity = gates.first().and_then(|gate| gate.identity);
    // A starting run's preconditions, observed before confinement.
    let start = match mode {
        Mode::FinishOnly => None,
        Mode::Start => match open_root(&canonical, identity)
            .and_then(|root| preconditions::check(&root, &canonical))
        {
            Ok(Check::Settle) => None,
            Ok(Check::Start(entries)) => Some(entries),
            Ok(Check::Defer { why, detail }) => return defer(lock, gates, why, &detail),
            Err(e) => return storage("io", &e.kind().to_string()),
        },
    };
    // The lock refreshed once here, after the preconditions and before
    // confinement: the refresher can't start before confinement (it is a
    // thread), so its first period then starts from a fresh mtime, however
    // long the preconditions took. The refresh is bound to the directory
    // this run made (`Lock::touch`): taken over meanwhile (an older build,
    // past the stale time), it is found before anything changes, and the
    // run ends `lock_lost` with nothing changed.
    if mode == Mode::Start && !lock.touch() {
        lock.release();
        drop(gates);
        return say(lost());
    }
    let grant = Grant::locking()
        .refer()
        .symlinks()
        .read_write(&canonical)
        .descriptors(gates.iter().flat_map(Gate::descriptors))
        .descriptors(lock.descriptor());
    if let Err(exit) = confine::confine(grant) {
        return exit;
    }
    step("before-keep");
    if let Err(e) = lock.keep() {
        return match e {
            LockError::Held => say(Outcome::Busy),
            LockError::Io(e) => storage("io", &e.kind().to_string()),
            // Taken over since it was taken: nothing was changed.
            LockError::Lost => say(lost()),
        };
    }
    crate::testhooks::profile_hold();
    step("after-exclusion");
    let held = || lock.held();
    let result = match start {
        None => recover(&canonical, identity, &held),
        Some(entries) => start_move(&canonical, identity, &entries, &held),
    };
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

/// A starting run that doesn't start: logged, its exclusion let go,
/// `deferred`.
fn defer(lock: Lock, gates: Vec<Gate>, why: &str, detail: &str) -> Exit {
    log::warn(
        "the move is deferred to the next start; nothing was changed",
        serde_json::json!({ "why": why, "detail": detail }),
    );
    lock.release();
    drop(gates);
    say(Outcome::Deferred)
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
    let root = open_root(canonical, identity)?;
    let Some(freedom) = root.child(OsStr::new(layout::FREEDOM_DIR), false)? else {
        return Ok(Outcome::Nothing);
    };
    let journal: Journal = match read_journal(&freedom)? {
        None => return settled(&root, &freedom, held),
        Some(text) => match text.as_deref().and_then(layout::parse_journal) {
            Some(journal) => journal,
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
    let entries = journal.entries();
    let mut states = Vec::with_capacity(entries.len());
    for name in entries {
        states.push(entry_state(&root, &freedom, name)?);
    }
    let journal_name = OsStr::new(layout::MOVE_JOURNAL);

    if marked {
        let mut sources = Vec::new();
        for (name, state) in entries.iter().zip(&states) {
            match layout::roll_forward(journal.is_copied(name), *state) {
                Ok(forward) if forward.remove_source => sources.push(*name),
                Ok(_) => {}
                Err(why) => return Ok(unsettled(name, why)),
            }
        }
        for name in sources {
            if !held() {
                return Ok(lost());
            }
            match remove_source(&root, &freedom, name, held, None) {
                Ok(()) => {}
                Err(Halt::Lost) => return Ok(lost()),
                Err(Halt::Io(e)) => return Err(e),
            }
            step("mid-recovery");
        }
        if layout::needs_placeholder(found(&root, layout::PLACEHOLDER)?) {
            if !held() {
                return Ok(lost());
            }
            write_placeholder(&root)?;
            step("mid-recovery");
        }
        root.sync()?;
        step("before-journal-removed");
        if !held() {
            return Ok(lost());
        }
        freedom.unlink(journal_name)?;
        freedom.sync()?;
        return Ok(Outcome::Migrated);
    }

    let mut plans = Vec::with_capacity(entries.len());
    for (name, state) in entries.iter().zip(&states) {
        match layout::rollback(name, journal.is_copied(name), *state) {
            Ok(steps) => plans.push((name, steps)),
            Err(why) => return Ok(unsettled(name, why)),
        }
    }
    for (name, steps) in plans.iter().rev() {
        let name = OsStr::new(name);
        if steps.remove_moving {
            if !held() {
                return Ok(lost());
            }
            let mut moving = name.to_owned();
            moving.push(layout::MOVING_SUFFIX);
            match remove_within(&freedom, &moving, held, None) {
                Ok(()) => {}
                Err(Halt::Lost) => return Ok(lost()),
                Err(Halt::Io(e)) => return Err(e),
            }
            step("mid-recovery");
        }
        if steps.remove_moved {
            if !held() {
                return Ok(lost());
            }
            match remove_within(&freedom, name, held, None) {
                Ok(()) => {}
                Err(Halt::Lost) => return Ok(lost()),
                Err(Halt::Io(e)) => return Err(e),
            }
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
            match rename_back(&freedom, name, &root, held) {
                Ok(()) => {}
                Err(Halt::Lost) => return Ok(lost()),
                Err(Halt::Io(e)) => return Err(e),
            }
            step("mid-recovery");
        }
    }
    root.sync()?;
    freedom.sync()?;
    step("before-journal-removed");
    if !held() {
        return Ok(lost());
    }
    freedom.unlink(journal_name)?;
    freedom.sync()?;
    drop(freedom);
    if held() && remove_freedom_if_empty(&root)? {
        root.sync()?;
    }
    Ok(Outcome::RolledBack)
}

/// One entry's state: at the root, in `freedom/`, and as its `.moving`
/// copy.
fn entry_state(root: &Dir, freedom: &Dir, name: &str) -> std::io::Result<EntryState> {
    let moving = format!("{name}{}", layout::MOVING_SUFFIX);
    Ok(EntryState {
        at_root: found(root, name)?,
        moved: found(freedom, name)?,
        moving: found(freedom, &moving)?,
    })
}

/// A copied entry's source removed from the root after the marker, only
/// while `fc_profile::layout::roll_forward` calls for it, from the entry's
/// state read right before the removal: what is at the root must be of its
/// copy's kind. Anything else there (a file where a copied directory was,
/// a directory where a copied file was) isn't its source, and stays. An
/// entry `roll_forward` can't settle is an error, which a starting run
/// settles by recovery (`corrupt`, the journal kept).
fn remove_source(
    root: &Dir,
    freedom: &Dir,
    name: &'static str,
    held: &dyn Fn() -> bool,
    at: Option<&str>,
) -> Result<(), Halt> {
    match layout::roll_forward(true, entry_state(root, freedom, name)?) {
        Ok(forward) if forward.remove_source => remove_within(root, OsStr::new(name), held, at),
        Ok(_) => {
            log::warn(
                "a copied entry's name at the root holds another kind of entry: it isn't the source, and stays",
                serde_json::json!({ "entry": name }),
            );
            Ok(())
        }
        Err(why) => Err(Halt::Io(std::io::Error::other(format!(
            "a copied entry can't be settled after the marker: {why:?}"
        )))),
    }
}

/// `freedom/` removed if it is empty and on the profile's own mount. One
/// on another mount is a volume mounted there before the move, where the
/// move found it: it stays (and can't be removed anyway).
fn remove_freedom_if_empty(root: &Dir) -> std::io::Result<bool> {
    let name = OsStr::new(layout::FREEDOM_DIR);
    match root.child(name, false)? {
        Some(freedom) if freedom.mount()?.same(root.mount()?) => {
            drop(freedom);
            root.remove_empty(name)
        }
        _ => Ok(false),
    }
}

/// `name` in `dir` and everything under it removed, never past `dir`'s
/// mount (fc-store's `remove_tree_within`): a mount point at `name` or
/// inside it stops the removal with an error, since removing through it
/// would empty the mounted volume. The lock is checked after each entry
/// removed, and the step `at`, if any, fired.
fn remove_within(
    dir: &Dir,
    name: &OsStr,
    held: &dyn Fn() -> bool,
    at: Option<&str>,
) -> Result<(), Halt> {
    let mut lost = false;
    let removed = dir.remove_tree_within(name, &mut || {
        if !held() {
            lost = true;
            return Err(std::io::Error::other("the profile's lock was taken over"));
        }
        if let Some(at) = at {
            step(at);
        }
        Ok(())
    });
    if lost {
        return Err(Halt::Lost);
    }
    removed.map(|_| ()).map_err(Halt::Io)
}

/// The profile's directory, opened from its gate's canonical path: the
/// very directory the gate was taken for (on Unix, by its device and
/// inode).
fn open_root(
    canonical: &Path,
    identity: Option<fc_service::gate::DirIdentity>,
) -> std::io::Result<Dir> {
    Dir::open_root(
        canonical,
        Resolve::Canonical(identity.map(crate::journal::anchored)),
    )?
    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
}

/// No journal: with the marker, the move is done, and the placeholder is
/// written if nothing is at the root's `identity` (MD9; a new profile's
/// empty move cut short between its marker and its placeholder leaves
/// none). Either way, `nothing`.
fn settled(root: &Dir, freedom: &Dir, held: &dyn Fn() -> bool) -> std::io::Result<Outcome> {
    if found(freedom, layout::LAYOUT_MARKER)? == Found::File
        && layout::needs_placeholder(found(root, layout::PLACEHOLDER)?)
    {
        if !held() {
            return Ok(lost());
        }
        write_placeholder(root)?;
        root.sync()?;
    }
    Ok(Outcome::Nothing)
}

/// How many times a starting move tries an entry's rename on Windows while
/// another handle holds it, 100 ms apart (MD3).
const START_RENAME_TRIES: u32 = 30;

/// The journal's temporary name: it is renamed into place whole, so a
/// crash never leaves a journal cut short (one that doesn't parse keeps the
/// profile closed).
const JOURNAL_TEMP: &str = ".move.json.freedom-new";

/// Why a starting move stops before its end.
enum Halt {
    /// The lock was taken over: nothing more may change.
    Lost,
    Io(std::io::Error),
}

impl From<std::io::Error> for Halt {
    fn from(error: std::io::Error) -> Halt {
        Halt::Io(error)
    }
}

/// The starting move (0013, "The move", 3–8) on `entries`, the ones
/// present, in the list's order, as the preconditions found them. A
/// failure is settled at once by [`recover`], as the next run would settle
/// it: rolled back before the marker, rolled forward after it.
fn start_move(
    canonical: &Path,
    identity: Option<fc_service::gate::DirIdentity>,
    entries: &[&'static str],
    held: &dyn Fn() -> bool,
) -> std::io::Result<Outcome> {
    match moving(canonical, identity, entries, held) {
        Ok(outcome) => Ok(outcome),
        Err(Halt::Lost) => Ok(lost()),
        Err(Halt::Io(e)) => {
            log::error(
                "the move failed; it is settled as the next start would settle it",
                serde_json::json!({ "error": e.kind().to_string(), "detail": e.to_string() }),
            );
            match recover(canonical, identity, held)? {
                // No journal: before it was in place, or an empty move.
                // With the marker the empty move is done (its placeholder
                // written by the recovery); without it, at most an empty
                // `freedom/` was made.
                Outcome::Nothing => {
                    let root = open_root(canonical, identity)?;
                    let marked = match root.child(OsStr::new(layout::FREEDOM_DIR), false)? {
                        Some(freedom) => found(&freedom, layout::LAYOUT_MARKER)? != Found::Missing,
                        None => false,
                    };
                    if marked {
                        return Ok(Outcome::Migrated);
                    }
                    if held() && remove_freedom_if_empty(&root)? {
                        root.sync()?;
                    }
                    Ok(Outcome::RolledBack)
                }
                outcome => Ok(outcome),
            }
        }
    }
}

fn moving(
    canonical: &Path,
    identity: Option<fc_service::gate::DirIdentity>,
    entries: &[&'static str],
    held: &dyn Fn() -> bool,
) -> Result<Outcome, Halt> {
    let root = open_root(canonical, identity)?;
    if !held() {
        return Err(Halt::Lost);
    }
    // Made `0700` (on Windows, inheriting the profile's ACL), the root
    // flushed.
    let freedom = root
        .child(OsStr::new(layout::FREEDOM_DIR), true)?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    step("after-freedom-dir");
    let mut journal = None;
    // What the copies so far took, by their surveys: all of them stay
    // within the cap.
    let mut copied_size = 0u64;
    if !entries.is_empty() {
        let mut written = Journal::new(entries)
            .ok_or_else(|| std::io::Error::other("an entry the move's list doesn't hold"))?;
        if !held() {
            return Err(Halt::Lost);
        }
        write_journal(&freedom, &written)?;
        step("after-journal");
        for name in entries {
            match rename_out(&root, OsStr::new(name), &freedom, held) {
                Ok(()) => {}
                // `freedom/` on another volume: the entry is copied.
                Err(Halt::Io(e)) if copy::crosses_devices(&e) => {
                    copy_entry(&root, &freedom, name, &mut written, &mut copied_size, held)?;
                }
                Err(halt) => return Err(halt),
            }
            step("mid-move");
        }
        root.sync()?;
        freedom.sync()?;
        step("after-renames");
        journal = Some(written);
    }
    if !held() {
        return Err(Halt::Lost);
    }
    write_marker(&freedom)?;
    step("after-marker");
    // Cleanup: each copied entry's source removed from the root, while it
    // is still of its copy's kind.
    let copied = journal.as_ref().map_or(&[][..], Journal::copied);
    for name in copied {
        if !held() {
            return Err(Halt::Lost);
        }
        remove_source(&root, &freedom, name, held, Some("mid-cleanup"))?;
    }
    if !copied.is_empty() {
        root.sync()?;
        step("after-cleanup");
    }
    if layout::needs_placeholder(found(&root, layout::PLACEHOLDER)?) {
        if !held() {
            return Err(Halt::Lost);
        }
        write_placeholder(&root)?;
        root.sync()?;
    }
    step("after-placeholder");
    if !entries.is_empty() {
        step("before-journal-removed");
        if !held() {
            return Err(Halt::Lost);
        }
        freedom.unlink(OsStr::new(layout::MOVE_JOURNAL))?;
        freedom.sync()?;
    }
    Ok(Outcome::Migrated)
}

/// The journal, written whole: to its temporary name (one a crash left
/// is replaced), synced, renamed into place, the directory flushed.
fn write_journal(freedom: &Dir, journal: &Journal) -> std::io::Result<()> {
    let temp = OsStr::new(JOURNAL_TEMP);
    freedom.unlink(temp)?;
    let written = freedom.create_new(temp).and_then(|mut file| {
        file.write_all(journal.text().as_bytes())?;
        file.sync_all()
    });
    if let Err(e) = written {
        let _ = freedom.unlink(temp);
        return Err(e);
    }
    freedom.rename(temp, OsStr::new(layout::MOVE_JOURNAL))?;
    freedom.sync()
}

/// The marker, `{ version: 1, moved_at, by }`, made new, synced and its
/// directory flushed. Its presence is what counts: one cut short by a
/// crash is still the marker, and every entry is in `freedom/` by then.
fn write_marker(freedom: &Dir) -> std::io::Result<()> {
    let text = format!(
        "{{\"version\":1,\"moved_at\":\"{}\",\"by\":\"freedom-cored {}\"}}\n",
        super::now_iso(),
        env!("CARGO_PKG_VERSION")
    );
    let mut file = freedom.create_new(OsStr::new(layout::LAYOUT_MARKER))?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    freedom.sync()
}

/// The root's `name` into `freedom/`, a symlink as the link
/// ([`rename_retried`]). One `FREEDOM_CORED_TEST_PROFILE_MIGRATE_EXDEV`
/// lists fails as on another device, untried.
fn rename_out(
    root: &Dir,
    name: &OsStr,
    freedom: &Dir,
    held: &dyn Fn() -> bool,
) -> Result<(), Halt> {
    if name
        .to_str()
        .is_some_and(crate::testhooks::profile_migrate_exdev)
    {
        if !held() {
            return Err(Halt::Lost);
        }
        return Err(Halt::Io(std::io::Error::from(
            std::io::ErrorKind::CrossesDevices,
        )));
    }
    rename_retried(root, name, freedom, name, held)
}

/// An entry on another device than `freedom/` (0013, "The move", 4;
/// PRF-9c), copied in place of its rename:
/// 1. surveyed, the copies' total with it checked against the cap, and the
///    room for it checked on `freedom/`'s volume (`copy.rs`): any of them
///    failing is a failure of the move, which rolls it back;
/// 2. named in the journal's `copied`, the journal written again whole and
///    durably before the copy begins (MG1);
/// 3. copied to `freedom/<name>.moving` (fc-store's `copy_tree`), the lock
///    checked after each entry made, and the cap enforced on the bytes it
///    reads: what the copies so far left of it is the copy's budget, so a
///    file grown or added since the survey can't take it past;
/// 4. renamed to its name ([`rename_retried`]), and `freedom/` flushed.
///
/// Its source stays at the root until the cleanup after the marker.
fn copy_entry(
    root: &Dir,
    freedom: &Dir,
    name: &'static str,
    journal: &mut Journal,
    copied_size: &mut u64,
    held: &dyn Fn() -> bool,
) -> Result<(), Halt> {
    let space = copy::space(freedom)?;
    let size = match copy::survey(root, name, space.block)? {
        Ok(size) => size,
        Err(unfit) => return Err(Halt::Io(unfit.error())),
    };
    let total = copied_size.saturating_add(size);
    if let Err(unfit) = copy::within_cap(total).and_then(|()| copy::room(space, size)) {
        return Err(Halt::Io(unfit.error()));
    }
    log::info(
        "an entry is on another device than freedom/: it is copied",
        serde_json::json!({ "entry": name, "bytes": size }),
    );
    let next = journal
        .with_copied(name)
        .ok_or_else(|| std::io::Error::other("an entry copied twice"))?;
    if !held() {
        return Err(Halt::Lost);
    }
    write_journal(freedom, &next)?;
    *journal = next;
    step("before-copy");
    let moving = format!("{name}{}", layout::MOVING_SUFFIX);
    let mut lost = false;
    let mut made = 0u64;
    // The copy enforces the cap on what it reads, files grown or added since
    // the survey included.
    let budget = copy::COPY_CAP.saturating_sub(*copied_size);
    let copied = root.copy_tree(
        OsStr::new(name),
        freedom,
        OsStr::new(&moving),
        budget,
        &mut || {
            if !held() {
                lost = true;
                return Err(std::io::Error::other("the profile's lock was taken over"));
            }
            made += 1;
            if crate::testhooks::profile_migrate_full(made) {
                return Err(std::io::Error::from(std::io::ErrorKind::StorageFull));
            }
            step("mid-copy");
            Ok(())
        },
    );
    if lost {
        return Err(Halt::Lost);
    }
    copied?;
    rename_retried(
        freedom,
        OsStr::new(&moving),
        freedom,
        OsStr::new(name),
        held,
    )?;
    freedom.sync()?;
    *copied_size = total;
    step("after-copy");
    Ok(())
}

/// `from` in `dir` renamed to `to` in `target`. On Windows, a rename
/// refused while an indexer or another handle holds the entry is tried
/// again, [`START_RENAME_TRIES`] times, 100 ms apart, the lock checked
/// before each try.
fn rename_retried(
    dir: &Dir,
    from: &OsStr,
    target: &Dir,
    to: &OsStr,
    held: &dyn Fn() -> bool,
) -> Result<(), Halt> {
    let mut tries = 0;
    loop {
        if !held() {
            return Err(Halt::Lost);
        }
        match dir.rename_into(from, target, to) {
            Ok(()) => return Ok(()),
            Err(e) if cfg!(windows) && tries < START_RENAME_TRIES && held_by_another(&e) => {
                tries += 1;
                step("rename-retry");
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(Halt::Io(e)),
        }
    }
}

/// The placeholder at the root's `identity`, made new (never over anything
/// there) and synced, its directory flushed by the caller.
fn write_placeholder(root: &Dir) -> std::io::Result<()> {
    let mut file = root.create_new(OsStr::new(layout::PLACEHOLDER))?;
    file.write_all(layout::PLACEHOLDER_TEXT.as_bytes())?;
    file.sync_all()
}

/// `freedom/<name>` back to the root. On Windows, a rename refused while an
/// indexer or another handle holds the entry is tried again, as
/// `profile-catalog.js` tries its fence: 10 times, 100 ms apart, the lock
/// checked before each try.
fn rename_back(
    freedom: &Dir,
    name: &OsStr,
    root: &Dir,
    held: &dyn Fn() -> bool,
) -> Result<(), Halt> {
    let mut tries = 0;
    loop {
        if !held() {
            return Err(Halt::Lost);
        }
        match freedom.rename_into(name, root, name) {
            Ok(()) => return Ok(()),
            Err(e) if cfg!(windows) && tries < 10 && held_by_another(&e) => {
                tries += 1;
                step("rename-back-retry");
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(Halt::Io(e)),
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
