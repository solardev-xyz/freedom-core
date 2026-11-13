//! `profile delete` (design 0013, "Deletion"; the reference's
//! `deleteProfile`, `profile-catalog.js`):
//!
//! ```text
//! freedom-cored profile delete --app-root <dir> --lock-dir <dir> --id <id>
//!     --confirm-display-name <name> [--dev [--checkout-hash <hex8>]]
//! ```
//!
//! In order, all under the catalog's write lock, held for the whole run:
//! 1. **The reference's checks** (`fc_profile::plan_deletion`): the id, the
//!    record, not the last profile, inside the app root, the display name
//!    confirmed. A fresh profile lock is open, as `isProfileLocked` reads it
//!    (`Profile is currently open: …`).
//! 2. **The target's gates, each tried once:** its profile gate, the core's
//!    identity gate (`identity`) and freedom-ipfsd's (`ipfs-data/
//!    freedom-ipfs`) in each Freedom root the profile's layout calls for,
//!    and, for a profile with a slot, freedom-radicled's on its Radicle
//!    home.
//!    Any one held refuses the delete with `lock_held` (exit 75) before
//!    anything changes, whatever the profile lock's age: a live profile
//!    whose main has stalled holds its profile gate. A missing directory is
//!    gated at the path it would have, and nothing is made.
//!    - **The layout** (`fc_profile::layout::Layout`, as `profile open`
//!      reports it and the reader release resolves it) is read once the
//!      profile gate is held: a move, and its recovery, hold that gate for
//!      their whole run, so the layout can't change under the delete. The
//!      root layout's directories are `<data root>/identity` and
//!      `<data root>/ipfs-data/freedom-ipfs`. Once a move has begun (its
//!      journal pending, before its marker or after it, or the marker
//!      there), the same below `<data root>/freedom/` too, the root's
//!      first: the root's stay gated, since a build from before the reader
//!      release, run after a downgrade, starts its services there. The
//!      root's `identity` is then the move's placeholder file, or may be:
//!      gated at its path, and removed as a file.
//! 3. **Confinement** (`confine.rs`): read-write on the app root and, in a
//!    dev build, the `R/` root of the Radicle homes beside it, with the
//!    gates' descriptors; no network, no process. The plan was read before
//!    (the gates it names come first), and the store is opened again under
//!    the same lock, confined.
//! 4. **The layout:** every step from the app root to the profile's data,
//!    and to each gated directory and the Radicle home, a real directory,
//!    or refused before anything changes. Each is reached from the app
//!    root's handle (`anchor::Dir`), as the catalog's store reaches its
//!    files, and every change below is made through those handles
//!    (`remove.rs`).
//! 5. **The forget record** (`forget::record`), before the catalog changes.
//! 6. **The fence and the catalog's change** in one step: each gated
//!    directory moved aside to its tombstone, then the catalog written
//!    without the record.
//! 7. **The removal:** the profile's directory (or, for the packaged
//!    default profile, the app root's entries but the shared ones), sparing
//!    the gated directories' places, then the tombstones, the Radicle home
//!    and its staging siblings, then anything made again empty.
//!
//! A directory on the way that was missing at the layout check may be made
//! by a start meanwhile, before it waits on a gate this process holds: the
//! profile's data and its Radicle home are reached again from the last
//! directory that was there, as the reference reaches them by path, so
//! what was made goes too, under the gates (review of #337).
//!
//! **Result:** `{ catalog, record, forget: [{ policy, item }] }`, with
//! `forget_unknown: true` when the target's secrets file couldn't be read.
//! Refusals as the other catalog subcommands', and `{ "error": "lock_held",
//! "gate": "profile" | "core" | "ipfs" | "radicle" }` or `{ "error":
//! "forget_backlog" }` with exit 75.

use std::path::{Path, PathBuf};

use fc_json::JsValue;
use fc_profile::layout::{Layout, PLACEHOLDER};
use fc_profile::{Deletion, Options, Style};
use fc_service::gate::{GateError, PROFILE_NAMESPACE};

use super::confine::{self, Grant};
use super::forget::{self, Recorded};
use super::lock;
use super::remove::{self, Failure, Gated, Located, Removal, ToFence};
use super::store::{self, DiskStore};
use super::{
    Flags, failed, keep, object, outside, prepare_app_root, print, refused, storage,
    take_catalog_lock,
};
use crate::anchor::{Dir, Resolve};
use crate::exit::Exit;
use crate::log;
use crate::testhooks::profile_delete_step as step;

pub fn run(args: impl Iterator<Item = std::ffi::OsString>) -> Result<Exit, ()> {
    let flags = Flags::parse(
        args,
        &[
            "--app-root",
            "--lock-dir",
            "--id",
            "--confirm-display-name",
            "--dev",
            "--checkout-hash",
        ],
    )?;
    let app_root = flags.path("--app-root")?.to_owned();
    let lock_dir = PathBuf::from(flags.path("--lock-dir")?);
    let id = flags.required("--id")?.to_owned();
    let confirm = flags.required("--confirm-display-name")?.to_owned();
    let opts = flags.options()?;
    Ok(delete(&app_root, &lock_dir, &opts, &id, &confirm))
}

/// The four gates, in the order taken.
#[derive(Clone, Copy)]
enum Which {
    Profile,
    Core,
    Ipfs,
    Radicle,
}

impl Which {
    fn name(self) -> &'static str {
        match self {
            Which::Profile => "profile",
            Which::Core => "core",
            Which::Ipfs => "ipfs",
            Which::Radicle => "radicle",
        }
    }

    fn lock_file_name(self, canonical: &Path) -> String {
        match self {
            Which::Profile => fc_service::gate::lock_file_name(PROFILE_NAMESPACE, canonical),
            Which::Core => crate::gate::lock_file_name(canonical),
            Which::Ipfs => fc_service::gate::lock_file_name("ipfs", canonical),
            Which::Radicle => fc_service::gate::lock_file_name("radicle", canonical),
        }
    }
}

/// Takes `which`'s gate on `dir`, once.
fn take(which: Which, dir: &Path, lock_dir: &Path) -> Result<fc_service::gate::Gate, Exit> {
    let name = |canonical: &Path| which.lock_file_name(canonical);
    let inside = matches!(which, Which::Profile);
    match fc_service::gate::acquire_for_delete(
        dir,
        lock_dir,
        &name,
        inside,
        std::time::Duration::ZERO,
    ) {
        Ok(gate) => Ok(gate),
        Err(GateError::Held) => {
            log::error(
                "a gate of the profile is held: it is in use",
                serde_json::json!({ "gate": which.name() }),
            );
            let _ = print(&object(vec![
                ("error", JsValue::string("lock_held")),
                ("gate", JsValue::string(which.name())),
            ]));
            Err(Exit::LockHeld)
        }
        Err(e) => Err(storage("gate", &e.to_string())),
    }
}

/// The services' gated directories, below a Freedom root: the core's
/// identity directory and freedom-ipfsd's.
const SERVICE_DIRS: [(Which, &[&str], &str); 2] = [
    (Which::Core, &["identity"], "identity data"),
    (Which::Ipfs, &["ipfs-data", "freedom-ipfs"], "IPFS data"),
];

/// A gated directory of the profile's data: the gate its service takes on
/// it, and its place below the data root.
struct GatedDir {
    which: Which,
    names: Vec<&'static str>,
    what: &'static str,
    placeholder: bool,
}

impl GatedDir {
    fn place(&self) -> Gated<'_> {
        Gated {
            names: &self.names,
            what: self.what,
            placeholder: self.placeholder,
        }
    }
}

/// The directories gated for `layout`: [`SERVICE_DIRS`] in each Freedom
/// root it calls for (`Layout::gated_roots`: the root's, and once a move
/// has begun, `freedom/`'s too).
fn gated_dirs(layout: Layout) -> Vec<GatedDir> {
    let mut dirs = Vec::new();
    for root in layout.gated_roots() {
        for (which, names, what) in SERVICE_DIRS {
            dirs.push(GatedDir {
                which,
                names: root.iter().chain(names).copied().collect(),
                what,
                // The move's step 4 leaves a file at the root's
                // `identity`, before the marker, and nothing removes it
                // after: once a move has begun, a regular file there is the
                // placeholder.
                placeholder: layout != Layout::Root && root.is_empty() && names == [PLACEHOLDER],
            });
        }
    }
    dirs
}

/// The gates, in order: the profile gate, then, with the layout read under
/// it, the core's and freedom-ipfsd's in each Freedom root it calls for,
/// then freedom-radicled's. Returns them and the gated directories.
fn gates(
    plan: &Deletion,
    lock_dir: &Path,
) -> Result<(Vec<fc_service::gate::Gate>, Vec<GatedDir>), Exit> {
    let mut held = vec![take(
        Which::Profile,
        Path::new(&plan.profile_dir),
        lock_dir,
    )?];
    let data_root = Path::new(&plan.data_root);
    let gated = gated_dirs(super::layout(data_root));
    for dir in &gated {
        let path = dir
            .names
            .iter()
            .fold(data_root.to_path_buf(), |path, name| path.join(name));
        held.push(take(dir.which, &path, lock_dir)?);
    }
    if let Some(home) = &plan.radicle {
        held.push(take(Which::Radicle, Path::new(&home.dir), lock_dir)?);
    }
    Ok((held, gated))
}

/// A failure as an exit.
fn ended(failure: Failure) -> Exit {
    match failure {
        Failure::Refused(message) => refused(&message),
        Failure::LockLost => storage("lock_lost", "the catalog's write lock was taken over"),
        Failure::Io(e) => storage("io", &e.kind().to_string()),
    }
}

fn delete(app_root: &str, lock_dir: &Path, opts: &Options, id: &str, confirm: &str) -> Exit {
    let root = Path::new(app_root);
    if let Err(exit) = prepare_app_root(root) {
        return exit;
    }
    let lock = match take_catalog_lock(root) {
        Ok(lock) => lock,
        Err(exit) => return exit,
    };
    let held = || lock.held();
    let result = delete_locked(&lock, app_root, lock_dir, opts, id, confirm, &held);
    if result.is_ok() {
        step("before-result");
    }
    let released = lock.release();
    match result {
        Ok(value) => {
            if !released {
                log::warn(
                    "the catalog's write lock was taken over after the change",
                    serde_json::json!({}),
                );
            }
            print(&value)
        }
        Err(exit) => exit,
    }
}

fn open_store<'a>(app_root: &str, held: &'a dyn Fn() -> bool) -> Result<DiskStore<'a>, Exit> {
    DiskStore::open(app_root, held).map_err(|e| storage("io", &e.kind().to_string()))
}

fn delete_locked(
    lock: &lock::Lock,
    app_root: &str,
    lock_dir: &Path,
    opts: &Options,
    id: &str,
    confirm: &str,
    held: &dyn Fn() -> bool,
) -> Result<JsValue, Exit> {
    // The plan, from the catalog read under the lock; its store closed
    // before confinement, which keeps no descriptor it doesn't know.
    let plan = {
        let mut store = open_store(app_root, held)?;
        fc_profile::plan_deletion(&mut store, app_root, opts, id, confirm)
            .map_err(|e| failed(&e))?
    };
    let profile_dir = Path::new(&plan.profile_dir);
    let (stale_ms, _) = fc_profile::lock::profile_lock_timing(opts.dev);
    if lock::is_fresh(
        &profile_dir.join(fc_profile::PROFILE_LOCK_TARGET),
        &profile_dir.join(fc_profile::PROFILE_LOCK_DIR),
        stale_ms,
    ) {
        return Err(refused(&format!(
            "Profile is currently open: {}",
            plan.display_name_text()
        )));
    }
    // Held to the end of the run; dropped after the result is made.
    let (gates, gated) = gates(&plan, lock_dir)?;
    let base = open_home_base(&plan).map_err(ended)?;
    confine::confine(grant(&plan, app_root, &gates, base.as_ref()))?;
    keep(lock)?;
    let mut store = open_store(app_root, held)?;
    let store = &mut store;
    let place = check_layout(&plan, base, &gated).map_err(ended)?;
    step("before-record");
    let recorded = forget::record(store, app_root, &plan, held)?;
    step("after-record");
    commit_and_remove(store, &plan, app_root, place, held).map_err(ended)?;
    Ok(result(&plan, &recorded))
}

/// The delete's grant: the app root, the Radicle homes' root where it lies
/// outside it (a dev build's `R/`, beside the app root), the gates and the
/// homes' base kept, and renames across directories (the fence).
fn grant(
    plan: &Deletion,
    app_root: &str,
    gates: &[fc_service::gate::Gate],
    base: Option<&Dir>,
) -> Grant {
    let root = Path::new(app_root);
    let mut grant = Grant::locking().refer().read_write(root);
    if let Some(home) = &plan.radicle
        && let Some(homes) = outside(root, Path::new(&home.root))
    {
        grant = grant.read_write(&homes);
    }
    grant
        .descriptors(gates.iter().flat_map(fc_service::gate::Gate::descriptors))
        .descriptors(base.and_then(Dir::descriptor))
}

/// A dev build's Radicle home is reached from the directory above the app
/// root, which the grant doesn't cover: its handle is opened before
/// confinement and crosses it. `None` where the base is the app root.
fn open_home_base(plan: &Deletion) -> Result<Option<Dir>, Failure> {
    match &plan.radicle {
        Some(home) if Path::new(&home.base) != Path::new(&plan.app_root) => {
            Dir::open_root(Path::new(&home.base), Resolve::Follow)?
                .map(Some)
                .ok_or_else(|| Failure::Io(std::io::Error::from(std::io::ErrorKind::NotFound)))
        }
        _ => Ok(None),
    }
}

/// What the layout check found, every directory reached through no
/// symlink: the app root's handle; the data root (`None` for the packaged
/// default profile, whose data root is the app root, kept); the gated
/// directories' place; and the Radicle home.
struct Found {
    app: Dir,
    data: Option<Located>,
    place: Option<remove::Place>,
    home: Option<Located>,
}

/// The app root's handle, as the catalog's store opens it.
fn open_app_root(plan: &Deletion) -> Result<Dir, Failure> {
    Dir::open_root(Path::new(&plan.app_root), Resolve::Follow)?
        .ok_or_else(|| Failure::Io(std::io::Error::from(std::io::ErrorKind::NotFound)))
}

/// `base`: the Radicle homes' base where it isn't the app root, opened
/// before confinement ([`open_home_base`]); `gated`: the directories
/// gated, for the profile's layout ([`gated_dirs`]).
fn check_layout(plan: &Deletion, base: Option<Dir>, gated: &[GatedDir]) -> Result<Found, Failure> {
    let app_path = PathBuf::from(&plan.app_root);
    let app = open_app_root(plan)?;
    let data_path = PathBuf::from(&plan.data_root);
    // Every step from the app root down to the profile's data a real
    // directory (beyond the reference).
    let data = if plan.shares_app_root {
        None
    } else {
        Some(remove::locate(
            &app,
            &app_path,
            &data_path,
            &remove::data_layout_refused,
        )?)
    };
    // `radicleHomeFence` and `refuseLinksBelow(radicle.base, radicle.dir)`:
    // the home reached from its app-owned base (the app root, or the
    // directory above it in a dev build) through no link.
    let home = match &plan.radicle {
        Some(home) => {
            let base_path = PathBuf::from(&home.base);
            let base = match base {
                Some(base) => base,
                None if base_path == app_path => app.try_clone()?,
                None => Dir::open_root(&base_path, Resolve::Follow)?.ok_or_else(|| {
                    Failure::Io(std::io::Error::from(std::io::ErrorKind::NotFound))
                })?,
            };
            Some(remove::locate(
                &base,
                &base_path,
                Path::new(&home.dir),
                &remove::radicle_layout_refused,
            )?)
        }
        None => None,
    };
    let mut other_roots = Vec::new();
    if let Some(home) = &home {
        other_roots.push(home.path.clone());
        if let Some(parent) = &home.parent {
            for name in remove::radicle_staging_siblings(parent, &home.name)? {
                other_roots.push(parent.path(&name));
            }
        }
    }
    let data_dir = match &data {
        Some(data) => data.dir.as_ref(),
        None => Some(&app),
    };
    let gated: Vec<Gated<'_>> = gated.iter().map(GatedDir::place).collect();
    let place = remove::gated_place(data_dir, &data_path, &gated, &other_roots)?;
    Ok(Found {
        app,
        data,
        place,
        home,
    })
}

/// A catalog write's failure, for the fence: a lost lock, or the I/O
/// error's kind (a Windows refusal is tried again).
fn commit_failure(error: &fc_profile::StoreError) -> Failure {
    if error.message == store::LOCK_LOST {
        return Failure::LockLost;
    }
    for kind in [
        std::io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::ResourceBusy,
    ] {
        if error.message == kind.to_string() {
            return Failure::Io(std::io::Error::from(kind));
        }
    }
    Failure::Io(std::io::Error::other(error.message.clone()))
}

fn commit_and_remove(
    store: &mut DiskStore<'_>,
    plan: &Deletion,
    app_root: &str,
    layout: Found,
    held: &dyn Fn() -> bool,
) -> Result<(), Failure> {
    let Found {
        app,
        data,
        place,
        home,
    } = layout;
    let mut fences: Vec<ToFence<'_>> = Vec::new();
    if let Some(place) = &place {
        for fence in &place.fences {
            if let Some(parent) = &fence.parent {
                fences.push(ToFence {
                    parent,
                    name: &fence.name,
                    what: fence.what,
                });
            }
        }
    }
    // The home's parent, reached again where it was missing at the layout
    // check (`R/`, or a dev build's `R/<checkout>/`, made since by a start
    // that now waits on the Radicle gate).
    let home_parent = match &home {
        Some(home) => home.parent_now()?,
        None => None,
    };
    if let (Some(home), Some(parent)) = (&home, &home_parent) {
        fences.push(ToFence {
            parent,
            name: &home.name,
            what: "Radicle data",
        });
    }
    let catalog = Style::native().join(&[app_root, fc_profile::PROFILE_REGISTRY_FILE]);
    let text = plan.catalog_text();
    let mut commit = || -> Result<(), Failure> {
        use fc_profile::Store as _;
        store.write(&catalog, &text).map_err(|e| commit_failure(&e))
    };
    let tombstones = remove::fence_and_commit(&fences, lock::now_ms(), held, &mut commit)?;
    step("after-catalog");

    let mut removal = Removal::new(held);
    // The fenced directories inside the profile go with it, and those of
    // the packaged default profile with the app root's entries: their
    // tombstones are beside them, under names no step is.
    match (&data, &place) {
        // The packaged default profile: the app root's entries but the
        // shared ones (`removeDefaultProfileDataFromAppRoot`).
        (None, Some(place)) => {
            let shared = |name: &std::ffi::OsStr| {
                name.to_str()
                    .is_some_and(fc_profile::delete::is_app_root_shared_entry)
            };
            removal.remove_sparing(&app, place, 0, Some(&shared))?;
        }
        (None, None) => {}
        (Some(data), Some(place)) => {
            if let Some(dir) = &data.dir {
                removal.remove_sparing(dir, place, 0, None)?;
            }
            if let Some(parent) = &data.parent {
                removal.remove_empty(parent, &data.name)?;
            }
        }
        // No data root when the layout was checked: anything made there
        // since goes as the reference's ungated removal has it, reached
        // again where a directory above it was missing too.
        (Some(data), None) => {
            if let Some(parent) = data.parent_now()? {
                removal.remove_tree(&parent, &data.name)?;
            }
        }
    }
    if let Some(home) = &home {
        // The fenced home's tombstone (the last fence), or the home by its
        // name: one made since, its parent reached again if it was missing
        // at the fence too.
        let (parent, fenced) = match &home_parent {
            Some(parent) => (
                Some(parent.try_clone()?),
                tombstones.last().cloned().flatten(),
            ),
            None => (home.parent_now()?, None),
        };
        if let Some(parent) = parent {
            removal.remove_tree(&parent, fenced.as_deref().unwrap_or(&home.name))?;
            // Listed again, as `removeRadicleStagingSiblings` does.
            for sibling in remove::radicle_staging_siblings(&parent, &home.name)? {
                removal.remove_tree(&parent, &sibling)?;
            }
        }
    }
    // `removeEmptyRemade`: each gated directory made again since the fence,
    // and what that leaves empty up to the data root (never the packaged
    // app root).
    if let Some(place) = &place {
        for fence in &place.fences {
            match &data {
                None => removal.remove_empty_chain(&app, &fence.names)?,
                Some(Located {
                    parent: Some(parent),
                    name,
                    ..
                }) => {
                    let mut names = vec![name.clone()];
                    names.extend(fence.names.iter().cloned());
                    removal.remove_empty_chain(parent, &names)?;
                }
                Some(_) => {}
            }
        }
    }
    // The Radicle home made again since its fence, empty, its parent
    // reached again if it was missing until now.
    if let Some(home) = &home
        && let Some(parent) = home.parent_now()?
    {
        removal.remove_empty(&parent, &home.name)?;
    }
    Ok(())
}

fn result(plan: &Deletion, recorded: &Recorded) -> JsValue {
    let mut out = object(vec![
        ("catalog", plan.catalog_after()),
        ("record", plan.record.clone()),
        (
            "forget",
            JsValue::Array(
                recorded
                    .items
                    .iter()
                    .map(fc_profile::forget::Item::listed)
                    .collect(),
            ),
        ),
    ]);
    if recorded.unknown {
        out.set("forget_unknown", JsValue::Bool(true));
    }
    out
}
