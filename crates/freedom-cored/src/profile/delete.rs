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
//!    identity gate (`<data root>/identity`), freedom-ipfsd's
//!    (`<data root>/ipfs-data/freedom-ipfs`) and, for a profile with a slot,
//!    freedom-radicled's on its Radicle home. Any one held refuses the
//!    delete with `lock_held` (exit 75) before anything changes, whatever
//!    the profile lock's age: a live profile whose main has stalled holds
//!    its profile gate. A missing directory is gated at the path it would
//!    have, and nothing is made.
//! 3. **The layout:** every step from the app root to the profile's data,
//!    and to each gated directory and the Radicle home, a real directory,
//!    or refused before anything changes. Each is reached from the app
//!    root's handle (`anchor::Dir`), as the catalog's store reaches its
//!    files, and every change below is made through those handles
//!    (`remove.rs`).
//! 4. **The forget record** (`forget::record`), before the catalog changes.
//! 5. **The fence and the catalog's change** in one step: each gated
//!    directory moved aside to its tombstone, then the catalog written
//!    without the record.
//! 6. **The removal:** the profile's directory (or, for the packaged
//!    default profile, the app root's entries but the shared ones), sparing
//!    the gated directories' places, then the tombstones, the Radicle home
//!    and its staging siblings, then anything made again empty.
//!
//! **Result:** `{ catalog, record, forget: [{ policy, item }] }`, with
//! `forget_unknown: true` when the target's secrets file couldn't be read.
//! Refusals as the other catalog subcommands', and `{ "error": "lock_held",
//! "gate": "profile" | "core" | "ipfs" | "radicle" }` or `{ "error":
//! "forget_backlog" }` with exit 75.

use std::path::{Path, PathBuf};

use fc_json::JsValue;
use fc_profile::{Deletion, Options, Style};
use fc_service::gate::{GateError, PROFILE_NAMESPACE};

use super::forget::{self, Recorded};
use super::lock;
use super::remove::{self, Failure, Gated, Located, Removal, ToFence};
use super::store::{self, DiskStore};
use super::{Flags, catalog_lock, failed, object, prepare_app_root, print, refused, storage};
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

fn gates(plan: &Deletion, lock_dir: &Path) -> Result<Vec<fc_service::gate::Gate>, Exit> {
    let mut held = vec![take(
        Which::Profile,
        Path::new(&plan.profile_dir),
        lock_dir,
    )?];
    held.push(take(Which::Core, Path::new(&plan.identity_dir), lock_dir)?);
    held.push(take(Which::Ipfs, Path::new(&plan.ipfs_dir), lock_dir)?);
    if let Some(home) = &plan.radicle {
        held.push(take(Which::Radicle, Path::new(&home.dir), lock_dir)?);
    }
    Ok(held)
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
    let lock = match catalog_lock(root) {
        Ok(lock) => lock,
        Err(exit) => return exit,
    };
    let held = || lock.held();
    let mut store = match DiskStore::open(app_root, &held) {
        Ok(store) => store,
        Err(e) => return storage("io", &e.kind().to_string()),
    };
    let result = delete_locked(&mut store, app_root, lock_dir, opts, id, confirm, &held);
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

fn delete_locked(
    store: &mut DiskStore<'_>,
    app_root: &str,
    lock_dir: &Path,
    opts: &Options,
    id: &str,
    confirm: &str,
    held: &dyn Fn() -> bool,
) -> Result<JsValue, Exit> {
    let plan =
        fc_profile::plan_deletion(store, app_root, opts, id, confirm).map_err(|e| failed(&e))?;
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
    let _gates = gates(&plan, lock_dir)?;
    let place = check_layout(&plan).map_err(ended)?;
    step("before-record");
    let recorded = forget::record(store, app_root, &plan, held)?;
    step("after-record");
    commit_and_remove(store, &plan, app_root, place, held).map_err(ended)?;
    Ok(result(&plan, &recorded))
}

/// The gated directories, below the data root.
const GATED: [Gated<'static>; 2] = [
    Gated {
        names: &["identity"],
        what: "identity data",
    },
    Gated {
        names: &["ipfs-data", "freedom-ipfs"],
        what: "IPFS data",
    },
];

/// What the layout check found, every directory reached through no
/// symlink: the app root's handle; the data root (`None` for the packaged
/// default profile, whose data root is the app root, kept); the gated
/// directories' place; and the Radicle home.
struct Layout {
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

fn check_layout(plan: &Deletion) -> Result<Layout, Failure> {
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
            let base = if base_path == app_path {
                app.try_clone()?
            } else {
                Dir::open_root(&base_path, Resolve::Follow)?.ok_or_else(|| {
                    Failure::Io(std::io::Error::from(std::io::ErrorKind::NotFound))
                })?
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
    let place = remove::gated_place(data_dir, &data_path, &GATED, &other_roots)?;
    Ok(Layout {
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
    layout: Layout,
    held: &dyn Fn() -> bool,
) -> Result<(), Failure> {
    let Layout {
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
    if let Some(Located {
        parent: Some(parent),
        name,
        ..
    }) = &home
    {
        fences.push(ToFence {
            parent,
            name,
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
        // since goes as the reference's ungated removal has it.
        (Some(data), None) => {
            if let Some(parent) = &data.parent {
                removal.remove_tree(parent, &data.name)?;
            }
        }
    }
    if let Some(Located {
        parent: Some(parent),
        name,
        ..
    }) = &home
    {
        let fenced = tombstones.last().cloned().flatten();
        removal.remove_tree(parent, fenced.as_deref().unwrap_or(name))?;
        // Listed again, as `removeRadicleStagingSiblings` does.
        for sibling in remove::radicle_staging_siblings(parent, name)? {
            removal.remove_tree(parent, &sibling)?;
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
    // The Radicle home made again since its fence, empty.
    if let Some(Located {
        parent: Some(parent),
        name,
        ..
    }) = &home
    {
        removal.remove_empty(parent, name)?;
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
