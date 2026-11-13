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
//!    or refused before anything changes.
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
use super::remove::{self, Failure, Gated, Removal};
use super::store::DiskStore;
use super::{Flags, catalog_lock, failed, object, prepare_app_root, print, refused, storage};
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
    let mut store = DiskStore { commit: &held };
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
    commit_and_remove(&plan, app_root, place, held).map_err(ended)?;
    Ok(result(&plan, &recorded))
}

/// What the layout checks find: the gated directories' place, and the
/// Radicle home's other roots.
struct Layout {
    place: Option<remove::Place>,
}

fn check_layout(plan: &Deletion) -> Result<Layout, Failure> {
    let app = PathBuf::from(&plan.app_root);
    let data_root = PathBuf::from(&plan.data_root);
    remove::refuse_links_below(&app, &data_root)?;
    let identity = PathBuf::from(&plan.identity_dir);
    let ipfs = PathBuf::from(&plan.ipfs_dir);
    let other_roots = match &plan.radicle {
        Some(home) => {
            let dir = PathBuf::from(&home.dir);
            let mut others = remove::radicle_staging_siblings(&dir, Path::new(&home.root))?;
            others.insert(0, dir);
            others
        }
        None => Vec::new(),
    };
    let radicle = plan
        .radicle
        .as_ref()
        .map(|home| (Path::new(&home.base), Path::new(&home.dir)));
    let place = remove::gated_place(
        &data_root,
        &[
            Gated {
                dir: &identity,
                what: "identity data",
            },
            Gated {
                dir: &ipfs,
                what: "IPFS data",
            },
        ],
        &other_roots,
        radicle,
    )?;
    // `radicleHomeFence`: its path free of links, whether or not the data
    // root is there.
    if let Some((base, home)) = radicle {
        remove::refuse_radicle_links(base, home)?;
    }
    Ok(Layout { place })
}

fn commit_and_remove(
    plan: &Deletion,
    app_root: &str,
    layout: Layout,
    held: &dyn Fn() -> bool,
) -> Result<(), Failure> {
    let Layout { place, .. } = layout;
    let mut fences: Vec<(&Path, &'static str)> = place
        .as_ref()
        .map(|place| {
            place
                .fences
                .iter()
                .map(|fence| (fence.dir.as_path(), fence.what))
                .collect()
        })
        .unwrap_or_default();
    if let Some(home) = &plan.radicle {
        fences.push((Path::new(&home.dir), "Radicle data"));
    }
    let catalog = Style::native().join(&[app_root, fc_profile::PROFILE_REGISTRY_FILE]);
    let text = plan.catalog_text();
    let mut commit = || -> Result<(), Failure> {
        match crate::fsx::replace_as(
            Path::new(&catalog),
            fc_profile::PROFILE_REGISTRY_FILE,
            text.as_bytes(),
            |_| Ok(()),
            held,
        ) {
            Ok(_) => Ok(()),
            Err(crate::fsx::WriteError::Io(e)) => Err(Failure::Io(e)),
            Err(crate::fsx::WriteError::Check(reason)) => {
                Err(Failure::Io(std::io::Error::other(reason)))
            }
            Err(crate::fsx::WriteError::Abandoned) => Err(Failure::LockLost),
        }
    };
    let moves = remove::fence_and_commit(&fences, lock::now_ms(), held, &mut commit)?;
    step("after-catalog");

    let mut removal = Removal::new(held);
    if plan.shares_app_root {
        removal.remove_default_from_app_root(Path::new(&plan.data_root), place.as_ref())?;
    } else if let Some(place) = &place {
        removal.remove_sparing(Path::new(&plan.profile_dir), place, 0, None, false)?;
    } else {
        removal.remove_path(Path::new(&plan.profile_dir))?;
    }
    // The fenced directories inside the profile went with it, and those of
    // the packaged default profile with the app root's entries: their
    // tombstones are beside them.
    if let Some(home) = &plan.radicle {
        let fenced = moves.iter().find(|m| m.dir == Path::new(&home.dir));
        match fenced {
            Some(m) => removal.remove_path(&m.tombstone)?,
            None => removal.remove_path(Path::new(&home.dir))?,
        }
        // Listed again, as `removeRadicleStagingSiblings` does.
        let root = Path::new(&home.root);
        for sibling in remove::radicle_staging_siblings(Path::new(&home.dir), root)? {
            removal.remove_path(&sibling)?;
        }
    }
    if let Some(place) = &place {
        removal.remove_empty_remade(place, plan.shares_app_root)?;
    }
    if let Some(home) = &plan.radicle {
        removal.remove_empty_home(Path::new(&home.dir))?;
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
