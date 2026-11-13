//! The forget file on disk (design 0013, "Forgetting an item"):
//! `profile-registry.json.forget` at the app root, written only under the
//! catalog's write lock, with the catalog's durable write and mode `0600`,
//! and read as the catalog is (a regular file the user owns, through no
//! symlink, within a bound). Its form and bounds are `fc_profile::forget`'s.
//!
//! ```text
//! freedom-cored profile forget-list --app-root <dir>
//! freedom-cored profile forget-done --app-root <dir> --item <32 hex>...
//! ```
//!
//! - **`forget-list`** → `{ items: [{ policy, item }] }`: the items main is
//!   to forget, each once. First it drops, without a `forget`, each item a
//!   profile the catalog still lists at the record's directory names in its
//!   own secrets file, and each item of a backend this OS doesn't have, and
//!   writes the file if that changed it.
//! - **`forget-done`** → `{ removed: <count> }`: each named item gone from
//!   every record; a record left empty goes too. An id no longer listed
//!   changes nothing.
//! - **A malformed file** (out of form, past a bound, or one that can't be
//!   read) is renamed aside to `profile-registry.json.forget.unreadable`,
//!   and reported (`set_aside: true`, and on stderr); nothing it names is
//!   forgotten, and the next delete starts a new one.

use std::ffi::OsString;
use std::path::Path;

use fc_json::JsValue;
use fc_profile::forget::{Backend, FORGET_ASIDE, ForgetFile, Item, Record};
use fc_profile::{Deletion, Store as _, Style};

use super::store::DiskStore;
use super::{Flags, catalog_lock, failed, object, prepare_app_root, print, storage};
use crate::exit::Exit;
use crate::log;

/// The backend whose items a deleted profile leaves in this OS's key
/// store: none on Windows, where DPAPI keeps nothing in the OS (0013,
/// "Windows").
pub const NATIVE: Option<Backend> = if cfg!(target_os = "macos") {
    Some(Backend::MacosKeychain)
} else if cfg!(target_os = "linux") {
    Some(Backend::SecretService)
} else {
    None
};

fn forget_path(app_root: &str) -> String {
    Style::native().join(&[app_root, fc_profile::FORGET_FILE])
}

/// The forget file as a change finds it: missing is empty; one that can't
/// be read, or is malformed, is renamed aside and the change starts from
/// empty (`true`: set aside).
fn load(
    store: &mut DiskStore<'_>,
    app_root: &str,
    held: &dyn Fn() -> bool,
) -> Result<(ForgetFile, bool), Exit> {
    let path = forget_path(app_root);
    let text = match store.read(&path) {
        Ok(None) => return Ok((ForgetFile::default(), false)),
        Ok(Some(text)) => Some(text),
        Err(_) => None,
    };
    if let Some(file) = text.and_then(|text| ForgetFile::parse(&text).ok()) {
        return Ok((file, false));
    }
    if !held() {
        return Err(storage(
            "lock_lost",
            "the catalog's write lock was taken over",
        ));
    }
    let aside = Style::native().join(&[app_root, FORGET_ASIDE]);
    match std::fs::rename(&path, &aside) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(storage("io", &e.kind().to_string())),
    }
    if crate::fsx::sync_rename(Path::new(app_root), Path::new(&aside)).is_err() {
        log::warn(
            "the forget file was set aside, but not flushed",
            serde_json::json!({}),
        );
    }
    log::warn(
        "the forget file was malformed or unreadable, and is set aside; nothing it names is forgotten",
        serde_json::json!({ "aside": FORGET_ASIDE }),
    );
    Ok((ForgetFile::default(), true))
}

fn save(store: &mut DiskStore<'_>, app_root: &str, file: &ForgetFile) -> Result<(), Exit> {
    store
        .write(&forget_path(app_root), &file.text())
        .map_err(|e| failed(&fc_profile::Error::Store(e)))
}

/// `profile-registry.json.forget.<digits>.<digits>.tmp`, the temp file a
/// writer killed before its rename left.
fn is_forget_temp(name: &str) -> bool {
    let Some(middle) = name
        .strip_prefix(fc_profile::FORGET_FILE)
        .and_then(|rest| rest.strip_prefix('.'))
        .and_then(|rest| rest.strip_suffix(".tmp"))
    else {
        return false;
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    matches!(middle.split_once('.'), Some((pid, n)) if digits(pid) && digits(n))
}

/// Removes the forget file's leftover temp files, under the catalog's
/// write lock, which every writer holds while its temp file exists: only
/// while it is still this process's.
fn remove_temps(app_root: &str, held: &dyn Fn() -> bool) {
    let Ok(entries) = std::fs::read_dir(app_root) else {
        return;
    };
    for entry in entries.flatten() {
        let name: OsString = entry.file_name();
        if name.to_str().is_some_and(is_forget_temp)
            && entry.file_type().is_ok_and(|t| t.is_file())
            && held()
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// What a delete recorded: the items, or that its secrets file couldn't be
/// read.
pub struct Recorded {
    pub items: Vec<Item>,
    pub unknown: bool,
}

/// A delete refused because the forget file is full (exit 75).
fn backlog() -> Exit {
    log::error(
        "the forget file has no room for this profile's items",
        serde_json::json!({}),
    );
    let _ = print(&object(vec![("error", JsValue::string("forget_backlog"))]));
    Exit::LockHeld
}

/// The delete's record, written before the catalog changes: the items the
/// target's secrets file names (in either layout), of this OS's backend.
/// Records still named by a listed profile go first, as in `forget-list`,
/// so a delete that stopped before its catalog change leaves no stale copy.
/// A secrets file that can't be read records nothing (`forget_unknown`).
/// No items, no record. A file with no room refuses the delete with
/// `forget_backlog`, nothing written.
pub fn record(
    store: &mut DiskStore<'_>,
    app_root: &str,
    plan: &Deletion,
    held: &dyn Fn() -> bool,
) -> Result<Recorded, Exit> {
    let style = Style::native();
    // A secrets file reached through a link (`freedom/` made one, say) may
    // be another profile's, whose items must not be forgotten: unknown.
    let data_root = Path::new(&plan.data_root);
    let linked = fc_profile::forget::secrets_paths(&plan.data_root, style)
        .iter()
        .any(|path| {
            Path::new(path)
                .parent()
                .is_some_and(|dir| !super::remove::no_links_below(data_root, dir))
        });
    let named = if linked {
        Err(fc_profile::forget::Malformed)
    } else {
        fc_profile::forget::secrets_named(store, &plan.data_root, style)
    };
    let (items, unknown) = match named {
        Ok(items) => (
            items
                .into_iter()
                .filter(|item| item.backend.recorded() && Some(item.backend) == NATIVE)
                .collect::<Vec<_>>(),
            false,
        ),
        Err(_) => {
            log::warn(
                "the profile's secrets file can't be read; its key-store items stay",
                serde_json::json!({}),
            );
            (Vec::new(), true)
        }
    };
    remove_temps(app_root, held);
    let (mut file, set_aside) = load(store, app_root, held)?;
    let pruned = file.drop_still_named(store, &plan.catalog, style);
    let foreign = file.drop_foreign(NATIVE);
    if !items.is_empty() {
        file.deleted.push(Record {
            id: plan.id.clone(),
            dir: plan.dir.clone(),
            items: items.clone(),
        });
        if !file.within_bounds() {
            return Err(backlog());
        }
    }
    if pruned || foreign || !items.is_empty() || set_aside {
        save(store, app_root, &file)?;
    }
    Ok(Recorded { items, unknown })
}

/// `profile forget-list` and `profile forget-done`.
pub fn run(sub: &str, args: impl Iterator<Item = std::ffi::OsString>) -> Result<Exit, ()> {
    let allowed: &[&str] = if sub == "forget-list" {
        &["--app-root"]
    } else {
        &["--app-root", "--item"]
    };
    let flags = Flags::parse(args, allowed)?;
    let app_root = flags.path("--app-root")?.to_owned();
    let items: Vec<String> = flags.all("--item").into_iter().map(str::to_owned).collect();
    if sub == "forget-done"
        && (items.is_empty() || !items.iter().all(|i| fc_profile::forget::is_item_id(i)))
    {
        return Err(());
    }
    Ok(run_locked(&app_root, sub == "forget-list", &items))
}

fn run_locked(app_root: &str, list: bool, done: &[String]) -> Exit {
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
    let result = if list {
        list_items(&mut store, app_root, &held)
    } else {
        forget_done(&mut store, app_root, &held, done)
    };
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

fn list_items(
    store: &mut DiskStore<'_>,
    app_root: &str,
    held: &dyn Fn() -> bool,
) -> Result<JsValue, Exit> {
    let style = Style::native();
    // Which profiles are still listed decides what is dropped: a catalog
    // that can't be read decides nothing, and nothing is listed.
    let catalog = fc_profile::load_catalog(store, app_root, style).map_err(|e| failed(&e))?;
    remove_temps(app_root, held);
    let (mut file, set_aside) = load(store, app_root, held)?;
    let pruned = file.drop_still_named(store, &catalog, style);
    let foreign = file.drop_foreign(NATIVE);
    if pruned || foreign || set_aside {
        save(store, app_root, &file)?;
    }
    let mut out = object(vec![(
        "items",
        JsValue::Array(file.live().into_iter().map(Item::listed).collect()),
    )]);
    if set_aside {
        out.set("set_aside", JsValue::Bool(true));
    }
    Ok(out)
}

fn forget_done(
    store: &mut DiskStore<'_>,
    app_root: &str,
    held: &dyn Fn() -> bool,
    done: &[String],
) -> Result<JsValue, Exit> {
    remove_temps(app_root, held);
    let (mut file, set_aside) = load(store, app_root, held)?;
    let removed = file.remove(done);
    if removed > 0 || set_aside {
        save(store, app_root, &file)?;
    }
    #[allow(clippy::cast_precision_loss)]
    let mut out = object(vec![("removed", JsValue::Number(removed as f64))]);
    if set_aside {
        out.set("set_aside", JsValue::Bool(true));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forget_temps_are_exactly_the_writers() {
        assert!(is_forget_temp("profile-registry.json.forget.12.0.tmp"));
        assert!(!is_forget_temp("profile-registry.json.forget"));
        assert!(!is_forget_temp("profile-registry.json.forget.unreadable"));
        assert!(!is_forget_temp("profile-registry.json.forget.12.tmp"));
        assert!(!is_forget_temp("profile-registry.json.12.0.tmp"));
    }
}
