//! A profile's deletion, the part with no I/O of its own: the reference's
//! `validateProfileDeletion`, `assertProfileDeletable` and
//! `assertDisplayNameConfirmation`, the paths `deleteProfile` removes, and
//! the app root's shared entries the packaged default profile's delete
//! spares (`profile-catalog.js`). The gates, the forget record, the fence
//! and the removal are `freedom-cored profile delete`'s (design 0013,
//! "Deletion").

use fc_json::JsValue;

use crate::catalog::{
    Error, Options, Store, catalog_path, find_index, load_catalog, profiles, record_dir,
};
use crate::ids::{DEFAULT_PROFILE_ID, display_name_from_id, sanitize_profile_id};
use crate::js::{or, prop, string};
use crate::path::Style;
use crate::{
    CATALOG_LOCK_DIR, CATALOG_LOCK_TARGET, PROFILE_REGISTRY_FILE, PROFILES_DIR, js::is_integer,
};

/// The short Radicle homes' directory (`RADICLE_SHORT_HOME_DIR`): `R/<slot>`
/// at the app root, or a dev build's `R/<checkout hash>/<slot>` beside it.
pub const RADICLE_HOMES_DIR: &str = "R";
/// The lock directory every Freedom build and profile shares, inside the
/// packaged app root on macOS and Windows (`SHARED_LOCK_DIR`).
pub const SHARED_LOCK_DIR: &str = "locks";
/// The cross-profile updater lock's target and directory
/// (`updater-owner-lock.js`).
pub const UPDATER_LOCK_TARGET: &str = "updater-owner";
pub const UPDATER_LOCK_DIR: &str = "updater-owner.lock";

/// `APP_ROOT_SHARED_ENTRIES`: the app root's entries that are the app's, not
/// the packaged default profile's, which lives beside them.
pub const APP_ROOT_SHARED_ENTRIES: [&str; 9] = [
    PROFILE_REGISTRY_FILE,
    CATALOG_LOCK_TARGET,
    CATALOG_LOCK_DIR,
    PROFILES_DIR,
    RADICLE_HOMES_DIR,
    UPDATER_LOCK_TARGET,
    UPDATER_LOCK_DIR,
    "logs",
    SHARED_LOCK_DIR,
];

/// `isAppRootSharedEntry(name)`: a shared entry, or any name starting with
/// `profile-registry.json.` (the catalog's temp files, and the forget file
/// with its own).
pub fn is_app_root_shared_entry(name: &str) -> bool {
    APP_ROOT_SHARED_ENTRIES.contains(&name)
        || name
            .strip_prefix(PROFILE_REGISTRY_FILE)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// A catalog profile's Radicle home, outside its directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadicleHome {
    /// The home, resolved: `R/<slot>`, or dev `R/<hash or dev>/<slot>`.
    pub dir: String,
    /// The homes' directory it must be strictly inside (`radicleRoot`).
    pub root: String,
    /// The app-owned directory above that (`path.dirname(radicleRoot)`),
    /// below which no step may be a link.
    pub base: String,
}

/// What a delete acts on, checked as `deleteProfile` checks it under the
/// catalog's write lock.
#[derive(Debug, Clone, PartialEq)]
pub struct Deletion {
    /// The catalog as loaded.
    pub catalog: JsValue,
    /// The record's index in it.
    pub index: usize,
    /// The record.
    pub record: JsValue,
    /// Its id (sanitized; the record's own).
    pub id: String,
    /// Its directory as the catalog records it.
    pub dir: String,
    /// `path.resolve(appRoot)`.
    pub app_root: String,
    /// `record.displayName || displayNameFromId(record.id)`.
    pub display_name: JsValue,
    /// `path.resolve(record.dir)`.
    pub profile_dir: String,
    /// The packaged default profile, whose directory is the app root.
    pub shares_app_root: bool,
    /// Where its data lives: the app root (resolved) when it shares it, its
    /// directory otherwise.
    pub data_root: String,
    /// `<data root>/identity`: the core's gated directory.
    pub identity_dir: String,
    /// `<data root>/ipfs-data/freedom-ipfs`: freedom-ipfsd's.
    pub ipfs_dir: String,
    /// A catalog profile with an integer slot's Radicle home.
    pub radicle: Option<RadicleHome>,
}

impl Deletion {
    /// The catalog's text once the record is gone (`saveCatalog` after
    /// `catalog.profiles.splice(recordIndex, 1)`).
    pub fn catalog_text(&self) -> String {
        let mut catalog = self.catalog.clone();
        if let Some(JsValue::Array(records)) = catalog.get_mut("profiles")
            && self.index < records.len()
        {
            records.remove(self.index);
        }
        catalog.stringify_pretty()
    }

    /// The catalog once the record is gone, as the result reports it.
    pub fn catalog_after(&self) -> JsValue {
        let mut catalog = self.catalog.clone();
        if let Some(JsValue::Array(records)) = catalog.get_mut("profiles")
            && self.index < records.len()
        {
            records.remove(self.index);
        }
        catalog
    }

    /// The display name as text, as `${displayName}` shows it.
    pub fn display_name_text(&self) -> String {
        self.display_name.js_string().unwrap_or_default()
    }
}

/// `path.resolve(path)`: the store's, with a trailing separator dropped
/// (except a root's), as Node's `resolve` drops it.
pub(crate) fn resolved(store: &dyn Store, style: Style, path: &str) -> String {
    let mut out = style.normalize(&store.resolve(path));
    while (out.ends_with('/') || (style == Style::Windows && out.ends_with('\\')))
        && style.dirname(&out) != out
    {
        out.pop();
    }
    out
}

fn sep(style: Style) -> char {
    match style {
        Style::Posix => '/',
        Style::Windows => '\\',
    }
}

/// `startsWith(`${parent}${path.sep}`)`, as the reference writes it.
fn strictly_under(style: Style, parent: &str, child: &str) -> bool {
    child != parent && child.starts_with(&format!("{parent}{}", sep(style)))
}

/// `assertProfileDeletable(appRoot, catalog, id)`, on the loaded catalog.
/// A record before the match that is `null` is the reference's `TypeError`
/// in `findIndex` ([`Error::Malformed`]).
fn assert_deletable(
    store: &dyn Store,
    app_root: &str,
    style: Style,
    catalog: &JsValue,
    id: &str,
) -> Result<(usize, JsValue, JsValue, String, String, bool), Error> {
    let path = catalog_path(app_root, style);
    let records = profiles(catalog);
    let index = find_index(records, id);
    let searched = index.map_or(records.len(), |i| i + 1);
    if records[..searched]
        .iter()
        .any(|record| matches!(record, JsValue::Null | JsValue::Undefined))
    {
        return Err(Error::Malformed { path });
    }
    let Some(index) = index else {
        return Err(Error::Refused(format!("Profile not found: {id}")));
    };
    if records.len() <= 1 {
        return Err(Error::Refused(
            "The last remaining profile cannot be deleted".into(),
        ));
    }
    let record = records[index].clone();
    let display_name = or(prop(&record, "displayName"), || {
        string(&display_name_from_id(id))
    });
    let dir = record_dir(&record, &path)?;
    let app = resolved(store, style, app_root);
    let profile_dir = resolved(store, style, &dir);
    let shares_app_root = profile_dir == app && id == DEFAULT_PROFILE_ID;
    if !shares_app_root && !strictly_under(style, &app, &profile_dir) {
        return Err(Error::Refused(
            "Refusing to delete a profile outside the app data root".into(),
        ));
    }
    Ok((
        index,
        record,
        display_name,
        dir,
        profile_dir,
        shares_app_root,
    ))
}

/// `assertDisplayNameConfirmation(expectedDisplayName, displayName)`: the
/// confirmation must be the display name exactly (a name that isn't text
/// never matches, as `!==` has it).
fn assert_confirmed(display_name: &JsValue, confirm: &str) -> Result<(), Error> {
    if matches!(display_name, JsValue::String(name) if name == confirm) {
        Ok(())
    } else {
        Err(Error::Refused(
            "Profile display name confirmation did not match".into(),
        ))
    }
}

/// `validateProfileDeletion(appRoot, profileId, expectedDisplayName)`: the
/// checks a delete makes first, with nothing locked or removed.
pub fn validate_deletion(
    store: &mut dyn Store,
    app_root: &str,
    style: Style,
    id: &str,
    confirm: &str,
) -> Result<(), Error> {
    let id = sanitize_profile_id(id)?;
    let catalog = load_catalog(store, app_root, style)?;
    let (_, _, display_name, ..) = assert_deletable(store, app_root, style, &catalog, &id)?;
    assert_confirmed(&display_name, confirm)
}

/// `getProfileRadicleDataDir(appRoot, record, options)`, checked inside its
/// root (`assertPathInside(radicleRoot, radicleDir, 'Radicle data')`).
fn radicle_home(
    store: &dyn Store,
    app_root: &str,
    record: &JsValue,
    opts: &Options,
) -> Result<Option<RadicleHome>, Error> {
    let style = opts.style;
    let slot = prop(record, "slot");
    if !is_integer(&slot) {
        return Ok(None);
    }
    let JsValue::Number(slot) = slot else {
        return Ok(None);
    };
    let slot = fc_json::number_to_string(slot);
    let parent = style.dirname(app_root);
    let (dir, root) = if opts.dev {
        let hash = opts
            .checkout_hash
            .as_deref()
            .filter(|h| !h.is_empty())
            .unwrap_or("dev");
        (
            style.join(&[&parent, RADICLE_HOMES_DIR, hash, &slot]),
            style.join(&[&parent, RADICLE_HOMES_DIR]),
        )
    } else {
        (
            style.join(&[app_root, RADICLE_HOMES_DIR, &slot]),
            style.join(&[app_root, RADICLE_HOMES_DIR]),
        )
    };
    let root_resolved = resolved(store, style, &root);
    let dir_resolved = resolved(store, style, &dir);
    if !strictly_under(style, &root_resolved, &dir_resolved) {
        return Err(Error::Refused(
            "Refusing to delete Radicle data outside its root".into(),
        ));
    }
    let base = resolved(store, style, &style.dirname(&root));
    Ok(Some(RadicleHome {
        dir: dir_resolved,
        root: root_resolved,
        base,
    }))
}

/// What `deleteProfile(appRoot, profileId, expectedDisplayName, options)`
/// acts on, checked as it checks it: the id sanitized, the record found,
/// not the last, inside the app root (or the packaged default profile at
/// it), the display name confirmed, and its Radicle home inside its root.
pub fn plan_deletion(
    store: &mut dyn Store,
    app_root: &str,
    opts: &Options,
    id: &str,
    confirm: &str,
) -> Result<Deletion, Error> {
    let style = opts.style;
    let id = sanitize_profile_id(id)?;
    let catalog = load_catalog(store, app_root, style)?;
    let (index, record, display_name, dir, profile_dir, shares_app_root) =
        assert_deletable(store, app_root, style, &catalog, &id)?;
    assert_confirmed(&display_name, confirm)?;
    let app = resolved(store, style, app_root);
    let data_root = if shares_app_root {
        app.clone()
    } else {
        profile_dir.clone()
    };
    let identity_dir = style.join(&[&data_root, "identity"]);
    let ipfs_dir = style.join(&[&data_root, "ipfs-data", "freedom-ipfs"]);
    let radicle = radicle_home(store, app_root, &record, opts)?;
    Ok(Deletion {
        catalog,
        index,
        record,
        id,
        dir,
        app_root: app,
        display_name,
        profile_dir,
        shares_app_root,
        data_root,
        identity_dir,
        ipfs_dir,
        radicle,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn shared_entries() {
        for name in APP_ROOT_SHARED_ENTRIES {
            assert!(is_app_root_shared_entry(name));
        }
        assert!(is_app_root_shared_entry("profile-registry.json.forget"));
        assert!(is_app_root_shared_entry("profile-registry.json.123.tmp"));
        assert!(is_app_root_shared_entry("profile-registry.json."));
        assert!(!is_app_root_shared_entry("profile-registry.jsonx"));
        assert!(!is_app_root_shared_entry("identity"));
        assert!(!is_app_root_shared_entry("Locks"));
    }
}
