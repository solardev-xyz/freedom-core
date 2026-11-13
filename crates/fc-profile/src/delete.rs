//! A profile's deletion, the part with no I/O of its own: the reference's
//! `validateProfileDeletion`, `assertProfileDeletable` and
//! `assertDisplayNameConfirmation`, the paths `deleteProfile` removes, and
//! the app root's shared entries the packaged default profile's delete
//! spares (`profile-catalog.js`). The gates, the forget record, the fence
//! and the removal are `freedom-cored profile delete`'s (design 0013,
//! "Deletion").

use fc_json::JsValue;
use unicode_normalization::UnicodeNormalization;

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

/// A name as [`overlaps`] compares it, on every OS: canonically
/// decomposed (NFD), as macOS's volumes compare names whatever their case
/// rule, and case folded at least as widely as any volume folds case (the
/// default ones on macOS and Windows): each character's uppercase
/// lowercased, decomposed again, until nothing changes. So `é` and `e` with
/// its accent, `É` and `é`, `ß`, `ẞ` and `SS`, `ς` and `Σ`, and the Kelvin
/// sign and `k` each make one key. A fold wider than a volume's only
/// refuses more. `profile migrate --finish-only` compares by it too.
pub fn fold(text: &str) -> String {
    let mut key: String = text.nfd().collect();
    // Two rounds reach the end for every character (`ẞ`, `ß`, `ss`); the
    // bound only keeps a future table from looping (`the_fold_is_stable`).
    for _ in 0..8 {
        let next: String = key
            .chars()
            .flat_map(char::to_uppercase)
            .flat_map(char::to_lowercase)
            .nfd()
            .collect();
        if next == key {
            break;
        }
        key = next;
    }
    key
}

/// One name of a resolved path, as written and as compared: [`fold`]ed, and
/// on Windows without the trailing dots and spaces Win32 drops from a name.
struct Name<'a> {
    text: &'a str,
    key: String,
}

fn names(style: Style, path: &str) -> Vec<Name<'_>> {
    path.split(|c| c == '/' || (style == Style::Windows && c == '\\'))
        .filter(|name| !name.is_empty())
        .map(|text| {
            let kept = match style {
                Style::Posix => text,
                Style::Windows => text.trim_end_matches(['.', ' ']),
            };
            Name {
                text,
                key: fold(kept),
            }
        })
        .collect()
}

fn same(a: &[Name<'_>], b: &[Name<'_>]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(a, b)| a.key == b.key)
}

fn inside(parent: &[Name<'_>], child: &[Name<'_>]) -> bool {
    child.len() > parent.len() && same(parent, &child[..parent.len()])
}

/// [`is_app_root_shared_entry`], for a name compared as [`Name`] has it.
fn shared_key(key: &str) -> bool {
    let registry = fold(PROFILE_REGISTRY_FILE);
    APP_ROOT_SHARED_ENTRIES
        .iter()
        .any(|entry| fold(entry) == key)
        || key
            .strip_prefix(registry.as_str())
            .is_some_and(|rest| rest.starts_with('.'))
}

/// What a profile's delete removes.
enum Removes<'a> {
    /// The packaged default profile's: the app root's entries but the
    /// shared ones (by their names exactly, as its removal spares them).
    AppRoot,
    /// A directory below the app root, and all below it.
    Dir(Vec<Name<'a>>),
}

/// Whether two deletes would remove some of the same data.
fn removes_overlap(app: &[Name<'_>], a: &Removes<'_>, b: &Removes<'_>) -> bool {
    match (a, b) {
        (Removes::AppRoot, Removes::AppRoot) => true,
        (Removes::AppRoot, Removes::Dir(dir)) | (Removes::Dir(dir), Removes::AppRoot) => dir
            .get(app.len())
            .is_none_or(|first| !is_app_root_shared_entry(first.text)),
        (Removes::Dir(a), Removes::Dir(b)) => same(a, b) || inside(a, b) || inside(b, a),
    }
}

/// Whether deleting the profile at `target` (resolved, inside the app root
/// `app`, or the app root for the packaged default profile) would remove
/// the app's own data or another profile's (beyond the reference, which
/// checks only that the directory is inside the app root; 0013's
/// `profile-delete-overlap`; review of #337):
/// - **the app's own:** the target is the profiles root or another of the
///   app root's shared entries, or inside one but the profiles root;
/// - **another profile's:** the target is at, above or inside another
///   record's directory, both resolved, or, for the packaged default
///   profile, at the app root, whose delete removes the app root's entries
///   but the shared ones. A record at a shared entry (`Profiles` itself) is
///   the app's directory, not a profile's; one outside the app root, or
///   above it, is no delete's to remove (its own is refused).
///
/// Names are compared as [`Name`] has them, so a spelling, a case or a
/// trailing dot that names the same directory on macOS or Windows doesn't
/// get past.
///
/// `profile migrate --finish-only`, which acts on a profile's directory
/// too, refuses by the same rule (design 0013, "The move").
pub fn overlaps(
    style: Style,
    app: &str,
    target: &str,
    shares_app_root: bool,
    others: &[String],
) -> bool {
    let app = names(style, app);
    let target = if shares_app_root {
        Removes::AppRoot
    } else {
        let dir = names(style, target);
        if !inside(&app, &dir) {
            return true;
        }
        let first = &dir[app.len()];
        let profiles = first.key == fold(PROFILES_DIR);
        if shared_key(&first.key) && !(profiles && dir.len() > app.len() + 1) {
            return true;
        }
        Removes::Dir(dir)
    };
    others.iter().any(|other| {
        let dir = names(style, other);
        let other = if same(&app, &dir) {
            Removes::AppRoot
        } else if inside(&app, &dir) {
            if dir.len() == app.len() + 1 && shared_key(&dir[app.len()].key) {
                return false;
            }
            Removes::Dir(dir)
        } else {
            return false;
        };
        removes_overlap(&app, &target, &other)
    })
}

/// `assertProfileDeletable(appRoot, catalog, id)`, on the loaded catalog.
/// A record before the match that is `null` is the reference's `TypeError`
/// in `findIndex` ([`Error::Malformed`]). Then, beyond the reference, a
/// directory that overlaps another profile's or the app's own data is
/// refused ([`overlaps`]), and so is a Radicle slot another record also
/// has, before the confirmation as the reference's refusal of a directory
/// outside the app root is.
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
    // Every other record's directory, resolved; one with none is no
    // profile's directory.
    let others: Vec<String> = records
        .iter()
        .enumerate()
        .filter(|(n, _)| *n != index)
        .filter_map(|(_, other)| match other.get("dir") {
            Some(JsValue::String(dir)) => Some(resolved(store, style, dir.as_str())),
            _ => None,
        })
        .collect();
    if overlaps(style, &app, &profile_dir, shares_app_root, &others) {
        return Err(Error::Refused(OVERLAP_REFUSED.into()));
    }
    // A slot another record has too: one Radicle home, `R/<slot>` (or a dev
    // build's `R/<checkout>/<slot>`), which this delete would remove.
    if let Some(slot) = home_slot(&record)
        && records
            .iter()
            .enumerate()
            .any(|(n, other)| n != index && home_slot(other).as_deref() == Some(slot.as_str()))
    {
        return Err(Error::Refused(SLOT_REFUSED.into()));
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

/// The refusal of a directory that overlaps another profile's or the app's
/// own data (0013's `profile-delete-overlap`).
pub const OVERLAP_REFUSED: &str =
    "Refusing to delete a profile whose directory overlaps another profile's or the app's own data";

/// The refusal of a Radicle slot another record also has, so a Radicle home
/// another profile's too (0013's `profile-delete-overlap`).
pub const SLOT_REFUSED: &str =
    "Refusing to delete a profile whose Radicle slot another profile also uses";

/// A record's Radicle home's name in its directory: its slot as
/// `String(slot)` writes it, when the slot is an integer
/// ([`radicle_home`]'s rule). `profile migrate --finish-only` refuses a
/// slot another record shares, as a delete does.
pub fn home_slot(record: &JsValue) -> Option<String> {
    match prop(record, "slot") {
        JsValue::Number(slot) if is_integer(&JsValue::Number(slot)) => {
            Some(fc_json::number_to_string(slot))
        }
        _ => None,
    }
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
    let Some(slot) = home_slot(record) else {
        return Ok(None);
    };
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
/// it), overlapping no other profile's directory and none of the app's own
/// and sharing no other record's Radicle slot (beyond the reference), the
/// display name confirmed, and its Radicle home inside its root.
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

    /// The overlap check on Windows paths: a case or a trailing dot or
    /// space names the same directory there.
    #[test]
    fn overlaps_on_windows() {
        let app = r"C:\Users\u\fb";
        let others = |dirs: &[&str]| dirs.iter().map(|d| (*d).to_owned()).collect::<Vec<_>>();
        let w = Style::Windows;
        let none = others(&[]);
        for target in [
            r"C:\Users\u\fb\Profiles",
            r"C:\Users\u\fb\profiles",
            r"C:\Users\u\fb\Profiles.",
            r"C:\Users\u\fb\Profiles .",
            r"C:\Users\u\fb\LOCKS",
            r"C:\Users\u\fb\R\3",
            r"C:\Users\u\fb\profile-registry.json.forget",
        ] {
            assert!(overlaps(w, app, target, false, &none), "{target}");
        }
        assert!(!overlaps(w, app, r"C:\Users\u\fb\Profiles\a", false, &none));
        // Another profile's directory under another case or a trailing dot.
        let peer = others(&[r"c:\users\U\FB\profiles\A"]);
        assert!(overlaps(w, app, r"C:\Users\u\fb\Profiles\a.", false, &peer));
        assert!(overlaps(
            w,
            app,
            r"C:\Users\u\fb\Profiles\a\b",
            false,
            &peer
        ));
        assert!(!overlaps(
            w,
            app,
            r"C:\Users\u\fb\Profiles\ab",
            false,
            &peer
        ));
        // The packaged default profile's data: the app root's entries but
        // the shared ones, by their names exactly.
        let default = others(&[app]);
        assert!(overlaps(w, app, r"C:\Users\u\fb\loose", false, &default));
        assert!(!overlaps(
            w,
            app,
            r"C:\Users\u\fb\Profiles\a",
            false,
            &default
        ));
        assert!(overlaps(
            w,
            app,
            app,
            true,
            &others(&[r"C:\Users\u\fb\Loose"])
        ));
        assert!(!overlaps(
            w,
            app,
            app,
            true,
            &others(&[r"C:\Users\u\fb\R\3"])
        ));
        // A name that is a shared entry's only ignoring case may be removed
        // there (the removal spares the names exactly): it counts.
        assert!(overlaps(w, app, app, true, &peer));
        let exact = others(&[r"c:\users\U\FB\Profiles\A"]);
        assert!(!overlaps(w, app, app, true, &exact));
        // The profiles root's record is the app's, and one above the app
        // root no delete's.
        let roots = others(&[r"C:\Users\u\fb\Profiles", r"C:\Users\u", r"D:\fb"]);
        assert!(!overlaps(
            w,
            app,
            r"C:\Users\u\fb\Profiles\a",
            false,
            &roots
        ));
        assert!(!overlaps(w, app, app, true, &roots));
    }

    /// The overlap check on names that are one directory's on macOS, whose
    /// volumes ignore normalization and, by default, case, or on Windows,
    /// whose default ones ignore case: compared so on every OS (review of
    /// #337).
    #[test]
    fn overlaps_unicode_equivalent_names() {
        let app = "/Users/u/fb";
        let p = Style::Posix;
        let at = |name: &str| format!("{app}/Profiles/{name}");
        for (target, peer) in [
            // NFC and NFD.
            ("caf\u{e9}", "cafe\u{301}"),
            ("cafe\u{301}", "caf\u{e9}"),
            // Marks in another order that is canonically the same.
            ("a\u{323}\u{301}", "a\u{301}\u{323}"),
            // Non-ASCII case, composed or not.
            ("\u{c9}t\u{e9}", "\u{e9}t\u{e9}"),
            ("\u{c9}T\u{c9}", "e\u{301}te\u{301}"),
            ("\u{3a9}", "\u{3c9}"),
            // Wider than a volume's fold: `ß`, `ẞ` and `SS`, final sigma,
            // the Kelvin and Ohm signs, `ﬀ`, and the dotted capital I.
            ("stra\u{df}e", "STRASSE"),
            ("stra\u{1e9e}e", "strasse"),
            ("\u{3c3}\u{3c2}", "\u{3a3}\u{3a3}"),
            ("\u{212a}", "k"),
            ("\u{2126}", "\u{3c9}"),
            ("\u{fb00}", "FF"),
            ("\u{130}", "i\u{307}"),
        ] {
            let peers = [at(peer)];
            assert!(
                overlaps(p, app, &at(target), false, &peers),
                "{target:?} {peer:?}"
            );
            assert!(
                overlaps(p, app, &format!("{}/x", at(target)), false, &peers),
                "inside {target:?} {peer:?}"
            );
            assert!(
                overlaps(p, app, &at(peer), false, &[format!("{}/x", at(target))]),
                "above {target:?} {peer:?}"
            );
        }
        // Names no volume takes for one another.
        for (target, peer) in [
            ("cafe", "caf\u{e9}"),
            ("e\u{301}", "e\u{300}"),
            ("\u{e9}", "\u{e8}"),
            ("ss", "s"),
        ] {
            assert!(
                !overlaps(p, app, &at(target), false, &[at(peer)]),
                "{target:?} {peer:?}"
            );
        }
        // The app's own entries under another spelling.
        let none: [String; 0] = [];
        for name in [
            "Profile\u{17f}",
            "LOC\u{212a}S",
            "r",
            "profile-registry.json.forget",
        ] {
            let target = format!("{app}/{name}");
            assert!(overlaps(p, app, &target, false, &none), "{name:?}");
        }
        assert!(!overlaps(
            p,
            app,
            &format!("{app}/Profile\u{17f}/a"),
            false,
            &none
        ));
        // The app root itself, spelled otherwise by another record.
        let app = "/Users/u/caf\u{e9}";
        assert!(overlaps(
            p,
            app,
            &format!("{app}/loose"),
            false,
            &["/Users/u/CAFE\u{301}".to_owned()]
        ));
    }

    /// The fold ends within its bound for every character: folding a key
    /// again changes nothing.
    #[test]
    fn the_fold_is_stable() {
        for c in (0..=0x10_FFFF).filter_map(char::from_u32) {
            let once = fold(c.encode_utf8(&mut [0; 4]));
            assert_eq!(fold(&once), once, "U+{:04X}", u32::from(c));
        }
    }

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
