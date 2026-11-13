//! The forget file, `profile-registry.json.forget` at the app root (design
//! 0013, "Forgetting an item"): deleted profiles' key-store items, kept
//! until main's `forget` of each succeeds.
//!
//! ```json
//! { "version": 1,
//!   "deleted": [ { "id": "<profile id>", "dir": "<its directory>",
//!                  "items": [ { "backend": "macos-keychain",
//!                               "policy": "unattended",
//!                               "item": "<32 hex>" } ] } ] }
//! ```
//!
//! - **Its form is fixed:** exactly these keys, `version` 1, `id` a
//!   canonical profile id, `dir` non-empty text, `backend` and `policy` from
//!   their lists, `item` 32 lowercase hex digits. Anything else is
//!   malformed.
//! - **Its bounds:** at most [`MAX_PROFILES`] records of at most
//!   [`MAX_ITEMS`] items each, each record at most [`MAX_RECORD_BYTES`] as
//!   `JSON.stringify` writes it, and the file's text at most
//!   [`MAX_FILE_BYTES`]. A file past one is malformed, and nothing it names
//!   is forgotten: the subcommands rename it aside
//!   (`profile-registry.json.forget.unreadable`).
//! - **Its text** is the catalog's: `JSON.stringify(…, null, 2)`.
//!
//! The backend and policy lists are PRF-1's (`fc-keystore`, not yet built).
//! Until then they are the names 0013 uses: the policies `unattended` and
//! `user_presence`, and the backends `macos-keychain`, `dpapi` and
//! `secret-service` (0013 names the Secret Service but gives no spelling).
//!
//! A deleted profile's items come from its secrets file
//! (`identity/secrets.json`, or `freedom/identity/secrets.json` in the moved
//! layout), whose form is PRF-1's too: [`secrets_items`] reads the narrowest
//! one 0013 shows.

use fc_json::JsValue;

use crate::catalog::{Store, profiles};
use crate::delete::resolved;
use crate::ids::sanitize_profile_id;
use crate::js::{object, string};
use crate::path::Style;

/// The most deleted profiles the file holds.
pub const MAX_PROFILES: usize = 16;
/// The most items a record holds: a secrets file names at most four.
pub const MAX_ITEMS: usize = 4;
/// The most bytes a record takes, as `JSON.stringify(record)` writes it.
pub const MAX_RECORD_BYTES: usize = 8 * 1024;
/// The most bytes the file's text takes.
pub const MAX_FILE_BYTES: usize = 64 * 1024;
/// Where a malformed forget file is renamed aside, at the app root: under
/// the catalog's prefix, which every build's default-profile delete spares.
pub const FORGET_ASIDE: &str = "profile-registry.json.forget.unreadable";
/// A profile's secrets file, in its identity directory (PRF-1).
pub const SECRETS_FILE: &str = "secrets.json";

/// A key store's backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    MacosKeychain,
    SecretService,
    Dpapi,
}

impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Backend::MacosKeychain => "macos-keychain",
            Backend::SecretService => "secret-service",
            Backend::Dpapi => "dpapi",
        }
    }

    fn parse(name: &str) -> Option<Backend> {
        match name {
            "macos-keychain" => Some(Backend::MacosKeychain),
            "secret-service" => Some(Backend::SecretService),
            "dpapi" => Some(Backend::Dpapi),
            _ => None,
        }
    }

    /// Whether a deleted profile's item of this backend is recorded: DPAPI
    /// keeps nothing in the OS, so dropping its blob is the whole `forget`,
    /// and no record is made (0013, "Windows").
    pub fn recorded(self) -> bool {
        self != Backend::Dpapi
    }
}

/// A key's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Unattended,
    UserPresence,
}

impl Policy {
    pub fn name(self) -> &'static str {
        match self {
            Policy::Unattended => "unattended",
            Policy::UserPresence => "user_presence",
        }
    }

    fn parse(name: &str) -> Option<Policy> {
        match name {
            "unattended" => Some(Policy::Unattended),
            "user_presence" => Some(Policy::UserPresence),
            _ => None,
        }
    }
}

/// One key-store item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub backend: Backend,
    pub policy: Policy,
    /// 32 lowercase hex digits.
    pub item: String,
}

impl Item {
    fn value(&self) -> JsValue {
        let mut out = object();
        out.set("backend", string(self.backend.name()));
        out.set("policy", string(self.policy.name()));
        out.set("item", string(&self.item));
        out
    }

    /// `{ policy, item }`, as `forget-list` and a delete's result give it.
    pub fn listed(&self) -> JsValue {
        let mut out = object();
        out.set("policy", string(self.policy.name()));
        out.set("item", string(&self.item));
        out
    }
}

/// A deleted profile's record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub id: String,
    pub dir: String,
    pub items: Vec<Item>,
}

impl Record {
    fn value(&self) -> JsValue {
        let mut out = object();
        out.set("id", string(&self.id));
        out.set("dir", string(&self.dir));
        out.set(
            "items",
            JsValue::Array(self.items.iter().map(Item::value).collect()),
        );
        out
    }

    fn within_bounds(&self) -> bool {
        self.items.len() <= MAX_ITEMS && self.value().stringify().len() <= MAX_RECORD_BYTES
    }
}

/// A forget file that isn't in its form, or is past a bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

/// The forget file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForgetFile {
    pub deleted: Vec<Record>,
}

/// `item`: 32 lowercase hex digits.
pub fn is_item_id(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// An object with exactly `keys`, each once.
fn exactly(value: &JsValue, keys: &[&str]) -> Result<(), Malformed> {
    let JsValue::Object(props) = value else {
        return Err(Malformed);
    };
    if props.len() != keys.len() || keys.iter().any(|key| value.get(key).is_none()) {
        return Err(Malformed);
    }
    Ok(())
}

/// Well-formed text (no lone surrogate).
fn text(value: Option<&JsValue>) -> Result<&str, Malformed> {
    match value {
        Some(JsValue::String(s)) if s.is_well_formed() => Ok(s.as_str()),
        _ => Err(Malformed),
    }
}

fn item_of(value: &JsValue) -> Result<Item, Malformed> {
    exactly(value, &["backend", "policy", "item"])?;
    let backend = Backend::parse(text(value.get("backend"))?).ok_or(Malformed)?;
    let policy = Policy::parse(text(value.get("policy"))?).ok_or(Malformed)?;
    let item = text(value.get("item"))?;
    if !is_item_id(item) {
        return Err(Malformed);
    }
    Ok(Item {
        backend,
        policy,
        item: item.to_owned(),
    })
}

fn record_of(value: &JsValue) -> Result<Record, Malformed> {
    exactly(value, &["id", "dir", "items"])?;
    let id = text(value.get("id"))?;
    if sanitize_profile_id(id).ok().as_deref() != Some(id) {
        return Err(Malformed);
    }
    let dir = text(value.get("dir"))?;
    if dir.is_empty() {
        return Err(Malformed);
    }
    let Some(JsValue::Array(items)) = value.get("items") else {
        return Err(Malformed);
    };
    if items.len() > MAX_ITEMS {
        return Err(Malformed);
    }
    let record = Record {
        id: id.to_owned(),
        dir: dir.to_owned(),
        items: items.iter().map(item_of).collect::<Result<_, _>>()?,
    };
    if !record.within_bounds() {
        return Err(Malformed);
    }
    Ok(record)
}

impl ForgetFile {
    /// Reads the file's text: [`Malformed`] unless it is in form and within
    /// every bound.
    pub fn parse(text: &str) -> Result<ForgetFile, Malformed> {
        if text.len() > MAX_FILE_BYTES {
            return Err(Malformed);
        }
        let value = fc_json::parse(text).map_err(|_| Malformed)?;
        exactly(&value, &["version", "deleted"])?;
        if !matches!(value.get("version"), Some(JsValue::Number(n)) if *n == 1.0) {
            return Err(Malformed);
        }
        let Some(JsValue::Array(deleted)) = value.get("deleted") else {
            return Err(Malformed);
        };
        if deleted.len() > MAX_PROFILES {
            return Err(Malformed);
        }
        Ok(ForgetFile {
            deleted: deleted.iter().map(record_of).collect::<Result<_, _>>()?,
        })
    }

    /// The file's text: `JSON.stringify(…, null, 2)`.
    pub fn text(&self) -> String {
        let mut out = object();
        out.set("version", JsValue::Number(1.0));
        out.set(
            "deleted",
            JsValue::Array(self.deleted.iter().map(Record::value).collect()),
        );
        out.stringify_pretty()
    }

    /// Whether the file is within every bound.
    pub fn within_bounds(&self) -> bool {
        self.deleted.len() <= MAX_PROFILES
            && self.deleted.iter().all(Record::within_bounds)
            && self.text().len() <= MAX_FILE_BYTES
    }

    /// The items it names, counted.
    pub fn count(&self) -> usize {
        self.deleted.iter().map(|record| record.items.len()).sum()
    }

    /// Drops the records left with no item. Whether any went.
    fn drop_empty(&mut self) -> bool {
        let before = self.deleted.len();
        self.deleted.retain(|record| !record.items.is_empty());
        self.deleted.len() != before
    }

    /// Drops every item of a backend this OS doesn't have (`native`; none
    /// on an OS with no recorded backend): its item isn't here, so it is
    /// dropped without a `forget` (0013, "An item already gone"). Whether
    /// anything went.
    pub fn drop_foreign(&mut self, native: Option<Backend>) -> bool {
        let before = self.count();
        for record in &mut self.deleted {
            record.items.retain(|item| Some(item.backend) == native);
        }
        let dropped = self.count() != before;
        self.drop_empty() || dropped
    }

    /// Drops each item a profile the catalog still lists at the record's
    /// directory names in its own secrets file, without a `forget`: either
    /// the delete stopped before the catalog changed, or the directory was
    /// imported again, and the profile's own file names the item (0013, "A
    /// record counts once its profile is gone"). Whether anything went.
    pub fn drop_still_named(
        &mut self,
        store: &mut dyn Store,
        catalog: &JsValue,
        style: Style,
    ) -> bool {
        let before = self.count();
        for record in &mut self.deleted {
            if !listed_at(store, catalog, style, &record.id, &record.dir) {
                continue;
            }
            let dir = resolved(store, style, &record.dir);
            // A secrets file that can't be read names nothing.
            let named = secrets_named(store, &dir, style).unwrap_or_default();
            record
                .items
                .retain(|item| !named.iter().any(|n| n.item == item.item));
        }
        let dropped = self.count() != before;
        self.drop_empty() || dropped
    }

    /// Removes every item whose id is in `ids` (`forget-done`), from every
    /// record. How many went.
    pub fn remove(&mut self, ids: &[String]) -> usize {
        let before = self.count();
        for record in &mut self.deleted {
            record.items.retain(|item| !ids.contains(&item.item));
        }
        let removed = before - self.count();
        self.drop_empty();
        removed
    }

    /// The items to forget, each id once, in the file's order.
    pub fn live(&self) -> Vec<&Item> {
        let mut out: Vec<&Item> = Vec::new();
        for item in self.deleted.iter().flat_map(|record| &record.items) {
            if !out.iter().any(|seen| seen.item == item.item) {
                out.push(item);
            }
        }
        out
    }
}

/// Whether the catalog lists a profile `id` at `dir` (both resolved).
fn listed_at(store: &mut dyn Store, catalog: &JsValue, style: Style, id: &str, dir: &str) -> bool {
    let dir = resolved(store, style, dir);
    profiles(catalog).iter().any(|record| {
        matches!(record.get("id"), Some(JsValue::String(s)) if s == id)
            && matches!(record.get("dir"), Some(JsValue::String(d))
                if resolved(store, style, d.as_str()) == dir)
    })
}

/// A secrets file's `backend` and `item` (`item` may be `null` where a key
/// holds only a `pending` one).
fn key_items(value: &JsValue, policy: Policy, out: &mut Vec<Item>) -> Result<(), Malformed> {
    if !matches!(value, JsValue::Object(_)) {
        return Err(Malformed);
    }
    let backend = Backend::parse(text(value.get("backend"))?).ok_or(Malformed)?;
    match value.get("item") {
        None | Some(JsValue::Null) => {}
        Some(item) => {
            let item = text(Some(item))?;
            if !is_item_id(item) {
                return Err(Malformed);
            }
            out.push(Item {
                backend,
                policy,
                item: item.to_owned(),
            });
        }
    }
    match value.get("pending") {
        None | Some(JsValue::Null) => {}
        Some(pending) => {
            if !matches!(pending, JsValue::Object(_)) {
                return Err(Malformed);
            }
            let backend = Backend::parse(text(pending.get("backend"))?).ok_or(Malformed)?;
            let item = text(pending.get("item"))?;
            if !is_item_id(item) {
                return Err(Malformed);
            }
            out.push(Item {
                backend,
                policy,
                item: item.to_owned(),
            });
        }
    }
    Ok(())
}

/// The items a secrets file names (0013, "The secrets file"): each key in
/// use (`keys.<policy>.item`), each `pending` one (`keys.<policy>.pending`,
/// `{ backend, item, … }`), and the `forget` list (`{ backend, policy, item
/// }`). PRF-1 defines the file; until then this is the narrowest reading of
/// 0013's example: `version` 1, `keys` an object keyed by policy, `forget`
/// an array, other members ignored. A file in no such form, or naming more
/// than four items, is [`Malformed`]: the delete goes on, with
/// `forget_unknown`.
pub fn secrets_items(text_: &str) -> Result<Vec<Item>, Malformed> {
    let value = fc_json::parse(text_).map_err(|_| Malformed)?;
    if !matches!(value, JsValue::Object(_))
        || !matches!(value.get("version"), Some(JsValue::Number(n)) if *n == 1.0)
    {
        return Err(Malformed);
    }
    let mut out = Vec::new();
    match value.get("keys") {
        None | Some(JsValue::Null) => {}
        Some(JsValue::Object(keys)) => {
            for (name, key) in keys {
                if !name.is_well_formed() {
                    return Err(Malformed);
                }
                let policy = Policy::parse(name.as_str()).ok_or(Malformed)?;
                key_items(key, policy, &mut out)?;
            }
        }
        Some(_) => return Err(Malformed),
    }
    match value.get("forget") {
        None | Some(JsValue::Null) => {}
        Some(JsValue::Array(items)) => {
            for item in items {
                let JsValue::Object(_) = item else {
                    return Err(Malformed);
                };
                let backend = Backend::parse(text(item.get("backend"))?).ok_or(Malformed)?;
                let policy = Policy::parse(text(item.get("policy"))?).ok_or(Malformed)?;
                let id = text(item.get("item"))?;
                if !is_item_id(id) {
                    return Err(Malformed);
                }
                out.push(Item {
                    backend,
                    policy,
                    item: id.to_owned(),
                });
            }
        }
        Some(_) => return Err(Malformed),
    }
    if out.len() > MAX_ITEMS {
        return Err(Malformed);
    }
    Ok(out)
}

/// The secrets files of the profile whose data is at `data_root`, in either
/// layout: `identity/secrets.json`, and `freedom/identity/secrets.json`
/// (the move's, PRF-9).
pub fn secrets_paths(data_root: &str, style: Style) -> [String; 2] {
    [
        style.join(&[data_root, "identity", SECRETS_FILE]),
        style.join(&[data_root, "freedom", "identity", SECRETS_FILE]),
    ]
}

/// The items the profile at `data_root` names in its secrets files, each
/// once; none where there is none. `Err` when one is there but can't be
/// read, or isn't in form: what it names is unknown.
pub fn secrets_named(
    store: &mut dyn Store,
    data_root: &str,
    style: Style,
) -> Result<Vec<Item>, Malformed> {
    let mut out: Vec<Item> = Vec::new();
    for path in secrets_paths(data_root, style) {
        let Some(text) = store.read(&path).map_err(|_| Malformed)? else {
            continue;
        };
        for item in secrets_items(&text)? {
            if !out.iter().any(|seen| seen.item == item.item) {
                out.push(item);
            }
        }
    }
    Ok(out)
}

/// `forget_pending` for `profile open`: the items the forget file names. A
/// file that can't be read (`text` absent with `unreadable`), or that is
/// malformed, counts as pending, so main runs `profile forget-list`, which
/// sets it aside: `profile open` never fails over it.
pub fn forget_pending(text: Option<&str>, unreadable: bool) -> u64 {
    if unreadable {
        return 1;
    }
    let Some(text) = text else {
        return 0;
    };
    match ForgetFile::parse(text) {
        Ok(file) => u64::try_from(file.count()).unwrap_or(u64::MAX),
        Err(Malformed) => 1,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn item(n: usize) -> Item {
        Item {
            backend: Backend::MacosKeychain,
            policy: Policy::Unattended,
            item: format!("{n:032x}"),
        }
    }

    fn record(id: &str, items: usize) -> Record {
        Record {
            id: id.to_owned(),
            dir: format!("/app/Profiles/{id}"),
            items: (0..items).map(item).collect(),
        }
    }

    #[test]
    fn round_trip_and_text() {
        let file = ForgetFile {
            deleted: vec![record("work", 2)],
        };
        let text = file.text();
        assert!(
            text.starts_with(
                "{\n  \"version\": 1,\n  \"deleted\": [\n    {\n      \"id\": \"work\""
            )
        );
        assert_eq!(ForgetFile::parse(&text).unwrap(), file);
        assert_eq!(forget_pending(Some(&text), false), 2);
        assert_eq!(forget_pending(None, false), 0);
        assert_eq!(forget_pending(None, true), 1);
        assert_eq!(
            ForgetFile::parse(&ForgetFile::default().text())
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn out_of_form_is_malformed() {
        let good = r#"{"version":1,"deleted":[{"id":"w","dir":"/d","items":[{"backend":"dpapi","policy":"user_presence","item":"0123456789abcdef0123456789abcdef"}]}]}"#;
        assert!(ForgetFile::parse(good).is_ok());
        for bad in [
            "",
            "null",
            "[]",
            r#"{"version":2,"deleted":[]}"#,
            r#"{"version":1,"deleted":{}}"#,
            r#"{"version":1,"deleted":[],"x":1}"#,
            r#"{"version":1}"#,
            &good.replace("dpapi", "keyring"),
            &good.replace("user_presence", "biometric"),
            &good.replace(
                "0123456789abcdef0123456789abcdef",
                "0123456789ABCDEF0123456789abcdef",
            ),
            &good.replace(
                "0123456789abcdef0123456789abcdef",
                "0123456789abcdef0123456789abcde",
            ),
            &good.replace(r#""id":"w""#, r#""id":"W""#),
            &good.replace(r#""id":"w""#, r#""id":"""#),
            &good.replace(r#""dir":"/d""#, r#""dir":"""#),
            &good.replace(r#""dir":"/d""#, r#""dir":"\ud800""#),
            &good.replace(r#""items":["#, r#""extra":1,"items":["#),
            &good.replace(r#""item":"0"#, r#""more":1,"item":"0"#),
        ] {
            assert_eq!(ForgetFile::parse(bad), Err(Malformed), "{bad}");
            assert_eq!(forget_pending(Some(bad), false), 1, "{bad}");
        }
    }

    #[test]
    fn bounds() {
        // 16 profiles of 4 items each: within.
        let full = ForgetFile {
            deleted: (0..MAX_PROFILES)
                .map(|n| record(&format!("p{n}"), MAX_ITEMS))
                .collect(),
        };
        assert!(full.within_bounds());
        assert!(full.text().len() <= MAX_FILE_BYTES);
        assert_eq!(ForgetFile::parse(&full.text()).unwrap(), full);
        // A 17th profile, or a fifth item.
        let mut more = full.clone();
        more.deleted.push(record("p16", 1));
        assert!(!more.within_bounds());
        assert_eq!(ForgetFile::parse(&more.text()), Err(Malformed));
        let mut fifth = ForgetFile {
            deleted: vec![record("w", MAX_ITEMS)],
        };
        fifth.deleted[0].items.push(item(9));
        assert!(!fifth.within_bounds());
        assert_eq!(ForgetFile::parse(&fifth.text()), Err(Malformed));
        // A record of exactly 8 KiB is within; one byte more isn't.
        let mut long = record("w", 1);
        let base = long.value().stringify().len();
        long.dir.push_str(&"x".repeat(MAX_RECORD_BYTES - base));
        assert_eq!(long.value().stringify().len(), MAX_RECORD_BYTES);
        let file = ForgetFile {
            deleted: vec![long.clone()],
        };
        assert!(file.within_bounds());
        assert!(ForgetFile::parse(&file.text()).is_ok());
        long.dir.push('x');
        let file = ForgetFile {
            deleted: vec![long],
        };
        assert!(!file.within_bounds());
        assert_eq!(ForgetFile::parse(&file.text()), Err(Malformed));
        // Eight records of 8 KiB pass the file's 64 KiB.
        let mut big = record("w", 0);
        big.dir
            .push_str(&"x".repeat(MAX_RECORD_BYTES - big.value().stringify().len()));
        let file = ForgetFile {
            deleted: (0..8)
                .map(|n| Record {
                    id: format!("p{n}"),
                    ..big.clone()
                })
                .collect(),
        };
        assert!(file.text().len() > MAX_FILE_BYTES);
        assert!(!file.within_bounds());
        assert_eq!(ForgetFile::parse(&file.text()), Err(Malformed));
    }

    #[test]
    fn remove_drop_and_live() {
        let mut file = ForgetFile {
            deleted: vec![record("a", 2), record("b", 1)],
        };
        // The same id in two records (a copy of a profile): listed once.
        assert_eq!(file.live().len(), 2);
        assert_eq!(file.remove(&[item(0).item]), 2);
        assert_eq!(file.deleted.len(), 1);
        assert_eq!(file.remove(&[item(7).item]), 0);
        assert_eq!(file.remove(&[item(1).item]), 1);
        assert!(file.deleted.is_empty());

        let mut file = ForgetFile {
            deleted: vec![record("a", 1)],
        };
        assert!(!file.drop_foreign(Some(Backend::MacosKeychain)));
        assert!(file.drop_foreign(Some(Backend::SecretService)));
        assert!(file.deleted.is_empty());
        let mut file = ForgetFile {
            deleted: vec![record("a", 1)],
        };
        assert!(file.drop_foreign(None));
    }

    #[test]
    fn secrets_files() {
        let id = |c: char| c.to_string().repeat(32);
        let text = format!(
            r#"{{"version":1,"keys":{{"unattended":{{"backend":"macos-keychain","item":"{}","sealed":null,"pending":{{"backend":"macos-keychain","item":"{}"}}}},"user_presence":{{"backend":"macos-keychain","item":null,"pending":null}}}},"forget":[{{"backend":"macos-keychain","policy":"user_presence","item":"{}"}}],"entries":{{}}}}"#,
            id('a'),
            id('b'),
            id('c')
        );
        let items = secrets_items(&text).unwrap();
        let ids: Vec<&str> = items.iter().map(|i| i.item.as_str()).collect();
        assert_eq!(ids, [id('a'), id('b'), id('c')]);
        assert_eq!(items[2].policy, Policy::UserPresence);
        assert_eq!(secrets_items(r#"{"version":1}"#).unwrap(), Vec::new());
        for bad in [
            "{",
            "[]",
            r#"{"version":2}"#,
            r#"{"version":1,"keys":[]}"#,
            r#"{"version":1,"keys":{"other":{"backend":"dpapi","item":null}}}"#,
            r#"{"version":1,"keys":{"unattended":{"backend":"dpapi","item":"x"}}}"#,
            r#"{"version":1,"forget":{}}"#,
            r#"{"version":1,"forget":[{"backend":"dpapi","policy":"unattended"}]}"#,
        ] {
            assert_eq!(secrets_items(bad), Err(Malformed), "{bad}");
        }
        // Five items are past the secrets file's bound.
        let five = format!(
            r#"{{"version":1,"forget":[{}]}}"#,
            (0..5)
                .map(|n| format!(
                    r#"{{"backend":"dpapi","policy":"unattended","item":"{n:032x}"}}"#
                ))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(secrets_items(&five), Err(Malformed));
    }
}
