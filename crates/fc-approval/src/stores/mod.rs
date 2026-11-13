//! The four grant files and their codecs (design 0012, "The files (Q10)").
//!
//! The core takes the files over where they are, in today's format, byte
//! for byte: each store keeps its file's object as JS left it (every field,
//! the ones it doesn't know included, in JS's key order), changes it as the
//! reference's store does, and writes `JSON.stringify(…, null, 2)`'s text.
//! `vectors/approvals.json`'s `stores`, produced from the reference's
//! stores, pins the text after each operation.
//!
//! A file is read as the reference reads it: its bytes as Node decodes
//! UTF-8 (an invalid sequence is U+FFFD), then `JSON.parse` (fc-json's
//! [`JsValue`]): every number a double, so `1e400` is `Infinity` and is
//! written `null`, and every double written as ECMAScript writes it; lone
//! surrogates kept; a repeated key in its first place with its last
//! value. Where the reference compares, subtracts or sorts a field it finds
//! there (a `lastUsed`, an `expiresAt`), the core coerces it as JS does
//! (`ToNumber`, V8's sort).
//!
//! The crate does no I/O (AGENTS rule 2). A store is read from its file's
//! bytes ([`DappStore::load`] and the others), changed in memory, and
//! written as [`DappStore::text`] gives it. The daemon writes the text with
//! 0001's single-file write. What a failed write leaves is the daemon's to
//! decide by each change's [`Effect`]: a widening that isn't written isn't
//! applied, a narrowing is (design 0012, "The files": "A failed write").
//! So the daemon changes a copy, writes its text, and keeps the copy once
//! the write succeeds, or at once for a narrowing.
//!
//! What differs from the reference (design 0012, Deviations):
//! - `file-unreadable`: a file that isn't a JSON object of objects (the
//!   reference loads `{}` for one that doesn't parse, and keeps whatever
//!   parses) is [`Unreadable`]: the daemon renames it aside and starts the
//!   store empty. x402's file is read as the reference reads it, dropping
//!   what isn't a live cap (its codec, [`CapStore::load`]).
//! - `file-bounds`: [`MAX_FILE_BYTES`], [`MAX_KEYS`] and
//!   [`MAX_TRANSACTION_RULES`]. A file past one is unreadable, and a change
//!   that would pass one is refused ([`Refused`]).
//! - A key is the permission key as main attests it (0011's `key`,
//!   `PageContext.origin`), which main normalizes; the core doesn't
//!   normalize it again.

mod caps;
mod dapp;
mod radicle;
mod swarm;

pub use caps::CapStore;
pub use dapp::{DappStore, LIMITED_FIELD, RULE_TTL_MS, SigningRule, TransactionRule};
pub use fc_json::{JsString, JsValue, ToPrimitiveError};
pub use radicle::{RadicleFlag, RadicleStore};
pub use swarm::{SwarmFlag, SwarmStore};

use crate::js;

/// `JSON.stringify(value, null, 2)`: a record's text as the reference
/// writes it, so two values JS holds alike compare alike.
pub fn js_text(value: &JsValue) -> String {
    value.stringify_pretty()
}

/// The most a grant file may hold, in bytes (4 MiB).
pub const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;

/// The most keys (sites) a store may hold.
pub const MAX_KEYS: usize = 4096;

/// The most transaction rules one key may hold: today's
/// (`autoApprove.transactions`) and Q9's limited ones
/// (`autoApprove.limited.transactions`) counted together.
pub const MAX_TRANSACTION_RULES: usize = 256;

/// The four stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreKind {
    Dapp,
    Swarm,
    Radicle,
    X402,
}

impl StoreKind {
    pub const ALL: [StoreKind; 4] = [
        StoreKind::Dapp,
        StoreKind::Swarm,
        StoreKind::Radicle,
        StoreKind::X402,
    ];

    /// The store's name on the wire (`approval.grant`'s `store`).
    pub fn name(self) -> &'static str {
        match self {
            StoreKind::Dapp => "dapp",
            StoreKind::Swarm => "swarm",
            StoreKind::Radicle => "radicle",
            StoreKind::X402 => "x402",
        }
    }

    pub fn from_name(name: &str) -> Option<StoreKind> {
        StoreKind::ALL.into_iter().find(|kind| kind.name() == name)
    }

    /// The file's name in the profile's `userData` (`grant_root`).
    pub fn file_name(self) -> &'static str {
        match self {
            StoreKind::Dapp => "dapp-permissions.json",
            StoreKind::Swarm => "swarm-permissions.json",
            StoreKind::Radicle => "radicle-permissions.json",
            StoreKind::X402 => "x402-permissions.json",
        }
    }
}

/// Why a file is read as unreadable: the daemon renames it aside
/// (`<name>.unreadable`) once, and the store starts empty
/// (`file-unreadable`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unreadable {
    #[error("the file is larger than {MAX_FILE_BYTES} bytes")]
    TooLarge,
    /// Not UTF-8 JSON, or nested deeper than the parser reads.
    #[error("the file is not JSON")]
    NotJson,
    #[error("the file is not a JSON object")]
    NotObject,
    #[error("a site's entry is not a JSON object")]
    EntryNotObject,
    #[error("the file holds more than {MAX_KEYS} sites")]
    TooManyKeys,
    #[error("a site holds more than {MAX_TRANSACTION_RULES} transaction rules")]
    TooManyRules,
    /// The reference's own load throws on it, and reads the store as empty
    /// (x402: an origin whose caps are `null`, or an `expiresAt` that can't
    /// be converted to a number).
    #[error("the reference's load fails on the file")]
    LoadFails,
}

/// A change refused because the store would pass a bound: nothing is
/// written, and the store is unchanged (`invalid_argument`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("the file would be larger than {MAX_FILE_BYTES} bytes")]
    TooLarge,
    #[error("the store would hold more than {MAX_KEYS} sites")]
    TooManyKeys,
    #[error("the site would hold more than {MAX_TRANSACTION_RULES} transaction rules")]
    TooManyRules,
}

/// What a change does to the authority a store grants, for the daemon's
/// handling of a failed write (design 0012, "The files").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Nothing changed, and the reference writes nothing: there is nothing
    /// to save.
    Unchanged,
    /// A new grant, rule or tier, or another account exposed: applied only
    /// once written.
    Widening,
    /// A revoke, or a rule or tier turned off: applied at once, and reported
    /// as not saved when its write fails.
    Narrowing,
    /// Neither (a site's last use, its chain): kept in memory as a
    /// narrowing is, since it grants nothing.
    Neutral,
}

/// A change's result, and its [`Effect`].
#[derive(Debug, Clone, PartialEq)]
pub struct Applied<T> {
    pub value: T,
    pub effect: Effect,
}

impl<T> Applied<T> {
    fn new(value: T, effect: Effect) -> Self {
        Applied { value, effect }
    }
}

/// A file's top-level object, read as the reference reads it
/// (`JSON.parse(fs.readFileSync(file, 'utf-8'))`) within
/// [`MAX_FILE_BYTES`].
fn parse(bytes: &[u8]) -> Result<JsValue, Unreadable> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Unreadable::TooLarge);
    }
    // Node decodes as the WHATWG decoder does: each maximal invalid
    // subpart is one U+FFFD, as `from_utf8_lossy` replaces it.
    let text = String::from_utf8_lossy(bytes);
    match fc_json::parse(&text) {
        Ok(object @ JsValue::Object(_)) => Ok(object),
        Ok(_) => Err(Unreadable::NotObject),
        Err(_) => Err(Unreadable::NotJson),
    }
}

/// A site-keyed file (dApp, Swarm, Radicle): every entry an object, at most
/// [`MAX_KEYS`] of them.
fn parse_sites(bytes: &[u8]) -> Result<JsValue, Unreadable> {
    let map = parse(bytes)?;
    if props(&map).len() > MAX_KEYS {
        return Err(Unreadable::TooManyKeys);
    }
    if props(&map)
        .iter()
        .any(|(_, entry)| !matches!(entry, JsValue::Object(_)))
    {
        return Err(Unreadable::EntryNotObject);
    }
    Ok(map)
}

/// The file's text, within [`MAX_KEYS`] and [`MAX_FILE_BYTES`].
fn text_of(map: &JsValue) -> Result<String, Refused> {
    if props(map).len() > MAX_KEYS {
        return Err(Refused::TooManyKeys);
    }
    let text = map.stringify_pretty();
    if text.len() > MAX_FILE_BYTES {
        return Err(Refused::TooLarge);
    }
    Ok(text)
}

/// A new, empty object.
fn object() -> JsValue {
    JsValue::Object(Vec::new())
}

/// An object's own properties, in JS's order (none for another value).
fn props(value: &JsValue) -> &[(JsString, JsValue)] {
    match value {
        JsValue::Object(props) => props,
        _ => &[],
    }
}

/// An array's items, to change in place.
fn items_mut(value: &mut JsValue) -> Option<&mut Vec<JsValue>> {
    match value {
        JsValue::Array(items) => Some(items),
        _ => None,
    }
}

/// `delete object[key]`: the property, if the object had it. The others
/// keep their order.
fn remove(object: &mut JsValue, key: &str) -> Option<JsValue> {
    let JsValue::Object(props) = object else {
        return None;
    };
    let at = props.iter().position(|(k, _)| k == key)?;
    Some(props.remove(at).1)
}

/// JS's truthiness of a field: absent, `null`, `false`, `0`, `NaN` and
/// `""` are falsy, every other value (an empty array or object included)
/// truthy.
fn truthy(value: Option<&JsValue>) -> bool {
    value.is_some_and(JsValue::truthy)
}

/// JS's `value === n` for a number.
fn number_is(value: Option<&JsValue>, n: f64) -> bool {
    matches!(value, Some(JsValue::Number(v)) if *v == n)
}

/// A wall-clock time in milliseconds, or a chain or account number, as JS
/// keeps it: a double.
fn number(n: u64) -> JsValue {
    JsValue::Number(n as f64)
}

/// `object.field = value`, as JS assigns it: replaced where it stands, or
/// added where JS adds it. A field of a value that isn't an object can't be
/// set (JS ignores the assignment, and its text doesn't change).
fn assign(target: &mut JsValue, field: &str, value: JsValue) {
    target.set(field, value);
}

/// `if (!entry.autoApprove) entry.autoApprove = default();` then
/// `entry.autoApprove[flag] = enabled`, as each store sets a rule.
fn set_auto_approve(entry: &mut JsValue, default: fn() -> JsValue, flag: &str, enabled: bool) {
    if !truthy(entry.get("autoApprove")) {
        assign(entry, "autoApprove", default());
    }
    if let Some(rules) = entry.get_mut("autoApprove") {
        assign(rules, flag, JsValue::Bool(enabled));
    }
}

/// `Object.values(permissions).sort((a, b) => b.lastUsed - a.lastUsed)`: the
/// reference's `getAllPermissions`, most recent first.
///
/// As JS runs it: each `lastUsed` through `ToNumber` (a numeric string is
/// its number, a missing one `NaN`), a comparison that comes to `NaN` read
/// as equal, and V8's own sort, on which the place of such an entry
/// depends. A `lastUsed` that can't be converted (an object with its own
/// `toString`) throws, as the reference's does, once there are two entries
/// to compare.
fn records_by_last_used(map: &JsValue) -> Result<Vec<&JsValue>, ToPrimitiveError> {
    let records: Vec<&JsValue> = props(map).iter().map(|(_, entry)| entry).collect();
    if records.len() < 2 {
        return Ok(records);
    }
    let last_used = records
        .iter()
        .map(|entry| js::to_number(entry.get("lastUsed").unwrap_or(&JsValue::Undefined)))
        .collect::<Result<Vec<f64>, _>>()?;
    let mut order: Vec<usize> = (0..records.len()).collect();
    js::sort(&mut order, |a, b| last_used[b] - last_used[a]);
    Ok(order.into_iter().map(|index| records[index]).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(map: Result<JsValue, Unreadable>) -> Result<usize, Unreadable> {
        map.map(|map| props(&map).len())
    }

    #[test]
    fn unreadable_files() {
        assert_eq!(keys(parse_sites(b"not json")), Err(Unreadable::NotJson));
        assert_eq!(keys(parse_sites(b"[]")), Err(Unreadable::NotObject));
        assert_eq!(
            keys(parse_sites(b"{\"a\":5}")),
            Err(Unreadable::EntryNotObject)
        );
        assert_eq!(keys(parse_sites(b"{\"a\":{}}")), Ok(1));
        assert_eq!(
            keys(parse_sites(&[b' '; MAX_FILE_BYTES + 1])),
            Err(Unreadable::TooLarge)
        );
        // A byte-order mark: JSON.parse refuses it.
        assert_eq!(
            keys(parse_sites(b"\xef\xbb\xbf{}")),
            Err(Unreadable::NotJson)
        );
    }

    #[test]
    fn bytes_as_node_decodes_them() {
        // Invalid UTF-8 inside a string: U+FFFD, as Node reads it.
        let map = parse_sites(b"{\"a\":{\"b\":\"\xff\xed\xa0\x80\"}}").unwrap();
        assert_eq!(
            map.get("a")
                .and_then(|a| a.get("b"))
                .and_then(JsValue::as_str),
            Some("\u{fffd}\u{fffd}\u{fffd}\u{fffd}")
        );
    }

    #[test]
    fn numbers_as_js_reads_and_writes_them() {
        let map = parse_sites(
            b"{\"a\":{\"tie\":1507408564916634.25,\"big\":1e400,\"neg\":-0,\"e\":1E21,\"i\":9007199254740993}}",
        )
        .unwrap();
        assert_eq!(
            text_of(&map).unwrap(),
            "{\n  \"a\": {\n    \"tie\": 1507408564916634.2,\n    \"big\": null,\n    \"neg\": 0,\n    \"e\": 1e+21,\n    \"i\": 9007199254740992\n  }\n}"
        );
    }

    #[test]
    fn file_bound_exactly() {
        // A file of exactly MAX_FILE_BYTES is read.
        let mut text = b"{}".to_vec();
        text.resize(MAX_FILE_BYTES, b' ');
        assert_eq!(keys(parse_sites(&text)), Ok(0));
    }

    #[test]
    fn keys_bound() {
        let mut map = object();
        for index in 0..MAX_KEYS {
            map.set(format!("k{index}"), object());
        }
        let text = text_of(&map).unwrap();
        assert_eq!(keys(parse_sites(text.as_bytes())), Ok(MAX_KEYS));
        map.set("one more", object());
        assert_eq!(text_of(&map), Err(Refused::TooManyKeys));
        let past = map.stringify_pretty();
        assert_eq!(
            keys(parse_sites(past.as_bytes())),
            Err(Unreadable::TooManyKeys)
        );
    }

    #[test]
    fn truthiness() {
        let values: [(&str, bool); 9] = [
            ("null", false),
            ("false", false),
            ("0", false),
            ("-0", false),
            ("\"\"", false),
            ("true", true),
            ("1", true),
            ("[]", true),
            ("{}", true),
        ];
        for (text, expected) in values {
            let value = fc_json::parse(text).unwrap();
            assert_eq!(truthy(Some(&value)), expected, "{text}");
        }
        assert!(!truthy(None));
    }

    #[test]
    fn records_sorted_as_v8_sorts_them() {
        // An entry without `lastUsed` compares equal to every other: V8's
        // sort leaves it first here, where a sort that puts the
        // non-numbers last would move it.
        let map = parse_sites(
            b"{\"a\":{},\"b\":{\"lastUsed\":1},\"c\":{\"lastUsed\":\"3\"},\"d\":{\"lastUsed\":2}}",
        )
        .unwrap();
        let order: Vec<String> = records_by_last_used(&map)
            .unwrap()
            .iter()
            .map(|entry| entry.stringify())
            .collect();
        assert_eq!(
            order,
            [
                "{}",
                "{\"lastUsed\":\"3\"}",
                "{\"lastUsed\":2}",
                "{\"lastUsed\":1}"
            ]
        );
        let lone = parse_sites(b"{\"a\":{\"lastUsed\":{\"toString\":1}}}").unwrap();
        assert_eq!(records_by_last_used(&lone).map(|r| r.len()), Ok(1));
        let two = parse_sites(b"{\"a\":{\"lastUsed\":{\"toString\":1}},\"b\":{}}").unwrap();
        assert_eq!(records_by_last_used(&two), Err(ToPrimitiveError));
    }
}
