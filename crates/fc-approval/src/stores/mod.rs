//! The four grant files and their codecs (design 0012, "The files (Q10)").
//!
//! The core takes the files over where they are, in today's format, byte
//! for byte: each store keeps its file's object as JS left it (every field,
//! the ones it doesn't know included, in JS's key order), changes it as the
//! reference's store does, and writes `JSON.stringify(…, null, 2)`'s text.
//! `vectors/approvals.json`'s `stores`, produced from the reference's
//! stores, pins the text after each operation.
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
pub use radicle::{RadicleFlag, RadicleStore};
pub use swarm::{SwarmFlag, SwarmStore};

use serde_json::{Map, Value};

use crate::json;

/// `JSON.stringify(value, null, 2)`: a record's text as the reference
/// writes it, so two values JS holds alike (`1.0` and `1`, or keys inserted
/// in another order where JS lists array indices first) compare alike.
pub fn js_text(value: &Value) -> String {
    json::stringify(value)
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

/// A file's top-level object, parsed as JSON within [`MAX_FILE_BYTES`].
fn parse(bytes: &[u8]) -> Result<Map<String, Value>, Unreadable> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Unreadable::TooLarge);
    }
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(Unreadable::NotObject),
        Err(_) => Err(Unreadable::NotJson),
    }
}

/// A site-keyed file (dApp, Swarm, Radicle): every entry an object, at most
/// [`MAX_KEYS`] of them.
fn parse_sites(bytes: &[u8]) -> Result<Map<String, Value>, Unreadable> {
    let map = parse(bytes)?;
    if map.len() > MAX_KEYS {
        return Err(Unreadable::TooManyKeys);
    }
    if map.values().any(|entry| !entry.is_object()) {
        return Err(Unreadable::EntryNotObject);
    }
    Ok(map)
}

/// The file's text, within [`MAX_KEYS`] and [`MAX_FILE_BYTES`].
fn text_of(map: &Map<String, Value>) -> Result<String, Refused> {
    if map.len() > MAX_KEYS {
        return Err(Refused::TooManyKeys);
    }
    let text = json::stringify_object(map);
    if text.len() > MAX_FILE_BYTES {
        return Err(Refused::TooLarge);
    }
    Ok(text)
}

/// JS's truthiness of a field: absent, `null`, `false`, `0` and `""` are
/// falsy, every other value (an empty array or object included) truthy.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|n| n != 0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(_) | Value::Object(_)) => true,
    }
}

/// JS's `value === n` for a number.
fn number_is(value: Option<&Value>, n: f64) -> bool {
    value.and_then(Value::as_f64) == Some(n)
}

/// A wall-clock time in milliseconds, or a chain or account number, as JS
/// keeps it: a double.
fn number(n: u64) -> Value {
    Value::from(n)
}

/// `object.field = value`, as JS assigns it: replaced where it stands, or
/// added last. A field of a value that isn't an object can't be set (JS
/// ignores the assignment, and its text doesn't change).
fn assign(target: &mut Value, field: &str, value: Value) {
    if let Value::Object(map) = target {
        map.insert(field.to_owned(), value);
    }
}

/// `if (!entry.autoApprove) entry.autoApprove = default();` then
/// `entry.autoApprove[flag] = enabled`, as each store sets a rule.
fn set_auto_approve(entry: &mut Value, default: fn() -> Value, flag: &str, enabled: bool) {
    if !truthy(entry.get("autoApprove")) {
        assign(entry, "autoApprove", default());
    }
    if let Some(rules) = entry.get_mut("autoApprove") {
        assign(rules, flag, Value::Bool(enabled));
    }
}

/// `Object.values(permissions).sort((a, b) => b.lastUsed - a.lastUsed)`: the
/// reference's `getAllPermissions`, a stable sort, most recent first. An
/// entry without a numeric `lastUsed` sorts last (JS compares it as equal to
/// every other).
fn records_by_last_used(map: &Map<String, Value>) -> Vec<&Value> {
    let mut records: Vec<&Value> = map.values().collect();
    let last_used = |entry: &Value| entry.get("lastUsed").and_then(Value::as_f64);
    records.sort_by(|a, b| match (last_used(a), last_used(b)) {
        (Some(a), Some(b)) => b.partial_cmp(&a).unwrap_or(std::cmp::Ordering::Equal),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreadable_files() {
        assert_eq!(parse_sites(b"not json"), Err(Unreadable::NotJson));
        assert_eq!(parse_sites(b"[]"), Err(Unreadable::NotObject));
        assert_eq!(parse_sites(b"{\"a\":5}"), Err(Unreadable::EntryNotObject));
        assert_eq!(parse_sites(b"{\"a\":{}}").map(|m| m.len()), Ok(1));
        assert_eq!(
            parse_sites(&[b' '; MAX_FILE_BYTES + 1]),
            Err(Unreadable::TooLarge)
        );
        // Invalid UTF-8 inside a string.
        assert_eq!(
            parse_sites(b"{\"a\":{\"b\":\"\xff\"}}"),
            Err(Unreadable::NotJson)
        );
    }

    #[test]
    fn file_bound_exactly() {
        // A file of exactly MAX_FILE_BYTES is read.
        let mut text = b"{}".to_vec();
        text.resize(MAX_FILE_BYTES, b' ');
        assert_eq!(parse_sites(&text).map(|m| m.len()), Ok(0));
    }

    #[test]
    fn keys_bound() {
        let mut map = Map::new();
        for index in 0..MAX_KEYS {
            map.insert(format!("k{index}"), Value::Object(Map::new()));
        }
        let text = text_of(&map).unwrap();
        assert_eq!(parse_sites(text.as_bytes()).map(|m| m.len()), Ok(MAX_KEYS));
        map.insert("one more".to_owned(), Value::Object(Map::new()));
        assert_eq!(text_of(&map), Err(Refused::TooManyKeys));
        let past = json::stringify_object(&map);
        assert_eq!(parse_sites(past.as_bytes()), Err(Unreadable::TooManyKeys));
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
            let value: Value = serde_json::from_str(text).unwrap();
            assert_eq!(truthy(Some(&value)), expected, "{text}");
        }
        assert!(!truthy(None));
    }
}
