//! `x402-permissions.json` (the reference's `x402/permissions.js`): its
//! codec. The caps' operations are X402-1's.
//!
//! `origin → "<chainId>:<asset>" → { capAmount, spentAmount, createdAt,
//! expiresAt }`, amounts as decimal strings, times in wall-clock seconds.
//! The reference drops expired caps as it reads the file
//! (`compactExpired`), in memory, so the file loses them at its next write.

use super::{JsString, JsValue, MAX_KEYS, Refused, Unreadable, object, parse, props, text_of};
use crate::js;

/// The x402 cap store.
#[derive(Debug, Clone, PartialEq)]
pub struct CapStore {
    entries: JsValue,
}

impl Default for CapStore {
    fn default() -> Self {
        CapStore { entries: object() }
    }
}

impl CapStore {
    pub fn new() -> Self {
        CapStore::default()
    }

    /// The store as its file's bytes give it at `now_s` (the wall clock, in
    /// seconds), as the reference's `compactExpired` reads it: every cap
    /// for which `record?.expiresAt > now` holds, in the file's order, and
    /// every origin left with one. JS's coercions apply: an origin's caps
    /// are `Object.entries` of whatever the origin holds (an array's by
    /// index, nothing of a string's or a number's), and `expiresAt` goes
    /// through `ToNumber` (a numeric string is its number; a missing or
    /// non-numeric one is `NaN`, and the cap is dropped).
    ///
    /// A file past [`MAX_KEYS`] origins is unreadable however many of them
    /// compaction would drop. Where the reference's load throws (an
    /// origin's caps `null`, an `expiresAt` that can't be converted), and
    /// so reads the store as empty, the file is unreadable
    /// ([`Unreadable::LoadFails`]).
    pub fn load(bytes: &[u8], now_s: u64) -> Result<Self, Unreadable> {
        let file = parse(bytes)?;
        if props(&file).len() > MAX_KEYS {
            return Err(Unreadable::TooManyKeys);
        }
        let now = now_s as f64;
        let mut entries = object();
        for (origin, caps) in props(&file) {
            let mut active = object();
            for (key, record) in own_entries(caps)? {
                if live(&record, now)? {
                    active.set(key, record);
                }
            }
            if !props(&active).is_empty() {
                entries.set(origin.clone(), active);
            }
        }
        Ok(CapStore { entries })
    }

    pub fn text(&self) -> Result<String, Refused> {
        text_of(&self.entries)
    }

    /// Every cap as the file holds it: its origin, its `"<chainId>:<asset>"`
    /// key and its record, in the file's order.
    pub fn caps(&self) -> impl Iterator<Item = (&str, &str, &JsValue)> {
        props(&self.entries).iter().flat_map(|(origin, caps)| {
            props(caps)
                .iter()
                .map(move |(key, record)| (origin.as_str(), key.as_str(), record))
        })
    }
}

/// `Object.entries(value)` of an origin's caps: an object's own properties,
/// an array's items by index, a string's code units (none of which is a
/// record); none of a number or a boolean. `null` throws.
fn own_entries(value: &JsValue) -> Result<Vec<(JsString, JsValue)>, Unreadable> {
    Ok(match value {
        JsValue::Null | JsValue::Undefined => return Err(Unreadable::LoadFails),
        JsValue::Object(props) => props.clone(),
        JsValue::Array(items) => items
            .iter()
            .enumerate()
            .map(|(index, item)| (JsString::from(index.to_string()), item.clone()))
            .collect(),
        // A string's units are strings, whose `expiresAt` is undefined: none
        // is kept.
        JsValue::String(_) | JsValue::Number(_) | JsValue::Bool(_) => Vec::new(),
    })
}

/// `record?.expiresAt > now`, by JS's relational comparison: only an
/// object has an own `expiresAt`, which goes through `ToNumber`; `NaN`
/// compares false.
fn live(record: &JsValue, now: f64) -> Result<bool, Unreadable> {
    let JsValue::Object(_) = record else {
        return Ok(false);
    };
    let Some(expires) = record.get("expiresAt") else {
        return Ok(false);
    };
    let expires = js::to_number(expires).map_err(|_| Unreadable::LoadFails)?;
    Ok(expires > now)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const NOW_S: u64 = 1_762_000_000;

    /// A file of `origins` origins, each holding `caps` as its JSON text.
    fn file(origins: usize, caps: &str) -> String {
        let entries: Vec<String> = (0..origins)
            .map(|index| format!("\"https://site{index}.example\": {caps}"))
            .collect();
        format!("{{{}}}", entries.join(","))
    }

    fn expired() -> String {
        format!(
            "{{\"8453:0xa\": {{\"capAmount\": \"1\", \"spentAmount\": \"0\", \"createdAt\": 1, \"expiresAt\": {NOW_S}}}}}"
        )
    }

    #[test]
    fn the_key_bound_counts_before_compaction() {
        // Exactly 4,096 origins, every cap expired: read, and empty.
        let exact = CapStore::load(file(MAX_KEYS, &expired()).as_bytes(), NOW_S).unwrap();
        assert_eq!(exact.caps().count(), 0);
        assert_eq!(exact.text().unwrap(), "{}");
        // One more: unreadable, though compaction would leave none.
        assert_eq!(
            CapStore::load(file(MAX_KEYS + 1, &expired()).as_bytes(), NOW_S),
            Err(Unreadable::TooManyKeys)
        );
        // Origins whose caps aren't records, which compaction drops too.
        assert_eq!(
            CapStore::load(file(MAX_KEYS, "\"not caps\"").as_bytes(), NOW_S)
                .unwrap()
                .caps()
                .count(),
            0
        );
        assert_eq!(
            CapStore::load(file(MAX_KEYS + 1, "\"not caps\"").as_bytes(), NOW_S),
            Err(Unreadable::TooManyKeys)
        );
        // A repeated origin is one key, as JSON.parse holds it.
        let mut repeated = file(MAX_KEYS, &expired());
        repeated.insert_str(1, &format!("\"https://site0.example\": {},", expired()));
        assert!(CapStore::load(repeated.as_bytes(), NOW_S).is_ok());
    }

    #[test]
    fn expiry_coerced_as_js_compares_it() {
        let cap = |expires: &str| {
            format!(
                "{{\"o\": {{\"1:0xa\": {{\"capAmount\": \"1\", \"spentAmount\": \"0\", \"createdAt\": 1, \"expiresAt\": {expires}}}}}}}"
            )
        };
        let live = |expires: &str| {
            CapStore::load(cap(expires).as_bytes(), 100).map(|store| store.caps().count() == 1)
        };
        assert_eq!(live("\"101\""), Ok(true));
        assert_eq!(live("\"100\""), Ok(false));
        assert_eq!(live("[101]"), Ok(true));
        assert_eq!(live("\" 0x65 \""), Ok(true));
        assert_eq!(live("1e400"), Ok(true));
        assert_eq!(live("\"abc\""), Ok(false));
        assert_eq!(live("null"), Ok(false));
        assert_eq!(live("{}"), Ok(false));
        assert_eq!(live("{\"toString\": 1}"), Err(Unreadable::LoadFails));
        // An origin's caps as an array: its records by index.
        let array = "{\"o\": [{\"capAmount\": \"1\", \"spentAmount\": \"0\", \"createdAt\": 1, \"expiresAt\": 101}]}";
        let store = CapStore::load(array.as_bytes(), 100).unwrap();
        assert_eq!(
            store
                .caps()
                .map(|(origin, key, _)| (origin, key))
                .collect::<Vec<_>>(),
            [("o", "0")]
        );
        assert_eq!(
            CapStore::load(b"{\"o\": null}", 100),
            Err(Unreadable::LoadFails)
        );
    }
}
