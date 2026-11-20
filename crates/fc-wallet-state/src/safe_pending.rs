//! `safe-pending.json` (the reference's `wallet/safe/pending-store.js`):
//! the half-signed Safe transactions that outlive a restart, one per Safe.
//!
//! `{ [walletIndex]: entry }`: each key a Safe's wallet index, each entry
//! the object main keeps for its pending SafeTx (`chainId`, `safeAddress`,
//! `safeTxData`, `safeTxHash`, `typedData`, `threshold`, `signatures`,
//! `createdAt`, and later `display` and `executed`). The core keeps each
//! entry as JS left it, every field in JS's property order, and doesn't
//! read one: the entries are main's.
//!
//! The operations are the reference's four, with its answers: [`get`]
//! (`getPending`: the entry, or none for a falsy one), [`set`]
//! (`setPending`: the file written after every set), [`clear`]
//! (`clearPending`: written only when the index had an entry) and [`list`]
//! (`listPendingIndexes`). A key is the index's decimal text, so JS puts
//! the array indices first, in ascending order, then the larger indices in
//! the order they were set (fc-json's `set`). The text written is
//! `JSON.stringify(store, null, 2)`, no trailing newline. A file is read as
//! the reference reads it: its bytes as Node decodes UTF-8 (an invalid
//! sequence is U+FFFD), then `JSON.parse` (fc-json).
//!
//! What differs from the reference (design 0013, Deviations):
//! - `safe-pending-unreadable`: a file outside this shape is
//!   [`Unreadable`]: the daemon renames it aside and reports it, and the
//!   store reads as empty. The shape: JSON within [`MAX_FILE_BYTES`] and
//!   fc-json's nesting limit, with no byte-order mark; an object; each key
//!   the decimal text of a wallet index, 0 to [`MAX_INDEX`], as the
//!   reference writes one (no sign, no leading zero). The reference has no
//!   bound and no key check: a file that doesn't parse reads as `{}`, and
//!   its next write replaces it; `null` makes every operation throw a
//!   `TypeError`; an array or a string is read by index; another primitive
//!   reads as empty, and a set on it writes it back unchanged; a key that
//!   isn't an index's text is listed as `Number(key)` (`NaN` for a word)
//!   and found by no index. No reference writer makes any of these.
//!   `stores.json`'s `safe_pending.malformed` pins each.
//! - The 1 MiB bound: a set whose file would be past it, or that the core
//!   couldn't read back, is refused and changes nothing (the reference
//!   writes any size). `stores.json`'s `safe_pending.bound` pins the edge.
//!
//! [`get`]: SafePending::get
//! [`set`]: SafePending::set
//! [`clear`]: SafePending::clear
//! [`list`]: SafePending::list

use fc_json::{JsString, JsValue};

/// The file's name at the Freedom root.
pub const FILE_NAME: &str = "safe-pending.json";

/// The largest file the core reads (design 0013, Bounds: `source:
/// design`). A file past it is unreadable, and a set that would pass it is
/// refused.
pub const MAX_FILE_BYTES: usize = 1024 * 1024;

/// The largest wallet index a key names: `Number.MAX_SAFE_INTEGER`, the
/// largest integer whose decimal text a JS number keeps exactly.
pub const MAX_INDEX: u64 = (1 << 53) - 1;

/// Why a file is unreadable (`safe-pending-unreadable`), or why a set is
/// refused (the file it would write is): the daemon renames an unreadable
/// file aside and reports it, and the store reads as empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unreadable {
    #[error("the file is larger than {MAX_FILE_BYTES} bytes")]
    TooLarge,
    /// Not JSON (a byte-order mark included): the reference reads `{}`.
    /// Or nested deeper than fc-json reads (512 levels), which the
    /// reference reads as it would any object (a resource limit).
    #[error("the file is not JSON")]
    NotJson,
    #[error("the file is not a JSON object")]
    NotObject,
    #[error("a key is not a wallet index")]
    KeyNotIndex,
}

impl Unreadable {
    /// Its name in the vectors (`reason`).
    pub fn reason(self) -> &'static str {
        match self {
            Unreadable::TooLarge => "too_large",
            Unreadable::NotJson => "not_json",
            Unreadable::NotObject => "not_object",
            Unreadable::KeyNotIndex => "key_not_index",
        }
    }
}

/// `safe-pending.json`'s object; empty when there is no file.
#[derive(Debug, Clone, PartialEq)]
pub struct SafePending {
    /// Always an object, each key an index's text.
    store: JsValue,
}

impl Default for SafePending {
    fn default() -> Self {
        SafePending {
            store: JsValue::Object(Vec::new()),
        }
    }
}

/// The key of `index`: its decimal text, as JS's `ToString` gives it.
fn key(index: u64) -> String {
    index.to_string()
}

/// The index a key names: the decimal text of 0 to [`MAX_INDEX`], with no
/// sign or leading zero.
fn index_of(key: &JsString) -> Option<u64> {
    let index: u64 = key.parse().ok()?;
    (index <= MAX_INDEX && *key == index.to_string()).then_some(index)
}

impl SafePending {
    /// No file: `{}`.
    pub fn empty() -> Self {
        SafePending::default()
    }

    /// The store as its file's bytes give it.
    pub fn load(bytes: &[u8]) -> Result<Self, Unreadable> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(Unreadable::TooLarge);
        }
        // Node decodes as the WHATWG decoder does: each maximal invalid
        // subpart is one U+FFFD, as `from_utf8_lossy` replaces it.
        let text = String::from_utf8_lossy(bytes);
        let store = fc_json::parse(&text).map_err(|_| Unreadable::NotJson)?;
        let JsValue::Object(props) = &store else {
            return Err(Unreadable::NotObject);
        };
        if props.iter().any(|(key, _)| index_of(key).is_none()) {
            return Err(Unreadable::KeyNotIndex);
        }
        Ok(SafePending { store })
    }

    /// The file's text, as the reference writes it
    /// (`JSON.stringify(store, null, 2)`, no trailing newline).
    pub fn text(&self) -> String {
        self.store.stringify_pretty()
    }

    /// `getPending(index)`: the entry, or none where there is none or it
    /// is falsy (`load()[index] || null`).
    pub fn get(&self, index: u64) -> Option<&JsValue> {
        self.store.get(&key(index)).filter(|entry| entry.truthy())
    }

    /// `setPending(index, entry)`: the entry in place of any the index
    /// had, which keeps its place. The reference writes the file after
    /// every set, so the caller writes [`SafePending::text`]. Refused, the
    /// store unchanged, where that file would be one the core can't read
    /// back: past [`MAX_FILE_BYTES`] ([`Unreadable::TooLarge`]), nested too
    /// deep, or with an index past [`MAX_INDEX`].
    pub fn set(&mut self, index: u64, entry: JsValue) -> Result<(), Unreadable> {
        let mut next = self.store.clone();
        next.set(key(index), entry);
        SafePending::load(next.stringify_pretty().as_bytes())?;
        self.store = next;
        Ok(())
    }

    /// `clearPending(index)`: the index's entry removed, the others in
    /// their places. Whether it had one (`index in store`, a falsy entry
    /// included), and so whether the reference writes the file.
    pub fn clear(&mut self, index: u64) -> bool {
        let JsValue::Object(props) = &mut self.store else {
            return false;
        };
        let key = key(index);
        match props.iter().position(|(k, _)| *k == key) {
            Some(at) => {
                props.remove(at);
                true
            }
            None => false,
        }
    }

    /// `listPendingIndexes()`: every index with an entry (a falsy one
    /// included), in the file's order.
    pub fn list(&self) -> Vec<u64> {
        match &self.store {
            JsValue::Object(props) => props.iter().filter_map(|(k, _)| index_of(k)).collect(),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(text: &str) -> JsValue {
        fc_json::parse(text).unwrap()
    }

    #[test]
    fn keys_are_index_texts() {
        let k = |s: &str| index_of(&JsString::from(s));
        assert_eq!(k("0"), Some(0));
        assert_eq!(k("1000000"), Some(1_000_000));
        assert_eq!(k("9007199254740991"), Some(MAX_INDEX));
        for bad in [
            "",
            "01",
            "+1",
            "-1",
            "-0",
            "1.5",
            "1e3",
            " 1",
            "abc",
            "9007199254740992",
            "18446744073709551616",
        ] {
            assert_eq!(k(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn javascript_orders_the_keys() {
        let mut store = SafePending::empty();
        for index in [4_294_967_295, 7, MAX_INDEX, 0, 4_294_967_294] {
            store.set(index, entry("{}")).unwrap();
        }
        assert_eq!(
            store.list(),
            vec![0, 7, 4_294_967_294, 4_294_967_295, MAX_INDEX]
        );
        // A key it has keeps its place; one cleared and set again goes
        // where a new one goes.
        store.set(4_294_967_295, entry("1")).unwrap();
        assert_eq!(store.list()[3], 4_294_967_295);
        assert!(store.clear(4_294_967_295));
        store.set(4_294_967_295, entry("2")).unwrap();
        assert_eq!(*store.list().last().unwrap(), 4_294_967_295);
        assert_eq!(
            store.set(MAX_INDEX + 1, entry("{}")),
            Err(Unreadable::KeyNotIndex)
        );
    }

    #[test]
    fn falsy_entries_are_got_as_none_and_cleared() {
        let mut store = SafePending::load(br#"{"1":null,"2":0,"3":"","4":false,"5":{}}"#).unwrap();
        for index in 1..=4 {
            assert_eq!(store.get(index), None);
        }
        assert_eq!(store.get(5), Some(&entry("{}")));
        assert_eq!(store.get(6), None);
        assert!(store.clear(2));
        assert!(!store.clear(2));
        assert_eq!(store.list(), vec![1, 3, 4, 5]);
        assert_eq!(
            store.text(),
            "{\n  \"1\": null,\n  \"3\": \"\",\n  \"4\": false,\n  \"5\": {}\n}"
        );
    }

    #[test]
    fn the_shape_and_the_bound() {
        assert_eq!(SafePending::load(b"").unwrap_err(), Unreadable::NotJson);
        assert_eq!(
            SafePending::load(b"\xef\xbb\xbf{}").unwrap_err(),
            Unreadable::NotJson
        );
        for not_object in ["null", "[]", "5", "\"a\"", "true"] {
            assert_eq!(
                SafePending::load(not_object.as_bytes()).unwrap_err(),
                Unreadable::NotObject
            );
        }
        assert_eq!(
            SafePending::load(br#"{"0":1,"x":2}"#).unwrap_err(),
            Unreadable::KeyNotIndex
        );
        let at = |n: usize| {
            let mut text = String::from("{\"1\":\"");
            text.push_str(&"x".repeat(n - 8));
            text.push_str("\"}");
            text
        };
        assert!(SafePending::load(at(MAX_FILE_BYTES).as_bytes()).is_ok());
        assert_eq!(
            SafePending::load(at(MAX_FILE_BYTES + 1).as_bytes()).unwrap_err(),
            Unreadable::TooLarge
        );
        // A set whose text would pass the bound changes nothing.
        let mut store = SafePending::empty();
        let fits = MAX_FILE_BYTES - "{\n  \"0\": \"\"\n}".len();
        store
            .set(0, JsValue::string("x".repeat(fits).as_str()))
            .unwrap();
        assert_eq!(store.text().len(), MAX_FILE_BYTES);
        let before = store.clone();
        assert_eq!(
            store.set(0, JsValue::string("x".repeat(fits + 1).as_str())),
            Err(Unreadable::TooLarge)
        );
        assert_eq!(store, before);
        // So is one whose file would be nested past fc-json's limit.
        let mut deep = JsValue::Null;
        for _ in 0..fc_json::MAX_DEPTH {
            deep = JsValue::Array(vec![deep]);
        }
        let mut store = SafePending::empty();
        assert_eq!(store.set(1, deep), Err(Unreadable::NotJson));
        assert_eq!(store, SafePending::empty());
    }
}
