//! Agreement between answers: the router compares `stableValue(result)`
//! strings; the core compares their SHA-256 digests.
//!
//! `stableValue` of a value `JSON.parse` gave is `JSON.stringify` with each
//! object's own keys sorted by UTF-16 code units: arrays in order, the last
//! of duplicate keys, `__proto__` an ordinary key, numbers as doubles in
//! JavaScript's shortest form (`1e2` is `100`, `-0` is `0`, `1e400` is
//! `null`), lone surrogates escaped. The core writes that string from the
//! answer's text through an [`Index`] (no value tree) straight into the
//! hash.

use fc_json::index::{Index, IndexError, KeyOrder, Sink, Value};
use sha2::{Digest as _, Sha256};

/// The SHA-256 of a `stableValue` string's UTF-8, or of the `undefined`
/// tag.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StableDigest([u8; 32]);

impl StableDigest {
    /// A missing `result`: `stableValue(undefined)` is `undefined`, equal
    /// only to itself. Its tag is the byte 0xFF, which is no string's UTF-8,
    /// so no JSON value's digest can equal it.
    pub fn undefined() -> Self {
        Self(Sha256::digest([0xFF]).into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for StableDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

struct Hasher(Sha256);

impl Sink for Hasher {
    fn push(&mut self, text: &str) {
        self.0.update(text.as_bytes());
    }
}

/// The digest of an indexed value.
pub fn value_digest(value: Value<'_, '_>) -> StableDigest {
    let mut hasher = Hasher(Sha256::new());
    value.write(KeyOrder::Sorted, &mut hasher);
    StableDigest(hasher.0.finalize().into())
}

/// The digest of a valid JSON value's text when it is a string with no
/// escape: `stableValue` of such a string is its own token, quotes and all
/// (JSON.stringify writes it back unchanged, `write_string`), so the digest
/// is the token's SHA-256, found without an index. `None` for any other
/// value, whose digest needs one. `json` must be one JSON value, as an
/// answer's indexed span is: it starts and ends with a quote only if it is
/// a single string.
pub(crate) fn plain_string_digest(json: &str) -> Option<StableDigest> {
    let plain =
        json.len() >= 2 && json.starts_with('"') && json.ends_with('"') && !json.contains('\\');
    plain.then(|| StableDigest(Sha256::digest(json.as_bytes()).into()))
}

/// The digest of a result: its JSON text, or `None` for `undefined`.
pub fn stable_digest(result: Option<&str>) -> Result<StableDigest, IndexError> {
    match result {
        None => Ok(StableDigest::undefined()),
        Some(text) => Ok(value_digest(Index::new(text)?.root())),
    }
}

/// `stableValue(JSON.parse(text))` itself.
pub fn stable_value(text: &str) -> Result<String, IndexError> {
    Ok(Index::new(text)?.root().stringify(KeyOrder::Sorted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_of_the_stable_string() {
        let text = r#"{"b":[1E2,-0],"a":"\ud800","a":{"y":1,"x":2}}"#;
        let stable = stable_value(text).unwrap();
        assert_eq!(stable, r#"{"a":{"x":2,"y":1},"b":[100,0]}"#);
        let expected: [u8; 32] = Sha256::digest(stable.as_bytes()).into();
        assert_eq!(stable_digest(Some(text)).unwrap().as_bytes(), &expected);
        assert_ne!(
            stable_digest(None).unwrap(),
            stable_digest(Some("null")).unwrap()
        );
        assert_ne!(
            stable_digest(None).unwrap(),
            stable_digest(Some("\"\"")).unwrap()
        );
        assert_eq!(stable_digest(None).unwrap(), StableDigest::undefined());
    }

    /// The fast path is the indexed digest for every escape-free string,
    /// and declines everything else (escapes, other values).
    #[test]
    fn a_plain_strings_digest_is_the_indexed_one() {
        let long = format!("\"0x{}\"", "61".repeat(1 << 16));
        for json in [
            "\"\"",
            "\"a\"",
            "\"0x\"",
            "\"caf\u{e9} \u{1f510} \u{7f}\"",
            "\"slash / and 'quote'\"",
            long.as_str(),
        ] {
            assert_eq!(
                plain_string_digest(json),
                Some(stable_digest(Some(json)).unwrap()),
                "{json}"
            );
        }
        for json in [
            r#""a\nb""#,
            r#""\u00e9""#,
            r#""\/""#,
            r#""\ud800""#,
            "0",
            "null",
            "[\"a\"]",
            "{\"a\":\"b\"}",
            "true",
        ] {
            assert_eq!(plain_string_digest(json), None, "{json}");
        }
    }
}
