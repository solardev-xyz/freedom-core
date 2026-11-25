//! The three Swarm stores (design 0015, "The stores"; design 0013's set A)
//! as codecs and rules: `swarm-feeds.json` ([`feeds`]),
//! `swarm-manifest-grants.json` ([`manifests`]) and `publish-history.sqlite`
//! ([`history`]), each with the behavior of its freedom-browser module
//! (`feed-store.js`, `permission-manifests.js`, `publish-history.js`) at
//! the swarm reference commit.
//!
//! The crate does no I/O (AGENTS rule 2): a store is read from the bytes or
//! rows it is handed, changed as the reference changes it, and answers the
//! exact text or the statements to write. The daemon reads and writes the
//! files with 0001's durable write through `fc-store`, and SQLite through
//! `rusqlite` (design 0015, "Crates"; deviation `store-writes`), one writer.
//!
//! **The JSON files** are kept as JavaScript holds them: the file's object
//! as `JSON.parse` read it (fc-json: doubles, lone surrogates, JavaScript's
//! property order, a repeated key in its first place with its last value),
//! changed as the reference changes it, and written as
//! `JSON.stringify(…, null, 2)` writes it. Each store's text is bounded
//! (design 0015, Budgets): a change whose text would pass the bound is
//! refused ([`StoreError::Full`], `store_full`), and nothing changes.
//!
//! **Where JavaScript's semantics end** (no `vectors/swarm.json` case
//! reaches these; the design says nothing of them):
//! - every key is an own property: a name on `Object.prototype`
//!   (`toString`, `constructor`, `__proto__`, …) is never read through the
//!   prototype or assigned through its setter, where the reference would
//!   read a function for it or set the object's prototype;
//! - the keys are the permission keys main attests (0011), which main
//!   normalizes, as in 0012's stores: the core doesn't normalize them again
//!   (`normalizeOrigin`).
//!
//! **A change is all or nothing:** a refused change leaves the store as it
//! was, where the reference can keep part of it in its cache (a refused
//! label after the index was taken). A change that answers a text to write
//! is applied in memory; the daemon keeps a copy from before it, and puts
//! it back if the write fails (0013: memory changes only after the durable
//! write).

use fc_json::{JsString, JsValue};

pub mod history;

/// The class of an error the reference throws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorName {
    Error,
    TypeError,
    RangeError,
}

impl ErrorName {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorName::Error => "Error",
            ErrorName::TypeError => "TypeError",
            ErrorName::RangeError => "RangeError",
        }
    }
}

/// What the reference throws: its class, its message and its `code`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct Thrown {
    pub name: ErrorName,
    pub message: String,
    pub code: Option<&'static str>,
}

impl Thrown {
    pub(crate) fn error(message: impl Into<String>) -> Self {
        Thrown {
            name: ErrorName::Error,
            message: message.into(),
            code: None,
        }
    }

    pub(crate) fn coded(message: impl Into<String>, code: &'static str) -> Self {
        Thrown {
            name: ErrorName::Error,
            message: message.into(),
            code: Some(code),
        }
    }

    pub(crate) fn type_error(message: impl Into<String>) -> Self {
        Thrown {
            name: ErrorName::TypeError,
            message: message.into(),
            code: None,
        }
    }

    pub(crate) fn range_error(message: impl Into<String>) -> Self {
        Thrown {
            name: ErrorName::RangeError,
            message: message.into(),
            code: None,
        }
    }
}

impl From<fc_json::ToPrimitiveError> for Thrown {
    fn from(error: fc_json::ToPrimitiveError) -> Self {
        Thrown::type_error(error.to_string())
    }
}

/// Why a change wasn't made. Either way the store is as it was.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The reference's own refusal.
    #[error(transparent)]
    Thrown(#[from] Thrown),
    /// The file's text would pass the store's bound: `store_full` (design
    /// 0015, Budgets).
    #[error("the store's file would pass its bound")]
    Full,
}

/// A file's text as the reference reads it: `fs.readFileSync(file,
/// 'utf8')` (each bad UTF-8 sequence U+FFFD, a byte-order mark kept), then
/// `JSON.parse`. `None` where `JSON.parse` throws, or where fc-json's
/// nesting bound refuses what V8 would read: no store the reference writes
/// nests past a few levels.
pub(crate) fn parse_file(bytes: &[u8]) -> Option<JsValue> {
    fc_json::parse(&String::from_utf8_lossy(bytes)).ok()
}

/// The text the reference writes: `JSON.stringify(value, null, 2)`, or
/// [`StoreError::Full`] past `bound` bytes.
pub(crate) fn file_text(value: &JsValue, bound: usize) -> Result<String, StoreError> {
    let text = value.stringify_pretty();
    if text.len() > bound {
        return Err(StoreError::Full);
    }
    Ok(text)
}

// --- JavaScript's reads and writes on JSON values ---------------------------

/// `undefined`, to read an absent property as. A static, not a const:
/// `JsValue` has a `Drop`, so a const's reference isn't promoted to
/// `'static`.
pub(crate) static UNDEFINED: JsValue = JsValue::Undefined;

/// `{}`.
pub(crate) fn object() -> JsValue {
    JsValue::Object(Vec::new())
}

/// A string value.
pub(crate) fn text(s: &str) -> JsValue {
    JsValue::string(s)
}

/// A wall-clock time as `Date.now()` answers it: a double.
pub(crate) fn time(ms: u64) -> JsValue {
    #[expect(
        clippy::cast_precision_loss,
        reason = "Date.now() is a double; times below 2^53 ms are exact"
    )]
    let ms = ms as f64;
    JsValue::Number(ms)
}

/// `value !== null && typeof value === 'object' && !Array.isArray(value)`.
pub(crate) fn is_plain_object(value: &JsValue) -> bool {
    matches!(value, JsValue::Object(_))
}

/// An object's own properties, in JavaScript's order (none for another
/// value).
pub(crate) fn props(value: &JsValue) -> &[(JsString, JsValue)] {
    match value {
        JsValue::Object(props) => props,
        _ => &[],
    }
}

/// `value[key]`, an own property of an object; `None` for another value,
/// or where the object has none.
pub(crate) fn get<'v>(value: &'v JsValue, key: &JsString) -> Option<&'v JsValue> {
    props(value).iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// [`get`], to change it in place.
pub(crate) fn get_mut<'v>(value: &'v mut JsValue, key: &JsString) -> Option<&'v mut JsValue> {
    match value {
        JsValue::Object(props) => props.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

/// `!!value` of a property read: absent is `undefined`.
pub(crate) fn truthy(value: Option<&JsValue>) -> bool {
    value.is_some_and(JsValue::truthy)
}

/// `value ?? null`: `undefined` (absent) and `null` are nullish.
pub(crate) fn nullish(value: Option<&JsValue>) -> bool {
    matches!(value, None | Some(JsValue::Undefined | JsValue::Null))
}

/// `value ?? fallback`.
pub(crate) fn or_nullish(value: Option<&JsValue>, fallback: JsValue) -> JsValue {
    match value {
        Some(v) if !nullish(Some(v)) => v.clone(),
        _ => fallback,
    }
}

/// `value || fallback`.
pub(crate) fn or_falsy(value: Option<&JsValue>, fallback: JsValue) -> JsValue {
    match value {
        Some(v) if v.truthy() => v.clone(),
        _ => fallback,
    }
}

/// `delete object[key]`: the property, if the object had it. The others
/// keep their order.
pub(crate) fn remove(object: &mut JsValue, key: &JsString) -> Option<JsValue> {
    let JsValue::Object(props) = object else {
        return None;
    };
    let at = props.iter().position(|(k, _)| k == key)?;
    Some(props.remove(at).1)
}

/// `Object.keys(value).length`, for a truthy value: an object's own keys,
/// an array's indices, a string's units.
pub(crate) fn key_count(value: &JsValue) -> usize {
    match value {
        JsValue::Object(props) => props.len(),
        JsValue::Array(items) => items.len(),
        JsValue::String(s) => s.utf16_len(),
        _ => 0,
    }
}

/// `{ ...value }`: an object's own properties in order, an array's
/// elements and a string's units under their indices, and nothing for any
/// other value.
pub(crate) fn spread(value: &JsValue) -> JsValue {
    let mut out = object();
    spread_into(&mut out, value);
    out
}

/// `{ ...target, ...value }` into `target`: each property set as an
/// assignment sets it (a key it has keeps its place).
pub(crate) fn spread_into(target: &mut JsValue, value: &JsValue) {
    match value {
        JsValue::Object(props) => {
            for (key, v) in props {
                target.set(key.clone(), v.clone());
            }
        }
        JsValue::Array(items) => {
            for (index, v) in items.iter().enumerate() {
                target.set(index.to_string(), v.clone());
            }
        }
        JsValue::String(s) => {
            for (index, unit) in s.units().enumerate() {
                target.set(
                    index.to_string(),
                    JsValue::String(JsString::from_units(&[unit])),
                );
            }
        }
        _ => {}
    }
}

/// `String(value)` as a property key: a string is itself, any other value
/// its text (`ToPropertyKey`). An object with its own `toString` throws.
pub(crate) fn property_key(value: &JsValue) -> Result<JsString, Thrown> {
    match value {
        JsValue::String(s) => Ok(s.clone()),
        other => Ok(JsString::from(other.js_string()?)),
    }
}

/// A JavaScript template's `${value}`: [`property_key`]'s text.
pub(crate) fn template(value: &JsValue) -> Result<String, Thrown> {
    Ok(property_key(value)?.as_str().to_owned())
}

/// `a === b` for JSON values: numbers by value (`NaN` is never equal, `0`
/// and `-0` are), strings by unit, objects and arrays never (each a
/// distinct reference; the callers compare no two of them).
pub(crate) fn strict_equals(a: &JsValue, b: &JsValue) -> bool {
    match (a, b) {
        (JsValue::Undefined, JsValue::Undefined) | (JsValue::Null, JsValue::Null) => true,
        (JsValue::Bool(x), JsValue::Bool(y)) => x == y,
        (JsValue::Number(x), JsValue::Number(y)) => x == y,
        (JsValue::String(x), JsValue::String(y)) => x == y,
        _ => false,
    }
}

/// Whether `value` is the string `s`.
pub(crate) fn is_str(value: Option<&JsValue>, s: &str) -> bool {
    matches!(value, Some(JsValue::String(v)) if v == s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> JsValue {
        fc_json::parse(text).unwrap()
    }

    #[test]
    fn spreads_as_javascript_does() {
        assert_eq!(
            spread(&parse("{\"b\":1,\"a\":2}")).stringify(),
            "{\"b\":1,\"a\":2}"
        );
        assert_eq!(spread(&parse("[5,6]")).stringify(), "{\"0\":5,\"1\":6}");
        assert_eq!(
            spread(&parse("\"ab\"")).stringify(),
            "{\"0\":\"a\",\"1\":\"b\"}"
        );
        assert_eq!(spread(&parse("null")).stringify(), "{}");
        assert_eq!(spread(&parse("7")).stringify(), "{}");
        // A key the target has keeps its place.
        let mut target = parse("{\"a\":1,\"b\":2}");
        spread_into(&mut target, &parse("{\"c\":3,\"a\":4}"));
        assert_eq!(target.stringify(), "{\"a\":4,\"b\":2,\"c\":3}");
        // An index key goes before the others.
        let mut target = parse("{\"version\":1}");
        spread_into(&mut target, &parse("[9]"));
        assert_eq!(target.stringify(), "{\"0\":9,\"version\":1}");
    }

    #[test]
    fn keys_count_as_object_keys_does() {
        assert_eq!(key_count(&parse("{\"a\":1}")), 1);
        assert_eq!(key_count(&parse("[1,2,3]")), 3);
        assert_eq!(key_count(&parse("\"\\ud800x\"")), 2);
        assert_eq!(key_count(&parse("5")), 0);
    }

    #[test]
    fn file_bytes_as_node_reads_them() {
        assert!(parse_file(b"\xef\xbb\xbf{}").is_none(), "a BOM is kept");
        let value = parse_file(b"{\"a\":\"\xff\"}").unwrap();
        assert_eq!(value.get("a").and_then(JsValue::as_str), Some("\u{fffd}"));
        assert_eq!(file_text(&parse("{}"), 2), Ok("{}".to_owned()));
        assert_eq!(file_text(&parse("{}"), 1), Err(StoreError::Full));
    }
}
