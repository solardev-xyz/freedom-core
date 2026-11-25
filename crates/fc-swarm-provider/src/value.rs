//! A request's params and a method's answer as JavaScript holds them
//! (design 0015, "Main's encoding of a request"). The validators read
//! JavaScript types (`typeof`, `Number.isInteger`, `Array.isArray`, key
//! order, `undefined` against `null`, BigInt), which JSON loses, so main
//! sends `params` in a typed form, which `vectors/swarm.json`'s
//! `formats.typed` defines, and [`Value::from_typed`] reads:
//!
//! - `{ string }`, `{ number: String(n) }` (`-0`, `NaN` and the
//!   infinities included), `{ bigint }`, `{ boolean }`, `{ null }`,
//!   `{ undefined }`, `{ array }` (`{ hole }` for a hole) and
//!   `{ object: [[key, value], …] }` in `Object.keys` order;
//! - where a method reads bytes, `{ bytes, kind, base64 }` up to 64 KiB, or
//!   `{ bytes, kind, part }`, which the core pulls with `shell.swarm_part`;
//!   a string there is `{ string_bytes, base64 | part }`, its UTF-8;
//!   `{ bytes_elsewhere, kind, base64 }` for bytes where no method reads
//!   them.
//!
//! A string with a lone surrogate needs no tag of its own on the wire:
//! fc-json reads the escape (`vectors/swarm.json` writes such strings as
//! `string_json`, its file being JSON text that tools other than fc-json
//! read too).
//!
//! An answer is a [`Value`] too: a result can hold a BigInt (a span past
//! 2^53 - 1) or `undefined` members (a feed record's missing fields).

use fc_json::{JsString, JsValue, number_to_string};

use crate::js::string_to_number;

/// A JavaScript value, as the typed form carries it.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    /// A BigInt, as its decimal text (`-` before a negative one).
    BigInt(String),
    String(JsString),
    /// `None` is a hole.
    Array(Vec<Option<Value>>),
    /// An object's own enumerable string keys and their values, in
    /// `Object.keys` order.
    Object(Vec<(JsString, Value)>),
    /// Bytes (an object to `typeof`).
    Bytes(Bytes),
}

/// `undefined`, to read an absent property as.
pub static UNDEFINED: Value = Value::Undefined;

/// Bytes a request carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bytes {
    /// How many bytes.
    pub len: u64,
    pub kind: BytesKind,
    pub source: Source,
    /// Whether the position is one a method reads as data
    /// (`normalizeBytes`); false for `bytes_elsewhere`.
    pub data: bool,
}

/// What JavaScript held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytesKind {
    Buffer,
    Uint8Array,
    ArrayBuffer,
    /// `{ type: 'Buffer', data: [...] }`.
    BufferJson,
    /// A string where a method reads data: its UTF-8.
    String,
}

/// Where the bytes are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Inline(Vec<u8>),
    /// A payload part of the request, at most once (`shell.swarm_part`).
    Part(u32),
}

/// Why a typed value isn't read: main sent something outside the typed
/// form, a protocol error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TypedError {
    #[error("a typed value isn't an object of one tag")]
    Shape,
    #[error("an unknown tag")]
    Tag,
    #[error("a tag's value is of another type")]
    Content,
    #[error("base64 that doesn't decode, or a length that isn't its bytes'")]
    Bytes,
}

/// Inline bytes are at most 64 KiB; past that they come as a part.
pub const INLINE_BYTES: usize = 64 * 1024;

impl Value {
    /// A string value.
    pub fn str(text: &str) -> Value {
        Value::String(JsString::from(text))
    }

    /// An object from its members, in order.
    pub fn object<K: Into<JsString>>(members: impl IntoIterator<Item = (K, Value)>) -> Value {
        Value::Object(members.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// An array of present elements.
    pub fn array(items: impl IntoIterator<Item = Value>) -> Value {
        Value::Array(items.into_iter().map(Some).collect())
    }

    /// A number from an integer: exact up to 2^53.
    pub fn int(n: u64) -> Value {
        #[expect(
            clippy::cast_precision_loss,
            reason = "Number(n): JavaScript rounds an integer past 2^53 the same way"
        )]
        Value::Number(n as f64)
    }

    /// `typeof value`.
    pub fn type_of(&self) -> &'static str {
        match self {
            Value::Undefined => "undefined",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::BigInt(_) => "bigint",
            Value::String(_) => "string",
            Value::Null | Value::Array(_) | Value::Object(_) | Value::Bytes(_) => "object",
        }
    }

    /// `value === undefined || value === null`.
    pub fn is_nullish(&self) -> bool {
        matches!(self, Value::Undefined | Value::Null)
    }

    /// `!!value`.
    pub fn truthy(&self) -> bool {
        match self {
            Value::Undefined | Value::Null => false,
            Value::Bool(b) => *b,
            Value::Number(n) => *n != 0.0 && !n.is_nan(),
            Value::BigInt(text) => text != "0",
            Value::String(s) => !s.is_empty(),
            Value::Array(_) | Value::Object(_) | Value::Bytes(_) => true,
        }
    }

    /// The string, if this is one.
    pub fn as_js_string(&self) -> Option<&JsString> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// `value[key]` for a key that no prototype in the request has (a
    /// method's params: `options`, `reference`, `index`, …): an object's
    /// own property, else `undefined`. An array's, a string's and the
    /// bytes' own properties are indices and `length`, which no method
    /// reads.
    pub fn get(&self, key: &str) -> &Value {
        match self {
            Value::Object(members) => members
                .iter()
                .find(|(k, _)| k.is_well_formed() && k.as_str() == key)
                .map_or(&UNDEFINED, |(_, v)| v),
            _ => &UNDEFINED,
        }
    }

    /// `Object.keys(value)[0]` for an object (`typeof` `object`, not an
    /// array): its first own key. Bytes' own keys are their indices.
    pub fn first_key(&self) -> Option<JsString> {
        match self {
            Value::Object(members) => members.first().map(|(k, _)| k.clone()),
            Value::Bytes(bytes) => match bytes.kind {
                BytesKind::BufferJson => Some(JsString::from("type")),
                _ if bytes.len > 0 => Some(JsString::from("0")),
                _ => None,
            },
            _ => None,
        }
    }

    /// A JSON value from a store, as JavaScript holds it.
    pub fn from_js(value: &JsValue) -> Value {
        match value {
            JsValue::Undefined => Value::Undefined,
            JsValue::Null => Value::Null,
            JsValue::Bool(b) => Value::Bool(*b),
            JsValue::Number(n) => Value::Number(*n),
            JsValue::String(s) => Value::String(s.clone()),
            JsValue::Array(items) => Value::array(items.iter().map(Value::from_js)),
            JsValue::Object(members) => Value::Object(
                members
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::from_js(v)))
                    .collect(),
            ),
        }
    }

    /// `JSON.stringify(value)`: `None` where it throws (a BigInt) or gives
    /// `undefined` (the value itself is `undefined`). Bytes are written as
    /// a `Buffer`'s `toJSON` writes them.
    pub fn stringify(&self) -> Option<String> {
        let mut out = String::new();
        stringify_into(self, &mut out).then_some(out)
    }

    /// Reads a typed value (`formats.typed`).
    pub fn from_typed(value: &JsValue) -> Result<Value, TypedError> {
        let JsValue::Object(members) = value else {
            return Err(TypedError::Shape);
        };
        let (tag, content) = members.first().ok_or(TypedError::Shape)?;
        let rest = &members[1..];
        let only = |extra: &[&str]| {
            rest.iter()
                .all(|(k, _)| extra.iter().any(|e| k == *e))
                .then_some(())
                .ok_or(TypedError::Shape)
        };
        let field = |name: &str| rest.iter().find(|(k, _)| k == name).map(|(_, v)| v);
        Ok(match tag.as_str() {
            "string" => {
                only(&[])?;
                Value::String(content.as_js_string().ok_or(TypedError::Content)?.clone())
            }
            "number" => {
                only(&[])?;
                let text = content.as_str().ok_or(TypedError::Content)?;
                Value::Number(string_to_number(text))
            }
            "bigint" => {
                only(&[])?;
                let text = content.as_str().ok_or(TypedError::Content)?;
                let digits = text.strip_prefix('-').unwrap_or(text);
                if digits.is_empty()
                    || !digits.bytes().all(|b| b.is_ascii_digit())
                    || (digits.len() > 1 && digits.starts_with('0'))
                    || text == "-0"
                {
                    return Err(TypedError::Content);
                }
                Value::BigInt(text.to_owned())
            }
            "boolean" => {
                only(&[])?;
                match content {
                    JsValue::Bool(b) => Value::Bool(*b),
                    _ => return Err(TypedError::Content),
                }
            }
            "null" | "undefined" => {
                only(&[])?;
                if *content != JsValue::Bool(true) {
                    return Err(TypedError::Content);
                }
                if tag == "null" {
                    Value::Null
                } else {
                    Value::Undefined
                }
            }
            "array" => {
                only(&[])?;
                let items = content.as_array().ok_or(TypedError::Content)?;
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    let hole = matches!(item, JsValue::Object(m)
                        if m.len() == 1 && m[0].0 == "hole" && m[0].1 == JsValue::Bool(true));
                    out.push(if hole {
                        None
                    } else {
                        Some(Value::from_typed(item)?)
                    });
                }
                Value::Array(out)
            }
            "object" => {
                only(&[])?;
                let pairs = content.as_array().ok_or(TypedError::Content)?;
                let mut out: Vec<(JsString, Value)> = Vec::with_capacity(pairs.len());
                for pair in pairs {
                    let [key, value] = pair.as_array().ok_or(TypedError::Content)? else {
                        return Err(TypedError::Content);
                    };
                    let key = key.as_js_string().ok_or(TypedError::Content)?;
                    if out.iter().any(|(k, _)| k == key) {
                        return Err(TypedError::Content);
                    }
                    out.push((key.clone(), Value::from_typed(value)?));
                }
                Value::Object(out)
            }
            "bytes" | "bytes_elsewhere" => {
                let elsewhere = tag == "bytes_elsewhere";
                if elsewhere {
                    only(&["kind", "base64"])?;
                } else {
                    only(&["kind", "base64", "part"])?;
                }
                let kind = match field("kind").and_then(JsValue::as_str) {
                    Some("Buffer") => BytesKind::Buffer,
                    Some("Uint8Array") => BytesKind::Uint8Array,
                    Some("ArrayBuffer") => BytesKind::ArrayBuffer,
                    Some("BufferJSON") => BytesKind::BufferJson,
                    _ => return Err(TypedError::Content),
                };
                Value::Bytes(read_bytes(content, kind, !elsewhere, field)?)
            }
            "string_bytes" => {
                only(&["base64", "part"])?;
                Value::Bytes(read_bytes(content, BytesKind::String, true, field)?)
            }
            _ => return Err(TypedError::Tag),
        })
    }
}

fn read_bytes<'a>(
    len: &JsValue,
    kind: BytesKind,
    data: bool,
    field: impl Fn(&str) -> Option<&'a JsValue>,
) -> Result<Bytes, TypedError> {
    let JsValue::Number(n) = len else {
        return Err(TypedError::Content);
    };
    if !(n.is_finite() && n.fract() == 0.0 && *n >= 0.0 && *n <= 9_007_199_254_740_991.0) {
        return Err(TypedError::Content);
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a non-negative integer below 2^53"
    )]
    let len = *n as u64;
    let source = match (field("base64"), field("part")) {
        (Some(JsValue::String(text)), None) => {
            let bytes = decode_base64(text.as_str()).ok_or(TypedError::Bytes)?;
            if bytes.len() as u64 != len || bytes.len() > INLINE_BYTES {
                return Err(TypedError::Bytes);
            }
            Source::Inline(bytes)
        }
        (None, Some(JsValue::Number(part))) if data => {
            if !(part.fract() == 0.0 && *part >= 0.0 && *part <= f64::from(u32::MAX)) {
                return Err(TypedError::Content);
            }
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "a non-negative integer within u32"
            )]
            Source::Part(*part as u32)
        }
        _ => return Err(TypedError::Content),
    };
    Ok(Bytes {
        len,
        kind,
        source,
        data,
    })
}

fn stringify_into(value: &Value, out: &mut String) -> bool {
    match value {
        Value::Undefined | Value::BigInt(_) => return false,
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) if n.is_finite() => out.push_str(&number_to_string(*n)),
        Value::Number(_) => out.push_str("null"),
        Value::String(s) => s.quote_into(out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                match item {
                    None | Some(Value::Undefined) => out.push_str("null"),
                    Some(item) => {
                        if !stringify_into(item, out) {
                            return false;
                        }
                    }
                }
            }
            out.push(']');
        }
        Value::Object(members) => {
            out.push('{');
            let mut first = true;
            for (key, member) in members {
                match member {
                    Value::Undefined => continue,
                    Value::BigInt(_) => return false,
                    _ => {}
                }
                if !first {
                    out.push(',');
                }
                first = false;
                key.quote_into(out);
                out.push(':');
                if !stringify_into(member, out) {
                    return false;
                }
            }
            out.push('}');
        }
        Value::Bytes(bytes) => match &bytes.source {
            // Buffer's toJSON; an ArrayBuffer and a typed array have none
            // and write their (absent) own enumerable keys, indices for a
            // typed array.
            Source::Inline(data) => match bytes.kind {
                BytesKind::Buffer | BytesKind::BufferJson | BytesKind::String => {
                    out.push_str("{\"type\":\"Buffer\",\"data\":[");
                    for (i, b) in data.iter().enumerate() {
                        if i > 0 {
                            out.push(',');
                        }
                        out.push_str(&b.to_string());
                    }
                    out.push_str("]}");
                }
                BytesKind::Uint8Array => {
                    out.push('{');
                    for (i, b) in data.iter().enumerate() {
                        if i > 0 {
                            out.push(',');
                        }
                        out.push_str(&format!("\"{i}\":{b}"));
                    }
                    out.push('}');
                }
                BytesKind::ArrayBuffer => out.push_str("{}"),
            },
            Source::Part(_) => return false,
        },
    }
    true
}

/// Standard base64 with padding, as `Buffer.toString('base64')` writes it.
pub fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let n = (u32::from(group[0]) << 16)
            | (u32::from(group.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(group.get(2).copied().unwrap_or(0));
        let sextet = |shift: u32| char::from(ALPHABET[((n >> shift) & 63) as usize]);
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if group.len() > 1 { sextet(6) } else { '=' });
        out.push(if group.len() > 2 { sextet(0) } else { '=' });
    }
    out
}

/// Strict standard base64 with padding: `None` for anything else.
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let groups = bytes.len() / 4;
    for (g, quad) in bytes.chunks(4).enumerate() {
        let last = g + 1 == groups;
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (i, &c) in quad.iter().enumerate() {
            let v = if i >= 4 - pad { 0 } else { value(c)? };
            n = (n << 6) | v;
        }
        let decoded = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        // Non-zero bits under the padding aren't canonical.
        if (pad == 1 && decoded[2] != 0) || (pad == 2 && decoded[1] != 0) {
            return None;
        }
        out.extend_from_slice(&decoded[..3 - pad]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn typed(text: &str) -> Value {
        Value::from_typed(&fc_json::parse(text).unwrap()).unwrap()
    }

    #[test]
    fn reads_the_typed_form() {
        assert_eq!(typed(r#"{"number":"-0"}"#).type_of(), "number");
        assert!(
            matches!(typed(r#"{"number":"-0"}"#), Value::Number(n) if n == 0.0 && n.is_sign_negative())
        );
        assert!(matches!(typed(r#"{"number":"NaN"}"#), Value::Number(n) if n.is_nan()));
        assert_eq!(typed(r#"{"bigint":"-12"}"#), Value::BigInt("-12".into()));
        assert_eq!(
            typed(r#"{"array":[{"hole":true},{"null":true}]}"#),
            Value::Array(vec![None, Some(Value::Null)])
        );
        let object = typed(r#"{"object":[["b",{"string":"x"}],["a",{"undefined":true}]]}"#);
        assert_eq!(object.get("b"), &Value::str("x"));
        assert_eq!(object.get("a"), &Value::Undefined);
        assert_eq!(object.get("c"), &Value::Undefined);
        assert_eq!(object.first_key(), Some(JsString::from("b")));
        let bytes = typed(r#"{"bytes":3,"kind":"Uint8Array","base64":"AQID"}"#);
        assert_eq!(bytes.type_of(), "object");
        assert_eq!(bytes.first_key(), Some(JsString::from("0")));
        for bad in [
            r#"{"bigint":"01"}"#,
            r#"{"bytes":4,"kind":"Buffer","base64":"AQID"}"#,
            r#"{"string":"a","extra":1}"#,
            r#"{"what":1}"#,
            r#"{"object":[["a",{"null":true}],["a",{"null":true}]]}"#,
        ] {
            assert!(
                Value::from_typed(&fc_json::parse(bad).unwrap()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn stringifies_as_json_does() {
        let value = Value::object([
            ("a", Value::Undefined),
            ("b", Value::array([Value::Undefined, Value::Number(-0.0)])),
            ("c", Value::Number(f64::NAN)),
            ("d", Value::str("\u{1}")),
        ]);
        assert_eq!(
            value.stringify().unwrap(),
            r#"{"b":[null,0],"c":null,"d":"\u0001"}"#
        );
        assert_eq!(Value::BigInt("1".into()).stringify(), None);
        assert_eq!(Value::Undefined.stringify(), None);
    }

    #[test]
    fn base64_both_ways() {
        for n in 0..10 {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 37) as u8).collect();
            assert_eq!(decode_base64(&encode_base64(&bytes)).unwrap(), bytes);
        }
        assert_eq!(encode_base64(b"hello swarm"), "aGVsbG8gc3dhcm0=");
        assert!(decode_base64("aGVsbG8gc3dhcm1=").is_none());
        assert!(decode_base64("a===").is_none());
    }
}
