//! JavaScript strings and errors, as the router's texts need them.

use std::fmt;

use fc_json::index::{Kind, Value, quote_units};
use fc_json::number_to_string;

/// A JavaScript string: UTF-16 code units. Node errors and the router's
/// texts can hold lone surrogates (an escape in an answer, or a slice
/// through a surrogate pair), which a Rust `String` can't, so texts stay
/// UTF-16 until they are written as JSON.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct JsString(Vec<u16>);

impl JsString {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_units(units: Vec<u16>) -> Self {
        Self(units)
    }

    pub fn units(&self) -> &[u16] {
        &self.0
    }

    /// The length in UTF-16 code units, as `string.length` counts.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn push_str(&mut self, text: &str) {
        self.0.extend(text.encode_utf16());
    }

    pub fn push_units(&mut self, units: &[u16]) {
        self.0.extend_from_slice(units);
    }

    /// `JSON.stringify(string)`: lone surrogates escaped, so the result is
    /// always well-formed.
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(self.0.len() + 2);
        quote_units(self.0.iter().copied(), &mut out);
        out
    }

    /// The text, with each lone surrogate replaced by U+FFFD.
    pub fn to_string_lossy(&self) -> String {
        String::from_utf16_lossy(&self.0)
    }
}

impl From<&str> for JsString {
    fn from(text: &str) -> Self {
        Self(text.encode_utf16().collect())
    }
}

impl fmt::Debug for JsString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_json())
    }
}

impl fmt::Display for JsString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_lossy())
    }
}

/// An error as the router throws it: its constructor's name and message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsError {
    /// `Error`, `TypeError`, `SyntaxError` or `RangeError`.
    pub name: &'static str,
    pub message: JsString,
}

impl JsError {
    pub(crate) fn new(name: &'static str, message: impl Into<JsString>) -> Self {
        Self {
            name,
            message: message.into(),
        }
    }
}

impl fmt::Display for JsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.message)
    }
}

impl std::error::Error for JsError {}

/// `ToPrimitive` threw: an object with its own `toString` key (no JSON
/// value is callable, so neither `toString` nor `valueOf` gives a
/// primitive).
pub(crate) const NOT_PRIMITIVE: &str = "Cannot convert object to primitive value";

/// `\s` in a JavaScript regular expression, and the whitespace `trim` and
/// `BigInt(string)` remove: WhiteSpace and LineTerminator, all in the BMP.
pub fn is_js_whitespace(unit: u16) -> bool {
    matches!(
        unit,
        0x09..=0x0D
            | 0x20
            | 0xA0
            | 0x1680
            | 0x2000..=0x200A
            | 0x2028
            | 0x2029
            | 0x202F
            | 0x205F
            | 0x3000
            | 0xFEFF
    )
}

/// `String.prototype.trim`.
pub(crate) fn trim(units: &[u16]) -> &[u16] {
    let start = units
        .iter()
        .position(|u| !is_js_whitespace(*u))
        .unwrap_or(units.len());
    let end = units
        .iter()
        .rposition(|u| !is_js_whitespace(*u))
        .map_or(start, |i| i + 1);
    units.get(start..end).unwrap_or_default()
}

/// `String(value)` for a JSON value. Arrays join their elements with commas
/// (nested arrays too, null elements empty); an object is `[object Object]`
/// unless it has its own `toString` key, which makes `ToPrimitive` throw.
pub(crate) fn js_string_of(value: Value<'_, '_>) -> Result<JsString, JsError> {
    let mut out = JsString::new();
    if value.kind() != Kind::Array {
        push_scalar(value, &mut out)?;
        return Ok(out);
    }
    // Iterative: an array can be nested as deep as the index allows.
    let mut stack = vec![(value.children(), true)];
    while let Some((items, first)) = stack.last_mut() {
        let Some(item) = items.next() else {
            stack.pop();
            continue;
        };
        if !*first {
            out.push_str(",");
        }
        *first = false;
        match item.kind() {
            Kind::Array => stack.push((item.children(), true)),
            Kind::Null => {}
            _ => push_scalar(item, &mut out)?,
        }
    }
    Ok(out)
}

/// `String(value)` for anything but an array.
fn push_scalar(value: Value<'_, '_>, out: &mut JsString) -> Result<(), JsError> {
    match value.kind() {
        Kind::Null => out.push_str("null"),
        Kind::True => out.push_str("true"),
        Kind::False => out.push_str("false"),
        Kind::Number => out.push_str(&number_to_string(value.number())),
        Kind::String => out.0.extend(value.units()),
        Kind::Object if value.get("toString").is_some() => {
            return Err(JsError::new("TypeError", NOT_PRIMITIVE));
        }
        Kind::Object => out.push_str("[object Object]"),
        Kind::Array => out.push_units(js_string_of(value)?.units()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fc_json::index::Index;

    fn string_of(text: &str) -> Result<String, JsError> {
        js_string_of(Index::new(text).unwrap().root()).map(|s| s.to_json())
    }

    #[test]
    fn strings_of_values() {
        assert_eq!(
            string_of(r#"[1,[2,[3,null]],{"a":1},"x",true,-0,1e21,[]]"#).unwrap(),
            r#""1,2,3,,[object Object],x,true,0,1e+21,""#
        );
        assert_eq!(string_of("null").unwrap(), r#""null""#);
        assert_eq!(string_of("1e400").unwrap(), r#""Infinity""#);
        assert_eq!(string_of(r#""\ud800""#).unwrap(), r#""\ud800""#);
        assert_eq!(
            string_of(r#"{"valueOf":1}"#).unwrap(),
            r#""[object Object]""#
        );
        assert_eq!(
            string_of(r#"{"toString":1}"#)
                .unwrap_err()
                .message
                .to_string_lossy(),
            NOT_PRIMITIVE
        );
        assert!(string_of(r#"[[{"toString":"x"}]]"#).is_err());
    }

    #[test]
    fn whitespace_and_trim() {
        let units: Vec<u16> = "\u{feff} a b\u{3000}\n".encode_utf16().collect();
        assert_eq!(String::from_utf16_lossy(trim(&units)), "a b");
        assert!(trim(&[0x20, 0x09]).is_empty());
        assert!(!is_js_whitespace(0x85) && !is_js_whitespace(0x180E) && !is_js_whitespace(0x200B));
    }
}
