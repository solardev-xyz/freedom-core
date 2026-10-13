//! JavaScript strings and errors, as the router's texts need them.

use std::fmt;

use fc_json::index::{KeyOrder, Kind, Value, quote_units, quoted_len};
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
    /// The length of [`Self::to_json`]'s text, measured without writing
    /// it.
    pub fn json_len(&self) -> usize {
        quoted_len(self.0.iter().copied())
    }

    /// What its units hold on the heap.
    pub fn heap_bytes(&self) -> usize {
        self.0.capacity().saturating_mul(2)
    }

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

/// `Number.isSafeInteger(x)` for a number.
pub(crate) fn is_safe_integer(x: f64) -> bool {
    x.is_finite() && x.trunc() == x && x.abs() <= 9_007_199_254_740_991.0
}

/// `Number(text)` (StringToNumber): JavaScript's whitespace trimmed; empty
/// is 0; `Infinity` with an optional sign; `0x`, `0o` and `0b` integers
/// without a sign; otherwise a decimal literal, or `NaN`.
pub(crate) fn string_to_number(text: &str) -> f64 {
    let text = text.trim_matches(|c: char| u16::try_from(u32::from(c)).is_ok_and(is_js_whitespace));
    match text {
        "" => return 0.0,
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    let bytes = text.as_bytes();
    if let [b'0', prefix, digits @ ..] = bytes {
        let radix = match prefix {
            b'x' | b'X' => Some(4),
            b'o' | b'O' => Some(3),
            b'b' | b'B' => Some(1),
            _ => None,
        };
        if let Some(bits) = radix {
            return radix_to_number(digits, bits);
        }
    }
    if decimal_literal(bytes) {
        text.parse().unwrap_or(f64::NAN)
    } else {
        f64::NAN
    }
}

/// `[+-]? (digits [. digits?] | . digits) ([eE] [+-]? digits)?`, all ASCII.
fn decimal_literal(bytes: &[u8]) -> bool {
    let digits = |s: &[u8]| s.iter().take_while(|b| b.is_ascii_digit()).count();
    let mut rest = match bytes {
        [b'+' | b'-', rest @ ..] => rest,
        rest => rest,
    };
    let whole = digits(rest);
    rest = rest.get(whole..).unwrap_or_default();
    let mut fraction = 0;
    if let [b'.', after @ ..] = rest {
        fraction = digits(after);
        rest = after.get(fraction..).unwrap_or_default();
    }
    if whole == 0 && fraction == 0 {
        return false;
    }
    if let [b'e' | b'E', after @ ..] = rest {
        let after = match after {
            [b'+' | b'-', after @ ..] => after,
            after => after,
        };
        let exponent = digits(after);
        return exponent > 0 && exponent == after.len();
    }
    rest.is_empty()
}

/// The digits of a `0x`, `0o` or `0b` literal (`bits` per digit), rounded
/// to the nearest double, ties to even; `NaN` when empty or invalid.
fn radix_to_number(digits: &[u8], bits: u32) -> f64 {
    let radix = 1u32 << bits;
    let Some(values) = digits
        .iter()
        .map(|&b| char::from(b).to_digit(radix))
        .collect::<Option<Vec<u32>>>()
    else {
        return f64::NAN;
    };
    if values.is_empty() {
        return f64::NAN;
    }
    // The top 64 significant bits, with any lower 1 bits folded into the
    // last one, round to 53 bits exactly as the whole value does.
    let mut top: u64 = 0;
    let mut width: u32 = 0;
    let mut shift: i32 = 0;
    let mut sticky = false;
    for value in values.into_iter().skip_while(|&v| v == 0) {
        for bit in (0..bits).rev() {
            let one = (value >> bit) & 1 == 1;
            if width < 64 {
                top = (top << 1) | u64::from(one);
                width += 1;
            } else {
                sticky |= one;
                shift = shift.saturating_add(1);
            }
        }
    }
    if sticky {
        top |= 1;
    }
    (top as f64) * 2f64.powi(shift)
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

/// What `value[i]` gives for a JSON value.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Element<'i, 't> {
    Undefined,
    Value(Value<'i, 't>),
    /// One UTF-16 unit of a string, as a one-unit string.
    Unit(u16),
}

impl<'i, 't> Element<'i, 't> {
    /// `element == null`.
    pub(crate) fn is_nullish(self) -> bool {
        match self {
            Self::Undefined => true,
            Self::Value(value) => value.kind() == Kind::Null,
            Self::Unit(_) => false,
        }
    }

    /// The value, when the element is a JSON value of `kind`.
    pub(crate) fn of_kind(self, kind: Kind) -> Option<Value<'i, 't>> {
        match self {
            Self::Value(value) if value.kind() == kind => Some(value),
            _ => None,
        }
    }

    /// `JSON.stringify(element)`; `None` for `undefined`.
    pub(crate) fn to_json(self) -> Option<String> {
        match self {
            Self::Undefined => None,
            Self::Value(value) => Some(value.stringify(KeyOrder::Property)),
            Self::Unit(unit) => Some(JsString::from_units(vec![unit]).to_json()),
        }
    }

    /// `String(element)`.
    pub(crate) fn js_string(self) -> Result<JsString, JsError> {
        match self {
            Self::Undefined => Ok(JsString::from("undefined")),
            Self::Value(value) => js_string_of(value),
            Self::Unit(unit) => Ok(JsString::from_units(vec![unit])),
        }
    }
}

/// `value[i]`: an array's element, an object's property `"i"`, a string's
/// code unit, or `undefined`. `None` for `null`, where JavaScript throws
/// (and `?.[i]` gives `undefined`).
pub(crate) fn element<'i, 't>(value: Value<'i, 't>, i: usize) -> Option<Element<'i, 't>> {
    let found = match value.kind() {
        Kind::Null => return None,
        Kind::Array => value.children().nth(i).map(Element::Value),
        Kind::Object => value.get(&i.to_string()).map(Element::Value),
        Kind::String => value.units().nth(i).map(Element::Unit),
        Kind::True | Kind::False | Kind::Number => None,
    };
    Some(found.unwrap_or(Element::Undefined))
}

/// `TypeError`'s message for `null[i]`.
pub(crate) fn null_index_message(i: usize) -> String {
    format!("Cannot read properties of null (reading '{i}')")
}

/// `String(value)` for a JSON value. Arrays join their elements with commas
/// (nested arrays too, null elements empty); an object is `[object Object]`
/// unless it has its own `toString` key, which makes `ToPrimitive` throw.
pub(crate) fn js_string_of(value: Value<'_, '_>) -> Result<JsString, JsError> {
    js_string_of_into(value, JsString::new())
}

/// [`js_string_of`], appended to `out`: a caller gives it a buffer sized
/// by [`js_string_len`].
pub(crate) fn js_string_of_into(
    value: Value<'_, '_>,
    mut out: JsString,
) -> Result<JsString, JsError> {
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

/// The length of [`js_string_of`]'s string in UTF-16 code units, found
/// without building it (a number's text is built, a few bytes): a caller
/// reserves the string's room first. An object with its own `toString` is
/// `None`, as [`js_string_of`] fails on it.
pub(crate) fn js_string_len(value: Value<'_, '_>) -> Option<usize> {
    fn scalar(value: Value<'_, '_>) -> Option<usize> {
        Some(match value.kind() {
            Kind::Null => 4,
            Kind::True => 4,
            Kind::False => 5,
            Kind::Number => number_to_string(value.number()).len(),
            Kind::String => value.units().count(),
            Kind::Object if value.get("toString").is_some() => return None,
            Kind::Object => "[object Object]".len(),
            Kind::Array => js_string_len(value)?,
        })
    }
    if value.kind() != Kind::Array {
        return scalar(value);
    }
    let mut len = 0usize;
    let mut stack = vec![(value.children(), true)];
    while let Some((items, first)) = stack.last_mut() {
        let Some(item) = items.next() else {
            stack.pop();
            continue;
        };
        if !*first {
            len += 1;
        }
        *first = false;
        match item.kind() {
            Kind::Array => stack.push((item.children(), true)),
            Kind::Null => {}
            _ => len = len.saturating_add(scalar(item)?),
        }
    }
    Some(len)
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
    fn string_lengths_are_known_before_the_strings() {
        for text in [
            r#"[1,[2,[3,null]],{"a":1},"x",true,-0,1e21,[]]"#,
            "null",
            "1e400",
            r#""\ud800é😀""#,
            r#"{"valueOf":1}"#,
            "[[[]],[null,false]]",
        ] {
            let index = fc_json::index::Index::new(text).unwrap();
            let built = js_string_of(index.root()).unwrap();
            assert_eq!(js_string_len(index.root()), Some(built.len()), "{text}");
        }
        let index = fc_json::index::Index::new(r#"[[{"toString":"x"}]]"#).unwrap();
        assert_eq!(js_string_len(index.root()), None);
    }

    #[test]
    fn whitespace_and_trim() {
        let units: Vec<u16> = "\u{feff} a b\u{3000}\n".encode_utf16().collect();
        assert_eq!(String::from_utf16_lossy(trim(&units)), "a b");
        assert!(trim(&[0x20, 0x09]).is_empty());
        assert!(!is_js_whitespace(0x85) && !is_js_whitespace(0x180E) && !is_js_whitespace(0x200B));
    }
}
