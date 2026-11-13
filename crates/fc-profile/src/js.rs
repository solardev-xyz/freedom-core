//! The few JavaScript semantics the reference's operations lean on: property
//! reads that never throw, `||`, object spread, `Number.isInteger`, `trim`,
//! and `>` between two values.

use fc_json::{JsString, JsValue};

/// `{}`.
pub(crate) fn object() -> JsValue {
    JsValue::Object(Vec::new())
}

/// `value?.[key]`: an own property of an object, `undefined` otherwise (a
/// string's or an array's named property included: none of the keys the
/// reference reads is `length` or an index).
pub(crate) fn prop(value: &JsValue, key: &str) -> JsValue {
    value.get(key).cloned().unwrap_or(JsValue::Undefined)
}

/// `null` or `undefined`.
pub(crate) fn nullish(value: &JsValue) -> bool {
    matches!(value, JsValue::Undefined | JsValue::Null)
}

/// `a || b`.
pub(crate) fn or(a: JsValue, b: impl FnOnce() -> JsValue) -> JsValue {
    if a.truthy() { a } else { b() }
}

/// `value === text`.
pub(crate) fn is_str(value: &JsValue, text: &str) -> bool {
    matches!(value, JsValue::String(s) if s == text)
}

/// `Number.isInteger(value)`.
pub(crate) fn is_integer(value: &JsValue) -> bool {
    matches!(value, JsValue::Number(n) if n.is_finite() && n.trunc() == *n)
}

/// A string value.
pub(crate) fn string(text: &str) -> JsValue {
    JsValue::string(text)
}

/// `{ ...target, ...source }`'s second half, on `target`: an object's own
/// properties in order, an array's elements under their indices, a string's
/// UTF-16 units under theirs; nothing for any other value.
pub(crate) fn spread(target: &mut JsValue, source: &JsValue) {
    match source {
        JsValue::Object(props) => {
            for (key, value) in props {
                target.set(key.clone(), value.clone());
            }
        }
        JsValue::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                target.set(index.to_string(), item.clone());
            }
        }
        JsValue::String(text) => {
            for (index, unit) in text.units().enumerate() {
                target.set(
                    index.to_string(),
                    JsValue::String(JsString::from_units(&[unit])),
                );
            }
        }
        _ => {}
    }
}

/// `String.prototype.trim`'s whitespace: ECMAScript's WhiteSpace and
/// LineTerminator, which differ from Rust's `char::is_whitespace` (U+FEFF
/// is one, U+0085 isn't).
pub(crate) fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\u{9}' | '\u{a}' | '\u{b}' | '\u{c}' | '\u{d}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// `String.prototype.trim`.
pub(crate) fn trim(text: &str) -> &str {
    text.trim_matches(is_js_space)
}

/// `String(value || '')`, the reference's coercion of an id: `None` when
/// `String()` would throw (an object with its own `toString`).
pub(crate) fn coerce_or_empty(value: &JsValue) -> Option<String> {
    if value.truthy() {
        value.js_string().ok()
    } else {
        Some(String::new())
    }
}

/// `a > b`, by ECMAScript's Abstract Relational Comparison: two strings by
/// their UTF-16 units, anything else as numbers (`NaN` compares false).
pub(crate) fn greater(a: &JsValue, b: &JsValue) -> bool {
    match (primitive(a), primitive(b)) {
        (Primitive::String(a), Primitive::String(b)) => a > b,
        (a, b) => {
            let (a, b) = (a.number(), b.number());
            a > b
        }
    }
}

enum Primitive {
    String(JsString),
    Number(f64),
}

impl Primitive {
    fn number(self) -> f64 {
        match self {
            Primitive::Number(n) => n,
            Primitive::String(s) => string_to_number(s.as_str()),
        }
    }
}

/// `ToPrimitive(value, number)`: an object's or array's `toString()`.
fn primitive(value: &JsValue) -> Primitive {
    match value {
        JsValue::Undefined => Primitive::Number(f64::NAN),
        JsValue::Null => Primitive::Number(0.0),
        JsValue::Bool(b) => Primitive::Number(if *b { 1.0 } else { 0.0 }),
        JsValue::Number(n) => Primitive::Number(*n),
        JsValue::String(s) => Primitive::String(s.clone()),
        JsValue::Array(_) | JsValue::Object(_) => match value.js_string() {
            Ok(text) => Primitive::String(JsString::from(text)),
            Err(_) => Primitive::Number(f64::NAN),
        },
    }
}

/// `Number(text)`: ECMAScript's StringToNumber.
fn string_to_number(text: &str) -> f64 {
    let text = trim(text);
    if text.is_empty() {
        return 0.0;
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(digits) = text.strip_prefix(prefix) {
            if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                return f64::NAN;
            }
            return digits.chars().fold(0.0, |n, c| {
                n * f64::from(radix) + f64::from(c.to_digit(radix).unwrap_or(0))
            });
        }
    }
    let (sign, body) = match text.as_bytes().first() {
        Some(b'-') => (-1.0, &text[1..]),
        Some(b'+') => (1.0, &text[1..]),
        _ => (1.0, text),
    };
    if body == "Infinity" {
        return sign * f64::INFINITY;
    }
    if !decimal_literal(body) {
        return f64::NAN;
    }
    body.parse::<f64>().map_or(f64::NAN, |n| sign * n)
}

/// StrUnsignedDecimalLiteral: digits with an optional point (at least one
/// digit on either side), and an optional exponent.
fn decimal_literal(text: &str) -> bool {
    let (mantissa, exponent) = match text.find(['e', 'E']) {
        Some(at) => (&text[..at], Some(&text[at + 1..])),
        None => (text, None),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty() && fraction.is_empty() || !digits(whole) || !digits(fraction) {
        return false;
    }
    match exponent {
        None => true,
        Some(e) => {
            let e = e.strip_prefix(['+', '-']).unwrap_or(e);
            !e.is_empty() && digits(e)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn comparisons_are_javascripts() {
        let s = |t: &str| JsValue::string(t);
        assert!(greater(&s("2026-01-02"), &s("2026-01-01")));
        assert!(!greater(&s("10"), &s("9")));
        assert!(greater(&JsValue::Number(10.0), &s("9")));
        assert!(!greater(&s("x"), &JsValue::Number(1.0)));
        assert!(greater(&JsValue::Bool(true), &JsValue::Null));
        assert!(greater(&s(" 0x10 "), &JsValue::Number(15.0)));
        assert!(!greater(&s("1e"), &JsValue::Number(0.0)));
        assert!(greater(&s(".5"), &JsValue::Number(0.0)));
        assert!(!greater(
            &s("-Infinity"),
            &JsValue::Number(f64::NEG_INFINITY)
        ));
    }

    #[test]
    fn trim_is_javascripts() {
        assert_eq!(trim("\u{feff}\u{a0} a b\u{2028}"), "a b");
        assert_eq!(trim("\u{85}a"), "\u{85}a");
    }

    #[test]
    fn spread_of_each_kind() {
        let mut target = object();
        spread(&mut target, &JsValue::string("ab"));
        spread(&mut target, &JsValue::Number(1.0));
        spread(&mut target, &fc_json::parse(r#"{"x":1}"#).unwrap());
        assert_eq!(target.stringify(), r#"{"0":"a","1":"b","x":1}"#);
    }
}
