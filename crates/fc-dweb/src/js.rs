//! JavaScript's string and number semantics, where the handlers rely on them.

/// `WhiteSpace` and `LineTerminator`: what `String.prototype.trim` and
/// `Number()` strip, and what the `\s` class matches.
pub fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{9}'..='\u{d}'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// `string.trim()`.
pub(crate) fn trim(text: &str) -> &str {
    text.trim_matches(is_js_whitespace)
}

/// `string.length`: UTF-16 code units.
pub(crate) fn utf16_len(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// `(method || 'GET').toUpperCase()`.
pub(crate) fn method(method: &str) -> String {
    if method.is_empty() {
        "GET".to_owned()
    } else {
        method.to_uppercase()
    }
}

/// `Number(string)`: ECMAScript's StringToNumber.
pub fn number(text: &str) -> f64 {
    let text = trim(text);
    if text.is_empty() {
        return 0.0;
    }
    let bytes = text.as_bytes();
    if let [b'0', prefix, digits @ ..] = bytes {
        let radix = match prefix {
            b'x' | b'X' => Some(16),
            b'o' | b'O' => Some(8),
            b'b' | b'B' => Some(2),
            _ => None,
        };
        if let Some(radix) = radix {
            return radix_number(digits, radix);
        }
    }
    match text {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    if !is_decimal_literal(bytes) {
        return f64::NAN;
    }
    // The grammar is checked; Rust's parser rounds as JavaScript's does.
    text.parse::<f64>().unwrap_or(f64::NAN)
}

/// A non-decimal literal's value, rounded to a double: exact up to 2^53,
/// and only ever compared against small integers.
fn radix_number(digits: &[u8], radix: u32) -> f64 {
    if digits.is_empty() {
        return f64::NAN;
    }
    let mut value = 0.0f64;
    for &digit in digits {
        match char::from(digit).to_digit(radix) {
            Some(d) => value = value * f64::from(radix) + f64::from(d),
            None => return f64::NAN,
        }
    }
    value
}

/// StrDecimalLiteral: `[+-]? (digits [. digits?] | . digits) ([eE] [+-]? digits)?`.
fn is_decimal_literal(bytes: &[u8]) -> bool {
    let mut i = 0;
    if matches!(bytes.first(), Some(b'+' | b'-')) {
        i += 1;
    }
    let int_start = i;
    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
        i += 1;
    }
    let mut digits = i - int_start;
    if bytes.get(i) == Some(&b'.') {
        i += 1;
        let frac_start = i;
        while bytes.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        digits += i - frac_start;
    }
    if digits == 0 {
        return false;
    }
    if matches!(bytes.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(bytes.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let exp_start = i;
        while bytes.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == exp_start {
            return false;
        }
    }
    i == bytes.len()
}

/// `Number.isInteger(value)`.
pub(crate) fn is_integer(value: f64) -> bool {
    value.is_finite() && value.trunc() == value
}

/// `decodeURIComponent(text)`, or `None` where it throws a `URIError`.
pub fn decode_uri_component(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        if byte != b'%' {
            out.push(byte);
            i += 1;
            continue;
        }
        let first = escaped_byte(bytes, i)?;
        i += 3;
        if first < 0x80 {
            out.push(first);
            continue;
        }
        let count = match first {
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf7 => 4,
            _ => return None,
        };
        let mut sequence = vec![first];
        for _ in 1..count {
            if bytes.get(i) != Some(&b'%') {
                return None;
            }
            let next = escaped_byte(bytes, i)?;
            if next & 0xc0 != 0x80 {
                return None;
            }
            sequence.push(next);
            i += 3;
        }
        // Overlong forms, surrogates and code points past U+10FFFF throw.
        std::str::from_utf8(&sequence).ok()?;
        out.extend_from_slice(&sequence);
    }
    String::from_utf8(out).ok()
}

/// The byte `%XX` at `at` names.
fn escaped_byte(bytes: &[u8], at: usize) -> Option<u8> {
    let high = char::from(*bytes.get(at + 1)?).to_digit(16)?;
    let low = char::from(*bytes.get(at + 2)?).to_digit(16)?;
    u8::try_from(high * 16 + low).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_follows_string_to_number() {
        for (text, value) in [
            ("", 0.0),
            (" \u{a0}12\u{feff} ", 12.0),
            ("0x10", 16.0),
            ("0B11", 3.0),
            ("0o17", 15.0),
            ("1e3", 1000.0),
            ("5.", 5.0),
            (".5e1", 5.0),
            ("-0", -0.0),
        ] {
            assert_eq!(number(text), value, "{text:?}");
        }
        for text in [
            "0x",
            "+0x1",
            "1_0",
            ".",
            "e5",
            "1e",
            "Infinityx",
            "infinity",
            "\u{85}1",
            "1 2",
        ] {
            assert!(number(text).is_nan(), "{text:?}");
        }
        assert_eq!(number("-Infinity"), f64::NEG_INFINITY);
    }

    #[test]
    fn decode_uri_component_throws_where_javascript_does() {
        assert_eq!(decode_uri_component("a%2Fb%C3%A9").as_deref(), Some("a/bé"));
        for text in [
            "%",
            "%4",
            "%zz",
            "%C3",
            "%C3%28",
            "%ED%A0%80",
            "%C0%AF",
            "%F8%88%80%80%80",
        ] {
            assert_eq!(decode_uri_component(text), None, "{text:?}");
        }
    }
}
