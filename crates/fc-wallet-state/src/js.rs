//! The few JavaScript operations identity-manager.js and payment-history.js
//! apply to their values, as V8 applies them.

use fc_json::{JsString, JsValue, ToPrimitiveError};

/// `Number.isInteger(value)`.
pub(crate) fn is_integer(value: Option<&JsValue>) -> bool {
    matches!(value, Some(JsValue::Number(n)) if n.is_finite() && n.trunc() == *n)
}

/// `a === b` for a number `b`: `a` is a number equal to it (`NaN` equals
/// nothing; `-0` equals `0`).
pub(crate) fn equals_number(a: Option<&JsValue>, b: f64) -> bool {
    matches!(a, Some(JsValue::Number(n)) if *n == b)
}

/// `a === b` for a string `b`.
pub(crate) fn equals_str(a: Option<&JsValue>, b: &str) -> bool {
    matches!(a, Some(JsValue::String(s)) if s.is_well_formed() && s.as_str() == b)
}

/// SameValueZero (`Set`, `Array.prototype.includes`) between two values
/// of a parsed document: primitives by value (`NaN` equals `NaN`), and no
/// two objects or arrays alike, since each is its own.
pub(crate) fn same_value_zero(a: &JsValue, b: &JsValue) -> bool {
    match (a, b) {
        (JsValue::Undefined, JsValue::Undefined) | (JsValue::Null, JsValue::Null) => true,
        (JsValue::Bool(x), JsValue::Bool(y)) => x == y,
        (JsValue::Number(x), JsValue::Number(y)) => x == y || (x.is_nan() && y.is_nan()),
        (JsValue::String(x), JsValue::String(y)) => x == y,
        _ => false,
    }
}

/// `String.prototype.trim`: JavaScript's white space and line terminators
/// off both ends (U+FEFF among them, U+0085 not, unlike Rust's `trim`).
pub(crate) fn trim(text: &JsString) -> JsString {
    let units: Vec<u16> = text.units().collect();
    let space = |unit: &u16| {
        matches!(
            *unit,
            0x09 | 0x0a | 0x0b | 0x0c | 0x0d | 0x20 | 0xa0 | 0x1680 | 0x2000
                ..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000 | 0xfeff
        )
    };
    let start = units.iter().position(|u| !space(u)).unwrap_or(units.len());
    let end = units
        .iter()
        .rposition(|u| !space(u))
        .map_or(start, |at| at + 1);
    JsString::from_units(&units[start..end.max(start)])
}

/// `String.prototype.toLowerCase`, as UTF-16 code units: Unicode's full
/// lowercase mapping (final sigma included) over each well-formed stretch,
/// and a lone surrogate kept as it is.
pub(crate) fn lowercase(text: &JsString) -> Vec<u16> {
    let mut out = Vec::new();
    let mut run = String::new();
    for decoded in char::decode_utf16(text.units()) {
        match decoded {
            Ok(c) => run.push(c),
            Err(lone) => {
                out.extend(run.to_lowercase().encode_utf16());
                run.clear();
                out.push(lone.unpaired_surrogate());
            }
        }
    }
    out.extend(run.to_lowercase().encode_utf16());
    out
}

/// `${value}`, as a template literal writes it (`ToString`), or the
/// `TypeError` message for an object whose `ToPrimitive` throws.
pub(crate) fn template(value: Option<&JsValue>) -> Result<String, String> {
    value
        .unwrap_or(&JsValue::Undefined)
        .js_string()
        .map_err(|error| error.to_string())
}

/// `${n}` for a number.
pub(crate) fn number(n: f64) -> String {
    fc_json::number_to_string(n)
}

/// The largest time value a `Date` holds, in milliseconds either side of
/// the epoch.
const MAX_TIME_MS: i64 = 8_640_000_000_000_000;

/// `new Date(ms).toISOString()`, or `None` where it throws (`RangeError:
/// Invalid time value`).
pub(crate) fn iso_string(ms: i64) -> Option<String> {
    if !(-MAX_TIME_MS..=MAX_TIME_MS).contains(&ms) {
        return None;
    }
    let days = ms.div_euclid(86_400_000);
    let in_day = ms.rem_euclid(86_400_000);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let year = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else if year < 0 {
        format!("-{:06}", -year)
    } else {
        format!("+{year:06}")
    };
    Some(format!(
        "{year}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        in_day / 3_600_000,
        in_day / 60_000 % 60,
        in_day / 1000 % 60,
        in_day % 1000
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso() {
        assert_eq!(iso_string(0).unwrap(), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            iso_string(1_762_000_000_123).unwrap(),
            "2025-11-01T12:26:40.123Z"
        );
        assert_eq!(
            iso_string(951_782_400_000).unwrap(),
            "2000-02-29T00:00:00.000Z"
        );
        assert_eq!(iso_string(-1).unwrap(), "1969-12-31T23:59:59.999Z");
        assert_eq!(
            iso_string(253_402_300_800_000).unwrap(),
            "+010000-01-01T00:00:00.000Z"
        );
        assert_eq!(
            iso_string(-62_198_755_200_000).unwrap(),
            "-000001-01-01T00:00:00.000Z"
        );
        assert_eq!(
            iso_string(MAX_TIME_MS).unwrap(),
            "+275760-09-13T00:00:00.000Z"
        );
        assert_eq!(
            iso_string(-MAX_TIME_MS).unwrap(),
            "-271821-04-20T00:00:00.000Z"
        );
        assert_eq!(iso_string(MAX_TIME_MS + 1), None);
    }

    #[test]
    fn trims_as_javascript() {
        let t = |s: &str| trim(&JsString::from(s)).as_str().to_owned();
        assert_eq!(t(" \t\u{a0}\u{feff}a b\u{2028}\u{3000}"), "a b");
        assert_eq!(t("\u{85}a\u{85}"), "\u{85}a\u{85}");
        assert_eq!(t("   "), "");
        assert_eq!(t(""), "");
    }

    #[test]
    fn lowercases_as_javascript() {
        let l = |s: &str| String::from_utf16(&lowercase(&JsString::from(s))).unwrap();
        assert_eq!(l("0xABcd"), "0xabcd");
        assert_eq!(l("ΑΣ"), "ας");
        assert_eq!(l("\u{130}"), "i\u{307}");
        let lone = JsString::from_units(&[0x41, 0xd800, 0x42]);
        assert_eq!(lowercase(&lone), vec![0x61, 0xd800, 0x62]);
    }

    #[test]
    fn same_value_zero_as_javascript() {
        let n = JsValue::Number;
        assert!(same_value_zero(&n(f64::NAN), &n(f64::NAN)));
        assert!(same_value_zero(&n(0.0), &n(-0.0)));
        assert!(!same_value_zero(&n(1.0), &JsValue::string("1")));
        assert!(!same_value_zero(
            &JsValue::Array(vec![]),
            &JsValue::Array(vec![])
        ));
        assert!(same_value_zero(&JsValue::Null, &JsValue::Null));
        assert!(!same_value_zero(&JsValue::Null, &JsValue::Undefined));
    }
}


/// `ToNumber(value)`, through `ToPrimitive(value, number)` for an array or
/// an object (its `toString`: no JSON value has a callable `valueOf`).
pub(crate) fn to_number(value: &JsValue) -> Result<f64, ToPrimitiveError> {
    Ok(match value {
        JsValue::Undefined => f64::NAN,
        JsValue::Null => 0.0,
        JsValue::Bool(flag) => f64::from(u8::from(*flag)),
        JsValue::Number(number) => *number,
        // A lone surrogate reads as U+FFFD, which no number holds either.
        JsValue::String(text) => string_to_number(text.as_str()),
        JsValue::Array(_) | JsValue::Object(_) => string_to_number(&value.js_string()?),
    })
}

/// ECMAScript's WhiteSpace and LineTerminator, which `StringToNumber`
/// trims (U+FEFF is one, U+0085 isn't).
fn is_js_space(c: char) -> bool {
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

/// `Number(text)`: ECMAScript's `StringToNumber`. Decimals are rounded to
/// the nearest double (ties to even), as `str::parse` rounds them; `0x`,
/// `0o` and `0b` integers too, as V8 rounds them.
pub(crate) fn string_to_number(text: &str) -> f64 {
    let text = text.trim_matches(is_js_space);
    if text.is_empty() {
        return 0.0;
    }
    for (prefix, bits) in [
        ("0x", 4),
        ("0X", 4),
        ("0o", 3),
        ("0O", 3),
        ("0b", 1),
        ("0B", 1),
    ] {
        if let Some(digits) = text.strip_prefix(prefix) {
            return radix_integer(digits, bits);
        }
    }
    let (negative, body) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let magnitude = if body == "Infinity" {
        f64::INFINITY
    } else if decimal_literal(body) {
        body.parse::<f64>().unwrap_or(f64::NAN)
    } else {
        return f64::NAN;
    };
    if negative { -magnitude } else { magnitude }
}

/// StrUnsignedDecimalLiteral, but `Infinity`: digits with an optional point
/// (a digit on at least one side of it) and an optional exponent.
fn decimal_literal(text: &str) -> bool {
    let (mantissa, exponent) = match text.find(['e', 'E']) {
        Some(at) => (&text[..at], Some(&text[at + 1..])),
        None => (text, None),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if (whole.is_empty() && fraction.is_empty()) || !digits(whole) || !digits(fraction) {
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

/// A `0x`/`0o`/`0b` integer's digits (`bits` a digit) as the nearest
/// double, ties to even; `NaN` if there are none or one isn't a digit.
fn radix_integer(digits: &str, bits: u32) -> f64 {
    let radix = 1u32 << bits;
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return f64::NAN;
    }
    // The first 60 or more significant bits, exactly; past them, how many
    // bits were left off and whether any of them was set.
    let mut mantissa: u64 = 0;
    let mut dropped: i64 = 0;
    let mut sticky = false;
    for c in digits.chars() {
        let digit = u64::from(c.to_digit(radix).unwrap_or(0));
        if mantissa < 1 << 60 {
            mantissa = (mantissa << bits) | digit;
        } else {
            dropped += i64::from(bits);
            sticky |= digit != 0;
        }
    }
    if mantissa == 0 {
        return 0.0;
    }
    // Round to 53 bits.
    let length = 64 - i64::from(mantissa.leading_zeros());
    let mut shift = (length - 53).max(0);
    let mut kept = mantissa >> shift;
    if shift > 0 {
        let rest = mantissa & ((1u64 << shift) - 1);
        let half = 1u64 << (shift - 1);
        if rest > half || (rest == half && (sticky || kept & 1 == 1)) {
            kept += 1;
            if kept == 1 << 53 {
                kept >>= 1;
                shift += 1;
            }
        }
    }
    let exponent = shift + dropped;
    if exponent > 1023 {
        return f64::INFINITY;
    }
    // `kept` < 2^53 is exact, and so is a power of two up to 2^1023.
    let scale = f64::from_bits(((exponent + 1023) as u64) << 52);
    kept as f64 * scale
}
