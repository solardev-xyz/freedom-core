//! JavaScript's coercions where the resolvers apply them to configuration
//! values (`Number(quorum.k) || 3`, `Math.min`, `Math.max`).

use crate::jsjson::JsValue;

/// `Number(value)`; `None` is `undefined`.
pub fn to_number(value: Option<&JsValue>) -> f64 {
    match value {
        None => f64::NAN,
        Some(JsValue::Null) => 0.0,
        Some(JsValue::Bool(b)) => f64::from(u8::from(*b)),
        Some(JsValue::Number(n)) => *n,
        Some(JsValue::String(s)) => string_to_number(s),
        // Arrays and objects go through ToPrimitive, i.e. their string.
        Some(other) => other.js_string().map_or(f64::NAN, |s| string_to_number(&s)),
    }
}

/// `Number(string)`: trimmed of JavaScript whitespace; empty is 0;
/// `0x`/`0o`/`0b` integers; `Infinity` with a sign; decimal literals.
pub fn string_to_number(s: &str) -> f64 {
    let t = crate::js_trim(s);
    if t.is_empty() {
        return 0.0;
    }
    let radix = |digits: &str, radix: u32| {
        if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
            return f64::NAN;
        }
        digits.chars().fold(0.0, |acc, c| {
            acc * f64::from(radix) + f64::from(c.to_digit(radix).unwrap_or(0))
        })
    };
    match t.get(..2).map(str::to_ascii_lowercase).as_deref() {
        Some("0x") => return radix(&t[2..], 16),
        Some("0o") => return radix(&t[2..], 8),
        Some("0b") => return radix(&t[2..], 2),
        _ => {}
    }
    let (sign, body) = match t.as_bytes().first() {
        Some(b'-') => (-1.0, &t[1..]),
        Some(b'+') => (1.0, &t[1..]),
        _ => (1.0, t),
    };
    if body == "Infinity" {
        return sign * f64::INFINITY;
    }
    // A StrDecimalLiteral: digits, an optional fraction, an optional
    // exponent; Rust's parser also takes "inf"/"nan", which JS doesn't.
    let valid = !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
        && body.bytes().any(|b| b.is_ascii_digit());
    if !valid {
        return f64::NAN;
    }
    body.parse::<f64>().map_or(f64::NAN, |n| sign * n)
}

/// `x || fallback` for a number.
pub fn or(x: f64, fallback: f64) -> f64 {
    if x == 0.0 || x.is_nan() { fallback } else { x }
}

/// `Math.min(a, b)`: NaN wins.
pub fn min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

/// `Math.max(a, b)`: NaN wins.
pub fn max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}

/// `Math.max(lo, Math.min(x, hi))`.
pub fn clamp(x: f64, lo: f64, hi: f64) -> f64 {
    max(lo, min(x, hi))
}

/// `array.slice(0, n)`'s end: ToIntegerOrInfinity, clamped to `len`.
pub fn slice_end(n: f64, len: usize) -> usize {
    if n.is_nan() || n <= 0.0 {
        return 0;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let end = n.trunc().min(usize::MAX as f64) as usize;
    end.min(len)
}

/// A `setTimeout` delay: truncated, and anything not ≥ 0 is 0, as the
/// reference's fake timers (`parseInt`) and Node both treat it.
pub fn delay_ms(ms: f64) -> u64 {
    if ms.is_nan() || ms <= 0.0 {
        return 0;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ms = ms.trunc().min(2_147_483_647.0) as u64;
    ms
}

/// `count >= m` for a set size and a possibly fractional M.
#[allow(clippy::cast_precision_loss)]
pub fn reaches(count: usize, m: f64) -> bool {
    count as f64 >= m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_coerce_as_javascript() {
        let s = |text: &str| to_number(Some(&JsValue::String(text.into())));
        assert_eq!(s(" 3 "), 3.0);
        assert_eq!(s(""), 0.0);
        assert_eq!(s("0x10"), 16.0);
        assert_eq!(s("1e3"), 1000.0);
        assert_eq!(s("-Infinity"), f64::NEG_INFINITY);
        assert!(s("3k").is_nan());
        assert!(s("inf").is_nan());
        assert_eq!(to_number(Some(&JsValue::Null)), 0.0);
        assert_eq!(to_number(Some(&JsValue::Bool(true))), 1.0);
        assert!(to_number(None).is_nan());
        assert_eq!(
            to_number(Some(&JsValue::Array(vec![JsValue::Number(5.0)]))),
            5.0
        );
    }

    #[test]
    fn clamps_follow_math_min_max() {
        // Math.max(2, Math.min(Number(k) || 3, 9)) for k = 0, 12, 2.5, NaN.
        assert_eq!(clamp(or(0.0, 3.0), 2.0, 9.0), 3.0);
        assert_eq!(clamp(or(12.0, 3.0), 2.0, 9.0), 9.0);
        assert_eq!(clamp(or(2.5, 3.0), 2.0, 9.0), 2.5);
        assert_eq!(clamp(or(f64::NAN, 3.0), 2.0, 9.0), 3.0);
        assert_eq!(slice_end(2.5, 4), 2);
        assert!(reaches(2, 1.5));
        assert!(!reaches(1, 1.5));
    }
}
