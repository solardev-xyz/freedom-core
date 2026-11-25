//! The few JavaScript operations the reference's texts and arithmetic rest
//! on, with ECMAScript's exact results: `String.prototype.trim`,
//! `toLowerCase` compared against ASCII text, `Math.round`, `2 ** n`,
//! `Number.isInteger`, and the two ways the reference turns a node's bytes
//! into a string (`Response.text()` and `Buffer.toString('utf8')`).

use fc_json::JsString;

/// `Response.text()`: UTF-8 with U+FFFD for each bad sequence (the WHATWG
/// decoder's maximal subparts, as `String::from_utf8_lossy` replaces them),
/// a leading byte-order mark dropped.
pub fn response_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(strip_bom(bytes)).into_owned()
}

/// `Buffer.toString('utf8')`: the same decoding, a byte-order mark kept.
pub fn buffer_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The bytes after a leading UTF-8 byte-order mark, as `Response.text()`
/// reads them.
pub fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)
}

/// Whether `c` is one of ECMAScript's WhiteSpace or LineTerminator code
/// points, which `trim` removes: tab, vertical tab, form feed, space,
/// no-break space, the byte-order mark, every `Zs` character, line feed,
/// carriage return, and the line and paragraph separators. (Rust's
/// `char::is_whitespace` differs: it takes U+0085 and leaves U+FEFF.)
pub fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

/// `s.trim().toLowerCase() === target`, for an ASCII `target`. A lone
/// surrogate is neither whitespace nor lowercased into ASCII, so a string
/// holding one never equals an ASCII target, as in JavaScript.
pub fn trimmed_lowercase_is(s: &JsString, target: &str) -> bool {
    if !s.is_well_formed() {
        return false;
    }
    s.as_str().trim_matches(is_js_whitespace).to_lowercase() == target
}

/// `s.trim()`, lone surrogates kept. Every ECMAScript whitespace character
/// is one UTF-16 unit outside the surrogates.
pub fn trim(s: &JsString) -> JsString {
    if s.is_well_formed() {
        return JsString::from(s.as_str().trim_matches(is_js_whitespace));
    }
    let units: Vec<u16> = s.units().collect();
    let space = |u: &u16| char::from_u32(u32::from(*u)).is_some_and(is_js_whitespace);
    let start = units.iter().position(|u| !space(u)).unwrap_or(units.len());
    let end = units
        .iter()
        .rposition(|u| !space(u))
        .map_or(start, |p| p + 1);
    JsString::from_units(&units[start..end])
}

/// `s.toLowerCase()`, lone surrogates kept. A lone surrogate is neither
/// cased nor case-ignorable, so lowercasing each well-formed run apart
/// gives what JavaScript gives, final sigma included.
pub fn to_lower(s: &JsString) -> JsString {
    if s.is_well_formed() {
        return JsString::from(s.as_str().to_lowercase());
    }
    let mut out: Vec<u16> = Vec::new();
    let mut run = String::new();
    for decoded in char::decode_utf16(s.units()) {
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
    JsString::from_units(&out)
}

/// `Math.round(x)`: the nearest integer, a tie towards +∞; -0 for a
/// result of zero from a negative `x` (or -0).
pub fn math_round(x: f64) -> f64 {
    if !x.is_finite() || x == 0.0 {
        return x;
    }
    let floor = x.floor();
    // Exact: a double's fractional part is itself a double.
    let rounded = if x - floor >= 0.5 { floor + 1.0 } else { floor };
    if rounded == 0.0 && x < 0.0 {
        -0.0
    } else {
        rounded
    }
}

/// `2 ** e` for an integer `e`, exactly as V8 computes it (built from its
/// bits; past the doubles' range it is Infinity or 0, as the rounded value
/// is). A fractional exponent would need V8's own `pow`, which the platform's
/// can differ from in the last place, so it is never computed: callers
/// refuse a fractional batch depth first (deviation `batch-depth`), and one
/// that reached here gives NaN.
pub fn pow2(e: f64) -> f64 {
    if !is_integer(e) {
        return f64::NAN;
    }
    if e > 1023.0 {
        f64::INFINITY
    } else if e >= -1022.0 {
        // A normal double: the biased exponent alone.
        f64::from_bits(((e as i64 + 1023) as u64) << 52)
    } else if e >= -1074.0 {
        // A subnormal: one mantissa bit.
        f64::from_bits(1u64 << ((e as i64 + 1074) as u64))
    } else {
        0.0
    }
}

/// `Number.isInteger(x)` for a number.
pub fn is_integer(x: f64) -> bool {
    x.is_finite() && x.floor() == x
}

/// A JavaScript string from its parts, each UTF-16 unit kept: `a + b`.
pub fn concat(parts: &[&JsString]) -> JsString {
    if parts.iter().all(|p| p.is_well_formed()) {
        let mut text = String::new();
        for part in parts {
            text.push_str(part.as_str());
        }
        return JsString::from(text);
    }
    let units: Vec<u16> = parts.iter().flat_map(|p| p.units()).collect();
    JsString::from_units(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_is_math_round() {
        let cases: [(f64, f64); 12] = [
            (0.5, 1.0),
            (1.5, 2.0),
            (2.5, 3.0),
            (-0.5, -0.0),
            (-1.5, -1.0),
            (-2.5, -2.0),
            (0.49999999999999994, 0.0),
            (4503599627370497.0, 4503599627370497.0),
            (-4503599627370497.0, -4503599627370497.0),
            (99.99999999999999, 100.0),
            (1e300, 1e300),
            (-0.2, -0.0),
        ];
        for (x, want) in cases {
            let got = math_round(x);
            assert_eq!(got.to_bits(), want.to_bits(), "Math.round({x})");
        }
        assert!(math_round(f64::NAN).is_nan());
        assert_eq!(math_round(f64::INFINITY), f64::INFINITY);
        assert_eq!(math_round(-0.0).to_bits(), (-0.0f64).to_bits());
    }

    #[test]
    fn powers_of_two_are_exact() {
        for e in -1074..=1023 {
            let want = if e >= 0 {
                (0..e).fold(1.0f64, |acc, _| acc * 2.0)
            } else {
                (0..-e).fold(1.0f64, |acc, _| acc / 2.0)
            };
            assert_eq!(pow2(f64::from(e)), want, "2 ** {e}");
        }
        assert_eq!(pow2(1024.0), f64::INFINITY);
        assert_eq!(pow2(-1075.0), 0.0);
        assert_eq!(pow2(-5000.0), 0.0);
        assert!(pow2(0.5).is_nan(), "no fractional power is computed");
    }

    #[test]
    fn trim_is_ecmascript_trim() {
        let s = |t: &str| JsString::from(t);
        assert!(trimmed_lowercase_is(
            &s(" Read Chunk Failed "),
            "read chunk failed"
        ));
        assert!(trimmed_lowercase_is(
            &s("\u{FEFF}\u{3000}read chunk failed\u{2029}"),
            "read chunk failed"
        ));
        // U+0085 is Rust whitespace, not ECMAScript's.
        assert!(!trimmed_lowercase_is(
            &s("\u{85}read chunk failed"),
            "read chunk failed"
        ));
        // The Kelvin sign lowercases to an ASCII k, in both.
        assert!(trimmed_lowercase_is(
            &s("read chun\u{212A} failed"),
            "read chunk failed"
        ));
        assert!(!trimmed_lowercase_is(
            &JsString::from_units(&[0xd800]),
            "\u{FFFD}"
        ));
    }

    #[test]
    fn texts_decode_as_the_reference_does() {
        assert_eq!(response_text(b"\xEF\xBB\xBFhi"), "hi");
        assert_eq!(buffer_text(b"\xEF\xBB\xBFhi"), "\u{FEFF}hi");
        assert_eq!(response_text(b"hi\xFF, \xC3"), "hi\u{FFFD}, \u{FFFD}");
        // One U+FFFD per maximal subpart.
        assert_eq!(response_text(b"\xE2\x82"), "\u{FFFD}");
        assert_eq!(response_text(b"\xF0\x80\x80"), "\u{FFFD}\u{FFFD}\u{FFFD}");
    }
}
