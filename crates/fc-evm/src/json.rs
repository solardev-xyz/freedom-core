//! JSON text read as `JSON.parse` reads it, for the values the signers take
//! (design 0002, Values): serde_json gives the structure, and every number
//! that isn't an exact integer is read again from its own spelling,
//! normalized ([`exact_f64`]), with Rust's correctly rounded parser.
//!
//! serde_json's default parser rounds approximately, and its
//! `float_roundtrip` parser still misrounds some valid spellings: an integer
//! significand padded with zeros and a compensating exponent
//! (`45035996273704965` and 752 zeros, then `e-753`, is 2^52 + ½, which
//! `JSON.parse` rounds to 2^52), and halfway values below the smallest
//! subnormal (2^-1075 is 0 in JavaScript). A typed-data integer read
//! another way than ethers reads it would be signed as another value than
//! the approval UI shows (#87).
//!
//! Rust's own parser isn't enough for every spelling either: it stops
//! reading an explicit exponent at 0x10000 before it adds the decimal
//! point's position, so `0.`, 655,359 zeros and `1e+655360` (exactly 1)
//! reads as 0. [`exact_f64`] therefore moves the decimal point first, and
//! hands std only a spelling whose exponent is small.

use fc_json::index::{Index, Kind, Value as Spanned};
use serde_json::{Number, Value};

use crate::Error;

fn invalid() -> Error {
    Error::Value("JSON".into())
}

/// Parses `text` as serde_json does, with each number that serde_json
/// doesn't hold as an exact integer read as `JSON.parse` reads it: the
/// double nearest its spelling, ties to even.
pub fn parse_json(text: &str) -> Result<Value, Error> {
    let mut value: Value = serde_json::from_str(text).map_err(|_| invalid())?;
    if has_inexact(&value) {
        // serde_json accepted the text, so the index's grammar (V8's, which
        // nests deeper) accepts it too.
        let index = Index::new(text).map_err(|_| invalid())?;
        correct(&mut value, index.root())?;
    }
    Ok(value)
}

/// Whether any number in `value` is held as a double: a spelling with a
/// fraction or an exponent, or an integer past 64 bits.
fn has_inexact(value: &Value) -> bool {
    match value {
        Value::Number(n) => n.is_f64(),
        Value::Array(items) => items.iter().any(has_inexact),
        Value::Object(map) => map.values().any(has_inexact),
        Value::Null | Value::Bool(_) | Value::String(_) => false,
    }
}

/// Rereads every double in `value` from the span the same text gave it, in
/// one walk of the whole value. serde_json keeps a duplicate key's last
/// value, so a member is matched with the key's last span.
fn correct(value: &mut Value, spanned: Spanned<'_, '_>) -> Result<(), Error> {
    match value {
        Value::Number(n) if n.is_f64() => {
            if spanned.kind() != Kind::Number {
                return Err(invalid());
            }
            let exact = exact_f64(spanned.raw()).ok_or_else(invalid)?;
            *n = Number::from_f64(exact).ok_or_else(invalid)?;
        }
        Value::Array(items) => {
            if spanned.kind() != Kind::Array {
                return Err(invalid());
            }
            let mut children = spanned.children();
            for item in items.iter_mut() {
                correct(item, children.next().ok_or_else(invalid)?)?;
            }
        }
        Value::Object(map) => {
            if spanned.kind() != Kind::Object {
                return Err(invalid());
            }
            let mut last = std::collections::HashMap::new();
            for (key, member) in spanned.members() {
                let key: String = serde_json::from_str(key.raw()).map_err(|_| invalid())?;
                last.insert(key, member);
            }
            for (key, member) in map.iter_mut() {
                correct(member, *last.get(key).ok_or_else(invalid)?)?;
            }
        }
        Value::Number(_) | Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

/// An explicit exponent's magnitude is read up to this, then saturates:
/// any exponent past it puts the value far outside a double's range, since
/// a frame holds at most about 10^6 digits to compensate with.
const EXPONENT_CAP: i128 = 1_000_000_000_000_000_000_000_000_000_000;

/// A JSON number's value as `JSON.parse` reads it: the double nearest the
/// exact decimal its spelling denotes, ties to even, however long the
/// spelling. `None` when that is infinite. `spelling` is a valid JSON
/// number (`-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`).
///
/// The digits, without leading and trailing zeros, are d1…dn with d1 ≠ 0,
/// and the value is 0.d1…dn × 10^E exactly, so it lies in [10^(E−1), 10^E):
/// - **E > 310:** the value is at least 10^310, above the largest double
///   (about 1.8 × 10^308) by far more than half its spacing: infinity.
/// - **E < −324:** the value is below 10^−325, which is less than 2^−1075
///   (about 2.5 × 10^−324), half the smallest subnormal: it rounds to 0.
/// - **Otherwise** |E| ≤ 324, and std reads the spelling `0.d1…dne<E>`
///   correctly: its exponent is far below std's saturation, and std counts
///   the digits after the point exactly.
fn exact_f64(spelling: &str) -> Option<f64> {
    let (negative, unsigned) = match spelling.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, spelling),
    };
    let (mantissa, exponent) = match unsigned.find(['e', 'E']) {
        Some(at) => (&unsigned[..at], &unsigned[at + 1..]),
        None => (unsigned, ""),
    };
    let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let explicit = explicit_exponent(exponent);
    let digits = || int.bytes().chain(frac.bytes());
    let total = int.len() + frac.len();
    let leading = digits().take_while(|d| *d == b'0').count();
    let signed = |value: f64| if negative { -value } else { value };
    if leading == total {
        return Some(signed(0.0));
    }
    let trailing = int
        .bytes()
        .chain(frac.bytes())
        .rev()
        .take_while(|d| *d == b'0')
        .count();
    let significant = total - leading - trailing;
    // value = D × 10^(explicit − frac) with D the digits as an integer, so
    // = 0.d1…dn × 10^(n + explicit − frac + trailing).
    #[allow(clippy::cast_possible_wrap)]
    let e = significant as i128 + explicit - frac.len() as i128 + trailing as i128;
    if e > 310 {
        return None;
    }
    if e < -324 {
        return Some(signed(0.0));
    }
    let mut canonical = String::with_capacity(significant + 8);
    canonical.push_str("0.");
    canonical.extend(digits().skip(leading).take(significant).map(char::from));
    canonical.push('e');
    canonical.push_str(&e.to_string());
    let value: f64 = canonical.parse().ok()?;
    value.is_finite().then(|| signed(value))
}

/// An exponent's digits, with their sign, saturating at [`EXPONENT_CAP`].
fn explicit_exponent(exponent: &str) -> i128 {
    let (negative, digits) = match exponent.as_bytes().first() {
        Some(b'-') => (true, &exponent[1..]),
        Some(b'+') => (false, &exponent[1..]),
        _ => (false, exponent),
    };
    let mut magnitude: i128 = 0;
    for digit in digits.bytes() {
        magnitude = (magnitude * 10 + i128::from(digit - b'0')).min(EXPONENT_CAP);
    }
    if negative { -magnitude } else { magnitude }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_take_their_correctly_rounded_value() {
        let one = |text: &str| parse_json(text).unwrap();
        // Exact integers stay as serde_json holds them.
        assert_eq!(
            one("9007199254740993"),
            Value::from(9_007_199_254_740_993u64)
        );
        assert_eq!(one("-5"), Value::from(-5));
        // A double's spelling is reread.
        assert_eq!(
            one("4503599627370496.5").as_f64(),
            Some(4_503_599_627_370_496.0)
        );
        let padded = format!("45035996273704965{}e-753", "0".repeat(752));
        assert_eq!(one(&padded).as_f64(), Some(4_503_599_627_370_496.0));
        assert_eq!(
            one(&format!("-{padded}")).as_f64(),
            Some(-4_503_599_627_370_496.0)
        );
        // Nested, in arrays, and under a duplicate key: the last one.
        let nested = format!(r#"{{"a":[1,{{"b":{padded}}}],"c":0.5,"c":{padded}}}"#);
        let value = one(&nested);
        assert_eq!(value["a"][1]["b"].as_f64(), Some(4_503_599_627_370_496.0));
        assert_eq!(value["c"].as_f64(), Some(4_503_599_627_370_496.0));
        // What serde_json refuses stays refused.
        assert!(parse_json("1e400").is_err());
        assert!(parse_json(r#""\ud800""#).is_err());
        assert!(parse_json("{").is_err());
    }

    /// Where std reads a spelling exactly (a short exponent), the
    /// normalization reads it the same: across the whole range, around both
    /// thresholds, ties and long mantissas included.
    #[test]
    fn normalized_reading_agrees_with_std_where_std_is_exact() {
        let mantissas = [
            "1",
            "25",
            "4999",
            "0.0001",
            "17976931348623157",
            "17976931348623159",
            "24703282292062327",
            "24703282292062328",
            "45035996273704965",
            "4503599627370496.5",
            "123456789012345678901234567890",
            "0",
            "0.000",
        ];
        for mantissa in mantissas {
            for exp in -420..=420i32 {
                for sign in ["", "-"] {
                    let spelling = format!("{sign}{mantissa}e{exp}");
                    let std: f64 = spelling.parse().unwrap();
                    let ours = exact_f64(&spelling);
                    if std.is_finite() {
                        assert_eq!(ours.map(f64::to_bits), Some(std.to_bits()), "{spelling}");
                    } else {
                        assert_eq!(ours, None, "{spelling}");
                    }
                }
            }
        }
    }

    /// Std stops reading an explicit exponent at 0x10000, before it adds
    /// the decimal point's position: an exponent of 655,360 reads as
    /// 65,536. A spelling that compensates is still exact here, on both
    /// sides of that boundary, in both directions.
    #[test]
    fn compensated_exponents_read_exactly() {
        let one = |zeros: usize| format!("0.{}1e+{}", "0".repeat(zeros), zeros + 1);
        let one_down = |zeros: usize| format!("1{}e-{zeros}", "0".repeat(zeros));
        for zeros in [65_534, 65_535, 655_358, 655_359, 1_048_000] {
            assert_eq!(exact_f64(&one(zeros)), Some(1.0), "fraction {zeros}");
            assert_eq!(exact_f64(&one_down(zeros)), Some(1.0), "integer {zeros}");
            assert_eq!(exact_f64(&format!("-{}", one(zeros))), Some(-1.0));
        }
        // What std reads for the reviewer's spellings: 0 and infinity.
        assert_eq!(one(655_359).parse::<f64>().unwrap(), 0.0);
        assert!(one_down(1_048_000).parse::<f64>().unwrap().is_infinite());
        // A padded tie past the boundary is still 2^52, and just above it
        // 2^52 + 1.
        let zeros = "0".repeat(655_360);
        let tie = format!("45035996273704965{zeros}e-655361");
        assert_eq!(exact_f64(&tie), Some(4_503_599_627_370_496.0));
        let above = format!("45035996273704965{zeros}1e-655362");
        assert_eq!(exact_f64(&above), Some(4_503_599_627_370_497.0));
        // Exponents past any compensation saturate harmlessly.
        assert_eq!(exact_f64(&format!("1e{}", "9".repeat(60))), None);
        assert_eq!(exact_f64(&format!("1e-{}", "9".repeat(60))), Some(0.0));
        assert_eq!(
            exact_f64("0e99999999999999999999999999999999999"),
            Some(0.0)
        );
    }
}
