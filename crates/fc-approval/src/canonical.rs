//! Canonical JSON: one text for each value the core parsed, so that two
//! texts of one request bind alike (design 0012, "Typed data").
//!
//! - Objects: every member kept, keys sorted by their UTF-8 bytes, no space.
//! - Arrays: in order.
//! - Strings: `"` and `\` escaped with a backslash, every control character
//!   below U+0020 as a six-character escape with lowercase hex, everything
//!   else as itself. A string written with other escapes in its own text
//!   (`Bob` with its `B` written as a `\u` escape, and `Bob`) is one
//!   string here.
//! - Numbers: what `JSON.parse` makes of them, where the core's parse
//!   ([`fc_evm::parse_json`]) keeps them apart only as `JSON.parse` would or
//!   more: an integer serde_json holds exactly is written in decimal; a
//!   double with no fraction and a magnitude below 2^63 is written as that
//!   integer (`1.0`, `1e0` and `1` are one number, and `-0` is `0`); any
//!   other double in Rust's shortest round-trip form. So two texts can bind
//!   apart where `JSON.parse` reads one number (an integer past 2^53 the
//!   core keeps exact), never alike where it reads two.

use serde_json::{Number, Value};
use sha2::{Digest as _, Sha256};

/// The canonical text of `value`.
pub(crate) fn text(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out);
    out
}

/// The SHA-256 of the canonical text of `value`.
pub(crate) fn digest(value: &Value) -> [u8; 32] {
    Sha256::digest(text(value).as_bytes()).into()
}

fn write(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => write_number(number, out),
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push('{');
            for (index, (key, member)) in members.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write(member, out);
            }
            out.push('}');
        }
    }
}

/// 2^63, the first double past `i64`.
const TWO_TO_63: f64 = 9_223_372_036_854_775_808.0;

fn write_number(number: &Number, out: &mut String) {
    if let Some(n) = number.as_u64() {
        out.push_str(&n.to_string());
    } else if let Some(n) = number.as_i64() {
        out.push_str(&n.to_string());
    } else if let Some(x) = number.as_f64() {
        if x.fract() == 0.0 && x.abs() < TWO_TO_63 {
            // Exact: an integral double below 2^63 converts without loss.
            #[allow(clippy::cast_possible_truncation)]
            let n = x as i64;
            out.push_str(&n.to_string());
        } else {
            out.push_str(&format!("{x:?}"));
        }
    }
}

fn write_string(text: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for c in text.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c if u32::from(c) < 0x20 => {
                let code = u32::from(c) as usize;
                out.push('\\');
                out.push('u');
                out.push('0');
                out.push('0');
                out.push(char::from(HEX[code >> 4]));
                out.push(char::from(HEX[code & 0xf]));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(json: &str) -> String {
        text(&fc_evm::parse_json(json).unwrap_or(Value::Null))
    }

    #[test]
    fn sorts_keys_and_keeps_every_member() {
        assert_eq!(
            canonical(r#"{ "b": [2, {"z": 1, "a": null}], "a": true }"#),
            r#"{"a":true,"b":[2,{"a":null,"z":1}]}"#
        );
    }

    #[test]
    fn numbers_as_json_parse_reads_them() {
        for (one, other) in [("1", "1.0"), ("1", "1e0"), ("100", "1e2"), ("0", "-0")] {
            assert_eq!(canonical(one), canonical(other), "{one} {other}");
        }
        assert_eq!(canonical("-5"), "-5");
        assert_eq!(canonical("1.5"), "1.5");
        assert_ne!(canonical("1.5"), canonical("1"));
        // Kept exact by the core's parse, so kept apart here.
        assert_ne!(canonical("9007199254740993"), canonical("9007199254740992"));
    }

    #[test]
    fn strings_have_one_spelling() {
        let backslash = char::from(b'\\');
        // "Bob" with its B escaped, and a newline escaped two ways.
        let escaped = format!("\"{backslash}u0042ob\"");
        assert_eq!(canonical(&escaped), "\"Bob\"");
        let newline_short = format!("\"a{backslash}nb\"");
        let newline_long = format!("\"a{backslash}u000ab\"");
        assert_eq!(canonical(&newline_short), canonical(&newline_long));
        assert_eq!(canonical(&newline_short), format!("\"a{backslash}u000ab\""));
        let quote = format!("\"{backslash}\"{backslash}{backslash}\"");
        assert_eq!(canonical(&quote), quote);
        assert_eq!(canonical("\"é\""), "\"é\"");
    }
}
