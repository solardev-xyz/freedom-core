//! JSON text as the reference writes its grant files:
//! `JSON.stringify(value, null, 2)` (design 0012, "The files": "the same
//! keys, `JSON.stringify(…, null, 2)`'s text, and JS's key order").
//!
//! What a rewrite keeps as JS writes it:
//! - **Key order:** a map's insertion order (`serde_json`'s
//!   `preserve_order`), but for keys that are array indices (`"0"` to
//!   `"4294967294"` in canonical form), which every JS object lists first,
//!   in ascending order.
//! - **Numbers:** JS reads every number as a double and writes it with
//!   `Number.prototype.toString`: `1e21` as `1e+21`, `-0` as `0`, `2.50` as
//!   `2.5`, and an integer past 2^53 rounded to the nearest double.
//! - **Strings:** `"`, `\` and the C0 controls escaped as `JSON.stringify`
//!   escapes them, everything else as it is.

use serde_json::{Map, Value};

/// `JSON.stringify(value, null, 2)`.
pub(crate) fn stringify(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value, 0);
    out
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn write_value(out: &mut String, value: &Value, depth: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => match number.as_f64() {
            Some(float) => out.push_str(&js_number(float)),
            None => out.push_str("null"),
        },
        Value::String(text) => quote(out, text),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push('\n');
                indent(out, depth + 1);
                write_value(out, item, depth + 1);
            }
            out.push('\n');
            indent(out, depth);
            out.push(']');
        }
        Value::Object(map) => write_object(out, map, depth),
    }
}

/// `JSON.stringify(object, null, 2)` of a map, as the files' top level is.
pub(crate) fn stringify_object(map: &Map<String, Value>) -> String {
    let mut out = String::new();
    write_object(&mut out, map, 0);
    out
}

fn write_object(out: &mut String, map: &Map<String, Value>, depth: usize) {
    if map.is_empty() {
        out.push_str("{}");
        return;
    }
    out.push('{');
    for (index, (key, item)) in js_order(map).into_iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('\n');
        indent(out, depth + 1);
        quote(out, key);
        out.push_str(": ");
        write_value(out, item, depth + 1);
    }
    out.push('\n');
    indent(out, depth);
    out.push('}');
}

/// A JS object's own keys in order: array indices first, ascending, then
/// the rest in insertion order.
pub(crate) fn js_order(map: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut indices: Vec<(u32, &String, &Value)> = Vec::new();
    let mut rest = Vec::with_capacity(map.len());
    for (key, value) in map {
        match array_index(key) {
            Some(index) => indices.push((index, key, value)),
            None => rest.push((key, value)),
        }
    }
    indices.sort_by_key(|(index, _, _)| *index);
    let mut ordered: Vec<(&String, &Value)> = indices
        .into_iter()
        .map(|(_, key, value)| (key, value))
        .collect();
    ordered.extend(rest);
    ordered
}

/// The key as an array index: a canonical decimal below 2^32 − 1.
fn array_index(key: &str) -> Option<u32> {
    if key.is_empty() || key.len() > 10 || !key.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if key.len() > 1 && key.starts_with('0') {
        return None;
    }
    let index: u64 = key.parse().ok()?;
    if index >= u64::from(u32::MAX) {
        return None;
    }
    u32::try_from(index).ok()
}

fn quote(out: &mut String, text: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let code = u32::from(c);
                out.push_str("\\u00");
                out.push(char::from(HEX[(code >> 4) as usize]));
                out.push(char::from(HEX[(code & 0xf) as usize]));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `Number.prototype.toString()` of a finite double (ECMA-262,
/// Number::toString): the shortest digits that read back as the same
/// double, written plainly while the exponent allows and in exponent form
/// past it.
pub(crate) fn js_number(value: f64) -> String {
    if !value.is_finite() {
        return "null".to_owned();
    }
    if value == 0.0 {
        return "0".to_owned();
    }
    // Rust's shortest round-trip digits, as `d.ddde±x`.
    let scientific = format!("{value:e}");
    let (negative, unsigned) = match scientific.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, scientific.as_str()),
    };
    let Some((mantissa, exponent)) = unsigned.split_once('e') else {
        return format!("{value}");
    };
    let Ok(exponent) = exponent.parse::<i64>() else {
        return format!("{value}");
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i64;
    // The value is 0.digits × 10^n.
    let n = exponent + 1;
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        for _ in 0..(n - k) {
            out.push('0');
        }
    } else if 0 < n && n <= 21 {
        let split = n as usize;
        out.push_str(&digits[..split]);
        out.push('.');
        out.push_str(&digits[split..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        out.push_str(&digits[..1]);
        if k > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        let shown = n - 1;
        out.push(if shown >= 0 { '+' } else { '-' });
        out.push_str(&shown.unsigned_abs().to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_as_js_writes_them() {
        let cases: &[(f64, &str)] = &[
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (1.5, "1.5"),
            (-1.25e-10, "-1.25e-10"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (123456789012345680000.0, "123456789012345680000"),
            (1e-7, "1e-7"),
            (1e-6, "0.000001"),
            (0.1, "0.1"),
            (1762000000000.0, "1762000000000"),
            (9007199254740993.0, "9007199254740992"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (123.456, "123.456"),
        ];
        for (value, text) in cases {
            assert_eq!(js_number(*value), *text, "{value}");
        }
    }

    #[test]
    fn array_indices_first() {
        let map: Map<String, Value> = serde_json::from_str(
            r#"{"b":1,"10":2,"2":3,"a":4,"01":5,"4294967295":6,"4294967294":7}"#,
        )
        .unwrap();
        let keys: Vec<&str> = js_order(&map).iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            ["2", "10", "4294967294", "b", "a", "01", "4294967295"]
        );
    }

    #[test]
    fn empty_containers_and_escapes() {
        let value: Value = serde_json::from_str(
            "{\"a\":[],\"b\":{},\"c\":\"\\u0001\\u001f\\b\\f\\n\\r\\t\\\"\\\\/\\u007f\"}",
        )
        .unwrap();
        assert_eq!(
            stringify(&value),
            "{\n  \"a\": [],\n  \"b\": {},\n  \"c\": \"\\u0001\\u001f\\b\\f\\n\\r\\t\\\"\\\\/\u{7f}\"\n}"
        );
        assert_eq!(stringify(&Value::Object(Map::new())), "{}");
    }
}
