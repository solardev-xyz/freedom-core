//! `normalizeParams`: the router rewrites an `eth_call` or
//! `eth_estimateGas` call object once, before any source sees it.
//!
//! - **Quantities** (`value`, `gas`, `gasPrice`, `maxFeePerGas`,
//!   `maxPriorityFeePerGas`, `nonce`, `chainId`, `type`) that are strings or
//!   numbers become `0x${BigInt(v).toString(16)}`, quirks included:
//!   whitespace is trimmed, `0b`/`0o`/`0X` parse, a negative gives `0x-1`,
//!   a number must be an integer (`-0` and `1e-400` are `0x0`). What
//!   `BigInt` refuses is left for the node to refuse.
//! - **`input`**: when `input` holds calldata and `data` doesn't, `data`
//!   takes `input`'s value as sent, in its own place or appended last.
//! - **The rest** is written as `JSON.stringify` writes the parsed params:
//!   property order, the last of duplicate keys, canonical numbers.
//!
//! A decimal quantity of 2^4096 or more is left as sent (deviation
//! `bigint-width`): converting it would take quadratic time, and the node
//! refuses it either way.

use fc_json::index::{Index, IndexError, KeyOrder, Kind, Value};

use crate::bigint::{BigInt, Parsed, parse_string};
use crate::js::trim;

const CALL_OBJECT_METHODS: [&str; 2] = ["eth_call", "eth_estimateGas"];

const CALL_QUANTITY_FIELDS: [&str; 8] = [
    "value",
    "gas",
    "gasPrice",
    "maxFeePerGas",
    "maxPriorityFeePerGas",
    "nonce",
    "chainId",
    "type",
];

/// Params as the router sends them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    /// `JSON.stringify(normalizeParams(method, JSON.parse(params)))`.
    pub params: String,
    /// Whether `normalizeParams` returned new params rather than its input.
    pub changed: bool,
}

/// Normalizes `params`, the caller's JSON text. Fails only where the text
/// isn't JSON, or nests deeper than 512 levels (deviation `json-depth`).
pub fn normalize_params(method: &str, params: &str) -> Result<Normalized, IndexError> {
    let index = Index::new(params)?;
    let root = index.root();
    let unchanged = || Normalized {
        params: root.stringify(KeyOrder::Property),
        changed: false,
    };
    if !CALL_OBJECT_METHODS.contains(&method) || root.kind() != Kind::Array {
        return Ok(unchanged());
    }
    let mut items = root.children();
    let Some(call) = items.next() else {
        return Ok(unchanged());
    };
    if call.kind() != Kind::Object {
        return Ok(unchanged());
    }
    let has_calldata = |key| call.get(key).is_some_and(is_calldata);
    let input = (has_calldata("input") && !has_calldata("data"))
        .then(|| call.get("input"))
        .flatten();
    let quantities: Vec<(&str, String)> = CALL_QUANTITY_FIELDS
        .iter()
        .filter_map(|field| Some((*field, quantity(call.get(field)?)?)))
        .collect();
    if input.is_none() && quantities.is_empty() {
        return Ok(unchanged());
    }

    let mut out = String::from("[{");
    let mut has_data = false;
    for (i, (key, value)) in call.properties().into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        key.write(KeyOrder::Property, &mut out);
        out.push(':');
        if let (true, Some(input)) = (key.is_str("data"), input) {
            has_data = true;
            input.write(KeyOrder::Property, &mut out);
        } else if let Some((_, hex)) = quantities.iter().find(|(field, _)| key.is_str(field)) {
            out.push('"');
            out.push_str(hex);
            out.push('"');
        } else {
            value.write(KeyOrder::Property, &mut out);
        }
    }
    if let (false, Some(input)) = (has_data, input) {
        // The call has at least `input`, so this isn't the first property.
        out.push_str(",\"data\":");
        input.write(KeyOrder::Property, &mut out);
    }
    out.push('}');
    for item in items {
        out.push(',');
        item.write(KeyOrder::Property, &mut out);
    }
    out.push(']');
    Ok(Normalized {
        params: out,
        changed: true,
    })
}

/// `calldata(value) !== null`: a string that, trimmed and lowercased, is
/// neither empty nor `0x`.
fn is_calldata(value: Value<'_, '_>) -> bool {
    if value.kind() != Kind::String {
        return false;
    }
    let units: Vec<u16> = value.units().collect();
    // Lowercasing changes no other text into "" or "0x".
    !matches!(trim(&units), [] | [0x30, 0x78 | 0x58])
}

/// The hex a quantity field becomes, or `None` where the router leaves it:
/// `null`, `""`, a type other than string or number, a value `BigInt`
/// refuses, or the hex it already is.
fn quantity(value: Value<'_, '_>) -> Option<String> {
    let parsed = match value.kind() {
        Kind::String => {
            let units: Vec<u16> = value.units().collect();
            if units.is_empty() {
                return None;
            }
            let Parsed::Value(parsed) = parse_string(&units)? else {
                return None; // bigint-width
            };
            let hex = format!("0x{}", parsed.to_hex());
            return (!hex.encode_utf16().eq(units.iter().copied())).then_some(hex);
        }
        // `BigInt(value || 0)`: -0 is 0.
        Kind::Number => BigInt::from_f64(value.number() + 0.0)?,
        _ => return None,
    };
    Some(format!("0x{}", parsed.to_hex()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalize(method: &str, params: &str) -> (String, bool) {
        let n = normalize_params(method, params).unwrap();
        (n.params, n.changed)
    }

    #[test]
    fn quantities_and_calldata() {
        assert_eq!(
            normalize(
                "eth_call",
                r#"[{"value":"1000","input":"0xab","gas":21000},"latest"]"#
            ),
            (
                r#"[{"value":"0x3e8","input":"0xab","gas":"0x5208","data":"0xab"},"latest"]"#
                    .into(),
                true
            )
        );
        assert_eq!(
            normalize("eth_call", r#"[{"value":"0x1a"}]"#),
            (r#"[{"value":"0x1a"}]"#.into(), false)
        );
        assert_eq!(
            normalize("eth_call", r#"[{"value":"-1"}]"#).0,
            r#"[{"value":"0x-1"}]"#
        );
        assert_eq!(
            normalize("eth_call", r#"[{"value":1.5}]"#),
            (r#"[{"value":1.5}]"#.into(), false)
        );
        assert_eq!(
            normalize("eth_call", r#"[{"value":1e400}]"#),
            (r#"[{"value":null}]"#.into(), false)
        );
        assert_eq!(
            normalize("eth_call", r#"[{"value":-0}]"#).0,
            r#"[{"value":"0x0"}]"#
        );
        assert_eq!(
            normalize("eth_getBalance", r#"[ {"value":"1"} ]"#),
            (r#"[{"value":"1"}]"#.into(), false)
        );
        assert_eq!(
            normalize("eth_call", r#"[{"data":"0x","input":"0xab"}]"#).0,
            r#"[{"data":"0xab","input":"0xab"}]"#
        );
        assert!(!normalize("eth_call", r#"[{"input":" 0X "}]"#).1);
        assert!(normalize_params("eth_call", "[").is_err());
    }
}
