//! swarm-provider-ipc.js's param checks, with today's texts and reasons,
//! as far as the Access and Reads methods use them.

use fc_json::JsString;

use super::Failure;
use crate::value::Value;

/// `!params || typeof params !== 'object'`: `params is required`.
pub(crate) fn require_params(params: &Value) -> Result<(), Failure> {
    if !params.truthy() || params.type_of() != "object" {
        return Err(Failure::invalid_params(
            "params is required",
            "invalid_params",
        ));
    }
    Ok(())
}

/// `validateEmptyOptions(options)`: `undefined` or `null`, or an object
/// with no own key.
pub(crate) fn empty_options(options: &Value) -> Result<(), Failure> {
    if options.is_nullish() {
        return Ok(());
    }
    if options.type_of() != "object" || matches!(options, Value::Array(_)) {
        return Err(Failure::invalid_params(
            "options must be an object",
            "invalid_params",
        ));
    }
    if let Some(key) = options.first_key() {
        return Err(Failure::invalid_params_with(
            crate::js::concat(&[&JsString::from("Unsupported option: "), &key]),
            "unsupported_option",
            vec![("option", Value::String(key))],
        ));
    }
    Ok(())
}

/// `/^[0-9a-fA-F]{n}$/` over a string's units.
pub(crate) fn is_hex(s: &JsString, n: usize) -> bool {
    s.is_well_formed() && s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `validateHexString(value, bytes, reason, field)` without `0x`: a string
/// of exactly `2 × bytes` hex digits. Returns it.
pub(crate) fn hex_string<'v>(
    value: &'v Value,
    bytes: usize,
    reason: &str,
    field: &str,
) -> Result<&'v JsString, Failure> {
    let refuse = || {
        Failure::invalid_params(
            format!("{field} must be a {}-character hex string", bytes * 2),
            reason,
        )
    };
    let Value::String(s) = value else {
        return Err(refuse());
    };
    // `startsWith('0x')` is refused before the length; either way the
    // same error.
    if !is_hex(s, bytes * 2) {
        return Err(refuse());
    }
    Ok(s)
}

/// `value.replace(/^0x/, '')` for a string.
pub(crate) fn strip_0x(s: &JsString) -> JsString {
    match s.as_str().strip_prefix("0x") {
        Some(rest) if s.is_well_formed() => JsString::from(rest),
        Some(_) => {
            let units: Vec<u16> = s.units().skip(2).collect();
            JsString::from_units(&units)
        }
        None => s.clone(),
    }
}

/// `normalizeAddress(address)`: a string without its `0x`, else `''`.
pub(crate) fn normalize_address(value: &Value) -> JsString {
    match value {
        Value::String(s) => strip_0x(s),
        _ => JsString::default(),
    }
}

/// An owner: `/^[0-9a-fA-F]{40}$/`, as 20 bytes.
pub(crate) fn owner_bytes(s: &JsString) -> Option<[u8; 20]> {
    if !is_hex(s, 40) {
        return None;
    }
    crate::chunks::unhex::<20>(s.as_str())
}

/// 32 bytes from 64 hex digits already checked.
pub(crate) fn bytes32(s: &JsString) -> Option<[u8; 32]> {
    crate::chunks::unhex::<32>(s.as_str())
}

/// `validateFeedName(name)`'s message, where it refuses.
pub(crate) fn feed_name(name: &Value) -> Result<&JsString, &'static str> {
    let Value::String(name) = name else {
        return Err("Feed name must be a non-empty string");
    };
    let units = name.utf16_len();
    if units == 0 {
        return Err("Feed name must be a non-empty string");
    }
    if units > 64 {
        return Err("Feed name exceeds 64 characters");
    }
    if name.units().any(|u| u == u16::from(b'/')) {
        return Err("Feed name must not contain \"/\"");
    }
    if name.units().any(|u| u < 32) {
        return Err("Feed name must not contain control characters");
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_0x_takes_only_a_lowercase_prefix() {
        assert_eq!(strip_0x(&JsString::from("0xab")), "ab");
        assert_eq!(strip_0x(&JsString::from("0Xab")), "0Xab");
        assert_eq!(strip_0x(&JsString::from("x0xab")), "x0xab");
        let lone = JsString::from_units(&[u16::from(b'0'), u16::from(b'x'), 0xd800]);
        assert_eq!(strip_0x(&lone).units().collect::<Vec<_>>(), [0xd800]);
    }

    #[test]
    fn feed_names_as_validate_feed_name() {
        assert!(feed_name(&Value::str("blog")).is_ok());
        assert_eq!(
            feed_name(&Value::str("a/b")),
            Err("Feed name must not contain \"/\"")
        );
        assert_eq!(
            feed_name(&Value::str("a\u{1f}")),
            Err("Feed name must not contain control characters")
        );
        assert_eq!(
            feed_name(&Value::str(&"é".repeat(65))),
            Err("Feed name exceeds 64 characters")
        );
        assert!(feed_name(&Value::str(&"é".repeat(64))).is_ok());
        assert_eq!(
            feed_name(&Value::Number(1.0)),
            Err("Feed name must be a non-empty string")
        );
    }
}
