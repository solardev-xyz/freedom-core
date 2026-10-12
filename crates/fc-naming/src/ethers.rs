//! ethers v6's error messages, reproduced exactly (design 0004, Errors:
//! agreement and text). A reverse `error` outcome carries the message the
//! reference's `err.message` holds, so legs agree and disagree where the
//! reference's do, and conflict groups carry the same bytes. They are never
//! shown: display text is the class's short message. The pinned reference
//! uses ethers 6.17.0.

use crate::jsjson::{self, JsValue};

/// The reference's ethers version, which every composed message ends with.
pub const VERSION: &str = "6.17.0";

/// `makeError(message, code, info)`'s message: `info`'s entries in order,
/// each already as ethers' `stringify` writes it, then the code and the
/// version.
pub fn make_error(message: &str, code: &str, info: &[(&str, String)]) -> String {
    let mut details: Vec<String> = info
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    details.push(format!("code={code}"));
    details.push(format!("version={VERSION}"));
    format!("{message} ({})", details.join(", "))
}

/// ethers' `stringify` of a string: `JSON.stringify`.
pub fn string(value: &str) -> String {
    JsValue::String(value.to_owned()).stringify()
}

/// `hexlify`: `0x` and lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0xf)] as char);
    }
    out
}

/// A 256-bit big-endian word in decimal, as a `bigint` prints.
pub fn u256_decimal(word: &[u8; 32]) -> String {
    // Four 64-bit limbs, most significant first, divided by 10^19 at a time.
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&word[i * 8..i * 8 + 8]);
        *limb = u64::from_be_bytes(bytes);
    }
    const CHUNK: u64 = 10_000_000_000_000_000_000;
    let mut chunks = Vec::new();
    while limbs.iter().any(|&l| l != 0) {
        let mut remainder: u128 = 0;
        for limb in &mut limbs {
            let value = (remainder << 64) | u128::from(*limb);
            *limb = u64::try_from(value / u128::from(CHUNK)).unwrap_or(u64::MAX);
            remainder = value % u128::from(CHUNK);
        }
        chunks.push(u64::try_from(remainder).unwrap_or(0));
    }
    match chunks.split_last() {
        None => "0".into(),
        Some((first, rest)) => {
            let mut out = first.to_string();
            for chunk in rest.iter().rev() {
                out.push_str(&format!("{chunk:019}"));
            }
            out
        }
    }
}

/// JavaScript's `Number(bigint)` for a 256-bit word: rounded to nearest,
/// ties to even.
pub fn u256_to_f64(word: &[u8; 32]) -> f64 {
    let Some(first) = word.iter().position(|&b| b != 0) else {
        return 0.0;
    };
    let bits = (32 - first) * 8 - word[first].leading_zeros() as usize;
    let read = |from_bit: usize| {
        // The 64 bits starting `from_bit` bits above the least significant.
        let mut value: u64 = 0;
        for i in (0..64).rev() {
            let bit = from_bit + i;
            let byte = 31 - bit / 8;
            let set = bit < 256 && (word[byte] >> (bit % 8)) & 1 == 1;
            value = (value << 1) | u64::from(set);
        }
        value
    };
    if bits <= 64 {
        #[allow(clippy::cast_precision_loss)]
        return read(0) as f64;
    }
    let shift = bits - 64;
    let top = read(shift);
    let sticky = (0..shift).any(|bit| (word[31 - bit / 8] >> (bit % 8)) & 1 == 1);
    let mantissa = top >> 11;
    let rest = top & 0x7ff;
    let up = rest > 0x400 || (rest == 0x400 && (sticky || mantissa & 1 == 1));
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_wrap,
        clippy::cast_possible_truncation
    )]
    let value = (mantissa + u64::from(up)) as f64 * 2f64.powi((shift + 11) as i32);
    value
}

fn panic_reason(code: f64) -> &'static str {
    const REASONS: [(f64, &str); 10] = [
        (0.0, "GENERIC_PANIC"),
        (1.0, "ASSERT_FALSE"),
        (17.0, "OVERFLOW"),
        (18.0, "DIVIDE_BY_ZERO"),
        (33.0, "ENUM_RANGE_ERROR"),
        (34.0, "BAD_STORAGE_DATA"),
        (49.0, "STACK_UNDERFLOW"),
        (50.0, "ARRAY_RANGE_ERROR"),
        (65.0, "OUT_OF_MEMORY"),
        (81.0, "UNINITIALIZED_FUNCTION_CALL"),
    ];
    REASONS
        .iter()
        .find(|(c, _)| *c == code)
        .map_or("UNKNOWN", |(_, name)| name)
}

/// `AbiCoder.getBuiltinCallException("call", { to, data: tx_data }, revert)`:
/// a call's revert data (`None` when ethers found none) and the failing call.
/// `Interface.makeError` adds nothing for the reference's ABIs, which
/// declare no custom errors.
pub fn call_exception(revert: Option<&[u8]>, to: &[u8; 20], tx_data: &[u8]) -> String {
    use crate::abi::{Kind, Value};
    let mut message = "missing revert data".to_owned();
    let mut data = "null".to_owned();
    let mut reason = "null".to_owned();
    let mut revert_info = "null".to_owned();
    if let Some(bytes) = revert {
        message = "execution reverted".into();
        data = string(&hex(bytes));
        let selector = bytes.get(..4);
        if bytes.is_empty() {
            message.push_str(" (no data present; likely require(false) occurred");
            reason = string("require(false)");
        } else if bytes.len() % 32 != 4 {
            message.push_str(" (could not decode reason; invalid data length)");
        } else if selector == Some(&[0x08, 0xc3, 0x79, 0xa0]) {
            match crate::abi::decode(&[Kind::String], &bytes[4..]).map(|f| f.into_iter().next()) {
                Ok(Some(Ok(Value::String(text)))) => {
                    reason = string(&text);
                    revert_info = format!(
                        "{{ \"args\": [ {reason} ], \"name\": \"Error\", \"signature\": \"Error(string)\" }}"
                    );
                    message.push_str(&format!(": {reason}"));
                }
                _ => message.push_str(" (could not decode reason; invalid string data)"),
            }
        } else if selector == Some(&[0x4e, 0x48, 0x7b, 0x71]) {
            match crate::abi::decode(&[Kind::Uint256], &bytes[4..]).map(|f| f.into_iter().next()) {
                Ok(Some(Ok(Value::Uint256(word)))) => {
                    let code = u256_to_f64(&word);
                    let printed = jsjson::number_to_string(code);
                    let text = format!("Panic due to {}({printed})", panic_reason(code));
                    reason = string(&text);
                    revert_info = format!(
                        "{{ \"args\": [ {printed} ], \"name\": \"Panic\", \"signature\": \"Panic(uint256)\" }}"
                    );
                    message.push_str(&format!(": {text}"));
                }
                _ => message.push_str(" (could not decode panic code)"),
            }
        } else {
            message.push_str(" (unknown custom error)");
        }
    }
    let transaction = format!(
        "{{ \"data\": {}, \"to\": {} }}",
        string(&hex(tx_data)),
        string(&crate::session::ens::checksum(to))
    );
    make_error(
        &message,
        "CALL_EXCEPTION",
        &[
            ("action", string("call")),
            ("data", data),
            ("reason", reason),
            ("transaction", transaction),
            ("invocation", "null".into()),
            ("revert", revert_info),
        ],
    )
}

/// `Interface.decodeFunctionResult(method, raw)`'s `BAD_DATA` when the
/// result doesn't decode.
pub fn bad_result(raw: &[u8], method: &str, signature: &str) -> String {
    let message = if raw.len().is_multiple_of(32) {
        "could not decode result data"
    } else {
        "invalid length for result data"
    };
    make_error(
        message,
        "BAD_DATA",
        &[
            ("value", string(&hex(raw))),
            (
                "info",
                format!(
                    "{{ \"method\": {}, \"signature\": {} }}",
                    string(method),
                    string(signature)
                ),
            ),
        ],
    )
}

/// `getBytes`'s refusal of a string that isn't even-length hex.
pub fn invalid_bytes_like(value: &str) -> String {
    make_error(
        "invalid BytesLike value",
        "INVALID_ARGUMENT",
        &[("argument", string("value")), ("value", string(value))],
    )
}

/// The short message of a composed ethers message (what precedes its
/// details); other messages (deferred errors, the resolver's own) are
/// already short.
pub fn short_of(message: &str) -> &str {
    if !message.ends_with(&format!(", version={VERSION})")) {
        return message;
    }
    // Each code's first detail key; the short part never holds one
    // unescaped (reasons are JSON strings).
    for marker in [
        " (action=\"call\"",
        " (argument=",
        " (value=",
        " (buffer=",
        " (code=",
    ] {
        if let Some(at) = message.find(marker) {
            return &message[..at];
        }
    }
    message
}

/// `sanitizeErrorDetail(value)`, as display text takes it (design 0004,
/// Errors): URLs become `<url>`, hex over 32 bytes is shortened, runs of
/// whitespace become one space, and the result is trimmed to 240 UTF-16
/// units.
pub fn sanitize(value: &str) -> String {
    const MAX: usize = 240;
    // URLs: `https?://` (any case) and every character up to whitespace or
    // one of `"'<>`.
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while !rest.is_empty() {
        let lower: String = rest
            .chars()
            .take(8)
            .collect::<String>()
            .to_ascii_lowercase();
        let scheme = if lower.starts_with("https://") {
            8
        } else if lower.starts_with("http://") {
            7
        } else {
            0
        };
        // The URL's end is looked for only after a scheme, so the scan
        // stays linear.
        let tail_len = if scheme > 0 {
            rest[scheme..]
                .find(|c: char| {
                    crate::normalize::is_js_whitespace(c) || matches!(c, '"' | '\'' | '<' | '>')
                })
                .unwrap_or(rest.len() - scheme)
        } else {
            0
        };
        if tail_len > 0 {
            out.push_str("<url>");
            rest = &rest[scheme + tail_len..];
        } else {
            let c = rest.chars().next().unwrap_or(' ');
            out.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    // Hex: `0x` and 66 or more hex digits.
    let mut shortened = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while !rest.is_empty() {
        let digits = rest.strip_prefix("0x").map_or(0, |after| {
            after.bytes().take_while(u8::is_ascii_hexdigit).count()
        });
        if digits >= 66 {
            shortened.push_str(&rest[..10]);
            shortened.push_str(&format!("…({} bytes)", digits / 2));
            rest = &rest[2 + digits..];
        } else {
            let c = rest.chars().next().unwrap_or(' ');
            shortened.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    // Whitespace runs, then trimming.
    let mut collapsed = String::with_capacity(shortened.len());
    let mut space = false;
    for c in shortened.chars() {
        if crate::normalize::is_js_whitespace(c) {
            space = true;
        } else {
            if space && !collapsed.is_empty() {
                collapsed.push(' ');
            }
            space = false;
            collapsed.push(c);
        }
    }
    let units: Vec<u16> = collapsed.encode_utf16().collect();
    if units.len() <= MAX {
        return collapsed;
    }
    format!("{}…", String::from_utf16_lossy(&units[..MAX - 1]))
}

/// `Result`'s deferred error, when a failed field is read.
pub fn deferred(index: usize) -> String {
    format!("deferred error during ABI decoding triggered accessing index {index}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const UR: [u8; 20] = crate::ur::UNIVERSAL_RESOLVER;

    /// Messages the pinned ethers produced for the same inputs.
    fn expect(revert: Option<&str>, want: &str) {
        let revert = revert.map(|h| crate::session::rpc::hex_string(h).unwrap_or_default());
        let tx = [0x5d, 0x78, 0xa2, 0x17];
        assert_eq!(call_exception(revert.as_deref(), &UR, &tx), want);
    }

    const TX: &str = r#"transaction={ "data": "0x5d78a217", "to": "0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe" }"#;

    #[test]
    fn call_exceptions_match_ethers() {
        expect(
            None,
            &format!(
                "missing revert data (action=\"call\", data=null, reason=null, {TX}, invocation=null, revert=null, code=CALL_EXCEPTION, version=6.17.0)"
            ),
        );
        expect(
            Some("0x"),
            &format!(
                "execution reverted (no data present; likely require(false) occurred (action=\"call\", data=\"0x\", reason=\"require(false)\", {TX}, invocation=null, revert=null, code=CALL_EXCEPTION, version=6.17.0)"
            ),
        );
        expect(
            Some("0x1234"),
            &format!(
                "execution reverted (could not decode reason; invalid data length) (action=\"call\", data=\"0x1234\", reason=null, {TX}, invocation=null, revert=null, code=CALL_EXCEPTION, version=6.17.0)"
            ),
        );
        expect(
            Some("0xdeadbeef"),
            &format!(
                "execution reverted (unknown custom error) (action=\"call\", data=\"0xdeadbeef\", reason=null, {TX}, invocation=null, revert=null, code=CALL_EXCEPTION, version=6.17.0)"
            ),
        );
        let error = "0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000e6e6f7065202271756f746564220a000000000000000000000000000000000000";
        expect(
            Some(error),
            &format!(
                "execution reverted: \"nope \\\"quoted\\\"\\n\" (action=\"call\", data=\"{error}\", reason=\"nope \\\"quoted\\\"\\n\", {TX}, invocation=null, revert={{ \"args\": [ \"nope \\\"quoted\\\"\\n\" ], \"name\": \"Error\", \"signature\": \"Error(string)\" }}, code=CALL_EXCEPTION, version=6.17.0)"
            ),
        );
        let bad = "0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001ff00000000000000000000000000000000000000000000000000000000000000";
        expect(
            Some(bad),
            &format!(
                "execution reverted (could not decode reason; invalid string data) (action=\"call\", data=\"{bad}\", reason=null, {TX}, invocation=null, revert=null, code=CALL_EXCEPTION, version=6.17.0)"
            ),
        );
        let panic = "0x4e487b710000000000000000000000000000000000000000000000000000000000000011";
        expect(
            Some(panic),
            &format!(
                "execution reverted: Panic due to OVERFLOW(17) (action=\"call\", data=\"{panic}\", reason=\"Panic due to OVERFLOW(17)\", {TX}, invocation=null, revert={{ \"args\": [ 17 ], \"name\": \"Panic\", \"signature\": \"Panic(uint256)\" }}, code=CALL_EXCEPTION, version=6.17.0)"
            ),
        );
        let unknown = "0x4e487b710000000000000000000000000000000000000000000000000000000000000099";
        expect(
            Some(unknown),
            &format!(
                "execution reverted: Panic due to UNKNOWN(153) (action=\"call\", data=\"{unknown}\", reason=\"Panic due to UNKNOWN(153)\", {TX}, invocation=null, revert={{ \"args\": [ 153 ], \"name\": \"Panic\", \"signature\": \"Panic(uint256)\" }}, code=CALL_EXCEPTION, version=6.17.0)"
            ),
        );
        let huge = format!("0x4e487b71{}", "ff".repeat(32));
        expect(
            Some(&huge),
            &format!(
                "execution reverted: Panic due to UNKNOWN(1.157920892373162e+77) (action=\"call\", data=\"{huge}\", reason=\"Panic due to UNKNOWN(1.157920892373162e+77)\", {TX}, invocation=null, revert={{ \"args\": [ 1.157920892373162e+77 ], \"name\": \"Panic\", \"signature\": \"Panic(uint256)\" }}, code=CALL_EXCEPTION, version=6.17.0)"
            ),
        );
        expect(
            Some("0x4e487b71"),
            &format!(
                "execution reverted (could not decode panic code) (action=\"call\", data=\"0x4e487b71\", reason=null, {TX}, invocation=null, revert=null, code=CALL_EXCEPTION, version=6.17.0)"
            ),
        );
    }

    #[test]
    fn result_and_bytes_errors_match_ethers() {
        assert_eq!(
            bad_result(&[0x12, 0x34], "reverse", "reverse(bytes,uint256)"),
            "invalid length for result data (value=\"0x1234\", info={ \"method\": \"reverse\", \"signature\": \"reverse(bytes,uint256)\" }, code=BAD_DATA, version=6.17.0)"
        );
        assert_eq!(
            bad_result(&[0; 64], "reverse", "reverse(bytes,uint256)"),
            format!(
                "could not decode result data (value=\"0x{}\", info={{ \"method\": \"reverse\", \"signature\": \"reverse(bytes,uint256)\" }}, code=BAD_DATA, version=6.17.0)",
                "00".repeat(64)
            )
        );
        assert_eq!(
            invalid_bytes_like("0x12zz"),
            "invalid BytesLike value (argument=\"value\", value=\"0x12zz\", code=INVALID_ARGUMENT, version=6.17.0)"
        );
    }

    #[test]
    fn display_text_is_the_short_message_sanitized() {
        let message = format!(
            "missing revert data (action=\"call\", data=null, reason=null, {TX}, invocation=null, revert=null, code=CALL_EXCEPTION, version=6.17.0)"
        );
        assert_eq!(short_of(&message), "missing revert data");
        assert_eq!(
            short_of("deferred error during ABI decoding triggered accessing index 1"),
            "deferred error during ABI decoding triggered accessing index 1"
        );
        assert_eq!(
            short_of(
                "data out-of-bounds (buffer=0x00, length=1, offset=32, code=BUFFER_OVERRUN, version=6.17.0)"
            ),
            "data out-of-bounds"
        );
        assert_eq!(
            sanitize(&format!(
                "see https://gw.example/x?a=1 and 0x{}  now\n",
                "ab".repeat(40)
            )),
            "see <url> and 0xabababab…(40 bytes) now"
        );
        let long = "é".repeat(300);
        assert_eq!(sanitize(&long).chars().count(), 240);
        assert!(sanitize(&long).ends_with('…'));
        assert_eq!(sanitize("   "), "");
    }

    #[test]
    fn sanitizing_long_text_is_linear() {
        // A contract's reason can be one long word: a megabyte must not take
        // quadratic time.
        let started = std::time::Instant::now();
        let long = "a".repeat(1 << 20);
        assert_eq!(sanitize(&long).chars().count(), 240);
        let urls = "https://x.example/ ".repeat(1 << 16);
        assert!(sanitize(&urls).starts_with("<url> <url>"));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn big_numbers_print_as_javascript_does() {
        assert_eq!(
            u256_decimal(&[0xff; 32]),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
        assert_eq!(u256_decimal(&[0; 32]), "0");
        let mut ten = [0u8; 32];
        ten[31] = 10;
        assert_eq!(u256_decimal(&ten), "10");
        assert_eq!(
            jsjson::number_to_string(u256_to_f64(&[0xff; 32])),
            "1.157920892373162e+77"
        );
        // 2^53 + 1 rounds to even (2^53); 2^53 + 3 rounds up.
        let mut odd = [0u8; 32];
        odd[24..].copy_from_slice(&((1u64 << 53) + 1).to_be_bytes());
        assert_eq!(u256_to_f64(&odd), 9_007_199_254_740_992.0);
        odd[24..].copy_from_slice(&((1u64 << 53) + 3).to_be_bytes());
        assert_eq!(u256_to_f64(&odd), 9_007_199_254_740_996.0);
    }
}
