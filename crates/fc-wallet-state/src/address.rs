//! An address as ethers 6's `isAddress` takes it (`getAddress` succeeds),
//! which is how identity-manager.js checks a device or Safe record's
//! address before storing it as given.

use fc_json::JsValue;

/// ethers' `isAddress(value)`: a string that is 40 hex digits with or
/// without a `0x` prefix (a mixed-case one with its EIP-55 checksum), or an
/// ICAP direct address (`XE`, two check digits, 30 or 31 base-36 digits)
/// whose check digits match.
pub fn is_address(value: &JsValue) -> bool {
    let Some(text) = value.as_js_string() else {
        return false;
    };
    // A lone surrogate is no hex or base-36 digit.
    if !text.is_well_formed() {
        return false;
    }
    let text = text.as_str();
    is_hex_address(text) || is_icap(text)
}

/// ethers' `getAddress(text)`, lower-cased: `0x` and the hex digits it
/// gives, or none where it throws (where `isAddress` is false). Every hex
/// form gives 40 digits, as does an ICAP below 2^160. An ICAP of 31
/// base-36 digits past 2^160 gives 41: `getAddress` pads its number to 40
/// hex digits and never cuts it. Two texts name one address when these
/// agree, as the reference compares what `getAddress` returns.
pub fn normalize_address(text: &str) -> Option<String> {
    hex_digits(text)
        .or_else(|| icap_digits(text))
        .map(|digits| format!("0x{digits}"))
}

/// A stored value's address, as [`normalize_address`] reads its text; none
/// for a value that isn't a string.
pub fn value_normalize_address(value: &JsValue) -> Option<String> {
    let text = value.as_js_string()?;
    if !text.is_well_formed() {
        return None;
    }
    normalize_address(text.as_str())
}

/// The 20 bytes of a [`normalize_address`] result of 40 digits; none for
/// one of 41, which names no account's key.
pub fn normalized_bytes(normalized: &str) -> Option<[u8; 20]> {
    let digits = normalized.strip_prefix("0x")?;
    if digits.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (byte, pair) in out.iter_mut().zip(digits.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// The 20 bytes `text` names, if it is an address of 20 bytes.
pub fn address_bytes(text: &str) -> Option<[u8; 20]> {
    normalized_bytes(&normalize_address(text)?)
}

/// A stored value's 20 bytes, as [`address_bytes`] reads its text.
pub fn value_address_bytes(value: &JsValue) -> Option<[u8; 20]> {
    normalized_bytes(&value_normalize_address(value)?)
}

fn is_hex_address(text: &str) -> bool {
    hex_digits(text).is_some()
}

/// 40 hex digits, with or without `0x` (a mixed-case one with its EIP-55
/// checksum), lower-cased.
fn hex_digits(text: &str) -> Option<String> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    if digits.len() != 40 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // A mixed-case one's checksum must match, as `parse_address` checks.
    fc_evm::parse_address(&format!("0x{digits}")).ok()?;
    Some(digits.to_ascii_lowercase())
}

/// An ICAP direct address's number in hex (`fromBase36(…).toString(16)`,
/// padded to 40 digits), if it is one whose check digits match.
fn icap_digits(text: &str) -> Option<String> {
    if !is_icap(text) {
        return None;
    }
    // 31 base-36 digits are below 2^161: 21 bytes hold any of them.
    let mut number = [0u8; 21];
    for c in text[4..].chars() {
        // `fromBase36` reads letters in either case.
        let mut carry = c.to_digit(36)?;
        for byte in number.iter_mut().rev() {
            let value = u32::from(*byte) * 36 + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    let hex: String = number.iter().map(|byte| format!("{byte:02x}")).collect();
    let significant = hex.trim_start_matches('0');
    Some(format!("{significant:0>40}"))
}

/// `^XE[0-9]{2}[0-9A-Za-z]{30,31}$` and ethers' `ibanChecksum`.
fn is_icap(text: &str) -> bool {
    let bytes = text.as_bytes();
    let shaped = (34..=35).contains(&bytes.len())
        && bytes.starts_with(b"XE")
        && bytes[2..4].iter().all(u8::is_ascii_digit)
        && bytes[4..].iter().all(u8::is_ascii_alphanumeric);
    shaped && text[2..4] == icap_checksum(text)
}

/// ethers' `ibanChecksum`: ISO 7064 mod 97-10 over the address moved to
/// `<body>XE00`, letters as 10 to 35, as two digits.
fn icap_checksum(text: &str) -> String {
    let upper = text.to_ascii_uppercase();
    let moved = format!("{}{}00", &upper[4..], &upper[..2]);
    let mut rest = 0u32;
    for c in moved.chars() {
        let Some(value) = c.to_digit(36) else {
            return String::new();
        };
        for digit in value.to_string().bytes() {
            rest = (rest * 10 + u32::from(digit - b'0')) % 97;
        }
    }
    format!("{:02}", 98 - rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(text: &str) -> JsValue {
        JsValue::string(text)
    }

    #[test]
    fn forms() {
        let checksummed = "0x8ba1f109551bD432803012645Ac136ddd64DBA72";
        assert!(is_address(&s(checksummed)));
        assert!(is_address(&s(&checksummed.to_lowercase())));
        assert!(is_address(&s(&checksummed[2..])));
        assert!(is_address(&s(&format!(
            "0x{}",
            checksummed[2..].to_uppercase()
        ))));
        assert!(!is_address(&s(
            "0x8Ba1f109551bD432803012645Ac136ddd64DBA72"
        )));
        assert!(!is_address(&s(&format!(
            "0X{}",
            checksummed[2..].to_lowercase()
        ))));
        assert!(!is_address(&s(&checksummed[..41])));
        assert!(!is_address(&s(&format!("{checksummed}0"))));
        assert!(!is_address(&JsValue::Number(1.0)));
        assert!(!is_address(&JsValue::Null));
    }

    #[test]
    fn bytes_of_each_form() {
        let checksummed = "0x8ba1f109551bD432803012645Ac136ddd64DBA72";
        let bytes = fc_evm::parse_address(checksummed).unwrap();
        let lower = checksummed.to_lowercase();
        let icap = "XE65GB6LDNXYOFTX0NSV3FUWKOWIXAMJK36";
        for form in [
            checksummed.to_owned(),
            checksummed.to_lowercase(),
            checksummed[2..].to_owned(),
            checksummed[2..].to_lowercase(),
            format!("0x{}", checksummed[2..].to_uppercase()),
            checksummed[2..].to_uppercase(),
            icap.to_owned(),
            icap.to_lowercase().replacen("xe", "XE", 1),
        ] {
            assert_eq!(normalize_address(&form).as_deref(), Some(lower.as_str()));
            assert_eq!(address_bytes(&form), Some(bytes), "{form}");
            assert!(is_address(&s(&form)), "{form}");
            assert_eq!(value_address_bytes(&s(&form)), Some(bytes), "{form}");
        }
        for bad in [
            "0x8Ba1f109551bD432803012645Ac136ddd64DBA72".to_owned(),
            format!("0X{}", checksummed[2..].to_lowercase()),
            checksummed[..41].to_owned(),
            format!("{lower}0"),
            icap.replacen("65", "66", 1),
            icap.to_lowercase(),
            String::new(),
        ] {
            assert_eq!(normalize_address(&bad), None, "{bad}");
            assert!(!is_address(&s(&bad)), "{bad}");
        }
        assert_eq!(value_normalize_address(&JsValue::Number(1.0)), None);
    }

    /// An ICAP of 31 digits past 2^160 is an address to ethers, and
    /// `getAddress` gives its number in 41 hex digits (Python's
    /// `format(int(body, 36), "x")` as the oracle): that is its form, and
    /// it has no 20 bytes.
    #[test]
    fn an_icap_past_twenty_bytes() {
        for (icap, digits) in [
            (
                "XE54ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
                "1343093195196b9fcca7c68ce3fffffffffffffff",
            ),
            (
                "XE62YZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
                "12ba100ca64a7df7ce14e49732fffffffffffffff",
            ),
        ] {
            assert!(is_address(&s(icap)));
            let expected = format!("0x{digits}");
            assert_eq!(normalize_address(icap).as_deref(), Some(expected.as_str()));
            let lower_body = format!("XE{}", icap[2..].to_lowercase());
            assert_eq!(
                normalize_address(&lower_body).as_deref(),
                Some(expected.as_str())
            );
            assert_eq!(address_bytes(icap), None);
            assert_eq!(normalized_bytes(&expected), None);
        }
        // 30 digits always fit: the largest is below 2^160.
        let body = "Z".repeat(30);
        let top = format!("XE{}{body}", icap_checksum(&format!("XE00{body}")));
        assert!(address_bytes(&top).is_some());
    }

    #[test]
    fn icap() {
        // ethers' own example (getIcapAddress of 0x8ba1…BA72).
        let icap = "XE65GB6LDNXYOFTX0NSV3FUWKOWIXAMJK36";
        assert!(is_address(&s(icap)));
        assert!(is_address(&s(&icap.to_lowercase().replacen("xe", "XE", 1))));
        assert!(!is_address(&s(&icap.replacen("65", "66", 1))));
        assert!(!is_address(&s(&icap.to_lowercase())));
        assert!(!is_address(&s(&icap[..33])));
    }
}
