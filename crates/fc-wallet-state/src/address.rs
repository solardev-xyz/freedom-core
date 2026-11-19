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

fn is_hex_address(text: &str) -> bool {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    if digits.len() != 40 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let upper = digits.bytes().any(|b| b.is_ascii_uppercase());
    let lower = digits.bytes().any(|b| b.is_ascii_lowercase());
    if !(upper && lower) {
        return true;
    }
    // Mixed case: the checksum must match.
    fc_evm::parse_address(&format!("0x{digits}")).is_ok()
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
