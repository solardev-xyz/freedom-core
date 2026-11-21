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

/// The 20 bytes an address [`is_address`] takes stands for, as ethers'
/// `getAddress` reads it: 40 hex digits with or without `0x` (a mixed-case
/// one with its EIP-55 checksum), or an ICAP direct address whose check
/// digits match, its base-36 digits read as a number. None for anything
/// else, and for an ICAP whose number doesn't fit 20 bytes, which
/// `getAddress` turns into a longer text than any account's address.
pub fn address_bytes(text: &str) -> Option<[u8; 20]> {
    hex_bytes(text).or_else(|| icap_bytes(text))
}

/// A record's address, as [`address_bytes`] reads its text.
pub fn value_address_bytes(value: &JsValue) -> Option<[u8; 20]> {
    let text = value.as_js_string()?;
    if !text.is_well_formed() {
        return None;
    }
    address_bytes(text.as_str())
}

fn is_hex_address(text: &str) -> bool {
    hex_bytes(text).is_some()
}

fn hex_bytes(text: &str) -> Option<[u8; 20]> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    if digits.len() != 40 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // A mixed-case one's checksum must match, as `parse_address` checks.
    fc_evm::parse_address(&format!("0x{digits}")).ok()
}

/// An ICAP direct address's number, if it is one and fits 20 bytes.
fn icap_bytes(text: &str) -> Option<[u8; 20]> {
    if !is_icap(text) {
        return None;
    }
    let mut out = [0u8; 20];
    for c in text[4..].chars() {
        // `fromBase36` reads letters in either case.
        let mut carry = c.to_digit(36)?;
        for byte in out.iter_mut().rev() {
            let value = u32::from(*byte) * 36 + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    Some(out)
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
            assert_eq!(address_bytes(&form), Some(bytes), "{form}");
            assert!(is_address(&s(&form)), "{form}");
            assert_eq!(value_address_bytes(&s(&form)), Some(bytes), "{form}");
        }
        for bad in [
            "0x8Ba1f109551bD432803012645Ac136ddd64DBA72".to_owned(),
            format!("0X{}", checksummed[2..].to_lowercase()),
            checksummed[..41].to_owned(),
            icap.replacen("65", "66", 1),
            icap.to_lowercase(),
            String::new(),
        ] {
            assert_eq!(address_bytes(&bad), None, "{bad}");
            assert!(!is_address(&s(&bad)), "{bad}");
        }
        assert_eq!(value_address_bytes(&JsValue::Number(1.0)), None);
        // An ICAP of 31 digits past 2^160: an address to `isAddress`, but
        // none of 20 bytes.
        let body = "Z".repeat(31);
        let big = format!("XE{}{body}", icap_checksum(&format!("XE00{body}")));
        assert!(is_address(&s(&big)));
        assert_eq!(address_bytes(&big), None);
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
