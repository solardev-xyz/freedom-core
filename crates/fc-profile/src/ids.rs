//! Profile ids and names: `sanitizeProfileId`, `displayNameFromId`,
//! `hashPath` and the checkout's id, as `profile-catalog.js` has them.

use sha2::{Digest, Sha256};

use crate::catalog::Error;
use crate::js;

/// The profile a first run registers, at slot 0.
pub const DEFAULT_PROFILE_ID: &str = "default";

/// `sanitizeProfileId(value)`: trimmed and lowercased, each run of anything
/// but `a-z`, `0-9`, `_` and `-` made one `-`, and `-` cut from both ends.
/// Refused with the reference's messages: an empty id, `.`, `..`, a slash
/// or a backslash, and an id that comes out empty.
pub fn sanitize_profile_id(value: &str) -> Result<String, Error> {
    sanitize_text(value, value)
}

/// `sanitizeProfileId` of any value: `String(value || '')`, with the
/// value's own `String()` in a refusal.
pub(crate) fn sanitize_value(value: &fc_json::JsValue) -> Result<String, Error> {
    let shown = value.js_string().map_err(|_| Error::Malformed {
        path: String::new(),
    })?;
    let text = js::coerce_or_empty(value).ok_or(Error::Malformed {
        path: String::new(),
    })?;
    sanitize_text(&text, &shown)
}

fn sanitize_text(text: &str, shown: &str) -> Result<String, Error> {
    let input = js::trim(text).to_lowercase();
    if input.is_empty() {
        return Err(Error::Refused("Profile id is required".into()));
    }
    let invalid = || Error::Refused(format!("Invalid profile id: {shown}"));
    if input == "." || input == ".." || input.contains('/') || input.contains('\\') {
        return Err(invalid());
    }
    let mut id = String::with_capacity(input.len());
    let mut in_run = false;
    for c in input.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' {
            id.push(c);
            in_run = false;
        } else if !in_run {
            id.push('-');
            in_run = true;
        }
    }
    let id = id.trim_matches('-');
    if id.is_empty() || id == "." || id == ".." {
        return Err(invalid());
    }
    Ok(id.to_owned())
}

/// `displayNameFromId(id)`: `My Profile` for `default`; otherwise each part
/// between runs of `-` and `_`, its first UTF-16 unit upper-cased, joined by
/// spaces, or the id itself if that leaves nothing.
pub fn display_name_from_id(id: &str) -> String {
    if id == DEFAULT_PROFILE_ID {
        return "My Profile".into();
    }
    let name = id
        .split(['-', '_'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                // A character outside the BMP: `charAt(0)` is its high
                // surrogate, which upper-cases to itself.
                Some(first) if first.len_utf16() == 1 => {
                    let mut out: String = first.to_uppercase().collect();
                    out.push_str(chars.as_str());
                    out
                }
                _ => part.to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    if name.is_empty() { id.to_owned() } else { name }
}

/// `hashPath(path)`: the first 8 hex digits of the SHA-256 of its UTF-8.
pub fn hash_path(path: &str) -> String {
    let digest = Sha256::digest(path.as_bytes());
    digest
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `getCheckoutId(repoRoot)`: a dev checkout's directory name.
pub fn checkout_id(repo_root: &str) -> String {
    format!("freedom-browser-{}", hash_path(repo_root))
}

/// `getDevPortOffset(checkoutHash)`: `(parseInt(hash, 16) % 100) * 10`,
/// `NaN` for a hash `parseInt` reads no digit of.
pub fn dev_port_offset(checkout_hash: &str) -> f64 {
    (parse_int_hex(checkout_hash) % 100.0) * 10.0
}

/// `parseInt(text, 16)`.
fn parse_int_hex(text: &str) -> f64 {
    let text = js::trim(text);
    let (sign, rest) = match text.as_bytes().first() {
        Some(b'-') => (-1.0, &text[1..]),
        Some(b'+') => (1.0, &text[1..]),
        _ => (1.0, text),
    };
    let rest = rest
        .strip_prefix("0x")
        .or_else(|| rest.strip_prefix("0X"))
        .unwrap_or(rest);
    let digits: Vec<u32> = rest.chars().map_while(|c| c.to_digit(16)).collect();
    if digits.is_empty() {
        return f64::NAN;
    }
    sign * digits
        .iter()
        .fold(0.0, |n, &digit| n * 16.0 + f64::from(digit))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn ids_as_the_reference_makes_them() {
        assert_eq!(
            sanitize_profile_id("  Work Stuff!! ").unwrap(),
            "work-stuff"
        );
        assert_eq!(sanitize_profile_id("a-\u{e9}").unwrap(), "a");
        assert_eq!(sanitize_profile_id("a-\u{e9}b").unwrap(), "a--b");
        assert!(matches!(
            sanitize_profile_id("a/b"),
            Err(Error::Refused(m)) if m == "Invalid profile id: a/b"
        ));
        assert!(matches!(
            sanitize_profile_id(" \u{feff}"),
            Err(Error::Refused(m)) if m == "Profile id is required"
        ));
        assert_eq!(display_name_from_id("work_stuff--x"), "Work Stuff X");
        assert_eq!(display_name_from_id("---"), "---");
        assert_eq!(display_name_from_id("default"), "My Profile");
        assert_eq!(dev_port_offset("ffffffff"), 950.0);
        assert!(dev_port_offset("zz").is_nan());
    }
}
