//! Name normalization: ENSIP-15 for ENS, WNS and GNS names, lowercasing for
//! Tezos Domains, as freedom-browser does it.

use crate::Error;

/// The longest name the core accepts, in bytes, before and after
/// normalization (design 0003, Limits).
pub const MAX_NAME_BYTES: usize = 1024;

/// JavaScript's `String.prototype.trim`: ECMAScript's WhiteSpace and
/// LineTerminator code points. Rust's `str::trim` differs: it strips U+0085
/// and keeps U+FEFF, the reverse of JavaScript.
pub fn js_trim(text: &str) -> &str {
    text.trim_matches(is_js_whitespace)
}

fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        // WhiteSpace: TAB, VT, FF, ZWNBSP and the Zs category.
        '\u{0009}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{FEFF}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}'
            | '\u{202F}' | '\u{205F}' | '\u{3000}'
            // LineTerminator.
            | '\u{000A}' | '\u{000D}' | '\u{2028}' | '\u{2029}'
    )
}

/// An ENS, WNS or GNS name as the resolver keys it: trimmed, then ENSIP-15
/// (spec 1.11.1, the data `@adraffy/ens-normalize` 1.11.1 ships).
///
/// The JS skips validation for names that are ASCII once lowercased and
/// lets ethers' `namehash` refuse them later. This validates every name up
/// front: the same names resolve and the same names fail (design 0003,
/// Deviations).
pub fn normalize_ens(name: &str) -> Result<String, Error> {
    let trimmed = js_trim(name);
    if trimmed.is_empty() {
        return Err(Error::EmptyName);
    }
    if trimmed.len() > MAX_NAME_BYTES {
        return Err(Error::NameTooLong(MAX_NAME_BYTES));
    }
    let normalized =
        ens_normalize::ens_normalize(trimmed).map_err(|e| Error::InvalidName(e.to_string()))?;
    if normalized.len() > MAX_NAME_BYTES {
        return Err(Error::NameTooLong(MAX_NAME_BYTES));
    }
    Ok(normalized)
}

/// A Tezos Domains name as the resolver keys it: trimmed and lowercased,
/// with no other normalization (`tezos-domains-resolver.js`).
pub fn normalize_tezos(name: &str) -> Result<String, Error> {
    let trimmed = js_trim(name);
    if trimmed.len() > MAX_NAME_BYTES {
        return Err(Error::NameTooLong(MAX_NAME_BYTES));
    }
    Ok(trimmed.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_like_javascript() {
        assert_eq!(js_trim("\u{FEFF} a.eth \u{3000}"), "a.eth");
        // NEL is not JavaScript whitespace, so it stays (and ENSIP-15 then
        // refuses it).
        assert_eq!(js_trim("\u{0085}a.eth"), "\u{0085}a.eth");
        assert_eq!(js_trim("\u{2028}\t\n a.eth\r\u{00A0}"), "a.eth");
    }

    #[test]
    fn normalizes_ens_names() {
        assert_eq!(
            normalize_ens("  Vitalik.ETH ").as_deref(),
            Ok("vitalik.eth")
        );
        assert_eq!(
            normalize_ens("\u{FF21}\u{FF22}\u{FF23}.eth").as_deref(),
            Ok("abc.eth")
        );
        assert_eq!(normalize_ens("\u{216B}.eth").as_deref(), Ok("xii.eth"));
        assert_eq!(normalize_ens("   "), Err(Error::EmptyName));
        assert!(
            matches!(normalize_ens("a_b.eth"), Err(Error::InvalidName(m)) if m.contains("underscore"))
        );
        assert!(matches!(
            normalize_ens("ab--cd.eth"),
            Err(Error::InvalidName(_))
        ));
        assert!(matches!(
            normalize_ens("foo..eth"),
            Err(Error::InvalidName(_))
        ));
    }

    #[test]
    fn caps_name_length() {
        let long = format!("{}.eth", "a".repeat(MAX_NAME_BYTES));
        assert_eq!(
            normalize_ens(&long),
            Err(Error::NameTooLong(MAX_NAME_BYTES))
        );
        assert_eq!(
            normalize_tezos(&long),
            Err(Error::NameTooLong(MAX_NAME_BYTES))
        );
    }

    #[test]
    fn lowercases_tezos_names() {
        assert_eq!(
            normalize_tezos(" Awesome-Tezos.TEZ ").as_deref(),
            Ok("awesome-tezos.tez")
        );
        // Full Unicode lowercasing with JavaScript's final-sigma rule: a
        // sigma followed by "." and a letter isn't final; one at the end is.
        assert_eq!(normalize_tezos("ΟΔΟΣ.tez").as_deref(), Ok("οδοσ.tez"));
        assert_eq!(normalize_tezos("ΟΔΟΣ").as_deref(), Ok("οδος"));
    }
}
