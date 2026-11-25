//! `normalizeOrigin(url)` (freedom-browser's `src/shared/origin-utils.js`,
//! `getPermissionKey`): the permission key of a document's URL, which the
//! manifest check compares with the key it was asked for, so that one
//! site's record is never pruned on another site's manifest.
//!
//! - a bare supported name (`name.eth/path`, `.box`, `.wei`, `.gwei`,
//!   `.tez`) is the name, lowercased; `ens://name/…` the same;
//! - `bzz://`, `ipfs://` and `ipns://` URLs are `scheme://host`, or the
//!   host lowercased where it is a supported name;
//! - `rad://rid/…` is `rad://rid`; `web3://0x…` its chain-scoped key;
//! - any other URL is the WHATWG origin, or the trimmed text where that is
//!   opaque (`null`) or the text isn't a URL.

/// `normalizeOrigin(url)`: [`permission_key`], or `""` for none.
pub fn normalize_origin(url: &str) -> String {
    permission_key(url).unwrap_or_default()
}

/// `getPermissionKey(displayUrl)`.
pub fn permission_key(display_url: &str) -> Option<String> {
    let trimmed = display_url.trim_matches(crate::js::is_js_whitespace);
    if trimmed.is_empty() {
        return None;
    }
    if let Some(name) = bare_name(trimmed) {
        return Some(name);
    }
    if let Some(host) = strip_scheme(trimmed, "ens").and_then(authority) {
        return Some(host.to_lowercase());
    }
    for scheme in ["ipfs", "bzz", "ipns"] {
        if let Some(host) = strip_scheme(trimmed, scheme).and_then(authority) {
            if is_dweb_name_host(host) {
                return Some(host.to_lowercase());
            }
            return Some(format!("{scheme}://{host}"));
        }
    }
    if let Some(rid) = strip_scheme(trimmed, "rad").and_then(authority) {
        return Some(format!("rad://{rid}"));
    }
    if let Some(key) = web3_key(trimmed) {
        return Some(key);
    }
    match url::Url::parse(trimmed) {
        Ok(url) => {
            let origin = url.origin().ascii_serialization();
            if origin == "null" {
                Some(trimmed.to_owned())
            } else {
                Some(origin)
            }
        }
        Err(_) => Some(trimmed.to_owned()),
    }
}

/// JavaScript's `\s`: WhiteSpace and LineTerminator.
fn is_space(c: char) -> bool {
    crate::js::is_js_whitespace(c)
}

/// `/^[^/?#\s]+\.(eth|box|wei|gwei|tez)(?:[/?#]|$)/i`, then
/// `trimmed.split(/[/?#]/, 1)[0].toLowerCase()`.
fn bare_name(trimmed: &str) -> Option<String> {
    let end = trimmed
        .find(|c: char| matches!(c, '/' | '?' | '#') || is_space(c))
        .unwrap_or(trimmed.len());
    // What follows the name is `/`, `?`, `#` or nothing: not a space.
    if trimmed[end..].starts_with(is_space) {
        return None;
    }
    let segment = &trimmed[..end];
    let lower = segment.to_ascii_lowercase();
    let named = ["eth", "box", "wei", "gwei", "tez"].iter().any(|tld| {
        lower
            .strip_suffix(tld)
            .and_then(|rest| rest.strip_suffix('.'))
            .is_some_and(|before| !before.is_empty())
    });
    named.then(|| segment.to_lowercase())
}

/// The text after `scheme://`, the scheme matched case-insensitively.
fn strip_scheme<'t>(text: &'t str, scheme: &str) -> Option<&'t str> {
    let head = text.get(..scheme.len())?;
    if !head.eq_ignore_ascii_case(scheme) {
        return None;
    }
    text[scheme.len()..].strip_prefix("://")
}

/// `([^/?#]+)` at the start: the authority, at least one character.
fn authority(rest: &str) -> Option<&str> {
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    (end > 0).then(|| &rest[..end])
}

/// `isDwebNameHost(host)`: an ENS name (`.eth`, `.box`, `.wei`, `.gwei`)
/// or a Tezos domain (`.tez`, every label non-empty).
fn is_dweb_name_host(host: &str) -> bool {
    let lower = host.to_lowercase();
    let ens = [".eth", ".box", ".wei", ".gwei"]
        .iter()
        .any(|tld| lower.ends_with(tld));
    let tezos = lower.ends_with(".tez") && lower.split('.').all(|label| !label.is_empty());
    ens || tezos
}

/// The ERC-8244 key: `/^web3:\/\/(0x[0-9a-f]{40})\.eip155-([0-9]+)(?:[/?#]|$)/i`
/// or `/^web3:\/\/(0x[0-9a-f]{40})(?::([0-9]+))?(?:[/?#]|$)/i`, its chain a
/// safe positive integer.
fn web3_key(trimmed: &str) -> Option<String> {
    let rest = strip_scheme(trimmed, "web3")?;
    let address = rest.get(..42)?;
    let hex_ok = address.len() == 42
        && address.as_bytes()[..2].eq_ignore_ascii_case(b"0x")
        && address.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit);
    if !hex_ok || !address.is_char_boundary(42) {
        return None;
    }
    let after = &rest[42..];
    let ends = |s: &str| s.is_empty() || s.starts_with(['/', '?', '#']);
    let digits_then = |s: &str| -> Option<String> {
        let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        (end > 0 && ends(&s[end..])).then(|| s[..end].to_owned())
    };
    let chain = if let Some(tail) = after
        .get(..8)
        .filter(|head| head.eq_ignore_ascii_case(".eip155-"))
        .map(|_| &after[8..])
    {
        Some(digits_then(tail)?)
    } else if let Some(tail) = after.strip_prefix(':') {
        Some(digits_then(tail)?)
    } else if ends(after) {
        None
    } else {
        return None;
    };
    let chain_id = match &chain {
        Some(digits) => crate::js::string_to_number(digits),
        None => 1.0,
    };
    // `Number.isSafeInteger(chainId) && chainId > 0`.
    if !(chain_id > 0.0 && chain_id <= 9_007_199_254_740_991.0 && crate::js::is_integer(chain_id)) {
        return None;
    }
    let suffix = if chain_id == 1.0 {
        String::new()
    } else {
        format!(":{}", fc_json::number_to_string(chain_id))
    };
    Some(format!("web3://{}{suffix}", address.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_as_get_permission_key_gives_them() {
        let cases: &[(&str, &str)] = &[
            ("ens://MyApp.eth/#/path", "myapp.eth"),
            ("myapp.eth/blog", "myapp.eth"),
            ("MyApp.ETH#/swap", "myapp.eth"),
            ("bzz://abc123/page", "bzz://abc123"),
            ("BZZ://ABC/page", "bzz://ABC"),
            ("bzz://myapp.eth/page", "myapp.eth"),
            ("ipfs://QmABC/docs", "ipfs://QmABC"),
            ("ipns://Name.TEZ/x", "name.tez"),
            ("ipns://a..tez/x", "ipns://a..tez"),
            ("rad://z123/tree", "rad://z123"),
            (
                "web3://0xABCDEF0123456789abcdef0123456789ABCDEF01.eip155-1/swap",
                "web3://0xabcdef0123456789abcdef0123456789abcdef01",
            ),
            (
                "web3://0xabcdef0123456789abcdef0123456789abcdef01:100/swap",
                "web3://0xabcdef0123456789abcdef0123456789abcdef01:100",
            ),
            ("https://app.example.com/x?y", "https://app.example.com"),
            ("  https://app.example.com:443/ ", "https://app.example.com"),
            ("about:blank", "about:blank"),
            ("not a url", "not a url"),
            ("bzz:x", "bzz:x"),
            ("bzz:foo.eth", "bzz:foo.eth"),
            ("a.eth x", "a.eth x"),
            (
                "web3://0xabcdef0123456789abcdef0123456789abcdef01:007",
                "web3://0xabcdef0123456789abcdef0123456789abcdef01:7",
            ),
            (
                "web3://0Xabcdef0123456789abcdef0123456789abcdef01.EIP155-5",
                "web3://0xabcdef0123456789abcdef0123456789abcdef01:5",
            ),
            ("https://\u{eb}xample.com/", "https://xn--xample-ova.com"),
            ("blob:https://a.example/x", "https://a.example"),
        ];
        // Each answer is Node's for `normalizeOrigin(url)` at the swarm
        // reference commit.
        for (url, key) in cases {
            assert_eq!(normalize_origin(url), *key, "{url}");
        }
        assert_eq!(normalize_origin("  "), "");
    }
}
