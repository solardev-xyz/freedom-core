//! Tezos Domains encodings, as `tezos-domains-resolver.js` does them:
//! `ScriptExpr` hashes of big-map keys, Micheline value walking, record
//! metadata, and the published-website URI check.

use blake2::{Blake2b, Digest, digest::consts::U32};
use serde_json::Value;
use sha2::Sha256;
use url::Url;

use crate::contenthash::encode_base58;

/// `expr` in base58check.
const SCRIPT_EXPR_PREFIX: [u8; 4] = [13, 44, 64, 27];

/// `base58Check`: base58 of the payload and the first 4 bytes of its
/// double SHA-256.
pub fn base58check(payload: &[u8]) -> String {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    let mut data = payload.to_vec();
    data.extend_from_slice(&second[..4]);
    encode_base58(&data)
}

/// `scriptExprHash`: the big-map key hash of a packed Micheline bytes value
/// (`05 0a`, a big-endian u32 length, the bytes), BLAKE2b-256, `expr…`.
pub fn script_expr_hash(key: &[u8]) -> String {
    let mut packed = vec![0x05, 0x0a];
    // A key longer than u32 can't come from a name (255 code units) or an
    // expiry key; JavaScript's `>>>` would wrap it the same way.
    packed.extend_from_slice(&(key.len() as u32).to_be_bytes());
    packed.extend_from_slice(key);
    let digest = Blake2b::<U32>::digest(&packed);
    let mut payload = SCRIPT_EXPR_PREFIX.to_vec();
    payload.extend_from_slice(&digest);
    base58check(&payload)
}

/// `isTezosDomainName`: lowercased, ends in `.tez`, at most 255 UTF-16 code
/// units, no whitespace, `/`, `?`, `#` or control characters, no empty label.
pub fn is_tezos_domain_name(value: &str) -> bool {
    let lower = value.to_lowercase();
    if !lower.ends_with(".tez") || lower.encode_utf16().count() > 255 {
        return false;
    }
    // JavaScript's `\s` is its whitespace and line terminators.
    if lower
        .chars()
        .any(|c| crate::normalize::is_js_whitespace(c) || matches!(c, '/' | '?' | '#'))
    {
        return false;
    }
    // The JS checks the first UTF-16 unit of each code point: controls only.
    if lower
        .chars()
        .any(|c| (c as u32) <= 0x1f || c as u32 == 0x7f)
    {
        return false;
    }
    lower.split('.').all(|label| !label.is_empty())
}

/// `isEnsHost || isTezosDomainHost`: a host that is a dweb *name*.
pub fn is_dweb_name_host(host: &str) -> bool {
    let lower = host.to_lowercase();
    lower.ends_with(".eth")
        || lower.ends_with(".box")
        || lower.ends_with(".wei")
        || lower.ends_with(".gwei")
        || (lower.ends_with(".tez") && lower.split('.').all(|label| !label.is_empty()))
}

fn annotation_matches(node: &Value, annotation: &str) -> bool {
    node.get("annots")
        .and_then(Value::as_array)
        .is_some_and(|annots| annots.iter().any(|a| a.as_str() == Some(annotation)))
}

/// `flattenPairLeaves`: the leaves of nested `pair`s (the prim compared
/// case-insensitively), left to right.
fn flatten_pair_leaves<'a>(node: &'a Value, out: &mut Vec<&'a Value>, depth: usize) {
    let is_pair = node.is_object()
        && node
            .get("prim")
            .map(js_string)
            .is_some_and(|prim| prim.to_lowercase() == "pair");
    if is_pair && depth < MAX_MICHELINE_DEPTH {
        if let Some(args) = node.get("args").and_then(Value::as_array) {
            for arg in args {
                flatten_pair_leaves(arg, out, depth + 1);
            }
        }
    } else {
        out.push(node);
    }
}

/// Deeper Micheline than real storage ever has is treated as a leaf (design
/// 0003, Limits).
const MAX_MICHELINE_DEPTH: usize = 64;

/// `String(x)` for the values a `prim` can hold.
fn js_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

/// `findAnnotatedValue`: the value leaf at the position of the type leaf
/// annotated `annotation`, with that type leaf.
pub fn find_annotated_value<'a>(
    type_node: &'a Value,
    value_node: &'a Value,
    annotation: &str,
) -> Option<(&'a Value, &'a Value)> {
    if type_node.is_null() || value_node.is_null() {
        return None;
    }
    let mut type_leaves = Vec::new();
    flatten_pair_leaves(type_node, &mut type_leaves, 0);
    let mut value_leaves = Vec::new();
    flatten_pair_leaves(value_node, &mut value_leaves, 0);
    let index = type_leaves
        .iter()
        .position(|node| annotation_matches(node, annotation))?;
    Some((type_leaves[index], *value_leaves.get(index)?))
}

/// `storageTypeFromScript`: the `storage` declaration's type.
pub fn storage_type_from_script(script: &Value) -> Option<&Value> {
    script
        .get("code")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("prim").and_then(Value::as_str) == Some("storage"))?
        .get("args")?
        .get(0)
}

/// `mapEntries`: a Micheline map of `Elt`s with string keys, as key →
/// `bytes` hex (or none). A later duplicate key wins, as in a JS `Map`.
pub fn map_entries(value: &Value) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    for entry in value.as_array().into_iter().flatten() {
        if entry.get("prim").and_then(Value::as_str) != Some("Elt") {
            continue;
        }
        let args = entry.get("args");
        let Some(key) = args
            .and_then(|a| a.get(0))
            .and_then(|k| k.get("string"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let bytes = args
            .and_then(|a| a.get(1))
            .and_then(|v| v.get("bytes"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(slot) = out.iter_mut().find(|(k, _)| k == key) {
            slot.1 = bytes;
        } else {
            out.push((key.to_owned(), bytes));
        }
    }
    out
}

/// `bytesFromHex`: even-length hex, any case.
pub fn bytes_from_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(value.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Why record metadata couldn't be read (`invalid Tezos Domains metadata: …`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataError {
    /// `Invalid Micheline bytes value`.
    Bytes,
    /// The bytes aren't JSON. JavaScript's message is V8's own, which the
    /// core can't reproduce (design 0003, Deviations).
    Json(String),
}

impl MetadataError {
    pub fn message(&self) -> String {
        match self {
            MetadataError::Bytes => "Invalid Micheline bytes value".into(),
            MetadataError::Json(message) => message.clone(),
        }
    }
}

/// `decodeJsonBytes`: hex bytes as UTF-8 (invalid sequences replaced, as
/// Node does), then JSON. `None` input is `bytesFromHex(undefined)`.
pub fn decode_json_bytes(value: Option<&str>) -> Result<Value, MetadataError> {
    let bytes = value.and_then(bytes_from_hex).ok_or(MetadataError::Bytes)?;
    serde_json::from_str(&String::from_utf8_lossy(&bytes))
        .map_err(|e| MetadataError::Json(e.to_string()))
}

/// What a website record points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Published {
    Web {
        protocol: String,
        uri: String,
        redirect: bool,
    },
    Content {
        protocol: String,
        uri: String,
        decoded: String,
        base_path: String,
    },
    Unsupported(String),
}

/// `parsePublishedUri`. `raw` is the record's JSON value, which must be a
/// string of at most 8,192 UTF-16 code units.
pub fn parse_published_uri(raw: &Value, redirect: bool) -> Published {
    let invalid = || Published::Unsupported("invalid website URI".into());
    let Some(raw) = raw.as_str() else {
        return invalid();
    };
    if raw.encode_utf16().count() > 8192 {
        return invalid();
    }
    let Ok(parsed) = Url::parse(raw) else {
        return invalid();
    };
    let protocol = parsed.scheme().to_lowercase();
    let web = protocol == "http" || protocol == "https";
    if redirect && !web {
        return Published::Unsupported("redirect URL must use HTTP(S)".into());
    }
    let hostname = parsed.host_str().unwrap_or("");
    let credentials = !parsed.username().is_empty() || parsed.password().is_some();
    if web {
        if hostname.is_empty() || credentials {
            return Published::Unsupported("invalid HTTP(S) website URI".into());
        }
        return Published::Web {
            protocol,
            uri: parsed.to_string(),
            redirect,
        };
    }
    if !redirect && (protocol == "ipfs" || protocol == "ipns") {
        let upper = protocol.to_uppercase();
        if hostname.is_empty() || credentials || parsed.port().is_some() {
            return Published::Unsupported(format!("invalid {upper} website URI"));
        }
        let trimmed = hostname.trim_end_matches('.');
        let host_for_check = decode_uri_component(trimmed).unwrap_or_else(|| trimmed.to_owned());
        if is_dweb_name_host(&host_for_check) {
            return Published::Unsupported(format!(
                "{upper} website URI must reference content, not a name"
            ));
        }
        let path = parsed.path();
        let base_path = if path == "/" {
            String::new()
        } else {
            path.strip_suffix('/').unwrap_or(path).to_owned()
        };
        return Published::Content {
            protocol,
            uri: parsed.to_string(),
            decoded: hostname.to_owned(),
            base_path,
        };
    }
    Published::Unsupported(format!("unsupported website protocol: {protocol}"))
}

/// JavaScript's `decodeURIComponent`: `None` where it throws, on any `%` not
/// followed by two hex digits or on escapes that aren't valid UTF-8.
fn decode_uri_component(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn script_expr_golden() {
        assert_eq!(
            script_expr_hash(b"awesome-tezos.tez"),
            "exprusUkj4PJBxvW1zeyb2JWiGTWF77vDLxMzPBv8LKtHrKGbDzmeB"
        );
    }

    #[test]
    fn tezos_domain_names() {
        assert!(is_tezos_domain_name("Awesome-Tezos.TEZ"));
        for bad in [
            "a.eth",
            ".tez",
            "a..tez",
            "a b.tez",
            "a/b.tez",
            "a\u{1}.tez",
            "a?.tez",
        ] {
            assert!(!is_tezos_domain_name(bad), "{bad}");
        }
        assert!(!is_tezos_domain_name(&format!("{}.tez", "a".repeat(252))));
        assert!(is_tezos_domain_name(&format!("{}.tez", "a".repeat(251))));
    }

    #[test]
    fn micheline_walks() {
        let ty = json!({"prim": "pair", "args": [{"prim": "address", "annots": ["%contract"]}, {"prim": "PAIR", "args": [{"prim": "nat", "annots": ["%x"]}, {"prim": "big_map", "annots": ["%records"]}]}]});
        let value = json!({"prim": "Pair", "args": [{"string": "KT1x"}, {"prim": "Pair", "args": [{"int": "1"}, {"int": "42"}]}]});
        assert_eq!(
            find_annotated_value(&ty, &value, "%contract").unwrap().1,
            &json!({"string": "KT1x"})
        );
        assert_eq!(
            find_annotated_value(&ty, &value, "%records").unwrap().1,
            &json!({"int": "42"})
        );
        assert!(find_annotated_value(&ty, &value, "%missing").is_none());
        let script =
            json!({"code": [{"prim": "parameter"}, {"prim": "storage", "args": [ty.clone()]}]});
        assert_eq!(storage_type_from_script(&script), Some(&ty));
    }

    #[test]
    fn record_maps_and_metadata() {
        let url = hex::encode("\"https://example.org\"");
        let map = json!([
            {"prim": "Elt", "args": [{"string": "web:content_url"}, {"bytes": "00"}]},
            {"prim": "Elt", "args": [{"string": "web:content_url"}, {"bytes": url}]},
            {"prim": "Elt", "args": [{"int": "1"}, {"bytes": "00"}]},
        ]);
        let entries = map_entries(&map);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            decode_json_bytes(entries[0].1.as_deref()).unwrap(),
            json!("https://example.org")
        );
        assert_eq!(decode_json_bytes(Some("0")), Err(MetadataError::Bytes));
        assert_eq!(decode_json_bytes(None), Err(MetadataError::Bytes));
        assert!(matches!(
            decode_json_bytes(Some("7b")),
            Err(MetadataError::Json(_))
        ));
    }

    #[test]
    fn published_uris() {
        assert_eq!(
            parse_published_uri(&json!("https://Example.org/a"), true),
            Published::Web {
                protocol: "https".into(),
                uri: "https://example.org/a".into(),
                redirect: true
            }
        );
        assert_eq!(
            parse_published_uri(&json!("ipfs://x"), true),
            Published::Unsupported("redirect URL must use HTTP(S)".into())
        );
        assert_eq!(
            parse_published_uri(&json!("ipfs://bafyCID/a/b/"), false),
            Published::Content {
                protocol: "ipfs".into(),
                uri: "ipfs://bafyCID/a/b/".into(),
                decoded: "bafyCID".into(),
                base_path: "/a/b".into()
            }
        );
        for (uri, reason) in [
            (
                "ipfs://self.tez/",
                "IPFS website URI must reference content, not a name",
            ),
            (
                "ipns://self.tez./",
                "IPNS website URI must reference content, not a name",
            ),
            (
                "ipns://self%2Etez/",
                "IPNS website URI must reference content, not a name",
            ),
            ("ipfs://cid:8080/", "invalid IPFS website URI"),
            ("https://user@example.org/", "invalid HTTP(S) website URI"),
            ("ftp://example.org/", "unsupported website protocol: ftp"),
            ("not a url", "invalid website URI"),
        ] {
            assert_eq!(
                parse_published_uri(&json!(uri), false),
                Published::Unsupported(reason.into()),
                "{uri}"
            );
        }
        assert_eq!(
            parse_published_uri(&json!(42), false),
            Published::Unsupported("invalid website URI".into())
        );
        // A malformed escape: decodeURIComponent throws, so the raw host is
        // checked, and `%zz%2Etez` is not a name.
        assert!(matches!(
            parse_published_uri(&json!("ipns://%zz%2Etez/"), false),
            Published::Content { .. }
        ));
    }
}
