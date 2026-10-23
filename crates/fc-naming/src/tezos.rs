//! Tezos Domains encodings, as `tezos-domains-resolver.js` does them:
//! `ScriptExpr` hashes of big-map keys, Micheline value walking, record
//! metadata, and the published-website URI check.

use crate::jsjson::{self, JsValue};
use blake2::{Blake2b, Digest, digest::consts::U32};
use sha2::Sha256;
use std::borrow::Cow;

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

/// A Micheline walk JavaScript would abort with a `TypeError` (an `args`
/// that isn't an array, a `code` that has no `find`). The caller fails the
/// lookup, as the JS does when the error propagates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MichelineError;

/// `obj?.[key]` on a JSON value: an object's property or an array's item,
/// borrowed, or a string's character, which is a new value.
fn index<'a>(value: &'a JsValue, key: &str) -> Option<Cow<'a, JsValue>> {
    match value {
        JsValue::Object(_) => value.get(key).map(Cow::Borrowed),
        JsValue::Array(items) => key
            .parse::<usize>()
            .ok()
            .and_then(|i| items.get(i))
            .map(Cow::Borrowed),
        JsValue::String(s) => {
            // A string indexes by UTF-16 unit; only "0" and "1" are used here.
            let i: usize = key.parse().ok()?;
            let unit = s.units().nth(i)?;
            Some(Cow::Owned(JsValue::String(jsjson::JsString::from_units(
                &[unit],
            ))))
        }
        _ => None,
    }
}

/// `obj?.[key]?.[field]`, borrowed: a string's character has no fields.
fn index_field<'a>(value: &'a JsValue, key: &str, field: &str) -> Option<&'a JsValue> {
    match index(value, key)? {
        Cow::Borrowed(item) => item.get(field),
        Cow::Owned(_) => None,
    }
}

fn annotation_matches(node: &JsValue, annotation: &str) -> bool {
    node.get("annots")
        .and_then(JsValue::as_array)
        .is_some_and(|annots| annots.iter().any(|a| a.as_str() == Some(annotation)))
}

/// `node && typeof node === 'object' && String(node.prim || '').toLowerCase() === 'pair'`.
/// `String` throws for a `prim` object with its own `toString` key.
fn is_pair(node: &JsValue) -> Result<bool, MichelineError> {
    if !matches!(node, JsValue::Object(_) | JsValue::Array(_)) {
        return Ok(false);
    }
    let prim = match node.get("prim").filter(|p| p.truthy()) {
        Some(prim) => prim.js_string().map_err(|_| MichelineError)?,
        None => String::new(),
    };
    Ok(prim.to_lowercase() == "pair")
}

/// `flattenPairLeaves`: the leaves of nested pairs, left to right. The walk
/// is iterative and borrows; a parsed value is at most `MAX_DEPTH` deep.
/// `(node.args || []).flatMap(…)` throws for an `args` that is truthy and
/// not an array.
fn flatten_pair_leaves(node: &JsValue) -> Result<Vec<&JsValue>, MichelineError> {
    let mut leaves = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if !is_pair(current)? {
            leaves.push(current);
            continue;
        }
        match current.get("args") {
            Some(JsValue::Array(args)) => stack.extend(args.iter().rev()),
            Some(args) if args.truthy() => return Err(MichelineError),
            _ => {}
        }
    }
    Ok(leaves)
}

/// `findAnnotatedValue`: the value leaf at the position of the type leaf
/// annotated `annotation`, with that type leaf.
pub fn find_annotated_value<'a>(
    type_node: Option<&'a JsValue>,
    value_node: Option<&'a JsValue>,
    annotation: &str,
) -> Result<Option<(&'a JsValue, &'a JsValue)>, MichelineError> {
    let (Some(type_node), Some(value_node)) = (type_node, value_node) else {
        return Ok(None);
    };
    if !type_node.truthy() || matches!(value_node, JsValue::Null) {
        return Ok(None);
    }
    let type_leaves = flatten_pair_leaves(type_node)?;
    let value_leaves = flatten_pair_leaves(value_node)?;
    let Some(i) = type_leaves
        .iter()
        .position(|node| annotation_matches(node, annotation))
    else {
        return Ok(None);
    };
    Ok(value_leaves.get(i).map(|value| (type_leaves[i], *value)))
}

/// `storageTypeFromScript`: `script?.code?.find(e => e?.prim === 'storage')?.args?.[0] || null`.
pub fn storage_type_from_script(
    script: &JsValue,
) -> Result<Option<Cow<'_, JsValue>>, MichelineError> {
    let code = match script.get("code") {
        None | Some(JsValue::Null) => return Ok(None),
        Some(JsValue::Array(code)) => code,
        Some(_) => return Err(MichelineError),
    };
    let Some(entry) = code
        .iter()
        .find(|e| e.get("prim").and_then(JsValue::as_str) == Some("storage"))
    else {
        return Ok(None);
    };
    Ok(entry
        .get("args")
        .and_then(|args| index(args, "0"))
        .filter(|ty| ty.truthy()))
}

/// `mapEntries`: a Micheline map's `Elt`s whose key has a `string`, as
/// key → `bytes`. Only string keys can ever be looked up, so only those are
/// kept; a later duplicate wins, as in a JS `Map`.
pub fn map_entries(value: &JsValue) -> Vec<(jsjson::JsString, Option<&JsValue>)> {
    let mut out: Vec<(jsjson::JsString, Option<&JsValue>)> = Vec::new();
    // Indexed, so a map of many records stays linear.
    let mut positions: std::collections::BTreeMap<jsjson::JsString, usize> =
        std::collections::BTreeMap::new();
    for entry in value.as_array().unwrap_or(&[]) {
        if entry.get("prim").and_then(JsValue::as_str) != Some("Elt") {
            continue;
        }
        let Some(args) = entry.get("args") else {
            continue;
        };
        let Some(JsValue::String(key)) = index_field(args, "0", "string") else {
            continue;
        };
        let key = key.clone();
        let bytes = index_field(args, "1", "bytes");
        if let Some(&i) = positions.get(&key) {
            out[i].1 = bytes;
        } else {
            positions.insert(key.clone(), out.len());
            out.push((key, bytes));
        }
    }
    out
}

/// `bytesFromHex`: even-length hex, any case.
pub fn bytes_from_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value.as_bytes().chunks(2).map(crate::hex_byte).collect()
}

/// Why record metadata couldn't be read (`invalid Tezos Domains metadata: …`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataError {
    /// `Invalid Micheline bytes value`.
    Bytes,
    /// The bytes aren't JSON, as `JSON.parse` judges it. The message after
    /// the prefix is the core's, not V8's (design 0003, Codec deviations).
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

/// `decodeJsonBytes`: a hex string's bytes as UTF-8 (invalid sequences
/// replaced, as Node does), then `JSON.parse`. Anything but a hex string
/// is `bytesFromHex`'s error.
pub fn decode_json_bytes(value: Option<&JsValue>) -> Result<JsValue, MetadataError> {
    let bytes = value
        .and_then(JsValue::as_str)
        .and_then(bytes_from_hex)
        .ok_or(MetadataError::Bytes)?;
    jsjson::parse(&String::from_utf8_lossy(&bytes)).map_err(|e| MetadataError::Json(e.to_string()))
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
pub fn parse_published_uri(raw: &JsValue, redirect: bool) -> Published {
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
            out.push(crate::hex_byte(bytes.get(i + 1..i + 3)?)?);
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

    fn js(text: &str) -> JsValue {
        jsjson::parse(text).unwrap()
    }

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
        let ty = js(
            r#"{"prim":"pair","args":[{"prim":"address","annots":["%contract"]},{"prim":"PAIR","args":[{"prim":"nat","annots":["%x"]},{"prim":"big_map","annots":["%records"]}]}]}"#,
        );
        let value = js(
            r#"{"prim":"Pair","args":[{"string":"KT1x"},{"prim":"Pair","args":[{"int":"1"},{"int":"42"}]}]}"#,
        );
        let found = |annotation| find_annotated_value(Some(&ty), Some(&value), annotation);
        assert_eq!(
            found("%contract").unwrap().unwrap().1.clone(),
            js(r#"{"string":"KT1x"}"#)
        );
        assert_eq!(
            found("%records").unwrap().unwrap().1.clone(),
            js(r#"{"int":"42"}"#)
        );
        assert_eq!(found("%missing"), Ok(None));
        let script = js(&format!(
            r#"{{"code":[{{"prim":"parameter"}},{{"prim":"storage","args":[{}]}}]}}"#,
            ty.stringify()
        ));
        assert_eq!(
            storage_type_from_script(&script).unwrap().as_deref(),
            Some(&ty)
        );
        // `code` without `find`, and `args` without `flatMap`: TypeErrors.
        assert_eq!(
            storage_type_from_script(&js(r#"{"code":"x"}"#)),
            Err(MichelineError)
        );
        let bad_args = js(r#"{"prim":"pair","args":"x"}"#);
        assert_eq!(
            find_annotated_value(Some(&bad_args), Some(&js("1")), "%a"),
            Err(MichelineError)
        );
        // A prim of ["PAIR"] is a pair: String(["PAIR"]) is "PAIR".
        let odd = js(r#"{"prim":["PAIR"],"args":[{"annots":["%a"]},{"annots":["%b"]}]}"#);
        let vals = js(r#"{"prim":"Pair","args":[1,2]}"#);
        assert_eq!(
            find_annotated_value(Some(&odd), Some(&vals), "%b")
                .unwrap()
                .unwrap()
                .1
                .clone(),
            js("2")
        );
    }

    #[test]
    fn string_of_a_prim_can_throw() {
        // String({toString: 1}) throws in JavaScript, so the walk fails.
        let ty = js(r#"{"prim":{"toString":1},"args":[]}"#);
        assert_eq!(
            find_annotated_value(Some(&ty), Some(&js("1")), "%a"),
            Err(MichelineError)
        );
    }

    #[test]
    fn micheline_walks_deep_pairs() {
        let mut ty = String::from(r#"{"annots":["%records"]}"#);
        let mut value = String::from(r#"{"int":"7"}"#);
        for _ in 0..200 {
            ty = format!(r#"{{"prim":"pair","args":[{ty}]}}"#);
            value = format!(r#"{{"prim":"Pair","args":[{value}]}}"#);
        }
        let (ty, value) = (js(&ty), js(&value));
        let found = find_annotated_value(Some(&ty), Some(&value), "%records")
            .unwrap()
            .unwrap();
        assert_eq!(found.1.clone(), js(r#"{"int":"7"}"#));
    }

    #[test]
    fn record_maps_and_metadata() {
        let url = hex::encode(r#""https://example.org""#);
        let map = js(&format!(
            r#"[{{"prim":"Elt","args":[{{"string":"web:content_url"}},{{"bytes":"00"}}]}},{{"prim":"Elt","args":[{{"string":"web:content_url"}},{{"bytes":"{url}"}}]}},{{"prim":"Elt","args":[{{"int":"1"}},{{"bytes":"00"}}]}}]"#
        ));
        let entries = map_entries(&map);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            decode_json_bytes(entries[0].1).unwrap(),
            js(r#""https://example.org""#)
        );
        assert_eq!(
            decode_json_bytes(Some(&js(r#""0""#))),
            Err(MetadataError::Bytes)
        );
        assert_eq!(decode_json_bytes(None), Err(MetadataError::Bytes));
        assert_eq!(decode_json_bytes(Some(&js("7"))), Err(MetadataError::Bytes));
        assert!(matches!(
            decode_json_bytes(Some(&js(r#""7b""#))),
            Err(MetadataError::Json(_))
        ));
        // A big integer loses precision, as in JavaScript.
        let big = JsValue::string(hex::encode("9007199254740993"));
        assert_eq!(
            decode_json_bytes(Some(&big)).unwrap(),
            JsValue::Number(9007199254740992.0)
        );
    }

    #[test]
    fn many_records_stay_linear() {
        // 32,000 distinct keys fit a Tezos answer; a quadratic map took
        // seconds on them.
        let items: Vec<String> = (0..32_000)
            .map(|i| format!(r#"{{"prim":"Elt","args":[{{"string":"k{i}"}},{{"bytes":"00"}}]}}"#))
            .collect();
        let map = js(&format!("[{}]", items.join(",")));
        let started = std::time::Instant::now();
        assert_eq!(map_entries(&map).len(), 32_000);
        assert!(started.elapsed().as_secs() < 2, "{:?}", started.elapsed());
    }

    #[test]
    fn published_uris() {
        let s = |text: &str| JsValue::string(text);
        assert_eq!(
            parse_published_uri(&s("https://Example.org/a"), true),
            Published::Web {
                protocol: "https".into(),
                uri: "https://example.org/a".into(),
                redirect: true
            }
        );
        assert_eq!(
            parse_published_uri(&s("ipfs://x"), true),
            Published::Unsupported("redirect URL must use HTTP(S)".into())
        );
        assert_eq!(
            parse_published_uri(&s("ipfs://bafyCID/a/b/"), false),
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
                parse_published_uri(&s(uri), false),
                Published::Unsupported(reason.into()),
                "{uri}"
            );
        }
        assert_eq!(
            parse_published_uri(&js("42"), false),
            Published::Unsupported("invalid website URI".into())
        );
        assert!(matches!(
            parse_published_uri(&s("ipns://%zz%2Etez/"), false),
            Published::Content { .. }
        ));
    }
}
