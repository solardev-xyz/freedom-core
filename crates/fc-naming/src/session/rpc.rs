//! JSON-RPC over `shell.rpc`, the way the reference's ethers 6.17
//! `JsonRpcProvider` and `Contract` see it (design 0004, Transport and
//! Classification): request bodies, and answers turned into results or
//! ethers' error classes. Main runs the `FetchRequest` itself: redirects,
//! 429 back-off, expiry.

use crate::jsjson::{self, JsValue};

/// A JSON-RPC method the resolver uses, with its params.
#[derive(Debug, Clone, PartialEq)]
pub enum Method {
    BlockNumber,
    /// `eth_getBlockByNumber(tag, false)`: a number or a tag (`finalized`).
    Block(BlockRef),
    /// `eth_call({ to, data }, block)`, `block` a hash or a tag.
    Call {
        to: [u8; 20],
        data: Vec<u8>,
        block: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum BlockRef {
    Number(u64),
    Tag(String),
}

impl Method {
    pub fn name(&self) -> &'static str {
        match self {
            Method::BlockNumber => "eth_blockNumber",
            Method::Block(_) => "eth_getBlockByNumber",
            Method::Call { .. } => "eth_call",
        }
    }

    /// The params, as ethers' `getRpcRequest` writes them.
    pub fn params(&self) -> JsValue {
        match self {
            Method::BlockNumber => JsValue::Array(Vec::new()),
            Method::Block(block) => JsValue::Array(vec![
                JsValue::String(match block {
                    BlockRef::Number(n) => format!("0x{n:x}"),
                    BlockRef::Tag(tag) => tag.clone(),
                }),
                JsValue::Bool(false),
            ]),
            Method::Call { to, data, block } => JsValue::Array(vec![
                JsValue::Object(vec![
                    ("to".into(), JsValue::String(hex(to))),
                    ("data".into(), JsValue::String(hex(data))),
                ]),
                JsValue::String(block.clone()),
            ]),
        }
    }
}

/// `0x` and lowercase hex, like ethers' `hexlify`.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The request body: `JSON.stringify({ method, params, id, jsonrpc })`.
pub fn body(id: u64, method: &Method) -> String {
    JsValue::Object(vec![
        ("method".into(), JsValue::String(method.name().into())),
        ("params".into(), method.params()),
        // Request ids stay far below 2^53.
        #[allow(clippy::cast_precision_loss)]
        ("id".into(), JsValue::Number(id as f64)),
        ("jsonrpc".into(), JsValue::String("2.0".into())),
    ])
    .stringify()
}

/// How main's transport ended an exchange (design 0004, Transport errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Timeout,
    Network,
    Refused,
    TooLarge,
    Cancelled,
    StaleGeneration,
}

/// A node's JSON-RPC `error` member, as ethers keeps it in `info.error`.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeError {
    pub value: JsValue,
}

impl NodeError {
    pub fn code(&self) -> Option<f64> {
        match self.value.get("code") {
            Some(JsValue::Number(n)) => Some(*n),
            _ => None,
        }
    }

    pub fn message(&self) -> String {
        match self.value.get("message") {
            Some(JsValue::String(s)) => s.clone(),
            _ => String::new(),
        }
    }

    /// `error.data` when it is a string (the resolver's `getRevertData`
    /// reads it, hex or not).
    pub fn data_string(&self) -> Option<&str> {
        self.value.get("data").and_then(JsValue::as_str)
    }
}

/// ethers' errors for a failed exchange, by class.
#[derive(Debug, Clone, PartialEq)]
pub enum RpcError {
    /// Main's transport failed: ethers' `TIMEOUT` or a socket-level error.
    Transport(Transport),
    /// `SERVER_ERROR`: a non-2xx status, or 429 past the last attempt.
    Http(u16),
    /// `UNSUPPORTED_OPERATION`: the body isn't UTF-8 or isn't JSON.
    NotJson,
    /// `BAD_DATA` "missing response for request".
    MissingResponse,
    /// `CALL_EXCEPTION` for an `eth_call`. With revert data (ethers'
    /// `spelunkData`), the `Contract` rebuilds the error from the data
    /// alone; without, the node's error stays in `info.error`.
    CallException {
        data: Option<Vec<u8>>,
        node: Option<NodeError>,
    },
    /// `UNKNOWN_ERROR` "could not coalesce error": a JSON-RPC error for
    /// another method.
    Coalesce(NodeError),
    /// The result failed ethers' formatting (`INVALID_ARGUMENT`,
    /// `BAD_DATA`, `NUMERIC_FAULT`).
    BadResult,
    /// An `error` member that isn't an object (design 0004,
    /// Classification rule 4).
    MalformedError,
}

/// Turns a 2xx body into the result for request `id`, as
/// `JsonRpcApiProvider` does: an array answer is searched for the id.
pub fn answer(id: u64, method: &Method, status: u16, body: &[u8]) -> Result<JsValue, RpcError> {
    if !(200..300).contains(&status) {
        return Err(RpcError::Http(status));
    }
    let text = std::str::from_utf8(body).map_err(|_| RpcError::NotJson)?;
    let parsed = jsjson::parse(text).map_err(|_| RpcError::NotJson)?;
    // `JsValue` drops iteratively, so its items are cloned, not moved.
    let responses = if let JsValue::Array(items) = &parsed {
        items.clone()
    } else {
        vec![parsed]
    };
    #[allow(clippy::cast_precision_loss)]
    let wanted = JsValue::Number(id as f64);
    let Some(response) = responses.into_iter().find(|r| r.get("id") == Some(&wanted)) else {
        return Err(RpcError::MissingResponse);
    };
    if let JsValue::Object(members) = &response
        && let Some((_, error)) = members.iter().find(|(key, _)| key == "error")
    {
        return Err(node_error(method, error.clone()));
    }
    Ok(response.get("result").cloned().unwrap_or(JsValue::Null))
}

fn node_error(method: &Method, error: JsValue) -> RpcError {
    if !matches!(error, JsValue::Object(_)) {
        return RpcError::MalformedError;
    }
    match method {
        // The node's error stays beside any revert data ethers extracts:
        // classification checks its code first (rule 5, −32603).
        Method::Call { .. } => RpcError::CallException {
            data: spelunk_data(&error, 0),
            node: Some(NodeError { value: error }),
        },
        _ => RpcError::Coalesce(NodeError { value: error }),
    }
}

/// ethers' `spelunkData`: the first object, depth first in property order,
/// whose `message` mentions a revert and whose `data` is hex; strings are
/// tried as JSON. (Its recursion is bounded by the answer's own depth.)
fn spelunk_data(value: &JsValue, depth: usize) -> Option<Vec<u8>> {
    if depth > jsjson::MAX_DEPTH {
        return None;
    }
    match value {
        JsValue::Object(members) => {
            let message = value.get("message").and_then(JsValue::as_str);
            let data = value.get("data").and_then(JsValue::as_str);
            if let (Some(message), Some(data)) = (message, data)
                && message.to_ascii_lowercase().contains("revert")
                && let Some(bytes) = hex_string(data)
            {
                return Some(bytes);
            }
            members
                .iter()
                .find_map(|(_, child)| spelunk_data(child, depth + 1))
        }
        JsValue::Array(items) => items
            .iter()
            .find_map(|child| spelunk_data(child, depth + 1)),
        JsValue::String(text) => jsjson::parse(text)
            .ok()
            .and_then(|inner| spelunk_data(&inner, depth + 1)),
        _ => None,
    }
}

/// ethers' `isHexString(value)` (any length) as bytes. An odd length is
/// hex but not bytes: `getBytes` would refuse it.
pub fn hex_string(value: &str) -> Option<Vec<u8>> {
    let digits = value.strip_prefix("0x")?;
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) || digits.len() % 2 != 0 {
        return None;
    }
    digits.as_bytes().chunks(2).map(crate::hex_byte).collect()
}

/// `hexlify(result)` for an `eth_call`: even-length hex, else
/// `INVALID_ARGUMENT`.
pub fn call_result(result: &JsValue) -> Result<Vec<u8>, RpcError> {
    result
        .as_str()
        .and_then(hex_string)
        .ok_or(RpcError::BadResult)
}

/// ethers' `getNumber` for a JSON value: a safe integer.
pub fn get_number(value: &JsValue) -> Option<i64> {
    const MAX: f64 = 9_007_199_254_740_991.0;
    match value {
        JsValue::Number(n) if n.fract() == 0.0 && n.abs() <= MAX =>
        {
            #[allow(clippy::cast_possible_truncation)]
            Some(*n as i64)
        }
        JsValue::String(s) if !s.is_empty() => {
            let n = string_to_bigint(s)?;
            (n.unsigned_abs() <= 9_007_199_254_740_991).then_some(n as i64)
        }
        _ => None,
    }
}

/// ethers' `getBigInt` for a JSON value, enough to validate it: any width
/// (a block's difficulty can exceed 128 bits).
fn is_big_int(value: &JsValue) -> bool {
    match value {
        JsValue::Number(n) => n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0,
        // `-BigInt(rest)` for a leading `-` not followed by another.
        JsValue::String(s) if !s.is_empty() => match s.strip_prefix('-') {
            Some(rest) if !rest.starts_with('-') => bigint_syntax(rest),
            _ => bigint_syntax(s),
        },
        _ => false,
    }
}

/// Whether JavaScript's `BigInt(text)` parses, at any width: trimmed of
/// JavaScript whitespace; empty is 0; a decimal with an optional sign, or
/// `0x`/`0o`/`0b` digits without one.
fn bigint_syntax(text: &str) -> bool {
    let trimmed = crate::js_trim(text);
    if trimmed.is_empty() {
        return true;
    }
    let digits =
        |rest: &str, radix: u32| !rest.is_empty() && rest.chars().all(|c| c.is_digit(radix));
    match trimmed.get(..2).map(str::to_ascii_lowercase).as_deref() {
        Some("0x") => digits(&trimmed[2..], 16),
        Some("0o") => digits(&trimmed[2..], 8),
        Some("0b") => digits(&trimmed[2..], 2),
        _ => digits(trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed), 10),
    }
}

/// JavaScript's `BigInt(string)`, for values that fit `i128`: trimmed of
/// JavaScript whitespace; a signed decimal, or `0x`/`0o`/`0b` digits; an
/// empty string is 0.
fn string_to_bigint(s: &str) -> Option<i128> {
    let trimmed = crate::js_trim(s);
    if let Some(rest) = trimmed.strip_prefix('-') {
        return decimal(rest).map(|n| -n);
    }
    if let Some(rest) = trimmed.strip_prefix('+') {
        return decimal(rest);
    }
    string_to_bigint_digits(trimmed)
}

fn string_to_bigint_digits(trimmed: &str) -> Option<i128> {
    let radix_digits = |rest: &str, radix: u32| {
        if rest.is_empty() {
            return None;
        }
        i128::from_str_radix(rest, radix)
            .ok()
            .filter(|_| rest.bytes().all(|b| (b as char).is_digit(radix)))
    };
    let lower = trimmed.get(..2).map(str::to_ascii_lowercase);
    match lower.as_deref() {
        Some("0x") => radix_digits(&trimmed[2..], 16),
        Some("0o") => radix_digits(&trimmed[2..], 8),
        Some("0b") => radix_digits(&trimmed[2..], 2),
        _ if trimmed.is_empty() => Some(0),
        _ => decimal(trimmed),
    }
}

fn decimal(digits: &str) -> Option<i128> {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// What the resolver needs from a block, after ethers' `formatBlock`
/// accepted it.
#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub number: i64,
    /// `null` for a pending block.
    pub hash: Option<String>,
}

/// `getBlock`: `null` is no block; anything else must pass `formatBlock`.
pub fn block_result(result: &JsValue) -> Result<Option<Block>, RpcError> {
    if matches!(result, JsValue::Null) {
        return Ok(None);
    }
    let field = |name: &str| result.get(name);
    let present = |name: &str| field(name).filter(|v| !matches!(v, JsValue::Null));
    let is_hash = |v: &JsValue| {
        v.as_str()
            .is_some_and(|s| s.len() == 66 && hex_string(s).is_some())
    };
    let is_data = |v: &JsValue| v.as_str().and_then(hex_string).is_some();
    let ok = (field("hash").is_none_or(|v| matches!(v, JsValue::Null) || is_hash(v)))
        && field("parentHash").is_some_and(is_hash)
        && [
            "parentBeaconBlockRoot",
            "stateRoot",
            "receiptsRoot",
            "transactionsRoot",
            "prevRandao",
        ]
        .iter()
        .all(|k| present(k).is_none_or(is_hash))
        && (present("prevRandao").is_some() || present("mixHash").is_none_or(is_hash))
        && field("number").and_then(get_number).is_some()
        && field("timestamp").and_then(get_number).is_some()
        && present("nonce").is_none_or(is_data)
        && ["difficulty", "gasLimit", "gasUsed"]
            .iter()
            .all(|k| field(k).is_some_and(is_big_int))
        && ["blobGasUsed", "excessBlobGas", "baseFeePerGas"]
            .iter()
            .all(|k| present(k).is_none_or(is_big_int))
        && present("miner").is_none_or(|v| v.as_str().is_some_and(is_address))
        && field("extraData").is_some_and(is_data)
        && field("transactions")
            .and_then(JsValue::as_array)
            .is_some_and(|txs| txs.iter().all(|tx| tx.as_str().is_some()));
    if !ok {
        return Err(RpcError::BadResult);
    }
    let number = field("number")
        .and_then(get_number)
        .ok_or(RpcError::BadResult)?;
    let hash = present("hash").and_then(JsValue::as_str).map(str::to_owned);
    Ok(Some(Block { number, hash }))
}

/// ethers' `getAddress` for the forms a node returns: 40 hex digits, all
/// one case or a valid checksum.
fn is_address(value: &str) -> bool {
    let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    else {
        return false;
    };
    if digits.len() != 40 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let lower = digits.to_ascii_lowercase();
    if digits == lower || digits == digits.to_ascii_uppercase() {
        return true;
    }
    use sha3::{Digest, Keccak256};
    let hash = Keccak256::digest(lower.as_bytes());
    digits.bytes().enumerate().all(|(i, c)| {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
        if c.is_ascii_digit() {
            true
        } else if nibble >= 8 {
            c.is_ascii_uppercase()
        } else {
            c.is_ascii_lowercase()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const UR: [u8; 20] = crate::ur::UNIVERSAL_RESOLVER;

    #[test]
    fn big_ints_validate_at_any_width() {
        let s = |v: &str| JsValue::String(v.into());
        // 2^160, as a difficulty ethers accepts.
        assert!(is_big_int(&s(
            "0x10000000000000000000000000000000000000000"
        )));
        assert!(is_big_int(&s(&"9".repeat(60))));
        assert!(is_big_int(&s(" 12 ")));
        assert!(is_big_int(&s("-0x10")));
        assert!(is_big_int(&s("-")));
        assert!(!is_big_int(&s("--1")));
        assert!(!is_big_int(&s("0x")));
        assert!(!is_big_int(&s("+0x1")));
        assert!(!is_big_int(&s("")));
        assert!(!is_big_int(&s("1.5")));
    }

    #[test]
    fn bodies_are_ethers_payloads() {
        assert_eq!(
            body(1, &Method::BlockNumber),
            r#"{"method":"eth_blockNumber","params":[],"id":1,"jsonrpc":"2.0"}"#
        );
        assert_eq!(
            body(2, &Method::Block(BlockRef::Number(19_999_992))),
            r#"{"method":"eth_getBlockByNumber","params":["0x1312cf8",false],"id":2,"jsonrpc":"2.0"}"#
        );
        let call = Method::Call {
            to: UR,
            data: vec![0x90, 0x61],
            block: "0xab".into(),
        };
        assert_eq!(
            call.params().stringify(),
            r#"[{"to":"0xeeeeeeee14d718c2b47d9923deab1335e144eeee","data":"0x9061"},"0xab"]"#
        );
    }

    #[test]
    fn answers_take_ethers_shapes() {
        let m = Method::BlockNumber;
        assert_eq!(
            answer(1, &m, 200, br#"{"jsonrpc":"2.0","id":1,"result":"0x10"}"#),
            Ok(JsValue::String("0x10".into()))
        );
        // A batch-shaped answer is searched by id.
        assert_eq!(
            answer(1, &m, 200, br#"[{"jsonrpc":"2.0","id":1,"result":"0x"}]"#),
            Ok(JsValue::String("0x".into()))
        );
        assert_eq!(answer(1, &m, 503, b"unavailable"), Err(RpcError::Http(503)));
        assert_eq!(answer(1, &m, 200, b"<html>"), Err(RpcError::NotJson));
        assert_eq!(
            answer(1, &m, 200, br#"{"jsonrpc":"2.0","id":99,"result":"0x"}"#),
            Err(RpcError::MissingResponse)
        );
        // No result: ethers resolves `undefined`, which formatting refuses.
        assert_eq!(
            answer(1, &m, 200, br#"{"jsonrpc":"2.0","id":1}"#),
            Ok(JsValue::Null)
        );
    }

    #[test]
    fn call_errors_keep_revert_data_or_the_node_error() {
        let call = Method::Call {
            to: UR,
            data: vec![],
            block: "latest".into(),
        };
        let reverted = answer(
            1,
            &call,
            200,
            br#"{"id":1,"error":{"code":3,"message":"execution reverted","data":"0x12345678"}}"#,
        );
        assert!(matches!(
            reverted,
            Err(RpcError::CallException { data: Some(ref data), node: Some(_) }) if data == &[0x12, 0x34, 0x56, 0x78]
        ));
        let failed = answer(
            1,
            &call,
            200,
            br#"{"id":1,"error":{"code":-32000,"message":"header not found"}}"#,
        );
        let Err(RpcError::CallException {
            data: None,
            node: Some(node),
        }) = failed
        else {
            unreachable!("{failed:?}");
        };
        assert_eq!(node.code(), Some(-32000.0));
        assert_eq!(node.message(), "header not found");
        // Without "revert" in the message, hex data isn't revert data.
        let plain = answer(
            1,
            &call,
            200,
            br#"{"id":1,"error":{"code":-32000,"message":"oops","data":"0x12"}}"#,
        );
        assert!(matches!(
            plain,
            Err(RpcError::CallException { data: None, .. })
        ));
        // Nested and JSON-in-string data, as spelunkData finds them.
        let nested = answer(1, &call, 200, br#"{"id":1,"error":{"code":-32000,"message":"x","data":"{\"message\":\"reverted\",\"data\":\"0xaa\"}"}}"#);
        assert!(matches!(
            nested,
            Err(RpcError::CallException { data: Some(ref data), node: Some(_) }) if data == &[0xaa]
        ));
        // An error member that isn't an object is malformed.
        let malformed = answer(1, &call, 200, br#"{"id":1,"error":"oops"}"#);
        assert_eq!(malformed, Err(RpcError::MalformedError));
    }

    #[test]
    fn numbers_follow_javascript_bigint() {
        let n = |s: &str| get_number(&JsValue::String(s.into()));
        assert_eq!(n("0x1312cf8"), Some(19_999_992));
        assert_eq!(n(" 42 "), Some(42));
        assert_eq!(n("0X10"), Some(16));
        assert_eq!(n("-0x10"), None);
        assert_eq!(n("0x"), None);
        assert_eq!(n(""), None);
        assert_eq!(n("   "), Some(0));
        assert_eq!(n("9007199254740992"), None);
        assert_eq!(get_number(&JsValue::Number(1.5)), None);
    }

    #[test]
    fn checksums_are_checked_only_in_mixed_case() {
        assert!(is_address("0x52908400098527886E0F7030069857D2E4169EE7"));
        assert!(is_address("0x52908400098527886e0f7030069857d2e4169ee7"));
        assert!(is_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"));
        assert!(!is_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"));
    }
}
