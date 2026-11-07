//! Read methods and the sources that serve them (design 0005, Methods and
//! sources): the router's `READ_METHODS`, `SINGLE_NODE_METHODS`,
//! `SOURCE_CAPABILITIES` and the order a request tries its sources in.

use fc_json::index::{Index, KeyOrder, Kind};

use crate::js::JsString;

/// `READ_METHODS`, in the reference's insertion order (the `web3_*` two are
/// added last).
pub const READ_METHODS: [&str; 17] = [
    "eth_blockNumber",
    "eth_getBalance",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_getTransactionCount",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_call",
    "eth_estimateGas",
    "eth_gasPrice",
    "eth_feeHistory",
    "eth_maxPriorityFeePerGas",
    "eth_getLogs",
    "web3_clientVersion",
    "web3_sha3",
];

/// Methods only one node can answer (stateful filters, and `web3_*`, which
/// describe the node): Direct alone serves them.
pub const SINGLE_NODE_METHODS: [&str; 8] = [
    "eth_getFilterChanges",
    "eth_getFilterLogs",
    "eth_newFilter",
    "eth_newBlockFilter",
    "eth_newPendingTransactionFilter",
    "eth_uninstallFilter",
    "web3_clientVersion",
    "web3_sha3",
];

/// `isReadMethod`: exact names only.
pub fn is_read_method(method: &str) -> bool {
    READ_METHODS.contains(&method) || SINGLE_NODE_METHODS.contains(&method)
}

/// The opt-in source: in no read order, joined before the quorum when the
/// caller names it and the request is one it serves.
pub const BLOCKSCOUT: &str = "blockscout";

/// Whether `source` serves `method` at all (`sourceServesMethod`). A source
/// the router doesn't know serves everything; it is refused when tried.
pub fn source_serves_method(source: &str, method: &str) -> bool {
    match source {
        "myotis" | "quorum" => !SINGLE_NODE_METHODS.contains(&method),
        "colibri" => {
            !SINGLE_NODE_METHODS.contains(&method)
                && method != "eth_getLogs"
                && !COLIBRI_UNPROVEN_METHODS.contains(&method)
        }
        // Every read method but eth_getLogs.
        BLOCKSCOUT => method == "eth_getLogs" || !is_read_method(method),
        _ => true,
    }
}

/// The read methods Colibri never serves (main's #1046). Colibri 3.0.3
/// answers `eth_gasPrice` and `eth_feeHistory` from one of its default
/// public RPC hosts, as a success, even under `Strategy.VerifiedOnly`
/// (`not_verifieable_yet_methods` in `eth_verify.c`,
/// `rpc_handle_unproofable`). In privacy mode (`privacy_mode: 'basic'`,
/// which the browser always sets) it runs `eth_call` and `eth_estimateGas`
/// locally (`METHOD_LOCAL`) on contract code from one of those hosts, never
/// checked against the proven code hash (`call_ctx.c`'s
/// `call_account_get_code`, `eth_account.c`), and a call that reads no
/// storage and no block context fetches no proof at all (`verify_call.c`'s
/// `verify_call_result_and_finish`). So Colibri doesn't serve them, and the
/// next source answers, labelled as itself.
pub const COLIBRI_UNPROVEN_METHODS: [&str; 4] = [
    "eth_gasPrice",
    "eth_feeHistory",
    "eth_call",
    "eth_estimateGas",
];

/// Where each read method Colibri serves takes its block parameter, as
/// Colibri 3.0.3 reads it (`eth_block_tag_index` in `eth_verify.c`).
/// Methods not listed take none.
pub const COLIBRI_BLOCK_PARAM: [(&str, usize); 5] = [
    ("eth_getBalance", 1),
    ("eth_getCode", 1),
    ("eth_getTransactionCount", 1),
    ("eth_getStorageAt", 2),
    ("eth_getBlockByNumber", 0),
];

/// The account reads, which Colibri 3.0.3 ties to the requested block only
/// at `latest` (main's #1060). `verify_account_proof.c` proves the account
/// against the header in the proof and compares no requested number or
/// hash with that header. No tag but `latest` is gated (`eth_verify.h`), so
/// `safe`, `finalized` or `justified` would pass unchecked. At `latest` each
/// proof must be at most a minute old (`eth_check_latest_freshness`). The
/// verifier reads the block as the account read's last param
/// (`account_block_tag`) and gates it only when that is the string
/// `latest`, so the block must be last.
pub const COLIBRI_LATEST_ONLY: [&str; 4] = [
    "eth_getBalance",
    "eth_getCode",
    "eth_getTransactionCount",
    "eth_getStorageAt",
];

/// How Colibri's refusal names a block that isn't a string
/// ([`colibri_request_params`]).
pub const COLIBRI_NOT_A_STRING: &str = "at a block that isn't a string";

/// What Colibri is asked for a read (`colibriRequestParams`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColibriParams {
    /// The params as sent.
    AsSent,
    /// The params with `"latest"` appended ([`colibri_latest_appended`]):
    /// an account read without its block parameter. Calls never get here,
    /// as Colibri serves none (main's #1046).
    LatestAppended,
    /// Refused before Colibri is asked: the text that completes `Colibri
    /// cannot prove <method> `.
    Refused(JsString),
}

/// `colibriRequestParams(method, params)`: whether Colibri is asked this
/// read, and with what (`params` is JSON text). Only a read whose answer
/// Colibri ties to the requested block goes to it:
/// - an account read ([`COLIBRI_LATEST_ONLY`]) at `latest`. Without its
///   block parameter it is read at `latest` by every source, and Colibri is
///   asked with `latest` appended: left out, Colibri would apply no
///   freshness gate. Any other block, params too short to append it in its
///   place, params after its block, and params that aren't an array, are
///   refused;
/// - `eth_getBlockByNumber` at `latest`, a block number ([`is_block_number`])
///   or a 32-byte hash, which `verify_block.c`'s `c4_eth_matches_blocknumber`
///   compares with the proven block or holds to the freshness gate, or with
///   no block at all (`null` params included). Every other string is
///   refused: `pending` and `earliest` Colibri answers from a public RPC
///   host; `safe`, `finalized` and any other string its validator lets
///   through (`check_hex` also passes `0X10` or `1x10`) it matches with any
///   proven block, as it compares only a string that starts with `0x`; and
///   `justified` it names but doesn't gate (`eth_verify.h`). Params that
///   aren't an array (Colibri reads them as `[params]`) are refused too;
/// - `eth_getBlockByHash` at a 32-byte hash (`0x` and 64 hex digits), the
///   only string `c4_eth_matches_blocknumber` compares as a hash.
///
/// A block that isn't a string (an EIP-1898 object, `null`, a number, a
/// boolean, an array) is refused for each of them
/// ([`COLIBRI_NOT_A_STRING`]): no verifier compares one. Every other method
/// is asked as sent, as are params that don't parse.
pub fn colibri_request_params(method: &str, params: &str) -> ColibriParams {
    let Some(position) = COLIBRI_BLOCK_PARAM
        .iter()
        .find(|(name, _)| *name == method)
        .map(|(_, at)| *at)
        .or_else(|| (method == "eth_getBlockByHash").then_some(0))
    else {
        return ColibriParams::AsSent;
    };
    let Ok(index) = Index::new(params) else {
        return ColibriParams::AsSent;
    };
    let root = index.root();
    let refused = |text: &str| ColibriParams::Refused(JsString::from(text));
    let at_block = |units: &[u16]| {
        let mut text = JsString::from("at block \"");
        text.push_units(units);
        text.push_str("\"");
        ColibriParams::Refused(text)
    };
    let latest_only = COLIBRI_LATEST_ONLY.contains(&method);
    let by_hash = method == "eth_getBlockByHash";
    if root.kind() != Kind::Array {
        return if by_hash {
            refused("without a block hash")
        } else if latest_only || root.kind() != Kind::Null {
            // Colibri reads params that aren't an array as `[params]`, and
            // `null` as `[]`.
            refused("with params that aren't an array")
        } else {
            ColibriParams::AsSent
        };
    }
    let length = root.children().count();
    if latest_only {
        if length == position {
            return ColibriParams::LatestAppended;
        }
        if length < position || length > position + 1 {
            return refused(format!("with params of length {length}").as_str());
        }
    } else if length <= position {
        return if by_hash {
            refused("without a block hash")
        } else {
            ColibriParams::AsSent
        };
    }
    let Some(block) = root.children().nth(position) else {
        return ColibriParams::AsSent;
    };
    if block.kind() != Kind::String {
        return refused(COLIBRI_NOT_A_STRING);
    }
    let units: Vec<u16> = block.units().collect();
    let is = |tag: &str| tag.encode_utf16().eq(units.iter().copied());
    let served = if latest_only {
        is("latest")
    } else if by_hash {
        is_block_hash(&units)
    } else {
        is("latest") || is_block_number(&units) || is_block_hash(&units)
    };
    if served {
        ColibriParams::AsSent
    } else {
        at_block(&units)
    }
}

/// `/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,15})$/`: `0x` and at most 16 hex
/// digits without a leading zero. Colibri's validator refuses a leading
/// zero, and it compares the number as 64 bits (`json_as_uint64`).
fn is_block_number(units: &[u16]) -> bool {
    let Some(digits) = units.strip_prefix(&[u16::from(b'0'), u16::from(b'x')]) else {
        return false;
    };
    let hex = |unit: &u16| u8::try_from(*unit).is_ok_and(|byte| byte.is_ascii_hexdigit());
    match digits {
        [only] => hex(only),
        [first, ..] => *first != u16::from(b'0') && digits.len() <= 16 && digits.iter().all(hex),
        [] => false,
    }
}

/// `/^0x[0-9a-fA-F]{64}$/`.
fn is_block_hash(units: &[u16]) -> bool {
    units.len() == 66
        && units[0] == u16::from(b'0')
        && units[1] == u16::from(b'x')
        && units[2..]
            .iter()
            .all(|&unit| u8::try_from(unit).is_ok_and(|byte| byte.is_ascii_hexdigit()))
}

/// `[...params, 'latest']` as `JSON.stringify` writes it, for params that
/// are an array (JSON text); `None` otherwise.
pub fn colibri_latest_appended(params: &str) -> Option<String> {
    let index = Index::new(params).ok()?;
    let root = index.root();
    if root.kind() != Kind::Array {
        return None;
    }
    let mut out = String::with_capacity(params.len() + LATEST_APPENDED.len());
    out.push('[');
    for item in root.children() {
        item.write(KeyOrder::Property, &mut out);
        out.push(',');
    }
    out.push_str("\"latest\"]");
    Some(out)
}

/// What [`colibri_latest_appended`] adds to the params' length, at most:
/// `,"latest"`.
pub const LATEST_APPENDED: &str = ",\"latest\"";

/// The sources of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceOrder<'a> {
    /// The read order with the opt-in sources inserted before each
    /// `quorum`.
    pub configured: Vec<&'a str>,
    /// What the request tries, in order.
    pub order: Vec<&'a str>,
    /// What it leaves out, in the configured order: the caller's exclusions
    /// and the sources that don't serve the method.
    pub dropped: Vec<&'a str>,
}

/// The order `request()` builds:
/// - each source the caller includes, once, if it is opt-in and not already
///   in the read order, and (for Blockscout) `blockscout_eligible`: an
///   `eth_getLogs` xBZZ Transfer scan over a numeric range by the Ant
///   profile;
/// - those inserted before every `quorum` of the read order;
/// - then the caller's exclusions and the sources that don't serve the
///   method are dropped, duplicates included.
pub fn source_order<'a>(
    read_order: &[&'a str],
    include_sources: &[&'a str],
    exclude_sources: &[&str],
    method: &str,
    blockscout_eligible: bool,
) -> SourceOrder<'a> {
    let mut opt_in: Vec<&'a str> = Vec::new();
    for &source in include_sources {
        if source == BLOCKSCOUT
            && blockscout_eligible
            && !read_order.contains(&source)
            && !opt_in.contains(&source)
        {
            opt_in.push(source);
        }
    }
    let mut configured = Vec::with_capacity(read_order.len() + opt_in.len());
    for &source in read_order {
        if source == "quorum" {
            configured.extend_from_slice(&opt_in);
        }
        configured.push(source);
    }
    let excluded =
        |source: &str| exclude_sources.contains(&source) || !source_serves_method(source, method);
    let (dropped, order) = configured
        .iter()
        .copied()
        .partition(|source| excluded(source));
    SourceOrder {
        configured,
        order,
        dropped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders() {
        let order = source_order(
            &["myotis", "quorum", "direct"],
            &[BLOCKSCOUT, "direct", BLOCKSCOUT],
            &["direct"],
            "eth_getLogs",
            true,
        );
        assert_eq!(order.configured, ["myotis", BLOCKSCOUT, "quorum", "direct"]);
        assert_eq!(order.order, ["myotis", BLOCKSCOUT, "quorum"]);
        assert_eq!(order.dropped, ["direct"]);
        let order = source_order(&["colibri"], &[BLOCKSCOUT], &[], "eth_getLogs", false);
        assert!(order.order.is_empty());
        assert_eq!(order.dropped, ["colibri"]);
        assert!(source_serves_method("foo", "web3_sha3"));
        assert!(!is_read_method("eth_sendRawTransaction"));
    }

    // Main's #1046: what Colibri would answer unproven, or run on code it
    // doesn't check.
    #[test]
    fn colibri_unproven() {
        for method in COLIBRI_UNPROVEN_METHODS {
            assert!(!source_serves_method("colibri", method), "{method}");
            for source in ["myotis", "quorum", "direct"] {
                assert!(source_serves_method(source, method), "{source} {method}");
            }
        }
        assert_eq!(
            COLIBRI_UNPROVEN_METHODS,
            [
                "eth_gasPrice",
                "eth_feeHistory",
                "eth_call",
                "eth_estimateGas"
            ]
        );
        assert!(source_serves_method("colibri", "eth_maxPriorityFeePerGas"));
        for method in ["eth_gasPrice", "eth_call", "eth_estimateGas"] {
            let order = source_order(&["colibri", "direct"], &[], &[], method, false);
            assert_eq!(order.order, ["direct"], "{method}");
            assert_eq!(order.dropped, ["colibri"], "{method}");
        }

        let ask = colibri_request_params;
        let refused = |text: &str| ColibriParams::Refused(JsString::from(text));
        let not_a_string = refused(COLIBRI_NOT_A_STRING);
        let hash = format!("\"0x{}\"", "22".repeat(32));
        let sixteen = format!("\"0x1{}\"", "0".repeat(15));
        let seventeen = format!("\"0x1{}\"", "0".repeat(16));
        let upper_x_hash = format!("\"0X{}\"", "22".repeat(32));
        // A method's params with `value` at its block parameter.
        let with = |at: usize, value: &str| {
            let mut params: Vec<String> = vec![r#""0xabc""#.into(); at + 1];
            params[at] = value.into();
            params
        };
        let text = |params: &[String]| format!("[{}]", params.join(","));
        let at_block = |value: &str| refused(format!("at block {value}").as_str());
        for (method, at) in COLIBRI_BLOCK_PARAM {
            let latest_only = COLIBRI_LATEST_ONLY.contains(&method);
            assert_eq!(latest_only, method != "eth_getBlockByNumber", "{method}");
            // Each string form, and whether eth_getBlockByNumber is Colibri's
            // at it; an account read is only at `latest`.
            for (value, by_number) in [
                (r#""0x10d4f00""#, true),
                (r#""0x10D4F00""#, true),
                (sixteen.as_str(), true),
                (r#""0x0""#, true),
                (hash.as_str(), true),
                (r#""latest""#, true),
                (r#""safe""#, false),
                (r#""finalized""#, false),
                (r#""justified""#, false),
                (r#""pending""#, false),
                (r#""earliest""#, false),
                (r#""0X10d4f00""#, false),
                (r#""1x10d4f00""#, false),
                (upper_x_hash.as_str(), false),
                (r#""0x010d4f00""#, false),
                (seventeen.as_str(), false),
                (r#""0x""#, false),
                (r#""0x10g""#, false),
            ] {
                let served = if latest_only {
                    value == r#""latest""#
                } else {
                    by_number
                };
                let params = with(at, value);
                let expected = if served {
                    ColibriParams::AsSent
                } else {
                    at_block(value)
                };
                assert_eq!(ask(method, &text(&params)), expected, "{method} {value}");
            }
            // A tag one place off is not the block: an account read with
            // params after its block is refused, a block read is Colibri's.
            let mut params = with(at, r#""latest""#);
            params.push(r#""pending""#.into());
            let expected = if latest_only {
                refused(format!("with params of length {}", at + 2).as_str())
            } else {
                ColibriParams::AsSent
            };
            assert_eq!(ask(method, &text(&params)), expected, "{method} {params:?}");
            // Anything there that isn't a string: EIP-1898's objects first.
            for other in [
                r#"{"blockHash":"0x1111111111111111111111111111111111111111111111111111111111111111","requireCanonical":true}"#,
                r#"{"blockNumber":"0x10d4f00"}"#,
                "null",
                "16",
                "true",
                r#"["latest"]"#,
            ] {
                let params = with(at, other);
                assert_eq!(
                    ask(method, &text(&params)),
                    not_a_string,
                    "{method} {other}"
                );
            }
            // Without the block parameter: `latest` appended for an account
            // read, as sent for a block.
            let mut params = with(at, r#""latest""#);
            params.truncate(at);
            let expected = if latest_only {
                ColibriParams::LatestAppended
            } else {
                ColibriParams::AsSent
            };
            assert_eq!(ask(method, &text(&params)), expected, "{method} {params:?}");
            // Shorter still: nowhere to append it.
            if at > 0 {
                params.truncate(at - 1);
                assert_eq!(
                    ask(method, &text(&params)),
                    refused(format!("with params of length {}", at - 1).as_str()),
                    "{method} {params:?}"
                );
            }
        }
        // The calls have no block rule: Colibri serves neither
        // (`source_serves_method`), so nothing here asks it.
        for method in ["eth_call", "eth_estimateGas"] {
            assert!(!COLIBRI_BLOCK_PARAM.iter().any(|(name, _)| *name == method));
            assert!(!COLIBRI_LATEST_ONLY.contains(&method));
        }
        // Exact strings only, in an array.
        assert_eq!(
            ask("eth_getBalance", r#"["0xabc","LATEST"]"#),
            at_block(r#""LATEST""#)
        );
        assert_eq!(
            ask("eth_getBalance", r#"["0xabc","latest "]"#),
            at_block(r#""latest ""#)
        );
        assert_eq!(
            ask("eth_getBalance", r#"["0xabc","lat\u0065st"]"#),
            ColibriParams::AsSent
        );
        assert_eq!(
            ask("eth_getBlockByNumber", r#"["pend\u0069ng",false]"#),
            at_block(r#""pending""#)
        );
        assert_eq!(
            ask("eth_getBlockByNumber", r#"["PENDING",false]"#),
            at_block(r#""PENDING""#)
        );
        assert_eq!(
            ask("eth_getBlockByNumber", r#"["LATEST",false]"#),
            at_block(r#""LATEST""#)
        );
        assert_eq!(
            ask("eth_getBlockByNumber", r#"["0x10d4f00 ",false]"#),
            at_block(r#""0x10d4f00 ""#)
        );
        for params in [r#"{"1":"latest"}"#, r#""safe""#, "null"] {
            assert_eq!(
                ask("eth_getBalance", params),
                refused("with params that aren't an array"),
                "{params}"
            );
            // Null is `[]` to Colibri: `latest`.
            let expected = if params == "null" {
                ColibriParams::AsSent
            } else {
                refused("with params that aren't an array")
            };
            assert_eq!(ask("eth_getBlockByNumber", params), expected, "{params}");
        }
        assert_eq!(ask("eth_getBalance", "not json"), ColibriParams::AsSent);
        // eth_getBlockByHash: a 32-byte hash only.
        let by_hash = |first: &str| ask("eth_getBlockByHash", &format!("[{first},false]"));
        assert_eq!(by_hash(&hash), ColibriParams::AsSent);
        let upper = format!("\"0x{}\"", "AB".repeat(32));
        assert_eq!(by_hash(&upper), ColibriParams::AsSent);
        for other in [
            format!("\"0x{}\"", "22".repeat(31)),
            format!("\"0x{}g\"", "2".repeat(63)),
            format!("\"0X{}\"", "22".repeat(32)),
            r#""0x10d4f00""#.to_owned(),
            r#""latest""#.to_owned(),
            r#""safe""#.to_owned(),
            r#""finalized""#.to_owned(),
            r#""justified""#.to_owned(),
        ] {
            assert_eq!(by_hash(&other), at_block(&other), "{other}");
        }
        assert_eq!(by_hash(r#"{"blockHash":"0x1"}"#), not_a_string);
        for params in ["[]", "{}", "null"] {
            assert_eq!(
                ask("eth_getBlockByHash", params),
                refused("without a block hash"),
                "{params}"
            );
        }
        // Methods that take no block parameter Colibri reads.
        for method in [
            "eth_getTransactionReceipt",
            "eth_blockNumber",
            "eth_getLogs",
        ] {
            assert_eq!(
                ask(method, r#"["pending","pending","pending"]"#),
                ColibriParams::AsSent,
                "{method}"
            );
        }
        // The params Colibri is then asked with.
        assert_eq!(
            colibri_latest_appended(r#"["0xabc"]"#).as_deref(),
            Some(r#"["0xabc","latest"]"#)
        );
        assert_eq!(
            colibri_latest_appended("[]").as_deref(),
            Some(r#"["latest"]"#)
        );
        assert_eq!(
            colibri_latest_appended(r#"[{"to":"0xabc","data":"0x1"}]"#).as_deref(),
            Some(r#"[{"to":"0xabc","data":"0x1"},"latest"]"#)
        );
        assert_eq!(colibri_latest_appended("{}"), None);
    }
}
