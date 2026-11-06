//! Read methods and the sources that serve them (design 0005, Methods and
//! sources): the router's `READ_METHODS`, `SINGLE_NODE_METHODS`,
//! `SOURCE_CAPABILITIES` and the order a request tries its sources in.

use fc_json::index::{Index, Kind};

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

/// The read methods Colibri never proves (main's #1046): Colibri 3.0.3
/// answers them from one of its default public RPC hosts, as a success,
/// even under `Strategy.VerifiedOnly` (`not_verifieable_yet_methods` in
/// `eth_verify.c`, `rpc_handle_unproofable`). So Colibri doesn't serve
/// them, and the next source answers, labelled as itself.
pub const COLIBRI_UNPROVEN_METHODS: [&str; 2] = ["eth_gasPrice", "eth_feeHistory"];

/// Where each read method Colibri serves takes its block parameter, as
/// Colibri 3.0.3 reads it (`eth_block_tag_index` in `eth_verify.c`).
/// Methods not listed take none.
pub const COLIBRI_BLOCK_PARAM: [(&str, usize); 7] = [
    ("eth_getBalance", 1),
    ("eth_getCode", 1),
    ("eth_getTransactionCount", 1),
    ("eth_call", 1),
    ("eth_estimateGas", 1),
    ("eth_getStorageAt", 2),
    ("eth_getBlockByNumber", 0),
];

/// The block tags Colibri can't prove a read at: a pending block has no
/// beacon block, and the earliest predates the beacon chain. It answers
/// such a read from a public RPC host, unproven (main's #1046).
pub const COLIBRI_UNPROVABLE_TAGS: [&str; 2] = ["pending", "earliest"];

/// `colibriUnprovableTag(method, params)`: the tag of [`COLIBRI_UNPROVABLE_TAGS`]
/// that `params` (JSON text) holds where `method` takes its block
/// parameter ([`COLIBRI_BLOCK_PARAM`]), compared exactly, as Colibri's
/// `eth_json_is_unproofable_tag` does; `None` otherwise, and for params
/// that aren't an array (`Array.isArray`) or don't parse.
pub fn colibri_unprovable_tag(method: &str, params: &str) -> Option<&'static str> {
    let (_, position) = COLIBRI_BLOCK_PARAM
        .iter()
        .find(|(name, _)| *name == method)?;
    let index = Index::new(params).ok()?;
    let root = index.root();
    if root.kind() != Kind::Array {
        return None;
    }
    let tag = root.children().nth(*position)?;
    if tag.kind() != Kind::String {
        return None;
    }
    let units: Vec<u16> = tag.units().collect();
    COLIBRI_UNPROVABLE_TAGS
        .iter()
        .copied()
        .find(|name| name.encode_utf16().eq(units.iter().copied()))
}

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

    // Main's #1046: what Colibri would answer unproven.
    #[test]
    fn colibri_unproven() {
        for method in ["eth_gasPrice", "eth_feeHistory"] {
            assert!(!source_serves_method("colibri", method), "{method}");
            for source in ["myotis", "quorum", "direct"] {
                assert!(source_serves_method(source, method), "{source} {method}");
            }
        }
        assert!(source_serves_method("colibri", "eth_maxPriorityFeePerGas"));
        let order = source_order(&["colibri", "direct"], &[], &[], "eth_gasPrice", false);
        assert_eq!(order.order, ["direct"]);
        assert_eq!(order.dropped, ["colibri"]);

        let tag = colibri_unprovable_tag;
        let call = r#"{"to":"0xabc"}"#;
        for (method, at) in COLIBRI_BLOCK_PARAM {
            for want in COLIBRI_UNPROVABLE_TAGS {
                // The tag in the method's block parameter, and nowhere else.
                let mut params: Vec<String> = vec![r#""0xabc""#.into(); at + 1];
                if matches!(method, "eth_call" | "eth_estimateGas") {
                    params[0] = call.into();
                }
                params[at] = format!("\"{want}\"");
                let text = format!("[{}]", params.join(","));
                assert_eq!(tag(method, &text), Some(want), "{method} {text}");
                params[at] = r#""latest""#.into();
                params.push(format!("\"{want}\""));
                let text = format!("[{}]", params.join(","));
                assert_eq!(tag(method, &text), None, "{method} {text}");
            }
            for other in [
                r#""latest""#,
                r#""safe""#,
                r#""finalized""#,
                r#""0x10d4f00""#,
            ] {
                let mut params: Vec<String> = vec![r#""0xabc""#.into(); at + 1];
                params[at] = other.into();
                assert_eq!(tag(method, &format!("[{}]", params.join(","))), None);
            }
        }
        // Exact strings only, in an array.
        assert_eq!(tag("eth_getBalance", r#"["0xabc","PENDING"]"#), None);
        assert_eq!(tag("eth_getBalance", r#"["0xabc","pending "]"#), None);
        assert_eq!(tag("eth_getBalance", r#"["0xabc",["pending"]]"#), None);
        assert_eq!(tag("eth_getBalance", r#"{"1":"pending"}"#), None);
        assert_eq!(tag("eth_getBalance", r#""xpending""#), None);
        assert_eq!(tag("eth_getBalance", "not json"), None);
        assert_eq!(
            tag("eth_getBalance", r#"["0xabc","pend\u0069ng"]"#),
            Some("pending")
        );
        // Methods that take no block parameter Colibri reads.
        for method in [
            "eth_getBlockByHash",
            "eth_getTransactionReceipt",
            "eth_blockNumber",
            "eth_getLogs",
        ] {
            assert_eq!(
                tag(method, r#"["pending","pending","pending"]"#),
                None,
                "{method}"
            );
        }
    }
}
