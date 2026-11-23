//! Read methods and the sources that serve them (design 0005, Methods and
//! sources): the router's `READ_METHODS`, `SINGLE_NODE_METHODS`,
//! `SOURCE_CAPABILITIES` and the order a request tries its sources in.

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

pub use fc_colibri::{
    COLIBRI_BLOCK_PARAM, COLIBRI_LATEST_ONLY, COLIBRI_NOT_A_STRING, COLIBRI_SERVED_METHODS,
    COLIBRI_UNPROVEN_METHODS, LATEST_APPENDED, colibri_latest_appended,
};

/// What Colibri is asked for a read (`colibriRequestParams`): `fc-colibri`'s
/// rule, which the Colibri service applies too, with the refusal as a
/// [`JsString`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColibriParams {
    /// The params as sent.
    AsSent,
    /// The params with `"latest"` appended ([`colibri_latest_appended`]):
    /// an account read without its block parameter.
    LatestAppended,
    /// Refused before Colibri is asked: the text that completes `Colibri
    /// cannot prove <method> `.
    Refused(JsString),
}

/// `colibriRequestParams(method, params)`: whether Colibri is asked this
/// read, and with what (`params` is JSON text). The rule is
/// [`fc_colibri::colibri_request_params`].
pub fn colibri_request_params(method: &str, params: &str) -> ColibriParams {
    match fc_colibri::colibri_request_params(method, params) {
        fc_colibri::ColibriParams::AsSent => ColibriParams::AsSent,
        fc_colibri::ColibriParams::LatestAppended => ColibriParams::LatestAppended,
        fc_colibri::ColibriParams::Refused(units) => {
            ColibriParams::Refused(JsString::from_units(units))
        }
    }
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

        // The rule itself is fc-colibri's, with #279's cases there; the
        // wrapper keeps its answers, the refusal's text included.
        let ask = colibri_request_params;
        let refused = |text: &str| ColibriParams::Refused(JsString::from(text));
        assert_eq!(
            ask("eth_getBalance", r#"["0xabc","latest"]"#),
            ColibriParams::AsSent
        );
        assert_eq!(
            ask("eth_getBalance", r#"["0xabc"]"#),
            ColibriParams::LatestAppended
        );
        assert_eq!(
            ask("eth_getBalance", r#"["0xabc","safe"]"#),
            refused(r#"at block "safe""#)
        );
        assert_eq!(
            ask("eth_getBlockByNumber", r#"["\ud800",false]"#),
            ColibriParams::Refused(JsString::from_units(
                "at block \""
                    .encode_utf16()
                    .chain([0xd800, u16::from(b'"')])
                    .collect()
            ))
        );
        // What the router sends Colibri is what the service serves.
        let routed: Vec<&str> = READ_METHODS
            .iter()
            .copied()
            .filter(|method| source_serves_method("colibri", method))
            .collect();
        assert_eq!(routed, COLIBRI_SERVED_METHODS);
    }
}
