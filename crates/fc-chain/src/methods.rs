//! Read methods and the sources that serve them (design 0005, Methods and
//! sources): the router's `READ_METHODS`, `SINGLE_NODE_METHODS`,
//! `SOURCE_CAPABILITIES` and the order a request tries its sources in.

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
        "colibri" => !SINGLE_NODE_METHODS.contains(&method) && method != "eth_getLogs",
        // Every read method but eth_getLogs.
        BLOCKSCOUT => method == "eth_getLogs" || !is_read_method(method),
        _ => true,
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
}
