//! The Ethereum rows of the reference's `page-methods.js`: each method main
//! routes to the dispatcher, with its class (design 0011, "Method
//! classes"). Main keeps the table's deadlines and its own refusals of a
//! method it doesn't list; the core answers the same for one it is sent.

/// A method's class (design 0011).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Nothing held under the key is read or changed.
    PermissionFree,
    /// It reads or changes what is held under the key: for a DNS name over
    /// IPNS, the name is resolved again first (APR-5f).
    NameRevalidated,
    /// It never runs, for any caller.
    Refused,
}

/// One row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Method {
    pub name: &'static str,
    pub class: Class,
    /// A refused method's error: its code and message.
    pub refusal: Option<(i64, &'static str)>,
}

/// The 23 read-only methods (`ETHEREUM_RPC_READS`): each is one read
/// through the core's chain machine.
pub const RPC_READS: &[&str] = &[
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
    "eth_getFilterChanges",
    "eth_getFilterLogs",
    "eth_newFilter",
    "eth_newBlockFilter",
    "eth_newPendingTransactionFilter",
    "eth_uninstallFilter",
    "web3_clientVersion",
    "web3_sha3",
];

const fn row(name: &'static str, class: Class) -> Method {
    Method {
        name,
        class,
        refusal: None,
    }
}

use Class::{NameRevalidated as NAMED, PermissionFree as FREE};

/// Every Ethereum row, in the reference's order.
pub const METHODS: &[Method] = &[
    row("eth_chainId", FREE),
    row("net_version", FREE),
    row("eth_blockNumber", FREE),
    row("eth_getBalance", FREE),
    row("eth_getCode", FREE),
    row("eth_getStorageAt", FREE),
    row("eth_getTransactionCount", FREE),
    row("eth_getBlockByNumber", FREE),
    row("eth_getBlockByHash", FREE),
    row("eth_getTransactionByHash", FREE),
    row("eth_getTransactionReceipt", FREE),
    row("eth_call", FREE),
    row("eth_estimateGas", FREE),
    row("eth_gasPrice", FREE),
    row("eth_feeHistory", FREE),
    row("eth_maxPriorityFeePerGas", FREE),
    row("eth_getLogs", FREE),
    row("eth_getFilterChanges", FREE),
    row("eth_getFilterLogs", FREE),
    row("eth_newFilter", FREE),
    row("eth_newBlockFilter", FREE),
    row("eth_newPendingTransactionFilter", FREE),
    row("eth_uninstallFilter", FREE),
    row("web3_clientVersion", FREE),
    row("web3_sha3", FREE),
    row("eth_accounts", NAMED),
    row("eth_requestAccounts", NAMED),
    row("wallet_switchEthereumChain", NAMED),
    row("eth_sendTransaction", NAMED),
    row("personal_sign", NAMED),
    row("eth_signTypedData_v4", NAMED),
    Method {
        name: "eth_sign",
        class: Class::Refused,
        refusal: Some((4200, "eth_sign is deprecated for security reasons")),
    },
];

/// The row for `name`, if main's table lists it.
pub fn method(name: &str) -> Option<&'static Method> {
    METHODS.iter().find(|m| m.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rpc_read_is_a_permission_free_row() {
        for name in RPC_READS {
            assert_eq!(
                method(name).map(|m| m.class),
                Some(Class::PermissionFree),
                "{name}"
            );
        }
        assert_eq!(METHODS.len(), RPC_READS.len() + 9);
        assert!(method("eth_foo").is_none());
    }
}
