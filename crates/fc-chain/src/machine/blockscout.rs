//! The Blockscout source (design 0005, Logs: Blockscout pairing): the
//! router's `requestLogIndex`.

use super::ctx::Req;
use super::error::Thrown;
use super::read::{SourceOptions, SourceResult};
use crate::blockscout::log_index_filter;

/// `requestLogIndex`.
pub(crate) async fn log_index(
    req: &Req,
    method: &str,
    params: &str,
    options: &SourceOptions<'_>,
) -> Result<SourceResult, Thrown> {
    let filter = if method == "eth_getLogs" {
        log_index_filter(req.chain.chain_id, params)
    } else {
        None
    };
    if options.log_range.is_none() || filter.is_none() {
        return Err(Thrown::unavailable(
            "Blockscout serves only range-capped xBZZ Transfer scans by sender or recipient",
        ));
    }
    Err(Thrown::unavailable(
        "Blockscout pairing is not implemented yet",
    ))
}
