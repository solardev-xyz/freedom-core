//! The Blockscout source (design 0005, Logs: Blockscout pairing): the
//! router's `requestLogIndex`. A range-capped xBZZ Transfer scan wider than
//! the RPC quorum can verify is answered by two independent providers that
//! agree: one RPC endpoint able to serve the span, then Blockscout's log
//! index, paged back from the newest; the newest blocks go to the quorum.

use std::cell::RefCell;
use std::rc::Rc;

use fc_json::index::{Index, KeyOrder, Kind};
use fc_naming::session::exec::{Either, race};

use super::config::{ms, number_text};
use super::ctx::{Ctx, Req, started};
use super::error::Thrown;
use super::exchange::{ResultText, exchange};
use super::io::{Answer, Delivered, Request, Transport};
use super::logs::{Keeper, LogRange};
use super::quorum::{QuorumOptions, request_quorum};
use super::read::{SourceOptions, SourceResult, with_member};
use super::trust::blockscout_trust;
use crate::blockscout::{
    BlockscoutError, LOG_INDEX_ABORT_COOLDOWN_MS, LOG_INDEX_DISAGREEMENT_COOLDOWN_MS,
    LOG_INDEX_PAIR_MALFORMED_COOLDOWN_MS, LOG_INDEX_TAIL_BLOCKS, MAX_PAGE_SIZE, MIN_COOLDOWN_MS,
    PageReply, ScanStep, Transfer, TransferScan, agreed_rpc_logs, log_index_filter, logs_agree,
    rpc_transfer_logs_well_formed,
};
use crate::text::safe_error_message;

fn unavailable(message: &str) -> Thrown {
    Thrown::unavailable(message)
}

/// A JavaScript `Error`'s message, shortened as the router quotes it.
fn safe(error: &Thrown) -> String {
    error.safe_message().to_string_lossy()
}

/// `requestLogIndex`.
pub(crate) async fn log_index(
    req: &Req,
    method: &str,
    params: &str,
    options: &SourceOptions<'_>,
) -> Result<SourceResult, Thrown> {
    let chain = Rc::clone(&req.chain);
    let chain_id = chain.chain_id;
    let filter = if method == "eth_getLogs" {
        log_index_filter(chain_id, params)
    } else {
        None
    };
    let (Some(range), Some(filter), Some(index)) =
        (options.log_range, filter, chain.blockscout.clone())
    else {
        return Err(unavailable(
            "Blockscout serves only range-capped xBZZ Transfer scans by sender or recipient",
        ));
    };
    let now = req.now();
    if req.ctx.state.borrow().logs.index_cool_until(chain_id) > now {
        return Err(unavailable(
            "Blockscout is left alone for a while after its last failure",
        ));
    }
    let m = chain.m;
    let endpoints = chain.urls();
    #[allow(clippy::cast_precision_loss)]
    if (endpoints.len() as f64) < m {
        return Err(unavailable(&format!(
            "RPC quorum needs {} endpoints",
            number_text(m)
        )));
    }
    let quorum_span = req
        .ctx
        .state
        .borrow()
        .logs
        .quorum_span(chain_id, &endpoints, m, now);
    #[allow(clippy::cast_precision_loss)]
    if quorum_span >= range.span as f64 {
        return Err(unavailable("the RPC quorum can verify this span itself"));
    }
    // `quorumSpan < 1`, a NaN included.
    if quorum_span.is_nan() || quorum_span < 1.0 {
        return Err(unavailable("no RPC quorum can verify the newest blocks"));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let tail = quorum_span.min(LOG_INDEX_TAIL_BLOCKS as f64) as u64;
    let pair_to = filter.to_block.saturating_sub(tail);
    let pair_span = (pair_to + 1).saturating_sub(filter.from_block);
    #[allow(clippy::cast_precision_loss)]
    let pair_urls: Vec<String> = {
        let state = req.ctx.state.borrow();
        endpoints
            .iter()
            .filter(|url| {
                state.logs.servable(chain_id, url, now) >= pair_span as f64
                    && state.logs.pair_cool_until(chain_id, url) <= now
            })
            .cloned()
            .collect()
    };
    if pair_urls.is_empty() {
        return Err(unavailable(
            "no RPC endpoint serves this span to compare Blockscout with",
        ));
    }
    let pair_params = with_member(params, "toBlock", &block_hex(pair_to), false)
        .ok_or_else(|| unavailable("the filter is not an object"))?;
    // One budget covers the whole source: the pair inside it less the
    // configured quorum timeout, held back for the newest blocks' quorum.
    let configured = chain.timeout;
    let budget = configured.max(
        options
            .quorum_timeout
            .filter(|q| *q != 0.0 && !q.is_nan())
            .unwrap_or(0.0),
    );
    let started_at = req.now();
    #[allow(clippy::cast_precision_loss)]
    let left = || budget - (req.now() - started_at) as f64;
    let remaining = || {
        let left = left() - configured;
        if left < 1000.0 {
            Err(unavailable("Blockscout pairing ran out of time"))
        } else {
            Ok(left)
        }
    };
    // The RPC first: Blockscout's rate limit is spent only on a span an RPC
    // has already answered.
    let pair = async {
        let mut last: Option<Thrown> = None;
        for url in &pair_urls {
            let timeout = remaining()?;
            let result = match exchange(req, url, method, &pair_params, timeout).await {
                Ok(result) => result,
                Err(error) => {
                    let now = req.now();
                    req.ctx
                        .state
                        .borrow_mut()
                        .logs
                        .note_failure(chain_id, url, pair_span, &error, &range, now);
                    last = Some(error);
                    continue;
                }
            };
            if !well_formed(&result) {
                let until = req.now() + LOG_INDEX_PAIR_MALFORMED_COOLDOWN_MS;
                req.ctx
                    .state
                    .borrow_mut()
                    .logs
                    .set_pair_cool_until(chain_id, url, until);
                // The reference names the endpoint's host, which the core
                // doesn't know.
                last = Some(Thrown::error(
                    "the paired endpoint answered the span with a malformed log entry",
                ));
                continue;
            }
            req.ctx
                .state
                .borrow_mut()
                .logs
                .note_answer(chain_id, url, pair_span);
            return Ok((url.clone(), result));
        }
        Err(last.unwrap_or_else(|| Thrown::error("no RPC endpoint was asked")))
    };
    let (rpc_url, rpc_result) = pair.await.map_err(|error| {
        if error.is_unavailable() {
            return error;
        }
        unavailable(&format!(
            "no RPC endpoint answered the span to compare Blockscout with: {}",
            safe(&error)
        ))
    })?;
    // Blockscout's pages.
    let timeout = remaining()?;
    let indexed = {
        // A caller that gives up while Blockscout is still reading leaves it
        // alone for a while.
        let mut guard = AbortCooling {
            ctx: Rc::clone(&req.ctx),
            chain_id,
            armed: true,
        };
        let read = read_index(req, &index, filter.clone(), pair_to, timeout).await;
        guard.armed = false;
        read
    };
    let indexed = match indexed {
        Ok(indexed) => indexed,
        Err(error) => {
            if error.cool_ms.is_finite() && error.cool_ms > 0.0 {
                let until = req.now() + ms(error.cool_ms);
                req.ctx
                    .state
                    .borrow_mut()
                    .logs
                    .set_index_cool_until(chain_id, until);
            }
            let message: Vec<u16> = error.message.encode_utf16().collect();
            return Err(unavailable(&format!(
                "Blockscout: {}",
                safe_error_message("BlockscoutError", &message).to_string_lossy()
            )));
        }
    };
    let rpc_text = rpc_result.as_ref().map_or("undefined", |r| r.json());
    let rpc_index = Index::new(rpc_text).ok();
    let agree = rpc_index
        .as_ref()
        .is_some_and(|index| logs_agree(&indexed, index.root()));
    if !agree {
        let until = req.now() + LOG_INDEX_DISAGREEMENT_COOLDOWN_MS;
        req.ctx
            .state
            .borrow_mut()
            .logs
            .set_index_cool_until(chain_id, until);
        let count = rpc_index
            .as_ref()
            .filter(|index| index.root().kind() == Kind::Array)
            .map_or_else(
                || "no".to_owned(),
                |index| index.root().children().count().to_string(),
            );
        return Err(unavailable(&format!(
            "Blockscout ({} logs) and the paired endpoint ({count} logs) disagree",
            indexed.len()
        )));
    }
    // The newest blocks: an ordinary range-capped scan through the quorum,
    // its rounds sharing what is left of the budget.
    let newest_params = with_member(params, "fromBlock", &block_hex(pair_to + 1), false)
        .ok_or_else(|| unavailable("the filter is not an object"))?;
    let keeper = RefCell::new(Keeper::new(range.ranker));
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ends_at = started_at + ms(budget);
    let newest = request_quorum(
        req,
        method,
        &newest_params,
        &QuorumOptions {
            include_trust: false,
            allow_direct_fallback: false,
            deadline: None,
            keeper: &keeper,
            quorum_timeout: Some(configured.max(left())),
            log_range: Some(LogRange {
                span: tail,
                ..range
            }),
            ends_at: Some(ends_at),
        },
    )
    .await
    .map_err(|error| {
        unavailable(&format!(
            "RPC quorum did not verify the newest {tail} blocks: {}",
            safe(&error)
        ))
    })?;
    let newest_text = newest.result.as_ref().map_or("undefined", |r| r.json());
    let newest_index = Index::new(newest_text).ok();
    let Some(newest_index) = newest_index.filter(|i| i.root().kind() == Kind::Array) else {
        return Err(unavailable(
            "RPC quorum answered the newest blocks without a log list",
        ));
    };
    if !rpc_transfer_logs_well_formed(newest_index.root()) {
        return Err(unavailable(&format!(
            "RPC quorum answered the newest {tail} blocks with a malformed log entry"
        )));
    }
    // Only what the pair compared is delivered; the quorum's entries were
    // compared whole by its members.
    let agreed = rpc_index
        .as_ref()
        .and_then(|index| agreed_rpc_logs(index.root()))
        .unwrap_or_else(|| "[]".to_owned());
    let mut items: Vec<String> = Vec::new();
    if let Ok(agreed) = Index::new(&agreed) {
        items.extend(
            agreed
                .root()
                .children()
                .map(|v| v.stringify(KeyOrder::Property)),
        );
    }
    items.extend(
        newest_index
            .root()
            .children()
            .map(|v| v.stringify(KeyOrder::Property)),
    );
    let json = format!("[{}]", items.join(","));
    Ok(SourceResult {
        result: super::exchange::owned(req, json)?,
        trust: options
            .include_trust
            .then(|| blockscout_trust(&index, &rpc_url)),
    })
}

fn block_hex(block: u64) -> String {
    format!("\"0x{block:x}\"")
}

fn well_formed(result: &ResultText) -> bool {
    result.as_ref().is_some_and(|text| {
        Index::new(text.json()).is_ok_and(|index| rpc_transfer_logs_well_formed(index.root()))
    })
}

/// Sets Blockscout's abort cooldown when dropped while armed: the request
/// ended (a cancel) while Blockscout was still reading.
struct AbortCooling {
    ctx: Rc<Ctx>,
    chain_id: u64,
    armed: bool,
}

impl Drop for AbortCooling {
    fn drop(&mut self) {
        if self.armed {
            let until = self.ctx.now() + LOG_INDEX_ABORT_COOLDOWN_MS;
            self.ctx
                .state
                .borrow_mut()
                .logs
                .set_index_cool_until(self.chain_id, until);
        }
    }
}

fn scan_error(message: String) -> BlockscoutError {
    BlockscoutError {
        message,
        cool_ms: MIN_COOLDOWN_MS,
    }
}

/// `fetchBlockscoutTransferLogs`: every page within one deadline.
async fn read_index(
    req: &Req,
    endpoint: &str,
    filter: crate::blockscout::LogIndexFilter,
    to_block: u64,
    timeout: f64,
) -> Result<Vec<Transfer>, BlockscoutError> {
    let mut scan = TransferScan::new(filter, to_block)?;
    let deadline = req.now() + ms(timeout);
    let expired = || scan_error(format!("no answer within {}ms", number_text(timeout)));
    loop {
        #[allow(clippy::cast_precision_loss)]
        let left = deadline as f64 - req.now() as f64;
        if left.is_nan() || left <= 0.0 {
            return Err(expired());
        }
        let timer = started(req.ctx.rt.sleep(ms(left)));
        let io = req.ctx.rt.request(Request::Blockscout {
            endpoint: endpoint.to_owned(),
            query: scan.query(),
            max_bytes: MAX_PAGE_SIZE,
            deadline_ms: ms(left),
        });
        let Delivered { answer, .. } = match race(io, timer).await {
            Either::Left(delivered) => delivered,
            Either::Right(()) => return Err(expired()),
        };
        let step = match answer {
            Answer::Blockscout {
                status,
                headers,
                body,
            } => {
                let header = |name: &str| {
                    headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(name))
                        .map(|(_, v)| v.as_str())
                };
                scan.on_page(PageReply {
                    status,
                    content_length: header("content-length"),
                    x_ratelimit_reset: header("x-ratelimit-reset"),
                    retry_after: header("retry-after"),
                    body,
                })?
            }
            Answer::Failed(Transport::Timeout) => return Err(expired()),
            Answer::Failed(Transport::Refused) => {
                return Err(scan_error("redirected to a refused location".into()));
            }
            Answer::Failed(Transport::TooLarge) => {
                return Err(scan_error("answer over 8 MiB".into()));
            }
            _ => return Err(scan_error("unreachable".into())),
        };
        match step {
            ScanStep::Next => {}
            ScanStep::Done(transfers) => return Ok(transfers),
        }
    }
}
