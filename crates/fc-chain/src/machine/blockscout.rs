//! The Blockscout source (design 0005, Logs: Blockscout pairing): the
//! router's `requestLogIndex`. A range-capped xBZZ Transfer scan wider than
//! the RPC quorum can verify is answered by two independent providers that
//! agree: one RPC endpoint able to serve the span, then Blockscout's log
//! index, paged back from the newest; the newest blocks go to the quorum.

use std::cell::RefCell;
use std::rc::Rc;

use fc_json::index::{Index, Kind};
use fc_naming::session::exec::{Either, race};

use super::budget::Charge;
use super::config::{ms, number_text};
use super::ctx::{Ctx, Req, started};
use super::ctx::{Over, reserve, within};
use super::error::Thrown;
use super::exchange::{ResultText, exchange, indexed};
use super::io::{Answer, Delivered, Request, Transport};
use super::logs::{Keeper, LogRange};
use super::quorum::{QuorumOptions, request_quorum};
use super::read::{SourceOptions, SourceResult, with_member};
use super::trust::blockscout_trust;
use crate::blockscout::{
    BlockscoutError, LOG_INDEX_ABORT_COOLDOWN_MS, LOG_INDEX_DISAGREEMENT_COOLDOWN_MS,
    LOG_INDEX_PAIR_MALFORMED_COOLDOWN_MS, LOG_INDEX_TAIL_BLOCKS, MAX_PAGE_SIZE, MIN_COOLDOWN_MS,
    PageReply, ScanStep, Transfer, TransferScan, agreed_rpc_logs, log_index_filter, logs_agree,
    page_text, rpc_transfer_logs_well_formed,
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
    // The pair's params, a copy of the request's (with one block changed),
    // reserved before it is made.
    let mut room = reserve!(req.ctx, params.len() + 64);
    let pair_params = with_member(params, "toBlock", &block_hex(pair_to), false)
        .ok_or_else(|| unavailable("the filter is not an object"))?;
    within!(room.settle(pair_params.capacity()).map_err(|()| Over));
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
            if !within!(well_formed(req, &result)) {
                let until = req.now() + LOG_INDEX_PAIR_MALFORMED_COOLDOWN_MS;
                req.ctx
                    .state
                    .borrow_mut()
                    .logs
                    .set_pair_cool_until(chain_id, url, until);
                // The reference names the endpoint's host, which the core
                // doesn't know (deviation `paired-endpoint-text`).
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
    drop((pair_params, room));
    // Blockscout's pages.
    let timeout = remaining()?;
    let read = {
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
    let (indexed, _transfers) = match read {
        Ok(read) => read,
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
    // The comparison and the agreed entries, from the RPC answer's index:
    // the index, the comparison's table and the agreed text reserved first,
    // and the index gone before the newest blocks' quorum.
    let rpc_text = rpc_result.as_ref().map_or("undefined", |r| r.json());
    let (agree, count, agreed) = {
        let rpc_index = within!(indexed_text(req, rpc_text));
        let _table = reserve!(req.ctx, indexed.len().saturating_mul(64));
        let agree = rpc_index
            .as_ref()
            .is_some_and(|(index, _)| logs_agree(&indexed, index.root()));
        let count = rpc_index
            .as_ref()
            .filter(|(index, _)| index.root().kind() == Kind::Array)
            .map_or_else(
                || "no".to_owned(),
                |(index, _)| index.root().children().count().to_string(),
            );
        let agreed = if agree {
            let mut room = reserve!(req.ctx, rpc_text.len().saturating_mul(2) + 64);
            let agreed = rpc_index
                .as_ref()
                .and_then(|(index, _)| agreed_rpc_logs(index.root()))
                .unwrap_or_else(|| "[]".to_owned());
            within!(room.settle(agreed.capacity()).map_err(|()| Over));
            Some((agreed, room))
        } else {
            None
        };
        (agree, count, agreed)
    };
    drop(rpc_result);
    let Some((agreed, _agreed)) = agreed.filter(|_| agree) else {
        let until = req.now() + LOG_INDEX_DISAGREEMENT_COOLDOWN_MS;
        req.ctx
            .state
            .borrow_mut()
            .logs
            .set_index_cool_until(chain_id, until);
        // Deviation `paired-endpoint-text`, as above.
        return Err(unavailable(&format!(
            "Blockscout ({} logs) and the paired endpoint ({count} logs) disagree",
            indexed.len()
        )));
    };
    drop(indexed);
    // The newest blocks: an ordinary range-capped scan through the quorum,
    // its rounds sharing what is left of the budget.
    let mut room = reserve!(req.ctx, params.len() + 64);
    let newest_params = with_member(params, "fromBlock", &block_hex(pair_to + 1), false)
        .ok_or_else(|| unavailable("the filter is not an object"))?;
    within!(room.settle(newest_params.capacity()).map_err(|()| Over));
    let keeper = RefCell::new(Keeper::new(range.ranker));
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
    drop((newest_params, room));
    let newest_text = newest.result.as_ref().map_or("undefined", |r| r.json());
    {
        let Some((index, _index)) = within!(indexed_text(req, newest_text))
            .filter(|(index, _)| index.root().kind() == Kind::Array)
        else {
            return Err(unavailable(
                "RPC quorum answered the newest blocks without a log list",
            ));
        };
        if !rpc_transfer_logs_well_formed(index.root()) {
            return Err(unavailable(&format!(
                "RPC quorum answered the newest {tail} blocks with a malformed log entry"
            )));
        }
    }
    // Only what the pair compared is delivered; the quorum's entries were
    // compared whole by its members. The result joins the two lists' texts
    // in a buffer reserved at its length.
    let (left_items, right_items) = (inner(&agreed), inner(newest_text));
    let comma = usize::from(!left_items.is_empty() && !right_items.is_empty());
    let size = left_items.len() + right_items.len() + comma + 2;
    let reserved = reserve!(req.ctx, size);
    let mut json = String::with_capacity(size);
    json.push('[');
    json.push_str(left_items);
    if comma == 1 {
        json.push(',');
    }
    json.push_str(right_items);
    json.push(']');
    Ok(SourceResult {
        result: within!(super::exchange::owned(json, reserved)),
        trust: options
            .include_trust
            .then(|| blockscout_trust(&index, &rpc_url)),
    })
}

/// A JSON array's text without its brackets.
fn inner(array: &str) -> &str {
    let trimmed = array.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\n' | '\r'));
    trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .map_or("", |items| {
            items.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\n' | '\r'))
        })
}

/// [`indexed`] for a text that may be `undefined`'s placeholder.
fn indexed_text<'t>(req: &Req, text: &'t str) -> Result<Option<(Index<'t>, Charge)>, Over> {
    indexed(req, text)
}

fn block_hex(block: u64) -> String {
    format!("\"0x{block:x}\"")
}

/// Whether an answer is a list of well-formed entries, its index reserved
/// first.
fn well_formed(req: &Req, result: &ResultText) -> Result<bool, Over> {
    let Some(text) = result else {
        return Ok(false);
    };
    Ok(indexed(req, text.json())?
        .is_some_and(|(index, _)| rpc_transfer_logs_well_formed(index.root())))
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

/// `fetchBlockscoutTransferLogs`: every page within one deadline. Each
/// page's query, decoded text and index are reserved before they are made,
/// and the transfers it adds before it is read; the transfers' charge is
/// returned with them.
async fn read_index(
    req: &Req,
    endpoint: &str,
    filter: crate::blockscout::LogIndexFilter,
    to_block: u64,
    timeout: f64,
) -> Result<(Vec<Transfer>, Charge), BlockscoutError> {
    let mut scan = TransferScan::new(filter, to_block)?;
    let deadline = req.now() + ms(timeout);
    let expired = || scan_error(format!("no answer within {}ms", number_text(timeout)));
    let mut transfers = reserve!(req.ctx, 0);
    loop {
        #[allow(clippy::cast_precision_loss)]
        let left = deadline as f64 - req.now() as f64;
        if left.is_nan() || left <= 0.0 {
            return Err(expired());
        }
        let timer = started(req.ctx.rt.sleep(ms(left)));
        // The page's query, at most a few hundred bytes, reserved first.
        let mut made = reserve!(req.ctx, endpoint.len() + 512);
        let request = Request::Blockscout {
            endpoint: endpoint.to_owned(),
            query: scan.query(),
            max_bytes: MAX_PAGE_SIZE,
            deadline_ms: ms(left),
        };
        within!(made.settle(request.bytes()).map_err(|()| Over));
        req.ctx.pend(made);
        let io = req.ctx.rt.request(request);
        let Delivered { answer, charge, .. } = match race(io, timer).await {
            Either::Left(delivered) => delivered,
            Either::Right(()) => return Err(expired()),
        };
        let (status, headers, body) = match answer {
            Answer::Blockscout {
                status,
                headers,
                body,
            } => (status, headers, body),
            Answer::Failed(Transport::Timeout) => return Err(expired()),
            Answer::Failed(Transport::Refused) => {
                return Err(scan_error("redirected to a refused location".into()));
            }
            Answer::Failed(Transport::TooLarge) => {
                return Err(scan_error("answer over 8 MiB".into()));
            }
            _ => return Err(scan_error("unreachable".into())),
        };
        let header = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        // A replacement-decoded text's growth, reserved before it is made;
        // the body's charge goes with the body.
        let grown = match crate::answer::replaced_len(&body) {
            Some(len) => Some(reserve!(req.ctx, len)),
            None => None,
        };
        let text = page_text(PageReply {
            status,
            content_length: header("content-length"),
            x_ratelimit_reset: header("x-ratelimit-reset"),
            retry_after: header("retry-after"),
            body,
        })?;
        let _text = match grown {
            Some(grown) => {
                drop(charge);
                grown
            }
            None => charge,
        };
        // The page's index, and the transfers it can add: each at most twice
        // its item's text, and the list's own doubling.
        let _index = reserve!(req.ctx, Index::heap_needed(&text).unwrap_or(0));
        let before = scan.held_bytes();
        within!(
            transfers
                .settle(
                    before
                        .saturating_mul(3)
                        .saturating_add(text.len().saturating_mul(2))
                )
                .map_err(|()| Over)
        );
        let step = scan.on_text(&text)?;
        within!(transfers.settle(scan.held_bytes()).map_err(|()| Over));
        match step {
            ScanStep::Next => {}
            ScanStep::Done(list) => {
                within!(
                    transfers
                        .settle(
                            list.capacity()
                                .saturating_mul(std::mem::size_of::<Transfer>())
                                .saturating_add(scan_strings(&list))
                        )
                        .map_err(|()| Over)
                );
                return Ok((list, transfers));
            }
        }
    }
}

/// What a list of transfers' strings hold.
fn scan_strings(list: &[Transfer]) -> usize {
    list.iter()
        .map(|t| {
            t.address.capacity()
                + t.block_hash.capacity()
                + t.transaction_hash.capacity()
                + t.from.capacity()
                + t.to.capacity()
                + t.value.capacity()
        })
        .sum()
}
