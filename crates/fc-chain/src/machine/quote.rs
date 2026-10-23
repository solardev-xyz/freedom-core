//! A fee quote (design 0005, Fee quotes): the router's `getFeeQuote`, with
//! main's #749 headroom. It walks the read order with no capabilities,
//! exclusions, bypass or Myotis slots. A source whose hint can't price a
//! quote reads its own latest block (Myotis's through the read path); one
//! whose block read fails leaves a legacy last resort, which the walk
//! replies with when no source quotes. Direct's step is B's (deviation
//! `fee-combination`): up to three endpoints at once, their quotes
//! combined.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

use fc_json::index::Index;
use fc_naming::session::exec::Sleep;

use super::budget::Charge;
use super::ctx::{Over, Release, Req, reply, reserve, started, within};
use super::error::{ErrorClass, Thrown};
use super::exchange::{ResultText, exchange};
use super::header::{HEADER_METHOD, HEADER_PARAMS, Header, HeaderRead, reads_header};
use super::io::{Answer, Delivered, Ms, MyotisReply, Request, VerifiedOp};
use super::logs::Keeper;
use super::read::{
    MYOTIS_FAILED, ReadOptions, SourceOptions, charged, myotis_adapter_error, myotis_failure, read,
    request_source,
};
use crate::fee::{
    FeeBlock, FeeQuote, GasPrice, LastResort, QUOTE_BYTES, QuoteStep, QuoteValues, Unpriced,
    combine_fee_quotes, combine_last_resorts, gas_price_reserving, lowest_priority,
    quote_step_reserving,
};
use crate::js::JsError;
use crate::myotis::{MYOTIS_NOT_READY, MyotisOperation, myotis_fee_values};
use crate::text::fee_quote_failure_text;

fn js(error: JsError) -> Thrown {
    Thrown::of_class(ErrorClass::from_name(error.name), error.message)
}

fn json(result: &ResultText) -> Option<&str> {
    result.as_ref().map(|text| text.json())
}

/// What a block read gives `feeQuote`: its result, or a failed read.
fn block_of(answer: &Result<ResultText, Thrown>) -> FeeBlock<'_> {
    match answer {
        Ok(result) => FeeBlock::Result(json(result)),
        Err(_) => FeeBlock::Failed,
    }
}

/// A source that gave no quote: its error, and the legacy last resort its
/// failed block read left (main's `legacyFallback`), charged while kept.
pub(crate) struct SourceFailure {
    pub error: Thrown,
    pub last_resort: Option<Box<(FeeQuote, Charge)>>,
}

impl From<Thrown> for SourceFailure {
    fn from(error: Thrown) -> Self {
        Self {
            error,
            last_resort: None,
        }
    }
}

/// What a block failure says. It never reaches a reply: a source that
/// fails at its block leaves a last resort, which the walk replies with
/// before any error.
const BLOCK_FAILED: &str = "the latest block could not price the fee";

/// `getFeeQuote(chainId)`.
pub(crate) async fn fee_quote(req: &Req) -> Result<FeeQuote, Thrown> {
    let chain = std::rc::Rc::clone(&req.chain);
    let mut failures: Vec<(&str, Thrown)> = Vec::new();
    let mut last_rpc_error: Option<Thrown> = None;
    // The first source's last resort is kept (main's `legacyFallback ||=`).
    let mut last_resort: Option<Box<(FeeQuote, Charge)>> = None;
    for &source in &chain.read_order {
        let attempt = match source {
            "myotis" => myotis(req).await,
            "direct" => direct(req).await,
            _ => other(req, source).await,
        };
        match attempt {
            Ok(quote) => return Ok(quote),
            Err(SourceFailure {
                error,
                last_resort: left,
            }) => {
                if last_resort.is_none() {
                    last_resort = left;
                }
                if !error.is_unavailable() {
                    last_rpc_error = Some(error.clone());
                }
                failures.push((source, error));
            }
        }
    }
    if let Some(kept) = last_resort {
        return Ok(kept.0);
    }
    if let Some(error) = last_rpc_error {
        return Err(error);
    }
    let parts: Vec<(&str, &[u16])> = failures
        .iter()
        .map(|(source, error)| (*source, error.message.units()))
        .collect();
    Err(Thrown::of_class(
        ErrorClass::Error,
        fee_quote_failure_text(&parts),
    ))
}

/// A source's last resort as the walk keeps it: its legacy quote, charged.
fn last_resort_of(quote: FeeQuote, mut charge: Charge) -> Result<SourceFailure, Over> {
    charge.settle(quote.heap_bytes()).map_err(|()| Over)?;
    Ok(SourceFailure {
        error: Thrown::unavailable(BLOCK_FAILED),
        last_resort: Some(Box::new((quote, charge))),
    })
}

/// Myotis answers both components in one operation, without a slot. A hint
/// that can't price its quote is priced from a block the read path reads,
/// as main's `request(chainId, 'eth_getBlockByNumber', ['latest', false])`
/// does: the quote names that block's source, and is verified only if the
/// read was (design 0005, Myotis's block).
async fn myotis(req: &Req) -> Result<FeeQuote, SourceFailure> {
    let chain_id = req.chain.chain_id;
    if !req.ctx.ready(chain_id) {
        return Err(Thrown::unavailable(MYOTIS_NOT_READY).into());
    }
    let cell = req.ctx.hold(
        Request::Verified(VerifiedOp::MyotisRead {
            chain_id,
            operation: MyotisOperation::Fee,
        }),
        Release::Nothing,
    );
    let Delivered {
        answer,
        charge: held,
        ..
    } = reply(&cell).await;
    let step = match answer {
        Answer::Myotis(MyotisReply::Read { payload, .. }) => {
            // The payload's index and the values' copies, reserved first
            // (`memory-budgets`).
            let index = reserve!(req.ctx, Index::heap_needed(&payload).unwrap_or(0));
            let copies = reserve!(req.ctx, payload.len().saturating_mul(4) + 2048);
            let (gas, priority) = match myotis_fee_values(Some(&payload)) {
                Ok(values) => values,
                Err(failure) => {
                    return Err(within!(charged(myotis_failure(failure), copies)).into());
                }
            };
            drop((index, held, payload));
            let gas = gas_within(req, "myotis", Some(&gas)).await?;
            step_within("myotis", gas, priority.as_deref()).await?
        }
        Answer::Myotis(MyotisReply::Failure(class)) => {
            return Err(myotis_adapter_error(req, class).into());
        }
        _ => return Err(Thrown::error(MYOTIS_FAILED).into()),
    };
    let (unpriced, work) = match step {
        Step::Values(values, _charge) => return Ok(values.quote("myotis")),
        Step::NeedsBlock(unpriced, work) => (unpriced, work),
    };
    let block = Box::pin(read(
        req,
        HEADER_METHOD,
        HEADER_PARAMS,
        &ReadOptions::default(),
    ))
    .await;
    let fed = match &block {
        Ok(answer) => FeeBlock::Result(json(&answer.result)),
        Err(_) => FeeBlock::Failed,
    };
    match block_within(unpriced, work, fed).await {
        Ok((values, _charge)) => {
            let (source, verified) = block
                .as_ref()
                .map(|answer| (answer.source, answer.verified))
                .unwrap_or(("", false));
            Ok(values.quote("myotis").priced_from(source, verified))
        }
        Err((last, charge)) => Err(within!(last_resort_of(last.quote("myotis"), charge))),
    }
}

/// How many endpoints B asks at once (design 0005, B: Collection).
pub(crate) const FEE_ENDPOINTS: usize = 3;

/// How long B's collection waits for more quotes after the first answered.
pub(crate) const FEE_CUTOFF_MS: Ms = 1_000;

/// The gas price half of `feeQuote`, with every allocation reserved
/// first, as [`quote_within`] reserves them: the value, charged at what it
/// holds, or the codec's error, charged at its size.
async fn gas_within(
    req: &Req,
    source: &str,
    gas_price: Option<&str>,
) -> Result<(GasPrice, Charge), Thrown> {
    let mut work = reserve!(req.ctx, 0);
    let read = gas_price_reserving(source, gas_price, |bytes| {
        work.settle(work.bytes().saturating_add(bytes))
            .map_err(|()| Over)
    });
    match within!(read) {
        Ok(gas) => {
            within!(work.settle(gas.heap_bytes()).map_err(|()| Over));
            Ok((gas, work))
        }
        Err(error) => Err(within!(charged(js(error), work))),
    }
}

/// The codec's next part: a quote, or a gas price its block is to price,
/// each charged at what it holds.
enum Step {
    Values(QuoteValues, Charge),
    NeedsBlock(Unpriced, Charge),
}

/// The rest of `feeQuote`, from a gas price [`gas_within`] read, with every
/// allocation reserved first: EIP-1559 from a usable hint, or the gas price
/// the source's block is to price.
async fn step_within(
    source: &str,
    (gas_price, mut work): (GasPrice, Charge),
    priority: Option<&str>,
) -> Result<Step, Thrown> {
    let stepped = quote_step_reserving(source, gas_price, priority, |bytes| {
        work.settle(work.bytes().saturating_add(bytes))
            .map_err(|()| Over)
    });
    match within!(stepped) {
        Ok(QuoteStep::Values(values)) => {
            within!(work.settle(values.heap_bytes()).map_err(|()| Over));
            Ok(Step::Values(values, work))
        }
        Ok(QuoteStep::NeedsBlock(unpriced)) => {
            within!(work.settle(unpriced.heap_bytes()).map_err(|()| Over));
            Ok(Step::NeedsBlock(unpriced, work))
        }
        Err(error) => Err(within!(charged(js(error), work))),
    }
}

/// The quote a source's block prices (main's `blockBaseFee`), with every
/// allocation reserved first, or the last resort a failed read leaves:
/// each charged at what it holds.
async fn block_within(
    unpriced: Unpriced,
    mut work: Charge,
    block: FeeBlock<'_>,
) -> Result<(QuoteValues, Charge), (LastResort, Charge)> {
    let priced = unpriced.with_block_reserving(block, |bytes| {
        work.settle(work.bytes().saturating_add(bytes))
            .map_err(|()| Over)
    });
    match within!(priced) {
        Ok(values) => {
            within!(work.settle(values.heap_bytes()).map_err(|()| Over));
            Ok((values, work))
        }
        Err(last) => {
            within!(work.settle(last.heap_bytes()).map_err(|()| Over));
            Err((last, work))
        }
    }
}

/// An endpoint's answer to B: its quote, or the last resort its failed
/// block read left; each charged while it is kept.
pub(crate) enum EndpointQuote {
    Answered(QuoteValues, Charge),
    BlockFailed(LastResort, Charge),
}

/// One endpoint's quote, as `requestDirectFeeQuote` asks it (main's #749):
/// `eth_gasPrice`, then, once that has answered, `eth_maxPriorityFeePerGas`
/// of the same endpoint, and, when that hint can't price a quote, the same
/// endpoint's latest block, each within `configured`. A failed gas price, a
/// non-positive one or an unparseable hint fails the endpoint; a failed
/// block read leaves its last resort.
///
/// Each answer is read as it arrives, and only its value (or its error) is
/// kept while the next is asked for: three endpoints run at once, and their
/// raw answers, each up to the answer cap, would otherwise all be kept
/// across those requests. The requests are the same, and so is the error:
/// a gas price that fails the codec fails the endpoint once the hint's
/// exchange has ended.
async fn endpoint_quote(req: &Req, url: &str) -> Result<EndpointQuote, Thrown> {
    let timeout = req.chain.timeout;
    let answer = exchange(req, url, "eth_gasPrice", "[]", timeout).await?;
    let gas = gas_within(req, "direct", json(&answer)).await;
    drop(answer);
    let priority = exchange(req, url, "eth_maxPriorityFeePerGas", "[]", timeout)
        .await
        .unwrap_or(None);
    let step = step_within("direct", gas?, json(&priority)).await?;
    drop(priority);
    let (unpriced, work) = match step {
        Step::Values(values, charge) => return Ok(EndpointQuote::Answered(values, charge)),
        Step::NeedsBlock(unpriced, work) => (unpriced, work),
    };
    let block = exchange(req, url, HEADER_METHOD, HEADER_PARAMS, timeout).await;
    Ok(match block_within(unpriced, work, block_of(&block)).await {
        Ok((values, charge)) => EndpointQuote::Answered(values, charge),
        Err((last, charge)) => EndpointQuote::BlockFailed(last, charge),
    })
}

/// B's answered quotes, each charged while it is kept.
pub(crate) struct Collected {
    pub values: Vec<QuoteValues>,
    _charges: Vec<Charge>,
}

impl Collected {
    /// Whether the answers mix EIP-1559 and legacy quotes.
    pub(crate) fn mixed(&self) -> bool {
        self.values.iter().any(QuoteValues::is_eip1559)
            && !self.values.iter().all(QuoteValues::is_eip1559)
    }
}

/// B's collection when no quote answered: the last error to arrive, and
/// the last resorts the endpoints that failed at their block left.
pub(crate) struct Uncollected {
    pub error: Thrown,
    pub last_resorts: Vec<(LastResort, Charge)>,
}

impl Uncollected {
    /// Direct's last resort: legacy at the headroom of the lowest gas price
    /// among them, `answered` their number (design 0005, B: No quote).
    fn last_resort(&self) -> Option<FeeQuote> {
        let last: Vec<LastResort> = self
            .last_resorts
            .iter()
            .map(|(last, _)| last.clone())
            .collect();
        combine_last_resorts(&last)
    }
}

type Asking<'a> = Pin<Box<dyn Future<Output = Result<EndpointQuote, Thrown>> + 'a>>;

/// An endpoint that failed in a tick: its registry index, its error, and
/// the last resort its failed block read left.
type Failed = (usize, Thrown, Option<(LastResort, Charge)>);

/// B's collection (design 0005, B: combining Direct's quotes; deviation
/// `fee-combination`):
///
/// - **Three at once:** the chain's endpoints in registry order, the
///   quorum's included; the first three start together.
/// - **Replacement:** until a quote has answered, an endpoint that fails
///   is replaced by the next one not yet asked, one whose block read failed
///   included. Once one has answered, no endpoint starts: a tick's answers
///   count before its failures, so a failure in the tick a quote answered
///   isn't replaced.
/// - **Cutoff:** collection ends when no started endpoint is still
///   running, or [`FEE_CUTOFF_MS`] after the first quote answered. The
///   cutoff goes first in its tick: an answer in that tick is left out.
///   Outstanding exchanges are then cancelled.
/// - **No quote:** every endpoint failed: the last error to arrive, in one
///   tick the higher registry index's, with the last resorts of those that
///   failed at their block. With no endpoint, today's `No RPC endpoint
///   configured`.
///
/// `header`, the verified header read, is polled alongside from the
/// collection's start; whether anything waits for it is the caller's.
pub(crate) async fn collect(
    req: &Req,
    mut header: Option<&mut HeaderRead<'_>>,
) -> Result<Collected, Uncollected> {
    let urls = req.chain.urls();
    if urls.is_empty() {
        return Err(Uncollected {
            error: Thrown::unavailable("No RPC endpoint configured"),
            last_resorts: Vec::new(),
        });
    }
    let mut asking: Vec<(usize, Asking<'_>)> = urls
        .iter()
        .take(FEE_ENDPOINTS)
        .enumerate()
        .map(|(index, url)| (index, Box::pin(endpoint_quote(req, url)) as Asking<'_>))
        .collect();
    let mut next = asking.len();
    let mut values: Vec<QuoteValues> = Vec::new();
    let mut charges: Vec<Charge> = Vec::new();
    // The last error, when it arrived, and its endpoint's registry index.
    let mut last: Option<(Ms, usize, Thrown)> = None;
    // The last resorts of endpoints whose block read failed.
    let mut last_resorts: Vec<(LastResort, Charge)> = Vec::new();
    let mut cutoff: Option<(Ms, Sleep<Request, Delivered>)> = None;
    std::future::poll_fn(|cx| {
        if cutoff.as_ref().is_some_and(|(at, _)| req.now() >= *at) {
            return Poll::Ready(());
        }
        // A tick's answers count before its failures: a failure is replaced
        // only while no quote has answered, this tick's included. A
        // replacement is polled in the same tick.
        let mut i = 0;
        let mut failed: Vec<Failed> = Vec::new();
        loop {
            while i < asking.len() {
                let Poll::Ready(settled) = asking[i].1.as_mut().poll(cx) else {
                    i += 1;
                    continue;
                };
                let (index, _) = asking.remove(i);
                match settled {
                    Ok(EndpointQuote::Answered(quote, charge)) => {
                        values.push(quote);
                        charges.push(charge);
                        // An error, and a last resort, are the reply only
                        // when no quote answers.
                        last = None;
                        last_resorts.clear();
                        if cutoff.is_none() {
                            let at = req.now().saturating_add(FEE_CUTOFF_MS);
                            cutoff = Some((at, started(req.ctx.rt.sleep(FEE_CUTOFF_MS))));
                        }
                    }
                    Ok(EndpointQuote::BlockFailed(resort, charge)) => {
                        failed.push((
                            index,
                            Thrown::unavailable(BLOCK_FAILED),
                            Some((resort, charge)),
                        ));
                    }
                    Err(error) => failed.push((index, error, None)),
                }
            }
            if failed.is_empty() {
                break;
            }
            let now = req.now();
            for (index, error, resort) in failed.drain(..) {
                if !values.is_empty() {
                    continue;
                }
                last_resorts.extend(resort);
                if last
                    .as_ref()
                    .is_none_or(|(at, at_index, _)| now > *at || index > *at_index)
                {
                    last = Some((now, index, error));
                }
                if let Some(url) = urls.get(next) {
                    asking.push((next, Box::pin(endpoint_quote(req, url))));
                    next += 1;
                }
            }
        }
        if let Some(header) = header.as_deref_mut() {
            let _ = header.poll(cx);
        }
        if asking.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    // Exchanges still outstanding are cancelled: those endpoints haven't
    // answered.
    drop(asking);
    drop(cutoff);
    if values.is_empty() {
        return Err(Uncollected {
            error: last.map_or_else(
                || Thrown::unavailable("All RPC endpoints failed"),
                |(_, _, error)| error,
            ),
            last_resorts,
        });
    }
    Ok(Collected {
        values,
        _charges: charges,
    })
}

/// B's combination of collected quotes, its arithmetic and quote reserved
/// first.
pub(crate) async fn combined(
    req: &Req,
    collected: &Collected,
    eip1559_verified: bool,
) -> Result<FeeQuote, Thrown> {
    let _work = reserve!(req.ctx, 2 * QUOTE_BYTES);
    combine_fee_quotes(&collected.values, eip1559_verified)
        .ok_or_else(|| Thrown::unavailable("All RPC endpoints failed"))
}

/// Direct's step: B's collection and combination, in place of
/// `requestDirectFeeQuote`'s walk. Mixed answers wait for the verified
/// header, within Colibri's budget, where the chain has one; otherwise
/// nothing waits for it, and its outcome is dropped when it arrives.
///
/// With no quote, Direct fails with B's last error, and with the last
/// resort of the endpoints that failed at their block read, when any did.
async fn direct(req: &Req) -> Result<FeeQuote, SourceFailure> {
    if req.chain.rpc.is_empty() {
        // No endpoint: no header is read.
        return Err(Thrown::unavailable("No RPC endpoint configured").into());
    }
    let mut header = reads_header(&req.chain).then(|| HeaderRead::new(req));
    let collected = match collect(req, header.as_mut()).await {
        Ok(collected) => collected,
        Err(uncollected) => {
            let last_resort = match uncollected.last_resort() {
                Some(quote) => {
                    let charge = reserve!(req.ctx, quote.heap_bytes());
                    Some(Box::new((quote, charge)))
                }
                None => None,
            };
            return Err(SourceFailure {
                error: uncollected.error,
                last_resort,
            });
        }
    };
    let eip1559_verified = match header.as_mut() {
        Some(header) if collected.mixed() => header
            .outcome()
            .await
            .is_some_and(|header| header.base_fee.is_some()),
        _ => false,
    };
    Ok(combined(req, &collected, eip1559_verified).await?)
}

/// `chain.fee_reference`'s evidence (design 0005, A: The evidence): the
/// verified header, and B's quotes.
#[derive(Debug, Clone, PartialEq)]
pub struct FeeReference {
    /// Colibri's verified header, or none: no prover, Colibri out of the
    /// read order, or a failed or malformed read.
    pub header: Option<Header>,
    /// The lowest priority fee among B's EIP-1559 quotes, in decimal.
    pub lowest_priority: Option<String>,
    /// B's combined quote, with `answered`; none when no endpoint
    /// answered, or the read order has neither `quorum` nor `direct`.
    pub quote: Option<FeeQuote>,
}

impl FeeReference {
    /// The length of its reply's JSON, `{"header":…,"lowest_priority":…,
    /// "quote":…}`, measured without writing it. Its numbers are decimal
    /// strings, which need no escaping, of any width the codecs accept (a
    /// priority fee of 4096 bits has 1,234 digits).
    pub fn json_len(&self) -> usize {
        let string = |text: &str| text.len() + 2;
        let header = self.header.as_ref().map_or(4, |header| {
            r#"{"source":"colibri","number":,"timestamp":,"base_fee":}"#.len()
                + string(&header.number)
                + string(&header.timestamp)
                + header.base_fee.as_deref().map_or(4, string)
        });
        r#"{"header":,"lowest_priority":,"quote":}"#.len()
            + header
            + self.lowest_priority.as_deref().map_or(4, string)
            + self.quote.as_ref().map_or(4, FeeQuote::json_len)
    }

    /// What its texts hold on the heap.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.header.as_ref().map_or(0, |header| {
            header.number.capacity()
                + header.timestamp.capacity()
                + header.base_fee.as_ref().map_or(0, String::capacity)
        }) + self.lowest_priority.as_ref().map_or(0, String::capacity)
            + self.quote.as_ref().map_or(0, FeeQuote::heap_bytes)
    }
}

/// `chain.fee_reference` (design 0005, A: The evidence). Its two parts run
/// at once:
///
/// - **The verified header,** where the chain has a prover and its read
///   order includes `colibri` ([`HeaderRead`]).
/// - **B's quotes,** where the read order includes `quorum` or `direct`:
///   B's collection, run for the reference itself even when an earlier
///   source would quote, and never asking Myotis, Colibri or the quorum
///   for quotes. Mixed answers combine as EIP-1559 when this request's
///   header has a base fee.
///
/// A part that fails is none; the request itself fails only as a fee quote
/// can (its deadline, a cancel, a configuration change, its budget).
pub(crate) async fn fee_reference(req: &Req) -> FeeReference {
    let mut header = reads_header(&req.chain).then(|| HeaderRead::new(req));
    let quotes = req
        .chain
        .read_order
        .iter()
        .any(|source| matches!(*source, "quorum" | "direct"));
    let collected = if quotes {
        Some(collect(req, header.as_mut()).await)
    } else {
        None
    };
    let header = match header.as_mut() {
        Some(read) => read.outcome().await.cloned(),
        None => None,
    };
    let collected = match collected {
        Some(Ok(collected)) => collected,
        // Every answering endpoint failed at its block: Direct's last
        // resort is the reference's quote.
        Some(Err(uncollected)) => {
            let quote = {
                let _work = reserve!(req.ctx, QUOTE_BYTES);
                uncollected.last_resort()
            };
            return FeeReference {
                header,
                lowest_priority: None,
                quote,
            };
        }
        None => {
            return FeeReference {
                header,
                lowest_priority: None,
                quote: None,
            };
        }
    };
    let eip1559_verified = collected.mixed()
        && header
            .as_ref()
            .is_some_and(|header| header.base_fee.is_some());
    let quote = combined(req, &collected, eip1559_verified).await.ok();
    let lowest_priority = {
        let _work = reserve!(req.ctx, QUOTE_BYTES);
        lowest_priority(&collected.values)
    };
    FeeReference {
        header,
        lowest_priority,
        quote,
    }
}

/// Colibri and the quorum make two requests, and a third for their own
/// latest block when the hint can't price a quote; any other source fails
/// as `requestSource` does.
async fn other(req: &Req, source: &str) -> Result<FeeQuote, SourceFailure> {
    let keeper = RefCell::new(Keeper::new(None));
    let options = SourceOptions {
        include_trust: false,
        route_key: None,
        fallback: None,
        attempted: &[],
        unanswered: &[],
        keeper: &keeper,
        allow_direct_fallback: false,
        deadline: None,
        background: false,
        direct_timeout: None,
        quorum_timeout: None,
        log_range: None,
        answered_by: None,
    };
    // A quorum with m = 1 is one endpoint's answer (deviation
    // `singleton-quorum`), its last resort's included.
    let label = |quote: FeeQuote| {
        if source == "quorum" && !req.chain.quorum_verifies() {
            quote.unverified()
        } else {
            quote
        }
    };
    let gas = Box::pin(request_source(req, source, "eth_gasPrice", "[]", &options)).await?;
    let read = gas_within(req, source, json(&gas.result)).await;
    drop(gas);
    // Preserve source coherence: this source's own block prices the quote.
    let priority = Box::pin(request_source(
        req,
        source,
        "eth_maxPriorityFeePerGas",
        "[]",
        &options,
    ))
    .await
    .map_or(None, |answer| answer.result);
    let step = step_within(source, read?, json(&priority)).await?;
    drop(priority);
    let (unpriced, work) = match step {
        Step::Values(values, _charge) => return Ok(label(values.quote(source))),
        Step::NeedsBlock(unpriced, work) => (unpriced, work),
    };
    let block = Box::pin(request_source(
        req,
        source,
        HEADER_METHOD,
        HEADER_PARAMS,
        &options,
    ))
    .await
    .map(|answer| answer.result);
    match block_within(unpriced, work, block_of(&block)).await {
        Ok((values, _charge)) => Ok(label(values.quote(source))),
        Err((last, charge)) => Err(within!(last_resort_of(label(last.quote(source)), charge))),
    }
}
