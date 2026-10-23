//! A fee quote (design 0005, Fee quotes): the router's `getFeeQuote`. It
//! walks the read order with no capabilities, exclusions, bypass or Myotis
//! slots. Direct's step is B's (deviation `fee-combination`): up to three
//! endpoints at once, their quotes combined.

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
use super::header::{Header, HeaderRead, reads_header};
use super::io::{Answer, Delivered, Ms, MyotisReply, Request, VerifiedOp};
use super::logs::Keeper;
use super::read::{
    MYOTIS_FAILED, SourceOptions, charged, myotis_adapter_error, myotis_failure, request_source,
};
use crate::fee::{
    FeeQuote, QUOTE_BYTES, QuoteValues, combine_fee_quotes, fee_quote_reserving,
    fee_quote_values_reserving, lowest_priority,
};
use crate::js::JsError;
use crate::myotis::{MYOTIS_NOT_READY, MyotisOperation, myotis_fee_values};
use crate::text::fee_quote_failure_text;

fn js(error: JsError) -> Thrown {
    Thrown::of_class(ErrorClass::from_name(error.name), error.message)
}

/// `feeQuote` with every allocation the codec makes reserved first
/// (`memory-budgets`): its indexes, conversions, limbs, messages and the
/// quote. A refused reservation stops the request; an error keeps the
/// work's charge, settled to its size, while any copy of it lives.
async fn quote_within(
    req: &Req,
    source: &str,
    gas_price: Option<&str>,
    priority: Option<&str>,
) -> Result<FeeQuote, Thrown> {
    let mut work = reserve!(req.ctx, 0);
    let quoted = fee_quote_reserving(source, gas_price, priority, |bytes| {
        work.settle(work.bytes().saturating_add(bytes))
            .map_err(|()| Over)
    });
    match within!(quoted) {
        Ok(quote) => Ok(quote),
        Err(error) => Err(within!(charged(js(error), work))),
    }
}

fn json(result: &ResultText) -> Option<&str> {
    result.as_ref().map(|text| text.json())
}

/// `getFeeQuote(chainId)`.
pub(crate) async fn fee_quote(req: &Req) -> Result<FeeQuote, Thrown> {
    let chain = std::rc::Rc::clone(&req.chain);
    let mut failures: Vec<(&str, Thrown)> = Vec::new();
    let mut last_rpc_error: Option<Thrown> = None;
    for &source in &chain.read_order {
        let attempt = match source {
            "myotis" => myotis(req).await,
            "direct" => direct(req).await,
            _ => other(req, source).await,
        };
        match attempt {
            Ok(quote) => return Ok(quote),
            Err(error) => {
                if !error.is_unavailable() {
                    last_rpc_error = Some(error.clone());
                }
                failures.push((source, error));
            }
        }
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

/// Myotis answers both components in one operation, without a slot.
async fn myotis(req: &Req) -> Result<FeeQuote, Thrown> {
    let chain_id = req.chain.chain_id;
    if !req.ctx.ready(chain_id) {
        return Err(Thrown::unavailable(MYOTIS_NOT_READY));
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
        charge: _held,
        ..
    } = reply(&cell).await;
    match answer {
        Answer::Myotis(MyotisReply::Read { payload, .. }) => {
            // The payload's index and the values' copies, reserved first
            // (`memory-budgets`).
            let _index = reserve!(req.ctx, Index::heap_needed(&payload).unwrap_or(0));
            let copies = reserve!(req.ctx, payload.len().saturating_mul(4) + 2048);
            let (gas, priority) = match myotis_fee_values(Some(&payload)) {
                Ok(values) => values,
                Err(failure) => return Err(within!(charged(myotis_failure(failure), copies))),
            };
            quote_within(req, "myotis", Some(&gas), priority.as_deref()).await
        }
        Answer::Myotis(MyotisReply::Failure(class)) => Err(myotis_adapter_error(req, class)),
        _ => Err(Thrown::error(MYOTIS_FAILED)),
    }
}

/// How many endpoints B asks at once (design 0005, B: Collection).
pub(crate) const FEE_ENDPOINTS: usize = 3;

/// How long B's collection waits for more quotes after the first answered.
pub(crate) const FEE_CUTOFF_MS: Ms = 1_000;

/// `feeQuote`'s values with every allocation reserved first, as
/// [`quote_within`] reserves them. They stay charged, at what they hold,
/// while they are kept.
async fn values_within(
    req: &Req,
    source: &str,
    gas_price: Option<&str>,
    priority: Option<&str>,
) -> Result<(QuoteValues, Charge), Thrown> {
    let mut work = reserve!(req.ctx, 0);
    let quoted = fee_quote_values_reserving(source, gas_price, priority, |bytes| {
        work.settle(work.bytes().saturating_add(bytes))
            .map_err(|()| Over)
    });
    match within!(quoted) {
        Ok(values) => {
            within!(work.settle(values.heap_bytes()).map_err(|()| Over));
            Ok((values, work))
        }
        Err(error) => Err(within!(charged(js(error), work))),
    }
}

/// One endpoint's quote, as `requestDirectFeeQuote` asks it:
/// `eth_gasPrice`, then, once that has answered, `eth_maxPriorityFeePerGas`
/// of the same endpoint, each within `configured`. A failed hint gives a
/// legacy quote; a failed gas price, a non-positive one or an unparseable
/// hint fails the endpoint.
async fn endpoint_quote(req: &Req, url: &str) -> Result<(QuoteValues, Charge), Thrown> {
    let timeout = req.chain.timeout;
    let gas = exchange(req, url, "eth_gasPrice", "[]", timeout).await?;
    let priority = exchange(req, url, "eth_maxPriorityFeePerGas", "[]", timeout)
        .await
        .unwrap_or(None);
    values_within(req, "direct", json(&gas), json(&priority)).await
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

type Asking<'a> = Pin<Box<dyn Future<Output = Result<(QuoteValues, Charge), Thrown>> + 'a>>;

/// B's collection (design 0005, B: combining Direct's quotes; deviation
/// `fee-combination`):
///
/// - **Three at once:** the chain's endpoints in registry order, the
///   quorum's included; the first three start together.
/// - **Replacement:** until a quote has answered, an endpoint that fails
///   is replaced by the next one not yet asked. Once one has answered, no
///   endpoint starts.
/// - **Cutoff:** collection ends when no started endpoint is still
///   running, or [`FEE_CUTOFF_MS`] after the first quote answered. The
///   cutoff goes first in its tick: an answer in that tick is left out.
///   Outstanding exchanges are then cancelled.
/// - **No quote:** every endpoint failed: the last error to arrive, in one
///   tick the higher registry index's. With no endpoint, today's `No RPC
///   endpoint configured`.
///
/// `header`, the verified header read, is polled alongside from the
/// collection's start; whether anything waits for it is the caller's.
pub(crate) async fn collect(
    req: &Req,
    mut header: Option<&mut HeaderRead<'_>>,
) -> Result<Collected, Thrown> {
    let urls = req.chain.urls();
    if urls.is_empty() {
        return Err(Thrown::unavailable("No RPC endpoint configured"));
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
    let mut cutoff: Option<(Ms, Sleep<Request, Delivered>)> = None;
    std::future::poll_fn(|cx| {
        if cutoff.as_ref().is_some_and(|(at, _)| req.now() >= *at) {
            return Poll::Ready(());
        }
        let mut i = 0;
        while i < asking.len() {
            let Poll::Ready(settled) = asking[i].1.as_mut().poll(cx) else {
                i += 1;
                continue;
            };
            let (index, _) = asking.remove(i);
            match settled {
                Ok((quote, charge)) => {
                    values.push(quote);
                    charges.push(charge);
                    if cutoff.is_none() {
                        let at = req.now().saturating_add(FEE_CUTOFF_MS);
                        cutoff = Some((at, started(req.ctx.rt.sleep(FEE_CUTOFF_MS))));
                    }
                }
                Err(error) => {
                    let now = req.now();
                    if last
                        .as_ref()
                        .is_none_or(|(at, at_index, _)| now > *at || index > *at_index)
                    {
                        last = Some((now, index, error));
                    }
                    if values.is_empty()
                        && let Some(url) = urls.get(next)
                    {
                        asking.push((next, Box::pin(endpoint_quote(req, url))));
                        next += 1;
                    }
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
        return Err(last.map_or_else(
            || Thrown::unavailable("All RPC endpoints failed"),
            |(_, _, error)| error,
        ));
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
async fn direct(req: &Req) -> Result<FeeQuote, Thrown> {
    if req.chain.rpc.is_empty() {
        // No endpoint: no header is read.
        return Err(Thrown::unavailable("No RPC endpoint configured"));
    }
    let mut header = reads_header(&req.chain).then(|| HeaderRead::new(req));
    let collected = collect(req, header.as_mut()).await?;
    let eip1559_verified = match header.as_mut() {
        Some(header) if collected.mixed() => header
            .outcome()
            .await
            .is_some_and(|header| header.base_fee.is_some()),
        _ => false,
    };
    combined(req, &collected, eip1559_verified).await
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
        collect(req, header.as_mut()).await.ok()
    } else {
        None
    };
    let header = match header.as_mut() {
        Some(read) => read.outcome().await.cloned(),
        None => None,
    };
    let Some(collected) = collected else {
        return FeeReference {
            header,
            lowest_priority: None,
            quote: None,
        };
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

/// Colibri and the quorum make two requests; any other source fails as
/// `requestSource` does.
async fn other(req: &Req, source: &str) -> Result<FeeQuote, Thrown> {
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
    let gas = Box::pin(request_source(req, source, "eth_gasPrice", "[]", &options)).await?;
    // Preserve source coherence: this source's gas price alone, legacy.
    let priority = Box::pin(request_source(
        req,
        source,
        "eth_maxPriorityFeePerGas",
        "[]",
        &options,
    ))
    .await
    .map_or(None, |answer| answer.result);
    let quote = quote_within(req, source, json(&gas.result), json(&priority)).await?;
    // A quorum with m = 1 is one endpoint's answer (deviation
    // `singleton-quorum`).
    Ok(if source == "quorum" && !req.chain.quorum_verifies() {
        quote.unverified()
    } else {
        quote
    })
}
