//! A fee quote (design 0005, Fee quotes): the router's `getFeeQuote`. It
//! walks the read order with no capabilities, exclusions, bypass or Myotis
//! slots.

use std::cell::RefCell;

use fc_json::index::Index;

use super::ctx::{Over, Release, Req, reply, reserve, within};
use super::error::{ErrorClass, Thrown};
use super::exchange::{ResultText, exchange};
use super::io::{Answer, Delivered, MyotisReply, Request, VerifiedOp};
use super::logs::Keeper;
use super::read::{
    MYOTIS_FAILED, SourceOptions, charged, myotis_adapter_error, myotis_failure, request_source,
};
use crate::fee::{FeeQuote, fee_quote_reserving};
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

/// `requestDirectFeeQuote`: both components from one endpoint.
async fn direct(req: &Req) -> Result<FeeQuote, Thrown> {
    let timeout = req.chain.timeout;
    let urls = req.chain.urls();
    if urls.is_empty() {
        return Err(Thrown::unavailable("No RPC endpoint configured"));
    }
    let mut last: Option<Thrown> = None;
    for url in &urls {
        let attempt = async {
            let gas = exchange(req, url, "eth_gasPrice", "[]", timeout).await?;
            // The same endpoint, deliberately; without a hint the quote is
            // legacy.
            let priority = exchange(req, url, "eth_maxPriorityFeePerGas", "[]", timeout)
                .await
                .unwrap_or(None);
            quote_within(req, "direct", json(&gas), json(&priority)).await
        };
        match attempt.await {
            Ok(quote) => return Ok(quote),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| Thrown::unavailable("All RPC endpoints failed")))
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
    quote_within(req, source, json(&gas.result), json(&priority)).await
}
