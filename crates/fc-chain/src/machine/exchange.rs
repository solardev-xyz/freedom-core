//! One JSON-RPC exchange, as the router's `requestRpcUrl` makes it: its own
//! timer first, then `shell.rpc`; the answer read as `response.json()` and
//! `data.error` / `data.result` read it.
//!
//! Every allocation is reserved against the request's budget before it is
//! made (`memory-budgets`): the request body, a replacement-decoded text,
//! the index an answer is read with, a node error's message and copies,
//! and an agreement digest's index and writer scratch. A reservation the
//! budget refuses stops the request's future ([`super::ctx::stall`]).

use std::rc::Rc;

use fc_json::index::{Index, KeyOrder};
use fc_naming::session::exec::{Either, race};

use super::budget::Charge;
use super::config::ms;
use super::ctx::{Over, Req, reserve, started, within};
use super::error::{ErrorClass, Thrown};
use super::io::{Answer, Delivered, Request, Transport, rpc_body, rpc_body_len};
use super::text::Retained;
use crate::answer::{
    Answer as Decoded, AnswerError, NodeError, Outcome, decode_body, read_answer_reserving,
    replaced_len,
};
use crate::stable::{StableDigest, value_digest};

/// A result's text, `None` for `undefined`.
pub(crate) type ResultText = Option<Rc<Retained>>;

/// The core's text for an answer over the cap (deviation `response-caps`).
pub const TOO_LARGE: &str = "The RPC answer is too large";
/// A transport failure: what undici reports for every network error.
pub const FETCH_FAILED: &str = "fetch failed";
/// Main's chain I/O pool was full.
pub const BUSY: &str = "The RPC exchange was refused: busy";
/// Main sent nothing.
pub const NOT_SENT: &str = "The RPC exchange was not sent";

/// Makes `shell.rpc`'s request: its body is reserved before it is made,
/// and stays charged to the request until the driver takes it.
pub(crate) fn rpc_request(
    req: &Req,
    endpoint: &str,
    method: &str,
    params: &str,
    timeout: f64,
) -> Result<Request, Over> {
    let id = req.next_rpc_id();
    let made = req
        .ctx
        .reserve(endpoint.len() + rpc_body_len(id, method, params))?;
    let request = Request::Rpc {
        endpoint: endpoint.to_owned(),
        body: rpc_body(id, method, params),
        max_bytes: req.ctx.bounds.answer_bytes,
        deadline_ms: ms(timeout),
    };
    req.ctx.pend(made);
    Ok(request)
}

/// `requestRpcUrl(url, method, params, timeoutMs)`.
pub(crate) async fn exchange(
    req: &Req,
    endpoint: &str,
    method: &str,
    params: &str,
    timeout: f64,
) -> Result<ResultText, Thrown> {
    let timer = started(req.ctx.rt.sleep(ms(timeout)));
    let request = within!(rpc_request(req, endpoint, method, params, timeout));
    let io = req.ctx.rt.request(request);
    match race(io, timer).await {
        Either::Left(delivered) => read(req, delivered, timeout).await,
        Either::Right(()) => Err(Thrown::rpc_timeout(timeout)),
    }
}

/// An exchange's answer, or what the router throws for it.
pub(crate) async fn read(
    req: &Req,
    delivered: Delivered,
    timeout: f64,
) -> Result<ResultText, Thrown> {
    let Delivered { answer, charge, .. } = delivered;
    match answer {
        Answer::Rpc { status, body } => {
            let (answer, held) = match decode(req, status, body, charge).await {
                Ok(decoded) => decoded,
                Err(error) => return Err(answer_error(error)),
            };
            match answer.result_span() {
                Some(None) => Ok(None),
                Some(Some(span)) => {
                    Ok(Some(Rc::new(Retained::new(answer.into_text(), span, held))))
                }
                None => match answer.outcome() {
                    Outcome::NodeError(error) => Err(within!(node_error(req, &error))),
                    Outcome::Result(_) => Ok(None),
                },
            }
        }
        Answer::Failed(transport) => Err(transport_error(transport, timeout)),
        _ => Err(Thrown::error(NOT_SENT)),
    }
}

/// A 2xx answer read with each allocation reserved first: a
/// replacement-decoded text (whose growth over the body is reserved, the
/// body's charge released with the body), the index it is read with, and a
/// node error's message. Returns the answer and the charge that covers it
/// for as long as it is held.
pub(crate) async fn decode(
    req: &Req,
    status: u16,
    body: Vec<u8>,
    charge: Charge,
) -> Result<(Decoded, Charge), AnswerError> {
    if !(200..=299).contains(&status) {
        return Err(AnswerError::Status(status));
    }
    let (text, mut held) = match replaced_len(&body) {
        Some(len) => {
            let grown = reserve!(req.ctx, len);
            let text = decode_body(body);
            // The body is freed: its charge with it.
            drop(charge);
            (text, grown)
        }
        None => (decode_body(body), charge),
    };
    let mut reservations: Vec<Charge> = Vec::new();
    let read = read_answer_reserving(text, |bytes| {
        reservations.push(req.ctx.reserve(bytes)?);
        Ok::<(), Over>(())
    });
    let answer = within!(read)?;
    // The index is gone; a node error's message stays with the answer.
    let message = match answer.outcome() {
        Outcome::NodeError(error) => error.message.len().saturating_mul(2),
        Outcome::Result(_) => 0,
    };
    drop(reservations);
    let size = answer
        .text()
        .len()
        .max(held.bytes())
        .saturating_add(message);
    within!(held.settle(size).map_err(|()| Over));
    Ok((answer, held))
}

/// A node's error, its copies reserved before they are made and charged to
/// its request for as long as any copy of it lives: its `data` can be as
/// large as its answer (`memory-budgets`).
pub(crate) fn node_error(req: &Req, error: &NodeError<'_>) -> Result<Thrown, Over> {
    let bytes = error.message.len().saturating_mul(2)
        + error.code.map_or(0, str::len)
        + error.data.map_or(0, str::len);
    let charge = req.ctx.reserve(bytes)?;
    Ok(Thrown::node(error).charged(charge))
}

/// What the router throws for an answer it can't read.
pub(crate) fn answer_error(error: AnswerError) -> Thrown {
    let class = ErrorClass::from_name(error.name());
    Thrown::of_class(class, error.to_string().as_str())
}

/// A transport failure as an error: main's own timeout is the router's;
/// every other failure has a fixed text.
pub(crate) fn transport_error(transport: Transport, timeout: f64) -> Thrown {
    match transport {
        Transport::Timeout => Thrown::rpc_timeout(timeout),
        Transport::Network | Transport::Refused => {
            Thrown::of_class(ErrorClass::TypeError, FETCH_FAILED)
        }
        Transport::TooLarge => Thrown::error(TOO_LARGE),
        Transport::Busy => Thrown::error(BUSY),
    }
}

/// An index of `text` with its heap reserved before it is built. `None`
/// for a text that isn't JSON.
pub(crate) fn indexed<'t>(req: &Req, text: &'t str) -> Result<Option<(Index<'t>, Charge)>, Over> {
    let Ok(needed) = Index::heap_needed(text) else {
        return Ok(None);
    };
    let charge = req.ctx.reserve(needed)?;
    Ok(Index::new(text).ok().map(|index| (index, charge)))
}

/// The agreement digest of a result (`stableValue`, design 0005,
/// Answers), with its index and the writer's scratch reserved first.
pub(crate) fn digest(req: &Req, result: &ResultText) -> Result<StableDigest, Over> {
    let Some(text) = result else {
        return Ok(StableDigest::undefined());
    };
    // The span was read as part of its body: it is JSON.
    let Some((index, _index)) = indexed(req, text.json())? else {
        return Ok(StableDigest::undefined());
    };
    let _scratch = req
        .ctx
        .reserve(index.root().write_scratch(KeyOrder::Sorted))?;
    Ok(value_digest(index.root()))
}

/// A result the core made itself, with the reservation made for it
/// settled to what it holds.
pub(crate) fn owned(json: String, mut reserved: Charge) -> Result<ResultText, Over> {
    reserved.settle(json.capacity()).map_err(|()| Over)?;
    let span = 0..json.len();
    Ok(Some(Rc::new(Retained::new(json, span, reserved))))
}
