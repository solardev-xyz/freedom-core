//! One JSON-RPC exchange, as the router's `requestRpcUrl` makes it: its own
//! timer first, then `shell.rpc`; the answer read as `response.json()` and
//! `data.error` / `data.result` read it.

use std::rc::Rc;

use fc_json::index::Index;
use fc_naming::session::exec::{Either, race};

use super::config::ms;
use super::ctx::{Req, started};
use super::error::{ErrorClass, Thrown};
use super::io::{Answer, Delivered, Request, Transport, rpc_body};
use super::text::Retained;
use crate::answer::{AnswerError, Outcome, decode_answer};
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

/// `requestRpcUrl(url, method, params, timeoutMs)`.
pub(crate) async fn exchange(
    req: &Req,
    endpoint: &str,
    method: &str,
    params: &str,
    timeout: f64,
) -> Result<ResultText, Thrown> {
    let timer = started(req.ctx.rt.sleep(ms(timeout)));
    let io = req.ctx.rt.request(Request::Rpc {
        endpoint: endpoint.to_owned(),
        body: rpc_body(req.next_rpc_id(), method, params),
        max_bytes: req.ctx.bounds.answer_bytes,
        deadline_ms: ms(timeout),
    });
    match race(io, timer).await {
        Either::Left(delivered) => read(req, delivered, timeout),
        Either::Right(()) => Err(Thrown::rpc_timeout(timeout)),
    }
}

/// An exchange's answer, or what the router throws for it.
pub(crate) fn read(req: &Req, delivered: Delivered, timeout: f64) -> Result<ResultText, Thrown> {
    let Delivered { answer, charge } = delivered;
    match answer {
        Answer::Rpc { status, body } => {
            let answer = decode_answer(status, body).map_err(answer_error)?;
            // The index the body was read with, while it was held.
            drop(req.ctx.charge(answer.index_bytes())?);
            match answer.result_span() {
                Some(None) => Ok(None),
                Some(Some(span)) => Ok(Some(Rc::new(Retained::new(
                    answer.into_text(),
                    span,
                    charge,
                )))),
                None => match answer.outcome() {
                    Outcome::NodeError(error) => Err(Thrown::node(&error)),
                    Outcome::Result(_) => Ok(None),
                },
            }
        }
        Answer::Failed(transport) => Err(transport_error(transport, timeout)),
        Answer::NotSent => Err(Thrown::error(NOT_SENT)),
        _ => Err(Thrown::error(NOT_SENT)),
    }
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

/// The agreement digest of a result (`stableValue`, design 0005,
/// Answers), with its index charged while it is held.
pub(crate) fn digest(req: &Req, result: &ResultText) -> Result<StableDigest, Thrown> {
    let Some(text) = result else {
        return Ok(StableDigest::undefined());
    };
    let index = Index::new(text.json()).map_err(|error| answer_error(error.into()))?;
    let _charge = req.ctx.charge(index.heap_bytes())?;
    Ok(value_digest(index.root()))
}

/// A result the core made itself (Myotis's), as a retained text.
pub(crate) fn owned(req: &Req, json: String) -> Result<ResultText, Thrown> {
    let charge = req.ctx.charge(json.capacity())?;
    let span = 0..json.len();
    Ok(Some(Rc::new(Retained::new(json, span, charge))))
}
