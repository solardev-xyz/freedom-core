//! The verified header (design 0005, A: the check at confirmation, The
//! evidence): Colibri's `eth_getBlockByNumber` with `["latest", false]`, a
//! method Colibri proves. B's mixed rule reads its base fee; it shows the
//! chain takes EIP-1559 transactions.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use fc_json::index::{Kind, Value};

use super::budget::Charge;
use super::config::Chain;
use super::ctx::{Over, Req, within};
use super::exchange::{ResultText, indexed};
use super::read::colibri;
use crate::bigint::{Parsed, parse_string};

/// The method and params the header is read with.
pub(crate) const HEADER_METHOD: &str = "eth_getBlockByNumber";
pub(crate) const HEADER_PARAMS: &str = r#"["latest",false]"#;

/// What a header's decimals hold at most: three of at most 78 digits.
const HEADER_BYTES: usize = 256;

/// A verified header: its `number`, `timestamp` and `baseFeePerGas`, in
/// decimal. `base_fee` is `None` on a chain without EIP-1559.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub number: String,
    pub timestamp: String,
    pub base_fee: Option<String>,
}

/// Whether a chain's header can be read: it has a prover, and its read
/// order includes `colibri`.
pub(crate) fn reads_header(chain: &Chain) -> bool {
    chain.prover.is_some() && chain.read_order.contains(&"colibri")
}

/// A quantity, as the JSON-RPC specification (ethereum/execution-apis,
/// `base-types.yaml`) writes one: `0x`, then lowercase hex digits without
/// a leading zero (`0x0` for zero), at most `digits` of them. Its value in
/// decimal; `None` for anything else.
fn quantity(value: Option<Value<'_, '_>>, digits: usize) -> Option<String> {
    let value = value?;
    // Counted before anything is copied: a longer string is none.
    if value.kind() != Kind::String || value.units().take(digits + 3).count() > digits + 2 {
        return None;
    }
    let units: Vec<u16> = value.units().collect();
    let hex = units.strip_prefix(&[0x30, 0x78][..])?;
    let lower_hex = |u: &u16| matches!(*u, 0x30..=0x39 | 0x61..=0x66);
    let compact = hex == [0x30] || hex.first().is_some_and(|u| *u != 0x30);
    if hex.is_empty() || hex.len() > digits || !compact || !hex.iter().all(lower_hex) {
        return None;
    }
    match parse_string(&units)? {
        Parsed::Value(number) => Some(number.to_decimal()),
        Parsed::TooWide { .. } => None,
    }
}

/// The header in a result: an object whose `number` and `timestamp` are
/// 64-bit quantities and whose `baseFeePerGas`, when present, is a 256-bit
/// one. A missing or malformed member, an `undefined` result or any other
/// value gives none; without `baseFeePerGas` the header has no base fee.
/// Its decimals stay charged while it is kept.
fn header_of(req: &Req, result: &ResultText) -> Result<Option<(Header, Charge)>, Over> {
    let Some(text) = result else {
        return Ok(None);
    };
    let Some((index, _index)) = indexed(req, text.json())? else {
        return Ok(None);
    };
    let root = index.root();
    if root.kind() != Kind::Object {
        return Ok(None);
    }
    let decimals = req.ctx.reserve(HEADER_BYTES)?;
    let (Some(number), Some(timestamp)) = (
        quantity(root.get("number"), 16),
        quantity(root.get("timestamp"), 16),
    ) else {
        return Ok(None);
    };
    let base_fee = match root.get("baseFeePerGas") {
        None => None,
        Some(value) => match quantity(Some(value), 64) {
            Some(base_fee) => Some(base_fee),
            None => return Ok(None),
        },
    };
    Ok(Some((
        Header {
            number,
            timestamp,
            base_fee,
        },
        decimals,
    )))
}

/// Reads the header: Colibri's `request` operation, within its budget, its
/// slot held until main's terminal reply. A failure gives none.
async fn read_header(req: &Req) -> Option<(Header, Charge)> {
    let result = colibri(req, HEADER_METHOD, HEADER_PARAMS, None, None)
        .await
        .ok()?;
    within!(header_of(req, &result))
}

type Reading<'a> = Pin<Box<dyn Future<Output = Option<(Header, Charge)>> + 'a>>;

/// A header read, started on its first poll, whose outcome is kept once
/// known. Dropped before it, its operation keeps its Colibri slot until
/// main's terminal reply, and that reply is dropped.
pub(crate) struct HeaderRead<'a> {
    reading: Option<Reading<'a>>,
    outcome: Option<Option<(Header, Charge)>>,
}

impl<'a> HeaderRead<'a> {
    pub(crate) fn new(req: &'a Req) -> Self {
        Self {
            reading: Some(Box::pin(read_header(req))),
            outcome: None,
        }
    }

    /// Polls the read; ready once its outcome is known.
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(reading) = self.reading.as_mut() {
            match reading.as_mut().poll(cx) {
                Poll::Ready(outcome) => {
                    self.reading = None;
                    self.outcome = Some(outcome);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(())
    }

    /// Waits for its outcome: the header, or none.
    pub(crate) async fn outcome(&mut self) -> Option<&Header> {
        std::future::poll_fn(|cx| self.poll(cx)).await;
        self.outcome
            .as_ref()
            .and_then(Option::as_ref)
            .map(|(header, _)| header)
    }
}
