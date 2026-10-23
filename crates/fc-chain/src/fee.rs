//! `feeQuote`: one source's quote from its gas price, its priority fee and,
//! when that fee can't price one, its latest block (main's #749 headroom,
//! design 0005, Fee quotes).
//!
//! - `BigInt(gasPrice)`, with JavaScript's conversions and their errors: a
//!   string as `BigInt(string)` reads it, a number only when an integer,
//!   `true` as 1, an array as its joined string, `null` and `undefined`
//!   refused.
//! - A gas price of zero or less is refused; a priority fee `BigInt`
//!   can't read fails the source.
//! - **A usable hint** (0 ≤ P ≤ G): EIP-1559 at base G − P, tip P.
//! - **Otherwise** the source's block prices it: EIP-1559 at its base fee,
//!   with the tip max(G − base, 0); legacy when it has none; and a failed
//!   read leaves a legacy last resort ([`LastResort`]).
//! - **The headroom:** every tip floored at [`MIN_PRIORITY_FEE_WEI`];
//!   `maxFeePerGas = 2·base + tip`, `effectiveGasPrice = base + tip`; a
//!   legacy gas price ⌊G·125/100⌋ + the floor.
//! - Decimal strings; `verified` for myotis, colibri and quorum. The
//!   machine unverifies a quorum's quote when its m is 1 (deviation
//!   `singleton-quorum`), and marks a Myotis quote priced from a block the
//!   read path read ([`FeeQuote::priced_from`]).
//!
//! A gas price or a block's base fee of 2^4096 or more fails the source or
//! its block (deviation `bigint-width`), where the router would quote it.
//!
//! B's combination of Direct's quotes ([`combine_fee_quotes`], deviation
//! `fee-combination`) reads each endpoint's quote from the same codec
//! ([`QuoteValues`]) and keeps the tightest constraints.

use fc_json::index::{Index, Kind, Value, quoted_len};
use fc_json::number_to_string;

use crate::bigint::{BigInt, MAX_DECIMAL_BITS, Parsed, parse_string};
use crate::js::{JsError, JsString, NOT_PRIMITIVE, js_string_reserving};

/// A fee quote, in the router's shape.
///
/// `answered` is B's mark on Direct's quotes (design 0005, deviation
/// `fee-combination`): the number of endpoints whose quotes were combined,
/// written after `verified`. `base_fee_source` is main's #749 mark on a
/// Myotis quote priced from a block the read path read: the source that
/// served it, written last. Every other quote has neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeQuote {
    Legacy {
        gas_price: String,
        source: String,
        verified: bool,
        answered: Option<u8>,
        base_fee_source: Option<String>,
    },
    Eip1559 {
        base_fee: String,
        max_priority_fee_per_gas: String,
        max_fee_per_gas: String,
        effective_gas_price: String,
        source: String,
        verified: bool,
        answered: Option<u8>,
        base_fee_source: Option<String>,
    },
}

/// The length of `,"answered":<n>`, or 0 without it.
fn answered_len(answered: Option<u8>) -> usize {
    answered.map_or(0, |n| {
        r#","answered":"#.len()
            + match n {
                0..=9 => 1,
                10..=99 => 2,
                _ => 3,
            }
    })
}

/// `,"answered":<n>`, or nothing without it.
fn answered_json(answered: Option<u8>) -> String {
    answered.map_or_else(String::new, |n| format!(r#","answered":{n}"#))
}

/// The length of `,"baseFeeSource":<source>`, or 0 without it.
fn base_fee_source_len(source: Option<&str>) -> usize {
    source.map_or(0, |source| {
        r#","baseFeeSource":"#.len() + quoted_len(source.encode_utf16())
    })
}

/// `,"baseFeeSource":<source>`, or nothing without it.
fn base_fee_source_json(source: Option<&str>) -> String {
    source.map_or_else(String::new, |source| {
        format!(r#","baseFeeSource":{}"#, JsString::from(source).to_json())
    })
}

impl FeeQuote {
    /// The length of [`Self::to_json`]'s text, measured without writing
    /// it.
    pub fn json_len(&self) -> usize {
        let quoted = |text: &str| quoted_len(text.encode_utf16());
        let flag = |verified: bool| if verified { 4 } else { 5 };
        match self {
            Self::Legacy {
                gas_price,
                source,
                verified,
                answered,
                base_fee_source,
            } => {
                r#"{"type":"legacy","gasPrice":"","effectiveGasPrice":"","source":,"verified":}"#
                    .len()
                    + 2 * gas_price.len()
                    + quoted(source)
                    + flag(*verified)
                    + answered_len(*answered)
                    + base_fee_source_len(base_fee_source.as_deref())
            }
            Self::Eip1559 {
                base_fee,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                effective_gas_price,
                source,
                verified,
                answered,
                base_fee_source,
            } => {
                r#"{"type":"eip1559","baseFee":"","maxPriorityFeePerGas":"","maxFeePerGas":"","effectiveGasPrice":"","source":,"verified":}"#
                    .len()
                    + base_fee.len()
                    + max_priority_fee_per_gas.len()
                    + max_fee_per_gas.len()
                    + effective_gas_price.len()
                    + quoted(source)
                    + flag(*verified)
                    + answered_len(*answered)
                    + base_fee_source_len(base_fee_source.as_deref())
            }
        }
    }

    /// The same quote, not `verified`: a quorum with m = 1 is one
    /// endpoint's answer (design 0005, deviation `singleton-quorum`).
    #[must_use]
    pub fn unverified(mut self) -> Self {
        match &mut self {
            Self::Legacy { verified, .. } | Self::Eip1559 { verified, .. } => *verified = false,
        }
        self
    }

    /// The number of endpoints B combined into it: Direct's quotes only.
    pub fn answered(&self) -> Option<u8> {
        match self {
            Self::Legacy { answered, .. } | Self::Eip1559 { answered, .. } => *answered,
        }
    }

    /// The same quote, marked with B's `answered`.
    #[must_use]
    pub fn answered_by(mut self, count: Option<u8>) -> Self {
        match &mut self {
            Self::Legacy { answered, .. } | Self::Eip1559 { answered, .. } => *answered = count,
        }
        self
    }

    /// The same quote priced from a block the read path read (main's #749,
    /// a Myotis quote): `baseFeeSource` names the block's source, and the
    /// quote is `verified` only if the read was too.
    #[must_use]
    pub fn priced_from(mut self, block_source: &str, block_verified: bool) -> Self {
        match &mut self {
            Self::Legacy {
                verified,
                base_fee_source,
                ..
            }
            | Self::Eip1559 {
                verified,
                base_fee_source,
                ..
            } => {
                *verified = *verified && block_verified;
                *base_fee_source = Some(block_source.to_owned());
            }
        }
        self
    }

    /// What its texts hold on the heap.
    pub fn heap_bytes(&self) -> usize {
        match self {
            Self::Legacy {
                gas_price,
                source,
                base_fee_source,
                ..
            } => {
                gas_price.capacity()
                    + source.capacity()
                    + base_fee_source.as_ref().map_or(0, String::capacity)
            }
            Self::Eip1559 {
                base_fee,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                effective_gas_price,
                source,
                base_fee_source,
                ..
            } => {
                base_fee.capacity()
                    + max_priority_fee_per_gas.capacity()
                    + max_fee_per_gas.capacity()
                    + effective_gas_price.capacity()
                    + source.capacity()
                    + base_fee_source.as_ref().map_or(0, String::capacity)
            }
        }
    }

    /// `JSON.stringify(quote)`, keys in the router's order, then B's
    /// `answered`, then main's `baseFeeSource`.
    pub fn to_json(&self) -> String {
        let quote = |text: &str| JsString::from(text).to_json();
        match self {
            Self::Legacy {
                gas_price,
                source,
                verified,
                answered,
                base_fee_source,
            } => format!(
                r#"{{"type":"legacy","gasPrice":"{gas_price}","effectiveGasPrice":"{gas_price}","source":{},"verified":{verified}{}{}}}"#,
                quote(source),
                answered_json(*answered),
                base_fee_source_json(base_fee_source.as_deref()),
            ),
            Self::Eip1559 {
                base_fee,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                effective_gas_price,
                source,
                verified,
                answered,
                base_fee_source,
            } => format!(
                r#"{{"type":"eip1559","baseFee":"{base_fee}","maxPriorityFeePerGas":"{max_priority_fee_per_gas}","maxFeePerGas":"{max_fee_per_gas}","effectiveGasPrice":"{effective_gas_price}","source":{},"verified":{verified}{}{}}}"#,
                quote(source),
                answered_json(*answered),
                base_fee_source_json(base_fee_source.as_deref()),
            ),
        }
    }
}

/// The smallest tip a quote signs with (main's #749, `MIN_PRIORITY_FEE_WEI`):
/// 0.05 gwei.
pub const MIN_PRIORITY_FEE_WEI: u64 = 50_000_000;

/// A legacy quote's gas price as a percentage of the source's (main's #749,
/// `LEGACY_GAS_PRICE_HEADROOM_PERCENT`).
const LEGACY_HEADROOM_PERCENT: u64 = 125;

/// A legacy quote's signed gas price: ⌊G·125/100⌋ + the floor.
fn legacy_headroom(gas_price: &BigInt) -> BigInt {
    gas_price
        .times(LEGACY_HEADROOM_PERCENT)
        .divided(100)
        .plus(&BigInt::from_u64(MIN_PRIORITY_FEE_WEI))
}

/// A tip, floored at [`MIN_PRIORITY_FEE_WEI`].
fn floored(tip: &BigInt) -> BigInt {
    tip.max(&BigInt::from_u64(MIN_PRIORITY_FEE_WEI)).clone()
}

/// One source's quote as `feeQuote` (main's #749) makes it, kept as
/// numbers: the source's raw gas price G, and how the quote is priced. B
/// combines Direct's quotes from these (design 0005, B: combining Direct's
/// quotes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteValues {
    gas_price: BigInt,
    priced: Priced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Priced {
    /// EIP-1559 at `base`, with its tip floored: from a usable hint
    /// (base = G − P), or from the source's block.
    Eip1559 { base: BigInt, tip: BigInt },
    /// Legacy: the source's block has no base fee.
    Legacy,
}

impl QuoteValues {
    fn eip1559(gas_price: BigInt, base: BigInt, tip: &BigInt) -> Self {
        Self {
            gas_price,
            priced: Priced::Eip1559 {
                base: base.compact(),
                tip: floored(tip).compact(),
            },
        }
    }

    /// Whether the quote is EIP-1559.
    pub fn is_eip1559(&self) -> bool {
        matches!(self.priced, Priced::Eip1559 { .. })
    }

    /// An EIP-1559 quote's priority fee, its floored tip, in decimal.
    pub fn priority_decimal(&self) -> Option<String> {
        match &self.priced {
            Priced::Eip1559 { tip, .. } => Some(tip.to_decimal()),
            Priced::Legacy => None,
        }
    }

    /// The quote main's `feeQuote` makes of them, from `source`: EIP-1559
    /// with `maxFeePerGas = 2·base + tip` and `effectiveGasPrice = base +
    /// tip`, or legacy at ⌊G·125/100⌋ + the floor.
    pub fn quote(&self, source: &str) -> FeeQuote {
        let verified = matches!(source, "myotis" | "colibri" | "quorum");
        let source = source.to_owned();
        match &self.priced {
            Priced::Eip1559 { base, tip } => FeeQuote::Eip1559 {
                max_fee_per_gas: base.plus(base).plus(tip).to_decimal(),
                base_fee: base.to_decimal(),
                max_priority_fee_per_gas: tip.to_decimal(),
                effective_gas_price: base.plus(tip).to_decimal(),
                source,
                verified,
                answered: None,
                base_fee_source: None,
            },
            Priced::Legacy => FeeQuote::Legacy {
                gas_price: legacy_headroom(&self.gas_price).to_decimal(),
                source,
                verified,
                answered: None,
                base_fee_source: None,
            },
        }
    }

    /// What its numbers hold on the heap.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.gas_price.heap_bytes()
            + match &self.priced {
                Priced::Eip1559 { base, tip } => base.heap_bytes() + tip.heap_bytes(),
                Priced::Legacy => 0,
            }
    }

    /// The two constraints B reads it as, as the quote signs them: the max
    /// fee per gas M and the priority fee P. An EIP-1559 quote gives
    /// `2·base + tip` and its tip; a legacy one M = P = its signed gas
    /// price. P is never above M.
    fn constraints(&self) -> (BigInt, BigInt) {
        match &self.priced {
            Priced::Eip1559 { base, tip } => (base.plus(base).plus(tip), tip.clone()),
            Priced::Legacy => {
                let signed = legacy_headroom(&self.gas_price);
                (signed.clone(), signed)
            }
        }
    }
}

/// A source whose block read failed (main's #749): it gives no quote, but
/// leaves a legacy one, headroom included, as the walk's last resort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastResort {
    gas_price: BigInt,
}

impl LastResort {
    /// Its legacy quote from `source`: ⌊G·125/100⌋ + the floor.
    pub fn quote(&self, source: &str) -> FeeQuote {
        QuoteValues {
            gas_price: self.gas_price.clone(),
            priced: Priced::Legacy,
        }
        .quote(source)
    }

    /// What its number holds on the heap.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.gas_price.heap_bytes()
    }
}

/// A source's block, as main's `getBlock` gives `feeQuote` its latest one
/// (`eth_getBlockByNumber` with `["latest", false]`): the result's JSON
/// text (`None` for `undefined`), or a failed read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeBlock<'a> {
    Result(Option<&'a str>),
    Failed,
}

/// What `feeQuote` gives for one source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeOutcome<T> {
    /// Its quote.
    Quote(T),
    /// Its hint is missing or can't form a type-2 quote, and no block was
    /// given to price it.
    NeedsBlock,
    /// Its block read failed: no quote, but a last resort.
    LastResort(LastResort),
    /// What the router throws.
    Error(JsError),
}

/// `feeQuote(source, gasPrice, priority, getBlock)` with main's #749
/// headroom, each value given as its JSON text, `None` being `undefined`,
/// and `block` what `getBlock` gives when it is asked. The error is the one
/// the router throws.
pub fn fee_quote(
    source: &str,
    gas_price: Option<&str>,
    priority: Option<&str>,
    block: Option<FeeBlock<'_>>,
) -> FeeOutcome<FeeQuote> {
    match fee_quote_values(source, gas_price, priority, block) {
        FeeOutcome::Quote(values) => FeeOutcome::Quote(values.quote(source)),
        FeeOutcome::NeedsBlock => FeeOutcome::NeedsBlock,
        FeeOutcome::LastResort(last) => FeeOutcome::LastResort(last),
        FeeOutcome::Error(error) => FeeOutcome::Error(error),
    }
}

/// [`fee_quote`]'s values, before they are written as a quote.
pub fn fee_quote_values(
    source: &str,
    gas_price: Option<&str>,
    priority: Option<&str>,
    block: Option<FeeBlock<'_>>,
) -> FeeOutcome<QuoteValues> {
    match fee_quote_values_reserving(source, gas_price, priority, block, |_| {
        Ok::<(), std::convert::Infallible>(())
    }) {
        Ok(outcome) => outcome,
        Err(never) => match never {},
    }
}

/// [`fee_quote_values`], asking `reserve` for room before each allocation:
/// each value's index, its conversion's text and stack, the `BigInt`'s
/// limbs, an error's message and the quote. An `Err` from `reserve` stops
/// the codec before it allocates.
pub fn fee_quote_values_reserving<E>(
    source: &str,
    gas_price: Option<&str>,
    priority: Option<&str>,
    block: Option<FeeBlock<'_>>,
    mut reserve: impl FnMut(usize) -> Result<(), E>,
) -> Result<FeeOutcome<QuoteValues>, E> {
    let gas_price = match gas_price_reserving(source, gas_price, &mut reserve)? {
        Ok(gas_price) => gas_price,
        Err(error) => return Ok(FeeOutcome::Error(error)),
    };
    let unpriced = match quote_step_reserving(source, gas_price, priority, &mut reserve)? {
        Ok(QuoteStep::Values(values)) => return Ok(FeeOutcome::Quote(values)),
        Ok(QuoteStep::NeedsBlock(unpriced)) => unpriced,
        Err(error) => return Ok(FeeOutcome::Error(error)),
    };
    let Some(block) = block else {
        return Ok(FeeOutcome::NeedsBlock);
    };
    Ok(match unpriced.with_block_reserving(block, reserve)? {
        Ok(values) => FeeOutcome::Quote(values),
        Err(last) => FeeOutcome::LastResort(last),
    })
}

/// The most a quote's text, or one of its errors, holds: four decimals of
/// at most [`MAX_DECIMAL_BITS`] bits and two more (1,235 digits each), and
/// the arithmetic's values, besides the source's name.
pub(crate) const QUOTE_BYTES: usize = 8 * 1024;

/// A positive gas price, as the codec reads it before the priority fee:
/// its value when a quote can carry it, or that it is wider than
/// [`MAX_DECIMAL_BITS`] bits, which fails the quote once the priority fee
/// has been read. Nothing of its text is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GasPrice {
    Fits(BigInt),
    Wide,
}

impl GasPrice {
    /// What it holds on the heap.
    pub(crate) fn heap_bytes(&self) -> usize {
        match self {
            Self::Fits(value) => value.heap_bytes(),
            Self::Wide => 0,
        }
    }
}

/// The first part of the codec: the gas price read alone, its errors (no
/// JSON, no `BigInt`, not positive) the codec's, with every allocation
/// asked of `reserve` first. A caller can read the gas price as it arrives
/// and keep only this while the priority fee is asked for, so an
/// endpoint's raw answer isn't kept across that request; the next part,
/// [`quote_step_reserving`], gives the same quote or error the whole codec
/// gives.
pub(crate) fn gas_price_reserving<E>(
    source: &str,
    gas_price: Option<&str>,
    mut reserve: impl FnMut(usize) -> Result<(), E>,
) -> Result<Result<GasPrice, JsError>, E> {
    let small = source.len().saturating_mul(2).saturating_add(256);
    let gas_index = match gas_price
        .map(|text| indexed(text, &mut reserve))
        .transpose()?
    {
        None => None,
        Some(Ok(index)) => Some(index),
        Some(Err(error)) => return Ok(Err(error)),
    };
    let gas_price = match to_bigint_reserving(gas_index.as_ref().map(Index::root), &mut reserve)? {
        Ok(value) => value,
        Err(error) => return Ok(Err(error)),
    };
    drop(gas_index);
    let positive = match &gas_price {
        Parsed::Value(value) => !value.is_negative() && !value.is_zero(),
        Parsed::TooWide { negative } => !negative,
    };
    if !positive {
        reserve(small)?;
        return Ok(Err(JsError::new(
            "Error",
            format!("{source} returned a non-positive gas price").as_str(),
        )));
    }
    Ok(Ok(match gas_price {
        Parsed::Value(value) if value.bits() <= MAX_DECIMAL_BITS => GasPrice::Fits(value.compact()),
        _ => GasPrice::Wide,
    }))
}

/// A gas price whose hint can't price a quote: its source's block will.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unpriced {
    gas_price: BigInt,
}

/// The second part of the codec's answer: the quote, or a gas price its
/// block is to price.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QuoteStep {
    Values(QuoteValues),
    NeedsBlock(Unpriced),
}

/// The second part of the codec: with a gas price [`gas_price_reserving`]
/// read and `priority`'s text, EIP-1559 when the hint is usable (0 ≤ P ≤
/// G), or the gas price its block is to price. A hint `BigInt` can't
/// parse fails the source, and a gas price too wide to quote fails it
/// once the hint has been read (deviation `bigint-width`).
pub(crate) fn quote_step_reserving<E>(
    source: &str,
    gas_price: GasPrice,
    priority: Option<&str>,
    mut reserve: impl FnMut(usize) -> Result<(), E>,
) -> Result<Result<QuoteStep, JsError>, E> {
    let small = source.len().saturating_mul(2).saturating_add(256);
    let priority_index = match priority
        .map(|text| indexed(text, &mut reserve))
        .transpose()?
    {
        None => None,
        Some(Ok(index)) => Some(index),
        Some(Err(error)) => return Ok(Err(error)),
    };
    let priority = match priority_index.as_ref().map(Index::root) {
        None => None,
        Some(value) if value.kind() == Kind::Null => None,
        Some(value) => match to_bigint_reserving(Some(value), &mut reserve)? {
            Ok(Parsed::Value(priority)) => Some(priority.compact()),
            // Negative, or above any gas price that can be quoted.
            Ok(Parsed::TooWide { .. }) => None,
            Err(error) => return Ok(Err(error)),
        },
    };
    drop(priority_index);
    let gas_price = match gas_price {
        GasPrice::Fits(value) => value,
        GasPrice::Wide => {
            reserve(small)?;
            return Ok(Err(JsError::new(
                "Error",
                format!("{source} returned a gas price wider than {MAX_DECIMAL_BITS} bits")
                    .as_str(),
            )));
        }
    };
    reserve(QUOTE_BYTES.saturating_add(source.len()))?;
    // A usable hint: 0 ≤ P ≤ G.
    Ok(Ok(match priority {
        Some(priority)
            if !priority.is_negative()
                && priority.compare(&gas_price) != std::cmp::Ordering::Greater =>
        {
            let base = gas_price.minus(&priority);
            QuoteStep::Values(QuoteValues::eip1559(gas_price, base, &priority))
        }
        _ => QuoteStep::NeedsBlock(Unpriced { gas_price }),
    }))
}

impl Unpriced {
    /// What it holds on the heap.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.gas_price.heap_bytes()
    }

    /// The last part of the codec (main's `blockBaseFee`): the quote its
    /// source's block prices, or the last resort a failed read leaves.
    ///
    /// - **A failed read,** a result that is `undefined`, `null` or not an
    ///   object (an array is one), a base fee `BigInt` can't read, a
    ///   negative one, or one wider than [`MAX_DECIMAL_BITS`] bits
    ///   (deviation `bigint-width`): the last resort.
    /// - **No base fee** (`baseFeePerGas` missing, `undefined` or `null`):
    ///   legacy.
    /// - **A base fee:** EIP-1559 at it, with the source's own tip
    ///   suggestion max(G − base, 0), floored.
    pub(crate) fn with_block_reserving<E>(
        self,
        block: FeeBlock<'_>,
        mut reserve: impl FnMut(usize) -> Result<(), E>,
    ) -> Result<Result<QuoteValues, LastResort>, E> {
        let last = |gas_price| Ok(Err(LastResort { gas_price }));
        let FeeBlock::Result(Some(text)) = block else {
            return last(self.gas_price);
        };
        let index = match indexed(text, &mut reserve)? {
            Ok(index) => index,
            Err(_) => return last(self.gas_price),
        };
        let root = index.root();
        let base_fee = match root.kind() {
            Kind::Object => root.get("baseFeePerGas"),
            Kind::Array => None,
            _ => return last(self.gas_price),
        };
        let base = match base_fee {
            None => None,
            Some(value) if value.kind() == Kind::Null => None,
            Some(value) => match to_bigint_reserving(Some(value), &mut reserve)? {
                Ok(Parsed::Value(base))
                    if !base.is_negative() && base.bits() <= MAX_DECIMAL_BITS =>
                {
                    Some(base.compact())
                }
                Ok(_) | Err(_) => return last(self.gas_price),
            },
        };
        drop(index);
        reserve(QUOTE_BYTES)?;
        Ok(Ok(match base {
            None => QuoteValues {
                gas_price: self.gas_price,
                priced: Priced::Legacy,
            },
            Some(base) => {
                let tip = if self.gas_price.compare(&base) == std::cmp::Ordering::Greater {
                    self.gas_price.minus(&base)
                } else {
                    BigInt::zero()
                };
                QuoteValues::eip1559(self.gas_price, base, &tip)
            }
        }))
    }
}

/// The lowest priority fee among EIP-1559 quotes, their floored tips, in
/// decimal: `None` when none is EIP-1559 (design 0005, A:
/// `chain.fee_reference`'s `lowest_priority`).
pub fn lowest_priority(quotes: &[QuoteValues]) -> Option<String> {
    quotes
        .iter()
        .filter_map(|quote| match &quote.priced {
            Priced::Eip1559 { tip, .. } => Some(tip),
            Priced::Legacy => None,
        })
        .reduce(|lowest, tip| lowest.min(tip))
        .map(BigInt::to_decimal)
}

/// `answered` as the reply writes it: the number of endpoints combined.
fn answered_of(count: usize) -> Option<u8> {
    Some(u8::try_from(count).unwrap_or(u8::MAX))
}

/// B's combination of Direct's answered quotes (design 0005, B: combining
/// Direct's quotes; deviation `fee-combination`, as amended for main's
/// #749), `None` for none. Each quote is read as two constraints, as it
/// signs them, headroom included: a max fee per gas M and a priority fee P
/// ([`QuoteValues`]); the combination keeps the tightest:
///
/// - **One answer:** that quote, unchanged.
/// - **All EIP-1559,** or **mixed where EIP-1559 is verified**
///   (`eip1559_verified`: a verified header has a base fee), a legacy
///   quote counting as M = P = its signed gas price: EIP-1559 with the
///   lowest M and the lowest P. `baseFee` is ⌊(M − P)/2⌋ and
///   `effectiveGasPrice` is `baseFee` + P: estimates for display, never
///   above any answering endpoint's `effectiveGasPrice`.
/// - **All legacy:** legacy, at the lowest signed gas price.
/// - **Mixed otherwise:** legacy, at the lowest raw gas price of all the
///   quotes, with the headroom applied once (⌊G·125/100⌋ + the floor).
///
/// The quote is Direct's: `source` `direct`, never `verified`, and
/// `answered` the number of quotes combined.
pub fn combine_fee_quotes(quotes: &[QuoteValues], eip1559_verified: bool) -> Option<FeeQuote> {
    let (first, rest) = quotes.split_first()?;
    let answered = answered_of(quotes.len());
    let source = String::from("direct");
    if rest.is_empty() {
        return Some(first.quote("direct").answered_by(answered));
    }
    let all_eip1559 = quotes.iter().all(QuoteValues::is_eip1559);
    let all_legacy = !quotes.iter().any(QuoteValues::is_eip1559);
    if all_legacy || (!all_eip1559 && !eip1559_verified) {
        let gas_price = rest.iter().fold(&first.gas_price, |lowest, quote| {
            lowest.min(&quote.gas_price)
        });
        return Some(FeeQuote::Legacy {
            gas_price: legacy_headroom(gas_price).to_decimal(),
            source,
            verified: false,
            answered,
            base_fee_source: None,
        });
    }
    let (mut max_fee, mut priority) = first.constraints();
    for quote in rest {
        let (m, p) = quote.constraints();
        if m.compare(&max_fee) == std::cmp::Ordering::Less {
            max_fee = m;
        }
        if p.compare(&priority) == std::cmp::Ordering::Less {
            priority = p;
        }
    }
    // Every quote's P is at most its M, so the lowest P is at most the
    // lowest M.
    let base_fee = max_fee.minus(&priority).half();
    Some(FeeQuote::Eip1559 {
        effective_gas_price: base_fee.plus(&priority).to_decimal(),
        base_fee: base_fee.to_decimal(),
        max_priority_fee_per_gas: priority.to_decimal(),
        max_fee_per_gas: max_fee.to_decimal(),
        source,
        verified: false,
        answered,
        base_fee_source: None,
    })
}

/// Direct's last resort when every answering endpoint failed at its block
/// read (design 0005, B: No quote, as amended for main's #749): legacy at
/// the headroom of their lowest raw gas price, `answered` the number of
/// those endpoints. `None` for none.
pub fn combine_last_resorts(last: &[LastResort]) -> Option<FeeQuote> {
    let (first, rest) = last.split_first()?;
    let gas_price = rest
        .iter()
        .fold(&first.gas_price, |lowest, last| lowest.min(&last.gas_price));
    Some(FeeQuote::Legacy {
        gas_price: legacy_headroom(gas_price).to_decimal(),
        source: String::from("direct"),
        verified: false,
        answered: answered_of(last.len()),
        base_fee_source: None,
    })
}

/// A value's index, its heap reserved before it is built.
fn indexed<'t, E>(
    text: &'t str,
    reserve: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<Result<Index<'t>, JsError>, E> {
    match Index::heap_needed(text) {
        Ok(bytes) => reserve(bytes)?,
        Err(error) => return Ok(Err(not_json(error))),
    }
    Ok(Index::new(text).map_err(not_json))
}

fn not_json(_: fc_json::index::IndexError) -> JsError {
    JsError::new("SyntaxError", "The fee value is not valid JSON")
}

/// `BigInt(value)` for a JSON value (`None` is `undefined`).
pub(crate) fn to_bigint(value: Option<Value<'_, '_>>) -> Result<Parsed, JsError> {
    match to_bigint_reserving(value, &mut |_| Ok::<(), std::convert::Infallible>(())) {
        Ok(parsed) => parsed,
        Err(never) => match never {},
    }
}

/// What parsing `units` of text into a `BigInt` can hold: hex, octal or
/// binary limbs (at most half a byte per unit), or a decimal's, which is
/// refused past [`MAX_DECIMAL_BITS`].
fn parse_bytes(units: usize) -> usize {
    (units / 2).saturating_add(MAX_DECIMAL_BITS)
}

/// [`to_bigint`], asking `reserve` for room before each allocation: the
/// string's units, an array's or object's joined text and the stack that
/// walks it, the limbs, and an error's message.
fn to_bigint_reserving<E>(
    value: Option<Value<'_, '_>>,
    reserve: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<Result<Parsed, JsError>, E> {
    const MESSAGE: usize = 256;
    let Some(value) = value else {
        reserve(MESSAGE)?;
        return Ok(Err(JsError::new(
            "TypeError",
            "Cannot convert undefined to a BigInt",
        )));
    };
    let string = match value.kind() {
        Kind::Null => {
            reserve(MESSAGE)?;
            return Ok(Err(JsError::new(
                "TypeError",
                "Cannot convert null to a BigInt",
            )));
        }
        Kind::True => return Ok(Ok(Parsed::Value(BigInt::from_u64(1)))),
        Kind::False => return Ok(Ok(Parsed::Value(BigInt::zero()))),
        Kind::Number => {
            // At most 1,024 bits of limbs, or a short message.
            reserve(MESSAGE)?;
            let number = value.number();
            return Ok(BigInt::from_f64(number).map(Parsed::Value).ok_or_else(|| {
                JsError::new(
                    "RangeError",
                    format!(
                        "The number {} cannot be converted to a BigInt because it is not an integer",
                        number_to_string(number)
                    )
                    .as_str(),
                )
            }));
        }
        Kind::String => {
            let units = value.units().count();
            reserve(units.saturating_mul(2))?;
            let mut text = Vec::with_capacity(units);
            text.extend(value.units());
            JsString::from_units(text)
        }
        // ToPrimitive: an array's joined string, `[object Object]`, or a
        // TypeError for an own `toString` (never callable in JSON), known
        // before any of the text is built.
        Kind::Array | Kind::Object => match js_string_reserving(value, reserve)? {
            Some(text) => text,
            None => {
                reserve(MESSAGE)?;
                return Ok(Err(JsError::new("TypeError", NOT_PRIMITIVE)));
            }
        },
    };
    reserve(parse_bytes(string.len()))?;
    if let Some(parsed) = parse_string(string.units()) {
        return Ok(Ok(parsed));
    }
    // V8 quotes at most 1,000 code units of the string.
    reserve(string.len().min(1000).saturating_add(32).saturating_mul(2))?;
    let mut message = JsString::from("Cannot convert ");
    match string.units().get(..1000) {
        Some(head) if string.len() > 1000 => {
            message.push_units(head);
            message.push_str("\u{2026}");
        }
        _ => message.push_units(string.units()),
    }
    message.push_str(" to a BigInt");
    Ok(Err(JsError {
        name: "SyntaxError",
        message,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_BASE_FEE: FeeBlock<'static> = FeeBlock::Result(Some(r#"{"number":"0x10"}"#));

    fn quote(source: &str, gas: &str, priority: Option<&str>) -> FeeQuote {
        match fee_quote(source, Some(gas), priority, Some(NO_BASE_FEE)) {
            FeeOutcome::Quote(quote) => quote,
            other => panic!("{other:?}"),
        }
    }

    fn error(source: &str, gas: Option<&str>, priority: Option<&str>) -> JsError {
        match fee_quote(source, gas, priority, Some(NO_BASE_FEE)) {
            FeeOutcome::Error(error) => error,
            other => panic!("{other:?}"),
        }
    }

    /// The whole codec, every allocation asked of `reserve` first.
    fn reserving<E>(
        source: &str,
        gas: Option<&str>,
        priority: Option<&str>,
        mut reserve: impl FnMut(usize) -> Result<(), E>,
    ) -> Result<Result<QuoteValues, JsError>, E> {
        let read = match gas_price_reserving(source, gas, &mut reserve)? {
            Ok(read) => read,
            Err(error) => return Ok(Err(error)),
        };
        Ok(
            match quote_step_reserving(source, read, priority, &mut reserve)? {
                Ok(QuoteStep::Values(values)) => Ok(values),
                Ok(QuoteStep::NeedsBlock(unpriced)) => {
                    match unpriced.with_block_reserving(NO_BASE_FEE, &mut reserve)? {
                        Ok(values) => Ok(values),
                        Err(last) => panic!("{last:?}"),
                    }
                }
                Err(error) => Err(error),
            },
        )
    }

    #[test]
    fn quotes() {
        // A usable hint: its tip floored at 0.05 gwei, 2·base + tip.
        assert_eq!(
            quote("quorum", r#""0x10""#, Some(r#""0x1""#)).to_json(),
            r#"{"type":"eip1559","baseFee":"15","maxPriorityFeePerGas":"50000000","maxFeePerGas":"50000030","effectiveGasPrice":"50000015","source":"quorum","verified":true}"#
        );
        assert_eq!(
            quote("myotis", r#""20000000000""#, Some(r#""2000000000""#)).to_json(),
            r#"{"type":"eip1559","baseFee":"18000000000","maxPriorityFeePerGas":"2000000000","maxFeePerGas":"38000000000","effectiveGasPrice":"20000000000","source":"myotis","verified":true}"#
        );
        // A hint over the gas price, priced from a block without a base
        // fee: legacy at 125% + the floor.
        assert_eq!(
            quote("direct", "16", Some("17")).to_json(),
            r#"{"type":"legacy","gasPrice":"50000020","effectiveGasPrice":"50000020","source":"direct","verified":false}"#
        );
        assert_eq!(
            error("x", Some("0"), Some("{")).message.to_string_lossy(),
            "x returned a non-positive gas price"
        );
        assert_eq!(error("x", None, None).name, "TypeError");
        // Without a block, a hint that can't price a quote asks for one.
        assert_eq!(
            fee_quote("direct", Some("16"), None, None),
            FeeOutcome::NeedsBlock
        );
        // A block with a base fee: G − base as the tip, floored.
        let priced = |block: &str| {
            fee_quote(
                "direct",
                Some("100000000000"),
                None,
                Some(FeeBlock::Result(Some(block))),
            )
        };
        assert_eq!(
            priced(r#"{"baseFeePerGas":"0x12a05f2000"}"#),
            FeeOutcome::Quote(FeeQuote::Eip1559 {
                base_fee: "80000000000".into(),
                max_priority_fee_per_gas: "20000000000".into(),
                max_fee_per_gas: "180000000000".into(),
                effective_gas_price: "100000000000".into(),
                source: "direct".into(),
                verified: false,
                answered: None,
                base_fee_source: None,
            })
        );
        // A failed read, or a block that isn't one: the last resort.
        for block in [
            FeeBlock::Failed,
            FeeBlock::Result(None),
            FeeBlock::Result(Some("null")),
            FeeBlock::Result(Some(r#""0x11""#)),
            FeeBlock::Result(Some(r#"{"baseFeePerGas":"-1"}"#)),
            FeeBlock::Result(Some(r#"{"baseFeePerGas":"xyz"}"#)),
        ] {
            match fee_quote("direct", Some("100"), None, Some(block)) {
                FeeOutcome::LastResort(last) => assert_eq!(
                    last.quote("direct").to_json(),
                    r#"{"type":"legacy","gasPrice":"50000125","effectiveGasPrice":"50000125","source":"direct","verified":false}"#,
                    "{block:?}"
                ),
                other => panic!("{block:?}: {other:?}"),
            }
        }
        // The reserving codec answers the same, asks for each index before
        // building it, and stops when refused.
        let gas = format!("[{}]", vec!["null"; 1_000].join(","));
        for (gas, priority) in [
            (gas.as_str(), Some(r#""0x1""#)),
            (r#""0x10""#, Some(r#""0x1""#)),
            ("16", None),
            ("[[1,2]]", None),
            ("{}", None),
            ("1.5", None),
        ] {
            let mut asked = Vec::new();
            let quoted = reserving("x", Some(gas), priority, |bytes| {
                asked.push(bytes);
                Ok::<(), ()>(())
            });
            let whole = match fee_quote_values("x", Some(gas), priority, Some(NO_BASE_FEE)) {
                FeeOutcome::Quote(values) => Ok(values),
                FeeOutcome::Error(error) => Err(error),
                other => panic!("{other:?}"),
            };
            assert_eq!(quoted, Ok(whole));
            assert_eq!(asked.first(), Some(&Index::heap_needed(gas).unwrap()));
        }
        // A conversion that throws is known before any of its text is
        // built: an object with its own `toString`, after a long string or
        // before it, is the same TypeError, with nothing of the string
        // reserved.
        let long = "a".repeat(100_000);
        for gas in [
            format!(r#"["{long}",{{"toString":null}}]"#),
            format!(r#"[{{"toString":null}},"{long}"]"#),
            format!(r#"[["{long}"],[{{"x":1,"toString":"f"}}]]"#),
            r#"{"toString":1}"#.to_owned(),
        ] {
            let mut asked = 0usize;
            let quoted = reserving("x", Some(&gas), None, |bytes| {
                asked += bytes;
                Ok::<(), ()>(())
            });
            let index = Index::new(&gas).unwrap();
            let thrown = crate::js::js_string_of(index.root()).unwrap_err();
            assert_eq!(quoted, Ok(Err(thrown)), "{gas}");
            assert!(
                asked < Index::heap_needed(&gas).unwrap() + 64 * 1024,
                "{asked}"
            );
        }
        let refused = reserving("x", Some(&gas), None, |bytes| {
            if bytes > 1_000 { Err("over") } else { Ok(()) }
        });
        assert_eq!(refused, Err("over"));
        for quote in [
            quote("quorum", r#""0x10""#, Some(r#""0x1""#)),
            quote("dir\"ect", "16", None),
            quote("myotis", "16", None).priced_from("col\"ibri", false),
        ] {
            assert_eq!(quote.json_len(), quote.to_json().len());
            assert_eq!(quote.answered(), None);
        }
        assert_eq!(
            error("x", Some("[[1,2]]"), None).message.to_string_lossy(),
            "Cannot convert 1,2 to a BigInt"
        );
        // A Myotis quote priced from a block the read path read: named, and
        // only as verified as that read.
        assert_eq!(
            quote("myotis", "16", None)
                .priced_from("colibri", true)
                .to_json(),
            r#"{"type":"legacy","gasPrice":"50000020","effectiveGasPrice":"50000020","source":"myotis","verified":true,"baseFeeSource":"colibri"}"#
        );
        assert_eq!(
            quote("myotis", "16", None)
                .priced_from("direct", false)
                .to_json(),
            r#"{"type":"legacy","gasPrice":"50000020","effectiveGasPrice":"50000020","source":"myotis","verified":false,"baseFeeSource":"direct"}"#
        );
    }

    #[test]
    fn combinations() {
        const GWEI: u64 = 1_000_000_000;
        let values = |gas: u64, priority: Option<u64>| {
            let (gas, priority) = (gas.to_string(), priority.map(|p| p.to_string()));
            match fee_quote_values("direct", Some(&gas), priority.as_deref(), Some(NO_BASE_FEE)) {
                FeeOutcome::Quote(values) => values,
                other => panic!("{other:?}"),
            }
        };
        // Hints of 60,000,001 and 60,000,000 at 1 gwei: M − P odd.
        let combined = combine_fee_quotes(
            &[
                values(GWEI, Some(60_000_001)),
                values(GWEI, Some(60_000_000)),
            ],
            false,
        )
        .unwrap();
        assert_eq!(
            combined.to_json(),
            r#"{"type":"eip1559","baseFee":"939999999","maxPriorityFeePerGas":"60000000","maxFeePerGas":"1939999999","effectiveGasPrice":"999999999","source":"direct","verified":false,"answered":2}"#
        );
        assert_eq!(combined.answered(), Some(2));
        // One answer: the endpoint's quote, marked.
        let one = combine_fee_quotes(&[values(16 * GWEI, Some(17 * GWEI))], true).unwrap();
        assert_eq!(
            one.to_json(),
            r#"{"type":"legacy","gasPrice":"20050000000","effectiveGasPrice":"20050000000","source":"direct","verified":false,"answered":1}"#
        );
        for quote in [combined, one] {
            assert_eq!(quote.json_len(), quote.to_json().len());
        }
        assert_eq!(combine_fee_quotes(&[], true), None);
        // Mixed: EIP-1559 only where it is verified; otherwise legacy at
        // the headroom of the lowest raw gas price.
        let mixed = [values(100 * GWEI, Some(GWEI)), values(1000 * GWEI, None)];
        assert_eq!(
            combine_fee_quotes(&mixed, true).unwrap().to_json(),
            r#"{"type":"eip1559","baseFee":"99000000000","maxPriorityFeePerGas":"1000000000","maxFeePerGas":"199000000000","effectiveGasPrice":"100000000000","source":"direct","verified":false,"answered":2}"#
        );
        assert_eq!(
            combine_fee_quotes(&mixed, false).unwrap().to_json(),
            r#"{"type":"legacy","gasPrice":"125050000000","effectiveGasPrice":"125050000000","source":"direct","verified":false,"answered":2}"#
        );
        // The lowest floored tip among EIP-1559 quotes only.
        assert_eq!(
            lowest_priority(&[
                values(100 * GWEI, Some(9 * GWEI)),
                values(5, None),
                values(100 * GWEI, Some(10 * GWEI)),
                values(100, Some(1)),
            ])
            .as_deref(),
            Some("50000000")
        );
        assert_eq!(lowest_priority(&[values(5, None)]), None);
        assert_eq!(lowest_priority(&[]), None);
        assert!(values(100, Some(1)).is_eip1559());
        assert_eq!(
            values(100 * GWEI, Some(GWEI)).priority_decimal().as_deref(),
            Some("1000000000")
        );
        assert_eq!(values(100, Some(101)).priority_decimal(), None);
        // The last resort: the headroom of the lowest raw gas price.
        let last = |gas: u64| match fee_quote_values(
            "direct",
            Some(&gas.to_string()),
            None,
            Some(FeeBlock::Failed),
        ) {
            FeeOutcome::LastResort(last) => last,
            other => panic!("{other:?}"),
        };
        let resort = combine_last_resorts(&[last(40 * GWEI), last(30 * GWEI)]).unwrap();
        assert_eq!(
            resort.to_json(),
            r#"{"type":"legacy","gasPrice":"37550000000","effectiveGasPrice":"37550000000","source":"direct","verified":false,"answered":2}"#
        );
        assert_eq!(combine_last_resorts(&[]), None);
    }

    // The codec in parts, the gas price read first: the same quote or error
    // as the whole, and only the value kept of a long text.
    #[test]
    fn gas_price_first() {
        let wide = format!("\"0x1{}\"", "0".repeat(1_100));
        for (gas, priority) in [
            (r#""0x64""#, Some(r#""0x1""#)),
            (r#""0x64""#, Some("{")),
            (r#""0xzz""#, Some("{")),
            ("0", Some("{")),
            (wide.as_str(), Some("{")),
            (wide.as_str(), Some(r#""0x1""#)),
            (r#""0x64""#, Some(r#""0x65""#)),
        ] {
            let parts = reserving("x", Some(gas), priority, |_| Ok::<(), ()>(())).unwrap();
            let whole = match fee_quote_values("x", Some(gas), priority, Some(NO_BASE_FEE)) {
                FeeOutcome::Quote(values) => Ok(values),
                FeeOutcome::Error(error) => Err(error),
                other => panic!("{other:?}"),
            };
            assert_eq!(parts, whole, "{gas:.20} {priority:?}");
        }
        // Leading zeros: the value keeps none of its text's room.
        let padded = format!("\"0x{}64\"", "0".repeat(64 * 1024));
        let read = gas_price_reserving("x", Some(&padded), |_| Ok::<(), ()>(()))
            .unwrap()
            .unwrap();
        assert_eq!(read, GasPrice::Fits(BigInt::from_u64(100)));
        assert!(read.heap_bytes() <= 8);
        let quoted = match quote_step_reserving("x", read, Some(&padded), |_| Ok::<(), ()>(()))
            .unwrap()
            .unwrap()
        {
            QuoteStep::Values(values) => values,
            other => panic!("{other:?}"),
        };
        assert!(quoted.heap_bytes() <= 24);
        // A block's base fee alike.
        let unpriced = Unpriced {
            gas_price: BigInt::from_u64(100),
        };
        let block = format!(r#"{{"baseFeePerGas":"0x{}50"}}"#, "0".repeat(64 * 1024));
        let priced = unpriced
            .with_block_reserving(FeeBlock::Result(Some(&block)), |_| Ok::<(), ()>(()))
            .unwrap()
            .unwrap();
        assert!(priced.heap_bytes() <= 24);
    }

    #[test]
    fn big_arithmetic() {
        let big = |n: u64| BigInt::from_u64(n);
        assert_eq!(legacy_headroom(&big(7)).to_decimal(), "50000008");
        assert_eq!(legacy_headroom(&big(100)).to_decimal(), "50000125");
        assert_eq!(
            big(u64::MAX).times(125).divided(100).to_decimal(),
            "23058430092136939518"
        );
        assert_eq!(floored(&big(1)).to_decimal(), "50000000");
        assert_eq!(floored(&big(60_000_000)).to_decimal(), "60000000");
    }
}
