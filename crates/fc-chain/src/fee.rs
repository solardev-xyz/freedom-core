//! `feeQuote`: today's quote from one source's gas price and priority fee.
//!
//! - `BigInt(gasPrice)`, with JavaScript's conversions and their errors: a
//!   string as `BigInt(string)` reads it, a number only when an integer,
//!   `true` as 1, an array as its joined string, `null` and `undefined`
//!   refused.
//! - A gas price of zero or less is refused.
//! - **Legacy** when there's no priority fee (`null` or `undefined`), or it
//!   is negative or above the gas price.
//! - Otherwise **EIP-1559**: `baseFee = gasPrice - priority`, `maxFeePerGas
//!   = 2 * baseFee + priority`.
//! - Decimal strings; `verified` for myotis, colibri and quorum. The
//!   machine unverifies a quorum's quote when its m is 1 (deviation
//!   `singleton-quorum`).
//!
//! A gas price of 2^4096 or more fails the source (deviation
//! `bigint-width`), where the router would quote it.
//!
//! B's combination of Direct's quotes ([`combine_fee_quotes`], deviation
//! `fee-combination`) reads each endpoint's quote from the same codec
//! ([`QuoteValues`]) and keeps the tightest constraints.

use fc_json::index::{Index, Kind, Value, quoted_len};
use fc_json::number_to_string;

use crate::bigint::{BigInt, MAX_DECIMAL_BITS, Parsed, parse_string};
use crate::js::{JsError, JsString, NOT_PRIMITIVE, js_string_reserving};

/// A fee quote, in today's shape.
///
/// `answered` is B's mark on Direct's quotes (design 0005, deviation
/// `fee-combination`): the number of endpoints whose quotes were combined,
/// written after `verified`. Every other quote has none, and keeps today's
/// shape exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeQuote {
    Legacy {
        gas_price: String,
        source: String,
        verified: bool,
        answered: Option<u8>,
    },
    Eip1559 {
        base_fee: String,
        max_priority_fee_per_gas: String,
        max_fee_per_gas: String,
        effective_gas_price: String,
        source: String,
        verified: bool,
        answered: Option<u8>,
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
            } => {
                r#"{"type":"legacy","gasPrice":"","effectiveGasPrice":"","source":,"verified":}"#
                    .len()
                    + 2 * gas_price.len()
                    + quoted(source)
                    + flag(*verified)
                    + answered_len(*answered)
            }
            Self::Eip1559 {
                base_fee,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                effective_gas_price,
                source,
                verified,
                answered,
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

    /// What its texts hold on the heap.
    pub fn heap_bytes(&self) -> usize {
        match self {
            Self::Legacy {
                gas_price, source, ..
            } => gas_price.capacity() + source.capacity(),
            Self::Eip1559 {
                base_fee,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                effective_gas_price,
                source,
                ..
            } => {
                base_fee.capacity()
                    + max_priority_fee_per_gas.capacity()
                    + max_fee_per_gas.capacity()
                    + effective_gas_price.capacity()
                    + source.capacity()
            }
        }
    }

    /// `JSON.stringify(quote)`, keys in the router's order, then B's
    /// `answered`.
    pub fn to_json(&self) -> String {
        let quote = |text: &str| JsString::from(text).to_json();
        match self {
            Self::Legacy {
                gas_price,
                source,
                verified,
                answered,
            } => format!(
                r#"{{"type":"legacy","gasPrice":"{gas_price}","effectiveGasPrice":"{gas_price}","source":{},"verified":{verified}{}}}"#,
                quote(source),
                answered_json(*answered),
            ),
            Self::Eip1559 {
                base_fee,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                effective_gas_price,
                source,
                verified,
                answered,
            } => format!(
                r#"{{"type":"eip1559","baseFee":"{base_fee}","maxPriorityFeePerGas":"{max_priority_fee_per_gas}","maxFeePerGas":"{max_fee_per_gas}","effectiveGasPrice":"{effective_gas_price}","source":{},"verified":{verified}{}}}"#,
                quote(source),
                answered_json(*answered),
            ),
        }
    }
}

/// One source's quote as `feeQuote` accepts it, kept as numbers: its gas
/// price G and, when the quote is EIP-1559, its priority fee P. B combines
/// Direct's quotes from these (design 0005, B: combining Direct's quotes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteValues {
    gas_price: BigInt,
    /// `None` for a legacy quote: no hint, or one negative or above G.
    priority: Option<BigInt>,
}

impl QuoteValues {
    /// Whether the quote is EIP-1559.
    pub fn is_eip1559(&self) -> bool {
        self.priority.is_some()
    }

    /// An EIP-1559 quote's priority fee, in decimal.
    pub fn priority_decimal(&self) -> Option<String> {
        self.priority.as_ref().map(BigInt::to_decimal)
    }

    /// The quote today's codec makes of them, from `source`: EIP-1559 with
    /// `baseFee = G − P` and `maxFeePerGas = 2·baseFee + P`, or legacy.
    pub fn quote(&self, source: &str) -> FeeQuote {
        let verified = matches!(source, "myotis" | "colibri" | "quorum");
        let source = source.to_owned();
        match &self.priority {
            Some(priority) => {
                let base_fee = self.gas_price.minus(priority);
                FeeQuote::Eip1559 {
                    max_fee_per_gas: base_fee.plus(&base_fee).plus(priority).to_decimal(),
                    base_fee: base_fee.to_decimal(),
                    max_priority_fee_per_gas: priority.to_decimal(),
                    effective_gas_price: self.gas_price.to_decimal(),
                    source,
                    verified,
                    answered: None,
                }
            }
            None => FeeQuote::Legacy {
                gas_price: self.gas_price.to_decimal(),
                source,
                verified,
                answered: None,
            },
        }
    }

    /// What its numbers hold on the heap.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.gas_price.heap_bytes() + self.priority.as_ref().map_or(0, BigInt::heap_bytes)
    }

    /// The two constraints B reads it as: the max fee per gas M and the
    /// priority fee P. An EIP-1559 quote gives `2·G − P` and P; a legacy
    /// one M = P = G. P is never above M.
    fn constraints(&self) -> (BigInt, BigInt) {
        match &self.priority {
            Some(priority) => {
                let base_fee = self.gas_price.minus(priority);
                (base_fee.plus(&base_fee).plus(priority), priority.clone())
            }
            None => (self.gas_price.clone(), self.gas_price.clone()),
        }
    }
}

/// `feeQuote(source, gasPrice, priority)`, each value given as its JSON
/// text, `None` being `undefined`. The error is the one the router throws.
pub fn fee_quote(
    source: &str,
    gas_price: Option<&str>,
    priority: Option<&str>,
) -> Result<FeeQuote, JsError> {
    fee_quote_values(source, gas_price, priority).map(|values| values.quote(source))
}

/// [`fee_quote`]'s values, before they are written as a quote.
pub fn fee_quote_values(
    source: &str,
    gas_price: Option<&str>,
    priority: Option<&str>,
) -> Result<QuoteValues, JsError> {
    match fee_quote_values_reserving(source, gas_price, priority, |_| {
        Ok::<(), std::convert::Infallible>(())
    }) {
        Ok(values) => values,
        Err(never) => match never {},
    }
}

/// The most a quote's text, or one of its errors, holds: four decimals of
/// at most [`MAX_DECIMAL_BITS`] bits (1,234 digits each), and the
/// arithmetic's values, besides the source's name.
pub(crate) const QUOTE_BYTES: usize = 8 * 1024;

/// [`fee_quote`], asking `reserve` for room before each allocation: each
/// value's index, its conversion's text and stack, the `BigInt`'s limbs,
/// an error's message and the quote. An `Err` from `reserve` stops the
/// codec before it allocates.
pub fn fee_quote_reserving<E>(
    source: &str,
    gas_price: Option<&str>,
    priority: Option<&str>,
    reserve: impl FnMut(usize) -> Result<(), E>,
) -> Result<Result<FeeQuote, JsError>, E> {
    Ok(
        fee_quote_values_reserving(source, gas_price, priority, reserve)?
            .map(|values| values.quote(source)),
    )
}

/// [`fee_quote_values`], asking `reserve` for room before each allocation
/// as [`fee_quote_reserving`] does, the quote's room included.
pub fn fee_quote_values_reserving<E>(
    source: &str,
    gas_price: Option<&str>,
    priority: Option<&str>,
    mut reserve: impl FnMut(usize) -> Result<(), E>,
) -> Result<Result<QuoteValues, JsError>, E> {
    match gas_price_reserving(source, gas_price, &mut reserve)? {
        Ok(gas_price) => fee_quote_values_with_reserving(source, gas_price, priority, reserve),
        Err(error) => Ok(Err(error)),
    }
}

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

/// The first half of [`fee_quote_values_reserving`]: the gas price read
/// alone, its errors (no JSON, no `BigInt`, not positive) the codec's,
/// with every allocation asked of `reserve` first. A caller can read the
/// gas price as it arrives and keep only this while the priority fee is
/// asked for, so an endpoint's raw answer isn't kept across that request;
/// the second half, [`fee_quote_values_with_reserving`], gives the same
/// quote or error the whole codec gives.
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

/// The second half of [`fee_quote_values_reserving`]: the quote of a gas
/// price [`gas_price_reserving`] read, with `priority`'s text.
pub(crate) fn fee_quote_values_with_reserving<E>(
    source: &str,
    gas_price: GasPrice,
    priority: Option<&str>,
    mut reserve: impl FnMut(usize) -> Result<(), E>,
) -> Result<Result<QuoteValues, JsError>, E> {
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
    // Legacy when the hint is negative or above the gas price.
    let priority = priority.filter(|priority| {
        !priority.is_negative() && priority.compare(&gas_price) != std::cmp::Ordering::Greater
    });
    Ok(Ok(QuoteValues {
        gas_price,
        priority,
    }))
}

/// The lowest priority fee among EIP-1559 quotes, in decimal: `None` when
/// none gave a valid hint (design 0005, A: `chain.fee_reference`'s
/// `lowest_priority`).
pub fn lowest_priority(quotes: &[QuoteValues]) -> Option<String> {
    quotes
        .iter()
        .filter_map(|quote| quote.priority.as_ref())
        .reduce(|lowest, priority| lowest.min(priority))
        .map(BigInt::to_decimal)
}

/// B's combination of Direct's answered quotes (design 0005, B: combining
/// Direct's quotes; deviation `fee-combination`), `None` for none. Each
/// quote is read as two constraints, a max fee per gas M and a priority
/// fee P ([`QuoteValues`]); the combination keeps the tightest:
///
/// - **One answer:** that quote, unchanged.
/// - **All EIP-1559,** or **mixed where EIP-1559 is verified**
///   (`eip1559_verified`: a verified header has a base fee), a legacy
///   quote counting as M = P = G: EIP-1559 with the lowest M and the
///   lowest P. `baseFee` is ⌊(M − P)/2⌋ and `effectiveGasPrice` is
///   `baseFee` + P: estimates for display, never above any answering
///   endpoint's gas price.
/// - **All legacy,** or **mixed otherwise:** legacy, at the lowest gas
///   price of all the quotes, an EIP-1559 quote's being its
///   `effectiveGasPrice` (G).
///
/// The quote is Direct's: `source` `direct`, never `verified`, and
/// `answered` the number of quotes combined.
pub fn combine_fee_quotes(quotes: &[QuoteValues], eip1559_verified: bool) -> Option<FeeQuote> {
    let (first, rest) = quotes.split_first()?;
    let answered = Some(u8::try_from(quotes.len()).unwrap_or(u8::MAX));
    let source = String::from("direct");
    if rest.is_empty() {
        return Some(match first.quote("direct") {
            FeeQuote::Legacy {
                gas_price,
                source,
                verified,
                ..
            } => FeeQuote::Legacy {
                gas_price,
                source,
                verified,
                answered,
            },
            FeeQuote::Eip1559 {
                base_fee,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                effective_gas_price,
                source,
                verified,
                ..
            } => FeeQuote::Eip1559 {
                base_fee,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                effective_gas_price,
                source,
                verified,
                answered,
            },
        });
    }
    let all_eip1559 = quotes.iter().all(QuoteValues::is_eip1559);
    let all_legacy = !quotes.iter().any(QuoteValues::is_eip1559);
    if all_legacy || (!all_eip1559 && !eip1559_verified) {
        let gas_price = rest.iter().fold(&first.gas_price, |lowest, quote| {
            lowest.min(&quote.gas_price)
        });
        return Some(FeeQuote::Legacy {
            gas_price: gas_price.to_decimal(),
            source,
            verified: false,
            answered,
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

    #[test]
    fn quotes() {
        assert_eq!(
            fee_quote("quorum", Some(r#""0x10""#), Some(r#""0x1""#))
                .unwrap()
                .to_json(),
            r#"{"type":"eip1559","baseFee":"15","maxPriorityFeePerGas":"1","maxFeePerGas":"31","effectiveGasPrice":"16","source":"quorum","verified":true}"#
        );
        assert_eq!(
            fee_quote("direct", Some("16"), Some("17"))
                .unwrap()
                .to_json(),
            r#"{"type":"legacy","gasPrice":"16","effectiveGasPrice":"16","source":"direct","verified":false}"#
        );
        assert_eq!(
            fee_quote("x", Some("0"), Some("{"))
                .unwrap_err()
                .message
                .to_string_lossy(),
            "x returned a non-positive gas price"
        );
        assert_eq!(fee_quote("x", None, None).unwrap_err().name, "TypeError");
        // The reserving entry point answers the same, asks for each index
        // before building it, and stops when refused.
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
            let quoted = fee_quote_reserving("x", Some(gas), priority, |bytes| {
                asked.push(bytes);
                Ok::<(), ()>(())
            });
            assert_eq!(quoted, Ok(fee_quote("x", Some(gas), priority)));
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
            let quoted = fee_quote_reserving("x", Some(&gas), None, |bytes| {
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
        let refused = fee_quote_reserving("x", Some(&gas), None, |bytes| {
            if bytes > 1_000 { Err("over") } else { Ok(()) }
        });
        assert_eq!(refused, Err("over"));
        for quote in [
            fee_quote("quorum", Some(r#""0x10""#), Some(r#""0x1""#)).unwrap(),
            fee_quote("dir\"ect", Some("16"), None).unwrap(),
        ] {
            assert_eq!(quote.json_len(), quote.to_json().len());
            assert_eq!(quote.answered(), None);
        }
        assert_eq!(
            fee_quote("x", Some("[[1,2]]"), None)
                .unwrap_err()
                .message
                .to_string_lossy(),
            "Cannot convert 1,2 to a BigInt"
        );
    }

    #[test]
    fn combinations() {
        let values = |gas: &str, priority: Option<&str>| {
            fee_quote_values("direct", Some(gas), priority).unwrap()
        };
        // 10/1 with 10/2: M = 18, P = 1, and M − P odd.
        let combined =
            combine_fee_quotes(&[values("10", Some("1")), values("10", Some("2"))], false).unwrap();
        assert_eq!(
            combined.to_json(),
            r#"{"type":"eip1559","baseFee":"8","maxPriorityFeePerGas":"1","maxFeePerGas":"18","effectiveGasPrice":"9","source":"direct","verified":false,"answered":2}"#
        );
        assert_eq!(combined.answered(), Some(2));
        // One answer: today's quote, marked.
        let one = combine_fee_quotes(&[values("16", Some("17"))], true).unwrap();
        assert_eq!(
            one.to_json(),
            r#"{"type":"legacy","gasPrice":"16","effectiveGasPrice":"16","source":"direct","verified":false,"answered":1}"#
        );
        for quote in [combined, one] {
            assert_eq!(quote.json_len(), quote.to_json().len());
        }
        assert_eq!(combine_fee_quotes(&[], true), None);
        // Mixed: EIP-1559 only where it is verified.
        let mixed = [values("100", Some("1")), values("1000", None)];
        assert_eq!(
            combine_fee_quotes(&mixed, true).unwrap().to_json(),
            r#"{"type":"eip1559","baseFee":"99","maxPriorityFeePerGas":"1","maxFeePerGas":"199","effectiveGasPrice":"100","source":"direct","verified":false,"answered":2}"#
        );
        assert_eq!(
            combine_fee_quotes(&mixed, false).unwrap().to_json(),
            r#"{"type":"legacy","gasPrice":"100","effectiveGasPrice":"100","source":"direct","verified":false,"answered":2}"#
        );
        // The lowest hint among EIP-1559 quotes only.
        assert_eq!(
            lowest_priority(&[
                values("100", Some("9")),
                values("5", None),
                values("100", Some("10"))
            ])
            .as_deref(),
            Some("9")
        );
        assert_eq!(lowest_priority(&[values("5", None)]), None);
        assert_eq!(lowest_priority(&[]), None);
        assert!(values("100", Some("1")).is_eip1559());
        assert_eq!(
            values("100", Some("1")).priority_decimal().as_deref(),
            Some("1")
        );
        assert_eq!(values("100", Some("101")).priority_decimal(), None);
    }

    // The codec in two halves, the gas price read first: the same quote or
    // error as the whole, and only the value kept of a long text.
    #[test]
    fn gas_price_first() {
        let whole = |gas: &str, priority: Option<&str>| {
            fee_quote_values_reserving("x", Some(gas), priority, |_| Ok::<(), ()>(()))
        };
        let halves =
            |gas: &str, priority: Option<&str>| match gas_price_reserving("x", Some(gas), |_| {
                Ok::<(), ()>(())
            })? {
                Ok(read) => fee_quote_values_with_reserving("x", read, priority, |_| Ok(())),
                Err(error) => Ok(Err(error)),
            };
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
            assert_eq!(
                halves(gas, priority),
                whole(gas, priority),
                "{gas:.20} {priority:?}"
            );
        }
        // Leading zeros: the value keeps none of its text's room.
        let padded = format!("\"0x{}64\"", "0".repeat(64 * 1024));
        let read = gas_price_reserving("x", Some(&padded), |_| Ok::<(), ()>(()))
            .unwrap()
            .unwrap();
        assert_eq!(read, GasPrice::Fits(BigInt::from_u64(100)));
        assert!(read.heap_bytes() <= 8);
        let quoted =
            fee_quote_values_with_reserving("x", read, Some(&padded), |_| Ok::<(), ()>(()))
                .unwrap()
                .unwrap();
        assert!(quoted.heap_bytes() <= 16);
    }
}
