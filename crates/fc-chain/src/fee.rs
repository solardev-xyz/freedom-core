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
//! - Decimal strings; `verified` for myotis, colibri and quorum.
//!
//! A gas price of 2^4096 or more fails the source (deviation
//! `bigint-width`), where the router would quote it.

use fc_json::index::{Index, Kind, Value, quoted_len};
use fc_json::number_to_string;

use crate::bigint::{BigInt, MAX_DECIMAL_BITS, Parsed, parse_string};
use crate::js::{JsError, JsString, js_string_len, js_string_of, js_string_of_into};

/// A fee quote, in today's shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeQuote {
    Legacy {
        gas_price: String,
        source: String,
        verified: bool,
    },
    Eip1559 {
        base_fee: String,
        max_priority_fee_per_gas: String,
        max_fee_per_gas: String,
        effective_gas_price: String,
        source: String,
        verified: bool,
    },
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
            } => {
                r#"{"type":"legacy","gasPrice":"","effectiveGasPrice":"","source":,"verified":}"#
                    .len()
                    + 2 * gas_price.len()
                    + quoted(source)
                    + flag(*verified)
            }
            Self::Eip1559 {
                base_fee,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                effective_gas_price,
                source,
                verified,
            } => {
                r#"{"type":"eip1559","baseFee":"","maxPriorityFeePerGas":"","maxFeePerGas":"","effectiveGasPrice":"","source":,"verified":}"#
                    .len()
                    + base_fee.len()
                    + max_priority_fee_per_gas.len()
                    + max_fee_per_gas.len()
                    + effective_gas_price.len()
                    + quoted(source)
                    + flag(*verified)
            }
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

    /// `JSON.stringify(quote)`, keys in the router's order.
    pub fn to_json(&self) -> String {
        let quote = |text: &str| JsString::from(text).to_json();
        match self {
            Self::Legacy {
                gas_price,
                source,
                verified,
            } => format!(
                r#"{{"type":"legacy","gasPrice":"{gas_price}","effectiveGasPrice":"{gas_price}","source":{},"verified":{verified}}}"#,
                quote(source)
            ),
            Self::Eip1559 {
                base_fee,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                effective_gas_price,
                source,
                verified,
            } => format!(
                r#"{{"type":"eip1559","baseFee":"{base_fee}","maxPriorityFeePerGas":"{max_priority_fee_per_gas}","maxFeePerGas":"{max_fee_per_gas}","effectiveGasPrice":"{effective_gas_price}","source":{},"verified":{verified}}}"#,
                quote(source)
            ),
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
    match fee_quote_reserving(source, gas_price, priority, |_| {
        Ok::<(), std::convert::Infallible>(())
    }) {
        Ok(quote) => quote,
        Err(never) => match never {},
    }
}

/// The most a quote's text, or one of its errors, holds: four decimals of
/// at most [`MAX_DECIMAL_BITS`] bits (1,234 digits each), and the
/// arithmetic's values, besides the source's name.
const QUOTE_BYTES: usize = 8 * 1024;

/// [`fee_quote`], asking `reserve` for room before each allocation: each
/// value's index, its conversion's text and stack, the `BigInt`'s limbs,
/// an error's message and the quote. An `Err` from `reserve` stops the
/// codec before it allocates.
pub fn fee_quote_reserving<E>(
    source: &str,
    gas_price: Option<&str>,
    priority: Option<&str>,
    mut reserve: impl FnMut(usize) -> Result<(), E>,
) -> Result<Result<FeeQuote, JsError>, E> {
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
            Ok(Parsed::Value(priority)) => Some(priority),
            // Negative, or above any gas price that can be quoted.
            Ok(Parsed::TooWide { .. }) => None,
            Err(error) => return Ok(Err(error)),
        },
    };
    drop(priority_index);
    let gas_price = match gas_price {
        Parsed::Value(value) if value.bits() <= MAX_DECIMAL_BITS => value,
        _ => {
            reserve(small)?;
            return Ok(Err(JsError::new(
                "Error",
                format!("{source} returned a gas price wider than {MAX_DECIMAL_BITS} bits")
                    .as_str(),
            )));
        }
    };
    reserve(QUOTE_BYTES.saturating_add(source.len()))?;
    let verified = matches!(source, "myotis" | "colibri" | "quorum");
    let source = source.to_owned();
    Ok(Ok(match priority {
        Some(priority)
            if !priority.is_negative()
                && priority.compare(&gas_price) != std::cmp::Ordering::Greater =>
        {
            let base_fee = gas_price.minus(&priority);
            FeeQuote::Eip1559 {
                max_fee_per_gas: base_fee.plus(&base_fee).plus(&priority).to_decimal(),
                base_fee: base_fee.to_decimal(),
                max_priority_fee_per_gas: priority.to_decimal(),
                effective_gas_price: gas_price.to_decimal(),
                source,
                verified,
            }
        }
        _ => FeeQuote::Legacy {
            gas_price: gas_price.to_decimal(),
            source,
            verified,
        },
    }))
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
        // TypeError for an own `toString`. The walks' stacks hold at most
        // one frame per level.
        Kind::Array | Kind::Object => {
            let frame = std::mem::size_of_val(&(value.children(), true));
            reserve(frame.saturating_mul(2 * fc_json::MAX_DEPTH))?;
            // An own `toString` has no length: the conversion fails on it,
            // with a short message.
            let built = match js_string_len(value) {
                Some(units) => {
                    reserve(units.saturating_mul(2))?;
                    js_string_of_into(value, JsString::from_units(Vec::with_capacity(units)))
                }
                None => {
                    reserve(MESSAGE)?;
                    js_string_of(value)
                }
            };
            match built {
                Ok(text) => text,
                Err(error) => return Ok(Err(error)),
            }
        }
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
        let refused = fee_quote_reserving("x", Some(&gas), None, |bytes| {
            if bytes > 1_000 { Err("over") } else { Ok(()) }
        });
        assert_eq!(refused, Err("over"));
        for quote in [
            fee_quote("quorum", Some(r#""0x10""#), Some(r#""0x1""#)).unwrap(),
            fee_quote("dir\"ect", Some("16"), None).unwrap(),
        ] {
            assert_eq!(quote.json_len(), quote.to_json().len());
        }
        assert_eq!(
            fee_quote("x", Some("[[1,2]]"), None)
                .unwrap_err()
                .message
                .to_string_lossy(),
            "Cannot convert 1,2 to a BigInt"
        );
    }
}
