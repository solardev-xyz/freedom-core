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

use fc_json::index::{Index, Kind, Value};
use fc_json::number_to_string;

use crate::bigint::{BigInt, MAX_DECIMAL_BITS, Parsed, parse_string};
use crate::js::{JsError, JsString, js_string_of};

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
    let gas_index = gas_price.map(Index::new).transpose().map_err(not_json)?;
    let gas_price = to_bigint(gas_index.as_ref().map(Index::root))?;
    let positive = match &gas_price {
        Parsed::Value(value) => !value.is_negative() && !value.is_zero(),
        Parsed::TooWide { negative } => !negative,
    };
    if !positive {
        return Err(JsError::new(
            "Error",
            format!("{source} returned a non-positive gas price").as_str(),
        ));
    }
    let priority_index = priority.map(Index::new).transpose().map_err(not_json)?;
    let priority = match priority_index.as_ref().map(Index::root) {
        None => None,
        Some(value) if value.kind() == Kind::Null => None,
        Some(value) => match to_bigint(Some(value))? {
            Parsed::Value(priority) => Some(priority),
            // Negative, or above any gas price that can be quoted.
            Parsed::TooWide { .. } => None,
        },
    };
    let gas_price = match gas_price {
        Parsed::Value(value) if value.bits() <= MAX_DECIMAL_BITS => value,
        _ => {
            return Err(JsError::new(
                "Error",
                format!("{source} returned a gas price wider than {MAX_DECIMAL_BITS} bits")
                    .as_str(),
            ));
        }
    };
    let verified = matches!(source, "myotis" | "colibri" | "quorum");
    let source = source.to_owned();
    Ok(match priority {
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
    })
}

fn not_json(_: fc_json::index::IndexError) -> JsError {
    JsError::new("SyntaxError", "The fee value is not valid JSON")
}

/// `BigInt(value)` for a JSON value (`None` is `undefined`).
fn to_bigint(value: Option<Value<'_, '_>>) -> Result<Parsed, JsError> {
    let Some(value) = value else {
        return Err(JsError::new(
            "TypeError",
            "Cannot convert undefined to a BigInt",
        ));
    };
    let string = match value.kind() {
        Kind::Null => return Err(JsError::new("TypeError", "Cannot convert null to a BigInt")),
        Kind::True => return Ok(Parsed::Value(BigInt::from_u64(1))),
        Kind::False => return Ok(Parsed::Value(BigInt::zero())),
        Kind::Number => {
            let number = value.number();
            return BigInt::from_f64(number).map(Parsed::Value).ok_or_else(|| {
                JsError::new(
                    "RangeError",
                    format!(
                        "The number {} cannot be converted to a BigInt because it is not an integer",
                        number_to_string(number)
                    )
                    .as_str(),
                )
            });
        }
        Kind::String => JsString::from_units(value.units().collect()),
        // ToPrimitive: an array's joined string, `[object Object]`, or a
        // TypeError for an own `toString`.
        Kind::Array | Kind::Object => js_string_of(value)?,
    };
    parse_string(string.units()).ok_or_else(|| {
        // V8 quotes at most 1,000 code units of the string.
        let mut message = JsString::from("Cannot convert ");
        match string.units().get(..1000) {
            Some(head) if string.len() > 1000 => {
                message.push_units(head);
                message.push_str("\u{2026}");
            }
            _ => message.push_units(string.units()),
        }
        message.push_str(" to a BigInt");
        JsError {
            name: "SyntaxError",
            message,
        }
    })
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
        assert_eq!(
            fee_quote("x", Some("[[1,2]]"), None)
                .unwrap_err()
                .message
                .to_string_lossy(),
            "Cannot convert 1,2 to a BigInt"
        );
    }
}
