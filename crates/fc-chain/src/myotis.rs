//! Myotis reads (design 0005, Myotis): the router's `requestMyotis` without
//! its I/O, in two halves around the verified operation main runs.
//! - [`myotis_operation`]: which operation a read is, after the gates (the
//!   block tag must be `latest` or absent, calls carry no state overrides
//!   and no blob fields), or why Myotis can't serve it.
//! - [`myotis_answer`]: `assertMyotisAnswer`'s classification of the
//!   payload, the verdict state reads need, and the answer in JSON-RPC's
//!   form. Payload keys are main's snake_case (`data_hex`, `verify_method`,
//!   `balance_wei`, ...).
//! - [`myotis_trust`]: the trust label, with the block number only when the
//!   head was the same before and after the read.
//!
//! Each failure says how the read loop treats it ([`MyotisFailure`]). The
//! texts are the router's.

use fc_json::index::{Index, KeyOrder, Kind, Value};

use crate::bigint::{BigInt, Parsed};
use crate::fee::to_bigint;
use crate::js::{
    Element, JsError, JsString, element, is_js_whitespace, is_safe_integer, null_index_message,
    trim,
};
use crate::pattern::{JsPattern, MatchText};

/// The error when Myotis isn't ready for the chain (from the last
/// `chain.availability`).
pub const MYOTIS_NOT_READY: &str = "Myotis is not ready";

/// Call-object fields of a blob transaction, which Myotis doesn't execute.
pub const MYOTIS_BLOB_FIELDS: [&str; 6] = [
    "blobVersionedHashes",
    "maxFeePerBlobGas",
    "blobs",
    "commitments",
    "proofs",
    "sidecar",
];

/// The longest refusal text kept, in UTF-16 code units.
pub const MAX_MYOTIS_REFUSAL_MESSAGE: usize = 300;

/// Refusals that name a limit of the engine build rather than the request:
/// another source can serve these.
static CAPABILITY_REFUSAL: JsPattern = JsPattern::new(
    r"EIP-7843|fork table|node's \d+-gas call budget|not supported by this node",
    "i",
);

const UNEXPECTED_RESPONSE: &str = "Myotis returned an unexpected response";

/// The verified operation a read runs (design 0005, Verified operations).
/// Arguments are the caller's JSON as the router passes it; `None` is
/// `undefined`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MyotisOperation {
    /// `eth_getBalance` and `eth_getTransactionCount`.
    Account { address: Option<String> },
    /// `eth_getCode`.
    Code { address: Option<String> },
    /// `eth_getStorageAt`.
    Storage {
        address: Option<String>,
        slot: Option<String>,
    },
    /// `eth_call`, at `latest`: the call object, or `{}`.
    CallTx { tx: String },
    /// `eth_estimateGas`, at `latest`.
    EstimateTx { tx: String },
    /// `eth_gasPrice` and `eth_maxPriorityFeePerGas`.
    Fee,
}

/// Myotis's answer from verified state that isn't a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MyotisVerdict {
    /// `execution reverted`, code 3, with the revert data.
    Revert,
    /// A permanent `-32602` refusal of the request (`invalid-params`).
    InvalidParams,
    /// The call can't succeed within its own gas, fees or funds: geth's
    /// `-32000` (`infeasible`).
    Infeasible,
}

/// The error a [`MyotisVerdict`] is served as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyotisRefusal {
    pub verdict: MyotisVerdict,
    pub code: i32,
    pub message: JsString,
    /// The revert data (a string, as Myotis sent it, or `0x`).
    pub data: Option<JsString>,
}

impl MyotisRefusal {
    /// The router's `myotisRefusal` marker; a revert has none.
    pub fn kind(&self) -> Option<&'static str> {
        match self.verdict {
            MyotisVerdict::Revert => None,
            MyotisVerdict::InvalidParams => Some("invalid-params"),
            MyotisVerdict::Infeasible => Some("infeasible"),
        }
    }
}

/// Why Myotis gave no result, and what the read loop does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MyotisFailure {
    /// Final: served to the caller, no other source tried.
    Final(MyotisRefusal),
    /// A `SourceUnavailableError`: the next source; never the last error.
    Unavailable(JsString),
    /// Any other error (`Error`, `TypeError`, ...): the next source; it can
    /// become the last error.
    Error(JsError),
}

fn unavailable(message: impl Into<JsString>) -> MyotisFailure {
    MyotisFailure::Unavailable(message.into())
}

fn plain(message: &str) -> MyotisFailure {
    MyotisFailure::Error(JsError::new("Error", message))
}

/// The operation for `method` with `params` (the request's normalized
/// params, as JSON), or the failure that ends the source first.
pub fn myotis_operation(method: &str, params: &str) -> Result<MyotisOperation, MyotisFailure> {
    // The machine's params were validated by normalization already.
    let index = Index::new(params).map_err(|_| {
        MyotisFailure::Error(JsError::new("SyntaxError", "The params are not valid JSON"))
    })?;
    let params = index.root();
    let at = |i: usize| {
        element(params, i).ok_or_else(|| {
            MyotisFailure::Error(JsError::new("TypeError", null_index_message(i).as_str()))
        })
    };
    let json = |item: Element<'_, '_>| item.to_json();
    match method {
        "eth_getBalance" | "eth_getTransactionCount" => {
            block_tag(method, at(1)?)?;
            Ok(MyotisOperation::Account {
                address: json(at(0)?),
            })
        }
        "eth_getCode" => {
            block_tag(method, at(1)?)?;
            Ok(MyotisOperation::Code {
                address: json(at(0)?),
            })
        }
        "eth_getStorageAt" => {
            block_tag(method, at(2)?)?;
            Ok(MyotisOperation::Storage {
                address: json(at(0)?),
                slot: json(at(1)?),
            })
        }
        "eth_call" | "eth_estimateGas" => {
            block_tag(method, at(1)?)?;
            if !at(2)?.is_nullish() {
                return Err(unavailable(
                    format!("Myotis cannot serve {method} with state overrides").as_str(),
                ));
            }
            let call = at(0)?;
            if let Some(object) = call.of_kind(Kind::Object) {
                for field in MYOTIS_BLOB_FIELDS {
                    match object.get(field) {
                        None => {}
                        Some(value) if value.kind() == Kind::Null => {}
                        Some(value)
                            if value.kind() == Kind::Array && value.children().next().is_none() => {
                        }
                        Some(_) => {
                            return Err(unavailable(
                                format!(
                                    "Myotis cannot serve {method} for a blob transaction (\"{field}\")"
                                )
                                .as_str(),
                            ));
                        }
                    }
                }
            }
            // `params[0] || {}`.
            let tx = match call {
                Element::Value(value) if value.truthy() => value.stringify(KeyOrder::Property),
                Element::Unit(_) => call.to_json().unwrap_or_default(),
                _ => "{}".to_owned(),
            };
            Ok(if method == "eth_call" {
                MyotisOperation::CallTx { tx }
            } else {
                MyotisOperation::EstimateTx { tx }
            })
        }
        "eth_gasPrice" | "eth_maxPriorityFeePerGas" => Ok(MyotisOperation::Fee),
        _ => Err(unavailable(
            format!("Myotis does not support {method}").as_str(),
        )),
    }
}

/// `assertMyotisBlockTag`: `latest`, `null` or nothing.
fn block_tag(method: &str, tag: Element<'_, '_>) -> Result<(), MyotisFailure> {
    if tag.is_nullish() {
        return Ok(());
    }
    if let Element::Value(value) = tag
        && value.is_str("latest")
    {
        return Ok(());
    }
    let tag = tag.js_string().map_err(MyotisFailure::Error)?;
    let mut message = JsString::from(format!("Myotis cannot serve {method} at block \"").as_str());
    message.push_units(tag.units());
    message.push_str("\"");
    Err(MyotisFailure::Unavailable(message))
}

/// The result of `method` from Myotis's `payload` (main's JSON, keys in
/// snake_case; `None` when the adapter returned nothing), as the JSON text
/// the router returns.
///
/// A balance, nonce or fee is `0x${BigInt(value).toString(16)}`. A decimal
/// value of 2^4096 or more fails with a plain error (deviation
/// `bigint-width`), where the router converts it.
pub fn myotis_answer(method: &str, payload: Option<&str>) -> Result<String, MyotisFailure> {
    let index = payload
        .map(Index::new)
        .transpose()
        .map_err(|_| plain(UNEXPECTED_RESPONSE))?;
    let payload = index.as_ref().map(Index::root);
    match method {
        "eth_getBalance" | "eth_getTransactionCount" => {
            let account = verified_state_read(payload)?;
            // A proven-absent account.
            if account
                .get("exists")
                .is_some_and(|v| v.kind() == Kind::False)
            {
                return Ok("\"0x0\"".to_owned());
            }
            let keys: &[&str] = if method == "eth_getBalance" {
                &["balance_wei", "balance"]
            } else {
                &["nonce"]
            };
            quantity(native_result(Some(account), keys)?)
        }
        "eth_getCode" => {
            let code = verified_state_read(payload)?;
            let hex = native_result(Some(code), &["code_hex"])?;
            // `/^0x(?:[0-9a-f]{2})*$/i`, lowercased.
            let text = ascii_string(hex)
                .filter(|text| hex_digits(text).is_some_and(|digits| digits.len() % 2 == 0));
            match text {
                Some(text) => Ok(format!("\"{}\"", text.to_ascii_lowercase())),
                None => Err(unavailable("Myotis returned invalid code")),
            }
        }
        "eth_getStorageAt" => {
            let slot = verified_state_read(payload)?;
            let digits = match slot.get("value_hex") {
                None => Some("0".to_owned()),
                Some(value) if value.kind() == Kind::Null => Some("0".to_owned()),
                Some(value) => ascii_string(value)
                    .and_then(|text| hex_digits(&text).map(str::to_owned))
                    .filter(|digits| digits.len() <= 64),
            };
            let digits =
                digits.ok_or_else(|| unavailable("Myotis returned an invalid storage value"))?;
            Ok(format!("\"0x{:0>64}\"", digits.to_ascii_lowercase()))
        }
        "eth_call" => {
            assert_answer(payload)?;
            Ok(native_result(payload, &["result_hex", "result"])?.stringify(KeyOrder::Property))
        }
        "eth_estimateGas" => {
            assert_answer(payload)?;
            let gas = native_result(payload, &["gas"])?;
            let number = gas.number();
            if gas.kind() != Kind::Number || !is_safe_integer(number) || number < 0.0 {
                return Err(unavailable("Myotis returned invalid gas"));
            }
            quantity(gas)
        }
        "eth_gasPrice" => quantity(native_result(payload, &["gas_price_wei", "gas_price"])?),
        "eth_maxPriorityFeePerGas" => quantity(native_result(
            payload,
            &["max_priority_fee_per_gas_wei", "max_priority_fee_per_gas"],
        )?),
        _ => Err(unavailable(
            format!("Myotis does not support {method}").as_str(),
        )),
    }
}

/// `getFeeQuote`'s Myotis half, from the `fee` operation's payload: the
/// gas price as `nativeResult(result, 'gasPriceWei', 'gasPrice')` reads it
/// (the payload must be an answer) and the priority fee as
/// `optionalNativeResult(result, 'maxPriorityFeePerGasWei',
/// 'maxPriorityFeePerGas')` does (`None` when neither is set), each as the
/// JSON text `feeQuote` converts.
pub fn myotis_fee_values(payload: Option<&str>) -> Result<(String, Option<String>), MyotisFailure> {
    let index = payload
        .map(Index::new)
        .transpose()
        .map_err(|_| plain(UNEXPECTED_RESPONSE))?;
    let payload = index.as_ref().map(Index::root);
    let gas = native_result(payload, &["gas_price_wei", "gas_price"])?;
    let priority = ["max_priority_fee_per_gas_wei", "max_priority_fee_per_gas"]
        .iter()
        .find_map(|key| payload?.get(key).filter(|v| v.kind() != Kind::Null))
        .map(|v| v.stringify(KeyOrder::Property));
    Ok((gas.stringify(KeyOrder::Property), priority))
}

/// `assertMyotisAnswer`: every payload that isn't a served answer fails.
fn assert_answer(payload: Option<Value<'_, '_>>) -> Result<(), MyotisFailure> {
    let get = |key: &str| payload.and_then(|p| p.get(key));
    if get("status").is_some_and(|s| s.is_str("revert")) {
        let data = match get("data_hex") {
            Some(data) if data.kind() == Kind::String => {
                JsString::from_units(data.units().collect())
            }
            _ => JsString::from("0x"),
        };
        return Err(MyotisFailure::Final(MyotisRefusal {
            verdict: MyotisVerdict::Revert,
            code: 3,
            message: JsString::from("execution reverted"),
            data: Some(data),
        }));
    }
    let error = get("error").filter(|e| e.truthy());
    if error.is_some()
        && get("code").is_some_and(|c| c.kind() == Kind::Number && c.number() == -32602.0)
    {
        let message = refusal_message(error, "invalid params");
        if CAPABILITY_REFUSAL.test(&MatchText::new(message.units())) {
            let mut text = JsString::from("Myotis cannot execute this request: ");
            text.push_units(message.units());
            return Err(MyotisFailure::Unavailable(text));
        }
        return Err(MyotisFailure::Final(MyotisRefusal {
            verdict: MyotisVerdict::InvalidParams,
            code: -32602,
            message,
            data: None,
        }));
    }
    if get("status").is_some_and(|s| s.is_str("infeasible")) {
        return Err(MyotisFailure::Final(MyotisRefusal {
            verdict: MyotisVerdict::Infeasible,
            code: -32000,
            message: refusal_message(get("reason"), "transaction is infeasible"),
            data: None,
        }));
    }
    let status = get("status");
    if !payload.is_some_and(|p| p.truthy())
        || error.is_some()
        || status.is_some_and(|s| s.is_str("error") || s.is_str("unavailable"))
    {
        return Err(unavailable("Myotis native read unavailable"));
    }
    Ok(())
}

/// `verifiedStateRead`: an account, code or storage payload is an answer
/// only with its verdict.
fn verified_state_read<'i, 't>(
    payload: Option<Value<'i, 't>>,
) -> Result<Value<'i, 't>, MyotisFailure> {
    assert_answer(payload)?;
    let payload = payload.ok_or_else(|| plain(UNEXPECTED_RESPONSE))?;
    let verdict = payload
        .get("verify_method")
        .is_some_and(|v| v.kind() == Kind::String && v.truthy());
    if !verdict {
        let mut message = JsString::from("Myotis read has no verdict (");
        message.push_units(refusal_message(payload.get("fail_reason"), "unverified").units());
        message.push_str(")");
        return Err(MyotisFailure::Unavailable(message));
    }
    Ok(payload)
}

/// `nativeResult`: the first of `keys` that is neither `null` nor missing.
fn native_result<'i, 't>(
    payload: Option<Value<'i, 't>>,
    keys: &[&str],
) -> Result<Value<'i, 't>, MyotisFailure> {
    assert_answer(payload)?;
    keys.iter()
        .find_map(|key| payload?.get(key).filter(|v| v.kind() != Kind::Null))
        .ok_or_else(|| plain(UNEXPECTED_RESPONSE))
}

/// `myotisRefusalMessage`: a non-blank string, trimmed, its whitespace runs
/// collapsed to one space, at most 300 code units; otherwise `fallback`.
fn refusal_message(value: Option<Value<'_, '_>>, fallback: &str) -> JsString {
    let Some(value) = value.filter(|v| v.kind() == Kind::String) else {
        return JsString::from(fallback);
    };
    let units: Vec<u16> = value.units().collect();
    let trimmed = trim(&units);
    if trimmed.is_empty() {
        return JsString::from(fallback);
    }
    let mut out: Vec<u16> = Vec::with_capacity(trimmed.len().min(MAX_MYOTIS_REFUSAL_MESSAGE));
    let mut in_space = false;
    for &unit in trimmed {
        if is_js_whitespace(unit) {
            if !in_space {
                out.push(0x20);
            }
            in_space = true;
        } else {
            out.push(unit);
            in_space = false;
        }
    }
    out.truncate(MAX_MYOTIS_REFUSAL_MESSAGE);
    JsString::from_units(out)
}

/// The router's `quantity`: `0x${BigInt(value || 0).toString(16)}`.
fn quantity(value: Value<'_, '_>) -> Result<String, MyotisFailure> {
    if !value.truthy() {
        return Ok("\"0x0\"".to_owned());
    }
    match to_bigint(Some(value)).map_err(MyotisFailure::Error)? {
        Parsed::Value(number) => Ok(format!("\"0x{}\"", BigInt::to_hex(&number))),
        Parsed::TooWide { .. } => Err(plain("Myotis returned a number wider than 4096 bits")),
    }
}

/// A string value made only of ASCII.
fn ascii_string(value: Value<'_, '_>) -> Option<String> {
    if value.kind() != Kind::String {
        return None;
    }
    value
        .units()
        .map(|unit| u8::try_from(unit).ok().filter(u8::is_ascii).map(char::from))
        .collect()
}

/// The digits of `0x` or `0X` and hex digits (`/^0x[0-9a-f]*$/i`).
fn hex_digits(text: &str) -> Option<&str> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    digits
        .bytes()
        .all(|b| b.is_ascii_hexdigit())
        .then_some(digits)
}

/// The block a Myotis answer is labelled with: the head's optimistic block
/// number after the read, only when it was the same (`===`) before it.
/// `before` and `after` are the numbers' JSON (`None` when there was none);
/// objects are never the same, as two status samples never share one.
pub fn myotis_trust_block(before: Option<&str>, after: Option<&str>) -> Option<String> {
    let before = Index::new(before?).ok()?;
    let after = Index::new(after?).ok()?;
    let (b, a) = (before.root(), after.root());
    let same = match (b.kind(), a.kind()) {
        (Kind::Number, Kind::Number) => b.number() == a.number(),
        (Kind::String, Kind::String) => b.units().eq(a.units()),
        (Kind::True, Kind::True) | (Kind::False, Kind::False) => true,
        _ => false,
    };
    same.then(|| a.stringify(KeyOrder::Property))
}

/// The proof a Myotis trust label names.
pub const MYOTIS_PROOF: &str =
    "P2P light client (optimistic beacon root \u{2014} attested, not finalized)";

/// The trust label of a Myotis answer (`myotisTrust`), as JSON.
pub fn myotis_trust(before: Option<&str>, after: Option<&str>) -> String {
    let block = myotis_trust_block(before, after).unwrap_or_else(|| "null".to_owned());
    format!(
        r#"{{"level":"verified","method":"myotis","finality":"optimistic","proof":"{MYOTIS_PROOF}","block":{block},"agreed":["myotis-p2p"],"dissented":[],"queried":["myotis-p2p"],"quorum":{{"k":1,"m":1,"achieved":true}}}}"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::safe_source;

    #[test]
    fn capability_pattern() {
        assert!(CAPABILITY_REFUSAL.compiles());
        assert!(safe_source(CAPABILITY_REFUSAL.source));
    }

    #[test]
    fn reads() {
        assert_eq!(
            myotis_operation("eth_call", r#"[{"to":"0x1"},"latest"]"#),
            Ok(MyotisOperation::CallTx {
                tx: r#"{"to":"0x1"}"#.into()
            })
        );
        assert!(matches!(
            myotis_operation("eth_call", r#"[{"blobs":["0x"]}]"#),
            Err(MyotisFailure::Unavailable(_))
        ));
        assert_eq!(
            myotis_answer(
                "eth_getBalance",
                Some(r#"{"verify_method":"proof","balance_wei":"1000"}"#)
            ),
            Ok("\"0x3e8\"".into())
        );
        let Err(MyotisFailure::Final(revert)) =
            myotis_answer("eth_call", Some(r#"{"status":"revert"}"#))
        else {
            panic!()
        };
        assert_eq!((revert.code, revert.kind()), (3, None));
        assert_eq!(
            myotis_trust_block(Some("-0"), Some("0")).as_deref(),
            Some("0")
        );
        assert_eq!(myotis_trust_block(Some("{}"), Some("{}")), None);
        assert!(myotis_trust(None, Some("1")).contains(r#""block":null"#));
    }
}
