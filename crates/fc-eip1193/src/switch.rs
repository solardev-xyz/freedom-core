//! `wallet_switchEthereumChain` (design 0012, APR-5c), as the approvals
//! reference's `switchChain` answers it (`page-ethereum.js`, `7f85551d`).
//! The reference opens no prompt for it (0011, PRQ-4):
//!
//! - **A document with no key** gets `4100` before anything else.
//! - **The params** are checked in today's order: no `params[0].chainId`
//!   is `-32602`. A string or a number is read as hex digits
//!   (`parseInt(raw, 16)`; anything else names no chain), so a number
//!   `100` asks for `0x100`: one of the three recorded quirks, kept (0012,
//!   "The three recorded quirks are kept").
//! - **An onchain app** keeps its own chain: another is `4200`.
//! - **The chain must be one the registry knows** (`4902`, "Unrecognized
//!   chain ID") **and has a source for** (`4902`, with the chrome's text).
//! - **Then main is asked whether the document still holds its key**
//!   (`approval.recheck`, the reference's `holdsKey`): if it doesn't,
//!   `4100`, with nothing changed. If it does, the key's grant, if it has
//!   one, takes the chain (`updateLastUsed(key, chainId)`), and main
//!   selects the chain for the page's window and sends `chainChanged`
//!   (main holds the windows and the documents). The answer is `null`.
//!
//! The chain written and selected is the one read from the page's params
//! and found in main's registry (`world.networks`), and nothing else.

use fc_json::JsValue;

use crate::connect::NO_ADDRESS;
use crate::prompt::Crossed;
use crate::request::object;
use crate::{Answer, Request};

const INVALID_PARAMS: (i64, &str) = (-32602, "Invalid parameters");
const CHAIN_NOT_ADDED: (i64, &str) = (4902, "Unrecognized chain ID");
/// The router's answer to a handler that threw a `TypeError` with no code.
const NO_PRIMITIVE: (i64, &str) = (-32603, "Cannot convert object to primitive value");

/// The largest integer a JS number holds exactly.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// A switch past its checks: main's recheck, the grant's chain, and main's
/// selection to come.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Switch {
    chain_id: u64,
}

impl Switch {
    /// The chain asked for, known to main's registry and available.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// What `approval.recheck`'s `live` does: `None` to go on (the grant's
    /// chain, then main's selection), or `4100` when the document no
    /// longer holds its key, with nothing changed.
    pub fn rechecked(&self, live: bool) -> Option<Answer> {
        (!live).then(|| Answer::error(NO_ADDRESS.0, NO_ADDRESS.1))
    }

    /// The answer once main has selected the chain: `null`.
    pub fn answer(&self) -> Answer {
        Answer::result(&JsValue::Null)
    }

    /// Main's answer to the core's `eip1193.select_chain`: `{}` once it has
    /// selected the chain and sent `chainChanged` (*inferred*); anything
    /// else is [`Crossed`].
    pub fn selected(answer: &str) -> Result<(), Crossed> {
        match fc_json::parse(answer).ok().and_then(object) {
            Some(props) if props.is_empty() => Ok(()),
            _ => Err(Crossed),
        }
    }
}

/// `switchChain` for a document with a key, up to main's recheck: the
/// switch, or its refusal.
pub(crate) fn start(request: &Request) -> Result<Switch, Answer> {
    let world = &request.world;
    let refuse = |(code, message): (i64, &str)| Answer::error(code, message);
    // `if (!params || !params[0] || !params[0].chainId)`.
    let raw = request
        .params
        .as_ref()
        .filter(|params| params.truthy())
        .and_then(first)
        .filter(|first| first.truthy())
        .and_then(|first| first.get("chainId"))
        .filter(|raw| raw.truthy())
        .ok_or_else(|| refuse(INVALID_PARAMS))?;
    let requested = match raw {
        JsValue::String(text) => parse_hex(text.as_str()),
        JsValue::Number(n) => parse_hex(&fc_json::number_to_string(*n)),
        _ => f64::NAN,
    };
    // `pinned && requested !== pinned`.
    if let Some(pinned) = world.chain {
        #[allow(clippy::cast_precision_loss)]
        if requested != pinned as f64 {
            return Err(Answer::error(
                4200,
                &format!("This onchain application is pinned to chain {pinned}."),
            ));
        }
    }
    // `networks()?.[requested]`: the registry's entry under the number's
    // text.
    let known = world
        .network_keyed(&fc_json::number_to_string(requested))
        .filter(|known| known.truthy())
        .ok_or_else(|| refuse(CHAIN_NOT_ADDED))?;
    // A chain id is a positive safe integer (*inferred*): an entry under
    // any other key names no chain the core can select.
    if !(requested > 0.0 && requested <= MAX_SAFE_INTEGER) {
        return Err(refuse(CHAIN_NOT_ADDED));
    }
    // Exact: `parseInt` gives an integer, and this one is safe.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let chain_id = requested as u64;
    // `isChainAvailable(requested)`, read as truthy.
    if !known.get("available").is_some_and(JsValue::truthy) {
        // `` `${known.name} requires an RPC provider. …` ``.
        let name = known
            .get("name")
            .unwrap_or(&JsValue::Undefined)
            .js_string()
            .map_err(|_| refuse(NO_PRIMITIVE))?;
        return Err(Answer::error(
            4902,
            &format!(
                "{name} requires an RPC provider. Please configure Alchemy, Infura, or DRPC in Settings."
            ),
        ));
    }
    Ok(Switch { chain_id })
}

/// `params[0]`: an array's first item, or an object's `"0"` property; a
/// string's first character, which has no `chainId`, reads as none.
fn first(params: &JsValue) -> Option<&JsValue> {
    match params {
        JsValue::Array(items) => items.first(),
        JsValue::Object(_) => params.get("0"),
        _ => None,
    }
}

/// JS's `StrWhiteSpaceChar`: what `parseInt` skips first.
fn js_space(c: char) -> bool {
    matches!(
        c,
        '\u{9}' | '\u{a}' | '\u{b}' | '\u{c}' | '\u{d}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// `parseInt(text, 16)`: leading space skipped, a sign, an optional `0x`,
/// then the longest run of hex digits; `NaN` for none.
fn parse_hex(text: &str) -> f64 {
    let text = text.trim_start_matches(js_space);
    let (negative, text) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let text = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    let digits: Vec<u32> = text.chars().map_while(|c| c.to_digit(16)).collect();
    if digits.is_empty() {
        return f64::NAN;
    }
    // Exact while it fits in 128 bits; past that, far beyond any chain id
    // whichever way it rounds.
    let mut exact: Option<u128> = Some(0);
    let mut approx = 0f64;
    for digit in digits {
        exact = exact
            .and_then(|n| n.checked_mul(16))
            .and_then(|n| n.checked_add(u128::from(digit)));
        approx = approx * 16.0 + f64::from(digit);
    }
    #[allow(clippy::cast_precision_loss)]
    let magnitude = exact.map_or(approx, |n| n as f64);
    if negative { -magnitude } else { magnitude }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(a: f64, b: f64) -> bool {
        (a.is_nan() && b.is_nan()) || (a == b && a.is_sign_negative() == b.is_sign_negative())
    }

    #[test]
    fn parse_int_reads_hex_as_javascript_does() {
        for (text, value) in [
            ("0x1", 1.0),
            ("0X1f", 31.0),
            ("1", 1.0),
            ("100", 256.0),
            ("64", 100.0),
            ("  \u{feff}\u{2028}0x2105", 8453.0),
            ("+0xa", 10.0),
            ("-0x1", -1.0),
            ("-0", -0.0),
            ("0x", f64::NAN),
            ("0xg", f64::NAN),
            ("1e+21", 30.0),
            ("1.5", 1.0),
            ("12zz", 18.0),
            ("", f64::NAN),
            ("\u{85}1", f64::NAN),
            ("--1", f64::NAN),
            ("0x0x1", 0.0),
        ] {
            assert!(
                same(parse_hex(text), value),
                "{text:?}: {}",
                parse_hex(text)
            );
        }
        // Past 128 bits it stays far beyond any chain id.
        assert!(parse_hex(&"f".repeat(40)) > 1e40);
    }

    fn request(params: &str, world: &str) -> Request {
        Request::parse(&format!(
            r#"{{"method":"wallet_switchEthereumChain"{params},"world":{{"enabled":true,"wallets":[],"networks":{{"1":{{"name":"Ethereum","available":true}},"256":{{"name":"Hex","available":true}},"11155111":{{"name":"Sepolia","available":false}},"0":{{"name":"Zero","available":true}},"7":{{"name":{{"toString":1}},"available":false}}}}{world}}}}}"#
        ))
        .unwrap()
    }

    fn answer(params: &str, world: &str) -> String {
        match start(&request(params, world)) {
            Ok(switch) => format!("switch {}", switch.chain_id()),
            Err(answer) => answer.into_string(),
        }
    }

    #[test]
    fn each_check_in_the_references_order() {
        let invalid = r#"{"error":{"code":-32602,"message":"Invalid parameters"}}"#;
        let unknown = r#"{"error":{"code":4902,"message":"Unrecognized chain ID"}}"#;
        for params in [
            "",
            r#","params":null"#,
            r#","params":[]"#,
            r#","params":[null]"#,
            r#","params":[{}]"#,
            r#","params":[{"chainId":""}]"#,
            r#","params":[{"chainId":0}]"#,
            r#","params":[{"chainId":false}]"#,
            r#","params":"0x1""#,
            r#","params":[[1]]"#,
        ] {
            assert_eq!(answer(params, ""), invalid, "{params}");
        }
        assert_eq!(answer(r#","params":[{"chainId":"0x1"}]"#, ""), "switch 1");
        assert_eq!(
            answer(r#","params":{"0":{"chainId":"0x1"}}"#, ""),
            "switch 1"
        );
        // A number is read as hex digits.
        assert_eq!(answer(r#","params":[{"chainId":100}]"#, ""), "switch 256");
        assert_eq!(answer(r#","params":[{"chainId":1}]"#, ""), "switch 1");
        for raw in [
            r#"{"id":1}"#,
            "true",
            r#"[1]"#,
            r#""0x539""#,
            r#""-0""#,
            r#""zz""#,
        ] {
            assert_eq!(
                answer(&format!(r#","params":[{{"chainId":{raw}}}]"#), ""),
                unknown,
                "{raw}"
            );
        }
        assert_eq!(
            answer(r#","params":[{"chainId":"0xaa36a7"}]"#, ""),
            r#"{"error":{"code":4902,"message":"Sepolia requires an RPC provider. Please configure Alchemy, Infura, or DRPC in Settings."}}"#
        );
        assert_eq!(
            answer(r#","params":[{"chainId":"0x7"}]"#, ""),
            r#"{"error":{"code":-32603,"message":"Cannot convert object to primitive value"}}"#
        );
        // An onchain app keeps its chain, before the registry is read.
        let pinned = r#"{"error":{"code":4200,"message":"This onchain application is pinned to chain 8453."}}"#;
        assert_eq!(
            answer(r#","params":[{"chainId":"0x1"}]"#, r#","chain":8453"#),
            pinned
        );
        assert_eq!(
            answer(r#","params":[{"chainId":{}}]"#, r#","chain":8453"#),
            pinned
        );
        assert_eq!(
            answer(r#","params":[{"chainId":"0x1"}]"#, r#","chain":1"#),
            "switch 1"
        );
        // The params are read before the pin.
        assert_eq!(answer(r#","params":[]"#, r#","chain":8453"#), invalid);
    }

    #[test]
    fn a_recheck_and_mains_selection() {
        let switch = start(&request(r#","params":[{"chainId":"0x1"}]"#, "")).unwrap();
        assert_eq!(switch.rechecked(true), None);
        assert_eq!(
            switch.rechecked(false).unwrap().as_str(),
            r#"{"error":{"code":4100,"message":"This page has no address to connect from yet"}}"#
        );
        assert_eq!(switch.answer().as_str(), r#"{"result":null}"#);
        assert_eq!(Switch::selected("{}"), Ok(()));
        for text in ["", "[]", "null", r#"{"selected":true}"#, r#"{"live":true}"#] {
            assert_eq!(Switch::selected(text), Err(Crossed), "{text}");
        }
    }
}
