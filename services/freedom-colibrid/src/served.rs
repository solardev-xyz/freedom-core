//! What the service serves (design 0014, "What the service serves"),
//! checked before any context exists: a closed list of methods, each in the
//! block forms Colibri 3.0.3 ties to the requested block. The rule is
//! `fc-colibri`'s, which the core's router applies first ("One rule, two
//! places").

use fc_colibri::{COLIBRI_SERVED_METHODS, ColibriParams, colibri_request_params};
use fc_json::JsString;

/// A refusal: the error text the reply carries, as a JSON string literal
/// (a block string may hold a lone surrogate, which a `String` can't).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

/// Whether the service serves `method` with `params` (the caller's JSON
/// text), or the error text it answers instead:
/// - a method outside the list gets the C core's own text, `Method <m> is
///   not supported` (deviations `colibri-unproofable` and
///   `colibri-no-calls`);
/// - a block form outside #279's gets #279's text, `Colibri cannot prove
///   <method> <why>`. An account read without its block counts as params
///   too short: the router appends `latest` before Colibri is asked, and the
///   service never changes params.
pub fn check(method: &str, params: &str) -> Result<(), Refusal> {
    if !COLIBRI_SERVED_METHODS.contains(&method) {
        return Err(quoted(
            format!("Method {method} is not supported")
                .encode_utf16()
                .collect(),
        ));
    }
    let why: Vec<u16> = match colibri_request_params(method, params) {
        ColibriParams::AsSent => return Ok(()),
        ColibriParams::LatestAppended => {
            // The params' length is the block parameter's position.
            let length = fc_colibri::COLIBRI_BLOCK_PARAM
                .iter()
                .find(|(name, _)| *name == method)
                .map_or(0, |(_, at)| *at);
            format!("with params of length {length}")
                .encode_utf16()
                .collect()
        }
        ColibriParams::Refused(units) => units,
    };
    let mut text: Vec<u16> = format!("Colibri cannot prove {method} ")
        .encode_utf16()
        .collect();
    text.extend(why);
    Err(quoted(text))
}

fn quoted(units: Vec<u16>) -> Refusal {
    let mut out = String::new();
    JsString::from_units(&units).quote_into(&mut out);
    Refusal(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(text: &str) -> Result<(), Refusal> {
        Err(Refusal(serde_json::to_string(text).unwrap()))
    }

    #[test]
    fn methods() {
        for method in COLIBRI_SERVED_METHODS {
            let params = match method {
                "eth_getStorageAt" => r#"["0xabc","0x0","latest"]"#,
                "eth_getBalance" | "eth_getCode" | "eth_getTransactionCount" => {
                    r#"["0xabc","latest"]"#
                }
                "eth_getBlockByHash" => {
                    r#"["0x2222222222222222222222222222222222222222222222222222222222222222",false]"#
                }
                "eth_getBlockByNumber" => r#"["latest",false]"#,
                _ => "[]",
            };
            assert_eq!(check(method, params), Ok(()), "{method}");
        }
        // F-1, F-11, and the rest.
        for method in [
            "eth_gasPrice",
            "eth_feeHistory",
            "eth_call",
            "eth_estimateGas",
            "eth_getLogs",
            "eth_sendRawTransaction",
            "eth_chainId",
            "",
        ] {
            assert_eq!(
                check(method, "[]"),
                refused(&format!("Method {method} is not supported")),
                "{method}"
            );
        }
    }

    #[test]
    fn block_forms() {
        assert_eq!(
            check("eth_getBalance", r#"["0xabc","safe"]"#),
            refused(r#"Colibri cannot prove eth_getBalance at block "safe""#)
        );
        // The service doesn't append `latest`.
        assert_eq!(
            check("eth_getBalance", r#"["0xabc"]"#),
            refused("Colibri cannot prove eth_getBalance with params of length 1")
        );
        assert_eq!(
            check("eth_getStorageAt", r#"["0xabc","0x0"]"#),
            refused("Colibri cannot prove eth_getStorageAt with params of length 2")
        );
        assert_eq!(
            check("eth_getBlockByNumber", r#"["pending",false]"#),
            refused(r#"Colibri cannot prove eth_getBlockByNumber at block "pending""#)
        );
        assert_eq!(
            check("eth_getBlockByHash", "[]"),
            refused("Colibri cannot prove eth_getBlockByHash without a block hash")
        );
        assert_eq!(
            check(
                "eth_getBlockByNumber",
                r#"[{"blockHash":"0x1","requireCanonical":true},false]"#
            ),
            refused("Colibri cannot prove eth_getBlockByNumber at a block that isn't a string")
        );
        // A lone surrogate stays one, escaped.
        assert_eq!(
            check("eth_getBlockByNumber", r#"["\ud800",false]"#),
            Err(Refusal(
                r#""Colibri cannot prove eth_getBlockByNumber at block \"\ud800\"""#.to_owned()
            ))
        );
        // No block, `null`: Colibri's `latest`.
        assert_eq!(check("eth_getBlockByNumber", "null"), Ok(()));
        assert_eq!(check("eth_getBlockByNumber", "[]"), Ok(()));
    }
}
