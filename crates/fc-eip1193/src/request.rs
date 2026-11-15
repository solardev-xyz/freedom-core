//! `eip1193.request`'s params (design 0012, APR-5b): the page's `method`
//! and `params`, and `world`, main's wallet state read as main sends the
//! request.
//!
//! **`world`** carries what main still holds, until it moves (*inferred*):
//!
//! `enabled`, `wallets` and `networks` are required; `chain` and
//! `window_chain` may be left out or null.
//!
//! - `enabled`: the Identity & Wallet switch (`enableIdentityWallet ===
//!   true`), a boolean;
//! - `chain`: the document's own chain, an onchain app's from its committed
//!   `web3://` URL (0011's record `chain`), and `window_chain`, the chain
//!   its window selected (`selectedChainOf`), each as main holds it: a
//!   value other than a positive safe integer is none;
//! - `wallets`: main's wallet list (`getDerivedWallets`), each `{ index,
//!   address, … }`; anything but an array is an empty list;
//! - `networks`: the registry, `{ "<chain id>": { name, available } }`:
//!   each network's name and whether it has a source
//!   (`isChainAvailable`). A chain it doesn't list has neither;
//! - `active` (APR-5c), optional: the active account's index
//!   (`getActiveWalletIndex`), any JSON value, compared with `===`; the
//!   connect prompt's default.

use fc_json::{JsString, JsValue, ToPrimitiveError};

use crate::FALLBACK_CHAIN_ID;

/// The largest integer a JS number holds exactly (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// Params that aren't `eip1193.request`'s: `invalid_argument`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalid;

/// A parsed `eip1193.request`.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub method: String,
    /// The page's params as main sent them; `None` when absent.
    pub params: Option<JsValue>,
    pub world: World,
}

/// Main's wallet state, sent with each request.
#[derive(Debug, Clone, PartialEq)]
pub struct World {
    pub enabled: bool,
    pub chain: Option<u64>,
    pub window_chain: Option<u64>,
    wallets: Vec<JsValue>,
    networks: Vec<(String, JsValue)>,
    active: Option<JsValue>,
}

impl Request {
    /// `{ method, params?, world }`, as main writes it: nothing else, the
    /// method a string and `world` as the module describes it.
    pub fn parse(text: &str) -> Result<Request, Invalid> {
        let props = object(fc_json::parse(text).map_err(|_| Invalid)?).ok_or(Invalid)?;
        let (mut method, mut params, mut world) = (None, None, None);
        for (key, value) in props {
            match key.as_str() {
                "method" => method = Some(value),
                "params" => params = Some(value),
                "world" => world = Some(value),
                _ => return Err(Invalid),
            }
        }
        let method = match method.as_ref().and_then(JsValue::as_js_string) {
            Some(method) if method.is_well_formed() => method.as_str().to_owned(),
            _ => return Err(Invalid),
        };
        let world = World::from_value(world.ok_or(Invalid)?)?;
        Ok(Request {
            method,
            params,
            world,
        })
    }

    /// A read's params, as the reference passes them on (`context.params
    /// || []`), in JSON.stringify's text.
    pub(crate) fn read_params(&self) -> String {
        match &self.params {
            Some(params) if params.truthy() => params.stringify(),
            _ => String::from("[]"),
        }
    }
}

impl World {
    /// `world` as main sends it, with a request or with an approve
    /// (`approval.request`'s answer).
    pub(crate) fn from_value(value: JsValue) -> Result<World, Invalid> {
        let props = object(value).ok_or(Invalid)?;
        let (mut enabled, mut chain, mut window_chain) = (None, None, None);
        let mut active = None;
        let (mut wallets, mut networks) = (None, None);
        for (key, value) in props {
            match key.as_str() {
                "enabled" => match value {
                    JsValue::Bool(on) => enabled = Some(on),
                    _ => return Err(Invalid),
                },
                "chain" => chain = positive_safe_integer(&value),
                "window_chain" => window_chain = positive_safe_integer(&value),
                // `Array.isArray(listed) ? listed : []`.
                "wallets" => {
                    wallets = Some(array(value).unwrap_or_default());
                }
                "networks" => {
                    let entries = object(value).ok_or(Invalid)?;
                    let mut table = Vec::with_capacity(entries.len());
                    for (id, network) in entries {
                        let JsValue::Object(_) = network else {
                            return Err(Invalid);
                        };
                        table.push((id.into_string(), network));
                    }
                    networks = Some(table);
                }
                "active" => active = Some(value),
                _ => return Err(Invalid),
            }
        }
        Ok(World {
            enabled: enabled.ok_or(Invalid)?,
            chain,
            window_chain,
            wallets: wallets.ok_or(Invalid)?,
            networks: networks.ok_or(Invalid)?,
            active,
        })
    }

    /// The active account's index as main sent it; `undefined` when absent.
    pub(crate) fn active(&self) -> &JsValue {
        static UNDEFINED: JsValue = JsValue::Undefined;
        self.active.as_ref().unwrap_or(&UNDEFINED)
    }

    /// The chain the page reads (the chrome's `getCurrentChainId`): its own
    /// chain, or else its window's, or else Gnosis.
    pub fn chain_id(&self) -> u64 {
        self.chain
            .or(self.window_chain)
            .unwrap_or(FALLBACK_CHAIN_ID)
    }

    /// Main's wallet list, its items as main sent them.
    pub fn wallets(&self) -> &[JsValue] {
        &self.wallets
    }

    pub(crate) fn network(&self, chain_id: u64) -> Option<&JsValue> {
        self.network_keyed(&chain_id.to_string())
    }

    /// The registry's entry under `key`, as `networks()[key]` reads it.
    pub(crate) fn network_keyed(&self, key: &str) -> Option<&JsValue> {
        self.networks
            .iter()
            .find(|(id, _)| id == key)
            .map(|(_, network)| network)
    }

    /// `isChainAvailable(chainId) === false`: the network says it has no
    /// source, or the registry doesn't list the chain.
    pub(crate) fn unavailable(&self, chain_id: u64) -> bool {
        self.network(chain_id)
            .is_none_or(|network| matches!(network.get("available"), Some(JsValue::Bool(false))))
    }

    /// `` `${name || `Chain ${chainId}`}` ``, or the conversion's throw.
    pub(crate) fn chain_label(&self, chain_id: u64) -> Result<String, ToPrimitiveError> {
        match self
            .network(chain_id)
            .and_then(|network| network.get("name"))
        {
            Some(name) if name.truthy() => name.js_string(),
            _ => Ok(format!("Chain {chain_id}")),
        }
    }
}

/// An object's properties, taken out of it (a `JsValue` drops its children
/// itself, so they can't be moved out by a pattern).
pub(crate) fn object(mut value: JsValue) -> Option<Vec<(JsString, JsValue)>> {
    match &mut value {
        JsValue::Object(props) => Some(std::mem::take(props)),
        _ => None,
    }
}

/// An array's items, taken out of it.
fn array(mut value: JsValue) -> Option<Vec<JsValue>> {
    match &mut value {
        JsValue::Array(items) => Some(std::mem::take(items)),
        _ => None,
    }
}

/// `Number.isSafeInteger(value) && value > 0`.
fn positive_safe_integer(value: &JsValue) -> Option<u64> {
    match value {
        JsValue::Number(n) if n.fract() == 0.0 && *n > 0.0 && *n <= MAX_SAFE_INTEGER => {
            // Exact: an integer no larger than 2^53 - 1.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Some(*n as u64)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn world(extra: &str) -> Result<Request, Invalid> {
        Request::parse(&format!(
            r#"{{"method":"eth_chainId","world":{{"enabled":true,"wallets":[],"networks":{{}}{extra}}}}}"#
        ))
    }

    #[test]
    fn chains_are_positive_safe_integers() {
        for (text, chain) in [
            ("1", Some(1)),
            ("8453.0", Some(8453)),
            ("9007199254740991", Some(9_007_199_254_740_991)),
            ("9007199254740992", None),
            ("0", None),
            ("-1", None),
            ("1.5", None),
            ("\"1\"", None),
            ("null", None),
            ("true", None),
        ] {
            let request = world(&format!(r#","chain":{text}"#)).unwrap();
            assert_eq!(request.world.chain, chain, "{text}");
            assert_eq!(request.world.chain_id(), chain.unwrap_or(100), "{text}");
        }
    }

    #[test]
    fn the_shape_is_strict() {
        assert!(world("").is_ok());
        assert_eq!(world(r#","extra":1"#), Err(Invalid));
        assert_eq!(world(r#","networks":[]"#), Err(Invalid));
        assert_eq!(world(r#","networks":{"1":true}"#), Err(Invalid));
        assert_eq!(
            Request::parse(r#"{"method":"eth_chainId","world":{}}"#),
            Err(Invalid)
        );
        assert_eq!(
            Request::parse(r#"{"method":"eth_chainId","world":{"enabled":true,"wallets":[]}}"#),
            Err(Invalid)
        );
        assert_eq!(
            Request::parse(
                r#"{"method":"eth_chainId","world":{"enabled":1,"wallets":[],"networks":{}}}"#
            ),
            Err(Invalid)
        );
        assert_eq!(
            Request::parse(r#"{"method":1,"world":{"enabled":true,"wallets":[],"networks":{}}}"#),
            Err(Invalid)
        );
        assert_eq!(
            Request::parse(
                r#"{"method":"x","world":{"enabled":true,"wallets":[],"networks":{}},"other":1}"#
            ),
            Err(Invalid)
        );
        assert_eq!(Request::parse("[]"), Err(Invalid));
        // A list that isn't one is an empty list, as `walletList` reads it.
        assert!(
            world(r#","wallets":{"0":1}"#)
                .unwrap()
                .world
                .wallets()
                .is_empty()
        );
    }

    #[test]
    fn read_params_are_the_pages_or_an_empty_list() {
        for (params, text) in [
            ("", "[]"),
            (r#","params":null"#, "[]"),
            (r#","params":0"#, "[]"),
            (r#","params":"""#, "[]"),
            (r#","params":false"#, "[]"),
            (r#","params":{"b":1,"a":2}"#, r#"{"b":1,"a":2}"#),
            (r#","params":[1e2,"\ud800"]"#, r#"[100,"\ud800"]"#),
        ] {
            let request = Request::parse(&format!(
                r#"{{"method":"eth_call"{params},"world":{{"enabled":true,"wallets":[],"networks":{{}}}}}}"#
            ))
            .unwrap();
            assert_eq!(request.read_params(), text, "{params}");
        }
    }
}
