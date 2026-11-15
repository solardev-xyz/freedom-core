//! x402 payments in the core (design 0012, "x402"; X402-1): the cap key, an
//! `accepts[]` entry's cap tuple, and the payment payload built from one
//! entry, byte for byte as main builds it today.
//!
//! The reference is freedom-browser's `src/main/x402/` at the approvals
//! reference (`payment-utils.js`' `tupleFromAccept`, `intercept.js`'
//! `originKeyForUrl`, `sign-flow.js`, `client.js`), over `@x402/core` and
//! `@x402/evm` 2.28.0: `client.js` builds an `x402Client` with
//! `ExactEvmScheme` for `eip155:*` and `ExactEvmSchemeV1` for `base` and
//! `ethereum`, and `sign-flow.js` asks it for the payload of exactly the
//! chosen entry. `vectors/approvals.json`'s `x402` pins every decision here.
//!
//! What the client refuses, the core refuses: an entry of another scheme or
//! network, an unknown `extra.paymentFlow`, the client's default spend
//! controls (only its default assets, at most $1 a payment: 10^decimals
//! atomic units), an address `viem`'s `getAddress` refuses, and an
//! EIP-3009 authorization with less than [`MIN_RUNWAY_SECONDS`] of life
//! (`sign-flow.js`' runway check, which a Permit2 payload skips). Where
//! the reference would sign a value JS coerced (a non-string EIP-712
//! `name`, a fractional `maxTimeoutSeconds`), the core refuses instead
//! (*inferred*, design 0012's X402-1 notes).
//!
//! The crate does no I/O: the wall clock comes in as `now_s`, the nonce as
//! bytes the caller drew, and the signature from the caller's key.

use fc_evm::U256;
use fc_json::JsValue;
use serde_json::{Map, Value, json};

use crate::js;

/// The least life, in seconds, an EIP-3009 authorization must have when it
/// is signed (`sign-flow.js`' `MIN_AUTHORIZATION_RUNWAY_SECONDS`).
pub const MIN_RUNWAY_SECONDS: u64 = 20;

/// Permit2's canonical address (`@x402/evm`'s `PERMIT2_ADDRESS`).
pub const PERMIT2_ADDRESS: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

/// x402's Permit2 proxy, the spender (`x402ExactPermit2ProxyAddress`).
pub const PERMIT2_PROXY: &str = "0x402085c248EeA27D92E8b30b2C58ed07f9E20001";

/// The V1 networks `client.js` registers, with their chains
/// (`EVM_NETWORK_CHAIN_ID_MAP`).
pub const V1_NETWORKS: [(&str, u64); 2] = [("base", 8453), ("ethereum", 1)];

/// One of `@x402/evm`'s default assets, which the client's default spend
/// controls allow: its network's chain, its address and its decimals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultAsset {
    pub chain_id: u64,
    pub asset: &'static str,
    pub decimals: u32,
}

const fn asset(chain_id: u64, asset: &'static str, decimals: u32) -> DefaultAsset {
    DefaultAsset {
        chain_id,
        asset,
        decimals,
    }
}

/// `@x402/evm` 2.28.0's `DEFAULT_ASSETS`, in its order; `vectors/approvals.json`'s
/// `x402.defaultAssets` is the same list, read from the reference.
pub const DEFAULT_ASSETS: [DefaultAsset; 31] = [
    asset(8453, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6),
    asset(84532, "0x036CbD53842c5426634e7929541eC2318f3dCF7e", 6),
    asset(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6),
    asset(43114, "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", 6),
    asset(4326, "0xFAfDdbb3FC7688494971a79cc65DCa3EF82079E7", 18),
    asset(143, "0x754704Bc059F8C67012fEd69BC8A327a5aafb603", 6),
    asset(10143, "0x534b2f3A21130d7a60830c2Df862319e593943A3", 6),
    asset(988, "0x779Ded0c9e1022225f8E0630b35a9b54bE713736", 6),
    asset(2201, "0x78Cf24370174180738C5B8E352B6D14c83a6c9A9", 6),
    asset(137, "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", 6),
    asset(42161, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 6),
    asset(421614, "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d", 6),
    asset(31612, "0xdD468A1DDc392dcdbEf6db6e34E89AA338F9F186", 18),
    asset(31611, "0x118917a40FAF1CD7a13dB0Ef56C86De7973Ac503", 18),
    asset(723487, "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb", 6),
    asset(72344, "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb", 6),
    asset(36900, "0x9cb8142aEBBcdc60AF7c97Af897A67A8f3CA71C2", 6),
    asset(190415, "0x401eCb1D350407f13ba348573E5630B83638E30D", 6),
    asset(181228, "0x401eCb1D350407f13ba348573E5630B83638E30D", 6),
    asset(50, "0xfA2958CB79b0491CC627c1557F441eF849Ca8eb1", 6),
    asset(51, "0xb5AB69F7bBada22B28e79C8FFAECe55eF1c771D4", 6),
    asset(38833, "0xA5b8BF902b2844dA17d4506cc827F7F1681735E7", 6),
    asset(14, "0xe7cd86e13AC4309349F30B3435a9d337750fC82D", 6),
    asset(42220, "0xcebA9300f2b948710d2653dD7B07f33A8B32118C", 6),
    asset(42220, "0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e", 6),
    asset(42220, "0xD2ab3C9A02DBBAB236BfEC45D1d755DF4267F771", 6),
    asset(11142220, "0x01C5C0122039549AD1493B8220cABEdD739BC44E", 6),
    asset(1329, "0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392", 6),
    asset(1328, "0x4fCF1784B31630811181f670Aea7A7bEF803eaED", 6),
    asset(5042, "0x3600000000000000000000000000000000000000", 6),
    asset(5042002, "0x3600000000000000000000000000000000000000", 6),
];

/// Why an entry can't be paid: nothing is charged or signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Unpayable(pub &'static str);

/// The cap key of a paid URL (design 0012, Q11): its origin, as
/// `originKeyForUrl` gives it for an `http` or `https` URL. x402 pays only
/// such a resource (*inferred*): any other URL has no key.
pub fn cap_key(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

/// An entry's cap tuple (`tupleFromAccept`): its chain, its asset in
/// lowercase, and its amount, as the entry writes it.
#[derive(Debug, Clone, PartialEq)]
pub struct Tuple {
    pub chain_id: f64,
    pub asset: String,
    pub amount: String,
}

impl Tuple {
    /// The cap's key in its origin's object, `"<chainId>:<asset>"`.
    pub fn key(&self) -> String {
        asset_key(self.chain_id, &self.asset)
    }
}

/// `"<chainId>:<asset>"`, the asset in lowercase whatever the caller wrote
/// (`x402-asset-case`), the chain as JS writes the number.
pub fn asset_key(chain_id: f64, asset: &str) -> String {
    format!(
        "{}:{}",
        fc_json::number_to_string(chain_id),
        asset.to_lowercase()
    )
}

/// `tupleFromAccept(accept)`: a CAIP-2 `eip155:` network whose chain
/// `Number` reads as finite, a string `amount` (V2's field) and a string
/// `asset`; none for anything else, a V1 entry included.
pub fn tuple(accept: &Value) -> Option<Tuple> {
    let network = accept.get("network")?.as_str()?;
    let chain = network.strip_prefix("eip155:")?;
    let chain_id = js::string_to_number(chain);
    if !chain_id.is_finite() {
        return None;
    }
    let amount = accept.get("amount")?.as_str()?;
    let asset = accept.get("asset")?.as_str()?;
    Some(Tuple {
        chain_id,
        asset: asset.to_lowercase(),
        amount: amount.to_owned(),
    })
}

/// A decimal amount as `/^\d+$/` takes it, read as BigInt reads it.
pub fn atomic(text: &str) -> Option<U256> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    U256::parse_decimal(text)
}

/// The requirements as main holds them: `@x402/core`'s schema's output
/// (closed objects, required fields and their JSON types).
#[derive(Debug, Clone)]
pub struct Requirements<'a> {
    pub version: u8,
    pub fields: &'a Map<String, Value>,
    pub accepts: &'a [Value],
}

fn closed<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
    what: &'static str,
) -> Result<&'a Map<String, Value>, Unpayable> {
    let object = value.as_object().ok_or(Unpayable(what))?;
    let known = |key: &str| required.contains(&key) || optional.contains(&key);
    if object.keys().any(|key| !known(key)) || required.iter().any(|key| !object.contains_key(*key))
    {
        return Err(Unpayable(what));
    }
    Ok(object)
}

fn nonempty(object: &Map<String, Value>, field: &str) -> bool {
    object
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|text| !text.is_empty())
}

fn string_or_absent(object: &Map<String, Value>, field: &str) -> bool {
    object.get(field).is_none_or(Value::is_string)
}

/// `record(unknown)`, optional and nullable (`OptionalAny`).
fn record_or_null(object: &Map<String, Value>, field: &str) -> bool {
    object
        .get(field)
        .is_none_or(|value| value.is_object() || value.is_null())
}

fn positive_number(object: &Map<String, Value>, field: &str) -> bool {
    object
        .get(field)
        .and_then(Value::as_f64)
        .is_some_and(|n| n > 0.0)
}

impl<'a> Requirements<'a> {
    pub fn parse(value: &'a Value) -> Result<Self, Unpayable> {
        let invalid = "requirements: not x402's PaymentRequired";
        let version = match value.get("x402Version").and_then(Value::as_u64) {
            Some(1) => 1,
            Some(2) => 2,
            _ => return Err(Unpayable(invalid)),
        };
        let fields = if version == 1 {
            closed(value, &["x402Version", "accepts"], &["error"], invalid)?
        } else {
            let fields = closed(
                value,
                &["x402Version", "resource", "accepts"],
                &["error", "extensions"],
                invalid,
            )?;
            let resource = closed(
                &fields["resource"],
                &["url"],
                &["description", "mimeType", "serviceName", "tags", "iconUrl"],
                invalid,
            )?;
            let strings = ["description", "mimeType", "serviceName", "iconUrl"];
            let tags = resource.get("tags").is_none_or(|tags| {
                tags.as_array()
                    .is_some_and(|t| t.iter().all(Value::is_string))
            });
            if !nonempty(resource, "url")
                || !strings.iter().all(|f| string_or_absent(resource, f))
                || !tags
                || !record_or_null(fields, "extensions")
            {
                return Err(Unpayable(invalid));
            }
            fields
        };
        if !string_or_absent(fields, "error") {
            return Err(Unpayable(invalid));
        }
        let accepts = fields["accepts"]
            .as_array()
            .filter(|accepts| !accepts.is_empty())
            .ok_or(Unpayable(invalid))?;
        for accept in accepts {
            entry(accept, version)?;
        }
        Ok(Requirements {
            version,
            fields,
            accepts,
        })
    }
}

/// One `accepts[]` entry, as the schema of its version takes it.
fn entry(accept: &Value, version: u8) -> Result<&Map<String, Value>, Unpayable> {
    let invalid = "requirements: an accepts[] entry isn't x402's PaymentRequirements";
    let fields = if version == 1 {
        let fields = closed(
            accept,
            &[
                "scheme",
                "network",
                "maxAmountRequired",
                "resource",
                "description",
                "payTo",
                "maxTimeoutSeconds",
                "asset",
            ],
            &["mimeType", "outputSchema", "extra"],
            invalid,
        )?;
        let ok = ["maxAmountRequired", "resource"]
            .iter()
            .all(|f| nonempty(fields, f))
            && fields["description"].is_string()
            && string_or_absent(fields, "mimeType")
            && record_or_null(fields, "outputSchema");
        if !ok {
            return Err(Unpayable(invalid));
        }
        fields
    } else {
        let fields = closed(
            accept,
            &[
                "scheme",
                "network",
                "amount",
                "asset",
                "payTo",
                "maxTimeoutSeconds",
            ],
            &["extra"],
            invalid,
        )?;
        let network = fields["network"].as_str().unwrap_or("");
        if !nonempty(fields, "amount") || network.chars().count() < 3 || !network.contains(':') {
            return Err(Unpayable(invalid));
        }
        fields
    };
    let ok = ["scheme", "network", "asset", "payTo"]
        .iter()
        .all(|f| nonempty(fields, f))
        && positive_number(fields, "maxTimeoutSeconds")
        && record_or_null(fields, "extra");
    if !ok {
        return Err(Unpayable(invalid));
    }
    Ok(fields)
}

/// How the authorization moves the asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    /// EIP-3009 `TransferWithAuthorization`, V2's.
    Eip3009,
    /// V1's EIP-3009, `validAfter` ten minutes back.
    Eip3009V1,
    Permit2,
}

/// One entry, checked as the client and `sign-flow.js` check it, ready to
/// be built for an account at a time with a nonce.
#[derive(Debug, Clone)]
pub struct Payment<'a> {
    requirements: Requirements<'a>,
    accept: &'a Map<String, Value>,
    method: Method,
    chain_id: u64,
    amount: U256,
    pay_to: [u8; 20],
    asset: [u8; 20],
    max_timeout: u64,
    /// EIP-3009's domain `name` and `version`.
    domain: Option<(&'a str, &'a str)>,
}

/// The default asset the spend controls find for `asset` on a network's
/// chain, compared in lowercase (`findDefaultAsset`).
fn default_asset(chain_id: u64, asset: &str) -> Option<&'static DefaultAsset> {
    let lower = asset.to_lowercase();
    DEFAULT_ASSETS
        .iter()
        .find(|entry| entry.chain_id == chain_id && entry.asset.to_lowercase() == lower)
}

/// The chain of a V2 network the spend controls know: exactly a
/// `DEFAULT_ASSETS` key, `eip155:<chain>` as the table writes it.
fn v2_chain(network: &str) -> Option<u64> {
    let digits = network.strip_prefix("eip155:")?;
    let chain: u64 = digits.parse().ok()?;
    (chain.to_string() == digits && DEFAULT_ASSETS.iter().any(|a| a.chain_id == chain))
        .then_some(chain)
}

impl<'a> Payment<'a> {
    /// `requirements.accepts[index]`, as `x402Client.createPaymentPayload`
    /// takes `{ ...requirements, accepts: [entry] }`.
    pub fn new(requirements: Requirements<'a>, index: usize) -> Result<Self, Unpayable> {
        let accept = requirements
            .accepts
            .get(index)
            .ok_or(Unpayable("accept_index: no such entry"))?;
        let fields = entry(accept, requirements.version)?;
        let text = |field: &str| fields.get(field).and_then(Value::as_str).unwrap_or("");
        if text("scheme") != "exact" {
            return Err(Unpayable("no client for this scheme"));
        }
        let extra = fields.get("extra").filter(|extra| extra.is_object());
        let extra_field = |name: &str| extra.and_then(|extra| extra.get(name));
        // An unknown payment flow is refused; null or absent is
        // `authorization`.
        match extra_field("paymentFlow") {
            None | Some(Value::Null) => {}
            Some(Value::String(flow))
                if ["authorization", "upfront", "escrow"].contains(&flow.as_str()) => {}
            Some(_) => return Err(Unpayable("unknown paymentFlow")),
        }
        let (chain_id, amount_field) = if requirements.version == 1 {
            let network = text("network");
            let chain = V1_NETWORKS
                .iter()
                .find(|(name, _)| *name == network)
                .map(|(_, chain)| *chain)
                .ok_or(Unpayable("no client for this V1 network"))?;
            (chain, "maxAmountRequired")
        } else {
            // `eip155:*` is registered for every CAIP-2 EVM network; the
            // spend controls then allow only a default asset's network.
            if !text("network").starts_with("eip155:") {
                return Err(Unpayable("no client for this network"));
            }
            let chain = v2_chain(text("network"))
                .ok_or(Unpayable("not one of the client's default assets"))?;
            (chain, "amount")
        };
        let default = default_asset(chain_id, text("asset"))
            .ok_or(Unpayable("not one of the client's default assets"))?;
        let amount = atomic(text(amount_field)).ok_or(Unpayable("amount: not atomic units"))?;
        // `convertToTokenAmount("1", decimals)`: $1 in atomic units.
        let limit = format!("1{}", "0".repeat(default.decimals as usize));
        let limit = U256::parse_decimal(&limit).ok_or(Unpayable("amount: no limit"))?;
        if amount > limit {
            return Err(Unpayable("amount: above the client's $1 limit"));
        }
        let pay_to =
            fc_evm::parse_address(text("payTo")).map_err(|_| Unpayable("payTo: not an address"))?;
        let asset =
            fc_evm::parse_address(text("asset")).map_err(|_| Unpayable("asset: not an address"))?;
        let max_timeout = fields
            .get("maxTimeoutSeconds")
            .and_then(Value::as_u64)
            .ok_or(Unpayable("maxTimeoutSeconds: not whole seconds"))?;
        let method = if requirements.version == 1 {
            Method::Eip3009V1
        } else {
            match extra_field("assetTransferMethod") {
                Some(Value::String(method)) if method == "permit2" => Method::Permit2,
                _ => Method::Eip3009,
            }
        };
        let domain = if method == Method::Permit2 {
            None
        } else {
            let name = extra_field("name").and_then(Value::as_str).unwrap_or("");
            let version = extra_field("version").and_then(Value::as_str).unwrap_or("");
            if name.is_empty() || version.is_empty() {
                return Err(Unpayable("extra: EIP-712 name and version are required"));
            }
            if max_timeout < MIN_RUNWAY_SECONDS {
                return Err(Unpayable("the authorization would expire too soon"));
            }
            Some((name, version))
        };
        Ok(Payment {
            requirements,
            accept: fields,
            method,
            chain_id,
            amount,
            pay_to,
            asset,
            max_timeout,
            domain,
        })
    }

    /// The entry's cap tuple, if it has one.
    pub fn tuple(&self) -> Option<Tuple> {
        tuple(&Value::Object(self.accept.clone()))
    }

    /// The authorization for `from` at `now_s`, with `nonce`: its EIP-712
    /// digest, to sign, and the payload around the signature.
    pub fn build(&self, from: &[u8; 20], now_s: u64, nonce: &[u8; 32]) -> Result<Built, Unpayable> {
        // JS adds doubles: past 2^53 the sum would round.
        let valid_before = now_s
            .checked_add(self.max_timeout)
            .filter(|t| *t < (1 << 53))
            .ok_or(Unpayable("maxTimeoutSeconds: too far ahead"))?;
        let from = fc_evm::checksum_address(from);
        let to = fc_evm::checksum_address(&self.pay_to);
        let token = fc_evm::checksum_address(&self.asset);
        let amount_text = self
            .accept
            .get(if self.requirements.version == 1 {
                "maxAmountRequired"
            } else {
                "amount"
            })
            .and_then(Value::as_str)
            .unwrap_or("");
        let value = self.amount.to_decimal();
        let (domain, types, message, inner) = match (self.method, self.domain) {
            (Method::Permit2, _) => {
                let nonce = U256::from_be_slice(nonce)
                    .ok_or(Unpayable("nonce"))?
                    .to_decimal();
                let authorization = js_object(vec![
                    ("from", js_str(&from)),
                    (
                        "permitted",
                        js_object(vec![
                            ("token", js_str(&token)),
                            ("amount", js_str(amount_text)),
                        ]),
                    ),
                    ("spender", js_str(PERMIT2_PROXY)),
                    ("nonce", js_str(&nonce)),
                    ("deadline", js_str(&valid_before.to_string())),
                    (
                        "witness",
                        js_object(vec![("to", js_str(&to)), ("validAfter", js_str("0"))]),
                    ),
                ]);
                (
                    json!({ "name": "Permit2", "chainId": self.chain_id, "verifyingContract": PERMIT2_ADDRESS }),
                    json!({
                        "PermitWitnessTransferFrom": [
                            { "name": "permitted", "type": "TokenPermissions" },
                            { "name": "spender", "type": "address" },
                            { "name": "nonce", "type": "uint256" },
                            { "name": "deadline", "type": "uint256" },
                            { "name": "witness", "type": "Witness" }
                        ],
                        "TokenPermissions": [
                            { "name": "token", "type": "address" },
                            { "name": "amount", "type": "uint256" }
                        ],
                        "Witness": [
                            { "name": "to", "type": "address" },
                            { "name": "validAfter", "type": "uint256" }
                        ]
                    }),
                    json!({
                        "permitted": { "token": token, "amount": value },
                        "spender": PERMIT2_PROXY,
                        "nonce": nonce,
                        "deadline": valid_before.to_string(),
                        "witness": { "to": to, "validAfter": "0" }
                    }),
                    Inner::Permit2(authorization),
                )
            }
            (method, Some((name, version))) => {
                let valid_after = if method == Method::Eip3009V1 {
                    now_s
                        .checked_sub(600)
                        .ok_or(Unpayable("the clock is before 1970-01-01T00:10:00Z"))?
                } else {
                    0
                };
                let nonce = fc_evm::to_hex(nonce);
                let authorization = js_object(vec![
                    ("from", js_str(&from)),
                    ("to", js_str(&to)),
                    ("value", js_str(amount_text)),
                    ("validAfter", js_str(&valid_after.to_string())),
                    ("validBefore", js_str(&valid_before.to_string())),
                    ("nonce", js_str(&nonce)),
                ]);
                (
                    json!({ "name": name, "version": version, "chainId": self.chain_id, "verifyingContract": token }),
                    json!({
                        "TransferWithAuthorization": [
                            { "name": "from", "type": "address" },
                            { "name": "to", "type": "address" },
                            { "name": "value", "type": "uint256" },
                            { "name": "validAfter", "type": "uint256" },
                            { "name": "validBefore", "type": "uint256" },
                            { "name": "nonce", "type": "bytes32" }
                        ]
                    }),
                    json!({
                        "from": from,
                        "to": to,
                        "value": value,
                        "validAfter": valid_after.to_string(),
                        "validBefore": valid_before.to_string(),
                        "nonce": nonce
                    }),
                    Inner::Eip3009(authorization),
                )
            }
            (_, None) => return Err(Unpayable("extra: EIP-712 name and version are required")),
        };
        let digest = fc_evm::typed_data_hash(&domain, &types, &message)
            .map_err(|_| Unpayable("the authorization can't be hashed"))?;
        Ok(Built {
            digest,
            inner,
            wrapper: self.wrapper()?,
        })
    }

    /// What surrounds the scheme's payload: V1's scheme and network, or
    /// V2's extensions, resource and the accepted entry, as the client
    /// writes them.
    fn wrapper(&self) -> Result<Wrapper, Unpayable> {
        let js = |value: &Value| {
            serde_json::to_string(value)
                .ok()
                .and_then(|text| fc_json::parse(&text).ok())
                .ok_or(Unpayable("requirements: not JSON"))
        };
        if self.requirements.version == 1 {
            return Ok(Wrapper::V1 {
                scheme: js(&self.accept["scheme"])?,
                network: js(&self.accept["network"])?,
            });
        }
        Ok(Wrapper::V2 {
            extensions: self
                .requirements
                .fields
                .get("extensions")
                .map(js)
                .transpose()?,
            resource: js(&self.requirements.fields["resource"])?,
            accepted: js(&Value::Object(self.accept.clone()))?,
        })
    }
}

#[derive(Debug, Clone)]
enum Inner {
    Eip3009(JsValue),
    Permit2(JsValue),
}

#[derive(Debug, Clone)]
enum Wrapper {
    V1 {
        scheme: JsValue,
        network: JsValue,
    },
    V2 {
        extensions: Option<JsValue>,
        resource: JsValue,
        accepted: JsValue,
    },
}

/// A built authorization: the digest to sign, and its payload once signed.
#[derive(Debug, Clone)]
pub struct Built {
    pub digest: [u8; 32],
    inner: Inner,
    wrapper: Wrapper,
}

impl Built {
    /// The payment payload with `signature`, as `JSON.stringify` writes the
    /// client's: the text main base64-encodes into the header.
    pub fn payload(&self, signature: &[u8; 65]) -> String {
        let signature = js_str(&fc_evm::to_hex(signature));
        let inner = match &self.inner {
            Inner::Eip3009(authorization) => js_object(vec![
                ("authorization", authorization.clone()),
                ("signature", signature),
            ]),
            Inner::Permit2(authorization) => js_object(vec![
                ("signature", signature),
                ("permit2Authorization", authorization.clone()),
            ]),
        };
        let payload = match &self.wrapper {
            Wrapper::V1 { scheme, network } => js_object(vec![
                ("x402Version", JsValue::Number(1.0)),
                ("scheme", scheme.clone()),
                ("network", network.clone()),
                ("payload", inner),
            ]),
            Wrapper::V2 {
                extensions,
                resource,
                accepted,
            } => {
                let mut props = vec![("x402Version", JsValue::Number(2.0)), ("payload", inner)];
                if let Some(extensions) = extensions {
                    props.push(("extensions", extensions.clone()));
                }
                props.push(("resource", resource.clone()));
                props.push(("accepted", accepted.clone()));
                js_object(props)
            }
        };
        payload.stringify()
    }
}

fn js_str(text: &str) -> JsValue {
    JsValue::string(text)
}

fn js_object(props: Vec<(&str, JsValue)>) -> JsValue {
    let mut object = JsValue::Object(Vec::new());
    for (name, value) in props {
        object.set(name, value);
    }
    object
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn keys_are_http_origins() {
        assert_eq!(
            cap_key("https://Paid.Example:443/a?b#c").as_deref(),
            Some("https://paid.example")
        );
        assert_eq!(
            cap_key("http://paid.example:8080/").as_deref(),
            Some("http://paid.example:8080")
        );
        assert_eq!(cap_key("bzz://abc/x"), None);
        assert_eq!(cap_key("not a url"), None);
    }

    fn accept() -> Value {
        json!({
            "scheme": "exact", "network": "eip155:8453", "amount": "10000",
            "asset": DEFAULT_ASSETS[0].asset, "payTo": PERMIT2_PROXY, "maxTimeoutSeconds": 60,
            "extra": { "name": "USD Coin", "version": "2" },
        })
    }

    fn v2(accept: Value) -> Value {
        json!({ "x402Version": 2, "resource": { "url": "https://paid.example/a" }, "accepts": [accept] })
    }

    fn payable(requirements: &Value) -> Result<(), Unpayable> {
        Payment::new(Requirements::parse(requirements)?, 0).map(|_| ())
    }

    /// The parse takes exactly what @x402/core's schema gives main: closed
    /// objects, each required field, each field's JSON type.
    #[test]
    fn requirements_as_the_schema_writes_them() {
        assert_eq!(payable(&v2(accept())), Ok(()));
        let changed = |edit: &dyn Fn(&mut Value)| {
            let mut requirements = v2(accept());
            edit(&mut requirements);
            payable(&requirements)
        };
        let refused: [&dyn Fn(&mut Value); 16] = [
            &|r| r["x402Version"] = json!(3),
            &|r| r["x402Version"] = json!("2"),
            &|r| r["unknown"] = json!(1),
            &|r| r["accepts"] = json!([]),
            &|r| r["error"] = json!(5),
            &|r| r["extensions"] = json!([1]),
            &|r| r["resource"]["url"] = json!(""),
            &|r| r["resource"]["tags"] = json!([1]),
            &|r| r["resource"]["other"] = json!("x"),
            &|r| r["accepts"][0]["unknown"] = json!(1),
            &|r| r["accepts"][0]["amount"] = json!(10000),
            &|r| r["accepts"][0]["network"] = json!("eip155"),
            &|r| r["accepts"][0]["maxTimeoutSeconds"] = json!(0),
            &|r| r["accepts"][0]["extra"] = json!("x"),
            &|r| r["accepts"][0]["payTo"] = json!(""),
            &|r| {
                r.as_object_mut().unwrap().remove("resource");
            },
        ];
        for (index, edit) in refused.iter().enumerate() {
            assert!(changed(*edit).is_err(), "edit {index}");
        }
        let kept: [&dyn Fn(&mut Value); 4] = [
            &|r| r["error"] = json!("payment required"),
            &|r| r["extensions"] = json!(null),
            &|r| r["resource"]["tags"] = json!(["a"]),
            &|r| r["accepts"][0]["extra"]["paymentFlow"] = json!("upfront"),
        ];
        for (index, edit) in kept.iter().enumerate() {
            assert_eq!(changed(*edit), Ok(()), "edit {index}");
        }
    }

    #[test]
    fn what_the_client_refuses() {
        let with = |edit: &dyn Fn(&mut Value)| {
            let mut a = accept();
            edit(&mut a);
            payable(&v2(a))
        };
        // $1 of six decimals, and one unit more.
        assert_eq!(with(&|a| a["amount"] = json!("1000000")), Ok(()));
        assert!(with(&|a| a["amount"] = json!("1000001")).is_err());
        assert!(with(&|a| a["amount"] = json!("+1")).is_err());
        assert!(with(&|a| a["scheme"] = json!("upto")).is_err());
        assert!(with(&|a| a["network"] = json!("eip155:8453 ")).is_err());
        assert!(with(&|a| a["asset"] = json!(DEFAULT_ASSETS[1].asset)).is_err());
        assert!(with(&|a| a["extra"]["paymentFlow"] = json!("stream")).is_err());
        assert!(with(&|a| a["extra"]["paymentFlow"] = json!(null)).is_ok());
        assert!(with(&|a| a["extra"]["version"] = json!("")).is_err());
        assert!(with(&|a| a["maxTimeoutSeconds"] = json!(19)).is_err());
        assert!(with(&|a| a["maxTimeoutSeconds"] = json!(20)).is_ok());
        assert!(with(&|a| a["maxTimeoutSeconds"] = json!(20.5)).is_err());
        // Permit2 needs no name, and its runway isn't checked.
        let permit2 = |a: &mut Value| a["extra"] = json!({ "assetTransferMethod": "permit2" });
        assert!(with(&permit2).is_ok());
        assert!(
            with(&|a| {
                permit2(a);
                a["maxTimeoutSeconds"] = json!(1);
            })
            .is_ok()
        );
        assert!(with(&|a| a["extra"] = json!({ "assetTransferMethod": "permit2x" })).is_err());
        // An entry past the list.
        assert!(Payment::new(Requirements::parse(&v2(accept())).unwrap(), 1).is_err());
    }

    #[test]
    fn the_window_is_the_wall_clock_s() {
        let requirements = v2(accept());
        let payment = Payment::new(Requirements::parse(&requirements).unwrap(), 0).unwrap();
        assert!(payment.build(&[1; 20], (1 << 53) - 61, &[0; 32]).is_ok());
        assert!(payment.build(&[1; 20], (1 << 53) - 60, &[0; 32]).is_err());
        let v1 = json!({ "x402Version": 1, "accepts": [{
            "scheme": "exact", "network": "base", "maxAmountRequired": "1", "resource": "r",
            "description": "", "payTo": PERMIT2_PROXY, "maxTimeoutSeconds": 60,
            "asset": DEFAULT_ASSETS[0].asset, "extra": { "name": "n", "version": "2" },
        }] });
        let payment = Payment::new(Requirements::parse(&v1).unwrap(), 0).unwrap();
        assert!(payment.build(&[1; 20], 600, &[0; 32]).is_ok());
        assert!(payment.build(&[1; 20], 599, &[0; 32]).is_err());
    }

    #[test]
    fn asset_keys_are_lowercase() {
        assert_eq!(asset_key(8453.0, "0xAbC"), "8453:0xabc");
        assert_eq!(asset_key(8453.5, "0xa"), "8453.5:0xa");
    }
}
