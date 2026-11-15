//! `personal_sign` and `eth_signTypedData_v4` (design 0012, APR-5d-1), as
//! the approvals reference's `page-signing.js` (`7f85551d`) runs them for a
//! vault account, the prompt asked through the core's `approval.request`:
//!
//! - **A document with no key** gets `4100` before anything else
//!   ([`crate::start`]).
//! - **Then, in the reference's order:** the key's grant (`4100` "Not
//!   connected" without one); the account it exposes, from main's wallet
//!   list (`-32603` once gone); a Safe off Gnosis refused; whether the
//!   site's signing rule would answer, read only outside Agent custody
//!   (`PageContext.agent`, a missing one counting as custody); and what is
//!   signed, before any prompt: the message's bytes, or the core's view of
//!   the typed data against the page's chain. One that can't be shown
//!   answers `-32603` with the reference's message.
//! - **The user decides** on `eth.sign`, with the reference's view. An
//!   approve is checked against the core's own grant again: the key must
//!   still expose the account shown. Then the daemon mints the page-kind
//!   token itself, for the page and the handle of that answer, spends it on
//!   the signature at once, and answers the signature
//!   ([`Approved`]). A rejection or a closed handle answers `4001`, a busy
//!   window `-32002`, and nothing is signed.
//!
//! **Left to APR-5d-2** (*inferred*, each answering `4200` "Method not
//! supported" for now, as a method without its route does): a request the
//! site's signing rule would answer with no prompt; a Ledger's, a phone's
//! or a Safe's signature (`{ device }`); and "Always allow", which Q9
//! writes as the limited rule. Until then the prompt offers
//! `{ "alwaysAllow": [false] }`, and an approve that ticks it is
//! [`Crossed`].

use fc_json::{JsString, JsValue};

use crate::prompt::{Crossed, Decision};
use crate::{Answer, Request, World, strictly_equal, v8json};

/// The prompt's kind (design 0011).
pub const SIGN_KIND: &str = "eth.sign";

/// What the prompt offers until APR-5d-2 (*inferred*): "Always allow"
/// unticked only.
const CHOICES: &str = r#"{"alwaysAllow":[false]}"#;

const INTERNAL_ERROR_CODE: i64 = -32603;
const NOT_CONNECTED: (i64, &str) = (4100, "Not connected. Call eth_requestAccounts first.");
const USER_REJECTED: (i64, &str) = (4001, "User rejected the request");
const BUSY: (i64, &str) = (-32002, "Another wallet request is already pending");
const ACCOUNT_GONE: &str = "The connected account is no longer available";
const SAFE_OFF_GNOSIS: &str = "This multi-owner account can only sign on Gnosis Chain \u{2014} switch the app to Gnosis first.";
/// `getSigner`'s refusal of an index no account can have (*inferred*: a
/// grant's index past fc-approval's `MAX_ACCOUNT`).
const INVALID_INDEX: &str = "Invalid wallet index";
/// v1 Safes live on Gnosis.
const GNOSIS_CHAIN_ID: u64 = 100;
/// The largest account index a grant holds (fc-approval's `MAX_ACCOUNT`).
const MAX_ACCOUNT: f64 = 2_147_483_647.0;
/// A raw 32-byte value: its signature can be a Swarm feed update's (#89).
const RAW_HASH_LENGTH: usize = 32;

/// The two signing methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `personal_sign`.
    Message,
    /// `eth_signTypedData_v4`.
    TypedData,
}

impl Method {
    pub(crate) fn of(name: &str) -> Option<Method> {
        match name {
            "personal_sign" => Some(Method::Message),
            "eth_signTypedData_v4" => Some(Method::TypedData),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Method::Message => "personal_sign",
            Method::TypedData => "eth_signTypedData_v4",
        }
    }

    /// The token kind an approve mints (design 0012, "Tokens").
    pub fn token_kind(self) -> &'static str {
        match self {
            Method::Message => "sign-message",
            Method::TypedData => "sign-typed-data",
        }
    }

    /// The core's method that signs it, and spends the token.
    pub fn core_method(self) -> &'static str {
        match self {
            Method::Message => "sign.message",
            Method::TypedData => "sign.typed_data",
        }
    }

    /// The vault signer's label for a failure (`signers.js`'s `wrapped`).
    fn failure_label(self) -> &'static str {
        match self {
            Method::Message => "Message signing failed",
            Method::TypedData => "Typed data signing failed",
        }
    }

    /// `failure`'s fallback when what is signed can't be shown.
    fn unshowable(self) -> &'static str {
        match self {
            Method::Message => "This message can\u{2019}t be shown",
            Method::TypedData => "This typed data can\u{2019}t be shown",
        }
    }
}

/// A signature request from a document with a key.
#[derive(Debug, Clone, PartialEq)]
pub struct Sign {
    method: Method,
    params: Option<JsValue>,
    world: World,
    key: String,
}

/// The core's view of typed data, `typed_data.hash`'s reply: the hash as
/// hex text, and the view as JSON text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedView {
    pub hash: String,
    pub view: String,
}

/// The `eth.sign` prompt, for a vault account.
#[derive(Debug, Clone, PartialEq)]
pub struct Ask {
    method: Method,
    key: String,
    /// The grant's `walletIndex`, as its file holds it.
    wallet_index: JsValue,
    view: String,
    payload: String,
    expected_hash: Option<String>,
}

/// What a decision does.
#[derive(Debug, Clone, PartialEq)]
pub enum Decided {
    /// Answered, with nothing signed.
    Answer(Answer),
    /// Approved: the daemon mints the token for it, spends it on the
    /// signature, and answers by [`Approved::answer`].
    Sign(Approved),
}

/// An approved signature: what the token binds and the core signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    method: Method,
    account: u32,
    handle: String,
    payload: String,
    expected_hash: Option<String>,
}

impl Approved {
    pub fn method(&self) -> Method {
        self.method
    }

    /// The account the grant exposes.
    pub fn account(&self) -> u32 {
        self.account
    }

    /// The handle main opened for the prompt, which the token binds.
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// The token's payload in the core's form, which is also what the core
    /// signs but the key: `{ message }` for a message, `{ typed_data,
    /// primary_type?, chain_id }` for typed data, as JSON text.
    pub fn payload(&self) -> &str {
        &self.payload
    }

    /// The hash the user was shown, `sign.typed_data`'s `expected_hash`.
    pub fn expected_hash(&self) -> Option<&str> {
        self.expected_hash.as_deref()
    }

    /// The answer: the signature, or the reference's failure. A locked
    /// vault's refusal is passed on as the core words it; any other is
    /// labelled as the vault signer labels it (`signers.js`).
    pub fn answer(&self, signed: Result<&str, (bool, &str)>) -> Answer {
        match signed {
            Ok(signature) => Answer::result(&JsValue::string(signature)),
            Err((true, message)) => failure(message, "Signing failed"),
            Err((false, message)) => Answer::error(
                INTERNAL_ERROR_CODE,
                &format!("{}: {message}", self.method.failure_label()),
            ),
        }
    }

    /// The answer when the wallet index can't name an account.
    fn invalid_index() -> Answer {
        Answer::error(INTERNAL_ERROR_CODE, INVALID_INDEX)
    }
}

/// `failure(err, fallback)`: `-32603` with the error's message, or the
/// fallback for an empty one.
fn failure(message: &str, fallback: &str) -> Answer {
    let message = if message.is_empty() {
        fallback
    } else {
        message
    };
    Answer::error(INTERNAL_ERROR_CODE, message)
}

static UNDEFINED: JsValue = JsValue::Undefined;

/// `candidate?.index`.
fn index_of(candidate: &JsValue) -> &JsValue {
    match candidate {
        JsValue::Null | JsValue::Undefined => &UNDEFINED,
        candidate => candidate.get("index").unwrap_or(&UNDEFINED),
    }
}

/// `params?.[n]`, as JavaScript reads it from what main sent.
fn element(params: Option<&JsValue>, n: usize) -> JsValue {
    match params {
        Some(JsValue::Array(items)) => items.get(n).cloned().unwrap_or(JsValue::Undefined),
        Some(object @ JsValue::Object(_)) => object
            .get(&n.to_string())
            .cloned()
            .unwrap_or(JsValue::Undefined),
        Some(JsValue::String(text)) => text.units().nth(n).map_or(JsValue::Undefined, |unit| {
            JsValue::String(JsString::from_units(&[unit]))
        }),
        _ => JsValue::Undefined,
    }
}

/// What can't be shown: the message `failure` answers.
enum Unshowable {
    Text(&'static str),
    Js(JsString),
    Core(String),
}

#[allow(clippy::cast_possible_truncation)]
/// `normalizeMessage`'s bytes: 0x hex decoded, strictly, or the text as
/// UTF-8 (a lone surrogate as U+FFFD, as `Buffer.from` writes it).
fn message_bytes(text: &JsString) -> Result<Vec<u8>, &'static str> {
    let units: Vec<u16> = text.units().collect();
    let Some(digits) = units.strip_prefix(&[0x30, 0x78]) else {
        return Ok(text.as_str().as_bytes().to_vec());
    };
    if digits.len() % 2 != 0 {
        return Err("Invalid hex message");
    }
    let nibble = |unit: u16| char::from_u32(u32::from(unit)).and_then(|c| c.to_digit(16));
    digits
        .chunks(2)
        .map(|pair| match (nibble(pair[0]), nibble(pair[1])) {
            (Some(high), Some(low)) => Ok((high * 16 + low) as u8),
            _ => Err("Invalid hex message"),
        })
        .collect()
}

/// `signsRawHash(message)`: exactly 32 bytes as main normalizes it; a
/// message that isn't a string counts, malformed hex doesn't.
fn signs_raw_hash(message: &JsValue) -> bool {
    match message {
        JsValue::String(text) => {
            message_bytes(text).is_ok_and(|bytes| bytes.len() == RAW_HASH_LENGTH)
        }
        _ => true,
    }
}

fn prop(name: &str, value: JsValue) -> (JsString, JsValue) {
    (JsString::from(name), value)
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// What is signed, before any prompt (#88).
struct Prepared {
    /// The view's `message`, or its `typedData` and `chains`.
    shown: Vec<(JsString, JsValue)>,
    payload: String,
    expected_hash: Option<String>,
    warned: bool,
}

impl Sign {
    pub(crate) fn new(request: &Request, method: Method, key: &str) -> Sign {
        Sign {
            method,
            params: request.params.clone(),
            world: request.world.clone(),
            key: key.to_owned(),
        }
    }

    pub fn method(&self) -> Method {
        self.method
    }

    /// Runs the request up to its prompt: the grant `grant` gives, the
    /// account, the Safe's chain, the rule, and what is signed, `view`
    /// giving the core's view of typed data from `typed_data.hash`'s params
    /// as JSON text (its error's message when it refuses them). `agent` is
    /// `PageContext.agent`.
    pub fn ask(
        &self,
        agent: Option<bool>,
        grant: impl FnOnce(&str) -> Option<JsValue>,
        view: impl FnOnce(&str) -> Result<TypedView, String>,
    ) -> Result<Ask, Answer> {
        let world = &self.world;
        let Some(permission) = grant(&self.key).filter(JsValue::truthy) else {
            return Err(Answer::error(NOT_CONNECTED.0, NOT_CONNECTED.1));
        };
        let wallet_index = permission
            .get("walletIndex")
            .cloned()
            .unwrap_or(JsValue::Undefined);
        let chain_id = world.chain_id();
        let account = world
            .wallets()
            .iter()
            .find(|candidate| strictly_equal(index_of(candidate), &wallet_index))
            .filter(|account| account.truthy())
            .ok_or_else(|| Answer::error(INTERNAL_ERROR_CODE, ACCOUNT_GONE))?;
        let kind = account.get("type").and_then(JsValue::as_str);
        let safe = kind == Some("safe");
        if safe && chain_id != GNOSIS_CHAIN_ID {
            return Err(Answer::error(INTERNAL_ERROR_CODE, SAFE_OFF_GNOSIS));
        }
        // The rule, read only outside custody: unknown custody is custody.
        let ruled = agent == Some(false) && self.rule_covers(&permission);
        let prepared = self.prepare(chain_id, view).map_err(|unshowable| {
            let fallback = self.method.unshowable();
            match unshowable {
                Unshowable::Text(message) => failure(message, fallback),
                Unshowable::Core(message) => failure(&message, fallback),
                Unshowable::Js(message) if message.utf16_len() == 0 => failure(fallback, fallback),
                Unshowable::Js(message) => Answer::error_js(INTERNAL_ERROR_CODE, &message),
            }
        })?;
        // A warned request always shows its prompt, rule or not (#88). The
        // rule's own path, and a device's, are APR-5d-2's.
        if ruled && !prepared.warned {
            return Err(Answer::unsupported());
        }
        if matches!(kind, Some("ledger" | "remote" | "safe")) {
            return Err(Answer::unsupported());
        }
        let account_view = JsValue::Object(vec![
            prop("index", index_of(account).clone()),
            prop(
                "name",
                match account.get("name") {
                    Some(name @ JsValue::String(_)) => name.clone(),
                    _ => JsValue::string(""),
                },
            ),
            prop(
                "address",
                match account.get("address") {
                    Some(address @ JsValue::String(_)) => address.clone(),
                    _ => JsValue::Null,
                },
            ),
            prop(
                "type",
                match account.get("type") {
                    Some(kind @ JsValue::String(_)) => kind.clone(),
                    _ => JsValue::string("mnemonic"),
                },
            ),
        ]);
        // `chainName(chainId) || null`.
        let name = world
            .network(chain_id)
            .and_then(|network| network.get("name"))
            .filter(|name| name.truthy())
            .cloned()
            .unwrap_or(JsValue::Null);
        // Exact: a chain id is a safe integer.
        #[allow(clippy::cast_precision_loss)]
        let chain = JsValue::Object(vec![
            prop("id", JsValue::Number(chain_id as f64)),
            prop("name", name),
        ]);
        let mut view = vec![
            prop("method", JsValue::string(self.method.name())),
            prop("account", account_view),
            prop("chain", chain),
        ];
        view.extend(prepared.shown);
        Ok(Ask {
            method: self.method,
            key: self.key.clone(),
            wallet_index,
            view: JsValue::Object(view).stringify(),
            payload: prepared.payload,
            expected_hash: prepared.expected_hash,
        })
    }

    /// `ruleCovers` before the view: the grant's signing rule on, and never
    /// for a `personal_sign` of exactly 32 bytes (#89).
    fn rule_covers(&self, permission: &JsValue) -> bool {
        let on = permission
            .get("autoApprove")
            .and_then(|rules| rules.get("signing"))
            == Some(&JsValue::Bool(true));
        on && !(self.method == Method::Message && signs_raw_hash(&element(self.params.as_ref(), 0)))
    }

    /// `prepare`: the message's bytes, or the core's view of the typed data.
    fn prepare(
        &self,
        chain_id: u64,
        view: impl FnOnce(&str) -> Result<TypedView, String>,
    ) -> Result<Prepared, Unshowable> {
        match self.method {
            Method::Message => {
                let message = element(self.params.as_ref(), 0);
                let JsValue::String(text) = &message else {
                    return Err(Unshowable::Text(
                        "The message to sign must be text or 0x-prefixed hex",
                    ));
                };
                let bytes = message_bytes(text).map_err(Unshowable::Text)?;
                let hex = lower_hex(&bytes);
                let raw_hash = bytes.len() == RAW_HASH_LENGTH;
                let shown = vec![prop(
                    "message",
                    JsValue::Object(vec![
                        prop("hex", JsValue::string(hex.as_str())),
                        prop("rawHash", JsValue::Bool(raw_hash)),
                    ]),
                )];
                let payload = JsValue::Object(vec![prop("message", JsValue::string(hex))]);
                Ok(Prepared {
                    shown,
                    payload: payload.stringify(),
                    expected_hash: None,
                    warned: raw_hash,
                })
            }
            Method::TypedData => self.prepare_typed(chain_id, view),
        }
    }

    /// `typedDataViewFor`, then the warnings and the chains they quote.
    fn prepare_typed(
        &self,
        chain_id: u64,
        view: impl FnOnce(&str) -> Result<TypedView, String>,
    ) -> Result<Prepared, Unshowable> {
        let typed = element(self.params.as_ref(), 1);
        let normalized = match &typed {
            JsValue::String(text) => v8json::parse(text).map_err(Unshowable::Js)?,
            other => other.clone(),
        };
        if !normalized.truthy() || !matches!(normalized, JsValue::Object(_) | JsValue::Array(_)) {
            return Err(Unshowable::Text("Typed data is required"));
        }
        let mut params = vec![prop("typed_data", core_typed_data(&normalized))];
        // `primaryType` as the dApp sent it, only when it sent one.
        if let JsValue::Object(props) = &normalized
            && let Some((_, primary)) = props.iter().find(|(key, _)| key == "primaryType")
        {
            params.push(prop("primary_type", primary.clone()));
        }
        params.push(prop("chain_id", JsValue::string(chain_id.to_string())));
        let payload = JsValue::Object(params).stringify();
        let viewed = view(&payload).map_err(Unshowable::Core)?;
        let shown_view =
            fc_json::parse(&viewed.view).map_err(|_| Unshowable::Text(self.method.unshowable()))?;
        let mut warnings = Vec::new();
        let report = |name: &str| shown_view.get(name).and_then(JsValue::as_str);
        if report("named_type") == Some("mismatch") {
            warnings.push("named-type");
        }
        if report("chain") == Some("mismatch") {
            warnings.push("chain-mismatch");
        }
        if report("chain") == Some("absent") {
            warnings.push("chain-absent");
        }
        let chains = if warnings.contains(&"chain-mismatch") {
            warning_chains(&self.world, chain_id, &shown_view)
        } else {
            JsValue::Object(Vec::new())
        };
        let warned = !warnings.is_empty();
        let shown = vec![
            prop(
                "typedData",
                JsValue::Object(vec![
                    prop("hash", JsValue::string(viewed.hash.as_str())),
                    prop("view", shown_view),
                    prop(
                        "warnings",
                        JsValue::Array(warnings.into_iter().map(JsValue::string).collect()),
                    ),
                ]),
            ),
            prop("chains", chains),
        ];
        Ok(Prepared {
            shown,
            payload,
            expected_hash: Some(viewed.hash),
            warned,
        })
    }
}

/// `toCoreTypedData`: the domain (a falsy one as `{}`), the types without
/// `EIP712Domain` (`{ ...types }`), and the message when there is one.
fn core_typed_data(typed: &JsValue) -> JsValue {
    let get = |name: &str| typed.get(name);
    let domain = get("domain")
        .filter(|domain| domain.truthy())
        .cloned()
        .unwrap_or_else(|| JsValue::Object(Vec::new()));
    let mut types = JsValue::Object(Vec::new());
    match get("types") {
        Some(JsValue::Object(props)) => {
            for (key, value) in props {
                if key != "EIP712Domain" {
                    types.set(key.clone(), value.clone());
                }
            }
        }
        Some(JsValue::Array(items)) => {
            for (i, value) in items.iter().enumerate() {
                types.set(i.to_string(), value.clone());
            }
        }
        Some(JsValue::String(text)) => {
            for (i, unit) in text.units().enumerate() {
                types.set(
                    i.to_string(),
                    JsValue::String(JsString::from_units(&[unit])),
                );
            }
        }
        _ => {}
    }
    let mut core = vec![prop("domain", domain), prop("types", types)];
    if let Some(message) = get("message") {
        core.push(prop("message", message.clone()));
    }
    JsValue::Object(core)
}

/// `warningChains`: the names of the page's chain and of the chain the
/// view's domain names, where the registry has a name for them.
fn warning_chains(world: &World, chain_id: u64, view: &JsValue) -> JsValue {
    let mut ids = vec![chain_id.to_string()];
    if let Some(named) = view.get("domain").and_then(|domain| domain.get("chainId"))
        && let Some(id) = big_int(named)
    {
        ids.push(id);
    }
    let mut chains = JsValue::Object(Vec::new());
    for id in ids {
        if let Some(name @ JsValue::String(_)) = world
            .network_keyed(&id)
            .and_then(|network| network.get("name"))
        {
            chains.set(
                id.as_str(),
                JsValue::Object(vec![prop("name", name.clone())]),
            );
        }
    }
    chains
}

/// `BigInt(value).toString()`, or `None` where it throws.
fn big_int(value: &JsValue) -> Option<String> {
    match value {
        JsValue::String(text) => string_to_big_int(text.as_str()),
        JsValue::Number(n) if n.is_finite() && n.fract() == 0.0 => Some(integer_text(*n)),
        JsValue::Bool(on) => Some(String::from(if *on { "1" } else { "0" })),
        JsValue::Array(_) => value
            .js_string()
            .ok()
            .and_then(|text| string_to_big_int(&text)),
        _ => None,
    }
}

/// JavaScript's whitespace and line terminators, which `BigInt` trims.
fn js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// `StringToBigInt`: trimmed; empty is 0; `0x`, `0o` or `0b` digits with
/// no sign; or decimal digits with an optional sign.
fn string_to_big_int(text: &str) -> Option<String> {
    let text = text.trim_matches(js_space);
    if text.is_empty() {
        return Some(String::from("0"));
    }
    let lower = text.get(..2).map(str::to_ascii_lowercase);
    let radix = match lower.as_deref() {
        Some("0x") => 16,
        Some("0o") => 8,
        Some("0b") => 2,
        _ => 10,
    };
    let (negative, digits) = if radix == 10 {
        match text.as_bytes()[0] {
            b'-' => (true, &text[1..]),
            b'+' => (false, &text[1..]),
            _ => (false, text),
        }
    } else {
        (false, &text[2..])
    };
    if digits.is_empty() {
        return None;
    }
    let mut decimal = Decimal::default();
    for c in digits.chars() {
        decimal.mul_add(radix, c.to_digit(radix)?);
    }
    let text = decimal.text();
    Some(if negative && text != "0" {
        format!("-{text}")
    } else {
        text
    })
}

/// An integral double's exact decimal digits, as `BigInt(n).toString()`.
#[allow(clippy::cast_possible_truncation)]
fn integer_text(n: f64) -> String {
    let bits = n.to_bits();
    let negative = n < 0.0;
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1u64 << 52) - 1);
    let (mantissa, shift) = if exponent == 0 {
        (fraction, -1074)
    } else {
        (fraction | (1u64 << 52), exponent - 1075)
    };
    let mut decimal = Decimal::default();
    let (mut mantissa, mut shift) = (mantissa, shift);
    // An integral value: any fraction bits shifted out are zero.
    while shift < 0 {
        mantissa >>= 1;
        shift += 1;
    }
    for c in mantissa.to_string().chars() {
        decimal.mul_add(10, c.to_digit(10).unwrap_or(0));
    }
    for _ in 0..shift {
        decimal.mul_add(2, 0);
    }
    let text = decimal.text();
    if negative && text != "0" {
        format!("-{text}")
    } else {
        text
    }
}

/// An unsigned integer in base 10^9 limbs, least significant first.
#[derive(Default)]
struct Decimal(Vec<u32>);

impl Decimal {
    const BASE: u64 = 1_000_000_000;

    // Each limb is below 10^9, so it fits a u32.
    #[allow(clippy::cast_possible_truncation)]
    fn mul_add(&mut self, factor: u32, add: u32) {
        let mut carry = u64::from(add);
        for limb in &mut self.0 {
            let next = u64::from(*limb) * u64::from(factor) + carry;
            *limb = (next % Self::BASE) as u32;
            carry = next / Self::BASE;
        }
        while carry > 0 {
            self.0.push((carry % Self::BASE) as u32);
            carry /= Self::BASE;
        }
    }

    fn text(&self) -> String {
        let mut limbs = self.0.iter().rev().skip_while(|limb| **limb == 0);
        let Some(first) = limbs.next() else {
            return String::from("0");
        };
        let mut out = first.to_string();
        for limb in limbs {
            out.push_str(&format!("{limb:09}"));
        }
        out
    }
}

impl Ask {
    pub fn kind(&self) -> &'static str {
        SIGN_KIND
    }

    /// The view's JSON text.
    pub fn view(&self) -> &str {
        &self.view
    }

    /// The choices' JSON text.
    pub fn choices(&self) -> &'static str {
        CHOICES
    }

    /// What main's decision does, `grant` giving the key's grant as it
    /// stands now. An approve with a pick not offered is [`Crossed`].
    pub fn decide(
        &self,
        decision: Decision,
        grant: impl FnOnce(&str) -> Option<JsValue>,
    ) -> Result<Decided, Crossed> {
        let (choices, handle) = match decision {
            Decision::Busy => return Ok(Decided::Answer(Answer::error(BUSY.0, BUSY.1))),
            Decision::Reject | Decision::Closed => {
                return Ok(Decided::Answer(Answer::error(
                    USER_REJECTED.0,
                    USER_REJECTED.1,
                )));
            }
            Decision::Approve {
                choices, handle, ..
            } => (choices, handle),
        };
        // The one pick: "Always allow", unticked until APR-5d-2.
        let JsValue::Object(picks) = &choices else {
            return Err(Crossed);
        };
        let offered = picks.iter().all(|(name, value)| {
            name.as_str() == "alwaysAllow" && matches!(value, JsValue::Bool(false))
        });
        if !offered {
            return Err(Crossed);
        }
        // The grant still exposing the account shown.
        let exposes = grant(&self.key)
            .filter(JsValue::truthy)
            .is_some_and(|permission| {
                strictly_equal(
                    permission.get("walletIndex").unwrap_or(&UNDEFINED),
                    &self.wallet_index,
                )
            });
        if !exposes {
            return Ok(Decided::Answer(Answer::error(
                NOT_CONNECTED.0,
                NOT_CONNECTED.1,
            )));
        }
        let account = match self.wallet_index {
            JsValue::Number(index)
                if index.fract() == 0.0 && (0.0..=MAX_ACCOUNT).contains(&index) =>
            {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let account = index as u32;
                account
            }
            _ => return Ok(Decided::Answer(Approved::invalid_index())),
        };
        Ok(Decided::Sign(Approved {
            method: self.method,
            account,
            handle,
            payload: self.payload.clone(),
            expected_hash: self.expected_hash.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_int_reads_as_javascript_does() {
        let s = |text: &str| string_to_big_int(text);
        assert_eq!(s("0x1").as_deref(), Some("1"));
        assert_eq!(s(" 0X64 ").as_deref(), Some("100"));
        assert_eq!(s("").as_deref(), Some("0"));
        assert_eq!(s("-0").as_deref(), Some("0"));
        assert_eq!(s("-12").as_deref(), Some("-12"));
        assert_eq!(s("007").as_deref(), Some("7"));
        assert_eq!(s("0b101").as_deref(), Some("5"));
        assert_eq!(s("-0x1"), None);
        assert_eq!(s("1.5"), None);
        assert_eq!(s("0x"), None);
        assert_eq!(
            s("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").as_deref(),
            Some("115792089237316195423570985008687907853269984665640564039457584007913129639935")
        );
        assert_eq!(integer_text(1e21), "1000000000000000000000");
        assert_eq!(integer_text(-5.0), "-5");
        assert_eq!(integer_text(0.0), "0");
        assert_eq!(integer_text(9_007_199_254_740_993.0), "9007199254740992");
        assert_eq!(big_int(&JsValue::Number(1.5)), None);
        assert_eq!(big_int(&JsValue::Null), None);
    }

    #[test]
    fn element_reads_params_as_javascript_does() {
        let parse = |text: &str| fc_json::parse(text).unwrap();
        assert_eq!(
            element(Some(&parse(r#"["a","b"]"#)), 1),
            JsValue::string("b")
        );
        assert_eq!(
            element(Some(&parse(r#"{"0":"x"}"#)), 0),
            JsValue::string("x")
        );
        assert_eq!(element(Some(&parse(r#""ab""#)), 1), JsValue::string("b"));
        assert_eq!(element(Some(&parse("7")), 0), JsValue::Undefined);
        assert_eq!(element(None, 0), JsValue::Undefined);
    }

    #[test]
    fn a_message_is_its_bytes() {
        let bytes = |text: &str| message_bytes(&JsString::from(text));
        assert_eq!(bytes("0x68656C6c6f").unwrap(), b"hello");
        assert_eq!(bytes("hello").unwrap(), b"hello");
        assert_eq!(bytes("0x"), Ok(Vec::new()));
        assert_eq!(bytes("0x6"), Err("Invalid hex message"));
        assert_eq!(bytes("0xzz"), Err("Invalid hex message"));
        // A lone surrogate's text is U+FFFD's three bytes.
        assert_eq!(
            message_bytes(&JsString::from_units(&[0x61, 0xd800])).unwrap(),
            "a\u{fffd}".as_bytes()
        );
        assert!(signs_raw_hash(&JsValue::string(
            "0x".to_owned() + &"ab".repeat(32)
        )));
        assert!(signs_raw_hash(&JsValue::string("a".repeat(32))));
        assert!(!signs_raw_hash(&JsValue::string(
            "0x".to_owned() + &"zz".repeat(32)
        )));
        assert!(signs_raw_hash(&JsValue::Null));
    }

    #[test]
    fn the_core_typed_data_is_to_core_typed_datas() {
        let parse = |text: &str| fc_json::parse(text).unwrap();
        let core = |text: &str| core_typed_data(&parse(text)).stringify();
        assert_eq!(
            core(r#"{"types":{"EIP712Domain":[],"A":[]},"domain":0,"message":{"x":1}}"#),
            r#"{"domain":{},"types":{"A":[]},"message":{"x":1}}"#
        );
        assert_eq!(
            core(r#"{"types":"ab"}"#),
            r#"{"domain":{},"types":{"0":"a","1":"b"}}"#
        );
        assert_eq!(core(r#"[1]"#), r#"{"domain":{},"types":{}}"#);
        assert_eq!(
            core(r#"{"domain":"d","message":null}"#),
            r#"{"domain":"d","types":{},"message":null}"#
        );
    }
}
