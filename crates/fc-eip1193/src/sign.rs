//! `personal_sign` and `eth_signTypedData_v4` (design 0012, APR-5d), as
//! the approvals reference's `page-signing.js` (`7f85551d`) runs them, the
//! prompts asked through the core's `approval.request`:
//!
//! - **A document with no key** gets `4100` before anything else
//!   ([`crate::start`]).
//! - **Then, in the reference's order:** the key's grant (`4100` "Not
//!   connected" without one); the account it exposes, from main's wallet
//!   list (`-32603` once gone); a Safe off Gnosis refused; and what is
//!   signed, before any prompt: the message's bytes, or the core's view of
//!   the typed data against the page's chain. One that can't be shown
//!   answers `-32603` with the reference's message.
//! - **The site's standing rule** (APR-5d-2) is chosen only outside Agent
//!   custody (`PageContext.agent`, a missing one counting as custody), for
//!   a vault account, never for a `personal_sign` of exactly 32 bytes (#89)
//!   or a warned view (#88), and only when the core's own grant answers it
//!   under Q9's limits ([`RuleNow`]: the limited rule within its 30 days,
//!   and the rate). A rule past its rate, expired, or today's unlimited
//!   one leaves the request to its prompt. The rule's request asks
//!   `vault.unlock` while the vault is locked, then main's recheck just
//!   before the effect ([`Ask::rechecked`]): custody, the rule gone or the
//!   document gone refuses it with nothing signed.
//! - **Otherwise the user decides** on `eth.sign`, with the reference's
//!   view. An approve is checked against the core's own grant again: the
//!   key must still expose the account shown. Then the daemon mints the
//!   page-kind token itself, for the page and the handle of that answer,
//!   and spends it on the signature at once ([`Approved`]). "Always allow"
//!   ticked writes Q9's limited rule after the signature. A rejection or a
//!   closed handle answers `4001`, a busy window `-32002`, and nothing is
//!   signed.
//! - **No "Always allow" in Agent custody** (APR-7): while
//!   `PageContext.agent` isn't `false` (a missing one counting as custody),
//!   the prompt offers it unticked only, whether the Agent's sheet or the
//!   user answers, and an approve that ticks it is [`Crossed`]: a rule given
//!   in custody would answer only once custody ends.
//! - **A Ledger's, a phone's or a Safe's account** (until 0016; *inferred*
//!   for the phone) is asked as any account is, with "Always allow"
//!   unticked only, and no rule answers it (*inferred*): the device's
//!   outcome isn't the core's to see. An approve mints the token and
//!   returns it to main with the approved request, `{ device }`
//!   ([`DeviceApproval`]).

use fc_json::{JsString, JsValue};

use crate::connect::NO_ADDRESS;
use crate::prompt::{Crossed, Decision, Recheck};
use crate::{Answer, Request, World, strictly_equal, v8json};

/// The prompt's kind (design 0011).
pub const SIGN_KIND: &str = "eth.sign";

/// The unlock a rule's request asks while the vault is locked.
pub const UNLOCK_KIND: &str = "vault.unlock";

/// What the prompt offers a vault account: "Always allow", unticked or
/// ticked.
const CHOICES: &str = r#"{"alwaysAllow":[false,true]}"#;

/// What it offers a device's account until 0016 (*inferred*), since the
/// core can't see whether the device signed, and any account in Agent
/// custody (APR-7): unticked only.
const UNTICKED_CHOICES: &str = r#"{"alwaysAllow":[false]}"#;

/// The unlock's one form of approve: no picks.
pub(crate) const UNLOCK_CHOICES: &str = "{}";

const INTERNAL_ERROR_CODE: i64 = -32603;
const NOT_CONNECTED: (i64, &str) = (4100, "Not connected. Call eth_requestAccounts first.");
const USER_REJECTED: (i64, &str) = (4001, "User rejected the request");
const BUSY: (i64, &str) = (-32002, "Another wallet request is already pending");
pub(crate) const UNLOCK_CANCELLED: (i64, &str) = (4001, "User cancelled unlock");
/// As Swarm and Radicle answer a request Agent custody refuses.
pub(crate) const AGENT_CUSTODY: &str = r#"{"error":{"code":4100,"message":"The origin is not authorized for this operation","data":{"reason":"agent_custody"}}}"#;
pub(crate) const RULE_GONE: &str =
    "Signing was not confirmed: this request is not covered by the site's auto-approve rules";
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

/// A device's account (the reference's `account.type`): its signature is
/// the device's, which main asks for until 0016.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Device {
    /// `ledger`.
    Ledger,
    /// `remote`, a phone (*inferred*: the core can't reach the phone's
    /// session; main relays its job with the token, PHN-2).
    Phone,
    /// `safe`: its owners sign through main's session.
    Safe,
}

impl Device {
    pub(crate) fn of(kind: Option<&str>) -> Option<Device> {
        match kind {
            Some("ledger") => Some(Device::Ledger),
            Some("remote") => Some(Device::Phone),
            Some("safe") => Some(Device::Safe),
            _ => None,
        }
    }

    /// Its `type` in main's wallet list.
    pub fn name(self) -> &'static str {
        match self {
            Device::Ledger => "ledger",
            Device::Phone => "remote",
            Device::Safe => "safe",
        }
    }
}

/// What a rule would answer: the bytes `sign.message` signs, or the core's
/// view of the typed data.
#[derive(Debug, Clone, Copy)]
pub enum Signed<'a> {
    Message(&'a [u8]),
    TypedData { hash: &'a str, view: &'a str },
}

/// A request the site's rule may answer, for the core to judge with its
/// own grant (`fc_approval::standing`).
#[derive(Debug, Clone, Copy)]
pub struct RuleQuery<'a> {
    /// `PageContext.origin`.
    pub key: &'a str,
    /// The account the grant exposes.
    pub account: u32,
    pub signed: Signed<'a>,
}

/// The core's standing rule for a request, counting nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleNow {
    /// The rule answers it.
    Covered,
    /// It would, but for its rate (Q9): the request is asked.
    RateLimited,
    /// No rule answers it: none, off, expired, today's unlimited one, past
    /// its account, in custody, or what the user must see.
    NotCovered,
}

/// What the rule signs, as the core judges it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RuleSigned {
    Message(Vec<u8>),
    TypedData { hash: String, view: String },
}

impl RuleSigned {
    fn borrowed(&self) -> Signed<'_> {
        match self {
            RuleSigned::Message(bytes) => Signed::Message(bytes),
            RuleSigned::TypedData { hash, view } => Signed::TypedData { hash, view },
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

/// A signature past its checks: asked on `eth.sign`, or answered by the
/// site's rule ([`Ask::ruled`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Ask {
    method: Method,
    key: String,
    /// The grant's `walletIndex`, as its file holds it.
    wallet_index: JsValue,
    view: String,
    payload: String,
    expected_hash: Option<String>,
    /// The prompt's `account`, which an unlock shows too.
    account_view: JsValue,
    device: Option<Device>,
    /// Asked in Agent custody: `PageContext.agent` other than `false`
    /// (APR-7).
    custody: bool,
    /// A Safe's address, which its `safe-message` token binds.
    address: Option<JsValue>,
    params: Option<JsValue>,
    chain_id: u64,
    signed: RuleSigned,
    ruled: bool,
}

/// What a decision does.
#[derive(Debug, Clone, PartialEq)]
pub enum Decided {
    /// Answered, with nothing signed.
    Answer(Answer),
    /// Approved: the daemon mints the token for it, spends it on the
    /// signature, and answers by [`Approved::answer`].
    Sign(Approved),
    /// Approved for a device's account: the daemon mints the token and
    /// returns it to main ([`DeviceApproval::answer`]).
    Device(DeviceApproval),
}

/// What main's recheck leaves of a rule's request.
#[derive(Debug, Clone, PartialEq)]
pub enum Rechecked {
    /// Refused, with nothing signed.
    Answer(Answer),
    /// The rule answers: the daemon signs it under `{ standing }`.
    Sign(Approved),
    /// The rule is past its rate now: the user is asked on `eth.sign`.
    Prompt,
}

/// An approved signature, or one the rule answers: what the core signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    method: Method,
    account: u32,
    /// The handle main opened for the prompt, which the token binds; none
    /// for a rule's.
    handle: Option<String>,
    payload: String,
    expected_hash: Option<String>,
    always_allow: bool,
}

impl Approved {
    pub fn method(&self) -> Method {
        self.method
    }

    /// The account the grant exposes.
    pub fn account(&self) -> u32 {
        self.account
    }

    /// The handle main opened for the prompt, which the token binds; `None`
    /// for a request the rule answers, which signs under `{ standing }`.
    pub fn handle(&self) -> Option<&str> {
        self.handle.as_deref()
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

    /// Whether "Always allow" was ticked: once signed, Q9's limited rule
    /// is written for the key, while its grant still exposes the account.
    pub fn always_allow(&self) -> bool {
        self.always_allow
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

/// An approved signature for a device's account (until 0016): the token
/// the daemon mints for it goes back to main with the approved request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceApproval {
    device: Device,
    account: u32,
    handle: String,
    kind: &'static str,
    payload: String,
    expected_hash: Option<String>,
    /// What the token binds, where it isn't `payload`: a device send's
    /// `{ tx, remember }` (APR-5e-2), whose answer shows `{ tx }`.
    binds: Option<String>,
    /// The refusal's text when the token can't be written.
    fallback: &'static str,
}

impl DeviceApproval {
    /// A device's approved send (APR-5e-2): its token kind, the payload
    /// main spends it with, and what the token binds.
    pub(crate) fn send(
        device: Device,
        account: u32,
        handle: String,
        kind: &'static str,
        payload: String,
        binds: Option<String>,
    ) -> DeviceApproval {
        DeviceApproval {
            device,
            account,
            handle,
            kind,
            payload,
            expected_hash: None,
            binds,
            fallback: "Transaction failed",
        }
    }

    /// What the token binds, as JSON text: the payload, or a device send's
    /// `{ tx, remember }`.
    pub fn binds(&self) -> &str {
        self.binds.as_deref().unwrap_or(&self.payload)
    }

    pub fn device(&self) -> Device {
        self.device
    }

    pub fn account(&self) -> u32 {
        self.account
    }

    /// The handle main opened for the prompt, which the token binds.
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// The token's kind: `sign-message` or `sign-typed-data`, or a Safe's
    /// `safe-message`.
    pub fn token_kind(&self) -> &'static str {
        self.kind
    }

    /// What the token binds, as JSON text: a vault signature's payload, or
    /// a Safe's `{ safe, chain_id, method, params }`.
    pub fn payload(&self) -> &str {
        &self.payload
    }

    /// `{ device: { type, kind, account, payload, expected_hash?, handle,
    /// token } }` (*inferred*): what main spends the token with
    /// (`approval.spend`, or a phone's `phone.job`), and the account's
    /// kind. The token is borrowed from the minter's wiping buffer and
    /// never copied here: the daemon writes the answer straight into its
    /// reply's own ([`DeviceAnswer::write_into`]). A token that isn't plain
    /// hex (the minter's are 64 lowercase hex digits) is refused, not
    /// quoted.
    pub fn answer<'t>(&self, token: &'t str) -> Result<DeviceAnswer<'t>, Answer> {
        if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(failure("", self.fallback));
        }
        let Ok(payload) = fc_json::parse(&self.payload) else {
            return Err(failure("", self.fallback));
        };
        let mut device = vec![
            prop("type", JsValue::string(self.device.name())),
            prop("kind", JsValue::string(self.kind)),
            prop("account", JsValue::Number(f64::from(self.account))),
            prop("payload", payload),
        ];
        if let Some(hash) = &self.expected_hash {
            device.push(prop("expected_hash", JsValue::string(hash.as_str())));
        }
        device.push(prop("handle", JsValue::string(self.handle.as_str())));
        // `{"type":…,"handle":"…"}` with its closing brace replaced by the
        // token's field, up to its opening quote.
        let mut before = String::from(r#"{"device":"#);
        before.push_str(&JsValue::Object(device).stringify());
        before.pop();
        before.push_str(r#","token":""#);
        Ok(DeviceAnswer { before, token })
    }

    /// The answer when the token couldn't be minted: `-32603` with the
    /// refusal's message.
    pub fn refused(message: &str) -> Answer {
        failure(message, "Signing failed")
    }
}

/// A `{ device }` answer: its public text, and the token it carries,
/// borrowed from the minter's wiping buffer (design 0012, "Tokens": never
/// in a plain copy, never in Debug output). Its `Debug` prints no token,
/// and it has no `Clone`.
pub struct DeviceAnswer<'t> {
    /// The JSON text up to the token's opening quote.
    before: String,
    token: &'t str,
}

impl DeviceAnswer<'_> {
    /// What follows the token: its closing quote and two braces.
    const AFTER: &'static str = r#""}}"#;

    /// The answer's length in bytes, for a reply sized before it is
    /// written.
    pub fn len(&self) -> usize {
        self.before.len() + self.token.len() + Self::AFTER.len()
    }

    /// Never: the answer always holds its `device`.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Appends the answer's JSON text, its token in place, to `out`: the
    /// caller's wiping buffer, sized for the whole reply first so that no
    /// grown buffer leaves a copy behind.
    pub fn write_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.before.as_bytes());
        out.extend_from_slice(self.token.as_bytes());
        out.extend_from_slice(Self::AFTER.as_bytes());
    }
}

impl std::fmt::Debug for DeviceAnswer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAnswer")
            .field("before", &self.before)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// `failure(err, fallback)`: `-32603` with the error's message, or the
/// fallback for an empty one.
pub(crate) fn failure(message: &str, fallback: &str) -> Answer {
    let message = if message.is_empty() {
        fallback
    } else {
        message
    };
    Answer::error(INTERNAL_ERROR_CODE, message)
}

pub(crate) static UNDEFINED: JsValue = JsValue::Undefined;

/// `candidate?.index`.
pub(crate) fn index_of(candidate: &JsValue) -> &JsValue {
    match candidate {
        JsValue::Null | JsValue::Undefined => &UNDEFINED,
        candidate => candidate.get("index").unwrap_or(&UNDEFINED),
    }
}

/// `params?.[n]`, as JavaScript reads it from what main sent.
pub(crate) fn element(params: Option<&JsValue>, n: usize) -> JsValue {
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

pub(crate) fn prop(name: &str, value: JsValue) -> (JsString, JsValue) {
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
    signed: RuleSigned,
}

/// A grant's `walletIndex` as an account index, where it is one.
pub(crate) fn account_index(wallet_index: &JsValue) -> Option<u32> {
    match wallet_index {
        JsValue::Number(index) if index.fract() == 0.0 && (0.0..=MAX_ACCOUNT).contains(index) => {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let account = *index as u32;
            Some(account)
        }
        _ => None,
    }
}

/// Main's decision on a rule's `vault.unlock`: `None` to go on; a refusal
/// (`4001` "User cancelled unlock", `-32002` for a busy window) otherwise.
/// An approve with any pick is [`Crossed`].
pub(crate) fn unlocked(decision: Decision) -> Result<Option<Answer>, Crossed> {
    match decision {
        Decision::Busy => Ok(Some(Answer::error(BUSY.0, BUSY.1))),
        Decision::Reject | Decision::Closed => {
            Ok(Some(Answer::error(UNLOCK_CANCELLED.0, UNLOCK_CANCELLED.1)))
        }
        Decision::Approve { choices, .. } => match &choices {
            JsValue::Object(picks) if picks.is_empty() => Ok(None),
            _ => Err(Crossed),
        },
    }
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

    /// Runs the request up to its prompt or its rule: the grant `grant`
    /// gives, the account, the Safe's chain, what is signed (`view` giving
    /// the core's view of typed data from `typed_data.hash`'s params as
    /// JSON text, or its error's message when it refuses them), and the
    /// rule, which `rule` judges with the core's own grant. `agent` is
    /// `PageContext.agent`.
    pub fn ask(
        &self,
        agent: Option<bool>,
        grant: impl FnOnce(&str) -> Option<JsValue>,
        rule: impl FnOnce(&RuleQuery<'_>) -> RuleNow,
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
        let device = Device::of(kind);
        if device == Some(Device::Safe) && chain_id != GNOSIS_CHAIN_ID {
            return Err(Answer::error(INTERNAL_ERROR_CODE, SAFE_OFF_GNOSIS));
        }
        // The rule, chosen only outside custody (unknown custody is
        // custody), for a vault account, and never for a raw 32-byte
        // value (#89).
        let rule_may_answer = agent == Some(false)
            && device.is_none()
            && !(self.method == Method::Message
                && signs_raw_hash(&element(self.params.as_ref(), 0)));
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
        // core judges the rule last, with its own grant: the limited rule,
        // its 30 days and its rate (Q9).
        let ruled = rule_may_answer
            && !prepared.warned
            && account_index(&wallet_index).is_some_and(|account| {
                rule(&RuleQuery {
                    key: &self.key,
                    account,
                    signed: prepared.signed.borrowed(),
                }) == RuleNow::Covered
            });
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
            prop("account", account_view.clone()),
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
            account_view,
            device,
            custody: agent != Some(false),
            address: account.get("address").cloned(),
            params: self.params.clone(),
            chain_id,
            signed: prepared.signed,
            ruled,
        })
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
                    signed: RuleSigned::Message(bytes),
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
        let signed = RuleSigned::TypedData {
            hash: viewed.hash.clone(),
            view: viewed.view.clone(),
        };
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
            signed,
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
pub(crate) fn big_int(value: &JsValue) -> Option<String> {
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

    /// The choices' JSON text: "Always allow" unticked or ticked, or
    /// unticked only for a device's account and in Agent custody.
    pub fn choices(&self) -> &'static str {
        if self.offers_always_allow() {
            CHOICES
        } else {
            UNTICKED_CHOICES
        }
    }

    /// Whether "Always allow" may be ticked: a vault account's, outside
    /// Agent custody (APR-7).
    fn offers_always_allow(&self) -> bool {
        self.device.is_none() && !self.custody
    }

    /// The account's kind, for a device's.
    pub fn device(&self) -> Option<Device> {
        self.device
    }

    /// Whether the site's rule answers it, with no prompt but a locked
    /// vault's unlock.
    pub fn ruled(&self) -> bool {
        self.ruled
    }

    /// Whether `decision` approves, with picks the prompt offered, so that
    /// the name is checked before the approve is acted on (APR-5f): `false`
    /// for a rejection, a close or a busy window, which [`Ask::decide`]
    /// answers, and [`Crossed`] for any other pick.
    pub fn approves(&self, decision: &Decision) -> Result<bool, Crossed> {
        match decision {
            Decision::Approve { choices, .. } => self.picks(choices).map(|_| true),
            Decision::Reject | Decision::Closed | Decision::Busy => Ok(false),
        }
    }

    /// The one pick: "Always allow", ticked only where it is offered.
    fn picks(&self, choices: &JsValue) -> Result<bool, Crossed> {
        let JsValue::Object(picks) = choices else {
            return Err(Crossed);
        };
        let mut always_allow = false;
        for (name, value) in picks {
            match value {
                JsValue::Bool(ticked) if name.as_str() == "alwaysAllow" => {
                    if *ticked && !self.offers_always_allow() {
                        return Err(Crossed);
                    }
                    always_allow = *ticked;
                }
                _ => return Err(Crossed),
            }
        }
        Ok(always_allow)
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
        let always_allow = self.picks(&choices)?;
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
        let Some(account) = account_index(&self.wallet_index) else {
            return Ok(Decided::Answer(Approved::invalid_index()));
        };
        if let Some(device) = self.device {
            return Ok(Decided::Device(
                self.device_approval(device, account, handle),
            ));
        }
        Ok(Decided::Sign(Approved {
            method: self.method,
            account,
            handle: Some(handle),
            payload: self.payload.clone(),
            expected_hash: self.expected_hash.clone(),
            always_allow,
        }))
    }

    /// The token a device's approve gets: a Safe's is a `safe-message`,
    /// binding the Safe, its chain and the page's request as sent.
    fn device_approval(&self, device: Device, account: u32, handle: String) -> DeviceApproval {
        let (kind, payload, expected_hash) = if device == Device::Safe {
            let payload = JsValue::Object(vec![
                prop("safe", self.address.clone().unwrap_or(JsValue::Null)),
                prop("chain_id", JsValue::string(self.chain_id.to_string())),
                prop("method", JsValue::string(self.method.name())),
                prop("params", self.params.clone().unwrap_or(JsValue::Null)),
            ]);
            ("safe-message", payload.stringify(), None)
        } else {
            (
                self.method.token_kind(),
                self.payload.clone(),
                self.expected_hash.clone(),
            )
        };
        DeviceApproval {
            device,
            account,
            handle,
            kind,
            payload,
            expected_hash,
            binds: None,
            fallback: "Signing failed",
        }
    }

    /// The unlock's kind, asked for a rule's request while the vault is
    /// locked.
    pub fn unlock_kind(&self) -> &'static str {
        UNLOCK_KIND
    }

    /// The unlock's view: `{ account, reason: "sign" }`.
    pub fn unlock_view(&self) -> String {
        JsValue::Object(vec![
            prop("account", self.account_view.clone()),
            prop("reason", JsValue::string("sign")),
        ])
        .stringify()
    }

    /// The unlock's choices: none.
    pub fn unlock_choices(&self) -> &'static str {
        UNLOCK_CHOICES
    }

    /// What main's decision on the unlock does: `None` to go on to the
    /// recheck; a refusal (`4001` "User cancelled unlock", `-32002` for a
    /// busy window) otherwise. An approve with any pick is [`Crossed`].
    pub fn unlocked(&self, decision: Decision) -> Result<Option<Answer>, Crossed> {
        unlocked(decision)
    }

    /// The rule's request, for the core to judge again just before the
    /// effect; `None` for a request no rule answers.
    pub fn query(&self) -> Option<RuleQuery<'_>> {
        let account = account_index(&self.wallet_index)?;
        self.ruled.then(|| RuleQuery {
            key: &self.key,
            account,
            signed: self.signed.borrowed(),
        })
    }

    /// Just before a rule's effect, after its last wait, in the reference's
    /// order: a tab gone into custody refused (`agent_custody`); the rule
    /// no longer answering (`now`, judged with the core's own grant and
    /// main's fresh custody) refused, but one past its rate asked of the
    /// user, as Q9 asks it (*inferred*); the document gone refused (`4100`
    /// "This page has no address to connect from yet"). Otherwise the rule
    /// answers it.
    pub fn rechecked(&self, recheck: &Recheck, now: RuleNow) -> Rechecked {
        if recheck.agent {
            return Rechecked::Answer(Answer::raw(AGENT_CUSTODY));
        }
        if now == RuleNow::NotCovered {
            return Rechecked::Answer(Answer::error(INTERNAL_ERROR_CODE, RULE_GONE));
        }
        if !recheck.live {
            return Rechecked::Answer(Answer::error(NO_ADDRESS.0, NO_ADDRESS.1));
        }
        let account = match account_index(&self.wallet_index) {
            Some(account) if self.ruled && self.device.is_none() => account,
            _ => return Rechecked::Answer(Answer::error(INTERNAL_ERROR_CODE, RULE_GONE)),
        };
        if now == RuleNow::RateLimited {
            return Rechecked::Prompt;
        }
        Rechecked::Sign(Approved {
            method: self.method,
            account,
            handle: None,
            payload: self.payload.clone(),
            expected_hash: self.expected_hash.clone(),
            always_allow: false,
        })
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

    /// A `{ device }` answer's token goes only into the reply's buffer: no
    /// Debug output shows it, the answer's, its approval's or the
    /// decision's. A token that isn't plain hex is refused, never quoted.
    #[test]
    fn a_device_token_is_in_no_debug_output() {
        const MARKER: &str = "feedfacecafebeef0123456789abcdef";
        let approval = DeviceApproval {
            device: Device::Ledger,
            account: 1,
            handle: "ab".repeat(32),
            kind: "sign-typed-data",
            payload: r#"{"typed_data":{"domain":{},"types":{}},"chain_id":"100"}"#.to_owned(),
            expected_hash: Some(format!("0x{}", "11".repeat(32))),
            binds: None,
            fallback: "Signing failed",
        };
        let answer = approval.answer(MARKER).unwrap();
        let decided = Decided::Device(approval.clone());
        for debug in [
            format!("{answer:?}"),
            format!("{answer:#?}"),
            format!("{approval:?}"),
            format!("{decided:?}"),
        ] {
            assert!(!debug.contains(MARKER), "{debug}");
            assert!(!debug.contains("feedface"), "{debug}");
        }
        let mut out = Vec::with_capacity(answer.len());
        answer.write_into(&mut out);
        assert_eq!(out.len(), answer.len());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!(
                r#"{{"device":{{"type":"ledger","kind":"sign-typed-data","account":1,"payload":{{"typed_data":{{"domain":{{}},"types":{{}}}},"chain_id":"100"}},"expected_hash":"0x{}","handle":"{}","token":"{MARKER}"}}}}"#,
                "11".repeat(32),
                "ab".repeat(32),
            )
        );
        for bad in ["", "ab\"cd", "ab\\cd", "0xab", "ab cd"] {
            assert_eq!(
                approval.answer(bad).unwrap_err(),
                failure("", "Signing failed"),
                "{bad}"
            );
        }
    }

    /// APR-7: while `agent` isn't `false` (true, or missing), "Always
    /// allow" is offered unticked only, and an approve that ticks it is
    /// crossed, nothing signed; unticked, it signs for the answer's handle.
    /// With `agent: false` it is offered and carried to the signature. A
    /// device's account offers it unticked only either way.
    #[test]
    fn no_always_allow_in_custody() {
        let sign_for = |kind: &str| {
            let text = format!(
                r#"{{"method":"personal_sign","params":["0x68656c6c6f","0x4444444444444444444444444444444444444444"],"world":{{"enabled":true,"window_chain":1,"wallets":[{{"index":0,"address":"0x4444444444444444444444444444444444444444","type":"{kind}"}}],"networks":{{}}}}}}"#
            );
            let request = Request::parse(&text).unwrap();
            let crate::Step::Sign(sign) = crate::start(&request, Some("k"), |_| None) else {
                panic!("{kind}")
            };
            sign
        };
        let grant = |_: &str| fc_json::parse(r#"{"walletIndex":0}"#).ok();
        let approve = |picks: &str| Decision::Approve {
            choices: fc_json::parse(picks).unwrap(),
            handle: "ab".repeat(32),
            world: World::from_value(
                fc_json::parse(r#"{"enabled":true,"wallets":[],"networks":{}}"#).unwrap(),
            )
            .unwrap(),
        };
        let ask = |sign: &Sign, agent: Option<bool>| {
            sign.ask(
                agent,
                grant,
                |_| RuleNow::NotCovered,
                |_| Err(String::new()),
            )
            .unwrap()
        };
        let vault = sign_for("mnemonic");
        for agent in [Some(true), None, Some(false)] {
            let ask = ask(&vault, agent);
            let offered = agent == Some(false);
            let ticked = approve(r#"{"alwaysAllow":true}"#);
            if offered {
                assert_eq!(ask.choices(), CHOICES);
                assert_eq!(ask.approves(&ticked), Ok(true));
                let Ok(Decided::Sign(approved)) = ask.decide(ticked, grant) else {
                    panic!("{agent:?}")
                };
                assert!(approved.always_allow());
            } else {
                assert_eq!(ask.choices(), UNTICKED_CHOICES, "{agent:?}");
                assert_eq!(ask.approves(&ticked), Err(Crossed), "{agent:?}");
                assert_eq!(ask.decide(ticked, grant), Err(Crossed), "{agent:?}");
            }
            let unticked = approve(r#"{"alwaysAllow":false}"#);
            assert_eq!(ask.approves(&unticked), Ok(true), "{agent:?}");
            let Ok(Decided::Sign(approved)) = ask.decide(unticked, grant) else {
                panic!("{agent:?}")
            };
            assert!(!approved.always_allow(), "{agent:?}");
            assert_eq!(approved.handle(), Some("ab".repeat(32).as_str()));
            assert_eq!(approved.account(), 0);
        }
        let ledger = sign_for("ledger");
        for agent in [Some(true), None, Some(false)] {
            let ask = ask(&ledger, agent);
            assert_eq!(ask.choices(), UNTICKED_CHOICES, "{agent:?}");
            assert_eq!(
                ask.decide(approve(r#"{"alwaysAllow":true}"#), grant),
                Err(Crossed)
            );
        }
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
