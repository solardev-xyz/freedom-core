//! `eth_sendTransaction` for a vault account (design 0012, APR-5e-1;
//! "Transaction building"), as the approvals reference's `page-sends.js`
//! (`7f85551d`) runs a prompted send, the prompt asked through the core's
//! `approval.request`:
//!
//! - **A document with no key** gets `4100` before anything else
//!   ([`crate::start`]).
//! - **Then, in the reference's order:** the transaction's form (`txOf`:
//!   `-32602` with its message), the key's grant (`4100` "Not
//!   connected"), the account it exposes in main's wallet list (`-32603`
//!   once gone), and a Safe off Gnosis refused. A Ledger's, a phone's or a
//!   Safe's account answers `4200` until APR-5e-2 (*inferred*), and no
//!   standing rule answers a send through the dispatcher until then: every
//!   vault send is asked (*inferred*: Q9 asks rather than refuses).
//! - **The core prepares the send** ([`Prepare`]): the gas limit is
//!   `eth_estimateGas` plus 20% through the core's own chain machine, and
//!   the fees are its own quote's, with the type they imply. Either failing
//!   leaves the send with no fee (the quirk "a failed estimate leaves the
//!   send without a fee"): the prompt shows none, and an approve asks for
//!   the quote again.
//! - **The prompt** is `eth.send`, its view the reference's, with the
//!   core's fee check's verdict. On an approve the fee is judged again; one
//!   newly above the threshold, not confirmed again, is asked again on a new
//!   prompt. Then the key's grant must still expose the account, and the
//!   daemon mints the `dapp-send` token for that answer's page and handle,
//!   binding the prepared transaction and "Always allow" ([`Prepared`]).
//! - **The answer is `{ send }`**: the prepared transaction without its
//!   nonce, and its token, for main to add the nonce, have it signed by
//!   `sign.transaction` with no other field changed, record it and
//!   broadcast it. "Always allow" rides in the token: `sign.transaction`
//!   writes Q9's limited rule once it has signed (`token-remember`).

use fc_json::{JsString, JsValue};

use crate::prompt::{Crossed, Decision};
use crate::sign::{Device, UNDEFINED, account_index, big_int, element, failure, index_of, prop};
use crate::{Answer, Request, World, strictly_equal};

/// The prompt's kind (design 0011).
pub const SEND_KIND: &str = "eth.send";

/// What the prompt offers: "Always allow" and the fee confirmed again, each
/// unticked or ticked, as the reference's `sendChoices` takes them whatever
/// the view offers (*inferred*). "Always allow" on a plain transfer writes
/// nothing, as in the reference.
const CHOICES: &str = r#"{"alwaysAllow":[false,true],"feeAcknowledged":[false,true]}"#;

/// The token kind an approve mints.
pub const TOKEN_KIND: &str = "dapp-send";

const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR_CODE: i64 = -32603;
const NOT_CONNECTED: (i64, &str) = (4100, "Not connected. Call eth_requestAccounts first.");
const USER_REJECTED: (i64, &str) = (4001, "User rejected the request");
const BUSY: (i64, &str) = (-32002, "Another wallet request is already pending");
const ACCOUNT_GONE: &str = "The connected account is no longer available";
const SAFE_OFF_GNOSIS: &str = "This multi-owner account can only transact on Gnosis Chain \u{2014} switch the app to Gnosis first.";
const INVALID_INDEX: &str = "Invalid wallet index";
/// v1 Safes live on Gnosis.
const GNOSIS_CHAIN_ID: u64 = 100;

/// A send request from a document with a key.
#[derive(Debug, Clone, PartialEq)]
pub struct Send {
    params: Option<JsValue>,
    world: World,
    key: String,
}

/// The page's transaction, checked for form (`txOf`): `to` as the page
/// sent it, `value` as a decimal, `data` as hex text.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PageTx {
    to: String,
    value: String,
    data: String,
}

/// A send past its checks, before its quote: the core asks its chain
/// machine for the estimate and the fee quote.
#[derive(Debug, Clone, PartialEq)]
pub struct Prepare {
    key: String,
    /// The grant's `walletIndex`, as its file holds it.
    wallet_index: JsValue,
    account_view: JsValue,
    /// The account's address, as main's wallet list gives it.
    address: JsValue,
    chain_id: u64,
    chain_view: JsValue,
    tx: PageTx,
}

/// The fees a quote gives, in the type they imply.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fees {
    Eip1559 { max_fee: String, priority: String },
    Legacy { gas_price: String },
}

/// A send's quote (`quote`): the gas limit, the fees, and the most the
/// send is shown to cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quoted {
    gas_limit: String,
    fees: Fees,
    estimate: String,
}

/// A send asked on `eth.send`.
#[derive(Debug, Clone, PartialEq)]
pub struct Ask {
    prepare: Prepare,
    quoted: Option<Quoted>,
    view: String,
}

/// What a decision on the prompt does.
#[derive(Debug, Clone, PartialEq)]
pub enum Decided {
    /// Answered, with nothing minted.
    Answer(Answer),
    /// Approved while the fee couldn't be quoted: the quote is asked again,
    /// then the prompt.
    Requote(Prepare),
    /// Approved: the fee is judged again ([`Judge::judged`]).
    Judge(Judge),
}

/// An approve, before the fee check at the moment of approval.
#[derive(Debug, Clone, PartialEq)]
pub struct Judge {
    prepare: Prepare,
    quoted: Quoted,
    handle: String,
    acknowledged: bool,
    always_allow: bool,
}

/// What the check at approval leaves.
#[derive(Debug, Clone, PartialEq)]
pub enum Judged {
    /// Refused, with nothing minted.
    Answer(Answer),
    /// The fee is newly above the threshold: asked again.
    Ask(Ask),
    /// The daemon mints the token, and answers `{ send }`.
    Send(Prepared),
}

/// An approved send: what the token binds, and main signs with the nonce
/// added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    account: u32,
    handle: String,
    tx: String,
    remember: bool,
}

/// `quantityOf`: a quantity as decimal text, `None` when absent; `Err` for
/// any other value.
fn quantity_of(value: &JsValue) -> Result<Option<String>, ()> {
    match value {
        JsValue::Undefined | JsValue::Null => return Ok(None),
        JsValue::String(text) if text.utf16_len() == 0 => return Ok(None),
        JsValue::String(_) => {}
        JsValue::Number(n) if n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0 => {}
        _ => return Err(()),
    }
    match big_int(value) {
        Some(text) if !text.starts_with('-') => Ok(Some(text)),
        _ => Err(()),
    }
}

/// `/^0x[0-9a-fA-F]{40}$/`.
fn is_address(text: &JsString) -> bool {
    let text = text.as_str();
    text.len() == 42 && text.starts_with("0x") && text[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// `/^0x(?:[0-9a-fA-F]{2})*$/`.
fn is_hex_data(text: &JsString) -> bool {
    let text = text.as_str();
    text.starts_with("0x")
        && text.len() % 2 == 0
        && text[2..].bytes().all(|b| b.is_ascii_hexdigit())
        && !text.contains('\u{fffd}')
}

/// `selectorOf`: the first four bytes of `data` in lowercase, or `None`
/// for a plain transfer.
fn selector_of(data: &str) -> Option<String> {
    let head = data.get(..10)?;
    (head.starts_with("0x") && head[2..].bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| head.to_ascii_lowercase())
}

/// `txOf(params)`, or its refusal's message.
fn tx_of(params: Option<&JsValue>) -> Result<PageTx, &'static str> {
    let raw = match params {
        Some(JsValue::Array(_)) => element(params, 0),
        _ => JsValue::Undefined,
    };
    if !matches!(raw, JsValue::Object(_)) {
        return Err("Transaction parameters are required");
    }
    let to = match raw.get("to") {
        Some(JsValue::String(to)) if is_address(to) => to.as_str().to_owned(),
        _ => return Err("The transaction needs a recipient address (to)"),
    };
    let data = match raw.get("data") {
        None | Some(JsValue::Undefined | JsValue::Null) => String::from("0x"),
        Some(JsValue::String(data)) if data.utf16_len() == 0 => String::from("0x"),
        Some(JsValue::String(data)) if is_hex_data(data) => data.as_str().to_owned(),
        Some(_) => return Err("Invalid transaction data"),
    };
    let value = quantity_of(raw.get("value").unwrap_or(&UNDEFINED))
        .map_err(|()| "Invalid transaction value")?
        .unwrap_or_else(|| String::from("0"));
    // The page's own gas is checked for form; the estimate gives the limit.
    quantity_of(raw.get("gas").unwrap_or(&UNDEFINED)).map_err(|()| "Invalid transaction gas")?;
    Ok(PageTx { to, value, data })
}

/// `accountView`, as main shows the account.
fn account_view(account: &JsValue) -> JsValue {
    let text = |name: &str, fallback: JsValue| match account.get(name) {
        Some(value @ JsValue::String(_)) => value.clone(),
        _ => fallback,
    };
    JsValue::Object(vec![
        prop("index", index_of(account).clone()),
        prop("name", text("name", JsValue::string(""))),
        prop("address", text("address", JsValue::Null)),
        prop("type", text("type", JsValue::string("mnemonic"))),
    ])
}

/// `chainView`: the registry's name, or null; its native symbol, or ETH.
fn chain_view(world: &World, chain_id: u64) -> JsValue {
    let network = world.network(chain_id);
    let name = network
        .and_then(|network| network.get("name"))
        .filter(|name| name.truthy())
        .cloned()
        .unwrap_or(JsValue::Null);
    let symbol = match network.and_then(|network| network.get("symbol")) {
        Some(symbol @ JsValue::String(text)) if text.utf16_len() > 0 => symbol.clone(),
        _ => JsValue::string("ETH"),
    };
    // Exact: a chain id is a safe integer.
    #[allow(clippy::cast_precision_loss)]
    let id = JsValue::Number(chain_id as f64);
    JsValue::Object(vec![
        prop("id", id),
        prop("name", name),
        prop("symbol", symbol),
    ])
}

impl Send {
    pub(crate) fn new(request: &Request, key: &str) -> Send {
        Send {
            params: request.params.clone(),
            world: request.world.clone(),
            key: key.to_owned(),
        }
    }

    /// Runs the request up to its quote: the form, the grant `grant`
    /// gives, the account, and the Safe's chain.
    pub fn prepare(&self, grant: impl FnOnce(&str) -> Option<JsValue>) -> Result<Prepare, Answer> {
        let tx = tx_of(self.params.as_ref())
            .map_err(|message| Answer::error(INVALID_PARAMS, message))?;
        let Some(permission) = grant(&self.key).filter(JsValue::truthy) else {
            return Err(Answer::error(NOT_CONNECTED.0, NOT_CONNECTED.1));
        };
        let wallet_index = permission
            .get("walletIndex")
            .cloned()
            .unwrap_or(JsValue::Undefined);
        // The chain this page reads (an onchain app's own), never the
        // grant's.
        let chain_id = self.world.chain_id();
        let account = self
            .world
            .wallets()
            .iter()
            .find(|candidate| strictly_equal(index_of(candidate), &wallet_index))
            .filter(|account| account.truthy())
            .ok_or_else(|| Answer::error(INTERNAL_ERROR_CODE, ACCOUNT_GONE))?;
        let device = Device::of(account.get("type").and_then(JsValue::as_str));
        if device == Some(Device::Safe) && chain_id != GNOSIS_CHAIN_ID {
            return Err(Answer::error(INTERNAL_ERROR_CODE, SAFE_OFF_GNOSIS));
        }
        // A device's send, and a Safe's, are APR-5e-2's.
        if device.is_some() {
            return Err(Answer::unsupported());
        }
        Ok(Prepare {
            key: self.key.clone(),
            wallet_index,
            account_view: account_view(account),
            address: account
                .get("address")
                .cloned()
                .unwrap_or(JsValue::Undefined),
            chain_id,
            chain_view: chain_view(&self.world, chain_id),
            tx,
        })
    }
}

impl Prepare {
    /// The chain the send is for: the page's.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// `eth_estimateGas`'s params, as transaction-service.js sends them:
    /// `[{ from, to, value, data }]`, the value in decimal.
    pub fn estimate_params(&self) -> String {
        let estimate = JsValue::Object(vec![
            prop("from", self.address.clone()),
            prop("to", JsValue::string(self.tx.to.as_str())),
            prop("value", JsValue::string(self.tx.value.as_str())),
            prop("data", JsValue::string(self.tx.data.as_str())),
        ]);
        JsValue::Array(vec![estimate]).stringify()
    }

    /// `quote`: from the estimate's `result` and the fee quote, each `None`
    /// when its read failed. `None` when either failed or gives nothing to
    /// sign with.
    pub fn quoted(&self, estimate: Option<&JsValue>, quote: Option<&JsValue>) -> Option<Quoted> {
        // `BigInt(result) * 120n / 100n`.
        let gas = big_int(estimate?)?;
        if gas.starts_with('-') {
            return None;
        }
        let gas_limit = div_small(&mul_small(&gas, 6), 5);
        let quote = quote?;
        let field = |name: &str| quote.get(name).unwrap_or(&UNDEFINED);
        let eip1559 =
            matches!(quote.get("type"), Some(JsValue::String(kind)) if kind.as_str() == "eip1559");
        let fees = if eip1559 {
            let max_fee = quantity_of(field("maxFeePerGas")).ok()?;
            let priority = quantity_of(field("maxPriorityFeePerGas")).ok()?;
            Fees::Eip1559 {
                max_fee: max_fee?,
                priority: priority?,
            }
        } else {
            Fees::Legacy {
                gas_price: quantity_of(field("gasPrice")).ok()??,
            }
        };
        let effective = quantity_of(field("effectiveGasPrice")).ok()?;
        let per_gas = effective.unwrap_or_else(|| match &fees {
            Fees::Eip1559 { max_fee, .. } => max_fee.clone(),
            Fees::Legacy { gas_price } => gas_price.clone(),
        });
        let estimate = mul(&gas_limit, &per_gas);
        Some(Quoted {
            gas_limit,
            fees,
            estimate,
        })
    }

    /// The prompt, with the quote (or none) and the fee check's verdict
    /// (`verdict`, JSON text: the core's, with the reference's names), or
    /// none.
    pub fn ask(self, quoted: Option<Quoted>, verdict: Option<&str>) -> Ask {
        let view = view(&self, quoted.as_ref(), verdict, false);
        Ask {
            prepare: self,
            quoted,
            view,
        }
    }
}

impl Quoted {
    /// The transaction in `sign.transaction`'s form, without its nonce.
    pub fn tx(&self, prepare: &Prepare) -> String {
        let tx = &prepare.tx;
        let mut fields = vec![
            prop(
                "type",
                JsValue::Number(match self.fees {
                    Fees::Eip1559 { .. } => 2.0,
                    Fees::Legacy { .. } => 0.0,
                }),
            ),
            prop("chain_id", JsValue::string(prepare.chain_id.to_string())),
            prop("gas_limit", JsValue::string(self.gas_limit.as_str())),
            prop("to", JsValue::string(tx.to.as_str())),
            prop("value", JsValue::string(tx.value.as_str())),
            prop("data", JsValue::string(tx.data.as_str())),
        ];
        match &self.fees {
            Fees::Eip1559 { max_fee, priority } => {
                fields.push(prop("max_fee_per_gas", JsValue::string(max_fee.as_str())));
                fields.push(prop(
                    "max_priority_fee_per_gas",
                    JsValue::string(priority.as_str()),
                ));
            }
            Fees::Legacy { gas_price } => {
                fields.push(prop("gas_price", JsValue::string(gas_price.as_str())));
            }
        }
        JsValue::Object(fields).stringify()
    }

    /// The view's `fee`: the gas limit, the fees and the estimate.
    fn view(&self) -> JsValue {
        let mut fee = vec![prop("gasLimit", JsValue::string(self.gas_limit.as_str()))];
        match &self.fees {
            Fees::Eip1559 { max_fee, priority } => {
                fee.push(prop("maxFeePerGas", JsValue::string(max_fee.as_str())));
                fee.push(prop(
                    "maxPriorityFeePerGas",
                    JsValue::string(priority.as_str()),
                ));
            }
            Fees::Legacy { gas_price } => {
                fee.push(prop("gasPrice", JsValue::string(gas_price.as_str())));
            }
        }
        fee.push(prop("estimate", JsValue::string(self.estimate.as_str())));
        JsValue::Object(fee)
    }
}

/// `sendView`: the account, the chain, the transaction in main's form
/// (`to` checksummed), the quoted fee, the fee check's verdict, whether
/// the fee is asked again, and whether "Always allow" is offered.
fn view(prepare: &Prepare, quoted: Option<&Quoted>, verdict: Option<&str>, again: bool) -> String {
    let tx = &prepare.tx;
    let to = fc_evm::parse_address(&tx.to)
        .map(|address| fc_evm::checksum_address(&address))
        .unwrap_or_else(|_| tx.to.clone());
    let verdict = verdict
        .and_then(|text| fc_json::parse(text).ok())
        .unwrap_or(JsValue::Null);
    JsValue::Object(vec![
        prop("account", prepare.account_view.clone()),
        prop("chain", prepare.chain_view.clone()),
        prop(
            "tx",
            JsValue::Object(vec![
                prop("to", JsValue::string(to)),
                prop("value", JsValue::string(tx.value.as_str())),
                prop("data", JsValue::string(tx.data.as_str())),
            ]),
        ),
        prop("fee", quoted.map_or(JsValue::Null, Quoted::view)),
        prop("feeCheck", verdict),
        prop("feeAskAgain", JsValue::Bool(again)),
        prop(
            "alwaysAllow",
            JsValue::Bool(selector_of(&tx.data).is_some()),
        ),
    ])
    .stringify()
}

impl Ask {
    pub fn kind(&self) -> &'static str {
        SEND_KIND
    }

    /// The view's JSON text.
    pub fn view(&self) -> &str {
        &self.view
    }

    /// The choices' JSON text.
    pub fn choices(&self) -> &'static str {
        CHOICES
    }

    /// What main's decision does. An approve with a pick not offered is
    /// [`Crossed`].
    pub fn decide(self, decision: Decision) -> Result<Decided, Crossed> {
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
        let JsValue::Object(picks) = &choices else {
            return Err(Crossed);
        };
        let (mut always_allow, mut acknowledged) = (false, false);
        for (name, value) in picks {
            match (name.as_str(), value) {
                ("alwaysAllow", JsValue::Bool(ticked)) => always_allow = *ticked,
                ("feeAcknowledged", JsValue::Bool(ticked)) => acknowledged = *ticked,
                _ => return Err(Crossed),
            }
        }
        // No fee to confirm: the approval asks for the quote again.
        let Some(quoted) = self.quoted else {
            return Ok(Decided::Requote(self.prepare));
        };
        Ok(Decided::Judge(Judge {
            prepare: self.prepare,
            quoted,
            handle,
            acknowledged,
            always_allow,
        }))
    }
}

impl Judge {
    /// The chain whose fee evidence judges it.
    pub fn chain_id(&self) -> u64 {
        self.prepare.chain_id
    }

    /// The transaction judged, in `sign.transaction`'s form without its
    /// nonce.
    pub fn tx(&self) -> String {
        self.quoted.tx(&self.prepare)
    }

    /// Whether the user confirmed the fee again.
    pub fn acknowledged(&self) -> bool {
        self.acknowledged
    }

    /// The check at approval's verdict (`verdict`, JSON text with
    /// `askAgain`): asked again when `ask_again`; otherwise the key's grant,
    /// as `grant` gives it now, must still expose the account shown.
    pub fn judged(
        self,
        verdict: &str,
        ask_again: bool,
        grant: impl FnOnce(&str) -> Option<JsValue>,
    ) -> Judged {
        if ask_again {
            let view = view(&self.prepare, Some(&self.quoted), Some(verdict), true);
            return Judged::Ask(Ask {
                prepare: self.prepare,
                quoted: Some(self.quoted),
                view,
            });
        }
        let exposes = grant(&self.prepare.key)
            .filter(JsValue::truthy)
            .is_some_and(|permission| {
                strictly_equal(
                    permission.get("walletIndex").unwrap_or(&UNDEFINED),
                    &self.prepare.wallet_index,
                )
            });
        if !exposes {
            return Judged::Answer(Answer::error(NOT_CONNECTED.0, NOT_CONNECTED.1));
        }
        let Some(account) = account_index(&self.prepare.wallet_index) else {
            return Judged::Answer(Answer::error(INTERNAL_ERROR_CODE, INVALID_INDEX));
        };
        // "Always allow" writes the contract rule, never one for a plain
        // transfer.
        let remember = self.always_allow && selector_of(&self.prepare.tx.data).is_some();
        Judged::Send(Prepared {
            account,
            tx: self.tx(),
            handle: self.handle,
            remember,
        })
    }
}

impl Prepared {
    /// The account the grant exposes.
    pub fn account(&self) -> u32 {
        self.account
    }

    /// The handle main opened for the prompt, which the token binds.
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// The transaction in `sign.transaction`'s form, without its nonce.
    pub fn tx(&self) -> &str {
        &self.tx
    }

    /// Whether the token carries "Always allow".
    pub fn remember(&self) -> bool {
        self.remember
    }

    /// The `dapp-send` token's payload: `{ tx, remember }`.
    pub fn payload(&self) -> String {
        format!(r#"{{"tx":{},"remember":{}}}"#, self.tx, self.remember)
    }

    /// `{ send: { kind, account, tx, handle, token } }` (*inferred*): what
    /// main signs with `sign.transaction`, the nonce added, presenting
    /// `{ token, kind, handle }`. A token the core can't mint answers
    /// `-32603` with its message.
    pub fn answer(&self, minted: Result<&str, &str>) -> Answer {
        let token = match minted {
            Ok(token) => token,
            Err(message) => return failure(message, "Transaction failed"),
        };
        let Ok(tx) = fc_json::parse(&self.tx) else {
            return failure("", "Transaction failed");
        };
        let send = JsValue::Object(vec![
            prop("kind", JsValue::string(TOKEN_KIND)),
            prop("account", JsValue::Number(f64::from(self.account))),
            prop("tx", tx),
            prop("handle", JsValue::string(self.handle.as_str())),
            prop("token", JsValue::string(token)),
        ]);
        Answer::raw(JsValue::Object(vec![prop("send", send)]).stringify())
    }
}

/// Decimal text as base-10^9 limbs, least significant first.
fn limbs(text: &str) -> Vec<u64> {
    let digits = text.as_bytes();
    let mut out = Vec::with_capacity(digits.len() / 9 + 1);
    let mut end = digits.len();
    while end > 0 {
        let start = end.saturating_sub(9);
        let limb = digits[start..end]
            .iter()
            .fold(0u64, |n, d| n * 10 + u64::from(d - b'0'));
        out.push(limb);
        end = start;
    }
    out
}

fn text_of(limbs: &[u64]) -> String {
    let mut iter = limbs.iter().rev().skip_while(|limb| **limb == 0);
    let Some(first) = iter.next() else {
        return String::from("0");
    };
    let mut out = first.to_string();
    for limb in iter {
        out.push_str(&format!("{limb:09}"));
    }
    out
}

const BASE: u64 = 1_000_000_000;

/// `a * b`, for decimal texts.
fn mul(a: &str, b: &str) -> String {
    let (a, b) = (limbs(a), limbs(b));
    let mut out = vec![0u128; a.len() + b.len() + 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            out[i + j] += u128::from(*x) * u128::from(*y);
        }
        // Carry as we go: each cell stays far below u128's range.
        let mut carry = 0u128;
        for cell in out.iter_mut() {
            let next = *cell + carry;
            *cell = next % u128::from(BASE);
            carry = next / u128::from(BASE);
        }
    }
    #[allow(clippy::cast_possible_truncation)]
    let limbs: Vec<u64> = out.into_iter().map(|cell| cell as u64).collect();
    text_of(&limbs)
}

fn mul_small(a: &str, factor: u64) -> String {
    mul(a, &factor.to_string())
}

/// `a / divisor`, rounded down, for decimal text.
fn div_small(a: &str, divisor: u64) -> String {
    let mut limbs = limbs(a);
    let mut rest = 0u64;
    for limb in limbs.iter_mut().rev() {
        let current = rest * BASE + *limb;
        *limb = current / divisor;
        rest = current % divisor;
    }
    text_of(&limbs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_arithmetic_is_bigints() {
        assert_eq!(mul("60000", "30000000000"), "1800000000000000");
        assert_eq!(mul("0", "5"), "0");
        assert_eq!(
            mul(
                "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                "2"
            ),
            "231584178474632390847141970017375815706539969331281128078915168015826259279870"
        );
        assert_eq!(div_small(&mul_small("50000", 6), 5), "60000");
        assert_eq!(div_small(&mul_small("21001", 6), 5), "25201");
        assert_eq!(div_small(&mul_small("1", 6), 5), "1");
        assert_eq!(
            div_small("1000000000000000000000", 7),
            "142857142857142857142"
        );
    }

    #[test]
    fn quantities_are_quantity_of() {
        let q = |text: &str| quantity_of(&fc_json::parse(text).unwrap());
        assert_eq!(q(r#""0x0""#), Ok(Some("0".into())));
        assert_eq!(q(r#""""#), Ok(None));
        assert_eq!(q("null"), Ok(None));
        assert_eq!(q("90000"), Ok(Some("90000".into())));
        assert_eq!(q("1.5"), Err(()));
        assert_eq!(q(r#""-1""#), Err(()));
        assert_eq!(q(r#""-0""#), Ok(Some("0".into())));
        assert_eq!(q(r#"" 12 ""#), Ok(Some("12".into())));
        assert_eq!(q(r#""0x""#), Err(()));
        assert_eq!(q("true"), Err(()));
        assert_eq!(q("9007199254740992"), Err(()));
    }

    #[test]
    fn selectors_are_four_bytes() {
        assert_eq!(selector_of("0xA9059CBB00"), Some("0xa9059cbb".into()));
        assert_eq!(selector_of("0x"), None);
        assert_eq!(selector_of("0xa9059c"), None);
    }
}
