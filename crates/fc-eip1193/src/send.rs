//! `eth_sendTransaction` (design 0012, APR-5e; "Transaction building"), as
//! the approvals reference's `page-sends.js` (`7f85551d`) runs it, the
//! prompts asked through the core's `approval.request`:
//!
//! - **A document with no key** gets `4100` before anything else
//!   ([`crate::start`]).
//! - **Then, in the reference's order:** the transaction's form (`txOf`:
//!   `-32602` with its message), the key's grant (`4100` "Not
//!   connected"), the account it exposes in main's wallet list (`-32603`
//!   once gone), and a Safe off Gnosis refused.
//! - **The site's standing rule** (APR-5e-2) is chosen, before the quote,
//!   only outside custody, for a vault account's contract call (*inferred*:
//!   no rule answers a device's), with D12's pause read as `false`
//!   (`world.paused`), and only when the core's own grant answers it under
//!   Q9's limits ([`Prepare::rule_query`]). It asks `vault.unlock` while the
//!   vault is locked, then is quoted: a read failing answers the
//!   reference's failure, and a fee the check doesn't let through goes to
//!   the prompt ([`Rule::judged`]). Just before the effect main's recheck
//!   refuses it for custody, the rule gone or the document gone; a rule past
//!   its rate, or a fee needing the user, is asked instead. Otherwise the
//!   answer is `{ send }` under the rule ([`Rule::rechecked`]).
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
//! - **A Ledger's or a phone's send** (APR-5e-2) is prepared and asked as a
//!   vault account's, "Always allow" included, which the token carries for
//!   the device send's receipt or the phone payment's rule. A phone picks
//!   its own fee, so its fee isn't checked. A Safe's is asked with its
//!   executor paying, and "Always allow" unticked only (*inferred*). An
//!   approve answers `{ device }` with the token ([`DeviceApproval`]): a
//!   `dapp-send` binding the prepared transaction, or a Safe's `safe-send`
//!   binding `{ safe, chain_id, tx: { to, value, data } }`.
//! - **The answer is `{ send }`**: the prepared transaction without its
//!   nonce, and its token, for main to add the nonce, have it signed by
//!   `sign.transaction` with no other field changed, record it and
//!   broadcast it. "Always allow" rides in the token: `sign.transaction`
//!   writes Q9's limited rule once it has signed (`token-remember`).

use fc_json::{JsString, JsValue};

use crate::connect::NO_ADDRESS;
use crate::prompt::{Crossed, Decision, Recheck};
use crate::sign::{
    AGENT_CUSTODY, Device, DeviceApproval, RULE_GONE, UNDEFINED, UNLOCK_CHOICES, account_index,
    big_int, element, failure, index_of, prop,
};
use crate::{Answer, Request, World, strictly_equal};

/// The prompt's kind (design 0011).
pub const SEND_KIND: &str = "eth.send";

/// What the prompt offers: "Always allow" and the fee confirmed again, each
/// unticked or ticked, as the reference's `sendChoices` takes them whatever
/// the view offers (*inferred*). "Always allow" on a plain transfer writes
/// nothing, as in the reference.
const CHOICES: &str = r#"{"alwaysAllow":[false,true],"feeAcknowledged":[false,true]}"#;

/// A Safe's: "Always allow" unticked only, as no rule answers a Safe's
/// send (*inferred*).
const SAFE_CHOICES: &str = r#"{"alwaysAllow":[false],"feeAcknowledged":[false,true]}"#;

/// The token a Safe's approve mints.
pub const SAFE_TOKEN_KIND: &str = "safe-send";

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
    /// The account's kind, for a device's.
    device: Option<Device>,
    /// D12's pause, as main sent it.
    paused: Option<bool>,
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
    /// A Safe's approved send (APR-5e-2): its token ([`SafeSend::judged`]).
    Safe(SafeSend),
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
    Ask(Box<Ask>),
    /// The daemon mints the token, and answers `{ send }`.
    Send(Prepared),
    /// A device's (APR-5e-2): the daemon mints the token, and answers
    /// `{ device }`.
    Device(DeviceApproval),
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
        && text.len().is_multiple_of(2)
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

    /// The transaction's form alone (`txOf`): the reference checks it
    /// before anything else, before its first name check (APR-5f-2).
    pub fn form(&self) -> Result<(), Answer> {
        tx_of(self.params.as_ref())
            .map(|_| ())
            .map_err(|message| Answer::error(INVALID_PARAMS, message))
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
            device,
            paused: self.world.paused(),
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

    /// Whether the core quotes the send: every account's but a Safe's,
    /// whose executor pays.
    pub fn quotes(&self) -> bool {
        self.device != Some(Device::Safe)
    }

    /// Whether its fee is checked: a phone picks and pays its own.
    pub fn checks_fee(&self) -> bool {
        self.device != Some(Device::Phone)
    }

    /// `quote`: from the estimate's `result` and the fee quote, each `None`
    /// when its read failed. `None` when either failed or gives nothing to
    /// sign with.
    pub fn quoted(&self, estimate: Option<&JsValue>, quote: Option<&JsValue>) -> Option<Quoted> {
        self.quote(estimate.ok_or(""), quote.ok_or("")).ok()
    }

    /// `quote`, from the estimate's `result` and the fee quote, each the
    /// read's failure message when it failed: the quote, or the message
    /// `quote` throws, as `estimateGas` and `getGasPrices` word it. With
    /// both failed, the estimate's (*inferred*: the reference's is the
    /// first to fail).
    pub fn quote(
        &self,
        estimate: Result<&JsValue, &str>,
        quote: Result<&JsValue, &str>,
    ) -> Result<Quoted, String> {
        // `estimateGas`: `BigInt(result) * 120n / 100n`.
        let estimate = estimate.map_err(|message| format!("Gas estimation failed: {message}"))?;
        let gas = big_int(estimate)
            .ok_or_else(|| format!("Gas estimation failed: {}", big_int_error(estimate)))?;
        let quote = quote.map_err(|message| format!("Failed to get gas prices: {message}"))?;
        if gas.starts_with('-') {
            return Err(String::from("Invalid transaction gas"));
        }
        let gas_limit = div_small(&mul_small(&gas, 6), 5);
        let field = |name: &str| quote.get(name).unwrap_or(&UNDEFINED);
        let fee = |name: &str| {
            quantity_of(field(name)).map_err(|()| String::from("Invalid transaction fee"))
        };
        let eip1559 =
            matches!(quote.get("type"), Some(JsValue::String(kind)) if kind.as_str() == "eip1559");
        let fees = if eip1559 {
            let max_fee = fee("maxFeePerGas")?;
            let priority = fee("maxPriorityFeePerGas")?;
            max_fee
                .zip(priority)
                .map(|(max_fee, priority)| Fees::Eip1559 { max_fee, priority })
        } else {
            fee("gasPrice")?.map(|gas_price| Fees::Legacy { gas_price })
        };
        let fees = fees.ok_or_else(|| String::from("Unable to estimate the network fee"))?;
        let per_gas = fee("effectiveGasPrice")?.unwrap_or_else(|| match &fees {
            Fees::Eip1559 { max_fee, .. } => max_fee.clone(),
            Fees::Legacy { gas_price } => gas_price.clone(),
        });
        let estimate = mul(&gas_limit, &per_gas);
        Ok(Quoted {
            gas_limit,
            fees,
            estimate,
        })
    }

    /// The site's rule's request, when a rule may answer the send (the
    /// reference's `ruleChosen`, before its quote): outside custody
    /// (`agent`, a missing one counting as custody), for a vault account
    /// (*inferred*: the core can't see a device's send, so no rule answers
    /// one), and a contract call. The core judges it with its own grant.
    pub fn rule_query(&self, agent: Option<bool>) -> Option<RuleQuery<'_>> {
        if agent != Some(false) || self.device.is_some() {
            return None;
        }
        selector_of(&self.tx.data)?;
        Some(RuleQuery {
            key: &self.key,
            account: account_index(&self.wallet_index)?,
            to: &self.tx.to,
            data: &self.tx.data,
            value: &self.tx.value,
            chain_id: self.chain_id,
            tx: None,
            paused: self.paused,
        })
    }

    /// The rule answers it: the unlock first while the vault is locked,
    /// then its quote. `None` for a send [`Prepare::rule_query`] gives no
    /// request for.
    pub fn ruled(self) -> Option<Rule> {
        let account = self.rule_query(Some(false)).map(|query| query.account)?;
        Some(Rule {
            prepare: self,
            account,
            quoted: None,
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
    // A Safe's executor pays, at its execution.
    let safe = prepare.device == Some(Device::Safe);
    let fee = if safe {
        JsValue::Object(vec![prop("paidBy", JsValue::string("executor"))])
    } else {
        quoted.map_or(JsValue::Null, Quoted::view)
    };
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
        prop("fee", fee),
        prop("feeCheck", verdict),
        prop("feeAskAgain", JsValue::Bool(again)),
        // "Always allow" is offered for a contract call, never a Safe's.
        prop(
            "alwaysAllow",
            JsValue::Bool(!safe && selector_of(&tx.data).is_some()),
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
        if self.prepare.device == Some(Device::Safe) {
            SAFE_CHOICES
        } else {
            CHOICES
        }
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
                ("alwaysAllow", JsValue::Bool(ticked)) => {
                    if *ticked && self.prepare.device == Some(Device::Safe) {
                        return Err(Crossed);
                    }
                    always_allow = *ticked;
                }
                ("feeAcknowledged", JsValue::Bool(ticked)) => acknowledged = *ticked,
                _ => return Err(Crossed),
            }
        }
        // A Safe's send: its token, once the grant still exposes it.
        if self.prepare.device == Some(Device::Safe) {
            return Ok(Decided::Safe(SafeSend {
                prepare: self.prepare,
                handle,
            }));
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

    /// Whether the fee is judged at the approval: not a phone's.
    pub fn checks_fee(&self) -> bool {
        self.prepare.checks_fee()
    }

    /// The check at approval's verdict (`verdict`, JSON text with
    /// `askAgain`): asked again when `ask_again`; otherwise
    /// [`Judge::confirmed`].
    pub fn judged(
        self,
        verdict: &str,
        ask_again: bool,
        grant: impl FnOnce(&str) -> Option<JsValue>,
    ) -> Judged {
        if ask_again {
            let view = view(&self.prepare, Some(&self.quoted), Some(verdict), true);
            return Judged::Ask(Box::new(Ask {
                prepare: self.prepare,
                quoted: Some(self.quoted),
                view,
            }));
        }
        self.confirmed(grant)
    }

    /// A send whose fee the check at approval let through: the key's grant,
    /// as `grant` gives it now, must still expose the account shown; then
    /// the token is minted. For a name-keyed document the daemon resolves
    /// the name between the two (APR-5f-2), as the reference checks it just
    /// before the grant in its send's guard.
    pub fn confirmed(self, grant: impl FnOnce(&str) -> Option<JsValue>) -> Judged {
        let account = match exposed(&self.prepare, grant) {
            Ok(account) => account,
            Err(answer) => return Judged::Answer(answer),
        };
        // "Always allow" writes the contract rule, never one for a plain
        // transfer.
        let remember = self.always_allow && selector_of(&self.prepare.tx.data).is_some();
        // A Ledger's or a phone's: the token goes back to main, which
        // spends it on the device's send (`approval.spend`, or `phone.job`);
        // "Always allow" rides in it, for the device send's receipt or the
        // phone payment's rule (0012).
        if let Some(device) = self.prepare.device {
            let tx = self.tx();
            return Judged::Device(DeviceApproval::send(
                device,
                account,
                self.handle,
                TOKEN_KIND,
                format!(r#"{{"tx":{tx}}}"#),
                Some(format!(r#"{{"tx":{tx},"remember":{remember}}}"#)),
            ));
        }
        Judged::Send(Prepared {
            account,
            tx: self.tx(),
            handle: self.handle,
            remember,
        })
    }
}

/// The key's grant, as `grant` gives it now, still exposing the account
/// shown: the account's index, or the refusal.
fn exposed(prepare: &Prepare, grant: impl FnOnce(&str) -> Option<JsValue>) -> Result<u32, Answer> {
    let exposes = grant(&prepare.key)
        .filter(JsValue::truthy)
        .is_some_and(|permission| {
            strictly_equal(
                permission.get("walletIndex").unwrap_or(&UNDEFINED),
                &prepare.wallet_index,
            )
        });
    if !exposes {
        return Err(Answer::error(NOT_CONNECTED.0, NOT_CONNECTED.1));
    }
    account_index(&prepare.wallet_index)
        .ok_or_else(|| Answer::error(INTERNAL_ERROR_CODE, INVALID_INDEX))
}

/// A Safe's approved send (APR-5e-2), before its token.
#[derive(Debug, Clone, PartialEq)]
pub struct SafeSend {
    prepare: Prepare,
    handle: String,
}

impl SafeSend {
    /// The key's grant, as `grant` gives it now, must still expose the
    /// Safe; then the daemon mints the site's `safe-send` for the Safe, its
    /// chain and the SafeTx, and main spends it on the SafeTx and its board
    /// (*inferred*: the reference's `safeSend` from its token on).
    pub fn judged(self, grant: impl FnOnce(&str) -> Option<JsValue>) -> Judged {
        let account = match exposed(&self.prepare, grant) {
            Ok(account) => account,
            Err(answer) => return Judged::Answer(answer),
        };
        let tx = &self.prepare.tx;
        let payload = JsValue::Object(vec![
            prop("safe", self.prepare.address.clone()),
            prop(
                "chain_id",
                JsValue::string(self.prepare.chain_id.to_string()),
            ),
            prop(
                "tx",
                JsValue::Object(vec![
                    prop("to", JsValue::string(tx.to.as_str())),
                    prop("value", JsValue::string(tx.value.as_str())),
                    prop("data", JsValue::string(tx.data.as_str())),
                ]),
            ),
        ]);
        Judged::Device(DeviceApproval::send(
            Device::Safe,
            account,
            self.handle,
            SAFE_TOKEN_KIND,
            payload.stringify(),
            None,
        ))
    }
}

/// A send the site's rule may answer, for the core to judge with its own
/// grant (`fc_approval::standing`'s transaction rule), counting nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleQuery<'a> {
    /// `PageContext.origin`.
    pub key: &'a str,
    /// The account the grant exposes.
    pub account: u32,
    /// `to` as the page sent it, `value` in decimal and `data` as hex.
    pub to: &'a str,
    pub value: &'a str,
    pub data: &'a str,
    pub chain_id: u64,
    /// The prepared transaction (`sign.transaction`'s form, no nonce), once
    /// quoted: its fee is judged too. `None` for the choice before the
    /// quote, which leaves the fee to the check.
    pub tx: Option<String>,
    /// D12's pause, as main sent it.
    pub paused: Option<bool>,
}

/// The core's standing rule for a send, counting nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleNow {
    /// The rule answers it.
    Covered,
    /// It would, but for its rate or its fee: the user is asked (Q9 asks
    /// rather than refuses; *inferred* for the fee at the recheck).
    Asked,
    /// No rule answers it.
    NotCovered,
}

/// A send the site's rule answers (APR-5e-2): no prompt but a locked
/// vault's unlock, and only once the fee check lets it.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    prepare: Prepare,
    account: u32,
    quoted: Option<Quoted>,
}

/// What a rule's quote leaves.
#[derive(Debug, Clone, PartialEq)]
pub enum Ruled {
    /// A read failed: the reference's failure, nothing asked.
    Answer(Answer),
    /// The fee check doesn't let it through: the user is asked, with this
    /// quote and verdict.
    Ask(Box<Ask>),
    /// Main's recheck, just before the effect.
    Recheck(Box<Rule>),
}

/// What main's recheck leaves of a rule's send.
#[derive(Debug, Clone, PartialEq)]
pub enum RuleRechecked {
    /// Refused, with nothing to sign.
    Answer(Answer),
    /// Past its rate, or its fee needing the user, by now: asked.
    Ask(Box<Ask>),
    /// The rule answers it: `{ send }` under the rule. For a name-keyed
    /// document the daemon resolves the name first, and asks main's last
    /// recheck after it (APR-5f-2).
    Send(Answer),
}

impl Rule {
    /// What the send is, before its quote.
    pub fn prepare(&self) -> &Prepare {
        &self.prepare
    }

    /// The unlock's kind, asked while the vault is locked.
    pub fn unlock_kind(&self) -> &'static str {
        crate::sign::UNLOCK_KIND
    }

    /// The unlock's view: `{ account, reason: "send" }`.
    pub fn unlock_view(&self) -> String {
        JsValue::Object(vec![
            prop("account", self.prepare.account_view.clone()),
            prop("reason", JsValue::string("send")),
        ])
        .stringify()
    }

    /// The unlock's choices: none.
    pub fn unlock_choices(&self) -> &'static str {
        UNLOCK_CHOICES
    }

    /// Main's decision on the unlock: `None` to go on to the quote; a
    /// refusal otherwise. An approve with any pick is [`Crossed`].
    pub fn unlocked(&self, decision: Decision) -> Result<Option<Answer>, Crossed> {
        crate::sign::unlocked(decision)
    }

    /// The quote (or the message a failed read gives), and `verdict`
    /// giving the fee check's on the prepared transaction (JSON text, the
    /// reference's names): a failure answers it; a fee the check doesn't
    /// auto-approve goes to the prompt; otherwise main's recheck.
    pub fn judged(
        mut self,
        quoted: Result<Quoted, String>,
        verdict: impl FnOnce(&str) -> String,
    ) -> Ruled {
        let quoted = match quoted {
            Ok(quoted) => quoted,
            Err(message) => return Ruled::Answer(failure(&message, "Transaction failed")),
        };
        let verdict = verdict(&quoted.tx(&self.prepare));
        if !auto_approved(&verdict) {
            return Ruled::Ask(Box::new(self.prepare.ask(Some(quoted), Some(&verdict))));
        }
        self.quoted = Some(quoted);
        Ruled::Recheck(Box::new(self))
    }

    /// The prepared transaction, once quoted.
    pub fn tx(&self) -> Option<String> {
        self.quoted.as_ref().map(|quoted| quoted.tx(&self.prepare))
    }

    /// The rule's request with its prepared transaction, for the core to
    /// judge again just before the effect.
    pub fn query(&self) -> Option<RuleQuery<'_>> {
        let mut query = self.prepare.rule_query(Some(false))?;
        query.tx = Some(self.tx()?);
        Some(query)
    }

    /// Just before the effect, after its last wait, in the reference's
    /// order (`ruleStillAnswers`): a tab gone into custody refused
    /// (`agent_custody`); the rule no longer answering (`now`, judged with
    /// the core's own grant and main's fresh custody) refused; the document
    /// gone refused (`4100`). A rule past its rate, or a fee needing the
    /// user, by now, is asked (`verdict`, the fee check's now). Otherwise
    /// `{ send: { kind, account, tx, standing: true } }` (*inferred*): main
    /// takes the site's turn without waiting (D12), adds the nonce, and
    /// signs under `{ standing }`, which the core decides again and counts.
    pub fn rechecked(self, recheck: &Recheck, now: RuleNow, verdict: &str) -> RuleRechecked {
        if recheck.agent {
            return RuleRechecked::Answer(Answer::raw(AGENT_CUSTODY));
        }
        if now == RuleNow::NotCovered {
            return RuleRechecked::Answer(Answer::error(INTERNAL_ERROR_CODE, RULE_GONE));
        }
        if !recheck.live {
            return RuleRechecked::Answer(Answer::error(NO_ADDRESS.0, NO_ADDRESS.1));
        }
        let Some(quoted) = self.quoted else {
            return RuleRechecked::Answer(Answer::error(INTERNAL_ERROR_CODE, RULE_GONE));
        };
        if now == RuleNow::Asked {
            return RuleRechecked::Ask(Box::new(self.prepare.ask(Some(quoted), Some(verdict))));
        }
        let Ok(tx) = fc_json::parse(&quoted.tx(&self.prepare)) else {
            return RuleRechecked::Answer(failure("", "Transaction failed"));
        };
        let send = JsValue::Object(vec![
            prop("kind", JsValue::string(TOKEN_KIND)),
            prop("account", JsValue::Number(f64::from(self.account))),
            prop("tx", tx),
            prop("standing", JsValue::Bool(true)),
        ]);
        RuleRechecked::Send(Answer::raw(
            JsValue::Object(vec![prop("send", send)]).stringify(),
        ))
    }
}

/// The verdict's `autoApprove`, true only when it says so.
fn auto_approved(verdict: &str) -> bool {
    fc_json::parse(verdict)
        .ok()
        .is_some_and(|verdict| matches!(verdict.get("autoApprove"), Some(JsValue::Bool(true))))
}

/// `BigInt(value)`'s error message, as V8 words it, for a value it refuses.
fn big_int_error(value: &JsValue) -> String {
    match value {
        JsValue::Number(_) => format!(
            "The number {} cannot be converted to a BigInt because it is not an integer",
            value.stringify()
        ),
        JsValue::Undefined => String::from("Cannot convert undefined to a BigInt"),
        JsValue::String(text) => format!("Cannot convert {} to a BigInt", text.as_str()),
        JsValue::Object(_) => String::from("Cannot convert [object Object] to a BigInt"),
        _ => format!("Cannot convert {} to a BigInt", value.stringify()),
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
    /// `{ token, kind, handle }`. The token is borrowed from the minter's
    /// wiping buffer and never copied here: the daemon writes the answer
    /// straight into its reply's own ([`SendAnswer::write_into`]), as a
    /// `{ device }` answer's. A token that isn't plain hex (the minter's
    /// are 64 lowercase hex digits) is refused, not quoted.
    pub fn answer<'t>(&self, token: &'t str) -> Result<SendAnswer<'t>, Answer> {
        if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(failure("", "Transaction failed"));
        }
        let Ok(tx) = fc_json::parse(&self.tx) else {
            return Err(failure("", "Transaction failed"));
        };
        let send = JsValue::Object(vec![
            prop("kind", JsValue::string(TOKEN_KIND)),
            prop("account", JsValue::Number(f64::from(self.account))),
            prop("tx", tx),
            prop("handle", JsValue::string(self.handle.as_str())),
        ]);
        // `{"kind":…,"handle":"…"}` with its closing brace replaced by the
        // token's field, up to its opening quote.
        let mut before = String::from(r#"{"send":"#);
        before.push_str(&send.stringify());
        before.pop();
        before.push_str(r#","token":""#);
        Ok(SendAnswer { before, token })
    }

    /// The answer when the token couldn't be minted: `-32603` with the
    /// refusal's message.
    pub fn refused(message: &str) -> Answer {
        failure(message, "Transaction failed")
    }
}

/// A `{ send }` answer: its public text, and the token it carries,
/// borrowed from the minter's wiping buffer (design 0012, "Tokens": never
/// in a plain copy, never in Debug output), as a `{ device }` answer's.
/// Its `Debug` prints no token, and it has no `Clone`.
pub struct SendAnswer<'t> {
    /// The JSON text up to the token's opening quote.
    before: String,
    token: &'t str,
}

impl SendAnswer<'_> {
    /// What follows the token: its closing quote and two braces.
    const AFTER: &'static str = r#""}}"#;

    /// The answer's length in bytes, for a reply sized before it is
    /// written.
    pub fn len(&self) -> usize {
        self.before.len() + self.token.len() + Self::AFTER.len()
    }

    /// Never: the answer always holds its `send`.
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

impl std::fmt::Debug for SendAnswer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendAnswer")
            .field("before", &self.before)
            .field("token", &"<redacted>")
            .finish()
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

    fn device_send(index: u32, kind: &str, data: &str) -> Prepare {
        let text = format!(
            r#"{{"method":"eth_sendTransaction","params":[{{"to":"0x5555555555555555555555555555555555555555","data":"{data}"}}],"world":{{"enabled":true,"window_chain":100,"paused":false,"wallets":[{{"index":{index},"address":"0x4444444444444444444444444444444444444444","type":"{kind}"}}],"networks":{{}}}}}}"#
        );
        let request = Request::parse(&text).unwrap();
        let crate::Step::Send(send) = crate::start(&request, Some("k"), |_| None) else {
            panic!("{kind}")
        };
        let grant = format!(r#"{{"walletIndex":{index}}}"#);
        send.prepare(|_| fc_json::parse(&grant).ok()).unwrap()
    }

    /// A Ledger's, a phone's or a Safe's send (on Gnosis) is asked, and no
    /// rule answers it. A Safe's executor pays: no quote, "Always allow"
    /// neither shown nor pickable, and its approve gives a `safe-send`
    /// binding the Safe, its chain and the SafeTx.
    #[test]
    fn a_device_send_is_asked_and_never_ruled() {
        for (index, kind) in [(1, "ledger"), (2, "remote"), (1000, "safe")] {
            let prepare = device_send(index, kind, "0xa9059cbb00");
            assert_eq!(prepare.rule_query(Some(false)), None, "{kind}");
            assert_eq!(prepare.clone().ruled(), None, "{kind}");
            assert_eq!(prepare.quotes(), kind != "safe", "{kind}");
            assert_eq!(prepare.checks_fee(), kind != "remote", "{kind}");
        }
        let ask = device_send(1000, "safe", "0xa9059cbb00").ask(None, None);
        let view = fc_json::parse(ask.view()).unwrap();
        assert_eq!(
            view.get("fee").unwrap().stringify(),
            r#"{"paidBy":"executor"}"#
        );
        assert_eq!(view.get("alwaysAllow"), Some(&JsValue::Bool(false)));
        assert_eq!(ask.choices(), SAFE_CHOICES);
        let approve = |picks: &str| Decision::Approve {
            choices: fc_json::parse(picks).unwrap(),
            handle: "ab".repeat(32),
            world: World::from_value(
                fc_json::parse(r#"{"enabled":true,"wallets":[],"networks":{}}"#).unwrap(),
            )
            .unwrap(),
        };
        assert_eq!(
            ask.clone().decide(approve(r#"{"alwaysAllow":true}"#)),
            Err(Crossed)
        );
        let Ok(Decided::Safe(safe)) = ask.decide(approve(r#"{"feeAcknowledged":true}"#)) else {
            panic!()
        };
        assert_eq!(
            safe.clone().judged(|_| None),
            Judged::Answer(Answer::error(NOT_CONNECTED.0, NOT_CONNECTED.1))
        );
        let Judged::Device(device) =
            safe.judged(|_| fc_json::parse(r#"{"walletIndex":1000}"#).ok())
        else {
            panic!()
        };
        assert_eq!(device.token_kind(), "safe-send");
        assert_eq!(
            device.binds(),
            r#"{"safe":"0x4444444444444444444444444444444444444444","chain_id":"100","tx":{"to":"0x5555555555555555555555555555555555555555","value":"0","data":"0xa9059cbb00"}}"#
        );
    }

    /// A vault account's contract call outside custody, with D12's pause
    /// read as `false`, is the rule's to judge; in custody, unknown custody,
    /// a pause not `false`, or a plain transfer, it isn't.
    #[test]
    fn a_rule_is_judged_only_for_what_it_may_answer() {
        let vault = |paused: &str, data: &str| {
            let text = format!(
                r#"{{"method":"eth_sendTransaction","params":[{{"to":"0x5555555555555555555555555555555555555555","data":"{data}"}}],"world":{{"enabled":true,"window_chain":1,{paused}"wallets":[{{"index":0,"address":"0x4444444444444444444444444444444444444444"}}],"networks":{{}}}}}}"#
            );
            let request = Request::parse(&text).unwrap();
            let crate::Step::Send(send) = crate::start(&request, Some("k"), |_| None) else {
                panic!()
            };
            send.prepare(|_| fc_json::parse(r#"{"walletIndex":0}"#).ok())
                .unwrap()
        };
        let query = vault(r#""paused":false,"#, "0xa9059cbb00");
        let asked = query.rule_query(Some(false)).unwrap();
        assert_eq!(
            (asked.account, asked.chain_id, asked.paused),
            (0, 1, Some(false))
        );
        assert_eq!(
            (asked.data, asked.value, asked.tx),
            ("0xa9059cbb00", "0", None)
        );
        assert!(query.rule_query(Some(true)).is_none());
        assert!(query.rule_query(None).is_none());
        assert!(
            vault(r#""paused":false,"#, "0x")
                .rule_query(Some(false))
                .is_none()
        );
        assert_eq!(
            vault("", "0xa9059cbb00")
                .rule_query(Some(false))
                .unwrap()
                .paused,
            None
        );
    }

    /// A `{ send }` answer's token goes only into the reply's buffer: no
    /// Debug output shows it, the answer's, the prepared send's or the
    /// verdict's. A token that isn't plain hex is refused, never quoted.
    #[test]
    fn a_send_token_is_in_no_debug_output() {
        const MARKER: &str = "feedfacecafebeef0123456789abcdef";
        let prepared = Prepared {
            account: 0,
            handle: "ab".repeat(32),
            tx: r#"{"type":2,"chain_id":"100","to":"0x5555555555555555555555555555555555555555","value":"0","data":"0x","gas_limit":"25200","max_fee_per_gas":"30000000000","max_priority_fee_per_gas":"2000000000"}"#.to_owned(),
            remember: false,
        };
        let answer = prepared.answer(MARKER).unwrap();
        let judged = Judged::Send(prepared.clone());
        for debug in [
            format!("{answer:?}"),
            format!("{answer:#?}"),
            format!("{prepared:?}"),
            format!("{judged:?}"),
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
                r#"{{"send":{{"kind":"dapp-send","account":0,"tx":{},"handle":"{}","token":"{MARKER}"}}}}"#,
                prepared.tx,
                "ab".repeat(32),
            )
        );
        for bad in ["", "ab\"cd", "ab\\cd", "0xab", "ab cd"] {
            assert_eq!(
                prepared.answer(bad).unwrap_err(),
                failure("", "Transaction failed"),
                "{bad}"
            );
        }
        assert_eq!(
            Prepared::refused("Vault is locked"),
            failure("Vault is locked", "Transaction failed")
        );
    }

    #[test]
    fn selectors_are_four_bytes() {
        assert_eq!(selector_of("0xA9059CBB00"), Some("0xa9059cbb".into()));
        assert_eq!(selector_of("0x"), None);
        assert_eq!(selector_of("0xa9059c"), None);
    }
}
