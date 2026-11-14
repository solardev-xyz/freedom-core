//! Design 0012's approvals in the daemon (APR-3a): approval tokens and Safe
//! approvals over the wire, and the authorization `sign.*` checks when one
//! is present. The decisions are `fc-approval`'s; this module wires them to
//! the callers, the vault's clock, the wall clock, the OS's RNG and the fee
//! evidence the core served.
//!
//! - `approval.issue { kind, account, payload, handle?, fee_ack?, phone? }`
//!   mints a token: a page kind only under `page`, with its `PageContext`
//!   and 0011's handle; a wallet kind only under `shell`. `chrome` mints
//!   none (APS-3, APS-5). A send is judged by the fee check first
//!   (`wallet-send`, `dapp-send`, `intent-replace`, `executor-send`), but a
//!   phone account's (`phone: true` on a `wallet-send` or `dapp-send`),
//!   which picks its own fees.
//! - `approval.discard { token }` burns one: a presented token is burnt
//!   whatever the outcome, a malformed request's included.
//! - `approval.spend { token, kind, account, payload, handle? }` spends one
//!   under the caller kind that minted it; a `safe-send`'s or
//!   `safe-message`'s gives a Safe approval. `{ standing, … }` (a Safe
//!   message a rule answers) reads the dApp grants, which APR-3b brings:
//!   until then no rule answers it.
//! - `approval.end { safe }` ends a Safe approval, and answers `{}` whatever
//!   it was. Every method here runs inline on the event loop, as `sign.*`
//!   does, so a signature that presented the approval has finished before
//!   the end is read.
//! - `sign.*`'s `authorization`: `{ token, handle? }`, `{ safe }`, or `{
//!   standing }`, checked after the request's public work and before any
//!   key is derived. `sign.transaction`'s token names the kind it expects,
//!   `{ token, kind, handle? }` (`wallet-send`, `executor-send` or
//!   `dapp-send`), or an `intent-replace`'s intent, `{ token, intent: { id }
//!   }`: a token of another kind, or one naming neither, is a `mismatch`,
//!   and burnt. Without an authorization, `sign.*` signs as before (APR-3;
//!   APR-4 requires it).
//! - `swarm.sign_soc`'s `authorization` (APR-3c): `{ swarm, soc }` from a
//!   page, checked against the page's Swarm grant at the same point. Main's
//!   own SOCs, under `shell`, take none.
//!
//! - The grant stores (APR-3b; [`crate::grants`] holds the files):
//!   `approval.check { request, chain_id?, paused? }` asks a site's
//!   standing rule for advice; `{ standing }` on `sign.*`, and on
//!   `approval.spend` for a Safe message, decides with it
//!   (`fc_approval::standing`). Today's rules answer until `dapp` is in
//!   `grant_moved`, Q9's limited ones from then. `approval.grants` reads a
//!   store; `approval.grant`, `approval.revoke`, `approval.touch` and
//!   `approval.forget_account` write one, and answer `not_moved` until its
//!   file has moved. Each change sends one `approval.changed { store, key
//!   }`.
//!
//! Tokens and Safe approvals are kept in memory and never logged.

use std::collections::VecDeque;
use std::sync::OnceLock;

use fc_approval::fee::{Evidence, Fees, Verdict, at_approval};
use fc_approval::safe::{
    Approved, ExecutorCheck, Holder, OwnerCheck, SafeApprovals, SafeRefusal, SafeSigned,
};
use fc_approval::standing::{
    AccountKind, DappAsk, DappRequest, Decision, Rules, Send, Signed as RuleSigned, SocApproval,
    SocAsk, SocRequest, Standing, page_soc,
};
use fc_approval::stores::{
    Applied, CapStore, DappStore, Effect, JsValue, RadicleFlag, RadicleStore, StoreKind, SwarmFlag,
    SwarmStore,
};
use fc_approval::{Handle, Kind, Limits, Minter, Page, Presented, Refusal, Request, Tokens};
use fc_evm::{Transaction, TypedDataView, U256};
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::message::{self, CallerKind, Context, PageContext};
use serde::Serialize;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::grants::{Grants, StoreFile, WriteFailure, Written};
use crate::rng::OsRng;

/// The methods this module serves.
pub const METHODS: [&str; 10] = [
    "approval.issue",
    "approval.discard",
    "approval.spend",
    "approval.end",
    "approval.check",
    "approval.grant",
    "approval.revoke",
    "approval.touch",
    "approval.grants",
    "approval.forget_account",
];

/// How many chains' fee evidence is kept (the reference's `MAX_CHAINS`).
const MAX_FEE_CHAINS: usize = 32;

/// How many `chain.fee_reference` requests are remembered until their
/// reply: more than main has outstanding at once.
const MAX_FEE_ASKED: usize = 64;

/// The two clocks a check reads.
#[derive(Debug, Clone, Copy)]
pub struct Clocks {
    /// The vault's clock (`clock.rs`): token lives, the evidence's age.
    pub vault_ms: u64,
    /// Wall-clock milliseconds: the evidence's header.
    pub wall_ms: u64,
}

/// The approvals the core holds.
pub struct Approvals {
    tokens: Tokens,
    safes: SafeApprovals,
    fees: FeeEvidence,
    /// The four permission files.
    grants: Grants,
    /// Q9's and R-6's buckets, in memory.
    standing: Standing,
    /// `approval.changed` events to send after the reply that made them.
    events: Vec<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for Approvals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Approvals")
            .field("tokens", &self.tokens)
            .field("safes", &self.safes)
            .finish_non_exhaustive()
    }
}

/// The newest `chain.fee_reference` reply the core served for each chain,
/// read as the fee check's evidence, with the vault-clock time it was asked
/// for (design 0012, "The fee check").
///
/// Which is newest is the order the requests were asked in, by a sequence
/// this core counts, never their vault-clock times: two asked in the same
/// millisecond are still ordered. The time is only the evidence's age.
#[derive(Default)]
struct FeeEvidence {
    /// The next ask's sequence.
    next: u64,
    /// Requests not yet answered, oldest first.
    asked: VecDeque<Asked>,
    /// Chain → the evidence and its ask's sequence, oldest first.
    chains: VecDeque<(u64, u64, Evidence)>,
}

/// A `chain.fee_reference` request not yet answered.
struct Asked {
    /// Main's request ID.
    id: u64,
    chain_id: u64,
    /// When it was asked, on the vault's clock.
    vault_ms: u64,
    /// Its place in the order of asks.
    sequence: u64,
}

impl FeeEvidence {
    fn asked(&mut self, id: u64, chain_id: u64, vault_ms: u64) {
        self.asked.retain(|asked| asked.id != id);
        while self.asked.len() >= MAX_FEE_ASKED {
            self.asked.pop_front();
        }
        let sequence = self.next;
        self.next = self.next.saturating_add(1);
        self.asked.push_back(Asked {
            id,
            chain_id,
            vault_ms,
            sequence,
        });
    }

    fn answered(&mut self, id: u64, result: &Value) {
        let Some(index) = self.asked.iter().position(|asked| asked.id == id) else {
            return;
        };
        let Some(asked) = self.asked.remove(index) else {
            return;
        };
        // A request asked before the evidence's, answered late, doesn't
        // replace it.
        if let Some(index) = self
            .chains
            .iter()
            .position(|(chain, _, _)| *chain == asked.chain_id)
        {
            if self.chains[index].1 > asked.sequence {
                return;
            }
            self.chains.remove(index);
        }
        while self.chains.len() >= MAX_FEE_CHAINS {
            self.chains.pop_front();
        }
        self.chains.push_back((
            asked.chain_id,
            asked.sequence,
            Evidence::read(result, asked.vault_ms),
        ));
    }

    fn get(&self, chain_id: u64) -> Option<&Evidence> {
        self.chains
            .iter()
            .find(|(chain, _, _)| *chain == chain_id)
            .map(|(_, _, evidence)| evidence)
    }
}

fn invalid(message: impl Into<String>) -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, message.into())
}

fn forbidden(message: &str) -> ErrorBody {
    ErrorBody::new(ErrorCode::Forbidden, message)
}

/// `not_authorized`, with `data.reason` (design 0012, API).
fn not_authorized(reason: &str, message: impl Into<String>) -> ErrorBody {
    ErrorBody::new(ErrorCode::NotAuthorized, message.into()).with_data(json!({ "reason": reason }))
}

fn refusal(refusal: Refusal) -> ErrorBody {
    let reason = match &refusal {
        Refusal::NoToken => "no_token",
        Refusal::UnknownToken => "unknown_token",
        Refusal::Expired => "expired",
        // A request that doesn't parse for the token's kind can't be the
        // one confirmed.
        Refusal::Mismatch | Refusal::Invalid(_) => "mismatch",
    };
    not_authorized(reason, refusal.to_string())
}

fn safe_refusal(refusal: SafeRefusal) -> ErrorBody {
    let reason = match refusal {
        SafeRefusal::Unknown => "unknown_token",
        SafeRefusal::Mismatch => "mismatch",
        SafeRefusal::FeeCheck => "fee_check",
    };
    not_authorized(reason, refusal.to_string())
}

fn approval_error(error: fc_approval::Error) -> ErrorBody {
    match error {
        fc_approval::Error::Randomness => crate::vault::internal(),
        other => invalid(other.to_string()),
    }
}

/// The params object, with exactly the given members.
fn object<'a>(
    params: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>, ErrorBody> {
    let object = params
        .as_object()
        .ok_or_else(|| invalid("Invalid parameters"))?;
    if let Some(unknown) = object
        .keys()
        .find(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(invalid(format!(
            "unknown field {}",
            fc_evm::shortened(unknown)
        )));
    }
    if let Some(missing) = required.iter().find(|key| !object.contains_key(**key)) {
        return Err(invalid(format!("missing field {missing}")));
    }
    Ok(object)
}

fn string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, ErrorBody> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{field}: expected a string")))
}

/// The `PageContext` a `page` caller must send (0011): every page request
/// here needs it.
pub fn page_context(context: &Context) -> Result<Option<&PageContext>, ErrorBody> {
    match (context.caller, &context.page) {
        (CallerKind::Page, Some(page)) => Ok(Some(page)),
        (CallerKind::Page, None) => Err(invalid("a page request needs its page context")),
        _ => Ok(None),
    }
}

fn minter(caller: CallerKind) -> Minter {
    match caller {
        CallerKind::Page => Minter::Page,
        CallerKind::Chrome => Minter::Chrome,
        CallerKind::Shell => Minter::Shell,
    }
}

/// Who presents a Safe approval: a page with its document, main itself, or
/// `chrome`, which presents none (design 0012: a page's under `page`, a
/// wallet's under `shell`).
fn presenter(context: &Context) -> Result<Option<Holder>, ErrorBody> {
    Ok(match (context.caller, page_context(context)?) {
        (CallerKind::Page, Some(page)) => Some(Holder::Page {
            origin: page.origin.clone(),
            frame: page.frame,
            navigation: page.navigation,
        }),
        (CallerKind::Shell, _) => Some(Holder::Wallet),
        _ => None,
    })
}

/// The page a page caller's token binds: its `PageContext` and the
/// handle. A handle under another caller, or none under `page`, is `Err`.
fn token_page(context: &Context, handle: Option<&Value>) -> Result<Option<Page>, HandleError> {
    match (page_context(context).map_err(HandleError::Body)?, handle) {
        (Some(page), Some(Value::String(handle))) => Ok(Some(Page {
            origin: page.origin.clone(),
            frame: page.frame,
            navigation: page.navigation,
            handle: Handle::parse(handle).map_err(|_| HandleError::Handle)?,
        })),
        (Some(_), _) => Err(HandleError::Handle),
        (None, None) => Ok(None),
        (None, Some(_)) => Err(HandleError::Handle),
    }
}

enum HandleError {
    Body(ErrorBody),
    /// A page caller without a valid handle, or another caller with one.
    Handle,
}

/// The longest typed-data view a token binds: what `sign.typed_data` would
/// reply with, and what `approval.issue`'s own reply carries in one frame
/// at the largest request ID, whichever is shorter. A view past it gets no
/// token (fc-approval refuses it as `view-size`), so no reply here is ever
/// too large to frame.
fn limits() -> Limits {
    Limits {
        max_view_len: crate::signing::max_view_len().min(max_issued_view_len()),
    }
}

/// The longest view `approval.issue`'s reply holds in one frame, at the
/// largest ID, with a typed-data token's hash and its full life.
fn max_issued_view_len() -> usize {
    static LIMIT: OnceLock<usize> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        let Ok(view) = serde_json::value::RawValue::from_string("0".to_owned()) else {
            return 0;
        };
        let token = "0".repeat(64);
        let reply = IssuedReply {
            expires_in_ms: fc_approval::TOKEN_TTL_MS,
            hash: Some(fc_evm::to_hex(&[0; 32])),
            view: Some(&view),
            fee_check: None,
            token: &token,
        };
        let mut out = Vec::new();
        if message::write_result(&mut out, message::MAX_ID, &reply).is_err() {
            return 0;
        }
        // Everything but the view has a fixed length.
        fc_protocol::frame::MAX_PAYLOAD.saturating_sub(out.len().saturating_sub(1))
    })
}

/// The verdict as the screen reads it.
fn verdict_json(verdict: &Verdict) -> Value {
    json!({
        "max_cost": verdict.max_cost,
        "comparable": verdict.comparable,
        "ratio": verdict.ratio,
        "above": verdict.above,
        "one_endpoint": verdict.one_endpoint,
        "basis": verdict.basis.map(|basis| basis.name()),
        "auto_approve": verdict.auto_approve,
    })
}

/// A send's transaction as the token binds it: its nonce, when absent, as
/// any (`fc-approval`'s bind reads it the same way).
fn send_tx(payload: &Value) -> Option<Transaction> {
    let tx = payload.get("tx")?.as_object()?;
    if tx.contains_key("nonce") {
        return Transaction::from_json(&Value::Object(tx.clone())).ok();
    }
    let mut with_nonce = tx.clone();
    with_nonce.insert("nonce".into(), Value::String("0".into()));
    Transaction::from_json(&Value::Object(with_nonce)).ok()
}

/// `approval.issue`'s result. The token goes last, into a buffer sized for
/// the whole reply, so that it is never left behind in a grown buffer's
/// old allocation.
#[derive(Serialize)]
struct IssuedReply<'a> {
    expires_in_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    view: Option<&'a serde_json::value::RawValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee_check: Option<Value>,
    token: &'a str,
}

/// `approval.spend`'s result; a Safe approval's id goes last, as a token
/// does.
#[derive(Serialize)]
struct SpentReply<'a> {
    bound: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    safe: Option<&'a str>,
}

fn secret_reply<R: Serialize>(
    id: u64,
    result: &R,
    size: usize,
) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
    let mut payload = Zeroizing::new(Vec::with_capacity(size.saturating_add(1024)));
    message::write_result(&mut *payload, id, result).map_err(|_| crate::vault::internal())?;
    Ok(payload)
}

fn json_reply<R: Serialize>(id: u64, result: &R) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
    secret_reply(id, result, 0)
}

/// The token a request presents, kept to be burnt however the request
/// ends: a token is burnt at its first presentation, whatever the outcome
/// (design 0012, "Tokens"), a malformed request's included.
pub fn presented_token(params: &Value, nested: bool) -> Option<Zeroizing<String>> {
    let holder = if nested {
        params.get("authorization")?
    } else {
        params
    };
    holder
        .get("token")
        .and_then(Value::as_str)
        .map(|token| Zeroizing::new(token.to_owned()))
}

/// What `sign.*` signs, for its authorization: its public work done.
pub enum Signed<'a> {
    Transaction {
        account: u32,
        /// `sign.transaction`'s `tx`, as sent.
        tx_json: &'a Value,
        tx: &'a Transaction,
    },
    Message {
        account: u32,
        /// `sign.message`'s `message`, as sent.
        message: &'a Value,
    },
    TypedData {
        account: u32,
        /// `sign.typed_data`'s params.
        fields: &'a Map<String, Value>,
        /// Its EIP-712 hash, equal to `expected_hash`.
        hash: &'a [u8; 32],
        /// The core's view of it, which a standing rule reads for warnings.
        view: &'a TypedDataView,
    },
}

/// What a checked authorization does once its signature is made.
#[derive(Debug)]
pub enum After {
    Nothing,
    /// The first owner's signature fixes the Safe approval's SafeTx or
    /// SafeMessage.
    Owner(OwnerCheck),
    /// The executor's signature ends the Safe approval.
    Executor(ExecutorCheck),
    /// A `dapp-send` with "Always allow" ticked: once signed, the rule for
    /// the call is written for the token's page, if the dApp file has
    /// moved and that page's grant exposes the account (`token-remember`).
    Remember(Remember),
}

/// What a flagged `dapp-send` asks to remember.
#[derive(Debug)]
pub struct Remember {
    key: String,
    account: u32,
    to: Option<[u8; 20]>,
    selector: Option<[u8; 4]>,
    chain_id: Option<u64>,
    value: U256,
}

impl Approvals {
    pub fn new() -> Self {
        Approvals {
            tokens: Tokens::new(limits()),
            safes: SafeApprovals::new(),
            fees: FeeEvidence::default(),
            grants: Grants::new(),
            standing: Standing::new(),
            events: Vec::new(),
        }
    }

    /// Whether this module serves `method`.
    pub fn handles(method: &str) -> bool {
        METHODS.contains(&method)
    }

    /// Main asked for `chain.fee_reference` (`params` as sent): its reply
    /// becomes the chain's evidence, asked for now on the vault's clock.
    pub fn fee_asked(&mut self, id: u64, params: Option<&str>, vault_ms: u64) {
        let chain_id = params
            .and_then(|params| serde_json::from_str::<Value>(params).ok())
            .and_then(|params| params.get("chain_id").and_then(Value::as_u64));
        if let Some(chain_id) = chain_id {
            self.fees.asked(id, chain_id, vault_ms);
        }
    }

    /// The core served `chain.fee_reference`'s reply to `id` (its whole
    /// response payload). An error reply carries no evidence.
    pub fn fee_answered(&mut self, id: u64, payload: &[u8]) {
        let Ok(response) = serde_json::from_slice::<Value>(payload) else {
            return;
        };
        if let Some(result) = response.get("result") {
            self.fees.answered(id, result);
        }
    }

    /// Handles one of [`METHODS`], `params` parsed as `sign.*` parses
    /// them (`JSON.parse`'s numbers, #87), and returns its reply.
    pub fn request(
        &mut self,
        id: u64,
        method: &str,
        params: &Value,
        context: &Context,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        match method {
            "approval.issue" => self.issue(id, params, context, clocks),
            "approval.discard" => {
                // Burnt at its presentation, whatever the outcome: a
                // malformed request's, or one refused for its context.
                let presented = presented_token(params, false);
                let reply = page_context(context)
                    .and_then(|_| object(params, &["token"], &[]))
                    .and_then(|fields| string(fields, "token"))
                    .and_then(|_| json_reply(id, &json!({})));
                if let Some(token) = presented {
                    self.tokens.discard(&token);
                }
                reply
            }
            "approval.spend" => {
                let presented = presented_token(params, false);
                let reply = self.spend(id, params, context, clocks);
                if let Some(token) = presented {
                    self.tokens.discard(&token);
                }
                reply
            }
            "approval.end" => {
                page_context(context)?;
                let fields = object(params, &["safe"], &[])?;
                self.safes.end(string(fields, "safe")?);
                json_reply(id, &json!({}))
            }
            "approval.check" => self.check(id, params, context, clocks),
            "approval.grant" => self.grant(id, params, context, clocks),
            "approval.revoke" => self.revoke(id, params, context),
            "approval.touch" => self.touch(id, params, context, clocks),
            "approval.grants" => self.records(id, params, clocks),
            "approval.forget_account" => self.forget_account(id, params),
            _ => Err(invalid("unknown method")),
        }
    }

    fn issue(
        &mut self,
        id: u64,
        params: &Value,
        context: &Context,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let fields = object(
            params,
            &["kind", "payload"],
            &["account", "handle", "fee_ack", "phone"],
        )?;
        let kind = Kind::from_name(string(fields, "kind")?)
            .ok_or_else(|| invalid("unknown confirmation kind"))?;
        // Design 0012, "Tokens": page kinds only under `page`, wallet kinds
        // only under `shell`.
        if !minter(context.caller).mints(kind) {
            return Err(forbidden("this caller can't confirm this kind"));
        }
        let page = match token_page(context, fields.get("handle")) {
            Ok(page) => page,
            Err(HandleError::Body(body)) => return Err(body),
            Err(HandleError::Handle) if context.caller == CallerKind::Page => {
                return Err(invalid("A page confirmation needs its handle"));
            }
            Err(HandleError::Handle) => return Err(invalid("handle: only a page's")),
        };
        let fee_ack = match fields.get("fee_ack") {
            None => false,
            Some(Value::Bool(ack)) => *ack,
            Some(_) => return Err(invalid("fee_ack: expected a boolean")),
        };
        // A phone account's send: main knows the account's kind (it owns
        // `vault-meta.json` until PRF-6a).
        // The field is a send's only: present on another kind, whatever its
        // value, it is refused.
        let phone = match fields.get("phone") {
            None => false,
            Some(_) if !matches!(kind, Kind::WalletSend | Kind::DappSend) => {
                return Err(invalid("phone: only a wallet-send's or a dapp-send's"));
            }
            Some(Value::Bool(phone)) => *phone,
            Some(_) => return Err(invalid("phone: expected a boolean")),
        };
        let payload = &fields["payload"];
        // The fee check at minting (design 0012, "The fee check"), as
        // `wallet:confirm-signing` runs it: never for a phone account,
        // which picks its own fees. A request that doesn't parse is refused
        // by the binding below.
        let mut fee_check = None;
        if !phone
            && matches!(
                kind,
                Kind::WalletSend | Kind::DappSend | Kind::IntentReplace | Kind::ExecutorSend
            )
            && let Some(tx) = send_tx(payload)
        {
            let evidence = tx
                .chain_id()
                .to_u64()
                .and_then(|chain_id| self.fees.get(chain_id));
            let (verdict, ask_again) = at_approval(
                &Fees::of(&tx),
                evidence,
                clocks.wall_ms,
                clocks.vault_ms,
                fee_ack,
            );
            if ask_again {
                return Err(ErrorBody::new(
                    ErrorCode::NotAuthorized,
                    "The fee is above the check's threshold: confirm it again",
                )
                .with_data(json!({ "reason": "fee_check", "fee_check": verdict_json(&verdict) })));
            }
            fee_check = Some(verdict_json(&verdict));
        }
        let request = Request {
            kind,
            account: fields.get("account"),
            payload,
            page: page.as_ref(),
        };
        let issued = self
            .tokens
            .issue_as(
                minter(context.caller),
                &request,
                clocks.vault_ms,
                &mut OsRng,
            )
            .map_err(approval_error)?;
        let token = issued.token.to_text();
        let view = match &issued.typed_data {
            Some(typed) => Some(
                serde_json::value::RawValue::from_string(typed.view.clone())
                    .map_err(|_| crate::vault::internal())?,
            ),
            None => None,
        };
        let size = view.as_ref().map_or(0, |view| view.get().len());
        let reply = secret_reply(
            id,
            &IssuedReply {
                expires_in_ms: issued.expires_at_ms.saturating_sub(clocks.vault_ms),
                hash: issued
                    .typed_data
                    .as_ref()
                    .map(|typed| fc_evm::to_hex(&typed.hash)),
                view: view.as_deref(),
                fee_check,
                token: &token,
            },
            size,
        );
        // Never a reply too large to frame (the limit above keeps every
        // view under it): its token isn't left outstanding.
        match reply {
            Ok(payload) if payload.len() <= fc_protocol::frame::MAX_PAYLOAD => Ok(payload),
            _ => {
                self.tokens.discard(&token);
                Err(crate::vault::internal())
            }
        }
    }

    fn spend(
        &mut self,
        id: u64,
        params: &Value,
        context: &Context,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        if params.get("standing").is_some() {
            return self.spend_standing(id, params, context, clocks);
        }
        let fields = object(
            params,
            &["token", "kind", "payload"],
            &["account", "handle"],
        )?;
        let token = string(fields, "token")?;
        let kind = Kind::from_name(string(fields, "kind")?)
            .ok_or_else(|| invalid("unknown confirmation kind"))?;
        // An x402 payment is spent by the payment's own signature
        // (X402-1), never here.
        if kind == Kind::X402Payment {
            return Err(refusal(Refusal::Mismatch));
        }
        let page = match token_page(context, fields.get("handle")) {
            Ok(page) => page,
            Err(HandleError::Body(body)) => return Err(body),
            Err(HandleError::Handle) => return Err(refusal(Refusal::Mismatch)),
        };
        let payload = &fields["payload"];
        let request = Request {
            kind,
            account: fields.get("account"),
            payload,
            page: page.as_ref(),
        };
        self.tokens
            .spend_as(minter(context.caller), token, &request, clocks.vault_ms)
            .map_err(refusal)?;
        let approved = match kind {
            Kind::SafeSend => Some(Approved::send(payload).map_err(approval_error)?),
            Kind::SafeMessage => Some(Approved::message(payload).map_err(approval_error)?),
            _ => None,
        };
        let Some(approved) = approved else {
            return json_reply(
                id,
                &SpentReply {
                    bound: true,
                    safe: None,
                },
            );
        };
        let holder = match page {
            Some(page) => Holder::Page {
                origin: page.origin,
                frame: page.frame,
                navigation: page.navigation,
            },
            None => Holder::Wallet,
        };
        let safe = self
            .safes
            .record(holder, approved, &mut OsRng)
            .map_err(approval_error)?
            .to_text();
        secret_reply(
            id,
            &SpentReply {
                bound: true,
                safe: Some(&safe),
            },
            0,
        )
    }

    /// Checks `sign.*`'s `authorization` for what it signs, before any key
    /// is derived (design 0012, API). The token it presents is burnt
    /// whatever the outcome; [`Approvals::burn`] burns one a request
    /// presented and never got this far with.
    pub fn authorize(
        &mut self,
        context: &Context,
        authorization: &Value,
        signed: Signed<'_>,
        clocks: Clocks,
    ) -> Result<After, ErrorBody> {
        let form = authorization
            .as_object()
            .ok_or_else(|| invalid("authorization: expected an object"))?;
        if form.contains_key("token") {
            // Only `sign.transaction` names a kind: its token may be any of
            // four, while each other method spends one kind alone.
            let optional: &[&str] = match signed {
                Signed::Transaction { .. } => &["handle", "intent", "kind"],
                _ => &["handle", "intent"],
            };
            let fields = object(authorization, &["token"], optional)?;
            self.authorize_token(context, fields, signed, clocks)
        } else if form.contains_key("safe") {
            let fields = object(authorization, &["safe"], &[])?;
            let id = string(fields, "safe")?;
            let presenter = presenter(context)?;
            match signed {
                Signed::TypedData { fields, hash, .. } => self
                    .safes
                    .check_owner(id, presenter.as_ref(), &fields["typed_data"], hash)
                    .map(After::Owner)
                    .map_err(safe_refusal),
                Signed::Transaction { tx, .. } => {
                    let evidence = tx
                        .chain_id()
                        .to_u64()
                        .and_then(|chain_id| self.fees.get(chain_id));
                    self.safes
                        .check_executor(
                            id,
                            presenter.as_ref(),
                            tx,
                            evidence,
                            clocks.wall_ms,
                            clocks.vault_ms,
                        )
                        .map(After::Executor)
                        .map_err(safe_refusal)
                }
                // A Safe's owners sign typed data, never a message.
                Signed::Message { .. } => Err(safe_refusal(SafeRefusal::Mismatch)),
            }
        } else if form.contains_key("standing") {
            let fields = object(authorization, &["standing"], &[])?;
            let standing = object(&fields["standing"], &[], &["paused"])?;
            let paused = optional_bool(standing, "paused")?;
            let Some(page) = page_context(context)? else {
                return Err(forbidden("a standing rule answers only a page"));
            };
            let bytes;
            let (account, request) = match signed {
                Signed::Message { account, message } => {
                    bytes = fc_evm::parse_bytes(message.as_str().unwrap_or(""), "message")
                        .map_err(|e| invalid(e.to_string()))?;
                    (account, DappRequest::Signature(RuleSigned::Message(&bytes)))
                }
                Signed::TypedData { account, view, .. } => {
                    (account, DappRequest::Signature(RuleSigned::TypedData(view)))
                }
                Signed::Transaction { account, tx, .. } => {
                    let evidence = tx
                        .chain_id()
                        .to_u64()
                        .and_then(|chain_id| self.fees.get(chain_id));
                    // The core signs with the vault's own key.
                    let send = Send::of(tx, AccountKind::Vault, paused, evidence);
                    (account, DappRequest::Transaction(send))
                }
            };
            let ask = DappAsk {
                key: &page.origin,
                agent: page.agent,
                account,
                request,
            };
            let rules = self.rules();
            let store = self.grants.view::<DappStore>(clocks.wall_ms / 1000);
            match self
                .standing
                .authorize_dapp_under(rules, &store, &ask, rule_clocks(clocks))
            {
                Decision::Covered => Ok(After::Nothing),
                Decision::NotCovered(reason) => Err(not_authorized(
                    reason.name(),
                    "no standing rule covers this request",
                )),
            }
        } else {
            Err(invalid(
                "authorization: expected a token, a Safe approval or a standing rule",
            ))
        }
    }

    fn authorize_token(
        &mut self,
        context: &Context,
        fields: &Map<String, Value>,
        signed: Signed<'_>,
        clocks: Clocks,
    ) -> Result<After, ErrorBody> {
        let token = string(fields, "token")?;
        let handle = fields.get("handle");
        let intent = match fields.get("intent") {
            None => None,
            Some(intent) => Some(intent_id(intent)?),
        };
        let named = match fields.get("kind") {
            None => None,
            Some(kind) => Some(named_kind(kind)?),
        };
        let presented = match (named, intent) {
            (Some(_), Some(_)) => {
                return Err(invalid(
                    "authorization: a token names its kind or its intent, not both",
                ));
            }
            (Some(kind), None) => Presented::Kind(kind),
            (None, Some(_)) => Presented::Intent,
            (None, None) => Presented::Unnamed,
        };
        // An intent names only an `intent-replace`, which `sign.transaction`
        // spends.
        if intent.is_some() && !matches!(signed, Signed::Transaction { .. }) {
            return Err(refusal(Refusal::Mismatch));
        }
        let page = match token_page(context, handle) {
            Ok(page) => page,
            Err(HandleError::Body(body)) => return Err(body),
            Err(HandleError::Handle) => return Err(refusal(Refusal::Mismatch)),
        };
        let page = page.as_ref();
        let under_page = page.is_some();
        let minter = minter(context.caller);
        match signed {
            Signed::Transaction {
                account,
                tx_json,
                tx,
            } => {
                let account_value = json!(account);
                let payload = json!({ "tx": tx_json });
                // An `intent-replace` binds the account that signs it again,
                // the intent's id, and the transaction at the intent's
                // nonce, with the payment it keeps and its new fees (design
                // 0012, Tokens, as amended by APR-3b). Its sender is main's
                // word at minting, read from the token: no key is derived to
                // compare it.
                let replace = intent.map(|id| {
                    json!({
                        "intent_id": id,
                        "sender": self.tokens.intent_sender(token).unwrap_or(""),
                        "tx": tx_json,
                    })
                });
                // A page's send is a `dapp-send`; the wallet's own is a
                // `wallet-send` or an `executor-send`, each named as the
                // kind it was minted as, or an `intent-replace` with its
                // intent named. Any other is a `mismatch`, the token burnt.
                let spent = self
                    .tokens
                    .spend_with(minter, token, clocks.vault_ms, |kind| {
                        if !presented.spends_transaction(kind, under_page) {
                            return None;
                        }
                        Some(match (&replace, kind) {
                            (Some(replace), Kind::IntentReplace) => Request {
                                kind,
                                account: Some(&account_value),
                                payload: replace,
                                page,
                            },
                            _ => Request {
                                kind,
                                account: Some(&account_value),
                                payload: &payload,
                                page,
                            },
                        })
                    })
                    .map_err(refusal)?;
                match page {
                    Some(page) if spent.kind == Kind::DappSend && spent.remember => {
                        Ok(After::Remember(Remember {
                            key: page.origin.clone(),
                            account,
                            to: tx.to().copied(),
                            selector: tx.data().first_chunk::<4>().copied(),
                            chain_id: tx.chain_id().to_u64(),
                            value: *tx.value(),
                        }))
                    }
                    _ => Ok(After::Nothing),
                }
            }
            Signed::Message { account, message } => {
                let account = json!(account);
                let payload = json!({ "message": message });
                self.tokens
                    .spend_with(minter, token, clocks.vault_ms, |kind| {
                        (kind == Kind::SignMessage && under_page).then_some(Request {
                            kind,
                            account: Some(&account),
                            payload: &payload,
                            page,
                        })
                    })
                    .map(|_| After::Nothing)
                    .map_err(refusal)
            }
            Signed::TypedData {
                account,
                fields,
                hash,
                ..
            } => {
                let account = json!(account);
                let mut payload = Map::new();
                for name in ["typed_data", "primary_type", "chain_id"] {
                    if let Some(value) = fields.get(name) {
                        payload.insert(name.to_owned(), value.clone());
                    }
                }
                let payload = Value::Object(payload);
                let spent = self
                    .tokens
                    .spend_with(minter, token, clocks.vault_ms, |kind| {
                        (kind == Kind::SignTypedData && under_page).then_some(Request {
                            kind,
                            account: Some(&account),
                            payload: &payload,
                            page,
                        })
                    })
                    .map_err(refusal)?;
                // The confirmed hash is the one signed (`expected_hash`).
                match spent.typed_data {
                    Some(typed) if typed.hash == *hash => Ok(After::Nothing),
                    _ => Err(refusal(Refusal::Mismatch)),
                }
            }
        }
    }

    /// A checked authorization's signature was made. For a flagged
    /// `dapp-send`, what became of its rule, for the reply.
    pub fn signed(&mut self, after: After, clocks: Clocks) -> Option<Value> {
        match after {
            After::Nothing => None,
            After::Owner(check) => {
                self.safes.owner_signed(check);
                None
            }
            After::Executor(check) => {
                self.safes.executor_signed(check);
                None
            }
            After::Remember(remember) => Some(self.remember(remember, clocks)),
        }
    }

    /// Burns a presented token: for a request that ended before its
    /// authorization was checked. A spent token is already gone.
    pub fn burn(&mut self, token: &str) {
        self.tokens.discard(token);
    }

    /// Checks `swarm.sign_soc`'s `authorization`, `{ swarm, soc }`, after
    /// the chunk's public work and before any key is derived (design 0012,
    /// "A page's SOC"). Only a page presents one: the core reads the page's
    /// Swarm grant for `PageContext.origin` from the swarm store as it
    /// stands, main's file until it moves. `swarm` is `user` (main's word
    /// that its prompt was answered) or `auto` (the site's flag); `soc`
    /// names the request, `feed` (a feed write) or `raw` (a raw SOC), as
    /// main names the key and the identifier until 0015.
    pub fn authorize_soc(
        &self,
        context: &Context,
        authorization: &Value,
        clocks: Clocks,
    ) -> Result<(), ErrorBody> {
        if !authorization.is_object() {
            return Err(invalid("authorization: expected an object"));
        }
        let fields = object(authorization, &["swarm", "soc"], &[])?;
        let approval = match string(fields, "swarm")? {
            "user" => SocApproval::User,
            "auto" => SocApproval::Auto,
            _ => return Err(invalid("swarm: expected user or auto")),
        };
        let request = match string(fields, "soc")? {
            "feed" => SocRequest::Feed,
            "raw" => SocRequest::Raw,
            _ => return Err(invalid("soc: expected feed or raw")),
        };
        let Some(page) = page_context(context)? else {
            return Err(forbidden("a Swarm grant answers only a page's SOC"));
        };
        let store = self.grants.view::<SwarmStore>(clocks.wall_ms / 1000);
        let ask = SocAsk {
            key: &page.origin,
            agent: page.agent,
            approval,
            request,
            // The feed grant is in main's feed store (`swarm-feeds.json`)
            // until 0015 moves it: main's word, as main sends a page's SOC
            // only once the site holds it, after its prompt has granted it.
            feed_grant: true,
        };
        match page_soc(&store, &ask) {
            Decision::Covered => Ok(()),
            Decision::NotCovered(reason) => Err(not_authorized(
                reason.name(),
                "the page's Swarm grant doesn't cover this SOC",
            )),
        }
    }
}

/// `sign.transaction`'s `authorization.kind`: one of the token kinds'
/// names. Whether it names one `sign.transaction` spends, and the token's,
/// is [`Presented::spends_transaction`]'s to say.
fn named_kind(kind: &Value) -> Result<Kind, ErrorBody> {
    kind.as_str()
        .and_then(Kind::from_name)
        .ok_or_else(|| invalid("authorization.kind: expected a token kind"))
}

/// An authorization's intent, `{ id }`: the id an `intent-replace` binds.
fn intent_id(intent: &Value) -> Result<&str, ErrorBody> {
    let fields = object(intent, &["id"], &[]).map_err(|_| invalid("intent: expected { id }"))?;
    string(fields, "id")
}

fn optional_bool(object: &Map<String, Value>, field: &str) -> Result<Option<bool>, ErrorBody> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::Bool(flag)) => Ok(Some(*flag)),
        Some(_) => Err(invalid(format!("{field}: expected a boolean"))),
    }
}

/// A chain id as the rules take it: an integer from 1 to `MAX_CHAIN_ID`.
fn chain_id(value: &Value, field: &str) -> Result<u64, ErrorBody> {
    value
        .as_u64()
        .filter(|chain_id| (1..=fc_approval::MAX_CHAIN_ID).contains(chain_id))
        .ok_or_else(|| invalid(format!("{field}: expected a chain id")))
}

fn optional_chain_id(object: &Map<String, Value>, field: &str) -> Result<Option<u64>, ErrorBody> {
    object
        .get(field)
        .map(|value| chain_id(value, field))
        .transpose()
}

/// An account index, as a token's: an integer from 0 to 2^31 - 1.
fn account(value: Option<&Value>, field: &str) -> Result<u32, ErrorBody> {
    value
        .and_then(Value::as_u64)
        .filter(|index| *index <= u64::from(fc_approval::MAX_ACCOUNT))
        .and_then(|index| u32::try_from(index).ok())
        .ok_or_else(|| invalid(format!("{field}: expected an account index")))
}

fn rule_clocks(clocks: Clocks) -> fc_approval::standing::Clocks {
    fc_approval::standing::Clocks {
        wall_ms: clocks.wall_ms,
        vault_ms: clocks.vault_ms,
    }
}

fn store_kind(object: &Map<String, Value>) -> Result<StoreKind, ErrorBody> {
    StoreKind::from_name(string(object, "store")?)
        .ok_or_else(|| invalid("store: expected dapp, swarm, radicle or x402"))
}

/// `not_moved`, with `data.store` (design 0012, API).
fn not_moved(kind: StoreKind) -> ErrorBody {
    ErrorBody::new(
        ErrorCode::NotMoved,
        "main still writes this permission file (it isn't in grant_moved)",
    )
    .with_data(json!({ "store": kind.name() }))
}

fn write_error(kind: StoreKind, failure: WriteFailure) -> ErrorBody {
    match failure {
        WriteFailure::NotMoved => not_moved(kind),
        WriteFailure::Bounds(refused) => invalid(refused.to_string()),
        // A narrowing stays active in memory, and isn't saved.
        WriteFailure::Io { applied } => ErrorBody::new(
            ErrorCode::Storage,
            "The permission file could not be written",
        )
        .with_data(json!({ "store": kind.name(), "applied": applied })),
    }
}

/// A JS value as JSON for a reply, in its own key order.
fn js_json(value: &JsValue) -> Result<Box<serde_json::value::RawValue>, ErrorBody> {
    serde_json::value::RawValue::from_string(value.stringify())
        .map_err(|_| crate::vault::internal())
}

/// The key a page's grant write changes: its own (`PageContext.origin`);
/// main names the site for a Swarm manifest's projection.
fn grant_key(context: &Context, change: &Map<String, Value>) -> Result<String, ErrorBody> {
    match (context.caller, page_context(context)?) {
        (CallerKind::Page, Some(page)) => {
            if change.contains_key("key") {
                return Err(invalid("change: a page changes its own grant"));
            }
            Ok(page.origin.clone())
        }
        _ => string(change, "key").map(str::to_owned),
    }
}

impl Approvals {
    /// The hello's `grant_root` and `grant_moved` (design 0012, "The
    /// files").
    pub fn configure_grants(
        &mut self,
        root: std::path::PathBuf,
        moved: Vec<StoreKind>,
        wall_ms: u64,
    ) {
        self.grants.configure(root, moved, wall_ms / 1000);
    }

    /// The `approval.changed` events the last request made, to send after
    /// its reply.
    pub fn take_events(&mut self) -> Vec<Zeroizing<Vec<u8>>> {
        std::mem::take(&mut self.events)
    }

    /// Which dApp rules answer: today's until the file moves.
    fn rules(&self) -> Rules {
        if self.grants.moved(StoreKind::Dapp) {
            Rules::Limited
        } else {
            Rules::Today
        }
    }

    fn changed(&mut self, kind: StoreKind, key: &str) {
        let mut payload = Zeroizing::new(Vec::new());
        if message::write_event(
            &mut *payload,
            "approval.changed",
            &json!({ "store": kind.name(), "key": key }),
        )
        .is_ok()
        {
            self.events.push(payload);
        }
    }

    /// Writes a moved store; one `approval.changed` for `key` when a
    /// widening or narrowing took effect, saved or not (a neutral change,
    /// a last use or a chain, sends none, whether its write failed or not).
    fn write<S: StoreFile, T>(
        &mut self,
        key: &str,
        change: impl FnOnce(&mut S) -> Applied<T>,
    ) -> Result<Written<T>, ErrorBody> {
        self.write_then(key, change, |_| {})
    }

    /// As [`Self::write`], and `then` runs once the change is active in
    /// memory: written, or a narrowing (or neutral change) whose write
    /// failed, which stands all the same.
    fn write_then<S: StoreFile, T>(
        &mut self,
        key: &str,
        change: impl FnOnce(&mut S) -> Applied<T>,
        then: impl FnOnce(&mut Self),
    ) -> Result<Written<T>, ErrorBody> {
        let mut effect = Effect::Unchanged;
        let result = self.grants.write::<S, T>(|store| {
            let applied = change(store);
            effect = applied.effect;
            applied
        });
        let grants = |effect: Effect| matches!(effect, Effect::Widening | Effect::Narrowing);
        match result {
            Ok(written) => {
                if grants(written.effect) {
                    self.changed(S::KIND, key);
                }
                then(self);
                Ok(written)
            }
            Err(failure) => {
                if matches!(failure, WriteFailure::Io { applied: true }) {
                    // The effect the change reported, as the write's own
                    // result isn't returned on a failure.
                    if grants(effect) {
                        self.changed(S::KIND, key);
                    }
                    then(self);
                }
                Err(write_error(S::KIND, failure))
            }
        }
    }

    /// `approval.check { request, chain_id?, paused? }`: whether a site's
    /// standing rule would answer, counting nothing (advice: `sign.*`
    /// decides again).
    fn check(
        &mut self,
        id: u64,
        params: &Value,
        context: &Context,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let fields = object(params, &["request"], &["chain_id", "paused"])?;
        let page = page_context(context)?
            .ok_or_else(|| forbidden("a standing rule answers only a page"))?;
        let chain = optional_chain_id(fields, "chain_id")?;
        let paused = optional_bool(fields, "paused")?;
        let request = object(
            &fields["request"],
            &["kind", "account", "account_kind"],
            &["message", "typed_data", "primary_type", "tx"],
        )?;
        let account = account(request.get("account"), "account")?;
        let kind = match string(request, "account_kind")? {
            "vault" => AccountKind::Vault,
            "ledger" => AccountKind::Ledger,
            "phone" => AccountKind::Phone,
            "safe" => AccountKind::Safe,
            _ => {
                return Err(invalid(
                    "account_kind: expected vault, ledger, phone or safe",
                ));
            }
        };
        let bytes;
        let view;
        let tx;
        let rule_request = match string(request, "kind")? {
            "message" => {
                bytes = fc_evm::parse_bytes(string(request, "message")?, "message")
                    .map_err(|e| invalid(e.to_string()))?;
                DappRequest::Signature(RuleSigned::Message(&bytes))
            }
            "typed_data" => {
                let typed = object(
                    request
                        .get("typed_data")
                        .ok_or_else(|| invalid("missing field typed_data"))?,
                    &["domain", "types", "message"],
                    &[],
                )?;
                view = fc_evm::typed_data_view(
                    &typed["domain"],
                    &typed["types"],
                    &typed["message"],
                    &fc_evm::ViewRequest {
                        primary_type: request.get("primary_type"),
                        chain_id: chain.map(U256::from_u64),
                        max_len: crate::signing::max_view_len(),
                    },
                )
                .map_err(|e| invalid(e.to_string()))?;
                DappRequest::Signature(RuleSigned::TypedData(&view))
            }
            "transaction" => {
                let payload = json!({
                    "tx": request.get("tx").ok_or_else(|| invalid("missing field tx"))?,
                });
                tx = send_tx(&payload).ok_or_else(|| invalid("tx: not a transaction"))?;
                // The chain the page names is the transaction's.
                if chain.is_some_and(|chain| tx.chain_id().to_u64() != Some(chain)) {
                    return Err(invalid("chain_id: not the transaction's"));
                }
                let evidence = tx
                    .chain_id()
                    .to_u64()
                    .and_then(|chain_id| self.fees.get(chain_id));
                DappRequest::Transaction(Send::of(&tx, kind, paused, evidence))
            }
            _ => return Err(invalid("kind: expected message, typed_data or transaction")),
        };
        let ask = DappAsk {
            key: &page.origin,
            agent: page.agent,
            account,
            request: rule_request,
        };
        let store = self.grants.view::<DappStore>(clocks.wall_ms / 1000);
        let decision =
            self.standing
                .check_dapp_under(self.rules(), &store, &ask, rule_clocks(clocks));
        let reply = match decision.reason() {
            None => json!({ "covered": true }),
            Some(reason) => json!({ "covered": false, "reason": reason.name() }),
        };
        json_reply(id, &reply)
    }

    /// `approval.spend { standing: { paused? }, kind, account, payload }`: a
    /// Safe message a site's signing rule answers, for the Safe's grant; it
    /// gives a Safe approval held by the page. Typed data is judged on the
    /// payload's chain, the Safe's.
    fn spend_standing(
        &mut self,
        id: u64,
        params: &Value,
        context: &Context,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let fields = object(params, &["standing", "kind", "payload", "account"], &[])?;
        let page = match (context.caller, page_context(context)?) {
            (CallerKind::Page, Some(page)) => page.clone(),
            _ => return Err(forbidden("a standing rule answers only a page")),
        };
        let standing = object(&fields["standing"], &[], &["paused"])?;
        optional_bool(standing, "paused")?;
        if Kind::from_name(string(fields, "kind")?) != Some(Kind::SafeMessage) {
            return Err(invalid(
                "a standing rule gives a Safe approval only for a Safe message",
            ));
        }
        let account = account(fields.get("account"), "account")?;
        let payload = &fields["payload"];
        let signed = fc_approval::safe::standing_signed(payload, limits().max_view_len)
            .map_err(approval_error)?;
        let approved = Approved::message(payload).map_err(approval_error)?;
        let request = match &signed {
            SafeSigned::Message(bytes) => DappRequest::Signature(RuleSigned::Message(bytes)),
            SafeSigned::TypedData(view) => DappRequest::Signature(RuleSigned::TypedData(view)),
        };
        let ask = DappAsk {
            key: &page.origin,
            agent: page.agent,
            account,
            request,
        };
        let rules = self.rules();
        let store = self.grants.view::<DappStore>(clocks.wall_ms / 1000);
        if let Some(reason) = self
            .standing
            .authorize_dapp_under(rules, &store, &ask, rule_clocks(clocks))
            .reason()
        {
            return Err(not_authorized(
                reason.name(),
                "no standing rule covers this request",
            ));
        }
        drop(store);
        let holder = Holder::Page {
            origin: page.origin,
            frame: page.frame,
            navigation: page.navigation,
        };
        let safe = self
            .safes
            .record(holder, approved, &mut OsRng)
            .map_err(approval_error)?
            .to_text();
        secret_reply(
            id,
            &SpentReply {
                bound: true,
                safe: Some(&safe),
            },
            0,
        )
    }

    /// `approval.grant { store, change }`: a decision main relays (design
    /// 0012, "The model"). A page writes its own grant in the dApp, Swarm
    /// and Radicle stores; main (`shell`) writes a Swarm manifest's
    /// projection. Never a transaction rule, and never an x402 cap.
    fn grant(
        &mut self,
        id: u64,
        params: &Value,
        context: &Context,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let fields = object(params, &["store", "change"], &[])?;
        let kind = store_kind(fields)?;
        let allowed = match (context.caller, kind) {
            (_, StoreKind::X402) => false,
            (CallerKind::Page, _) => true,
            (CallerKind::Shell, StoreKind::Swarm) => true,
            _ => false,
        };
        if !allowed {
            return Err(forbidden("this caller can't write this store's grants"));
        }
        let change = fields["change"]
            .as_object()
            .ok_or_else(|| invalid("change: expected an object"))?;
        let op = string(change, "op")?;
        if kind == StoreKind::Dapp && op == "transaction" {
            return Err(forbidden(
                "a transaction rule comes only with a confirmed send",
            ));
        }
        if !self.grants.moved(kind) {
            return Err(not_moved(kind));
        }
        let key = grant_key(context, change)?;
        let keyed: &[&str] = if context.caller == CallerKind::Page {
            &[]
        } else {
            &["key"]
        };
        let with = |extra: &[&'static str]| -> Vec<&'static str> {
            let mut names = vec!["op"];
            names.extend_from_slice(extra);
            names
        };
        let now = clocks.wall_ms;
        let (wrote, durable) = match (kind, op) {
            (StoreKind::Dapp, "connect") => {
                object(&fields["change"], &with(&["account", "chain_id"]), keyed)?;
                let account = account(change.get("account"), "account")?;
                let chain = chain_id(&change["chain_id"], "chain_id")?;
                let written = self.write::<DappStore, _>(&key, |store| {
                    store.connect(&key, account, chain, now)
                })?;
                (true, written.durable)
            }
            (StoreKind::Dapp, "account") => {
                object(&fields["change"], &with(&["account"]), keyed)?;
                let account = account(change.get("account"), "account")?;
                let written = self
                    .write::<DappStore, _>(&key, |store| store.set_account(&key, account, now))?;
                (written.value, written.durable)
            }
            (StoreKind::Dapp, "signing") => {
                object(&fields["change"], &with(&[]), keyed)?;
                let written =
                    self.write::<DappStore, _>(&key, |store| store.allow_signing(&key, now))?;
                (written.value, written.durable)
            }
            (StoreKind::Swarm, "connect") => {
                object(&fields["change"], &with(&[]), keyed)?;
                let written = self.write::<SwarmStore, _>(&key, |store| {
                    let applied = store.connect(&key, now);
                    Applied {
                        value: true,
                        effect: applied.effect,
                    }
                })?;
                (written.value, written.durable)
            }
            (StoreKind::Swarm, "flag") => {
                object(&fields["change"], &with(&["flag"]), keyed)?;
                let flag = SwarmFlag::from_name(string(change, "flag")?)
                    .ok_or_else(|| invalid("flag: unknown"))?;
                let written =
                    self.write::<SwarmStore, _>(&key, |store| store.set_flag(&key, flag, true))?;
                (written.value, written.durable)
            }
            (StoreKind::Swarm, "messaging") => {
                object(&fields["change"], &with(&[]), keyed)?;
                let written =
                    self.write::<SwarmStore, _>(&key, |store| store.grant_messaging(&key, now))?;
                (written.value, written.durable)
            }
            (StoreKind::Radicle, "connect") => {
                object(&fields["change"], &with(&[]), keyed)?;
                let written = self.write::<RadicleStore, _>(&key, |store| {
                    let applied = store.connect(&key, now);
                    Applied {
                        value: true,
                        effect: applied.effect,
                    }
                })?;
                (written.value, written.durable)
            }
            (StoreKind::Radicle, "flag") => {
                object(&fields["change"], &with(&["flag"]), keyed)?;
                let flag = RadicleFlag::from_name(string(change, "flag")?)
                    .ok_or_else(|| invalid("flag: unknown"))?;
                let written =
                    self.write::<RadicleStore, _>(&key, |store| store.set_flag(&key, flag, true))?;
                (written.value, written.durable)
            }
            (StoreKind::Radicle, "signing") => {
                object(&fields["change"], &with(&[]), keyed)?;
                let written =
                    self.write::<RadicleStore, _>(&key, |store| store.grant_signing(&key))?;
                (written.value, written.durable)
            }
            _ => return Err(invalid("change: unknown op for this store")),
        };
        let grant = if wrote {
            self.entry(kind, &key, clocks)?
        } else {
            None
        };
        let mut reply = json!({ "grant": grant });
        if !durable {
            reply["durable"] = json!(false);
        }
        json_reply(id, &reply)
    }

    /// A key's entry in a store, as the file holds it.
    fn entry(
        &self,
        kind: StoreKind,
        key: &str,
        clocks: Clocks,
    ) -> Result<Option<Box<serde_json::value::RawValue>>, ErrorBody> {
        let wall_s = clocks.wall_ms / 1000;
        let entry = match kind {
            StoreKind::Dapp => self.grants.view::<DappStore>(wall_s).entry(key).cloned(),
            StoreKind::Swarm => self.grants.view::<SwarmStore>(wall_s).entry(key).cloned(),
            StoreKind::Radicle => self.grants.view::<RadicleStore>(wall_s).entry(key).cloned(),
            StoreKind::X402 => None,
        };
        entry.as_ref().map(js_json).transpose()
    }

    /// `approval.revoke { store, key, what }`: a narrowing, open to the
    /// chrome as well (0011). A page revokes only its own grant.
    fn revoke(
        &mut self,
        id: u64,
        params: &Value,
        context: &Context,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let fields = object(params, &["store", "key", "what"], &[])?;
        let kind = store_kind(fields)?;
        let key = string(fields, "key")?.to_owned();
        if let Some(page) = page_context(context)?
            && page.origin != key
        {
            return Err(forbidden("a page revokes only its own grant"));
        }
        if !self.grants.moved(kind) {
            return Err(not_moved(kind));
        }
        let what = &fields["what"];
        let flag = what.get("flag").and_then(Value::as_str);
        let written = match (kind, what.as_str()) {
            // The buckets go once the revoke stands, saved or not: a grant
            // made again starts full.
            (StoreKind::Dapp, Some("grant")) => self.write_then::<DappStore, _>(
                &key,
                |store| store.revoke(&key),
                |this| this.standing.forget_dapp(&key),
            )?,
            (StoreKind::Dapp, Some("signing")) => {
                self.write::<DappStore, _>(&key, |store| store.signing_off(&key))?
            }
            (StoreKind::Dapp, None) if what.get("transaction").is_some() => {
                object(what, &["transaction"], &[])?;
                let call = object(&what["transaction"], &["to", "selector", "chain_id"], &[])?;
                let to = fc_evm::parse_address(string(call, "to")?)
                    .map_err(|_| invalid("to: expected an address"))?;
                let selector: [u8; 4] = fc_evm::parse_bytes(string(call, "selector")?, "selector")
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| invalid("selector: expected 4 bytes"))?;
                let chain = chain_id(&call["chain_id"], "chain_id")?;
                self.write::<DappStore, _>(&key, |store| {
                    store.remove_transaction_rule(&key, &to, &selector, chain)
                })?
            }
            (StoreKind::Swarm, Some("grant")) => {
                self.write::<SwarmStore, _>(&key, |store| store.revoke(&key))?
            }
            (StoreKind::Swarm, Some("messaging")) => {
                self.write::<SwarmStore, _>(&key, |store| store.revoke_messaging(&key))?
            }
            (StoreKind::Swarm, None) if flag.is_some() => {
                object(what, &["flag"], &[])?;
                let flag = SwarmFlag::from_name(flag.unwrap_or(""))
                    .ok_or_else(|| invalid("flag: unknown"))?;
                self.write::<SwarmStore, _>(&key, |store| store.set_flag(&key, flag, false))?
            }
            (StoreKind::Radicle, Some("grant")) => self.write_then::<RadicleStore, _>(
                &key,
                |store| store.revoke(&key),
                |this| {
                    this.standing.forget_radicle(&key);
                },
            )?,
            (StoreKind::Radicle, None) if flag.is_some() => {
                object(what, &["flag"], &[])?;
                let flag = RadicleFlag::from_name(flag.unwrap_or(""))
                    .ok_or_else(|| invalid("flag: unknown"))?;
                self.write::<RadicleStore, _>(&key, |store| store.set_flag(&key, flag, false))?
            }
            // A cap's revoke comes with X402-1's cap operations.
            (StoreKind::X402, _) => {
                return Err(invalid("x402 caps change through X402-1's methods"));
            }
            _ => return Err(invalid("what: unknown for this store")),
        };
        let mut reply = json!({ "revoked": written.value });
        if !written.durable {
            reply["durable"] = json!(false);
        }
        json_reply(id, &reply)
    }

    /// `approval.touch { store, chain_id? }`: a page's last use, and a
    /// dApp's chain. Neither widens nor narrows: no `approval.changed`.
    fn touch(
        &mut self,
        id: u64,
        params: &Value,
        context: &Context,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let fields = object(params, &["store"], &["chain_id"])?;
        let kind = store_kind(fields)?;
        let key = page_context(context)?
            .ok_or_else(|| forbidden("only a page marks its own use"))?
            .origin
            .clone();
        let chain = optional_chain_id(fields, "chain_id")?;
        if chain.is_some() && kind != StoreKind::Dapp {
            return Err(invalid("chain_id: only a dApp grant has a chain"));
        }
        if kind == StoreKind::X402 {
            return Err(invalid("store: x402 caps have no last use"));
        }
        if !self.grants.moved(kind) {
            return Err(not_moved(kind));
        }
        let now = clocks.wall_ms;
        let written = match kind {
            StoreKind::Dapp => {
                self.write::<DappStore, _>(&key, |store| store.touch(&key, chain, now))?
            }
            StoreKind::Swarm => {
                self.write::<SwarmStore, _>(&key, |store| store.touch(&key, now))?
            }
            _ => {
                // The reference throws on a `lastUsed` it can't convert:
                // nothing changes.
                let mut thrown = false;
                let written = self.write::<RadicleStore, _>(&key, |store| {
                    store.touch(&key, now).unwrap_or_else(|_| {
                        thrown = true;
                        Applied {
                            value: false,
                            effect: Effect::Unchanged,
                        }
                    })
                })?;
                if thrown {
                    return Err(invalid("lastUsed can't be read as a number"));
                }
                written
            }
        };
        let mut reply = json!({});
        if !written.durable {
            reply["durable"] = json!(false);
        }
        json_reply(id, &reply)
    }

    /// `approval.grants { store, key? }`: the store's records in today's
    /// shapes, most recently used first (`getAllPermissions`), or the key's
    /// alone.
    fn records(
        &self,
        id: u64,
        params: &Value,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let fields = object(params, &["store"], &["key"])?;
        let kind = store_kind(fields)?;
        let key = match fields.get("key") {
            None => None,
            Some(_) => Some(string(fields, "key")?),
        };
        let wall_s = clocks.wall_ms / 1000;
        let thrown = |_| invalid("a record can't be read as the reference reads it");
        let records: Vec<JsValue> = match kind {
            StoreKind::Dapp => {
                site_records(&*self.grants.view::<DappStore>(wall_s), key).map_err(thrown)?
            }
            StoreKind::Swarm => {
                site_records(&*self.grants.view::<SwarmStore>(wall_s), key).map_err(thrown)?
            }
            StoreKind::Radicle => {
                site_records(&*self.grants.view::<RadicleStore>(wall_s), key).map_err(thrown)?
            }
            StoreKind::X402 => cap_records(&self.grants.view::<CapStore>(wall_s), key, wall_s),
        };
        let records = records.iter().map(js_json).collect::<Result<Vec<_>, _>>()?;
        json_reply(id, &json!({ "records": records }))
    }

    /// `approval.forget_account { wallet_index }`: an account deleted;
    /// every dApp grant that exposes it is revoked (main's own write).
    fn forget_account(&mut self, id: u64, params: &Value) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let fields = object(params, &["wallet_index"], &[])?;
        let account = account(fields.get("wallet_index"), "wallet_index")?;
        if !self.grants.moved(StoreKind::Dapp) {
            return Err(not_moved(StoreKind::Dapp));
        }
        // The keys it revokes, known before the write: a narrowing whose
        // write fails stands in memory, and its events go all the same.
        let exposing: Vec<String> = {
            let store = self.grants.view::<DappStore>(0);
            store
                .keys()
                .filter(|key| store.exposes(key, account))
                .map(str::to_owned)
                .collect()
        };
        let result = self
            .grants
            .write::<DappStore, _>(|store| store.forget_account(account));
        let (keys, durable, error) = match result {
            Ok(written) => (written.value, written.durable, None),
            Err(failure @ WriteFailure::Io { applied: true }) => {
                (exposing, true, Some(write_error(StoreKind::Dapp, failure)))
            }
            Err(failure) => return Err(write_error(StoreKind::Dapp, failure)),
        };
        for key in &keys {
            self.standing.forget_dapp(key);
            self.changed(StoreKind::Dapp, key);
        }
        if let Some(error) = error {
            return Err(error);
        }
        let mut reply = json!({ "keys": keys });
        if !durable {
            reply["durable"] = json!(false);
        }
        json_reply(id, &reply)
    }

    /// The rule a flagged `dapp-send` asked for, written once it signed
    /// (design 0012, "The model"): only when the dApp file has moved, the
    /// page's grant exposes the account, and the call has a selector.
    fn remember(&mut self, remember: Remember, clocks: Clocks) -> Value {
        let refused = |reason: &str| json!({ "added": false, "reason": reason });
        if !self.grants.moved(StoreKind::Dapp) {
            return refused("not_moved");
        }
        let key = remember.key;
        if !self
            .grants
            .view::<DappStore>(clocks.wall_ms / 1000)
            .exposes(&key, remember.account)
        {
            return refused("not_exposed");
        }
        let (Some(to), Some(selector), Some(chain)) = (
            remember.to,
            remember.selector,
            remember
                .chain_id
                .filter(|chain| (1..=fc_approval::MAX_CHAIN_ID).contains(chain)),
        ) else {
            return refused("no_rule");
        };
        let value = remember.value;
        let now = clocks.wall_ms;
        match self.write::<DappStore, _>(&key, |store| {
            store.allow_transaction(&key, &to, &selector, chain, &value, now)
        }) {
            Ok(written) if written.value && written.durable => json!({ "added": true }),
            Ok(written) if written.value => json!({ "added": true, "durable": false }),
            Ok(_) => refused("not_exposed"),
            Err(error) if error.code == ErrorCode::InvalidArgument => refused("bounds"),
            Err(_) => refused("not_saved"),
        }
    }
}

/// A site store's records, most recently used first, or the key's alone.
trait SiteRecords {
    fn site_entry(&self, key: &str) -> Option<&JsValue>;
    fn site_records(&self) -> Result<Vec<&JsValue>, fc_approval::stores::ToPrimitiveError>;
}

impl SiteRecords for DappStore {
    fn site_entry(&self, key: &str) -> Option<&JsValue> {
        self.entry(key)
    }
    fn site_records(&self) -> Result<Vec<&JsValue>, fc_approval::stores::ToPrimitiveError> {
        self.records()
    }
}

impl SiteRecords for SwarmStore {
    fn site_entry(&self, key: &str) -> Option<&JsValue> {
        self.entry(key)
    }
    fn site_records(&self) -> Result<Vec<&JsValue>, fc_approval::stores::ToPrimitiveError> {
        self.records()
    }
}

impl SiteRecords for RadicleStore {
    fn site_entry(&self, key: &str) -> Option<&JsValue> {
        self.entry(key)
    }
    fn site_records(&self) -> Result<Vec<&JsValue>, fc_approval::stores::ToPrimitiveError> {
        self.records()
    }
}

fn site_records<S: SiteRecords>(
    store: &S,
    key: Option<&str>,
) -> Result<Vec<JsValue>, fc_approval::stores::ToPrimitiveError> {
    Ok(match key {
        Some(key) => store.site_entry(key).cloned().into_iter().collect(),
        None => store.site_records()?.into_iter().cloned().collect(),
    })
}

/// x402's records as `getAllPermissions` gives them: `{ origin, chainId,
/// asset, ...record }` for each live cap.
fn cap_records(store: &CapStore, key: Option<&str>, wall_s: u64) -> Vec<JsValue> {
    // Read again at now, so a cap that expired since it loaded is dropped.
    let live = store
        .text()
        .ok()
        .and_then(|text| CapStore::load(text.as_bytes(), wall_s).ok())
        .unwrap_or_default();
    live.caps()
        .filter(|(origin, _, _)| key.is_none_or(|key| key == *origin))
        .map(|(origin, asset_key, record)| {
            let mut parts = asset_key.split(':');
            let chain = parts.next().unwrap_or("");
            let asset = parts.next();
            let mut out = JsValue::Object(Vec::new());
            out.set("origin", JsValue::string(origin));
            out.set("chainId", js_number(chain));
            out.set("asset", asset.map_or(JsValue::Null, JsValue::string));
            if let JsValue::Object(props) = record {
                for (name, value) in props {
                    out.set(name.clone(), value.clone());
                }
            }
            out
        })
        .collect()
}

/// `Number(text)` for a cap key's chain, as JSON keeps it: the decimal the
/// reference writes, or `null` (NaN) for anything else.
fn js_number(text: &str) -> JsValue {
    if text.is_empty() {
        return JsValue::Number(0.0);
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return JsValue::Null;
    }
    text.parse::<f64>().map_or(JsValue::Null, JsValue::Number)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const CLOCKS: Clocks = Clocks {
        vault_ms: 10_000,
        wall_ms: 1_700_000_000_000,
    };

    fn reply(payload: &[u8]) -> Value {
        serde_json::from_slice(payload).unwrap()
    }

    fn shell() -> Context {
        Context::shell()
    }

    fn send() -> Value {
        json!({ "tx": {
            "type": 2,
            "chain_id": "100",
            "gas_limit": "21000",
            "to": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "value": "1",
            "data": "0x",
            "max_fee_per_gas": "7000000000",
            "max_priority_fee_per_gas": "1000000000",
        } })
    }

    fn quote(per_gas: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": "response",
            "id": 5,
            "result": {
                "header": null,
                "lowest_priority": null,
                "quote": { "source": "direct", "type": "eip1559", "maxFeePerGas": per_gas, "answered": 2 },
                "generation": 0,
            },
        }))
        .unwrap()
    }

    /// The fee check at minting judges a send against the newest
    /// `chain.fee_reference` reply the core served for its chain: above
    /// three times it, no token without `fee_ack`.
    #[test]
    fn a_send_above_the_threshold_needs_fee_ack() {
        let mut approvals = Approvals::new();
        let issue = |approvals: &mut Approvals, ack: Option<bool>| {
            let mut params = json!({ "kind": "wallet-send", "account": 0, "payload": send() });
            if let Some(ack) = ack {
                params["fee_ack"] = json!(ack);
            }
            approvals.request(1, "approval.issue", &params, &shell(), CLOCKS)
        };
        // No evidence: nothing to compare with, so a token.
        let minted = reply(&issue(&mut approvals, None).unwrap());
        assert_eq!(minted["result"]["fee_check"]["comparable"], false);
        assert_eq!(minted["result"]["expires_in_ms"], 120_000);
        assert_eq!(minted["result"]["token"].as_str().unwrap().len(), 64);
        // A reply for another request, and one for chain 1, change nothing.
        approvals.fee_asked(4, Some(r#"{"chain_id":100,"deadline_ms":15000}"#), 9_000);
        approvals.fee_answered(5, &quote("2000000000"));
        approvals.fee_asked(5, Some(r#"{"chain_id":1,"deadline_ms":15000}"#), 9_000);
        approvals.fee_answered(5, &quote("2000000000"));
        assert!(issue(&mut approvals, None).is_ok());
        approvals.fee_asked(6, Some(r#"{"chain_id":100,"deadline_ms":15000}"#), 9_000);
        let mut answer = quote("2000000000");
        answer = String::from_utf8(answer)
            .unwrap()
            .replace(r#""id":5"#, r#""id":6"#)
            .into_bytes();
        approvals.fee_answered(6, &answer);
        let refused = issue(&mut approvals, None).unwrap_err();
        assert_eq!(refused.code, ErrorCode::NotAuthorized);
        let data = refused.data.unwrap();
        assert_eq!(data["reason"], "fee_check");
        assert_eq!(data["fee_check"]["above"], true);
        assert_eq!(data["fee_check"]["ratio"], "3.5");
        assert!(issue(&mut approvals, Some(false)).is_err());
        let acknowledged = reply(&issue(&mut approvals, Some(true)).unwrap());
        assert_eq!(acknowledged["result"]["fee_check"]["above"], true);
        // Sixty seconds after it was asked, the quote is too old to judge.
        let later = Clocks {
            vault_ms: 9_000 + 60_001,
            ..CLOCKS
        };
        let params = json!({ "kind": "wallet-send", "account": 0, "payload": send() });
        let stale = approvals.request(1, "approval.issue", &params, &shell(), later);
        assert!(stale.is_ok());
    }

    /// A token's view fits `approval.issue`'s reply, which is longer than
    /// `sign.typed_data`'s: the binding takes the shorter limit.
    #[test]
    fn an_issued_view_fits_one_frame() {
        let issued = max_issued_view_len();
        assert!(issued > 0);
        assert!(issued < crate::signing::max_view_len());
        assert_eq!(limits().max_view_len, issued);
    }

    #[test]
    fn evidence_answered_late_keeps_the_newer() {
        let mut fees = FeeEvidence::default();
        fees.asked(1, 100, 1_000);
        fees.asked(2, 100, 2_000);
        let result = |per_gas: &str| reply(&quote(per_gas))["result"].clone();
        fees.answered(2, &result("3"));
        fees.answered(1, &result("4"));
        assert_eq!(fees.get(100).unwrap().requested_at_ms, 2_000);
        // Two asked in one millisecond: the later ask is the newer, and the
        // earlier one, answered late with a higher quote, doesn't replace
        // it.
        fees.asked(3, 100, 2_500);
        fees.asked(4, 100, 2_500);
        fees.answered(4, &result("3"));
        fees.answered(3, &result("9"));
        assert_eq!(*fees.get(100).unwrap(), Evidence::read(&result("3"), 2_500));
        // Answered in order, the later ask replaces the earlier.
        fees.asked(5, 100, 2_600);
        fees.asked(6, 100, 2_600);
        fees.answered(5, &result("7"));
        assert_eq!(*fees.get(100).unwrap(), Evidence::read(&result("7"), 2_600));
        fees.answered(6, &result("5"));
        assert_eq!(*fees.get(100).unwrap(), Evidence::read(&result("5"), 2_600));
        // The same ID asked again is a new ask: its old place is gone.
        fees.asked(7, 100, 2_700);
        fees.asked(8, 100, 2_700);
        fees.asked(7, 100, 2_700);
        fees.answered(8, &result("2"));
        fees.answered(7, &result("6"));
        assert_eq!(*fees.get(100).unwrap(), Evidence::read(&result("6"), 2_700));
        // At most 32 chains: the oldest goes.
        for chain in 0..MAX_FEE_CHAINS as u64 {
            fees.asked(chain + 10, chain + 1_000, 3_000);
            fees.answered(chain + 10, &result("1"));
        }
        assert!(fees.get(100).is_none());
        assert!(fees.get(1_000).is_some());
        for id in 0..MAX_FEE_ASKED as u64 + 5 {
            fees.asked(id + 10, 1, 0);
        }
        assert_eq!(fees.asked.len(), MAX_FEE_ASKED);
    }

    /// A phone account picks its own fees: `phone: true` on a
    /// `wallet-send` or `dapp-send` mints without the fee check, while the
    /// same send without it needs `fee_ack`. No other kind takes it.
    #[test]
    fn a_phone_send_skips_the_fee_check() {
        let mut approvals = Approvals::new();
        approvals.fee_asked(6, Some(r#"{"chain_id":100,"deadline_ms":15000}"#), 9_000);
        let answer = String::from_utf8(quote("2000000000"))
            .unwrap()
            .replace(r#""id":5"#, r#""id":6"#);
        approvals.fee_answered(6, answer.as_bytes());
        let wallet = json!({ "kind": "wallet-send", "account": 0, "payload": send() });
        let refused = approvals
            .request(1, "approval.issue", &wallet, &shell(), CLOCKS)
            .unwrap_err();
        assert_eq!(refused.data.unwrap()["reason"], "fee_check");
        let mut not_phone = wallet.clone();
        not_phone["phone"] = json!(false);
        let refused = approvals
            .request(1, "approval.issue", &not_phone, &shell(), CLOCKS)
            .unwrap_err();
        assert_eq!(refused.data.unwrap()["reason"], "fee_check");
        let mut phone = wallet.clone();
        phone["phone"] = json!(true);
        let minted = reply(
            &approvals
                .request(1, "approval.issue", &phone, &shell(), CLOCKS)
                .unwrap(),
        );
        assert_eq!(minted["result"]["token"].as_str().unwrap().len(), 64);
        assert!(minted["result"].get("fee_check").is_none());
        // A page's send for a phone account.
        let site = Context {
            caller: CallerKind::Page,
            page: Some(PageContext {
                origin: "https://app.example".into(),
                top_origin: "https://app.example".into(),
                frame: 1,
                navigation: 1,
                agent: Some(false),
            }),
        };
        let mut dapp = json!({ "kind": "dapp-send", "account": 0, "payload": send(), "handle": "a1".repeat(32) });
        let refused = approvals
            .request(1, "approval.issue", &dapp, &site, CLOCKS)
            .unwrap_err();
        assert_eq!(refused.data.unwrap()["reason"], "fee_check");
        dapp["phone"] = json!(true);
        let minted = reply(
            &approvals
                .request(1, "approval.issue", &dapp, &site, CLOCKS)
                .unwrap(),
        );
        assert!(minted["result"].get("fee_check").is_none());
        // Not a boolean, or on another kind.
        let mut text = phone.clone();
        text["phone"] = json!("yes");
        let executor =
            json!({ "kind": "executor-send", "account": 0, "payload": send(), "phone": true });
        let executor_false =
            json!({ "kind": "executor-send", "account": 0, "payload": send(), "phone": false });
        for params in [text, executor, executor_false] {
            let refused = approvals
                .request(1, "approval.issue", &params, &shell(), CLOCKS)
                .unwrap_err();
            assert_eq!(refused.code, ErrorCode::InvalidArgument, "{params}");
        }
    }

    /// `approval.discard` burns a presented token whatever the outcome: a
    /// malformed request's, and a page's refused for its missing
    /// `PageContext`. `approval.end` under `page` needs one too.
    #[test]
    fn a_discard_burns_its_token_whatever_the_outcome() {
        let mut approvals = Approvals::new();
        let mint = |approvals: &mut Approvals| {
            let params = json!({ "kind": "wallet-send", "account": 0, "payload": send() });
            let minted = reply(
                &approvals
                    .request(1, "approval.issue", &params, &shell(), CLOCKS)
                    .unwrap(),
            );
            minted["result"]["token"].as_str().unwrap().to_owned()
        };
        let bare_page = Context {
            caller: CallerKind::Page,
            page: None,
        };
        for (extra, context) in [(Some(json!(1)), shell()), (None, bare_page.clone())] {
            let token = mint(&mut approvals);
            let mut params = json!({ "token": token });
            if let Some(extra) = extra {
                params["extra"] = extra;
            }
            let refused = approvals
                .request(1, "approval.discard", &params, &context, CLOCKS)
                .unwrap_err();
            assert_eq!(refused.code, ErrorCode::InvalidArgument);
            let spend =
                json!({ "token": token, "kind": "wallet-send", "account": 0, "payload": send() });
            let refused = approvals
                .request(1, "approval.spend", &spend, &shell(), CLOCKS)
                .unwrap_err();
            assert_eq!(refused.data.unwrap()["reason"], "unknown_token");
        }
        assert!(
            approvals
                .request(
                    1,
                    "approval.end",
                    &json!({ "safe": "00".repeat(16) }),
                    &bare_page,
                    CLOCKS
                )
                .is_err()
        );
        assert!(
            approvals
                .request(
                    1,
                    "approval.end",
                    &json!({ "safe": "00".repeat(16) }),
                    &shell(),
                    CLOCKS
                )
                .is_ok()
        );
    }
}
