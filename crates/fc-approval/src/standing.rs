//! The standing rules (design 0012, "The rules"): whether a site's "Always
//! allow" answers a request with no prompt, from the core's own grants for
//! `PageContext.origin`, R-6's and Q9's rate, and 0005's fee check.
//!
//! The reference is freedom-browser's `page/page-signing.js` (`ruleCovers`
//! and the rule's choice in `sign`), `page/page-sends.js` (`ruleMatches`,
//! `ruleChosen`, `autoSend`'s fee check and `sendDappPayment`'s pause),
//! `page/page-swarm.js` (each method's `ruled`) and
//! `radicle/radicle-provider-ipc.js` (the COB writes' rule and R-6);
//! `vectors/approvals.json`'s `rules.decisions`, produced from the first
//! two, is the contract (AGENTS rule 5). What differs is design 0012's:
//!
//! - `rule-legacy`, `rule-expiry` and `rule-value`: a dApp rule answers only
//!   in Q9's limited form, for 30 days of the wall clock from its
//!   `grantedAt`, and a transaction rule for no more `value` than the send
//!   it came from ([`DappStore::signing_rule`],
//!   [`DappStore::transaction_rule`]).
//! - `rule-rate`: R-6's limiter for each key and [`RequestClass`], counted
//!   only for a request every other check covers. Over it, the request is
//!   asked ([`Reason::RateLimited`]), never refused; one the user approves
//!   at its prompt isn't counted, since only [`Standing::authorize_dapp`]
//!   counts, and only what it covers.
//! - `rule-inputs`: custody (`PageContext.agent`) and the D12 pause come
//!   with the request, read by main; a missing one answers no rule
//!   ([`Reason::Custody`], [`Reason::Paused`]).
//!
//! **Advice and decision.** `approval.check` asks [`Standing::check_dapp`],
//! which counts nothing; `sign.*` with `{ standing }` asks
//! [`Standing::authorize_dapp`], which decides again and counts what it
//! covers. Swarm's flags and Radicle's keep today's rules, R-6 included
//! ([`swarm`], [`Standing::authorize_radicle`]).
//!
//! **The order of the checks**, so that one reason is given: custody
//! first, then the grant and its rule (`no_rule`), then what the rule never
//! covers (`warning`), the pause and the fee check, and the rate last, as
//! Q9 counts a request only once every other check has passed.
//!
//! The module does no I/O: the stores, both clocks and the fee evidence
//! come in (AGENTS rule 2).

use fc_evm::{Transaction, TypedDataView, U256};
use serde_json::Value;

use crate::MAX_CHAIN_ID;
use crate::fee::{Evidence, Fees, judge_fees, reference_fee};
use crate::rate::{RateLimiter, RequestClass};
use crate::stores::{
    DappStore, RadicleFlag, RadicleStore, SigningRule, SwarmFlag, SwarmStore, TransactionRule,
};

/// Why no standing rule answers a request: design 0012's API's
/// `data.reason`. The request goes to its prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// No grant exposes the account, or no rule (in Q9's form, within its 30
    /// days and its value) covers the request; or a request no rule ever
    /// answers: a plain transfer, a contract creation, a Safe's send.
    NoRule,
    /// A send while the site's payments wait their turn (D12), or with no
    /// pause sent.
    Paused,
    /// A send the fee check doesn't allow: above three times the reference,
    /// with no reference or one endpoint's, or naming no fee of its own.
    FeeCheck,
    /// A tab the agent holds, or a request with no `agent` sent.
    Custody,
    /// Past the rule's rate (R-6, Q9).
    RateLimited,
    /// What the user must see: a `personal_sign` of exactly 32 bytes (#89),
    /// or typed data whose view carries a warning (#88).
    Warning,
}

impl Reason {
    pub const ALL: [Reason; 6] = [
        Reason::NoRule,
        Reason::Paused,
        Reason::FeeCheck,
        Reason::Custody,
        Reason::RateLimited,
        Reason::Warning,
    ];

    /// Its name on the wire.
    pub fn name(self) -> &'static str {
        match self {
            Reason::NoRule => "no_rule",
            Reason::Paused => "paused",
            Reason::FeeCheck => "fee_check",
            Reason::Custody => "custody",
            Reason::RateLimited => "rate_limited",
            Reason::Warning => "warning",
        }
    }

    pub fn from_name(name: &str) -> Option<Reason> {
        Reason::ALL.into_iter().find(|reason| reason.name() == name)
    }
}

/// A standing rule's answer.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The rule answers: no prompt.
    Covered,
    /// The prompt, and why.
    NotCovered(Reason),
}

impl Decision {
    pub fn is_covered(self) -> bool {
        self == Decision::Covered
    }

    pub fn reason(self) -> Option<Reason> {
        match self {
            Decision::Covered => None,
            Decision::NotCovered(reason) => Some(reason),
        }
    }

    fn of(result: Result<(), Reason>) -> Decision {
        match result {
            Ok(()) => Decision::Covered,
            Err(reason) => Decision::NotCovered(reason),
        }
    }
}

/// What signs for an account, as far as a rule cares (the reference's
/// `account.type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountKind {
    /// The vault's own key (`mnemonic`).
    Vault,
    /// A Ledger (`ledger`).
    Ledger,
    /// A phone (`remote`): it picks and pays its own fee, so its sends
    /// aren't judged.
    Phone,
    /// A Safe (`safe`): its board confirms each send, so no rule answers
    /// one. Its messages go as any account's, for the Safe's grant.
    Safe,
}

/// The two clocks a rule reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clocks {
    /// Wall-clock milliseconds: Q9's expiry, and the fee evidence's header.
    pub wall_ms: u64,
    /// The vault's clock: the rate, and the fee evidence's age.
    pub vault_ms: u64,
}

/// What a signature signs.
#[derive(Debug, Clone, Copy)]
pub enum Signed<'a> {
    /// `personal_sign`: the bytes `sign.message` signs.
    Message(&'a [u8]),
    /// `eth_signTypedData_v4`: the core's view of the typed data, which
    /// says whether it warns.
    TypedData(&'a TypedDataView),
}

/// A send, as the core takes it.
#[derive(Debug, Clone)]
pub struct Send<'a> {
    pub kind: AccountKind,
    /// `None` for a contract creation.
    pub to: Option<&'a [u8; 20]>,
    pub data: &'a [u8],
    pub value: &'a U256,
    pub chain_id: &'a U256,
    /// The fees it is signed with.
    pub fees: Fees,
    /// D12's pause, which main reads in the send's own turn; `None` when it
    /// isn't sent.
    pub paused: Option<bool>,
    /// The newest `chain.fee_reference` reply the core served for the
    /// chain, read as evidence; `None` without one.
    pub evidence: Option<&'a Evidence>,
}

impl<'a> Send<'a> {
    /// The send `sign.transaction` signs.
    pub fn of(
        tx: &'a Transaction,
        kind: AccountKind,
        paused: Option<bool>,
        evidence: Option<&'a Evidence>,
    ) -> Send<'a> {
        let (max_fee_per_gas, max_priority_fee_per_gas) = match tx.eip1559_fees() {
            Some((max_fee, priority)) => (Some(*max_fee), Some(*priority)),
            None => (None, None),
        };
        Send {
            kind,
            to: tx.to(),
            data: tx.data(),
            value: tx.value(),
            chain_id: tx.chain_id(),
            fees: Fees {
                max_fee_per_gas,
                max_priority_fee_per_gas,
                gas_price: tx.gas_price().copied(),
                gas_limit: Some(*tx.gas_limit()),
            },
            paused,
            evidence,
        }
    }
}

/// A request a site's dApp rules may answer.
#[derive(Debug, Clone)]
pub enum DappRequest<'a> {
    /// `personal_sign` or `eth_signTypedData_v4`, a Safe's message
    /// included, under the signing rule.
    Signature(Signed<'a>),
    /// `eth_sendTransaction`, under a transaction rule.
    Transaction(Send<'a>),
}

/// A request, for the page that sent it.
#[derive(Debug, Clone)]
pub struct DappAsk<'a> {
    /// `PageContext.origin`.
    pub key: &'a str,
    /// `PageContext.agent`: whether the agent holds the tab, read as main
    /// sent the request; `None` when it wasn't sent.
    pub agent: Option<bool>,
    /// The account that signs: for a Safe's message, the Safe's.
    pub account: u32,
    pub request: DappRequest<'a>,
}

/// A Swarm request a site's flags may answer (`page-swarm.js`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwarmRequest {
    /// An upload: the `publish` flag.
    Publish,
    /// A feed's creation, update or entry: the `feeds` flag, for a site
    /// with feed access (`hasFeedGrant`, main's feed store's until 0015).
    Feeds { feed_grant: bool },
    /// A raw SOC, or the signing identity: the `signing` flag, for a site
    /// with feed access.
    Signing { feed_grant: bool },
    /// A message sent: the messaging grant and the `messaging` flag.
    Message,
}

/// A Swarm request, for the page that sent it.
#[derive(Debug, Clone, Copy)]
pub struct SwarmAsk<'a> {
    pub key: &'a str,
    pub agent: Option<bool>,
    pub request: SwarmRequest,
}

/// A Radicle request a site's flags may answer
/// (`radicle-provider-ipc.js`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadicleRequest {
    /// `radicle_seed` or `radicle_unseed`: the `node` flag.
    Seed,
    /// A COB write (an issue, its comment or state, a patch's comment): the
    /// signing grant and the `signing` flag, within R-6.
    CobWrite,
}

/// A Radicle request, for the page that sent it.
#[derive(Debug, Clone, Copy)]
pub struct RadicleAsk<'a> {
    pub key: &'a str,
    pub agent: Option<bool>,
    pub request: RadicleRequest,
}

/// The standing rules' memory: Q9's buckets and R-6's, in memory only, so a
/// restart (a new `Standing`) starts every bucket full and empty.
#[derive(Debug, Clone, Default)]
pub struct Standing {
    dapp: RateLimiter<(String, RequestClass)>,
    radicle: RateLimiter<String>,
}

impl Standing {
    pub fn new() -> Self {
        Standing::default()
    }

    /// Whether a site's rule would answer the request now, counting
    /// nothing: advice, for the choice between a prompt and none
    /// (`approval.check`).
    pub fn check_dapp(&self, store: &DappStore, ask: &DappAsk<'_>, clocks: Clocks) -> Decision {
        Decision::of(dapp_rule(store, ask, clocks).and_then(|class| {
            let bucket = (ask.key.to_owned(), class);
            within(self.dapp.would_admit(&bucket, clocks.vault_ms))
        }))
    }

    /// Whether a site's rule answers the request, as `sign.*` decides it
    /// under `{ standing }`: covered, and counted in its bucket, only when
    /// every other check passes and the rate allows it.
    pub fn authorize_dapp(
        &mut self,
        store: &DappStore,
        ask: &DappAsk<'_>,
        clocks: Clocks,
    ) -> Decision {
        Decision::of(dapp_rule(store, ask, clocks).and_then(|class| {
            let bucket = (ask.key.to_owned(), class);
            within(self.dapp.admit(&bucket, clocks.vault_ms))
        }))
    }

    /// A dApp grant revoked (a disconnect, an account deleted): its
    /// buckets, both classes, forgotten. A new grant needs its prompts
    /// again, and then starts full.
    pub fn forget_dapp(&mut self, key: &str) {
        self.dapp.forget_where(|(site, _)| site == key);
    }

    /// Whether a site's Radicle rule would answer now, counting nothing.
    pub fn check_radicle(
        &self,
        store: &RadicleStore,
        ask: &RadicleAsk<'_>,
        vault_ms: u64,
    ) -> Decision {
        Decision::of(radicle_rule(store, ask).and_then(|limited| {
            if limited {
                within(self.radicle.would_admit(&ask.key.to_owned(), vault_ms))
            } else {
                Ok(())
            }
        }))
    }

    /// Whether a site's Radicle rule answers: a COB write is counted in R-6
    /// when it is covered.
    pub fn authorize_radicle(
        &mut self,
        store: &RadicleStore,
        ask: &RadicleAsk<'_>,
        vault_ms: u64,
    ) -> Decision {
        Decision::of(radicle_rule(store, ask).and_then(|limited| {
            if limited {
                within(self.radicle.admit(&ask.key.to_owned(), vault_ms))
            } else {
                Ok(())
            }
        }))
    }

    /// `radicle_disconnect`, or a revoked Radicle grant: R-6 forgets the
    /// site. Whether it had a bucket.
    pub fn forget_radicle(&mut self, key: &str) -> bool {
        self.radicle.forget(&key.to_owned())
    }
}

/// Whether a site's Swarm flag answers the request (advised but for a
/// page's SOC, which the core signs). No rate: Swarm's flags keep today's
/// rules.
pub fn swarm(store: &SwarmStore, ask: &SwarmAsk<'_>) -> Decision {
    Decision::of(swarm_rule(store, ask))
}

fn within(admitted: bool) -> Result<(), Reason> {
    if admitted {
        Ok(())
    } else {
        Err(Reason::RateLimited)
    }
}

fn outside_custody(agent: Option<bool>) -> Result<(), Reason> {
    // Unknown custody is custody, as the reference reads one it can't tell.
    if agent == Some(false) {
        Ok(())
    } else {
        Err(Reason::Custody)
    }
}

fn require(holds: bool, reason: Reason) -> Result<(), Reason> {
    if holds { Ok(()) } else { Err(reason) }
}

/// Every check but the rate; the bucket the request counts in.
fn dapp_rule(store: &DappStore, ask: &DappAsk<'_>, clocks: Clocks) -> Result<RequestClass, Reason> {
    outside_custody(ask.agent)?;
    match &ask.request {
        DappRequest::Signature(signed) => {
            signature(store, ask.key, ask.account, signed, clocks)?;
            Ok(RequestClass::Signature)
        }
        DappRequest::Transaction(send) => {
            transaction(store, ask.key, ask.account, send, clocks)?;
            Ok(RequestClass::Transaction)
        }
    }
}

/// `ruleCovers`: the grant exposes the account and its signing rule
/// answers; never 32 bytes, nor a warned view.
fn signature(
    store: &DappStore,
    key: &str,
    account: u32,
    signed: &Signed<'_>,
    clocks: Clocks,
) -> Result<(), Reason> {
    require(store.exposes(key, account), Reason::NoRule)?;
    require(
        store.signing_rule(key, clocks.wall_ms) == SigningRule::Active,
        Reason::NoRule,
    )?;
    match signed {
        // `signsRawHash`: exactly 32 bytes, as main normalizes them.
        Signed::Message(bytes) => require(bytes.len() != 32, Reason::Warning),
        Signed::TypedData(view) => require(!warned(view), Reason::Warning),
    }
}

/// `typedDataWarnings` of the core's view: a named type other than the
/// inferred root, or a domain chain other than the page's, or none. A view
/// that can't be read warns.
fn warned(view: &TypedDataView) -> bool {
    let Ok(parsed) = serde_json::from_str::<Value>(&view.view) else {
        return true;
    };
    let field = |name: &str| parsed.get(name).and_then(Value::as_str);
    field("named_type") == Some("mismatch") || matches!(field("chain"), Some("mismatch" | "absent"))
}

/// `ruleChosen` and `autoSend`: the grant exposes the account; a contract
/// call a rule covers; not paused; the fee check.
fn transaction(
    store: &DappStore,
    key: &str,
    account: u32,
    send: &Send<'_>,
    clocks: Clocks,
) -> Result<(), Reason> {
    require(send.kind != AccountKind::Safe, Reason::NoRule)?;
    require(store.exposes(key, account), Reason::NoRule)?;
    let to = send.to.ok_or(Reason::NoRule)?;
    // `selectorOf`: a plain transfer has none.
    let selector = send.data.first_chunk::<4>().ok_or(Reason::NoRule)?;
    let chain_id = send
        .chain_id
        .to_u64()
        .filter(|chain_id| (1..=MAX_CHAIN_ID).contains(chain_id))
        .ok_or(Reason::NoRule)?;
    let rule = store.transaction_rule(key, to, selector, chain_id, send.value, clocks.wall_ms);
    require(rule == TransactionRule::Covered, Reason::NoRule)?;
    require(send.paused == Some(false), Reason::Paused)?;
    if send.kind != AccountKind::Phone {
        // `namesOwnFees`; then `judgeFees` against the reference.
        let fees = &send.fees;
        let named = (fees.max_fee_per_gas.is_some() && fees.max_priority_fee_per_gas.is_some())
            || fees.gas_price.is_some();
        require(named, Reason::FeeCheck)?;
        let reference = reference_fee(send.evidence, clocks.wall_ms, clocks.vault_ms);
        require(
            judge_fees(fees, reference.as_ref()).auto_approve,
            Reason::FeeCheck,
        )?;
    }
    Ok(())
}

/// `page-swarm.js`'s `ruled`: connected, outside custody, and the flag for
/// the request (with feed access for feeds and signing, the messaging grant
/// for a message).
fn swarm_rule(store: &SwarmStore, ask: &SwarmAsk<'_>) -> Result<(), Reason> {
    outside_custody(ask.agent)?;
    require(store.entry(ask.key).is_some(), Reason::NoRule)?;
    let ruled = match ask.request {
        SwarmRequest::Publish => store.flag(ask.key, SwarmFlag::Publish),
        SwarmRequest::Feeds { feed_grant } => feed_grant && store.flag(ask.key, SwarmFlag::Feeds),
        SwarmRequest::Signing { feed_grant } => {
            feed_grant && store.flag(ask.key, SwarmFlag::Signing)
        }
        SwarmRequest::Message => {
            store.has_messaging(ask.key) && store.flag(ask.key, SwarmFlag::Messaging)
        }
    };
    require(ruled, Reason::NoRule)
}

/// `radicle-provider-ipc.js`: connected, outside custody, and the node
/// flag for a seed, or the signing grant and flag for a COB write. Whether
/// R-6 counts it.
fn radicle_rule(store: &RadicleStore, ask: &RadicleAsk<'_>) -> Result<bool, Reason> {
    outside_custody(ask.agent)?;
    require(store.entry(ask.key).is_some(), Reason::NoRule)?;
    match ask.request {
        RadicleRequest::Seed => {
            require(store.flag(ask.key, RadicleFlag::Node), Reason::NoRule)?;
            Ok(false)
        }
        RadicleRequest::CobWrite => {
            require(
                store.has_signing(ask.key) && store.flag(ask.key, RadicleFlag::Signing),
                Reason::NoRule,
            )?;
            Ok(true)
        }
    }
}
