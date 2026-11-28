//! The store ops main calls (design 0015, "Methods main calls"; SWM-4's
//! D6, D7 and D8): `swarm.identities` ([`identities`]), `swarm.history`
//! ([`history`]) and `swarm.manifest` ([`manifest`]). Each op is read from
//! its wire form strictly ([`Call::parse`]), applied through part 2's codecs
//! ([`crate::stores`]), and answered in today's shape.
//!
//! **The wire form.** `params` is an object: `op`, a string naming the op,
//! and the op's own members, each a value in the typed form
//! (`vectors/swarm.json`'s `formats.typed`, [`Value::from_typed`]), since
//! the reference reads the chrome's IPC values by their JavaScript types (a
//! label that isn't a string, an `activate` that isn't `true`, an identity
//! id of any type). An unknown op or member, a member missing or of
//! another typed shape, or a site key that isn't a string is
//! [`Refused::Invalid`] (`invalid_argument`); a typed value no store holds
//! (a BigInt, bytes, an array with a hole) is too. An op only main makes,
//! called by the chrome, is [`Refused::Forbidden`] on its name alone: `op`
//! is read first, and no other member is decoded.
//!
//! **Running an op.** The swarm thread makes an [`Op`] for each call and
//! moves it with its [`Stores`] in hand: [`Op::start`], then each answer
//! ([`Op::answer`]), its feed-store change's answer if the change waited
//! for SW-1's hold ([`Op::changed`]), and [`Op::retry`] after each hold's
//! end while it waits for one, until a [`Step::Done`].
//! - **The stores are synchronous** (the amendment's "SWM-4 must apply
//!   feed-store writes in order"): the feed store through SW-1's keeper
//!   ([`Keeper::change`], each change written durably before it is kept),
//!   the manifest store with its file, its `.bak` copy and its projections
//!   onto the Swarm grants ([`Grants`], design 0012's handle, D2) and the
//!   feed store, and the history's statements, each through [`Io`].
//! - **Asks** ([`Need`]) are what needs the vault or main: a key's owner
//!   and the user's accounts for an identity list, and D6's
//!   `shell.swarm_manifest` fetch for a check.
//! - **SW-1's hold** ("SW-1 in the core"): a feed-store change the keeper
//!   defers ([`crate::machine::keeper`]: an activation, a revoke, an index
//!   taken) is answered when the hold ends, under the op's [`Ticket`]. A
//!   manifest op whose transaction would revoke a held site's feed grant
//!   waits, whole, for the hold's end, so no transaction stops half-way;
//!   every other op goes on.
//!
//! **Admission** (design 0015, Budgets): [`Call::gated`] names the ops that
//! take a place in the swarm thread's 64 and 256: `swarm.manifest`'s
//! `check`, and `swarm.identities`' ops that read owners. The others run in
//! the thread's order with no place.

use fc_json::{JsString, JsValue};

pub mod history;
pub mod identities;
pub mod manifest;

pub use crate::machine::AskId;
use crate::machine::SignKey;
use crate::machine::keeper::{ChangeAnswer, ChangeError, Keeper, STORE_FULL_MESSAGE, Ticket};
use crate::stores::history::{Row, Statement};
use crate::stores::manifests::{Capability, Effect, ManifestStore, Projection, Save};
use crate::stores::{StoreError, Thrown};
use crate::value::Value;

/// The methods' names.
pub const IDENTITIES: &str = "swarm.identities";
pub const HISTORY: &str = "swarm.history";
pub const MANIFEST: &str = "swarm.manifest";

/// `store_full`'s code on a thrown answer (design 0015, Budgets).
pub const STORE_FULL: &str = "store_full";

/// Who calls (design 0015's rows, D5): `swarm.identities` and
/// `swarm.history` are the chrome's and main's, `swarm.manifest` main's;
/// some ops of the first two are main's alone (D7; `swarm.history`'s `add`
/// and `update`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    Chrome,
    Shell,
}

/// Why params aren't an op.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// `invalid_argument`: an unknown op or member, a member missing or of
    /// another shape.
    #[error("invalid params: {0}")]
    Invalid(String),
    /// `forbidden`: an op only main makes, from the chrome.
    #[error("{0} is main's own op")]
    Forbidden(&'static str),
}

/// A parsed call.
#[derive(Debug, Clone, PartialEq)]
pub enum Call {
    Identities(identities::Op),
    History(history::Op),
    Manifest(manifest::Op),
}

impl Call {
    /// Reads `params` of `method` for `caller`: `op` first, then, unless
    /// it names an op only main makes and the chrome calls it (refused on
    /// the name alone, before any other member is decoded), the op's
    /// members.
    pub fn parse(method: &str, params: &JsValue, caller: Caller) -> Result<Call, Refused> {
        let (op, props) = Members::op(params)?;
        if caller == Caller::Chrome
            && let Some(name) = main_op(method, &op)
        {
            return Err(Refused::Forbidden(name));
        }
        let members = Members::read(props)?;
        match method {
            IDENTITIES => identities::Op::parse(op, members).map(Call::Identities),
            HISTORY => history::Op::parse(op, members).map(Call::History),
            MANIFEST => manifest::Op::parse(op, members).map(Call::Manifest),
            _ => Err(Refused::Invalid(format!("no store op for {method}"))),
        }
    }

    /// Whether the call takes a place among the swarm thread's running
    /// requests (design 0015, Budgets): it asks main or the vault.
    pub fn gated(&self) -> bool {
        match self {
            Call::Identities(op) => op.reads_owners(),
            Call::History(_) => false,
            Call::Manifest(op) => matches!(op, manifest::Op::Check { .. }),
        }
    }
}

/// What the Swarm grants (design 0012's handle, D2) answer and take for a
/// manifest's projections.
pub trait Grants {
    /// `permissions.getPermission(key)`.
    fn connected(&self, key: &JsString) -> bool;
    /// `permissions.hasMessagingGrant(key)`.
    fn messaging(&self, key: &JsString) -> bool;
    /// `permissions.getAutoApprove(key, capability)`.
    fn auto_approve(&self, key: &JsString, capability: Capability) -> bool;
    /// One of a projection's grant effects ([`Effect::Connect`],
    /// [`Effect::Disconnect`], [`Effect::Flag`], [`Effect::Messaging`]),
    /// written durably as main's own change; the write's text if it fails.
    fn apply(&mut self, key: &JsString, effect: Effect) -> Result<(), JsString>;
    /// The grants' file made to hold the store as memory has it, where an
    /// earlier write left it behind (a narrowing whose write failed stands
    /// in memory alone); the write's text if it fails. The manifest store
    /// saves only after it (D17): a record a transaction removes, or a
    /// projection it marks off, is never on disk while the grants' file
    /// still holds what memory no longer does (the user's revoke whose
    /// write failed, which a disconnect then finds already made and
    /// leaves). Nothing to do by default.
    fn settle(&mut self) -> Result<(), JsString> {
        Ok(())
    }
}

/// The stores' files, their randomness and the history's database: the
/// swarm thread's, each synchronous.
pub trait Io {
    /// `swarm-feeds.json`'s text, written durably (0013).
    fn write_feeds(&mut self, text: &str) -> Result<(), JsString>;
    /// `swarm-manifest-grants.json`'s bytes, `None` when there is none.
    fn read_manifests(&mut self) -> Option<Vec<u8>>;
    /// Its `.bak` copy's, read only when the file can't be.
    fn read_manifests_backup(&mut self) -> Option<Vec<u8>>;
    /// One write of `swarm-manifest-grants.json` (the `.bak` copy first
    /// where [`Save::backup`] says).
    fn save_manifests(&mut self, save: &Save) -> Result<(), JsString>;
    /// `crypto.randomBytes(24)`, for a consent's token: `None` when the
    /// system's randomness fails, which fails the check rather than make a
    /// token anyone could guess.
    fn random(&mut self) -> Option<[u8; 24]>;
    /// `publish-history.sqlite`'s rows for a query.
    fn query(&mut self, statement: &Statement) -> Result<Vec<Row>, JsString>;
    /// A statement run: the rows it changed.
    fn run(&mut self, statement: &Statement) -> Result<usize, JsString>;
    /// One `INSERT` run: the new row's rowid (`swarm.history`'s `add`).
    fn insert(&mut self, statement: &Statement) -> Result<i64, JsString>;
}

/// What an op runs against: the swarm thread's stores, at `now_ms`
/// (`Date.now()`).
pub struct Stores<'a> {
    pub now_ms: u64,
    pub keeper: &'a mut Keeper,
    pub manifests: &'a mut ManifestStore,
    pub grants: &'a mut dyn Grants,
    pub io: &'a mut dyn Io,
}

/// What an op asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Need {
    /// The vault: a key's owner (identity-manager.js's
    /// `getBeeWalletAddress`, `getPublisherAddress`), answered
    /// [`Event::Owner`] (`None` while the vault is locked).
    Owner(SignKey),
    /// The user's accounts (`getDerivedWallets`, `accounts.list`'s
    /// `wallets`), for a stored `ethereum-wallet` identity's label and
    /// owner, answered [`Event::Accounts`].
    Accounts,
    /// D6: `shell.swarm_manifest { for, url }`, main's fetch of the
    /// manifest at a `bzz:` address, answered [`Event::Manifest`].
    Manifest { url: String },
}

/// An ask, with its handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    pub id: AskId,
    pub need: Need,
}

/// An ask's answer.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Owner(Result<Option<[u8; 20]>, JsString>),
    Accounts(Result<Vec<JsValue>, JsString>),
    Manifest(Fetch),
}

/// Main's answer to `shell.swarm_manifest` (D6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetch {
    /// `{ failed }`: the fetch threw, or its body stalled or broke (a
    /// transport failure, the check's `unresolved`), or the ask passed
    /// D13's bound.
    Failed,
    /// `{ status, body_base64 }`: at most 8 KiB + 1 bytes of the body.
    Answered { status: u16, body: Vec<u8> },
}

/// How an op ended.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Its answer, today's shape, in the typed form (D5).
    Result(Value),
    /// What the reference throws, `{ name, message, code? }`, or the
    /// core's own refusal in that form (`store_full`, a history row it
    /// can't read, a write that failed).
    Thrown(Thrown),
    /// Main cancelled it.
    Cancelled,
}

/// What an op waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waiting {
    /// The answers to its asks.
    Answers,
    /// Its feed-store change, which SW-1's hold deferred: the keeper's
    /// release answers it under the op's ticket ([`Op::changed`]).
    Change,
    /// A hold's end, before it can run ([`Op::retry`]).
    Hold,
}

/// What an op needs next.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Send these asks, then wait for their answers.
    Asks(Vec<Ask>),
    Wait(Waiting),
    Done(Outcome),
    /// It ended already: what came is dropped.
    Ended,
}

/// One store op.
#[derive(Debug, Clone)]
pub struct Op {
    run: Run,
    ticket: Ticket,
    next_ask: u64,
    ended: bool,
}

#[derive(Debug, Clone)]
enum Run {
    Identities(identities::Run),
    History(history::Op),
    Manifest(manifest::Run),
}

impl Op {
    /// An op for `call`. `ticket` is its handle for a feed-store change
    /// SW-1's hold defers.
    pub fn new(call: Call, ticket: Ticket) -> Op {
        let run = match call {
            Call::Identities(op) => Run::Identities(identities::Run::new(op)),
            Call::History(op) => Run::History(op),
            Call::Manifest(op) => Run::Manifest(manifest::Run::new(op)),
        };
        Op {
            run,
            ticket,
            next_ask: 0,
            ended: false,
        }
    }

    /// Its ticket.
    pub fn ticket(&self) -> Ticket {
        self.ticket
    }

    /// The site whose manifest record a `swarm.manifest` op reads or
    /// changes (`check`'s and `decide`'s `key`, the chrome's ops'
    /// `origin`); `None` for `release`, which reads no record, and for
    /// every other method's op. A user's change of the site's Swarm grants
    /// detaches in order with these (D17).
    pub fn manifest_key(&self) -> Option<&JsString> {
        match &self.run {
            Run::Manifest(run) => run.key(),
            Run::Identities(_) | Run::History(_) => None,
        }
    }

    /// Runs it as far as it goes.
    pub fn start(&mut self, stores: &mut Stores<'_>) -> Step {
        if self.ended {
            return Step::Ended;
        }
        let mut cx = Cx {
            ticket: self.ticket,
            next_ask: &mut self.next_ask,
        };
        let step = match &mut self.run {
            Run::Identities(run) => run.start(&mut cx, stores),
            Run::History(op) => Step::Done(op.run(stores.now_ms, stores.io)),
            Run::Manifest(run) => run.start(&mut cx, stores),
        };
        self.settle(step)
    }

    /// An ask's answer.
    pub fn answer(&mut self, ask: AskId, event: Event, stores: &mut Stores<'_>) -> Step {
        if self.ended {
            return Step::Ended;
        }
        let mut cx = Cx {
            ticket: self.ticket,
            next_ask: &mut self.next_ask,
        };
        let step = match &mut self.run {
            Run::Identities(run) => run.answer(&mut cx, ask, event, stores),
            Run::History(_) => Step::Ended,
            Run::Manifest(run) => run.answer(&mut cx, ask, event, stores),
        };
        self.settle(step)
    }

    /// Its deferred feed-store change, made (or refused) as the hold that
    /// deferred it ended.
    pub fn changed(
        &mut self,
        answer: Result<ChangeAnswer, ChangeError>,
        stores: &mut Stores<'_>,
    ) -> Step {
        if self.ended {
            return Step::Ended;
        }
        let mut cx = Cx {
            ticket: self.ticket,
            next_ask: &mut self.next_ask,
        };
        let step = match &mut self.run {
            Run::Identities(run) => run.changed(&mut cx, answer, stores),
            Run::History(_) | Run::Manifest(_) => Step::Ended,
        };
        self.settle(step)
    }

    /// A hold ended: an op waiting for one tries again.
    pub fn retry(&mut self, stores: &mut Stores<'_>) -> Step {
        if self.ended {
            return Step::Ended;
        }
        let mut cx = Cx {
            ticket: self.ticket,
            next_ask: &mut self.next_ask,
        };
        let step = match &mut self.run {
            Run::Manifest(run) => run.retry(&mut cx, stores),
            Run::Identities(run) => run.waiting(),
            Run::History(_) => Step::Ended,
        };
        self.settle(step)
    }

    /// Main cancelled it: it ends now. A feed-store change already handed
    /// to the keeper is still made (a write can't be called back), and its
    /// answer dropped.
    pub fn cancel(&mut self) -> Step {
        if self.ended {
            return Step::Ended;
        }
        self.ended = true;
        Step::Done(Outcome::Cancelled)
    }

    fn settle(&mut self, step: Step) -> Step {
        if matches!(step, Step::Done(_)) {
            self.ended = true;
        }
        step
    }
}

/// What a running op uses of its [`Op`].
pub(crate) struct Cx<'o> {
    ticket: Ticket,
    next_ask: &'o mut u64,
}

impl Cx<'_> {
    fn ask(&mut self, need: Need) -> Ask {
        let id = AskId(*self.next_ask);
        *self.next_ask += 1;
        Ask { id, need }
    }
}

/// The user changed a projection of site `key` outside an op (design 0015,
/// D17: a change of the Swarm grants, which the event loop writes):
/// `detachManaged(key, projection)`, as the reference's
/// `detachManagedLater` runs it. A connection changed by hand disconnects
/// (the record removed, the feed grant and the connection revoked); any
/// other projection is marked detached in the site's record, dropped from
/// what it manages, the revision moved on and the store saved, and a site
/// with no record keeps nothing to change. A store that can't be read or
/// written keeps its record, as the reference only logs that failure.
///
/// `false`, with nothing changed, while SW-1's hold would defer a
/// feed-store change it makes (the disconnect's revoke of a held site's
/// feed grant, or a journal it replays): the caller tries again once a
/// hold ends, as a manifest op waits ([`Waiting::Hold`]).
pub fn detach(stores: &mut Stores<'_>, key: &JsString, projection: Projection) -> bool {
    if manifest::detach_held(stores, key, projection) {
        return false;
    }
    manifest::detach(stores, key, projection);
    true
}

/// A feed-store change's refusal as its caller reads it: the reference's
/// own, `store_full`'s, or the write's text.
pub(crate) fn change_thrown(error: ChangeError) -> Thrown {
    match error {
        ChangeError::Store(StoreError::Thrown(thrown)) => thrown,
        ChangeError::Store(StoreError::Full) => Thrown::coded(STORE_FULL_MESSAGE, STORE_FULL),
        ChangeError::Write(text) => Thrown::error(text.as_str()),
    }
}

// --- the wire form ---------------------------------------------------------------

/// `op` of `method` if only main makes it (D7: `swarm.identities`' prompt
/// ops and `getEthereumWalletIdentityReferences`, `swarm.history`'s `add`
/// and `update`), as [`Refused::Forbidden`] names it.
fn main_op(method: &str, op: &str) -> Option<&'static str> {
    let ops: &[&'static str] = match method {
        IDENTITIES => &identities::MAIN_OPS,
        HISTORY => &history::MAIN_OPS,
        _ => &[],
    };
    ops.iter().copied().find(|name| *name == op)
}

/// `params`' properties, as JSON gives them.
type Props = [(JsString, JsValue)];

/// An op's members, each read from the typed form.
#[derive(Debug)]
pub(crate) struct Members {
    members: Vec<(JsString, Value)>,
}

impl Members {
    /// `params`' `op`, which must be an object's string member, and its
    /// properties, none of the others decoded yet.
    fn op(params: &JsValue) -> Result<(String, &Props), Refused> {
        let JsValue::Object(props) = params else {
            return Err(invalid("params must be an object"));
        };
        let mut op = None;
        for (name, value) in props {
            if name == "op" {
                match value {
                    JsValue::String(s) if s.is_well_formed() => op = Some(s.as_str().to_owned()),
                    _ => return Err(invalid("op must be a string")),
                }
            }
        }
        let op = op.ok_or_else(|| invalid("op is missing"))?;
        Ok((op, props))
    }

    /// Every property but `op`, each read from the typed form.
    fn read(props: &Props) -> Result<Members, Refused> {
        let mut members = Vec::with_capacity(props.len());
        for (name, value) in props {
            if name != "op" {
                let typed = Value::from_typed(value)
                    .map_err(|e| invalid(format!("{}: {e}", name.as_str())))?;
                members.push((name.clone(), typed));
            }
        }
        Ok(Members { members })
    }

    /// Refuses any member `allowed` doesn't name.
    pub(crate) fn only(&self, op: &str, allowed: &[&str]) -> Result<(), Refused> {
        match self
            .members
            .iter()
            .find(|(name, _)| !allowed.iter().any(|a| name == *a))
        {
            Some((name, _)) => Err(invalid(format!("{op} takes no member {}", name.as_str()))),
            None => Ok(()),
        }
    }

    fn get(&self, name: &str) -> Option<&Value> {
        self.members.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// A member that must be a string (a site's key, a token, a URL).
    pub(crate) fn string(&self, name: &str) -> Result<JsString, Refused> {
        match self.get(name) {
            Some(Value::String(s)) => Ok(s.clone()),
            Some(_) => Err(invalid(format!("{name} must be a string"))),
            None => Err(invalid(format!("{name} is missing"))),
        }
    }

    /// A member that must be a boolean, `default` when absent.
    pub(crate) fn boolean(&self, name: &str, default: Option<bool>) -> Result<bool, Refused> {
        match (self.get(name), default) {
            (Some(Value::Bool(b)), _) => Ok(*b),
            (None, Some(default)) => Ok(default),
            (Some(_), _) => Err(invalid(format!("{name} must be a boolean"))),
            (None, None) => Err(invalid(format!("{name} is missing"))),
        }
    }

    /// A JavaScript value the reference reads by its type: `undefined`
    /// when absent.
    pub(crate) fn js(&self, name: &str) -> Result<JsValue, Refused> {
        match self.get(name) {
            None => Ok(JsValue::Undefined),
            Some(value) => {
                js_value(value).ok_or_else(|| invalid(format!("{name} holds no store value")))
            }
        }
    }
}

pub(crate) fn invalid(why: impl Into<String>) -> Refused {
    Refused::Invalid(why.into())
}

/// A typed value as a store holds it: `None` for a BigInt, bytes, or an
/// array with a hole, which no store value is.
fn js_value(value: &Value) -> Option<JsValue> {
    Some(match value {
        Value::Undefined => JsValue::Undefined,
        Value::Null => JsValue::Null,
        Value::Bool(b) => JsValue::Bool(*b),
        Value::Number(n) => JsValue::Number(*n),
        Value::String(s) => JsValue::String(s.clone()),
        Value::Array(items) => JsValue::Array(
            items
                .iter()
                .map(|item| item.as_ref().and_then(js_value))
                .collect::<Option<Vec<_>>>()?,
        ),
        Value::Object(members) => JsValue::Object(
            members
                .iter()
                .map(|(k, v)| js_value(v).map(|v| (k.clone(), v)))
                .collect::<Option<Vec<_>>>()?,
        ),
        Value::BigInt(_) | Value::Bytes(_) => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(text: &str) -> JsValue {
        fc_json::parse(text).unwrap()
    }

    #[test]
    fn the_wire_form_is_read_strictly() {
        let refused = |method: &str, text: &str, caller| {
            Call::parse(method, &params(text), caller).unwrap_err()
        };
        // Not an object, no op, op not a string, an unknown op or method.
        for text in ["[]", "{}", r#"{"op":5}"#, r#"{"op":"nope"}"#] {
            assert!(matches!(
                refused(IDENTITIES, text, Caller::Shell),
                Refused::Invalid(_)
            ));
        }
        assert!(matches!(
            refused("swarm.publish", r#"{"op":"list"}"#, Caller::Shell),
            Refused::Invalid(_)
        ));
        // A member outside the typed form, of another shape, or unknown.
        for text in [
            r#"{"op":"has-feed-identity","origin":"https://a"}"#,
            r#"{"op":"has-feed-identity","origin":{"number":"1"}}"#,
            r#"{"op":"has-feed-identity"}"#,
            r#"{"op":"has-feed-identity","origin":{"string":"a"},"extra":{"null":true}}"#,
            r#"{"op":"create-app-scoped-identity","origin":{"string":"a"},"options":{"bigint":"1"}}"#,
            r#"{"op":"create-app-scoped-identity","origin":{"string":"a"},"options":{"array":[{"hole":true}]}}"#,
        ] {
            assert!(
                matches!(
                    refused(IDENTITIES, text, Caller::Chrome),
                    Refused::Invalid(_)
                ),
                "{text}"
            );
        }
        // Main's own op, from the chrome.
        assert_eq!(
            refused(
                IDENTITIES,
                r#"{"op":"grantFeedAccess","key":{"string":"a"}}"#,
                Caller::Chrome
            ),
            Refused::Forbidden("grantFeedAccess")
        );
        assert!(
            Call::parse(
                IDENTITIES,
                &params(r#"{"op":"grantFeedAccess","key":{"string":"a"}}"#),
                Caller::Shell
            )
            .is_ok()
        );
        // ...refused on its name alone: no other member is decoded first,
        // so a malformed one, before `op` or after it, is still
        // `forbidden` from the chrome and `invalid_argument` from main.
        for (method, text, name) in [
            (HISTORY, r#"{"op":"add","entry":{}}"#, "add"),
            (HISTORY, r#"{"entry":"raw","op":"add"}"#, "add"),
            (HISTORY, r#"{"op":"add","entry":{"bigint":"x"}}"#, "add"),
            (HISTORY, r#"{"op":"update","id":1,"updates":{}}"#, "update"),
            (HISTORY, r#"{"updates":[],"op":"update"}"#, "update"),
            (
                IDENTITIES,
                r#"{"key":"a","op":"grantFeedAccess"}"#,
                "grantFeedAccess",
            ),
        ] {
            assert_eq!(
                refused(method, text, Caller::Chrome),
                Refused::Forbidden(name),
                "{text}"
            );
            assert!(
                matches!(refused(method, text, Caller::Shell), Refused::Invalid(_)),
                "{text}"
            );
        }
        // The chrome's own ops still have their members read.
        assert!(matches!(
            refused(HISTORY, r#"{"op":"remove","id":5}"#, Caller::Chrome),
            Refused::Invalid(_)
        ));
        // History's remove needs its id; list takes none.
        assert!(matches!(
            refused(
                HISTORY,
                r#"{"op":"list","id":{"number":"1"}}"#,
                Caller::Chrome
            ),
            Refused::Invalid(_)
        ));
        // A manifest decision's token and outcome are strings, its live
        // fact a boolean.
        for text in [
            r#"{"op":"decide","key":{"string":"k"},"token":{"number":"1"},"outcome":{"string":"allow"},"live":{"boolean":true}}"#,
            r#"{"op":"decide","key":{"string":"k"},"token":{"string":"t"},"outcome":{"string":"allow"}}"#,
            r#"{"op":"check","key":{"string":"k"},"url":{"string":"u"},"eager":{"string":"yes"}}"#,
        ] {
            assert!(
                matches!(refused(MANIFEST, text, Caller::Shell), Refused::Invalid(_)),
                "{text}"
            );
        }
    }

    #[test]
    fn a_refused_change_reads_as_its_caller_reads_it() {
        assert_eq!(
            change_thrown(ChangeError::Store(StoreError::Full)),
            Thrown::coded("Swarm feed store is full", "store_full")
        );
        assert_eq!(
            change_thrown(ChangeError::Write(JsString::from("EIO"))),
            Thrown::error("EIO")
        );
        let own = Thrown::type_error("x");
        assert_eq!(
            change_thrown(ChangeError::Store(StoreError::Thrown(own.clone()))),
            own
        );
    }

    #[test]
    fn only_the_ops_that_ask_main_or_the_vault_are_gated() {
        let gated = |method: &str, text: &str| {
            Call::parse(method, &params(text), Caller::Shell)
                .unwrap()
                .gated()
        };
        assert!(gated(
            IDENTITIES,
            r#"{"op":"get-origin-identities","origin":{"string":"a"}}"#
        ));
        assert!(gated(
            IDENTITIES,
            r#"{"op":"previewAppScopedIdentity","key":{"string":"a"}}"#
        ));
        assert!(!gated(IDENTITIES, r#"{"op":"get-all-origins"}"#));
        assert!(!gated(
            IDENTITIES,
            r#"{"op":"revoke-feed-access","origin":{"string":"a"}}"#
        ));
        assert!(gated(
            MANIFEST,
            r#"{"op":"check","key":{"string":"k"},"url":{"string":"u"}}"#
        ));
        assert!(!gated(MANIFEST, r#"{"op":"get","origin":{"string":"k"}}"#));
        assert!(!gated(HISTORY, r#"{"op":"list"}"#));
    }
}
