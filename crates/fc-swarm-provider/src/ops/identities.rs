//! `swarm.identities` (design 0015, "Methods main calls"; SWM-4's D7 and
//! D8): the publisher identities and feed grants of `swarm-feeds.json`, as
//! the chrome and main reach them today.
//!
//! **The chrome's ops** (and main's, which proxies them), one per IPC
//! handler of `feed-store.js`'s `registerFeedStoreIpc`, named by its
//! channel, each answering what the handler answers:
//!
//! | op | params | answer |
//! |---|---|---|
//! | `get-all-origins` | | `getAllOriginEntries()` |
//! | `has-feed-identity` | `origin` | `hasIdentityMode(origin)` |
//! | `get-identity-mode` | `origin` | `getOriginEntry(origin)?.identityMode \|\| null` |
//! | `get-origin-identities` | `origin` | `getOriginIdentityStateWithOwners(origin)` |
//! | `create-app-scoped-identity` | `origin`, `options?` | `createAppScopedIdentity(origin, { ...options, source: 'user' })`, then the state with owners |
//! | `ensure-ant-wallet-identity` | `origin`, `options?` | `ensureAntWalletIdentity(origin, { ...options, source: 'user' })`, then the state with owners |
//! | `activate-feed-identity` | `origin`, `identity_id?` | `activateIdentity(origin, identityId)`, then the state with owners |
//! | `set-feed-identity` | | refused, as for every site since PRQ-7d |
//! | `revoke-feed-access` | `origin` | `revokeFeedAccess(origin)`, then `true` |
//!
//! **Main's own ops** (D7; shell only), named by the function main calls,
//! each answering what it returns: page-swarm.js's feed prompt
//! (`getOriginIdentityStateWithOwners`, `previewAppScopedIdentity`,
//! `createAppScopedIdentityAt`, `ensureAntWalletIdentity`,
//! `activateIdentity`, `grantFeedAccess`, each change with `source:
//! 'user'`), the two reads that prompt also makes (`hasFeedGrant`,
//! `assertFeedGrantable`), and `getEthereumWalletIdentityReferences` for
//! `accounts.remove`'s references (D8's order):
//!
//! | op | params |
//! |---|---|
//! | `getOriginIdentityStateWithOwners` | `key` |
//! | `previewAppScopedIdentity` | `key`, `options?` |
//! | `createAppScopedIdentityAt` | `key`, `index?`, `options?` (main's: `{ activate: true }`) |
//! | `ensureAntWalletIdentity` | `key`, `options?` (main's: `{ activate: true }`) |
//! | `activateIdentity` | `key`, `identity_id?` |
//! | `grantFeedAccess` | `key` |
//! | `hasFeedGrant` | `key` |
//! | `assertFeedGrantable` | `key` |
//! | `getEthereumWalletIdentityReferences` | `wallet_index?` |
//!
//! `origin` and `key` are a site's permission key, a string, taken as main
//! gives it (the stores don't normalize it again). Every other member is
//! the JavaScript value the reference reads, `undefined` when absent.
//!
//! **Owners** come from the vault: every owner an identity list needs is
//! asked at once ([`super::Need::Owner`], [`super::Need::Accounts`]), and
//! the answer is read from the store as it stands when the last one
//! arrives, in the reference's order, so the first owner that fails is its
//! error (a locked vault gives the reference's text for each mode). An
//! owner a change made meanwhile needs is asked then.
//!
//! **Changes** go through SW-1's keeper as [`FeedChange`]s: one the hold
//! defers waits for the hold's end ([`super::Waiting::Change`]). A user's
//! change of the active identity or of the feed grant lets go of what a
//! permission manifest managed (`notifyManifestMutation`, the reference's
//! `detachManagedLater`), once the change is made.

use fc_json::{JsString, JsValue};

use super::{
    Ask, AskId, Cx, Event, Members, Need, Outcome, Refused, Step, Stores, Waiting, change_thrown,
    invalid,
};
use crate::machine::SignKey;
use crate::machine::keeper::{ChangeAnswer, ChangeError, Ran};
use crate::stores::feeds::{FeedChange, FeedStore, Owners, Source};
use crate::stores::{Thrown, spread};
use crate::value::Value;

/// `FEED_GRANT_REFUSED`: the chrome's feed grant, refused for every site.
pub const FEED_GRANT_REFUSED: &str = "Swarm feed access is granted only from its own prompt";

/// A `swarm.identities` op.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    // The chrome's.
    GetAllOrigins,
    HasFeedIdentity {
        origin: JsString,
    },
    GetIdentityMode {
        origin: JsString,
    },
    GetOriginIdentities {
        origin: JsString,
    },
    CreateAppScopedIdentity {
        origin: JsString,
        options: JsValue,
    },
    EnsureAntWalletIdentity {
        origin: JsString,
        options: JsValue,
    },
    ActivateFeedIdentity {
        origin: JsString,
        identity_id: JsValue,
    },
    SetFeedIdentity,
    RevokeFeedAccess {
        origin: JsString,
    },
    // Main's own.
    StateWithOwners {
        key: JsString,
    },
    Preview {
        key: JsString,
        options: JsValue,
    },
    CreateAt {
        key: JsString,
        index: JsValue,
        options: JsValue,
    },
    Ensure {
        key: JsString,
        options: JsValue,
    },
    Activate {
        key: JsString,
        identity_id: JsValue,
    },
    GrantFeedAccess {
        key: JsString,
    },
    HasFeedGrant {
        key: JsString,
    },
    AssertFeedGrantable {
        key: JsString,
    },
    EthereumWalletReferences {
        wallet_index: JsValue,
    },
}

/// Main's own ops' names, forbidden to the chrome on their name alone
/// ([`super::Call::parse`]).
pub(crate) const MAIN_OPS: [&str; 9] = [
    "getOriginIdentityStateWithOwners",
    "previewAppScopedIdentity",
    "createAppScopedIdentityAt",
    "ensureAntWalletIdentity",
    "activateIdentity",
    "grantFeedAccess",
    "hasFeedGrant",
    "assertFeedGrantable",
    "getEthereumWalletIdentityReferences",
];

impl Op {
    pub(crate) fn parse(op: String, m: Members) -> Result<Op, Refused> {
        let only = |allowed: &[&str]| m.only(&op, allowed);
        Ok(match op.as_str() {
            "get-all-origins" => {
                only(&[])?;
                Op::GetAllOrigins
            }
            "has-feed-identity" => {
                only(&["origin"])?;
                Op::HasFeedIdentity {
                    origin: m.string("origin")?,
                }
            }
            "get-identity-mode" => {
                only(&["origin"])?;
                Op::GetIdentityMode {
                    origin: m.string("origin")?,
                }
            }
            "get-origin-identities" => {
                only(&["origin"])?;
                Op::GetOriginIdentities {
                    origin: m.string("origin")?,
                }
            }
            "create-app-scoped-identity" => {
                only(&["origin", "options"])?;
                Op::CreateAppScopedIdentity {
                    origin: m.string("origin")?,
                    options: m.js("options")?,
                }
            }
            "ensure-ant-wallet-identity" => {
                only(&["origin", "options"])?;
                Op::EnsureAntWalletIdentity {
                    origin: m.string("origin")?,
                    options: m.js("options")?,
                }
            }
            "activate-feed-identity" => {
                only(&["origin", "identity_id"])?;
                Op::ActivateFeedIdentity {
                    origin: m.string("origin")?,
                    identity_id: m.js("identity_id")?,
                }
            }
            "set-feed-identity" => {
                only(&[])?;
                Op::SetFeedIdentity
            }
            "revoke-feed-access" => {
                only(&["origin"])?;
                Op::RevokeFeedAccess {
                    origin: m.string("origin")?,
                }
            }
            "getOriginIdentityStateWithOwners" => {
                only(&["key"])?;
                Op::StateWithOwners {
                    key: m.string("key")?,
                }
            }
            "previewAppScopedIdentity" => {
                only(&["key", "options"])?;
                Op::Preview {
                    key: m.string("key")?,
                    options: m.js("options")?,
                }
            }
            "createAppScopedIdentityAt" => {
                only(&["key", "index", "options"])?;
                Op::CreateAt {
                    key: m.string("key")?,
                    index: m.js("index")?,
                    options: m.js("options")?,
                }
            }
            "ensureAntWalletIdentity" => {
                only(&["key", "options"])?;
                Op::Ensure {
                    key: m.string("key")?,
                    options: m.js("options")?,
                }
            }
            "activateIdentity" => {
                only(&["key", "identity_id"])?;
                Op::Activate {
                    key: m.string("key")?,
                    identity_id: m.js("identity_id")?,
                }
            }
            "grantFeedAccess" => {
                only(&["key"])?;
                Op::GrantFeedAccess {
                    key: m.string("key")?,
                }
            }
            "hasFeedGrant" => {
                only(&["key"])?;
                Op::HasFeedGrant {
                    key: m.string("key")?,
                }
            }
            "assertFeedGrantable" => {
                only(&["key"])?;
                Op::AssertFeedGrantable {
                    key: m.string("key")?,
                }
            }
            "getEthereumWalletIdentityReferences" => {
                only(&["wallet_index"])?;
                Op::EthereumWalletReferences {
                    wallet_index: m.js("wallet_index")?,
                }
            }
            other => return Err(invalid(format!("swarm.identities has no op {other}"))),
        })
    }

    /// Whether it reads owners from the vault, and so takes a place in the
    /// swarm thread's admission (design 0015, Budgets).
    pub fn reads_owners(&self) -> bool {
        matches!(
            self,
            Op::GetOriginIdentities { .. }
                | Op::CreateAppScopedIdentity { .. }
                | Op::EnsureAntWalletIdentity { .. }
                | Op::ActivateFeedIdentity { .. }
                | Op::StateWithOwners { .. }
                | Op::Preview { .. }
        )
    }

    /// The site it changes or reads.
    fn key(&self) -> Option<&JsString> {
        match self {
            Op::GetAllOrigins | Op::SetFeedIdentity | Op::EthereumWalletReferences { .. } => None,
            Op::HasFeedIdentity { origin }
            | Op::GetIdentityMode { origin }
            | Op::GetOriginIdentities { origin }
            | Op::CreateAppScopedIdentity { origin, .. }
            | Op::EnsureAntWalletIdentity { origin, .. }
            | Op::ActivateFeedIdentity { origin, .. }
            | Op::RevokeFeedAccess { origin } => Some(origin),
            Op::StateWithOwners { key }
            | Op::Preview { key, .. }
            | Op::CreateAt { key, .. }
            | Op::Ensure { key, .. }
            | Op::Activate { key, .. }
            | Op::GrantFeedAccess { key }
            | Op::HasFeedGrant { key }
            | Op::AssertFeedGrantable { key } => Some(key),
        }
    }

    /// The change it makes, if it makes one.
    fn change(&self) -> Option<FeedChange> {
        let user = Source::User;
        Some(match self {
            // The handlers' `{ ...options, source: 'user' }`.
            Op::CreateAppScopedIdentity { origin, options } => {
                FeedChange::CreateAppScopedIdentity {
                    key: origin.clone(),
                    options: spread(options),
                    source: user,
                }
            }
            Op::EnsureAntWalletIdentity { origin, options } => {
                FeedChange::EnsureAntWalletIdentity {
                    key: origin.clone(),
                    options: spread(options),
                    source: user,
                }
            }
            Op::ActivateFeedIdentity {
                origin,
                identity_id,
            } => FeedChange::ActivateIdentity {
                key: origin.clone(),
                identity_id: identity_id.clone(),
                source: user,
            },
            Op::RevokeFeedAccess { origin } => FeedChange::RevokeFeedAccess {
                key: origin.clone(),
                source: user,
            },
            Op::CreateAt {
                key,
                index,
                options,
            } => FeedChange::CreateAppScopedIdentityAt {
                key: key.clone(),
                index: index.clone(),
                options: options.clone(),
                source: user,
            },
            Op::Ensure { key, options } => FeedChange::EnsureAntWalletIdentity {
                key: key.clone(),
                options: options.clone(),
                source: user,
            },
            Op::Activate { key, identity_id } => FeedChange::ActivateIdentity {
                key: key.clone(),
                identity_id: identity_id.clone(),
                source: user,
            },
            Op::GrantFeedAccess { key } => FeedChange::GrantFeedAccess {
                key: key.clone(),
                source: user,
            },
            _ => return None,
        })
    }

    /// The answer that needs owners, read from `store` with `owners`.
    fn read_with_owners(
        &self,
        store: &FeedStore,
        now_ms: u64,
        owners: &mut impl Owners,
    ) -> Result<JsValue, Thrown> {
        match self {
            Op::Preview { key, options } => {
                store.preview_app_scoped_identity(key, options, now_ms, owners)
            }
            _ => match self.key() {
                Some(key) => store.origin_identity_state_with_owners(key, owners),
                None => Err(Thrown::error("Internal error")),
            },
        }
    }

    /// The answer read from the store alone. The references come as the
    /// typed value the op answers with, made once within their bound.
    fn read(&self, store: &FeedStore) -> Option<Result<Value, Thrown>> {
        if let Op::EthereumWalletReferences { wallet_index } = self {
            return Some(store.ethereum_wallet_identity_references(wallet_index));
        }
        let read = match self {
            Op::GetAllOrigins => store.all_origin_entries().map(JsValue::Array),
            Op::HasFeedIdentity { origin } => Ok(JsValue::Bool(store.has_identity_mode(origin))),
            Op::GetIdentityMode { origin } => Ok(store
                .origin_entry(origin)
                .and_then(|entry| entry.get("identityMode").filter(|m| m.truthy()).cloned())
                .unwrap_or(JsValue::Null)),
            Op::SetFeedIdentity => Err(Thrown::error(FEED_GRANT_REFUSED)),
            Op::HasFeedGrant { key } => Ok(JsValue::Bool(store.has_feed_grant(key))),
            Op::AssertFeedGrantable { key } => store
                .assert_feed_grantable(key)
                .map(|()| JsValue::Undefined),
            _ => return None,
        };
        Some(read.map(|value| Value::from_js(&value)))
    }
}

/// An owner the vault answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerKey {
    Key(SignKey),
    Accounts,
}

impl OwnerKey {
    fn need(self) -> Need {
        match self {
            OwnerKey::Key(key) => Need::Owner(key),
            OwnerKey::Accounts => Need::Accounts,
        }
    }

    /// The vault's key for publisher index `index` (a non-negative
    /// integer: the store refuses any other before it asks). One past
    /// BIP-32's hardened range is the vault's to refuse; one past u32
    /// reaches it as `u32::MAX`, refused the same way.
    fn publisher(index: f64) -> OwnerKey {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a non-negative integer, saturated"
        )]
        let index = index as u64;
        OwnerKey::Key(SignKey::Publisher(u32::try_from(index).unwrap_or(u32::MAX)))
    }
}

/// The vault's answer for an owner.
#[derive(Debug, Clone, PartialEq)]
enum OwnerAnswer {
    Owner(Result<Option<[u8; 20]>, JsString>),
    Accounts(Result<Vec<JsValue>, JsString>),
}

/// A running `swarm.identities` op.
#[derive(Debug, Clone)]
pub(crate) struct Run {
    op: Op,
    phase: Phase,
}

#[derive(Debug, Clone)]
enum Phase {
    Start,
    /// Its change waits for SW-1's hold.
    Change,
    /// The owners asked and answered so far.
    Owners {
        asked: Vec<(AskId, OwnerKey)>,
        answers: Vec<(OwnerKey, OwnerAnswer)>,
    },
}

impl Run {
    pub(crate) fn new(op: Op) -> Run {
        Run {
            op,
            phase: Phase::Start,
        }
    }

    pub(crate) fn start(&mut self, cx: &mut Cx<'_>, stores: &mut Stores<'_>) -> Step {
        if !matches!(self.phase, Phase::Start) {
            return Step::Ended;
        }
        if let Some(answer) = self.op.read(stores.keeper.store()) {
            return Step::Done(match answer {
                Ok(value) => Outcome::Result(value),
                Err(thrown) => Outcome::Thrown(thrown),
            });
        }
        if let Some(change) = self.op.change() {
            let io = &mut *stores.io;
            let mut write = |text: &str| io.write_feeds(text);
            return match stores
                .keeper
                .change(cx.ticket, change, stores.now_ms, &mut write)
            {
                Ran::Applied(answer) => self.changed_now(cx, answer, stores),
                Ran::Deferred => {
                    self.phase = Phase::Change;
                    Step::Wait(Waiting::Change)
                }
            };
        }
        self.owners(cx, stores)
    }

    /// What it waits for: a hold's end doesn't move it (its change, if
    /// deferred, comes back through [`Run::changed`]).
    pub(crate) fn waiting(&self) -> Step {
        match self.phase {
            Phase::Start => Step::Ended,
            Phase::Change => Step::Wait(Waiting::Change),
            Phase::Owners { .. } => Step::Wait(Waiting::Answers),
        }
    }

    pub(crate) fn changed(
        &mut self,
        cx: &mut Cx<'_>,
        answer: Result<ChangeAnswer, ChangeError>,
        stores: &mut Stores<'_>,
    ) -> Step {
        if !matches!(self.phase, Phase::Change) {
            return Step::Ended;
        }
        self.changed_now(cx, answer, stores)
    }

    /// Its change made, or refused.
    fn changed_now(
        &mut self,
        cx: &mut Cx<'_>,
        answer: Result<ChangeAnswer, ChangeError>,
        stores: &mut Stores<'_>,
    ) -> Step {
        let answer = match answer {
            Ok(answer) => answer,
            Err(error) => return Step::Done(Outcome::Thrown(change_thrown(error))),
        };
        if let (Some(projection), Some(key)) = (answer.detach, self.op.key()) {
            super::manifest::detach(stores, key, projection);
        }
        match &self.op {
            Op::CreateAppScopedIdentity { .. }
            | Op::EnsureAntWalletIdentity { .. }
            | Op::ActivateFeedIdentity { .. } => self.owners(cx, stores),
            Op::RevokeFeedAccess { .. } => done(Ok(JsValue::Bool(true))),
            _ => done(Ok(answer.value)),
        }
    }

    pub(crate) fn answer(
        &mut self,
        cx: &mut Cx<'_>,
        ask: AskId,
        event: Event,
        stores: &mut Stores<'_>,
    ) -> Step {
        let Phase::Owners { asked, answers } = &mut self.phase else {
            return Step::Ended;
        };
        let Some(at) = asked.iter().position(|(id, _)| *id == ask) else {
            return Step::Wait(Waiting::Answers);
        };
        let (_, key) = asked.remove(at);
        let answer = match (key, event) {
            (OwnerKey::Key(_), Event::Owner(owner)) => OwnerAnswer::Owner(owner),
            (OwnerKey::Accounts, Event::Accounts(accounts)) => OwnerAnswer::Accounts(accounts),
            // An answer of another kind: the swarm thread's mistake.
            _ => return done(Err(Thrown::error("Internal error"))),
        };
        answers.push((key, answer));
        if !asked.is_empty() {
            return Step::Wait(Waiting::Answers);
        }
        self.owners(cx, stores)
    }

    /// The answer from the owners answered so far, or the owners still
    /// needed, asked.
    fn owners(&mut self, cx: &mut Cx<'_>, stores: &mut Stores<'_>) -> Step {
        if !matches!(self.phase, Phase::Owners { .. }) {
            self.phase = Phase::Owners {
                asked: Vec::new(),
                answers: Vec::new(),
            };
        }
        let Phase::Owners { asked, answers } = &mut self.phase else {
            return Step::Ended;
        };
        let store = stores.keeper.store();
        let mut served = Served {
            answers,
            missing: Vec::new(),
        };
        let answer = self.op.read_with_owners(store, stores.now_ms, &mut served);
        if served.missing.is_empty() {
            return done(answer);
        }
        // Every owner the list needs, so they go together: the first that
        // was missing, then the rest in the reference's order.
        let mut needed = served.missing;
        let mut all = Recorded::default();
        let _ = self.op.read_with_owners(store, stores.now_ms, &mut all);
        for key in all.keys {
            if !needed.contains(&key) {
                needed.push(key);
            }
        }
        needed.retain(|key| {
            !answers.iter().any(|(k, _)| k == key) && !asked.iter().any(|(_, k)| k == key)
        });
        if needed.is_empty() {
            return Step::Wait(Waiting::Answers);
        }
        let asks: Vec<Ask> = needed
            .into_iter()
            .map(|key| {
                let ask = cx.ask(key.need());
                asked.push((ask.id, key));
                ask
            })
            .collect();
        Step::Asks(asks)
    }
}

fn done(answer: Result<JsValue, Thrown>) -> Step {
    Step::Done(match answer {
        Ok(value) => Outcome::Result(Value::from_js(&value)),
        Err(thrown) => Outcome::Thrown(thrown),
    })
}

/// What a read throws where an owner isn't answered yet; the read's answer
/// is then dropped.
fn unanswered() -> Thrown {
    Thrown::error("an owner isn't answered yet")
}

/// Owners from the vault's answers, noting the first one missing.
struct Served<'a> {
    answers: &'a [(OwnerKey, OwnerAnswer)],
    missing: Vec<OwnerKey>,
}

impl Served<'_> {
    fn find(&self, key: OwnerKey) -> Option<&OwnerAnswer> {
        self.answers.iter().find(|(k, _)| *k == key).map(|(_, a)| a)
    }

    fn owner(&mut self, key: OwnerKey) -> Result<Option<String>, Thrown> {
        match self.find(key) {
            Some(OwnerAnswer::Owner(Ok(owner))) => Ok(owner.as_ref().map(fc_evm::checksum_address)),
            Some(OwnerAnswer::Owner(Err(text))) => Err(Thrown::error(text.as_str())),
            _ => {
                self.missing.push(key);
                Err(unanswered())
            }
        }
    }
}

impl Owners for Served<'_> {
    fn bee_wallet(&mut self) -> Result<Option<String>, Thrown> {
        self.owner(OwnerKey::Key(SignKey::BeeWallet))
    }

    fn publisher(&mut self, index: f64) -> Result<Option<String>, Thrown> {
        self.owner(OwnerKey::publisher(index))
    }

    fn wallets(&mut self) -> Result<Vec<JsValue>, Thrown> {
        match self.find(OwnerKey::Accounts) {
            Some(OwnerAnswer::Accounts(Ok(accounts))) => Ok(accounts.clone()),
            Some(OwnerAnswer::Accounts(Err(text))) => Err(Thrown::error(text.as_str())),
            _ => {
                self.missing.push(OwnerKey::Accounts);
                Err(unanswered())
            }
        }
    }
}

/// Every owner a read asks for, each answered as unlocked, in order.
#[derive(Default)]
struct Recorded {
    keys: Vec<OwnerKey>,
}

impl Recorded {
    fn note(&mut self, key: OwnerKey) {
        if !self.keys.contains(&key) {
            self.keys.push(key);
        }
    }
}

impl Owners for Recorded {
    fn bee_wallet(&mut self) -> Result<Option<String>, Thrown> {
        self.note(OwnerKey::Key(SignKey::BeeWallet));
        Ok(Some(fc_evm::checksum_address(&[0; 20])))
    }

    fn publisher(&mut self, index: f64) -> Result<Option<String>, Thrown> {
        self.note(OwnerKey::publisher(index));
        Ok(Some(fc_evm::checksum_address(&[0; 20])))
    }

    fn wallets(&mut self) -> Result<Vec<JsValue>, Thrown> {
        self.note(OwnerKey::Accounts);
        Ok(Vec::new())
    }
}
