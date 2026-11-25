//! `swarm.manifest` (design 0015, "Methods main calls"; SWM-4's D6):
//! `permission-manifests.js`'s page path, which main runs for a page's
//! request, and the chrome's three IPC handlers, which main proxies.
//!
//! | op | params | answer |
//! |---|---|---|
//! | `check` | `key`, `url`, `eager?` | `checkPageManifest({ key, url, eager })`: `legacy`, `unresolved`, `ready`, or a consent with its token and model |
//! | `decide` | `key`, `token`, `outcome`, `live` | `decidePageManifest(key, token, outcome, guard)`: `{ allowed, mode }`, or `{ refused: true }` |
//! | `release` | `token` | `releasePageManifest(token)`: `undefined` |
//! | `get` | `origin` | `getRecord(origin)` (`swarm:manifest-get`) |
//! | `use-individual` | `origin`, `capability?` | `useIndividual(origin, capability)` (`swarm:manifest-use-individual`) |
//! | `disconnect` | `origin` | `disconnect(origin)` (`swarm:manifest-disconnect`) |
//!
//! The design's table names `check`, `decide`, `list` and `revoke`; the
//! reference has no list or revoke, so the ops are its own functions: the
//! three its page path calls and the three its IPC handlers do.
//!
//! - **`check`** runs the legacy and backoff checks, then asks main for the
//!   manifest at the committed URL's `bzz:` address (D6's
//!   `shell.swarm_manifest`, [`super::Need::Manifest`]), and decides from
//!   the bytes main fetched. Its consent is main's own (`owner: 'page'`):
//!   single-use, never shared, at most 64 waiting. The window checks the
//!   reference makes first (`manifestFetchContext`, `stillAsking`) are
//!   main's, before it calls.
//! - **`decide`**: the token must be a page consent waiting for `key`
//!   (else `Manifest consent expired`); then `live`, main's answer to the
//!   reference's guard (the name still binds and the document still holds
//!   its key: `recheck()` and `holds()`), which main reads just before it
//!   calls, as the reference reads it just before its decision: `false`
//!   spends the consent and answers `{ refused: true }` with nothing
//!   written. Both come before the store is read, so they answer as the
//!   reference's do even while the file and its `.bak` can't be read.
//!
//! **SW-1's hold.** A transaction that would revoke a held site's feed
//! grant (a disconnect, a capability handed back, a manifest gone, or a
//! journal replayed) waits, whole, until no hold defers that revoke: the op
//! is tried first on a copy of the store, its effects recorded and none
//! made, and runs only once none would be deferred. With no hold standing,
//! nothing is tried.

use fc_json::{JsString, JsValue};

use super::{
    Cx, Event, Fetch, Grants, Io, Members, Need, Outcome, Refused, STORE_FULL, Step, Stores,
    Waiting, invalid,
};
use crate::machine::keeper::{ChangeError, Keeper, Ran, STORE_FULL_MESSAGE, Ticket};
use crate::stores::feeds::{FeedChange, FeedStore, Source};
use crate::stores::manifests::{
    self, CheckStep, Effect, Fetched, ManifestError, ManifestFetch, ManifestStore, Owner,
    Projection, Unreadable,
};
use crate::stores::{StoreError, Thrown};
use crate::value::Value;

/// What a write past the manifest store's bound throws (design 0015,
/// Budgets: `store_full`).
pub const MANIFESTS_FULL_MESSAGE: &str = "Swarm manifest store is full";

/// A `swarm.manifest` op.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Check {
        key: JsString,
        url: JsString,
        eager: bool,
    },
    Decide {
        key: JsString,
        token: JsString,
        outcome: JsString,
        live: bool,
    },
    Release {
        token: JsString,
    },
    Get {
        origin: JsString,
    },
    UseIndividual {
        origin: JsString,
        capability: JsValue,
    },
    Disconnect {
        origin: JsString,
    },
}

impl Op {
    pub(crate) fn parse(op: String, m: Members) -> Result<Op, Refused> {
        let only = |allowed: &[&str]| m.only(&op, allowed);
        Ok(match op.as_str() {
            "check" => {
                only(&["key", "url", "eager"])?;
                Op::Check {
                    key: m.string("key")?,
                    url: m.string("url")?,
                    eager: m.boolean("eager", Some(false))?,
                }
            }
            "decide" => {
                only(&["key", "token", "outcome", "live"])?;
                Op::Decide {
                    key: m.string("key")?,
                    token: m.string("token")?,
                    outcome: m.string("outcome")?,
                    live: m.boolean("live", None)?,
                }
            }
            "release" => {
                only(&["token"])?;
                Op::Release {
                    token: m.string("token")?,
                }
            }
            "get" => {
                only(&["origin"])?;
                Op::Get {
                    origin: m.string("origin")?,
                }
            }
            "use-individual" => {
                only(&["origin", "capability"])?;
                Op::UseIndividual {
                    origin: m.string("origin")?,
                    capability: m.js("capability")?,
                }
            }
            "disconnect" => {
                only(&["origin"])?;
                Op::Disconnect {
                    origin: m.string("origin")?,
                }
            }
            other => return Err(invalid(format!("swarm.manifest has no op {other}"))),
        })
    }
}

/// A running `swarm.manifest` op.
#[derive(Debug, Clone)]
pub(crate) struct Run {
    op: Op,
    phase: Phase,
}

#[derive(Debug, Clone)]
enum Phase {
    Start,
    /// Its checks passed: it runs once no hold defers its transaction.
    Ready,
    /// A check waits for main's fetch.
    Fetching {
        ask: super::AskId,
        fetch: ManifestFetch,
    },
    /// A check has its manifest, and runs once no hold defers what it
    /// decides.
    Fetched {
        fetch: ManifestFetch,
        fetched: Fetch,
    },
}

/// What an op made before any fetch.
enum Made {
    Value(JsValue),
    Fetch(ManifestFetch),
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
        if let Op::Release { token } = &self.op {
            stores.manifests.release_page_token(token.as_str());
            return done(Ok(JsValue::Undefined));
        }
        // `decidePageManifest`'s checks come before any read of the store:
        // the consents live in memory, as the reference's do.
        if let Op::Decide {
            key, token, live, ..
        } = &self.op
        {
            if !stores
                .manifests
                .page_token_is_for(token.as_str(), key, stores.now_ms)
            {
                return done(Err(Thrown::error("Manifest consent expired")));
            }
            if !live {
                stores.manifests.release_page_token(token.as_str());
                let mut refused = JsValue::Object(Vec::new());
                refused.set("refused", JsValue::Bool(true));
                return done(Ok(refused));
            }
        }
        self.phase = Phase::Ready;
        self.ready(cx, stores)
    }

    pub(crate) fn answer(
        &mut self,
        _cx: &mut Cx<'_>,
        ask: super::AskId,
        event: Event,
        stores: &mut Stores<'_>,
    ) -> Step {
        let Phase::Fetching { ask: asked, fetch } = &self.phase else {
            return Step::Ended;
        };
        if *asked != ask {
            return Step::Wait(Waiting::Answers);
        }
        let Event::Manifest(fetched) = event else {
            // An answer of another kind: the swarm thread's mistake.
            return done(Err(Thrown::error("Internal error")));
        };
        self.phase = Phase::Fetched {
            fetch: fetch.clone(),
            fetched,
        };
        self.concluded(stores)
    }

    pub(crate) fn retry(&mut self, cx: &mut Cx<'_>, stores: &mut Stores<'_>) -> Step {
        match self.phase {
            Phase::Ready => self.ready(cx, stores),
            Phase::Fetched { .. } => self.concluded(stores),
            Phase::Fetching { .. } => Step::Wait(Waiting::Answers),
            Phase::Start => Step::Ended,
        }
    }

    /// The op, once no hold defers it.
    fn ready(&mut self, cx: &mut Cx<'_>, stores: &mut Stores<'_>) -> Step {
        if let Err(thrown) = ensure_loaded(stores) {
            return Step::Done(Outcome::Thrown(thrown));
        }
        let op = &self.op;
        let now_ms = stores.now_ms;
        if held(stores, |store, probe| {
            let _ = made(op, store, probe, now_ms);
        }) {
            return Step::Wait(Waiting::Hold);
        }
        let (store, mut world) = split(stores);
        match made(op, store, &mut world, now_ms) {
            Ok(Made::Value(value)) => done(Ok(value)),
            Ok(Made::Fetch(fetch)) => {
                let ask = cx.ask(Need::Manifest {
                    url: fetch.url.clone(),
                });
                self.phase = Phase::Fetching { ask: ask.id, fetch };
                Step::Asks(vec![ask])
            }
            Err(error) => done(Err(thrown(error))),
        }
    }

    /// A check's decision on the manifest main fetched, once no hold
    /// defers it.
    fn concluded(&mut self, stores: &mut Stores<'_>) -> Step {
        let Phase::Fetched { fetch, fetched } = &self.phase else {
            return Step::Ended;
        };
        if let Err(thrown) = ensure_loaded(stores) {
            return Step::Done(Outcome::Thrown(thrown));
        }
        let now_ms = stores.now_ms;
        if held(stores, |store, probe| {
            let _ = store.check_fetched(fetch.clone(), fetched_of(fetched), probe, now_ms, || {
                [0; 24]
            });
        }) {
            return Step::Wait(Waiting::Hold);
        }
        let random = stores.io.random();
        let (store, mut world) = split(stores);
        let answer = store.check_fetched(
            fetch.clone(),
            fetched_of(fetched),
            &mut world,
            now_ms,
            || random,
        );
        done(answer.map_err(thrown))
    }
}

/// The op on `store`, through `world`, up to a check's fetch.
fn made<W: manifests::World<Error = WorldError>>(
    op: &Op,
    store: &mut ManifestStore,
    world: &mut W,
    now_ms: u64,
) -> Result<Made, ManifestError<WorldError>> {
    let value = match op {
        Op::Check { key, url, eager } => {
            return match store.check(key, url.as_str(), *eager, Owner::Page, world, now_ms)? {
                CheckStep::Done(value) => Ok(Made::Value(value)),
                CheckStep::Fetch(fetch) => Ok(Made::Fetch(fetch)),
            };
        }
        Op::Decide { token, outcome, .. } => {
            store.decide(token.as_str(), outcome.as_str(), Owner::Page, world, now_ms)?
        }
        Op::Get { origin } => store.get_record(origin, world)?,
        Op::UseIndividual { origin, capability } => {
            JsValue::Bool(store.use_individual(origin, capability, world, now_ms)?)
        }
        Op::Disconnect { origin } => JsValue::Bool(store.disconnect(origin, world)?),
        Op::Release { token } => {
            store.release_page_token(token.as_str());
            JsValue::Undefined
        }
    };
    Ok(Made::Value(value))
}

fn fetched_of(fetch: &Fetch) -> Fetched<'_> {
    match fetch {
        Fetch::Failed => Fetched::Failed,
        Fetch::Answered { status, body } => Fetched::Answered {
            status: *status,
            body,
        },
    }
}

fn done(answer: Result<JsValue, Thrown>) -> Step {
    Step::Done(match answer {
        Ok(value) => Outcome::Result(Value::from_js(&value)),
        Err(thrown) => Outcome::Thrown(thrown),
    })
}

/// The store loaded, as `loadStore()` loads it at each operation while
/// nothing is: the file, or where it isn't readable its `.bak` copy.
fn ensure_loaded(stores: &mut Stores<'_>) -> Result<(), Thrown> {
    if stores.manifests.is_loaded() {
        return Ok(());
    }
    let file = stores.io.read_manifests();
    let io = &mut *stores.io;
    stores
        .manifests
        .load(file.as_deref(), || io.read_manifests_backup())
        .map_err(|Unreadable| Thrown::error(Unreadable.to_string()))
}

/// The user changed a projection a manifest manages (the feed store's
/// report, `detachManagedLater`): the record lets go of it. Like the
/// reference's, it doesn't fail its caller: a store that can't be read or
/// written keeps its record.
pub(crate) fn detach(stores: &mut Stores<'_>, key: &JsString, projection: Projection) {
    if ensure_loaded(stores).is_err() {
        return;
    }
    let (store, mut world) = split(stores);
    let _ = store.detach_managed(key, projection, &mut world);
}

/// What a manifest change's world fails with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WorldError {
    /// A write's text: the file's, a grant's or the feed store's.
    Write(JsString),
    /// The feed store would pass its bound.
    FeedsFull,
    /// SW-1's hold defers the feed-store change: never made, since the op
    /// waited for no hold to defer it.
    Held,
}

/// A manifest error as the caller reads it.
fn thrown(error: ManifestError<WorldError>) -> Thrown {
    match error {
        ManifestError::Thrown(thrown) => thrown,
        ManifestError::Full => Thrown::coded(MANIFESTS_FULL_MESSAGE, STORE_FULL),
        ManifestError::NotLoaded => Thrown::error(Unreadable.to_string()),
        ManifestError::World(WorldError::Write(text)) => Thrown::error(text.as_str()),
        ManifestError::World(WorldError::FeedsFull) => {
            Thrown::coded(STORE_FULL_MESSAGE, STORE_FULL)
        }
        ManifestError::World(WorldError::Held) => Thrown::error("Internal error"),
    }
}

/// A projection's feed-store change, if it is one: the manifest's own
/// (`source: 'manifest'`), which reports nothing back.
fn feed_change(key: &JsString, effect: Effect) -> Option<FeedChange> {
    let key = key.clone();
    let source = Source::Manifest;
    match effect {
        Effect::FeedGrant(true) => Some(FeedChange::GrantFeedAccess { key, source }),
        Effect::FeedGrant(false) => Some(FeedChange::RevokeFeedAccess { key, source }),
        Effect::CreateIdentity => {
            let mut options = JsValue::Object(Vec::new());
            options.set("activate", JsValue::Bool(true));
            Some(FeedChange::CreateAppScopedIdentity {
                key,
                options,
                source,
            })
        }
        Effect::Connect | Effect::Disconnect | Effect::Flag { .. } | Effect::Messaging(_) => None,
    }
}

/// The manifest store, and its world over the swarm thread's other stores.
fn split<'s>(stores: &'s mut Stores<'_>) -> (&'s mut ManifestStore, World<'s>) {
    (
        &mut *stores.manifests,
        World {
            now_ms: stores.now_ms,
            keeper: &mut *stores.keeper,
            grants: &mut *stores.grants,
            io: &mut *stores.io,
        },
    )
}

/// A manifest change's world: the Swarm grants, and the feed store through
/// SW-1's keeper, each written as it changes.
struct World<'s> {
    now_ms: u64,
    keeper: &'s mut Keeper,
    grants: &'s mut dyn Grants,
    io: &'s mut dyn Io,
}

impl manifests::Reads for World<'_> {
    fn connected(&self, key: &JsString) -> bool {
        self.grants.connected(key)
    }

    fn messaging(&self, key: &JsString) -> bool {
        self.grants.messaging(key)
    }

    fn auto_approve(&self, key: &JsString, capability: manifests::Capability) -> bool {
        self.grants.auto_approve(key, capability)
    }

    fn feeds(&self) -> &FeedStore {
        self.keeper.store()
    }
}

impl manifests::World for World<'_> {
    type Error = WorldError;

    fn apply(&mut self, key: &JsString, effect: Effect) -> Result<(), ManifestError<WorldError>> {
        let Some(change) = feed_change(key, effect) else {
            return self
                .grants
                .apply(key, effect)
                .map_err(|text| ManifestError::World(WorldError::Write(text)));
        };
        if self.keeper.defers(&change) {
            return Err(ManifestError::World(WorldError::Held));
        }
        let io = &mut *self.io;
        let mut write = |text: &str| io.write_feeds(text);
        // Not deferred, so made now: the ticket names no caller.
        match self
            .keeper
            .change(Ticket(u64::MAX), change, self.now_ms, &mut write)
        {
            Ran::Applied(Ok(_)) => Ok(()),
            Ran::Applied(Err(ChangeError::Store(StoreError::Thrown(thrown)))) => {
                Err(ManifestError::Thrown(thrown))
            }
            Ran::Applied(Err(ChangeError::Store(StoreError::Full))) => {
                Err(ManifestError::World(WorldError::FeedsFull))
            }
            Ran::Applied(Err(ChangeError::Write(text))) => {
                Err(ManifestError::World(WorldError::Write(text)))
            }
            Ran::Deferred => Err(ManifestError::World(WorldError::Held)),
        }
    }

    fn save(&mut self, save: &manifests::Save) -> Result<(), WorldError> {
        self.io.save_manifests(save).map_err(WorldError::Write)
    }
}

/// Whether SW-1's hold would defer a feed-store change `run` makes: `run`
/// on a copy of the manifest store, through a world that records the
/// changes and makes none. Nothing is tried while no hold stands.
fn held(stores: &Stores<'_>, run: impl FnOnce(&mut ManifestStore, &mut Probe<'_>)) -> bool {
    if stores.keeper.holds() == 0 {
        return false;
    }
    let mut copy = stores.manifests.clone();
    let mut probe = Probe {
        keeper: &*stores.keeper,
        grants: &*stores.grants,
        held: false,
    };
    run(&mut copy, &mut probe);
    probe.held
}

/// The world of a try: the stores as they stand, read; each effect noted
/// and none made; the first feed-store change the hold defers stops it.
struct Probe<'s> {
    keeper: &'s Keeper,
    grants: &'s dyn Grants,
    held: bool,
}

impl manifests::Reads for Probe<'_> {
    fn connected(&self, key: &JsString) -> bool {
        self.grants.connected(key)
    }

    fn messaging(&self, key: &JsString) -> bool {
        self.grants.messaging(key)
    }

    fn auto_approve(&self, key: &JsString, capability: manifests::Capability) -> bool {
        self.grants.auto_approve(key, capability)
    }

    fn feeds(&self) -> &FeedStore {
        self.keeper.store()
    }
}

impl manifests::World for Probe<'_> {
    type Error = WorldError;

    fn apply(&mut self, key: &JsString, effect: Effect) -> Result<(), ManifestError<WorldError>> {
        if feed_change(key, effect).is_some_and(|change| self.keeper.defers(&change)) {
            self.held = true;
            return Err(ManifestError::World(WorldError::Held));
        }
        Ok(())
    }

    fn save(&mut self, _: &manifests::Save) -> Result<(), WorldError> {
        Ok(())
    }
}
