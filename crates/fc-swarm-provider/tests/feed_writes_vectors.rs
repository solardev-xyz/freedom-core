//! The feed and SOC writes against vectors/swarm.json (design 0015, SWM-3
//! part 3c): every `methods` case of `createFeed`, `updateFeed`,
//! `writeFeedEntry`, `writeSingleOwnerChunk` and `getSigningIdentity` but
//! the ones [`LEFT_OUT`] names; the `stamps` and `errors` cases these
//! machines reach (a feed write's batch choice, the SOC upload's error
//! texts, a bee-js upload's and an explicit index's); and SW-1's
//! interleaving gate on the machine.
//!
//! **What the core sees.** Each step went through main's page dispatcher,
//! which recorded what it handed the service (`service`: the key and how
//! main approved it). Before the hand-off main made its own writes, which
//! the core makes for it from SWM-6 on (`swarm.identities`): a feed
//! prompt's pick of identity and the feed grant (`grantFeedIdentity`), an
//! "always allow" rule, an unlock; then the case's `at_execute` changes
//! (the vault locked, the feed grant or the connection revoked). The test
//! replays them on the core's store, through SW-1's keeper, as the swarm
//! thread will.
//!
//! **Main, the vault and the node.** A scripted swarm thread answers the
//! core's asks: the publish readiness from the case; the vault's owners and
//! signatures from keys.json's test keys, refusing while locked; main's
//! recheck before each effect from the case's custody and the node's
//! scripted world changes; the store writes through the keeper and SQLite;
//! a node over the case's declarative `node` (the generator's own answers:
//! rules first, then the probes, the stored chunks and feeds, and the
//! uploads stored as a node stores them), held to main's rules. Upload
//! bodies stream under main's credit, and a part's bytes under the core's.
//!
//! **What is checked,** each step: the result or error (the case's `core`
//! where a deviation changes it); the core's node calls against the
//! grammar's honest scenario for the step, exactly, query, headers and
//! bodies included (the signature in `sig` is the vault's, so the
//! reference's own); the calls against the row's ready check, forms and
//! counts; each call's charge; the signatures the vault made against the
//! step's `sign_soc` events (key, identifier, payload, span, the
//! authorization); one recheck for each `effect` event and one ready check
//! for each `readiness` event. Each case: `swarm-feeds.json`'s text after,
//! and the history's rows (`getEntries()`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use common::*;
use fc_json::index::{Index, Kind, Value as V};
use fc_json::{JsString, JsValue};
use fc_swarm::verify;
use fc_swarm_provider::budgets::ReadBudgets;
use fc_swarm_provider::machine::keeper::{ChangeAnswer, ChangeError, HoldId, Keeper, Ran, Ticket};
use fc_swarm_provider::machine::node::{BodyOut, WINDOW};
use fc_swarm_provider::machine::{
    Approval, Ask, AskId, Body, Call, Effect, Event, Failed, Failure, Form, Need, NodeCall,
    Outcome, Reads, ReadyCheck, Reply, Request, SignKey, SignSoc, Signed, StoreWrite, TagOwners,
    UPLOAD_CHARGE, World, whole_charge,
};
use fc_swarm_provider::stores::feeds::{FeedChange, FeedStore, Source};
use fc_swarm_provider::stores::history::{self, Bind, Cell, Statement};
use fc_swarm_provider::stores::manifests::Capability;
use fc_swarm_provider::value::Value;

/// The methods this part's machines answer.
const FIVE: [&str; 5] = [
    "swarm_createFeed",
    "swarm_updateFeed",
    "swarm_writeFeedEntry",
    "swarm_writeSingleOwnerChunk",
    "swarm_getSigningIdentity",
];

/// Cases of the five methods this test doesn't play, each with why. The
/// test fails on any case of the five it neither plays nor names here.
const LEFT_OUT: &[(&str, &str)] = &[
    (
        "write-feed-explicit-index-timeout",
        "the page gives up as the explicit index's chunk read reaches the node (`abortPage`), and \
         the vector records the reference's -32603 `Request aborted`; that is the page's timer, \
         which the core answers `cancelled` with nothing more asked (deviation `deadlines`), but \
         the case isn't marked with it. `the_page_giving_up_is_a_cancel` plays it as the core's",
    ),
    (
        "write-soc-no-page",
        "`executeSwarmMethod` called with no page (`page: false`) reaches `pageSocSigner`'s refusal \
         after the history row; the core's `swarm.request` is always a page's (0011), so no raw \
         SOC reaches it without one, and main's own SOCs (`swarm.feed`) sign only feed updates \
         under the Bee wallet key",
    ),
];

/// The deviations a case of the five marks, and what the core answers.
fn core_answer(deviation: &str, core: V<'_, '_>) -> Want {
    if let Some(want) = shared_answer(deviation, core) {
        return want;
    }
    let text = string(core);
    match deviation {
        "index-probe" => assert_eq!(
            text,
            "feed_head with swarm-only-root-chunk instead of the whole latest payload; the same index"
        ),
        "feed-wrap-root" => assert!(
            text == "the same index; the SOC wraps the core's own root, with no GET /chunks"
                || text == "the SOC wraps the core's own root, with no GET /chunks",
            "{text}"
        ),
        "stamps-one-read" => assert_eq!(text, "one GET /stamps; the same error"),
        other => panic!("a deviation this part doesn't answer: {other}"),
    }
    Want::Reference
}

// ---------------------------------------------------------------------------
// The world the machines read.

struct WriteWorld {
    now: u64,
    grants: BTreeSet<JsString>,
    /// `(key, capability)` pairs whose auto-approve rule is on.
    rules: BTreeSet<(JsString, String)>,
    keeper: Keeper,
    budgets: ReadBudgets,
    /// Agent custody, as main reads it live.
    custody: bool,
    /// The page's name still answers and its document holds its key.
    live: bool,
    tags: TagOwners,
    /// The effect guards run: each reads the key's binding first.
    guards: std::cell::Cell<usize>,
}

impl Reads for WriteWorld {
    fn connected(&self, key: &JsString) -> bool {
        self.grants.contains(key)
    }
    fn messaging(&self, _key: &JsString) -> bool {
        false
    }
    fn auto_approve(&self, key: &JsString, capability: Capability) -> bool {
        self.rules
            .contains(&(key.clone(), capability.key().to_owned()))
    }
    fn feeds(&self) -> &FeedStore {
        self.keeper.store()
    }
}

impl World for WriteWorld {
    fn now(&self) -> u64 {
        self.now
    }
    fn budgets(&mut self) -> &mut ReadBudgets {
        &mut self.budgets
    }
    fn key_holds(&self, _key: &JsString) -> bool {
        self.guards.set(self.guards.get() + 1);
        self.live
    }
    fn agent(&self, _key: &JsString) -> bool {
        self.custody
    }
    fn tags(&mut self) -> &mut TagOwners {
        &mut self.tags
    }
}

impl WriteWorld {
    fn new(now: u64, feeds: FeedStore) -> WriteWorld {
        WriteWorld {
            now,
            grants: BTreeSet::new(),
            rules: BTreeSet::new(),
            keeper: Keeper::new(feeds),
            budgets: ReadBudgets::new(),
            custody: false,
            live: true,
            tags: TagOwners::new(),
            guards: std::cell::Cell::new(0),
        }
    }

    fn of(case: V<'_, '_>) -> WriteWorld {
        let feeds = case
            .get("feeds")
            .filter(|f| f.kind() == Kind::String)
            .map(string);
        let store = match &feeds {
            Some(text) => FeedStore::load(Some(text.as_bytes()), 0, |_| false).store,
            None => FeedStore::empty(),
        };
        let mut world = WriteWorld::new(number(get(case, "clock")) as u64, store);
        for (key, grant) in get(case, "grants").members() {
            let key = js(key);
            world.grants.insert(key.clone());
            if let Some(rules) = grant.get("autoApprove") {
                for (capability, on) in rules.members() {
                    if on.kind() == Kind::True {
                        world.rules.insert((key.clone(), string(capability)));
                    }
                }
            }
        }
        world
    }
}

// ---------------------------------------------------------------------------
// The vault: keys.json's test keys, counting signatures.

struct Vault<'k> {
    keys: &'k Keys,
    unlocked: bool,
    signed: Vec<SignSoc>,
}

impl Vault<'_> {
    fn key(&self, key: SignKey) -> &k256::ecdsa::SigningKey {
        match key {
            SignKey::BeeWallet => &self.keys.bee,
            SignKey::Publisher(index) => &self.keys.publishers[&u64::from(index)],
        }
    }

    fn owner(&self, key: SignKey) -> Event {
        Event::Owner(Ok(self
            .unlocked
            .then(|| fc_evm::address_of(self.key(key)))))
    }

    fn sign(&mut self, soc: &SignSoc) -> Event {
        if !self.unlocked {
            return Event::Signed(Err(JsString::from("Vault is locked")));
        }
        self.signed.push(soc.clone());
        let signed =
            fc_swarm::sign_soc(self.key(soc.key), &soc.identifier, Some(soc.span), &soc.payload)
                .unwrap();
        Event::Signed(Ok(Signed {
            signature: signed.signature,
            owner: signed.owner,
        }))
    }
}

// ---------------------------------------------------------------------------
// The node: the generator's answers over a case's declarative `node`.

struct WriteRule {
    method: Option<String>,
    path: Option<String>,
    prefix: Option<String>,
    reply: ReplySpec,
    world: Option<(String, String)>,
}

struct Probe {
    owner: [u8; 20],
    topic: [u8; 32],
    head: Option<u64>,
}

/// A change to the world as a request reaches the node (a rule's `world`).
#[derive(Debug, Clone, PartialEq)]
enum WorldChange {
    Custody,
    RuleOff(String),
    NameMoved,
}

struct WriteNode {
    base: Node,
    rules: Vec<WriteRule>,
    stamps: Option<String>,
    probes: Vec<Probe>,
    probe_fail: Option<(u64, u16)>,
    soc_posts: usize,
    bzz_tag: u64,
}

impl WriteNode {
    fn new() -> WriteNode {
        WriteNode {
            base: Node::new(),
            rules: Vec::new(),
            stamps: None,
            probes: Vec::new(),
            probe_fail: None,
            soc_posts: 0,
            bzz_tag: 1,
        }
    }

    fn of(case: V<'_, '_>, keys: &Keys) -> WriteNode {
        let mut node = WriteNode::new();
        for (k, v) in get(case, "node").members() {
            match string(k).as_str() {
                "stamps" => node.stamps = Some(v.stringify(fc_json::index::KeyOrder::Property)),
                "data" => {
                    for d in v.children() {
                        let bytes = data_of(d);
                        let root = tree_of(&bytes, &mut node.base.chunks);
                        node.base.blobs.insert(hex(&root.address()), bytes);
                    }
                }
                "chunks" => {
                    for c in v.children() {
                        node.base
                            .chunks
                            .insert(string(get(c, "address")), data_of(c));
                    }
                }
                "entries" => {
                    for e in v.children() {
                        let key = keys.of(&string(get(e, "key")));
                        let topic = fc_swarm::feed::topic(&string(get(e, "topic")));
                        let id = verify::feed_update_id(&topic, number(get(e, "index")) as u64);
                        let bytes = data_of(get(e, "data"));
                        let (span, payload) =
                            if e.get("wrap").is_some_and(|w| w.kind() == Kind::True) {
                                let root = tree_of(&bytes, &mut node.base.chunks);
                                node.base.blobs.insert(hex(&root.address()), bytes);
                                (root.span(), root.payload().to_vec())
                            } else {
                                (bytes.len() as u64, bytes)
                            };
                        let signed = fc_swarm::sign_soc(key, &id, Some(span), &payload).unwrap();
                        let wire = fc_swarm::soc::body(&id, &signed, &payload).unwrap();
                        node.base.chunks.insert(hex(&signed.soc_address), wire);
                    }
                }
                "latest" => {
                    for l in v.children() {
                        let owner = hex(&fc_evm::address_of(keys.of(&string(get(l, "key")))));
                        let topic = hex(&fc_swarm::feed::topic(&string(get(l, "topic"))));
                        node.base
                            .feeds
                            .insert((owner, topic), ReplySpec::of(get(l, "reply")));
                    }
                }
                "probes" => {
                    for p in v.children() {
                        // Without `head`, the probe table names indexes
                        // only (no update answers from it).
                        let Some(head) = p.get("head") else {
                            continue;
                        };
                        node.probes.push(Probe {
                            owner: fc_evm::address_of(keys.of(&string(get(p, "key")))),
                            topic: fc_swarm::feed::topic(&string(get(p, "topic"))),
                            head: (head.kind() != Kind::Null).then(|| number(head) as u64),
                        });
                    }
                }
                "probeFail" => {
                    node.probe_fail = Some((
                        number(get(v, "index")) as u64,
                        number(get(v, "status")) as u16,
                    ))
                }
                "rules" => {
                    for r in v.children() {
                        assert!(r.get("times").is_none());
                        let m = get(r, "match");
                        let world = r.get("world").map(|w| {
                            let (k, v) = w.members().next().unwrap();
                            let v = match v.kind() {
                                Kind::True => "true".to_owned(),
                                _ => string(v),
                            };
                            (string(k), v)
                        });
                        node.rules.push(WriteRule {
                            method: m.get("method").map(string),
                            path: m.get("path").map(string),
                            prefix: m.get("prefix").map(string),
                            reply: ReplySpec::of(get(r, "reply")),
                            world,
                        });
                    }
                }
                other => panic!("node spec {other:?}"),
            }
        }
        node
    }

    /// The node's reply to `call` (with its request body), and the world
    /// change its rule makes.
    fn reply(&mut self, call: &NodeCall, body: &[u8]) -> (ReplySpec, Option<WorldChange>) {
        let method = call.method();
        let path = call.path.as_str();
        if let Some(rule) = self.rules.iter().find(|r| {
            r.method.as_deref().is_none_or(|m| m == method)
                && r.path.as_deref().is_none_or(|p| p == path)
                && r.prefix.as_deref().is_none_or(|p| path.starts_with(p))
        }) {
            let change = rule.world.as_ref().map(|(k, v)| match k.as_str() {
                "custody" => {
                    assert_eq!(v, "true");
                    WorldChange::Custody
                }
                "rule_off" => WorldChange::RuleOff(v.clone()),
                "name" => WorldChange::NameMoved,
                other => panic!("a rule's world {other}"),
            });
            if path.starts_with("/soc/") {
                self.soc_posts += 1;
            }
            return (rule.reply.clone(), change);
        }
        if let (Some(feed), Some(address)) = (call.feed, path.strip_prefix("/chunks/")) {
            for probe in &self.probes {
                let at = hex(&verify::feed_update_address(
                    &probe.owner,
                    &probe.topic,
                    feed.index,
                ));
                if feed.owner != probe.owner || at != address {
                    continue;
                }
                if let Some((index, status)) = self.probe_fail
                    && index == feed.index
                {
                    let body = format!(r#"{{"code":{status},"message":"read chunk failed"}}"#);
                    return (
                        ReplySpec {
                            status,
                            status_text: reason_phrase(status).to_owned(),
                            headers: vec![(
                                "content-type".to_owned(),
                                "application/json; charset=utf-8".to_owned(),
                            )],
                            body: body.into_bytes(),
                            ..ReplySpec::ok(Vec::new(), "")
                        },
                        None,
                    );
                }
                if probe.head.is_some_and(|head| feed.index <= head) {
                    return (ReplySpec::ok(vec![0; 105], "binary/octet-stream"), None);
                }
            }
        }
        let created = |reference: String, tag: Option<u64>| {
            let mut spec = ReplySpec::ok(
                format!(r#"{{"reference":"{reference}"}}"#).into_bytes(),
                "application/json; charset=utf-8",
            );
            spec.status = 201;
            spec.status_text = "Created".to_owned();
            if let Some(tag) = tag {
                spec.headers.push(("swarm-tag".to_owned(), tag.to_string()));
            }
            spec
        };
        match (method, path) {
            ("GET", "/stamps") => {
                let json = self
                    .stamps
                    .clone()
                    .unwrap_or_else(|| r#"{"stamps":[]}"#.to_owned());
                (
                    ReplySpec::ok(json.into_bytes(), "application/json; charset=utf-8"),
                    None,
                )
            }
            ("POST", p) if p.starts_with("/soc/") => {
                self.soc_posts += 1;
                let mut parts = p["/soc/".len()..].split('/');
                let owner: [u8; 20] = unhex(parts.next().unwrap()).try_into().unwrap();
                let id: [u8; 32] = unhex(parts.next().unwrap()).try_into().unwrap();
                let sig = unhex(&call.query[0].1);
                let address = verify::soc_address(&id, &owner);
                let mut wire = id.to_vec();
                wire.extend_from_slice(&sig);
                wire.extend_from_slice(body);
                self.base.chunks.insert(hex(&address), wire);
                (created(hex(&address), None), None)
            }
            ("POST", "/bytes") => {
                let root = tree_of(body, &mut self.base.chunks);
                self.base.blobs.insert(hex(&root.address()), body.to_vec());
                self.bzz_tag += 1;
                (created(hex(&root.address()), Some(self.bzz_tag)), None)
            }
            ("POST", p) if p.starts_with("/feeds/") => {
                (created(sha(format!("feed manifest {p}").as_bytes()), None), None)
            }
            ("GET", _) => (self.base.reply(method, path), None),
            _ => panic!("the fake node has no answer for {method} {path}"),
        }
    }
}

/// Main's answer to a whole call, under main's rules: an error status
/// whole with at most 8 KiB of body, a 2xx past `max_bytes` failed
/// `too_large`, the headers the core reads forwarded.
fn whole_answer(spec: &ReplySpec, call: &NodeCall) -> Vec<Event> {
    if spec.hang_up {
        return vec![Event::Failed(Failed::Error)];
    }
    let mut headers: Vec<(String, String)> = spec
        .headers
        .iter()
        .filter(|(k, _)| READ_HEADERS.contains(&k.as_str()))
        .cloned()
        .collect();
    if !(200..300).contains(&spec.status) {
        let mut body = spec.body.clone();
        body.truncate(8192);
        return vec![Event::Reply(Reply {
            status: spec.status,
            status_text: spec.status_text.clone(),
            headers,
            body,
        })];
    }
    if spec.body.len() > call.max_bytes {
        return vec![Event::Failed(Failed::TooLarge)];
    }
    headers.push(("content-length".to_owned(), spec.body.len().to_string()));
    vec![Event::Reply(Reply {
        status: spec.status,
        status_text: spec.status_text.clone(),
        headers,
        body: spec.body.clone(),
    })]
}

// ---------------------------------------------------------------------------
// The swarm thread, scripted.

/// A part main streams to the core.
struct PartStream {
    id: AskId,
    data: Vec<u8>,
    sent: usize,
    window: usize,
}

struct Thread<'k> {
    world: WriteWorld,
    vault: Vault<'k>,
    readiness: Result<(), JsString>,
    node: WriteNode,
    db: rusqlite::Connection,
    /// Every feed-store write fails (the gate's write failures).
    fail_writes: bool,
    parts_data: BTreeMap<u32, Vec<u8>>,
    request: Option<Request>,
    queue: VecDeque<Effect>,
    parts: Vec<PartStream>,
    /// A streamed upload's call, its charge, the length its head gave and
    /// the body so far.
    uploads: BTreeMap<AskId, (NodeCall, usize, Option<u64>, Vec<u8>)>,
    cancelled: HashSet<AskId>,
    holds: Vec<HoldId>,
    tickets: u64,
    // What happened.
    ready: Vec<(ReadyCheck, usize)>,
    calls: Vec<Logged>,
    /// Each streamed upload's body, by its index in `calls`.
    bodies: BTreeMap<usize, Vec<u8>>,
    answers: Vec<(Ticket, Result<ChangeAnswer, ChangeError>)>,
    cancels_after_outcome: usize,
}

impl<'k> Thread<'k> {
    fn new(world: WriteWorld, keys: &'k Keys, node: WriteNode) -> Thread<'k> {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(history::DDL).unwrap();
        Thread {
            world,
            vault: Vault {
                keys,
                unlocked: true,
                signed: Vec::new(),
            },
            readiness: Ok(()),
            node,
            db,
            fail_writes: false,
            parts_data: BTreeMap::new(),
            request: None,
            queue: VecDeque::new(),
            parts: Vec::new(),
            uploads: BTreeMap::new(),
            cancelled: HashSet::new(),
            holds: Vec::new(),
            tickets: 0,
            ready: Vec::new(),
            calls: Vec::new(),
            bodies: BTreeMap::new(),
            answers: Vec::new(),
            cancels_after_outcome: 0,
        }
    }

    /// Clears what one request left in the logs.
    fn reset_logs(&mut self) {
        self.ready.clear();
        self.calls.clear();
        self.bodies.clear();
        self.world.guards.set(0);
        self.vault.signed.clear();
        self.node.soc_posts = 0;
        self.cancels_after_outcome = 0;
        self.cancelled.clear();
        self.parts.clear();
        self.uploads.clear();
    }

    fn write_store(fail: bool) -> impl FnMut(&str) -> Result<(), JsString> {
        move |text: &str| {
            assert!(text.len() <= fc_swarm_provider::stores::feeds::MAX_FILE_BYTES);
            if fail {
                Err(JsString::from("EIO: the write failed"))
            } else {
                Ok(())
            }
        }
    }

    /// A store change from outside the request (the chrome's
    /// `swarm.identities`, main's grant writes), through the keeper.
    fn change(&mut self, change: FeedChange) -> Ran {
        self.tickets += 1;
        let mut write = Self::write_store(self.fail_writes);
        self.world
            .keeper
            .change(Ticket(self.tickets), change, self.world.now, &mut write)
    }

    fn start(&mut self, call: &Call) {
        let mut request = Request::start(call, &mut self.world).expect("a method this part brings");
        self.queue.extend(request.take_effects());
        self.request = Some(request);
    }

    fn outcome(&self) -> Option<&Outcome> {
        self.request.as_ref().and_then(Request::outcome)
    }

    fn give(&mut self, id: AskId, event: Event) {
        let Some(request) = self.request.as_mut() else {
            return;
        };
        let done = request.outcome().is_some();
        request.answer(&mut self.world, id, event);
        self.queue.extend(request.take_effects());
        if !done && request.outcome().is_some() {
            self.end_holds();
        }
    }

    /// The request ended: its holds end with it.
    fn end_holds(&mut self) {
        let mut write = Self::write_store(self.fail_writes);
        for hold in std::mem::take(&mut self.holds) {
            let answers = self
                .world
                .keeper
                .release(hold, self.world.now, &mut write);
            self.answers.extend(answers);
        }
    }

    /// Main's cancel, or the request's deadline.
    fn cancel(&mut self) {
        if let Some(request) = self.request.as_mut() {
            request.cancel();
            self.queue.extend(request.take_effects());
        }
        self.end_holds();
    }

    /// Runs until the request's outcome, or until an ask `stop` picks,
    /// which is taken (a signature's hold begins) but not answered.
    fn run_until(&mut self, stop: impl Fn(&Need) -> bool) -> Option<Ask> {
        loop {
            if self.outcome().is_some() {
                for effect in std::mem::take(&mut self.queue) {
                    match effect {
                        Effect::Cancel(_) => self.cancels_after_outcome += 1,
                        // The write a request still makes as it ends
                        // (its history row's), which isn't called back.
                        Effect::Ask(Ask {
                            need: Need::Write(StoreWrite::History(statements)),
                            ..
                        }) => {
                            for statement in &statements {
                                execute(&self.db, statement);
                            }
                        }
                        _ => {}
                    }
                }
                return None;
            }
            if let Some(effect) = self.queue.pop_front() {
                match effect {
                    Effect::Ask(ask) => {
                        if let Need::Sign(soc) = &ask.need
                            && let Some(key) = &soc.hold
                        {
                            let hold = HoldId(ask.id.0);
                            self.world.keeper.hold(hold, key.clone());
                            self.holds.push(hold);
                        }
                        if stop(&ask.need) {
                            return Some(ask);
                        }
                        self.answer(ask);
                    }
                    Effect::Cancel(id) => {
                        self.cancelled.insert(id);
                        self.parts.retain(|p| p.id != id);
                    }
                    Effect::Credit { id, bytes } => {
                        if let Some(part) = self.parts.iter_mut().find(|p| p.id == id) {
                            part.window += bytes;
                        }
                    }
                    Effect::Body { id, out } => match out {
                        BodyOut::Head { bytes } => {
                            self.uploads.get_mut(&id).unwrap().2 = Some(bytes);
                        }
                        BodyOut::Data(bytes) => {
                            assert!(!bytes.is_empty() && bytes.len() <= 65536);
                            let len = bytes.len();
                            let upload = self.uploads.get_mut(&id).unwrap();
                            assert!(upload.2.is_some(), "data before the body's head");
                            upload.3.extend(bytes);
                            // Main credits each frame as the node takes it.
                            self.give(id, Event::BodyCredit(len));
                        }
                        BodyOut::End => self.uploaded(id),
                        BodyOut::Abort(_) => {
                            self.uploads.remove(&id);
                        }
                    },
                }
                continue;
            }
            // A part's next frame, within the core's credit.
            if let Some(part) = self
                .parts
                .iter_mut()
                .find(|p| p.window > 0 && p.sent < p.data.len())
            {
                let n = part.window.min(65536).min(part.data.len() - part.sent);
                let frame = part.data[part.sent..part.sent + n].to_vec();
                part.sent += n;
                part.window -= n;
                let id = part.id;
                let ended = part.sent == part.data.len();
                if ended {
                    self.parts.retain(|p| p.id != id);
                }
                self.give(id, Event::Data(frame));
                if ended {
                    self.give(id, Event::End);
                }
                continue;
            }
            panic!("the request waits with nothing asked");
        }
    }

    fn run(&mut self) -> Outcome {
        assert!(self.run_until(|_| false).is_none());
        self.outcome().unwrap().clone()
    }

    /// Answers an ask as the thread does.
    fn answer(&mut self, ask: Ask) {
        match ask.need {
            Need::Ready(check) => {
                assert_eq!(ask.charge, 0);
                assert_eq!(check, ReadyCheck::Publish);
                self.ready.push((check, self.calls.len()));
                let answer = self.readiness.clone();
                self.give(ask.id, Event::Ready(answer));
            }
            Need::Owner(key) => {
                assert_eq!(ask.charge, 0);
                let answer = self.vault.owner(key);
                self.give(ask.id, answer);
            }
            Need::Sign(soc) => {
                assert_eq!(ask.charge, 0);
                let answer = self.vault.sign(&soc);
                self.give(ask.id, answer);
                // The vault answered: the hold ends.
                let hold = HoldId(ask.id.0);
                if let Some(at) = self.holds.iter().position(|h| *h == hold) {
                    self.holds.remove(at);
                    let mut write = Self::write_store(self.fail_writes);
                    let answers = self.world.keeper.release(hold, self.world.now, &mut write);
                    self.answers.extend(answers);
                }
            }
            Need::Upload => {
                assert_eq!(ask.charge, UPLOAD_CHARGE);
                self.give(ask.id, Event::Turn);
            }
            Need::Lock(_) => {
                assert_eq!(ask.charge, 0);
                self.give(ask.id, Event::Locked);
            }
            Need::Write(write) => {
                assert_eq!(ask.charge, 0);
                let answer = match write {
                    StoreWrite::Feeds(change) => match self.change(change) {
                        Ran::Applied(Ok(_)) => Event::Written(Ok(())),
                        Ran::Applied(Err(err)) => Event::Written(Err(err.message())),
                        Ran::Deferred => panic!("a request's own change deferred"),
                    },
                    StoreWrite::HistoryInsert(insert) => {
                        execute(&self.db, &insert);
                        Event::Inserted(Ok(self.db.last_insert_rowid()))
                    }
                    StoreWrite::History(statements) => {
                        for statement in &statements {
                            execute(&self.db, statement);
                        }
                        Event::Written(Ok(()))
                    }
                    StoreWrite::Manifests(_) => panic!("a manifest write"),
                };
                self.give(ask.id, answer);
            }
            Need::Part(part) => {
                assert_eq!(ask.charge, 0);
                let data = self.parts_data[&part].clone();
                let len = data.len() as u64;
                self.parts.push(PartStream {
                    id: ask.id,
                    data,
                    sent: 0,
                    window: WINDOW as usize,
                });
                self.give(ask.id, Event::PartHead(len));
            }
            Need::Node(call) => {
                if let Some(Body::Stream { .. }) = call.body {
                    assert_eq!(ask.charge, whole_charge(call.form));
                    self.uploads.insert(ask.id, (call, ask.charge, None, Vec::new()));
                    self.give(ask.id, Event::BodyOpen);
                    return;
                }
                assert_eq!(ask.charge, whole_charge(call.form), "{}", call.path);
                let body = match &call.body {
                    Some(Body::Base64(bytes)) => bytes.clone(),
                    _ => Vec::new(),
                };
                let (spec, change) = self.node.reply(&call, &body);
                self.world_change(change);
                let events = whole_answer(&spec, &call);
                let reply = events.iter().find_map(|e| match e {
                    Event::Reply(r) if r.ok() => Some(r.body.clone()),
                    _ => None,
                });
                self.calls.push(Logged {
                    call,
                    charge: ask.charge,
                    body: reply,
                });
                if spec.abort_page {
                    self.cancel();
                }
                for event in events {
                    if self.cancelled.contains(&ask.id) {
                        break;
                    }
                    self.give(ask.id, event);
                }
            }
            other => panic!("an ask these machines don't make: {other:?}"),
        }
    }

    /// A streamed upload's body is whole: the node's answer.
    fn uploaded(&mut self, id: AskId) {
        let (call, charge, head, body) = self.uploads.remove(&id).unwrap();
        if let Some(Body::Stream { bytes }) = call.body {
            assert_eq!(body.len() as u64, bytes, "the body is its declared length");
            assert_eq!(head, Some(bytes), "the body's head");
        }
        let (spec, change) = self.node.reply(&call, &body);
        self.world_change(change);
        let events = whole_answer(&spec, &call);
        let reply = events.iter().find_map(|e| match e {
            Event::Reply(r) if r.ok() => Some(r.body.clone()),
            _ => None,
        });
        self.bodies.insert(self.calls.len(), body);
        self.calls.push(Logged {
            call,
            charge,
            body: reply,
        });
        for event in events {
            self.give(id, event);
        }
    }

    fn world_change(&mut self, change: Option<WorldChange>) {
        match change {
            None => {}
            Some(WorldChange::Custody) => self.world.custody = true,
            Some(WorldChange::RuleOff(capability)) => {
                self.world.rules.retain(|(_, c)| *c != capability);
            }
            Some(WorldChange::NameMoved) => self.world.live = false,
        }
    }

    /// The history's rows, as `getEntries()` answers them.
    fn history(&self) -> JsValue {
        let rows = query(&self.db, &history::get_entries());
        history::entries(&rows).unwrap()
    }
}

fn sql_value(bind: &Bind) -> rusqlite::types::Value {
    match bind {
        Bind::Null => rusqlite::types::Value::Null,
        Bind::Integer(n) => rusqlite::types::Value::Integer(*n),
        Bind::Real(n) => rusqlite::types::Value::Real(*n),
        Bind::Text(t) => rusqlite::types::Value::Text(t.clone()),
    }
}

fn execute(conn: &rusqlite::Connection, statement: &Statement) -> usize {
    conn.execute(
        statement.sql,
        rusqlite::params_from_iter(statement.params.iter().map(sql_value)),
    )
    .unwrap()
}

fn query(conn: &rusqlite::Connection, statement: &Statement) -> Vec<Vec<Cell>> {
    let mut prepared = conn.prepare(statement.sql).unwrap();
    let columns = prepared.column_count();
    let rows = prepared
        .query_map(
            rusqlite::params_from_iter(statement.params.iter().map(sql_value)),
            |row| {
                (0..columns)
                    .map(|i| {
                        Ok(match row.get_ref(i)? {
                            rusqlite::types::ValueRef::Null => Cell::Null,
                            rusqlite::types::ValueRef::Integer(n) => Cell::Integer(n),
                            rusqlite::types::ValueRef::Real(n) => Cell::Real(n),
                            rusqlite::types::ValueRef::Text(t) => {
                                Cell::Text(String::from_utf8(t.to_vec()).unwrap())
                            }
                            rusqlite::types::ValueRef::Blob(b) => Cell::Blob(b.to_vec()),
                        })
                    })
                    .collect()
            },
        )
        .unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

// ---------------------------------------------------------------------------
// Main's side of a step: its grant writes, then what it handed the core.

/// Main's writes before it hands the step over, made on the core's store:
/// an unlock, a feed prompt's identity and the feed grant
/// (`grantFeedIdentity`), "always allow" and a connect (`grant` events);
/// then the case's `at_execute` changes.
fn main_writes(thread: &mut Thread<'_>, case: V<'_, '_>, step: V<'_, '_>, key: &JsString) {
    let events: Vec<_> = step
        .get("events")
        .map(|e| e.children().collect())
        .unwrap_or_default();
    for event in &events {
        if event.get("service").is_some() {
            break;
        }
        if let Some(prompt) = event.get("prompt") {
            let answer = get(prompt, "answer");
            if answer.get("approve").is_none_or(|a| a.kind() != Kind::True) {
                continue;
            }
            match string(get(prompt, "kind")).as_str() {
                "vault.unlock" => thread.vault.unlocked = true,
                "swarm.feed" => {
                    let picked = string(get(get(answer, "choices"), "identity"));
                    let new_id = string(get(get(get(prompt, "view"), "newIdentity"), "id"));
                    let options = fc_json::parse(r#"{"activate":true,"source":"user"}"#).unwrap();
                    let change = if picked == "bee-wallet" {
                        FeedChange::EnsureAntWalletIdentity {
                            key: key.clone(),
                            options,
                            source: Source::User,
                        }
                    } else if picked == new_id {
                        let index = thread.world.keeper.store().next_publisher_key_index();
                        FeedChange::CreateAppScopedIdentityAt {
                            key: key.clone(),
                            index: JsValue::Number(index),
                            options,
                            source: Source::User,
                        }
                    } else {
                        FeedChange::ActivateIdentity {
                            key: key.clone(),
                            identity_id: JsValue::string(picked.as_str()),
                            source: Source::User,
                        }
                    };
                    assert!(matches!(thread.change(change), Ran::Applied(Ok(_))));
                    if !thread.world.keeper.store().has_feed_grant(key) {
                        let grant = FeedChange::GrantFeedAccess {
                            key: key.clone(),
                            source: Source::User,
                        };
                        assert!(matches!(thread.change(grant), Ran::Applied(Ok(_))));
                    }
                }
                other => panic!("a prompt {other}"),
            }
        }
        if let Some(grant) = event.get("grant") {
            let change = get(grant, "change");
            match string(get(change, "op")).as_str() {
                "flag" => {
                    thread
                        .world
                        .rules
                        .insert((key.clone(), string(get(change, "flag"))));
                }
                "connect" => {
                    thread.world.grants.insert(key.clone());
                }
                other => panic!("a grant change {other}"),
            }
        }
    }
    if let Some(changes) = case.get("at_execute") {
        for (what, how) in changes.members() {
            match (string(what).as_str(), string(how).as_str()) {
                ("vault", "locked") => thread.vault.unlocked = false,
                ("feed_access", "revoked") => {
                    let revoke = FeedChange::RevokeFeedAccess {
                        key: key.clone(),
                        source: Source::User,
                    };
                    assert!(matches!(thread.change(revoke), Ran::Applied(Ok(_))));
                }
                ("connection", "revoked") => {
                    thread.world.grants.remove(key);
                }
                (what, how) => panic!("at_execute {what}: {how}"),
            }
        }
    }
}

/// How main approved the step's request (`service.approval`).
fn approval_of(step: V<'_, '_>) -> Option<Approval> {
    let service = step
        .get("events")?
        .children()
        .find_map(|e| e.get("service"))?;
    match service.get("approval").map(string).as_deref() {
        Some("auto") => Some(Approval::Auto),
        Some("user") => Some(Approval::User),
        _ => None,
    }
}

/// The step's parts (`parts[i]`), their bytes from the seed.
fn parts_of(step: V<'_, '_>) -> BTreeMap<u32, Vec<u8>> {
    step.get("parts")
        .map(|parts| {
            parts
                .children()
                .map(|p| {
                    let bytes = content(
                        &string(get(p, "seed")),
                        number(get(p, "length")) as usize,
                    );
                    assert_eq!(sha(&bytes), string(get(p, "sha256")));
                    (number(get(p, "part")) as u32, bytes)
                })
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// The checks.

/// The grammar's row for a step's request.
fn row_of(method: &str) -> &'static str {
    match method {
        "swarm_createFeed" => "createFeed",
        "swarm_updateFeed" => "updateFeed",
        "swarm_writeFeedEntry" => "writeFeedEntry",
        "swarm_writeSingleOwnerChunk" => "writeSingleOwnerChunk",
        "swarm_getSigningIdentity" => "getSigningIdentity",
        other => panic!("{other}"),
    }
}

/// The core's calls against the honest scenario's, exactly: form, method,
/// path, query, the row's headers (main adds its own), the body, `feed`.
fn check_calls(id: &str, scenario: V<'_, '_>, thread: &Thread<'_>, earlier: bool) {
    let main_headers = ["accept", "accept-encoding"];
    let wants: Vec<_> = get(scenario, "calls").children().collect();
    let paths = || {
        thread
            .calls
            .iter()
            .map(|c| c.call.path.clone())
            .collect::<Vec<_>>()
    };
    if earlier {
        // The core's own error ends the request at a call the scenario
        // goes past.
        assert!(thread.calls.len() <= wants.len(), "{id}: {:?}", paths());
    } else {
        assert_eq!(wants.len(), thread.calls.len(), "{id}: {:?}", paths());
    }
    for (at, (want, logged)) in wants.iter().zip(&thread.calls).enumerate() {
        let call = &logged.call;
        let what = format!("{id}: call {at} {}", call.path);
        assert!(get(*want, "form").is_str(call.form.as_str()), "{what}");
        assert!(get(*want, "method").is_str(call.method()), "{what}");
        assert!(get(*want, "path").is_str(&call.path), "{what}");
        let query: Vec<(String, String)> = want
            .get("query")
            .map(|q| {
                q.children()
                    .map(|pair| {
                        let mut it = pair.children();
                        (string(it.next().unwrap()), string(it.next().unwrap()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(query, call.query, "{what}: query");
        let headers: Vec<(String, String)> = get(*want, "headers")
            .children()
            .filter_map(|h| {
                let mut it = h.children();
                let (k, v) = (string(it.next().unwrap()), string(it.next().unwrap()));
                (!main_headers.contains(&k.as_str())).then_some((k, v))
            })
            .collect();
        assert_eq!(headers, call.headers, "{what}: headers");
        let body = match &call.body {
            None => None,
            Some(Body::Base64(bytes)) => Some(bytes.clone()),
            Some(Body::Stream { .. }) => Some(thread.bodies[&at].clone()),
        };
        match (want.get("body"), body) {
            (None, None) => {}
            (Some(w), Some(got)) => {
                assert_eq!(number(get(w, "bytes")) as usize, got.len(), "{what}: body");
                match (w.get("base64"), w.get("sha256")) {
                    (Some(b), _) => assert_eq!(b64(&string(b)), got, "{what}: body"),
                    (None, Some(d)) => assert_eq!(sha(&got), string(d), "{what}: body"),
                    _ => panic!("{what}: a body spec"),
                }
            }
            (w, got) => panic!("{what}: body {:?} against {:?}", w.map(|w| w.raw()), got),
        }
        match (want.get("feed"), call.feed) {
            (None, None) => {}
            (Some(f), Some(feed)) => {
                assert!(get(f, "owner").is_str(&hex(&feed.owner)), "{what}: feed");
                assert_eq!(number(get(f, "index")) as u64, feed.index, "{what}: feed");
            }
            _ => panic!("{what}: feed"),
        }
        assert!(call.tree.is_none(), "{what}");
        if let Some(m) = want.get("max_bytes") {
            assert_eq!(number(m) as usize, call.max_bytes, "{what}");
        }
    }
}

/// The values the row binds, beyond the scenario's exact calls: the topic
/// and one owner throughout a feed row, each feed `chunk` at the address
/// main builds from its `feed`, a feed write's `<id>` at the index its
/// last `feed` asked (or the next one), a raw SOC's `<id>` the page's,
/// and a large entry's SOC wrapping `bytes_up`'s reference.
fn check_binds(
    id: &str,
    row: &str,
    key: &JsString,
    params: &Value,
    outcome: &Outcome,
    thread: &Thread<'_>,
) {
    let feed_row = matches!(row, "createFeed" | "updateFeed" | "writeFeedEntry");
    let name = params
        .get(if row == "updateFeed" { "feedId" } else { "name" })
        .as_js_string()
        .map(|n| n.as_str().to_owned());
    let topic = name.map(|n| fc_swarm::feed::topic(&format!("{}/{n}", key.as_str())));
    let mut owner: Option<String> = None;
    // The indexes whose update a probe found.
    let mut probed: Vec<u64> = Vec::new();
    let mut uploaded: Option<String> = None;
    for logged in &thread.calls {
        let call = &logged.call;
        let segments: Vec<&str> = call.path.split('/').collect();
        let named_owner = match call.form {
            Form::FeedHead | Form::FeedManifest | Form::SocUp => Some(segments[2].to_owned()),
            Form::Chunk => call.feed.map(|f| hex(&f.owner)),
            _ => None,
        };
        if feed_row && let Some(o) = named_owner {
            assert_eq!(owner.get_or_insert(o.clone()), &o, "{id}: one <o>");
        }
        match call.form {
            Form::FeedHead | Form::FeedManifest => {
                assert_eq!(segments[3], hex(&topic.unwrap()), "{id}: <t>");
            }
            Form::Chunk => {
                let feed = call.feed.unwrap_or_else(|| panic!("{id}: a feed chunk"));
                let address = verify::feed_update_address(&feed.owner, &topic.unwrap(), feed.index);
                assert_eq!(call.path, format!("/chunks/{}", hex(&address)), "{id}");
                if logged.body.is_some() {
                    // An update that exists.
                    probed.push(feed.index);
                }
            }
            Form::BytesUp => {
                let reply = logged.body.as_ref().map(|b| String::from_utf8_lossy(b).into_owned());
                uploaded = reply.and_then(|r| {
                    let parsed = fc_json::parse(&r).ok()?;
                    Some(parsed.get("reference")?.as_str()?.to_owned())
                });
            }
            Form::SocUp => {
                let body = match &call.body {
                    Some(Body::Base64(bytes)) => bytes.clone(),
                    other => panic!("{id}: a SOC body {other:?}"),
                };
                if row == "writeSingleOwnerChunk" {
                    let identifier = params.get("identifier").as_js_string().unwrap();
                    assert_eq!(segments[3], identifier.as_str().to_lowercase(), "{id}: <id>");
                    continue;
                }
                // The identifier is keccak256(<t> ‖ the write's index): the
                // explicit one, or the lookup's, which a write that went
                // through answers; and past every probe that found its
                // update.
                let index = match (params.get("index"), outcome) {
                    (Value::Number(n), _) => Some(*n as u64),
                    (_, Outcome::Result(result)) => match result.get("index") {
                        Value::Number(n) => Some(*n as u64),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(index) = index {
                    assert_eq!(
                        segments[3],
                        hex(&verify::feed_update_id(&topic.unwrap(), index)),
                        "{id}: <id>"
                    );
                    assert!(probed.iter().all(|p| *p < index), "{id}: {probed:?}");
                }
                if body.len() > 8 + 4096 || uploaded.is_some() {
                    let span: [u8; 8] = body[..8].try_into().unwrap();
                    let address = verify::address_of(&span, &body[8..]).unwrap();
                    assert_eq!(Some(hex(&address)), uploaded, "{id}: the root bytes_up named");
                }
            }
            _ => {}
        }
    }
}

/// The vault's signatures against the step's `sign_soc` events; where the
/// core ends the request earlier than the reference (a deviation's own
/// error), a prefix of them.
fn check_signatures(
    id: &str,
    step: V<'_, '_>,
    approval: Option<Approval>,
    thread: &Thread<'_>,
    earlier: bool,
) {
    let wants: Vec<_> = step
        .get("events")
        .map(|e| e.children().filter_map(|e| e.get("sign_soc")).collect())
        .unwrap_or_default();
    if earlier {
        assert!(thread.vault.signed.len() <= wants.len(), "{id}: signatures");
    } else {
        assert_eq!(wants.len(), thread.vault.signed.len(), "{id}: signatures");
    }
    for (want, soc) in wants.iter().zip(&thread.vault.signed) {
        let key = get(*want, "key");
        match soc.key {
            SignKey::BeeWallet => assert!(get(key, "kind").is_str("bee_wallet"), "{id}"),
            SignKey::Publisher(index) => {
                assert!(get(key, "kind").is_str("publisher"), "{id}");
                assert_eq!(number(get(key, "origin_index")), f64::from(index), "{id}");
            }
        }
        assert!(
            get(*want, "identifier").is_str(&hex(&soc.identifier)),
            "{id}: identifier"
        );
        let payload = get(*want, "payload");
        assert_eq!(number(get(payload, "bytes")) as usize, soc.payload.len(), "{id}");
        match (payload.get("hex"), payload.get("sha256")) {
            (Some(h), _) => assert_eq!(string(h), hex(&soc.payload), "{id}: payload"),
            (None, Some(d)) => assert_eq!(string(d), sha(&soc.payload), "{id}: payload"),
            _ => panic!("{id}: a payload spec"),
        }
        match want.get("span") {
            Some(span) => assert_eq!(string(span), soc.span.to_string(), "{id}: span"),
            None => assert_eq!(soc.span, soc.payload.len() as u64, "{id}: span"),
        }
        let authorization = get(*want, "authorization");
        assert!(get(authorization, "soc").is_str(soc.kind.as_str()), "{id}");
        let swarm = match approval {
            Some(Approval::Auto) => "auto",
            _ => "user",
        };
        assert!(get(authorization, "swarm").is_str(swarm), "{id}");
        // A raw SOC holds its site's key until the vault answers; a feed
        // write signs under no hold.
        assert_eq!(
            soc.hold.is_some(),
            soc.kind == fc_swarm_provider::machine::SocKind::Raw,
            "{id}"
        );
    }
}

/// The rows the core leaves: the reference's, but where a deviation gives
/// the core's own error (`core`), the step's row is failed with the core's
/// text, or absent where the core refuses before it (`core_before`).
fn expected_history(case: V<'_, '_>, want: Want) -> JsValue {
    let rows = fc_json::parse(
        &get(get(case, "after"), "history").stringify(fc_json::index::KeyOrder::Property),
    )
    .unwrap();
    let core_error = match want {
        Want::Exact => get(case, "core").get("error").map(|e| string(get(e, "message"))),
        Want::Transport => Some(fc_swarm_provider::machine::node::ERROR_TEXT.to_owned()),
        _ => None,
    };
    let Some(message) = core_error else {
        return rows;
    };
    let mut rows = rows.as_array().unwrap().to_vec();
    // getEntries() answers the latest first: the step's row.
    if case.get("core_before").is_some() {
        rows.remove(0);
        return JsValue::Array(rows);
    }
    let row = &mut rows[0];
    row.set("status", JsValue::string("failed"));
    row.set("errorMessage", JsValue::string(message.as_str()));
    for field in ["reference", "bzzUrl", "batchIdUsed"] {
        row.set(field, JsValue::Null);
    }
    let timestamp = row.get("timestamp").cloned().unwrap();
    row.set("completedAt", timestamp);
    JsValue::Array(rows)
}

fn count(step: V<'_, '_>, name: &str) -> usize {
    step.get("events")
        .map(|e| e.children().filter(|e| e.get(name).is_some()).count())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The test.

struct Vectors {
    text: String,
    grammar: String,
    keys: String,
}

fn vectors() -> Vectors {
    Vectors {
        text: text_of("swarm.json"),
        grammar: text_of("swarm-grammar.json"),
        keys: text_of("keys.json"),
    }
}

#[test]
fn feed_and_soc_writes() {
    let v = vectors();
    let index = Index::new(&v.text).unwrap();
    let grammar_index = Index::new(&v.grammar).unwrap();
    let grammar = grammar_index.root();
    let keys_index = Index::new(&v.keys).unwrap();
    let keys = keys(&keys_index);
    let scenarios = scenarios(grammar);

    let mut played = 0usize;
    let mut main_answered = 0usize;
    let mut scenarios_used = BTreeSet::new();
    let mut left_out_seen = BTreeSet::new();
    let mut deviations = BTreeSet::new();
    for case in get(index.root(), "methods").children() {
        let id = string(get(case, "id"));
        let steps: Vec<_> = get(case, "steps").children().collect();
        let methods: Vec<Option<String>> =
            steps.iter().map(|s| s.get("method").map(string)).collect();
        if !methods
            .iter()
            .any(|m| m.as_ref().is_some_and(|m| FIVE.contains(&m.as_str())))
        {
            continue;
        }
        if let Some((_, why)) = LEFT_OUT.iter().find(|(l, _)| *l == id) {
            assert!(!why.is_empty());
            left_out_seen.insert(id.clone());
            continue;
        }
        assert!(
            methods
                .iter()
                .all(|m| m.as_ref().is_some_and(|m| FIVE.contains(&m.as_str()))),
            "{id}: a case that mixes in another piece's method"
        );
        if case.get("at_execute").is_some() {
            assert_eq!(steps.len(), 1, "{id}");
        }

        let deviation = case.get("deviation").map(string);
        let want = match &deviation {
            Some(d) => {
                deviations.insert(d.clone());
                core_answer(d, get(case, "core"))
            }
            None => {
                assert!(case.get("core").is_none(), "{id}");
                Want::Reference
            }
        };
        if let Some(also) = case.get("also") {
            for d in also.children() {
                deviations.insert(string(d));
            }
        }
        let origin = js(get(case, "origin"));
        let mut thread = Thread::new(WriteWorld::of(case), &keys, WriteNode::of(case, &keys));
        thread.vault.unlocked = get(case, "vault").is_str("unlocked");
        thread.world.custody = get(case, "custody").kind() == Kind::True;
        thread.readiness = publish_readiness(case);

        for (k, step) in steps.iter().enumerate() {
            let sid = if steps.len() > 1 {
                format!("{id}/{k}")
            } else {
                id.clone()
            };
            if let Some(clock) = step.get("clock") {
                thread.world.now = number(clock) as u64;
            }
            // The core never sees a step main answered itself.
            let mut probe = TestWorld::new(thread.world.now);
            let Some(handoff) = handoff(*step, &origin, &mut probe) else {
                assert_eq!(get(*step, "requests").children().count(), 0, "{sid}");
                main_answered += 1;
                continue;
            };
            main_writes(&mut thread, case, *step, &handoff.key);
            thread.reset_logs();
            thread.parts_data = parts_of(*step);
            let approval = approval_of(*step);
            let call = Call {
                method: handoff.method.clone(),
                params: handoff.params.clone(),
                key: handoff.key.clone(),
                approval,
            };
            thread.start(&call);
            let outcome = thread.run();
            played += 1;

            let last = k + 1 == steps.len();
            check_outcome(&sid, want, last, case, *step, &outcome);

            let name = handoff.name.clone().unwrap();
            let row = row_of(&name);
            let shape = common::Ran {
                outcome: outcome.clone(),
                ready: thread.ready.clone(),
                calls: thread.calls.clone(),
                cancels_after_outcome: thread.cancels_after_outcome,
            };
            check_row_shape(&sid, grammar, row, &shape);
            check_binds(&sid, row, &handoff.key, &handoff.params, &outcome, &thread);
            // The core's own error ends the request where the reference
            // went on.
            let earlier = want == Want::Exact && last && get(case, "core").get("error").is_some();
            match scenarios.get(&sid) {
                // The core refuses before any node call (`core_before`):
                // the scenario's calls are the reference's.
                Some(_) if case.get("core_before").is_some() => {
                    assert!(get(case, "core_before").is_str("any node call"), "{sid}");
                    assert!(thread.calls.is_empty() && thread.ready.is_empty(), "{sid}");
                    scenarios_used.insert(sid.clone());
                }
                Some(scenario) => {
                    assert!(get(*scenario, "row").is_str(row), "{sid}");
                    check_calls(&sid, *scenario, &thread, earlier);
                    scenarios_used.insert(sid.clone());
                }
                None => assert!(thread.calls.is_empty(), "{sid}: calls, and no honest scenario"),
            }
            check_signatures(&sid, *step, approval, &thread, earlier);
            if earlier {
                assert!(thread.world.guards.get() <= count(*step, "effect"), "{sid}: effects");
                assert!(thread.ready.len() <= count(*step, "readiness"), "{sid}");
            } else {
                assert_eq!(thread.world.guards.get(), count(*step, "effect"), "{sid}: effects");
                assert_eq!(thread.ready.len(), count(*step, "readiness"), "{sid}: readiness");
            }
            assert_eq!(
                thread.node.soc_posts,
                thread
                    .calls
                    .iter()
                    .filter(|c| c.call.form == Form::SocUp)
                    .count(),
                "{sid}"
            );
        }

        // The stores after.
        let after = get(case, "after");
        let feeds_after = after
            .get("feeds")
            .filter(|f| f.kind() == Kind::String)
            .map(string);
        let text = thread.world.keeper.store().text().unwrap();
        match feeds_after {
            Some(want) => assert_eq!(text, want, "{id}: swarm-feeds.json"),
            None => assert_eq!(
                *thread.world.keeper.store(),
                FeedStore::empty(),
                "{id}: no swarm-feeds.json"
            ),
        }
        let history = thread.history();
        assert_eq!(
            history.stringify(),
            expected_history(case, want).stringify(),
            "{id}: history"
        );
    }
    let left_out: BTreeSet<String> = LEFT_OUT.iter().map(|(id, _)| (*id).to_owned()).collect();
    assert_eq!(left_out_seen, left_out, "every case left out exists");
    // Every honest scenario of these rows is one a step played, but the
    // cases left out.
    for (sid, scenario) in &scenarios {
        let from = string(get(*scenario, "from"));
        let Some(case_id) = from.strip_prefix("methods/") else {
            continue;
        };
        let row = string(get(*scenario, "row"));
        if !FIVE.iter().any(|m| row_of(m) == row) || left_out.contains(case_id) {
            continue;
        }
        assert!(scenarios_used.contains(sid), "{sid}: an honest scenario no step played");
    }
    for d in [
        "index-probe",
        "feed-wrap-root",
        "feed-entry-bound",
        "reference-check",
        "stamps-one-read",
        "reply-syntax",
        "transport-error-text",
    ] {
        assert!(deviations.contains(d), "{d}: no case played");
    }
    assert_eq!((played, main_answered), (181, 11), "steps played and main's own");
    assert_eq!(scenarios_used.len(), 99);
}

/// `write-feed-explicit-index-timeout` as the core answers it: the page
/// gives up as the existence check reaches the node, so the request ends
/// `cancelled`, nothing more is asked, and the history row is left
/// `uploading` (the row's end is the thread's, at the cancel: SWM-4).
#[test]
fn the_page_giving_up_is_a_cancel() {
    let v = vectors();
    let index = Index::new(&v.text).unwrap();
    let keys_index = Index::new(&v.keys).unwrap();
    let keys = keys(&keys_index);
    let case = get(index.root(), "methods")
        .children()
        .find(|c| get(*c, "id").is_str("write-feed-explicit-index-timeout"))
        .unwrap();
    let step = get(case, "steps").children().next().unwrap();
    let origin = js(get(case, "origin"));
    let mut thread = Thread::new(WriteWorld::of(case), &keys, WriteNode::of(case, &keys));
    thread.readiness = publish_readiness(case);
    let mut probe = TestWorld::new(thread.world.now);
    let handoff = handoff(step, &origin, &mut probe).unwrap();
    main_writes(&mut thread, case, step, &handoff.key);
    thread.start(&Call {
        method: handoff.method,
        params: handoff.params,
        key: handoff.key,
        approval: approval_of(step),
    });
    assert_eq!(thread.run(), Outcome::Cancelled);
    assert_eq!(thread.calls.len(), 2, "the stamps, then the existence check");
    assert!(thread.vault.signed.is_empty());
    assert_eq!(thread.node.soc_posts, 0);
}

// ---------------------------------------------------------------------------
// The stamps and errors cases these machines reach.

/// A connected site with a feed and its grant, under the Bee wallet.
fn feed_site() -> (JsString, FeedStore) {
    let key = JsString::from("https://app.example");
    let text = r#"{"version":2,"nextPublisherKeyIndex":1,"origins":{"https://app.example":{"activeIdentityId":"app-scoped:0","identities":{"app-scoped:0":{"id":"app-scoped:0","mode":"app-scoped","publisherKeyIndex":0,"walletIndex":null,"label":"App-scoped identity 1","createdAt":1767225550123,"lastUsedAt":null},"bee-wallet":{"id":"bee-wallet","mode":"bee-wallet","publisherKeyIndex":null,"walletIndex":null,"label":"Bee wallet identity","createdAt":1767225550123,"lastUsedAt":null}},"feedGranted":true,"grantedAt":1767225550123,"feeds":{}}}}"#;
    (
        key,
        FeedStore::load(Some(text.as_bytes()), 0, |_| false).store,
    )
}

fn site_world(key: &JsString, store: FeedStore) -> WriteWorld {
    let mut world = WriteWorld::new(1_767_225_600_123, store);
    world.grants.insert(key.clone());
    world
}

/// `stamps.select`'s `feed-4096` cases through `createFeed`'s batch choice:
/// one `/stamps` read, then the manifest under the chosen batch, or the
/// write's error through `nodeWriteError`.
#[test]
fn a_feed_writes_batch_is_select_best_batch() {
    let v = vectors();
    let index = Index::new(&v.text).unwrap();
    let keys_index = Index::new(&v.keys).unwrap();
    let keys = keys(&keys_index);
    let mut played = 0;
    for case in get(get(index.root(), "stamps"), "select").children() {
        let id = string(get(case, "id"));
        if !id.ends_with("/feed-4096") {
            continue;
        }
        assert_eq!(number(get(case, "size")), 4096.0, "{id}");
        assert_eq!(get(case, "options").members().count(), 0, "{id}");
        let (key, store) = feed_site();
        let mut node = WriteNode::new();
        node.stamps = Some(get(case, "stamps").stringify(fc_json::index::KeyOrder::Property));
        let mut thread = Thread::new(site_world(&key, store), &keys, node);
        thread.start(&Call {
            method: Value::str("swarm_createFeed"),
            params: Value::object([("name", Value::str("blog"))]),
            key: key.clone(),
            approval: Some(Approval::User),
        });
        let outcome = thread.run();
        let forms: Vec<Form> = thread.calls.iter().map(|c| c.call.form).collect();
        // One `/stamps` read, the core's where the reference made two.
        assert_eq!(
            forms.iter().filter(|f| **f == Form::Stamps).count(),
            1,
            "{id}: stamps-one-read"
        );
        if let Some(error) = case.get("error") {
            assert_eq!(forms, [Form::Stamps], "{id}");
            assert_eq!(
                outcome,
                Outcome::Error(Failure::internal(js(get(error, "message")))),
                "{id}"
            );
        } else if get(case, "result").kind() == Kind::Null {
            // No batch with room: the pre-flight's `no-usable-stamps`.
            assert_eq!(forms, [Form::Stamps], "{id}");
            assert_eq!(
                outcome,
                Outcome::Error(Failure {
                    data: Some(Value::object([("reason", Value::str("no-usable-stamps"))])),
                    ..Failure::bare(4900, fc_swarm_provider::errors::NO_USABLE_BATCH_MESSAGE)
                }),
                "{id}"
            );
        } else {
            assert_eq!(forms, [Form::Stamps, Form::FeedManifest], "{id}");
            let header = thread.calls[1]
                .call
                .headers
                .iter()
                .find(|(k, _)| k == "swarm-postage-batch-id")
                .map(|(_, v)| v.clone());
            assert_eq!(header, Some(string(get(case, "result"))), "{id}");
            assert!(matches!(outcome, Outcome::Result(_)), "{id}");
        }
        played += 1;
    }
    assert_eq!(played, 11);
}

/// A node error case's body and reply.
fn error_reply(case: V<'_, '_>) -> ReplySpec {
    let status = number(get(case, "status")) as u16;
    let body = get(case, "body");
    let bytes = match (body.get("base64"), body.get("data")) {
        (Some(b), _) => b64(&string(b)),
        (None, Some(data)) => data_of(data),
        (None, None) => Vec::new(),
    };
    assert_eq!(bytes.len() as f64, number(get(body, "length")));
    ReplySpec {
        status,
        status_text: string(get(case, "status_text")),
        headers: Vec::new(),
        body: bytes,
        ..ReplySpec::ok(Vec::new(), "")
    }
}

/// `errors`' `soc-upload` cases through `writeSingleOwnerChunk`, the
/// `bee-js-json` ones at 500 through `createFeed`'s manifest, and the
/// `bee-js-arraybuffer` ones through `writeFeedEntry`'s existence check:
/// the page's -32603 is the site's error text (the first 8 KiB's where the
/// case's `core` says so, deviation `error-body-bound`).
#[test]
fn write_errors_read_as_each_site() {
    let v = vectors();
    let index = Index::new(&v.text).unwrap();
    let keys_index = Index::new(&v.keys).unwrap();
    let keys = keys(&keys_index);
    let mut played = BTreeMap::<&str, usize>::new();
    for case in get(index.root(), "errors").children() {
        let id = string(get(case, "id"));
        if !get(case, "kind").is_str("http_error") {
            continue;
        }
        let site = string(get(case, "site"));
        let status = number(get(case, "status"));
        let (method, params, prefix, site_name) = match site.as_str() {
            "soc-upload" => (
                "swarm_writeSingleOwnerChunk",
                Value::object([
                    ("identifier", Value::str(&"42".repeat(32))),
                    ("data", Value::str("x")),
                ]),
                "/soc/",
                "soc-upload",
            ),
            "bee-js-json" if status == 500.0 => (
                "swarm_createFeed",
                Value::object([("name", Value::str("blog"))]),
                "/feeds/",
                "bee-js-json",
            ),
            "bee-js-arraybuffer" => (
                "swarm_writeFeedEntry",
                Value::object([
                    ("name", Value::str("blog")),
                    ("data", Value::str("x")),
                    ("index", Value::Number(3.0)),
                ]),
                "/chunks/",
                "bee-js-arraybuffer",
            ),
            _ => continue,
        };
        let (key, mut store) = feed_site();
        if method == "swarm_writeFeedEntry" {
            let data = fc_json::parse(&format!(
                r#"{{"topic":"{}","owner":"0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0","manifestReference":"{}","identityId":"bee-wallet"}}"#,
                "00".repeat(32),
                "cd".repeat(32)
            ))
            .unwrap();
            store
                .set_feed(&key, &JsString::from("blog"), &data, 1)
                .unwrap();
        }
        let mut node = WriteNode::new();
        node.stamps = Some(
            r#"{"stamps":[{"batchID":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","utilization":0,"usable":true,"label":"freedom","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000}]}"#
                .to_owned(),
        );
        node.rules.push(WriteRule {
            method: None,
            path: None,
            prefix: Some(prefix.to_owned()),
            reply: error_reply(case),
            world: None,
        });
        let mut thread = Thread::new(site_world(&key, store), &keys, node);
        thread.start(&Call {
            method: Value::str(method),
            params,
            key: key.clone(),
            approval: Some(Approval::User),
        });
        let outcome = thread.run();
        let want = get(case.get("core").unwrap_or(case), "error");
        let Outcome::Error(failure) = &outcome else {
            panic!("{id}: {outcome:?}")
        };
        let message = match want.get("message") {
            Some(m) => js(m),
            None => {
                let digest = get(want, "message_digest");
                assert_eq!(
                    failure.message.utf16_len() as f64,
                    number(get(digest, "units")),
                    "{id}"
                );
                assert_eq!(sha(failure.message.as_bytes()), string(get(digest, "sha256")), "{id}");
                failure.message.clone()
            }
        };
        assert_eq!(failure.message, message, "{id}");
        assert_eq!(failure.code, -32603, "{id}");
        // The history row keeps the same text.
        let rows = thread.history();
        let rows = rows.as_array().unwrap();
        assert_eq!(rows.len(), 1, "{id}");
        // `errorMessage || null`: an empty text is no message.
        assert_eq!(
            rows[0].get("errorMessage").and_then(JsValue::as_js_string),
            (!message.is_empty()).then_some(&message),
            "{id}"
        );
        *played.entry(site_name).or_default() += 1;
    }
    assert_eq!(
        played.into_iter().collect::<Vec<_>>(),
        [("bee-js-arraybuffer", 18), ("bee-js-json", 36), ("soc-upload", 18)]
    );
}

// ---------------------------------------------------------------------------
// SW-1's interleaving gate (design 0015, "SW-1 in the core"), on the
// machine: each case a fixed script, the vault counting signatures and the
// node counting `POST /soc`.

const A: &str = "https://a.example";
const B: &str = "https://b.example";

/// Site `a` holds app-scoped index 0, exclusive, with its feed grant and a
/// Bee wallet identity beside it; site `b` uses the Bee wallet. The counter
/// is behind the held index (F-8), as only stored data can make it.
fn gate_store() -> FeedStore {
    let text = format!(
        r#"{{"version":2,"nextPublisherKeyIndex":0,"origins":{{"{A}":{{"activeIdentityId":"app-scoped:0","identities":{{"app-scoped:0":{{"id":"app-scoped:0","mode":"app-scoped","publisherKeyIndex":0,"walletIndex":null,"label":"A","createdAt":1,"lastUsedAt":null}},"bee-wallet":{{"id":"bee-wallet","mode":"bee-wallet","publisherKeyIndex":null,"walletIndex":null,"label":"Bee","createdAt":1,"lastUsedAt":null}}}},"feedGranted":true,"grantedAt":1,"feeds":{{}}}},"{B}":{{"activeIdentityId":"bee-wallet","identities":{{"bee-wallet":{{"id":"bee-wallet","mode":"bee-wallet","publisherKeyIndex":null,"walletIndex":null,"label":"Bee","createdAt":1,"lastUsedAt":null}}}},"feedGranted":true,"grantedAt":1,"feeds":{{}}}}}}}}"#
    );
    FeedStore::load(Some(text.as_bytes()), 0, |_| false).store
}

fn gate_thread(keys: &Keys) -> Thread<'_> {
    let mut world = WriteWorld::new(1_767_225_600_123, gate_store());
    world.grants.insert(JsString::from(A));
    world.grants.insert(JsString::from(B));
    let mut node = WriteNode::new();
    node.stamps = Some(
        r#"{"stamps":[{"batchID":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","utilization":0,"usable":true,"label":"freedom","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000}]}"#
            .to_owned(),
    );
    Thread::new(world, keys, node)
}

fn raw_soc(thread: &mut Thread<'_>) {
    thread.reset_logs();
    thread.start(&Call {
        method: Value::str("swarm_writeSingleOwnerChunk"),
        params: Value::object([
            ("identifier", Value::str(&"42".repeat(32))),
            ("data", Value::str("x")),
        ]),
        key: JsString::from(A),
        approval: Some(Approval::User),
    });
}

/// Another site takes `a`'s publisher index: a set with an explicit index.
fn take_index() -> FeedChange {
    FeedChange::SetOriginEntry {
        key: JsString::from(B),
        data: fc_json::parse(r#"{"identityMode":"app-scoped","publisherKeyIndex":0}"#).unwrap(),
    }
}

fn switch_to_shared() -> FeedChange {
    FeedChange::ActivateIdentity {
        key: JsString::from(A),
        identity_id: JsValue::string("bee-wallet"),
        source: Source::User,
    }
}

fn revoke() -> FeedChange {
    FeedChange::RevokeFeedAccess {
        key: JsString::from(A),
        source: Source::User,
    }
}

fn is_owner(need: &Need) -> bool {
    matches!(need, Need::Owner(_))
}

fn is_sign(need: &Need) -> bool {
    matches!(need, Need::Sign(_))
}

fn shared_identity() -> Outcome {
    Outcome::Error(fc_swarm_provider::methods::soc_write::shared_identity())
}


/// The change wins: paused after the first SW-1 check (at the vault's
/// owner), the change lands; the re-check refuses: no signature, no upload.
#[test]
fn gate_the_change_wins() {
    let text = text_of("keys.json");
    let index = Index::new(&text).unwrap();
    let keys = keys(&index);
    let cases: [(FeedChange, Outcome); 3] = [
        (take_index(), shared_identity()),
        (switch_to_shared(), shared_identity()),
        (
            revoke(),
            Outcome::Error(Failure::not_authorized("feed_not_granted")),
        ),
    ];
    for (change, want) in cases {
        let mut thread = gate_thread(&keys);
        raw_soc(&mut thread);
        let owner = thread.run_until(is_owner).expect("paused at the vault");
        // No hold yet: the change completes at once.
        assert!(matches!(thread.change(change.clone()), Ran::Applied(Ok(_))), "{change:?}");
        thread.answer(owner);
        assert_eq!(thread.run(), want, "{change:?}");
        assert!(thread.vault.signed.is_empty(), "{change:?}: no signature");
        assert_eq!(thread.node.soc_posts, 0, "{change:?}: no upload");
        let rows = thread.history();
        assert_eq!(
            rows.as_array().unwrap()[0].get("status").and_then(JsValue::as_str),
            Some("failed")
        );
    }
}

/// The change waits: paused after the re-check, the vault's answer held
/// back, the other site's change doesn't complete and writes nothing; the
/// vault released, the SOC is uploaded and the change applies; the site's
/// next raw SOC is refused.
#[test]
fn gate_the_change_waits() {
    let text = text_of("keys.json");
    let index = Index::new(&text).unwrap();
    let keys = keys(&index);
    for change in [take_index(), switch_to_shared(), revoke()] {
        let mut thread = gate_thread(&keys);
        raw_soc(&mut thread);
        let sign = thread.run_until(is_sign).expect("paused at the signature");
        let before = thread.world.keeper.store().clone();
        let mut wrote = false;
        thread.tickets += 1;
        let ran = thread.world.keeper.change(
            Ticket(thread.tickets),
            change.clone(),
            thread.world.now,
            &mut |_: &str| {
                wrote = true;
                Ok(())
            },
        );
        assert_eq!(ran, Ran::Deferred, "{change:?}");
        assert!(!wrote, "{change:?}: nothing written");
        assert_eq!(*thread.world.keeper.store(), before, "{change:?}");
        // Other store writes go on.
        let other = FeedChange::GrantFeedAccess {
            key: JsString::from(B),
            source: Source::User,
        };
        assert!(matches!(thread.change(other), Ran::Applied(Ok(_))));
        thread.answer(sign);
        assert_eq!(thread.world.keeper.deferred(), 0, "{change:?}: applied");
        assert!(
            matches!(thread.answers.as_slice(), [(Ticket(t), Ok(_))] if *t == thread.tickets - 1),
            "{change:?}: the change's caller answered"
        );
        let outcome = thread.run();
        let uploaded = matches!(outcome, Outcome::Result(_));
        assert_eq!(thread.vault.signed.len(), 1, "{change:?}");
        if change == revoke() {
            // The signature exists; the upload's guard reads the grant
            // revoked, as one made just before the change would.
            assert_eq!(
                outcome,
                Outcome::Error(Failure::not_authorized("feed_not_granted")),
                "{change:?}"
            );
            assert_eq!(thread.node.soc_posts, 0, "{change:?}");
        } else {
            assert!(uploaded, "{change:?}: {outcome:?}");
            assert_eq!(thread.node.soc_posts, 1, "{change:?}");
        }
        // The site's next raw SOC is refused at today's check.
        raw_soc(&mut thread);
        let next = thread.run();
        let want = if change == revoke() {
            Outcome::Error(Failure::not_authorized("feed_not_granted"))
        } else {
            shared_identity()
        };
        assert_eq!(next, want, "{change:?}");
        assert!(thread.vault.signed.is_empty() && thread.node.soc_posts == 0);
    }
}

/// Cancel during the hold, and the deadline passing during it: the
/// deferred change completes at once, the late signature is dropped, and
/// nothing is uploaded.
#[test]
fn gate_cancel_during_the_hold() {
    let text = text_of("keys.json");
    let index = Index::new(&text).unwrap();
    let keys = keys(&index);
    for _deadline in [false, true] {
        let mut thread = gate_thread(&keys);
        raw_soc(&mut thread);
        let sign = thread.run_until(is_sign).expect("paused at the signature");
        assert_eq!(thread.change(take_index()), Ran::Deferred);
        // Main's cancel, or the deadline: the same call (deviation
        // `deadlines`).
        thread.cancel();
        assert_eq!(thread.world.keeper.deferred(), 0, "completed at once");
        assert_eq!(thread.answers.len(), 1);
        assert_eq!(thread.world.keeper.holds(), 0);
        // The vault's late answer is taken and dropped.
        thread.answer(sign);
        assert_eq!(thread.run(), Outcome::Cancelled);
        assert_eq!(thread.node.soc_posts, 0, "nothing uploaded");
        assert!(thread.calls.is_empty());
        raw_soc(&mut thread);
        assert_eq!(thread.run(), shared_identity());
    }
}

/// A write failure during the hold: the deferred change's write fails, so
/// its caller gets the store's error, the store is unchanged, and the next
/// raw SOC passes. Another store write that fails during the hold leaves
/// the hold and the SOC as they were.
#[test]
fn gate_a_write_failure_during_the_hold() {
    let text = text_of("keys.json");
    let index = Index::new(&text).unwrap();
    let keys = keys(&index);
    // The deferred change's own write fails.
    let mut thread = gate_thread(&keys);
    raw_soc(&mut thread);
    let sign = thread.run_until(is_sign).expect("paused at the signature");
    assert_eq!(thread.change(take_index()), Ran::Deferred);
    let before = thread.world.keeper.store().clone();
    thread.fail_writes = true;
    thread.answer(sign);
    thread.fail_writes = false;
    let [(_, Err(err))] = thread.answers.as_slice() else {
        panic!("{:?}", thread.answers)
    };
    assert_eq!(err.message(), "EIO: the write failed");
    assert_eq!(*thread.world.keeper.store(), before, "the store unchanged");
    assert!(matches!(thread.run(), Outcome::Result(_)));
    assert_eq!(thread.node.soc_posts, 1);
    raw_soc(&mut thread);
    assert!(matches!(thread.run(), Outcome::Result(_)), "the next raw SOC passes");
    assert_eq!((thread.vault.signed.len(), thread.node.soc_posts), (1, 1));

    // Another store write fails during the hold.
    let mut thread = gate_thread(&keys);
    raw_soc(&mut thread);
    let sign = thread.run_until(is_sign).expect("paused at the signature");
    thread.fail_writes = true;
    let other = FeedChange::GrantFeedAccess {
        key: JsString::from(B),
        source: Source::User,
    };
    let other_revoke = FeedChange::RevokeFeedAccess {
        key: JsString::from(B),
        source: Source::User,
    };
    assert!(matches!(thread.change(other_revoke), Ran::Applied(Err(_))));
    assert!(matches!(thread.change(other), Ran::Applied(Err(_))));
    thread.fail_writes = false;
    assert_eq!(thread.world.keeper.holds(), 1, "the hold stands");
    thread.answer(sign);
    assert!(matches!(thread.run(), Outcome::Result(_)));
    assert_eq!((thread.vault.signed.len(), thread.node.soc_posts), (1, 1));
}

/// Allocation: with the counter at or below the held index, an allocation
/// during the hold takes a fresh index and isn't deferred.
#[test]
fn gate_allocation_during_the_hold() {
    let text = text_of("keys.json");
    let index = Index::new(&text).unwrap();
    let keys = keys(&index);
    let mut thread = gate_thread(&keys);
    raw_soc(&mut thread);
    let sign = thread.run_until(is_sign).expect("paused at the signature");
    let create = FeedChange::CreateAppScopedIdentity {
        key: JsString::from(B),
        options: JsValue::Undefined,
        source: Source::User,
    };
    let Ran::Applied(Ok(made)) = thread.change(create) else {
        panic!("not deferred")
    };
    assert_eq!(
        made.value.get("activeIdentityId").and_then(JsValue::as_str),
        Some("app-scoped:1"),
        "a fresh index"
    );
    let Ran::Applied(Ok(index)) = thread.change(FeedChange::AllocatePublisherKeyIndex) else {
        panic!("not deferred")
    };
    assert_eq!(index.value, JsValue::Number(2.0));
    thread.answer(sign);
    assert!(matches!(thread.run(), Outcome::Result(_)));
    assert_eq!((thread.vault.signed.len(), thread.node.soc_posts), (1, 1));
    raw_soc(&mut thread);
    assert!(matches!(thread.run(), Outcome::Result(_)), "still exclusive");
}

/// SW-1's cases at today's check, with today's errors in today's order:
/// the Bee wallet, a shared index, an exclusive index, a missing index,
/// and #89's identity first.
#[test]
fn sw1_cases() {
    let text = text_of("keys.json");
    let index = Index::new(&text).unwrap();
    let keys = keys(&index);
    let store = |a_identity: &str, a_active: &str, b_identity: &str| {
        let text = format!(
            r#"{{"version":2,"nextPublisherKeyIndex":5,"origins":{{"{A}":{{"activeIdentityId":"{a_active}","identities":{{"{a_active}":{a_identity}}},"feedGranted":true,"grantedAt":1,"feeds":{{}}}},"{B}":{{"activeIdentityId":"x","identities":{{"x":{b_identity}}},"feedGranted":true,"grantedAt":1,"feeds":{{}}}}}}}}"#
        );
        FeedStore::load(Some(text.as_bytes()), 0, |_| false).store
    };
    let bee = r#"{"id":"bee-wallet","mode":"bee-wallet","publisherKeyIndex":null}"#;
    let app = |i: &str| format!(r#"{{"id":"app-scoped:{i}","mode":"app-scoped","publisherKeyIndex":{i}}}"#);
    let eth = r#"{"id":"ethereum-wallet:0","mode":"ethereum-wallet","walletIndex":0}"#;
    let cases: Vec<(&str, FeedStore, Option<Outcome>)> = vec![
        ("the Bee wallet", store(bee, "bee-wallet", bee), Some(shared_identity())),
        (
            "a shared index",
            store(&app("1"), "app-scoped:1", &app("1")),
            Some(shared_identity()),
        ),
        ("an exclusive index", store(&app("1"), "app-scoped:1", &app("2")), None),
        (
            "a missing index",
            store(r#"{"id":"app-scoped:x","mode":"app-scoped"}"#, "app-scoped:x", bee),
            Some(shared_identity()),
        ),
        (
            "#89's identity first",
            store(eth, "ethereum-wallet:0", eth),
            Some(Outcome::Error(Failure::internal(
                fc_swarm_provider::stores::feeds::ETHEREUM_WALLET_UNAVAILABLE,
            ))),
        ),
    ];
    for (what, store, want) in cases {
        let mut world = WriteWorld::new(1_767_225_600_123, store);
        world.grants.insert(JsString::from(A));
        let mut thread = gate_thread(&keys);
        thread.world = world;
        raw_soc(&mut thread);
        let outcome = thread.run();
        match want {
            Some(want) => {
                assert_eq!(outcome, want, "{what}");
                assert!(thread.calls.is_empty() && thread.ready.is_empty(), "{what}");
                assert!(thread.history().as_array().unwrap().is_empty(), "{what}");
            }
            None => {
                assert!(matches!(outcome, Outcome::Result(_)), "{what}: {outcome:?}");
                assert_eq!(thread.node.soc_posts, 1, "{what}");
                assert_eq!(thread.vault.signed[0].key, SignKey::Publisher(1), "{what}");
            }
        }
    }
}

/// The feed store's change reaches no request mid-write: a change refused
/// by the store (`store-refusal`) changes nothing a request then reads.
#[test]
fn a_refused_change_changes_nothing_a_request_reads() {
    let text = text_of("keys.json");
    let index = Index::new(&text).unwrap();
    let keys = keys(&index);
    let mut thread = gate_thread(&keys);
    let before = thread.world.keeper.store().clone();
    let refused = FeedChange::CreateAppScopedIdentity {
        key: JsString::from(B),
        options: fc_json::parse(&format!(r#"{{"label":"{}"}}"#, "x".repeat(81))).unwrap(),
        source: Source::User,
    };
    assert!(matches!(thread.change(refused), Ran::Applied(Err(_))));
    assert_eq!(*thread.world.keeper.store(), before);
    raw_soc(&mut thread);
    assert!(matches!(thread.run(), Outcome::Result(_)));
}
