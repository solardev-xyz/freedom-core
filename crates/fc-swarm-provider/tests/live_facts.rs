//! The live facts (design 0015's D1): the page's name binding, its
//! document's key and Agent custody are one ask, [`Need::Live`], answered
//! [`Event::Live`], made at every effect's guard, before each signature,
//! at the reference's three `afterEffect` checks and before the answers
//! page-swarm.js gives only while the name answers.
//!
//! An honest main plays each method that asks them. At each of the
//! method's points, main's answer then says the name moved, the document
//! lost its key or custody was taken (and the world can change as it
//! answers: the rule off, the connection or a grant revoked), and the
//! request must answer exactly what the synchronous read gave at that
//! point: a guard in page-swarm.js's order (the name, then for a rule's
//! request custody and the rule, then the key, then the connection and the
//! grant), with nothing asked past a refusal but the row's own writes; a
//! re-check before a signature that reads the name and the key only; an
//! `afterEffect` that keeps what it writes only while the name and the key
//! hold, custody left out.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, HashMap, VecDeque};

use common::*;
use fc_json::index::Index;
use fc_json::{JsString, JsValue};
use fc_swarm_provider::machine::node::BodyOut;
use fc_swarm_provider::machine::{
    Approval, Ask, AskId, Body, Call, Effect, Event, Live, Mined, Need, NodeCall, OpenFailed,
    Outcome, Protocol, ReadyCheck, Request, SignKey, Signed, StoreWrite, Subscription,
    SubscriptionKind,
};
use fc_swarm_provider::stores::feeds::{FeedChange, Source};
use fc_swarm_provider::stores::manifests::Capability;
use fc_swarm_provider::value::{Bytes, BytesKind, Value};

const KEY: &str = "https://app.example";
const CLOCK: u64 = 1_767_225_600_000;
const STAMPS: &str = r#"{"stamps":[{"batchID":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","utilization":0,"usable":true,"label":"freedom","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000}]}"#;
const ADDRESSES: &str = r#"{"overlay":"36b7efd913ca4cf880b8eeac5093fa27b0825906c600685b6abdd6566e6cfe8f","underlay":["/ip4/127.0.0.1"],"ethereum":"0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0","publicKey":"039fd0991d0222b4e1339c1a1a5b5f6d9f6a96672a3247b638ee6156d9ea877a2f","pssPublicKey":"03c22c83fb49ab0ad897aa0c74e51311c95a3d1e1b27b2dedd7f42a7d2538c3a9e"}"#;
const TAG: &str = r#"{"uid":101,"split":10,"seen":2,"stored":10,"sent":5,"synced":3,"address":"ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB","startedAt":"2026-01-01T00:00:00Z"}"#;
const RECIPIENT: &str = "023263e186e68d31581a2ac1bec6ca730ba9b9e6b4a194dd78798a36271d0a4a0b";
/// The id main gives the subscriptions it opens.
const SUBSCRIPTION_ID: &str = "59820d1a24fddf7bceaad40b518018f0";
/// The first `/bzz` upload's tag (the fake node's).
const FIRST_TAG: u64 = 101;
/// A feed entry past one chunk, which goes to `POST /bytes` first.
const LARGE: usize = 5000;

fn key() -> JsString {
    JsString::from(KEY)
}

fn bytes(data: Vec<u8>) -> Value {
    Value::Bytes(Bytes {
        len: data.len() as u64,
        kind: BytesKind::Uint8Array,
        source: fc_swarm_provider::value::Source::Inline(data),
        data: true,
    })
}

fn large_entry() -> Vec<u8> {
    content("large entry", LARGE)
}

// ---------------------------------------------------------------------------
// An honest main.

/// What an ask was, as the log keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    Live,
    /// A node call, a signature, a search, a turn or a topic's lock: what
    /// a refusal must leave unasked.
    Effectful,
    /// A store write: a feed-store change.
    Feeds,
    /// A subscription's close.
    Close,
    /// The rest: readiness, the vault's owner, the history.
    Other,
}

/// Answers every ask honestly; the live facts as `live` says, by their
/// turn among the request's live asks.
struct Main {
    world: TestWorld,
    node: Node,
    keys: Keys,
    signers: HashMap<[u8; 32], u32>,
    rows: i64,
    log: Vec<Asked>,
    /// The subscriptions main opened and closed.
    opened: usize,
    closed: usize,
    /// Main's `{ failed }` to every open, when set.
    open_fails: Option<OpenFailed>,
}

type Script<'a> = &'a mut dyn FnMut(usize, &mut TestWorld) -> Live;

impl Main {
    fn new() -> Main {
        let text = text_of("keys.json");
        let index = Index::new(&text).unwrap();
        let mut world = TestWorld::new(CLOCK);
        world.grants.insert(key());
        world.messaging.insert(key());
        for capability in Capability::ALL {
            world.rules.insert((key(), capability.key()));
        }
        let options = fc_json::parse(r#"{"activate":true,"source":"user"}"#).unwrap();
        let create = FeedChange::CreateAppScopedIdentityAt {
            key: key(),
            index: JsValue::Number(world.feeds.next_publisher_key_index()),
            options,
            source: Source::User,
        };
        assert!(create.apply(&mut world.feeds, CLOCK).is_ok());
        let grant = FeedChange::GrantFeedAccess {
            key: key(),
            source: Source::User,
        };
        assert!(grant.apply(&mut world.feeds, CLOCK).is_ok());
        let entry = large_entry();
        let root = tree_of(&entry, &mut BTreeMap::new());
        let bytes_reply = ReplySpec {
            status: 201,
            status_text: "Created".to_owned(),
            body: format!(r#"{{"reference":"{}"}}"#, hex(&root.address())).into_bytes(),
            ..ReplySpec::ok(Vec::new(), "application/json; charset=utf-8")
        };
        let mut node = Node {
            stamps: Some(STAMPS.as_bytes().to_vec()),
            addresses: Some(ADDRESSES.as_bytes().to_vec()),
            ..Node::new()
        };
        node.tags
            .insert(FIRST_TAG.to_string(), TAG.as_bytes().to_vec());
        node.rules.push(Rule {
            method: Some("POST".to_owned()),
            path: Some("/bytes".to_owned()),
            prefix: None,
            reply: bytes_reply,
            world: Vec::new(),
        });
        // A feed's manifest.
        node.rules.push(Rule {
            method: Some("POST".to_owned()),
            path: None,
            prefix: Some("/feeds/".to_owned()),
            reply: ReplySpec {
                status: 201,
                status_text: "Created".to_owned(),
                body: format!(r#"{{"reference":"{}"}}"#, "5a".repeat(32)).into_bytes(),
                ..ReplySpec::ok(Vec::new(), "application/json; charset=utf-8")
            },
            world: Vec::new(),
        });
        Main {
            world,
            node,
            keys: keys(&index),
            signers: HashMap::new(),
            rows: 0,
            log: Vec::new(),
            opened: 0,
            closed: 0,
            open_fails: None,
        }
    }

    fn signing_key(&self, key: SignKey) -> &k256::ecdsa::SigningKey {
        match key {
            SignKey::BeeWallet => &self.keys.bee,
            SignKey::Publisher(index) => &self.keys.publishers[&u64::from(index)],
        }
    }

    /// Plays `call` to its outcome, the live facts every honest main gives
    /// (the world's) unless `live` says otherwise.
    fn honest(&mut self, call: &Call) -> Outcome {
        self.play(call, &mut |_, world| world.live())
    }

    fn play(&mut self, call: &Call, live: Script<'_>) -> Outcome {
        self.log.clear();
        let mut request = Request::start(call, &mut self.world).expect("a method with a machine");
        let mut queue: VecDeque<Effect> = request.take_effects().into();
        // Streamed bodies main is reading: the call and what came.
        let mut bodies: BTreeMap<AskId, (NodeCall, Vec<u8>)> = BTreeMap::new();
        let mut lives = 0;
        while request.outcome().is_none() {
            let effect = queue
                .pop_front()
                .expect("the request waits with nothing asked");
            let give = |request: &mut Request, world: &mut TestWorld, id, event| {
                request.answer(world, id, event);
                request.take_effects()
            };
            let more = match effect {
                Effect::Ask(ask) => self.answer(&mut request, ask, &mut bodies, &mut lives, live),
                Effect::Body { id, out } => match out {
                    BodyOut::Head { .. } => Vec::new(),
                    BodyOut::Data(data) => {
                        let len = data.len();
                        bodies.get_mut(&id).unwrap().1.extend(data);
                        give(&mut request, &mut self.world, id, Event::BodyCredit(len))
                    }
                    BodyOut::End => {
                        let (call, data) = bodies.remove(&id).unwrap();
                        let spec = self.node.upload(call.method(), &call.path, &data);
                        let mut more = Vec::new();
                        for event in forward(&spec, &call).1 {
                            more.extend(give(&mut request, &mut self.world, id, event));
                        }
                        more
                    }
                    BodyOut::Abort(_) => {
                        bodies.remove(&id);
                        Vec::new()
                    }
                },
                Effect::Cancel(_) | Effect::Credit { .. } => Vec::new(),
            };
            queue.extend(more);
        }
        request.outcome().unwrap().clone()
    }

    fn answer(
        &mut self,
        request: &mut Request,
        ask: Ask,
        bodies: &mut BTreeMap<AskId, (NodeCall, Vec<u8>)>,
        lives: &mut usize,
        live: Script<'_>,
    ) -> Vec<Effect> {
        let asked = match &ask.need {
            Need::Live => Asked::Live,
            Need::Node(_)
            | Need::Sign(_)
            | Need::Mine(_)
            | Need::Upload
            | Need::Lock(_)
            | Need::Subscribe(_) => Asked::Effectful,
            Need::Unsubscribe(_) => Asked::Close,
            Need::Write(StoreWrite::Feeds(_)) => Asked::Feeds,
            _ => Asked::Other,
        };
        self.log.push(asked);
        let events = match ask.need {
            Need::Ready(_) => vec![Event::Ready(Ok(()))],
            Need::Live => {
                assert_eq!(ask.charge, 0, "the live facts bring no bytes in");
                let facts = live(*lives, &mut self.world);
                *lives += 1;
                vec![Event::Live(facts)]
            }
            Need::Node(call) => {
                if let Some(Body::Stream { .. }) = call.body {
                    bodies.insert(ask.id, (call, Vec::new()));
                    vec![Event::BodyOpen]
                } else {
                    let spec = match &call.body {
                        Some(Body::Base64(data)) => {
                            self.node.upload(call.method(), &call.path, data)
                        }
                        _ => self.node.reply(call.method(), &call.path),
                    };
                    forward(&spec, &call).1
                }
            }
            Need::Owner(key) => {
                let owner = fc_evm::address_of(self.signing_key(key));
                vec![Event::Owner(Ok(Some(owner)))]
            }
            Need::Sign(soc) => {
                let signed = fc_swarm::sign_soc(
                    self.signing_key(soc.key),
                    &soc.identifier,
                    Some(soc.span),
                    &soc.payload,
                )
                .unwrap();
                vec![Event::Signed(Ok(Signed {
                    signature: signed.signature,
                    owner: signed.owner,
                }))]
            }
            Need::Mine(job) => {
                let index = *self.signers.entry(job.target).or_insert_with(|| {
                    fc_swarm::gsoc::mine(&job.target, &job.identifier, job.proximity)
                        .unwrap()
                        .index()
                });
                vec![Event::Mined(Mined::Found(index))]
            }
            Need::Upload => vec![Event::Turn],
            Need::Lock(_) => vec![Event::Locked],
            Need::Subscribe(_) => match &self.open_fails {
                Some(failed) => vec![Event::Opened(Err(failed.clone()))],
                None => {
                    self.opened += 1;
                    vec![Event::Opened(Ok(JsString::from(SUBSCRIPTION_ID)))]
                }
            },
            Need::Unsubscribe(id) => {
                assert_eq!(id, SUBSCRIPTION_ID, "main closes what it opened");
                self.closed += 1;
                vec![Event::Closed]
            }
            Need::Write(StoreWrite::HistoryInsert(_)) => {
                self.rows += 1;
                vec![Event::Inserted(Ok(self.rows))]
            }
            Need::Write(StoreWrite::Feeds(change)) => {
                let applied = change.apply(&mut self.world.feeds, CLOCK);
                vec![Event::Written(
                    applied
                        .map(|_| ())
                        .map_err(|e| JsString::from(format!("{e:?}"))),
                )]
            }
            Need::Write(_) => vec![Event::Written(Ok(()))],
            other => panic!("an ask these methods don't make: {other:?}"),
        };
        let mut more = Vec::new();
        for event in events {
            if request.outcome().is_some() {
                break;
            }
            request.answer(&mut self.world, ask.id, event);
            more.extend(request.take_effects());
        }
        more
    }

    /// The asks made after the `n`th live ask.
    fn after_live(&self, n: usize) -> &[Asked] {
        let at = self
            .log
            .iter()
            .enumerate()
            .filter(|(_, a)| **a == Asked::Live)
            .nth(n)
            .map(|(i, _)| i)
            .expect("the live ask");
        &self.log[at + 1..]
    }

    fn lives(&self) -> usize {
        self.log.iter().filter(|a| **a == Asked::Live).count()
    }
}

// ---------------------------------------------------------------------------
// The methods, and the points where each asks.

/// What the grant a guard checks last is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grant {
    Connection,
    Feeds,
    Messaging,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Point {
    /// An effect's guard.
    Guard(Grant),
    /// The re-check before a signature: the name and the key only.
    Recheck,
    /// `afterEffect`: what the write leaves under the key is kept only
    /// while the name and the key hold.
    After,
    /// An answer given only while the name and the key hold.
    Answer,
}

struct Method {
    what: &'static str,
    call: fn(Option<Approval>) -> Call,
    /// Main's own earlier requests the method needs (a feed, a tag).
    setup: fn(&mut Main),
    /// Whether a site's rule can answer it (`guardEffect`'s `rule`).
    ruled: bool,
    points: &'static [Point],
    /// What an `afterEffect` keeps, held now.
    kept: fn(&Main) -> bool,
}

fn call(method: &str, params: Value, approval: Option<Approval>) -> Call {
    Call {
        method: Value::str(method),
        params,
        key: key(),
        approval,
    }
}

fn no_setup(_: &mut Main) {}

fn nothing_kept(_: &Main) -> bool {
    false
}

fn a_feed(main: &mut Main) {
    let created = main.honest(&create_feed(Some(Approval::User)));
    assert!(matches!(created, Outcome::Result(_)), "{created:?}");
}

fn a_tag(main: &mut Main) {
    let published = main.honest(&publish_files(Some(Approval::User)));
    assert!(matches!(published, Outcome::Result(_)), "{published:?}");
    assert_eq!(main.world.tags.get(FIRST_TAG), Some(&key()));
}

fn feed_kept(main: &Main) -> bool {
    main.world
        .feeds
        .feed(&key(), &JsString::from("blog"))
        .is_some()
}

fn tag_kept(main: &Main) -> bool {
    main.world.tags.get(FIRST_TAG) == Some(&key())
}

fn reference_kept(main: &Main) -> bool {
    main.world
        .feeds
        .feed(&key(), &JsString::from("blog"))
        .and_then(|feed| feed.get("lastReference").cloned())
        == Some(JsValue::string("cd".repeat(32)))
}

fn publish_data(approval: Option<Approval>) -> Call {
    call(
        "swarm_publishData",
        Value::object([
            ("data", Value::str("hello")),
            ("contentType", Value::str("text/plain")),
        ]),
        approval,
    )
}

fn publish_chunk(approval: Option<Approval>) -> Call {
    call(
        "swarm_publishChunk",
        Value::object([("data", bytes(b"chunk".to_vec()))]),
        approval,
    )
}

fn publish_files(approval: Option<Approval>) -> Call {
    let file = Value::object([
        ("path", Value::str("index.html")),
        ("bytes", bytes(b"<p>hi</p>".to_vec())),
    ]);
    call(
        "swarm_publishFiles",
        Value::object([("files", Value::Array(vec![Some(file)]))]),
        approval,
    )
}

fn upload_status(approval: Option<Approval>) -> Call {
    call(
        "swarm_getUploadStatus",
        Value::object([("tagUid", Value::Number(FIRST_TAG as f64))]),
        approval,
    )
}

fn create_feed(approval: Option<Approval>) -> Call {
    call(
        "swarm_createFeed",
        Value::object([("name", Value::str("blog"))]),
        approval,
    )
}

fn update_feed(approval: Option<Approval>) -> Call {
    call(
        "swarm_updateFeed",
        Value::object([
            ("feedId", Value::str("blog")),
            ("reference", Value::str(&"cd".repeat(32))),
        ]),
        approval,
    )
}

fn write_entry(approval: Option<Approval>) -> Call {
    call(
        "swarm_writeFeedEntry",
        Value::object([("name", Value::str("blog")), ("data", Value::str("hi"))]),
        approval,
    )
}

fn write_large_entry(approval: Option<Approval>) -> Call {
    call(
        "swarm_writeFeedEntry",
        Value::object([("name", Value::str("blog")), ("data", bytes(large_entry()))]),
        approval,
    )
}

fn write_soc(approval: Option<Approval>) -> Call {
    call(
        "swarm_writeSingleOwnerChunk",
        Value::object([
            ("identifier", Value::str(&"42".repeat(32))),
            ("data", Value::str("x")),
        ]),
        approval,
    )
}

fn signing_identity(approval: Option<Approval>) -> Call {
    call("swarm_getSigningIdentity", Value::Undefined, approval)
}

fn send_pss(approval: Option<Approval>) -> Call {
    call(
        "swarm_sendPss",
        Value::object([
            ("topic", Value::str("chat")),
            ("recipient", Value::str(RECIPIENT)),
            ("targets", Value::str("abcd")),
            ("data", Value::str("hi")),
        ]),
        approval,
    )
}

fn send_gsoc(approval: Option<Approval>) -> Call {
    call(
        "swarm_sendGsoc",
        Value::object([("topic", Value::str("chat")), ("data", Value::str("hi"))]),
        approval,
    )
}

fn subscribe(approval: Option<Approval>) -> Call {
    call(
        "swarm_subscribe",
        Value::object([("kind", Value::str("pss")), ("topic", Value::str("chat"))]),
        approval,
    )
}

fn messaging_identity(approval: Option<Approval>) -> Call {
    call("swarm_getMessagingIdentity", Value::Undefined, approval)
}

const FEEDS: Point = Point::Guard(Grant::Feeds);

fn methods() -> Vec<Method> {
    let method = |what, call, points| Method {
        what,
        call,
        setup: no_setup,
        ruled: true,
        points,
        kept: nothing_kept,
    };
    vec![
        method(
            "publishData",
            publish_data,
            &[Point::Guard(Grant::Connection)],
        ),
        method(
            "publishChunk",
            publish_chunk,
            &[Point::Guard(Grant::Connection)],
        ),
        Method {
            kept: tag_kept,
            ..method(
                "publishFiles",
                publish_files,
                &[Point::Guard(Grant::Connection), Point::After],
            )
        },
        Method {
            setup: a_tag,
            ruled: false,
            ..method("getUploadStatus", upload_status, &[Point::Answer])
        },
        Method {
            kept: feed_kept,
            ..method("createFeed", create_feed, &[FEEDS, Point::After])
        },
        Method {
            setup: a_feed,
            ..method("createFeed of a feed it has", create_feed, &[FEEDS])
        },
        Method {
            setup: a_feed,
            kept: reference_kept,
            ..method(
                "updateFeed",
                update_feed,
                &[Point::Recheck, FEEDS, Point::After],
            )
        },
        Method {
            setup: a_feed,
            ..method("writeFeedEntry", write_entry, &[Point::Recheck, FEEDS])
        },
        Method {
            setup: a_feed,
            ..method(
                "writeFeedEntry past a chunk",
                write_large_entry,
                &[FEEDS, Point::Recheck, FEEDS],
            )
        },
        method("writeSingleOwnerChunk", write_soc, &[Point::Recheck, FEEDS]),
        method("getSigningIdentity", signing_identity, &[FEEDS]),
        method(
            "sendPss",
            send_pss,
            &[
                Point::Guard(Grant::Messaging),
                Point::Guard(Grant::Messaging),
            ],
        ),
        method(
            "sendGsoc",
            send_gsoc,
            &[
                Point::Guard(Grant::Messaging),
                Point::Guard(Grant::Messaging),
            ],
        ),
        Method {
            ruled: false,
            ..method(
                "subscribe",
                subscribe,
                &[Point::Guard(Grant::Messaging), Point::Answer],
            )
        },
        Method {
            ruled: false,
            ..method("getMessagingIdentity", messaging_identity, &[Point::Answer])
        },
    ]
}

// ---------------------------------------------------------------------------
// The checks.

fn facts(name: bool, live: bool, agent: bool) -> Live {
    Live { name, live, agent }
}

/// The page's error's `data.reason`, or what else the request answered.
fn answered(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Result(_) => "result".to_owned(),
        Outcome::Error(failure) => failure
            .data
            .as_ref()
            .and_then(|d| {
                d.get("reason")
                    .as_js_string()
                    .map(|r| r.as_str().to_owned())
            })
            .unwrap_or_else(|| failure.message.as_str().to_owned()),
        Outcome::Cancelled => "cancelled".to_owned(),
        Outcome::Protocol(p) => format!("protocol: {p}"),
    }
}

/// A change to the world as main answers the live facts.
#[derive(Debug, Clone, Copy)]
enum Change {
    None,
    RuleOff,
    Disconnect,
    RevokeGrant,
}

fn change(world: &mut TestWorld, change: Change, grant: Grant, ruled: Capability) {
    match change {
        Change::None => {}
        Change::RuleOff => {
            world.rules.remove(&(key(), ruled.key()));
        }
        Change::Disconnect => {
            world.grants.remove(&key());
        }
        Change::RevokeGrant => match grant {
            Grant::Connection => {
                world.grants.remove(&key());
            }
            Grant::Feeds => {
                let revoke = FeedChange::RevokeFeedAccess {
                    key: key(),
                    source: Source::User,
                };
                assert!(revoke.apply(&mut world.feeds, CLOCK).is_ok());
            }
            Grant::Messaging => {
                world.messaging.remove(&key());
            }
        },
    }
}

/// The capability a method's rule is for.
fn capability(what: &str) -> Capability {
    match what {
        w if w.starts_with("publish") => Capability::Publish,
        w if w.starts_with("send") || w == "subscribe" => Capability::Messaging,
        "writeSingleOwnerChunk" | "getSigningIdentity" => Capability::Signing,
        _ => Capability::Feeds,
    }
}

/// One answer at point `n`: the request's outcome, and whether what it
/// asked after that answer is what the expected outcome allows.
fn play_at(
    method: &Method,
    n: usize,
    approval: Option<Approval>,
    at: Live,
    world_change: Change,
    grant: Grant,
) -> (String, Main) {
    let mut main = Main::new();
    (method.setup)(&mut main);
    let ruled = capability(method.what);
    let mut script = |turn: usize, world: &mut TestWorld| {
        if turn == n {
            change(world, world_change, grant, ruled);
            at
        } else {
            world.live()
        }
    };
    let outcome = main.play(&(method.call)(approval), &mut script);
    (answered(&outcome), main)
}

/// Each method asks the live facts once at each of its points, and an
/// honest run answers.
#[test]
fn each_method_asks_once_at_each_point() {
    for method in methods() {
        for approval in [Some(Approval::User), Some(Approval::Auto)] {
            let mut main = Main::new();
            (method.setup)(&mut main);
            let outcome = main.honest(&(method.call)(approval));
            assert!(
                matches!(outcome, Outcome::Result(_)),
                "{}: {outcome:?}",
                method.what
            );
            assert_eq!(main.lives(), method.points.len(), "{}", method.what);
            if method.points.contains(&Point::After) {
                assert!((method.kept)(&main), "{}: kept", method.what);
            }
        }
    }
}

/// At each guard, the live facts in page-swarm.js's order: the name, then
/// for a rule's request custody and the rule, then the document's key,
/// then the connection and the grant; a refusal there asks nothing past
/// it but the row's writes.
#[test]
fn each_guard_reads_them_in_the_references_order() {
    let mut points = 0;
    for method in methods() {
        for (n, point) in method.points.iter().enumerate() {
            let Point::Guard(grant) = *point else {
                continue;
            };
            points += 1;
            let auto = Some(Approval::Auto);
            let user = Some(Approval::User);
            // A request no rule can answer (`subscribe`) reads no custody
            // and no rule.
            let custody = if method.ruled {
                "agent_custody"
            } else {
                "no_address"
            };
            let rule_off = if method.ruled {
                "not_auto_approved"
            } else {
                "no_address"
            };
            let last = match grant {
                Grant::Connection | Grant::Feeds => "not_connected",
                Grant::Messaging => "messaging_not_granted",
            };
            let granted = match grant {
                Grant::Connection => "not_connected",
                Grant::Feeds => "feed_not_granted",
                Grant::Messaging => "messaging_not_granted",
            };
            let cases = [
                (
                    "the name first",
                    auto,
                    facts(false, false, true),
                    Change::RuleOff,
                    "no_address",
                ),
                (
                    "custody before the key",
                    auto,
                    facts(true, false, true),
                    Change::None,
                    custody,
                ),
                (
                    "the rule before the key",
                    auto,
                    facts(true, false, false),
                    Change::RuleOff,
                    rule_off,
                ),
                (
                    "the key",
                    auto,
                    facts(true, false, false),
                    Change::None,
                    "no_address",
                ),
                (
                    "no custody without a rule",
                    user,
                    facts(true, false, true),
                    Change::RuleOff,
                    "no_address",
                ),
                (
                    "the key before the connection",
                    user,
                    facts(true, false, false),
                    Change::Disconnect,
                    "no_address",
                ),
                (
                    "the connection",
                    user,
                    facts(true, true, false),
                    Change::Disconnect,
                    last,
                ),
                (
                    "the grant",
                    user,
                    facts(true, true, false),
                    Change::RevokeGrant,
                    granted,
                ),
                (
                    "custody of a prompt's request",
                    user,
                    facts(true, true, true),
                    Change::RuleOff,
                    "pass",
                ),
            ];
            for (what, approval, at, world_change, want) in cases {
                let (got, main) = play_at(&method, n, approval, at, world_change, grant);
                let label = format!("{} guard {n}, {what}", method.what);
                if want == "pass" {
                    assert_eq!(got, "result", "{label}");
                    continue;
                }
                assert_eq!(got, want, "{label}");
                let after = main.after_live(n);
                assert!(
                    after.iter().all(|a| *a == Asked::Other),
                    "{label}: asked past the refusal: {after:?}"
                );
            }
        }
    }
    assert_eq!(points, 16, "every guard point");
}

/// Before a signature, the name and the document again; custody and the
/// rule wait for the upload's guard. A refusal signs nothing.
#[test]
fn the_recheck_before_a_signature_reads_the_name_and_the_key() {
    let mut points = 0;
    for method in methods() {
        for (n, point) in method.points.iter().enumerate() {
            if *point != Point::Recheck {
                continue;
            }
            points += 1;
            let auto = Some(Approval::Auto);
            for (what, at, want) in [
                ("the name moved", facts(false, true, false), "no_address"),
                ("the key gone", facts(true, false, false), "no_address"),
                ("custody taken", facts(true, true, true), "result"),
            ] {
                let (got, main) = play_at(&method, n, auto, at, Change::None, Grant::Feeds);
                let label = format!("{} re-check {n}, {what}", method.what);
                assert_eq!(got, want, "{label}");
                let after = main.after_live(n);
                if want == "result" {
                    assert_eq!(after.first(), Some(&Asked::Effectful), "{label}: signed");
                } else {
                    assert!(
                        after.iter().all(|a| *a == Asked::Other),
                        "{label}: asked past the refusal: {after:?}"
                    );
                }
            }
        }
    }
    assert_eq!(points, 4, "every signature");
}

/// `afterEffect` keeps what the write leaves under the key only while the
/// name and the key hold, custody left out; the effect stands either way.
#[test]
fn after_an_effect_custody_is_left_out() {
    let mut points = 0;
    for method in methods() {
        for (n, point) in method.points.iter().enumerate() {
            if *point != Point::After {
                continue;
            }
            points += 1;
            for (what, approval, at, kept) in [
                (
                    "custody taken",
                    Some(Approval::Auto),
                    facts(true, true, true),
                    true,
                ),
                (
                    "the name moved",
                    Some(Approval::User),
                    facts(false, true, false),
                    false,
                ),
                (
                    "the key gone",
                    Some(Approval::User),
                    facts(true, false, false),
                    false,
                ),
            ] {
                let (got, main) = play_at(&method, n, approval, at, Change::None, Grant::Feeds);
                let label = format!("{} afterEffect, {what}", method.what);
                assert_eq!(got, "result", "{label}");
                assert_eq!((method.kept)(&main), kept, "{label}: kept");
                let after = main.after_live(n);
                let wrote = after.contains(&Asked::Feeds);
                assert!(
                    after
                        .iter()
                        .all(|a| matches!(a, Asked::Other | Asked::Feeds)),
                    "{label}: {after:?}"
                );
                if method.what != "publishFiles" {
                    assert_eq!(wrote, kept, "{label}: the record's write");
                }
            }
        }
    }
    assert_eq!(points, 3, "the reference's three afterEffect checks");
}

/// What reveals or reads under the key goes out only while the name and the
/// key hold, custody left out.
#[test]
fn an_answer_under_the_key_waits_for_them() {
    let mut points = 0;
    for method in methods() {
        for (n, point) in method.points.iter().enumerate() {
            if *point != Point::Answer {
                continue;
            }
            points += 1;
            for (what, at, want) in [
                ("custody taken", facts(true, true, true), "result"),
                ("the name moved", facts(false, true, false), "no_address"),
                ("the key gone", facts(true, false, false), "no_address"),
            ] {
                let (got, main) = play_at(&method, n, None, at, Change::None, Grant::Connection);
                assert_eq!(got, want, "{} answer, {what}", method.what);
                // A subscription the page doesn't get is closed.
                let kept = if want == "result" { main.opened } else { 0 };
                assert_eq!(
                    main.closed,
                    main.opened - kept,
                    "{} answer, {what}",
                    method.what
                );
            }
        }
    }
    assert_eq!(points, 3);
}

/// page-swarm.js's `uploadStatus` asks the name after `executeSwarmMethod`
/// whatever it answered: a name that moved (or a key gone) answers
/// `NO_ADDRESS` before a failed tag read, a tag that isn't the site's
/// (another site's, or its own forgotten past the bound), a refused
/// `tagUid` or the connection's refusal; with the name holding, each keeps
/// its own answer. Each asks the live facts once, and a refused tag makes
/// no `tag` call.
#[test]
fn upload_status_answers_no_address_first_whatever_its_handler_said() {
    fn read_fails(main: &mut Main) {
        main.node.rules.insert(
            0,
            Rule {
                method: Some("GET".to_owned()),
                path: Some(format!("/tags/{FIRST_TAG}")),
                prefix: None,
                reply: ReplySpec {
                    status: 500,
                    status_text: "Internal Server Error".to_owned(),
                    body: br#"{"code":500,"message":"Internal Server Error"}"#.to_vec(),
                    ..ReplySpec::ok(Vec::new(), "application/json; charset=utf-8")
                },
                world: Vec::new(),
            },
        );
    }
    fn another_sites(main: &mut Main) {
        main.world
            .tags
            .set(FIRST_TAG, JsString::from("https://other.example"));
    }
    fn forgotten(main: &mut Main) {
        // tag-owners-bound: 4,096 newer tags forget the site's.
        for tag in 1..=4096 {
            main.world
                .tags
                .set(FIRST_TAG + tag, JsString::from("https://other.example"));
        }
        assert_eq!(main.world.tags.get(FIRST_TAG), None);
    }
    fn disconnected(main: &mut Main) {
        main.world.grants.remove(&key());
    }
    let status = upload_status(None);
    let zero = call(
        "swarm_getUploadStatus",
        Value::object([("tagUid", Value::Number(0.0))]),
        None,
    );
    /// What, the world before it, the call, the answer while the name
    /// holds, and whether the tag is read.
    type Case<'c> = (&'static str, fn(&mut Main), &'c Call, &'static str, bool);
    let cases: [Case<'_>; 6] = [
        ("the status", no_setup, &status, "result", true),
        (
            "a failed tag read",
            read_fails,
            &status,
            "Internal Server Error",
            true,
        ),
        (
            "another site's tag",
            another_sites,
            &status,
            "tag_ownership_mismatch",
            false,
        ),
        (
            "its tag forgotten past the bound",
            forgotten,
            &status,
            "tag_ownership_mismatch",
            false,
        ),
        ("a refused tagUid", no_setup, &zero, "invalid_params", false),
        (
            "no connection",
            disconnected,
            &status,
            "not_connected",
            false,
        ),
    ];
    for (what, setup, call, holding, reads) in cases {
        for (facts_now, want) in [
            (facts(true, true, true), holding),
            (facts(false, true, false), "no_address"),
            (facts(true, false, false), "no_address"),
        ] {
            let mut main = Main::new();
            a_tag(&mut main);
            setup(&mut main);
            let outcome = main.play(call, &mut |_, _| facts_now);
            let got = answered(&outcome);
            let label = format!("{what}, {facts_now:?}");
            assert!(got.starts_with(want), "{label}: {got}");
            assert_eq!(main.lives(), 1, "{label}: one live check");
            assert_eq!(
                main.log.contains(&Asked::Effectful),
                reads,
                "{label}: the tag call"
            );
            assert_eq!(
                main.log.last(),
                Some(&Asked::Live),
                "{label}: the live facts last"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The ask under the framework's rules.

/// Runs `publishData` honestly up to its guard's ask.
fn to_the_guard(main: &mut Main) -> (Request, AskId) {
    let mut request = Request::start(&publish_data(Some(Approval::User)), &mut main.world).unwrap();
    let mut queue: VecDeque<Effect> = request.take_effects().into();
    let mut bodies = BTreeMap::new();
    let mut lives = 0;
    while let Some(effect) = queue.pop_front() {
        let Effect::Ask(ask) = effect else {
            continue;
        };
        if ask.need == Need::Live {
            return (request, ask.id);
        }
        let more = main.answer(&mut request, ask, &mut bodies, &mut lives, &mut |_, w| {
            w.live()
        });
        queue.extend(more);
    }
    panic!("no live ask: {:?}", request.outcome())
}

/// The ask takes only its own kind of answer, and its answer goes to no
/// other ask: either is a protocol error.
#[test]
fn the_ask_is_read_strictly() {
    for wrong in [
        Event::Locked,
        Event::Turn,
        Event::Ready(Ok(())),
        Event::Owner(Ok(None)),
        Event::Written(Ok(())),
    ] {
        let mut main = Main::new();
        let (mut request, live) = to_the_guard(&mut main);
        request.answer(&mut main.world, live, wrong.clone());
        assert_eq!(
            request.outcome(),
            Some(&Outcome::Protocol(Protocol::WrongKind)),
            "{wrong:?}"
        );
    }
    // The live facts answering a readiness check.
    let mut main = Main::new();
    let mut request = Request::start(&publish_data(Some(Approval::User)), &mut main.world).unwrap();
    let Some(Effect::Ask(ready)) = request.take_effects().pop() else {
        panic!("the readiness check")
    };
    assert_eq!(ready.need, Need::Ready(ReadyCheck::Publish));
    request.answer(
        &mut main.world,
        ready.id,
        Event::Live(facts(true, true, false)),
    );
    assert_eq!(
        request.outcome(),
        Some(&Outcome::Protocol(Protocol::WrongKind))
    );
}

/// A cancel while the live facts are asked cancels the ask, ends the row
/// `failed` with `cancelled`, and drops the late answer: nothing more is
/// asked, and the upload never goes.
#[test]
fn a_cancel_cancels_the_ask_and_drops_its_answer() {
    let mut main = Main::new();
    let (mut request, live) = to_the_guard(&mut main);
    request.cancel();
    assert_eq!(request.outcome(), Some(&Outcome::Cancelled));
    let effects = request.take_effects();
    assert!(effects.contains(&Effect::Cancel(live)), "{effects:?}");
    let rows: Vec<_> = effects
        .iter()
        .filter_map(|e| match e {
            Effect::Ask(Ask {
                need: Need::Write(StoreWrite::History(statements)),
                ..
            }) => Some(statements),
            _ => None,
        })
        .collect();
    assert_eq!(rows.len(), 1, "the row ends failed: {effects:?}");
    let open = request.open_asks();
    request.answer(&mut main.world, live, Event::Live(facts(true, true, false)));
    assert_eq!(
        request.open_asks(),
        open - 1,
        "the ask closed on its answer"
    );
    assert!(
        request.take_effects().is_empty(),
        "nothing after the late answer"
    );
    assert_eq!(request.outcome(), Some(&Outcome::Cancelled));
    // A wrong kind after the outcome changes nothing either.
    request.answer(&mut main.world, live, Event::Turn);
    assert_eq!(request.outcome(), Some(&Outcome::Cancelled));
}

// ---------------------------------------------------------------------------
// Running to an ask, and what a request leaves when it ends there.

impl Main {
    /// Plays `call` honestly until the ask `stop` picks (given how many live
    /// asks came before it), which is taken but not answered.
    fn run_to(&mut self, call: &Call, stop: impl Fn(&Need, usize) -> bool) -> (Request, Ask) {
        self.log.clear();
        let mut request = Request::start(call, &mut self.world).expect("a method with a machine");
        let mut queue: VecDeque<Effect> = request.take_effects().into();
        let mut bodies: BTreeMap<AskId, (NodeCall, Vec<u8>)> = BTreeMap::new();
        let mut lives = 0;
        while let Some(effect) = queue.pop_front() {
            let more = match effect {
                Effect::Ask(ask) => {
                    if stop(&ask.need, lives) {
                        return (request, ask);
                    }
                    self.answer(&mut request, ask, &mut bodies, &mut lives, &mut |_, w| {
                        w.live()
                    })
                }
                Effect::Body { id, out } => match out {
                    BodyOut::Data(data) => {
                        let len = data.len();
                        bodies.get_mut(&id).unwrap().1.extend(data);
                        request.answer(&mut self.world, id, Event::BodyCredit(len));
                        request.take_effects()
                    }
                    BodyOut::End => {
                        let (call, data) = bodies.remove(&id).unwrap();
                        let spec = self.node.upload(call.method(), &call.path, &data);
                        let mut more = Vec::new();
                        for event in forward(&spec, &call).1 {
                            request.answer(&mut self.world, id, event);
                            more.extend(request.take_effects());
                        }
                        more
                    }
                    BodyOut::Head { .. } | BodyOut::Abort(_) => Vec::new(),
                },
                Effect::Cancel(_) | Effect::Credit { .. } => Vec::new(),
            };
            queue.extend(more);
        }
        panic!("no such ask: {:?}", request.outcome())
    }
}

/// The history rows a request's effects end `failed` with `text`.
fn rows_failed(effects: &[Effect], text: &str) -> usize {
    use fc_swarm_provider::stores::history::Bind;
    effects
        .iter()
        .filter(|e| {
            matches!(e, Effect::Ask(Ask {
                need: Need::Write(StoreWrite::History(statements)),
                ..
            }) if statements.iter().any(|s| {
                s.params.contains(&Bind::Text("failed".to_owned()))
                    && s.params.contains(&Bind::Text(text.to_owned()))
            }))
        })
        .count()
}

/// A cancel while an `afterEffect`'s live facts are asked (the effect
/// already made): the request answers `cancelled`, the ask is cancelled,
/// the row ends `failed` with `cancelled`, and nothing is kept under the
/// key, even when the late answer says the name still holds, which is
/// dropped.
#[test]
fn a_cancel_at_an_after_effect_keeps_nothing_and_fails_the_row() {
    /// What, main's earlier requests, the call, the live asks before the
    /// `afterEffect`'s, and what it keeps.
    type Case = (
        &'static str,
        fn(&mut Main),
        fn(Option<Approval>) -> Call,
        usize,
        fn(&Main) -> bool,
    );
    let cases: [Case; 3] = [
        (
            "publishFiles' tag owner",
            no_setup,
            publish_files,
            1,
            tag_kept,
        ),
        ("createFeed's record", no_setup, create_feed, 1, feed_kept),
        (
            "updateFeed's reference",
            a_feed,
            update_feed,
            2,
            reference_kept,
        ),
    ];
    for (what, setup, call, before, kept) in cases {
        let mut main = Main::new();
        setup(&mut main);
        let (mut request, live) = main.run_to(&call(Some(Approval::User)), |need, lives| {
            *need == Need::Live && lives == before
        });
        // The effect is made: its upload went before this ask.
        assert!(main.log.contains(&Asked::Effectful), "{what}");
        request.cancel();
        assert_eq!(request.outcome(), Some(&Outcome::Cancelled), "{what}");
        let effects = request.take_effects();
        assert!(
            effects.contains(&Effect::Cancel(live.id)),
            "{what}: {effects:?}"
        );
        assert_eq!(
            rows_failed(&effects, "cancelled"),
            1,
            "{what}: the row: {effects:?}"
        );
        let open = request.open_asks();
        request.answer(
            &mut main.world,
            live.id,
            Event::Live(facts(true, true, false)),
        );
        assert_eq!(request.open_asks(), open - 1, "{what}: the ask closed");
        assert!(
            request.take_effects().is_empty(),
            "{what}: the late answer dropped"
        );
        assert!(!kept(&main), "{what}: nothing kept under the key");
        assert_eq!(request.outcome(), Some(&Outcome::Cancelled), "{what}");
    }
}

fn pss_key() -> [u8; 32] {
    fc_evm::keccak256(b"chat")
}

/// A subscription opens inside the request (D16): its guard, then main's
/// open, then the live facts again; the page gets the reference's result
/// with main's id.
#[test]
fn a_subscription_opens_then_asks_the_name() {
    let mut main = Main::new();
    let outcome = main.honest(&subscribe(None));
    let Outcome::Result(result) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(
        result,
        Value::object([
            ("subscriptionId", Value::str(SUBSCRIPTION_ID)),
            ("kind", Value::str("pss")),
            ("key", Value::str(&hex(&pss_key()))),
        ])
    );
    assert_eq!(
        main.log,
        [Asked::Other, Asked::Live, Asked::Effectful, Asked::Live],
        "readiness, the guard, the open, the name"
    );
    assert_eq!((main.opened, main.closed), (1, 0));
    // What main opens: the kind and the topic's key.
    let (_, open) = main.run_to(&subscribe(None), |need, _| {
        matches!(need, Need::Subscribe(_))
    });
    assert_eq!(
        open.need,
        Need::Subscribe(Subscription {
            kind: SubscriptionKind::Pss,
            key: pss_key(),
        })
    );
    assert_eq!(open.charge, 0);
}

/// After the open, a moved name or a lost key closes the subscription and
/// answers `NO_ADDRESS` once main has closed it; custody isn't read.
#[test]
fn a_subscription_the_name_lost_is_closed() {
    for (what, after_open, want, closed) in [
        ("the name moved", facts(false, true, false), "no_address", 1),
        ("the key gone", facts(true, false, false), "no_address", 1),
        ("custody taken", facts(true, true, true), "result", 0),
    ] {
        let mut main = Main::new();
        let outcome = main.play(&subscribe(Some(Approval::Auto)), &mut |turn, world| {
            if turn == 1 { after_open } else { world.live() }
        });
        assert_eq!(answered(&outcome), want, "{what}");
        assert_eq!((main.opened, main.closed), (1, closed), "{what}");
        if closed == 1 {
            assert_eq!(
                main.log.last(),
                Some(&Asked::Close),
                "{what}: closed, then answered"
            );
        }
    }
    // The answer waits for the close.
    let mut main = Main::new();
    let (mut request, live) = main.run_to(&subscribe(None), |need, lives| {
        *need == Need::Live && lives == 1
    });
    request.answer(
        &mut main.world,
        live.id,
        Event::Live(facts(false, true, false)),
    );
    assert_eq!(request.outcome(), None);
    let effects = request.take_effects();
    let [Effect::Ask(close)] = &effects[..] else {
        panic!("{effects:?}")
    };
    assert_eq!(
        close.need,
        Need::Unsubscribe(JsString::from(SUBSCRIPTION_ID))
    );
    request.answer(&mut main.world, close.id, Event::Closed);
    assert_eq!(answered(request.outcome().unwrap()), "no_address");
}

/// A subscription that doesn't open answers as `subscribeError` does, and
/// nothing more is asked.
#[test]
fn a_failed_open_answers_as_subscribe_error() {
    let failed = |reason: Option<&str>, message: &str| OpenFailed {
        reason: reason.map(JsString::from),
        message: JsString::from(message),
    };
    let unavailable = |message: &str, reason: &str| {
        (
            4900,
            message.to_owned(),
            Some(Value::object([("reason", Value::str(reason))])),
        )
    };
    let cases = [
        (
            failed(
                Some("establish_timeout"),
                "Subscription did not establish within 10000ms",
            ),
            unavailable(
                "Subscription did not establish within 10000ms",
                "establish_timeout",
            ),
        ),
        (
            failed(
                Some("subscription_cancelled"),
                "Subscription was cancelled before it was established",
            ),
            unavailable(
                "Subscription was cancelled before it was established",
                "subscription_cancelled",
            ),
        ),
        (
            failed(Some("cancelled"), "Subscription cancelled"),
            unavailable("Subscription cancelled", "cancelled"),
        ),
        (
            failed(
                Some("too_many_subscriptions"),
                "Origin has reached the maximum of 32 subscriptions",
            ),
            (
                -32602,
                "Origin has reached the maximum of 32 subscriptions".to_owned(),
                Some(Value::object([
                    ("reason", Value::str("too_many_subscriptions")),
                    ("limit", Value::int(32)),
                ])),
            ),
        ),
        (
            failed(
                Some("node_subscription_limit"),
                "Node subscription limit reached",
            ),
            unavailable(
                "Node subscription capacity exhausted: Node subscription limit reached",
                "node_subscription_limit",
            ),
        ),
        (
            failed(None, "socket hang up"),
            (-32603, "socket hang up".to_owned(), None),
        ),
        (
            failed(Some("other"), "Unexpected server response: 500"),
            (-32603, "Unexpected server response: 500".to_owned(), None),
        ),
    ];
    for (open, (code, message, data)) in cases {
        let mut main = Main::new();
        main.open_fails = Some(open.clone());
        let outcome = main.honest(&subscribe(None));
        let Outcome::Error(failure) = outcome else {
            panic!("{open:?}: {outcome:?}")
        };
        assert_eq!(failure.code, code, "{open:?}");
        assert_eq!(failure.message.as_str(), message, "{open:?}");
        assert_eq!(failure.data, data, "{open:?}");
        assert_eq!(
            main.log.last(),
            Some(&Asked::Effectful),
            "{open:?}: nothing after"
        );
    }
}

/// `subscribe` up to main's close, the name having moved after the open.
fn to_the_close(main: &mut Main) -> (Request, Ask) {
    let (mut request, live) = main.run_to(&subscribe(None), |need, lives| {
        *need == Need::Live && lives == 1
    });
    request.answer(
        &mut main.world,
        live.id,
        Event::Live(facts(false, true, false)),
    );
    assert!(request.outcome().is_none());
    let mut effects = request.take_effects();
    let Some(Effect::Ask(close)) = effects.pop() else {
        panic!("the close")
    };
    assert!(effects.is_empty());
    assert_eq!(
        close.need,
        Need::Unsubscribe(JsString::from(SUBSCRIPTION_ID))
    );
    (request, close)
}

/// A request that ends while main opens or holds its subscription closes
/// what main opened: a cancel before the open asks nothing of it; one
/// while it opens closes what the open answers; one after it closes it
/// at once; one while main closes it leaves the close to finish.
#[test]
fn a_cancel_closes_what_main_opened() {
    let close_of = |effects: &[Effect]| {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::Ask(
                    ask @ Ask {
                        need: Need::Unsubscribe(id),
                        ..
                    },
                ) => {
                    assert_eq!(id, SUBSCRIPTION_ID);
                    Some(ask.id)
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let opened = || Event::Opened(Ok(JsString::from(SUBSCRIPTION_ID)));

    // Before the open: the guard's ask is cancelled, nothing opened.
    let mut main = Main::new();
    let (mut request, guard) = main.run_to(&subscribe(None), |need, _| *need == Need::Live);
    request.cancel();
    let effects = request.take_effects();
    assert_eq!(effects, [Effect::Cancel(guard.id)]);
    request.answer(
        &mut main.world,
        guard.id,
        Event::Live(facts(true, true, false)),
    );
    assert!(request.take_effects().is_empty(), "nothing opened");
    assert_eq!(request.open_asks(), 0);

    // While it opens: the open is cancelled, and what it opens is closed.
    for late in [
        opened(),
        Event::Opened(Err(OpenFailed {
            reason: Some(JsString::from("cancelled")),
            message: JsString::from("cancelled"),
        })),
    ] {
        let mut main = Main::new();
        let (mut request, open) = main.run_to(&subscribe(None), |need, _| {
            matches!(need, Need::Subscribe(_))
        });
        request.cancel();
        assert_eq!(request.take_effects(), [Effect::Cancel(open.id)]);
        assert_eq!(request.outcome(), Some(&Outcome::Cancelled));
        let closes = matches!(late, Event::Opened(Ok(_)));
        request.answer(&mut main.world, open.id, late);
        let effects = request.take_effects();
        let close = close_of(&effects);
        assert_eq!(close.len(), usize::from(closes), "{effects:?}");
        if let Some(close) = close.first() {
            request.answer(&mut main.world, *close, Event::Closed);
        }
        assert!(request.take_effects().is_empty());
        assert_eq!(request.open_asks(), 0);
        assert_eq!(request.outcome(), Some(&Outcome::Cancelled));
    }

    // After it, while the name is asked: closed at once; the late live
    // facts dropped.
    let mut main = Main::new();
    let (mut request, live) = main.run_to(&subscribe(None), |need, lives| {
        *need == Need::Live && lives == 1
    });
    request.cancel();
    let effects = request.take_effects();
    assert!(effects.contains(&Effect::Cancel(live.id)), "{effects:?}");
    let close = close_of(&effects);
    assert_eq!(close.len(), 1, "{effects:?}");
    assert!(
        !effects.contains(&Effect::Cancel(close[0])),
        "a close isn't called back"
    );
    request.answer(
        &mut main.world,
        live.id,
        Event::Live(facts(true, true, false)),
    );
    request.answer(&mut main.world, close[0], Event::Closed);
    assert!(request.take_effects().is_empty());
    assert_eq!(request.open_asks(), 0);
    assert_eq!(request.outcome(), Some(&Outcome::Cancelled));

    // While main closes it: the close isn't called back.
    let mut main = Main::new();
    let (mut request, close) = to_the_close(&mut main);
    request.cancel();
    assert!(request.take_effects().is_empty(), "the close goes on");
    request.answer(&mut main.world, close.id, Event::Closed);
    assert_eq!(request.open_asks(), 0);
    assert_eq!(request.outcome(), Some(&Outcome::Cancelled));
}

/// Both new asks are read strictly; a protocol error after the open still
/// closes the subscription.
#[test]
fn the_open_and_the_close_are_read_strictly() {
    let mut main = Main::new();
    let (mut request, open) = main.run_to(&subscribe(None), |need, _| {
        matches!(need, Need::Subscribe(_))
    });
    request.answer(&mut main.world, open.id, Event::Closed);
    assert_eq!(
        request.outcome(),
        Some(&Outcome::Protocol(Protocol::WrongKind))
    );

    let mut main = Main::new();
    let (mut request, live) = main.run_to(&subscribe(None), |need, lives| {
        *need == Need::Live && lives == 1
    });
    request.answer(
        &mut main.world,
        live.id,
        Event::Opened(Ok(JsString::from("x"))),
    );
    assert_eq!(
        request.outcome(),
        Some(&Outcome::Protocol(Protocol::WrongKind))
    );
    let effects = request.take_effects();
    assert!(
        effects.iter().any(|e| matches!(e, Effect::Ask(Ask {
            need: Need::Unsubscribe(id),
            ..
        }) if id == SUBSCRIPTION_ID)),
        "{effects:?}"
    );

    let mut main = Main::new();
    let (mut request, close) = to_the_close(&mut main);
    request.answer(&mut main.world, close.id, Event::Locked);
    assert_eq!(
        request.outcome(),
        Some(&Outcome::Protocol(Protocol::WrongKind))
    );
}
