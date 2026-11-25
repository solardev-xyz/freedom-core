//! The Publish machines against vectors/swarm.json (design 0015, SWM-3
//! part 3b): every `methods` case of `publishData`, `publishFiles`,
//! `publishChunk` and `getUploadStatus` but those [`LEFT_OUT`] names; and
//! the `stamps` and `errors` cases these machines reach (`stamps.select`
//! for a content upload and for a chunk; `errors.http_error` at the page
//! upload's site and at bee-js's, through an upload's answer and a tag
//! read).
//!
//! **What the core sees,** as in `methods_vectors.rs`: what main's
//! dispatcher handed the service (the key, with main's grant writes before
//! the hand-off applied, "always allow" among them), the approval main
//! reports (`user` after the publish prompt, `auto` when the site's rule
//! answered), and the world as the dispatcher hands the request over
//! (`at_execute`). A node rule's `world` changes the world as its request
//! arrives (Agent custody, the rule turned off, the name moved).
//!
//! **Main,** scripted from the case: the publish readiness; the node's
//! answers under main's rules (`forward`); each part streamed from the
//! step's `parts` in frames of at most 64 KiB within the core's credit; a
//! body read from `swarm.body` within main's window, its credit given back
//! only when main has nothing else to do (a node that reads slowly, so the
//! window shuts); the upload's turn; and the history's statements run
//! through SQLite (rusqlite, the schema the reference creates).
//!
//! **What is checked,** each step: the answer (the case's `core` where a
//! deviation changes it); the calls against the method's row in
//! `swarm-grammar.json` (ready check, forms, counts) and against the
//! grammar's honest scenario for the step (form, method, path, query,
//! headers, and the body, byte for byte or by its SHA-256); the values the
//! row binds (the content type, the name, the body's length, the tag);
//! each ask's charge; that a part is credited only for bytes that went out
//! on the body; whether the effect ran. Each case: the publish history
//! after it (`getEntries()`, through part 2's `entry`), and no feed store
//! written.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use common::*;
use fc_json::JsString;
use fc_json::index::{Index, KeyOrder, Kind, Value as V};
use fc_swarm_provider::machine::node::{BodyOut, MAX_FRAME, WINDOW};
use fc_swarm_provider::machine::{
    Approval, AskId, Body, Call, Effect, Event, Failure, Form, Need, Outcome, ReadyCheck, Request,
    StoreWrite, UPLOAD_CHARGE, whole_charge,
};
use fc_swarm_provider::stamps::STAMPS_REPLY_CAP;
use fc_swarm_provider::stores::history::{self, Bind, Cell, Statement};
use fc_swarm_provider::value::Value;

/// The methods this piece's machines answer.
const FOUR: [&str; 4] = [
    "swarm_publishData",
    "swarm_publishFiles",
    "swarm_publishChunk",
    "swarm_getUploadStatus",
];

/// Cases of the four methods this test doesn't play, each with why. The
/// test fails on any case of the four it neither plays nor names here.
const LEFT_OUT: &[(&str, &str)] = &[(
    "publish-data-node-stopped-after-ready",
    "main holds the node: with no node URL after a passing pre-flight, the reference throws \
     `Swarm node is not ready` before any request (publishPageData's getAntApiUrl()); in the \
     core that is main's answer to the core's `stamps` call, for which `failed` has no class \
     (`unreachable` reads `fetch failed`). The design is silent and the case records no core \
     answer.",
)];

/// The deviations a case of the four marks, and what the core answers.
fn core_answer(deviation: &str, core: V<'_, '_>) -> Want {
    if let Some(want) = shared_answer(deviation, core) {
        return want;
    }
    let text = string(core);
    match deviation {
        // One read of /stamps: the same batch or error as the reference's
        // two (checked: one `stamps` call).
        "stamps-one-read" => {
            assert!(text.starts_with("one GET /stamps; the same"), "{text}");
            Want::Reference
        }
        other => panic!("a deviation this piece doesn't answer: {other}"),
    }
}

// ---------------------------------------------------------------------------
// The history, through SQLite.

struct HistoryDb {
    conn: rusqlite::Connection,
}

fn sql_value(bind: &Bind) -> rusqlite::types::Value {
    match bind {
        Bind::Null => rusqlite::types::Value::Null,
        Bind::Integer(n) => rusqlite::types::Value::Integer(*n),
        Bind::Real(n) => rusqlite::types::Value::Real(*n),
        Bind::Text(t) => rusqlite::types::Value::Text(t.clone()),
    }
}

impl HistoryDb {
    /// A new database as the reference's first `getDb()` makes it.
    fn open(now: u64) -> HistoryDb {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(history::DDL).unwrap();
        conn.pragma_update(None, "user_version", history::SCHEMA_VERSION)
            .unwrap();
        let db = HistoryDb { conn };
        let opened = history::open(history::Legacy::Absent, now);
        assert!(opened.import.is_empty());
        db.run(&opened.sweep);
        db.run(&opened.trim);
        db
    }

    fn run(&self, statement: &Statement) -> usize {
        self.conn
            .execute(
                statement.sql,
                rusqlite::params_from_iter(statement.params.iter().map(sql_value)),
            )
            .unwrap()
    }

    fn insert(&self, statement: &Statement) -> i64 {
        assert_eq!(statement.sql, history::INSERT_SQL);
        assert_eq!(self.run(statement), 1);
        self.conn.last_insert_rowid()
    }

    fn rows(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(*) FROM publishes", [], |r| r.get::<_, i64>(0))
            .unwrap() as usize
    }

    /// `getEntries()`.
    fn entries(&self) -> String {
        let statement = history::get_entries();
        let mut prepared = self.conn.prepare(statement.sql).unwrap();
        let rows: Vec<Vec<Cell>> = prepared
            .query_map([], |row| {
                (0..history::COLUMNS.len())
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
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        Value::from_js(&history::entries(&rows).unwrap())
            .stringify()
            .unwrap()
    }
}

// ---------------------------------------------------------------------------
// Main, scripted.

/// A part main streams.
struct PartFeed {
    data: Vec<u8>,
    sent: usize,
    /// What main may send: the window and the core's credit.
    allowed: usize,
    head: bool,
    done: bool,
    /// The credit the core gave.
    credited: usize,
}

/// A body main reads from `swarm.body`.
struct BodyIn {
    call: usize,
    expected: u64,
    head: bool,
    data: Vec<u8>,
    window: u64,
    ended: bool,
}

/// A step's run.
struct Played {
    ran: Ran,
    /// The body each call carried.
    sent: Vec<Option<Vec<u8>>>,
    /// The parts asked, in order.
    parts: Vec<u32>,
    turns: usize,
    /// The statements written after the outcome (the row's last update).
    closing: usize,
}

struct MainSide<'a> {
    node: &'a Node,
    db: &'a HistoryDb,
    readiness: Result<(), JsString>,
    parts: &'a BTreeMap<u32, Vec<u8>>,
    /// The case's key, which a node rule's world change is made for.
    case_key: &'a JsString,
}

fn play(world: &mut TestWorld, main: &MainSide<'_>, call: &Call, sid: &str) -> Played {
    let mut request = Request::start(call, world).expect("a method this piece brings");
    let mut queue: VecDeque<Effect> = request.take_effects().into();
    let mut played = Played {
        ran: Ran {
            outcome: Outcome::Cancelled,
            ready: Vec::new(),
            calls: Vec::new(),
            cancels_after_outcome: 0,
        },
        sent: Vec::new(),
        parts: Vec::new(),
        turns: 0,
        closing: 0,
    };
    let mut feeds: BTreeMap<AskId, PartFeed> = BTreeMap::new();
    let mut bodies: BTreeMap<AskId, BodyIn> = BTreeMap::new();
    let mut calls: BTreeMap<AskId, usize> = BTreeMap::new();
    let mut held: Vec<(AskId, usize)> = Vec::new();
    let mut cancelled: HashSet<AskId> = HashSet::new();
    let mut body_out = 0usize;
    let mut part_credit = 0usize;
    // The row just inserted, until the bound's trim keeping it runs
    // (deviation `history-bound`).
    let mut untrimmed: Option<i64> = None;

    macro_rules! give {
        ($id:expr, $event:expr) => {{
            request.answer(world, $id, $event);
            queue.extend(request.take_effects());
        }};
    }

    while request.outcome().is_none() {
        if let Some(effect) = queue.pop_front() {
            match effect {
                Effect::Ask(ask) => match ask.need {
                    Need::Ready(check) => {
                        assert_eq!(ask.charge, 0, "{sid}");
                        assert_eq!(check, ReadyCheck::Publish, "{sid}");
                        played.ran.ready.push((check, played.ran.calls.len()));
                        give!(ask.id, Event::Ready(main.readiness.clone()));
                    }
                    Need::Node(node_call) => {
                        assert_eq!(untrimmed, None, "{sid}: no trim after the insert");
                        assert_eq!(ask.charge, whole_charge(node_call.form), "{sid}");
                        // The design's charges: /stamps' 1 MiB as JSON with
                        // its 4,096 batches (7.7 MiB), every other JSON reply
                        // the 512 KiB floor.
                        let design = match node_call.form {
                            Form::Stamps => 8_055_472,
                            _ => 512 * 1024,
                        };
                        assert_eq!(ask.charge, design, "{sid}: {:?}'s charge", node_call.form);
                        assert!(
                            !node_call.stream(),
                            "{sid}: no publish call streams its reply"
                        );
                        // The world changes as the request arrives.
                        if let Some(rule) = main.node.matching(node_call.method(), &node_call.path)
                        {
                            for (what, value) in &rule.world {
                                world.apply(main.case_key, what, value);
                            }
                        }
                        let index = played.ran.calls.len();
                        calls.insert(ask.id, index);
                        played.ran.calls.push(Logged {
                            call: node_call.clone(),
                            charge: ask.charge,
                            body: None,
                        });
                        match &node_call.body {
                            Some(Body::Stream { bytes }) => {
                                played.sent.push(None);
                                bodies.insert(
                                    ask.id,
                                    BodyIn {
                                        call: index,
                                        expected: *bytes,
                                        head: false,
                                        data: Vec::new(),
                                        window: WINDOW,
                                        ended: false,
                                    },
                                );
                                give!(ask.id, Event::BodyOpen);
                            }
                            body => {
                                let spec = match body {
                                    Some(Body::Base64(bytes)) => {
                                        assert!(bytes.len() <= 64 * 1024, "{sid}");
                                        played.sent.push(Some(bytes.clone()));
                                        main.node.upload(node_call.method(), &node_call.path, bytes)
                                    }
                                    _ => {
                                        played.sent.push(None);
                                        main.node.reply(node_call.method(), &node_call.path)
                                    }
                                };
                                let (abort_page, events) = forward(&spec, &node_call);
                                assert!(!abort_page, "{sid}");
                                played.ran.calls[index].body =
                                    events.iter().find_map(|e| match e {
                                        Event::Reply(r) if r.ok() => Some(r.body.clone()),
                                        _ => None,
                                    });
                                for event in events {
                                    give!(ask.id, event);
                                }
                            }
                        }
                    }
                    Need::Part(part) => {
                        assert_eq!(ask.charge, 0, "{sid}: a part is held under the turn");
                        played.parts.push(part);
                        let data = main
                            .parts
                            .get(&part)
                            .unwrap_or_else(|| panic!("{sid}: part {part} isn't the step's"));
                        feeds.insert(
                            ask.id,
                            PartFeed {
                                data: data.clone(),
                                sent: 0,
                                allowed: WINDOW as usize,
                                head: false,
                                done: false,
                                credited: 0,
                            },
                        );
                    }
                    Need::Upload => {
                        assert_eq!(ask.charge, UPLOAD_CHARGE, "{sid}");
                        played.turns += 1;
                        give!(ask.id, Event::Turn);
                    }
                    Need::Write(StoreWrite::History(statements)) => {
                        assert_eq!(ask.charge, 0, "{sid}");
                        for statement in &statements {
                            if statement.sql == history::TRIM_SQL {
                                let kept = untrimmed.take();
                                assert_eq!(
                                    statement.params,
                                    vec![Bind::Integer(kept.expect("a trim with no insert"))],
                                    "{sid}: the trim keeps the row just inserted"
                                );
                            } else {
                                assert_eq!(untrimmed, None, "{sid}: no trim after the insert");
                            }
                            main.db.run(statement);
                        }
                        give!(ask.id, Event::Written(Ok(())));
                    }
                    Need::Write(StoreWrite::HistoryInsert(statement)) => {
                        assert_eq!(ask.charge, 0, "{sid}");
                        assert_eq!(untrimmed, None, "{sid}");
                        let rowid = main.db.insert(&statement);
                        untrimmed = Some(rowid);
                        give!(ask.id, Event::Inserted(Ok(rowid)));
                    }
                    other => panic!("{sid}: an ask this piece's machines don't make: {other:?}"),
                },
                Effect::Cancel(id) => {
                    cancelled.insert(id);
                    feeds.remove(&id);
                }
                Effect::Credit { id, bytes } => {
                    let feed = feeds
                        .get_mut(&id)
                        .unwrap_or_else(|| panic!("{sid}: credit on a stream main isn't sending"));
                    feed.allowed += bytes;
                    feed.credited += bytes;
                    part_credit += bytes;
                    assert!(feed.credited <= feed.sent, "{sid}: credit past what came");
                    assert!(
                        part_credit <= body_out,
                        "{sid}: a part credited before its bytes went out"
                    );
                }
                Effect::Body { id, out } => {
                    let body = bodies
                        .get_mut(&id)
                        .unwrap_or_else(|| panic!("{sid}: a body for no streaming call"));
                    assert!(!body.ended, "{sid}: body after its terminal");
                    match out {
                        BodyOut::Head { bytes } => {
                            assert!(!body.head, "{sid}: a second head");
                            assert_eq!(bytes, body.expected, "{sid}: the head's length");
                            body.head = true;
                        }
                        BodyOut::Data(bytes) => {
                            assert!(body.head, "{sid}: data before the head");
                            assert!(
                                !bytes.is_empty() && bytes.len() <= MAX_FRAME,
                                "{sid}: a frame of {}",
                                bytes.len()
                            );
                            assert!(bytes.len() as u64 <= body.window, "{sid}: past the window");
                            body.window -= bytes.len() as u64;
                            body_out += bytes.len();
                            body.data.extend_from_slice(&bytes);
                            // Main's node reads slowly: the credit comes back
                            // once main has nothing else to do.
                            held.push((id, bytes.len()));
                        }
                        BodyOut::End => {
                            body.ended = true;
                            assert_eq!(body.data.len() as u64, body.expected, "{sid}");
                            let index = body.call;
                            let data = std::mem::take(&mut body.data);
                            let node_call = played.ran.calls[index].call.clone();
                            let spec = main.node.upload(node_call.method(), &node_call.path, &data);
                            played.sent[index] = Some(data);
                            let (abort_page, events) = forward(&spec, &node_call);
                            assert!(!abort_page, "{sid}");
                            played.ran.calls[index].body = events.iter().find_map(|e| match e {
                                Event::Reply(r) if r.ok() => Some(r.body.clone()),
                                _ => None,
                            });
                            if !cancelled.contains(&id) {
                                for event in events {
                                    give!(id, event);
                                }
                            }
                        }
                        BodyOut::Abort(_) => body.ended = true,
                    }
                }
            }
            continue;
        }
        // Nothing to take: main streams the next frame of a part.
        if let Some((&id, feed)) = feeds
            .iter_mut()
            .find(|(_, f)| !f.done && (!f.head || f.sent == f.data.len() || f.sent < f.allowed))
        {
            let event = if !feed.head {
                feed.head = true;
                Event::PartHead(feed.data.len() as u64)
            } else if feed.sent == feed.data.len() {
                feed.done = true;
                Event::End
            } else {
                let n = (feed.data.len() - feed.sent)
                    .min(MAX_FRAME)
                    .min(feed.allowed - feed.sent);
                let frame = feed.data[feed.sent..feed.sent + n].to_vec();
                feed.sent += n;
                Event::Data(frame)
            };
            give!(id, event);
            continue;
        }
        // Or gives the body credit it held.
        if !held.is_empty() {
            for (id, bytes) in std::mem::take(&mut held) {
                if let Some(body) = bodies.get_mut(&id)
                    && !body.ended
                {
                    body.window += bytes as u64;
                    give!(id, Event::BodyCredit(bytes));
                }
            }
            continue;
        }
        panic!("{sid}: the request waits with nothing main can answer");
    }
    // After the outcome: cancels of what was open, and the row's last
    // update, which is made.
    for effect in queue.into_iter().chain(request.take_effects()) {
        match effect {
            Effect::Cancel(_) => played.ran.cancels_after_outcome += 1,
            Effect::Ask(ask) => match ask.need {
                Need::Write(StoreWrite::History(statements)) => {
                    for statement in &statements {
                        main.db.run(statement);
                    }
                    played.closing += 1;
                }
                Need::Node(call) => played.ran.calls.push(Logged {
                    call,
                    charge: ask.charge,
                    body: None,
                }),
                other => panic!("{sid}: {other:?} after the outcome"),
            },
            Effect::Credit { .. } | Effect::Body { .. } => {}
        }
    }
    played.ran.outcome = request.outcome().unwrap().clone();
    played
}

// ---------------------------------------------------------------------------
// The grammar's rows and scenarios.

fn row_of(method: &str) -> &'static str {
    match method {
        "swarm_publishData" => "publishData",
        "swarm_publishFiles" => "publishFiles",
        "swarm_publishChunk" => "publishChunk",
        "swarm_getUploadStatus" => "getUploadStatus",
        other => panic!("{other}"),
    }
}

fn header<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// The data a step's `data` param is: a string's UTF-8 or the bytes,
/// inline or the step's part.
fn data_bytes(value: &Value, parts: &BTreeMap<u32, Vec<u8>>) -> Vec<u8> {
    use fc_swarm_provider::value::Source;
    match value {
        Value::Bytes(b) => match &b.source {
            Source::Inline(data) => data.clone(),
            Source::Part(k) => parts[k].clone(),
        },
        Value::String(s) => s.as_str().as_bytes().to_vec(),
        other => panic!("data {other:?}"),
    }
}

/// The values the row binds (design 0015, "The operation grammar").
fn check_values(
    sid: &str,
    row: &str,
    played: &Played,
    params: &Value,
    parts: &BTreeMap<u32, Vec<u8>>,
) {
    for (i, logged) in played.ran.calls.iter().enumerate() {
        let call = &logged.call;
        match call.form {
            Form::Stamps => {
                assert_eq!(i, 0, "{sid}: /stamps first");
                assert_eq!(call.path, "/stamps", "{sid}");
                assert!(call.query.is_empty() && call.headers.is_empty(), "{sid}");
                assert!(call.body.is_none(), "{sid}");
                assert_eq!(call.max_bytes, STAMPS_REPLY_CAP, "{sid}");
            }
            Form::BzzFile => {
                let data = data_bytes(params.get("data"), parts);
                let name = params.get("name");
                let want_name = if name.truthy() {
                    match name {
                        Value::String(s) => s.as_str().to_owned(),
                        Value::Number(n) => fc_json::number_to_string(*n),
                        other => panic!("{sid}: a name {other:?}"),
                    }
                } else {
                    "data".to_owned()
                };
                assert_eq!(call.path, "/bzz", "{sid}");
                assert_eq!(call.query, vec![("name".to_owned(), want_name)], "{sid}");
                assert_eq!(
                    header(&call.headers, "content-type"),
                    Some(params.get("contentType").as_js_string().unwrap().as_str()),
                    "{sid}"
                );
                assert_eq!(
                    header(&call.headers, "swarm-deferred-upload"),
                    Some("false"),
                    "{sid}"
                );
                assert!(header(&call.headers, "swarm-encrypt").is_none(), "{sid}");
                assert_eq!(
                    played.sent[i].as_ref(),
                    Some(&data),
                    "{sid}: the body is the data"
                );
                let inline = matches!(params.get("data"), Value::Bytes(b)
                    if matches!(b.source, fc_swarm_provider::value::Source::Inline(_)));
                assert_eq!(
                    matches!(call.body, Some(Body::Base64(_))),
                    inline,
                    "{sid}: inline data goes inline"
                );
            }
            Form::BzzTar => {
                let Value::Array(files) = params.get("files") else {
                    panic!("{sid}")
                };
                // T(files): every entry's header, room for a long name,
                // its padded bytes, and the end.
                let mut bound = 1024u64;
                for file in files.iter().flatten() {
                    let path = file.get("path").as_js_string().unwrap();
                    let Value::Bytes(b) = file.get("bytes") else {
                        panic!("{sid}")
                    };
                    bound += 1024
                        + (path.as_str().len() as u64).div_ceil(512) * 512
                        + b.len.div_ceil(512) * 512;
                }
                let body = played.sent[i].as_ref().unwrap();
                assert!(body.len() as u64 <= bound, "{sid}: the tar past T(files)");
                assert_eq!(call.path, "/bzz", "{sid}");
                assert!(call.query.is_empty(), "{sid}");
                assert!(matches!(call.body, Some(Body::Stream { .. })), "{sid}");
                // `swarm-index-document`: the page's, else index.html at the
                // top, else none.
                let index = params
                    .get("indexDocument")
                    .as_js_string()
                    .map(|s| s.as_str().to_owned())
                    .or_else(|| {
                        files
                            .iter()
                            .flatten()
                            .any(|f| f.get("path").as_js_string().unwrap() == "index.html")
                            .then(|| "index.html".to_owned())
                    });
                assert_eq!(
                    header(&call.headers, "swarm-index-document"),
                    index.as_deref(),
                    "{sid}"
                );
            }
            Form::ChunkUp => {
                let data = data_bytes(params.get("data"), parts);
                // A span of 0 is falsy to core-sdk: the payload's length.
                let span = match params.get("span") {
                    Value::Number(n) => *n as u64,
                    Value::BigInt(t) => t.parse().unwrap(),
                    _ => 0,
                };
                let span = if span == 0 { data.len() as u64 } else { span };
                let mut want = span.to_le_bytes().to_vec();
                want.extend_from_slice(&data);
                assert_eq!(call.path, "/chunks", "{sid}");
                assert_eq!(
                    call.body,
                    Some(Body::Base64(want)),
                    "{sid}: span ‖ the data"
                );
            }
            Form::Tag => {
                let Value::Number(uid) = params.get("tagUid") else {
                    panic!("{sid}")
                };
                assert_eq!(call.path, format!("/tags/{}", *uid as u64), "{sid}");
                assert!(call.body.is_none() && call.headers.is_empty(), "{sid}");
            }
            other => panic!("{sid}: {other:?} under {row}"),
        }
        if let Some(batch) = header(&call.headers, "swarm-postage-batch-id") {
            assert!(
                batch.len() == 64
                    && batch
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "{sid}: {batch}"
            );
        }
    }
}

/// The core's calls against the grammar's honest scenario for the step:
/// form, method, path, query, the headers but main's, and the body. With
/// `prefix`, the core's calls may stop early (a deviation that ends the
/// request where the reference went on).
fn check_scenario_calls(sid: &str, scenario: V<'_, '_>, played: &Played, prefix: bool) {
    let main_headers = ["accept", "accept-encoding"];
    let wants: Vec<_> = get(scenario, "calls").children().collect();
    if prefix {
        assert!(
            played.ran.calls.len() <= wants.len(),
            "{sid}: calls past the scenario's"
        );
    } else {
        assert_eq!(
            played.ran.calls.len(),
            wants.len(),
            "{sid}: the scenario's calls"
        );
    }
    for (i, (logged, want)) in played.ran.calls.iter().zip(&wants).enumerate() {
        let call = &logged.call;
        assert!(
            get(*want, "form").is_str(call.form.as_str()),
            "{sid}/{i}: form"
        );
        assert!(get(*want, "method").is_str(call.method()), "{sid}/{i}");
        assert!(get(*want, "path").is_str(&call.path), "{sid}/{i}: path");
        let query: Vec<(String, String)> = want
            .get("query")
            .map(|q| {
                q.children()
                    .map(|p| {
                        let mut it = p.children();
                        (string(it.next().unwrap()), string(it.next().unwrap()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(call.query, query, "{sid}/{i}: query");
        let headers: Vec<(String, String)> = get(*want, "headers")
            .children()
            .filter_map(|h| {
                let mut it = h.children();
                let (k, v) = (string(it.next().unwrap()), string(it.next().unwrap()));
                (!main_headers.contains(&k.as_str())).then_some((k, v))
            })
            .collect();
        assert_eq!(call.headers, headers, "{sid}/{i}: headers");
        match want.get("body") {
            // The recording leaves out an empty body.
            None => assert!(
                played.sent[i].as_ref().is_none_or(Vec::is_empty),
                "{sid}/{i}: a body"
            ),
            Some(body) => {
                let sent = played.sent[i]
                    .as_ref()
                    .unwrap_or_else(|| panic!("{sid}/{i}: no body"));
                assert_eq!(sent.len() as f64, number(get(body, "bytes")), "{sid}/{i}");
                match body.get("base64") {
                    Some(b) => assert_eq!(*sent, b64(&string(b)), "{sid}/{i}: the body"),
                    None => assert_eq!(sha(sent), string(get(body, "sha256")), "{sid}/{i}"),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Playing the cases.

/// The step's parts (`parts[i] = { part, seed | repeat + count, length,
/// sha256 }`), each checked against its SHA-256.
fn parts_of(step: V<'_, '_>) -> BTreeMap<u32, Vec<u8>> {
    let mut out = BTreeMap::new();
    for part in step
        .get("parts")
        .map(|p| p.children())
        .into_iter()
        .flatten()
    {
        let length = number(get(part, "length")) as usize;
        let data = match part.get("seed") {
            Some(seed) => content(&string(seed), length),
            None => {
                let unit = string(get(part, "repeat"));
                unit.repeat(number(get(part, "count")) as usize)
                    .into_bytes()
            }
        };
        assert_eq!(data.len(), length);
        assert_eq!(sha(&data), string(get(part, "sha256")));
        out.insert(number(get(part, "part")) as u32, data);
    }
    out
}

/// How main approved a step: `user` after its publish prompt, `auto` when
/// the site's rule answered (the dispatcher read custody for it); none for
/// a method without approval.
fn approval_of(method: &str, step: V<'_, '_>) -> Option<Approval> {
    if method == "swarm_getUploadStatus" {
        return None;
    }
    let events: Vec<_> = step
        .get("events")
        .map(|e| e.children().collect())
        .unwrap_or_default();
    if events.iter().any(|e| {
        e.get("prompt")
            .is_some_and(|p| get(p, "kind").is_str("swarm.publish"))
    }) {
        Some(Approval::User)
    } else {
        assert!(
            events.iter().any(|e| e.get("custody").is_some()),
            "a rule answered without its custody read"
        );
        Some(Approval::Auto)
    }
}

/// The history the core leaves: the reference's, but where a deviation
/// turns the result into the core's error, the row ends `failed` with the
/// core's text and nothing the upload gave.
fn core_history(case: V<'_, '_>, want: Want) -> String {
    let rows: Vec<_> = get(get(case, "after"), "history").children().collect();
    if want != Want::Exact || get(case, "core").get("error").is_none() {
        return get(get(case, "after"), "history").stringify(KeyOrder::Property);
    }
    let message = get(get(get(case, "core"), "error"), "message").stringify(KeyOrder::Property);
    assert_eq!(rows.len(), 1, "a deviation's one row");
    let mut out = String::from("[{");
    for (i, (k, v)) in rows[0].members().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let key = string(k);
        out.push_str(&format!("{:?}:", key));
        let value = match key.as_str() {
            "status" => "\"failed\"".to_owned(),
            "reference" | "bzzUrl" | "tagUid" | "batchIdUsed" => "null".to_owned(),
            "errorMessage" => message.clone(),
            _ => v.stringify(KeyOrder::Property),
        };
        out.push_str(&value);
    }
    out.push_str("}]");
    out
}

#[test]
fn publish_methods() {
    let text = text_of("swarm.json");
    let index = Index::new(&text).unwrap();
    let grammar_text = text_of("swarm-grammar.json");
    let grammar_index = Index::new(&grammar_text).unwrap();
    let grammar = grammar_index.root();
    let keys_text = text_of("keys.json");
    let keys_index = Index::new(&keys_text).unwrap();
    let keys = keys(&keys_index);
    let scenarios = scenarios(grammar);

    let mut played_steps = 0usize;
    let mut main_answered = 0usize;
    let mut uploads = 0usize;
    let mut streamed = 0usize;
    let mut cases = 0usize;
    let mut scenarios_used = BTreeSet::new();
    let mut left_out_seen = BTreeSet::new();
    for case in get(index.root(), "methods").children() {
        let id = string(get(case, "id"));
        let steps: Vec<_> = get(case, "steps").children().collect();
        let methods: Vec<String> = steps
            .iter()
            .filter_map(|s| s.get("method").map(string))
            .collect();
        if !methods.iter().any(|m| FOUR.contains(&m.as_str())) {
            continue;
        }
        if let Some((_, why)) = LEFT_OUT.iter().find(|(l, _)| *l == id) {
            assert!(!why.is_empty());
            left_out_seen.insert(id.clone());
            continue;
        }
        assert!(
            methods.iter().all(|m| FOUR.contains(&m.as_str())),
            "{id}: a case that mixes in another piece's method"
        );
        cases += 1;
        let feeds_before = case
            .get("feeds")
            .filter(|f| f.kind() == Kind::String)
            .map(string);
        let mut world = TestWorld::of(case);
        let node = Node::of(case, &keys);
        let origin = js(get(case, "origin"));
        let db = HistoryDb::open(world.now);
        let deviation = case.get("deviation").map(string);
        let want = match &deviation {
            Some(d) => core_answer(d, get(case, "core")),
            None => {
                assert!(case.get("core").is_none(), "{id}");
                Want::Reference
            }
        };
        let mut at_execute = case.get("at_execute");
        for (k, step) in steps.iter().enumerate() {
            let sid = if steps.len() > 1 {
                format!("{id}/{k}")
            } else {
                id.clone()
            };
            if let Some(clock) = step.get("clock") {
                world.now = number(clock) as u64;
            }
            let Some(handoff) = handoff(*step, &origin, &mut world) else {
                assert_eq!(get(*step, "requests").children().count(), 0, "{sid}");
                main_answered += 1;
                continue;
            };
            // The world as the dispatcher hands the request over.
            if let Some(change) = at_execute.take() {
                world.change(&origin, change);
            }
            let name = handoff.name.clone().unwrap();
            let parts = parts_of(*step);
            let call = Call {
                method: handoff.method.clone(),
                params: handoff.params.clone(),
                key: handoff.key.clone(),
                approval: approval_of(&name, *step),
            };
            let main = MainSide {
                node: &node,
                db: &db,
                readiness: publish_readiness(case),
                parts: &parts,
                case_key: &origin,
            };
            let played = play(&mut world, &main, &call, &sid);
            played_steps += 1;

            let last = k + 1 == steps.len();
            check_outcome(&sid, want, last, case, *step, &played.ran.outcome);
            let row = row_of(&name);
            check_row_shape(&sid, grammar, row, &played.ran);
            check_values(&sid, row, &played, &handoff.params, &parts);
            // Each part once, in the params' order.
            let mut asked = played.parts.clone();
            asked.dedup();
            assert_eq!(asked.len(), played.parts.len(), "{sid}: a part twice");
            assert!(
                played.parts.windows(2).all(|w| w[0] < w[1]),
                "{sid}: parts in order"
            );
            let uploaded = played
                .ran
                .calls
                .iter()
                .any(|c| c.call.form != Form::Stamps && c.call.form != Form::Tag);
            if uploaded {
                uploads += 1;
            }
            // A turn for a streamed body, and only for one.
            let streams = played
                .ran
                .calls
                .iter()
                .any(|c| matches!(c.call.body, Some(Body::Stream { .. })));
            assert_eq!(
                played.turns,
                usize::from(streams),
                "{sid}: the upload's turn"
            );
            streamed += usize::from(streams);
            // Whether the effect ran, as the reference's guard recorded it.
            let effect = step
                .get("events")
                .and_then(|e| e.children().find_map(|e| e.get("effect")));
            if deviation.is_none() {
                match effect {
                    Some(e) => assert_eq!(
                        uploaded,
                        e.get("outcome").is_some_and(|o| o.is_str("ran")),
                        "{sid}: the effect"
                    ),
                    None => assert!(!uploaded, "{sid}: an upload with no effect"),
                }
            }
            match scenarios.get(&sid) {
                Some(scenario) => {
                    assert!(get(*scenario, "row").is_str(row), "{sid}");
                    let prefix = want == Want::Exact && get(case, "core").get("error").is_some();
                    check_scenario_calls(&sid, *scenario, &played, prefix);
                    scenarios_used.insert(sid.clone());
                }
                None => assert!(
                    played.ran.calls.is_empty(),
                    "{sid}: calls, and no honest scenario"
                ),
            }
            // A collection's tag is the site's while it holds its key.
            if name == "swarm_publishFiles"
                && let Outcome::Result(result) = &played.ran.outcome
                && let Value::Number(tag) = result.get("tagUid")
            {
                assert_eq!(
                    world.tags.get(*tag as u64),
                    Some(&handoff.key),
                    "{sid}: the tag's owner"
                );
            }
            assert_eq!(played.closing, 0, "{sid}: the machine updates its own row");
        }
        // The history after the case, and no feed store written.
        assert_eq!(db.entries(), core_history(case, want), "{id}: the history");
        assert!(db.rows() <= history::MAX_ROWS, "{id}");
        let after = get(case, "after");
        let feeds_after = after
            .get("feeds")
            .filter(|f| f.kind() == Kind::String)
            .map(string);
        assert_eq!(feeds_after, feeds_before, "{id}: swarm-feeds.json");
    }
    let left_out: BTreeSet<String> = LEFT_OUT.iter().map(|(id, _)| (*id).to_owned()).collect();
    assert_eq!(left_out_seen, left_out, "every case left out exists");
    // Every honest scenario of these methods' cases is one a step played.
    for (sid, scenario) in &scenarios {
        let from = string(get(*scenario, "from"));
        let Some(case_id) = from.strip_prefix("methods/") else {
            continue;
        };
        if left_out.contains(case_id) {
            continue;
        }
        let row = string(get(*scenario, "row"));
        if [
            "publishData",
            "publishFiles",
            "publishChunk",
            "getUploadStatus",
        ]
        .contains(&row.as_str())
        {
            assert!(
                scenarios_used.contains(sid),
                "{sid}: an honest scenario no step played"
            );
        }
    }
    // Every case of the four but the one left out; every step of theirs
    // but main's own answers; every honest scenario of their rows.
    assert_eq!((cases, played_steps, main_answered), (177, 176, 10));
    assert_eq!(scenarios_used.len(), 86);
    assert!(uploads > 60 && streamed > 20, "{uploads} {streamed}");
}

// ---------------------------------------------------------------------------
// The `stamps` and `errors` cases the machines reach.

const KEY: &str = "https://app.example";
const CLOCK: u64 = 1_767_225_600_123;

/// A connected site's world, at the cases' clock.
fn site_world() -> TestWorld {
    TestWorld {
        grants: BTreeSet::from([JsString::from(KEY)]),
        ..TestWorld::new(CLOCK)
    }
}

/// The usable batch the method cases use.
fn usable_stamps() -> Vec<u8> {
    format!(
        r#"{{"stamps":[{{"batchID":"{}","utilization":0,"usable":true,"label":"freedom","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000}}]}}"#,
        "a1".repeat(32)
    )
    .into_bytes()
}

/// A rule answering `method path` with `reply`.
fn rule(method: &str, path: &str, reply: ReplySpec) -> Rule {
    Rule {
        method: Some(method.to_owned()),
        path: Some(path.to_owned()),
        prefix: None,
        reply,
        world: Vec::new(),
    }
}

fn bytes_value(data: Vec<u8>) -> Value {
    use fc_swarm_provider::value::{Bytes, BytesKind, Source};
    Value::Bytes(Bytes {
        len: data.len() as u64,
        kind: BytesKind::Uint8Array,
        source: Source::Inline(data),
        data: true,
    })
}

fn part_value(part: u32, len: u64) -> Value {
    use fc_swarm_provider::value::{Bytes, BytesKind, Source};
    Value::Bytes(Bytes {
        len,
        kind: BytesKind::Uint8Array,
        source: Source::Part(part),
        data: true,
    })
}

/// Runs one request of a connected site that its prompt approved.
fn run_site(
    node: &Node,
    world: &mut TestWorld,
    method: &str,
    params: Value,
    parts: &BTreeMap<u32, Vec<u8>>,
    sid: &str,
) -> (Played, HistoryDb) {
    let db = HistoryDb::open(CLOCK);
    let key = JsString::from(KEY);
    let main = MainSide {
        node,
        db: &db,
        readiness: Ok(()),
        parts,
        case_key: &key,
    };
    let call = Call {
        method: Value::str(method),
        params,
        key: key.clone(),
        approval: (method != "swarm_getUploadStatus").then_some(Approval::User),
    };
    let played = play(world, &main, &call, sid);
    (played, db)
}

/// `nodeWriteError` of a service's error as the vectors record it: no
/// batch with room is 4900 `no-usable-stamps`, anything else -32603 with
/// its message.
fn write_error_of(error: V<'_, '_>) -> Failure {
    let message = js(get(error, "message"));
    match error.get("code").map(string).as_deref() {
        Some("POSTAGE_UNAVAILABLE" | "POSTAGE_CAPACITY_INSUFFICIENT" | "no-usable-stamps") => {
            Failure {
                code: 4900,
                message,
                data: Some(Value::object([("reason", Value::str("no-usable-stamps"))])),
            }
        }
        _ => Failure::internal(message),
    }
}

/// `stamps.select` through the uploads: a content upload's (`requireCapacity`,
/// 4,096 bytes inline or 10 MiB from a part) through `publishData`, and a
/// chunk's (`selectChunkBatch(4096)`) through `publishChunk`. The batch the
/// upload carries is the case's, or the page gets its error through
/// `nodeWriteError`; `/stamps` is read once (`stamps-one-read`). The
/// messaging cases (`allowFullMutable`) are the Messaging piece's.
#[test]
fn stamps_through_the_uploads() {
    let text = text_of("swarm.json");
    let index = Index::new(&text).unwrap();
    let (mut played_cases, mut messaging) = (0, 0);
    for case in get(get(index.root(), "stamps"), "select").children() {
        let id = string(get(case, "id"));
        let options = get(case, "options");
        if options.get("allowFullMutable").is_some() {
            messaging += 1;
            continue;
        }
        let size = number(get(case, "size")) as u64;
        let node = Node {
            stamps: Some(
                get(case, "stamps")
                    .stringify(KeyOrder::Property)
                    .into_bytes(),
            ),
            ..Node::new()
        };
        let mut world = site_world();
        let data = content(&format!("stamps-reach/{id}"), size as usize);
        let mut parts = BTreeMap::new();
        let (method, params, form) = if options.get("requireCapacity").is_some() {
            let data = if size as usize > 64 * 1024 {
                parts.insert(0, data);
                part_value(0, size)
            } else {
                bytes_value(data)
            };
            (
                "swarm_publishData",
                Value::object([("data", data), ("contentType", Value::str("text/plain"))]),
                Form::BzzFile,
            )
        } else {
            assert_eq!(size, 4096, "{id}");
            (
                "swarm_publishChunk",
                Value::object([("data", bytes_value(data))]),
                Form::ChunkUp,
            )
        };
        let (played, _db) = run_site(&node, &mut world, method, params, &parts, &id);
        let reads = played
            .ran
            .calls
            .iter()
            .filter(|c| c.call.form == Form::Stamps)
            .count();
        assert_eq!(reads, 1, "{id}: one /stamps read");
        if let Some(core) = case.get("core") {
            assert_eq!(number(get(core, "stamps_reads")), 1.0, "{id}");
        }
        match (case.get("result"), case.get("error")) {
            (Some(batch), None) if batch.kind() == Kind::String => {
                let upload = played
                    .ran
                    .calls
                    .iter()
                    .find(|c| c.call.form == form)
                    .unwrap();
                assert_eq!(
                    header(&upload.call.headers, "swarm-postage-batch-id"),
                    Some(string(batch).as_str()),
                    "{id}: the batch"
                );
                assert!(matches!(played.ran.outcome, Outcome::Result(_)), "{id}");
            }
            // `selectChunkBatch`'s null: `noUsableBatchError`.
            (Some(_), None) => assert_eq!(
                played.ran.outcome,
                Outcome::Error(Failure {
                    code: 4900,
                    message: JsString::from(fc_swarm_provider::errors::NO_USABLE_BATCH_MESSAGE),
                    data: Some(Value::object([("reason", Value::str("no-usable-stamps"))])),
                }),
                "{id}"
            ),
            (None, Some(error)) => {
                assert_eq!(
                    played.ran.outcome,
                    Outcome::Error(write_error_of(error)),
                    "{id}"
                );
                assert_eq!(played.ran.calls.len(), 1, "{id}: nothing uploaded");
            }
            _ => panic!("{id}"),
        }
        played_cases += 1;
    }
    assert_eq!((played_cases, messaging), (33, 11));
}

/// An error body as the case gives it.
fn error_body(body: V<'_, '_>) -> Vec<u8> {
    match body.get("data") {
        Some(data) => data_of(data),
        None => body
            .get("base64")
            .map_or_else(Vec::new, |b| b64(&string(b))),
    }
}

/// `errors.http_error` through the machines: page-upload.js's site through
/// `publishData`'s upload, and bee-js's JSON site through `publishChunk`'s
/// upload and `getUploadStatus`'s tag read. The node answers the call with
/// the case's status, reason phrase and body (main hands the core at most
/// 8 KiB of it); the page reads the case's error message (the core's where
/// `error-body-bound` cuts it), and an upload's row keeps it. The other
/// sites are the reads' (array buffers, `fetchNode`) and the SOC upload's.
#[test]
fn errors_through_the_machines() {
    let text = text_of("swarm.json");
    let index = Index::new(&text).unwrap();
    let mut counts = BTreeMap::<String, usize>::new();
    for case in get(index.root(), "errors").children() {
        if !get(case, "kind").is_str("http_error") {
            continue;
        }
        let id = string(get(case, "id"));
        let site = string(get(case, "site"));
        let calls: &[(&str, &str, &str)] = match site.as_str() {
            "page-upload" => &[("swarm_publishData", "POST", "/bzz")],
            "bee-js-json" => &[
                ("swarm_publishChunk", "POST", "/chunks"),
                ("swarm_getUploadStatus", "GET", "/tags/101"),
                ("swarm_publishData", "GET", "/stamps"),
            ],
            _ => {
                *counts.entry(format!("other {site}")).or_default() += 1;
                continue;
            }
        };
        let status = number(get(case, "status")) as u16;
        let error = case
            .get("core")
            .map_or_else(|| get(case, "error"), |core| get(core, "error"));
        for (method, verb, path) in calls {
            let sid = format!("{id} via {method}");
            let reply = ReplySpec {
                status,
                status_text: string(get(case, "status_text")),
                headers: Vec::new(),
                body: error_body(get(case, "body")),
                ..ReplySpec::ok(Vec::new(), "")
            };
            let node = Node {
                stamps: Some(usable_stamps()),
                rules: vec![rule(verb, path, reply)],
                ..Node::new()
            };
            let mut world = site_world();
            world.tags.set(101, JsString::from(KEY));
            let params = match *method {
                "swarm_getUploadStatus" => Value::object([("tagUid", Value::int(101))]),
                "swarm_publishChunk" => Value::object([("data", bytes_value(b"x".to_vec()))]),
                _ => Value::object([
                    ("data", bytes_value(b"x".to_vec())),
                    ("contentType", Value::str("text/plain")),
                ]),
            };
            let (played, db) = run_site(&node, &mut world, method, params, &BTreeMap::new(), &sid);
            let Outcome::Error(failure) = &played.ran.outcome else {
                panic!("{sid}: {:?}", played.ran.outcome)
            };
            assert_eq!(failure.code, -32603, "{sid}");
            assert!(failure.data.is_none(), "{sid}");
            match error.get("message") {
                Some(m) => assert_eq!(failure.message, js(m), "{sid}"),
                None => {
                    let digest = get(error, "message_digest");
                    assert_eq!(
                        failure.message.utf16_len() as f64,
                        number(get(digest, "units")),
                        "{sid}"
                    );
                    assert_eq!(
                        sha(failure.message.as_str().as_bytes()),
                        string(get(digest, "sha256")),
                        "{sid}"
                    );
                }
            }
            if *method != "swarm_getUploadStatus" {
                // The row keeps the service's message.
                let rows = db.entries();
                assert!(rows.contains("\"status\":\"failed\""), "{sid}");
                // `errorMessage || null`: an empty message is no message.
                let quoted = if failure.message.is_empty() {
                    "null".to_owned()
                } else {
                    Value::String(failure.message.clone()).stringify().unwrap()
                };
                assert!(
                    rows.contains(&format!("\"errorMessage\":{quoted}")),
                    "{sid}: {rows}"
                );
            }
            *counts.entry(site.clone()).or_default() += 1;
        }
    }
    let count = |k: &str| counts.get(k).copied().unwrap_or_default();
    // Every page-upload case once, every bee-js JSON case at three sites.
    assert_eq!(count("page-upload"), 18, "{counts:?}");
    assert_eq!(count("bee-js-json"), 3 * 90, "{counts:?}");
    assert_eq!(
        count("other bee-js-arraybuffer")
            + count("other bee-js-bytes")
            + count("other fetch-node")
            + count("other soc-upload"),
        18 + 18 + 36 + 18
    );
}

// ---------------------------------------------------------------------------
// A request's end without its machine, and main's parts read strictly.

/// Starts a two-file `publishFiles` whose second file is a part, and runs
/// it up to the moment main has the body open and the core asks for the
/// part: the request, the upload's ask, the part's ask, and how many body
/// bytes went out before it.
fn files_up_to_the_part(
    world: &mut TestWorld,
    node: &Node,
    db: &HistoryDb,
) -> (Request, AskId, AskId, usize) {
    let files = Value::Array(vec![
        Some(Value::object([
            ("path", Value::str("index.html")),
            ("bytes", bytes_value(b"<p>hi</p>".to_vec())),
        ])),
        Some(Value::object([
            ("path", Value::str("big.bin")),
            ("bytes", part_value(0, 200_000)),
        ])),
    ]);
    let call = Call {
        method: Value::str("swarm_publishFiles"),
        params: Value::object([("files", files)]),
        key: JsString::from(KEY),
        approval: Some(Approval::User),
    };
    let mut request = Request::start(&call, world).unwrap();
    let mut upload = None;
    let mut sent = 0;
    let mut queue: VecDeque<Effect> = request.take_effects().into();
    while let Some(effect) = queue.pop_front() {
        let ask = match effect {
            Effect::Ask(ask) => ask,
            Effect::Body {
                out: BodyOut::Data(bytes),
                ..
            } => {
                sent += bytes.len();
                continue;
            }
            _ => continue,
        };
        let event = match ask.need {
            Need::Ready(_) => Event::Ready(Ok(())),
            Need::Write(StoreWrite::HistoryInsert(s)) => Event::Inserted(Ok(db.insert(&s))),
            Need::Write(StoreWrite::History(statements)) => {
                statements.iter().for_each(|s| {
                    db.run(s);
                });
                Event::Written(Ok(()))
            }
            Need::Node(call) if call.form == Form::Stamps => {
                forward(&node.reply("GET", "/stamps"), &call).1.remove(0)
            }
            Need::Upload => Event::Turn,
            Need::Node(call) => {
                assert_eq!(call.form, Form::BzzTar);
                upload = Some(ask.id);
                Event::BodyOpen
            }
            Need::Part(0) => return (request, upload.unwrap(), ask.id, sent),
            other => panic!("{other:?}"),
        };
        request.answer(world, ask.id, event);
        queue.extend(request.take_effects());
    }
    panic!("no part asked")
}

/// The deadline (or main's cancel) mid-upload: the core answers cancelled,
/// cancels the call and the part, asks for nothing more but the row's last
/// update, which ends it `failed` with `cancelled` (design 0015,
/// "Deadlines and cancel"); `busy` at a reservation's deadline does the
/// same with `busy`.
#[test]
fn a_cancel_mid_upload_ends_the_row() {
    for (end, text) in [("cancel", "cancelled"), ("busy", "busy")] {
        let node = Node {
            stamps: Some(usable_stamps()),
            ..Node::new()
        };
        let mut world = site_world();
        let db = HistoryDb::open(CLOCK);
        let (mut request, upload, part, _) = files_up_to_the_part(&mut world, &node, &db);
        world.now = CLOCK + 5_000;
        if end == "cancel" {
            request.cancel();
        } else {
            request.busy();
        }
        let effects = request.take_effects();
        assert!(effects.contains(&Effect::Cancel(upload)), "{end}: the call");
        assert!(effects.contains(&Effect::Cancel(part)), "{end}: the part");
        let writes: Vec<_> = effects
            .iter()
            .filter_map(|e| match e {
                Effect::Ask(ask) => Some(ask),
                _ => None,
            })
            .collect();
        assert_eq!(writes.len(), 1, "{end}: one ask after the outcome");
        let Need::Write(StoreWrite::History(statements)) = &writes[0].need else {
            panic!("{end}: {:?}", writes[0])
        };
        statements.iter().for_each(|s| {
            db.run(s);
        });
        let rows = db.entries();
        assert!(rows.contains("\"status\":\"failed\""), "{end}: {rows}");
        assert!(
            rows.contains(&format!("\"errorMessage\":\"{text}\"")),
            "{end}: {rows}"
        );
        // Nothing more after it: answers are dropped.
        request.answer(&mut world, part, Event::PartHead(200_000));
        assert!(request.take_effects().is_empty(), "{end}");
        match end {
            "cancel" => assert_eq!(request.outcome(), Some(&Outcome::Cancelled)),
            _ => assert_eq!(request.outcome(), Some(&Outcome::Error(Failure::busy()))),
        }
    }
}

/// A part main streams at another length than its params gave is a
/// protocol error; a part main can't stream ends the body
/// `body_stream_error` and the request -32603, its row `failed`.
#[test]
fn parts_are_read_strictly() {
    use fc_swarm_provider::machine::Protocol;
    use fc_swarm_provider::machine::node::{Abort, BodyAbort};
    let cases: Vec<(&str, Vec<Event>)> = vec![
        ("short head", vec![Event::PartHead(199_999)]),
        (
            "past its length",
            vec![
                Event::PartHead(200_000),
                Event::Data(vec![0; 65_536]),
                Event::Data(vec![0; 65_536]),
                Event::Data(vec![0; 65_536]),
                Event::Data(vec![0; 3_393]),
            ],
        ),
        (
            "ends short",
            vec![
                Event::PartHead(200_000),
                Event::Data(vec![0; 10]),
                Event::End,
            ],
        ),
        (
            "aborted",
            vec![
                Event::PartHead(200_000),
                Event::Abort(Abort::BodyStreamError),
            ],
        ),
    ];
    for (what, events) in cases {
        let node = Node {
            stamps: Some(usable_stamps()),
            ..Node::new()
        };
        let mut world = site_world();
        let db = HistoryDb::open(CLOCK);
        let (mut request, upload, part, _) = files_up_to_the_part(&mut world, &node, &db);
        let mut effects = request.take_effects();
        for event in events {
            if request.outcome().is_some() {
                break;
            }
            // Main's window: credit back whatever the body sent.
            for effect in &effects {
                if let Effect::Body {
                    id,
                    out: BodyOut::Data(bytes),
                } = effect
                {
                    request.answer(&mut world, *id, Event::BodyCredit(bytes.len()));
                }
            }
            request.answer(&mut world, part, event);
            effects = request.take_effects();
        }
        match what {
            "aborted" => {
                assert!(
                    effects.contains(&Effect::Body {
                        id: upload,
                        out: BodyOut::Abort(BodyAbort::BodyStreamError)
                    }),
                    "{what}: {effects:?}"
                );
                // The row's update, then the answer.
                let write = effects
                    .iter()
                    .find_map(|e| match e {
                        Effect::Ask(ask) => Some(ask.clone()),
                        _ => None,
                    })
                    .unwrap();
                let Need::Write(StoreWrite::History(statements)) = &write.need else {
                    panic!("{what}")
                };
                statements.iter().for_each(|s| {
                    db.run(s);
                });
                request.answer(&mut world, write.id, Event::Written(Ok(())));
                assert_eq!(
                    request.outcome(),
                    Some(&Outcome::Error(Failure::internal_error())),
                    "{what}"
                );
                assert!(db.entries().contains("\"errorMessage\":\"Internal error\""));
            }
            _ => {
                assert_eq!(
                    request.outcome(),
                    Some(&Outcome::Protocol(Protocol::PartLength)),
                    "{what}"
                );
                // The row ends with the request.
                let closing = request.take_effects();
                assert!(
                    effects.iter().chain(&closing).any(|e| matches!(e,
                        Effect::Ask(a) if matches!(a.need, Need::Write(StoreWrite::History(_))))),
                    "{what}: the row's update"
                );
            }
        }
    }
}

/// `history-bound`: with the table full, an upload's row is inserted and
/// the oldest finished row goes, so the table holds 10,000 rows, the new
/// one among them, even when the clock was set back (the new row would
/// then be the oldest).
#[test]
fn an_upload_keeps_the_history_bound() {
    for set_back in [false, true] {
        let db = HistoryDb::open(CLOCK);
        db.conn.execute_batch("BEGIN").unwrap();
        for i in 0..history::MAX_ROWS {
            db.conn
                .execute(
                    "INSERT INTO publishes (type, status, started_at) VALUES ('data', 'completed', ?)",
                    [CLOCK as i64 - 1_000_000 + i as i64],
                )
                .unwrap();
        }
        db.conn.execute_batch("COMMIT").unwrap();
        let node = Node {
            stamps: Some(usable_stamps()),
            ..Node::new()
        };
        let mut world = site_world();
        if set_back {
            world.now = CLOCK - 2_000_000;
        }
        let key = JsString::from(KEY);
        let main = MainSide {
            node: &node,
            db: &db,
            readiness: Ok(()),
            parts: &BTreeMap::new(),
            case_key: &key,
        };
        let call = Call {
            method: Value::str("swarm_publishChunk"),
            params: Value::object([("data", bytes_value(b"x".to_vec()))]),
            key: key.clone(),
            approval: Some(Approval::User),
        };
        let played = play(&mut world, &main, &call, "history-bound");
        assert!(
            matches!(played.ran.outcome, Outcome::Result(_)),
            "{set_back}"
        );
        assert_eq!(db.rows(), history::MAX_ROWS, "{set_back}");
        let kept: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM publishes WHERE name = 'CAC chunk'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, 1, "{set_back}: the new row stays");
        let first: i64 = db
            .conn
            .query_row("SELECT MIN(id) FROM publishes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(first, 2, "{set_back}: the oldest row went");
    }
}

/// Main's `swarm.body` answers are read strictly: a second `swarm.body`
/// for one call, or credit of 0 bytes, is a protocol error; and the core
/// never sends past main's window.
#[test]
fn body_answers_are_read_strictly() {
    use fc_swarm_provider::machine::Protocol;
    for (what, event, want) in [
        ("a second swarm.body", Event::BodyOpen, Protocol::WrongKind),
        ("no credit", Event::BodyCredit(0), Protocol::Frame),
    ] {
        let node = Node {
            stamps: Some(usable_stamps()),
            ..Node::new()
        };
        let mut world = site_world();
        let db = HistoryDb::open(CLOCK);
        let (mut request, upload, part, sent) = files_up_to_the_part(&mut world, &node, &db);
        // The first entry, padded, and the second's header have gone; the
        // part is asked.
        assert!(request.take_effects().is_empty(), "{what}");
        assert_eq!(sent, 512 + 512 + 512, "{what}");
        // The part fills the window, and the core stops there.
        request.answer(&mut world, part, Event::PartHead(200_000));
        request.answer(&mut world, part, Event::Data(vec![7; 65_536]));
        request.answer(&mut world, part, Event::Data(vec![7; 65_536]));
        let effects = request.take_effects();
        let out: usize = effects
            .iter()
            .map(|e| match e {
                Effect::Body {
                    out: BodyOut::Data(bytes),
                    ..
                } => bytes.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(sent + out, WINDOW as usize, "{what}: the window, no more");
        let credit: usize = effects
            .iter()
            .map(|e| match e {
                Effect::Credit { id, bytes } if *id == part => *bytes,
                _ => 0,
            })
            .sum();
        assert_eq!(credit, out, "{what}: credit for what went out");
        request.answer(&mut world, upload, event);
        assert_eq!(request.outcome(), Some(&Outcome::Protocol(want)), "{what}");
    }
}
