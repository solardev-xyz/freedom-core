//! Main's own node methods (design 0015, SWM-4 PR 3): `swarm.publish`,
//! `swarm.feed`, `swarm.stamps` and `swarm.upload_status`, the shell
//! parents ([`Shell`]), against what the vectors have for them until D12's
//! `methods` cases come:
//!
//! - **the grammar's scenarios** (`vectors/swarm-grammar.json`): every
//!   honest scenario of the rows `swarm.publish:data,file`,
//!   `swarm.publish:collection`, `swarm.feed:create`, `swarm.feed:update`,
//!   `swarm.stamps` and `swarm.upload_status`, played through the machine
//!   with exact calls (form, method, path, query, headers, the body byte
//!   for byte), and every forbidden scenario of those rows never made;
//! - **`bodies`**: every tar (the `tar-paths` deviation's cases with the
//!   core's whole names) through a collection, and every single-file body
//!   through `data`;
//! - **`stamps`**: `stamps.mapped` through `swarm.stamps` (the list and one
//!   batch), and `stamps.select` through `swarm.publish` (`requireCapacity`)
//!   and `swarm.feed` (no options);
//! - **results and errors** as the reference's services give them for the
//!   inputs those use (publish-service.js, feed-service.js,
//!   stamp-service.js, swarm-signer.js, chunk-service.js over bee-js
//!   13.2.0), the history row `freedom://publish` keeps (through SQLite),
//!   each ask's charge, and D13's bounds.
//!
//! The scenarios' params are abbreviated (they name what the row binds);
//! each test gives the whole params main sends, with what the scenario's
//! calls show (a name, a content type, the bytes of the body).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, VecDeque};

use common::*;
use fc_json::JsString;
use fc_json::index::{Index, KeyOrder, Kind, Value as V};
use fc_swarm_provider::machine::node::{BodyAbort, BodyOut, CHARGE_FLOOR, MAX_FRAME, WINDOW};
use fc_swarm_provider::machine::shell::{
    AskBound, Deadline, Shell, ShellCall, ShellError, ShellMethod, ShellOutcome, ask_bound,
};
use fc_swarm_provider::machine::{
    Abort, Ask, AskId, Body, Effect, ErrorCode, Event, Failed, Form, Need, NodeCall, Protocol,
    Reply, Rule, SignKey, SignSoc, Signed, StoreWrite, UPLOAD_CHARGE, whole_charge,
};
use fc_swarm_provider::methods::shell_publish::{EARLY_ANSWER_MESSAGE, USER_ORIGIN};
use fc_swarm_provider::stores::history::{self, Bind, Cell, Statement};
use fc_swarm_provider::value::Value;

/// The rows these machines make calls under.
const ROWS: [&str; 6] = [
    "swarm.publish:data,file",
    "swarm.publish:collection",
    "swarm.feed:create",
    "swarm.feed:update",
    "swarm.stamps",
    "swarm.upload_status",
];

/// The vectors' clock (`bodies`' `mtime_ms`; the feed update's timestamp
/// is its second).
const CLOCK: u64 = 1_767_225_600_123;

// ---------------------------------------------------------------------------
// Main, scripted.

/// The node's answer to a call and the body it received.
type NodeFn<'a> = Box<dyn FnMut(&NodeCall, &[u8]) -> Event + 'a>;

struct PartFeed {
    id: AskId,
    part: u32,
    data: Vec<u8>,
    sent: usize,
    window: usize,
    ended: bool,
}

/// A call the core made, and the body main sent the node for it.
#[derive(Debug, Clone)]
struct Called {
    call: NodeCall,
    body: Vec<u8>,
}

#[derive(Default)]
struct Played {
    calls: Vec<Called>,
    asks: Vec<Ask>,
    writes: Vec<StoreWrite>,
    signed: Vec<SignSoc>,
    cancels: Vec<AskId>,
    /// Each streamed body's terminal.
    terminals: Vec<(AskId, BodyOut)>,
}

struct Main<'a> {
    world: TestWorld,
    node: NodeFn<'a>,
    parts: BTreeMap<u32, Vec<u8>>,
    keys: &'a Keys,
    unlocked: bool,
    next_row: i64,
    /// Store writes from this one on (counting from 0) fail with the text.
    fail_writes: Option<(usize, &'static str)>,
    /// The history's statements, run through SQLite.
    db: Option<HistoryDb>,
    /// Stop (and return) once this many node calls were asked.
    stop_after: Option<usize>,
    /// Main ends this part with this abort after its first frame (a
    /// picked file's read failing).
    abort_part: Option<(u32, Abort)>,
}

impl<'a> Main<'a> {
    fn new(keys: &'a Keys, node: NodeFn<'a>) -> Main<'a> {
        Main {
            world: TestWorld::new(CLOCK),
            node,
            parts: BTreeMap::new(),
            keys,
            unlocked: true,
            next_row: 1,
            fail_writes: None,
            db: None,
            stop_after: None,
            abort_part: None,
        }
    }

    fn key(&self, key: SignKey) -> &k256::ecdsa::SigningKey {
        match key {
            SignKey::BeeWallet => &self.keys.bee,
            SignKey::Publisher(i) => &self.keys.publishers[&u64::from(i)],
        }
    }

    /// Plays `call` to its outcome.
    fn play(&mut self, call: ShellCall) -> (ShellOutcome, Played, Shell) {
        let mut shell = Shell::start(call, &mut self.world);
        let mut played = Played::default();
        let mut queue: VecDeque<Effect> = shell.take_effects().into();
        let mut parts: Vec<PartFeed> = Vec::new();
        let mut credits: VecDeque<(AskId, usize)> = VecDeque::new();
        let mut at: BTreeMap<AskId, usize> = BTreeMap::new();
        loop {
            if shell.outcome().is_some() {
                break;
            }
            if self
                .stop_after
                .is_some_and(|n| played.calls.len() >= n && queue.is_empty())
            {
                break;
            }
            if let Some(effect) = queue.pop_front() {
                match effect {
                    Effect::Ask(ask) => {
                        played.asks.push(ask.clone());
                        self.answer(&mut shell, &mut played, &mut parts, &mut at, ask);
                    }
                    Effect::Credit { id, bytes } => {
                        let part = parts.iter_mut().find(|p| p.id == id).expect("a part");
                        part.window += bytes;
                    }
                    Effect::Cancel(id) => played.cancels.push(id),
                    Effect::Body { id, out } => match out {
                        BodyOut::Head { bytes } => {
                            let Some(Body::Stream { bytes: declared }) =
                                &played.calls[at[&id]].call.body
                            else {
                                panic!("a head for a body that doesn't stream")
                            };
                            assert_eq!(bytes, *declared);
                        }
                        BodyOut::Data(frame) => {
                            assert!(!frame.is_empty() && frame.len() <= MAX_FRAME);
                            played.calls[at[&id]].body.extend_from_slice(&frame);
                            credits.push_back((id, frame.len()));
                        }
                        BodyOut::End => {
                            played.terminals.push((id, BodyOut::End));
                            credits.retain(|(c, _)| *c != id);
                            let called = &played.calls[at[&id]];
                            let event = (self.node)(&called.call, &called.body);
                            shell.answer(&mut self.world, id, event);
                        }
                        BodyOut::Abort(why) => {
                            credits.retain(|(c, _)| *c != id);
                            played.terminals.push((id, BodyOut::Abort(why)));
                        }
                    },
                }
                queue.extend(shell.take_effects());
                continue;
            }
            if let Some((id, bytes)) = credits.pop_front() {
                shell.answer(&mut self.world, id, Event::BodyCredit(bytes));
                queue.extend(shell.take_effects());
                continue;
            }
            if let Some(part) = parts
                .iter_mut()
                .find(|p| !p.ended && (p.window > 0 || p.sent == p.data.len()))
            {
                let n = part.window.min(MAX_FRAME).min(part.data.len() - part.sent);
                let id = part.id;
                if let Some((_, abort)) = self.abort_part.filter(|(k, _)| *k == part.part)
                    && (part.sent > 0 || part.data.is_empty())
                {
                    part.ended = true;
                    shell.answer(&mut self.world, id, Event::Abort(abort));
                } else if n > 0 {
                    let frame = part.data[part.sent..part.sent + n].to_vec();
                    part.sent += n;
                    part.window -= n;
                    shell.answer(&mut self.world, id, Event::Data(frame));
                } else {
                    part.ended = true;
                    shell.answer(&mut self.world, id, Event::End);
                }
                queue.extend(shell.take_effects());
                continue;
            }
            panic!("the request waits with nothing asked");
        }
        // After the outcome: cancels, a body's terminal, a row's last write.
        loop {
            let rest = shell.take_effects();
            if rest.is_empty() && queue.is_empty() {
                break;
            }
            for effect in queue.drain(..).chain(rest) {
                match effect {
                    Effect::Cancel(id) => played.cancels.push(id),
                    Effect::Body { id, out } => played.terminals.push((id, out)),
                    Effect::Ask(ask) => {
                        played.asks.push(ask.clone());
                        if let Need::Write(write) = ask.need {
                            let event = self.write(&mut played, write);
                            shell.answer(&mut self.world, ask.id, event);
                        }
                    }
                    Effect::Credit { .. } => {}
                }
            }
        }
        let outcome = shell.outcome().cloned().unwrap_or(ShellOutcome::Cancelled);
        (outcome, played, shell)
    }

    fn write(&mut self, played: &mut Played, write: StoreWrite) -> Event {
        let n = played.writes.len();
        played.writes.push(write.clone());
        let failing = self.fail_writes.filter(|(from, _)| n >= *from);
        match write {
            StoreWrite::HistoryInsert(statement) => match failing {
                Some((_, text)) => Event::Inserted(Err(JsString::from(text))),
                None => {
                    let row = match &self.db {
                        Some(db) => db.insert(&statement),
                        None => {
                            let row = self.next_row;
                            self.next_row += 1;
                            row
                        }
                    };
                    Event::Inserted(Ok(row))
                }
            },
            StoreWrite::History(statements) => match failing {
                Some((_, text)) => Event::Written(Err(JsString::from(text))),
                None => {
                    if let Some(db) = &self.db {
                        for s in &statements {
                            db.run(s);
                        }
                    }
                    Event::Written(Ok(()))
                }
            },
            other => panic!("a shell parent writes no {other:?}"),
        }
    }

    fn answer(
        &mut self,
        shell: &mut Shell,
        played: &mut Played,
        parts: &mut Vec<PartFeed>,
        at: &mut BTreeMap<AskId, usize>,
        ask: Ask,
    ) {
        let id = ask.id;
        let event = match ask.need {
            Need::Node(call) => {
                let streams = matches!(call.body, Some(Body::Stream { .. }));
                let body = match &call.body {
                    Some(Body::Base64(b)) => b.clone(),
                    _ => Vec::new(),
                };
                at.insert(id, played.calls.len());
                played.calls.push(Called {
                    call: call.clone(),
                    body: body.clone(),
                });
                if self.stop_after.is_some_and(|n| played.calls.len() > n) {
                    return;
                }
                if streams {
                    Event::BodyOpen
                } else {
                    (self.node)(&call, &body)
                }
            }
            Need::Part(k) => {
                let data = self.parts[&k].clone();
                let len = data.len() as u64;
                parts.push(PartFeed {
                    id,
                    part: k,
                    data,
                    sent: 0,
                    window: WINDOW as usize,
                    ended: false,
                });
                Event::PartHead(len)
            }
            Need::Upload => Event::Turn,
            Need::Lock(_) => Event::Locked,
            Need::Owner(key) => {
                Event::Owner(Ok(self.unlocked.then(|| fc_evm::address_of(self.key(key)))))
            }
            Need::Sign(soc) => {
                played.signed.push(soc.clone());
                let signed = fc_swarm::sign_soc(
                    self.key(soc.key),
                    &soc.identifier,
                    Some(soc.span),
                    &soc.payload,
                )
                .unwrap();
                Event::Signed(Ok(Signed {
                    signature: signed.signature,
                    owner: signed.owner,
                }))
            }
            Need::Write(write) => self.write(played, write),
            other => panic!("a shell parent asks no {other:?}"),
        };
        shell.answer(&mut self.world, id, event);
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
    fn open() -> HistoryDb {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(history::DDL).unwrap();
        HistoryDb { conn }
    }

    fn run(&self, statement: &Statement) {
        self.conn
            .execute(
                statement.sql,
                rusqlite::params_from_iter(statement.params.iter().map(sql_value)),
            )
            .unwrap();
    }

    fn insert(&self, statement: &Statement) -> i64 {
        assert_eq!(statement.sql, history::INSERT_SQL);
        self.run(statement);
        self.conn.last_insert_rowid()
    }

    /// `getEntries()`, as `rowToEntry` gives them.
    fn entries(&self) -> Vec<fc_json::JsValue> {
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
        history::entries(&rows)
            .unwrap()
            .as_array()
            .unwrap()
            .to_vec()
    }
}

// ---------------------------------------------------------------------------
// The vectors.

struct Vectors {
    swarm: String,
    grammar: String,
    keys: String,
}

impl Vectors {
    fn load() -> Vectors {
        Vectors {
            swarm: text_of("swarm.json"),
            grammar: text_of("swarm-grammar.json"),
            keys: text_of("keys.json"),
        }
    }
}

/// `{ stamps: [<the usable batch a1a1…>] }`, stamps.select's
/// `usable/content-4096`.
fn usable_stamps(swarm: V<'_, '_>) -> Vec<u8> {
    let case = get(get(swarm, "stamps"), "select")
        .children()
        .find(|c| get(*c, "id").is_str("usable/content-4096"))
        .unwrap();
    get(case, "stamps")
        .stringify(KeyOrder::Property)
        .into_bytes()
}

fn json_reply(status: u16, headers: Vec<(&str, String)>, body: &str) -> Event {
    let mut headers: Vec<(String, String)> = headers
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
    headers.insert(
        0,
        (
            "content-type".to_owned(),
            "application/json; charset=utf-8".to_owned(),
        ),
    );
    Event::Reply(Reply {
        status,
        status_text: reason_phrase(status).to_owned(),
        headers,
        body: body.as_bytes().to_vec(),
    })
}

/// A node that answers every form honestly: `/stamps` from `stamps`, an
/// upload with the SHA-256 of its body as its reference and tag 101, a feed
/// manifest, a SOC with its own address, a tag.
fn honest_node<'a>(stamps: Vec<u8>) -> NodeFn<'a> {
    Box::new(move |call: &NodeCall, body: &[u8]| {
        match call.form {
        Form::Stamps => Event::Reply(Reply {
            status: 200,
            status_text: "OK".to_owned(),
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: stamps.clone(),
        }),
        Form::BzzFile | Form::BzzTar => json_reply(
            201,
            vec![("swarm-tag", "101".to_owned())],
            &format!(r#"{{"reference":"{}"}}"#, sha(body)),
        ),
        Form::FeedManifest => json_reply(201, Vec::new(), &format!(r#"{{"reference":"{}"}}"#, "e1".repeat(32))),
        Form::SocUp => {
            let segments: Vec<&str> = call.path.split('/').collect();
            let owner: [u8; 20] = unhex(segments[2]).try_into().unwrap();
            let id: [u8; 32] = unhex(segments[3]).try_into().unwrap();
            let address = fc_swarm::verify::soc_address(&id, &owner);
            json_reply(201, Vec::new(), &format!(r#"{{"reference":"{}"}}"#, hex(&address)))
        }
        Form::FeedHead => Event::Reply(ReplySpec::not_found().into_reply()),
        Form::Chunk => Event::Reply(ReplySpec::not_found().into_reply()),
        Form::Tag => json_reply(
            200,
            Vec::new(),
            r#"{"uid":101,"address":"","split":10,"seen":0,"stored":10,"sent":5,"synced":10,"startedAt":"2026-01-01T00:00:00Z"}"#,
        ),
        Form::Stamp => Event::Reply(Reply {
            status: 200,
            status_text: "OK".to_owned(),
            headers: Vec::new(),
            body: br#"{"batchID":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","utilization":0,"usable":true,"label":"freedom","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000}"#.to_vec(),
        }),
        other => panic!("a shell parent makes no {other:?} call"),
    }
    })
}

trait IntoReply {
    fn into_reply(self) -> Reply;
}

impl IntoReply for ReplySpec {
    fn into_reply(self) -> Reply {
        Reply {
            status: self.status,
            status_text: self.status_text,
            headers: self.headers,
            body: self.body,
        }
    }
}

fn parse(method: ShellMethod, params: &str) -> ShellCall {
    ShellCall::parse(method, &fc_json::parse(params).unwrap()).unwrap()
}

fn b64_of(bytes: &[u8]) -> String {
    fc_swarm_provider::value::encode_base64(bytes)
}

/// A tar body's entries and mtime (ustar, names in the name field or
/// prefixed), as a test reads the scenarios' bodies back.
fn untar(tar: &[u8]) -> (u64, Vec<(String, Vec<u8>)>) {
    let octal = |field: &[u8]| {
        let text: String = field
            .iter()
            .take_while(|b| **b != 0 && **b != b' ')
            .map(|b| char::from(*b))
            .collect();
        u64::from_str_radix(&text, 8).unwrap_or(0)
    };
    let cstr = |field: &[u8]| {
        String::from_utf8(field.iter().take_while(|b| **b != 0).copied().collect()).unwrap()
    };
    let mut at = 0;
    let mut mtime = 0;
    let mut entries = Vec::new();
    let mut long: Option<String> = None;
    while at + 512 <= tar.len() && tar[at..at + 512].iter().any(|b| *b != 0) {
        let header = &tar[at..at + 512];
        let size = octal(&header[124..136]) as usize;
        let data = tar[at + 512..at + 512 + size].to_vec();
        at += 512 + size.div_ceil(512) * 512;
        if header[156] == b'L' {
            // A GNU long link: the next entry's whole path.
            long = Some(cstr(&data));
            continue;
        }
        mtime = octal(&header[136..148]);
        let prefix = cstr(&header[345..500]);
        let name = cstr(&header[..100]);
        let path = match long.take() {
            Some(path) => path,
            None if prefix.is_empty() => name,
            None => format!("{prefix}/{name}"),
        };
        entries.push((path, data));
    }
    (mtime, entries)
}

// ---------------------------------------------------------------------------
// The scenarios' calls.

/// A core call against a scenario call: form, method, path, query, the
/// headers (main's own aside), the body (its bytes, inline or streamed),
/// `max_bytes` where the scenario gives it.
fn same_call(got: &Called, want: V<'_, '_>) -> Result<(), String> {
    let call = &got.call;
    if !get(want, "form").is_str(call.form.as_str())
        || !get(want, "method").is_str(call.method())
        || !get(want, "path").is_str(&call.path)
    {
        return Err(format!(
            "{} {} {}",
            call.form.as_str(),
            call.method(),
            call.path
        ));
    }
    let pairs = |v: Option<V<'_, '_>>| -> Vec<(String, String)> {
        v.map(|q| {
            q.children()
                .map(|p| {
                    let mut it = p.children();
                    (string(it.next().unwrap()), string(it.next().unwrap()))
                })
                .collect()
        })
        .unwrap_or_default()
    };
    if pairs(want.get("query")) != call.query {
        return Err(format!("query {:?}", call.query));
    }
    let headers: Vec<(String, String)> = pairs(want.get("headers"))
        .into_iter()
        .filter(|(k, _)| k != "accept" && k != "accept-encoding")
        .collect();
    if headers != call.headers {
        return Err(format!("headers {:?} where {headers:?}", call.headers));
    }
    match want.get("body") {
        // No body bytes: none, or an empty inline body (an empty file).
        None => {
            let empty = match &call.body {
                None => true,
                Some(Body::Base64(b)) => b.is_empty(),
                Some(Body::Stream { .. }) => false,
            };
            if !empty || !got.body.is_empty() {
                return Err("a body where none".to_owned());
            }
        }
        Some(body) => {
            let bytes = number(get(body, "bytes")) as usize;
            if got.body.len() != bytes {
                return Err(format!("a body of {} where {bytes}", got.body.len()));
            }
            if let Some(b) = body.get("base64") {
                if got.body != common::b64(&string(b)) {
                    return Err("the body's bytes".to_owned());
                }
            } else if !get(body, "sha256").is_str(&sha(&got.body)) {
                return Err("the body's SHA-256".to_owned());
            }
        }
    }
    if let Some(m) = want.get("max_bytes")
        && number(m) as usize != call.max_bytes
    {
        return Err(format!("max_bytes {}", call.max_bytes));
    }
    Ok(())
}

/// The params main sends for each honest scenario, with what its calls
/// show beyond the scenario's abbreviated params, and the parts' bytes.
fn scenario_params(id: &str, scenario: V<'_, '_>) -> (String, BTreeMap<u32, Vec<u8>>, u64) {
    let calls: Vec<V<'_, '_>> = get(scenario, "calls").children().collect();
    let last = *calls.last().unwrap();
    let body = || {
        last.get("body")
            .map(|b| common::b64(&string(get(b, "base64"))))
    };
    let mut parts = BTreeMap::new();
    let mut clock = CLOCK;
    let params = match id {
        "swarm.publish-data-default" => format!(
            r#"{{"kind":"data","parts":[{{"bytes":5,"base64":"{}"}}],"pin":true,"deferred":false}}"#,
            b64_of(&body().unwrap())
        ),
        "swarm.publish-data-batch-encrypt" => format!(
            r#"{{"kind":"data","parts":[{{"bytes":5,"base64":"{}"}}],"name":"draft.md","content_type":"text/markdown","encrypt":true,"batch":"{}","pin":true,"deferred":false}}"#,
            b64_of(&body().unwrap()),
            "b2".repeat(32)
        ),
        "swarm.publish-file-default" => {
            // A picked file: main streams it as a part.
            parts.insert(0, body().unwrap());
            r#"{"kind":"file","parts":[{"bytes":9,"part":0}],"name":"notes.txt","pin":true,"deferred":true}"#.to_owned()
        }
        "swarm.publish-collection-index-default" | "swarm.publish-collection-batch-encrypt" => {
            let (mtime, entries) = untar(&body().unwrap());
            clock = mtime * 1000;
            let mut items = Vec::new();
            for (k, (path, data)) in entries.iter().enumerate() {
                parts.insert(k as u32, data.clone());
                items.push(format!(
                    r#"{{"path":"{path}","bytes":{},"part":{k}}}"#,
                    data.len()
                ));
            }
            let extra = if id.ends_with("batch-encrypt") {
                format!(
                    r#","index_document":"x.txt","encrypt":true,"batch":"{}""#,
                    "b2".repeat(32)
                )
            } else {
                String::new()
            };
            format!(
                r#"{{"kind":"collection","parts":[{}]{extra},"pin":true,"deferred":true}}"#,
                items.join(",")
            )
        }
        _ => get(scenario, "params").stringify(KeyOrder::Property),
    };
    (params, parts, clock)
}

fn method_of(row: &str) -> ShellMethod {
    match row.split(':').next().unwrap() {
        "swarm.publish" => ShellMethod::Publish,
        "swarm.feed" => ShellMethod::Feed,
        "swarm.stamps" => ShellMethod::Stamps,
        "swarm.upload_status" => ShellMethod::UploadStatus,
        other => panic!("{other}"),
    }
}

/// A node that answers a scenario's calls in order with each call's
/// recorded reply (status and headers) and the body the form needs.
fn scenario_node<'a>(swarm: V<'_, '_>, scenario: V<'a, 'a>) -> NodeFn<'a> {
    let honest = std::cell::RefCell::new(honest_node(usable_stamps(swarm)));
    let replies: Vec<Option<V<'a, 'a>>> = get(scenario, "calls")
        .children()
        .map(|c| c.get("reply"))
        .collect();
    let mut n = 0usize;
    Box::new(move |call: &NodeCall, body: &[u8]| {
        let recorded = replies.get(n).copied().flatten();
        n += 1;
        let mut event = (honest.borrow_mut())(call, body);
        if let (Some(reply), Event::Reply(r)) = (recorded, &mut event) {
            r.status = number(get(reply, "status")) as u16;
            r.status_text = reason_phrase(r.status).to_owned();
            if let Some(headers) = reply.get("headers") {
                for (k, v) in headers.members() {
                    r.headers.push((string(k), string(v)));
                }
            }
        }
        event
    })
}

#[test]
fn every_honest_scenario_makes_its_calls_exactly() {
    let v = Vectors::load();
    let swarm_index = Index::new(&v.swarm).unwrap();
    let grammar_index = Index::new(&v.grammar).unwrap();
    let keys_index = Index::new(&v.keys).unwrap();
    let keys = keys(&keys_index);
    let mut played_rows = BTreeMap::new();
    for scenario in get(grammar_index.root(), "honest").children() {
        let row = string(get(scenario, "row"));
        if !ROWS.contains(&row.as_str()) {
            continue;
        }
        let id = string(get(scenario, "id"));
        let (params, parts, clock) = scenario_params(&id, scenario);
        let mut main = Main::new(&keys, scenario_node(swarm_index.root(), scenario));
        main.world.now = clock;
        main.parts = parts;
        let (outcome, played, _) = main.play(parse(method_of(&row), &params));
        let wants: Vec<_> = get(scenario, "calls").children().collect();
        assert_eq!(played.calls.len(), wants.len(), "{id}: {:?}", played.calls);
        for (got, want) in played.calls.iter().zip(&wants) {
            same_call(got, *want).unwrap_or_else(|why| panic!("{id}: {why}"));
        }
        let ShellOutcome::Result(result) = &outcome else {
            panic!("{id}: {outcome:?}")
        };
        check_scenario_result(&id, result, &played);
        *played_rows.entry(row).or_insert(0) += 1;
    }
    for row in ROWS {
        assert!(played_rows.get(row).is_some_and(|n| *n > 0), "{row}");
    }
}

/// Each honest scenario's answer, as the reference's service gives it.
fn check_scenario_result(id: &str, result: &Value, played: &Played) {
    let upload = |reference: &str, batch: &str, bytes: u64| {
        Value::object([
            ("reference", Value::str(reference)),
            ("tag_uid", Value::int(101)),
            ("batch", Value::str(batch)),
            ("bytes", Value::int(bytes)),
        ])
    };
    let a1 = "a1".repeat(32);
    let b2 = "b2".repeat(32);
    let body_sha = || sha(&played.calls.last().unwrap().body);
    let want = match id {
        "swarm.publish-data-default" => upload(&body_sha(), &a1, 5),
        "swarm.publish-data-batch-encrypt" => upload(&body_sha(), &b2, 5),
        "swarm.publish-file-default" => upload(&body_sha(), &a1, 9),
        "swarm.publish-collection-index-default" => upload(&body_sha(), &a1, 5),
        "swarm.publish-collection-batch-encrypt" => upload(&body_sha(), &b2, 1),
        // feed-service.js's `createFeed`: the owner as `toChecksum()`.
        "swarm.feed-create-batch" => Value::object([
            (
                "topic",
                Value::str("535f5e55cf50c240bce75d6b2d03c817fc460a43489eb32bdf53710d06fcc18f"),
            ),
            (
                "owner",
                Value::str("0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"),
            ),
            ("manifestReference", Value::str(&"e1".repeat(32))),
            ("bzzUrl", Value::str(&format!("bzz://{}", "e1".repeat(32)))),
        ]),
        // `Math.max(minIndex, nextIndex)`: 9 over the head's next, 3.
        "swarm.feed-update-min-index" => Value::object([("index", Value::int(9))]),
        // mapPostageBatch's fields, then the raw flags and TTL.
        "swarm.stamps-list" => Value::array([Value::object([
            ("batchID", Value::str(&a1)),
            ("utilization", Value::int(0)),
            ("usable", Value::Bool(true)),
            ("label", Value::str("freedom")),
            ("depth", Value::int(22)),
            ("amount", Value::str("100000000000")),
            ("bucketDepth", Value::int(16)),
            ("blockNumber", Value::int(1000)),
            ("immutableFlag", Value::Bool(true)),
            ("usage", Value::int(0)),
            ("usageText", Value::str("0%")),
            ("size", Value::int(7_070_000_000)),
            ("remainingSize", Value::int(7_070_000_000)),
            ("theoreticalSize", Value::int(17_179_869_184)),
            ("duration", Value::int(864_000)),
            ("exists", Value::Bool(true)),
            ("batchTTL", Value::int(864_000)),
        ])]),
        // normalizeTag: 5 of 10 sent, every chunk synced.
        "swarm.upload_status" => Value::object([
            ("tagUid", Value::int(101)),
            ("split", Value::int(10)),
            ("seen", Value::int(0)),
            ("stored", Value::int(10)),
            ("sent", Value::int(5)),
            ("synced", Value::int(10)),
            ("progress", Value::int(50)),
            ("done", Value::Bool(true)),
        ]),
        other => panic!("{other}: no answer written for it"),
    };
    assert_eq!(*result, want, "{id}");
}

/// Each forbidden alternative's last call is never made: the machine run
/// on the params of the honest scenario it comes from makes another call
/// there, and the rule's own property holds.
#[test]
fn no_forbidden_alternative_is_made() {
    let v = Vectors::load();
    let swarm_index = Index::new(&v.swarm).unwrap();
    let grammar_index = Index::new(&v.grammar).unwrap();
    let keys_index = Index::new(&v.keys).unwrap();
    let keys = keys(&keys_index);
    let honest = scenarios(grammar_index.root());
    let mut checked = 0;
    for forbidden in get(grammar_index.root(), "forbidden").children() {
        let row = string(get(forbidden, "row"));
        if !ROWS.contains(&row.as_str()) {
            continue;
        }
        let id = string(get(forbidden, "id"));
        let from = string(get(forbidden, "from"));
        let from = from.strip_prefix("honest/").unwrap();
        let scenario = honest[from];
        let (params, parts, clock) = scenario_params(from, scenario);
        let mut main = Main::new(&keys, scenario_node(swarm_index.root(), scenario));
        main.world.now = clock;
        main.parts = parts;
        let (_, played, _) = main.play(parse(method_of(&row), &params));
        let wants: Vec<_> = get(forbidden, "calls").children().collect();
        let (last, before) = wants.split_last().unwrap();
        let prefix = before.len();
        let made = played.calls.len() > prefix
            && played.calls[..prefix]
                .iter()
                .zip(before)
                .all(|(got, want)| same_call(got, *want).is_ok())
            && same_call(&played.calls[prefix], *last).is_ok();
        assert!(!made, "{id}: the machine made the forbidden call");
        // The rule's own property, over every call.
        let header = |c: &Called, name: &str| {
            c.call
                .headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        match id.as_str() {
            "swarm.publish-batch-other" => {
                assert!(played.calls.iter().all(|c| c.call.form == Form::Stamps
                    || header(c, "swarm-postage-batch-id") == Some("b2".repeat(32))))
            }
            "swarm.publish-batch-and-stamps" => {
                assert!(played.calls.iter().all(|c| c.call.form != Form::Stamps));
            }
            "swarm.publish-encrypt-not-asked" => {
                assert!(
                    played
                        .calls
                        .iter()
                        .all(|c| header(c, "swarm-encrypt").is_none())
                );
            }
            "swarm.stamps-write" => assert!(
                played
                    .calls
                    .iter()
                    .all(|c| matches!(c.call.form, Form::Stamps | Form::Stamp))
            ),
            other => panic!("{other}: no property written for it"),
        }
        checked += 1;
    }
    assert_eq!(checked, 4);
}

// ---------------------------------------------------------------------------
// `bodies`.

/// T(parts): a header, room for a long-name entry and the body, each padded
/// to 512 bytes, then the two zero blocks (the grammar's bound on a
/// collection's tar).
fn tar_bound(entries: &[(String, Vec<u8>)]) -> u64 {
    1024 + entries
        .iter()
        .map(|(path, data)| {
            1024 + (path.len() as u64).div_ceil(512) * 512 + (data.len() as u64).div_ceil(512) * 512
        })
        .sum::<u64>()
}

/// A collection of `entries` through `swarm.publish`, each part streamed:
/// its upload call.
fn publish_collection(
    keys: &Keys,
    now: u64,
    entries: &[(String, Vec<u8>)],
) -> (ShellOutcome, Called) {
    let mut main = Main::new(keys, honest_node(Vec::new()));
    main.world.now = now;
    let mut items = Vec::new();
    for (k, (path, data)) in entries.iter().enumerate() {
        main.parts.insert(k as u32, data.clone());
        items.push(format!(
            r#"{{"path":{},"bytes":{},"part":{k}}}"#,
            fc_json::JsValue::string(path.as_str()).stringify(),
            data.len()
        ));
    }
    let params = format!(
        r#"{{"kind":"collection","parts":[{}],"batch":"{}","pin":true,"deferred":true}}"#,
        items.join(","),
        "a1".repeat(32)
    );
    let (outcome, played, _) = main.play(parse(ShellMethod::Publish, &params));
    assert_eq!(played.calls.len(), 1, "no /stamps with a batch");
    (outcome, played.calls[0].clone())
}

#[test]
fn every_tar_body_byte_for_byte() {
    let v = Vectors::load();
    let index = Index::new(&v.swarm).unwrap();
    let keys_index = Index::new(&v.keys).unwrap();
    let keys = keys(&keys_index);
    let mut seen = 0;
    for case in get(index.root(), "bodies").children() {
        if !get(case, "kind").is_str("tar") {
            continue;
        }
        let id = string(get(case, "id"));
        let entries: Vec<(String, Vec<u8>)> = get(case, "entries")
            .children()
            .map(|e| (string(get(e, "path")), data_of(get(e, "data"))))
            .collect();
        let now = number(get(case, "mtime_ms")) as u64;
        let (outcome, upload) = publish_collection(&keys, now, &entries);
        assert!(
            matches!(outcome, ShellOutcome::Result(_)),
            "{id}: {outcome:?}"
        );
        assert_eq!(upload.call.form, Form::BzzTar);
        assert_eq!(
            upload.call.body,
            Some(Body::Stream {
                bytes: upload.body.len() as u64
            }),
            "{id}"
        );
        // The grammar's bound holds for every tar the core writes.
        assert!(upload.body.len() as u64 <= tar_bound(&entries), "{id}");
        match case.get("deviation").map(string).as_deref() {
            None => {
                let body = get(case, "body");
                assert_eq!(
                    upload.body.len(),
                    number(get(body, "length")) as usize,
                    "{id}"
                );
                assert!(get(body, "sha256").is_str(&sha(&upload.body)), "{id}");
                if let Some(b) = body.get("base64") {
                    assert_eq!(upload.body, common::b64(&string(b)), "{id}");
                }
            }
            Some("tar-paths") => {
                // bee-js cuts a name; the core keeps every one (counted in
                // bytes: a split, or a GNU long link).
                let reference = common::b64(&string(get(get(case, "reference"), "base64")));
                assert_ne!(upload.body, reference, "{id}");
                assert_eq!(untar(&upload.body), (now / 1000, entries.clone()), "{id}");
                let (_, theirs) = untar(&reference);
                assert!(
                    theirs
                        .iter()
                        .zip(&entries)
                        .any(|((p, _), (want, _))| p != want),
                    "{id}: bee-js kept every name"
                );
                let as_refs: Vec<(&str, &[u8])> = entries
                    .iter()
                    .map(|(p, d)| (p.as_str(), d.as_slice()))
                    .collect();
                assert_eq!(
                    upload.body,
                    fc_swarm::tar::write(&as_refs, now / 1000).unwrap(),
                    "{id}"
                );
            }
            Some(other) => panic!("{id}: {other}"),
        }
        seen += 1;
    }
    assert_eq!(seen, 13);
}

/// `bodies`' single-file requests (publishData's) through `swarm.publish`
/// `data`: the query, the headers and the body, inline up to 64 KiB, else
/// streamed from its part.
#[test]
fn every_file_body_through_data() {
    let v = Vectors::load();
    let index = Index::new(&v.swarm).unwrap();
    let keys_index = Index::new(&v.keys).unwrap();
    let keys = keys(&keys_index);
    let mut seen = 0;
    for case in get(index.root(), "bodies").children() {
        if !get(case, "kind").is_str("file") {
            continue;
        }
        let id = string(get(case, "id"));
        let data = data_of(get(case, "data"));
        let request = get(case, "request");
        let batch = string(
            get(request, "headers")
                .children()
                .find(|h| {
                    h.children()
                        .next()
                        .unwrap()
                        .is_str("swarm-postage-batch-id")
                })
                .unwrap()
                .children()
                .nth(1)
                .unwrap(),
        );
        let mut main = Main::new(&keys, honest_node(Vec::new()));
        let source = if data.len() <= 64 * 1024 {
            format!(r#""base64":"{}""#, b64_of(&data))
        } else {
            main.parts.insert(0, data.clone());
            r#""part":0"#.to_owned()
        };
        let name = case
            .get("name")
            .map(|n| format!(r#","name":{}"#, n.stringify(KeyOrder::Property)))
            .unwrap_or_default();
        let params = format!(
            r#"{{"kind":"data","parts":[{{"bytes":{},{source}}}]{name},"content_type":{},"batch":"{batch}","pin":true,"deferred":false}}"#,
            data.len(),
            get(case, "content_type").stringify(KeyOrder::Property),
        );
        let (outcome, played, _) = main.play(parse(ShellMethod::Publish, &params));
        assert!(
            matches!(outcome, ShellOutcome::Result(_)),
            "{id}: {outcome:?}"
        );
        assert_eq!(played.calls.len(), 1);
        let mut want = request.stringify(KeyOrder::Property);
        // The scenario form of the request: its body as `{ bytes, base64 }`
        // or `{ bytes, sha256 }`.
        want = want.replace(r#""via":"http","#, "");
        let want_index = Index::new(&want).unwrap();
        let mut want_call = want_index.root().stringify(KeyOrder::Property);
        want_call.insert_str(1, r#""form":"bzz_file","#);
        let want_index = Index::new(&want_call).unwrap();
        same_call(&played.calls[0], want_index.root()).unwrap_or_else(|why| panic!("{id}: {why}"));
        let streamed = matches!(played.calls[0].call.body, Some(Body::Stream { .. }));
        assert_eq!(streamed, data.len() > 64 * 1024, "{id}");
        seen += 1;
    }
    assert_eq!(seen, 5);
}

// ---------------------------------------------------------------------------
// `stamps`.

fn stamps_reply(body: Vec<u8>) -> NodeFn<'static> {
    Box::new(move |call: &NodeCall, _: &[u8]| {
        assert!(matches!(call.form, Form::Stamps | Form::Stamp));
        Event::Reply(Reply {
            status: 200,
            status_text: "OK".to_owned(),
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: body.clone(),
        })
    })
}

/// A mapped batch as the vector writes it, then the raw fields
/// `swarm.stamps` keeps beside it.
fn mapped_with_raw(case: V<'_, '_>) -> Value {
    let Value::Object(mut members) =
        Value::from_js(&fc_json::parse(get(case, "mapped").raw()).unwrap())
    else {
        panic!("an object")
    };
    let raw = get(case, "raw");
    for key in ["exists", "propagating"] {
        if let Some(flag) = raw
            .get(key)
            .filter(|f| matches!(f.kind(), Kind::True | Kind::False))
        {
            members.push((JsString::from(key), Value::Bool(flag.kind() == Kind::True)));
        }
    }
    if let Some(ttl) = raw.get("batchTTL").filter(|t| t.kind() == Kind::Number) {
        members.push((JsString::from("batchTTL"), Value::Number(number(ttl))));
    }
    Value::Object(members)
}

/// `stamps.mapped` through `swarm.stamps`, the list (`/stamps`, one batch
/// in it) and one batch (`/stamps/<b>`, the batch alone): the mapped
/// fields with the raw `exists`, `propagating` and `batchTTL`, or bee-js's
/// error (a ZodError's message, its issues' paths from the batch for one),
/// or the core's (`batch-depth`).
#[test]
fn every_mapped_batch_through_swarm_stamps() {
    let v = Vectors::load();
    let index = Index::new(&v.swarm).unwrap();
    let keys_index = Index::new(&v.keys).unwrap();
    let keys = keys(&keys_index);
    let mut seen = 0;
    for case in get(get(index.root(), "stamps"), "mapped").children() {
        let id = string(get(case, "id"));
        let raw = get(case, "raw").stringify(KeyOrder::Property);
        let deviation = case.get("deviation").map(string);
        let error = match deviation.as_deref() {
            Some("batch-depth") => Some(string(get(get(get(case, "core"), "error"), "message"))),
            Some(other) => panic!("{id}: {other}"),
            None => case.get("error").map(|e| string(get(e, "message"))),
        };
        for one in [false, true] {
            let body = if one {
                raw.clone()
            } else {
                format!(r#"{{"stamps":[{raw}]}}"#)
            };
            let mut main = Main::new(&keys, stamps_reply(body.into_bytes()));
            let params = if one {
                format!(r#"{{"id":"{}"}}"#, "A1".repeat(32))
            } else {
                "{}".to_owned()
            };
            let (outcome, played, _) = main.play(parse(ShellMethod::Stamps, &params));
            assert_eq!(played.calls.len(), 1);
            let call = &played.calls[0].call;
            if one {
                // `<b>` = id, lowercased.
                assert_eq!(call.path, format!("/stamps/{}", "a1".repeat(32)));
                assert_eq!((call.form, call.max_bytes), (Form::Stamp, 64 * 1024));
            } else {
                assert_eq!((call.form, call.path.as_str()), (Form::Stamps, "/stamps"));
            }
            match &error {
                Some(message) => {
                    let message = if one {
                        // The batch at the root: no `stamps`, 0 in a path.
                        message.replace("\"stamps\",\n      0,\n      ", "")
                    } else {
                        message.clone()
                    };
                    assert_eq!(
                        outcome,
                        ShellOutcome::Error(ShellError::new(message.as_str())),
                        "{id} one={one}"
                    );
                }
                None => {
                    let want = mapped_with_raw(case);
                    let want = if one { want } else { Value::array([want]) };
                    assert_eq!(outcome, ShellOutcome::Result(want), "{id} one={one}");
                }
            }
        }
        seen += 1;
    }
    assert_eq!(seen, 23);
}

/// `stamps.select` through the methods that choose a batch: a content
/// upload's `{ requireCapacity: true }` through `swarm.publish` (its size
/// the upload's), and a feed's no options at 4,096 through `swarm.feed`.
/// One `/stamps` read where the reference made two (`stamps-one-read`).
#[test]
fn batch_choice_as_select_best_batch() {
    let v = Vectors::load();
    let index = Index::new(&v.swarm).unwrap();
    let keys_index = Index::new(&v.keys).unwrap();
    let keys = keys(&keys_index);
    let mut seen = 0;
    for case in get(get(index.root(), "stamps"), "select").children() {
        let id = string(get(case, "id"));
        let options = get(case, "options").stringify(KeyOrder::Property);
        let size = number(get(case, "size")) as u64;
        let stamps = get(case, "stamps")
            .stringify(KeyOrder::Property)
            .into_bytes();
        let node = honest_node(stamps);
        let mut main = Main::new(&keys, node);
        let call = match options.as_str() {
            r#"{"requireCapacity":true}"# => {
                main.parts.insert(0, Vec::new());
                // The upload itself isn't made: the batch is its header.
                main.stop_after = Some(2);
                parse(
                    ShellMethod::Publish,
                    &format!(
                        r#"{{"kind":"file","parts":[{{"bytes":{size},"part":0}}],"name":"f","pin":true,"deferred":true}}"#
                    ),
                )
            }
            "{}" => {
                assert_eq!(size, 4096);
                parse(
                    ShellMethod::Feed,
                    &format!(
                        r#"{{"op":"create","key":{{"kind":"bee_wallet"}},"topic":"{}"}}"#,
                        "77".repeat(32)
                    ),
                )
            }
            // Messaging's options: no main method of these.
            _ => continue,
        };
        let (outcome, played, _) = main.play(call);
        let stamps_reads = played
            .calls
            .iter()
            .filter(|c| c.call.form == Form::Stamps)
            .count();
        assert_eq!(stamps_reads, 1, "{id}");
        let header = |c: &Called| {
            c.call
                .headers
                .iter()
                .find(|(k, _)| k == "swarm-postage-batch-id")
                .map(|(_, v)| v.clone())
        };
        match (case.get("result"), case.get("error")) {
            (Some(r), _) if r.kind() == Kind::String => {
                assert_eq!(played.calls.len(), 2, "{id}");
                assert_eq!(header(&played.calls[1]), Some(string(r)), "{id}");
            }
            (Some(_), _) => {
                // `null`: noUsableBatchError.
                assert_eq!(
                    outcome,
                    ShellOutcome::Error(ShellError {
                        code: Some("no-usable-stamps"),
                        ..ShellError::new(fc_swarm_provider::errors::NO_USABLE_BATCH_MESSAGE)
                    }),
                    "{id}"
                );
            }
            (None, Some(e)) => {
                let ShellOutcome::Error(err) = &outcome else {
                    panic!("{id}: {outcome:?}")
                };
                assert_eq!(err.message, string(get(e, "message")).as_str(), "{id}");
                assert_eq!(err.code, e.get("code").map(|c| leak(string(c))), "{id}");
                let capacity = e.get("capacity").map(|c| {
                    (
                        number(get(c, "uploadBytes")),
                        number(get(c, "requiredBytes")),
                        number(get(c, "largestRemainingBytes")),
                    )
                });
                let got = err
                    .capacity
                    .map(|c| (c.upload_bytes, c.required_bytes, c.largest_remaining_bytes));
                assert_eq!(got, capacity, "{id}");
                assert_eq!(played.calls.len(), 1, "{id}");
            }
            _ => panic!("{id}"),
        }
        seen += 1;
    }
    assert_eq!(seen, 33);
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

// ---------------------------------------------------------------------------
// Results and errors, as the reference's services give them.

fn keys_of(v: &Vectors) -> Keys {
    let index = Index::new(&v.keys).unwrap();
    keys(&index)
}

fn a1_stamps() -> Vec<u8> {
    let v = Vectors::load();
    let index = Index::new(&v.swarm).unwrap();
    usable_stamps(index.root())
}

/// The honest node, but `form`'s calls answered with `event`.
fn node_with<'a>(form: Form, event: Event) -> NodeFn<'a> {
    let mut honest = honest_node(a1_stamps());
    Box::new(move |call: &NodeCall, body: &[u8]| {
        if call.form == form {
            event.clone()
        } else {
            honest(call, body)
        }
    })
}

const DATA: &str =
    r#"{"kind":"data","parts":[{"bytes":5,"base64":"aGVsbG8="}],"pin":true,"deferred":false}"#;

fn error(message: &str) -> ShellOutcome {
    ShellOutcome::Error(ShellError::new(message))
}

/// zod's one-issue message (`JSON.stringify(issues, null, 2)`).
fn zod(expected: &str, received: &str, path: &[&str]) -> String {
    let path = if path.is_empty() {
        "[]".to_owned()
    } else {
        format!(
            "[\n      {}\n    ]",
            path.iter()
                .map(|p| format!("\"{p}\""))
                .collect::<Vec<_>>()
                .join(",\n      ")
        )
    };
    format!(
        "[\n  {{\n    \"expected\": \"{expected}\",\n    \"code\": \"invalid_type\",\n    \"path\": {path},\n    \"message\": \"Invalid input: expected {expected}, received {received}\"\n  }}\n]"
    )
}

#[test]
fn publish_answers_and_errors_as_bee_js_reads_them() {
    let v = Vectors::load();
    let keys = keys_of(&v);
    let json = |status: u16, tag: Option<&str>, body: &str| {
        json_reply(
            status,
            tag.map(|t| vec![("swarm-tag", t.to_owned())])
                .unwrap_or_default(),
            body,
        )
    };
    let reference = "AB".repeat(32);
    let ok = |result: &ShellOutcome| match result {
        ShellOutcome::Result(v) => v.clone(),
        other => panic!("{other:?}"),
    };
    type Check<'c> = Box<dyn Fn(&ShellOutcome) + 'c>;
    let cases: Vec<(&str, Form, Event, Check<'_>)> = vec![
        // `toHex(result.reference)`: lowercase; `tagUid || null`.
        (
            "upper-case reference, no tag",
            Form::BzzFile,
            json(201, None, &format!(r#"{{"reference":"0x{reference}"}}"#)),
            Box::new(move |o| {
                let v = ok(o);
                assert_eq!(v.get("reference"), &Value::str(&"ab".repeat(32)));
                assert_eq!(v.get("tag_uid"), &Value::Null);
            }),
        ),
        (
            "an encrypted reference",
            Form::BzzFile,
            json(
                201,
                Some("7"),
                &format!(r#"{{"reference":"{}"}}"#, "cd".repeat(64)),
            ),
            Box::new(|o| {
                let v = ok(o);
                assert_eq!(v.get("reference"), &Value::str(&"cd".repeat(64)));
                assert_eq!(v.get("tag_uid"), &Value::int(7));
            }),
        ),
        // makeTagUid: `z.coerce.number().min(0)`.
        (
            "tag 0",
            Form::BzzFile,
            json(201, Some("0"), &format!(r#"{{"reference":"{reference}"}}"#)),
            Box::new(|o| assert_eq!(ok(o).get("tag_uid"), &Value::Null)),
        ),
        (
            "tag 12.5",
            Form::BzzFile,
            json(
                201,
                Some(" 12.5 "),
                &format!(r#"{{"reference":"{reference}"}}"#),
            ),
            Box::new(|o| assert_eq!(ok(o).get("tag_uid"), &Value::Number(12.5))),
        ),
        (
            "tag NaN",
            Form::BzzFile,
            json(
                201,
                Some("abc"),
                &format!(r#"{{"reference":"{reference}"}}"#),
            ),
            Box::new(|o| match o {
                ShellOutcome::Error(e) => {
                    assert!(
                        e.message.as_str().contains("\"expected\": \"number\""),
                        "{e:?}"
                    );
                    assert!(e.message.as_str().contains("NaN"), "{e:?}");
                }
                other => panic!("{other:?}"),
            }),
        ),
        (
            "tag -1",
            Form::BzzFile,
            json(
                201,
                Some("-1"),
                &format!(r#"{{"reference":"{reference}"}}"#),
            ),
            Box::new(|o| match o {
                ShellOutcome::Error(e) => {
                    assert!(e.message.as_str().contains("too_small"), "{e:?}");
                }
                other => panic!("{other:?}"),
            }),
        ),
        // UploadResultBody.
        (
            "no reference",
            Form::BzzFile,
            json(201, None, "{}"),
            Box::new(|o| assert_eq!(*o, error(&zod("string", "undefined", &["reference"])))),
        ),
        (
            "an empty body",
            Form::BzzFile,
            json(201, None, ""),
            Box::new(|o| assert_eq!(*o, error(&zod("object", "null", &[])))),
        ),
        (
            "not JSON (reply-syntax)",
            Form::BzzFile,
            json(201, None, "<html>"),
            Box::new(|o| assert_eq!(*o, error("Swarm node reply is not valid JSON"))),
        ),
        (
            "a short reference",
            Form::BzzFile,
            json(201, None, r#"{"reference":"abcd"}"#),
            Box::new(|o| {
                assert_eq!(
                    *o,
                    error("Bytes#checkByteLength: bytes length is 2 but expected 32 or 64")
                );
            }),
        ),
        // throwHttpError: `<status_text>: <JSON.stringify(body)>`, with the
        // status the agent reads.
        (
            "a node error",
            Form::BzzFile,
            json(402, None, r#"{"code":402,"message":"batch is overissued"}"#),
            Box::new(|o| {
                assert_eq!(
                    *o,
                    ShellOutcome::Error(ShellError {
                        status: Some(402),
                        ..ShellError::new(
                            r#"Payment Required: {"code":402,"message":"batch is overissued"}"#
                        )
                    })
                );
            }),
        ),
        (
            "a node error, a text body",
            Form::Stamps,
            json(500, None, "read failed"),
            Box::new(|o| {
                assert_eq!(
                    *o,
                    ShellOutcome::Error(ShellError {
                        status: Some(500),
                        ..ShellError::new("Internal Server Error: read failed")
                    })
                );
            }),
        ),
        // Transport classes (transport-error-text), main's pool, the cap.
        (
            "unreachable",
            Form::BzzFile,
            Event::Failed(Failed::Unreachable),
            Box::new(|o| assert_eq!(*o, error("fetch failed"))),
        ),
        (
            "stopped",
            Form::Stamps,
            Event::Failed(Failed::Stopped),
            Box::new(|o| assert_eq!(*o, error("Swarm node is not ready"))),
        ),
        (
            "busy",
            Form::Stamps,
            Event::Failed(Failed::Busy),
            Box::new(|o| assert_eq!(*o, ShellOutcome::Busy)),
        ),
        (
            "too large",
            Form::BzzFile,
            Event::Failed(Failed::TooLarge),
            Box::new(|o| assert_eq!(*o, error("Swarm node reply too large"))),
        ),
        // Main's grammar refused the call: only a core bug makes one.
        (
            "refused",
            Form::BzzFile,
            Event::Refused(Rule::Header),
            Box::new(|o| assert_eq!(*o, error("Internal error"))),
        ),
        // A /stamps reply bee-js's schema refuses.
        (
            "stamps malformed",
            Form::Stamps,
            json(200, None, r#"{"stamps":7}"#),
            Box::new(|o| assert_eq!(*o, error(&zod("array", "number", &["stamps"])))),
        ),
    ];
    for (what, form, event, check) in cases {
        let mut main = Main::new(&keys, node_with(form, event));
        let (outcome, _, shell) = main.play(parse(ShellMethod::Publish, DATA));
        check(&outcome);
        assert_eq!(shell.open_asks(), 0, "{what}");
    }
    // A reply past its form's cap is main breaking the protocol.
    let mut main = Main::new(
        &keys,
        node_with(
            Form::Stamps,
            json_reply(200, Vec::new(), &"x".repeat((1 << 20) + 1)),
        ),
    );
    let (outcome, _, _) = main.play(parse(ShellMethod::Publish, DATA));
    assert_eq!(outcome, ShellOutcome::Protocol(Protocol::Bounds));
}

/// A file part main streams: a success before the node took the whole
/// body isn't the upload's.
#[test]
fn an_answer_before_the_whole_body_is_refused() {
    let mut world = TestWorld::new(CLOCK);
    let call = parse(
        ShellMethod::Publish,
        &format!(
            r#"{{"kind":"file","parts":[{{"bytes":200000,"part":3}}],"name":"big.bin","batch":"{}","pin":true,"deferred":true}}"#,
            "a1".repeat(32)
        ),
    );
    let mut shell = Shell::start(call, &mut world);
    let effects = shell.take_effects();
    let [Effect::Ask(turn)] = &effects[..] else {
        panic!("{effects:?}")
    };
    assert_eq!(
        (turn.need.clone(), turn.charge),
        (Need::Upload, UPLOAD_CHARGE)
    );
    shell.answer(&mut world, turn.id, Event::Turn);
    let effects = shell.take_effects();
    let [Effect::Ask(upload)] = &effects[..] else {
        panic!("{effects:?}")
    };
    shell.answer(&mut world, upload.id, Event::BodyOpen);
    let effects = shell.take_effects();
    assert!(matches!(
        &effects[..],
        [
            Effect::Body {
                out: BodyOut::Head { bytes: 200_000 },
                ..
            },
            Effect::Ask(Ask {
                need: Need::Part(3),
                ..
            })
        ]
    ));
    shell.answer(
        &mut world,
        upload.id,
        json_reply(
            201,
            Vec::new(),
            &format!(r#"{{"reference":"{}"}}"#, "ab".repeat(32)),
        ),
    );
    assert_eq!(shell.outcome(), Some(&error(EARLY_ANSWER_MESSAGE)));
    let effects = shell.take_effects();
    assert!(
        effects.iter().any(|e| matches!(
            e,
            Effect::Body {
                out: BodyOut::Abort(BodyAbort::Cancelled),
                ..
            }
        )),
        "{effects:?}"
    );
    assert!(
        effects.iter().any(|e| matches!(e, Effect::Cancel(_))),
        "the part"
    );
}

// ---------------------------------------------------------------------------
// The history row freedom://publish keeps.

fn entry_field(entry: &fc_json::JsValue, key: &str) -> fc_json::JsValue {
    entry
        .get(key)
        .cloned()
        .unwrap_or(fc_json::JsValue::Undefined)
}

#[test]
fn the_history_row_as_the_ipc_handlers_keep_it() {
    let v = Vectors::load();
    let keys = keys_of(&v);
    let with_history = |kind: &str, history: &str, extra: &str| {
        let parts = if kind == "data" {
            r#"[{"bytes":5,"base64":"aGVsbG8="}]"#
        } else {
            r#"[{"bytes":5,"part":0}]"#
        };
        let name = if kind == "file" {
            r#","name":"notes.txt""#
        } else {
            ""
        };
        format!(
            r#"{{"kind":"{kind}","parts":{parts}{name}{extra},"pin":true,"deferred":{},"history":{history}}}"#,
            kind != "data"
        )
    };
    // swarm:publish-data: `{ type: 'data', name: 'Text' }`, then `{ status:
    // 'completed', ...result }`.
    let mut main = Main::new(&keys, honest_node(a1_stamps()));
    main.db = Some(HistoryDb::open());
    let (outcome, played, _) = main.play(parse(
        ShellMethod::Publish,
        &with_history("data", r#"{"type":"data","name":"Text"}"#, ""),
    ));
    let ShellOutcome::Result(result) = &outcome else {
        panic!("{outcome:?}")
    };
    let reference = string_of(result.get("reference"));
    let entries = main.db.as_ref().unwrap().entries();
    assert_eq!(entries.len(), 1);
    let row = &entries[0];
    for (key, want) in [
        ("type", fc_json::JsValue::string("data")),
        ("name", fc_json::JsValue::string("Text")),
        ("status", fc_json::JsValue::string("completed")),
        ("origin", fc_json::JsValue::string(USER_ORIGIN)),
        ("reference", fc_json::JsValue::string(reference.as_str())),
        (
            "bzzUrl",
            fc_json::JsValue::string(format!("bzz://{reference}")),
        ),
        ("tagUid", fc_json::JsValue::Number(101.0)),
        ("batchIdUsed", fc_json::JsValue::string("a1".repeat(32))),
        ("bytesSize", fc_json::JsValue::Number(5.0)),
    ] {
        assert_eq!(entry_field(row, key), want, "{key}");
    }
    // The insert, the bound's trim keeping the row, then the update.
    assert!(matches!(
        &played.writes[..],
        [StoreWrite::HistoryInsert(_), StoreWrite::History(trim), StoreWrite::History(update)]
            if trim[0].sql == history::TRIM_SQL && update[0].sql == history::UPDATE_SQL
    ));

    // A failure: swarm:publish-data keeps the message; -file gives
    // describePublishError's for a batch the network doesn't know yet.
    let unknown = "postage batch a1 rejected by 3 peer(s) as not found on-chain";
    for (kind, history_kind, row_text) in [
        ("data", "data", unknown),
        (
            "file",
            "file",
            fc_swarm_provider::errors::BATCH_NOT_YET_KNOWN_MESSAGE,
        ),
    ] {
        let mut main = Main::new(
            &keys,
            node_with(
                Form::BzzFile,
                json_reply(500, Vec::new(), &format!(r#""{unknown}""#)),
            ),
        );
        main.parts.insert(0, b"hello".to_vec());
        main.db = Some(HistoryDb::open());
        let (outcome, _, _) = main.play(parse(
            ShellMethod::Publish,
            &with_history(
                kind,
                &format!(r#"{{"type":"{history_kind}","name":"n"}}"#),
                "",
            ),
        ));
        let message = format!("Internal Server Error: {unknown}");
        assert_eq!(
            outcome,
            ShellOutcome::Error(ShellError {
                status: Some(500),
                ..ShellError::new(message.as_str())
            }),
            "{kind}"
        );
        let entries = main.db.as_ref().unwrap().entries();
        let want = if kind == "data" {
            message.clone()
        } else {
            row_text.to_owned()
        };
        assert_eq!(
            entry_field(&entries[0], "status"),
            fc_json::JsValue::string("failed")
        );
        assert_eq!(
            entry_field(&entries[0], "errorMessage"),
            fc_json::JsValue::string(want),
            "{kind}"
        );
    }

    // `addEntry` throws: the handler throws, nothing reaches the node.
    let mut main = Main::new(&keys, honest_node(a1_stamps()));
    main.fail_writes = Some((0, "SQLITE_FULL"));
    let (outcome, played, _) = main.play(parse(
        ShellMethod::Publish,
        &with_history("data", r#"{"type":"data","name":"Text"}"#, ""),
    ));
    assert_eq!(outcome, error("SQLITE_FULL"));
    assert!(played.calls.is_empty());

    // The completed update throws: the failed update with its message
    // (once), and the write's error is the answer.
    let mut main = Main::new(&keys, honest_node(a1_stamps()));
    main.fail_writes = Some((2, "EIO"));
    let (outcome, played, _) = main.play(parse(
        ShellMethod::Publish,
        &with_history("data", r#"{"type":"data","name":"Text"}"#, ""),
    ));
    assert_eq!(outcome, error("EIO"));
    assert_eq!(played.writes.len(), 4, "insert, trim, completed, failed");

    // Cancelled mid-upload: the body ends `cancelled`, the row `failed`
    // with `cancelled`.
    let mut main = Main::new(&keys, honest_node(a1_stamps()));
    main.parts.insert(0, vec![7; 300_000]);
    main.db = Some(HistoryDb::open());
    main.stop_after = Some(2);
    let (_, played, mut shell) = main.play(parse(
        ShellMethod::Publish,
        r#"{"kind":"file","parts":[{"bytes":300000,"part":0}],"name":"big","pin":true,"deferred":true,"history":{"type":"file","name":"big"}}"#,
    ));
    assert_eq!(played.calls.len(), 2);
    shell.cancel();
    assert_eq!(shell.outcome(), Some(&ShellOutcome::Cancelled));
    let effects = shell.take_effects();
    assert!(effects.iter().any(|e| matches!(
        e,
        Effect::Body {
            out: BodyOut::Abort(BodyAbort::Cancelled),
            ..
        }
    )));
    let write = effects
        .iter()
        .find_map(|e| match e {
            Effect::Ask(Ask {
                need: Need::Write(StoreWrite::History(s)),
                ..
            }) => Some(s.clone()),
            _ => None,
        })
        .expect("the row's failed update");
    let db = main.db.as_ref().unwrap();
    for s in &write {
        db.run(s);
    }
    let entries = db.entries();
    assert_eq!(
        entry_field(&entries[0], "status"),
        fc_json::JsValue::string("failed")
    );
    assert_eq!(
        entry_field(&entries[0], "errorMessage"),
        fc_json::JsValue::string("cancelled")
    );
}

fn string_of(v: &Value) -> String {
    v.as_js_string().unwrap().as_str().to_owned()
}

// ---------------------------------------------------------------------------
// swarm.feed.

fn feed_params(op: &str, extra: &str) -> String {
    format!(
        r#"{{"op":"{op}","key":{{"kind":"bee_wallet"}},"topic":"{}"{extra}}}"#,
        "77".repeat(32)
    )
}

/// The update's index: the lookup's, or the head probe's after a 404 or a
/// 500, and at least `min_index`; each probe at the next index the probe
/// asks, with its `feed`.
#[test]
fn a_feed_update_writes_at_the_next_index() {
    let v = Vectors::load();
    let keys = keys_of(&v);
    let owner = fc_evm::address_of(&keys.bee);
    let topic = [0x77; 32];
    let reference = "ef".repeat(32);
    // (feed_head's status, the updates that exist, min_index, the index)
    for (head, exist, min_index, want) in [
        (404, 0u64, 0u64, 0u64),
        (404, 0, 5, 5),
        (500, 1, 0, 1),
        (404, 2, 0, 2),
        (404, 5, 3, 5),
        (404, 5, 9, 9),
    ] {
        let mut probes = Vec::new();
        let node = {
            let mut honest = honest_node(a1_stamps());
            let probes = &mut probes;
            Box::new(move |call: &NodeCall, body: &[u8]| match call.form {
                Form::FeedHead => Event::Reply(Reply {
                    status: head,
                    status_text: reason_phrase(head).to_owned(),
                    headers: Vec::new(),
                    body: br#"{"code":404,"message":"Not Found"}"#.to_vec(),
                }),
                Form::Chunk => {
                    let feed = call.feed.expect("a probe names its feed");
                    assert_eq!(feed.owner, owner);
                    let address = fc_swarm::verify::feed_update_address(&owner, &topic, feed.index);
                    assert_eq!(call.path, format!("/chunks/{}", hex(&address)));
                    probes.push(feed.index);
                    if feed.index < exist {
                        Event::Reply(Reply {
                            status: 200,
                            status_text: "OK".to_owned(),
                            headers: Vec::new(),
                            body: vec![0; 105],
                        })
                    } else {
                        Event::Reply(ReplySpec::not_found().into_reply())
                    }
                }
                _ => honest(call, body),
            }) as NodeFn<'_>
        };
        let mut main = Main::new(&keys, node);
        let (outcome, played, _) = main.play(parse(
            ShellMethod::Feed,
            &feed_params(
                "update",
                &format!(r#","reference":"{reference}","min_index":{min_index}"#),
            ),
        ));
        assert_eq!(
            outcome,
            ShellOutcome::Result(Value::object([("index", Value::int(want))])),
            "{head} {exist} {min_index}"
        );
        let soc = played.calls.last().unwrap();
        let id = fc_swarm::verify::feed_update_id(&topic, want);
        assert_eq!(soc.call.path, format!("/soc/{}/{}", hex(&owner), hex(&id)));
        // span ‖ unix seconds ‖ reference.
        let mut body = 40u64.to_le_bytes().to_vec();
        body.extend_from_slice(&(CLOCK / 1000).to_be_bytes());
        body.extend_from_slice(&unhex(&reference));
        assert_eq!(soc.body, body);
        assert_eq!(
            played.signed[0],
            SignSoc {
                key: SignKey::BeeWallet,
                identifier: id,
                span: 40,
                payload: body[8..].to_vec(),
                hold: None,
                kind: fc_swarm_provider::machine::SocKind::Feed,
            }
        );
        drop(main);
        let mut expected = Vec::new();
        if exist > 0 || head != 0 {
            // 0, then 1, 2, 4, … while they exist, then the halving.
            let mut lo = None;
            let mut hi = 0u64;
            loop {
                expected.push(hi);
                if hi >= exist {
                    break;
                }
                lo = Some(hi);
                hi = if hi == 0 { 1 } else { hi * 2 };
            }
            if let Some(mut lo) = lo {
                while hi - lo > 1 {
                    let mid = lo + (hi - lo) / 2;
                    expected.push(mid);
                    if mid < exist {
                        lo = mid;
                    } else {
                        hi = mid;
                    }
                }
            }
        }
        assert_eq!(probes, expected, "{head} {exist}");
    }
}

#[test]
fn feed_answers_and_errors_as_the_reference_gives_them() {
    let v = Vectors::load();
    let keys = keys_of(&v);
    // A locked vault: resolveSwarmSigner's text, nothing asked of the node.
    let mut main = Main::new(&keys, honest_node(a1_stamps()));
    main.unlocked = false;
    let (outcome, played, _) = main.play(parse(ShellMethod::Feed, &feed_params("create", "")));
    assert_eq!(outcome, error("Vault is locked"));
    assert!(played.calls.is_empty());
    // An encrypted reference: an 80-byte body.
    let mut main = Main::new(&keys, honest_node(a1_stamps()));
    let (outcome, played, _) = main.play(parse(
        ShellMethod::Feed,
        &feed_params(
            "update",
            &format!(
                r#","reference":"{}","batch":"{}""#,
                "ab".repeat(64),
                "c3".repeat(32)
            ),
        ),
    ));
    assert!(matches!(outcome, ShellOutcome::Result(_)), "{outcome:?}");
    let soc = played.calls.last().unwrap();
    assert_eq!(soc.body.len(), 80);
    assert!(played.calls.iter().all(|c| c.call.form != Form::Stamps));
    assert!(
        soc.call
            .headers
            .contains(&("swarm-postage-batch-id".to_owned(), "c3".repeat(32)))
    );
    // feed_head's own error ends the lookup with bee-js's text.
    for (form, event, want) in [
        (
            Form::FeedHead,
            json_reply(503, Vec::new(), r#"{"message":"down"}"#),
            error(r#"Service Unavailable: {"message":"down"}"#),
        ),
        (
            Form::FeedHead,
            json_reply(
                200,
                vec![("swarm-feed-index", "0000000000000001".to_owned())],
                "",
            ),
            error("Response did not contain expected swarm-feed-index-next!"),
        ),
        // chunk-service.js's own texts.
        (
            Form::SocUp,
            Event::Reply(Reply {
                status: 500,
                status_text: "Internal Server Error".to_owned(),
                headers: Vec::new(),
                body: b"boom".to_vec(),
            }),
            error("SOC upload failed (500): boom"),
        ),
        (
            Form::SocUp,
            json_reply(
                201,
                Vec::new(),
                &format!(r#"{{"reference":"{}"}}"#, "00".repeat(32)),
            ),
            error(&format!(
                "SOC upload returned unexpected reference: {}",
                "00".repeat(32)
            )),
        ),
        (Form::SocUp, Event::Failed(Failed::Busy), ShellOutcome::Busy),
        (
            Form::FeedHead,
            Event::Failed(Failed::Aborted),
            error("This operation was aborted"),
        ),
    ] {
        let mut main = Main::new(&keys, node_with(form, event));
        let (outcome, _, _) = main.play(parse(
            ShellMethod::Feed,
            &feed_params("update", &format!(r#","reference":"{}""#, "ab".repeat(32))),
        ));
        assert_eq!(outcome, want, "{form:?}");
    }
    // A manifest's answer read as bee-js reads it.
    let mut main = Main::new(
        &keys,
        node_with(Form::FeedManifest, json_reply(201, Vec::new(), "{}")),
    );
    let (outcome, _, _) = main.play(parse(ShellMethod::Feed, &feed_params("create", "")));
    assert_eq!(outcome, error(&zod("string", "undefined", &["reference"])));
}

/// The vault's signature is checked as `createSwarmSigner` checks it.
#[test]
fn a_signature_that_does_not_match_is_refused() {
    let v = Vectors::load();
    let keys = keys_of(&v);
    let mut world = TestWorld::new(CLOCK);
    let call = parse(
        ShellMethod::Feed,
        &feed_params(
            "update",
            &format!(
                r#","reference":"{}","batch":"{}""#,
                "ab".repeat(32),
                "a1".repeat(32)
            ),
        ),
    );
    let mut shell = Shell::start(call, &mut world);
    let owner = fc_evm::address_of(&keys.bee);
    let step = |shell: &mut Shell| -> Ask {
        let effects = shell.take_effects();
        let [Effect::Ask(ask)] = &effects[..] else {
            panic!("{effects:?}")
        };
        ask.clone()
    };
    let ask = step(&mut shell);
    assert_eq!(ask.need, Need::Owner(SignKey::BeeWallet));
    shell.answer(&mut world, ask.id, Event::Owner(Ok(Some(owner))));
    let ask = step(&mut shell);
    assert_eq!(ask.need, Need::Lock([0x77; 32]));
    shell.answer(&mut world, ask.id, Event::Locked);
    let ask = step(&mut shell);
    shell.answer(
        &mut world,
        ask.id,
        json_reply(
            200,
            vec![
                ("swarm-feed-index", "0000000000000000".to_owned()),
                ("swarm-feed-index-next", "0000000000000001".to_owned()),
            ],
            "",
        ),
    );
    let ask = step(&mut shell);
    let Need::Sign(soc) = &ask.need else {
        panic!("{ask:?}")
    };
    let mut signed = fc_swarm::sign_soc(
        &keys.publishers[&0],
        &soc.identifier,
        Some(soc.span),
        &soc.payload,
    )
    .unwrap();
    signed.owner = owner;
    shell.answer(
        &mut world,
        ask.id,
        Event::Signed(Ok(Signed {
            signature: signed.signature,
            owner: signed.owner,
        })),
    );
    assert_eq!(
        shell.outcome(),
        Some(&error(
            "The identity core returned a chunk signature that does not match"
        ))
    );
}

// ---------------------------------------------------------------------------
// swarm.upload_status.

#[test]
fn upload_status_as_get_upload_status_reads_it() {
    let v = Vectors::load();
    let keys = keys_of(&v);
    let tag = |body: &str| json_reply(200, Vec::new(), body);
    for (event, want) in [
        (
            tag(&format!(
                r#"{{"uid":9,"address":"{}","split":0,"seen":0,"stored":0,"sent":0,"synced":0,"startedAt":"x"}}"#,
                "AB".repeat(64)
            )),
            ShellOutcome::Result(Value::object([
                ("tagUid", Value::int(9)),
                ("reference", Value::str(&"ab".repeat(64))),
                ("split", Value::int(0)),
                ("seen", Value::int(0)),
                ("stored", Value::int(0)),
                ("sent", Value::int(0)),
                ("synced", Value::int(0)),
                ("progress", Value::int(0)),
                ("done", Value::Bool(false)),
            ])),
        ),
        (
            json_reply(
                404,
                Vec::new(),
                r#"{"code":404,"message":"tag not present"}"#,
            ),
            ShellOutcome::Error(ShellError {
                status: Some(404),
                ..ShellError::new(r#"Not Found: {"code":404,"message":"tag not present"}"#)
            }),
        ),
        (
            tag(r#"{"uid":"9","seen":0,"sent":0,"split":0,"startedAt":"x","stored":0,"synced":0}"#),
            error(&zod("number", "string", &["uid"])),
        ),
        (
            Event::Failed(Failed::Error),
            error("fetch failed: other side closed"),
        ),
    ] {
        let mut main = Main::new(&keys, node_with(Form::Tag, event));
        let (outcome, played, _) = main.play(parse(ShellMethod::UploadStatus, r#"{"tag_uid":9}"#));
        assert_eq!(outcome, want);
        assert_eq!(played.calls[0].call.path, "/tags/9");
        // No tag owner is read or forgotten.
        assert!(main.world.tags.is_empty());
    }
}

// ---------------------------------------------------------------------------
// D13 and the charges.

/// What each ask charges and what bounds it, as the driver reads them.
#[test]
fn each_ask_charges_and_is_bound_as_the_design_gives_it() {
    let v = Vectors::load();
    let keys = keys_of(&v);
    let mut main = Main::new(&keys, honest_node(a1_stamps()));
    main.parts.insert(0, vec![1; 70_000]);
    main.parts.insert(1, b"<h1>".to_vec());
    let (outcome, played, _) = main.play(parse(
        ShellMethod::Publish,
        r#"{"kind":"collection","parts":[{"path":"a.bin","bytes":70000,"part":0},{"path":"index.html","bytes":4,"part":1}],"pin":true,"deferred":true}"#,
    ));
    assert!(matches!(outcome, ShellOutcome::Result(_)));
    let deadline = ShellMethod::Publish.deadline();
    assert_eq!(deadline, Deadline::Idle);
    for ask in &played.asks {
        let (charge, bound) = match &ask.need {
            Need::Node(call) if call.form == Form::Stamps => {
                (whole_charge(Form::Stamps), AskBound::Total(300_000))
            }
            Need::Node(call) => {
                assert_eq!(call.form, Form::BzzTar);
                (
                    CHARGE_FLOOR,
                    AskBound::BodyThenReply {
                        idle: 60_000,
                        total: 300_000,
                    },
                )
            }
            Need::Upload => (UPLOAD_CHARGE, AskBound::None),
            Need::Part(_) => (0, AskBound::Idle(60_000)),
            other => panic!("{other:?}"),
        };
        assert_eq!(ask.charge, charge, "{:?}", ask.need);
        assert_eq!(ask_bound(deadline, &ask.need), bound, "{:?}", ask.need);
    }
    // A feed update: the vault's and the topic's asks bring no bytes in;
    // each node call its form's whole charge; the request's deadline bounds
    // every one.
    let mut main = Main::new(&keys, honest_node(a1_stamps()));
    let (_, played, _) = main.play(parse(
        ShellMethod::Feed,
        &feed_params("update", &format!(r#","reference":"{}""#, "ab".repeat(32))),
    ));
    for ask in &played.asks {
        let charge = match &ask.need {
            Need::Node(call) => whole_charge(call.form),
            _ => 0,
        };
        assert_eq!(ask.charge, charge, "{:?}", ask.need);
        let bound = ask_bound(ShellMethod::Feed.deadline(), &ask.need);
        match &ask.need {
            Need::Node(_) => assert_eq!(bound, AskBound::Deadline),
            _ => assert_eq!(bound, AskBound::None),
        }
    }
}

/// D13: an ask past its bound is cancelled and read as `failed: error`;
/// main's late answer is taken and dropped; a memory wait past its 60 s
/// ends the request `busy`.
#[test]
fn an_ask_past_its_bound_ends_the_request() {
    let tar = |world: &mut TestWorld| {
        let call = parse(
            ShellMethod::Publish,
            &format!(
                r#"{{"kind":"collection","parts":[{{"path":"a","bytes":10,"part":0}}],"batch":"{}","pin":true,"deferred":true,"history":{{"type":"directory","name":"site"}}}}"#,
                "a1".repeat(32)
            ),
        );
        let mut shell = Shell::start(call, world);
        let mut ids = Vec::new();
        // The insert, the trim, the turn: to the upload call.
        for event in [Event::Inserted(Ok(4)), Event::Written(Ok(())), Event::Turn] {
            let effects = shell.take_effects();
            let [Effect::Ask(ask)] = &effects[..] else {
                panic!("{effects:?}")
            };
            shell.answer(world, ask.id, event);
        }
        let effects = shell.take_effects();
        let [Effect::Ask(upload)] = &effects[..] else {
            panic!("{effects:?}")
        };
        ids.push(upload.id);
        (shell, upload.id)
    };
    // The upload's body gets no credit: the call is cancelled, the body
    // ends `cancelled`, the part goes, and the row ends with the failure.
    let mut world = TestWorld::new(CLOCK);
    let (mut shell, upload) = tar(&mut world);
    shell.answer(&mut world, upload, Event::BodyOpen);
    let effects = shell.take_effects();
    let part = effects
        .iter()
        .find_map(|e| match e {
            Effect::Ask(Ask {
                id,
                need: Need::Part(0),
                ..
            }) => Some(*id),
            _ => None,
        })
        .unwrap();
    shell.answer(&mut world, part, Event::PartHead(10));
    shell.take_effects();
    shell.expire(&mut world, upload);
    let effects = shell.take_effects();
    assert!(effects.contains(&Effect::Cancel(upload)), "{effects:?}");
    assert!(effects.contains(&Effect::Cancel(part)), "{effects:?}");
    assert!(effects.contains(&Effect::Body {
        id: upload,
        out: BodyOut::Abort(BodyAbort::Cancelled)
    }));
    let row_update = effects
        .iter()
        .find_map(|e| match e {
            Effect::Ask(Ask {
                id,
                need: Need::Write(StoreWrite::History(s)),
                ..
            }) => Some((*id, s.clone())),
            _ => None,
        })
        .expect("the row's update");
    assert!(
        row_update.1[0]
            .params
            .contains(&Bind::Text("fetch failed: other side closed".to_owned())),
        "{:?}",
        row_update.1
    );
    // The bound is the request's no more: a second expiry, and main's
    // terminal answers, are taken and dropped.
    shell.expire(&mut world, upload);
    shell.answer(&mut world, upload, Event::Failed(Failed::Error));
    shell.answer(
        &mut world,
        part,
        Event::Abort(fc_swarm_provider::machine::Abort::Cancelled),
    );
    assert_eq!(shell.outcome(), None, "the row's update first");
    shell.answer(&mut world, row_update.0, Event::Written(Ok(())));
    assert_eq!(
        shell.outcome(),
        Some(&error("fetch failed: other side closed"))
    );
    assert_eq!(shell.open_asks(), 0);

    // A part that stops: the body ends `body_stream_error`.
    let mut world = TestWorld::new(CLOCK);
    let (mut shell, upload) = tar(&mut world);
    shell.answer(&mut world, upload, Event::BodyOpen);
    let effects = shell.take_effects();
    let part = effects
        .iter()
        .find_map(|e| match e {
            Effect::Ask(Ask {
                id,
                need: Need::Part(0),
                ..
            }) => Some(*id),
            _ => None,
        })
        .unwrap();
    shell.answer(&mut world, part, Event::PartHead(10));
    shell.expire(&mut world, part);
    let effects = shell.take_effects();
    assert!(effects.contains(&Effect::Cancel(part)));
    assert!(effects.contains(&Effect::Cancel(upload)));
    assert!(effects.contains(&Effect::Body {
        id: upload,
        out: BodyOut::Abort(BodyAbort::BodyStreamError)
    }));

    // Expired before main asked for the body: a `swarm.body` that crosses
    // the cancel still gets its terminal, while the row is written.
    let mut world = TestWorld::new(CLOCK);
    let (mut shell, upload) = tar(&mut world);
    shell.expire(&mut world, upload);
    let effects = shell.take_effects();
    assert!(effects.contains(&Effect::Cancel(upload)));
    assert!(!effects.iter().any(|e| matches!(e, Effect::Body { .. })));
    shell.answer(&mut world, upload, Event::BodyOpen);
    assert_eq!(
        shell.take_effects(),
        vec![Effect::Body {
            id: upload,
            out: BodyOut::Abort(BodyAbort::Cancelled)
        }]
    );

    // Not main's asks: no bound of their own, nothing expires.
    let mut world = TestWorld::new(CLOCK);
    let call = parse(
        ShellMethod::Publish,
        r#"{"kind":"data","parts":[{"bytes":1,"base64":"eA=="}],"history":{"type":"data","name":"Text"},"pin":true,"deferred":false}"#,
    );
    let mut shell = Shell::start(call, &mut world);
    let effects = shell.take_effects();
    let [Effect::Ask(insert)] = &effects[..] else {
        panic!()
    };
    shell.expire(&mut world, insert.id);
    assert!(shell.take_effects().is_empty());
    assert_eq!(shell.outcome(), None);
    // A memory wait past 60 s: `busy`, the row ended `busy` once its insert
    // answers.
    shell.busy();
    assert_eq!(shell.outcome(), Some(&ShellOutcome::Busy));
    shell.answer(&mut world, insert.id, Event::Inserted(Ok(8)));
    let effects = shell.take_effects();
    let [
        Effect::Ask(Ask {
            need: Need::Write(StoreWrite::History(s)),
            ..
        }),
    ] = &effects[..]
    else {
        panic!("{effects:?}")
    };
    assert_eq!(s[0].sql, history::TRIM_SQL);
    assert!(s[1].params.contains(&Bind::Text("busy".to_owned())));
}

// ---------------------------------------------------------------------------
// A picked file's read error (main's part abort with its reason).

#[test]
fn error_codes_are_errno_names() {
    for good in ["EIO", "ENOENT", "EACCES", "E", "E_2BIG", &"E".repeat(32)] {
        assert_eq!(
            ErrorCode::new(good).map(|c| c.as_str().to_owned()),
            Some(good.to_owned())
        );
    }
    for bad in ["", "eio", "2BIG", "_E", "E-IO", "EÏO", &"E".repeat(33)] {
        assert_eq!(ErrorCode::new(bad), None, "{bad}");
    }
}

/// publishFile's and publishDirectory's catches: `describePickedPathError`
/// gives `Could not read "<the file's name>" (<code>)` for an error with a
/// code, as the answer and as the row's text; a part main ends without a
/// reason, a data part, and D13's expiry keep `Internal error`.
#[test]
fn a_picked_files_read_error_names_the_file_and_its_code() {
    let v = Vectors::load();
    let keys = keys_of(&v);
    let unreadable = |code: &str| Abort::Unreadable(ErrorCode::new(code).unwrap());
    let file = r#"{"kind":"file","parts":[{"bytes":200000,"part":0}],"name":"report.txt","pin":true,"deferred":true,"history":{"type":"file","name":"report.txt"}}"#;
    let collection = r#"{"kind":"collection","parts":[{"path":"index.html","bytes":4,"base64":"PGgxPg=="},{"path":"assets/app.js","bytes":200000,"part":1}],"pin":true,"deferred":true,"history":{"type":"directory","name":"site"}}"#;
    let data = r#"{"kind":"data","parts":[{"bytes":200000,"part":0}],"pin":true,"deferred":false}"#;
    for (what, params, part, abort, want) in [
        (
            "a file, EIO",
            file,
            0,
            unreadable("EIO"),
            r#"Could not read "report.txt" (EIO)"#,
        ),
        (
            "a collection's entry, ENOENT",
            collection,
            1,
            unreadable("ENOENT"),
            r#"Could not read "app.js" (ENOENT)"#,
        ),
        (
            "a file, no reason",
            file,
            0,
            Abort::BodyStreamError,
            "Internal error",
        ),
        (
            "data, a reason",
            data,
            0,
            unreadable("EACCES"),
            "Internal error",
        ),
    ] {
        let mut main = Main::new(&keys, honest_node(a1_stamps()));
        main.parts.insert(part, vec![9; 200_000]);
        main.abort_part = Some((part, abort));
        main.db = Some(HistoryDb::open());
        let (outcome, played, shell) = main.play(parse(ShellMethod::Publish, params));
        assert_eq!(outcome, error(want), "{what}");
        let upload = played.calls.last().unwrap();
        assert!(
            matches!(upload.call.form, Form::BzzFile | Form::BzzTar),
            "{what}"
        );
        // The body ends `body_stream_error`, the call goes, nothing stays open.
        assert!(
            played
                .terminals
                .iter()
                .any(|(_, out)| *out == BodyOut::Abort(BodyAbort::BodyStreamError)),
            "{what}: {:?}",
            played.terminals
        );
        assert_eq!(
            shell.open_asks(),
            1,
            "{what}: the call, until main answers it"
        );
        let entries = main.db.as_ref().unwrap().entries();
        if params.contains("history") {
            assert_eq!(
                entry_field(&entries[0], "errorMessage"),
                fc_json::JsValue::string(want),
                "{what}"
            );
        }
    }

    // D13's bound on the part: its fixed text, not a read error's.
    let mut world = TestWorld::new(CLOCK);
    let call = parse(
        ShellMethod::Publish,
        &format!(
            r#"{{"kind":"file","parts":[{{"bytes":10,"part":0}}],"name":"report.txt","batch":"{}","pin":true,"deferred":true}}"#,
            "a1".repeat(32)
        ),
    );
    let mut shell = Shell::start(call, &mut world);
    let next = |shell: &mut Shell| match &shell.take_effects()[..] {
        [Effect::Ask(ask)] => ask.clone(),
        other => panic!("{other:?}"),
    };
    let turn = next(&mut shell);
    shell.answer(&mut world, turn.id, Event::Turn);
    let upload = next(&mut shell);
    shell.answer(&mut world, upload.id, Event::BodyOpen);
    let part = shell
        .take_effects()
        .into_iter()
        .find_map(|e| match e {
            Effect::Ask(Ask {
                id,
                need: Need::Part(0),
                ..
            }) => Some(id),
            _ => None,
        })
        .unwrap();
    shell.answer(&mut world, part, Event::PartHead(10));
    shell.expire(&mut world, part);
    assert_eq!(shell.outcome(), Some(&error("Internal error")));
}

/// A read error is a part's reason only: on a node reply it is main
/// breaking the protocol.
#[test]
fn a_read_error_on_a_node_reply_is_a_protocol_error() {
    let mut world = TestWorld::new(CLOCK);
    let key = JsString::from("https://site.example");
    let call = fc_swarm_provider::machine::Call {
        method: Value::str("swarm_readFeedEntry"),
        params: Value::object([
            ("topic", Value::str(&"ab".repeat(32))),
            ("owner", Value::str(&"cd".repeat(20))),
        ]),
        key,
        approval: None,
    };
    let mut request = fc_swarm_provider::machine::Request::start(&call, &mut world).unwrap();
    let ask = |request: &mut fc_swarm_provider::machine::Request| match &request.take_effects()[..]
    {
        [Effect::Ask(ask)] => ask.id,
        other => panic!("{other:?}"),
    };
    let ready = ask(&mut request);
    request.answer(&mut world, ready, Event::Ready(Ok(())));
    let read = ask(&mut request);
    request.answer(
        &mut world,
        read,
        Event::Head(fc_swarm_provider::machine::Head {
            status: 200,
            status_text: "OK".to_owned(),
            headers: vec![
                ("swarm-feed-index".to_owned(), "0000000000000000".to_owned()),
                (
                    "swarm-feed-index-next".to_owned(),
                    "0000000000000001".to_owned(),
                ),
            ],
        }),
    );
    request.answer(
        &mut world,
        read,
        Event::Abort(Abort::Unreadable(ErrorCode::new("EIO").unwrap())),
    );
    assert_eq!(
        request.outcome(),
        Some(&fc_swarm_provider::machine::Outcome::Protocol(
            Protocol::WrongKind
        ))
    );
}
