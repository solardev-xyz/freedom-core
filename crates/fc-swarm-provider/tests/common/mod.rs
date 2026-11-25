//! The case-playing harness the method tests share (design 0015, SWM-3):
//! `vectors/swarm.json` read with fc-json's index, its typed values, the
//! answers checked against a step's (or a case's `core`), the world the
//! machines read, the fake node over a case's declarative `node` (the
//! generator's own semantics, `vectors/generator/swarm-node.js`), the fake
//! main that answers the core's asks from it under main's rules, and the
//! grammar's checks of the core's node calls (`vectors/swarm-grammar.json`).
//!
//! Each test file that plays `methods` cases (`methods_vectors.rs` for
//! Access and the Reads; the later pieces' for theirs) brings its own
//! cases, its rows' value checks and its deviations' answers.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::path::PathBuf;

use base64::Engine;
use fc_json::index::{Index, KeyOrder, Kind, Value as V};
use fc_json::{JsString, number_to_string};
use fc_swarm::verify;
use fc_swarm_provider::budgets::ReadBudgets;
use fc_swarm_provider::machine::node::WINDOW;
use fc_swarm_provider::machine::{
    Abort, AskId, Call, Effect, Event, Failed, Failure, Form, Head, Need, NodeCall, Outcome, Reads,
    ReadyCheck, Reply, Request, TagOwners, World, whole_charge,
};
use fc_swarm_provider::stores::feeds::FeedStore;
use fc_swarm_provider::stores::manifests::Capability;
use fc_swarm_provider::value::{Bytes, BytesKind, Source, Value};
use sha2::{Digest, Sha256};

/// What the core answers where a case marks a deviation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    /// The step's recorded answer.
    Reference,
    /// The case's `core` object.
    Exact,
    /// -32603 with the error class's text.
    Transport,
    Cancelled,
}

// ---------------------------------------------------------------------------
// Reading the vectors.

pub fn text_of(file: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(file);
    std::fs::read_to_string(path).unwrap()
}

pub fn get<'i, 't>(v: V<'i, 't>, key: &str) -> V<'i, 't> {
    v.get(key)
        .unwrap_or_else(|| panic!("no {key:?} in {}", &v.raw()[..v.raw().len().min(200)]))
}

pub fn string(v: V<'_, '_>) -> String {
    assert_eq!(v.kind(), Kind::String, "{}", v.raw());
    char::decode_utf16(v.units())
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

pub fn js(v: V<'_, '_>) -> JsString {
    assert_eq!(v.kind(), Kind::String, "{}", v.raw());
    JsString::from_units(&v.units().collect::<Vec<_>>())
}

pub fn number(v: V<'_, '_>) -> f64 {
    v.number()
}

pub fn content(seed: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut i = 0u64;
    while out.len() < n {
        let mut h = Sha256::new();
        h.update(seed.as_bytes());
        h.update(i.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        i += 1;
    }
    out.truncate(n);
    out
}

pub fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Vec<u8> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub fn b64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .unwrap()
}

/// A data spec: `{ utf8 }`, `{ hex }`, `{ base64 }` or `{ seed, length }`.
pub fn data_of(spec: V<'_, '_>) -> Vec<u8> {
    if let Some(t) = spec.get("utf8") {
        return string(t).into_bytes();
    }
    if let Some(t) = spec.get("hex") {
        return unhex(&string(t));
    }
    if let Some(t) = spec.get("base64") {
        return b64(&string(t));
    }
    content(
        &string(get(spec, "seed")),
        number(get(spec, "length")) as usize,
    )
}

/// A typed value (`formats.typed`) as the core reads it, its vector-only
/// forms (`string_json`, `string_repeat`) expanded.
pub fn typed(v: V<'_, '_>) -> Value {
    let (tag, content) = v.members().next().unwrap();
    match string(tag).as_str() {
        "string" => Value::String(js(content)),
        "string_json" => Value::String(
            fc_json::parse(&string(content))
                .unwrap()
                .as_js_string()
                .unwrap()
                .clone(),
        ),
        "string_repeat" => {
            let unit = string(content);
            Value::String(JsString::from(
                unit.repeat(number(get(v, "count")) as usize),
            ))
        }
        "number" => {
            let t = string(content);
            Value::Number(match t.as_str() {
                "NaN" => f64::NAN,
                "Infinity" => f64::INFINITY,
                "-Infinity" => f64::NEG_INFINITY,
                other => other.parse().unwrap(),
            })
        }
        "bigint" => Value::BigInt(string(content)),
        "boolean" => Value::Bool(content.kind() == Kind::True),
        "null" => Value::Null,
        "undefined" => Value::Undefined,
        "array" => Value::Array(
            content
                .children()
                .map(|item| (item.get("hole").is_none()).then(|| typed(item)))
                .collect(),
        ),
        "object" => Value::Object(
            content
                .children()
                .map(|pair| {
                    let mut it = pair.children();
                    let (k, val) = (it.next().unwrap(), it.next().unwrap());
                    (js(k), typed(val))
                })
                .collect(),
        ),
        "bytes" | "bytes_elsewhere" | "string_bytes" => {
            let kind = match v.get("kind").map(string).as_deref() {
                Some("Buffer") => BytesKind::Buffer,
                Some("Uint8Array") => BytesKind::Uint8Array,
                Some("ArrayBuffer") => BytesKind::ArrayBuffer,
                Some("BufferJSON") => BytesKind::BufferJson,
                _ => BytesKind::String,
            };
            let source = match v.get("base64") {
                Some(t) => Source::Inline(b64(&string(t))),
                None => Source::Part(number(get(v, "part")) as u32),
            };
            Value::Bytes(Bytes {
                len: number(content) as u64,
                kind,
                source,
                data: string(tag) != "bytes_elsewhere",
            })
        }
        other => panic!("typed form {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Answers against the vectors.

/// An outcome as the page reads it.
pub fn outcome_value(outcome: &Outcome) -> (bool, Value) {
    match outcome {
        Outcome::Result(v) => (true, v.clone()),
        Outcome::Error(f) => (false, failure_value(f)),
        other => panic!("not a page's answer: {other:?}"),
    }
}

pub fn failure_value(f: &Failure) -> Value {
    let mut members = vec![
        (JsString::from("code"), Value::Number(f64::from(f.code))),
        (JsString::from("message"), Value::String(f.message.clone())),
    ];
    if let Some(data) = &f.data {
        members.push((JsString::from("data"), data.clone()));
    }
    Value::Object(members)
}

/// Whether JSON keeps the value exactly, as the generator's `jsonExact`.
pub fn json_exact(v: &Value) -> bool {
    match v {
        Value::Null | Value::Bool(_) => true,
        Value::String(s) => s.is_well_formed(),
        Value::Number(n) => n.is_finite() && !(*n == 0.0 && n.is_sign_negative()),
        Value::Array(items) => items.iter().all(|i| i.as_ref().is_some_and(json_exact)),
        Value::Object(members) => members.iter().all(|(_, m)| json_exact(m)),
        _ => false,
    }
}

pub fn has_long_string(v: &Value) -> bool {
    match v {
        Value::String(s) => s.utf16_len() > 8192,
        Value::Array(items) => items.iter().flatten().any(has_long_string),
        Value::Object(members) => members.iter().any(|(_, m)| has_long_string(m)),
        _ => false,
    }
}

/// `got` against a typed tree.
pub fn check_typed(id: &str, want: V<'_, '_>, got: &Value) {
    let (tag, content) = want.members().next().unwrap();
    match (string(tag).as_str(), got) {
        ("string_digest", Value::String(s)) => {
            assert_eq!(s.utf16_len() as f64, number(content), "{id}");
            assert_eq!(sha(s.as_bytes()), string(get(want, "sha256")), "{id}");
        }
        ("string", Value::String(s)) => {
            assert_eq!(
                s.units().collect::<Vec<_>>(),
                content.units().collect::<Vec<_>>(),
                "{id}"
            )
        }
        ("number", Value::Number(n)) => {
            let text = if *n == 0.0 && n.is_sign_negative() {
                "-0".to_owned()
            } else {
                number_to_string(*n)
            };
            assert_eq!(text, string(content), "{id}");
        }
        ("bigint", Value::BigInt(t)) => assert_eq!(*t, string(content), "{id}"),
        ("boolean", Value::Bool(b)) => assert_eq!(*b, content.kind() == Kind::True, "{id}"),
        ("null", Value::Null) | ("undefined", Value::Undefined) => {}
        ("array", Value::Array(items)) => {
            let wants: Vec<_> = content.children().collect();
            assert_eq!(wants.len(), items.len(), "{id}");
            for (w, g) in wants.into_iter().zip(items) {
                check_typed(id, w, g.as_ref().unwrap());
            }
        }
        ("object", Value::Object(members)) => {
            let wants: Vec<_> = content.children().collect();
            assert_eq!(wants.len(), members.len(), "{id}: members of {got:?}");
            for (pair, (k, g)) in wants.into_iter().zip(members) {
                let mut it = pair.children();
                let (wk, wv) = (it.next().unwrap(), it.next().unwrap());
                assert_eq!(js(wk), *k, "{id}");
                check_typed(id, wv, g);
            }
        }
        (tag, got) => panic!("{id}: typed {tag} against {got:?}"),
    }
}

/// The core's answer against the step's recorded one (or the case's
/// `core`, which has the same members).
pub fn check_answer(id: &str, want: V<'_, '_>, outcome: &Outcome) {
    let (ok, got) = outcome_value(outcome);
    let key = if ok { "result" } else { "error" };
    if let Some(w) = want.get(key) {
        assert!(
            json_exact(&got) && !has_long_string(&got),
            "{id}: JSON keeps the vector's {key}, not {got:?}"
        );
        assert_eq!(
            got.stringify().unwrap(),
            w.stringify(KeyOrder::Property),
            "{id}: {key}"
        );
    } else if let Some(w) = want.get(&format!("{key}_typed")) {
        check_typed(id, w, &got);
    } else if let Some(w) = want.get(&format!("{key}_digest")) {
        let text = got.stringify().unwrap();
        assert_eq!(
            text.encode_utf16().count() as f64,
            number(get(w, "json_length")),
            "{id}"
        );
        assert_eq!(sha(text.as_bytes()), string(get(w, "sha256")), "{id}");
    } else {
        panic!(
            "{id}: the core answered {key} {got:?}, the vector {}",
            &want.raw()[..want.raw().len().min(300)]
        );
    }
}

// ---------------------------------------------------------------------------
// The world.

pub struct TestWorld {
    pub now: u64,
    pub grants: BTreeSet<JsString>,
    pub feeds: FeedStore,
    pub budgets: ReadBudgets,
    /// The sites' standing rules on: (key, the capability's key).
    pub rules: BTreeSet<(JsString, &'static str)>,
    /// Agent custody of the page's tab (the case's `custody`).
    pub custody: bool,
    /// The document still holds its key (a `name: moved` change clears it).
    pub key_holds: bool,
    pub tags: TagOwners,
}

impl TestWorld {
    /// A world at `now` with no grants, no feeds and fresh budgets. Build
    /// one as `TestWorld { now, grants, ..TestWorld::new(now) }`, so a field
    /// a later piece adds keeps its default.
    pub fn new(now: u64) -> TestWorld {
        TestWorld {
            now,
            grants: BTreeSet::new(),
            feeds: FeedStore::empty(),
            budgets: ReadBudgets::new(),
            rules: BTreeSet::new(),
            custody: false,
            key_holds: true,
            tags: TagOwners::new(),
        }
    }

    /// The case's world: its clock, its grants' keys and its feed store's
    /// text (`feeds`, a string or null).
    pub fn of(case: V<'_, '_>) -> TestWorld {
        let feeds = case
            .get("feeds")
            .filter(|f| f.kind() == Kind::String)
            .map(string);
        let mut rules = BTreeSet::new();
        for (key, grant) in get(case, "grants").members() {
            for (capability, on) in grant
                .get("autoApprove")
                .map(|a| a.members())
                .into_iter()
                .flatten()
            {
                if on.kind() == Kind::True {
                    let capability = Capability::from_key(&string(capability)).unwrap();
                    rules.insert((js(key), capability.key()));
                }
            }
        }
        TestWorld {
            rules,
            custody: case.get("custody").is_some_and(|c| c.kind() == Kind::True),
            grants: get(case, "grants").members().map(|(k, _)| js(k)).collect(),
            feeds: match &feeds {
                Some(text) => FeedStore::load(Some(text.as_bytes()), 0, |_| false).store,
                None => FeedStore::empty(),
            },
            ..TestWorld::new(number(get(case, "clock")) as u64)
        }
    }
}

impl Reads for TestWorld {
    fn connected(&self, key: &JsString) -> bool {
        self.grants.contains(key)
    }
    fn messaging(&self, _key: &JsString) -> bool {
        false
    }
    fn auto_approve(&self, key: &JsString, capability: Capability) -> bool {
        self.rules.contains(&(key.clone(), capability.key()))
    }
    fn feeds(&self) -> &FeedStore {
        &self.feeds
    }
}

impl World for TestWorld {
    fn now(&self) -> u64 {
        self.now
    }
    fn budgets(&mut self) -> &mut ReadBudgets {
        &mut self.budgets
    }
    fn key_holds(&self, _key: &JsString) -> bool {
        self.key_holds
    }
    fn agent(&self, _key: &JsString) -> bool {
        self.custody
    }
    fn tags(&mut self) -> &mut TagOwners {
        &mut self.tags
    }
}

impl TestWorld {
    /// A change to the case's world (`at_execute`, or a node rule's `world`
    /// as its request arrives), as swarm-run.js's `world.change` makes it
    /// for the case's key.
    pub fn change(&mut self, key: &JsString, change: V<'_, '_>) {
        for (what, value) in change.members() {
            self.apply(key, &string(what), &text_value(value));
        }
    }

    /// One change: (what, its value's text).
    pub fn apply(&mut self, key: &JsString, what: &str, value: &str) {
        match what {
            "custody" => self.custody = value == "true",
            "name" => self.key_holds = value != "moved",
            "rule_off" => {
                let capability = Capability::from_key(value).unwrap();
                self.rules.remove(&(key.clone(), capability.key()));
            }
            "connection" => {
                assert_eq!(value, "revoked");
                self.grants.remove(key);
            }
            other => panic!("a world change this harness doesn't make: {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// The fake node: vectors/generator/swarm-node.js's `own()` and the rules,
// over swarm-run.js's `nodeWorld`.

#[derive(Debug, Clone)]
pub struct ReplySpec {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Chunked: the pieces as the node writes them, and no length.
    pub pieces: Option<Vec<Vec<u8>>>,
    pub cut_after_pieces: bool,
    /// A declared length past the body, then the connection cut.
    pub declare: Option<usize>,
    pub hang_up: bool,
    pub abort_page: bool,
}

pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        206 => "Partial Content",
        400 => "Bad Request",
        402 => "Payment Required",
        404 => "Not Found",
        500 => "Internal Server Error",
        307 => "Temporary Redirect",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        other => panic!("no reason phrase for {other}"),
    }
}

impl ReplySpec {
    pub fn ok(body: Vec<u8>, content_type: &str) -> ReplySpec {
        ReplySpec {
            status: 200,
            status_text: "OK".to_owned(),
            headers: vec![("content-type".to_owned(), content_type.to_owned())],
            body,
            pieces: None,
            cut_after_pieces: false,
            declare: None,
            hang_up: false,
            abort_page: false,
        }
    }

    pub fn not_found() -> ReplySpec {
        ReplySpec {
            status: 404,
            status_text: "Not Found".to_owned(),
            headers: vec![(
                "content-type".to_owned(),
                "application/json; charset=utf-8".to_owned(),
            )],
            body: br#"{"code":404,"message":"Not Found"}"#.to_vec(),
            ..ReplySpec::ok(Vec::new(), "")
        }
    }

    pub fn of(reply: V<'_, '_>) -> ReplySpec {
        for (k, _) in reply.members() {
            let key = string(k);
            assert!(
                matches!(
                    key.as_str(),
                    "status"
                        | "statusText"
                        | "headers"
                        | "json"
                        | "body_utf8"
                        | "body_hex"
                        | "body_base64"
                        | "body_data"
                        | "chunked"
                        | "pieces_data"
                        | "cutAfterPieces"
                        | "declare"
                        | "hangUp"
                        | "delayMs"
                        | "abortPage"
                ),
                "a reply's {key:?}"
            );
        }
        let status = reply.get("status").map_or(200, |s| number(s) as u16);
        let mut headers: Vec<(String, String)> = reply
            .get("headers")
            .map(|h| h.members().map(|(k, v)| (string(k), string(v))).collect())
            .unwrap_or_default();
        let body = if let Some(j) = reply.get("json") {
            if !headers.iter().any(|(k, _)| k == "content-type") {
                headers.push((
                    "content-type".to_owned(),
                    "application/json; charset=utf-8".to_owned(),
                ));
            }
            j.stringify(KeyOrder::Property).into_bytes()
        } else if let Some(t) = reply.get("body_utf8") {
            string(t).into_bytes()
        } else if let Some(t) = reply.get("body_hex") {
            unhex(&string(t))
        } else if let Some(t) = reply.get("body_base64") {
            b64(&string(t))
        } else if let Some(d) = reply.get("body_data") {
            data_of(d)
        } else {
            Vec::new()
        };
        let chunked = reply.get("chunked").is_some_and(|c| c.kind() == Kind::True);
        let pieces = chunked.then(|| {
            reply
                .get("pieces_data")
                .map(|p| p.children().map(data_of).collect())
                .unwrap_or_else(|| vec![body.clone()])
        });
        ReplySpec {
            status,
            status_text: reply
                .get("statusText")
                .map_or_else(|| reason_phrase(status).to_owned(), string),
            headers,
            body,
            pieces,
            cut_after_pieces: reply
                .get("cutAfterPieces")
                .is_some_and(|c| c.kind() == Kind::True),
            declare: reply.get("declare").map(|d| number(d) as usize),
            hang_up: reply.get("hangUp").is_some_and(|c| c.kind() == Kind::True),
            abort_page: reply
                .get("abortPage")
                .is_some_and(|c| c.kind() == Kind::True),
        }
    }
}

pub struct Rule {
    pub method: Option<String>,
    pub path: Option<String>,
    pub prefix: Option<String>,
    pub reply: ReplySpec,
    /// The change to the case's world as this rule's request arrives:
    /// (what, value), a value as its text (`true`, `moved`, `publish`).
    pub world: Vec<(String, String)>,
}

pub struct Node {
    pub rules: Vec<Rule>,
    pub chunks: BTreeMap<String, Vec<u8>>,
    pub blobs: BTreeMap<String, Vec<u8>>,
    /// `(owner, topic)` → GET /feeds' reply.
    pub feeds: BTreeMap<(String, String), ReplySpec>,
    pub stopped: bool,
    /// GET /stamps' JSON (`{ stamps: [] }` when the case gives none).
    pub stamps: Option<Vec<u8>>,
    /// GET /tags/<uid>'s JSON, by uid.
    pub tags: BTreeMap<String, Vec<u8>>,
    /// The next `swarm-tag` of a `/bzz` or `/bytes` upload.
    pub bzz_tag: std::cell::Cell<u64>,
    /// Chunks uploaded with `POST /chunks`, by address.
    pub uploaded: std::cell::RefCell<BTreeMap<String, Vec<u8>>>,
}

pub struct Keys {
    pub bee: k256::ecdsa::SigningKey,
    pub publishers: BTreeMap<u64, k256::ecdsa::SigningKey>,
}

impl Keys {
    pub fn of(&self, name: &str) -> &k256::ecdsa::SigningKey {
        if name == "bee" {
            return &self.bee;
        }
        let index: u64 = name.strip_prefix("publisher:").unwrap().parse().unwrap();
        &self.publishers[&index]
    }
}

pub fn keys(index: &Index<'_>) -> Keys {
    let vector = get(index.root(), "vectors")
        .children()
        .find(|v| get(*v, "id").is_str("abandon-12"))
        .unwrap();
    let key = |v: V<'_, '_>| {
        k256::ecdsa::SigningKey::from_slice(&unhex(&string(get(v, "privateKey")))).unwrap()
    };
    Keys {
        bee: key(get(vector, "beeWallet")),
        publishers: get(vector, "publisherKeys")
            .children()
            .map(|k| (number(get(k, "originIndex")) as u64, key(k)))
            .collect(),
    }
}

/// The data's chunk tree as ChunkSplitter builds it, each chunk as the node
/// stores it.
pub fn tree_of(data: &[u8], chunks: &mut BTreeMap<String, Vec<u8>>) -> fc_swarm::chunker::Root {
    let mut chunker = fc_swarm::chunker::Chunker::new();
    let mut sink = |sealed: fc_swarm::chunker::Sealed<'_>| {
        let mut wire = sealed.span.to_le_bytes().to_vec();
        wire.extend_from_slice(sealed.payload);
        chunks.insert(hex(&sealed.address), wire);
    };
    chunker.write(data, &mut sink).unwrap();
    let root = chunker.finish(&mut sink);
    chunks.insert(hex(&root.address()), root.wire());
    root
}

impl Node {
    /// A node that stores nothing. Build one as `Node { chunks,
    /// ..Node::new() }`, so a field a later piece adds keeps its default.
    pub fn new() -> Node {
        Node {
            rules: Vec::new(),
            chunks: BTreeMap::new(),
            blobs: BTreeMap::new(),
            feeds: BTreeMap::new(),
            stopped: false,
            stamps: None,
            tags: BTreeMap::new(),
            bzz_tag: std::cell::Cell::new(101),
            uploaded: std::cell::RefCell::new(BTreeMap::new()),
        }
    }

    pub fn of(case: V<'_, '_>, keys: &Keys) -> Node {
        let spec = get(case, "node");
        let mut node = Node {
            stopped: case
                .get("node_stopped")
                .is_some_and(|s| s.kind() == Kind::True),
            ..Node::new()
        };
        for (k, v) in spec.members() {
            match string(k).as_str() {
                "data" => {
                    for d in v.children() {
                        let bytes = data_of(d);
                        let root = tree_of(&bytes, &mut node.chunks);
                        node.blobs.insert(hex(&root.address()), bytes);
                    }
                }
                "chunks" => {
                    for c in v.children() {
                        node.chunks.insert(string(get(c, "address")), data_of(c));
                    }
                }
                "blobs" => assert_eq!(v.children().count(), 0, "blobs"),
                "entries" => {
                    for e in v.children() {
                        let key = keys.of(&string(get(e, "key")));
                        let topic = fc_swarm::feed::topic(&string(get(e, "topic")));
                        let id = verify::feed_update_id(&topic, number(get(e, "index")) as u64);
                        let bytes = data_of(get(e, "data"));
                        let (span, payload) =
                            if e.get("wrap").is_some_and(|w| w.kind() == Kind::True) {
                                let root = tree_of(&bytes, &mut node.chunks);
                                node.blobs.insert(hex(&root.address()), bytes);
                                (root.span(), root.payload().to_vec())
                            } else {
                                (bytes.len() as u64, bytes)
                            };
                        let signed = fc_swarm::sign_soc(key, &id, Some(span), &payload).unwrap();
                        let wire = fc_swarm::soc::body(&id, &signed, &payload).unwrap();
                        node.chunks.insert(hex(&signed.soc_address), wire);
                    }
                }
                "latest" => {
                    for l in v.children() {
                        let owner = hex(&fc_evm::address_of(keys.of(&string(get(l, "key")))));
                        let topic = hex(&fc_swarm::feed::topic(&string(get(l, "topic"))));
                        node.feeds
                            .insert((owner, topic), ReplySpec::of(get(l, "reply")));
                    }
                }
                "probes" => {
                    for p in v.children() {
                        assert!(p.get("head").is_none(), "a probe table no read makes");
                    }
                }
                "rules" => {
                    for r in v.children() {
                        assert!(r.get("times").is_none());
                        let m = get(r, "match");
                        node.rules.push(Rule {
                            method: m.get("method").map(string),
                            path: m.get("path").map(string),
                            prefix: m.get("prefix").map(string),
                            reply: ReplySpec::of(get(r, "reply")),
                            world: r
                                .get("world")
                                .map(|w| {
                                    w.members()
                                        .map(|(k, v)| (string(k), text_value(v)))
                                        .collect()
                                })
                                .unwrap_or_default(),
                        });
                    }
                }
                "stamps" => node.stamps = Some(v.stringify(KeyOrder::Property).into_bytes()),
                // The usable batch, its label that many bytes of `l`
                // (swarm-run.js's nodeWorld).
                "stamps_label_bytes" => {
                    let label = "l".repeat(number(v) as usize);
                    node.stamps = Some(
                        format!(
                            r#"{{"stamps":[{{"batchID":"{}","utilization":0,"usable":true,"label":"{label}","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000}}]}}"#,
                            "a1".repeat(32)
                        )
                        .into_bytes(),
                    );
                }
                "tags" => {
                    for (uid, tag) in v.members() {
                        node.tags
                            .insert(string(uid), tag.stringify(KeyOrder::Property).into_bytes());
                    }
                }
                other => panic!("node spec {other:?}"),
            }
        }
        node
    }

    pub fn rule(&self, method: &str, path: &str) -> Option<&ReplySpec> {
        self.matching(method, path).map(|r| &r.reply)
    }

    /// The first rule a request matches.
    pub fn matching(&self, method: &str, path: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| {
            r.method.as_deref().is_none_or(|m| m == method)
                && r.path.as_deref().is_none_or(|p| p == path)
                && r.prefix.as_deref().is_none_or(|p| path.starts_with(p))
        })
    }

    /// The node's reply to an upload with `body`: the rules first, then
    /// what the generator's node answers (swarm-node.js's `own()`): `/bzz`
    /// with SHA-256 of the body as its reference and the next tag;
    /// `/chunks` with the chunk's address, which it stores.
    pub fn upload(&self, method: &str, path: &str, body: &[u8]) -> ReplySpec {
        if let Some(rule) = self.rule(method, path) {
            return rule.clone();
        }
        let created = |headers: Vec<(String, String)>, reference: String| ReplySpec {
            status: 201,
            status_text: "Created".to_owned(),
            headers: [
                headers,
                vec![(
                    "content-type".to_owned(),
                    "application/json; charset=utf-8".to_owned(),
                )],
            ]
            .concat(),
            body: format!(r#"{{"reference":"{reference}"}}"#).into_bytes(),
            ..ReplySpec::ok(Vec::new(), "")
        };
        match (method, path) {
            ("POST", "/bzz") => {
                let tag = self.bzz_tag.get();
                self.bzz_tag.set(tag + 1);
                created(vec![("swarm-tag".to_owned(), tag.to_string())], sha(body))
            }
            ("POST", "/chunks") => {
                let span: [u8; 8] = body[..8].try_into().unwrap();
                let address = hex(&verify::address_of(&span, &body[8..]).unwrap());
                self.uploaded
                    .borrow_mut()
                    .insert(address.clone(), body.to_vec());
                created(vec![("swarm-tag".to_owned(), "0".to_owned())], address)
            }
            _ => panic!("the fake node has no answer for {method} {path}"),
        }
    }

    /// The node's reply to a request, as the generator's node gives it.
    pub fn reply(&self, method: &str, path: &str) -> ReplySpec {
        if let Some(rule) = self.rule(method, path) {
            return rule.clone();
        }
        if let Some(a) = path.strip_prefix("/chunks/") {
            return self.chunks.get(a).map_or_else(ReplySpec::not_found, |c| {
                ReplySpec::ok(c.clone(), "binary/octet-stream")
            });
        }
        if let Some(a) = path.strip_prefix("/bytes/") {
            return self.blobs.get(a).map_or_else(ReplySpec::not_found, |b| {
                ReplySpec::ok(b.clone(), "application/octet-stream")
            });
        }
        if method == "GET" && path == "/stamps" {
            let body = self
                .stamps
                .clone()
                .unwrap_or_else(|| br#"{"stamps":[]}"#.to_vec());
            return ReplySpec::ok(body, "application/json; charset=utf-8");
        }
        if let Some(uid) = path.strip_prefix("/tags/") {
            return self.tags.get(uid).map_or_else(ReplySpec::not_found, |t| {
                ReplySpec::ok(t.clone(), "application/json; charset=utf-8")
            });
        }
        if let Some(rest) = path.strip_prefix("/feeds/") {
            let (owner, topic) = rest.split_once('/').unwrap();
            return self
                .feeds
                .get(&(owner.to_owned(), topic.to_owned()))
                .cloned()
                .unwrap_or_else(ReplySpec::not_found);
        }
        panic!("the fake node has no answer for {method} {path}")
    }

    /// `shell.swarm_ready { check: "reachable" }`: main's 5 s `GET /node`.
    pub fn reachable(&self) -> Result<(), JsString> {
        if self.stopped {
            return Err(JsString::from("node-stopped"));
        }
        match self.rule("GET", "/node") {
            Some(r) if r.status != 200 || r.hang_up => Err(JsString::from("node-stopped")),
            _ => Ok(()),
        }
    }
}

/// The reply headers the core reads, which main forwards.
pub const READ_HEADERS: [&str; 5] = [
    "content-type",
    "content-length",
    "swarm-tag",
    "swarm-feed-index",
    "swarm-feed-index-next",
];

/// Main's answer to a call: what it sends the core, in order, and whether
/// the page gave up as the request reached the node.
pub fn main_answer(node: &Node, call: &NodeCall) -> (bool, Vec<Event>) {
    let spec = node.reply(call.method(), &call.path);
    if spec.hang_up {
        return (spec.abort_page, vec![Event::Failed(Failed::Error)]);
    }
    let forwarded = |extra: Option<usize>| -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = spec
            .headers
            .iter()
            .filter(|(k, _)| READ_HEADERS.contains(&k.as_str()))
            .cloned()
            .collect();
        if let Some(n) = extra {
            out.push(("content-length".to_owned(), n.to_string()));
        }
        out
    };
    let encoded = spec
        .headers
        .iter()
        .any(|(k, v)| k == "content-encoding" && !v.eq_ignore_ascii_case("identity"));
    if !(200..300).contains(&spec.status) {
        // An error status, whole, with at most 8 KiB of its body.
        let mut body = spec.body.clone();
        body.truncate(8192);
        return (
            spec.abort_page,
            vec![Event::Reply(Reply {
                status: spec.status,
                status_text: spec.status_text.clone(),
                headers: forwarded(None),
                body,
            })],
        );
    }
    if !call.stream() {
        if spec.body.len() > call.max_bytes {
            return (spec.abort_page, vec![Event::Failed(Failed::TooLarge)]);
        }
        return (
            spec.abort_page,
            vec![Event::Reply(Reply {
                status: spec.status,
                status_text: spec.status_text.clone(),
                headers: forwarded(Some(spec.body.len())),
                body: spec.body.clone(),
            })],
        );
    }
    // A stream: the head, frames of at most 64 KiB, held to max_bytes.
    let declared = if spec.pieces.is_some() || encoded {
        None
    } else {
        Some(spec.declare.unwrap_or(spec.body.len()))
    };
    let mut events = vec![Event::Head(Head {
        status: spec.status,
        status_text: spec.status_text.clone(),
        headers: forwarded(declared),
    })];
    if encoded {
        // Main's stack decodes what came despite identity; this doesn't.
        events.push(Event::Abort(Abort::BodyStreamError));
        return (spec.abort_page, events);
    }
    if declared.is_some_and(|d| d > call.max_bytes) {
        // Main reads no body past max_bytes; the head told the core why.
        events.push(Event::Abort(Abort::TooLarge));
        return (spec.abort_page, events);
    }
    let pieces = spec
        .pieces
        .clone()
        .unwrap_or_else(|| vec![spec.body.clone()]);
    let mut sent = 0usize;
    for piece in &pieces {
        for frame in piece.chunks(64 * 1024) {
            let room = call.max_bytes - sent;
            if frame.len() > room {
                if room > 0 {
                    events.push(Event::Data(frame[..room].to_vec()));
                }
                events.push(Event::Abort(Abort::TooLarge));
                return (spec.abort_page, events);
            }
            events.push(Event::Data(frame.to_vec()));
            sent += frame.len();
        }
    }
    if spec.cut_after_pieces || spec.declare.is_some_and(|d| d > sent) {
        events.push(Event::Abort(Abort::BodyStreamError));
    } else {
        events.push(Event::End);
    }
    (spec.abort_page, events)
}

// ---------------------------------------------------------------------------
// Running a step.

/// A call the core made, and the whole body main returned for it.
#[derive(Debug, Clone)]
pub struct Logged {
    pub call: NodeCall,
    pub charge: usize,
    pub body: Option<Vec<u8>>,
}

pub struct Ran {
    pub outcome: Outcome,
    pub ready: Vec<(ReadyCheck, usize)>,
    pub calls: Vec<Logged>,
    pub cancels_after_outcome: usize,
}

pub fn run(world: &mut TestWorld, node: &Node, call: &Call) -> Ran {
    let mut request = Request::start(call, world).expect("a method this part brings");
    let mut queue: VecDeque<Effect> = request.take_effects().into();
    let mut ran = Ran {
        outcome: Outcome::Cancelled,
        ready: Vec::new(),
        calls: Vec::new(),
        cancels_after_outcome: 0,
    };
    let mut cancelled: HashSet<AskId> = HashSet::new();
    while request.outcome().is_none() {
        let effect = queue
            .pop_front()
            .expect("the request waits with nothing asked");
        let Effect::Ask(ask) = effect else {
            if let Effect::Cancel(id) = effect {
                cancelled.insert(id);
            }
            continue;
        };
        match ask.need {
            Need::Ready(check) => {
                assert_eq!(ask.charge, 0);
                ran.ready.push((check, ran.calls.len()));
                let answer = match check {
                    ReadyCheck::Reachable => node.reachable(),
                    other => panic!("main's {other:?} check is the case's readiness"),
                };
                request.answer(world, ask.id, Event::Ready(answer));
                queue.extend(request.take_effects());
            }
            Need::Node(node_call) => {
                let expected = if node_call.stream() {
                    None
                } else {
                    Some(whole_charge(node_call.form))
                };
                if let Some(expected) = expected {
                    assert_eq!(ask.charge, expected, "{}", node_call.path);
                }
                let (abort_page, events) = main_answer(node, &node_call);
                let body = events.iter().find_map(|e| match e {
                    Event::Reply(r) if r.ok() => Some(r.body.clone()),
                    _ => None,
                });
                ran.calls.push(Logged {
                    call: node_call,
                    charge: ask.charge,
                    body,
                });
                if abort_page {
                    // The page gives up as the request reaches the node.
                    request.cancel();
                }
                let mut window = WINDOW as usize;
                let mut received = 0usize;
                for event in events {
                    if request.outcome().is_some() || cancelled.contains(&ask.id) {
                        break;
                    }
                    if let Event::Data(bytes) = &event {
                        received += bytes.len();
                        assert!(
                            received <= window,
                            "main waits for credit the core never gives"
                        );
                    }
                    request.answer(world, ask.id, event);
                    for effect in request.take_effects() {
                        match effect {
                            Effect::Credit { id, bytes } if id == ask.id => window += bytes,
                            Effect::Cancel(id) => {
                                cancelled.insert(id);
                            }
                            other => queue.push_back(other),
                        }
                    }
                }
            }
            Need::Hash(job) => {
                assert_eq!(ask.charge, 0);
                request.answer(world, ask.id, Event::Hashed(job.run()));
                queue.extend(request.take_effects());
            }
            other => panic!("an ask this part's machines don't make: {other:?}"),
        }
    }
    // Taken after the outcome: only cancels of what was open.
    for effect in queue.into_iter().chain(request.take_effects()) {
        match effect {
            Effect::Cancel(_) => ran.cancels_after_outcome += 1,
            Effect::Ask(ask) => {
                // Asked before the outcome, never answered: still a call
                // main received.
                if let Need::Node(call) = ask.need {
                    ran.calls.push(Logged {
                        call,
                        charge: ask.charge,
                        body: None,
                    });
                }
            }
            Effect::Credit { .. } | Effect::Body { .. } => {}
        }
    }
    ran.outcome = request.outcome().unwrap().clone();
    ran
}

/// `shell.swarm_ready { check: "publish" }` from the case's readiness:
/// main answers a pre-flight that throws as `node-stopped`, as
/// `checkSwarmPreFlight` does.
pub fn publish_readiness(case: V<'_, '_>) -> Result<(), JsString> {
    let r = get(case, "readiness");
    if r.kind() == Kind::String {
        assert!(r.is_str("throws"));
        return Err(JsString::from("node-stopped"));
    }
    if get(r, "ok").kind() == Kind::True {
        Ok(())
    } else {
        Err(js(get(r, "reason")))
    }
}

/// Runs a step whose ready check is main's publish readiness.
pub fn run_with_readiness(world: &mut TestWorld, node: &Node, call: &Call, case: V<'_, '_>) -> Ran {
    let mut request = Request::start(call, world).expect("a method this part brings");
    let mut ran = Ran {
        outcome: Outcome::Cancelled,
        ready: Vec::new(),
        calls: Vec::new(),
        cancels_after_outcome: 0,
    };
    let effects = request.take_effects();
    for effect in effects {
        match effect {
            Effect::Ask(ask) => match ask.need {
                Need::Ready(ReadyCheck::Publish) => {
                    ran.ready.push((ReadyCheck::Publish, 0));
                    request.answer(world, ask.id, Event::Ready(publish_readiness(case)));
                }
                other => panic!("getCapabilities asks {other:?}"),
            },
            other => panic!("getCapabilities: {other:?}"),
        }
    }
    let _ = node;
    ran.outcome = request.outcome().expect("answered").clone();
    ran
}

pub fn form_name(form: Form) -> &'static str {
    form.as_str()
}

/// The core's calls against the grammar's honest scenario for the step:
/// the reference's requests as the core keeps them.
pub fn check_scenario(id: &str, scenario: V<'_, '_>, ran: &Ran, deviation: bool) {
    let main_headers = ["accept", "accept-encoding"];
    let wants: Vec<_> = get(scenario, "calls").children().collect();
    let mut at = 0usize;
    for want in &wants {
        let matches = |logged: &Logged| {
            let call = &logged.call;
            let headers: Vec<(String, String)> = get(*want, "headers")
                .children()
                .filter_map(|h| {
                    let mut it = h.children();
                    let (k, v) = (string(it.next().unwrap()), string(it.next().unwrap()));
                    (!main_headers.contains(&k.as_str())).then_some((k, v))
                })
                .collect();
            get(*want, "form").is_str(call.form.as_str())
                && get(*want, "method").is_str(call.method())
                && get(*want, "path").is_str(&call.path)
                && headers == call.headers
                && want
                    .get("max_bytes")
                    .is_none_or(|m| number(m) as usize == call.max_bytes)
                && match (want.get("feed"), call.feed) {
                    (None, None) => true,
                    (Some(f), Some(feed)) => {
                        get(f, "owner").is_str(&hex(&feed.owner))
                            && number(get(f, "index")) as u64 == feed.index
                    }
                    _ => false,
                }
                && match (want.get("tree"), call.tree) {
                    (None, None) => true,
                    (Some(t), Some(tree)) => {
                        number(get(t, "length")) as u64 == tree.length
                            && number(get(t, "depth")) as u8 == tree.depth
                    }
                    _ => false,
                }
        };
        if deviation {
            // The scenario's calls in order among the core's, which may add
            // a leaf's own chunk after a failed check.
            while at < ran.calls.len() && !matches(&ran.calls[at]) {
                at += 1;
            }
            assert!(at < ran.calls.len(), "{id}: no call for {}", want.raw());
            at += 1;
        } else {
            let logged = ran
                .calls
                .get(at)
                .unwrap_or_else(|| panic!("{id}: no call for {}", want.raw()));
            assert!(
                matches(logged),
                "{id}: {:?} against {}",
                logged.call,
                want.raw()
            );
            at += 1;
        }
    }
    if !deviation {
        assert_eq!(at, ran.calls.len(), "{id}: calls past the scenario's");
    }
}
// ---------------------------------------------------------------------------
// Deviations, hand-offs, answers and rows: what every piece's play loop does.

/// The answer of a deviation every piece shares, or `None` for one the
/// piece answers itself: a `core` object is the core's exact answer; at the
/// page's timer (`deadlines`) the core answers cancelled and asks for
/// nothing more; a transport failure has one text for its class
/// (`transport-error-text`).
pub fn shared_answer(deviation: &str, core: V<'_, '_>) -> Option<Want> {
    if core.kind() == Kind::Object {
        return Some(Want::Exact);
    }
    let text = string(core);
    match deviation {
        "deadlines" if text.starts_with("cancelled at the page's timer") => {
            assert_eq!(
                text,
                "cancelled at the page's timer: the core answers cancelled and nothing more is sent"
            );
            Some(Want::Cancelled)
        }
        "transport-error-text" => {
            assert_eq!(text, "one text for the failure class (error)");
            Some(Want::Transport)
        }
        _ => None,
    }
}

/// What main handed the service for a step: the key, the method and the
/// params, in the typed form.
pub struct Handoff {
    pub key: JsString,
    pub method: Value,
    /// The method, when it is a string.
    pub name: Option<String>,
    pub params: Value,
}

/// Main's grant writes before it hands the step's request over, applied to
/// `world`, then what it handed the service: `None` for a step main
/// answered itself (no `service` event), which the core never sees. A step
/// with `page: false` called the service directly, under `origin`.
pub fn handoff(step: V<'_, '_>, origin: &JsString, world: &mut TestWorld) -> Option<Handoff> {
    let events: Vec<_> = step
        .get("events")
        .map(|e| e.children().collect())
        .unwrap_or_default();
    let page = step.get("page").is_none_or(|p| p.kind() != Kind::False);
    let mut service = None;
    for event in &events {
        if let Some(g) = event.get("grant") {
            let change = get(g, "change");
            if get(change, "op").is_str("connect") {
                let key = change.get("key").map_or_else(|| origin.clone(), js);
                world.grants.insert(key);
            }
        }
        if let Some(s) = event.get("service") {
            service = Some(js(get(s, "key")));
            break;
        }
    }
    let key = match (page, service) {
        (false, _) => origin.clone(),
        (true, Some(key)) => key,
        (true, None) => return None,
    };
    let method = step.get("method").map_or_else(
        || typed(get(step, "method_typed")),
        |m| Value::String(js(m)),
    );
    let name = method.as_js_string().map(|m| m.as_str().to_owned());
    // requestAccess: the dispatcher hands the service `{}`.
    let params = if name.as_deref() == Some("swarm_requestAccess") {
        Value::Object(Vec::new())
    } else {
        typed(get(step, "params"))
    };
    Some(Handoff {
        key,
        method,
        name,
        params,
    })
}

/// The core's answer for a step: the case's `core` on its last step where
/// a deviation changes it, else the step's own.
pub fn check_outcome(
    sid: &str,
    want: Want,
    last: bool,
    case: V<'_, '_>,
    step: V<'_, '_>,
    outcome: &Outcome,
) {
    match (want, last) {
        (Want::Exact, true) => check_answer(sid, get(case, "core"), outcome),
        (Want::Transport, true) => assert_eq!(
            *outcome,
            Outcome::Error(Failure::internal(
                fc_swarm_provider::machine::node::ERROR_TEXT
            )),
            "{sid}"
        ),
        (Want::Cancelled, true) => assert_eq!(*outcome, Outcome::Cancelled, "{sid}"),
        _ => check_answer(sid, step, outcome),
    }
}

/// The grammar's honest scenarios, by id.
pub fn scenarios<'i, 't>(grammar: V<'i, 't>) -> BTreeMap<String, V<'i, 't>> {
    get(grammar, "honest")
        .children()
        .map(|s| (string(get(s, "id")), s))
        .collect()
}

/// The core's calls against a row's ready check (once, first, before any
/// call) and its forms, in order, each group within its counts (design
/// 0015, "The operation grammar"). The values the row binds are each
/// piece's to check.
pub fn check_row_shape(id: &str, grammar: V<'_, '_>, row: &str, ran: &Ran) {
    let rule = get(get(grammar, "rows"), row);
    match get(rule, "ready").kind() {
        Kind::Null => assert!(
            ran.ready.is_empty(),
            "{id}: a ready check {row} doesn't have"
        ),
        _ => {
            if !ran.calls.is_empty() {
                assert_eq!(ran.ready.len(), 1, "{id}: one ready check");
            }
            if let Some((check, at)) = ran.ready.first() {
                assert!(get(rule, "ready").is_str(check.as_str()), "{id}: {check:?}");
                assert_eq!(*at, 0, "{id}: the ready check comes first");
                assert_eq!(ran.ready.len(), 1, "{id}");
            }
        }
    }
    let groups: Vec<(Vec<String>, usize, usize)> = get(rule, "calls")
        .children()
        .map(|g| {
            let forms = get(g, "forms").children().map(string).collect();
            let mut count = get(g, "count").children();
            let min = number(count.next().unwrap()) as usize;
            let max = number(count.next().unwrap()) as usize;
            (forms, min, max)
        })
        .collect();
    let mut at = 0usize;
    for (forms, _min, max) in &groups {
        let mut taken = 0;
        while at < ran.calls.len()
            && forms
                .iter()
                .any(|f| f == form_name(ran.calls[at].call.form))
            && taken < *max
        {
            at += 1;
            taken += 1;
        }
    }
    assert_eq!(
        at,
        ran.calls.len(),
        "{id}: a call outside {row}'s forms or counts"
    );
}

/// A world change's value as its text: a string as it is, `true` or
/// `false`.
fn text_value(v: V<'_, '_>) -> String {
    match v.kind() {
        Kind::True => "true".to_owned(),
        Kind::False => "false".to_owned(),
        _ => string(v),
    }
}
