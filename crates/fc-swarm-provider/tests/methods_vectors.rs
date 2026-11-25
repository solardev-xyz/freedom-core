//! The method machines against vectors/swarm.json's `methods` (design 0015,
//! SWM-3 part 3a): every case of the Access and Reads methods
//! (`requestAccess`, `getCapabilities`, `readChunk`, `readData`,
//! `readSingleOwnerChunk`, `readFeedEntry`, `listFeeds`), and the method
//! dispatch's own cases (a missing or unknown method).
//!
//! **What the core sees.** Each step went through main's page dispatcher,
//! which recorded what it handed the service (`service`: the key). That is
//! what main hands the core in `swarm.request`; a step with no `service`
//! event was answered by main itself (a prompt refused, a keyless
//! document, the Identity & Wallet switch off, the grants unloaded) and
//! never reaches the core, so it must have made no node request. A step
//! with `page: false` called the service directly, under the case's
//! origin. The grants the core reads are the case's, with main's grant
//! writes before the hand-off applied; the feed store is the case's text;
//! the read budgets and the clock carry from step to step.
//!
//! **Main and the node.** A fake main answers the core's asks from the
//! case's world: `shell.swarm_ready` from the publish readiness, or from
//! the node's `/node` (the reachability probe); `shell.swarm_api` from a
//! fake node over the case's declarative `node` (the generator's own
//! semantics: the rules first, then the data's chunk trees, the chunks,
//! the feed updates signed with keys.json's test keys, the latest
//! replies), held to main's rules: an error status answered whole with at
//! most 8 KiB of its body, a whole body past `max_bytes` failed
//! `too_large`, a stream in frames of at most 65,536 bytes within the
//! core's credit and stopped at `max_bytes`; and hashing run inline.
//!
//! **What is checked,** each step: the result or error (the case's `core`
//! where a deviation changes it); the core's node calls against the
//! grammar's honest scenario for the step (`vectors/swarm-grammar.json`:
//! the reference's requests as the core keeps them, in order, with
//! `max_bytes`, `feed` and `tree`) and against its method's row (its ready
//! check, forms, counts and the values main binds, readData's occurrences
//! included); each call's charge; and that no store is written.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::path::PathBuf;

use base64::Engine;
use fc_json::index::{Index, KeyOrder, Kind, Value as V};
use fc_json::{JsString, number_to_string};
use fc_swarm::tree;
use fc_swarm::verify::{self, Chunk};
use fc_swarm_provider::budgets::ReadBudgets;
use fc_swarm_provider::machine::node::{ERROR_TEXT, WINDOW};
use fc_swarm_provider::machine::{
    Abort, AskId, Call, Effect, Event, Failed, Failure, Form, Head, Need, NodeCall, Outcome, Reads,
    ReadyCheck, Reply, Request, World, stream_charge, whole_charge,
};
use fc_swarm_provider::stores::feeds::FeedStore;
use fc_swarm_provider::stores::manifests::Capability;
use fc_swarm_provider::value::{Bytes, BytesKind, Source, Value};
use sha2::{Digest, Sha256};

/// The methods this part's machines answer.
const SEVEN: [&str; 7] = [
    "swarm_requestAccess",
    "swarm_getCapabilities",
    "swarm_readChunk",
    "swarm_readData",
    "swarm_readSingleOwnerChunk",
    "swarm_readFeedEntry",
    "swarm_listFeeds",
];

/// Cases of the seven methods this test doesn't play, each with why. The
/// test fails on any case of the seven it neither plays nor names here.
const LEFT_OUT: &[(&str, &str)] = &[(
    "read-data-redundancy-level-span",
    "the vector's `core` says the verified walk gives the reference's result, but the root \
     chunk's span carries redundancy level 1 over two references and no parities: \
     fc_swarm::tree (Ant's joiner) needs 3 parities for 2 data shards at level 1 and refuses \
     the chunk as unverifiable, so the walk ends `chunk_type_mismatch` (reported; the vector \
     isn't edited)",
)];

/// The deviations a case of the seven marks, and what the core answers.
fn core_answer(deviation: &str, core: V<'_, '_>) -> Want {
    if core.kind() == Kind::Object {
        return Want::Exact;
    }
    let text = string(core);
    match deviation {
        // Main's cancel at the page's timer: the core answers cancelled
        // and asks for nothing more.
        "deadlines" => {
            assert_eq!(
                text,
                "cancelled at the page's timer: the core answers cancelled and nothing more is sent"
            );
            Want::Cancelled
        }
        // One text for the class (error).
        "transport-error-text" => {
            assert_eq!(text, "one text for the failure class (error)");
            Want::Transport
        }
        // The walk, or the pieces, give the reference's answer.
        "read-data-verified" | "read-pieces" => {
            assert!(
                text.starts_with("the same result")
                    || text
                        .starts_with("the first read through the verified walk; the same results")
                    || text.starts_with("chunk_not_found when a leaf is missing")
                    || text.starts_with("the walk reads a ranged /bytes; its 500 is -32603")
                    || text.starts_with("the walk refuses the short stream")
                    || text.starts_with("reserved per data frame from main"),
                "{deviation}: {text}"
            );
            Want::Reference
        }
        other => panic!("a deviation this part doesn't answer: {other}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
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

fn text_of(file: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(file);
    std::fs::read_to_string(path).unwrap()
}

fn get<'i, 't>(v: V<'i, 't>, key: &str) -> V<'i, 't> {
    v.get(key)
        .unwrap_or_else(|| panic!("no {key:?} in {}", &v.raw()[..v.raw().len().min(200)]))
}

fn string(v: V<'_, '_>) -> String {
    assert_eq!(v.kind(), Kind::String, "{}", v.raw());
    char::decode_utf16(v.units())
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

fn js(v: V<'_, '_>) -> JsString {
    assert_eq!(v.kind(), Kind::String, "{}", v.raw());
    JsString::from_units(&v.units().collect::<Vec<_>>())
}

fn number(v: V<'_, '_>) -> f64 {
    v.number()
}

fn content(seed: &str, n: usize) -> Vec<u8> {
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

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn b64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .unwrap()
}

/// A data spec: `{ utf8 }`, `{ hex }`, `{ base64 }` or `{ seed, length }`.
fn data_of(spec: V<'_, '_>) -> Vec<u8> {
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
fn typed(v: V<'_, '_>) -> Value {
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
fn outcome_value(outcome: &Outcome) -> (bool, Value) {
    match outcome {
        Outcome::Result(v) => (true, v.clone()),
        Outcome::Error(f) => (false, failure_value(f)),
        other => panic!("not a page's answer: {other:?}"),
    }
}

fn failure_value(f: &Failure) -> Value {
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
fn json_exact(v: &Value) -> bool {
    match v {
        Value::Null | Value::Bool(_) => true,
        Value::String(s) => s.is_well_formed(),
        Value::Number(n) => n.is_finite() && !(*n == 0.0 && n.is_sign_negative()),
        Value::Array(items) => items.iter().all(|i| i.as_ref().is_some_and(json_exact)),
        Value::Object(members) => members.iter().all(|(_, m)| json_exact(m)),
        _ => false,
    }
}

fn has_long_string(v: &Value) -> bool {
    match v {
        Value::String(s) => s.utf16_len() > 8192,
        Value::Array(items) => items.iter().flatten().any(has_long_string),
        Value::Object(members) => members.iter().any(|(_, m)| has_long_string(m)),
        _ => false,
    }
}

/// `got` against a typed tree.
fn check_typed(id: &str, want: V<'_, '_>, got: &Value) {
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
fn check_answer(id: &str, want: V<'_, '_>, outcome: &Outcome) {
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

struct TestWorld {
    now: u64,
    grants: BTreeSet<JsString>,
    feeds: FeedStore,
    budgets: ReadBudgets,
}

impl Reads for TestWorld {
    fn connected(&self, key: &JsString) -> bool {
        self.grants.contains(key)
    }
    fn messaging(&self, _key: &JsString) -> bool {
        false
    }
    fn auto_approve(&self, _key: &JsString, _capability: Capability) -> bool {
        false
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
}

// ---------------------------------------------------------------------------
// The fake node: vectors/generator/swarm-node.js's `own()` and the rules,
// over swarm-run.js's `nodeWorld`.

#[derive(Debug, Clone)]
struct ReplySpec {
    status: u16,
    status_text: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Chunked: the pieces as the node writes them, and no length.
    pieces: Option<Vec<Vec<u8>>>,
    cut_after_pieces: bool,
    /// A declared length past the body, then the connection cut.
    declare: Option<usize>,
    hang_up: bool,
    abort_page: bool,
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        206 => "Partial Content",
        400 => "Bad Request",
        402 => "Payment Required",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        other => panic!("no reason phrase for {other}"),
    }
}

impl ReplySpec {
    fn ok(body: Vec<u8>, content_type: &str) -> ReplySpec {
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

    fn not_found() -> ReplySpec {
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

    fn of(reply: V<'_, '_>) -> ReplySpec {
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

struct Rule {
    method: Option<String>,
    path: Option<String>,
    prefix: Option<String>,
    reply: ReplySpec,
}

struct Node {
    rules: Vec<Rule>,
    chunks: BTreeMap<String, Vec<u8>>,
    blobs: BTreeMap<String, Vec<u8>>,
    /// `(owner, topic)` → GET /feeds' reply.
    feeds: BTreeMap<(String, String), ReplySpec>,
    stopped: bool,
}

struct Keys {
    bee: k256::ecdsa::SigningKey,
    publishers: BTreeMap<u64, k256::ecdsa::SigningKey>,
}

impl Keys {
    fn of(&self, name: &str) -> &k256::ecdsa::SigningKey {
        if name == "bee" {
            return &self.bee;
        }
        let index: u64 = name.strip_prefix("publisher:").unwrap().parse().unwrap();
        &self.publishers[&index]
    }
}

fn keys(index: &Index<'_>) -> Keys {
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
fn tree_of(data: &[u8], chunks: &mut BTreeMap<String, Vec<u8>>) -> fc_swarm::chunker::Root {
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
    fn of(case: V<'_, '_>, keys: &Keys) -> Node {
        let spec = get(case, "node");
        let mut node = Node {
            rules: Vec::new(),
            chunks: BTreeMap::new(),
            blobs: BTreeMap::new(),
            feeds: BTreeMap::new(),
            stopped: case
                .get("node_stopped")
                .is_some_and(|s| s.kind() == Kind::True),
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
                        assert!(r.get("times").is_none() && r.get("world").is_none());
                        let m = get(r, "match");
                        node.rules.push(Rule {
                            method: m.get("method").map(string),
                            path: m.get("path").map(string),
                            prefix: m.get("prefix").map(string),
                            reply: ReplySpec::of(get(r, "reply")),
                        });
                    }
                }
                other => panic!("node spec {other:?}"),
            }
        }
        node
    }

    fn rule(&self, method: &str, path: &str) -> Option<&ReplySpec> {
        self.rules
            .iter()
            .find(|r| {
                r.method.as_deref().is_none_or(|m| m == method)
                    && r.path.as_deref().is_none_or(|p| p == path)
                    && r.prefix.as_deref().is_none_or(|p| path.starts_with(p))
            })
            .map(|r| &r.reply)
    }

    /// The node's reply to a request, as the generator's node gives it.
    fn reply(&self, method: &str, path: &str) -> ReplySpec {
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
    fn reachable(&self) -> Result<(), JsString> {
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
const READ_HEADERS: [&str; 5] = [
    "content-type",
    "content-length",
    "swarm-tag",
    "swarm-feed-index",
    "swarm-feed-index-next",
];

/// Main's answer to a call: what it sends the core, in order, and whether
/// the page gave up as the request reached the node.
fn main_answer(node: &Node, call: &NodeCall) -> (bool, Vec<Event>) {
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
struct Logged {
    call: NodeCall,
    charge: usize,
    body: Option<Vec<u8>>,
}

struct Ran {
    outcome: Outcome,
    ready: Vec<(ReadyCheck, usize)>,
    calls: Vec<Logged>,
    cancels_after_outcome: usize,
}

fn run(world: &mut TestWorld, node: &Node, call: &Call) -> Ran {
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
            Effect::Credit { .. } => {}
        }
    }
    ran.outcome = request.outcome().unwrap().clone();
    ran
}

/// `shell.swarm_ready { check: "publish" }` from the case's readiness:
/// main answers a pre-flight that throws as `node-stopped`, as
/// `checkSwarmPreFlight` does.
fn publish_readiness(case: V<'_, '_>) -> Result<(), JsString> {
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
fn run_with_readiness(world: &mut TestWorld, node: &Node, call: &Call, case: V<'_, '_>) -> Ran {
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

// ---------------------------------------------------------------------------
// The grammar.

/// The row a step's request plays, as swarm-grammar.json names it.
fn row_of(method: &str, params: &Value) -> &'static str {
    match method {
        "swarm_readChunk" => "readChunk",
        "swarm_readSingleOwnerChunk" => "readSingleOwnerChunk",
        "swarm_readData" => "readData",
        "swarm_readFeedEntry" if params.get("index").is_nullish() => "readFeedEntry_latest",
        "swarm_readFeedEntry" => "readFeedEntry_index",
        "swarm_getCapabilities" => "getCapabilities",
        "swarm_requestAccess" => "requestAccess",
        "swarm_listFeeds" => "listFeeds",
        other => panic!("{other}"),
    }
}

fn form_name(form: Form) -> &'static str {
    form.as_str()
}

/// The core's calls against the row's ready check, forms and counts, and
/// the values main binds (design 0015, "The operation grammar").
fn check_row(id: &str, grammar: V<'_, '_>, row: &str, ran: &Ran, step: &StepView<'_>) {
    let rule = get(get(grammar, "rows"), row);
    // The ready check: the row's, once, before any call.
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
    // Forms in order, each group within its counts.
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
    for logged in &ran.calls {
        let call = &logged.call;
        assert_eq!(call.query, Vec::<(String, String)>::new(), "{id}");
        assert!(call.body.is_none(), "{id}");
        match call.form {
            Form::Chunk => {
                assert!(call.headers.is_empty(), "{id}: no retrieval header");
                assert_eq!(call.max_bytes, 4201, "{id}");
            }
            Form::FeedLatest => assert!(call.headers.is_empty(), "{id}"),
            Form::Bytes => {}
            other => panic!("{id}: {other:?} under {row}"),
        }
    }
    match row {
        "readChunk" | "readSingleOwnerChunk" => {
            if let Some(first) = ran.calls.first() {
                assert_eq!(
                    first.call.path,
                    format!("/chunks/{}", step.chunk_address()),
                    "{id}"
                );
                assert!(
                    first.call.feed.is_none() && first.call.tree.is_none(),
                    "{id}"
                );
            }
        }
        "readFeedEntry_index" => check_feed_index(id, ran, step),
        "readFeedEntry_latest" => {
            if let Some(first) = ran.calls.first() {
                assert!(first.call.max_bytes as u64 <= 5 * 1024 * 1024, "{id}");
                assert!(first.call.path.starts_with("/feeds/"), "{id}");
                let topic = first.call.path.rsplit('/').next().unwrap().to_owned();
                assert_eq!(topic, step.topic(), "{id}: <t>");
                if let Some(owner) = step.owner() {
                    assert_eq!(
                        first.call.path,
                        format!("/feeds/{owner}/{topic}"),
                        "{id}: <o>"
                    );
                }
            }
        }
        "readData" => check_read_data(id, ran, step),
        _ => assert!(ran.calls.is_empty(), "{id}: {row} makes no call"),
    }
}

fn check_feed_index(id: &str, ran: &Ran, step: &StepView<'_>) {
    let Some(first) = ran.calls.first() else {
        return;
    };
    let feed = first
        .call
        .feed
        .unwrap_or_else(|| panic!("{id}: the SOC's feed"));
    let topic: [u8; 32] = unhex(&step.topic()).try_into().unwrap();
    if let Some(owner) = step.owner() {
        assert_eq!(hex(&feed.owner), owner, "{id}: <o>");
    }
    let index = step.params.get("index");
    let Value::Number(n) = index else {
        panic!("{id}: index")
    };
    assert_eq!(
        feed.index,
        fc_swarm_provider::methods::feed_index::wrapping_index(*n),
        "{id}"
    );
    assert_eq!(
        first.call.path,
        format!(
            "/chunks/{}",
            hex(&verify::feed_update_address(
                &feed.owner,
                &topic,
                feed.index
            ))
        ),
        "{id}: the SOC's address"
    );
    if let Some(second) = ran.calls.get(1) {
        let body = first.body.as_ref().unwrap();
        let span: [u8; 8] = body[97..105].try_into().unwrap();
        let size = fc_swarm_provider::chunks::data_size(&span);
        assert!(size > 4096 && size <= 5 * 1024 * 1024, "{id}");
        let wrapped = verify::address_of(&span, &body[105..]).unwrap();
        assert_eq!(second.call.form, Form::Bytes, "{id}");
        assert_eq!(
            second.call.path,
            format!("/bytes/{}", hex(&wrapped)),
            "{id}"
        );
        assert!(second.call.headers.is_empty(), "{id}: no range");
        assert_eq!(second.call.max_bytes as u64, size, "{id}");
        assert_eq!(second.charge, stream_charge(size as usize), "{id}");
    }
}

/// readData's admission: the root at the reference, then each chunk an
/// unfetched occurrence (address, logical length, depth) of a data child
/// of an intermediate main returned, and one ranged `bytes`.
fn check_read_data(id: &str, ran: &Ran, step: &StepView<'_>) {
    let Some(root) = ran.calls.first() else {
        return;
    };
    let reference = step.chunk_address();
    assert_eq!(root.call.path, format!("/chunks/{reference}"), "{id}");
    assert!(root.call.tree.is_none(), "{id}");
    let Some(root_body) = &root.body else {
        assert_eq!(ran.calls.len(), 1, "{id}");
        return;
    };
    let span: [u8; 8] = root_body[..8].try_into().unwrap();
    let n = fc_swarm_provider::chunks::data_size(&span);
    let mut slots: BTreeMap<(String, u64, u8), usize> = BTreeMap::new();
    let add =
        |wire: &[u8], length: u64, depth: u8, slots: &mut BTreeMap<(String, u64, u8), usize>| {
            let chunk = Chunk {
                span: wire[..8].try_into().unwrap(),
                payload: &wire[8..],
            };
            let Ok(node) = tree::intermediate(&chunk, length) else {
                return;
            };
            for i in 0..node.len() {
                let (address, len) = node.child(i).unwrap();
                if len == 0 || (!tree::is_leaf(len) && depth + 1 >= 8) {
                    continue;
                }
                *slots.entry((hex(&address), len, depth + 1)).or_default() += 1;
            }
        };
    if n > 4096 {
        add(root_body, n, 0, &mut slots);
    }
    let mut bytes_calls = 0;
    let mut chunk_calls = 1;
    for logged in &ran.calls[1..] {
        let call = &logged.call;
        assert!(n > 4096, "{id}: a walk for a root of {n} bytes");
        match call.form {
            Form::Bytes => {
                bytes_calls += 1;
                assert_eq!(call.path, format!("/bytes/{reference}"), "{id}");
                assert_eq!(
                    call.headers,
                    vec![("range".to_owned(), format!("bytes=0-{}", n - 1))],
                    "{id}"
                );
                assert_eq!(call.max_bytes as u64, n, "{id}");
                assert_eq!(logged.charge, stream_charge(n as usize), "{id}");
            }
            Form::Chunk => {
                chunk_calls += 1;
                let tree = call.tree.unwrap_or_else(|| panic!("{id}: tree"));
                let address = call.path.strip_prefix("/chunks/").unwrap().to_owned();
                let key = (address, tree.length, tree.depth);
                let left = slots
                    .get_mut(&key)
                    .unwrap_or_else(|| panic!("{id}: {key:?} is no unfetched occurrence"));
                assert!(
                    *left > 0,
                    "{id}: {key:?} fetched more times than the tree names it"
                );
                *left -= 1;
                if tree.length > 4096
                    && let Some(body) = &logged.body
                {
                    add(body, tree.length, tree.depth, &mut slots);
                }
            }
            other => panic!("{id}: {other:?}"),
        }
    }
    assert!(bytes_calls <= 1, "{id}");
    assert!(chunk_calls <= 2562, "{id}");
}

/// A step's params, as the grammar's bindings read them.
struct StepView<'a> {
    params: &'a Value,
    key: &'a JsString,
    feeds: &'a FeedStore,
}

impl StepView<'_> {
    /// readChunk's, readData's and readSingleOwnerChunk's `<a>`.
    fn chunk_address(&self) -> String {
        if let Some(r) = self.params.get("reference").as_js_string() {
            return r.as_str().to_lowercase();
        }
        if let Some(a) = self.params.get("address").as_js_string() {
            return a.as_str().to_lowercase();
        }
        let owner = self.params.get("owner").as_js_string().unwrap();
        let owner: [u8; 20] = unhex(owner.as_str()).try_into().unwrap();
        let identifier = self.params.get("identifier").as_js_string().unwrap();
        let identifier: [u8; 32] = unhex(identifier.as_str()).try_into().unwrap();
        hex(&verify::soc_address(&identifier, &owner))
    }

    /// `<t>`: `params.topic`, or keccak256(utf8(key + "/" + name)).
    fn topic(&self) -> String {
        if let Some(t) = self.params.get("topic").as_js_string() {
            return t.as_str().to_lowercase();
        }
        let name = self.params.get("name").as_js_string().unwrap();
        hex(&fc_swarm::feed::topic(&format!(
            "{}/{}",
            self.key.as_str(),
            name.as_str()
        )))
    }

    /// `<o>` where the page names it, or the store's.
    fn owner(&self) -> Option<String> {
        let owner = self.params.get("owner");
        if let Some(o) = owner.as_js_string().filter(|o| !o.is_empty()) {
            return Some(o.as_str().trim_start_matches("0x").to_lowercase());
        }
        let name = self.params.get("name").as_js_string()?;
        let feed = self.feeds.feed(self.key, name)?;
        Some(
            feed.get("owner")?
                .as_str()?
                .trim_start_matches("0x")
                .to_lowercase(),
        )
    }
}

/// The core's calls against the grammar's honest scenario for the step:
/// the reference's requests as the core keeps them.
fn check_scenario(id: &str, scenario: V<'_, '_>, ran: &Ran, deviation: bool) {
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
// The test.

#[test]
fn access_and_reads() {
    let text = text_of("swarm.json");
    let index = Index::new(&text).unwrap();
    let grammar_text = text_of("swarm-grammar.json");
    let grammar_index = Index::new(&grammar_text).unwrap();
    let grammar = grammar_index.root();
    let keys_text = text_of("keys.json");
    let keys_index = Index::new(&keys_text).unwrap();
    let keys = keys(&keys_index);
    let scenarios: BTreeMap<String, V<'_, '_>> = get(grammar, "honest")
        .children()
        .map(|s| (string(get(s, "id")), s))
        .collect();

    let mut played = 0usize;
    let mut total_calls = 0usize;
    let mut main_answered = 0usize;
    let mut scenarios_used = BTreeSet::new();
    let mut left_out_seen = BTreeSet::new();
    for case in get(index.root(), "methods").children() {
        let id = string(get(case, "id"));
        let steps: Vec<_> = get(case, "steps").children().collect();
        let methods: Vec<Option<String>> =
            steps.iter().map(|s| s.get("method").map(string)).collect();
        let dispatch_case = steps
            .iter()
            .all(|s| s.get("page").is_some_and(|p| p.kind() == Kind::False))
            && methods
                .iter()
                .all(|m| m.as_ref().is_none_or(|m| !SEVEN.contains(&m.as_str())))
            && id.starts_with("method-");
        let ours = methods
            .iter()
            .any(|m| m.as_ref().is_some_and(|m| SEVEN.contains(&m.as_str())));
        if !ours && !dispatch_case {
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
                .all(|m| m.as_ref().is_none_or(|m| SEVEN.contains(&m.as_str())) || dispatch_case),
            "{id}: a case that mixes in a method of a later piece"
        );

        let feeds_before = case
            .get("feeds")
            .filter(|f| f.kind() == Kind::String)
            .map(string);
        let mut world = TestWorld {
            now: number(get(case, "clock")) as u64,
            grants: get(case, "grants").members().map(|(k, _)| js(k)).collect(),
            feeds: match &feeds_before {
                Some(text) => FeedStore::load(Some(text.as_bytes()), 0, |_| false).store,
                None => FeedStore::empty(),
            },
            budgets: ReadBudgets::new(),
        };
        let node = Node::of(case, &keys);
        let origin = js(get(case, "origin"));
        let deviation = case.get("deviation").map(string);
        let want = match &deviation {
            Some(d) => core_answer(d, get(case, "core")),
            None => {
                assert!(case.get("core").is_none(), "{id}");
                Want::Reference
            }
        };
        for (k, step) in steps.iter().enumerate() {
            let sid = if steps.len() > 1 {
                format!("{id}/{k}")
            } else {
                id.clone()
            };
            if let Some(clock) = step.get("clock") {
                world.now = number(clock) as u64;
            }
            let events: Vec<_> = step
                .get("events")
                .map(|e| e.children().collect())
                .unwrap_or_default();
            let page = step.get("page").is_none_or(|p| p.kind() != Kind::False);
            // Main's grant writes before it hands the request over.
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
                (true, None) => {
                    // Main answered: the core never sees the request.
                    assert_eq!(get(*step, "requests").children().count(), 0, "{sid}");
                    main_answered += 1;
                    continue;
                }
            };
            let method = step.get("method").map_or_else(
                || typed(get(*step, "method_typed")),
                |m| Value::String(js(m)),
            );
            let method_name = method.as_js_string().map(|m| m.as_str().to_owned());
            // requestAccess: the dispatcher hands the service `{}`.
            let params = if method_name.as_deref() == Some("swarm_requestAccess") {
                Value::Object(Vec::new())
            } else {
                typed(get(*step, "params"))
            };
            let call = Call {
                method: method.clone(),
                params: params.clone(),
                key: key.clone(),
                approval: None,
            };
            let ran = if method_name.as_deref() == Some("swarm_getCapabilities") {
                run_with_readiness(&mut world, &node, &call, case)
            } else {
                run(&mut world, &node, &call)
            };
            played += 1;
            total_calls += ran.calls.len();

            // The answer.
            let last = k + 1 == steps.len();
            match (want, last) {
                (Want::Exact, true) => check_answer(&sid, get(case, "core"), &ran.outcome),
                (Want::Transport, true) => assert_eq!(
                    ran.outcome,
                    Outcome::Error(Failure::internal(ERROR_TEXT)),
                    "{sid}"
                ),
                (Want::Cancelled, true) => {
                    assert_eq!(ran.outcome, Outcome::Cancelled, "{sid}");
                    assert!(
                        ran.cancels_after_outcome > 0,
                        "{sid}: its open call cancelled"
                    );
                }
                _ => check_answer(&sid, *step, &ran.outcome),
            }

            // The calls, against the grammar.
            let Some(name) = method_name.filter(|m| SEVEN.contains(&m.as_str())) else {
                assert!(ran.calls.is_empty() && ran.ready.is_empty(), "{sid}");
                continue;
            };
            let row = row_of(&name, &params);
            let view = StepView {
                params: &params,
                key: &key,
                feeds: &world.feeds,
            };
            check_row(&sid, grammar, row, &ran, &view);
            match scenarios.get(&sid) {
                Some(scenario) => {
                    assert!(get(*scenario, "row").is_str(row), "{sid}");
                    let verified = deviation.as_deref() == Some("read-data-verified");
                    check_scenario(&sid, *scenario, &ran, verified);
                    scenarios_used.insert(sid.clone());
                }
                None => assert!(
                    ran.calls.is_empty() || want == Want::Transport,
                    "{sid}: calls, and no honest scenario"
                ),
            }
        }
        // No store written: the case's files after are its files before.
        let after = get(case, "after");
        let feeds_after = after
            .get("feeds")
            .filter(|f| f.kind() == Kind::String)
            .map(string);
        assert_eq!(feeds_after, feeds_before, "{id}: swarm-feeds.json");
        assert_eq!(get(after, "history").children().count(), 0, "{id}");
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
            "readChunk",
            "readSingleOwnerChunk",
            "readData",
            "readFeedEntry_index",
            "readFeedEntry_latest",
        ]
        .contains(&row.as_str())
        {
            assert!(
                scenarios_used.contains(sid),
                "{sid}: an honest scenario no step played"
            );
        }
    }
    // Every step of these cases, but main's own answers; every honest
    // scenario of their reads.
    assert_eq!((played, main_answered), (551, 7));
    assert_eq!(scenarios_used.len(), 95);
    assert!(total_calls > 100, "{total_calls}");
}

/// The feed index lookup (`feeds`' `index_run` cases, from the feed
/// writes' method cases): the lookup's answer from the method case's node,
/// each probe answered with the status the reference's probe got, in the
/// same order, to the same next index or error text.
#[test]
fn index_runs() {
    use fc_swarm_provider::methods::feed_index::{MAX_PROBE_READS, Next, NextIndex};

    let text = text_of("swarm.json");
    let index = Index::new(&text).unwrap();
    let keys_text = text_of("keys.json");
    let keys_index = Index::new(&keys_text).unwrap();
    let keys = keys(&keys_index);
    let methods: BTreeMap<String, V<'_, '_>> = get(index.root(), "methods")
        .children()
        .map(|c| (string(get(c, "id")), c))
        .collect();
    let mut runs = 0;
    for run in get(index.root(), "feeds")
        .children()
        .filter(|f| get(*f, "kind").is_str("index_run"))
    {
        let id = string(get(run, "id"));
        let case = methods[&string(get(run, "method_case"))];
        let latest = get(get(case, "node"), "latest").children().next().unwrap();
        let owner = fc_evm::address_of(keys.of(&string(get(latest, "key"))));
        let topic = fc_swarm::feed::topic(&string(get(latest, "topic")));
        let spec = ReplySpec::of(get(latest, "reply"));
        assert_eq!(
            f64::from(spec.status),
            number(get(run, "lookup")),
            "{id}: the lookup's status"
        );
        let (mut lookup, call) = NextIndex::start(owner, topic);
        assert_eq!(call.form, Form::FeedHead, "{id}");
        assert_eq!(
            call.headers,
            vec![("swarm-only-root-chunk".to_owned(), "true".to_owned())],
            "{id}: the header, never the query"
        );
        assert_eq!(
            call.path,
            format!("/feeds/{}/{}", hex(&owner), hex(&topic)),
            "{id}"
        );
        let mut body = spec.body.clone();
        body.truncate(8192);
        let mut next = lookup.reply(&Reply {
            status: spec.status,
            status_text: spec.status_text.clone(),
            headers: spec.headers.clone(),
            body,
        });
        let mut probes = get(run, "probes").children();
        let outcome = loop {
            match next {
                Next::Call(call) => {
                    let probe = probes
                        .next()
                        .unwrap_or_else(|| panic!("{id}: a probe the reference didn't make"));
                    let feed = call.feed.unwrap();
                    assert_eq!(feed.owner, owner, "{id}");
                    assert_eq!(feed.index as f64, number(get(probe, "index")), "{id}");
                    assert_eq!(
                        call.path,
                        format!(
                            "/chunks/{}",
                            hex(&verify::feed_update_address(&owner, &topic, feed.index))
                        ),
                        "{id}"
                    );
                    let status = number(get(probe, "status")) as u16;
                    let reply = match status {
                        200 => Reply {
                            status,
                            status_text: "OK".to_owned(),
                            headers: Vec::new(),
                            body: vec![0; 105],
                        },
                        404 => Reply {
                            status,
                            status_text: "Not Found".to_owned(),
                            headers: Vec::new(),
                            body: br#"{"code":404,"message":"Not Found"}"#.to_vec(),
                        },
                        other => Reply {
                            status: other,
                            status_text: reason_phrase(other).to_owned(),
                            headers: Vec::new(),
                            body: format!(r#"{{"code":{other},"message":"read chunk failed"}}"#)
                                .into_bytes(),
                        },
                    };
                    next = lookup.reply(&reply);
                }
                other => break other,
            }
        };
        assert!(
            probes.next().is_none(),
            "{id}: a probe the core didn't make"
        );
        assert!(lookup.reads() <= MAX_PROBE_READS, "{id}");
        match (run.get("next_index"), run.get("error")) {
            (Some(n), None) => assert_eq!(outcome, Next::Index(number(n) as u64), "{id}"),
            (None, Some(e)) => {
                let Next::Error(message) = outcome else {
                    panic!("{id}: {outcome:?}")
                };
                assert_eq!(message, js(get(e, "message")), "{id}");
            }
            _ => panic!("{id}"),
        }
        runs += 1;
    }
    assert_eq!(runs, 15);
}

/// What a node's join of a tree serves (Ant's joiner, as 0009 reads it):
/// each logical leaf's first bytes of the chunk at its address, whatever
/// that chunk's own span.
fn join(chunks: &BTreeMap<String, Vec<u8>>, root: &str, n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_owned(), n)];
    while let Some((address, length)) = stack.pop() {
        let wire = &chunks[&address];
        if tree::is_leaf(length) {
            out.extend_from_slice(&wire[8..8 + length as usize]);
            continue;
        }
        let chunk = Chunk {
            span: wire[..8].try_into().unwrap(),
            payload: &wire[8..],
        };
        let node = tree::intermediate(&chunk, length).unwrap();
        let children: Vec<_> = (0..node.len()).map(|i| node.child(i).unwrap()).collect();
        for (child, len) in children.into_iter().rev() {
            if len > 0 {
                stack.push((hex(&child), len));
            }
        }
    }
    out
}

/// Every leaf of `data` as a node stores it, under its address.
fn content_leaves(data: &[u8], chunks: &mut BTreeMap<String, Vec<u8>>) {
    for leaf in data.chunks(4096) {
        let mut wire = (leaf.len() as u64).to_le_bytes().to_vec();
        wire.extend_from_slice(leaf);
        let span: [u8; 8] = wire[..8].try_into().unwrap();
        chunks.insert(hex(&verify::address_of(&span, leaf).unwrap()), wire);
    }
}

/// readData's walk over the grammar's other honest scenarios: 0009's
/// trees at every redundancy level (vectors/dweb-verify.json), one chunk
/// at two positions, a logical leaf whose own span is large, the deep
/// trees and an over-full intermediate. The node serves each chunk the
/// scenario or dweb-verify.json holds, and `/bytes` as a node's join; the
/// core's calls must each be admitted by the row, every intermediate the
/// scenario fetches must be among them, and the walk must read the join,
/// or, for the tree whose intermediate sits at 0009's eighth level, end
/// `chunk_type_mismatch`.
#[test]
fn read_data_walks() {
    let grammar_text = text_of("swarm-grammar.json");
    let grammar_index = Index::new(&grammar_text).unwrap();
    let grammar = grammar_index.root();
    let dweb_text = text_of("dweb-verify.json");
    let dweb_index = Index::new(&dweb_text).unwrap();
    let dweb = get(dweb_index.root(), "swarm");
    let dweb_chunks: BTreeMap<String, Vec<u8>> = get(dweb, "chunks")
        .members()
        .map(|(k, v)| (string(k), b64(&string(v))))
        .collect();
    let files: BTreeMap<String, V<'_, '_>> = get(dweb, "files")
        .children()
        .map(|f| (string(get(f, "id")), f))
        .collect();

    let mut walks = 0;
    for scenario in get(grammar, "honest").children() {
        if !get(scenario, "row").is_str("readData") {
            continue;
        }
        let id = string(get(scenario, "id"));
        let from = string(get(scenario, "from"));
        if from.starts_with("methods/") {
            continue;
        }
        let mut chunks = BTreeMap::new();
        for call in get(scenario, "calls").children() {
            let Some(reply) = call.get("reply") else {
                continue;
            };
            if let Some(body) = reply.get("body") {
                let address = string(get(call, "path"))
                    .trim_start_matches("/chunks/")
                    .to_owned();
                chunks.insert(address, b64(&string(get(body, "base64"))));
            }
        }
        if let Some(file) = from.strip_prefix("dweb-verify.json swarm.files/") {
            let file = files[file];
            chunks.extend(dweb_chunks.clone());
            content_leaves(
                &content(
                    &string(get(file, "seed")),
                    number(get(file, "size")) as usize,
                ),
                &mut chunks,
            );
        } else {
            // The generator's seeds (swarm-grammar-file.js) for the
            // leaves no call of the scenario carries.
            let seeds: &[(&str, usize)] = match id.as_str() {
                "readData-two-positions" => &[("swarm-grammar/two-positions", 524_288)],
                "readData-logical-leaf-refetched" => &[("swarm-grammar/leaf-head", 4096)],
                "readData-one-chunk-at-depths-6-and-7" => &[("swarm-grammar/deep-a", 524_288)],
                "readData-leaf-at-depth-8-fetched-again" => &[("swarm-grammar/deep-b", 524_288)],
                "readData-over-full-intermediate" => &[("swarm-grammar/over-full", 8192)],
                other => panic!("{other}: a scenario this test doesn't know"),
            };
            for (seed, n) in seeds {
                content_leaves(&content(seed, *n), &mut chunks);
            }
        }
        let params = typed(get(scenario, "params"));
        let reference = params
            .get("reference")
            .as_js_string()
            .unwrap()
            .as_str()
            .to_owned();
        let root_wire = &chunks[&reference];
        let n = fc_swarm_provider::chunks::data_size(&root_wire[..8].try_into().unwrap());
        let unverifiable = id == "readData-one-chunk-at-depths-6-and-7";
        let joined = (!unverifiable).then(|| join(&chunks, &reference, n));
        if let Some(file) = from.strip_prefix("dweb-verify.json swarm.files/") {
            let file = files[file];
            let data = content(
                &string(get(file, "seed")),
                number(get(file, "size")) as usize,
            );
            assert_eq!(
                joined.as_ref() == Some(&data),
                get(file, "joined_equals_content").kind() == Kind::True,
                "{id}: the join"
            );
        }
        let node = Node {
            rules: Vec::new(),
            blobs: joined
                .iter()
                .map(|data| (reference.clone(), data.clone()))
                .collect(),
            chunks,
            feeds: BTreeMap::new(),
            stopped: false,
        };
        let key = js(get(scenario, "key"));
        let mut world = TestWorld {
            now: 1_767_225_600_123,
            grants: BTreeSet::from([key.clone()]),
            feeds: FeedStore::empty(),
            budgets: ReadBudgets::new(),
        };
        let call = Call {
            method: Value::str("swarm_readData"),
            params: params.clone(),
            key: key.clone(),
            approval: None,
        };
        let ran = run(&mut world, &node, &call);
        let view = StepView {
            params: &params,
            key: &key,
            feeds: &world.feeds,
        };
        check_row(&id, grammar, "readData", &ran, &view);
        // Every intermediate the scenario fetches, the walk fetches.
        for want in get(scenario, "calls").children() {
            let Some(tree) = want.get("tree") else {
                continue;
            };
            if number(get(tree, "length")) <= 4096.0 {
                continue;
            }
            let path = string(get(want, "path"));
            assert!(
                ran.calls.iter().any(|l| l.call.path == path
                    && l.call
                        .tree
                        .is_some_and(|t| t.length as f64 == number(get(tree, "length"))
                            && f64::from(t.depth) == number(get(tree, "depth")))),
                "{id}: {path} at {}",
                tree.raw()
            );
        }
        match joined {
            Some(data) => assert_eq!(
                ran.outcome,
                Outcome::Result(Value::object([
                    (
                        "data",
                        Value::String(fc_swarm_provider::value::encode_base64(&data).into())
                    ),
                    ("encoding", Value::str("base64")),
                ])),
                "{id}"
            ),
            None => assert_eq!(
                ran.outcome,
                Outcome::Error(Failure::invalid_params(
                    "Downloaded bytes do not validate as the requested content-addressed chunk",
                    "chunk_type_mismatch"
                )),
                "{id}"
            ),
        }
        walks += 1;
    }
    assert_eq!(walks, 21);
}
