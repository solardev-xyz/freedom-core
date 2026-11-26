//! The grammar's property test (design 0015, Migration, SWM-3's row): over
//! every `vectors/swarm.json` `methods` case's node and random node
//! answers, every call each machine makes matches its method's row at its
//! step in `vectors/swarm-grammar.json`, and no machine reaches a form or
//! a value another method's row alone allows. It runs every method with a
//! machine: Access, the Reads, Publish, the feed and SOC writes and
//! Messaging.
//!
//! **One run** plays a case's steps in order on one world, the way the
//! vectors tests do (main's grant writes, a feed prompt's identity, the
//! case's `at_execute`), with a scripted main whose every answer is drawn
//! from a seeded generator ([`Rng`], written here; no randomness reaches
//! the library). For each node call it picks the case's own node's honest
//! answer, that answer damaged (a flipped, cut or lengthened body, its
//! headers dropped), a node error (each status, JSON, text, empty, past 8
//! KiB), a 2xx with another body (random bytes, JSON of another shape, past
//! the form's cap, nested past 64 levels, a byte-order mark), a 1xx or
//! 3xx, stream oddities (short, long, cut, a declared length the body
//! doesn't reach, past `max_bytes`), a transport failure of each class
//! (`stopped` among them), main's grammar refusal, or an answer that
//! breaks the protocol. Every other ask is answered the same way: the
//! readiness checks, parts (a wrong length, an abort), signatures and
//! owners (refused, a wrong signature), store writes (failing), the mining
//! lane (each way it ends), the upload's turn, a topic's turn, and main's
//! `swarm.body` credit (or the reply before the body is in). A run may be
//! cancelled, or end `busy`, at any answer.
//!
//! **What is checked,** for every node call as the core asks it, by an
//! admission check written here from design 0015's grammar, as main's
//! executor will make it ("The operation grammar", "Values main derives
//! from its own replies"):
//! - the form (from the grammar file): method, path and its values'
//!   syntax, query names in order and their values, the headers (only the
//!   form's, each once, at their values, a `publish` header never, a
//!   `soc-raw` one exactly under `writeSingleOwnerChunk`), the body's kind
//!   and bounds, `max_bytes`, and `feed` and `tree` only where they may be;
//! - the row: its ready check once and first, its forms in order within
//!   their counts (common's `check_row_shape`), one call open at a time
//!   (eight for `readData`), and each value the row binds, worked out from
//!   the params, the page's key and main's own earlier answers in the
//!   request: addresses, topics, owners, the feed index main replays from
//!   its answers (the head probe), the wrapped chunk's address and size,
//!   `readData`'s size and the children its returned chunks name, a large
//!   entry's root against `bytes_up`'s reference, bodies against the
//!   params.
//!
//! **Seeds:** `GRAMMAR_SEEDS` sets the runs per case (default 24, 3 for a
//! case with megabytes of data); each run picks how often the node answers
//! honestly (95, 70 or 40 times in a hundred). `GRAMMAR_SEED` runs one seed
//! and `GRAMMAR_CASE` one case, to replay a failure, whose message names
//! both; `GRAMMAR_TIMES` prints the slow cases.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    // The run's summary and `GRAMMAR_TIMES`' slow cases.
    clippy::print_stderr
)]

mod common;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use common::*;
use fc_json::index::{Index, KeyOrder, Kind, Value as V};
use fc_json::{JsString, JsValue};
use fc_swarm::verify;
use fc_swarm_provider::machine::node::{BodyOut, WINDOW};
use fc_swarm_provider::machine::shell::{Shell, ShellCall, ShellMethod, ShellOutcome};
use fc_swarm_provider::machine::{
    Abort, Approval, Ask, AskId, Body, Call, Effect, ErrorCode, Event, Failed, Form, Head, MineJob,
    Mined, Need, NodeCall, Outcome, ReadyCheck, Reply, Request, Rule, SignKey, Signed, StoreWrite,
};
use fc_swarm_provider::methods::feed_index::{round_trip, wrapping_index};
use fc_swarm_provider::stores::feeds::{FeedChange, Source};
use fc_swarm_provider::value::{Bytes, Source as DataSource, Value};

/// `B`: the larger read budget's `maxBytes`.
const B: u64 = 5 * 1024 * 1024;

// ---------------------------------------------------------------------------
// A seeded generator (SplitMix64), the test's own.

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed ^ 0x9e37_79b9_7f4a_7c15)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }

    /// True `percent` times in a hundred.
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<T: Clone>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize].clone()
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

// ---------------------------------------------------------------------------
// The grammar's forms, read from the file.

#[derive(Debug, Clone)]
struct HeaderSpec {
    name: String,
    value: String,
    when: Option<String>,
}

#[derive(Debug, Clone)]
struct FormSpec {
    method: String,
    path: Vec<String>,
    query: Vec<String>,
    headers: Vec<HeaderSpec>,
    body: Option<Vec<String>>,
    body_bytes: Option<(usize, usize)>,
    whole: Option<usize>,
}

fn forms(grammar: V<'_, '_>) -> BTreeMap<String, FormSpec> {
    get(grammar, "forms")
        .members()
        .map(|(name, f)| {
            let spec = FormSpec {
                method: string(get(f, "method")),
                path: string(get(f, "path"))
                    .split('/')
                    .map(str::to_owned)
                    .collect(),
                query: get(f, "query").children().map(string).collect(),
                headers: get(f, "headers")
                    .children()
                    .map(|h| {
                        let mut it = h.children();
                        HeaderSpec {
                            name: string(it.next().unwrap()),
                            value: string(it.next().unwrap()),
                            when: it.next().map(string),
                        }
                    })
                    .collect(),
                body: (get(f, "body").kind() != Kind::Null)
                    .then(|| get(f, "body").children().map(string).collect()),
                body_bytes: f.get("body_bytes").map(|b| {
                    let mut it = b.children();
                    (
                        number(it.next().unwrap()) as usize,
                        number(it.next().unwrap()) as usize,
                    )
                }),
                whole: get(f, "reply").get("whole").map(|w| number(w) as usize),
            };
            (string(name), spec)
        })
        .collect()
}

fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A path value's syntax (`values`).
fn value_ok(placeholder: &str, s: &str) -> bool {
    match placeholder {
        "<a>" | "<t>" | "<id>" | "<b>" => is_hex(s, 64),
        "<o>" => is_hex(s, 40),
        "<x>" => is_hex(s, 4) || is_hex(s, 6),
        "<uid>" => {
            !s.is_empty()
                && !s.starts_with('0')
                && s.bytes().all(|b| b.is_ascii_digit())
                && s.parse::<u64>().is_ok_and(|n| (1..1 << 53).contains(&n))
        }
        literal => literal == s,
    }
}

/// The call against its form: method, path, query, headers, body,
/// `max_bytes` and the annotations.
fn check_form(call: &NodeCall, form: &FormSpec, row: &str) -> Result<(), String> {
    if call.method() != form.method {
        return Err(format!("method {}", call.method()));
    }
    let segments: Vec<&str> = call.path.split('/').collect();
    if segments.len() != form.path.len()
        || !segments.iter().zip(&form.path).all(|(s, p)| value_ok(p, s))
    {
        return Err(format!("path {}", call.path));
    }
    let names: Vec<&str> = call.query.iter().map(|(k, _)| k.as_str()).collect();
    if names != form.query.iter().map(String::as_str).collect::<Vec<_>>() {
        return Err(format!("query {:?}", call.query));
    }
    for (k, v) in &call.query {
        let ok = match k.as_str() {
            "sig" => is_hex(v, 130),
            "recipient" => is_hex(v, 66) && (v.starts_with("02") || v.starts_with("03")),
            "name" => true,
            _ => false,
        };
        if !ok {
            return Err(format!("query {k}={v}"));
        }
    }
    let mut seen = BTreeSet::new();
    for (k, v) in &call.headers {
        let Some(spec) = form.headers.iter().find(|h| h.name == *k) else {
            return Err(format!("header {k}"));
        };
        if !seen.insert(k.clone()) {
            return Err(format!("header {k} twice"));
        }
        let value_ok = match spec.value.as_str() {
            "<b>" => is_hex(v, 64),
            "<content-type>" | "<p>" => true,
            "true|false" => v == "true" || v == "false",
            "bytes=<s>-<e>" => v
                .strip_prefix("bytes=")
                .and_then(|r| r.split_once('-'))
                .and_then(|(s, e)| Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?)))
                .is_some_and(|(s, e)| s <= e),
            literal => literal == v,
        };
        if !value_ok {
            return Err(format!("header {k}: {v}"));
        }
        if spec.when.as_deref() == Some("publish") && !row.starts_with("swarm.publish") {
            return Err(format!("header {k} is swarm.publish's"));
        }
    }
    for spec in &form.headers {
        let required = match spec.when.as_deref() {
            None => true,
            Some("soc-raw") => row == "writeSingleOwnerChunk",
            _ => false,
        };
        let allowed = match spec.when.as_deref() {
            Some("soc-raw") => row == "writeSingleOwnerChunk",
            Some("publish") => row.starts_with("swarm.publish"),
            _ => true,
        };
        let has = seen.contains(&spec.name);
        if (required && !has) || (has && !allowed) {
            return Err(format!(
                "header {} {}",
                spec.name,
                if has { "not allowed" } else { "missing" }
            ));
        }
    }
    let (kind, len) = match &call.body {
        None => (None, 0usize),
        Some(Body::Base64(b)) => (Some("base64"), b.len()),
        Some(Body::Stream { bytes }) => (Some("stream"), *bytes as usize),
    };
    match (&form.body, kind) {
        (None, None) => {}
        (Some(kinds), Some(kind)) if kinds.iter().any(|k| k == kind) => {
            if kind == "base64" && len > 64 * 1024 {
                return Err(format!("an inline body of {len}"));
            }
            if let Some((min, max)) = form.body_bytes
                && !(min..=max).contains(&len)
            {
                return Err(format!("a body of {len}"));
            }
        }
        (want, got) => return Err(format!("body {got:?} where {want:?}")),
    }
    match form.whole {
        Some(cap) if call.max_bytes > cap => return Err(format!("max_bytes {}", call.max_bytes)),
        None if call.max_bytes as u64 > B || call.max_bytes == 0 => {
            return Err(format!("stream max_bytes {}", call.max_bytes));
        }
        _ => {}
    }
    if call.feed.is_some()
        && (call.form != Form::Chunk
            || !matches!(
                row,
                "readFeedEntry_index"
                    | "updateFeed"
                    | "writeFeedEntry"
                    | "swarm.feed:update"
                    | "swarm.feed:read"
            ))
    {
        return Err("feed outside a feed row's chunks".to_owned());
    }
    if call.tree.is_some() && (call.form != Form::Chunk || row != "readData") {
        return Err("tree outside readData's chunks".to_owned());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The row's values, as main works them out.

/// Main's answer to a call, as far as later values read it.
#[derive(Debug, Clone)]
enum Answered {
    Reply(Reply),
    /// A streamed reply's head, its body under way.
    Head,
    Failed,
}

/// The head probe, replayed over main's own answers (feed-service.js's
/// `probeFeedHead`, design 0015, "Which index").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lookup {
    /// `feed_head` asked.
    Head,
    /// The probe asked `asked`.
    Zero,
    Grow {
        lo: u64,
        hi: u64,
    },
    Bisect {
        lo: u64,
        hi: u64,
        mid: u64,
    },
    /// The index to write at.
    Done(u64),
    /// No more calls of the lookup.
    Ended,
}

impl Lookup {
    fn asked(self) -> Option<u64> {
        match self {
            Lookup::Zero => Some(0),
            Lookup::Grow { hi, .. } => Some(hi),
            Lookup::Bisect { mid, .. } => Some(mid),
            _ => None,
        }
    }

    fn bisect(lo: u64, hi: u64) -> Lookup {
        if hi - lo > 1 {
            Lookup::Bisect {
                lo,
                hi,
                mid: lo + (hi - lo) / 2,
            }
        } else {
            Lookup::Done(lo + 1)
        }
    }

    fn found(self, found: bool) -> Lookup {
        match (self, found) {
            (Lookup::Zero, false) => Lookup::Done(0),
            (Lookup::Zero, true) => Lookup::Grow { lo: 0, hi: 1 },
            (Lookup::Grow { hi, .. }, true) if hi * 2 > 1 << 40 => Lookup::Ended,
            (Lookup::Grow { hi, .. }, true) => Lookup::Grow { lo: hi, hi: hi * 2 },
            (Lookup::Grow { lo, hi }, false) => Lookup::bisect(lo, hi),
            (Lookup::Bisect { mid, hi, .. }, true) => Lookup::bisect(mid, hi),
            (Lookup::Bisect { lo, mid, .. }, false) => Lookup::bisect(lo, mid),
            _ => Lookup::Ended,
        }
    }
}

/// The row's admission of one request's calls.
struct Checker<'a> {
    row: &'static str,
    params: &'a Value,
    key: JsString,
    parts: &'a BTreeMap<u32, Vec<u8>>,
    forms: &'a BTreeMap<String, FormSpec>,
    /// The forms the row allows at any step.
    row_forms: Vec<String>,
    calls: Vec<(NodeCall, Option<Answered>)>,
    owner: Option<String>,
    lookup: Option<Lookup>,
    /// readData: the addresses the returned chunks name.
    named: HashSet<[u8; 32]>,
    later_chunks: usize,
}

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn param_str(params: &Value, key: &str) -> Option<String> {
    params
        .get(key)
        .as_js_string()
        .map(|s| s.as_str().to_owned())
}

/// A data param's bytes: a string's UTF-8, inline bytes, or a part's.
fn data_bytes(value: &Value, parts: &BTreeMap<u32, Vec<u8>>) -> Option<Vec<u8>> {
    match value {
        Value::String(s) => Some(s.as_str().as_bytes().to_vec()),
        Value::Bytes(Bytes {
            source: DataSource::Inline(b),
            ..
        }) => Some(b.clone()),
        Value::Bytes(Bytes {
            source: DataSource::Part(k),
            ..
        }) => parts.get(k).cloned(),
        _ => None,
    }
}

fn data_len(value: &Value) -> Option<u64> {
    match value {
        Value::String(s) => Some(s.len() as u64),
        Value::Bytes(b) => Some(b.len),
        _ => None,
    }
}

impl<'a> Checker<'a> {
    fn new(
        row: &'static str,
        params: &'a Value,
        key: JsString,
        parts: &'a BTreeMap<u32, Vec<u8>>,
        forms: &'a BTreeMap<String, FormSpec>,
    ) -> Checker<'a> {
        Checker {
            row,
            params,
            key,
            parts,
            forms,
            row_forms: Vec::new(),
            calls: Vec::new(),
            owner: None,
            lookup: None,
            named: HashSet::new(),
            later_chunks: 0,
        }
    }

    /// `keccak256(utf8(key + "/" + name))`.
    fn feed_topic(&self, name_param: &str) -> Option<[u8; 32]> {
        let name = param_str(self.params, name_param)?;
        Some(fc_swarm::feed::topic(&format!(
            "{}/{name}",
            self.key.as_str()
        )))
    }

    /// One `<o>` throughout a feed row, fixed by the first call naming it.
    fn fix_owner(&mut self, owner: &str) -> Result<(), String> {
        match &self.owner {
            Some(o) if o != owner => Err(format!("a second <o> {owner}")),
            _ => {
                self.owner = Some(owner.to_owned());
                Ok(())
            }
        }
    }

    fn previous(&self, form: Form) -> Option<&Answered> {
        self.calls
            .iter()
            .rev()
            .find(|(c, _)| c.form == form)
            .and_then(|(_, a)| a.as_ref())
    }

    /// The call, as main admits it at its step.
    fn admit(&mut self, call: &NodeCall) -> Result<(), String> {
        if !self.row_forms.iter().any(|f| f == call.form.as_str()) {
            return Err(format!(
                "{} isn't one of {}'s forms",
                call.form.as_str(),
                self.row
            ));
        }
        let form = &self.forms[call.form.as_str()];
        check_form(call, form, self.row)?;
        let segments: Vec<String> = call.path.split('/').map(str::to_owned).collect();
        let body = match &call.body {
            Some(Body::Base64(b)) => Some(b.clone()),
            _ => None,
        };
        let span_and = |data: &[u8], span: u64| {
            let mut want = span.to_le_bytes().to_vec();
            want.extend_from_slice(data);
            want
        };
        if self.row.starts_with("swarm.") {
            return self.shell(call, &segments, body.as_deref());
        }
        match (self.row, call.form) {
            (_, Form::Stamps) => {}
            ("readChunk", Form::Chunk) => {
                let reference = lower(&param_str(self.params, "reference").unwrap_or_default());
                if segments[2] != reference {
                    return Err("<a> isn't params.reference".to_owned());
                }
            }
            ("readSingleOwnerChunk", Form::Chunk) => {
                let address = match param_str(self.params, "address") {
                    Some(a) => lower(&a),
                    None => {
                        let id = lower(&param_str(self.params, "identifier").unwrap_or_default());
                        let owner = lower(strip_0x(
                            &param_str(self.params, "owner").unwrap_or_default(),
                        ));
                        let id: [u8; 32] = unhex(&id).try_into().map_err(|_| "identifier")?;
                        let owner: [u8; 20] = unhex(&owner).try_into().map_err(|_| "owner")?;
                        hex(&verify::soc_address(&id, &owner))
                    }
                };
                if segments[2] != address {
                    return Err("<a> isn't the SOC's".to_owned());
                }
            }
            ("readData", Form::Chunk) if self.calls.is_empty() => {
                let reference = lower(&param_str(self.params, "reference").unwrap_or_default());
                if segments[2] != reference || call.tree.is_some() {
                    return Err("the root isn't params.reference".to_owned());
                }
            }
            ("readData", form) => {
                let n = self
                    .root_size()
                    .ok_or("a call after a root of 4,096 bytes or less")?;
                match form {
                    Form::Bytes => {
                        if self.calls.iter().any(|(c, _)| c.form == Form::Bytes) {
                            return Err("a second bytes".to_owned());
                        }
                        let reference =
                            lower(&param_str(self.params, "reference").unwrap_or_default());
                        let range = format!("bytes=0-{}", n - 1);
                        if segments[2] != reference
                            || call.headers != [("range".to_owned(), range)]
                            || call.max_bytes as u64 != n
                        {
                            return Err(format!("bytes {:?} for {n}", call.headers));
                        }
                    }
                    Form::Chunk => {
                        let tree = call.tree.ok_or("a later chunk without its tree")?;
                        let address: [u8; 32] = unhex(&segments[2]).try_into().unwrap();
                        self.later_chunks += 1;
                        if !self.named.contains(&address)
                            || tree.length == 0
                            || tree.length > n
                            || !(1..=8).contains(&tree.depth)
                            || self.later_chunks > 2562
                        {
                            return Err(format!("a chunk no returned chunk names: {tree:?}"));
                        }
                    }
                    other => return Err(format!("{other:?} under readData")),
                }
            }
            ("readFeedEntry_index", Form::Chunk) => {
                let feed = call.feed.ok_or("a feed chunk without its feed")?;
                let owner = hex(&feed.owner);
                // A falsy owner (`''`) is none: the site's own.
                if let Some(o) = param_str(self.params, "owner").filter(|o| !o.is_empty())
                    && lower(strip_0x(&o)) != owner
                {
                    return Err("<o> isn't params.owner".to_owned());
                }
                self.fix_owner(&owner)?;
                let index = match self.params.get("index") {
                    Value::Number(n) => wrapping_index(*n),
                    _ => return Err("no params.index".to_owned()),
                };
                if feed.index != index {
                    return Err(format!("feed index {} for {index}", feed.index));
                }
                let topic = match param_str(self.params, "topic") {
                    Some(t) => unhex(&lower(&t)).try_into().map_err(|_| "topic")?,
                    None => self.feed_topic("name").ok_or("no topic")?,
                };
                let address = verify::feed_update_address(&feed.owner, &topic, index);
                if segments[2] != hex(&address) {
                    return Err("the SOC's address".to_owned());
                }
            }
            ("readFeedEntry_index", Form::Bytes) => {
                let Some(Answered::Reply(soc)) = self.previous(Form::Chunk) else {
                    return Err("bytes without the SOC".to_owned());
                };
                if !soc.ok() || soc.body.len() < 105 {
                    return Err("bytes after a SOC that isn't one".to_owned());
                }
                let span: [u8; 8] = soc.body[97..105].try_into().unwrap();
                let size = fc_swarm_provider::chunks::data_size(&span);
                let wrapped = verify::address_of(&span, &soc.body[105..])
                    .ok_or("a wrapped chunk past 4,096 bytes")?;
                if segments[2] != hex(&wrapped)
                    || !call.headers.is_empty()
                    || call.max_bytes as u64 != size
                    || size <= 4096
                    || size > B
                {
                    return Err(format!(
                        "bytes {} for the wrapped {}",
                        call.path,
                        hex(&wrapped)
                    ));
                }
            }
            ("readFeedEntry_latest", Form::FeedLatest) => {
                if let Some(o) = param_str(self.params, "owner").filter(|o| !o.is_empty())
                    && lower(strip_0x(&o)) != segments[2]
                {
                    return Err("<o> isn't params.owner".to_owned());
                }
                let topic = match param_str(self.params, "topic") {
                    Some(t) => lower(&t),
                    None => hex(&self.feed_topic("name").ok_or("no topic")?),
                };
                if segments[3] != topic {
                    return Err("<t>".to_owned());
                }
            }
            ("getUploadStatus", Form::Tag) => {
                let uid = match self.params.get("tagUid") {
                    Value::Number(n) => format!("{n}"),
                    _ => String::new(),
                };
                if segments[2] != uid {
                    return Err("<uid> isn't params.tagUid".to_owned());
                }
            }
            ("getMessagingIdentity", Form::Addresses) => {}
            ("publishData", Form::BzzFile) => {
                let header = |name: &str| {
                    call.headers
                        .iter()
                        .find(|(k, _)| k == name)
                        .map(|(_, v)| v.clone())
                };
                if header("swarm-deferred-upload").as_deref() != Some("false") {
                    return Err("swarm-deferred-upload: true".to_owned());
                }
                if let Some(ct) = param_str(self.params, "contentType")
                    && header("content-type") != Some(ct.clone())
                {
                    return Err("content-type isn't params.contentType".to_owned());
                }
                let len = match &call.body {
                    Some(Body::Base64(b)) => b.len() as u64,
                    Some(Body::Stream { bytes }) => *bytes,
                    None => 0,
                };
                if Some(len) != data_len(self.params.get("data")) {
                    return Err(format!("a body of {len}"));
                }
            }
            ("publishFiles", Form::BzzTar) => {
                let Value::Array(files) = self.params.get("files") else {
                    return Err("no files".to_owned());
                };
                let files: Vec<&Value> = files.iter().flatten().collect();
                let mut bound = 1024u64;
                let mut top_index = false;
                for f in &files {
                    let path = param_str(f, "path").unwrap_or_default();
                    top_index |= path == "index.html";
                    let size = data_len(f.get("bytes")).unwrap_or(0);
                    bound +=
                        1024 + (path.len() as u64).div_ceil(512) * 512 + size.div_ceil(512) * 512;
                }
                let index = param_str(self.params, "indexDocument")
                    .or_else(|| top_index.then(|| "index.html".to_owned()));
                let header = call
                    .headers
                    .iter()
                    .find(|(k, _)| k == "swarm-index-document")
                    .map(|(_, v)| v.clone());
                if header != index {
                    return Err(format!("swarm-index-document {header:?} for {index:?}"));
                }
                match call.body {
                    Some(Body::Stream { bytes }) if bytes <= bound => {}
                    _ => return Err(format!("a tar past T(files) = {bound}")),
                }
            }
            ("publishChunk", Form::ChunkUp) => {
                let data = data_bytes(self.params.get("data"), self.parts).unwrap_or_default();
                let body = body.unwrap_or_default();
                if body.len() != 8 + data.len() || body[8..] != data[..] {
                    return Err("the body isn't span ‖ the data".to_owned());
                }
            }
            ("writeSingleOwnerChunk", Form::SocUp) => {
                let id = lower(&param_str(self.params, "identifier").unwrap_or_default());
                let data = data_bytes(self.params.get("data"), self.parts).unwrap_or_default();
                let body = body.unwrap_or_default();
                if segments[3] != id {
                    return Err("<id> isn't params.identifier".to_owned());
                }
                if body.len() != 8 + data.len() || body[8..] != data[..] {
                    return Err("the body isn't span ‖ the data".to_owned());
                }
            }
            ("createFeed", Form::FeedManifest) => {
                let topic = self.feed_topic("name").ok_or("no name")?;
                if segments[3] != hex(&topic) {
                    return Err("<t>".to_owned());
                }
                self.fix_owner(&segments[2])?;
            }
            ("updateFeed" | "writeFeedEntry", form) => {
                let name = if self.row == "updateFeed" {
                    "feedId"
                } else {
                    "name"
                };
                let topic = self.feed_topic(name).ok_or("no topic")?;
                let explicit = match self.params.get("index") {
                    Value::Number(n) if self.row == "writeFeedEntry" => Some(wrapping_index(*n)),
                    _ => None,
                };
                self.feed_write(call, form, &segments, topic, explicit)?;
            }
            ("sendPss", Form::PssSend) => {
                let topic = param_str(self.params, "topic").unwrap_or_default();
                let targets = lower(&param_str(self.params, "targets").unwrap_or_default());
                let recipient = lower(strip_0x(
                    &param_str(self.params, "recipient").unwrap_or_default(),
                ));
                if segments[3] != hex(&fc_evm::keccak256(topic.as_bytes()))
                    || segments[4] != targets
                    || call.query != [("recipient".to_owned(), recipient)]
                    || body.unwrap_or_default()
                        != data_bytes(self.params.get("data"), self.parts).unwrap_or_default()
                {
                    return Err("pss_send's values".to_owned());
                }
            }
            ("sendGsoc", Form::SocUp) => {
                let topic = param_str(self.params, "topic").unwrap_or_default();
                let data = data_bytes(self.params.get("data"), self.parts).unwrap_or_default();
                if segments[3] != hex(&fc_evm::keccak256(topic.as_bytes()))
                    || body != Some(span_and(&data, data.len() as u64))
                {
                    return Err("the GSOC SOC's values".to_owned());
                }
            }
            (row, form) => return Err(format!("{form:?} under {row}")),
        }
        Ok(())
    }

    /// A shell parent's call: the values its row binds, from main's own
    /// params (the grammar's `swarm.publish`, `swarm.feed`, `swarm.stamps`
    /// and `swarm.upload_status` rows), and a given batch as its upload's.
    fn shell(
        &mut self,
        call: &NodeCall,
        segments: &[String],
        body: Option<&[u8]>,
    ) -> Result<(), String> {
        let header = |name: &str| {
            call.headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        let batch = param_str(self.params, "batch").map(|b| lower(&b));
        if call.form == Form::Stamps {
            return match (self.row, &batch) {
                ("swarm.stamps", _) if param_str(self.params, "id").is_some() => {
                    Err("/stamps where the row binds <b> = id".to_owned())
                }
                ("swarm.stamps", _) | (_, None) => Ok(()),
                (_, Some(_)) => Err("a /stamps when the parent named its batch".to_owned()),
            };
        }
        if let Some(batch) = &batch
            && call.method() == "POST"
            && header("swarm-postage-batch-id").as_ref() != Some(batch)
        {
            return Err("swarm-postage-batch-id isn't the parent's batch".to_owned());
        }
        let truthy = |key: &str| self.params.get(key) == &Value::Bool(true);
        let parts: Vec<&Value> = match self.params.get("parts") {
            Value::Array(parts) => parts.iter().flatten().collect(),
            _ => Vec::new(),
        };
        let part_bytes = |p: &Value| match p.get("bytes") {
            Value::Number(n) => *n as u64,
            _ => 0,
        };
        let encrypt = header("swarm-encrypt");
        if call.form.as_str().starts_with("bzz") && encrypt.is_some() != truthy("encrypt") {
            return Err(format!(
                "swarm-encrypt {encrypt:?} for encrypt {}",
                truthy("encrypt")
            ));
        }
        match (self.row, call.form) {
            ("swarm.stamps", Form::Stamp) => {
                let id = param_str(self.params, "id").map(|i| lower(&i));
                if id.as_deref() != Some(segments[2].as_str()) {
                    return Err("<b> isn't id".to_owned());
                }
            }
            ("swarm.upload_status", Form::Tag) => {
                let uid = match self.params.get("tag_uid") {
                    Value::Number(n) => format!("{n}"),
                    _ => String::new(),
                };
                if segments[2] != uid {
                    return Err("<uid> isn't tag_uid".to_owned());
                }
            }
            ("swarm.publish:data,file", Form::BzzFile) => {
                let data = param_str(self.params, "kind").as_deref() == Some("data");
                let name = param_str(self.params, "name")
                    .filter(|n| !n.is_empty())
                    .or_else(|| data.then(|| "data".to_owned()));
                if call.query != [("name".to_owned(), name.unwrap_or_default())] {
                    return Err(format!("name {:?}", call.query));
                }
                let content_type = param_str(self.params, "content_type")
                    .filter(|c| !c.is_empty())
                    .unwrap_or_else(|| {
                        if data {
                            "text/plain"
                        } else {
                            "application/octet-stream"
                        }
                        .to_owned()
                    });
                if header("content-type") != Some(content_type) {
                    return Err("content-type".to_owned());
                }
                let deferred = truthy("deferred").to_string();
                if header("swarm-deferred-upload") != Some(deferred) {
                    return Err("swarm-deferred-upload isn't deferred".to_owned());
                }
                let part = parts.first().ok_or("no part")?;
                let len = match &call.body {
                    Some(Body::Base64(b)) => b.len() as u64,
                    Some(Body::Stream { bytes }) => *bytes,
                    None => 0,
                };
                if len != part_bytes(part) {
                    return Err(format!("a body of {len}"));
                }
                if let (Some(body), Some(text)) = (body, param_str(part, "base64"))
                    && fc_swarm_provider::value::decode_base64(&text).as_deref() != Some(body)
                {
                    return Err("the body isn't the part's bytes".to_owned());
                }
            }
            ("swarm.publish:collection", Form::BzzTar) => {
                let mut bound = 1024u64;
                let mut top_index = false;
                for p in &parts {
                    let path = param_str(p, "path").unwrap_or_default();
                    top_index |= path == "index.html";
                    bound += 1024
                        + (path.len() as u64).div_ceil(512) * 512
                        + part_bytes(p).div_ceil(512) * 512;
                }
                let index = param_str(self.params, "index_document")
                    .or_else(|| top_index.then(|| "index.html".to_owned()));
                if header("swarm-index-document") != index {
                    return Err(format!("swarm-index-document for {index:?}"));
                }
                match call.body {
                    Some(Body::Stream { bytes }) if bytes <= bound => {}
                    _ => return Err(format!("a tar past T(parts) = {bound}")),
                }
            }
            ("swarm.feed:create", Form::FeedManifest) => {
                let topic = lower(&param_str(self.params, "topic").unwrap_or_default());
                if segments[3] != topic {
                    return Err("<t> isn't topic".to_owned());
                }
                self.fix_owner(&segments[2])?;
            }
            ("swarm.feed:update", form) => {
                let topic = lower(&param_str(self.params, "topic").unwrap_or_default());
                let topic: [u8; 32] = unhex(&topic).try_into().map_err(|_| "topic")?;
                self.feed_write(call, form, segments, topic, None)?;
            }
            // readFeedState: feed_head once, then the head probe after its
            // 404 alone; nothing else.
            ("swarm.feed:read", form @ (Form::FeedHead | Form::Chunk)) => {
                let topic = lower(&param_str(self.params, "topic").unwrap_or_default());
                let topic: [u8; 32] = unhex(&topic).try_into().map_err(|_| "topic")?;
                self.feed_write(call, form, segments, topic, None)?;
            }
            (row, form) => return Err(format!("{form:?} under {row}")),
        }
        Ok(())
    }

    /// readData's `n`: the root chunk main returned, over 4,096 bytes and
    /// at most `B`; its references are the children main admits.
    fn root_size(&self) -> Option<u64> {
        let (_, Some(Answered::Reply(root))) = self.calls.first()? else {
            return None;
        };
        if !root.ok() || root.body.len() < 8 {
            return None;
        }
        let span: [u8; 8] = root.body[..8].try_into().ok()?;
        let n = fc_swarm_provider::chunks::data_size(&span);
        (n > 4096 && n <= B).then_some(n)
    }

    /// A feed write's lookup, existence check, large entry and SOC.
    fn feed_write(
        &mut self,
        call: &NodeCall,
        form: Form,
        segments: &[String],
        topic: [u8; 32],
        explicit: Option<u64>,
    ) -> Result<(), String> {
        match form {
            Form::FeedHead => {
                if explicit.is_some() || self.lookup.is_some() {
                    return Err("a feed_head where the row has none".to_owned());
                }
                if segments[3] != hex(&topic) {
                    return Err("<t>".to_owned());
                }
                self.fix_owner(&segments[2])?;
                self.lookup = Some(Lookup::Head);
            }
            Form::Chunk => {
                let feed = call.feed.ok_or("a feed chunk without its feed")?;
                self.fix_owner(&hex(&feed.owner))?;
                let index = match (explicit, self.lookup.and_then(Lookup::asked)) {
                    (Some(index), _) if self.calls.iter().all(|(c, _)| c.form != Form::Chunk) => {
                        index
                    }
                    (None, Some(index)) => index,
                    _ => return Err("a chunk the lookup doesn't ask".to_owned()),
                };
                if feed.index != index {
                    return Err(format!(
                        "probe index {} where main asks {index}",
                        feed.index
                    ));
                }
                let address = verify::feed_update_address(&feed.owner, &topic, index);
                if segments[2] != hex(&address) {
                    return Err("a probe chunk's address".to_owned());
                }
            }
            Form::BytesUp => {
                let len = data_len(self.params.get("data")).unwrap_or(0);
                if self.row != "writeFeedEntry"
                    || len <= 4096
                    || call.body != Some(Body::Stream { bytes: len })
                {
                    return Err("a bytes_up the row doesn't allow".to_owned());
                }
            }
            Form::SocUp => {
                self.fix_owner(&segments[2])?;
                let index = match (explicit, self.lookup) {
                    (Some(index), _) => index,
                    (None, Some(Lookup::Done(index))) => index,
                    _ => return Err(format!("a soc_up before its index: {:?}", self.lookup)),
                };
                // swarm.feed's update: at least `min_index`.
                let index = match self.params.get("min_index") {
                    Value::Number(n) if self.row == "swarm.feed:update" => index.max(*n as u64),
                    _ => index,
                };
                if segments[3] != hex(&verify::feed_update_id(&topic, index)) {
                    return Err(format!("<id> isn't the index {index}'s"));
                }
                let Some(Body::Base64(body)) = &call.body else {
                    return Err("a SOC body".to_owned());
                };
                if matches!(self.row, "updateFeed" | "swarm.feed:update") {
                    let reference = lower(&param_str(self.params, "reference").unwrap_or_default());
                    if !(body.len() == 48 || body.len() == 80) || hex(&body[16..]) != reference {
                        return Err("updateFeed's body".to_owned());
                    }
                } else {
                    let len = data_len(self.params.get("data")).unwrap_or(0);
                    if len <= 4096 {
                        let data =
                            data_bytes(self.params.get("data"), self.parts).unwrap_or_default();
                        let mut want = (data.len() as u64).to_le_bytes().to_vec();
                        want.extend_from_slice(&data);
                        if *body != want {
                            return Err("the body isn't span ‖ the data".to_owned());
                        }
                    } else {
                        let Some(Answered::Reply(up)) = self.previous(Form::BytesUp) else {
                            return Err("a large entry's SOC before bytes_up".to_owned());
                        };
                        let reference = fc_json::parse(&String::from_utf8_lossy(&up.body))
                            .ok()
                            .and_then(|j| j.get("reference").and_then(|r| r.as_str().map(lower)));
                        let span: [u8; 8] = body[..8].try_into().unwrap();
                        let root = verify::address_of(&span, &body[8..]).map(|a| hex(&a));
                        if !up.ok() || root.is_none() || root != reference {
                            return Err("the root isn't bytes_up's reference".to_owned());
                        }
                    }
                }
            }
            other => return Err(format!("{other:?} under {}", self.row)),
        }
        Ok(())
    }

    /// Main's terminal answer to call `at`: what later values read.
    fn answered(&mut self, at: usize, answer: Answered) {
        let (call, slot) = &mut self.calls[at];
        *slot = Some(answer.clone());
        let call = call.clone();
        if self.row == "readData"
            && let Answered::Reply(reply) = &answer
            && reply.ok()
            && call.form == Form::Chunk
            && reply.body.len() > 8
        {
            let longer = call.tree.is_none_or(|t| t.length > 4096);
            if longer {
                for reference in reply.body[8..].as_chunks::<32>().0 {
                    self.named.insert(*reference);
                }
            }
        }
        // The lookup's next step.
        let Some(lookup) = self.lookup else {
            return;
        };
        let status = match &answer {
            Answered::Reply(r) => Some(r),
            _ => None,
        };
        self.lookup = Some(match (lookup, call.form) {
            (Lookup::Head, Form::FeedHead) => match status {
                Some(r) if r.ok() => {
                    let header = |name: &str| {
                        r.headers
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case(name))
                            .map(|(_, v)| v.clone())
                            .filter(|v| !v.is_empty())
                    };
                    let index = header("swarm-feed-index")
                        .and_then(|i| fc_swarm_provider::chunks::bytes_from_hex::<8>(&i).ok());
                    let next = header("swarm-feed-index-next")
                        .and_then(|i| fc_swarm_provider::chunks::bytes_from_hex::<8>(&i).ok());
                    match (index, next) {
                        (Some(_), Some(next)) => Lookup::Done(round_trip(u64::from_be_bytes(next))),
                        _ => Lookup::Ended,
                    }
                }
                // An update probes after a 404 or a 500; a read, which
                // throws a 500, after a 404 alone.
                Some(r) if r.status == 404 => Lookup::Zero,
                Some(r) if r.status == 500 && self.row != "swarm.feed:read" => Lookup::Zero,
                _ => Lookup::Ended,
            },
            (asking, Form::Chunk) if asking.asked().is_some() => match status {
                Some(r) if r.ok() => asking.found(true),
                Some(r) if r.status == 404 => asking.found(false),
                _ => Lookup::Ended,
            },
            (other, _) => other,
        });
    }
}

// ---------------------------------------------------------------------------
// The node: a case's declarative node, its honest answers for every form.

struct PropNode {
    rules: Vec<Rule2>,
    chunks: BTreeMap<String, Vec<u8>>,
    blobs: BTreeMap<String, Vec<u8>>,
    feeds: BTreeMap<(String, String), ReplySpec>,
    probes: Vec<([u8; 20], [u8; 32], Option<u64>)>,
    stamps: Option<Vec<u8>>,
    tags: BTreeMap<String, Vec<u8>>,
    addresses: Option<Vec<u8>>,
    stopped: bool,
    /// Bytes of data the node holds, to scale the runs.
    weight: usize,
}

/// Seeded contents, each made once: the test's own SHA-256 loop runs
/// unoptimized, and many cases' nodes hold the same data.
#[derive(Default)]
struct Contents(HashMap<(String, usize), Vec<u8>>);

impl Contents {
    fn data(&mut self, spec: V<'_, '_>) -> Vec<u8> {
        match spec.get("seed") {
            Some(seed) => {
                let length = number(get(spec, "length")) as usize;
                self.0
                    .entry((string(seed), length))
                    .or_insert_with(|| content(&string(seed), length))
                    .clone()
            }
            None => data_of(spec),
        }
    }
}

struct Rule2 {
    method: Option<String>,
    path: Option<String>,
    prefix: Option<String>,
    reply: ReplySpec,
}

impl PropNode {
    fn of(case: V<'_, '_>, keys: &Keys, contents: &mut Contents) -> PropNode {
        let mut data_of = |spec: V<'_, '_>| contents.data(spec);
        let mut node = PropNode {
            rules: Vec::new(),
            chunks: BTreeMap::new(),
            blobs: BTreeMap::new(),
            feeds: BTreeMap::new(),
            probes: Vec::new(),
            stamps: None,
            tags: BTreeMap::new(),
            addresses: None,
            stopped: case
                .get("node_stopped")
                .is_some_and(|s| s.kind() == Kind::True),
            weight: 0,
        };
        for (k, v) in get(case, "node").members() {
            match string(k).as_str() {
                "data" => {
                    for d in v.children() {
                        let bytes = data_of(d);
                        node.weight += bytes.len();
                        let root = tree_of(&bytes, &mut node.chunks);
                        node.blobs.insert(hex(&root.address()), bytes);
                    }
                }
                "chunks" => {
                    for c in v.children() {
                        node.chunks.insert(string(get(c, "address")), data_of(c));
                    }
                }
                "blobs" => {}
                "entries" => {
                    for e in v.children() {
                        let key = keys.of(&string(get(e, "key")));
                        let topic = fc_swarm::feed::topic(&string(get(e, "topic")));
                        let id = verify::feed_update_id(&topic, number(get(e, "index")) as u64);
                        let bytes = data_of(get(e, "data"));
                        node.weight += bytes.len();
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
                        let reply = ReplySpec::of(get(l, "reply"));
                        node.weight += reply.body.len();
                        node.feeds.insert((owner, topic), reply);
                    }
                }
                "probes" => {
                    for p in v.children() {
                        let Some(head) = p.get("head") else {
                            continue;
                        };
                        node.probes.push((
                            fc_evm::address_of(keys.of(&string(get(p, "key")))),
                            fc_swarm::feed::topic(&string(get(p, "topic"))),
                            (head.kind() != Kind::Null).then(|| number(head) as u64),
                        ));
                    }
                }
                "probeFail" => {}
                "rules" => {
                    for r in v.children() {
                        let m = get(r, "match");
                        node.rules.push(Rule2 {
                            method: m.get("method").map(string),
                            path: m.get("path").map(string),
                            prefix: m.get("prefix").map(string),
                            reply: ReplySpec::of(get(r, "reply")),
                        });
                    }
                }
                "stamps" => node.stamps = Some(v.stringify(KeyOrder::Property).into_bytes()),
                "stamps_label_bytes" => {
                    node.stamps = Some(
                        format!(
                            r#"{{"stamps":[{{"batchID":"{}","utilization":0,"usable":true,"label":"{}","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000}}]}}"#,
                            "a1".repeat(32),
                            "l".repeat(number(v) as usize)
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
                "addresses" => node.addresses = Some(v.stringify(KeyOrder::Property).into_bytes()),
                other => panic!("node spec {other:?}"),
            }
        }
        node
    }

    /// The node's honest reply to `call` with its request body.
    fn reply(&self, call: &NodeCall, body: &[u8]) -> ReplySpec {
        let method = call.method();
        let path = call.path.as_str();
        if let Some(rule) = self.rules.iter().find(|r| {
            r.method.as_deref().is_none_or(|m| m == method)
                && r.path.as_deref().is_none_or(|p| p == path)
                && r.prefix.as_deref().is_none_or(|p| path.starts_with(p))
        }) {
            return rule.reply.clone();
        }
        let json = |body: Vec<u8>| ReplySpec::ok(body, "application/json; charset=utf-8");
        let created = |reference: String, tag: Option<u64>| {
            let mut spec = json(format!(r#"{{"reference":"{reference}"}}"#).into_bytes());
            spec.status = 201;
            spec.status_text = "Created".to_owned();
            if let Some(tag) = tag {
                spec.headers.push(("swarm-tag".to_owned(), tag.to_string()));
            }
            spec
        };
        match call.form {
            Form::Chunk => {
                let address = &path["/chunks/".len()..];
                if let Some(feed) = call.feed {
                    for (owner, topic, head) in &self.probes {
                        let at = hex(&verify::feed_update_address(owner, topic, feed.index));
                        if *owner == feed.owner
                            && at == address
                            && head.is_some_and(|h| feed.index <= h)
                        {
                            return ReplySpec::ok(vec![0; 105], "binary/octet-stream");
                        }
                    }
                }
                self.chunks
                    .get(address)
                    .map_or_else(ReplySpec::not_found, |c| {
                        ReplySpec::ok(c.clone(), "binary/octet-stream")
                    })
            }
            Form::Bytes => self
                .blobs
                .get(&path["/bytes/".len()..])
                .map_or_else(ReplySpec::not_found, |b| {
                    ReplySpec::ok(b.clone(), "application/octet-stream")
                }),
            Form::FeedHead | Form::FeedLatest => {
                let mut it = path["/feeds/".len()..].split('/');
                let key = (it.next().unwrap().to_owned(), it.next().unwrap().to_owned());
                self.feeds
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(ReplySpec::not_found)
            }
            Form::Stamps => json(
                self.stamps
                    .clone()
                    .unwrap_or_else(|| br#"{"stamps":[]}"#.to_vec()),
            ),
            Form::Tag => self
                .tags
                .get(&path["/tags/".len()..])
                .map_or_else(ReplySpec::not_found, |t| json(t.clone())),
            Form::Addresses => self
                .addresses
                .clone()
                .map_or_else(ReplySpec::not_found, json),
            Form::BzzFile | Form::BzzTar => created(sha(body), Some(101)),
            Form::ChunkUp => {
                let span: [u8; 8] = body
                    .get(..8)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0; 8]);
                let address = verify::address_of(&span, body.get(8..).unwrap_or(&[]))
                    .map_or_else(|| "00".repeat(32), |a| hex(&a));
                created(address, Some(0))
            }
            Form::SocUp => {
                let mut it = path["/soc/".len()..].split('/');
                let owner: [u8; 20] = unhex(it.next().unwrap()).try_into().unwrap();
                let id: [u8; 32] = unhex(it.next().unwrap()).try_into().unwrap();
                created(hex(&verify::soc_address(&id, &owner)), None)
            }
            Form::BytesUp => {
                let mut scratch = BTreeMap::new();
                let root = tree_of(body, &mut scratch);
                created(hex(&root.address()), Some(102))
            }
            Form::FeedManifest => created(sha(format!("feed manifest {path}").as_bytes()), None),
            Form::PssSend => ReplySpec {
                status: 201,
                status_text: "Created".to_owned(),
                headers: Vec::new(),
                ..ReplySpec::ok(Vec::new(), "")
            },
            // `/stamps/<b>`: that batch of the node's `/stamps`, alone.
            Form::Stamp => {
                let id = &path["/stamps/".len()..];
                self.stamps
                    .as_ref()
                    .and_then(|s| fc_json::parse(&String::from_utf8_lossy(s)).ok())
                    .and_then(|all| {
                        all.get("stamps")?
                            .as_array()?
                            .iter()
                            .find(|b| b.get("batchID").and_then(|i| i.as_str()) == Some(id))
                            .map(|b| b.stringify().into_bytes())
                    })
                    .map_or_else(ReplySpec::not_found, json)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Random answers.

const REASONS: [&str; 5] = [
    "node-stopped",
    "node-not-ready",
    "ultra-light-mode",
    "no-usable-stamps",
    "proxy-or-tor",
];

fn random_failed(rng: &mut Rng) -> Failed {
    rng.pick(&[
        Failed::Unreachable,
        Failed::Error,
        Failed::Aborted,
        Failed::TooLarge,
        Failed::Busy,
        Failed::Stopped,
    ])
}

fn random_headers(rng: &mut Rng) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for name in READ_HEADERS {
        if !rng.chance(30) {
            continue;
        }
        let value = match rng.below(6) {
            0 => hex(&rng.bytes(8)),
            1 => String::new(),
            2 => "zz".to_owned(),
            3 => rng.below(1_000_000).to_string(),
            4 => "a".repeat(rng.below(1024) as usize),
            _ => format!("0x{}", hex(&rng.bytes(8))),
        };
        out.push((name.to_owned(), value));
    }
    out
}

/// A body of some shape: empty, bytes, JSON of another shape, deep, a BOM,
/// bad UTF-8, or past `cap`.
fn random_body(rng: &mut Rng, cap: usize) -> Vec<u8> {
    match rng.below(10) {
        0 => Vec::new(),
        1 => {
            let n = rng.below(600) as usize;
            rng.bytes(n)
        }
        2 => format!(r#"{{"reference":"{}"}}"#, hex(&rng.bytes(32))).into_bytes(),
        3 => format!(
            r#"{{"code":500,"message":"{}"}}"#,
            "x".repeat(rng.below(50) as usize)
        )
        .into_bytes(),
        4 => br#"{"stamps":[{"batchID":5}],"reference":null,"uid":"x","overlay":7}"#.to_vec(),
        5 => {
            let depth = 60 + rng.below(10) as usize;
            format!("{}{}", "[".repeat(depth), "]".repeat(depth)).into_bytes()
        }
        6 => {
            let mut b = vec![0xef, 0xbb, 0xbf];
            b.extend_from_slice(br#"{"reference":"ab"}"#);
            b
        }
        7 => vec![0xff, 0xfe, b'{', 0xc3],
        8 => vec![b'1'; cap.saturating_add(1).min(2 * 1024 * 1024)],
        _ => b"not json".to_vec(),
    }
}

fn random_spec(rng: &mut Rng, call: &NodeCall, honest: ReplySpec) -> ReplySpec {
    let cap = if call.stream() {
        call.max_bytes
    } else {
        call.form.cap()
    };
    let mut spec = honest;
    match rng.below(9) {
        // Damaged.
        0 => {
            if !spec.body.is_empty() {
                let at = rng.below(spec.body.len() as u64) as usize;
                spec.body[at] ^= 1 << rng.below(8);
            }
        }
        1 => {
            let len = rng.below(spec.body.len() as u64 + 1) as usize;
            spec.body.truncate(len);
        }
        2 => {
            let n = rng.below(200) as usize + 1;
            let more = rng.bytes(n);
            spec.body.extend(more);
        }
        3 => spec.headers.clear(),
        // A node error.
        4 => {
            spec.status = rng.pick(&[400, 402, 404, 404, 500, 500, 502, 503]);
            spec.status_text = reason_phrase(spec.status).to_owned();
            spec.body = if rng.chance(20) {
                vec![b'e'; 9000]
            } else {
                random_body(rng, 8192)
            };
            spec.headers = random_headers(rng);
        }
        // A 2xx of another body.
        5 => {
            spec.status = rng.pick(&[200, 201, 206]);
            spec.status_text = reason_phrase(spec.status).to_owned();
            spec.body = random_body(rng, cap);
            spec.headers = random_headers(rng);
        }
        // A 1xx or a 3xx, or no reason phrase.
        6 => {
            spec.status = rng.pick(&[100, 101, 199, 204, 301, 304, 307, 399, 418, 599]);
            spec.status_text = if rng.chance(50) {
                String::new()
            } else {
                "Odd".to_owned()
            };
            spec.body = random_body(rng, 8192);
        }
        // Stream oddities: cut, short of its declared length, chunked.
        7 => {
            if rng.chance(50) {
                spec.declare = Some(spec.body.len() + 1 + rng.below(1000) as usize);
            } else {
                let mut pieces = Vec::new();
                let mut rest = spec.body.clone();
                while !rest.is_empty() {
                    let n = (rng.below(70_000) as usize + 1).min(rest.len());
                    pieces.push(rest.drain(..n).collect());
                }
                spec.pieces = Some(pieces);
                spec.cut_after_pieces = rng.chance(50);
            }
        }
        // Past the cap.
        _ => {
            spec.status = 200;
            spec.status_text = "OK".to_owned();
            spec.body = vec![
                7;
                cap.saturating_add(1 + rng.below(100) as usize)
                    .min(6 * 1024 * 1024)
            ];
        }
    }
    spec
}

/// An answer main never sends: the core ends the request `Protocol`.
fn protocol_breach(rng: &mut Rng, call: &NodeCall) -> Vec<Event> {
    let head = || {
        Event::Head(Head {
            status: 200,
            status_text: "OK".to_owned(),
            headers: Vec::new(),
        })
    };
    match rng.below(5) {
        0 => vec![Event::Data(vec![1, 2, 3])],
        1 if call.stream() => vec![head(), head()],
        1 | 2 => vec![Event::Reply(Reply {
            status: 99,
            status_text: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
        })],
        3 => vec![Event::Reply(Reply {
            status: 200,
            status_text: "OK".to_owned(),
            headers: (0..9).map(|i| (format!("x-{i}"), "v".to_owned())).collect(),
            body: Vec::new(),
        })],
        _ => vec![Event::Turn],
    }
}

// ---------------------------------------------------------------------------
// The scripted main.

/// What the scripted main moves: a page's request or a shell parent.
trait Machine {
    fn answer(&mut self, world: &mut TestWorld, id: AskId, event: Event);
    fn take_effects(&mut self) -> Vec<Effect>;
    fn done(&self) -> bool;
    fn cancel(&mut self);
    fn busy(&mut self);
    /// D13's bound passed for ask `id`: a shell parent's; a page's request
    /// has its deadline instead.
    fn expire(&mut self, _world: &mut TestWorld, _id: AskId) {}
}

impl Machine for Request {
    fn answer(&mut self, world: &mut TestWorld, id: AskId, event: Event) {
        Request::answer(self, world, id, event);
    }
    fn take_effects(&mut self) -> Vec<Effect> {
        Request::take_effects(self)
    }
    fn done(&self) -> bool {
        self.outcome().is_some()
    }
    fn cancel(&mut self) {
        Request::cancel(self);
    }
    fn busy(&mut self) {
        Request::busy(self);
    }
}

impl Machine for Shell {
    fn answer(&mut self, world: &mut TestWorld, id: AskId, event: Event) {
        Shell::answer(self, world, id, event);
    }
    fn take_effects(&mut self) -> Vec<Effect> {
        Shell::take_effects(self)
    }
    fn done(&self) -> bool {
        self.outcome().is_some()
    }
    fn cancel(&mut self) {
        Shell::cancel(self);
    }
    fn busy(&mut self) {
        Shell::busy(self);
    }
    fn expire(&mut self, world: &mut TestWorld, id: AskId) {
        Shell::expire(self, world, id);
    }
}

struct Upload {
    call: NodeCall,
    body: Vec<u8>,
    /// The body's terminal: `Some(true)` for its end, `Some(false)` for an
    /// abort.
    ended: Option<bool>,
}

struct PartStream {
    id: AskId,
    data: Vec<u8>,
    sent: usize,
    window: usize,
}

type JobKey = ([u8; 32], [u8; 32], u32);

struct Main<'a> {
    rng: Rng,
    /// How often, in a hundred, a node call gets the node's honest answer.
    honesty: u64,
    world: TestWorld,
    node: &'a PropNode,
    keys: &'a Keys,
    signers: &'a mut HashMap<JobKey, Option<u32>>,
    parts_data: BTreeMap<u32, Vec<u8>>,
    // The request's.
    queue: VecDeque<Effect>,
    /// Credit main gives an upload's body, as each frame goes.
    body_credits: VecDeque<(AskId, usize)>,
    /// Each node call's place in the checker's log.
    call_at: HashMap<AskId, usize>,
    /// A streamed reply's window.
    windows: HashMap<AskId, usize>,
    uploads: BTreeMap<AskId, Upload>,
    parts: Vec<PartStream>,
    cancelled: HashSet<AskId>,
    open_calls: BTreeSet<AskId>,
    most_open: usize,
    ready: Vec<(ReadyCheck, usize)>,
    violations: Vec<String>,
}

impl Main<'_> {
    fn take<M: Machine>(&mut self, request: &mut M) {
        for effect in request.take_effects() {
            match effect {
                Effect::Ask(Ask {
                    id,
                    need: Need::Node(_),
                    ..
                }) => {
                    self.open_calls.insert(id);
                    self.most_open = self.most_open.max(self.open_calls.len());
                    self.queue.push_back(effect);
                }
                Effect::Ask(_) => self.queue.push_back(effect),
                Effect::Credit { id, bytes } => {
                    if let Some(window) = self.windows.get_mut(&id) {
                        *window += bytes;
                    }
                    if let Some(part) = self.parts.iter_mut().find(|p| p.id == id) {
                        part.window += bytes;
                    }
                }
                Effect::Cancel(id) => {
                    self.cancelled.insert(id);
                    self.parts.retain(|p| p.id != id);
                }
                Effect::Body { id, out } => match out {
                    BodyOut::Head { .. } => {}
                    BodyOut::Data(bytes) => {
                        if let Some(upload) = self.uploads.get_mut(&id) {
                            upload.body.extend_from_slice(&bytes);
                        }
                        self.body_credits.push_back((id, bytes.len()));
                    }
                    BodyOut::End | BodyOut::Abort(_) => {
                        let end = matches!(out, BodyOut::End);
                        if let Some(upload) = self.uploads.get_mut(&id) {
                            upload.ended = Some(end);
                            if end
                                && let Some(Body::Stream { bytes }) = upload.call.body
                                && upload.body.len() as u64 != bytes
                            {
                                self.violations.push(format!(
                                    "a body of {} where its call declared {bytes}",
                                    upload.body.len()
                                ));
                            }
                        }
                    }
                },
            }
        }
    }

    /// Gives `event` to ask `id`, unless the request ended; a random cancel
    /// or `busy` may come first.
    fn give<M: Machine>(
        &mut self,
        request: &mut M,
        checker: &mut Checker<'_>,
        id: AskId,
        event: Event,
    ) {
        if request.done() {
            return;
        }
        let roll = self.rng.below(1000);
        if roll < 4 {
            request.cancel();
        } else if roll < 5 {
            request.busy();
        } else if roll < 8 {
            // D13: the ask went past its bound; main's answer, when it
            // comes, is a late one.
            request.expire(&mut self.world, id);
        }
        if request.done() {
            self.take(request);
            return;
        }
        let terminal = matches!(
            event,
            Event::Reply(_) | Event::Failed(_) | Event::End | Event::Abort(_) | Event::Refused(_)
        );
        if let Some(&at) = self.call_at.get(&id) {
            match &event {
                Event::Head(_) => checker.calls[at].1 = Some(Answered::Head),
                Event::Reply(reply) => checker.answered(at, Answered::Reply(reply.clone())),
                Event::Failed(_) | Event::Refused(_) => checker.answered(at, Answered::Failed),
                Event::End | Event::Abort(_) => {
                    let answer = checker.calls[at].1.clone().unwrap_or(Answered::Failed);
                    checker.answered(at, answer);
                }
                _ => {}
            }
        }
        request.answer(&mut self.world, id, event);
        if terminal {
            self.open_calls.remove(&id);
            self.windows.remove(&id);
        }
        self.take(request);
    }

    /// The node call's events: the node's honest answer, or another.
    fn node_events(&mut self, call: &NodeCall, body: &[u8]) -> Vec<Event> {
        if self.node.stopped && self.rng.chance(80) {
            return vec![Event::Failed(Failed::Stopped)];
        }
        let honest = self.node.reply(call, body);
        if self.rng.chance(self.honesty) {
            return forward(&honest, call).1;
        }
        match self.rng.below(100) {
            0..=59 => {
                let spec = random_spec(&mut self.rng, call, honest);
                forward(&spec, call).1
            }
            60..=84 => vec![Event::Failed(random_failed(&mut self.rng))],
            85..=92 => vec![Event::Refused(self.rng.pick(&[
                Rule::Form,
                Rule::Order,
                Rule::Count,
                Rule::Value,
                Rule::Header,
                Rule::Query,
                Rule::Body,
                Rule::Ended,
            ]))],
            _ => protocol_breach(&mut self.rng, call),
        }
    }

    /// Delivers a node call's events in order, a streamed reply's data
    /// frames only within the core's credit (one that runs out stalls).
    fn deliver<M: Machine>(
        &mut self,
        request: &mut M,
        checker: &mut Checker<'_>,
        id: AskId,
        events: Vec<Event>,
    ) {
        for event in events {
            if request.done() || self.cancelled.contains(&id) {
                return;
            }
            if let Event::Data(bytes) = &event
                && let Some(window) = self.windows.get_mut(&id)
            {
                if bytes.len() > *window {
                    self.give(request, checker, id, Event::Abort(Abort::Stalled));
                    return;
                }
                *window -= bytes.len();
            }
            self.give(request, checker, id, event);
        }
    }

    fn mined(&mut self, job: MineJob) -> Mined {
        if self.rng.chance(70) {
            let key = (job.target, job.identifier, job.proximity);
            let found = *self.signers.entry(key).or_insert_with(|| {
                fc_swarm::gsoc::mine(&job.target, &job.identifier, job.proximity).map(|s| s.index())
            });
            return found.map_or(Mined::Exhausted, Mined::Found);
        }
        self.rng.pick(&[
            Mined::Exhausted,
            Mined::Timeout,
            Mined::Busy,
            Mined::RateLimited {
                retry_after_ms: 1234,
            },
            Mined::Stuck,
            Mined::Off,
            Mined::Found(17),
        ])
    }

    fn signing_key(&self, key: SignKey) -> Option<&k256::ecdsa::SigningKey> {
        match key {
            SignKey::BeeWallet => Some(&self.keys.bee),
            SignKey::Publisher(index) => self.keys.publishers.get(&u64::from(index)),
        }
    }

    fn answer<M: Machine>(&mut self, request: &mut M, checker: &mut Checker<'_>, ask: Ask) {
        let id = ask.id;
        match ask.need {
            Need::Ready(check) => {
                self.ready.push((check, checker.calls.len()));
                let answer = if self.rng.chance(92) {
                    Ok(())
                } else {
                    Err(JsString::from(self.rng.pick(&REASONS)))
                };
                self.give(request, checker, id, Event::Ready(answer));
            }
            Need::Node(call) => {
                if let Err(why) = checker.admit(&call) {
                    self.violations.push(format!(
                        "call {} {}: {why}",
                        checker.calls.len(),
                        call.path
                    ));
                }
                self.call_at.insert(id, checker.calls.len());
                checker.calls.push((call.clone(), None));
                if call.stream() {
                    self.windows.insert(id, WINDOW as usize);
                }
                if let Some(Body::Stream { .. }) = call.body {
                    self.uploads.insert(
                        id,
                        Upload {
                            call,
                            body: Vec::new(),
                            ended: None,
                        },
                    );
                    self.give(request, checker, id, Event::BodyOpen);
                    return;
                }
                let body = match &call.body {
                    Some(Body::Base64(b)) => b.clone(),
                    _ => Vec::new(),
                };
                let events = self.node_events(&call, &body);
                self.deliver(request, checker, id, events);
            }
            Need::Hash(job) => self.give(request, checker, id, Event::Hashed(job.run())),
            Need::Part(k) => {
                let data = self.parts_data.get(&k).cloned().unwrap_or_default();
                match self.rng.below(100) {
                    0..=3 => self.give(request, checker, id, Event::Failed(Failed::Error)),
                    4..=6 => {
                        self.give(request, checker, id, Event::PartHead(data.len() as u64 + 1));
                    }
                    _ => {
                        let len = data.len() as u64;
                        self.parts.push(PartStream {
                            id,
                            data,
                            sent: 0,
                            window: WINDOW as usize,
                        });
                        self.give(request, checker, id, Event::PartHead(len));
                    }
                }
            }
            Need::Upload => self.give(request, checker, id, Event::Turn),
            Need::Lock(_) => self.give(request, checker, id, Event::Locked),
            // From the case's world, as the synchronous reads it replaces
            // read it, with no roll (no random cancel or `busy` first): every
            // run's answers and outcomes are those the reads gave.
            Need::Live => {
                if !request.done() {
                    let live = self.world.live();
                    request.answer(&mut self.world, id, Event::Live(live));
                    self.take(request);
                }
            }
            // Main opens and closes a subscription with no roll either, so
            // the other answers stay as they were.
            Need::Subscribe(_) => {
                if !request.done() {
                    let opened =
                        Event::Opened(Ok(JsString::from("59820d1a24fddf7bceaad40b518018f0")));
                    request.answer(&mut self.world, id, opened);
                    self.take(request);
                }
            }
            Need::Unsubscribe { .. } => {
                if !request.done() {
                    request.answer(&mut self.world, id, Event::Closed);
                    self.take(request);
                }
            }
            Need::Mine(job) => {
                let mined = self.mined(job);
                self.give(request, checker, id, Event::Mined(mined));
            }
            Need::Owner(key) => {
                let answer = match (self.rng.below(10), self.signing_key(key)) {
                    (0, _) => Ok(None),
                    (1, _) | (_, None) => Err(JsString::from("The identity core failed")),
                    (_, Some(k)) => Ok(Some(fc_evm::address_of(k))),
                };
                self.give(request, checker, id, Event::Owner(answer));
            }
            Need::Sign(soc) => {
                let answer = match (self.rng.below(10), self.signing_key(soc.key)) {
                    (0, _) | (_, None) => Err(JsString::from("Vault is locked")),
                    (roll, Some(k)) => {
                        match fc_swarm::sign_soc(k, &soc.identifier, Some(soc.span), &soc.payload) {
                            Ok(s) => {
                                let mut signature = s.signature;
                                if roll == 1 {
                                    signature[3] ^= 1;
                                }
                                Ok(Signed {
                                    signature,
                                    owner: s.owner,
                                })
                            }
                            Err(_) => Err(JsString::from("no chunk")),
                        }
                    }
                };
                self.give(request, checker, id, Event::Signed(answer));
            }
            Need::Write(write) => {
                let fail = self.rng.chance(12);
                let event = match write {
                    StoreWrite::HistoryInsert(_) if fail => {
                        Event::Inserted(Err(JsString::from("SQLITE_FULL")))
                    }
                    StoreWrite::HistoryInsert(_) => {
                        Event::Inserted(Ok(1 + self.rng.below(10_000) as i64))
                    }
                    _ if fail => Event::Written(Err(JsString::from("EIO: the write failed"))),
                    StoreWrite::Feeds(change) => {
                        let now = self.world.now;
                        match change.apply(&mut self.world.feeds, now) {
                            Ok(_) => Event::Written(Ok(())),
                            Err(err) => Event::Written(Err(JsString::from(format!("{err:?}")))),
                        }
                    }
                    _ => Event::Written(Ok(())),
                };
                self.give(request, checker, id, event);
            }
        }
    }

    /// An upload's body is in, or main answers before it is: the node's
    /// reply.
    fn uploaded<M: Machine>(&mut self, request: &mut M, checker: &mut Checker<'_>, id: AskId) {
        let Some(upload) = self.uploads.remove(&id) else {
            return;
        };
        let events = self.node_events(&upload.call, &upload.body);
        self.deliver(request, checker, id, events);
    }

    fn run<M: Machine>(&mut self, request: &mut M, checker: &mut Checker<'_>) {
        self.take(request);
        while !request.done() {
            if let Some((id, bytes)) = self.body_credits.pop_front() {
                // A frame of an upload's body went: its credit back, or, now
                // and then, the reply before the body is in.
                if !self.uploads.contains_key(&id) {
                    continue;
                }
                if self.rng.below(200) == 0 {
                    self.uploaded(request, checker, id);
                } else {
                    self.give(request, checker, id, Event::BodyCredit(bytes));
                }
                continue;
            }
            if let Some(effect) = self.queue.pop_front() {
                if let Effect::Ask(ask) = effect {
                    self.answer(request, checker, ask);
                }
                continue;
            }
            if let Some(id) = self
                .uploads
                .iter()
                .find(|(_, u)| u.ended.is_some())
                .map(|(id, _)| *id)
            {
                self.uploaded(request, checker, id);
                continue;
            }
            if let Some(part) = self
                .parts
                .iter_mut()
                .find(|p| p.window > 0 || p.sent == p.data.len())
            {
                let n = part.window.min(65_536).min(part.data.len() - part.sent);
                let frame = part.data[part.sent..part.sent + n].to_vec();
                part.sent += n;
                part.window -= n;
                let id = part.id;
                let ended = part.sent == part.data.len();
                let abort = self.rng.below(400) == 0;
                if ended || abort {
                    self.parts.retain(|p| p.id != id);
                }
                if abort {
                    // A part's stream failing, with a file's read error as
                    // its reason now and then.
                    let why = if self.rng.chance(50) {
                        Abort::BodyStreamError
                    } else {
                        Abort::Unreadable(ErrorCode::new("EIO").unwrap())
                    };
                    self.give(request, checker, id, Event::Abort(why));
                    continue;
                }
                if !frame.is_empty() {
                    self.give(request, checker, id, Event::Data(frame));
                }
                if ended {
                    self.give(request, checker, id, Event::End);
                }
                continue;
            }
            // Main's idle bound: an upload whose body stopped coming.
            if let Some(id) = self.uploads.keys().next().copied() {
                self.uploads.remove(&id);
                self.give(request, checker, id, Event::Failed(Failed::Error));
                continue;
            }
            self.violations
                .push("the request waits with nothing asked".to_owned());
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// The test.

fn row_of(method: &str, calls: &[(NodeCall, Option<Answered>)]) -> Option<&'static str> {
    Some(match method {
        "swarm_requestAccess" => "requestAccess",
        "swarm_getCapabilities" => "getCapabilities",
        "swarm_listFeeds" => "listFeeds",
        "swarm_readChunk" => "readChunk",
        "swarm_readSingleOwnerChunk" => "readSingleOwnerChunk",
        "swarm_readData" => "readData",
        "swarm_readFeedEntry" => {
            if calls.iter().any(|(c, _)| c.form == Form::FeedLatest) {
                "readFeedEntry_latest"
            } else {
                "readFeedEntry_index"
            }
        }
        "swarm_publishData" => "publishData",
        "swarm_publishFiles" => "publishFiles",
        "swarm_publishChunk" => "publishChunk",
        "swarm_getUploadStatus" => "getUploadStatus",
        "swarm_createFeed" => "createFeed",
        "swarm_updateFeed" => "updateFeed",
        "swarm_writeFeedEntry" => "writeFeedEntry",
        "swarm_writeSingleOwnerChunk" => "writeSingleOwnerChunk",
        "swarm_getSigningIdentity" => "getSigningIdentity",
        "swarm_getMessagingIdentity" => "getMessagingIdentity",
        "swarm_sendPss" => "sendPss",
        "swarm_sendGsoc" => "sendGsoc",
        "swarm_subscribe" => "subscribe",
        _ => return None,
    })
}

/// The step's parts (`parts[i]`), their bytes from the seed.
fn parts_of(step: V<'_, '_>) -> BTreeMap<u32, Vec<u8>> {
    step.get("parts")
        .map(|parts| {
            parts
                .children()
                .map(|p| {
                    let length = number(get(p, "length")) as usize;
                    let bytes = match p.get("seed") {
                        Some(seed) => content(&string(seed), length),
                        None => string(get(p, "repeat"))
                            .repeat(number(get(p, "count")) as usize)
                            .into_bytes(),
                    };
                    (number(get(p, "part")) as u32, bytes)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// How main approved the step: the service event's, else a prompt's.
fn approval_of(step: V<'_, '_>) -> Option<Approval> {
    let events: Vec<_> = step
        .get("events")
        .map(|e| e.children().collect())
        .unwrap_or_default();
    let service = events.iter().find_map(|e| e.get("service"));
    match service
        .and_then(|s| s.get("approval"))
        .map(string)
        .as_deref()
    {
        Some("auto") => return Some(Approval::Auto),
        Some("user") => return Some(Approval::User),
        _ => {}
    }
    let prompted = events.iter().any(|e| e.get("prompt").is_some());
    let ruled = events
        .iter()
        .any(|e| e.get("custody").is_some_and(|c| c.kind() == Kind::False));
    if ruled && !prompted {
        Some(Approval::Auto)
    } else {
        Some(Approval::User)
    }
}

/// Main's own writes before it hands the step over that a world change
/// can't make through the shared harness: a feed prompt's identity and the
/// feed grant, and the case's `at_execute` (the vault's lock is the
/// vault's own answer, so it is left to the random owners).
fn main_writes(
    world: &mut TestWorld,
    case: V<'_, '_>,
    step: V<'_, '_>,
    key: &JsString,
    first: bool,
) {
    let events: Vec<_> = step
        .get("events")
        .map(|e| e.children().collect())
        .unwrap_or_default();
    for event in &events {
        if event.get("service").is_some() {
            break;
        }
        let Some(prompt) = event.get("prompt") else {
            continue;
        };
        let answer = get(prompt, "answer");
        if answer.get("approve").is_none_or(|a| a.kind() != Kind::True)
            || !get(prompt, "kind").is_str("swarm.feed")
        {
            continue;
        }
        let picked = string(get(get(answer, "choices"), "identity"));
        let new_id = get(prompt, "view")
            .get("newIdentity")
            .map(|n| string(get(n, "id")))
            .unwrap_or_default();
        let options = fc_json::parse(r#"{"activate":true,"source":"user"}"#).unwrap();
        let change = if picked == "bee-wallet" {
            FeedChange::EnsureAntWalletIdentity {
                key: key.clone(),
                options,
                source: Source::User,
            }
        } else if picked == new_id {
            FeedChange::CreateAppScopedIdentityAt {
                key: key.clone(),
                index: JsValue::Number(world.feeds.next_publisher_key_index()),
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
        let _ = change.apply(&mut world.feeds, world.now);
        if !world.feeds.has_feed_grant(key) {
            let grant = FeedChange::GrantFeedAccess {
                key: key.clone(),
                source: Source::User,
            };
            let _ = grant.apply(&mut world.feeds, world.now);
        }
    }
    if !first {
        return;
    }
    if let Some(changes) = case.get("at_execute") {
        for (what, how) in changes.members() {
            let how = match how.kind() {
                Kind::True => "true".to_owned(),
                _ => string(how),
            };
            match string(what).as_str() {
                "vault" => {}
                "feed_access" => {
                    let revoke = FeedChange::RevokeFeedAccess {
                        key: key.clone(),
                        source: Source::User,
                    };
                    let _ = revoke.apply(&mut world.feeds, world.now);
                }
                other => world.apply(key, other, &how),
            }
        }
    }
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

#[test]
fn every_call_matches_its_row() {
    let text = text_of("swarm.json");
    let grammar_text = text_of("swarm-grammar.json");
    let keys_text = text_of("keys.json");
    let index = Index::new(&text).unwrap();
    let grammar_index = Index::new(&grammar_text).unwrap();
    let grammar = grammar_index.root();
    let keys_index = Index::new(&keys_text).unwrap();
    let keys = keys(&keys_index);
    let forms = forms(grammar);
    let seeds = env_u64("GRAMMAR_SEEDS").unwrap_or(24);
    let only_seed = env_u64("GRAMMAR_SEED");
    let only_case = std::env::var("GRAMMAR_CASE").ok();
    let mut signers = HashMap::new();
    let mut nodes: HashMap<String, std::rc::Rc<PropNode>> = HashMap::new();
    let mut contents = Contents::default();

    let mut runs = 0usize;
    let mut calls = 0usize;
    let mut rows_called: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut outcomes: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut failures = Vec::new();
    for case in get(index.root(), "methods").children() {
        let id = string(get(case, "id"));
        if only_case.as_ref().is_some_and(|c| *c != id) {
            continue;
        }
        let steps: Vec<_> = get(case, "steps").children().collect();
        let origin = js(get(case, "origin"));
        let started = std::time::Instant::now();
        // Cases share their nodes' specs: each node is built once.
        let spec = format!(
            "{}{}",
            get(case, "node").raw(),
            case.get("node_stopped").map_or("", |s| s.raw())
        );
        let node = nodes
            .entry(spec)
            .or_insert_with(|| std::rc::Rc::new(PropNode::of(case, &keys, &mut contents)))
            .clone();
        let step_parts: Vec<BTreeMap<u32, Vec<u8>>> = steps.iter().map(|s| parts_of(*s)).collect();
        let heavy = node.weight > 8 << 20
            || step_parts
                .iter()
                .any(|p| p.values().map(Vec::len).sum::<usize>() > 1 << 20);
        let case_seeds: Vec<u64> = match only_seed {
            Some(seed) => vec![seed],
            None => (0..if heavy { seeds.min(3) } else { seeds }).collect(),
        };
        for seed in case_seeds {
            let mut world = TestWorld::of(case);
            let mut rng_seed = seed;
            for b in id.bytes() {
                rng_seed = rng_seed.wrapping_mul(31).wrapping_add(u64::from(b));
            }
            for (k, step) in steps.iter().enumerate() {
                let sid = format!("{id}/{k} (GRAMMAR_CASE={id} GRAMMAR_SEED={seed})");
                if let Some(clock) = step.get("clock") {
                    world.now = number(clock) as u64;
                }
                let Some(handoff) = handoff(*step, &origin, &mut world) else {
                    continue;
                };
                let Some(name) = handoff.name.clone() else {
                    continue;
                };
                main_writes(&mut world, case, *step, &handoff.key, k == 0);
                let call = Call {
                    method: handoff.method.clone(),
                    params: handoff.params.clone(),
                    key: handoff.key.clone(),
                    approval: approval_of(*step),
                };
                let Ok(mut request) = Request::start(&call, &mut world) else {
                    continue;
                };
                let parts = &step_parts[k];
                let mut checker = Checker::new(
                    "pending",
                    &handoff.params,
                    handoff.key.clone(),
                    parts,
                    &forms,
                );
                // The row is known from the method; readFeedEntry's from
                // whether the params name an index.
                checker.row = match name.as_str() {
                    "swarm_readFeedEntry" if !handoff.params.get("index").is_nullish() => {
                        "readFeedEntry_index"
                    }
                    "swarm_readFeedEntry" => "readFeedEntry_latest",
                    other => match row_of(other, &[]) {
                        Some(row) => row,
                        None => continue,
                    },
                };
                let mut rng = Rng::new(rng_seed.wrapping_add(k as u64));
                let honesty = rng.pick(&[95, 70, 40]);
                checker.row_forms = get(get(get(grammar, "rows"), checker.row), "calls")
                    .children()
                    .flat_map(|g| get(g, "forms").children().map(string).collect::<Vec<_>>())
                    .collect();
                let mut main = Main {
                    rng,
                    honesty,
                    world,
                    node: &node,
                    keys: &keys,
                    signers: &mut signers,
                    parts_data: parts.clone(),
                    queue: VecDeque::new(),
                    body_credits: VecDeque::new(),
                    call_at: HashMap::new(),
                    windows: HashMap::new(),
                    uploads: BTreeMap::new(),
                    parts: Vec::new(),
                    cancelled: HashSet::new(),
                    open_calls: BTreeSet::new(),
                    most_open: 0,
                    ready: Vec::new(),
                    violations: Vec::new(),
                };
                main.run(&mut request, &mut checker);
                runs += 1;
                calls += checker.calls.len();
                let row = checker.row;
                *rows_called.entry(row).or_default() += checker.calls.len();
                let kind = match request.outcome() {
                    Some(Outcome::Result(_)) => "result",
                    Some(Outcome::Error(_)) => "error",
                    Some(Outcome::Cancelled) => "cancelled",
                    Some(Outcome::Protocol(_)) => "protocol",
                    None => "none",
                };
                *outcomes.entry(kind).or_default() += 1;
                let shape = common::Ran {
                    outcome: request.outcome().cloned().unwrap_or(Outcome::Cancelled),
                    ready: main.ready.clone(),
                    calls: checker
                        .calls
                        .iter()
                        .map(|(c, _)| Logged {
                            call: c.clone(),
                            charge: 0,
                            body: None,
                        })
                        .collect(),
                    cancels_after_outcome: 0,
                    most_open: main.most_open,
                };
                let shaped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    check_row_shape(&sid, grammar, row, &shape);
                }));
                if let Err(panic) = shaped {
                    let why = panic
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                        .unwrap_or_default();
                    main.violations.push(format!("the row's shape: {why}"));
                }
                for v in &main.violations {
                    failures.push(format!("{sid} [{row}]: {v}"));
                }
                world = main.world;
            }
        }
        if std::env::var("GRAMMAR_TIMES").is_ok() && started.elapsed().as_millis() > 30 {
            eprintln!("{id}: {:?}", started.elapsed());
        }
    }
    assert!(
        failures.is_empty(),
        "{} violations:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!(
        "grammar property: {runs} runs, {calls} calls, outcomes {outcomes:?}, calls by row {rows_called:?}"
    );
    if only_case.is_none() && only_seed.is_none() {
        // Every row with calls was reached with some.
        for row in [
            "readChunk",
            "readSingleOwnerChunk",
            "readData",
            "readFeedEntry_index",
            "readFeedEntry_latest",
            "getUploadStatus",
            "getMessagingIdentity",
            "publishData",
            "publishFiles",
            "publishChunk",
            "writeSingleOwnerChunk",
            "createFeed",
            "updateFeed",
            "writeFeedEntry",
            "sendPss",
            "sendGsoc",
        ] {
            assert!(
                rows_called.get(row).is_some_and(|n| *n > 0),
                "{row}: no run made a call"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Main's own node methods, the shell parents.

/// The shell parents' node: the usable batch and a second one, a tag, and
/// three feeds of the Bee wallet key (their topics main computes from
/// these strings): one whose updates 0 to 3 exist (the head probe's), one
/// `GET /feeds` answers with its index, one with none.
const SHELL_NODE: &str = r#"{"node":{
  "stamps":{"stamps":[
    {"batchID":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","utilization":0,"usable":true,"label":"freedom","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000},
    {"batchID":"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2","utilization":0,"usable":false,"label":"","depth":20,"amount":"7","bucketDepth":16,"blockNumber":9,"immutableFlag":true,"exists":true,"batchTTL":5,"propagating":true}]},
  "tags":{"101":{"uid":101,"address":"","split":10,"seen":2,"stored":10,"sent":7,"synced":5,"startedAt":"2026-01-01T00:00:00Z"}},
  "probes":[{"key":"bee","topic":"shell/probed","head":3}],
  "latest":[{"key":"bee","topic":"shell/latest","reply":{"status":200,"headers":{"swarm-feed-index":"0000000000000004","swarm-feed-index-next":"0000000000000005"}}}]
}}"#;

/// Main's params for one shell run, drawn from the seed: the row, the
/// method, the params' JSON and the parts' bytes.
fn shell_params(rng: &mut Rng) -> (&'static str, ShellMethod, String, BTreeMap<u32, Vec<u8>>) {
    let opt = |rng: &mut Rng, percent: u64, text: String| {
        if rng.chance(percent) {
            text
        } else {
            String::new()
        }
    };
    let batch = |rng: &mut Rng| {
        let id = rng.pick(&["b2", "B2", "a1", "c3"]).repeat(32);
        opt(rng, 40, format!(r#","batch":"{id}""#))
    };
    let encrypt = |rng: &mut Rng| rng.pick(&["", r#","encrypt":true"#, r#","encrypt":false"#]);
    let mut parts = BTreeMap::new();
    let mut part = |rng: &mut Rng, k: u32, len: usize, inline: bool| {
        let data = rng.bytes(len);
        if inline && len <= 64 * 1024 {
            format!(
                r#""bytes":{len},"base64":"{}""#,
                fc_swarm_provider::value::encode_base64(&data)
            )
        } else {
            parts.insert(k, data);
            format!(r#""bytes":{len},"part":{k}"#)
        }
    };
    let (row, method, params) = match rng.below(9) {
        0..=1 => {
            let len = rng.pick(&[0usize, 1, 5, 4096, 65_536, 65_537, 150_000]);
            let inline = rng.chance(70);
            let source = part(rng, 0, len, inline);
            let name = rng.pick(&[
                "",
                r#","name":"""#,
                r#","name":"draft.md""#,
                r#","name":"ñandú & co/?#.txt""#,
            ]);
            let content_type = rng.pick(&[
                "",
                r#","content_type":"text/markdown""#,
                r#","content_type":"""#,
            ]);
            let history = opt(
                rng,
                30,
                r#","history":{"type":"data","name":"Text"}"#.to_owned(),
            );
            (
                "swarm.publish:data,file",
                ShellMethod::Publish,
                format!(
                    r#"{{"kind":"data","parts":[{{{source}}}]{name}{content_type}{}{},"pin":true,"deferred":{}{history}}}"#,
                    encrypt(rng),
                    batch(rng),
                    rng.chance(50)
                ),
            )
        }
        2 => {
            let len = rng.pick(&[0usize, 9, 70_000, 300_000]);
            let source = part(rng, 0, len, false);
            let history = opt(
                rng,
                30,
                r#","history":{"type":"file","name":"notes.txt"}"#.to_owned(),
            );
            (
                "swarm.publish:data,file",
                ShellMethod::Publish,
                format!(
                    r#"{{"kind":"file","parts":[{{{source}}}],"name":"notes.txt"{}{},"pin":true,"deferred":{}{history}}}"#,
                    encrypt(rng),
                    batch(rng),
                    rng.chance(80)
                ),
            )
        }
        3..=4 => {
            let long = format!("{}.txt", "é".repeat(60));
            let pool = [
                "index.html",
                "a/b.txt",
                "assets/app.js",
                long.as_str(),
                "d/index.html",
            ];
            let n = rng.below(4) as usize;
            let mut items = Vec::new();
            let mut paths = Vec::new();
            for k in 0..n {
                let path = pool[(k + rng.below(2) as usize * 2) % pool.len()];
                if paths.contains(&path) {
                    continue;
                }
                paths.push(path);
                let len = rng.pick(&[0usize, 1, 511, 513, 70_000]);
                let inline = rng.chance(50);
                let source = part(rng, k as u32, len, inline);
                items.push(format!(
                    r#"{{"path":{},{source}}}"#,
                    JsValue::string(path).stringify()
                ));
            }
            let index = match paths.first() {
                Some(p) if rng.chance(30) => {
                    format!(r#","index_document":{}"#, JsValue::string(*p).stringify())
                }
                _ => String::new(),
            };
            let history = opt(
                rng,
                30,
                r#","history":{"type":"directory","name":"site"}"#.to_owned(),
            );
            (
                "swarm.publish:collection",
                ShellMethod::Publish,
                format!(
                    r#"{{"kind":"collection","parts":[{}]{index}{}{},"pin":true,"deferred":true{history}}}"#,
                    items.join(","),
                    encrypt(rng),
                    batch(rng)
                ),
            )
        }
        5..=6 => {
            let topic =
                fc_swarm::feed::topic(rng.pick(&["shell/probed", "shell/latest", "shell/none"]));
            let mut topic_hex = hex(&topic);
            if rng.chance(20) {
                topic_hex = topic_hex.to_ascii_uppercase();
            }
            let base = format!(
                r#""key":{{"kind":"bee_wallet"}},"topic":"{topic_hex}"{}"#,
                batch(rng)
            );
            if rng.chance(30) {
                (
                    "swarm.feed:create",
                    ShellMethod::Feed,
                    format!(r#"{{"op":"create",{base}}}"#),
                )
            } else if rng.chance(35) {
                // A read takes no batch.
                (
                    "swarm.feed:read",
                    ShellMethod::Feed,
                    format!(
                        r#"{{"op":"read","key":{{"kind":"bee_wallet"}},"topic":"{topic_hex}"}}"#
                    ),
                )
            } else {
                let reference = rng.pick(&["ef", "EF"]).repeat(rng.pick(&[32, 64]));
                let min = rng.pick(&[
                    "",
                    r#","min_index":0"#,
                    r#","min_index":2"#,
                    r#","min_index":9"#,
                    r#","min_index":1099511627776"#,
                ]);
                (
                    "swarm.feed:update",
                    ShellMethod::Feed,
                    format!(r#"{{"op":"update",{base},"reference":"{reference}"{min}}}"#),
                )
            }
        }
        7 => {
            let id = rng.pick(&[
                "",
                r#""id":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1""#,
                r#""id":"B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2""#,
                r#""id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd""#,
            ]);
            ("swarm.stamps", ShellMethod::Stamps, format!("{{{id}}}"))
        }
        _ => {
            let uid = rng.pick(&[101u64, 7, 9_007_199_254_740_991]);
            (
                "swarm.upload_status",
                ShellMethod::UploadStatus,
                format!(r#"{{"tag_uid":{uid}}}"#),
            )
        }
    };
    (row, method, params, parts)
}

/// The property over main's own methods: every call a shell parent makes,
/// over seeded params and random answers from main, the node and the vault
/// (D13's expiry among them), matches its row at its step, and a given
/// batch is the upload's with no `/stamps`.
#[test]
fn every_shell_call_matches_its_row() {
    let grammar_text = text_of("swarm-grammar.json");
    let keys_text = text_of("keys.json");
    let grammar_index = Index::new(&grammar_text).unwrap();
    let grammar = grammar_index.root();
    let keys_index = Index::new(&keys_text).unwrap();
    let keys = keys(&keys_index);
    let forms = forms(grammar);
    let node_index = Index::new(SHELL_NODE).unwrap();
    let mut contents = Contents::default();
    let node = PropNode::of(node_index.root(), &keys, &mut contents);
    let runs = env_u64("GRAMMAR_SHELL_RUNS").unwrap_or(1500);
    let only_seed = env_u64("GRAMMAR_SEED");
    let mut signers = HashMap::new();
    let mut failures = Vec::new();
    let mut rows_called: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut outcomes: BTreeMap<&'static str, usize> = BTreeMap::new();
    for seed in 0..runs {
        if only_seed.is_some_and(|s| s != seed) {
            continue;
        }
        let mut rng = Rng::new(seed.wrapping_mul(0x5851_f42d_4c95_7f2d));
        let (row, method, params, parts) = shell_params(&mut rng);
        let json = fc_json::parse(&params).unwrap();
        let call = ShellCall::parse(method, &json)
            .unwrap_or_else(|why| panic!("seed {seed}: {params}: {why}"));
        let typed = Value::from_js(&json);
        let mut world = TestWorld::new(1_767_225_600_123);
        let mut shell = Shell::start(call, &mut world);
        let mut checker = Checker::new(row, &typed, JsString::default(), &parts, &forms);
        checker.row_forms = get(get(get(grammar, "rows"), row), "calls")
            .children()
            .flat_map(|g| get(g, "forms").children().map(string).collect::<Vec<_>>())
            .collect();
        let honesty = rng.pick(&[95, 70, 40]);
        let mut main = Main {
            rng,
            honesty,
            world,
            node: &node,
            keys: &keys,
            signers: &mut signers,
            parts_data: parts.clone(),
            queue: VecDeque::new(),
            body_credits: VecDeque::new(),
            call_at: HashMap::new(),
            windows: HashMap::new(),
            uploads: BTreeMap::new(),
            parts: Vec::new(),
            cancelled: HashSet::new(),
            open_calls: BTreeSet::new(),
            most_open: 0,
            ready: Vec::new(),
            violations: Vec::new(),
        };
        main.run(&mut shell, &mut checker);
        *rows_called.entry(row).or_default() += checker.calls.len();
        let kind = match shell.outcome() {
            Some(ShellOutcome::Result(_)) => "result",
            Some(ShellOutcome::Error(_)) => "error",
            Some(ShellOutcome::Cancelled) => "cancelled",
            Some(ShellOutcome::Busy) => "busy",
            Some(ShellOutcome::Protocol(_)) => "protocol",
            None => "none",
        };
        *outcomes.entry(kind).or_default() += 1;
        let shape = common::Ran {
            outcome: Outcome::Cancelled,
            ready: main.ready.clone(),
            calls: checker
                .calls
                .iter()
                .map(|(c, _)| Logged {
                    call: c.clone(),
                    charge: 0,
                    body: None,
                })
                .collect(),
            cancels_after_outcome: 0,
            most_open: main.most_open,
        };
        let sid = format!("seed {seed} (GRAMMAR_SEED={seed}) {params}");
        let shaped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_row_shape(&sid, grammar, row, &shape);
        }));
        if let Err(panic) = shaped {
            let why = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_default();
            main.violations.push(format!("the row's shape: {why}"));
        }
        for v in &main.violations {
            failures.push(format!("{sid} [{row}]: {v}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} violations:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("shell property: {runs} runs, outcomes {outcomes:?}, calls by row {rows_called:?}");
    if only_seed.is_none() {
        for row in [
            "swarm.publish:data,file",
            "swarm.publish:collection",
            "swarm.feed:create",
            "swarm.feed:update",
            "swarm.feed:read",
            "swarm.stamps",
            "swarm.upload_status",
        ] {
            assert!(
                rows_called.get(row).is_some_and(|n| *n > 0),
                "{row}: no call"
            );
        }
        for kind in ["result", "error", "cancelled", "busy"] {
            assert!(outcomes.contains_key(kind), "no run ended {kind}");
        }
    }
}
