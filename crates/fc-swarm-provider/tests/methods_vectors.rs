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

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::*;
use fc_json::JsString;
use fc_json::index::{Index, Kind, Value as V};
use fc_swarm::tree;
use fc_swarm::verify::{self, Chunk};
use fc_swarm_provider::machine::{Call, Failure, Form, Outcome, Reply, stream_charge};
use fc_swarm_provider::stores::feeds::FeedStore;
use fc_swarm_provider::value::Value;

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
const LEFT_OUT: &[(&str, &str)] = &[];

/// The deviations a case of the seven marks, and what the core answers.
fn core_answer(deviation: &str, core: V<'_, '_>) -> Want {
    if let Some(want) = shared_answer(deviation, core) {
        return want;
    }
    let text = string(core);
    match deviation {
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

/// The core's calls against the row's ready check, forms and counts, and
/// the values main binds (design 0015, "The operation grammar").
fn check_row(id: &str, grammar: V<'_, '_>, row: &str, ran: &Ran, step: &StepView<'_>) {
    check_row_shape(id, grammar, row, ran);
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
    let scenarios = scenarios(grammar);

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
        let mut world = TestWorld::of(case);
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
            let Some(handoff) = handoff(*step, &origin, &mut world) else {
                // Main answered: the core never sees the request.
                assert_eq!(get(*step, "requests").children().count(), 0, "{sid}");
                main_answered += 1;
                continue;
            };
            let Handoff {
                key,
                method,
                name: method_name,
                params,
            } = handoff;
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
            check_outcome(&sid, want, last, case, *step, &ran.outcome);
            if want == Want::Cancelled && last {
                assert!(
                    ran.cancels_after_outcome > 0,
                    "{sid}: its open call cancelled"
                );
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
    assert_eq!((played, main_answered), (552, 7));
    assert_eq!(scenarios_used.len(), 96);
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
                let message = match outcome {
                    Next::Error(message) => message,
                    Next::Node(err) => err.message,
                    other => panic!("{id}: {other:?}"),
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
            blobs: joined
                .iter()
                .map(|data| (reference.clone(), data.clone()))
                .collect(),
            chunks,
            ..Node::new()
        };
        let key = js(get(scenario, "key"));
        let mut world = TestWorld {
            grants: BTreeSet::from([key.clone()]),
            ..TestWorld::new(1_767_225_600_123)
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
