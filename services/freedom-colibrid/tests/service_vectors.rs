//! Every COL-1 request case through the `freedom-colibrid` binary, with a
//! scripted main (design 0014, COL-4: "the vectors through the binary with
//! a scripted main, on three OSes").
//!
//! For each case, in the order its warm stores need: the service starts on
//! a copy of its source case's directory, takes each recorded request with
//! the recorded clock (the `testhooks` feature), and main answers each
//! `shell.colibri_fetch` with what the C core got in the recording, after
//! checking the fetch against the request the recording's C core made.
//! The reply must be the design's outcome, every marker must be cleared,
//! and the directory must end as the recording's store did. #750's cases
//! end in an error or in a death inside their step, never a result.
//!
//! The C-call-level replay is `tests/replay.rs`; this is the process.

// Test code: a failed setup ends the test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Each case's outcome is reported as it runs.
#![allow(clippy::print_stderr)]
mod common;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{Colibrid, Dirs, Frame, repo_root};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// How long one request may take.
const REQUEST_WAIT: Duration = Duration::from_secs(120);
/// The deadline main gives each request.
const DEADLINE_MS: u64 = 600_000;
/// Main's cut on the completed message, in UTF-16 units (0014).
const MESSAGE_CUT: usize = 2_000;

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The fixtures' bodies, and a case's scripted and flipped ones.
struct Bodies {
    dir: PathBuf,
    flips: HashMap<String, (usize, String)>,
    scripted: HashMap<String, Vec<u8>>,
}

impl Bodies {
    fn for_case(case: &Value) -> Bodies {
        let mut flips = HashMap::new();
        let mut scripted = HashMap::new();
        for op in case["trace"].as_array().unwrap() {
            let (Some(reply), Some(derived)) = (op.get("reply"), op["reply"].get("derived")) else {
                continue;
            };
            let sha = reply["sha256"].as_str().unwrap().to_owned();
            if let Some(offset) = derived.get("flip") {
                flips.insert(
                    sha,
                    (
                        offset.as_u64().unwrap() as usize,
                        derived["of"].as_str().unwrap().to_owned(),
                    ),
                );
            } else if derived["scripted"] == true {
                scripted.insert(sha, derived["body"].as_str().unwrap().as_bytes().to_vec());
            }
        }
        Bodies {
            dir: repo_root().join("vectors/fixtures/colibri/bodies"),
            flips,
            scripted,
        }
    }

    fn get(&self, sha: &str, len: usize) -> Vec<u8> {
        let bytes = if let Some(body) = self.scripted.get(sha) {
            body.clone()
        } else if let Some((offset, of)) = self.flips.get(sha) {
            let mut bytes = self.file(of);
            bytes[*offset] ^= 1;
            bytes
        } else {
            self.file(sha)
        };
        assert_eq!(
            (bytes.len(), sha256_hex(&bytes).as_str()),
            (len, sha),
            "body {sha}"
        );
        bytes
    }

    fn file(&self, sha: &str) -> Vec<u8> {
        std::fs::read(self.dir.join(format!("{sha}.bin"))).unwrap()
    }
}

/// The recording's data requests, numbered as its recorder numbered them
/// (by first appearance), with what the C core got for each.
struct Recorded {
    requests: Vec<Value>,
    answers: HashMap<u64, Value>,
}

impl Recorded {
    fn of(case: &Value) -> Recorded {
        let mut seen = HashMap::new();
        let mut requests = Vec::new();
        let mut answers = HashMap::new();
        for op in case["trace"].as_array().unwrap() {
            match op["op"].as_str().unwrap() {
                "step" | "verify" => {
                    // A trap step (#750) has no status.
                    let Some(status) = op["status"].as_str() else {
                        continue;
                    };
                    let status: Value = serde_json::from_str(status).unwrap();
                    if status["status"] != "pending" {
                        continue;
                    }
                    for request in status["requests"].as_array().unwrap() {
                        let pointer = request["req_ptr"].to_string().trim_matches('"').to_owned();
                        if let std::collections::hash_map::Entry::Vacant(slot) = seen.entry(pointer)
                        {
                            slot.insert(requests.len());
                            requests.push(request.clone());
                        }
                    }
                }
                "response" | "error" => {
                    answers.insert(op["req"].as_u64().unwrap(), op.clone());
                }
                _ => {}
            }
        }
        Recorded { requests, answers }
    }
}

/// `JSON.stringify(params)` for the arrays the request cases send.
fn stringify(params: &Value) -> String {
    serde_json::to_string(params).unwrap()
}

/// The first `units` UTF-16 units of `text`.
fn cut(text: &str, units: usize) -> String {
    let mut count = 0;
    let mut out = String::new();
    for c in text.chars() {
        count += c.len_utf16();
        if count > units {
            break;
        }
        out.push(c);
    }
    out
}

/// The request's freshness bound, as the recording's client set it on the
/// request's context.
fn min_latest_block_ts(case: &Value, index: usize, method: &str) -> u64 {
    let ops = case["trace"].as_array().unwrap();
    let start = ops
        .iter()
        .position(|op| op["op"] == "request" && op["index"] == index as u64)
        .unwrap();
    let Some(ctx) = ops[start..]
        .iter()
        .find(|op| op["op"] == "create" && op["method"] == method)
        .map(|op| op["ctx"].clone())
    else {
        return 0;
    };
    ops[start..]
        .iter()
        .find(|op| op["op"] == "min_latest_block_ts" && op["ctx"] == ctx)
        .and_then(|op| op["ts"].as_str()?.parse().ok())
        .unwrap_or(0)
}

/// The directory's key files: key, bytes and digest.
fn store_of(dir: &Path) -> BTreeMap<String, Value> {
    let mut entries = BTreeMap::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        let bytes = std::fs::read(entry.path()).unwrap();
        entries.insert(
            name,
            json!({ "bytes": bytes.len(), "sha256": sha256_hex(&bytes) }),
        );
    }
    entries
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

/// How one request ended.
enum Ended {
    Reply(Value),
    /// The process died with request `id`'s step open.
    DiedInStep,
}

#[allow(clippy::too_many_lines)]
fn run_case(case: &Value, warm: &Path, warm_root: &Path) -> Result<(), String> {
    let id = case["id"].as_str().unwrap();
    let chain = case["chain"].as_u64().unwrap();
    let dirs = Dirs::new(&id.replace(|c: char| !c.is_ascii_alphanumeric(), "_"));
    if let Some(from) = case["store"]["from"].as_str() {
        copy_dir(&warm.join(from), &dirs.data());
    }
    let before = store_of(&dirs.data());
    if let Some(entries) = case["store"]["entries"].as_object() {
        let expected: BTreeMap<String, Value> = entries.clone().into_iter().collect();
        if before != expected {
            return Err(format!("{id}: the warm store isn't the recorded one"));
        }
    }
    let refused = case["design"]["refused"].as_str();
    let outcomes = case["design"]
        .get("outcomes")
        .unwrap_or(&case["outcomes"])
        .as_array()
        .unwrap()
        .clone();
    let fetch_error = case["design"]["fetch_error"].as_str();
    let recorded = Recorded::of(case);
    let bodies = Bodies::for_case(case);
    // A private session's process has no directory (0014, "Private
    // sessions"): its store is in memory, and nothing reaches the disk.
    let private = id.contains("private");
    let mut colibrid = Colibrid::serve(chain, (!private).then_some(&dirs));
    colibrid.hello();
    let mut asks = 0u64;
    let mut died = false;
    for (index, request) in case["requests"].as_array().unwrap().iter().enumerate() {
        let method = request["method"].as_str().unwrap();
        let params = stringify(&request["params"]);
        let rid = colibrid.request(
            "colibri.request",
            json!({
                "client": "c",
                "zk": case["zk"].as_bool().unwrap(),
                "method": method,
                "params": params,
                "min_latest_block_ts": min_latest_block_ts(case, index, method),
                "deadline_ms": DEADLINE_MS,
                "test_clock_ms": request["clock"].as_u64().unwrap(),
            }),
        );
        let mut open_step = false;
        let deadline = Instant::now() + REQUEST_WAIT;
        let ended = loop {
            if Instant::now() > deadline {
                return Err(format!("{id}: no reply; stderr: {}", colibrid.stderr()));
            }
            let Some(frame) = colibrid.recv(Duration::from_millis(500)) else {
                if colibrid.exited() {
                    break if open_step {
                        Ended::DiedInStep
                    } else {
                        return Err(format!(
                            "{id}: died outside a step; stderr: {}",
                            colibrid.stderr()
                        ));
                    };
                }
                continue;
            };
            let Frame::Json(message, _) = frame else {
                continue;
            };
            match message["type"].as_str() {
                Some("event") => {
                    let event = message["event"].as_str().unwrap_or_default();
                    if message["data"]["request"] != rid {
                        return Err(format!("{id}: a marker for another request: {message}"));
                    }
                    match (event, open_step) {
                        ("colibri.step", false) => open_step = true,
                        ("colibri.stepped", true) => open_step = false,
                        _ => return Err(format!("{id}: marker out of order: {message}")),
                    }
                }
                Some("request") => {
                    let ask = message["id"].as_u64().unwrap();
                    let p = &message["params"];
                    let Some(want) = recorded.requests.get(asks as usize) else {
                        return Err(format!("{id}: an unrecorded fetch: {p}"));
                    };
                    let same = p["request"] == rid
                        && p["type"] == want["type"]
                        && p["method"] == want["method"]
                        && p["path"] == want["url"]
                        && p["accept"] == want["encoding"]
                        && p.get("payload") == want.get("payload");
                    if !same {
                        return Err(format!(
                            "{id}: fetch {asks} differs:\n  service:   {p}\n  recorded:  {want}"
                        ));
                    }
                    let Some(answer) = recorded.answers.get(&asks) else {
                        return Err(format!("{id}: no recorded answer for fetch {asks}"));
                    };
                    if answer["op"] == "response" {
                        let len = answer["bytes"].as_u64().unwrap() as usize;
                        let body = bodies.get(answer["sha256"].as_str().unwrap(), len);
                        let node = answer["node"].as_u64().unwrap_or(0) as u16;
                        colibrid.answer_body(ask, node, body, len);
                    } else {
                        let text = fetch_error
                            .unwrap_or_else(|| answer["error"].as_str().unwrap_or_default());
                        colibrid.respond(ask, json!({ "error": text }));
                    }
                    asks += 1;
                }
                Some("response") if message["id"] == rid => break Ended::Reply(message),
                _ => {}
            }
        };
        let reply = match ended {
            Ended::DiedInStep => {
                // #750: a crash is an allowed end, never a result.
                if !id.contains("unknown") && !id.contains("unindexed") {
                    return Err(format!(
                        "{id}: died in a step; stderr: {}",
                        colibrid.stderr()
                    ));
                }
                died = true;
                break;
            }
            Ended::Reply(reply) => reply,
        };
        if open_step {
            return Err(format!("{id}: replied with its step open"));
        }
        let result = &reply["result"];
        if let Some(text) = refused {
            if result != &json!({ "status": "error", "error": text }) {
                return Err(format!("{id}: refusal differs: {reply}"));
            }
            continue;
        }
        let outcome = &outcomes[index];
        if outcome["ok"] == true {
            // The result as the client's caller got it: JSON.stringify of
            // the parsed text, with JavaScript's property order. A long one
            // is recorded by its length in UTF-16 units and its digest.
            let got = match result.get("result") {
                Some(value) => fc_json::parse(&value.to_string())
                    .map_err(|e| format!("{id}: the result doesn't parse: {e:?}"))?
                    .stringify(),
                None => "undefined".to_owned(),
            };
            let same = if let Some(digest) = outcome.get("result_json") {
                got.encode_utf16().count() as u64 == digest["chars"].as_u64().unwrap_or(0)
                    && sha256_hex(got.as_bytes()) == digest["sha256"].as_str().unwrap_or_default()
            } else {
                let want = match outcome.get("result") {
                    Some(value) => fc_json::parse(&value.to_string())
                        .map_err(|e| format!("{id}: the outcome doesn't parse: {e:?}"))?
                        .stringify(),
                    None => "undefined".to_owned(),
                };
                got == want
            };
            if result["status"] != "success" || !same {
                return Err(format!(
                    "{id}: success differs:\n  service:   {}\n  reference: {outcome}",
                    cut(&reply.to_string(), 600)
                ));
            }
        } else {
            if result["status"] != "error" {
                return Err(format!(
                    "{id}: not an error:\n  service:   {reply}\n  reference: {outcome}"
                ));
            }
            let message = format!(
                "Error in rpc call {method}{params} : {}",
                result["error"].as_str().unwrap_or_default()
            );
            if cut(&message, MESSAGE_CUT)
                != outcome["error"]["message"].as_str().unwrap_or_default()
            {
                return Err(format!(
                    "{id}: error differs:\n  service:   {message}\n  reference: {outcome}"
                ));
            }
        }
    }
    if !died && colibrid.shutdown() != Some(0) {
        return Err(format!(
            "{id}: didn't exit 0; stderr: {}",
            colibrid.stderr()
        ));
    }
    drop(colibrid);
    let after = store_of(&dirs.data());
    if refused.is_some() {
        if after != before {
            return Err(format!("{id}: a refused request changed the store"));
        }
    } else if !died {
        let expected: BTreeMap<String, Value> = case["store_after"]
            .as_object()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        if after != expected {
            return Err(format!(
                "{id}: final store differs:\n  service:   {after:?}\n  reference: {expected:?}"
            ));
        }
    }
    copy_dir(&dirs.data(), &warm_root.join(id));
    Ok(())
}

#[test]
fn every_request_case_through_the_binary() {
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("vectors/colibri.json")).unwrap(),
    )
    .unwrap();
    let cases: Vec<&Value> = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["kind"] == "request")
        .collect();
    let filter: Vec<String> = std::env::var("COLIBRID_CASES")
        .map(|v| v.split(',').map(str::to_owned).collect())
        .unwrap_or_default();
    // Sources first.
    let mut ordered: Vec<&Value> = Vec::new();
    let mut done: std::collections::HashSet<&str> = std::collections::HashSet::new();
    while ordered.len() < cases.len() {
        let before = ordered.len();
        for case in &cases {
            let id = case["id"].as_str().unwrap();
            let ready = case["store"]["from"]
                .as_str()
                .is_none_or(|from| done.contains(from));
            if !done.contains(id) && ready {
                done.insert(id);
                ordered.push(case);
            }
        }
        assert!(ordered.len() > before, "a store source is missing");
    }
    let warm = Dirs::new("warm");
    let mut failures = Vec::new();
    let mut ran = 0;
    for case in ordered {
        let id = case["id"].as_str().unwrap();
        if !filter.is_empty() && !filter.iter().any(|f| f == id) {
            // A source of a filtered case still runs, for its store.
            let needed = cases
                .iter()
                .any(|c| filter.iter().any(|f| c["id"] == f.as_str()) && c["store"]["from"] == id);
            if !needed {
                continue;
            }
        }
        ran += 1;
        match run_case(case, &warm.root, &warm.root) {
            Ok(()) => eprintln!("ok {id}"),
            Err(e) => {
                eprintln!("FAILED {e}");
                failures.push(id.to_owned());
            }
        }
    }
    eprintln!("{ran} cases, {} failed", failures.len());
    assert!(failures.is_empty(), "failed: {failures:?}");
}

/// The raw parts of a reply, as the service wrote them.
#[derive(serde::Deserialize)]
struct RawReply<'a> {
    #[serde(borrow)]
    result: &'a serde_json::value::RawValue,
}

#[derive(serde::Deserialize)]
struct RawChecked<'a> {
    #[serde(borrow)]
    decoded: &'a serde_json::value::RawValue,
    #[serde(borrow)]
    result: &'a serde_json::value::RawValue,
}

fn run_checkpoint_case(case: &Value) -> Result<(), String> {
    let id = case["id"].as_str().unwrap();
    let chain = case["chain"].as_u64().unwrap();
    let ops = case["trace"].as_array().unwrap();
    let bodies = Bodies::for_case(case);
    let recorded = Recorded::of(case);
    let proof = ops
        .iter()
        .find(|op| op["op"] == "main_fetch" && op["variant"] == "checkpoint_proof")
        .ok_or_else(|| format!("{id}: no proof fetch"))?;
    let min_ts = ops
        .iter()
        .find(|op| op["op"] == "verify_create")
        .and_then(|op| op["min_latest_block_ts"].as_str()?.parse::<u64>().ok())
        .unwrap_or(1);
    // What the recording's C core decoded, and how its verification ended.
    let decode = ops.iter().find(|op| op["op"] == "decode");
    let decoded_digest = if case["deviation"] == "checked-decode" {
        None
    } else {
        decode
            .and_then(|op| op.get("result"))
            .filter(|r| !r.is_null())
    };
    let last_verify: Option<Value> = ops
        .iter()
        .filter(|op| op["op"] == "verify")
        .filter_map(|op| op["status"].as_str())
        .last()
        .map(|status| serde_json::from_str(status).unwrap());
    let mut colibrid = Colibrid::checkpoint(chain);
    colibrid.hello();
    let rid = colibrid.request(
        "colibri.checkpoint",
        json!({ "min_latest_block_ts": min_ts, "deadline_ms": DEADLINE_MS }),
    );
    let mut asked_proof = false;
    let mut asks = 0u64;
    let deadline = Instant::now() + REQUEST_WAIT;
    let raw = loop {
        if Instant::now() > deadline {
            return Err(format!("{id}: no reply; stderr: {}", colibrid.stderr()));
        }
        let Some(Frame::Json(message, raw)) = colibrid.recv(Duration::from_millis(500)) else {
            continue;
        };
        match message["type"].as_str() {
            Some("request") => {
                let ask = message["id"].as_u64().unwrap();
                let p = &message["params"];
                if p["type"] == "checkpoint_proof" {
                    if std::mem::replace(&mut asked_proof, true) {
                        return Err(format!("{id}: a second proof fetch"));
                    }
                    let reply = &proof["reply"];
                    if reply["status"] == 200 {
                        let len = reply["bytes"].as_u64().unwrap() as usize;
                        let body = bodies.get(reply["sha256"].as_str().unwrap(), len);
                        colibrid.answer_body(ask, 0, body, len);
                    } else {
                        colibrid.respond(
                            ask,
                            json!({ "error": format!("HTTP error! Status: {}", reply["status"]) }),
                        );
                    }
                    continue;
                }
                let Some(want) = recorded.requests.get(asks as usize) else {
                    return Err(format!("{id}: an unrecorded fetch: {p}"));
                };
                if p["type"] != want["type"]
                    || p["path"] != want["url"]
                    || p["method"] != want["method"]
                {
                    return Err(format!(
                        "{id}: fetch {asks} differs:\n  service:  {p}\n  recorded: {want}"
                    ));
                }
                let answer = recorded
                    .answers
                    .get(&asks)
                    .ok_or_else(|| format!("{id}: no recorded answer for fetch {asks}"))?;
                if answer["op"] == "response" {
                    let len = answer["bytes"].as_u64().unwrap() as usize;
                    let body = match answer["body"].as_str() {
                        Some(text) => text.as_bytes().to_vec(),
                        None => bodies.get(answer["sha256"].as_str().unwrap(), len),
                    };
                    colibrid.answer_body(ask, 0, body, len);
                } else {
                    colibrid.respond(ask, json!({ "error": answer["error"] }));
                }
                asks += 1;
            }
            Some("response") if message["id"] == rid => break raw,
            _ => {}
        }
    };
    let reply: RawReply<'_> = serde_json::from_str(&raw).map_err(|e| format!("{id}: {e}"))?;
    let result: Value = serde_json::from_str(reply.result.get()).unwrap();
    match (decoded_digest, &last_verify) {
        (None, _) => {
            if result["status"] != "error" || result["stage"] != "decode" {
                return Err(format!("{id}: expected a decode failure: {result}"));
            }
        }
        (Some(digest), Some(status)) if status["status"] == "success" => {
            let checked: RawChecked<'_> = serde_json::from_str(reply.result.get())
                .map_err(|e| format!("{id}: not a check's result: {e}: {result}"))?;
            let decoded = checked.decoded.get();
            if decoded.encode_utf16().count() as u64 != digest["chars"].as_u64().unwrap_or(0)
                || sha256_hex(decoded.as_bytes()) != digest["sha256"].as_str().unwrap_or_default()
            {
                return Err(format!("{id}: the decoded proof differs"));
            }
            let recorded_status = ops
                .iter()
                .filter(|op| op["op"] == "verify")
                .filter_map(|op| op["status"].as_str())
                .last()
                .unwrap();
            let recorded_result: RawReply<'_> = serde_json::from_str(recorded_status).unwrap();
            if checked.result.get() != recorded_result.result.get() {
                return Err(format!("{id}: the verified result differs"));
            }
        }
        (Some(_), Some(status)) => {
            if result["status"] != "error"
                || result["stage"] != "verify"
                || result["error"] != status["error"]
            {
                return Err(format!(
                    "{id}: expected the verify error {}: {result}",
                    status["error"]
                ));
            }
        }
        (Some(_), None) => return Err(format!("{id}: the recording never verified")),
    }
    // One check, then the process exits 0.
    if colibrid.exit_code(Duration::from_secs(20)) != Some(0) {
        return Err(format!(
            "{id}: didn't exit 0 after its check; stderr: {}",
            colibrid.stderr()
        ));
    }
    Ok(())
}

#[test]
fn every_checkpoint_case_through_the_binary() {
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("vectors/colibri.json")).unwrap(),
    )
    .unwrap();
    let mut failures = Vec::new();
    let mut ran = 0;
    for case in vectors["cases"].as_array().unwrap() {
        if case["kind"] != "checkpoint" {
            continue;
        }
        ran += 1;
        let id = case["id"].as_str().unwrap();
        match run_checkpoint_case(case) {
            Ok(()) => eprintln!("ok {id}"),
            Err(e) => {
                eprintln!("FAILED {e}");
                failures.push(id.to_owned());
            }
        }
    }
    eprintln!("{ran} checkpoint cases, {} failed", failures.len());
    assert!(ran > 0);
    assert!(failures.is_empty(), "failed: {failures:?}");
}
