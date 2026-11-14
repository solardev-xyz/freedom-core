//! R-6 over the wire (design 0012, "A page's Radicle write"; #372):
//! `approval.radicle_write { key }` decides a page's Radicle COB write with
//! the core's own Radicle grant, and counts it in R-6 when the rule answers.
//! It answers `not_moved` until `radicle` is in `grant_moved`, refuses
//! another page's key and every caller but `page`, and a revoked grant
//! forgets the key's bucket.
//!
//! The approvals' vault clock is the test's
//! (`FREEDOM_CORED_TEST_APPROVAL_CLOCK`), so each of R-6's runs lands on
//! the millisecond it names.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use common::*;
use serde_json::{Value, json};

const SITE: &str = "https://issues.example";
const OTHER: &str = "https://other.example";
/// Where the test's vault clock starts.
const T0: u64 = 1_000_000;
const REFILL_MS: u64 = 30_000;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

fn page_as(origin: &str, agent: Option<bool>) -> Value {
    let mut page = json!({ "origin": origin, "top_origin": origin, "frame": 1, "navigation": 1 });
    if let Some(agent) = agent {
        page["agent"] = json!(agent);
    }
    json!({ "caller": "page", "page": page })
}

fn site() -> Value {
    page_as(SITE, Some(false))
}

fn chrome() -> Value {
    json!({ "caller": "chrome" })
}

fn shell() -> Value {
    json!({ "caller": "shell" })
}

fn covered() -> Value {
    json!({ "covered": true })
}

fn not_covered(reason: &str) -> Value {
    json!({ "covered": false, "reason": reason })
}

fn refused(reply: &Value, code: &str) {
    assert_eq!(reply["error"]["code"], code, "{reply}");
}

/// Every file in `dir`, with its bytes.
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let bytes = std::fs::read(entry.path()).unwrap_or_default();
            (entry.file_name().to_string_lossy().into_owned(), bytes)
        })
        .collect()
}

/// A Radicle file as main wrote it: `key` connected, with the signing
/// grant and its rule.
fn granted_file(key: &str) -> String {
    serde_json::to_string_pretty(&json!({ key: {
        "origin": key, "connectedAt": 1_762_000_000_000_u64, "lastUsed": 1_762_000_000_000_u64,
        "signing": true, "autoApprove": { "node": false, "signing": true },
    } }))
    .unwrap()
}

/// A core whose approvals read the test's vault clock, at [`T0`].
struct Run {
    core: Core,
    id: u64,
    clock: PathBuf,
}

impl Run {
    fn start(root: &Path, moved: &[&'static str]) -> Run {
        let clock = root.join("clock");
        std::fs::write(&clock, T0.to_string()).unwrap();
        let clock_env = clock.to_string_lossy().into_owned();
        let mut core = spawn_env(
            "serve",
            &root.join("identity"),
            &root.join("locks"),
            &[],
            &[("FREEDOM_CORED_TEST_APPROVAL_CLOCK", &clock_env)],
        );
        std::fs::create_dir_all(&core.grant_root).unwrap();
        core.grant_moved = moved.to_vec();
        assert_eq!(core.hello()["result"]["protocol"], 2);
        Run {
            core,
            id: 10,
            clock,
        }
    }

    fn grant_root(&self) -> PathBuf {
        self.core.grant_root.clone()
    }

    /// The vault's clock reads `ms` from the next request on.
    fn at(&mut self, ms: u64) {
        std::fs::write(&self.clock, ms.to_string()).unwrap();
    }

    fn call(&mut self, context: &Value, method: &str, params: Value) -> Value {
        self.id += 1;
        self.core.send(&json!({
            "type": "request", "id": self.id, "method": method, "params": params, "context": context,
        }));
        self.core.response(self.id)
    }

    fn ask(&mut self, context: &Value, key: &str) -> Value {
        self.call(context, "approval.radicle_write", json!({ "key": key }))
    }

    /// The page's own write: its answer.
    fn write(&mut self, context: &Value) -> Value {
        let key = context["page"]["origin"].as_str().unwrap().to_owned();
        let reply = self.ask(context, &key);
        assert!(reply["result"].is_object(), "{reply}");
        reply["result"].clone()
    }

    fn grant(&mut self, context: &Value, change: Value) {
        let reply = self.call(
            context,
            "approval.grant",
            json!({ "store": "radicle", "change": change }),
        );
        assert!(reply["result"]["grant"].is_object(), "{reply}");
    }

    fn revoke(&mut self, context: &Value, what: Value) {
        let reply = self.call(
            context,
            "approval.revoke",
            json!({ "store": "radicle", "key": SITE, "what": what }),
        );
        assert_eq!(reply["result"]["revoked"], true, "{reply}");
    }

    /// The page's connection, its signing grant and its "always allow
    /// writes" rule, each from its prompt.
    fn allow_writes(&mut self, page: &Value) {
        self.grant(page, json!({ "op": "connect" }));
        self.grant(page, json!({ "op": "signing" }));
        self.grant(page, json!({ "op": "flag", "flag": "signing" }));
    }

    /// A burst of five at once, then the sixth asked.
    fn burst(&mut self, page: &Value) {
        for n in 1..=5 {
            assert_eq!(self.write(page), covered(), "write {n}");
        }
        assert_eq!(self.write(page), not_covered("rate_limited"));
    }
}

/// R-6's runs: a sixth write at once is asked; one more is admitted at
/// 30 s and none at 29,999 ms; the 51st within 24 hours is asked, and
/// admitted at exactly 24 hours after the first. A write the limit refuses
/// isn't counted.
#[test]
fn r6_runs_over_the_wire() {
    let root = tempfile::tempdir().unwrap();
    let mut run = Run::start(root.path(), &["radicle"]);
    run.allow_writes(&site());
    run.burst(&site());
    run.at(T0 + REFILL_MS - 1);
    assert_eq!(run.write(&site()), not_covered("rate_limited"));
    run.at(T0 + REFILL_MS);
    assert_eq!(run.write(&site()), covered(), "write 6");
    assert_eq!(run.write(&site()), not_covered("rate_limited"));
    // One each 30 s from then: the 50th at T0 + 45 × 30 s, all admitted, as
    // none of the refusals above counted.
    for k in 2..=45 {
        run.at(T0 + k * REFILL_MS);
        assert_eq!(run.write(&site()), covered(), "write {}", k + 4);
    }
    // An hour on the burst is full again, but 50 were counted within the
    // day: the 51st is asked, up to the last millisecond of the first's day.
    run.at(T0 + 3_600_000);
    assert_eq!(run.write(&site()), not_covered("rate_limited"));
    run.at(T0 + DAY_MS - 1);
    assert_eq!(run.write(&site()), not_covered("rate_limited"));
    // At exactly 24 hours the first five stop counting.
    run.at(T0 + DAY_MS);
    assert_eq!(run.write(&site()), covered(), "write 51");
}

/// The core's own grant decides: connected, with the signing grant and its
/// rule, outside custody. A file another process renames into place after
/// the move isn't read. No refusal counts.
#[test]
fn the_core_s_own_grant_decides() {
    let root = tempfile::tempdir().unwrap();
    let mut run = Run::start(root.path(), &["radicle"]);
    assert_eq!(run.write(&site()), not_covered("no_rule"));
    // Main's word in a file is no grant once the file is the core's.
    let dir = run.grant_root();
    std::fs::write(dir.join("planted.json"), granted_file(SITE)).unwrap();
    std::fs::rename(
        dir.join("planted.json"),
        dir.join("radicle-permissions.json"),
    )
    .unwrap();
    assert_eq!(run.write(&site()), not_covered("no_rule"));
    run.grant(&site(), json!({ "op": "connect" }));
    assert_eq!(run.write(&site()), not_covered("no_rule"));
    // The rule alone, without the signing grant, answers nothing; nor the
    // signing grant without the rule.
    run.grant(&site(), json!({ "op": "flag", "flag": "signing" }));
    assert_eq!(run.write(&site()), not_covered("no_rule"));
    run.revoke(&site(), json!({ "flag": "signing" }));
    run.grant(&site(), json!({ "op": "signing" }));
    assert_eq!(run.write(&site()), not_covered("no_rule"));
    // The node's rule isn't the writes'.
    run.grant(&site(), json!({ "op": "flag", "flag": "node" }));
    assert_eq!(run.write(&site()), not_covered("no_rule"));
    run.grant(&site(), json!({ "op": "flag", "flag": "signing" }));
    // Never in custody, nor without `agent`.
    for agent in [Some(true), None] {
        assert_eq!(
            run.write(&page_as(SITE, agent)),
            not_covered("custody"),
            "{agent:?}"
        );
    }
    // None of the refusals counted: the whole burst is left.
    run.burst(&site());
}

/// Only a page, for its own key, and only once the file has moved: before
/// it main's limiter counts, and nothing in `grant_root` changes. A refused
/// call counts nothing, and each key has its own bucket.
#[test]
fn callers_keys_and_the_move() {
    let root = tempfile::tempdir().unwrap();
    let mut run = Run::start(root.path(), &[]);
    let dir = run.grant_root();
    std::fs::write(dir.join("radicle-permissions.json"), granted_file(SITE)).unwrap();
    let before = snapshot(&dir);
    for context in [site(), page_as(SITE, Some(true))] {
        let reply = run.ask(&context, SITE);
        refused(&reply, "not_moved");
        assert_eq!(reply["error"]["data"]["store"], "radicle", "{reply}");
    }
    assert_eq!(snapshot(&dir), before);
    drop(run);

    let root = tempfile::tempdir().unwrap();
    let mut run = Run::start(root.path(), &["radicle"]);
    run.allow_writes(&site());
    let other = page_as(OTHER, Some(false));
    run.allow_writes(&other);
    // Another page's key, and the chrome's and main's calls, are refused.
    refused(&run.ask(&site(), OTHER), "forbidden");
    refused(&run.ask(&other, SITE), "forbidden");
    for context in [chrome(), shell()] {
        refused(&run.ask(&context, SITE), "forbidden");
    }
    for params in [
        json!({}),
        json!({ "key": SITE, "store": "radicle" }),
        json!({ "key": 5 }),
        json!([SITE]),
    ] {
        refused(
            &run.call(&site(), "approval.radicle_write", params),
            "invalid_argument",
        );
    }
    // None of them counted, and the other page's bucket is its own.
    run.burst(&site());
    run.burst(&other);
}

/// A revoked grant forgets the key's bucket, whoever revokes it (the
/// page's own disconnect, the chrome, main), so the grant made again
/// starts full; so does a restart. Turning the rule off and on again
/// doesn't.
#[test]
fn a_revoke_forgets_the_bucket() {
    let root = tempfile::tempdir().unwrap();
    let mut run = Run::start(root.path(), &["radicle"]);
    run.allow_writes(&site());
    run.burst(&site());
    run.revoke(&site(), json!({ "flag": "signing" }));
    assert_eq!(run.write(&site()), not_covered("no_rule"));
    run.grant(&site(), json!({ "op": "flag", "flag": "signing" }));
    assert_eq!(run.write(&site()), not_covered("rate_limited"));
    for revoker in [site(), chrome(), shell()] {
        run.revoke(&revoker, json!("grant"));
        assert_eq!(run.write(&site()), not_covered("no_rule"), "{revoker}");
        run.allow_writes(&site());
        run.burst(&site());
    }
    // The buckets are in memory: a restart starts them full, the grant read
    // from the core's file.
    drop(run);
    let mut run = Run::start(root.path(), &["radicle"]);
    run.burst(&site());
}
