//! Design 0012's phone jobs through the real binary (PHN-1): a job only
//! from a checked authorization, for the `target` it names; the answer only
//! from that webContents, once, within the job's life; a signature that
//! recovers to the account over what was confirmed; a payment compared on
//! the job's chain at the answer, or recorded in `phone-payments.json` and
//! compared once it shows, across restarts; a failed save at each stage of
//! the write; and the bounds: the site key, the 256 slots, the file and its
//! records, and a record's day. The test plays main: it answers the core's
//! `shell.rpc` reads from a table of transactions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine as _;
use common::*;
use fc_approval::phone::{Fields, JobId, Payment, Record};
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const HANDLE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SITE: &str = "https://app.example";
const TO: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const OTHER: &str = "0x3333333333333333333333333333333333333333";
const TARGET: u64 = 42;
const ACCOUNT: u32 = 7;
const WALL: u64 = 1_700_000_000_000;
const DAY: u64 = 86_400_000;
const FILE: &str = "phone-payments.json";

fn key(index: u32) -> fc_keys::Secp256k1Key {
    let seed = fc_keys::Mnemonic::parse(ABANDON).unwrap().to_seed();
    fc_keys::freedom::derive_user_wallet(&seed, index).unwrap()
}

/// The phone account's address, lowercase.
fn address() -> String {
    fc_evm::to_hex(&fc_evm::address_of(key(ACCOUNT).signing_key()))
}

fn sign(index: u32, digest: &[u8; 32]) -> String {
    fc_evm::to_hex(&fc_evm::sign_digest(key(index).signing_key(), digest).unwrap())
}

fn page_as(origin: &str) -> Value {
    json!({ "caller": "page", "page": {
        "origin": origin, "top_origin": origin, "frame": 1, "navigation": 1, "agent": false,
    } })
}

fn site() -> Value {
    page_as(SITE)
}

fn chrome() -> Value {
    json!({ "caller": "chrome" })
}

fn shell() -> Value {
    json!({ "caller": "shell" })
}

fn tx_with(value: &str, data: &str) -> Value {
    json!({
        "type": 2, "chain_id": "100", "gas_limit": "60000", "to": TO,
        "value": value, "data": data,
        "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000000",
    })
}

fn tx() -> Value {
    tx_with("5", "0xabcd")
}

/// The transaction as the chain shows it.
fn seen(value: &str, data: &str) -> Value {
    json!({
        "from": address(), "to": TO, "value": value, "input": data, "chainId": "0x64",
        "nonce": "0x3", "gas": "0x5208",
    })
}

fn seen_tx() -> Value {
    seen("0x5", "0xabcd")
}

fn hash(n: u8) -> String {
    format!("0x{}", format!("{n:02x}").repeat(32))
}

/// The clock and hook files a core reads.
struct Hooks {
    wall: PathBuf,
    vault: PathBuf,
    fail: PathBuf,
}

impl Hooks {
    fn new(root: &Path) -> Self {
        let hooks = Hooks {
            wall: root.join("wall"),
            vault: root.join("vault"),
            fail: root.join("fail"),
        };
        hooks.set_wall(WALL);
        hooks.set_vault(1_000_000);
        hooks.fail("");
        hooks
    }

    fn set_wall(&self, ms: u64) {
        std::fs::write(&self.wall, ms.to_string()).unwrap();
    }

    fn set_vault(&self, ms: u64) {
        std::fs::write(&self.vault, ms.to_string()).unwrap();
    }

    fn fail(&self, spec: &str) {
        std::fs::write(&self.fail, spec).unwrap();
    }
}

/// One core, with main played: reads answered from `txs` (a hash missing
/// is a transaction not visible).
struct World {
    core: Core,
    root: PathBuf,
    hooks: Hooks,
    id: u64,
    txs: BTreeMap<String, Value>,
    /// The hashes the core read, in order.
    reads: Vec<String>,
    /// Reads held, unanswered, while `hold` is set.
    held: Vec<Value>,
    hold: bool,
    events: Vec<Value>,
    responses: BTreeMap<u64, Value>,
}

/// Chain 100: one RPC endpoint, read directly.
fn chain_snapshot() -> Value {
    json!({
        "chain_id": 100,
        "display_name": "Gnosis",
        "read_order": ["direct"],
        "broadcast_order": ["direct"],
        "quorum": { "k": 3, "m": 2, "timeout_ms": 5_000 },
        "rpc": [{ "endpoint": "https://rpc.example", "user_configured": false }],
        "prover": null,
        "myotis": false,
        "blockscout": null,
    })
}

impl World {
    fn start(root: &Path) -> World {
        let hooks = Hooks::new(root);
        World::spawn(root, hooks)
    }

    fn spawn(root: &Path, hooks: Hooks) -> World {
        World::spawn_moved(root, hooks, &[])
    }

    /// With `moved` in the hello's `grant_moved`.
    fn spawn_moved(root: &Path, hooks: Hooks, moved: &[&'static str]) -> World {
        let env = [
            (
                "FREEDOM_CORED_TEST_WALL_CLOCK",
                hooks.wall.to_str().unwrap(),
            ),
            (
                "FREEDOM_CORED_TEST_APPROVAL_CLOCK",
                hooks.vault.to_str().unwrap(),
            ),
            (
                "FREEDOM_CORED_TEST_GRANT_WRITE_FAIL",
                hooks.fail.to_str().unwrap(),
            ),
            ("FREEDOM_CORED_TEST_PHONE_RECHECK_MS", "50"),
            MAINS_WORD,
        ];
        let mut core = spawn_env(
            "serve",
            &root.join("identity"),
            &root.join("locks"),
            &[],
            &env,
        );
        core.grant_root = root.join("userData");
        core.grant_moved = moved.to_vec();
        std::fs::create_dir_all(&core.grant_root).unwrap();
        assert_eq!(core.hello()["result"]["protocol"], 2);
        let mut world = World {
            events: std::mem::take(&mut core.events),
            core,
            root: root.to_owned(),
            hooks,
            id: 100,
            txs: BTreeMap::new(),
            reads: Vec::new(),
            held: Vec::new(),
            hold: false,
            responses: BTreeMap::new(),
        };
        let configured = world.call(
            &shell(),
            "chain.configure",
            json!({ "chains": [chain_snapshot()] }),
        );
        assert!(configured["result"].is_object(), "{configured}");
        world
    }

    /// The same profile, started again (the old core killed): the table of
    /// transactions carries over.
    fn restart(self) -> World {
        self.restart_moved(&[])
    }

    /// As [`World::restart`], with `moved` in the hello's `grant_moved`.
    fn restart_moved(self, moved: &[&'static str]) -> World {
        let World {
            core,
            root,
            hooks,
            txs,
            ..
        } = self;
        drop(core);
        let mut world = World::spawn_moved(&root, hooks, moved);
        world.txs = txs;
        world
    }

    fn file(&self) -> PathBuf {
        self.core.grant_root.join(FILE)
    }

    fn send(&mut self, context: &Value, method: &str, params: Value) -> u64 {
        self.id += 1;
        self.core.send(&json!({
            "type": "request", "id": self.id, "method": method, "params": params,
            "context": context,
        }));
        self.id
    }

    fn call(&mut self, context: &Value, method: &str, params: Value) -> Value {
        let id = self.send(context, method, params);
        self.wait(|world| world.responses.contains_key(&id));
        self.responses.remove(&id).unwrap()
    }

    /// Plays main until `done`, at most 30 s.
    fn wait(&mut self, mut done: impl FnMut(&World) -> bool) {
        let until = Instant::now() + Duration::from_secs(30);
        while !done(self) {
            assert!(
                Instant::now() < until,
                "waited 30 s; events {:?}",
                self.events
            );
            self.step(Duration::from_millis(200));
        }
    }

    /// Plays main for `period`, whatever comes.
    fn idle(&mut self, period: Duration) {
        let until = Instant::now() + period;
        while Instant::now() < until {
            self.step(until.saturating_duration_since(Instant::now()));
        }
    }

    fn step(&mut self, within: Duration) {
        let Some(wire) = self.core.recv_wire_within(within) else {
            return;
        };
        let message = match wire {
            Wire::Message(message) => message,
            Wire::Credit => return,
            other => panic!("unexpected {other:?}"),
        };
        match message["type"].as_str() {
            Some("request") if message["method"] == "shell.rpc" => {
                if self.hold {
                    self.held.push(message);
                } else {
                    self.answer_read(&message, None);
                }
            }
            Some("event") => self.events.push(message),
            Some("response") => {
                self.responses
                    .insert(message["id"].as_u64().unwrap(), message);
            }
            _ => panic!("unexpected {message}"),
        }
    }

    /// Answers a held or live read: from the table, or `forced`.
    fn answer_read(&mut self, request: &Value, forced: Option<Value>) {
        let body: Value =
            serde_json::from_str(request["params"]["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["method"], "eth_getTransactionByHash", "{body}");
        let hash = body["params"][0].as_str().unwrap().to_owned();
        let tx = forced.unwrap_or_else(|| self.txs.get(&hash).cloned().unwrap_or(Value::Null));
        self.reads.push(hash);
        let text = json!({ "jsonrpc": "2.0", "id": body["id"], "result": tx }).to_string();
        self.core.send(&json!({
            "type": "response", "id": request["id"],
            "result": { "status": 200, "body": base64::engine::general_purpose::STANDARD.encode(text) },
        }));
    }

    /// Waits for the next event named `name`, and takes it.
    fn event(&mut self, name: &str) -> Value {
        self.wait(|world| world.events.iter().any(|e| e["event"] == name));
        let index = self.events.iter().position(|e| e["event"] == name).unwrap();
        self.events.remove(index)
    }

    fn checked(&mut self, job: &str) -> Value {
        self.wait(|world| {
            world
                .events
                .iter()
                .any(|e| e["event"] == "phone.checked" && e["data"]["job"] == job)
        });
        let index = self
            .events
            .iter()
            .position(|e| e["event"] == "phone.checked" && e["data"]["job"] == job)
            .unwrap();
        self.events.remove(index)["data"].clone()
    }

    /// How many times the core read `hash`.
    fn read_count(&self, hash: &str) -> usize {
        self.reads.iter().filter(|read| *read == hash).count()
    }

    /// Waits until the core has read `hash` `count` times in all.
    fn reads_of(&mut self, hash: &str, count: usize) {
        let hash = hash.to_owned();
        self.wait(|world| world.read_count(&hash) >= count);
    }

    fn token(&mut self, context: &Value, kind: &str, payload: Value, phone: bool) -> String {
        let mut params = json!({ "kind": kind, "account": ACCOUNT, "payload": payload });
        if context["caller"] == "page" {
            params["handle"] = HANDLE.into();
        }
        if phone {
            params["phone"] = true.into();
        }
        let issued = self.call(context, "approval.issue", params);
        issued["result"]["token"]
            .as_str()
            .unwrap_or_else(|| panic!("{issued}"))
            .to_owned()
    }

    fn job(
        &mut self,
        context: &Value,
        method: &str,
        payload: Value,
        authorization: Option<Value>,
    ) -> Value {
        let mut params = json!({
            "account": ACCOUNT, "address": address(), "method": method, "payload": payload,
            "target": TARGET,
        });
        if let Some(authorization) = authorization {
            params["authorization"] = authorization;
        }
        self.call(context, "phone.job", params)
    }

    /// A page's payment job, from its `dapp-send` token: the job's id.
    fn page_payment(&mut self, tx: Value) -> String {
        let token = self.token(&site(), "dapp-send", json!({ "tx": tx }), true);
        let opened = self.job(
            &site(),
            "transaction",
            json!({ "tx": tx }),
            Some(json!({ "token": token, "kind": "dapp-send", "handle": HANDLE })),
        );
        job_of(&opened)
    }

    /// Main's own payment job (`shell`, on main's word): the job's id.
    fn shell_payment(&mut self, tx: Value) -> String {
        let opened = self.job(&shell(), "transaction", json!({ "tx": tx }), None);
        job_of(&opened)
    }

    fn sent(&mut self, job: &str, sender: u64) -> Value {
        self.call(
            &chrome(),
            "phone.sent",
            json!({ "job": job, "sender": sender }),
        )
    }

    fn result(&mut self, job: &str, sender: u64, result: Value) -> Value {
        self.call(
            &chrome(),
            "phone.result",
            json!({ "job": job, "sender": sender, "result": result }),
        )
    }

    fn error(&mut self, job: &str, sender: u64, error: Value) -> Value {
        self.call(
            &chrome(),
            "phone.result",
            json!({ "job": job, "sender": sender, "error": error }),
        )
    }

    /// The records the file holds, by job.
    fn recorded(&self) -> Vec<String> {
        match std::fs::read(self.file()) {
            Ok(bytes) => fc_approval::phone::read_file(&bytes)
                .unwrap()
                .iter()
                .map(|record| record.job.text())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

fn job_of(opened: &Value) -> String {
    opened["result"]["job"]
        .as_str()
        .unwrap_or_else(|| panic!("{opened}"))
        .to_owned()
}

fn refused(reply: &Value, code: &str, reason: Option<&str>) {
    assert_eq!(reply["error"]["code"], code, "{reply}");
    if let Some(reason) = reason {
        assert_eq!(reply["error"]["data"]["reason"], reason, "{reply}");
    }
}

fn outcome(reply: &Value) -> &Value {
    assert!(reply["result"].is_object(), "{reply}");
    &reply["result"]["outcome"]
}

/// A job comes only from a checked authorization, as `sign.*` checks it:
/// none from a page or the chrome without one, nor with another document's
/// token, nor with one spent; main's own on its word. The job is for the
/// `target` main names, and its reply is the request to relay.
#[test]
fn a_job_comes_only_from_a_checked_authorization() {
    let root = tempfile::tempdir().unwrap();
    let mut world = World::start(root.path());
    let payload = json!({ "tx": tx() });
    for context in [site(), chrome()] {
        let refused_job = world.job(&context, "transaction", payload.clone(), None);
        refused(&refused_job, "not_authorized", Some("no_token"));
    }
    // Another document's token, and a token spent.
    let token = world.token(&site(), "dapp-send", payload.clone(), true);
    let authorization = json!({ "token": token, "kind": "dapp-send", "handle": HANDLE });
    let other = world.job(
        &page_as("https://other.example"),
        "transaction",
        payload.clone(),
        Some(authorization.clone()),
    );
    refused(&other, "not_authorized", None);
    let token = world.token(&site(), "dapp-send", payload.clone(), true);
    let authorization = json!({ "token": token, "kind": "dapp-send", "handle": HANDLE });
    // Another transaction than the token's.
    let changed = world.job(
        &site(),
        "transaction",
        json!({ "tx": tx_with("6", "0xabcd") }),
        Some(authorization.clone()),
    );
    refused(&changed, "not_authorized", Some("mismatch"));
    let token = world.token(&site(), "dapp-send", payload.clone(), true);
    let authorization = json!({ "token": token, "kind": "dapp-send", "handle": HANDLE });
    let opened = world.job(
        &site(),
        "transaction",
        payload.clone(),
        Some(authorization.clone()),
    );
    let job = job_of(&opened);
    assert_eq!(job.len(), 32);
    assert_eq!(opened["result"]["expires_in_ms"], 300_000);
    let checksummed = fc_evm::checksum_address(&fc_evm::address_of(key(ACCOUNT).signing_key()));
    assert_eq!(
        opened["result"]["request"],
        json!({ "method": "eth_sendTransaction", "params": [{
            "from": checksummed,
            "to": fc_evm::checksum_address(&fc_evm::parse_address(TO).unwrap()),
            "value": "0x5", "chainId": "0x64", "data": "0xabcd",
        }] })
    );
    let spent = world.job(&site(), "transaction", payload.clone(), Some(authorization));
    refused(&spent, "not_authorized", Some("unknown_token"));
    // The chrome's wallet-kind token, and main's own word.
    let wallet = world.token(&shell(), "wallet-send", payload.clone(), true);
    let chrome_job = world.job(
        &chrome(),
        "transaction",
        payload.clone(),
        Some(json!({ "token": wallet, "kind": "wallet-send" })),
    );
    refused(&chrome_job, "not_authorized", None);
    let main_job = world.job(&shell(), "transaction", payload.clone(), None);
    assert_eq!(job_of(&main_job).len(), 32);
    // A creation, which could never check, and a page without its context.
    let mut creation = tx();
    creation.as_object_mut().unwrap().remove("to");
    let refused_creation = world.job(&shell(), "transaction", json!({ "tx": creation }), None);
    refused(&refused_creation, "invalid_argument", None);
    let bare = world.job(
        &json!({ "caller": "page" }),
        "transaction",
        payload.clone(),
        None,
    );
    refused(&bare, "invalid_argument", None);
    // A standing rule answers only a page, and only with its grant.
    let standing = world.job(
        &site(),
        "transaction",
        payload,
        Some(json!({ "standing": {} })),
    );
    refused(&standing, "not_authorized", None);
}

/// `phone.sent` and `phone.result` only from the job's target: another
/// sender is refused and the job stays open for its own. A second answer,
/// one for another job, and one after the job's life are refused.
#[test]
fn only_the_target_marks_or_answers_a_job_once() {
    let root = tempfile::tempdir().unwrap();
    let mut world = World::start(root.path());
    let message = json!({ "message": "0x68656c6c6f" });
    let token = world.token(&site(), "sign-message", message.clone(), false);
    let job = job_of(&world.job(
        &site(),
        "message",
        message.clone(),
        Some(json!({ "token": token, "handle": HANDLE })),
    ));
    refused(
        &world.sent(&job, TARGET + 1),
        "not_authorized",
        Some("wrong_sender"),
    );
    let signature = sign(ACCOUNT, &fc_evm::eip191_digest(b"hello"));
    refused(
        &world.result(&job, TARGET + 1, signature.clone().into()),
        "not_authorized",
        Some("wrong_sender"),
    );
    assert_eq!(world.sent(&job, TARGET)["result"], json!({}));
    let answered = world.result(&job, TARGET, signature.clone().into());
    assert_eq!(answered["result"], json!({ "signature": signature }));
    refused(
        &world.result(&job, TARGET, signature.clone().into()),
        "not_authorized",
        Some("settled"),
    );
    refused(&world.sent(&job, TARGET), "not_authorized", Some("settled"));
    refused(
        &world.result(&"00".repeat(16), TARGET, signature.clone().into()),
        "not_authorized",
        Some("unknown_job"),
    );
    refused(
        &world.result("not-a-job", TARGET, signature.clone().into()),
        "invalid_argument",
        None,
    );
    // Both or neither of result and error.
    let token = world.token(&site(), "sign-message", message.clone(), false);
    let late = job_of(&world.job(
        &site(),
        "message",
        message,
        Some(json!({ "token": token, "handle": HANDLE })),
    ));
    let both = world.call(
        &chrome(),
        "phone.result",
        json!({ "job": late, "sender": TARGET, "result": signature, "error": {} }),
    );
    refused(&both, "invalid_argument", None);
    // After its life of five minutes on the vault's clock: refused. At a
    // millisecond before, still open.
    world.hooks.set_vault(1_000_000 + 299_999);
    assert_eq!(world.sent(&late, TARGET)["result"], json!({}));
    world.hooks.set_vault(1_000_000 + 300_000);
    let expired = world.result(&late, TARGET, signature.into());
    refused(&expired, "not_authorized", Some("expired"));
    // A signature's job may not have gone: no unknown outcome.
    assert!(
        expired["error"]["data"].get("outcome").is_none(),
        "{expired}"
    );
    // A payment marked sent, past its life: its outcome is unknown.
    let payment = world.shell_payment(tx());
    world.sent(&payment, TARGET);
    world.hooks.set_vault(1_000_000 + 600_000);
    let late_payment = world.result(&payment, TARGET, hash(1).into());
    refused(&late_payment, "not_authorized", Some("expired"));
    assert_eq!(late_payment["error"]["data"]["outcome"], "unknown");
    assert_eq!(world.read_count(&hash(1)), 0);
}

/// A signature must be 65 bytes and recover to the account over the bound
/// digest: the message's EIP-191 digest, or the confirmed EIP-712 hash,
/// which the relayed view hashes to.
#[test]
fn a_signature_recovers_to_the_account_over_what_was_confirmed() {
    let root = tempfile::tempdir().unwrap();
    let mut world = World::start(root.path());
    let message = json!({ "message": "0x68656c6c6f" });
    let message_job = |world: &mut World| {
        let token = world.token(&site(), "sign-message", message.clone(), false);
        let opened = world.job(
            &site(),
            "message",
            message.clone(),
            Some(json!({ "token": token, "handle": HANDLE })),
        );
        assert_eq!(
            opened["result"]["request"],
            json!({ "method": "personal_sign", "params": [
                "0x68656c6c6f",
                fc_evm::checksum_address(&fc_evm::address_of(key(ACCOUNT).signing_key())),
            ] })
        );
        job_of(&opened)
    };
    let digest = fc_evm::eip191_digest(b"hello");
    // Another account's signature, and malformed ones; each settles its job.
    let job = message_job(&mut world);
    refused(
        &world.result(&job, TARGET, sign(ACCOUNT + 1, &digest).into()),
        "not_authorized",
        Some("wrong_account"),
    );
    refused(
        &world.result(&job, TARGET, sign(ACCOUNT, &digest).into()),
        "not_authorized",
        Some("settled"),
    );
    let good = sign(ACCOUNT, &digest);
    let mut zero_v = good.clone();
    zero_v.replace_range(
        130..,
        &format!("{:02x}", u8::from_str_radix(&good[130..], 16).unwrap() - 27),
    );
    let mut bad_v = good.clone();
    bad_v.replace_range(130.., "1d");
    for bad in [
        json!(good[..130]),
        json!(format!("{good}00")),
        json!(good.replace("0x", "")),
        json!(bad_v),
        json!(null),
        json!(1),
    ] {
        let job = message_job(&mut world);
        refused(
            &world.result(&job, TARGET, bad),
            "not_authorized",
            Some("bad_response"),
        );
    }
    // `v` as 0 or 1, as ethers reads it.
    let job = message_job(&mut world);
    assert_eq!(
        world.result(&job, TARGET, zero_v.clone().into())["result"]["signature"],
        zero_v
    );
    // Typed data: the phone gets the core's view, which hashes to the
    // confirmed hash, and its signature is checked over that hash.
    let typed = json!({
        "domain": { "name": "Mail", "version": "1", "chainId": 100 },
        "types": { "Mail": [{ "name": "contents", "type": "string" }] },
        "message": { "contents": "hi", "unsigned": "dropped" },
    });
    let issued = world.call(
        &site(),
        "approval.issue",
        json!({ "kind": "sign-typed-data", "account": ACCOUNT, "handle": HANDLE,
                "payload": { "typed_data": typed } }),
    );
    let token = issued["result"]["token"].as_str().unwrap().to_owned();
    let confirmed = issued["result"]["hash"].as_str().unwrap().to_owned();
    let opened = world.job(
        &site(),
        "typed_data",
        json!({ "typed_data": typed, "expected_hash": confirmed }),
        Some(json!({ "token": token, "handle": HANDLE })),
    );
    assert_eq!(
        opened["result"]["request"]["method"],
        "eth_signTypedData_v4"
    );
    let relayed: Value =
        serde_json::from_str(opened["result"]["request"]["params"][1].as_str().unwrap()).unwrap();
    assert_eq!(relayed["primaryType"], "Mail");
    assert_eq!(relayed["message"], json!({ "contents": "hi" }));
    let mut types = relayed["types"].clone();
    types.as_object_mut().unwrap().remove("EIP712Domain");
    let rehashed =
        fc_evm::typed_data_hash(&relayed["domain"], &types, &relayed["message"]).unwrap();
    assert_eq!(fc_evm::to_hex(&rehashed), confirmed);
    let job = job_of(&opened);
    // A signature over other typed data recovers elsewhere.
    let other =
        fc_evm::typed_data_hash(&relayed["domain"], &types, &json!({ "contents": "other" }))
            .unwrap();
    refused(
        &world.result(&job, TARGET, sign(ACCOUNT, &other).into()),
        "not_authorized",
        Some("wrong_account"),
    );
    let issued = world.call(
        &site(),
        "approval.issue",
        json!({ "kind": "sign-typed-data", "account": ACCOUNT, "handle": HANDLE,
                "payload": { "typed_data": typed } }),
    );
    let token = issued["result"]["token"].as_str().unwrap().to_owned();
    let job = job_of(&world.job(
        &site(),
        "typed_data",
        json!({ "typed_data": typed, "expected_hash": confirmed }),
        Some(json!({ "token": token, "handle": HANDLE })),
    ));
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&fc_evm::parse_bytes(&confirmed, "hash").unwrap());
    let signature = sign(ACCOUNT, &digest);
    assert_eq!(
        world.result(&job, TARGET, signature.clone().into())["result"]["signature"],
        signature
    );
    // Another expected hash than the view's: no job.
    let mismatched = world.job(
        &shell(),
        "typed_data",
        json!({ "typed_data": typed, "expected_hash": hash(9) }),
        None,
    );
    refused(&mismatched, "invalid_argument", None);
}

/// A payment's hash read at the answer: visible and the same, verified;
/// visible with another sender, recipient, amount, data or chain, or with
/// no chain id, refused with the transaction's fields. No record either way.
#[test]
fn a_payment_visible_at_the_answer_is_compared() {
    let root = tempfile::tempdir().unwrap();
    let mut world = World::start(root.path());
    world.txs.insert(hash(1), seen_tx());
    let job = world.page_payment(tx());
    world.sent(&job, TARGET);
    let verified = world.result(&job, TARGET, hash(1).into());
    assert_eq!(
        verified["result"],
        json!({ "outcome": "verified", "hash": hash(1) })
    );
    assert_eq!(world.read_count(&hash(1)), 1);
    let mut cases: Vec<(Value, &str)> = Vec::new();
    let mut other_from = seen_tx();
    other_from["from"] = OTHER.into();
    cases.push((other_from, "wrong_account"));
    for (field, value) in [
        ("to", json!(OTHER)),
        ("value", json!("0x6")),
        ("input", json!("0xabce")),
        ("input", json!("0xabcd00")),
        ("chainId", json!("0x1")),
        ("chainId", Value::Null),
    ] {
        let mut changed = seen_tx();
        if value.is_null() {
            changed.as_object_mut().unwrap().remove(field);
        } else {
            changed[field] = value;
        }
        cases.push((changed, "wrong_transaction"));
    }
    for (n, (shown, reason)) in cases.into_iter().enumerate() {
        let n = 10 + n as u8;
        world.txs.insert(hash(n), shown.clone());
        let job = world.page_payment(tx());
        let refused_answer = world.result(&job, TARGET, hash(n).into());
        refused(&refused_answer, "not_authorized", Some(reason));
        let fields = &refused_answer["error"]["data"]["transaction"];
        assert_eq!(
            fields["value"],
            if shown["value"] == "0x6" { "6" } else { "5" }
        );
        refused(
            &world.result(&job, TARGET, hash(n).into()),
            "not_authorized",
            Some("settled"),
        );
    }
    assert!(world.recorded().is_empty());
    // An answer that isn't a hash leaves the payment unknown.
    let job = world.page_payment(tx());
    let unreadable = world.result(&job, TARGET, json!("sent!"));
    assert_eq!(unreadable["result"], json!({ "outcome": "unknown" }));
}

/// Not visible at the answer: `unverified`, and recorded; it becomes
/// `verified` once it shows the same, `mismatch` (never `verified`) once it
/// shows otherwise, and the same with a restart between the answer and the
/// transaction appearing, `data` compared by its length and SHA-256.
#[test]
fn an_unseen_payment_is_unverified_until_it_shows() {
    let root = tempfile::tempdir().unwrap();
    let mut world = World::start(root.path());
    // A payment of large data: the record keeps its length and digest.
    let data = format!("0x{}", "ab".repeat(200 * 1024));
    let big = world.shell_payment(tx_with("5", &data));
    let same = world.page_payment(tx());
    let differs = world.page_payment(tx());
    for (job, n) in [(&big, 1), (&same, 2), (&differs, 3)] {
        world.sent(job, TARGET);
        let answer = world.result(job, TARGET, hash(n).into());
        assert_eq!(
            answer["result"],
            json!({ "outcome": "unverified", "hash": hash(n) })
        );
    }
    let text = std::fs::read_to_string(world.file()).unwrap();
    assert!(
        text.contains(&format!(r#""data_length":{}"#, 200 * 1024)),
        "{text}"
    );
    assert!(!text.contains("abababab"));
    assert!(text.contains(&format!(r#""site":"{SITE}""#)));
    assert_eq!(world.recorded().len(), 3);
    // What each record keeps: the job, the hash, the account, the bound
    // fields, the authorization's kind and site, and `answeredAt` on the
    // wall clock.
    let kept = fc_approval::phone::read_file(&std::fs::read(world.file()).unwrap()).unwrap();
    assert_eq!(kept[0].job.text(), big);
    assert_eq!(
        (kept[0].kind.as_str(), kept[0].site.as_deref()),
        ("none", None)
    );
    assert_eq!(kept[0].fields.data_length, 200 * 1024);
    let page = &kept[1];
    assert_eq!(page.job.text(), same);
    assert_eq!(fc_evm::to_hex(&page.hash), hash(2));
    assert_eq!(
        (page.kind.as_str(), page.site.as_deref()),
        ("dapp-send", Some(SITE))
    );
    assert_eq!((page.account, page.answered_at), (ACCOUNT, WALL));
    assert_eq!(page.fields.from, address());
    assert_eq!(page.fields.to, TO);
    assert_eq!(page.fields.value, "5");
    assert_eq!(page.fields.chain_id, "100");
    assert_eq!(page.fields.data_length, 2);
    // Rechecked: still not visible, nothing reported.
    world.reads_of(&hash(2), 3);
    assert!(world.events.is_empty(), "{:?}", world.events);
    world.txs.insert(hash(1), seen("0x5", &data));
    world.txs.insert(hash(2), seen_tx());
    let mut other = seen_tx();
    other["to"] = OTHER.into();
    world.txs.insert(hash(3), other);
    assert_eq!(
        world.checked(&big),
        json!({ "job": big, "outcome": "verified" })
    );
    assert_eq!(
        world.checked(&same),
        json!({ "job": same, "outcome": "verified" })
    );
    let mismatch = world.checked(&differs);
    assert_eq!(mismatch["outcome"], "mismatch");
    assert_eq!(mismatch["reason"], "wrong_transaction");
    assert_eq!(mismatch["transaction"]["to"], OTHER);
    world.wait(|world| world.recorded().is_empty());
    // Dropped: no more reads of them.
    let reads = world.reads.len();
    world.idle(Duration::from_millis(400));
    assert_eq!(world.reads.len(), reads);

    // With a restart between the answer and the transaction appearing:
    // the same, the data differing only in its last byte, and in its
    // length.
    let mut jobs = Vec::new();
    for n in 20..24u8 {
        let job = world.page_payment(tx());
        let answer = world.result(&job, TARGET, hash(n).into());
        assert_eq!(outcome(&answer), "unverified");
        jobs.push(job);
    }
    let mut world = world.restart();
    world.txs.insert(hash(20), seen_tx());
    world.txs.insert(hash(21), seen("0x5", "0xabce"));
    world.txs.insert(hash(22), seen("0x5", "0xabcd00"));
    world.txs.insert(hash(23), seen("0x6", "0xabcd"));
    assert_eq!(world.checked(&jobs[0])["outcome"], "verified");
    for job in &jobs[1..] {
        let checked = world.checked(job);
        assert_eq!(checked["outcome"], "mismatch", "{checked}");
    }
    world.wait(|world| world.recorded().is_empty());
    assert!(
        world.events.iter().all(|e| e["event"] != "phone.lost"),
        "{:?}",
        world.events
    );
}

/// Errors map as today: 4001, 4100 and 4200 fail as the phone's refusals,
/// before and after `phone.sent`; after it, any other error, a minted code
/// and main's timeout leave a payment unknown. A signature's errors fail.
#[test]
fn errors_and_timeouts_map_as_today() {
    let root = tempfile::tempdir().unwrap();
    let mut world = World::start(root.path());
    for sent in [false, true] {
        for (rpc, code) in [
            (4001, "REMOTE_USER_REJECTED"),
            (4100, "REMOTE_WRONG_ACCOUNT"),
            (4200, "REMOTE_UNSUPPORTED"),
        ] {
            let job = world.shell_payment(tx());
            if sent {
                world.sent(&job, TARGET);
            }
            let answer = world.error(&job, TARGET, json!({ "rpc_code": rpc, "message": "no" }));
            assert_eq!(outcome(&answer), "failed", "{answer}");
            assert_eq!(answer["result"]["code"], code);
            assert_eq!(
                answer["result"].get("message").is_some(),
                rpc != 4001,
                "{answer}"
            );
        }
    }
    for error in [
        json!({ "rpc_code": -32603, "message": "internal" }),
        json!({ "rpc_code": 4900 }),
        json!({ "code": "REMOTE_TIMEOUT" }),
        json!({ "code": "REMOTE_USER_CANCELLED" }),
        json!({}),
    ] {
        let job = world.shell_payment(tx());
        world.sent(&job, TARGET);
        let answer = world.error(&job, TARGET, error.clone());
        assert_eq!(answer["result"], json!({ "outcome": "unknown" }), "{error}");
        // Before `phone.sent`, the request never reached the phone.
        let job = world.shell_payment(tx());
        let answer = world.error(&job, TARGET, error.clone());
        assert_eq!(outcome(&answer), "failed", "{error}");
    }
    let job = world.shell_payment(tx());
    let answer = world.error(&job, TARGET, json!({ "code": "REMOTE_TIMEOUT" }));
    assert_eq!(
        answer["result"],
        json!({ "outcome": "failed", "code": "REMOTE_TIMEOUT" })
    );
    let job = world.shell_payment(tx());
    let answer = world.error(&job, TARGET, json!({ "code": "MADE_UP" }));
    assert_eq!(answer["result"]["code"], "REMOTE_UNKNOWN");
    // A malformed error changes nothing: the job is still open.
    let job = world.shell_payment(tx());
    refused(
        &world.error(&job, TARGET, json!({ "rpc_code": "4001" })),
        "invalid_argument",
        None,
    );
    refused(
        &world.error(&job, TARGET, json!({ "extra": 1 })),
        "invalid_argument",
        None,
    );
    assert_eq!(world.sent(&job, TARGET)["result"], json!({}));
    // A signature's job: its errors fail, sent or not.
    let message = json!({ "message": "0x68656c6c6f" });
    let opened = world.job(&shell(), "message", message, None);
    let job = job_of(&opened);
    world.sent(&job, TARGET);
    let answer = world.error(&job, TARGET, json!({ "code": "REMOTE_TIMEOUT" }));
    assert_eq!(
        answer["result"],
        json!({ "outcome": "failed", "code": "REMOTE_TIMEOUT" })
    );
    assert!(world.reads.is_empty());
}

/// A failed save, at each stage of the write: `unknown` with the hash and
/// `durable: false`; a second answer refused; the record kept in memory
/// and reported once its transaction shows; before the rename the file
/// unchanged and a restart with no record, after a failed flush the file
/// holding it; the next good write carrying it.
#[test]
fn a_failed_save_answers_unknown_and_keeps_the_record() {
    for stage in ["write", "fsync", "rename", "flush"] {
        let root = tempfile::tempdir().unwrap();
        let mut world = World::start(root.path());
        // One saved record before: the file's text to compare.
        let first = world.page_payment(tx());
        world.result(&first, TARGET, hash(1).into());
        let before = std::fs::read(world.file()).unwrap();
        world.hooks.fail(&format!("phone:{stage}"));
        let job = world.page_payment(tx());
        world.sent(&job, TARGET);
        let answer = world.result(&job, TARGET, hash(2).into());
        assert_eq!(
            answer["result"],
            json!({ "outcome": "unknown", "hash": hash(2), "durable": false }),
            "{stage}"
        );
        refused(
            &world.result(&job, TARGET, hash(2).into()),
            "not_authorized",
            Some("settled"),
        );
        if stage == "flush" {
            assert_eq!(
                world.recorded(),
                vec![first.clone(), job.clone()],
                "{stage}"
            );
        } else {
            assert_eq!(std::fs::read(world.file()).unwrap(), before, "{stage}");
        }
        // Checked as a saved one is.
        world.txs.insert(hash(2), seen_tx());
        assert_eq!(world.checked(&job)["outcome"], "verified", "{stage}");

        // Another, unsaved, then a good write that carries it.
        let carried = world.page_payment(tx());
        let answer = world.result(&carried, TARGET, hash(3).into());
        assert_eq!(answer["result"]["durable"], false);
        world.hooks.fail("");
        let next = world.page_payment(tx());
        let answer = world.result(&next, TARGET, hash(4).into());
        assert_eq!(outcome(&answer), "unverified");
        let recorded = world.recorded();
        assert!(
            recorded.contains(&carried) && recorded.contains(&next),
            "{stage}"
        );

        // Unsaved before the rename, then a restart: no record of it.
        world.hooks.fail(&format!("phone:{stage}"));
        let lost = world.page_payment(tx());
        let answer = world.result(&lost, TARGET, hash(5).into());
        assert_eq!(answer["result"]["durable"], false);
        world.hooks.fail("");
        let mut world = world.restart();
        world.reads_of(&hash(4), 2);
        if stage == "flush" {
            world.reads_of(&hash(5), 2);
        } else {
            world.idle(Duration::from_millis(300));
            assert_eq!(world.read_count(&hash(5)), 0, "{stage}");
        }
    }
}

/// A record whose drop isn't saved is found again after a restart, and
/// reported once more.
#[test]
fn a_failed_drop_is_found_again_after_a_restart() {
    let root = tempfile::tempdir().unwrap();
    let mut world = World::start(root.path());
    let job = world.page_payment(tx());
    assert_eq!(
        outcome(&world.result(&job, TARGET, hash(1).into())),
        "unverified"
    );
    world.hooks.fail("phone:rename");
    world.txs.insert(hash(1), seen_tx());
    assert_eq!(world.checked(&job)["outcome"], "verified");
    assert_eq!(world.recorded(), vec![job.clone()]);
    world.hooks.fail("");
    let mut world = world.restart();
    assert_eq!(world.checked(&job)["outcome"], "verified");
    world.wait(|world| world.recorded().is_empty());
}

/// A site key of 2,048 bytes as written, and one that reaches it through
/// escapes, recorded, saved and reloaded; one of 2,049 refused at
/// `phone.job`, with nothing to relay and the token burnt.
#[test]
fn a_site_key_is_bounded_as_written() {
    let root = tempfile::tempdir().unwrap();
    let mut world = World::start(root.path());
    let plain = format!("https://{}", "a".repeat(2_048 - 8));
    let escaped = format!("https://{}", "\"".repeat(1_020));
    assert_eq!(serde_json::to_string(&escaped).unwrap().len() - 2, 2_048);
    let mut jobs = Vec::new();
    for (n, origin) in [(1u8, &plain), (2, &escaped)] {
        let context = page_as(origin);
        let token = world.token(&context, "dapp-send", json!({ "tx": tx() }), true);
        let opened = world.job(
            &context,
            "transaction",
            json!({ "tx": tx() }),
            Some(json!({ "token": token, "kind": "dapp-send", "handle": HANDLE })),
        );
        let job = job_of(&opened);
        assert_eq!(
            outcome(&world.result(&job, TARGET, hash(n).into())),
            "unverified"
        );
        jobs.push(job);

        let long = format!("{origin}a");
        let context = page_as(&long);
        let token = world.token(&context, "dapp-send", json!({ "tx": tx() }), true);
        let authorization = json!({ "token": token, "kind": "dapp-send", "handle": HANDLE });
        let refused_job = world.job(
            &context,
            "transaction",
            json!({ "tx": tx() }),
            Some(authorization.clone()),
        );
        refused(&refused_job, "invalid_argument", None);
        assert!(refused_job["error"]["data"].get("job").is_none());
        // The token presented is burnt all the same.
        let spend = world.call(
            &context,
            "approval.spend",
            json!({ "token": authorization["token"], "kind": "dapp-send", "account": ACCOUNT,
                    "payload": { "tx": tx() }, "handle": HANDLE }),
        );
        refused(&spend, "not_authorized", Some("unknown_token"));
    }
    let bytes = std::fs::read(world.file()).unwrap();
    let records = fc_approval::phone::read_file(&bytes).unwrap();
    let sites: Vec<_> = records.iter().map(|r| r.site.clone().unwrap()).collect();
    assert_eq!(sites, vec![plain, escaped]);
    let mut world = world.restart();
    world.txs.insert(hash(1), seen_tx());
    world.txs.insert(hash(2), seen_tx());
    for job in &jobs {
        assert_eq!(world.checked(job)["outcome"], "verified");
    }
}

/// Records for a profile's file, answered at `answered_at`.
fn records(count: usize, answered_at: u64) -> Vec<Record> {
    let address: [u8; 20] = fc_evm::parse_address(&address()).unwrap();
    let payment = Payment {
        chain_id: 100,
        to: fc_evm::parse_address(TO).unwrap(),
        value: fc_evm::U256::from_u64(5),
        data: vec![0xab, 0xcd],
    };
    (0..count)
        .map(|n| {
            let mut job = [0u8; 16];
            job[..8].copy_from_slice(&(n as u64 + 1).to_be_bytes());
            let mut hash = [0x77u8; 32];
            hash[..8].copy_from_slice(&(n as u64 + 1).to_be_bytes());
            Record {
                job: JobId::parse(&fc_evm::to_hex(&job)[2..]).unwrap(),
                hash,
                account: ACCOUNT,
                fields: Fields::bound(&address, &payment),
                kind: "dapp-send".into(),
                site: Some(SITE.into()),
                answered_at,
            }
        })
        .collect()
}

fn write_records(root: &Path, records: &[Record]) {
    let dir = root.join("userData");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(FILE), fc_approval::phone::file_text(records)).unwrap();
}

/// The 256 slots, held by open payment jobs and records together: a 257th
/// payment job refused before anything is relayed, and one accepted once a
/// job ends without a record or a record is dropped.
#[test]
fn payments_share_256_slots() {
    let root = tempfile::tempdir().unwrap();
    let held = records(200, WALL);
    write_records(root.path(), &held);
    let mut world = World::start(root.path());
    let mut open = Vec::new();
    for _ in 0..56 {
        open.push(world.shell_payment(tx()));
    }
    let busy = world.job(&shell(), "transaction", json!({ "tx": tx() }), None);
    refused(&busy, "busy", None);
    // A page's job too, its authorization checked or not.
    let token = world.token(&site(), "dapp-send", json!({ "tx": tx() }), true);
    let authorization = json!({ "token": token, "kind": "dapp-send", "handle": HANDLE });
    let busy = world.job(
        &site(),
        "transaction",
        json!({ "tx": tx() }),
        Some(authorization),
    );
    refused(&busy, "busy", None);
    // A signature's job takes no payment slot.
    let message = world.job(&shell(), "message", json!({ "message": "0x00" }), None);
    assert_eq!(job_of(&message).len(), 32);
    // A job ends without a record: its slot is free.
    world.error(&open[0], TARGET, json!({ "rpc_code": 4001 }));
    let again = world.shell_payment(tx());
    refused(
        &world.job(&shell(), "transaction", json!({ "tx": tx() }), None),
        "busy",
        None,
    );
    // A transaction visible at the answer ends its job without a record.
    world.txs.insert(hash(1), seen_tx());
    assert_eq!(
        outcome(&world.result(&again, TARGET, hash(1).into())),
        "verified"
    );
    let another = world.shell_payment(tx());
    // An unverified answer keeps its slot as a record.
    assert_eq!(
        outcome(&world.result(&another, TARGET, hash(2).into())),
        "unverified"
    );
    refused(
        &world.job(&shell(), "transaction", json!({ "tx": tx() }), None),
        "busy",
        None,
    );
    // A record dropped frees one.
    let first = fc_evm::to_hex(&held[0].hash);
    world.txs.insert(first, seen("0x5", "0xabcd"));
    let dropped = held[0].job.text();
    assert_eq!(world.checked(&dropped)["outcome"], "verified");
    assert_eq!(world.shell_payment(tx()).len(), 32);
    refused(
        &world.job(&shell(), "transaction", json!({ "tx": tx() }), None),
        "busy",
        None,
    );
    // An expiry frees every open job's.
    world.hooks.set_vault(1_000_000 + 300_000);
    assert_eq!(world.shell_payment(tx()).len(), 32);
}

/// The file's bounds when read at a start: a file of exactly 1 MiB and a
/// record of exactly 4,000 bytes read; a byte more of either, a 257th
/// record, a symlink, a FIFO, a file that doesn't parse, or one another
/// user owns, is renamed aside and `phone.lost` sent.
#[test]
fn the_file_s_bounds_and_its_unreadable_forms() {
    let record = records(1, WALL);
    let one = String::from_utf8(fc_approval::phone::file_text(&record)).unwrap();
    // Padded with whitespace to a length.
    let padded = |len: usize| {
        let mut text = one.clone();
        let pad = len - text.len();
        text.insert_str(text.len() - 1, &" ".repeat(pad));
        text
    };
    // A record of a length, by a longer site than a job takes.
    let sized = |len: usize| {
        let mut long = record.clone();
        long[0].site = Some(String::new());
        let base = fc_approval::phone::record_len(&long[0]);
        long[0].site = Some("s".repeat(len - base));
        assert_eq!(fc_approval::phone::record_len(&long[0]), len);
        String::from_utf8(fc_approval::phone::file_text(&long)).unwrap()
    };
    let hash = fc_evm::to_hex(&record[0].hash);
    let readable = [padded(1_048_576), sized(4_000)];
    for text in readable {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("userData");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(FILE), &text).unwrap();
        let mut world = World::start(root.path());
        world.reads_of(&hash, 1);
        assert!(world.events.iter().all(|e| e["event"] != "phone.lost"));
        assert!(!dir.join(format!("{FILE}.unreadable")).exists());
    }
    let many = String::from_utf8(fc_approval::phone::file_text(&records(257, WALL))).unwrap();
    let unreadable: Vec<(&str, Option<String>)> = vec![
        ("long file", Some(padded(1_048_577))),
        ("long record", Some(sized(4_001))),
        ("257 records", Some(many)),
        ("torn", Some(one[..one.len() - 3].to_owned())),
        ("symlink", None),
        ("fifo", None),
    ];
    for (case, text) in unreadable {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("userData");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(FILE);
        match (case, text) {
            (_, Some(text)) => std::fs::write(&file, text).unwrap(),
            #[cfg(unix)]
            ("symlink", None) => {
                std::fs::write(dir.join("good"), &one).unwrap();
                std::os::unix::fs::symlink(dir.join("good"), &file).unwrap();
            }
            #[cfg(unix)]
            ("fifo", None) => {
                let status = std::process::Command::new("mkfifo")
                    .arg(&file)
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            _ => continue,
        }
        let mut world = World::start(root.path());
        world.event("phone.lost");
        assert!(!file.exists(), "{case}");
        let aside = dir.join(format!("{FILE}.unreadable"));
        assert!(aside.symlink_metadata().is_ok(), "{case}");
        world.idle(Duration::from_millis(200));
        assert_eq!(world.read_count(&hash), 0, "{case}");
        // The core starts with no records, and writes a good file.
        let job = world.shell_payment(tx());
        world.result(&job, TARGET, hash.clone().into());
        assert_eq!(world.recorded(), vec![job], "{case}");
    }
    // A file another user owns: refused before a byte is read. Only root
    // can give a file away.
    #[cfg(unix)]
    if rustix::process::getuid().is_root() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("userData");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(FILE);
        std::fs::write(&file, &one).unwrap();
        let status = std::process::Command::new("chown")
            .arg("65534")
            .arg(&file)
            .status()
            .unwrap();
        assert!(status.success());
        let mut world = World::start(root.path());
        world.event("phone.lost");
        assert!(dir.join(format!("{FILE}.unreadable")).exists());
        assert_eq!(world.read_count(&hash), 0);
    }
}

/// The age comes first: a record waits while `answeredAt ≤ now <
/// answeredAt + 24 h` on the wall clock, and ends `unknown` (never
/// `verified`, with its transaction visible) at its end or under a clock
/// set before it, at a recheck and at a start.
#[test]
fn a_record_waits_a_day_of_the_wall_clock() {
    // At a recheck: still waiting at 86,399,999 ms, ended at 86,400,000.
    for (last, end) in [(WALL + DAY - 1, WALL + DAY), (WALL, WALL - 1)] {
        let root = tempfile::tempdir().unwrap();
        let mut world = World::start(root.path());
        let job = world.page_payment(tx());
        assert_eq!(
            outcome(&world.result(&job, TARGET, hash(1).into())),
            "unverified"
        );
        world.hooks.set_wall(last);
        let reads = world.read_count(&hash(1));
        world.reads_of(&hash(1), reads + 2);
        assert!(world.events.is_empty(), "{:?}", world.events);
        // A read in flight when the clock moves answers "not visible";
        // after that, the transaction shows, and the age ends it first.
        world.hold = true;
        world.wait(|world| !world.held.is_empty());
        world.hooks.set_wall(end);
        world.txs.insert(hash(1), seen_tx());
        for held in std::mem::take(&mut world.held) {
            world.answer_read(&held, Some(Value::Null));
        }
        world.hold = false;
        assert_eq!(
            world.checked(&job),
            json!({ "job": job, "outcome": "unknown" })
        );
        world.wait(|world| world.recorded().is_empty());
        world.idle(Duration::from_millis(300));
        assert!(world.events.is_empty(), "{:?}", world.events);
    }
    // At a start: the same edges, before any read.
    for (wall, waits) in [
        (WALL + DAY - 1, true),
        (WALL + DAY, false),
        (WALL - 1, false),
    ] {
        let root = tempfile::tempdir().unwrap();
        let held = records(1, WALL);
        write_records(root.path(), &held);
        let hooks = Hooks::new(root.path());
        hooks.set_wall(wall);
        let mut world = World::spawn(root.path(), hooks);
        let hash = fc_evm::to_hex(&held[0].hash);
        world.txs.insert(hash.clone(), seen("0x5", "0xabcd"));
        let checked = world.checked(&held[0].job.text());
        if waits {
            assert_eq!(checked["outcome"], "verified");
        } else {
            assert_eq!(checked["outcome"], "unknown");
            assert_eq!(world.read_count(&hash), 0);
        }
    }
    // 256 records under a clock set back: all ended, and their slots free.
    let root = tempfile::tempdir().unwrap();
    let held = records(256, WALL);
    write_records(root.path(), &held);
    let mut world = World::start(root.path());
    refused(
        &world.job(&shell(), "transaction", json!({ "tx": tx() }), None),
        "busy",
        None,
    );
    world.hooks.set_wall(WALL - 1);
    world.wait(|world| {
        world
            .events
            .iter()
            .filter(|e| e["event"] == "phone.checked" && e["data"]["outcome"] == "unknown")
            .count()
            == 256
    });
    assert!(
        world
            .events
            .iter()
            .all(|e| e["data"]["outcome"] == "unknown")
    );
    world.wait(|world| world.recorded().is_empty());
    assert_eq!(world.shell_payment(tx()).len(), 32);
}

/// A start removes the file's leftover temp files, and rechecks its
/// records 16 at a time.
#[test]
fn a_start_removes_its_temp_files_and_rechecks_16_at_a_time() {
    let root = tempfile::tempdir().unwrap();
    write_records(root.path(), &records(40, WALL));
    let dir = root.path().join("userData");
    let temp = dir.join(format!(".{FILE}.123.4.tmp"));
    let other = dir.join(format!(".{FILE}.x.tmp"));
    std::fs::write(&temp, b"torn").unwrap();
    std::fs::write(&other, b"not ours").unwrap();
    let mut world = World::start(root.path());
    assert!(!temp.exists());
    assert!(other.exists());
    world.hold = true;
    world.wait(|world| world.held.len() >= 16);
    world.idle(Duration::from_millis(300));
    assert_eq!(world.held.len(), 16);
}

/// A site's standing rule answers a phone's send as a phone's: the fee
/// check, which the phone's own fee escapes, doesn't stop it.
#[test]
fn a_standing_rule_judges_a_phone_s_send_as_a_phone_s() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("userData");
    std::fs::create_dir_all(&dir).unwrap();
    let grant = json!({ SITE: {
        "origin": SITE, "connectedAt": 1_762_000_000_000_u64, "lastUsed": 1_762_000_000_000_u64,
        "walletIndex": ACCOUNT, "chainId": 100,
        "autoApprove": { "signing": true, "transactions": [
            { "to": TO, "selector": "0x095ea7b3", "chainId": 100, "maxValue": "5" },
        ] },
    } });
    std::fs::write(dir.join("dapp-permissions.json"), grant.to_string()).unwrap();
    let mut world = World::start(root.path());
    let approve = format!("0x095ea7b3{}", "00".repeat(32));
    let opened = world.job(
        &site(),
        "transaction",
        json!({ "tx": tx_with("5", &approve) }),
        Some(json!({ "standing": { "paused": false } })),
    );
    assert_eq!(job_of(&opened).len(), 32);
    // Paused, the rule answers nothing.
    let paused = world.job(
        &site(),
        "transaction",
        json!({ "tx": tx_with("5", &approve) }),
        Some(json!({ "standing": { "paused": true } })),
    );
    refused(&paused, "not_authorized", Some("paused"));
}

/// Room first: a job refused as busy spends none of the standing rule's
/// rate (R-6's burst of 5), so once there is room the next job is still
/// within it.
#[test]
fn a_busy_job_spends_none_of_the_rule_s_rate() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("userData");
    std::fs::create_dir_all(&dir).unwrap();
    let granted = WALL - 600_000;
    let grant = json!({ SITE: {
        "origin": SITE, "connectedAt": granted, "lastUsed": granted,
        "walletIndex": ACCOUNT, "chainId": 100,
        "autoApprove": {
            "signing": false, "transactions": [],
            "limited": { "signing": { "grantedAt": granted }, "transactions": [] },
        },
    } });
    std::fs::write(dir.join("dapp-permissions.json"), grant.to_string()).unwrap();
    let hooks = Hooks::new(root.path());
    let mut world = World::spawn_moved(root.path(), hooks, &["dapp"]);
    let message = || json!({ "message": "0x68656c6c6f" });
    let standing = || Some(json!({ "standing": { "paused": false } }));
    // 64 signature jobs: no room for another.
    let held: Vec<String> = (0..64)
        .map(|_| job_of(&world.job(&shell(), "message", message(), None)))
        .collect();
    for _ in 0..5 {
        refused(
            &world.job(&site(), "message", message(), standing()),
            "busy",
            None,
        );
    }
    // Room again: the rule still answers, its burst unspent.
    world.error(&held[0], TARGET, json!({ "rpc_code": 4001 }));
    let opened = world.job(&site(), "message", message(), standing());
    assert_eq!(job_of(&opened).len(), 32, "{opened}");
}

/// A flagged `dapp-send`'s "Always allow" (design 0012, "A phone
/// payment's rule"): a page whose dApp file has moved, connected to the
/// account, and the calls' rules it holds.
struct Flagged {
    world: World,
    selectors: u32,
}

impl Flagged {
    fn start(root: &Path) -> Flagged {
        let hooks = Hooks::new(root);
        let mut flagged = Flagged {
            world: World::spawn_moved(root, hooks, &["dapp"]),
            selectors: 0,
        };
        flagged.connect();
        flagged
    }

    fn connect(&mut self) {
        let connected = self.world.call(
            &site(),
            "approval.grant",
            json!({ "store": "dapp", "change": { "op": "connect", "account": ACCOUNT, "chain_id": 100 } }),
        );
        assert!(connected["result"].is_object(), "{connected}");
    }

    fn restart(self) -> Flagged {
        Flagged {
            world: self.world.restart_moved(&["dapp"]),
            selectors: self.selectors,
        }
    }

    /// A new call (its own selector), confirmed with "Always allow" and
    /// sent to the phone: the job, and the call's data.
    fn job(&mut self) -> (String, String) {
        self.selectors += 1;
        let data = format!("0x{:08x}{}", 0x1000_0000 + self.selectors, "00".repeat(32));
        (self.job_for(&data), data)
    }

    /// The call `data`, confirmed with "Always allow" and sent to the
    /// phone: the job.
    fn job_for(&mut self, data: &str) -> String {
        let tx = tx_with("5", data);
        let token = self.world.token(
            &site(),
            "dapp-send",
            json!({ "tx": tx, "remember": true }),
            true,
        );
        let opened = self.world.job(
            &site(),
            "transaction",
            json!({ "tx": tx }),
            Some(json!({ "token": token, "kind": "dapp-send", "handle": HANDLE })),
        );
        job_of(&opened)
    }

    /// The page's grant moved to `account`.
    fn switch(&mut self, account: u32) {
        let switched = self.world.call(
            &site(),
            "approval.grant",
            json!({ "store": "dapp", "change": { "op": "account", "account": account } }),
        );
        assert!(switched["result"].is_object(), "{switched}");
    }

    /// A dApp revoke for the page, from `context`: its reply.
    fn revoke(&mut self, context: &Value, what: Value) -> Value {
        self.world.call(
            context,
            "approval.revoke",
            json!({ "store": "dapp", "key": SITE, "what": what }),
        )
    }

    fn forget_account(&mut self, account: u32) -> Value {
        self.world.call(
            &shell(),
            "approval.forget_account",
            json!({ "wallet_index": account }),
        )
    }

    fn dapp_file(&self) -> String {
        std::fs::read_to_string(self.world.core.grant_root.join("dapp-permissions.json")).unwrap()
    }

    /// The page's `connectedAt`, as the dApp file holds it.
    fn connected_at(&self) -> Value {
        serde_json::from_str::<Value>(&self.dapp_file()).unwrap()[SITE]["connectedAt"].clone()
    }

    /// The payment `job` (the call `data`, sent as `hash`) shows, and
    /// matches: verified, and no rule written.
    fn verified_without_rule(&mut self, job: &str, hash: &str, data: &str, case: &str) {
        self.world.txs.insert(hash.to_owned(), seen("0x5", data));
        let checked = self.world.checked(job);
        assert_eq!(checked["outcome"], "verified", "{case}: {checked}");
        assert!(checked.get("rule").is_none(), "{case}: {checked}");
        assert!(!self.has_rule(data), "{case}");
    }

    /// An open flagged payment answered with `hash`, not visible yet.
    fn unverified(&mut self, job: &str, hash: &str) {
        let answer = self.world.result(job, TARGET, hash.into());
        assert_eq!(answer["result"]["outcome"], "unverified", "{answer}");
    }

    /// Whether the dApp file holds the rule for the call `data` begins.
    fn has_rule(&self, data: &str) -> bool {
        self.dapp_file().contains(&data[..10])
    }
}

/// The rule waits for the transaction, in memory (design 0012, "A phone
/// payment's rule"): never written on the hash alone, written once when the
/// payment shows and matches, at the answer or later in the same run; never
/// on a swap, a mismatch, an `unknown` end, or after a restart, though the
/// payment still verifies. The phone's file never holds it.
#[test]
fn a_flagged_send_s_rule_waits_for_its_transaction() {
    let root = tempfile::tempdir().unwrap();
    let mut f = Flagged::start(root.path());
    // Swapped at the answer: refused, and no rule.
    let (job, data) = f.job();
    let mut swapped = seen("0x5", &data);
    swapped["to"] = OTHER.into();
    f.world.txs.insert(hash(1), swapped);
    refused(
        &f.world.result(&job, TARGET, hash(1).into()),
        "not_authorized",
        Some("wrong_transaction"),
    );
    assert!(!f.has_rule(&data));
    // Visible and the same at the answer: written.
    let (job, data) = f.job();
    f.world.txs.insert(hash(2), seen("0x5", &data));
    let answer = f.world.result(&job, TARGET, hash(2).into());
    assert_eq!(answer["result"]["outcome"], "verified");
    assert_eq!(
        answer["result"]["rule"],
        json!({ "added": true }),
        "{answer}"
    );
    assert!(f.has_rule(&data));
    // Not visible: unverified, and nothing written on the hash alone, nor
    // in the phone's file.
    let (later, later_data) = f.job();
    let answer = f.world.result(&later, TARGET, hash(3).into());
    assert_eq!(
        answer["result"],
        json!({ "outcome": "unverified", "hash": hash(3) })
    );
    assert!(!f.has_rule(&later_data));
    assert!(
        !std::fs::read_to_string(f.world.file())
            .unwrap()
            .contains("rule")
    );
    // Later another transaction: a mismatch, and no rule.
    let (other, other_data) = f.job();
    f.unverified(&other, &hash(4));
    f.world.txs.insert(hash(4), seen("0x6", &other_data));
    let checked = f.world.checked(&other);
    assert_eq!(checked["outcome"], "mismatch");
    assert!(checked.get("rule").is_none(), "{checked}");
    assert!(!f.has_rule(&other_data));
    // Later the same: verified, and the rule written then, once.
    f.world.txs.insert(hash(3), seen("0x5", &later_data));
    let checked = f.world.checked(&later);
    assert_eq!(checked["outcome"], "verified");
    assert_eq!(checked["rule"], json!({ "added": true }), "{checked}");
    assert_eq!(f.dapp_file().matches(&later_data[2..10]).count(), 1);
    // A restart between the answer and the transaction: the payment
    // verifies, and no rule is written.
    let (restarted, restarted_data) = f.job();
    f.unverified(&restarted, &hash(5));
    let mut f = f.restart();
    f.verified_without_rule(&restarted, &hash(5), &restarted_data, "restart");
    // A day passes with the transaction visible: unknown, and no rule.
    let (aged, aged_data) = f.job();
    f.unverified(&aged, &hash(7));
    f.world.hooks.set_wall(WALL + DAY);
    f.world.txs.insert(hash(7), seen("0x5", &aged_data));
    assert_eq!(f.world.checked(&aged)["outcome"], "unknown");
    assert!(!f.has_rule(&aged_data));
}

/// Every dApp revoke for the key forgets its waiting rules, whatever it
/// revokes, whoever asks and whatever its write does, and so does a deleted
/// account: the payment verifies later in the same run, and no rule is
/// written, a connect made again included.
#[test]
fn every_revoke_forgets_the_waiting_rule() {
    let root = tempfile::tempdir().unwrap();
    let mut f = Flagged::start(root.path());
    // A rule the site holds, for the exact rule's revoke.
    let (held, held_data) = f.job();
    f.world.txs.insert(hash(1), seen("0x5", &held_data));
    let answer = f.world.result(&held, TARGET, hash(1).into());
    assert_eq!(answer["result"]["rule"], json!({ "added": true }));
    let call = |selector: &str| json!({ "transaction": { "to": TO, "selector": selector, "chain_id": 100 } });
    let cases = [
        ("the exact rule", chrome(), call(&held_data[..10]), ""),
        ("another rule", chrome(), call("0xdeadbeef"), ""),
        ("signing", chrome(), json!("signing"), ""),
        ("the grant", chrome(), json!("grant"), ""),
        ("the page's own", site(), json!("grant"), ""),
        ("an unsaved revoke", chrome(), json!("grant"), "dapp:write"),
        ("a malformed revoke", chrome(), json!({ "flag": "x" }), ""),
    ];
    let mut n = 10;
    for (case, context, what, fail) in cases {
        n += 1;
        let (job, data) = f.job();
        f.unverified(&job, &hash(n));
        f.world.hooks.fail(fail);
        let revoked = f.revoke(&context, what);
        f.world.hooks.fail("");
        if case == "the exact rule" {
            assert!(revoked["result"].is_object(), "{revoked}");
            assert!(!f.has_rule(&held_data));
        }
        f.connect();
        f.verified_without_rule(&job, &hash(n), &data, case);
    }
    // Revoked between the job and its answer, the transaction visible then.
    for case in ["revoke", "forget_account"] {
        n += 1;
        let (job, data) = f.job();
        match case {
            "revoke" => f.revoke(&chrome(), json!("grant")),
            _ => f.forget_account(ACCOUNT),
        };
        f.connect();
        f.world.txs.insert(hash(n), seen("0x5", &data));
        let answer = f.world.result(&job, TARGET, hash(n).into());
        assert_eq!(answer["result"]["outcome"], "verified", "{case}");
        assert!(answer["result"].get("rule").is_none(), "{case}: {answer}");
        assert!(!f.has_rule(&data), "{case}");
    }
    // The account the rule names deleted, the page on another by then.
    n += 1;
    let (job, data) = f.job();
    f.unverified(&job, &hash(n));
    f.switch(ACCOUNT + 1);
    f.forget_account(ACCOUNT);
    f.switch(ACCOUNT);
    f.verified_without_rule(&job, &hash(n), &data, "its account");
    // Another account deleted, which ends the page's grant.
    n += 1;
    let (job, data) = f.job();
    f.unverified(&job, &hash(n));
    f.switch(ACCOUNT + 1);
    f.forget_account(ACCOUNT + 1);
    f.connect();
    f.verified_without_rule(&job, &hash(n), &data, "its grant's account");
    // A deleted account whose write fails.
    n += 1;
    let (job, data) = f.job();
    f.unverified(&job, &hash(n));
    f.world.hooks.fail("dapp:write");
    f.forget_account(ACCOUNT);
    f.world.hooks.fail("");
    f.connect();
    f.verified_without_rule(&job, &hash(n), &data, "an unsaved deletion");
}

/// Review round 3's three ways for an old decision to write under a revoke,
/// each writing nothing now: a revoke and a connect made again between the
/// job and its visible answer, with a grant at the largest safe
/// `connectedAt` in the file; the exact rule revoked, a failed phone write
/// and a restart; and a revoke or a deleted account, a failed phone write,
/// a restart, then a connect at the same millisecond.
#[test]
fn an_old_decision_never_writes_under_a_revoke() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("userData");
    std::fs::create_dir_all(&dir).unwrap();
    let far = 9_007_199_254_740_991_u64;
    let other = "https://other.example";
    let grant = json!({ other: {
        "origin": other, "connectedAt": far, "lastUsed": far,
        "walletIndex": ACCOUNT, "chainId": 100,
        "autoApprove": {
            "signing": false, "transactions": [],
            "limited": { "signing": { "grantedAt": far }, "transactions": [] },
        },
    } });
    std::fs::write(dir.join("dapp-permissions.json"), grant.to_string()).unwrap();
    let mut f = Flagged::start(root.path());
    // A connect writes the wall clock, as main does.
    assert_eq!(f.connected_at(), json!(WALL));
    let (job, data) = f.job();
    f.revoke(&chrome(), json!("grant"));
    f.connect();
    assert_eq!(f.connected_at(), json!(WALL));
    f.world.txs.insert(hash(1), seen("0x5", &data));
    let answer = f.world.result(&job, TARGET, hash(1).into());
    assert_eq!(answer["result"]["outcome"], "verified");
    assert!(answer["result"].get("rule").is_none(), "{answer}");
    assert!(!f.has_rule(&data));
    // The exact rule, written; another payment of the same call; a failed
    // phone write; the rule revoked; a restart.
    let (first, data) = f.job();
    f.world.txs.insert(hash(2), seen("0x5", &data));
    let answer = f.world.result(&first, TARGET, hash(2).into());
    assert_eq!(answer["result"]["rule"], json!({ "added": true }));
    let job = f.job_for(&data);
    f.unverified(&job, &hash(3));
    f.world.hooks.fail("phone:write");
    let call = json!({ "to": TO, "selector": &data[..10], "chain_id": 100 });
    let revoked = f.revoke(&chrome(), json!({ "transaction": call }));
    assert!(revoked["result"].is_object(), "{revoked}");
    f.world.hooks.fail("");
    assert!(!f.has_rule(&data));
    let mut f = f.restart();
    f.verified_without_rule(&job, &hash(3), &data, "the exact rule");
    // A revoke or a deleted account, a failed phone write, a restart before
    // the connect made again at the same millisecond.
    for (n, case) in [(4, "revoke"), (5, "forget_account")] {
        let (job, data) = f.job();
        f.unverified(&job, &hash(n));
        f.world.hooks.fail("phone:write");
        let narrowed = match case {
            "revoke" => f.revoke(&chrome(), json!("grant")),
            _ => f.forget_account(ACCOUNT),
        };
        assert!(narrowed["result"].is_object(), "{narrowed}");
        f.world.hooks.fail("");
        f = f.restart();
        f.connect();
        assert_eq!(f.connected_at(), json!(WALL));
        f.verified_without_rule(&job, &hash(n), &data, case);
    }
}

/// A failed save of the record, at each stage: `unknown`, no rule yet, and
/// the rule written once the transaction shows in the same run. A failed
/// drop writes it once: the restart that verifies the payment again writes
/// none.
#[test]
fn a_flagged_send_s_rule_waits_through_a_failed_save() {
    let root = tempfile::tempdir().unwrap();
    let mut f = Flagged::start(root.path());
    for (n, stage) in ["write", "fsync", "rename", "flush"]
        .into_iter()
        .enumerate()
    {
        let n = u8::try_from(n).unwrap() + 1;
        f.world.hooks.fail(&format!("phone:{stage}"));
        let (job, data) = f.job();
        let answer = f.world.result(&job, TARGET, hash(n).into());
        assert_eq!(
            answer["result"],
            json!({ "outcome": "unknown", "hash": hash(n), "durable": false }),
            "{stage}"
        );
        assert!(!f.has_rule(&data), "{stage}");
        f.world.hooks.fail("");
        f.world.txs.insert(hash(n), seen("0x5", &data));
        let checked = f.world.checked(&job);
        assert_eq!(
            checked["rule"],
            json!({ "added": true }),
            "{stage}: {checked}"
        );
        assert!(f.has_rule(&data), "{stage}");
    }
    // The drop unsaved: the rule written once, then revoked, and the record
    // found again after a restart writes it no more.
    let (job, data) = f.job();
    f.unverified(&job, &hash(9));
    f.world.hooks.fail("phone:write");
    f.world.txs.insert(hash(9), seen("0x5", &data));
    let checked = f.world.checked(&job);
    assert_eq!(checked["rule"], json!({ "added": true }), "{checked}");
    assert!(f.has_rule(&data));
    f.world.hooks.fail("");
    let call = json!({ "to": TO, "selector": &data[..10], "chain_id": 100 });
    f.revoke(&chrome(), json!({ "transaction": call }));
    assert!(!f.has_rule(&data));
    assert!(f.world.recorded().contains(&job));
    let mut f = f.restart();
    f.verified_without_rule(&job, &hash(9), &data, "found again");
}

/// APR-4d at `phone.job`, as at `sign.*`: under `shell`, a 32-byte message
/// job is refused `no_token`, where 31 and 33 bytes open; a job calling
/// `approveHash` or a module's `execTransactionFromModule`, to any address,
/// is refused without a token and opens with a `wallet-send` that binds
/// it. Under `page`, a matching rule answers none (`no_rule`), and its
/// `dapp-send` opens it. The selector counts only at the start of `data`.
#[test]
fn a_safe_route_needs_a_token_at_a_job() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("userData");
    std::fs::create_dir_all(&dir).unwrap();
    let selectors = ["0xd4d9bdcd", "0x468721a7", "0x5229073f"];
    let args = "55".repeat(32);
    let mut rules = Vec::new();
    for to in [TO, OTHER] {
        for selector in selectors {
            rules.push(json!({ "to": to, "selector": selector, "chainId": 100, "maxValue": "5" }));
        }
    }
    let grant = json!({ SITE: {
        "origin": SITE, "connectedAt": 1_762_000_000_000_u64, "lastUsed": 1_762_000_000_000_u64,
        "walletIndex": ACCOUNT, "chainId": 100,
        "autoApprove": { "signing": true, "transactions": rules },
    } });
    std::fs::write(dir.join("dapp-permissions.json"), grant.to_string()).unwrap();
    let mut world = World::start(root.path());
    let message = |len: usize| json!({ "message": format!("0x{}", "00".repeat(len)) });
    let refused_job = world.job(&shell(), "message", message(32), None);
    refused(&refused_job, "not_authorized", Some("no_token"));
    for len in [31, 33] {
        assert_eq!(
            job_of(&world.job(&shell(), "message", message(len), None)).len(),
            32
        );
    }
    let call = |to: &str, data: &str| {
        let mut tx = tx_with("0", data);
        tx["to"] = json!(to);
        json!({ "tx": tx })
    };
    for to in [TO, OTHER] {
        for selector in selectors {
            let payload = call(to, &format!("{selector}{args}"));
            let refused_job = world.job(&shell(), "transaction", payload.clone(), None);
            refused(&refused_job, "not_authorized", Some("no_token"));
            let wallet = world.token(&shell(), "wallet-send", payload.clone(), true);
            let opened = world.job(
                &shell(),
                "transaction",
                payload.clone(),
                Some(json!({ "token": wallet, "kind": "wallet-send" })),
            );
            assert_eq!(job_of(&opened).len(), 32);
            let ruled = world.job(
                &site(),
                "transaction",
                payload.clone(),
                Some(json!({ "standing": { "paused": false } })),
            );
            refused(&ruled, "not_authorized", Some("no_rule"));
            let dapp = world.token(&site(), "dapp-send", payload.clone(), true);
            let opened = world.job(
                &site(),
                "transaction",
                payload,
                Some(json!({ "token": dapp, "kind": "dapp-send", "handle": HANDLE })),
            );
            assert_eq!(job_of(&opened).len(), 32);
        }
        for data in [
            "0xd4d9bd".to_owned(),
            format!("0x00468721a7{args}"),
            format!("0x5229073e{args}"),
        ] {
            let opened = world.job(&shell(), "transaction", call(to, &data), None);
            assert_eq!(job_of(&opened).len(), 32);
        }
    }
}
