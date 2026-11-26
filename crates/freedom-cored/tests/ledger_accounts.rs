//! `ledger.accounts` and `ledger.add` over the wire (design 0016,
//! "Accounts"; LDG-2's L3), against a scripted main that answers each
//! `shell.ledger_apdu` from a scripted device: a `vectors/ledger.json`
//! case's recorded answers, in order.
//!
//! - **Every `ledger.accounts` and `ledger.add` vector:** the core's APDUs
//!   are the grammar's honest stream, each with `deadline_ms` (300000 only
//!   on `ledger.add`'s `E0 02 01 00`); its answer is the reference's, the
//!   deviations as 0016's table has them (`address-from-device`,
//!   `key-check`, `no-device`, `path-strict`, `check-bound`); and
//!   `vault-meta.json` after it holds what the reference's record calls
//!   kept, and the record `ledger.add` added.
//! - **D1's check:** `mismatched`; the 20-record bound; a failed check
//!   (main's refusal, its `{ failed }`, the core's write failing, a status
//!   or an unplug) leaves `mismatched` empty and discovery answered.
//! - **The lane:** discovery `LEDGER_BUSY` while an add waits for the user,
//!   or another discovery runs; a cancel during the user's wait.
//! - **D9:** before `vault_meta` is moved nothing is checked or written;
//!   a record whose path or address changed since the check read it isn't
//!   kept.
//! - **The params,** read strictly, refused before any APDU.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use common::*;
use fc_ledger::LedgerPath;
use serde_json::{Value, json};

const FILE: &str = "vault-meta.json";
const HOOK: &str = "FREEDOM_CORED_TEST_GRANT_WRITE_FAIL";

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn ledger() -> &'static Value {
    static FILE: OnceLock<Value> = OnceLock::new();
    FILE.get_or_init(|| load("ledger.json"))
}

fn grammar() -> &'static Value {
    static FILE: OnceLock<Value> = OnceLock::new();
    FILE.get_or_init(|| load("ledger-grammar.json"))
}

fn cases(operation: &str) -> Vec<&'static Value> {
    ledger()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["operation"] == operation)
        .collect()
}

fn case(id: &str) -> &'static Value {
    ledger()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()
}

fn marks(case: &Value) -> BTreeSet<String> {
    let mut marks: BTreeSet<String> = case["also"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| m.as_str().unwrap().to_owned())
        .collect();
    if let Some(deviation) = case["deviation"].as_str() {
        marks.insert(deviation.to_owned());
    }
    marks
}

fn honest(id: &str) -> Option<Vec<String>> {
    grammar()["honest"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["case"] == id)
        .map(|h| {
            h["apdus"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap().to_owned())
                .collect()
        })
}

fn refused(id: &str) -> bool {
    grammar()["refused"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["case"] == id)
}

/// The records discovery's check reads (D1): the case's `records` that
/// account-checks.js reads, each at a scheme's path, at most 20.
fn read_records(case: &Value) -> Vec<&Value> {
    case["records"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["path"].as_str().is_some_and(|p| !p.is_empty()) && r["address"].is_string())
        .filter(|r| LedgerPath::parse(r["path"].as_str().unwrap()).is_ok())
        .take(20)
        .collect()
}

/// A core over `root`'s identity directory, `vault_meta` moved or not,
/// with `meta` as its `vault-meta.json`.
fn start(root: &Path, meta: Option<&Value>, moved: bool, env: &[(&str, &str)]) -> Core {
    let identity = root.join("identity");
    std::fs::create_dir_all(&identity).unwrap();
    if let Some(meta) = meta {
        std::fs::write(
            identity.join(FILE),
            serde_json::to_string_pretty(meta).unwrap(),
        )
        .unwrap();
    }
    let mut core = spawn_env("serve", &identity, &root.join("locks"), &[], env);
    std::fs::create_dir_all(&core.grant_root).unwrap();
    core.store_moved = if moved {
        vec!["vault_meta"]
    } else {
        Vec::new()
    };
    let hello = core.hello();
    assert!(hello["result"].is_object(), "{hello}");
    core
}

fn meta_path(root: &Path) -> PathBuf {
    root.join("identity").join(FILE)
}

fn read_meta(root: &Path) -> Option<Value> {
    std::fs::read_to_string(meta_path(root))
        .ok()
        .map(|text| serde_json::from_str(&text).unwrap())
}

/// A wallet list with the main wallet alone.
fn bare_meta() -> Value {
    let main = case("add-live-0")["request"]["address"].clone();
    json!({ "addresses": { "userWallet": main }, "derivedWallets": [{ "index": 0, "name": "Main Wallet" }], "activeWalletIndex": 0 })
}

/// One `shell.ledger_apdu` the core sent.
#[derive(Debug, Clone)]
struct Asked {
    id: u64,
    parent: u64,
    apdu: String,
    deadline_ms: u64,
}

/// Main's reply to one.
enum Reply {
    Result(Value),
    Error(Value),
    /// Left unanswered: the drive stops there.
    Hold,
}

fn answer(hex: &str) -> Reply {
    Reply::Result(json!({ "answer": hex }))
}

/// The next message from the core, events set aside.
fn next(core: &mut Core) -> Value {
    loop {
        let message = core.recv();
        if message["type"] == "event" {
            core.events.push(message);
            continue;
        }
        return message;
    }
}

fn asked(message: &Value) -> Asked {
    assert_eq!(message["type"], "request", "{message}");
    assert_eq!(message["method"], "shell.ledger_apdu", "{message}");
    assert_eq!(message["context"]["caller"], "shell");
    let params = &message["params"];
    let keys: BTreeSet<&str> = params
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, BTreeSet::from(["for", "apdu", "deadline_ms"]));
    Asked {
        id: message["id"].as_u64().unwrap(),
        parent: params["for"].as_u64().unwrap(),
        apdu: params["apdu"].as_str().unwrap().to_owned(),
        deadline_ms: params["deadline_ms"].as_u64().unwrap(),
    }
}

fn reply(core: &mut Core, id: u64, reply: Reply) {
    match reply {
        Reply::Result(result) => {
            core.send(&json!({ "type": "response", "id": id, "result": result }))
        }
        Reply::Error(error) => core.send(&json!({ "type": "response", "id": id, "error": error })),
        Reply::Hold => {}
    }
}

/// Request `id` driven to its answer: each APDU it sends answered by
/// `main`, until its response (`Some`) or an APDU `main` holds (`None`).
fn drive(
    core: &mut Core,
    id: u64,
    mut main: impl FnMut(usize, &Asked) -> Reply,
) -> (Vec<Asked>, Option<Value>) {
    let mut sent = Vec::new();
    loop {
        let message = next(core);
        if message["type"] == "response" {
            assert_eq!(message["id"], id, "{message}");
            return (sent, Some(message));
        }
        let apdu = asked(&message);
        assert_eq!(apdu.parent, id);
        let answer = main(sent.len(), &apdu);
        sent.push(apdu.clone());
        if matches!(answer, Reply::Hold) {
            return (sent, None);
        }
        reply(core, apdu.id, answer);
    }
}

fn call(core: &mut Core, id: u64, method: &str, params: Value, caller: &str) {
    core.send(&json!({ "type": "request", "id": id, "method": method, "params": params, "context": { "caller": caller } }));
}

/// A case's device: its recorded answers, in order, each to the APDU the
/// reference sent there (the core's `ledger.add` asks with the display,
/// P1 `01`, where the reference's read had none); a device main can't
/// open, `{ failed: "not_found" }`.
fn device(case: &'static Value) -> impl FnMut(usize, &Asked) -> Reply {
    move |at, asked| {
        if case["device"].get("open").is_some() {
            return Reply::Result(json!({ "failed": "not_found" }));
        }
        let exchange = &case["exchanges"][at];
        let theirs = exchange["apdu"].as_str().unwrap();
        let display = asked.apdu.starts_with("e0020100") && theirs.starts_with("e0020000");
        if display {
            assert_eq!(asked.apdu[8..], theirs[8..], "{}: APDU {at}", case["id"]);
        } else {
            assert_eq!(asked.apdu, theirs, "{}: APDU {at}", case["id"]);
        }
        if exchange.get("thrown").is_some() {
            return Reply::Result(json!({ "failed": "disconnected" }));
        }
        answer(exchange["answer"].as_str().unwrap())
    }
}

fn error_code(response: &Value) -> &str {
    response["error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
}

fn ledger_code(response: &Value) -> &str {
    assert_eq!(error_code(response), "device_failed", "{response}");
    response["error"]["data"]["ledger"].as_str().unwrap()
}

/// The device's address in a recorded `E0 02` answer, checksummed.
fn answered_address(exchange: &Value) -> String {
    let answer = exchange["answer"].as_str().unwrap();
    let text = &answer[2 * 67..2 * 107];
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    let ascii = String::from_utf8(bytes).unwrap();
    let address = fc_evm::parse_address(&format!("0x{ascii}")).unwrap();
    fc_evm::checksum_address(&address)
}

/// What `vault-meta.json` holds after a discovery case: the case's file
/// with each record the core read and kept (the reference's record calls,
/// for the records the core reads) at its new state.
fn kept_meta(case: &Value) -> Value {
    let mut meta = case["meta"].clone();
    if case.get("core").is_some() {
        return meta;
    }
    let read: Vec<u64> = read_records(case)
        .iter()
        .map(|r| r["index"].as_u64().unwrap())
        .collect();
    for event in case["events"].as_array().into_iter().flatten() {
        let params = &event["core"]["params"];
        if event["core"]["method"] != "accounts.record_address_check" {
            continue;
        }
        let index = params["index"].as_u64().unwrap();
        if !read.contains(&index) {
            continue;
        }
        let state = if params["matched"] == true {
            "matched"
        } else {
            "mismatched"
        };
        for wallet in meta["derivedWallets"].as_array_mut().unwrap() {
            if wallet["index"] == index {
                wallet["addressCheck"] = json!(state);
            }
        }
    }
    meta
}

/// Every `ledger.accounts` vector: the APDUs, the answer and the file.
#[test]
fn every_discovery_vector() {
    let mut ran = 0;
    for case in cases("ledger.accounts") {
        let id = case["id"].as_str().unwrap();
        let marks = marks(case);
        let root = tempfile::tempdir().unwrap();
        let hook = root.path().join("hook");
        let mut env = Vec::new();
        let hook_env = hook.to_string_lossy().into_owned();
        if case.get("core").is_some() {
            std::fs::write(&hook, "vault_meta:write\n").unwrap();
            env.push((HOOK, hook_env.as_str()));
        }
        let meta = case.get("meta");
        let mut core = start(root.path(), meta, true, &env);
        call(
            &mut core,
            10,
            "ledger.accounts",
            case["request"].clone(),
            "chrome",
        );
        let (sent, response) = drive(&mut core, 10, device(case));
        let response = response.unwrap();
        ran += 1;
        if refused(id) {
            // path-strict: refused before any APDU.
            assert!(sent.is_empty(), "{id}");
            assert_eq!(error_code(&response), "invalid_argument", "{id}");
            continue;
        }
        let ours: Vec<String> = sent.iter().map(|a| a.apdu.clone()).collect();
        if let Some(stream) = honest(id) {
            assert_eq!(ours, stream, "{id}: the honest stream");
        }
        for apdu in &sent {
            assert_eq!(
                apdu.deadline_ms, 15_000,
                "{id}: display off, no confirmation"
            );
            assert!(apdu.apdu.starts_with("e0020000"), "{id}");
        }
        let result = &case["result"];
        if marks.contains("no-device") {
            assert_eq!(ledger_code(&response), "LEDGER_DEVICE_NOT_FOUND", "{id}");
        } else if marks.contains("key-check") {
            assert_eq!(ledger_code(&response), "LEDGER_UNKNOWN", "{id}");
        } else if result["status"] == "error" {
            assert_eq!(ledger_code(&response), result["code"], "{id}");
        } else {
            let answer = &response["result"];
            assert_eq!(answer["accounts"], result["accounts"], "{id}");
            let read: Vec<&Value> = read_records(case).iter().map(|r| &r["index"]).collect();
            let want: Vec<&Value> = if case.get("core").is_some() {
                Vec::new()
            } else {
                // The reference's, but for the records the core doesn't
                // read (check-bound, path-strict).
                result["mismatched"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|m| read.contains(&&m["index"]))
                    .collect()
            };
            let got: Vec<&Value> = answer["mismatched"].as_array().unwrap().iter().collect();
            assert_eq!(got, want, "{id}: mismatched");
            let keys: BTreeSet<&str> = answer
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(keys, BTreeSet::from(["accounts", "mismatched"]), "{id}");
        }
        // The file: what the reference's record calls kept, for the
        // records the core read; no file stays none.
        match meta {
            Some(_) => assert_eq!(read_meta(root.path()).unwrap(), kept_meta(case), "{id}"),
            None => assert!(read_meta(root.path()).is_none(), "{id}"),
        }
    }
    assert_eq!(ran, 63);
}

/// Every `ledger.add` vector: `E0 02 01 00` with the display, its
/// 5 minutes; the device's address answered and stored, never the
/// chrome's.
#[test]
fn every_add_vector() {
    let mut ran = 0;
    for case in cases("ledger.add") {
        let id = case["id"].as_str().unwrap();
        let marks = marks(case);
        let request = &case["request"];
        let Ok(path) = LedgerPath::parse(request["path"].as_str().unwrap()) else {
            // No `{ scheme, index }` names a path outside the schemes.
            assert!(refused(id) && marks.contains("path-strict"), "{id}");
            continue;
        };
        let root = tempfile::tempdir().unwrap();
        let mut core = start(root.path(), Some(&bare_meta()), true, &[]);
        let params = json!({
            "scheme": path.scheme().as_str(),
            "index": path.index(),
            "name": request["name"],
        });
        call(&mut core, 10, "ledger.add", params, "chrome");
        let (sent, response) = drive(&mut core, 10, device(case));
        let response = response.unwrap();
        ran += 1;
        assert_eq!(sent.len(), 1, "{id}");
        assert!(sent[0].apdu.starts_with("e0020100"), "{id}: the display on");
        assert_eq!(&sent[0].apdu[10..], hex(&path.encode()), "{id}");
        assert_eq!(sent[0].deadline_ms, 300_000, "{id}: the user confirms");
        let result = &case["result"];
        let mismatch = result["code"] == "LEDGER_ADDRESS_MISMATCH";
        if marks.contains("key-check") {
            assert_eq!(ledger_code(&response), "LEDGER_UNKNOWN", "{id}");
            assert_eq!(read_meta(root.path()).unwrap(), bare_meta(), "{id}");
            continue;
        }
        if result["status"] == "error" && !mismatch {
            assert_eq!(ledger_code(&response), result["code"], "{id}");
            assert_eq!(read_meta(root.path()).unwrap(), bare_meta(), "{id}");
            continue;
        }
        // address-from-device: the device's address at the path, whatever
        // the chrome would have sent.
        let address = answered_address(&case["exchanges"][0]);
        let name = request["name"].as_str().unwrap().trim();
        let wallet = json!({
            "index": 1_000_000,
            "name": if name.is_empty() { "Ledger 1" } else { name },
            "address": address,
            "type": "ledger",
            "path": path.to_string(),
            "addressCheck": "matched",
        });
        assert_eq!(
            response["result"],
            json!({ "path": path.to_string(), "address": address, "wallet": wallet }),
            "{id}"
        );
        let meta = read_meta(root.path()).unwrap();
        assert_eq!(meta["derivedWallets"][1], wallet, "{id}");
        assert_eq!(meta["nextHardwareWalletIndex"], 1_000_001, "{id}");
    }
    assert_eq!(ran, 16);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `discovery-records-mixed` world: its file, moved.
fn mixed(env: &[(&str, &str)]) -> (tempfile::TempDir, Core) {
    let root = tempfile::tempdir().unwrap();
    let core = start(
        root.path(),
        Some(&case("discovery-records-mixed")["meta"]),
        true,
        env,
    );
    (root, core)
}

/// `mismatched`: the records the device doesn't hold, and each result kept
/// on its record; a second discovery reads only the ones still unmatched.
#[test]
fn mismatched_and_the_results_kept() {
    let case = case("discovery-records-mixed");
    let (root, mut core) = mixed(&[]);
    call(
        &mut core,
        10,
        "ledger.accounts",
        case["request"].clone(),
        "shell",
    );
    let (sent, response) = drive(&mut core, 10, device(case));
    let response = response.unwrap();
    assert_eq!(sent.len(), 6);
    let names: Vec<&str> = response["result"]["mismatched"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Planted", "Still planted"]);
    let meta = read_meta(root.path()).unwrap();
    let state = |name: &str| {
        meta["derivedWallets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["name"] == name)
            .unwrap()["addressCheck"]
            .clone()
    };
    assert_eq!(state("Ledger 1"), "matched");
    assert_eq!(state("Planted"), "mismatched");
    assert_eq!(state("Checked"), "matched");
    assert_eq!(state("Back"), "matched");
    assert_eq!(state("Still planted"), "mismatched");
    assert_eq!(state("No path"), "unchecked");
    assert_eq!(state("Phone"), "unchecked");
    // Again: the two still mismatched are read, in the list's order.
    call(
        &mut core,
        11,
        "ledger.accounts",
        case["request"].clone(),
        "shell",
    );
    let replies = [
        &case["exchanges"][0],
        &case["exchanges"][1],
        &case["exchanges"][3],
        &case["exchanges"][5],
    ];
    let (sent, response) = drive(&mut core, 11, |at, asked| {
        assert_eq!(asked.apdu, replies[at]["apdu"]);
        answer(replies[at]["answer"].as_str().unwrap())
    });
    assert_eq!(sent.len(), 4);
    assert_eq!(
        response.unwrap()["result"]["mismatched"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

/// D1's bound: of 25 records no device has matched, the first 20 are read,
/// in the list's order, and only theirs come back.
#[test]
fn twenty_records_at_most() {
    for (id, read) in [
        ("discovery-records-20", 20),
        ("discovery-records-21", 20),
        ("discovery-records-25", 20),
    ] {
        let case = case(id);
        let root = tempfile::tempdir().unwrap();
        let mut core = start(root.path(), Some(&case["meta"]), true, &[]);
        call(
            &mut core,
            10,
            "ledger.accounts",
            case["request"].clone(),
            "chrome",
        );
        let (sent, response) = drive(&mut core, 10, device(case));
        assert_eq!(sent.len(), 2 + read, "{id}");
        let records = case["records"].as_array().unwrap();
        for (k, apdu) in sent[2..].iter().enumerate() {
            let path = LedgerPath::parse(records[k]["path"].as_str().unwrap()).unwrap();
            assert_eq!(apdu.apdu[10..], hex(&path.encode()), "{id}: record {k}");
        }
        let mismatched = response.unwrap()["result"]["mismatched"].clone();
        for m in mismatched.as_array().unwrap() {
            assert!(m["index"].as_u64().unwrap() < 1_000_020, "{id}: {m}");
        }
        assert_eq!(mismatched.as_array().unwrap().len(), 10, "{id}");
        // The 21st on keep their state.
        let meta = read_meta(root.path()).unwrap();
        for wallet in meta["derivedWallets"].as_array().unwrap() {
            if wallet["index"].as_u64().unwrap() >= 1_000_020 {
                assert!(wallet.get("addressCheck").is_none(), "{id}: {wallet}");
            }
        }
    }
}

/// A failed check leaves `mismatched` empty and discovery answered, and
/// keeps nothing: main's refusal of a check's APDU, its `{ failed }`, and
/// the core's write failing; a failure in discovery itself fails it.
#[test]
fn a_failed_check_leaves_mismatched_empty() {
    let case = case("discovery-records-mixed");
    let accounts = case["result"]["accounts"].clone();
    let refusal = json!({ "code": "invalid_argument", "message": "Invalid argument", "data": { "rule": "path" } });
    for (what, at, main) in [
        ("main's refusal", 2, Reply::Error(refusal.clone())),
        (
            "main's refusal of the last",
            5,
            Reply::Error(refusal.clone()),
        ),
        (
            "unresponsive",
            3,
            Reply::Result(json!({ "failed": "unresponsive" })),
        ),
        (
            "unplugged",
            4,
            Reply::Result(json!({ "failed": "disconnected" })),
        ),
        ("busy", 2, Reply::Result(json!({ "failed": "busy" }))),
    ] {
        let (root, mut core) = mixed(&[]);
        let before = std::fs::read(meta_path(root.path())).unwrap();
        call(
            &mut core,
            10,
            "ledger.accounts",
            case["request"].clone(),
            "chrome",
        );
        let mut recorded = device(case);
        let mut main = Some(main);
        let (sent, response) = drive(&mut core, 10, |k, asked| {
            if k == at {
                main.take().unwrap()
            } else {
                recorded(k, asked)
            }
        });
        let response = response.unwrap();
        assert_eq!(sent.len(), at + 1, "{what}: nothing after");
        assert_eq!(
            response["result"],
            json!({ "accounts": accounts, "mismatched": [] }),
            "{what}"
        );
        assert_eq!(
            std::fs::read(meta_path(root.path())).unwrap(),
            before,
            "{what}"
        );
    }
    // The write fails: nothing kept, mismatched empty.
    let root = tempfile::tempdir().unwrap();
    let hook = root.path().join("hook");
    std::fs::write(&hook, "vault_meta:rename\n").unwrap();
    let hook_env = hook.to_string_lossy().into_owned();
    let mut core = start(root.path(), Some(&case["meta"]), true, &[(HOOK, &hook_env)]);
    let before = std::fs::read(meta_path(root.path())).unwrap();
    call(
        &mut core,
        10,
        "ledger.accounts",
        case["request"].clone(),
        "chrome",
    );
    let (_, response) = drive(&mut core, 10, device(case));
    assert_eq!(
        response.unwrap()["result"],
        json!({ "accounts": accounts, "mismatched": [] })
    );
    assert_eq!(std::fs::read(meta_path(root.path())).unwrap(), before);
    // Discovery's own APDU refused: the operation fails, LEDGER_UNKNOWN.
    let (_root, mut core) = mixed(&[]);
    call(
        &mut core,
        10,
        "ledger.accounts",
        case["request"].clone(),
        "chrome",
    );
    let (sent, response) = drive(&mut core, 10, |_, _| Reply::Error(refusal.clone()));
    assert_eq!(sent.len(), 1);
    assert_eq!(ledger_code(&response.unwrap()), "LEDGER_UNKNOWN");
}

/// Discovery doesn't wait (deviation `discovery-busy`): while `ledger.add`
/// waits for the user, or another discovery runs, it is `LEDGER_BUSY` at
/// once, with no APDU; once the lane is free it runs.
#[test]
fn discovery_is_busy_while_the_device_is() {
    let add = case("add-live-0");
    let discovery = case("discovery-live-0-2");
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), Some(&bare_meta()), true, &[]);
    call(
        &mut core,
        10,
        "ledger.add",
        json!({ "scheme": "live", "index": 0 }),
        "chrome",
    );
    let (sent, response) = drive(&mut core, 10, |_, _| Reply::Hold);
    assert!(response.is_none());
    assert_eq!(sent[0].deadline_ms, 300_000);
    let held = sent[0].id;
    call(
        &mut core,
        11,
        "ledger.accounts",
        discovery["request"].clone(),
        "chrome",
    );
    let response = next(&mut core);
    assert_eq!(response["id"], 11, "{response}");
    assert_eq!(ledger_code(&response), "LEDGER_BUSY");
    // The user confirms: the add ends, and discovery runs again.
    reply(
        &mut core,
        held,
        answer(add["exchanges"][0]["answer"].as_str().unwrap()),
    );
    let response = next(&mut core);
    assert_eq!(response["id"], 10);
    assert!(response["result"]["wallet"].is_object(), "{response}");
    // A discovery while another runs.
    call(
        &mut core,
        12,
        "ledger.accounts",
        discovery["request"].clone(),
        "chrome",
    );
    let (sent, response) = drive(&mut core, 12, |_, _| Reply::Hold);
    assert!(response.is_none());
    call(
        &mut core,
        13,
        "ledger.accounts",
        discovery["request"].clone(),
        "chrome",
    );
    let response = next(&mut core);
    assert_eq!(response["id"], 13, "{response}");
    assert_eq!(ledger_code(&response), "LEDGER_BUSY");
    let mut recorded = device(discovery);
    reply(&mut core, sent[0].id, recorded(0, &sent[0]));
    let (rest, response) = drive(&mut core, 12, |at, asked| recorded(at + 1, asked));
    assert_eq!(rest.len(), 1);
    assert_eq!(
        response.unwrap()["result"]["accounts"],
        discovery["result"]["accounts"]
    );
}

/// D9: before `vault_meta` is moved the core keeps no Ledger record, so
/// discovery reads none (its own paths alone, `mismatched` empty) and
/// `ledger.add` answers `{ path, address }` for main to write; the file is
/// as main left it.
#[test]
fn before_the_move_nothing_is_checked_or_written() {
    let mixed = case("discovery-records-mixed");
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), Some(&mixed["meta"]), false, &[]);
    let before = std::fs::read(meta_path(root.path())).unwrap();
    call(
        &mut core,
        10,
        "ledger.accounts",
        mixed["request"].clone(),
        "chrome",
    );
    let (sent, response) = drive(&mut core, 10, device(mixed));
    assert_eq!(sent.len(), 2, "discovery's paths alone");
    assert_eq!(
        response.unwrap()["result"],
        json!({ "accounts": mixed["result"]["accounts"], "mismatched": [] })
    );
    let add = case("add-live-0");
    call(
        &mut core,
        11,
        "ledger.add",
        json!({ "scheme": "live", "index": 0, "name": "Ledger 1" }),
        "chrome",
    );
    let (sent, response) = drive(&mut core, 11, device(add));
    assert_eq!(sent[0].deadline_ms, 300_000);
    let address = answered_address(&add["exchanges"][0]);
    assert_eq!(
        response.unwrap()["result"],
        json!({ "path": "44'/60'/0'/0/0", "address": address })
    );
    assert_eq!(std::fs::read(meta_path(root.path())).unwrap(), before);
    // Main still writes it: accounts.add_ledger is main's, not_moved here.
    call(
        &mut core,
        12,
        "accounts.add_ledger",
        json!({ "name": "Ledger 1", "address": address, "path": "44'/60'/0'/0/0" }),
        "shell",
    );
    let response = next(&mut core);
    assert_eq!(error_code(&response), "not_moved", "{response}");
}

/// D9: a record whose path or address changed between the check's read
/// and its keeping, or that went, isn't kept or returned; the others are.
#[test]
fn a_record_changed_since_its_read_isnt_kept() {
    let case = case("discovery-records-mixed");
    let (root, mut core) = mixed(&[]);
    call(
        &mut core,
        10,
        "ledger.accounts",
        case["request"].clone(),
        "chrome",
    );
    let mut recorded = device(case);
    // Held at the check's first APDU while the file changes under it.
    let (sent, response) = drive(&mut core, 10, |at, asked| {
        if at == 2 {
            Reply::Hold
        } else {
            recorded(at, asked)
        }
    });
    assert!(response.is_none());
    let mut meta = read_meta(root.path()).unwrap();
    let wallets = meta["derivedWallets"].as_array_mut().unwrap();
    // "Ledger 1" at another path, "Planted" with another address, and
    // "Still planted" gone.
    wallets[1]["path"] = json!("44'/60'/7'/0/0");
    wallets[2]["address"] = json!("0x000000000000000000000000000000000000F0aa");
    wallets.retain(|w| w["name"] != "Still planted");
    std::fs::write(
        meta_path(root.path()),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .unwrap();
    let held = sent[2].clone();
    reply(&mut core, held.id, recorded(2, &held));
    let (_, response) = drive(&mut core, 10, |at, asked| recorded(at + 3, asked));
    let response = response.unwrap();
    // Only "Back" is kept (matched); none comes back mismatched.
    assert_eq!(response["result"]["mismatched"], json!([]));
    let after = read_meta(root.path()).unwrap();
    let mut want = meta.clone();
    for wallet in want["derivedWallets"].as_array_mut().unwrap() {
        if wallet["name"] == "Back" {
            wallet["addressCheck"] = json!("matched");
        }
    }
    assert_eq!(after, want);
}

/// The parent's cancel during the user's wait: `cancelled`, the APDU
/// cancelled at main, nothing written.
#[test]
fn an_add_cancelled_while_the_user_confirms() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), Some(&bare_meta()), true, &[]);
    call(
        &mut core,
        10,
        "ledger.add",
        json!({ "scheme": "legacy", "index": 3 }),
        "chrome",
    );
    let (sent, _) = drive(&mut core, 10, |_, _| Reply::Hold);
    core.send(&json!({ "type": "cancel", "id": 10 }));
    let mut seen = Vec::new();
    for _ in 0..2 {
        seen.push(next(&mut core));
    }
    let response = seen.iter().find(|m| m["type"] == "response").unwrap();
    assert_eq!(response["id"], 10);
    assert_eq!(error_code(response), "cancelled");
    let cancel = seen.iter().find(|m| m["type"] == "cancel").unwrap();
    assert_eq!(cancel["id"], sent[0].id);
    // Main's answer to the cancel; the core goes on.
    reply(
        &mut core,
        sent[0].id,
        Reply::Error(json!({ "code": "cancelled", "message": "Cancelled" })),
    );
    let status = {
        call(&mut core, 11, "accounts.list", json!({}), "chrome");
        next(&mut core)
    };
    assert_eq!(status["id"], 11);
    assert_eq!(read_meta(root.path()).unwrap(), bare_meta());
}

/// The params, read strictly: refused `invalid_argument` before any APDU;
/// a page never reaches either method.
#[test]
fn params_are_read_strictly() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), Some(&bare_meta()), true, &[]);
    let mut id = 10;
    for (method, params) in [
        ("ledger.accounts", json!({ "scheme": "live", "start": 0 })),
        (
            "ledger.accounts",
            json!({ "scheme": "live", "start": 0, "count": 2, "extra": 1 }),
        ),
        (
            "ledger.accounts",
            json!({ "scheme": "other", "start": 0, "count": 2 }),
        ),
        (
            "ledger.accounts",
            json!({ "scheme": "live", "start": 0, "count": 0 }),
        ),
        (
            "ledger.accounts",
            json!({ "scheme": "live", "start": 0, "count": 21 }),
        ),
        (
            "ledger.accounts",
            json!({ "scheme": "live", "start": -1, "count": 2 }),
        ),
        (
            "ledger.accounts",
            json!({ "scheme": "live", "start": 1.5, "count": 2 }),
        ),
        (
            "ledger.accounts",
            json!({ "scheme": "live", "start": "0", "count": 2 }),
        ),
        (
            "ledger.accounts",
            json!({ "scheme": "legacy", "start": 2_147_483_647u64, "count": 2 }),
        ),
        ("ledger.accounts", json!(["live", 0, 2])),
        ("ledger.add", json!({ "scheme": "live" })),
        (
            "ledger.add",
            json!({ "scheme": "live", "index": 2_147_483_648u64 }),
        ),
        (
            "ledger.add",
            json!({ "scheme": "live", "index": 0, "name": 7 }),
        ),
        (
            "ledger.add",
            json!({ "scheme": "live", "index": 0, "address": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94" }),
        ),
        (
            "ledger.add",
            json!({ "scheme": "live", "index": 0, "path": "44'/60'/0'/0/0" }),
        ),
    ] {
        id += 1;
        call(&mut core, id, method, params.clone(), "chrome");
        let response = next(&mut core);
        assert_eq!(response["type"], "response", "{method} {params}: no APDU");
        assert_eq!(
            error_code(&response),
            "invalid_argument",
            "{method} {params}"
        );
    }
    for method in ["ledger.accounts", "ledger.add"] {
        id += 1;
        core.send(&json!({ "type": "request", "id": id, "method": method, "params": { "scheme": "live", "start": 0, "count": 1, "index": 0 }, "context": { "caller": "page", "page": { "origin": "https://app.example", "top_origin": "https://app.example", "frame": 1, "navigation": 1 } } }));
        let response = next(&mut core);
        assert_eq!(error_code(&response), "forbidden", "{method}");
    }
}
