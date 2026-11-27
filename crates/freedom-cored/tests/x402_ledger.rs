//! x402 from a Ledger account over the wire (design 0016, "x402 from a
//! Ledger account", D2 and D10; LDG-2's L5), against a scripted main that
//! answers each `shell.ledger_apdu` from fc-ledger's scripted device, with
//! the core's wall clock and its nonce fixed at `vectors/ledger.json`'s
//! (`FREEDOM_CORED_TEST_WALL_CLOCK`, `FREEDOM_CORED_TEST_X402_NONCE`):
//!
//! - **`now_s`:** main's clock 30 s either side of the core's is taken, and
//!   31 s refused, before any token is spent or cap charged; only a Ledger
//!   account's payment takes it, and only once `vault_meta` is moved.
//! - **The three forms** (EIP-3009 versions 2 and 1, and Permit2): the
//!   typed data `x402.authorize` hands out is `ledger.json`'s, which
//!   `@x402/evm` 2.29.0 built under that clock and nonce, so main's rebuild
//!   equals it; `x402.settle { reservation, typed_data }` with it sends the
//!   grammar's honest stream for the case, `deadline_ms` 300000 only on the
//!   APDU the user confirms, and answers the payload with the case's
//!   signature in it.
//! - **Any other authorization** (each of `ledger-grammar.json`'s
//!   `x402_changes`, and a value that isn't typed data) is refused
//!   `mismatch` before any APDU, the reservation spent; a reservation made
//!   with `now_s` takes no `{ signature }`, and one made without takes no
//!   `{ typed_data }` (it still settles with its signature).
//! - **The charge is held, not written** (Codex's round 1 on #532): under
//!   a cap, `x402.authorize` writes nothing; open holds count against the
//!   cap in every check (another hold, a phone's written charge); a
//!   restart while the device signs leaves the cap file as it was and the
//!   whole cap there; a reservation dropped for room drops its hold.
//! - **Failure writes nothing:** another authorization, the device's
//!   refusal, a disconnect and a cancel during the user's wait each drop
//!   the hold, the cap file untouched, and spend the reservation, with
//!   `refunded` as it should be; a token's payment that fails writes no
//!   grant and charges nothing.
//! - **The charge before the signature:** a signed payment's charge is in
//!   the file when its payload arrives; with the write failing, its
//!   directory flush failing (the charge kept), or the cap revoked while
//!   the device signs, no signature leaves the core.
//! - **A failed reservation draw** (Codex's round 2 on #532): the ID drawn
//!   after the nonce failing holds nothing, however often it fails.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

/// fc-ledger's scripted device and its vector loaders, the same the
/// crate's own vector tests run.
#[path = "../../fc-ledger/tests/common/mod.rs"]
mod device;

use std::collections::BTreeSet;
use std::path::Path;

use common::*;
use device::{Device, Fault, Owned};
use fc_ledger::LedgerPath;
use serde_json::{Value, json};

/// The Ledger record of [`meta`]: abandon-12's key at `44'/60'/0'/0/0`,
/// the key `ledger.json`'s x402 cases sign with.
const LIVE: u32 = 1_000_000;
const LIVE_PATH: &str = "44'/60'/0'/0/0";
/// A phone's record.
const PHONE: u32 = 1_000_001;
const SELLER: &str = "https://paid.example";
const CONFIRM_MS: u64 = 300_000;
const APDU_MS: u64 = 15_000;

/// `ledger.json`'s x402 cases: the three forms, in its order.
const FORMS: [&str; 3] = ["x402-eip3009-v2", "x402-eip3009-v1", "x402-permit2-v2"];

// The world.

fn live_address() -> String {
    fc_evm::checksum_address(&device::account_at(LIVE_PATH).address)
}

/// `vault-meta.json`: the main wallet, the Ledger record and a phone's.
fn meta() -> Value {
    let live = live_address();
    json!({
        "addresses": { "userWallet": live },
        "derivedWallets": [
            { "index": 0, "name": "Main Wallet" },
            { "index": LIVE, "name": "Ledger", "address": live, "type": "ledger",
                "path": LIVE_PATH, "addressCheck": "matched" },
            { "index": PHONE, "name": "Phone",
                "address": "0x000000000000000000000000000000000000F002", "type": "remote" },
        ],
        "activeWalletIndex": 0,
        "nextHardwareWalletIndex": 1_000_002,
    })
}

/// The clock and nonce every x402 case of `ledger.json` was built under.
fn vector_now() -> u64 {
    let now = device::case(FORMS[0])["x402"]["now_s"].as_u64().unwrap();
    for form in FORMS {
        assert_eq!(device::case(form)["x402"]["now_s"], now, "{form}");
    }
    now
}

fn vector_nonce() -> String {
    let nonce = device::case(FORMS[0])["x402"]["nonce"]
        .as_str()
        .unwrap()
        .to_owned();
    for form in FORMS {
        assert_eq!(
            device::case(form)["x402"]["nonce"],
            nonce.as_str(),
            "{form}"
        );
    }
    nonce
}

/// A cap on the sellers' USDC on Base, `spent` of 1,000,000 spent.
fn cap(spent: &str) -> Value {
    cap_of("1000000", spent)
}

/// A cap on the sellers' USDC on Base, `spent` of `amount` spent.
fn cap_of(amount: &str, spent: &str) -> Value {
    let now = vector_now();
    json!({ SELLER: { "8453:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": {
        "capAmount": amount, "spentAmount": spent,
        "createdAt": now - 100, "expiresAt": now + 3600,
    } } })
}

/// A core over `root`, the wall clock and nonce the vectors', with
/// [`meta`] and `vault_meta` moved if `moved`, `x402` moved, and `caps` as
/// the cap file.
fn start_with(root: &Path, moved: bool, caps: Option<Value>) -> Core {
    start_env(root, moved, caps, &[])
}

/// [`start_with`], with more of the core's environment.
fn start_env(root: &Path, moved: bool, caps: Option<Value>, more: &[(&str, &str)]) -> Core {
    let identity = root.join("identity");
    std::fs::create_dir_all(&identity).unwrap();
    std::fs::write(
        identity.join("vault-meta.json"),
        serde_json::to_string_pretty(&meta()).unwrap(),
    )
    .unwrap();
    let clock = root.join("wall-clock");
    std::fs::write(&clock, (vector_now() * 1000).to_string()).unwrap();
    let nonce = vector_nonce();
    let mut env = vec![
        ("FREEDOM_CORED_TEST_WALL_CLOCK", clock.to_str().unwrap()),
        ("FREEDOM_CORED_TEST_X402_NONCE", nonce.as_str()),
    ];
    env.extend_from_slice(more);
    let mut core = spawn_env("serve", &identity, &root.join("locks"), &[], &env);
    std::fs::create_dir_all(&core.grant_root).unwrap();
    if let Some(caps) = caps {
        std::fs::write(
            core.grant_root.join("x402-permissions.json"),
            serde_json::to_string_pretty(&caps).unwrap(),
        )
        .unwrap();
    }
    core.grant_moved = vec!["x402"];
    core.store_moved = if moved {
        vec!["vault_meta"]
    } else {
        Vec::new()
    };
    let hello = core.hello();
    assert!(hello["result"].is_object(), "{hello}");
    core
}

fn start(root: &Path) -> Core {
    start_with(root, true, Some(cap("0")))
}

fn shell() -> Value {
    json!({ "caller": "shell" })
}

/// What the cap file says is spent.
fn spent(core: &Core) -> Value {
    let caps: Value = serde_json::from_str(&cap_file(core).unwrap()).unwrap();
    caps[SELLER]["8453:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"]["spentAmount"].clone()
}

/// The cap file's text, if there is one.
fn cap_file(core: &Core) -> Option<String> {
    std::fs::read_to_string(core.grant_root.join("x402-permissions.json")).ok()
}

// The wire, as `ledger_sign.rs` drives it.

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
    /// Left unanswered: the drive stops there.
    Hold,
}

fn wire(owned: Owned) -> Reply {
    match owned {
        Owned::Answer(bytes, shown) => {
            let mut result = json!({ "answer": device::hex(&bytes) });
            if shown {
                result["hash_only"] = json!("shown");
            }
            Reply::Result(result)
        }
        Owned::Failed(failed) => Reply::Result(json!({ "failed": failed.as_str() })),
        Owned::Refused => panic!("main refuses nothing here"),
    }
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

fn respond(core: &mut Core, id: u64, result: Value) {
    core.send(&json!({ "type": "response", "id": id, "result": result }));
}

/// Request `id` driven to its answer: each APDU it sends answered by
/// `main`, until its response (`Some`) or an APDU `main` holds (`None`).
fn drive(
    core: &mut Core,
    id: u64,
    mut main: impl FnMut(&Asked) -> Reply,
) -> (Vec<Asked>, Option<Value>) {
    let mut sent = Vec::new();
    loop {
        let message = next(core);
        if message["type"] == "response" {
            assert_eq!(message["id"], id, "{message}");
            return (sent, Some(message));
        }
        let apdu = asked(&message);
        assert_eq!(apdu.parent, id, "{message}");
        let answer = main(&apdu);
        sent.push(apdu.clone());
        match answer {
            Reply::Hold => return (sent, None),
            Reply::Result(result) => respond(core, apdu.id, result),
        }
    }
}

/// Main relaying to a scripted Ledger whose `E0 0C 00 01` signs `hash`.
struct Main {
    device: Device,
    at: usize,
}

impl Main {
    fn new(hash: &str) -> Self {
        let mut device = Device::default();
        device.typed_hash = Some(device::unhex(hash).try_into().unwrap());
        Main { device, at: 0 }
    }

    fn faulty(hash: &str, at: usize, fault: Fault) -> Self {
        let mut main = Main::new(hash);
        main.device.fault = Some((at, fault));
        main
    }

    fn answer(&mut self, asked: &Asked) -> Reply {
        let apdu = device::unhex(&asked.apdu);
        let owned = device::relay(self.at, &apdu, self.device.answer(&apdu));
        self.at += 1;
        wire(owned)
    }
}

// The requests.

fn detection() -> Value {
    json!({ "tab": 1, "id": "d1", "url": format!("{SELLER}/a") })
}

/// A case's x402 requirements, as main holds them: its one entry.
fn requirements(case: &Value) -> Value {
    let accept = case["x402"]["requirements"].clone();
    match case["x402"]["version"].as_u64().unwrap() {
        1 => json!({ "x402Version": 1, "accepts": [accept] }),
        _ => json!({
            "x402Version": 2, "resource": { "url": format!("{SELLER}/a") }, "accepts": [accept],
        }),
    }
}

fn call(core: &mut Core, id: &mut u64, method: &str, params: Value) -> Value {
    *id += 1;
    core.send(&json!({
        "type": "request", "id": *id, "method": method, "params": params, "context": shell(),
    }));
    let response = next(core);
    assert_eq!(
        response["id"], *id,
        "an APDU, or another response: {response}"
    );
    response
}

fn result(reply: &Value) -> &Value {
    assert!(reply["result"].is_object(), "{reply}");
    &reply["result"]
}

fn refused(reply: &Value, code: &str, reason: Option<&str>) {
    assert_eq!(reply["error"]["code"], code, "{reply}");
    if let Some(reason) = reason {
        assert_eq!(reply["error"]["data"]["reason"], reason, "{reply}");
    }
    assert!(reply.get("result").is_none(), "{reply}");
}

fn ledger_code(reply: &Value) -> &str {
    assert_eq!(reply["error"]["code"], "device_failed", "{reply}");
    reply["error"]["data"]["ledger"].as_str().unwrap()
}

/// An `x402-payment` token for the Ledger account and the case's entry.
fn token(core: &mut Core, id: &mut u64, case: &Value, grant: Option<&Value>) -> String {
    let mut payload = json!({
        "detection": detection(), "accept_index": 0, "accept": case["x402"]["requirements"],
    });
    if let Some(grant) = grant {
        payload["grant"] = grant.clone();
    }
    let reply = call(
        core,
        id,
        "approval.issue",
        json!({ "kind": "x402-payment", "account": LIVE, "payload": payload }),
    );
    result(&reply)["token"].as_str().unwrap().to_owned()
}

/// `x402.authorize` for the Ledger account and the case's entry, under
/// `authorization`, with `now_s` if given.
fn authorize(
    core: &mut Core,
    id: &mut u64,
    case: &Value,
    authorization: Value,
    now_s: Option<Value>,
) -> Value {
    let token = authorization.get("token").is_some();
    let mut params = json!({
        "account": LIVE, "device": { "kind": "ledger", "address": live_address() },
        "detection": detection(), "requirements": requirements(case),
        "authorization": authorization,
    });
    if token {
        params["accept_index"] = json!(0);
    }
    if let Some(now_s) = now_s {
        params["now_s"] = now_s;
    }
    call(core, id, "x402.authorize", params)
}

/// The case paid with a token (and the grant it binds), main's clock the
/// vectors': its reply.
fn pay_token(core: &mut Core, id: &mut u64, case: &Value, grant: Option<&Value>) -> Value {
    let token = token(core, id, case, grant);
    let mut params = json!({
        "account": LIVE, "device": { "kind": "ledger", "address": live_address() },
        "detection": detection(), "requirements": requirements(case),
        "accept_index": 0, "authorization": { "token": token }, "now_s": vector_now(),
    });
    if let Some(grant) = grant {
        params["grant"] = grant.clone();
    }
    call(core, id, "x402.authorize", params)
}

/// The case paid under the cap, main's clock `now_s`: its reply.
fn pay_cap(core: &mut Core, id: &mut u64, case: &Value, now_s: u64) -> Value {
    authorize(
        core,
        id,
        case,
        json!({ "cap": { "agent": false, "attributable": true } }),
        Some(json!(now_s)),
    )
}

/// The `{ device }` reply's reservation and typed data.
fn handed(reply: &Value) -> (String, Value) {
    let paid = result(reply);
    assert!(paid.get("payload").is_none(), "{paid}");
    (
        paid["reservation"].as_str().unwrap().to_owned(),
        paid["device"]["typed_data"].clone(),
    )
}

/// `x402.settle { reservation, typed_data }` sent as request `id + 1`.
fn settle_typed(core: &mut Core, id: &mut u64, reservation: &str, typed: &Value) -> u64 {
    *id += 1;
    core.send(&json!({
        "type": "request", "id": *id, "method": "x402.settle", "context": shell(),
        "params": { "reservation": reservation, "typed_data": typed },
    }));
    *id
}

/// A settle answered with no APDU sent: its response.
fn settle_unasked(core: &mut Core, id: &mut u64, reservation: &str, typed: &Value) -> Value {
    let parent = settle_typed(core, id, reservation, typed);
    let (sent, response) = drive(core, parent, |asked| {
        panic!("an APDU for a payment refused before the device: {asked:?}")
    });
    assert!(sent.is_empty());
    response.unwrap()
}

fn settle(core: &mut Core, id: &mut u64, reservation: &str, outcome: &str) -> Value {
    call(
        core,
        id,
        "x402.settle",
        json!({ "reservation": reservation, "outcome": outcome }),
    )
}

/// The grammar file's honest stream for case `id`.
fn honest(id: &str) -> Vec<String> {
    device::grammar()["honest"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["case"] == id)
        .unwrap()["apdus"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_owned())
        .collect()
}

/// The JSON text of a value, its members in their order.
fn text(value: &Value) -> String {
    serde_json::to_string(value).unwrap()
}

// The tests.

/// Each form, paid with a token on main's clock: the typed data handed out
/// is `ledger.json`'s, the stream the core sends for main's copy of it is
/// the grammar's honest one (one `deadline_ms` of 300000, on `E0 0C 00
/// 01`), and the payload carries the case's own signature. Then the
/// reservation waits for its outcome, once.
#[test]
fn the_three_forms_sign_on_the_lane() {
    let root = tempfile::tempdir().unwrap();
    // No cap: a token's payment charges one that covers it.
    let mut core = start_with(root.path(), true, None);
    let mut id = 10;
    for form in FORMS {
        let case = device::case(form);
        let reply = pay_token(&mut core, &mut id, case, None);
        assert_eq!(result(&reply)["charged"], false, "{form}");
        let (reservation, typed) = handed(&reply);
        let vector = &case["request"]["typed_data"];
        assert_eq!(text(&typed), text(vector), "{form}");
        let hash = case["request"]["expected_hash"].as_str().unwrap();
        assert_eq!(result(&reply)["device"]["hash"], hash, "{form}");
        // Main sends back its own copy: the 2.29.0 rebuild the case records.
        let parent = settle_typed(&mut core, &mut id, &reservation, vector);
        let mut main = Main::new(hash);
        let (sent, response) = drive(&mut core, parent, |asked| main.answer(asked));
        let streamed: Vec<String> = sent.iter().map(|a| a.apdu.clone()).collect();
        assert_eq!(streamed, honest(form), "{form}");
        for asked in &sent {
            let confirm = asked.apdu.starts_with("e00c0001");
            assert_eq!(
                asked.deadline_ms,
                if confirm { CONFIRM_MS } else { APDU_MS },
                "{form}: {}",
                asked.apdu
            );
        }
        let response = response.unwrap();
        let paid = result(&response);
        assert_eq!(paid["charged"], false, "{form}");
        assert!(paid.get("grant").is_none(), "{form}");
        let theirs: Value =
            serde_json::from_str(case["result"]["payload"].as_str().unwrap()).unwrap();
        if case["x402"]["version"] == 1 {
            assert_eq!(text(&paid["payload"]), text(&theirs), "{form}");
        } else {
            assert_eq!(paid["payload"]["x402Version"], 2, "{form}");
            assert_eq!(
                text(&paid["payload"]["payload"]),
                text(&theirs["payload"]),
                "{form}"
            );
            assert_eq!(
                paid["payload"]["accepted"], case["x402"]["requirements"],
                "{form}"
            );
        }
        // Signed: the reservation waits for its outcome, and is settled once.
        refused(
            &settle_unasked(&mut core, &mut id, &reservation, vector),
            "invalid_argument",
            None,
        );
        assert_eq!(
            result(&settle(&mut core, &mut id, &reservation, "sent"))["refunded"],
            false
        );
        refused(
            &settle(&mut core, &mut id, &reservation, "sent"),
            "invalid_argument",
            None,
        );
    }
}

/// Main's `now_s` is taken 30 s either side of the core's clock, every time
/// field built on it, and refused at 31 s, before the cap is charged or the
/// token spent. Only a Ledger account's payment takes it, in whole seconds,
/// and only once `vault_meta` is moved.
#[test]
fn now_s_at_30_s_is_taken_and_at_31_s_refused() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path());
    let mut id = 10;
    let now = vector_now();
    let v2 = device::case(FORMS[0]);
    let v1 = device::case(FORMS[1]);
    for at in [now - 30, now + 30, now] {
        for case in [v2, device::case(FORMS[2])] {
            let reply = pay_cap(&mut core, &mut id, case, at);
            assert_eq!(result(&reply)["charged"], true, "{at}");
            let (reservation, typed) = handed(&reply);
            let message = &typed["message"];
            let before = (at + 60).to_string();
            assert!(
                message["validBefore"] == before.as_str() || message["deadline"] == before.as_str(),
                "{at}: {typed}"
            );
            // Held, not written.
            assert_eq!(spent(&core), "0");
            assert_eq!(
                result(&settle(&mut core, &mut id, &reservation, "withheld"))["refunded"],
                true
            );
            assert_eq!(spent(&core), "0");
        }
        // Version 1's validAfter is ten minutes before main's clock.
        let token = token(&mut core, &mut id, v1, None);
        let reply = authorize(
            &mut core,
            &mut id,
            v1,
            json!({ "token": token }),
            Some(json!(at)),
        );
        let (_, typed) = handed(&reply);
        assert_eq!(typed["message"]["validAfter"], (at - 600).to_string());
        assert_eq!(typed["message"]["validBefore"], (at + 60).to_string());
    }
    for at in [now - 31, now + 31] {
        refused(
            &pay_cap(&mut core, &mut id, v2, at),
            "invalid_argument",
            None,
        );
        assert_eq!(spent(&core), "0");
        let token = token(&mut core, &mut id, v2, None);
        refused(
            &authorize(
                &mut core,
                &mut id,
                v2,
                json!({ "token": token }),
                Some(json!(at)),
            ),
            "invalid_argument",
            None,
        );
        // The token was burnt all the same.
        refused(
            &authorize(&mut core, &mut id, v2, json!({ "token": token }), None),
            "not_authorized",
            Some("unknown_token"),
        );
    }
    // Whole seconds only.
    for bad in [
        json!(now.to_string()),
        json!(now as f64 + 0.5),
        json!(-1),
        json!(null),
    ] {
        refused(
            &authorize(
                &mut core,
                &mut id,
                v2,
                json!({ "cap": { "agent": false, "attributable": true } }),
                Some(bad),
            ),
            "invalid_argument",
            None,
        );
    }
    // Only a Ledger account's payment: not a phone's, not the vault's.
    let phone = json!({
        "account": PHONE,
        "device": { "kind": "phone", "address": "0x000000000000000000000000000000000000F002" },
        "detection": detection(), "requirements": requirements(v2),
        "authorization": { "cap": { "agent": false, "attributable": true } }, "now_s": now,
    });
    refused(
        &call(&mut core, &mut id, "x402.authorize", phone.clone()),
        "invalid_argument",
        None,
    );
    let mut vault = phone;
    vault["account"] = json!(0);
    vault.as_object_mut().unwrap().remove("device");
    refused(
        &call(&mut core, &mut id, "x402.authorize", vault),
        "invalid_argument",
        None,
    );
    // The phone's payment without now_s still goes.
    let phone = json!({
        "account": PHONE,
        "device": { "kind": "phone", "address": "0x000000000000000000000000000000000000F002" },
        "detection": detection(), "requirements": requirements(v2),
        "authorization": { "cap": { "agent": false, "attributable": true } },
    });
    let (reservation, _) = handed(&call(&mut core, &mut id, "x402.authorize", phone));
    assert_eq!(spent(&core), "10000");
    assert_eq!(
        result(&settle(&mut core, &mut id, &reservation, "withheld"))["refunded"],
        true
    );
    assert_eq!(spent(&core), "0");
    drop(core);
    // Before vault_meta is moved: no record, so not_moved.
    let root = tempfile::tempdir().unwrap();
    let mut core = start_with(root.path(), false, Some(cap("0")));
    let reply = pay_cap(&mut core, &mut id, v2, now);
    refused(&reply, "not_moved", None);
    assert_eq!(reply["error"]["data"]["store"], "vault_meta", "{reply}");
    assert_eq!(spent(&core), "0");
}

/// `x402.settle { typed_data }` signs only the reserved authorization:
/// each of the grammar file's changes (what only main's rebuild would
/// catch, the APDUs made to match) and a value that isn't typed data is
/// refused `mismatch` before any APDU, the reservation spent. A Ledger
/// reservation made with `now_s` takes no device signature; one made
/// without takes no typed data, and still settles with its signature.
#[test]
fn any_other_authorization_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path());
    let mut id = 10;
    let changes = device::grammar()["x402_changes"].as_array().unwrap();
    assert_eq!(changes.len(), 99);
    let mut forms = BTreeSet::new();
    for change in changes {
        let form = change["case"].as_str().unwrap();
        forms.insert(form);
        let case = device::case(form);
        let reply = pay_token(&mut core, &mut id, case, None);
        let (reservation, typed) = handed(&reply);
        assert_eq!(text(&typed), text(&case["request"]["typed_data"]), "{form}");
        let refusal = settle_unasked(&mut core, &mut id, &reservation, &change["typed_data"]);
        refused(&refusal, "not_authorized", Some("mismatch"));
        assert_eq!(refusal["error"]["data"]["refunded"], false, "{refusal}");
        // Spent: the honest copy finds no reservation.
        refused(
            &settle_unasked(&mut core, &mut id, &reservation, &typed),
            "invalid_argument",
            None,
        );
    }
    assert_eq!(forms, BTreeSet::from(FORMS));
    let case = device::case(FORMS[0]);
    let vector = &case["request"]["typed_data"];
    // Not typed data at all, and the typed data without a member.
    let mut short = vector.clone();
    short.as_object_mut().unwrap().remove("primaryType");
    for other in [json!("typed data"), json!(null), short] {
        let (reservation, _) = handed(&pay_token(&mut core, &mut id, case, None));
        refused(
            &settle_unasked(&mut core, &mut id, &reservation, &other),
            "not_authorized",
            Some("mismatch"),
        );
    }
    // A reservation made with now_s takes no device signature: refused,
    // nothing changed, and it still settles with its typed data.
    let hash = case["request"]["expected_hash"].as_str().unwrap();
    let key = device::key_at(&LedgerPath::parse(LIVE_PATH).unwrap());
    let digest: [u8; 32] = device::unhex(hash).try_into().unwrap();
    let signature = fc_evm::to_hex(&fc_evm::sign_digest(key.signing_key(), &digest).unwrap());
    let (reservation, _) = handed(&pay_token(&mut core, &mut id, case, None));
    refused(
        &call(
            &mut core,
            &mut id,
            "x402.settle",
            json!({ "reservation": reservation, "signature": signature }),
        ),
        "invalid_argument",
        None,
    );
    let parent = settle_typed(&mut core, &mut id, &reservation, vector);
    let mut main = Main::new(hash);
    let (_, response) = drive(&mut core, parent, |asked| main.answer(asked));
    assert!(result(&response.unwrap())["payload"].is_object());
    // One made without now_s: no typed data, nothing changed; its
    // signature settles it (#392).
    let token = token(&mut core, &mut id, case, None);
    let reply = authorize(&mut core, &mut id, case, json!({ "token": token }), None);
    let (reservation, typed) = handed(&reply);
    refused(
        &settle_unasked(&mut core, &mut id, &reservation, &typed),
        "invalid_argument",
        None,
    );
    let hash = result(&reply)["device"]["hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let digest: [u8; 32] = device::unhex(&hash).try_into().unwrap();
    let signature = fc_evm::to_hex(&fc_evm::sign_digest(key.signing_key(), &digest).unwrap());
    let signed = call(
        &mut core,
        &mut id,
        "x402.settle",
        json!({ "reservation": reservation, "signature": signature }),
    );
    assert_eq!(
        result(&signed)["payload"]["payload"]["signature"],
        signature
    );
    // Two forms at once, and an unknown reservation.
    refused(
        &call(
            &mut core,
            &mut id,
            "x402.settle",
            json!({ "reservation": reservation, "signature": signature, "typed_data": vector }),
        ),
        "invalid_argument",
        None,
    );
    refused(
        &settle_unasked(&mut core, &mut id, "00", vector),
        "invalid_argument",
        None,
    );
}

/// The parent's `shell.ledger_apdu`s answered up to the APDU the user
/// confirms, which main holds: that APDU, and main, to answer it later.
fn held_at_confirm(core: &mut Core, parent: u64, hash: &str) -> (Asked, Main) {
    let mut main = Main::new(hash);
    let (sent, response) = drive(core, parent, |asked| {
        if asked.deadline_ms == CONFIRM_MS {
            Reply::Hold
        } else {
            main.answer(asked)
        }
    });
    assert!(response.is_none(), "{response:?}");
    (sent.last().unwrap().clone(), main)
}

/// Main cancels `parent` while `held` is out: the parent's response, once
/// main answered the core's cancel of `held`.
fn cancel(core: &mut Core, parent: u64, held: &Asked) -> Value {
    core.send(&json!({ "type": "cancel", "id": parent }));
    let seen = [next(core), next(core)];
    let cancel = seen.iter().find(|m| m["type"] == "cancel").unwrap();
    assert_eq!(cancel["id"], held.id, "{seen:?}");
    core.send(&json!({ "type": "response", "id": held.id,
        "error": { "code": "cancelled", "message": "Cancelled" } }));
    let response = seen.iter().find(|m| m["type"] == "response").unwrap();
    assert_eq!(response["id"], parent);
    response.clone()
}

/// A Ledger payment under the cap holds its charge and writes nothing; one
/// that ends without a signature drops the hold, the cap file untouched,
/// and spends the reservation: another authorization, the device's
/// refusal on `E0 0C`, a disconnect at the first APDU, and a cancel while
/// the user confirms. Each error but the cancel's says `refunded: true`,
/// the room back on the cap. A token's payment that fails writes no grant,
/// charges nothing and says `refunded: false`; one that signs writes its
/// grant and charges its cap.
#[test]
fn a_failed_or_cancelled_settle_writes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path());
    let mut id = 10;
    let now = vector_now();
    let case = device::case(FORMS[0]);
    let vector = &case["request"]["typed_data"];
    let hash = case["request"]["expected_hash"].as_str().unwrap();
    let stream = honest(FORMS[0]);
    let confirm = stream.len() - 1;
    assert!(stream[confirm].starts_with("e00c0001"));
    let before = cap_file(&core).unwrap();
    // Under the cap: held, nothing written.
    let held = |core: &mut Core, id: &mut u64| {
        let reply = pay_cap(core, id, case, now);
        assert_eq!(result(&reply)["charged"], true);
        assert!(result(&reply).get("durable").is_none());
        assert_eq!(cap_file(core).unwrap(), before);
        handed(&reply).0
    };
    let spent_then = |core: &mut Core, id: &mut u64, reservation: &str| {
        assert_eq!(cap_file(core).unwrap(), before);
        refused(
            &settle(core, id, reservation, "withheld"),
            "invalid_argument",
            None,
        );
    };
    // Another authorization.
    let reservation = held(&mut core, &mut id);
    let mut other = vector.clone();
    other["message"]["value"] = json!("10001");
    let refusal = settle_unasked(&mut core, &mut id, &reservation, &other);
    refused(&refusal, "not_authorized", Some("mismatch"));
    assert_eq!(refusal["error"]["data"]["refunded"], true);
    spent_then(&mut core, &mut id, &reservation);
    // The device's refusal on the APDU the user confirms, and a disconnect
    // at the first.
    for (at, fault, code) in [
        (confirm, Fault::Status(0x6985), "LEDGER_USER_REJECTED"),
        (0, Fault::Disconnect, "LEDGER_DISCONNECTED"),
    ] {
        let reservation = held(&mut core, &mut id);
        let parent = settle_typed(&mut core, &mut id, &reservation, vector);
        let mut main = Main::faulty(hash, at, fault);
        let (sent, response) = drive(&mut core, parent, |asked| main.answer(asked));
        assert_eq!(sent.len(), at + 1, "{code}");
        let response = response.unwrap();
        assert_eq!(ledger_code(&response), code);
        assert_eq!(response["error"]["data"]["refunded"], true, "{response}");
        assert!(response.get("result").is_none());
        spent_then(&mut core, &mut id, &reservation);
    }
    // A cancel while the device waits for the user.
    let reservation = held(&mut core, &mut id);
    let parent = settle_typed(&mut core, &mut id, &reservation, vector);
    let (waiting, _) = held_at_confirm(&mut core, parent, hash);
    let response = cancel(&mut core, parent, &waiting);
    assert_eq!(response["error"]["code"], "cancelled", "{response}");
    assert!(response["error"].get("data").is_none(), "{response}");
    spent_then(&mut core, &mut id, &reservation);
    // No approval.changed for any of it: nothing changed in the file.
    assert!(
        !core
            .events
            .iter()
            .any(|event| event["event"] == "approval.changed"),
        "{:?}",
        core.events
    );
    // Signed under the cap: the charge written, standing until withheld.
    let reservation = held(&mut core, &mut id);
    let parent = settle_typed(&mut core, &mut id, &reservation, vector);
    let mut main = Main::new(hash);
    let (_, response) = drive(&mut core, parent, |asked| main.answer(asked));
    assert_eq!(result(&response.unwrap())["charged"], true);
    assert_eq!(spent(&core), "10000");
    assert_eq!(
        result(&settle(&mut core, &mut id, &reservation, "withheld"))["refunded"],
        true
    );
    assert_eq!(spent(&core), "0");
    drop(core);
    // A token's payment with a grant: refused on the device, nothing
    // written; signed, its grant written and its cap charged.
    let root = tempfile::tempdir().unwrap();
    let mut core = start_with(root.path(), true, None);
    let grant = json!({ "cap_amount": "30000", "window_seconds": 3600 });
    let reply = pay_token(&mut core, &mut id, case, Some(&grant));
    assert_eq!(result(&reply)["charged"], false);
    let (reservation, _) = handed(&reply);
    let parent = settle_typed(&mut core, &mut id, &reservation, vector);
    let mut main = Main::faulty(hash, confirm, Fault::Status(0x6985));
    let (_, response) = drive(&mut core, parent, |asked| main.answer(asked));
    let response = response.unwrap();
    assert_eq!(ledger_code(&response), "LEDGER_USER_REJECTED");
    assert_eq!(response["error"]["data"]["refunded"], false);
    assert_eq!(cap_file(&core), None);
    let reply = pay_token(&mut core, &mut id, case, Some(&grant));
    let (reservation, _) = handed(&reply);
    let parent = settle_typed(&mut core, &mut id, &reservation, vector);
    let mut main = Main::new(hash);
    let (_, response) = drive(&mut core, parent, |asked| main.answer(asked));
    let response = response.unwrap();
    let paid = result(&response);
    assert_eq!(paid["charged"], true);
    assert_eq!(paid["grant"], json!({ "added": true }));
    assert_eq!(spent(&core), "10000");
    assert_eq!(
        result(&settle(&mut core, &mut id, &reservation, "withheld"))["refunded"],
        true
    );
    assert_eq!(spent(&core), "0");
}

/// Codex's round 1 on #532: the core stops while a settle waits on the
/// device (killed, as a crash), and the next one finds the cap file as it
/// was, nothing charged and nothing to give back, and the whole cap there
/// for payments again.
#[test]
fn a_restart_while_the_device_signs_leaves_the_cap_whole() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start_with(root.path(), true, Some(cap_of("20000", "0")));
    let before = cap_file(&core).unwrap();
    let mut id = 10;
    let now = vector_now();
    let case = device::case(FORMS[0]);
    let vector = &case["request"]["typed_data"];
    let hash = case["request"]["expected_hash"].as_str().unwrap();
    // Two holds take the whole cap: one on the device, one awaiting its
    // settle.
    let (signing, _) = handed(&pay_cap(&mut core, &mut id, case, now));
    let (_waiting, _) = handed(&pay_cap(&mut core, &mut id, case, now));
    refused(
        &pay_cap(&mut core, &mut id, case, now),
        "not_authorized",
        Some("cap"),
    );
    let parent = settle_typed(&mut core, &mut id, &signing, vector);
    let _held = held_at_confirm(&mut core, parent, hash);
    assert_eq!(cap_file(&core).unwrap(), before);
    core.child.kill().unwrap();
    core.child.wait().unwrap();
    drop(core);
    assert_eq!(
        std::fs::read_to_string(root.path().join("userData").join("x402-permissions.json"))
            .unwrap(),
        before
    );
    let mut core = start_with(root.path(), true, None);
    assert_eq!(cap_file(&core).unwrap(), before);
    assert_eq!(spent(&core), "0");
    // The old reservations are gone with the process.
    refused(
        &settle_unasked(&mut core, &mut id, &signing, vector),
        "invalid_argument",
        None,
    );
    // The whole cap again: two payments, and no third.
    for _ in 0..2 {
        let reservation = handed(&pay_cap(&mut core, &mut id, case, now)).0;
        let parent = settle_typed(&mut core, &mut id, &reservation, vector);
        let mut main = Main::new(hash);
        let (_, response) = drive(&mut core, parent, |asked| main.answer(asked));
        assert_eq!(result(&response.unwrap())["charged"], true);
    }
    assert_eq!(spent(&core), "20000");
    refused(
        &pay_cap(&mut core, &mut id, case, now),
        "not_authorized",
        Some("cap"),
    );
}

/// Open holds count against the cap in every check: two of 10,000 fill a
/// cap of 20,000, so a third Ledger payment, and a phone's payment, which
/// writes its charge at once (#392), are refused; a hold and a written
/// charge fill it alike; a withheld hold gives its room back. Once the cap
/// is revoked, a withheld hold's room is back on no cap.
#[test]
fn open_holds_count_against_the_cap() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start_with(root.path(), true, Some(cap_of("20000", "0")));
    let mut id = 10;
    let now = vector_now();
    let case = device::case(FORMS[0]);
    let phone = json!({
        "account": PHONE,
        "device": { "kind": "phone", "address": "0x000000000000000000000000000000000000F002" },
        "detection": detection(), "requirements": requirements(case),
        "authorization": { "cap": { "agent": false, "attributable": true } },
    });
    let (first, _) = handed(&pay_cap(&mut core, &mut id, case, now));
    // One hold and the phone's written charge fill it.
    let (phone_paid, _) = handed(&call(&mut core, &mut id, "x402.authorize", phone.clone()));
    assert_eq!(spent(&core), "10000");
    refused(
        &pay_cap(&mut core, &mut id, case, now),
        "not_authorized",
        Some("cap"),
    );
    assert_eq!(
        result(&settle(&mut core, &mut id, &phone_paid, "withheld"))["refunded"],
        true
    );
    assert_eq!(spent(&core), "0");
    // Two holds fill it.
    let (second, _) = handed(&pay_cap(&mut core, &mut id, case, now));
    for refusal in [
        pay_cap(&mut core, &mut id, case, now),
        call(&mut core, &mut id, "x402.authorize", phone.clone()),
    ] {
        refused(&refusal, "not_authorized", Some("cap"));
    }
    assert_eq!(spent(&core), "0");
    // One withheld: room for one more, and only one.
    assert_eq!(
        result(&settle(&mut core, &mut id, &first, "withheld"))["refunded"],
        true
    );
    let (third, _) = handed(&pay_cap(&mut core, &mut id, case, now));
    refused(
        &pay_cap(&mut core, &mut id, case, now),
        "not_authorized",
        Some("cap"),
    );
    // Revoked: the holds' room isn't back on any cap.
    let revoke = call(
        &mut core,
        &mut id,
        "approval.revoke",
        json!({ "store": "x402", "key": SELLER, "what": "grant" }),
    );
    assert_eq!(result(&revoke)["revoked"], true);
    assert_eq!(
        result(&settle(&mut core, &mut id, &second, "withheld"))["refunded"],
        false
    );
    assert_eq!(
        result(&settle(&mut core, &mut id, &third, "withheld"))["refunded"],
        false
    );
}

/// A successful settle writes the held charge before the reply carries the
/// signature: the file has it when the payload arrives; with the cap file's
/// write failing, the reply carries no payload and no signature, the
/// reservation is spent, nothing is written, and `refunded` says the room
/// is back; with its directory flush failing after the rename, no payload
/// and no signature either, the reservation spent and the charge kept,
/// `refunded: false`; with the cap revoked while the device signs,
/// `cap_changed`, nothing released, and `refunded: false`.
#[test]
fn the_charge_is_written_before_the_signature_leaves() {
    let root = tempfile::tempdir().unwrap();
    let hook = root.path().join("write-fail");
    let hook_env = hook.to_str().unwrap().to_owned();
    let mut core = start_env(
        root.path(),
        true,
        Some(cap("0")),
        &[("FREEDOM_CORED_TEST_GRANT_WRITE_FAIL", &hook_env)],
    );
    let mut id = 10;
    let now = vector_now();
    let case = device::case(FORMS[0]);
    let vector = &case["request"]["typed_data"];
    let hash = case["request"]["expected_hash"].as_str().unwrap();
    let before = cap_file(&core).unwrap();
    // Signed: the charge is in the file by the time the payload arrives.
    let (reservation, _) = handed(&pay_cap(&mut core, &mut id, case, now));
    let parent = settle_typed(&mut core, &mut id, &reservation, vector);
    let (waiting, mut main) = held_at_confirm(&mut core, parent, hash);
    assert_eq!(cap_file(&core).unwrap(), before);
    respond_apdu(&mut core, &waiting, &mut main);
    let response = next(&mut core);
    assert_eq!(response["id"], parent, "{response}");
    let signature = result(&response)["payload"]["payload"]["signature"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(spent(&core), "10000");
    assert_eq!(
        result(&settle(&mut core, &mut id, &reservation, "withheld"))["refunded"],
        true
    );
    assert_eq!(spent(&core), "0");
    let before = cap_file(&core).unwrap();
    // The write fails once the device has signed: no signature leaves.
    let (reservation, _) = handed(&pay_cap(&mut core, &mut id, case, now));
    let parent = settle_typed(&mut core, &mut id, &reservation, vector);
    let (waiting, mut main) = held_at_confirm(&mut core, parent, hash);
    std::fs::write(&hook, "x402:write\n").unwrap();
    respond_apdu(&mut core, &waiting, &mut main);
    let response = next(&mut core);
    assert_eq!(response["id"], parent, "{response}");
    assert_eq!(response["error"]["code"], "storage", "{response}");
    assert_eq!(response["error"]["data"]["refunded"], true, "{response}");
    assert!(response.get("result").is_none());
    assert!(!response.to_string().contains(&signature[2..]));
    std::fs::remove_file(&hook).unwrap();
    assert_eq!(cap_file(&core).unwrap(), before);
    refused(
        &settle(&mut core, &mut id, &reservation, "withheld"),
        "invalid_argument",
        None,
    );
    // Codex's round 2: the write renamed into place, and its directory
    // flush failing, once the device has signed. No signature or payload
    // leaves, the reservation is spent, and the charge stays counted, in
    // the file and in memory, with no room given back.
    let (reservation, _) = handed(&pay_cap(&mut core, &mut id, case, now));
    let parent = settle_typed(&mut core, &mut id, &reservation, vector);
    let (waiting, mut main) = held_at_confirm(&mut core, parent, hash);
    std::fs::write(&hook, "x402:flush\n").unwrap();
    respond_apdu(&mut core, &waiting, &mut main);
    let response = next(&mut core);
    assert_eq!(response["id"], parent, "{response}");
    assert_eq!(response["error"]["code"], "storage", "{response}");
    assert_eq!(response["error"]["data"]["durable"], false, "{response}");
    assert_eq!(response["error"]["data"]["refunded"], false, "{response}");
    assert!(response.get("result").is_none());
    assert!(!response.to_string().contains(&signature[2..]));
    std::fs::remove_file(&hook).unwrap();
    assert_eq!(spent(&core), "10000");
    refused(
        &settle(&mut core, &mut id, &reservation, "withheld"),
        "invalid_argument",
        None,
    );
    // Memory counts it too: the next signed payment's write has both.
    let (reservation, _) = handed(&pay_cap(&mut core, &mut id, case, now));
    let parent = settle_typed(&mut core, &mut id, &reservation, vector);
    let mut main = Main::new(hash);
    let (_, response) = drive(&mut core, parent, |asked| main.answer(asked));
    assert_eq!(result(&response.unwrap())["charged"], true);
    assert_eq!(spent(&core), "20000");
    assert_eq!(
        result(&settle(&mut core, &mut id, &reservation, "withheld"))["refunded"],
        true
    );
    assert_eq!(spent(&core), "10000");
    // Nothing of the refused signatures reached main in an event either:
    // the one signed payment's went out in its reply alone.
    assert!(
        core.events
            .iter()
            .all(|event| !event.to_string().contains(&signature[2..])),
        "{:?}",
        core.events
    );
    // The cap revoked while the device signs: nothing released, and no
    // room back on a cap that is gone.
    let (reservation, _) = handed(&pay_cap(&mut core, &mut id, case, now));
    let parent = settle_typed(&mut core, &mut id, &reservation, vector);
    let (waiting, mut main) = held_at_confirm(&mut core, parent, hash);
    let revoke = call(
        &mut core,
        &mut id,
        "approval.revoke",
        json!({ "store": "x402", "key": SELLER, "what": "grant" }),
    );
    assert_eq!(result(&revoke)["revoked"], true);
    let revoked = cap_file(&core);
    respond_apdu(&mut core, &waiting, &mut main);
    let response = next(&mut core);
    assert_eq!(response["id"], parent, "{response}");
    refused(&response, "not_authorized", Some("cap_changed"));
    assert_eq!(response["error"]["data"]["refunded"], false, "{response}");
    assert_eq!(cap_file(&core), revoked);
}

/// Main answers `asked`, the APDU it held, from `main`'s device.
fn respond_apdu(core: &mut Core, asked: &Asked, main: &mut Main) {
    match main.answer(asked) {
        Reply::Result(result) => respond(core, asked.id, result),
        Reply::Hold => panic!("held again"),
    }
}

/// A reservation dropped for room (the oldest of 64 kept) drops its hold:
/// with a cap of 65 payments, 66 Ledger payments are each held, as the
/// first's hold went when the 65th came, and the first two are unknown.
#[test]
fn a_reservation_dropped_for_room_drops_its_hold() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start_with(root.path(), true, Some(cap_of("650000", "0")));
    let mut id = 10;
    let now = vector_now();
    let case = device::case(FORMS[0]);
    let mut kept = Vec::new();
    // The 66th fits only if the first's hold went: 64 kept and itself.
    for _ in 0..66 {
        kept.push(handed(&pay_cap(&mut core, &mut id, case, now)).0);
    }
    for dropped in &kept[..2] {
        refused(
            &settle(&mut core, &mut id, dropped, "withheld"),
            "invalid_argument",
            None,
        );
    }
    assert_eq!(
        result(&settle(&mut core, &mut id, &kept[2], "withheld"))["refunded"],
        true
    );
    assert_eq!(spent(&core), "0");
}

/// Codex's round 2 on #532: the reservation's ID, drawn from the OS's RNG
/// after the payment's nonce, fails (`FREEDOM_CORED_TEST_X402_ID_FAILS`)
/// before any charge is held, so the failure holds nothing. After 65 such
/// failures, more than the 64 reservations kept, the cap file is as it was
/// and the whole cap of two payments is there, and no third.
#[test]
fn a_failed_reservation_draw_holds_nothing() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start_env(
        root.path(),
        true,
        Some(cap_of("20000", "0")),
        &[("FREEDOM_CORED_TEST_X402_ID_FAILS", "65")],
    );
    let before = cap_file(&core).unwrap();
    let mut id = 10;
    let now = vector_now();
    let case = device::case(FORMS[0]);
    for _ in 0..65 {
        refused(&pay_cap(&mut core, &mut id, case, now), "internal", None);
    }
    assert_eq!(cap_file(&core).unwrap(), before);
    let kept: Vec<String> = (0..2)
        .map(|_| handed(&pay_cap(&mut core, &mut id, case, now)).0)
        .collect();
    refused(
        &pay_cap(&mut core, &mut id, case, now),
        "not_authorized",
        Some("cap"),
    );
    for reservation in &kept {
        assert_eq!(
            result(&settle(&mut core, &mut id, reservation, "withheld"))["refunded"],
            true
        );
    }
    assert_eq!(cap_file(&core).unwrap(), before);
}
