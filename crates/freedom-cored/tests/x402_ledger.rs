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
//! - **Failure refunds:** another authorization, the device's refusal, a
//!   disconnect, and a cancel during the user's wait each give a cap's
//!   charge back and spend the reservation; a token's payment that fails
//!   writes no grant and charges nothing.

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
        assert_eq!(device::case(form)["x402"]["nonce"], nonce.as_str(), "{form}");
    }
    nonce
}

/// A cap on the sellers' USDC on Base, `spent` of 1,000,000 spent.
fn cap(spent: &str) -> Value {
    let now = vector_now();
    json!({ SELLER: { "8453:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": {
        "capAmount": "1000000", "spentAmount": spent,
        "createdAt": now - 100, "expiresAt": now + 3600,
    } } })
}

/// A core over `root`, the wall clock and nonce the vectors', with
/// [`meta`] and `vault_meta` moved if `moved`, `x402` moved, and `caps` as
/// the cap file.
fn start_with(root: &Path, moved: bool, caps: Option<Value>) -> Core {
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
    let mut core = spawn_env(
        "serve",
        &identity,
        &root.join("locks"),
        &[],
        &[
            ("FREEDOM_CORED_TEST_WALL_CLOCK", clock.to_str().unwrap()),
            ("FREEDOM_CORED_TEST_X402_NONCE", nonce.as_str()),
        ],
    );
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
    let text = std::fs::read_to_string(core.grant_root.join("x402-permissions.json")).unwrap();
    let caps: Value = serde_json::from_str(&text).unwrap();
    caps[SELLER]["8453:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"]["spentAmount"].clone()
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
    assert_eq!(response["id"], *id, "an APDU, or another response: {response}");
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
            assert_eq!(spent(&core), "10000");
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
        refused(&pay_cap(&mut core, &mut id, v2, at), "invalid_argument", None);
        assert_eq!(spent(&core), "0");
        let token = token(&mut core, &mut id, v2, None);
        refused(
            &authorize(&mut core, &mut id, v2, json!({ "token": token }), Some(json!(at))),
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
    for bad in [json!(now.to_string()), json!(now as f64 + 0.5), json!(-1), json!(null)] {
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
    let hash = result(&reply)["device"]["hash"].as_str().unwrap().to_owned();
    let digest: [u8; 32] = device::unhex(&hash).try_into().unwrap();
    let signature = fc_evm::to_hex(&fc_evm::sign_digest(key.signing_key(), &digest).unwrap());
    let signed = call(
        &mut core,
        &mut id,
        "x402.settle",
        json!({ "reservation": reservation, "signature": signature }),
    );
    assert_eq!(result(&signed)["payload"]["payload"]["signature"], signature);
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

/// A payment that ends without a signature gives a cap's charge back and
/// spends the reservation: another authorization, the device's refusal on
/// `E0 0C`, a disconnect at the first APDU, and a cancel while the user
/// confirms. A token's payment that fails writes no grant and charges
/// nothing; one that signs writes its grant and charges its cap.
#[test]
fn failure_refunds() {
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
    // Under the cap: charged as it is handed out.
    let charged = |core: &mut Core, id: &mut u64| {
        let reply = pay_cap(core, id, case, now);
        assert_eq!(result(&reply)["charged"], true);
        assert_eq!(spent(core), "10000");
        handed(&reply).0
    };
    let spent_then = |core: &mut Core, id: &mut u64, reservation: &str| {
        assert_eq!(spent(core), "0");
        refused(
            &settle(core, id, reservation, "withheld"),
            "invalid_argument",
            None,
        );
    };
    // Another authorization.
    let reservation = charged(&mut core, &mut id);
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
        let reservation = charged(&mut core, &mut id);
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
    let reservation = charged(&mut core, &mut id);
    let parent = settle_typed(&mut core, &mut id, &reservation, vector);
    let mut main = Main::new(hash);
    let (sent, response) = drive(&mut core, parent, |asked| {
        if asked.deadline_ms == CONFIRM_MS {
            Reply::Hold
        } else {
            main.answer(asked)
        }
    });
    assert!(response.is_none());
    let held = sent.last().unwrap().clone();
    core.send(&json!({ "type": "cancel", "id": parent }));
    let seen = [next(&mut core), next(&mut core)];
    let cancel = seen.iter().find(|m| m["type"] == "cancel").unwrap();
    assert_eq!(cancel["id"], held.id, "{seen:?}");
    core.send(&json!({ "type": "response", "id": held.id,
        "error": { "code": "cancelled", "message": "Cancelled" } }));
    let response = seen.iter().find(|m| m["type"] == "response").unwrap();
    assert_eq!(response["id"], parent);
    assert_eq!(response["error"]["code"], "cancelled", "{response}");
    assert!(response["error"].get("data").is_none(), "{response}");
    spent_then(&mut core, &mut id, &reservation);
    // Signed under the cap: the charge stands until withheld.
    let reservation = charged(&mut core, &mut id);
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
    let file = |core: &Core| std::fs::read_to_string(core.grant_root.join("x402-permissions.json")).ok();
    let reply = pay_token(&mut core, &mut id, case, Some(&grant));
    assert_eq!(result(&reply)["charged"], false);
    let (reservation, _) = handed(&reply);
    let parent = settle_typed(&mut core, &mut id, &reservation, vector);
    let mut main = Main::faulty(hash, confirm, Fault::Status(0x6985));
    let (_, response) = drive(&mut core, parent, |asked| main.answer(asked));
    let response = response.unwrap();
    assert_eq!(ledger_code(&response), "LEDGER_USER_REJECTED");
    assert_eq!(response["error"]["data"]["refunded"], false);
    assert_eq!(file(&core), None);
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
