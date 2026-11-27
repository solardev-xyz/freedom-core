//! `sign.*` with a Ledger key over the wire (design 0016, "Accounts",
//! "Approvals: enforced", API; LDG-2's L4), against a scripted main that
//! answers each `shell.ledger_apdu` from a scripted device: fc-ledger's
//! own (`formats.device`), shared with its tests rather than copied, and a
//! `vectors/ledger.json` case's recorded answers where one is replayed.
//!
//! - **Every sign vector** through `sign.*`: the core's APDUs are
//!   fc-ledger's stream for the request (the grammar's honest one where it
//!   lists the case), each with `deadline_ms` 300000 only where the user
//!   confirms; the answer is the reference's, the deviations as 0016's
//!   table has them; and what a Ledger can't carry is refused before any
//!   APDU.
//! - **D9:** `not_moved` before `vault_meta` is moved; then only a Ledger
//!   record at a scheme's path signs, and a `path` or `address` given must
//!   be the record's; the vault isn't needed.
//! - **APR-3 and APR-4 with a Ledger key:** a page's signature needs its
//!   token or a standing rule, the chrome's a wallet-kind token, and main's
//!   own Safe or 32-byte one an approval; a flagged `dapp-send` writes its
//!   rule once the device signed, and never on a refusal or a cancel; a
//!   Safe approval's first owner fixes the SafeTx when its signature comes
//!   back, checked again then, and a cancelled one fixes nothing.
//! - **The token** is spent as it is presented: burnt by a cancel before
//!   the first APDU, during one and during the user's wait, and by a
//!   ninth signature the lane refuses `LEDGER_BUSY`.
//! - **The device:** another address `LEDGER_WRONG_DEVICE`, another app
//!   `LEDGER_ETH_APP_NOT_OPEN`, a stale signature `LEDGER_BAD_SIGNATURE`.
//! - **Q23's order:** the hash-only APDU only after `6D00` answered the
//!   first `E0 1A` with main's `hash_only: "shown"`; without it
//!   `LEDGER_UNKNOWN` and nothing more sent; `hash_only` on any other
//!   answer a protocol error.
//! - **A restart** fails the parent: no answer, and nothing of it in the
//!   next core.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

/// fc-ledger's scripted device and its vector loaders, the same the
/// crate's own vector tests run.
#[path = "../../fc-ledger/tests/common/mod.rs"]
mod device;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use device::{Answer, Device, Fault, Owned};
use fc_ledger::Failed;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const HANDLE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SITE: &str = "https://app.example";
const TO: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
/// `approve(…)`: a contract call a transaction rule's selector names.
const APPROVE: &str = "0x095ea7b30000000000000000000000000000000000000000000000000000000000000001";
const SAFE: &str = "0x1111111111111111111111111111111111111111";
const OTHER_SAFE: &str = "0x2222222222222222222222222222222222222222";
const ZERO: &str = "0x0000000000000000000000000000000000000000";

/// The Ledger records of [`meta`]: abandon-12's keys at `44'/60'/0'/0/0`
/// (the vault's account 0's key too) and at `44'/60'/0'/3`.
const LIVE: u32 = 1_000_000;
const LIVE_PATH: &str = "44'/60'/0'/0/0";
const LEGACY: u32 = 1_000_001;
const LEGACY_PATH: &str = "44'/60'/0'/3";
/// Its other records: a phone's, a Safe's, and two Ledger records no
/// Ledger signs at, one at a path that isn't a scheme's and one with none.
const PHONE: u32 = 1_000_002;
const SAFE_RECORD: u32 = 1_000_003;
const OFF_SCHEME: u32 = 1_000_004;
const PATHLESS: u32 = 1_000_005;

const CONFIRM_MS: u64 = 300_000;
const APDU_MS: u64 = 15_000;

// The world.

fn address_at(path: &str) -> String {
    fc_evm::checksum_address(&device::account_at(path).address)
}

/// `vault-meta.json` with the main wallet and the records above.
fn meta() -> Value {
    let live = address_at(LIVE_PATH);
    json!({
        "addresses": { "userWallet": live },
        "derivedWallets": [
            { "index": 0, "name": "Main Wallet" },
            { "index": LIVE, "name": "Ledger", "address": live, "type": "ledger",
                "path": LIVE_PATH, "addressCheck": "matched" },
            { "index": LEGACY, "name": "Legacy", "address": address_at(LEGACY_PATH),
                "type": "ledger", "path": LEGACY_PATH },
            { "index": PHONE, "name": "Phone",
                "address": "0x000000000000000000000000000000000000F002", "type": "remote" },
            { "index": SAFE_RECORD, "name": "Safe", "address": SAFE, "type": "safe", "owners": [0] },
            { "index": OFF_SCHEME, "name": "Odd path", "address": live, "type": "ledger",
                "path": format!("m/{LIVE_PATH}") },
            { "index": PATHLESS, "name": "No path", "address": live, "type": "ledger" },
        ],
        "activeWalletIndex": 0,
        "nextHardwareWalletIndex": 1_000_006,
    })
}

/// A core over `root`, its `vault-meta.json` [`meta`] if `with_meta`,
/// `vault_meta` moved if `moved`, with `grant_moved` and `dapp` as the dApp
/// file's text; a page's `approval.issue` on main's word. No vault.
fn start_with(
    root: &Path,
    with_meta: bool,
    moved: bool,
    grant_moved: &[&'static str],
    dapp: Option<&str>,
) -> Core {
    let identity = root.join("identity");
    std::fs::create_dir_all(&identity).unwrap();
    if with_meta {
        std::fs::write(
            identity.join("vault-meta.json"),
            serde_json::to_string_pretty(&meta()).unwrap(),
        )
        .unwrap();
    }
    let mut core = spawn_env("serve", &identity, &root.join("locks"), &[], &[MAINS_WORD]);
    std::fs::create_dir_all(&core.grant_root).unwrap();
    if let Some(dapp) = dapp {
        std::fs::write(core.grant_root.join("dapp-permissions.json"), dapp).unwrap();
    }
    core.grant_moved = grant_moved.to_vec();
    core.store_moved = if moved {
        vec!["vault_meta"]
    } else {
        Vec::new()
    };
    let hello = core.hello();
    assert!(hello["result"].is_object(), "{hello}");
    core
}

/// [`meta`], moved.
fn start(root: &Path) -> Core {
    start_with(root, true, true, &[], None)
}

fn page_as(origin: &str, frame: u64, navigation: u64, agent: Option<bool>) -> Value {
    let mut page = json!({
        "origin": origin, "top_origin": origin, "frame": frame, "navigation": navigation,
    });
    if let Some(agent) = agent {
        page["agent"] = json!(agent);
    }
    json!({ "caller": "page", "page": page })
}

fn site() -> Value {
    page_as(SITE, 1, 1, Some(false))
}

fn chrome() -> Value {
    json!({ "caller": "chrome" })
}

fn shell() -> Value {
    json!({ "caller": "shell" })
}

// The wire.

/// One `shell.ledger_apdu` the core sent.
#[derive(Debug, Clone)]
struct Asked {
    id: u64,
    parent: u64,
    apdu: String,
    deadline_ms: u64,
}

impl Asked {
    fn bytes(&self) -> Vec<u8> {
        device::unhex(&self.apdu)
    }
}

/// Main's reply to one.
enum Reply {
    Result(Value),
    Error(Value),
    /// Left unanswered: the drive stops there.
    Hold,
}

/// Main as the design has it relay a device's answer: `{ answer }`, with
/// `hash_only: "shown"` on a `6D00` to the first `E0 1A` (fc-ledger's
/// [`device::relay`] decides it), `{ failed }`, or its refusal.
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
        Owned::Refused => Reply::Error(json!({
            "code": "invalid_argument", "message": "Invalid argument", "data": { "rule": "payload" },
        })),
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

fn respond(core: &mut Core, id: u64, reply: Reply) {
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
        assert_eq!(apdu.parent, id, "{message}");
        let answer = main(sent.len(), &apdu);
        sent.push(apdu.clone());
        if matches!(answer, Reply::Hold) {
            return (sent, None);
        }
        respond(core, apdu.id, answer);
    }
}

fn call(core: &mut Core, id: u64, context: &Value, method: &str, params: Value) {
    core.send(&json!({
        "type": "request", "id": id, "method": method, "params": params, "context": context,
    }));
}

/// A request answered with no APDU sent: its response.
fn unasked(core: &mut Core, id: &mut u64, context: &Value, method: &str, params: Value) -> Value {
    *id += 1;
    call(core, *id, context, method, params);
    let (sent, response) = drive(core, *id, |_, asked| {
        panic!("an APDU for a request refused before the device: {asked:?}")
    });
    assert!(sent.is_empty());
    response.unwrap()
}

/// A request answered with `main` relaying to the device: its APDUs and
/// response.
fn signed_with(
    core: &mut Core,
    id: &mut u64,
    context: &Value,
    method: &str,
    params: Value,
    main: impl FnMut(usize, &Asked) -> Reply,
) -> (Vec<Asked>, Value) {
    *id += 1;
    call(core, *id, context, method, params);
    let (sent, response) = drive(core, *id, main);
    (sent, response.unwrap())
}

fn result(reply: &Value) -> &Value {
    assert!(reply["result"].is_object(), "{reply}");
    &reply["result"]
}

fn error_code(response: &Value) -> &str {
    response["error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
}

/// Refused with `code` (and `reason`), and nothing signed.
fn refused(reply: &Value, code: &str, reason: Option<&str>) {
    assert_eq!(error_code(reply), code, "{reply}");
    if let Some(reason) = reason {
        assert_eq!(reply["error"]["data"]["reason"], reason, "{reply}");
    }
    assert!(reply.get("result").is_none(), "{reply}");
}

fn ledger_code(response: &Value) -> &str {
    assert_eq!(error_code(response), "device_failed", "{response}");
    response["error"]["data"]["ledger"].as_str().unwrap()
}

/// Main relaying to a scripted device, which keeps its own count of the
/// APDUs it was sent.
struct Main {
    device: Device,
    at: usize,
}

impl Main {
    /// A Ledger with the Ethereum app open, holding abandon-12, whose
    /// `E0 0C 00 01` signs `typed`'s hash.
    fn new(typed: Option<&Value>) -> Self {
        let mut device = Device::default();
        device.typed_hash = typed.map(typed_hash);
        Main { device, at: 0 }
    }

    fn answer(&mut self, asked: &Asked) -> Reply {
        let apdu = asked.bytes();
        let owned = device::relay(self.at, &apdu, self.device.answer(&apdu));
        self.at += 1;
        wire(owned)
    }

    /// Answers every APDU.
    fn all(&mut self) -> impl FnMut(usize, &Asked) -> Reply + '_ {
        |_, asked| self.answer(asked)
    }

    /// Answers every APDU but the one the user confirms, which it holds.
    fn until_confirm(&mut self) -> impl FnMut(usize, &Asked) -> Reply + '_ {
        |_, asked| {
            if asked.deadline_ms == CONFIRM_MS {
                Reply::Hold
            } else {
                self.answer(asked)
            }
        }
    }
}

// The requests.

fn ledger_key(index: u32) -> Value {
    json!({ "kind": "ledger", "index": index })
}

fn account(index: u32) -> Value {
    json!({ "kind": "account", "index": index })
}

fn send_tx(value: &str, data: &str) -> Value {
    json!({
        "type": 2, "chain_id": "100", "nonce": "3", "gas_limit": "60000", "to": TO,
        "value": value, "data": data,
        "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000000",
    })
}

fn mail() -> Value {
    json!({
        "domain": { "name": "Ether Mail", "chainId": "100" },
        "types": { "Mail": [{ "name": "contents", "type": "string" }] },
        "message": { "contents": "Hello" },
    })
}

fn typed_hash(typed: &Value) -> [u8; 32] {
    fc_evm::typed_data_hash(&typed["domain"], &typed["types"], &typed["message"]).unwrap()
}

/// The three signing methods.
#[derive(Debug, Clone, Copy)]
enum Method {
    Transaction,
    Message,
    TypedData,
}

impl Method {
    const ALL: [Method; 3] = [Method::Transaction, Method::Message, Method::TypedData];

    fn name(self) -> &'static str {
        match self {
            Method::Transaction => "sign.transaction",
            Method::Message => "sign.message",
            Method::TypedData => "sign.typed_data",
        }
    }

    /// Its page kind, and what the token binds, for account `index`.
    fn mint(self, index: u32) -> Value {
        let (kind, payload) = match self {
            Method::Transaction => ("dapp-send", json!({ "tx": send_tx("1000", "0x") })),
            Method::Message => ("sign-message", json!({ "message": "0x68656c6c6f" })),
            Method::TypedData => ("sign-typed-data", json!({ "typed_data": mail() })),
        };
        json!({ "kind": kind, "account": index, "payload": payload, "handle": HANDLE })
    }

    /// The request with `key`, and `authorization` if given.
    fn params(self, key: Value, authorization: Option<Value>) -> Value {
        let mut params = match self {
            Method::Transaction => json!({ "key": key, "tx": send_tx("1000", "0x") }),
            Method::Message => json!({ "key": key, "message": "0x68656c6c6f" }),
            Method::TypedData => json!({
                "key": key, "typed_data": mail(),
                "expected_hash": fc_evm::to_hex(&typed_hash(&mail())),
            }),
        };
        if let Some(authorization) = authorization {
            params["authorization"] = authorization;
        }
        params
    }

    /// A page's token as this method presents it.
    fn page_token(self, token: &str) -> Value {
        match self {
            Method::Transaction => json!({ "token": token, "kind": "dapp-send", "handle": HANDLE }),
            _ => json!({ "token": token, "handle": HANDLE }),
        }
    }

    /// The device for it.
    fn main(self) -> Main {
        match self {
            Method::TypedData => Main::new(Some(&mail())),
            _ => Main::new(None),
        }
    }

    /// What was signed: the raw transaction, or the 65-byte signature.
    fn signed(self, reply: &Value) -> String {
        let field = match self {
            Method::Transaction => "raw",
            _ => "signature",
        };
        result(reply)[field].as_str().unwrap().to_owned()
    }
}

/// A page's token for `method`'s request by account `index`.
fn mint(core: &mut Core, id: &mut u64, method: Method, index: u32) -> String {
    *id += 1;
    call(core, *id, &site(), "approval.issue", method.mint(index));
    let reply = core.response(*id);
    result(&reply)["token"].as_str().unwrap().to_owned()
}

/// A plain call, no APDU expected or allowed.
fn call_as(core: &mut Core, id: &mut u64, context: &Value, method: &str, params: Value) -> Value {
    *id += 1;
    call(core, *id, context, method, params);
    core.response(*id)
}

// Every vector.

/// A case's end, or the core's.
#[derive(Debug, Clone, PartialEq, Eq)]
enum End {
    Raw(String),
    Signature(String),
    Code(String),
    Refused(String),
}

fn wire_end(response: &Value) -> End {
    if let Some(result) = response.get("result") {
        return match result.get("raw") {
            Some(raw) => End::Raw(raw.as_str().unwrap().to_owned()),
            None => End::Signature(result["signature"].as_str().unwrap().to_owned()),
        };
    }
    match error_code(response) {
        "device_failed" => End::Code(ledger_code(response).to_owned()),
        other => End::Refused(other.to_owned()),
    }
}

fn machine_end(done: &Result<fc_ledger::Signed, fc_ledger::Failure>) -> End {
    match done {
        Ok(fc_ledger::Signed::Transaction(tx)) => End::Raw(fc_evm::to_hex(&tx.raw)),
        Ok(fc_ledger::Signed::Signature(signature)) => End::Signature(fc_evm::to_hex(signature)),
        Ok(other) => panic!("a signature's operation ended {other:?}"),
        Err(failure) => End::Code(failure.code.as_str().to_owned()),
    }
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

/// The reference's end for a case, the deviations as 0016's table has
/// them (fc-ledger's vector test reads them so too).
fn wanted(case: &Value, end: &End) -> End {
    let marks = marks(case);
    let result = &case["result"];
    let mut want = if result["status"] == "error" {
        End::Code(result["code"].as_str().unwrap().to_owned())
    } else if let Some(raw) = result.get("raw") {
        End::Raw(raw.as_str().unwrap().to_owned())
    } else if let Some(signature) = result.get("signature") {
        End::Signature(signature.as_str().unwrap().to_owned())
    } else {
        // x402: the payload @x402/evm built around the signature.
        let payload: Value = serde_json::from_str(result["payload"].as_str().unwrap()).unwrap();
        End::Signature(payload["payload"]["signature"].as_str().unwrap().to_owned())
    };
    let code = |code: &str| End::Code(code.to_owned());
    if marks.contains("app-check") && case["device"]["app"]["name"] != "Ethereum" {
        want = code("LEDGER_ETH_APP_NOT_OPEN");
    }
    if marks.contains("signature-check") {
        want = code("LEDGER_BAD_SIGNATURE");
    }
    if marks.contains("blind-typed-data") {
        // A 6D00 anywhere but the first E0 1A: today's mapping.
        want = code("LEDGER_ETH_APP_NOT_OPEN");
    }
    if marks.contains("key-check") {
        want = code("LEDGER_UNKNOWN");
    }
    if marks.contains("chain-id-width") {
        // Signed, its sender the account; fc-ledger's test checks the v.
        let End::Raw(raw) = end else {
            panic!("{}: {end:?}", case["id"])
        };
        let decoded = fc_evm::decode_signed(&device::unhex(raw)).unwrap();
        assert_eq!(
            decoded.signer().unwrap(),
            device::account(&case["record"]).address
        );
        want = end.clone();
    }
    if marks.contains("no-device") {
        want = code("LEDGER_DEVICE_NOT_FOUND");
    }
    want
}

/// A case's recorded answers, then fc-ledger's scripted device where the
/// core leaves the reference's stream (`app-check`'s `B0 01`, the pieces
/// `chain-id-width` and `field-pieces` change), as fc-ledger's vector test
/// replays them.
struct Replay {
    case: &'static Value,
    cursor: usize,
    diverged: bool,
    device: Device,
}

impl Replay {
    fn new(case: &'static Value) -> Self {
        Replay {
            case,
            cursor: 0,
            diverged: false,
            device: device::device_for(case),
        }
    }

    fn reply(&mut self, index: usize, apdu: &[u8]) -> Owned {
        if self.case["device"].get("open").is_some() {
            return Owned::Failed(Failed::NotFound);
        }
        let device = self.device.answer(apdu);
        if !self.diverged {
            let recorded = self.case["exchanges"].as_array().unwrap();
            if let Some(exchange) = recorded.get(self.cursor)
                && device::unhex(exchange["apdu"].as_str().unwrap()) == apdu
            {
                self.cursor += 1;
                if exchange.get("thrown").is_some() {
                    return Owned::Failed(Failed::Disconnected);
                }
                let answer = device::unhex(exchange["answer"].as_str().unwrap());
                return device::relay(index, apdu, Answer::Bytes(answer));
            }
            if apdu == [0xb0, 0x01, 0x00, 0x00, 0x00] {
                return device::relay(index, apdu, device);
            }
            self.diverged = true;
        }
        device::relay(index, apdu, device)
    }
}

/// Whether main's own signature of the case's request needs an approval
/// (APR-4b): typed data declaring a `SafeTx` or a `SafeMessage`.
fn safes(case: &Value) -> bool {
    let types = &case["request"]["typed_data"]["types"];
    types.get("SafeTx").is_some() || types.get("SafeMessage").is_some()
}

/// Every sign vector of `vectors/ledger.json` through `sign.*`, on one
/// core: main's own under `shell`, a Safe's under its page token.
#[test]
fn every_sign_vector() {
    let grammar = device::grammar();
    let refusals: BTreeMap<&str, &str> = grammar["refused"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["case"].as_str().unwrap(),
                r["deviation"].as_str().unwrap(),
            )
        })
        .collect();
    let honest: BTreeMap<&str, Vec<String>> = grammar["honest"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            let apdus = h["apdus"].as_array().unwrap();
            let apdus = apdus.iter().map(|a| a.as_str().unwrap().to_owned());
            (h["case"].as_str().unwrap(), apdus.collect())
        })
        .collect();
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path());
    let mut id = 100;
    let mut ran = 0;
    let mut honest_seen = 0;
    for case in device::cases() {
        let method = case["operation"].as_str().unwrap();
        if !method.starts_with("sign.") {
            continue;
        }
        let name = case["id"].as_str().unwrap();
        let index = match case["record"]["path"].as_str().unwrap() {
            LIVE_PATH => LIVE,
            LEGACY_PATH => LEGACY,
            other => panic!("{name}: a record at {other}"),
        };
        assert_eq!(
            case["record"]["address"].as_str().unwrap(),
            match index {
                LIVE => address_at(LIVE_PATH),
                _ => address_at(LEGACY_PATH),
            }
        );
        let mut params = case["request"].clone();
        params["key"] = ledger_key(index);
        // @x402/evm's typed data names its primary type inside; 0002's
        // `sign.typed_data` takes it beside, as `primary_type`.
        if let Some(primary) = params
            .get_mut("typed_data")
            .and_then(Value::as_object_mut)
            .and_then(|typed| typed.remove("primaryType"))
        {
            params["primary_type"] = primary;
        }
        let mut context = shell();
        if safes(case) {
            id += 1;
            call(
                &mut core,
                id,
                &site(),
                "approval.issue",
                json!({ "kind": "sign-typed-data", "account": index, "handle": HANDLE,
                    "payload": { "typed_data": case["request"]["typed_data"] } }),
            );
            let issued = core.response(id);
            let token = result(&issued)["token"].as_str().unwrap().to_owned();
            params["authorization"] = json!({ "token": token, "handle": HANDLE });
            context = site();
        }
        let mut replay = Replay::new(case);
        let (sent, response) =
            signed_with(&mut core, &mut id, &context, method, params, |at, asked| {
                wire(replay.reply(at, &asked.bytes()))
            });
        ran += 1;
        let end = wire_end(&response);
        if let Some(deviation) = refusals.get(name) {
            assert!(sent.is_empty(), "{name}: APDUs sent");
            let want = match *deviation {
                // 0002's identifier rule, in the core's public work.
                "name-ascii" => End::Refused("invalid_argument".into()),
                "device-bounds" => End::Code("LEDGER_TOO_LARGE".into()),
                "empty-message" => End::Code("LEDGER_EMPTY_MESSAGE".into()),
                other => panic!("{name}: a refusal for {other}"),
            };
            assert_eq!(end, want, "{name}");
            continue;
        }
        // The core's stream is fc-ledger's own for the request.
        let mut local = Replay::new(case);
        let machine = device::run(&mut device::operation(case).unwrap(), |at, apdu| {
            local.reply(at, apdu)
        });
        let ours: Vec<String> = sent.iter().map(|a| a.apdu.clone()).collect();
        let theirs: Vec<String> = machine.apdus.iter().map(|a| device::hex(a)).collect();
        assert_eq!(ours, theirs, "{name}: the APDUs");
        for (asked, confirm) in sent.iter().zip(&machine.confirms) {
            let deadline = if *confirm { CONFIRM_MS } else { APDU_MS };
            assert_eq!(asked.deadline_ms, deadline, "{name}: {}", asked.apdu);
        }
        if let Some(stream) = honest.get(name) {
            assert_eq!(&ours, stream, "{name}: not the grammar's honest stream");
            honest_seen += 1;
        }
        assert_eq!(end, machine_end(&machine.done), "{name}");
        assert_eq!(end, wanted(case, &end), "{name}");
        if method == "sign.typed_data" && matches!(end, End::Signature(_)) {
            assert!(result(&response)["view"].is_object(), "{name}");
        }
    }
    assert_eq!(ran, 381);
    assert!(honest_seen > 0);
}

// D9: the record.

/// D9: a Ledger key needs `vault_meta` moved (`not_moved` before), then
/// account `index`'s Ledger record at one of the schemes' paths; a `path`
/// or `address` given must be the record's. Each refusal comes before any
/// APDU. The record's own path and address, in any form a record's may
/// take, sign, with no vault at all. A vault key at a Ledger's index stays
/// refused, and a Ledger key signs no chunk.
#[test]
fn a_ledger_key_signs_only_with_its_record() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start_with(root.path(), true, false, &[], None);
    let mut id = 10;
    for method in Method::ALL {
        let reply = unasked(
            &mut core,
            &mut id,
            &shell(),
            method.name(),
            method.params(ledger_key(LIVE), None),
        );
        assert_eq!(error_code(&reply), "not_moved", "{reply}");
        assert_eq!(reply["error"]["data"]["store"], "vault_meta");
    }
    drop(core);
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path());
    let invalid = |reply: &Value, message: &str| {
        assert_eq!(error_code(reply), "invalid_argument", "{reply}");
        assert_eq!(reply["error"]["message"], message, "{reply}");
    };
    for method in Method::ALL {
        // Not a Ledger's: the main wallet, a vault index with no record, a
        // phone's, a Safe's, a hardware index with none.
        for index in [0, 7, PHONE, SAFE_RECORD, 1_000_009] {
            let reply = unasked(
                &mut core,
                &mut id,
                &shell(),
                method.name(),
                method.params(ledger_key(index), None),
            );
            invalid(&reply, "This account isn't a Ledger's (vault-meta.json)");
        }
        for index in [OFF_SCHEME, PATHLESS] {
            let reply = unasked(
                &mut core,
                &mut id,
                &shell(),
                method.name(),
                method.params(ledger_key(index), None),
            );
            invalid(
                &reply,
                "The Ledger account's path isn't one a Ledger signs at",
            );
        }
    }
    // Another path or address than the record's, and keys that aren't one.
    let legacy = address_at(LEGACY_PATH);
    let others = [
        (
            json!({ "kind": "ledger", "index": LIVE, "path": LEGACY_PATH }),
            "path: not the Ledger account's",
        ),
        (
            json!({ "kind": "ledger", "index": LIVE, "address": legacy }),
            "address: not the Ledger account's",
        ),
        (
            json!({ "kind": "ledger", "index": LIVE, "path": format!("m/{LIVE_PATH}") }),
            "path: not a Ledger account's path",
        ),
        (
            json!({ "kind": "ledger", "index": LIVE, "path": 7 }),
            "path: expected a string",
        ),
        (
            json!({ "kind": "ledger", "index": LIVE, "address": "0x12" }),
            "address: expected an address",
        ),
        (
            json!({ "kind": "ledger", "index": LIVE, "name": "Ledger" }),
            "unknown field name",
        ),
        (json!({ "kind": "ledger" }), "missing field index"),
        (
            json!({ "kind": "ledger", "index": 2_147_483_648_u64 }),
            "Index out of range",
        ),
    ];
    for (key, message) in others {
        let reply = unasked(
            &mut core,
            &mut id,
            &shell(),
            "sign.message",
            json!({ "key": key, "message": "0x68656c6c6f" }),
        );
        invalid(&reply, message);
    }
    // The record's own: each form signs the same, three APDUs each.
    let live = address_at(LIVE_PATH);
    let mut signatures = BTreeSet::new();
    for key in [
        ledger_key(LIVE),
        json!({ "kind": "ledger", "index": LIVE, "path": LIVE_PATH, "address": live }),
        json!({ "kind": "ledger", "index": LIVE, "address": live.to_lowercase() }),
        json!({ "kind": "ledger", "index": LIVE, "address": live[2..].to_uppercase() }),
    ] {
        let mut main = Main::new(None);
        let (sent, reply) = signed_with(
            &mut core,
            &mut id,
            &shell(),
            "sign.message",
            json!({ "key": key, "message": "0x68656c6c6f" }),
            main.all(),
        );
        assert_eq!(sent.len(), 3, "{reply}");
        signatures.insert(result(&reply)["signature"].as_str().unwrap().to_owned());
    }
    assert_eq!(signatures.len(), 1);
    // The legacy record, at its own path.
    let mut main = Main::new(None);
    let (sent, reply) = signed_with(
        &mut core,
        &mut id,
        &shell(),
        "sign.message",
        json!({ "key": ledger_key(LEGACY), "message": "0x68656c6c6f" }),
        main.all(),
    );
    assert!(sent[0].apdu.starts_with("e0020000110480"), "{:?}", sent[0]);
    let signature = device::unhex(result(&reply)["signature"].as_str().unwrap());
    let signer = fc_evm::recover_address(
        &fc_evm::eip191_digest(b"hello"),
        &signature.try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(fc_evm::checksum_address(&signer), legacy);
    // A vault key at a Ledger's index, as before; a Ledger key's chunk.
    let reply = unasked(
        &mut core,
        &mut id,
        &shell(),
        "sign.message",
        Method::Message.params(account(LIVE), None),
    );
    invalid(
        &reply,
        "This account keeps its key on another device; sign via its device signer",
    );
    let soc = json!({ "key": ledger_key(LIVE),
        "identifier": format!("0x{}", "ab".repeat(32)), "payload": "0x01" });
    let reply = unasked(&mut core, &mut id, &shell(), "swarm.sign_soc", soc);
    invalid(&reply, "unknown key kind");
}

// APR-3 and APR-4 with a Ledger key.

/// A wallet's send token, as main mints it under `shell`, for account
/// `index`.
fn wallet_token(core: &mut Core, id: &mut u64, index: u32) -> String {
    let params = json!({ "kind": "wallet-send", "account": index,
        "payload": { "tx": send_tx("1000", "0x") } });
    let reply = call_as(core, id, &shell(), "approval.issue", params);
    result(&reply)["token"].as_str().unwrap().to_owned()
}

/// APR-4a with a Ledger key: each method under `page` is refused without
/// a token, with another document's (burnt), another account's (the
/// vault's account 0, whose key this Ledger holds), and a wallet's, each
/// before any APDU; its own signs once on the device, what main's own
/// signature of the same request is, and again is refused.
#[test]
fn a_page_ledger_signature_needs_its_token() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path());
    let mut id = 10;
    for method in Method::ALL {
        let name = method.name();
        let key = || ledger_key(LIVE);
        let mut main = method.main();
        let (_, own) = signed_with(
            &mut core,
            &mut id,
            &shell(),
            name,
            method.params(key(), None),
            main.all(),
        );
        let own = method.signed(&own);
        refused(
            &unasked(
                &mut core,
                &mut id,
                &site(),
                name,
                method.params(key(), None),
            ),
            "not_authorized",
            Some("no_token"),
        );
        for other in [
            page_as(SITE, 2, 1, Some(false)),
            page_as(SITE, 1, 2, Some(false)),
            page_as("https://other.example", 1, 1, Some(false)),
        ] {
            let token = mint(&mut core, &mut id, method, LIVE);
            let authorization = Some(method.page_token(&token));
            refused(
                &unasked(
                    &mut core,
                    &mut id,
                    &other,
                    name,
                    method.params(key(), authorization.clone()),
                ),
                "not_authorized",
                Some("mismatch"),
            );
            refused(
                &unasked(
                    &mut core,
                    &mut id,
                    &site(),
                    name,
                    method.params(key(), authorization),
                ),
                "not_authorized",
                Some("unknown_token"),
            );
        }
        let token = mint(&mut core, &mut id, method, 0);
        refused(
            &unasked(
                &mut core,
                &mut id,
                &site(),
                name,
                method.params(key(), Some(method.page_token(&token))),
            ),
            "not_authorized",
            Some("mismatch"),
        );
        let token = wallet_token(&mut core, &mut id, LIVE);
        let wallet = match method {
            Method::Transaction => json!({ "token": token, "kind": "wallet-send" }),
            _ => json!({ "token": token }),
        };
        refused(
            &unasked(
                &mut core,
                &mut id,
                &site(),
                name,
                method.params(key(), Some(wallet)),
            ),
            "not_authorized",
            Some("mismatch"),
        );
        // Its own: signs once, on the device, as main's own does.
        let token = mint(&mut core, &mut id, method, LIVE);
        let authorization = Some(method.page_token(&token));
        let mut main = method.main();
        let (sent, signed) = signed_with(
            &mut core,
            &mut id,
            &site(),
            name,
            method.params(key(), authorization.clone()),
            main.all(),
        );
        assert!(sent.iter().any(|a| a.deadline_ms == CONFIRM_MS), "{name}");
        assert_eq!(method.signed(&signed), own, "{name}");
        refused(
            &unasked(
                &mut core,
                &mut id,
                &site(),
                name,
                method.params(key(), authorization),
            ),
            "not_authorized",
            Some("unknown_token"),
        );
    }
}

/// The SafeTx a `safe-send` of `safe_send(safe)` approves, at `nonce`.
fn safe_tx(safe: &str, nonce: u64) -> Value {
    let field = |name: &str, kind: &str| json!({ "name": name, "type": kind });
    json!({
        "domain": { "chainId": "100", "verifyingContract": safe },
        "types": { "SafeTx": [
            field("to", "address"), field("value", "uint256"), field("data", "bytes"),
            field("operation", "uint8"), field("safeTxGas", "uint256"), field("baseGas", "uint256"),
            field("gasPrice", "uint256"), field("gasToken", "address"),
            field("refundReceiver", "address"), field("nonce", "uint256"),
        ]},
        "message": {
            "to": TO, "value": "1000", "data": "0xa9059cbb", "operation": "0",
            "safeTxGas": "0", "baseGas": "0", "gasPrice": "0",
            "gasToken": ZERO, "refundReceiver": ZERO, "nonce": nonce.to_string(),
        },
    })
}

fn typed_params(key: Value, typed: &Value, authorization: Option<Value>) -> Value {
    let mut params = json!({ "key": key, "typed_data": typed,
        "expected_hash": fc_evm::to_hex(&typed_hash(typed)) });
    if let Some(authorization) = authorization {
        params["authorization"] = authorization;
    }
    params
}

/// The chrome signs nothing with a Ledger key: without a token, with
/// main's wallet-send token, with a page's, with a standing rule or a
/// Safe approval, each refused before any APDU. Main's own signs without
/// one, but for a Safe's (APR-4b) and 32 bytes (APR-4d), refused before
/// any APDU too; a standing rule answers only a page.
#[test]
fn the_chrome_and_main_with_a_ledger_key() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path());
    let mut id = 10;
    let key = || ledger_key(LIVE);
    for method in Method::ALL {
        let name = method.name();
        refused(
            &unasked(
                &mut core,
                &mut id,
                &chrome(),
                name,
                method.params(key(), None),
            ),
            "not_authorized",
            Some("no_token"),
        );
        let token = wallet_token(&mut core, &mut id, LIVE);
        let wallet = match method {
            Method::Transaction => json!({ "token": token, "kind": "wallet-send" }),
            _ => json!({ "token": token }),
        };
        refused(
            &unasked(
                &mut core,
                &mut id,
                &chrome(),
                name,
                method.params(key(), Some(wallet)),
            ),
            "not_authorized",
            Some("mismatch"),
        );
        let token = mint(&mut core, &mut id, method, LIVE);
        refused(
            &unasked(
                &mut core,
                &mut id,
                &chrome(),
                name,
                method.params(key(), Some(method.page_token(&token))),
            ),
            "not_authorized",
            Some("mismatch"),
        );
        for (context, authorization, reason) in [
            (
                chrome(),
                json!({ "standing": { "paused": false } }),
                Some("no_rule"),
            ),
            (chrome(), json!({ "safe": "00".repeat(16) }), None),
            (
                shell(),
                json!({ "standing": { "paused": false } }),
                Some("no_rule"),
            ),
        ] {
            refused(
                &unasked(
                    &mut core,
                    &mut id,
                    &context,
                    name,
                    method.params(key(), Some(authorization)),
                ),
                "not_authorized",
                reason,
            );
        }
    }
    for safe in [safe_tx(SAFE, 7), {
        let mut message = safe_tx(SAFE, 7);
        message["types"] = json!({ "SafeMessage": [{ "name": "message", "type": "bytes" }] });
        message["message"] = json!({ "message": format!("0x{}", "11".repeat(32)) });
        message
    }] {
        refused(
            &unasked(
                &mut core,
                &mut id,
                &shell(),
                "sign.typed_data",
                typed_params(key(), &safe, None),
            ),
            "not_authorized",
            Some("no_token"),
        );
    }
    refused(
        &unasked(
            &mut core,
            &mut id,
            &shell(),
            "sign.message",
            json!({ "key": key(), "message": format!("0x{}", "11".repeat(32)) }),
        ),
        "not_authorized",
        Some("no_token"),
    );
}

/// A dApp entry for `origin`, connected with account `index` on chain 100,
/// with today's rules: the signing flag, and `approve` to `TO` up to 5 wei.
fn dapp_file(index: u32) -> String {
    serde_json::to_string_pretty(&json!({ SITE: {
        "origin": SITE, "connectedAt": 1_762_000_000_000_u64, "lastUsed": 1_762_000_000_000_u64,
        "walletIndex": index, "chainId": 100,
        "autoApprove": { "signing": true, "transactions": [
            { "to": TO, "selector": "0x095ea7b3", "chainId": 100, "maxValue": "5" },
        ] },
    } }))
    .unwrap()
}

/// A page's standing rule answers a Ledger key's signature as a vault
/// key's, and never skips the device's prompt: a message and typed data it
/// covers sign on the device, the user confirming there; custody, 32 bytes
/// and a warned view are refused before any APDU.
#[test]
fn a_standing_rule_answers_a_ledger_signature_on_the_device() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start_with(root.path(), true, true, &[], Some(&dapp_file(LIVE)));
    let mut id = 10;
    let standing = json!({ "standing": {} });
    let mut main = Main::new(None);
    let (sent, reply) = signed_with(
        &mut core,
        &mut id,
        &site(),
        "sign.message",
        Method::Message.params(ledger_key(LIVE), Some(standing.clone())),
        main.all(),
    );
    assert!(result(&reply)["signature"].is_string());
    assert_eq!(sent.last().unwrap().deadline_ms, CONFIRM_MS);
    let mut typed = typed_params(ledger_key(LIVE), &mail(), Some(standing.clone()));
    typed["chain_id"] = json!("100");
    let mut main = Main::new(Some(&mail()));
    let (sent, reply) = signed_with(
        &mut core,
        &mut id,
        &site(),
        "sign.typed_data",
        typed.clone(),
        main.all(),
    );
    assert!(result(&reply)["signature"].is_string());
    assert_eq!(sent.last().unwrap().deadline_ms, CONFIRM_MS);
    refused(
        &unasked(
            &mut core,
            &mut id,
            &page_as(SITE, 1, 1, Some(true)),
            "sign.message",
            Method::Message.params(ledger_key(LIVE), Some(standing.clone())),
        ),
        "not_authorized",
        Some("custody"),
    );
    refused(
        &unasked(
            &mut core,
            &mut id,
            &site(),
            "sign.message",
            json!({ "key": ledger_key(LIVE), "message": format!("0x{}", "11".repeat(32)),
                "authorization": standing }),
        ),
        "not_authorized",
        Some("warning"),
    );
    typed["chain_id"] = json!("1");
    refused(
        &unasked(&mut core, &mut id, &site(), "sign.typed_data", typed),
        "not_authorized",
        Some("warning"),
    );
}

/// The site's limited transaction rules in the core's dApp file.
fn limited_rules(core: &Core) -> Value {
    let text = std::fs::read_to_string(core.grant_root.join("dapp-permissions.json")).unwrap();
    let stored: Value = serde_json::from_str(&text).unwrap();
    stored[SITE]["autoApprove"]["limited"]["transactions"].clone()
}

/// `token-remember` with a Ledger key (After on the signature): a flagged
/// `dapp-send` writes its rule once the device has signed, and the reply
/// says so; the user's rejection on the device and a cancel while they
/// confirm write none, and spend their tokens.
#[test]
fn a_flagged_send_writes_its_rule_once_the_device_signed() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start_with(root.path(), true, true, &["dapp"], None);
    let mut id = 10;
    let granted = call_as(
        &mut core,
        &mut id,
        &site(),
        "approval.grant",
        json!({ "store": "dapp", "change": { "op": "connect", "account": LIVE, "chain_id": 100 } }),
    );
    assert_eq!(result(&granted)["grant"]["walletIndex"], LIVE, "{granted}");
    let issue = |core: &mut Core, id: &mut u64| {
        let issued = call_as(
            core,
            id,
            &site(),
            "approval.issue",
            json!({ "kind": "dapp-send", "account": LIVE, "handle": HANDLE,
                "payload": { "tx": send_tx("3", APPROVE), "remember": true } }),
        );
        result(&issued)["token"].as_str().unwrap().to_owned()
    };
    let params = |token: &str| {
        json!({ "key": ledger_key(LIVE), "tx": send_tx("3", APPROVE),
            "authorization": { "token": token, "kind": "dapp-send", "handle": HANDLE } })
    };
    let before = limited_rules(&core);
    assert!(before.as_array().is_none_or(Vec::is_empty), "{before}");
    // Rejected on the device (6985 to the piece the user confirms).
    let token = issue(&mut core, &mut id);
    let mut main = Main::new(None);
    main.device.fault = Some((2, Fault::Status(0x6985)));
    let (_, reply) = signed_with(
        &mut core,
        &mut id,
        &site(),
        "sign.transaction",
        params(&token),
        main.all(),
    );
    assert_eq!(ledger_code(&reply), "LEDGER_USER_REJECTED");
    assert_eq!(limited_rules(&core), before);
    refused(
        &unasked(
            &mut core,
            &mut id,
            &site(),
            "sign.transaction",
            params(&token),
        ),
        "not_authorized",
        Some("unknown_token"),
    );
    // Cancelled while the user confirms.
    let token = issue(&mut core, &mut id);
    let mut main = Main::new(None);
    id += 1;
    call(&mut core, id, &site(), "sign.transaction", params(&token));
    let (sent, held) = drive(&mut core, id, main.until_confirm());
    assert!(held.is_none());
    let response = cancel(&mut core, id, sent.last().unwrap());
    assert_eq!(error_code(&response), "cancelled");
    assert_eq!(limited_rules(&core), before);
    refused(
        &unasked(
            &mut core,
            &mut id,
            &site(),
            "sign.transaction",
            params(&token),
        ),
        "not_authorized",
        Some("unknown_token"),
    );
    // Signed: the rule, written as the signature comes back.
    let token = issue(&mut core, &mut id);
    let mut main = Main::new(None);
    let (_, reply) = signed_with(
        &mut core,
        &mut id,
        &site(),
        "sign.transaction",
        params(&token),
        main.all(),
    );
    assert_eq!(result(&reply)["rule"], json!({ "added": true }), "{reply}");
    let rules = limited_rules(&core);
    assert_eq!(rules[0]["maxValue"], "3", "{rules}");
    assert_eq!(rules[0]["selector"], "0x095ea7b3");
}

/// Main cancels parent `parent` while `held` is out: the parent's
/// response, after the core's cancel of `held`, which main answers. The
/// response.
fn cancel(core: &mut Core, parent: u64, held: &Asked) -> Value {
    core.send(&json!({ "type": "cancel", "id": parent }));
    let seen = [next(core), next(core)];
    let cancel = seen.iter().find(|m| m["type"] == "cancel").unwrap();
    assert_eq!(cancel["id"], held.id, "{seen:?}");
    respond(
        core,
        held.id,
        Reply::Error(json!({ "code": "cancelled", "message": "Cancelled" })),
    );
    let response = seen.iter().find(|m| m["type"] == "response").unwrap();
    assert_eq!(response["id"], parent);
    response.clone()
}

/// A `safe-send` approval for `safe`, a wallet's, under `shell`.
fn send_approval(core: &mut Core, id: &mut u64, safe: &str) -> String {
    let mut params = json!({ "kind": "safe-send", "account": 0, "payload": {
        "safe": safe, "chain_id": "100", "tx": { "to": TO, "value": "1000", "data": "0xa9059cbb" },
    } });
    let issued = call_as(core, id, &shell(), "approval.issue", params.clone());
    params["token"] = result(&issued)["token"].clone();
    let spent = call_as(core, id, &shell(), "approval.spend", params);
    result(&spent)["safe"].as_str().unwrap().to_owned()
}

/// A core with the abandon vault unlocked, `vault_meta` moved, and the
/// records of [`meta`]: written over the file the import wrote, since the
/// reference refuses to add a Ledger whose address is the main wallet's,
/// and read by the next `accounts.*` request.
fn with_vault(root: &Path) -> Core {
    let mut core = start_with(root, false, true, &[], None);
    let imported = core.call(
        2,
        "vault.import",
        json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(ABANDON),
            "user_knows_password": true }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    assert_eq!(core.event()["event"], "vault.unlocked");
    std::fs::write(
        root.join("identity").join("vault-meta.json"),
        serde_json::to_string_pretty(&meta()).unwrap(),
    )
    .unwrap();
    let listed = core.call_shell(3, "accounts.list", json!({}));
    assert!(listed["result"].is_object(), "{listed}");
    core
}

/// The Ledger at [`LIVE_PATH`] holds the vault's account 0's key, so each
/// method's Ledger signature is the vault's, byte for byte: the raw
/// transaction, the message's and the typed data's, with the same view.
#[test]
fn the_ledger_signs_what_the_vault_signs() {
    let root = tempfile::tempdir().unwrap();
    let mut core = with_vault(root.path());
    let mut id = 10;
    for method in Method::ALL {
        let vault = call_as(
            &mut core,
            &mut id,
            &shell(),
            method.name(),
            method.params(account(0), None),
        );
        let mut main = method.main();
        let (_, ledger) = signed_with(
            &mut core,
            &mut id,
            &shell(),
            method.name(),
            method.params(ledger_key(LIVE), None),
            main.all(),
        );
        assert_eq!(result(&ledger), result(&vault), "{}", method.name());
    }
}

/// A Safe approval with a Ledger owner (APR-4, its end asynchronous): the
/// Ledger's signature fixes the SafeTx when it comes back, as a vault
/// owner's does; one checked before a vault owner fixed another SafeTx is
/// refused when it comes back (`mismatch`), so one approval never has two
/// SafeTxs signed; a cancelled one fixes nothing.
#[test]
fn a_ledger_owner_fixes_the_safe_tx_when_its_signature_comes_back() {
    let root = tempfile::tempdir().unwrap();
    let mut core = with_vault(root.path());
    let mut id = 10;
    let owner = |index: u32| account(index);
    let safe = |approval: &str| Some(json!({ "safe": approval }));
    // The Ledger first: nonce 7.
    let approval = send_approval(&mut core, &mut id, SAFE);
    let typed = safe_tx(SAFE, 7);
    let mut main = Main::new(Some(&typed));
    let (_, reply) = signed_with(
        &mut core,
        &mut id,
        &shell(),
        "sign.typed_data",
        typed_params(ledger_key(LIVE), &typed, safe(&approval)),
        main.all(),
    );
    assert!(result(&reply)["signature"].is_string(), "{reply}");
    refused(
        &call_as(
            &mut core,
            &mut id,
            &shell(),
            "sign.typed_data",
            typed_params(owner(1), &safe_tx(SAFE, 8), safe(&approval)),
        ),
        "not_authorized",
        Some("mismatch"),
    );
    let vault = call_as(
        &mut core,
        &mut id,
        &shell(),
        "sign.typed_data",
        typed_params(owner(1), &typed, safe(&approval)),
    );
    assert!(result(&vault)["signature"].is_string(), "{vault}");
    // A vault owner fixes nonce 8 while the Ledger's nonce 7 waits.
    let approval = send_approval(&mut core, &mut id, OTHER_SAFE);
    let typed = safe_tx(OTHER_SAFE, 7);
    let mut main = Main::new(Some(&typed));
    id += 1;
    let parent = id;
    call(
        &mut core,
        parent,
        &shell(),
        "sign.typed_data",
        typed_params(ledger_key(LIVE), &typed, safe(&approval)),
    );
    let (sent, held) = drive(&mut core, parent, main.until_confirm());
    assert!(held.is_none());
    let vault = call_as(
        &mut core,
        &mut id,
        &shell(),
        "sign.typed_data",
        typed_params(owner(1), &safe_tx(OTHER_SAFE, 8), safe(&approval)),
    );
    assert!(result(&vault)["signature"].is_string(), "{vault}");
    let confirm = sent.last().unwrap();
    respond(&mut core, confirm.id, main.answer(confirm));
    let (more, response) = drive(&mut core, parent, |_, asked| panic!("{asked:?}"));
    assert!(more.is_empty());
    refused(&response.unwrap(), "not_authorized", Some("mismatch"));
    // Cancelled while the user confirms: nothing fixed.
    let approval = send_approval(&mut core, &mut id, SAFE);
    let typed = safe_tx(SAFE, 9);
    let mut main = Main::new(Some(&typed));
    id += 1;
    let parent = id;
    call(
        &mut core,
        parent,
        &shell(),
        "sign.typed_data",
        typed_params(ledger_key(LIVE), &typed, safe(&approval)),
    );
    let (sent, held) = drive(&mut core, parent, main.until_confirm());
    assert!(held.is_none());
    let response = cancel(&mut core, parent, sent.last().unwrap());
    assert_eq!(error_code(&response), "cancelled");
    let vault = call_as(
        &mut core,
        &mut id,
        &shell(),
        "sign.typed_data",
        typed_params(owner(1), &safe_tx(SAFE, 10), safe(&approval)),
    );
    assert!(result(&vault)["signature"].is_string(), "{vault}");
}

// The token and the lane.

/// The token is spent as it is presented, so a cancel finds it gone:
/// before the first APDU (queued behind another operation), during the
/// address check and during the user's wait, each `cancelled`, the APDU out
/// cancelled at main, and the token presented again `unknown_token` with
/// nothing sent. A ninth waiting is refused `LEDGER_BUSY` at once, its
/// token spent too.
#[test]
fn a_cancel_burns_the_token() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path());
    let mut id = 10;
    let params = |token: &str| {
        Method::Message.params(ledger_key(LIVE), Some(Method::Message.page_token(token)))
    };
    // Main's own holds the lane at its first APDU.
    id += 1;
    let first = id;
    call(
        &mut core,
        first,
        &shell(),
        "sign.message",
        Method::Message.params(ledger_key(LIVE), None),
    );
    let (running, _) = drive(&mut core, first, |_, _| Reply::Hold);
    assert_eq!(running.len(), 1);
    // Queued, then cancelled: no APDU of its own.
    let token = mint(&mut core, &mut id, Method::Message, LIVE);
    id += 1;
    let queued = id;
    call(&mut core, queued, &site(), "sign.message", params(&token));
    core.send(&json!({ "type": "cancel", "id": queued }));
    let response = next(&mut core);
    assert_eq!(response["id"], queued, "{response}");
    assert_eq!(error_code(&response), "cancelled");
    refused(
        &unasked(&mut core, &mut id, &site(), "sign.message", params(&token)),
        "not_authorized",
        Some("unknown_token"),
    );
    // Eight wait; a ninth is refused at once.
    let mut waiting = Vec::new();
    for _ in 0..8 {
        id += 1;
        waiting.push(id);
        call(
            &mut core,
            id,
            &shell(),
            "sign.message",
            Method::Message.params(ledger_key(LIVE), None),
        );
    }
    let token = mint(&mut core, &mut id, Method::Message, LIVE);
    id += 1;
    call(&mut core, id, &site(), "sign.message", params(&token));
    let busy = next(&mut core);
    assert_eq!(busy["id"], id, "{busy}");
    assert_eq!(ledger_code(&busy), "LEDGER_BUSY");
    refused(
        &unasked(&mut core, &mut id, &site(), "sign.message", params(&token)),
        "not_authorized",
        Some("unknown_token"),
    );
    for parent in waiting {
        core.send(&json!({ "type": "cancel", "id": parent }));
        let response = next(&mut core);
        assert_eq!(response["id"], parent, "{response}");
        assert_eq!(error_code(&response), "cancelled");
    }
    let response = cancel(&mut core, first, &running[0]);
    assert_eq!(error_code(&response), "cancelled");
    // During the address check, and during the user's wait.
    for at_confirm in [false, true] {
        let token = mint(&mut core, &mut id, Method::Message, LIVE);
        id += 1;
        let parent = id;
        call(&mut core, parent, &site(), "sign.message", params(&token));
        let mut main = Main::new(None);
        let (sent, held) = if at_confirm {
            drive(&mut core, parent, main.until_confirm())
        } else {
            drive(&mut core, parent, |_, _| Reply::Hold)
        };
        assert!(held.is_none());
        let out = sent.last().unwrap();
        assert_eq!(
            out.deadline_ms,
            if at_confirm { CONFIRM_MS } else { APDU_MS }
        );
        let response = cancel(&mut core, parent, out);
        assert_eq!(error_code(&response), "cancelled");
        refused(
            &unasked(&mut core, &mut id, &site(), "sign.message", params(&token)),
            "not_authorized",
            Some("unknown_token"),
        );
    }
}

// The device.

/// Another address at the record's path ends each method
/// `LEDGER_WRONG_DEVICE` at its first APDU, and another app
/// `LEDGER_ETH_APP_NOT_OPEN` at its second, nothing more sent.
#[test]
fn another_device_or_app_signs_nothing() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path());
    let mut id = 10;
    for method in Method::ALL {
        let mut main = method.main();
        main.device.fault = Some((0, Fault::OtherAddress));
        let (sent, reply) = signed_with(
            &mut core,
            &mut id,
            &shell(),
            method.name(),
            method.params(ledger_key(LIVE), None),
            main.all(),
        );
        assert_eq!(ledger_code(&reply), "LEDGER_WRONG_DEVICE");
        assert_eq!(sent.len(), 1);
        for (name, format_ok) in [("Bitcoin", true), ("Ethereum", false)] {
            let mut main = method.main();
            main.device.app_name = name.to_owned();
            let mut wrap = |at: usize, asked: &Asked| {
                let mut answer = main.answer(asked);
                // `B0 01`'s format byte: 1, or another.
                if at == 1
                    && !format_ok
                    && let Reply::Result(result) = &mut answer
                {
                    let text = result["answer"].as_str().unwrap();
                    result["answer"] = json!(format!("02{}", &text[2..]));
                }
                answer
            };
            let (sent, reply) = signed_with(
                &mut core,
                &mut id,
                &shell(),
                method.name(),
                method.params(ledger_key(LIVE), None),
                &mut wrap,
            );
            assert_eq!(ledger_code(&reply), "LEDGER_ETH_APP_NOT_OPEN", "{name}");
            assert_eq!(sent.len(), 2);
            assert_eq!(sent[1].apdu, "b001000000");
        }
    }
}

/// A device that answers with the previous operation's signature: each
/// method's is refused `LEDGER_BAD_SIGNATURE`, nothing returned.
#[test]
fn a_stale_signature_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path());
    let mut id = 10;
    let second = |method: Method| match method {
        Method::Transaction => json!({ "key": ledger_key(LIVE), "tx": send_tx("1001", "0x") }),
        Method::Message => json!({ "key": ledger_key(LIVE), "message": "0x776f726c64" }),
        Method::TypedData => {
            let mut typed = mail();
            typed["message"]["contents"] = json!("Bye");
            typed_params(ledger_key(LIVE), &typed, None)
        }
    };
    for method in Method::ALL {
        let mut main = method.main();
        let mut last = None;
        let (_, first) = signed_with(
            &mut core,
            &mut id,
            &shell(),
            method.name(),
            method.params(ledger_key(LIVE), None),
            |_, asked| {
                let answer = main.answer(asked);
                if let (true, Reply::Result(result)) = (asked.deadline_ms == CONFIRM_MS, &answer) {
                    last = Some(result.clone());
                }
                answer
            },
        );
        assert!(result(&first).is_object());
        let stale = last.unwrap();
        let mut main = method.main();
        let (_, reply) = signed_with(
            &mut core,
            &mut id,
            &shell(),
            method.name(),
            second(method),
            |_, asked| {
                if asked.deadline_ms == CONFIRM_MS {
                    Reply::Result(stale.clone())
                } else {
                    main.answer(asked)
                }
            },
        );
        assert_eq!(
            ledger_code(&reply),
            "LEDGER_BAD_SIGNATURE",
            "{}",
            method.name()
        );
    }
}

/// Q23: on a device that can't show fields, `6D00` to the first `E0 1A`,
/// answered with main's `hash_only: "shown"`, is followed by the one
/// hash-only APDU, `E0 0C 00 00` with fc-evm's domain separator and struct
/// hash, which the user confirms; its signature recovers over the
/// confirmed hash. A `6D00` answered without `hash_only` ends the
/// operation `LEDGER_UNKNOWN`, nothing more sent; `hash_only` on any other
/// answer is a protocol error, and the connection ends.
#[test]
fn the_hash_only_form_comes_only_after_main_shows_its_warning() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path());
    let mut id = 10;
    let typed = mail();
    let params = || typed_params(ledger_key(LIVE), &typed, None);
    let mut main = Main::new(Some(&typed));
    main.device.fields = false;
    let (sent, reply) = signed_with(
        &mut core,
        &mut id,
        &shell(),
        "sign.typed_data",
        params(),
        main.all(),
    );
    assert_eq!(sent.len(), 4, "{reply}");
    assert!(sent[2].apdu.starts_with("e01a0000"), "{:?}", sent[2]);
    let parsed =
        fc_evm::typed_data_parse(&typed["domain"], &typed["types"], &typed["message"]).unwrap();
    let mut data = fc_ledger::LedgerPath::parse(LIVE_PATH).unwrap().encode();
    data.extend_from_slice(&parsed.domain_separator);
    data.extend_from_slice(&parsed.struct_hash);
    let mut apdu = vec![0xe0, 0x0c, 0x00, 0x00, u8::try_from(data.len()).unwrap()];
    apdu.extend_from_slice(&data);
    assert_eq!(sent[3].apdu, device::hex(&apdu));
    assert_eq!(sent[3].deadline_ms, CONFIRM_MS);
    let signature = device::unhex(result(&reply)["signature"].as_str().unwrap());
    let signer =
        fc_evm::recover_address(&typed_hash(&typed), &signature.try_into().unwrap()).unwrap();
    assert_eq!(fc_evm::checksum_address(&signer), address_at(LIVE_PATH));
    // The 6D00 without hash_only.
    let mut main = Main::new(Some(&typed));
    main.device.fields = false;
    let (sent, reply) = signed_with(
        &mut core,
        &mut id,
        &shell(),
        "sign.typed_data",
        params(),
        |at, asked| {
            let mut answer = main.answer(asked);
            if at == 2
                && let Reply::Result(result) = &mut answer
            {
                assert_eq!(
                    result.as_object_mut().unwrap().remove("hash_only"),
                    Some(json!("shown"))
                );
            }
            answer
        },
    );
    assert_eq!(ledger_code(&reply), "LEDGER_UNKNOWN");
    assert_eq!(sent.len(), 3);
    drop(core);
    // hash_only beside another answer: the address check's, and a 6D00 to
    // a later definition.
    for at in [0, 3] {
        let root = tempfile::tempdir().unwrap();
        let mut core = start(root.path());
        call(&mut core, 20, &shell(), "sign.typed_data", params());
        let mut main = Main::new(Some(&typed));
        let (sent, held) = drive(&mut core, 20, |index, asked| {
            if index == at {
                Reply::Hold
            } else {
                main.answer(asked)
            }
        });
        assert!(held.is_none());
        let out = sent.last().unwrap();
        let answer = match main.answer(out) {
            Reply::Result(result) if at == 0 => result["answer"].clone(),
            _ => json!("6d00"),
        };
        respond(
            &mut core,
            out.id,
            Reply::Result(json!({ "answer": answer, "hash_only": "shown" })),
        );
        assert_eq!(core.exit_code(Duration::from_secs(10)), 76, "at {at}");
    }
}

/// A core restart mid-operation fails the parent: the core ends with no
/// answer to it, and the next core holds nothing of it, its token unknown
/// and main's late answer to its APDU unsolicited, a protocol error.
#[test]
fn a_restart_fails_the_parent() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path());
    let mut id = 10;
    let token = mint(&mut core, &mut id, Method::Message, LIVE);
    let authorization = Some(Method::Message.page_token(&token));
    id += 1;
    let parent = id;
    call(
        &mut core,
        parent,
        &site(),
        "sign.message",
        Method::Message.params(ledger_key(LIVE), authorization.clone()),
    );
    let mut main = Main::new(None);
    let (sent, held) = drive(&mut core, parent, main.until_confirm());
    assert!(held.is_none());
    let confirm = sent.last().unwrap().clone();
    // Main goes away: the core ends, the parent unanswered.
    core.close_stdin();
    let rest = core.rest();
    assert!(
        !rest
            .iter()
            .any(|m| m["type"] == "response" && m["id"] == parent),
        "{rest:?}"
    );
    core.exit_code(Duration::from_secs(10));
    drop(core);
    let mut core = start(root.path());
    refused(
        &unasked(
            &mut core,
            &mut id,
            &site(),
            "sign.message",
            Method::Message.params(ledger_key(LIVE), authorization),
        ),
        "not_authorized",
        Some("unknown_token"),
    );
    respond(&mut core, confirm.id, main.answer(&confirm));
    assert_eq!(core.exit_code(Duration::from_secs(10)), 76);
}
