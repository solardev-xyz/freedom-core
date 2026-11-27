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
    core.store_moved = if moved { vec!["vault_meta"] } else { Vec::new() };
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
        assert_eq!(apdu.parent, id, "{message}");
        let answer = main(sent.len(), &apdu);
        sent.push(apdu.clone());
        if matches!(answer, Reply::Hold) {
            return (sent, None);
        }
        reply(core, apdu.id, answer);
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
        .map(|r| (r["case"].as_str().unwrap(), r["deviation"].as_str().unwrap()))
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
        let (sent, response) = signed_with(&mut core, &mut id, &context, method, params, |at, asked| {
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
