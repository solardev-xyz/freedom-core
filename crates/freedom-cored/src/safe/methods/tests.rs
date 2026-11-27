//! S2's methods against a scripted chain (design 0016, SAFE-2's tests:
//! `safe.create` reads nothing; *Deployed*; *Not deployed*; *The store*),
//! each read answered as the chain thread writes its reply, and the
//! labels through the chain thread's own machine where they decide.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use base64::Engine as _;
use fc_safe::constants::{FALLBACK_HANDLER, SENTINEL, SINGLETON};
use fc_safe::reads::Query;

use super::*;
use crate::chain::scripted::Scripted;

const A: &str = "0x1111111111111111111111111111111111111111";
const B: &str = "0x2222222222222222222222222222222222222222";
const C: &str = "0x4444444444444444444444444444444444444444";
const LEDGER: &str = "0x5555555555555555555555555555555555555555";
const PHONE: &str = "0x6666666666666666666666666666666666666666";
const SAFE: u64 = 1_000_001;
const SALT: u64 = 7;
const CLOCKS: Clocks = Clocks {
    vault_ms: 10_000,
    wall_ms: 1_700_000_000_000,
};

fn address(text: &str) -> [u8; 20] {
    fc_wallet_state::address_bytes(text).unwrap()
}

fn setup_of(owners: &[&str], threshold: usize) -> Setup {
    Setup::new(owners.iter().map(|o| address(o)).collect(), threshold).unwrap()
}

/// The Safe of owners 0 and 1, 1 of 2, salt 7.
fn setup() -> Setup {
    setup_of(&[A, B], 1)
}

fn safe_address() -> [u8; 20] {
    setup().address(&U256::from_u64(SALT))
}

/// `vault-meta.json`: two vault accounts, a Ledger, a phone and `safe`.
fn meta_with(safe: Value) -> Value {
    json!({
        "userKnowsPassword": true,
        "addresses": { "userWallet": A, "beeWallet": C },
        "derivedWallets": [
            { "index": 0, "name": "Wallet 1", "address": A },
            { "index": 1, "name": "Wallet 2", "address": B },
            { "index": 1_000_000, "name": "Ledger 1", "address": LEDGER, "type": "ledger",
              "path": "m/44'/60'/0'/0/0", "addressCheck": "matched" },
            { "index": 1_000_003, "name": "Phone 1", "address": PHONE, "type": "remote",
              "addressCheck": "matched" },
            safe,
        ],
        "activeWalletIndex": 0,
        "nextHardwareWalletIndex": 1_000_004,
    })
}

fn safe_record(owners: &[u64], addresses: &[&str], threshold: usize, marked: bool) -> Value {
    let address = checksum_address(&setup_of(addresses, threshold).address(&U256::from_u64(SALT)));
    json!({
        "index": SAFE, "name": "Safe 1", "address": address, "type": "safe",
        "owners": owners, "threshold": threshold, "saltNonce": SALT.to_string(),
        "deployed": if marked { json!({ "100": { "verified": true } }) } else { json!({}) },
    })
}

fn meta(marked: bool) -> Value {
    meta_with(safe_record(&[0, 1], &[A, B], 1, marked))
}

fn word(bytes: &[u8]) -> [u8; 32] {
    let mut word = [0; 32];
    word[32 - bytes.len()..].copy_from_slice(bytes);
    word
}

fn uint(value: u64) -> [u8; 32] {
    word(&value.to_be_bytes())
}

fn hex_words(words: &[[u8; 32]]) -> Value {
    json!(to_hex(&words.concat()))
}

fn owner_list(owners: &[[u8; 20]]) -> Value {
    let mut words = vec![uint(0x20), uint(owners.len() as u64)];
    words.extend(owners.iter().map(|owner| word(owner)));
    hex_words(&words)
}

const HASH: [u8; 32] = [0xab; 32];

/// The deployment's receipt as a node gives it.
fn receipt() -> Value {
    json!({
        "transactionHash": to_hex(&HASH),
        "status": "0x1",
        "logs": [
            { "address": to_hex(&[0x77; 20]), "topics": [to_hex(&[0x01; 32])], "data": "0x" },
            {
                "address": to_hex(&PROXY_FACTORY),
                "topics": [
                    to_hex(&keccak256(PROXY_CREATION.as_bytes())),
                    to_hex(&word(&safe_address())),
                ],
                "data": to_hex(&word(&SINGLETON)),
            },
        ],
    })
}

/// How a read is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Serve {
    Verified,
    Unverified,
    Failed,
}

/// What Gnosis shows, by read name (`code`, `receipt`, `estimate`, `fee`,
/// `balance`, `reference`, and the setup reads' names).
#[derive(Clone)]
struct Chain {
    answers: BTreeMap<&'static str, Value>,
    serve: BTreeMap<&'static str, Serve>,
}

impl Chain {
    /// The Safe deployed as Freedom made it, nonce 7; a deployment priced
    /// at 200,000 gas and 7 gwei; the executor holding 1 xDAI; fee
    /// evidence of 2 gwei.
    fn deployed() -> Self {
        let answers = BTreeMap::from([
            (
                "code",
                json!("0x608060405273ffffffffffffffffffffffffffffffffffffffff"),
            ),
            ("singleton", hex_words(&[word(&SINGLETON)])),
            ("owners", owner_list(&[address(A), address(B)])),
            ("threshold", hex_words(&[uint(1)])),
            ("guard", hex_words(&[[0; 32]])),
            ("handler", hex_words(&[word(&FALLBACK_HANDLER)])),
            (
                "modules",
                hex_words(&[uint(0x40), word(&SENTINEL), uint(0)]),
            ),
            ("nonce", hex_words(&[uint(7)])),
            ("receipt", receipt()),
            ("estimate", json!("0x30d40")),
            (
                "fee",
                json!({
                    "type": "eip1559", "baseFee": "1", "maxPriorityFeePerGas": "1000000000",
                    "maxFeePerGas": "7000000000", "effectiveGasPrice": "1000000001",
                    "source": "quorum", "verified": true, "generation": 0,
                }),
            ),
            ("balance", json!("0xde0b6b3a7640000")),
            (
                "reference",
                json!({
                    "header": null, "lowest_priority": null, "generation": 0,
                    "quote": { "source": "direct", "type": "eip1559", "maxFeePerGas": "2000000000",
                               "answered": 2 },
                }),
            ),
        ]);
        Chain {
            answers,
            serve: BTreeMap::new(),
        }
    }

    /// Not deployed: no code.
    fn undeployed() -> Self {
        Chain::deployed().with("code", json!("0x"))
    }

    fn with(mut self, name: &'static str, answer: Value) -> Self {
        self.answers.insert(name, answer);
        self
    }

    fn served(mut self, name: &'static str, serve: Serve) -> Self {
        self.serve.insert(name, serve);
        self
    }
}

/// Which read `read` is.
fn name_of(read: &ChainRead) -> &'static str {
    match read.method {
        "eth_getCode" => "code",
        "eth_getTransactionReceipt" => "receipt",
        "eth_estimateGas" => "estimate",
        "eth_getBalance" => "balance",
        crate::chain::INTERNAL_FEE_QUOTE => "fee",
        crate::chain::INTERNAL_FEE_REFERENCE => "reference",
        method => {
            let params: Value = serde_json::from_str(&read.params).unwrap();
            fc_safe::Read::ALL
                .into_iter()
                .find(|r| {
                    let query = r.query();
                    query.method() == method
                        && match &query {
                            Query::Code => true,
                            Query::Storage(slot) => params[1] == to_hex(slot),
                            Query::Call(data) => params[0]["data"] == to_hex(data),
                        }
                })
                .unwrap_or_else(|| panic!("{method} {params}"))
                .name()
        }
    }
}

/// The chain thread's reply to `read`, from `chain`.
fn payload(chain: &Chain, read: &ChainRead) -> Vec<u8> {
    let name = name_of(read);
    let serve = chain.serve.get(name).copied().unwrap_or(Serve::Verified);
    let answer = chain.answers[name].clone();
    let message = match (serve, name) {
        (Serve::Failed, _) => json!({
            "type": "response", "id": read.tag,
            "error": { "code": "chain_error", "message": "execution reverted" },
        }),
        (_, "fee" | "reference") => {
            let mut answer = answer;
            if name == "fee" {
                answer["verified"] = json!(serve == Serve::Verified);
            }
            json!({ "type": "response", "id": read.tag, "result": answer })
        }
        _ => json!({
            "type": "response", "id": read.tag,
            "result": {
                "result": answer,
                "source": if serve == Serve::Verified { "quorum" } else { "direct" },
                "verified": serve == Serve::Verified,
                "generation": 0,
            },
        }),
    };
    serde_json::to_vec(&message).unwrap()
}

/// The methods, the approvals and the pending store, with the vault's mark
/// played by the test: it sets the record's verified mark.
struct Harness {
    safes: Safes,
    approvals: Approvals,
    pending: SafePending,
    _dir: tempfile::TempDir,
    meta: Value,
    chain: Chain,
    /// The reads made, by name, in order.
    asked: Vec<&'static str>,
    /// The indices marked.
    marked: Vec<u64>,
    now: Instant,
    /// Reads held back, unanswered.
    hold: bool,
    held: Vec<ChainRead>,
}

macro_rules! ctx {
    ($h:expr) => {
        &mut Ctx {
            approvals: &mut $h.approvals,
            pending: &$h.pending,
            clocks: CLOCKS,
            now: $h.now,
        }
    };
}

impl Harness {
    fn new(meta: Value, chain: Chain) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let pending = SafePending::new();
        pending.configure(dir.path().to_owned(), true);
        let mut harness = Harness {
            safes: Safes::new(),
            approvals: Approvals::new(),
            pending,
            _dir: dir,
            meta,
            chain,
            asked: Vec::new(),
            marked: Vec::new(),
            now: Instant::now(),
            hold: false,
            held: Vec::new(),
        };
        harness.records();
        harness
    }

    /// The records' snapshot, taken as the vault's `refresh_records` takes
    /// it: the session's reports follow it.
    fn records(&mut self) {
        let meta = VaultMeta::load(self.meta.to_string().as_bytes()).unwrap();
        self.approvals.set_records(Some(Records::Read(meta)));
        self.safes.records_changed(self.approvals.account_records());
    }

    /// The Safe's record removed, and the snapshot taken again.
    fn remove_safe(&mut self) {
        self.meta["derivedWallets"]
            .as_array_mut()
            .unwrap()
            .retain(|record| record["index"] != SAFE);
        self.records();
    }

    fn path(&self) -> std::path::PathBuf {
        self._dir
            .path()
            .join(fc_wallet_state::safe_pending::FILE_NAME)
    }

    /// Request `method`, every read answered from the chain: its reply.
    fn call(&mut self, method: &str, params: Value) -> Value {
        let outs = self.send(method, params);
        self.drive(outs).expect("no reply")
    }

    fn send(&mut self, method: &str, params: Value) -> Vec<Out> {
        self.safes
            .request(9, method, Some(&params.to_string()), ctx!(self))
    }

    /// Answers each read, and plays the vault's mark: the reply, if any.
    fn drive(&mut self, outs: Vec<Out>) -> Option<Value> {
        let mut queue: VecDeque<Out> = outs.into();
        let mut answer = None;
        loop {
            for (id, index, at) in self.safes.take_marks() {
                assert_eq!(at, safe_address());
                self.marked.push(index);
                for record in self.meta["derivedWallets"].as_array_mut().unwrap() {
                    if record["index"] == index {
                        record["deployed"] = json!({ "100": { "verified": true } });
                    }
                }
                self.records();
                queue.extend(self.safes.marked(id, Ok(()), ctx!(self)));
            }
            let Some(out) = queue.pop_front() else {
                return answer;
            };
            match out {
                Out::Send(payload) => {
                    assert!(answer.is_none(), "two replies");
                    answer = Some(serde_json::from_slice::<Value>(&payload).unwrap());
                }
                Out::ChainRead(read) => {
                    assert!(is_safe_tag(read.tag));
                    assert_eq!(read.chain_id, 100);
                    assert!(read.deadline_ms <= DEADLINE_MS && read.deadline_ms > 0);
                    self.asked.push(name_of(&read));
                    if self.hold {
                        self.held.push(read);
                        continue;
                    }
                    let payload = payload(&self.chain, &read);
                    queue.extend(self.safes.chain_read(read.tag, &payload, false, ctx!(self)));
                }
                _ => panic!("unexpected out"),
            }
        }
    }
}

fn is_safe_tag(tag: u64) -> bool {
    super::super::evidence::is_safe_tag(tag)
}

fn result(reply: &Value) -> &Value {
    assert!(reply.get("error").is_none(), "{reply}");
    &reply["result"]
}

/// A refusal's `data.safe`, or its code.
fn refusal(reply: &Value) -> String {
    let error = &reply["error"];
    assert!(error.is_object(), "{reply}");
    error["data"]["safe"]
        .as_str()
        .map_or_else(|| error["code"].as_str().unwrap().to_owned(), str::to_owned)
}

/// `safe.status`'s reads of a deployed Safe: the code and the six setup
/// reads, no nonce.
const STATUS_READS: [&str; 7] = [
    "code",
    "singleton",
    "owners",
    "threshold",
    "guard",
    "handler",
    "modules",
];

// --- `safe.create` -----------------------------------------------------

#[test]
fn create_computes_the_address_from_the_records_with_no_read() {
    let meta = VaultMeta::load(meta(false).to_string().as_bytes()).unwrap();
    let (address, salt) = created(
        &meta,
        &fc_json::parse("[0,1]").unwrap(),
        &JsValue::Number(1.0),
    )
    .unwrap();
    let salt = U256::parse_decimal(salt.as_str().unwrap()).unwrap();
    assert!(salt.bits() <= 128);
    assert_eq!(
        address.as_str().unwrap(),
        checksum_address(&setup().address(&salt))
    );
    // Two draws, two salts.
    let (again, _) = created(
        &meta,
        &fc_json::parse("[0,1]").unwrap(),
        &JsValue::Number(1.0),
    )
    .unwrap();
    assert_ne!(address, again);
    // A Ledger owner's address is its record's too.
    let (with_ledger, salt) = created(
        &meta,
        &fc_json::parse("[0,1,1000000]").unwrap(),
        &JsValue::Number(2.0),
    )
    .unwrap();
    let salt = U256::parse_decimal(salt.as_str().unwrap()).unwrap();
    assert_eq!(
        with_ledger.as_str().unwrap(),
        checksum_address(&setup_of(&[A, B, LEDGER], 2).address(&salt))
    );
}

#[test]
fn create_refuses_as_the_reference_does() {
    let meta = VaultMeta::load(meta(false).to_string().as_bytes()).unwrap();
    let refused = |owners: &str, threshold: f64| {
        created(
            &meta,
            &fc_json::parse(owners).unwrap(),
            &JsValue::Number(threshold),
        )
        .unwrap_err()
        .message
    };
    assert_eq!(refused("[0,9]", 1.0), "Owner wallet index 9 does not exist");
    assert_eq!(
        refused("[0,1]", 2.0),
        "A Safe needs 1 of 2 or 2 of 3 owners"
    );
    assert_eq!(refused("[0]", 1.0), "A Safe needs 1 of 2 or 2 of 3 owners");
    assert_eq!(refused("[0,0]", 1.0), "Duplicate owner accounts");
    assert_eq!(refused("{}", 1.0), "A Safe needs 1 of 2 or 2 of 3 owners");
}

// --- `safe.status` -------------------------------------------------------

#[test]
fn status_of_an_undeployed_safe_prices_its_activation() {
    let mut h = Harness::new(meta(false), Chain::undeployed());
    let reply = h.call("safe.status", json!({ "safe": SAFE }));
    assert_eq!(
        result(&reply),
        &json!({
            "deployed": false, "chainId": 100, "executorIndex": 0, "executorAddress": A,
            "executorBalance": "1000000000000000000",
            // 200,000 gas plus 20%, at 7 gwei.
            "estimatedCost": "1680000000000000", "needsFunds": false,
            "setup": { "state": "not_deployed" },
        })
    );
    // Display only: no fee evidence, no setup read.
    assert_eq!(h.asked, ["code", "estimate", "fee", "balance"]);
    assert!(h.marked.is_empty());
    // The balance and cost keep their labels and block nothing.
    let mut h = Harness::new(
        meta(false),
        Chain::undeployed()
            .with("balance", json!("0x1"))
            .served("balance", Serve::Unverified)
            .served("estimate", Serve::Unverified),
    );
    let reply = h.call("safe.status", json!({ "safe": SAFE }));
    assert_eq!(result(&reply)["needsFunds"], true);
    assert_eq!(result(&reply)["executorBalance"], "1");
}

#[test]
fn status_with_no_vault_owner_needs_funds_and_reads_no_price() {
    let meta = meta_with(safe_record(
        &[1_000_000, 1_000_003],
        &[LEDGER, PHONE],
        1,
        false,
    ));
    let mut h = Harness::new(meta, Chain::undeployed());
    let reply = h.call("safe.status", json!({ "safe": SAFE }));
    assert_eq!(
        result(&reply),
        &json!({
            "deployed": false, "chainId": 100, "executorIndex": null, "executorAddress": null,
            "executorBalance": null, "estimatedCost": null, "needsFunds": true,
            "setup": { "state": "not_deployed" },
        })
    );
    assert_eq!(h.asked, ["code"]);
}

#[test]
fn status_of_a_marked_safe_reads_its_setup_and_no_nonce() {
    let mut h = Harness::new(meta(true), Chain::deployed());
    let reply = h.call("safe.status", json!({ "safe": SAFE }));
    assert_eq!(
        result(&reply),
        &json!({
            "deployed": true, "chainId": 100, "executorIndex": 0, "executorAddress": A,
            "executorBalance": null, "estimatedCost": null, "needsFunds": false,
            "setup": { "state": "unchanged" },
        })
    );
    // Seven reads answered, the nonce not among them.
    assert_eq!(h.asked, STATUS_READS);
}

/// `safe.status` of the marked Safe on `chain`: its `setup`, and the reads
/// the chain answered.
fn marked_status(chain: Chain) -> (Value, Vec<&'static str>) {
    let mut h = Harness::new(meta(true), chain);
    let reply = h.call("safe.status", json!({ "safe": SAFE }));
    let status = result(&reply);
    assert_eq!(status["deployed"], true, "{reply}");
    assert_eq!(status["executorIndex"], 0);
    assert_eq!(status["needsFunds"], false);
    assert!(!h.asked.contains(&"nonce"), "{:?}", h.asked);
    (status["setup"].clone(), h.asked)
}

#[test]
fn status_reports_each_setup_state_as_data() {
    // `changed`, naming what changed as `check_setup` does: never a
    // refusal, since status signs nothing.
    let mut handler = word(&FALLBACK_HANDLER);
    handler[31] ^= 1;
    for (chain, changed) in [
        (
            Chain::deployed().with("threshold", hex_words(&[uint(2)])),
            json!(["threshold"]),
        ),
        (
            Chain::deployed().with("owners", owner_list(&[address(A), address(B), address(C)])),
            json!(["owners"]),
        ),
        (
            Chain::deployed().with("guard", hex_words(&[word(&[0x99; 20])])),
            json!(["guard"]),
        ),
        (
            Chain::deployed().with(
                "modules",
                hex_words(&[uint(0x40), word(&SENTINEL), uint(1), word(&[0x99; 20])]),
            ),
            json!(["module"]),
        ),
        (
            Chain::deployed()
                .with("singleton", hex_words(&[word(&[0x99; 20])]))
                .with("handler", hex_words(&[handler])),
            json!(["singleton", "handler"]),
        ),
    ] {
        let (setup, asked) = marked_status(chain);
        assert_eq!(setup, json!({ "state": "changed", "changed": changed }));
        assert_eq!(asked, STATUS_READS);
    }
    // `unverified`, naming the read and why: each of the seven answered
    // unverified in turn. An unverified code ends the check there.
    for read in STATUS_READS {
        let (setup, asked) = marked_status(Chain::deployed().served(read, Serve::Unverified));
        assert_eq!(
            setup,
            json!({ "state": "unverified", "read": read, "why": "unverified" }),
            "{read}"
        );
        let expected: &[&str] = if read == "code" {
            &["code"]
        } else {
            &STATUS_READS
        };
        assert_eq!(asked, expected, "{read}");
    }
    // A reverted call, and an answer that isn't Safe 1.4.1's encoding.
    let (setup, _) = marked_status(Chain::deployed().served("owners", Serve::Failed));
    assert_eq!(
        setup,
        json!({ "state": "unverified", "read": "owners", "why": "failed" })
    );
    let (setup, _) = marked_status(Chain::deployed().with("threshold", json!("0x02")));
    assert_eq!(
        setup,
        json!({ "state": "unverified", "read": "threshold", "why": "length" })
    );
    // `not_deployed`: no code, verified, where the record marks it.
    let (setup, asked) = marked_status(Chain::undeployed());
    assert_eq!(setup, json!({ "state": "not_deployed" }));
    assert_eq!(asked, ["code"]);
}

#[test]
fn a_nonce_status_doesnt_read_fails_nothing() {
    // The code and the six setup reads verified, the nonce unverified,
    // reverting or unreadable: a normal status, the nonce never asked.
    for chain in [
        Chain::deployed().served("nonce", Serve::Unverified),
        Chain::deployed().served("nonce", Serve::Failed),
        Chain::deployed().with("nonce", json!("0x")),
    ] {
        let mut h = Harness::new(meta(true), chain);
        let reply = h.call("safe.status", json!({ "safe": SAFE }));
        assert_eq!(
            result(&reply),
            &json!({
                "deployed": true, "chainId": 100, "executorIndex": 0, "executorAddress": A,
                "executorBalance": null, "estimatedCost": null, "needsFunds": false,
                "setup": { "state": "unchanged" },
            })
        );
        assert_eq!(h.asked, STATUS_READS);
    }
}

#[test]
fn status_of_an_unmarked_safe_reports_its_code_read() {
    // No code, but unverified: the activation is priced, and the code's
    // read is named unverified.
    let mut h = Harness::new(
        meta(false),
        Chain::undeployed().served("code", Serve::Unverified),
    );
    let reply = h.call("safe.status", json!({ "safe": SAFE }));
    assert_eq!(result(&reply)["deployed"], false);
    assert_eq!(result(&reply)["estimatedCost"], "1680000000000000");
    assert_eq!(
        result(&reply)["setup"],
        json!({ "state": "unverified", "read": "code", "why": "unverified" })
    );
    // Code, unverified: the session's report, its read named.
    let mut h = Harness::new(
        meta(false),
        Chain::deployed().served("code", Serve::Unverified),
    );
    let reply = h.call("safe.status", json!({ "safe": SAFE }));
    assert_eq!(
        result(&reply),
        &json!({
            "deployed": true, "chainId": 100, "executorIndex": 0, "executorAddress": A,
            "executorBalance": null, "estimatedCost": null, "needsFunds": false,
            "setup": { "state": "unverified", "read": "code", "why": "unverified" },
        })
    );
    assert_eq!(h.asked, ["code"]);
    // Then a failed read: still the session's, the failure named.
    h.chain = Chain::deployed().served("code", Serve::Failed);
    let reply = h.call("safe.status", json!({ "safe": SAFE }));
    assert_eq!(result(&reply)["deployed"], true);
    assert_eq!(
        result(&reply)["setup"],
        json!({ "state": "unverified", "read": "code", "why": "failed" })
    );
    // A code read nothing answered, neither marked nor reported: no
    // `deployed` to give, so `isDeployedOnChain`'s failure.
    let mut h = Harness::new(meta(false), Chain::deployed().served("code", Serve::Failed));
    let reply = h.call("safe.status", json!({ "safe": SAFE }));
    assert_eq!(refusal(&reply), "unverified");
    assert_eq!(reply["error"]["message"], ACTIVATION_UNVERIFIED_TEXT);
}

#[test]
fn status_marks_a_safe_whose_verified_code_shows_it() {
    let mut h = Harness::new(meta(false), Chain::deployed());
    let reply = h.call("safe.status", json!({ "safe": SAFE }));
    assert_eq!(result(&reply)["deployed"], true);
    assert_eq!(result(&reply)["setup"], json!({ "state": "unchanged" }));
    assert_eq!(h.marked, [SAFE]);
    // The mark, then the setup check, without the nonce.
    let mut expected = vec!["code"];
    expected.extend(STATUS_READS);
    assert_eq!(h.asked, expected);
}

// --- `safe.deploy` -------------------------------------------------------

#[test]
fn deploy_prepares_the_executors_deployment() {
    let mut h = Harness::new(meta(false), Chain::undeployed());
    // Fee evidence of 2 gwei: 7 gwei is above the check's threshold.
    let reply = h.call("safe.deploy", json!({ "safe": SAFE }));
    let fee_check = &result(&reply)["fee_check"];
    assert_eq!(fee_check["above"], true, "{reply}");
    assert_eq!(fee_check["askAgain"], true);
    assert_eq!(h.asked, ["code", "estimate", "fee", "balance", "reference"]);
    // Confirmed: the send, the evidence still fresh.
    h.asked.clear();
    let reply = h.call("safe.deploy", json!({ "safe": SAFE, "fee_ack": true }));
    let deployment = setup().deployment(&U256::from_u64(SALT));
    assert_eq!(
        result(&reply),
        &json!({ "send": { "account": 0, "tx": {
            "type": 2, "chain_id": "100", "gas_limit": "240000",
            "to": checksum_address(&PROXY_FACTORY), "value": "0",
            "data": to_hex(&deployment.data),
            "max_fee_per_gas": "7000000000", "max_priority_fee_per_gas": "1000000000",
        } } })
    );
    assert_eq!(h.asked, ["code", "estimate", "fee", "balance"]);
    assert!(h.marked.is_empty());
    // Within the check: the send at once.
    let mut h = Harness::new(
        meta(false),
        Chain::undeployed().with(
            "fee",
            json!({ "type": "legacy", "gasPrice": "2000000000", "source": "quorum",
                    "verified": true, "generation": 0 }),
        ),
    );
    let reply = h.call("safe.deploy", json!({ "safe": SAFE }));
    let tx = &result(&reply)["send"]["tx"];
    assert_eq!(tx["type"], 0, "{reply}");
    assert_eq!(tx["gas_price"], "2000000000");
}

#[test]
fn deploy_refuses_what_cant_pay() {
    let mut h = Harness::new(
        meta(false),
        Chain::undeployed().with("balance", json!("0x0")),
    );
    let reply = h.call("safe.deploy", json!({ "safe": SAFE, "fee_ack": true }));
    assert_eq!(refusal(&reply), "SAFE_NEEDS_FUNDS");
    assert_eq!(
        reply["error"]["message"],
        format!("Fund {A} with at least 0.00168 xDAI to activate")
    );
    let devices = meta_with(safe_record(
        &[1_000_000, 1_000_003],
        &[LEDGER, PHONE],
        1,
        false,
    ));
    let mut h = Harness::new(devices, Chain::undeployed());
    let reply = h.call("safe.deploy", json!({ "safe": SAFE }));
    assert_eq!(refusal(&reply), "SAFE_NEEDS_FUNDS");
    assert_eq!(reply["error"]["message"], NO_EXECUTOR_TEXT);
    // A failed estimate is its failure, worded as estimateGas words it.
    let mut h = Harness::new(
        meta(false),
        Chain::undeployed().served("estimate", Serve::Failed),
    );
    let reply = h.call("safe.deploy", json!({ "safe": SAFE }));
    assert_eq!(reply["error"]["code"], "chain_error");
    assert_eq!(
        reply["error"]["message"],
        "Gas estimation failed: execution reverted"
    );
}

#[test]
fn deploy_of_a_deployed_safe_sends_nothing() {
    let mut h = Harness::new(meta(true), Chain::deployed());
    let reply = h.call("safe.deploy", json!({ "safe": SAFE }));
    assert_eq!(result(&reply), &json!({ "deployed": true }));
    assert!(h.asked.is_empty());
}

// --- `safe.deployed` (D4) ----------------------------------------------

fn deployed(chain: Chain) -> (Value, Harness) {
    let mut h = Harness::new(meta(false), chain);
    let reply = h.call(
        "safe.deployed",
        json!({ "safe": SAFE, "hash": to_hex(&HASH) }),
    );
    (reply, h)
}

#[test]
fn a_verified_receipt_of_the_deployment_marks_it() {
    let (reply, h) = deployed(Chain::undeployed());
    assert_eq!(result(&reply), &json!({ "deployed": true }));
    assert_eq!(h.marked, [SAFE]);
    // The receipt alone decides.
    assert_eq!(h.asked, ["receipt"]);
}

#[test]
fn a_receipt_that_isnt_the_deployments_marks_nothing() {
    let topic = to_hex(&keccak256(PROXY_CREATION.as_bytes()));
    let log = |address: &[u8; 20], topic: &str, named: &[u8; 20]| json!({ "address": to_hex(address), "topics": [topic, to_hex(&word(named))], "data": "0x" });
    let with = |status: &str, logs: Vec<Value>, hash: [u8; 32]| json!({ "transactionHash": to_hex(&hash), "status": status, "logs": logs });
    let other = to_hex(&keccak256(b"Other(address,address)"));
    let good = log(&PROXY_FACTORY, &topic, &safe_address());
    for receipt in [
        // Status 0.
        with("0x0", vec![good.clone()], HASH),
        // Another address's creation.
        with("0x1", vec![log(&PROXY_FACTORY, &topic, &address(C))], HASH),
        // Not from the factory.
        with("0x1", vec![log(&[0x77; 20], &topic, &safe_address())], HASH),
        // Another event.
        with(
            "0x1",
            vec![log(&PROXY_FACTORY, &other, &safe_address())],
            HASH,
        ),
        // No log.
        with("0x1", vec![], HASH),
        // Another transaction's.
        with("0x1", vec![good.clone()], [0xcd; 32]),
        // None yet.
        Value::Null,
    ] {
        let (reply, h) = deployed(Chain::undeployed().with("receipt", receipt.clone()));
        assert_eq!(result(&reply), &json!({ "deployed": false }), "{receipt}");
        assert!(h.marked.is_empty(), "{receipt}");
        assert_eq!(h.asked, ["receipt", "code"]);
    }
    // The code, verified, still marks it.
    let (reply, h) = deployed(Chain::deployed().with("receipt", with("0x0", vec![good], HASH)));
    assert_eq!(result(&reply), &json!({ "deployed": true }));
    assert_eq!(h.marked, [SAFE]);
}

#[test]
fn an_unverified_answer_is_the_sessions_and_marks_nothing() {
    // An unverified receipt and an unverified code read, each showing the
    // deployment.
    for chain in [
        Chain::undeployed()
            .served("receipt", Serve::Unverified)
            .served("code", Serve::Unverified),
        Chain::deployed()
            .with("receipt", Value::Null)
            .served("code", Serve::Unverified),
    ] {
        let (reply, mut h) = deployed(chain);
        assert_eq!(
            result(&reply),
            &json!({ "deployed": true, "verified": false })
        );
        assert!(h.marked.is_empty());
        // The session's report: deployed, with nothing marked, while no read
        // is verified.
        h.chain = Chain::deployed().served("code", Serve::Unverified);
        let status = h.call("safe.status", json!({ "safe": SAFE }));
        assert_eq!(result(&status)["deployed"], true);
        h.chain = Chain::undeployed().served("code", Serve::Failed);
        let status = h.call("safe.status", json!({ "safe": SAFE }));
        assert_eq!(result(&status)["deployed"], true);
        assert!(h.marked.is_empty());
        let deploy = h.call("safe.deploy", json!({ "safe": SAFE }));
        assert_eq!(result(&deploy), &json!({ "deployed": true }));
        // A verified empty code ends it.
        h.chain = Chain::undeployed();
        let status = h.call("safe.status", json!({ "safe": SAFE }));
        assert_eq!(result(&status)["deployed"], false);
        // And a verified one marks it.
        h.chain = Chain::deployed();
        let status = h.call("safe.status", json!({ "safe": SAFE }));
        assert_eq!(result(&status)["deployed"], true);
        assert_eq!(h.marked, [SAFE]);
    }
}

#[test]
fn an_empty_or_unanswered_code_marks_nothing() {
    let (reply, h) = deployed(Chain::undeployed().with("receipt", Value::Null));
    assert_eq!(result(&reply), &json!({ "deployed": false }));
    assert!(h.marked.is_empty());
    let (reply, h) = deployed(
        Chain::undeployed()
            .with("receipt", Value::Null)
            .served("code", Serve::Unverified),
    );
    assert_eq!(result(&reply), &json!({ "deployed": false }));
    assert!(h.marked.is_empty());
    // Nothing answered: the reference's refusal, nothing marked.
    let (reply, h) = deployed(
        Chain::deployed()
            .served("receipt", Serve::Failed)
            .served("code", Serve::Failed),
    );
    assert_eq!(refusal(&reply), "unverified");
    assert_eq!(reply["error"]["message"], DEPLOYMENT_UNVERIFIED_TEXT);
    assert!(h.marked.is_empty());
}

#[test]
fn a_removed_safes_session_report_goes_with_its_record() {
    let (reply, mut h) = deployed(
        Chain::undeployed()
            .served("receipt", Serve::Unverified)
            .served("code", Serve::Unverified),
    );
    assert_eq!(
        result(&reply),
        &json!({ "deployed": true, "verified": false })
    );
    assert_eq!(h.safes.session, BTreeSet::from([safe_address()]));
    // A snapshot that still holds the Safe keeps its report.
    h.meta["activeWalletIndex"] = json!(1);
    h.records();
    assert_eq!(h.safes.session.len(), 1);
    // Its record removed: the report goes.
    h.remove_safe();
    assert!(h.safes.session.is_empty());
}

#[test]
fn an_answer_for_a_safe_no_record_holds_adds_nothing() {
    for method in ["safe.deployed", "safe.status"] {
        let chain = Chain::undeployed()
            .served("receipt", Serve::Unverified)
            .served("code", Serve::Unverified);
        let chain = if method == "safe.status" {
            chain.with("code", Chain::deployed().answers["code"].clone())
        } else {
            chain
        };
        let mut h = Harness::new(meta(false), chain);
        h.hold = true;
        let params = if method == "safe.status" {
            json!({ "safe": SAFE })
        } else {
            json!({ "safe": SAFE, "hash": to_hex(&HASH) })
        };
        let outs = h.send(method, params);
        let outs = if method == "safe.status" {
            outs
        } else {
            // `safe.deployed`'s receipt, then its code read, held.
            assert!(h.drive(outs).is_none());
            let read = h.held.pop().unwrap();
            h.safes
                .chain_read(read.tag, &payload(&h.chain, &read), false, ctx!(h))
        };
        assert!(h.drive(outs).is_none());
        // The record goes while the code read is out.
        h.remove_safe();
        h.hold = false;
        let read = h.held.pop().unwrap();
        assert_eq!(name_of(&read), "code");
        let outs = h
            .safes
            .chain_read(read.tag, &payload(&h.chain, &read), false, ctx!(h));
        let reply = h.drive(outs).unwrap();
        assert_eq!(result(&reply)["deployed"], true, "{method} {reply}");
        assert!(h.safes.session.is_empty(), "{method}");
    }
    // A snapshot keeps only the reports of the Safes its records hold.
    let mut h = Harness::new(meta(false), Chain::deployed());
    h.safes.session.insert(safe_address());
    h.records();
    assert_eq!(h.safes.session.len(), 1);
    h.safes.session.insert([0x99; 20]);
    h.records();
    assert_eq!(h.safes.session, BTreeSet::from([safe_address()]));
}

/// Gnosis's snapshot: `read_order` over endpoints `a` and `b`, quorum 2 of
/// 2, no Colibri.
fn gnosis(read_order: &[&str]) -> Value {
    json!({
        "chain_id": 100,
        "display_name": "Gnosis Chain",
        "read_order": read_order,
        "broadcast_order": ["direct"],
        "quorum": { "k": 2, "m": 2, "timeout_ms": 5000 },
        "rpc": [
            { "endpoint": "a", "user_configured": false },
            { "endpoint": "b", "user_configured": false },
        ],
        "prover": null,
        "myotis": false,
        "blockscout": null,
    })
}

/// `safe.deployed` through the chain thread's own machine, main answering
/// every endpoint from `chain` but those `down`: whether it marked.
fn deployed_through(config: Value, down: &[&str], chain: &Chain) -> (Value, Vec<u64>) {
    let mut thread = Scripted::new(json!([config]));
    let mut h = Harness::new(meta(false), chain.clone());
    h.hold = true;
    let outs = h.send(
        "safe.deployed",
        json!({ "safe": SAFE, "hash": to_hex(&HASH) }),
    );
    assert!(h.drive(outs).is_none());
    for _ in 0..10_000 {
        for read in std::mem::take(&mut h.held) {
            thread.internal(read);
        }
        for frame in thread.written() {
            if frame["type"] != "request" {
                continue;
            }
            assert_eq!(frame["method"], "shell.rpc", "{frame}");
            let id = frame["id"].as_u64().unwrap();
            let params = &frame["params"];
            if down.contains(&params["endpoint"].as_str().unwrap()) {
                thread.answer(id, Err(ErrorBody::new(ErrorCode::Network, "unreachable")));
                continue;
            }
            let body: Value = serde_json::from_str(params["body"].as_str().unwrap()).unwrap();
            let name = match body["method"].as_str().unwrap() {
                "eth_getCode" => "code",
                "eth_getTransactionReceipt" => "receipt",
                other => panic!("{other}"),
            };
            let text = json!({ "jsonrpc": "2.0", "id": body["id"], "result": chain.answers[name] });
            thread.answer(
                id,
                Ok(json!({
                    "status": 200,
                    "body": base64::engine::general_purpose::STANDARD.encode(text.to_string()),
                })),
            );
        }
        thread.tick(1);
        for (tag, payload, past_due) in thread.served() {
            let outs = h.safes.chain_read(tag, &payload, past_due, ctx!(h));
            if let Some(reply) = h.drive(outs) {
                return (reply, h.marked);
            }
        }
    }
    panic!("never answered");
}

#[test]
fn only_two_agreeing_endpoints_verify_the_mark() {
    // Direct alone, and a quorum one endpoint answered: unverified, the
    // session's.
    for (order, down) in [(&["direct"][..], &[][..]), (&["quorum", "direct"], &["b"])] {
        let (reply, marked) = deployed_through(gnosis(order), down, &Chain::deployed());
        assert_eq!(
            result(&reply),
            &json!({ "deployed": true, "verified": false })
        );
        assert!(marked.is_empty(), "{order:?}");
    }
    // A quorum of two that agree: the receipt verified, and marked.
    let (reply, marked) = deployed_through(gnosis(&["quorum", "direct"]), &[], &Chain::deployed());
    assert_eq!(result(&reply), &json!({ "deployed": true }));
    assert_eq!(marked, [SAFE]);
}

// --- Every request -----------------------------------------------------

#[test]
fn a_record_that_isnt_its_address_is_refused_before_any_read() {
    let mut record = safe_record(&[0, 1], &[A, B], 1, false);
    record["address"] = json!(C);
    for method in ["safe.status", "safe.deploy"] {
        let mut h = Harness::new(meta_with(record.clone()), Chain::deployed());
        let reply = h.call(method, json!({ "safe": SAFE }));
        assert_eq!(refusal(&reply), "SAFE_ADDRESS_MISMATCH");
        assert!(h.asked.is_empty());
    }
    let mut h = Harness::new(meta(false), Chain::deployed());
    let reply = h.call("safe.status", json!({ "safe": 0 }));
    assert_eq!(reply["error"]["message"], "Wallet 0 is not a Safe account");
    for params in [
        json!({}),
        json!({ "safe": -1 }),
        json!({ "safe": 1.5 }),
        json!({ "safe": SAFE, "x": 1 }),
    ] {
        assert_eq!(refusal(&h.call("safe.status", params)), "invalid_argument");
    }
    let reply = h.call("safe.deployed", json!({ "safe": SAFE, "hash": "0x12" }));
    assert_eq!(refusal(&reply), "invalid_argument");
    assert!(h.asked.is_empty());
}

#[test]
fn nothing_is_served_before_vault_meta_moves() {
    let mut h = Harness::new(meta(false), Chain::deployed());
    h.approvals.set_records(None);
    for method in [
        "safe.status",
        "safe.deploy",
        "safe.deployed",
        "safe.pending",
        "safe.discard",
    ] {
        let reply = h.call(method, json!({ "safe": SAFE }));
        assert_eq!(reply["error"]["code"], "not_moved", "{method}");
        assert_eq!(reply["error"]["data"]["store"], "vault_meta");
    }
    assert!(h.asked.is_empty());
}

#[test]
fn a_cancel_or_the_deadline_ends_a_request() {
    let mut h = Harness::new(meta(true), Chain::deployed());
    h.hold = true;
    let outs = h.send("safe.status", json!({ "safe": SAFE }));
    assert!(h.drive(outs).is_none());
    let reply: Value = match h.safes.cancel(9).pop() {
        Some(Out::Send(payload)) => serde_json::from_slice(&payload).unwrap(),
        _ => panic!("no reply"),
    };
    assert_eq!(reply["error"]["code"], "cancelled");
    assert!(h.safes.cancel(9).is_empty());
    // Its late reply changes nothing.
    let held = std::mem::take(&mut h.held);
    let late = payload(&h.chain, &held[0]);
    assert!(
        h.safes
            .chain_read(held[0].tag, &late, false, ctx!(h))
            .is_empty()
    );
    // The bound: 120 s from receipt.
    let outs = h.send("safe.status", json!({ "safe": SAFE }));
    assert!(h.drive(outs).is_none());
    let at = h.safes.next_wakeup().unwrap();
    assert_eq!(at, h.now + Duration::from_millis(120_000));
    assert!(h.safes.tick(at - Duration::from_millis(1)).is_empty());
    let reply: Value = match h.safes.tick(at).pop() {
        Some(Out::Send(payload)) => serde_json::from_slice(&payload).unwrap(),
        _ => panic!("no reply"),
    };
    assert_eq!(reply["error"]["code"], "deadline");
    assert_eq!(h.safes.next_wakeup(), None);
    // A read that failed past its deadline is the deadline.
    let outs = h.send("safe.status", json!({ "safe": SAFE }));
    assert!(h.drive(outs).is_none());
    let read = h.held.pop().unwrap();
    let outs = h
        .safes
        .chain_read(read.tag, &payload(&h.chain, &read), true, ctx!(h));
    h.hold = false;
    assert_eq!(h.drive(outs).unwrap()["error"]["code"], "deadline");
}

#[test]
fn the_bound_is_the_session_class() {
    let row = fc_protocol::methods::method("safe.status").unwrap();
    assert_eq!(row.deadline.default_ms(), Some(DEADLINE_MS));
}

// --- The pending store (D3) ----------------------------------------------

fn entry(hash: &str, created_at: u64, signers: &[&str]) -> Value {
    json!({
        "chainId": 100, "safeAddress": checksum_address(&safe_address()),
        "safeTxData": { "to": C, "value": "5", "data": "0x" },
        "safeTxHash": hash, "threshold": 1,
        "display": { "symbol": "xDAI", "amount": "5" },
        "signatures": signers.iter().map(|s| json!({ "signer": s, "data": "0x" })).collect::<Vec<_>>(),
        "createdAt": created_at,
    })
}

#[test]
fn pending_renders_each_entry_as_the_board_does() {
    let mut h = Harness::new(meta(false), Chain::deployed());
    let file = json!({
        SAFE.to_string(): entry("0xaa", 20, &["0x1111111111111111111111111111111111111111"]),
        "7": entry("0xbb", 10, &[]),
        "8": "not an entry",
    });
    std::fs::write(h.path(), file.to_string()).unwrap();
    let reply = h.call("safe.pending", json!({}));
    let states = result(&reply)["states"].as_array().unwrap();
    // Oldest first; the one the view can't read left out.
    assert_eq!(states.len(), 2);
    assert_eq!(states[0]["safeIndex"], 7);
    // No Safe record at 7: no owners, no executor.
    assert_eq!(states[0]["owners"], json!([]));
    assert_eq!(states[0]["executorIndex"], Value::Null);
    assert_eq!(
        states[1],
        json!({
            "safeIndex": SAFE, "chainId": 100, "safeTxHash": "0xaa", "threshold": 1,
            "collected": 1,
            "owners": [
                { "index": 0, "address": A, "type": "mnemonic", "signed": true },
                { "index": 1, "address": B, "type": "mnemonic", "signed": false },
            ],
            "executorIndex": 0, "display": { "symbol": "xDAI", "amount": "5" },
            "call": { "to": C, "value": "5", "data": "0x" },
            "createdAt": 20, "status": "awaiting",
        })
    );
    assert!(h.asked.is_empty());
}

#[test]
fn discard_ends_the_sends_approval_then_clears_its_entry() {
    let mut h = Harness::new(meta(false), Chain::deployed());
    let file = json!({ SAFE.to_string(): entry("0xaa", 20, &[]) });
    std::fs::write(h.path(), file.to_string()).unwrap();
    // Another SafeTx named: nothing discarded.
    let reply = h.call(
        "safe.discard",
        json!({ "safe": SAFE, "safe_tx_hash": "0xbb" }),
    );
    assert_eq!(refusal(&reply), "SAFE_DISCARDED");
    assert!(h.pending.entry(SAFE).is_some());
    let reply = h.call(
        "safe.discard",
        json!({ "safe": SAFE, "safe_tx_hash": "0xaa" }),
    );
    assert_eq!(result(&reply), &json!({}));
    assert!(h.pending.entry(SAFE).is_none());
    assert_eq!(std::fs::read(h.path()).unwrap(), b"{}");
    // Nothing pending: nothing to do, but a named one is refused.
    assert_eq!(
        result(&h.call("safe.discard", json!({ "safe": SAFE }))),
        &json!({})
    );
    let reply = h.call(
        "safe.discard",
        json!({ "safe": SAFE, "safe_tx_hash": "0xaa" }),
    );
    assert_eq!(refusal(&reply), "SAFE_DISCARDED");
    // Before the store moves: main's file, untouched.
    let pending = SafePending::new();
    pending.configure(h._dir.path().to_owned(), false);
    h.pending = pending;
    std::fs::write(h.path(), file.to_string()).unwrap();
    let reply = h.call("safe.discard", json!({ "safe": SAFE }));
    assert_eq!(reply["error"]["code"], "not_moved");
    assert_eq!(reply["error"]["data"]["store"], "safe_pending");
    assert!(h.pending.entry(SAFE).is_some());
}

/// A file of `size` bytes holding one entry at `SAFE`, padded in its
/// display.
fn file_of(size: usize) -> Vec<u8> {
    let mut entry = entry("0xaa", 20, &[]);
    entry["display"]["pad"] = json!("");
    let base = json!({ SAFE.to_string(): entry.clone() }).to_string().len();
    entry["display"]["pad"] = json!("x".repeat(size - base));
    let text = json!({ SAFE.to_string(): entry }).to_string();
    assert_eq!(text.len(), size);
    text.into_bytes()
}

#[test]
fn the_store_holds_one_mib_and_sets_aside_a_byte_more() {
    const MIB: usize = 1024 * 1024;
    let mut h = Harness::new(meta(false), Chain::deployed());
    std::fs::write(h.path(), file_of(MIB)).unwrap();
    let reply = h.call("safe.pending", json!({}));
    assert_eq!(result(&reply)["states"].as_array().unwrap().len(), 1);
    let reply = h.call("safe.discard", json!({ "safe": SAFE }));
    assert_eq!(result(&reply), &json!({}));
    assert_eq!(std::fs::read(h.path()).unwrap(), b"{}");
    // A byte past the bound: unreadable, renamed aside, and the store reads
    // as empty.
    std::fs::write(h.path(), file_of(MIB + 1)).unwrap();
    let reply = h.call("safe.pending", json!({}));
    assert_eq!(result(&reply)["states"], json!([]));
    assert!(!h.path().exists());
    let aside = h._dir.path().join("safe-pending.json.unreadable");
    assert_eq!(std::fs::read(aside).unwrap().len(), MIB + 1);
    // A discard then has nothing to clear.
    assert_eq!(
        result(&h.call("safe.discard", json!({ "safe": SAFE }))),
        &json!({})
    );
}

// --- Arithmetic ------------------------------------------------------------

#[test]
fn ether_is_formatted_as_ethers_formats_it() {
    let ether = |wei: &str| format_ether(&U256::parse_decimal(wei).unwrap());
    assert_eq!(ether("0"), "0.0");
    assert_eq!(ether("1"), "0.000000000000000001");
    assert_eq!(ether("1680000000000000"), "0.00168");
    assert_eq!(ether("1000000000000000000"), "1.0");
    assert_eq!(ether("12345000000000000000000"), "12345.0");
    assert_eq!(ether("1500000000000000001"), "1.500000000000000001");
}

#[test]
fn the_cost_is_exact_to_two_to_the_256() {
    let big = |text: &str| U256::parse_decimal(text).unwrap();
    assert_eq!(
        mul(240_000, &big("7000000000")),
        Some(big("1680000000000000"))
    );
    assert_eq!(mul(0, &big("7")), Some(U256::from_u64(0)));
    // u64::MAX × 2^128.
    let two_128 = big("340282366920938463463374607431768211456");
    assert_eq!(
        mul(u64::MAX, &two_128),
        Some(big(
            "6277101735386680763495507056286727952638980837032266301440"
        ))
    );
    // Past 2^256.
    let max = big("115792089237316195423570985008687907853269984665640564039457584007913129639935");
    assert_eq!(mul(2, &max), None);
    assert_eq!(mul(1, &max), Some(max));
}
