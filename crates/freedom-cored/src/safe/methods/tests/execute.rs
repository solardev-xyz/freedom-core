//! SAFE-2's S4 against a scripted chain (design 0016, SAFE-2's tests: *The
//! nonce*, *The executor*, and `safe.execute`'s rows of *The setup*,
//! *Unverified* and *Not deployed*): the pending SafeTx executed through
//! the executor's prepared send, its calldata the one the reference sent
//! (`vectors/safe.json`'s flows); the send's `executor-send` token, which
//! `sign.transaction` refuses with any field changed but the nonce; a fee
//! the check stops offered for the user to confirm, then sent as offered;
//! superseded and `safe_nonce_behind`; nothing prepared on a changed
//! setup, an unverified read or no code; the Safe's hold; `safe.executed`;
//! and the token burnt whenever the SafeTx stops being executable.

use fc_evm::Transaction;
use fc_protocol::message::CallerKind;

use fc_vault::state::VaultState;

use super::propose::{
    Flows, OA, OB, OD, OE, S2, S3, S4, SIGNING_READS, chain_for, flow, flows_meta, world,
};
use super::*;
use crate::approvals::Signed;

/// The `legal-12` test phrase (`vectors/keys.json`): D's and E's keys.
const LEGAL: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn shell() -> Context {
    Context {
        caller: CallerKind::Shell,
        page: None,
    }
}

/// Fee evidence of 3 gwei: the executor's 7 gwei is within the check.
fn within(chain: Chain) -> Chain {
    chain.with(
        "reference",
        json!({
            "header": null, "lowest_priority": null, "generation": 0,
            "quote": { "source": "direct", "type": "eip1559", "maxFeePerGas": "3000000000",
                       "answered": 2 },
        }),
    )
}

/// An entry as the reference keeps it: the vector's, with its clock.
fn kept(entry: &Value) -> JsValue {
    let mut entry = entry.clone();
    entry["createdAt"] = json!(5);
    fc_json::parse(&entry.to_string()).unwrap()
}

/// The flows' world with the Safe at `index` at `nonce`, the fee within
/// the check, and `entry` pending for it.
fn pending(index: u64, nonce: u64, entry: &Value) -> Harness {
    let mut h = world(index, nonce);
    h.chain = within(h.chain.clone());
    h.pending.set(index, kept(entry)).unwrap();
    h
}

/// A flow's step: the pending entry before its last `execute`, and that
/// `execute`'s step.
fn executed_step(id: &str) -> (Value, Value) {
    let flow = flow(id);
    let steps = flow["steps"].as_array().unwrap();
    let last = steps.len() - 1;
    assert_eq!(steps[last]["step"], "execute", "{id}");
    let before = steps[..last]
        .iter()
        .rev()
        .find(|step| step.get("pending").is_some_and(Value::is_object))
        .unwrap();
    (before["pending"].clone(), steps[last].clone())
}

impl Harness {
    /// `safe.execute` for the Safe at `index`, with `more` params.
    fn execute(&mut self, index: u64, more: Value) -> Value {
        let mut params = json!({ "safe": index });
        for (key, value) in more.as_object().unwrap() {
            params[key] = value.clone();
        }
        self.call("safe.execute", params)
    }

    /// Main's `sign.transaction` of `send`'s transaction with a nonce,
    /// changed by `edit` first, under `shell` with the send's token: the
    /// authorization's outcome.
    fn spend(&mut self, send: &Value, edit: impl FnOnce(&mut Value)) -> Result<(), ErrorBody> {
        self.spend_as(&shell(), send, edit)
    }

    fn spend_as(
        &mut self,
        context: &Context,
        send: &Value,
        edit: impl FnOnce(&mut Value),
    ) -> Result<(), ErrorBody> {
        let mut tx = send["tx"].clone();
        tx["nonce"] = json!("9");
        edit(&mut tx);
        let parsed = Transaction::from_json(&tx).unwrap();
        let signed = Signed::Transaction {
            account: u32::try_from(send["account"].as_u64().unwrap()).unwrap(),
            tx_json: &tx,
            tx: &parsed,
        };
        let authorization = json!({ "token": send["token"], "kind": send["kind"] });
        self.approvals
            .authorize(context, &authorization, signed, CLOCKS)
            .map(|_| ())
    }

    /// A legacy `safe-send` approval (APR-4's) for the Safe at `index`.
    fn legacy_approval(&mut self, index: u64) {
        let legacy = json!({
            "safe": checksum_address(&Flows::address(index)), "chain_id": "100",
            "tx": { "to": OD, "value": "1", "data": "0x" },
        });
        let mint = json!({ "kind": "safe-send", "account": index, "payload": legacy });
        let issued = self
            .approvals
            .request(1, "approval.issue", &mint, &shell(), CLOCKS)
            .unwrap();
        let issued: Value = serde_json::from_slice(&issued).unwrap();
        let spend = json!({
            "token": issued["result"]["token"], "kind": "safe-send", "account": index,
            "payload": legacy,
        });
        self.approvals
            .request(2, "approval.spend", &spend, &shell(), CLOCKS)
            .unwrap();
    }
}

/// A change main's bug could make to the prepared send.
type Change = Box<dyn Fn(&mut Value)>;

fn reason(error: &ErrorBody) -> &str {
    assert_eq!(error.code, ErrorCode::NotAuthorized, "{error:?}");
    error.data.as_ref().unwrap()["reason"].as_str().unwrap()
}

/// The prepared send, `{ send }`, of an answer.
fn send_of(reply: &Value) -> Value {
    let send = result(reply)["send"].clone();
    assert!(send.is_object(), "{reply}");
    let token = send["token"].as_str().unwrap();
    assert!(
        token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()),
        "{token}"
    );
    send
}

/// The reads of an execution whose fee evidence is asked: the eight, then
/// the quote's.
fn quoted_reads() -> Vec<&'static str> {
    let mut reads = SIGNING_READS.to_vec();
    reads.extend(["estimate", "fee", "reference"]);
    reads
}

// --- The executor's send ------------------------------------------------------

/// Each flow's execution through the core: after the eight reads, the nonce
/// last, the executor's send is `execTransaction` to the Safe with the
/// calldata the reference sent, every counted signature joined, value 0,
/// from the first vault owner, its gas the estimate plus 20% and its fees
/// the core's quote; the token spends on `sign.transaction` at any nonce.
#[test]
fn execute_prepares_the_send_the_reference_sent() {
    for (id, index, nonce) in [
        ("one-of-two", S2, 3),
        ("two-of-three-vault-owners", S3, 4),
        ("three-signatures", S3, 4),
        ("two-of-three-device-owner", S4, 2),
    ] {
        let (entry, step) = executed_step(id);
        let sent = &step["sent"][0];
        let mut h = pending(index, nonce, &entry);
        let reply = h.execute(index, json!({}));
        assert_eq!(h.asked, quoted_reads(), "{id}");
        let send = send_of(&reply);
        assert_eq!(send["kind"], "executor-send");
        assert_eq!(send["account"], 0, "{id}: the first vault owner");
        assert_eq!(
            send["tx"],
            json!({
                "type": 2, "chain_id": "100", "gas_limit": "240000",
                "to": sent["to"], "value": "0", "data": sent["data"],
                "max_fee_per_gas": "7000000000", "max_priority_fee_per_gas": "1000000000",
            }),
            "{id}"
        );
        assert_eq!(sent["executor"], OA);
        // Nothing changes in the store until main says it executed.
        assert_eq!(
            h.entry_at(index).unwrap()["safeTxHash"],
            entry["safeTxHash"]
        );
        // Main adds the nonce: the token spends once.
        assert!(h.spend(&send, |_| {}).is_ok(), "{id}");
        assert_eq!(
            reason(&h.spend(&send, |_| {}).unwrap_err()),
            "unknown_token"
        );
    }
}

/// `sign.transaction` refuses the prepared send with any field changed but
/// the nonce (design 0016, SAFE-2's *The executor*): each change is a
/// `mismatch`, the token burnt; the nonce is main's to choose.
#[test]
fn the_prepared_send_signs_only_as_prepared() {
    let (entry, _) = executed_step("one-of-two");
    let mut h = pending(S2, 3, &entry);
    let changes: Vec<(&str, Change)> = vec![
        (
            "type",
            Box::new(|tx: &mut Value| {
                let object = tx.as_object_mut().unwrap();
                object.remove("max_fee_per_gas");
                object.remove("max_priority_fee_per_gas");
                object.insert("type".into(), json!(0));
                object.insert("gas_price".into(), json!("7000000000"));
            }),
        ),
        (
            "chain_id",
            Box::new(|tx: &mut Value| tx["chain_id"] = json!("1")),
        ),
        (
            "gas_limit",
            Box::new(|tx: &mut Value| tx["gas_limit"] = json!("240001")),
        ),
        ("to", Box::new(|tx: &mut Value| tx["to"] = json!(OB))),
        ("value", Box::new(|tx: &mut Value| tx["value"] = json!("1"))),
        (
            "data",
            Box::new(|tx: &mut Value| {
                // The last signature's `v`, 27 for 28.
                let mut data = tx["data"].as_str().unwrap().to_owned();
                let at = data.rfind("1b").unwrap();
                data.replace_range(at..at + 2, "1c");
                tx["data"] = json!(data);
            }),
        ),
        (
            "max_fee_per_gas",
            Box::new(|tx: &mut Value| {
                tx["max_fee_per_gas"] = json!("7000000001");
            }),
        ),
        (
            "max_priority_fee_per_gas",
            Box::new(|tx: &mut Value| {
                tx["max_priority_fee_per_gas"] = json!("1000000001");
            }),
        ),
    ];
    for (field, change) in &changes {
        let send = send_of(&h.execute(S2, json!({})));
        let error = h.spend(&send, |tx| change(tx));
        assert_eq!(reason(&error.unwrap_err()), "mismatch", "{field}");
        // Burnt with it.
        assert_eq!(
            reason(&h.spend(&send, |_| {}).unwrap_err()),
            "unknown_token"
        );
    }
    for nonce in ["0", "1", "123456"] {
        let send = send_of(&h.execute(S2, json!({})));
        assert!(
            h.spend(&send, |tx| tx["nonce"] = json!(nonce)).is_ok(),
            "{nonce}"
        );
    }
    // Named as another kind, or presented by the chrome: refused, burnt.
    let send = send_of(&h.execute(S2, json!({})));
    let mut wallet = send.clone();
    wallet["kind"] = json!("wallet-send");
    assert_eq!(reason(&h.spend(&wallet, |_| {}).unwrap_err()), "mismatch");
    assert_eq!(
        reason(&h.spend(&send, |_| {}).unwrap_err()),
        "unknown_token"
    );
    let send = send_of(&h.execute(S2, json!({})));
    let chrome = Context {
        caller: CallerKind::Chrome,
        page: None,
    };
    assert_eq!(
        reason(&h.spend_as(&chrome, &send, |_| {}).unwrap_err()),
        "mismatch"
    );
    // Without it, an `execTransaction` signs on no one's word (APR-4b).
    let tx = {
        let mut tx = send["tx"].clone();
        tx["nonce"] = json!("9");
        tx
    };
    let parsed = Transaction::from_json(&tx).unwrap();
    let signed = Signed::Transaction {
        account: 0,
        tx_json: &tx,
        tx: &parsed,
    };
    assert_eq!(
        reason(&crate::approvals::without_authorization(&shell(), &signed).unwrap_err()),
        "no_token"
    );
}

/// A fee the check doesn't approve on its own stops the execution with
/// nothing minted, `{ fee_check }`, as `quotedExecutorSend` stops it;
/// `fee_ack` then gets the send as offered, with no new quote, while the
/// SafeTx and its calldata are the same. A new quote replaces the offer.
#[test]
fn a_fee_the_check_stops_needs_the_users_confirmation() {
    let (entry, step) = executed_step("one-of-two");
    let mut h = pending(S2, 3, &entry);
    // Fee evidence of 2 gwei: 7 gwei is above three times it.
    h.chain = chain_for(S2, 3);
    let reply = h.execute(S2, json!({}));
    let fee_check = &result(&reply)["fee_check"];
    assert_eq!(fee_check["above"], true, "{reply}");
    assert_eq!(fee_check["autoApprove"], false);
    assert_eq!(fee_check["askAgain"], true);
    assert!(result(&reply).get("send").is_none());
    assert_eq!(h.asked, quoted_reads());
    // Confirmed: the offer, without a quote, though the quote moved since.
    h.chain = h
        .chain
        .clone()
        .with("estimate", json!("0x40000"))
        .served("fee", Serve::Failed);
    h.asked.clear();
    let send = send_of(&h.execute(S2, json!({ "fee_ack": true })));
    assert_eq!(h.asked, SIGNING_READS);
    assert_eq!(send["tx"]["gas_limit"], "240000");
    assert_eq!(send["tx"]["max_fee_per_gas"], "7000000000");
    assert_eq!(send["tx"]["data"], step["sent"][0]["data"]);
    assert!(h.spend(&send, |_| {}).is_ok());
    // Confirmed again: the same offer, while it stands.
    let again = send_of(&h.execute(S2, json!({ "fee_ack": true })));
    assert_eq!(again["tx"], send["tx"]);
    // Asked without `fee_ack`: quoted again, and the new quote is offered.
    h.chain = h.chain.clone().served("fee", Serve::Verified);
    h.asked.clear();
    let reply = h.execute(S2, json!({}));
    assert_eq!(result(&reply)["fee_check"]["above"], true, "{reply}");
    let send = send_of(&h.execute(S2, json!({ "fee_ack": true })));
    assert_eq!(send["tx"]["gas_limit"], "314572", "0x40000 plus 20%");
    // The SafeTx's calldata changed (a signature more): the offer no longer
    // stands, and `fee_ack` confirms no fee the user wasn't shown.
    let (three, _) = executed_step("three-signatures");
    let mut h = pending(S3, 4, &executed_step("two-of-three-vault-owners").0);
    h.chain = chain_for(S3, 4);
    assert!(result(&h.execute(S3, json!({}))).get("fee_check").is_some());
    h.pending.set(S3, kept(&three)).unwrap();
    let reply = h.execute(S3, json!({ "fee_ack": true }));
    assert!(result(&reply).get("fee_check").is_some(), "{reply}");
    // No evidence at all: nothing to compare, so the user confirms.
    let mut h = pending(S2, 3, &entry);
    h.chain = chain_for(S2, 3).served("reference", Serve::Failed);
    let reply = h.execute(S2, json!({}));
    let fee_check = &result(&reply)["fee_check"];
    assert_eq!(fee_check["comparable"], false, "{reply}");
    assert_eq!(fee_check["autoApprove"], false);
}

// --- The nonce ----------------------------------------------------------------

/// A Safe nonce past the SafeTx's: superseded, as the reference marks it:
/// the Safe's `safe-send` approvals ended, the entry marked
/// `superseded: true` (`vectors/safe.json`'s `superseded` flow), the
/// board's state with `status: "superseded"`, and the Safe's prepared send
/// burnt.
#[test]
fn a_nonce_past_the_safe_txs_is_superseded() {
    let flow = flow("superseded");
    let start = &flow["steps"][0];
    let execute = &flow["steps"][2];
    assert_eq!(execute["step"], "execute");
    let mut h = pending(S2, 3, &start["pending"]);
    let send = send_of(&h.execute(S2, json!({})));
    h.legacy_approval(S2);
    h.chain = within(chain_for(S2, 4));
    let reply = h.execute(S2, json!({}));
    let state = &result(&reply)["superseded"];
    let reference = &execute["state"];
    for key in [
        "chainId",
        "safeTxHash",
        "threshold",
        "collected",
        "owners",
        "executorIndex",
        "call",
        "status",
    ] {
        assert_eq!(state[key], reference[key], "{key}");
    }
    assert_eq!(state["safeIndex"], S2);
    // The entry, as the reference writes it, `superseded` last.
    let mut entry = h.entry_at(S2).unwrap();
    entry.as_object_mut().unwrap().shift_remove("createdAt");
    assert_eq!(entry, execute["pending"]);
    let keys: Vec<&String> = entry.as_object().unwrap().keys().collect();
    let expected: Vec<&String> = execute["pending"].as_object().unwrap().keys().collect();
    assert_eq!(keys, expected);
    assert_eq!(h.approvals.end_safe_sends(&Flows::address(S2)), 0);
    assert_eq!(
        reason(&h.spend(&send, |_| {}).unwrap_err()),
        "unknown_token"
    );
    // The board shows it superseded; asked again, superseded again.
    let states = result(&h.call("safe.pending", json!({})))["states"].clone();
    assert_eq!(states[0]["status"], "superseded");
    let reply = h.execute(S2, json!({}));
    assert_eq!(result(&reply)["superseded"]["status"], "superseded");
}

/// A Safe nonce below the SafeTx's: `safe_nonce_behind` (deviation
/// `nonce-behind`; the `nonce-behind` flow's `core`), nothing prepared.
#[test]
fn a_nonce_below_the_safe_txs_is_nonce_behind() {
    let flow = flow("nonce-behind");
    assert_eq!(flow["core"]["refused"], "nonce_behind");
    let start = &flow["steps"][0]["pending"];
    let mut h = pending(S2, 2, start);
    let before = std::fs::read(h.path()).unwrap();
    let reply = h.execute(S2, json!({}));
    assert_eq!(refusal(&reply), "nonce_behind");
    assert_eq!(
        reply["error"]["message"],
        "The Safe's nonce on Gnosis is below this transaction's, so Freedom won't sign it. Try again."
    );
    assert_eq!(h.asked, SIGNING_READS);
    assert_eq!(std::fs::read(h.path()).unwrap(), before);
}

/// Below the record's threshold of signatures that count: the reference's
/// refusal, after the reads, nothing prepared (the `two-of-three-device-
/// owner` flow's first `execute`).
#[test]
fn fewer_signatures_than_the_threshold_prepare_nothing() {
    let flow = flow("two-of-three-device-owner");
    let error = &flow["steps"][1]["error"]["message"];
    let mut h = pending(S4, 2, &flow["steps"][0]["pending"]);
    let reply = h.execute(S4, json!({}));
    assert_eq!(reply["error"]["message"], *error, "{reply}");
    assert_eq!(reply["error"]["code"], "invalid_argument");
    assert_eq!(h.asked, SIGNING_READS);
    // A signature that doesn't count (another SafeTx's) adds nothing.
    let mut entry = flow["steps"][0]["pending"].clone();
    let stray = flow["steps"][2]["pending"]["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["signer"] == OD)
        .unwrap()
        .clone();
    let mut stray = stray;
    let data = stray["data"].as_str().unwrap().to_owned();
    stray["data"] = json!(format!("{}00", &data[..data.len() - 2]));
    entry["signatures"].as_array_mut().unwrap().push(stray);
    let mut h = pending(S4, 2, &entry);
    let reply = h.execute(S4, json!({}));
    assert_eq!(reply["error"]["message"], *error, "{reply}");
}

// --- What an execution refuses ------------------------------------------------

#[test]
fn execute_refuses_before_any_read() {
    let (entry, _) = executed_step("one-of-two");
    // Nothing pending.
    let mut h = world(S2, 3);
    let reply = h.execute(S2, json!({}));
    assert_eq!(
        reply["error"]["message"],
        "No pending transaction for this account"
    );
    // Another SafeTx named.
    h.pending.set(S2, kept(&entry)).unwrap();
    let reply = h.execute(S2, json!({ "safe_tx_hash": to_hex(&[0x11; 32]) }));
    assert_eq!(refusal(&reply), "SAFE_DISCARDED");
    // Not a hash, or another member.
    let reply = h.execute(S2, json!({ "safe_tx_hash": "0x11" }));
    assert_eq!(reply["error"]["code"], "invalid_argument");
    let reply = h.execute(S2, json!({ "fee_ack": "yes" }));
    assert_eq!(reply["error"]["code"], "invalid_argument");
    let reply = h.execute(S2, json!({ "tx": {} }));
    assert_eq!(reply["error"]["code"], "invalid_argument");
    // An entry the codec sets aside: nothing executes it.
    let mut bad = entry.clone();
    bad["safeTxData"]["value"] = json!("1");
    h.pending.set(S2, kept(&bad)).unwrap();
    let reply = h.execute(S2, json!({}));
    assert_eq!(
        reply["error"]["message"],
        "No pending transaction for this account"
    );
    assert!(h.asked.is_empty());
    // A Safe the record doesn't mark deployed: nothing read.
    let mut h = Harness::new(flows_meta(true), chain_for(S2, 3));
    h.pending.set(S2, kept(&entry)).unwrap();
    let reply = h.execute(S2, json!({}));
    assert_eq!(refusal(&reply), "not_deployed");
    assert!(h.asked.is_empty());
    // The store not moved, then `vault_meta` not moved.
    let mut h = pending(S2, 3, &entry);
    let unmoved = SafePending::new();
    unmoved.configure(h._dir.path().to_owned(), false);
    h.pending = unmoved;
    let reply = h.execute(S2, json!({}));
    assert_eq!(reply["error"]["data"]["store"], "safe_pending", "{reply}");
    h.approvals.set_records(None);
    let reply = h.execute(S2, json!({}));
    assert_eq!(reply["error"]["data"]["store"], "vault_meta", "{reply}");
    let reply = h.call(
        "safe.executed",
        json!({ "safe": S2, "safe_tx_hash": entry["safeTxHash"], "hash": to_hex(&[1; 32]) }),
    );
    assert_eq!(reply["error"]["data"]["store"], "vault_meta", "{reply}");
    assert!(h.asked.is_empty());
}

#[test]
fn a_changed_setup_or_a_read_not_evidence_prepares_nothing() {
    let (entry, _) = executed_step("one-of-two");
    let mut handler = word(&FALLBACK_HANDLER);
    handler[31] ^= 1;
    let base = || within(chain_for(S2, 3));
    for (chain, changed) in [
        (base().with("threshold", hex_words(&[uint(2)])), "threshold"),
        (
            base().with("owners", owner_list(&[address(OA), address(OD)])),
            "owners",
        ),
        (
            base().with("guard", hex_words(&[word(&[0x99; 20])])),
            "guard",
        ),
        (base().with("handler", hex_words(&[handler])), "handler"),
        (
            base().with(
                "modules",
                hex_words(&[uint(0x40), word(&SENTINEL), uint(1), word(&[0x99; 20])]),
            ),
            "module",
        ),
        (
            base().with("singleton", hex_words(&[word(&[0x99; 20])])),
            "singleton",
        ),
    ] {
        let mut h = pending(S2, 3, &entry);
        h.chain = chain;
        let reply = h.execute(S2, json!({}));
        assert_eq!(refusal(&reply), "changed", "{changed}");
        assert!(!h.asked.contains(&"estimate"), "{changed}");
    }
    // Each of the eight unverified in turn, while it reports the record's
    // value; a reverted call; no code, verified.
    for read in SIGNING_READS {
        let mut h = pending(S2, 3, &entry);
        h.chain = base().served(read, Serve::Unverified);
        let reply = h.execute(S2, json!({}));
        assert_eq!(refusal(&reply), "unverified", "{read}");
        assert_eq!(
            reply["error"]["message"],
            "Freedom couldn't verify this Safe on Gnosis, so it won't sign. Try again, or add an \
             RPC provider in Settings."
        );
        assert!(!h.asked.contains(&"estimate"), "{read}");
    }
    let mut h = pending(S2, 3, &entry);
    h.chain = base().served("nonce", Serve::Failed);
    assert_eq!(refusal(&h.execute(S2, json!({}))), "unverified");
    let mut h = pending(S2, 3, &entry);
    h.chain = base().with("code", json!("0x"));
    assert_eq!(refusal(&h.execute(S2, json!({}))), "not_deployed");
    assert_eq!(h.asked, ["code"]);
    // A failed estimate is its failure, nothing minted.
    let mut h = pending(S2, 3, &entry);
    h.chain = base().served("estimate", Serve::Failed);
    let reply = h.execute(S2, json!({}));
    assert_eq!(reply["error"]["code"], "chain_error");
    assert_eq!(
        reply["error"]["message"],
        "Gas estimation failed: execution reverted"
    );
    // No vault owner to pay: the reference's refusal, once the threshold
    // is met (a Safe of D and E, 1 of 2, D's signature).
    let devices = setup_of(&[OD, OE], 1);
    let safe = devices.address(&parse_salt("1").unwrap());
    let mut meta = flows_meta(false);
    for record in meta["derivedWallets"].as_array_mut().unwrap() {
        if record["index"] == S4 {
            record["owners"] = json!([1_000_000, 1_000_001]);
            record["threshold"] = json!(1);
            record["address"] = json!(checksum_address(&safe));
        }
    }
    let chain = within(chain_for(S4, 2))
        .with("owners", owner_list(devices.owners()))
        .with("threshold", hex_words(&[uint(1)]));
    let mut h = Harness::new(meta, chain);
    let tx = fc_safe::SafeTx::new(address(OB), U256::from_u64(1), vec![], 2).unwrap();
    let hash = tx.hash(&safe).unwrap();
    let mut ledger = VaultState::new();
    let ticket = ledger.ticket();
    let phrase = fc_keys::Mnemonic::parse(LEGAL).unwrap();
    ledger
        .install(ticket, fc_vault::state::Prepared::new(phrase), 0, 0)
        .unwrap();
    let signature =
        fc_evm::sign_digest(ledger.user_wallet(0).unwrap().signing_key(), &hash).unwrap();
    let entry = json!({
        "chainId": 100, "safeAddress": checksum_address(&safe), "safeTxData": tx.fields(),
        "safeTxHash": to_hex(&hash), "threshold": 1,
        "signatures": [{ "signer": OD, "data": to_hex(&signature) }],
    });
    h.pending.set(S4, kept(&entry)).unwrap();
    let reply = h.execute(S4, json!({}));
    assert_eq!(
        reply["error"]["message"],
        "No browser account among the owners to act as executor \u{2014} choose one that can \
         pay gas",
        "{reply}"
    );
    assert!(!h.asked.contains(&"estimate"));
    // With no signature, the threshold's refusal comes first, as the
    // reference counts before it picks the executor.
    let mut unsigned = entry;
    unsigned["signatures"] = json!([]);
    h.pending.set(S4, kept(&unsigned)).unwrap();
    let reply = h.execute(S4, json!({}));
    assert_eq!(
        reply["error"]["message"],
        "Not enough signatures yet (0 of 1)"
    );
}

// --- The hold, and the entry read again ------------------------------------

#[test]
fn an_execution_holds_its_safe() {
    let (entry, _) = executed_step("one-of-two");
    let mut h = pending(S2, 3, &entry);
    h.hold = true;
    let outs = h.send("safe.execute", json!({ "safe": S2 }));
    assert!(h.drive(outs).is_none());
    let reply = h.call("safe.discard", json!({ "safe": S2 }));
    assert_eq!(refusal(&reply), "SAFE_BUSY");
    assert_eq!(
        reply["error"]["message"],
        "Wait for the current step to finish first"
    );
    let outs = h.send("safe.execute", json!({ "safe": S2 }));
    let reply = h.drive(outs).unwrap();
    assert_eq!(refusal(&reply), "SAFE_BUSY");
    assert_eq!(
        reply["error"]["message"],
        "Another step of this transaction is still running"
    );
    let reply = h.call(
        "safe.propose",
        json!({ "safe": S2, "safe_tx_hash": entry["safeTxHash"],
                "authorization": { "token": "00".repeat(32) } }),
    );
    assert_eq!(refusal(&reply), "SAFE_PENDING_EXISTS");
    // The cancel ends the hold.
    assert!(!h.safes.cancel(9).is_empty());
    h.hold = false;
    h.held.clear();
    let reply = h.call("safe.discard", json!({ "safe": S2 }));
    assert_eq!(result(&reply), &json!({}));
}

/// An entry replaced or cleared while the reads were out: `SAFE_DISCARDED`,
/// nothing prepared, as `executeSafePending` refuses it.
#[test]
fn an_entry_replaced_meanwhile_is_discarded() {
    let (entry, _) = executed_step("one-of-two");
    let (other, _) = executed_step("superseded");
    let mut other = other;
    other["safeTxData"]["value"] = json!("1");
    for replace in [true, false] {
        let mut h = pending(S2, 3, &entry);
        h.hold = true;
        let outs = h.send("safe.execute", json!({ "safe": S2 }));
        assert!(h.drive(outs).is_none());
        if replace {
            let tx = fc_safe::SafeTx::new(address(OD), U256::from_u64(1), vec![], 3).unwrap();
            let mut replaced = entry.clone();
            replaced["safeTxData"] = tx.fields();
            replaced["safeTxHash"] = json!(to_hex(&tx.hash(&Flows::address(S2)).unwrap()));
            replaced["signatures"] = json!([]);
            h.pending.set(S2, kept(&replaced)).unwrap();
        } else {
            h.pending.clear(S2).unwrap();
        }
        h.hold = false;
        let mut queue = Vec::new();
        for read in std::mem::take(&mut h.held) {
            let payload = payload(&h.chain, &read);
            queue.extend(h.safes.chain_read(read.tag, &payload, false, ctx!(h)));
        }
        let reply = h.drive(queue).unwrap();
        assert_eq!(refusal(&reply), "SAFE_DISCARDED", "{replace}");
        assert!(!h.asked.contains(&"estimate"));
    }
}

// --- `safe.executed`, and the token's end -----------------------------------

#[test]
fn executed_clears_only_the_safe_tx_it_names() {
    let (entry, _) = executed_step("one-of-two");
    let mut h = pending(S2, 3, &entry);
    let send = send_of(&h.execute(S2, json!({})));
    h.legacy_approval(S2);
    let hash = to_hex(&[0xe1; 32]);
    // Another SafeTx named: nothing cleared, nothing ended.
    let reply = h.call(
        "safe.executed",
        json!({ "safe": S2, "safe_tx_hash": to_hex(&[0x11; 32]), "hash": hash }),
    );
    assert_eq!(refusal(&reply), "SAFE_DISCARDED");
    assert!(h.entry_at(S2).is_some());
    // Not hashes: refused.
    let reply = h.call(
        "safe.executed",
        json!({ "safe": S2, "safe_tx_hash": entry["safeTxHash"], "hash": "0x01" }),
    );
    assert_eq!(reply["error"]["code"], "invalid_argument");
    // The SafeTx named: its approvals ended, its entry cleared, its send
    // burnt.
    let reply = h.call(
        "safe.executed",
        json!({ "safe": S2, "safe_tx_hash": entry["safeTxHash"], "hash": hash }),
    );
    assert_eq!(result(&reply), &json!({}));
    assert!(h.entry_at(S2).is_none());
    assert_eq!(h.approvals.end_safe_sends(&Flows::address(S2)), 0);
    assert_eq!(
        reason(&h.spend(&send, |_| {}).unwrap_err()),
        "unknown_token"
    );
    // Told again: nothing pending, nothing to do.
    let reply = h.call(
        "safe.executed",
        json!({ "safe": S2, "safe_tx_hash": entry["safeTxHash"], "hash": hash }),
    );
    assert_eq!(result(&reply), &json!({}));
    assert!(h.asked.len() == quoted_reads().len(), "it reads no chain");
}

/// Each Safe has one outstanding prepared send: a newer one burns the
/// older, and so do the Safe's discard and its record's removal.
#[test]
fn a_prepared_send_ends_when_its_safe_tx_can_no_longer_execute() {
    let (entry, _) = executed_step("one-of-two");
    let mut h = pending(S2, 3, &entry);
    let first = send_of(&h.execute(S2, json!({})));
    let second = send_of(&h.execute(S2, json!({})));
    assert_eq!(
        reason(&h.spend(&first, |_| {}).unwrap_err()),
        "unknown_token"
    );
    assert!(h.spend(&second, |_| {}).is_ok());
    // Discarded.
    let send = send_of(&h.execute(S2, json!({})));
    assert_eq!(
        result(&h.call("safe.discard", json!({ "safe": S2 }))),
        &json!({})
    );
    assert_eq!(
        reason(&h.spend(&send, |_| {}).unwrap_err()),
        "unknown_token"
    );
    // The Safe's record removed.
    let mut h = pending(S2, 3, &entry);
    let send = send_of(&h.execute(S2, json!({})));
    h.meta["derivedWallets"]
        .as_array_mut()
        .unwrap()
        .retain(|record| record["index"] != S2);
    h.records();
    assert_eq!(
        reason(&h.spend(&send, |_| {}).unwrap_err()),
        "unknown_token"
    );
    // Another Safe's send stands.
    let mut h = pending(S2, 3, &entry);
    h.pending
        .set(S3, kept(&executed_step("two-of-three-vault-owners").0))
        .unwrap();
    let s2 = send_of(&h.execute(S2, json!({})));
    h.chain = within(chain_for(S3, 4));
    let s3 = send_of(&h.execute(S3, json!({})));
    assert!(h.spend(&s2, |_| {}).is_ok());
    assert!(h.spend(&s3, |_| {}).is_ok());
}

/// The deployment is the executor's send too (design 0016, "The executor":
/// it goes the same way): judged as `quotedExecutorSend` judges it, so a
/// fee with no evidence to compare is offered, not sent, and `fee_ack`
/// sends exactly the offer, the balance read again; a `fee_ack` with no
/// offer standing confirms nothing.
#[test]
fn a_deployment_is_judged_and_confirmed_as_an_execution_is() {
    let legacy = json!({ "type": "legacy", "gasPrice": "2000000000", "source": "quorum",
                         "verified": true, "generation": 0 });
    let mut h = Harness::new(
        meta(false),
        Chain::undeployed()
            .with("fee", legacy)
            .served("reference", Serve::Failed),
    );
    let reply = h.call("safe.deploy", json!({ "safe": SAFE }));
    let fee_check = &result(&reply)["fee_check"];
    assert_eq!(fee_check["comparable"], false, "{reply}");
    assert_eq!(fee_check["autoApprove"], false);
    // Confirmed: the offer, though the quote moved since.
    h.chain = h.chain.clone().with("estimate", json!("0x40000"));
    h.asked.clear();
    let reply = h.call("safe.deploy", json!({ "safe": SAFE, "fee_ack": true }));
    let send = send_of(&reply);
    assert_eq!(send["tx"]["gas_limit"], "240000");
    assert_eq!(send["tx"]["gas_price"], "2000000000");
    assert_eq!(h.asked, ["code", "estimate", "fee", "balance", "reference"]);
    // A `fee_ack` with no offer standing: the new quote is offered.
    let mut h = Harness::new(meta(false), Chain::undeployed());
    let reply = h.call("safe.deploy", json!({ "safe": SAFE, "fee_ack": true }));
    assert_eq!(result(&reply)["fee_check"]["above"], true, "{reply}");
}
