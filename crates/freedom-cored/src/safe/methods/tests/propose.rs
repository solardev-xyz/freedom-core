//! SAFE-2's S3 against a scripted chain (design 0016, SAFE-2's tests): a
//! SafeTx prepared at the verified nonce and proposed with the token that
//! binds it whole (D6); the vault owners signing at `safe.propose`, the
//! entry the reference writes (`vectors/safe.json`'s flows); `safe_changed`,
//! `safe_unverified`, `not_deployed` and `safe_self_call` with nothing
//! signed or written; the Safe's hold; an entry set aside; the 1 MiB edge;
//! and a reload.

use std::path::PathBuf;

use fc_protocol::message::{CallerKind, PageContext};
use fc_vault::state::VaultState;

use super::*;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// The flows' owners (`vectors/safe.json`'s `owners`): A, B and C the
/// vault's accounts 0 to 2, D a Ledger, E a phone.
pub(super) const OA: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
pub(super) const OB: &str = "0x78839F6054d7ed13918bAe0473BA31b1Ca9D7265";
pub(super) const OC: &str = "0x07B5FdfEB4E11826D233403Fe8Db0611CCF4c231";
pub(super) const OD: &str = "0x58A57ed9d8d624cBD12e2C467D34787555bB1b25";
pub(super) const OE: &str = "0x44f649fc8Dc77694E6ABEF1aA966983Dd6ED7C64";
/// The flows' Safes, at these indices.
pub(super) const S2: u64 = 1_000_002;
pub(super) const S3: u64 = 1_000_003;
pub(super) const S4: u64 = 1_000_004;
const HANDLE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

/// The eight reads of a step that signs, the nonce last.
pub(super) const SIGNING_READS: [&str; 8] = [
    "code",
    "singleton",
    "owners",
    "threshold",
    "guard",
    "handler",
    "modules",
    "nonce",
];

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/safe.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

pub(super) fn flow(id: &str) -> Value {
    vectors()["flows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|flow| flow["id"] == id)
        .unwrap()
        .clone()
}

/// A Safe's owners and threshold, with its salt.
pub(super) struct Flows;

impl Flows {
    pub(super) fn owners(index: u64) -> (Vec<&'static str>, usize, &'static str) {
        match index {
            S2 => (vec![OA, OB], 1, "0"),
            S3 => (vec![OA, OB, OC], 2, "1"),
            S4 => (vec![OD, OA, OE], 2, "1"),
            _ => panic!("{index}"),
        }
    }

    pub(super) fn setup(index: u64) -> Setup {
        let (owners, threshold, _) = Flows::owners(index);
        setup_of(&owners, threshold)
    }

    pub(super) fn address(index: u64) -> [u8; 20] {
        let (_, _, salt) = Flows::owners(index);
        Flows::setup(index).address(&parse_salt(salt).unwrap())
    }
}

/// `vault-meta.json` with the flows' owners and Safes, each marked
/// deployed unless `unmarked`.
pub(super) fn flows_meta(unmarked: bool) -> Value {
    let index_of = |owner: &str| match owner {
        OA => 0,
        OB => 1,
        OC => 2,
        OD => 1_000_000,
        OE => 1_000_001,
        _ => panic!("{owner}"),
    };
    let mut wallets = vec![
        json!({ "index": 0, "name": "Wallet 1", "address": OA }),
        json!({ "index": 1, "name": "Wallet 2", "address": OB }),
        json!({ "index": 2, "name": "Wallet 3", "address": OC }),
        json!({ "index": 1_000_000, "name": "Ledger 1", "address": OD, "type": "ledger",
                "path": "44'/60'/0'/0/0", "addressCheck": "matched" }),
        json!({ "index": 1_000_001, "name": "Phone 1", "address": OE, "type": "remote",
                "addressCheck": "matched" }),
    ];
    for index in [S2, S3, S4] {
        let (owners, threshold, salt) = Flows::owners(index);
        wallets.push(json!({
            "index": index, "name": format!("Safe {index}"),
            "address": checksum_address(&Flows::address(index)), "type": "safe",
            "owners": owners.iter().map(|o| index_of(o)).collect::<Vec<_>>(),
            "threshold": threshold, "saltNonce": salt,
            "deployed": if unmarked { json!({}) } else { json!({ "100": { "verified": true } }) },
        }));
    }
    json!({
        "userKnowsPassword": true,
        "addresses": { "userWallet": OA, "beeWallet": OB },
        "derivedWallets": wallets,
        "activeWalletIndex": 0,
        "nextHardwareWalletIndex": 1_000_005,
    })
}

/// Gnosis with the Safe at `index` as Freedom made it, at `nonce`.
pub(super) fn chain_for(index: u64, nonce: u64) -> Chain {
    let setup = Flows::setup(index);
    Chain::deployed()
        .with("owners", owner_list(setup.owners()))
        .with("threshold", hex_words(&[uint(setup.threshold() as u64)]))
        .with("nonce", hex_words(&[uint(nonce)]))
}

pub(super) fn unlocked() -> VaultState {
    let mut state = VaultState::new();
    let ticket = state.ticket();
    let prepared = fc_vault::state::Prepared::new(fc_keys::Mnemonic::parse(ABANDON).unwrap());
    state.install(ticket, prepared, 0, 0).unwrap();
    state
}

/// The flows' world, the vault unlocked, the Safe at `index` at `nonce`.
pub(super) fn world(index: u64, nonce: u64) -> Harness {
    let mut h = Harness::new(flows_meta(false), chain_for(index, nonce));
    h.state = unlocked();
    h
}

fn page_context() -> Context {
    Context {
        caller: CallerKind::Page,
        page: Some(PageContext {
            origin: "https://app.example".to_owned(),
            top_origin: "https://app.example".to_owned(),
            frame: 1,
            navigation: 1,
            agent: Some(false),
            transport_key: None,
        }),
    }
}

/// The flows' call: 0.25 xDAI to D.
pub(super) fn call() -> Value {
    json!({ "to": OD, "value": "250000000000000000", "data": "0x" })
}

impl Harness {
    /// `safe.prepare` for the call to the Safe at `index`: its answer.
    pub(super) fn prepare(&mut self, index: u64, tx: Value) -> Value {
        self.call(
            "safe.prepare",
            json!({ "safe": index, "chain_id": 100, "tx": tx }),
        )
    }

    /// A token for `payload`, minted by the harness's caller (with the
    /// handle when it is a page).
    pub(super) fn token(&mut self, index: u64, payload: &Value) -> String {
        let mut params = json!({ "kind": "safe-send", "account": index, "payload": payload });
        if self.context.caller == CallerKind::Page {
            params["handle"] = json!(HANDLE);
        }
        let context = self.context.clone();
        let reply = self
            .approvals
            .request(1, "approval.issue", &params, &context, CLOCKS)
            .unwrap();
        let reply: Value = serde_json::from_slice(&reply).unwrap();
        reply["result"]["token"].as_str().unwrap().to_owned()
    }

    /// `safe.propose` of the prepared `answer` with `token`.
    pub(super) fn propose(
        &mut self,
        index: u64,
        answer: &Value,
        token: &str,
        display: Value,
    ) -> Value {
        let mut authorization = json!({ "token": token });
        if self.context.caller == CallerKind::Page {
            authorization["handle"] = json!(HANDLE);
        }
        self.call(
            "safe.propose",
            json!({
                "safe": index, "safe_tx_hash": answer["safe_tx_hash"],
                "authorization": authorization, "display": display,
            }),
        )
    }

    /// The token payload for a prepared answer, as main mints it (D6).
    pub(super) fn payload(&self, index: u64, answer: &Value) -> Value {
        json!({
            "safe": checksum_address(&Flows::address(index)), "chain_id": "100",
            "safe_tx": answer["safe_tx"], "safe_tx_hash": answer["safe_tx_hash"],
        })
    }

    /// Prepared, minted and proposed: the answer to `safe.propose`.
    pub(super) fn proposed(&mut self, index: u64) -> Value {
        let answer = result(&self.prepare(index, call())).clone();
        let token = self.token(index, &self.payload(index, &answer));
        self.propose(index, &answer, &token, json!({ "symbol": "xDAI" }))
    }

    /// The file's entry at `index`, as JSON.
    pub(super) fn entry_at(&self, index: u64) -> Option<Value> {
        let text = std::fs::read_to_string(self.path()).ok()?;
        let file: Value = serde_json::from_str(&text).unwrap();
        file.get(index.to_string()).cloned()
    }
}

pub(super) fn without_clock(mut entry: Value) -> Value {
    entry.as_object_mut().unwrap().shift_remove("createdAt");
    entry
}

// --- The entry the reference writes ------------------------------------

/// Each flow's start through the core: `safe.prepare` builds the
/// reference's SafeTx at the verified nonce, after all eight reads, the
/// nonce last; `safe.propose`, with the token over it, has the vault owners
/// sign in the record's order until the threshold (a Ledger's and a
/// phone's owners never), and writes the entry the reference writes, byte
/// for byte but its clock; its answer is the board's state, and a fresh
/// store reads it back.
#[test]
fn propose_writes_the_entry_the_reference_writes() {
    for (id, index) in [
        ("one-of-two", S2),
        ("two-of-three-vault-owners", S3),
        ("two-of-three-device-owner", S4),
        ("three-signatures", S3),
    ] {
        let flow = flow(id);
        let start = &flow["steps"][0];
        assert_eq!(start["step"], "start");
        let pending = &start["pending"];
        let nonce = flow["chainNonce"].as_u64().unwrap();
        let mut h = world(index, nonce);
        let answer = result(&h.prepare(index, flow["tx"].clone())).clone();
        assert_eq!(h.asked, SIGNING_READS, "{id}");
        assert_eq!(answer["safe_tx"], pending["safeTxData"], "{id}");
        assert_eq!(answer["safe_tx_hash"], pending["safeTxHash"], "{id}");
        assert_eq!(answer["view"]["primary_type"], "SafeTx");
        // Nothing is stored yet.
        assert!(h.entry_at(index).is_none());
        let token = h.token(index, &h.payload(index, &answer));
        h.asked.clear();
        let state = h.propose(index, &answer, &token, pending["display"].clone());
        let state = result(&state).clone();
        assert_eq!(h.asked, SIGNING_READS, "{id}: read again");
        let entry = h.entry_at(index).unwrap();
        assert_eq!(without_clock(entry.clone()), *pending, "{id}");
        assert_eq!(entry["createdAt"], CLOCKS.wall_ms, "{id}");
        // The board's state, as `getSafeSendState` gives it.
        let reference = &start["state"];
        for key in [
            "chainId",
            "safeTxHash",
            "threshold",
            "collected",
            "call",
            "status",
        ] {
            assert_eq!(state[key], reference[key], "{id}: {key}");
        }
        let signed = |state: &Value| -> Vec<(Value, Value)> {
            state["owners"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| (row["address"].clone(), row["signed"].clone()))
                .collect()
        };
        assert_eq!(signed(&state), signed(reference), "{id}");
        assert_eq!(state["safeIndex"], index);
        assert_eq!(state["display"], pending["display"]);
        assert_eq!(state["createdAt"], CLOCKS.wall_ms);
        // A restart reloads it: a fresh store, a fresh core's methods.
        let reloaded = SafePending::new();
        reloaded.configure(h._dir.path().to_owned(), true);
        h.pending = reloaded;
        h.safes = Safes::new();
        let reply = h.call("safe.pending", json!({}));
        assert_eq!(result(&reply)["states"], json!([state]), "{id}");
        // The Safe has its one pending SafeTx: proposed again, refused.
        let again = h.call(
            "safe.propose",
            json!({ "safe": index, "safe_tx_hash": answer["safe_tx_hash"],
                    "authorization": { "token": token } }),
        );
        assert_eq!(refusal(&again), "SAFE_PENDING_EXISTS");
    }
}

#[test]
fn a_locked_vault_signs_nothing_and_the_entry_waits() {
    let mut h = world(S2, 3);
    h.state = VaultState::new();
    let state = h.proposed(S2);
    assert_eq!(result(&state)["collected"], 0);
    let entry = h.entry_at(S2).unwrap();
    assert_eq!(entry["signatures"], json!([]));
    assert_eq!(entry["display"], json!({ "symbol": "xDAI" }));
}

#[test]
fn a_sites_token_proposes_for_its_page_only() {
    let mut h = world(S2, 3);
    h.context = page_context();
    let answer = result(&h.prepare(S2, call())).clone();
    let token = h.token(S2, &h.payload(S2, &answer));
    // Presented by main, it is the wallet's form: refused, and burnt.
    h.context = Context {
        caller: CallerKind::Shell,
        page: None,
    };
    let reply = h.propose(S2, &answer, &token, json!(null));
    assert_eq!(reply["error"]["code"], "not_authorized", "{reply}");
    assert_eq!(reply["error"]["data"]["reason"], "mismatch");
    assert!(h.entry_at(S2).is_none());
    // A new one, under its page with its handle: proposed.
    h.context = page_context();
    let token = h.token(S2, &h.payload(S2, &answer));
    let reply = h.propose(S2, &answer, &token, json!(null));
    assert_eq!(result(&reply)["collected"], 1);
    assert_eq!(h.entry_at(S2).unwrap()["display"], Value::Null);
}

// --- The token (D6) -----------------------------------------------------------

/// A token that binds anything but the prepared SafeTx is refused:
/// each field Freedom varies changed, another Safe, APR-4's form; none,
/// one never minted. The SafeTx stays prepared, nothing is read or written,
/// and a token over it then proposes it.
#[test]
fn a_token_for_another_safe_tx_proposes_nothing() {
    let mut h = world(S2, 3);
    let answer = result(&h.prepare(S2, call())).clone();
    let good = h.payload(S2, &answer);
    let mut cases = Vec::new();
    for (name, value) in [
        ("to", json!(OC)),
        ("value", json!("1")),
        ("data", json!("0x00")),
        ("nonce", json!(4)),
    ] {
        let mut fields = answer["safe_tx"].clone();
        fields[name] = value;
        let tx = fc_safe::SafeTx::from_fields(&fields).unwrap();
        let mut payload = good.clone();
        payload["safe_tx"] = fields;
        payload["safe_tx_hash"] = json!(to_hex(&tx.hash(&Flows::address(S2)).unwrap()));
        cases.push((name.to_owned(), payload));
    }
    // The same SafeTx for another Safe of the same owners.
    let elsewhere = Flows::setup(S2).address(&U256::from_u64(9));
    let tx = fc_safe::SafeTx::from_fields(&answer["safe_tx"]).unwrap();
    let mut payload = good.clone();
    payload["safe"] = json!(checksum_address(&elsewhere));
    payload["safe_tx_hash"] = json!(to_hex(&tx.hash(&elsewhere).unwrap()));
    cases.push(("safe".to_owned(), payload));
    cases.push((
        "legacy".to_owned(),
        json!({ "safe": checksum_address(&Flows::address(S2)), "chain_id": "100", "tx": call() }),
    ));
    for (what, payload) in cases {
        h.asked.clear();
        let token = h.token(S2, &payload);
        let reply = h.propose(S2, &answer, &token, json!(null));
        assert_eq!(reply["error"]["code"], "not_authorized", "{what}: {reply}");
        assert_eq!(reply["error"]["data"]["reason"], "mismatch", "{what}");
        assert!(h.asked.is_empty(), "{what}");
        assert!(h.entry_at(S2).is_none(), "{what}");
    }
    for authorization in [json!({}), json!({ "token": "00".repeat(32) })] {
        let reply = h.call(
            "safe.propose",
            json!({ "safe": S2, "safe_tx_hash": answer["safe_tx_hash"],
                    "authorization": authorization }),
        );
        assert!(reply["error"].is_object(), "{reply}");
    }
    // No authorization at all.
    let reply = h.call(
        "safe.propose",
        json!({ "safe": S2, "safe_tx_hash": answer["safe_tx_hash"] }),
    );
    assert_eq!(reply["error"]["code"], "invalid_argument");
    // A hash nothing prepared.
    let token = h.token(S2, &good);
    let reply = h.call(
        "safe.propose",
        json!({ "safe": S2, "safe_tx_hash": to_hex(&[0x11; 32]),
                "authorization": { "token": token } }),
    );
    assert_eq!(refusal(&reply), "SAFE_DISCARDED");
    // That token was burnt with its request.
    let reply = h.propose(S2, &answer, &token, json!(null));
    assert_eq!(reply["error"]["data"]["reason"], "unknown_token", "{reply}");
    // And the prepared SafeTx still proposes with a token over it.
    let token = h.token(S2, &good);
    assert_eq!(
        result(&h.propose(S2, &answer, &token, json!(null)))["collected"],
        1
    );
}

/// The new form is spent only by `safe.propose`: `approval.spend` refuses
/// it, and burns it.
#[test]
fn approval_spend_refuses_the_built_form() {
    let mut h = world(S2, 3);
    let answer = result(&h.prepare(S2, call())).clone();
    let payload = h.payload(S2, &answer);
    let token = h.token(S2, &payload);
    let context = h.context.clone();
    let spend = json!({ "token": token, "kind": "safe-send", "account": S2, "payload": payload });
    let refused = h
        .approvals
        .request(2, "approval.spend", &spend, &context, CLOCKS)
        .unwrap_err();
    assert_eq!(refused.code, ErrorCode::NotAuthorized);
    assert_eq!(refused.data, Some(json!({ "reason": "mismatch" })));
    let reply = h.propose(S2, &answer, &token, json!(null));
    assert_eq!(reply["error"]["data"]["reason"], "unknown_token", "{reply}");
}

// --- What a step that signs refuses ------------------------------------------

#[test]
fn prepare_refuses_before_any_read() {
    let mut h = world(S2, 3);
    // Another chain: the reference's refusal.
    let reply = h.call(
        "safe.prepare",
        json!({ "safe": S2, "chain_id": 1, "tx": call() }),
    );
    assert_eq!(refusal(&reply), "unsupported");
    assert_eq!(
        reply["error"]["message"],
        "Multi-signature accounts can only send on Gnosis"
    );
    // A call to the Safe itself (question 4).
    let to_self =
        json!({ "to": checksum_address(&Flows::address(S2)), "value": "0", "data": "0x" });
    assert_eq!(refusal(&h.prepare(S2, to_self)), "self_call");
    // Not a call.
    let reply = h.prepare(S2, json!({ "to": OD, "value": "1" }));
    assert_eq!(reply["error"]["code"], "invalid_argument");
    // Not a Safe.
    let reply = h.prepare(0, call());
    assert_eq!(reply["error"]["code"], "invalid_argument");
    assert!(h.asked.is_empty());
    // A Safe the record doesn't mark deployed.
    let mut h = Harness::new(flows_meta(true), chain_for(S2, 3));
    assert_eq!(refusal(&h.prepare(S2, call())), "not_deployed");
    let reply = h.call(
        "safe.propose",
        json!({ "safe": S2, "safe_tx_hash": to_hex(&[0x11; 32]),
                "authorization": { "token": "00".repeat(32) } }),
    );
    assert_eq!(refusal(&reply), "not_deployed");
    assert!(h.asked.is_empty());
}

/// The chain answers a SafeTx prepared on `prepared`, then proposed on
/// `proposed`: the proposal's answer, with nothing written.
fn propose_on(prepared: Chain, proposed: Chain) -> (Value, Harness) {
    let mut h = Harness::new(flows_meta(false), prepared);
    h.state = unlocked();
    let answer = result(&h.prepare(S2, call())).clone();
    let token = h.token(S2, &h.payload(S2, &answer));
    h.chain = proposed;
    h.asked.clear();
    let reply = h.propose(S2, &answer, &token, json!(null));
    assert!(h.entry_at(S2).is_none(), "{reply}");
    (reply, h)
}

#[test]
fn a_changed_setup_is_safe_changed_with_nothing_signed() {
    let mut handler = word(&FALLBACK_HANDLER);
    handler[31] ^= 1;
    let base = || chain_for(S2, 3);
    for (chain, changed) in [
        (base().with("threshold", hex_words(&[uint(2)])), "threshold"),
        (
            base().with(
                "owners",
                owner_list(&[address(OA), address(OB), address(OC)]),
            ),
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
        // At `safe.prepare`: nothing built.
        let mut h = world(S2, 3);
        h.chain = chain.clone();
        let reply = h.prepare(S2, call());
        assert_eq!(refusal(&reply), "changed", "{changed}");
        assert_eq!(
            reply["error"]["message"],
            "This Safe was changed outside Freedom, so Freedom can't sign for it."
        );
        // At `safe.propose`, changed since: nothing signed or written.
        let (reply, h) = propose_on(base(), chain);
        assert_eq!(refusal(&reply), "changed", "{changed}");
        // Another singleton ends the check before the nonce is read; the
        // rest are judged once all eight are in.
        assert_eq!(
            h.asked.contains(&"nonce"),
            changed != "singleton",
            "{changed}: {:?}",
            h.asked
        );
    }
}

#[test]
fn an_unverified_read_is_safe_unverified_with_nothing_signed() {
    // Each of the eight answered unverified in turn, while it reports the
    // record's value.
    for read in SIGNING_READS {
        let unverified = chain_for(S2, 3).served(read, Serve::Unverified);
        let mut h = world(S2, 3);
        h.chain = unverified.clone();
        let reply = h.prepare(S2, call());
        assert_eq!(refusal(&reply), "unverified", "{read}");
        let (reply, _) = propose_on(chain_for(S2, 3), unverified);
        assert_eq!(refusal(&reply), "unverified", "{read}");
    }
    // A reverted call.
    let (reply, _) = propose_on(
        chain_for(S2, 3),
        chain_for(S2, 3).served("nonce", Serve::Failed),
    );
    assert_eq!(refusal(&reply), "unverified");
    // No code, verified: not deployed after all.
    let (reply, h) = propose_on(chain_for(S2, 3), chain_for(S2, 3).with("code", json!("0x")));
    assert_eq!(refusal(&reply), "not_deployed");
    assert_eq!(h.asked, ["code"]);
}

#[test]
fn the_nonce_must_still_be_the_safe_txs() {
    // Moved on since: the SafeTx can never execute, so it isn't stored.
    let (reply, _) = propose_on(chain_for(S2, 3), chain_for(S2, 4));
    assert_eq!(refusal(&reply), "SAFE_DISCARDED");
    // Below it: `safe_nonce_behind`.
    let (reply, _) = propose_on(chain_for(S2, 3), chain_for(S2, 2));
    assert_eq!(refusal(&reply), "nonce_behind");
    // Past 2^53 − 1 at `safe.prepare`: no SafeTx.
    let mut h = world(S2, 3);
    h.chain = chain_for(S2, fc_safe::MAX_NONCE + 1);
    let reply = h.prepare(S2, call());
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
}

// --- The Safe's hold, and one pending SafeTx per Safe -----------------------

#[test]
fn a_proposal_holds_its_safe() {
    let mut h = world(S2, 3);
    let answer = result(&h.prepare(S2, call())).clone();
    let token = h.token(S2, &h.payload(S2, &answer));
    h.hold = true;
    let outs = h.send(
        "safe.propose",
        json!({ "safe": S2, "safe_tx_hash": answer["safe_tx_hash"],
                "authorization": { "token": token } }),
    );
    assert!(h.drive(outs).is_none());
    // Another proposal: the reservation's refusal; a discard: busy.
    let second = h.token(S2, &h.payload(S2, &answer));
    let reply = h.propose(S2, &answer, &second, json!(null));
    assert_eq!(refusal(&reply), "SAFE_PENDING_EXISTS");
    assert_eq!(
        reply["error"]["message"],
        "A transaction is already waiting for signatures \u{2014} finish or discard it first"
    );
    let reply = h.call("safe.discard", json!({ "safe": S2 }));
    assert_eq!(refusal(&reply), "SAFE_BUSY");
    assert_eq!(
        reply["error"]["message"],
        "Wait for the current step to finish first"
    );
    // Another Safe isn't held.
    let reply = h.call("safe.discard", json!({ "safe": S3 }));
    assert_eq!(result(&reply), &json!({}));
    // The cancel ends the hold.
    assert!(!h.safes.cancel(9).is_empty());
    h.hold = false;
    h.held.clear();
    let reply = h.call("safe.discard", json!({ "safe": S2 }));
    assert_eq!(result(&reply), &json!({}));
    assert!(h.entry_at(S2).is_none());
}

#[test]
fn one_pending_safe_tx_per_safe() {
    let mut h = world(S2, 3);
    assert_eq!(result(&h.proposed(S2))["collected"], 1);
    let before = std::fs::read(h.path()).unwrap();
    h.asked.clear();
    let reply = h.proposed(S2);
    assert_eq!(refusal(&reply), "SAFE_PENDING_EXISTS");
    // Refused before the second proposal's reads.
    assert_eq!(h.asked, SIGNING_READS, "the prepare's only");
    assert_eq!(std::fs::read(h.path()).unwrap(), before);
}

/// An entry written for the Safe while the proposal's reads were out
/// (main's own `safe_pending.set`) is kept: the proposal writes nothing.
#[test]
fn an_entry_written_meanwhile_is_kept() {
    let mut h = world(S2, 3);
    let answer = result(&h.prepare(S2, call())).clone();
    let token = h.token(S2, &h.payload(S2, &answer));
    h.hold = true;
    let outs = h.send(
        "safe.propose",
        json!({ "safe": S2, "safe_tx_hash": answer["safe_tx_hash"],
                "authorization": { "token": token } }),
    );
    assert!(h.drive(outs).is_none());
    // Another of main's entries, one that reads, lands meanwhile.
    let theirs = flow("one-of-two")["steps"][0]["pending"].clone();
    let mut theirs = theirs;
    theirs["display"] = json!({ "theirs": true });
    h.pending
        .set(S2, fc_json::parse(&theirs.to_string()).unwrap())
        .unwrap();
    h.hold = false;
    let mut queue = Vec::new();
    for read in std::mem::take(&mut h.held) {
        let payload = payload(&h.chain, &read);
        queue.extend(h.safes.chain_read(read.tag, &payload, false, ctx!(h)));
    }
    let reply = h.drive(queue).unwrap();
    assert_eq!(refusal(&reply), "SAFE_PENDING_EXISTS");
    assert_eq!(
        h.entry_at(S2).unwrap()["display"],
        json!({ "theirs": true })
    );
}

/// A Safe removed while the proposal's reads were out: nothing written.
#[test]
fn a_safe_removed_meanwhile_gets_nothing() {
    let mut h = world(S2, 3);
    let answer = result(&h.prepare(S2, call())).clone();
    let token = h.token(S2, &h.payload(S2, &answer));
    h.hold = true;
    let outs = h.send(
        "safe.propose",
        json!({ "safe": S2, "safe_tx_hash": answer["safe_tx_hash"],
                "authorization": { "token": token } }),
    );
    assert!(h.drive(outs).is_none());
    h.meta["derivedWallets"]
        .as_array_mut()
        .unwrap()
        .retain(|record| record["index"] != S2);
    h.records();
    h.hold = false;
    let mut queue = Vec::new();
    for read in std::mem::take(&mut h.held) {
        let payload = payload(&h.chain, &read);
        queue.extend(h.safes.chain_read(read.tag, &payload, false, ctx!(h)));
    }
    let reply = h.drive(queue).unwrap();
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
    assert!(h.entry_at(S2).is_none());
}

/// An entry the codec sets aside holds no Safe: it is left out of the
/// board, and a new proposal takes its place.
#[test]
fn a_set_aside_entry_gives_way() {
    let mut h = world(S2, 3);
    let mut bad = flow("one-of-two")["steps"][0]["pending"].clone();
    bad["safeTxData"]["value"] = json!("1");
    std::fs::write(h.path(), json!({ S2.to_string(): bad }).to_string()).unwrap();
    assert_eq!(
        result(&h.call("safe.pending", json!({})))["states"],
        json!([])
    );
    assert_eq!(result(&h.proposed(S2))["collected"], 1);
    let entry = h.entry_at(S2).unwrap();
    assert_eq!(entry["safeTxData"]["value"], "250000000000000000");
}

/// A proposal ends the Safe's older `safe-send` approvals (APR-4's), as a
/// new one ends them: a Safe has one pending SafeTx.
#[test]
fn a_proposal_ends_the_safes_older_send_approvals() {
    let mut h = world(S2, 3);
    let legacy =
        json!({ "safe": checksum_address(&Flows::address(S2)), "chain_id": "100", "tx": call() });
    let token = h.token(S2, &legacy);
    let context = h.context.clone();
    let spend = json!({ "token": token, "kind": "safe-send", "account": S2, "payload": legacy });
    let spent = h
        .approvals
        .request(2, "approval.spend", &spend, &context, CLOCKS)
        .unwrap();
    let spent: Value = serde_json::from_slice(&spent).unwrap();
    assert!(spent["result"]["safe"].is_string());
    assert_eq!(h.approvals.end_safe_sends(&Flows::address(S2)), 1);
    // Recorded again, then a proposal: it ends it.
    let token = h.token(S2, &legacy);
    let spend = json!({ "token": token, "kind": "safe-send", "account": S2, "payload": legacy });
    h.approvals
        .request(3, "approval.spend", &spend, &context, CLOCKS)
        .unwrap();
    assert_eq!(result(&h.proposed(S2))["collected"], 1);
    assert_eq!(h.approvals.end_safe_sends(&Flows::address(S2)), 0);
}

// --- The store (D3) -----------------------------------------------------------

#[test]
fn propose_needs_the_store_moved() {
    let mut h = world(S2, 3);
    let answer = result(&h.prepare(S2, call())).clone();
    let token = h.token(S2, &h.payload(S2, &answer));
    let pending = SafePending::new();
    pending.configure(h._dir.path().to_owned(), false);
    h.pending = pending;
    h.asked.clear();
    let reply = h.propose(S2, &answer, &token, json!(null));
    assert_eq!(reply["error"]["code"], "not_moved");
    assert_eq!(reply["error"]["data"]["store"], "safe_pending");
    assert!(h.asked.is_empty());
    assert!(h.entry_at(S2).is_none());
    // The token was burnt with it.
    let moved = SafePending::new();
    moved.configure(h._dir.path().to_owned(), true);
    h.pending = moved;
    let reply = h.propose(S2, &answer, &token, json!(null));
    assert_eq!(reply["error"]["data"]["reason"], "unknown_token", "{reply}");
}

/// The 1 MiB bound (D3): a proposal whose file would be exactly 1 MiB is
/// written; one byte more is `store_full`, with the store unchanged.
#[test]
fn the_store_takes_a_proposal_to_one_mib_and_refuses_a_byte_more() {
    const MIB: usize = 1024 * 1024;
    // The file's size with a display of `pad` bytes.
    let size = |pad: usize| {
        let mut h = world(S2, 3);
        let answer = result(&h.prepare(S2, call())).clone();
        let token = h.token(S2, &h.payload(S2, &answer));
        let display = json!({ "pad": "x".repeat(pad) });
        let reply = h.propose(S2, &answer, &token, display);
        (reply, std::fs::read(h.path()).map(|f| f.len()).ok(), h)
    };
    let (_, base, _) = size(0);
    let pad = MIB - base.unwrap();
    let (reply, at, _) = size(pad);
    assert_eq!(result(&reply)["collected"], 1);
    assert_eq!(at, Some(MIB));
    let (reply, at, h) = size(pad + 1);
    assert_eq!(refusal(&reply), "store_full");
    assert!(at.is_none(), "nothing written");
    assert!(h.entry_at(S2).is_none());
}
