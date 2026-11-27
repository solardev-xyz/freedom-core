//! SAFE-2's S6 against a scripted chain and a scripted Ledger (design 0016,
//! SAFE-2's tests, *Owners*: a Ledger owner through the lane, a SafeTx's by
//! `safe.sign_owner` and a SafeMessage's by `safe.message_sign`): a Ledger
//! owner's APDUs over the core's SafeTx and SafeMessage are
//! `vectors/ledger.json`'s, its signatures `vectors/safe.json`'s (the
//! `two-of-three-device-owner` flow's `sign` step, byte for byte but the
//! clock, and the `S4-device-owner` message); the vault owners' sweep after
//! a proposal made while the vault was locked; a named owner past the
//! threshold (the `three-signatures` flow); every refusal before the
//! reads and after them, with nothing signed or written; the core's
//! proposal mark (an entry main's `safe_pending.set` wrote is never
//! signed, a mark for another Safe or SafeTx is refused, a proposal's
//! survives a restart, and main's set keeps it only for the same SafeTx);
//! and the Safe's hold, a cancel and a failure while the device waits, and
//! a SafeTx or a session ended meanwhile.

use std::cell::RefCell;
use std::rc::Rc;

use fc_keys::{Mnemonic, derive_secp256k1};
use fc_ledger::{Account, LedgerCode, LedgerPath, Operation, Reply, Signed, Step};
use fc_vault::state::VaultState;

use super::super::owners::{
    DISCARDED_WHILE_TEXT, NOT_PROPOSED_TEXT, message_operation, tx_operation,
};
use super::messages::{message, session_of, vector_signatures};
use super::propose::{
    Flows, OA, OB, OD, S2, S3, S4, SIGNING_READS, flow, mark_of, unlocked, without_clock, world,
};
use super::*;

/// The `legal-12` test phrase (`vectors/keys.json`): D's key, at D's path.
const LEGAL: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
/// The flows' Ledger owner D and phone owner E, by wallet index.
const LEDGER_D: u64 = 1_000_000;
const PHONE_E: u64 = 1_000_001;
const D_PATH: &str = "44'/60'/0'/0/0";

fn ledger_json() -> Value {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/ledger.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn bytes32(text: &Value) -> [u8; 32] {
    parse_bytes(text.as_str().unwrap(), "hash")
        .unwrap()
        .try_into()
        .unwrap()
}

fn d_account() -> Account {
    Account {
        path: LedgerPath::parse(D_PATH).unwrap(),
        address: address(OD),
    }
}

/// A Ledger holding legal-12 (D's key at [`D_PATH`]), its Ethereum app
/// open, and main relaying to it: each APDU of `op` answered, a `6D00` to
/// the first `E0 1A` with `hash_only: "shown"` on a Nano S (`fields`
/// false). Its `E0 0C 00 01` signs `hash`, the hash the device computes
/// from the fields it was shown, and its `E0 0C 00 00` the two hashes it
/// was sent. The APDUs, and the operation's end.
fn ledger_run(
    op: &mut Operation,
    hash: &[u8; 32],
    fields: bool,
) -> (Vec<Vec<u8>>, Result<Signed, fc_ledger::Failure>) {
    let path = LedgerPath::parse(D_PATH).unwrap();
    let seed = Mnemonic::parse(LEGAL).unwrap().to_seed();
    let key = derive_secp256k1(&seed, path.derivation_path()).unwrap();
    let encoded = path.encode();
    let ok = [0x90, 0x00];
    let mut apdus = Vec::new();
    let mut step = op.start();
    loop {
        let exchange = match step {
            Step::Send(exchange) => exchange,
            Step::Done(done) => return (apdus, done),
        };
        let apdu = exchange.apdu.into_bytes();
        let data = apdu[5..].to_vec();
        let mut shown = false;
        let answer = match (apdu[0], apdu[1]) {
            (0xb0, 0x01) => {
                let mut out = vec![1, 8];
                out.extend_from_slice(b"Ethereum");
                out.push(6);
                out.extend_from_slice(b"1.13.0");
                out.extend_from_slice(&[1, 0]);
                out.extend_from_slice(&ok);
                out
            }
            (0xe0, 0x02) => {
                assert_eq!(data, encoded, "the address check is at D's path");
                let mut out = vec![65];
                out.extend_from_slice(&key.public_key_uncompressed());
                out.push(40);
                out.extend_from_slice(&key.address().to_checksum().as_bytes()[2..]);
                out.extend_from_slice(&ok);
                out
            }
            (0xe0, 0x1a | 0x1c) if !fields => {
                shown = apdus.len() == 2;
                vec![0x6d, 0x00]
            }
            (0xe0, 0x1a | 0x1c) => ok.to_vec(),
            (0xe0, 0x0c) => {
                assert_eq!(data[..encoded.len()], encoded[..]);
                let digest = if apdu[3] == 0x01 {
                    *hash
                } else {
                    let mut whole = vec![0x19, 0x01];
                    whole.extend_from_slice(&data[encoded.len()..]);
                    keccak256(&whole)
                };
                let signature = fc_evm::sign_digest(key.signing_key(), &digest).unwrap();
                let mut out = vec![signature[64]];
                out.extend_from_slice(&signature[..64]);
                out.extend_from_slice(&ok);
                out
            }
            other => panic!("no APDU {other:?}"),
        };
        apdus.push(apdu);
        step = op.answer(Reply::Answer {
            answer: &answer,
            hash_only_shown: shown,
        });
    }
}

/// Each Ledger operation the harness hands to the lane: its APDUs.
type Sent = Rc<RefCell<Vec<Vec<Vec<u8>>>>>;

impl Harness {
    /// The lane drives each Ledger owner's operation on [`ledger_run`]'s
    /// device, its typed-data hash `hash`; the APDUs of each go to the
    /// answer.
    fn with_ledger(&mut self, hash: [u8; 32], fields: bool) -> Sent {
        let sent: Sent = Rc::new(RefCell::new(Vec::new()));
        let log = Rc::clone(&sent);
        self.device = Some(Box::new(move |op: &mut Operation| {
            let (apdus, done) = ledger_run(op, &hash, fields);
            log.borrow_mut().push(apdus);
            done.map_err(|failure| crate::ledger::methods::device_failed(failure.code))
        }));
        sent
    }

    /// `safe.sign_owner` for the Safe at `index`, naming `owner`.
    fn sign_owner(&mut self, index: u64, owner: Option<u64>) -> Value {
        let mut params = json!({ "safe": index });
        if let Some(owner) = owner {
            params["owner"] = json!(owner);
        }
        self.call("safe.sign_owner", params)
    }

    /// A flow's start through the core: prepared, minted and proposed with
    /// its display, the vault as the harness has it. The SafeTx's hash.
    fn flow_proposed(&mut self, index: u64, flow: &Value) -> [u8; 32] {
        let answer = result(&self.prepare(index, flow["tx"].clone())).clone();
        let token = self.token(index, &self.payload(index, &answer));
        let display = flow["steps"][0]["pending"]["display"].clone();
        let state = self.propose(index, &answer, &token, display);
        assert!(result(&state).is_object());
        bytes32(&answer["safe_tx_hash"])
    }

    /// Request 9 sent, its reads answered: held on the lane, no reply.
    fn on_the_lane(&mut self, method: &str, params: Value) {
        let outs = self.send(method, params);
        assert!(
            self.drive(outs).is_none(),
            "no reply while the device waits"
        );
        assert_eq!(self.on_lane.len(), 1);
    }

    /// The held operation ended with `ended`: the reply.
    fn lane_ends(&mut self, ended: Result<Signed, ErrorBody>) -> Value {
        let outs = self.safes.device_ended(9, ended, self.now);
        self.drive(outs).expect("a reply")
    }

    /// The held operation driven on D's device: the reply.
    fn lane_signs(&mut self, hash: &[u8; 32]) -> Value {
        let (_, mut op) = self.on_lane.pop().unwrap();
        let (_, done) = ledger_run(&mut op, hash, true);
        self.lane_ends(Ok(done.unwrap()))
    }
}

/// The board's rows: each owner's address and whether it signed.
fn signed_rows(state: &Value) -> Vec<(Value, Value)> {
    state["owners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| (row["address"].clone(), row["signed"].clone()))
        .collect()
}

/// The board's state against the reference's, the wallet indices aside.
fn same_state(state: &Value, reference: &Value) {
    for key in [
        "chainId",
        "safeTxHash",
        "threshold",
        "collected",
        "call",
        "status",
    ] {
        assert_eq!(state[key], reference[key], "{key}");
    }
    assert_eq!(signed_rows(state), signed_rows(reference));
}

// --- The vectors ---------------------------------------------------------

/// A Ledger owner's operation over a SafeTx and over a SafeMessage is
/// `vectors/ledger.json`'s stream for it, byte for byte, the hash-only
/// form's too, and the recorded answers give the recorded signature.
#[test]
fn a_ledger_owners_apdus_are_the_ledger_vectors() {
    let ledger = ledger_json();
    for id in [
        "typed-safe-tx",
        "typed-hash-only-safe-tx",
        "typed-safe-message",
    ] {
        let case = ledger["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["id"] == id)
            .unwrap();
        let typed = &case["request"]["typed_data"];
        let safe = address(typed["domain"]["verifyingContract"].as_str().unwrap());
        let hash = bytes32(&case["request"]["expected_hash"]);
        let account = Account {
            path: LedgerPath::parse(case["record"]["path"].as_str().unwrap()).unwrap(),
            address: address(case["record"]["address"].as_str().unwrap()),
        };
        let message = &typed["message"];
        let mut op = if typed["types"].get("SafeTx").is_some() {
            let tx = fc_safe::SafeTx::new(
                address(message["to"].as_str().unwrap()),
                U256::parse_decimal(message["value"].as_str().unwrap()).unwrap(),
                parse_bytes(message["data"].as_str().unwrap(), "data").unwrap(),
                message["nonce"].as_str().unwrap().parse().unwrap(),
            )
            .unwrap();
            assert_eq!(tx.hash(&safe).unwrap(), hash, "{id}");
            tx_operation(account, &safe, &tx, &hash).unwrap()
        } else {
            let digest = bytes32(&message["message"]);
            assert_eq!(
                fc_safe::SafeMessage::new(digest).hash(&safe).unwrap(),
                hash,
                "{id}"
            );
            message_operation(account, &safe, &digest, &hash).unwrap()
        };
        let exchanges = case["exchanges"].as_array().unwrap();
        let mut step = op.start();
        for (at, exchange) in exchanges.iter().enumerate() {
            let Step::Send(sent) = step else {
                panic!("{id}: ended before APDU {at}")
            };
            assert_eq!(
                to_hex(&sent.apdu.into_bytes())[2..],
                *exchange["apdu"].as_str().unwrap(),
                "{id}: APDU {at}"
            );
            let answer =
                parse_bytes(&format!("0x{}", exchange["answer"].as_str().unwrap()), "").unwrap();
            // Main's warning is on screen for the first `E0 1A`'s `6D00`.
            let shown = at == 2 && answer == [0x6d, 0x00];
            step = op.answer(Reply::Answer {
                answer: &answer,
                hash_only_shown: shown,
            });
        }
        let Step::Done(Ok(Signed::Signature(signature))) = step else {
            panic!("{id}: {step:?}")
        };
        assert_eq!(to_hex(&signature), case["result"]["signature"], "{id}");
    }
}

/// The `two-of-three-device-owner` flow through the core: A signs at the
/// proposal; then the Ledger owner D through `safe.sign_owner` on the
/// device lane, with the vault locked (a Ledger needs none), after the
/// eight reads, on a device that shows the fields and on a Nano S (the
/// hash-only form): the entry is the reference's after D's signature, byte
/// for byte but its clock, and the answer its board. The APDUs are
/// fc-ledger's stream for the entry's SafeTx. D signed already is answered
/// at once, with no read and no device.
#[test]
fn a_ledger_owner_signs_the_pending_safe_tx_on_the_lane() {
    let flow = flow("two-of-three-device-owner");
    let steps = flow["steps"].as_array().unwrap();
    let (start, sign) = (&steps[0], &steps[2]);
    assert_eq!(
        (&sign["step"], &sign["owner"]),
        (&json!("sign"), &json!("D"))
    );
    for fields in [true, false] {
        let mut h = world(S4, 2);
        let hash = h.flow_proposed(S4, &flow);
        assert_eq!(without_clock(h.entry_at(S4).unwrap()), start["pending"]);
        let sent = h.with_ledger(hash, fields);
        h.state = VaultState::new();
        h.asked.clear();
        let reply = h.sign_owner(S4, Some(LEDGER_D));
        let state = result(&reply).clone();
        assert_eq!(h.asked, SIGNING_READS, "{fields}");
        let entry = h.entry_at(S4).unwrap();
        assert_eq!(without_clock(entry.clone()), sign["pending"], "{fields}");
        assert_eq!(entry["createdAt"], CLOCKS.wall_ms);
        same_state(&state, &sign["state"]);
        assert_eq!(state["display"], start["pending"]["display"]);
        // The lane got the operation over the entry's own SafeTx.
        let tx = fc_safe::SafeTx::from_fields(&sign["pending"]["safeTxData"]).unwrap();
        let mut expected = tx_operation(d_account(), &Flows::address(S4), &tx, &hash).unwrap();
        let (expected, _) = ledger_run(&mut expected, &hash, fields);
        let sent_now = sent.borrow().clone();
        assert_eq!(sent_now, std::slice::from_ref(&expected), "{fields}");
        assert_eq!(expected[0][..4], [0xe0, 0x02, 0x00, 0x00]);
        assert_eq!(expected[1][..4], [0xb0, 0x01, 0x00, 0x00]);
        let last = expected.last().unwrap();
        assert_eq!(last[..2], [0xe0, 0x0c]);
        // Signed already: the state, idempotent, with no read or device.
        h.asked.clear();
        let again = h.sign_owner(S4, Some(LEDGER_D));
        assert_eq!(result(&again)["collected"], 2);
        assert!(h.asked.is_empty());
        assert_eq!(sent.borrow().len(), 1);
        // Nothing holds the Safe now: the board's sweep answers (A signed).
        let sweep = h.sign_owner(S4, None);
        assert_eq!(result(&sweep)["collected"], 2);
    }
}

/// The `S4-device-owner` message through the core: A signs at the start;
/// the Ledger owner D through `safe.message_sign` on the lane, the vault
/// locked, after the eight reads; the signatures and the joined one are
/// the reference's.
#[test]
fn a_ledger_owner_signs_a_safe_message_on_the_lane() {
    let case = message("S4-device-owner");
    let mut h = world(S4, 3);
    let answer = h.message_started(S4, &case["request"]);
    let session = session_of(&answer);
    let hash = bytes32(&case["hash"]);
    let sent = h.with_ledger(hash, true);
    h.state = VaultState::new();
    h.asked.clear();
    let reply = h.board("safe.message_sign", S4, &session, Some(LEDGER_D));
    assert_eq!(result(&reply)["collected"], 2, "{reply}");
    assert_eq!(result(&reply)["complete"], true);
    assert_eq!(h.asked, SIGNING_READS);
    assert_eq!(h.kept(S4), vector_signatures(&case));
    let digest = bytes32(&case["digest"]);
    let mut expected = message_operation(d_account(), &Flows::address(S4), &digest, &hash).unwrap();
    let (expected, _) = ledger_run(&mut expected, &hash, true);
    assert_eq!(*sent.borrow(), [expected]);
    // The threshold met: no owner signs after it.
    let done = h.board("safe.message_complete", S4, &session, None);
    assert_eq!(result(&done)["signature"], case["signature"]);
}

// --- The vault owners -----------------------------------------------------

/// A proposal made while the vault was locked keeps no signature; the
/// board's sweep then signs nothing, with no read, until the vault is
/// unlocked, and a named vault owner is `vault_locked`. Unlocked, the
/// sweep reads the setup and signs the vault owners in the record's order
/// until the threshold: the entry the reference writes when the vault was
/// unlocked at the proposal (`two-of-three-vault-owners`). With the
/// threshold met, the sweep reads nothing.
#[test]
fn the_sweep_signs_after_a_proposal_made_while_locked() {
    let flow = flow("two-of-three-vault-owners");
    let start = &flow["steps"][0];
    let mut h = world(S3, 4);
    h.state = VaultState::new();
    h.flow_proposed(S3, &flow);
    assert_eq!(h.entry_at(S3).unwrap()["signatures"], json!([]));
    h.asked.clear();
    let reply = h.sign_owner(S3, None);
    assert_eq!(result(&reply)["collected"], 0);
    let reply = h.sign_owner(S3, Some(0));
    assert_eq!(reply["error"]["code"], "vault_locked", "{reply}");
    assert!(h.asked.is_empty());
    h.state = unlocked();
    let reply = h.sign_owner(S3, None);
    let state = result(&reply).clone();
    assert_eq!(h.asked, SIGNING_READS);
    assert_eq!(without_clock(h.entry_at(S3).unwrap()), start["pending"]);
    same_state(&state, &start["state"]);
    h.asked.clear();
    let again = h.sign_owner(S3, None);
    assert_eq!(result(&again)["collected"], 2);
    assert!(h.asked.is_empty());
}

/// A named owner signs past the threshold, as the reference's chosen owner
/// does (`three-signatures`: C after A and B): the entry is the reference's
/// after C's signature.
#[test]
fn a_named_vault_owner_signs_past_the_threshold() {
    let flow = flow("three-signatures");
    let sign = &flow["steps"][1];
    assert_eq!(
        (&sign["step"], &sign["owner"]),
        (&json!("sign"), &json!("C"))
    );
    let mut h = world(S3, 4);
    h.flow_proposed(S3, &flow);
    h.asked.clear();
    let reply = h.sign_owner(S3, Some(2));
    let state = result(&reply).clone();
    assert_eq!(h.asked, SIGNING_READS);
    assert_eq!(without_clock(h.entry_at(S3).unwrap()), sign["pending"]);
    same_state(&state, &sign["state"]);
}

// --- What it refuses --------------------------------------------------------

/// Before any read, nothing signed or written: no SafeTx pending; another
/// one named; one marked superseded; not one of the Safe's owners (the
/// `not-an-owner` flow); a phone owner (`unsupported`); a Ledger record no
/// Ledger signs at (D9). Signed already, and a sweep with nothing to sign,
/// are the state.
#[test]
fn sign_owner_refuses_before_any_read() {
    let mut h = world(S2, 3);
    let reply = h.sign_owner(S2, None);
    assert_eq!(
        reply["error"]["message"],
        "No pending transaction for this account"
    );
    let not_an_owner = flow("not-an-owner");
    let hash = h.flow_proposed(S2, &not_an_owner);
    h.asked.clear();
    let before = std::fs::read(h.path()).unwrap();
    let other = h.call(
        "safe.sign_owner",
        json!({ "safe": S2, "safe_tx_hash": to_hex(&[0x11; 32]) }),
    );
    assert_eq!(refusal(&other), "SAFE_DISCARDED");
    let named = h.call(
        "safe.sign_owner",
        json!({ "safe": S2, "owner": 0, "safe_tx_hash": to_hex(&hash) }),
    );
    assert_eq!(result(&named)["collected"], 1, "signed already");
    let reply = h.sign_owner(S2, Some(2));
    assert_eq!(
        reply["error"]["message"],
        not_an_owner["steps"][1]["error"]["message"]
    );
    let sweep = h.sign_owner(S2, None);
    assert_eq!(result(&sweep)["collected"], 1, "the threshold met");
    assert!(h.asked.is_empty());
    assert_eq!(std::fs::read(h.path()).unwrap(), before);
    // Marked superseded (by `safe.execute`): nothing more signs it.
    let mut marked = h.entry_at(S2).unwrap();
    marked["superseded"] = json!(true);
    h.pending
        .set(S2, fc_json::parse(&marked.to_string()).unwrap())
        .unwrap();
    let reply = h.sign_owner(S2, Some(1));
    assert_eq!(
        reply["error"]["message"],
        "This transaction can no longer be signed \u{2014} discard it"
    );
    assert!(h.asked.is_empty());
    // A phone owner, and a Ledger record whose path isn't a scheme's.
    let mut h = world(S4, 2);
    h.flow_proposed(S4, &flow("two-of-three-device-owner"));
    h.asked.clear();
    let reply = h.sign_owner(S4, Some(PHONE_E));
    assert_eq!(refusal(&reply), "unsupported");
    for record in h.meta["derivedWallets"].as_array_mut().unwrap() {
        if record["index"] == LEDGER_D {
            record["path"] = json!(format!("m/{D_PATH}"));
        }
    }
    h.records();
    let reply = h.sign_owner(S4, Some(LEDGER_D));
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
    assert_eq!(
        reply["error"]["message"],
        crate::accounts::LEDGER_PATH,
        "{reply}"
    );
    assert!(h.asked.is_empty());
}

/// A change to what Gnosis shows.
type ChainChange = dyn Fn(Chain) -> Chain;

/// After the reads, nothing signed or written: a changed setup
/// (`safe_changed`), an unverified read (`safe_unverified`), no code
/// (`not_deployed`), the Safe's nonce past the SafeTx's (it can never
/// execute: the superseded refusal, no mark written) and below it
/// (`nonce_behind`).
#[test]
fn sign_owner_refuses_after_the_reads() {
    let flow = flow("two-of-three-vault-owners");
    let cases: Vec<(&str, Box<ChainChange>)> = vec![
        (
            "changed",
            Box::new(|chain: Chain| chain.with("owners", owner_list(&[address(OA), address(OB)]))),
        ),
        (
            "unverified",
            Box::new(|chain: Chain| chain.served("nonce", Serve::Unverified)),
        ),
        (
            "not_deployed",
            Box::new(|chain: Chain| chain.with("code", json!("0x"))),
        ),
        (
            "superseded",
            Box::new(|chain: Chain| chain.with("nonce", hex_words(&[uint(5)]))),
        ),
        (
            "nonce_behind",
            Box::new(|chain: Chain| chain.with("nonce", hex_words(&[uint(3)]))),
        ),
    ];
    for (name, change) in cases {
        let mut h = world(S3, 4);
        h.state = VaultState::new();
        h.flow_proposed(S3, &flow);
        h.state = unlocked();
        h.chain = change(h.chain.clone());
        let before = std::fs::read(h.path()).unwrap();
        let reply = h.sign_owner(S3, None);
        match name {
            "superseded" => assert_eq!(
                reply["error"]["message"],
                "This transaction can no longer be signed \u{2014} discard it",
                "{reply}"
            ),
            name => assert_eq!(refusal(&reply), name, "{reply}"),
        }
        assert_eq!(std::fs::read(h.path()).unwrap(), before, "{name}");
    }
}

// --- The core's proposal mark ------------------------------------------------

/// A transfer of the Safe's xDAI to someone no prompt showed.
fn transfer() -> Value {
    json!({ "to": checksum_address(&[0x77; 20]), "value": "1000000000000000000", "data": "0x" })
}

/// The entry main's `safe_pending.set` would write for the SafeTx
/// `safe.prepare` answered with: the members the codec reads.
fn main_entry(index: u64, answer: &Value) -> Value {
    json!({
        "chainId": 100,
        "safeAddress": checksum_address(&Flows::address(index)),
        "safeTxData": answer["safe_tx"],
        "safeTxHash": answer["safe_tx_hash"],
        "signatures": [],
    })
}

impl Harness {
    /// Main's `safe_pending.set { index, entry }`, as the request reaches
    /// the store.
    fn main_sets(&mut self, index: u64, entry: &Value) {
        let params = json!({ "index": index, "entry": entry });
        self.pending
            .request("safe_pending.set", Some(&params.to_string()))
            .unwrap();
    }

    /// The file's entry at `index` written as given, as no request writes
    /// it: a mark the core didn't write for it.
    fn plant(&mut self, index: u64, entry: &Value) {
        let entry = fc_json::parse(&entry.to_string()).unwrap();
        self.pending.set_where(index, entry, |_| true).unwrap();
    }

    /// The sweep and each vault owner named are `not_proposed`, before any
    /// read, the file unchanged.
    fn never_signed(&mut self, index: u64, owners: &[u64], what: &str) {
        self.asked.clear();
        let before = std::fs::read(self.path()).unwrap();
        let named = owners.iter().copied().map(Some);
        for owner in std::iter::once(None).chain(named) {
            let reply = self.sign_owner(index, owner);
            assert_eq!(
                refusal(&reply),
                "not_proposed",
                "{what}, {owner:?}: {reply}"
            );
            assert_eq!(reply["error"]["message"], NOT_PROPOSED_TEXT);
        }
        assert!(self.asked.is_empty(), "{what}");
        assert_eq!(std::fs::read(self.path()).unwrap(), before, "{what}");
    }
}

/// Codex's round 1 on #538: main's `safe_pending.set` writes the SafeTx
/// `safe.prepare` built for a transfer, as a minimal entry, with no mark or
/// with the mark the core would write for it. The set drops the mark, and
/// neither the board's sweep (which would sign two of the 2-of-3's vault
/// owners, an executable transfer) nor a named vault owner signs it, the
/// vault unlocked: `not_proposed`, before any read. Nor does a Ledger
/// owner, which never reaches the lane.
#[test]
fn an_entry_main_wrote_is_never_signed() {
    for forged in [false, true] {
        let mut h = world(S3, 4);
        let answer = result(&h.prepare(S3, transfer())).clone();
        let mut entry = main_entry(S3, &answer);
        if forged {
            entry[entry::PROPOSAL] = mark_of(S3, &bytes32(&answer["safe_tx_hash"]));
        }
        h.main_sets(S3, &entry);
        let written = h.entry_at(S3).unwrap();
        assert!(written.get(entry::PROPOSAL).is_none(), "{written}");
        // The board shows it: it reads.
        let pending = h.call("safe.pending", json!({}));
        assert_eq!(
            result(&pending)["states"][0]["safeTxHash"],
            answer["safe_tx_hash"]
        );
        h.never_signed(S3, &[0, 1, 2], "main's entry");
        assert_eq!(h.entry_at(S3).unwrap()["signatures"], json!([]));
    }
    let mut h = world(S4, 2);
    let answer = result(&h.prepare(S4, transfer())).clone();
    h.main_sets(S4, &main_entry(S4, &answer));
    let sent = h.with_ledger(bytes32(&answer["safe_tx_hash"]), true);
    h.state = VaultState::new();
    h.never_signed(S4, &[LEDGER_D], "a Ledger owner");
    assert!(sent.borrow().is_empty(), "nothing reached the device");
}

/// Marks the core didn't write for exactly this Safe and SafeTx, planted in
/// the file as no request can: one copied from the Safe's earlier proposal,
/// one for another Safe, one for another chain, and forged ones. None
/// signs. The exact mark, planted the same way, does: what decides is the
/// mark, and only the core writes it.
#[test]
fn a_mark_for_another_safe_or_safe_tx_is_refused() {
    let mut h = world(S3, 4);
    let proposed = h.flow_proposed(S3, &flow("two-of-three-vault-owners"));
    let earlier = h.entry_at(S3).unwrap()[entry::PROPOSAL].clone();
    assert_eq!(earlier, mark_of(S3, &proposed));
    let discarded = h.call("safe.discard", json!({ "safe": S3 }));
    assert_eq!(result(&discarded), &json!({}));
    let answer = result(&h.prepare(S3, transfer())).clone();
    let hash = bytes32(&answer["safe_tx_hash"]);
    let exact = mark_of(S3, &hash);
    let with = |key: &str, value: Value| {
        let mut mark = exact.clone();
        mark[key] = value;
        mark
    };
    let mut reordered = serde_json::Map::new();
    for key in ["safeTxHash", "safeAddress", "chainId"] {
        reordered.insert(key.to_owned(), exact[key].clone());
    }
    for (what, mark) in [
        ("the earlier SafeTx's, copied", earlier),
        ("another Safe's", mark_of(S2, &hash)),
        ("another chain's", with("chainId", json!(1))),
        (
            "another hash",
            with("safeTxHash", json!(to_hex(&[0x11; 32]))),
        ),
        (
            "an address in lower case",
            with("safeAddress", json!(to_hex(&Flows::address(S3)))),
        ),
        ("an extra member", with("by", json!("safe.propose"))),
        ("reordered", Value::Object(reordered)),
        ("true", json!(true)),
        ("the hash alone", answer["safe_tx_hash"].clone()),
        ("empty", json!({})),
    ] {
        let mut entry = main_entry(S3, &answer);
        entry[entry::PROPOSAL] = mark;
        h.plant(S3, &entry);
        h.never_signed(S3, &[0, 1], what);
    }
    let mut entry = main_entry(S3, &answer);
    entry[entry::PROPOSAL] = exact;
    h.plant(S3, &entry);
    let reply = h.sign_owner(S3, None);
    assert_eq!(result(&reply)["collected"], 2, "{reply}");
}

/// A proposal made while the vault was locked keeps its mark through a
/// restart (a fresh store, a fresh core's methods and approvals): unlocked,
/// the sweep signs it, the reference's entry but its clock and the mark,
/// as 0016 has it (the vault owners aren't affected by a restart).
#[test]
fn a_proposed_entry_signs_after_a_restart() {
    let flow = flow("two-of-three-vault-owners");
    let start = &flow["steps"][0];
    let mut h = world(S3, 4);
    h.state = VaultState::new();
    let hash = h.flow_proposed(S3, &flow);
    let reloaded = SafePending::new();
    reloaded.configure(h._dir.path().to_owned(), true);
    h.pending = reloaded;
    h.safes = Safes::new();
    h.approvals = Approvals::new();
    h.records();
    h.state = unlocked();
    h.asked.clear();
    let reply = h.sign_owner(S3, None);
    same_state(result(&reply), &start["state"]);
    assert_eq!(h.asked, SIGNING_READS);
    let entry = h.entry_at(S3).unwrap();
    assert_eq!(without_clock(entry.clone()), start["pending"]);
    assert_eq!(entry[entry::PROPOSAL], mark_of(S3, &hash));
}

/// Main's `safe_pending.set` of a proposed entry for the same SafeTx (its
/// `display` changed, the mark sent back as the reference's `{ ...current
/// }` would, or left out) keeps the core's mark, and the sweep signs it.
/// One whose SafeTx changed (another value, its hash recomputed, the mark
/// sent back) loses it: `not_proposed`. Setting the first SafeTx again,
/// its mark sent back, doesn't bring the mark back.
#[test]
fn main_keeps_the_mark_only_while_the_safe_tx_is_the_same() {
    let mut h = world(S3, 4);
    h.state = VaultState::new();
    let hash = h.flow_proposed(S3, &flow("two-of-three-vault-owners"));
    let proposed = h.entry_at(S3).unwrap();
    for sent_back in [true, false] {
        let mut same = proposed.clone();
        same["display"] = json!({ "note": sent_back });
        if !sent_back {
            same.as_object_mut().unwrap().shift_remove(entry::PROPOSAL);
        }
        h.main_sets(S3, &same);
        let entry = h.entry_at(S3).unwrap();
        assert_eq!(entry[entry::PROPOSAL], mark_of(S3, &hash), "{sent_back}");
        assert_eq!(entry["display"], same["display"]);
    }
    h.state = unlocked();
    let reply = h.sign_owner(S3, None);
    assert_eq!(result(&reply)["collected"], 2, "{reply}");
    let signed = h.entry_at(S3).unwrap();
    assert_eq!(signed[entry::PROPOSAL], mark_of(S3, &hash));
    // Another SafeTx in its place.
    let mut changed = signed.clone();
    changed["safeTxData"]["value"] = json!("1");
    changed["signatures"] = json!([]);
    let tx = fc_safe::SafeTx::from_fields(&changed["safeTxData"]).unwrap();
    changed["safeTxHash"] = json!(to_hex(&tx.hash(&Flows::address(S3)).unwrap()));
    h.main_sets(S3, &changed);
    assert!(h.entry_at(S3).unwrap().get(entry::PROPOSAL).is_none());
    h.never_signed(S3, &[0, 1], "another SafeTx");
    // The first SafeTx again, its mark sent back: still not the core's.
    h.main_sets(S3, &proposed);
    assert!(h.entry_at(S3).unwrap().get(entry::PROPOSAL).is_none());
    h.never_signed(S3, &[0, 1], "set again");
}

// --- The device's wait ------------------------------------------------------

/// While a Ledger owner's operation is on the lane the Safe is held:
/// another owner's step, a discard and an execution are `SAFE_BUSY`, and
/// the reads' bound doesn't end it. A device's failure and a cancel end it
/// with nothing written, and release the Safe. A SafeTx discarded while
/// the device waited is never signed: `SAFE_DISCARDED`, the reference's
/// text, nothing kept.
#[test]
fn the_device_wait_holds_the_safe_and_its_end_is_checked() {
    let flow = flow("two-of-three-device-owner");
    let mut h = world(S4, 2);
    let hash = h.flow_proposed(S4, &flow);
    let before = std::fs::read(h.path()).unwrap();
    let to_d = json!({ "safe": S4, "owner": LEDGER_D });
    h.on_the_lane("safe.sign_owner", to_d.clone());
    for (method, params) in [
        ("safe.sign_owner", json!({ "safe": S4 })),
        ("safe.discard", json!({ "safe": S4 })),
        ("safe.execute", json!({ "safe": S4 })),
    ] {
        let reply = h.call(method, params);
        assert_eq!(refusal(&reply), "SAFE_BUSY", "{method}");
    }
    assert!(h.safes.tick(h.now + Duration::from_secs(3600)).is_empty());
    assert_eq!(h.safes.next_wakeup(), None);
    // The device fails: its code, nothing written, the Safe free again.
    let reply = h.lane_ends(Err(crate::ledger::methods::device_failed(
        LedgerCode::Timeout,
    )));
    assert_eq!(reply["error"]["code"], "device_failed", "{reply}");
    assert_eq!(reply["error"]["data"]["ledger"], "LEDGER_TIMEOUT");
    assert_eq!(std::fs::read(h.path()).unwrap(), before);
    h.on_lane.clear();
    // Cancelled on the lane: `cancelled`; a late end changes nothing.
    h.on_the_lane("safe.sign_owner", to_d.clone());
    let reply = h.lane_ends(Err(ErrorBody::new(ErrorCode::Cancelled, "Cancelled")));
    assert_eq!(reply["error"]["code"], "cancelled");
    let (_, mut op) = h.on_lane.pop().unwrap();
    let (_, done) = ledger_run(&mut op, &hash, true);
    assert!(h.safes.device_ended(9, Ok(done.unwrap()), h.now).is_empty());
    assert_eq!(std::fs::read(h.path()).unwrap(), before);
    // The Safe methods' own cancel (the vault's): one `cancelled`, and the
    // lane's end after it changes nothing.
    h.on_the_lane("safe.sign_owner", to_d.clone());
    let outs = h.safes.cancel(9);
    let reply = h.drive(outs).unwrap();
    assert_eq!(reply["error"]["code"], "cancelled");
    let (_, mut op) = h.on_lane.pop().unwrap();
    let (_, done) = ledger_run(&mut op, &hash, true);
    assert!(h.safes.device_ended(9, Ok(done.unwrap()), h.now).is_empty());
    assert_eq!(std::fs::read(h.path()).unwrap(), before);
    // Discarded meanwhile (main's own clear): the signature isn't kept.
    h.on_the_lane("safe.sign_owner", to_d);
    h.pending.clear(S4).unwrap();
    let reply = h.lane_signs(&hash);
    assert_eq!(refusal(&reply), "SAFE_DISCARDED");
    assert_eq!(reply["error"]["message"], DISCARDED_WHILE_TEXT);
    assert!(h.entry_at(S4).is_none());
}

/// A Safe message's session cancelled while its Ledger owner's device
/// waits: the cancel ends it (`SAFE_BUSY`), and the signature that comes
/// back is never kept (`SAFE_DISCARDED`).
#[test]
fn a_session_ended_while_the_device_waits_keeps_nothing() {
    let case = message("S4-device-owner");
    let mut h = world(S4, 3);
    let answer = h.message_started(S4, &case["request"]);
    let session = session_of(&answer);
    h.context = Context {
        caller: fc_protocol::message::CallerKind::Shell,
        page: None,
    };
    h.on_the_lane(
        "safe.message_sign",
        json!({ "safe": S4, "session": session, "owner": LEDGER_D }),
    );
    let reply = h.board("safe.message_cancel", S4, &session, None);
    assert_eq!(refusal(&reply), "SAFE_BUSY");
    let reply = h.lane_signs(&bytes32(&case["hash"]));
    assert_eq!(refusal(&reply), "SAFE_DISCARDED");
    assert_eq!(h.kept(S4).len(), 1, "A's alone");
}
