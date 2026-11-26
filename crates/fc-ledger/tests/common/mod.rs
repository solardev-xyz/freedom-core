//! The tests' world: vectors/ledger.json and ledger-grammar.json, a
//! scripted Ledger as `formats.device` describes the generator's (it
//! holds keys.json's abandon-12 mnemonic, answers `E0 02` with the key at
//! the path and `B0 01` with its app, signs a transaction or a message over
//! what it was sent, and typed data over the hash it is given), a replay of
//! a case's recorded answers, and a runner that drives an operation to its
//! end.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::OnceLock;

use fc_evm::{
    Transaction, U256, eip191_digest, keccak256, parse_address, parse_bytes, rlp, sign_digest,
    to_hex,
};
use fc_keys::{Mnemonic, Secp256k1Key, Seed, derive_secp256k1};
use fc_ledger::{Account, Failed, LedgerPath, Operation, Reply, Signed, Step};
use serde_json::Value;

pub fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

pub fn ledger() -> &'static Value {
    static FILE: OnceLock<Value> = OnceLock::new();
    FILE.get_or_init(|| load("ledger.json"))
}

pub fn grammar() -> &'static Value {
    static FILE: OnceLock<Value> = OnceLock::new();
    FILE.get_or_init(|| load("ledger-grammar.json"))
}

pub fn cases() -> &'static [Value] {
    ledger()["cases"].as_array().unwrap()
}

pub fn case(id: &str) -> &'static Value {
    cases().iter().find(|c| c["id"] == id).unwrap()
}

/// keys.json's mnemonic by its id.
pub fn seed(id: &str) -> Seed {
    let keys = load("keys.json");
    let phrase = keys["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
        .unwrap()["mnemonic"]
        .as_str()
        .unwrap()
        .to_owned();
    Mnemonic::parse(&phrase).unwrap().to_seed()
}

pub fn abandon() -> &'static Seed {
    static SEED: OnceLock<Seed> = OnceLock::new();
    SEED.get_or_init(|| seed("abandon-12"))
}

pub fn key_at(path: &LedgerPath) -> Secp256k1Key {
    derive_secp256k1(abandon(), path.derivation_path()).unwrap()
}

/// Another key than the account's: abandon-12's at `44'/60'/9'/0/0`.
pub fn other_key() -> Secp256k1Key {
    key_at(&LedgerPath::parse("44'/60'/9'/0/0").unwrap())
}

pub fn hex(bytes: &[u8]) -> String {
    to_hex(bytes)[2..].to_owned()
}

pub fn unhex(text: &str) -> Vec<u8> {
    parse_bytes(&format!("0x{}", text.trim_start_matches("0x")), "hex").unwrap()
}

pub fn account(record: &Value) -> Account {
    Account {
        path: LedgerPath::parse(record["path"].as_str().unwrap()).unwrap(),
        address: parse_address(record["address"].as_str().unwrap()).unwrap(),
    }
}

/// The account at a path, its address abandon-12's there.
pub fn account_at(path: &str) -> Account {
    let path = LedgerPath::parse(path).unwrap();
    let address = *key_at(&path).address().as_bytes();
    Account { path, address }
}

/// What the scripted device does at one of its APDUs (0-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The status word alone.
    Status(u16),
    /// node-hid's read fails.
    Disconnect,
    /// The proper answer with one more byte before its status.
    Long,
    /// The proper answer with one byte less before its status.
    Short,
    /// `E0 02`: another key, with the path's address text.
    KeyNotAddress,
    /// `E0 02`: another key and its own address.
    OtherAddress,
    /// A signature by another key.
    OtherKey,
    /// A signature over keccak256 of the digest.
    OtherDigest,
    /// The same signature with `s` in the high half.
    HighS,
    /// The parity flipped.
    FlipV,
    /// `v` set to this byte.
    V(u8),
}

/// The scripted Ledger.
pub struct Device {
    pub app_name: String,
    pub app_version: String,
    /// `false`: a Nano S, `6D00` to every `E0 1A` and `E0 1C`.
    pub fields: bool,
    /// The hash `E0 0C 00 01` signs.
    pub typed_hash: Option<[u8; 32]>,
    pub fault: Option<(usize, Fault)>,
    pub count: usize,
    tx: Option<(LedgerPath, Vec<u8>)>,
    msg: Option<(LedgerPath, usize, Vec<u8>)>,
}

/// A device's answer, or its disconnect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Bytes(Vec<u8>),
    Disconnected,
}

const OK: [u8; 2] = [0x90, 0x00];

impl Default for Device {
    fn default() -> Self {
        Device {
            app_name: "Ethereum".into(),
            app_version: "1.13.0".into(),
            fields: true,
            typed_hash: None,
            fault: None,
            count: 0,
            tx: None,
            msg: None,
        }
    }
}

fn path_of(data: &[u8]) -> (LedgerPath, usize) {
    let n = data[0] as usize;
    let elements: Vec<u32> = (0..n)
        .map(|i| u32::from_be_bytes(data[1 + 4 * i..5 + 4 * i].try_into().unwrap()))
        .collect();
    let text = elements
        .iter()
        .map(|e| {
            if e & 0x8000_0000 != 0 {
                format!("{}'", e & 0x7fff_ffff)
            } else {
                e.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    (LedgerPath::parse(&text).unwrap(), 1 + 4 * n)
}

/// The total length of the RLP list at the head of `bytes`, once its header
/// is whole.
fn rlp_length(bytes: &[u8]) -> Option<usize> {
    let b = *bytes.first()?;
    assert!(b >= 0xc0, "a transaction is a list");
    if b <= 0xf7 {
        return Some(1 + (b - 0xc0) as usize);
    }
    let width = (b - 0xf7) as usize;
    let len = bytes.get(1..1 + width)?;
    Some(1 + width + len.iter().fold(0usize, |acc, x| (acc << 8) | *x as usize))
}

impl Device {
    pub fn answer(&mut self, apdu: &[u8]) -> Answer {
        let at = self.count;
        self.count += 1;
        let fault = self.fault.filter(|(index, _)| *index == at).map(|(_, f)| f);
        match fault {
            Some(Fault::Status(status)) => return Answer::Bytes(status.to_be_bytes().to_vec()),
            Some(Fault::Disconnect) => return Answer::Disconnected,
            _ => {}
        }
        let (cla, ins, p1, p2, lc) = (apdu[0], apdu[1], apdu[2], apdu[3], apdu[4]);
        let data = &apdu[5..];
        assert_eq!(lc as usize, data.len(), "Lc is the data's length");
        let mut body = if cla == 0xb0 && ins == 0x01 {
            let mut out = vec![1, self.app_name.len() as u8];
            out.extend_from_slice(self.app_name.as_bytes());
            out.push(self.app_version.len() as u8);
            out.extend_from_slice(self.app_version.as_bytes());
            out.extend_from_slice(&[1, 0]);
            out
        } else {
            assert_eq!(cla, 0xe0);
            if !self.fields && (ins == 0x1a || ins == 0x1c) {
                return Answer::Bytes(vec![0x6d, 0x00]);
            }
            match ins {
                0x02 => self.address(data, fault),
                0x04 => self.transaction(p1, data, fault).unwrap_or_default(),
                0x08 => self.message(p1, data, fault).unwrap_or_default(),
                0x1a | 0x1c => Vec::new(),
                0x0c => self.typed(p2, data, fault),
                other => panic!("no INS {other:02x}"),
            }
        };
        match fault {
            Some(Fault::Long) => body.push(0),
            Some(Fault::Short) => {
                body.pop();
            }
            _ => {}
        }
        body.extend_from_slice(&OK);
        Answer::Bytes(body)
    }

    fn address(&self, data: &[u8], fault: Option<Fault>) -> Vec<u8> {
        let (path, length) = path_of(data);
        assert_eq!(length, data.len(), "E0 02 carries one path");
        let own = key_at(&path);
        let other = other_key();
        let (key, text) = match fault {
            Some(Fault::OtherAddress) => (other.public_key_uncompressed(), other.address()),
            Some(Fault::KeyNotAddress) => (other.public_key_uncompressed(), own.address()),
            _ => (own.public_key_uncompressed(), own.address()),
        };
        let mut out = vec![65];
        out.extend_from_slice(&key);
        out.push(40);
        out.extend_from_slice(&text.to_checksum().as_bytes()[2..]);
        out
    }

    fn transaction(&mut self, p1: u8, data: &[u8], fault: Option<Fault>) -> Option<Vec<u8>> {
        if p1 == 0x00 {
            let (path, length) = path_of(data);
            self.tx = Some((path, data[length..].to_vec()));
        } else {
            assert_eq!(p1, 0x80);
            self.tx.as_mut().unwrap().1.extend_from_slice(data);
        }
        let (path, t) = self.tx.clone().unwrap();
        let typed = t[0] < 0x80;
        let body = if typed { &t[1..] } else { &t[..] };
        let total = rlp_length(body)?;
        if body.len() < total {
            return None;
        }
        assert_eq!(body.len(), total, "no byte past the transaction");
        self.tx = None;
        let digest = keccak256(&t);
        let (rs, parity) = self.sign(&path, &digest, fault);
        let v = if typed {
            parity
        } else {
            let fields = rlp::decode(body).unwrap().list().unwrap();
            let chain = fields.items().nth(6).unwrap().unwrap().bytes().unwrap();
            let prime = chain
                .iter()
                .take(4)
                .fold(0u64, |acc, b| (acc << 8) | *b as u64);
            ((prime * 2 + 35 + parity as u64) % 256) as u8
        };
        Some(signature_answer(v, &rs, fault))
    }

    fn message(&mut self, p1: u8, data: &[u8], fault: Option<Fault>) -> Option<Vec<u8>> {
        if p1 == 0x00 {
            let (path, length) = path_of(data);
            let len = u32::from_be_bytes(data[length..length + 4].try_into().unwrap()) as usize;
            self.msg = Some((path, len, data[length + 4..].to_vec()));
        } else {
            assert_eq!(p1, 0x80);
            self.msg.as_mut().unwrap().2.extend_from_slice(data);
        }
        let (path, len, bytes) = self.msg.clone().unwrap();
        if bytes.len() < len {
            return None;
        }
        assert_eq!(bytes.len(), len, "no byte past the message");
        self.msg = None;
        let (rs, parity) = self.sign(&path, &eip191_digest(&bytes), fault);
        Some(signature_answer(27 + parity, &rs, fault))
    }

    fn typed(&self, p2: u8, data: &[u8], fault: Option<Fault>) -> Vec<u8> {
        let (path, length) = path_of(data);
        let digest = if p2 == 0x01 {
            assert_eq!(length, data.len(), "E0 0C 00 01 carries the path only");
            self.typed_hash.expect("the device's typed-data hash")
        } else {
            assert_eq!(p2, 0x00);
            assert_eq!(data.len() - length, 64, "E0 0C 00 00 carries two hashes");
            let mut whole = vec![0x19, 0x01];
            whole.extend_from_slice(&data[length..]);
            keccak256(&whole)
        };
        let (rs, parity) = self.sign(&path, &digest, fault);
        signature_answer(27 + parity, &rs, fault)
    }

    fn sign(&self, path: &LedgerPath, digest: &[u8; 32], fault: Option<Fault>) -> ([u8; 64], u8) {
        let key = match fault {
            Some(Fault::OtherKey) => other_key(),
            _ => key_at(path),
        };
        let signed = match fault {
            Some(Fault::OtherDigest) => keccak256(digest),
            _ => *digest,
        };
        let signature = sign_digest(key.signing_key(), &signed).unwrap();
        let mut rs = [0u8; 64];
        rs.copy_from_slice(&signature[..64]);
        let mut parity = signature[64] - 27;
        if fault == Some(Fault::HighS) {
            let s = U256::from_be_slice(&rs[32..]).unwrap();
            let high = order().checked_sub(&s).unwrap();
            rs[32..].copy_from_slice(&high.to_be_bytes());
            parity ^= 1;
        }
        if fault == Some(Fault::FlipV) {
            parity ^= 1;
        }
        (rs, parity)
    }
}

/// secp256k1's order.
pub fn order() -> U256 {
    U256::parse_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap()
}

fn signature_answer(v: u8, rs: &[u8; 64], fault: Option<Fault>) -> Vec<u8> {
    let v = match fault {
        Some(Fault::V(v)) => v,
        _ => v,
    };
    let mut out = vec![v];
    out.extend_from_slice(rs);
    out
}

/// Drives an operation to its end, each APDU answered by `reply`. Returns
/// the APDUs it sent, whether each waits for the user, and its end.
pub struct Run {
    pub apdus: Vec<Vec<u8>>,
    pub confirms: Vec<bool>,
    pub done: Result<Signed, fc_ledger::Failure>,
}

pub fn run(op: &mut Operation, mut reply: impl FnMut(usize, &[u8]) -> Owned) -> Run {
    let mut apdus = Vec::new();
    let mut confirms = Vec::new();
    let mut step = op.start();
    loop {
        match step {
            Step::Send(exchange) => {
                assert!(apdus.len() < 5000, "an operation that doesn't end");
                let apdu = exchange.apdu.into_bytes();
                let owned = reply(apdus.len(), &apdu);
                apdus.push(apdu);
                confirms.push(exchange.confirm);
                step = op.answer(owned.as_reply());
            }
            Step::Done(done) => {
                return Run {
                    apdus,
                    confirms,
                    done,
                };
            }
        }
    }
}

/// An owned [`Reply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owned {
    Answer(Vec<u8>, bool),
    Failed(Failed),
    Refused,
}

impl Owned {
    pub fn as_reply(&self) -> Reply<'_> {
        match self {
            Owned::Answer(answer, shown) => Reply::Answer {
                answer,
                hash_only_shown: *shown,
            },
            Owned::Failed(failed) => Reply::Failed(*failed),
            Owned::Refused => Reply::Refused,
        }
    }
}

/// Main as the design has it for the tests: a device's answer relayed, a
/// disconnect as `failed: disconnected`, and a `6D00` to the operation's
/// first `E0 1A` with `hash_only: "shown"` (the warning is on screen).
pub fn relay(index: usize, apdu: &[u8], answer: Answer) -> Owned {
    match answer {
        Answer::Disconnected => Owned::Failed(Failed::Disconnected),
        Answer::Bytes(bytes) => {
            let first_definition = index == 2 && apdu[..4] == [0xe0, 0x1a, 0x00, 0x00];
            let shown = first_definition && bytes == [0x6d, 0x00];
            Owned::Answer(bytes, shown)
        }
    }
}

/// An operation over the scripted device alone.
pub fn run_device(op: &mut Operation, device: &mut Device) -> Run {
    run(op, |index, apdu| relay(index, apdu, device.answer(apdu)))
}

/// The operation a case's request names, or its refusal; with the hash
/// its typed data's signature recovers over.
pub fn operation(case: &Value) -> Result<Operation, fc_ledger::Refusal> {
    let request = &case["request"];
    match case["operation"].as_str().unwrap() {
        "ledger.accounts" => Operation::accounts(
            fc_ledger::Scheme::parse(request["scheme"].as_str().unwrap()).unwrap(),
            request["start"].as_u64().unwrap(),
            request["count"].as_u64().unwrap(),
        ),
        "ledger.add" => LedgerPath::parse(request["path"].as_str().unwrap())
            .map(Operation::add)
            .map_err(fc_ledger::Refusal::Path),
        "sign.transaction" => Operation::sign_transaction(
            account(&case["record"]),
            &Transaction::from_json(&request["tx"]).unwrap(),
        ),
        "sign.message" => Operation::sign_message(
            account(&case["record"]),
            unhex(request["message"].as_str().unwrap()),
        ),
        "sign.typed_data" => typed_operation(
            account(&case["record"]),
            &request["typed_data"],
            &typed_hash(case),
        ),
        other => panic!("no operation {other}"),
    }
}

pub fn typed_hash(case: &Value) -> [u8; 32] {
    unhex(case["request"]["expected_hash"].as_str().unwrap())
        .try_into()
        .unwrap()
}

pub fn typed_operation(
    account: Account,
    typed: &Value,
    hash: &[u8; 32],
) -> Result<Operation, fc_ledger::Refusal> {
    Operation::sign_typed_data(
        account,
        &typed["domain"],
        &typed["types"],
        &typed["message"],
        hash,
    )
}

/// A scripted device for a case's request: its app, its fields, its hash.
pub fn device_for(case: &Value) -> Device {
    let mut device = Device::default();
    if let Some(app) = case["device"].get("app") {
        device.app_name = app["name"].as_str().unwrap().into();
        device.app_version = app["version"].as_str().unwrap().into();
    }
    device.fields = case["device"].get("fields") != Some(&Value::Bool(false));
    if case["operation"] == "sign.typed_data" {
        device.typed_hash = Some(typed_hash(case));
    }
    device
}
