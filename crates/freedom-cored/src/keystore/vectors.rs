//! `vectors/keystore.json` (design 0013, PRF-1b): the helper's answers
//! under a fixed request key, with the refusals, byte for byte.
//!
//! - **`helper`:** each request through the helper's own logic
//!   ([`helper::answer`]), with the one OS call scripted and the RNG's draws
//!   fixed: the exact line, every draw used, and no OS call but the one the
//!   case names.
//! - **`answers`:** each answer main relays, read as the core reads it
//!   ([`client::relayed_answer`], then [`client::take`]) with the fixed
//!   request key's private half: the wrapping key (and a DPAPI create's
//!   blob), done, or the error, and for `backend` its reason.
//!
//! The generator seals with HPKE composed from Node's primitives and pinned
//! to RFC 9180's own vectors; this replays it with the `hpke` crate
//! through fc-seal.

use std::cell::RefCell;
use std::ffi::OsString;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use fc_keystore::{Backend, BackendError, Capabilities, ItemId, KeyStoreError, Policy};
use serde_json::Value;
use zeroize::Zeroizing;

use super::client::{self, Taken};
use super::helper::{self, OsStore};
use super::{Answer, LABEL, MAX_ANSWER_BYTES, Op, SEALED_KEY_BYTES};
use crate::rng::RngError;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../../vectors/keystore.json")).unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "{text}");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key}: {value}"))
}

/// Hands out the case's draws in order, each one fill of its exact length;
/// a fill past the list, or of another length, fails.
struct Draws {
    draws: Vec<Vec<u8>>,
    used: usize,
}

impl Draws {
    fn new(draws: &[Value]) -> Self {
        Self {
            draws: draws.iter().map(|d| unhex(d.as_str().unwrap())).collect(),
            used: 0,
        }
    }

    fn all_used(&self) -> bool {
        self.used == self.draws.len()
    }
}

impl rand_core::TryRng for Draws {
    type Error = RngError;

    fn try_next_u32(&mut self) -> Result<u32, RngError> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, RngError> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
        match self.draws.get(self.used) {
            Some(draw) if draw.len() == dst.len() => {
                dst.copy_from_slice(draw);
                self.used += 1;
                Ok(())
            }
            _ => Err(RngError),
        }
    }
}

impl rand_core::TryCryptoRng for Draws {}

/// The fixed request key: the key pair DeriveKeyPair gives for its `ikm`.
fn recipient(v: &Value) -> fc_seal::RecipientKey {
    let ikm = unhex(str_of(&v["recipient"], "ikm"));
    let mut draws = Draws {
        draws: vec![ikm],
        used: 0,
    };
    let key = fc_seal::RecipientKey::generate(&mut draws).unwrap();
    assert!(draws.all_used());
    key
}

fn error_of(code: &str, reason: Option<&str>) -> KeyStoreError {
    match code {
        "not_found" => KeyStoreError::NotFound,
        "cancelled" => KeyStoreError::Cancelled,
        "unavailable" => super::unavailable(match reason {
            Some("timeout") => "timeout",
            _ => "unsupported",
        }),
        "invalidated" => KeyStoreError::Invalidated,
        "denied" => KeyStoreError::Denied,
        // The line carries the reason; the error's own is the store's.
        "backend" => KeyStoreError::Backend(BackendError::new(match reason {
            Some("duplicate") => "duplicate",
            _ => "status",
        })),
        other => panic!("error {other}"),
    }
}

/// The one OS call a case scripts, and what the store answers.
struct Scripted {
    call: Option<Value>,
    result: Option<Value>,
    calls: RefCell<Vec<Vec<String>>>,
}

impl Scripted {
    fn record(&self, call: Vec<String>) -> Result<(), Answer> {
        let mut calls = self.calls.borrow_mut();
        calls.push(call.clone());
        let expected: Option<Vec<String>> = self.call.as_ref().map(|c| {
            c.as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_owned())
                .collect()
        });
        assert_eq!(Some(call), expected, "an OS call the case doesn't name");
        assert_eq!(calls.len(), 1, "a second OS call");
        match self.result.as_ref().unwrap() {
            Value::String(ok) if ok == "ok" => Ok(()),
            Value::Object(result) if result.contains_key("failed") => {
                let failed = result["failed"].as_array().unwrap();
                let reason = failed[1].as_str();
                Err(Answer::Failed {
                    error: error_of(failed[0].as_str().unwrap(), reason),
                    reason: reason.map(str::to_owned),
                })
            }
            Value::Object(result) if result.contains_key("key") => Ok(()),
            other => panic!("result {other}"),
        }
    }

    fn opened_key(&self) -> Zeroizing<[u8; 32]> {
        let key = unhex(str_of(self.result.as_ref().unwrap(), "key"));
        Zeroizing::new(key.try_into().unwrap())
    }
}

impl OsStore for Scripted {
    fn create(&self, policy: Policy, item: ItemId, key: &[u8; 32]) -> Result<(), Answer> {
        self.record(vec![
            "create".into(),
            policy.name().into(),
            item.hex(),
            hex(key),
        ])
    }

    fn open(&self, policy: Policy, item: ItemId) -> Result<Zeroizing<[u8; 32]>, Answer> {
        self.record(vec!["open".into(), policy.name().into(), item.hex()])?;
        Ok(self.opened_key())
    }

    fn forget(&self, policy: Policy, item: ItemId) -> Result<(), Answer> {
        self.record(vec!["forget".into(), policy.name().into(), item.hex()])
    }
}

#[test]
fn the_fixed_request_key_is_the_vectors() {
    let v = vectors();
    assert_eq!(str_of(&v["constants"], "label").as_bytes(), LABEL);
    assert_eq!(v["constants"]["max_answer_bytes"], MAX_ANSWER_BYTES);
    assert_eq!(v["constants"]["sealed_key_bytes"], SEALED_KEY_BYTES);
    // fc-seal's suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
    assert_eq!(
        (
            &v["constants"]["kem_id"],
            &v["constants"]["kdf_id"],
            &v["constants"]["aead_id"]
        ),
        (&Value::from(0x20), &Value::from(1), &Value::from(2))
    );
    let public = recipient(&v).public_key();
    assert_eq!(hex(&public), str_of(&v["recipient"], "pk"));
    assert_eq!(
        STANDARD.encode(public),
        str_of(&v["recipient"], "pk_base64")
    );
}

#[test]
fn the_helper_writes_each_line_of_the_vectors() {
    let v = vectors();
    let cases = v["helper"].as_array().unwrap();
    assert!(cases.len() >= 20);
    for case in cases {
        let id = str_of(case, "id");
        let args: Vec<OsString> = case["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| OsString::from(a.as_str().unwrap()))
            .collect();
        let stdin = unhex(str_of(case, "stdin_hex"));
        let offers = match &case["offers"] {
            Value::Null => None,
            offers => Some(Capabilities {
                backend: Some(Backend::parse(str_of(offers, "backend")).unwrap()),
                unattended: offers["unattended"].as_bool().unwrap(),
                user_presence: offers["user_presence"].as_bool().unwrap(),
            }),
        };
        let store = Scripted {
            call: case["os"].get("call").cloned(),
            result: case["os"].get("result").cloned(),
            calls: RefCell::new(Vec::new()),
        };
        let mut draws = Draws::new(case["rng"].as_array().unwrap());
        let answer = helper::answer(
            args.into_iter(),
            &mut stdin.as_slice(),
            offers.map(|caps| (&store as &dyn OsStore, caps)),
            &mut draws,
        )
        .unwrap_or_else(|| panic!("{id}: no answer"));
        let mut line = answer.text();
        line.push('\n');
        assert_eq!(line, str_of(case, "line"), "{id}");
        assert!(line.len() <= MAX_ANSWER_BYTES, "{id}");
        assert!(draws.all_used(), "{id}: draws left");
        let calls = store.calls.borrow().len();
        assert_eq!(calls, usize::from(case["os"].is_object()), "{id}: OS calls");
    }
}

#[test]
fn the_core_reads_each_answer_of_the_vectors() {
    let v = vectors();
    let cases = v["answers"].as_array().unwrap();
    assert!(cases.len() >= 80);
    let (mut keys, mut refused) = (0, 0);
    for case in cases {
        let id = str_of(case, "id");
        let request = &case["request"];
        let op = Op::parse(str_of(request, "op")).unwrap();
        let backend = Backend::parse(str_of(request, "backend")).unwrap();
        let item = ItemId::parse(str_of(request, "item")).unwrap();
        let text = str_of(case, "text").as_bytes();
        let taken = client::relayed_answer(text).and_then(|answer| {
            client::take(
                op,
                item,
                backend.keeps_blob(),
                op.returns_key().then(|| recipient(&v)),
                answer,
            )
        });
        let outcome = &case["outcome"];
        match (taken, outcome) {
            (Ok(Taken::Key(key, blob)), _) if outcome.get("key").is_some() => {
                assert_eq!(hex(key.expose()), str_of(outcome, "key"), "{id}");
                assert_eq!(
                    blob.map(|b| b.base64()),
                    outcome.get("blob").map(|b| b.as_str().unwrap().to_owned()),
                    "{id}"
                );
                keys += 1;
            }
            (Ok(Taken::Done), _) if outcome == &serde_json::json!({ "done": true }) => {}
            (Err(error), _) if outcome.get("error").is_some() => {
                assert_eq!(error.code(), str_of(outcome, "error"), "{id}");
                match error {
                    KeyStoreError::Backend(backend) => {
                        assert_eq!(backend.reason(), str_of(outcome, "reason"), "{id}");
                    }
                    // The line's reason comes through the trait.
                    KeyStoreError::Unavailable(why) => {
                        assert!(outcome.get("reason").is_none(), "{id}");
                        let line: Value = serde_json::from_str(str_of(case, "text")).unwrap();
                        let reason = line["reason"].as_str();
                        assert!(
                            reason == Some(why.reason()) || why.reason() == "helper",
                            "{id}: {why}"
                        );
                    }
                    _ => assert!(outcome.get("reason").is_none(), "{id}"),
                }
                refused += 1;
            }
            (Ok(Taken::Key(..)), _) => panic!("{id}: opened, expected {outcome}"),
            (Ok(Taken::Done), _) => panic!("{id}: done, expected {outcome}"),
            (Err(error), _) => panic!("{id}: {error:?}, expected {outcome}"),
        }
    }
    assert!(keys >= 5 && refused >= 70, "{keys} keys, {refused} refused");
}

/// Each sealed answer the vectors call good opens under the request's own
/// associated data, rebuilt by the core's function, and the generator
/// wrote that same associated data.
#[test]
fn the_vectors_bind_the_cores_associated_data() {
    let v = vectors();
    for case in v["answers"].as_array().unwrap() {
        let Some(key) = case["outcome"].get("key") else {
            continue;
        };
        let request = &case["request"];
        let op = Op::parse(str_of(request, "op")).unwrap();
        let item = ItemId::parse(str_of(request, "item")).unwrap();
        let blob = case["outcome"]
            .get("blob")
            .map(|b| fc_keystore::Blob::from_base64(b.as_str().unwrap()).unwrap());
        let aad = super::associated_data(op, item, blob.as_ref());
        let sealed = &case["sealed"];
        assert_eq!(hex(&aad), str_of(sealed, "aad_hex"), "{}", case["id"]);
        assert_eq!(str_of(sealed, "info").as_bytes(), LABEL);
        assert_eq!(str_of(sealed, "wrap"), key.as_str().unwrap());
    }
}
