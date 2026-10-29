//! fc_ipfs::ipns against every IPNS record in the vectors: the design's
//! cases in dweb-verify-cases.json (RSA lies, other key types, a weak
//! Ed25519 key, CBOR bounds), and the records in dweb-verify.json with
//! freedom-ipfs's verdict on each.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use base64::Engine;
use fc_ipfs::{Refusal, cid, ipns};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn code(r: Refusal) -> &'static str {
    match r {
        Refusal::VerificationFailed => "verification_failed",
        Refusal::Unverifiable => "unverifiable",
        Refusal::Malformed => "malformed",
    }
}

fn check(name: &str, record: &[u8], now: i64) -> Result<ipns::Record, Refusal> {
    let bytes = cid::from_key_text(name).unwrap_or_else(|| panic!("{name} isn't a key CID"));
    let name = cid::parse(&bytes).unwrap();
    ipns::check(&name, record, now)
}

fn as_json(r: &Result<ipns::Record, Refusal>) -> Value {
    match r {
        Ok(r) => {
            serde_json::json!({ "ok": { "value": r.value, "sequence": r.sequence, "validity": r.validity, "ttl_ns": r.ttl_ns } })
        }
        Err(e) => serde_json::json!({ "fail": code(*e) }),
    }
}

#[test]
fn the_designs_cases() {
    let cases = load("dweb-verify-cases.json");
    let now = cases["meta"]["clock_unix"].as_i64().unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    let list = cases["ipns"]["records"].as_array().unwrap();
    assert!(list.len() >= 20);
    for c in list {
        let id = &c["id"];
        let record = b64.decode(c["record"]["base64"].as_str().unwrap()).unwrap();
        let got = check(c["name"].as_str().unwrap(), &record, now);
        assert_eq!(as_json(&got), c["expect"], "{id}");
        // freedom-ipfs agrees, unless the case names a deviation.
        if c.get("deviation").is_none() {
            assert_eq!(
                got.is_ok(),
                c["native"].get("ok").is_some(),
                "{id}: freedom-ipfs says {}",
                c["native"]
            );
        }
    }
}

/// The records 1b signed, with freedom-ipfs's verdicts: the core agrees,
/// except for RSA keys encoded otherwise than libp2p's deterministic form
/// or of 2,041 bits, which the native reader takes (deviation rsa-keys).
#[test]
fn freedom_ipfs_verdicts() {
    let doc = load("dweb-verify.json");
    let b64 = base64::engine::general_purpose::STANDARD;
    let rsa_keys = ["rsa-2041", "rsa-fields-reordered", "rsa-unknown-key-field"];
    // The validities are far from any day the vectors are read.
    let now = doc["meta"]["clock_unix"].as_i64().unwrap();
    let mut n = 0;
    for r in doc["ipfs"]["ipns"]["records"].as_array().unwrap() {
        let id = r["id"].as_str().unwrap();
        let record = b64.decode(r["record"].as_str().unwrap()).unwrap();
        let got = check(r["name"].as_str().unwrap(), &record, now);
        if rsa_keys.contains(&id) {
            assert_eq!(got, Err(Refusal::VerificationFailed), "{id}");
            assert!(r["native"].get("ok").is_some(), "{id}");
        } else if let Some(ok) = r["native"].get("ok") {
            let got = got.unwrap_or_else(|e| panic!("{id}: {e:?}"));
            assert_eq!(got.value, ok["value"], "{id}");
            assert_eq!(got.sequence, ok["sequence"].as_u64().unwrap(), "{id}");
            assert_eq!(got.validity, ok["validity"], "{id}");
            assert_eq!(got.ttl_ns, ok["ttl_ns"].as_u64().unwrap(), "{id}");
        } else {
            assert_eq!(
                got.map(|_| ()),
                Err(Refusal::VerificationFailed),
                "{id}: freedom-ipfs says {}",
                r["native"]
            );
        }
        n += 1;
    }
    assert!(n >= 19, "{n}");
}

#[test]
fn an_expired_record_at_its_second() {
    // ed25519-v2 is valid until 2099-01-01T00:00:00Z: valid the second
    // before, expired at it.
    let doc = load("dweb-verify.json");
    let b64 = base64::engine::general_purpose::STANDARD;
    let r = doc["ipfs"]["ipns"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "ed25519-v2")
        .unwrap();
    let record = b64.decode(r["record"].as_str().unwrap()).unwrap();
    let name = r["name"].as_str().unwrap();
    assert!(check(name, &record, 4_070_908_799).is_ok());
    assert_eq!(
        check(name, &record, 4_070_908_800).map(|_| ()),
        Err(Refusal::VerificationFailed)
    );
}
