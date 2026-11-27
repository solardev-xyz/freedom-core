//! The entry codec against `vectors/safe.json`'s flows: each entry the
//! reference's `startSafeSend` and `signEntryOwner` leave written as it
//! writes it, and read back with every signature counted; what the codec
//! sets aside, refuses and drops; and the core's proposal mark, read only
//! in the form the core writes it for the entry's Safe and SafeTx, and
//! kept through main's set only for the same Safe and SafeTx.

use std::path::PathBuf;

use fc_evm::{U256, keccak256, sign_digest};
use fc_safe::{Setup, parse_salt};
use k256::ecdsa::SigningKey;
use serde_json::{Value, json};

use super::*;

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/safe.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn address(value: &Value) -> [u8; 20] {
    parse_address(value.as_str().unwrap()).unwrap()
}

/// A flow's Safe: its owners' addresses, in the record's order, its
/// threshold and its address.
fn safe_of(v: &Value, flow: &Value) -> (Setup, [u8; 20]) {
    let safe = &flow["safe"];
    let owners = safe["owners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| address(&v["owners"][name.as_str().unwrap()]["address"]))
        .collect();
    let setup = Setup::new(owners, safe["threshold"].as_u64().unwrap() as usize).unwrap();
    let salt = parse_salt(safe["saltNonce"].as_str().unwrap()).unwrap();
    let at = setup.address(&salt);
    assert_eq!(checksum_address(&at), safe["address"]);
    (setup, at)
}

fn js(value: &Value) -> JsValue {
    fc_json::parse(&value.to_string()).unwrap()
}

/// The entry without its clock reading, as the vectors record it.
fn without_clock(entry: &JsValue) -> Value {
    let mut value: Value = serde_json::from_str(&entry.stringify()).unwrap();
    value.as_object_mut().unwrap().shift_remove("createdAt");
    value
}

#[test]
fn every_entry_the_reference_writes_is_written_and_read_back() {
    let v = vectors();
    let mut checked = 0;
    for flow in v["flows"].as_array().unwrap() {
        let (setup, safe) = safe_of(&v, flow);
        for step in flow["steps"].as_array().unwrap() {
            let pending = &step["pending"];
            if !pending.is_object() || pending.get("superseded").is_some() {
                continue;
            }
            let id = format!("{} {}", flow["id"], step["step"]);
            // Read back: every signature counts.
            let read = read(&js(pending), &safe, setup.owners()).unwrap();
            let listed = pending["signatures"].as_array().unwrap();
            assert_eq!(read.signatures.len(), listed.len(), "{id}");
            assert_eq!(read.refused, 0, "{id}");
            assert!(!read.superseded);
            assert_eq!(to_hex(&read.hash), pending["safeTxHash"], "{id}");
            // Written again from the SafeTx and those signatures, in the
            // order the owners signed: the reference's text.
            let signatures: Vec<OwnerSignature> = listed
                .iter()
                .map(|s| {
                    OwnerSignature::check(
                        &read.hash,
                        &parse_bytes(s["data"].as_str().unwrap(), "data").unwrap(),
                        &address(&s["signer"]),
                        setup.owners(),
                    )
                    .unwrap()
                })
                .collect();
            let display = js(&pending["display"]);
            let entry = written(&New {
                safe: &safe,
                tx: &read.tx,
                hash: &read.hash,
                threshold: setup.threshold(),
                display: Some(&display),
                signatures: &signatures,
                created_at_ms: 1_700_000_000_123,
            })
            .unwrap();
            assert_eq!(without_clock(&entry), *pending, "{id}");
            assert_eq!(
                entry.get("createdAt"),
                Some(&JsValue::Number(1_700_000_000_123.0))
            );
            // Its text is the reference's, key for key.
            let mut text = pending.clone();
            text["createdAt"] = json!(1_700_000_000_123u64);
            assert_eq!(entry.stringify(), text.to_string(), "{id}");
            checked += 1;
        }
    }
    assert!(checked >= 8, "{checked}");
    // A superseded entry reads as superseded.
    let flow = &v["flows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|flow| flow["id"] == "superseded")
        .unwrap();
    let (setup, safe) = safe_of(&v, flow);
    let pending = &flow["steps"][2]["pending"];
    assert_eq!(pending["superseded"], true);
    assert!(
        read(&js(pending), &safe, setup.owners())
            .unwrap()
            .superseded
    );
}

/// The one-of-two flow's first entry, its Safe and setup.
fn start() -> (Value, Setup, [u8; 20]) {
    let v = vectors();
    let flow = v["flows"][0].clone();
    assert_eq!(flow["id"], "one-of-two");
    let (setup, safe) = safe_of(&v, &flow);
    (flow["steps"][0]["pending"].clone(), setup, safe)
}

#[test]
fn an_entry_that_isnt_its_safes_is_set_aside() {
    let (pending, setup, safe) = start();
    let owners = setup.owners();
    let aside = |entry: &Value| read(&js(entry), &safe, owners).map(|_| ()).unwrap_err();
    let changed = |name: &str, value: Value| {
        let mut entry = pending.clone();
        entry[name] = value;
        entry
    };
    assert_eq!(aside(&json!("an entry")), SetAside::Shape);
    assert_eq!(aside(&json!([pending.clone()])), SetAside::Shape);
    assert_eq!(aside(&changed("signatures", json!({}))), SetAside::Shape);
    assert_eq!(aside(&changed("chainId", json!(1))), SetAside::Chain);
    assert_eq!(aside(&changed("chainId", json!("100"))), SetAside::Chain);
    let other = checksum_address(&[0x77; 20]);
    assert_eq!(aside(&changed("safeAddress", json!(other))), SetAside::Safe);
    let mut missing = pending.clone();
    missing.as_object_mut().unwrap().shift_remove("safeAddress");
    assert_eq!(aside(&missing), SetAside::Safe);
    // Each of the ten fields changed: its hash no longer recomputes, or it
    // isn't one of Freedom's SafeTxs at all.
    for (name, value, why) in [
        ("to", json!(other), SetAside::Hash),
        ("value", json!("1"), SetAside::Hash),
        ("data", json!("0x00"), SetAside::Hash),
        ("nonce", json!(4), SetAside::Hash),
        ("operation", json!(1), SetAside::Fields),
        ("safeTxGas", json!("1"), SetAside::Fields),
        ("baseGas", json!("1"), SetAside::Fields),
        ("gasPrice", json!("1"), SetAside::Fields),
        ("gasToken", json!(other), SetAside::Fields),
        ("refundReceiver", json!(other), SetAside::Fields),
    ] {
        let mut entry = pending.clone();
        entry["safeTxData"][name] = value;
        assert_eq!(aside(&entry), why, "{name}");
    }
    let mut extra = pending.clone();
    extra["safeTxData"]["signatures"] = json!("0x");
    assert_eq!(aside(&extra), SetAside::Fields);
    assert_eq!(
        aside(&changed("safeTxHash", json!(to_hex(&[0x11; 32])))),
        SetAside::Hash
    );
    assert_eq!(aside(&changed("safeTxHash", json!(null))), SetAside::Hash);
    // The same entry for another Safe of the same owners.
    let elsewhere = setup.address(&U256::from_u64(99));
    assert_eq!(
        read(&js(&pending), &elsewhere, owners)
            .map(|_| ())
            .unwrap_err(),
        SetAside::Safe
    );
    // `typedData` isn't read: nothing signs from it.
    let mut typed = pending.clone();
    typed["typedData"] = json!(null);
    assert!(read(&js(&typed), &safe, owners).is_ok());
    // The hash in upper case is the same hash.
    let upper = pending["safeTxHash"]
        .as_str()
        .unwrap()
        .to_uppercase()
        .replace("0X", "0x");
    assert!(read(&js(&changed("safeTxHash", json!(upper))), &safe, owners).is_ok());
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&keccak256(&[n]).into()).unwrap()
}

#[test]
fn only_an_owners_good_signature_counts_once() {
    let (pending, setup, safe) = start();
    let owners = setup.owners();
    let hash: [u8; 32] = parse_bytes(pending["safeTxHash"].as_str().unwrap(), "")
        .unwrap()
        .try_into()
        .unwrap();
    let good = pending["signatures"][0].clone();
    let data = parse_bytes(good["data"].as_str().unwrap(), "").unwrap();
    let with = |signatures: Vec<Value>| {
        let mut entry = pending.clone();
        entry["signatures"] = Value::Array(signatures);
        let read = read(&js(&entry), &safe, owners).unwrap();
        (read.signatures.len(), read.refused)
    };
    assert_eq!(with(vec![good.clone()]), (1, 0));
    // A second from the same owner is dropped; the first counts.
    assert_eq!(with(vec![good.clone(), good.clone()]), (1, 1));
    // Each other kind is refused, and the entry stays.
    let bad = |data: Vec<u8>| json!({ "signer": good["signer"], "data": to_hex(&data) });
    let mut v0 = data.clone();
    v0[64] = 0;
    let mut v1 = data.clone();
    v1[64] = 1;
    let mut flipped = data.clone();
    flipped[64] ^= 1;
    // The same signature with its `s` in the high half (n − s, `v` flipped).
    let n = U256::parse_decimal(
        "115792089237316195423570985008687907852837564279074904382605163141518161494337",
    )
    .unwrap();
    let s = U256::from_be_slice(&data[32..64]).unwrap();
    let mut high = data.clone();
    high[32..64].copy_from_slice(&n.checked_sub(&s).unwrap().to_be_bytes());
    high[64] ^= 1;
    let elsewhere = sign_digest(&key(9), &[0x22; 32]).unwrap();
    let stranger = sign_digest(&key(9), &hash).unwrap();
    for (what, signature) in [
        ("v 0", bad(v0)),
        ("v 1", bad(v1)),
        ("v flipped", bad(flipped)),
        ("64 bytes", bad(data[..64].to_vec())),
        ("66 bytes", bad([data.as_slice(), &[0]].concat())),
        ("a high s", bad(high)),
        ("another hash", bad(elsewhere.to_vec())),
        (
            "a non-owner",
            json!({
                "signer": checksum_address(&fc_evm::address_of(&key(9))),
                "data": to_hex(&stranger),
            }),
        ),
        ("another owner's row", {
            let mut row = good.clone();
            row["signer"] = json!(checksum_address(&owners[1]));
            row
        }),
        ("no data", json!({ "signer": good["signer"] })),
        ("not hex", json!({ "signer": good["signer"], "data": "zz" })),
        ("no signer", json!({ "data": good["data"] })),
        ("not an object", json!("0x00")),
    ] {
        assert_eq!(with(vec![signature.clone()]), (0, 1), "{what}");
        assert_eq!(with(vec![signature, good.clone()]), (1, 1), "{what}");
    }
}

#[test]
fn no_display_is_left_out_as_json_leaves_out_undefined() {
    let (pending, setup, safe) = start();
    let read = read(&js(&pending), &safe, setup.owners()).unwrap();
    let entry = written(&New {
        safe: &safe,
        tx: &read.tx,
        hash: &read.hash,
        threshold: 1,
        display: None,
        signatures: &[],
        created_at_ms: 5,
    })
    .unwrap();
    let keys: Vec<String> = serde_json::from_str::<Value>(&entry.stringify())
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        keys,
        [
            "chainId",
            "safeAddress",
            "safeTxData",
            "safeTxHash",
            "typedData",
            "threshold",
            "signatures",
            "createdAt",
        ]
    );
    // And a `null` one is kept.
    let entry = written(&New {
        display: Some(&JsValue::Null),
        ..New {
            safe: &safe,
            tx: &read.tx,
            hash: &read.hash,
            threshold: 1,
            display: None,
            signatures: &[],
            created_at_ms: 5,
        }
    })
    .unwrap();
    assert_eq!(entry.get("display"), Some(&JsValue::Null));
}

/// The flow's entry as main's `safe_pending.set` sends it: `entry` changed
/// by `change`.
fn changed_by(entry: &Value, change: impl FnOnce(&mut Value)) -> Value {
    let mut entry = entry.clone();
    change(&mut entry);
    entry
}

fn mark_value(safe: &[u8; 20], hash: &[u8; 32]) -> Value {
    serde_json::from_str(&proposal(safe, hash).stringify()).unwrap()
}

/// An entry reads as proposed only with the mark the core writes for the
/// record's Safe and the SafeTx its fields recompute to; the reference's
/// entries carry none.
#[test]
fn only_the_cores_mark_for_this_safe_and_safe_tx_reads_as_proposed() {
    let (pending, setup, safe) = start();
    let owners = setup.owners();
    let read = read(&js(&pending), &safe, owners).unwrap();
    assert!(!read.proposed, "the reference's entry");
    let hash = read.hash;
    let mut marked = js(&pending);
    mark(&mut marked, &safe, &hash);
    let again = super::read(&marked, &safe, owners).unwrap();
    assert!(again.proposed);
    let text: Value = serde_json::from_str(&marked.stringify()).unwrap();
    assert_eq!(
        text[PROPOSAL],
        json!({
            "chainId": 100,
            "safeAddress": checksum_address(&safe),
            "safeTxHash": to_hex(&hash),
        })
    );
    let proposed = |mark: Value| {
        let mut entry = pending.clone();
        entry[PROPOSAL] = mark;
        super::read(&js(&entry), &safe, owners).unwrap().proposed
    };
    let exact = mark_value(&safe, &hash);
    assert!(proposed(exact.clone()));
    let with = |key: &str, value: Value| {
        let mut mark = exact.clone();
        mark[key] = value;
        mark
    };
    let elsewhere = setup.address(&U256::from_u64(99));
    for (what, mark) in [
        ("another Safe's", mark_value(&elsewhere, &hash)),
        ("another SafeTx's", mark_value(&safe, &[0x11; 32])),
        ("another chain", with("chainId", json!(1))),
        ("the chain as text", with("chainId", json!("100"))),
        ("lower case", with("safeAddress", json!(to_hex(&safe)))),
        ("an extra member", with("by", json!("core"))),
        ("no hash", {
            let mut mark = exact.clone();
            mark.as_object_mut().unwrap().shift_remove("safeTxHash");
            mark
        }),
        ("true", json!(true)),
        ("null", json!(null)),
    ] {
        assert!(!proposed(mark), "{what}");
    }
}

/// Main's set: a mark it sends is dropped; the index's own is kept, after
/// the others, only while the new entry is for the same Safe on Gnosis and
/// recomputes to the same SafeTx, whatever else changed; an entry that
/// isn't an object passes as it is.
#[test]
fn main_keeps_the_mark_only_for_the_same_safe_and_safe_tx() {
    let (pending, setup, safe) = start();
    let hash: [u8; 32] = parse_bytes(pending["safeTxHash"].as_str().unwrap(), "")
        .unwrap()
        .try_into()
        .unwrap();
    let exact = mark_value(&safe, &hash);
    let mut current = js(&pending);
    mark(&mut current, &safe, &hash);
    let set = |entry: &Value, current: Option<&JsValue>| -> Value {
        serde_json::from_str(&from_main(js(entry), current).stringify()).unwrap()
    };
    // A mark main sends is dropped, with or without an entry there.
    let sent = changed_by(&pending, |entry| entry[PROPOSAL] = exact.clone());
    assert_eq!(set(&sent, None), pending);
    assert_eq!(set(&sent, Some(&js(&pending))), pending, "an unmarked one");
    let mut bogus = js(&pending);
    bogus.set(PROPOSAL, JsValue::Bool(true));
    assert_eq!(set(&sent, Some(&bogus)), pending, "a bogus one");
    // The same Safe and SafeTx: kept, after the others, whatever main sent.
    let other = checksum_address(&[0x77; 20]);
    for (what, entry) in [
        ("as it is", pending.clone()),
        ("its mark sent back", sent.clone()),
        (
            "another mark sent",
            changed_by(&pending, |entry| entry[PROPOSAL] = json!(true)),
        ),
        (
            "a signature more",
            changed_by(&pending, |entry| {
                entry["signatures"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({ "signer": other, "data": "0x00" }))
            }),
        ),
        (
            "another display",
            changed_by(&pending, |entry| entry["display"] = json!("x")),
        ),
        (
            "superseded",
            changed_by(&pending, |entry| entry["superseded"] = json!(true)),
        ),
        (
            "the hash in upper case",
            changed_by(&pending, |entry| {
                let upper = to_hex(&hash).to_uppercase().replace("0X", "0x");
                entry["safeTxHash"] = json!(upper);
            }),
        ),
        (
            "the address in lower case",
            changed_by(&pending, |entry| {
                entry["safeAddress"] = json!(to_hex(&safe))
            }),
        ),
    ] {
        let written = set(&entry, Some(&current));
        assert_eq!(written[PROPOSAL], exact, "{what}");
        assert_eq!(
            written.as_object().unwrap().keys().next_back().unwrap(),
            PROPOSAL
        );
        let mut without = written.clone();
        without.as_object_mut().unwrap().shift_remove(PROPOSAL);
        let mut sent = entry.clone();
        sent.as_object_mut().unwrap().shift_remove(PROPOSAL);
        assert_eq!(without, sent, "{what}: the rest as sent");
    }
    // Another Safe, chain or SafeTx: dropped, the mark sent back or not.
    let elsewhere = checksum_address(&setup.address(&U256::from_u64(99)));
    let changes: [(&str, &str, Value); 6] = [
        ("another Safe", "safeAddress", json!(elsewhere)),
        ("another chain", "chainId", json!(1)),
        ("no chain", "chainId", Value::Null),
        ("another value", "value", json!("1")),
        (
            "another hash named",
            "safeTxHash",
            json!(to_hex(&[0x11; 32])),
        ),
        ("no fields", "safeTxData", Value::Null),
    ];
    for (what, key, value) in changes {
        let change = |entry: &mut Value| match key {
            "value" => entry["safeTxData"]["value"] = value.clone(),
            "chainId" if value.is_null() => {
                entry.as_object_mut().unwrap().shift_remove("chainId");
            }
            key => entry[key] = value.clone(),
        };
        for sent_back in [false, true] {
            let entry = changed_by(&pending, |entry| {
                change(entry);
                if sent_back {
                    entry[PROPOSAL] = exact.clone();
                }
            });
            let written = set(&entry, Some(&current));
            assert!(written.get(PROPOSAL).is_none(), "{what}, {sent_back}");
        }
    }
    // The fields of another SafeTx with their own hash: still another.
    let mut fields = pending["safeTxData"].clone();
    fields["value"] = json!("1");
    let tx = SafeTx::from_fields(&fields).unwrap();
    let rehashed = changed_by(&pending, |entry| {
        entry["safeTxData"] = fields.clone();
        entry["safeTxHash"] = json!(to_hex(&tx.hash(&safe).unwrap()));
    });
    assert!(set(&rehashed, Some(&current)).get(PROPOSAL).is_none());
    // An entry that isn't an object, falsy or not, passes as it is.
    for entry in [json!(null), json!(0), json!("a"), json!([1])] {
        assert_eq!(set(&entry, Some(&current)), entry);
    }
}
