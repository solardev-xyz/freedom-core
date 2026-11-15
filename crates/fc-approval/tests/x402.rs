//! Replays vectors/approvals.json's `x402` (design 0012, X402-1), which the
//! approvals reference's x402 code produced over the pinned @x402 SDK: the
//! client's default assets, the cap key of a paid URL, `tupleFromAccept`,
//! `findCoveringPermission` with its charge, and each payment payload, byte
//! for byte, under the vector's clock, nonce and test key; and for a device
//! account (core #392), the typed data its signer is handed, the device's
//! signature checked, and the payload around it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_approval::phone::check_signature;
use fc_approval::stores::CapStore;
use fc_approval::x402::{self, DEFAULT_ASSETS, Payment, Requirements};
use serde_json::Value;

fn x402() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/approvals.json");
    let all: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    all["x402"].clone()
}

fn hex(text: &str) -> Vec<u8> {
    let digits = text.strip_prefix("0x").unwrap();
    (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).unwrap())
        .collect()
}

#[test]
fn default_assets_are_the_sdk_s() {
    let vectors = x402();
    let listed: Vec<(u64, String, u64)> = vectors["defaultAssets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["chainId"].as_u64().unwrap(),
                a["asset"].as_str().unwrap().to_owned(),
                a["decimals"].as_u64().unwrap(),
            )
        })
        .collect();
    let ours: Vec<(u64, String, u64)> = DEFAULT_ASSETS
        .iter()
        .map(|a| (a.chain_id, a.asset.to_owned(), u64::from(a.decimals)))
        .collect();
    assert_eq!(ours, listed);
}

#[test]
fn keys_are_the_paid_url_s_origin() {
    for case in x402()["keys"].as_array().unwrap() {
        let url = case["url"].as_str().unwrap();
        assert_eq!(
            x402::cap_key(url).as_deref(),
            case["core"].as_str(),
            "{url}"
        );
        // Where the core keys a URL, it keys it as the reference does.
        if !case["core"].is_null() {
            assert_eq!(case["core"], case["js"], "{url}");
        }
    }
}

#[test]
fn tuples_as_the_reference_takes_them() {
    for case in x402()["tuples"].as_array().unwrap() {
        let ours = x402::tuple(&case["accept"]);
        let js = &case["js"];
        match ours {
            None => assert!(js.is_null(), "{case}"),
            Some(tuple) => {
                assert_eq!(Some(tuple.chain_id), js["chainId"].as_f64(), "{case}");
                assert_eq!(Some(tuple.asset.as_str()), js["asset"].as_str(), "{case}");
                assert_eq!(Some(tuple.amount.as_str()), js["amount"].as_str(), "{case}");
            }
        }
    }
}

#[test]
fn covering_as_the_reference_charges() {
    let cases = x402()["covering"].as_array().unwrap().clone();
    let mut deviations = 0;
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        let now_s = case["at"].as_u64().unwrap() / 1000;
        let store = match case["start"].as_str() {
            Some(text) => CapStore::load(text.as_bytes(), now_s).unwrap(),
            None => CapStore::new(),
        };
        let accepts = case["accepts"].as_array().unwrap();
        let ours = store
            .covering(case["origin"].as_str().unwrap(), accepts, now_s)
            .map(|(index, _)| index as u64);
        assert_eq!(ours, case["core"].as_u64(), "{id}");
        // The core's answer is the reference's, but where 0012 says.
        if case.get("deviation").is_some() {
            deviations += 1;
        } else {
            let reference = case["charged"]
                .as_bool()
                .unwrap()
                .then(|| case["js"].as_u64())
                .flatten();
            assert_eq!(ours, reference, "{id}");
        }
    }
    assert_eq!(deviations, 1);
}

/// The payload the core builds for a vector, signed with its test key, or
/// why it refuses.
fn build(case: &Value) -> Result<String, x402::Unpayable> {
    let requirements = Requirements::parse(&case["requirements"])?;
    let payment = Payment::new(
        requirements,
        case["accept_index"].as_u64().unwrap() as usize,
    )?;
    let from: [u8; 20] = hex(case["signer"]["address"].as_str().unwrap())
        .try_into()
        .unwrap();
    let nonce: [u8; 32] = hex(case["nonce"].as_str().unwrap()).try_into().unwrap();
    let built = payment.build(&from, case["now"].as_u64().unwrap(), &nonce)?;
    let key =
        k256::ecdsa::SigningKey::from_slice(&hex(case["signer"]["privateKey"].as_str().unwrap()))
            .unwrap();
    let signature = fc_evm::sign_digest(&key, &built.digest).unwrap();
    Ok(built.payload(&signature))
}

#[test]
fn payloads_byte_for_byte() {
    let mut kinds = [0; 3];
    for case in x402()["payloads"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let ours = build(case);
        match case["core"].as_str().unwrap() {
            "payload" => {
                let payload = ours.unwrap_or_else(|e| panic!("{id}: {e}"));
                assert_eq!(payload, case["js"]["payload"].as_str().unwrap(), "{id}");
                let index = if payload.contains("\"permit2Authorization\"") {
                    1
                } else if payload.starts_with("{\"x402Version\":1") {
                    2
                } else {
                    0
                };
                kinds[index] += 1;
            }
            "refused" => {
                assert!(ours.is_err(), "{id}: {ours:?}");
                // A refusal is the reference's, or a narrowing 0012 notes.
                assert!(
                    case["js"].get("error").is_some() || case["inferred"] == true,
                    "{id}"
                );
            }
            other => panic!("{id}: core {other}"),
        }
    }
    // EIP-3009 V2, Permit2 and EIP-3009 V1 each signed.
    assert!(kinds.iter().all(|n| *n >= 2), "{kinds:?}");
}

/// The device payloads (core #392): the typed data the client hands a
/// device's signer, and its hash, byte for byte; the device's signature
/// checked as PHN-1 checks a phone's; and the payload around the text the
/// device returned, byte for byte, or the reason the core refuses it.
#[test]
fn device_payloads_byte_for_byte() {
    let cases = x402()["devices"].as_array().unwrap().clone();
    let (mut paid, mut refused, mut inferred) = (0, [0; 2], 0);
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        let requirements = Requirements::parse(&case["requirements"]).unwrap();
        let payment = Payment::new(
            requirements,
            case["accept_index"].as_u64().unwrap() as usize,
        )
        .unwrap();
        let from: [u8; 20] = hex(case["address"].as_str().unwrap()).try_into().unwrap();
        let nonce: [u8; 32] = hex(case["nonce"].as_str().unwrap()).try_into().unwrap();
        let built = payment
            .build(&from, case["now"].as_u64().unwrap(), &nonce)
            .unwrap();
        assert_eq!(
            built.typed_data(),
            case["typedData"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            fc_evm::to_hex(&built.digest),
            case["hash"].as_str().unwrap(),
            "{id}"
        );
        let checked = check_signature(&case["signature"], &built.digest, &from);
        if case["core"] == "payload" {
            let text = checked.unwrap_or_else(|e| panic!("{id}: {e:?}"));
            assert_eq!(text, case["signature"].as_str().unwrap(), "{id}");
            assert_eq!(
                built.payload_with(text),
                case["js"]["payload"].as_str().unwrap(),
                "{id}"
            );
            assert_eq!(case["recovers"], case["address"], "{id}");
            paid += 1;
        } else {
            let reason = case["core"]["refused"].as_str().unwrap();
            assert_eq!(checked.map_err(|e| e.reason()), Err(reason), "{id}");
            refused[usize::from(reason == "bad_response")] += 1;
            // A signature ethers recovers to the account is refused only
            // where 0012 notes it.
            if case["recovers"] == case["address"] {
                assert_eq!(case["inferred"], true, "{id}");
                inferred += 1;
            }
        }
    }
    assert!(
        paid >= 20 && refused.iter().all(|n| *n >= 1) && inferred == 1,
        "{paid} {refused:?} {inferred}"
    );
}
