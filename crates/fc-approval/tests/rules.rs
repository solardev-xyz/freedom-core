//! Replays vectors/approvals.json's `rules`, which the pinned reference's
//! auto-write-limiter.js and fee-check.js produced (design 0012, APR-2):
//! R-6's runs, which Q9's rate reuses, and the fee check's evidence,
//! references and verdicts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_approval::fee::{
    Basis, EVIDENCE_MAX_AGE_MS, Evidence, FEE_CHECK_MULTIPLE, Fees, MIN_PRIORITY_FEE_WEI,
    Reference, Wei, judge_fees, reference_fee,
};
use fc_approval::rate::{LIMITS, RateLimiter, RequestClass};
use fc_evm::U256;
use serde_json::{Value, json};

fn rules() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/approvals.json");
    let all: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    all["rules"].clone()
}

#[test]
fn limiter_runs() {
    let limiter = &rules()["limiter"];
    assert_eq!(
        limiter["limits"],
        json!({ "burst": LIMITS.burst, "refillMs": LIMITS.refill_ms, "dailyMax": LIMITS.daily_max, "dayMs": LIMITS.day_ms })
    );
    let runs = limiter["runs"].as_array().unwrap();
    assert!(runs.len() >= 6);
    for run in runs {
        let id = run["id"].as_str().unwrap();
        let mut r6: RateLimiter<String> = RateLimiter::default();
        // Q9's buckets go as R-6's: the transaction bucket of each key,
        // with the signature bucket of the same key untouched.
        let mut q9: RateLimiter<(String, RequestClass)> = RateLimiter::default();
        for (index, step) in run["steps"].as_array().unwrap().iter().enumerate() {
            let key = step["key"].as_str().unwrap().to_owned();
            let at = step["at"].as_u64().unwrap();
            let expected = step["result"].as_bool().unwrap();
            let label = format!("{id} step {index}");
            match step["op"].as_str().unwrap() {
                "admit" => {
                    assert_eq!(r6.would_admit(&key, at), expected, "{label}: advice");
                    assert_eq!(r6.admit(&key, at), expected, "{label}");
                    assert_eq!(
                        q9.admit(&(key.clone(), RequestClass::Transaction), at),
                        expected,
                        "{label}: q9"
                    );
                    assert!(
                        q9.would_admit(&(key, RequestClass::Signature), at),
                        "{label}: classes apart"
                    );
                }
                "forget" => {
                    assert_eq!(r6.forget(&key), expected, "{label}");
                    q9.forget_where(|(site, _)| *site == key);
                }
                other => panic!("{label}: {other}"),
            }
        }
    }
}

fn wei(text: &str) -> Wei {
    Wei::from_digits(text).unwrap()
}

fn decimal_or_null(value: Option<&Wei>) -> Value {
    value.map_or(Value::Null, |value| json!(value.to_decimal()))
}

fn evidence_json(evidence: &Evidence) -> Value {
    json!({
        "requestedAt": evidence.requested_at_ms,
        "header": evidence.header.as_ref().map(|header| json!({
            "number": header.number.to_decimal(),
            "timestamp": header.timestamp.to_decimal(),
            "baseFee": decimal_or_null(header.base_fee.as_ref()),
        })),
        "lowestPriority": decimal_or_null(evidence.lowest_priority.as_ref()),
        "quote": evidence.quote.as_ref().map(|quote| json!({
            "type": quote.kind.name(),
            "perGas": quote.per_gas.to_decimal(),
            "answered": quote.answered,
        })),
    })
}

fn reference_json(reference: Option<&Reference>) -> Value {
    reference.map_or(Value::Null, |reference| {
        json!({ "fee": reference.fee.to_decimal(), "basis": reference.basis.name(), "oneEndpoint": reference.one_endpoint })
    })
}

#[test]
fn fee_constants() {
    assert_eq!(FEE_CHECK_MULTIPLE, 3);
    assert_eq!(MIN_PRIORITY_FEE_WEI, 50_000_000);
    assert_eq!(EVIDENCE_MAX_AGE_MS, 60_000);
}

#[test]
fn fee_evidence_and_references() {
    let cases = rules()["fees"]["evidence"].as_array().unwrap().clone();
    assert!(cases.len() >= 30);
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        let evidence = Evidence::read(&case["reply"], case["requestedAt"].as_u64().unwrap());
        assert_eq!(evidence_json(&evidence), case["evidence"], "{id}: evidence");
        let reference = reference_fee(
            Some(&evidence),
            case["wallNow"].as_u64().unwrap(),
            case["monotonicNow"].as_u64().unwrap(),
        );
        assert_eq!(
            reference_json(reference.as_ref()),
            case["reference"],
            "{id}: reference"
        );
    }
    // No evidence kept for the chain: no reference.
    assert_eq!(reference_fee(None, 1, 1), None);
}

fn quantity(tx: &Value, field: &str) -> Option<U256> {
    tx.get(field)
        .map(|value| U256::parse_decimal(value.as_str().unwrap()).unwrap())
}

#[test]
fn fee_verdicts() {
    let cases = rules()["fees"]["judged"].as_array().unwrap().clone();
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        let tx = &case["tx"];
        let fees = Fees {
            max_fee_per_gas: quantity(tx, "maxFeePerGas"),
            max_priority_fee_per_gas: quantity(tx, "maxPriorityFeePerGas"),
            gas_price: quantity(tx, "gasPrice"),
            gas_limit: quantity(tx, "gasLimit"),
        };
        let reference = case["reference"].as_object().map(|reference| Reference {
            fee: wei(reference["fee"].as_str().unwrap()),
            basis: match reference["basis"].as_str().unwrap() {
                "header" => Basis::Header,
                _ => Basis::Quote,
            },
            one_endpoint: reference["oneEndpoint"].as_bool().unwrap(),
        });
        let verdict = judge_fees(&fees, reference.as_ref());
        let actual = json!({
            "maxCost": verdict.max_cost,
            "comparable": verdict.comparable,
            "ratio": verdict.ratio,
            "above": verdict.above,
            "oneEndpoint": verdict.one_endpoint,
            "basis": verdict.basis.map(Basis::name),
            "autoApprove": verdict.auto_approve,
        });
        assert_eq!(actual, case["verdict"], "{id}");
    }
    // The cases the design names: at 3·R, above it, with no reference, and
    // with one endpoint's.
    let auto = |id: &str| {
        cases.iter().find(|c| c["id"] == json!(id)).unwrap()["verdict"]["autoApprove"].clone()
    };
    assert_eq!(auto("at-3r"), json!(true));
    assert_eq!(auto("above-3r"), json!(false));
    assert_eq!(auto("no-reference"), json!(false));
    assert_eq!(auto("one-endpoint"), json!(false));
}

#[test]
fn decimals_as_the_reference_reads_them() {
    for (text, read) in [
        ("0", true),
        ("10", true),
        ("010", false),
        ("", false),
        ("1.5", false),
        ("0x10", false),
        (" 1", false),
        ("+1", false),
    ] {
        assert_eq!(Wei::parse_decimal(text).is_some(), read, "{text:?}");
    }
    assert!(Wei::parse_decimal(&"9".repeat(78)).is_some());
    assert!(Wei::parse_decimal(&format!("1{}", "0".repeat(78))).is_none());
}
