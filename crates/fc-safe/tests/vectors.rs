//! Replays vectors/safe.json, which the pinned browser's own Safe modules
//! produced over protocol-kit 8.0.11 and safe-deployments 1.37.66
//! (vectors/generator/safe.js): every case byte for byte, the deviations
//! as design 0016 has them. fc-safe does no I/O, so every address is the
//! core's with no chain read.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use fc_evm::{U256, checksum_address, keccak256, parse_address, parse_bytes, to_hex};
use fc_naming::abi::{self, Kind, Value as AbiValue};
use fc_safe::constants::{
    CHAIN_ID, FALLBACK_HANDLER, PROXY_CREATION_CODE, PROXY_CREATION_CODE_HASH, PROXY_FACTORY,
    SAFE_VERSION, SINGLETON,
};
use fc_safe::{
    Error, NonceState, OwnerSignature, SafeMessage, SafeTx, Setup, Signatures, check_chain,
    exec_transaction, parse_salt,
};
use serde_json::{Value, json};

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/safe.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn text(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("not text: {value}"))
}

fn addr_of(value: &Value) -> [u8; 20] {
    parse_address(text(value)).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    parse_bytes(text(value), "bytes").unwrap()
}

fn hash(value: &Value) -> [u8; 32] {
    bytes(value).try_into().unwrap()
}

/// JSON text with the vector's property order, as safe-pending.json keeps it.
fn same_json(core: &Value, reference: &Value, what: &str) {
    assert_eq!(
        serde_json::to_string(core).unwrap(),
        serde_json::to_string(reference).unwrap(),
        "{what}"
    );
}

/// The owners' addresses by the vectors' names (A to E).
fn owners(v: &Value) -> BTreeMap<String, [u8; 20]> {
    v["owners"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(id, owner)| (id.clone(), addr_of(&owner["address"])))
        .collect()
}

fn setup_of(names: &BTreeMap<String, [u8; 20]>, case: &Value) -> Result<Setup, Error> {
    let list = case["owners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| names[text(id)])
        .collect();
    Setup::new(list, case["threshold"].as_u64().unwrap() as usize)
}

fn u256(value: &Value) -> U256 {
    match value {
        Value::String(digits) => U256::parse_decimal(digits).unwrap(),
        Value::Number(n) => U256::from_u64(n.as_u64().unwrap()),
        _ => panic!("not a quantity: {value}"),
    }
}

/// The SafeTx a case's `tx` and the Safe's nonce make, as the reference's
/// `buildSafeTransaction` builds it: a missing value is 0, missing data
/// none.
fn safe_tx(tx: &Value, nonce: u64) -> SafeTx {
    let value = tx.get("value").map(u256).unwrap_or(U256::ZERO);
    let data = tx.get("data").map(bytes).unwrap_or_default();
    SafeTx::new(addr_of(&tx["to"]), value, data, nonce).unwrap()
}

fn refused(case: &Value) -> Option<&str> {
    case.get("core")
        .and_then(|core| core.get("refused"))
        .and_then(Value::as_str)
}

#[test]
fn the_constants_are_safe_deployments_and_the_recorded_code() {
    let v = vectors();
    let c = &v["constants"];
    assert_eq!(text(&c["version"]), SAFE_VERSION);
    assert_eq!(c["chainId"], json!(CHAIN_ID));
    assert_eq!(text(&c["singleton"]), checksum_address(&SINGLETON));
    assert_eq!(text(&c["factory"]), checksum_address(&PROXY_FACTORY));
    assert_eq!(
        text(&c["fallbackHandler"]),
        checksum_address(&FALLBACK_HANDLER)
    );
    assert_eq!(bytes(&c["proxyCreationCode"]), PROXY_CREATION_CODE);
    assert_eq!(hash(&c["proxyCreationCodeHash"]), PROXY_CREATION_CODE_HASH);
    assert_eq!(keccak256(&PROXY_CREATION_CODE), PROXY_CREATION_CODE_HASH);
    assert_eq!(PROXY_CREATION_CODE.len(), 486);
    // As safe-deployments 1.37.66 lists them.
    let listed = &c["safeDeployments"]["listed"];
    for (name, pinned, contract) in [
        ("singleton", SINGLETON, "SafeL2"),
        ("factory", PROXY_FACTORY, "SafeProxyFactory"),
        (
            "fallbackHandler",
            FALLBACK_HANDLER,
            "CompatibilityFallbackHandler",
        ),
    ] {
        assert_eq!(addr_of(&listed[name]["address"]), pinned, "{name}");
        assert_eq!(text(&listed[name]["contractName"]), contract);
    }
    // The factory's recorded runtime code is the one safe-deployments
    // lists, and it embeds the proxy code once.
    let runtime = bytes(&c["factoryRuntimeCode"]);
    assert_eq!(keccak256(&runtime), hash(&listed["factory"]["codeHash"]));
    let embedded = runtime
        .windows(PROXY_CREATION_CODE.len())
        .filter(|window| *window == PROXY_CREATION_CODE)
        .count();
    assert_eq!(embedded, 1);
    // And the factory's recorded proxyCreationCode() answer is the code.
    let answer = abi::decode(&[Kind::Bytes], &bytes(&c["proxyCreationCodeAnswer"])).unwrap();
    assert_eq!(
        answer,
        vec![Ok(AbiValue::Bytes(PROXY_CREATION_CODE.to_vec()))]
    );
}

/// A case's address and deployment as the core computes them, with no chain
/// read, or its refusal.
fn address_case(names: &BTreeMap<String, [u8; 20]>, case: &Value) -> Result<(), Error> {
    check_chain(&u256(&case["chainId"]))?;
    let setup = setup_of(names, case)?;
    let salt = parse_salt(text(&case["saltNonce"]))?;
    let address = setup.address(&salt);
    assert_eq!(
        checksum_address(&address),
        text(&case["address"]),
        "{}",
        case["id"]
    );
    let deployment = setup.deployment(&salt);
    assert_eq!(deployment.safe, address);
    let expected = &case["deployment"];
    assert_eq!(checksum_address(&deployment.to), text(&expected["to"]));
    assert_eq!(text(&expected["value"]), "0");
    assert_eq!(
        to_hex(&deployment.data),
        text(&expected["data"]),
        "{}",
        case["id"]
    );
    setup.check_address(&salt, &address)?;
    Ok(())
}

#[test]
fn every_address_and_deployment() {
    let v = vectors();
    let names = owners(&v);
    let cases = v["addresses"].as_array().unwrap();
    assert!(cases.len() >= 30);
    for case in cases {
        let result = address_case(&names, case).map_err(|e| e.kind());
        match refused(case) {
            Some(kind) => {
                assert!(
                    case.get("error").is_some(),
                    "the reference refuses {}",
                    case["id"]
                );
                assert_eq!(result, Err(kind), "{}", case["id"]);
            }
            None => assert_eq!(result, Ok(()), "{}", case["id"]),
        }
    }
}

#[test]
fn every_created_safe() {
    let v = vectors();
    let names = owners(&v);
    for case in v["created"].as_array().unwrap() {
        // generateSaltNonce: 16 random bytes, read big-endian, in decimal.
        let drawn = U256::from_be_slice(&bytes(&json!(format!("0x{}", text(&case["drawnBytes"])))))
            .unwrap();
        assert_eq!(drawn.to_decimal(), text(&case["saltNonce"]));
        assert_eq!(case["record"]["saltNonce"], case["saltNonce"]);
        let entry = json!({
            "chainId": CHAIN_ID,
            "owners": case["owners"],
            "threshold": case["threshold"],
            "saltNonce": case["saltNonce"],
            "address": case["address"],
            "deployment": case["deployment"],
        });
        address_case(&names, &entry).unwrap();
    }
}

fn safes(v: &Value) -> BTreeMap<String, (Setup, U256, [u8; 20])> {
    let names = owners(v);
    v["safes"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, safe)| {
            let setup = setup_of(&names, safe).unwrap();
            let salt = parse_salt(text(&safe["saltNonce"])).unwrap();
            let address = setup.address(&salt);
            assert_eq!(checksum_address(&address), text(&safe["address"]));
            (name.clone(), (setup, salt, address))
        })
        .collect()
}

fn safe_of<'a>(
    safes: &'a BTreeMap<String, (Setup, U256, [u8; 20])>,
    case: &Value,
) -> &'a (Setup, U256, [u8; 20]) {
    &safes[text(&case["safe"]["name"])]
}

/// The six fields only Freedom's value is allowed in, each with another.
const OTHER_FIELDS: [(&str, &str); 6] = [
    ("operation", "1"),
    ("safeTxGas", "1"),
    ("baseGas", "1"),
    ("gasPrice", "1"),
    ("gasToken", "0x0000000000000000000000000000000000000001"),
    (
        "refundReceiver",
        "0x0000000000000000000000000000000000000001",
    ),
];

#[test]
fn every_safe_tx_its_typed_data_and_hash() {
    let v = vectors();
    let safes = safes(&v);
    for case in v["safeTxs"].as_array().unwrap() {
        let id = &case["id"];
        let (setup, salt, address) = safe_of(&safes, case);
        let chain_nonce = match &case["chainNonce"] {
            Value::Null => U256::ZERO,
            nonce => u256(nonce),
        };
        let result = (|| {
            check_chain(&u256(&case["chainId"]))?;
            if let Some(record) = case.get("recordAddress") {
                setup.check_address(salt, &addr_of(record))?;
            }
            SafeTx::nonce_from(&chain_nonce)
        })();
        if let Some(kind) = refused(case) {
            assert!(case.get("error").is_some(), "the reference refuses {id}");
            assert_eq!(result.map_err(|e| e.kind()), Err(kind), "{id}");
            continue;
        }
        let tx = safe_tx(&case["tx"], result.unwrap());
        assert_eq!(
            checksum_address(address),
            text(&case["safeAddress"]),
            "{id}"
        );
        same_json(
            &tx.fields(),
            &case["safeTxData"],
            &format!("{id}: safeTxData"),
        );
        same_json(
            &tx.typed_data(address),
            &case["typedData"],
            &format!("{id}: typedData"),
        );
        assert_eq!(tx.hash(address).unwrap(), hash(&case["safeTxHash"]), "{id}");
        // Read back from the fields the reference keeps, and refused with
        // any operation, gas field, gas token or refund receiver but
        // Freedom's.
        assert_eq!(
            SafeTx::from_fields(&case["safeTxData"]).as_ref(),
            Ok(&tx),
            "{id}"
        );
        for (field, other) in OTHER_FIELDS {
            let mut fields = case["safeTxData"].clone();
            fields[field] = if field == "operation" {
                json!(1)
            } else {
                json!(other)
            };
            assert_eq!(
                SafeTx::from_fields(&fields),
                Err(Error::Field(field)),
                "{id}: {field}"
            );
        }
    }
}

/// The signatures a case lists, each checked as an owner's and kept.
fn kept(list: &Value, hash: &[u8; 32], owners: &[[u8; 20]]) -> Signatures {
    let mut signatures = Signatures::new();
    for signature in list.as_array().unwrap() {
        let checked = OwnerSignature::check(
            hash,
            &bytes(&signature["data"]),
            &addr_of(&signature["signer"]),
            owners,
        )
        .unwrap();
        signatures.add(checked);
    }
    signatures
}

#[test]
fn every_exec_transaction_call() {
    let v = vectors();
    let safes = safes(&v);
    let cases = v["executions"].as_array().unwrap();
    for case in cases {
        let id = &case["id"];
        let (setup, _, address) = safe_of(&safes, case);
        let tx = SafeTx::from_fields(&case["safeTxData"]).unwrap();
        let safe_tx_hash = tx.hash(address).unwrap();
        assert_eq!(safe_tx_hash, hash(&case["safeTxHash"]), "{id}");
        // In whatever order they come, once each, joined in owner order.
        let signatures = kept(&case["signatures"], &safe_tx_hash, setup.owners());
        let send = &case["send"];
        assert_eq!(addr_of(&send["to"]), *address, "{id}");
        assert_eq!(text(&send["value"]), "0");
        assert_eq!(send["chainId"], json!(CHAIN_ID));
        assert_eq!(
            to_hex(&exec_transaction(&tx, &signatures.joined())),
            text(&send["data"]),
            "{id}"
        );
    }
    // Each order of the three owners came out the same.
    let of_three = |id: &str| {
        id.strip_prefix("S3-").is_some_and(|order| {
            let mut order: Vec<char> = order.chars().collect();
            order.sort();
            order == ['A', 'B', 'C']
        })
    };
    let calls: Vec<&str> = cases
        .iter()
        .filter(|c| of_three(text(&c["id"])))
        .map(|c| text(&c["send"]["data"]))
        .collect();
    assert_eq!(calls.len(), 6);
    assert!(calls.iter().all(|call| *call == calls[0]));
}

#[test]
fn every_owner_signature() {
    let v = vectors();
    let safes = safes(&v);
    let names = owners(&v);
    let mut deviations = 0;
    for case in v["ownerSignatures"].as_array().unwrap() {
        let id = &case["id"];
        let (setup, _, address) = safe_of(&safes, case);
        assert_eq!(checksum_address(address), text(&case["safeAddress"]));
        let safe_tx_hash = hash(&case["safeTxHash"]);
        let owner = names[text(&case["owner"])];
        let answered = match &case["answered"] {
            Value::Null => Vec::new(),
            signature => bytes(signature),
        };
        let checked = OwnerSignature::check(&safe_tx_hash, &answered, &owner, setup.owners());
        match refused(case) {
            Some(kind) => {
                assert_eq!(checked.map(|_| ()).map_err(|e| e.kind()), Err(kind), "{id}");
                if case.get("deviation").is_some() {
                    // The reference kept it, as ethers recovers it.
                    assert_eq!(case["deviation"], json!("owner-signatures"));
                    assert_eq!(case["reference"]["kept"].as_array().unwrap().len(), 1);
                    deviations += 1;
                } else {
                    assert!(case["reference"].get("error").is_some(), "{id}");
                }
            }
            None => {
                let checked = checked.unwrap();
                let kept = &case["core"]["kept"];
                assert_eq!(kept, &case["reference"]["kept"], "{id}");
                assert_eq!(kept.as_array().unwrap().len(), 1);
                assert_eq!(addr_of(&kept[0]["signer"]), owner);
                assert_eq!(bytes(&kept[0]["data"]), checked.signature());
                // A second from one owner is dropped.
                let mut signatures = Signatures::new();
                assert!(signatures.add(checked));
                assert!(!signatures.add(checked));
                assert_eq!(signatures.len(), 1);
            }
        }
    }
    assert!(deviations >= 4);
}

#[test]
fn every_safe_tx_course() {
    let v = vectors();
    let safes = safes(&v);
    let names = owners(&v);
    for flow in v["flows"].as_array().unwrap() {
        let id = &flow["id"];
        let (setup, _, address) = safe_of(&safes, flow);
        let threshold = setup.threshold();
        let mut chain_nonce = u256(&flow["chainNonce"]);
        let mut tx = None;
        let mut signatures = Signatures::new();
        for step in flow["steps"].as_array().unwrap() {
            let what = text(&step["step"]);
            if what == "chainNonce" {
                chain_nonce = u256(&step["nonce"]);
                continue;
            }
            match (what, step.get("error")) {
                ("start", Some(_)) => {
                    let refusal = check_chain(&u256(&flow["chainId"])).map_err(|e| e.kind());
                    assert_eq!(refusal, Err(refused(flow).unwrap()), "{id}");
                }
                ("start", None) => {
                    check_chain(&u256(&flow["chainId"])).unwrap();
                    let built = safe_tx(&flow["tx"], SafeTx::nonce_from(&chain_nonce).unwrap());
                    let pending = &step["pending"];
                    let safe_tx_hash = built.hash(address).unwrap();
                    assert_eq!(safe_tx_hash, hash(&step["state"]["safeTxHash"]), "{id}");
                    assert_eq!(safe_tx_hash, hash(&pending["safeTxHash"]), "{id}");
                    assert_eq!(addr_of(&pending["safeAddress"]), *address);
                    same_json(
                        &built.fields(),
                        &pending["safeTxData"],
                        &format!("{id}: fields"),
                    );
                    same_json(
                        &built.typed_data(address),
                        &pending["typedData"],
                        &format!("{id}: typed data"),
                    );
                    signatures = kept(&pending["signatures"], &safe_tx_hash, setup.owners());
                    tx = Some(built);
                }
                ("sign", Some(_)) => {
                    let owner = names[text(&step["owner"])];
                    let checked = OwnerSignature::check(&[0; 32], &[], &owner, setup.owners());
                    assert_eq!(
                        checked.map(|_| ()).map_err(|e| e.kind()),
                        Err("not_owner"),
                        "{id}"
                    );
                }
                ("sign", None) => {
                    let tx = tx.as_ref().unwrap();
                    signatures = kept(
                        &step["pending"]["signatures"],
                        &tx.hash(address).unwrap(),
                        setup.owners(),
                    );
                    assert_eq!(step["state"]["collected"], json!(signatures.len()));
                }
                ("execute", Some(_)) => {
                    assert!(text(&step["error"]["message"]).starts_with("Not enough signatures"));
                    assert_eq!(
                        signatures.joined_at(threshold).map_err(|e| e.kind()),
                        Err("threshold")
                    );
                    assert_eq!(step["sent"], json!([]));
                }
                ("execute", None) => {
                    let tx = tx.as_ref().unwrap();
                    let sent = step["sent"].as_array().unwrap();
                    match tx.nonce_state(&chain_nonce) {
                        NonceState::Ready => {
                            assert_eq!(text(&step["state"]["status"]), "executed", "{id}");
                            assert_eq!(sent.len(), 1);
                            let call =
                                exec_transaction(tx, &signatures.joined_at(threshold).unwrap());
                            assert_eq!(to_hex(&call), text(&sent[0]["data"]), "{id}");
                            assert_eq!(addr_of(&sent[0]["to"]), *address);
                            assert_eq!(text(&sent[0]["value"]), "0");
                        }
                        NonceState::Superseded => {
                            assert_eq!(text(&step["state"]["status"]), "superseded", "{id}");
                            assert!(sent.is_empty());
                        }
                        NonceState::Behind => {
                            // The reference executes it; the core refuses it.
                            assert_eq!(flow["deviation"], json!("nonce-behind"), "{id}");
                            assert_eq!(refused(flow), Some("nonce_behind"));
                            assert_eq!(text(&step["state"]["status"]), "executed");
                        }
                    }
                }
                _ => panic!("{id}: an unknown step {what}"),
            }
        }
    }
}

/// `normalizeMessage`'s bytes: `0x` and hex as the bytes, other text as its
/// UTF-8.
fn message_bytes(message: &str) -> Vec<u8> {
    match message.strip_prefix("0x") {
        Some(_) => parse_bytes(message, "message").unwrap(),
        None => message.as_bytes().to_vec(),
    }
}

/// The core's typed data from a page's request (`toCoreTypedData`):
/// parsed if it is text, its domain `{}` if absent, its types without
/// EIP712Domain.
fn request_digest(request: &Value) -> SafeMessage {
    let params = request["params"].as_array().unwrap();
    match text(&request["method"]) {
        "personal_sign" => SafeMessage::personal_sign(&message_bytes(text(&params[0]))),
        "eth_signTypedData_v4" => {
            let typed = match &params[1] {
                Value::String(json) => serde_json::from_str(json).unwrap(),
                typed => typed.clone(),
            };
            let mut types = typed["types"].clone();
            types.as_object_mut().unwrap().shift_remove("EIP712Domain");
            let domain = typed.get("domain").cloned().unwrap_or(json!({}));
            SafeMessage::typed_data_request(&domain, &types, &typed["message"]).unwrap()
        }
        method => panic!("no Safe message for {method}"),
    }
}

#[test]
fn every_safe_message_and_its_joined_signatures() {
    let v = vectors();
    let safes = safes(&v);
    for case in v["messages"].as_array().unwrap() {
        let id = &case["id"];
        let (setup, _, address) = safe_of(&safes, case);
        let message = request_digest(&case["request"]);
        assert_eq!(to_hex(message.digest()), text(&case["digest"]), "{id}");
        same_json(
            &message.typed_data(address),
            &case["typedData"],
            &format!("{id}: typed data"),
        );
        let message_hash = message.hash(address).unwrap();
        assert_eq!(message_hash, hash(&case["hash"]), "{id}");
        let signatures = kept(&case["signatures"], &message_hash, setup.owners());
        match refused(case) {
            Some(kind) => {
                assert!(case.get("error").is_some());
                assert_eq!(
                    signatures
                        .joined_at(setup.threshold())
                        .map_err(|e| e.kind()),
                    Err(kind)
                );
            }
            None => assert_eq!(
                to_hex(&signatures.joined_at(setup.threshold()).unwrap()),
                text(&case["signature"]),
                "{id}"
            ),
        }
    }
}

/// Every deviation a case is marked with is one of design 0016's, and each
/// is reached.
#[test]
fn the_deviations_are_the_designs() {
    fn marks(value: &Value, out: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                if let Some(Value::String(id)) = map.get("deviation") {
                    out.insert(id.clone());
                }
                map.values().for_each(|v| marks(v, out));
            }
            Value::Array(items) => items.iter().for_each(|v| marks(v, out)),
            _ => {}
        }
    }
    let mut found = BTreeSet::new();
    marks(&vectors(), &mut found);
    let expected: BTreeSet<String> = ["nonce-behind", "owner-signatures"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(found, expected);
}
