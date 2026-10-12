//! Replays `vectors/naming.json`, produced by the pinned freedom-browser JS
//! (design 0003). A mismatch is a parity bug in the crate, never a reason
//! to edit the vectors.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_naming::abi::{self, FieldError, Kind, Value as AbiValue};
use fc_naming::ccip::{self, Method};
use fc_naming::jsjson::{self, JsValue};
use fc_naming::tezos::{self, Published};
use fc_naming::ur::{self, NameSystem, ReverseOutcome, Revert};
use fc_naming::{Error, coin_type, dns_encode, namehash, normalize_ens, parse_contenthash};
use serde_json::{Value, json};

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/naming.json");
    let text = std::fs::read_to_string(path).unwrap();
    let mut deserializer = serde_json::Deserializer::from_str(&text);
    deserializer.disable_recursion_limit();
    serde::Deserialize::deserialize(&mut deserializer).unwrap()
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    hex::decode(text.strip_prefix("0x")?).ok()
}

/// A vector's JSON value, read as the core reads JSON.
fn to_js(value: &Value) -> JsValue {
    jsjson::parse(&value.to_string()).unwrap()
}

/// The generator's `aliasedStrings`: one string aliased by every item.
fn aliased_strings(count: usize, length: usize) -> Vec<u8> {
    let word = |n: usize| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&(n as u64).to_be_bytes());
        w
    };
    let mut data = Vec::new();
    data.extend_from_slice(&word(32));
    data.extend_from_slice(&word(count));
    for _ in 0..count {
        data.extend_from_slice(&word(32 * count));
    }
    data.extend_from_slice(&word(length));
    data.extend(std::iter::repeat_n(b'z', length));
    data
}

#[test]
fn names() {
    let v = vectors();
    for case in v["names"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let js = &case["js"];
        let ours = normalize_ens(input);
        if case["deviation"] == "name-length" {
            assert_eq!(
                ours,
                Err(Error::NameTooLong(fc_naming::MAX_NAME_BYTES)),
                "{input:?}"
            );
            continue;
        }
        match js["stage"].as_str() {
            Some("empty") => assert_eq!(ours, Err(Error::EmptyName), "{input:?}"),
            Some("normalize") => {
                // The same normalizer and the same displayed message, as
                // fastNormalize throws it.
                let shown = ours.map_err(|e| e.to_string());
                assert_eq!(
                    shown,
                    Err(js["error"].as_str().unwrap().to_owned()),
                    "{input:?}"
                );
            }
            // The JS lets ethers' namehash refuse these; the core refuses
            // them up front (design 0003, Deviations).
            Some("namehash") => assert!(ours.is_err(), "{input:?} must fail"),
            Some(other) => panic!("unknown stage {other}"),
            None => {
                let normalized = ours.unwrap_or_else(|e| panic!("{input:?}: {e}"));
                assert_eq!(normalized, js["normalized"].as_str().unwrap(), "{input:?}");
                assert_eq!(
                    hex0x(&namehash(&normalized).unwrap()),
                    js["namehash"].as_str().unwrap(),
                    "{input:?}"
                );
                match js["dns_encoded"].as_str() {
                    Some(encoded) => assert_eq!(
                        hex0x(&dns_encode(&normalized, 255).unwrap()),
                        encoded,
                        "{input:?}"
                    ),
                    None => assert!(dns_encode(&normalized, 255).is_err(), "{input:?}"),
                }
                assert_eq!(
                    NameSystem::for_name(&normalized).id(),
                    js["system"].as_str().unwrap()
                );
            }
        }
    }
}

#[test]
fn coin_types() {
    let v = vectors();
    for case in v["coin_types"].as_array().unwrap() {
        let ours = case["chain_id"].as_u64().map(coin_type);
        match case.get("value") {
            Some(expected) => assert_eq!(
                ours.unwrap().unwrap().to_string(),
                expected.as_str().unwrap(),
                "{case}"
            ),
            None => assert!(ours.is_none_or(|r| r.is_err()), "{case}"),
        }
    }
}

#[test]
fn contenthash() {
    let v = vectors();
    for case in v["contenthash"].as_array().unwrap() {
        let input = unhex(case["input"].as_str().unwrap()).unwrap();
        let ours = parse_contenthash(&input).map(|c| {
            json!({ "codec": c.codec, "protocol": c.protocol, "uri": c.uri(), "decoded": c.decoded })
        });
        assert_eq!(ours.unwrap_or(Value::Null), case["js"], "{}", case["input"]);
    }
}

fn kind(name: &str) -> Kind {
    match name {
        "address" => Kind::Address,
        "uint256" => Kind::Uint256,
        "bytes4" => Kind::Bytes4,
        "bytes" => Kind::Bytes,
        "string" => Kind::String,
        "string[]" => Kind::StringArray,
        other => panic!("unknown type {other}"),
    }
}

fn decimal(word: &[u8; 32]) -> String {
    assert!(word[..16].iter().all(|&b| b == 0), "test values fit u128");
    let mut low = [0u8; 16];
    low.copy_from_slice(&word[16..]);
    u128::from_be_bytes(low).to_string()
}

/// Our field next to the JS one: values equal, or both errors.
fn same_field(ours: &Result<AbiValue, FieldError>, js: &Value) -> bool {
    match (ours, js.get("value")) {
        (Err(_), None) => true,
        (Ok(AbiValue::Address(a)), Some(Value::String(s))) => hex0x(a) == s.to_lowercase(),
        (Ok(AbiValue::Uint256(w)), Some(Value::String(s))) => &decimal(w) == s,
        (Ok(AbiValue::Bytes4(b)), Some(Value::String(s))) => &hex0x(b) == s,
        (Ok(AbiValue::Bytes(b)), Some(Value::String(s))) => &hex0x(b) == s,
        (Ok(AbiValue::String(t)), Some(Value::String(s))) => t == s,
        (Ok(AbiValue::StringArray(items)), Some(Value::Object(summary))) => {
            items.len() as u64 == summary["count"].as_u64().unwrap()
                && items
                    .first()
                    .and_then(|i| i.as_ref().ok())
                    .map(|s| s.len() as u64)
                    == summary["first_length"].as_u64()
        }
        (Ok(AbiValue::StringArray(items)), Some(Value::Array(js_items))) => {
            items.len() == js_items.len()
                && items
                    .iter()
                    .zip(js_items)
                    .all(|(item, js_item)| match item {
                        Ok(s) => js_item["value"].as_str() == Some(s.as_str()),
                        Err(_) => js_item.get("error").is_some(),
                    })
        }
        _ => false,
    }
}

#[test]
fn abi_rules() {
    let v = vectors();
    for case in v["abi"].as_array().unwrap() {
        let kinds: Vec<Kind> = case["types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| kind(t.as_str().unwrap()))
            .collect();
        let data = match case.get("recipe") {
            Some(r) => aliased_strings(
                r["aliased_strings"].as_u64().unwrap() as usize,
                r["string_length"].as_u64().unwrap() as usize,
            ),
            None => unhex(case["data"].as_str().unwrap()).unwrap(),
        };
        let ours = abi::decode(&kinds, &data);
        match case["js"].get("fields") {
            None => assert!(
                ours.is_err(),
                "{}: the whole decode must fail",
                case["data"]
            ),
            Some(fields) => {
                let ours = ours.unwrap_or_else(|_| panic!("{}: decodes in JS", case["data"]));
                for (field, js) in ours.iter().zip(fields.as_array().unwrap()) {
                    assert!(same_field(field, js), "{}: {field:?} vs {js}", case["data"]);
                }
            }
        }
    }
}

#[test]
fn universal_resolver() {
    let v = vectors();
    let u = &v["ur"];
    for case in u["results"].as_array().unwrap() {
        let data = unhex(case["data"].as_str().unwrap()).unwrap();
        let ours = ur::decode_result(&[Kind::Bytes, Kind::Address], &data);
        match case["js"].get("fields") {
            None => assert!(ours.is_err(), "{}", case["data"]),
            Some(fields) => {
                for (field, js) in ours.unwrap().iter().zip(fields.as_array().unwrap()) {
                    assert!(same_field(field, js), "{}", case["data"]);
                }
            }
        }
    }
    for case in u["reverts"].as_array().unwrap() {
        let data = unhex(case["data"].as_str().unwrap()).unwrap();
        let js = &case["js"];
        assert_eq!(
            ur::classify_revert(&data) == Some(Revert::ReverseAddressMismatch),
            js["mismatch"].as_bool().unwrap(),
            "{}",
            case["data"]
        );
        assert_eq!(
            ur::reverse_mismatch_claimed_name(&data).as_deref(),
            js["claimed_name"].as_str(),
            "{}",
            case["data"]
        );
        let selector = js["selector"].as_str();
        assert_eq!(
            data.get(..4).map(hex0x).as_deref(),
            selector,
            "{}",
            case["data"]
        );
    }
    let calls = &u["calls"];
    let node = namehash("vitalik.eth").unwrap();
    let dns = dns_encode("vitalik.eth", 255).unwrap();
    assert_eq!(
        hex0x(&ur::encode_resolve(&dns, &ur::contenthash_call(&node))),
        calls["resolve"]
    );
    assert_eq!(
        hex0x(&ur::encode_reverse(&[0xab; 20], 60)),
        calls["reverse"]
    );
    assert_eq!(
        hex0x(&ur::addr_multicoin_call(&node, 2_147_492_101)),
        calls["addr_multicoin"]
    );
    assert_eq!(
        hex0x(&ur::reverse_resolve_call(&[0xab; 20])),
        calls["reverse_resolve"]
    );
    for case in u["reverse_outcomes"].as_array().unwrap() {
        let status = match case["status"].as_u64().unwrap() {
            0 => ReverseOutcome::NoRecord,
            1 => ReverseOutcome::Name,
            2 => ReverseOutcome::Mismatch,
            _ => ReverseOutcome::Error,
        };
        assert_eq!(
            hex0x(&ur::encode_reverse_outcome(
                status,
                case["detail"].as_str().unwrap()
            )),
            case["encoded"]
        );
    }
    for case in u["nodes"].as_array().unwrap() {
        let ours =
            unhex(case["input"].as_str().unwrap()).and_then(|call| ur::node_from_call(&call));
        assert_eq!(
            ours.map(|n| hex0x(&n)).as_deref(),
            case["js"]["value"].as_str(),
            "{}",
            case["input"]
        );
    }
    let lookup =
        ur::decode_offchain_lookup(&unhex(u["offchain_lookup"].as_str().unwrap()).unwrap())
            .unwrap();
    assert_eq!(lookup.sender, ur::UNIVERSAL_RESOLVER);
    assert_eq!(
        lookup.urls,
        [
            Ok("https://gw.example/{sender}/{data}.json".to_owned()),
            Ok("https://gw2.example".to_owned())
        ]
    );
    assert_eq!(
        (lookup.call_data, lookup.callback, lookup.extra_data),
        (vec![1, 2], [0xde, 0xad, 0xbe, 0xef], vec![9])
    );
    let cb = &u["callback"];
    let encoded = ur::encode_callback(
        [0xde, 0xad, 0xbe, 0xef],
        &unhex(cb["response"].as_str().unwrap()).unwrap(),
        &unhex(cb["extra"].as_str().unwrap()).unwrap(),
    );
    assert_eq!(hex0x(&encoded), cb["encoded"]);
}

#[test]
fn offchain_lookups() {
    let v = vectors();
    for case in v["offchain_lookup"].as_array().unwrap() {
        let data = unhex(case["data"].as_str().unwrap()).unwrap();
        let ours = ur::decode_offchain_lookup(&data);
        match case["strict"].get("value") {
            None => assert!(ours.is_none(), "{}: the strict path refuses it", case["id"]),
            Some(js) => {
                let ours =
                    ours.unwrap_or_else(|| panic!("{}: the strict path accepts it", case["id"]));
                assert_eq!(hex0x(&ours.sender), js["sender"], "{}", case["id"]);
                // Each URL on its own, as the JS reads them lazily.
                let urls: Vec<Value> = ours
                    .urls
                    .iter()
                    .map(|u| match u {
                        Ok(url) => json!({ "value": url }),
                        Err(_) => json!({ "error": true }),
                    })
                    .collect();
                let expected: Vec<Value> = js["urls"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|u| match u.get("value") {
                        Some(v) => json!({ "value": v }),
                        None => json!({ "error": true }),
                    })
                    .collect();
                assert_eq!(urls, expected, "{}", case["id"]);
                assert_eq!(hex0x(&ours.call_data), js["call_data"], "{}", case["id"]);
                assert_eq!(hex0x(&ours.callback), js["callback"], "{}", case["id"]);
                assert_eq!(hex0x(&ours.extra_data), js["extra_data"], "{}", case["id"]);
            }
        }
    }
}

#[test]
fn ccip_gateways() {
    let v = vectors();
    let c = &v["ccip"];
    let sender: [u8; 20] = unhex(c["sender"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    for case in c["policy"].as_array().unwrap() {
        let template = case["template"].as_str().unwrap();
        let data = unhex(case["data"].as_str().unwrap()).unwrap();
        let ours = ccip::gateway_request(template, &sender, &data);
        let requests = case["requests"].as_array().unwrap();
        match (ours, requests.first()) {
            (None, None) => {}
            (Some(ours), Some(js)) => {
                assert_eq!(ours.url, js["url"].as_str().unwrap(), "{template}");
                assert_eq!(
                    ours.method == Method::Get,
                    js["method"] == "GET",
                    "{template}"
                );
                assert_eq!(ours.body.as_deref(), js["body"].as_str(), "{template}");
            }
            (ours, js) => panic!("{template}: core {ours:?}, JS {js:?}"),
        }
    }
    for case in c["answers"].as_array().unwrap() {
        // Status handling is main's (it sees the HTTP response); the core
        // parses 2xx bodies.
        if case.get("status").is_some_and(|s| s != 200) {
            continue;
        }
        let body = match case.get("body_hex") {
            Some(h) => hex::decode(h.as_str().unwrap()).unwrap(),
            None => case["body"].as_str().unwrap().as_bytes().to_vec(),
        };
        let ours = ccip::parse_gateway_response(&body).map(|d| hex0x(&d));
        if case["deviation"] == "json-depth" {
            // Deeper than MAX_DEPTH: refused, where V8 accepts it.
            assert_eq!(ours, None, "{case}");
            continue;
        }
        assert_eq!(ours.as_deref(), case["result"].as_str(), "{case}");
    }
}

#[test]
fn numbers_print_like_javascript() {
    let v = vectors();
    for case in v["numbers"].as_array().unwrap() {
        let bits = u64::from_str_radix(case["bits"].as_str().unwrap(), 16).unwrap();
        let n = f64::from_bits(bits);
        assert_eq!(
            jsjson::number_to_string(n),
            case["js"].as_str().unwrap(),
            "{bits:016x}"
        );
    }
}

#[test]
fn tezos_codecs() {
    let v = vectors();
    let t = &v["tezos"];
    for case in t["script_expr"].as_array().unwrap() {
        assert_eq!(
            tezos::script_expr_hash(case["key"].as_str().unwrap().as_bytes()),
            case["js"].as_str().unwrap()
        );
    }
    for case in t["names"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        assert_eq!(
            tezos::is_tezos_domain_name(name),
            case["js"].as_bool().unwrap(),
            "{name:?}"
        );
    }
    for case in t["uris"].as_array().unwrap() {
        let redirect = case["redirect"].as_bool().unwrap();
        let ours = match tezos::parse_published_uri(&to_js(&case["raw"]), redirect) {
            Published::Web {
                protocol,
                uri,
                redirect,
            } => {
                json!({ "type": "ok", "protocol": protocol, "uri": uri, "redirect": redirect, "system": "tezos" })
            }
            Published::Content {
                protocol,
                uri,
                decoded,
                base_path,
            } => {
                json!({ "type": "ok", "protocol": protocol, "uri": uri, "decoded": decoded, "basePath": base_path, "redirect": false, "system": "tezos" })
            }
            Published::Unsupported(reason) => {
                json!({ "type": "unsupported", "reason": reason, "system": "tezos" })
            }
        };
        assert_eq!(ours, case["js"], "{}", case["raw"]);
    }
    for case in t["maps"].as_array().unwrap() {
        let ours: Vec<Value> = tezos::map_entries(&to_js(&case["value"]))
            .into_iter()
            .map(|(k, b)| {
                let bytes: Value = b.map_or(Value::Null, |b| {
                    serde_json::from_str(&b.stringify()).unwrap()
                });
                json!([k, bytes])
            })
            .collect();
        assert_eq!(Value::Array(ours), case["js"], "{}", case["value"]);
    }
    for case in t["metadata"].as_array().unwrap() {
        let hex = case["hex"].as_str().map(|h| JsValue::String(h.to_owned()));
        let ours = tezos::decode_json_bytes(hex.as_ref());
        if case["deviation"] == "json-depth" {
            assert!(ours.is_err(), "{}: deeper than MAX_DEPTH", case["hex"]);
            continue;
        }
        if case["deviation"] == "lone-surrogate-keys" {
            // Keys that differ only in lone surrogates become one key.
            assert!(ours.is_ok(), "{}", case["hex"]);
            continue;
        }
        if case["deviation"] == "lone-surrogate" {
            // JavaScript keeps the lone surrogate; the core holds U+FFFD.
            assert_eq!(
                ours.unwrap(),
                JsValue::String("\u{FFFD}".into()),
                "{}",
                case["hex"]
            );
            continue;
        }
        match case["js"].get("stringified") {
            Some(text) => assert_eq!(
                ours.unwrap().stringify(),
                text.as_str().unwrap(),
                "{}",
                case["hex"]
            ),
            None => {
                let error = ours.unwrap_err();
                if case["js"]["error"] == "Invalid Micheline bytes value" {
                    assert_eq!(error.message(), "Invalid Micheline bytes value");
                }
            }
        }
    }
    let annotated = &t["annotated"];
    let (annotated_type, annotated_value) = (to_js(&annotated["type"]), to_js(&annotated["value"]));
    for case in annotated["cases"].as_array().unwrap() {
        let ours = tezos::find_annotated_value(
            Some(&annotated_type),
            Some(&annotated_value),
            case["annotation"].as_str().unwrap(),
        )
        .unwrap()
        .map(|(ty, value)| to_value(&json_pair(ty, value)));
        assert_eq!(
            ours.unwrap_or(Value::Null),
            case["js"],
            "{}",
            case["annotation"]
        );
    }
    for case in t["micheline"].as_array().unwrap() {
        let (case_type, case_value) = (to_js(&case["type"]), to_js(&case["value"]));
        let ours = tezos::find_annotated_value(
            Some(&case_type),
            Some(&case_value),
            case["annotation"].as_str().unwrap(),
        );
        match case["js"].get("value") {
            None => assert!(ours.is_err(), "{}: a TypeError in JS", case["type"]),
            Some(js) => {
                let ours = ours
                    .unwrap()
                    .map(|(ty, value)| to_value(&json_pair(ty, value)));
                assert_eq!(&ours.unwrap_or(Value::Null), js, "{}", case["type"]);
            }
        }
    }
    for case in t["scripts"].as_array().unwrap() {
        let ours = tezos::storage_type_from_script(&to_js(&case["script"]));
        match case["js"].get("value") {
            None => assert!(ours.is_err(), "{}: a TypeError in JS", case["script"]),
            Some(js) => {
                let ours = ours.unwrap().map(|ty| to_value(&ty));
                assert_eq!(&ours.unwrap_or(Value::Null), js, "{}", case["script"]);
            }
        }
    }
}

fn json_pair(ty: &JsValue, value: &JsValue) -> JsValue {
    JsValue::Object(vec![
        ("type".into(), ty.clone()),
        ("value".into(), value.clone()),
    ])
}

fn to_value(value: &JsValue) -> Value {
    serde_json::from_str(&value.stringify()).unwrap()
}
