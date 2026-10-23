//! Replays vectors/chain.json, generated from the pinned chain-data router.
//! JavaScript strings that may hold lone surrogates are recorded as their
//! JSON text (`*_json`); entries marked `deviation` are where the core
//! differs by design.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_chain::{
    ANT_EXCLUDE_SOURCES, ANT_INCLUDE_SOURCES, ANT_LOG_SCAN_SHRINK_NEEDLES, AnswerError,
    AttemptClass, BLOCKSCOUT, BLOCKSCOUT_MAX_PAGES, BlockscoutError, ERC20_TRANSFER_TOPIC,
    ErrorRank, JSON_PARSE_FAILURE, JsString, LOG_INDEX_ABORT_COOLDOWN_MS, LOG_INDEX_CHAIN_ID,
    LOG_INDEX_DISAGREEMENT_COOLDOWN_MS, LOG_INDEX_PAIR_MALFORMED_COOLDOWN_MS,
    LOG_INDEX_TAIL_BLOCKS, LOG_INDEX_TOKEN, LOG_RANGE_CAP_TTL_MS, LOG_RANGE_REFUSAL_CODE,
    LOG_SCAN_COOLDOWN_MS, LOG_SCAN_QUORUM_ROUNDS, LOG_SCAN_QUORUM_TIMEOUT_MS,
    LOG_TRUNCATION_MIN_SPAN, LOG_TRUNCATION_TAIL_BLOCKS, LogIndexFilter, MAX_COOLDOWN_MS,
    MAX_DECIMAL_BITS, MAX_MYOTIS_REFUSAL_MESSAGE, MAX_PAGE_SIZE, MIN_COOLDOWN_MS,
    MYOTIS_BLOB_FIELDS, MYOTIS_NOT_READY, MyotisFailure, MyotisOperation, Outcome, PageReply,
    Party, RATE_LIMIT_COOLDOWN_MS, READ_METHODS, ReceivedError, RefusalReason, SINGLE_NODE_METHODS,
    ScanStep, SourceFailure, StableDigest, TransferScan, TxHash, agreed_rpc_logs,
    ant_shrinks_log_scan_on, blockscout_transfer, broadcast_failure_text, canonical_log,
    classify_broadcast_answer, combine_fee_quotes, cooldown_from, decode_answer, fee_quote,
    fee_quote_failure_text, fee_quote_values, is_js_whitespace, is_read_method, log_index_filter,
    log_query_span, log_range_refusal_text, log_scan_range_cap, logs_agree, myotis_answer,
    myotis_operation, myotis_trust, no_source_left_text, normalize_params, rank_log_scan_error,
    request_failure_text, rpc_transfer, rpc_transfer_log_well_formed, safe_error_message,
    source_order, source_serves_method, stable_digest, stable_value, transaction_hash,
    transfers_json, unsupported_read_method_text,
};
use fc_json::index::{Index, IndexError, KeyOrder};
use serde_json::Value as Json;

fn vectors() -> Json {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/chain.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn str_of<'a>(entry: &'a Json, key: &str) -> &'a str {
    entry[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} in {entry}"))
}

fn opt_str<'a>(entry: &'a Json, key: &str) -> Option<&'a str> {
    entry[key].as_str()
}

/// A JavaScript string recorded as its JSON text.
fn js_units(json_text: &str) -> Vec<u16> {
    Index::new(json_text).unwrap().root().units().collect()
}

/// `JSON.stringify(JSON.parse(text))`.
fn stringify(text: &str) -> String {
    Index::new(text)
        .unwrap()
        .root()
        .stringify(KeyOrder::Property)
}

fn id(entry: &Json) -> String {
    entry["id"].as_str().unwrap_or("?").to_owned()
}

fn deviation(entry: &Json) -> Option<&str> {
    entry["deviation"].as_str()
}

#[test]
fn normalization() {
    let vectors = vectors();
    let cases = vectors["normalization"].as_array().unwrap();
    let mut deviations = 0;
    for case in cases {
        let (method, params) = (str_of(case, "method"), str_of(case, "params"));
        let js = &case["js"];
        let result = normalize_params(method, params);
        match deviation(case) {
            Some("json-depth") => {
                assert_eq!(result, Err(IndexError::TooDeep), "{}", id(case));
                deviations += 1;
            }
            Some("bigint-width") => {
                // Left as sent, for the node to refuse.
                let result = result.unwrap();
                assert!(!result.changed, "{}", id(case));
                assert_eq!(result.params, stringify(params), "{}", id(case));
                assert_ne!(result.params, str_of(js, "params"), "{}", id(case));
                deviations += 1;
            }
            None => {
                let result = result.unwrap_or_else(|e| panic!("{}: {e}", id(case)));
                assert_eq!(result.params, str_of(js, "params"), "{}", id(case));
                assert_eq!(
                    Some(result.changed),
                    js["changed"].as_bool(),
                    "{}",
                    id(case)
                );
            }
            Some(other) => panic!("unknown deviation {other}"),
        }
    }
    assert!(cases.len() > 100 && deviations == 3, "{deviations}");
}

#[test]
fn whitespace_sets() {
    let vectors = vectors();
    for key in ["bigint_whitespace", "safe_error_whitespace"] {
        let units: Vec<u64> = vectors[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u.as_u64().unwrap())
            .collect();
        for unit in 0..=u16::MAX {
            assert_eq!(
                is_js_whitespace(unit),
                units.contains(&u64::from(unit)),
                "{key}: {unit:#x}"
            );
        }
    }
}

#[test]
fn stable_values() {
    let vectors = vectors();
    let cases = vectors["stable"].as_array().unwrap();
    let mut digests = Vec::new();
    for case in cases {
        let js = &case["js"];
        let Some(text) = opt_str(case, "text") else {
            assert!(js["stable"].is_null());
            assert_eq!(stable_digest(None).unwrap(), StableDigest::undefined());
            continue;
        };
        if deviation(case) == Some("json-depth") {
            assert_eq!(stable_value(text), Err(IndexError::TooDeep), "{}", id(case));
            assert_eq!(stable_digest(Some(text)), Err(IndexError::TooDeep));
            continue;
        }
        assert_eq!(deviation(case), None);
        assert_eq!(
            stable_value(text).unwrap(),
            str_of(js, "stable"),
            "{}",
            id(case)
        );
        let digest = stable_digest(Some(text)).unwrap();
        assert_eq!(
            hex::encode(digest.as_bytes()),
            str_of(js, "sha256"),
            "{}",
            id(case)
        );
        digests.push(digest);
    }
    // No JSON value's digest is undefined's.
    assert!(digests.len() > 50);
    assert!(!digests.contains(&StableDigest::undefined()));
}

#[test]
fn equivalence_pairs() {
    let vectors = vectors();
    let pairs = vectors["equivalence"].as_array().unwrap();
    for pair in pairs {
        let a = stable_digest(opt_str(pair, "a")).unwrap();
        let b = stable_digest(opt_str(pair, "b")).unwrap();
        assert_eq!(a == b, pair["equal"].as_bool().unwrap(), "{pair}");
    }
    let equal = pairs.iter().filter(|p| p["equal"] == true).count();
    assert!(equal > 10 && pairs.len() - equal > 10);
}

#[test]
fn answers() {
    let vectors = vectors();
    let cases = vectors["answers"].as_array().unwrap();
    for case in cases {
        let body = hex::decode(str_of(case, "body_hex")).unwrap();
        let status = u16::try_from(case["status"].as_u64().unwrap()).unwrap();
        let js = &case["js"];
        let decoded = decode_answer(status, body);
        let name = id(case);
        match deviation(case) {
            Some("json-depth") => {
                assert_eq!(decoded.unwrap_err(), AnswerError::TooDeep, "{name}");
                continue;
            }
            Some("json-parse-text") => {
                assert_eq!(str_of(&js["error"], "name"), "SyntaxError", "{name}");
                let error = decoded.unwrap_err();
                assert_eq!(error, AnswerError::Syntax, "{name}");
                assert_eq!(error.to_string(), JSON_PARSE_FAILURE);
                continue;
            }
            None => {}
            Some(other) => panic!("unknown deviation {other}"),
        }
        if js["undefined"] == true {
            let answer = decoded.unwrap();
            assert_eq!(answer.outcome(), Outcome::Result(None), "{name}");
            continue;
        }
        if let Some(expected) = opt_str(js, "result_json") {
            let answer = decoded.unwrap_or_else(|e| panic!("{name}: {e}"));
            let Outcome::Result(Some(result)) = answer.outcome() else {
                panic!("{name}: {:?}", answer.outcome());
            };
            assert_eq!(stringify(result), expected, "{name}");
            assert_eq!(
                stable_value(result).unwrap(),
                str_of(js, "stable"),
                "{name}"
            );
            continue;
        }
        let error = &js["error"];
        let message = js_units(str_of(error, "message_json"));
        let error_name = str_of(error, "name");
        match decoded {
            Err(failure) => {
                assert_eq!(failure.name(), error_name, "{name}");
                assert_eq!(
                    JsString::from(failure.to_string().as_str()).units(),
                    message,
                    "{name}"
                );
                assert!(error.get("code_json").is_none(), "{name}");
            }
            Ok(answer) => {
                let Outcome::NodeError(node) = answer.outcome() else {
                    panic!("{name}: {:?}", answer.outcome());
                };
                assert_eq!(error_name, "Error", "{name}");
                assert_eq!(node.message.units(), message, "{name}");
                assert_eq!(
                    node.message.to_json(),
                    str_of(error, "message_json"),
                    "{name}"
                );
                // The router always sets both; null is undefined.
                for (key, value) in [("code_json", node.code), ("data_json", node.data)] {
                    assert_eq!(
                        value.map(stringify).as_deref(),
                        opt_str(error, key),
                        "{name} {key}"
                    );
                    assert!(error.get(key).is_some(), "{name} {key}");
                }
            }
        }
    }
    assert!(cases.len() > 90);
}

#[test]
fn fee_quotes() {
    let vectors = vectors();
    let cases = vectors["fee_quotes"].as_array().unwrap();
    for case in cases {
        let name = id(case);
        let source = str_of(case, "source");
        let quote = fee_quote(
            source,
            opt_str(case, "gas_price"),
            opt_str(case, "priority"),
        );
        let js = &case["js"];
        match deviation(case) {
            Some("bigint-width") => {
                assert!(js.get("quote_json").is_some(), "{name}");
                let error = quote.unwrap_err();
                assert_eq!(error.name, "Error");
                assert_eq!(
                    error.message.to_string_lossy(),
                    format!("{source} returned a gas price wider than {MAX_DECIMAL_BITS} bits")
                );
            }
            None => match opt_str(js, "quote_json") {
                Some(expected) => assert_eq!(quote.unwrap().to_json(), expected, "{name}"),
                None => {
                    let error = quote.unwrap_err();
                    assert_eq!(error.name, str_of(&js["error"], "name"), "{name}");
                    assert_eq!(
                        error.message.to_json(),
                        str_of(&js["error"], "message_json"),
                        "{name}"
                    );
                }
            },
            Some(other) => panic!("unknown deviation {other}"),
        }
    }
    assert!(cases.len() > 50);
}

/// B's combination of Direct's quotes (deviation `fee-combination`): the
/// design's own expected values, each endpoint's quote the reference's.
#[test]
fn fee_combinations() {
    let vectors = vectors();
    let combinations = &vectors["fee_combinations"];
    assert_eq!(combinations["deviation"], "fee-combination");
    let cases = combinations["cases"].as_array().unwrap();
    for case in cases {
        let name = id(case);
        let values: Vec<_> = case["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .map(|endpoint| {
                let values = fee_quote_values(
                    "direct",
                    opt_str(endpoint, "gas_price"),
                    opt_str(endpoint, "priority"),
                )
                .unwrap();
                assert_eq!(
                    values.quote("direct").to_json(),
                    str_of(&endpoint["js"], "quote_json"),
                    "{name}"
                );
                values
            })
            .collect();
        let verified = case["eip1559_verified"].as_bool().unwrap();
        let combined = combine_fee_quotes(&values, verified).unwrap();
        assert_eq!(
            combined.to_json(),
            str_of(&case["design"], "quote_json"),
            "{name}"
        );
        assert_eq!(combined.json_len(), combined.to_json().len(), "{name}");
    }
    assert!(cases.len() >= 20);
}

#[test]
fn safe_error_messages() {
    let vectors = vectors();
    for case in vectors["safe_error_message"].as_array().unwrap() {
        let message = js_units(str_of(case, "message_json"));
        let text = safe_error_message(str_of(case, "name"), &message);
        assert_eq!(text.to_json(), str_of(&case["js"], "text_json"), "{case}");
    }
}

#[test]
fn failure_texts() {
    let vectors = vectors();
    let texts = &vectors["failure_texts"];
    for case in texts["request"].as_array().unwrap() {
        let messages: Vec<Vec<u16>> = case["failures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| opt_str(f, "message_json").map(js_units).unwrap_or_default())
            .collect();
        let failures: Vec<SourceFailure<'_>> = case["failures"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&messages)
            .map(|(failure, message)| {
                if failure["bypassed"] == true {
                    SourceFailure::Bypassed {
                        source: str_of(failure, "source"),
                    }
                } else {
                    SourceFailure::Failed {
                        source: str_of(failure, "source"),
                        name: str_of(failure, "name"),
                        message,
                    }
                }
            })
            .collect();
        let excluded: Vec<&str> = case["excluded"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        let text = request_failure_text(str_of(case, "method"), &failures, &excluded);
        assert_eq!(
            text.to_json(),
            str_of(&case["js"], "text_json"),
            "{}",
            id(case)
        );
    }
    for (key, build) in [
        (
            "fee_quote",
            fee_quote_failure_text as fn(&[(&str, &[u16])]) -> JsString,
        ),
        ("broadcast", broadcast_failure_text),
    ] {
        for case in texts[key].as_array().unwrap() {
            let messages: Vec<(&str, Vec<u16>)> = case["failures"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| (str_of(f, "source"), js_units(str_of(f, "message_json"))))
                .collect();
            let failures: Vec<(&str, &[u16])> =
                messages.iter().map(|(s, m)| (*s, m.as_slice())).collect();
            assert_eq!(
                build(&failures).to_json(),
                str_of(&case["js"], "text_json"),
                "{key} {}",
                id(case)
            );
        }
    }
}

#[test]
fn transaction_hashes() {
    let vectors = vectors();
    let cases = vectors["transaction_hashes"].as_array().unwrap();
    for case in cases {
        let raw = str_of(case, "raw");
        let hash = transaction_hash(raw);
        match opt_str(&case["js"], "hash") {
            Some(expected) => {
                let hash = hash.unwrap();
                assert_eq!(hash.to_hex(), expected, "{raw}");
                assert_eq!(TxHash::from_hex(expected), Some(hash));
                assert_eq!(TxHash::from_hex(&expected.to_uppercase()), Some(hash));
                assert_eq!(TxHash::from_json(&format!("\"{expected}\"")), Some(hash));
            }
            None => assert!(hash.is_err(), "{raw}"),
        }
    }
    assert!(cases.iter().filter(|c| c["js"]["invalid"] == true).count() >= 5);
}

// ---------------------------------------------------------------------------
// Read methods, the source order, Myotis, the Ant profile, Blockscout and
// broadcast refusals.

fn strings(value: &Json) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect()
}

/// A JSON text recorded as a string, or `null` for none: `None`.
fn json_text(value: &Json) -> Option<&str> {
    value.as_str()
}

#[test]
fn read_methods() {
    let vectors = vectors();
    let methods = &vectors["methods"];
    assert_eq!(strings(&methods["read_methods"]), READ_METHODS);
    assert_eq!(
        strings(&methods["single_node_methods"]),
        SINGLE_NODE_METHODS
    );
    let probes = methods["is_read_method"].as_array().unwrap();
    for probe in probes {
        let method = str_of(probe, "method");
        assert_eq!(is_read_method(method), probe["js"] == true, "{method:?}");
    }
    let capabilities = methods["source_capabilities"].as_array().unwrap();
    assert_eq!(capabilities.len(), 5);
    for capability in capabilities {
        let source = str_of(capability, "source");
        let unsupported = strings(&capability["unsupported"]);
        assert_eq!(capability["opt_in"] == true, source == BLOCKSCOUT);
        for probe in probes {
            let method = str_of(probe, "method");
            assert_eq!(
                source_serves_method(source, method),
                !unsupported.contains(&method),
                "{source} {method:?}"
            );
        }
    }
    for case in methods["unsupported"].as_array().unwrap() {
        let text = unsupported_read_method_text(str_of(case, "method"));
        assert_eq!(
            JsString::from(text.as_str()).to_json(),
            str_of(&case["js"], "text_json")
        );
    }
}

#[test]
fn source_orders() {
    let vectors = vectors();
    let cases = vectors["source_orders"].as_array().unwrap();
    let mut empty = 0;
    for case in cases {
        let name = id(case);
        let (method, params) = (str_of(case, "method"), str_of(case, "params"));
        let chain_id = case["chain_id"].as_u64().unwrap();
        let eligible = case["profile"] == "ant"
            && log_query_span(method, params).is_some()
            && log_index_filter(chain_id, params).is_some();
        let read_order = strings(&case["read_order"]);
        let order = source_order(
            &read_order,
            &strings(&case["include_sources"]),
            &strings(&case["exclude_sources"]),
            method,
            eligible,
        );
        let js = &case["js"];
        let tried = js["tried"].as_array().unwrap();
        let tried_sources: Vec<&str> = tried.iter().map(|t| str_of(t, "source")).collect();
        assert_eq!(order.order, tried_sources, "{name}");
        let text = if order.order.is_empty() {
            empty += 1;
            JsString::from(
                no_source_left_text(method, chain_id, &order.configured, &order.dropped).as_str(),
            )
        } else {
            let messages: Vec<Vec<u16>> = tried
                .iter()
                .map(|t| js_units(str_of(t, "message_json")))
                .collect();
            let failures: Vec<SourceFailure<'_>> = tried
                .iter()
                .zip(&messages)
                .map(|(t, message)| SourceFailure::Failed {
                    source: str_of(t, "source"),
                    name: str_of(t, "name"),
                    message,
                })
                .collect();
            request_failure_text(method, &failures, &order.dropped)
        };
        assert_eq!(text.to_json(), str_of(js, "text_json"), "{name}");
    }
    assert!(empty > 10 && cases.len() - empty >= 3);
}

/// Checks a Myotis failure against the router's error.
fn assert_myotis_failure(failure: &MyotisFailure, error: &Json, name: &str) {
    match failure {
        MyotisFailure::Final(refusal) => {
            assert_eq!(error["final"], true, "{name}");
            assert_eq!(str_of(error, "name"), "Error", "{name}");
            assert_eq!(
                refusal.message.to_json(),
                str_of(error, "message_json"),
                "{name}"
            );
            assert_eq!(
                opt_str(error, "code_json"),
                Some(refusal.code.to_string().as_str()),
                "{name}"
            );
            assert_eq!(
                opt_str(error, "data_json"),
                refusal.data.as_ref().map(JsString::to_json).as_deref(),
                "{name}"
            );
            assert_eq!(opt_str(error, "myotis_refusal"), refusal.kind(), "{name}");
        }
        MyotisFailure::Unavailable(message) => {
            assert_eq!(error["unavailable"], true, "{name}");
            assert_eq!(error["final"], false, "{name}");
            assert_eq!(message.to_json(), str_of(error, "message_json"), "{name}");
            assert!(error.get("code_json").is_none(), "{name}");
        }
        MyotisFailure::Error(js) => {
            assert_eq!(error["unavailable"], false, "{name}");
            assert_eq!(error["final"], false, "{name}");
            assert_eq!(js.name, str_of(error, "name"), "{name}");
            assert_eq!(
                js.message.to_json(),
                str_of(error, "message_json"),
                "{name}"
            );
            assert!(error.get("code_json").is_none(), "{name}");
        }
    }
}

fn assert_operation(operation: &MyotisOperation, expected: &Json, name: &str) {
    let address = |key: &str| json_text(&expected[key]);
    match operation {
        MyotisOperation::Account { address: a } => {
            assert_eq!(expected["kind"], "account", "{name}");
            assert_eq!(a.as_deref(), address("address_json"), "{name}");
        }
        MyotisOperation::Code { address: a } => {
            assert_eq!(expected["kind"], "code", "{name}");
            assert_eq!(a.as_deref(), address("address_json"), "{name}");
        }
        MyotisOperation::Storage { address: a, slot } => {
            assert_eq!(expected["kind"], "storage", "{name}");
            assert_eq!(a.as_deref(), address("address_json"), "{name}");
            assert_eq!(slot.as_deref(), address("slot_json"), "{name}");
        }
        MyotisOperation::CallTx { tx } => {
            assert_eq!(expected["kind"], "call_tx", "{name}");
            assert_eq!(tx, str_of(expected, "tx_json"), "{name}");
        }
        MyotisOperation::EstimateTx { tx } => {
            assert_eq!(expected["kind"], "estimate_tx", "{name}");
            assert_eq!(tx, str_of(expected, "tx_json"), "{name}");
        }
        MyotisOperation::Fee => assert_eq!(expected["kind"], "fee", "{name}"),
    }
}

#[test]
fn myotis_reads() {
    let vectors = vectors();
    let myotis = &vectors["myotis"];
    assert_eq!(strings(&myotis["blob_fields"]), MYOTIS_BLOB_FIELDS);
    assert_eq!(
        myotis["max_refusal_message"].as_u64(),
        Some(MAX_MYOTIS_REFUSAL_MESSAGE as u64)
    );
    assert_eq!(
        JsString::from(MYOTIS_NOT_READY).to_json(),
        str_of(&myotis["not_ready"], "message_json")
    );
    assert_eq!(myotis["not_ready"]["unavailable"], true);
    let reads = myotis["reads"].as_array().unwrap();
    let (mut finals, mut deviations) = (0, 0);
    for read in reads {
        let name = id(read);
        let method = str_of(read, "method");
        let js = &read["js"];
        let operation = myotis_operation(method, str_of(read, "params"));
        if js["operation"].is_null() {
            let failure = operation.expect_err(&name);
            assert_myotis_failure(&failure, &js["error"], &name);
            continue;
        }
        let operation = operation.unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_operation(&operation, &js["operation"], &name);
        let answer = myotis_answer(method, opt_str(read, "wire_json"));
        if deviation(read) == Some("bigint-width") {
            // The router converts it; the core refuses it.
            assert!(opt_str(js, "result_json").is_some(), "{name}");
            let Err(MyotisFailure::Error(error)) = answer else {
                panic!("{name}: {answer:?}")
            };
            assert_eq!(error.name, "Error");
            deviations += 1;
            continue;
        }
        assert_eq!(deviation(read), None);
        match (answer, opt_str(js, "result_json")) {
            (Ok(result), Some(expected)) => assert_eq!(result, expected, "{name}"),
            (Err(failure), None) => {
                finals += usize::from(matches!(failure, MyotisFailure::Final(_)));
                assert_myotis_failure(&failure, &js["error"], &name);
            }
            (answer, _) => panic!("{name}: {answer:?}"),
        }
    }
    assert!(reads.len() > 150 && finals > 15 && deviations == 1);
    let trust = myotis["trust"].as_array().unwrap();
    for case in trust {
        let label = myotis_trust(
            opt_str(case, "block_before_json"),
            opt_str(case, "block_after_json"),
        );
        assert_eq!(label, str_of(&case["js"], "trust_json"), "{case}");
    }
    assert!(trust.len() > 20);
}

fn received<'a>(case: &'a Json, message: &'a [u16]) -> ReceivedError<'a> {
    ReceivedError {
        name: str_of(case, "name"),
        message,
        code: opt_str(case, "code_json"),
        timeout: case["failure_kind"] == "timeout",
    }
}

#[test]
fn ant_profile() {
    let vectors = vectors();
    let profile = &vectors["ant_profile"];
    for (rank, value) in [
        (ErrorRank::Endpoint, "ENDPOINT"),
        (ErrorRank::Hint, "HINT"),
        (ErrorRank::Timeout, "TIMEOUT"),
        (ErrorRank::Request, "REQUEST"),
    ] {
        assert_eq!(profile["rank"][value].as_u64(), Some(rank as u64));
    }
    assert_eq!(strings(&profile["needles"]), ANT_LOG_SCAN_SHRINK_NEEDLES);
    let options = &profile["router_options"];
    assert_eq!(strings(&options["exclude_sources"]), ANT_EXCLUDE_SOURCES);
    assert_eq!(strings(&options["include_sources"]), ANT_INCLUDE_SOURCES);
    assert_eq!(
        options["quorum_timeout_ms"].as_u64(),
        Some(LOG_SCAN_QUORUM_TIMEOUT_MS)
    );
    let spans: Vec<Option<u64>> = profile["cap_spans"]
        .as_array()
        .unwrap()
        .iter()
        .map(Json::as_u64)
        .collect();
    let errors = profile["errors"].as_array().unwrap();
    let mut ranks = [0; 4];
    for case in errors {
        let message = js_units(str_of(case, "message_json"));
        let error = received(case, &message);
        let js = &case["js"];
        let rank = rank_log_scan_error(&error);
        assert_eq!(Some(rank as u64), js["rank"].as_u64(), "{case}");
        ranks[rank as usize] += 1;
        assert_eq!(
            ant_shrinks_log_scan_on(&message),
            js["shrinks"] == true,
            "{case}"
        );
        for (span, cap) in spans.iter().zip(js["caps"].as_array().unwrap()) {
            assert_eq!(
                log_scan_range_cap(&error, *span),
                cap.as_u64(),
                "{case} {span:?}"
            );
        }
    }
    assert!(ranks.iter().all(|&n| n > 10), "{ranks:?}");
    for case in profile["range_refusals"].as_array().unwrap() {
        let span = case["span"].as_u64().unwrap();
        let error = &case["js"];
        assert_eq!(str_of(error, "name"), "Error");
        assert_eq!(
            JsString::from(log_range_refusal_text(span).as_str()).to_json(),
            str_of(error, "message_json")
        );
        assert_eq!(
            opt_str(error, "code_json"),
            Some(LOG_RANGE_REFUSAL_CODE.to_string().as_str())
        );
    }
    let constants = &profile["log_constants"];
    for (key, value) in [
        ("LOG_RANGE_CAP_TTL_MS", LOG_RANGE_CAP_TTL_MS),
        ("LOG_SCAN_COOLDOWN_MS", LOG_SCAN_COOLDOWN_MS),
        ("LOG_SCAN_QUORUM_ROUNDS", u64::from(LOG_SCAN_QUORUM_ROUNDS)),
        ("LOG_TRUNCATION_TAIL_BLOCKS", LOG_TRUNCATION_TAIL_BLOCKS),
        ("LOG_TRUNCATION_MIN_SPAN", LOG_TRUNCATION_MIN_SPAN),
    ] {
        assert_eq!(constants[key].as_u64(), Some(value), "{key}");
    }
}

/// The JSON of an optional value, `null` for none.
fn or_null(text: Option<String>) -> String {
    text.unwrap_or_else(|| "null".to_owned())
}

#[test]
fn blockscout_mappers() {
    let vectors = vectors();
    let blockscout = &vectors["blockscout"];
    let constants = &blockscout["constants"];
    assert_eq!(constants["log_index_token"], LOG_INDEX_TOKEN);
    assert_eq!(constants["erc20_transfer_topic"], ERC20_TRANSFER_TOPIC);
    assert_eq!(
        constants["log_index_chains"],
        serde_json::json!([LOG_INDEX_CHAIN_ID])
    );
    assert_eq!(
        constants["max_pages"].as_u64(),
        Some(BLOCKSCOUT_MAX_PAGES as u64)
    );
    assert_eq!(
        constants["max_response_bytes"].as_u64(),
        Some(MAX_PAGE_SIZE as u64)
    );
    for (key, value) in [
        ("rate_limit_cooldown_ms", RATE_LIMIT_COOLDOWN_MS),
        ("min_cooldown_ms", MIN_COOLDOWN_MS),
        ("max_cooldown_ms", MAX_COOLDOWN_MS),
    ] {
        assert_eq!(constants[key].as_f64(), Some(value), "{key}");
    }
    for (key, value) in [
        ("tail_blocks", LOG_INDEX_TAIL_BLOCKS),
        (
            "disagreement_cooldown_ms",
            LOG_INDEX_DISAGREEMENT_COOLDOWN_MS,
        ),
        ("abort_cooldown_ms", LOG_INDEX_ABORT_COOLDOWN_MS),
        (
            "pair_malformed_cooldown_ms",
            LOG_INDEX_PAIR_MALFORMED_COOLDOWN_MS,
        ),
    ] {
        assert_eq!(constants[key].as_u64(), Some(value), "{key}");
    }
    for case in blockscout["filters"].as_array().unwrap() {
        let filter = log_index_filter(case["chain_id"].as_u64().unwrap(), str_of(case, "params"));
        assert_eq!(
            filter.map(|f| f.to_json()).as_deref(),
            opt_str(&case["js"], "filter_json"),
            "{}",
            id(case)
        );
    }
    for case in blockscout["logs"].as_array().unwrap() {
        let index = Index::new(str_of(case, "entry_json")).unwrap();
        let entry = index.root();
        let js = &case["js"];
        let name = id(case);
        assert_eq!(
            or_null(canonical_log(entry).map(|l| l.to_json())),
            str_of(js, "canonical_json"),
            "{name}"
        );
        assert_eq!(
            rpc_transfer_log_well_formed(entry),
            js["well_formed"] == true,
            "{name}"
        );
        assert_eq!(
            or_null(rpc_transfer(entry).map(|t| t.to_json())),
            str_of(js, "transfer_json"),
            "{name}"
        );
    }
    for case in blockscout["items"].as_array().unwrap() {
        let index = Index::new(str_of(case, "item_json")).unwrap();
        assert_eq!(
            or_null(blockscout_transfer(index.root()).map(|t| t.to_json())),
            str_of(&case["js"], "transfer_json"),
            "{}",
            id(case)
        );
    }
    let pairs = blockscout["pairs"].as_array().unwrap();
    for case in pairs {
        let name = id(case);
        let items = Index::new(str_of(case, "items_json")).unwrap();
        let indexed: Vec<_> = items
            .root()
            .children()
            .map(|item| blockscout_transfer(item).unwrap())
            .collect();
        let rpc = Index::new(str_of(case, "rpc_json")).unwrap();
        let agree = logs_agree(&indexed, rpc.root());
        assert_eq!(agree, case["js"]["agree"] == true, "{name}");
        if agree {
            assert_eq!(
                agreed_rpc_logs(rpc.root()).as_deref(),
                opt_str(&case["js"], "agreed_json"),
                "{name}"
            );
        }
    }
    assert!(pairs.iter().filter(|p| p["js"]["agree"] == true).count() >= 4);
    for case in blockscout["cooldowns"].as_array().unwrap() {
        assert_eq!(
            cooldown_from(
                opt_str(case, "x_ratelimit_reset"),
                opt_str(case, "retry_after")
            ),
            case["js"]["cool_ms"].as_f64().unwrap(),
            "{case}"
        );
    }
}

fn page_body(page: &Json) -> Vec<u8> {
    if let Some(repeat) = page.get("body_repeat") {
        let unit = str_of(repeat, "unit").repeat(repeat["count"].as_u64().unwrap() as usize);
        return format!(
            "{}{unit}{}",
            str_of(repeat, "prefix"),
            str_of(repeat, "suffix")
        )
        .into_bytes();
    }
    hex::decode(str_of(page, "body_hex")).unwrap()
}

/// A filter recorded as the reference's JSON.
fn filter_of(json: &str) -> LogIndexFilter {
    let filter: Json = serde_json::from_str(json).unwrap();
    let topic = |key: &str| filter[key].as_str().map(str::to_owned);
    let party = match (topic("sender"), topic("recipient")) {
        (Some(sender), Some(recipient)) => Party::Both { sender, recipient },
        (Some(sender), None) => Party::Sender(sender),
        (None, Some(recipient)) => Party::Recipient(recipient),
        (None, None) => panic!("{json}"),
    };
    let built = LogIndexFilter {
        chain_id: filter["chainId"].as_u64().unwrap(),
        party,
        from_block: filter["fromBlock"].as_u64().unwrap(),
        to_block: filter["toBlock"].as_u64().unwrap(),
    };
    assert_eq!(built.to_json(), json);
    built
}

#[test]
fn blockscout_scans() {
    let vectors = vectors();
    let blockscout = &vectors["blockscout"];
    let base = str_of(&blockscout["constants"], "log_index_url");
    let scans = blockscout["scans"].as_array().unwrap();
    let mut deviations = 0;
    for case in scans {
        let name = id(case);
        let byte_cap = match deviation(case) {
            None => false,
            Some("blockscout-page-bytes") => {
                deviations += 1;
                true
            }
            Some(other) => panic!("unknown deviation {other}"),
        };
        let filter = match opt_str(case, "params") {
            Some(params) => log_index_filter(LOG_INDEX_CHAIN_ID, params).unwrap(),
            None => filter_of(str_of(case, "filter_json")),
        };
        let js = &case["js"];
        let expect_error = |error: &BlockscoutError| {
            assert_eq!(error.message, str_of(&js["error"], "message"), "{name}");
            assert_eq!(
                Some(error.cool_ms),
                js["error"]["cool_ms"].as_f64(),
                "{name}"
            );
        };
        let mut scan = match TransferScan::new(filter, case["to_block"].as_u64().unwrap()) {
            Ok(scan) => scan,
            Err(error) => {
                assert!(case["pages"].as_array().unwrap().is_empty(), "{name}");
                expect_error(&error);
                continue;
            }
        };
        let pages = case["pages"].as_array().unwrap();
        for (i, page) in pages.iter().enumerate() {
            assert_eq!(
                format!("{base}{}", scan.query()),
                str_of(page, "url"),
                "{name} {i}"
            );
            let reply = PageReply {
                status: u16::try_from(page["status"].as_u64().unwrap()).unwrap(),
                content_length: opt_str(page, "content_length"),
                x_ratelimit_reset: opt_str(page, "x_ratelimit_reset"),
                retry_after: opt_str(page, "retry_after"),
                body: page_body(page),
            };
            let last = i + 1 == pages.len();
            if byte_cap {
                // Under the reference's UTF-16 cap, over the core's bytes:
                // whatever the reference made of it, the core refuses it.
                match scan.on_page(reply) {
                    Err(error) => assert_eq!(error.message, "answer over 8 MiB", "{name}"),
                    other => panic!("{name}: {other:?}"),
                }
                continue;
            }
            match scan.on_page(reply) {
                Ok(ScanStep::Next) => assert!(!last, "{name}: more pages expected"),
                Ok(ScanStep::Done(transfers)) => {
                    assert!(last, "{name}: done early");
                    assert_eq!(
                        transfers_json(&transfers),
                        str_of(js, "transfers_json"),
                        "{name}"
                    );
                }
                Err(error) => {
                    assert!(last, "{name}: failed early: {error}");
                    expect_error(&error);
                }
            }
        }
    }
    assert!(scans.len() > 40 && deviations == 2, "{deviations}");
}

#[test]
fn broadcast_refusals() {
    let vectors = vectors();
    let refusals = &vectors["broadcast_refusals"];
    assert_eq!(refusals["deviation"], "broadcast-outcome");
    let hash = TxHash::from_hex(str_of(refusals, "hash")).unwrap();
    assert_eq!(transaction_hash(str_of(refusals, "raw")), Ok(hash));
    let class_of = |design: &Json| match str_of(design, "class") {
        "accepted" => AttemptClass::Accepted,
        "ambiguous" => AttemptClass::Ambiguous,
        "refused" => {
            let reason = str_of(design, "reason");
            let all = [
                RefusalReason::InsufficientFunds,
                RefusalReason::NonceTooLow,
                RefusalReason::ReplacementUnderpriced,
                RefusalReason::Underpriced,
                RefusalReason::IntrinsicGasTooLow,
                RefusalReason::ExceedsBlockGasLimit,
                RefusalReason::FeeCapBelowBaseFee,
                RefusalReason::TipAboveFeeCap,
                RefusalReason::InvalidSender,
                RefusalReason::InvalidChainId,
                RefusalReason::OversizedData,
                RefusalReason::TransactionTypeNotSupported,
            ];
            AttemptClass::Refused(*all.iter().find(|r| r.as_str() == reason).unwrap())
        }
        other => panic!("{other}"),
    };
    let mut refused = std::collections::HashSet::new();
    for key in ["errors", "attempts"] {
        for case in refusals[key].as_array().unwrap() {
            let status = u16::try_from(case["status"].as_u64().unwrap()).unwrap();
            let answer = decode_answer(status, str_of(case, "body").as_bytes().to_vec());
            // The classifier reads the error the router builds today.
            if let (Ok(decoded), Some(error)) = (&answer, case["js"].get("error"))
                && let Outcome::NodeError(node) = decoded.outcome()
            {
                assert_eq!(
                    node.message.to_json(),
                    str_of(error, "message_json"),
                    "{case}"
                );
            }
            let class = classify_broadcast_answer(&hash, &answer);
            assert_eq!(class, class_of(&case["design"]), "{case}");
            if let AttemptClass::Refused(reason) = class {
                refused.insert(reason);
            }
        }
    }
    // Every reason has a client's wording.
    assert_eq!(refused.len(), 12);
}
