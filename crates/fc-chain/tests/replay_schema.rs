//! Checks `vectors/chain-replay.json`, the pinned chain-data router run in
//! scripted worlds (design 0005, step 2): its schema, its encodings and its
//! scenario IDs, which the design cites. Replaying the scenarios through the
//! machine is step 3.
//!
//! The file's frame is plain JSON, read with serde_json. Every value the
//! reference produced or was given is JSON text in a string field, read
//! with fc-json's index, which keeps strings as UTF-16 (lone surrogates
//! included) and nesting up to 512 levels, as the core does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use fc_json::index::{Index, IndexError, Kind};
use serde_json::{Map, Value as Json};
use sha2::{Digest as _, Sha256};

/// Every scenario, in file order. The IDs are stable: the design cites them.
const SCENARIO_IDS: &[&str] = &[
    "router-myotis-balance",
    "router-myotis-account-unverified",
    "router-myotis-account-absent",
    "router-myotis-code",
    "router-myotis-code-not-served",
    "router-myotis-storage",
    "router-myotis-tagged-state-reads",
    "router-myotis-revert-final",
    "router-myotis-unavailable-shapes",
    "router-myotis-broadcast-rejected",
    "router-myotis-broadcast-in-band-failure",
    "router-pending-nonce-to-colibri",
    "router-historical-balance-to-colibri",
    "router-tagged-estimate-to-colibri",
    "router-historical-call-to-colibri",
    "router-state-overrides-to-colibri",
    "router-myotis-whole-transaction",
    "router-myotis-invalid-params-call",
    "router-myotis-invalid-params-estimate",
    "router-myotis-invalid-params-account",
    "router-myotis-capability-refusals",
    "router-myotis-blob-transaction",
    "router-myotis-infeasible",
    "router-myotis-head-state-call",
    "router-myotis-trust",
    "router-myotis-trust-head-moved",
    "router-myotis-no-payload-to-colibri",
    "router-colibri-deadline",
    "router-myotis-broadcast-uncertain",
    "router-myotis-broadcast",
    "router-fee-quote-myotis",
    "router-fee-quote-inconsistent",
    "router-fee-quote-direct-same-endpoint",
    "router-filter-on-direct",
    "router-quorum-hex-quantities",
    "router-direct-hex-quantities",
    "router-myotis-estimate-hex",
    "router-myotis-chain-id-type-numbers",
    "router-myotis-chain-id-type-decimal-strings",
    "router-myotis-chain-id-type-zero-padded-hex",
    "router-myotis-legacy-type-zero",
    "router-myotis-gas-refused",
    "router-myotis-input-alias-call",
    "router-myotis-input-alias-estimate",
    "router-input-alias-rpc",
    "router-myotis-input-over-empty-data",
    "router-myotis-data-input-conflict",
    "router-broadcast-direct-when-myotis-not-ready",
    "router-final-rpc-error-kept",
    "router-custom-chain-default-order",
    "router-colibri-interactive-bypass",
    "router-excluded-source",
    "router-getlogs-never-colibri",
    "router-exclusion-named-no-source",
    "router-exclusion-named-all-failed",
    "router-myotis-interactive-bypass",
    "router-myotis-noncancellable-no-starvation",
    "router-myotis-late-read-keeps-slot",
    "router-myotis-serialized",
    "router-myotis-terminal-concurrent",
    "router-myotis-queue-full",
    "router-myotis-status-throw-releases-slot",
    "router-colibri-cooldown-escalation",
    "router-colibri-capacity-demotion",
    "router-colibri-route-limit",
    "router-quorum-settles-at-m",
    "router-quorum-carries-past-deadline",
    "router-quorum-no-extension-before-colibri",
    "router-quorum-wallet-read-stays-verified",
    "router-quorum-last-source",
    "router-colibri-last-source",
    "router-myotis-last-source",
    "router-quorum-member-reused-as-direct",
    "router-quorum-partial-without-direct",
    "cancel-read-no-fallthrough",
    "cancel-broadcast-no-fallthrough",
    "cancel-background-never-queues",
    "cancel-direct-timeout-widened-never-narrowed",
    "cancel-quorum-timeout-widened-never-narrowed",
    "cancel-range-not-learned-without-cap-reader",
    "cancel-quorum-reverts-aggregate",
    "cancel-range-limit-not-kept-without-rank",
    "cancel-broadcast-later-timeout-wins",
    "cancel-broadcast-no-second-rpc",
    "cancel-filter-names-sources",
    "truncation-earlier-logs-fail-at-once",
    "truncation-empty-earlier-window-accepted",
    "truncation-failed-check-accepted",
    "truncation-direct-check-one-attempt",
    "truncation-direct-check-asks-answering-endpoint",
    "truncation-direct-check-reused-member",
    "truncation-unchecked-shapes",
    "truncation-quorum-agreed-checked-through-quorum",
    "ant-scan-quorum-only",
    "ant-scan-colibri-never-asked",
    "ant-scan-one-answer-does-not-settle",
    "ant-scan-no-quorum-reply",
    "ant-scan-members-3of3-range",
    "ant-scan-members-3of3-timeout-reply",
    "ant-scan-members-3of3-endpoint",
    "ant-scan-members-3of3-hang",
    "ant-scan-members-3of3-success",
    "ant-scan-members-2of3-range",
    "ant-scan-members-2of3-timeout-reply",
    "ant-scan-members-2of3-endpoint",
    "ant-scan-members-2of3-hang",
    "ant-scan-members-2of3-success",
    "ant-scan-members-1of3-range",
    "ant-scan-members-1of3-timeout-reply",
    "ant-scan-members-1of3-endpoint",
    "ant-scan-members-1of3-hang",
    "ant-scan-members-1of3-success",
    "ant-scan-range-after-endpoint-ends-quorum",
    "ant-scan-endpoint-after-range-kept",
    "ant-scan-timeouts-after-range-kept",
    "ant-scan-timeout-replaces-endpoint-error",
    "ant-scan-answer-does-not-outvote-ranges",
    "ant-scan-two-answers-beat-failure",
    "ant-scan-r1-f1-upstream-wording",
    "ant-scan-r4-f1-hung-member-range-final",
    "ant-scan-r6-f1-range-survives-429",
    "ant-scan-r6-f1-range-survives-endpoint",
    "ant-scan-r6-f1-range-survives-down",
    "ant-scan-throttle-two-agree",
    "ant-scan-limit-exceeded-two-agree",
    "ant-scan-reth-lag-two-agree",
    "ant-scan-erigon-lag-two-agree",
    "ant-scan-all-throttled",
    "ant-scan-r2-f2-all-limit-exceeded",
    "ant-scan-r2-f2-all-log-cap",
    "ant-scan-r3-f1-log-cap-then-down",
    "ant-scan-r3-f1-down-then-log-cap",
    "ant-scan-r3-f1-log-cap-then-429",
    "ant-scan-r3-f1-429-then-log-cap",
    "ant-scan-r3-f1-log-cap-then-throttle",
    "ant-scan-r3-f1-throttle-then-log-cap",
    "ant-scan-r3-f1-limit-exceeded-then-down",
    "ant-scan-r3-f1-down-then-limit-exceeded",
    "ant-scan-r3-f1-limit-exceeded-then-429",
    "ant-scan-r3-f1-429-then-limit-exceeded",
    "ant-scan-r3-f1-ranges-over-then-down",
    "ant-scan-r3-f1-down-then-ranges-over",
    "ant-scan-r3-f1-cap-loses-to-timeout",
    "ant-scan-r3-f1-cap-loses-to-answers",
    "ant-scan-r3-f1-lag-not-kept",
    "ant-scan-caps-full-history-one-answer",
    "ant-scan-caps-capped-endpoint-left-out",
    "ant-scan-caps-fourth-endpoint-joins",
    "ant-scan-caps-two-down-second-round",
    "ant-scan-caps-widest-servable-span",
    "ant-scan-caps-shrink-to-capped-windows",
    "ant-scan-caps-full-history-endpoint-fails-later",
    "ant-scan-caps-hung-endpoint-cools-down",
    "ant-scan-caps-expire",
    "ant-scan-caps-upstream-timeout-brief",
    "ant-scan-caps-timed-out-span-holds",
    "ant-scan-caps-result-count-not-learned",
    "ant-scan-caps-all-down",
    "ant-scan-truncation-halves-until-complete",
    "ant-scan-truncation-narrow-window-checked",
    "ant-scan-truncation-check-timeout-reply-leaves-no-cooldown",
    "ant-scan-truncation-check-hang-leaves-no-cooldown",
    "ant-scan-truncation-sparse-recent-accepted",
    "ant-index-first-wallet-scan",
    "ant-index-blockscout-down-window-by-window",
    "ant-index-pairs-leading-part",
    "ant-index-only-compared-fields",
    "ant-index-blockscout-down-falls-back",
    "ant-index-blockscout-429-falls-back",
    "ant-index-blockscout-missing-old-log-falls-back",
    "ant-index-429-named-reset",
    "ant-index-blockscout-hung",
    "ant-index-slow-multipage-budget",
    "ant-index-late-blockscout-tail-budget",
    "ant-index-tail-rounds-share-budget",
    "ant-index-blockscout-slower-than-budget",
    "ant-index-caller-abort-cools-blockscout",
    "ant-index-hung-pair-rpc",
    "ant-index-lagging-blockscout-agrees",
    "ant-index-truncated-rpc-never-accepted",
    "ant-index-malformed-pair-entry-no-block-hash",
    "ant-index-malformed-pair-entry-short-block-hash",
    "ant-index-malformed-pair-entry-two-word-value",
    "ant-index-malformed-pair-entry-recipient-not-address",
    "ant-index-malformed-pair-entry-sender-not-address",
    "ant-index-malformed-pair-entry-removed",
    "ant-index-tail-quorum-malformed",
    "ant-index-capped-blockscout-page-disagrees",
    "ant-index-no-full-history-pair",
    "ant-index-pair-rpc-fails-blockscout-not-cooled",
    "ant-index-two-full-history-quorum",
    "ant-index-routine-tail-quorum",
    "ant-index-page-without-include-never-blockscout",
    "ant-index-other-filters-never-blockscout",
    "ant-index-order-without-quorum",
    "bridge-router-range-limit-forwarded",
    "bridge-router-slow-members-agree",
    "bridge-router-single-answer-no-settle",
    "bridge-router-fourth-joins",
    "bridge-router-endpoint-error-two-agree",
    "blockscout-recipient-scan",
    "blockscout-sender-and-recipient-scan",
    "blockscout-pages-until-from-block",
    "blockscout-empty-page-not-last",
    "blockscout-over-40-pages",
    "blockscout-transfer-after-to-block",
    "blockscout-transfer-other-sender",
    "blockscout-transfer-other-token",
    "blockscout-transfer-malformed",
    "blockscout-transfers-out-of-order",
    "blockscout-same-transfer-twice",
    "blockscout-page-repeats-last-transfer",
    "blockscout-429-cooldown-bounds",
    "blockscout-http-500",
    "blockscout-not-json",
    "blockscout-refusal",
    "blockscout-items-not-a-list",
    "blockscout-no-next-page-params",
    "blockscout-throttle-in-body",
    "blockscout-redirect-off-https",
    "blockscout-redirect-without-location",
    "blockscout-transport-failure",
    "blockscout-redirect-followed",
    "blockscout-redirect-loop",
    "blockscout-redirect-local-host-loopback",
    "blockscout-redirect-local-host-mapped-private",
    "blockscout-redirect-local-host-localhost-name",
    "blockscout-redirect-dns-local",
    "blockscout-redirect-dns-fails",
    "blockscout-redirect-same-origin",
    "blockscout-dns-hang",
    "boundary-html-8mib-through-quorum",
    "boundary-direct-lower-index-answered-later",
    "boundary-quorum-agrees-without-result",
    "boundary-quorum-undefined-null-disagree",
    "boundary-truncation-quorum-probe-fails",
    "boundary-truncation-quorum-probe-empty",
    "boundary-truncation-with-direct-left",
    "boundary-quorum-reverts-direct-untried",
    "boundary-quorum-reverts-colibri-revert-survives",
    "boundary-quorum-reverts-one-answer",
    "boundary-fee-myotis-priority-equals-gas-price",
    "boundary-fee-myotis-priority-zero",
    "boundary-fee-myotis-priority-over-gas-price",
    "boundary-fee-myotis-priority-negative",
    "boundary-fee-myotis-no-priority",
    "boundary-fee-myotis-non-positive-gas-price",
    "boundary-fee-quorum-priority-disagrees",
    "boundary-fee-direct-priority-unparseable",
    "boundary-fee-direct-gas-price-fails-first",
    "boundary-fee-all-sources-unavailable",
    "boundary-broadcast-resends-until-accepted",
    "boundary-broadcast-last-error-wins",
    "boundary-broadcast-lost-reply-then-already-known",
    "boundary-broadcast-lost-reply-then-nonce-too-low",
    "boundary-broadcast-refusal-after-ambiguous",
    "boundary-broadcast-mined-bytes-nonce-too-low",
    "boundary-broadcast-other-hash-accepted",
    "boundary-broadcast-cancel-after-send",
    "boundary-broadcast-myotis-uncertain-in-band",
    "boundary-broadcast-myotis-odd-payload",
    "boundary-broadcast-myotis-not-sent-then-direct",
    "boundary-broadcast-myotis-not-running-last-error",
    "boundary-broadcast-unknown-broadcaster",
    "boundary-adaptive-quorum-deadline-not-a-timeout",
    "boundary-adaptive-capacity-survives-success",
    "boundary-adaptive-route-target-case",
    "boundary-adaptive-capacity-whitespace",
    "boundary-adaptive-capacity-past-500-units",
    "boundary-adaptive-capacity-hex-elided",
    "boundary-adaptive-capacity-failure-kind",
    "boundary-origin-not-interactive",
    "boundary-myotis-waiter-abandons-at-deadline",
    "boundary-myotis-budget-covers-wait",
    "boundary-myotis-unsupported-method-holds-slot",
    "boundary-myotis-not-running-last-error",
    "boundary-myotis-state-changed-last-error",
    "boundary-myotis-queue-full-last-error",
    "boundary-myotis-queue-deadline-last-error",
    "boundary-myotis-caller-deadline-last-error",
    "boundary-myotis-unexpected-response-last-error",
    "boundary-myotis-readiness-sampled-live",
    "boundary-colibri-global-limit",
    "boundary-colibri-errors-fall-through",
    "boundary-colibri-revert-last-error",
    "boundary-registry-change-mid-request",
    "boundary-order-duplicates-and-unknown",
    "boundary-quorum-clamps",
    "boundary-direct-user-configured-trust",
    "boundary-unparseable-endpoint-host",
    "boundary-colibri-trust",
    "boundary-result-literal-undefined-tag",
    "boundary-result-literal-repeat-tag",
    "boundary-result-empty-body",
    "boundary-json-depth-512",
    "boundary-json-depth-513",
    "boundary-agreement-duplicate-keys",
    "boundary-agreement-number-spellings",
    "boundary-agreement-proto-key",
    "boundary-agreement-lone-surrogates",
    "boundary-unsupported-requests",
];

const CALLS: &[&str] = &["request", "getFeeQuote", "broadcastRawTransaction"];
const KINDS: &[&str] = &[
    "rpc",
    "verified-op",
    "myotis-status",
    "blockscout-read",
    "blockscout-page",
    "blockscout",
    "dns",
    "event",
];
const OUTCOMES: &[&str] = &["answered", "failed", "aborted", "refused", "open", "fired"];
const DEVIATIONS: &[&str] = &["json-depth"];

fn vectors() -> Json {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/chain-replay.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn scenario<'a>(vectors: &'a Json, id: &str) -> &'a Json {
    array(&vectors["scenarios"], "scenarios")
        .iter()
        .find(|scenario| scenario["id"] == id)
        .unwrap_or_else(|| panic!("no scenario {id}"))
}

fn object<'a>(value: &'a Json, what: &str) -> &'a Map<String, Json> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("{what} is not an object"))
}

fn array<'a>(value: &'a Json, what: &str) -> &'a [Json] {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{what} is not an array"))
}

fn text<'a>(value: &'a Json, what: &str) -> &'a str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{what} is not a string"))
}

fn time(value: &Json, what: &str) -> u64 {
    value
        .as_u64()
        .unwrap_or_else(|| panic!("{what} is not a virtual time"))
}

fn kebab(id: &str) -> bool {
    !id.is_empty()
        && id.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// A repeat form's text, checked against its length and SHA-256.
fn expand(repeat: &Json, at: &str) -> String {
    let head = text(&repeat["head"], at);
    let unit = text(&repeat["unit"], at);
    let tail = text(&repeat["tail"], at);
    let count = usize::try_from(time(&repeat["count"], at)).unwrap();
    assert!(!unit.is_empty() && count > 0, "{at}: an empty repeat");
    let expanded = format!("{head}{}{tail}", unit.repeat(count));
    let length = expanded.encode_utf16().count() as u64;
    assert_eq!(length, time(&repeat["length"], at), "{at}: repeat length");
    assert_eq!(
        hex::encode(Sha256::digest(expanded.as_bytes())),
        text(&repeat["sha256"], at),
        "{at}: repeat digest"
    );
    expanded
}

/// Reads every value text under `value` (`json`, `*_json` and their repeat
/// forms) with fc-json, checks every other repeat form, and refuses keys
/// that look like encodings. Returns each value text by where it is.
fn values(value: &Json, at: &str, found: &mut BTreeMap<String, String>) {
    match value {
        Json::Object(map) => {
            for (key, item) in map {
                let here = format!("{at}.{key}");
                assert!(
                    !key.starts_with('$'),
                    "{here}: a key that looks like an encoding"
                );
                if key == "json" || key.ends_with("_json") {
                    let source = text(item, &here);
                    Index::new(source).unwrap_or_else(|err| panic!("{here}: {err}"));
                    found.insert(here, source.to_owned());
                } else if key == "json_repeat" || key.ends_with("_json_repeat") {
                    let source = expand(item, &here);
                    Index::new(&source).unwrap_or_else(|err| panic!("{here}: {err}"));
                    found.insert(here, source);
                } else if key.ends_with("_repeat") && key != "result_repeat" {
                    expand(item, &here);
                } else if key == "undefined" || key.ends_with("_undefined") {
                    assert_eq!(item, &Json::Bool(true), "{here}");
                } else {
                    values(item, &here, found);
                }
            }
        }
        Json::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                values(item, &format!("{at}[{index}]"), found);
            }
        }
        _ => {}
    }
}

/// An entry of an object the router returned or threw.
fn check_entry(entry: &Json, at: &str) {
    let entry = object(entry, at);
    text(&entry["key"], at);
    let shapes = ["json", "json_repeat", "undefined"]
        .iter()
        .filter(|key| entry.contains_key(**key))
        .count();
    assert_eq!(entry.len(), 2, "{at}: an entry is a key and one value");
    assert_eq!(shapes, 1, "{at}: one of json, json_repeat or undefined");
}

fn check_error(thrown: &Json, at: &str) {
    text(&thrown["class"], at);
    text(&thrown["name"], at);
    let message = text(&thrown["message_json"], at);
    assert_eq!(
        Index::new(message).unwrap().root().kind(),
        Kind::String,
        "{at}: message"
    );
    for entry in array(&thrown["props"], at) {
        check_entry(entry, at);
    }
}

#[test]
fn scenario_ids_are_stable() {
    let vectors = vectors();
    let ids: Vec<&str> = array(&vectors["scenarios"], "scenarios")
        .iter()
        .map(|scenario| text(&scenario["id"], "id"))
        .collect();
    assert_eq!(ids, SCENARIO_IDS);
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "an ID is used twice");
    for id in ids {
        assert!(kebab(id), "{id} is not kebab-case");
    }
}

#[test]
fn meta_and_encodings() {
    let vectors = vectors();
    assert_eq!(
        vectors["meta"]["freedomBrowserCommit"],
        "fb540328162839e68150fe2c5e517edb86734d1c"
    );
    assert!(vectors["meta"]["packages"]["@sinonjs/fake-timers"].is_string());
    let encodings = object(&vectors["encodings"], "encodings");
    for key in [
        "json",
        "undefined",
        "entries",
        "repeat",
        "plain",
        "times",
        "rpc_body",
        "expect_settle_ms",
    ] {
        assert!(encodings.contains_key(key), "encodings.{key}");
    }
}

#[test]
fn scenarios_follow_the_schema() {
    let vectors = vectors();
    for scenario in array(&vectors["scenarios"], "scenarios") {
        let id = text(&scenario["id"], "id");
        assert!(!text(&scenario["from"], id).is_empty(), "{id}: from");
        if let Some(deviation) = scenario.get("deviation") {
            assert!(DEVIATIONS.contains(&text(deviation, id)), "{id}: deviation");
        }
        object(&scenario["world"], id);
        let steps = array(&scenario["steps"], id);
        assert!(!steps.is_empty(), "{id}: no steps");
        let mut previous = 0;
        for (index, step) in steps.iter().enumerate() {
            let at = format!("{id} step {index}");
            let start = time(&step["at"], &at);
            assert!(start >= previous, "{at}: steps go back in time");
            object(&step["state"], &at);
            let calls = array(&step["calls"], &at);
            let results = array(&step["results"], &at);
            assert!(!calls.is_empty(), "{at}: no calls");
            assert_eq!(calls.len(), results.len(), "{at}: a result per call");
            for (call, result) in calls.iter().zip(results) {
                assert!(CALLS.contains(&text(&call["fn"], &at)), "{at}: fn");
                assert!(call["chain"].is_u64(), "{at}: chain");
                if call["fn"] == "request" {
                    text(&call["method"], &at);
                    assert!(call.get("params").is_none(), "{at}: params as a value");
                }
                let started = time(&call["started"], &at);
                assert!(started >= start, "{at}: a call before its step");
                let result = object(result, &at);
                let shapes = ["value", "value_json", "thrown", "pending"]
                    .iter()
                    .filter(|key| result.contains_key(**key))
                    .count();
                assert_eq!(
                    shapes, 1,
                    "{at}: one of value, value_json, thrown or pending"
                );
                if let Some(value) = result.get("value") {
                    for entry in array(value, &at) {
                        check_entry(entry, &at);
                    }
                }
                if let Some(thrown) = result.get("thrown") {
                    check_error(thrown, &at);
                }
                if !result.contains_key("pending") {
                    let took = time(&result["settled"], &at) - started;
                    if let Some(expected) = call.get("expect_settle_ms") {
                        assert_eq!(took, time(expected, &at), "{at}: settle time");
                    }
                    if let Some(bound) = call.get("expect_settle_max_ms") {
                        assert!(took <= time(bound, &at), "{at}: settle bound");
                    }
                }
                previous = previous.max(started);
            }
            previous = previous.max(start);
        }
        let io = array(&scenario["io"], id);
        let mut kinds = BTreeMap::new();
        for (index, entry) in io.iter().enumerate() {
            let at = format!("{id} io {index}");
            assert_eq!(time(&entry["id"], &at), index as u64, "{at}: id");
            let kind = text(&entry["kind"], &at);
            assert!(KINDS.contains(&kind), "{at}: kind {kind}");
            kinds.insert(index, kind);
            let step = usize::try_from(time(&entry["step"], &at)).unwrap();
            assert!(step < steps.len(), "{at}: step");
            if kind != "event" {
                let call = usize::try_from(time(&entry["call"], &at)).unwrap();
                assert!(call < array(&steps[step]["calls"], &at).len(), "{at}: call");
            }
            let start = time(&entry["t"], &at);
            let outcome = text(&entry["outcome"], &at);
            assert!(OUTCOMES.contains(&outcome), "{at}: outcome {outcome}");
            if outcome == "open" {
                assert!(entry["end"].is_null(), "{at}: an open request ended");
            } else {
                assert!(
                    time(&entry["end"], &at) >= start,
                    "{at}: ended before it started"
                );
            }
            if let Some(within) = entry.get("within") {
                let owner = usize::try_from(time(within, &at)).unwrap();
                let expected = if kind == "blockscout-page" {
                    "blockscout-read"
                } else {
                    "blockscout-page"
                };
                assert_eq!(kinds.get(&owner), Some(&expected), "{at}: within");
            }
            if let Some(thrown) = entry.get("answer").and_then(|answer| answer.get("thrown")) {
                check_error(thrown, &at);
            }
            match kind {
                "rpc" => {
                    let method = text(&entry["method"], &at);
                    let prefix = format!("{{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"{method}\"");
                    assert!(text(&entry["body"], &at).starts_with(&prefix), "{at}: body");
                    if outcome == "answered" {
                        assert!(entry["answer"]["status"].is_u64(), "{at}: status");
                    }
                }
                "verified-op" => {
                    let host = text(&entry["host"], &at);
                    assert!(host == "myotis" || host == "colibri", "{at}: host");
                    text(&entry["params_json"], &at);
                }
                "blockscout" | "blockscout-page" | "dns" => {
                    assert!(entry.get("within").is_some(), "{at}: within nothing");
                }
                _ => {}
            }
        }
    }
}

#[test]
fn every_value_reads_back() {
    let vectors = vectors();
    let mut found = BTreeMap::new();
    values(&vectors["scenarios"], ".scenarios", &mut found);
    assert!(found.len() > 1000, "only {} value texts", found.len());
}

/// The text of the `result` entry of a step's first call.
fn result_text(scenario: &Json, step: usize) -> String {
    let entry = array(&scenario["steps"][step]["results"][0]["value"], "value")
        .iter()
        .find(|entry| entry["key"] == "result")
        .unwrap();
    match entry.get("json") {
        Some(json) => text(json, "result").to_owned(),
        None => expand(&entry["json_repeat"], "result"),
    }
}

#[test]
fn boundaries_read_as_the_reference_made_them() {
    let vectors = vectors();
    // An html() document at its 8 MiB limit: 16,777,346 hex characters, and
    // a minimal JSON-RPC answer of 16,777,382 bytes (design 0005, Transport).
    let html = scenario(&vectors, "boundary-html-8mib-through-quorum");
    let result = result_text(html, 0);
    let index = Index::new(&result).unwrap();
    assert_eq!(index.root().units().count(), 16_777_346);
    let body = &html["io"][0]["answer"]["body_repeat"];
    assert_eq!(time(&body["length"], "body"), 16_777_382);
    // Nesting: a body of 512 levels is read; one of 513 is refused (deviation
    // json-depth), though the reference read it and agreed on it.
    for (id, refused) in [
        ("boundary-json-depth-512", false),
        ("boundary-json-depth-513", true),
    ] {
        let scenario = scenario(&vectors, id);
        assert_eq!(scenario.get("deviation").is_some(), refused, "{id}");
        for entry in array(&scenario["io"], id) {
            let body = text(&entry["answer"]["body"], id);
            match Index::new(body) {
                Ok(_) => assert!(!refused, "{id}: read a body over 512 levels"),
                Err(IndexError::TooDeep) => assert!(refused, "{id}: refused 512 levels"),
                Err(err) => panic!("{id}: {err}"),
            }
        }
        assert!(
            Index::new(&result_text(scenario, 0)).is_ok(),
            "{id}: its result"
        );
    }
    // Agreed values keep what JSON.parse made: a lone surrogate, -0, an
    // infinity, and an own __proto__ property.
    let surrogate = result_text(scenario(&vectors, "boundary-agreement-lone-surrogates"), 0);
    let index = Index::new(&surrogate).unwrap();
    assert_eq!(index.root().units().collect::<Vec<u16>>(), [0xD800]);
    let numbers = scenario(&vectors, "boundary-agreement-number-spellings");
    let zero = result_text(numbers, 2);
    let zero = Index::new(&zero).unwrap().root().number();
    assert!(zero == 0.0 && zero.is_sign_negative(), "-0");
    let infinite = result_text(numbers, 5);
    assert!(Index::new(&infinite).unwrap().root().number().is_infinite());
    let proto = result_text(scenario(&vectors, "boundary-agreement-proto-key"), 0);
    assert!(
        Index::new(&proto)
            .unwrap()
            .root()
            .get("__proto__")
            .is_some()
    );
    // A missing result is its own field, and literal tags are values.
    let empty = scenario(&vectors, "boundary-result-empty-body");
    let first = &array(&empty["steps"][0]["results"][0]["value"], "value")[0];
    assert_eq!(first["key"], "result");
    assert_eq!(first["undefined"], Json::Bool(true));
    let tag = scenario(&vectors, "boundary-result-literal-undefined-tag");
    assert_eq!(result_text(tag, 0), r#"{"$undefined":true}"#);
}
