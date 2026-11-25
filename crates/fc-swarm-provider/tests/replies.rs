//! The node's JSON replies (design 0015, "JSON replies"), the tests that
//! section gives SWM-3 for the readers built here:
//!
//! - **the `/stamps` reader:** replies at each cap and one past it (the
//!   reply's 1 MiB, its 4,096 batches); a 1 MiB dense array of `0,` under
//!   an unknown key; 4,096 minimal batches; one batch whose label is the
//!   whole reply; nesting at 64 and 65; a key repeated through the whole
//!   reply; each with what the reader keeps measured against its charge
//!   (`2m + E × 256 B`);
//! - **the error-body transcoder:** bodies that are dense arrays, deep
//!   objects, repeated keys and lone surrogates, against
//!   `JSON.stringify(JSON.parse(text))` (fc-json's, which `vectors/` holds
//!   to V8's);
//! - **replies past the vectors' shapes** against the reference's own
//!   answers: `tests/data/stamps-reference.json`, which
//!   `tests/data/stamps-reference.js` records from the swarm reference's
//!   bee-js 13.2.0 (`JSON.parse`, zod's schema, `mapPostageBatch`).
//!
//! SWM-4's memory gate (eight such replies at once, resident memory within
//! the charges) is the swarm thread's.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_json::index::{Index, Kind, Value};
use fc_json::{JsString, JsValue, number_to_string};
use fc_swarm_provider::ReplyError;
use fc_swarm_provider::errors::{self, Parsed, Site, transcode};
use fc_swarm_provider::json::{MAX_NESTING, ReadError};
use fc_swarm_provider::stamps::{
    ELEMENT_BYTES, STAMPS_BATCH_CAP, STAMPS_REPLY_CAP, SelectOptions, Stamps, read_stamps,
    select_best_batch,
};

const M: usize = STAMPS_REPLY_CAP;

/// What the typed reader may keep for a `/stamps` reply at its cap.
const CHARGE: usize = 2 * M + STAMPS_BATCH_CAP * ELEMENT_BYTES;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn string(v: Value<'_, '_>) -> String {
    assert_eq!(v.kind(), Kind::String, "{}", v.raw());
    char::decode_utf16(v.units())
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

const BATCH: &str = r#""batchID":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","utilization":0,"usable":true,"depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"batchTTL":864000"#;

/// A reply of `prefix`, `fill` repeated, then `suffix`, exactly `len`
/// bytes long (`fill` one byte).
fn sized(prefix: &str, fill: char, suffix: &str, len: usize) -> Vec<u8> {
    let n = len - prefix.len() - suffix.len();
    let mut out = String::with_capacity(len);
    out.push_str(prefix);
    out.extend(std::iter::repeat_n(fill, n));
    out.push_str(suffix);
    assert_eq!(out.len(), len);
    out.into_bytes()
}

fn kept_within_charge(stamps: &Stamps, reply_len: usize) {
    let kept = stamps.kept_bytes();
    assert!(kept <= CHARGE, "kept {kept} past the charge {CHARGE}");
    // Tighter: the strings never pass the reply's own length.
    let batches = stamps.batches().count();
    assert!(
        kept <= reply_len + batches * ELEMENT_BYTES + stamps.issues().heap_bytes(),
        "kept {kept}"
    );
}

#[test]
fn reference_answers() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/stamps-reference.json");
    let text = std::fs::read_to_string(path).unwrap();
    let index = Index::new(&text).unwrap();
    let mut n = 0;
    for (k, case) in index.root().members() {
        let id = string(k);
        n += 1;
        let reply = hex(&string(case.get("reply").unwrap()));
        let stamps = read_stamps(&reply).unwrap_or_else(|e| panic!("{id}: {e}"));
        let all = stamps.get_all();
        match (case.get("mapped"), case.get("error")) {
            (Some(want), None) => {
                let all = all.unwrap_or_else(|e| panic!("{id}: {e:?}"));
                let wants: Vec<_> = want.children().collect();
                assert_eq!(all.len(), wants.len(), "{id}");
                for (b, w) in all.iter().zip(wants) {
                    let s = |key: &str| string(w.get(key).unwrap());
                    let mut label = String::new();
                    b.label.quote_into(&mut label);
                    assert_eq!(b.batch_id.to_hex(), s("batchID"), "{id}");
                    assert_eq!(label, s("label"), "{id}");
                    assert_eq!(b.amount, s("amount"), "{id}");
                    assert_eq!(number_to_string(b.usage), s("usage"), "{id}");
                    assert_eq!(b.usage_text, s("usageText"), "{id}");
                    assert_eq!(number_to_string(b.size), s("size"), "{id}");
                    assert_eq!(
                        number_to_string(b.remaining_size),
                        s("remainingSize"),
                        "{id}"
                    );
                    assert_eq!(
                        number_to_string(b.theoretical_size),
                        s("theoreticalSize"),
                        "{id}"
                    );
                    assert_eq!(b.duration, w.get("duration").unwrap().number(), "{id}");
                }
            }
            (None, Some(want)) => {
                let err = all.err().unwrap_or_else(|| panic!("{id}: no error"));
                assert_eq!(err.name.as_str(), string(want.get("name").unwrap()), "{id}");
                assert_eq!(
                    err.message.units().collect::<Vec<_>>(),
                    want.get("message").unwrap().units().collect::<Vec<_>>(),
                    "{id}"
                );
            }
            _ => panic!("{id}"),
        }
    }
    assert_eq!(n, 27);
}

#[test]
fn a_reply_at_the_cap_and_one_past() {
    let at = sized("{\"stamps\":[]", ' ', "}", M);
    let stamps = read_stamps(&at).unwrap();
    assert!(stamps.get_all().unwrap().is_empty());
    kept_within_charge(&stamps, at.len());
    let past = sized("{\"stamps\":[]", ' ', "}", M + 1);
    assert_eq!(read_stamps(&past).err(), Some(ReplyError::TooLarge));
}

#[test]
fn one_batch_whose_label_is_the_whole_reply() {
    let prefix = format!("{{\"stamps\":[{{{BATCH},\"label\":\"");
    let reply = sized(&prefix, 'l', "\"}]}", M);
    let stamps = read_stamps(&reply).unwrap();
    kept_within_charge(&stamps, reply.len());
    let label_len = M - prefix.len() - 4;
    let all = stamps.get_all().unwrap();
    assert_eq!(all[0].label.utf16_len(), label_len);
    let selection = select_best_batch(&stamps, 4096, SelectOptions::default()).unwrap();
    assert_eq!(
        selection.outcome.unwrap().unwrap().to_hex(),
        "a1".repeat(32)
    );
    // methods' publish-data-stamps-reply-past-cap: a byte more is too large.
    let past = sized(&prefix, 'l', "\"}]}", M + 1);
    assert_eq!(read_stamps(&past).err(), Some(ReplyError::TooLarge));
}

#[test]
fn a_dense_array_under_an_unknown_key() {
    // `[0,0,…,0]`: half a million values, none kept.
    let prefix = "{\"x\":[0";
    let suffix = "],\"stamps\":[]}";
    let n = (M - prefix.len() - suffix.len()) / 2;
    let mut text = String::from(prefix);
    text.push_str(&",0".repeat(n));
    text.push_str(suffix);
    let text = sized(&text[..text.len() - suffix.len()], ' ', suffix, M);
    let stamps = read_stamps(&text).unwrap();
    assert!(stamps.get_all().unwrap().is_empty());
    assert_eq!(stamps.kept_bytes(), 0);
    // A whole reply of them is no object: zod's one issue.
    let array = sized("[0", ',', "]", 3);
    let refused = read_stamps(&array).unwrap();
    assert_eq!(refused.issues().len(), 1);
}

fn minimal_batch(i: usize) -> String {
    format!(
        "{{\"batchID\":\"{i:064x}\",\"utilization\":0,\"usable\":true,\"label\":\"\",\"depth\":0,\"amount\":\"0\",\"bucketDepth\":0,\"blockNumber\":0,\"immutableFlag\":true,\"batchTTL\":0}}"
    )
}

fn list(items: impl Iterator<Item = String>) -> Vec<u8> {
    let items: Vec<String> = items.collect();
    format!("{{\"stamps\":[{}]}}", items.join(",")).into_bytes()
}

#[test]
fn minimal_batches_to_the_cap() {
    let reply = list((0..STAMPS_BATCH_CAP).map(minimal_batch));
    assert!(reply.len() <= M);
    let stamps = read_stamps(&reply).unwrap();
    let all = stamps.get_all().unwrap();
    assert_eq!(all.len(), STAMPS_BATCH_CAP);
    assert_eq!(all[4095].batch_id.to_hex(), format!("{:064x}", 4095));
    kept_within_charge(&stamps, reply.len());
    // Depth 0 holds nothing: no batch has room.
    let selection = select_best_batch(&stamps, 1, SelectOptions::default()).unwrap();
    assert_eq!(selection.outcome, Ok(None));

    let past = list((0..=STAMPS_BATCH_CAP).map(minimal_batch));
    assert!(past.len() <= M);
    assert_eq!(read_stamps(&past).err(), Some(ReplyError::TooLarge));
}

#[test]
fn empty_batches_and_the_refusals_text() {
    // Ten issues each: a hundred empty batches' text fits the cap.
    let reply = list((0..100).map(|_| "{}".to_owned()));
    let stamps = read_stamps(&reply).unwrap();
    assert_eq!(stamps.issues().len(), 1000);
    let err = stamps.get_all().unwrap_err();
    assert!(err.message.len() <= M);
    assert!(
        err.message
            .starts_with("[\n  {\n    \"expected\": \"string\"")
    );
    kept_within_charge(&stamps, reply.len());
    // 4,096 of them would make a text of some 8 MiB: too large.
    let reply = list((0..STAMPS_BATCH_CAP).map(|_| "{}".to_owned()));
    assert_eq!(read_stamps(&reply).err(), Some(ReplyError::TooLarge));
}

#[test]
fn nesting_at_64_and_65() {
    let nested = |levels: usize| format!("{}{}", "[".repeat(levels), "]".repeat(levels));
    // The root object is one level: an unknown key's value takes the rest.
    let at = format!("{{\"x\":{},\"stamps\":[]}}", nested(MAX_NESTING - 1));
    assert!(read_stamps(at.as_bytes()).is_ok());
    let past = format!("{{\"x\":{},\"stamps\":[]}}", nested(MAX_NESTING));
    assert_eq!(
        read_stamps(past.as_bytes()).err(),
        Some(ReplyError::TooDeep)
    );
    // Inside a batch: root, the array and the batch are three.
    let at = format!(
        "{{\"stamps\":[{{{BATCH},\"label\":\"\",\"u\":{}}}]}}",
        nested(MAX_NESTING - 3)
    );
    assert_eq!(
        read_stamps(at.as_bytes()).unwrap().get_all().unwrap().len(),
        1
    );
    let past = format!(
        "{{\"stamps\":[{{{BATCH},\"label\":\"\",\"u\":{}}}]}}",
        nested(MAX_NESTING - 2)
    );
    assert_eq!(
        read_stamps(past.as_bytes()).err(),
        Some(ReplyError::TooDeep)
    );
}

#[test]
fn a_key_repeated_through_the_reply() {
    // A label written over and over: the last is kept, the rest given back.
    let mut text = format!("{{\"stamps\":[{{{BATCH}");
    while text.len() < M - 64 {
        text.push_str(",\"label\":\"xxxxxxxxxxxxxxxx\"");
    }
    text.push_str(",\"label\":\"last\"}]}");
    let stamps = read_stamps(text.as_bytes()).unwrap();
    assert_eq!(stamps.get_all().unwrap()[0].label, "last");
    assert!(
        stamps.kept_bytes() < 2 * ELEMENT_BYTES,
        "{}",
        stamps.kept_bytes()
    );
    // `stamps` itself, over and over: the last array is the one.
    let mut text = String::from("{");
    while text.len() < M - 1024 {
        text.push_str(&format!("\"stamps\":[{}],", minimal_batch(1)));
    }
    text.push_str(&format!("\"stamps\":[{{{BATCH},\"label\":\"end\"}}]}}"));
    let stamps = read_stamps(text.as_bytes()).unwrap();
    let all = stamps.get_all().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].label, "end");
    kept_within_charge(&stamps, text.len());
}

#[test]
fn replies_that_arent_json() {
    for bad in [
        &b"  "[..],
        b"{\"stamps\":[]",
        b"{\"stamps\":[]}x",
        b"\xEF\xBB\xBF\xEF\xBB\xBF{}",
    ] {
        assert!(
            matches!(read_stamps(bad), Err(ReplyError::Syntax(_))),
            "{bad:?}"
        );
    }
}

/// `JSON.stringify(JSON.parse(text))`, by fc-json.
fn reference(text: &str) -> Result<Parsed, ()> {
    match fc_json::parse(text) {
        Ok(JsValue::String(ref s)) => Ok(Parsed::String(s.clone())),
        Ok(value) => Ok(Parsed::Json {
            text: value.stringify(),
            message: match value.get("message") {
                Some(JsValue::String(s)) => Some(s.clone()),
                _ => None,
            },
        }),
        Err(_) => Err(()),
    }
}

fn same_as_reference(text: &str) {
    let ours = transcode(text.as_bytes());
    match (ours, reference(text)) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "{text:.200}"),
        (Err(ReadError::Syntax(_)), Err(())) => {}
        (a, b) => panic!("{text:.200}: {a:?} against {b:?}"),
    }
}

#[test]
fn error_bodies_against_stringify_of_parse() {
    let cap = errors::ERROR_BODY_CAP;
    // Dense arrays.
    let zeros = format!("[0{}]", ",0".repeat(cap / 2 - 2));
    assert!(zeros.len() <= cap);
    same_as_reference(&zeros);
    let big = format!("[1e20{}]", ",1e20".repeat(cap / 5 - 2));
    same_as_reference(&big);
    // Deep objects, to the nesting bound and one past.
    let deep = |n: usize| format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n));
    same_as_reference(&deep(MAX_NESTING));
    assert_eq!(
        transcode(deep(MAX_NESTING + 1).as_bytes()),
        Err(ReadError::TooDeep)
    );
    assert_eq!(
        errors::http_error(
            Site::BeeJs,
            500,
            "Internal Server Error",
            deep(MAX_NESTING + 1).as_bytes()
        ),
        Err(ReadError::TooDeep)
    );
    // Repeated keys, and keys that are array indices, in any order.
    let mut repeated = String::from("{");
    for i in 0..600 {
        repeated.push_str(&format!(
            "\"{}\":{i},",
            ["k", "1", "b", "0", "01", "4294967294"][i % 6]
        ));
    }
    repeated.push_str("\"message\":\"read chunk failed\"}");
    assert!(repeated.len() <= cap);
    same_as_reference(&repeated);
    // Lone surrogates, in keys and values.
    same_as_reference(r#"{"m":"\ud800","\udc00":"x\udfff","p":"😀","message":"\udbff"}"#);
    same_as_reference(r#""\ud800""#);
    // Through bee-js's site: `<status text>: <stringify>`.
    let err = errors::http_error(
        Site::BeeJs,
        500,
        "Internal Server Error",
        repeated.as_bytes(),
    )
    .unwrap();
    let Ok(Parsed::Json { text, .. }) = reference(&repeated) else {
        panic!()
    };
    assert_eq!(
        err.message,
        JsString::from(format!("Internal Server Error: {text}"))
    );
    assert!(err.is_chunk_not_found());
}

/// A small deterministic generator of JSON-like texts, some broken.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[(self.next() as usize) % items.len()]
    }

    fn value(&mut self, depth: usize, out: &mut String) {
        let choice = if depth > 6 {
            self.next() % 4
        } else {
            self.next() % 7
        };
        match choice {
            0 => out.push_str(self.pick(&[
                "0",
                "-0",
                "1e400",
                "12345678901234567890",
                "0.1",
                "-1.5e-7",
                "1E21",
                "5e-324",
            ])),
            1 => out.push_str(self.pick(&["true", "false", "null"])),
            2 => out.push_str(self.pick(&[
                r#""""#,
                r#""a""#,
                r#""\ud800""#,
                r#""é\n\t\"""#,
                "\"\u{e9}\u{1F600}\"",
                r#""\udc00\ud800""#,
            ])),
            3 => out.push_str(self.pick(&[r#""message""#, r#""read chunk failed""#])),
            4 | 5 => {
                out.push('{');
                for i in 0..self.next() % 4 {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(self.pick(&[
                        r#""a""#,
                        r#""1""#,
                        r#""0""#,
                        r#""message""#,
                        r#""01""#,
                        r#""a""#,
                    ]));
                    out.push(':');
                    self.value(depth + 1, out);
                }
                out.push('}');
            }
            _ => {
                out.push('[');
                for i in 0..self.next() % 4 {
                    if i > 0 {
                        out.push(',');
                    }
                    self.value(depth + 1, out);
                }
                out.push(']');
            }
        }
    }
}

#[test]
fn transcoding_agrees_with_parse_and_stringify() {
    let mut rng = Lcg(0x5eed);
    for _ in 0..20_000 {
        let mut text = String::new();
        if rng.next().is_multiple_of(4) {
            text.push_str(rng.pick(&[" ", "\n", "\t "]));
        }
        rng.value(0, &mut text);
        // Now and then, break it.
        match rng.next() % 10 {
            0 if !text.is_empty() => {
                let at = (rng.next() as usize) % text.len();
                if text.is_char_boundary(at) {
                    text.insert_str(at, rng.pick(&[",", "]", "}", ":", "\"", "x", " "]));
                }
            }
            1 => text.push_str(rng.pick(&[" ", ",", "x"])),
            _ => {}
        }
        same_as_reference(&text);
    }
}
