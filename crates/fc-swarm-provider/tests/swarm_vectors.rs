//! fc-swarm-provider against vectors/swarm.json (design 0015, SWM-1): every
//! `stamps` case (`mapped`, `select`) and every `errors` case
//! (`http_error`, `mapping`), as SWM-3's done-when asks of batch choice and
//! node errors. The `methods` and `stores` sections are the later parts'
//! (the method machines and the stores' codecs).
//!
//! The `mapping` cases name method cases. Each is played as far as this
//! part reaches: its `/stamps` answer through `read_stamps` and
//! `select_best_batch` (the batch an upload carries, or the page's error
//! through `node_write_error`), then the node error that ends it through
//! its site and `node_write_error` or `map_chunk_read_error`. What only
//! the method machines decide (an upload's answer, a reference check, a
//! transport failure's text, the verified `readData` walk) is listed by
//! name in [`REST`] as `Machines`, with why.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use base64::Engine;
use fc_json::JsString;
use fc_json::index::{Index, KeyOrder, Kind, Value};
use fc_swarm_provider::errors::{
    self, ChunkRead, ERROR_BODY_CAP, ErrorBody, NodeError, PageError, ServiceError, Site,
};
use fc_swarm_provider::stamps::{
    Capacity, JsError, PostageError, SelectOptions, read_stamps, select_best_batch,
};
use fc_swarm_provider::{ReplyError, json};
use sha2::{Digest, Sha256};

fn vectors_text() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/swarm.json");
    std::fs::read_to_string(path).unwrap()
}

/// content(seed, n): SHA-256(seed ‖ u64_be(i)), concatenated and cut.
fn content(seed: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut i = 0u64;
    while out.len() < n {
        let mut h = Sha256::new();
        h.update(seed.as_bytes());
        h.update(i.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        i += 1;
    }
    out.truncate(n);
    out
}

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn b64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .unwrap()
}

fn get<'i, 't>(v: Value<'i, 't>, key: &str) -> Value<'i, 't> {
    v.get(key)
        .unwrap_or_else(|| panic!("no {key:?} in {}", &v.raw()[..v.raw().len().min(200)]))
}

fn string(v: Value<'_, '_>) -> String {
    assert_eq!(v.kind(), Kind::String, "{}", v.raw());
    char::decode_utf16(v.units())
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

fn units(v: Value<'_, '_>) -> Vec<u16> {
    assert_eq!(v.kind(), Kind::String, "{}", v.raw());
    v.units().collect()
}

fn js_units(s: &JsString) -> Vec<u16> {
    s.units().collect()
}

fn boolean(v: Value<'_, '_>) -> bool {
    match v.kind() {
        Kind::True => true,
        Kind::False => false,
        _ => panic!("not a boolean: {}", v.raw()),
    }
}

fn keys<'t>(v: Value<'_, 't>) -> Vec<String> {
    v.members().map(|(k, _)| string(k)).collect()
}

/// An error as the vectors record it, from the crate's answers.
#[derive(Debug, Default)]
struct Got {
    name: String,
    message: JsString,
    status: Option<u16>,
    status_text: Option<String>,
    body: Option<ErrorBody>,
    reason: Option<String>,
    code: Option<String>,
    capacity: Option<Capacity>,
}

impl Got {
    fn node(err: &NodeError) -> Self {
        Self {
            name: err.name.as_str().to_owned(),
            message: err.message.clone(),
            status: err.status,
            status_text: err.status_text.clone(),
            body: err.body.clone(),
            ..Self::default()
        }
    }

    fn js(err: &JsError) -> Self {
        Self {
            name: err.name.as_str().to_owned(),
            message: err.message.clone(),
            ..Self::default()
        }
    }

    fn postage(err: &PostageError) -> Self {
        Self {
            name: "Error".to_owned(),
            message: JsString::from(err.code.message()),
            code: Some(err.code.code().to_owned()),
            capacity: Some(err.capacity),
            ..Self::default()
        }
    }

    fn service(err: &ServiceError) -> Self {
        Self {
            name: "Error".to_owned(),
            message: err.message.clone(),
            reason: err.reason.map(str::to_owned),
            code: err.code.map(str::to_owned),
            ..Self::default()
        }
    }
}

/// A typed answer (`formats.typed`) as `JSON.stringify` writes the value.
fn typed_json(v: Value<'_, '_>) -> String {
    let (tag, value) = v.members().next().unwrap();
    match string(tag).as_str() {
        "object" => {
            let members: Vec<String> = value
                .children()
                .map(|pair| {
                    let mut it = pair.children();
                    let (k, val) = (it.next().unwrap(), it.next().unwrap());
                    let mut out = String::new();
                    JsString::from_units(&units(k)).quote_into(&mut out);
                    format!("{out}:{}", typed_json(val))
                })
                .collect();
            format!("{{{}}}", members.join(","))
        }
        "array" => {
            let items: Vec<String> = value.children().map(typed_json).collect();
            format!("[{}]", items.join(","))
        }
        "string" => {
            let mut out = String::new();
            JsString::from_units(&units(value)).quote_into(&mut out);
            out
        }
        // A string with a lone surrogate, as its JSON text: JSON.stringify's.
        "string_json" => string(value),
        "number" => string(value),
        "null" => "null".to_owned(),
        "boolean" => value.raw().to_owned(),
        other => panic!("no JSON text for the typed form {other:?}"),
    }
}

fn check_body(id: &str, key: &str, want: Value<'_, '_>, got: Option<&ErrorBody>) {
    let got = got.unwrap_or_else(|| panic!("{id}: no responseBody"));
    if key == "responseBody" {
        match (want.kind(), got) {
            (Kind::String, ErrorBody::String(s)) => assert_eq!(js_units(s), units(want), "{id}"),
            (_, ErrorBody::Json { text, .. }) => {
                assert_eq!(*text, want.stringify(KeyOrder::Property), "{id}")
            }
            _ => panic!("{id}: responseBody {} against {got:?}", want.raw()),
        }
        return;
    }
    let (tag, value) = want.members().next().unwrap();
    match (string(tag).as_str(), got) {
        ("undefined", ErrorBody::Undefined) => {}
        ("string_digest", ErrorBody::String(s)) => {
            assert_eq!(s.utf16_len() as f64, value.number(), "{id}");
            assert_eq!(sha(s.as_bytes()), string(get(want, "sha256")), "{id}");
        }
        ("string_json", ErrorBody::String(s)) => {
            let parsed = fc_json::parse(&string(value)).unwrap();
            assert_eq!(Some(s), parsed.as_js_string(), "{id}");
        }
        (_, ErrorBody::Json { text, .. }) => assert_eq!(*text, typed_json(want), "{id}"),
        (tag, _) => panic!("{id}: responseBody_typed {tag} against {got:?}"),
    }
}

/// Every member of `want` against `got`, and nothing `got` has that `want`
/// lacks.
fn check_error(id: &str, want: Value<'_, '_>, got: &Got) {
    let mut seen = Vec::new();
    for (k, v) in want.members() {
        let key = string(k);
        match key.as_str() {
            "name" => assert_eq!(got.name, string(v), "{id}: name"),
            "message" => assert_eq!(js_units(&got.message), units(v), "{id}: message"),
            "message_digest" => {
                assert_eq!(
                    got.message.utf16_len() as f64,
                    get(v, "units").number(),
                    "{id}"
                );
                assert_eq!(
                    sha(got.message.as_bytes()),
                    string(get(v, "sha256")),
                    "{id}"
                );
            }
            "status" => assert_eq!(got.status.map(f64::from), Some(v.number()), "{id}: status"),
            "statusText" => assert_eq!(got.status_text.as_deref(), Some(&*string(v)), "{id}"),
            "responseBody" | "responseBody_typed" => check_body(id, &key, v, got.body.as_ref()),
            "reason" => assert_eq!(got.reason.as_deref(), Some(&*string(v)), "{id}: reason"),
            "code" => assert_eq!(got.code.as_deref(), Some(&*string(v)), "{id}: code"),
            "capacity" => {
                let c = got.capacity.unwrap_or_else(|| panic!("{id}: no capacity"));
                assert_eq!(c.upload_bytes, get(v, "uploadBytes").number(), "{id}");
                assert_eq!(c.required_bytes, get(v, "requiredBytes").number(), "{id}");
                assert_eq!(
                    c.largest_remaining_bytes,
                    get(v, "largestRemainingBytes").number(),
                    "{id}"
                );
                assert_eq!(keys(v).len(), 3, "{id}: capacity");
            }
            other => panic!("{id}: the record's {other:?} isn't checked"),
        }
        seen.push(key);
    }
    let has = |k: &str| seen.iter().any(|s| s == k);
    assert_eq!(got.status.is_some(), has("status"), "{id}: status");
    assert_eq!(
        got.status_text.is_some(),
        has("statusText"),
        "{id}: statusText"
    );
    assert_eq!(
        got.body.is_some(),
        has("responseBody") || has("responseBody_typed"),
        "{id}: responseBody"
    );
    assert_eq!(got.reason.is_some(), has("reason"), "{id}: reason");
    assert_eq!(got.code.is_some(), has("code"), "{id}: code");
    assert_eq!(got.capacity.is_some(), has("capacity"), "{id}: capacity");
}

fn options(v: Value<'_, '_>) -> SelectOptions {
    let mut o = SelectOptions::default();
    for (k, val) in v.members() {
        match string(k).as_str() {
            "requireCapacity" => o.require_capacity = boolean(val),
            "allowFullMutable" => o.allow_full_mutable = boolean(val),
            other => panic!("option {other:?}"),
        }
    }
    o
}

#[test]
fn stamps_mapped() {
    let text = vectors_text();
    let index = Index::new(&text).unwrap();
    let cases: Vec<_> = get(get(index.root(), "stamps"), "mapped")
        .children()
        .collect();
    assert_eq!(cases.len(), 23);
    for case in cases {
        let id = string(get(case, "id"));
        // batch-depth: a fractional depth the reference maps, which the
        // core refuses; its classification is still the reference's.
        let refused = case.get("deviation").map(string);
        assert!(
            refused.is_none() || refused.as_deref() == Some("batch-depth"),
            "{id}: a deviation to handle"
        );
        let reply = format!("{{\"stamps\":[{}]}}", get(case, "raw").raw());
        let stamps = read_stamps(reply.as_bytes()).unwrap();
        let raw = stamps.batches().next().unwrap();
        let classified = get(case, "classified");
        assert_eq!(raw.is_usable(), boolean(get(classified, "usable")), "{id}");
        assert_eq!(
            raw.is_pending(),
            boolean(get(classified, "pending")),
            "{id}"
        );
        assert_eq!(
            raw.is_propagating(),
            boolean(get(classified, "propagating")),
            "{id}"
        );
        assert_eq!(
            raw.is_full_immutable(),
            boolean(get(classified, "full_immutable")),
            "{id}"
        );
        assert_eq!(
            js_units(&raw.batch_id_key().unwrap()),
            units(get(classified, "key")),
            "{id}"
        );
        assert_eq!(keys(classified).len(), 5, "{id}");

        if refused.is_some() {
            let err = stamps.get_all().unwrap_err();
            check_error(&id, get(get(case, "core"), "error"), &Got::js(&err));
            continue;
        }
        match (case.get("mapped"), case.get("error")) {
            (Some(want), None) => {
                let all = stamps.get_all().unwrap();
                let [b] = all.as_slice() else {
                    panic!("{id}: one batch")
                };
                let n = |key: &str| get(want, key).number();
                assert_eq!(b.batch_id.to_hex(), string(get(want, "batchID")), "{id}");
                assert_eq!(b.utilization, n("utilization"), "{id}");
                assert_eq!(b.usable, boolean(get(want, "usable")), "{id}");
                assert_eq!(js_units(&b.label), units(get(want, "label")), "{id}");
                assert_eq!(b.depth, n("depth"), "{id}");
                assert_eq!(b.amount, string(get(want, "amount")), "{id}");
                assert_eq!(b.bucket_depth, n("bucketDepth"), "{id}");
                assert_eq!(b.block_number, n("blockNumber"), "{id}");
                assert_eq!(
                    b.immutable_flag,
                    boolean(get(want, "immutableFlag")),
                    "{id}"
                );
                assert_eq!(b.usage, n("usage"), "{id}");
                assert_eq!(b.usage_text, string(get(want, "usageText")), "{id}");
                assert_eq!(b.size, n("size"), "{id}");
                assert_eq!(b.remaining_size, n("remainingSize"), "{id}");
                assert_eq!(b.theoretical_size, n("theoreticalSize"), "{id}");
                assert_eq!(b.duration, n("duration"), "{id}");
                assert_eq!(keys(want).len(), 15, "{id}: every mapped field checked");
            }
            (None, Some(want)) => {
                let err = stamps.get_all().unwrap_err();
                check_error(&id, want, &Got::js(&err));
            }
            _ => panic!("{id}: mapped or error"),
        }
    }
}

#[test]
fn stamps_select() {
    let text = vectors_text();
    let index = Index::new(&text).unwrap();
    let cases: Vec<_> = get(get(index.root(), "stamps"), "select")
        .children()
        .collect();
    assert_eq!(cases.len(), 44);
    for case in cases {
        let id = string(get(case, "id"));
        // Where the reference reads /stamps twice it is marked
        // stamps-one-read, with the core's one read as `core`; the batch or
        // error is the same, and is checked below.
        if get(case, "stamps_reads").number() > 1.0 {
            assert!(get(case, "deviation").is_str("stamps-one-read"), "{id}");
            assert_eq!(get(get(case, "core"), "stamps_reads").number(), 1.0, "{id}");
        } else {
            assert!(
                case.get("deviation").is_none(),
                "{id}: a deviation to handle"
            );
        }
        let stamps = read_stamps(get(case, "stamps").raw().as_bytes()).unwrap();
        let size = get(case, "size").number();
        let opts = options(get(case, "options"));
        let reference_reads = get(case, "stamps_reads").number();
        match select_best_batch(&stamps, size as u64, opts) {
            Err(err) => {
                // What stamp.getAll throws ends the call at the first read.
                assert_eq!(reference_reads, 1.0, "{id}");
                check_error(&id, get(case, "error"), &Got::js(&err));
            }
            Ok(selection) => {
                // The reference reads again for the propagating pass; the
                // core reads once (stamps-one-read).
                let reads = 1.0 + f64::from(u8::from(selection.propagating_pass));
                assert_eq!(
                    reads, reference_reads,
                    "{id}: the reference's /stamps reads"
                );
                match selection.outcome {
                    Ok(batch) => {
                        let want = get(case, "result");
                        match batch {
                            Some(b) => assert_eq!(b.to_hex(), string(want), "{id}"),
                            None => assert_eq!(want.kind(), Kind::Null, "{id}"),
                        }
                        assert!(case.get("error").is_none(), "{id}");
                    }
                    Err(err) => {
                        assert!(case.get("result").is_none(), "{id}");
                        check_error(&id, get(case, "error"), &Got::postage(&err));
                    }
                }
            }
        }
    }
}

fn site(name: &str) -> Site {
    match name {
        "bee-js-json" | "bee-js-arraybuffer" | "bee-js-bytes" => Site::BeeJs,
        "fetch-node" => Site::FetchNode,
        "soc-upload" => Site::SocUpload,
        "page-upload" => Site::PageUpload,
        other => panic!("site {other:?}"),
    }
}

fn body_bytes(body: Value<'_, '_>) -> Vec<u8> {
    let bytes = match (body.get("base64"), body.get("data")) {
        (Some(b), _) => b64(&string(b)),
        (None, Some(data)) => content(
            &string(get(data, "seed")),
            get(data, "length").number() as usize,
        ),
        _ => panic!("a body: {}", body.raw()),
    };
    assert_eq!(bytes.len() as f64, get(body, "length").number());
    if let Some(digest) = body.get("sha256") {
        assert_eq!(sha(&bytes), string(digest));
    }
    bytes
}

/// Every `errors` entry is one of the kinds the tests below play, so a new
/// or misspelt kind fails here instead of being skipped by both.
#[test]
fn errors_are_all_played() {
    let text = vectors_text();
    let index = Index::new(&text).unwrap();
    let mut http = 0;
    let mut mapping = 0;
    for case in get(index.root(), "errors").children() {
        let kind = get(case, "kind");
        if kind.is_str("http_error") {
            http += 1;
        } else if kind.is_str("mapping") {
            mapping += 1;
        } else {
            panic!("{}: an errors kind no test plays", string(get(case, "id")));
        }
    }
    assert_eq!((http, mapping), (198, 2));
}

#[test]
fn errors_http() {
    let text = vectors_text();
    let index = Index::new(&text).unwrap();
    let cases: Vec<_> = get(index.root(), "errors")
        .children()
        .filter(|c| get(*c, "kind").is_str("http_error"))
        .collect();
    assert_eq!(cases.len(), 198);
    for case in cases {
        let id = string(get(case, "id"));
        let site = site(&string(get(case, "site")));
        let status = get(case, "status").number() as u16;
        let status_text = string(get(case, "status_text"));
        let body = body_bytes(get(case, "body"));
        let err = errors::http_error(site, status, &status_text, &body).unwrap();

        // Past 8 KiB the core reads the first 8,192 bytes (error-body-bound):
        // its answer is the case's `core`.
        let want = match case.get("deviation") {
            Some(d) => {
                assert!(d.is_str("error-body-bound"), "{id}: deviation {}", d.raw());
                assert!(body.len() > ERROR_BODY_CAP, "{id}");
                get(get(case, "core"), "error")
            }
            None => {
                assert!(body.len() <= ERROR_BODY_CAP, "{id}");
                get(case, "error")
            }
        };
        let got = if site == Site::FetchNode {
            // The site is reached through readFeedPayload, which reads a
            // 404 or 500 as an empty feed.
            match errors::feed_read_error(&err, None) {
                Some(mapped) => Got::service(&mapped),
                None => Got::node(&err),
            }
        } else {
            Got::node(&err)
        };
        check_error(&id, want, &got);
        match case.get("chunk_not_found") {
            Some(v) => {
                assert_eq!(site, Site::BeeJs, "{id}");
                assert_eq!(
                    err.is_chunk_not_found(),
                    boolean(v),
                    "{id}: isChunkNotFoundError"
                );
            }
            None => assert_ne!(site, Site::BeeJs, "{id}"),
        }
    }
}

/// How a mapping case ends past its `/stamps` read, where that doesn't end
/// it.
#[derive(Debug, Clone, Copy)]
enum Rest {
    /// The node's error answer at this site, then `node_write_error` (a
    /// write) or the read's `chunk_not_found` and `map_chunk_read_error`.
    Node(Site, Wrap),
    /// The downloaded bytes aren't the chunk asked for: the read's
    /// `chunk_type_mismatch` through `map_chunk_read_error`. (Telling that
    /// the bytes don't validate is the read machine's, over fc-swarm.)
    Mismatch(ChunkRead),
    /// The batch was chosen and the upload went (checked); the method
    /// answered its result.
    Selected,
    /// A JSON success reply that doesn't parse (deviation `reply-syntax`):
    /// the core's fixed text, the case's `core`.
    Syntax,
    /// Decided by what only the method machines do (a later part).
    Machines(&'static str),
}

#[derive(Debug, Clone, Copy)]
enum Wrap {
    Write,
    Read(ChunkRead),
}

const UPLOAD_ANSWER: &str = "the upload's answer (reference, tag) is the publish machine's";
const VERIFIED_WALK: &str =
    "read-data-verified: the core's verified readData walk is the read machine's";
const TRANSPORT: &str = "transport-error-text: a transport failure's text is the machines'";

const REST: &[(&str, Rest)] = &[
    ("write-soc-node-not-json", Rest::Syntax),
    ("publish-data-stamps-propagating", Rest::Selected),
    ("publish-data-stamps-longest-ttl", Rest::Selected),
    (
        "publish-data-node-500",
        Rest::Node(Site::PageUpload, Wrap::Write),
    ),
    (
        "publish-data-node-batch-not-yet-known",
        Rest::Node(Site::PageUpload, Wrap::Write),
    ),
    (
        "publish-data-node-text-error",
        Rest::Node(Site::PageUpload, Wrap::Write),
    ),
    (
        "publish-data-node-json-string-error",
        Rest::Node(Site::PageUpload, Wrap::Write),
    ),
    (
        "publish-data-node-empty-error",
        Rest::Node(Site::PageUpload, Wrap::Write),
    ),
    (
        "publish-data-node-redirect",
        Rest::Node(Site::PageUpload, Wrap::Write),
    ),
    (
        "publish-data-node-no-reference",
        Rest::Machines(UPLOAD_ANSWER),
    ),
    (
        "publish-data-node-upper-case-reference",
        Rest::Machines(UPLOAD_ANSWER),
    ),
    (
        "publish-data-node-encrypted-reference",
        Rest::Machines(UPLOAD_ANSWER),
    ),
    ("publish-data-node-not-json", Rest::Machines(UPLOAD_ANSWER)),
    (
        "publish-data-node-stopped-after-ready",
        Rest::Machines("the node's URL gone after the pre-flight: no node call is made"),
    ),
    (
        "publish-files-node-500",
        Rest::Node(Site::PageUpload, Wrap::Write),
    ),
    ("publish-files-node-no-tag", Rest::Machines(UPLOAD_ANSWER)),
    ("publish-files-node-bad-tag", Rest::Machines(UPLOAD_ANSWER)),
    (
        "publish-chunk-node-500",
        Rest::Node(Site::BeeJs, Wrap::Write),
    ),
    (
        "publish-chunk-node-other-reference",
        Rest::Machines("reference-check: the chunk's address against the node's"),
    ),
    (
        "write-soc-node-500",
        Rest::Node(Site::SocUpload, Wrap::Write),
    ),
    (
        "write-soc-node-error-empty",
        Rest::Node(Site::SocUpload, Wrap::Write),
    ),
    (
        "write-soc-node-error-text",
        Rest::Node(Site::SocUpload, Wrap::Write),
    ),
    (
        "write-soc-node-other-reference",
        Rest::Machines("the SOC upload's answer against the SOC's address"),
    ),
    (
        "write-soc-node-no-reference",
        Rest::Machines("the SOC upload's answer against the SOC's address"),
    ),
    (
        "write-soc-node-batch-not-yet-known",
        Rest::Node(Site::SocUpload, Wrap::Write),
    ),
    ("create-feed-node-500", Rest::Node(Site::BeeJs, Wrap::Write)),
    (
        "create-feed-node-no-reference",
        Rest::Machines("the feed manifest's answer (bee-js's Reference)"),
    ),
    (
        "update-feed-node-500",
        Rest::Node(Site::SocUpload, Wrap::Write),
    ),
    (
        "write-feed-explicit-index-500",
        Rest::Node(Site::BeeJs, Wrap::Write),
    ),
    (
        "write-feed-explicit-index-503",
        Rest::Node(Site::BeeJs, Wrap::Write),
    ),
    (
        "write-feed-explicit-index-not-the-soc",
        Rest::Machines("feedEntryExists' SOC check over fc-swarm"),
    ),
    (
        "write-feed-bytes-upload-500",
        Rest::Node(Site::BeeJs, Wrap::Write),
    ),
    (
        "write-feed-soc-500",
        Rest::Node(Site::SocUpload, Wrap::Write),
    ),
    (
        "send-pss-bad-point",
        Rest::Machines("the recipient's point, checked as the message is sent"),
    ),
    ("send-pss-full-mutable-batch", Rest::Selected),
    ("send-pss-node-400", Rest::Node(Site::BeeJs, Wrap::Write)),
    ("send-pss-node-hangs-up", Rest::Machines(TRANSPORT)),
    ("send-gsoc-full-mutable-batch", Rest::Selected),
    ("send-gsoc-node-500", Rest::Node(Site::BeeJs, Wrap::Write)),
    (
        "read-chunk-not-found",
        Rest::Node(Site::BeeJs, Wrap::Read(ChunkRead::Chunk)),
    ),
    (
        "read-chunk-500-read-chunk-failed",
        Rest::Node(Site::BeeJs, Wrap::Read(ChunkRead::Chunk)),
    ),
    (
        "read-chunk-500-other",
        Rest::Node(Site::BeeJs, Wrap::Read(ChunkRead::Chunk)),
    ),
    (
        "read-chunk-500-text",
        Rest::Node(Site::BeeJs, Wrap::Read(ChunkRead::Chunk)),
    ),
    ("read-chunk-wrong-bytes", Rest::Mismatch(ChunkRead::Chunk)),
    ("read-chunk-short-bytes", Rest::Mismatch(ChunkRead::Chunk)),
    ("read-chunk-node-hangs-up", Rest::Machines(TRANSPORT)),
    (
        "read-data-not-found",
        Rest::Node(Site::BeeJs, Wrap::Read(ChunkRead::Data)),
    ),
    (
        "read-data-root-wrong-bytes",
        Rest::Mismatch(ChunkRead::Data),
    ),
    ("read-data-bytes-not-found", Rest::Machines(VERIFIED_WALK)),
    ("read-data-bytes-500", Rest::Machines(VERIFIED_WALK)),
    ("read-data-join-short", Rest::Machines(VERIFIED_WALK)),
    ("read-data-join-wrong-bytes", Rest::Machines(VERIFIED_WALK)),
    (
        "read-soc-not-found",
        Rest::Node(Site::BeeJs, Wrap::Read(ChunkRead::SingleOwnerChunk)),
    ),
    (
        "read-soc-500-read-chunk-failed",
        Rest::Node(Site::BeeJs, Wrap::Read(ChunkRead::SingleOwnerChunk)),
    ),
    (
        "read-soc-wrong-address",
        Rest::Mismatch(ChunkRead::SingleOwnerChunk),
    ),
    (
        "read-soc-cac-not-soc",
        Rest::Mismatch(ChunkRead::SingleOwnerChunk),
    ),
];

/// The reason phrases the fake node sends (Node's `http.STATUS_CODES`).
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        402 => "Payment Required",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        other => panic!("no reason phrase for {other}"),
    }
}

/// The fake node's answer to a request: the first rule that matches, else
/// its own 404 for what it lacks.
fn node_reply(case: Value<'_, '_>, request: Value<'_, '_>) -> (u16, String, Vec<u8>) {
    let method = string(get(request, "method"));
    let path = string(get(request, "path"));
    let rules = get(case, "node").get("rules");
    let rule = rules.into_iter().flat_map(|r| r.children()).find(|rule| {
        let m = get(*rule, "match");
        m.get("method").is_none_or(|v| v.is_str(&method))
            && m.get("path").is_none_or(|v| v.is_str(&path))
            && m.get("prefix").is_none_or(|v| path.starts_with(&string(v)))
    });
    let Some(rule) = rule else {
        return (
            404,
            "Not Found".to_owned(),
            br#"{"code":404,"message":"Not Found"}"#.to_vec(),
        );
    };
    let reply = get(rule, "reply");
    for (k, _) in reply.members() {
        let key = string(k);
        assert!(
            // Headers (a redirect's location) don't reach the error.
            matches!(
                key.as_str(),
                "status" | "statusText" | "json" | "body_utf8" | "headers"
            ),
            "a reply's {key:?}"
        );
    }
    let status = get(reply, "status").number() as u16;
    let text = reply
        .get("statusText")
        .map_or_else(|| reason_phrase(status).to_owned(), string);
    let body = match (reply.get("json"), reply.get("body_utf8")) {
        (Some(json), _) => json.stringify(KeyOrder::Property).into_bytes(),
        (None, Some(utf8)) => string(utf8).into_bytes(),
        (None, None) => Vec::new(),
    };
    (status, text, body)
}

/// The typed param `key` of a step's params.
fn param<'i, 't>(params: Value<'i, 't>, key: &str) -> Option<Value<'i, 't>> {
    get(params, "object").children().find_map(|pair| {
        let mut it = pair.children();
        let (k, v) = (it.next()?, it.next()?);
        k.is_str(key).then_some(v)
    })
}

/// The length a typed data param reads as.
fn data_len(v: Value<'_, '_>) -> u64 {
    v.get("string_bytes")
        .or_else(|| v.get("bytes"))
        .map(|n| n.number() as u64)
        .unwrap()
}

/// The `selectBestBatch` call a method makes: its size and options.
fn select_call(method: &str, params: Value<'_, '_>) -> Option<(u64, SelectOptions)> {
    let content = SelectOptions {
        require_capacity: true,
        allow_full_mutable: false,
    };
    let messaging = SelectOptions {
        require_capacity: false,
        allow_full_mutable: true,
    };
    Some(match method {
        "swarm_publishData" => (data_len(param(params, "data")?), content),
        "swarm_publishFiles" => {
            let files = get(param(params, "files")?, "array").children();
            let total = files
                .map(|f| {
                    let file = Value::get(f, "object").unwrap();
                    let bytes = file
                        .children()
                        .find_map(|pair| {
                            let mut it = pair.children();
                            let (k, v) = (it.next()?, it.next()?);
                            k.is_str("bytes").then_some(v)
                        })
                        .unwrap();
                    data_len(bytes)
                })
                .sum();
            (total, content)
        }
        "swarm_publishChunk"
        | "swarm_writeSingleOwnerChunk"
        | "swarm_createFeed"
        | "swarm_updateFeed" => (4096, SelectOptions::default()),
        "swarm_writeFeedEntry" => (
            data_len(param(params, "data")?).max(4096),
            SelectOptions::default(),
        ),
        "swarm_sendPss" | "swarm_sendGsoc" => (4096, messaging),
        _ => return None,
    })
}

fn check_page(id: &str, want: Value<'_, '_>, got: &PageError) {
    assert_eq!(
        f64::from(got.code),
        get(want, "code").number(),
        "{id}: code"
    );
    assert_eq!(
        js_units(&got.message),
        units(get(want, "message")),
        "{id}: message"
    );
    match want.get("data") {
        Some(data) => {
            assert_eq!(keys(data), ["reason"], "{id}");
            assert_eq!(
                got.reason,
                Some(&*string(get(data, "reason"))),
                "{id}: reason"
            );
        }
        None => assert_eq!(got.reason, None, "{id}: reason"),
    }
    for key in keys(want) {
        assert!(
            matches!(key.as_str(), "code" | "message" | "data"),
            "{id}: {key}"
        );
    }
}

/// The `/stamps` answer a case's node gives.
fn stamps_reply(node: Value<'_, '_>) -> Vec<u8> {
    if let Some(n) = node.get("stamps_label_bytes") {
        // The usable batch, its label that many bytes of `l`.
        let label = "l".repeat(n.number() as usize);
        return format!(
            "{{\"stamps\":[{{\"batchID\":\"{}\",\"utilization\":0,\"usable\":true,\"label\":\"{label}\",\"depth\":22,\"amount\":\"100000000000\",\"bucketDepth\":16,\"blockNumber\":1000,\"immutableFlag\":true,\"exists\":true,\"batchTTL\":864000}}]}}",
            "a1".repeat(32)
        )
        .into_bytes();
    }
    get(node, "stamps").raw().as_bytes().to_vec()
}

/// What a mapping case's play reached.
#[derive(Debug, PartialEq)]
enum Played {
    /// Its `/stamps` read decided its answer, checked.
    DecidedByStamps,
    /// The rest, checked or listed; `uploaded` when a request carried the
    /// batch chosen (checked).
    Rest { uploaded: bool },
}

fn play_stamps(id: &str, case: Value<'_, '_>, step: Value<'_, '_>) -> Played {
    let requests: Vec<_> = get(step, "requests").children().collect();
    let reads: Vec<_> = requests
        .iter()
        .filter(|r| get(**r, "method").is_str("GET") && get(**r, "path").is_str("/stamps"))
        .collect();
    let Some(first) = reads.first() else {
        return Played::Rest { uploaded: false };
    };
    let method = string(get(step, "method"));
    let (size, opts) = select_call(&method, get(step, "params")).unwrap();
    let error = step.get("error");
    let deviation = case.get("deviation").map(string);

    if get(**first, "status").number() != 200.0 {
        // The node's error answer to GET /stamps, through bee-js.
        let (status, text, body) = node_reply(case, **first);
        let err = errors::http_error(Site::BeeJs, status, &text, &body).unwrap();
        let page = errors::node_write_error(&ServiceError::from(&err));
        check_page(id, error.unwrap(), &page);
        return Played::DecidedByStamps;
    }
    // A rule for GET /stamps answers before the stored batches.
    let ruled = get(case, "node")
        .get("rules")
        .into_iter()
        .flat_map(|r| r.children())
        .any(|rule| {
            get(rule, "match")
                .get("path")
                .is_some_and(|p| p.is_str("/stamps"))
        });
    let reply = if ruled {
        node_reply(case, **first).2
    } else {
        stamps_reply(get(case, "node"))
    };
    let stamps = match read_stamps(&reply) {
        Ok(stamps) => stamps,
        Err(ReplyError::Syntax(_)) => {
            // reply-syntax: the page read V8's SyntaxError text; the core's
            // answer is the case's `core`.
            assert_eq!(deviation.as_deref(), Some("reply-syntax"), "{id}");
            check_page(
                id,
                get(get(case, "core"), "error"),
                &errors::reply_not_json(),
            );
            return Played::DecidedByStamps;
        }
        Err(ReplyError::TooLarge) => {
            // reply-bounds: the reference read it whole and went on; the
            // core's answer is the case's `core`.
            assert_eq!(deviation.as_deref(), Some("reply-bounds"), "{id}");
            check_page(
                id,
                get(get(case, "core"), "error"),
                &errors::reply_too_large(),
            );
            return Played::DecidedByStamps;
        }
        Err(e) => panic!("{id}: {e}"),
    };
    let selection = match select_best_batch(&stamps, size, opts) {
        Ok(selection) => selection,
        Err(err) => {
            let page = errors::node_write_error(&ServiceError::from(&err));
            check_page(id, error.unwrap(), &page);
            return Played::DecidedByStamps;
        }
    };
    // The reference's second read (stamps-one-read) is the propagating pass.
    assert_eq!(
        reads.len(),
        1 + usize::from(selection.propagating_pass),
        "{id}"
    );
    if let Some(second) = reads.get(1) {
        assert!(get(**second, "deviation").is_str("stamps-one-read"), "{id}");
        assert_eq!(deviation.as_deref(), Some("stamps-one-read"), "{id}");
    }
    let refusal = match selection.outcome {
        Ok(Some(batch)) => {
            // Each request that carries a batch (none, when the method ends
            // before its upload) carries the one chosen.
            let carried: Vec<String> = requests
                .iter()
                .filter_map(|r| {
                    r.get("headers")?.children().find_map(|h| {
                        let mut it = h.children();
                        let (name, value) = (it.next()?, it.next()?);
                        name.is_str("swarm-postage-batch-id").then(|| string(value))
                    })
                })
                .collect();
            for header in &carried {
                assert_eq!(*header, batch.to_hex(), "{id}: the batch chosen");
            }
            return Played::Rest {
                uploaded: !carried.is_empty(),
            };
        }
        Ok(None) => ServiceError::no_usable_batch(),
        Err(err) => ServiceError::from(&err),
    };
    check_page(id, error.unwrap(), &errors::node_write_error(&refusal));
    Played::DecidedByStamps
}

#[test]
fn errors_mapping() {
    let text = vectors_text();
    let index = Index::new(&text).unwrap();
    let mappings: Vec<_> = get(index.root(), "errors")
        .children()
        .filter(|c| get(*c, "kind").is_str("mapping"))
        .collect();
    assert_eq!(mappings.len(), 2);
    let methods: Vec<_> = get(index.root(), "methods").children().collect();
    let mut used = vec![false; REST.len()];
    let mut machines = 0;
    for mapping in mappings {
        let function = string(get(mapping, "function"));
        assert!(
            matches!(function.as_str(), "nodeWriteError" | "mapChunkReadError"),
            "{function}"
        );
        for name in get(mapping, "method_cases").children() {
            let id = string(name);
            let case = *methods
                .iter()
                .find(|c| get(**c, "id").is_str(&id))
                .unwrap_or_else(|| panic!("no method case {id}"));
            let step = get(case, "steps").children().last().unwrap();
            let entry = REST.iter().position(|(rid, _)| *rid == id);
            let Played::Rest { uploaded } = play_stamps(&id, case, step) else {
                assert!(entry.is_none(), "{id}: decided by its /stamps read");
                continue;
            };
            let i = entry.unwrap_or_else(|| panic!("{id}: how does it end?"));
            used[i] = true;
            let error = step.get("error");
            match REST[i].1 {
                Rest::Selected => {
                    assert!(uploaded, "{id}: the upload carries the batch chosen");
                    assert!(error.is_none() && step.get("error_typed").is_none(), "{id}");
                }
                Rest::Machines(why) => {
                    assert!(!why.is_empty(), "{id}");
                    machines += 1;
                }
                Rest::Syntax => {
                    assert!(get(case, "deviation").is_str("reply-syntax"), "{id}");
                    check_page(
                        &id,
                        get(get(case, "core"), "error"),
                        &errors::reply_not_json(),
                    );
                }
                Rest::Mismatch(read) => {
                    let page = errors::map_chunk_read_error(&errors::chunk_type_mismatch(read));
                    check_page(&id, error.unwrap(), &page);
                }
                Rest::Node(site, wrap) => {
                    let failed = get(step, "requests")
                        .children()
                        .filter(|r| {
                            r.get("status")
                                .is_some_and(|s| !(200.0..300.0).contains(&s.number()))
                        })
                        .last()
                        .unwrap_or_else(|| panic!("{id}: no failed request"));
                    let (status, text, body) = node_reply(case, failed);
                    let err = if site == Site::PageUpload && (300..400).contains(&status) {
                        errors::page_upload_redirect(status, &text)
                    } else {
                        errors::http_error(site, status, &text, &body).unwrap()
                    };
                    let page = match wrap {
                        Wrap::Write => errors::node_write_error(&ServiceError::from(&err)),
                        Wrap::Read(read) => {
                            let params = get(step, "params");
                            let reference = param(params, "reference")
                                .or_else(|| param(params, "address"))
                                .map(|v| string(get(v, "string")))
                                .unwrap();
                            errors::map_chunk_read_error(&errors::chunk_read_error(
                                read, &reference, &err,
                            ))
                        }
                    };
                    check_page(&id, error.unwrap(), &page);
                }
            }
        }
    }
    let unused: Vec<_> = REST
        .iter()
        .zip(&used)
        .filter(|(_, u)| !**u)
        .map(|((id, _), _)| *id)
        .collect();
    assert!(
        unused.is_empty(),
        "entries no mapping case reaches: {unused:?}"
    );
    // Left to the method machines, by name above.
    assert_eq!(machines, 19);
}

/// The 8 KiB a site reads is the design's (`shell.swarm_api`), and the
/// nesting bound the readers'.
#[test]
fn bounds_are_the_designs() {
    assert_eq!(ERROR_BODY_CAP, 8 * 1024);
    assert_eq!(json::MAX_NESTING, 64);
}
