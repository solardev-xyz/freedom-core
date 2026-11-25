//! Messaging (design 0015, "Messaging and GSOC mining"), each method in
//! today's order with today's codes, reasons and texts
//! (swarm-provider-ipc.js's `handleGetMessagingIdentity`, `handleSendPss`,
//! `handleSendGsoc`, `handleSubscribe`; messaging-service.js):
//!
//! - **`getMessagingIdentity`:** the messaging grant, the reachability
//!   check, `GET /addresses` read as bee-js's `GetNodeAddressesResponse`
//!   reads it (zod's schema, core-sdk's transforms and their texts), then
//!   the node's compressed PSS key and the first two bytes of its overlay.
//!   What reveals the key's authority goes out only while the page's name
//!   still binds its key and the document is still under it (page-swarm.js,
//!   after the method's wait): the live facts asked then, custody left
//!   out.
//! - **`sendPss`:** the params, the grant, the publish readiness, the
//!   effect's guard, one `/stamps` read and the batch through
//!   `selectBestBatch` with `selectMessageBatch`'s rule (a full mutable
//!   batch allowed), the guard again after that wait, the recipient
//!   checked as a point (core-sdk's `PublicKey`), then `POST
//!   /pss/send/<t>/<x>?recipient=<66 hex>` with the page's compressed key
//!   (F-9). The node mines the trojan chunk.
//! - **`sendGsoc`:** the params, the grant, the readiness, the guard, the
//!   signer from the mining lane (the frozen identifier `keccak256(topic)`
//!   and target `keccak256("freedom-gsoc-v1:" + topic)`, proximity 12),
//!   the batch, the guard again, the SOC signed with the mined key (public
//!   by construction, nothing of the vault), and `POST /soc/<o>/<id>`
//!   through bee-js's `uploadSingleOwnerChunk`, the node's reference
//!   checked against the SOC's address (deviation `reference-check`, which
//!   bee-js doesn't make). The page gets the address, never the key.
//! - **`subscribe`:** the params, the grant, `shell.swarm_ready { check:
//!   "subscribe" }` (main's probe after question 4's proxy check:
//!   `proxy-or-tor` refuses, deviation `subscribe-proxy`), the key (the
//!   page's GSOC address, the mined one for a topic, or a PSS topic's
//!   hash), the guard, then main opens the subscription for the request's
//!   document (`shell.swarm_subscribe`, design 0015's D16) and the live
//!   facts are asked again (page-swarm.js, after the method's wait, custody
//!   left out): while the name and the document still hold the key, the
//!   page gets `{ subscriptionId, kind, key }` with main's id; otherwise
//!   main closes it (`shell.swarm_unsubscribe`) and the page gets
//!   `NO_ADDRESS`. A subscription that doesn't open answers as
//!   `subscribeError` does. A request that ends while main opens or holds
//!   its subscription closes it.
//!
//! The guard is page-swarm.js's `guardEffect` with `whileMessagingGranted`,
//! on the live facts asked just before it (design 0015's D1): the name, for
//! a send a rule approved Agent custody and the rule, the document's key,
//! then the messaging grant. The reference runs it once,
//! before the send's waits; the core runs it there too, so a refusal makes
//! the reference's calls, and again after the last wait on the node,
//! before the effect (design 0015, "Name checks"). A send a rule approved
//! has no admission check of its own at the start: custody taken or the
//! rule turned off between main's check and the hand-off reach the guard
//! after the readiness check, as in the reference
//! (`send-pss-rule-off-before-send` answers `not_auto_approved`, not
//! `no_rule`).

use fc_json::JsString;
use fc_swarm::gsoc;

use super::chunk_reads::ready;
use super::feed_write::{Data, data_of};
use super::limits::{MAX_MESSAGE_BYTES, MAX_SUBSCRIPTIONS, MAX_TARGET_DEPTH};
use super::publish::OTHER_REFERENCE_MESSAGE;
use super::writes::{Fail, batch_with, bytes_uploaded, soc_up};
use super::{live_of, no_address, permitted};
use crate::ReplyError;
use crate::chunks::hex;
use crate::errors::{self, Site, node_write_error};
use crate::js::{self, concat, to_lower};
use crate::json::{Reader, Token};
use crate::machine::node::{Failed, JSON_REPLY_CAP, transport_text};
use crate::machine::params::{empty_options, hex_string, normalize_address, require_params};
use crate::machine::{
    Approval, AskId, Body, Closing, Cx, Event, Failure, Form, Live, MineJob, Mined, NodeCall,
    OpenFailed, Outcome, ReadyCheck, Step, Subscription, SubscriptionKind, World, done, fail,
};
use crate::stamps::{BatchId, SelectOptions};
use crate::stores::manifests::Capability;
use crate::value::Value;
use crate::zod::{Expected, Issue, Issues, Received, Segment};

/// messaging-service.js's `GSOC_TARGET_CONTEXT`, frozen.
pub const GSOC_TARGET_CONTEXT: &str = "freedom-gsoc-v1:";
/// `GSOC_PROXIMITY`, bee-js's default, frozen.
pub const GSOC_PROXIMITY: u32 = 12;
/// `LIMITS.minTargetDepth` (`DEFAULT_TARGET_DEPTH`).
const MIN_TARGET_DEPTH: usize = 2;
/// `LIMITS.defaultTargetDepth`: the overlay's bytes `pssTarget` shows.
const DEFAULT_TARGET_DEPTH: usize = 2;
/// A message's batch: `selectBestBatch(4096, { allowFullMutable: true })`.
const MESSAGE_BATCH_SIZE: u64 = 4096;
/// secp256k1's field prime, big-endian.
const FIELD_PRIME: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

// --- shared checks ----------------------------------------------------------

/// `messagingNotGranted()`.
pub(crate) fn messaging_not_granted() -> Failure {
    Failure::not_authorized("messaging_not_granted")
}

fn invalid(message: &str, reason: &str) -> Failure {
    Failure::invalid_params(message, reason)
}

/// `validateMessagingTopic(topic)`: a non-empty string of at most 256
/// UTF-8 bytes (a lone surrogate counts as U+FFFD's three) with no unit
/// below U+0020.
fn topic(value: &Value) -> Result<&JsString, Failure> {
    let Value::String(topic) = value else {
        return Err(invalid("topic must be a non-empty string", "invalid_topic"));
    };
    if topic.utf16_len() == 0 {
        return Err(invalid("topic must be a non-empty string", "invalid_topic"));
    }
    if topic.len() > 256 {
        return Err(invalid("topic exceeds 256 UTF-8 bytes", "invalid_topic"));
    }
    if topic.units().any(|u| u < 32) {
        return Err(invalid(
            "topic must not contain control characters",
            "invalid_topic",
        ));
    }
    Ok(topic)
}

/// `keccak256(utf8(text))`, a lone surrogate as U+FFFD, as
/// `Buffer.from(text, 'utf-8')` and `Topic.fromString` encode it.
fn keccak_utf8(text: &str) -> [u8; 32] {
    fc_evm::keccak256(text.as_bytes())
}

/// The GSOC search for `topic`: messaging-service.js's frozen derivation.
pub fn gsoc_job(topic: &str) -> MineJob {
    MineJob {
        target: keccak_utf8(&format!("{GSOC_TARGET_CONTEXT}{topic}")),
        identifier: keccak_utf8(topic),
        proximity: GSOC_PROXIMITY,
    }
}

/// `validateBoundedPayload(data, 4000, 'message', …)`: the message's bytes
/// (a string's UTF-8). An empty one passes unless `empty` names the
/// reason its refusal gives (`allowEmpty` for PSS; `invalid_payload` for
/// GSOC, whose SOC can't be empty).
fn message(data: &Value, empty: Option<&str>) -> Result<Vec<u8>, Failure> {
    let data = if data.is_nullish() {
        None
    } else {
        data_of(data)
    };
    let Some(data) = data else {
        return Err(invalid(
            "data must be a string, Uint8Array, or ArrayBuffer",
            "invalid_params",
        ));
    };
    let len = match &data {
        Data::Inline(bytes) => bytes.len() as u64,
        Data::Part { len, .. } => *len,
    };
    if len == 0
        && let Some(reason) = empty
    {
        return Err(invalid("data must not be empty", reason));
    }
    if len > MAX_MESSAGE_BYTES {
        return Err(Failure::invalid_params_with(
            format!("Payload exceeds maximum message size of {MAX_MESSAGE_BYTES} bytes"),
            "payload_too_large",
            vec![
                ("limit", Value::int(MAX_MESSAGE_BYTES)),
                ("actual", Value::int(len)),
            ],
        ));
    }
    match data {
        Data::Inline(bytes) => Ok(bytes),
        // A part is past 64 KiB, so refused above.
        Data::Part { .. } => Err(Failure::internal_error()),
    }
}

/// The effect's guard (page-swarm.js's `guardEffect`, then
/// `whileMessagingGranted`), on the live facts just asked: the name still
/// binds the key; for a send the site's rule approved, the agent doesn't
/// hold the tab and the rule stands; the document is still under the key;
/// the site still has its messaging grant.
fn guard<W: World>(cx: &Cx<'_, W>, live: Live, approval: Option<Approval>) -> Result<(), Failure> {
    if !live.name {
        return Err(no_address());
    }
    if approval == Some(Approval::Auto) {
        if live.agent {
            return Err(Failure::not_authorized("agent_custody"));
        }
        if !cx.auto_approve(Capability::Messaging) {
            return Err(Failure::not_authorized("not_auto_approved"));
        }
    }
    if !live.live {
        return Err(no_address());
    }
    if !cx.messaging() {
        return Err(messaging_not_granted());
    }
    Ok(())
}

/// The publish readiness answer: on, or `Node not available: <reason>`.
fn readiness(event: Event) -> Result<(), Failure> {
    match event {
        Event::Ready(Ok(())) => Ok(()),
        Event::Ready(Err(reason)) => Err(Failure::node_unavailable(&reason)),
        _ => Err(Failure::internal_error()),
    }
}

/// `gsocDerivationError(err)` for what the lane answered when it found no
/// signer: the new-topic budget's -32602, `busy`, or -32603 with the
/// miner's text and reason.
pub fn mined_failure(mined: Mined) -> Failure {
    let mining = |message: &str, reason: &str| Failure {
        data: Some(Value::object([("reason", Value::str(reason))])),
        ..Failure::internal(message)
    };
    match mined {
        Mined::RateLimited { retry_after_ms } => Failure::invalid_params_with(
            format!(
                "Too many new messaging topics: at most {} new topics per {} s per origin. \
                 Retry in {} s.",
                crate::mining::NEW_TOPICS,
                crate::mining::NEW_TOPIC_WINDOW_MS / 1000,
                retry_after_ms.div_ceil(1000)
            ),
            "rate_limited",
            vec![
                ("limit", Value::int(crate::mining::NEW_TOPICS as u64)),
                ("windowMs", Value::int(crate::mining::NEW_TOPIC_WINDOW_MS)),
                ("retryAfterMs", Value::int(retry_after_ms)),
            ],
        ),
        Mined::Busy => Failure::busy(),
        Mined::Timeout => mining(
            &format!(
                "GSOC mining failed: timed out after {} ms",
                crate::mining::JOB_MS
            ),
            "gsoc_mining_timeout",
        ),
        Mined::Exhausted => mining(
            "GSOC mining failed: Could not mine a valid signer",
            "gsoc_mining_failed",
        ),
        Mined::Stuck => mining(
            "GSOC mining failed: mining lane stuck",
            "gsoc_mining_failed",
        ),
        Mined::Off => mining(
            "GSOC mining failed: mining is off until the core restarts",
            "gsoc_mining_failed",
        ),
        // A signer is no failure; a caller never asks for one.
        Mined::Found(_) => Failure::internal_error(),
    }
}

/// The mined signer for `job`: its key (`0xb33 + index`, public by
/// construction) and owner, and the SOC address, which must be within the
/// search's proximity of the target, or the lane answered for another job.
struct Signer {
    key: k256::ecdsa::SigningKey,
    owner: [u8; 20],
    address: [u8; 32],
}

fn signer(job: &MineJob, index: u32) -> Result<Signer, Failure> {
    if index >= gsoc::CANDIDATES {
        return Err(Failure::internal_error());
    }
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&(gsoc::KEY_START + u64::from(index)).to_be_bytes());
    let key = k256::ecdsa::SigningKey::from_slice(&bytes).map_err(|_| Failure::internal_error())?;
    let owner = fc_evm::address_of(&key);
    let address = fc_swarm::verify::soc_address(&job.identifier, &owner);
    if gsoc::proximity(&address, &job.target) < job.proximity {
        return Err(Failure::internal_error());
    }
    Ok(Signer {
        key,
        owner,
        address,
    })
}

/// A whole call's failure before any reply, as a page's -32603 with its
/// class's text: main's pool full is `busy`, a reply past its cap `Swarm
/// node reply too large`.
fn plain(failed: Failed) -> Failure {
    match failed {
        Failed::Busy => Failure::busy(),
        Failed::TooLarge => errors::reply_too_large().into(),
        class => Failure::internal(transport_text(class)),
    }
}

// --- core-sdk's byte types --------------------------------------------------

/// `new Bytes(text)` for a string: optional `0x` (either case), then an
/// even count of hex digits; with core-sdk's texts.
fn bytes_of(text: &JsString) -> Result<Vec<u8>, JsString> {
    if text.utf16_len() == 0 {
        return Err(JsString::from(
            "Bytes#constructor: constructor parameter is falsy: ",
        ));
    }
    let invalid = || {
        concat(&[
            &JsString::from("Bytes#constructor: invalid hex string: "),
            text,
        ])
    };
    if !text.is_well_formed() {
        return Err(invalid());
    }
    let s = text.as_str();
    let digits = match s.get(..2) {
        Some("0x" | "0X") => &s[2..],
        _ => s,
    };
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) || !digits.len().is_multiple_of(2) {
        return Err(invalid());
    }
    let digit = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| Some(digit(pair[0])? * 16 + digit(pair[1])?))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(invalid)
}

/// `new Bytes(text, n)`.
fn sized(text: &JsString, n: usize) -> Result<Vec<u8>, JsString> {
    let bytes = bytes_of(text)?;
    if bytes.len() != n {
        return Err(JsString::from(format!(
            "Bytes#checkByteLength: bytes length is {} but expected {n}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// A point as core-sdk's `PublicKey` holds it: `x ‖ y`, not checked.
type Point = [u8; 64];

/// x at or past the field's prime.
fn past_prime(x: &[u8]) -> bool {
    x >= FIELD_PRIME.as_slice()
}

/// noble's `Point.fromBytes` of a compressed key (`publicKeyFromCompressed`).
fn decompress(compressed: &[u8]) -> Result<Point, JsString> {
    if compressed.len() != 33 || !matches!(compressed[0], 2 | 3) {
        return Err(JsString::from("Invalid compressed public key"));
    }
    if past_prime(&compressed[1..]) {
        return Err(JsString::from("bad point: is not on curve, wrong x"));
    }
    let key = k256::PublicKey::from_sec1_bytes(compressed).map_err(|_| {
        JsString::from("bad point: is not on curve, sqrt error: Cannot find square root")
    })?;
    let encoded = k256::elliptic_curve::sec1::ToSec1Point::to_sec1_point(key.as_affine(), false);
    let mut point = [0u8; 64];
    let raw = encoded.as_bytes();
    if raw.len() != 65 {
        return Err(JsString::from("Invalid compressed public key"));
    }
    point.copy_from_slice(&raw[1..]);
    Ok(point)
}

/// `new PublicKey(text)`: 33 bytes decompressed, else exactly 64.
fn public_key(text: &JsString) -> Result<Point, JsString> {
    let bytes = bytes_of(text)?;
    if bytes.len() == 33 {
        return decompress(&bytes);
    }
    let bytes = sized(text, 64)?;
    let mut point = [0u8; 64];
    point.copy_from_slice(&bytes);
    Ok(point)
}

/// `publicKey.toCompressedHex()`: noble's `Point.fromAffine(…).toBytes(true)`,
/// which checks the point, as hex.
fn compressed_hex(point: &Point) -> Result<String, JsString> {
    let (x, y) = point.split_at(32);
    if past_prime(x) || past_prime(y) {
        return Err(JsString::from("invalid affine point"));
    }
    if point.iter().all(|b| *b == 0) {
        return Err(JsString::from("bad point: ZERO"));
    }
    let mut sec1 = [0u8; 65];
    sec1[0] = 4;
    sec1[1..].copy_from_slice(point);
    if k256::PublicKey::from_sec1_bytes(&sec1).is_err() {
        return Err(JsString::from("bad point: equation left != right"));
    }
    let mut out = String::with_capacity(66);
    out.push_str(if y[31] & 1 == 1 { "03" } else { "02" });
    out.push_str(&hex(x));
    Ok(out)
}

// --- `GET /addresses` -------------------------------------------------------

/// A field as the reply had it, the last of a repeated key.
#[derive(Debug, Clone, PartialEq)]
enum Field {
    Missing,
    Wrong(Received),
    Ok(JsString),
}

/// `underlay` as the reply had it: the elements that aren't strings, up to
/// as many as could still fit the refusal's text.
#[derive(Debug, Clone, PartialEq)]
enum Underlay {
    Missing,
    Wrong(Received),
    Array {
        wrong: Vec<(u32, Received)>,
        more: bool,
    },
}

/// Elements kept for the refusal's text: each element's issue is over 128
/// bytes of it (171 at the shortest), so past this many (512, 8 bytes
/// each) the refusal can't fit the form's 64 KiB, and the call fails
/// `too_large` unless a transform throws first.
const UNDERLAY_ISSUES: usize = JSON_REPLY_CAP / 128;

fn received(token: &Token<'_>) -> Received {
    match token {
        Token::Object => Received::Object,
        Token::Array => Received::Array,
        Token::String(_) => Received::String,
        Token::Number(n) => Received::of_number(*n),
        Token::Bool(_) => Received::Boolean,
        Token::Null => Received::Null,
    }
}

/// The node's messaging identity as `getMessagingIdentity` answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addresses {
    /// `pssPublicKey.toCompressedHex()`.
    pub pss_public_key: String,
    /// `toHex(overlay)`, lowercase.
    pub overlay: String,
}

/// The node's `/addresses` reply as bee-js reads it (`Response.text()`: a
/// byte-order mark dropped, an empty text `null`) and
/// `GetNodeAddressesResponse` parses it: each field in the schema's order,
/// a transform that throws (core-sdk's `PeerAddress`, `EthAddress`,
/// `PublicKey`) ending the parse with its text whatever the others' issues;
/// else zod's refusal; else the key compressed (noble's checks) and the
/// overlay. Fails `TooLarge` past 64 KiB or where the refusal's text would
/// be; `TooDeep` past the nesting bound; `Syntax` for a text `JSON.parse`
/// refuses.
pub fn read_addresses(reply: &[u8]) -> Result<Result<Addresses, JsString>, ReplyError> {
    if reply.len() > JSON_REPLY_CAP {
        return Err(ReplyError::TooLarge);
    }
    let text = js::strip_bom(reply);
    let mut issues = Issues::new();
    let push = |issues: &mut Issues, issue: Issue| {
        issues
            .push(issue, JSON_REPLY_CAP)
            .map_err(|_| ReplyError::TooLarge)
    };
    if text.is_empty() {
        push(
            &mut issues,
            Issue::new(Expected::Object, Received::Null, &[]),
        )?;
        return Ok(Err(JsString::from(issues.message())));
    }
    let mut r = Reader::new(text);
    let root = r.token()?;
    if root != Token::Object {
        push(
            &mut issues,
            Issue::new(Expected::Object, received(&root), &[]),
        )?;
        r.skip(root)?;
        r.finish()?;
        return Ok(Err(JsString::from(issues.message())));
    }
    let mut strings = [
        ("overlay", Field::Missing),
        ("ethereum", Field::Missing),
        ("publicKey", Field::Missing),
        ("pssPublicKey", Field::Missing),
    ];
    let mut underlay = Underlay::Missing;
    while let Some(key) = r.next_key()? {
        let token = r.token()?;
        if key.is("underlay") {
            underlay = match token {
                Token::Array => {
                    let mut wrong = Vec::new();
                    let mut more = false;
                    let mut at = 0u32;
                    while r.next_element()? {
                        let element = r.token()?;
                        if !matches!(element, Token::String(_)) {
                            if wrong.len() < UNDERLAY_ISSUES {
                                wrong.push((at, received(&element)));
                            } else {
                                more = true;
                            }
                        }
                        r.skip(element)?;
                        at = at.saturating_add(1);
                    }
                    Underlay::Array { wrong, more }
                }
                other => {
                    let what = received(&other);
                    r.skip(other)?;
                    Underlay::Wrong(what)
                }
            };
            continue;
        }
        match strings.iter_mut().find(|(name, _)| key.is(name)) {
            Some((_, field)) => {
                *field = match token {
                    Token::String(raw) => Field::Ok(raw.decode()),
                    other => {
                        let what = received(&other);
                        r.skip(other)?;
                        Field::Wrong(what)
                    }
                };
            }
            None => r.skip(token)?,
        }
    }
    r.finish()?;
    // The transforms, in the schema's order: the first that throws ends
    // the parse.
    let [overlay, ethereum, public, pss] = &strings;
    let mut overlay_bytes = None;
    let mut pss_point = None;
    if let Field::Ok(text) = &overlay.1 {
        match sized(text, 32) {
            Ok(bytes) => overlay_bytes = Some(bytes),
            Err(thrown) => return Ok(Err(thrown)),
        }
    }
    if let Field::Ok(text) = &ethereum.1
        && let Err(thrown) = sized(text, 20)
    {
        return Ok(Err(thrown));
    }
    if let Field::Ok(text) = &public.1
        && let Err(thrown) = public_key(text)
    {
        return Ok(Err(thrown));
    }
    if let Field::Ok(text) = &pss.1 {
        match public_key(text) {
            Ok(point) => pss_point = Some(point),
            Err(thrown) => return Ok(Err(thrown)),
        }
    }
    // zod's issues, in the schema's order.
    let field_issue = |name: &'static str, field: &Field| match field {
        Field::Missing => Some(Issue::new(
            Expected::String,
            Received::Undefined,
            &[Segment::Key(name)],
        )),
        Field::Wrong(what) => Some(Issue::new(Expected::String, *what, &[Segment::Key(name)])),
        Field::Ok(_) => None,
    };
    if let Some(issue) = field_issue("overlay", &overlay.1) {
        push(&mut issues, issue)?;
    }
    match &underlay {
        Underlay::Missing => push(
            &mut issues,
            Issue::new(
                Expected::Array,
                Received::Undefined,
                &[Segment::Key("underlay")],
            ),
        )?,
        Underlay::Wrong(what) => push(
            &mut issues,
            Issue::new(Expected::Array, *what, &[Segment::Key("underlay")]),
        )?,
        Underlay::Array { wrong, more } => {
            for (at, what) in wrong {
                push(
                    &mut issues,
                    Issue::new(
                        Expected::String,
                        *what,
                        &[Segment::Key("underlay"), Segment::Index(*at)],
                    ),
                )?;
            }
            if *more {
                return Err(ReplyError::TooLarge);
            }
        }
    }
    for (name, field) in [ethereum, public, pss] {
        if let Some(issue) = field_issue(name, field) {
            push(&mut issues, issue)?;
        }
    }
    if !issues.is_empty() {
        return Ok(Err(JsString::from(issues.message())));
    }
    let (Some(overlay), Some(point)) = (overlay_bytes, pss_point) else {
        return Ok(Err(JsString::from("Internal error")));
    };
    Ok(match compressed_hex(&point) {
        Ok(pss_public_key) => Ok(Addresses {
            pss_public_key,
            overlay: hex(&overlay),
        }),
        Err(thrown) => Err(thrown),
    })
}

// --- getMessagingIdentity ---------------------------------------------------

enum IdentityStage {
    Ready(AskId),
    Addresses(AskId),
    /// The live facts, before the answer goes.
    Live {
        id: AskId,
        addresses: Addresses,
    },
    Gone,
}

/// `handleGetMessagingIdentity`.
pub(crate) struct Identity {
    stage: IdentityStage,
}

impl Identity {
    pub(crate) fn start<W: World>(cx: &mut Cx<'_, W>) -> Result<Self, Outcome> {
        permitted(cx)?;
        if !cx.messaging() {
            return Err(messaging_not_granted().into());
        }
        Ok(Identity {
            stage: IdentityStage::Ready(cx.ready(ReadyCheck::Reachable)),
        })
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        match std::mem::replace(&mut self.stage, IdentityStage::Gone) {
            IdentityStage::Ready(ready_id) if id == ready_id => {
                if let Err(step) = ready(event) {
                    return step;
                }
                self.stage = IdentityStage::Addresses(cx.whole(NodeCall::addresses()));
                Step::Wait
            }
            IdentityStage::Addresses(call) if id == call => {
                let reply = match event {
                    Event::Reply(reply) => reply,
                    Event::Failed(failed) => return fail(plain(failed)),
                    _ => return fail(Failure::internal_error()),
                };
                if !reply.ok() {
                    // The provider's catch: -32603 with bee-js's text.
                    return fail(match reply.error(Site::BeeJs) {
                        Ok(err) => Failure::internal(err.message),
                        Err(failed) => plain(failed),
                    });
                }
                let addresses = match read_addresses(&reply.body) {
                    Ok(Ok(addresses)) => addresses,
                    Ok(Err(thrown)) => return fail(Failure::internal(thrown)),
                    Err(ReplyError::Syntax(_)) => return fail(errors::reply_not_json().into()),
                    Err(ReplyError::TooLarge) => return fail(plain(Failed::TooLarge)),
                    Err(ReplyError::TooDeep) => return fail(plain(Failed::Error)),
                };
                self.stage = IdentityStage::Live {
                    id: cx.live(),
                    addresses,
                };
                Step::Wait
            }
            IdentityStage::Live {
                id: asked,
                addresses,
            } if asked == id => {
                // What reveals the key's authority goes out only while the
                // name still binds it (page-swarm.js, after the wait).
                match live_of(&event) {
                    Some(live) if live.holds() => {}
                    Some(_) => return fail(no_address()),
                    None => return fail(Failure::internal_error()),
                }
                let target = addresses
                    .overlay
                    .get(..DEFAULT_TARGET_DEPTH * 2)
                    .unwrap_or_default()
                    .to_owned();
                done(Value::object([
                    ("pssPublicKey", Value::str(&addresses.pss_public_key)),
                    ("pssTarget", Value::str(&target)),
                    ("identityMode", Value::str("bee-wallet")),
                ]))
            }
            _ => fail(Failure::internal_error()),
        }
    }
}

// --- sendPss ----------------------------------------------------------------

enum PssStage {
    Ready(AskId),
    /// The live facts for the guard before `/stamps`.
    Guard(AskId),
    Stamps(AskId),
    /// The live facts for the guard after it, before the send.
    Recheck {
        id: AskId,
        batch: BatchId,
    },
    Send(AskId),
}

/// `handleSendPss`.
pub(crate) struct SendPss {
    approval: Option<Approval>,
    topic: [u8; 32],
    targets: JsString,
    recipient: JsString,
    message: Vec<u8>,
    stage: PssStage,
}

impl SendPss {
    pub(crate) fn start<W: World>(
        cx: &mut Cx<'_, W>,
        params: &Value,
        approval: Option<Approval>,
    ) -> Result<Self, Outcome> {
        permitted(cx)?;
        require_params(params)?;
        empty_options(params.get("options"))?;
        let topic = topic(params.get("topic"))?;
        let recipient = normalize_address(params.get("recipient"));
        let compressed = recipient.utf16_len() == 66
            && recipient.is_well_formed()
            && matches!(recipient.as_str().get(..2), Some("02" | "03"))
            && recipient.bytes().all(|b| b.is_ascii_hexdigit());
        if !compressed {
            return Err(invalid(
                "recipient must be a 66-character hex compressed secp256k1 public key",
                "invalid_recipient",
            )
            .into());
        }
        let targets = match params.get("targets") {
            Value::String(t)
                if t.utf16_len().is_multiple_of(2)
                    && (MIN_TARGET_DEPTH..=MAX_TARGET_DEPTH as usize)
                        .contains(&(t.utf16_len() / 2))
                    && t.is_well_formed()
                    && t.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                to_lower(t)
            }
            _ => {
                return Err(invalid(
                    &format!(
                        "targets must be hex encoding {MIN_TARGET_DEPTH}-{MAX_TARGET_DEPTH} whole bytes"
                    ),
                    "invalid_target",
                )
                .into());
            }
        };
        let message = message(params.get("data"), None)?;
        if !cx.messaging() {
            return Err(messaging_not_granted().into());
        }
        Ok(SendPss {
            approval,
            topic: keccak_utf8(topic.as_str()),
            targets,
            recipient: to_lower(&recipient),
            message,
            stage: PssStage::Ready(cx.ready(ReadyCheck::Publish)),
        })
    }

    /// `POST /pss/send/<t>/<x>?recipient=…` with the message.
    fn send_call(&self, batch: &BatchId) -> NodeCall {
        NodeCall::upload(
            Form::PssSend,
            &format!("/pss/send/{}/{}", hex(&self.topic), self.targets.as_str()),
            vec![("recipient".to_owned(), self.recipient.as_str().to_owned())],
            vec![
                (
                    "content-type".to_owned(),
                    "application/octet-stream".to_owned(),
                ),
                ("swarm-postage-batch-id".to_owned(), batch.to_hex()),
            ],
            Body::Base64(self.message.clone()),
        )
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        match self.stage {
            PssStage::Ready(ready_id) if id == ready_id => {
                if let Err(failure) = readiness(event) {
                    return fail(failure);
                }
                self.stage = PssStage::Guard(cx.live());
                Step::Wait
            }
            PssStage::Guard(asked) if id == asked => {
                let Some(live) = live_of(&event) else {
                    return fail(Failure::internal_error());
                };
                if let Err(refused) = guard(cx, live, self.approval) {
                    return fail(refused);
                }
                self.stage = PssStage::Stamps(cx.whole(NodeCall::stamps()));
                Step::Wait
            }
            PssStage::Stamps(call) if id == call => {
                let options = SelectOptions {
                    allow_full_mutable: true,
                    ..SelectOptions::default()
                };
                let batch = match batch_with(event, MESSAGE_BATCH_SIZE, options) {
                    Ok(batch) => batch,
                    Err(failed) => return fail(failed.page),
                };
                self.stage = PssStage::Recheck {
                    id: cx.live(),
                    batch,
                };
                Step::Wait
            }
            PssStage::Recheck { id: asked, batch } if id == asked => {
                let Some(live) = live_of(&event) else {
                    return fail(Failure::internal_error());
                };
                if let Err(refused) = guard(cx, live, self.approval) {
                    return fail(refused);
                }
                // `new PublicKey(recipient)`: bee-js's point check, kept for
                // its texts.
                if let Err(thrown) = public_key(&self.recipient) {
                    return fail(Fail::text(thrown).page);
                }
                self.stage = PssStage::Send(cx.whole(self.send_call(&batch)));
                Step::Wait
            }
            PssStage::Send(call) if id == call => {
                let reply = match event {
                    Event::Reply(reply) => reply,
                    Event::Failed(failed) => return fail(Fail::transport(failed).page),
                    _ => return fail(Failure::internal_error()),
                };
                if !reply.ok() {
                    // `pssSendHttpError`: bee-js's wording, through
                    // `nodeWriteError`.
                    return fail(match reply.error(Site::BeeJs) {
                        Ok(err) => node_write_error(&errors::ServiceError::from(&err)).into(),
                        Err(failed) => Fail::transport(failed).page,
                    });
                }
                done(Value::object([("sent", Value::Bool(true))]))
            }
            _ => fail(Failure::internal_error()),
        }
    }
}

// --- sendGsoc ---------------------------------------------------------------

enum GsocStage {
    Ready(AskId),
    /// The live facts for the guard before the search.
    Guard(AskId),
    Mine(AskId),
    Stamps {
        id: AskId,
        signer: Box<Signer>,
    },
    /// The live facts for the guard after `/stamps`, before the upload.
    Recheck {
        id: AskId,
        signer: Box<Signer>,
        batch: BatchId,
    },
    Upload {
        id: AskId,
        address: [u8; 32],
    },
    Gone,
}

/// `handleSendGsoc`.
pub(crate) struct SendGsoc {
    approval: Option<Approval>,
    job: MineJob,
    message: Vec<u8>,
    stage: GsocStage,
}

impl SendGsoc {
    pub(crate) fn start<W: World>(
        cx: &mut Cx<'_, W>,
        params: &Value,
        approval: Option<Approval>,
    ) -> Result<Self, Outcome> {
        permitted(cx)?;
        require_params(params)?;
        empty_options(params.get("options"))?;
        if !params.get("address").is_nullish() {
            return Err(invalid(
                "Sending to a raw GSOC address is not supported: the signing key derives from \
                 the topic. Provide topic instead.",
                "invalid_address",
            )
            .into());
        }
        let topic = topic(params.get("topic"))?;
        let message = message(params.get("data"), Some("invalid_payload"))?;
        if !cx.messaging() {
            return Err(messaging_not_granted().into());
        }
        Ok(SendGsoc {
            approval,
            job: gsoc_job(topic.as_str()),
            message,
            stage: GsocStage::Ready(cx.ready(ReadyCheck::Publish)),
        })
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        match std::mem::replace(&mut self.stage, GsocStage::Gone) {
            GsocStage::Ready(ready_id) if id == ready_id => {
                if let Err(failure) = readiness(event) {
                    return fail(failure);
                }
                self.stage = GsocStage::Guard(cx.live());
                Step::Wait
            }
            GsocStage::Guard(asked) if id == asked => {
                let Some(live) = live_of(&event) else {
                    return fail(Failure::internal_error());
                };
                if let Err(refused) = guard(cx, live, self.approval) {
                    return fail(refused);
                }
                self.stage = GsocStage::Mine(cx.mine(self.job));
                Step::Wait
            }
            GsocStage::Mine(mine) if id == mine => {
                let index = match event {
                    Event::Mined(Mined::Found(index)) => index,
                    Event::Mined(other) => return fail(mined_failure(other)),
                    _ => return fail(Failure::internal_error()),
                };
                let signer = match signer(&self.job, index) {
                    Ok(signer) => signer,
                    Err(failure) => return fail(failure),
                };
                self.stage = GsocStage::Stamps {
                    id: cx.whole(NodeCall::stamps()),
                    signer: Box::new(signer),
                };
                Step::Wait
            }
            GsocStage::Stamps { id: call, signer } if id == call => {
                let options = SelectOptions {
                    allow_full_mutable: true,
                    ..SelectOptions::default()
                };
                let batch = match batch_with(event, MESSAGE_BATCH_SIZE, options) {
                    Ok(batch) => batch,
                    Err(failed) => return fail(failed.page),
                };
                self.stage = GsocStage::Recheck {
                    id: cx.live(),
                    signer,
                    batch,
                };
                Step::Wait
            }
            GsocStage::Recheck {
                id: asked,
                signer,
                batch,
            } if id == asked => {
                let Some(live) = live_of(&event) else {
                    return fail(Failure::internal_error());
                };
                if let Err(refused) = guard(cx, live, self.approval) {
                    return fail(refused);
                }
                // `makeContentAddressedChunk(data).toSingleOwnerChunk(id,
                // key)`, signed with the mined key.
                let signed = match fc_swarm::sign_soc(
                    &signer.key,
                    &self.job.identifier,
                    None,
                    &self.message,
                ) {
                    Ok(signed) if signed.owner == signer.owner => signed,
                    _ => return fail(Failure::internal_error()),
                };
                let call = soc_up(
                    &signer.owner,
                    &self.job.identifier,
                    &signed.signature,
                    &batch,
                    false,
                    signed.span,
                    &self.message,
                );
                self.stage = GsocStage::Upload {
                    id: cx.whole(call),
                    address: signer.address,
                };
                Step::Wait
            }
            GsocStage::Upload { id: call, address } if id == call => {
                // bee-js's `uploadSingleOwnerChunk`: `UploadResultBody` and
                // the tag, its errors through `nodeWriteError`; then the
                // node's reference must be the SOC's own address, which
                // bee-js doesn't check (deviation `reference-check`).
                let reference = match bytes_uploaded(event) {
                    Ok(reference) => reference,
                    Err(failed) => return fail(failed.page),
                };
                if reference != address.as_slice() {
                    return fail(Fail::text(OTHER_REFERENCE_MESSAGE).page);
                }
                done(Value::object([
                    ("sent", Value::Bool(true)),
                    ("address", Value::str(&hex(&address))),
                ]))
            }
            _ => fail(Failure::internal_error()),
        }
    }
}

// --- subscribe --------------------------------------------------------------

/// `subscribeError`: what a subscription that didn't open answers, from the
/// registry's reason and message as main gives them; or question 4's
/// refusal, which main's check just before the open gives.
fn subscribe_error(failed: OpenFailed) -> Failure {
    let OpenFailed { reason, message } = failed;
    let unavailable = |message: JsString, reason: &JsString| Failure {
        code: crate::errors::NODE_UNAVAILABLE,
        message,
        data: Some(Value::object([("reason", Value::String(reason.clone()))])),
    };
    match reason {
        // Never established within the window, or torn down while main
        // waited (navigation, tab close, grant revoke): retryable.
        Some(r)
            if matches!(
                r.as_str(),
                "establish_timeout" | "subscription_cancelled" | "cancelled"
            ) =>
        {
            unavailable(message, &r)
        }
        Some(r) if r.as_str() == "too_many_subscriptions" => Failure::invalid_params_with(
            message,
            "too_many_subscriptions",
            vec![("limit", Value::int(MAX_SUBSCRIPTIONS))],
        ),
        // The node's pool is full (possibly by other sites): a retryable
        // 4900, not a parameter error.
        Some(r) if r.as_str() == "node_subscription_limit" => unavailable(
            concat(&[
                &JsString::from("Node subscription capacity exhausted: "),
                &message,
            ]),
            &r,
        ),
        // Main's own check again just before it opens (question 4, deviation
        // `subscribe-proxy`): a proxy or Tor came on while a GSOC key was
        // mined. The page gets the first check's 4900 shape.
        Some(r) if r.as_str() == "proxy-or-tor" => Failure::node_unavailable(&r),
        _ => Failure::internal(message),
    }
}

enum SubscribeStage {
    Ready(AskId),
    Mine(AskId),
    /// The live facts for the guard, with the key to open.
    Guard {
        id: AskId,
        key: [u8; 32],
    },
    /// Main opens the subscription.
    Open {
        id: AskId,
        key: [u8; 32],
    },
    /// The live facts once it is open, with main's id.
    Opened {
        id: AskId,
        key: [u8; 32],
        subscription: JsString,
    },
    /// The name or the document moved: main closes it, then `NO_ADDRESS`.
    Close(AskId),
    Gone,
}

/// The key a subscription derives: given, a PSS topic's hash, or a GSOC
/// topic's mined address.
enum Key {
    Given([u8; 32]),
    Pss([u8; 32]),
    Gsoc(MineJob),
}

/// `handleSubscribe` and `subscribeForPage`, the socket opened by main, and
/// page-swarm.js's check after it.
pub(crate) struct Subscribe {
    kind: SubscriptionKind,
    key: Key,
    stage: SubscribeStage,
}

impl Subscribe {
    pub(crate) fn start<W: World>(
        cx: &mut Cx<'_, W>,
        params: &Value,
        _approval: Option<Approval>,
    ) -> Result<Self, Outcome> {
        permitted(cx)?;
        require_params(params)?;
        empty_options(params.get("options"))?;
        let kind = match params.get("kind") {
            Value::String(k) if k.is_well_formed() && k.as_str() == "gsoc" => {
                SubscriptionKind::Gsoc
            }
            Value::String(k) if k.is_well_formed() && k.as_str() == "pss" => SubscriptionKind::Pss,
            _ => return Err(invalid("kind must be \"gsoc\" or \"pss\"", "invalid_kind").into()),
        };
        let has_topic = !params.get("topic").is_nullish();
        let has_address = !params.get("address").is_nullish();
        let mut given = None;
        match kind {
            SubscriptionKind::Gsoc => {
                if has_topic == has_address {
                    return Err(invalid(
                        "Provide either topic or address, not both",
                        "invalid_params",
                    )
                    .into());
                }
                if has_address {
                    let address =
                        hex_string(params.get("address"), 32, "invalid_address", "address")?;
                    given = Some(
                        crate::chunks::unhex::<32>(&address.as_str().to_ascii_lowercase())
                            .ok_or_else(Failure::internal_error)?,
                    );
                }
            }
            SubscriptionKind::Pss => {
                if has_address {
                    return Err(invalid(
                        "address is only valid for gsoc subscriptions",
                        "invalid_params",
                    )
                    .into());
                }
                if !has_topic {
                    return Err(invalid("topic is required", "invalid_topic").into());
                }
            }
        }
        let key = match given {
            Some(address) => Key::Given(address),
            None => {
                let topic = topic(params.get("topic"))?;
                match kind {
                    SubscriptionKind::Pss => Key::Pss(keccak_utf8(topic.as_str())),
                    SubscriptionKind::Gsoc => Key::Gsoc(gsoc_job(topic.as_str())),
                }
            }
        };
        if !cx.messaging() {
            return Err(messaging_not_granted().into());
        }
        Ok(Subscribe {
            kind,
            key,
            stage: SubscribeStage::Ready(cx.ready(ReadyCheck::Subscribe)),
        })
    }

    /// The registry's slot, under the guard: the live facts first.
    fn open<W: World>(&mut self, cx: &mut Cx<'_, W>, key: [u8; 32]) -> Step {
        self.stage = SubscribeStage::Guard { id: cx.live(), key };
        Step::Wait
    }

    /// What the request still closes when it ends without its machine: the
    /// subscription main opened for it, or the one it is opening.
    pub(crate) fn closing(&self) -> Option<Closing> {
        match &self.stage {
            SubscribeStage::Open { id, .. } => Some(Closing::AfterOpen(*id)),
            SubscribeStage::Opened { subscription, .. } => {
                Some(Closing::Unsubscribe(subscription.clone()))
            }
            _ => None,
        }
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        match std::mem::replace(&mut self.stage, SubscribeStage::Gone) {
            SubscribeStage::Ready(ready_id) if id == ready_id => {
                if let Err(step) = ready(event) {
                    return step;
                }
                match &self.key {
                    Key::Given(key) | Key::Pss(key) => {
                        let key = *key;
                        self.open(cx, key)
                    }
                    Key::Gsoc(job) => {
                        self.stage = SubscribeStage::Mine(cx.mine(*job));
                        Step::Wait
                    }
                }
            }
            SubscribeStage::Mine(mine) if id == mine => {
                let Key::Gsoc(job) = &self.key else {
                    return fail(Failure::internal_error());
                };
                let index = match event {
                    Event::Mined(Mined::Found(index)) => index,
                    Event::Mined(other) => return fail(mined_failure(other)),
                    _ => return fail(Failure::internal_error()),
                };
                match signer(job, index) {
                    Ok(signer) => self.open(cx, signer.address),
                    Err(failure) => fail(failure),
                }
            }
            SubscribeStage::Guard { id: asked, key } if id == asked => {
                let Some(live) = live_of(&event) else {
                    return fail(Failure::internal_error());
                };
                if let Err(refused) = guard(cx, live, None) {
                    return fail(refused);
                }
                // `subscriptionRegistry.subscribe`, in main.
                let subscription = Subscription {
                    kind: self.kind,
                    key,
                };
                self.stage = SubscribeStage::Open {
                    id: cx.subscribe(subscription),
                    key,
                };
                Step::Wait
            }
            SubscribeStage::Open { id: asked, key } if id == asked => match event {
                Event::Opened(Ok(subscription)) => {
                    // After the method's wait: what binds the key goes out
                    // only while the name still answers.
                    self.stage = SubscribeStage::Opened {
                        id: cx.live(),
                        key,
                        subscription,
                    };
                    Step::Wait
                }
                Event::Opened(Err(failed)) => fail(subscribe_error(failed)),
                _ => fail(Failure::internal_error()),
            },
            SubscribeStage::Opened {
                id: asked,
                key,
                subscription,
            } if id == asked => match live_of(&event) {
                Some(live) if live.holds() => done(Value::object([
                    ("subscriptionId", Value::String(subscription)),
                    ("kind", Value::str(self.kind.as_str())),
                    ("key", Value::str(&hex(&key))),
                ])),
                // `endDocumentSubscription`, then `NO_ADDRESS`.
                Some(_) => {
                    self.stage = SubscribeStage::Close(cx.unsubscribe(subscription));
                    Step::Wait
                }
                None => {
                    // What main opened is closed as the request ends.
                    self.stage = SubscribeStage::Opened {
                        id: asked,
                        key,
                        subscription,
                    };
                    fail(Failure::internal_error())
                }
            },
            SubscribeStage::Close(asked) if id == asked => match event {
                Event::Closed => fail(no_address()),
                _ => fail(Failure::internal_error()),
            },
            _ => fail(Failure::internal_error()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const GOOD: &str = r#"{"overlay":"36b7efd913ca4cf880b8eeac5093fa27b0825906c600685b6abdd6566e6cfe8f","underlay":["/ip4/127.0.0.1"],"ethereum":"0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0","publicKey":"039fd0991d0222b4e1339c1a1a5b5f6d9f6a96672a3247b638ee6156d9ea877a2f","pssPublicKey":"03c22c83fb49ab0ad897aa0c74e51311c95a3d1e1b27b2dedd7f42a7d2538c3a9e"}"#;
    const G: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    const P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

    fn with(field: &str, value: &str) -> Vec<u8> {
        let mut parsed = fc_json::parse(GOOD).unwrap();
        parsed.set(field, fc_json::parse(value).unwrap());
        parsed.stringify().into_bytes()
    }

    fn thrown(body: &[u8]) -> String {
        match read_addresses(body).unwrap() {
            Err(text) => text.as_str().to_owned(),
            Ok(a) => panic!("read {a:?}"),
        }
    }

    /// Each answer, as the reference's install gives it (core-sdk 0.2.2,
    /// noble, zod 4), probed against bee-js 13.2.0's schema.
    #[test]
    fn addresses_read_as_bee_js() {
        let ok = read_addresses(GOOD.as_bytes()).unwrap().unwrap();
        assert_eq!(
            ok.pss_public_key,
            "03c22c83fb49ab0ad897aa0c74e51311c95a3d1e1b27b2dedd7f42a7d2538c3a9e"
        );
        assert_eq!(&ok.overlay[..4], "36b7");
        // A throw wins over every issue, the first in the schema's order.
        let mut both = fc_json::parse(GOOD).unwrap();
        both.set("overlay", fc_json::JsValue::Number(5.0));
        both.set("ethereum", fc_json::JsValue::string("zz"));
        assert_eq!(
            thrown(both.stringify().as_bytes()),
            "Bytes#constructor: invalid hex string: zz"
        );
        assert_eq!(
            thrown(&with("overlay", "\"abcd\"")),
            "Bytes#checkByteLength: bytes length is 2 but expected 32"
        );
        assert_eq!(
            thrown(&with("pssPublicKey", &format!("\"{}\"", "ab".repeat(64)))),
            "bad point: equation left != right"
        );
        assert_eq!(
            thrown(&with("pssPublicKey", "\"\"")),
            "Bytes#constructor: constructor parameter is falsy: "
        );
        assert_eq!(
            thrown(&with(
                "pssPublicKey",
                "\"04c22c83fb49ab0ad897aa0c74e51311c95a3d1e1b27b2dedd7f42a7d2538c3a9e\""
            )),
            "Invalid compressed public key"
        );
        assert_eq!(
            thrown(&with("pssPublicKey", &format!("\"{}\"", "00".repeat(64)))),
            "bad point: ZERO"
        );
        assert_eq!(
            thrown(&with(
                "pssPublicKey",
                &format!("\"{P}{}\"", "00".repeat(32))
            )),
            "invalid affine point"
        );
        assert_eq!(
            thrown(&with("pssPublicKey", &format!("\"02{P}\""))),
            "bad point: is not on curve, wrong x"
        );
        assert_eq!(
            thrown(&with("pssPublicKey", &format!("\"02{}\"", "00".repeat(32)))),
            "bad point: is not on curve, sqrt error: Cannot find square root"
        );
        assert_eq!(
            thrown(&with("pssPublicKey", "\"ab\"")),
            "Bytes#checkByteLength: bytes length is 1 but expected 64"
        );
        let upper = read_addresses(&with(
            "pssPublicKey",
            &format!("\"0X{}\"", G.to_uppercase()),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(upper.pss_public_key, format!("02{}", &G[..64]));
        let compressed =
            read_addresses(&with("pssPublicKey", &format!("\"03{}\"", &G[..64]))).unwrap();
        assert_eq!(
            compressed.unwrap().pss_public_key,
            format!("03{}", &G[..64])
        );
        // Element issues, in order; another type at the root.
        let issues = thrown(&with("underlay", "[1,\"a\",null]"));
        assert!(issues.contains("\"underlay\",\n      0"), "{issues}");
        assert!(issues.contains("\"underlay\",\n      2"), "{issues}");
        assert!(thrown(b"[1]").contains("expected object, received array"));
        assert!(thrown(b"").contains("expected object, received null"));
        assert_eq!(read_addresses(b"<html>"), Err(ReplyError::Syntax(0)));
        // A refusal past the form's cap.
        let many = format!("[{}0]", "0,".repeat(20_000));
        assert_eq!(
            read_addresses(&with("underlay", &many)),
            Err(ReplyError::TooLarge)
        );
    }

    /// What the `/addresses` reader holds beyond its strings and the
    /// refusal's text fits the floor its call reserves (design 0015, "JSON
    /// replies"): the kept `underlay` entries and the refusal's issue list
    /// at the cap, above `4m + 2 × b64(m) + 16 KiB + E × 256 B`.
    #[test]
    fn the_addresses_reader_fits_its_charge() {
        use crate::machine::node::b64;
        let m = JSON_REPLY_CAP;
        let base = 4 * m + 2 * b64(m) + 16 * 1024 + 256;
        let shortest = Issue::new(
            Expected::String,
            Received::Null,
            &[Segment::Key("underlay"), Segment::Index(0)],
        );
        let mut issues = Issues::new();
        let mut fit = 0;
        while issues.push(shortest, JSON_REPLY_CAP).is_ok() {
            fit += 1;
        }
        assert_eq!(fit, 378);
        assert!(fit < UNDERLAY_ISSUES);
        let entries = UNDERLAY_ISSUES * std::mem::size_of::<(u32, Received)>();
        assert_eq!(entries, 4096);
        assert!(issues.heap_bytes() <= 40 * 1024);
        assert_eq!(
            crate::machine::whole_charge(Form::Addresses),
            crate::machine::node::CHARGE_FLOOR
        );
        assert!(base + entries + issues.heap_bytes() <= crate::machine::node::CHARGE_FLOOR);
    }

    #[test]
    fn a_recipient_is_checked_as_a_point() {
        let check = |k: &str| public_key(&JsString::from(k)).map(|_| ());
        assert_eq!(
            check(&format!("02{}", "f".repeat(64))).unwrap_err(),
            "bad point: is not on curve, wrong x"
        );
        assert_eq!(
            check(&format!("02{}", "0".repeat(63))).unwrap_err(),
            "Bytes#constructor: invalid hex string: 02000000000000000000000000000000000000000000000000000000000000000"
        );
        assert!(check(&format!("02{}", &G[..64])).is_ok());
    }

    #[test]
    fn the_gsoc_derivation_is_frozen() {
        let job = gsoc_job("chat");
        assert_eq!(
            hex(&job.identifier),
            "7d37ee8427bc4ef7fa6c30bba155020c46b01043618747ed07cb611ab74a11ee"
        );
        assert_eq!(
            hex(&job.target),
            "afa687bb5286ada3f159cc0be350b0d036a335c691ea6e7faf2d763932b58189"
        );
        let signer = signer(&job, 143).unwrap();
        assert_eq!(
            hex(&signer.owner),
            "6620b69328c5d52a787bac965a0c090432872639"
        );
        assert_eq!(
            hex(&signer.address),
            "afa2b50effd3d1c01bd48e2dcc1fcc44fa704bf271ac8f9e02dd5f28705e3d0e"
        );
        // Another index isn't within the proximity: the lane answered for
        // another job.
        assert!(super::signer(&job, 144).is_err());
        assert!(super::signer(&job, gsoc::CANDIDATES).is_err());
    }

    #[test]
    fn a_rate_limit_reads_as_today() {
        let failure = mined_failure(Mined::RateLimited {
            retry_after_ms: 59_001,
        });
        assert_eq!(
            failure.message,
            "Too many new messaging topics: at most 16 new topics per 60 s per origin. Retry in 60 s."
        );
    }
}
