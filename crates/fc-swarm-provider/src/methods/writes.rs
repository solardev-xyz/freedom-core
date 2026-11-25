//! What the feed and SOC writes share (design 0015, "Feeds, SOCs and
//! SW-1"), in the reference's terms:
//!
//! - **the identity and its key** (swarm-provider-ipc.js's
//!   `getActiveOriginIdentity`, `getFeedIdentity`, `unavailableIdentityError`;
//!   swarm-signer.js's `resolveSwarmSigner`): the core picks the key from
//!   its own store, by the page's key, never main;
//! - **the vault's answers**: a key's owner, and a signature checked as
//!   `createSwarmSigner` checks it;
//! - **the effect's guard** (`meta.page.effect` and `whileGranted`): just
//!   before each upload, main's live checks (the name, the document, Agent
//!   custody), the site's rule for an automatic request, then the
//!   connection and the feed grant;
//! - **the batch** from one `/stamps` read (`selectBestBatch`, deviation
//!   `stamps-one-read`), and the node's replies to the uploads;
//! - **the history row** (`addEntry`, `updateEntry`) and the failures after
//!   it, each with the row's text and the page's error.

use fc_json::{JsString, JsValue};
use fc_swarm::PreparedChunk;

use crate::chunks::hex;
use crate::errors::{self, ServiceError, Site, node_write_error};
use crate::js::{is_integer, strip_bom, to_lower};
use crate::json::{ReadError, Reader, Token};
use crate::machine::node::{Failed, JSON_REPLY_CAP, transport_text};
use crate::machine::{
    Approval, AskId, Body, Cx, Event, Failure, Form, NodeCall, SignKey, StoreWrite, World,
};
use crate::stamps::{BatchId, SelectOptions, read_stamps, select_best_batch};
use crate::stores::feeds::{
    APP_SCOPED, BEE_WALLET, ETHEREUM_WALLET, ETHEREUM_WALLET_UNAVAILABLE, identity_mode,
};
use crate::stores::manifests::Capability;
use crate::stores::{history, is_str, object, template, text};
use crate::zod::{Expected, Issue, Issues, Received, Segment};
use crate::{ReplyError, stamps::STAMPS_REPLY_CAP};

/// A failure after the history row: the row's `errorMessage` and the
/// page's error.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Fail {
    pub message: JsString,
    pub page: Failure,
}

impl Fail {
    /// What a service threw, through `nodeWriteError`.
    pub fn thrown(err: &ServiceError) -> Fail {
        Fail {
            message: err.message.clone(),
            page: node_write_error(err).into(),
        }
    }

    /// A plain `Error(message)` a service threw, through `nodeWriteError`.
    pub fn text(message: impl Into<JsString>) -> Fail {
        Fail::thrown(&ServiceError {
            message: message.into(),
            code: None,
            reason: None,
        })
    }

    /// An answer the page gets as it is (a guard's refusal); the row takes
    /// its message.
    pub fn answer(page: Failure) -> Fail {
        Fail {
            message: page.message.clone(),
            page,
        }
    }

    /// A node call that failed before any reply: its class's text
    /// (deviation `transport-error-text`); main's pool full is `busy`; a
    /// reply past its cap `Swarm node reply too large` (`reply-bounds`).
    pub fn transport(failed: Failed) -> Fail {
        match failed {
            Failed::Busy => Fail::answer(Failure::busy()),
            Failed::TooLarge => Fail::answer(errors::reply_too_large().into()),
            class => Fail::text(transport_text(class)),
        }
    }

    /// A JSON reply that isn't read: not JSON (`reply-syntax`), past a cap,
    /// or nested too deep (`error`).
    pub fn reply(err: ReplyError) -> Fail {
        match err {
            ReplyError::Syntax(_) => Fail::answer(errors::reply_not_json().into()),
            ReplyError::TooLarge => Fail::transport(Failed::TooLarge),
            ReplyError::TooDeep => Fail::transport(Failed::Error),
        }
    }

    /// An answer of the wrong kind, which strict reading already refuses,
    /// or a call main's grammar refused: -32603 `Internal error`.
    pub fn internal() -> Fail {
        Fail::answer(Failure::internal_error())
    }
}

impl From<ReadError> for Fail {
    fn from(err: ReadError) -> Self {
        Fail::reply(err.into())
    }
}

// --- identities and keys ---------------------------------------------------

/// `unavailableIdentityError(identity)` (#89): a stored `ethereum-wallet`
/// identity's -32603, before node readiness.
pub(crate) fn unavailable(identity: Option<&JsValue>) -> Result<(), Failure> {
    if is_str(Some(&identity_mode(identity)), ETHEREUM_WALLET) {
        return Err(Failure::internal(ETHEREUM_WALLET_UNAVAILABLE));
    }
    Ok(())
}

/// `resolveSwarmSigner(identity)` up to its vault call: the identity's key
/// reference, or what it throws first.
pub(crate) fn signer_key(identity: Option<&JsValue>) -> Result<SignKey, Failure> {
    let mode = identity_mode(identity);
    if is_str(Some(&mode), BEE_WALLET) {
        return Ok(SignKey::BeeWallet);
    }
    if is_str(Some(&mode), APP_SCOPED) {
        let Some(JsValue::Number(index)) = identity.and_then(|i| i.get("publisherKeyIndex"))
        else {
            return Err(Failure::internal(
                "App-scoped identity is missing a publisher key index",
            ));
        };
        // identity-manager.js's `getPublisherAddress`.
        if *index < 0.0 || !is_integer(*index) {
            return Err(Failure::internal(
                "Origin index must be a non-negative integer",
            ));
        }
        // The vault refuses an index past BIP-32's hardened range itself;
        // one past u32 reaches it as u32::MAX, refused the same way.
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a non-negative integer, saturated"
        )]
        let index = *index as u64;
        return Ok(SignKey::Publisher(
            u32::try_from(index).unwrap_or(u32::MAX),
        ));
    }
    if is_str(Some(&mode), ETHEREUM_WALLET) {
        return Err(Failure::internal(ETHEREUM_WALLET_UNAVAILABLE));
    }
    let shown = template(&mode).unwrap_or_else(|thrown| thrown.message);
    Err(Failure::internal(format!("Unknown identity mode: {shown}")))
}

/// The vault's answer for `key`'s owner: the address, or the reference's
/// text for a locked vault (`VAULT_LOCKED_MESSAGE`, or
/// `getPublisherAddress`'s).
pub(crate) fn owner(key: SignKey, event: Event) -> Result<[u8; 20], Failure> {
    match event {
        Event::Owner(Ok(Some(owner))) => Ok(owner),
        Event::Owner(Ok(None)) => Err(Failure::internal(match key {
            SignKey::BeeWallet => "Vault is locked",
            SignKey::Publisher(_) => "Vault must be unlocked to derive publisher keys",
        })),
        Event::Owner(Err(text)) => Err(Failure::internal(text)),
        _ => Err(Failure::internal_error()),
    }
}

/// The vault's signature of `prepared` for `owner`, checked as
/// `createSwarmSigner` checks it: the owner its own, a wire signature (`v`
/// 27 or 28) that recovers to it.
pub(crate) fn signature(
    event: Event,
    owner: &[u8; 20],
    prepared: &PreparedChunk,
) -> Result<[u8; 65], Fail> {
    match event {
        Event::Signed(Ok(signed)) => {
            let v = signed.signature[64];
            let recovered = fc_evm::recover_address(&prepared.digest(), &signed.signature).ok();
            if signed.owner != *owner || !(v == 27 || v == 28) || recovered != Some(*owner) {
                return Err(Fail::text(
                    "The identity core returned a chunk signature that does not match",
                ));
            }
            Ok(signed.signature)
        }
        Event::Signed(Err(text)) => Err(Fail::text(text)),
        _ => Err(Fail::internal()),
    }
}

// --- the effect's guard ----------------------------------------------------

/// A keyless document's answer, or one whose name moved (page-swarm.js's
/// `NO_ADDRESS`).
pub(crate) fn no_address() -> Failure {
    Failure {
        data: Some(crate::value::Value::object([(
            "reason",
            crate::value::Value::str("no_address"),
        )])),
        ..Failure::bare(4100, "This page has no address to connect from yet")
    }
}

/// `feedNotGranted()`.
pub(crate) fn feed_not_granted() -> Failure {
    Failure::not_authorized("feed_not_granted")
}

/// The effect's guard, on main's [`Event::Rechecked`]: the page still
/// there, then for a request the site's rule answered Agent custody and the
/// rule itself (`AGENT_CUSTODY`, `RULE_OFF`), then the connection and, for
/// a feed or SOC write, the feed grant (`whileGranted`).
pub(crate) fn guard<W: World>(
    cx: &Cx<'_, W>,
    capability: Capability,
    event: Event,
) -> Result<(), Failure> {
    let Event::Rechecked(recheck) = event else {
        return Err(Failure::internal_error());
    };
    if !recheck.live {
        return Err(no_address());
    }
    if cx.approval == Some(Approval::Auto) {
        if recheck.agent {
            return Err(Failure::not_authorized("agent_custody"));
        }
        if !cx.world.auto_approve(cx.origin, capability) {
            return Err(Failure::not_authorized("not_auto_approved"));
        }
    }
    if !cx.connected() {
        return Err(Failure::not_connected());
    }
    if !cx.world.feeds().has_feed_grant(cx.origin) {
        return Err(feed_not_granted());
    }
    Ok(())
}

// --- the batch -------------------------------------------------------------

/// `GET /stamps`, once (deviation `stamps-one-read`).
pub(crate) fn stamps_call() -> NodeCall {
    NodeCall {
        form: Form::Stamps,
        path: "/stamps".to_owned(),
        query: Vec::new(),
        headers: Vec::new(),
        body: None,
        max_bytes: STAMPS_REPLY_CAP,
        feed: None,
        tree: None,
    }
}

/// `selectBestBatch(size)` over `/stamps`' answer: the batch, or what the
/// write throws (no batch with room is `noUsableBatchError`).
pub(crate) fn batch(event: Event, size: u64) -> Result<BatchId, Fail> {
    let reply = match event {
        Event::Reply(reply) => reply,
        Event::Failed(failed) => return Err(Fail::transport(failed)),
        _ => return Err(Fail::internal()),
    };
    if !reply.ok() {
        return Err(match reply.error(Site::BeeJs) {
            Ok(err) => Fail::thrown(&ServiceError::from(&err)),
            Err(failed) => Fail::transport(failed),
        });
    }
    let stamps = read_stamps(&reply.body).map_err(Fail::reply)?;
    let selection = select_best_batch(&stamps, size, SelectOptions::default())
        .map_err(|err| Fail::thrown(&ServiceError::from(&err)))?;
    match selection.outcome {
        Ok(Some(batch)) => Ok(batch),
        Ok(None) => Err(Fail::thrown(&ServiceError::no_usable_batch())),
        Err(err) => Err(Fail::thrown(&ServiceError::from(&err))),
    }
}

// --- the uploads -----------------------------------------------------------

fn post(form: Form, path: String, headers: Vec<(&str, String)>, body: Option<Body>) -> NodeCall {
    NodeCall {
        form,
        path,
        query: Vec::new(),
        headers: headers
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
        body,
        max_bytes: JSON_REPLY_CAP,
        feed: None,
        tree: None,
    }
}

/// `POST /soc/<o>/<id>?sig=…` with `span ‖ payload` (chunk-service.js's
/// `uploadSingleOwnerChunk`); a raw SOC also pins and doesn't defer.
pub(crate) fn soc_up(
    owner: &[u8; 20],
    identifier: &[u8; 32],
    signature: &[u8; 65],
    batch: &BatchId,
    raw: bool,
    span: u64,
    payload: &[u8],
) -> NodeCall {
    let mut headers = vec![
        ("content-type", "application/octet-stream".to_owned()),
        ("swarm-postage-batch-id", batch.to_hex()),
    ];
    if raw {
        headers.push(("swarm-pin", "true".to_owned()));
        headers.push(("swarm-deferred-upload", "false".to_owned()));
    }
    let mut body = Vec::with_capacity(8 + payload.len());
    body.extend_from_slice(&span.to_le_bytes());
    body.extend_from_slice(payload);
    let mut call = post(
        Form::SocUp,
        format!("/soc/{}/{}", hex(owner), hex(identifier)),
        headers,
        Some(Body::Base64(body)),
    );
    call.query.push(("sig".to_owned(), hex(signature)));
    call
}

/// `POST /feeds/<o>/<t>` (bee-js's `createFeedManifest`).
pub(crate) fn feed_manifest(owner: &[u8; 20], topic: &[u8; 32], batch: &BatchId) -> NodeCall {
    post(
        Form::FeedManifest,
        format!("/feeds/{}/{}", hex(owner), hex(topic)),
        vec![("swarm-postage-batch-id", batch.to_hex())],
        None,
    )
}

/// `POST /bytes` (bee-js's `bytes.upload`), its body streamed.
pub(crate) fn bytes_up(batch: &BatchId, bytes: u64) -> NodeCall {
    post(
        Form::BytesUp,
        "/bytes".to_owned(),
        vec![
            ("content-type", "application/octet-stream".to_owned()),
            ("swarm-postage-batch-id", batch.to_hex()),
        ],
        Some(Body::Stream { bytes }),
    )
}

/// The reply to one of bee-js's uploads (`feed_manifest`, `bytes_up`):
/// `UploadResultBody.parse(response.data).reference`.
pub(crate) fn bee_upload(event: Event) -> Result<Vec<u8>, Fail> {
    let reply = match event {
        Event::Reply(reply) => reply,
        Event::Failed(failed) => return Err(Fail::transport(failed)),
        _ => return Err(Fail::internal()),
    };
    if !reply.ok() {
        return Err(match reply.error(Site::BeeJs) {
            Ok(err) => Fail::thrown(&ServiceError::from(&err)),
            Err(failed) => Fail::transport(failed),
        });
    }
    match upload_reference(strip_bom(&reply.body))? {
        Ok(reference) => reference_bytes(&reference).map_err(Fail::text),
        Err(issue) => {
            let mut issues = Issues::new();
            issues
                .push(issue, JSON_REPLY_CAP)
                .map_err(|_| Fail::transport(Failed::TooLarge))?;
            Err(Fail::text(issues.message()))
        }
    }
}

/// zod's read of `{ reference: string }`: the last `reference`'s string, or
/// the issue it raises.
fn upload_reference(body: &[u8]) -> Result<Result<JsString, Issue>, ReadError> {
    let mut r = Reader::new(body);
    let first = r.token()?;
    if first != Token::Object {
        let received = received(&first);
        r.skip(first)?;
        r.finish()?;
        return Ok(Err(Issue::new(Expected::Object, received, &[])));
    }
    let mut reference: Result<JsString, Received> = Err(Received::Undefined);
    while let Some(key) = r.next_key()? {
        let token = r.token()?;
        if key.is("reference") {
            reference = match token {
                Token::String(raw) => Ok(raw.decode()),
                ref other => Err(received(other)),
            };
        }
        r.skip(token)?;
    }
    r.finish()?;
    Ok(reference.map_err(|received| {
        Issue::new(Expected::String, received, &[Segment::Key("reference")])
    }))
}

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

/// core-sdk's `new Reference(text)`: 32 or 64 bytes of hex, a `0x` taken
/// off, with `Bytes`' messages.
fn reference_bytes(text: &JsString) -> Result<Vec<u8>, JsString> {
    let invalid = || {
        crate::js::concat(&[
            &JsString::from("Bytes#constructor: invalid hex string: "),
            text,
        ])
    };
    if text.is_empty() {
        return Err(JsString::from(
            "Bytes#constructor: constructor parameter is falsy: ",
        ));
    }
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
    let len = digits.len() / 2;
    if len != 32 && len != 64 {
        return Err(JsString::from(format!(
            "Bytes#checkByteLength: bytes length is {len} but expected 32 or 64"
        )));
    }
    let digit = |c: u8| char::from(c).to_digit(16).and_then(|d| u8::try_from(d).ok());
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| Some(digit(pair[0])? * 16 + digit(pair[1])?))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(invalid)
}

/// The SOC upload's answer (chunk-service.js's `uploadSingleOwnerChunk`):
/// an error status is `SOC upload failed (…)`; a success's JSON
/// (`response.json()`) must name the SOC's own address.
pub(crate) fn soc_uploaded(event: Event, expected: &[u8; 32]) -> Result<String, Fail> {
    let reply = match event {
        Event::Reply(reply) => reply,
        Event::Failed(failed) => return Err(Fail::transport(failed)),
        _ => return Err(Fail::internal()),
    };
    if !reply.ok() {
        return Err(match reply.error(Site::SocUpload) {
            Ok(err) => Fail::thrown(&ServiceError::from(&err)),
            Err(failed) => Fail::transport(failed),
        });
    }
    // `normalizeReference(body.reference)`.
    let reference = match soc_reference(strip_bom(&reply.body))? {
        Ok(text) => to_lower(&crate::machine::params::strip_0x(&text)),
        Err(thrown) => return Err(Fail::text(thrown)),
    };
    if reference.is_empty() {
        return Err(Fail::text("SOC upload response missing reference"));
    }
    let expected = hex(expected);
    if reference != expected.as_str() {
        return Err(Fail::text(crate::js::concat(&[
            &JsString::from("SOC upload returned unexpected reference: "),
            &reference,
        ])));
    }
    Ok(expected)
}

/// `String(body.reference || '')` over the reply's JSON, or what reading it
/// throws.
fn soc_reference(body: &[u8]) -> Result<Result<JsString, String>, ReadError> {
    let mut r = Reader::new(body);
    let first = r.token()?;
    match first {
        Token::Null => {
            r.finish()?;
            return Ok(Err(String::from(
                "Cannot read properties of null (reading 'reference')",
            )));
        }
        Token::Object => {}
        other => {
            r.skip(other)?;
            r.finish()?;
            return Ok(Ok(JsString::default()));
        }
    }
    let mut value: Result<JsString, String> = Ok(JsString::default());
    while let Some(key) = r.next_key()? {
        let start = r.position();
        let token = r.token()?;
        let is_reference = key.is("reference");
        if is_reference {
            value = Ok(match token {
                Token::String(raw) => raw.decode(),
                Token::Number(n) if n != 0.0 && !n.is_nan() => {
                    JsString::from(fc_json::number_to_string(n))
                }
                Token::Bool(true) => JsString::from("true"),
                Token::Number(_) | Token::Bool(false) | Token::Null => JsString::default(),
                Token::Object | Token::Array => JsString::default(),
            });
        }
        r.skip(token)?;
        if is_reference && matches!(token, Token::Object | Token::Array) {
            // An object or array is truthy: `String()` of it, joined as
            // JavaScript joins an array, which throws for an object with
            // its own `toString`.
            let slice = body.get(start..r.position()).unwrap_or(&[]);
            value = match fc_json::parse(&String::from_utf8_lossy(slice)) {
                Ok(parsed) => parsed
                    .js_string()
                    .map(JsString::from)
                    .map_err(|_| String::from("Cannot convert object to primitive value")),
                Err(_) => return Err(ReadError::Syntax(start)),
            };
        }
    }
    r.finish()?;
    Ok(value)
}

// --- the history row --------------------------------------------------------

/// A history row's fields, as the handler passes them to `addEntry` or
/// `updateEntry`.
pub(crate) fn row(fields: &[(&str, JsValue)]) -> JsValue {
    let mut out = object();
    for (key, value) in fields {
        out.set(*key, value.clone());
    }
    out
}

/// A string field.
pub(crate) fn s(value: &str) -> JsValue {
    text(value)
}

/// `addEntry(entry)`: the insert, answered with its rowid.
pub(crate) fn add_row<W: World>(cx: &mut Cx<'_, W>, entry: &JsValue) -> Result<AskId, Failure> {
    let statement =
        history::add_entry(entry, cx.world.now()).map_err(|t| Failure::internal(t.message))?;
    Ok(cx.write(StoreWrite::HistoryAdd(statement)))
}

/// `updateEntry(id, updates)`.
pub(crate) fn update_row<W: World>(
    cx: &mut Cx<'_, W>,
    id: i64,
    updates: &JsValue,
) -> Result<AskId, Failure> {
    #[expect(
        clippy::cast_precision_loss,
        reason = "better-sqlite3 answers lastInsertRowid as a JavaScript number"
    )]
    let id = JsValue::Number(id as f64);
    let statement = history::update_entry(&id, updates, cx.world.now())
        .map_err(|t| Failure::internal(t.message))?;
    Ok(cx.write(StoreWrite::History(vec![statement])))
}

/// The row a failure leaves: `{ status: 'failed', errorMessage }`.
pub(crate) fn failed_row(fail: &Fail) -> JsValue {
    row(&[
        ("status", s("failed")),
        ("errorMessage", JsValue::String(fail.message.clone())),
    ])
}

/// The rowid an insert answered.
pub(crate) fn row_added(event: Event) -> Result<i64, Failure> {
    match event {
        Event::RowAdded(Ok(id)) => Ok(id),
        Event::RowAdded(Err(text)) => Err(Failure::internal(text)),
        _ => Err(Failure::internal_error()),
    }
}

/// A store write's answer.
pub(crate) fn written(event: Event) -> Result<(), JsString> {
    match event {
        Event::Written(result) => result,
        _ => Err(JsString::from("Internal error")),
    }
}

/// A write's last step once its history row exists: the row's update
/// (`updateEntry`: completed with the write's fields, or failed with the
/// failure's text), then the answer.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Ending {
    pub id: AskId,
    outcome: Result<crate::value::Value, Failure>,
}

impl Ending {
    pub fn start<W: World>(
        cx: &mut Cx<'_, W>,
        row: i64,
        result: Result<(crate::value::Value, JsValue), Fail>,
    ) -> Result<Ending, Failure> {
        let (updates, outcome) = match result {
            Ok((value, updates)) => (updates, Ok(value)),
            Err(fail) => (failed_row(&fail), Err(fail.page)),
        };
        Ok(Ending {
            id: update_row(cx, row, &updates)?,
            outcome,
        })
    }

    /// The row's update answered: the write's answer, or the update's
    /// failure.
    pub fn on(self, event: Event) -> crate::machine::Step {
        match written(event) {
            Ok(()) => match self.outcome {
                Ok(value) => crate::machine::done(value),
                Err(page) => crate::machine::fail(page),
            },
            Err(text) => crate::machine::fail(Failure::internal(text)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn references_read_as_core_sdk() {
        let r = |t: &str| reference_bytes(&JsString::from(t));
        assert_eq!(
            r("xyz").unwrap_err(),
            "Bytes#constructor: invalid hex string: xyz"
        );
        assert_eq!(
            r("abcd").unwrap_err(),
            "Bytes#checkByteLength: bytes length is 2 but expected 32 or 64"
        );
        assert_eq!(
            r("").unwrap_err(),
            "Bytes#constructor: constructor parameter is falsy: "
        );
        assert_eq!(r(&format!("0x{}", "AB".repeat(32))).unwrap(), [0xab; 32]);
        assert_eq!(r(&"ab".repeat(64)).unwrap().len(), 64);
    }

    #[test]
    fn upload_results_read_as_zod() {
        let read = |body: &str| upload_reference(body.as_bytes()).unwrap();
        assert_eq!(read(r#"{"reference":"ab"}"#), Ok(JsString::from("ab")));
        let issue = read("{}").unwrap_err();
        assert_eq!(
            issue.message(),
            "Invalid input: expected string, received undefined"
        );
        let issue = read("[1]").unwrap_err();
        assert_eq!(
            issue.message(),
            "Invalid input: expected object, received array"
        );
        assert!(upload_reference(b"<html>").is_err());
    }

    #[test]
    fn soc_references_read_as_string_of_or_empty() {
        let read = |body: &str| soc_reference(body.as_bytes()).unwrap();
        assert_eq!(read(r#"{"reference":"AB"}"#), Ok(JsString::from("AB")));
        assert_eq!(read("{}"), Ok(JsString::default()));
        assert_eq!(read(r#"{"reference":0}"#), Ok(JsString::default()));
        assert_eq!(read(r#"{"reference":12}"#), Ok(JsString::from("12")));
        assert_eq!(read(r#"{"reference":["a",[1,null]]}"#), Ok(JsString::from("a,1,")));
        assert_eq!(read(r#"{"reference":{}}"#), Ok(JsString::from("[object Object]")));
        assert_eq!(read("\"x\""), Ok(JsString::default()));
        assert_eq!(
            read("null"),
            Err(String::from("Cannot read properties of null (reading 'reference')"))
        );
    }
}
