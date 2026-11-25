//! `updateFeed` and `writeFeedEntry` (swarm-provider-ipc.js's
//! `handleUpdateFeed`, `handleWriteFeedEntry`; feed-service.js's
//! `updateFeed`, `writeFeedPayload`): a signed update of the site's own
//! feed, under the identity the feed was created with, else the active one
//! (`getFeedIdentity`).
//!
//! The core computes everything a page could otherwise name: the topic
//! `keccak256(utf8(key + "/" + name))`, the index, and the identifier
//! `keccak256(topic ‖ index as 8 bytes, big-endian)`.
//!
//! In today's order: the params, the feed grant, the feed's record, #89's
//! refusal, the readiness check, the vault (the owner), the history row,
//! one `/stamps` read, then, one write to a topic at a time
//! ([`crate::machine::Need::Lock`]):
//! - **the index:** an explicit one checked as #1057's `feedEntryExists`
//!   checks it (its SOC only; only a 404 frees it), else the lookup
//!   ([`super::feed_index::NextIndex`]: `feed_head` with
//!   `swarm-only-root-chunk`, then the head probe; deviation
//!   `index-probe`);
//! - **the update:** `updateFeed`'s `timestamp ‖ reference`; an entry of 1
//!   to 4,096 bytes itself; a larger one streamed to `POST /bytes` under
//!   the guard, its root computed as the bytes pass, and the node's
//!   reference checked against it (deviations `feed-wrap-root`,
//!   `reference-check`);
//! - **the signature,** the guard, `POST /soc/<o>/<id>`, checked against
//!   the SOC's own address; `updateFeed`'s last reference recorded; the
//!   row's update.
//!
//! Each guard, the re-check before the signature and the reference's
//! record (`afterEffect`, custody left out) read the live facts asked just
//! before them (design 0015's D1).
//!
//! A feed entry is at most 10 MiB (deviation `feed-entry-bound`, question
//! 3), refused with the params, where #1233 refuses it on browser main.

use fc_json::{JsString, JsValue, number_to_string};
use fc_swarm::PreparedChunk;
use fc_swarm::verify::{feed_update_address, feed_update_id, soc_address};

use super::body::{BodyWriter, Fault, Piece};
use super::feed_index::{Next, NextIndex, wrapping_index};
use super::writes::{
    Ended, Ending, Fail, add_row, batch, bytes_up, bytes_uploaded, closing, feed_not_granted,
    guard, inserted, owner, row, s, signature, signer_key, soc_up, soc_uploaded, stamps_call,
    still_here, unavailable, written,
};
use super::{live_of, permitted};
use crate::chunks::single_owner;
use crate::machine::node::BodyAbort;
use crate::machine::params::{feed_name, is_hex, require_params};
use crate::machine::{
    Approval, AskId, Closing, Cx, Effect, Event, Failure, Live, NodeCall, Outcome, Protocol,
    ReadyCheck, SignKey, SignSoc, SocKind, Step, StoreWrite, World, fail,
};
use crate::methods::limits::MAX_DATA_BYTES;
use crate::stamps::BatchId;
use crate::stores::feeds::FeedChange;
use crate::stores::manifests::Capability;
use crate::stores::{UNDEFINED, template};
use crate::value::{Bytes, Source, Value};

/// The page's data for a write: its bytes, or the part main holds them in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Data {
    Inline(Vec<u8>),
    Part { part: u32, len: u64 },
}

impl Data {
    fn len(&self) -> u64 {
        match self {
            Data::Inline(bytes) => bytes.len() as u64,
            Data::Part { len, .. } => *len,
        }
    }
}

/// A write's data param as `normalizePayloadParam` reads it: a string's
/// UTF-8, bytes `normalizeBytes` takes, or `None` for anything else.
pub(crate) fn data_of(value: &Value) -> Option<Data> {
    match value {
        Value::String(text) => Some(Data::Inline(text.as_str().as_bytes().to_vec())),
        Value::Bytes(Bytes { source, len, .. }) => Some(match source {
            Source::Inline(bytes) => Data::Inline(bytes.clone()),
            Source::Part(part) => Data::Part {
                part: *part,
                len: *len,
            },
        }),
        _ => None,
    }
}

/// Which write.
enum Kind {
    Update {
        /// `params.reference` as the page gave it.
        reference: JsString,
        bytes: [u8; 32],
        /// `bzz://${existingFeed.manifestReference}`.
        bzz_url: JsString,
    },
    Entry {
        data: Data,
        /// `params.index` as the page gave it.
        explicit: Option<f64>,
    },
}

/// `handleUpdateFeed` and `handleWriteFeedEntry`.
pub(crate) struct FeedWrite {
    approval: Option<Approval>,
    kind: Kind,
    name: JsString,
    topic: [u8; 32],
    identity: Option<JsValue>,
    key: SignKey,
    owner: [u8; 20],
    row: Option<i64>,
    /// The row's last update is asked.
    closed: bool,
    now: u64,
    batch: Option<BatchId>,
    /// The write's index, and the answer's.
    index: u64,
    shown: Value,
    stage: Stage,
}

enum Stage {
    Ready(AskId),
    Owner(AskId),
    Insert(AskId),
    Trim(AskId),
    Stamps(AskId),
    Lock(AskId),
    Lookup {
        id: AskId,
        next: NextIndex,
    },
    Exists {
        id: AskId,
        address: [u8; 32],
    },
    /// A large entry waits for its turn among the streaming uploads.
    Turn(AskId),
    /// The live facts for its upload's guard.
    UploadGuard(AskId),
    /// Its `POST /bytes`, the body hashed as it goes out.
    Upload {
        call: AskId,
        body: Box<BodyWriter>,
    },
    /// The live facts for the re-check before the signature.
    Recheck {
        id: AskId,
        span: u64,
        payload: Vec<u8>,
    },
    Sign(Box<Signing>),
    /// The live facts for the SOC upload's guard.
    Guard(Box<Signed>),
    SocUp {
        id: AskId,
        address: [u8; 32],
    },
    /// The live facts for `updateFeed`'s record (`afterEffect`).
    Kept(AskId),
    Record(AskId),
    Ending(Ending),
    Gone,
}

/// The update the vault signs.
struct Signing {
    id: AskId,
    identifier: [u8; 32],
    prepared: PreparedChunk,
    span: u64,
    payload: Vec<u8>,
}

/// The signed update, waiting for its upload's guard.
struct Signed {
    id: AskId,
    identifier: [u8; 32],
    signature: [u8; 65],
    span: u64,
    payload: Vec<u8>,
}

fn invalid(message: &str, reason: &str) -> Outcome {
    Failure::invalid_params(message, reason).into()
}

impl FeedWrite {
    /// `handleUpdateFeed`'s checks.
    pub(crate) fn update<W: World>(
        cx: &mut Cx<'_, W>,
        params: &Value,
        approval: Option<Approval>,
    ) -> Result<Self, Outcome> {
        permitted(cx)?;
        require_params(params)?;
        let name = match params.get("feedId") {
            Value::String(id) if !id.is_empty() => id.clone(),
            _ => return Err(invalid("feedId is required", "invalid_params")),
        };
        let reference = match params.get("reference") {
            Value::String(r) if is_hex(r, 64) => r.clone(),
            _ => {
                return Err(invalid(
                    "reference must be a 64-character hex string",
                    "invalid_reference",
                ));
            }
        };
        let bytes = crate::chunks::unhex::<32>(&reference.as_str().to_ascii_lowercase())
            .ok_or_else(Failure::internal_error)?;
        let feeds = cx.world.feeds();
        if !feeds.has_feed_grant(cx.origin) {
            return Err(feed_not_granted().into());
        }
        let Some(feed) = feeds.feed(cx.origin, &name) else {
            let message = crate::js::concat(&[&JsString::from("Feed not found: "), &name]);
            return Err(Failure::invalid_params(message, "feed_not_found").into());
        };
        let manifest = template(feed.get("manifestReference").unwrap_or(&UNDEFINED))
            .map_err(|thrown| Failure::internal(thrown.message))?;
        let bzz_url = JsString::from(format!("bzz://{manifest}"));
        let kind = Kind::Update {
            reference,
            bytes,
            bzz_url,
        };
        Self::begin(cx, approval, kind, name, &feed)
    }

    /// `handleWriteFeedEntry`'s checks.
    pub(crate) fn entry<W: World>(
        cx: &mut Cx<'_, W>,
        params: &Value,
        approval: Option<Approval>,
    ) -> Result<Self, Outcome> {
        permitted(cx)?;
        require_params(params)?;
        let name = feed_name(params.get("name"))
            .map_err(|m| Failure::invalid_params(m, "invalid_feed_name"))?
            .clone();
        let raw = params.get("data");
        if raw.is_nullish() {
            return Err(invalid("data is required", "invalid_params"));
        }
        let Some(data) = data_of(raw) else {
            return Err(invalid(
                "data must be a string, Uint8Array, or ArrayBuffer",
                "invalid_params",
            ));
        };
        // feed-entry-bound: publishData's limit, where #1233 checks it.
        let size = data.len();
        if size > MAX_DATA_BYTES {
            return Err(Failure::invalid_params_with(
                format!("Payload exceeds maximum size of {MAX_DATA_BYTES} bytes"),
                "payload_too_large",
                vec![
                    ("limit", Value::int(MAX_DATA_BYTES)),
                    ("actual", Value::int(size)),
                ],
            )
            .into());
        }
        let explicit = match params.get("index") {
            Value::Undefined | Value::Null => None,
            Value::Number(n) if crate::js::is_integer(*n) && *n >= 0.0 => Some(*n),
            _ => {
                return Err(invalid(
                    "index must be a non-negative integer",
                    "invalid_params",
                ));
            }
        };
        let feeds = cx.world.feeds();
        if !feeds.has_feed_grant(cx.origin) {
            return Err(feed_not_granted().into());
        }
        let Some(feed) = feeds.feed(cx.origin, &name) else {
            let message = crate::js::concat(&[
                &JsString::from("Feed not found: "),
                &name,
                &JsString::from(". Create it with createFeed first."),
            ]);
            return Err(Failure::invalid_params(message, "feed_not_found").into());
        };
        Self::begin(cx, approval, Kind::Entry { data, explicit }, name, &feed)
    }

    fn begin<W: World>(
        cx: &mut Cx<'_, W>,
        approval: Option<Approval>,
        kind: Kind,
        name: JsString,
        feed: &JsValue,
    ) -> Result<Self, Outcome> {
        let identity = cx.world.feeds().feed_identity(cx.origin, feed);
        unavailable(identity.as_ref())?;
        let topic = fc_swarm::feed::topic(&format!("{}/{}", cx.origin.as_str(), name.as_str()));
        Ok(FeedWrite {
            approval,
            kind,
            name,
            topic,
            identity,
            key: SignKey::BeeWallet,
            owner: [0; 20],
            row: None,
            closed: false,
            now: cx.world.now(),
            batch: None,
            index: 0,
            shown: Value::Undefined,
            stage: Stage::Ready(cx.ready(ReadyCheck::Publish)),
        })
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        self.now = cx.world.now();
        match std::mem::replace(&mut self.stage, Stage::Gone) {
            Stage::Ready(asked) if asked == id => {
                if let Err(step) = super::chunk_reads::ready(event) {
                    return step;
                }
                self.key = match signer_key(self.identity.as_ref()) {
                    Ok(key) => key,
                    Err(failure) => return fail(failure),
                };
                self.stage = Stage::Owner(cx.owner(self.key));
                Step::Wait
            }
            Stage::Owner(asked) if asked == id => {
                self.owner = match owner(self.key, event) {
                    Ok(owner) => owner,
                    Err(failure) => return fail(failure),
                };
                let entry = match &self.kind {
                    Kind::Update { .. } => row(&[
                        ("type", s("feed-update")),
                        ("name", JsValue::String(self.name.clone())),
                        ("status", s("uploading")),
                        ("origin", JsValue::String(cx.origin.clone())),
                    ]),
                    Kind::Entry { data, .. } => {
                        #[expect(
                            clippy::cast_precision_loss,
                            reason = "Buffer.byteLength, at most 10 MiB"
                        )]
                        let size = data.len() as f64;
                        row(&[
                            ("type", s("feed-entry")),
                            ("name", JsValue::String(self.name.clone())),
                            ("status", s("uploading")),
                            ("origin", JsValue::String(cx.origin.clone())),
                            ("bytesSize", JsValue::Number(size)),
                        ])
                    }
                };
                match add_row(cx, &entry) {
                    Ok(id) => {
                        self.stage = Stage::Insert(id);
                        Step::Wait
                    }
                    Err(failure) => fail(failure),
                }
            }
            Stage::Insert(asked) if asked == id => match inserted(cx, event) {
                Ok((row, trim)) => {
                    self.row = Some(row);
                    self.stage = Stage::Trim(trim);
                    Step::Wait
                }
                Err(failure) => fail(failure),
            },
            Stage::Trim(asked) if asked == id => match written(event) {
                Ok(()) => {
                    self.stage = Stage::Stamps(cx.whole(stamps_call()));
                    Step::Wait
                }
                Err(text) => self.end(cx, Err(Fail::text(text))),
            },
            Stage::Stamps(asked) if asked == id => {
                let size = match &self.kind {
                    Kind::Update { .. } => 4096,
                    Kind::Entry { data, .. } => data.len().max(4096),
                };
                match batch(event, size) {
                    Ok(batch) => {
                        self.batch = Some(batch);
                        self.stage = Stage::Lock(cx.lock(self.topic));
                        Step::Wait
                    }
                    Err(failure) => self.end(cx, Err(failure)),
                }
            }
            Stage::Lock(asked) if asked == id => {
                if !matches!(event, Event::Locked) {
                    return self.end(cx, Err(Fail::internal()));
                }
                let explicit = match &self.kind {
                    Kind::Entry { explicit, .. } => *explicit,
                    Kind::Update { .. } => None,
                };
                match explicit {
                    Some(n) => {
                        let index = wrapping_index(n);
                        self.index = index;
                        self.shown = Value::Number(n);
                        let address = feed_update_address(&self.owner, &self.topic, index);
                        let call = NodeCall::chunk(&address).with_feed(self.owner, index);
                        self.stage = Stage::Exists {
                            id: cx.whole(call),
                            address,
                        };
                    }
                    None => {
                        let (next, call) = NextIndex::start(self.owner, self.topic);
                        self.stage = Stage::Lookup {
                            id: cx.whole(call),
                            next,
                        };
                    }
                }
                Step::Wait
            }
            Stage::Lookup {
                id: asked,
                mut next,
            } if asked == id => {
                let step = match event {
                    Event::Reply(reply) => next.reply(&reply),
                    Event::Failed(failed) => next.failed(failed),
                    _ => return self.end(cx, Err(Fail::internal())),
                };
                match step {
                    Next::Call(call) => {
                        self.stage = Stage::Lookup {
                            id: cx.whole(call),
                            next,
                        };
                        Step::Wait
                    }
                    Next::Index(index) => {
                        self.index = index;
                        self.shown = Value::int(index);
                        self.write(cx)
                    }
                    Next::Error(message) => self.end(cx, Err(Fail::text(message))),
                    Next::Failed(failed) => self.end(cx, Err(Fail::transport(failed))),
                    // A write's lookup never answers a read's head.
                    Next::Head(_) => self.end(cx, Err(Fail::internal())),
                }
            }
            Stage::Exists { id: asked, address } if asked == id => {
                match entry_exists(&address, event) {
                    Ok(false) => self.write(cx),
                    Ok(true) => {
                        let message = format!(
                            "Feed entry already exists at index {}",
                            number_to_string(match self.shown {
                                Value::Number(n) => n,
                                _ => 0.0,
                            })
                        );
                        let page =
                            Failure::invalid_params(message.as_str(), "index_already_exists");
                        self.end(cx, Err(Fail::mapped(message, page)))
                    }
                    Err(failure) => self.end(cx, Err(failure)),
                }
            }
            Stage::Turn(asked) if asked == id => {
                if !matches!(event, Event::Turn) {
                    return self.end(cx, Err(Fail::internal()));
                }
                self.stage = Stage::UploadGuard(cx.live());
                Step::Wait
            }
            Stage::UploadGuard(asked) if asked == id => {
                let Some(live) = live_of(&event) else {
                    return self.end(cx, Err(Fail::internal()));
                };
                if let Err(refused) = guard(cx, live, self.approval, Capability::Feeds) {
                    return self.end(cx, Err(Fail::refused(refused)));
                }
                let (Kind::Entry { data, .. }, Some(batch)) = (&self.kind, &self.batch) else {
                    return self.end(cx, Err(Fail::internal()));
                };
                let piece = match data {
                    Data::Inline(bytes) => Piece::Own(bytes.clone()),
                    Data::Part { part, len } => Piece::Part {
                        part: *part,
                        len: *len,
                    },
                };
                let mut body = Box::new(BodyWriter::hashed(piece));
                let call = cx.whole(bytes_up(batch, body.total()));
                body.bind(call);
                self.stage = Stage::Upload { call, body };
                Step::Wait
            }
            Stage::Upload { call, body } if id == call || body.copies(id) => {
                self.upload(cx, call, body, id, event)
            }
            Stage::Recheck {
                id: asked,
                span,
                payload,
            } if asked == id => {
                let Some(live) = live_of(&event) else {
                    return self.end(cx, Err(Fail::internal()));
                };
                self.sign(cx, live, span, payload)
            }
            Stage::Sign(signing) if signing.id == id => {
                let sig = match signature(event, &self.owner, &signing.prepared) {
                    Ok(sig) => sig,
                    Err(failure) => return self.end(cx, Err(failure)),
                };
                // After the vault's wait, the guard owns the upload.
                let Signing {
                    identifier,
                    span,
                    payload,
                    ..
                } = *signing;
                self.stage = Stage::Guard(Box::new(Signed {
                    id: cx.live(),
                    identifier,
                    signature: sig,
                    span,
                    payload,
                }));
                Step::Wait
            }
            Stage::Guard(signed) if signed.id == id => {
                let Some(live) = live_of(&event) else {
                    return self.end(cx, Err(Fail::internal()));
                };
                if let Err(refused) = guard(cx, live, self.approval, Capability::Feeds) {
                    return self.end(cx, Err(Fail::refused(refused)));
                }
                let Some(batch) = &self.batch else {
                    return self.end(cx, Err(Fail::internal()));
                };
                let call = soc_up(
                    &self.owner,
                    &signed.identifier,
                    &signed.signature,
                    batch,
                    false,
                    signed.span,
                    &signed.payload,
                );
                self.stage = Stage::SocUp {
                    id: cx.whole(call),
                    address: soc_address(&signed.identifier, &self.owner),
                };
                Step::Wait
            }
            Stage::SocUp { id: asked, address } if asked == id => {
                if let Err(failure) = soc_uploaded(event, &address) {
                    return self.end(cx, Err(failure));
                }
                match &self.kind {
                    // `afterEffect`: the live facts first.
                    Kind::Update { .. } => {
                        self.stage = Stage::Kept(cx.live());
                        Step::Wait
                    }
                    Kind::Entry { .. } => {
                        let result = Value::object([("index", self.shown.clone())]);
                        self.end(cx, Ok((result, row(&[("status", s("completed"))]))))
                    }
                }
            }
            Stage::Kept(asked) if asked == id => {
                let Some(live) = live_of(&event) else {
                    return self.end(cx, Err(Fail::internal()));
                };
                match &self.kind {
                    // `afterEffect`: recorded only while the name answers;
                    // the write stands either way.
                    Kind::Update { .. } if !live.holds() => self.updated(cx),
                    Kind::Update { reference, .. } => {
                        let change = FeedChange::UpdateFeedReference {
                            key: cx.origin.clone(),
                            name: self.name.clone(),
                            reference: JsValue::String(reference.clone()),
                        };
                        self.stage = Stage::Record(cx.write(StoreWrite::Feeds(change)));
                        Step::Wait
                    }
                    Kind::Entry { .. } => self.end(cx, Err(Fail::internal())),
                }
            }
            Stage::Record(asked) if asked == id => {
                if let Err(text) = written(event) {
                    return self.end(cx, Err(Fail::text(text)));
                }
                self.updated(cx)
            }
            Stage::Ending(ending) if ending.id == id => match ending.on(cx, event) {
                Ended::Again(again) => {
                    self.stage = Stage::Ending(again);
                    Step::Wait
                }
                Ended::Step(step) => step,
            },
            _ => self.end(cx, Err(Fail::internal())),
        }
    }

    /// `updateFeed`'s answer and its row's update.
    fn updated<W: World>(&mut self, cx: &mut Cx<'_, W>) -> Step {
        let Kind::Update {
            reference, bzz_url, ..
        } = &self.kind
        else {
            return self.end(cx, Err(Fail::internal()));
        };
        let result = Value::object([
            ("feedId", Value::String(self.name.clone())),
            ("reference", Value::String(reference.clone())),
            ("bzzUrl", Value::String(bzz_url.clone())),
            ("index", self.shown.clone()),
        ]);
        #[expect(
            clippy::cast_precision_loss,
            reason = "the index as a JavaScript number"
        )]
        let index = JsValue::Number(self.index as f64);
        let updates = row(&[
            ("status", s("completed")),
            ("index", index),
            ("reference", JsValue::String(reference.clone())),
        ]);
        self.end(cx, Ok((result, updates)))
    }

    /// The index is known: the update, signed, or a large entry's upload
    /// first.
    fn write<W: World>(&mut self, cx: &mut Cx<'_, W>) -> Step {
        let payload = match &self.kind {
            Kind::Update { bytes, .. } => {
                // bee-js's update payload: unix seconds ‖ reference.
                let seconds = cx.world.now() / 1000;
                fc_swarm::feed::reference_payload(seconds, bytes).to_vec()
            }
            Kind::Entry { data, .. } => {
                if data.len() == 0 {
                    return self.end(
                        cx,
                        Err(Fail::mapped(
                            "A feed entry needs at least 1 byte of data",
                            Failure::invalid_params(
                                "Payload exceeds maximum SOC size",
                                "payload_too_large",
                            ),
                        )),
                    );
                }
                match data {
                    Data::Inline(bytes) if bytes.len() <= fc_swarm::CHUNK_SIZE => bytes.clone(),
                    // Main sends no part of 64 KiB or less.
                    Data::Part { len, .. } if *len <= fc_swarm::CHUNK_SIZE as u64 => {
                        return self.end(cx, Err(Fail::internal()));
                    }
                    _ => {
                        self.stage = Stage::Turn(cx.turn());
                        return Step::Wait;
                    }
                }
            }
        };
        let span = payload.len() as u64;
        self.recheck(cx, span, payload)
    }

    /// Before the signature, the live facts.
    fn recheck<W: World>(&mut self, cx: &mut Cx<'_, W>, span: u64, payload: Vec<u8>) -> Step {
        self.stage = Stage::Recheck {
            id: cx.live(),
            span,
            payload,
        };
        Step::Wait
    }

    /// The re-check on the live facts just asked, then the signature.
    fn sign<W: World>(
        &mut self,
        cx: &mut Cx<'_, W>,
        live: Live,
        span: u64,
        payload: Vec<u8>,
    ) -> Step {
        if let Err(moved) = still_here(live) {
            return self.end(cx, Err(Fail::refused(moved)));
        }
        let identifier = feed_update_id(&self.topic, self.index);
        let prepared = match fc_swarm::prepare_soc(&identifier, Some(span), &payload) {
            Ok(prepared) => prepared,
            Err(_) => return self.end(cx, Err(Fail::internal())),
        };
        let id = cx.sign(SignSoc {
            key: self.key,
            identifier,
            span,
            payload: payload.clone(),
            hold: None,
            kind: SocKind::Feed,
        });
        self.stage = Stage::Sign(Box::new(Signing {
            id,
            identifier,
            prepared,
            span,
            payload,
        }));
        Step::Wait
    }

    /// The large entry's upload: main's `swarm.body` and its credit, the
    /// part's bytes, then the node's answer, checked against the core's own
    /// root, which the SOC then wraps.
    fn upload<W: World>(
        &mut self,
        cx: &mut Cx<'_, W>,
        call: AskId,
        mut body: Box<BodyWriter>,
        id: AskId,
        event: Event,
    ) -> Step {
        let pumped = if id != call {
            body.part(cx, event)
        } else {
            match event {
                Event::BodyOpen => body.open(cx),
                Event::BodyCredit(bytes) => body.credit(cx, bytes),
                reply @ (Event::Reply(_) | Event::Failed(_)) => {
                    let whole = body.ended();
                    body.abort(cx, BodyAbort::Cancelled);
                    let reference = match bytes_uploaded(reply) {
                        Ok(reference) => reference,
                        Err(failure) => return self.end(cx, Err(failure)),
                    };
                    // reference-check: the node's reference is the core's
                    // own root, which the SOC wraps (feed-wrap-root).
                    let root = match body.root() {
                        Some(root) if whole && reference == root.address() => root,
                        _ => {
                            return self.end(
                                cx,
                                Err(Fail::text("The Swarm node returned another reference")),
                            );
                        }
                    };
                    return match fc_swarm::feed::Update::wrap(root) {
                        Ok(update) => self.recheck(cx, update.span(), update.payload().to_vec()),
                        Err(_) => self.end(cx, Err(Fail::internal())),
                    };
                }
                _ => {
                    body.abort(cx, BodyAbort::Cancelled);
                    return self.end(cx, Err(Fail::internal()));
                }
            }
        };
        match pumped {
            Ok(()) => {
                self.stage = Stage::Upload { call, body };
                Step::Wait
            }
            Err(fault) => {
                let why = match fault {
                    Fault::Part | Fault::Unreadable { .. } => BodyAbort::BodyStreamError,
                    Fault::PartLength | Fault::Internal => BodyAbort::Internal,
                };
                body.abort(cx, why);
                cx.cancel(call);
                match fault {
                    Fault::PartLength => Step::Done(Outcome::Protocol(Protocol::PartLength)),
                    Fault::Part | Fault::Unreadable { .. } | Fault::Internal => {
                        self.end(cx, Err(Fail::internal()))
                    }
                }
            }
        }
    }

    /// The terminal a large entry's opened body still needs when the
    /// request ends without its machine: `cancelled`, or `internal` at a
    /// protocol error, exactly once.
    pub(crate) fn terminal(&mut self, outcome: &Outcome) -> Option<Effect> {
        let why = match outcome {
            Outcome::Protocol(_) => BodyAbort::Internal,
            _ => BodyAbort::Cancelled,
        };
        let Stage::Upload { body, .. } = &mut self.stage else {
            return None;
        };
        let (id, out) = body.terminal(why)?;
        Some(Effect::Body { id, out })
    }

    /// What the request still writes when it ends without its machine.
    pub(crate) fn closing(&self, outcome: &Outcome) -> Option<Closing> {
        let (inserting, last) = match &self.stage {
            Stage::Insert(id) => (Some(*id), None),
            Stage::Ending(ending) => (None, Some(ending)),
            _ => (None, None),
        };
        closing(self.row, inserting, self.closed, last, outcome, self.now)
    }

    fn end<W: World>(
        &mut self,
        cx: &mut Cx<'_, W>,
        result: Result<(Value, JsValue), Fail>,
    ) -> Step {
        let Some(row) = self.row else {
            return fail(
                result
                    .err()
                    .map_or_else(Failure::internal_error, |f| f.page),
            );
        };
        self.closed = true;
        match Ending::start(cx, row, result) {
            Ok(ending) => {
                self.stage = Stage::Ending(ending);
                Step::Wait
            }
            Err(failure) => fail(failure),
        }
    }
}

/// `feedEntryExists`: only a 404 frees the index; a SOC at its address
/// (checked as `unmarshalSingleOwnerChunk` checks it) is an entry; any
/// other answer is the node's failure.
fn entry_exists(address: &[u8; 32], event: Event) -> Result<bool, Fail> {
    let reply = match event {
        Event::Reply(reply) => reply,
        Event::Failed(failed) => return Err(Fail::transport(failed)),
        _ => return Err(Fail::internal()),
    };
    if reply.status == 404 {
        return Ok(false);
    }
    if !reply.ok() {
        return Err(match reply.error(crate::errors::Site::BeeJs) {
            Ok(err) => Fail::thrown(&crate::errors::ServiceError::from(&err)),
            Err(failed) => Fail::transport(failed),
        });
    }
    single_owner(address, &reply.body).map_err(Fail::text)?;
    Ok(true)
}
