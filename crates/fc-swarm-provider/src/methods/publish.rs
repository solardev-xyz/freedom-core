//! The uploads: `publishData`, `publishFiles` and `publishChunk`
//! (swarm-provider-ipc.js's `handlePublishData`, `handlePublishFiles`,
//! `handlePublishChunk`; publish-service.js's `publishPageData` and
//! `publishFilesFromContent`; page-upload.js; chunk-service.js's
//! `publishChunk`), as design 0015's "Uploads" gives the path:
//!
//! 1. the params checked in today's order, with today's codes, reasons and
//!    texts;
//! 2. `shell.swarm_ready { check: "publish" }`;
//! 3. the history row (`addEntry`, then the bound: deviation
//!    `history-bound`);
//! 4. `/stamps` read once (deviation `stamps-one-read`) and the batch chosen
//!    by `selectBestBatch`;
//! 5. for a streamed body, the upload's turn among the four that stream;
//! 6. the effect's guard: the document still holds its key, and for a
//!    request a site's rule approved, the agent doesn't hold its tab and
//!    the rule still stands; the site is still connected;
//! 7. the upload: `POST /bzz` with one file (`{ base64 }` when the params
//!    carry it inline, else `{ stream }` from its part) or a tar (`{ stream
//!    }`, page-upload.js's ustar byte for byte, through `fc_swarm::tar`),
//!    or `POST /chunks` with span ‖ payload;
//! 8. the node's answer read as the reference reads it: page-upload.js's
//!    `{ reference }` and `swarm-tag`, or bee-js's for a chunk, whose
//!    reference the core checks against its own (deviation
//!    `reference-check`);
//! 9. for a collection, the tag's owner, while the document holds its key;
//!    the row updated; the answer.
//!
//! A failure after the row exists updates it `failed` with the text the
//! reference gives it (the service's error's message) before the answer.
//! A request that ends without its machine (a cancel, the deadline,
//! `busy`, a protocol error) leaves that update to [`Publish::closing`].

use fc_json::{JsString, JsValue, number_to_string};

use super::body::{BodyWriter, Fault, Piece};
use super::upload_status::{call_failed, reply_failed};
use super::{limits, no_address, permitted};
use crate::errors::{self, ServiceError, Site};
use crate::machine::node::{Body, BodyAbort, Failed, INLINE_BODY};
use crate::machine::params::{empty_options, require_params};
use crate::machine::{
    Approval, AskId, Capability, Cx, Event, Failure, Form, NodeCall, Outcome, Protocol, ReadyCheck,
    Reply, Step, StoreWrite, World, fail,
};
use crate::replies::{self, ChunkUpload, NO_REFERENCE_MESSAGE, PageUpload};
use crate::stamps::{SelectOptions, read_stamps, select_best_batch};
use crate::stores::history;
use crate::value::{Bytes, BytesKind, Source, Value};

/// Which upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Data,
    Files,
    Chunk,
}

/// What goes to the node.
#[derive(Debug)]
enum Upload {
    /// `publishData`: one file.
    File {
        /// `name || 'data'`, as the query writes it.
        name: String,
        content_type: JsString,
        data: Piece,
    },
    /// `publishFiles`: a tar of the files, in the page's order.
    Tar {
        files: Vec<(JsString, Piece)>,
        index_document: Option<JsString>,
    },
    /// `publishChunk`: span ‖ payload, and its address.
    Chunk { wire: Vec<u8>, address: [u8; 32] },
}

#[derive(Debug)]
enum Stage {
    Ready(AskId),
    Insert(AskId),
    Trim(AskId),
    Stamps(AskId),
    Turn(AskId),
    Upload(AskId),
    /// The row's last update, then the answer.
    Closing(AskId, Outcome),
}

/// One upload.
pub(crate) struct Publish {
    method: Method,
    approval: Option<Approval>,
    /// The history row's `name`.
    name: JsValue,
    /// Its `bytesSize`, and the size the batch must have room for.
    size: u64,
    upload: Upload,
    stage: Stage,
    row: Option<i64>,
    /// The row's last update is asked.
    closed: bool,
    batch: String,
    body: Option<BodyWriter>,
    /// The clock at the last answer, for the row's update when the request
    /// ends without the machine (which then has no world to read).
    now: u64,
}

/// A failure after the row exists: the row's text (the service's error's
/// message) and the page's error.
type Failing = (JsString, Failure);

impl Publish {
    pub(crate) fn start<W: World>(
        cx: &mut Cx<'_, W>,
        method: &str,
        params: &Value,
        approval: Option<Approval>,
    ) -> Result<Self, Outcome> {
        permitted(cx)?;
        admit(cx, approval)?;
        let (method, name, size, upload) = match method {
            "swarm_publishData" => publish_data(params)?,
            "swarm_publishFiles" => publish_files(params)?,
            _ => publish_chunk(params)?,
        };
        let ready = cx.ready(ReadyCheck::Publish);
        Ok(Publish {
            method,
            approval,
            name,
            size,
            upload,
            stage: Stage::Ready(ready),
            row: None,
            closed: false,
            batch: String::new(),
            body: None,
            now: cx.world.now(),
        })
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        self.now = cx.world.now();
        match self.stage {
            Stage::Ready(ask) if ask == id => match event {
                Event::Ready(Ok(())) => self.insert(cx),
                Event::Ready(Err(reason)) => fail(Failure::node_unavailable(&reason)),
                _ => fail(Failure::internal_error()),
            },
            Stage::Insert(ask) if ask == id => match event {
                Event::Inserted(Ok(rowid)) => {
                    self.row = Some(rowid);
                    let trim = history::trim(Some(rowid));
                    self.stage = Stage::Trim(cx.write(StoreWrite::History(vec![trim])));
                    Step::Wait
                }
                Event::Inserted(Err(text)) => fail(Failure::internal(text)),
                _ => fail(Failure::internal_error()),
            },
            Stage::Trim(ask) if ask == id => match event {
                Event::Written(Ok(())) => {
                    self.stage = Stage::Stamps(cx.whole(NodeCall::stamps()));
                    Step::Wait
                }
                Event::Written(Err(text)) => {
                    self.close_failed(cx, (text.clone(), Failure::internal(text)))
                }
                _ => self.close_failed(cx, internal()),
            },
            Stage::Stamps(ask) if ask == id => match self.batch_of(event) {
                Ok(batch) => {
                    self.batch = batch;
                    if self.streams() {
                        self.stage = Stage::Turn(cx.turn());
                        Step::Wait
                    } else {
                        self.send(cx)
                    }
                }
                Err(failing) => self.close_failed(cx, failing),
            },
            Stage::Turn(ask) if ask == id => match event {
                Event::Turn => self.send(cx),
                _ => self.close_failed(cx, internal()),
            },
            Stage::Upload(ask) if ask == id => self.upload_event(cx, event),
            Stage::Upload(_) if self.body.as_ref().is_some_and(|b| b.copies(id)) => {
                let Some(body) = self.body.as_mut() else {
                    return self.close_failed(cx, internal());
                };
                match body.part(cx, event) {
                    Ok(()) => Step::Wait,
                    Err(fault) => self.fault(cx, fault),
                }
            }
            Stage::Closing(ask, _) if ask == id => {
                let Stage::Closing(_, outcome) =
                    std::mem::replace(&mut self.stage, Stage::Ready(ask))
                else {
                    return fail(Failure::internal_error());
                };
                match event {
                    Event::Written(Ok(())) => Step::Done(outcome),
                    // `updateEntry` threw: the provider's catch answers its
                    // message.
                    Event::Written(Err(text)) => fail(Failure::internal(text)),
                    _ => fail(Failure::internal_error()),
                }
            }
            _ => self.close_failed(cx, internal()),
        }
    }

    /// What the request still writes when it ends without its machine: the
    /// row `failed`, with the request's end as its text (`cancelled`,
    /// `busy`, `Internal error`). Nothing once the machine asked for the
    /// row's last update, which is made whatever comes after.
    pub(crate) fn closing(&self, outcome: &Outcome) -> Option<StoreWrite> {
        let row = self.row?;
        if self.closed {
            return None;
        }
        let text = match outcome {
            Outcome::Result(_) => return None,
            Outcome::Error(failure) => failure.message.clone(),
            Outcome::Cancelled => JsString::from("cancelled"),
            Outcome::Protocol(_) => Failure::internal_error().message,
        };
        update(row, &failed_update(&text), self.now).map(|s| StoreWrite::History(vec![s]))
    }

    /// Whether the body streams (a tar, or a file the params carry as a
    /// part).
    fn streams(&self) -> bool {
        match &self.upload {
            Upload::File { data, .. } => file_streams(data),
            Upload::Tar { .. } => true,
            Upload::Chunk { .. } => false,
        }
    }

    /// `addEntry({ type, name, status: 'uploading', origin, bytesSize })`.
    fn insert<W: World>(&mut self, cx: &mut Cx<'_, W>) -> Step {
        let kind = match self.method {
            Method::Data => "data",
            Method::Files => "directory",
            Method::Chunk => "chunk",
        };
        let mut entry = JsValue::Object(Vec::new());
        entry.set("type", JsValue::String(JsString::from(kind)));
        entry.set("name", self.name.clone());
        entry.set("status", JsValue::String(JsString::from("uploading")));
        entry.set("origin", JsValue::String(cx.origin.clone()));
        entry.set("bytesSize", number(self.size));
        match history::add_entry(&entry, cx.world.now()) {
            Ok(insert) => {
                self.stage = Stage::Insert(cx.write(StoreWrite::HistoryInsert(insert)));
                Step::Wait
            }
            // What binding throws, through the provider's catch.
            Err(thrown) => fail(Failure::internal(thrown.message.as_str())),
        }
    }

    /// The batch from `/stamps`' answer, by `selectBestBatch`.
    fn batch_of(&self, event: Event) -> Result<String, Failing> {
        let reply = match event {
            Event::Reply(reply) => reply,
            Event::Failed(failed) => return Err(failed_call(failed)),
            _ => return Err(internal()),
        };
        if !reply.ok() {
            return Err(match reply.error(Site::BeeJs) {
                Ok(err) => write_error(&ServiceError::from(&err)),
                Err(class) => failed_call(class),
            });
        }
        let stamps = read_stamps(&reply.body).map_err(|err| page_only(reply_failed(err)))?;
        let (size, options) = match self.method {
            // `selectChunkBatch`: room for a chunk, and `null` when none.
            Method::Chunk => (4096, SelectOptions::default()),
            _ => (
                self.size,
                SelectOptions {
                    require_capacity: true,
                    allow_full_mutable: false,
                },
            ),
        };
        let selection = select_best_batch(&stamps, size, options)
            .map_err(|err| write_error(&ServiceError::from(&err)))?;
        match selection.outcome {
            Ok(Some(batch)) => Ok(batch.to_hex()),
            Ok(None) => Err(write_error(&ServiceError::no_usable_batch())),
            Err(postage) => Err(write_error(&ServiceError::from(&postage))),
        }
    }

    /// The effect's guard, then the upload.
    fn send<W: World>(&mut self, cx: &mut Cx<'_, W>) -> Step {
        if let Err(refused) = guard(cx, self.approval) {
            return self.close_failed(cx, (refused.message.clone(), refused));
        }
        let batch = self.batch.clone();
        let call = match &mut self.upload {
            Upload::File {
                name,
                content_type,
                data,
            } => {
                let content_type = match header_value("content-type", content_type) {
                    Ok(value) => value,
                    Err(failing) => return self.close_failed(cx, failing),
                };
                let headers = vec![
                    ("content-type".to_owned(), content_type),
                    ("swarm-postage-batch-id".to_owned(), batch),
                    ("swarm-pin".to_owned(), "true".to_owned()),
                    ("swarm-deferred-upload".to_owned(), "false".to_owned()),
                ];
                let query = vec![("name".to_owned(), std::mem::take(name))];
                let data = std::mem::replace(data, Piece::Own(Vec::new()));
                let body = match data {
                    Piece::Own(bytes) if bytes.len() <= INLINE_BODY => Body::Base64(bytes),
                    data => {
                        let writer = BodyWriter::file(data);
                        let bytes = writer.total();
                        self.body = Some(writer);
                        Body::Stream { bytes }
                    }
                };
                NodeCall::upload(Form::BzzFile, "/bzz", query, headers, body)
            }
            Upload::Tar {
                files,
                index_document,
            } => {
                let mut headers = vec![
                    ("content-type".to_owned(), "application/x-tar".to_owned()),
                    ("swarm-collection".to_owned(), "true".to_owned()),
                    ("swarm-postage-batch-id".to_owned(), batch),
                    ("swarm-pin".to_owned(), "true".to_owned()),
                    ("swarm-deferred-upload".to_owned(), "true".to_owned()),
                ];
                // `options.indexDocument || (index.html at the top)`.
                let index = index_document.clone().or_else(|| {
                    files
                        .iter()
                        .any(|(path, _)| *path == "index.html")
                        .then(|| JsString::from("index.html"))
                });
                if let Some(index) = index {
                    match header_value("swarm-index-document", &index) {
                        Ok(value) => headers.push(("swarm-index-document".to_owned(), value)),
                        Err(failing) => return self.close_failed(cx, failing),
                    }
                }
                // `Math.floor(Date.now() / 1000)`, each header's time.
                let mtime = cx.world.now() / 1000;
                let entries = std::mem::take(files)
                    .into_iter()
                    .map(|(path, piece)| (path.as_str().to_owned(), piece))
                    .collect();
                let Some(writer) = BodyWriter::tar(entries, mtime) else {
                    return self.close_failed(cx, internal());
                };
                let bytes = writer.total();
                self.body = Some(writer);
                NodeCall::upload(
                    Form::BzzTar,
                    "/bzz",
                    Vec::new(),
                    headers,
                    Body::Stream { bytes },
                )
            }
            Upload::Chunk { wire, .. } => {
                let headers = vec![
                    (
                        "content-type".to_owned(),
                        "application/octet-stream".to_owned(),
                    ),
                    ("swarm-postage-batch-id".to_owned(), batch),
                    ("swarm-pin".to_owned(), "true".to_owned()),
                    ("swarm-deferred-upload".to_owned(), "false".to_owned()),
                ];
                NodeCall::upload(
                    Form::ChunkUp,
                    "/chunks",
                    Vec::new(),
                    headers,
                    Body::Base64(std::mem::take(wire)),
                )
            }
        };
        let id = cx.whole(call);
        if let Some(body) = self.body.as_mut() {
            body.bind(id);
        }
        self.stage = Stage::Upload(id);
        Step::Wait
    }

    /// An answer to the upload call: main's `swarm.body` and its credit,
    /// then the node's answer.
    fn upload_event<W: World>(&mut self, cx: &mut Cx<'_, W>, event: Event) -> Step {
        let reply = match event {
            Event::BodyOpen | Event::BodyCredit(_) => {
                let Some(body) = self.body.as_mut() else {
                    return self.close_failed(cx, internal());
                };
                let pumped = match event {
                    Event::BodyOpen => body.open(cx),
                    Event::BodyCredit(bytes) => body.credit(cx, bytes),
                    _ => Ok(()),
                };
                return match pumped {
                    Ok(()) => Step::Wait,
                    Err(fault) => self.fault(cx, fault),
                };
            }
            Event::Reply(reply) => reply,
            Event::Failed(failed) => {
                self.stop_body(cx);
                return self.close_failed(cx, failed_call(failed));
            }
            _ => {
                self.stop_body(cx);
                return self.close_failed(cx, internal());
            }
        };
        let unsent = self.body.as_ref().is_some_and(|b| !b.ended());
        self.stop_body(cx);
        match self.method {
            Method::Chunk => self.chunk_answer(cx, &reply),
            _ if !reply.ok() => {
                let err = if (300..400).contains(&reply.status) {
                    errors::page_upload_redirect(reply.status, &reply.status_text)
                } else {
                    match reply.error(Site::PageUpload) {
                        Ok(err) => err,
                        Err(class) => return self.close_failed(cx, failed_call(class)),
                    }
                };
                self.close_failed(cx, write_error(&ServiceError::from(&err)))
            }
            // A success before the node took the whole body can't be the
            // upload's.
            _ if unsent => self.close_failed(
                cx,
                write_error(&ServiceError::plain(JsString::from(
                    "The node answered before it had taken the whole upload",
                ))),
            ),
            _ => self.page_answer(cx, &reply),
        }
    }

    /// page-upload.js's `uploadResult`, then the service's result, the
    /// tag's owner for a collection, and the row.
    fn page_answer<W: World>(&mut self, cx: &mut Cx<'_, W>, reply: &Reply) -> Step {
        let tag = reply.header("swarm-tag").map(|h| h.text());
        let (reference, tag_uid) = match replies::page_upload(&reply.body, tag.as_deref()) {
            Ok(PageUpload::Ok { reference, tag_uid }) => (reference, tag_uid),
            Ok(PageUpload::NoReference) => {
                return self.close_failed(
                    cx,
                    write_error(&ServiceError::plain(JsString::from(NO_REFERENCE_MESSAGE))),
                );
            }
            Err(err) => return self.close_failed(cx, page_only(reply_failed(err))),
        };
        let bzz_url = format!("bzz://{reference}");
        let tag_value = tag_uid.map_or(Value::Null, Value::int);
        let mut result = vec![
            ("reference", Value::str(&reference)),
            ("bzzUrl", Value::str(&bzz_url)),
        ];
        if self.method == Method::Files {
            if let Some(tag) = tag_uid
                && cx.name_holds()
                && cx.key_holds()
            {
                // `afterEffect`: held under the key only while the document
                // still holds it.
                cx.world.tags().set(tag, cx.origin.clone());
            }
            result.push(("tagUid", tag_value));
        }
        let mut row = JsValue::Object(Vec::new());
        row.set("status", text("completed"));
        row.set("reference", text(&reference));
        row.set("bzzUrl", text(&bzz_url));
        row.set("tagUid", tag_uid.map_or(JsValue::Null, number));
        row.set("batchIdUsed", text(&self.batch));
        row.set("bytesSize", number(self.size));
        self.close(cx, row, Outcome::Result(Value::object(result)))
    }

    /// bee-js's reading of `POST /chunks`' answer, then the core's check of
    /// the node's reference (deviation `reference-check`).
    fn chunk_answer<W: World>(&mut self, cx: &mut Cx<'_, W>, reply: &Reply) -> Step {
        if !reply.ok() {
            return self.close_failed(
                cx,
                match reply.error(Site::BeeJs) {
                    Ok(err) => write_error(&ServiceError::from(&err)),
                    Err(class) => failed_call(class),
                },
            );
        }
        let Upload::Chunk { address, .. } = &self.upload else {
            return self.close_failed(cx, internal());
        };
        let address = *address;
        let tag = reply.header("swarm-tag").map(|h| h.text());
        match replies::chunk_upload(&reply.body, tag.as_deref()) {
            Ok(node) if node == address => {}
            Ok(_) => {
                return self.close_failed(
                    cx,
                    write_error(&ServiceError::plain(JsString::from(
                        OTHER_REFERENCE_MESSAGE,
                    ))),
                );
            }
            Err(ChunkUpload::NotJson) => {
                return self.close_failed(cx, page_only(errors::reply_not_json().into()));
            }
            Err(ChunkUpload::TooDeep) => return self.close_failed(cx, failed_call(Failed::Error)),
            Err(ChunkUpload::TooLarge) => {
                return self.close_failed(cx, failed_call(Failed::TooLarge));
            }
            Err(ChunkUpload::Refused(message)) => {
                return self.close_failed(cx, write_error(&ServiceError::plain(message)));
            }
        }
        let reference = crate::chunks::hex(&address);
        let mut row = JsValue::Object(Vec::new());
        row.set("status", text("completed"));
        row.set("reference", text(&reference));
        row.set("batchIdUsed", text(&self.batch));
        self.close(
            cx,
            row,
            Outcome::Result(Value::object([("reference", Value::str(&reference))])),
        )
    }

    /// Stops a body that is still being written.
    fn stop_body<W: World>(&mut self, cx: &mut Cx<'_, W>) {
        if let Some(body) = self.body.as_mut() {
            body.abort(cx, BodyAbort::Cancelled);
        }
    }

    /// The body stopped: a part main couldn't stream, or one of another
    /// length than its params gave (a protocol error).
    fn fault<W: World>(&mut self, cx: &mut Cx<'_, W>, fault: Fault) -> Step {
        let why = match fault {
            Fault::Part => BodyAbort::BodyStreamError,
            Fault::PartLength | Fault::Internal => BodyAbort::Internal,
        };
        if let Some(body) = self.body.as_mut() {
            body.abort(cx, why);
        }
        if let Stage::Upload(call) = self.stage {
            cx.cancel(call);
        }
        match fault {
            Fault::PartLength => Step::Done(Outcome::Protocol(Protocol::PartLength)),
            Fault::Part | Fault::Internal => self.close_failed(cx, internal()),
        }
    }

    /// The row `failed` with the failure's text, then the page's error.
    fn close_failed<W: World>(&mut self, cx: &mut Cx<'_, W>, (text, failure): Failing) -> Step {
        self.close(cx, failed_update(&text), Outcome::Error(failure))
    }

    /// The row's last update, then `outcome`; at once when there's no row.
    fn close<W: World>(&mut self, cx: &mut Cx<'_, W>, updates: JsValue, outcome: Outcome) -> Step {
        let Some(row) = self.row else {
            return Step::Done(outcome);
        };
        if self.closed {
            return Step::Done(outcome);
        }
        self.closed = true;
        match update(row, &updates, cx.world.now()) {
            Some(statement) => {
                let id = cx.write(StoreWrite::History(vec![statement]));
                self.stage = Stage::Closing(id, outcome);
                Step::Wait
            }
            None => fail(Failure::internal_error()),
        }
    }
}

/// Whether one file's body streams: a part, or (which main doesn't send)
/// inline bytes past a `{ base64 }` body's 64 KiB.
fn file_streams(data: &Piece) -> bool {
    match data {
        Piece::Own(bytes) => bytes.len() > INLINE_BODY,
        Piece::Part { .. } => true,
    }
}

/// The core's text for a node that answered a chunk upload with another
/// reference than the chunk's (deviation `reference-check`).
pub const OTHER_REFERENCE_MESSAGE: &str = "The Swarm node returned another reference";

/// The admission of a request a site's rule approved (design 0015,
/// "Methods main calls": `approval`): the agent mustn't hold the tab, and
/// the rule must stand; otherwise `agent_custody`, or `no_rule`, which only
/// a main bug reaches.
fn admit<W: World>(cx: &Cx<'_, W>, approval: Option<Approval>) -> Result<(), Outcome> {
    if approval != Some(Approval::Auto) {
        return Ok(());
    }
    if cx.agent() {
        return Err(Failure::not_authorized("agent_custody").into());
    }
    if !cx.auto_approve(Capability::Publish) {
        return Err(Failure::not_authorized("no_rule").into());
    }
    Ok(())
}

/// The effect's guard (page-swarm.js's `guardEffect`, then the provider's
/// `whileGranted`), after the upload's last wait, in its order: the name
/// still binds the key; for a request the site's rule approved, the agent
/// doesn't hold its tab and the rule stands; the document is still under
/// its key; the site is still connected.
fn guard<W: World>(cx: &Cx<'_, W>, approval: Option<Approval>) -> Result<(), Failure> {
    if !cx.name_holds() {
        return Err(no_address());
    }
    if approval == Some(Approval::Auto) {
        if cx.agent() {
            return Err(Failure::not_authorized("agent_custody"));
        }
        if !cx.auto_approve(Capability::Publish) {
            return Err(Failure::not_authorized("not_auto_approved"));
        }
    }
    if !cx.key_holds() {
        return Err(no_address());
    }
    if !cx.connected() {
        return Err(Failure::not_connected());
    }
    Ok(())
}

/// A header value as Node's `http` takes it (`checkInvalidHeaderChar`):
/// tab, and U+0020 to U+007E and U+0080 to U+00FF (each sent as its one
/// latin1 byte); anything else throws before the request goes.
fn header_value(name: &str, value: &JsString) -> Result<String, Failing> {
    let ok = value
        .units()
        .all(|u| u == 0x09 || (0x20..=0x7e).contains(&u) || (0x80..=0xff).contains(&u));
    if ok {
        return Ok(value.as_str().to_owned());
    }
    Err(write_error(&ServiceError::plain(JsString::from(format!(
        "Invalid character in header content [\"{name}\"]"
    )))))
}

/// `nodeWriteError(err)` for a service's error, and its message for the row.
fn write_error(err: &ServiceError) -> Failing {
    (err.message.clone(), errors::node_write_error(err).into())
}

/// A failure the core gives itself (`busy`, a reply past its cap, a reply
/// that isn't JSON, a transport class's text): the row takes its text.
fn page_only(failure: Failure) -> Failing {
    (failure.message.clone(), failure)
}

/// A call that failed before any reply.
fn failed_call(failed: Failed) -> Failing {
    page_only(call_failed(failed))
}

/// -32603 `Internal error`: what only a core or main bug reaches.
fn internal() -> Failing {
    page_only(Failure::internal_error())
}

/// `updateEntry(row, updates)`'s statement at `now` (its `completed_at`
/// for a final status).
fn update(row: i64, updates: &JsValue, now: u64) -> Option<history::Statement> {
    #[expect(
        clippy::cast_precision_loss,
        reason = "better-sqlite3 answers lastInsertRowid as a JavaScript number"
    )]
    let id = JsValue::Number(row as f64);
    history::update_entry(&id, updates, now).ok()
}

/// `{ status: 'failed', errorMessage }`.
fn failed_update(message: &JsString) -> JsValue {
    let mut row = JsValue::Object(Vec::new());
    row.set("status", text("failed"));
    row.set("errorMessage", JsValue::String(message.clone()));
    row
}

fn text(s: &str) -> JsValue {
    JsValue::String(JsString::from(s))
}

fn number(n: u64) -> JsValue {
    #[expect(
        clippy::cast_precision_loss,
        reason = "sizes and tags below 2^53, as JavaScript holds them"
    )]
    JsValue::Number(n as f64)
}

// ---------------------------------------------------------------------------
// The params, checked in today's order.

/// `handlePublishData`'s checks: `{ data, contentType, name }`.
fn publish_data(params: &Value) -> Result<(Method, JsValue, u64, Upload), Outcome> {
    require_params(params)?;
    let data = params.get("data");
    if data.is_nullish() {
        return Err(Failure::invalid_params("data is required", "invalid_params").into());
    }
    let content_type = match params.get("contentType") {
        Value::String(s) if !s.is_empty() => s.clone(),
        _ => {
            return Err(
                Failure::invalid_params("contentType is required", "missing_content_type").into(),
            );
        }
    };
    // A string or bytes (Buffer, Uint8Array, ArrayBuffer, a Buffer's JSON).
    let Some(piece) = string_data(data).or_else(|| bytes_of(data)) else {
        return Err(not_bytes().into());
    };
    let size = piece.len();
    if size > limits::MAX_DATA_BYTES {
        return Err(Failure::invalid_params_with(
            format!(
                "Payload exceeds maximum size of {} bytes",
                limits::MAX_DATA_BYTES
            ),
            "payload_too_large",
            vec![
                ("limit", Value::int(limits::MAX_DATA_BYTES)),
                ("actual", Value::int(size)),
            ],
        )
        .into());
    }
    let name = params.get("name");
    let query_name = if name.truthy() {
        to_text(name)
    } else {
        "data".to_owned()
    };
    let row_name = if name.truthy() {
        js_value(name)
    } else {
        text("Published data")
    };
    Ok((
        Method::Data,
        row_name,
        size,
        Upload::File {
            name: query_name,
            content_type,
            data: piece,
        },
    ))
}

/// `handlePublishFiles`'s checks: `{ files: [{ path, bytes }], indexDocument }`.
fn publish_files(params: &Value) -> Result<(Method, JsValue, u64, Upload), Outcome> {
    require_params(params)?;
    let files = match params.get("files") {
        Value::Array(files) if !files.is_empty() => files,
        _ => {
            return Err(
                Failure::invalid_params("files must be a non-empty array", "empty_files").into(),
            );
        }
    };
    if files.len() as u64 > limits::MAX_FILE_COUNT {
        return Err(Failure::invalid_params_with(
            format!("File count exceeds maximum of {}", limits::MAX_FILE_COUNT),
            "too_many_files",
            vec![
                ("limit", Value::int(limits::MAX_FILE_COUNT)),
                ("actual", Value::int(files.len() as u64)),
            ],
        )
        .into());
    }
    let mut seen: Vec<JsString> = Vec::with_capacity(files.len());
    let mut total: u64 = 0;
    let mut entries = Vec::with_capacity(files.len());
    for (i, file) in files.iter().enumerate() {
        let file = file.as_ref().unwrap_or(&crate::value::UNDEFINED);
        if !file.truthy() || file.type_of() != "object" {
            return Err(Failure::invalid_params(
                format!("files[{i}] is not a valid file object"),
                "invalid_params",
            )
            .into());
        }
        let path = file.get("path");
        if let Err(message) = virtual_path(path) {
            return Err(Failure::invalid_params(
                crate::js::concat(&[&JsString::from(format!("files[{i}].path: ")), &message]),
                "invalid_path",
            )
            .into());
        }
        let Value::String(path) = path else {
            return Err(Failure::internal_error().into());
        };
        if seen.contains(path) {
            return Err(Failure::invalid_params_with(
                crate::js::concat(&[&JsString::from("Duplicate path: "), path]),
                "duplicate_path",
                vec![("path", Value::String(path.clone()))],
            )
            .into());
        }
        seen.push(path.clone());
        let Some(piece) = bytes_of(file.get("bytes")) else {
            return Err(Failure::invalid_params(
                format!("files[{i}].bytes must be a Buffer, Uint8Array, or ArrayBuffer"),
                "invalid_params",
            )
            .into());
        };
        total = total.saturating_add(piece.len());
        entries.push((path.clone(), piece));
    }
    if total > limits::MAX_FILES_BYTES {
        return Err(Failure::invalid_params_with(
            format!(
                "Total size exceeds maximum of {} bytes",
                limits::MAX_FILES_BYTES
            ),
            "payload_too_large",
            vec![
                ("limit", Value::int(limits::MAX_FILES_BYTES)),
                ("actual", Value::int(total)),
            ],
        )
        .into());
    }
    let index = params.get("indexDocument");
    let index_document = match index {
        Value::Undefined | Value::Null => None,
        Value::String(s) if seen.contains(s) => Some(s.clone()),
        _ => {
            return Err(Failure::invalid_params(
                "indexDocument must match an existing file path",
                "invalid_index_document",
            )
            .into());
        }
    };
    // `indexDocument || `${n} files``.
    let row_name = match &index_document {
        Some(s) if !s.is_empty() => JsValue::String(s.clone()),
        _ => text(&format!("{} files", entries.len())),
    };
    Ok((
        Method::Files,
        row_name,
        total,
        Upload::Tar {
            files: entries,
            index_document,
        },
    ))
}

/// `handlePublishChunk`'s checks: `{ data, span, options }`, and the chunk
/// bee-js makes of them (`makeContentAddressedChunk`).
fn publish_chunk(params: &Value) -> Result<(Method, JsValue, u64, Upload), Outcome> {
    require_params(params)?;
    empty_options(params.get("options"))?;
    let data = params.get("data");
    let payload = if data.is_nullish() {
        None
    } else {
        string_data(data).or_else(|| bytes_of(data))
    };
    let Some(payload) = payload else {
        return Err(not_bytes().into());
    };
    let Piece::Own(payload) = payload else {
        // A part is past 64 KiB, and so past a chunk's 4,096 bytes.
        return Err(too_large_chunk(payload.len()).into());
    };
    if payload.is_empty() {
        return Err(Failure::invalid_params("data must not be empty", "invalid_params").into());
    }
    let max = limits::MAX_CHUNK_PAYLOAD_BYTES;
    if payload.len() as u64 > max {
        return Err(too_large_chunk(payload.len() as u64).into());
    }
    let span = span_of(params.get("span")).ok_or_else(|| {
        Failure::invalid_params(
            "span must be a non-negative unsigned 64-bit integer",
            "invalid_span",
        )
    })?;
    // core-sdk's `span ? Span.fromBigInt(span) : <the payload's length>`:
    // a span of 0n is falsy, so it is the payload's length too.
    let span = span
        .filter(|s| *s != 0)
        .unwrap_or(payload.len() as u64)
        .to_le_bytes();
    let address =
        fc_swarm::verify::address_of(&span, &payload).ok_or_else(Failure::internal_error)?;
    let size = payload.len() as u64;
    let mut wire = span.to_vec();
    wire.extend_from_slice(&payload);
    Ok((
        Method::Chunk,
        text("CAC chunk"),
        size,
        Upload::Chunk { wire, address },
    ))
}

/// `Payload exceeds maximum chunk size of 4096 bytes`.
fn too_large_chunk(actual: u64) -> Failure {
    let max = limits::MAX_CHUNK_PAYLOAD_BYTES;
    Failure::invalid_params_with(
        format!("Payload exceeds maximum chunk size of {max} bytes"),
        "payload_too_large",
        vec![("limit", Value::int(max)), ("actual", Value::int(actual))],
    )
}

/// `data must be a string, Uint8Array, or ArrayBuffer`.
fn not_bytes() -> Failure {
    Failure::invalid_params(
        "data must be a string, Uint8Array, or ArrayBuffer",
        "invalid_params",
    )
}

/// A string where a method reads data: its UTF-8 (`Buffer.from(s,
/// 'utf-8')`, a lone surrogate as U+FFFD), inline or as a part.
fn string_data(value: &Value) -> Option<Piece> {
    match value {
        Value::Bytes(b) if b.kind == BytesKind::String => Some(piece(b)),
        Value::String(s) => Some(Piece::Own(s.as_str().as_bytes().to_vec())),
        _ => None,
    }
}

/// `normalizeBytes(value)`: a `Buffer`, a `Uint8Array`, an `ArrayBuffer`
/// or a Buffer's JSON; anything else (a string among them) is not bytes.
fn bytes_of(value: &Value) -> Option<Piece> {
    match value {
        Value::Bytes(b) if b.kind != BytesKind::String => Some(piece(b)),
        _ => None,
    }
}

fn piece(bytes: &Bytes) -> Piece {
    match &bytes.source {
        Source::Inline(data) => Piece::Own(data.clone()),
        Source::Part(part) => Piece::Part {
            part: *part,
            len: bytes.len,
        },
    }
}

/// `validateSpan(span)`: `None` where it refuses; `Some(None)` for no span.
fn span_of(value: &Value) -> Option<Option<u64>> {
    match value {
        Value::Undefined | Value::Null => Some(None),
        Value::Number(n) => {
            // `Number.isInteger`, `>= 0` and `Number.isSafeInteger` (-0 is
            // 0).
            if !n.is_finite() || n.trunc() != *n || *n < 0.0 || *n > 9_007_199_254_740_991.0 {
                return None;
            }
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "a safe non-negative integer"
            )]
            Some(Some(*n as u64))
        }
        Value::BigInt(text) => text.parse::<u64>().ok().map(Some),
        _ => None,
    }
}

/// The reference's `WINDOWS_RESERVED_NAMES` over a segment's stem
/// (`segment.split('.')[0].replace(/[ .]+$/, '')`), case-folded as a
/// non-Unicode `/i` folds: ASCII letters only.
fn is_windows_reserved(segment: &JsString) -> bool {
    let units: Vec<u16> = segment.units().collect();
    let stem_end = units
        .iter()
        .position(|u| *u == u16::from(b'.'))
        .unwrap_or(units.len());
    let mut stem = &units[..stem_end];
    while let [rest @ .., last] = stem
        && (*last == u16::from(b' ') || *last == u16::from(b'.'))
    {
        stem = rest;
    }
    let lower: Vec<u16> = stem
        .iter()
        .map(|u| match u8::try_from(*u) {
            Ok(b) if b.is_ascii_uppercase() => u16::from(b.to_ascii_lowercase()),
            _ => *u,
        })
        .collect();
    let is = |word: &str| lower.iter().copied().eq(word.encode_utf16());
    if ["con", "prn", "aux", "nul", "conin$", "conout$"]
        .iter()
        .any(|w| is(w))
    {
        return true;
    }
    if lower.len() == 4 {
        let head: Vec<u16> = lower[..3].to_vec();
        let last = lower[3];
        let digit = (u16::from(b'0')..=u16::from(b'9')).contains(&last)
            || [0xb9, 0xb2, 0xb3].contains(&last);
        return digit
            && (head.iter().copied().eq("com".encode_utf16())
                || head.iter().copied().eq("lpt".encode_utf16()));
    }
    false
}

/// `validateVirtualPath(p)`'s message where it refuses.
fn virtual_path(path: &Value) -> Result<(), JsString> {
    let refuse = |m: &str| Err(JsString::from(m));
    let Value::String(p) = path else {
        return refuse("Path must be a non-empty string");
    };
    if p.is_empty() {
        return refuse("Path must be a non-empty string");
    }
    // `Buffer.byteLength(p, 'utf-8')`: a lone surrogate is U+FFFD's three.
    if p.as_str().len() as u64 > limits::MAX_PATH_BYTES {
        return refuse("Path exceeds 100 UTF-8 bytes");
    }
    let units: Vec<u16> = p.units().collect();
    if units.contains(&u16::from(b'\\')) {
        return refuse("Backslashes are not allowed");
    }
    if units.first() == Some(&u16::from(b'/')) {
        return refuse("Leading slash is not allowed");
    }
    if units.contains(&u16::from(b':')) {
        return refuse("Colons are not allowed");
    }
    if units.iter().any(|u| *u < 32) {
        return refuse("Control characters are not allowed");
    }
    for segment in units.split(|u| *u == u16::from(b'/')) {
        if segment.is_empty() {
            return refuse("Empty path segments are not allowed");
        }
        if segment == [u16::from(b'.')] || segment == [u16::from(b'.'), u16::from(b'.')] {
            return refuse("\".\" and \"..\" segments are not allowed");
        }
        if matches!(segment.last(), Some(&u) if u == u16::from(b'.') || u == u16::from(b' ')) {
            return refuse("Path segments may not end in a dot or space");
        }
        let segment = JsString::from_units(segment);
        if is_windows_reserved(&segment) {
            return Err(crate::js::concat(&[
                &JsString::from("\""),
                &segment,
                &JsString::from("\" is a reserved device name on Windows"),
            ]));
        }
    }
    Ok(())
}

/// `String(value)`, for a name the query takes.
fn to_text(value: &Value) -> String {
    match value {
        Value::Undefined => "undefined".to_owned(),
        Value::Null => "null".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) if *n == 0.0 => "0".to_owned(),
        Value::Number(n) => number_to_string(*n),
        Value::BigInt(t) => t.clone(),
        Value::String(s) => s.as_str().to_owned(),
        // `Array.prototype.join`: null, undefined and holes are empty.
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                None | Some(Value::Undefined | Value::Null) => String::new(),
                Some(v) => to_text(v),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_owned(),
        Value::Bytes(b) => match (b.kind, &b.source) {
            (BytesKind::Buffer | BytesKind::String, Source::Inline(data)) => {
                String::from_utf8_lossy(data).into_owned()
            }
            (BytesKind::Uint8Array, Source::Inline(data)) => {
                data.iter().map(u8::to_string).collect::<Vec<_>>().join(",")
            }
            (BytesKind::ArrayBuffer, _) => "[object ArrayBuffer]".to_owned(),
            _ => "[object Object]".to_owned(),
        },
    }
}

/// A value as the history row binds it. A BigInt binds as an INTEGER,
/// which the `name` column's TEXT affinity stores as its decimal text, so
/// it is that text here. Bytes would bind as a BLOB, which the core never
/// writes (deviation `history-blobs` refuses one on read): they are NULL.
fn js_value(value: &Value) -> JsValue {
    match value {
        Value::Undefined => JsValue::Undefined,
        Value::Null | Value::Bytes(_) => JsValue::Null,
        Value::Bool(b) => JsValue::Bool(*b),
        Value::Number(n) => JsValue::Number(*n),
        Value::BigInt(t) => JsValue::String(JsString::from(t.as_str())),
        Value::String(s) => JsValue::String(s.clone()),
        Value::Array(items) => JsValue::Array(
            items
                .iter()
                .map(|i| i.as_ref().map_or(JsValue::Undefined, js_value))
                .collect(),
        ),
        Value::Object(members) => JsValue::Object(
            members
                .iter()
                .map(|(k, v)| (k.clone(), js_value(v)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_names_fold_ascii_only() {
        for name in [
            "CON",
            "nul.txt",
            "COM¹.log",
            "conin$",
            "lpt9 .x",
            "Aux",
            "lpt0",
        ] {
            assert!(is_windows_reserved(&JsString::from(name)), "{name}");
        }
        for name in ["console", "com10", "ſon", "lpt", "a.con"] {
            assert!(!is_windows_reserved(&JsString::from(name)), "{name}");
        }
    }

    #[test]
    fn spans_as_validate_span() {
        assert_eq!(span_of(&Value::Undefined), Some(None));
        assert_eq!(span_of(&Value::Number(-0.0)), Some(Some(0)));
        assert_eq!(span_of(&Value::Number(1.5)), None);
        assert_eq!(span_of(&Value::Number(9_007_199_254_740_992.0)), None);
        assert_eq!(
            span_of(&Value::BigInt("18446744073709551615".into())),
            Some(Some(u64::MAX))
        );
        assert_eq!(span_of(&Value::BigInt("18446744073709551616".into())), None);
        assert_eq!(span_of(&Value::BigInt("-1".into())), None);
        assert_eq!(span_of(&Value::str("1")), None);
    }

    #[test]
    fn header_values_as_node_takes_them() {
        assert!(header_value("content-type", &JsString::from("text/plain; é")).is_ok());
        for bad in ["テキスト", "a\u{7f}b", "a\u{0}b"] {
            let (text, failure) = header_value("content-type", &JsString::from(bad)).unwrap_err();
            assert_eq!(
                text,
                "Invalid character in header content [\"content-type\"]"
            );
            assert_eq!(failure.code, -32603);
        }
        let lone = JsString::from_units(&[0xd800]);
        assert!(header_value("content-type", &lone).is_err());
    }

    #[test]
    fn names_as_string_gives_them() {
        assert_eq!(to_text(&Value::Number(7.0)), "7");
        assert_eq!(to_text(&Value::Number(-0.0)), "0");
        assert_eq!(
            to_text(&Value::Array(vec![
                Some(Value::Null),
                None,
                Some(Value::int(1))
            ])),
            ",,1"
        );
        assert_eq!(to_text(&Value::Object(Vec::new())), "[object Object]");
    }
}
