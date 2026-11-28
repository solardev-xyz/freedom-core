//! `swarm.publish` (design 0015, "Methods main calls"): main's own uploads,
//! as publish-service.js's `publishData`, `publishFile`,
//! `publishCollection` and `publishDirectory` make them over bee-js, and,
//! when main asks for it, the history row its IPC handlers keep for
//! `freedom://publish` (`swarm:publish-data`, `-file`, `-directory`).
//!
//! In the reference's order:
//! 1. with `history`, the row (`addEntry({ type, name, status: 'uploading',
//!    origin: 'freedom://publish' })`), then the bound (deviation
//!    `history-bound`);
//! 2. without a `batch`, one `/stamps` read and `selectBestBatch(size, {
//!    requireCapacity: true })` (deviation `stamps-one-read`); a given batch
//!    means no `/stamps` (the grammar's "A given batch");
//! 3. for a streamed body, the upload's turn among the four that stream;
//! 4. the upload: `POST /bzz?name=…` with one file (`bee.file.upload`: its
//!    bytes inline when the params carry them, else streamed from its part),
//!    or `POST /bzz` with the parts as a tar (`bee.collection.upload`'s
//!    `TarStream`, through `fc_swarm::tar`, names counted in bytes: deviation
//!    `tar-paths`), `swarm-pin: true`, `swarm-encrypt: true` only when asked,
//!    `swarm-deferred-upload` as asked;
//! 5. the node's answer as bee-js reads it (`UploadResultBody`, `makeTagUid`),
//!    then `normalizeUploadResult`'s fields: `{ reference, tag_uid, batch,
//!    bytes }`;
//! 6. the row's update (`{ status: 'completed', ...result }`, or `failed`
//!    with the handler's text), then the answer.
//!
//! A history write that fails answers the store's text with a code (core
//! PR K2), so main can answer as the IPC handler does: `history_insert`
//! for the insert or the bound's trim after it, before any node call
//! (`addEntry` throws before the handler's `try`, and the invoke rejects);
//! `history_update` for a later update of the row, after its one retry
//! (`history-retry`).
//!
//! No readiness check, no grant, no guard: the row has none, and main's own
//! upload has no page. A request that ends without its machine (a cancel,
//! D13's bounds, `busy`, a protocol error) leaves the row's update to
//! [`ShellPublish::closing`].

use std::collections::BTreeMap;

use fc_json::{JsString, JsValue};

use super::body::{BodyWriter, Fault, Piece};
use super::writes::{BeeRead, bee_upload_read};
use crate::chunks::hex;
use crate::errors::{self, ServiceError, Site};
use crate::machine::node::{Body, BodyAbort, INLINE_BODY};
use crate::machine::shell::{
    self, HISTORY_INSERT, HISTORY_UPDATE, HistoryEntry, HistoryKind, PublishCall, PublishKind,
    ShellError, ShellOutcome, ShellStep,
};
use crate::machine::{
    AfterInsert, AskId, Closing, Cx, Effect, Event, Form, InFlight, NodeCall, Protocol, Reply,
    RowEnd, StoreWrite, World,
};
use crate::stamps::{BatchId, SelectOptions, read_stamps, select_best_batch};
use crate::stores::history;
use crate::value::{Source, Value};

/// publish-service.js's `USER_ORIGIN`: the origin of the rows its IPC
/// handlers keep.
pub const USER_ORIGIN: &str = "freedom://publish";

/// The core's text for a node that answers an upload before it took the
/// whole body (a page's upload has the same).
pub const EARLY_ANSWER_MESSAGE: &str = "The node answered before it had taken the whole upload";

/// What goes to the node.
#[derive(Debug)]
enum Upload {
    File(Piece),
    /// The tar's entries, in the parts' order.
    Tar(Vec<(String, Piece)>),
}

#[derive(Debug)]
enum Stage {
    Insert(AskId),
    Trim(AskId),
    Stamps(AskId),
    Turn(AskId),
    Upload(AskId),
    /// The row's last update, then the answer.
    Closing {
        id: AskId,
        outcome: ShellOutcome,
        last: Last,
    },
    Gone,
}

/// Where the row's last update sits in the IPC handler, which decides what
/// follows when the write fails.
#[derive(Debug)]
enum Last {
    /// Inside its `try` (the `completed` update): if it throws, the `catch`
    /// updates the row `failed` with the write's message, and the handler
    /// answers that failure.
    Try,
    /// In its `catch`: if it throws, the handler throws the write's error;
    /// the core still asks once to end the row `failed` with it.
    Catch,
    /// The row's `failed` update after the bound's trim failed (part of the
    /// insert, before the handler's `try`): as `Catch`, its failure retried
    /// once, but the answer's code stays `history_insert`.
    Bound,
    /// The one retry after the last update failed with `first`; `code` is
    /// the answer's.
    Retry {
        first: JsString,
        in_try: bool,
        code: &'static str,
    },
}

pub(crate) struct ShellPublish {
    upload: Upload,
    /// The query's `name` (one file).
    name: String,
    /// The `content-type` header (one file).
    content_type: String,
    index_document: Option<String>,
    encrypt: bool,
    deferred: bool,
    batch: Option<BatchId>,
    history: Option<HistoryEntry>,
    /// The size estimate the batch needs room for, and `bytes`.
    size: u64,
    stage: Stage,
    row: Option<i64>,
    /// The row's last update is asked.
    closed: bool,
    body: Option<BodyWriter>,
    /// Each streamed part's file name, for a read error's text.
    picked: BTreeMap<u32, String>,
    /// The clock at the last answer, for the row's update when the request
    /// ends without the machine.
    now: u64,
}

impl ShellPublish {
    pub(crate) fn start<W: World>(
        cx: &mut Cx<'_, W>,
        call: PublishCall,
    ) -> Result<Self, ShellOutcome> {
        let size = call
            .parts
            .iter()
            .fold(0u64, |total, p| total.saturating_add(p.bytes));
        let text =
            |s: Option<&JsString>| s.filter(|s| !s.is_empty()).map(|s| s.as_str().to_owned());
        let (name, content_type) = match call.kind {
            // `options.name || 'data'`, `options.contentType || 'text/plain'`.
            PublishKind::Data => (
                text(call.name.as_ref()).unwrap_or_else(|| "data".to_owned()),
                text(call.content_type.as_ref()).unwrap_or_else(|| "text/plain".to_owned()),
            ),
            // `options.name || path.basename(filePath)` (main names it), and
            // bee-js's `application/octet-stream` for a stream without one.
            PublishKind::File => (
                text(call.name.as_ref()).unwrap_or_default(),
                text(call.content_type.as_ref())
                    .unwrap_or_else(|| "application/octet-stream".to_owned()),
            ),
            PublishKind::Collection => (String::new(), String::new()),
        };
        // `options.indexDocument || (index.html at the top ? 'index.html' :
        // undefined)`.
        let top_index = call
            .parts
            .iter()
            .any(|p| p.path.as_ref().is_some_and(|path| *path == "index.html"));
        let index_document = match call.kind {
            PublishKind::Collection => text(call.index_document.as_ref())
                .or_else(|| top_index.then(|| "index.html".to_owned())),
            _ => None,
        };
        // The file each streamed part reads, by its name
        // (`path.basename`): a picked file's, or a collection entry's, for
        // `describePickedPathError`. A data part reads no file.
        let mut picked = BTreeMap::new();
        for p in &call.parts {
            let file = match (call.kind, &p.path) {
                (PublishKind::File, _) => call.name.as_ref(),
                (PublishKind::Collection, Some(path)) => Some(path),
                _ => None,
            };
            if let (Source::Part(k), Some(file)) = (&p.source, file) {
                picked.insert(*k, basename(file.as_str()).to_owned());
            }
        }
        let piece = |source: Source, len: u64| match source {
            Source::Inline(bytes) => Piece::Own(bytes),
            Source::Part(part) => Piece::Part { part, len },
        };
        let upload = match call.kind {
            PublishKind::Collection => Upload::Tar(
                call.parts
                    .into_iter()
                    .map(|p| {
                        let path = p.path.map(|s| s.as_str().to_owned()).unwrap_or_default();
                        (path, piece(p.source, p.bytes))
                    })
                    .collect(),
            ),
            _ => match call.parts.into_iter().next() {
                Some(p) => Upload::File(piece(p.source, p.bytes)),
                None => return Err(shell::internal()),
            },
        };
        let mut publish = ShellPublish {
            upload,
            name,
            content_type,
            index_document,
            encrypt: call.encrypt,
            deferred: call.deferred,
            batch: call.batch,
            history: call.history,
            size,
            stage: Stage::Gone,
            row: None,
            closed: false,
            body: None,
            picked,
            now: cx.world.now(),
        };
        let step = match publish.history.clone() {
            Some(entry) => publish.insert(cx, &entry),
            None => publish.batch_step(cx),
        };
        match step {
            ShellStep::Wait => Ok(publish),
            ShellStep::Done(outcome) => Err(outcome),
        }
    }

    pub(crate) fn on<W: World>(
        &mut self,
        cx: &mut Cx<'_, W>,
        id: AskId,
        event: Event,
    ) -> ShellStep {
        self.now = cx.world.now();
        match std::mem::replace(&mut self.stage, Stage::Gone) {
            Stage::Insert(ask) if ask == id => match event {
                Event::Inserted(Ok(row)) => {
                    self.row = Some(row);
                    let trim = history::trim(Some(row));
                    self.stage = Stage::Trim(cx.write(StoreWrite::History(vec![trim])));
                    ShellStep::Wait
                }
                // `addEntry` throws before the handler's `try`.
                Event::Inserted(Err(text)) => ShellStep::Done(history_error(text, HISTORY_INSERT)),
                _ => ShellStep::Done(shell::internal()),
            },
            Stage::Trim(ask) if ask == id => match event {
                Event::Written(Ok(())) => self.batch_step(cx),
                // The bound is the insert's: still before the `try`.
                Event::Written(Err(text)) => {
                    let outcome = history_error(text, HISTORY_INSERT);
                    let updates = failed_update(&self.row_text(&outcome_text(&outcome)));
                    self.close(cx, updates, outcome, Last::Bound)
                }
                _ => self.close_failed(cx, shell::internal()),
            },
            Stage::Stamps(ask) if ask == id => match self.batch_of(event) {
                Ok(batch) => {
                    self.batch = Some(batch);
                    self.turn_step(cx)
                }
                Err(outcome) => self.close_failed(cx, outcome),
            },
            Stage::Turn(ask) if ask == id => match event {
                Event::Turn => self.send(cx),
                _ => self.close_failed(cx, shell::internal()),
            },
            Stage::Upload(ask) if ask == id => self.upload_event(cx, ask, event),
            Stage::Upload(ask) if self.body.as_ref().is_some_and(|b| b.copies(id)) => {
                self.stage = Stage::Upload(ask);
                let Some(body) = self.body.as_mut() else {
                    return self.close_failed(cx, shell::internal());
                };
                match body.part(cx, event) {
                    Ok(()) => ShellStep::Wait,
                    Err(fault) => self.fault(cx, ask, fault),
                }
            }
            Stage::Closing {
                id: ask,
                outcome,
                last,
            } if ask == id => self.closed_step(cx, event, outcome, last),
            _ => self.close_failed(cx, shell::internal()),
        }
    }

    /// What the request still writes when it ends without its machine: the
    /// row `failed`, with the request's end as its text (`cancelled`,
    /// `busy`, `Internal error`, or D13's failure); for an insert still in
    /// flight, once it answers its rowid, the bound's trim keeping that row
    /// first. Once the machine asked for the row's last update, nothing more
    /// is asked unless it fails.
    pub(crate) fn closing(&self, outcome: &ShellOutcome) -> Option<Closing> {
        if self.closed {
            return match (&self.stage, self.row) {
                (Stage::Closing { id, last, .. }, Some(row)) => Some(Closing::InFlight(InFlight {
                    id: *id,
                    row,
                    now: self.now,
                    retry: !matches!(last, Last::Retry { .. }),
                })),
                _ => None,
            };
        }
        let text = match outcome {
            ShellOutcome::Result(_) => return None,
            ShellOutcome::Error(err) => err.message.clone(),
            ShellOutcome::Cancelled => JsString::from("cancelled"),
            ShellOutcome::Busy => JsString::from("busy"),
            ShellOutcome::Protocol(_) => JsString::from("Internal error"),
        };
        match (self.row, &self.stage) {
            (Some(row), _) => Some(Closing::Row(RowEnd {
                row,
                text,
                now: self.now,
            })),
            (None, Stage::Insert(id)) => Some(Closing::AfterInsert(AfterInsert {
                id: *id,
                text,
                now: self.now,
            })),
            (None, _) => None,
        }
    }

    /// The terminal an opened body still needs when the request ends
    /// without its machine: `cancelled`, or `internal` at a protocol error.
    pub(crate) fn end(&mut self, outcome: &ShellOutcome) -> Option<Effect> {
        let why = match outcome {
            ShellOutcome::Protocol(_) => BodyAbort::Internal,
            _ => BodyAbort::Cancelled,
        };
        let (id, out) = self.body.as_mut()?.terminal(why)?;
        Some(Effect::Body { id, out })
    }

    /// `addEntry(…)`, answered with the new row's rowid.
    fn insert<W: World>(&mut self, cx: &mut Cx<'_, W>, entry: &HistoryEntry) -> ShellStep {
        let mut row = JsValue::Object(Vec::new());
        row.set("type", text(entry.kind.as_str()));
        row.set("name", JsValue::String(entry.name.clone()));
        row.set("status", text("uploading"));
        row.set("origin", text(USER_ORIGIN));
        match history::add_entry(&row, cx.world.now()) {
            Ok(insert) => {
                self.stage = Stage::Insert(cx.write(StoreWrite::HistoryInsert(insert)));
                ShellStep::Wait
            }
            Err(thrown) => ShellStep::Done(history_error(thrown.message.as_str(), HISTORY_INSERT)),
        }
    }

    /// The batch: the given one, else `/stamps`.
    fn batch_step<W: World>(&mut self, cx: &mut Cx<'_, W>) -> ShellStep {
        if self.batch.is_some() {
            return self.turn_step(cx);
        }
        self.stage = Stage::Stamps(cx.whole(NodeCall::stamps()));
        ShellStep::Wait
    }

    /// A streamed body's turn, else the upload.
    fn turn_step<W: World>(&mut self, cx: &mut Cx<'_, W>) -> ShellStep {
        let streams = match &self.upload {
            Upload::File(Piece::Own(bytes)) => bytes.len() > INLINE_BODY,
            Upload::File(Piece::Part { .. }) | Upload::Tar(_) => true,
        };
        if streams {
            self.stage = Stage::Turn(cx.turn());
            return ShellStep::Wait;
        }
        self.send(cx)
    }

    /// `selectBestBatch(size, { requireCapacity: true })` over `/stamps`'
    /// answer.
    fn batch_of(&self, event: Event) -> Result<BatchId, ShellOutcome> {
        let reply = shell::whole_reply(event)?;
        if !reply.ok() {
            return Err(shell::error_reply(&reply, Site::BeeJs));
        }
        let stamps = read_stamps(&reply.body).map_err(shell::reply_error)?;
        let options = SelectOptions {
            require_capacity: true,
            allow_full_mutable: false,
        };
        let selection = select_best_batch(&stamps, self.size, options)
            .map_err(|err| ShellOutcome::Error(ShellError::js(&err)))?;
        match selection.outcome {
            Ok(Some(batch)) => Ok(batch),
            // `if (!batchId) throw noUsableBatchError()`, which
            // `requireCapacity` leaves unreachable.
            Ok(None) => Err(ShellOutcome::Error(ShellError::service(
                &ServiceError::no_usable_batch(),
            ))),
            Err(postage) => Err(ShellOutcome::Error(ShellError::postage(&postage))),
        }
    }

    /// The upload.
    fn send<W: World>(&mut self, cx: &mut Cx<'_, W>) -> ShellStep {
        let Some(batch) = self.batch.map(|b| b.to_hex()) else {
            return self.close_failed(cx, shell::internal());
        };
        let encrypt = self.encrypt;
        let call = match &mut self.upload {
            Upload::File(piece) => {
                let mut headers = vec![
                    ("content-type".to_owned(), self.content_type.clone()),
                    ("swarm-postage-batch-id".to_owned(), batch),
                    ("swarm-pin".to_owned(), "true".to_owned()),
                ];
                if encrypt {
                    headers.push(("swarm-encrypt".to_owned(), "true".to_owned()));
                }
                headers.push((
                    "swarm-deferred-upload".to_owned(),
                    self.deferred.to_string(),
                ));
                let query = vec![("name".to_owned(), self.name.clone())];
                let body = match std::mem::replace(piece, Piece::Own(Vec::new())) {
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
            Upload::Tar(entries) => {
                let mut headers = vec![
                    ("content-type".to_owned(), "application/x-tar".to_owned()),
                    ("swarm-collection".to_owned(), "true".to_owned()),
                    ("swarm-postage-batch-id".to_owned(), batch),
                    ("swarm-pin".to_owned(), "true".to_owned()),
                ];
                if encrypt {
                    headers.push(("swarm-encrypt".to_owned(), "true".to_owned()));
                }
                headers.push(("swarm-deferred-upload".to_owned(), "true".to_owned()));
                if let Some(index) = &self.index_document {
                    headers.push(("swarm-index-document".to_owned(), index.clone()));
                }
                // Each header's time is the clock as it is written.
                let Some(writer) = BodyWriter::tar(std::mem::take(entries)) else {
                    return self.close_failed(cx, shell::internal());
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
        };
        let id = cx.whole(call);
        if let Some(body) = self.body.as_mut() {
            body.bind(id);
        }
        self.stage = Stage::Upload(id);
        ShellStep::Wait
    }

    /// An answer to the upload call: main's `swarm.body` and its credit,
    /// then the node's answer.
    fn upload_event<W: World>(
        &mut self,
        cx: &mut Cx<'_, W>,
        ask: AskId,
        event: Event,
    ) -> ShellStep {
        match event {
            Event::BodyOpen | Event::BodyCredit(_) => {
                let Some(body) = self.body.as_mut() else {
                    return self.close_failed(cx, shell::internal());
                };
                let pumped = match event {
                    Event::BodyCredit(bytes) => body.credit(cx, bytes),
                    _ => body.open(cx),
                };
                match pumped {
                    Ok(()) => {
                        self.stage = Stage::Upload(ask);
                        ShellStep::Wait
                    }
                    Err(fault) => self.fault(cx, ask, fault),
                }
            }
            Event::Reply(reply) => {
                let unsent = self.body.as_ref().is_some_and(|b| !b.ended());
                self.stop_body(cx);
                self.answered(cx, &reply, unsent)
            }
            Event::Failed(class) => {
                self.stop_body(cx);
                self.close_failed(cx, shell::failed(class))
            }
            // Main's grammar refused the call.
            _ => {
                self.stop_body(cx);
                self.close_failed(cx, shell::internal())
            }
        }
    }

    /// bee-js's reading of the upload's answer, `normalizeUploadResult`, and
    /// the row's `completed` update.
    fn answered<W: World>(&mut self, cx: &mut Cx<'_, W>, reply: &Reply, unsent: bool) -> ShellStep {
        if !reply.ok() {
            return self.close_failed(cx, shell::error_reply(reply, Site::BeeJs));
        }
        if unsent {
            // A success before the node took the whole body can't be the
            // upload's.
            return self.close_failed(cx, shell::error(EARLY_ANSWER_MESSAGE));
        }
        let tag = reply.header("swarm-tag").map(|h| h.text());
        let (reference, tag_uid) = match bee_upload_read(&reply.body, tag.as_deref()) {
            Ok(read) => read,
            Err(BeeRead::Reply(err)) => return self.close_failed(cx, shell::reply_error(err)),
            Err(BeeRead::Thrown(message)) => return self.close_failed(cx, shell::error(message)),
        };
        // `toHex(result.reference)`: lowercase, 64 hex or 128 for an
        // encrypted upload.
        let reference = hex(&reference);
        let batch = self.batch.map(|b| b.to_hex()).unwrap_or_default();
        // `result.tagUid || null`.
        let tag_uid = tag_uid.filter(|t| *t != 0.0);
        let bzz_url = format!("bzz://{reference}");
        let result = Value::object([
            ("reference", Value::str(&reference)),
            ("tag_uid", tag_uid.map_or(Value::Null, Value::Number)),
            ("batch", Value::str(&batch)),
            ("bytes", Value::int(self.size)),
        ]);
        // `updateEntry(id, { status: 'completed', ...result })`.
        let mut row = JsValue::Object(Vec::new());
        row.set("status", text("completed"));
        row.set("reference", text(&reference));
        row.set("bzzUrl", text(&bzz_url));
        row.set("tagUid", tag_uid.map_or(JsValue::Null, JsValue::Number));
        row.set("batchIdUsed", text(&batch));
        row.set("bytesSize", number(self.size));
        self.close(cx, row, ShellOutcome::Result(result), Last::Try)
    }

    /// Stops a body that is still being written.
    fn stop_body<W: World>(&mut self, cx: &mut Cx<'_, W>) {
        if let Some(body) = self.body.as_mut() {
            body.abort(cx, BodyAbort::Cancelled);
        }
    }

    /// The body stopped: a part main couldn't stream (or that went past its
    /// bound, D13), or one of another length than its params gave (a
    /// protocol error).
    fn fault<W: World>(&mut self, cx: &mut Cx<'_, W>, call: AskId, fault: Fault) -> ShellStep {
        let why = match fault {
            Fault::Part | Fault::Unreadable { .. } => BodyAbort::BodyStreamError,
            Fault::PartLength | Fault::Internal => BodyAbort::Internal,
        };
        if let Some(body) = self.body.as_mut() {
            body.abort(cx, why);
        }
        cx.cancel(call);
        match fault {
            Fault::PartLength => ShellStep::Done(ShellOutcome::Protocol(Protocol::PartLength)),
            // publishFile's and publishDirectory's catches: the file and the
            // error's code, the path itself never.
            Fault::Unreadable { part, code } => match self.picked.get(&part) {
                Some(name) => {
                    let text = format!("Could not read \"{name}\" ({})", code.as_str());
                    self.close_failed(cx, shell::error(text))
                }
                None => self.close_failed(cx, shell::internal()),
            },
            Fault::Part | Fault::Internal => self.close_failed(cx, shell::internal()),
        }
    }

    /// The row's text for an error message: `swarm:publish-data` keeps the
    /// message; `-file` and `-directory` give `describePublishError`'s (a
    /// batch the network doesn't know yet reads as "try again shortly").
    fn row_text(&self, message: &JsString) -> JsString {
        match self.history.as_ref().map(|h| h.kind) {
            Some(HistoryKind::File | HistoryKind::Directory)
                if errors::is_batch_not_yet_known_error(message) =>
            {
                JsString::from(errors::BATCH_NOT_YET_KNOWN_MESSAGE)
            }
            _ => message.clone(),
        }
    }

    /// The row `failed` with the failure's text (the handler's `catch`),
    /// then the answer.
    fn close_failed<W: World>(&mut self, cx: &mut Cx<'_, W>, outcome: ShellOutcome) -> ShellStep {
        let updates = failed_update(&self.row_text(&outcome_text(&outcome)));
        self.close(cx, updates, outcome, Last::Catch)
    }

    /// The row's last update, then `outcome`; at once when there's no row.
    fn close<W: World>(
        &mut self,
        cx: &mut Cx<'_, W>,
        updates: JsValue,
        outcome: ShellOutcome,
        last: Last,
    ) -> ShellStep {
        let Some(row) = self.row else {
            return ShellStep::Done(outcome);
        };
        if self.closed {
            return ShellStep::Done(outcome);
        }
        self.closed = true;
        match update(row, &updates, cx.world.now()) {
            Some(statement) => {
                let id = cx.write(StoreWrite::History(vec![statement]));
                self.stage = Stage::Closing { id, outcome, last };
                ShellStep::Wait
            }
            None => ShellStep::Done(shell::internal()),
        }
    }

    /// The row's last update answered.
    fn closed_step<W: World>(
        &mut self,
        cx: &mut Cx<'_, W>,
        event: Event,
        outcome: ShellOutcome,
        last: Last,
    ) -> ShellStep {
        match (event, last) {
            (Event::Written(Ok(())), _) => ShellStep::Done(outcome),
            // `updateEntry` threw.
            (Event::Written(Err(text)), Last::Try) => self.retry(cx, text, true, HISTORY_UPDATE),
            (Event::Written(Err(text)), Last::Catch) => self.retry(cx, text, false, HISTORY_UPDATE),
            (Event::Written(Err(text)), Last::Bound) => self.retry(cx, text, false, HISTORY_INSERT),
            (
                Event::Written(Err(text)),
                Last::Retry {
                    first,
                    in_try,
                    code,
                },
            ) => ShellStep::Done(history_error(if in_try { text } else { first }, code)),
            _ => ShellStep::Done(shell::internal()),
        }
    }

    /// The row's last update failed with `first`: the `failed` update with
    /// its message, once, then the write's error as the answer, with `code`.
    fn retry<W: World>(
        &mut self,
        cx: &mut Cx<'_, W>,
        first: JsString,
        in_try: bool,
        code: &'static str,
    ) -> ShellStep {
        let outcome = history_error(first.clone(), code);
        let Some(row) = self.row else {
            return ShellStep::Done(outcome);
        };
        match update(row, &failed_update(&self.row_text(&first)), cx.world.now()) {
            Some(statement) => {
                let id = cx.write(StoreWrite::History(vec![statement]));
                self.stage = Stage::Closing {
                    id,
                    outcome,
                    last: Last::Retry {
                        first,
                        in_try,
                        code,
                    },
                };
                ShellStep::Wait
            }
            None => ShellStep::Done(shell::internal()),
        }
    }
}

/// `path.basename(p)` for a `/`-separated path: its last segment, a
/// trailing `/` dropped.
fn basename(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

/// `updateEntry(row, updates)`'s statement at `now`.
fn update(row: i64, updates: &JsValue, now: u64) -> Option<history::Statement> {
    #[expect(
        clippy::cast_precision_loss,
        reason = "better-sqlite3 answers lastInsertRowid as a JavaScript number"
    )]
    let id = JsValue::Number(row as f64);
    history::update_entry(&id, updates, now).ok()
}

/// A history write's failure: the store's `text`, with `code`.
fn history_error(text: impl Into<JsString>, code: &'static str) -> ShellOutcome {
    ShellOutcome::Error(ShellError::history(text, code))
}

/// The text the row's `failed` update keeps for `outcome`.
fn outcome_text(outcome: &ShellOutcome) -> JsString {
    match outcome {
        ShellOutcome::Error(err) => err.message.clone(),
        ShellOutcome::Busy => JsString::from("busy"),
        ShellOutcome::Cancelled => JsString::from("cancelled"),
        ShellOutcome::Result(_) | ShellOutcome::Protocol(_) => JsString::from("Internal error"),
    }
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
        reason = "sizes below 2^53, as JavaScript holds them"
    )]
    JsValue::Number(n as f64)
}
