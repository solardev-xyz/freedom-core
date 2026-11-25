//! `createFeed` (swarm-provider-ipc.js's `handleCreateFeed`; feed-service.js's
//! `createFeed`): the feed's manifest under the site's active identity,
//! its topic `keccak256(utf8(key + "/" + name))`, and the feed's record.
//!
//! In today's order: the params, the feed grant; an existing feed answers
//! its record under the effect's guard; then #89's refusal, the readiness
//! check, the vault (the owner), the history row, one `/stamps` read, the
//! guard, `POST /feeds/<o>/<t>`, the feed's record (`setFeed`) and the
//! row's update.

use fc_json::{JsString, JsValue};

use super::permitted;
use super::writes::{
    Ending, Fail, add_row, admit, bee_upload, batch, closing, feed_manifest, feed_not_granted,
    guard, inserted, owner, row as fields, s, signer_key, stamps_call, unavailable, written,
};
use crate::chunks::hex;
use crate::js::concat;
use crate::machine::params::{feed_name, require_params};
use crate::machine::{
    Approval, AskId, Cx, Event, Failure, Outcome, ReadyCheck, SignKey, Step, StoreWrite, World,
    fail,
};
use crate::stores::feeds::{FeedChange, identity_mode};
use crate::stores::manifests::Capability;
use crate::stores::{UNDEFINED, template};
use crate::value::Value;

/// `handleCreateFeed`.
pub(crate) struct CreateFeed {
    approval: Option<Approval>,
    name: JsString,
    topic: [u8; 32],
    /// The active identity, read before the waits, as the reference reads
    /// it once.
    identity: Option<JsValue>,
    owner: [u8; 20],
    row: Option<i64>,
    /// The row's last update is asked.
    closed: bool,
    now: u64,
    stage: Stage,
}

enum Stage {
    Ready(AskId),
    Owner { id: AskId, key: SignKey },
    Insert(AskId),
    Trim(AskId),
    Stamps(AskId),
    Manifest(AskId),
    Record { id: AskId, result: Value },
    Ending(Ending),
    Gone,
}

impl CreateFeed {
    pub(crate) fn start<W: World>(
        cx: &mut Cx<'_, W>,
        params: &Value,
        approval: Option<Approval>,
    ) -> Result<Self, Outcome> {
        permitted(cx)?;
        admit(cx, approval, Capability::Feeds)?;
        require_params(params)?;
        let name = feed_name(params.get("name"))
            .map_err(|m| Failure::invalid_params(m, "invalid_feed_name"))?
            .clone();
        let feeds = cx.world.feeds();
        if !feeds.has_feed_grant(cx.origin) {
            return Err(feed_not_granted().into());
        }
        let topic = fc_swarm::feed::topic(&format!("{}/{}", cx.origin.as_str(), name.as_str()));
        if let Some(feed) = feeds.feed(cx.origin, &name) {
            // Idempotent: the record, under the guard.
            let identity = feeds.feed_identity(cx.origin, &feed);
            let field = |key: &str| feed.get(key).unwrap_or(&UNDEFINED);
            let reference = template(field("manifestReference"))
                .map_err(|thrown| Failure::internal(thrown.message))?;
            let result = Value::object([
                ("feedId", Value::String(name.clone())),
                ("owner", Value::from_js(field("owner"))),
                ("topic", Value::from_js(field("topic"))),
                ("manifestReference", Value::from_js(field("manifestReference"))),
                (
                    "bzzUrl",
                    Value::String(concat(&[
                        &JsString::from("bzz://"),
                        &JsString::from(reference),
                    ])),
                ),
                (
                    "identityMode",
                    Value::from_js(&identity_mode(identity.as_ref())),
                ),
            ]);
            guard(cx, approval, Capability::Feeds)?;
            return Err(Outcome::Result(result));
        }
        let identity = feeds.active_origin_identity(cx.origin);
        unavailable(identity.as_ref())?;
        Ok(CreateFeed {
            approval,
            name,
            topic,
            identity,
            owner: [0; 20],
            row: None,
            closed: false,
            now: cx.world.now(),
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
                let key = match signer_key(self.identity.as_ref()) {
                    Ok(key) => key,
                    Err(failure) => return fail(failure),
                };
                self.stage = Stage::Owner {
                    id: cx.owner(key),
                    key,
                };
                Step::Wait
            }
            Stage::Owner { id: asked, key } if asked == id => {
                self.owner = match owner(key, event) {
                    Ok(owner) => owner,
                    Err(failure) => return fail(failure),
                };
                let entry = fields(&[
                    ("type", s("feed-create")),
                    ("name", JsValue::String(self.name.clone())),
                    ("status", s("uploading")),
                    ("origin", JsValue::String(cx.origin.clone())),
                ]);
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
                let batch = match batch(event, 4096) {
                    Ok(batch) => batch,
                    Err(failure) => return self.end(cx, Err(failure)),
                };
                if let Err(refused) = guard(cx, self.approval, Capability::Feeds) {
                    return self.end(cx, Err(Fail::answer(refused)));
                }
                self.stage = Stage::Manifest(cx.whole(feed_manifest(&self.owner, &self.topic, &batch)));
                Step::Wait
            }
            Stage::Manifest(asked) if asked == id => {
                let manifest = match bee_upload(event) {
                    Ok(reference) => hex(&reference),
                    Err(failure) => return self.end(cx, Err(failure)),
                };
                let topic = hex(&self.topic);
                let owner = fc_evm::checksum_address(&self.owner);
                let bzz = format!("bzz://{manifest}");
                let identity_id = self
                    .identity
                    .as_ref()
                    .and_then(|identity| identity.get("id"))
                    .cloned()
                    .unwrap_or(JsValue::Undefined);
                let record = fields(&[
                    ("topic", s(&topic)),
                    ("owner", s(&owner)),
                    ("manifestReference", s(&manifest)),
                    ("identityId", identity_id),
                ]);
                let result = Value::object([
                    ("feedId", Value::String(self.name.clone())),
                    ("owner", Value::str(&owner)),
                    ("topic", Value::str(&topic)),
                    ("manifestReference", Value::str(&manifest)),
                    ("bzzUrl", Value::str(&bzz)),
                    (
                        "identityMode",
                        Value::from_js(&identity_mode(self.identity.as_ref())),
                    ),
                ]);
                let change = FeedChange::SetFeed {
                    key: cx.origin.clone(),
                    name: self.name.clone(),
                    data: record,
                };
                self.stage = Stage::Record {
                    id: cx.write(StoreWrite::Feeds(change)),
                    result,
                };
                Step::Wait
            }
            Stage::Record { id: asked, result } if asked == id => match written(event) {
                Ok(()) => {
                    // `{ status: 'completed', ...result }`.
                    let updates = row_of_result(&result);
                    self.end(cx, Ok((result, updates)))
                }
                Err(text) => self.end(cx, Err(Fail::text(text))),
            },
            Stage::Ending(ending) if ending.id == id => ending.on(event),
            _ => self.end(cx, Err(Fail::internal())),
        }
    }

    /// What the request still writes when it ends without its machine.
    pub(crate) fn closing(&self, outcome: &Outcome) -> Option<StoreWrite> {
        closing(self.row, self.closed, outcome, self.now)
    }

    /// The row's last update, then the answer; at once with no row.
    fn end<W: World>(&mut self, cx: &mut Cx<'_, W>, result: Result<(Value, JsValue), Fail>) -> Step {
        let Some(row) = self.row else {
            return fail(result.err().map_or_else(Failure::internal_error, |f| f.page));
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

/// `{ status: 'completed', ...result }`, the fields `updateEntry` reads
/// among them (`bzzUrl`).
fn row_of_result(result: &Value) -> JsValue {
    let mut updates = vec![("status", s("completed"))];
    for key in ["topic", "owner", "manifestReference", "bzzUrl"] {
        if let Some(text) = result.get(key).as_js_string() {
            updates.push((key, JsValue::String(text.clone())));
        }
    }
    fields(&updates)
}
