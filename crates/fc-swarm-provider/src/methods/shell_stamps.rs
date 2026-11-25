//! `swarm.stamps` (design 0015, "Methods main calls"): the node's postage
//! batches, or one of them, as main reads them today: stamp-service.js's
//! `getStamps` (bee-js's `stamp.getAll` beside the node's raw `/stamps`)
//! and the agent's `stamp.get(id)` (swarm-postage-readiness.js).
//!
//! One call, `GET /stamps` or `GET /stamps/<id>`, read once by its typed
//! reader (design 0015, "JSON replies"): each batch as bee-js's
//! `mapPostageBatch` gives it (its sizes in bytes, its duration in seconds,
//! a fractional depth refused: deviation `batch-depth`), with the raw
//! fields bee-js drops that Freedom reads: `exists` and `propagating`
//! (where the node sent a boolean), and the node's own `batchTTL`
//! (`isPendingStamp` reads it where `propagating` is absent).

use fc_json::JsString;

use crate::chunks::hex;
use crate::errors::Site;
use crate::machine::shell::{self, ShellError, ShellOutcome, ShellStep};
use crate::machine::{AskId, Cx, Event, NodeCall, World};
use crate::stamps::{BatchId, PostageBatch, RawBatchView, Stamps, read_stamp, read_stamps};
use crate::value::Value;

pub(crate) struct ShellStamps {
    one: bool,
    call: AskId,
}

impl ShellStamps {
    pub(crate) fn start<W: World>(cx: &mut Cx<'_, W>, id: Option<BatchId>) -> Self {
        let call = match id {
            Some(batch) => NodeCall::stamp(&batch.0),
            None => NodeCall::stamps(),
        };
        ShellStamps {
            one: id.is_some(),
            call: cx.whole(call),
        }
    }

    pub(crate) fn on(&mut self, id: AskId, event: Event) -> ShellStep {
        if id != self.call {
            return ShellStep::Done(shell::internal());
        }
        ShellStep::Done(self.answer(event))
    }

    fn answer(&self, event: Event) -> ShellOutcome {
        let reply = match shell::whole_reply(event) {
            Ok(reply) => reply,
            Err(outcome) => return outcome,
        };
        if !reply.ok() {
            return shell::error_reply(&reply, Site::BeeJs);
        }
        let read = if self.one {
            read_stamp(&reply.body)
        } else {
            read_stamps(&reply.body)
        };
        let stamps = match read {
            Ok(stamps) => stamps,
            Err(err) => return shell::reply_error(err),
        };
        let batches = match stamps.get_all() {
            Ok(batches) => batches,
            Err(err) => return ShellOutcome::Error(ShellError::js(&err)),
        };
        let mut values = batches_of(&stamps, &batches);
        if self.one {
            return match values.pop() {
                Some(batch) if values.is_empty() => ShellOutcome::Result(batch),
                _ => shell::internal(),
            };
        }
        ShellOutcome::Result(Value::array(values))
    }
}

/// Each batch zod accepted, mapped, beside its raw fields, in the reply's
/// order.
fn batches_of(stamps: &Stamps, batches: &[PostageBatch]) -> Vec<Value> {
    // zod accepted the reply, so every element was a batch, in order.
    stamps
        .batches()
        .zip(batches)
        .map(|(raw, mapped)| batch_value(mapped, raw))
        .collect()
}

/// `mapPostageBatch`'s fields, then `exists`, `propagating` and the node's
/// `batchTTL`.
pub(crate) fn batch_value(batch: &PostageBatch, raw: RawBatchView<'_>) -> Value {
    let mut members: Vec<(JsString, Value)> = vec![
        ("batchID".into(), Value::str(&hex(&batch.batch_id.0))),
        ("utilization".into(), Value::Number(batch.utilization)),
        ("usable".into(), Value::Bool(batch.usable)),
        ("label".into(), Value::String(batch.label.clone())),
        ("depth".into(), Value::Number(batch.depth)),
        ("amount".into(), Value::str(&batch.amount)),
        ("bucketDepth".into(), Value::Number(batch.bucket_depth)),
        ("blockNumber".into(), Value::Number(batch.block_number)),
        ("immutableFlag".into(), Value::Bool(batch.immutable_flag)),
        ("usage".into(), Value::Number(batch.usage)),
        ("usageText".into(), Value::str(&batch.usage_text)),
        ("size".into(), Value::Number(batch.size)),
        ("remainingSize".into(), Value::Number(batch.remaining_size)),
        (
            "theoreticalSize".into(),
            Value::Number(batch.theoretical_size),
        ),
        ("duration".into(), Value::Number(batch.duration)),
    ];
    if let Some(exists) = raw.exists() {
        members.push(("exists".into(), Value::Bool(exists)));
    }
    if let Some(propagating) = raw.propagating() {
        members.push(("propagating".into(), Value::Bool(propagating)));
    }
    if let Some(ttl) = raw.batch_ttl() {
        members.push(("batchTTL".into(), Value::Number(ttl)));
    }
    Value::Object(members)
}
