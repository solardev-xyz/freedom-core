//! `getUploadStatus` (swarm-provider-ipc.js's `handleGetUploadStatus`;
//! publish-service.js's `getUploadStatus`): the tag must be one this site's
//! upload recorded, then one `tag` call, read as bee-js's `TagSchema` reads
//! it, and `normalizeTag`'s object. A tag that is done forgets its owner.
//! As page-swarm.js's `uploadStatus` does, the document must still hold
//! its key when the answer goes.

use std::collections::BTreeMap;

use fc_json::JsString;

use super::{no_address, permitted};
use crate::ReplyError;
use crate::errors::{self, Site};
use crate::machine::node::{Failed, transport_text};
use crate::machine::params::require_params;
use crate::machine::{AskId, Cx, Event, Failure, NodeCall, Outcome, Step, World, done, fail};
use crate::replies::{normalize_tag, read_tag};
use crate::value::Value;

/// The tags' owners (`tagOwnership`: tag → the site whose upload made it),
/// session-scoped, never written to disk. The reference bounds it only by
/// forgetting a tag once its status reads done.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TagOwners {
    owners: BTreeMap<u64, JsString>,
}

impl TagOwners {
    pub fn new() -> Self {
        Self::default()
    }

    /// `tagOwnership.set(tag, origin)`.
    pub fn set(&mut self, tag: u64, origin: JsString) {
        self.owners.insert(tag, origin);
    }

    /// `tagOwnership.get(tag)`.
    pub fn get(&self, tag: u64) -> Option<&JsString> {
        self.owners.get(&tag)
    }

    /// `tagOwnership.delete(tag)`.
    pub fn remove(&mut self, tag: u64) {
        self.owners.remove(&tag);
    }

    pub fn len(&self) -> usize {
        self.owners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }
}

/// The largest safe integer, the largest tag an upload records.
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// `handleGetUploadStatus`.
pub(crate) struct UploadStatus {
    uid: u64,
    call: AskId,
}

impl UploadStatus {
    pub(crate) fn start<W: World>(cx: &mut Cx<'_, W>, params: &Value) -> Result<Self, Outcome> {
        permitted(cx)?;
        require_params(params)?;
        let positive = match params.get("tagUid") {
            Value::Number(n) => n.is_finite() && n.trunc() == *n && *n > 0.0,
            _ => false,
        };
        let Value::Number(uid) = params.get("tagUid") else {
            return Err(refuse_tag().into());
        };
        if !positive {
            return Err(refuse_tag().into());
        }
        // Only safe integers are recorded: any other number has no owner.
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a positive integer no larger than 2^53 - 1"
        )]
        let uid = (*uid <= MAX_SAFE).then_some(*uid as u64);
        let owned = uid.filter(|uid| {
            cx.world
                .tags()
                .get(*uid)
                .is_some_and(|owner| owner == cx.origin)
        });
        let Some(uid) = owned else {
            return Err(Failure::not_authorized("tag_ownership_mismatch").into());
        };
        let call = cx.whole(NodeCall::tag(uid));
        Ok(UploadStatus { uid, call })
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        if id != self.call {
            return fail(Failure::internal_error());
        }
        let reply = match event {
            Event::Reply(reply) => reply,
            Event::Failed(failed) => return fail(call_failed(failed)),
            _ => return fail(Failure::internal_error()),
        };
        if !reply.ok() {
            return fail(match reply.error(Site::BeeJs) {
                Ok(err) => Failure::internal(err.message),
                Err(class) => call_failed(class),
            });
        }
        let tag = match read_tag(&reply.body) {
            Ok(Ok(tag)) => tag,
            Ok(Err(zod)) => return fail(Failure::internal(zod)),
            Err(err) => return fail(reply_failed(err)),
        };
        let (status, finished) = normalize_tag(&tag);
        // Clean up completed tags to prevent unbounded map growth.
        if finished {
            cx.world.tags().remove(self.uid);
        }
        if !cx.key_holds() {
            return fail(no_address());
        }
        done(status)
    }
}

/// `tagUid must be a positive integer`.
fn refuse_tag() -> Failure {
    Failure::invalid_params("tagUid must be a positive integer", "invalid_params")
}

/// A bee-js read's call that failed before any reply: busy, a reply past
/// its cap, or its class's text, each -32603 through the provider's catch.
pub(crate) fn call_failed(failed: Failed) -> Failure {
    match failed {
        Failed::Busy => Failure::busy(),
        Failed::TooLarge => errors::reply_too_large().into(),
        class => Failure::internal(transport_text(class)),
    }
}

/// A bee-js JSON read whose reply the typed reader refused.
pub(crate) fn reply_failed(err: ReplyError) -> Failure {
    match err {
        ReplyError::TooLarge => errors::reply_too_large().into(),
        ReplyError::TooDeep => Failure::internal(transport_text(Failed::Error)),
        ReplyError::Syntax(_) => errors::reply_not_json().into(),
    }
}
