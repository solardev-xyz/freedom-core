//! `getUploadStatus` (swarm-provider-ipc.js's `handleGetUploadStatus`;
//! publish-service.js's `getUploadStatus`): the tag must be one this site's
//! upload recorded, then one `tag` call, read as bee-js's `TagSchema` reads
//! it, and `normalizeTag`'s object. A tag that is done forgets its owner,
//! and at most 4,096 owners are held at once, the oldest forgotten first
//! (deviation `tag-owners-bound`).
//! As page-swarm.js's `uploadStatus` does, the name must still bind the
//! key and the document still hold it when the answer goes, whatever the
//! handler answered: the live facts are asked after it (design 0015's D1),
//! custody left out, and a name that moved answers `NO_ADDRESS` before the
//! handler's own answer. That holds for every answer `executeSwarmMethod`
//! gives this method: the connection's refusal, the params' and the tag's
//! (`tag_ownership_mismatch`, a tag forgotten past the bound among them,
//! with no `tag` call), the read's failure, and the status.

use std::collections::BTreeMap;

use fc_json::JsString;

use super::{live_of, no_address, permitted};
use crate::ReplyError;
use crate::errors::{self, Site};
use crate::machine::node::{Failed, transport_text};
use crate::machine::params::require_params;
use crate::machine::{AskId, Cx, Event, Failure, NodeCall, Outcome, Step, World, fail};
use crate::replies::{normalize_tag, read_tag};
use crate::value::Value;

/// The most tags whose owners are held at once (deviation
/// `tag-owners-bound`): the reference forgets a tag only when a page polls
/// it done, so its map grows with every collection a page publishes and
/// never polls.
pub const MAX_TAG_OWNERS: usize = 4096;

/// The tags' owners (`tagOwnership`: tag → the site whose upload made it),
/// session-scoped, never written to disk, and at most [`MAX_TAG_OWNERS`]
/// of them: a new tag past the bound forgets the oldest, which then answers
/// as another site's tag does (`tag_ownership_mismatch`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TagOwners {
    /// Tag → (when it was recorded, its owner).
    owners: BTreeMap<u64, (u64, JsString)>,
    /// When each tag was recorded → the tag: the oldest first.
    order: BTreeMap<u64, u64>,
    next: u64,
}

impl TagOwners {
    pub fn new() -> Self {
        Self::default()
    }

    /// `tagOwnership.set(tag, origin)`. A tag already held keeps its age,
    /// as a JavaScript `Map` keeps a key's place; a new one past the bound
    /// forgets the oldest.
    pub fn set(&mut self, tag: u64, origin: JsString) {
        if let Some((_, owner)) = self.owners.get_mut(&tag) {
            *owner = origin;
            return;
        }
        if self.owners.len() >= MAX_TAG_OWNERS
            && let Some((_, oldest)) = self.order.pop_first()
        {
            self.owners.remove(&oldest);
        }
        let at = self.next;
        self.next += 1;
        self.order.insert(at, tag);
        self.owners.insert(tag, (at, origin));
    }

    /// `tagOwnership.get(tag)`.
    pub fn get(&self, tag: u64) -> Option<&JsString> {
        self.owners.get(&tag).map(|(_, owner)| owner)
    }

    /// `tagOwnership.delete(tag)`.
    pub fn remove(&mut self, tag: u64) {
        if let Some((at, _)) = self.owners.remove(&tag) {
            self.order.remove(&at);
        }
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
    stage: Stage,
}

enum Stage {
    Call(AskId),
    /// The live facts, then `normalizeTag`'s object.
    /// The live facts, then the handler's answer.
    Live {
        id: AskId,
        answer: Outcome,
    },
    Gone,
}

impl UploadStatus {
    /// `handleGetUploadStatus` up to its `tag` call; a refusal before it
    /// waits for the live facts too.
    pub(crate) fn start<W: World>(cx: &mut Cx<'_, W>, params: &Value) -> Result<Self, Outcome> {
        let stage = match Self::checks(cx, params) {
            Ok((uid, call)) => {
                return Ok(UploadStatus {
                    uid,
                    stage: Stage::Call(call),
                });
            }
            Err(answer) => Stage::Live {
                id: cx.live(),
                answer,
            },
        };
        Ok(UploadStatus { uid: 0, stage })
    }

    /// The handler's checks, in its order, then the `tag` call.
    fn checks<W: World>(cx: &mut Cx<'_, W>, params: &Value) -> Result<(u64, AskId), Outcome> {
        permitted(cx)?;
        require_params(params)?;
        // `typeof tagUid !== 'number' || !Number.isInteger(tagUid) ||
        // tagUid <= 0`.
        let uid = match params.get("tagUid") {
            Value::Number(n) if n.is_finite() && n.trunc() == *n && *n > 0.0 => *n,
            _ => return Err(refuse_tag().into()),
        };
        // Only safe integers are recorded: any other number has no owner.
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a positive integer no larger than 2^53 - 1"
        )]
        let uid = (uid <= MAX_SAFE).then_some(uid as u64);
        let owned = uid.filter(|uid| {
            cx.world
                .tags()
                .get(*uid)
                .is_some_and(|owner| owner == cx.origin)
        });
        let Some(uid) = owned else {
            return Err(Failure::not_authorized("tag_ownership_mismatch").into());
        };
        Ok((uid, cx.whole(NodeCall::tag(uid))))
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        match std::mem::replace(&mut self.stage, Stage::Gone) {
            Stage::Call(call) if call == id => {
                let answer = self.tag(cx, event);
                self.stage = Stage::Live {
                    id: cx.live(),
                    answer,
                };
                Step::Wait
            }
            Stage::Live { id: asked, answer } if asked == id => match live_of(&event) {
                Some(live) if live.holds() => Step::Done(answer),
                Some(_) => fail(no_address()),
                None => fail(Failure::internal_error()),
            },
            _ => fail(Failure::internal_error()),
        }
    }

    /// The handler's answer from the `tag` call's: the status, or the
    /// read's failure through the provider's catch.
    fn tag<W: World>(&mut self, cx: &mut Cx<'_, W>, event: Event) -> Outcome {
        let reply = match event {
            Event::Reply(reply) => reply,
            Event::Failed(failed) => return call_failed(failed).into(),
            _ => return Failure::internal_error().into(),
        };
        if !reply.ok() {
            return match reply.error(Site::BeeJs) {
                Ok(err) => Failure::internal(err.message),
                Err(class) => call_failed(class),
            }
            .into();
        }
        let tag = match read_tag(&reply.body) {
            Ok(Ok(tag)) => tag,
            Ok(Err(zod)) => return Failure::internal(zod).into(),
            Err(err) => return reply_failed(err).into(),
        };
        let (status, finished) = normalize_tag(&tag);
        // Clean up completed tags to prevent unbounded map growth.
        if finished {
            cx.world.tags().remove(self.uid);
        }
        Outcome::Result(status)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_owners_keep_at_most_the_bound() {
        let site = |n: u64| JsString::from(format!("https://site{n}.example"));
        let mut tags = TagOwners::new();
        for tag in 1..=MAX_TAG_OWNERS as u64 {
            tags.set(tag, site(tag));
        }
        assert_eq!(tags.len(), MAX_TAG_OWNERS);
        // A tag already held keeps its age and forgets nothing.
        tags.set(1, site(0));
        assert_eq!(tags.len(), MAX_TAG_OWNERS);
        assert_eq!(tags.get(1), Some(&site(0)));
        // A new one forgets the oldest.
        tags.set(5000, site(5000));
        assert_eq!(tags.len(), MAX_TAG_OWNERS);
        assert_eq!(tags.get(1), None);
        assert_eq!(tags.get(2), Some(&site(2)));
        assert_eq!(tags.get(5000), Some(&site(5000)));
        // A tag removed (done) frees its place: nothing more is forgotten.
        tags.remove(3);
        tags.set(5001, site(5001));
        assert_eq!(tags.len(), MAX_TAG_OWNERS);
        assert_eq!(tags.get(2), Some(&site(2)));
        tags.set(5002, site(5002));
        assert_eq!(tags.get(2), None);
        assert_eq!(tags.get(4), Some(&site(4)));
    }
}
