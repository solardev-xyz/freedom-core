//! `swarm.upload_status` (design 0015, "Methods main calls"): an upload's
//! progress as publish-service.js's `getUploadStatus` reads it for main's
//! own callers (`freedom://publish`, the agent): one `GET /tags/<uid>`,
//! read as bee-js's `TagSchema` reads it, and `normalizeTag`'s object.
//!
//! Unlike a page's `getUploadStatus`, no tag owner is checked or forgotten
//! (main reads its own uploads' tags), and no live facts are asked. The
//! reference's 10 s read timeout is the caller's `deadline_ms`, within the
//! `swarm` deadline kind.

use crate::errors::Site;
use crate::machine::shell::{self, ShellOutcome, ShellStep};
use crate::machine::{AskId, Cx, Event, NodeCall, World};
use crate::replies::{normalize_tag, read_tag};

pub(crate) struct ShellStatus {
    call: AskId,
}

impl ShellStatus {
    pub(crate) fn start<W: World>(cx: &mut Cx<'_, W>, tag_uid: u64) -> Self {
        ShellStatus {
            call: cx.whole(NodeCall::tag(tag_uid)),
        }
    }

    pub(crate) fn on(&mut self, id: AskId, event: Event) -> ShellStep {
        if id != self.call {
            return ShellStep::Done(shell::internal());
        }
        let reply = match shell::whole_reply(event) {
            Ok(reply) => reply,
            Err(outcome) => return ShellStep::Done(outcome),
        };
        if !reply.ok() {
            return ShellStep::Done(shell::error_reply(&reply, Site::BeeJs));
        }
        ShellStep::Done(match read_tag(&reply.body) {
            Ok(Ok(tag)) => ShellOutcome::Result(normalize_tag(&tag).0),
            // zod's refusal: its `ZodError`'s message.
            Ok(Err(zod)) => shell::error(zod),
            Err(err) => shell::reply_error(err),
        })
    }
}
