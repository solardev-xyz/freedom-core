//! `getSigningIdentity` (swarm-provider-ipc.js's `handleGetSigningIdentity`):
//! the site's signing owner, after the feed grant, with no node readiness.
//! The owner needs the unlocked vault; disclosing it is the effect, so the
//! guard runs just before the answer.

use fc_json::JsValue;

use super::writes::{feed_not_granted, guard, owner, signer_key};
use crate::machine::{AskId, Cx, Event, Outcome, SignKey, Step, World, done, fail};
use crate::stores::feeds::identity_mode;
use crate::stores::manifests::Capability;
use crate::value::Value;

/// `handleGetSigningIdentity`.
pub(crate) struct Signing {
    key: SignKey,
    /// `getIdentityMode(activeIdentity)`.
    mode: JsValue,
    stage: Stage,
}

enum Stage {
    Owner(AskId),
    Guard { id: AskId, owner: [u8; 20] },
}

impl Signing {
    pub(crate) fn start<W: World>(cx: &mut Cx<'_, W>) -> Result<Self, Outcome> {
        if !cx.world.feeds().has_feed_grant(cx.origin) {
            return Err(feed_not_granted().into());
        }
        let identity = cx.world.feeds().active_origin_identity(cx.origin);
        let key = signer_key(identity.as_ref())?;
        Ok(Signing {
            key,
            mode: identity_mode(identity.as_ref()),
            stage: Stage::Owner(cx.owner(key)),
        })
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        match self.stage {
            Stage::Owner(asked) if asked == id => match owner(self.key, event) {
                Ok(owner) => {
                    self.stage = Stage::Guard {
                        id: cx.recheck(),
                        owner,
                    };
                    Step::Wait
                }
                Err(failure) => fail(failure),
            },
            Stage::Guard { id: asked, owner } if asked == id => {
                if let Err(refused) = guard(cx, Capability::Signing, event) {
                    return fail(refused);
                }
                done(Value::object([
                    ("owner", Value::str(&fc_evm::checksum_address(&owner))),
                    ("identityMode", Value::from_js(&self.mode)),
                ]))
            }
            _ => fail(crate::machine::Failure::internal_error()),
        }
    }
}
