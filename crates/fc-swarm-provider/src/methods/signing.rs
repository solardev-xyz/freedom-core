//! `getSigningIdentity` (swarm-provider-ipc.js's `handleGetSigningIdentity`):
//! the site's signing owner, after the feed grant, with no node readiness.
//! The owner needs the unlocked vault; disclosing it is the effect, so the
//! guard runs once the vault answered, just before the answer.

use fc_json::JsValue;

use super::permitted;
use super::writes::{feed_not_granted, guard, owner, signer_key};
use crate::machine::{
    Approval, AskId, Cx, Event, Failure, Outcome, SignKey, Step, World, done, fail,
};
use crate::stores::feeds::identity_mode;
use crate::stores::manifests::Capability;
use crate::value::Value;

/// `handleGetSigningIdentity`.
pub(crate) struct Signing {
    approval: Option<Approval>,
    key: SignKey,
    /// `getIdentityMode(activeIdentity)`.
    mode: JsValue,
    owner: AskId,
}

impl Signing {
    pub(crate) fn start<W: World>(
        cx: &mut Cx<'_, W>,
        approval: Option<Approval>,
    ) -> Result<Self, Outcome> {
        permitted(cx)?;
        if !cx.world.feeds().has_feed_grant(cx.origin) {
            return Err(feed_not_granted().into());
        }
        let identity = cx.world.feeds().active_origin_identity(cx.origin);
        let key = signer_key(identity.as_ref())?;
        Ok(Signing {
            approval,
            key,
            mode: identity_mode(identity.as_ref()),
            owner: cx.owner(key),
        })
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        if id != self.owner {
            return fail(Failure::internal_error());
        }
        let owner = match owner(self.key, event) {
            Ok(owner) => owner,
            Err(failure) => return fail(failure),
        };
        if let Err(refused) = guard(cx, self.approval, Capability::Signing) {
            return fail(refused);
        }
        done(Value::object([
            ("owner", Value::str(&fc_evm::checksum_address(&owner))),
            ("identityMode", Value::from_js(&self.mode)),
        ]))
    }
}
