//! `writeSingleOwnerChunk` (swarm-provider-ipc.js's
//! `handleWriteSingleOwnerChunk`; chunk-service.js's
//! `writeSingleOwnerChunk`), with SW-1 in the core (design 0015, "SW-1 in
//! the core").
//!
//! **Today's order:** the params, the feed grant, #89's refusal, SW-1, the
//! vault (the owner), the readiness check, the history row, then the
//! signature, the batch, the guard and the upload.
//!
//! **SW-1.** A raw SOC's identifier is the page's to choose, so it needs an
//! identity only this site uses: anything but an app-scoped identity with
//! a numeric publisher index that no other site's identity holds is shared
//! (`isIdentitySharedWithOtherOrigins`), and refused 4100
//! `shared_identity`.
//! - **The check** stays in today's place, with today's cases and errors.
//! - **The re-check:** the vault, the readiness check and the history row
//!   are waits, so in the step that hands the signature to the vault the
//!   machine runs the feed-grant check, #89's and SW-1 again. If one fails
//!   now, the request ends with its error and nothing is signed. If the
//!   site's active identity changed to another exclusive one meanwhile,
//!   the vault is asked for that key's owner, and the re-check runs again.
//! - **The hold:** the signature is asked with [`SignSoc::hold`] naming the
//!   site's key, so the swarm thread defers the listed store changes until
//!   the vault answers or the request ends ([`crate::machine::keeper`]).
//! - **The boundary is the signature:** one that comes after the request's
//!   cancel is dropped with the request, and nothing is uploaded. Once a
//!   signature exists, the upload goes on under today's guard.

use fc_json::JsValue;
use fc_swarm::PreparedChunk;
use fc_swarm::verify::soc_address;

use super::permitted;
use super::writes::{
    Ended, Ending, Fail, add_row, admit, batch, closing, feed_not_granted, guard, inserted, owner,
    row, s, signature, signer_key, soc_up, soc_uploaded, stamps_call, still_here, unavailable,
    written,
};
use crate::chunks::hex;
use crate::machine::params::{bytes32, empty_options, hex_string, require_params};
use crate::machine::{
    Approval, AskId, Closing, Cx, Event, Failure, Outcome, ReadyCheck, SignKey, SignSoc, SocKind,
    Step, World, fail,
};
use crate::methods::feed_write::{Data, data_of};
use crate::methods::limits::MAX_CHUNK_PAYLOAD_BYTES;
use crate::stamps::BatchId;
use crate::stores::manifests::Capability;
use crate::value::Value;

/// `MAX_U64`.
const MAX_U64: u128 = u64::MAX as u128;

/// SW-1's refusal.
pub fn shared_identity() -> Failure {
    Failure {
        data: Some(Value::object([("reason", Value::str("shared_identity"))])),
        ..Failure::bare(
            crate::machine::page::UNAUTHORIZED,
            "Single Owner Chunks need a publisher identity only this site uses; the active one is shared with other sites",
        )
    }
}

/// `handleWriteSingleOwnerChunk`.
pub(crate) struct SocWrite {
    approval: Option<Approval>,
    identifier: [u8; 32],
    payload: Vec<u8>,
    /// The span the vault signs: the page's, or the payload's length for
    /// none or 0, as the vault and bee-js read it.
    span: u64,
    key: SignKey,
    owner: [u8; 20],
    /// The history row, once added.
    row: Option<i64>,
    /// The row's last update is asked.
    closed: bool,
    now: u64,
    stage: Stage,
}

enum Stage {
    /// The vault: the key's owner; `recheck` once the row exists (the
    /// active identity changed before the signature).
    Owner {
        id: AskId,
        recheck: bool,
    },
    Ready(AskId),
    Insert(AskId),
    Trim(AskId),
    Sign {
        id: AskId,
        prepared: PreparedChunk,
    },
    Stamps {
        id: AskId,
        signature: [u8; 65],
    },
    SocUp {
        id: AskId,
        address: [u8; 32],
        batch: BatchId,
    },
    Ending(Ending),
    Gone,
}

fn invalid(message: &str, reason: &str) -> Outcome {
    Failure::invalid_params(message, reason).into()
}

impl SocWrite {
    pub(crate) fn start<W: World>(
        cx: &mut Cx<'_, W>,
        params: &Value,
        approval: Option<Approval>,
    ) -> Result<Self, Outcome> {
        permitted(cx)?;
        admit(cx, approval, Capability::Signing)?;
        require_params(params)?;
        empty_options(params.get("options"))?;
        let identifier = hex_string(
            params.get("identifier"),
            32,
            "invalid_identifier",
            "identifier",
        )?;
        let identifier = bytes32(&identifier.as_str().to_ascii_lowercase().into())
            .ok_or_else(Failure::internal_error)?;
        // validateChunkPayload.
        let raw = params.get("data");
        let data = if raw.is_nullish() { None } else { data_of(raw) };
        let Some(data) = data else {
            return Err(invalid(
                "data must be a string, Uint8Array, or ArrayBuffer",
                "invalid_params",
            ));
        };
        let len = match &data {
            Data::Inline(bytes) => bytes.len() as u64,
            Data::Part { len, .. } => *len,
        };
        if len == 0 {
            return Err(invalid("data must not be empty", "invalid_params"));
        }
        if len > MAX_CHUNK_PAYLOAD_BYTES {
            return Err(Failure::invalid_params_with(
                format!("Payload exceeds maximum chunk size of {MAX_CHUNK_PAYLOAD_BYTES} bytes"),
                "payload_too_large",
                vec![
                    ("limit", Value::int(MAX_CHUNK_PAYLOAD_BYTES)),
                    ("actual", Value::int(len)),
                ],
            )
            .into());
        }
        let Data::Inline(payload) = data else {
            // A part is past 64 KiB, so refused above.
            return Err(Failure::internal_error().into());
        };
        let span = validate_span(params.get("span")).ok_or_else(|| {
            invalid(
                "span must be a non-negative unsigned 64-bit integer",
                "invalid_span",
            )
        })?;
        let key = check(cx)?;
        let span = match span {
            Some(span) if span != 0 => span,
            _ => payload.len() as u64,
        };
        Ok(SocWrite {
            approval,
            identifier,
            payload,
            span,
            key,
            owner: [0; 20],
            row: None,
            closed: false,
            now: cx.world.now(),
            stage: Stage::Owner {
                id: cx.owner(key),
                recheck: false,
            },
        })
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        self.now = cx.world.now();
        match std::mem::replace(&mut self.stage, Stage::Gone) {
            Stage::Owner { id: asked, recheck } if asked == id => {
                self.owner = match owner(self.key, event) {
                    Ok(owner) => owner,
                    Err(failure) if recheck => return self.end(cx, Err(Fail::answer(failure))),
                    Err(failure) => return fail(failure),
                };
                if recheck {
                    return self.sign(cx);
                }
                self.stage = Stage::Ready(cx.ready(ReadyCheck::Publish));
                Step::Wait
            }
            Stage::Ready(asked) if asked == id => {
                if let Err(step) = super::chunk_reads::ready(event) {
                    return step;
                }
                #[expect(clippy::cast_precision_loss, reason = "at most 4,096 bytes")]
                let size = self.payload.len() as f64;
                let entry = row(&[
                    ("type", s("soc")),
                    ("name", s("SOC chunk")),
                    ("status", s("uploading")),
                    ("origin", JsValue::String(cx.origin.clone())),
                    ("bytesSize", JsValue::Number(size)),
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
                Ok(()) => self.sign(cx),
                Err(text) => self.end(cx, Err(Fail::text(text))),
            },
            Stage::Sign {
                id: asked,
                prepared,
            } if asked == id => match signature(event, &self.owner, &prepared) {
                Ok(signature) => {
                    self.stage = Stage::Stamps {
                        id: cx.whole(stamps_call()),
                        signature,
                    };
                    Step::Wait
                }
                Err(failure) => self.end(cx, Err(failure)),
            },
            Stage::Stamps {
                id: asked,
                signature,
            } if asked == id => {
                let batch = match batch(event, 4096) {
                    Ok(batch) => batch,
                    Err(failure) => return self.end(cx, Err(failure)),
                };
                // After the batch's wait, the guard owns the upload.
                if let Err(refused) = guard(cx, self.approval, Capability::Signing) {
                    return self.end(cx, Err(Fail::refused(refused)));
                }
                let call = soc_up(
                    &self.owner,
                    &self.identifier,
                    &signature,
                    &batch,
                    true,
                    self.span,
                    &self.payload,
                );
                self.stage = Stage::SocUp {
                    id: cx.whole(call),
                    address: soc_address(&self.identifier, &self.owner),
                    batch,
                };
                Step::Wait
            }
            Stage::SocUp {
                id: asked,
                address,
                batch,
            } if asked == id => match soc_uploaded(event, &address) {
                Ok(reference) => {
                    let result = Value::object([
                        ("reference", Value::str(&reference)),
                        ("owner", Value::str(&fc_evm::checksum_address(&self.owner))),
                        ("identifier", Value::str(&hex(&self.identifier))),
                    ]);
                    let updates = row(&[
                        ("status", s("completed")),
                        ("reference", s(&reference)),
                        ("batchIdUsed", s(&batch.to_hex())),
                    ]);
                    self.end(cx, Ok((result, updates)))
                }
                Err(failure) => self.end(cx, Err(failure)),
            },
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

    /// The step that hands the signature to the vault: SW-1 again, with
    /// the feed-grant check, then the signature under the hold.
    fn sign<W: World>(&mut self, cx: &mut Cx<'_, W>) -> Step {
        let key = match check(cx).and_then(|key| still_here(cx).map(|()| key)) {
            Ok(key) => key,
            Err(failure) => return self.end(cx, Err(Fail::refused(failure))),
        };
        if key != self.key {
            // Another exclusive identity is active now: its owner first.
            self.key = key;
            self.stage = Stage::Owner {
                id: cx.owner(key),
                recheck: true,
            };
            return Step::Wait;
        }
        let prepared = match fc_swarm::prepare_soc(&self.identifier, Some(self.span), &self.payload)
        {
            Ok(prepared) => prepared,
            Err(_) => return self.end(cx, Err(Fail::internal())),
        };
        let id = cx.sign(SignSoc {
            key,
            identifier: self.identifier,
            span: self.span,
            payload: self.payload.clone(),
            hold: Some(cx.origin.clone()),
            kind: SocKind::Raw,
        });
        self.stage = Stage::Sign { id, prepared };
        Step::Wait
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

/// The feed grant, #89's refusal and SW-1, in today's order, over the store
/// as it stands: the active identity's key, or the first check's error.
fn check<W: World>(cx: &Cx<'_, W>) -> Result<SignKey, Failure> {
    let feeds = cx.world.feeds();
    if !feeds.has_feed_grant(cx.origin) {
        return Err(feed_not_granted());
    }
    let identity = feeds.active_origin_identity(cx.origin);
    unavailable(identity.as_ref())?;
    let shown = identity.clone().unwrap_or(JsValue::Null);
    if feeds.is_identity_shared_with_other_origins(cx.origin, &shown) {
        return Err(shared_identity());
    }
    signer_key(identity.as_ref())
}

/// `validateSpan(span)`: `Some(None)` for none, `Some(Some(n))` for a span
/// within u64, `None` for one refused.
fn validate_span(span: &Value) -> Option<Option<u64>> {
    match span {
        Value::Undefined | Value::Null => Some(None),
        Value::Number(n) => {
            let safe = crate::js::is_integer(*n)
                && *n >= 0.0
                && *n <= crate::chunks::MAX_SAFE_INTEGER as f64;
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "a safe non-negative integer"
            )]
            safe.then_some(Some(*n as u64))
        }
        Value::BigInt(text) => {
            if text.starts_with('-') {
                return None;
            }
            let n: u128 = text.parse().ok()?;
            (n <= MAX_U64).then(|| u64::try_from(n).ok())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_as_validate_span() {
        assert_eq!(validate_span(&Value::Undefined), Some(None));
        assert_eq!(validate_span(&Value::Number(-0.0)), Some(Some(0)));
        assert_eq!(validate_span(&Value::Number(1.5)), None);
        assert_eq!(validate_span(&Value::Number(-1.0)), None);
        assert_eq!(validate_span(&Value::Number(9_007_199_254_740_992.0)), None);
        assert_eq!(
            validate_span(&Value::BigInt("18446744073709551615".into())),
            Some(Some(u64::MAX))
        );
        assert_eq!(
            validate_span(&Value::BigInt("18446744073709551616".into())),
            None
        );
        assert_eq!(validate_span(&Value::BigInt("-1".into())), None);
        assert_eq!(validate_span(&Value::str("1")), None);
    }

    #[test]
    fn the_refusal_reads_as_today() {
        let failure = shared_identity();
        assert_eq!(failure.code, 4100);
        assert_eq!(
            failure.data,
            Some(Value::object([("reason", Value::str("shared_identity"))]))
        );
    }
}
