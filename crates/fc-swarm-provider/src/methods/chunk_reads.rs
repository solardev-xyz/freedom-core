//! `readChunk` and `readSingleOwnerChunk` (swarm-provider-ipc.js's
//! `handleReadChunk`, `handleReadSingleOwnerChunk`; chunk-service.js's
//! `readChunk`, `readSingleOwnerChunk`): permission-free, so one request
//! is charged to the read budget, then the reachability check, then one
//! `chunk` call, checked as bee-js's `unmarshal*` checks it, and the
//! payload's bytes charged.

use fc_json::JsString;

use super::{chunk_error, chunk_failed, mismatch};
use crate::chunks::{self, content_addressed, safe_number, single_owner, span_value};
use crate::errors::ChunkRead;
use crate::machine::params::{
    bytes32, empty_options, hex_string, normalize_address, owner_bytes, require_params,
};
use crate::machine::{
    AskId, Cx, Event, Failure, NodeCall, Outcome, ReadyCheck, Step, World, done, fail,
};
use crate::value::{Value, encode_base64};

enum Stage {
    Ready(AskId),
    Chunk(AskId),
}

/// The reads' first steps: one request charged, then the reachability
/// check.
pub(crate) fn begin<W: World>(cx: &mut Cx<'_, W>) -> Result<AskId, Outcome> {
    cx.consume(1, 0)?;
    Ok(cx.ready(ReadyCheck::Reachable))
}

/// The readiness answer: on, or `Node not available: <reason>`.
pub(crate) fn ready(event: Event) -> Result<(), Step> {
    match event {
        Event::Ready(Ok(())) => Ok(()),
        Event::Ready(Err(reason)) => Err(fail(Failure::node_unavailable(&reason))),
        _ => Err(fail(Failure::internal_error())),
    }
}

/// `handleReadChunk`.
pub(crate) struct ReadChunk {
    /// The page's reference, as its texts quote it.
    reference: JsString,
    address: [u8; 32],
    stage: Stage,
}

impl ReadChunk {
    pub(crate) fn start<W: World>(cx: &mut Cx<'_, W>, params: &Value) -> Result<Self, Outcome> {
        require_params(params)?;
        empty_options(params.get("options"))?;
        let reference = hex_string(
            params.get("reference"),
            32,
            "invalid_reference",
            "reference",
        )?
        .clone();
        let address = bytes32(&reference).ok_or_else(Failure::internal_error)?;
        let ready = begin(cx)?;
        Ok(ReadChunk {
            reference,
            address,
            stage: Stage::Ready(ready),
        })
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        match self.stage {
            Stage::Ready(ready_id) if id == ready_id => {
                if let Err(step) = ready(event) {
                    return step;
                }
                self.stage = Stage::Chunk(cx.whole(NodeCall::chunk(&self.address)));
                Step::Wait
            }
            Stage::Chunk(chunk_id) if id == chunk_id => {
                let read = ChunkRead::Chunk;
                let reply = match event {
                    Event::Reply(reply) => reply,
                    Event::Failed(failed) => return fail(chunk_failed(failed, read)),
                    _ => return fail(Failure::internal_error()),
                };
                if !reply.ok() {
                    return fail(chunk_error(read, self.reference.as_str(), &reply));
                }
                let Some(cac) = content_addressed(&self.address, &reply.body) else {
                    return fail(mismatch(read));
                };
                let result = Value::object([
                    ("data", Value::String(encode_base64(cac.payload).into())),
                    ("encoding", Value::str("base64")),
                    ("span", safe_number(span_value(&cac.span))),
                ]);
                if let Err(refused) = cx.consume(0, cac.payload.len() as u64) {
                    return fail(refused);
                }
                done(result)
            }
            _ => fail(Failure::internal_error()),
        }
    }
}

/// `handleReadSingleOwnerChunk`: by `address`, or by `owner` and
/// `identifier`.
pub(crate) struct ReadSoc {
    address: [u8; 32],
    stage: Stage,
}

impl ReadSoc {
    pub(crate) fn start<W: World>(cx: &mut Cx<'_, W>, params: &Value) -> Result<Self, Outcome> {
        require_params(params)?;
        empty_options(params.get("options"))?;
        let address = params.get("address");
        let owner = params.get("owner");
        let identifier = params.get("identifier");
        let (has_address, has_owner, has_identifier) = (
            !address.is_nullish(),
            !owner.is_nullish(),
            !identifier.is_nullish(),
        );
        if has_address && (has_owner || has_identifier) {
            return Err(Failure::invalid_params(
                "Provide either address, or owner + identifier, not both",
                "invalid_params",
            )
            .into());
        }
        if !has_address && (!has_owner || !has_identifier) {
            return Err(Failure::invalid_params(
                "Either address, or owner + identifier, is required",
                "invalid_params",
            )
            .into());
        }
        let address = if has_address {
            let text = hex_string(address, 32, "invalid_reference", "address")?;
            bytes32(text).ok_or_else(Failure::internal_error)?
        } else {
            let Some(owner) = owner_bytes(&normalize_address(owner)) else {
                return Err(Failure::invalid_params(
                    "owner must be a valid 40-character hex address",
                    "invalid_owner",
                )
                .into());
            };
            let text = hex_string(identifier, 32, "invalid_identifier", "identifier")?;
            let identifier = bytes32(text).ok_or_else(Failure::internal_error)?;
            fc_swarm::verify::soc_address(&identifier, &owner)
        };
        let ready = begin(cx)?;
        Ok(ReadSoc {
            address,
            stage: Stage::Ready(ready),
        })
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        match self.stage {
            Stage::Ready(ready_id) if id == ready_id => {
                if let Err(step) = ready(event) {
                    return step;
                }
                self.stage = Stage::Chunk(cx.whole(NodeCall::chunk(&self.address)));
                Step::Wait
            }
            Stage::Chunk(chunk_id) if id == chunk_id => {
                let read = ChunkRead::SingleOwnerChunk;
                let reply = match event {
                    Event::Reply(reply) => reply,
                    Event::Failed(failed) => return fail(chunk_failed(failed, read)),
                    _ => return fail(Failure::internal_error()),
                };
                if !reply.ok() {
                    // The reference's text names no reference.
                    return fail(chunk_error(read, "", &reply));
                }
                let Ok(soc) = single_owner(&self.address, &reply.body) else {
                    return fail(mismatch(read));
                };
                let result = Value::object([
                    ("data", Value::String(encode_base64(soc.payload).into())),
                    ("encoding", Value::str("base64")),
                    ("span", safe_number(span_value(&soc.span))),
                    (
                        "reference",
                        Value::String(chunks::hex(&self.address).into()),
                    ),
                    (
                        "owner",
                        Value::String(fc_evm::checksum_address(&soc.owner).into()),
                    ),
                    (
                        "identifier",
                        Value::String(chunks::hex(&soc.identifier).into()),
                    ),
                    (
                        "signature",
                        Value::String(chunks::hex(&soc.signature).into()),
                    ),
                ]);
                if let Err(refused) = cx.consume(0, soc.payload.len() as u64) {
                    return fail(refused);
                }
                done(result)
            }
            _ => fail(Failure::internal_error()),
        }
    }
}
