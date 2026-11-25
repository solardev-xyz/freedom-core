//! `swarm.feed` (design 0015, "Methods main calls"): main's own feeds (the
//! agent's stable addresses), as feed-service.js's `createFeed` and
//! `updateFeed` write them, under the Bee wallet key only (SW-1, "Feeds,
//! SOCs and SW-1": `swarm.feed` takes only the Bee wallet key).
//!
//! In the reference's order:
//! - **the signer** (swarm-signer.js's `resolveSwarmSigner({ mode:
//!   'bee-wallet' })`, which main's caller resolves first): the vault's
//!   owner of the Bee wallet key; a locked vault is `Vault is locked`;
//! - **the batch:** the given one, else one `/stamps` read and
//!   `selectBestBatch(4096)` (`null` is `noUsableBatchError`);
//! - **create:** `POST /feeds/<o>/<t>` (`createFeedManifest`), answered `{
//!   topic, owner, manifestReference, bzzUrl }`;
//! - **update:** one write to a topic at a time (`withWriteLock`); the next
//!   index (`resolveNextIndex`: `feed_head` with `swarm-only-root-chunk`,
//!   else the head probe, deviation `index-probe`) and at least
//!   `min_index`; the update `unix seconds ‖ reference` signed by the
//!   vault and checked as `createSwarmSigner` checks it; `POST
//!   /soc/<o>/<id>` checked against the SOC's own address; answered `{
//!   index }`.
//!
//! The `topic` is the 32 bytes main computes (`Topic.fromString(…)`), as
//! the grammar binds `<t> = topic`.

use fc_swarm::PreparedChunk;
use fc_swarm::verify::{feed_update_id, soc_address};

use super::feed_index::{Next, NextIndex};
use super::writes::{
    BeeRead, bee_upload_read, feed_manifest, owner, signature, soc_up, soc_uploaded,
};
use crate::chunks::hex;
use crate::errors::{ServiceError, Site};
use crate::machine::shell::{self, FeedCall, FeedOp, ShellError, ShellOutcome, ShellStep};
use crate::machine::{AskId, Cx, Event, NodeCall, SignKey, SignSoc, SocKind, World};
use crate::stamps::{BatchId, SelectOptions, read_stamps, select_best_batch};
use crate::value::Value;

/// The size every feed write's batch needs room for (`selectBestBatch(4096)`).
const FEED_BATCH_SIZE: u64 = 4096;

pub(crate) struct ShellFeed {
    op: FeedOp,
    topic: [u8; 32],
    batch: Option<BatchId>,
    owner: [u8; 20],
    stage: Stage,
}

enum Stage {
    Owner(AskId),
    Stamps(AskId),
    Manifest(AskId),
    Lock(AskId),
    Lookup {
        id: AskId,
        next: NextIndex,
    },
    Sign(Box<Signing>),
    SocUp {
        id: AskId,
        address: [u8; 32],
        index: u64,
    },
    Gone,
}

/// The update the vault signs.
struct Signing {
    id: AskId,
    index: u64,
    identifier: [u8; 32],
    prepared: PreparedChunk,
    span: u64,
    payload: Vec<u8>,
}

impl ShellFeed {
    pub(crate) fn start<W: World>(cx: &mut Cx<'_, W>, call: FeedCall) -> Self {
        ShellFeed {
            op: call.op,
            topic: call.topic,
            batch: call.batch,
            owner: [0; 20],
            stage: Stage::Owner(cx.owner(SignKey::BeeWallet)),
        }
    }

    pub(crate) fn on<W: World>(
        &mut self,
        cx: &mut Cx<'_, W>,
        id: AskId,
        event: Event,
    ) -> ShellStep {
        match std::mem::replace(&mut self.stage, Stage::Gone) {
            Stage::Owner(asked) if asked == id => match owner(SignKey::BeeWallet, event) {
                Ok(owner) => {
                    self.owner = owner;
                    if self.batch.is_some() {
                        return self.write(cx);
                    }
                    self.stage = Stage::Stamps(cx.whole(NodeCall::stamps()));
                    ShellStep::Wait
                }
                Err(failure) => ShellStep::Done(shell::error(failure.message)),
            },
            Stage::Stamps(asked) if asked == id => match batch_of(event) {
                Ok(batch) => {
                    self.batch = Some(batch);
                    self.write(cx)
                }
                Err(outcome) => ShellStep::Done(outcome),
            },
            Stage::Manifest(asked) if asked == id => ShellStep::Done(self.manifest(event)),
            Stage::Lock(asked) if asked == id => {
                if event != Event::Locked {
                    return ShellStep::Done(shell::internal());
                }
                let (next, call) = NextIndex::start(self.owner, self.topic);
                self.stage = Stage::Lookup {
                    id: cx.whole(call),
                    next,
                };
                ShellStep::Wait
            }
            Stage::Lookup {
                id: asked,
                mut next,
            } if asked == id => {
                let step = match event {
                    Event::Reply(reply) => next.reply(&reply),
                    Event::Failed(class) => next.failed(class),
                    _ => return ShellStep::Done(shell::internal()),
                };
                match step {
                    Next::Call(call) => {
                        self.stage = Stage::Lookup {
                            id: cx.whole(call),
                            next,
                        };
                        ShellStep::Wait
                    }
                    Next::Index(index) => self.sign(cx, index),
                    Next::Error(message) => ShellStep::Done(shell::error(message)),
                    Next::Failed(class) => ShellStep::Done(shell::failed(class)),
                }
            }
            Stage::Sign(signing) if signing.id == id => {
                let sig = match signature(event, &self.owner, &signing.prepared) {
                    Ok(sig) => sig,
                    Err(fail) => return ShellStep::Done(shell::error(fail.message)),
                };
                let Some(batch) = &self.batch else {
                    return ShellStep::Done(shell::internal());
                };
                let call = soc_up(
                    &self.owner,
                    &signing.identifier,
                    &sig,
                    batch,
                    false,
                    signing.span,
                    &signing.payload,
                );
                self.stage = Stage::SocUp {
                    id: cx.whole(call),
                    address: soc_address(&signing.identifier, &self.owner),
                    index: signing.index,
                };
                ShellStep::Wait
            }
            Stage::SocUp {
                id: asked,
                address,
                index,
            } if asked == id => ShellStep::Done(match event {
                Event::Failed(class) => shell::failed(class),
                event => match soc_uploaded(event, &address) {
                    // `{ index }`: the index as a JavaScript number.
                    Ok(_) => ShellOutcome::Result(Value::object([("index", Value::int(index))])),
                    Err(fail) => shell::error(fail.message),
                },
            }),
            _ => ShellStep::Done(shell::internal()),
        }
    }

    /// The batch is known: the manifest, or the update's turn on its topic.
    fn write<W: World>(&mut self, cx: &mut Cx<'_, W>) -> ShellStep {
        let Some(batch) = &self.batch else {
            return ShellStep::Done(shell::internal());
        };
        self.stage = match self.op {
            FeedOp::Create => {
                Stage::Manifest(cx.whole(feed_manifest(&self.owner, &self.topic, batch)))
            }
            FeedOp::Update { .. } => Stage::Lock(cx.lock(self.topic)),
        };
        ShellStep::Wait
    }

    /// `createFeed`'s answer from the manifest's.
    fn manifest(&self, event: Event) -> ShellOutcome {
        let reply = match shell::whole_reply(event) {
            Ok(reply) => reply,
            Err(outcome) => return outcome,
        };
        if !reply.ok() {
            return shell::error_reply(&reply, Site::BeeJs);
        }
        let reference = match bee_upload_read(&reply.body, None) {
            Ok((reference, _)) => hex(&reference),
            Err(BeeRead::Reply(err)) => return shell::reply_error(err),
            Err(BeeRead::Thrown(message)) => return shell::error(message),
        };
        ShellOutcome::Result(Value::object([
            ("topic", Value::str(&hex(&self.topic))),
            ("owner", Value::str(&fc_evm::checksum_address(&self.owner))),
            ("manifestReference", Value::str(&reference)),
            ("bzzUrl", Value::str(&format!("bzz://{reference}"))),
        ]))
    }

    /// The index the lookup gave, at least `min_index`: the update signed.
    fn sign<W: World>(&mut self, cx: &mut Cx<'_, W>, next: u64) -> ShellStep {
        let FeedOp::Update {
            reference,
            min_index,
        } = &self.op
        else {
            return ShellStep::Done(shell::internal());
        };
        // `Math.max(minIndex, nextIndex)`.
        let index = next.max(*min_index);
        // bee-js's update payload: unix seconds (uint64, big endian) ‖ the
        // reference.
        let mut payload = (cx.world.now() / 1000).to_be_bytes().to_vec();
        payload.extend_from_slice(reference);
        let span = payload.len() as u64;
        let identifier = feed_update_id(&self.topic, index);
        let Ok(prepared) = fc_swarm::prepare_soc(&identifier, Some(span), &payload) else {
            return ShellStep::Done(shell::internal());
        };
        let id = cx.sign(SignSoc {
            key: SignKey::BeeWallet,
            identifier,
            span,
            payload: payload.clone(),
            hold: None,
            kind: SocKind::Feed,
        });
        self.stage = Stage::Sign(Box::new(Signing {
            id,
            index,
            identifier,
            prepared,
            span,
            payload,
        }));
        ShellStep::Wait
    }
}

/// `selectBestBatch(4096)` over `/stamps`' answer: `null` is
/// `noUsableBatchError`.
fn batch_of(event: Event) -> Result<BatchId, ShellOutcome> {
    let reply = shell::whole_reply(event)?;
    if !reply.ok() {
        return Err(shell::error_reply(&reply, Site::BeeJs));
    }
    let stamps = read_stamps(&reply.body).map_err(shell::reply_error)?;
    let selection = select_best_batch(&stamps, FEED_BATCH_SIZE, SelectOptions::default())
        .map_err(|err| ShellOutcome::Error(ShellError::js(&err)))?;
    match selection.outcome {
        Ok(Some(batch)) => Ok(batch),
        Ok(None) => Err(ShellOutcome::Error(ShellError::service(
            &ServiceError::no_usable_batch(),
        ))),
        Err(postage) => Err(ShellOutcome::Error(ShellError::postage(&postage))),
    }
}
