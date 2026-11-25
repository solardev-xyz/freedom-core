//! `readFeedEntry` (swarm-provider-ipc.js's `handleReadFeedEntry`;
//! feed-service.js's `readFeedPayload` with #1057's metered reads):
//! permission-free, by `topic` and `owner`, or by `name` with the site's
//! own topic and, without an `owner`, the owner its feed store records.
//!
//! **At an explicit index** (`readExactFeedEntry`): the update's SOC as one
//! `chunk` call (with `feed: { owner, index }`), its wire bytes charged as
//! soon as it is read; then the size in the span it wraps. An entry that
//! fits in the SOC is its payload held to that size. A larger one past the
//! site's `maxBytes` is `data_too_large`; otherwise the rest of its size is
//! reserved before `bytes` streams the chunk it wraps, held to exactly that
//! size.
//!
//! **The latest entry** (`readLatestFeedEntry`): `feed_latest`, streamed
//! under the site's `maxBytes`. A declared length is checked and reserved
//! on the head; without one, each data frame main sends is reserved as it
//! comes (deviation `read-pieces`: #1057 reserves per network read). Past
//! `maxBytes` or past what is left of the window, the stream is cancelled.
//! Its memory charge is for `maxBytes`, all it may hold: the budget's
//! window can roll during the read, and then its frames are reserved in
//! the next window, so what is left of the first one doesn't bound it.

use fc_json::{JsString, number_to_string};
use fc_swarm::verify::feed_update_address;

use super::chunk_reads::{begin, ready};
use super::feed_index::wrapping_index;
use crate::chunks::{bytes_from_hex, data_size, safe_number, single_owner, span_value};
use crate::errors::Site;
use crate::js::{concat, is_js_whitespace};
use crate::machine::node::{ERROR_TEXT, Failed, transport_text};
use crate::machine::params::{feed_name, is_hex, require_params, strip_0x};
use crate::machine::{
    Abort, AskId, Cx, Event, Failure, Head, NodeCall, Outcome, Reply, Step, World, done, fail,
};
use crate::value::{Value, encode_base64};

/// `handleReadFeedEntry`.
pub(crate) struct ReadFeed {
    /// `params.index` as the page gave it, and the update's index.
    index: Option<(f64, u64)>,
    /// The owner as resolved (`owner.replace(/^0x/, '')`), read as an
    /// `EthAddress` once the node is reachable.
    owner: JsString,
    topic: [u8; 32],
    stage: Stage,
}

enum Stage {
    Ready(AskId),
    Soc {
        id: AskId,
        address: [u8; 32],
    },
    Wrapped {
        id: AskId,
        expected: u64,
        data: Vec<u8>,
    },
    Latest {
        id: AskId,
        max: u64,
        head: Option<LatestHead>,
        data: Vec<u8>,
    },
    Gone,
}

#[derive(Debug, Clone, Copy)]
struct LatestHead {
    index: u64,
    next: u64,
    declared: Option<u64>,
}

fn invalid(message: &str, reason: &str) -> Outcome {
    Failure::invalid_params(message, reason).into()
}

impl ReadFeed {
    pub(crate) fn start<W: World>(cx: &mut Cx<'_, W>, params: &Value) -> Result<Self, Outcome> {
        require_params(params)?;
        let (topic, name, owner, index) = (
            params.get("topic"),
            params.get("name"),
            params.get("owner"),
            params.get("index"),
        );
        let (has_topic, has_name) = (!topic.is_nullish(), !name.is_nullish());
        if has_topic && has_name {
            return Err(invalid(
                "Provide either topic or name, not both",
                "invalid_params",
            ));
        }
        if !has_topic && !has_name {
            return Err(invalid(
                "Either topic or name is required",
                "invalid_params",
            ));
        }
        let index = match index {
            Value::Undefined | Value::Null => None,
            Value::Number(n) if n.is_finite() && n.fract() == 0.0 && *n >= 0.0 => {
                Some((*n, wrapping_index(*n)))
            }
            _ => {
                return Err(invalid(
                    "index must be a non-negative integer",
                    "invalid_params",
                ));
            }
        };
        let bad_owner = || {
            invalid(
                "owner must be a valid 40-character hex address",
                "invalid_owner",
            )
        };
        let (topic, owner) = if has_topic {
            let topic = match topic {
                Value::String(t) if is_hex(t, 64) => crate::chunks::unhex::<32>(t.as_str())
                    .ok_or_else(|| {
                        invalid("topic must be a 64-character hex string", "invalid_topic")
                    })?,
                _ => {
                    return Err(invalid(
                        "topic must be a 64-character hex string",
                        "invalid_topic",
                    ));
                }
            };
            let Value::String(owner) = owner else {
                return Err(invalid(
                    "owner is required when using topic",
                    "invalid_owner",
                ));
            };
            if owner.is_empty() {
                return Err(invalid(
                    "owner is required when using topic",
                    "invalid_owner",
                ));
            }
            let resolved = strip_0x(owner);
            if !is_hex(&resolved, 40) {
                return Err(bad_owner());
            }
            (topic, resolved)
        } else {
            let name = feed_name(name).map_err(|m| invalid(m, "invalid_feed_name"))?;
            // Topic.fromString(`${origin}/${name}`): its UTF-8, a lone
            // surrogate as U+FFFD.
            let topic = fc_swarm::feed::topic(&format!("{}/{}", cx.origin.as_str(), name.as_str()));
            let owner = if owner.truthy() {
                let resolved = match owner {
                    Value::String(s) => strip_0x(s),
                    _ => JsString::default(),
                };
                if !is_hex(&resolved, 40) {
                    return Err(bad_owner());
                }
                resolved
            } else {
                let feed = cx.world.feeds().feed(cx.origin, name);
                let stored = feed
                    .as_ref()
                    .and_then(|f| f.get("owner"))
                    .filter(|o| o.truthy());
                match stored {
                    None => {
                        let message = concat(&[
                            &JsString::from("Feed not found: "),
                            name,
                            &JsString::from(". Create it first or provide owner explicitly."),
                        ]);
                        return Err(Failure::invalid_params(message, "feed_not_found").into());
                    }
                    Some(fc_json::JsValue::String(s)) => strip_0x(s),
                    // `existingFeed.owner.replace(...)` of a value that
                    // isn't a string: a TypeError, executeSwarmMethod's
                    // -32603.
                    Some(_) => {
                        return Err(Failure::internal(
                            "existingFeed.owner.replace is not a function",
                        )
                        .into());
                    }
                }
            };
            (topic, owner)
        };
        let ready = begin(cx)?;
        Ok(ReadFeed {
            index,
            owner,
            topic,
            stage: Stage::Ready(ready),
        })
    }

    pub(crate) fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        match std::mem::replace(&mut self.stage, Stage::Gone) {
            Stage::Ready(ready_id) if id == ready_id => {
                if let Err(step) = ready(event) {
                    return step;
                }
                // `new EthAddress(ownerAddress)`, before the read.
                let owner = match bytes_from_hex::<20>(self.owner.as_str()) {
                    Ok(owner) => owner,
                    Err(message) => return fail(Failure::internal(message)),
                };
                match self.index {
                    Some((_, index)) => {
                        let address = feed_update_address(&owner, &self.topic, index);
                        let call = NodeCall::chunk(&address).with_feed(owner, index);
                        self.stage = Stage::Soc {
                            id: cx.whole(call),
                            address,
                        };
                    }
                    None => {
                        // Charged for all it may hold: its `max_bytes`, the
                        // site's `maxBytes`. The room left in this window
                        // isn't a bound: the window can roll during the
                        // read, and the frames after it are reserved in the
                        // next one, as the reference reserves them.
                        let max = cx.max_bytes();
                        let call = NodeCall::feed_latest(
                            &owner,
                            &self.topic,
                            usize::try_from(max).unwrap_or(usize::MAX),
                        );
                        self.stage = Stage::Latest {
                            id: cx.stream(call, max),
                            max,
                            head: None,
                            data: Vec::new(),
                        };
                    }
                }
                Step::Wait
            }
            Stage::Soc {
                id: soc_id,
                address,
            } if id == soc_id => self.soc(cx, &address, event),
            Stage::Wrapped {
                id: wrapped_id,
                expected,
                mut data,
            } if id == wrapped_id => match event {
                Event::Head(_) => {
                    self.stage = Stage::Wrapped {
                        id: wrapped_id,
                        expected,
                        data,
                    };
                    Step::Wait
                }
                Event::Data(bytes) => {
                    data.extend_from_slice(&bytes);
                    cx.credit(wrapped_id, bytes.len());
                    self.stage = Stage::Wrapped {
                        id: wrapped_id,
                        expected,
                        data,
                    };
                    Step::Wait
                }
                Event::End => {
                    if data.len() as u64 != expected {
                        return fail(Failure::internal(format!(
                            "Node returned {} bytes for a {expected}-byte feed entry",
                            data.len()
                        )));
                    }
                    done(self.result(&data))
                }
                Event::Abort(Abort::TooLarge) | Event::Failed(Failed::TooLarge) => {
                    fail(Failure::internal(format!(
                        "Node returned more than {expected} bytes for a {expected}-byte feed entry"
                    )))
                }
                Event::Abort(_) => fail(Failure::internal(ERROR_TEXT)),
                Event::Reply(reply) => fail(self.node_error(&reply, Site::BeeJs)),
                Event::Failed(failed) => fail(failed_read(failed)),
                _ => fail(Failure::internal_error()),
            },
            Stage::Latest {
                id: latest_id,
                max,
                head,
                data,
            } if id == latest_id => self.latest(cx, latest_id, max, head, data, event),
            _ => fail(Failure::internal_error()),
        }
    }

    /// The update's SOC (`readExactFeedEntry`).
    fn soc<W: World>(&mut self, cx: &mut Cx<'_, W>, address: &[u8; 32], event: Event) -> Step {
        let reply = match event {
            Event::Reply(reply) => reply,
            // A SOC past its 4,201 bytes: the reference's own text names
            // the payload's length, which main didn't read.
            Event::Failed(Failed::TooLarge) => {
                return fail(crate::errors::reply_too_large().into());
            }
            Event::Failed(failed) => return fail(failed_read(failed)),
            _ => return fail(Failure::internal_error()),
        };
        if !reply.ok() {
            return fail(self.node_error(&reply, Site::BeeJs));
        }
        let raw = reply.body.len() as u64;
        // The SOC came off the network: charged before any refusal.
        let charged = cx.consume(0, raw);
        let soc = match single_owner(address, &reply.body) {
            Ok(soc) => soc,
            Err(message) => return fail(Failure::internal(message)),
        };
        // makeContentAddressedChunk(soc.payload, soc.span).
        if soc.payload.is_empty() {
            return fail(Failure::internal("payload size 0 exceeds limits [1, 4096]"));
        }
        let size = data_size(&soc.span);
        if span_value(&soc.span) <= 4096 {
            if let Err(refused) = charged {
                return fail(refused);
            }
            // The entry is the payload held to its size.
            let expected = usize::try_from(size).unwrap_or(usize::MAX);
            if soc.payload.len() < expected {
                return fail(Failure::internal(format!(
                    "Node returned {} bytes for a {expected}-byte feed entry",
                    soc.payload.len()
                )));
            }
            return done(self.result(&soc.payload[..expected]));
        }
        let max = cx.max_bytes();
        if size > max {
            return fail(too_large(max, Some(size)));
        }
        if let Err(refused) = charged {
            return fail(refused);
        }
        if size > raw
            && let Err(refused) = cx.reserve(size - raw)
        {
            return fail(refused);
        }
        let Some(wrapped) = soc.wrapped_address() else {
            return fail(Failure::internal_error());
        };
        let n = usize::try_from(size).unwrap_or(usize::MAX);
        let id = cx.stream(NodeCall::bytes(&wrapped, None, n), size);
        self.stage = Stage::Wrapped {
            id,
            expected: size,
            data: Vec::with_capacity(n),
        };
        Step::Wait
    }

    /// The latest entry's stream (`readLatestFeedEntry`).
    fn latest<W: World>(
        &mut self,
        cx: &mut Cx<'_, W>,
        id: AskId,
        max: u64,
        head: Option<LatestHead>,
        mut data: Vec<u8>,
        event: Event,
    ) -> Step {
        match event {
            Event::Head(h) => {
                let head = match read_head(&h) {
                    Ok(head) => head,
                    Err(failure) => return fail(failure),
                };
                if let Some(declared) = head.declared {
                    if declared > max {
                        return fail(too_large(max, Some(declared)));
                    }
                    if let Err(refused) = cx.reserve(declared) {
                        return fail(refused);
                    }
                }
                self.stage = Stage::Latest {
                    id,
                    max,
                    head: Some(head),
                    data,
                };
                Step::Wait
            }
            Event::Data(bytes) => {
                let Some(h) = head else {
                    return fail(Failure::internal_error());
                };
                let total = (data.len() + bytes.len()) as u64;
                match h.declared {
                    Some(declared) if total > declared => {
                        return fail(Failure::internal(format!(
                            "Node sent more than the {declared} bytes it declared for the feed entry"
                        )));
                    }
                    Some(_) => {}
                    None => {
                        if total > max {
                            return fail(too_large(max, None));
                        }
                        if let Err(refused) = cx.reserve(bytes.len() as u64) {
                            return fail(refused);
                        }
                    }
                }
                data.extend_from_slice(&bytes);
                cx.credit(id, bytes.len());
                self.stage = Stage::Latest {
                    id,
                    max,
                    head,
                    data,
                };
                Step::Wait
            }
            Event::End => {
                let Some(h) = head else {
                    return fail(Failure::internal_error());
                };
                if let Some(declared) = h.declared
                    && data.len() as u64 != declared
                {
                    return fail(Failure::internal(format!(
                        "Node sent {} of the {declared} bytes it declared for the feed entry",
                        data.len()
                    )));
                }
                done(entry(&data, h.index, h.next))
            }
            Event::Abort(Abort::TooLarge) | Event::Failed(Failed::TooLarge) => {
                fail(too_large(max, None))
            }
            Event::Abort(_) => fail(Failure::internal(ERROR_TEXT)),
            Event::Reply(reply) => fail(self.node_error(&reply, Site::FetchNode)),
            Event::Failed(failed) => fail(failed_read(failed)),
            _ => fail(Failure::internal_error()),
        }
    }

    /// `readFeedPayload`'s reading of a node's error answer: a 404 or a
    /// 500 is `entry_not_found` at an index and `feed_empty` for the latest
    /// entry; anything else -32603 with its text.
    fn node_error(&self, reply: &Reply, site: Site) -> Failure {
        let err = match reply.error(site) {
            Ok(err) => err,
            Err(failed) => return failed_read(failed),
        };
        if !err.is_not_found() {
            return Failure::internal(err.message);
        }
        match self.index {
            Some((index, _)) => Failure::invalid_params(
                format!("Feed entry not found at index {}", number_to_string(index)),
                "entry_not_found",
            ),
            None => Failure::invalid_params("Feed is empty — no entries to read", "feed_empty"),
        }
    }

    fn result(&self, payload: &[u8]) -> Value {
        let index = self.index.map_or(0, |(_, index)| index);
        entry(payload, index, index.wrapping_add(1))
    }
}

/// The read's answer: `{ data, encoding, index, nextIndex }`, the indexes
/// as `Number`s.
fn entry(payload: &[u8], index: u64, next: u64) -> Value {
    Value::object([
        ("data", Value::String(encode_base64(payload).into())),
        ("encoding", Value::str("base64")),
        ("index", Value::int(index)),
        ("nextIndex", Value::int(next)),
    ])
}

/// `entryTooLarge(limit, actual?)` through `invalidParams`.
fn too_large(limit: u64, actual: Option<u64>) -> Failure {
    let mut extra = vec![("limit", Value::int(limit))];
    if let Some(actual) = actual {
        extra.push(("actual", safe_number(actual)));
    }
    Failure::invalid_params_with(
        format!("Feed entry exceeds the maximum read size of {limit} bytes"),
        "data_too_large",
        extra,
    )
}

/// A feed read's call that failed before any reply: its class's text, as
/// `readFeedPayload` passes a network error through; main's pool full is
/// `busy`.
fn failed_read(failed: Failed) -> Failure {
    match failed {
        Failed::Busy => Failure::busy(),
        class => Failure::internal(transport_text(class)),
    }
}

/// The latest entry's headers as bee-js reads them, and its declared
/// length (`declaredLength`).
fn read_head(head: &Head) -> Result<LatestHead, Failure> {
    let text = |name: &str| {
        head.header(name)
            .map(|v| v.text())
            .filter(|t| !t.is_empty())
    };
    let index = text("swarm-feed-index")
        .ok_or_else(|| Failure::internal("Response did not contain expected swarm-feed-index!"))?;
    let next = text("swarm-feed-index-next").ok_or_else(|| {
        Failure::internal("Response did not contain expected swarm-feed-index-next!")
    })?;
    let index = bytes_from_hex::<8>(&index).map_err(Failure::internal)?;
    let next = bytes_from_hex::<8>(&next).map_err(Failure::internal)?;
    let declared = head.header("content-length").and_then(|v| {
        let value = v.text();
        let trimmed = value.trim_matches(is_js_whitespace);
        if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: f64 = trimmed.parse().ok()?;
        // Number.isSafeInteger.
        (n <= 9_007_199_254_740_991.0)
            .then(|| trimmed.parse::<u64>().ok())
            .flatten()
    });
    Ok(LatestHead {
        index: u64::from_be_bytes(index),
        next: u64::from_be_bytes(next),
        declared,
    })
}
