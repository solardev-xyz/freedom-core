//! `requestAccess`, `getCapabilities` and `listFeeds`
//! (swarm-provider-ipc.js's `handleRequestAccess`, `handleGetCapabilities`,
//! `handleListFeeds`).
//!
//! The prompt and the grant's write are main's (0011, 0012): a site main's
//! dispatcher connected is connected by the time the core reads the grant.
//! The core answers from the grant as it stands.

use fc_json::{JsString, JsValue};

use super::limits;
use crate::machine::{AskId, Cx, Event, Failure, Outcome, ReadyCheck, Step, World, done, fail};
use crate::stores::{UNDEFINED, property_key};
use crate::value::Value;

/// `SPEC_VERSION`.
pub const SPEC_VERSION: &str = "1.0";

/// `handleRequestAccess(origin)`: the site's grant, or `not_connected`.
pub(crate) fn request_access<W: World>(cx: &mut Cx<'_, W>) -> Outcome {
    if !cx.connected() {
        return Failure::not_connected().into();
    }
    Outcome::Result(Value::object([
        ("connected", Value::Bool(true)),
        ("origin", Value::String(cx.origin.clone())),
        ("capabilities", Value::array([Value::str("publish")])),
    ]))
}

/// `handleGetCapabilities(origin)`: the grant, read first, then the
/// publish pre-flight (`shell.swarm_ready { check: "publish" }`).
pub(crate) struct Capabilities {
    connected: bool,
    ready: AskId,
}

impl Capabilities {
    pub(crate) fn start<W: World>(cx: &mut Cx<'_, W>) -> Result<Self, Outcome> {
        let connected = cx.connected();
        let ready = cx.ready(ReadyCheck::Publish);
        Ok(Capabilities { connected, ready })
    }

    pub(crate) fn on<W: World>(&mut self, _cx: &mut Cx<'_, W>, id: AskId, event: Event) -> Step {
        if id != self.ready {
            return fail(Failure::internal_error());
        }
        let answer = match event {
            Event::Ready(answer) => answer,
            _ => return fail(Failure::internal_error()),
        };
        let ok = answer.is_ok();
        let reason = if !self.connected {
            Value::str("not-connected")
        } else {
            match answer {
                Ok(()) => Value::Null,
                Err(reason) => Value::String(reason),
            }
        };
        done(capabilities(self.connected && ok, reason))
    }
}

fn capabilities(can_publish: bool, reason: Value) -> Value {
    Value::object([
        ("specVersion", Value::str(SPEC_VERSION)),
        ("canPublish", Value::Bool(can_publish)),
        ("reason", reason),
        (
            "publisherIdentityModes",
            Value::array([Value::str("app-scoped"), Value::str("bee-wallet")]),
        ),
        ("features", Value::array([Value::str("messaging")])),
        (
            "extensions",
            Value::object([("publisherSigning", Value::Bool(true))]),
        ),
        (
            "limits",
            Value::object([
                ("maxDataBytes", Value::int(limits::MAX_DATA_BYTES)),
                ("maxFilesBytes", Value::int(limits::MAX_FILES_BYTES)),
                ("maxFileCount", Value::int(limits::MAX_FILE_COUNT)),
                ("maxPathBytes", Value::int(limits::MAX_PATH_BYTES)),
                (
                    "maxChunkPayloadBytes",
                    Value::int(limits::MAX_CHUNK_PAYLOAD_BYTES),
                ),
                ("maxMessageBytes", Value::int(limits::MAX_MESSAGE_BYTES)),
                ("maxTargetDepth", Value::int(limits::MAX_TARGET_DEPTH)),
                ("maxSubscriptions", Value::int(limits::MAX_SUBSCRIPTIONS)),
            ]),
        ),
    ])
}

/// `handleListFeeds(origin)`: the site's feed records from the feed store,
/// then one request and the answer's JSON bytes charged to the read
/// budget. The params are ignored.
pub(crate) fn list_feeds<W: World>(cx: &mut Cx<'_, W>) -> Outcome {
    let feeds = cx.world.feeds().all_feeds(cx.origin);
    let members: &[(JsString, JsValue)] = match &feeds {
        JsValue::Object(members) => members,
        _ => &[],
    };
    let mut items = Vec::with_capacity(members.len());
    for (name, feed) in members {
        let field = |key: &str| feed.get(key).unwrap_or(&UNDEFINED);
        // `bzz://${feed.manifestReference}`.
        let reference = match property_key(field("manifestReference")) {
            Ok(text) => text,
            Err(thrown) => return Failure::internal(thrown.message).into(),
        };
        let bzz_url = crate::js::concat(&[&JsString::from("bzz://"), &reference]);
        items.push(Value::object([
            ("name", Value::String(name.clone())),
            ("topic", Value::from_js(field("topic"))),
            ("owner", Value::from_js(field("owner"))),
            (
                "manifestReference",
                Value::from_js(field("manifestReference")),
            ),
            ("bzzUrl", Value::String(bzz_url)),
            ("createdAt", Value::from_js(field("createdAt"))),
            ("lastUpdated", Value::from_js(field("lastUpdated"))),
            ("lastReference", Value::from_js(field("lastReference"))),
        ]));
    }
    let result = Value::array(items);
    // Buffer.byteLength(JSON.stringify(result)): the text is ASCII but for
    // the strings' own characters, which UTF-8 counts as it encodes them.
    let bytes = result.stringify().map_or(0, |text| text.len());
    if let Err(refused) = cx.consume(1, bytes as u64) {
        return refused.into();
    }
    Outcome::Result(result)
}
