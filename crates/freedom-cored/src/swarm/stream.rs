//! The swarm thread's streams on the wire (design 0015, "Streams"): a
//! part's request and head (`shell.swarm_part`), main's `swarm.body`
//! request and the core's head for it, and the abort codes each way. The
//! frames themselves are fc-protocol's ([`fc_protocol::stream::Duplex`]),
//! which the thread holds; these are the messages around them, read
//! strictly as [`super::wire`] reads the rest.
//!
//! - **Into the core:** a part (`shell.swarm_part { for, part }`) answers a
//!   head `{ bytes }`, then exactly that many bytes, ended by `end` or an
//!   abort with a part's codes ([`fc_protocol::stream::Codes::SwarmPart`]): `cancelled`,
//!   `stalled`, or `body_stream_error`, which alone may name the error code
//!   the part's file failed with (an errno name). A node body
//!   (`shell.swarm_api` with `stream: true`) answers its head (see
//!   [`super::wire::api_reply`]) and its bytes, ended by `end` or an abort
//!   with a piece's codes and `too_large`
//!   ([`fc_protocol::stream::Codes::SwarmPiece`]).
//! - **Out of the core:** `swarm.body { for }` names one of the thread's
//!   own `shell.swarm_api` calls whose body streams; the core answers a
//!   head `{ bytes }` and the body, ended by `end` or an abort with an
//!   upload's codes (`cancelled`, `internal`, `body_stream_error`).

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::message;
use fc_protocol::stream::{Abort as WireAbort, AbortCode};
use fc_swarm_provider::machine::{Abort, BodyAbort};
use serde::Deserialize;

/// The largest integer JavaScript keeps exactly.
const MAX_SAFE: u64 = (1 << 53) - 1;

/// `shell.swarm_part { for, part }`.
pub fn part_params(parent: u64, part: u32) -> Vec<u8> {
    format!(r#"{{"for":{parent},"part":{part}}}"#).into_bytes()
}

/// A part's head, `{ bytes }`: the part's length, a whole number up to
/// 2^53 − 1; `None` for anything else.
pub fn part_head(text: &str) -> Option<u64> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Head {
        bytes: u64,
    }
    let head: Head = super::wire::object(text)?;
    (head.bytes <= MAX_SAFE).then_some(head.bytes)
}

/// `swarm.body { for }`: the core's request whose body main asks for, or
/// why the params don't read (a fixed text).
pub fn body_params(text: Option<&str>) -> Result<u64, &'static str> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Params {
        #[serde(rename = "for")]
        parent: u64,
    }
    let params: Params = super::wire::object(text.ok_or("swarm.body needs params")?)
        .ok_or("swarm.body's params are { for }, a request of the core's")?;
    if params.parent == 0 || params.parent > MAX_SAFE {
        return Err("swarm.body's for is a request of the core's");
    }
    Ok(params.parent)
}

/// The core's head for `swarm.body` `id`: `{ bytes }`, the body's length,
/// as a response message.
pub fn body_head(id: u64, bytes: u64) -> Vec<u8> {
    format!(r#"{{"type":"response","id":{id},"result":{{"bytes":{bytes}}}}}"#).into_bytes()
}

/// `swarm.body` `id`'s error answer, as a response message.
pub fn body_error(id: u64, error: &ErrorBody) -> Option<Vec<u8>> {
    let mut payload = Vec::with_capacity(128);
    message::write_error(&mut payload, id, error).ok()?;
    Some(payload)
}

/// How the core ends a body short, on the wire: its abort, and the error
/// answer it is in place of a head that was never written.
pub fn body_abort(why: BodyAbort) -> (WireAbort, ErrorBody) {
    match why {
        BodyAbort::Cancelled => (
            WireAbort::cancelled(),
            ErrorBody::new(ErrorCode::Cancelled, "Cancelled"),
        ),
        BodyAbort::Internal => (
            WireAbort::new(AbortCode::Internal, "the core failed the body"),
            ErrorBody::new(ErrorCode::Internal, "the core failed the body"),
        ),
        BodyAbort::BodyStreamError => (
            WireAbort::new(AbortCode::BodyStreamError, "a part of the body failed"),
            ErrorBody::new(ErrorCode::Internal, "a part of the body failed"),
        ),
    }
}

/// Main's abort of a part or a node body, as the machines read it; `None`
/// for one the duplex wouldn't have taken.
pub fn abort_of(abort: &WireAbort) -> Option<Abort> {
    Some(match (abort.code, abort.error_code.as_deref()) {
        (AbortCode::Cancelled, None) => Abort::Cancelled,
        (AbortCode::Stalled, None) => Abort::Stalled,
        (AbortCode::BodyStreamError, None) => Abort::BodyStreamError,
        (AbortCode::TooLarge, None) => Abort::TooLarge,
        // A part's file failed with this error code (design 0015).
        (AbortCode::BodyStreamError, Some(name)) => {
            Abort::Unreadable(fc_swarm_provider::machine::ErrorCode::new(name)?)
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use fc_protocol::stream::Codes;

    #[test]
    fn a_parts_head_is_its_length() {
        assert_eq!(part_head(r#"{"bytes":0}"#), Some(0));
        assert_eq!(part_head(r#"{"bytes":200000}"#), Some(200_000));
        assert_eq!(
            part_head(r#"{"bytes":9007199254740991}"#),
            Some(9_007_199_254_740_991)
        );
        for bad in [
            r#"{}"#,
            r#"{"bytes":-1}"#,
            r#"{"bytes":1.5}"#,
            r#"{"bytes":"1"}"#,
            r#"{"bytes":9007199254740992}"#,
            r#"{"bytes":1,"more":1}"#,
            r#"[1]"#,
        ] {
            assert_eq!(part_head(bad), None, "{bad}");
        }
        assert_eq!(
            String::from_utf8(part_params(7, 2)).unwrap(),
            r#"{"for":7,"part":2}"#
        );
    }

    #[test]
    fn swarm_body_names_one_of_the_cores_requests() {
        assert_eq!(body_params(Some(r#"{"for":12}"#)), Ok(12));
        for bad in [
            None,
            Some(r#"{}"#),
            Some(r#"{"for":0}"#),
            Some(r#"{"for":-1}"#),
            Some(r#"{"for":"12"}"#),
            Some(r#"{"for":9007199254740992}"#),
            Some(r#"{"for":12,"more":1}"#),
            Some(r#"[12]"#),
        ] {
            assert!(body_params(bad).is_err(), "{bad:?}");
        }
        let head: serde_json::Value = serde_json::from_slice(&body_head(5, 9)).unwrap();
        assert_eq!(
            head,
            serde_json::json!({ "type": "response", "id": 5, "result": { "bytes": 9 } })
        );
    }

    #[test]
    fn aborts_read_as_the_machines_read_them() {
        assert_eq!(abort_of(&WireAbort::cancelled()), Some(Abort::Cancelled));
        assert_eq!(
            abort_of(&WireAbort::new(AbortCode::TooLarge, "m")),
            Some(Abort::TooLarge)
        );
        let unreadable = WireAbort::new(AbortCode::BodyStreamError, "m")
            .with_error_code("ENOENT")
            .unwrap();
        assert_eq!(
            abort_of(&unreadable),
            Some(Abort::Unreadable(
                fc_swarm_provider::machine::ErrorCode::new("ENOENT").unwrap()
            ))
        );
        assert_eq!(abort_of(&WireAbort::new(AbortCode::Internal, "m")), None);
        for why in [
            BodyAbort::Cancelled,
            BodyAbort::Internal,
            BodyAbort::BodyStreamError,
        ] {
            let (abort, _) = body_abort(why);
            assert!(Codes::CoreUpload.allows_abort(&abort), "{why:?}");
        }
    }
}
