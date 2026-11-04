//! The dweb thread's messages (design 0009, `dweb.verify`, `dweb.forget`,
//! `shell.dweb_get`): what main sends, read strictly, and what the core
//! writes.
//!
//! - **`dweb.verify`'s params** are exactly `{ plan, method, partition,
//!   private, deadline_ms }`, and `car` for an IPFS plan, whose gateway
//!   main probed. Any other member, or a value of another type, is
//!   `invalid_argument`. Main is trusted for `car`: a wrong `true` costs a
//!   CAR the walk then gives up for raw blocks, never verification.
//! - **Its answer** is a head, `{ status, headers, body, trust }`, or 0006's
//!   error plan, `{ error: { status, code, message } }`, which main answers
//!   as it answers any error plan. Protocol error replies are only `busy`,
//!   `cancelled` and `invalid_argument`.
//! - **`shell.dweb_get`'s replies** are exactly one of `{ status, headers,
//!   body_base64 }` (a whole piece), `{ status, headers, body: true }` (a
//!   stream's head) and `{ failed }`, its code one of a closed set. The
//!   headers are at most 8, each at most 8 KiB, and only those the core
//!   reads. Anything else is main breaking the protocol.

use base64::Engine as _;
use fc_dweb::ErrorPlan;
use fc_dweb::verifier::{Head, Method, PieceFailure, PieceRequest};
use fc_json::JsValue;

use super::engine::{Ms, Reply, Request};

/// The headers a piece's reply may carry: those the core reads.
pub const REPLY_HEADERS: [&str; 4] = [
    "content-type",
    "content-length",
    "content-range",
    "swarm-feed-index",
];
/// At most this many, each name and value at most [`MAX_HEADER`].
pub const MAX_REPLY_HEADERS: usize = 8;
pub const MAX_HEADER: usize = 8 << 10;

/// The members of `value` when it is an object with exactly `required`,
/// and of `optional` at most those: each one's value, in order.
fn members<'v, const R: usize, const O: usize>(
    value: &'v JsValue,
    required: [&str; R],
    optional: [&str; O],
) -> Option<([&'v JsValue; R], [Option<&'v JsValue>; O])> {
    let JsValue::Object(props) = value else {
        return None;
    };
    let known = |k: &str| required.contains(&k) || optional.contains(&k);
    if props.iter().any(|(k, _)| !known(k.as_str())) {
        return None;
    }
    let found: Vec<&JsValue> = required
        .iter()
        .map(|k| value.get(k))
        .collect::<Option<_>>()?;
    let found: [&JsValue; R] = found.try_into().ok()?;
    let optional = optional.map(|k| value.get(k));
    Some((found, optional))
}

fn integer(value: &JsValue) -> Option<u64> {
    let JsValue::Number(n) = *value else {
        return None;
    };
    if !(0.0..=9_007_199_254_740_991.0).contains(&n) || n.fract() != 0.0 {
        return None;
    }
    Some(n as u64)
}

/// `dweb.verify`'s params; the reason as `invalid_argument`'s message when
/// they aren't its own.
pub fn verify_params(params: Option<&str>) -> Result<Request, &'static str> {
    const INVALID: &str = "Invalid dweb.verify parameters";
    let value = fc_json::parse(params.ok_or(INVALID)?).map_err(|_| INVALID)?;
    let ([plan, method, partition, private, deadline_ms], [car]) = members(
        &value,
        ["plan", "method", "partition", "private", "deadline_ms"],
        ["car"],
    )
    .ok_or(INVALID)?;
    let plan = fc_dweb::Verify::from_value(plan).ok_or(INVALID)?;
    let method = match method.as_str() {
        Some("GET") => Method::Get,
        Some("HEAD") => Method::Head,
        _ => return Err(INVALID),
    };
    let partition = match partition {
        JsValue::Null => None,
        JsValue::String(s) => Some(s.as_str().to_owned()),
        _ => return Err(INVALID),
    };
    let JsValue::Bool(private) = *private else {
        return Err(INVALID);
    };
    let deadline_ms: Ms = integer(deadline_ms).ok_or(INVALID)?;
    // An IPFS plan says whether its gateway serves ordered CARs; an Ant
    // plan has nothing to say.
    let car = match (&plan.node, car) {
        (fc_dweb::Node::Ipfs, Some(JsValue::Bool(car))) => *car,
        (fc_dweb::Node::Ant, None) => false,
        _ => return Err(INVALID),
    };
    Ok(Request {
        plan,
        method,
        partition,
        private,
        deadline_ms,
        car,
    })
}

/// `dweb.forget`'s params: the partition, `None` for the profile's.
pub fn forget_params(params: Option<&str>) -> Result<Option<String>, &'static str> {
    const INVALID: &str = "Invalid dweb.forget parameters";
    let value = fc_json::parse(params.ok_or(INVALID)?).map_err(|_| INVALID)?;
    let ([partition], []) = members(&value, ["partition"], []).ok_or(INVALID)?;
    match partition {
        JsValue::Null => Ok(None),
        JsValue::String(s) => Ok(Some(s.as_str().to_owned())),
        _ => Err(INVALID),
    }
}

/// `dweb.verify`'s head, as its result.
pub fn head_result(head: &Head) -> serde_json::Value {
    serde_json::json!({
        "status": head.status,
        "headers": head.headers.iter().map(|(n, v)| [n, v]).collect::<Vec<_>>(),
        "body": head.body,
        "trust": { "name": head.trust.name, "content": head.trust.content.as_str() },
    })
}

/// A failure before the head, as its result: 0006's error plan.
pub fn error_result(error: &ErrorPlan) -> serde_json::Value {
    serde_json::json!({
        "error": { "status": error.status, "code": error.status, "message": error.message },
    })
}

/// `shell.dweb_get`'s params for `piece` of main's request `request`.
pub fn get_params(request: u64, piece: &PieceRequest) -> serde_json::Value {
    serde_json::json!({
        "for": request,
        "path": piece.path,
        "headers": piece.headers.iter().map(|(n, v)| [n, v]).collect::<Vec<_>>(),
        "stream": piece.stream,
        "max_bytes": piece.max_bytes,
    })
}

/// A piece's reply headers: an array of `[name, value]`, at most
/// [`MAX_REPLY_HEADERS`], each a header the core reads and each part at
/// most [`MAX_HEADER`].
fn reply_headers(value: &JsValue) -> Option<Vec<(String, String)>> {
    let items = value.as_array()?;
    if items.len() > MAX_REPLY_HEADERS {
        return None;
    }
    items
        .iter()
        .map(|pair| {
            let [n, v] = pair.as_array()? else {
                return None;
            };
            let (n, v) = (n.as_str()?, v.as_str()?);
            if !REPLY_HEADERS.contains(&n) || n.len() > MAX_HEADER || v.len() > MAX_HEADER {
                return None;
            }
            Some((n.to_owned(), v.to_owned()))
        })
        .collect()
}

/// `shell.dweb_get`'s reply, its `result` as main wrote it; `None` when it
/// isn't one of the three forms.
pub fn get_reply(result: &str) -> Option<Reply> {
    let value = fc_json::parse(result).ok()?;
    if let Some(([failed], [])) = members(&value, ["failed"], []) {
        let failure = match failed.as_str()? {
            "unreachable" => PieceFailure::Unreachable,
            "error" => PieceFailure::Error,
            "aborted" => PieceFailure::Aborted,
            "too_large" => PieceFailure::TooLarge,
            _ => return None,
        };
        return Some(Reply::Failed(failure));
    }
    let status = |v: &JsValue| {
        integer(v)
            .and_then(|s| u16::try_from(s).ok())
            .filter(|s| (100..600).contains(s))
    };
    if let Some(([s, h, body], [])) = members(&value, ["status", "headers", "body_base64"], []) {
        let body = base64::engine::general_purpose::STANDARD
            .decode(body.as_str()?)
            .ok()?;
        return Some(Reply::Whole {
            status: status(s)?,
            headers: reply_headers(h)?,
            body,
        });
    }
    let ([s, h, body], []) = members(&value, ["status", "headers", "body"], [])?;
    if *body != JsValue::Bool(true) {
        return None;
    }
    Some(Reply::Stream {
        status: status(s)?,
        headers: reply_headers(h)?,
    })
}

#[cfg(test)]
mod tests {
    use fc_dweb::{Backend, ContentTrust, Node, Plan, ResponseOp, Root, Trust, retry, timers};

    use super::*;

    fn plan(node: Node) -> fc_dweb::Verify {
        let (backend, root, response) = match node {
            Node::Ant => (
                Backend::ant(fc_dweb::Ant::External, true),
                Root::Swarm("ab".repeat(32)),
                vec![ResponseOp::CanonicalizeRedirect, ResponseOp::StripPageState],
            ),
            Node::Ipfs => (
                Backend::ipfs(fc_dweb::Ipfs::Gateway, true),
                Root::Ipfs("bafkqaaa".into()),
                vec![ResponseOp::StripPageState],
            ),
        };
        fc_dweb::Verify {
            node,
            root,
            path: "/".into(),
            query: String::new(),
            headers: vec![],
            retry: retry(backend),
            timers: timers(backend),
            response,
            trust: Trust {
                name: None,
                content: ContentTrust::Verified,
            },
        }
    }

    fn params(node: Node, car: Option<bool>) -> serde_json::Value {
        let plan: serde_json::Value =
            serde_json::from_str(&Plan::Verify(plan(node)).to_json()).unwrap();
        let mut p = serde_json::json!({
            "plan": plan, "method": "GET", "partition": null, "private": false, "deadline_ms": 360000,
        });
        if let Some(car) = car {
            p["car"] = car.into();
        }
        p
    }

    #[test]
    fn verify_params_are_read_strictly() {
        let ok = |v: &serde_json::Value| verify_params(Some(&v.to_string()));
        let r = ok(&params(Node::Ipfs, Some(false))).unwrap();
        assert_eq!(
            (r.method, r.car, r.deadline_ms),
            (Method::Get, false, 360_000)
        );
        assert!(ok(&params(Node::Ipfs, Some(true))).unwrap().car);
        assert!(!ok(&params(Node::Ant, None)).unwrap().car);
        // `car` is the IPFS plan's own: required there, refused for Ant.
        assert!(ok(&params(Node::Ipfs, None)).is_err());
        assert!(ok(&params(Node::Ant, Some(true))).is_err());
        let mut p = params(Node::Ant, None);
        p["partition"] = "private-1".into();
        p["method"] = "HEAD".into();
        p["private"] = true.into();
        let r = ok(&p).unwrap();
        assert_eq!(
            (r.method, r.partition.as_deref(), r.private),
            (Method::Head, Some("private-1"), true)
        );
        // Unknown members, wrong types, other methods, no params at all.
        for edit in [
            |p: &mut serde_json::Value| p["extra"] = 1.into(),
            |p: &mut serde_json::Value| p["method"] = "POST".into(),
            |p: &mut serde_json::Value| p["private"] = 0.into(),
            |p: &mut serde_json::Value| p["deadline_ms"] = (-1).into(),
            |p: &mut serde_json::Value| p["partition"] = 3.into(),
            |p: &mut serde_json::Value| p["plan"]["verify"]["node"] = "bee".into(),
            |p: &mut serde_json::Value| {
                p.as_object_mut().unwrap().remove("deadline_ms");
            },
        ] {
            let mut p = params(Node::Ant, None);
            edit(&mut p);
            assert!(ok(&p).is_err(), "{p}");
        }
        assert!(verify_params(None).is_err());
        assert!(verify_params(Some("[]")).is_err());
        assert_eq!(forget_params(Some(r#"{"partition":null}"#)), Ok(None));
        assert_eq!(
            forget_params(Some(r#"{"partition":"w"}"#)),
            Ok(Some("w".into()))
        );
        assert!(forget_params(Some(r#"{"partition":null,"x":1}"#)).is_err());
    }

    #[test]
    fn a_head_and_an_error_plan_are_told_apart() {
        // A node's own 404, proven: a head, with its body and its trust.
        let head = Head {
            status: 404,
            headers: vec![("content-type".into(), "application/json".into())],
            body: true,
            trust: Trust {
                name: None,
                content: ContentTrust::Verified,
            },
        };
        assert_eq!(
            head_result(&head),
            serde_json::json!({
                "status": 404, "headers": [["content-type", "application/json"]], "body": true,
                "trust": { "name": null, "content": "verified" },
            })
        );
        // A failure the core writes: 0006's error plan.
        let error = ErrorPlan {
            status: 404,
            message: fc_dweb::verifier::SWARM_NOT_FOUND.into(),
        };
        assert_eq!(
            error_result(&error),
            serde_json::json!({ "error": { "status": 404, "code": 404, "message": fc_dweb::verifier::SWARM_NOT_FOUND } })
        );
    }

    #[test]
    fn piece_replies_are_one_of_three_forms() {
        assert_eq!(
            get_reply(r#"{"status":200,"headers":[["content-type","x/y"]],"body_base64":"AAE="}"#),
            Some(Reply::Whole {
                status: 200,
                headers: vec![("content-type".into(), "x/y".into())],
                body: vec![0, 1],
            })
        );
        assert_eq!(
            get_reply(r#"{"status":206,"headers":[["content-range","bytes 0-1/2"]],"body":true}"#),
            Some(Reply::Stream {
                status: 206,
                headers: vec![("content-range".into(), "bytes 0-1/2".into())],
            })
        );
        for (code, failure) in [
            ("unreachable", PieceFailure::Unreachable),
            ("error", PieceFailure::Error),
            ("aborted", PieceFailure::Aborted),
            ("too_large", PieceFailure::TooLarge),
        ] {
            assert_eq!(
                get_reply(&format!(r#"{{"failed":"{code}"}}"#)),
                Some(Reply::Failed(failure))
            );
        }
        let long = "x".repeat(MAX_HEADER + 1);
        let nine = vec![r#"["content-type","a"]"#; 9].join(",");
        for bad in [
            // `stalled` is a stream's abort, never a failed dial.
            r#"{"failed":"stalled"}"#.to_owned(),
            r#"{"failed":"error","extra":1}"#.to_owned(),
            r#"{"status":200,"headers":[],"body_base64":"AA==","x":1}"#.to_owned(),
            r#"{"status":200,"headers":[],"body":false}"#.to_owned(),
            r#"{"status":99,"headers":[],"body":true}"#.to_owned(),
            r#"{"status":200,"headers":[["set-cookie","a"]],"body":true}"#.to_owned(),
            format!(r#"{{"status":200,"headers":[{nine}],"body":true}}"#),
            format!(r#"{{"status":200,"headers":[["content-type","{long}"]],"body":true}}"#),
            r#"{"status":200,"headers":[],"body_base64":"!!"}"#.to_owned(),
        ] {
            assert_eq!(get_reply(&bad), None, "{bad}");
        }
        // The core's request: the piece, for its dweb.verify.
        let piece = PieceRequest {
            id: fc_dweb::verifier::PieceId(3),
            path: "/chunks/ab".into(),
            headers: vec![("swarm-redundancy-strategy".into(), "3".into())],
            stream: false,
            max_bytes: Some(4104),
        };
        assert_eq!(
            get_params(7, &piece),
            serde_json::json!({
                "for": 7, "path": "/chunks/ab", "headers": [["swarm-redundancy-strategy", "3"]],
                "stream": false, "max_bytes": 4104,
            })
        );
    }
}
