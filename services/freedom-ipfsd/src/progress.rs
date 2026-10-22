//! Loading progress (design 0007, "Stats" and "Inside the process"):
//! upstream's per-node recorders, in the persistent process only.
//!
//! - **The persistent process** installs, first thing, a subscriber that
//!   feeds only the progress recorders ([`install`]): upstream's tracing
//!   goes nowhere else, as with the add-on today. Each instance records
//!   into its own recorder ([`Instance::progress`]), which `ipfs.stats`
//!   reports.
//! - **The ephemeral process** installs no subscriber at all, so a private
//!   window's paths and CIDs are never recorded, even in memory, and its
//!   `progress` is `null`.
//!
//! What reaches each instance's recorder is upstream's routing: its
//! runtime's threads are marked with it, and its gateway binds each
//! request's span to it. Everything the service runs on an instance's
//! behalf goes through those: requests and their bodies run on the
//! instance's runtime, in the request's span ([`Instance::spawn_request`]).
//! The service calls no provider or resolver itself, and emits no tracing
//! of its own; what it runs on its own threads (the stats job's SQL, a
//! start's build, a stop's teardown) emits no progress events. So nothing
//! of a request's reaches the process's default recorder, which nothing
//! reads.
//!
//! **A reply fits one frame** ([`fit`]): a snapshot holds at most 512
//! events, but its active targets, and every path in them, aren't bounded
//! by bytes. So the stats reply keeps as many active targets as fit, in
//! order, then as many of the newest events as fit, and drops the rest.
//! `active_count` and `event_count` stay what the recorder holds, so a
//! reader sees what was cut.
//!
//! [`Instance::progress`]: freedom_ipfs_gateway::Instance::progress
//! [`Instance::spawn_request`]: freedom_ipfs_gateway::Instance::spawn_request

use fc_protocol::frame::MAX_PAYLOAD;
use serde_json::Value;

/// A JSON frame's header, which [`fc_service::conn::head_len`] counts.
const JSON_HEADER: usize = 5;

/// Installs the process's tracing subscriber: upstream's, which feeds only
/// the progress recorders.
///
/// `init_progress_tracing` rather than a subscriber of the service's own
/// around `progress_layer()`: it is the same subscriber, a registry with the
/// progress layer and nothing else, and its layer always records, where
/// `progress_layer()` hands out a no-op to all but its first caller. It
/// needs no tracing crate of the service's own. It installs nothing if a
/// subscriber is installed already, which in this process none is: this
/// runs before anything else that could.
pub fn install() {
    freedom_ipfs_gateway::progress::init_progress_tracing();
}

/// `result`, the stats reply for request `id`, with its `progress` cut to
/// fit one frame: as many of its active targets as fit, in order, then as
/// many of its newest events as fit. A reply without progress, or one that
/// fits, is unchanged.
pub fn fit(id: u64, mut result: Value) -> Value {
    let Some(progress) = result.get_mut("progress").and_then(Value::as_object_mut) else {
        return result;
    };
    let mut take = |name: &str| match progress.get_mut(name) {
        Some(Value::Array(items)) => std::mem::take(items),
        _ => Vec::new(),
    };
    let (active, events) = (take("active"), take("events"));
    // What the reply takes with both lists empty: the rest of it, and the
    // envelope.
    let base = fc_service::conn::head_len(id, &result)
        .map_or(usize::MAX, |len| len.saturating_sub(JSON_HEADER));
    let mut room = MAX_PAYLOAD.saturating_sub(base);
    let active = keep(active.into_iter(), &mut room);
    let mut kept = keep(events.into_iter().rev(), &mut room);
    kept.reverse();
    if let Some(progress) = result.get_mut("progress").and_then(Value::as_object_mut) {
        progress.insert("active".into(), Value::Array(active));
        progress.insert("events".into(), Value::Array(kept));
    }
    result
}

/// The items of `items`, in its order, while they fit in `room` as one
/// list: each its JSON, and every one but the first a comma before it.
fn keep(items: impl Iterator<Item = Value>, room: &mut usize) -> Vec<Value> {
    let mut kept = Vec::new();
    for item in items {
        let comma = usize::from(!kept.is_empty());
        let len = encoded_len(&item).saturating_add(comma);
        if len > *room {
            break;
        }
        *room -= len;
        kept.push(item);
    }
    kept
}

/// The length of `value`'s JSON, counted without encoding it.
fn encoded_len(value: &Value) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    match serde_json::to_writer(&mut count, value) {
        Ok(()) => count.0,
        Err(_) => usize::MAX,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use serde_json::json;

    use super::*;

    /// A stats reply whose progress has `active` targets and `events`
    /// events, with paths of `pad` and `event_pad` bytes.
    fn reply(active: usize, events: usize, pad: usize, event_pad: usize) -> Value {
        let item = |n: usize, pad: usize| json!({ "id": n, "path": "x".repeat(pad) });
        json!({
            "gateway": { "total_started": 1 },
            "progress": {
                "generated_at_unix_ms": 1,
                "active_count": active,
                "event_count": events,
                "active": (0..active).map(|n| item(n, pad)).collect::<Vec<_>>(),
                "events": (0..events).map(|n| item(n, event_pad)).collect::<Vec<_>>(),
            },
            "store": null,
            "budget": {},
        })
    }

    fn frame_len(id: u64, result: &Value) -> usize {
        fc_service::conn::head_len(id, result).unwrap_or(usize::MAX) - JSON_HEADER
    }

    #[test]
    fn a_reply_that_fits_is_unchanged() {
        let small = reply(3, 10, 100, 100);
        assert_eq!(fit(7, small.clone()), small);
        let none = json!({ "progress": null, "store": null });
        assert_eq!(fit(7, none.clone()), none);
    }

    /// `result` with the path of `progress[list][0]` padded so that the
    /// reply for `id` is exactly one frame.
    fn exactly_a_frame(id: u64, mut result: Value, list: &str) -> Value {
        let short = frame_len(id, &result);
        result["progress"][list][0]["path"] = Value::String("x".repeat(MAX_PAYLOAD - short));
        assert_eq!(frame_len(id, &result), MAX_PAYLOAD);
        result
    }

    /// Review of #143: a reply that is exactly one frame is unchanged: a
    /// list's first item has no comma before it. With the largest ID, and
    /// with a target and an event.
    #[test]
    fn a_reply_of_exactly_a_frame_is_unchanged() {
        let one = |active: Value, events: Value| {
            json!({ "gateway": {}, "budget": {}, "store": null,
                "progress": { "active_count": active.as_array().unwrap().len(),
                    "event_count": events.as_array().unwrap().len(),
                    "active": active, "events": events } })
        };
        let max = fc_protocol::message::MAX_ID;
        for (id, result, list) in [
            (
                max,
                one(json!([{ "id": 1, "path": "" }]), json!([])),
                "active",
            ),
            (7, one(json!([]), json!([{ "path": "" }])), "events"),
            (
                max,
                one(json!([{ "path": "a" }]), json!([{ "path": "" }])),
                "events",
            ),
        ] {
            let exact = exactly_a_frame(id, result, list);
            assert_eq!(fit(id, exact.clone()), exact, "{id} {list}");
            // One byte more, and the item that made it so goes.
            let mut over = exact.clone();
            let path = format!("{}x", over["progress"][list][0]["path"].as_str().unwrap());
            over["progress"][list][0]["path"] = Value::String(path);
            let fitted = fit(id, over);
            assert_eq!(fitted["progress"][list], json!([]), "{id} {list}");
        }
    }

    /// Review point: a snapshot past one frame keeps its active targets,
    /// then its newest events, and its counts.
    #[test]
    fn a_reply_past_a_frame_keeps_active_targets_then_the_newest_events() {
        // 512 events and 40 targets of 8 KiB paths: about 4.4 MiB.
        let big = reply(40, 512, 8 << 10, 8 << 10);
        assert!(encoded_len(&big) > MAX_PAYLOAD);
        let fitted = fit(7, big);
        assert!(frame_len(7, &fitted) <= MAX_PAYLOAD);
        let progress = &fitted["progress"];
        assert_eq!(
            (&progress["active_count"], &progress["event_count"]),
            (&json!(40), &json!(512))
        );
        let active = progress["active"].as_array().unwrap();
        assert_eq!(active.len(), 40, "every target, before any event");
        let events = progress["events"].as_array().unwrap();
        assert!(!events.is_empty() && events.len() < 512, "{}", events.len());
        // The newest, in order.
        let ids: Vec<u64> = events.iter().map(|e| e["id"].as_u64().unwrap()).collect();
        let first = 512 - ids.len() as u64;
        assert_eq!(ids, (first..512).collect::<Vec<_>>());
        // No room was left for one more.
        let next = json!({ "id": first - 1, "path": "x".repeat(8 << 10) });
        assert!(frame_len(7, &fitted) + encoded_len(&next) + 1 > MAX_PAYLOAD);
    }

    /// Targets alone past a frame: as many as fit, in order, and no events.
    #[test]
    fn targets_past_a_frame_are_cut_in_order() {
        // Events larger than any room a target leaves.
        let big = reply(300, 5, 8 << 10, 16 << 10);
        let fitted = fit(7, big);
        assert!(frame_len(7, &fitted) <= MAX_PAYLOAD);
        let active = fitted["progress"]["active"].as_array().unwrap();
        let ids: Vec<u64> = active.iter().map(|t| t["id"].as_u64().unwrap()).collect();
        assert!(ids.len() < 300);
        assert_eq!(ids, (0..ids.len() as u64).collect::<Vec<_>>());
        assert_eq!(fitted["progress"]["events"], json!([]));
        assert_eq!(fitted["progress"]["active_count"], 300);
    }
}
