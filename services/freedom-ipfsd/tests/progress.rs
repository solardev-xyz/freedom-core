//! Loading progress in `ipfs.stats` through the binary (design 0007,
//! "Stats"): the persistent process records each instance's own, the
//! ephemeral one records none. `test_progress` (a test hook) says what the
//! instance's recorder and the process's default recorder hold.

#![cfg(feature = "testhooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{Value, json};

const COUNTS: (&str, &str) = ("FREEDOM_IPFSD_TEST_PROGRESS_COUNTS", "1");

fn stats(ipfsd: &mut Ipfsd, instance: &str) -> Value {
    let reply = ipfsd.call("ipfs.stats", json!({ "instance": instance }));
    assert!(reply["result"].is_object(), "{reply}");
    reply["result"].clone()
}

/// The targets of a snapshot's events: a request's is its envelope ID (the
/// native request's ID, as main sets it today; `request_id` is the
/// gateway's own count).
fn targets(progress: &Value) -> Vec<u64> {
    progress["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["target_id"].as_u64())
        .collect()
}

fn shut_down(mut ipfsd: Ipfsd) {
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}

#[test]
fn each_instance_records_its_own_requests_under_their_ids() {
    let dirs = Dirs::new();
    let cids = seed(&dirs, &[vec![1u8; 1000]]);
    let mut ipfsd = Ipfsd::persistent(&dirs, &[COUNTS]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(disk("p-1"))["result"]["instance"], "p-1");
    let fresh = stats(&mut ipfsd, "p-1");
    assert_eq!(fresh["progress"]["event_count"], 0, "{}", fresh["progress"]);
    let first = ipfsd.request("ipfs.request", get("p-1", &format!("/ipfs/{}", cids[0])));
    assert_eq!(ipfsd.reply(first)["result"]["status"], 200);
    ipfsd.body(first);
    let after = stats(&mut ipfsd, "p-1");
    let progress = &after["progress"];
    // Its events, under its request ID, from its start to its end.
    let ids = targets(progress);
    assert!(ids.contains(&first), "{progress}");
    let phases: Vec<&str> = progress["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["target_id"] == first)
        .filter_map(|event| event["raw_phase"].as_str())
        .collect();
    assert!(phases.contains(&"request_start"), "{phases:?}");
    assert!(
        progress["active"]
            .as_array()
            .unwrap()
            .iter()
            .all(|target| target["id"] != first),
        "done, not active: {progress}"
    );
    // Nothing of it in the process's default recorder.
    assert_eq!(
        after["test_progress"]["default"],
        json!({ "active_count": 0, "event_count": 0 }),
        "{}",
        after["test_progress"]
    );

    // The next instance starts with nothing of the first's.
    assert_eq!(ipfsd.stop("p-1")["result"]["instance"], "p-1");
    assert_eq!(ipfsd.start(disk("p-2"))["result"]["instance"], "p-2");
    let next = stats(&mut ipfsd, "p-2");
    assert_eq!(next["progress"]["event_count"], 0, "{}", next["progress"]);
    let second = ipfsd.request("ipfs.request", get("p-2", &format!("/ipfs/{}", cids[0])));
    assert_eq!(ipfsd.reply(second)["result"]["status"], 200);
    ipfsd.body(second);
    let later = stats(&mut ipfsd, "p-2");
    let ids = targets(&later["progress"]);
    assert!(ids.contains(&second), "{}", later["progress"]);
    assert!(!ids.contains(&first), "{}", later["progress"]);
    assert_eq!(later["test_progress"]["default"]["event_count"], 0);
    shut_down(ipfsd);
}

#[test]
fn the_ephemeral_process_records_no_progress() {
    let mut ipfsd = Ipfsd::ephemeral(&[COUNTS]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(memory("e-1"))["result"]["instance"], "e-1");
    // A request for content the instance doesn't have, and one it can't
    // parse as a path it has.
    let missing = freedom_ipfs_core::cid_from_data(0x55, b"a private window's");
    for path in [
        format!("/ipfs/{missing}"),
        format!("/ipfs/{missing}/page.html"),
    ] {
        let id = ipfsd.request("ipfs.request", get("e-1", &path));
        let head = ipfsd.reply(id);
        if head["result"]["body"] == true {
            ipfsd.body(id);
        }
    }
    let result = stats(&mut ipfsd, "e-1");
    assert_eq!(result["progress"], Value::Null);
    // Nothing recorded, anywhere in the process.
    assert_eq!(
        result["test_progress"],
        json!({ "instance": { "active_count": 0, "event_count": 0 },
            "default": { "active_count": 0, "event_count": 0 } })
    );
    shut_down(ipfsd);
}

/// A snapshot past one frame is cut to fit: the reply still comes, with the
/// newest events and the recorder's own counts.
#[test]
fn a_snapshot_past_a_frame_is_cut_to_fit() {
    let dirs = Dirs::new();
    let mut ipfsd = Ipfsd::persistent(&dirs, &[]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(disk("p-1"))["result"]["instance"], "p-1");
    // Requests whose paths are 16 KiB: 512 events of them pass a frame.
    let missing = freedom_ipfs_core::cid_from_data(0x55, b"nowhere");
    let name = "n".repeat(16 << 10);
    let path = format!("/ipfs/{missing}/{name}");
    let mut asked = 0;
    let last = loop {
        let id = ipfsd.request("ipfs.request", get("p-1", &path));
        let head = ipfsd.reply(id);
        if head["result"]["body"] == true {
            ipfsd.body(id);
        }
        asked += 1;
        if asked % 20 == 0 && stats(&mut ipfsd, "p-1")["progress"]["event_count"] == 512 {
            break id;
        }
        assert!(asked < 1000, "the recorder never filled");
    };
    let progress = stats(&mut ipfsd, "p-1")["progress"].clone();
    assert_eq!(progress["event_count"], 512);
    let events = progress["events"].as_array().unwrap();
    assert!(
        !events.is_empty() && events.len() < 512,
        "{} of 512 kept",
        events.len()
    );
    // The newest: consecutive event IDs, ending with the last request's.
    let ids: Vec<u64> = events
        .iter()
        .map(|event| event["event_id"].as_u64().unwrap())
        .collect();
    assert!(ids.windows(2).all(|pair| pair[1] == pair[0] + 1), "{ids:?}");
    assert_eq!(events.last().unwrap()["target_id"], last);
    shut_down(ipfsd);
}

/// Review of #143: with main not reading, at most 4 stats replies wait for
/// the writer, each up to a frame: the rest are `busy`. The recorder is
/// filled with 16 KiB paths first, so each reply is near a frame. Main
/// resumes reading only once the service acknowledges (a test hook, off
/// stdout) that its reader has handled every call, so each was admitted or
/// refused while main wasn't reading, however late the reader ran.
#[test]
fn a_main_that_stops_reading_holds_at_most_4_stats_replies() {
    let dirs = Dirs::new();
    // Inside the data directory: the one place the confined process writes.
    let handled = dirs.data.join("handled");
    let mut ipfsd = Ipfsd::persistent(
        &dirs,
        &[("FREEDOM_IPFSD_TEST_HANDLED_FILE", handled.to_str().unwrap())],
    );
    ipfsd.hello();
    assert_eq!(ipfsd.start(disk("p-1"))["result"]["instance"], "p-1");
    let missing = freedom_ipfs_core::cid_from_data(0x55, b"missing");
    let path = format!("/ipfs/{missing}/{}", "n".repeat(16 << 10));
    for _ in 0..24 {
        let id = ipfsd.request("ipfs.request", get("p-1", &path));
        let head = ipfsd.reply(id);
        if head["result"]["body"] == true {
            ipfsd.body(id);
        }
    }
    ipfsd.pause_reading();
    // Each call given time for its job to run and queue its reply, so a
    // place a job freed on ending, not on its reply's write, would admit
    // the next; then main waits for the reader's acknowledgement.
    let ids: Vec<u64> = (0..18)
        .map(|_| {
            let id = ipfsd.request("ipfs.stats", json!({ "instance": "p-1" }));
            std::thread::sleep(std::time::Duration::from_millis(150));
            id
        })
        .collect();
    let last = ids[ids.len() - 1].to_string();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !std::fs::read_to_string(&handled)
        .unwrap_or_default()
        .lines()
        .any(|line| line == last)
    {
        assert!(
            std::time::Instant::now() < deadline,
            "call {last} never handled"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    ipfsd.resume_reading();
    let (mut answered, mut busy) = (0, 0);
    for id in ids {
        let reply = ipfsd.reply(id);
        if reply["result"].is_object() {
            answered += 1;
        } else {
            assert_eq!(reply["error"]["code"], "busy", "{reply}");
            busy += 1;
        }
    }
    shut_down(ipfsd);
    // One may have been read before main stopped reading.
    assert!(
        (4..=5).contains(&answered),
        "{answered} answered, {busy} busy"
    );
    assert_eq!(answered + busy, 18);
}
