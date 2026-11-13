#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write as _;
use std::sync::mpsc;

use serde::Serialize;
use serde::ser::{SerializeSeq as _, Serializer};

use super::*;

/// A deadline `ms` from now, and a token nobody else holds.
fn within(ms: u64) -> Until {
    Until::new(
        Instant::now() + Duration::from_millis(ms),
        CancelToken::new(),
    )
}

/// A writer of at most `limit` bytes, from a budget of `total`.
fn writer(total: u64, limit: u64) -> (Arc<Budget>, Json) {
    let budget = Budget::new(total);
    let json = Json::new(budget.clone(), within(10_000), limit);
    (budget, json)
}

/// `value` serialized into a writer of at most `limit` bytes: its JSON, or
/// its refusal.
fn bounded<T: Serialize + ?Sized>(value: &T, limit: u64) -> Result<Vec<u8>, Refused> {
    let (budget, mut json) = writer(BUDGET, limit);
    let written = serde_json::to_writer(&mut json, value);
    assert!(json.allocated() as u64 <= budget.used());
    match json.finish(written) {
        Ok(body) => Ok(collect(body)),
        Err(Failure::Refused(refused)) => Err(refused),
        Err(other) => panic!("{other:?}"),
    }
}

fn collect(body: Body) -> Vec<u8> {
    let bytes = body.bytes();
    let mut out = Vec::new();
    for chunk in body {
        assert!(!chunk.as_slice().is_empty() && chunk.as_slice().len() <= MAX_DATA);
        out.extend_from_slice(chunk.as_slice());
    }
    assert_eq!(out.len() as u64, bytes);
    out
}

fn too_large(size: u64, limit: u64) -> Refused {
    Refused::TooLarge { size, limit }
}

/// Arrays nested `0` deep: `[[…]]`, two bytes a level.
struct Nest(usize);

impl Serialize for Nest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(None)?;
        if self.0 > 1 {
            seq.serialize_element(&Nest(self.0 - 1))?;
        }
        seq.end()
    }
}

/// `n` zeros in an array, counting how many the serializer asked for.
struct Wide<'a> {
    n: usize,
    asked: &'a std::sync::atomic::AtomicUsize,
}

impl Serialize for Wide<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq((0..self.n).map(|_| {
            self.asked
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            0u8
        }))
    }
}

#[test]
fn the_designs_figures() {
    assert_eq!(BUDGET, 256 << 20);
    assert_eq!(STEP, 64 << 10);
    assert_eq!(JSON, 32 << 20);
    assert_eq!(BUILT, 32 << 20);
    assert_eq!(JSON_READ, 64 << 20);
    assert_eq!(BLOB, 64 << 20);
    // Twice the blob, and libgit2's NUL and 256 bytes of structs.
    assert_eq!(BLOB_LOADING, (128 << 20) + 257);
    assert_eq!(Budget::new(BUDGET).total(), BUDGET);
    assert_eq!(
        READ,
        Limits {
            built: BUILT,
            json: JSON
        }
    );
    // The read pool's 4 threads, each at a JSON read's most, fill the
    // budget and no more.
    assert_eq!(crate::pools::READ.threads as u64 * JSON_READ, BUDGET);
}

#[test]
fn a_reservation_of_what_is_left_fits_and_one_byte_more_waits_to_its_deadline() {
    let budget = Budget::new(1000);
    let whole = budget.reserve(1000, &within(0)).unwrap();
    assert_eq!((whole.bytes(), budget.used()), (1000, 1000));
    drop(whole);
    let first = budget.reserve(600, &within(0)).unwrap();
    let rest = budget.reserve(400, &within(0)).unwrap();
    assert_eq!(budget.used(), 1000);
    let started = Instant::now();
    assert_eq!(
        budget.reserve(1, &within(100)).unwrap_err(),
        Refused::Deadline
    );
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert_eq!(budget.used(), 1000);
    drop((first, rest));
    assert_eq!(budget.used(), 0);
}

#[test]
fn a_reservation_over_the_whole_budget_is_too_large_at_once() {
    let budget = Budget::new(1000);
    assert_eq!(
        budget.reserve(1001, &within(5_000)).unwrap_err(),
        too_large(1001, 1000)
    );
    // At once: it never waited, rather than timed on a runner's clock.
    assert_eq!(budget.waits.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(budget.used(), 0);
    assert_eq!(
        Refused::TooLarge {
            size: 1001,
            limit: 1000
        }
        .error(),
        ErrorBody::new(ErrorCode::TooLarge, "1001 bytes is over the limit of 1000")
    );
}

#[test]
fn a_reservation_waits_until_enough_is_released() {
    let budget = Budget::new(100);
    let mut held = budget.reserve(80, &within(0)).unwrap();
    let (granted, got) = mpsc::channel();
    let waiter = {
        let budget = budget.clone();
        std::thread::spawn(move || {
            let reservation = budget.reserve(50, &within(10_000));
            granted.send(()).unwrap();
            reservation
        })
    };
    assert!(got.recv_timeout(Duration::from_millis(100)).is_err());
    // 40 free: still short.
    held.release(20);
    assert_eq!(budget.used(), 60);
    assert!(got.recv_timeout(Duration::from_millis(100)).is_err());
    drop(held);
    // A hang guard, never a timing assertion.
    got.recv_timeout(Duration::from_secs(60)).unwrap();
    let reservation = waiter.join().unwrap().unwrap();
    assert_eq!((reservation.bytes(), budget.used()), (50, 50));
}

#[test]
fn bytes_released_after_its_deadline_grant_a_waiting_reservation_nothing() {
    let budget = Budget::new(10);
    let mut held = budget.reserve(10, &within(0)).unwrap();
    // Time for the waiter's thread to start and wait, and for this one to
    // take the lock, before the deadline: microseconds, but the test fails
    // if a stalled runner holds them up past it (the 1 s this had was
    // tight: a Windows runner has stalled every process for seconds, issue
    // #311). The test sleeps to the deadline, so not longer still.
    let until = within(5_000);
    let deadline = until.deadline;
    let waiter = {
        let budget = budget.clone();
        std::thread::spawn(move || budget.reserve(1, &until))
    };
    // A wait is counted with the lock held: once one is, and the lock is
    // taken, the reservation is waiting.
    let started = Instant::now();
    while budget.waits.load(std::sync::atomic::Ordering::Relaxed) == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "it never waited"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    {
        let mut used = budget.lock();
        assert!(
            Instant::now() < deadline,
            "the lock came after the deadline"
        );
        // The budget held through the deadline, then all of it released,
        // the lock held throughout: the waiter looks next after both.
        std::thread::sleep(
            (deadline + Duration::from_millis(50)).saturating_duration_since(Instant::now()),
        );
        *used -= held.bytes;
        held.bytes = 0;
    }
    budget.released.notify_all();
    assert_eq!(waiter.join().unwrap().unwrap_err(), Refused::Deadline);
    assert_eq!(budget.used(), 0);
}

#[test]
fn a_reservation_that_fits_at_its_first_look_is_granted_past_its_deadline() {
    let budget = Budget::new(10);
    let until = within(0);
    std::thread::sleep(Duration::from_millis(5));
    assert!(Instant::now() > until.deadline);
    // It waits for nothing: granted.
    let reservation = budget.reserve(10, &until).unwrap();
    assert_eq!(budget.used(), 10);
    // One that doesn't fit is `deadline` at once, without a wait.
    assert_eq!(budget.reserve(1, &until).unwrap_err(), Refused::Deadline);
    assert_eq!(budget.waits.load(std::sync::atomic::Ordering::Relaxed), 0);
    drop(reservation);
    assert_eq!(budget.used(), 0);
}

#[test]
fn a_waiting_reservation_ends_at_its_tokens_cancel() {
    let budget = Budget::new(10);
    let _held = budget.reserve(10, &within(0)).unwrap();
    let until = within(120_000);
    let cancel = until.cancel.clone();
    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        cancel.cancel();
    });
    let started = Instant::now();
    assert_eq!(budget.reserve(1, &until).unwrap_err(), Refused::Cancelled);
    // At the cancel, not the deadline: a wait that looked at its token only
    // at its deadline would answer `cancelled` too, but 120 s on. The bound
    // is the property, so it has headroom: a runner has stalled every
    // thread for 5.9 s (Windows CI, issue #311).
    assert!(started.elapsed() < Duration::from_secs(60));
    canceller.join().unwrap();
    assert_eq!(budget.used(), 10);
}

#[test]
fn a_cancelled_read_reserves_nothing_even_what_fits() {
    let budget = Budget::new(10);
    let until = within(10_000);
    until.cancel.cancel();
    assert_eq!(budget.reserve(1, &until).unwrap_err(), Refused::Cancelled);
    assert_eq!(budget.used(), 0);
}

#[test]
fn a_reservation_is_released_in_parts_and_as_it_drops() {
    let budget = Budget::new(1000);
    let other = budget.reserve(5, &within(0)).unwrap();
    let mut reservation = budget.reserve(100, &within(0)).unwrap();
    reservation.release(30);
    assert_eq!((reservation.bytes(), budget.used()), (70, 75));
    // Never more than it holds.
    reservation.release(1000);
    assert_eq!((reservation.bytes(), budget.used()), (0, 5));
    drop(reservation);
    assert_eq!(budget.used(), 5);
    drop(other);
    assert_eq!(budget.used(), 0);
}

#[test]
fn json_at_its_limit_is_written_and_one_byte_over_is_too_large() {
    // Past a step's boundary, and not a multiple of it.
    let limit = STEP as u64 + 4465;
    let (budget, mut json) = writer(BUDGET, limit);
    json.write_all(&vec![b'x'; STEP + 4465]).unwrap();
    assert_eq!((json.len(), budget.used()), (limit, limit));
    let body = json.finish(Ok(())).unwrap();
    assert_eq!(collect(body), vec![b'x'; STEP + 4465]);
    assert_eq!(budget.used(), 0);

    let (budget, mut json) = writer(BUDGET, limit);
    assert!(json.write_all(&vec![b'x'; STEP + 4466]).is_err());
    assert_eq!(json.refused(), Some(&too_large(limit + 1, limit)));
    assert_eq!((json.len(), budget.used()), (0, 0));

    // In two writes: the second passes it by one.
    let (_, mut json) = writer(BUDGET, limit);
    json.write_all(&vec![b'x'; STEP + 4464]).unwrap();
    assert!(json.write_all(b"yz").is_err());
    assert_eq!(json.refused(), Some(&too_large(limit + 1, limit)));
    assert_eq!(json.len(), limit - 1);

    // Serialized: a string whose JSON is the limit, and one a byte longer.
    let text = "a".repeat(98);
    assert_eq!(
        bounded(&text, 100).unwrap(),
        serde_json::to_vec(&text).unwrap()
    );
    assert_eq!(bounded(&text, 99).unwrap_err(), too_large(100, 99));
}

#[test]
fn escapes_count_as_written_not_as_raw() {
    let nul = char::from(0u8);
    // Each NUL is 6 bytes of JSON, so 1000 of them make 6002, though the
    // raw text is 1000.
    let nuls: String = std::iter::repeat_n(nul, 1000).collect();
    assert_eq!(bounded(&nuls, 6002).unwrap().len(), 6002);
    let refused = bounded(&nuls, 6001).unwrap_err();
    assert!(matches!(refused, Refused::TooLarge { limit: 6001, .. }));

    // Backslashes, quotes and newlines are 2 each, other controls 6,
    // and UTF-8 text is its bytes, unescaped.
    let mut mixed = String::new();
    for _ in 0..500 {
        mixed.push('\\');
        mixed.push('"');
        mixed.push('\n');
        mixed.push(char::from(0x1fu8));
        mixed.push('é');
        mixed.push('x');
    }
    let full = serde_json::to_vec(&mixed).unwrap();
    assert_eq!(full.len(), 2 + 500 * (2 + 2 + 2 + 6 + 2 + 1));
    assert_eq!(bounded(&mixed, full.len() as u64).unwrap(), full);
    assert!(matches!(
        bounded(&mixed, full.len() as u64 - 1).unwrap_err(),
        Refused::TooLarge { .. }
    ));
}

#[test]
fn lossy_text_counts_three_bytes_for_each_invalid_byte() {
    // libradicle's `/blob/` JSON: text as lossy UTF-8.
    let mut content = vec![0xffu8; 1000];
    content.extend_from_slice(b"ok");
    let blob = libradicle::Blob {
        binary: false,
        content,
    };
    let mut full = Vec::new();
    libradicle::json::blob(&mut full, "dir/f.txt", &blob).unwrap();
    let empty = br#"{"binary":false,"name":"f.txt","content":""}"#.len();
    assert_eq!(full.len(), empty + 3 * 1000 + 2);

    let at = |limit: u64| {
        let (_, mut json) = writer(BUDGET, limit);
        let written = libradicle::json::blob(&mut json, "dir/f.txt", &blob);
        json.finish(written).map(collect)
    };
    assert_eq!(at(full.len() as u64).unwrap(), full);
    assert!(matches!(
        at(full.len() as u64 - 1),
        Err(Failure::Refused(Refused::TooLarge { .. }))
    ));
}

#[test]
fn deep_json_is_counted_bracket_by_bracket() {
    assert_eq!(bounded(&Nest(1000), 2000).unwrap().len(), 2000);
    assert!(matches!(
        bounded(&Nest(1000), 1999).unwrap_err(),
        Refused::TooLarge { limit: 1999, .. }
    ));
}

#[test]
fn wide_json_stops_while_it_is_written() {
    // 100,000 zeros: 200,001 bytes in all.
    let asked = std::sync::atomic::AtomicUsize::new(0);
    let wide = Wide {
        n: 100_000,
        asked: &asked,
    };
    assert_eq!(bounded(&wide, 200_001).unwrap().len(), 200_001);

    let asked = std::sync::atomic::AtomicUsize::new(0);
    let wide = Wide {
        n: 100_000,
        asked: &asked,
    };
    let (budget, mut json) = writer(BUDGET, 100_000);
    let written = serde_json::to_writer(&mut json, &wide);
    assert!(written.is_err());
    assert!(json.len() <= 100_000);
    assert!(json.allocated() <= 100_000 && budget.used() <= 100_000);
    // The serializer stopped at the item that passed the limit.
    // 50,000 zeros fill it; the comma before the next one passes it.
    assert_eq!(asked.load(std::sync::atomic::Ordering::Relaxed), 50_001);
    assert!(matches!(
        json.finish(written),
        Err(Failure::Refused(Refused::TooLarge { limit: 100_000, .. }))
    ));
    assert_eq!(budget.used(), 0);
}

#[test]
fn every_byte_is_reserved_before_it_is_allocated() {
    // Three steps of budget, for a writer that would take ten.
    let budget = Budget::new(3 * STEP as u64);
    let mut json = Json::new(budget.clone(), within(50), 10 * STEP as u64);
    let piece = vec![b'x'; 1000];
    let refused = loop {
        let before = json.allocated();
        match json.write(&piece) {
            Ok(n) => assert_eq!(n, piece.len()),
            Err(_) => {
                // Refused before anything more was allocated.
                assert_eq!(json.allocated(), before);
                break json.refused().cloned();
            }
        }
        assert!(json.allocated() as u64 <= budget.used());
        assert!(json.allocated() <= json.len() as usize + STEP);
    };
    assert_eq!(refused, Some(Refused::Deadline));
    assert_eq!(json.allocated(), 3 * STEP);
    assert_eq!(budget.used(), 3 * STEP as u64);
    assert_eq!(json.len(), 3 * STEP as u64);
    drop(json);
    assert_eq!(budget.used(), 0);
}

#[test]
fn a_limit_short_of_a_step_reserves_no_more_than_the_limit() {
    // A budget of 100 bytes holds a writer of at most 100.
    let budget = Budget::new(100);
    let mut json = Json::new(budget.clone(), within(10_000), 100);
    json.write_all(&[b'x'; 100]).unwrap();
    assert_eq!((json.allocated(), budget.used()), (100, 100));
    drop(json);

    let budget = Budget::new(BUDGET);
    let mut json = Json::new(budget.clone(), within(10_000), STEP as u64 + 1);
    json.write_all(&vec![b'x'; STEP + 1]).unwrap();
    assert_eq!(budget.used(), STEP as u64 + 1);
}

#[test]
fn a_refused_writer_takes_nothing_more() {
    let (budget, mut json) = writer(BUDGET, 10);
    json.write_all(b"12345").unwrap();
    assert!(json.write_all(b"123456").is_err());
    assert!(json.write_all(b"1").is_err());
    assert_eq!(json.len(), 5);
    assert!(matches!(
        json.finish(Ok(())),
        Err(Failure::Refused(Refused::TooLarge {
            size: 11,
            limit: 10
        }))
    ));
    assert_eq!(budget.used(), 0);
}

#[test]
fn the_writers_refusal_stands_whatever_the_serializer_made_of_it() {
    // A serializer that swallowed the writer's error.
    let (_, mut json) = writer(BUDGET, 10);
    let _ = json.write_all(b"12345678901");
    assert!(matches!(
        json.finish(Ok(())),
        Err(Failure::Refused(Refused::TooLarge { .. }))
    ));
    // The serializer's own error, with the writer's consent: internal.
    let (_, json) = writer(BUDGET, 10);
    let own = serde_json::to_vec(&std::collections::BTreeMap::from([((1, 2), 3)])).unwrap_err();
    let failure = json.finish(Err(own)).unwrap_err();
    assert!(matches!(failure, Failure::Json(_)));
    assert_eq!(failure.error(|_| unreachable!()).code, ErrorCode::Internal);
}

#[test]
fn a_body_is_its_json_in_frames_each_released_as_it_drops() {
    let budget = Budget::new(BUDGET);
    let text = "b".repeat(3 * STEP + STEP / 2);
    let mut json = Json::new(budget.clone(), within(10_000), JSON);
    let written = serde_json::to_writer(&mut json, &text);
    let body = json.finish(written).unwrap();
    let full = serde_json::to_vec(&text).unwrap();
    assert_eq!(body.bytes(), full.len() as u64);
    assert_eq!(budget.used(), 4 * STEP as u64);
    let mut out = Vec::new();
    let mut held = 4;
    for chunk in body {
        assert!(chunk.as_slice().len() <= MAX_DATA);
        out.extend_from_slice(chunk.as_slice());
        drop(chunk);
        held -= 1;
        assert_eq!(budget.used(), held * STEP as u64);
    }
    assert_eq!(out, full);
    assert_eq!(budget.used(), 0);
}

#[test]
fn a_json_read_reserves_its_whole_build_before_it_walks_and_releases_it_once_written() {
    let budget = Budget::new(BUDGET);
    let limits = Limits {
        built: 1000,
        json: 500,
    };
    let until = within(10_000);
    let body = json_read_within(
        limits,
        0,
        &budget,
        &until,
        |bounds| {
            assert_eq!(budget.used(), 1000);
            // Half for what it builds, half for what it loads, both held at
            // once within the one reservation (review of #277, round 3).
            assert_eq!((bounds.budget, bounds.loads), (500, 500));
            assert!(!bounds.cancel.is_cancelled());
            Ok::<_, libradicle::Error>("x".repeat(100))
        },
        |json, text| {
            serde_json::to_writer(&mut *json, text)?;
            // The built data is held while it is written.
            assert_eq!(budget.used(), 1000 + 500);
            Ok(())
        },
    )
    .unwrap();
    // Only the JSON's step is left, within its limit.
    assert_eq!(budget.used(), 500);
    assert_eq!(body.bytes(), 102);
    drop(body);
    assert_eq!(budget.used(), 0);
}

#[test]
fn a_json_reads_walk_has_the_reads_token() {
    let budget = Budget::new(BUDGET);
    let until = within(10_000);
    let failure = json_read(
        &budget,
        &until,
        |bounds| -> Result<(), _> {
            // The add-on's bounds: 16 MiB of items, 16 of loads.
            assert_eq!((bounds.budget, bounds.loads), (BUILT / 2, BUILT / 2));
            assert_eq!(BUILT / 2, libradicle::BINDING_READ_BUDGET);
            until.cancel.cancel();
            assert!(bounds.cancel.is_cancelled());
            Err(libradicle::Error::Cancelled)
        },
        |_, _| unreachable!(),
    )
    .unwrap_err();
    assert!(matches!(failure, Failure::Refused(Refused::Cancelled)));
    assert_eq!(failure.error(|_| unreachable!()).code, ErrorCode::Cancelled);
    assert_eq!(budget.used(), 0);
}

#[test]
fn libradicles_too_large_is_the_reads_too_large_and_its_other_errors_its_own() {
    let budget = Budget::new(BUDGET);
    let failure = json_read(
        &budget,
        &within(10_000),
        |_| -> Result<(), _> { Err(libradicle::Error::TooLarge { size: 5, limit: 4 }) },
        |_, _| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(
        failure.error(|_| unreachable!()),
        ErrorBody::new(ErrorCode::TooLarge, "5 bytes is over the limit of 4")
    );
    let failure = json_read(
        &budget,
        &within(10_000),
        |_| -> Result<(), _> { Err(libradicle::Error::NotABlob("src".into())) },
        |_, _| unreachable!(),
    )
    .unwrap_err();
    assert!(matches!(
        failure,
        Failure::Radicle(libradicle::Error::NotABlob(_))
    ));
    assert_eq!(
        failure
            .error(|e| ErrorBody::new(ErrorCode::Failed, e.to_string()))
            .code,
        ErrorCode::Failed
    );
    assert_eq!(budget.used(), 0);
}

/// #340: the node's reactor unanswered within the read's deadline left, or
/// not asked as too many calls wait on it, is the read's `deadline`, never
/// libradicle's `failed`.
#[test]
fn a_reactor_past_its_bound_or_too_busy_to_ask_is_the_reads_deadline() {
    let failure = Failure::from(libradicle::Error::NodeDeadline {
        call: "sessions",
        within: std::time::Duration::from_secs(1),
    });
    assert_eq!(
        failure.error(|_| unreachable!()),
        ErrorBody::new(ErrorCode::Deadline, "past its deadline")
    );
    let failure = Failure::from(libradicle::Error::NodeBusy {
        call: "sessions",
        waiting: 8,
    });
    assert_eq!(
        failure.error(|_| unreachable!()),
        ErrorBody::new(
            ErrorCode::Deadline,
            "sessions wasn't sent: 8 calls are already waiting on the node"
        )
    );
}

#[test]
fn a_json_read_that_cant_reserve_its_build_never_walks() {
    let budget = Budget::new(100);
    let _held = budget.reserve(100, &within(0)).unwrap();
    let limits = Limits {
        built: 50,
        json: 50,
    };
    let started = Instant::now();
    let failure = json_read_within(
        limits,
        0,
        &budget,
        &within(50),
        |_| -> Result<(), libradicle::Error> { panic!("walked without its reservation") },
        |_, _| unreachable!(),
    )
    .unwrap_err();
    assert!(started.elapsed() >= Duration::from_millis(50));
    assert_eq!(failure.error(|_| unreachable!()).code, ErrorCode::Deadline);
    assert_eq!(budget.used(), 100);
}

#[test]
fn a_json_read_past_its_json_is_too_large_and_holds_nothing() {
    let budget = Budget::new(BUDGET);
    let limits = Limits {
        built: 1000,
        json: 10,
    };
    let failure = json_read_within(
        limits,
        0,
        &budget,
        &within(10_000),
        |_| Ok::<_, libradicle::Error>("y".repeat(20)),
        |json, text| serde_json::to_writer(json, text),
    )
    .unwrap_err();
    assert!(matches!(
        failure,
        Failure::Refused(Refused::TooLarge { limit: 10, .. })
    ));
    assert_eq!(budget.used(), 0);
}

#[test]
fn the_6_mib_nul_blob_is_too_large_while_it_is_written() {
    // 0008, "Tests first": its escaped JSON would be 36 MiB.
    let budget = Budget::new(BUDGET);
    let failure = json_read(
        &budget,
        &within(60_000),
        |_| {
            Ok::<_, libradicle::Error>(libradicle::Blob {
                binary: false,
                content: vec![0; 6 << 20],
            })
        },
        |json, blob| libradicle::json::blob(json, "nul.bin", blob),
    )
    .unwrap_err();
    let Failure::Refused(Refused::TooLarge { size, limit }) = failure else {
        panic!("{failure:?}");
    };
    // Stopped at the write that passed the cap (an escape is one write of
    // 6 bytes), not at the end, 4 MiB later.
    assert_eq!(limit, JSON);
    assert!(size > JSON && size < JSON + STEP as u64, "{size}");
    assert_eq!(budget.used(), 0);
}

#[test]
fn json_at_the_cap_is_served_and_one_byte_more_is_too_large() {
    let budget = Budget::new(BUDGET);
    let read = |len: u64| {
        json_read(
            &budget,
            &within(60_000),
            |_| Ok::<_, libradicle::Error>("j".repeat(len as usize - 2)),
            |json, text| serde_json::to_writer(json, text),
        )
    };
    let body = read(JSON).unwrap();
    assert_eq!(body.bytes(), JSON);
    assert_eq!(budget.used(), JSON);
    drop(body);
    let Err(Failure::Refused(refused)) = read(JSON + 1) else {
        panic!("one byte over the cap was served");
    };
    assert_eq!(refused, too_large(JSON + 1, JSON));
    assert_eq!(budget.used(), 0);
}

#[test]
fn four_reads_at_their_most_fill_the_budget_and_a_fifth_waits() {
    let budget = Budget::new(BUDGET);
    // Each reader says when it holds its most, then waits to be let go: a
    // reader that fails never says so, and the test fails, never hangs.
    let (written, holding) = mpsc::channel();
    let mut go = Vec::new();
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let (let_go, gone) = mpsc::channel::<()>();
            go.push(let_go);
            let (budget, written) = (budget.clone(), written.clone());
            std::thread::spawn(move || {
                json_read(
                    &budget,
                    &within(30_000),
                    |_| Ok::<_, libradicle::Error>(()),
                    |json, _| {
                        let step = [b' '; STEP];
                        for _ in 0..JSON / STEP as u64 {
                            json.write_all(&step).map_err(serde_json::Error::io)?;
                        }
                        // A JSON read at its most: its build and its JSON.
                        written.send(()).unwrap();
                        let _ = gone.recv();
                        Ok(())
                    },
                )
            })
        })
        .collect();
    for _ in 0..4 {
        holding
            .recv_timeout(Duration::from_secs(30))
            .expect("four reads at their most didn't fit the budget");
    }
    assert_eq!(budget.used(), BUDGET);
    let fifth = json_read(
        &budget,
        &within(100),
        |_| Ok::<_, libradicle::Error>(()),
        |_, _| unreachable!(),
    );
    assert!(matches!(fifth, Err(Failure::Refused(Refused::Deadline))));
    drop(go);
    let bodies: Vec<Body> = readers
        .into_iter()
        .map(|reader| reader.join().unwrap().unwrap())
        .collect();
    // Their builds are released; their JSON is held until it is written.
    assert_eq!(budget.used(), 4 * JSON);
    assert!(bodies.iter().all(|body| body.bytes() == JSON));
    drop(bodies);
    assert_eq!(budget.used(), 0);
}

/// A reservation split gives nothing back: the part is released as it
/// drops, the rest as the rest does.
#[test]
fn a_split_reservation_releases_each_part_as_it_drops() {
    let budget = Budget::new(1000);
    let mut whole = budget.reserve(600, &within(1000)).unwrap();
    let part = whole.split(200);
    assert_eq!(
        (whole.bytes(), part.bytes(), budget.used()),
        (400, 200, 600)
    );
    drop(part);
    assert_eq!(budget.used(), 400);
    // Past what it holds: all of it.
    let rest = whole.split(10_000);
    assert_eq!((whole.bytes(), rest.bytes(), budget.used()), (0, 400, 400));
    drop(whole);
    assert_eq!(budget.used(), 400);
    drop(rest);
    assert_eq!(budget.used(), 0);
}

/// `rad.blob`'s range copied into a body: chunks of at most 64 KiB, each
/// holding its own share of the reservation, released as it drops; the
/// rest stays with the reservation. One the reservation doesn't cover is
/// refused, and takes nothing.
#[test]
fn bytes_copied_into_a_body_hold_their_share_of_the_reservation() {
    let budget = Budget::new(BUDGET);
    let bytes: Vec<u8> = (0..3 * STEP + 7).map(|i| (i % 251) as u8).collect();
    let mut held = budget
        .reserve(2 * bytes.len() as u64, &within(1000))
        .unwrap();
    let mut body = Body::copied(&bytes, &mut held).unwrap();
    assert_eq!(body.bytes(), bytes.len() as u64);
    assert_eq!(held.bytes(), bytes.len() as u64);
    assert_eq!(budget.used(), 2 * bytes.len() as u64);
    drop(held);
    assert_eq!(budget.used(), bytes.len() as u64);
    let first = body.next().unwrap();
    assert_eq!(first.as_slice(), &bytes[..STEP]);
    assert_eq!(first.reservation.bytes(), STEP as u64);
    assert_eq!(first.bytes.capacity(), STEP);
    drop(first);
    assert_eq!(budget.used(), (bytes.len() - STEP) as u64);
    let mut out = bytes[..STEP].to_vec();
    for chunk in body {
        assert!(!chunk.as_slice().is_empty() && chunk.as_slice().len() <= STEP);
        out.extend_from_slice(chunk.as_slice());
    }
    assert_eq!(out, bytes);
    assert_eq!(budget.used(), 0);

    let mut short = budget.reserve(10, &within(1000)).unwrap();
    assert!(matches!(
        Body::copied(&[0; 11], &mut short),
        Err(Failure::Internal(_))
    ));
    assert_eq!(short.bytes(), 10);
    // Empty: no chunk.
    let empty = Body::copied(&[], &mut short).unwrap();
    assert_eq!((empty.bytes(), empty.count(), short.bytes()), (0, 0, 10));
}
