#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::str::FromStr as _;

use super::*;

const RID: &str = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5";
const REV: &str = "0123456789abcdef0123456789abcdef01234567";

fn checked(params: Value) -> Result<Request, ErrorBody> {
    let raw = serde_json::value::to_raw_value(&params).unwrap();
    request(Some(&raw))
}

fn with(extra: Value) -> Value {
    let mut params = json!({ "rid": RID, "revision": REV, "path": "dir/a.png" });
    for (k, v) in extra.as_object().unwrap() {
        params[k] = v.clone();
    }
    params
}

fn message(checked: Result<Request, ErrorBody>) -> String {
    let error = checked.unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument, "{error:?}");
    error.message
}

/// 0008, "The blob API" and "Ranges": `{ rid, revision, path }`, with an
/// optional range in one of its three shapes and an optional `head_only`.
#[test]
fn rad_blob_takes_its_params() {
    let rid = RepoId::from_str(RID).unwrap();
    let request = |range, head_only| Request {
        rid,
        revision: REV.into(),
        path: "dir/a.png".into(),
        range,
        head_only,
    };
    for (params, expected) in [
        (with(json!({})), request(None, false)),
        (
            with(json!({ "range": null, "head_only": null })),
            request(None, false),
        ),
        (with(json!({ "head_only": true })), request(None, true)),
        (with(json!({ "head_only": false })), request(None, false)),
        (
            with(json!({ "range": { "start": 0, "end": 9 } })),
            request(Some(Range::Closed { start: 0, end: 9 }), false),
        ),
        (
            with(json!({ "range": { "start": 7, "end": 7 } })),
            request(Some(Range::Closed { start: 7, end: 7 }), false),
        ),
        (
            with(json!({ "range": { "start": 5 }, "head_only": true })),
            request(Some(Range::From { start: 5 }), true),
        ),
        (
            with(json!({ "range": { "suffix": 10 } })),
            request(Some(Range::Suffix { suffix: 10 }), false),
        ),
        (
            with(json!({ "range": { "suffix": 0 } })),
            request(Some(Range::Suffix { suffix: 0 }), false),
        ),
        (
            with(json!({ "range": { "start": 0, "end": u64::MAX } })),
            request(
                Some(Range::Closed {
                    start: 0,
                    end: u64::MAX,
                }),
                false,
            ),
        ),
    ] {
        assert_eq!(checked(params.clone()), Ok(expected), "{params}");
    }
}

/// 0008, "Errors": a range, or any param, that doesn't parse is
/// `invalid_argument`. A range has exactly one shape's members, each a
/// non-negative integer, and a closed one's `start` is at most its `end`.
#[test]
fn what_doesnt_parse_is_invalid_argument() {
    for range in [
        json!({ "start": 5, "end": 4 }),
        json!({ "start": -1 }),
        json!({ "start": 1.5 }),
        json!({ "start": 1.0 }),
        json!({ "start": "0" }),
        json!({ "suffix": -3 }),
        json!({ "end": 9 }),
        json!({}),
        json!({ "start": 0, "suffix": 1 }),
        json!({ "start": 0, "end": 1, "suffix": 1 }),
        json!({ "start": 0, "end": 1, "unit": "bytes" }),
        // Past u64: serde_json reads it as a float.
        serde_json::from_str::<Value>(r#"{ "start": 18446744073709551616 }"#).unwrap(),
        json!("bytes=0-9"),
        json!([{ "start": 0, "end": 1 }, { "start": 4, "end": 5 }]),
        // serde would take a struct from an array of its members.
        json!([0, 9]),
        json!([5]),
        json!(0),
        json!(true),
    ] {
        assert_eq!(
            message(checked(with(json!({ "range": range })))),
            RANGES,
            "{range}"
        );
    }
    for params in [
        json!({ "rid": RID, "revision": REV }),
        json!({ "rid": RID, "path": "a" }),
        json!({ "revision": REV, "path": "a" }),
        with(json!({ "head_only": "yes" })),
        with(json!({ "head_only": 1 })),
        with(json!({ "op": "blob_at" })),
        json!([RID, REV, "a"]),
        json!(null),
    ] {
        assert_eq!(message(checked(params.clone())), TAKES, "{params}");
    }
    assert_eq!(message(request(None)), TAKES);
    assert_eq!(
        message(checked(with(json!({ "revision": REV.to_uppercase() })))),
        "revision isn't a commit ID (40 lowercase hex digits)"
    );
    assert_eq!(
        message(checked(with(json!({ "revision": &REV[1..] })))),
        "revision isn't a commit ID (40 lowercase hex digits)"
    );
    assert_eq!(
        message(checked(with(
            json!({ "rid": "z3gqcJUoA1n9HaHKufZs5FCSGazv5x" })
        ))),
        "rid isn't a repository ID"
    );
}

fn unsatisfiable(size: u64) -> ErrorBody {
    let error = ErrorBody::new(
        ErrorCode::RangeNotSatisfiable,
        format!("the range is outside the blob's {size} bytes"),
    );
    error.with_data(json!({ "size": size }))
}

fn closed(start: u64, end: u64) -> Option<Range> {
    Some(Range::Closed { start, end })
}

fn spanned(start: u64, end: u64) -> Result<Option<Span>, ErrorBody> {
    Ok(Some(Span { start, end }))
}

/// 0008, "Ranges": no range is the whole blob; an end at or past the size
/// is clamped; a suffix is the last bytes, the whole blob when it is longer;
/// a start at or past the size, a suffix of 0, and any range of an empty
/// blob are unsatisfiable, with the size.
#[test]
fn a_range_is_normalized_against_the_size() {
    let from = |start| Some(Range::From { start });
    let suffix = |suffix| Some(Range::Suffix { suffix });
    for (range, size, expected) in [
        (None, 0, Ok(None)),
        (None, 31, Ok(None)),
        (closed(0, 9), 31, spanned(0, 9)),
        (closed(0, 0), 31, spanned(0, 0)),
        (closed(30, 30), 31, spanned(30, 30)),
        (closed(5, 30), 31, spanned(5, 30)),
        (closed(5, 31), 31, spanned(5, 30)),
        (closed(5, 1031), 31, spanned(5, 30)),
        (closed(0, u64::MAX), 31, spanned(0, 30)),
        (closed(31, 31), 31, Err(unsatisfiable(31))),
        (closed(31, 40), 31, Err(unsatisfiable(31))),
        (closed(u64::MAX, u64::MAX), 31, Err(unsatisfiable(31))),
        (from(0), 31, spanned(0, 30)),
        (from(5), 31, spanned(5, 30)),
        (from(30), 31, spanned(30, 30)),
        (from(31), 31, Err(unsatisfiable(31))),
        (from(999_999), 31, Err(unsatisfiable(31))),
        (suffix(10), 31, spanned(21, 30)),
        (suffix(1), 31, spanned(30, 30)),
        (suffix(30), 31, spanned(1, 30)),
        (suffix(31), 31, spanned(0, 30)),
        (suffix(32), 31, spanned(0, 30)),
        (suffix(u64::MAX), 31, spanned(0, 30)),
        (suffix(0), 31, Err(unsatisfiable(31))),
        (closed(0, 0), 1, spanned(0, 0)),
        (suffix(5), 1, spanned(0, 0)),
        (closed(0, 0), 0, Err(unsatisfiable(0))),
        (from(0), 0, Err(unsatisfiable(0))),
        (suffix(1), 0, Err(unsatisfiable(0))),
        (suffix(0), 0, Err(unsatisfiable(0))),
        (from(0), BLOB, spanned(0, BLOB - 1)),
        (suffix(1), BLOB, spanned(BLOB - 1, BLOB - 1)),
    ] {
        assert_eq!(span(range, size), expected, "{range:?} of {size}");
    }
}

/// The walk's reservation, three objects of the add-on's 16 MiB (the
/// commit, a tree and the next), and a blob's while it loads, never less
/// than the walk's.
#[test]
fn the_figures() {
    assert_eq!(WALK, 48 << 20);
    assert_eq!(loading(BLOB), BLOB_LOADING);
    assert_eq!(loading(BLOB - 1), BLOB_LOADING - 2);
    assert_eq!(loading(25 << 20), 50 << 20);
    assert_eq!(loading(24 << 20), WALK);
    assert_eq!(loading(16 << 20), WALK);
    assert_eq!(loading(1), WALK);
    assert_eq!(loading(0), WALK);
}
