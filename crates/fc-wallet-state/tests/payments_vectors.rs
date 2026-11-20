//! Replays vectors/sqlite.json's `payments` through the codec alone: every
//! operation the reference refused is refused here with its class and
//! message, before any statement, and every one it answered gets its
//! statements. The rows each leaves are freedom-cored's replay (its
//! `payments` tests), where SQLite runs them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_json::JsValue;
use fc_wallet_state::payments::{self, Thrown};

fn operations() -> Vec<JsValue> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/sqlite.json");
    let text = std::fs::read_to_string(path).expect("vectors/sqlite.json");
    let all = fc_json::parse(&text).expect("sqlite.json parses");
    let operations = all
        .get("payments")
        .and_then(|p| p.get("operations"))
        .and_then(JsValue::as_array);
    operations.expect("payments.operations").to_vec()
}

/// The codec's part of an operation: `None` for one that only reads rows.
fn codec(op: &str, args: &[JsValue], now: f64) -> Option<Result<(), Thrown>> {
    let arg = |i: usize| args.get(i).cloned().unwrap_or(JsValue::Undefined);
    Some(match op {
        "append" => payments::append(&arg(0), now).map(drop),
        "update" => payments::update(&arg(0), &arg(1), now).map(drop),
        "markConfirmed" => payments::confirmed_patch(&arg(1))
            .and_then(|p| payments::update(&arg(0), &p, now))
            .map(drop),
        "markFailed" => payments::failed_patch(&arg(1))
            .and_then(|p| payments::update(&arg(0), &p, now))
            .map(drop),
        "markDropped" | "setDroppedSeen" | "getById" => payments::by_id(&arg(0)).map(drop),
        "getRecent" => payments::get_recent(&arg(0)).map(drop),
        "getCount" => payments::get_count(&arg(0)).map(drop),
        _ => return None,
    })
}

#[test]
fn each_refusal_is_the_references() {
    let mut refused = 0;
    for (index, step) in operations().iter().enumerate() {
        let op = step.get("op").and_then(JsValue::as_str).expect("op");
        let args = step.get("args").and_then(JsValue::as_array).expect("args");
        let Some(JsValue::Number(now)) = step.get("now") else {
            panic!("now")
        };
        let Some(got) = codec(op, args, *now) else {
            continue;
        };
        let result = step.get("result").expect("result");
        match (result.get("error"), got) {
            (None, Ok(())) => {}
            (Some(error), Err(thrown)) => {
                assert_eq!(
                    error.get("name").and_then(JsValue::as_str),
                    Some(thrown.name.as_str()),
                    "step {index}"
                );
                assert_eq!(
                    error.get("message").and_then(JsValue::as_str),
                    Some(thrown.message.as_str()),
                    "step {index}"
                );
                refused += 1;
            }
            (expected, got) => panic!("step {index} ({op}): expected {expected:?}, got {got:?}"),
        }
    }
    assert!(refused >= 25, "{refused} refusals replayed");
}

/// better-sqlite3's binder: arrays spread, one object binds nothing, a
/// second is refused, and the count must match.
#[test]
fn the_binder() {
    let parse = |text: &str| fc_json::parse(text).expect("json");
    let (one, two, empty, obj) = (
        parse(r#"["a"]"#),
        parse(r#"["a","b"]"#),
        parse("[]"),
        parse(r#"{"k":1}"#),
    );
    let n = JsValue::Number(1.5);
    assert_eq!(
        payments::bind(&[&one, &obj, &n], 2),
        Ok(vec![
            payments::Bind::Text("a".into()),
            payments::Bind::Real(1.5)
        ])
    );
    let message = |args: &[&JsValue], count| payments::bind(args, count).map_err(|t| t.message);
    assert_eq!(
        message(&[&two], 1),
        Err("Too many parameter values were provided".into())
    );
    assert_eq!(
        message(&[&empty, &n], 2),
        Err("Too few parameter values were provided".into())
    );
    assert_eq!(
        message(&[&obj, &obj], 0),
        Err("You cannot specify named parameters in two different objects".into())
    );
    assert_eq!(
        message(&[&JsValue::Bool(false)], 1),
        Err("SQLite3 can only bind numbers, strings, bigints, buffers, and null".into())
    );
    assert_eq!(
        payments::bind(&[&JsValue::Undefined, &JsValue::Null], 2),
        Ok(vec![payments::Bind::Null; 2])
    );
}

/// `getRecent`'s page: 50 rows without a `limit`, and a `limit` clamped to
/// 500 (freedom-cored's `the_reference_pages` runs the reference's pages on
/// 501 rows).
#[test]
fn the_page_is_50_and_at_most_500() {
    let page = |filters: &str| {
        let filters = fc_json::parse(filters).expect("json");
        payments::get_recent(&filters).expect("a statement").params
    };
    let real = payments::Bind::Real;
    assert_eq!(page("{}"), [real(50.0), real(0.0)]);
    assert_eq!(
        payments::get_recent(&JsValue::Undefined)
            .expect("a statement")
            .params,
        [real(50.0), real(0.0)]
    );
    assert_eq!(page(r#"{"limit":500}"#), [real(500.0), real(0.0)]);
    assert_eq!(page(r#"{"limit":501}"#), [real(500.0), real(0.0)]);
    assert_eq!(
        page(r#"{"limit":1e10,"offset":-3}"#),
        [real(500.0), real(0.0)]
    );
}
