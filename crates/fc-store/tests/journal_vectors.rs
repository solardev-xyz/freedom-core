//! Replays `vectors/journal.json` (design 0013, PRF-5d): freedom-browser's
//! `durable-journal.js` lines, parses, reads and journal runs, byte for
//! byte.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use fc_json::JsValue;
use fc_store::NoHooks;
use fc_store::journal::{self, Journal, Parsed};

fn vectors() -> JsValue {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/journal.json");
    fc_json::parse(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn field<'a>(value: &'a JsValue, key: &str) -> &'a JsValue {
    value
        .get(key)
        .unwrap_or_else(|| panic!("no {key} in {}", value.stringify()))
}

fn text<'a>(value: &'a JsValue, key: &str) -> &'a str {
    field(value, key).as_str().unwrap()
}

fn number(value: &JsValue) -> u64 {
    match value {
        JsValue::Number(n) => *n as u64,
        other => panic!("not a number: {}", other.stringify()),
    }
}

fn list<'a>(value: &'a JsValue, key: &str) -> &'a [JsValue] {
    field(value, key).as_array().unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn record(text: &str) -> JsValue {
    fc_json::parse(text).unwrap()
}

/// `parsed` against the reference's `parseJournal` result, as JSON.
fn check_parsed(parsed: &Parsed, expected: &JsValue, case: &str) {
    let records: Vec<String> = parsed.records.iter().map(JsValue::stringify).collect();
    let want: Vec<&str> = list(expected, "records")
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert_eq!(records, want, "{case}: records");
    let corrupt: Vec<(u64, u64, &str)> = parsed
        .corrupt
        .iter()
        .map(|c| (c.line, c.offset, c.reason.name()))
        .collect();
    let want: Vec<(u64, u64, &str)> = list(expected, "corrupt")
        .iter()
        .map(|c| {
            (
                number(field(c, "line")),
                number(field(c, "offset")),
                text(c, "reason"),
            )
        })
        .collect();
    assert_eq!(corrupt, want, "{case}: corrupt");
    assert_eq!(
        parsed.complete_length,
        number(field(expected, "completeLength")),
        "{case}: completeLength"
    );
    assert_eq!(
        parsed.torn_tail,
        number(field(expected, "tornTail")),
        "{case}: tornTail"
    );
    assert_eq!(
        JsValue::Bool(parsed.unterminated),
        *field(expected, "unterminated"),
        "{case}: unterminated"
    );
}

fn bound(value: &JsValue) -> u64 {
    match field(value, "maxBytes") {
        JsValue::Null => journal::DEFAULT_MAX_BYTES,
        n => number(n),
    }
}

#[test]
fn the_constants_are_the_references() {
    let v = vectors();
    let constants = field(&v, "constants");
    assert_eq!(
        number(field(constants, "defaultMaxBytes")),
        journal::DEFAULT_MAX_BYTES
    );
    assert_eq!(
        number(field(constants, "fileMode")),
        u64::from(journal::FILE_MODE)
    );
}

#[test]
fn lines_are_the_references_byte_for_byte() {
    let v = vectors();
    for case in list(&v, "encode") {
        let name = text(case, "name");
        let encoded = journal::encode_line(&record(text(case, "record")));
        match case.get("line") {
            Some(line) => assert_eq!(hex(&encoded.unwrap()), line.as_str().unwrap(), "{name}"),
            None => assert_eq!(encoded.unwrap_err().code(), text(case, "error"), "{name}"),
        }
    }
}

#[test]
fn parses_are_the_references() {
    let v = vectors();
    for case in list(&v, "parse") {
        let name = text(case, "name");
        let parsed = journal::parse(&unhex(text(case, "bytes")));
        let expected = match case.get("deviation").map(|d| d.as_str()) {
            Some(Some("json-depth")) => field(case, "core"),
            Some(other) => panic!("{name}: unknown deviation {other:?}"),
            None => case,
        };
        check_parsed(&parsed, expected, name);
    }
}

#[test]
fn reads_are_the_references_at_each_bound() {
    let v = vectors();
    let constants = field(&v, "constants");
    let file_name = text(constants, "name");
    for case in list(&v, "read") {
        let name = text(case, "name");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(file_name);
        match text(case, "kind") {
            "missing" => {}
            "file" => std::fs::write(&path, unhex(text(case, "bytes"))).unwrap(),
            "zeros" => std::fs::File::create(&path)
                .unwrap()
                .set_len(number(field(case, "size")))
                .unwrap(),
            "directory" => std::fs::create_dir(&path).unwrap(),
            "symlink" => {
                #[cfg(unix)]
                {
                    std::fs::write(dir.path().join("target"), unhex(text(case, "bytes"))).unwrap();
                    std::os::unix::fs::symlink("target", &path).unwrap();
                }
                #[cfg(not(unix))]
                continue;
            }
            other => panic!("{name}: unknown kind {other}"),
        }
        let read = journal::read(&path, bound(case));
        match case.get("result") {
            Some(result) => {
                let read = read.unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(
                    JsValue::Bool(read.missing),
                    *field(result, "missing"),
                    "{name}"
                );
                assert_eq!(read.size, number(field(result, "size")), "{name}");
                check_parsed(&read.parsed, result, name);
            }
            None => assert_eq!(read.unwrap_err().code(), text(case, "error"), "{name}"),
        }
    }
}

/// Every file in `dir` and its bytes, as the vectors list them.
fn snapshot(dir: &Path) -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().into_string().unwrap(),
                hex(&std::fs::read(e.path()).unwrap()),
            )
        })
        .collect();
    files.sort();
    files
}

fn expected_files(value: &JsValue) -> Vec<(String, String)> {
    let JsValue::Object(files) = field(value, "files") else {
        panic!("files isn't an object");
    };
    let mut files: Vec<(String, String)> = files
        .iter()
        .map(|(k, v)| (k.to_string(), v.as_str().unwrap().to_owned()))
        .collect();
    files.sort();
    files
}

fn check_mode(path: &Path, expected: &JsValue, case: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .ok()
            .map(|m| f64::from(m.permissions().mode() & 0o777));
        let want = match expected {
            JsValue::Number(n) => Some(*n),
            _ => None,
        };
        assert_eq!(mode, want, "{case}: mode");
    }
    #[cfg(not(unix))]
    let _ = (path, expected, case);
}

#[test]
fn journal_runs_are_the_references_step_by_step() {
    let v = vectors();
    let file_name = text(field(&v, "constants"), "name");
    for run in list(&v, "journal") {
        let name = text(run, "name");
        let dir = tempfile::tempdir().unwrap();
        for (file, bytes) in expected_files(run) {
            let path = dir.path().join(&file);
            std::fs::write(&path, unhex(&bytes)).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        let mut journal = Journal::new(dir.path(), file_name, bound(run));
        for (i, step) in list(run, "steps").iter().enumerate() {
            let case = format!("{name} step {i} ({})", text(step, "op"));
            let outcome: Result<JsValue, journal::Error> = match text(step, "op") {
                "open" => journal.open().map(|read| {
                    check_parsed(&read.parsed, field(step, "result"), &case);
                    JsValue::Null
                }),
                "append" => journal
                    .append(&record(text(step, "record")), &NoHooks)
                    .map(|()| JsValue::Null),
                "compact" => {
                    let records: Vec<JsValue> = list(step, "records")
                        .iter()
                        .map(|r| record(r.as_str().unwrap()))
                        .collect();
                    journal.compact(&records, &NoHooks).map(|()| JsValue::Null)
                }
                "moveAside" => journal.move_aside(text(step, "tag")).map(|moved| {
                    moved.map_or(JsValue::Null, |p| {
                        JsValue::string(p.file_name().unwrap().to_str().unwrap())
                    })
                }),
                other => panic!("{case}: unknown op {other}"),
            };
            match (outcome, step.get("error")) {
                (Ok(result), None) => {
                    if text(step, "op") != "open" {
                        assert_eq!(&result, field(step, "result"), "{case}");
                    }
                }
                (Err(e), Some(code)) => assert_eq!(e.code(), code.as_str().unwrap(), "{case}"),
                (outcome, want) => panic!("{case}: {outcome:?}, wanted {want:?}"),
            }
            assert_eq!(journal.size(), number(field(step, "size")), "{case}: size");
            assert_eq!(snapshot(dir.path()), expected_files(step), "{case}: files");
            check_mode(journal.path(), field(step, "mode"), &case);
        }
    }
}
