use std::panic::{AssertUnwindSafe, catch_unwind};

use super::*;
use crate::NoHooks;

/// Fails the steps given, as the OS would.
struct Fail(Vec<Step>);

impl Hooks for Fail {
    fn fails(&self, step: Step) -> bool {
        self.0.contains(&step)
    }
}

/// The process dies at `0`, before that step runs: nothing after it
/// happens, no cleanup included.
struct Crash(Step);

impl Hooks for Crash {
    fn fails(&self, step: Step) -> bool {
        if step == self.0 {
            panic!("crash at {}", step.name());
        }
        false
    }
}

fn record(text: &str) -> JsValue {
    fc_json::parse(text).unwrap()
}

fn texts(records: &[JsValue]) -> Vec<String> {
    records.iter().map(JsValue::stringify).collect()
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// A journal in a fresh directory, opened, holding `{"n":1}` and `{"n":2}`.
fn two() -> (tempfile::TempDir, Journal) {
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::new(dir.path(), "j.jsonl", DEFAULT_MAX_BYTES);
    journal.open().unwrap();
    journal.append(&record(r#"{"n":1}"#), &NoHooks).unwrap();
    journal.append(&record(r#"{"n":2}"#), &NoHooks).unwrap();
    (dir, journal)
}

fn reopened(dir: &Path) -> (Journal, Read) {
    let mut journal = Journal::new(dir, "j.jsonl", DEFAULT_MAX_BYTES);
    let read = journal.open().unwrap();
    (journal, read)
}

const ONE_TWO: [&str; 2] = [r#"{"n":1}"#, r#"{"n":2}"#];

#[test]
fn a_line_is_the_records_text_and_its_checksum() {
    let line = encode_line(&record(r#"{"b":1,"a":"é"}"#)).unwrap();
    let body = r#"{"b":1,"a":"é"}"#;
    let expected = format!(
        "{{\"v\":1,\"sha256\":\"{}\",\"record\":{body}}}\n",
        hex(&Sha256::digest(body.as_bytes()))
    );
    assert_eq!(String::from_utf8(line.clone()).unwrap(), expected);
    let parsed = parse(&line);
    assert_eq!(texts(&parsed.records), [body]);
    for text in ["[]", "null", "1", "\"x\""] {
        assert!(matches!(
            encode_line(&record(text)),
            Err(Error::InvalidRecord)
        ));
    }
}

#[test]
fn a_digest_in_upper_case_is_malformed_and_a_wrong_one_a_checksum() {
    let line = encode_line(&record(r#"{"a":1}"#)).unwrap();
    let text = String::from_utf8(line).unwrap();
    let digest = &text[17..81];
    let upper = text.replacen(digest, &digest.to_uppercase(), 1);
    let flipped = text.replacen(&digest[..1], if &digest[..1] == "0" { "1" } else { "0" }, 1);
    let parsed = parse(format!("{upper}{flipped}").as_bytes());
    assert!(parsed.records.is_empty());
    let reasons: Vec<_> = parsed.corrupt.iter().map(|c| (c.line, c.reason)).collect();
    assert_eq!(reasons, [(1, Reason::Malformed), (2, Reason::Checksum)]);
}

#[test]
fn appends_create_the_file_0600_and_the_size_follows() {
    let (dir, journal) = two();
    let bytes = std::fs::read(dir.path().join("j.jsonl")).unwrap();
    assert_eq!(journal.size(), bytes.len() as u64);
    assert_eq!(texts(&parse(&bytes).records), ONE_TWO);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(journal.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn a_write_before_open_is_refused_and_a_bad_record_before_that() {
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::new(dir.path(), "j.jsonl", DEFAULT_MAX_BYTES);
    let refused = journal.append(&record(r#"{"a":1}"#), &NoHooks);
    assert!(matches!(refused, Err(Error::NotOpen)));
    assert!(matches!(
        journal.compact(&[], &NoHooks),
        Err(Error::NotOpen)
    ));
    assert!(matches!(
        journal.append(&record("[1]"), &NoHooks),
        Err(Error::InvalidRecord)
    ));
    assert!(matches!(
        journal.compact(&[record("{}"), record("2")], &NoHooks),
        Err(Error::InvalidRecord)
    ));
    assert!(names(dir.path()).is_empty());
}

#[test]
fn a_failed_write_or_fsync_is_cut_back_and_the_journal_goes_on() {
    for step in [Step::Write, Step::Fsync] {
        let (dir, mut journal) = two();
        let before = std::fs::read(journal.path()).unwrap();
        let failed = journal.append(&record(r#"{"n":3}"#), &Fail(vec![step]));
        assert!(matches!(failed, Err(Error::Io(_))), "{step:?}");
        assert_eq!(std::fs::read(journal.path()).unwrap(), before, "{step:?}");
        assert_eq!(journal.size(), before.len() as u64);
        journal.append(&record(r#"{"n":4}"#), &NoHooks).unwrap();
        let (_, read) = reopened(dir.path());
        assert_eq!(
            texts(&read.parsed.records),
            [ONE_TWO[0], ONE_TWO[1], r#"{"n":4}"#]
        );
    }
}

#[test]
fn a_failed_cut_breaks_the_journal_until_it_is_opened_again() {
    let (dir, mut journal) = two();
    let before = std::fs::read(journal.path()).unwrap();
    let failed = journal.append(
        &record(r#"{"n":3}"#),
        &Fail(vec![Step::Write, Step::Truncate]),
    );
    assert!(matches!(failed, Err(Error::Io(_))));
    // Half a line is left on disk: a torn tail.
    let torn = std::fs::read(journal.path()).unwrap();
    assert!(torn.len() > before.len());
    assert_eq!(parse(&torn).torn_tail, (torn.len() - before.len()) as u64);
    assert!(matches!(
        journal.append(&record(r#"{"n":4}"#), &NoHooks),
        Err(Error::Broken(io::ErrorKind::Other))
    ));
    assert!(matches!(
        journal.compact(&[], &NoHooks),
        Err(Error::Broken(_))
    ));
    let read = journal.open().unwrap();
    assert_eq!(read.parsed.torn_tail, (torn.len() - before.len()) as u64);
    assert_eq!(std::fs::read(journal.path()).unwrap(), before);
    journal.append(&record(r#"{"n":5}"#), &NoHooks).unwrap();
    let (_, read) = reopened(dir.path());
    assert_eq!(
        texts(&read.parsed.records),
        [ONE_TWO[0], ONE_TWO[1], r#"{"n":5}"#]
    );
}

#[test]
fn a_failed_directory_sync_at_create_keeps_the_line_and_breaks_the_journal() {
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::new(dir.path(), "j.jsonl", DEFAULT_MAX_BYTES);
    journal.open().unwrap();
    let failed = journal.append(&record(r#"{"n":1}"#), &Fail(vec![Step::Flush]));
    assert!(matches!(failed, Err(Error::Io(_))));
    assert!(matches!(
        journal.append(&record(r#"{"n":2}"#), &NoHooks),
        Err(Error::Broken(_))
    ));
    let (mut journal, read) = reopened(dir.path());
    assert_eq!(texts(&read.parsed.records), [ONE_TWO[0]]);
    // The file exists now: no directory sync, so no flush to fail.
    journal
        .append(&record(r#"{"n":2}"#), &Fail(vec![Step::Flush]))
        .unwrap();
}

#[test]
fn a_failed_compaction_before_the_rename_keeps_the_old_journal() {
    for step in [Step::Write, Step::Fsync, Step::Rename] {
        let (dir, mut journal) = two();
        let before = std::fs::read(journal.path()).unwrap();
        let failed = journal.compact(&[record(r#"{"n":2}"#)], &Fail(vec![step]));
        assert!(matches!(failed, Err(Error::Io(_))), "{step:?}");
        assert_eq!(std::fs::read(journal.path()).unwrap(), before, "{step:?}");
        assert_eq!(names(dir.path()), ["j.jsonl"], "{step:?}");
        assert_eq!(journal.size(), before.len() as u64);
        journal.append(&record(r#"{"n":3}"#), &NoHooks).unwrap();
    }
}

#[test]
fn a_compaction_replaces_the_file_and_a_failed_sync_after_it_breaks_the_journal() {
    let (dir, mut journal) = two();
    journal.compact(&[record(r#"{"n":2}"#)], &NoHooks).unwrap();
    let bytes = std::fs::read(journal.path()).unwrap();
    assert_eq!(bytes, encode_line(&record(r#"{"n":2}"#)).unwrap());
    assert_eq!(journal.size(), bytes.len() as u64);
    assert_eq!(names(dir.path()), ["j.jsonl"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(journal.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let failed = journal.compact(&[], &Fail(vec![Step::Flush]));
    assert!(matches!(failed, Err(Error::Io(_))));
    assert_eq!(std::fs::read(journal.path()).unwrap(), b"");
    assert!(matches!(
        journal.append(&record(r#"{"n":3}"#), &NoHooks),
        Err(Error::Broken(_))
    ));
}

/// A crash at each step of an append leaves the old records or the new
/// line, and the next open leaves a file the next append extends.
#[test]
fn a_crash_at_each_step_of_an_append_leaves_the_old_records_or_the_new() {
    for (step, fresh) in [
        (Step::Write, false),
        (Step::Fsync, false),
        (Step::Write, true),
        (Step::Fsync, true),
        (Step::Flush, true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::new(dir.path(), "j.jsonl", DEFAULT_MAX_BYTES);
        journal.open().unwrap();
        let mut old = Vec::new();
        if !fresh {
            journal.append(&record(ONE_TWO[0]), &NoHooks).unwrap();
            old.push(ONE_TWO[0]);
        }
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            journal.append(&record(ONE_TWO[1]), &Crash(step))
        }));
        assert!(crashed.is_err(), "{step:?}");
        drop(journal);
        let (mut journal, read) = reopened(dir.path());
        let got = texts(&read.parsed.records);
        let mut new = old.clone();
        new.push(ONE_TWO[1]);
        // Before the write, nothing of the line; after it, the whole line
        // (unsynced, so a power cut could still lose it).
        let expected = if step == Step::Write { &old } else { &new };
        assert_eq!(&got, expected, "{step:?} fresh {fresh}");
        assert!(read.parsed.corrupt.is_empty());
        journal.append(&record(r#"{"n":9}"#), &NoHooks).unwrap();
        let (_, read) = reopened(dir.path());
        assert_eq!(read.parsed.records.len(), got.len() + 1, "{step:?}");
    }
}

#[test]
fn a_crash_at_each_step_of_a_compaction_leaves_the_old_file_or_the_new() {
    for step in [Step::Write, Step::Fsync, Step::Rename, Step::Flush] {
        let (dir, mut journal) = two();
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            journal.compact(&[record(ONE_TWO[1])], &Crash(step))
        }));
        assert!(crashed.is_err(), "{step:?}");
        drop(journal);
        let leftover = names(dir.path()).len() > 1;
        // Before the rename, the temp file is left behind, and the old file.
        assert_eq!(leftover, step != Step::Flush, "{step:?}");
        let (_, read) = reopened(dir.path());
        assert_eq!(names(dir.path()), ["j.jsonl"], "{step:?}");
        let expected: &[&str] = if step == Step::Flush {
            &ONE_TWO[1..]
        } else {
            &ONE_TWO
        };
        assert_eq!(texts(&read.parsed.records), expected, "{step:?}");
    }
}

#[test]
fn open_ends_a_whole_last_record_cuts_a_torn_tail_and_tightens_the_mode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.jsonl");
    let one = encode_line(&record(ONE_TWO[0])).unwrap();
    let two = encode_line(&record(ONE_TWO[1])).unwrap();
    // A whole last record without its newline.
    let mut bytes = one.clone();
    bytes.extend_from_slice(&two[..two.len() - 1]);
    std::fs::write(&path, &bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let (mut journal, read) = reopened(dir.path());
    assert!(read.parsed.unterminated);
    assert_eq!(read.size, bytes.len() as u64);
    assert_eq!(texts(&read.parsed.records), ONE_TWO);
    let mut ended = one.clone();
    ended.extend_from_slice(&two);
    assert_eq!(std::fs::read(&path).unwrap(), ended);
    assert_eq!(journal.size(), ended.len() as u64);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // A torn tail: two bytes short of a whole record.
    journal.compact(&[], &NoHooks).unwrap();
    let mut torn = one.clone();
    torn.extend_from_slice(&two[..two.len() - 2]);
    std::fs::write(&path, &torn).unwrap();
    let (journal, read) = reopened(dir.path());
    assert!(!read.parsed.unterminated);
    assert_eq!(read.parsed.torn_tail, (two.len() - 2) as u64);
    assert_eq!(std::fs::read(&path).unwrap(), one);
    assert_eq!(journal.size(), one.len() as u64);
}

#[test]
fn open_removes_compaction_temps_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    for name in [
        "j.jsonl.compact-1b4e28ba-2fa1-11d2-883f-0016d3cca427.tmp",
        "j.jsonl.compact-.tmp",
        "j.jsonl.compact-1-0.tmp",
        "j.jsonl.compact-x.tmp.keep",
        "k.jsonl.compact-x.tmp",
        ".j.jsonl.1.0.tmp",
        "j.jsonl.compactx.tmp",
    ] {
        std::fs::write(dir.path().join(name), b"x").unwrap();
    }
    std::fs::create_dir(dir.path().join("j.jsonl.compact-dir.tmp")).unwrap();
    let (_, read) = reopened(dir.path());
    assert!(read.missing);
    assert_eq!(
        names(dir.path()),
        [
            ".j.jsonl.1.0.tmp",
            "j.jsonl.compact-dir.tmp",
            "j.jsonl.compact-x.tmp.keep",
            "j.jsonl.compactx.tmp",
            "k.jsonl.compact-x.tmp",
        ]
    );
}

#[test]
fn read_refuses_what_isnt_a_regular_file_and_holds_the_bound() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.jsonl");
    std::fs::create_dir(&path).unwrap();
    assert!(matches!(read(&path, 100), Err(Error::NotAFile)));
    std::fs::remove_dir(&path).unwrap();
    #[cfg(unix)]
    {
        std::fs::write(dir.path().join("target"), b"").unwrap();
        std::os::unix::fs::symlink("target", &path).unwrap();
        assert!(matches!(read(&path, 100), Err(Error::NotAFile)));
        std::fs::remove_file(&path).unwrap();
    }
    std::fs::write(&path, vec![b'x'; 100]).unwrap();
    assert_eq!(read(&path, 100).unwrap().parsed.torn_tail, 100);
    assert!(matches!(read(&path, 99), Err(Error::TooLarge)));
    let mut journal = Journal::new(dir.path(), "j.jsonl", 99);
    assert!(matches!(journal.open(), Err(Error::TooLarge)));
    assert!(matches!(
        journal.append(&record("{}"), &NoHooks),
        Err(Error::NotOpen)
    ));
}

#[test]
fn move_aside_takes_the_first_free_name_and_starts_an_empty_journal() {
    let (dir, mut journal) = two();
    std::fs::write(dir.path().join("j.jsonl.bad"), b"").unwrap();
    let moved = journal.move_aside("bad").unwrap();
    assert_eq!(moved, Some(dir.path().join("j.jsonl.bad-1")));
    assert_eq!(journal.size(), 0);
    assert_eq!(journal.move_aside("bad").unwrap(), None);
    journal.append(&record(ONE_TWO[0]), &NoHooks).unwrap();
    std::fs::write(dir.path().join("j.jsonl.bad-2"), b"").unwrap();
    let moved = journal.move_aside("bad").unwrap();
    assert_eq!(moved, Some(dir.path().join("j.jsonl.bad-3")));
    let moved_bytes = std::fs::read(dir.path().join("j.jsonl.bad-3")).unwrap();
    assert_eq!(texts(&parse(&moved_bytes).records), [ONE_TWO[0]]);
    // A journal open refused, moved aside, then written.
    let mut refused = Journal::new(dir.path(), "j.jsonl", 0);
    journal.append(&record(ONE_TWO[1]), &NoHooks).unwrap();
    assert!(matches!(refused.open(), Err(Error::TooLarge)));
    assert!(refused.move_aside("big").unwrap().is_some());
    refused.append(&record(ONE_TWO[0]), &NoHooks).unwrap();
    assert_eq!(
        std::fs::read(refused.path()).unwrap(),
        encode_line(&record(ONE_TWO[0])).unwrap()
    );
}
