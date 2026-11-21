//! `vectors/layout.json` replayed (design 0013, 5.4b; PRF-9a): the list of
//! what moves, the journal's texts as recovery reads them and as a move
//! writes them, each entry state's rollback and roll-forward, the
//! placeholder, and the start's decisions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_profile::layout::{
    self, AtRoot, Deferral, EntryState, Forward, Found, FreedomDir, Journal, StartState, Steps,
    Unsettled,
};
use serde_json::Value;

const VECTORS: &str = include_str!("../../../vectors/layout.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn str_of(value: &Value) -> &str {
    value.as_str().unwrap()
}

fn names(value: &Value) -> Vec<&str> {
    value.as_array().unwrap().iter().map(str_of).collect()
}

fn found(word: &str) -> Found {
    match word {
        "missing" => Found::Missing,
        "file" => Found::File,
        "dir" => Found::Dir,
        "other" => Found::Other,
        _ => panic!("kind {word}"),
    }
}

fn state(value: &Value) -> EntryState {
    let kinds = names(value);
    assert_eq!(kinds.len(), 3);
    EntryState {
        at_root: found(kinds[0]),
        moved: found(kinds[1]),
        moving: found(kinds[2]),
    }
}

fn unsettled(word: &str) -> Unsettled {
    match word {
        "moving_without_source" => Unsettled::MovingWithoutSource,
        "source_gone" => Unsettled::SourceGone,
        "at_both" => Unsettled::AtBoth,
        "not_moved" => Unsettled::NotMoved,
        "nowhere" => Unsettled::Nowhere,
        _ => panic!("unsettled {word}"),
    }
}

#[test]
fn the_constants_and_the_list() {
    let v = vectors();
    let c = &v["constants"];
    assert_eq!(str_of(&c["freedom_dir"]), layout::FREEDOM_DIR);
    assert_eq!(str_of(&c["move_journal"]), layout::MOVE_JOURNAL);
    assert_eq!(str_of(&c["layout_marker"]), layout::LAYOUT_MARKER);
    assert_eq!(str_of(&c["moving_suffix"]), layout::MOVING_SUFFIX);
    assert_eq!(str_of(&c["placeholder"]), layout::PLACEHOLDER);
    assert_eq!(
        c["max_journal_bytes"].as_u64(),
        Some(layout::MAX_JOURNAL_BYTES)
    );
    assert_eq!(names(&v["moved_entries"]), layout::MOVED_ENTRIES);
}

#[test]
fn the_journals_as_recovery_reads_them() {
    let v = vectors();
    for case in v["journals"].as_array().unwrap() {
        let text = str_of(&case["text"]);
        let parsed = layout::parse_journal(text);
        if case.get("malformed").is_some() {
            assert_eq!(parsed, None, "{text}");
            continue;
        }
        let journal = parsed.unwrap_or_else(|| panic!("in form: {text}"));
        assert_eq!(journal.entries(), names(&case["entries"]), "{text}");
        assert_eq!(journal.copied(), names(&case["copied"]), "{text}");
    }
}

#[test]
fn the_journals_a_move_writes() {
    let v = vectors();
    for case in v["written"].as_array().unwrap() {
        let mut journal = Journal::new(&names(&case["entries"])).unwrap();
        for name in names(&case["copied"]) {
            journal = journal.with_copied(name).unwrap();
        }
        assert_eq!(journal.text(), str_of(&case["text"]));
        assert_eq!(layout::parse_journal(&journal.text()), Some(journal));
    }
}

#[test]
fn every_rollback() {
    let v = vectors();
    for case in v["rollback"].as_array().unwrap() {
        let id = str_of(&case["id"]);
        let result = layout::rollback(
            str_of(&case["name"]),
            case["copied"].as_bool().unwrap(),
            state(&case["state"]),
        );
        let expected = match case.get("steps") {
            Some(steps) => {
                let steps = names(steps);
                for step in &steps {
                    assert!(
                        [
                            "remove_moving",
                            "remove_moved",
                            "remove_placeholder",
                            "rename_back"
                        ]
                        .contains(step),
                        "{id}: {step}"
                    );
                }
                Ok(Steps {
                    remove_moving: steps.contains(&"remove_moving"),
                    remove_moved: steps.contains(&"remove_moved"),
                    remove_placeholder: steps.contains(&"remove_placeholder"),
                    rename_back: steps.contains(&"rename_back"),
                })
            }
            None => Err(unsettled(str_of(&case["unsettled"]))),
        };
        assert_eq!(result, expected, "{id}");
    }
}

#[test]
fn every_roll_forward() {
    let v = vectors();
    for case in v["roll_forward"].as_array().unwrap() {
        let id = str_of(&case["id"]);
        let result = layout::roll_forward(case["copied"].as_bool().unwrap(), state(&case["state"]));
        let expected = match case.get("remove_source") {
            Some(remove) => Ok(Forward {
                remove_source: remove.as_bool().unwrap(),
            }),
            None => Err(unsettled(str_of(&case["unsettled"]))),
        };
        assert_eq!(result, expected, "{id}");
    }
}

#[test]
fn the_placeholder() {
    let v = vectors();
    for case in v["placeholder"].as_array().unwrap() {
        assert_eq!(
            layout::needs_placeholder(found(str_of(&case["identity_at_root"]))),
            case["needed"].as_bool().unwrap()
        );
    }
}

#[test]
fn every_start() {
    let v = vectors();
    for case in v["plan_start"].as_array().unwrap() {
        let id = str_of(&case["id"]);
        let root: Vec<(&str, AtRoot)> = case["root"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, seen)| {
                (
                    name.as_str(),
                    AtRoot {
                        found: found(str_of(&seen["found"])),
                        mount_point: seen["mount_point"].as_bool().unwrap(),
                    },
                )
            })
            .collect();
        let inside: Vec<String> = match &case["freedom"] {
            Value::Array(list) => list.iter().map(|n| str_of(n).to_owned()).collect(),
            _ => Vec::new(),
        };
        let freedom = match &case["freedom"] {
            Value::Null => FreedomDir::Missing,
            Value::Array(_) => FreedomDir::Dir(&inside),
            other => {
                assert_eq!(other.as_str(), Some("other"), "{id}");
                FreedomDir::Other
            }
        };
        let result = layout::plan_start(&StartState {
            root: &root,
            freedom,
            node_identity_journal: case["node_identity_journal"].as_bool().unwrap(),
        });
        match case.get("moves") {
            Some(moves) => assert_eq!(result, Ok(names(moves)), "{id}"),
            None => {
                let deferred = &case["deferred"];
                let reason = str_of(&deferred["reason"]);
                let name = deferred.get("name").map(str_of);
                let expected = match reason {
                    "node_identity_journal" => Deferral::NodeIdentityJournal,
                    "freedom_not_dir" => Deferral::FreedomNotDir,
                    "freedom_holds" => Deferral::FreedomHolds(name.unwrap().to_owned()),
                    "mount_point" => {
                        let name = name.unwrap();
                        let known = layout::MOVED_ENTRIES
                            .iter()
                            .find(|entry| **entry == name)
                            .unwrap();
                        Deferral::MountPoint(known)
                    }
                    _ => panic!("{id}: reason {reason}"),
                };
                assert_eq!(expected.word(), reason, "{id}");
                assert_eq!(result, Err(expected), "{id}");
            }
        }
    }
}
