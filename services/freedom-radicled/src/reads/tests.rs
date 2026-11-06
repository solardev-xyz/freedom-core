#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use super::*;
use crate::output;

const RID: &str = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5";
const REV: &str = "0123456789abcdef0123456789abcdef01234567";

fn rid_of() -> RepoId {
    RepoId::from_str(RID).unwrap()
}

fn checked(params: Value) -> Result<Op, ErrorBody> {
    let raw = serde_json::value::to_raw_value(&params).unwrap();
    op(Some(&raw))
}

fn read(name: &str, args: Value) -> Result<Op, ErrorBody> {
    checked(json!({ "op": name, "args": args }))
}

fn code(checked: Result<Op, ErrorBody>) -> Option<ErrorCode> {
    checked.err().map(|e| e.code)
}

/// Each pass-through op takes the add-on's args, by name, and names the
/// repository it reads.
#[test]
fn each_op_takes_todays_args() {
    let rid = rid_of();
    let cases = [
        (
            read("repo_info", json!({ "rid": RID })),
            Op::RepoInfo { rid },
        ),
        (
            read("tree", json!({ "rid": RID, "path": "src" })),
            Op::Tree {
                rid,
                path: "src".into(),
            },
        ),
        (
            read(
                "tree_at",
                json!({ "rid": RID, "revision": REV, "path": "" }),
            ),
            Op::TreeAt {
                rid,
                revision: REV.into(),
                path: String::new(),
            },
        ),
        (
            read("blob", json!({ "rid": RID, "path": "README.md" })),
            Op::Blob {
                rid,
                path: "README.md".into(),
            },
        ),
        (
            read(
                "blob_at",
                json!({ "rid": RID, "revision": REV, "path": "a/b.txt" }),
            ),
            Op::BlobAt {
                rid,
                revision: REV.into(),
                path: "a/b.txt".into(),
            },
        ),
        (
            read(
                "commits",
                json!({ "rid": RID, "parent": REV, "page": 2, "per_page": 30 }),
            ),
            Op::Commits {
                rid,
                parent: REV.into(),
                page: 2,
                per_page: 30,
            },
        ),
        (
            read("commit", json!({ "rid": RID, "revision": REV })),
            Op::Commit {
                rid,
                revision: REV.into(),
            },
        ),
        (read("issues", json!({ "rid": RID })), Op::Issues { rid }),
        (read("patches", json!({ "rid": RID })), Op::Patches { rid }),
        (read("list_repos", json!({})), Op::ListRepos),
        (read("list_seeded_repos", json!({})), Op::ListSeededRepos),
        (read("seeders", json!({ "rid": RID })), Op::Seeders { rid }),
        (read("identity", json!({})), Op::Identity),
        (read("status", json!({})), Op::Status),
    ];
    for (checked, expected) in cases {
        let op = checked.unwrap();
        assert_eq!(op, expected);
        let named = !matches!(
            op,
            Op::ListRepos | Op::ListSeededRepos | Op::Identity | Op::Status
        );
        assert_eq!(op.rid(), named.then_some(rid), "{op:?}");
        assert_eq!(
            op.cob(),
            matches!(op, Op::Issues { .. } | Op::Patches { .. }),
            "{op:?}"
        );
    }
}

/// The ops without args take none, null or `{}`, and nothing else.
#[test]
fn ops_without_args_take_none() {
    for name in ["list_repos", "list_seeded_repos", "identity", "status"] {
        assert!(checked(json!({ "op": name })).is_ok(), "{name}");
        assert!(read(name, Value::Null).is_ok(), "{name}");
        assert!(read(name, json!({})).is_ok(), "{name}");
        assert_eq!(
            code(read(name, json!({ "rid": RID }))),
            Some(ErrorCode::InvalidArgument),
            "{name}"
        );
        assert_eq!(
            code(read(name, json!([]))),
            Some(ErrorCode::InvalidArgument),
            "{name}"
        );
    }
}

/// `per_page` is cut to the add-on's 100; `page` and `per_page` are the
/// add-on's `u32`s.
#[test]
fn commits_pages_as_the_add_on_does() {
    let commits = |page: Value, per_page: Value| {
        read(
            "commits",
            json!({ "rid": RID, "parent": REV, "page": page, "per_page": per_page }),
        )
    };
    let Op::Commits { page, per_page, .. } = commits(json!(0), json!(100)).unwrap() else {
        panic!()
    };
    assert_eq!((page, per_page), (0, 100));
    let Op::Commits { page, per_page, .. } = commits(json!(u32::MAX), json!(101)).unwrap() else {
        panic!()
    };
    assert_eq!((page, per_page), (u32::MAX as usize, BINDING_MAX_PER_PAGE));
    assert_eq!(BINDING_MAX_PER_PAGE, 100);
    let Op::Commits { per_page, .. } = commits(json!(0), json!(0)).unwrap() else {
        panic!()
    };
    assert_eq!(per_page, 0);
    for (page, per_page) in [
        (json!(-1), json!(30)),
        (json!(0), json!(-1)),
        (json!(1.5), json!(30)),
        (json!(u64::from(u32::MAX) + 1), json!(30)),
        (json!("1"), json!(30)),
    ] {
        assert_eq!(
            code(commits(page.clone(), per_page.clone())),
            Some(ErrorCode::InvalidArgument),
            "{page} {per_page}"
        );
    }
}

/// What doesn't parse is `invalid_argument`: the params, an op 0008 doesn't
/// list, args the op doesn't take, a RID, a revision or a parent that isn't
/// 40 lowercase hex digits.
#[test]
fn what_doesnt_parse_is_invalid_argument() {
    let invalid = Some(ErrorCode::InvalidArgument);
    assert_eq!(code(op(None)), invalid);
    assert_eq!(code(checked(json!({}))), invalid);
    assert_eq!(
        code(checked(json!({ "op": "status", "other": 1 }))),
        invalid
    );
    assert_eq!(code(read("list_files", json!({ "rid": RID }))), invalid);
    assert_eq!(code(read("", json!({}))), invalid);
    assert_eq!(code(read("repo_info", json!({}))), invalid);
    assert_eq!(
        code(read("repo_info", json!({ "rid": "rad:nope" }))),
        invalid
    );
    assert_eq!(
        code(read("repo_info", json!({ "rid": RID, "path": "" }))),
        invalid
    );
    assert_eq!(code(read("tree", json!({ "rid": RID }))), invalid);
    let upper = REV.to_ascii_uppercase();
    for bad in [
        &REV[..39],
        &format!("{REV}0"),
        upper.as_str(),
        "g123456789abcdef0123456789abcdef01234567",
        "",
    ] {
        for (name, args) in [
            (
                "tree_at",
                json!({ "rid": RID, "revision": bad, "path": "" }),
            ),
            (
                "blob_at",
                json!({ "rid": RID, "revision": bad, "path": "a" }),
            ),
            ("commit", json!({ "rid": RID, "revision": bad })),
            (
                "commits",
                json!({ "rid": RID, "parent": bad, "page": 0, "per_page": 1 }),
            ),
        ] {
            assert_eq!(code(read(name, args)), invalid, "{name} {bad:?}");
        }
    }
}

/// The ops 0008 lists that a later step serves are `stopped`, not served
/// in this build.
#[test]
fn later_ops_are_not_served_in_this_build() {
    for name in LATER {
        let error = read(name, json!({ "rid": RID })).unwrap_err();
        assert_eq!(error.code, ErrorCode::Stopped, "{name}");
        assert_eq!(error.message, "not served in this build");
    }
}

fn gate_with(state: Option<RepoState>) -> RepoGate {
    let gate = RepoGate::new();
    if let Some(state) = state {
        gate.close(rid_of(), state, Duration::ZERO).unwrap();
    }
    gate
}

/// What the fence answers each kind of op, by the repository's state at
/// the gate and its writes.
fn fenced(state: Option<RepoState>, writing: bool, op: &Op) -> Option<ErrorBody> {
    let home = tempfile::tempdir().unwrap();
    let gate = gate_with(state);
    fence(home.path(), &gate, |rid| writing && *rid == rid_of(), op)
}

fn every_op() -> Vec<Op> {
    let rid = rid_of();
    vec![
        Op::RepoInfo { rid },
        Op::Tree {
            rid,
            path: String::new(),
        },
        Op::TreeAt {
            rid,
            revision: REV.into(),
            path: String::new(),
        },
        Op::Blob {
            rid,
            path: "a".into(),
        },
        Op::BlobAt {
            rid,
            revision: REV.into(),
            path: "a".into(),
        },
        Op::Commits {
            rid,
            parent: REV.into(),
            page: 0,
            per_page: 1,
        },
        Op::Commit {
            rid,
            revision: REV.into(),
        },
        Op::Issues { rid },
        Op::Patches { rid },
        Op::ListRepos,
        Op::ListSeededRepos,
        Op::Seeders { rid },
        Op::Identity,
        Op::Status,
    ]
}

/// 0008, "Methods" ("The repair fence") and "Errors" (`quarantined`): the
/// COB ops answer `stopped` while the repository is being repaired, or a
/// COB write to it is past its start and unproven, and `quarantined` once
/// it is quarantined; every op naming it is `quarantined` for a
/// `namespace` quarantine; the others read on.
#[test]
fn the_fence_by_the_repositorys_state() {
    use gate::Quarantine::{Cache, Namespace};
    for op in every_op() {
        let cob = op.cob();
        let named = op.rid().is_some();
        let answer = |state, writing| fenced(state, writing, &op).map(|e| e.code);
        assert_eq!(answer(None, false), None, "{op:?}");
        assert_eq!(
            answer(Some(RepoState::Repairing), false),
            cob.then_some(ErrorCode::Stopped),
            "{op:?}"
        );
        assert_eq!(
            answer(None, true),
            cob.then_some(ErrorCode::Stopped),
            "{op:?}"
        );
        assert_eq!(
            answer(Some(RepoState::Quarantined(Cache)), false),
            cob.then_some(ErrorCode::Quarantined),
            "{op:?}"
        );
        assert_eq!(
            answer(Some(RepoState::Quarantined(Namespace)), false),
            named.then_some(ErrorCode::Quarantined),
            "{op:?}"
        );
        // Quarantined comes first.
        assert_eq!(
            answer(Some(RepoState::Quarantined(Cache)), true),
            cob.then_some(ErrorCode::Quarantined),
            "{op:?}"
        );
    }
}

/// A quarantined repository's refusal carries the record's kind; with no
/// record, the gate's, and a null step.
#[test]
fn a_quarantined_refusal_has_its_kind() {
    let op = Op::Issues { rid: rid_of() };
    let error = fenced(
        Some(RepoState::Quarantined(gate::Quarantine::Namespace)),
        false,
        &op,
    )
    .unwrap();
    assert_eq!(
        error.data,
        Some(json!({ "kind": "namespace", "step": null }))
    );
    let error = fenced(
        Some(RepoState::Quarantined(gate::Quarantine::Cache)),
        false,
        &op,
    )
    .unwrap();
    assert_eq!(error.data, Some(json!({ "kind": "cache", "step": null })));
}

/// Another repository's state or writes fence nothing.
#[test]
fn the_fence_is_the_repositorys_own() {
    let home = tempfile::tempdir().unwrap();
    let gate = gate_with(Some(RepoState::Quarantined(gate::Quarantine::Namespace)));
    let other = RepoId::from_str("rad:z4V1sjrXqjvFdnCUbxPFqd5p4DtH5").unwrap();
    assert_ne!(other, rid_of());
    let op = Op::Issues { rid: other };
    assert!(fence(home.path(), &gate, |rid| *rid == rid_of(), &op).is_none());
}

/// Today's test of a message (`/not found|does not exist|NotFound/i`).
#[test]
fn not_found_is_todays_message_test() {
    for message in [
        "repository rad:z… not found",
        "the path 'x' does not exist in the given tree",
        "NotFound: reference",
        "NOT FOUND",
        "Does Not Exist",
        "notfound",
    ] {
        assert!(not_found(message), "{message}");
    }
    for message in ["invalid revision", "found", "not a blob", "exists"] {
        assert!(!not_found(message), "{message}");
    }
    let error = radicle_error(libradicle::Error::NotABlob("src".into()));
    assert_eq!(error.code, ErrorCode::Failed);
    assert_eq!(
        error.message,
        libradicle::Error::NotABlob("src".into()).to_string()
    );
}

fn text(content: &[u8]) -> Blob {
    Blob {
        binary: false,
        content: content.to_vec(),
    }
}

/// What a blob's JSON holds beside the JSON as libradicle writes it: the
/// content, and for text the value's copy, and the lossy copy before it.
#[test]
fn a_blobs_held_bytes() {
    assert_eq!(blob_held(&text(b"")), 0);
    assert_eq!(blob_held(&text(b"plain text")), 20);
    assert_eq!(
        blob_held(&Blob {
            binary: true,
            content: vec![0; 10],
        }),
        10
    );
    // `café` in Latin-1: four bytes, one invalid; lossy, `caf` and U+FFFD.
    assert_eq!(lossy_len(b"caf\xe9"), Some(6));
    assert_eq!(
        lossy_len(b"caf\xe9"),
        Some(String::from_utf8_lossy(b"caf\xe9").len() as u64)
    );
    assert_eq!(blob_held(&text(b"caf\xe9")), 4 + 2 * 6);
    // Each invalid sequence is one U+FFFD, however long: a truncated
    // three-byte sequence is one, two lone bytes are two.
    for bytes in [
        &b"\xe2\x82"[..],
        b"\xff\xfe",
        b"a\xf0\x9f\x98",
        b"\xc3(",
        b"\xed\xa0\x80",
        &[0xffu8; 1000][..],
    ] {
        assert_eq!(
            lossy_len(bytes),
            Some(String::from_utf8_lossy(bytes).len() as u64),
            "{bytes:?}"
        );
    }
    assert_eq!(lossy_len("ünïcödé".as_bytes()), None);
}

/// A blob is loaded up to half the built budget, and refused `too_large`
/// if its JSON's writing would hold more than it.
#[test]
fn a_blob_is_bounded_by_the_built_budget() {
    let bounds = |budget| Bounds::new(libradicle::CancelToken::new(), budget);
    let mut asked = None;
    let blob = bounded_blob(&bounds(100), |limit| {
        asked = Some(limit);
        Ok(text(&[b'a'; 50]))
    })
    .unwrap();
    assert_eq!(asked, Some(50));
    assert_eq!(blob.content.len(), 50);
    // 26 bytes of Latin-1: 26 + 2 × 78 held.
    let refused = bounded_blob(&bounds(100), |_| Ok(text(&[0xe9; 26]))).unwrap_err();
    assert!(
        matches!(
            refused,
            libradicle::Error::TooLarge {
                size: 182,
                limit: 100
            }
        ),
        "{refused:?}"
    );
    // 20 bytes of Latin-1 hold 20 + 2 × 60: at the budget, taken; one byte
    // over, refused.
    assert!(bounded_blob(&bounds(140), |_| Ok(text(&[0xe9; 20]))).is_ok());
    assert!(bounded_blob(&bounds(139), |_| Ok(text(&[0xe9; 20]))).is_err());
    // libradicle's own refusal stands.
    let refused = bounded_blob(&bounds(100), |limit| {
        Err(libradicle::Error::TooLarge { size: 51, limit })
    })
    .unwrap_err();
    assert!(matches!(
        refused,
        libradicle::Error::TooLarge {
            size: 51,
            limit: 50
        }
    ));
}

/// 0008's figures: a blob read as JSON is at most 16 MiB, the add-on's cap,
/// so its loading's two copies fit the built budget.
#[test]
fn the_figures() {
    assert_eq!(output::BUILT / 2, 16 << 20);
    assert_eq!(output::BUILT / 2, libradicle::BINDING_READ_BUDGET);
    let bounds = Bounds::new(libradicle::CancelToken::new(), output::BUILT).with_loads(7);
    let half = halved(&bounds);
    assert_eq!(half.budget, output::BUILT / 2);
    assert_eq!(half.loads, 7);
}
