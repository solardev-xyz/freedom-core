//! Each profile subcommand, confined, can't read outside its grant (design
//! 0013, PRF-3; 0010). The test hook `FREEDOM_CORED_TEST_PROFILE_CONFINED`
//! reads the paths it names right after the run confines itself, and logs
//! what worked with the confinement report: a file inside the grant reads,
//! one outside doesn't, and `hold-profile` reads nothing at all. Every run
//! still does its work confined (the other profile tests run the same
//! binary). On Windows files aren't confined yet (0010's D4): there the
//! report says so, and only the inside reads are checked.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_freedom-cored");

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn run(args: &[&str], reads: &[&Path]) -> Output {
    let list = std::env::join_paths(reads).unwrap();
    Command::new(BIN)
        .args(args)
        .env("FREEDOM_CORED_TEST_PROFILE_CONFINED", list)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// The hook's line: the report's `files`, and whether each path read.
fn confined(output: &Output) -> (String, Vec<bool>) {
    let text = String::from_utf8_lossy(&output.stderr);
    let line = text
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|line| line["msg"] == "test: confined")
        .unwrap_or_else(|| panic!("no confinement: {output:?}"));
    let files = line["confinement"]["files"].as_str().unwrap().to_owned();
    let reads = line["reads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|read| read["ok"].as_bool().unwrap())
        .collect();
    (files, reads)
}

/// Files must be confined where the OS confines them.
fn confines_files() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}

/// The run read every path in `inside` and, where files are confined, none
/// in `outside`.
fn check(what: &str, output: &Output, inside: usize, outside: usize) {
    let (files, reads) = confined(output);
    assert_eq!(reads.len(), inside + outside, "{what}");
    assert!(
        reads[..inside].iter().all(|ok| *ok),
        "{what}: a read inside the grant failed: {output:?}"
    );
    if confines_files() {
        assert!(
            files == "enforced" || files == "partial",
            "{what}: files {files}"
        );
        assert!(
            reads[inside..].iter().all(|ok| !ok),
            "{what}: a read outside the grant worked: {output:?}"
        );
    } else {
        assert_eq!(files, "unavailable", "{what}");
    }
}

#[test]
fn each_subcommand_confined_reads_nothing_outside_its_grant() {
    let root = tempfile::tempdir().unwrap();
    let base: PathBuf = if cfg!(windows) {
        root.path().to_path_buf()
    } else {
        std::fs::canonicalize(root.path()).unwrap()
    };
    let app = base.join("app");
    let locks = base.join("locks");
    let elsewhere = base.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let secret = elsewhere.join("secret");
    std::fs::write(&secret, "secret").unwrap();
    // A sibling of the app root, and the user's other files.
    let sibling = base.join("app-other");
    std::fs::create_dir_all(&sibling).unwrap();
    std::fs::write(sibling.join("file"), "x").unwrap();
    let outside: [&Path; 3] = [&secret, &elsewhere, &sibling.join("file")];

    // The lock directory, as main's first `hold-lock` leaves it.
    std::fs::create_dir_all(&locks).unwrap();
    std::fs::write(locks.join("gate.lock"), "").unwrap();
    let a = s(&app);
    let l = s(&locks);
    // First, unhooked: the catalog and a profile `work`, with its lock
    // directory's gate file.
    for args in [
        vec!["profile", "open", "--app-root", a, "--lock-dir", l],
        vec![
            "profile",
            "open",
            "--app-root",
            a,
            "--lock-dir",
            l,
            "--profile",
            "work",
        ],
    ] {
        let out = Command::new(BIN).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{out:?}");
    }
    let catalog = app.join("profile-registry.json");
    let work = app.join("Profiles").join("work");
    let work_meta = work.join("profile.json");
    std::fs::create_dir_all(app.join("Profiles").join("leftover")).unwrap();

    let with = |inside: &[&Path]| -> Vec<PathBuf> {
        inside
            .iter()
            .chain(outside.iter())
            .map(|p| p.to_path_buf())
            .collect()
    };
    let cases: Vec<(&str, Vec<&str>, Vec<PathBuf>, usize)> = vec![
        (
            "open",
            vec!["profile", "open", "--app-root", a, "--lock-dir", l],
            with(&[&catalog, &locks]),
            2,
        ),
        (
            "list",
            vec!["profile", "list", "--app-root", a],
            with(&[&catalog]),
            1,
        ),
        (
            "create",
            vec![
                "profile",
                "create",
                "--app-root",
                a,
                "--display-name",
                "New",
            ],
            with(&[&catalog]),
            1,
        ),
        (
            "rename",
            vec![
                "profile",
                "rename",
                "--app-root",
                a,
                "--id",
                "work",
                "--display-name",
                "Work",
            ],
            with(&[&catalog]),
            1,
        ),
        (
            "import",
            vec!["profile", "import", "--app-root", a, "--id", "leftover"],
            with(&[&catalog]),
            1,
        ),
        (
            "update-nodes",
            vec![
                "profile",
                "update-nodes",
                "--app-root",
                a,
                "--id",
                "work",
                "--user-data-dir",
                s(&work),
                "--protocol",
                "bee",
                "--updates",
                "{}",
                "--metadata",
                "{}",
            ],
            with(&[&work_meta]),
            1,
        ),
        (
            "reserved-ports",
            vec!["profile", "reserved-ports", "--app-root", a],
            with(&[&catalog]),
            1,
        ),
        (
            "status",
            vec![
                "profile",
                "status",
                "--lock-dir",
                l,
                "--user-data-dir",
                s(&work),
            ],
            with(&[&work_meta, &locks]),
            2,
        ),
        (
            "forget-list",
            vec!["profile", "forget-list", "--app-root", a],
            with(&[&catalog]),
            1,
        ),
        (
            "forget-done",
            vec![
                "profile",
                "forget-done",
                "--app-root",
                a,
                "--item",
                "0123456789abcdef0123456789abcdef",
            ],
            with(&[&catalog]),
            1,
        ),
        (
            "migrate",
            vec![
                "profile",
                "migrate",
                "--profile-dir",
                s(&work),
                "--lock-dir",
                l,
                "--finish-only",
            ],
            with(&[&work_meta]),
            1,
        ),
        (
            "delete",
            vec![
                "profile",
                "delete",
                "--app-root",
                a,
                "--lock-dir",
                l,
                "--id",
                "leftover",
                "--confirm-display-name",
                "Leftover",
            ],
            with(&[&catalog]),
            1,
        ),
    ];
    for (what, args, reads, inside) in &cases {
        let reads: Vec<&Path> = reads.iter().map(PathBuf::as_path).collect();
        let out = run(args, &reads);
        assert_eq!(out.status.code(), Some(0), "{what}: {out:?}");
        check(what, &out, *inside, outside.len());
    }

    // `hold-profile`, once `locked`: nothing at all, its own profile's
    // files and the catalog included.
    let out = run(
        &[
            "hold-profile",
            "--user-data-dir",
            s(&work),
            "--lock-dir",
            l,
            "--app-root",
            a,
            "--id",
            "work",
        ],
        &with(&[]).iter().map(PathBuf::as_path).collect::<Vec<_>>(),
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "locked\n");
    check("hold-profile", &out, 0, outside.len());
    let out = run(
        &["hold-profile", "--user-data-dir", s(&work), "--lock-dir", l],
        &[&work_meta, &catalog],
    );
    check("hold-profile's own files", &out, 0, 2);
}
