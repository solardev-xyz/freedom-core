//! The one-shot import process through the real binary (design 0010,
//! "The Radicle import (D5)" and its Tests; design 0008, "Writes" and its
//! Tests' "Import"):
//! - a working copy outside the home imports after `rad.reconcile`, signed
//!   and seeded, the working copy untouched, its hooks not run and its
//!   `url.<base>.insteadOf` not applied; the process then exits, and the
//!   service serves the repository;
//! - `rad.import_repo` before `rad.reconcile` has succeeded is `stopped`
//!   and changes nothing; a second is refused; main's cancel before the
//!   start is `cancelled`, and past it changes nothing;
//! - each refusal before the start is definitive, and clears the marker;
//! - the roots: a linked worktree, a separate git directory, alternates;
//!   a root that is, contains or lies inside a protected one, and
//!   alternates too deep, are `unsupported_layout`;
//! - confinement: a file outside the roots isn't read, a symlink out of the
//!   source fails the import, and no socket opens;
//! - an unclean stop before admission is repaired first, and a
//!   reconciliation past its cutoff, or still running, imports nothing;
//! - a kill, the deadline (exit 70) or a panic during an import: the marker
//!   stays, no process is left, and the service's next start removes the
//!   temporary clone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::fixture;
use common::*;
use radicle::git::raw as git2;
use radicle::prelude::RepoId;
use radicle::storage::ValidateRepository as _;
use serde_json::{Value, json};

const NAME: &str = "imported";
const DESCRIPTION: &str = "An import process test.";

/// A working copy in a directory of its own, outside every grant.
struct Work {
    _dir: tempfile::TempDir,
    /// The directory holding it.
    root: PathBuf,
    /// The working copy.
    source: PathBuf,
    /// `master`'s tip.
    tip: git2::Oid,
}

/// A commit on `refs/heads/master` of `repo`, whose work tree is `dir`.
fn commit(repo: &git2::Repository, dir: &Path, text: &str) -> git2::Oid {
    std::fs::write(dir.join("README.md"), text).unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(Path::new("README.md")).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let signature = git2::Signature::now("Import", "import@example.invalid").unwrap();
    let parent = repo
        .refname_to_id("refs/heads/master")
        .ok()
        .map(|oid| repo.find_commit(oid).unwrap());
    repo.commit(
        Some("refs/heads/master"),
        &signature,
        &signature,
        text,
        &tree,
        &parent.iter().collect::<Vec<_>>(),
    )
    .unwrap()
}

/// A working copy with two commits on `master`, hooks that would leave
/// `hooked` beside it if they ran, and a `url.<base>.insteadOf` that would
/// send a fetch of it elsewhere if it applied.
fn working_copy() -> Work {
    let dir = tempfile::tempdir().unwrap();
    // As main names it: not canonical (on Windows, canonical is a verbatim
    // `\\?\` path).
    let root = dir.path().to_path_buf();
    let source = root.join("work");
    let repo = git2::Repository::init(&source).unwrap();
    commit(&repo, &source, "# One\n");
    let tip = commit(&repo, &source, "# Two\n");
    for hook in [
        "pre-push",
        "post-update",
        "reference-transaction",
        "pre-upload-pack",
    ] {
        let path = repo.path().join("hooks").join(hook);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            format!("#!/bin/sh\ntouch '{}'\n", root.join("hooked").display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    let gitdir = std::fs::canonicalize(repo.path()).unwrap();
    let mut config = repo.config().unwrap();
    config
        .set_str(
            &format!("url.{}.insteadOf", root.join("elsewhere").display()),
            gitdir.to_str().unwrap(),
        )
        .unwrap();
    Work {
        _dir: dir,
        root,
        source,
        tip,
    }
}

fn params(source: &Path) -> Value {
    json!({
        "path": source.to_str().unwrap(),
        "name": NAME,
        "description": DESCRIPTION,
        "default_branch": "master",
    })
}

/// Every file under `dir`, by its path, with its bytes.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(at) = stack.pop() {
        for entry in std::fs::read_dir(&at).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            } else {
                files.insert(
                    entry.path().strip_prefix(dir).unwrap().to_path_buf(),
                    std::fs::read(entry.path()).unwrap_or_default(),
                );
            }
        }
    }
    files
}

/// The entries of the home's storage, by name.
fn storage(dirs: &Dirs) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dirs.home.join("storage"))
        .map(|dir| {
            dir.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// A home ready for an import: `config.json` names the alias.
fn ready() -> Dirs {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    dirs
}

fn enforced(hello: &Value, property: &str) -> bool {
    hello["result"]["confinement"][property] == "enforced"
}

/// The imported repository `rid` holds `tip` in `NID`'s namespace and
/// canonically, every ref signed.
fn check_imported(dirs: &Dirs, rid: RepoId, tip: git2::Oid) {
    let repo =
        radicle::storage::git::Repository::open(fixture::storage_of(&dirs.home, rid), rid).unwrap();
    let ours = format!("refs/namespaces/{NID}/refs/heads/master");
    assert_eq!(repo.backend.refname_to_id(&ours).unwrap(), tip);
    assert_eq!(
        repo.backend.refname_to_id("refs/heads/master").unwrap(),
        tip
    );
    let validations = repo.validate().unwrap();
    assert!(validations.is_empty(), "{validations:?}");
}

/// The RID of a reply `{ rid }`, in the form main's bridge accepts.
fn rid_of(reply: &Value) -> RepoId {
    let rid = reply["result"]["rid"]
        .as_str()
        .unwrap_or_else(|| panic!("{reply}"));
    assert!(
        rid.starts_with("rad:z") && (25..=65).contains(&rid.len()),
        "{rid}"
    );
    rid.parse().unwrap()
}

/// Asserts the process refused the import with `code` (and `message`, if
/// given), then exited 0 with nothing imported and the marker cleared.
fn refused(radicled: &mut Radicled, dirs: &Dirs, reply: &Value, code: &str, message: Option<&str>) {
    assert_eq!(reply["error"]["code"], code, "{reply}");
    if let Some(message) = message {
        assert_eq!(reply["error"]["message"], message, "{reply}");
    }
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert!(storage(dirs).is_empty(), "{:?}", storage(dirs));
    assert_eq!(fixture::marked(&dirs.home), None);
}

#[test]
fn an_import_after_reconcile_is_signed_and_seeded_and_the_process_exits() {
    let dirs = ready();
    let work = working_copy();
    let before = snapshot(&work.root);
    let mut radicled = Radicled::import(&dirs, &work.source, &[], &[]);
    let hello = radicled.hello();
    // No network policy: the import process has none.
    assert_eq!(hello["result"]["network"], json!({ "mode": "offline" }));
    #[cfg(target_os = "linux")]
    if let Ok(abi) = fc_sys::linux::landlock_abi() {
        let confinement = &hello["result"]["confinement"];
        let files = if abi >= 2 { "enforced" } else { "unavailable" };
        assert_eq!(confinement["files"], files, "{confinement}");
        assert_eq!(confinement["network"], "enforced", "{confinement}");
        assert_eq!(confinement["exec"], "enforced", "{confinement}");
    }
    let identity = radicled.call("rad.identity", sealed_to(&hello, &SEED));
    assert!(identity["result"].is_object(), "{identity}");
    // Before `rad.reconcile`: `stopped`, nothing changes, the process goes
    // on.
    let early = radicled.call("rad.import_repo", params(&work.source));
    assert_eq!(early["error"]["code"], "stopped", "{early}");
    assert!(storage(&dirs).is_empty());
    let reconciled = radicled.call("rad.reconcile", json!({}));
    assert_eq!(reconciled["result"]["was_dirty"], false, "{reconciled}");
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));

    let reply = radicled.call("rad.import_repo", params(&work.source));
    let rid = rid_of(&reply);
    // libradicle's `json::rid` text, as the add-on's `importRepo` answers.
    assert_eq!(
        serde_json::to_string(&reply["result"]).unwrap(),
        format!("{{\"rid\":\"{rid}\"}}")
    );
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert!(radicled.stderr().contains("the import is proven"));
    assert_eq!(fixture::marked(&dirs.home), None);
    assert_eq!(storage(&dirs), [rid.canonical()]);
    check_imported(&dirs, rid, work.tip);
    // The working copy is as it was, and none of its hooks ran.
    assert_eq!(snapshot(&work.root), before);
    assert!(!work.root.join("hooked").exists());

    // The service, started again, serves it.
    let mut service = Radicled::serve(&dirs, &[]);
    let started = service.start();
    assert!(started["result"].is_object(), "{started}");
    let info = service.read("repo_info", json!({ "rid": rid.to_string() }));
    let info: Value = serde_json::from_slice(&info.unwrap()).unwrap();
    assert_eq!(info["name"], NAME, "{info}");
    assert_eq!(info["head"], work.tip.to_string(), "{info}");
    assert_eq!(
        info["delegates"],
        json!([format!("did:key:{NID}")]),
        "{info}"
    );
    service.shutdown();
    assert_eq!(service.exit_code(EXIT_TIMEOUT), Some(0));
}

#[test]
fn a_second_import_is_refused_and_a_cancel_past_the_start_changes_nothing() {
    let dirs = ready();
    let work = working_copy();
    let (hold, release) = dirs.held("start@until", "release");
    let mut radicled = Radicled::import(
        &dirs,
        &work.source,
        &[],
        &[("FREEDOM_RADICLED_TEST_HOLD_IMPORT", hold.as_str())],
    );
    radicled.reconciled();
    let first = radicled.request("rad.import_repo", params(&work.source));
    assert!(radicled.logs("test hook: the import holds at a stage", READ_TIMEOUT));
    let second = radicled.call("rad.import_repo", params(&work.source));
    assert_eq!(second["error"]["code"], "invalid_argument", "{second}");
    assert_eq!(
        second["error"]["message"],
        "rad.import_repo was already called"
    );
    // Past its start, main's cancel queues nothing: the import answers.
    radicled.cancel(first);
    std::fs::write(&release, "").unwrap();
    let reply = radicled.reply(first);
    rid_of(&reply);
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert_eq!(fixture::marked(&dirs.home), None);
}

#[test]
fn a_cancel_before_the_start_imports_nothing() {
    let dirs = ready();
    let work = working_copy();
    let (hold, release) = dirs.held("admitted@until", "release");
    let mut radicled = Radicled::import(
        &dirs,
        &work.source,
        &[],
        &[("FREEDOM_RADICLED_TEST_HOLD_IMPORT", hold.as_str())],
    );
    radicled.reconciled();
    let id = radicled.request("rad.import_repo", params(&work.source));
    assert!(radicled.logs("test hook: the import holds at a stage", READ_TIMEOUT));
    radicled.cancel(id);
    let reply = radicled.reply(id);
    std::fs::write(&release, "").unwrap();
    refused(&mut radicled, &dirs, &reply, "cancelled", None);
    assert!(!radicled.stderr().contains("the import has started"));
}

#[test]
fn refusals_before_the_start_are_definitive() {
    let work = working_copy();
    let source = work.source.to_str().unwrap();
    let cases: [(Value, &str, Option<&str>); 5] = [
        (
            json!({ "path": source }),
            "invalid_argument",
            Some("rad.import_repo takes { path, name, description, default_branch }"),
        ),
        (
            json!({ "path": format!("{source}/"), "name": NAME, "description": "", "default_branch": "master" }),
            "invalid_argument",
            Some("path isn't the --source this import process was started with"),
        ),
        (
            json!({ "path": source, "name": NAME, "description": "", "default_branch": "trunk" }),
            "invalid_argument",
            Some("the working copy has no branch trunk"),
        ),
        (
            json!({ "path": source, "name": "", "description": "", "default_branch": "master" }),
            "invalid_argument",
            None,
        ),
        (
            json!({ "path": source, "name": NAME, "description": "", "default_branch": "master", "extra": 1 }),
            "invalid_argument",
            None,
        ),
    ];
    for (params, code, message) in cases {
        let dirs = ready();
        let mut radicled = Radicled::import(&dirs, &work.source, &[], &[]);
        radicled.reconciled();
        let reply = radicled.call("rad.import_repo", params);
        refused(&mut radicled, &dirs, &reply, code, message);
    }

    // A throwaway key: `needs_vault`.
    let dirs = ready();
    let mut radicled = Radicled::import(&dirs, &work.source, &[], &[]);
    radicled.hello();
    let identity = radicled.call("rad.identity", json!({ "ephemeral": true }));
    assert!(identity["result"].is_object(), "{identity}");
    let reconciled = radicled.call("rad.reconcile", json!({}));
    assert!(reconciled["result"].is_object(), "{reconciled}");
    let reply = radicled.call("rad.import_repo", self::params(&work.source));
    refused(&mut radicled, &dirs, &reply, "needs_vault", None);

    // Not a repository: libgit2's open, by today's message test.
    let empty = tempfile::tempdir().unwrap();
    let dirs = ready();
    let mut radicled = Radicled::import(&dirs, empty.path(), &[], &[]);
    radicled.reconciled();
    let reply = radicled.call("rad.import_repo", self::params(empty.path()));
    refused(&mut radicled, &dirs, &reply, "not_found", None);

    // A repository already in storage: `failed`, with libradicle's text,
    // which names it.
    let dirs = ready();
    let mut radicled = Radicled::import(&dirs, &work.source, &[], &[]);
    radicled.reconciled();
    let rid = rid_of(&radicled.call("rad.import_repo", self::params(&work.source)));
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let mut radicled = Radicled::import(&dirs, &work.source, &[], &[]);
    radicled.reconciled();
    let reply = radicled.call("rad.import_repo", self::params(&work.source));
    assert_eq!(reply["error"]["code"], "failed", "{reply}");
    assert_eq!(
        reply["error"]["message"],
        format!("{rid} already exists in storage")
    );
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert_eq!(storage(&dirs), [rid.canonical()]);
    assert_eq!(fixture::marked(&dirs.home), None);
}

/// Imports `source` through a process, and returns the home, the reply
/// and the log's line for the import's admission (its roots, or why
/// none).
fn import_layout(source: &Path, protected: &[&Path]) -> (Dirs, Value, Value) {
    let (dirs, _, reply, admitted) = import_confined(source, protected);
    (dirs, reply, admitted)
}

/// [`import_layout`], with `rad.hello`'s reply.
fn import_confined(source: &Path, protected: &[&Path]) -> (Dirs, Value, Value, Value) {
    let dirs = ready();
    let mut radicled = Radicled::import(&dirs, source, protected, &[]);
    let (hello, _) = radicled.reconciled();
    let reply = radicled.call("rad.import_repo", params(source));
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    let line = log
        .lines()
        .find(|line| line.contains("the import is admitted"))
        .unwrap_or_else(|| panic!("{log}"));
    (dirs, hello, reply, serde_json::from_str(line).unwrap())
}

#[test]
fn the_roots_grant_a_linked_worktree_a_separate_git_directory_and_alternates() {
    // A linked worktree: its git directory in the main repository's, and
    // that repository's common directory.
    let work = working_copy();
    let linked = work.root.join("linked");
    git2::Repository::open(&work.source)
        .unwrap()
        .worktree("linked", &linked, None)
        .unwrap();
    let (dirs, reply, admitted) = import_layout(&linked, &[]);
    check_imported(&dirs, rid_of(&reply), work.tip);
    assert_eq!(admitted["roots"], 2, "{admitted}");

    // A separate git directory, which a `.git` file names.
    let work = working_copy();
    let gitdir = work.root.join("elsewhere.git");
    std::fs::rename(work.source.join(".git"), &gitdir).unwrap();
    std::fs::write(
        work.source.join(".git"),
        format!("gitdir: {}\n", gitdir.display()),
    )
    .unwrap();
    let (dirs, reply, admitted) = import_layout(&work.source, &[]);
    check_imported(&dirs, rid_of(&reply), work.tip);
    assert_eq!(admitted["roots"], 2, "{admitted}");

    // Alternates: the commits live only in another repository's objects.
    let work = working_copy();
    let borrower = work.root.join("borrower");
    let repo = git2::Repository::init(&borrower).unwrap();
    let info = repo.path().join("objects").join("info");
    std::fs::create_dir_all(&info).unwrap();
    std::fs::write(
        info.join("alternates"),
        format!("{}\n", work.source.join(".git").join("objects").display()),
    )
    .unwrap();
    repo.reference("refs/heads/master", work.tip, true, "borrowed")
        .unwrap();
    let (dirs, reply, admitted) = import_layout(&borrower, &[]);
    check_imported(&dirs, rid_of(&reply), work.tip);
    assert_eq!(admitted["roots"], 2, "{admitted}");
}

#[test]
fn layouts_that_cant_be_granted_are_unsupported() {
    // A protected root inside the source, existing or not yet.
    let work = working_copy();
    for inner in [
        work.source.join("README.md"),
        work.source.join("future/dir"),
    ] {
        let (dirs, reply, _) = import_layout(&work.source, &[&inner]);
        assert_eq!(reply["error"]["code"], "unsupported_layout", "{reply}");
        assert!(storage(&dirs).is_empty());
    }
    // A source inside a protected root.
    let (_, reply, _) = import_layout(&work.source, &[&work.root]);
    assert_eq!(reply["error"]["code"], "unsupported_layout", "{reply}");
    // A source that holds the home, which holds Freedom's data.
    let dirs = ready();
    let holder = dirs.home.parent().unwrap().to_path_buf();
    let mut radicled = Radicled::import(&dirs, &holder, &[], &[]);
    radicled.reconciled();
    let reply = radicled.call("rad.import_repo", params(&holder));
    assert_eq!(reply["error"]["code"], "unsupported_layout", "{reply}");
    assert_eq!(
        reply["error"]["message"],
        "the repository is, contains, or lies inside a directory of Freedom's own"
    );
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert_eq!(fixture::marked(&dirs.home), None);
    // Alternates nested deeper than libgit2 reads them.
    let work = working_copy();
    let mut objects = work.source.join(".git").join("objects");
    for n in 0..7 {
        let next = work.root.join(format!("a{n}"));
        std::fs::create_dir_all(next.join("info")).unwrap();
        std::fs::create_dir_all(objects.join("info")).unwrap();
        std::fs::write(
            objects.join("info").join("alternates"),
            format!("{}\n", next.display()),
        )
        .unwrap();
        objects = next;
    }
    let (_, reply, admitted) = import_layout(&work.source, &[]);
    assert_eq!(reply["error"]["code"], "unsupported_layout", "{reply}");
    assert!(
        admitted["unsupported"]
            .as_str()
            .unwrap()
            .contains("nested deeper"),
        "{admitted}"
    );
}

/// Runs an import of `work` with `extra`, and returns `rad.hello`'s reply,
/// the import's reply and the process's log.
fn probed(work: &Work, extra: &[(&str, &str)]) -> (Value, Value, String) {
    let dirs = ready();
    let mut radicled = Radicled::import(&dirs, &work.source, &[], extra);
    let (hello, _) = radicled.reconciled();
    let reply = radicled.call("rad.import_repo", params(&work.source));
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    (hello, reply, radicled.stderr())
}

/// The outcome of the probe `probe` in `log`.
fn probe(log: &str, probe: &str) -> String {
    log.lines()
        .filter(|line| line.contains("test hook: probe"))
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|line| line["probe"] == probe)
        .unwrap_or_else(|| panic!("no {probe} probe in {log}"))["outcome"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn confinement_reads_the_roots_alone_and_opens_no_socket() {
    // A file beside the working copy, outside every root, and one inside it.
    let work = working_copy();
    let outside = work.root.join("canary");
    std::fs::write(&outside, "canary").unwrap();
    let path = outside.to_str().unwrap();
    let (hello, reply, log) = probed(&work, &[("FREEDOM_RADICLED_TEST_PROBE_READ", path)]);
    rid_of(&reply);
    if enforced(&hello, "files") {
        assert_ne!(probe(&log, "read"), "ok", "{log}");
    }
    let inside = work.source.join("README.md");
    let path = inside.to_str().unwrap();
    let (_, reply, log) = probed(&work, &[("FREEDOM_RADICLED_TEST_PROBE_READ", path)]);
    rid_of(&reply);
    assert_eq!(probe(&log, "read"), "ok", "{log}");

    // No socket: a TCP listener and a Unix one, canaries, see nothing.
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    tcp.set_nonblocking(true).unwrap();
    let addr = tcp.local_addr().unwrap().to_string();
    #[cfg(unix)]
    let socket_dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let unix = {
        let listener =
            std::os::unix::net::UnixListener::bind(socket_dir.path().join("canary.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        listener
    };
    #[cfg(unix)]
    let socket = socket_dir.path().join("canary.sock");
    let mut extra = vec![("FREEDOM_RADICLED_TEST_PROBE_DIAL", addr.as_str())];
    #[cfg(unix)]
    extra.push(("FREEDOM_RADICLED_TEST_PROBE_UNIX", socket.to_str().unwrap()));
    let (hello, reply, log) = probed(&work, &extra);
    rid_of(&reply);
    if enforced(&hello, "network") {
        assert_ne!(probe(&log, "dial"), "ok", "{log}");
        assert!(tcp.accept().is_err());
    }
    #[cfg(unix)]
    if enforced(&hello, "ipc") {
        assert_ne!(probe(&log, "unix"), "ok", "{log}");
        assert!(unix.accept().is_err());
    }
}

/// A symlink out of the source: the git directory's configuration is a
/// link to a file outside every root. Confined, its open fails before the
/// start, and nothing is imported.
#[cfg(unix)]
#[test]
fn a_symlink_out_of_the_source_fails_the_import_before_its_start() {
    let work = working_copy();
    let config = work.source.join(".git").join("config");
    let moved = work.root.join("config-outside");
    std::fs::rename(&config, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &config).unwrap();
    let (dirs, hello, reply, _) = import_confined(&work.source, &[]);
    if enforced(&hello, "files") {
        let code = reply["error"]["code"].as_str().unwrap_or_default();
        assert!(code == "failed" || code == "not_found", "{reply}");
        assert!(storage(&dirs).is_empty());
        assert_eq!(fixture::marked(&dirs.home), None);
    } else {
        rid_of(&reply);
    }
}

#[test]
fn an_unclean_stop_before_admission_is_repaired_first() {
    // A write past its start and a fetch, cut off at the stop's 5 s exit:
    // an unsigned ref, a ref lock file and the marker.
    let dirs = Dirs::new();
    let rid = fixture::repository(&dirs.home, &SEED, "unclean");
    fixture::unsigned_ref(&dirs.home, rid, NID);
    let lock = fixture::storage_of(&dirs.home, rid)
        .join("refs")
        .join("heads")
        .join("master.lock");
    std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
    std::fs::write(&lock, "").unwrap();
    fixture::mark(&dirs.home, &[NID]);

    let work = working_copy();
    let mut radicled = Radicled::import(&dirs, &work.source, &[], &[]);
    let (_, reconciled) = radicled.reconciled();
    let repaired = &reconciled["result"]["repaired"];
    assert_eq!(reconciled["result"]["was_dirty"], true, "{reconciled}");
    assert_eq!(repaired["locks"], 1, "{reconciled}");
    assert_eq!(repaired["resigned"], 1, "{reconciled}");
    assert!(!lock.exists());
    let reply = radicled.call("rad.import_repo", params(&work.source));
    let imported = rid_of(&reply);
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    check_imported(&dirs, imported, work.tip);
    assert_eq!(fixture::marked(&dirs.home), None);
}

#[test]
fn an_unfinished_or_cut_off_reconciliation_imports_nothing() {
    // Past its cutoff: `deadline`, and the process ends.
    let dirs = Dirs::new();
    let rid = fixture::repository(&dirs.home, &SEED, "cutoff");
    fixture::mark(&dirs.home, &[NID]);
    let work = working_copy();
    let mut radicled = Radicled::import(
        &dirs,
        &work.source,
        &[],
        &[("FREEDOM_RADICLED_TEST_RECONCILE_CUTOFF_MS", "0")],
    );
    let hello = radicled.hello();
    radicled.call("rad.identity", sealed_to(&hello, &SEED));
    let reply = radicled.call("rad.reconcile", json!({}));
    assert_eq!(reply["error"]["code"], "deadline", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert_eq!(storage(&dirs), [rid.canonical()]);
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));

    // Still running, its unit hung: `rad.import_repo` is `stopped`, and the
    // unit's overrun ends the process (70) with nothing imported.
    let dirs = Dirs::new();
    let rid = fixture::repository(&dirs.home, &SEED, "hung");
    fixture::mark(&dirs.home, &[NID]);
    let mut radicled = Radicled::import(
        &dirs,
        &work.source,
        &[],
        &[
            ("FREEDOM_RADICLED_TEST_HANG_UNIT", "ref-locks"),
            ("FREEDOM_RADICLED_TEST_UNIT_LIMIT_MS", "3000"),
        ],
    );
    let hello = radicled.hello();
    radicled.call("rad.identity", sealed_to(&hello, &SEED));
    let reconcile = radicled.request("rad.reconcile", json!({}));
    let early = radicled.call("rad.import_repo", params(&work.source));
    assert_eq!(early["error"]["code"], "stopped", "{early}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(70));
    let _ = reconcile;
    assert_eq!(storage(&dirs), [rid.canonical()]);
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
}

/// The tasks' children of process `pid`: none, as the import starts no
/// process.
#[cfg(target_os = "linux")]
fn children(pid: u32) -> Vec<String> {
    let mut found = Vec::new();
    for task in std::fs::read_dir(format!("/proc/{pid}/task")).unwrap() {
        let path = task.unwrap().path().join("children");
        let text = std::fs::read_to_string(path).unwrap_or_default();
        found.extend(text.split_whitespace().map(str::to_owned));
    }
    found
}

/// The service's start on `dirs` after a cut-off import: reconciliation
/// finds the marker and removes the temporary clone; the repository isn't
/// in storage.
fn restart_removes_the_clone(dirs: &Dirs) {
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
    let clones: Vec<String> = storage(dirs)
        .into_iter()
        .filter(|name| name.ends_with(".tmp"))
        .collect();
    assert_eq!(clones.len(), 1, "{:?}", storage(dirs));
    let mut service = Radicled::serve(dirs, &[]);
    let hello = service.hello();
    service.call("rad.identity", sealed_to(&hello, &SEED));
    let reconciled = service.call("rad.reconcile", json!({}));
    assert_eq!(reconciled["result"]["was_dirty"], true, "{reconciled}");
    assert_eq!(
        reconciled["result"]["repaired"]["clones"], 1,
        "{reconciled}"
    );
    assert!(storage(dirs).is_empty(), "{:?}", storage(dirs));
    let started = service.call("rad.start", json!({ "alias": "restarted" }));
    assert!(started["result"].is_object(), "{started}");
    service.shutdown();
    assert_eq!(service.exit_code(EXIT_TIMEOUT), Some(0));
    assert_eq!(fixture::marked(&dirs.home), None);
}

#[test]
fn a_kill_during_an_import_leaves_its_clone_to_the_next_start() {
    let dirs = ready();
    let work = working_copy();
    let (hold, _release) = dirs.held("signed@until", "never");
    let mut radicled = Radicled::import(
        &dirs,
        &work.source,
        &[],
        &[("FREEDOM_RADICLED_TEST_HOLD_IMPORT", hold.as_str())],
    );
    radicled.reconciled();
    radicled.request("rad.import_repo", params(&work.source));
    assert!(radicled.logs("test hook: the import holds at a stage", READ_TIMEOUT));
    // No child process, during the import.
    #[cfg(target_os = "linux")]
    assert_eq!(children(radicled.child.id()), Vec::<String>::new());
    radicled.child.kill().unwrap();
    radicled.child.wait().unwrap();
    restart_removes_the_clone(&dirs);
}

#[test]
fn the_imports_deadline_ends_the_process_with_70() {
    let dirs = ready();
    let work = working_copy();
    let (hold, _release) = dirs.held("fetched@until", "never");
    let mut radicled = Radicled::import(
        &dirs,
        &work.source,
        &[],
        &[
            ("FREEDOM_RADICLED_TEST_HOLD_IMPORT", hold.as_str()),
            ("FREEDOM_RADICLED_TEST_IMPORT_LIMIT_MS", "1500"),
        ],
    );
    radicled.reconciled();
    radicled.request("rad.import_repo", params(&work.source));
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(70));
    assert!(radicled.stderr().contains("import_deadline"));
    restart_removes_the_clone(&dirs);
}

#[test]
fn libradicles_error_past_the_start_is_outcome_unknown() {
    let dirs = ready();
    let work = working_copy();
    let (hold, release) = dirs.held("created@until", "release");
    let mut radicled = Radicled::import(
        &dirs,
        &work.source,
        &[],
        &[("FREEDOM_RADICLED_TEST_HOLD_IMPORT", hold.as_str())],
    );
    radicled.reconciled();
    let id = radicled.request("rad.import_repo", params(&work.source));
    assert!(radicled.logs("test hook: the import holds at a stage", READ_TIMEOUT));
    // The branch goes from the working copy before the fetch: libradicle's
    // run fails past the start, and removes its temporary clone.
    git2::Repository::open(&work.source)
        .unwrap()
        .find_reference("refs/heads/master")
        .unwrap()
        .delete()
        .unwrap();
    std::fs::write(&release, "").unwrap();
    let reply = radicled.reply(id);
    assert_eq!(reply["error"]["code"], "outcome_unknown", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert!(storage(&dirs).is_empty(), "{:?}", storage(&dirs));
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
    let mut service = Radicled::serve(&dirs, &[]);
    let hello = service.hello();
    service.call("rad.identity", sealed_to(&hello, &SEED));
    let reconciled = service.call("rad.reconcile", json!({}));
    assert_eq!(reconciled["result"]["was_dirty"], true, "{reconciled}");
}

#[test]
fn a_panic_past_the_start_is_outcome_unknown() {
    let dirs = ready();
    let work = working_copy();
    let mut radicled = Radicled::import(
        &dirs,
        &work.source,
        &[],
        &[("FREEDOM_RADICLED_TEST_HOLD_IMPORT", "seeded@panic")],
    );
    radicled.reconciled();
    let reply = radicled.call("rad.import_repo", params(&work.source));
    assert_eq!(reply["error"]["code"], "outcome_unknown", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    restart_removes_the_clone(&dirs);
}

#[test]
fn the_connections_end_before_the_start_imports_nothing() {
    let dirs = ready();
    let work = working_copy();
    let (hold, release) = dirs.held("admitted@until", "release");
    let (hold_end, ended) = dirs.held("until", "ended");
    let mut radicled = Radicled::import(
        &dirs,
        &work.source,
        &[],
        &[
            ("FREEDOM_RADICLED_TEST_HOLD_IMPORT", hold.as_str()),
            ("FREEDOM_RADICLED_TEST_HOLD_END", hold_end.as_str()),
        ],
    );
    radicled.reconciled();
    radicled.request("rad.import_repo", params(&work.source));
    assert!(radicled.logs("test hook: the import holds at a stage", READ_TIMEOUT));
    radicled.shutdown();
    // The end has closed the start; the process lives on while the import's
    // thread meets it: `stopped`, and nothing starts.
    assert!(radicled.logs("test hook: the end holds", READ_TIMEOUT));
    std::fs::write(&release, "").unwrap();
    assert!(radicled.logs("the import is answered", READ_TIMEOUT));
    std::fs::write(&ended, "").unwrap();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(!log.contains("the import has started"), "{log}");
    assert!(log.contains(r#""code":"stopped""#), "{log}");
    assert!(storage(&dirs).is_empty(), "{:?}", storage(&dirs));
    assert_eq!(fixture::marked(&dirs.home), None);
}

#[test]
fn the_connections_end_past_the_start_leaves_the_marker() {
    let dirs = ready();
    let work = working_copy();
    let (hold, _release) = dirs.held("created@until", "never");
    let mut radicled = Radicled::import(
        &dirs,
        &work.source,
        &[],
        &[("FREEDOM_RADICLED_TEST_HOLD_IMPORT", hold.as_str())],
    );
    radicled.reconciled();
    radicled.request("rad.import_repo", params(&work.source));
    assert!(radicled.logs("test hook: the import holds at a stage", READ_TIMEOUT));
    radicled.shutdown();
    // The connection's 5 s exit ends the process, and the import with it.
    assert!(radicled.exit_code(EXIT_TIMEOUT).is_some());
    assert!(radicled.stderr().contains("the dirty marker stays"));
    restart_removes_the_clone(&dirs);
}

#[test]
fn other_methods_are_unknown_to_the_import_process() {
    let dirs = ready();
    let work = working_copy();
    let mut radicled = Radicled::import(&dirs, &work.source, &[], &[]);
    radicled.reconciled();
    for method in ["rad.start", "rad.read", "rad.write", "rad.clone"] {
        let reply = radicled.call(method, json!({}));
        assert_eq!(reply["error"]["code"], "unknown_method", "{reply}");
    }
    radicled.shutdown();
    assert_eq!(radicled.exit_code(Duration::from_secs(15)), Some(0));
    // No import started: the home is as reconciliation left it.
    assert_eq!(fixture::marked(&dirs.home), None);
}
