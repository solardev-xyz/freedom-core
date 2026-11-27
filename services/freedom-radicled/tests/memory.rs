//! The memory cap's fail-stop through the real binary (design 0008, Tests:
//! "the memory cap's fail-stop"; design 0010, Tests, "The memory cap", its
//! third and fourth bullets). Each case runs in a process of its own, the
//! service's or the import process's, with the cap lowered by a test hook
//! (`FREEDOM_RADICLED_TEST_MEMORY_CAP`) to a few hundred MiB, above what
//! the process holds: the test process's own limits are never touched.
//! - **A Rust allocation** past the cap aborts the process, and its request
//!   isn't answered (Linux and Windows: macOS has no cap).
//! - **A libgit2 inflate** past it, of a large object in the working copy
//!   the import process fetches, ends the process with 71 through
//!   libradicle's allocator hook, and the import isn't answered: main makes
//!   that `outcome_unknown`. The marker stays (Linux and Windows).
//! - **A pack mapped read-only,** larger than the cap, doesn't trip it: the
//!   import reads every object from a working copy's pack that a sparse
//!   hole makes larger than the cap, and is proven (Linux).
//! - **The backstop:** an out-of-memory error that reaches the service
//!   anyway (libgit2's `GIT_ERROR_NOMEMORY`, as zlib's comes back from a
//!   stream) ends it with 71, unanswered, while `GIT_ERROR_ZLIB`, as a
//!   corrupt object's inflate comes back, is the read's `failed` (every OS).
//! - **The backstop with the heap exhausted:** under the lowered cap, with
//!   every block the allocator would still give taken, the backstop still
//!   ends the process with 71 and its fixed line: it allocates nothing
//!   (Linux and Windows).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use common::fixture;
use common::*;
use radicle::git::raw as git2;
use serde_json::{Value, json};

/// The lowered cap: 256 MiB, well above what a process holds before its
/// test's allocation, and below each allocation or map under test.
#[cfg(any(target_os = "linux", windows))]
const CAP: u64 = 256 << 20;

/// What the Rust allocation and the large object each ask for: twice the
/// cap.
#[cfg(any(target_os = "linux", windows))]
const PAST_CAP: u64 = 512 << 20;

/// libradicle's line as its libgit2 hook ends the process.
#[cfg(any(target_os = "linux", windows))]
const LIBGIT2_OUT_OF_MEMORY: &str = "libradicle: libgit2 is out of memory: exit 71 (out_of_memory)";

/// The service's line as its backstop ends the process ([`crate::oom`]).
const BACKSTOP: &str = "out of memory: the process ends";

/// That line, whole, as the backstop writes it, fixed.
#[cfg(any(target_os = "linux", windows))]
const BACKSTOP_LINE: &str =
    r#"{"level":"error","msg":"out of memory: the process ends","reason":"out_of_memory"}"#;

/// A working copy in a directory of its own, outside every grant, with one
/// commit on `master`.
struct Work {
    _dir: tempfile::TempDir,
    source: PathBuf,
    repo: git2::Repository,
}

/// What writes a blob into a working copy, and gives its ID.
type Blob<'a> = &'a dyn Fn(&git2::Repository) -> git2::Oid;

/// A working copy whose one commit's tree holds `entries`, each a name and
/// what writes its blob.
fn working_copy(entries: &[(&str, Blob<'_>)]) -> Work {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("work");
    let repo = git2::Repository::init(&source).unwrap();
    {
        let mut tree = repo.treebuilder(None).unwrap();
        for (name, blob) in entries {
            tree.insert(name, blob(&repo), 0o100_644).unwrap();
        }
        let tree = repo.find_tree(tree.write().unwrap()).unwrap();
        let signature = git2::Signature::now("Memory", "memory@example.invalid").unwrap();
        repo.commit(
            Some("refs/heads/master"),
            &signature,
            &signature,
            "the memory cap",
            &tree,
            &[],
        )
        .unwrap();
    }
    Work {
        _dir: dir,
        source,
        repo,
    }
}

/// A blob of `size` zero bytes, written as a loose object in pieces: the
/// test process never holds it, and zlib makes it a few hundred KiB.
#[cfg(any(target_os = "linux", windows))]
fn zeros(repo: &git2::Repository, size: u64) -> git2::Oid {
    use std::io::Write as _;
    let odb = repo.odb().unwrap();
    let mut writer = odb
        .writer(usize::try_from(size).unwrap(), git2::ObjectType::Blob)
        .unwrap();
    let piece = vec![0u8; 1 << 20];
    let mut left = size;
    while left > 0 {
        let n = left.min(piece.len() as u64);
        writer.write_all(&piece[..n as usize]).unwrap();
        left -= n;
    }
    writer.finalize().unwrap()
}

fn readme(repo: &git2::Repository) -> git2::Oid {
    repo.blob(b"# The memory cap\n").unwrap()
}

fn params(source: &std::path::Path) -> Value {
    json!({
        "path": source.to_str().unwrap(),
        "name": "capped",
        "description": "A memory cap test.",
        "default_branch": "master",
    })
}

/// A home ready for an import or a start: `config.json` names the alias.
fn ready() -> Dirs {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    dirs
}

/// The process's exit status, once it has exited, and its stderr.
fn ended(radicled: &mut Radicled) -> (ExitStatus, String) {
    let until = Instant::now() + EXIT_TIMEOUT;
    let status = loop {
        if let Some(status) = radicled.child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= until {
            let (_, log) = radicled.exit_and_stderr(Duration::ZERO);
            panic!("freedom-radicled didn't exit; its stderr:\n{log}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    (status, radicled.stderr())
}

/// Whether `log` holds Rust's allocation-failure message for `bytes`. The
/// allocator writes it in three pieces, "memory allocation of ", the size
/// and " bytes failed", each its own write, and the service's log writer
/// can land whole lines between any two (CI has shown both: "memory
/// allocation of 536870912{...}\n bytes failed" and "memory allocation of
/// {...}\n536870912 bytes failed"). Each log line is one write of a JSON
/// object and its newline, so after the first piece, whole lines at the
/// start are skipped before each of the others.
#[cfg(any(target_os = "linux", windows))]
fn allocation_failed(log: &str, bytes: u64) -> bool {
    const HEAD: &str = "memory allocation of ";
    let size = bytes.to_string();
    log.match_indices(HEAD).any(|(at, _)| {
        past_log_lines(&log[at + HEAD.len()..])
            .strip_prefix(size.as_str())
            .map(past_log_lines)
            .is_some_and(|rest| rest.starts_with(" bytes failed"))
    })
}

/// `text` past the whole log lines at its start.
#[cfg(any(target_os = "linux", windows))]
fn past_log_lines(mut text: &str) -> &str {
    while text.starts_with('{') {
        match text.find('\n') {
            Some(end) => text = &text[end + 1..],
            None => break,
        }
    }
    text
}

/// The message read through whole log lines at each of its two seams, as
/// CI has shown them, and nothing else read as it.
#[cfg(any(target_os = "linux", windows))]
#[test]
fn the_allocation_message_is_read_through_log_lines() {
    let line = "{\"bytes\":512,\"level\":\"info\",\"msg\":\"test hook: an allocation\"}\n";
    for log in [
        "memory allocation of 512 bytes failed\n".to_owned(),
        format!("memory allocation of 512{line} bytes failed\n"),
        format!("memory allocation of {line}512 bytes failed\n"),
        format!("{line}memory allocation of {line}{line}512{line} bytes failed\n"),
    ] {
        assert!(allocation_failed(&log, 512), "{log}");
    }
    for log in [
        "memory allocation of 5120 bytes failed\n".to_owned(),
        "memory allocation of 51 bytes failed\n".to_owned(),
        format!("memory allocation of {line} bytes failed\n"),
        format!("{line}512 bytes failed\n"),
        format!("memory allocation of x{line}512 bytes failed\n"),
    ] {
        assert!(!allocation_failed(&log, 512), "{log}");
    }
}

/// Whether `status` is `std::process::abort`'s: `SIGABRT` on Unix, and
/// `__fastfail`'s status (or the CRT's 3) on Windows.
#[cfg(any(target_os = "linux", windows))]
fn aborted(status: &ExitStatus) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        status.signal() == Some(libc::SIGABRT)
    }
    #[cfg(windows)]
    {
        matches!(status.code(), Some(c) if c as u32 == 0xC000_0409 || c == 3)
    }
}

/// `rad.hello`'s report holds the lowered cap, read back.
#[cfg(any(target_os = "linux", windows))]
fn assert_capped(hello: &Value) {
    let confinement = &hello["result"]["confinement"];
    assert_eq!(confinement["memory_cap"], CAP, "{confinement}");
}

/// A Rust allocation past the cap aborts the process: Rust's allocator
/// fails stop by itself. `rad.identity`, whose handler made it, isn't
/// answered.
#[cfg(any(target_os = "linux", windows))]
#[test]
fn a_rust_allocation_past_the_cap_aborts_the_process() {
    let dirs = Dirs::new();
    let (cap, past) = (CAP.to_string(), PAST_CAP.to_string());
    let mut radicled = Radicled::serve(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_MEMORY_CAP", cap.as_str()),
            ("FREEDOM_RADICLED_TEST_ALLOCATE", past.as_str()),
        ],
    );
    let hello = radicled.hello();
    assert_capped(&hello);
    let id = radicled.request("rad.identity", json!({ "ephemeral": true }));
    let (status, log) = ended(&mut radicled);
    assert!(aborted(&status), "{status:?}\n{log}");
    assert!(allocation_failed(&log, PAST_CAP), "{log}");
    // The hook's own lines go through the log's queue, which the abort
    // cuts off: only one written after the allocation would prove it made.
    assert!(!log.contains("the allocation was made"), "{log}");
    assert!(!radicled.any_within(id, Duration::from_millis(200)));
}

/// A libgit2 allocation past the cap ends the process with 71: the import
/// process's fetch inflates a 512 MiB object of the working copy, whose
/// buffer libgit2 can't get. The import, past its start, isn't answered:
/// main makes it `outcome_unknown`. Its marker stays for the service's
/// next start.
#[cfg(any(target_os = "linux", windows))]
#[test]
fn a_libgit2_inflate_past_the_cap_exits_71_unanswered() {
    let dirs = ready();
    let work = working_copy(&[
        ("README.md", &readme),
        ("zeros", &|repo: &git2::Repository| zeros(repo, PAST_CAP)),
    ]);
    let cap = CAP.to_string();
    let mut radicled = Radicled::import(
        &dirs,
        &work.source,
        &[],
        &[("FREEDOM_RADICLED_TEST_MEMORY_CAP", cap.as_str())],
    );
    let (hello, _) = radicled.reconciled();
    assert_capped(&hello);
    let id = radicled.request("rad.import_repo", params(&work.source));
    let (status, log) = ended(&mut radicled);
    assert_eq!(status.code(), Some(71), "{log}");
    assert!(log.contains("the import has started"), "{log}");
    assert!(log.contains(LIBGIT2_OUT_OF_MEMORY), "{log}");
    assert!(!log.contains("the import is answered"), "{log}");
    assert!(!radicled.any_within(id, Duration::from_millis(200)));
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
}

/// A pack of the working copy's, which a sparse hole before its trailer
/// makes `size` bytes, its loose objects removed: libgit2 maps a window of
/// it whole, up to its 1 GiB, read-only and shared, when the fetch reads
/// any object. The trailer stays the pack's own, which libgit2 compares
/// with its index's.
#[cfg(target_os = "linux")]
fn sparse_pack(work: &Work, size: u64) {
    use std::io::{Seek as _, SeekFrom, Write as _};
    let objects = work.repo.path().join("objects");
    let packs = objects.join("pack");
    let mut builder = work.repo.packbuilder().unwrap();
    let mut walk = work.repo.revwalk().unwrap();
    walk.push_ref("refs/heads/master").unwrap();
    builder.insert_walk(&mut walk).unwrap();
    builder.write(&packs, 0o644).unwrap();
    for entry in std::fs::read_dir(&objects).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.len() == 2 && name.chars().all(|c| c.is_ascii_hexdigit()) {
            std::fs::remove_dir_all(&path).unwrap();
        }
    }
    let pack = std::fs::read_dir(&packs)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "pack"))
        .unwrap();
    let bytes = std::fs::read(&pack).unwrap();
    let (content, trailer) = bytes.split_at(bytes.len() - 20);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&pack)
        .unwrap();
    file.write_all(content).unwrap();
    file.seek(SeekFrom::Start(size - 20)).unwrap();
    file.write_all(trailer).unwrap();
    drop(file);
    assert_eq!(std::fs::metadata(&pack).unwrap().len(), size);
}

/// `/proc/<pid>/status`'s `field`, in bytes.
#[cfg(target_os = "linux")]
fn status_bytes(pid: u32, field: &str) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .unwrap_or_else(|| panic!("no {field} in {status}"));
    let kib: u64 = line.trim().trim_end_matches("kB").trim().parse().unwrap();
    kib * 1024
}

/// A file mapped read-only, larger than the cap, doesn't trip it: the
/// import's fetch reads every object from a pack of 768 MiB, which libgit2
/// maps whole, and is proven. Held once the fetch is done, the process's
/// peak address space stands above what it maps now by more than the cap:
/// only a map the cap doesn't count, read-only or shared, could have taken
/// that much and gone (an anonymous one would have failed), and the pack's
/// is the only one so large.
#[cfg(target_os = "linux")]
#[test]
fn a_read_only_pack_map_larger_than_the_cap_doesnt_trip_it() {
    const PACK: u64 = 768 << 20;
    let dirs = ready();
    let work = working_copy(&[("README.md", &readme)]);
    sparse_pack(&work, PACK);
    let cap = CAP.to_string();
    let (hold, release) = dirs.held("fetched@until", "release");
    let mut radicled = Radicled::import(
        &dirs,
        &work.source,
        &[],
        &[
            ("FREEDOM_RADICLED_TEST_MEMORY_CAP", cap.as_str()),
            ("FREEDOM_RADICLED_TEST_HOLD_IMPORT", hold.as_str()),
        ],
    );
    let (hello, _) = radicled.reconciled();
    assert_capped(&hello);
    let id = radicled.request("rad.import_repo", params(&work.source));
    assert!(radicled.logs("test hook: the import holds at a stage", READ_TIMEOUT));
    let pid = radicled.child.id();
    let (peak, now) = (status_bytes(pid, "VmPeak"), status_bytes(pid, "VmSize"));
    assert!(
        peak.saturating_sub(now) > CAP,
        "peak {peak}, now {now}: no map larger than the cap came and went"
    );
    std::fs::write(&release, "").unwrap();
    let reply = radicled.reply(id);
    assert!(
        reply["result"]["rid"]
            .as_str()
            .is_some_and(|rid| rid.starts_with("rad:z")),
        "{reply}"
    );
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert_eq!(fixture::marked(&dirs.home), None);
}

/// The backstop: libgit2's `GIT_ERROR_NOMEMORY` reaching a read ends the
/// process with 71, and the read isn't answered; `GIT_ERROR_ZLIB`, which a
/// corrupt object's inflate gives too, is the read's `failed`, and the
/// service goes on.
#[test]
fn an_out_of_memory_error_ends_the_service_and_zlibs_is_answered() {
    let dirs = ready();
    let mut radicled = Radicled::serve(&dirs, &[("FREEDOM_RADICLED_TEST_READ_ERROR", "zlib")]);
    let started = radicled.start();
    assert!(started["result"].is_object(), "{started}");
    let reply = radicled.read("identity", json!({})).unwrap_err();
    assert_eq!(reply["error"]["code"], "failed", "{reply}");
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    assert!(!radicled.stderr().contains(BACKSTOP));

    let mut radicled = Radicled::serve(&dirs, &[("FREEDOM_RADICLED_TEST_READ_ERROR", "nomemory")]);
    let started = radicled.start();
    assert!(started["result"].is_object(), "{started}");
    let id = radicled.request("rad.read", json!({ "op": "identity", "args": {} }));
    let (status, log) = ended(&mut radicled);
    assert_eq!(status.code(), Some(71), "{log}");
    let line = log
        .lines()
        .find(|line| line.contains(BACKSTOP))
        .unwrap_or_else(|| panic!("no backstop line: {log}"));
    let line: Value = serde_json::from_str(line).unwrap();
    assert_eq!(line["reason"], "out_of_memory", "{line}");
    assert!(!radicled.any_within(id, Duration::from_millis(200)));
}

/// The backstop with the heap exhausted: `rad.identity`'s handler, by a
/// test hook, takes every block the allocator will still give under the
/// lowered cap, then asks the backstop about libgit2's
/// `GIT_ERROR_NOMEMORY`. The process ends with 71 and the backstop's fixed
/// line, and `rad.identity` isn't answered: nothing on the way allocated,
/// or Rust's allocator would have aborted the process first.
#[cfg(any(target_os = "linux", windows))]
#[test]
fn the_backstop_ends_the_process_with_the_heap_exhausted() {
    let dirs = Dirs::new();
    let cap = CAP.to_string();
    let mut radicled = Radicled::serve(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_MEMORY_CAP", cap.as_str()),
            ("FREEDOM_RADICLED_TEST_ALLOCATE", "exhaust"),
        ],
    );
    let hello = radicled.hello();
    assert_capped(&hello);
    let id = radicled.request("rad.identity", json!({ "ephemeral": true }));
    let (status, log) = ended(&mut radicled);
    assert_eq!(status.code(), Some(71), "{status:?}\n{log}");
    assert!(
        log.lines().any(|line| line == BACKSTOP_LINE),
        "no fixed line: {log}"
    );
    assert!(!log.contains("memory allocation of"), "{log}");
    assert!(!radicled.any_within(id, Duration::from_millis(200)));
}
