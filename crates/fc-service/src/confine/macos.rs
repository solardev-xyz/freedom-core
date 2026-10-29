//! Confinement on macOS (design 0010, "macOS"): a Seatbelt profile
//! generated from the policy ([`super::seatbelt`]), self-applied through
//! Seatbelt's private calls (`fc-sys`), each status derived from the
//! sandbox's own checks once it is applied.
//!
//! The entry's re-exec runs the file `proc_pidpath` names, and carries that
//! file's identity in the marker (`<pid>:<dev>:<ino>`): an exec runs a path,
//! not the running image, so the re-executed image checks that it is the
//! same file ([`super::Entry::Replaced`]).

use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use fc_sys::macos::{self as sys, Filter};

use super::seatbelt::{self, Grants};
use super::{Entry, Invalid, Network, Options, Policy, REEXEC_MARKER, Report, Status};

/// Set by the entry when the re-executed file isn't the one recorded before
/// the exec: `confine` refuses the process.
static REPLACED: AtomicBool = AtomicBool::new(false);

/// The descriptor table.
const FD_TABLE: &str = "/dev/fd";

/// A file's identity: its device and inode.
type Identity = (u64, u64);

fn identity_of(path: &Path) -> std::io::Result<Identity> {
    let metadata = std::fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

/// The marker this process would set: its id and its file's identity.
fn marker_for(identity: Identity) -> String {
    format!("{}:{}:{}", std::process::id(), identity.0, identity.1)
}

/// What the marker says about this process: not ours (`None`), or ours with
/// the identity recorded before the exec.
fn marked() -> Option<Identity> {
    parse_marker(std::env::var_os(REEXEC_MARKER)?.to_str()?)
}

/// A marker's identity, if it holds exactly this process's id and an
/// identity: any other value is no marker.
fn parse_marker(value: &str) -> Option<Identity> {
    let mut parts = value.split(':');
    let (pid, dev, ino) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || pid != std::process::id().to_string() {
        return None;
    }
    Some((dev.parse().ok()?, ino.parse().ok()?))
}

pub(super) fn clean_entry(exe: Option<&Path>) -> Entry {
    let recorded = marked();
    let reexeced = recorded.is_some();
    if let Some(recorded) = recorded {
        // The re-executed image: the same file as before the exec?
        let same = sys::executable_path()
            .and_then(|path| identity_of(&path))
            .is_ok_and(|now| now == recorded);
        if !same {
            REPLACED.store(true, Ordering::SeqCst);
            return Entry::Replaced;
        }
    }
    let open = match descriptors_above_stderr() {
        Ok(open) => open,
        Err(_) => {
            return Entry::Left {
                reexeced,
                error: None,
            };
        }
    };
    match (open.is_empty(), reexeced) {
        (true, false) => Entry::Clean,
        (true, true) => Entry::Reexeced,
        (false, true) => Entry::Left {
            reexeced,
            error: None,
        },
        (false, false) => Entry::Left {
            reexeced,
            error: Some(reexec(exe, &open)),
        },
    }
}

/// Marks each descriptor in `open` close-on-exec, and executes this
/// process's file again (or `exe`, a test seam) with its arguments and
/// environment, plus the marker with the file's identity. Returns only the
/// error of a re-exec that failed.
fn reexec(exe: Option<&Path>, open: &[i32]) -> std::io::Error {
    use std::os::unix::process::CommandExt;

    let path = match exe {
        Some(exe) => exe.to_path_buf(),
        None => match sys::executable_path() {
            Ok(path) => path,
            Err(error) => return error,
        },
    };
    // The file the exec will run, from a descriptor on it: what the
    // re-executed image compares its own with.
    let identity = match std::fs::File::open(&path).and_then(|file| file.metadata()) {
        Ok(metadata) => (metadata.dev(), metadata.ino()),
        Err(error) => return error,
    };
    for &fd in open {
        let _ = fc_sys::unix::set_cloexec(fd);
    }
    let mut args = std::env::args_os();
    let mut command = std::process::Command::new(&path);
    if let Some(arg0) = args.next() {
        command.arg0(arg0);
    }
    command
        .args(args)
        .env(REEXEC_MARKER, marker_for(identity))
        .exec()
}

/// The descriptors above stderr, from `/dev/fd`, without the listing's own.
/// A table that can't be read is [`Invalid::Unreadable`].
fn descriptors_above_stderr() -> Result<Vec<i32>, Invalid> {
    use std::os::fd::AsRawFd;

    use rustix::fs::{Dir, Mode, OFlags};

    const WHAT: &str = "descriptor table";
    let table = rustix::fs::open(
        FD_TABLE,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Invalid::Unreadable(WHAT))?;
    let own = table.as_raw_fd();
    let mut dir = Dir::new(table).map_err(|_| Invalid::Unreadable(WHAT))?;
    let mut open = Vec::new();
    while let Some(entry) = dir.read() {
        let entry = entry.map_err(|_| Invalid::Unreadable(WHAT))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let fd = name
            .to_str()
            .ok()
            .and_then(|name| name.parse::<i32>().ok())
            .ok_or(Invalid::Unreadable(WHAT))?;
        if fd > 2 && fd != own {
            open.push(fd);
        }
    }
    open.sort_unstable();
    Ok(open)
}

/// The lowest descriptor above stderr the policy doesn't register, named by
/// its type from a `stat` of its `/dev/fd` entry, which opens nothing.
fn unregistered_descriptor(registered: &[i32]) -> Result<(), Invalid> {
    use rustix::fs::FileType;

    let Some(fd) = descriptors_above_stderr()?
        .into_iter()
        .find(|fd| !registered.contains(fd))
    else {
        return Ok(());
    };
    let kind = match rustix::fs::stat(format!("{FD_TABLE}/{fd}").as_str())
        .ok()
        .map(|stat| FileType::from_raw_mode(stat.st_mode))
    {
        Some(FileType::Socket) => "socket",
        Some(FileType::Fifo) => "pipe",
        Some(FileType::Directory) => "directory",
        Some(FileType::RegularFile) => "file",
        Some(FileType::CharacterDevice | FileType::BlockDevice) => "device",
        _ => "other",
    };
    Err(Invalid::Descriptor { fd, kind })
}

pub(super) fn confine(policy: &Policy, options: &Options) -> Result<Report, Invalid> {
    if REPLACED.load(Ordering::SeqCst) {
        return Err(Invalid::Replaced);
    }
    let threads = sys::thread_count().map_err(|_| Invalid::Unreadable("thread count"))?;
    if threads != 1 {
        return Err(Invalid::Threads(threads));
    }
    // Seatbelt checks new opens and calls only: a descriptor opened before
    // it stays usable, so only the registered ones cross.
    unregistered_descriptor(&policy.descriptors)?;
    if sys::sandboxed() {
        // An outer sandbox: another can't be applied (D2: blocked, runs).
        return Ok(blocked("the process is in a sandbox already"));
    }
    let grants = grants(policy)?;
    let profile =
        seatbelt::profile(policy.network, policy.refer, &grants).map_err(Invalid::Rules)?;
    let mut text = profile.text;
    if options.seatbelt_invalid {
        // Not SBPL: the service's own rules refused.
        text.push_str("(allow no-such-operation\n");
    }
    let text = CString::new(text).map_err(|_| Invalid::Rules("the profile holds a NUL".into()))?;
    let params = profile
        .params
        .into_iter()
        .map(
            |(name, value)| -> Result<(CString, CString), std::ffi::NulError> {
                Ok((CString::new(name)?, CString::new(value)?))
            },
        )
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Invalid::Rules("a parameter holds a NUL".into()))?;
    let borrowed: Vec<(&std::ffi::CStr, &std::ffi::CStr)> = params
        .iter()
        .map(|(name, value)| (name.as_c_str(), value.as_c_str()))
        .collect();
    sys::apply_profile(&text, &borrowed)
        .map_err(|why| Invalid::Rules(format!("Seatbelt refused the profile: {why}")))?;
    Ok(derive(policy, &grants))
}

/// The policy's grants as the profile names them: canonical, since Seatbelt
/// matches resolved paths (`/private/var`, not `/var`). A read-write
/// directory must exist; a read-only one that doesn't is left out.
fn grants(policy: &Policy) -> Result<Grants, Invalid> {
    let mut grants = Grants::default();
    for dir in &policy.read_write {
        let real = std::fs::canonicalize(dir).map_err(|e| {
            Invalid::Rules(format!(
                "a read-write grant can't be resolved: {}",
                e.kind()
            ))
        })?;
        grants.read_write.push(real);
    }
    for path in &policy.read_only {
        let Ok(real) = std::fs::canonicalize(path) else {
            continue;
        };
        if real.is_dir() {
            grants.read_only_dirs.push(real);
        } else {
            grants.read_only_files.push(real);
        }
    }
    Ok(grants)
}

/// A report for an outer sandbox: every property `blocked`.
fn blocked(why: &str) -> Report {
    let mut reasons = BTreeMap::new();
    for property in ["files", "exec", "ipc", "network"] {
        reasons.insert(property, why.to_owned());
    }
    Report {
        mechanism: "none".into(),
        files: Status::Blocked,
        exec: Status::Blocked,
        ipc: Status::Blocked,
        network: Status::Blocked,
        gaps: Vec::new(),
        reasons,
        resolution: None,
    }
}

/// Files that exist on every macOS and lie outside every grant: what the
/// derived `files` status asks the sandbox about.
const OUTSIDE_READ: &std::ffi::CStr = c"/Library/Preferences";
const OUTSIDE_WRITE: &std::ffi::CStr = c"/Library/Caches";
/// A program every macOS has: the derived `exec` status asks about it.
const SOME_PROGRAM: &std::ffi::CStr = c"/bin/sh";
/// A Mach service outside the authorized channels: the derived `ipc`
/// status asks about it.
const SOME_SERVICE: &std::ffi::CStr = c"com.apple.pasteboard.1";

/// Each status, from the sandbox's own answers once the profile is applied:
/// `enforced` only where it denies what the property says it must.
fn derive(policy: &Policy, grants: &Grants) -> Report {
    let mut gaps = Vec::new();
    let mut reasons = BTreeMap::new();
    // `enforced` where every check answers a denial; `partial` where one
    // allows, or none answers, with what the sandbox returned.
    let mut status = |property: &'static str, answers: &[Result<bool, i32>]| {
        if answers.iter().all(|answer| *answer == Ok(false)) {
            return Status::Enforced;
        }
        gaps.push(property);
        if !answers.contains(&Ok(true)) {
            let codes: Vec<String> = answers
                .iter()
                .filter_map(|answer| answer.err().map(|code| code.to_string()))
                .collect();
            reasons.insert(
                property,
                format!(
                    "the sandbox's own check didn't answer ({})",
                    codes.join(", ")
                ),
            );
        }
        Status::Partial
    };
    let mut file_checks = vec![
        sys::check(c"file-read-data", Filter::Path(OUTSIDE_READ)),
        sys::check(c"file-write-data", Filter::Path(OUTSIDE_WRITE)),
    ];
    // Metadata stays unchangeable inside the read-write grant too.
    let dirs: Vec<CString> = grants
        .read_write
        .iter()
        .filter_map(|dir| {
            CString::new(std::os::unix::ffi::OsStrExt::as_bytes(dir.as_os_str())).ok()
        })
        .collect();
    for dir in &dirs {
        file_checks.push(sys::check(c"file-write-mode", Filter::Path(dir)));
    }
    let files = status("files", &file_checks);
    let exec = status(
        "exec",
        &[
            sys::check(c"process-fork", Filter::None),
            sys::check(c"process-exec", Filter::Path(SOME_PROGRAM)),
        ],
    );
    let ipc = status(
        "ipc",
        &[sys::check(c"mach-lookup", Filter::GlobalName(SOME_SERVICE))],
    );
    // The network rule names the proxy's port (and loopback host) alone:
    // the profile holds no other, and the sandbox can't be asked about an
    // address.
    let network = match policy.network {
        Network::Direct => Status::None,
        Network::Socks5 { .. } | Network::Offline => Status::Enforced,
    };
    Report {
        mechanism: "seatbelt".into(),
        files,
        exec,
        ipc,
        network,
        gaps,
        reasons,
        resolution: None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn the_marker_is_ours_only_with_our_id_and_an_identity() {
        let ours = marker_for((1, 2));
        assert_eq!(parse_marker(&ours), Some((1, 2)));
        // Linux's form, another id, a longer value: no marker.
        assert_eq!(parse_marker(&std::process::id().to_string()), None);
        assert_eq!(parse_marker("1:2:3"), None);
        assert_eq!(parse_marker(&format!("{ours}:4")), None);
        assert_eq!(parse_marker(&format!("{}:x:2", std::process::id())), None);
    }

    #[test]
    fn this_test_has_no_descriptor_it_cant_name() {
        // The table reads, and every entry is a number.
        assert!(descriptors_above_stderr().is_ok());
    }

    #[test]
    fn grants_resolve_to_where_seatbelt_matches() {
        let dir = tempfile::tempdir().unwrap();
        let policy = Policy {
            read_write: vec![dir.path().to_path_buf()],
            read_only: vec![PathBuf::from("/etc/hosts"), PathBuf::from("/nonexistent")],
            refer: false,
            min_abi: 1,
            network: Network::Offline,
            system_resolver: false,
            descriptors: Vec::new(),
            interface_index: false,
        };
        let grants = grants(&policy).unwrap();
        // macOS's temporary directories live under /private.
        assert!(grants.read_write[0].starts_with("/private"));
        assert_eq!(
            grants.read_only_files,
            [PathBuf::from("/private/etc/hosts")]
        );
        assert!(grants.read_only_dirs.is_empty());
    }
}
