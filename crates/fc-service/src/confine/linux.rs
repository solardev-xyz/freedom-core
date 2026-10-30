//! Confinement on Linux (design 0010, "The recommendation", step 2):
//! no-new-privileges, Landlock at the kernel's ABI with every right that
//! ABI knows handled, then the seccomp filters. Each status is derived from
//! what was installed: the ABI the kernel reports, the rights handled at
//! it, and the filters installed.

use std::collections::BTreeMap;
use std::path::Path;

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    PathFd, RestrictSelfAttr, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus, Scope, make_bitflags,
};

use super::seccomp::{self, Installed};
use super::{
    Entry, Invalid, Network, Options, Policy, REEXEC_MARKER, Report, Resolution, Status, resolver,
};

/// The newest Landlock ABI this build knows (the `landlock` crate's).
const NEWEST_ABI: u32 = 9;

/// How Landlock ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Landlock {
    /// Applied at this ABI.
    Applied(u32),
    Unavailable(String),
    Blocked(String),
}

pub(super) fn confine(policy: &Policy, options: &Options) -> Result<Report, Invalid> {
    let threads = thread_count()?;
    if threads != 1 {
        return Err(Invalid::Threads(threads));
    }
    // Landlock and seccomp check new opens and calls only: a descriptor
    // opened before them stays usable, so only the registered ones cross.
    unregistered_descriptor(&policy.descriptors)?;
    // Read from nsswitch.conf; no lookup is made before the rules, so no
    // NSS source can connect (and keep) a socket across them.
    let resolution =
        (policy.system_resolver && policy.network == Network::Direct).then(resolver::resolution);
    // Both mechanisms need it, and it is wanted whatever they do.
    let _ = rustix::thread::set_no_new_privs(true);
    let landlock = landlock(policy, options)?;
    let seccomp = match seccomp::target() {
        None => Installed::Unavailable("no seccomp filter for this architecture".into()),
        Some(arch) => {
            let mut programs = seccomp::programs(policy.network, arch, policy.interface_index)
                .map_err(Invalid::Rules)?;
            if options.seccomp_invalid {
                programs.insert(0, seccomp::invalid_program());
            }
            seccomp::install(&programs, options.seccomp_errno).map_err(Invalid::Rules)?
        }
    };
    let mut report = derive(policy, &landlock, &seccomp);
    if let Some((resolution, why)) = resolution {
        report.resolution = Some(resolution);
        if let (Resolution::FilesOnly, Some(why)) = (resolution, why) {
            report.reasons.insert("resolution", why);
        }
    }
    Ok(report)
}

/// The process's threads, from `/proc/self/task`. A list that can't be
/// read, or an entry that can't, is [`Invalid`]: it proves nothing.
fn thread_count() -> Result<usize, Invalid> {
    const WHAT: &str = "thread list";
    let mut threads = 0;
    for entry in std::fs::read_dir("/proc/self/task").map_err(|_| Invalid::Unreadable(WHAT))? {
        let entry = entry.map_err(|_| Invalid::Unreadable(WHAT))?;
        if entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .is_none()
        {
            return Err(Invalid::Unreadable(WHAT));
        }
        threads += 1;
    }
    Ok(threads)
}

/// The process's entry ([`super::clean_entry`]): the one re-exec, if
/// anything is open above stderr.
pub(super) fn clean_entry(exe: &Path, one_at_a_time: bool) -> Entry {
    let reexeced = marked();
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
            error: Some(reexec(exe, &open, one_at_a_time)),
        },
    }
}

/// Whether this image is the re-exec: the marker holds this process's id,
/// exactly as the re-exec wrote it. Any other value (a parent service's id,
/// or anything not a number) is no marker. Nothing removes the marker; if a
/// far descendant inherits it and gets the same id, it doesn't re-execute,
/// and `confine` refuses what it inherited: that fails closed.
fn marked() -> bool {
    std::env::var_os(REEXEC_MARKER).is_some_and(|value| value == own_id().as_str())
}

/// This process's id, as the marker holds it.
fn own_id() -> String {
    std::process::id().to_string()
}

/// Marks every descriptor above stderr close-on-exec, and executes `exe`
/// with this process's arguments and environment, plus the marker. Returns
/// only the error of a re-exec that failed: close-on-exec is then merely
/// set, and every descriptor and its owner as it was. `one_at_a_time`
/// skips `close_range`, as before Linux 5.11 (a test seam).
fn reexec(exe: &Path, open: &[i32], one_at_a_time: bool) -> std::io::Error {
    use std::os::unix::process::CommandExt;

    if one_at_a_time || fc_sys::linux::cloexec_from(3).is_err() {
        // Before Linux 5.11: one at a time.
        for &fd in open {
            let _ = fc_sys::unix::set_cloexec(fd);
        }
    }
    let mut args = std::env::args_os();
    let mut command = std::process::Command::new(exe);
    if let Some(arg0) = args.next() {
        command.arg0(arg0);
    }
    command.args(args).env(REEXEC_MARKER, own_id()).exec()
}

/// The descriptors above stderr, from `/proc/self/fd`, without the
/// listing's own, which is opened here and known by its number. A table
/// that can't be opened or read, or an entry that isn't a descriptor
/// number, is [`Invalid::Unreadable`]: it proves nothing.
fn descriptors_above_stderr() -> Result<Vec<i32>, Invalid> {
    use std::os::fd::AsRawFd;

    use rustix::fs::{Dir, Mode, OFlags};

    const WHAT: &str = "descriptor table";
    let table = rustix::fs::open(
        "/proc/self/fd",
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

/// Checks every descriptor above stderr against `registered`, whatever its
/// type: the lowest other one is [`Invalid::Descriptor`], opened by the
/// setup or left after the entry's re-exec. A table that can't be read is
/// [`Invalid::Unreadable`]. What a descriptor is only names it in the
/// error, from `readlink` and `stat` on its `/proc/self/fd` entry, which
/// open nothing: an unregistered one is refused whether or not it can be
/// identified.
fn unregistered_descriptor(registered: &[i32]) -> Result<(), Invalid> {
    let Some(fd) = descriptors_above_stderr()?
        .into_iter()
        .find(|fd| !registered.contains(fd))
    else {
        return Ok(());
    };
    let path = format!("/proc/self/fd/{fd}");
    let target = rustix::fs::readlink(path.as_str(), Vec::new()).ok();
    let file_type = rustix::fs::stat(path.as_str())
        .ok()
        .map(|stat| rustix::fs::FileType::from_raw_mode(stat.st_mode));
    Err(Invalid::Descriptor {
        fd,
        kind: kind_of(target.as_ref().map(|t| t.as_bytes()), file_type),
    })
}

/// What a descriptor is, from its `/proc/self/fd` link and the type of what
/// it refers to: never its path.
fn kind_of(target: Option<&[u8]>, file_type: Option<rustix::fs::FileType>) -> &'static str {
    use rustix::fs::FileType;

    match target {
        Some(t) if t.starts_with(b"socket:") => return "socket",
        Some(t) if t.starts_with(b"pipe:") => return "pipe",
        Some(b"anon_inode:[eventfd]") => return "eventfd",
        Some(b"anon_inode:[eventpoll]") => return "epoll",
        Some(t) if t.starts_with(b"anon_inode:") => return "anon_inode",
        _ => {}
    }
    match file_type {
        Some(FileType::Socket) => "socket",
        Some(FileType::Fifo) => "pipe",
        Some(FileType::Directory) => "directory",
        Some(FileType::RegularFile) => "file",
        Some(FileType::CharacterDevice | FileType::BlockDevice) => "device",
        Some(FileType::Symlink | FileType::Unknown) | None => "other",
    }
}

/// Applies Landlock at the kernel's ABI (capped by `options`), or says why
/// not. An error is the service's own rules refused: [`Invalid`].
fn landlock(policy: &Policy, options: &Options) -> Result<Landlock, Invalid> {
    let version = match options.landlock_errno {
        Some(errno) => Err(errno),
        None => fc_sys::linux::landlock_abi(),
    };
    let kernel = match version {
        Ok(version) => version,
        Err(libc::ENOSYS) => return Ok(Landlock::Unavailable("the kernel has no Landlock".into())),
        Err(libc::EOPNOTSUPP) => {
            return Ok(Landlock::Unavailable("Landlock is disabled at boot".into()));
        }
        Err(errno) => {
            return Ok(Landlock::Blocked(format!(
                "Landlock's version query is refused (errno {errno})"
            )));
        }
    };
    let abi_number = kernel
        .min(NEWEST_ABI)
        .min(options.landlock_abi_cap.unwrap_or(NEWEST_ABI));
    if abi_number < policy.min_abi {
        return Ok(Landlock::Unavailable(format!(
            "Landlock ABI {abi_number} is below this service's minimum, {}",
            policy.min_abi
        )));
    }
    let abi = ABI::from(abi_number as i32);
    match restrict(policy, abi) {
        Ok(()) => Ok(Landlock::Applied(abi_number)),
        Err(Refused::Outside(why)) => Ok(Landlock::Blocked(why)),
        Err(Refused::Rules(why)) => Err(Invalid::Rules(why)),
    }
}

enum Refused {
    /// Something outside the service: `EPERM` or the 16-layer limit.
    Outside(String),
    /// The service's own rules.
    Rules(String),
}

/// The rights a read-write directory gets: everything `abi` handles but
/// execute, special files (devices, FIFOs, sockets, symlinks), device
/// `ioctl`s and connecting to pathname sockets, and `refer` only if asked.
fn read_write_rights(abi: ABI, refer: bool) -> BitFlags<AccessFs> {
    let mut rights = AccessFs::from_all(abi)
        & !make_bitflags!(AccessFs::{
            Execute | MakeChar | MakeBlock | MakeFifo | MakeSock | MakeSym | IoctlDev | ResolveUnix
        });
    if !refer {
        rights &= !BitFlags::from(AccessFs::Refer);
    }
    rights
}

/// What a read-only path gets: reading, and listing a directory.
fn read_only_rights(path: &Path) -> BitFlags<AccessFs> {
    if path.is_dir() {
        AccessFs::ReadFile | AccessFs::ReadDir
    } else {
        AccessFs::ReadFile.into()
    }
}

fn restrict(policy: &Policy, abi: ABI) -> Result<(), Refused> {
    let rules = |e: RulesetError| Refused::Rules(format!("Landlock refused the rules: {e}"));
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(rules)?;
    if abi >= ABI::V4 {
        let net = match policy.network {
            // Connect is left unhandled: any port. Bind is handled with no
            // rule: none.
            Network::Direct => BitFlags::from(AccessNet::BindTcp),
            Network::Socks5 { .. } | Network::Offline => AccessNet::BindTcp | AccessNet::ConnectTcp,
        };
        ruleset = ruleset.handle_access(net).map_err(rules)?;
    }
    if abi >= ABI::V6 {
        ruleset = ruleset
            .scope(Scope::AbstractUnixSocket | Scope::Signal)
            .map_err(rules)?;
    }
    let mut created = ruleset
        .create()
        .map_err(|e| outside_or_rules(e, "creating the ruleset"))?;
    let read_write = read_write_rights(abi, policy.refer);
    for dir in &policy.read_write {
        let fd = PathFd::new(dir)
            .map_err(|e| Refused::Rules(format!("Landlock can't open a grant: {e}")))?;
        created = created
            .add_rule(PathBeneath::new(fd, read_write))
            .map_err(rules)?;
    }
    let mut read_only = super::system_read_only();
    read_only.extend(policy.read_only.iter().cloned());
    for path in &read_only {
        let fd = PathFd::new(path)
            .map_err(|e| Refused::Rules(format!("Landlock can't open a grant: {e}")))?;
        created = created
            .add_rule(PathBeneath::new(
                fd,
                read_only_rights(path) & AccessFs::from_all(abi),
            ))
            .map_err(rules)?;
    }
    if let (Network::Socks5 { port, .. }, true) = (policy.network, abi >= ABI::V4) {
        created = created
            .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
            .map_err(rules)?;
    }
    if abi >= ABI::V8 {
        // A backstop: the order already keeps the process single-threaded.
        created = created.all_threads(true).map_err(rules)?;
    }
    let status = created
        .restrict_self()
        .map_err(|e| outside_or_rules(e, "restricting the process"))?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(Refused::Rules(format!(
            "Landlock enforced only part of the rules ({:?})",
            status.ruleset
        )));
    }
    Ok(())
}

/// A ruleset error from a system call: `EPERM` or `E2BIG` (an outer
/// sandbox's 16 layers) is something outside; anything else is the rules.
fn outside_or_rules(error: RulesetError, step: &str) -> Refused {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(e) = source {
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && matches!(io.raw_os_error(), Some(libc::EPERM | libc::E2BIG))
        {
            return Refused::Outside(format!("{step} is refused: {io}"));
        }
        source = e.source();
    }
    Refused::Rules(format!("{step} failed: {error}"))
}

/// Landlock's status and reason when it applied nothing.
fn landlock_reason(landlock: &Landlock) -> (Status, String) {
    match landlock {
        Landlock::Blocked(why) => (Status::Blocked, why.clone()),
        Landlock::Unavailable(why) => (Status::Unavailable, why.clone()),
        Landlock::Applied(_) => (Status::Unavailable, String::new()),
    }
}

/// Each property's status from what was installed (design 0010, step 5).
fn derive(policy: &Policy, landlock: &Landlock, seccomp: &Installed) -> Report {
    let abi = match landlock {
        Landlock::Applied(abi) => Some(*abi),
        _ => None,
    };
    let filters = *seccomp == Installed::All;
    let mut gaps = Vec::new();
    let mut reasons = BTreeMap::new();
    // Why a property got nothing: the mechanism's own reason, a block
    // before an absence.
    let not = |landlock_too: bool| -> (Status, String) {
        let from_landlock = match landlock {
            Landlock::Blocked(why) => Some((Status::Blocked, why.clone())),
            Landlock::Unavailable(why) => Some((Status::Unavailable, why.clone())),
            Landlock::Applied(_) => None,
        };
        let from_seccomp = match seccomp {
            Installed::Blocked(why) => Some((Status::Blocked, why.clone())),
            Installed::Unavailable(why) => Some((Status::Unavailable, why.clone())),
            Installed::All => None,
        };
        let candidates = [
            landlock_too.then_some(from_landlock).flatten(),
            from_seccomp,
        ];
        candidates
            .into_iter()
            .flatten()
            .max_by_key(|(status, _)| *status)
            .unwrap_or((Status::Unavailable, "not confined".into()))
    };

    let files = match (abi, filters) {
        (Some(_), true) => Status::Enforced,
        (Some(_), false) => {
            gaps.push("metadata");
            Status::Partial
        }
        (None, _) => {
            let (status, why) = landlock_reason(landlock);
            reasons.insert("files", why);
            status
        }
    };

    let exec = match (filters, abi.is_some()) {
        (true, _) => Status::Enforced,
        (false, true) => {
            gaps.push("processes");
            Status::Partial
        }
        (false, false) => {
            let (status, why) = not(true);
            reasons.insert("exec", why);
            status
        }
    };

    let signals = abi.is_some_and(|abi| abi >= 6);
    let sockets = filters || abi.is_some_and(|abi| abi >= 9);
    let debugging = filters || abi.is_some();
    let ipc_gaps: Vec<&'static str> = [
        (!signals).then_some("signals"),
        (!sockets).then_some("sockets"),
        (!debugging).then_some("debugging"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let ipc = if ipc_gaps.is_empty() {
        Status::Enforced
    } else if ipc_gaps.len() == 3 {
        let (status, why) = not(true);
        reasons.insert("ipc", why);
        status
    } else {
        gaps.extend(ipc_gaps);
        Status::Partial
    };

    let network = match policy.network {
        Network::Direct => Status::None,
        Network::Socks5 { .. } => match abi {
            Some(abi) if abi >= 4 => Status::Enforced,
            Some(abi) => {
                reasons.insert(
                    "network",
                    format!("TCP rules need Landlock ABI 4; the kernel offers {abi}"),
                );
                Status::Unavailable
            }
            None => {
                let (status, why) = landlock_reason(landlock);
                reasons.insert("network", why);
                status
            }
        },
        // No socket at all: seccomp refuses every family.
        Network::Offline => {
            if filters {
                Status::Enforced
            } else {
                let (status, why) = not(false);
                reasons.insert("network", why);
                status
            }
        }
    };

    let mechanism = match (abi, filters) {
        (Some(abi), true) => format!("landlock-{abi}+seccomp"),
        (Some(abi), false) => format!("landlock-{abi}"),
        (None, true) => "seccomp".into(),
        (None, false) => "none".into(),
    };
    Report {
        mechanism,
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
    use super::*;

    fn policy(network: Network) -> Policy {
        Policy {
            read_write: Vec::new(),
            read_only: Vec::new(),
            refer: false,
            min_abi: 1,
            network,
            system_resolver: false,
            descriptors: Vec::new(),
            interface_index: false,
        }
    }

    /// A descriptor is named by what it is, never by its path.
    #[test]
    fn descriptor_kinds() {
        use rustix::fs::FileType;
        let path: &[u8] = b"/home/user/secret";
        for (target, file_type, kind) in [
            (Some(&b"socket:[4242]"[..]), None, "socket"),
            (Some(b"pipe:[4242]"), Some(FileType::Fifo), "pipe"),
            (Some(b"anon_inode:[eventfd]"), None, "eventfd"),
            (Some(b"anon_inode:[eventpoll]"), None, "epoll"),
            (Some(b"anon_inode:[timerfd]"), None, "anon_inode"),
            (Some(path), Some(FileType::RegularFile), "file"),
            (Some(path), Some(FileType::Directory), "directory"),
            (Some(path), Some(FileType::Fifo), "pipe"),
            (Some(path), Some(FileType::Socket), "socket"),
            (
                Some(b"/dev/null"),
                Some(FileType::CharacterDevice),
                "device",
            ),
            (None, None, "other"),
        ] {
            assert_eq!(kind_of(target, file_type), kind, "{target:?}");
        }
    }

    #[test]
    fn everything_installed_is_enforced() {
        let report = derive(
            &policy(Network::Socks5 {
                port: 9150,
                loopback: true,
            }),
            &Landlock::Applied(6),
            &Installed::All,
        );
        assert_eq!(report.mechanism, "landlock-6+seccomp");
        assert_eq!(
            (report.files, report.exec, report.ipc, report.network),
            (
                Status::Enforced,
                Status::Enforced,
                Status::Enforced,
                Status::Enforced
            )
        );
        assert!(report.gaps.is_empty() && report.reasons.is_empty());
    }

    #[test]
    fn older_abis_leave_named_gaps() {
        let report = derive(
            &policy(Network::Socks5 {
                port: 9150,
                loopback: true,
            }),
            &Landlock::Applied(3),
            &Installed::All,
        );
        assert_eq!(report.ipc, Status::Partial);
        assert_eq!(report.gaps, ["signals"]);
        assert_eq!(report.network, Status::Unavailable);
        assert!(report.reasons["network"].contains("ABI 4"));
        let direct = derive(
            &policy(Network::Direct),
            &Landlock::Applied(3),
            &Installed::All,
        );
        assert_eq!(direct.network, Status::None);
    }

    #[test]
    fn a_missing_mechanism_is_reported_with_its_reason() {
        let without = Landlock::Unavailable("the kernel has no Landlock".into());
        let report = derive(&policy(Network::Direct), &without, &Installed::All);
        assert_eq!(report.mechanism, "seccomp");
        assert_eq!(report.files, Status::Unavailable);
        assert_eq!(report.reasons["files"], "the kernel has no Landlock");
        assert_eq!(
            (report.exec, report.ipc),
            (Status::Enforced, Status::Partial)
        );
        assert_eq!(report.gaps, ["signals"]);

        let blocked = Installed::Blocked("installing the seccomp filter failed: EPERM".into());
        let report = derive(
            &policy(Network::Direct),
            &Landlock::Blocked("refused".into()),
            &blocked,
        );
        assert_eq!(report.mechanism, "none");
        assert_eq!(
            (report.files, report.exec, report.ipc),
            (Status::Blocked, Status::Blocked, Status::Blocked)
        );
    }

    #[test]
    fn landlock_without_seccomp_is_partial() {
        let none = Installed::Unavailable("no seccomp filter for this architecture".into());
        let report = derive(&policy(Network::Direct), &Landlock::Applied(9), &none);
        assert_eq!(report.mechanism, "landlock-9");
        assert_eq!(
            (report.files, report.exec, report.ipc),
            (Status::Partial, Status::Partial, Status::Enforced)
        );
        assert_eq!(report.gaps, ["metadata", "processes"]);
    }

    #[test]
    fn rights_handle_what_the_abi_knows() {
        let v1 = read_write_rights(ABI::V1, true);
        assert!(!v1.contains(AccessFs::Execute) && !v1.contains(AccessFs::MakeSock));
        assert!(v1.contains(AccessFs::WriteFile) && v1.contains(AccessFs::RemoveFile));
        let v2 = read_write_rights(ABI::V2, true);
        assert!(v2.contains(AccessFs::Refer));
        assert!(!read_write_rights(ABI::V2, false).contains(AccessFs::Refer));
        let v5 = read_write_rights(ABI::V5, false);
        assert!(v5.contains(AccessFs::Truncate) && !v5.contains(AccessFs::IoctlDev));
    }
}
