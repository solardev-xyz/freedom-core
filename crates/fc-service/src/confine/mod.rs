//! OS confinement (design 0010): each service confines itself once, on its
//! main thread **while it is the process's only thread**, after its lock
//! and its directories are open, and before it starts another thread or
//! reads any untrusted input.
//!
//! [`confine`] applies a [`Policy`] with what the OS offers and returns a
//! [`Report`], one status per property, derived from what was installed.
//! A mechanism the OS lacks, or that something outside refuses, is
//! reported and the service runs (D2). Only an invalid policy, a second
//! thread, a descriptor the policy doesn't register, or an installation
//! stopped halfway is an [`Invalid`], which the service answers with exit
//! 77 (`confinement`).
//!
//! - **Linux:** Landlock at the kernel's ABI, with every right that ABI
//!   knows handled, and a seccomp denylist behind an ABI guard
//!   ([`linux`], [`seccomp`]).
//! - **Elsewhere,** for now: nothing is applied, and every property is
//!   `unavailable` (macOS and Windows follow).
//!
//! **The order** (0010, "The recommendation", step 1):
//! 1. at entry, the panic hook, then [`clean_entry`]: if anything is open
//!    above stderr, one re-exec of the running image, with every
//!    descriptor above stderr close-on-exec, so the kernel closes them.
//!    Nothing is closed by a call: a close can't prove that no Rust object
//!    owns the descriptor, and the re-exec replaces the whole image;
//! 2. only the listed setup: hardening, the arguments, the lock and the
//!    data directory. No socket, no name lookup, no file outside the
//!    grants;
//! 3. `confine`, which checks the threads and the whole descriptor table
//!    before it installs anything. A descriptor above stderr that the
//!    policy doesn't register ([`Policy::descriptors`]) is [`Invalid`],
//!    whatever its type: one opened by the setup, or one the re-exec left.
//!    A table that can't be read is [`Invalid`] too;
//! 4. only then the runtimes and every other thread.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod resolver;
#[cfg(target_os = "linux")]
pub mod seccomp;

/// What a service may use once confined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Directories it reads and writes: its data directory, or the Radicle
    /// home and its own `HOME`. Each must exist. Empty for the ephemeral
    /// IPFS process.
    pub read_write: Vec<PathBuf>,
    /// Files or directories it only reads, beyond the system's own
    /// ([`system_read_only`], which `confine` adds): an import's checked
    /// roots, say.
    pub read_only: Vec<PathBuf>,
    /// Renames and links across the read-write directories (Landlock's
    /// `refer`, ABI 2): libgit2 links each loose object into place.
    pub refer: bool,
    /// The lowest Landlock ABI the service's file rules work under. Below
    /// it no Landlock rules are applied, and `files` is `unavailable`.
    pub min_abi: u32,
    pub network: Network,
    /// Whether the service resolves names through the C library in
    /// `direct` mode (0010, "Name resolution through glibc"): then the
    /// report says whether it can reach DNS while confined. No lookup is
    /// made before the rules: glibc loads its sources at the first one
    /// after, from the read grants.
    pub system_resolver: bool,
    /// The descriptors above stderr the service opened before `confine`
    /// and keeps: the lock ([`crate::gate::Gate::descriptors`]), and any
    /// directory it holds open. Every other descriptor above stderr is
    /// [`Invalid::Descriptor`], whatever its type. Empty for the ephemeral
    /// IPFS process. Unix descriptor numbers; unused on Windows.
    pub descriptors: Vec<i32>,
    /// Whether the service looks interfaces up by name (`SIOCGIFINDEX`, the
    /// one `ioctl` this adds to the allowlist): NAT64 discovery's link-local
    /// resolvers with a named zone, such as `fe80::1%eth0` (design 0010).
    /// Sysfs's `/sys/class/net/<name>` resolves into `/sys/devices`, far
    /// more than a grant should cover, so no grant does it.
    pub interface_index: bool,
}

/// The network policy, fixed for the process's life (0007's `--network`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Outbound TCP and UDP to any port.
    Direct,
    /// TCP to the proxy's port only.
    Socks5 { port: u16 },
    /// No network at all: the import process.
    Offline,
}

/// One property's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Enforced,
    /// Some of it holds; [`Report::gaps`] says what doesn't.
    Partial,
    /// The OS lacks the mechanism.
    Unavailable,
    /// Something outside refuses a mechanism the OS has.
    Blocked,
    /// Nothing to confine: `network` in `direct` mode.
    None,
}

/// Whether the C library's resolver reaches DNS while confined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// `nsswitch.conf` reaches its `dns` source once the sources that need
    /// a local socket answer that they are unavailable.
    System,
    /// It doesn't: names outside `/etc/hosts` don't resolve while confined.
    FilesOnly,
}

/// What confinement the process got: `hello`'s `confinement`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// `landlock-<abi>+seccomp`, `landlock-<abi>`, `seccomp` or `none`.
    pub mechanism: String,
    /// Outside the grant, no file is read or written; outside the
    /// read-write grant, none is truncated; and no file's mode, owner,
    /// xattrs, flags or times change.
    pub files: Status,
    /// No program runs, and no process is created.
    pub exec: Status,
    /// No local IPC reaches another process beyond the authorized
    /// channels: main's connection on stdio (and on macOS, mDNSResponder
    /// and `configd`). No other local socket connects, and no signal is
    /// sent to another process.
    pub ipc: Status,
    /// In `socks5` mode, TCP reaches only the proxy's port.
    pub network: Status,
    /// What a `partial` property leaves open.
    pub gaps: Vec<&'static str>,
    /// Why a property is `unavailable` or `blocked`, and why resolution is
    /// `files_only`.
    pub reasons: BTreeMap<&'static str, String>,
    /// On Linux in `direct` mode, for a service that resolves through the C
    /// library.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<Resolution>,
}

impl Report {
    /// The report as `hello`'s JSON.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Why confinement refused to report: exit 77 (`confinement`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
    /// More than one thread before the rules: a thread started earlier
    /// would stay unconfined.
    Threads(usize),
    /// A descriptor above stderr that the policy doesn't register, open
    /// before the rules: Landlock and seccomp revoke nothing opened before
    /// them, so it would stay usable. `kind` says what it is (`socket`,
    /// `pipe`, `file`, `directory`, `eventfd`, `epoll`, …), never its path.
    Descriptor { fd: i32, kind: &'static str },
    /// The thread list or the descriptor table couldn't be read, or held
    /// an entry that isn't a number, so it couldn't be checked.
    Unreadable(&'static str),
    /// The mechanism refused the service's own rules, or stopped halfway.
    Rules(String),
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Invalid::Threads(n) => write!(f, "{n} threads before confinement"),
            Invalid::Descriptor { fd, kind } => write!(
                f,
                "descriptor {fd} ({kind}) open before confinement, and not registered"
            ),
            Invalid::Unreadable(what) => write!(f, "the {what} can't be read before confinement"),
            Invalid::Rules(why) => f.write_str(why),
        }
    }
}

/// Test seams: an ABI cap, so CI's kernel exercises older ABIs' rules, and
/// forced outcomes for D2. Production passes the default.
#[doc(hidden)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Use at most this Landlock ABI.
    pub landlock_abi_cap: Option<u32>,
    /// Pretend Landlock's version query failed with this errno.
    pub landlock_errno: Option<i32>,
    /// Pretend installing the seccomp filters failed with this errno.
    pub seccomp_errno: Option<i32>,
    /// Install, as the first seccomp filter, a program the kernel's checker
    /// rejects (an invalid opcode): the service's own rules refused.
    pub seccomp_invalid: bool,
}

/// The environment variable the entry's re-exec sets ([`clean_entry`]), to
/// the process's id. An exec keeps the id, so the re-executed image finds
/// its own id there and doesn't re-execute again. Any other value is no
/// marker: one inherited from a parent service names another process.
///
/// Nothing removes it: mutating the process's environment is unsafe, and
/// a stale value harms nothing (below). A child a service spawns drops it
/// with `Command::env_remove`, which touches only the child's environment.
pub const REEXEC_MARKER: &str = "FREEDOM_SERVICE_REEXEC";

/// How the process's entry went ([`clean_entry`]).
#[derive(Debug)]
pub enum Entry {
    /// Nothing open above stderr: no re-exec.
    Clean,
    /// This image is the re-exec, and nothing is left above stderr.
    Reexeced,
    /// Something is left above stderr, which [`confine`] refuses: after the
    /// re-exec (`reexeced`), because the re-exec failed (`error`), or
    /// because the descriptor table can't be read.
    Left {
        reexeced: bool,
        error: Option<std::io::Error>,
    },
}

impl Entry {
    /// A name for the log.
    pub fn name(&self) -> &'static str {
        match self {
            Entry::Clean => "clean",
            Entry::Reexeced => "reexeced",
            Entry::Left { .. } => "left",
        }
    }
}

/// At process entry, right after the panic hook and before anything opens
/// a descriptor (design 0010, step 1).
///
/// If a descriptor is open above stderr, it marks every descriptor above
/// stderr close-on-exec (`close_range` with `CLOSE_RANGE_CLOEXEC`, or
/// `fcntl` one at a time before Linux 5.11). It then executes the running
/// image again (`/proc/self/exe`), with the same arguments and environment
/// plus [`REEXEC_MARKER`], so the kernel closes them all. Returns only when
/// there is nothing to drop, or the re-exec failed.
///
/// - **Once:** with the marker set to this process's id, nothing is
///   re-executed. Since an exec keeps the id, a loop can't happen.
/// - **A reused id fails closed:** a far descendant that inherited the
///   marker and happens to get the same id doesn't re-execute; whatever it
///   inherited is then refused by [`confine`] (exit 77).
/// - **Sound:** nothing is closed by a call, so no Rust owner of a
///   descriptor is invalidated. The re-exec replaces the whole image; a
///   failed one leaves only close-on-exec set, and every owner valid.
/// - **The backstop:** [`confine`] still refuses whatever is left.
///
/// Elsewhere, for now, it does nothing (macOS follows).
pub fn clean_entry() -> Entry {
    #[cfg(target_os = "linux")]
    {
        linux::clean_entry(Path::new("/proc/self/exe"), false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Entry::Clean
    }
}

/// [`clean_entry`], re-executing `exe`, and with `one_at_a_time` marking
/// each descriptor as before Linux 5.11: test seams.
#[doc(hidden)]
pub fn clean_entry_with(exe: &Path, one_at_a_time: bool) -> Entry {
    #[cfg(target_os = "linux")]
    {
        linux::clean_entry(exe, one_at_a_time)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (exe, one_at_a_time);
        Entry::Clean
    }
}

/// Confines the process to `policy` (design 0010).
pub fn confine(policy: &Policy) -> Result<Report, Invalid> {
    confine_with(policy, &Options::default())
}

/// [`confine`], with test seams.
#[doc(hidden)]
pub fn confine_with(policy: &Policy, options: &Options) -> Result<Report, Invalid> {
    #[cfg(target_os = "linux")]
    {
        linux::confine(policy, options)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (policy, options);
        Ok(unconfined("not yet confined on this OS"))
    }
}

/// A report with every property `unavailable` for `why`.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn unconfined(why: &str) -> Report {
    let mut reasons = BTreeMap::new();
    for property in ["files", "exec", "ipc", "network"] {
        reasons.insert(property, why.to_owned());
    }
    Report {
        mechanism: "none".into(),
        files: Status::Unavailable,
        exec: Status::Unavailable,
        ipc: Status::Unavailable,
        network: Status::Unavailable,
        gaps: Vec::new(),
        reasons,
        resolution: None,
    }
}

/// The read-only grant for a resolver file the service reads itself, such
/// as NAT64 discovery's (design 0010, "The recommendation", step 2): on
/// Linux, the file alone when it sits in `/etc` itself, or else the directory
/// that holds it after its symlinks are followed, so a replacement there
/// stays readable. `None` if it doesn't exist, or elsewhere.
pub fn resolver_grant(file: &Path) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        resolver::grant_in(file, Path::new(resolver::ETC))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        None
    }
}

/// [`resolver_grant`], with `etc` standing for `/etc`: a test seam.
#[doc(hidden)]
pub fn resolver_grant_in(file: &Path, etc: &Path) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        resolver::grant_in(file, etc)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, etc);
        None
    }
}

/// The system files a confined service reads (design 0010, "What each
/// service needs"): on Linux, glibc's resolver configuration,
/// `ld.so.cache`, the C library's own directory, `/proc/self` and the
/// cgroup tree. Each is named where it really lives, after its symlinks.
/// Empty elsewhere.
pub fn system_read_only() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        resolver::system_read_only()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}
