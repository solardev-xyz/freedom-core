//! The system files a confined service reads on Linux, and glibc's resolver
//! (design 0010, "What each service needs" and "Name resolution through
//! glibc").

use std::path::{Path, PathBuf};

use super::{Resolution, Resolver};

/// glibc's resolver configuration, read at each lookup, and the loader's
/// cache, read to load an NSS source.
const RESOLVER_FILES: &[&str] = &[
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/host.conf",
    "/etc/gai.conf",
    "/etc/ld.so.cache",
];

/// What the service's own resolver reads ([`Resolver::ResolvConf`]):
/// hickory's servers and its hosts file.
const RESOLV_CONF_FILES: &[&str] = &["/etc/resolv.conf", "/etc/hosts"];

/// What the standard library reads: `/proc/self` (its cgroup and mount
/// tables among it) and the cgroup tree, for the CPU count; and the random
/// devices, which the getrandom crate reads where glibc has no `getrandom`
/// (before 2.25: the release builds run on 2.17), polling `/dev/random`
/// once until the pool is ready, then reading `/dev/urandom`.
const PROCESS_FILES: &[&str] = &[
    "/proc/self",
    "/sys/fs/cgroup",
    "/dev/random",
    "/dev/urandom",
];

/// The read-only grants, each where it really lives ([`grant_in`]).
///
/// - **A file in `/etc` itself** is granted alone. One replaced by a rename
///   while the service runs is unreadable until the next process.
/// - **Any other file** (`/etc/resolv.conf` resolving to
///   `/run/systemd/resolve/stub-resolv.conf`, say) is granted by the
///   directory that holds it, so a replacement stays readable.
/// - **The C library's directory,** from `/proc/self/maps`: glibc before
///   2.34 loads its `files` and `dns` sources from there at the first lookup
///   that reaches them, and every glibc loads its other sources from there.
///
/// What doesn't exist is left out. The resolver's files are its own: glibc's
/// for [`Resolver::System`], `resolv.conf` and `/etc/hosts` alone for
/// [`Resolver::ResolvConf`], none for [`Resolver::None`].
pub(super) fn system_read_only(resolver: Resolver) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let files: &[&str] = match resolver {
        Resolver::System => RESOLVER_FILES,
        Resolver::ResolvConf => RESOLV_CONF_FILES,
        Resolver::None => &[],
    };
    for file in files {
        if let Some(path) = grant_in(Path::new(file), Path::new(ETC)) {
            push_unique(&mut paths, path);
        }
    }
    if resolver == Resolver::System
        && let Some(dir) = libc_directory()
    {
        push_unique(&mut paths, dir);
    }
    for path in PROCESS_FILES {
        if let Ok(real) = std::fs::canonicalize(path) {
            push_unique(&mut paths, real);
        }
    }
    paths
}

fn push_unique(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.contains(&path) {
        paths.push(path);
    }
}

/// The directory whose files are granted alone.
pub(super) const ETC: &str = "/etc";

/// The file the service's own resolver reads its servers from.
pub(super) const RESOLV_CONF: &str = "/etc/resolv.conf";

/// The read-only grant for a resolver file (0010, "The recommendation",
/// step 2), after its symlinks are followed: the file itself when it sits in
/// `etc` itself, or else the directory that holds it, so a file replaced
/// there by a rename stays readable. `None` if it doesn't exist.
pub(super) fn grant_in(file: &Path, etc: &Path) -> Option<PathBuf> {
    let real = std::fs::canonicalize(file).ok()?;
    let dir = real.parent()?;
    if dir == etc {
        Some(real)
    } else {
        Some(dir.to_path_buf())
    }
}

/// The directory of the C library the process runs on, from its own
/// mappings: the path of the mapping whose file name is `libc.so.6` or a
/// versioned `libc-2.*.so`.
fn libc_directory() -> Option<PathBuf> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    maps.lines()
        .filter_map(|line| line.split_whitespace().nth(5))
        .map(Path::new)
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name == "libc.so.6" || (name.starts_with("libc-2.") && name.ends_with(".so"))
                })
        })
        .and_then(|path| std::fs::canonicalize(path).ok())
        .and_then(|path| path.parent().map(Path::to_path_buf))
}

/// The NSS sources that need a local socket, which confinement refuses:
/// they answer that they are unavailable.
const SOCKET_SOURCES: &[&str] = &[
    "resolve",
    "mdns",
    "mdns4",
    "mdns6",
    "mdns_minimal",
    "mdns4_minimal",
    "mdns6_minimal",
    "sss",
];

/// Whether the C library's resolver reaches `dns` while confined, from
/// `nsswitch.conf`'s `hosts` line (glibc's default line when there is none),
/// with the reason when it doesn't.
pub(super) fn resolution() -> (Resolution, Option<String>) {
    let text = std::fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default();
    resolution_of(&text)
}

/// [`resolution`] for the text of `nsswitch.conf`.
pub(super) fn resolution_of(text: &str) -> (Resolution, Option<String>) {
    // glibc's default without a `hosts` line.
    const DEFAULT: &str = "dns [!UNAVAIL=return] files";
    let line = text
        .lines()
        .map(|line| line.split('#').next().unwrap_or(""))
        .find_map(|line| line.trim_start().strip_prefix("hosts:"))
        .unwrap_or(DEFAULT);
    let mut tokens = tokenize(line).into_iter().peekable();
    while let Some(source) = tokens.next() {
        let mut actions = Vec::new();
        while let Some(next) = tokens.peek() {
            if !next.starts_with('[') {
                break;
            }
            actions.push(tokens.next().unwrap_or_default());
        }
        if source == "dns" {
            return (Resolution::System, None);
        }
        if SOCKET_SOURCES.contains(&source.as_str()) && returns_on_unavailable(&actions) {
            return (
                Resolution::FilesOnly,
                Some(format!(
                    "nsswitch.conf's hosts line returns when `{source}`, which needs a local socket, is unavailable"
                )),
            );
        }
    }
    (
        Resolution::FilesOnly,
        Some(
            "nsswitch.conf's hosts line has no dns source after the ones that need a local socket"
                .into(),
        ),
    )
}

/// The line's sources and its bracketed action lists, each one token.
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut rest = line.trim();
    while !rest.is_empty() {
        if rest.starts_with('[') {
            let end = rest.find(']').map_or(rest.len(), |i| i + 1);
            tokens.push(rest[..end].to_owned());
            rest = rest[end..].trim_start();
        } else {
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '[')
                .unwrap_or(rest.len());
            tokens.push(rest[..end].to_owned());
            rest = rest[end..].trim_start();
        }
    }
    tokens
}

/// Whether a source's action lists stop the lookup when it is unavailable:
/// `UNAVAIL=return`, or `!X=return` for any status X but `UNAVAIL`. glibc's
/// default for an unavailable source is to continue.
fn returns_on_unavailable(actions: &[String]) -> bool {
    let mut returns = false;
    for list in actions {
        let inner = list.trim_start_matches('[').trim_end_matches(']');
        for item in inner.split_whitespace() {
            let Some((status, action)) = item.split_once('=') else {
                continue;
            };
            let status = status.to_ascii_uppercase();
            let stops = action.eq_ignore_ascii_case("return");
            if let Some(negated) = status.strip_prefix('!') {
                if negated != "UNAVAIL" {
                    returns = stops;
                }
            } else if status == "UNAVAIL" {
                returns = stops;
            }
        }
    }
    returns
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file in `/etc` itself alone; anything else by its directory, after
    /// symlinks, so a replacement there stays readable.
    #[test]
    fn a_file_in_etc_is_granted_alone_and_any_other_by_its_directory() {
        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let etc = root.join("etc");
        let resolve = root.join("run").join("resolve");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::create_dir_all(&resolve).unwrap();
        std::fs::write(etc.join("hosts"), b"").unwrap();
        std::fs::write(resolve.join("stub-resolv.conf"), b"").unwrap();
        std::fs::write(resolve.join("resolv.conf"), b"").unwrap();
        std::os::unix::fs::symlink(resolve.join("stub-resolv.conf"), etc.join("resolv.conf"))
            .unwrap();
        assert_eq!(grant_in(&etc.join("hosts"), &etc), Some(etc.join("hosts")));
        assert_eq!(
            grant_in(&etc.join("resolv.conf"), &etc),
            Some(resolve.clone())
        );
        // Named where it lives, but not in /etc itself: its directory.
        assert_eq!(grant_in(&resolve.join("resolv.conf"), &etc), Some(resolve));
        assert_eq!(grant_in(&etc.join("missing"), &etc), None);
    }

    #[test]
    fn common_configurations_reach_dns() {
        for text in [
            "hosts: files dns",
            "hosts:          files mdns4_minimal [NOTFOUND=return] dns",
            "hosts: files myhostname resolve [!UNAVAIL=return] dns",
            "# nothing about hosts\npasswd: files",
            "",
        ] {
            assert_eq!(resolution_of(text).0, Resolution::System, "{text:?}");
        }
    }

    #[test]
    fn a_line_that_stops_before_dns_is_files_only() {
        for text in [
            "hosts: files resolve",
            "hosts: files resolve [UNAVAIL=return] dns",
            "hosts: files mdns4_minimal [!NOTFOUND=return] dns",
            "hosts: files",
        ] {
            let (resolution, reason) = resolution_of(text);
            assert_eq!(resolution, Resolution::FilesOnly, "{text:?}");
            assert!(reason.is_some());
        }
    }

    #[test]
    fn a_comment_or_a_bracket_without_space_is_read_as_glibc_reads_it() {
        assert_eq!(
            resolution_of("hosts: files resolve[!UNAVAIL=return] dns # local").0,
            Resolution::System
        );
        assert_eq!(resolution_of("hosts: files # dns").0, Resolution::FilesOnly);
    }

    #[test]
    fn each_resolver_is_granted_its_own_files_alone() {
        let real = |file: &str| std::fs::canonicalize(file).ok();
        let system = system_read_only(Resolver::System);
        let resolv_conf = system_read_only(Resolver::ResolvConf);
        let none = system_read_only(Resolver::None);
        // The random devices and the process's own files, whatever the
        // resolver: getrandom's fallback reads them below glibc 2.25.
        for grants in [&system, &resolv_conf, &none] {
            for device in ["/dev/random", "/dev/urandom"] {
                assert!(grants.contains(&real(device).unwrap()), "{device}");
            }
        }
        // glibc's configuration, the loader's cache and the C library for
        // the C library's resolver alone.
        for file in ["/etc/nsswitch.conf", "/etc/ld.so.cache"] {
            if let Some(path) = real(file).filter(|p| p.parent() == Some(Path::new(ETC))) {
                assert!(system.contains(&path), "{file}");
                assert!(!resolv_conf.contains(&path), "{file}");
                assert!(!none.contains(&path), "{file}");
            }
        }
        if let Some(dir) = libc_directory() {
            assert!(system.contains(&dir));
            assert!(!resolv_conf.contains(&dir));
        }
        // resolv.conf (or the directory it really lives in) for both.
        if let Some(conf) = grant_in(Path::new("/etc/resolv.conf"), Path::new(ETC)) {
            assert!(system.contains(&conf) && resolv_conf.contains(&conf));
            assert!(!none.contains(&conf));
        }
    }

    #[test]
    fn the_system_grants_exist_and_name_the_c_library() {
        let grants = system_read_only(Resolver::System);
        assert!(grants.iter().all(|path| path.exists()));
        assert!(
            grants
                .iter()
                .any(|path| path.ends_with("self") || path.starts_with("/proc"))
        );
        // A glibc build maps libc.so.6 (CI's runners and the release
        // builds link glibc).
        if cfg!(target_env = "gnu") {
            assert!(libc_directory().is_some());
        }
    }
}
