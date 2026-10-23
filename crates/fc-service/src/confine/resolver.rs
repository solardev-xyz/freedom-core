//! The system files a confined service reads on Linux, and glibc's resolver
//! (design 0010, "What each service needs" and "Name resolution through
//! glibc").

use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};

use super::Resolution;

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

/// What the standard library reads: `/proc/self` (its cgroup and mount
/// tables among it) and the cgroup tree, for the CPU count.
const PROCESS_FILES: &[&str] = &["/proc/self", "/sys/fs/cgroup"];

/// The read-only grants, each where it really lives.
///
/// - **A file in `/etc` itself** is granted alone. One replaced by a rename
///   while the service runs is unreadable until the next process.
/// - **A file that resolves elsewhere** (`/etc/resolv.conf` to
///   `/run/systemd/resolve/stub-resolv.conf`) is granted by the directory
///   that holds it, so a replacement stays readable.
/// - **The C library's directory,** from `/proc/self/maps`: glibc before
///   2.34 loads its `files` and `dns` sources from there at the first lookup
///   that reaches them, and every glibc loads its other sources from there.
///
/// What doesn't exist is left out.
pub(super) fn system_read_only() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for file in RESOLVER_FILES {
        if let Some(path) = grant_for(Path::new(file)) {
            push_unique(&mut paths, path);
        }
    }
    if let Some(dir) = libc_directory() {
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

/// The grant for `file`: itself when it is where it is named, or else the
/// directory its real location sits in.
fn grant_for(file: &Path) -> Option<PathBuf> {
    let real = std::fs::canonicalize(file).ok()?;
    if real == file {
        return Some(real);
    }
    real.parent().map(Path::to_path_buf)
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

/// Resolves `localhost` once through the C library, before the rules, so
/// glibc has read its configuration and loaded the sources a local answer
/// reaches while every file is readable. A failure is the resolver's own,
/// and shows before any untrusted input; it doesn't stop confinement.
pub(super) fn warm_up() -> bool {
    ("localhost", 0).to_socket_addrs().is_ok()
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
    fn the_system_grants_exist_and_name_the_c_library() {
        let grants = system_read_only();
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
