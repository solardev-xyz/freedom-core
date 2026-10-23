//! The environment the service starts with (design 0008, "Spawn and lock").
//!
//! Main spawns the service with its environment cleared, as 0007's is, and
//! `HOME` pointing at an empty directory the service owns. The service
//! can't clear anything itself (changing the environment isn't safe once
//! the process could have threads), so it checks instead, before anything
//! else starts, and refuses to run with what heartwood, libgit2 or systemd
//! socket activation would read:
//!
//! - `RAD_*`: heartwood's own (`RAD_SOCKET`, `RAD_KEYGEN_SEED`,
//!   `RAD_PASSPHRASE`, `RAD_RNG_SEED`, `RAD_LOCAL_TIME`, `RAD_HOME`, …);
//! - `GIT_*`: commit identities and dates (`GIT_COMMITTER_DATE`, …), and
//!   git's configuration and tracing;
//! - `SSH_AUTH_SOCK`: an agent that could sign;
//! - `LISTEN_*`: systemd's socket activation;
//! - `XDG_CONFIG_HOME`: where libgit2 looks for a global configuration.
//!
//! A refusal names only the variable's class, never its value.

use std::ffi::OsString;
use std::path::PathBuf;

/// Why the environment was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A variable from the list above is set.
    Inherited(&'static str),
    /// `HOME` is missing, not absolute, or not a directory.
    Home,
}

impl Refusal {
    /// A fixed name, for the log.
    pub fn reason(self) -> &'static str {
        match self {
            Refusal::Inherited(class) => class,
            Refusal::Home => "home",
        }
    }
}

/// The class of a variable the service must not inherit, if `name` is one.
fn refused(name: &str) -> Option<&'static str> {
    // Windows names are case-insensitive.
    let upper = name.to_ascii_uppercase();
    if upper.starts_with("RAD_") {
        Some("rad")
    } else if upper.starts_with("GIT_") {
        Some("git")
    } else if upper == "SSH_AUTH_SOCK" {
        Some("ssh_agent")
    } else if upper.starts_with("LISTEN_") {
        Some("socket_activation")
    } else if upper == "XDG_CONFIG_HOME" {
        Some("xdg_config")
    } else {
        None
    }
}

/// Checks `vars`, the process's environment: returns `HOME`, the service's
/// own directory, or why the service must not run.
pub fn check(vars: impl IntoIterator<Item = (OsString, OsString)>) -> Result<PathBuf, Refusal> {
    let mut home = None;
    for (name, value) in vars {
        // A name that isn't Unicode is none of the above.
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(class) = refused(name) {
            return Err(Refusal::Inherited(class));
        }
        if name == "HOME" {
            home = Some(PathBuf::from(value));
        }
    }
    let home = home.ok_or(Refusal::Home)?;
    if !home.is_absolute() || !home.is_dir() {
        return Err(Refusal::Home);
    }
    Ok(home)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }

    #[test]
    fn a_cleared_environment_with_its_own_home_passes() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_str().unwrap();
        assert_eq!(
            check(vars(&[("HOME", home), ("PATH", "/usr/bin"), ("LANG", "C")])),
            Ok(dir.path().to_path_buf())
        );
    }

    #[test]
    fn what_heartwood_libgit2_or_systemd_would_read_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_str().unwrap();
        for (name, class) in [
            ("RAD_SOCKET", "rad"),
            ("RAD_KEYGEN_SEED", "rad"),
            ("RAD_PASSPHRASE", "rad"),
            ("RAD_RNG_SEED", "rad"),
            ("RAD_LOCAL_TIME", "rad"),
            ("RAD_HOME", "rad"),
            ("rad_home", "rad"),
            ("GIT_COMMITTER_DATE", "git"),
            ("GIT_CONFIG_GLOBAL", "git"),
            ("GIT_TRACE", "git"),
            ("SSH_AUTH_SOCK", "ssh_agent"),
            ("LISTEN_FDS", "socket_activation"),
            ("LISTEN_PID", "socket_activation"),
            ("LISTEN_FDNAMES", "socket_activation"),
            ("XDG_CONFIG_HOME", "xdg_config"),
        ] {
            assert_eq!(
                check(vars(&[("HOME", home), (name, "x")])),
                Err(Refusal::Inherited(class)),
                "{name}"
            );
        }
    }

    #[test]
    fn home_must_be_an_existing_absolute_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(check(vars(&[("PATH", "/usr/bin")])), Err(Refusal::Home));
        assert_eq!(check(vars(&[("HOME", "relative")])), Err(Refusal::Home));
        assert_eq!(
            check(vars(&[(
                "HOME",
                dir.path().join("missing").to_str().unwrap()
            )])),
            Err(Refusal::Home)
        );
        assert_eq!(
            check(vars(&[("HOME", file.to_str().unwrap())])),
            Err(Refusal::Home)
        );
    }
}
