//! The command line (design 0007, "Spawn" and "Lifetime lock").
//!
//! ```text
//! freedom-ipfsd serve     --data-dir <dir> --lock-dir <dir> [--parent-pid <pid>]
//! freedom-ipfsd serve     --ephemeral [--parent-pid <pid>]
//! freedom-ipfsd hold-lock --data-dir <dir> --lock-dir <dir>
//! ```
//!
//! Each flag appears at most once. `--ephemeral` takes no data directory,
//! no lock directory and no lock.

use std::ffi::OsString;
use std::path::PathBuf;

pub const USAGE: &str = "usage: freedom-ipfsd serve (--data-dir <dir> --lock-dir <dir> | --ephemeral) [--parent-pid <pid>] | freedom-ipfsd hold-lock --data-dir <dir> --lock-dir <dir>";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Serve {
        mode: Mode,
        parent_pid: Option<u32>,
    },
    HoldLock {
        data_dir: PathBuf,
        lock_dir: PathBuf,
    },
}

/// Which process `serve` runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// The profile's process: one disk instance, under the data directory's
    /// gate.
    Persistent {
        data_dir: PathBuf,
        lock_dir: PathBuf,
    },
    /// The private windows' process: memory instances, no lock.
    Ephemeral,
}

/// Parses the arguments after the program name; `None` is a usage error.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Option<Command> {
    let mut args = args.into_iter();
    let command = args.next()?.into_string().ok()?;
    let mut data_dir = None;
    let mut lock_dir = None;
    let mut parent_pid = None;
    let mut ephemeral = false;
    while let Some(flag) = args.next() {
        match flag.to_str()? {
            "--data-dir" if data_dir.is_none() => data_dir = Some(PathBuf::from(args.next()?)),
            "--lock-dir" if lock_dir.is_none() => lock_dir = Some(PathBuf::from(args.next()?)),
            "--parent-pid" if parent_pid.is_none() => {
                parent_pid = Some(args.next()?.to_str()?.parse::<u32>().ok()?);
            }
            "--ephemeral" if !ephemeral => ephemeral = true,
            _ => return None,
        }
    }
    match (command.as_str(), ephemeral, data_dir, lock_dir) {
        ("serve", false, Some(data_dir), Some(lock_dir)) => Some(Command::Serve {
            mode: Mode::Persistent { data_dir, lock_dir },
            parent_pid,
        }),
        ("serve", true, None, None) => Some(Command::Serve {
            mode: Mode::Ephemeral,
            parent_pid,
        }),
        ("hold-lock", false, Some(data_dir), Some(lock_dir)) if parent_pid.is_none() => {
            Some(Command::HoldLock { data_dir, lock_dir })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(args: &[&str]) -> Option<Command> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn the_three_forms() {
        assert_eq!(
            parse_str(&[
                "serve",
                "--data-dir",
                "d",
                "--lock-dir",
                "l",
                "--parent-pid",
                "7"
            ]),
            Some(Command::Serve {
                mode: Mode::Persistent {
                    data_dir: "d".into(),
                    lock_dir: "l".into()
                },
                parent_pid: Some(7),
            })
        );
        assert_eq!(
            parse_str(&["serve", "--ephemeral", "--parent-pid", "7"]),
            Some(Command::Serve {
                mode: Mode::Ephemeral,
                parent_pid: Some(7),
            })
        );
        assert_eq!(
            parse_str(&["serve", "--lock-dir", "l", "--data-dir", "d"]),
            Some(Command::Serve {
                mode: Mode::Persistent {
                    data_dir: "d".into(),
                    lock_dir: "l".into()
                },
                parent_pid: None,
            })
        );
        assert_eq!(
            parse_str(&["hold-lock", "--data-dir", "d", "--lock-dir", "l"]),
            Some(Command::HoldLock {
                data_dir: "d".into(),
                lock_dir: "l".into()
            })
        );
    }

    #[test]
    fn usage_errors() {
        for args in [
            &[][..],
            &["serve"],
            &["serve", "--data-dir", "d"],
            &["serve", "--lock-dir", "l"],
            &["serve", "--ephemeral", "--data-dir", "d", "--lock-dir", "l"],
            &["serve", "--ephemeral", "--lock-dir", "l"],
            &["serve", "--ephemeral", "--ephemeral"],
            &[
                "serve",
                "--data-dir",
                "d",
                "--data-dir",
                "e",
                "--lock-dir",
                "l",
            ],
            &["serve", "--ephemeral", "--parent-pid"],
            &["serve", "--ephemeral", "--parent-pid", "-1"],
            &["serve", "--ephemeral", "--parent-pid", "x"],
            &["serve", "--ephemeral", "--frobnicate"],
            &["hold-lock", "--ephemeral"],
            &["hold-lock", "--data-dir", "d"],
            &[
                "hold-lock",
                "--data-dir",
                "d",
                "--lock-dir",
                "l",
                "--parent-pid",
                "7",
            ],
            &["frobnicate", "--data-dir", "d", "--lock-dir", "l"],
        ] {
            assert_eq!(parse_str(args), None, "{args:?}");
        }
    }
}
