//! The command line (design 0014, "Spawn"):
//!
//! ```text
//! freedom-colibrid serve --chain <id> --data-dir <dir> --lock-dir <dir> [--parent-pid <pid>]
//! freedom-colibrid serve --chain <id> [--parent-pid <pid>]
//! freedom-colibrid checkpoint --chain <id> [--parent-pid <pid>]
//! freedom-colibrid hold-lock --data-dir <dir> --lock-dir <dir>
//! ```
//!
//! `serve` with both directories is a chain's persistent process; with
//! neither, a private session's, whose store is in memory (fail closed: one
//! directory without the other is a usage error, never a disk store).
//! `checkpoint` is the one-shot process of a checkpoint check: no
//! directory, no lock, one `colibri.checkpoint`.
//! `hold-lock` holds a chain directory's gate until stdin closes, as 0007's
//! services do.

use std::ffi::OsString;
use std::path::PathBuf;

pub const USAGE: &str = "usage: freedom-colibrid serve --chain <id> [--data-dir <dir> --lock-dir <dir>] [--parent-pid <pid>] | freedom-colibrid checkpoint --chain <id> [--parent-pid <pid>] | freedom-colibrid hold-lock --data-dir <dir> --lock-dir <dir>";

#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    /// The chain's directory and the gate's.
    Persistent {
        data_dir: PathBuf,
        lock_dir: PathBuf,
    },
    /// A private session's: no directory, no lock.
    Private,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Serve {
        chain: u64,
        mode: Mode,
        parent_pid: Option<u32>,
    },
    Checkpoint {
        chain: u64,
        parent_pid: Option<u32>,
    },
    HoldLock {
        data_dir: PathBuf,
        lock_dir: PathBuf,
    },
}

/// Parses the arguments after the program's name; `None` for a usage
/// error: an unknown or repeated flag, a missing value, or a value that
/// doesn't parse.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Option<Command> {
    let mut args = args.into_iter();
    let command = args.next()?;
    let mut chain = None;
    let mut data_dir = None;
    let mut lock_dir = None;
    let mut parent_pid = None;
    while let Some(flag) = args.next() {
        let value = args.next()?;
        let slot_taken = match flag.to_str()? {
            "--chain" => chain
                .replace(value.to_str()?.parse::<u64>().ok()?)
                .is_some(),
            "--data-dir" => data_dir.replace(PathBuf::from(value)).is_some(),
            "--lock-dir" => lock_dir.replace(PathBuf::from(value)).is_some(),
            "--parent-pid" => parent_pid
                .replace(value.to_str()?.parse::<u32>().ok()?)
                .is_some(),
            _ => return None,
        };
        if slot_taken {
            return None;
        }
    }
    match command.to_str()? {
        "serve" => {
            let mode = match (data_dir, lock_dir) {
                (Some(data_dir), Some(lock_dir)) => Mode::Persistent { data_dir, lock_dir },
                (None, None) => Mode::Private,
                _ => return None,
            };
            Some(Command::Serve {
                chain: chain?,
                mode,
                parent_pid,
            })
        }
        "checkpoint" if data_dir.is_none() && lock_dir.is_none() => Some(Command::Checkpoint {
            chain: chain?,
            parent_pid,
        }),
        "hold-lock" if chain.is_none() && parent_pid.is_none() => Some(Command::HoldLock {
            data_dir: data_dir?,
            lock_dir: lock_dir?,
        }),
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
    fn commands() {
        assert_eq!(
            parse_str(&[
                "serve",
                "--chain",
                "1",
                "--data-dir",
                "/d",
                "--lock-dir",
                "/l",
                "--parent-pid",
                "9"
            ]),
            Some(Command::Serve {
                chain: 1,
                mode: Mode::Persistent {
                    data_dir: "/d".into(),
                    lock_dir: "/l".into()
                },
                parent_pid: Some(9),
            })
        );
        assert_eq!(
            parse_str(&["serve", "--chain", "100"]),
            Some(Command::Serve {
                chain: 100,
                mode: Mode::Private,
                parent_pid: None,
            })
        );
        assert_eq!(
            parse_str(&["checkpoint", "--chain", "1", "--parent-pid", "3"]),
            Some(Command::Checkpoint {
                chain: 1,
                parent_pid: Some(3),
            })
        );
        assert_eq!(
            parse_str(&["hold-lock", "--data-dir", "/d", "--lock-dir", "/l"]),
            Some(Command::HoldLock {
                data_dir: "/d".into(),
                lock_dir: "/l".into()
            })
        );
    }

    #[test]
    fn usage_errors() {
        for args in [
            &[][..],
            &["serve"],
            &["serve", "--chain"],
            &["serve", "--chain", "x"],
            &["serve", "--chain", "-1"],
            &["serve", "--chain", "1", "--chain", "1"],
            &["serve", "--chain", "1", "--data-dir", "/d"],
            &["serve", "--chain", "1", "--lock-dir", "/l"],
            &["serve", "--chain", "1", "--network", "direct"],
            &["serve", "--chain", "1", "--parent-pid", "x"],
            &["hold-lock", "--data-dir", "/d"],
            &[
                "hold-lock",
                "--data-dir",
                "/d",
                "--lock-dir",
                "/l",
                "--chain",
                "1",
            ],
            &["checkpoint"],
            &[
                "checkpoint",
                "--chain",
                "1",
                "--data-dir",
                "/d",
                "--lock-dir",
                "/l",
            ],
            &["nope"],
        ] {
            assert_eq!(parse_str(args), None, "{args:?}");
        }
    }
}
