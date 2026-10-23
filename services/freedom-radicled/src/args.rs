//! The command line (design 0008, "Spawn and lock").
//!
//! ```text
//! freedom-radicled serve     --home <dir> --lock-dir <dir> [--parent-pid <pid>]
//! freedom-radicled hold-lock --home <dir> --lock-dir <dir>
//! ```
//!
//! Each flag appears at most once. `--home` is the profile's Radicle home
//! (`getRadicleDataDir()`), whose canonical path keys the gate.

use std::ffi::OsString;
use std::path::PathBuf;

pub const USAGE: &str = "usage: freedom-radicled serve --home <dir> --lock-dir <dir> [--parent-pid <pid>] | freedom-radicled hold-lock --home <dir> --lock-dir <dir>";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Serve {
        home: PathBuf,
        lock_dir: PathBuf,
        parent_pid: Option<u32>,
    },
    HoldLock {
        home: PathBuf,
        lock_dir: PathBuf,
    },
}

/// Parses the arguments after the program name; `None` is a usage error.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Option<Command> {
    let mut args = args.into_iter();
    let command = args.next()?.into_string().ok()?;
    let mut home = None;
    let mut lock_dir = None;
    let mut parent_pid = None;
    while let Some(flag) = args.next() {
        match flag.to_str()? {
            "--home" if home.is_none() => home = Some(PathBuf::from(args.next()?)),
            "--lock-dir" if lock_dir.is_none() => lock_dir = Some(PathBuf::from(args.next()?)),
            "--parent-pid" if parent_pid.is_none() => {
                parent_pid = Some(args.next()?.to_str()?.parse::<u32>().ok()?);
            }
            _ => return None,
        }
    }
    match (command.as_str(), home, lock_dir) {
        ("serve", Some(home), Some(lock_dir)) => Some(Command::Serve {
            home,
            lock_dir,
            parent_pid,
        }),
        ("hold-lock", Some(home), Some(lock_dir)) if parent_pid.is_none() => {
            Some(Command::HoldLock { home, lock_dir })
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
    fn the_two_forms() {
        assert_eq!(
            parse_str(&[
                "serve",
                "--home",
                "h",
                "--lock-dir",
                "l",
                "--parent-pid",
                "7"
            ]),
            Some(Command::Serve {
                home: "h".into(),
                lock_dir: "l".into(),
                parent_pid: Some(7),
            })
        );
        assert_eq!(
            parse_str(&["serve", "--lock-dir", "l", "--home", "h"]),
            Some(Command::Serve {
                home: "h".into(),
                lock_dir: "l".into(),
                parent_pid: None,
            })
        );
        assert_eq!(
            parse_str(&["hold-lock", "--home", "h", "--lock-dir", "l"]),
            Some(Command::HoldLock {
                home: "h".into(),
                lock_dir: "l".into(),
            })
        );
    }

    #[test]
    fn usage_errors() {
        for args in [
            &[][..],
            &["serve"],
            &["serve", "--home", "h"],
            &["serve", "--lock-dir", "l"],
            &["serve", "--home", "h", "--home", "i", "--lock-dir", "l"],
            &["serve", "--home", "h", "--lock-dir", "l", "--parent-pid"],
            &[
                "serve",
                "--home",
                "h",
                "--lock-dir",
                "l",
                "--parent-pid",
                "x",
            ],
            &[
                "serve",
                "--home",
                "h",
                "--lock-dir",
                "l",
                "--network",
                "direct",
            ],
            &["serve", "--data-dir", "h", "--lock-dir", "l"],
            &["hold-lock", "--home", "h"],
            &[
                "hold-lock",
                "--home",
                "h",
                "--lock-dir",
                "l",
                "--parent-pid",
                "7",
            ],
            &["start", "--home", "h", "--lock-dir", "l"],
        ] {
            assert_eq!(parse_str(args), None, "{args:?}");
        }
    }
}
