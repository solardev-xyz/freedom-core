//! The command line (design 0008, "Spawn and lock").
//!
//! ```text
//! freedom-radicled serve     --home <dir> --lock-dir <dir> --network <policy> [--parent-pid <pid>]
//! freedom-radicled import    --home <dir> --lock-dir <dir> --source <path> [--protected <dir>]… [--parent-pid <pid>]
//! freedom-radicled hold-lock --home <dir> --lock-dir <dir>
//! ```
//!
//! Each flag appears at most once, but `--protected`, which `import` takes
//! any number of times. `--home` is the profile's Radicle home
//! (`getRadicleDataDir()`), whose canonical path keys the gate. `--network`
//! is 0007's forms (`fc_service::network`): `serve` takes it, `import` and
//! `hold-lock` none (the import process has no network: design 0010, D5).
//! `--source` is the working copy the import reads, as main names it, and
//! each `--protected` one of main's protected roots (0010, "The
//! recommendation", step 7), which none of the import's roots may be,
//! contain, or lie inside.

use std::ffi::OsString;
use std::path::PathBuf;

use fc_service::network::NetworkPolicy;

pub const USAGE: &str = "usage: freedom-radicled serve --home <dir> --lock-dir <dir> --network (direct | socks5:<ip>:<port>) [--parent-pid <pid>] | freedom-radicled import --home <dir> --lock-dir <dir> --source <path> [--protected <dir>]... [--parent-pid <pid>] | freedom-radicled hold-lock --home <dir> --lock-dir <dir>";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Serve {
        home: PathBuf,
        lock_dir: PathBuf,
        network: NetworkPolicy,
        parent_pid: Option<u32>,
    },
    Import {
        home: PathBuf,
        lock_dir: PathBuf,
        /// The working copy, as main named it: `rad.import_repo`'s `path`
        /// must be this, exactly.
        source: OsString,
        protected: Vec<PathBuf>,
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
    let mut network = None;
    let mut source = None;
    let mut protected = Vec::new();
    while let Some(flag) = args.next() {
        match flag.to_str()? {
            "--source" if source.is_none() => source = Some(args.next()?),
            "--protected" => protected.push(PathBuf::from(args.next()?)),
            "--home" if home.is_none() => home = Some(PathBuf::from(args.next()?)),
            "--lock-dir" if lock_dir.is_none() => lock_dir = Some(PathBuf::from(args.next()?)),
            "--parent-pid" if parent_pid.is_none() => {
                parent_pid = Some(args.next()?.to_str()?.parse::<u32>().ok()?);
            }
            "--network" if network.is_none() => {
                network = Some(NetworkPolicy::parse(args.next()?.to_str()?)?);
            }
            _ => return None,
        }
    }
    let import_only = source.is_some() || !protected.is_empty();
    match (command.as_str(), home, lock_dir, network) {
        ("serve", Some(home), Some(lock_dir), Some(network)) if !import_only => {
            Some(Command::Serve {
                home,
                lock_dir,
                network,
                parent_pid,
            })
        }
        ("import", Some(home), Some(lock_dir), None) => Some(Command::Import {
            home,
            lock_dir,
            source: source.filter(|s| !s.is_empty())?,
            protected,
            parent_pid,
        }),
        ("hold-lock", Some(home), Some(lock_dir), None) if parent_pid.is_none() && !import_only => {
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
                "--network",
                "direct",
                "--parent-pid",
                "7"
            ]),
            Some(Command::Serve {
                home: "h".into(),
                lock_dir: "l".into(),
                network: NetworkPolicy::Direct,
                parent_pid: Some(7),
            })
        );
        assert_eq!(
            parse_str(&[
                "serve",
                "--network",
                "socks5:[::1]:9150",
                "--lock-dir",
                "l",
                "--home",
                "h"
            ]),
            Some(Command::Serve {
                home: "h".into(),
                lock_dir: "l".into(),
                network: NetworkPolicy::Socks5 {
                    proxy: "[::1]:9150".parse().unwrap()
                },
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
        assert_eq!(
            parse_str(&[
                "import",
                "--home",
                "h",
                "--protected",
                "p1",
                "--lock-dir",
                "l",
                "--source",
                "s",
                "--protected",
                "p2",
                "--parent-pid",
                "7"
            ]),
            Some(Command::Import {
                home: "h".into(),
                lock_dir: "l".into(),
                source: "s".into(),
                protected: vec!["p1".into(), "p2".into()],
                parent_pid: Some(7),
            })
        );
        assert_eq!(
            parse_str(&["import", "--source", "s", "--home", "h", "--lock-dir", "l"]),
            Some(Command::Import {
                home: "h".into(),
                lock_dir: "l".into(),
                source: "s".into(),
                protected: vec![],
                parent_pid: None,
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
            // `--network` is required, once, and in its forms.
            &["serve", "--home", "h", "--lock-dir", "l"],
            &[
                "serve",
                "--home",
                "h",
                "--lock-dir",
                "l",
                "--network",
                "socks5:localhost:9150",
            ],
            &[
                "hold-lock",
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
            // `import` needs `--source`, once and not empty, and takes no
            // `--network`; the others take neither `--source` nor
            // `--protected`.
            &["import", "--home", "h", "--lock-dir", "l"],
            &["import", "--home", "h", "--lock-dir", "l", "--source", ""],
            &[
                "import",
                "--home",
                "h",
                "--lock-dir",
                "l",
                "--source",
                "s",
                "--source",
                "t",
            ],
            &[
                "import",
                "--home",
                "h",
                "--lock-dir",
                "l",
                "--source",
                "s",
                "--network",
                "direct",
            ],
            &["import", "--home", "h", "--lock-dir", "l", "--protected"],
            &[
                "serve",
                "--home",
                "h",
                "--lock-dir",
                "l",
                "--network",
                "direct",
                "--source",
                "s",
            ],
            &[
                "hold-lock",
                "--home",
                "h",
                "--lock-dir",
                "l",
                "--protected",
                "p",
            ],
        ] {
            assert_eq!(parse_str(args), None, "{args:?}");
        }
    }
}
