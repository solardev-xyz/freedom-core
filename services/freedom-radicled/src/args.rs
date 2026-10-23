//! The command line (design 0008, "Spawn and lock").
//!
//! ```text
//! freedom-radicled serve     --home <dir> --lock-dir <dir> --network <policy> [--parent-pid <pid>]
//! freedom-radicled hold-lock --home <dir> --lock-dir <dir>
//! ```
//!
//! Each flag appears at most once. `--home` is the profile's Radicle home
//! (`getRadicleDataDir()`), whose canonical path keys the gate. `--network`
//! is 0007's forms (`fc_service::network`): `serve` takes it, `hold-lock`
//! none.

use std::ffi::OsString;
use std::path::PathBuf;

use fc_service::network::NetworkPolicy;

pub const USAGE: &str = "usage: freedom-radicled serve --home <dir> --lock-dir <dir> --network (direct | socks5:<ip>:<port>) [--parent-pid <pid>] | freedom-radicled hold-lock --home <dir> --lock-dir <dir>";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Serve {
        home: PathBuf,
        lock_dir: PathBuf,
        network: NetworkPolicy,
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
    while let Some(flag) = args.next() {
        match flag.to_str()? {
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
    match (command.as_str(), home, lock_dir, network) {
        ("serve", Some(home), Some(lock_dir), Some(network)) => Some(Command::Serve {
            home,
            lock_dir,
            network,
            parent_pid,
        }),
        ("hold-lock", Some(home), Some(lock_dir), None) if parent_pid.is_none() => {
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
        ] {
            assert_eq!(parse_str(args), None, "{args:?}");
        }
    }
}
