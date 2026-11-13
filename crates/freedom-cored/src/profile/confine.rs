//! Each profile subcommand's confinement (design 0013, 5.1: "Each confines
//! itself with 0010's mechanisms before it reads anything"; 0010).
//!
//! - **What it gets:** read-write on the directories its run writes (the
//!   app root, and in a dev build the `R/` root beside it for a delete;
//!   the profile's directory for `migrate`), read-only on the ones it only
//!   reads (the lock directory for a gate's probe, the app root for `list`
//!   and `reserved-ports`), no network (no socket of any family) and no
//!   child process. `hold-profile` gets nothing but its stdin and stdout,
//!   and the gate's descriptor. A directory that isn't there gets no grant:
//!   nothing in it can be read.
//! - **When:** after the setup that confinement would refuse and before
//!   the run reads the catalog or a profile's files: after the gates are
//!   taken (taking one may tighten a directory's mode, which confinement
//!   refuses), and while the process is still one thread, before the
//!   catalog lock's refresher starts ([`super::lock::Lock::keep`]). Logging
//!   writes its lines directly: its writer thread never starts in a
//!   subcommand.
//! - **The lock's mtime:** a run that takes proper-lockfile's lock sets its
//!   directory's mtime (the precision probe and each refresh), so its
//!   policy has `times` (fc-service's [`Policy::times`]): on Linux,
//!   `futimens` on a descriptor alone, and on macOS file times in the
//!   read-write grants alone.
//! - **Renames across directories** (Landlock's `refer`, ABI 2) for the
//!   runs that move things: a delete's fence and `migrate`'s rollback.
//! - **D2:** a mechanism the OS lacks, or that something outside refuses,
//!   is reported and the run goes on; the report is logged. A refusal of
//!   the confinement itself (a second thread, a descriptor it can't
//!   account for, rules refused halfway) is exit 77, with `{ "error":
//!   "confinement" }` on stdout.

use std::path::{Path, PathBuf};

use fc_json::JsValue;
use fc_service::confine::{self, Network, Policy, Resolver};

use super::{object, print};
use crate::exit::Exit;
use crate::log;

/// What a subcommand may use once confined.
#[derive(Default)]
pub struct Grant {
    read_write: Vec<PathBuf>,
    read_only: Vec<PathBuf>,
    descriptors: Vec<i32>,
    refer: bool,
    times: bool,
}

impl Grant {
    /// Nothing at all: no file, no network, no process.
    pub fn none() -> Grant {
        Grant::default()
    }

    /// A run that takes proper-lockfile's lock: its mtime is set.
    pub fn locking() -> Grant {
        Grant {
            times: true,
            ..Grant::default()
        }
    }

    /// `dir` read and written, if it is a directory.
    pub fn read_write(mut self, dir: &Path) -> Grant {
        if dir.is_dir() {
            self.read_write.push(dir.to_owned());
        }
        self
    }

    /// `path` only read, if it is there.
    pub fn read_only(mut self, path: &Path) -> Grant {
        if path.exists() {
            self.read_only.push(path.to_owned());
        }
        self
    }

    /// Descriptors opened before confinement and kept: the gates' locks.
    pub fn descriptors(mut self, descriptors: impl IntoIterator<Item = i32>) -> Grant {
        self.descriptors.extend(descriptors);
        self
    }

    /// Renames across the read-write directories.
    pub fn refer(mut self) -> Grant {
        self.refer = true;
        self
    }

    fn policy(self) -> Policy {
        let mut read_write = self.read_write;
        read_write.extend(crate::testhooks::profile_hook_dirs());
        Policy {
            read_write,
            read_only: self.read_only,
            read_only_dirs: Vec::new(),
            refer: self.refer,
            // `refer` is Landlock's from ABI 2: below it, a rename across
            // directories would be refused, so no rules are applied there.
            min_abi: if self.refer { 2 } else { 1 },
            network: Network::Offline,
            resolver: Resolver::None,
            descriptors: self.descriptors,
            interface_index: false,
            times: self.times,
        }
    }
}

/// Confines the process to `grant`, or ends the run with exit 77.
pub fn confine(grant: Grant) -> Result<(), Exit> {
    match confine::confine(&grant.policy()) {
        Ok(report) => {
            log::info(
                "profile subcommand confined",
                serde_json::json!({ "confinement": report.to_json() }),
            );
            crate::testhooks::profile_confined(&report);
            Ok(())
        }
        Err(invalid) => {
            log::error(
                "confinement refused the process",
                serde_json::json!({ "reason": invalid.to_string() }),
            );
            let _ = print(&object(vec![("error", JsValue::string("confinement"))]));
            Err(Exit::Confinement)
        }
    }
}

/// How the entry went (fc-service's `clean_entry`), logged as the services
/// log it. Whatever is left, `confine` refuses.
pub fn log_entry(entry: &confine::Entry) {
    match entry {
        confine::Entry::Clean => {}
        confine::Entry::Reexeced => log::info(
            "re-executed once at entry: descriptors were inherited",
            serde_json::json!({}),
        ),
        confine::Entry::Replaced => log::error(
            "re-executed at entry, but not from the file that ran: confinement refuses it",
            serde_json::json!({}),
        ),
        confine::Entry::Left { reexeced, error } => log::error(
            "descriptors inherited at entry are left",
            serde_json::json!({
                "reexeced": reexeced,
                "error": error.as_ref().map(|e| e.kind().to_string()),
            }),
        ),
    }
}
