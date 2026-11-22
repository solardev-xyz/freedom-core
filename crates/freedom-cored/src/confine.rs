//! `serve`'s, `hold-lock`'s and `recover`'s own confinement (design 0017),
//! with 0010's mechanisms (`fc_service::confine`).
//!
//! - **The order** (0017, "The order in serve"): at entry, `clean_entry`
//!   drops inherited descriptors (one re-exec on Linux and macOS); then the
//!   arguments, the gate and the setup, on the process's only thread, with
//!   log lines written directly; then [`apply`], while the process is still
//!   one thread; only then the logging thread and every other.
//! - **The grant (C2):** read-write on the directories the caller names
//!   ([`policy`]), and nothing else but the system reads `confine` always
//!   grants; no network (no socket of any family), no process, no local
//!   IPC but stdio. The lock directory isn't granted (C3): the gate and the
//!   Radicle gate files cross as descriptors opened before.
//! - **Modes (C4):** a narrowing to owner-only on a descriptor is allowed
//!   (`fchmod` without group, other or special bits, on Linux; in the
//!   read-write grants, on macOS), which is all the vault's, the node
//!   layout's and the intent journal's tightening does once confined.
//! - **D2:** a mechanism the OS lacks, or that something outside refuses,
//!   is reported and the process runs; the report is logged, and `serve`'s
//!   goes back in `core.hello`'s answer. A refusal of the confinement
//!   itself (a second thread, a descriptor it can't account for, rules
//!   refused halfway) is exit 77.

use std::path::PathBuf;

use fc_service::confine::{self, Network, Policy, Report, Resolver};

use crate::exit::Exit;
use crate::log;

/// C2's policy: read-write on `read_write`, each of which must exist, and
/// the descriptors opened before `confine` and kept (`descriptors`).
/// Nothing read-only, no rename across directories (`refer`), no symlink
/// made, no file time set, offline, no name resolution, and owner-only
/// mode changes (`modes`).
///
/// A test build adds the directories of the test hooks' files, and `refer`
/// for `FREEDOM_CORED_TEST_SWAP`'s renames
/// ([`crate::testhooks::core_hook_grant`]): nothing without the `testhooks`
/// feature, nor without those variables.
pub fn policy(mut read_write: Vec<PathBuf>, descriptors: Vec<i32>) -> Policy {
    let (hook_dirs, refer) = crate::testhooks::core_hook_grant();
    read_write.extend(hook_dirs);
    Policy {
        read_write,
        read_only: Vec::new(),
        read_only_dirs: Vec::new(),
        refer,
        // `refer` is Landlock's from ABI 2.
        min_abi: if refer { 2 } else { 1 },
        network: Network::Offline,
        resolver: Resolver::None,
        descriptors,
        interface_index: false,
        times: false,
        symlinks: false,
        modes: true,
    }
}

/// Confines the process to `policy` and logs the report under `confined`;
/// an [`confine::Invalid`] is logged and is exit 77 (`confinement`).
pub fn apply(policy: &Policy, confined: &'static str) -> Result<Report, Exit> {
    match confine::confine(policy) {
        Ok(report) => {
            log::info(
                confined,
                serde_json::json!({ "confinement": report.to_json() }),
            );
            crate::testhooks::core_confined(&report);
            Ok(report)
        }
        Err(invalid) => {
            log::error(
                "confinement refused the process",
                serde_json::json!({ "reason": invalid.to_string() }),
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    /// C2's table, as built: only the directories given (no test hook's
    /// variable is set in a unit test), and every other field fixed.
    #[test]
    fn the_policy_is_c2s() {
        let dirs = vec![PathBuf::from("/a/identity"), PathBuf::from("/a/freedom")];
        assert_eq!(
            policy(dirs.clone(), vec![3, 4]),
            Policy {
                read_write: dirs,
                read_only: Vec::new(),
                read_only_dirs: Vec::new(),
                refer: false,
                min_abi: 1,
                network: Network::Offline,
                resolver: Resolver::None,
                descriptors: vec![3, 4],
                interface_index: false,
                times: false,
                symlinks: false,
                modes: true,
            }
        );
    }
}
