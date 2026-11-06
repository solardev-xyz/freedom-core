//! Windows's report, step 1 (design 0010, "Windows", D4): each status from
//! what the job object and the mitigation policies read back
//! ([`super::windows`] applies them). Derived and tested on every OS, as the
//! Seatbelt profile is generated on every OS.
//!
//! - **`exec`:** with the job in place, `partial`, with the gap
//!   [`PARENT_PROCESS`]. The job refuses every process the service creates
//!   as its own child. But a process created with another process as its
//!   parent (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) takes that process's
//!   job, not the service's, and the service runs with the user's own
//!   token, so it can open any of the user's processes to name one, main
//!   included. A restricted token (a later step) closes that.
//! - **`files` and `ipc`:** `unavailable`: they need a restricted token or
//!   AppContainer, a later step.
//! - **`network`:** in `socks5` mode `unavailable`: nothing here names a
//!   port. The service's own gate enforces the policy (0007).
//! - **The mitigations** are reported by name, each `set` only when it read
//!   back with every flag asked for.

use std::collections::BTreeMap;

use super::{Mitigation, Network, Report, Status};

/// The gap `exec` leaves with the job in place: a process created with
/// another of the user's processes as its parent.
pub const PARENT_PROCESS: &str = "parent_process";

/// Why `files` and `ipc` are `unavailable` on Windows.
pub const LATER_STEP: &str =
    "needs a restricted token or AppContainer, a later step (design 0010, D4)";

/// Why `network` is `unavailable` on Windows in `socks5` mode.
pub const NO_NETWORK_RULE: &str = "no per-process network rule on Windows without AppContainer; the service's gate enforces the policy";

/// How the job went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobOutcome {
    /// Assigned to the process, and read back: the process is in it, and
    /// its immediate job allows one active process and no breakaway.
    Limited,
    /// Something outside refused it: creating the job, or nesting it in the
    /// process's own (an outer job with UI restrictions). Why.
    Blocked(String),
}

/// How one mitigation went: read back with every flag asked for, or
/// missing, with why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MitigationOutcome {
    Set,
    Missing(String),
}

/// The report for `network`, from the job's and each mitigation's outcome.
pub fn report(
    network: Network,
    job: &JobOutcome,
    mitigations: &[(&'static str, MitigationOutcome)],
) -> Report {
    let mut gaps = Vec::new();
    let mut reasons = BTreeMap::new();
    let exec = match job {
        JobOutcome::Limited => {
            gaps.push(PARENT_PROCESS);
            Status::Partial
        }
        JobOutcome::Blocked(why) => {
            reasons.insert("exec", why.clone());
            Status::Blocked
        }
    };
    for property in ["files", "ipc"] {
        reasons.insert(property, LATER_STEP.to_owned());
    }
    let network = match network {
        Network::Direct => Status::None,
        Network::Socks5 { .. } | Network::Offline => {
            reasons.insert("network", NO_NETWORK_RULE.to_owned());
            Status::Unavailable
        }
    };
    let mut applied = BTreeMap::new();
    for (name, outcome) in mitigations {
        let status = match outcome {
            MitigationOutcome::Set => Mitigation::Set,
            MitigationOutcome::Missing(why) => {
                reasons.insert(*name, why.clone());
                Mitigation::Missing
            }
        };
        applied.insert(*name, status);
    }
    Report {
        mechanism: match job {
            JobOutcome::Limited => "job",
            JobOutcome::Blocked(_) => "none",
        }
        .into(),
        files: Status::Unavailable,
        exec,
        ipc: Status::Unavailable,
        network,
        gaps,
        reasons,
        resolution: None,
        mitigations: applied,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn all_set() -> Vec<(&'static str, MitigationOutcome)> {
        ["dynamic_code", "image_load", "extension_points"]
            .into_iter()
            .map(|name| (name, MitigationOutcome::Set))
            .collect()
    }

    #[test]
    fn the_job_in_place_is_named_with_its_gap_and_every_mitigation() {
        let report = report(Network::Direct, &JobOutcome::Limited, &all_set());
        assert_eq!(
            report.to_json(),
            json!({
                "mechanism": "job",
                "files": "unavailable",
                "exec": "partial",
                "ipc": "unavailable",
                "network": "none",
                "gaps": ["parent_process"],
                "reasons": { "files": LATER_STEP, "ipc": LATER_STEP },
                "mitigations": {
                    "dynamic_code": "set",
                    "extension_points": "set",
                    "image_load": "set",
                },
            })
        );
    }

    #[test]
    fn socks5_has_no_rule_here() {
        let port = Network::Socks5 {
            port: 9050,
            loopback: true,
        };
        for network in [port, Network::Offline] {
            let report = report(network, &JobOutcome::Limited, &all_set());
            assert_eq!(report.network, Status::Unavailable);
            assert_eq!(report.reasons["network"], NO_NETWORK_RULE);
        }
    }

    #[test]
    fn a_refused_job_is_blocked_and_names_no_mechanism() {
        let job = JobOutcome::Blocked("nesting refused".into());
        let report = report(Network::Direct, &job, &all_set());
        assert_eq!(report.mechanism, "none");
        assert_eq!(report.exec, Status::Blocked);
        assert_eq!(report.reasons["exec"], "nesting refused");
        assert!(report.gaps.is_empty());
        // The mitigations stand on their own.
        assert!(report.mitigations.values().all(|m| *m == Mitigation::Set));
    }

    #[test]
    fn a_missing_mitigation_says_why_alone() {
        let mut mitigations = all_set();
        mitigations[1].1 = MitigationOutcome::Missing("unknown policy".into());
        let report = report(Network::Direct, &JobOutcome::Limited, &mitigations);
        assert_eq!(report.mitigations["image_load"], Mitigation::Missing);
        assert_eq!(report.reasons["image_load"], "unknown policy");
        for name in ["dynamic_code", "extension_points"] {
            assert_eq!(report.mitigations[name], Mitigation::Set);
            assert!(!report.reasons.contains_key(name));
        }
        assert_eq!(report.exec, Status::Partial);
    }
}
