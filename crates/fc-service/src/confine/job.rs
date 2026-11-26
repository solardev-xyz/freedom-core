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
//! - **`memory_cap`:** the job's memory limit as read back, where the policy
//!   asks for one; null, with the job's reason, where something outside
//!   refused the job (design 0010, "The memory cap").

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
    /// its immediate job allows one active process and no breakaway, and
    /// commits at most `job_memory` bytes where the policy has a memory cap.
    Limited { job_memory: Option<u64> },
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

/// The report for `network` and the policy's `memory_cap`, from the job's
/// and each mitigation's outcome.
pub fn report(
    network: Network,
    memory_cap: Option<u64>,
    job: &JobOutcome,
    mitigations: &[(&'static str, MitigationOutcome)],
) -> Report {
    let mut gaps = Vec::new();
    let mut reasons = BTreeMap::new();
    let exec = match job {
        JobOutcome::Limited { .. } => {
            gaps.push(PARENT_PROCESS);
            Status::Partial
        }
        JobOutcome::Blocked(why) => {
            reasons.insert("exec", why.clone());
            Status::Blocked
        }
    };
    let memory_cap = memory_cap.map(|_| match job {
        JobOutcome::Limited { job_memory } => *job_memory,
        JobOutcome::Blocked(why) => {
            reasons.insert("memory_cap", why.clone());
            None
        }
    });
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
            JobOutcome::Limited { .. } => "job",
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
        memory_cap,
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

    /// The job in place, without a memory limit: `freedom-cored`'s.
    const LIMITED: JobOutcome = JobOutcome::Limited { job_memory: None };

    #[test]
    fn the_job_in_place_is_named_with_its_gap_and_every_mitigation() {
        let report = report(Network::Direct, None, &LIMITED, &all_set());
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

    /// The memory cap as the job's limit read back (design 0010, "The
    /// memory cap"); null with the job's reason where something outside
    /// refused the job.
    #[test]
    fn the_memory_cap_is_the_job_s_limit_read_back() {
        let cap = crate::confine::MEMORY_CAP;
        let limited = JobOutcome::Limited {
            job_memory: Some(cap),
        };
        let json = report(Network::Direct, Some(cap), &limited, &all_set()).to_json();
        assert_eq!(json["memory_cap"], json!(2_147_483_648_u64));
        assert!(json["reasons"].get("memory_cap").is_none());
        let refused = JobOutcome::Blocked("nesting refused".into());
        let blocked = report(Network::Direct, Some(cap), &refused, &all_set());
        assert_eq!(blocked.memory_cap, Some(None));
        assert_eq!(blocked.reasons["memory_cap"], "nesting refused");
        assert_eq!(blocked.to_json()["memory_cap"], serde_json::Value::Null);
    }

    #[test]
    fn socks5_has_no_rule_here() {
        let port = Network::Socks5 {
            port: 9050,
            loopback: true,
        };
        for network in [port, Network::Offline] {
            let report = report(network, None, &LIMITED, &all_set());
            assert_eq!(report.network, Status::Unavailable);
            assert_eq!(report.reasons["network"], NO_NETWORK_RULE);
        }
    }

    #[test]
    fn a_refused_job_is_blocked_and_names_no_mechanism() {
        let job = JobOutcome::Blocked("nesting refused".into());
        let report = report(Network::Direct, None, &job, &all_set());
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
        let report = report(Network::Direct, None, &LIMITED, &mitigations);
        assert_eq!(report.mitigations["image_load"], Mitigation::Missing);
        assert_eq!(report.reasons["image_load"], "unknown policy");
        for name in ["dynamic_code", "extension_points"] {
            assert_eq!(report.mitigations[name], Mitigation::Set);
            assert!(!report.reasons.contains_key(name));
        }
        assert_eq!(report.exec, Status::Partial);
    }
}
