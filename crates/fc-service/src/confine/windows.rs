//! Confinement on Windows, step 1 (design 0010, "Windows", D4), self-applied
//! through `fc-sys`:
//! - **a job object** that allows one active process and no breakaway,
//!   nested in any job the process is in already (libuv puts each child of
//!   main in a job of its own, which allows breakaway: an inner job that
//!   doesn't keeps its children in). No UI restrictions, which a nested job
//!   may not have. Once it reads back, the process's one handle to it is
//!   closed, so nothing in the process can change its limits; the job lives
//!   on while the process is in it;
//! - **the process mitigation policies:** no dynamic code; no image from a
//!   remote device or with a low mandatory label, and System32 first; no
//!   legacy extension points. Each is set, then read back, alone: one the OS
//!   doesn't know is missing, and the others stand.
//!
//! Both are process-wide, so a thread started before them gets no way round
//! them, and `confine` doesn't count threads here: Windows's loader starts
//! worker threads of its own at process start. The report is [`super::job`]'s.

use std::io;

use fc_sys::windows::{
    DISABLE_EXTENSION_POINTS, Job, Limits, Mitigation, NO_LOW_LABEL_IMAGES, NO_REMOTE_IMAGES,
    PREFER_SYSTEM32_IMAGES, PROHIBIT_DYNAMIC_CODE, limit,
};

use super::job::{self, JobOutcome, MitigationOutcome};
use super::{Invalid, Options, Policy, Report};

/// Each mitigation, by its report name, with the flags set for it.
const MITIGATIONS: [(&str, Mitigation, u32); 3] = [
    (
        "dynamic_code",
        Mitigation::DynamicCode,
        PROHIBIT_DYNAMIC_CODE,
    ),
    (
        "image_load",
        Mitigation::ImageLoad,
        NO_REMOTE_IMAGES | NO_LOW_LABEL_IMAGES | PREFER_SYSTEM32_IMAGES,
    ),
    (
        "extension_points",
        Mitigation::ExtensionPoints,
        DISABLE_EXTENSION_POINTS,
    ),
];

/// The job's limits: one active process, the service itself.
const ONE_PROCESS: Limits = Limits {
    flags: limit::ACTIVE_PROCESS,
    active_processes: 1,
};

pub(super) fn confine(policy: &Policy, options: &Options) -> Result<Report, Invalid> {
    let job = limit_to_one_process(options)?;
    let mitigations: Vec<(&'static str, MitigationOutcome)> = MITIGATIONS
        .into_iter()
        .map(|(name, mitigation, flags)| {
            (name, mitigate(mitigation, flags, options.mitigation_error))
        })
        .collect();
    Ok(job::report(policy.network, &job, &mitigations))
}

/// Puts the process in a new job of [`ONE_PROCESS`], nested in its own,
/// and reads it back. Something outside refusing the job is
/// [`JobOutcome::Blocked`] (D2: the service runs). The job refusing its own
/// limit, or a job assigned that doesn't read back, is [`Invalid`].
fn limit_to_one_process(options: &Options) -> Result<JobOutcome, Invalid> {
    if let Some(code) = options.job_error {
        return Ok(JobOutcome::Blocked(format!(
            "the job: {}",
            io::Error::from_raw_os_error(code)
        )));
    }
    let job = match Job::new() {
        Ok(job) => job,
        Err(error) => return Ok(JobOutcome::Blocked(format!("CreateJobObject: {error}"))),
    };
    job.set_limits(ONE_PROCESS)
        .map_err(|error| Invalid::Rules(format!("the job refused its limit: {error}")))?;
    if let Err(error) = job.assign_current_process() {
        // Before it, the process is in no new job: nothing is half-done.
        return Ok(JobOutcome::Blocked(format!(
            "the job can't be nested in the process's own (AssignProcessToJobObject: {error})"
        )));
    }
    // Assigned, for good: it must read back, or the process exits 77. The
    // immediate job is the innermost, the one whose limit a new child of
    // the process meets first.
    let held = job.holds_current_process();
    let own = fc_sys::windows::own_job_limits();
    let breakaway = limit::BREAKAWAY_OK | limit::SILENT_BREAKAWAY_OK;
    match (&held, &own) {
        (Ok(true), Ok(own))
            if own.flags & limit::ACTIVE_PROCESS != 0
                && own.active_processes == 1
                && own.flags & breakaway == 0 =>
        {
            // `job` drops here: the process's one handle to its job closes.
            Ok(JobOutcome::Limited)
        }
        _ => Err(Invalid::Rules(format!(
            "the job was assigned, but doesn't read back: in it {}, its limits {}",
            match &held {
                Ok(held) => held.to_string(),
                Err(error) => error.to_string(),
            },
            match &own {
                Ok(own) => format!("{:#x} with {} processes", own.flags, own.active_processes),
                Err(error) => error.to_string(),
            },
        ))),
    }
}

/// Sets `mitigation` to `flags`, unless `forced` pretends that failed, and
/// reads it back: `Set` only with every flag there.
fn mitigate(mitigation: Mitigation, flags: u32, forced: Option<i32>) -> MitigationOutcome {
    let set = match forced {
        Some(code) => Err(io::Error::from_raw_os_error(code)),
        None => mitigation.set(flags),
    };
    match mitigation.get() {
        Ok(read) if read & flags == flags => MitigationOutcome::Set,
        Ok(read) => MitigationOutcome::Missing(match set {
            Err(error) => format!("SetProcessMitigationPolicy: {error}"),
            Ok(()) => format!(
                "set, but reads back {read:#x}, without {:#x}",
                flags & !read
            ),
        }),
        Err(error) => MitigationOutcome::Missing(format!("GetProcessMitigationPolicy: {error}")),
    }
}
