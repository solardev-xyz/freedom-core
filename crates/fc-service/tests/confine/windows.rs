//! Confinement on Windows through a real process (design 0010, Tests): each
//! case in a child of its own, which confines itself as a service does,
//! tries what the case names, and prints one line per check.
//!
//! The parent first puts each child in a job of its own, as libuv puts each
//! child of main in one (`uv_spawn`: breakaway allowed, silently too, and
//! the children killed when the job closes). Confinement's job then nests
//! inside it, and its limit holds even though the outer job lets children
//! break away. One case runs with no outer job, as a service started from a
//! terminal would.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::panic
)]

use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::AsHandle;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};

use fc_service::confine::{self, Mitigation, Network, Options, Policy, Resolver, Status};
use fc_sys::windows::{self as sys, Job, Limits, limit};

const CASE: &str = "FC_CONFINE_CASE";

/// `CREATE_BREAKAWAY_FROM_JOB`: a child that asks to leave the job.
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

/// libuv's job for each child it spawns (`uv__init_global_job_handle`).
const LIBUV_JOB: Limits = Limits {
    flags: limit::BREAKAWAY_OK
        | limit::SILENT_BREAKAWAY_OK
        | limit::DIE_ON_UNHANDLED_EXCEPTION
        | limit::KILL_ON_JOB_CLOSE,
    active_processes: 0,
};

/// The mitigations the service sets, by report name, with their flags.
const MITIGATIONS: [(&str, sys::Mitigation, u32); 3] = [
    (
        "dynamic_code",
        sys::Mitigation::DynamicCode,
        sys::PROHIBIT_DYNAMIC_CODE,
    ),
    (
        "image_load",
        sys::Mitigation::ImageLoad,
        sys::NO_REMOTE_IMAGES | sys::NO_LOW_LABEL_IMAGES | sys::PREFER_SYSTEM32_IMAGES,
    ),
    (
        "extension_points",
        sys::Mitigation::ExtensionPoints,
        sys::DISABLE_EXTENSION_POINTS,
    ),
];

pub fn main() {
    if let Ok(case) = std::env::var(CASE) {
        child(&case);
        return;
    }
    parent();
}

// -------------------------------------------------------------------
// The child.

fn check(name: &str, ok: bool) {
    println!("{} {name}", if ok { "OK" } else { "FAIL" });
}

/// Runs `cmd.exe /d /c exit 0` with `flags`: whether it ran and exited 0,
/// or the spawn's error.
fn run_cmd(flags: u32) -> std::io::Result<bool> {
    Command::new("cmd.exe")
        .args(["/d", "/c", "exit 0"])
        .creation_flags(flags)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
}

/// A spawn's outcome for the log: `ran`, or the Win32 error.
fn outcome(spawned: &std::io::Result<bool>) -> String {
    match spawned {
        Ok(ok) => format!("ran (success {ok})"),
        Err(error) => format!("refused (error {:?}: {error})", error.raw_os_error()),
    }
}

fn read_line() -> String {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    line
}

fn child(case: &str) {
    // The parent puts this process in its job first, as libuv does before
    // a child runs, then says so.
    read_line();
    println!("START");
    let policy = Policy {
        read_write: Vec::new(),
        read_only: Vec::new(),
        read_only_dirs: Vec::new(),
        refer: false,
        min_abi: 1,
        network: Network::Direct,
        resolver: Resolver::None,
        descriptors: Vec::new(),
        interface_index: false,
    };
    match case {
        "control" => {
            // Unconfined, under libuv's job alone: cmd.exe runs.
            let spawned = run_cmd(0);
            println!("SPAWN {}", outcome(&spawned));
            check("cmd.exe runs unconfined", matches!(spawned, Ok(true)));
        }
        "confined" | "confined-alone" => {
            // A thread started before `confine` changes nothing on Windows:
            // both mechanisms are process-wide.
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let thread = std::thread::spawn(move || {
                let _ = rx.recv();
                run_cmd(0)
            });
            let report = confine::confine(&policy).unwrap();
            println!("REPORT {}", report.to_json());
            check("the mechanism is the job", report.mechanism == "job");
            check(
                "exec is partial, its gap named",
                report.exec == Status::Partial && report.gaps == ["parent_process"],
            );
            check(
                "files and ipc are unavailable, with reasons",
                report.files == Status::Unavailable
                    && report.ipc == Status::Unavailable
                    && report.reasons.contains_key("files")
                    && report.reasons.contains_key("ipc"),
            );
            check(
                "network is none in direct mode",
                report.network == Status::None,
            );
            for (name, mitigation, flags) in MITIGATIONS {
                check(
                    &format!("{name} is reported set"),
                    report.mitigations.get(name) == Some(&Mitigation::Set),
                );
                // Asked of the OS again, here.
                let read = mitigation.get();
                println!("MITIGATION {name} {read:?}");
                check(
                    &format!("{name} reads back as set"),
                    read.is_ok_and(|read| read & flags == flags),
                );
            }
            let own = sys::own_job_limits();
            println!("JOB {own:?}");
            check(
                "the immediate job allows one process and no breakaway",
                own.is_ok_and(|own| {
                    own.flags & limit::ACTIVE_PROCESS != 0
                        && own.active_processes == 1
                        && own.flags & (limit::BREAKAWAY_OK | limit::SILENT_BREAKAWAY_OK) == 0
                }),
            );
            let spawned = run_cmd(0);
            println!("SPAWN {}", outcome(&spawned));
            check("cmd.exe is refused", spawned.is_err());
            check(
                "by the job's limit (ERROR_NOT_ENOUGH_QUOTA)",
                spawned
                    .as_ref()
                    .err()
                    .and_then(std::io::Error::raw_os_error)
                    == Some(1816),
            );
            let breakaway = run_cmd(CREATE_BREAKAWAY_FROM_JOB);
            println!("SPAWN BREAKAWAY {}", outcome(&breakaway));
            check("cmd.exe is refused, breaking away too", breakaway.is_err());
            drop(tx);
            let earlier = thread.join().unwrap();
            println!("SPAWN EARLIER THREAD {}", outcome(&earlier));
            check(
                "cmd.exe is refused from a thread started before",
                earlier.is_err(),
            );
            // The parent checks this process is still in its job, then lets
            // it end.
            println!("WAITING");
            read_line();
        }
        "forced" => {
            // D2: something outside refuses the job, and the OS every
            // mitigation. The report says so, and the service runs.
            let options = Options {
                job_error: Some(5),
                mitigation_error: Some(87),
                ..Options::default()
            };
            let report = confine::confine_with(&policy, &options).unwrap();
            println!("REPORT {}", report.to_json());
            check(
                "exec is blocked, with its reason, and no mechanism named",
                report.exec == Status::Blocked
                    && report.reasons.contains_key("exec")
                    && report.mechanism == "none"
                    && report.gaps.is_empty(),
            );
            for (name, _, _) in MITIGATIONS {
                check(
                    &format!("{name} is missing, with its reason"),
                    report.mitigations.get(name) == Some(&Mitigation::Missing)
                        && report.reasons.contains_key(name),
                );
            }
            // Nothing was applied: honestly reported, cmd.exe still runs.
            let spawned = run_cmd(0);
            println!("SPAWN {}", outcome(&spawned));
            check("cmd.exe runs", matches!(spawned, Ok(true)));
        }
        _ => panic!("unknown case {case}"),
    }
    println!("END");
}

// -------------------------------------------------------------------
// The parent.

/// Runs `case` in a child, inside `outer` if given: its lines, with the
/// parent's own checks among them.
fn run(case: &str, outer: Option<&Job>) -> Vec<String> {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .env(CASE, case)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut lines = Vec::new();
    if let Some(outer) = outer {
        outer.assign(child.as_handle()).unwrap();
        let held = outer.holds(child.as_handle()).unwrap();
        lines.push(format!(
            "{} in the outer job",
            if held { "OK" } else { "FAIL" }
        ));
    }
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "go").unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    for line in stdout.lines() {
        let line = line.unwrap();
        if line == "WAITING" {
            // Confinement's job nested inside the outer one: the child is in
            // both.
            if let Some(outer) = outer {
                let held = outer.holds(child.as_handle()).unwrap();
                lines.push(format!(
                    "{} still in the outer job, confined",
                    if held { "OK" } else { "FAIL" }
                ));
            }
            writeln!(stdin, "end").unwrap();
            continue;
        }
        lines.push(line);
    }
    let status = child.wait().unwrap();
    lines.push(format!(
        "{} exit {status}",
        if status.success() { "OK" } else { "FAIL" }
    ));
    lines
}

fn parent() {
    let outer = Job::new().unwrap();
    outer.set_limits(LIBUV_JOB).unwrap();
    let cases = [
        ("control", Some(&outer)),
        ("confined", Some(&outer)),
        ("confined-alone", None),
        ("forced", Some(&outer)),
    ];
    let mut failed = Vec::new();
    for (case, outer) in cases {
        let lines = run(case, outer);
        let complete =
            lines.iter().any(|line| line == "START") && lines.iter().any(|line| line == "END");
        for line in &lines {
            eprintln!("confine {case}: {line}");
        }
        if !complete || lines.iter().any(|line| line.starts_with("FAIL")) {
            failed.push(case);
        }
    }
    assert!(failed.is_empty(), "confine: failed cases {failed:?}");
    eprintln!("confine: {} cases passed", cases.len());
}
