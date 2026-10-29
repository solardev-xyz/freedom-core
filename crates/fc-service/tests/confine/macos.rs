//! Confinement on macOS through a real process (design 0010, Tests): each
//! case in a child of its own, which confines itself with a Seatbelt
//! profile as a service does, tries what the case names, and prints one
//! line per check. The parent checks from outside what the child must not
//! have changed. A profile Seatbelt can't compile fails every case here
//! first, on the macOS runners.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::panic
)]

use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Output};

use fc_service::confine::{self, Network, Options, Policy, Report};

const CASE: &str = "FC_CONFINE_CASE";

pub fn main() {
    if let Ok(case) = std::env::var(CASE) {
        child(&case);
        return;
    }
    parent();
}

// -------------------------------------------------------------------
// The child.

struct Paths {
    data: PathBuf,
    outside: PathBuf,
    read_only: PathBuf,
    socket: PathBuf,
    allowed_port: u16,
    other_port: u16,
    /// A process outside, with a canary in its environment.
    target_pid: i32,
}

fn paths() -> Paths {
    let var = |name: &str| std::env::var(name).unwrap();
    Paths {
        data: var("FC_DATA").into(),
        outside: var("FC_OUTSIDE").into(),
        read_only: var("FC_READ_ONLY").into(),
        socket: var("FC_SOCKET").into(),
        allowed_port: var("FC_PORT").parse().unwrap(),
        other_port: var("FC_OTHER_PORT").parse().unwrap(),
        target_pid: var("FC_TARGET_PID").parse().unwrap(),
    }
}

fn check(name: &str, ok: bool) {
    println!("{} {name}", if ok { "OK" } else { "FAIL" });
}

fn child(case: &str) {
    println!("START ours={}", marker_is_ours());
    if case == "replaced" && std::env::var_os(confine::REEXEC_MARKER).is_none() {
        // This image executes itself with a marker naming another file's
        // identity, as if the file had been replaced across the re-exec.
        use std::os::unix::process::CommandExt;
        let error = Command::new(std::env::current_exe().unwrap())
            .env(
                confine::REEXEC_MARKER,
                format!("{}:1:1", std::process::id()),
            )
            .exec();
        panic!("exec: {error}");
    }
    let entry = confine::clean_entry();
    println!("ENTRY {}", entry.name());
    let p = paths();
    if case == "ports" {
        // The Mach rights the process holds at the confinement point, for
        // the record (design 0010: they cross, as descriptors would), each
        // named where it can be: the task's special ports, and the system
        // services a task holds one name for, found by looking each up.
        use fc_sys::macos::mach;
        let ports = mach::port_names().unwrap_or_default();
        let mut labels: Vec<(u32, String)> = mach::special_ports()
            .into_iter()
            .map(|(label, name)| (name, label.to_owned()))
            .collect();
        for service in [
            "com.apple.system.notification_center",
            "com.apple.logd",
            "com.apple.diagnosticd",
            "com.apple.system.logger",
            "com.apple.system.opendirectoryd.libinfo",
            "com.apple.system.opendirectoryd.membership",
            "com.apple.cfprefsd.daemon",
            "com.apple.cfprefsd.agent",
            "com.apple.SystemConfiguration.configd",
            "com.apple.SystemConfiguration.DNSConfiguration",
            "com.apple.trustd",
            "com.apple.analyticsd",
            "com.apple.coreservices.launchservicesd",
        ] {
            let Ok(c_name) = std::ffi::CString::new(service) else {
                continue;
            };
            if let Some(name) = mach::look_up_name(&c_name)
                && ports.iter().any(|(held, _)| *held == name)
            {
                labels.push((name, service.to_owned()));
            }
        }
        let named: Vec<String> = ports
            .iter()
            .map(|(name, kind)| {
                let label = labels
                    .iter()
                    .find(|(held, _)| held == name)
                    .map_or("?", |(_, label)| label.as_str());
                format!("{name}:{kind:#x}:{label}")
            })
            .collect();
        println!("PORTS {}", named.join(" "));
    }
    let network = match case {
        "socks5" => Network::Socks5 {
            port: p.allowed_port,
            loopback: true,
        },
        "lan" => Network::Socks5 {
            port: p.allowed_port,
            loopback: false,
        },
        "offline" => Network::Offline,
        _ => Network::Direct,
    };
    let (registered, held) = registered(&p);
    let refer = case == "refer";
    let policy = |p: &Paths, network: Network, descriptors: Vec<i32>| Policy {
        refer,
        ..policy(p, network, descriptors)
    };
    match case {
        "inject-pipe" => {
            let pipe = std::io::pipe().unwrap();
            refused(confine::confine(&policy(&p, network, registered)));
            drop((pipe, held));
            return;
        }
        "thread-first" => {
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let handle = std::thread::spawn(move || {
                let _ = rx.recv();
            });
            refused(confine::confine(&policy(&p, network, registered)));
            drop(tx);
            let _ = handle.join();
            return;
        }
        "invalid" => {
            let options = Options {
                seatbelt_invalid: true,
                ..Options::default()
            };
            refused(confine::confine_with(
                &policy(&p, network, registered),
                &options,
            ));
            return;
        }
        "replaced" | "reexec-left" => {
            refused(confine::confine(&policy(&p, network, registered)));
            return;
        }
        "ephemeral" => {
            let mut ephemeral = policy(&p, network, Vec::new());
            ephemeral.read_write.clear();
            drop(held);
            let report = confine::confine(&ephemeral).unwrap();
            println!("REPORT {}", report.to_json());
            check(
                "ephemeral writes nothing",
                std::fs::write(p.data.join("ephemeral"), b"x").is_err(),
            );
            return;
        }
        _ => {}
    }
    let report = match confine::confine(&policy(&p, network, registered)) {
        Ok(report) => report,
        Err(invalid) => {
            println!("INVALID {invalid}");
            return;
        }
    };
    println!("REPORT {}", report.to_json());
    match case {
        "files" | "reexec" | "ports" => files(&p),
        "refer" => refer_links(&p),
        "sysctl" => sysctls(&p),
        "exec-direct" => exec_direct(),
        "processes" => processes(),
        "ipc" => ipc(&p, true),
        "socks5" | "lan" | "offline" => {
            tcp(&p, case);
            ipc(&p, false);
        }
        "direct" => {
            tcp(&p, case);
            resolver();
        }
        other => panic!("unknown case {other}"),
    }
    drop(held);
}

/// The marker holds this process's id (the re-executed image).
fn marker_is_ours() -> bool {
    std::env::var(confine::REEXEC_MARKER)
        .is_ok_and(|value| value.split(':').next() == Some(&std::process::id().to_string()))
}

/// A lock file and the data directory, held as a service holds its lock.
fn registered(p: &Paths) -> (Vec<i32>, Vec<std::fs::File>) {
    use std::os::fd::AsRawFd;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(p.data.join("lock"))
        .unwrap();
    let dir = std::fs::File::open(&p.data).unwrap();
    (vec![lock.as_raw_fd(), dir.as_raw_fd()], vec![lock, dir])
}

fn policy(p: &Paths, network: Network, descriptors: Vec<i32>) -> Policy {
    Policy {
        read_write: vec![p.data.clone()],
        read_only: vec![p.read_only.clone()],
        refer: false,
        min_abi: 1,
        network,
        system_resolver: true,
        descriptors,
        interface_index: false,
    }
}

fn refused(result: Result<Report, confine::Invalid>) {
    match result {
        Err(confine::Invalid::Descriptor { kind, .. }) => println!("INVALID {kind}"),
        Err(confine::Invalid::Threads(n)) => println!("INVALID threads {n}"),
        Err(confine::Invalid::Rules(why)) => println!("INVALID rules {why}"),
        Err(confine::Invalid::Replaced) => println!("INVALID replaced"),
        Err(other) => println!("INVALID other: {other}"),
        Ok(report) => println!("REPORT {}", report.to_json()),
    }
}

fn files(p: &Paths) {
    let inside = p.data.join("inside");
    check("write inside", std::fs::write(&inside, b"x").is_ok());
    check("read inside", std::fs::read(&inside).is_ok());
    check(
        "truncate inside",
        std::fs::OpenOptions::new()
            .write(true)
            .open(&inside)
            .and_then(|f| f.set_len(0))
            .is_ok(),
    );
    check(
        "a directory inside",
        std::fs::create_dir(p.data.join(format!("dir-{}", std::process::id()))).is_ok(),
    );
    check(
        "rename inside",
        std::fs::rename(&inside, p.data.join("renamed")).is_ok(),
    );
    check(
        "unlink inside",
        std::fs::remove_file(p.data.join("renamed")).is_ok(),
    );
    let mode_inside = p.data.join("mode");
    std::fs::write(&mode_inside, b"x").unwrap();
    check(
        "chmod inside refused",
        std::fs::set_permissions(&mode_inside, std::fs::Permissions::from_mode(0o777)).is_err(),
    );
    check(
        "times inside refused",
        std::fs::File::options()
            .write(true)
            .open(&mode_inside)
            .and_then(|f| f.set_modified(std::time::UNIX_EPOCH))
            .is_err(),
    );
    let canary = p.outside.join("canary");
    check("read outside refused", std::fs::read(&canary).is_err());
    check(
        "write outside refused",
        std::fs::write(&canary, b"changed").is_err(),
    );
    check(
        "create outside refused",
        std::fs::write(p.outside.join("new"), b"x").is_err(),
    );
    // A hard link to a file outside would give it the grant's path
    // (design 0010, step 7): Seatbelt allows `file-link` only inside it.
    check(
        "a hard link to a file outside refused",
        std::fs::hard_link(
            &canary,
            p.data.join(format!("linked-{}", std::process::id())),
        )
        .is_err(),
    );
    check("stat outside refused", std::fs::metadata(&canary).is_err());
    check(
        "chmod outside refused",
        std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o777)).is_err(),
    );
    check(
        "list outside refused",
        std::fs::read_dir(&p.outside).is_err(),
    );
    let ro = p.read_only.join("file");
    check("read the read-only grant", std::fs::read(&ro).is_ok());
    check(
        "write the read-only grant refused",
        std::fs::write(&ro, b"x").is_err(),
    );
    check(
        "home refused",
        std::env::var_os("HOME").is_none_or(|home| std::fs::read_dir(home).is_err()),
    );
}

/// With `refer`, hard links inside the grant; still none from outside it
/// or from the read-only grant.
fn refer_links(p: &Paths) {
    let a = p.data.join(format!("a-{}", std::process::id()));
    std::fs::write(&a, b"a").unwrap();
    let b = p.data.join(format!("b-{}", std::process::id()));
    check(
        "a hard link inside the grant",
        std::fs::hard_link(&a, &b).is_ok(),
    );
    check(
        "its source has two names",
        std::fs::metadata(&a).is_ok_and(|m| m.nlink() == 2),
    );
    check(
        "a hard link from outside refused",
        std::fs::hard_link(p.outside.join("canary"), p.data.join("from-outside")).is_err(),
    );
    check(
        "a hard link from the read-only grant refused",
        std::fs::hard_link(p.read_only.join("file"), p.data.join("from-read-only")).is_err(),
    );
}

/// The sysctls a service reads work, by name and by number; another
/// process's arguments and environment, and the process list, don't.
fn sysctls(p: &Paths) {
    use fc_sys::macos::probe;
    check("hw.ncpu by name", probe::sysctl_name(c"hw.ncpu").is_ok());
    check("hw.ncpu by number", probe::ncpu().is_ok_and(|n| n > 0));
    check(
        "kern.osversion",
        probe::sysctl_name(c"kern.osversion").is_ok(),
    );
    check(
        "hw.optional by prefix",
        probe::sysctl_name(c"hw.optional.floatingpoint").is_ok(),
    );
    // A known gap (design 0010, "macOS"): Seatbelt doesn't mediate
    // KERN_PROCARGS2, so another same-user process's arguments and
    // environment stay readable by pid. Recorded, so a macOS that closes
    // it shows here.
    let parent = rustix::process::getppid().map_or(1, |pid| pid.as_raw_nonzero().get());
    for (who, pid) in [("another process", p.target_pid), ("the parent", parent)] {
        let readable = probe::procargs(pid).is_ok();
        println!(
            "GAP procargs2 {who}: {}",
            if readable { "readable" } else { "refused" }
        );
    }
    check("the process list refused", probe::all_processes().is_err());
    check(
        "kern.proc by name refused",
        probe::sysctl_name(c"kern.proc.all").is_err(),
    );
    check(
        "the interface list in direct mode",
        probe::interface_addresses().is_ok_and(|n| n > 0),
    );
}

/// An exec in place, with no fork: refused. Were it allowed, this process
/// would become `/usr/bin/true` and print nothing more.
fn exec_direct() {
    use std::os::unix::process::CommandExt;
    let error = Command::new("/usr/bin/true").exec();
    check(
        &format!("an exec in place refused ({})", error.kind()),
        true,
    );
}

fn processes() {
    check(
        "exec refused",
        Command::new("/bin/sh")
            .arg("-c")
            .arg("true")
            .status()
            .is_err(),
    );
    check(
        "exec of this binary refused",
        Command::new(std::env::current_exe().unwrap())
            .status()
            .is_err(),
    );
    let parent = rustix::process::getppid();
    check(
        "a signal to the parent refused",
        parent.is_none_or(|pid| rustix::process::test_kill_process(pid).is_err()),
    );
    check(
        "a signal to itself allowed",
        rustix::process::test_kill_process(rustix::process::getpid()).is_ok(),
    );
}

fn ipc(p: &Paths, direct: bool) {
    check(
        "a UNIX socket outside refused",
        UnixStream::connect(&p.socket).is_err(),
    );
    check(
        "an unlisted Mach service refused",
        !fc_sys::macos::mach::look_up(c"com.apple.pasteboard.1"),
    );
    check(
        "configd only in direct mode",
        fc_sys::macos::mach::look_up(c"com.apple.SystemConfiguration.configd") == direct,
    );
}

fn tcp(p: &Paths, case: &str) {
    let to = |port: u16| TcpStream::connect(("127.0.0.1", port)).is_ok();
    match case {
        "direct" => {
            check("the proxy port", to(p.allowed_port));
            check("another port", to(p.other_port));
        }
        "socks5" | "lan" => {
            check("the proxy port", to(p.allowed_port));
            check("another port refused", !to(p.other_port));
            check(
                "UDP refused",
                std::net::UdpSocket::bind("127.0.0.1:0")
                    .and_then(|s| s.send_to(b"x", ("127.0.0.1", p.other_port)))
                    .is_err(),
            );
        }
        _ => {
            check("the proxy port refused", !to(p.allowed_port));
            check("another port refused", !to(p.other_port));
        }
    }
}

fn resolver() {
    use std::net::ToSocketAddrs;
    check(
        "localhost resolves",
        ("localhost", 80)
            .to_socket_addrs()
            .is_ok_and(|mut addrs| addrs.next().is_some()),
    );
}

// -------------------------------------------------------------------
// The parent.

struct World {
    _root: tempfile::TempDir,
    data: PathBuf,
    outside: PathBuf,
    read_only: PathBuf,
    socket: PathBuf,
    allowed: TcpListener,
    other: TcpListener,
    _unix: UnixListener,
    /// A process with a canary in its environment, outside.
    target: std::process::Child,
}

/// The environment variable the target process holds, and its value.
fn canary_env() -> (String, String) {
    (
        "FC_ENV_CANARY".to_owned(),
        format!("fc-canary-{}", std::process::id()),
    )
}

fn world() -> World {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let outside = root.path().join("outside");
    let read_only = root.path().join("read-only");
    for dir in [&data, &outside, &read_only] {
        std::fs::create_dir(dir).unwrap();
    }
    std::fs::write(outside.join("canary"), b"canary").unwrap();
    std::fs::set_permissions(
        outside.join("canary"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(read_only.join("file"), b"read-only").unwrap();
    let socket = root.path().join("listener.sock");
    let unix = UnixListener::bind(&socket).unwrap();
    World {
        data,
        outside,
        read_only,
        socket,
        allowed: TcpListener::bind("127.0.0.1:0").unwrap(),
        other: TcpListener::bind("127.0.0.1:0").unwrap(),
        _unix: unix,
        target: {
            let (key, value) = canary_env();
            Command::new("/bin/sleep")
                .arg("120")
                .env(key, value)
                .spawn()
                .unwrap()
        },
        _root: root,
    }
}

fn command(world: &World, case: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .env("FC_TARGET_PID", world.target.id().to_string())
        .env(CASE, case)
        .env("FC_DATA", &world.data)
        .env("FC_OUTSIDE", &world.outside)
        .env("FC_READ_ONLY", &world.read_only)
        .env("FC_SOCKET", &world.socket)
        .env(
            "FC_PORT",
            world.allowed.local_addr().unwrap().port().to_string(),
        )
        .env(
            "FC_OTHER_PORT",
            world.other.local_addr().unwrap().port().to_string(),
        )
        .env_remove(confine::REEXEC_MARKER);
    command
}

fn run(world: &World, case: &str) -> Output {
    command(world, case).output().unwrap()
}

/// `case` with a pipe it inherits, made without close-on-exec.
fn inheriting(world: &World, case: &str) -> Output {
    let extra = rustix::pipe::pipe().unwrap();
    // rustix's pipe is close-on-exec on macOS only where asked: clear it.
    for fd in [&extra.0, &extra.1] {
        rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::empty()).unwrap();
    }
    let output = run(world, case);
    drop(extra);
    output
}

fn lines(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn report_json(output: &Output) -> Option<serde_json::Value> {
    lines(output)
        .lines()
        .find_map(|line| line.strip_prefix("REPORT "))
        .and_then(|json| serde_json::from_str(json).ok())
}

fn passed(case: &str, output: &Output) -> Vec<String> {
    let text = lines(output);
    let checks: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("OK ") || line.starts_with("FAIL "))
        .collect();
    let mut failures = Vec::new();
    if checks.is_empty() {
        failures.push(format!(
            "{case}: no checks ran: {text}{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    failures.extend(
        checks
            .iter()
            .filter(|line| line.starts_with("FAIL "))
            .map(|line| format!("{case}: {line}")),
    );
    failures
}

fn expect(failures: &mut Vec<String>, ok: bool, what: String) {
    if !ok {
        failures.push(what);
    }
}

fn has_line(output: &Output, line: &str) -> bool {
    lines(output).lines().any(|l| l == line)
}

fn parent() {
    let world = world();
    let canary = world.outside.join("canary");
    let before = std::fs::metadata(&canary).unwrap();
    let mut failures: Vec<String> = Vec::new();

    // The probe works: unconfined, the target's environment is readable,
    // canary and all, so a refusal below is the sandbox's.
    let target_pid = i32::try_from(world.target.id()).unwrap();
    let (_, canary_value) = canary_env();
    let mut seen = false;
    for _ in 0..50 {
        if fc_sys::macos::probe::procargs(target_pid).is_ok_and(|args| {
            args.windows(canary_value.len())
                .any(|w| w == canary_value.as_bytes())
        }) {
            seen = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    expect(
        &mut failures,
        seen,
        "unconfined, the target's environment canary isn't readable: the probe proves nothing"
            .into(),
    );

    for case in [
        "files",
        "processes",
        "ipc",
        "direct",
        "socks5",
        "lan",
        "offline",
        "refer",
        "sysctl",
        "exec-direct",
    ] {
        let output = run(&world, case);
        let report = report_json(&output);
        let Some(report) = report else {
            failures.push(format!(
                "{case}: no report: {}{}",
                lines(&output),
                String::from_utf8_lossy(&output.stderr)
            ));
            continue;
        };
        expect(
            &mut failures,
            report["mechanism"] == "seatbelt",
            format!("{case}: mechanism {report}"),
        );
        for property in ["files", "exec"] {
            expect(
                &mut failures,
                report[property] == "enforced",
                format!("{case}: {property} {report}"),
            );
        }
        // Partial, naming what stays open: another process's arguments
        // and environment (the KERN_PROCARGS2 gap).
        expect(
            &mut failures,
            report["ipc"] == "partial"
                && report["gaps"]
                    .as_array()
                    .is_some_and(|gaps| gaps.iter().any(|g| g == "process_args")),
            format!("{case}: ipc {report}"),
        );
        let network = if matches!(case, "socks5" | "lan" | "offline") {
            "enforced"
        } else {
            "none"
        };
        expect(
            &mut failures,
            report["network"] == network,
            format!("{case}: network {report}"),
        );
        failures.extend(passed(case, &output));
    }

    // Nothing outside changed.
    let after = std::fs::metadata(&canary).unwrap();
    expect(
        &mut failures,
        after.mode() == before.mode()
            && after.nlink() == 1
            && std::fs::read(&canary).unwrap() == b"canary",
        "the canary changed".into(),
    );
    expect(
        &mut failures,
        std::fs::metadata(world.read_only.join("file"))
            .unwrap()
            .nlink()
            == 1,
        "the read-only grant's file gained a hard link".into(),
    );

    let ephemeral = run(&world, "ephemeral");
    failures.extend(passed("ephemeral", &ephemeral));

    // Refusals: exit 77's causes.
    for (case, line) in [
        ("inject-pipe", "INVALID pipe"),
        ("thread-first", "INVALID threads 2"),
        ("replaced", "INVALID replaced"),
    ] {
        let output = run(&world, case);
        expect(
            &mut failures,
            has_line(&output, line),
            format!(
                "{case}: {}{}",
                lines(&output),
                String::from_utf8_lossy(&output.stderr)
            ),
        );
    }
    let invalid = run(&world, "invalid");
    expect(
        &mut failures,
        lines(&invalid)
            .lines()
            .any(|l| l.starts_with("INVALID rules Seatbelt refused the profile")),
        format!("invalid: {}", lines(&invalid)),
    );

    // An inherited descriptor: one re-exec, then the rules.
    let reexec = inheriting(&world, "reexec");
    expect(
        &mut failures,
        lines(&reexec).matches("START").count() == 2
            && has_line(&reexec, "START ours=true")
            && has_line(&reexec, "ENTRY reexeced"),
        format!("reexec: {}", lines(&reexec)),
    );
    failures.extend(passed("reexec", &reexec));

    // The Mach rights held at the confinement point, for the record.
    // The KERN_PROCARGS2 gap, as this macOS has it.
    let sysctl = run(&world, "sysctl");
    for line in lines(&sysctl).lines().filter(|l| l.starts_with("GAP ")) {
        println!("confine: {line}");
    }

    let ports = run(&world, "ports");
    if let Some(line) = lines(&ports).lines().find(|l| l.starts_with("PORTS ")) {
        println!("confine: at the confinement point: {line}");
    }
    failures.extend(passed("ports", &ports));

    let mut target = world.target;
    let _ = target.kill();
    let _ = target.wait();
    if failures.is_empty() {
        println!("confine: all macOS cases passed");
    } else {
        for failure in &failures {
            eprintln!("FAILED {failure}");
        }
        std::process::exit(1);
    }
}
