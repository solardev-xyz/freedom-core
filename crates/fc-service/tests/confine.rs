//! Confinement through a real process (design 0010, Tests).
//!
//! A process confines itself once, for good, and the default test harness
//! runs threads, which `confine` refuses. So this test has no harness: the
//! parent runs each case in a child of its own (this binary again, with
//! `FC_CONFINE_CASE` set), which confines itself as a service does, tries
//! what the case names, and prints one line per check. The parent reads
//! the lines, and checks from outside what the child must not have
//! changed.
//!
//! On other platforms it does nothing yet (macOS and Windows follow).

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("confine: nothing to test on this platform yet");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(target_os = "linux")]
#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::panic
)]
mod linux {
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::process::{Command, Output};

    use fc_service::confine::{self, Network, Options, Policy, Report, Status};

    const CASE: &str = "FC_CONFINE_CASE";

    pub fn main() {
        if let Ok(case) = std::env::var(CASE) {
            child(&case);
            return;
        }
        parent();
    }

    // ---------------------------------------------------------------
    // The child: confine, then try.

    /// The paths the parent prepared, passed in the environment.
    struct Paths {
        data: PathBuf,
        outside: PathBuf,
        read_only: PathBuf,
        socket: PathBuf,
        abstract_name: String,
        allowed_port: u16,
        other_port: u16,
    }

    fn paths() -> Paths {
        let var = |name: &str| std::env::var(name).unwrap();
        Paths {
            data: var("FC_DATA").into(),
            outside: var("FC_OUTSIDE").into(),
            read_only: var("FC_READ_ONLY").into(),
            socket: var("FC_SOCKET").into(),
            abstract_name: var("FC_ABSTRACT"),
            allowed_port: var("FC_PORT").parse().unwrap(),
            other_port: var("FC_OTHER_PORT").parse().unwrap(),
        }
    }

    fn check(name: &str, ok: bool) {
        println!("{} {name}", if ok { "OK" } else { "FAIL" });
    }

    fn child(case: &str) {
        let p = paths();
        let network = match case {
            "socks5" => Network::Socks5 {
                port: p.allowed_port,
            },
            "offline" => Network::Offline,
            _ => Network::Direct,
        };
        let mut options = Options::default();
        let mut min_abi = 1;
        match case {
            "abi1" => options.landlock_abi_cap = Some(1),
            "abi2" => options.landlock_abi_cap = Some(2),
            "abi3" => options.landlock_abi_cap = Some(3),
            "below-minimum" => {
                options.landlock_abi_cap = Some(1);
                min_abi = 2;
            }
            "unavailable" => options.landlock_errno = Some(libc_enosys()),
            "blocked" => {
                options.landlock_errno = Some(libc_eperm());
                options.seccomp_errno = Some(libc_eperm());
            }
            _ => {}
        }
        if case == "socket-first" {
            // An NSS client's cached connection, made before the rules.
            let stream = UnixStream::connect(&p.socket).unwrap();
            let result = confine::confine(&policy(&p, network, min_abi));
            println!(
                "INVALID {}",
                matches!(result, Err(confine::Invalid::Socket(_)))
            );
            drop(stream);
            return;
        }
        if case == "thread-first" {
            let handle =
                std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_millis(500)));
            let result = confine::confine(&policy(&p, network, min_abi));
            println!("INVALID {}", result.is_err());
            let _ = handle.join();
            return;
        }
        let report = confine::confine_with(&policy(&p, network, min_abi), &options).unwrap();
        println!("REPORT {}", report.to_json());
        match case {
            "files" | "abi1" | "abi2" | "abi3" => files(&p),
            // Only the report: the rules weren't all applied.
            "below-minimum" | "unavailable" | "blocked" => {}
            "processes" => processes(),
            "ipc" => ipc(&p),
            "socks5" | "direct" | "offline" => tcp(&p),
            "threads" => threads(&p),
            "resolver" => resolver(),
            #[cfg(target_arch = "x86_64")]
            "x32" => {
                println!("CALLING");
                let _ = fc_sys::linux::getpid_x32();
                println!("SURVIVED");
            }
            #[cfg(target_arch = "x86_64")]
            "i386" => {
                println!("CALLING");
                let _ = fc_sys::linux::getpid_i386();
                println!("SURVIVED");
            }
            other => panic!("unknown case {other}"),
        }
    }

    fn libc_enosys() -> i32 {
        38
    }

    fn libc_eperm() -> i32 {
        1
    }

    fn policy(p: &Paths, network: Network, min_abi: u32) -> Policy {
        Policy {
            read_write: vec![p.data.clone()],
            read_only: vec![p.read_only.clone()],
            refer: false,
            min_abi,
            network,
            // No lookup comes before confinement: the first needs the
            // read grants alone.
            system_resolver: true,
        }
    }

    fn files(p: &Paths) {
        let inside = p.data.join("inside");
        check("write inside", std::fs::write(&inside, b"x").is_ok());
        check("read inside", std::fs::read(&inside).is_ok());
        check(
            "ftruncate inside",
            std::fs::OpenOptions::new()
                .write(true)
                .open(&inside)
                .and_then(|f| f.set_len(0))
                .is_ok(),
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
        check("stat outside allowed", std::fs::metadata(&canary).is_ok());
        check(
            "chmod outside refused",
            rustix::fs::chmod(&canary, rustix::fs::Mode::from_raw_mode(0o777)).is_err(),
        );
        check(
            "chown outside refused",
            rustix::fs::chown(&canary, None, None).is_err(),
        );
        check(
            "setxattr outside refused",
            rustix::fs::setxattr(&canary, "user.fc", b"1", rustix::fs::XattrFlags::empty())
                .is_err(),
        );
        let times = rustix::fs::Timestamps {
            last_access: rustix::fs::Timespec {
                tv_sec: 1,
                tv_nsec: 0,
            },
            last_modification: rustix::fs::Timespec {
                tv_sec: 1,
                tv_nsec: 0,
            },
        };
        check(
            "utimensat outside refused",
            rustix::fs::utimensat(
                rustix::fs::CWD,
                &canary,
                &times,
                rustix::fs::AtFlags::empty(),
            )
            .is_err(),
        );
        // A read-only grant: readable, and its descriptor changes nothing.
        let ro = p.read_only.join("file");
        check("read the read-only grant", std::fs::read(&ro).is_ok());
        check(
            "write the read-only grant refused",
            std::fs::write(&ro, b"x").is_err(),
        );
        let file = std::fs::File::open(&ro).unwrap();
        check(
            "fchmod on a read-only descriptor refused",
            rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o777)).is_err(),
        );
        check(
            "fsetxattr on a read-only descriptor refused",
            rustix::fs::fsetxattr(&file, "user.fc", b"1", rustix::fs::XattrFlags::empty()).is_err(),
        );
        check(
            "futimens on a read-only descriptor refused",
            rustix::fs::futimens(&file, &times).is_err(),
        );
        check(
            "FS_IOC_SETFLAGS refused",
            rustix::fs::ioctl_setflags(&file, rustix::fs::IFlags::IMMUTABLE).is_err(),
        );
        check(
            "FIONREAD allowed",
            rustix::io::ioctl_fionread(&file).is_ok(),
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
    }

    fn ipc(p: &Paths) {
        check(
            "pathname socket refused",
            UnixStream::connect(&p.socket).is_err(),
        );
        let addr = <std::os::unix::net::SocketAddr as std::os::linux::net::SocketAddrExt>::from_abstract_name(p.abstract_name.as_bytes()).unwrap();
        check(
            "abstract socket refused",
            UnixStream::connect_addr(&addr).is_err(),
        );
        check("a stream pair allowed", UnixStream::pair().is_ok());
    }

    fn tcp(p: &Paths) {
        let connect = |port: u16| TcpStream::connect(("127.0.0.1", port)).is_ok();
        println!("CONNECT allowed {}", connect(p.allowed_port));
        println!("CONNECT other {}", connect(p.other_port));
        println!("BIND {}", TcpListener::bind(("127.0.0.1", 0)).is_ok());
    }

    fn threads(p: &Paths) {
        let canary = p.outside.join("canary");
        let first = {
            let canary = canary.clone();
            std::thread::spawn(move || {
                let nested = {
                    let canary = canary.clone();
                    std::thread::spawn(move || std::fs::read(&canary).is_err())
                };
                (std::fs::read(&canary).is_err(), nested.join().unwrap())
            })
        };
        let (thread, nested) = first.join().unwrap();
        check("a thread started after is confined", thread);
        check("a thread it starts is confined", nested);
        check(
            "the main thread is confined",
            std::fs::read(&canary).is_err(),
        );
    }

    fn resolver() {
        use std::net::ToSocketAddrs;
        check(
            "localhost resolves",
            ("localhost", 0).to_socket_addrs().is_ok(),
        );
        if let Ok(name) = std::env::var("FC_DNS_NAME") {
            check(
                "a DNS name resolves",
                (name.as_str(), 0).to_socket_addrs().is_ok(),
            );
        }
    }

    // ---------------------------------------------------------------
    // The parent: prepare, run each case, check.

    struct World {
        _root: tempfile::TempDir,
        data: PathBuf,
        outside: PathBuf,
        read_only: PathBuf,
        socket: PathBuf,
        abstract_name: String,
        allowed: TcpListener,
        other: TcpListener,
        _unix: UnixListener,
        _abstract: UnixListener,
    }

    fn world() -> World {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let outside = root.path().join("outside");
        let read_only = root.path().join("read-only");
        for dir in [&data, &outside, &read_only] {
            std::fs::create_dir(dir).unwrap();
        }
        let data = std::fs::canonicalize(data).unwrap();
        std::fs::write(outside.join("canary"), b"canary").unwrap();
        std::fs::set_permissions(
            outside.join("canary"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::write(read_only.join("file"), b"read-only").unwrap();
        let socket = root.path().join("listener.sock");
        let unix = UnixListener::bind(&socket).unwrap();
        let abstract_name = format!("fc-confine-{}", std::process::id());
        let addr = <std::os::unix::net::SocketAddr as std::os::linux::net::SocketAddrExt>::from_abstract_name(abstract_name.as_bytes()).unwrap();
        let abstract_listener = UnixListener::bind_addr(&addr).unwrap();
        World {
            data,
            outside: std::fs::canonicalize(outside).unwrap(),
            read_only: std::fs::canonicalize(read_only).unwrap(),
            socket,
            abstract_name,
            allowed: TcpListener::bind(("127.0.0.1", 0)).unwrap(),
            other: TcpListener::bind(("127.0.0.1", 0)).unwrap(),
            _unix: unix,
            _abstract: abstract_listener,
            _root: root,
        }
    }

    fn run(world: &World, case: &str) -> Output {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env(CASE, case)
            .env("FC_DATA", &world.data)
            .env("FC_OUTSIDE", &world.outside)
            .env("FC_READ_ONLY", &world.read_only)
            .env("FC_SOCKET", &world.socket)
            .env("FC_ABSTRACT", &world.abstract_name)
            .env(
                "FC_PORT",
                world.allowed.local_addr().unwrap().port().to_string(),
            )
            .env(
                "FC_OTHER_PORT",
                world.other.local_addr().unwrap().port().to_string(),
            );
        if let Some(name) = dns_name() {
            command.env("FC_DNS_NAME", name);
        }
        command.output().unwrap()
    }

    /// A name the unconfined parent can resolve through DNS, if any: the
    /// child must then resolve it too.
    fn dns_name() -> Option<&'static str> {
        use std::net::ToSocketAddrs;
        let name = "example.com";
        (name, 0).to_socket_addrs().ok().map(|_| name)
    }

    fn lines(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn report(output: &Output) -> Report {
        let text = lines(output);
        let json = text
            .lines()
            .find_map(|line| line.strip_prefix("REPORT "))
            .unwrap_or_else(|| {
                panic!(
                    "no report: {text}\n{}",
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        parse(&value)
    }

    fn status(value: &serde_json::Value) -> Status {
        match value.as_str().unwrap() {
            "enforced" => Status::Enforced,
            "partial" => Status::Partial,
            "unavailable" => Status::Unavailable,
            "blocked" => Status::Blocked,
            "none" => Status::None,
            other => panic!("status {other}"),
        }
    }

    fn parse(value: &serde_json::Value) -> Report {
        Report {
            mechanism: value["mechanism"].as_str().unwrap().into(),
            files: status(&value["files"]),
            exec: status(&value["exec"]),
            ipc: status(&value["ipc"]),
            network: status(&value["network"]),
            gaps: value["gaps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|gap| -> &'static str {
                    Box::leak(gap.as_str().unwrap().to_owned().into_boxed_str())
                })
                .collect(),
            reasons: Default::default(),
            resolution: None,
        }
    }

    /// Every check line of `output` passed, and there was at least one.
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

    /// The kernel's Landlock ABI, as the child would see it.
    fn kernel_abi() -> Option<u32> {
        fc_sys::linux::landlock_abi().ok().map(|abi| abi.min(9))
    }

    fn parent() {
        let world = world();
        let canary = world.outside.join("canary");
        let before = std::fs::metadata(&canary).unwrap();
        let abi = kernel_abi();
        let mut failures: Vec<String> = Vec::new();
        println!("confine: Landlock ABI {abi:?}");

        let Some(abi) = abi else {
            // A runner without Landlock can't show the rules; the reports
            // still say why.
            let report = report(&run(&world, "files"));
            expect(
                &mut failures,
                report.files == Status::Unavailable || report.files == Status::Blocked,
                format!("files without Landlock: {report:?}"),
            );
            finish(failures);
            return;
        };
        // CI's kernel offers Landlock: the report must show the ABI it
        // offers, so a silent downgrade fails.
        let files = run(&world, "files");
        let r = report(&files);
        expect(
            &mut failures,
            r.mechanism == format!("landlock-{abi}+seccomp"),
            format!("mechanism {}", r.mechanism),
        );
        expect(
            &mut failures,
            r.files == Status::Enforced && r.exec == Status::Enforced,
            format!("files run: {r:?}"),
        );
        failures.extend(passed("files", &files));

        // Nothing outside changed: mode, owner, times, xattrs.
        let after = std::fs::metadata(&canary).unwrap();
        expect(
            &mut failures,
            after.mode() == before.mode(),
            "the canary's mode changed".into(),
        );
        expect(
            &mut failures,
            after.uid() == before.uid() && after.gid() == before.gid(),
            "the canary's owner changed".into(),
        );
        expect(
            &mut failures,
            after.mtime() == before.mtime() && after.atime() == before.atime(),
            "the canary's times changed".into(),
        );
        expect(
            &mut failures,
            std::fs::read(&canary).unwrap() == b"canary",
            "the canary changed".into(),
        );
        expect(
            &mut failures,
            rustix::fs::getxattr(&canary, "user.fc", &mut [0u8; 8]).is_err(),
            "the canary gained an xattr".into(),
        );
        let ro = world.read_only.join("file");
        expect(
            &mut failures,
            std::fs::metadata(&ro).unwrap().mode() & 0o777 != 0o777,
            "the read-only file's mode changed".into(),
        );

        for case in ["processes", "ipc", "threads", "resolver"] {
            failures.extend(passed(case, &run(&world, case)));
        }

        // The network: direct reaches any port and binds nothing; socks5
        // only the proxy's port, from ABI 4; offline nothing.
        let connects = |output: &Output| {
            let text = lines(output);
            let get = |key: &str| {
                text.lines()
                    .find_map(|line| line.strip_prefix(key))
                    .map(|value| value.trim().to_owned())
            };
            (get("CONNECT allowed"), get("CONNECT other"), get("BIND"))
        };
        let direct = run(&world, "direct");
        let (allowed, other, bind) = connects(&direct);
        expect(
            &mut failures,
            allowed.as_deref() == Some("true") && other.as_deref() == Some("true"),
            format!("direct: {allowed:?} {other:?}"),
        );
        if abi >= 4 {
            expect(
                &mut failures,
                bind.as_deref() == Some("false"),
                format!("direct bind: {bind:?}"),
            );
        }
        let socks = run(&world, "socks5");
        let r = report(&socks);
        let (allowed, other, _) = connects(&socks);
        if abi >= 4 {
            expect(
                &mut failures,
                r.network == Status::Enforced,
                format!("socks5 network: {r:?}"),
            );
            expect(
                &mut failures,
                allowed.as_deref() == Some("true") && other.as_deref() == Some("false"),
                format!("socks5: {allowed:?} {other:?}"),
            );
        } else {
            expect(
                &mut failures,
                r.network == Status::Unavailable,
                format!("socks5 network below ABI 4: {r:?}"),
            );
        }
        let offline = run(&world, "offline");
        let (allowed, other, _) = connects(&offline);
        expect(
            &mut failures,
            allowed.as_deref() == Some("false") && other.as_deref() == Some("false"),
            format!("offline: {allowed:?} {other:?}"),
        );

        // Older ABIs on this kernel: their rights only, and the gaps named.
        for cap in 1..=3u32.min(abi) {
            let case = format!("abi{cap}");
            let output = run(&world, &case);
            let r = report(&output);
            expect(
                &mut failures,
                r.mechanism == format!("landlock-{cap}+seccomp"),
                format!("{case}: {}", r.mechanism),
            );
            expect(
                &mut failures,
                r.files == Status::Enforced,
                format!("{case} files: {r:?}"),
            );
            expect(
                &mut failures,
                r.ipc == Status::Partial && r.gaps.contains(&"signals"),
                format!("{case} ipc: {r:?}"),
            );
            failures.extend(passed(&case, &output));
        }
        let r = report(&run(&world, "below-minimum"));
        expect(
            &mut failures,
            r.files == Status::Unavailable && r.mechanism == "seccomp",
            format!("below the minimum: {r:?}"),
        );

        // D2: forced outcomes.
        let r = report(&run(&world, "unavailable"));
        expect(
            &mut failures,
            r.files == Status::Unavailable && r.exec == Status::Enforced,
            format!("forced unavailable: {r:?}"),
        );
        let r = report(&run(&world, "blocked"));
        expect(
            &mut failures,
            r.files == Status::Blocked && r.exec == Status::Blocked && r.mechanism == "none",
            format!("forced blocked: {r:?}"),
        );

        // A socket connected before confine (as an NSS source's would be):
        // refused, so the service exits 77.
        let output = run(&world, "socket-first");
        expect(
            &mut failures,
            lines(&output).contains("INVALID true"),
            format!("socket first: {}", lines(&output)),
        );

        // A thread before confine: refused, so the service exits 77.
        let output = run(&world, "thread-first");
        expect(
            &mut failures,
            lines(&output).contains("INVALID true"),
            format!("thread first: {}", lines(&output)),
        );

        // The ABI guard.
        #[cfg(target_arch = "x86_64")]
        for case in ["x32", "i386"] {
            use std::os::unix::process::ExitStatusExt;
            let output = run(&world, case);
            let signal = output.status.signal();
            let text = lines(&output);
            let sigsys = 31;
            let sigsegv = 11;
            if case == "i386" && signal == Some(sigsegv) {
                println!("confine: no i386 emulation on this kernel");
                continue;
            }
            expect(
                &mut failures,
                text.contains("CALLING") && !text.contains("SURVIVED") && signal == Some(sigsys),
                format!("{case}: {text} {:?}", output.status),
            );
        }

        finish(failures);
        let _ = std::io::stdout().flush();
    }

    fn expect(failures: &mut Vec<String>, ok: bool, what: String) {
        if !ok {
            failures.push(what);
        }
    }

    fn finish(failures: Vec<String>) {
        if failures.is_empty() {
            println!("confine: all cases passed");
        } else {
            for failure in &failures {
                eprintln!("FAILED {failure}");
            }
            std::process::exit(1);
        }
    }
}
