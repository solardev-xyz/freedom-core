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
        // At entry, as a service does: one line per image, so the parent
        // counts the re-execs.
        println!("START ours={}", marker() == "ours");
        // Every argument, argv[0] included, byte for byte.
        println!("ARGV {}", argv_hex());
        let p = paths();
        // A file this process owns before its entry, for the failure path:
        // the marks must leave it working.
        let owned = (case == "reexec-fails").then(|| owned_file(&p));
        let entry = match case {
            // A re-exec that can't happen.
            "reexec-fails" => confine::clean_entry_with(
                std::path::Path::new("/nonexistent/freedom-service"),
                false,
            ),
            // Marked one at a time, as before Linux 5.11.
            "fallback" | "argv-fallback" => {
                confine::clean_entry_with(std::path::Path::new("/proc/self/exe"), true)
            }
            _ => confine::clean_entry(),
        };
        println!("ENTRY {}", entry.name());
        println!("MARKER {}", marker());
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
        if let Some(kind) = case.strip_prefix("inject-") {
            // Opened by the process's own startup, before `confine`, as an
            // early mistake in the setup would be: refused.
            let injected = inject(kind, &p);
            let (registered, held) = registered(&p);
            refused(confine::confine(&policy(&p, network, min_abi, registered)));
            drop((injected, held));
            return;
        }
        if case == "marker-inherited" || case == "reexec-fails" {
            // The parent's extra descriptor is left: after a re-exec (the
            // marker), or because the re-exec failed. `confine` refuses it.
            let (mut registered, held) = registered(&p);
            if let Some(owned) = &owned {
                use std::io::{Read, Seek, Write};
                use std::os::fd::AsRawFd;
                let mut file = owned;
                let works = file.write_all(b"owned").is_ok() && file.rewind().is_ok() && {
                    let mut text = String::new();
                    file.read_to_string(&mut text).is_ok() && text == "owned"
                };
                check("an owned descriptor still works", works);
                registered.push(owned.as_raw_fd());
            }
            refused(confine::confine(&policy(&p, network, min_abi, registered)));
            drop((held, owned));
            return;
        }
        if let Some(hidden) = case.strip_prefix("unreadable-") {
            // An outer Landlock layer hides the list `confine` must read,
            // with a socket connected before it, as an NSS source's would
            // be: no list, no report.
            let stream = UnixStream::connect(&p.socket).unwrap();
            let (registered, _held) = registered(&p);
            hide(hidden);
            refused(confine::confine(&policy(&p, network, min_abi, registered)));
            drop(stream);
            return;
        }
        if case == "invalid-bpf" {
            // The service's own first filter refused by a kernel that takes
            // filters: an invalid policy, not an outside refusal.
            options.seccomp_invalid = true;
            let (registered, _held) = registered(&p);
            refused(confine::confine_with(
                &policy(&p, network, min_abi, registered),
                &options,
            ));
            return;
        }
        if case == "ephemeral" {
            // No lock and no data directory: nothing registered, nothing
            // writable.
            let mut ephemeral = policy(&p, network, min_abi, Vec::new());
            ephemeral.read_write.clear();
            let report = confine::confine(&ephemeral).unwrap();
            println!("REPORT {}", report.to_json());
            check(
                "ephemeral writes nothing",
                std::fs::write(p.data.join("ephemeral"), b"x").is_err(),
            );
            return;
        }
        // The lock and a directory, opened before `confine` and registered,
        // as a service's are: they cross.
        let (registered, _held) = registered(&p);
        if case == "thread-first" {
            let handle =
                std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_millis(500)));
            let result = confine::confine(&policy(&p, network, min_abi, registered));
            println!("INVALID {}", result.is_err());
            let _ = handle.join();
            return;
        }
        let report =
            confine::confine_with(&policy(&p, network, min_abi, registered), &options).unwrap();
        println!("REPORT {}", report.to_json());
        match case {
            "files" | "abi1" | "abi2" | "abi3" | "fallback" | "argv" | "argv-fallback" => files(&p),
            // Only the report: the rules weren't all applied.
            "below-minimum" | "unavailable" | "blocked" => {}
            "processes" => processes(),
            "ipc" => ipc(&p),
            "socks5" | "direct" | "offline" => tcp(&p),
            "threads" => threads(&p),
            "resolver" => resolver(),
            "stdio-socket" => stdio_socket(),
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

    /// A lock file and the data directory, opened and held as a service
    /// holds its lock: their numbers, and the files.
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

    /// A descriptor of `kind`, opened by the process itself before `confine`.
    fn inject(kind: &str, p: &Paths) -> Box<dyn std::any::Any> {
        match kind {
            // An NSS client's cached connection.
            "socket" => Box::new(UnixStream::connect(&p.socket).unwrap()),
            "pipe" => Box::new(std::io::pipe().unwrap()),
            // A file outside the grants, opened before them.
            "file" => Box::new(std::fs::File::open(p.outside.join("canary")).unwrap()),
            "eventfd" => {
                Box::new(rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC).unwrap())
            }
            "epoll" => Box::new(
                rustix::event::epoll::create(rustix::event::epoll::CreateFlags::CLOEXEC).unwrap(),
            ),
            other => panic!("unknown descriptor {other}"),
        }
    }

    /// The re-exec's marker: `ours` (this process's id), `other` (any other
    /// value) or `absent`.
    fn marker() -> &'static str {
        match std::env::var_os(confine::REEXEC_MARKER) {
            None => "absent",
            Some(value) if value == std::process::id().to_string().as_str() => "ours",
            Some(_) => "other",
        }
    }

    /// This image's arguments, argv[0] first, each in hex: a JSON array.
    fn argv_hex() -> String {
        use std::os::unix::ffi::OsStrExt;
        let args: Vec<String> = std::env::args_os().map(|arg| hex(arg.as_bytes())).collect();
        serde_json::to_string(&args).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A file in the data directory, opened read-write.
    fn owned_file(p: &Paths) -> std::fs::File {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(p.data.join("owned"))
            .unwrap()
    }

    /// What `confine` refused, as one line; a report is a failure.
    fn refused(result: Result<Report, confine::Invalid>) {
        match result {
            Err(confine::Invalid::Descriptor { kind, .. }) => println!("INVALID {kind}"),
            Err(confine::Invalid::Unreadable(what)) => println!("INVALID unreadable {what}"),
            Err(confine::Invalid::Rules(_)) => println!("INVALID rules"),
            Err(other) => println!("INVALID other: {other}"),
            Ok(report) => println!("REPORT {}", report.to_json()),
        }
    }

    /// An outer Landlock layer that handles listing directories and allows
    /// it only beneath `/proc/self/task` (`fd`), or nowhere (`task`).
    fn hide(hidden: &str) {
        use landlock::{AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr};
        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::ReadDir)
            .unwrap()
            .create()
            .unwrap();
        if hidden == "fd" {
            ruleset = ruleset
                .add_rule(PathBeneath::new(
                    PathFd::new("/proc/self/task").unwrap(),
                    AccessFs::ReadDir,
                ))
                .unwrap();
        }
        ruleset.restrict_self().unwrap();
    }

    /// stdin is a socket pair's end, as main's connection may be: it
    /// crosses, and still carries both ways once confined.
    fn stdio_socket() {
        use std::io::BufRead;
        use std::os::fd::AsFd;
        let mut line = String::new();
        let read = std::io::stdin().lock().read_line(&mut line).is_ok() && line == "ping\n";
        check("stdio socket reads", read);
        let stdin = std::io::stdin();
        check(
            "stdio socket writes",
            rustix::io::write(stdin.as_fd(), b"pong\n").is_ok(),
        );
    }

    fn policy(p: &Paths, network: Network, min_abi: u32, descriptors: Vec<i32>) -> Policy {
        Policy {
            read_write: vec![p.data.clone()],
            read_only: vec![p.read_only.clone()],
            refer: false,
            min_abi,
            network,
            // No lookup comes before confinement: the first needs the
            // read grants alone.
            system_resolver: true,
            descriptors,
            interface_index: false,
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
        // A hard link to a file outside the grant would give it the
        // grant's path (design 0010, step 7): refused.
        check(
            "a hard link to a file outside refused",
            std::fs::hard_link(&canary, p.data.join("linked-canary")).is_err(),
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
        command(world, case).output().unwrap()
    }

    /// Runs `command` with an extra pipe or socket (`kind`) it inherits:
    /// made without close-on-exec, and closed here once it ran.
    fn inheriting(kind: &str, mut command: Command) -> Output {
        let extra: (std::os::fd::OwnedFd, std::os::fd::OwnedFd) = match kind {
            "pipe" => rustix::pipe::pipe_with(rustix::pipe::PipeFlags::empty()).unwrap(),
            _ => rustix::net::socketpair(
                rustix::net::AddressFamily::UNIX,
                rustix::net::SocketType::STREAM,
                rustix::net::SocketFlags::empty(),
                None,
            )
            .unwrap(),
        };
        let output = command.output().unwrap();
        drop(extra);
        output
    }

    /// `case` through a shell that sets the marker to its own id and then
    /// execs the case, which keeps the id: the child starts with the marker
    /// already its own.
    fn with_own_marker(world: &World, case: &str) -> Command {
        let mut shell = Command::new("/bin/sh");
        shell
            .arg("-c")
            .arg(format!("export {}=$$; exec \"$0\"", confine::REEXEC_MARKER))
            .arg(std::env::current_exe().unwrap());
        configure(shell, world, case)
    }

    /// The `stdio-socket` case, its stdin a socket pair's end: what it
    /// wrote back.
    fn run_on_socket(world: &World) -> (Output, String) {
        use std::io::Read;
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        ours.write_all(b"ping\n").unwrap();
        let output = command(world, "stdio-socket")
            .stdin(std::process::Stdio::from(std::os::fd::OwnedFd::from(
                theirs,
            )))
            .output()
            .unwrap();
        ours.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut answer = [0u8; 5];
        let n = ours.read(&mut answer).unwrap_or(0);
        (output, String::from_utf8_lossy(&answer[..n]).into_owned())
    }

    fn command(world: &World, case: &str) -> Command {
        configure(Command::new(std::env::current_exe().unwrap()), world, case)
    }

    /// `command`, with the case and the paths the parent prepared.
    fn configure(mut command: Command, world: &World, case: &str) -> Command {
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
        command
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

    /// The descriptors above stderr this process holds, from its start:
    /// what its children would inherit.
    fn inherited_descriptors() -> Vec<String> {
        use std::os::fd::AsRawFd;
        let table = rustix::fs::open(
            "/proc/self/fd",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let own = table.as_raw_fd();
        let mut dir = rustix::fs::Dir::new(table).unwrap();
        let mut held = Vec::new();
        while let Some(entry) = dir.read() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            if name.parse::<i32>().is_ok_and(|fd| fd > 2 && fd != own) {
                held.push(name);
            }
        }
        held
    }

    fn parent() {
        // Main spawns a service with stdio alone, and `confine` refuses
        // anything else: so must this test be run, or every case fails.
        let held = inherited_descriptors();
        if !held.is_empty() {
            eprintln!(
                "confine: this process inherited descriptors {held:?} beyond stdio, which \
                 every child would inherit and refuse; run it with stdio alone: \
                 python3 scripts/stdio-only.py cargo test …"
            );
            std::process::exit(1);
        }
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
            after.nlink() == 1,
            "the canary gained a hard link".into(),
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

        // Descriptors. Inherited from the parent: exactly one re-exec, then
        // a clean start, the marker then this process's id. A marker with
        // another id, or not a number, is no marker. A marker already its
        // own (a re-exec that left one), or a re-exec that fails: refused,
        // and an owned descriptor still works. Opened by the startup after
        // the entry: refused whatever its type, so the service exits 77.
        let starts = |text: &str| -> Vec<String> {
            text.lines()
                .filter(|line| line.starts_with("START "))
                .map(str::to_owned)
                .collect()
        };
        let once = |text: &str| {
            starts(text) == ["START ours=false", "START ours=true"]
                && text.contains("ENTRY reexeced\n")
                && text.contains("MARKER ours\n")
                && text.contains("REPORT ")
        };
        for (case, kind, marker) in [
            ("files", "pipe", None),
            ("files", "socket", None),
            ("fallback", "pipe", None),
            // Another process's id, as a parent service's would be.
            ("files", "pipe", Some("1")),
            ("files", "socket", Some("yes")),
        ] {
            let mut command = command(&world, case);
            if let Some(marker) = marker {
                command.env(confine::REEXEC_MARKER, marker);
            }
            let output = inheriting(kind, command);
            let text = lines(&output);
            let what = format!("{case}, inherited {kind}, marker {marker:?}");
            expect(&mut failures, once(&text), format!("{what}: {text}"));
            failures.extend(passed(&what, &output));
        }
        let output = inheriting("pipe", with_own_marker(&world, "marker-inherited"));
        let text = lines(&output);
        expect(
            &mut failures,
            starts(&text) == ["START ours=true"]
                && text.contains("ENTRY left\n")
                && text.contains("INVALID pipe\n"),
            format!("our own marker with a descriptor left: {text}"),
        );
        let output = inheriting("socket", command(&world, "reexec-fails"));
        let text = lines(&output);
        expect(
            &mut failures,
            starts(&text) == ["START ours=false"]
                && text.contains("ENTRY left\n")
                && text.contains("INVALID socket\n"),
            format!("a failed re-exec: {text}"),
        );
        failures.extend(passed("reexec-fails", &output));

        // The re-exec keeps every argument, argv[0] included, byte for
        // byte: an empty one and bytes that aren't UTF-8 among them, on
        // both ways of marking.
        for case in ["argv", "argv-fallback"] {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::process::CommandExt;
            let arg0: &[u8] = b"freedom-\xff-service";
            let args: [&[u8]; 4] = [b"serve", b"", b"--data-dir=\xc3\x28\xfe", b"last arg"];
            let mut command = command(&world, case);
            command.arg0(std::ffi::OsStr::from_bytes(arg0));
            for arg in args {
                command.arg(std::ffi::OsStr::from_bytes(arg));
            }
            let output = inheriting("pipe", command);
            let text = lines(&output);
            let expected = serde_json::to_string(
                &std::iter::once(arg0)
                    .chain(args)
                    .map(|arg| arg.iter().map(|b| format!("{b:02x}")).collect::<String>())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            let argv: Vec<&str> = text
                .lines()
                .filter_map(|line| line.strip_prefix("ARGV "))
                .collect();
            expect(
                &mut failures,
                once(&text) && argv == [expected.as_str(), expected.as_str()],
                format!("{case}: {argv:?}, expected {expected}: {text}"),
            );
        }
        for kind in ["socket", "pipe", "file", "eventfd", "epoll"] {
            let case = format!("inject-{kind}");
            let output = run(&world, &case);
            expect(
                &mut failures,
                lines(&output).contains(&format!("INVALID {kind}\n")),
                format!("{case}: {}", lines(&output)),
            );
        }
        let (output, answer) = run_on_socket(&world);
        failures.extend(passed("stdio-socket", &output));
        expect(
            &mut failures,
            answer == "pong\n",
            format!("stdio socket answer: {answer:?}"),
        );
        failures.extend(passed("ephemeral", &run(&world, "ephemeral")));

        // A list `confine` can't read proves nothing: refused, no report.
        for (case, what) in [
            ("unreadable-fd", "descriptor table"),
            ("unreadable-task", "thread list"),
        ] {
            let output = run(&world, case);
            let text = lines(&output);
            expect(
                &mut failures,
                text.contains(&format!("INVALID unreadable {what}\n")) && !text.contains("REPORT"),
                format!("{case}: {text}"),
            );
        }

        // The service's own first filter refused: an invalid policy, never
        // `blocked`, so the service exits 77.
        let output = run(&world, "invalid-bpf");
        let text = lines(&output);
        expect(
            &mut failures,
            text.contains("INVALID rules\n") && !text.contains("REPORT"),
            format!("invalid first filter: {text}"),
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
