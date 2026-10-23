# 0010: OS confinement for the service processes

**Status:** decided (the user, 2026-10-23): every recommendation, D1–D7. It answers #96, for the service processes of [0007](0007-ipfs-service.md) (`freedom-ipfsd`) and [0008](0008-radicle-service.md) (`freedom-radicled`), on [0001](0001-freedom-cored.md)'s process model and hardening and `fc-service`'s shared skeleton.
- **D1:** confinement is adopted.
- **D2:** a service runs without a mechanism the OS lacks, and reports it, per property.
- **D3:** macOS gets a self-applied Seatbelt profile, through FFI.
- **D4:** Windows gets the job object and the mitigation policies now. A restricted token with a relaunch follows once a spike qualifies it, and AppContainer only if that fails.
- **D5:** the Radicle import runs in a one-shot import process, which reconciles the home first and reads only the checked repository roots.
- **D6:** the `landlock` and `seccompiler` crates, pinned exactly.
- **D7:** `freedom-cored` is confined too, in a later design.

[Decisions](#decisions) records each, and the options weighed are kept throughout as the decisions' rationale.

## Summary

- **The problem:**
  - Both services parse data from untrusted peers:
    - `freedom-ipfsd`: libp2p, Bitswap, UnixFS, DNS answers and HTTP responses;
    - `freedom-radicled`: heartwood's wire protocol, git packs and COBs.
  - Both run as the user, with no OS confinement. 0007 and 0008 list an OS sandbox as a non-goal.
- **What a compromise reaches:** a parser bug that gives a peer code execution, or a logic bug that reads a path it shouldn't, reaches everything the user can:
  - the profile's vault file, for offline guessing;
  - the Bee keystore with its password beside it, and so the Bee wallet (0001, K-3);
  - the Radicle key;
  - other profiles and the rest of the user's files;
  - local services that act for the user, such as the session bus and the systemd user manager, which can start processes.
- **Why now:** each service needs only its own data directory, its pipes, the network and a few system files. The skeleton they share is being built now.
- **The decision** (D1): each service confines itself once at startup, after it has taken its lock, and before it starts a second thread or reads any untrusted input:
  - **Linux:** Landlock for files, and for TCP ports where the kernel has them, plus a seccomp filter that refuses process creation, local sockets, the file calls Landlock doesn't check, and other syscalls the service never makes;
  - **macOS:** a Seatbelt profile with the same paths;
  - **Windows:** a job object that allows no child process, plus process mitigation policies. Confining file reads needs a relaunch under a restricted token, the next step once a spike qualifies it, or AppContainer if that fails (D4).
- **The network policy becomes fixed per process:** main passes it at spawn, and a change starts a new process. 0007 and 0008 change to match ([The network policy and the lifecycle](#the-network-policy-and-the-lifecycle)).
- **What it protects,** on Linux and macOS: the node secrets of other components, the user's other files, and the user's local services, from a compromised service. On Windows the first step only refuses child processes (D4).
- **What it can't protect:**
  - a service's own secrets and data. `freedom-radicled` holds the Radicle key in memory, whatever the custody mode;
  - on Linux, other files' metadata: names, sizes, modes and times stay readable;
  - the network beyond the in-process [address gate](0007-ipfs-service.md#the-gate);
  - the kernel.
- **The Radicle import,** which reads a path the user picks at runtime, runs in a one-shot import process of its own (D5).

## Goals and non-goals

**Goals**
- **No file access outside the service's own directory:** a compromised service can't read, write or change the user's other files, on every OS where an unprivileged mechanism exists: Linux and macOS, and Windows only with a restricted token or AppContainer (D4).
- **No local IPC beyond the authorized channels:** no connection to another process's local socket, and no signal to one, on Linux and macOS. The authorized channels are main's connection on stdio, inherited at spawn, and on macOS the system's resolver and configuration services that the profile must allow ([macOS](#macos)). The `ipc` property is reported, and tested, by this definition ([Reporting](#the-recommendation), step 5).
- **No child processes,** on every OS, and **no debugging of other processes** where the OS can refuse it: Linux and macOS.
- **No admin rights and no installer changes.** On every OS, main spawns the services exactly as 0007 and 0008 say: on macOS too, since the profile is self-applied (D3).
- **Honest reporting:** the service reports, per property, what confinement it got and why anything is missing. Tests prove each OS's rules.
- **A chosen failure behavior** when the OS lacks a mechanism: run, and report the gap (D2).

**Non-goals**
- **Confining `freedom-cored`.** It must read the vault and write node identities. A later design confines it to those directories (D7).
- **Confining Bee, Ant, Arti, Myotis, or Electron's own processes.**
- **Enforcing the address policy in the kernel.** That is only partly possible: ports on Linux, and on macOS a port on loopback or on any host. 0007's gate stays the enforcement point.
- **Defending against kernel exploits, root or admin.**

## What a compromised service reaches

| What | Where | Today, from either service | Confined, on Linux and macOS |
|---|---|---|---|
| the vault file (ciphertext) | the identity directory | readable: offline guessing against PBKDF2 | not readable |
| the Bee keystore and the password in `config.yaml` (0001, K-3) | the Bee data directory | readable: the Bee wallet and its funds | not readable |
| the Radicle key | no file at rest: the core releases it sealed to `freedom-radicled` at each start (0008) | held in `freedom-radicled`'s memory, by design | the same: `freedom-radicled` [keeps it](#the-radicle-home-and-key-custody) |
| other profiles, the browser's data, the user's files | anywhere | readable and writable | neither. On Linux, their metadata stays readable ([Linux](#linux)) |
| start-up items and shell profiles | the user's home | writable: persistence | not writable |
| local services: the session bus, the systemd user manager, agent sockets | the user's runtime directory | reachable: they act for the user, and some start processes | not reachable |
| other processes | — | can start any; can debug a same-user process that allows it | can start none and debug none |
| the network | — | anything | unchanged, except where [noted](#options-per-os) |
| main | the pipe | frames only, which main checks (0001, 0007) | the same |

On Windows, the first step (a job object and mitigation policies) refuses child processes only. The files, local IPC and other same-user processes stay reachable until a restricted token or AppContainer (D4).

## What each service needs

| | Read and write | Read only | Network |
|---|---|---|---|
| `freedom-ipfsd`, persistent | its data directory: the SQLite file, its `-wal` and `-shm`, its journal | on Linux, glibc's resolver configuration and the C library's own directory ([Name resolution](#name-resolution-through-glibc)), with `/run/systemd/resolve/resolv.conf` and what the files link to. No TLS roots: the TLS stack has them built in (`webpki-roots`) | `direct`: outbound TCP and UDP (QUIC), including port 53 to resolvers on loopback and private addresses. `socks5`: TCP to the proxy's endpoint only, the IP literal and port of `--network`, on loopback or the LAN (0007) |
| `freedom-ipfsd`, ephemeral | nothing | the same | the same |
| `freedom-radicled` | its Radicle home, and the empty `HOME` directory it owns (0008), with renames and links across their directories | the same | `direct`: outbound TCP, and port 53 as above. `socks5`: TCP to the proxy's endpoint only |

**Both services also use:**
- stdin, stdout and stderr, which are inherited: a socket pair or pipes, connected to main only;
- the lock file, opened before confinement, whose descriptor stays usable. The service registers it with `confine` ([The recommendation](#the-recommendation), step 1). The ephemeral IPFS process has none;
- the network policy, from the spawn arguments ([below](#the-network-policy-and-the-lifecycle));
- threads, memory, clocks and `getrandom`;
- in `freedom-ipfsd`, one UNIX socket pair, which tokio's signal driver creates. No other local socket: glibc's resolver reaches DNS without one, and its sources that need one are refused ([Name resolution](#name-resolution-through-glibc));
- on Linux, `/proc/self` and the cgroup files the standard library reads for the CPU count.

**No other writable place:** SQLite's temporary files stay in memory (`temp_store = MEMORY`, which 0007 already sets for memory stores) or in the data directory.

**NAT64 prefix discovery** ([0007](0007-ipfs-service.md#network-specific-nat64-prefixes), which 0008 shares) runs in `direct` mode, at startup and at least once a minute after. So its accesses last for the process's life:
- one AAAA query for `ipv4only.arpa`, over plain DNS on port 53, to each resolver the interfaces learned, which is often on loopback (`127.0.0.53`) or a private address (a LAN router);
- the files that list them, on Linux. Network changes replace these files, so the grant must survive a replacement ([The recommendation](#the-recommendation));
- on macOS, SystemConfiguration's dynamic store (`State:/Network/Service/<id>/DNS`), a Mach lookup of `com.apple.SystemConfiguration.configd`;
- on Windows, `GetAdaptersAddresses`, and the registry value `DhcpNameServer` under each interface's `Tcpip` parameters.

**The exception:** `rad.import_repo` reads a working copy anywhere on disk, at a path the user picks at runtime ([Import](#the-radicle-import-d5)).

## Options per OS

### Linux

**Landlock** is a Linux security module that an unprivileged process applies to itself (`landlock_restrict_self`, after `PR_SET_NO_NEW_PRIVS`). It can't be lifted, and children inherit it. Its ABI grows with the kernel. The last column is this design's initial policy, not a complete inventory: later ABIs join it as the `landlock` crate and the supported kernels gain them.

| ABI | Kernel | Adds | The initial policy |
|---|---|---|---|
| 1 | 5.13 | file access rights under a path: read, write, execute, create, remove, and so on | uses it |
| 2 | 5.19 | renames and links across directories (`refer`) | uses it; `freedom-radicled`'s minimum |
| 3 | 6.2 | truncation | uses it |
| 4 | 6.7 | TCP `bind` and `connect`, by port | uses it |
| 5 | 6.10 | device `ioctl`s | uses it |
| 6 | 6.12 | scopes: abstract UNIX sockets and signals | uses it |
| 7 | 6.15 | audit logging controls | not needed |
| 8 | 7.0 | `TSYNC`: restricting every thread at once | a backstop ([the order](#the-recommendation)) |
| 9 | 7.1 | pathname UNIX sockets (`resolve_unix`) | uses it |
| 10 | 7.2 | UDP `bind` and `send`, by port | later: the `landlock` crate (0.4.7) stops at ABI 9 |

- **What it protects:**
  - Every file opened after the restriction is checked against the rules. Descriptors opened before it, such as stdio and the lock file, keep working.
  - Without an execute right on any path, no program can be run.
  - A confined process can't `ptrace` one outside its domain.
  - ABI 4 limits TCP by port. ABI 6 stops connections to abstract UNIX sockets, and signals, outside the domain; ABI 9 stops connections to pathname sockets. ABI 10 limits UDP by port.
- **Its limits:**
  - **Some file calls aren't checked:**
    - before ABI 3, `truncate` on a path. A confined process can empty an outside file it can't open;
    - on every ABI, `chmod`, `chown`, `setxattr` (POSIX ACLs included) and `utime` on a path, and metadata reads such as `stat` and `access`;
    - on every ABI, what a descriptor does after its open. On a file the process owns, `fchmod`, `fchown`, `fsetxattr` and `futimens` work on a read-only descriptor, so a read-only grant doesn't stop them.

    seccomp refuses the changes (below). Metadata reads stay: names, sizes, modes and times, not contents. Landlock restricts operations, and gives no private view of the filesystem.
  - **On ABI 1, every rename or link across directories fails** with `EXDEV`, inside the grant too. libgit2 writes each loose object to `objects/tmp_object_git2_…`, then links or renames it into `objects/<xx>/`. So `freedom-radicled` can't write on ABI 1. `freedom-ipfsd`, whose SQLite files share one directory, can.
  - **A rule on a file follows the file, not its name.** A file replaced by a rename isn't covered by its old rule. A rule on a directory covers whatever it holds.
  - **Pathname UNIX sockets wait for ABI 9.** Until then a confined process can connect to any listener: the session bus, the systemd user manager (which starts units on request), an agent's socket. seccomp's socket rule closes that (below).
  - **Threads:** before ABI 8, it restricts only the calling thread and the threads it starts later. A thread started earlier stays unconfined ([the order](#the-recommendation)).
  - **UDP** isn't covered before ABI 10, so QUIC can't be limited there. Port rules name ports, not addresses.
  - **Availability:** the kernel must enable the module. Ubuntu 24.04's does (checked on a 6.8 kernel); elsewhere the service gets the best ABI available, or none (D2).
- **Its cost:**
  - The `landlock` crate (MIT or Apache-2.0, from the Landlock maintainers) gives a safe API that handles older ABIs. Otherwise, an estimated hundred lines of FFI (D6).
  - The rules name paths when they are applied, so the data directory must exist first.

**seccomp-bpf** is a syscall filter the process installs on itself, also after no-new-privileges. It can't be lifted, and children inherit it. It sees the syscall number and its integer arguments, never a path behind a pointer. There are two styles:
- **An allowlist** of exactly the syscalls the service makes. It is the strongest, but fragile:
  - tokio, libp2p, SQLite, libgit2, heartwood and the C library (glibc, from 2.17: 0007's release builds link it dynamically) each choose their syscalls;
  - a dependency update or a new kernel path (`clone3`, `rseq`, `statx`) then kills the process in the field, or fails a call somewhere unexpected;
  - it needs a list per architecture.
- **A denylist** of syscalls a service never makes, answered with an error rather than a kill:
  - process creation and exec: `execve`, `execveat`, and `fork`, `vfork` and `clone` without `CLONE_THREAD`. `clone3`'s flags can't be inspected, so it answers `ENOSYS`, and the C library falls back to `clone`;
  - other processes: `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`;
  - **file changes Landlock doesn't check,** by every route, path or descriptor:
    - `truncate` (`ftruncate` stays: it needs a descriptor open for writing, which Landlock checked);
    - mode and owner: `chmod`, `fchmod`, `fchmodat`, `fchmodat2`, `chown`, `fchown`, `lchown`, `fchownat`;
    - xattrs: `setxattr`, `lsetxattr`, `fsetxattr`, `setxattrat`, and the matching `removexattr` calls;
    - times and attributes: `utime`, `utimes`, `futimesat`, `utimensat`, `file_setattr`;
    - **`ioctl`, by an allowlist** of the commands the services make, compared on the command's low 32 bits, as the kernel reads it: `FIONBIO`, `FIOCLEX`, `FIONCLEX`, `FIONREAD`, and the terminal queries `TCGETS` and `TIOCGWINSZ` (`isatty`). Every other command answers `ENOTTY`, as an unknown one would. A denylist can't be complete: besides the inode-flag commands (`FS_IOC_SETFLAGS`, `FS_IOC_FSSETXATTR`), `FS_IOC_ENABLE_VERITY` takes a read-only descriptor and makes a file permanently read-only, `FS_IOC_SET_ENCRYPTION_POLICY` sets an empty directory's policy, and ext4's `SETVERSION` changes the inode generation, and filesystems add more. Landlock's ioctl right (ABI 5) covers devices only.

    So no file's metadata changes: not one outside the grant, nor one under a read-only grant, such as the import's source. Files in the data directory keep the modes they were created with.
    - **Who makes them,** and none fails for it (the `ioctl` list is the qualification's record of the release binaries' calls; a command outside it fails CI):
      - SQLite's unix VFS (3.51) `fchmod`s a new journal or WAL file to the database's mode, and ignores a failure: the file keeps the mode its creation gave it. It calls `fchown` only as root;
      - libgit2 1.9.6, in heartwood's bare-repository workflow, makes two path calls and no descriptor ones (shared-mode repositories would add more). Its `chmod` probe at repository creation then records `core.filemode = false`, which a bare repository ignores. Its `utimes`, which "freshens" an object that already exists, makes it write the object again. It sets object files' modes when it creates them;
      - std and tokio make them only when asked (`set_permissions`, `set_times`, `fs::copy`). fc-service asks only while it prepares the gate and the data directory (`gate.rs`), before `confine`; after it, neither it, freedom-ipfs v0.4.6 nor heartwood `c208df3` asks. `freedom-cored` does, but isn't confined (D7).
  - **local sockets:** `socket` for any family but `AF_INET` and `AF_INET6`, and `socketpair` for anything but stream sockets. No UNIX socket (pathname or abstract), netlink or packet socket can be opened, so no local service is reachable.
    - **Who needs one:** tokio's signal driver, a stream pair. heartwood's control socket would, and 0008 turns it off upstream.
    - **Name resolution needs none:** glibc's `dns` source reads `/etc/resolv.conf` and asks the DNS server over UDP and TCP. Its sources that need a local socket are refused, and glibc moves on to the next ([Name resolution](#name-resolution-through-glibc)). `freedom-ipfsd`'s own resolver needs none either.
  - kernel surface the service never uses: `bpf`, `perf_event_open`, `userfaultfd`, the `io_uring` calls, `keyctl`, `add_key`, `request_key`, module loading, `kexec`, `mount`, `umount2`, `pivot_root`, `unshare`, `setns`, `personality`, `swapon`, `reboot`.
- **The ABI guard,** before any rule:
  - a call through another architecture's ABI (i386 on x86-64, AArch32 on AArch64) is killed;
  - on x86-64, so is any number with `__X32_SYSCALL_BIT`. x32 shares `AUDIT_ARCH_X86_64` with the native ABI but numbers its syscalls differently, so a denylist of native numbers would let x32 calls through.

  `seccompiler` 0.5.0 checks the architecture, and kills a mismatch, but not the x32 bit. A second filter of a few hand-built instructions adds that check. seccomp runs every filter installed, and the strictest answer wins.
- **Newer syscalls:** a denylist misses calls newer than itself (`fchmodat2` arrived in 6.6, `setxattrat` in 6.13). CI checks the list against the newest kernel's syscall table.
- **Its cost:** `seccompiler` (Apache-2.0 or BSD-3-Clause, a pure-Rust BPF compiler from the rust-vmm project), or a hand-written filter (D6). The syscall numbers differ per architecture: x86-64 and AArch64 here.

#### Name resolution through glibc

0007's Linux release builds link glibc dynamically, built against 2.17 and running on it and every newer glibc, so they resolve host names as the host's glibc does. That is every name `freedom-radicled` resolves in `direct` mode (0008), and any `getaddrinfo` `freedom-ipfsd` makes; its own resolver reads `/etc/resolv.conf` itself. In `socks5` mode neither resolves through glibc: names go to the proxy.

- **How glibc resolves:**
  - It follows the `hosts` line of `/etc/nsswitch.conf`, one source at a time.
  - Before 2.34, the `files` and `dns` sources are libraries of their own (`libnss_files.so.2`, `libnss_dns.so.2`, with `libresolv.so.2`), loaded lazily at the first lookup that reaches each source. From 2.34 they are part of libc. Other sources are always libraries (`libnss_resolve`, `libnss_mdns4_minimal`, `libnss_myhostname`).
  - At each lookup it reads `/etc/nsswitch.conf`, `/etc/resolv.conf`, `/etc/hosts`, `/etc/host.conf` and `/etc/gai.conf`, where they exist. To load a source, the loader reads `/etc/ld.so.cache`.
- **The read-only grant,** on Linux:
  - those configuration files;
  - `/etc/ld.so.cache`;
  - the directory of the running C library, taken from `/proc/self/maps` (`/lib/x86_64-linux-gnu`, say), where glibc keeps its NSS modules and `libresolv`;
  - each file's real location after its symlinks, as for the resolver files ([The recommendation](#the-recommendation)).

  Loading a library needs only the read right: Landlock's execute right covers `execve`, not mapping a library that is open for reading. Nothing in the C library's directory is secret: it is the system's own code.
- **No lookup before `confine`,** in either mode. glibc reads its configuration and loads its sources at the first lookup after it, from the grants above.
  - **A warm-up would gain nothing:** a `localhost` lookup stops at `files` and loads no `dns`.
  - **It could also keep a socket across the boundary.** With `hosts: sss files dns`, SSSD's client would connect to its socket and keep that connection cached, and neither Landlock nor seccomp revokes a connection made before them. So no source ever connects before the rules ([The recommendation](#the-recommendation), step 1).
- **Sources that need a local socket are refused:**
  - **Which:** `resolve` (systemd-resolved's varlink socket), `mdns` and `mdns4_minimal` (avahi), nscd's cache, and `sss`.
  - **What happens:** seccomp refuses the socket. The source answers that it is unavailable, and glibc goes on to the next source, as its default action for an unavailable source says.
  - **With systemd-resolved,** the `dns` source then asks its stub at `127.0.0.53` over port 53, which `direct` mode allows. Common configurations work this way: Ubuntu's `files mdns4_minimal [NOTFOUND=return] dns`, and Fedora's `files myhostname resolve [!UNAVAIL=return] dns`.
- **Unsupported:**
  - **The configurations:** a `hosts` line with no `dns` source after the refused ones, or one that returns on an unavailable source.
  - **What happens:** while confined, names outside `/etc/hosts` don't resolve.
  - **The report:** the service reads `/etc/nsswitch.conf` before `confine`, and `confinement` gives `"resolution": "system"`, or `"files_only"` with its reason, so main can show why. It doesn't confine less for it.
- **Qualified on the release runtime,** not only CI's (Tests, *Before shipping*):
  - the release binaries;
  - glibc 2.25, the oldest the browser runs on (Electron's floor), another from before 2.34, and a current one;
  - in each, a first lookup after confinement, with no lookup before it;
  - with systemd-resolved's `resolve` source and avahi's `mdns4_minimal` in `nsswitch.conf`, and without them.

**Namespaces** (an unprivileged user namespace, then mount, PID, IPC and network namespaces, as `bubblewrap` builds them) would give a private view of the filesystem and of processes. They aren't recommended:
- **Availability varies:**
  - Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor by default (`kernel.apparmor_restrict_unprivileged_userns=1`), unless the binary has an AppArmor profile that allows them, and installing one needs root;
  - other distributions disable them;
  - so do some container and Flatpak setups.
- **No network without help:** a network namespace can't reach the network without a privileged helper or a user-space network stack.
- **Landlock and seccomp already restrict** the operations that matter. What namespaces would add is the private view: metadata outside, and the other processes, would be invisible.

**bubblewrap (`bwrap`)**, which builds those namespaces from outside and then runs the program, is what Freedom's AI agent feature uses (an unmerged branch). It isn't chosen for the services:
- it is an external binary, which Freedom would have to bundle or require;
- it relies on unprivileged user namespaces, which Ubuntu 24.04 and later restrict through AppArmor (above);
- a service confines itself in process, at the marked point: after its lock, and before untrusted input ([The recommendation](#the-recommendation)). bubblewrap would apply its view before the service starts, from a launcher main spawns instead.

**AppArmor or SELinux profiles** need root to install, and fit only distribution packages. They are an option for a `.deb` or `.rpm` later.

**Always:**
- `PR_SET_NO_NEW_PRIVS`, which both mechanisms need anyway;
- 0001's `PR_SET_DUMPABLE=0`.

`RLIMIT_NPROC` counts all of the user's processes, so it can't be used.

### macOS

**A Seatbelt profile, applied by the service itself:**
- **The mechanism:** the `sandbox_init` family of calls, deprecated since macOS 10.8 but still the kernel's sandbox. Chromium confines its helper processes with the same mechanism, through private calls.
- **What it protects:**
  - file reads and writes outside the profile's paths, which can be parameters such as the data directory;
  - `process-exec` and `process-fork`;
  - Mach service lookups, and connections to UNIX sockets;
  - metadata: mode, owner, xattr, flag and time changes are write operations of their own (`file-write-mode`, `file-write-flags` and the like), which a read-only rule doesn't grant, and the profile grants `file-ioctl` nowhere outside the read-write grant;
  - network access, by host and port. The host is `localhost` or `*`: the profile compiler refuses an address literal. So a loopback proxy gets `(remote ip "localhost:9150")`, and a LAN proxy, such as `--network socks5:192.168.1.10:9150`, gets `(remote ip "*:9150")`: port-only, as on Linux. The qualification gate checks both forms on each supported version.
- **Its cost:**
  - FFI, so `unsafe`, in `fc-sys` (AGENTS.md rule 6; D6);
  - an undocumented profile language, for which Apple's own profiles are the reference;
  - Apple may change it.
  - **What the profile must allow:** name resolution through mDNSResponder, a Mach service and a UNIX socket; read access to system libraries and frameworks; for NAT64 discovery, `com.apple.SystemConfiguration.configd`, and in `direct` mode port 53 to loopback and private addresses.
    - mDNSResponder and `configd` are the `ipc` property's authorized channels on macOS, besides main's stdio, and the profile allows them by name. If qualification finds another system service the services need, it joins this list by name, with a change to this design. The profile allows nothing else.
- **A qualification gate:** Linux tests can't show what a profile must allow. Before a release ships, its signed build runs the contract suite confined on every supported macOS version: DNS, TLS, the file operations in the data directory, NAT64 discovery, and `socks5` mode through Arti on loopback and through a SOCKS proxy on the LAN.

**`sandbox-exec(1)`, run by main:** `/usr/bin/sandbox-exec -f <profile> -D DATA_DIR=<dir> freedom-ipfsd serve …`.
- **How it works:** it applies the same profile, then execs the service. The PID and the pipes stay main's child's.
- **For:** no FFI in the service.
- **Against:**
  - its man page marks it deprecated;
  - main's spawn changes;
  - the service can't tell on its own whether it is confined, so main must pass that on.

**App Sandbox** (the `com.apple.security.app-sandbox` entitlement, applied by the kernel when a signed binary starts) is the documented mechanism, but it fits badly:
- **Its own container:** a sandboxed helper gets its own container. It reaches the profile's data directory only through static exception entitlements or security-scoped bookmarks.
  - Static exceptions can't name per-profile directories.
  - A broad one, such as all of Freedom's Application Support folder, would include the identity directories it is meant to keep out.
- **No sandboxed parent:** the usual helper arrangement (`com.apple.security.inherit`) needs a sandboxed parent, and Freedom's app isn't sandboxed.
- **Moving data:** it would move the services' data into their containers, and sign each helper with entitlements of its own.

**Already in place:** the hardened runtime, and `RLIMIT_CORE` 0 (0001).

### Windows

- **A job object, applied by the service itself** (`CreateJobObject`, then `AssignProcessToJobObject` on itself):
  - an active-process limit of 1 refuses every child process;
  - a memory limit would answer 0007's and 0008's open question on an OS memory limit.
  - **No UI restrictions:** libuv already places the service in main's job (0007), and Windows (8 and later) nests a second job only if neither job sets UI limits. A job with them would fail to be assigned.

  Cheap (an estimate), but it doesn't restrict files.
- **Process mitigation policies** (`SetProcessMitigationPolicy`, also self-applied):
  - no dynamic code (`ProcessDynamicCodePolicy`);
  - no images from remote or low-label locations (`ProcessImageLoadPolicy`);
  - no legacy extension points (`ProcessExtensionPointDisablePolicy`);
  - optionally, only Microsoft-signed images from then on (`ProcessSignaturePolicy`). The service loads only system DLLs after it starts, which needs testing.
  - **Each is detected on its own:** set, then read back with `GetProcessMitigationPolicy`. One the OS doesn't know fails alone, and is reported missing.
  - **Not self-applied:** refusing child processes as a mitigation (`PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY`) is set only when a process is created. The job's limit does that job here.

  Cheap (an estimate), but they don't restrict files either.
- **A restricted token with restricting SIDs** (Chromium's model on Windows):
  - **How it works:** every access check runs twice, once with the token's enabled SIDs and once with its restricting SIDs, and access needs both. So it limits reads as well as writes. (`WRITE_RESTRICTED` would limit only writes.)
  - **No privilege needed:** a process may start another with a restricted version of its own token.
  - **A relaunch:** a running process's token can't be replaced. The service, started by main as today, starts its confined copy with the restricted token, passes it only stdio and the lock (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, plus the child-process policy), and relays its exit. That is one more process per service, or a launcher.
  - **ACLs:** the data directory needs an entry for a restricting SID, a lasting change to the user's files, as for AppContainer. System files are reached through restricting SIDs their ACLs already grant (for example `Users`). The user's own files grant only the user, so they stay out. Whatever else grants those SIDs stays reachable, so the set is kept as narrow as qualification allows.
  - **Another desktop:** Microsoft says to run a restricted process on a desktop of its own, so it can't send window messages to the user's applications. The relaunch creates one.
  - **What may break,** to be qualified: anything whose ACL grants no restricting SID, such as DNS through the DNS Client service, Winsock, and NAT64 discovery's `GetAdaptersAddresses` and registry reads.
  - **Its limits:** files on FAT and exFAT volumes have no ACLs, so the token doesn't protect them.
  - **No loopback exemption:** a restricted token has no network isolation, so `socks5` mode works.
- **AppContainer,** or its less-privileged variant, also confines file reads without admin rights. Its costs:
  - **A launcher:** main must spawn the service with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`. Node's `child_process` (libuv) can't, so a small native launcher is needed: a `freedom-cored` subcommand, or an add-on;
  - **ACL changes:** the data directory needs an ACL entry for the container's SID, a lasting change to the user's files;
  - **No loopback:** an AppContainer can't connect to loopback by default. Arti's SOCKS port needs a loopback exemption, which needs admin rights (`CheckNetIsolation`). Without one, `socks5` mode breaks;
  - name resolution and outbound connections need the `internetClient` capability.
- **Low integrity alone** stops writes to the user's files ("no write up") but not reads. It doesn't keep the node secrets in, so it isn't enough on its own.

### In all

| Mechanism | File reads | File writes | Child processes | Local IPC | Kernel surface | Network | Admin rights | Code | Main changes |
|---|---|---|---|---|---|---|---|---|---|
| Linux: Landlock | confined | confined, except metadata | no exec of any file | abstract (ABI 6) and pathname (ABI 9) sockets | — | TCP ports (ABI 4), UDP ports (ABI 10) | no | small | none |
| Linux: seccomp denylist | — | metadata changes and `truncate` refused | refused | no local sockets | reduced | — | no | small | none |
| macOS: Seatbelt | confined | confined | refused | confined | reduced | by port, on loopback or any host | no | FFI, or `sandbox-exec` | D3 |
| Windows: job and mitigations | — | — | refused | — | — | — | no | small FFI | none |
| Windows: restricted token | confined, by ACLs | confined, by ACLs | with the job | by ACLs | — | — | no | relaunch, ACLs, a desktop | none, or a launcher |
| Windows: AppContainer | confined | confined | with the job | confined | — | loopback needs an exemption | for loopback | launcher and ACLs | yes |

"Small" and "cheap" are estimates until the [measurements](#tests) before shipping.

## The recommendation

**The first step, with the services (0007 and 0008, step 4):**
1. **A `confine` step in `fc-service`,** run once on the main thread **while it is the process's only thread**:
   - **Before it, in this order:**
     1. **At entry, one re-exec if anything is inherited.** Right after the panic hook, before anything opens a descriptor, the service lists its descriptors.
        - **If one is open above stderr** and `FREEDOM_SERVICE_REEXEC` doesn't hold the process's own id, the service:
          - marks every descriptor above stderr close-on-exec: `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)` from Linux 5.11, or an `fcntl(F_SETFD)` loop over `/proc/self/fd` before it;
          - executes itself again through `/proc/self/exe`, with the same arguments, `argv[0]` included, and the same environment, plus the marker set to the process's id. `/proc/self/exe` is the running image even if its file was replaced.

          The kernel then closes them all.
        - **The marker is the process's id, and nothing removes it** (`fc_service::confine::REEXEC_MARKER`):
          - **No loop:** an exec keeps the id, so the re-executed image finds its own id and doesn't re-execute again.
          - **Only an exact match counts:** any other value is no marker. That includes a parent service's id, so a nested service still gets its one re-exec, and anything that isn't a number.
          - **Why it stays:** changing the process's environment is unsafe, since a thread could read it at the same moment, and checking for a single thread first doesn't prove there isn't one. So the marker stays.
          - **A reused id fails closed:** a far descendant that inherits the marker and happens to get the same id doesn't re-execute, and `confine` refuses what it inherited (exit 77).
        - **If a service ever spawns a child,** it drops the marker from the child's environment with `Command::env_remove`, which touches only the child's. None does today: the services start no process (0008), and seccomp refuses exec once they are confined. This is tidiness, not safety: a child has another id, so it would ignore the marker anyway.
        - **On macOS** (with the Seatbelt work): a loop over `/dev/fd`, and `execv` of `_NSGetExecutablePath`'s path.
        - **Why a re-exec:** a close can't prove that no Rust object owns the descriptor it closes. Close-on-exec closes nothing, and the exec replaces the whole image, so no owner of a closed descriptor survives. If the exec fails, close-on-exec is merely set, and every owner is still valid. The calls are `fc-sys`'s, as rule 6 says, and the exec is std's.
     2. **Only the listed setup:**
        - the process is hardened;
        - the arguments are parsed, the network policy included;
        - for the persistent IPFS process and `freedom-radicled`: the lock is taken, and the data directory is created and opened. The service registers the lock's descriptor, and any directory it holds open, with `confine`. The ephemeral IPFS process takes no lock and opens no directory: its read-write grant is empty, and it registers nothing.
        - **Nothing else:** no socket, no name lookup, and no file outside the grants. Logging writes stderr only, NAT64 discovery starts with the runtime after `confine`, and the TLS roots are built in.
     3. **`confine` checks** the threads and the whole descriptor table (below), and only then installs the rules.
   - **Refusal is the backstop.** After the re-exec, or with the marker already holding the process's own id, a descriptor still there is refused at `confine`: exit 77, logged by its kind.
     - Main spawns each service with stdio alone: Node and libuv open their own descriptors close-on-exec, as Rust's `Command` does.
     - So the re-exec should seldom happen. It means the launcher leaked a descriptor into main.
   - **After it,** everything that starts a thread: logging's writer (`log::init`; lines before it are written directly), the async runtimes (built explicitly, never by `#[tokio::main]`), `conn::run`'s reader, writer, stdin and lifecycle threads, and the watchdogs. Then the handshake, and only then any untrusted input.
   - **Why:** before ABI 8, Landlock restricts only the calling thread and the threads it starts later. A thread started earlier stays unconfined, and a compromise could use it. seccomp is installed with `TSYNC`, and Landlock with its `TSYNC` from ABI 8, as backstops. The order doesn't rely on them.
   - **Checked:** `confine` counts the process's threads first (`/proc/self/task` on Linux). More than one is a bug, so the service exits 77 rather than report confinement.
   - **Checked too: only the registered descriptors cross.** Landlock and seccomp check new opens and calls only. Nothing they do closes or revokes a descriptor opened before them: a connected socket, a pipe or FIFO, or a file opened outside the grants stays usable.
     - **The check:** `confine` compares every descriptor in the process's table (`/proc/self/fd` on Linux, `/dev/fd` on macOS) with stdio and the descriptors the service registered, whatever its type. The table's own descriptor, which `confine` opens to read it, is known by its number and skipped, and nothing else is opened while it reads.
     - **Anything else** above stderr, opened by the setup or left after the entry's re-exec, is a bug, and the service exits 77:
       - a socket, pipe or FIFO: a channel the rules wouldn't see, such as an NSS source's cached connection;
       - a regular file or directory: access the grants may not give;
       - an `eventfd` or `epoll` descriptor: no channel of its own, but a sign that a runtime was built early, which the thread count misses for a runtime on the current thread.
     - **stdio may be pipes or a socket pair:** main's connection, inherited at spawn.
     - **A list it can't read proves nothing:** if `confine` can't open or read the thread list or the descriptor table, or finds an entry that isn't a number (an outer Landlock layer may hide `/proc/self/fd`), the service exits 77.
2. **Linux:**
   - No-new-privileges.
   - Landlock at the best ABI available, with every right that ABI knows handled:
     - read and write on the data directory, with no execute and no special files (sockets, FIFOs, devices); `refer` on it for `freedom-radicled`; nothing at all for the ephemeral IPFS process;
     - read only on glibc's resolver configuration and the C library's directory ([Name resolution](#name-resolution-through-glibc)), `/proc/self` and the cgroup files. For a resolver file, the grant names the directory that holds it after its symlinks are followed (`/run/systemd/resolve/` with systemd-resolved), so a replaced file stays readable. A file that sits in `/etc` itself is granted alone. Once replaced, it is unreadable until the next process: NAT64 discovery then reports `unknown` and fails closed, as 0007 says for a failed resolver, and lookups may use stale or default servers;
     - no execute right anywhere.
     - From ABI 4: TCP `connect` to any port in `direct` mode, and only the proxy's port in `socks5` mode, on any address, since Landlock's rules name ports only; no TCP `bind`.
     - From ABI 6: both scopes. From ABI 9: `resolve_unix`, with no rule.
     - **Minimum ABIs:** `freedom-ipfsd` uses ABI 1 and up. `freedom-radicled` needs ABI 2: below it, it applies no Landlock rules and reports `files` as `unavailable`, with the reason.
   - The seccomp denylist above, answering `EPERM` (`ENOSYS` for `clone3`), behind the ABI guard.
3. **macOS:** a Seatbelt profile with the same paths and rules, self-applied through FFI (D3), so all three OSes work the same way. It passes the qualification gate before each release.
4. **Windows:** the job object and the mitigation policies, self-applied, each detected on its own. File confinement follows with a restricted token, once its spike qualifies (D4).
5. **Reporting:** `ipfs.hello` and `rad.hello` gain `confinement`, one status per property:

   ```jsonc
   "confinement": {
     "mechanism": "landlock-4+seccomp",   // or "seatbelt", "job", "none"
     "files": "enforced", "exec": "enforced", "ipc": "partial", "network": "enforced",
     "gaps": ["signals"],                 // what "partial" leaves open
     "reasons": {},                       // per property: why it is "unavailable" or "blocked"
     "resolution": "system"               // Linux, `direct` mode: or "files_only", with its reason
   }
   ```

   - **The properties:**
     - `files`: outside the grant, no file can be read or written; outside the read-write grant, none can be truncated; and no file, granted or not, can have its mode, owner, xattrs, flags or times changed;
     - `exec`: no program runs, and no process is created;
     - `ipc`: no local IPC reaches another process beyond the authorized channels ([Goals](#goals-and-non-goals)): main's connection on stdio, and on macOS mDNSResponder and `configd`. No other local socket connects, and no signal is sent to another process. `enforced` means exactly this, and `partial` names what is left open (`gaps`);
     - `network`: in `socks5` mode, TCP reaches only the proxy's port (on macOS, at the proxy's loopback host where it is one).
   - **The statuses:** `enforced`, `partial`, `unavailable` or `blocked` (step 6), or, for `network` in `direct` mode, `none`.
   - **Derived, not assumed:** each status comes from what was installed: the ABI the kernel reports and the rights handled at it, the `landlock` crate's `RestrictionStatus`, each mitigation read back. A best-effort call that returned success is not evidence: the crate drops unsupported rights silently.

   Main logs it, and shows it in the nodes panel's diagnostics.
6. **Failure,** as D2 decided: a missing mechanism doesn't stop the service. The outcomes are kept apart:

   | Outcome | When | Reported | Then |
   |---|---|---|---|
   | partial | the kernel lacks some rights: Landlock before ABI 4 has no TCP rules, before ABI 6 no signal scope | `partial`, with the gaps | runs |
   | unavailable | the OS lacks the mechanism: Landlock disabled, an ABI below the service's minimum, a mitigation an older Windows doesn't know | `unavailable`, with the reason | runs (D2) |
   | externally blocked | something outside refuses a mechanism that exists: a container's seccomp filter answering `EPERM` to the Landlock calls, or an outer sandbox that used Landlock's 16 layers | `blocked`, with the reason | as unavailable |
   | invalid policy | the mechanism refuses the service's own rules; a second thread before `confine`; a descriptor it didn't register, or a thread list or descriptor table it can't read; an installation stopped halfway | never | exit 77 (`confinement`), which main doesn't restart |

   - **seccomp's first filter:** when the kernel refuses it, a filter that allows everything is tried. If the kernel takes that one, it takes filters, so it refused the service's own: invalid policy. If it refuses that one too, its error decides: `EINVAL` or `ENOSYS` is `unavailable`, anything else `blocked`.

7. **Main's check,** before it spawns a service:
   - **The grant:** this service's own directory: the persistent IPFS data directory, or the Radicle home with its `HOME` directory.
   - **The protected roots:** the lock directory, and the identity directory and every other component's data directory (Bee, Ant, Myotis, Tor, the other service), for this profile and the catalog's others.
   - **The rule:** main refuses a grant that is, contains, or lies inside a protected root. The service's own directory is the grant, never a protected root.
   - **Compared as canonical paths,** under 0001's rules: symlinks resolved, and case folded on case-insensitive volumes. So an override such as `FREEDOM_IPFS_DATA` can't widen the grant over the secrets.

**Later:**
- a seccomp allowlist, once the release builds' syscalls are measured, as a decision of its own;
- on Windows, a restricted token with a relaunch, once a spike qualifies DNS, Winsock, NAT64 discovery and the desktop; AppContainer only if that fails (D4);
- confining `freedom-cored` to its own directories, in a later design (D7).

## The network policy and the lifecycle

- **The conflict:** Landlock and Seatbelt fix their network rules when they are applied, before `hello`. But 0007 sent the policy later, in `ipfs.start`, and changed it by restarting instances inside the process. A rule fixed to Arti's port P can't later allow port Q or `direct` mode. A rule left open for later would break `socks5` mode's promise.
- **The policy comes with the spawn:** main passes it as an argument, `--network direct` or `--network socks5:<ip>:<port>` with an IP literal, to both IPFS processes and to `freedom-radicled`.
  - It is trusted configuration, like `--data-dir`. `confine` applies it before `hello`, and `hello` reports it back.
  - `ipfs.start` and `rad.start` no longer carry it. With the proxy setting on, main spawns a service only once `tor-manager` reports Arti's endpoint.
- **A change is a new process:** a switch between `direct` and `socks5`, or a new Arti endpoint, ends each service process and starts a new generation with the new policy:
  - **IPFS:** main retires the generation of the persistent and the ephemeral process, so every request captured for either fails at once, and shuts both down. It spawns the persistent process again once the old one has exited, and the ephemeral one when a private window next needs it. Private instances come back cold, under new IDs.
  - **Radicle:** as 0008 already does ("changing the policy restarts the process").
- **0007 and 0008 change to match** in this PR: their spawn lines, `hello`'s result, `ipfs.start`'s and `rad.start`'s parameters, and 0007's *Changing the policy* and its tests.

## The Radicle home and key custody

- **Confinement can't protect a service's own secrets.** `freedom-radicled` holds the Radicle key in memory while the node runs (0008, *Keys*), in every custody mode. What confinement adds:
  - it keeps the vault and the Bee keys from `freedom-radicled`;
  - it keeps `freedom-ipfsd` from the Radicle home. The Radicle key itself has no file at rest (below), and 0001's `PR_SET_DUMPABLE=0` already keeps a same-user process from reading `freedom-radicled`'s memory.
- **The custody is 0008's, decided** (the user, 2026-10-22; 0008's open questions 2 and 3): the sealed host key. No key file is at rest, and the core releases the key sealed to the service at each start (`rad.identity`), but the service still holds it.
- **So this design neither changes nor depends on the custody decision.** Confinement narrows what a `freedom-radicled` compromise adds beyond the Radicle identity.
- **Unconfined processes:** the Bee keystore password beside the keystore (0001, K-3) stays readable by every unconfined same-user process. Confinement only removes the two services from that set.

## The Radicle import (D5)

`rad.import_repo` reads a working copy at a path the user picks at runtime (0008, *Writes*). Landlock and Seatbelt rules are fixed once applied, and can only be narrowed. A working copy's git data may also lie outside the path the user picked.

**Decided (the user, 2026-10-23): the one-shot import process** (option 1). The others are kept below as the decision's rationale.

1. **A one-shot import process** (decided):
   - Main stops the service and runs `freedom-radicled import --home … --lock-dir … --source <path>`. The process takes the home gate, confines itself, and answers four of 0008's methods, in order: `rad.hello`, `rad.identity`, `rad.reconcile`, then `rad.import_repo`, whose `path` must be the `--source`. It exits after the import. Then main starts the service again.
   - **The repository's roots** are found before confinement, from the source's own files, without libgit2:
     - the source;
     - its git directory: `.git`, or the directory a `gitdir:` file names;
     - for a linked worktree, the common directory its `commondir` names;
     - each objects directory that `objects/info/alternates` lists, recursively, to libgit2's depth.

     Each is canonical.
   - **Every root passes main's check** ([step 7](#the-recommendation)): none is, contains, or lies inside a protected root. So a repository at the user's home is refused, since it contains Freedom's data.
   - **The grant:** read only on exactly those roots, read and write on the home, and no network: no TCP rule (ABI 4), and seccomp refuses every socket family.
   - **Unsupported layouts are refused** with `unsupported_layout`, before anything changes: a root that fails the check, or more roots or depth than the bound. Anything libgit2 then reads outside the roots, such as a configuration `include`, fails the source's open, which comes before the import starts.
   - **A clean home first:** a stopped node doesn't prove the home clean. 0008 lets a stop reach its 5 s exit with a write or a fetch unfinished, which leaves the dirty marker, ref lock files or an unsigned namespace. So the process runs 0008's reconciliation before it admits the import:
     - `rad.import_repo` is admitted only after `rad.reconcile` has succeeded in the same process. Before that it gets `stopped`, and nothing changes.
     - A reconciliation that ends in `deadline` or `recovery_failed` ends the process with nothing imported, as it ends a service's start. Main shows 0008's "Radicle is still repairing its data" with Retry, or the error.
     - Quarantines are recorded and reported as at a start.
     - **Why repair rather than refuse a dirty home:** the procedure is this binary's own, and resumable. A refusal would make main start the service to repair, stop it, and try again, and that stop can be unclean too.
   - **The bounds:** `rad.reconcile` keeps 0008's 300 s, with main's watchdog at 315 s. `rad.import_repo` then has its own 300 s from admission, under the process's watchdog (exit 70), with main's at 315 s. So the node is down for at most about ten minutes. Without the marker, reconciliation only removes temporary clones and ref lock files.
   - **0008's contracts hold:**
     - **Key custody:** the import, and any re-signing during reconciliation, use the node key the core releases sealed, through `rad.identity`, as at a start (0008, *Keys*). So, on a profile with a vault, an import waits for an unlock as a start does. A profile without one has no import: main refuses it with `needs_vault`, and the process never makes a throwaway key.
     - **The dirty marker:** as in a service's run. Reconciliation writes it before changing anything, and it stays while the process runs. It is removed at the exit only when no write is uncertain: after a proven import, or a refusal before the mutation. Any other end leaves it, and the service's next start reconciles again.
     - **Outcomes:** a failure before the mutation starts is definitive (`invalid_argument`, `unsupported_layout`). After it, only a success is proven. An error, a crash, a kill or the deadline is `outcome_unknown`.
     - **Upstream:** libradicle's import runs on storage, without a running node. The node announces the repository with its inventory at its next start.
   - **What 0008 gains** (made in this PR, to its *Writes*, methods and bounds):
     - the `import` subcommand, with its four methods and the admission rule above;
     - `rad.import_repo` leaves the service's write queue, and with it the need to hold the node exclusively;
     - main's `importRepo` stops the service, runs the import process, and starts the service again. It still refuses private partitions.
   - **Cost:** the node is down for the import, and for any repair before it. Imports are rare and user-started.
2. **A read-only grant on the user's home,** or on a root the user configures:
   - **For:** simple.
   - **Against:** a `freedom-radicled` compromise can then read the user's files, Freedom's own included. Landlock can't express "the home except these directories".
3. **Main stages the working copy** into a directory inside the home, for example as a git bundle, and the service imports from there.
   - **Cost:** a copy, and git work in main.
4. **Main passes an open directory handle:**
   - On Unix, that needs a socket rather than 0001's pipes; on Windows, a duplicated handle.
   - It changes the protocol.

## Tests

Through the binary, in CI's job for each OS:
- **Files:**
  - two canary files, one in a sibling of the data directory and one in the user's home: reading and writing either fails once the service is confined;
  - on the same canaries: `truncate`, `chmod`, `chown`, `setxattr` and `utimensat` with a path all fail, and the size, mode, xattrs and times are unchanged. `stat` succeeds: the accepted residual;
  - **a read-only grant:** a file in the import's source, opened read-only. `fchmod`, `fsetxattr` and `futimens` on its descriptor fail, and the parent sees its mode, xattrs and times unchanged. On macOS, the same through the profile;
  - **the `ioctl` allowlist:** on that descriptor, `FS_IOC_SETFLAGS`, `FS_IOC_FSSETXATTR`, `FS_IOC_ENABLE_VERITY`, `FS_IOC_SET_ENCRYPTION_POLICY` (on an empty directory in the source), ext4's `SETVERSION` and an unknown command answer `ENOTTY`, and the file is unchanged. Where CI's filesystem lacks verity or encryption, the generated filter is evaluated on those commands instead, as for the ABI guard. The qualification workload's recorded `ioctl`s are exactly the allowlist;
  - **per ABI,** with each ABI's rights on CI's kernel: on ABIs 1 and 2, seccomp's `truncate` rule holds; on ABI 1, `freedom-radicled` reports `files` as `unavailable`, and `freedom-ipfsd` passes its contract suite;
  - **qualification under the metadata rule:** SQLite creates and checkpoints its journal and WAL, and libgit2 creates a repository, writes loose objects and packs, and writes an existing object again, all without error;
  - a resolver file replaced by a rename while the service runs: still readable through its directory's grant; in `/etc`, discovery reports `unknown`;
  - the service still passes its contract suite confined.
- **Descriptors,** each case stating where its descriptor comes from:
  - **inherited from the parent:** an extra pipe, and an extra socket, each give exactly one re-exec, then a clean start, with the marker holding the process's own id. This holds through `close_range` and through the `fcntl` fallback. An inherited marker holding another id, or no number, counts as none and gives the same one re-exec;
  - **the re-exec keeps every argument:** `argv[0]` and each argument, an empty one and bytes that aren't UTF-8 among them, compare byte for byte before and after it, through both ways of marking;
  - **the marker already holding the process's own id, with a descriptor still there:** no re-exec, and exit 77;
  - **a re-exec that fails:** a descriptor the process owns still works after close-on-exec is set, and the inherited one is refused (exit 77);
  - **opened by the process's own startup, after its entry and before `confine`:** a UNIX socket connected to a listener, as an NSS client's cached connection would be, a pipe, a file opened outside the grants, an `eventfd` and an `epoll` descriptor. Each makes `confine` refuse (exit 77);
  - **hidden:** with a socket connected, an outer Landlock layer that hides `/proc/self/fd`, or `/proc/self/task`, makes `confine` refuse, and no report comes back;
  - **allowed:** stdio as pipes, and as a socket pair, with a registered lock and directory, passes. So does the ephemeral IPFS process, which registers nothing;
  - **in each service,** the descriptors open at `confine` are exactly stdio and the lock, and the ephemeral process's are stdio alone.
- **Threads:** a test hook reads a canary from every kind of thread the real binary has: the main thread, the log writer, the reader, writer, stdin and lifecycle threads, a runtime worker and a blocking-pool thread. Each fails. A hook that starts a thread before `confine` makes the service exit 77.
- **Processes:**
  - a test hook's attempt to run `/bin/sh` (`cmd.exe` on Windows) fails;
  - on Linux, `ptrace` and `process_vm_readv` of another process fail.
- **seccomp:**
  - **live:** each denied call that std or rustix offers safely (exec and process creation, the mode, owner, xattr and time calls, `ioctl`, the socket families) fails as the filter answers. Rule 6 allows no raw-syscall facility outside `fc-sys`, and a generic one would be unsound, so calls without a safe API aren't made live;
  - **the whole denylist:** the generated BPF, the exact programs installed, evaluated in a unit test on synthetic records for every denied call, and for native, compat (i386, AArch32) and x32 calls, whatever CI's kernel enables. The calls it must deny are a list in the test, by name and number from the kernel's tables for each architecture, independent of the code that builds the filter, so dropping a rule fails it;
  - **the ABI guard, live:** on x86-64, `getpid` with `__X32_SYSCALL_BIT`, and through the i386 ABI (`int 0x80`), is killed, where the kernel has those ABIs. These two calls are `fc-sys`'s only test helpers, behind its `test-abis` feature.
- **Local IPC,** by `ipc`'s definition: a listener on a pathname socket and one on an abstract socket, outside every grant: connecting to either fails (seccomp; and from ABI 9, Landlock). Main's connection on stdio, as a socket pair, still works, and so does tokio's socket pair inside the process. On macOS, the qualification gate shows mDNSResponder and `configd` answering, and a listener outside them refused.
- **Network:**
  - in `socks5` mode, a TCP connection to any port but the proxy's is refused by the kernel, on Linux from ABI 4 and on macOS;
  - **a LAN proxy:** `--network socks5:<a private address>:<port>`, with a SOCKS proxy listening there: the service reaches it, and on macOS its profile has the port-only rule;
  - **name resolution, on Linux** (`freedom-radicled`, and `freedom-ipfsd`'s `getaddrinfo` if it makes any):
    - a first lookup after confinement, with no lookup before it, resolves a name in `/etc/hosts` and one through DNS;
    - with `resolve` before `dns` in a fixture `nsswitch.conf`, the lookup falls back to `dns`;
    - with no `dns` source, `confinement` reports `files_only`;
  - **policy changes:** `direct` → `socks5` → `direct`, and Arti's port P → Q. Each runs in a new generation with the new `--network`; the old generation's process has exited; and a private instance, recreated after each change, gets the new rules;
  - **NAT64 discovery:** a fake resolver on a loopback address, listed in a fixture resolver file, sees one AAAA query for `ipv4only.arpa` per refresh. From `freedom-ipfsd` it sees no other DNS. `freedom-radicled`'s ordinary lookups use the system resolver in `direct` mode (0008), so for it the check is that discovery sends nothing else.
- **Reporting:**
  - `hello` reports the mechanism and each property's status;
  - where CI's kernel offers Landlock, the test requires the ABI it offers, so a silent downgrade fails CI.
- **D2:**
  - a forced unavailable mechanism gives `unavailable` with its reason, and a working service;
  - a forced `EPERM` from the setup calls gives `blocked`;
  - a forced invalid rule gives exit 77, and main doesn't restart the service;
  - an invalid first seccomp program, on a kernel that takes filters, gives exit 77, never `blocked`.
- **Main:**
  - the default directories pass: `<userData>/ipfs-data/freedom-ipfs`, and the Radicle homes `<appRoot>/R/<slot>` and `<userData>/radicle-data`;
  - a grant equal to, inside, or containing the identity directory, the lock directory or another component's directory is refused, through overrides (`FREEDOM_IPFS_DATA`, `FREEDOM_RADICLE_DATA`), a symlink alias and, on macOS and Windows, a case alias.
- **D5,** the import process:
  - a working copy outside the home; a linked worktree; a separate git directory; alternates; a symlink out of the source;
  - a source that contains a protected root: refused;
  - the helper opens no socket, and a canary listener sees nothing;
  - a kill and a timeout during the import, then a restart: the marker stays, the service reconciles, and the reply is `outcome_unknown`;
  - **an unclean stop before admission:** a write and a fetch unfinished at the stop's 5 s exit, leaving the marker and a ref lock file. The import process repairs them before it admits the import. A `rad.import_repo` sent before `rad.reconcile` has replied gets `stopped` and changes nothing. A reconciliation that reaches its deadline imports nothing.
- **Windows:** the job is assigned inside libuv's job, and each mitigation reads back as set.
- **Before shipping, on the release runtime** (each release's checklist): the release binaries, confined, on glibc 2.25 (the oldest the browser runs on), another from before 2.34 and a current one, each with a first lookup after confinement and none before it; with and without `resolve` and `mdns4_minimal` in `nsswitch.conf`; `socks5` mode through a LAN proxy, on Linux and macOS; and the packaged app started each way users start it (the desktop entry, a terminal, each Linux package format, macOS's Finder and Dock), checking from the services' logs that their entry re-exec seldom happens. A descriptor the app itself inherited without close-on-exec passes through to the services on Linux, and each start then re-executes once.
- **Before shipping, measured:**
  - cold start to `hello`;
  - IPFS over direct TCP and QUIC, `socks5` reconnects to Arti, and SQLite;
  - Radicle's fetch, import and COB writes;

  all under the release policies, with the denial and fallback cases on the oldest supported kernels and both architectures. One recent kernel doesn't exercise the missing-right cases.

## Decisions

Each is decided (the user, 2026-10-23), as recommended. The options weighed stay with each, as the decision's rationale.

- **D1. Adopt confinement** for the service processes, as above, or keep 0007's and 0008's non-goal for now.
  - **Decided: adopt.** 0007's and 0008's non-goal now points here.
- **D2. When the OS lacks a mechanism, or something outside blocks it:**
  - run without it and report it, per property;
  - or refuse to start unless `files` and `exec` are `enforced`.

  Either way, partial confinement runs and is reported, and an invalid policy exits 77. `freedom-radicled` below ABI 2 counts as `files` unavailable.
  - **Decided: run, and report it, per property.** A service runs on a kernel without Landlock, or behind a container's seccomp filter, and `hello` says what it lacks. Only an invalid policy exits 77.
- **D3. macOS:**
  - a self-applied Seatbelt profile through FFI;
  - `sandbox-exec` run by main;
  - or nothing until App Sandbox can work.
  - **Decided: a self-applied Seatbelt profile, through FFI** in `fc-sys`. Main's spawn doesn't change, and the service knows its own confinement.
- **D4. Windows:**
  - the job object and mitigation policies now; then a restricted token with a relaunch, once a spike qualifies DNS, Winsock, NAT64 discovery and the desktop; AppContainer only if that fails;
  - or a restricted token now, with the relaunch, ACLs on the data directories and a desktop;
  - or AppContainer now, with a launcher, ACLs on the data directories and a loopback exemption for Arti.
  - **Decided: the job object and mitigation policies now, then the restricted token after its spike, and AppContainer only if that fails.**
- **D5. The Radicle import:** a one-shot import process that reconciles the home first and reads only the checked repository roots, a read-only home grant, staging by main, or handle passing.
  - **Decided: the one-shot import process** ([The Radicle import](#the-radicle-import-d5)). 0008 changes to match in this PR.
- **D6. Code:**
  - the `landlock` crate (MIT or Apache-2.0) and `seccompiler` (Apache-2.0 or BSD-3-Clause), which keep their `unsafe` inside them, pinned to exact versions (today `landlock` 0.4.7 and `seccompiler` 0.5.0). Each mechanism maps to one status: Landlock's from its `RestrictionStatus` and the kernel's ABI; seccomp's from installing both filters; each Windows mitigation from its read-back;
  - or hand-written FFI.

  The macOS and Windows calls need FFI either way. AGENTS.md rule 6 puts every `unsafe` of this workspace in `fc-sys`, each a single reviewed call with a `SAFETY` comment behind a safe function, as `fc-service`'s Windows calls already are (#116). `fc-service` keeps `forbid(unsafe_code)`, and calls them through `fc-sys`'s safe functions. So do Landlock's version query and the entry's close-on-exec marks (step 1). None of them closes a descriptor, so none can invalidate an owner, and the exec that drops the marked descriptors is std's. Nothing changes the process's environment: the marker is the process's id, and stays. A range close isn't among them: a safe function can't prove that no Rust object owns what it closes.
  - **Decided: the `landlock` and `seccompiler` crates, pinned to exact versions,** with `cargo deny` checking them.
- **D7. `freedom-cored`:** confine it too, in a later design, or not.
  - **Decided: confine it too, in a later design.**

Radicle key custody, with the AGENTS.md rules around it, is 0008's, decided there (open questions 2 and 3, #98).
