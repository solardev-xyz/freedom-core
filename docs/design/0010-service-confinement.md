# 0010: OS confinement for the service processes

**Status:** proposed; the decisions are the user's. It answers #96, for the service processes of [0007](0007-ipfs-service.md) (`freedom-ipfsd`) and [0008](0008-radicle-service.md) (`freedom-radicled`), on [0001](0001-freedom-cored.md)'s process model and hardening and `fc-service`'s shared skeleton. **Every choice marked D1–D7 is the user's. This design recommends; it decides nothing.** The [Decisions](#decisions-for-the-user) section lists them.

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
  - other profiles and the rest of the user's files.
- **Why now:** each service needs only its own data directory, its pipes, the network and a few system files. The skeleton they share is being built now.
- **The recommendation:** each service confines itself once at startup, after it has taken its lock and before it reads any untrusted input:
  - **Linux:** Landlock for files, and for TCP ports where the kernel has them, plus a seccomp filter that refuses process creation, debugging and other syscalls the service never makes;
  - **macOS:** a Seatbelt profile with the same paths;
  - **Windows:** a job object that allows no child process, plus process mitigation policies. Windows has no cheap way to confine file reads; AppContainer is a later step.
- **What it protects,** on Linux and macOS: the node secrets of other components, and the user's other files, from a compromised service. On Windows the first step only refuses child processes; files wait for AppContainer (D4).
- **What it can't protect:**
  - a service's own secrets and data. `freedom-radicled` holds the Radicle key in memory, whatever the custody mode;
  - the network beyond the in-process [address gate](0007-ipfs-service.md#the-gate);
  - the kernel.
- **The Radicle import,** which reads a path the user picks at runtime, needs its own answer (D5).

## Goals and non-goals

**Goals**
- **No file access outside the service's own directory:** a compromised service can't read or write the user's other files, on every OS where an unprivileged mechanism exists: Linux and macOS, and Windows only with AppContainer (D4).
- **No child processes,** on every OS, and **no debugging of other processes** where the OS can refuse it: Linux and macOS.
- **No admin rights and no installer changes.** On Linux and Windows, main spawns the services exactly as 0007 and 0008 say. On macOS, that depends on D3.
- **Honest reporting:** the service reports what confinement it got, and tests prove each OS's rules.
- **A chosen failure behavior** when the OS lacks a mechanism (D2).

**Non-goals**
- **Confining `freedom-cored`.** It must read the vault and write node identities. A later design could confine it to those directories (D7).
- **Confining Bee, Ant, Arti, Myotis, or Electron's own processes.**
- **Enforcing the address policy in the kernel.** That is only partly possible: ports on Linux, loopback only on macOS. 0007's gate stays the enforcement point.
- **Defending against kernel exploits, root or admin.**

## What a compromised service reaches

| What | Where | Today, from either service | Confined, on Linux and macOS |
|---|---|---|---|
| the vault file (ciphertext) | the identity directory | readable: offline guessing against PBKDF2 | not readable |
| the Bee keystore and the password in `config.yaml` (0001, K-3) | the Bee data directory | readable: the Bee wallet and its funds | not readable |
| the Radicle key, `<home>/keys/radicle` | the Radicle home | readable by `freedom-ipfsd`; held by `freedom-radicled` by design | not readable by `freedom-ipfsd`; `freedom-radicled` [keeps it](#the-radicle-home-and-key-custody) |
| other profiles, the browser's data, the user's files | anywhere | readable and writable | neither |
| start-up items and shell profiles | the user's home | writable: persistence | not writable |
| other processes | — | can start any; can debug a same-user process that allows it | can start none and debug none |
| the network | — | anything | unchanged, except where [noted](#options-per-os) |
| main | the pipe | frames only, which main checks (0001, 0007) | the same |

On Windows, the first step (a job object and mitigation policies) refuses child processes only. The files, and other same-user processes, stay reachable until AppContainer (D4).

## What each service needs

| | Read and write | Read only | Network |
|---|---|---|---|
| `freedom-ipfsd`, persistent | its data directory: the SQLite file, its `-wal` and `-shm`, its journal | name resolution files (`/etc/resolv.conf`, `/etc/hosts` on Unix); TLS roots, if the TLS stack reads them from disk | `direct`: outbound TCP and UDP (QUIC). `socks5`: TCP to Arti's loopback port only |
| `freedom-ipfsd`, ephemeral | nothing | the same | the same |
| `freedom-radicled` | its Radicle home, and the empty `HOME` directory it owns (0008) | the same | `direct`: outbound TCP. `socks5`: TCP to Arti's port only |

**Both services also use:**
- stdin, stdout and stderr, which are inherited descriptors;
- the lock file, opened before confinement, whose descriptor stays usable;
- threads, memory, clocks and `getrandom`;
- on Linux, `/proc/self` and the cgroup files the standard library reads for the CPU count.

**No other writable place:** SQLite's temporary files stay in memory (`temp_store = MEMORY`, which 0007 already sets for memory stores) or in the data directory.

**The exception:** `rad.import_repo` reads a working copy anywhere on disk, at a path the user picks at runtime ([Import](#the-radicle-import-d5)).

## Options per OS

### Linux

**Landlock** is a Linux security module that an unprivileged process applies to itself (`landlock_restrict_self`, after `PR_SET_NO_NEW_PRIVS`). It can't be lifted, and children inherit it. Its ABI grows with the kernel:

| ABI | Kernel | Adds |
|---|---|---|
| 1 | 5.13 | file access rights under a path: read, write, execute, create, remove, and so on |
| 2 | 5.19 | renames and links across directories (`refer`) |
| 3 | 6.2 | truncation |
| 4 | 6.7 | TCP `bind` and `connect`, by port |
| 5 | 6.10 | device `ioctl`s |
| 6 | 6.12 | scopes: abstract UNIX sockets and signals |

- **What it protects:**
  - Every file opened after the restriction is checked against the rules. Descriptors opened before it, such as stdio and the lock file, keep working.
  - Without an execute right on any path, no program can be run.
  - A confined process can't `ptrace` one outside its domain.
  - Version 4 limits TCP by port; version 6 stops connections to abstract UNIX sockets and signals to processes outside the domain.
- **Its limits:**
  - UDP isn't covered, so QUIC can't be limited.
  - TCP rules name ports, not addresses.
  - The kernel must enable the module. Ubuntu 24.04's does (checked on a 6.8 kernel); where it is missing or older, the service gets the best ABI available, or none (D2).
- **Its cost:**
  - The `landlock` crate (MIT or Apache-2.0, from the Landlock maintainers) gives a safe API that handles older ABIs. Otherwise, about a hundred lines of FFI (D6).
  - The rules name paths when they are applied, so the data directory must exist first.

**seccomp-bpf** is a syscall filter the process installs on itself, also after no-new-privileges. It can't be lifted, and children inherit it. There are two styles:
- **An allowlist** of exactly the syscalls the service makes. It is the strongest, but fragile:
  - tokio, libp2p, SQLite, libgit2, heartwood and the C library (musl in release builds, glibc in dev builds) each choose their syscalls;
  - a dependency update or a new kernel path (`clone3`, `rseq`, `statx`) then kills the process in the field, or fails a call somewhere unexpected;
  - it needs a list per architecture.
- **A denylist** of syscalls a service never makes, answered with an error rather than a kill:
  - process creation and exec: `execve`, `execveat`, and `fork`, `vfork` and `clone` without `CLONE_THREAD`. `clone3`'s flags can't be inspected, so it answers `ENOSYS`, and the C library falls back to `clone`;
  - other processes: `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`;
  - kernel surface the service never uses: `bpf`, `perf_event_open`, `userfaultfd`, the `io_uring` calls, `keyctl`, `add_key`, `request_key`, module loading, `kexec`, `mount`, `umount2`, `pivot_root`, `unshare`, `setns`, `personality`, `swapon`, `reboot`.
- **Its cost:** `seccompiler` (Apache-2.0 or BSD-3-Clause, a pure-Rust BPF compiler from the rust-vmm project), or a hand-written filter (D6). The syscall numbers differ per architecture: x86-64 and AArch64 here.

**Namespaces** (an unprivileged user namespace, then mount, PID, IPC and network namespaces, as `bubblewrap` builds them) would give a private view of the filesystem and of processes. They aren't recommended:
- **Availability varies:**
  - Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor by default (`kernel.apparmor_restrict_unprivileged_userns=1`), unless the binary has an AppArmor profile that allows them, and installing one needs root;
  - other distributions disable them;
  - so do some container and Flatpak setups.
- **No network without help:** a network namespace can't reach the network without a privileged helper or a user-space network stack.
- **Landlock already gives** the filesystem view without them.

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
  - Mach service lookups;
  - network access. A rule can allow only loopback with a port (`(remote ip "localhost:9150")`), which fits `socks5` mode.
- **Its cost:**
  - FFI, so `unsafe`, in one reviewed place (D6);
  - an undocumented profile language, for which Apple's own profiles are the reference;
  - Apple may change it.
  - Name resolution goes through mDNSResponder, a Mach service and a UNIX socket, so the profile must allow both. System libraries and frameworks need read access.

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

- **A job object, applied by the service itself** (`CreateJobObject`, then `AssignProcessToJobObject` on itself; jobs nest since Windows 8):
  - an active-process limit of 1 refuses every child process;
  - a memory limit would answer 0007's and 0008's open question on an OS memory limit;
  - UI restrictions.

  Cheap, but it doesn't restrict files.
- **Process mitigation policies** (`SetProcessMitigationPolicy`, also self-applied):
  - no child processes (`ProcessChildProcessPolicy`);
  - no dynamic code (`ProcessDynamicCodePolicy`);
  - no images from remote or low-label locations (`ProcessImageLoadPolicy`);
  - no legacy extension points (`ProcessExtensionPointDisablePolicy`);
  - optionally, only Microsoft-signed images from then on (`ProcessSignaturePolicy`). The service loads only system DLLs after it starts, which needs testing.

  Cheap, but they don't restrict files either.
- **AppContainer,** or its less-privileged variant, is the only Windows mechanism that confines file reads without admin rights. Its costs:
  - **A launcher:** main must spawn the service with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`. Node's `child_process` (libuv) can't, so a small native launcher is needed: a `freedom-cored` subcommand, or an add-on;
  - **ACL changes:** the data directory needs an ACL entry for the container's SID, a lasting change to the user's files;
  - **No loopback:** an AppContainer can't connect to loopback by default. Arti's SOCKS port needs a loopback exemption, which needs admin rights (`CheckNetIsolation`). Without one, `socks5` mode breaks;
  - name resolution and outbound connections need the `internetClient` capability.
- **A restricted token at low integrity:** low integrity stops writes to the user's files ("no write up") but not reads. It doesn't keep the node secrets in, so it isn't enough on its own.

### In all

| Mechanism | File reads | File writes | Child processes | Kernel surface | Network | Admin rights | Code | Main changes |
|---|---|---|---|---|---|---|---|---|
| Linux: Landlock | confined | confined | no exec of any file | — | TCP ports (ABI 4) | no | small | none |
| Linux: seccomp denylist | — | — | refused | reduced | — | no | small | none |
| macOS: Seatbelt | confined | confined | refused | reduced | loopback-only possible | no | FFI, or `sandbox-exec` | D3 |
| Windows: job and mitigations | — | — | refused | — | — | no | small FFI | none |
| Windows: AppContainer | confined | confined | with the job | — | loopback needs an exemption | for loopback | launcher and ACLs | yes |

## The recommendation

**The first step, with the services (0007 and 0008, step 4):**
1. **A `confine` step in `fc-service`.** Each service runs it once, before it reads any untrusted input or starts an instance, and after all of these:
   - its lock is taken;
   - stdio and logging are set up;
   - its data directory is opened.
2. **Linux:**
   - No-new-privileges.
   - Landlock at the best ABI available:
     - read and write on the data directory; none at all for the ephemeral IPFS process;
     - read only on the resolver and TLS files, `/proc/self` and the cgroup files;
     - no execute right anywhere.
     - From ABI 4: TCP `connect` to any port in `direct` mode, and only Arti's port in `socks5` mode; no TCP `bind`.
     - From ABI 6: both scopes.
   - The seccomp denylist above, answering `EPERM` (`ENOSYS` for `clone3`).
3. **macOS:** a Seatbelt profile with the same paths and rules, by D3's mechanism. Recommended: self-applied, so all three OSes work the same way.
4. **Windows:** the job object and the mitigation policies, self-applied. AppContainer waits for D4.
5. **Reporting:** `ipfs.hello` and `rad.hello` gain `confinement: { mechanism, files, exec }`:
   - `mechanism` is, for example, `landlock-6+seccomp`, `seatbelt`, `job` or `none`;
   - `files` and `exec` say whether file access and child processes are confined.

   Main logs it, and shows it in the nodes panel's diagnostics.
6. **Failure, with D2's answer:**
   - **Recommended:** when the OS lacks a mechanism, the service runs without it and reports so.
   - **A mechanism that exists but refuses the rules is a bug:** the service exits 77 (`confinement`), which main doesn't restart.
7. **Main's check:** before it spawns a service, main refuses a data directory that is, contains, or lies inside the identity directory, a node's data directory or the lock directory, compared as canonical paths. An override such as `FREEDOM_IPFS_DATA` can't then widen the grant over the secrets.

**Later, each its own decision:**
- a seccomp allowlist, once the release builds' syscalls are measured;
- AppContainer on Windows, with a launcher;
- confining `freedom-cored` to its own directories (D7).

## The Radicle home and key custody

- **Confinement can't protect a service's own secrets.** `freedom-radicled` holds the Radicle key in memory while the node runs (0008, *Keys*), in every custody mode. What confinement adds:
  - it keeps the vault and the Bee keys from `freedom-radicled`;
  - it keeps the Radicle key from `freedom-ipfsd`.
- **The custody modes:**
  - **The key file** (0008's option 1): the key also sits in `freedom-radicled`'s home, inside its own grant.
  - **The sealed host key** (option 2): no key file is at rest, but the service still holds the key.
- **So this design neither changes nor depends on the custody decision.** That decision is 0008's open questions 2 and 3, with the AGENTS.md rules it involves (#98), and it stays the user's. Confinement narrows what a `freedom-radicled` compromise adds beyond the Radicle identity.
- **Unconfined processes:** the Bee keystore password beside the keystore (0001, K-3) stays readable by every unconfined same-user process. Confinement only removes the two services from that set.

## The Radicle import (D5)

`rad.import_repo` reads a working copy at a path the user picks at runtime (0008, *Writes*). Landlock and Seatbelt rules are fixed once applied, and can only be narrowed. The options:

1. **A one-shot import process** (recommended):
   - Main stops the service and runs `freedom-radicled import --home … --source <path>`.
   - That process takes the home gate, confines itself to the home (read and write) and the source (read only), imports, and exits. Then main starts the service again.
   - **Cost:** the node is down for the import. Imports are rare, user-started, and bounded at 300 s.
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
  - the service still passes its contract suite confined.
- **Processes:**
  - a test hook's attempt to run `/bin/sh` (`cmd.exe` on Windows) fails;
  - on Linux, `ptrace` and `process_vm_readv` of another process fail.
- **Network,** in `socks5` mode: a TCP connection to any port but Arti's is refused by the kernel, on Linux from ABI 4 and on macOS.
- **Reporting:**
  - `hello` reports the mechanism;
  - where CI's kernel offers Landlock, the test requires the ABI it offers, so a silent downgrade fails CI.
- **D2:** a test hook that makes the mechanism unavailable gives `none` and a working service (best effort), or exit 77 (fail closed).
- **Main:** a data directory that contains the identity directory is refused before spawn.
- **D5:** the chosen import route, with a working copy outside the home, and with a symlink out of the source.

## Decisions for the user

- **D1. Adopt confinement** for the service processes, as above, or keep 0007's and 0008's non-goal for now.
- **D2. When the OS lacks a mechanism:**
  - run without it and report it (recommended);
  - or refuse to start.
- **D3. macOS:**
  - a self-applied Seatbelt profile through FFI (recommended);
  - `sandbox-exec` run by main;
  - or nothing until App Sandbox can work.
- **D4. Windows:**
  - the job object and mitigation policies now, and AppContainer later (recommended);
  - or AppContainer now, with a launcher, ACLs on the data directories and a loopback exemption for Arti.
- **D5. The Radicle import:** a one-shot import process (recommended), a read-only home grant, staging by main, or handle passing.
- **D6. Code:**
  - the `landlock` crate (MIT or Apache-2.0) and `seccompiler` (Apache-2.0 or BSD-3-Clause), which keep their `unsafe` inside them;
  - or hand-written FFI. The macOS and Windows calls need FFI either way. `fc-service` makes its few Windows calls today under a reviewed `#[allow(unsafe_code)]` (#103), and #116 proposes `fc-sys` as the one home for such calls. Either way, AGENTS.md rule 6 governs where the `unsafe` may live.
- **D7. `freedom-cored`:** confine it too, in a later design, or not.

Not decided here, and still the user's: Radicle key custody and the AGENTS.md rules around it (0008's open questions 2 and 3, #98).
