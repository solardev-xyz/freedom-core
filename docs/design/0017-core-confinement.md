# 0017: OS confinement for `freedom-cored serve`

**Status:** proposed. It is [0010](0010-service-confinement.md)'s D7 ("`freedom-cored` is confined too, in a later design", decided by the user 2026-10-23), on what [0013](0013-profiles.md) left for it ("Effects on 0010 and D7"). PRF-9's move is released (`cored-v0.26.0`), so this design starts at 0013's D7b, the `freedom/` grant, and keeps D7a's wider grant only for a profile whose move hasn't happened yet. Every choice below is a technical one, made by the coordinator, which the user may veto; none is a product question.

**Amended** after review round 1: the claims and tests are scoped per OS by what each mechanism reports (Windows enforces only part of `exec` before 0010's restricted token); C5 hands over only a receipts file today's import would read, with a cross-directory durable rename; C6 follows recovery's own rules for each record kind; C8 gives up Seatbelt carve-outs; the inventory lists `fc_service`'s system grants and the stores' generic temp and set-aside names.

**The references:**
- **freedom-core** at `c54cafdb` (`main`, `cored-v0.26.0`):
  - `crates/freedom-cored/src/main.rs` and `serve.rs` (the entry and the event loop), `gate.rs`, `hardening.rs`, `journal.rs`, `vault.rs`, `nodes.rs`, `payments_store.rs`, `sqlite.rs`, `intents.rs`, `log.rs`;
  - `crates/freedom-cored/src/profile/confine.rs`, how the profile subcommands confine themselves;
  - `crates/fc-service/src/confine/` (`mod.rs`, `linux.rs`, `resolver.rs`, `seccomp.rs`, `seatbelt.rs`, `macos.rs`, `windows.rs`, `job.rs`) and `gate.rs`;
  - `crates/fc-store/src/fsx.rs`, `file.rs`, `anchor.rs`, `journal.rs`.
- **freedom-browser** at `ca489ffe` (PRF-9 B3, #1304): `src/main/core/core-process.js` (the spawn), `core-client.js` (the hello), `identity-manager.js` and `radicle/radicled-node.js` (`nodes.write_identity`'s directories), `profile-paths.js`.
- An inventory of every file, thread, descriptor and call `serve` makes, taken at `c54cafdb` for this design ([What `serve` touches](#what-serve-touches)).

## Summary

- **Today** `serve` runs as the user with 0001's hardening only: no core dumps, not dumpable, and the parent's death signal. Every subcommand around it already confines itself (0013: `profile *`, `hold-profile`), and so do both services (0010). `serve` holds the most: the vault, the profile's secrets, the wallet's stores and the node keys it writes. It parses only main's frames, so it is the least exposed process, but a bug in its JSON, CBOR or RLP handling, its SQLite or a dependency reached through a page's request would today give whoever exploits it everything the user can reach.
- **The grant (C1, C2):** read-write on the profile's Freedom root (`<profile>/freedom/`), the identity directory, the Ant or Bee data directory and the Radicle home, each from `serve`'s arguments, plus the system reads `fc_service` always grants; no network, no process, no local IPC but main's pipe. The lock directory is held through descriptors opened before confinement, not granted (C3).
- **The order (C1):** main passes every directory `serve` needs on its command line. `serve` drops inherited descriptors (one re-exec on Linux and macOS, as the subcommands do), takes its gate, opens what it holds, does its setup, and confines itself while it is the process's only thread, before the logging thread and before it reads a byte from the pipe. The hello then has to name the same directories, or it is refused.
- **What changes in `serve` to fit:**
  - **Modes (C4):** mode changes stay refused except a narrowing to owner-only (`fchmod` with no group, other or special bits), which is all `serve`'s tightening does.
  - **The legacy receipts (C5):** `x402-receipts.json` is imported from the profile's root today. Before confining itself, `serve` hands a file that today's import would read over to the Freedom root, with a durable rename, and imports from there. Electron's own data leaves the grant.
  - **A pending node journal (C6):** before confinement, `serve` plans what recovery will need by record kind, granting the roots a committed journal or a live intent names, and creating only what recovery would have created.
  - **SQLite's temp files (C7):** in memory, so nothing is written outside the grant.
- **Per OS,** with what 0010 already ships: Landlock and the seccomp denylist on Linux, and a Seatbelt profile on macOS, enforce the grant. Windows gets the job object and the mitigation policies: `exec` is `partial` and files, IPC and network are `unavailable` until 0010's restricted token (D4). A mechanism the OS lacks is reported and `serve` runs (0010 D2); the report goes back in `core.hello`'s answer, and main logs it.
- **Before the move (C8):** a profile in the old layout gets D7a's grant, its whole `userData`. For a named profile that still keeps other profiles and the catalog out; for the packaged default profile, whose `userData` is the app root, it doesn't. The move retries at every start, so that state is short.

## Goals and non-goals

**Goals, on Linux and macOS:**
- A compromised `serve` can't read or write another profile, the catalog, Electron's own data (cookies, cache, local storage) or anything else of the user's outside its grant, nor run a program, open a socket, or reach the session bus or the Keychain.

**Goals everywhere:**
- Nothing `serve` does today stops working, on any OS, confined or not.
- On Windows, what 0010 step 1 gives the services: a job that refuses `serve`'s own child processes, and the mitigation policies, each reported as read back.
- The same mechanisms and code as 0010: `fc_service::confine`, with one new policy field (`modes`) and a gate over an open file, and no new dependency.

**Non-goals:**
- **The key-store helper** (`freedom-cored keystore`). It has to reach the OS key store, which is its whole job: the session bus on Linux, the Security server on macOS, DPAPI on Windows. It is a one-shot run by main that reads no file and parses only main's arguments, so it stays as 0013 left it.
- **Windows files, IPC, network and the parent-process escape** before 0010's restricted token qualifies (D4; its spike is parked). The token's relaunch is what closes them, and it isn't part of this design.
- **A compromised main.** Main spawns `serve` and chooses its grant; nothing here protects against main.
- **A same-user process,** which can read the profile's files directly, as in 0001, 0010 and 0013.

## What `serve` touches

Taken at `c54cafdb`. All renames today stay inside one directory, no link of either kind is made, and no file's times are set.

| Where | What `serve` does there | Known from |
|---|---|---|
| **Identity directory** (`--data-dir`, canonicalized by the gate) | the vault, `secrets.json`, `vault-meta.json`; the node-identity, delete and vault-meta journals; `*.freedom-new` staging, `*.corrupt` and `.unreadable` set-asides, `.<name>.<pid>.<n>.tmp` temps; directory `fsync` | argv |
| **Lock directory** (`--lock-dir`) | creates it (0700), `statfs`, `fchmod`; its gate `<sha256(identity)>.lock` held with `flock` for the whole run; `radicle-<sha256(home)>.lock` for the length of `nodes.write_identity` or Radicle recovery | argv |
| **Freedom root** (hello `grant_root`) | the four permission files (read at every check, written once moved), `phone-payments.json`, `safe-pending.json`, `rpc-api-keys.json`, each with fc-store's `.<name>.<pid>.<n>.tmp` temps and `<name>.unreadable` set-aside; `wallet-intents.jsonl` (append, `ftruncate`, compaction temps, `.corrupt-<ms>`); `payment-history.sqlite` with `-wal` and `-shm` (`fcntl` locks, a shared map of `-shm`), and a short-lived `-journal` when a new database switches to WAL | hello |
| **Profile directory** (hello `user_data_dir`) | `x402-receipts.json`: read, then renamed `.migrated` or removed, at the first `payments.*` request | hello |
| **Ant/Bee data directory** | `keys/swarm.key`, `config.yaml`; created with its ancestors if missing; staged, renamed, `fsync` | `nodes.write_identity` |
| **Radicle home** | `keys/radicle`, `keys/radicle.pub`, `config.json`, `node/dirty`; a wipe removes `node/`, `cobs/`, `storage/` | `nodes.write_identity` |
| **Any node root** an earlier run's node-identity journal or intent names | recovery, before the hello, on the snapshot thread | the records on disk |
| **System** | `/proc/self/mountinfo` (only when a checked directory is on FUSE); `/dev/urandom` (SQLite's salts; `getrandom`'s fallback); SQLite's temp directories, only if a statement spills | — |

- **Threads:** the log writer starts first, in `main`, then `stdout`, `vault`, `naming`, `chain`, `stdin`, `snapshot` and `parent`; then, in the hello, `dweb-hash` (two), `dweb` and `adopt`; after its answer, `secrets`. No pool of any kind.
- **Network:** none. No socket, name lookup or HTTP client is on `serve`'s path, and no network crate is in the lockfile: every request leaves through main's `shell.*` executors, key-store calls included (`shell.keystore`).
- **Processes:** none spawned, no signal sent. The parent watch polls `getppid()`; the death signal is `PR_SET_PDEATHSIG`.
- **Calls a filter could break:** `fchmod` (the gate, `fsx::tighten` at the vault's start, in `adopt` and at the intent journal's open; SQLite on a new `-wal`/`-shm` under an unusual umask), `flock`, `fcntl` locks, a shared `mmap`, `statfs`, `fsync`, `ftruncate`, `prctl`. None of `openat2`, `memfd`, `mlock`, `ioctl` or `utimensat`.
- **Descriptors kept:** the gate's lock, the duplicated stdin and stdout, and SQLite's three files once payments open. `serve` never runs `clean_entry`, so whatever main's spawn leaks stays open today.

## What a compromised `serve` reaches today, and after

- **Today:** everything the user can: every profile, the catalog, the browser's cookies and saved data, the user's documents and keys, any program, the network, the session bus and the Keychain's items that don't name a code signature.
- **After, on Linux and macOS:** its own profile's Freedom data and node keys, which it holds anyway, and the system reads every confined process gets ([C2](#c2-the-grant)). Through main it can still ask for what main's executors give any core: page-originated chain reads, naming lookups and key-store calls on its own profile's items (0013, "Not covered").
- **After, on Windows:** no child process of its own, and no dynamic code, unsigned image or extension point. Files, IPC and the network stay as today, and a process created with another of the user's processes as its parent escapes the job (0010's `parent_process` gap), until the restricted token.

## The recommendation

### C1. The grant comes from `serve`'s arguments

`confine` (0010) refuses to run with a second thread, and Landlock can't widen a grant later. `serve` starts its logging thread before anything else and learns `grant_root` and `user_data_dir` only from the hello.

**Options:**
- **(a) Main passes every directory on the command line,** and the hello must match. Main already knows them all when it spawns `serve`: `core-process.js` builds the hello's `grant_root` and `user_data_dir` beside the arguments, and the node directories come from the same getters (`profile-paths.js`).
- **(b) `serve` reads the hello on its only thread** before anything else, then confines itself, then starts its threads. The reader, its credits and the hello deadline would move out of their thread for that one frame, and confinement would follow reading main's input instead of preceding it.
- **(c) A grant wide enough for any hello,** such as the whole profile. That is D7a's grant, which keeps Electron's data in.

**Recommended: (a).** It is the services' order (0010, "The recommendation", step 1): confinement before the first byte of input. The new arguments:

```text
freedom-cored serve --data-dir <identity dir> --lock-dir <lock dir> [--parent-pid <pid>]
                    --grant-root <dir> [--user-data-dir <dir>]
                    [--node-root bee=<dir>] [--node-root radicle=<dir>]
```

- Each must be absolute and normalized, as the hello's are today.
- **The hello** must name the same `grant_root` and `user_data_dir` (after the same normalization). A mismatch is `invalid_argument` and exit 76, as a missing `grant_root` is today.
- **`nodes.write_identity`** must name the `--node-root` of its node kind, exactly: anything else is `invalid_argument`, before any write. Main sends one Bee data directory and one Radicle home per profile, so this narrows nothing main does.
- **Compatibility:** main and the core are pinned together. A core given none of the new arguments refuses to start (usage, exit 64), so a main that forgot them fails loudly in CI instead of running unconfined.

### C2. The grant

The policy `serve` passes to `fc_service::confine`:

| Policy field | Value |
|---|---|
| `read_write` | the identity directory (canonical), `--grant-root`, each `--node-root`, and the roots C6 plans. After PRF-9 the identity directory is `freedom/identity` unless overridden, so it is usually inside the Freedom root already. |
| `read_only` | none |
| `read_only_dirs` | none |
| `refer` | false: every rename but C5's stays in its directory, and C5's runs before `confine` |
| `symlinks`, `times` | false |
| `network` | `Offline` |
| `resolver` | `None` |
| `interface_index` | false |
| `descriptors` | the gate's lock, each Radicle gate file (C3), and anything else opened before `confine` |
| `modes` (new, C4) | true |

**What `confine` adds on its own,** for every confined process, and so the effective read grant:
- **Linux** (`resolver.rs`, with `Resolver::None`): `/proc/self` (its `mountinfo` included), `/sys/fs/cgroup`, `/dev/random` and `/dev/urandom`, read-only.
- **macOS** (`seatbelt.rs`): the system's libraries and frameworks, the random devices and `/dev/null`.
- **Windows:** nothing; no file rule applies yet.

**Directories that don't exist yet:** Landlock and Seatbelt grant existing paths. Before confining, `serve` creates each `--node-root` that is missing, with its ancestors, mode 0700, as `nodes.write_identity` would have; the Radicle home as fc-service's gate creates it today. The Freedom root and the identity directory exist by the time main spawns `serve`.

### C3. The lock directory, through descriptors

The lock directory holds every profile's gates and every Radicle home's. Granting it would let a compromised `serve` remove another profile's lock file, after which a second core could take that profile.

**Recommended:** `serve` opens what it needs there before confining itself, and the directory isn't granted:
- **its gate**, taken and held as today;
- **the Radicle gate file** for its `--node-root radicle=` home, and for each Radicle root C6 plans, opened but not locked. `nodes.write_identity` and Radicle recovery then `flock` that descriptor for their length instead of opening the path. fc-service's `gate` gets a variant over an open file that keeps today's canonical path, the lock directory's identity check, the retry and the contention rules.

No other path in the lock directory is used after the hello. The alternative, granting the lock directory, is simpler and leaves that residual; the qualification tests below include a confined `serve` failing to remove another profile's lock.

### C4. Mode changes: a narrowing only

`serve` tightens modes with `fchmod` (the gate, the vault's files at start, the node layout in `adopt`, the intent journal at its open), and 0010's seccomp denylist refuses `fchmod` because Landlock doesn't check modes. Moving every tightening before `confine` doesn't work: `adopt` and the intent journal run after the hello.

**Recommended:** a `modes` policy field.
- **Linux:** the denylist keeps refusing `fchmod(fd, mode)` when any bit of `mode & 0o7077` is set (seccompiler's `MaskedEq` rules, one for each forbidden bit, since the filter matches what to refuse), so only owner-only modes without setuid, setgid or sticky can be set, on a descriptor Landlock let the process open. The 0600 and 0700 that `serve` sets pass. `fchmodat`, `fchmodat2` and every owner, xattr and times call stay refused.
- **macOS:** Seatbelt can't compare a mode, so the profile allows `file-write-mode` in the read-write grants alone. A compromised `serve` could widen a mode there; the identity and node directories are 0700, so another user still can't reach their files.
- **Windows:** no change.
- The report's `files` stays `enforced` on Linux and is `partial` on macOS, naming `modes`.

### C5. The legacy receipts move into the Freedom root

`payments_store::Store::import` reads `x402-receipts.json` from `user_data_dir`, at the database's first open, and renames it `.migrated` there. Under the `freedom/` grant the profile's root is out of reach, and its `metadata` would fail as if the file were absent: the import would be skipped without a word.

**Options:**
- **(a) `serve` hands the file over to the Freedom root before confining itself,** only when today's import would read it, and imports from there.
- **(b) Main hands it over:** a `shell.*` request for its bytes, and another to rename it after the commit. Two new methods for a one-time import.
- **(c) Grant the profile's root.** That brings Electron's data back into the grant.

**Recommended: (a),** as a step that runs at every start of a moved profile (its `--user-data-dir` differs from `--grant-root`), on the only thread, before `confine`. It applies `Store::import`'s own rules at the root, in its order:
1. **No file:** `x402-receipts.json` absent at the root, as `metadata` finds it today (a link followed, any error as absent): nothing.
2. **A stray:** a `.migrated` at the root too: the root's `x402-receipts.json` is removed there, through the same `fsx::remove` as today's stray branch, and nothing moves. A `.migrated` alone never moves: its only meaning is "drop a stray", and there is no stray.
3. **Not readable as today's import reads it:** the file is opened as `read_file` opens it (no link followed, a regular file, the current user's, at most `MAX_LEGACY_BYTES`). Anything refused (a directory, a link, a special file, another user's file, an oversized one) stays at the root, logged as today's `Kept` (`unreadable`).
4. **A conflict:** a `x402-receipts.json` or `.migrated` already in the Freedom root: the root's file stays, logged. Downgrades are out of scope (the user, 2026-11-21), so this arises only by hand.
5. **The handover:** the root's file is renamed to `x402-receipts.json` in the Freedom root, the profile and its `freedom/` being one filesystem (the move defers on a mounted `freedom/`; an `EXDEV` leaves the file, logged). The moved entry is then checked against the handle opened in step 3 (device and inode on Unix, volume and file id on Windows); another entry is renamed back and left, logged. Then the rename is made durable across both directories: the Freedom root is synced, then the profile's root (`fsync` on each directory on Unix; on Windows the rename is `MoveFileExW` with `MOVEFILE_WRITE_THROUGH`). A new `fsx::sync_rename_across(from_dir, to_dir)` does this.

**Crash safety:** a rename is atomic in the filesystem's namespace, so after a crash at any point the file is in exactly one of the two places. Left at the root, the next start hands it over again. In the Freedom root, the import finds it there. Once imported, the import's own `.migrated` rename happens in the Freedom root, as it does at the root today. A file that arrived in the Freedom root but whose root entry survives too can't happen: one rename moves one entry.

The import then runs unchanged with the Freedom root as its root. A profile in the old layout has the same directory for both, and nothing moves.

### C6. A pending node journal's roots

Startup recovery, before the hello, finishes or discards what an earlier run left in the identity directory: a committed journal (`node-identity-journal.json`) is replayed, an intent with no journal (`node-identity-staging.json`) is discarded. If main's node directory changed since (an override moved), the record's root isn't among the arguments. And every `read_write` path must exist (`confine`'s rule), while recovery deliberately neither creates nor looks under a missing intent root.

**Recommended:** before confining itself, `serve` reads both records (as recovery parses them, with the same bounds and validity checks) and plans by record kind, mirroring recovery:
- **No record, an invalid one, or a journal the done list already records:** nothing is granted. Recovery sets the invalid one aside, or removes the finished journal, with the identity directory alone, as today.
- **A committed journal not yet done:** replay will write the root, creating it if it is gone. So the plan does now what replay would do first: for Bee, a missing root is created with its ancestors, 0700, as replay creates it; for Radicle, the home is created by the gate's own path, as `radicle_gate(…, true)` does, and its gate file is opened (C3). The root is granted. A held Radicle gate still makes recovery wait (`Waiting`), as today.
- **An intent, no journal:** a root that exists and is a directory is granted, with its Radicle gate file (C3); recovery gates it and removes the staged names, as today. A missing root is neither created nor granted: recovery removes the intent without the gate and without looking under the root, as today, with the identity directory alone. A root that isn't a directory isn't granted; recovery fails on it as it does today (`pending_recovery`).
- **A race:** a root that appears or changes between the plan and recovery is outside the grant, so recovery's access fails and the record stays, reported as `pending_recovery`, as today's identity checks report a changed root. Nothing is created outside the plan.

The granted roots are the user's own node directories from an earlier run, so the grant stays within what the profile used.

### C7. SQLite keeps its temp files in memory

SQLite writes a temp file for a statement that spills, in `$SQLITE_TMPDIR`, `$TMPDIR`, `/var/tmp`, `/usr/tmp`, `/tmp` or the working directory. **Recommended:** `PRAGMA temp_store = MEMORY` at every open (`sqlite.rs`). No payments statement is expected to spill; if one does, memory is the right place for a temp table of the payment history.

### C8. Before the move: D7a's grant

A profile whose move deferred (0013's `deferred` outcomes) keeps its Freedom data at the root of its `userData`, and main passes that as `--grant-root`. The grant is then the whole profile directory, Electron's data included:
- **A named profile** is still separated from the others and from the catalog.
- **The packaged default profile's** `userData` is the app root, which holds `Profiles/`, `R/` and the catalog. On every OS its `serve` then reaches every profile until the move happens.

0013 noted that Seatbelt could deny `Profiles/`, the other `R/` homes, the catalog and its forget file inside that grant, if the qualification showed it worked. This design doesn't take that option: `Policy` has no exclusion field, Seatbelt would have to keep this profile's own `R/<slot>` home allowed inside a denied `R/` and deny slots created after confinement, and all of it would serve a state that ends at the next successful start. Main logs the layout at every start, and the move retries at every start. Refusing to start instead would leave the user without a wallet over a reason the move already logs.

### The order in `serve`

1. **Entry:** the panic hook, then `fc_service::confine::clean_entry`: on Linux and macOS one re-exec with every descriptor above stderr close-on-exec, as the subcommands do; on Windows nothing, where an inherited handle is one main made inheritable and the report claims nothing it could undo. Logging writes its lines directly until step 7, as the subcommands' does.
2. **Arguments,** checked as in C1.
3. **Hardening** (0001), then the parent's death signal and its check.
4. **The gate,** taken and held; the Radicle gate files opened (C3).
5. **Setup on the only thread:** each missing node root created (C2); the records planned (C6); the receipts handed over (C5); the vault's and the journal's files tightened, as the vault's start does today.
6. **`confine`,** with C2's policy. An `Invalid` is exit 77 (`confinement`), as for the services: main reports the core unavailable and restarts it under its usual rules. A mechanism the OS lacks is reported, not fatal (0010 D2).
7. **The logging thread,** then `serve::run` as today. The hello's answer carries the `Report` under `confinement`, and main logs it with the core's version.

### Per OS

- **Linux:** Landlock at the kernel's ABI with every right it knows handled, and the seccomp denylist with C4's rules, exactly as `fc_service::confine` applies them. Every property `enforced` where the kernel has the ABI.
- **macOS:** the Seatbelt profile `seatbelt.rs` generates, with C4's `file-write-mode` and no `mach-lookup` beyond 0010's offline profile. `serve` never calls Security.framework (key-store calls go to main), but the framework is linked for the helper; the tests check that a confined `serve` starts and that nothing in its life asks for a Mach service.
- **Windows:** the job object, nested in main's, with one active process, and the mitigation policies (dynamic code, image load, extension points), read back. `exec` is `partial` (`parent_process`); `files`, `ipc` and `network` are `unavailable`.

## Tests

In freedom-core's CI, against a `serve` started with C1's arguments.

**On every OS:**
- **The report:** the hello's `confinement` says `enforced` for every property (Linux, at a kernel with the ABI), `partial` for `files` naming `modes` and `enforced` otherwise (macOS), or `exec` `partial` naming `parent_process`, `files`, `ipc` and `network` `unavailable`, and each mitigation `set` (Windows).
- **Everything `serve` does still works, confined:** the existing integration suites (vault, secrets, stores, intents, payments, approvals, dweb, naming, chain) run against the confined binary; `nodes.write_identity` for Bee and Radicle, and a wipe; the key-store calls through main's helper (0013's D7 tests: create, open, replace and forget on every OS that offers them).
- **Refusals:** a hello whose `grant_root` or `user_data_dir` differs from the arguments; a `nodes.write_identity` for another directory; a `serve` missing the new arguments.
- **The receipts (C5):** a moved profile with `x402-receipts.json` at its root imports it once, from the Freedom root, and the root keeps no copy; with a `.migrated` at the root too, the stray is dropped at the root and nothing moves; a directory, a link, a FIFO, another user's file (Unix) and an oversized file named `x402-receipts.json` each stay at the root, unread; a name in the Freedom root already blocks the handover; the entry swapped between the check and the rename (a test hook) is renamed back; a crash (a test hook) before and after the rename, and before and after each directory sync, leaves the file in one place, and the next start imports it once; a profile in the old layout behaves as today.
- **The records (C6),** for Bee and Radicle each: a committed journal with its root present, missing (created, then replayed), changed since the arguments, and held (Radicle: `Waiting`); an intent with its root present, missing (the core starts, the intent goes, and the root isn't created), and not a directory; an invalid record; a journal already done.
- **SQLite (C7):** a new database's first open and its switch to WAL, confined.

**On Linux and macOS:**
- **Outside the grant,** from a test method (`testhooks`): reading another profile's directory, the catalog `profile-registry.json`, the forget file, a file at the profile's root (Electron's), and the lock directory all fail; removing another profile's lock file fails (C3); a TCP connect, a Unix-socket connect to the session bus and an exec all fail.
- **The gate's and the vault's tightening** at start, confined (C4).

**On Linux:** `fchmod` to 0600 and 0700 succeeds; to 0644, 0755, 04700, 02700 and 01700 it fails with `EPERM` (C4).

**On Windows:** a child process `serve` creates as its own is refused by the job.

**Before the move (C8),** on Linux and macOS: a named profile in the old layout can't read another profile.

In freedom-browser's CI: every core integration suite and e2e job runs against the confined core it pins, with main passing C1's arguments; a moved profile with legacy receipts shows them in the payment history.

## Steps

1. **D7-1 (fc-service, fc-store):** the `modes` field (seccomp's per-bit `MaskedEq` rules, Seatbelt's `file-write-mode`), the gate over an open file (C3), and `fsx::sync_rename_across` (C5). Tests on each OS.
2. **D7-2 (freedom-cored):** C1's arguments and checks, the hello and `nodes.write_identity` matches, C5's handover, C6's plan, C7's pragma, the order above with `clean_entry`, and the report in the hello's answer. `serve` confines itself; `hold-lock` takes the same order with only the identity directory and its gate, and `recover` with the identity directory, its gate and C6's plan. Tests above.
3. **Release,** then **B-D7 (freedom-browser):** pass C1's arguments from `core-process.js`, log the report, pin the release; the browser tests above.

## Decisions

All the coordinator's, open to the user's veto:
- **C1:** the grant from `serve`'s arguments, the hello and `nodes.write_identity` checked against them.
- **C2:** read-write on the identity directory, the Freedom root and the node roots, with `confine`'s own system reads; offline.
- **C3:** the lock directory through descriptors opened before `confine`, not granted.
- **C4:** mode changes allowed only to owner-only modes (Linux), in the read-write grants (macOS).
- **C5:** a legacy receipts file today's import would read handed over to the Freedom root before `confine`, with a durable cross-directory rename.
- **C6:** a pending record's roots planned by its kind, as recovery treats it.
- **C7:** SQLite's temp store in memory.
- **C8:** D7a's grant for a profile in the old layout, with no Seatbelt carve-outs.
