# 0017: OS confinement for `freedom-cored serve`

**Status:** proposed. It is [0010](0010-service-confinement.md)'s D7 ("`freedom-cored` is confined too, in a later design", decided by the user 2026-10-23), on what [0013](0013-profiles.md) left for it ("Effects on 0010 and D7"). PRF-9's move is released (`cored-v0.26.0`), so this design starts at 0013's D7b, the `freedom/` grant, and keeps D7a's wider grant only for a profile whose move hasn't happened yet. Every choice below is a technical one, made by the coordinator, which the user may veto; none is a product question.

**The references:**
- **freedom-core** at `c54cafdb` (`main`, `cored-v0.26.0`):
  - `crates/freedom-cored/src/main.rs` and `serve.rs` (the entry and the event loop), `gate.rs`, `hardening.rs`, `journal.rs`, `vault.rs`, `nodes.rs`, `payments_store.rs`, `sqlite.rs`, `intents.rs`, `log.rs`;
  - `crates/freedom-cored/src/profile/confine.rs`, how the profile subcommands confine themselves;
  - `crates/fc-service/src/confine/` (`mod.rs`, `linux.rs`, `seccomp.rs`, `seatbelt.rs`, `macos.rs`, `windows.rs`) and `gate.rs`;
  - `crates/fc-store/src/fsx.rs`, `anchor.rs`, `journal.rs`.
- **freedom-browser** at `ca489ffe` (PRF-9 B3, #1304): `src/main/core/core-process.js` (the spawn), `core-client.js` (the hello), `identity-manager.js` and `radicle/radicled-node.js` (`nodes.write_identity`'s directories), `profile-paths.js`.
- An inventory of every file, thread, descriptor and call `serve` makes, taken at `c54cafdb` for this design ([What `serve` touches](#what-serve-touches)).

## Summary

- **Today** `serve` runs as the user with 0001's hardening only: no core dumps, not dumpable, and the parent's death signal. Every subcommand around it already confines itself (0013: `profile *`, `hold-profile`), and so do both services (0010). `serve` holds the most: the vault, the profile's secrets, the wallet's stores and the node keys it writes. It parses only main's frames, so it is the least exposed process, but a bug in its JSON, CBOR or RLP handling, its SQLite or a dependency reached through a page's request would today give whoever exploits it everything the user can reach.
- **The grant (C1, C2):** read-write on the profile's Freedom root (`<profile>/freedom/`), the identity directory, the Ant or Bee data directory and the Radicle home, each from `serve`'s arguments; nothing else. No network, no process, no local IPC but main's pipe. The lock directory is held through descriptors opened before confinement, not granted (C3).
- **The order (C1):** main passes every directory `serve` needs on its command line. `serve` drops inherited descriptors (one re-exec, as the subcommands do), takes its gate, opens what it holds, tightens modes, and confines itself while it is the process's only thread, before the logging thread and before it reads a byte from the pipe. The hello then has to name the same directories, or it is refused.
- **What changes in `serve` to fit:**
  - **Modes (C4):** mode changes stay refused except a narrowing to owner-only (`fchmod` with no group or other bits), which is all `serve`'s tightening does.
  - **The legacy receipts (C5):** `x402-receipts.json` is imported from the profile's root today. Before confining itself, `serve` renames it, and its `.migrated` marker, into the Freedom root, and imports from there. Electron's own data leaves the grant.
  - **A pending node journal (C6):** the roots an earlier run's node-identity journal names are read before confinement and granted, so recovery still reaches them.
  - **SQLite's temp files (C7):** in memory, so nothing is written outside the grant.
- **Per OS,** with what 0010 already ships: Landlock and the seccomp denylist on Linux, a Seatbelt profile on macOS, the job object and mitigation policies on Windows, whose files wait for 0010's restricted token (D4). A mechanism the OS lacks is reported and `serve` runs (0010 D2); the report goes back in `core.hello`'s answer, and main logs it.
- **Before the move (C8):** a profile in the old layout gets D7a's grant, its whole `userData`. For a named profile that still keeps other profiles and the catalog out; for the packaged default profile, whose `userData` is the app root, it doesn't on Linux. The move retries at every start, so that state is short.

## Goals and non-goals

**Goals:**
- A compromised `serve` can't read or write another profile, the catalog, Electron's own data (cookies, cache, local storage) or anything else of the user's outside its grant, nor run a program, open a socket, or reach the session bus or the Keychain.
- Nothing `serve` does today stops working, on any OS, confined or not.
- The same mechanisms and code as 0010: `fc_service::confine`, with two new policy fields, and no new dependency.

**Non-goals:**
- **The key-store helper** (`freedom-cored keystore`). It has to reach the OS key store, which is its whole job: the session bus on Linux, the Security server on macOS, DPAPI on Windows. It is a one-shot run by main that reads no file and parses only main's arguments, so it stays as 0013 left it.
- **Windows files and IPC** before 0010's restricted token qualifies (D4; its spike is parked). Until then Windows gets what 0010 step 1 gives the services.
- **A compromised main.** Main spawns `serve` and chooses its grant; nothing here protects against main.
- **A same-user process,** which can read the profile's files directly, as in 0001, 0010 and 0013.

## What `serve` touches

Taken at `c54cafdb`. All renames stay inside one directory, no link of either kind is made, and no file's times are set.

| Where | What `serve` does there | Known from |
|---|---|---|
| **Identity directory** (`--data-dir`, canonicalized by the gate) | the vault, `secrets.json`, `vault-meta.json`; the node-identity, delete and vault-meta journals; `*.freedom-new` staging, `*.corrupt` and `.unreadable` set-asides, `.<name>.<pid>.<n>.tmp` temps; directory `fsync` | argv |
| **Lock directory** (`--lock-dir`) | creates it (0700), `statfs`, `fchmod`; its gate `<sha256(identity)>.lock` held with `flock` for the whole run; `radicle-<sha256(home)>.lock` for the length of `nodes.write_identity` or Radicle recovery | argv |
| **Freedom root** (hello `grant_root`) | the four permission files (read at every check, written once moved), `phone-payments.json`, `safe-pending.json`, `rpc-api-keys.json`, `wallet-intents.jsonl` (append, `ftruncate`, compaction temps), `payment-history.sqlite` with `-wal` and `-shm` (`fcntl` locks, a shared map of `-shm`) | hello |
| **Profile directory** (hello `user_data_dir`) | `x402-receipts.json`: read, then renamed `.migrated` or removed, at the first `payments.*` request | hello |
| **Ant/Bee data directory** | `keys/swarm.key`, `config.yaml`; created with its ancestors if missing; staged, renamed, `fsync` | `nodes.write_identity` |
| **Radicle home** | `keys/radicle`, `keys/radicle.pub`, `config.json`, `node/dirty`; a wipe removes `node/`, `cobs/`, `storage/` | `nodes.write_identity` |
| **Any node root** an earlier run's node-identity journal names | recovery, before the hello, on the snapshot thread | the journal on disk |
| **System** | `/proc/self/mountinfo` (only when a checked directory is on FUSE); `/dev/urandom` (SQLite's salts; `getrandom`'s fallback); SQLite's temp directories, only if a statement spills | — |

- **Threads:** the log writer starts first, in `main`, then `stdout`, `vault`, `naming`, `chain`, `stdin`, `snapshot` and `parent`; then, in the hello, `dweb-hash` (two), `dweb` and `adopt`; after its answer, `secrets`. No pool of any kind.
- **Network:** none. No socket, name lookup or HTTP client is on `serve`'s path, and no network crate is in the lockfile: every request leaves through main's `shell.*` executors, key-store calls included (`shell.keystore`).
- **Processes:** none spawned, no signal sent. The parent watch polls `getppid()`; the death signal is `PR_SET_PDEATHSIG`.
- **Calls a filter could break:** `fchmod` (the gate, `fsx::tighten` at the vault's start, in `adopt` and at the intent journal's open; SQLite on a new `-wal`/`-shm` under an unusual umask), `flock`, `fcntl` locks, a shared `mmap`, `statfs`, `fsync`, `ftruncate`, `prctl`. None of `openat2`, `memfd`, `mlock`, `ioctl` or `utimensat`.
- **Descriptors kept:** the gate's lock, the duplicated stdin and stdout, and SQLite's three files once payments open. `serve` never runs `clean_entry`, so whatever main's spawn leaks stays open today.

## What a compromised `serve` reaches today, and after

- **Today:** everything the user can: every profile, the catalog, the browser's cookies and saved data, the user's documents and keys, any program, the network, the session bus and the Keychain's items that don't name a code signature.
- **After, on Linux and macOS:** its own profile's Freedom data and node keys, which it holds anyway. Through main it can still ask for what main's executors give any core: page-originated chain reads, naming lookups and key-store calls on its own profile's items (0013, "Not covered").
- **After, on Windows:** no program, no child process, no dynamic code; files and IPC as today, until the restricted token.

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

| Policy field | Value |
|---|---|
| `read_write` | the identity directory (canonical), `--grant-root`, each `--node-root`, and each root a pending node journal names (C6). After PRF-9 the identity directory is `freedom/identity` unless overridden, so it is usually inside the Freedom root already. |
| `read_only` | `/dev/urandom`; `/proc/self/mountinfo` on Linux |
| `read_only_dirs` | none |
| `refer` | false: every rename stays in its directory |
| `symlinks`, `times` | false |
| `network` | `Offline` |
| `resolver` | `None` |
| `interface_index` | false |
| `descriptors` | the gate's lock, each Radicle gate file (C3), and anything else opened before `confine` |
| `modes` (new, C4) | true |

**Directories that don't exist yet:** Landlock and Seatbelt grant existing paths. Before confining, `serve` creates each `--node-root` that is missing, with its ancestors, mode 0700, as `nodes.write_identity` would have; the Radicle home as fc-service's gate creates it today. The Freedom root and the identity directory exist by the time main spawns `serve`.

### C3. The lock directory, through descriptors

The lock directory holds every profile's gates and every Radicle home's. Granting it would let a compromised `serve` remove another profile's lock file, after which a second core could take that profile.

**Recommended:** `serve` opens what it needs there before confining itself, and the directory isn't granted:
- **its gate**, taken and held as today;
- **the Radicle gate file** for its `--node-root radicle=` home (and for each journal root, C6), opened but not locked. `nodes.write_identity` and Radicle recovery then `flock` that descriptor for their length instead of opening the path. fc-service's `gate` gets a variant over an open file, with the same retry and contention rules.

The alternative, granting the lock directory, is simpler and leaves that residual; the qualification tests below include a confined `serve` failing to remove another profile's lock.

### C4. Mode changes: a narrowing only

`serve` tightens modes with `fchmod` (the gate, the vault's files at start, the node layout in `adopt`, the intent journal at its open), and 0010's seccomp denylist refuses `fchmod` because Landlock doesn't check modes. Moving every tightening before `confine` doesn't work: `adopt` and the intent journal run after the hello.

**Recommended:** a `modes` policy field.
- **Linux:** seccomp lets `fchmod(fd, mode)` through when `mode & 0o7077 == 0` (a masked compare on its second argument), so only owner-only modes can be set, on a descriptor Landlock let the process open. `fchmodat`, `fchmodat2` and every owner, xattr and times call stay refused.
- **macOS:** Seatbelt can't compare a mode, so the profile allows `file-write-mode` in the read-write grants alone. A compromised `serve` could widen a mode there; the identity and node directories are 0700, so another user still can't reach their files.
- **Windows:** no change.
- The report's `files` stays `enforced` on Linux and is `partial` on macOS, naming `modes`.

### C5. The legacy receipts move into the Freedom root

`payments_store::Store::import` reads `x402-receipts.json` from `user_data_dir`, at the database's first open, and renames it `.migrated` there. Under the `freedom/` grant the profile's root is out of reach, and its `metadata` would fail as if the file were absent: the import would be skipped without a word.

**Options:**
- **(a) `serve` renames both files into the Freedom root before confining itself:** `x402-receipts.json.migrated` first, then `x402-receipts.json`, each only if the Freedom root has none of that name, each one atomic rename within one filesystem (the move defers on a mounted `freedom/`, so the profile and its `freedom/` share one). The import then reads from the Freedom root, unchanged otherwise. A failure leaves the file where it was, logged, and the import treats it as absent, as any unreadable file is today.
- **(b) Main hands the file over:** a `shell.*` request for its bytes, and another to rename it after the commit. Two new methods for a one-time import.
- **(c) Grant the profile's root.** That brings Electron's data back into the grant.

**Recommended: (a).** It needs `--user-data-dir` only before `confine`. A profile still in the old layout has the same directory for both, and nothing moves. Downgrades are out of scope (the user, 2026-11-21), so an older build not finding the receipts at the root costs nothing.

### C6. A pending node journal's roots

Startup recovery, before the hello, can finish a node-identity journal an earlier run left, in any absolute root that journal names. If main's node directory changed since (an override moved), that root isn't among the arguments.

**Recommended:** before confining itself, `serve` reads the identity directory's `node-identity-journal.json` and `node-identity-staging.json` (as recovery parses them, with the same bounds), and adds each root they name to the grant, with its Radicle gate file (C3). A journal that doesn't parse adds nothing; recovery then sets it aside as it does today. The roots are the user's own node directories from an earlier run, so the grant stays within what the profile used.

### C7. SQLite keeps its temp files in memory

SQLite writes a temp file for a statement that spills, in `$SQLITE_TMPDIR`, `$TMPDIR`, `/var/tmp`, `/usr/tmp`, `/tmp` or the working directory. **Recommended:** `PRAGMA temp_store = MEMORY` at every open (`sqlite.rs`). No payments statement is expected to spill; if one does, memory is the right place for a temp table of the payment history.

### C8. Before the move: D7a's grant

A profile whose move deferred (0013's `deferred` outcomes) keeps its Freedom data at the root of its `userData`, and main passes that as `--grant-root`. The grant is then the whole profile directory, Electron's data included:
- **A named profile** is still separated from the others and from the catalog.
- **The packaged default profile's** `userData` is the app root, which holds `Profiles/`, `R/` and the catalog. Landlock can't carve a subtree back out, so on Linux its `serve` reaches every profile until the move happens. On macOS the Seatbelt profile denies `Profiles/`, the other `R/<slot>` homes, the catalog and its forget file inside that grant.
- Main logs the layout at every start, and the move retries at every start, so this state lasts only while something blocks the move. Nothing else is needed: refusing to start would leave the user without a wallet over a reason the move already logs.

### The order in `serve`

1. **Entry:** the panic hook, then `fc_service::confine::clean_entry`: one re-exec with every descriptor above stderr close-on-exec, as the subcommands do. Logging writes its lines directly until step 7, as theirs do.
2. **Arguments,** checked as in C1.
3. **Hardening** (0001), then the parent's death signal and its check.
4. **The gate,** taken and held; the Radicle gate files opened (C3).
5. **Setup on the only thread:** each missing node root created (C2); the journal's roots read (C6); the receipts renamed (C5); the vault's and the journal's files tightened, as the vault's start does today.
6. **`confine`,** with C2's policy. An `Invalid` is exit 77 (`confinement`), as for the services: main reports the core unavailable and restarts it under its usual rules. A mechanism the OS lacks is reported, not fatal (0010 D2).
7. **The logging thread,** then `serve::run` as today. The hello's answer carries the `Report` under `confinement`, and main logs it with the core's version.

### Per OS

- **Linux:** Landlock at the kernel's ABI with every right it knows handled, and the seccomp denylist with C4's exception, exactly as `fc_service::confine` applies them.
- **macOS:** the Seatbelt profile `seatbelt.rs` generates, with C4's `file-write-mode`, no `mach-lookup` beyond what 0010's offline profile allows, and C8's denials for a default profile in the old layout. `serve` never calls Security.framework (key-store calls go to main), but the framework is linked for the helper; the tests below check that a confined `serve` starts and that nothing in its life asks for a Mach service.
- **Windows:** the job object, nested in main's, with one active process, and the mitigation policies (dynamic code, image load, extension points), read back. Files and IPC are `unavailable` until 0010's restricted token.

## Tests

In freedom-core's CI, on Linux, macOS and Windows, against a `serve` started with C1's arguments:
- **Confined:** the hello's `confinement` report says `enforced` (Linux), `partial` naming `modes` (macOS), or the job and mitigations with files and IPC `unavailable` (Windows).
- **Outside the grant,** from a test method (`testhooks`): reading another profile's directory, the catalog `profile-registry.json`, the forget file, a file at the profile's root (Electron's), and the lock directory all fail; removing another profile's lock file fails (C3); a TCP connect, a Unix-socket connect to the session bus and an exec all fail.
- **Everything `serve` does still works, confined:** the existing integration suites (vault, secrets, stores, intents, payments, approvals, dweb, naming, chain) run against the confined binary; `nodes.write_identity` for Bee and Radicle, and a wipe; startup recovery of a journal whose root isn't among the arguments (C6); the gate's and the vault's tightening, and SQLite's first open (C4, C7); the key-store calls through main's helper (0013's D7 tests: create, open, replace and forget on every OS that offers them).
- **Refusals:** a hello whose `grant_root` or `user_data_dir` differs from the arguments; a `nodes.write_identity` for another directory; a `serve` missing the new arguments.
- **Modes (Linux):** `fchmod` to 0600 and 0700 succeeds, to 0644 and 0755 fails with `EPERM`.
- **The receipts (C5):** a moved profile with `x402-receipts.json` at its root imports it once, from the Freedom root, and the root keeps no copy; with a `.migrated` at the root too, the stray is dropped as today; a profile in the old layout behaves as today.
- **Before the move (C8):** a named profile in the old layout can't read another profile; on macOS the default profile in the old layout can't read `Profiles/`.

In freedom-browser's CI: every core integration suite and e2e job runs against the confined core it pins, with main passing C1's arguments; a moved profile with legacy receipts shows them in the payment history.

## Steps

1. **D7-1 (fc-service):** the `modes` field (seccomp's masked compare, Seatbelt's `file-write-mode`), and the gate over an open file (C3). Tests on each OS.
2. **D7-2 (freedom-cored):** C1's arguments and checks, the hello and `nodes.write_identity` matches, C5's rename, C6's journal roots, C7's pragma, the order above with `clean_entry`, and the report in the hello's answer. `serve` confines itself; `hold-lock` takes the same order with only the identity directory and its gate, and `recover` with the identity directory, its gate and C6's journal roots. Tests above.
3. **Release,** then **B-D7 (freedom-browser):** pass C1's arguments from `core-process.js`, log the report, pin the release; the browser tests above.

## Decisions

All the coordinator's, open to the user's veto:
- **C1:** the grant from `serve`'s arguments, the hello and `nodes.write_identity` checked against them.
- **C2:** read-write on the identity directory, the Freedom root and the node roots; `/dev/urandom` and `/proc/self/mountinfo` read-only; offline.
- **C3:** the lock directory through descriptors opened before `confine`, not granted.
- **C4:** mode changes allowed only to owner-only modes (Linux), in the read-write grants (macOS).
- **C5:** the legacy receipts renamed into the Freedom root before `confine`.
- **C6:** a pending node journal's roots granted.
- **C7:** SQLite's temp store in memory.
- **C8:** D7a's grant for a profile in the old layout, with Seatbelt's carve-outs for the default profile on macOS.
