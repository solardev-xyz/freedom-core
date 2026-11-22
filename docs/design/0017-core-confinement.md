# 0017: OS confinement for `freedom-cored serve`

**Status:** proposed. It is [0010](0010-service-confinement.md)'s D7 ("`freedom-cored` is confined too, in a later design", decided by the user 2026-10-23), on what [0013](0013-profiles.md) left for it ("Effects on 0010 and D7"). PRF-9's move is released (`cored-v0.26.0`), so this design starts at 0013's D7b, the `freedom/` grant, and keeps D7a's wider grant only for a profile whose move hasn't happened yet. Every choice below is a technical one, made by the coordinator, which the user may veto; none is a product question.

**Amended** after review round 1: the claims and tests are scoped per OS by what each mechanism reports (Windows enforces only part of `exec` before 0010's restricted token); C5 hands over only a receipts file today's import would read, with a cross-directory durable rename; C6 follows recovery's own rules for each record kind; C8 gives up Seatbelt carve-outs; the inventory lists `fc_service`'s system grants and the stores' generic temp and set-aside names. After round 2: C5 copies instead of moving, so the profile's root keeps its file until the import has committed; C6 leaves a missing committed Bee root missing, as recovery does; the Windows and macOS grants are stated as `fc_service` sets them. After round 3: C5 drops the original only when the Freedom root holds the same bytes and its directory has just been synced, and a conflict skips the legacy import instead of reading either side; C6 states the exception for a record naming a current argument root, and what each backend does with a root replaced mid-start.

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
  - **The legacy receipts (C5):** `x402-receipts.json` is imported from the profile's root today. Before confining itself, `serve` copies a file that today's import would read into the Freedom root, with fc-store's durable write, and imports the copy; the original at the profile's root is dropped at a later start, once the copy's `.migrated` shows the import committed. Electron's own data leaves the grant.
  - **A pending node journal (C6):** before confinement, `serve` plans what recovery will need by record kind and node, granting the roots a committed journal or a live intent names that exist, and creating only what recovery would have created (a Radicle home, through its gate).
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
- **After, on Windows:** no child process of its own; no dynamic code; no image loaded from a remote device or a low-integrity location, with System32 searched first; no extension point. Files, IPC and the network stay as today, and a process created with another of the user's processes as its parent escapes the job (0010's `parent_process` gap), until the restricted token.

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
| `refer` | false: every rename stays in its directory |
| `symlinks`, `times` | false |
| `network` | `Offline` |
| `resolver` | `None` |
| `interface_index` | false |
| `descriptors` | the gate's lock, each Radicle gate file (C3), and anything else opened before `confine` |
| `modes` (new, C4) | true |

**What `confine` adds on its own,** for every confined process, so the effective grant beyond the table:
- **Linux** (`resolver.rs`, with `Resolver::None`): `/proc/self` (its `mountinfo` included), `/sys/fs/cgroup`, `/dev/random` and `/dev/urandom`, read-only.
- **macOS** (`seatbelt.rs`): read and executable mapping of the system's libraries and frameworks; the random devices; `/dev/null`, read and written; and `/usr/bin/true`, read and mapped executable, the target of the profile's exec self-test (it can't run: `process-exec` is denied).
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
- **(a) `serve` copies the file into the Freedom root before confining itself,** only when today's import would read it, and imports the copy.
- **(b) Main hands it over:** a `shell.*` request for its bytes, and another to rename it after the commit. Two new methods for a one-time import.
- **(c) Grant the profile's root.** That brings Electron's data back into the grant.

**Recommended: (a), as a copy.** The original stays at the profile's root until the import has committed, so the root's file is authoritative until then, as it is today. A step at every start of a moved profile (`--user-data-dir` given, and different from `--grant-root`), on the only thread, before `confine`, in this order. Without `--user-data-dir` the import's root is the Freedom root, as it is today without `user_data_dir`, and the step does nothing.
1. **No file:** `x402-receipts.json` absent at the root, as `metadata` finds it today (a link followed, any error as absent): nothing.
2. **A stray at the root:** a `.migrated` at the root too, as today: the root's `x402-receipts.json` is removed there through the same `fsx::remove` as today's stray branch. Nothing is copied. A `.migrated` at the root never moves: its only meaning is "drop a stray".
3. **Not readable as today's import reads it:** the root's file is read as `read_file` reads it (no link followed, a regular file, the current user's, at most `MAX_LEGACY_BYTES`). Anything refused (a directory, a link, a special file, another user's file, an oversized one) stays at the root, logged as today's `Kept` (`unreadable`), and nothing else happens.
Steps 4 to 6 look at both names in the Freedom root before acting on either: a name with other bytes than the root file's, or one `read_file` refuses, makes it a conflict (step 6) even beside a copy with the same bytes, since the import would otherwise drop that copy as a stray without importing it.
4. **Imported from a copy already:** a `x402-receipts.json.migrated` in the Freedom root, read the same way, with exactly the root file's bytes: an earlier start's copy was imported. The Freedom root's directory and that file are synced first (`fsync` on Unix; on Windows fc-store's `FlushFileBuffers` primitive, best effort as fc-store documents it), and only if that succeeds is the root's original removed, as a stray. A sync that fails leaves the original for the next start.
5. **Copied already:** a `x402-receipts.json` in the Freedom root with exactly the root file's bytes: an earlier start's copy whose import hasn't committed (refused, or a write failed). Nothing is copied again; the import retries on that copy, as today's retries on the root's file.
6. **A conflict:** a `x402-receipts.json` or `.migrated` in the Freedom root with other bytes, or one that `read_file` refuses: neither is C5's copy of this file, and the root's file is the one today's import would read. Nothing is copied, both files stay as they are, the conflict is logged, and the legacy import is skipped for this run: the database opens and serves, with no row imported from either file and neither renamed. Each start checks again, so removing one of the two by hand settles it.
7. **The copy:** fc-store's temps for this one name in the Freedom root (`fsx::remove_temps`, which nothing else calls for it) are removed first. Then the bytes `read_file` returned, from the handle it checked, are written to `x402-receipts.json` there by fc-store's atomic write (temp file, `fsync`, rename, directory sync; on Windows its flush primitive), mode 0600 on Unix (on Windows it inherits the directory's ACL, as every fc-store file does). A `NotDurable` outcome is logged and changes nothing below: the original can only go at step 4, after a sync of its own. Nothing at the root changes.

The legacy import runs only after a copy proved to hold the root file's bytes (step 5) or just made (step 7), unchanged, with the Freedom root as its root: it reads the copy, commits its rows, and renames the copy `.migrated` there (`fsx::sync_rename`), exactly as it does at the root today. After every other step (1 to 4, 6, and a copy whose write failed) it is skipped for this run: the database opens and serves, and no file in the Freedom root that today's import wouldn't read is imported, renamed or removed. At the next start, step 4 drops the root's original.

**Crash safety,** at each point:
- **Before the copy's rename:** no copy, or only fc-store's temp, which step 7 removes at the next start. The root's file is untouched; the next start copies again.
- **Copy visible, import not committed, durable or not:** step 5 at the next start; the import retries on the copy. If a power loss took a copy that wasn't durable, step 7 makes it again. The original stays at the root.
- **Import committed, the copy's rename to `.migrated` not durable:** today's state at the root, now in the Freedom root: after a power loss the copy is back without `.migrated`, and the next import imports again; `import_legacy` skips every entry imported already (`payments.rs`), as it does in today's window.
- **`.migrated` visible, the original still at the root:** step 4 syncs the Freedom root before removing anything, so the original goes only once the marker is durable. A failed sync, or a crash before the removal, leaves the original for the next start. No point removes the original while the marker could still be lost, so no point loses the only copy.

Two copies at once (the root's original and the Freedom root's copy or `.migrated`) are a state C5 makes on purpose. It settles them by comparing bytes, so a file in the Freedom root that didn't come from this original (put there by hand, or by an older core run without `user_data_dir`) never stands in for it.

**Parity with today's import:** a file the import would refuse (bad JSON, refused rows) or fail to write is `Kept` and retried at every start, as today; the copy is what is retried, and the original stays at the root until a retry commits. The log lines are the import's own, plus one each for the copy, the dropped original and a conflict.

A profile in the old layout has the same directory for both, and the step does nothing: the import runs at the root as today.

### C6. A pending node journal's roots

Startup recovery, before the hello, finishes or discards what an earlier run left in the identity directory: a committed journal (`node-identity-journal.json`) is replayed, an intent with no journal (`node-identity-staging.json`) is discarded. If main's node directory changed since (an override moved), the record's root isn't among the arguments. And every `read_write` path must exist (`confine`'s rule), while recovery deliberately neither creates nor looks under a missing intent root.

**Recommended:** before confining itself, `serve` reads both records (as recovery parses them, with the same bounds and validity checks) and plans by record kind and node, mirroring recovery:
- **No record, an invalid one, or a journal the done list already records:** nothing is granted. Recovery sets the invalid one aside, or removes the finished journal, with the identity directory alone, as today.
- **A committed Radicle journal not yet done:** recovery takes the home's gate through the creating path (`radicle_gate(…, true)`), which makes a missing home. The plan does that part now: the home is made as the gate makes it, its gate file is opened (C3), and the home is granted. A held gate still makes recovery wait (`Waiting`), as today.
- **A committed Bee journal not yet done:** recovery opens the recorded root once (`Resolve::Follow`) and, if it is gone, concludes with no root: every install is marked corrupt, the status is `Corrupt`, and the journal goes, with nothing created. So the plan grants the root only if it exists; a missing one is neither created nor granted, and recovery concludes it as today, with the identity directory alone.
- **An intent, no journal:** a root that exists and is a directory (for Bee, following links, as recovery's `Resolve::Follow` does, so a dangling link is a missing root; for Radicle, through no link, as its gate's canonical path requires) is granted, with its Radicle gate file (C3); recovery gates it and removes the staged names, as today. A missing root is neither created nor granted: recovery removes the intent without the gate and without looking under the root, as today, with the identity directory alone. A root that isn't a directory isn't granted; recovery fails on it as it does today (`pending_recovery`).
- **A record naming a current argument root:** C2 creates a missing `--node-root` before the plan, so a record whose missing root is that same path finds it present and empty. A committed Bee journal then concludes `Corrupt` as it would with no root, since every staged file went with the old root; an intent's cleanup finds nothing staged and removes the intent. The status is the same; the one difference is that the empty root exists, and it is the profile's current node directory, which main and the node make at the node's start anyway. The absence rules above hold for roots the arguments don't name.
- **A root replaced or made during start-up:** a same-user process doing it is outside the boundary (non-goals), so the plan adds no identity check of its own, and what happens is each backend's:
  - **between the plan and `confine`:** both backends resolve the policy's paths while `confine` runs, so a replacement is what gets granted, and recovery follows it, as it would today;
  - **after `confine`, under Landlock:** the rule is bound to the directory the path named at `confine`, so a replacement is refused; recovery's open fails with a permission error, not "not found", and the record stays (`pending_recovery`) for the next start's plan;
  - **after `confine`, under Seatbelt:** the rule is a path, so a replacement at the same path is allowed, and recovery follows it, as today;
  - **a root made at a path nothing granted:** refused on both, and the record stays (`pending_recovery`).

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
5. **Setup on the only thread:** each missing node root created (C2); the records planned (C6); the receipts copied (C5); the vault's and the journal's files tightened, as the vault's start does today.
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
- **The receipts (C5):** a moved profile with `x402-receipts.json` at its root imports it once, from its copy in the Freedom root, and the original goes at the next start; with a `.migrated` at the root too, the stray is dropped at the root and nothing is copied; a directory, a link, a FIFO, another user's file (Unix) and an oversized file named `x402-receipts.json` each stay at the root, unread and uncopied; bad JSON and refused rows leave the copy and the original, and the import retries at the next start; a database write failure (a test hook) does the same; the deliberate two-copy states (original and copy; original and the copy's `.migrated`) each converge at the next start with every row imported once; a copy or `.migrated` in the Freedom root with other bytes is a conflict: both files stay unrenamed, the database gains no legacy row from either, it serves payments, and the conflict is logged; a crash (a test hook) before and after the copy's rename, before and after the import's commit, and before and after the original's removal, never loses the receipts, and a crashed copy's temp is gone after the next start; a forced flush failure of the copy, and of the Freedom root's sync at step 4, each leave the original at the root; a profile in the old layout, and a `serve` without `--user-data-dir`, behave as today.
- **The records (C6),** for Bee and Radicle each: a committed journal with its root present, changed since the arguments, and missing (Radicle: the home made and the journal replayed; Bee: `Corrupt`, and the root and its missing ancestors still absent); a held Radicle gate (`Waiting`); an intent with its root present, missing (the core starts, the intent goes, and the root isn't created), and not a directory; a missing root that is also the current `--node-root` (created by C2; the same status as with no root) and one that isn't (left absent, with its missing ancestors); a dangling Bee link as an intent's root (discarded, as today); a root made at an ungranted path after `confine` (the record stays, `pending_recovery`); on Linux, a granted root replaced after `confine` (refused, `pending_recovery`); on macOS, the same replacement (followed, as today); an invalid record; a journal already done.
- **SQLite (C7):** a new database's first open and its switch to WAL, confined.

**On Linux and macOS:**
- **Outside the grant,** from a test method (`testhooks`): reading another profile's directory, the catalog `profile-registry.json`, the forget file, a file at the profile's root (Electron's), and the lock directory all fail; removing another profile's lock file fails (C3); a TCP connect, a Unix-socket connect to the session bus and an exec all fail.
- **The gate's and the vault's tightening** at start, confined (C4).

**On Linux:** `fchmod` to 0600 and 0700 succeeds; to 0644, 0755, 04700, 02700 and 01700 it fails with `EPERM` (C4).

**On Windows:** a child process `serve` creates as its own is refused by the job.

**Before the move (C8),** on Linux and macOS: a named profile in the old layout can't read another profile.

In freedom-browser's CI: every core integration suite and e2e job runs against the confined core it pins, with main passing C1's arguments; a moved profile with legacy receipts shows them in the payment history.

## Steps

1. **D7-1 (fc-service):** the `modes` field (seccomp's per-bit `MaskedEq` rules, Seatbelt's `file-write-mode`) and the gate over an open file (C3). Tests on each OS.
2. **D7-2 (freedom-cored):** C1's arguments and checks, the hello and `nodes.write_identity` matches, C5's copy, C6's plan, C7's pragma, the order above with `clean_entry`, and the report in the hello's answer. `serve` confines itself; `hold-lock` takes the same order with only the identity directory and its gate, and `recover` with the identity directory, its gate and C6's plan. Tests above.
3. **Release,** then **B-D7 (freedom-browser):** pass C1's arguments from `core-process.js`, log the report, pin the release; the browser tests above.

## Decisions

All the coordinator's, open to the user's veto:
- **C1:** the grant from `serve`'s arguments, the hello and `nodes.write_identity` checked against them.
- **C2:** read-write on the identity directory, the Freedom root and the node roots, with `confine`'s own system reads; offline.
- **C3:** the lock directory through descriptors opened before `confine`, not granted.
- **C4:** mode changes allowed only to owner-only modes (Linux), in the read-write grants (macOS).
- **C5:** a legacy receipts file today's import would read copied into the Freedom root before `confine`, the original dropped once the copy's import has committed.
- **C6:** a pending record's roots planned by its kind and node, as recovery treats it.
- **C7:** SQLite's temp store in memory.
- **C8:** D7a's grant for a profile in the old layout, with no Seatbelt carve-outs.
