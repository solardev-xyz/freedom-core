# 0008: The libradicle service process

**Status:** proposed. Roadmap Phase 4 (item 4.4). Builds on [0001](0001-freedom-cored.md) (process model, lifetime lock, node identity writes, process hardening), [0006](0006-dweb-transports.md) (the outline in *Service processes*) and 0007 (#68: the IPFS service, whose process model, stream frames, ring buffers, `ServiceClient` and SOCKS contract this design reuses).

**The references:**
- **freedom-browser** at `c5bd66d5` (#704):
  - `radicle-embedded.js`, `radicle-manager.js` and `radicle-api-protocol.js`;
  - `radicle/rad-protocol.js`, `radicle/cob-service.js`, `radicle/seed-status.js` and `radicle/radicle-provider-ipc.js`;
  - `identity-manager.js` and `profile-paths.js`;
  - `scripts/fetch-radicle-addon.js` and `src/shared/radicle-addon-version.js`.
- **libradicle** v0.8.0 (`e5b137e`), the release freedom-browser pins. Its release workflow builds the add-on with `no-spawn`.
  - `lr` below is `src/lib.rs`; `napi` is `napi/src/lib.rs`.
- **heartwood** at `c208df3`, the `solardev-xyz/heartwood` revision libradicle pins.
  - `hw/` paths are under its `crates/`.

## Summary

Radicle runs inside Electron main today. The libradicle N-API add-on hosts a whole heartwood node in main's process:
- its reactor, its workers and its control socket;
- storage reads on main's libuv pool, under one process-wide mutex.

As a result:
- a panic on an add-on call aborts the browser;
- nothing restarts the node;
- it honors no proxy;
- a blob comes back as JSON, with binary content dropped and text decoded lossily.

This design moves it into **its own supervised process, `freedom-radicled`**. It reuses 0007 wherever the two agree, and differs where heartwood does:

- **The process model is 0007's:**
  - a plain Rust binary on stdio frames;
  - `--parent-pid`;
  - 0001's lifetime lock, keyed by the Radicle home;
  - restarts after 0.5 s, 2 s and 10 s.

  The difference: **one node per process, the process is the only teardown, and the process starts no child.**
  - heartwood's threads can't be cancelled from outside, so stopping the node, changing its policy, or recovering from a failed start all end the process.
  - The import that spawns `git push` today becomes an in-process libgit2 fetch. So when the process has exited, every writer it had is gone, and a restart is always a new generation.
- **The state isn't a cache.** The Radicle home holds:
  - the user's signed issues and comments;
  - the seeding policies;
  - the node's key.

  So the service reconciles interrupted writes under the lock before it reports `RUNNING`, and a write that has started is either proven, or reported as **outcome unknown**.
- **The blob API (0006's requirement):** `rad.blob` returns a blob's **raw bytes**, **chunked** over 0007's stream frames, with an optional **byte range**.
  - The existing JSON endpoint stays byte-identical.
  - A new `rad:` endpoint, `/raw/<rev>/<path>`, serves the bytes themselves, with Range, under conservative headers.
- **Bounded, cancellable reads:**
  - `rad:` and `radapi:` take main's dweb admission, and a page's abort reaches the service.
  - Reads run on a bounded pool, with no process-wide mutex.
  - JSON results are reserved as they are built and stopped at a cap.
  - Main **streams** them to handlers. Only small results are collected, under their own budget.
- **Keys:**
  - The service holds one secret: the user's Radicle node key, which heartwood needs for every connection and signature. It is a separate identity, not a wallet key, and not a cache that a vault lock wipes.
  - It keeps today's source: the key file the core writes. The service reads it, so main no longer holds the key, and the service never generates one.
  - The custody mode, and reconciling it with AGENTS.md, is the user's decision ([Keys](#keys)).
- **Network policy:**
  - heartwood's SOCKS5 proxy and onion settings are set in memory, `direct` or `socks5` through Arti, with every other routing field overridden.
  - Names are resolved, checked and pinned, as in 0007's SOCKS contract.
  - An address policy covers addresses learned from peers.
  - The node listens on nothing: no inbound port, and, after an upstream change, no control socket.
- **Private windows** read the profile's node, as today. A private read sends nothing, signs nothing, writes nothing and records nothing. Private partitions can't seed, sync or write.
- **The code goes beside 0007's,** as `services/freedom-radicled` in its own Cargo workspace. A new repository remains the user's call.
- **Tests come first:**
  - a contract suite over the add-on's 30 exports;
  - golden JSON recorded from v0.8.0 on a fixture repository, which the service must reproduce byte for byte.

## Goals and non-goals

**Goals**
- **Crash isolation:** no Radicle fault can end main. A crashed service restarts with back-off.
- **Parity:**
  - the same `Embedded` calls, the same Radicle home and the same key file;
  - the same JSON bytes for every read main passes through;
  - the [deviations](#deviations) are listed.
- **The blob API:** raw, chunked and ranged bytes, with bounded memory.
- **Bounded, cancellable reads:**
  - admission in main;
  - pools and an output budget in the service;
  - streaming to handlers;
  - aborts that reach the service.
- **One owner per Radicle home,** enforced by the OS before anything touches it, for every Freedom writer.
- **Writes with an honest outcome,** and a home that is reconciled after any interruption.
- **A network policy the node honors,** failing closed: under a proxy, no direct peer socket.
- **Honest key custody:** the key's holders and sources are stated, and anything new is left to the user.

**Non-goals**
- **Planning `rad:` in the core** (0006's model for `bzz:` and `ipfs:`). `serveRepoApi` stays in main. Moving it into `fc-dweb` is a later step, once the service exists.
- **The Radicle provider's consent model** (`window.radicle`): unchanged.
- **New Radicle features:** no patch creation and no repository creation beyond today's `importRepo`.
- **Mobile:** iOS keeps linking libradicle through UniFFI.
- **Content verification (4.5):** not here. heartwood verifies refs against signed sigrefs itself.
- **An OS sandbox.** Process separation is a crash domain and a resource boundary, not a sandbox.

## Today

- **Loading:**
  - `radicle-embedded.js` `require`s `libradicle.node` from the app's resources or the repository.
  - It checks that the 30 exports in `RADICLE_ADDON_REQUIRED_EXPORTS` exist.
  - `fetch-radicle-addon.js` pins v0.8.0 with an in-repo digest over the release's `SHA256SUMS`.
- **Lifecycle** (`radicle-manager.js`):
  - Start is `start(radHome, 'FreedomBrowser')`, which is `Embedded::start` with `listen: []` (`napi:218`–`243`).
  - Then, in the background, `connectSeeds(15000)` and `cloneRepo(<Freedom's repo>, 120000)`.
  - Stop is `shutdown()`.
  - There is no health check and no restart.
  - Quit gives Radicle no budget of its own beyond the 20 s watchdog.
- **Threads:**
  - Every export except `cancelClone` runs on the libuv pool. `UV_THREADPOOL_SIZE` is 16.
  - Storage reads and writes hold the add-on's one `NODE` mutex for the whole call (`napi:22`, `napi:81`). Connects and clones use a cloned network handle and don't hold it.
  - heartwood runs on its own threads:
    - a reactor;
    - 8 workers;
    - a control-socket listener.
- **Reads:**
  - `serveRepoApi` serves both `rad:` and the internal `radapi:` viewer. It passes the add-on's JSON text through untouched (#514).
  - A blob is `blobAt(rid, revision, path)`. The add-on returns `{"binary": true, "name"}` with no content for a blob libgit2 flags as binary, or `{"binary": false, "name", "content"}` with `String::from_utf8_lossy` text (`napi:742`–`765`).
  - Neither handler reads Range, sets length or caching headers, takes admission, or watches the request's abort signal.
- **Import:** `importRepo` runs `rad::init`, which pushes the working copy into storage with the `git` executable (`hw/radicle/src/rad.rs:107`–`120`, `hw/radicle/src/git.rs:741`–`756`). It is the add-on's one child process.
- **Home:**
  - The Radicle home is `<appRoot>/R/<slot>` for catalog profiles (`profile-paths.js`). It is short because of the control socket's path limit.
  - It holds:
    - `config.json`;
    - `keys/radicle` and `radicle.pub`;
    - `storage/` (bare git repositories);
    - `node/` (`node.db` in WAL mode, `policies.db`, `notifications.db`, `control.sock`);
    - `cobs/cache.db`.
- **Exclusion:** heartwood takes no lock on the home. Binding the control socket is its only exclusion between nodes.
- **Key:**
  - `keys/radicle` is an unencrypted OpenSSH Ed25519 key (`cipher none`), mode `0600`.
  - It is written by the core's `nodes.write_identity` from the vault seed at `m/44'/73404'/0'/0'/0'`, or generated at random by libradicle on a profile that has none.
  - The add-on loads it into main's process.
- **Network:**
  - outbound only (`listen: []`);
  - the shipped seed book (14 DNS seeds) and heartwood's defaults;
  - no proxy or onion setting;
  - `tor-proxy.js`: the decentralized protocols "keep connecting directly".
- **Private windows** register the same handlers on the same node. Only main's log redaction differs.

## Process model

```
Electron main (profile P) ──spawn──▶ freedom-radicled serve --home <rad home> --lock-dir <locks> --parent-pid <pid>
     stdin  ──frames──▶
     stdout ◀──frames──
     stderr ◀──JSON log lines──
```

### Spawn and lock

- **One process per profile,** for the profile's Radicle home (`getRadicleDataDir()`, unchanged).
  - It is spawned when Radicle starts in managed mode.
  - The binary comes from `<resources>/freedom-radicled/`. `FREEDOM_RADICLED_PATH` is honored only when `!app.isPackaged`.
- **No child processes:**
  - The service is built with libradicle's `no-spawn` feature, explicitly, so serving fetches runs in process and `git gc` is skipped.
  - The import becomes an in-process libgit2 fetch ([Writes](#writes)).
  - The service never starts a process. So its exit ends every writer it had, and its lock, which is close-on-exec, is held by nothing else.
- **The environment** is cleared, as 0007's is. That drops:
  - `RAD_SOCKET`, `RAD_KEYGEN_SEED`, `RAD_PASSPHRASE`, `RAD_RNG_SEED`, `RAD_LOCAL_TIME`, `GIT_COMMITTER_DATE`, `SSH_AUTH_SOCK` and systemd's `LISTEN_*` variables, all of which heartwood reads;
  - everything else main has.

  `HOME` points at an empty directory the service owns. With libgit2's configuration search paths emptied ([upstream](#upstream-changes)), no global or system git configuration applies.
- **Handshake:** `rad.hello` within 10 s, as 0001.
- **The lock:** `<lock-dir>/radicle-<sha256(canonical home)>.lock`, under 0001's rules, which also cover the canonical path, the stable lock directory, network filesystems and bind mounts.
  - Contention retries for 5 s, then exits 75. Other errors and network filesystems exit 74.
  - **It is taken before anything opens the home.** heartwood's own exclusion is the control-socket bind, which comes after its threads have started (`hw/radicle-node/src/runtime.rs:202`–`249`).
- **Every Freedom writer of Radicle files takes this gate:**
  - the service;
  - `hold-lock`;
  - the core, in every path of 0001's node identity protocol that touches Radicle files: `nodes.write_identity`, its startup recovery before `core.hello`, the `recover` subcommand, and the retries after `pending_recovery` ([Identity changes](#identity-changes)).

  The `rad` CLI pointed at Freedom's home doesn't take it, and is unsupported, as is any older build sharing the home.
- **`freedom-radicled hold-lock --home … --lock-dir …`** holds the gate until stdin closes, as 0001's does. It is used by:
  - the alias rewrite;
  - profile delete and reset;
  - `radicle:reset`.
- **Process hardening** is 0001's, because the process holds a key:
  - Linux: `PR_SET_DUMPABLE=0`;
  - macOS: no core files, plus the hardened runtime from signing.

### Start, stop and reconciliation

- **Start:**
  1. spawn;
  2. `rad.hello`;
  3. **`rad.reconcile`,** a phase of its own, with its own deadline ([Reconciliation](#reconciliation)). Its reply is the boundary main can see: the home is consistent;
  4. `rad.start`, which runs `Embedded::start` with today's options, the [network policy](#network-policy) and no key generation, and returns `{ did, nid, alias }`;
  5. `RUNNING`;
  6. main runs today's background `rad.connect_seeds` and default-repository `rad.clone`.

  Until `RUNNING`, every other request gets `stopped`.
- **A failed start ends the process.**
  - libradicle can fail after heartwood's threads have started (`lr:777`). Those threads hold each other alive.
  - So the service answers with the error and then exits: `recovery_failed` or `deadline` from `rad.reconcile`, or `start_failed` or `no_identity` from `rad.start`. Main shows the error and doesn't restart, as a failed start is handled today.
  - The menu's start spawns a fresh process.
- **Stop is the process's end:**
  1. main sends `rad.shutdown` and closes stdin;
  2. the service fences new work, answers waiting requests `stopped`, and calls `Embedded::shutdown`;
  3. it exits 0 when that returns, or after 5 s whatever its state (`lr:1343` joins with no timeout);
  4. main kills it 10 s after `rad.shutdown`.
- **Quit:** Radicle gets a 10 s leg in the wind-down. That equals Tor's, so the 20 s watchdog stands.
- **Parent death:**
  - stdin EOF, with `--parent-pid` and `PR_SET_PDEATHSIG` as 0001;
  - a watchdog thread exits the process 5 s after EOF;
  - on Windows, EOF or a writer failure is the guaranteed path. libuv's kill-on-close job object is only a backstop, because libuv carries on when assigning the job fails.

### Reconciliation

A kill can land between the steps of one operation:
- a first clone's temporary directory and its rename;
- a COB write's object, its ref, `rad/sigrefs` and the COB cache.

Each ref is renamed into place atomically, but the steps together aren't. So before `RUNNING`, with the lock held, the service runs an **upstream reconciliation procedure** (`Storage::reconcile`, [upstream](#upstream-changes)) as `rad.reconcile`.

**The dirty marker** (`node/dirty`) records that the home may hold a partial mutation:
- **It is set before any mutation can run.** `rad.reconcile` writes it durably (the file, then its directory, flushed) before it changes anything. It stays present for the whole run, and every mutation of the home happens while it is present: COB writes, `unseed`, the import, clones, and heartwood's own fetches.
- **It is kept after anything that may be partial:** a write that ends `outcome_unknown`, or a clone or fetch that is cancelled or cut off.
- **It is cleared only after a proven clean stop.** At `rad.shutdown`, it is removed (durably) only when all of these hold:
  - the write queue is empty, and the executing writer, if any, has returned;
  - every write that ended `outcome_unknown` this run has had its repository repaired or quarantined since ([Writes](#writes));
  - `Embedded::shutdown` has returned, so heartwood's workers have finished their fetches.

  A shutdown with a timed-out writer still running, or one that reaches the 5 s exit, leaves the marker.
- **What it selects:** with the marker present at start, the own-namespace check and the cache rebuild run. Temporary clones and ref lock files are handled on every start.

- **Temporary clones:**
  - **What is recognized:** directories directly under `storage/` named `<RID>.tmp`, which is heartwood's `TempRepository` format (`hw/radicle/src/storage/git/temp.rs`: `<rid>.<random>` with its extension replaced by `tmp`), and the legacy `<RID>.lock`, where `<RID>` parses as a repository ID.
  - **How they are removed:** after an `lstat` shows a real directory, not a symlink, with a delete that follows no symlinks.
  - Any other name with an extension is left alone and counted.
- **Ref lock files:**
  - **What is recognized:** regular files named `*.lock` under a repository's `refs/`, plus `packed-refs.lock`, `HEAD.lock` and `config.lock` at its root.
  - A lock file is an update that never committed, so its ref keeps its old value. It is removed, with no symlinks followed.
- **The node's own namespace,** in every repository, when the marker was present:
  - its refs are checked against its `rad/sigrefs`;
  - if refs advanced without a matching signature (a kill between the ref and the signing), the namespace is re-signed over its current refs, with the node's key. The refs were written by this node.
  - The repository is queued for a refs announcement once the node runs.
- **The COB cache,** when the marker was present: rebuilt from storage for every repository, in bounded, resumable batches ([Work units](#work-units)). `cobs/cache.db` is derived data.
- **Failure:**
  - Anything the procedure doesn't recognize, or can't repair, is left exactly as it is. An example is an owned ref that points at a missing object.
  - **Within one repository,** that repository is quarantined ([the escape](#the-escape)), with the step and the evidence kept. The [repository gate](#the-repository-gate) shuts it, and the node runs without it.
  - **Outside any one repository,** for example an unreadable cache database or storage directory, `rad.reconcile` answers `recovery_failed`.
  - Either way, nothing is deleted to make the start succeed.
- **Logs:** counts and repository IDs, never paths inside a repository.

#### Work units

Every potentially long step is a **unit**. Each unit has a work limit and a time limit, and a durable in-progress record (the repository, the unit's kind and its position) is written before it starts. The deadline is checked between units.

| Unit | Work limit | Time limit |
|---|---|---|
| removing one temporary clone, or one repository's ref lock files | one directory | 30 s |
| checking the node's namespace against its `rad/sigrefs` | 1,024 refs; a larger namespace takes several units, each with a checkpoint | 30 s |
| re-signing the namespace | one ref update, flushed, with libgit2's fsync option on | 30 s |
| materializing one COB into staging | one COB | 30 s |
| committing a batch | one transaction: at most 64 staged COBs and the checkpoint | 30 s |
| publication | one transaction | 30 s |

- **The cache rebuild** of a repository runs in **batches** of at most 64 COBs:
  - Each batch materializes its COBs into a staging table in `cobs/cache.db` (`rebuild_staging`) and records its checkpoint, the last COB it finished. Both go in one durable transaction, with `synchronous = FULL` during reconciliation.
  - When every COB is staged, **publication** swaps the repository's live cache rows for the staged ones in one transaction, and clears its staging.
  - So a rebuild interrupted at any point resumes from its last checkpoint, and readers never see a half-built cache.
- **The progress state** (`reconcile_state`, in the same database) holds the checkpoints, each repository's finished steps, and the unit in progress.
  - An entry is written in the same transaction as the work it records. For a re-sign, it is written after the ref update has been flushed.
  - So the state never claims work that isn't durable.
  - **It is bound to its input:** each repository's checkpoints carry the repository's input version, a hash over its refs taken when its repair began. A resumed repair whose input version differs discards that repository's staging and starts it over.
  - **Online,** a repository's progress rows are deleted in its publication transaction. So a completed repair can't be reused once later mutations begin.
- **Before `RUNNING`:** once every repository is done or quarantined, the progress state is cleared in one durable transaction, before `rad.reconcile` replies. No completion record survives into a run whose new mutations could make it wrong.

#### The deadline

- `rad.reconcile` has 300 s from admission, owned by the service. Main's watchdog is at 315 s: 0001's deadline plus 15 s.
- It is checked between units: between batches, between COBs within a batch, and between namespace checks.
- At the deadline, the service does all of these:
  - stops after the current unit;
  - commits the partial batch with its checkpoint;
  - keeps the marker and the progress state;
  - answers `deadline`.
- Main shows "Radicle is still repairing its data" with **Retry**. A retry spawns a new process, which continues from the checkpoints. There is no automatic restart loop.
- **Shutdown and kill:** `rad.shutdown` stops after the current unit. A kill is safe at any point, since every unit is idempotent and is recorded only once it is durable.

#### The unit watchdog

A unit that doesn't return can't be interrupted from inside the process. So time is enforced from outside the worker.

- **The watchdog:** an independent thread holds the current unit's time limit. A unit that overruns isn't interrupted: the watchdog ends the process (exit 70, `unit_overrun`), so the worker, and every thread that could still mutate, ends with it.
- **The record survives.** The unit's in-progress record and the dirty marker stay, so the next start sees exactly which unit overran.
- **Online as at startup:**
  - An online repair that hangs ends the process within 30 s.
  - Main restarts it, which counts as a crash, and startup reconciliation retries the unit, or quarantines its repository.
  - `rad.stats` reports the unit in progress and its elapsed time, so a healthy node thread isn't mistaken for a healthy repair.
- **Quarantine waits for the worker to be gone.** A hang is quarantined only at a later start, after the process that ran the unit has ended. A unit that fails with an error has already returned. Either way, no quarantine is acknowledged, and no write resumes, while an old worker could still mutate.
- **The interruption allowance:** the writer is held by at most one unit at a time, so for at most 30 s by the watchdog. Writes to other repositories run between units, and wait at most 30 s behind an online repair, within their 60 s deadline.

#### The escape

A unit that can't finish is not retried forever.

- **After one interrupted attempt,** the next attempt reruns the unit in its smallest form: a batch one COB at a time, and a namespace check in single refs. It records each piece durably before starting it.
- **A poison unit:** a unit that was in progress when two processes ended quarantines its repository, with the unit's kind and position. A unit that fails with an error quarantines it at once.
- **So every retry makes progress or reaches a diagnosis:** it advances a checkpoint, or it quarantines a repository.
- **Two kinds of quarantine:**
  - **`cache`:** a COB or the cache can't be rebuilt. The repository's git data and the node's namespace are intact.
  - **`namespace`:** the node's own namespace doesn't verify and can't be re-signed, for example an owned ref that points at a missing object.
- **The record:** a quarantine is recorded durably, in a `quarantine` table that outlives the run, before anything else resumes:
  - at a start, before `rad.reconcile` replies;
  - online, before the writer takes its next task.

  It stays on disk, untouched beyond its staging, and the [repository gate](#the-repository-gate) shuts it.
- **Unseed doesn't clear it:**
  - Unseeding changes the seeding policy, not the record. While `storage/<rid>` exists, the record stays and the gate stays shut. A later seed or clone of the same repository is refused with `quarantined`.
  - **Remove** (`rad.remove_repo`) is the only way out. It does these in order, durably:
    1. unseeds the repository;
    2. deletes `storage/<rid>`, following no symlinks;
    3. deletes the repository's cache rows;
    4. clears the record.

    Main warns first that this deletes the local copy, including the user's own issues and comments in it that haven't been shared.
- **The diagnosis isn't retryable:** the repository stays quarantined until it is removed, or until a later service version clears the record.
- **Main's view:**
  - `rad.reconcile` reports the first 16 quarantined repositories, and `rad.quarantine_list` pages through all of them ([Methods](#methods)).
  - Main shows "Radicle couldn't repair <name>", with the kind, the step and **Remove**.

#### The repository gate

heartwood fetches, updates the COB cache, announces and serves on its own. So repair and quarantine are enforced inside the node, not only at the service's methods.

- **The gate** is an upstream hook ([heartwood item 14](#upstream-changes)), held by the service and consulted by heartwood for:
  - every fetch, explicit or automatic: clones, syncs, gossip-driven fetches, and the retries of seeded repositories that are missing;
  - every COB cache update;
  - refs and inventory announcements;
  - serving the repository to peers.
- **Its states, per repository:**

| State | Fetch and cache update | Announcements | Serving | COB reads | File reads and `repo_info` | Writes |
|---|---|---|---|---|---|---|
| open | yes | yes | yes | yes | yes | yes |
| repairing | deferred until publication | deferred until publication | yes | `stopped` (503) | yes | wait behind the repair |
| quarantined, `cache` | refused | refs and inventory as before | yes | `quarantined` (503) | yes; counts may lag | refused |
| quarantined, `namespace` | refused | the repository is left out | refused | `quarantined` (503) | `quarantined` (503) | refused |

- **The whole repair is fenced:** from the start of a repository's repair until its publication, every mutator of that repository waits, heartwood's included. Its staging input can't change underneath it.
- **Catching up:** fetches deferred during a repair run after publication, through the normal path, which updates the cache. A peer's update that arrives mid-repair is therefore applied after the repaired cache, never overwritten by it.
- **Other repositories** stay open throughout.

**Reads of unreconciled state:**
- Nothing is read before `RUNNING`.
- During a run, an uncertain write's repository is repaired before its COBs are read again ([Writes](#writes)).
- A read is never proof that an uncertain write is absent.

**After reconciliation:**
- a COB write that was cut off is either absent, because its ref was never committed, or present, with its ref signed and cached. Otherwise its repository is quarantined;
- an unreferenced object may remain, which is harmless.

### Crashes and restarts

0007's rules (0001's back-off) and generations, with these differences:

- **The node's own threads:**
  - heartwood's reactor and worker panics are caught by nothing, and `Handle::is_running()` always returns true (`hw/radicle-node/src/runtime/handle.rs:162`).
  - The service watches the node thread itself: an upstream change exposes it ([below](#upstream-changes)).
  - When the node thread has ended, the service answers what is in flight and exits 70 (`node_down`). That is a crash, and main restarts it.
- **Panics on the service's own threads:**
  - A startup panic hook replaces Rust's default. It writes one fixed JSON line to stderr, `{"panic": "<thread kind>"}`, never the payload, and suppresses the backtrace.
  - On a request thread, inside the request's `catch_unwind`, the panic becomes that request's `internal` error (`outcome_unknown` for a write that has started), and the service then checks the node thread.
  - On any other thread, the hook ends the process with 70.

  So no panic payload, which can contain a path or a RID, reaches a log.
- **A restart is a new generation.**
  - The node, its policy and its key are re-read from the home, after reconciliation.
  - Requests captured by main before the restart fail with the old generation, as 0007's do.
  - There is no in-process restart, so instance epochs aren't needed.
  - There are no partition instances either, so 0007's lease and per-partition readiness don't apply: readiness is the node's ([Main's side](#mains-side)).

## The protocol

### Frames and streams

0007's frame layer, envelope and stream frames, unchanged:
- `0x02` data, `0x03` end, `0x04` abort and `0x05` credit;
- the stream ID is the request ID;
- a 128 KiB window per stream;
- data frames of at most 64 KiB.

The rules this design relies on, as 0007 specifies them:
- **Per-stream order:**
  - the head, then data, then one terminal;
  - `end` is written only after the stream's last data frame;
  - `abort` purges the stream's unwritten data, and nothing of the stream follows it.
- **Cancel against an unwritten head:** the head is dropped and `cancelled` is the only reply.
- **Credit:** checked accounting on both sides. Data beyond the window, or credit beyond what was sent, is a protocol error. Late credit for an ended stream is ignored, which needs no table because request IDs strictly increase.
- **Allocation:**
  - main keeps each stream in **one 128 KiB ring**, so its backing storage equals the window;
  - a pull copies out into a chunk the consumer owns;
  - the decoder holds at most one partial frame (≤ 1 MiB);
  - a cancelled stream keeps only a retirement record until its terminal frame.
- **Progress under backpressure:**
  - the service's reader never waits on the writer: credit, cancel and shutdown are applied as they are read;
  - main keeps decoding while its own writes wait.

### Methods

| Method | Params | Result | Pool and deadline |
|---|---|---|---|
| `rad.hello` | `protocol`, `shell_version`, `frames` | `protocol`, `service_version`, `libradicle` build info | 10 s after spawn |
| `rad.reconcile` | none | `{ was_dirty, repaired, quarantined: { count, first } }`: counts per step, and up to 16 quarantine entries | 300 s ([the bound](#reconciliation)); on failure or deadline, the process exits |
| `rad.quarantine_list` | `page` | `{ entries, next_page }`: up to 64 entries `{ rid, kind, step, unit, since }` per page | read pool; 60 s |
| `rad.remove_repo` | `rid` | `{ removed }` | write queue; 60 s |
| `rad.start` | `alias`, `network` | `did`, `nid`, `alias` | 30 s; on failure, the process exits |
| `rad.stats` | none | `connected_peers`, `node_alive`, the repair unit in progress and its elapsed time, `quarantined_count`, pool and budget use | inline; 5 s |
| `rad.shutdown` | none | none: the process exits | main kills after 10 s |
| `rad.read` | `op`, `args` | head `{ content_type: "application/json", bytes }`, then the JSON as a body stream | read pool; 60 s to the head |
| `rad.blob` | `rid`, `revision`, `path`, `range?`, `head_only?` | head `{ oid, size, binary?, range }`, then the bytes | read pool; 60 s to the head |
| `rad.connect_seeds` | `timeout_ms` | today's report | network pool; `timeout_ms` + 30 s |
| `rad.clone` | `rid`, `timeout_ms`, `progress` | `{ ok }` or `{ cancelled }`; `rad.progress` events | network pool; `timeout_ms` + 30 s |
| `rad.unseed` | `rid` | `{ unseeded }` | write queue; 60 s |
| `rad.write` | `op` (`create_issue`, `comment_issue`, `edit_issue_state`, `comment_patch`), `args` | today's JSON | write queue; 60 s |
| `rad.import_repo` | `path`, `name`, `description`, `default_branch` | `{ rid }` | write queue; 300 s |

- **`rad.read`'s `op`** is one of the ops below, in three classes. Each body is JSON, and its class says whose bytes it reproduces ([Parity](#parity)).
  - **Pass-through:** the exact JSON text the v0.8.0 add-on returns for that export, with today's arguments:
    - `repo_info`, `tree`, `tree_at`, `blob`, `blob_at`;
    - `commits`, `commit`, `issues`, `patches`;
    - `list_repos`, `list_seeded_repos`;
    - `seeders`, `identity`, `status`.
  - **Main's serialization:** the bytes main's `JSON.stringify` writes today for the parsed add-on result: `issue`, `patch`, `remotes` and `repo_stats`.
  - **Composed:** new ops, each reproducing what main composes today:

| Op | Params | Result | Notes |
|---|---|---|---|
| `readme_at` | `rid`, `revision` | the README blob's JSON with `"path"` spliced in, as `readmeAtRaw` builds it from `tree_at` and `blob_at` | `not_found` ("no readme") when there is none |
| `repo_meta` | `rid` | `buildRepoMeta`'s object | a `seeders` failure gives `seeding: 0`, logged without the RID |
| `repos_meta` | none | an array of `repo_meta`, one per `list_repos` entry, in its order | any failure fails the whole listing (500), as today |
| `issues_page`, `patches_page` | `rid`; `status`, `page` and `per_page` as the raw query strings, or null | the page main's `paginate` returns: filtered by `state.status`; `page` from `Number.parseInt`, at least 0; `per_page` clamped to 1–100, with 30 by default | JavaScript's `parseInt` rules, pinned by vectors |
| `node_info` | none | `{ connected_peers, repos_total, repos_error }`, where `repos_total` is null and `repos_error` holds the message when enumeration fails | a `status` failure fails the call; collected, at most 64 KiB |

- **The repair fence:** the COB ops (`issues`, `issue`, `patches`, `patch`, `issues_page`, `patches_page`) answer `stopped` (503) for a repository under repair, and `quarantined` (503) for a quarantined one ([Reconciliation](#reconciliation)).
- **Why reads stream:** the 1 MiB JSON frame (0001) is smaller than many results, such as a commit's diff or a large text blob. Streaming also lets main pass a result to a handler without holding it ([JSON results](#json-results)).
- **`rad.progress`** events carry `{ id, event }`, where `event` is today's progress JSON string ([Progress](#progress)).
- **Cancel:**
  - The envelope's `cancel` on a `rad.clone` flips its `CancelToken`, which replaces `cancelClone(rid)`. Main maps the RID to the request.
  - libradicle checks the token between candidates, and an in-flight fetch finishes first (`lr:449`). So the reply comes when the clone actually stops.
  - Cancelling a queued read removes it before it starts. Cancelling a running read stops its stream at once, and its walk at the next check ([upstream](#upstream-changes)).
  - For writes, see [Writes](#writes).

### Deadlines

- **Reads (`rad.read`, `rad.blob`):**
  - **To the head:** the 60 s deadline runs from admission, and includes the queue and any wait for an output reservation. It ends when the head is written.
  - A read still queued at its deadline is removed before work starts, and answered `deadline`. A running read past it is cancelled, and answered `deadline` if its head hasn't been written.
  - **After the head there is no service deadline.** A stalled or paused body is main's to judge: 0006's pull-driven idle timer cancels a body that leaves a pull unanswered for 60 s, and a paused reader is never timed out. The service ends a stream early only with `abort`: `cancelled`, `stopped`, `internal` or `too_large`.
- **Network operations:** `timeout_ms` + 30 s. A network operation past it gets `deadline`, but keeps its slot until libradicle returns.
- **Writes:** 60 s (300 s for import), with the outcome rules in [Writes](#writes).
- **Main's watchdogs** are each deadline + 15 s, as 0001.

### Errors

| Code | When | Main |
|---|---|---|
| `invalid_argument` | a RID, revision (40 hex), COB ID (6–40 hex), op or range that doesn't parse | 400, today's texts |
| `not_found` | libradicle's not-found errors: the ones today's message test (`/not found\|does not exist\|NotFound/i`) matches | 404 with `{"error": message}` |
| `failed` | any other libradicle error before a write has started; `message` is its `Display` text, as today | 500 with `{"error": message}` |
| `too_large` | a blob over 64 MiB, or a read whose JSON or materialized data passes its cap | 413 (new) |
| `range_not_satisfiable` | `range` outside the blob; `data.size` | 416 with `Content-Range: bytes */size` |
| `busy` | a pool's queue is full | 503 |
| `deadline` | past the deadline, before a head or before a write starts | 504 for reads; the provider's existing errors otherwise |
| `cancelled` | main's cancel, before a write starts | the request is already gone |
| `outcome_unknown` | any write that has started and isn't proven ([Writes](#writes)) | provider error -32603 with new text |
| `stopped` | not yet `RUNNING`, shutting down, or a repository under online repair (COB ops) | 503 |
| `quarantined` | on a quarantined repository: COB ops; for `namespace`, every read; a write, seed, clone or sync; `data.kind`, `data.step` | 503 with `{"error": message}`; the provider's existing errors for writes |
| `internal` | a panic on a read's thread | 500 |
| `recovery_failed`; `deadline` | `rad.reconcile`: a failure outside any one repository, or the deadline; `message` names the step | the manager's error state; for `deadline`, "Radicle is still repairing its data" with Retry |
| `start_failed`, `no_identity` | `rad.start`; `message` is libradicle's | the manager's error state, with that message |

Exit codes:
- 0001's: 64, 74, 75 and 76;
- 70 for `node_down`, or a panic outside a request.

### Progress

- **What libradicle emits:** clone progress, from its clone loop on a network-pool thread (`lr:454`). The reactor is never involved.
- **The service's callback never blocks.** It writes into a bounded per-clone queue and returns.
- **The queue,** per clone:
  - **`resolving`, `connecting` and `fetching`:** only the latest unwritten one is kept.
  - **`peer-failed`:** up to 8 unwritten events are kept as they are. Beyond that, they fold into one summary event, `{"phase":"peer-failed","summary":{"count":N,"reasons":[…]}}`, holding the count and the 4 most recent reasons.
  - **The terminal event** (`done`, `failed` or `cancelled`) has a reserved slot and is never dropped. It is written after everything queued before it.
  - **Size:** every event is measured as encoded JSON, envelope fields and escaping included, and must be at most 4 KiB.
    - An event that would be larger is cut down before it is queued. First the summary's oldest reasons are dropped. Then the remaining `reason` texts are shortened at UTF-8 character boundaries, each ending with `…`, until the whole encoded event fits.
    - The phase and the count are never cut. Escaping counts: a NUL encodes to 6 bytes, a backslash to 2.
- **So a clone holds at most 10 unwritten events of at most 4 KiB encoded:** one latest phase event, 8 failures, and the summary. Its terminal event is separate.
- **This is a deviation** (`progress-summary`): today every event reaches the callback. `seed-status.js` accepts the summary event.

### Pools and budgets

All bounds are process-wide. The service hosts one node.

- **The read pool:** 4 threads, with **320 queued requests**: main's dweb admission of 256, plus 64 for other callers ([Main's side](#mains-side)). Beyond that, `busy`.
  - Reads run concurrently, under a shared lock on the node; there is no process-wide mutex.
  - Three methods take `&mut self` and take that lock exclusively: `seeders` (`lr:1143`), `unseed_repo` (`lr:847`) and `import_repo` (`lr:1012`). `seeders` is a short query on the read pool; the other two are on the write queue.
- **The network pool:** 8 threads for `connect_seeds` and `clone`, with 16 queued.
- **The write queue:** one writer, with 16 queued.
- **The output budget: 256 MiB,** enforced by reservation, as 0007's budget is. Every byte a read holds is reserved before it is allocated, and released when it is freed.
  - **A blob** reserves twice its size while libgit2's buffer and the service's copy both exist, then once until its last byte is written.
  - **A JSON read** reserves both its materialized data and its serialized JSON ([JSON results](#json-results)).
  - **Per read:** a blob of at most 64 MiB (128 MiB reserved while loading); a JSON read of at most 64 MiB, of which at most 32 MiB is JSON.
  - A read that can't reserve waits, inside its deadline to the head.
- **What the service can't bound:** heartwood's own buffers:
  - fetch streams of up to 500 MiB each;
  - its reactor queues and per-peer write buffers.

  The service doesn't promise a total memory bound for the process. Whether to add an OS-level limit is an [open question](#open-questions).

### JSON results

- **In the service, construction is bounded before allocation.**
  - **Materialization:** the walks that build a result (`commits`, `commit` with its diff, `repo_stats`, `list_files`, `issues`, `patches`, `list_repos`) take a byte budget and a cancel token ([upstream](#upstream-changes)).
    - Each item reserves an estimate of its size as it is built: a commit's message and fixed fields, a diff hunk's text, a COB's events.
    - The walk stops with `too_large` when the next item doesn't fit.
  - **Serialization:**
    - The shared serializers write into a size-limited writer. It reserves in 64 KiB steps from the output budget, and fails as soon as the output passes 32 MiB.
    - The limit counts output bytes after escaping. So lossy text and escape expansion (`\u0000` is 6 bytes for 1) can't pass it.
    - The finished JSON is then streamed, under credit, with its length in the head, and its reservation is released as it is written.
- **In main, handlers get streams.**
  - `serveRepoApi`'s reads become `callStream`, which returns the head and a body stream. The handler builds `new Response(body, …)` from it.
  - Main holds 0007's 128 KiB ring per stream and nothing more.
  - `HEAD` cancels the body after the head.
- **Composition moves into the service.** What main builds today from parsed results, the service builds, writing the same bytes main's `JSON.stringify` writes. Vectors recorded from main's code at the reference pin each one ([Tests first](#tests-first)).
- **Collected results** are for callers that need a parsed value, and only for a closed list of small results, each with its own cap. A body past its cap aborts the call with `too_large`.
- **Every export has a route.** None is dropped, and no caller parses a whole body outside `callScoped`:

| Export (today) | Callers today | Route |
|---|---|---|
| `treeAt`, `blobAt`, `commits`, `commit` | `serveRepoApi` (passed through) | `callStream` of the same op |
| `readmeAt` (composed in main from `treeAt` and `blobAt`) | `serveRepoApi` `/readme/` | `callStream` of `readme_at` |
| `buildRepoMeta` (`repoInfo` and `seeders`, composed in main) | `serveRepoApi`'s repository root; `radapi`'s repository list | `callStream` of `repo_meta`, and of `repos_meta` for the list. A `seeders` failure still gives `seeding: 0`, as today |
| `issues`, `patches` (filtered and paginated in main) | `serveRepoApi` | `callStream` of `issues_page` and `patches_page`, with `status`, `page` and `perPage` exactly as main's `paginate` reads them |
| `issue`, `patch`, `remotes`, `repoStats` (parsed and re-serialized in main) | `serveRepoApi` | `callStream` of the same op |
| `status` | `serveNodeApi`'s `/` | collected `status` (64 KiB), alone. It answers `{ version: status.version \|\| "embedded", mode: "embedded" }`, or 503 when `status` fails, as today |
| `status` with a `listRepos` count | `/api/v1/stats`; the manager's connection count | collected `node_info` (64 KiB). The stats endpoint requires the count: a `repos_error` answers 503 `{error}`, as today. The manager takes `repos_total` as `reposCount`, which is null when enumeration failed, as today. A `status` failure is 503 for the endpoint and `GET_CONNECTIONS_FAILED` for the manager |
| `repoInfo` | the `rad:` visibility check; the manager | collected (64 KiB) |
| `seeders`, `identity`, `status` | the manager; `cob-service.js` | collected (64 KiB each) |
| `listSeededRepos` | the manager; the provider | collected (4 MiB) |
| `listRepos` | the GitHub bridge | collected (4 MiB) |
| `tree`, `blob` (no revision) | none of the handlers today | `callStream` |
| `start`, `shutdown`, `connectSeeds`, `cloneRepo`, `cloneRepoWithProgress`, `cancelClone`, `unseedRepo`, `importRepo`, and the four COB writes | as today | their own methods ([Methods](#methods)); small results |

- **The collection budget:** 16 MiB in main, for the bytes being collected and the parsed value.
  - It is reserved as bytes arrive. A call that can't reserve waits up to 5 s, then fails `busy`.
  - The result is handed to a scope: `callScoped(op, args, async (value) => …)`. The reservation is released when the scope's callback settles, which is the result's lifetime.
  - A value under 4 KiB (`identity`, `status`) may be kept after its scope. It is no longer charged.
- **Cancel and ownership:**
  - **Before the handoff,** an abort cancels the call, and the bytes collected so far are released at once.
  - **After the handoff,** the scope owns the value. An abort reaches the callback as a signal, but the reservation stays until the callback settles. So a scope's allowance can't be reused while its callback may still hold the value.

### Writes

- **Serialized:**
  - COB writes, `unseed` and `import_repo` go one at a time through the write queue. `unseed_repo` and `import_repo` also need the node exclusively.
  - The executing write keeps the writer slot until its libradicle call has actually returned, even after its reply.
- **The mutation-start boundary:** a write *starts* when the writer thread calls into libradicle's mutation.
  - **Before it, failure is definitive:**
    - validation errors (`invalid_argument`) and a full queue (`busy`);
    - a queued write that is cancelled, passes its deadline, or meets a shutdown. It is removed from the queue before it can run, and answered `cancelled`, `deadline` or `stopped`.

    None of them ran.
  - **After it, only a success is proven.** Every other result is **`outcome_unknown`**:
    - a libradicle error;
    - a panic;
    - a cancel;
    - the deadline;
    - a shutdown;
    - `node_down`;
    - a crash, which main derives for a write in flight.

    The error's text is logged with its code, never with the content.
  - **Why:** a COB write commits a git object, updates a ref, re-signs `rad/sigrefs`, updates the COB cache and announces the change. An error at a later step doesn't prove that an earlier one didn't commit.
- **What the page sees:**
  - `outcome_unknown` answers -32603 with "The Radicle node stopped before confirming this write; it may have been recorded."
  - Main never retries one, and the page must check before writing again. The write is either absent or complete once its repository's repair has run, online (below) or at the next start, unless the repository is quarantined ([Reconciliation](#reconciliation)).
- **Online repair after an uncertain write:**
  - When the executing call returns, that repository's repair is queued on the writer: validate and re-sign the node's own namespace, then rebuild the repository's COB cache in the same batches and checkpoints as reconciliation ([Work units](#work-units)).
  - It runs one unit per writer turn, interleaved with other repositories' writes, under the [unit watchdog](#the-unit-watchdog). So it never holds the writer for longer than one unit, which is at most 30 s.
  - The [repository gate](#the-repository-gate) is set to `repairing` for the whole repair. Until publication, that repository's COB ops answer `stopped` (503), its fetches are deferred, and writes to it wait behind it.
  - A unit that fails with an error quarantines the repository at once. A unit that hangs ends the process, and the next start retries the unit or quarantines. The marker stays set, so the next start checks the repository again.
  - This mirrors 0005's uncertain broadcasts.
- **Import, in process:**
  - `rad.import_repo` creates the repository in storage and fetches the working copy's default branch into the node's namespace with libgit2's local transport, then signs the refs ([upstream](#upstream-changes)).
  - libgit2 runs no hooks, uses no helpers, and reads no configuration that could send it to the network: it has no global or system configuration ([Spawn](#spawn-and-lock)), and its source is a local path.
  - The working copy is read, never written: it gets no `rad` remote (deviation `import-in-process`).
  - A stop, kill or policy change during an import ends the process, and with it the import. Reconciliation at the next start handles the partial repository, and the reply is `outcome_unknown`.

## The blob API

0006 requires raw, chunked and ranged bytes. libgit2 can't stream objects from packs (`Odb::reader` works only for loose objects), and fetched data lands in packs, often deltified. So **"chunked" means chunked over the pipe, from one bounded copy in memory**, not streamed from disk.

- **`rad.blob { rid, revision, path, range?, head_only? }`:**
  1. Resolve `path` at the commit, as `read_blob_at` does (`lr:1263`), refusing anything that isn't a blob with today's `NotABlob` message.
  2. `Odb::read_header` gives the size and type without loading the content. Refuse a blob over 64 MiB with `too_large`.
  3. Normalize and validate `range` against that size, before anything is loaded ([Ranges](#ranges)).
  4. With `head_only`, the head is written now, without `binary`, and nothing is loaded. This serves `HEAD`.
  5. Otherwise, reserve the output budget, load the blob, and compute `binary` with libgit2's rule (`git_blob_is_binary`, the first 8000 bytes).
  6. Write the head `{ oid, size, binary, range }`, then stream the range in 64 KiB frames under credit. A zero-length body opens no stream.
- **The JSON endpoint stays:**
  - `/blob/<rev>/<path>` on `rad:` and `radapi:` keeps returning `{ binary, name, content? }`, built by `rad.read`'s `blob_at` with v0.8.0's serializer, byte for byte;
  - that includes `from_utf8_lossy` for text and no content for binary.

  Pages and the viewer keep working unchanged.

### Ranges

- **Shape:** `range` is one of:
  - `{ start, end }`, both inclusive;
  - `{ start }`, which runs to the end;
  - `{ suffix }`, meaning the last `suffix` bytes.

  Main parses a single `bytes=` range into it. A header that doesn't parse is ignored, as HTTP allows.
- **Normalization against `size`:**
  - an `end` at or past `size` is clamped to `size − 1`;
  - a suffix becomes `start = max(0, size − suffix)` and `end = size − 1`;
  - a `start` at or past `size`, or a suffix of 0, is `range_not_satisfiable`;
  - for a zero-length blob, every range is unsatisfiable.
- **Answers:**
  - no range: 200 with the whole blob;
  - a satisfiable range: 206 with `Content-Range: bytes start-end/size`;
  - an unsatisfiable one: 416 with `Content-Range: bytes */size`;
  - several ranges in one header: the whole body, 200, as a server may.
- **`HEAD`** answers exactly as `GET` would, with the same status, `Content-Range` and `Content-Length`, but with no body and nothing loaded.

### The raw endpoint

`rad://<rid>/raw/<40 hex>/<path>`, and the same under `radapi://local/api/v1/repos/<rid>/raw/…` for the viewer.
- **Checks:** it passes `serveRepoApi`'s existing checks first, the public/private repository gates and the frame checks included, on every route.
- **Headers:**
  - `Content-Length` and `Accept-Ranges: bytes`;
  - `ETag: "<blob oid>"`;
  - `Cache-Control: public, max-age=31536000, immutable`, since the URL pins a commit;
  - `X-Content-Type-Options: nosniff`;
  - `Content-Security-Policy: sandbox`.
- **`Content-Type`** comes from the extension, from an allowlist of inert types:
  - PNG, JPEG, GIF, WebP, AVIF and ICO images;
  - MP4, WebM and Ogg media;
  - `text/plain; charset=utf-8` for the text extensions the viewer highlights.

  Everything else is `application/octet-stream`. It is never HTML, SVG, XML or JavaScript.
- **The viewer** gains images and a download link through it. "Binary file not shown." goes away.

## Keys

**What the service holds:**
- **One secret: the user's Radicle node key,** an Ed25519 key.
- heartwood holds it in memory for the node's lifetime, in several clones that each zeroize on drop. It needs it continuously:
  - as the Noise XK static key of every peer connection (the node ID is its public key);
  - to sign node, inventory and refs announcements, `rad/sigrefs`, COB changes, and identity documents on import.
- **It survives a vault lock.**
  - The node keeps running, and signing, while the vault is locked, as it does today.
  - The key isn't a derived-key cache of the kind AGENTS.md rule 4 has wiped by every lock. It is a node identity with its own lifetime, like Bee's.
- The service holds no wallet key, no recovery phrase and no vault data, and has no connection to the core.

**Where the key comes from** (unchanged for profiles with a vault):
- `<home>/keys/radicle`, an unencrypted OpenSSH file with mode `0600`, which `Embedded::start` loads (`lr:723`).
- **On a profile with a vault,** the core's `nodes.write_identity` writes it (0001, *Multi-file writes*), derived from the vault seed at `m/44'/73404'/0'/0'/0'` (SLIP-0010).
  - Ed25519 derivation is hardened at every level, and the file holds no chain code, so the key leads to neither the seed nor any other derived key.
  - It does let anyone holding it act as the user's Radicle identity, which is derived from the wallet and can't be rotated without a new derivation path.
- **On a profile without one,** the core writes a random device key, through the same journaled, atomic `0600` write under the home gate. Today libradicle generates it at first start.
  - The service never generates a key. `rad.start` with no key file answers `no_identity` ([upstream](#upstream-changes)).
  - Main asks the core for the device key, then starts again.

**What changes:**
- The add-on loads the key into main's process today. After this design only the service does, under 0001's process hardening. Main never holds it.

**How this fits AGENTS.md:**
- **Rule 3** ("No raw private key or seed leaves the core"):
  - The Radicle key leaves the core today, as a file, through 0001's `nodes.write_identity`. AGENTS.md's list of exceptions doesn't name node identity writes.
  - This design adds no new release of key material. It moves the file's reader from main to the service, and the random device key's writer from libradicle to the core.
- **Rule 4:**
  - Secret files are atomic and `0600`: this now holds for both kinds of key, since the core writes both.
  - The lock-wipes-caches rule doesn't cover a node identity that outlives a lock, as above.
- **A prerequisite:** reconciling rules 3 and 4 with node identities (listing them, and their lifetime across locks) comes before any custody mode is chosen. It is the user's decision ([Open questions](#open-questions)).

**Options for the user:**
1. **The key file (this design's default, today's behavior):** no change to the core's key release, and the node starts at launch without the vault being unlocked.
2. **A host key with no file at rest:**
   - libradicle v0.8.0 has `Embedded::start_with_key` (`lr:744`): it writes nothing secret and keeps the key in memory. UniFFI exposes it; the add-on doesn't.
   - **How the key would arrive:** from the core, sealed (HPKE, RFC 9180) to an X25519 key the service generates at each start. Main relays only ciphertext.
   - **The switch:** the core deletes any plaintext `keys/radicle` under the home gate, as a journaled step. `start_with_key` would otherwise leave an old file in place (`lr:744` documents that), and a later `start` would bring that identity back.
   - **No fallback:** in this mode the service calls only `start_with_key`. It refuses to start while a `keys/radicle` file exists, and never falls back to a file or a generated key, including while the vault is locked.
   - **Costs:**
     - a new core method that releases a node key, sealed. That is a new exception to rule 3, which needs a design change;
     - the node can start only while the vault is unlocked, including every restart after a crash.
   - **What sealing protects:** only the relay through main, meaning main's heap and logs. The core and the service still hold the key in plaintext, so their swap and memory dumps are covered only by 0001's hardening. A compromised main can still ask for the key sealed to a key of its own.
3. **Signing in the core:** rejected.
   - The Noise handshake needs the secret for every connection, and heartwood copies it into its reactor and sessions.
   - The core would have to serve network handshakes on demand.

## Main's side

- **`radicle-embedded.js` keeps its exports and their shapes.** It becomes a client of the service (0007's `ServiceClient`), so its callers change only where results are collected:
  - `radicle-manager.js`;
  - `radicle-api-protocol.js`;
  - `cob-service.js`;
  - `seed-status.js`;
  - `github-bridge.js`.

  The mapping:
  - `callRaw` becomes `callStream` for handlers, and `call` becomes `callScoped` for the closed list of small results ([JSON results](#json-results));
  - `cloneRepoWithProgress` maps `rad.progress` events to its callback;
  - `cancelClone` cancels the clone's request.
- **Reads take admission and cancel:**
  - `rad:` and `radapi:` requests take main's dweb admission (256 active, 512 waiting), the same one IPFS uses;
  - the request's abort signal sends `cancel`;
  - the blob and JSON bodies are 0007's pull-driven streams, with idle bounds;
  - main holds one 128 KiB ring per stream.
- **Other callers:**
  - The manager, `cob-service.js`, the provider and the GitHub bridge aren't dweb-admitted. They share a limit of 64 outstanding service requests, with 64 more waiting in main. Beyond that a call fails `busy`.
  - Their reads use the same 60 s deadline to the head. Their parsed results take the routes in [JSON results](#json-results), and so the collection budget, with no whole-body parsing outside it.
- **Readiness:**
  - The node is up while all of these hold:
    - its generation is live;
    - `rad.start` succeeded;
    - the last `rad.stats` says `node_alive` and is under 15 s old.
  - `rad.stats` runs every 5 s while the node is `RUNNING`. Today there's no probe.
  - There is one node and no partition instances, so 0007's lease and per-partition readiness have no counterpart here.
- **Private partitions are read-only:**
  - main refuses `seed`, `sync`, COB writes and `importRepo` for a private partition before anything is sent;
  - reads go to the profile's node as today.

### Identity changes

One owner holds the home gate at each step, and no step waits on a gate that its own caller holds:

1. **Main stops the service.** The process exits, and its gate is free, since it starts no child.
2. **The core takes the gate for the whole identity change.**
   - `nodes.write_identity { node: "radicle", home, alias, wipe: true }`. It extends 0001's journaled multi-file write.
   - It stages the key files, then commits the journal, which records the wipe. It then wipes `node/`, `cobs/` and `storage/`, installs the files, and finishes.
   - Recovery of such a journal repeats the wipe, which is idempotent, and then the install. All of this is under the same gate.
   - The wipe moves from main into the core, so main never holds `hold-lock` while the core needs the gate.
3. **Main starts the service** only on `installed` (0001: "Main starts a node only on `installed`"). The service's own start then reconciles under the gate before `RUNNING`.

- **Contention:** if the gate is held, for example by a running service that main didn't stop, `nodes.write_identity` retries for 5 s, then answers `lock_held` and touches nothing.
- **The core's own recovery:** startup recovery before `core.hello`, and `recover`, take the gate per Radicle journal in the same way. If the gate is held, the journal is left in place, and the core reports `pending_recovery` for Radicle without blocking `core.hello`. Main keeps the service stopped and retries, as 0001 already requires.
- **Lock order:** the core's own lifetime lock, then the Radicle home gate. The service and `hold-lock` take only the home gate, so no cycle exists.
- **The alias rewrite** runs under `hold-lock` alone, with the service stopped. The core isn't involved.

## Private windows

- **No ephemeral node.** `rad:` reads touch only local storage, and a read never starts a network fetch.
- **The boundary:** a read from a private window causes:
  - no explicit fetch;
  - no signed announcement;
  - no write to the home;
  - no visit record;
  - no identifying log line. The service logs no RID or path for any read, and main keeps its private-window redaction.
- **Outside the guarantee:** the profile's node and files are shared. Read caches (SQLite's page cache, the OS's file cache) and the timing effects of reads are therefore shared with other windows. Isolating them would need partition-aware read state, which this design doesn't add.
- **Read-only:** private partitions can't seed, sync or write ([Main's side](#mains-side)). `window.radicle` isn't injected in private windows today, and that stays.

## Network policy

### What heartwood can honor

- **`node.proxy`:**
  - a SOCKS5 proxy, given as an IP and port (`hw/radicle/src/node/config.rs:618`);
  - when it is set, every peer dial goes through it (`hw/radicle-node/src/wire.rs:1125`–`1130`).
- **Per-family settings:** `node.onion`, and `node.i2p` when built with I2P. Each is `Proxy { address }`, `Forward` or `Drop` (`config.rs:418`–`435`).
  - `Forward` without a global proxy dials those names as ordinary hosts, for transparent-proxy setups (`wire.rs:1112`). This design never uses it.
- **`listen`:** empty, so the node is outbound only.
- **libradicle exposes none of these.**
  - `Options` has only `home`, `alias` and `listen` (`lr:41`).
  - The node's settings come from `config.json`, whose own `listen` is ignored (`lr:773`).

### Features and address families

- **The service's `radicle-node` features,** exactly:
  - `tor` (onion addresses);
  - `socket2` (TCP keepalive).
- **Left out:**
  - `i2p`;
  - `systemd`, whose socket activation reads and removes `LISTEN_*` at bind (`hw/radicle-node/src/runtime.rs:314`–`349`);
  - `backtrace`;
  - `structured-logger`, since the service logs through its own hook.

  The address families are therefore IPv4, IPv6, DNS names and onion. I2P addresses can't be dialled, and the address book's I2P entries are refused before any socket.
- **Every routing field is set in memory,** whatever `config.json` says:
  - `proxy`;
  - `onion`;
  - `listen` (empty);
  - `externalAddresses` (empty, so the node advertises no address of its own).

  A `config.json` with a conflicting proxy, an onion `Forward`, or an I2P route has no effect. The service never rewrites the user's `config.json`.

### Modes

The service sets these through an [upstream](#upstream-changes) `Options` change.

- **`direct`, the default:**
  - `proxy` unset and `onion: Drop`, which is heartwood's default;
  - a name is resolved once, every address is checked, and the connection goes to a checked address, with no second lookup.
- **`socks5 { ip, port }`,** with 0007's SOCKS contract:
  - `proxy` and `onion: Proxy` are both set to Arti's endpoint, given as an IP literal, so reaching the proxy needs no DNS;
  - **ordinary names** are resolved through Arti's `RESOLVE`, every answer is checked, and the dial is a SOCKS `CONNECT` to a checked IP literal;
  - **a failed lookup, an empty answer, or an answer whose every address is refused** is an error. The dial fails, and the name is never sent to the proxy;
  - **only onion names** are handed to the proxy as names, through a separate, explicit route;
  - nothing falls back to a direct socket;
  - if the pinned Arti can't `RESOLVE`, the setting waits, as 0007 decides.
- **The setting:** a per-profile **Route Radicle through Tor**, off by default, using `tor-manager`'s endpoint. Whether it and 0007's IPFS setting become one switch is an [open question](#open-questions).
- **Changing the policy restarts the process.** Nothing of the old policy survives its process, since there is no child.

### The address policy

- **Untrusted targets** are addresses learned from peers: node announcements and the address book they fill.
- **Configured targets** are the shipped seed book, `preferredSeeds` and `connect` in `config.json`, and Arti's endpoint.
- **In both modes**, untrusted targets in these ranges are refused:
  - loopback, `0.0.0.0/8` and `::`;
  - private ranges (RFC 1918, `fc00::/7`);
  - link-local (`169.254.0.0/16`, `fe80::/10`);
  - CGNAT (`100.64.0.0/10`);
  - multicast, broadcast and the documentation ranges.
- **When the check runs:**
  - on IP literals, before the dial;
  - on DNS names, on every resolved address, locally in `direct` mode and through `RESOLVE` in `socks5` mode, before the connection. The connection goes to a checked address.

  That needs resolution moved off the reactor thread ([upstream](#upstream-changes)).
- **Configured targets** are exempt, by exact address, so a user's LAN seed keeps working.
- **Onion targets** are classified as in 0007: a host whose last label is `onion`, case-insensitive, with any trailing dot removed. In `direct` mode they are refused before any socket exists, as heartwood's `Drop` does.

### Seeding and serving

- **This is Radicle's model, unchanged:**
  - a seeded repository is announced in the node's signed inventory and served to peers that ask for it;
  - seeding happens only on an explicit seed, clone or sync, and on the default repository at start.
- **Browsing through `rad:`** reads local storage and announces nothing.
- **No listening socket:**
  - no inbound port;
  - after the upstream change, no control socket.

  The service controls the node through its in-process handle.

## Upstream changes

**libradicle** (v0.8.0):
1. **Policy in `Options`** (`lr:41`):
   - add `proxy: Option<SocketAddr>`, `onion: AddressConfig`, `control_socket: bool`, `generate_key: bool`, a resolver hook and an address policy;
   - `run` (`lr:757`–`793`) applies them to `profile.config.node` before `Runtime::init`, overriding every routing field and `externalAddresses`;
   - nothing is written to `config.json`.
2. **Node health:** `Embedded::node_alive()`, from the node thread's `JoinHandle::is_finished` (`lr:684`, `lr:781`).
3. **No key generation, and errors rather than panics, at start:**
   - with `generate_key: false`, `start` fails with `NoIdentity` instead of generating a key (`lr:700`–`720`);
   - the key-generation `expect` becomes an error (`lr:706`).
4. **The JSON serializers move out of the add-on:**
   - Today they are written inline in each export (`napi:34`–`216` and every export's `json!`, for example `blob_at` at `napi:742`–`765`).
   - Move them to a library module that writes into any `io::Write`, so the add-on, UniFFI and the service emit the same bytes, and the service can bound the writer.
   - `readme_at` joins them.
5. **The blob header:**
   - `Embedded::blob_header(rid, revision, path) -> { oid, size }`, using `Odb::read_header` before any load;
   - `read_blob_at` (`lr:1263`) takes a size cap.
6. **Bounded, cancellable walks:**
   - `repo_stats` (`lr:1311`), `list_files` (`lr:1118`), `commits` (`lr:1161`), `commit` with its diff (`lr:1179`), `issues`, `patches` (`lr:1040`–`1085`) and `list_repos` (`lr:852`) take a `CancelToken` and a byte budget;
   - each charges every item as it is built, and stops with `TooLarge` when the next doesn't fit.
7. **A bounded shutdown:** `shutdown` (`lr:1343`) takes a timeout. The service exits after 5 s anyway.
8. **Features:** depend on `radicle-node` with `default-features = false` and exactly `tor` and `socket2` ([Features](#features-and-address-families)). Keep `no-spawn` on.
9. **An in-process import:**
   - `import_repo` (`lr:1012`) creates the repository in storage, fetches the working copy's branch into the node's namespace with libgit2's local transport, and signs the refs;
   - it replaces `rad::init`'s `git push` (`hw/radicle/src/rad.rs:107`–`120`);
   - at start, libradicle empties libgit2's configuration search paths, so no global or system git configuration applies.

**heartwood** (the `freedom/embed` fork):

10. **An optional control socket:**
    - `Runtime::init` takes `Option<PathBuf>` (`runtime.rs:202`–`249`, bind at `344`–`359`);
    - `Handle::shutdown` must not need to connect to the socket (`runtime/handle.rs:355`–`374`).
11. **The dial gate:**
    - resolve names through the host's resolver hook on a resolver thread, with a deadline, rather than on the reactor (`wire.rs:1146`–`1153`). The service's hook is the system resolver in `direct` mode, and Arti's `RESOLVE` in `socks5` mode;
    - apply the address policy to every answer, and connect to a checked address. Through the proxy, that is a SOCKS `CONNECT` to the IP literal (`Wire::dial`, `wire.rs:1089`–`1172`);
    - treat a failed, empty or wholly refused answer as an error that fails the dial, never as a reason to hand the proxy the name;
    - route onion names to the proxy as names, through a separate, explicit path;
    - apply the same policy where announced addresses enter the address book.
12. **Errors, not panics:**
    - in the reactor's policy-store calls (`hw/radicle-protocol/src/service.rs:863`–`896`, `1185`, `1556`, `1641`, `2066`);
    - in start-time configuration checks (`service.rs:566`, `service/gossip.rs:12`–`16`, `runtime.rs:163`–`165`).

    A failure there should stop the node with an error the host can see.
13. **`Storage::reconcile`,** the procedure in [Reconciliation](#reconciliation):
    - typed recognition of temporary clones (`<RID>.tmp`, legacy `<RID>.lock`) and ref lock files, with no symlinks followed;
    - validation and re-signing of the node's own namespace;
    - a COB cache rebuild in batches into a staging table, with durable checkpoints and atomic publication;
    - progress state written in the same transactions as the work, bound to each repository's input version, with an in-progress record for every unit;
    - namespace checks in units of 1,024 refs, with checkpoints;
    - a cancel token and a deadline checked between units;
    - a `quarantine` table with its two kinds, and `remove_repo`;
    - `reconcile_repository(rid)` for the online repair, one unit per call;
    - a report of what it changed, and an error that names anything it couldn't repair.
14. **The repository gate:**
    - a per-repository state (`open`, `repairing`, `quarantined` with its kind) that the host sets;
    - heartwood consults it before every fetch, the automatic retries of seeded repositories included (`hw/radicle-protocol/src/service.rs:765`–`772`, `2486`–`2538`), and before every COB cache update;
    - before refs and inventory announcements (`service.rs:1967`–`1968`, `2131`, `2394`);
    - before serving a repository to a peer (`hw/radicle-node/src/worker.rs:243`–`258`);
    - a deferred fetch runs once its repository reopens.

## Where the code lives

0007's options and recommendation apply.

1. **This repository, `services/freedom-radicled`, its own Cargo workspace** (recommended):
   - it shares `fc-protocol` and 0007's service skeleton;
   - it has its own lockfile and `deny.toml`. libradicle's lockfile, which also covers its add-on and UniFFI bindings, has 453 packages, including vendored libgit2 (C; GPL-2.0 with a linking exception, which the notices must carry) and bundled SQLite;
   - heartwood comes from `solardev-xyz/heartwood`, which `deny.toml`'s organization allowlist covers.
2. **A member of the core's workspace:** rejected, for 0007's reasons.
3. **Upstream libradicle,** as a binary beside `napi/` and `uniffi/`.
   - **For:** the closest home.
   - **Against:** the frame protocol, lock and supervision contract are Freedom's, and this repository's lack of a license blocks depending on `fc-protocol`.
4. **A new repository:** the user's decision.

**Scope of the separation:**
- A separate workspace separates dependency resolution and advisory gates. It is not supply-chain isolation: build scripts and proc macros still run with the build host's authority.
- So each service builds in its own disposable CI job and checkout, with its own caches and artifact names, and read-only credentials.
- Publishing runs no dependency code. The service release can't supply or overwrite core artifacts.
- Changes to the shared `fc-protocol` pass the core's own review and tests.

## Migration

### Tests first

- **One contract suite over `radicle-embedded.js`'s 30 exports,** in freedom-browser. It runs against:
  - the fake add-on, as today;
  - the real v0.8.0 add-on, in CI's `radicle-addon-load` job;
  - then against the service.
- **Golden vectors:**
  - **The fixture repository** has two commits, and contains:
    - a binary file;
    - a non-UTF-8 text file;
    - a 70 MiB file;
    - an empty file;
    - a symlink;
    - issues and patches with comments.
  - Every read export's output on it is recorded from the v0.8.0 add-on, including the README composition. The service must match every byte.
  - The deliberate differences are:
    - the 70 MiB blob (`too_large`);
    - the error codes (the same message text, a code alongside).
- **The handlers:**
  - **`/raw/`:**
    - 200, and 206 for `bytes=0-9`, `bytes=5-` and `bytes=-10`;
    - an end beyond EOF, clamped;
    - 416 for a start beyond EOF;
    - a zero-length blob: 200 with no range, 416 with one;
    - `HEAD` with and without a range;
    - the inert-type headers;
  - cancel mid-body, a paused reader, and admission's 503;
  - the service exiting mid-body;
  - private partitions refused for writes.
- **Composed outputs:** `readme_at`, `repo_meta`, `repos_meta`, `issues_page` and `patches_page` (with each `status` and page bound), `node_info`, and the re-serialized `issue`, `patch`, `remotes` and `repo_stats`, each recorded from main's code at the reference and matched byte for byte.
- **`node_info`'s three contracts,** with vectors from `serveNodeApi` and `getConnections` at the reference:
  - `status` succeeds and enumeration fails: `/` answers 200 with its `version` and `mode`; `/api/v1/stats` answers 503 with the error; the manager reports `reposCount: null`;
  - `status` fails: `/` and `/api/v1/stats` answer 503, and the manager reports `GET_CONNECTIONS_FAILED`.
- **Admission and routing, one test per new op** (`readme_at`, `repo_meta`, `repos_meta`, `issues_page`, `patches_page`, `node_info`):
  - it is routed from its handler path or caller;
  - it is admitted through the read pool's queue with its deadline, and refused `busy` past the queue;
  - the COB pages are fenced during a repair and under quarantine.
- **JSON results:**
  - 4 concurrent maximum-size results with slow consumers: the output budget holds, and main holds one ring per stream;
  - a blob of 6 MiB of NUL bytes, whose escaped JSON would be 36 MiB: `too_large`, stopped while it was being written;
  - a history walk past its byte budget: `too_large`, stopped while it was being built;
  - collected results over their caps, and over the 16 MiB collection budget: `too_large`, then `busy`;
  - an aborted collecting call releases its bytes;
  - a scope paused with a 4 MiB result, then aborted: its allowance stays reserved until the callback settles, and a new call can't use it;
  - the budget tests include the composed issue and patch endpoints, and the callers outside the handlers: the manager, the provider, the GitHub bridge and `cob-service.js`.
- **Deadlines:** a read queued past its deadline never starts; a read waiting for a reservation past its deadline gets `deadline`; a paused body after the head is never timed out by the service.
- **Writes:**
  - a failure injected at each durable stage of a COB write (the object, the ref, the sigrefs, the cache, the announcement), and on each terminal path (error, panic, cancel, deadline, shutdown, kill): every result after the boundary is `outcome_unknown`;
  - after a restart, the issue is either absent or complete, signed and cached;
  - queued writes that are cancelled or expired never run;
  - the writer slot stays held until the call returns.
- **Import:**
  - a stop and a kill during an import, then a restart: reconciliation handles the partial repository, and no process outlives the service;
  - a policy change during an import;
  - an import whose working copy has hooks and a `url.*.insteadOf` configuration: none of it runs or applies.
- **The dirty marker:**
  - a failure injected after a COB ref and before its sigrefs, then an ordinary `rad.shutdown` and a restart: the marker stays, and the restart repairs;
  - a shutdown while a timed-out writer is still running: the marker stays;
  - an `outcome_unknown` write, then reads of its repository: 503 until the online repair is done;
  - a unit of the online repair that fails with an error: the repository is quarantined persistently and at once. Its COB reads answer `quarantined`, and other repositories keep working;
  - a clean run: the marker is cleared, and the next start skips the full repair.
- **The bound:**
  - **one repository whose cache rebuild alone takes longer than 315 s:** each attempt advances its checkpoint, and a retry completes;
  - **a repository with a COB that never finishes loading:** after two attempts end during it, the repository is quarantined. The node reaches `RUNNING`, its COB reads answer `quarantined`, and its file reads still work;
  - **a kill between a batch's work and its commit:** the progress state doesn't claim the batch, and the retry redoes it;
  - **at `RUNNING`:** no progress state is left;
  - **an online repair:** it runs one unit at a time between other writes.
- **Units and the watchdog:**
  - **a COB that never returns during an online repair:**
    - `rad.stats` stays answered, and shows the unit's elapsed time;
    - the watchdog ends the process within 30 s;
    - the restart's reconciliation retries the unit and overruns again;
    - the next start quarantines the repository;
    - writes to another repository resume between units, and after the restarts;
  - **an oversized namespace check (100,000 refs):** it advances in units of 1,024 with checkpoints. A namespace unit that never finishes reaches quarantine after two process ends;
  - **every unit kind** leaves an in-progress record that the next start finds.
- **The repository gate:**
  - **a peer update during a repair,** both to an already-staged COB and adding a new one: the fetch is deferred, then applied after publication. The published cache keeps both changes;
  - **after a restart,** an automatic fetch of a quarantined repository is refused;
  - **unseed, then seed again:** the gate stays shut, and only Remove opens it, after the data is deleted;
  - **a `namespace` quarantine** isn't served or announced, and its reads answer `quarantined`. A `cache` quarantine keeps its file reads;
  - **other repositories** stay usable during a repair and under a quarantine.
- **Diagnostics:** `rad.reconcile` reports at most 16 entries, and `rad.quarantine_list` pages through 100 quarantined repositories, 64 at a time.
- **Reconciliation:**
  - a kill between a COB ref and its sigrefs: the namespace is re-signed;
  - between the sigrefs and the cache: the cache is rebuilt;
  - during a first clone: `<RID>.tmp` is removed;
  - a symlinked `<RID>.tmp` and an unknown extension: left alone;
  - an owned ref pointing at a missing object: the repository is quarantined (`namespace`) persistently, with nothing deleted. Its reads answer `quarantined`, it isn't served or announced, and other repositories work;
  - an unreadable cache database (home-level): `recovery_failed`, with nothing deleted.
- **Identity changes:**
  - stop → wipe and key write by the core → restart, including a failed write;
  - with an independently running service holding the gate: `lock_held`, and no file touched;
  - core recovery while the gate is held: `pending_recovery`, then completion once the service stops;
  - a profile without a key: `no_identity`, the core's device key, then a start.
- **Progress:** more than 16 failed candidates with a paused writer, then a cancel: the summary counts every failure, the terminal `cancelled` arrives, and memory stays bounded. Also an oversized `reason`, and a summary whose reasons are NULs and backslashes: the encoded event stays within 4 KiB, cut at character boundaries.
- **Rust tests through the binary,** with test hooks behind a feature:
  - the lock and `hold-lock`;
  - parent death;
  - a failed start that exits;
  - a panic in a read (`internal`, others unaffected, no payload in the log);
  - a killed node thread (exit 70);
  - the 5 s shutdown;
  - 0007's stream cases.
- **Network:**
  - a SOCKS recorder and canary, as 0007: in `socks5` mode no direct peer socket;
  - 0007's SOCKS fixture with `RESOLVE`:
    - a name that resolves to loopback;
    - an answer that changes between checks;
    - an empty answer, and an answer whose every address is refused. In both, no `CONNECT` carries the name;
  - `.onion` refused in `direct`;
  - a test peer announcing loopback and private addresses, which are never dialled;
  - I2P addresses, which are refused;
  - a `config.json` with a conflicting proxy, an onion `Forward` and an I2P route, which change nothing;
  - in `direct` mode, one lookup per connection, connected to the checked address.
- **Live:** the packaged `nodes.spec.js` Radicle leg, re-pointed at the service.

### Parity

| Item | Today | The service |
|---|---|---|
| start | `Embedded::start({ home, alias: 'FreedomBrowser', listen: [] })` in main | the same call, in the service, after reconciliation |
| key | `keys/radicle`, loaded in main | the same file, loaded in the service |
| read results | the add-on's JSON text | the same bytes, from the shared serializers |
| README | composed in main from `tree_at` and `blob_at` | composed in the service; the same bytes |
| errors | `{"error": message}`; 404 by message test, else 500 | the same bodies and statuses; a code alongside |
| clone progress | JSON strings through a ThreadsafeFunction | the same strings in `rad.progress` events, with failures beyond 8 folded into a summary |
| `cancelClone` | a token found by RID | `cancel` of that clone's request; the same timing |
| start-up network | `connectSeeds(15000)`, then the default-repository clone | the same |
| alias | `config.json` `node.alias` | the same file, rewritten under `hold-lock` |
| import | `git push` from the working copy, which gains a `rad` remote | an in-process fetch; the working copy is untouched |

### Gates

Measured against the add-on on linux-x64, macOS arm64 and win-x64:
- the median `rad:` metadata read (`repo_info` plus `tree_at` on the fixture) may be no more than 5 ms slower;
- the median time to the last byte of a 1 MiB text blob through `/blob/` may be no more than 10 ms slower.

### Rollback

- The add-on path stays selectable in dev builds (`FREEDOM_RADICLE_BACKEND=addon`) until the service ships in one stable release.
- While selected, the add-on runs under `hold-lock`. A build that doesn't take the lock is unsupported on the same home.
- Then the add-on, its fetch script and its `check-binaries.js` rule go.
- The home's format doesn't change, so rollback needs no migration.

## Bounds

| Budget | Bound | Exhausted |
|---|---|---|
| handshake; `rad.reconcile`; `rad.start` | 10 s; 300 s, checked between COBs; 30 s | kill; error, and the process exits (Retry continues from the checkpoints) |
| every repair unit | its work limit, and 30 s by an independent watchdog, at startup and online | exit 70 with the record kept; a unit in progress when two processes ended quarantines its repository |
| the writer during an online repair | one unit at a time, at most 30 s | other repositories' writes run between units |
| quarantine diagnostics | 16 entries in `rad.reconcile`'s reply; 64 per page of `rad.quarantine_list` | the next page |
| shutdown | the service exits within 5 s of `rad.shutdown`; main kills at 10 s | kill |
| exit after stdin EOF | 5 s, a watchdog thread | `std::process::exit` |
| lock contention | 5 s of retries, for the service, the core and `hold-lock` | exit 75; `lock_held` |
| restarts | 0.5 s, 2 s, 10 s; three crashes in 60 s | stop, and "Restart Radicle" |
| child processes | none | — |
| read pool | 4 threads, 320 queued; 60 s to the head, queue and reservation waits included | `busy`; `deadline` |
| network pool | 8 threads, 16 queued; `timeout_ms` + 30 s | `busy`; `deadline`, with the slot held until libradicle returns |
| write queue | 1 at a time, 16 queued; 60 s (300 s for import); the slot held until the call returns | `busy`; `outcome_unknown` once started |
| output budget | 256 MiB by reservation; a blob ≤ 64 MiB (128 MiB reserved while loading); a JSON read ≤ 64 MiB with ≤ 32 MiB of JSON | the read waits within its deadline; `too_large` per read |
| progress events | per clone, ≤ 10 unwritten of ≤ 4 KiB encoded, plus the terminal; failures past 8 are summarized | the summary grows its count, not its size; reasons are cut |
| streams | 0007's: a 128 KiB window, 64 KiB frames, one 128 KiB ring per stream in main | the service waits for credit |
| collected results in main | per call: 64 KiB, or 4 MiB for the lists; 16 MiB in all, held until the scope's callback settles, even after an abort | `too_large`; `busy` after 5 s |
| other callers in main | 64 outstanding, 64 waiting | `busy` |
| admission in main | shared with dweb fetches: 256 active, 512 waiting | 503 |
| health | `rad.stats` every 5 s; main's watchdog at 20 s | kill |
| heartwood internals | not bounded by the service ([Pools and budgets](#pools-and-budgets)) | an [open question](#open-questions) |

## Deviations

| ID | Today | After | Effect |
|---|---|---|---|
| `crash-domain` | the node runs in main | a separate process | a Radicle fault ends Radicle only |
| `auto-restart` | none | 0.5 s, 2 s, 10 s; three in 60 s stop | brief outages heal on their own |
| `home-lock` | the control-socket bind | an OS lock, taken by every Freedom writer before it touches the home | a second owner fails at start (75); the core never writes under a running node |
| `network-fs` | any filesystem | a network filesystem is refused (74) | Radicle doesn't start there |
| `failed-start` | handled in main's process | the process exits after replying | nothing of a failed start survives |
| `reconcile` | an interrupted write stays as it was left | a dirty marker; bounded, resumable repair units under a watchdog; an online repair after an uncertain write; a repository gate inside the node; quarantine for a repository that can't be repaired, until it is removed | writes are absent or complete after any interruption; a repository's COB reads answer 503 during its repair or quarantine; a quarantined repository isn't fetched |
| `control-socket` | `node/control.sock` is bound | none | the `rad` CLI can't attach to Freedom's node |
| `import-in-process` | `git push` from the working copy, which gains a `rad` remote | a libgit2 fetch; the working copy is untouched | no child process, and no git configuration from outside the service |
| `blob-api` | text as lossy JSON; binary dropped | `/raw/` with raw bytes, Range, length, ETag and inert types; `/blob/` unchanged | images and downloads work; the JSON endpoint is the same |
| `size-caps` | no limit | blobs ≤ 64 MiB, JSON ≤ 32 MiB, built data ≤ 64 MiB per read | 413 beyond |
| `rad-admission` | no admission or abort for `rad:` and `radapi:` | dweb admission; aborts cancel | 503 under extreme load; aborted reads stop |
| `read-deadline` | none | 60 s to the head | a read stuck before its head gets 504 |
| `read-concurrency` | reads serialized by one mutex | 4 concurrent | reads don't queue behind each other |
| `outcome-unknown` | a write that failed after starting reports its error | any started write that isn't proven is `outcome_unknown`, never retried | pages check before writing again |
| `progress-summary` | every progress event is delivered | failures beyond 8 fold into a summary; the terminal is reserved | the same outcome, fewer events in a burst |
| `device-key` | libradicle generates a random key on a profile without a vault | the core writes it, atomically and `0600`, under the gate | the service never generates a key |
| `stop-budget` | no Radicle budget | 10 s, then kill | quit can't wait on Radicle |
| `env` | the add-on inherits main's environment | cleared; `HOME` an empty directory; no git configuration | `RAD_*`, `SSH_AUTH_SOCK` and git configuration no longer apply |
| `proxy` | none | an optional SOCKS5 policy, names resolved through the proxy and checked, failing closed | new: Route Radicle through Tor |
| `address-policy` | none | untrusted private, loopback and link-local targets refused | configured local seeds still work |
| `address-families` | as `config.json` and the default features allow | IPv4, IPv6, DNS and onion; no I2P; every routing field set in memory | a conflicting `config.json` can't change routing |
| `health` | none | `rad.stats` every 5 s | a dead node is noticed and restarted |

## Implementation steps

1. **Tests first,** in freedom-browser: the contract suite, the fixture repository and golden vectors from the v0.8.0 add-on.
2. **Upstream:**
   - libradicle items 1–9;
   - heartwood items 10–14, on the `freedom/embed` fork.

   The service can start on items 1–4, 9, 10 and 13.
3. **The shared service skeleton,** from 0007: the lock, `hold-lock`, the handshake, parent death, the panic hook, hardening and the frame I/O.
4. **`services/freedom-radicled`:**
   - the dirty marker, `rad.reconcile` with its bound, the repair units and their watchdog, the online repair, the repository gate, quarantine and `rad.remove_repo`;
   - the pools, the output budget and bounded JSON construction;
   - `rad.read` and `rad.blob`, with ranges;
   - network operations with bounded progress and cancel;
   - the write queue with the mutation-start boundary, and the in-process import;
   - `rad.stats`;
   - the test hooks and the Rust tests.
5. **Release:** five targets, `SHA256SUMS`, attestations and notices (libgit2's included), on `radicled-v*` tags, in separate build jobs.
6. **freedom-core:**
   - `nodes.write_identity` for Radicle takes the home gate and gains `wipe`;
   - the core's recovery paths take the gate;
   - a random device key for profiles without a vault.
7. **freedom-browser:**
   - `radicle-embedded.js` on the service, behind `FREEDOM_RADICLE_BACKEND` in dev, with `callStream` and `callScoped`;
   - admission and cancel for `rad:` and `radapi:`;
   - the limits for other callers;
   - private partitions read-only;
   - the identity change through the core, and `hold-lock` for the alias and profile removal;
   - the contract suite against the binary, the gates;
   - then the default switches.
8. **The raw endpoint** and the viewer's images and downloads.
9. **Network policy:** the setting, Arti's endpoint and its `RESOLVE` qualification, and the SOCKS, canary, address-policy and family tests.
10. **Removal,** one stable release later.

## Open questions

1. **Where the code lives:** a separate workspace here (recommended), upstream libradicle, or a new repository (the user's decision).
2. **Key custody:** keep the key file (this design), or move to a sealed host key with no file at rest? The latter needs a new exception to rule 3, and an unlocked vault for every start (the user's decision).
3. **AGENTS.md, a prerequisite to the custody choice:** should rules 3 and 4 name node identities: 0001's node identity writes (Bee and Radicle), and keys that outlive a vault lock? (The user's decision.)
4. **The device key:** this design has the core write the random key on profiles without a vault. Is a device identity that isn't derived from the wallet still wanted there, or should Radicle require a vault?
5. **The control socket:** is it acceptable that the `rad` CLI can no longer attach to Freedom's node, or should a developer setting keep it?
6. **The raw endpoint for pages:** is the inert-type allowlist right? Should pages get `/raw/` at all, or only the viewer?
7. **Caps:** are 64 MiB per blob, 32 MiB per JSON result and 64 MiB of built data per read right?
8. **The address policy:** are these the right ranges, and is the exact-address exemption for configured seeds enough for LAN setups?
9. **One Tor switch:** should Route Radicle through Tor and 0007's Route IPFS through Tor be one setting?
10. **heartwood's memory:** should the service run under an OS-level limit (`RLIMIT_AS`, or a Windows job memory limit), given that heartwood's own buffers aren't bounded by the service?
11. **Private windows:** is read-only the right rule for private partitions, or should an explicit, user-initiated seed be allowed there?
