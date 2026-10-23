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
  - the seeding policies.

  It no longer holds the node's key ([Keys](#keys)). So the service reconciles interrupted writes under the lock before it reports `RUNNING`, and a write that has started is either proven, or reported as **outcome unknown**.
- **The blob API (0006's requirement):** `rad.blob` returns a blob's **raw bytes**, **chunked** over 0007's stream frames, with an optional **byte range**.
  - The existing JSON endpoint stays byte-identical.
  - A new `rad:` endpoint, `/raw/<rev>/<path>`, serves the bytes themselves, with Range, under conservative headers.
- **Bounded, cancellable reads:**
  - `rad:` and `radapi:` take main's dweb admission, and a page's abort reaches the service.
  - Reads run on a bounded pool, with no process-wide mutex.
  - JSON results are reserved as they are built and stopped at a cap.
  - Main **streams** them to handlers. Only small results are collected, under their own budget.
- **Keys** (the user's decision, 2026-10-22, [Keys](#keys)):
  - The service holds one secret: the user's Radicle node key, which heartwood needs for every connection and signature. It is a separate identity, not a wallet key, and not a cache that a vault lock wipes.
  - **No file holds it.** On a profile with a vault, the core releases the derived key at each start, sealed (HPKE) to a key the service makes for that start. Main relays only ciphertext.
  - So a start needs the vault unlocked until the core releases the key, every restart included. After that release, a lock stops neither the start nor the node.
  - A profile without a vault runs its node with a throwaway key, made in memory at each start and never written. It reads and browses, with no lasting identity.
- **Network policy:**
  - heartwood's SOCKS5 proxy and onion settings are set in memory, `direct` or `socks5` through Arti, with every other routing field overridden.
  - Names are resolved, checked and pinned, as in 0007's SOCKS contract.
  - An address policy covers addresses learned from peers.
  - The node listens on nothing: no inbound port, and, after an upstream change, no control socket.
- **Private windows** read the profile's node, as today. A private read sends nothing, signs nothing, writes nothing and records nothing. Private partitions can't seed, sync or write.
- **The code goes beside 0007's,** as `services/freedom-radicled` in its own Cargo workspace (the user's decision, 2026-10-22). Moving it to a new repository later would be a new decision.
- **Tests come first:**
  - a contract suite over the add-on's 30 exports;
  - golden JSON recorded from v0.8.0 on a fixture repository, which the service must reproduce byte for byte.

## Goals and non-goals

**Goals**
- **Crash isolation:** no Radicle fault can end main. A crashed service restarts with back-off.
- **Parity:**
  - the same `Embedded` calls, with `start_with_key` in place of `start`, the same Radicle home, and the same identity on a profile with a vault;
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
- **Honest key custody:** no key at rest. The key's holders, sources and route are stated, with what sealing protects and what it doesn't.

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

  The service checks it before anything else, since a process that could have threads can't safely change its environment: it refuses to start (64) with any `RAD_*`, `GIT_*`, `SSH_AUTH_SOCK`, `LISTEN_*` or `XDG_CONFIG_HOME` set, or without `HOME` as an absolute directory.
- **Handshake:** `rad.hello` within 10 s, as 0001. Its reply carries the X25519 public key the service made for this start ([The sealed release](#the-sealed-release)).
- **The lock:** `<lock-dir>/radicle-<sha256(canonical home)>.lock`, under 0001's rules, which also cover the canonical path, the stable lock directory, network filesystems and bind mounts.
  - Contention retries for 5 s, then exits 75. Other errors and network filesystems exit 74.
  - **It is taken before anything opens the home.** heartwood's own exclusion is the control-socket bind, which comes after its threads have started (`hw/radicle-node/src/runtime.rs:202`–`249`).
- **Every Freedom writer of Radicle files takes this gate:**
  - the service;
  - `hold-lock`;
  - the core, in every path of 0001's node identity protocol that touches Radicle files: `nodes.write_identity` (the [switch](#the-switch) included), its startup recovery before `core.hello`, the `recover` subcommand, and the retries after `pending_recovery` ([Identity changes](#identity-changes)).

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
  3. **`rad.identity`:** the node key arrives, sealed by the core, or, on a profile without a vault, the service makes a throwaway key ([Keys](#keys)). On a profile with a vault, a start while the vault is locked waits in main, before the spawn ([When the node can start](#when-the-node-can-start));
  4. **`rad.reconcile`,** a phase of its own, with its own deadline ([Reconciliation](#reconciliation)). Its reply is the boundary main can see: the home is consistent;
  5. `rad.start`, which runs `Embedded::start_with_key` with today's options, the [network policy](#network-policy) and the key from `rad.identity`, and returns `{ did, nid, alias }`;
  6. `RUNNING`;
  7. main runs today's background `rad.connect_seeds` and default-repository `rad.clone`.

  Until `RUNNING`, every other request gets `stopped`.
- **A failed start ends the process.**
  - libradicle can fail after heartwood's threads have started (`lr:777`). Those threads hold each other alive.
  - So the service answers with the error and then exits: `key_file_present`, `bad_sealed_key` or `no_identity` from `rad.identity`; `recovery_failed` or `deadline` from `rad.reconcile`; `start_failed` or `key_file_present` from `rad.start`. Main shows the error and doesn't restart, as a failed start is handled today. The one exception is `key_file_present`: main runs the [switch](#the-switch), then starts once more.
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
- **It names the writers.** It holds the node IDs (public keys, so public data) of every identity that may have left a partial mutation:
  - `rad.reconcile` adds the running identity's before it changes anything;
  - an earlier identity stays named until its namespace has been checked, whatever key later processes run with. Its vault may have been deleted or replaced since. The [switch](#the-switch) names the identity whose key file it removes in the same way;
  - once every earlier identity's namespace is checked or its repository quarantined, `rad.reconcile` rewrites the marker durably to name only the running identity, before it replies.
- **It is kept after anything that may be partial:** a write that ends `outcome_unknown`, or a clone or fetch that is cancelled or cut off.
- **It is cleared only after a proven clean stop.** At `rad.shutdown`, it is removed (durably) only when all of these hold:
  - the write queue is empty, and the executing writer, if any, has returned;
  - every write that ended `outcome_unknown` this run has had its repository repaired or quarantined since ([Writes](#writes));
  - `Embedded::shutdown` has returned, so heartwood's workers have finished their fetches.

  A shutdown with a timed-out writer still running, or one that reaches the 5 s exit, leaves the marker.
- **What it selects:** with the marker present at start, the checks of the namespaces it names and the cache rebuild run. Temporary clones and ref lock files are handled on every start.

- **Temporary clones:**
  - **What is recognized:** directories directly under `storage/` named `<RID>.tmp`, which is heartwood's `TempRepository` format (`hw/radicle/src/storage/git/temp.rs`: `<rid>.<random>` with its extension replaced by `tmp`), and the legacy `<RID>.lock`, where `<RID>` parses as a repository ID.
  - **How they are removed:** after an `lstat` shows a real directory, not a symlink, with a delete that follows no symlinks.
  - Any other name with an extension is left alone and counted.
- **Ref lock files:**
  - **What is recognized:** regular files named `*.lock` under a repository's `refs/`, plus `packed-refs.lock`, `HEAD.lock` and `config.lock` at its root.
  - A lock file is an update that never committed, so its ref keeps its old value. It is removed, with no symlinks followed.
- **The namespaces the marker names,** in every repository, when the marker was present. Each one's refs are checked against its `rad/sigrefs`:
  - **The running identity's own:** if refs advanced without a matching signature (a kill between the ref and the signing), the namespace is re-signed over its current refs, with the node's key, which `rad.identity` has delivered by then. The refs were written by this node. The repository is queued for a refs announcement once the node runs.
  - **An earlier identity's,** whose key this process doesn't hold: checked the same way, and never signed. Refs that don't match its `rad/sigrefs` quarantine the repository as `namespace`, with every byte kept ([the escape](#the-escape)). Nothing recovers that key or writes a key file, and nothing signs that namespace with the running key.
  - A throwaway key owns no namespace, since it never writes ([Profiles without a vault](#profiles-without-a-vault)), so its own check finds nothing.
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
| checking one named namespace against its `rad/sigrefs` | 1,024 refs; a larger namespace takes several units, each with a checkpoint | 30 s |
| re-signing the running identity's namespace | one ref update, flushed, with libgit2's fsync option on | 30 s |
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
  - **And to the signing authority:** each namespace check's checkpoint names the namespace it checks (its node ID), that namespace's input version (a hash over its refs), and the signing authority that applies: the namespace's own identity when the running key is that identity, and otherwise none.
    - A resumed check keeps its checkpoint while all three are unchanged, whatever the running key. So successive throwaway keys, none of which can sign A's namespace, each continue A's read-only check where the last one stopped.
    - It starts that namespace over only when its input version or the authority changes: A's key arrives, or A's key goes. A retry alone never changes either.
    - A namespace is never signed with any key but its own.
  - **Online,** a repository's progress rows are deleted in its publication transaction. So a completed repair can't be reused once later mutations begin.
- **Before `RUNNING`:** once every repository is done or quarantined, the progress state is cleared in one durable transaction, before `rad.reconcile` replies. No completion record survives into a run whose new mutations could make it wrong.

#### The deadline

- `rad.reconcile` has 300 s from admission, owned by the service. Main's watchdog is at 315 s: 0001's deadline plus 15 s.
- It is checked between units: between batches, between COBs within a batch, and between namespace checks.
- **No unit starts after 240 s.** That reserves the worst case after the cutoff: one unit already running (at most 30 s) and the partial batch's commit (one unit, at most 30 s). So the reply is sent by 300 s, before main's watchdog at 315 s.
- At the cutoff, the service does all of these:
  - lets the current unit finish;
  - commits the partial batch with its checkpoint;
  - keeps the marker and the progress state;
  - answers `deadline`.
- **A cutoff is not an overrun.** `deadline` is a normal reply, and Retry continues. A unit that exceeds its own 30 s is a [unit overrun](#the-unit-watchdog): the process ends with 70, and the next attempt treats that unit as interrupted.
- Main shows "Radicle is still repairing its data" with **Retry**. A retry spawns a new process, which continues from the checkpoints, with a new throwaway key too ([the progress state](#work-units)). There is no automatic restart loop.
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
  - **`namespace`:** a namespace the marker names doesn't verify and can't be re-signed: for example an owned ref that points at a missing object, or an earlier identity's refs that its `rad/sigrefs` doesn't sign.
- **The record:** a quarantine is recorded durably, in a `quarantine` table that outlives the run, before anything else resumes:
  - at a start, before `rad.reconcile` replies;
  - online, before the writer takes its next task.

  It stays on disk, untouched beyond its staging, and the [repository gate](#the-repository-gate) shuts it.
- **Unseed doesn't clear it:**
  - Unseeding changes the seeding policy, not the record. While `storage/<rid>` exists, the record stays and the gate stays shut. A later seed or clone of the same repository is refused with `quarantined`.
  - **Remove** (`rad.remove_repo`) is the only way out, and only for a quarantined repository.
    - **Each record has its own `qid`,** a random 128-bit ID created with the record. Every quarantine entry carries it, and main passes back the `qid` of the entry the user saw in the warning.
    - **The precondition:** when the writer starts the removal, it checks under the repository gate that the record for `rid` exists and has that `qid`. If the record is missing or has another `qid`, nothing is deleted, and the answer is `not_quarantined`. A delayed or duplicate removal can therefore never act on a repository that was cloned again after an earlier removal.
    - It then does these in order, durably, with the gate shut throughout:
      1. unseeds the repository;
      2. deletes `storage/<rid>`, following no symlinks;
      3. deletes the repository's cache rows;
      4. clears the record.
    - **Partial failure or cancel:** the record, and its `qid`, stay until step 4. A retry with the same `qid` repeats the steps, each of which is idempotent.

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
  - The node and its policy are re-read from the home, after reconciliation. Its key arrives again through `rad.identity`: sealed anew, so on a profile with a vault a restart waits for an unlock ([When the node can start](#when-the-node-can-start)), or a new throwaway key.
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
| `rad.hello` | `protocol`, `shell_version`, `frames` | `protocol`, `service_version`, `libradicle` build info, `recipient` (the service's X25519 public key for this start, base64) | 10 s after spawn |
| `rad.identity` | `sealed: { enc, ciphertext }` from the core's `nodes.seal_radicle_key`, or `ephemeral: true` on a profile without a vault | `{ did, nid, ephemeral }` | inline; within 30 s of `rad.hello`'s reply; once per process; on failure, the process exits ([Keys](#the-sealed-release)) |
| `rad.reconcile` | none | `{ was_dirty, repaired, quarantined: { count, first } }`: counts per step, and up to 16 quarantine entries | 300 s ([the bound](#reconciliation)); on failure or deadline, the process exits |
| `rad.quarantine_list` | `page` | `{ entries, next_page }`: up to 64 entries `{ rid, qid, kind, step, unit, since }` per page | read pool; 60 s |
| `rad.remove_repo` | `rid`, `qid` | `{ removed }`, or `not_quarantined` when no record with that `qid` exists ([the escape](#the-escape)) | write queue; 60 s |
| `rad.start` | `alias`, `network` | `did`, `nid`, `alias`; the node runs as the key from `rad.identity` | 30 s; on failure, the process exits |
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
| `key_file_present` | `rad.identity` or `rad.start`: something exists at `keys/radicle` ([The switch](#the-switch)) | main runs the switch and starts again, once; then the manager's error state |
| `bad_sealed_key` | `rad.identity`: the ciphertext doesn't open with this process's key, or doesn't hold 32 bytes | the manager's error state |
| `no_identity` | `rad.reconcile` or `rad.start` before `rad.identity` succeeded | the manager's error state |
| `start_failed` | `rad.start`; `message` is libradicle's | the manager's error state, with that message |
| `needs_vault` | a COB write or `rad.import_repo` on a node with a throwaway key ([Profiles without a vault](#profiles-without-a-vault)) | refused in main before anything is sent; the provider's existing errors |

Exit codes:
- 0001's: 64, 74, 75 and 76;
- 70 for `node_down`, or a panic outside a request;
- 0 after a start step the service answered with an error (`rad.identity`, `rad.reconcile`, `rad.start`): main has read the error, and doesn't restart.

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
    - validation errors (`invalid_argument`), a full queue (`busy`), and a write on a node with a throwaway key (`needs_vault`);
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

**Decided (the user, 2026-10-22): a host key with no file at rest, and a vault for a lasting identity** ([Open questions](#open-questions), 2–4). The options the user weighed are kept at the end of this section, as the reasons for that choice.

**What the service holds:**
- **One secret: the user's Radicle node key,** an Ed25519 key.
- heartwood holds it in memory for the node's lifetime, in several clones that each zeroize on drop. It needs it continuously:
  - as the Noise XK static key of every peer connection (the node ID is its public key);
  - to sign node, inventory and refs announcements, `rad/sigrefs`, COB changes, and identity documents on import.
- **It survives a vault lock.**
  - Once the core has released the key, a lock stops neither the rest of the start nor the node, which keeps running, and signing, as it does today. Only the next start needs the vault again ([When the node can start](#when-the-node-can-start)).
  - The key isn't a derived-key cache of the kind AGENTS.md rule 4 has wiped by every lock. It is a node identity with its own lifetime, like Bee's.
- **Until the key arrives,** the service also holds an X25519 key pair of its own, made for that one start ([The sealed release](#the-sealed-release)).
- The service holds no wallet key, no recovery phrase and no vault data, and has no connection to the core.

**Where the key comes from:**
- **No file holds it.** The service starts the node only with `Embedded::start_with_key` (`lr:744`), which keeps the key in memory and writes nothing secret: the profile gets the public key, in memory, and `keys/` isn't touched (`lr:615`). The service never calls `Embedded::start`, which loads `keys/radicle` or generates it (`lr:698`–`726`).
- **On a profile with a vault:** the key derived from the vault seed at `m/44'/73404'/0'/0'/0'` (SLIP-0010), which the core releases sealed, at each start ([The sealed release](#the-sealed-release)).
  - Ed25519 derivation is hardened at every level, and the release carries no chain code, so the key leads to neither the seed nor any other derived key.
  - It does let anyone holding it act as the user's Radicle identity, which is derived from the wallet and can't be rotated without a new derivation path.
- **On a profile without one:** a throwaway key, which the service makes in memory at each start ([Profiles without a vault](#profiles-without-a-vault)).
- **The core writes no Radicle key:** no derived key file, and no random device key. `nodes.write_identity`'s Radicle form writes no key file at all ([Identity changes](#identity-changes)).

### The sealed release

**`nodes.seal_radicle_key`,** a new core method:

| | |
|---|---|
| Params | `{ recipient }`: the service's X25519 public key for this start (32 bytes, base64), as `rad.hello` returned it |
| Result | `{ enc, ciphertext }`, base64: HPKE's encapsulated key (32 bytes), and the sealed key with its tag (48 bytes) |
| Plaintext | the 32-byte Ed25519 secret seed (RFC 8032) at `m/44'/73404'/0'/0'/0'`: the bytes libradicle's `HostKey` takes (`lr:654`). Never a chain code, the seed, or any other key |
| Sealing | HPKE (RFC 9180), base mode, single-shot: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM (IDs `0x0020`, `0x0001`, `0x0002`). `info` is `freedom-radicle-node-key/1`; `aad` is empty |
| Callers | `shell` only, like 0001's other main-only methods. No renderer channel reaches it |
| Errors | `no_vault`; `vault_locked`; `invalid_argument` for a recipient that isn't 32 bytes, or that gives HPKE's all-zero shared secret; 0001's protocol errors |

- **It requires an unlocked vault, and refuses otherwise:**
  - **no vault:** `no_vault`. That is the only answer that leads main to a throwaway key;
  - **locked:** `vault_locked`;
  - **a lock while it runs:** it is admitted against the current epoch, as 0001's derivations are, so a result from a revoked epoch is wiped and answers `vault_locked`. The epoch is checked when the reply is handed to the core's writer. A reply handed over isn't recalled (0001), and that handoff is the start's boundary ([When the node can start](#when-the-node-can-start)).
- **One key only:** no parameter selects another path or another node's key.
- The core derives the key into a zeroizing buffer, seals it, and wipes it. It logs the method, never the recipient or the ciphertext.

**The service's side:**
- At spawn, after the lock, the service makes an X25519 key pair from the OS's randomness. The private half lives in zeroizing memory. `rad.hello`'s reply carries the public half as `recipient`.
- **`rad.identity { sealed: { enc, ciphertext } }`:**
  1. It checks `keys/radicle` first ([The switch](#the-switch)).
  2. It opens the ciphertext with its private half. The plaintext must be 32 bytes, and goes straight into a `HostKey`, which zeroes its input (`lr:659`).
  3. It wipes the private half after this one attempt, whether the ciphertext opened or not. So a ciphertext opens in one process, once, and one captured from an earlier start opens nowhere.
  4. It replies `{ did, nid, ephemeral: false }`.
- **Failures end the process:**
  - a ciphertext that doesn't open, or doesn't hold 32 bytes: `bad_sealed_key`;
  - a second `rad.identity`: `invalid_argument`;
  - `rad.reconcile` or `rad.start` before `rad.identity` has succeeded: `no_identity`;
  - no `rad.identity` within 30 s of `rad.hello`'s reply: the service exits.
- **The key in the service:** reconciliation signs with it ([Reconciliation](#reconciliation)). Then `rad.start` hands it to `start_with_key`, and the service keeps no copy of its own.

**A start, end to end:**
1. Main spawns the service, and `rad.hello` returns `recipient`.
2. Main asks the core for `nodes.seal_radicle_key { recipient }`, and passes the reply on in `rad.identity`.
3. `rad.reconcile`, then `rad.start` ([Start](#start-stop-and-reconciliation)).

Main sees the recipient, `enc` and the ciphertext, and never the key.

### The switch

- **The core deletes any plaintext `keys/radicle`** under the home gate, as a journaled step of `nodes.write_identity`'s Radicle form ([Identity changes](#identity-changes)). It removes `keys/radicle.pub` with it, which names an identity the node may no longer run as, and which nothing reads now ([Main's side](#mains-side)). The step writes no key, so it needs no vault.
- **Why:** `start_with_key` leaves an old key file in place (`lr:744` documents that), and a later `start` would bring that identity back. Every home from before this design has one: the derived key the core wrote, or the random key libradicle generated.
- **When:** main runs it when the service refuses with `key_file_present`, then starts again, once.
- **The old identity stays checked.** The add-on leaves no dirty marker, so nothing records whether it stopped in the middle of a write. The switch therefore adds the old identity's node ID to `node/dirty` ([the dirty marker](#reconciliation)):
  - It reads the node ID from the key file's public part (an OpenSSH private key file carries its public key in the clear), or from `keys/radicle.pub`. It never needs the secret part.
  - So the first start after the switch runs the full reconciliation once, and checks that identity's namespace in every repository, whatever key the start runs with. The core's derived key is the same identity, and re-signs. Any other key quarantines a namespace that doesn't verify ([Reconciliation](#reconciliation)).
  - If neither file yields a public key, the switch answers `node_identity_corrupt` and touches nothing. Only an identity change with `wipe`, which leaves nothing to check, removes such a file.
- **The journal:** the marker and the removals are recorded before anything is removed, and the marker is installed first. Recovery repeats each step, and a file that's already gone counts as done. So a crash at any point leaves either the key file, which the next start refuses, or no key file and a marker that names the old identity.
- **What it ends:** on a home whose key libradicle generated, the switch ends that identity. What it published stays, signed, but no Freedom node can act as it again. A key the core derived stays the profile's identity for as long as the profile keeps that vault, since the sealed key is the same key.
- **No fallback:**
  - The service starts the node only with `start_with_key`.
  - It refuses to start while anything exists at `keys/radicle`, as `lstat` sees it (a file, or a symlink, even a dangling one). `rad.identity` checks before it opens anything, and `rad.start` checks again just before `start_with_key`. Either answers `key_file_present`, and the process exits.
  - It never falls back to a file or a generated key. It makes a throwaway key only when main asks for one on a profile without a vault ([below](#profiles-without-a-vault)), never because a sealed key is missing, locked, or doesn't open.

### When the node can start

- **On a profile with a vault, every start needs it unlocked until the key is released:** the start at launch, a restart after a crash, and the restart that a policy change causes, such as Route Radicle through Tor.
- **The boundary is the key's release.** A start owns its identity from the moment the core hands its seal reply to its writer, after the epoch check ([The sealed release](#the-sealed-release)).
  - **Before it,** a lock ends the start. The core answers `vault_locked` and returns nothing, main shuts the process down, and the start waits as below.
  - **From then on,** a lock stops nothing: not the reply on its way to main, nor `rad.identity`, `rad.reconcile` (up to its 300 s), `rad.start`, or the run. Main completes the start whatever the vault does, and the node keeps the key as a running node does.
- **A start while the vault is locked waits, in main.**
  - Main doesn't spawn the service. Radicle's status says it is waiting for the unlock, and main starts it on the core's `vault.unlocked` event.
  - A crash restart that comes due while the vault is locked waits too. The wait doesn't count as a crash.
- **The service never waits for a key.** Without one, it exits. So a waiting start holds no gate on the home, and profile removal, `radicle:reset` and identity changes stay possible.
- **Once running, the node keeps running** across every lock, manual or automatic, until it stops, crashes, or its policy changes.
- **The cost, which the user accepted:** after a launch, Radicle is down until the first unlock. A crash or a policy change while the vault is locked takes it down until the next one.

### Profiles without a vault

- **Radicle needs a vault for a lasting identity.** A profile without one gets no stored key.
- **Its node runs with a throwaway Ed25519 key:**
  - on `rad.identity { ephemeral: true }`, the service checks `keys/radicle` first, then fills a `HostKey` with 32 bytes from the OS's randomness, and replies `{ did, nid, ephemeral: true }`. `rad.start` runs `start_with_key` with it, as with a sealed key;
  - the key is made in memory at each start and never written to a file. Nothing secret is stored;
  - so each start is a new node ID to peers. A new throwaway key resets no repair checkpoint, since none can sign an earlier identity's namespace ([Work units](#work-units)).
- **Main asks for it only on the core's `no_vault`,** never while the vault is locked, and never after another error. The service can't tell a profile without a vault from a main that asks for a throwaway key anyway: under 0001's threat model, main is trusted to choose.
- **Reading and browsing, with no identity of its own:**
  - reads, clones, seeding and syncing work as on any profile;
  - **a generation with a throwaway key can't publish under an identity of its own.** COB writes and the import answer `needs_vault`. Main refuses them before anything is sent, by the running generation's identity ([Main's side](#mains-side)), and the service refuses them again. A throwaway identity's writes couldn't be edited after the next start, and reconciliation, which signs only with the running key, couldn't repair them.
- **The vault changes the identity only at a start.**
  - **Creating a vault** gives the profile its derived identity at the next start. Until then, the running throwaway generation keeps its identity, and writes stay refused.
  - **Deleting the vault** leaves a node that runs as the derived identity as it is, writes included: it keeps its key, as across a lock, until it stops. Its next start uses a throwaway key.

### What sealing protects

- **Only the relay through main,** meaning main's heap and logs.
- The core and the service still hold the key in plaintext, so their swap and memory dumps are covered only by 0001's hardening.
- A compromised main can still ask for the key sealed to a key of its own.

**What having no file adds:** the key isn't on disk, so a copy of the home, a backup of it, or a program reading it carries no Radicle key. Swap, above, is the exception.

**What changes:**
- The add-on loads the key into main's process today, from a file. After this design only the service holds it, under 0001's process hardening, and no file holds it at rest. Main never holds it.

### How this fits AGENTS.md

- **Rule 3** ("No raw private key or seed leaves the core"):
  - `nodes.seal_radicle_key` releases a node key, sealed. That is a new exception, and this design is the design change it needs. AGENTS.md rule 3 is amended to match (#120): it names this release, and no other node key may be released.
  - The core no longer writes the Radicle key to a file, so rule 3 has no Radicle file exception.
- **Rule 4:**
  - Secret files are atomic and `0600`: the Radicle key has no file now.
  - The lock-wipes-caches rule doesn't cover a node identity that outlives a lock, as above. AGENTS.md says so (#120).

### The options the user weighed

1. **The key file (today's behavior):** not chosen. It needed no new release from the core, and the node started at launch without an unlock, but an unencrypted key stayed at rest.
2. **A host key with no file at rest:** chosen, as above. libradicle v0.8.0 already has `Embedded::start_with_key`, which UniFFI exposes and the add-on doesn't.
3. **Signing in the core:** rejected.
   - The Noise handshake needs the secret for every connection, and heartwood copies it into its reactor and sessions.
   - The core would have to serve network handshakes on demand.

**For profiles without a vault,** the core writing a random device key was not chosen either: a lasting identity needs a vault.

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
- **The start brings the key** ([Keys](#keys)):
  - after `rad.hello`, main asks the core for `nodes.seal_radicle_key` and passes the reply on in `rad.identity`. On the core's `no_vault` it sends `{ ephemeral: true }` instead;
  - on a profile with a vault, main spawns the service only while the vault is unlocked, and otherwise starts it on `vault.unlocked` ([When the node can start](#when-the-node-can-start));
  - a `vault_locked` answer ends the start. Once the seal reply has arrived, main completes the start whatever the vault does;
  - on `key_file_present`, main runs the [switch](#the-switch), then starts again, once.
- **The active identity belongs to the generation:**
  - `rad.identity`'s reply, `{ did, nid, ephemeral }`, is the running node's identity. Main keeps it with the generation, and drops it with the generation.
  - It alone gives the DID main shows for the node, and it alone decides write admission. While the generation is `ephemeral`, main refuses COB writes and `importRepo` before anything is sent (`needs_vault`); otherwise it admits them. Whether the profile has a vault now doesn't enter into it. Reads, seeding, cloning and syncing work in either mode.
  - **Creating, locking, unlocking or deleting the vault** changes neither while the generation runs ([Profiles without a vault](#profiles-without-a-vault)).
- **The next start's identity is a separate value:** the derived DID from `keys.addresses` while the vault is unlocked, or none. Main may show it as the identity Radicle will use at its next start, never as the running node's. With no generation running, there is no active identity.
- **Main no longer reads `keys/`:** `isRadicleIdentityInjected` (whether `keys/radicle` exists) and `readRadicleDid` (which reads `keys/radicle.pub`) go. The file never exists now, so nothing may read its absence as an identity never written.

### Identity changes

One owner holds the home gate at each step, and no step waits on a gate that its own caller holds:

1. **Main stops the service.** The process exits, and its gate is free, since it starts no child.
2. **The core takes the gate for the whole identity change.**
   - `nodes.write_identity { node: "radicle", home, alias, wipe: true }`. It extends 0001's journaled multi-file write, and writes no key file: the Radicle key is never written ([Keys](#keys)). It needs no vault.
   - It stages the config, then commits the journal, which records the wipe and the removal of `keys/radicle` and `keys/radicle.pub`. It then wipes `node/`, `cobs/` and `storage/`, removes the key files, installs the config, and finishes.
   - Recovery of such a journal repeats the wipe and the removals, which are idempotent, and then the install. All of this is under the same gate.
   - The wipe moves from main into the core, so main never holds `hold-lock` while the core needs the gate.
   - **The [switch](#the-switch)** is the same call without `wipe`. It also stages `node/dirty` with the old identity's node ID. With `wipe`, nothing is left to check, and no marker is written.
3. **Main starts the service** only on `installed` (0001: "Main starts a node only on `installed`"). The new process gets its key through `rad.identity`, then reconciles under the gate before `RUNNING`.

- **When:** an identity change is one that main starts on purpose, as onboarding's forced re-injection does today when a profile's nodes already had identities. The derived identity itself needs no write, since it arrives sealed at each start. So creating a vault on a profile whose node ran with throwaway keys needs no identity change: that node owned nothing ([Profiles without a vault](#profiles-without-a-vault)).

- **Contention:** if the gate is held, for example by a running service that main didn't stop, `nodes.write_identity` retries for 5 s, then answers `lock_held` and touches nothing.
- **The core's own recovery:** startup recovery before `core.hello`, and `recover`, take the gate per Radicle journal in the same way. If the gate is held, the journal is left in place, and the core reports `pending_recovery` for Radicle without blocking `core.hello`. Main keeps the service stopped and retries, as 0001 already requires.
- **Lock order:** the core's own lifetime lock, then the Radicle home gate. The service and `hold-lock` take only the home gate, so no cycle exists.
- **The alias rewrite** runs under `hold-lock` alone, with the service stopped. The core isn't involved.

## Private windows

- **No node of their own.** `rad:` reads touch only local storage, and a read never starts a network fetch.
- **Whatever key the node runs with:** private windows read the profile's node, whether it runs with the vault's key or, on a profile without a vault, with a throwaway key ([Keys](#profiles-without-a-vault)). A read signs nothing, so the key plays no part in it.
- **Only while the node runs:** on a profile with a vault, the node starts only after an unlock ([When the node can start](#when-the-node-can-start)). Until then, private reads answer `stopped` (503), as other windows' do.
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
- **The setting:** a per-profile **Route Radicle through Tor**, off by default, using `tor-manager`'s endpoint. It is a switch of its own, apart from 0007's IPFS setting; a future "everything through Tor" mode would turn both on ([Open questions](#open-questions), 9).
- **Changing the policy restarts the process.** Nothing of the old policy survives its process, since there is no child. On a profile with a vault, the new process starts only while the vault is unlocked ([When the node can start](#when-the-node-can-start)).

### The address policy

- **Untrusted targets** are addresses learned from peers: node announcements and the address book they fill.
- **Configured targets** are the shipped seed book, `preferredSeeds` and `connect` in `config.json`, and Arti's endpoint.
- **In both modes**, untrusted targets follow 0007's rule ([Addresses](0007-ipfs-service.md#addresses)):
  - only a globally reachable unicast address passes. Loopback, private, link-local, shared (CGNAT), multicast, broadcast, documentation, benchmarking and reserved ranges are refused;
  - an IPv6 form that embeds an IPv4 address (mapped, NAT64, 6to4, ISATAP) is judged by that address, and the forms 0007 refuses whole stay refused;
  - in `direct` mode the service learns the network's NAT64 prefixes as 0007 does, refuses IPv6 outside the fixed forms while it can't, and has the same limits ([What the gate can't see](0007-ipfs-service.md#what-the-gate-cant-see));
  - one table and one classifier serve both services.
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
   - add `proxy: Option<SocketAddr>`, `onion: AddressConfig`, `control_socket: bool`, a resolver hook and an address policy;
   - `run` (`lr:757`–`793`) applies them to `profile.config.node` before `Runtime::init`, overriding every routing field and `externalAddresses`;
   - nothing is written to `config.json`.
2. **Node health:** `Embedded::node_alive()`, from the node thread's `JoinHandle::is_finished` (`lr:684`, `lr:781`).
3. **No key generation at start: no change needed** since the custody decision ([Keys](#keys)).
   - The service calls only `start_with_key` (`lr:744`), which generates no key and writes nothing secret.
   - So it never reaches `start`'s key generation (`lr:700`–`720`) or its `expect` (`lr:706`).
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
    - validation of every namespace the marker names, and re-signing of the running identity's, with a signer the host passes in (the key from `rad.identity`), since the node isn't running yet. A namespace whose node ID isn't the signer's is never signed;
    - a COB cache rebuild in batches into a staging table, with durable checkpoints and atomic publication;
    - progress state written in the same transactions as the work, bound to each repository's input version and to each namespace check's signing authority, with an in-progress record for every unit;
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

**Decided (the user, 2026-10-22): the first option,** as for 0007. The others are kept as the reasons for that choice.

1. **This repository, `services/freedom-radicled`, its own Cargo workspace** (chosen):
   - it shares `fc-protocol` and 0007's service skeleton;
   - it has its own lockfile and `deny.toml`. libradicle's lockfile, which also covers its add-on and UniFFI bindings, has 453 packages, including vendored libgit2 (C; GPL-2.0 with a linking exception, which the notices must carry) and bundled SQLite;
   - heartwood comes from `solardev-xyz/heartwood`, which `deny.toml`'s organization allowlist covers.
2. **A member of the core's workspace:** rejected, for 0007's reasons.
3. **Upstream libradicle,** as a binary beside `napi/` and `uniffi/`.
   - **For:** the closest home.
   - **Against:** the frame protocol, lock and supervision contract are Freedom's, and this repository's lack of a license blocks depending on `fc-protocol`.
4. **A new repository:** not chosen. Moving later would be a new decision.

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
  - **a healthy unit near the cutoff:** a unit starting at 239 s and taking 29 s, then the partial batch's commit. The reply is `deadline` before 300 s, main doesn't kill, and the retry treats nothing as interrupted;
  - **removal bound to its record:** remove quarantine A, clone the same RID again and add local work, then deliver A's delayed removal. It answers `not_quarantined`, and the new data survives. A cancel or failure between each pair of removal steps keeps the record, and a retry with the same `qid` completes;
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
  - stop → wipe and key-file removal by the core → restart, including a failed write; no key file is written;
  - with an independently running service holding the gate: `lock_held`, and no file touched;
  - core recovery while the gate is held: `pending_recovery`, then completion once the service stops.
- **Keys:**
  - **a lock while the node runs,** manual and automatic: the node stays `RUNNING` and connected, and a COB write after the lock still signs;
  - **a start while the vault is locked,** at launch, as a crash restart and after a policy change: main spawns nothing until `vault.unlocked`, then the node starts. Nothing on a profile with a vault ever leads to a throwaway key;
  - **the lock boundary:**
    - a lock between `rad.hello` and the seal, and one during the derivation, before the reply is handed to the core's writer: `vault_locked`, nothing returned, the process is shut down, and the start waits;
    - a lock just after the core hands the reply to its writer, before main reads it (a test hook), and one after main reads it, before `rad.identity`: the start completes;
    - a lock during `rad.reconcile`, through a repair that runs for minutes, and one during `rad.start`: the start completes, and the node runs. A running node's behavior is unchanged;
  - **a key file present:** a file, a symlink and a dangling symlink at `keys/radicle`. `rad.identity` answers `key_file_present` before it opens the ciphertext, and the process exits. One placed between `rad.identity` and `rad.start`, through a test hook: `rad.start` refuses;
  - **ciphertext only through main:** with a test vault whose derived key is known, a recorder on both pipes and on main's log finds the key's bytes nowhere, raw, in base64 or in hex. Main sees the recipient, `enc` and the ciphertext;
  - **the seal:** RFC 9180's test vectors for the suite. A ciphertext sealed to another process's recipient, a tampered one, and one from an earlier start: `bad_sealed_key`, then the exit. A second `rad.identity`: `invalid_argument`. `nodes.seal_radicle_key` from `chrome`: `forbidden`; with no vault: `no_vault`; locked: `vault_locked`; a lock during the call: `vault_locked`, with nothing returned; a low-order recipient: `invalid_argument`;
  - **the throwaway key is never written:** on a profile without a vault, after a start, reads, a clone and a stop, no file under the home or the service's `HOME` holds the key's bytes, and `keys/` holds no key. Each start has a new node ID. COB writes and the import answer `needs_vault`, in main and in the service;
  - **vault changes without a restart:** a vault created, locked and unlocked, and deleted, each while a node runs. The DID main shows and its write admission stay the generation's: a throwaway node keeps refusing writes after a vault is created, and a derived node keeps admitting them after a lock and after a delete. The derived DID is shown only as the next start's. Then a restart: the derived identity after a create, a throwaway one after a delete;
  - **the switch:** a home with the core's derived key file, and one with libradicle's random key. `key_file_present`, the switch, then a start: with the derived key, the DID is the file's. A crash before the journal commit, after it, after the marker's install, and after each removal: recovery finishes the switch, and the next start succeeds. No start ever runs with the file present. A key file whose public key can't be read: `node_identity_corrupt`, and nothing is touched;
  - **a dirty home across an identity's loss:** identity A commits a COB ref and is killed before `rad/sigrefs`. Then:
    - A's vault is deleted, and the next start uses a throwaway key;
    - or the vault is replaced by another, without a wipe, and the next start uses its derived key;
    - or, the first switch from a generated identity: the add-on, running as libradicle's key, is killed in the same place, then the switch runs, and the next start uses the sealed key or a throwaway one.

    Each time, the reconciliation checks A's namespace, quarantines the repository as `namespace` with every byte kept, writes no key file, and signs nothing with the new key. The marker then names only the running identity, and a clean stop clears it. With A's vault kept or restored instead, or with the core's derived key file before the switch, the start runs as A and re-signs;
  - **a resumed check across a key change:** a check of A's namespace cut off by the deadline while A runs, then a start under another key. The check starts over, and doesn't sign;
  - **successive throwaway keys:** A's vault deleted, A's refs unchanged, and a namespace check of A that needs several reconciliation deadlines. Each Retry runs a fresh throwaway key, and each continues from the last checkpoint. The check completes, or quarantines the repository as `namespace`, within a bounded number of retries, and A's key is never recovered or used;
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
  - a test peer announcing loopback and private addresses, and the IPv6 forms that embed them (0007's embedded-IPv4 cases), none of which is dialled;
  - I2P addresses, which are refused;
  - a `config.json` with a conflicting proxy, an onion `Forward` and an I2P route, which change nothing;
  - in `direct` mode, one lookup per connection, connected to the checked address.
- **Live:** the packaged `nodes.spec.js` Radicle leg, re-pointed at the service.

### Parity

| Item | Today | The service |
|---|---|---|
| start | `Embedded::start({ home, alias: 'FreedomBrowser', listen: [] })` in main | `Embedded::start_with_key` with the same options and the key from `rad.identity`, in the service, after reconciliation |
| key | `keys/radicle`, loaded in main | no file: the derived key, sealed by the core to the service at each start; a throwaway key on a profile without a vault ([Keys](#keys)) |
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
- **It runs only on a home that still has `keys/radicle`.** On a home without one, its `start` would generate a key file of its own (`lr:700`–`720`), so main refuses it there. The service's first start switches a home ([The switch](#the-switch)), so after that the add-on is refused on it.
- Then the add-on, its fetch script and its `check-binaries.js` rule go.
- **The switch is one-way.** The home's other files keep their format, but a build from before this design finds no `keys/radicle`:
  - its add-on generates a random key file at start (`lr:700`–`720`), so the node runs as a new identity, with a key at rest again;
  - getting the derived identity back there takes a re-injection, which wipes `node/`, `cobs/` and `storage/` first, as `injectRadicleIdentityNow` in `identity-manager.js` does.

  So no release rolls back past the switch to the add-on. Once the service has shipped, fixes go forward.

## Bounds

| Budget | Bound | Exhausted |
|---|---|---|
| handshake; `rad.identity`; `rad.reconcile`; `rad.start` | 10 s; 30 s after the handshake; 300 s, checked between COBs; 30 s | kill; the process exits; error, and the process exits (Retry continues from the checkpoints) |
| a start on a profile with a vault, while it is locked | no process, so nothing to bound: main waits for `vault.unlocked` | — |
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
| `key-custody` | `keys/radicle`, an unencrypted file, loaded in main | no key file: the core releases the derived key at each start, sealed to the service, and main relays only ciphertext; the switch removes the old file | no Radicle key at rest |
| `locked-start` | the node starts at launch whatever the vault's state | on a profile with a vault, every start needs an unlock until the core releases the key, restarts included; after that, the rest of the start and the running node outlive a lock | Radicle is down from launch until the first unlock, and after a crash or a policy change while locked |
| `device-key` | libradicle generates a random key on a profile without a vault, and keeps it in `keys/radicle` | a throwaway key, made in memory at each start and never written; COB writes and the import are refused (`needs_vault`) | such a profile reads and browses with no lasting identity; the switch ends an identity libradicle generated, though what it published stays |
| `locked-did` | the DID shows while the vault is locked, read from `keys/radicle.pub` | the running generation's, from `rad.identity`; with no node running, only the next start's, from `keys.addresses` while unlocked | while the vault is locked and no node runs, no Radicle DID shows |
| `stop-budget` | no Radicle budget | 10 s, then kill | quit can't wait on Radicle |
| `env` | the add-on inherits main's environment | cleared; `HOME` an empty directory; no git configuration | `RAD_*`, `SSH_AUTH_SOCK` and git configuration no longer apply |
| `proxy` | none | an optional SOCKS5 policy, names resolved through the proxy and checked, failing closed | new: Route Radicle through Tor |
| `address-policy` | none | untrusted targets refused unless globally reachable unicast, with IPv6 forms that embed IPv4 judged by their IPv4 address (0007) | configured local seeds still work |
| `address-families` | as `config.json` and the default features allow | IPv4, IPv6, DNS and onion; no I2P; every routing field set in memory | a conflicting `config.json` can't change routing |
| `health` | none | `rad.stats` every 5 s | a dead node is noticed and restarted |

## Implementation steps

1. **Tests first,** in freedom-browser: the contract suite, the fixture repository and golden vectors from the v0.8.0 add-on.
2. **Upstream:**
   - libradicle items 1, 2 and 4–9 (item 3 needs nothing now);
   - heartwood items 10–14, on the `freedom/embed` fork.

   The service can start on items 1, 2, 4, 9, 10 and 13.
3. **The shared service skeleton,** from 0007: the lock, `hold-lock`, the handshake, parent death, the panic hook, hardening and the frame I/O.
4. **`services/freedom-radicled`:**
   - the dirty marker and the identities it names, `rad.reconcile` with its bound, the repair units and their watchdog, the online repair, the repository gate, quarantine and `rad.remove_repo`;
   - the pools, the output budget and bounded JSON construction;
   - `rad.read` and `rad.blob`, with ranges;
   - network operations with bounded progress and cancel;
   - the write queue with the mutation-start boundary, and the in-process import;
   - `rad.stats`;
   - the X25519 recipient, `rad.identity` with HPKE, the key-file check and the throwaway key, and `needs_vault` for writes under a throwaway key;
   - the test hooks and the Rust tests.
5. **Release:** five targets, `SHA256SUMS`, attestations and notices (libgit2's included), on `radicled-v*` tags, in separate build jobs.
6. **freedom-core:**
   - `nodes.write_identity` for Radicle takes the home gate and gains `wipe`. It writes no key file, removes `keys/radicle` and `keys/radicle.pub` (the switch) after naming the old identity in `node/dirty`, and needs no vault;
   - the core's recovery paths take the gate;
   - `nodes.seal_radicle_key`, with HPKE.
7. **freedom-browser:**
   - `radicle-embedded.js` on the service, behind `FREEDOM_RADICLE_BACKEND` in dev, with `callStream` and `callScoped`;
   - admission and cancel for `rad:` and `radapi:`;
   - the limits for other callers;
   - private partitions read-only;
   - the start with the sealed key, the wait for an unlock, the throwaway key on `no_vault`, and the switch on `key_file_present`;
   - the active identity bound to the generation, writes refused while it is a throwaway one, and no more reads of `keys/`;
   - the identity change through the core, and `hold-lock` for the alias and profile removal;
   - the add-on refused on a home without `keys/radicle`;
   - the contract suite against the binary, the gates;
   - then the default switches.
8. **The raw endpoint** and the viewer's images and downloads.
9. **Network policy:** the setting, Arti's endpoint and its `RESOLVE` qualification, and the SOCKS, canary, address-policy and family tests.
10. **Removal,** one stable release later.

## Open questions

1. **Where the code lives:** a separate workspace here (recommended), upstream libradicle, or a new repository (the user's decision).
   - **Decided (the user, 2026-10-22): a separate workspace here,** following 0007's `services/freedom-ipfsd`.
2. **Key custody:** keep the key file (the draft's default), or move to a sealed host key with no file at rest? The latter needs a new exception to rule 3, and an unlocked vault for every start (the user's decision).
   - **Decided (the user, 2026-10-22): the sealed host key, with no file at rest.** The node starts only while the vault is unlocked, every restart included, and a later lock doesn't stop a running node. [Keys](#keys) is now that design. Its boundary is the key's release: a start that already has its key completes whatever the vault does ([When the node can start](#when-the-node-can-start)).
3. **AGENTS.md, a prerequisite to the custody choice:** should rules 3 and 4 name node identities: 0001's node identity writes (Bee and Radicle), and keys that outlive a vault lock? (The user's decision.)
   - **Decided (the user, 2026-10-22):** rule 3 names the sealed release of the Radicle node key to this service, and no other node key may be released. Bee's keystore file stays a temporary exception until Phase 5, and rule 4 says that a node keeps its key across a lock once it has been released to it. AGENTS.md is amended to match (#120).
4. **The device key:** the draft had the core write a random key on profiles without a vault. Is a device identity that isn't derived from the wallet still wanted there, or should Radicle require a vault?
   - **Decided (the user, 2026-10-22): Radicle needs a vault for a lasting identity.** A profile without one runs its node with a throwaway key, made in memory at each start and never written. It reads and browses, and can't publish under an identity of its own. Creating a vault gives it the derived identity at the next start ([Profiles without a vault](#profiles-without-a-vault)).
5. **The control socket:** is it acceptable that the `rad` CLI can no longer attach to Freedom's node, or should a developer setting keep it?
6. **The raw endpoint for pages:** is the inert-type allowlist right? Should pages get `/raw/` at all, or only the viewer?
7. **Caps:** are 64 MiB per blob, 32 MiB per JSON result and 64 MiB of built data per read right?
8. **The address policy:** are these the right ranges, and is the exact-address exemption for configured seeds enough for LAN setups?
9. **One Tor switch:** should Route Radicle through Tor and 0007's Route IPFS through Tor be one setting?
   - **Decided (the user, 2026-10-22): separate switches now, and a future "everything through Tor" mode turns both on.** The two protocols pay different costs under Tor, so a user can take one without the other.
10. **heartwood's memory:** should the service run under an OS-level limit (`RLIMIT_AS`, or a Windows job memory limit), given that heartwood's own buffers aren't bounded by the service?
11. **Private windows:** is read-only the right rule for private partitions, or should an explicit, user-initiated seed be allowed there?
