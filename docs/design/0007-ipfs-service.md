# 0007: The freedom-ipfs service process

**Status:** proposed. Roadmap Phase 4 (item 4.2). Builds on [0001](0001-freedom-cored.md) (process model, lifetime lock, framing, hardening), [0005](0005-chain-data.md) (credit) and [0006](0006-dweb-transports.md) (plans, and the outline in *Service processes*).

**The references:**
- **freedom-browser** at `c5bd66d5` (#704, `claude/dweb-plans`), and at `485819a9` (`integration/rust-core`) for the delegated routers (#724):
  - `ipfs/freedom-ipfs-native-binding.js`, `ipfs/freedom-ipfs-native-node.js` and `ipfs/freedom-ipfs-event-worker.js`;
  - `ipfs-manager.js` and its `ipfsBackend()`;
  - `dweb/plan-executor.js` and `dweb/fetch-admission.js`;
  - `core/core-client.js` and `core/frame.js`;
  - `scripts/fetch-freedom-ipfs-native.js`.
- **freedom-ipfs** v0.4.6 (`ee6b95c`), the release freedom-browser pins on `integration/rust-core` (`485819a9`). It changes only dependencies, so its source is v0.4.5's, which the commit above pins. Line references below are to that tag:
  - `mob` is `crates/freedom-ipfs-mobile/src/lib.rs`;
  - `rt`, `rv`, `ns` and `st` are the `lib.rs` of the routing, retrieval, namesys and store crates.

## Summary

freedom-ipfs runs inside Electron main today:
- an N-API add-on wraps the `freedom-ipfs-mobile` C ABI;
- a worker thread waits on its event queue;
- main reads the bodies.

A native fault ends the browser: #345 was one, a worker `terminate()` racing a native call. A Rust panic that crosses the add-on's `extern "C"` boundary would be another. Nothing restarts the node. It honors no proxy. Private windows share its on-disk cache.

This design moves it into **its own supervised process, `freedom-ipfsd`**:

- **The process model is 0001's, not Myotis's.**
  - A plain Rust binary on stdin and stdout frames, with `--parent-pid` and the same OS lifetime lock, keyed by the IPFS data directory.
  - Restarts back off after 0.5 s, 2 s and 10 s.
  - The data is a cache, so the OS lock's release proves an owner gone. No ownership record, supervisor or Electron-as-Node child is needed.
- **The binary calls the gateway crate directly.**
  - It uses `GatewayCore::handle`, with no C ABI, no handles that are raw pointers and no event worker.
  - Its own code forbids `unsafe` and panics.
  - A panic inside freedom-ipfs on a request's task fails that request and retires its instance, which is torn down and replaced: the panic may have left the instance's shared state half-updated. A panic anywhere else ends the process. Either way a hook logs a fixed code, never the payload.
- **Instances are owned and fenced.**
  - Each instance owns its tasks, swarms, blocking work and network capability, and carries an ID that is never reused.
  - A stop, an eviction or a policy change does all of these, in order:
    1. fences new work;
    2. revokes the network capability;
    3. cancels everything;
    4. waits until nothing of the instance runs.

    Only then does it acknowledge. If that can't be proven within 5 s, the process is restarted instead.
- **Bodies stream over the same pipe.**
  - Four stream frames from 0001's reserved kinds (`0x02`–`0x05`) carry them.
  - Each stream has a 128 KiB credit window, with checked accounting.
  - An `end` never overtakes its stream's data.
  - The reader never waits on the writer.
  - Main's existing admission (256 active fetches) bounds what main holds.
- **The plan executor's contract (#704) keeps its shape.**
  - `ipfsBackend().request()` keeps its contract: a `Response` whose body is pulled with backpressure.
  - It becomes a client of the service instead of the add-on.
  - The handler gains a lease, which it releases on every exit, and a 503 `busy` for capacity, distinct from a node that isn't up.
  - The core and the plans don't change: the backend reference stays `{ ipfs: "native", up }`.
- **Private windows get memory-only nodes.**
  - One ephemeral process serves every private window, with one in-memory instance per private partition.
  - The instance starts on the partition's first request, inside `request()`.
  - Readiness is per partition: an existing instance stays usable, and capacity is checked only when a partition needs a new one.
  - Nothing a private window loads reaches the profile's cache or the application's files. The instances partition caches and PeerIDs; they don't partition address spaces.
- **Budgets are process-wide.**
  - Retrieval admission, background queues and one memory budget span every instance in a process.
  - Every accounted allocation reserves its bytes before it is made, and memory stores have a hard page cap.
  - Admitted work that can't reserve waits for a bounded time, then ends with `busy`.
- **Network policy becomes configuration, behind one gate.**
  - `direct`, or `socks5` for all of the service's traffic. Under SOCKS, QUIC and the local DNS resolvers are off.
  - In both modes, a name is resolved, every answer is checked, and the connection is pinned to a checked address. Under SOCKS, names are resolved through the proxy (Tor's `RESOLVE`), and only onions are handed to it as names.
  - Every target is classified once (onion, IP literal or name) before any expansion. The policy is applied again after expansion, before each connection, and on every HTTP redirect hop.
  - By default, a target learned from the network must be a globally reachable unicast address. Loopback, private, link-local and the other special-purpose ranges are refused, and so is an IPv6 form that embeds a refused IPv4 address. Configured endpoints are exempt.
  - freedom-ipfs has no hook for any of this today, so it needs upstream changes, [listed](#upstream-changes-in-freedom-ipfs) by file and line.
- **The code lives in this repository, in its own Cargo workspace** (`services/freedom-ipfsd`).
  - It shares `fc-protocol` and the release workflow, but not the core's lockfile, build jobs or credentials.
  - A new repository remains the user's call ([Where the code lives](#where-the-code-lives)).
- **Tests come first.** #704's native-backend cases become one contract suite, run against the add-on before anything moves, and then against the service.

## Goals and non-goals

**Goals**
- **Crash isolation:** no IPFS fault can end main. A crashed service is restarted with back-off, and only its in-flight requests fail.
- **Parity:**
  - the same `GatewayCore`, configuration and cache file, so responses are byte-identical;
  - #704's backend contract holds unchanged (see [Main's side](#mains-side));
  - the [deviations](#deviations) are listed.
- **One owner per data directory,** enforced by the OS for every writer that takes the gate.
- **Private windows leave nothing behind in the application's files:** no blocks, names or provider records on disk, and none shared with the profile or with each other.
- **A network policy the node can honor,** failing closed: under a proxy, no direct socket; no connection to a target the policy refuses.
- **Bounded resources,** with budgets an implementer can test: across the pipe, in the service and in main.

**Non-goals**
- **Content verification (4.5).** The service returns what `GatewayCore` returns. Main keeps no verifier; 0006's later design covers this.
- **The external gateway path** (`gatewayFetch`) stays as #704 left it, including in private windows.
- **libradicle (4.4):** its own design (0008). It reuses this one's process model, streams and client.
- **Persistent libp2p identity, content providing and a DHT server:** freedom-ipfs is a read-only client, and stays one.
- **Mobile:** iOS and Android keep linking freedom-ipfs in process.
- **An OS sandbox.** Process separation is a crash domain and a resource boundary, not a sandbox.

## Today

- **Loading:**
  - `freedom-ipfs-native-binding.js` `require`s `freedom_ipfs_native.node`, an N-API add-on in C++ over the `freedom-ipfs-mobile` static library.
  - It is fetched per target by `fetch-freedom-ipfs-native.js`, with one pinned SHA-256 per asset.
  - The add-on needs GLIBC ≥ 2.38 on Linux (#350).
- **Lifecycle:**
  - `FreedomIpfsNativeNode` serializes `start` and `stop`, and runs the add-on's `*Async` calls on the libuv pool.
  - Start is `nodeNewWithDataDirAsync(dataDir, 256 MiB)`, then `nodeStartNativeGatewayOnlineAsync(handle, DELEGATED_ROUTERS, AUTO, 0, 3, 0, 15000)`:
    - two delegated routers, `https://delegated-ipfs.dev/routing/v1` and `https://cid.contact/routing/v1`, as one comma-separated string (#724);
    - a 3 s DHT query timeout;
    - the default 8 header permits;
    - a 15 s request queue.
  - A restart waits for the previous free before reopening the data directory.
- **Requests:**
  - `gatewayRequestStart` returns a handle. A worker thread blocks in `gatewayWaitNextEvent` and posts events to main.
  - Main pulls each body in 64 KiB reads, and only while the stream has demand.
  - Every terminal path cancels and then frees the handle.
- **Failure:**
  - A dispatcher exit or a `GATEWAY_STOPPED` event fails the node.
  - `ipfs-manager.js` then shows "Node unavailable. Restart IPFS from the nodes menu." It does not restart the node.
- **Data:**
  - `<userData>/ipfs-data/freedom-ipfs/freedom-ipfs.sqlite3`, in WAL mode, holds blocks, provider records, failing providers and resolved names.
  - `FREEDOM_IPFS_DATA` moves it.
  - No lock guards it beyond the profile lock.
- **Routing,** in `AUTO` mode: the string is split at commas, and the list feeds both kinds of lookup (`mob:2200`–`2227`, `mob:2274`–`2299`):
  - **Providers:** both routers are asked in parallel, and their providers merged (`rt:357`–`426`). The light DHT stays the fallback (`rt:636`–`700`).
  - **IPNS names:** the same list, both routers in parallel, then the DHT (`ns:412`–`447`, `ns:514`–`530`).
  - **One router's 404 masks the other's failure** ([freedom-ipfs#30](https://github.com/solardev-xyz/freedom-ipfs/issues/30)). cid.contact holds no IPNS records and answers 404, so when delegated-ipfs.dev can't be reached, an `/ipns/` load reports "not found" rather than a network error. No miss is cached, so a retry recovers.
- **Network:**
  - Delegated routing, DoH and HTTP providers go through `reqwest`.
  - Bitswap and the light DHT go through libp2p over TCP, QUIC and WebSocket. libp2p resolves names through its own resolver.
  - Nothing reaches the add-on from the session's proxy or onion policy (`tor-proxy.js`: the decentralized protocols "keep connecting directly").
- **Private windows** call the same `ipfsBackend()`, and so use the same node and cache.

## Process model

```
Electron main (profile P)
  ├─spawn─▶ freedom-ipfsd serve --data-dir <ipfs-data>/freedom-ipfs --lock-dir <locks> --parent-pid <pid>
  │           stdin  ──frames──▶
  │           stdout ◀──frames──
  │           stderr ◀──JSON log lines──
  └─spawn─▶ freedom-ipfsd serve --ephemeral --parent-pid <pid>     (only while a private window uses IPFS)
```

### Spawn

- **One persistent process per profile,** for the profile's IPFS data directory (`getIpfsDataPath()`, unchanged).
  - It is spawned when IPFS starts in bundled mode: at launch if `startIpfsAtLaunch` is set, and from the nodes menu.
- **One ephemeral process per profile,** spawned on the first private-window request ([Private windows](#private-windows)). It takes no data directory and no lock.
- **The binary:**
  - It comes from the app's resources, at `<resources>/freedom-ipfsd/`.
  - `FREEDOM_IPFSD_PATH` is honored only when `!app.isPackaged`, as `FREEDOM_CORED_PATH` is.
- **The environment** is cleared except for `PATH`, `HOME`/`USERPROFILE`, `LANG`, `RUST_LOG` and `SystemRoot` (`core-client.js`'s `scrubbedEnv`). That drops:
  - the proxy variables `reqwest` would otherwise read;
  - the `FREEDOM_IPFS_*` tuning variables freedom-ipfs's routing and retrieval crates read.
- **Handshake:** `ipfs.hello` must complete within 10 s of spawn. Both sides enforce this, as for `core.hello`.
- **No listening socket.** The service binds nothing. Upstream's loopback HTTP gateway is never started.
- **Hardening:** 0001's, for both kinds of process:
  - Linux: `PR_SET_DUMPABLE=0`, which also suppresses core dumps;
  - macOS: no core files (`RLIMIT_CORE` 0), plus the hardened runtime from signing;
  - Windows: Windows Error Reporting's dialog and dump collection are turned off for the process where the API allows it. This is best-effort.

  These are application guarantees. The OS can still page the ephemeral process's memory to swap or a hibernation file. A private window promises nothing against OS-level memory forensics.

### Lifetime lock

0001's lock, with its own namespace:

- **The file:** `<lock-dir>/ipfs-<sha256(canonical data dir)>.lock`.
  - The lock directory is the core's, `<OS app-data>/Freedom/locks`, which is shared by every build and catalog.
  - The prefix keeps the IPFS gate apart from the core's, even if both are pointed at one directory.
  - 0001's limits apply unchanged, to the service and to destructive operations alike:
    - the canonical path resolves symlinks;
    - the lock directory is stable;
    - network filesystems are refused;
    - bind mounts that alias a directory aren't covered.
- **Taking it:** `File::try_lock`. On contention, retry for 5 s, then exit 75 (`lock_held`).
- **Errors:**
  - any other locking error exits 74 (`storage`);
  - so does a data or lock directory on a network filesystem, under 0001's qualification rules. SQLite's WAL mode isn't safe there in any case.
- **`hold-lock`:** `freedom-ipfsd hold-lock --data-dir … --lock-dir …` holds the gate until its stdin closes, as the core's does. Profile delete holds it while it removes the directory. freedom-browser has no profile reset and no IPFS reset; one added later holds it too.
- **What the lock guarantees, and what it doesn't:**
  - **It excludes only writers that take it:** the service, `hold-lock`, and the dev add-on fallback, which holds `hold-lock` for its whole lifetime ([Rollback](#rollback)).
  - **An older build** runs the add-on with no gate. Old and new builds sharing one data directory, for example through `FREEDOM_IPFS_DATA` or two profiles pointed at one directory, are unsupported.
  - **The profile lock** only excludes two owners of the same profile, as today.
  - **Until the default switches, only development builds take it.** Only they can run the service, so only there can the service and the add-on share a directory. A packaged build keeps today's behaviour, with today's limits. The profile lock's lease is its only exclusion, and a profile delete trusts a lease that looks stale (no heartbeat for 30 s): a stalled but live profile's data, its cache included, can be removed under it, as it can today. Gating packaged builds now would refuse such a delete while the profile's IPFS node runs, but would bring [`network-fs` and `data-dir-lock`](#deviations) to add-on users before the service ships; the lease's limit is the profile lock's to fix. The switch makes the gate unconditional, for the service, profile delete and the add-on fallback alike.
- **Why not Myotis's model** (a C supervisor, an owner record, an Electron-as-Node child):
  - Myotis needs a JavaScript host for its add-on, and its directory holds sync state whose interrupted generation must be preserved.
  - Here the binary is plain Rust. The data is a cache in SQLite's WAL mode, so a kill costs at most the last writes.
  - The kernel releases the lock when the process dies, so "lock free" proves "owner gone". No boot witness or recovery record is needed, and `runAsNode` gains no new user.

### Startup and shutdown

- **Start:**
  1. spawn;
  2. `ipfs.hello`;
  3. `ipfs.start` for the instance ([Methods](#methods)), which opens the store and wires the gateway, with no network traffic yet;
  4. the manager goes to `RUNNING`, and `ipfsBackend()` reports `up`.

  Until then the status is `STARTING`, and plans get the 503 of a node that isn't up, as today.
- **Ordering:**
  - IPFS needs neither the vault nor `freedom-cored`, and starts independently of both.
  - When the profile's IPFS proxy setting is on, main sends `ipfs.start` only once `tor-manager` reports Arti's SOCKS endpoint. Until then IPFS stays `STARTING` ([Network policy](#network-policy)).
- **Stopping an instance:** `ipfs.stop`, which covers a private partition closing, an eviction and a [policy change](#changing-the-policy). It follows [the teardown](#instances-and-their-teardown).
- **Stopping the process** (the nodes menu, a profile mode change, or quit):
  1. main sends `ipfs.shutdown` and closes stdin;
  2. the service tears down every instance;
  3. it exits 0;
  4. main kills it 5 s after `ipfs.shutdown`.

  A kill is safe, because the cache tolerates lost writes.
- **Quit:**
  - IPFS stays one leg of the wind-down's `Promise.allSettled`.
  - Its budget grows from 2 s to 5 s. That stays under Tor's 10 s, so `SHUTDOWN_WATCHDOG_MS` (20 s) stands.
- **Parent death:**
  - **The guaranteed path is stdin EOF, or a failed write to stdout.** Either ends the I/O task, whatever else is waiting.
  - On Unix, `--parent-pid` with `PR_SET_PDEATHSIG` on Linux, then a 2 s `getppid()` poll, as 0001.
  - A plain watchdog thread, independent of the async runtime, ends the process 5 s after EOF whatever the runtime's state. A wedged orphan therefore can't hold the lock.
  - On Windows, libuv places the child in main's kill-on-close job object. This is a backstop only: libuv carries on when assigning the job fails, for example with access denied.

### Crashes, hangs and restarts

- **A crash** is any exit main didn't ask for, other than 64, 74 or 75. Exit 76 (`protocol`, which includes 0001's 30 s writer stall) is a crash too, as it is for the core. On a crash:
  - every pending head is rejected and every open body errors as truncated, with `freedom-ipfs service exited`;
  - `up` is false until a new generation has completed `ipfs.hello` and `ipfs.start`;
  - main restarts after 0.5 s, 2 s, then 10 s;
  - three crashes within 60 s stop the restarts, and the status shows today's text: "Node unavailable. Restart IPFS from the nodes menu."
- **An instance retired after a request panic** (*Panics*, below) counts as a crash of its process, for the back-off and for the three in 60 s:
  - **the persistent instance:** `up` is false until a replacement has started. Main sends `ipfs.start` for a new ID after the back-off, in the same process;
  - **a private instance:** the partition's next request starts a new one cold, as after a restart;
  - **the third within 60 s** stops that process as three crashes do. Main sends `ipfs.shutdown`, and the status shows the same text.
- **No restart for:**
  - 64 (usage);
  - 74 (`storage`);
  - 75 (`lock_held`);
  - a handshake protocol mismatch, which is a packaging bug;
  - an `ipfs.start` that fails with `storage`, for example a store that won't open, as `start()` returning `false` is today.

  These are errors, not crashes. The menu's restart tries again.
- **Hangs:**
  - Main runs hang watchdogs only. The service owns deadlines and always replies (0001).
  - A head with no reply by `headers_ms` + 15 s, or an `ipfs.stats` with no reply within 20 s, means the service is hung. Main kills it, and the restart rules apply.
- **Generations:**
  - Each child is a generation, as in `core-client.js`.
  - Frames from a retired generation are ignored, so a late body can't reach a newer request.
  - Within a generation, instances have their own [epochs](#instance-ids).
- **Panics:**
  - **A startup panic hook replaces Rust's default** before any other work. It writes one fixed JSON line to stderr, `{"panic": "<task kind>"}`, never the payload or a backtrace, in both kinds of process. Payloads can carry paths, names and CIDs, and stderr is forwarded to main's persistent log.
  - **Request work** runs on tasks marked as request tasks, built with `panic = "unwind"`. A panic there is caught at its join handle, after the hook's fixed line. The request is owed `internal` unless it is already settled, and the writer, which holds the request's [protocol state](#frames), decides what that means:
    - **no head queued yet:** the request's `internal` error;
    - **head queued but not written:** the head is dropped, as for a cancel, and `internal` is the request's only reply;
    - **head written, stream open:** the stream's `internal` abort, which purges its queued data, as any abort does;
    - **already settled** (an error or `cancelled` sent, `end` written, or an abort queued): nothing more is sent, and the earlier outcome stands. This covers a panic in a request future's destructor after a cancel, which `fc-service` also runs as request work.
  - **A caught request panic retires its instance,** whether or not anything was still owed. The panic may have struck while the task held the instance's store, a cache, a Bitswap want or an in-flight table. A lock left poisoned or an invariant half-updated would then fail or corrupt every later request on that instance. So the join handle, which knows the request's instance, acts in this order:
    1. **Fence first.** Before it queues any reply or waits for anything, it runs steps 1 and 2 of the instance's [teardown](#instances-and-their-teardown): the ID is retired and the network capability revoked. The teardown's 5 s watchdog is armed at the same moment. From then on, a request for the instance gets `stopped`, including one main sends after it has seen the `internal`.
    2. **The request's terminal,** as the writer decides it above. It is queued, not awaited: the teardown doesn't wait for stdout.
    3. **The rest of the teardown,** from step 3, exactly as for `ipfs.stop`: the instance's other requests are cancelled (`stopped`, as in any teardown), and quiescence is awaited. If it isn't proven within the 5 s, the process exits 70.
    4. **The event** `ipfs.instance_retired { instance, reason: "panic" }`. Main marks the pair retired and restarts as [above](#crashes-hangs-and-restarts).

    A request panic on an instance that is already being torn down adds nothing: that teardown goes on. The store keeps what was committed. A transaction the panic interrupted is rolled back when the store closes, as after a kill. Between the panic and its join handle seeing it, a request that meets a lock the panic poisoned fails with `internal`: only the teardown recovers a poisoned lock ([Upstream changes](#upstream-changes-in-freedom-ipfs)).
  - **Other instances are untouched.** In the ephemeral process, the instances share only process-wide state. A request task holds these parts of it, each as an owned guard whose drop releases it, so an unwinding task returns it ([Budgets](#budgets)):
    - its admission slot;
    - retrieval permits;
    - the dynamic reservations of its work, such as its block fetches.

    **The stream's protocol state isn't the task's.** The writer's record of the request is the writer's: its queued head and that head's reservation, its queued data in the writer's data queue, and the stream's credit account. The task holds only a producer handle, and dropping it on unwind removes none of this. The record lives until the request's terminal frame is written, as for any request, so the terminal the writer decides on can still be sent, and credit is checked against the account until the abort is written. No lock of the service's is held across a call into freedom-ipfs, so an upstream panic can't poison one.
  - **Why the instance, and not just the request or the whole process:**
    - **Not just the request:** Rust unwinds memory-safely, but it doesn't restore an instance's own invariants. The store, caches, swarm state and in-flight tables belong to the instance.
    - **Not the whole process:** the instance is the unit that owns that state, and its teardown already proves that none of it survives. Restarting the ephemeral process would end every private window's instance for one partition's fault.
  - **Every other task the service spawns itself** (the Bitswap swarm's task, background retrieval, the instance's own tasks, the reader and writer) belongs to an instance's task set or to the process ([Instances](#instances-and-their-teardown)). The service observes each of these tasks' end. A panic, or an unexpected end, of one exits the process with 70, so it is a crash and main restarts it.
  - **Tasks the libraries spawn on an instance's runtime** (hyper's and libp2p's connection tasks) have no join handle the service holds, so their ordinary completion isn't observed. Their lifetime ends with the instance's runtime, whose shutdown is proven ([teardown](#instances-and-their-teardown)). A panic in one is still caught by the hook, and the hook exits the process with 70: any panic outside a request task is fatal, whether or not its task is tracked.
  - **A panic on any non-runtime thread** exits with 70 from the hook.
  - **One exit at a time.** The first exit to begin reports and ends the process: a hook's, a watchdog's, or `main` returning. Any later one waits for it, so it can't cut off the first's report or change its code. The owner coming back (a panic in its report, or in a thread-local destructor as it exits) never waits on itself. While its report's timer is armed, that timer ends the process with the first code. Once the owner is already exiting, it aborts.
  - **In all:**

    | Where the panic is | The request | Its instance | The process |
    |---|---|---|---|
    | a request task | `internal` unless already settled: an error before the head is written, an abort after it | fenced first, then torn down, then `ipfs.instance_retired` | goes on |
    | a task the service spawned for an instance or for the process | — | — | exits 70, from the hook |
    | a library's task on an instance's runtime | — | — | exits 70, from the hook |
    | any other thread: blocking work a library spawned, the teardown thread, the watchdogs | — | — | exits 70, from the hook |
    | (after a request panic) the teardown, not proven within 5 s | — | — | exits 70, from the watchdog |

    Only a request task's panic is ever caught. Every other panic ends the process in the hook, before unwinding reaches anything that could catch it.
  - The service's own code is under the workspace lints: no `unsafe`, `unwrap`, `expect` or `panic!`.

### Inside the process

- **Runtimes: one for the process, and one per instance.**
  - All are tokio, multi-threaded. freedom-ipfs requires it: its block provider calls `block_in_place` (`rv:5448`, `rv:5500`, `rv:5535`), which panics on a current-thread runtime.
  - **The process runtime** runs the reader, the writer, admission and the control methods. It has 2 worker threads.
  - **Each instance gets its own runtime,** which its [teardown](#instances-and-their-teardown) shuts down last.
    - This is needed because hyper (through reqwest, which has no executor hook) and libp2p spawn connection tasks on whatever runtime is current. No task set can track those tasks.
    - Upstream's implementation showed that with every request cancelled and the task set empty, connection sockets stayed open until the instance's runtime was shut down. Shutting the runtime down is what proves no socket survives.
  - **Per-instance bounds:**
    - The persistent process's one instance gets the core count of worker threads, capped at 8, and a blocking cap of 512.
    - Each of the ephemeral process's up to 8 instances gets 2 worker threads and a blocking cap of 64. That makes at most 16 workers and 512 blocking threads in total.
    - Every in-flight block fetch holds a blocking thread. What bounds that work is the process-wide [retrieval admission](#budgets), not these caps or upstream's constants.
- **Tasks,** as in `freedom-cored`:
  - one reader and one writer ([Frames](#frames));
  - one task per request;
  - each instance's task set.
- **An instance** is one store, one block provider, one name resolver and one `GatewayCore`, built by upstream's [builder](#upstream-changes-in-freedom-ipfs).
  - **The persistent process** holds one instance at a time, for the store `<data-dir>/freedom-ipfs.sqlite3`. That is the file the add-on uses, so the cache carries over and nothing migrates either way.
  - **The ephemeral process** holds up to 8 memory instances ([Private windows](#private-windows)).
- **Logs:**
  - JSON lines on stderr, forwarded to main's log.
  - The service logs its own lifecycle and failures with codes, never a path, name or CID.
  - In the persistent process, upstream's tracing feeds only the progress recorders, as the add-on's subscriber does today: the process installs upstream's subscriber (`init_progress_tracing`, the progress layer and nothing else) before anything of freedom-ipfs runs. Each instance records into its own recorder (`Instance::progress`): its runtime's threads and its requests' spans carry it, so nothing of one instance's reaches another's, or the process's default recorder.
  - The ephemeral process installs no subscriber at all, so nothing is recorded, not even in memory ([Private windows](#private-windows)).

### Instances and their teardown

Aborting a task doesn't stop work that is blocked in `block_in_place`, and work an instance spawns on its own outlives its spawner. So an instance is an **owned group**, and every boundary waits for proof that the group has finished.

- **The group:** upstream's builder returns an `Instance` that owns:
  - **a root cancellation token,** which every operation observes: HTTP requests, DoH and DNS lookups, DHT queries, Bitswap requests, and each `block_on` inside a blocking region;
  - **a task set,** with every task the instance spawns: request work, the shared Bitswap swarm's task (`rv:7390` spawns it today), and any background retrieval, such as provider preconnects. DHT lookups build their swarm and drive it inside the lookup's own future, so they end with the request;
  - **its runtime,** on which every task the instance or its libraries spawn runs;
  - **a blocking-region count,** raised and lowered around every `block_in_place`;
  - **a network capability:** the instance's handle on [the gate](#the-gate). Every socket, HTTP attempt and redirect hop asks it first, and revoking it makes every later ask fail.
- **The teardown,** for a stop, an eviction, a policy change and shutdown alike:
  1. **Fence:** the instance's ID is retired at once ([Instance IDs](#instance-ids)), and new requests for it get `stopped`.
  2. **Revoke:** the network capability is revoked, so no new connection can be made, whatever is still running.
  3. **Cancel:**
     - the root token is cancelled and the task set aborted;
     - the swarms are dropped, which closes their connections;
     - in-flight heads are answered `stopped`, and open streams aborted with `stopped`.
       - **"In flight" means not yet written.** A head that is queued but not written is in flight: it is dropped with its body, and `stopped` is the only reply, even for a complete bodiless response.
       - **A stream is open until its `end` is written,** so a stream whose work ended and whose `end` is still queued is aborted too. Teardown doesn't wait on the writer for main to read.
  4. **Wait for quiescence:** the task set is empty and the blocking-region count is zero. Then:
     - **The instance's runtime is dropped and joined** on a dedicated teardown thread, never on the process runtime's workers. Dropping a tokio runtime waits for its workers and every blocking-pool thread to exit, including blocking jobs the libraries spawned that no counter sees. A timed shutdown (`shutdown_timeout`, `shutdown_background`) is not used, because it may return while that work is still running.
     - **The store is closed** after the join (`close`, waiting at most 2 s for a statement in progress, as upstream's `close_or_close_later` does).
     - **Quiescence is proven** only when the join has returned and the store is closed. The managed counters reaching zero are necessary, not sufficient.
     - **No uncancellable blocking work:** the service's resolver ([The resolver contract](#the-resolver-contract)) is async and cancellable, and replaces reqwest's default blocking resolver (`getaddrinfo` on a blocking thread). So in normal operation the join waits only for work that cancellation already ended.
  5. **Acknowledge:** only then does `ipfs.stop` reply, a replacement start, an eviction count as done, or `ipfs.shutdown` exit.
- **The bound:** the teardown has 5 s, enforced by an independent watchdog thread, not by the teardown thread itself. If the runtime join and store close haven't both returned by then, the service doesn't proceed: it writes `teardown_unproven` and exits 70. Reservations, the instance ID and any replacement stay blocked until quiescence is proven, so a timeout never releases them.
  - Main treats that as a crash and restarts the process.
  - So no surviving work of an old instance can resume after a boundary, and its budget share isn't handed to a new instance while it might still be in use.
- **Charges stay until the end:** a stopping instance keeps its [budget](#budgets) charges until quiescence. A new instance starts only within what is free.

## The protocol

### Frames

0001's frame layer: a `u32` big-endian length, a `u8` kind, then the payload.

- **Kind `0x01`** carries a JSON message of at most 1 MiB, with 0001's envelope: `request`, `response`, `event` and `cancel`, and exactly one terminal response per request.
- **Request IDs strictly increase** within a connection (0001's counter, never reused). The stream rules below rely on it, so the service treats a request whose ID isn't above every earlier one as a protocol error (`request_order`) and closes the connection.
- **Kinds `0x02`–`0x05`** are the stream frames, taken from 0001's reserved range.
  - Each payload starts with the stream's 8-byte big-endian ID.
  - The payload length is checked against the kind before anything else is done with the frame, its direction included: a stream frame of the wrong length is a length error whichever side sent it.
- **The stream ID is the `ipfs.request`'s envelope ID.** One request has at most one body, so no separate ID space or open frame is needed: the head response opens the stream.

| Kind | Name | Direction | Payload after the ID |
|---|---|---|---|
| `0x02` | data | service → main | 1 to 65 536 body bytes |
| `0x03` | end | service → main | none (exactly 8 bytes in all): the body is complete |
| `0x04` | abort | service → main | JSON `{ code, message }`, 1 byte to 1 KiB: the body is truncated |
| `0x05` | credit | main → service | a `u32` big-endian, > 0 (exactly 12 bytes in all): bytes main has handed on |

**Order, per stream:**
- **The sequence is fixed:** the head (a `0x01` response), then data, then exactly one terminal (`end` or `abort`). A head that says `body: false` opens no stream.
- **Each stream is a FIFO.** Its head, data and `end` are queued in order, and **`end` is written only after the stream's last data frame has been written**.
- **`abort` is the one frame that jumps the queue.** It purges the stream's queued, unwritten data and is then written. Nothing of the stream is written after it.
- **Cancel against an unwritten head:** when main's `cancel` arrives while the head is queued but not yet written, the head is dropped. `cancelled` is the request's only reply, and no stream opens.
- **Once the head is written,** a cancel gives `abort { code: "cancelled" }`, unless the stream's terminal is already settled: `end` already written, or an abort already queued. Then the cancel is late and is ignored, as in 0001.
- **Written means taken by the writer.** The service's writer takes one frame at a time from the queue, as it is about to write it, so every frame behind the one being written stays queued and cancellable. A frame whose write has begun can't be taken back, even if main hasn't read it yet: stdout's writes block, and their bytes are the OS's. `vectors/streams.json` models each take as a `write` step.
- **A cancel for an ID the service doesn't hold** (one already answered or ended, one never seen, or one above the highest request ID seen) is late and is ignored, as `freedom-cored` ignores IDs it doesn't hold. It is not a protocol error.

**Credit:**
- **The window** is 128 KiB per stream, fixed by the handshake.
- **The service's account,** per stream, in checked 64-bit arithmetic:
  - `sent` counts the bytes in data frames queued for the stream;
  - `credited` counts the bytes main has returned.
  - **Debit** happens when a data frame is queued: queuing is allowed only while `sent − credited + len ≤ 128 KiB`.
  - **Refund:** none. A purge by `abort` returns nothing: the account stays as it was, and credit is still checked against it, until the abort is written. Then the stream has ended, its account is dropped, and later credit for it is late.
- **Main's account,** per stream:
  - `received` counts data bytes that have arrived;
  - `returned` counts the bytes main has credited.
  - Main credits a chunk's bytes when it hands that chunk to the body's consumer, so `returned ≤ received`.
  - **After `end`** nothing more can come, so pulls send no credit, and a local cancel frees the bytes still buffered and sends nothing: the stream is complete.
- **Protocol errors** (0001: log and close):
  - data beyond the window (`received − returned > 128 KiB` in main), except on a retiring stream, whose data is dropped as it is read without the check (its record is the ID alone);
  - credit beyond what was sent (`credited > sent` in the service);
  - an empty data frame;
  - a wrong fixed payload length;
  - a frame for a stream ID above the highest request ID seen;
  - a second terminal frame;
  - stream data sent by main, or credit sent by the service;
  - a request whose ID isn't above every earlier one (`request_order`, in the service).
- **Error categories are a contract.** `fc-protocol` and main's `frame.js` report each failure under the same fixed name, safe to log, and `vectors/streams.json` pins them. Data or a terminal frame for a request whose stream isn't open (before its head, after a head without a body or an error reply, or after its terminal) is `stream_not_open`, whichever it is: main keeps no table of ended streams, and a name that depended on whether the consumer had drained the ring would depend on timing.
- **Late frames:**
  - Credit for a stream ID that was opened and has since ended is late and is ignored: it can cross a terminal frame in flight.
  - Because IDs increase, recognizing it needs no table: an ID at or below the highest seen that isn't live is late.

**Allocation bounds:**
- **Main keeps each stream in one ring of 128 KiB.**
  - It is allocated at the stream's first data. Received data is copied into it, never kept as one object per frame.
  - **When it is freed:**
    - receiving `end` only records EOF;
    - the ring is freed once the consumer has drained it after EOF;
    - it is freed at once on `abort`, a local cancel, or the end of the generation.
  - A `pull` copies up to 64 KiB out, into a fresh chunk that the consumer owns, and credits those bytes.
  - Since `received − returned ≤ 128 KiB`, the ring never grows. Main's backing storage per stream is exactly the window, whatever the frame sizes.
- **Main's decoder is counted separately.** It holds at most one partial frame (≤ 1 MiB plus its 5-byte header), and dispatches every complete frame as it decodes it.
- **The service coalesces too.** A data frame carries as much of the stream's pending body as the window and the 64 KiB frame limit allow. A frame smaller than 4 KiB is written only when it is all that is pending, or all the credit allows.
  - **Pending** is what the producer has handed over. A push queues as much as the window and the writer's 16 MiB cap allow, and the producer keeps the rest.
  - **A push the cap would cut below 4 KiB** queues nothing; the producer waits for the writer to make room rather than queue a fragment.
  - **The writer** cuts each data frame from what is queued, as large as the queue and 64 KiB allow. A stream that is aborted leaves the writer's rotation at once, so the rotation never holds more streams than are live.
- **The reader's frame budget** (0001: 256 frames and 16 MiB not yet handled) bounds frames between the pipe and their stream.
- **Retirement:** on a local cancel, main does all of these:
  - discards the stream's queued bytes at once;
  - sends `cancel`, and no more credit;
  - keeps a retirement record (the ID and its generation) until the terminal frame or reply arrives.

  Data arriving for a retiring stream is dropped as it is read. Retiring requests count against main's 512 outstanding service requests, the same bound as the service's admission, so the records are bounded.

**Progress under backpressure:**
- **The service's reader never waits on the writer.** Each frame is handled as it is read:
  - `credit`, `cancel` and `ipfs.shutdown` change state and need no writer room;
  - an ordinary request is admitted or answered `busy` at once ([Admission](#cancel-deadlines-and-admission)).
- **Every reply is bounded by construction:**
  - each admitted request produces exactly one head or error and at most one terminal;
  - refusals are bounded by the reader's frame budget.

  So the control queue is bounded by the admission bound plus the frames the reader holds. It never makes the reader wait.
- **The writer** serves the control queue first (responses, aborts and replies to `cancel`), then stream FIFOs round-robin, one frame per stream that has both credit and queued data.
  - It holds at most 16 MiB of data frames.
  - A stream's producer waits for room before queuing more, so a main that stops reading backs the service up rather than growing it.
- **The reader stops reading** only when its 0001 frame budget is full. Because control frames are handled on arrival, that happens only when main sends ordinary requests faster than they can be admitted or refused.
- **EOF** on stdin is seen by the reader independently of every wait, and starts the shutdown.
- **Main:**
  - its decoder keeps reading and dispatching while its own writes (credit, cancel and requests) wait for pipe room;
  - its writer queue for credit and cancel is bounded by the number of live streams.
- **The stall exit:** 0001's 30 s writer stall (exit 76) still applies, measured as 0001 measures it.

**Alternatives considered:**
- **Why not 0005's fragments:**
  - a fragmented response is one whole message, reassembled before use, at most 32 MiB, and one at a time per direction;
  - a video or a large download would have to be buffered whole, and every body would wait behind it.
- **Why not a second channel,** such as a loopback HTTP server or a second pipe:
  - a loopback port is reachable by every local process, and upstream's axum server checks no `Host`;
  - a second pipe adds handles to supervise for no gain, since control frames already go first.

**Shared with the core later:**
- The codec goes in `fc-protocol`, sans-I/O, with vectors that main's `frame.js` also passes. It covers the frames, the order, credit and coalescing.
- `freedom-cored`'s connections never grant `stream`, so the stream kinds stay refused there until 4.5's protocol version 2 adopts them, with an explicit global credit added.

### Methods

```jsonc
{ "type": "request", "id": 1, "method": "ipfs.hello",
  "params": { "protocol": 1, "shell_version": "0.9.0", "frames": ["stream"] } }
{ "type": "response", "id": 1, "result": { "protocol": 1, "service_version": "0.1.0",
  "freedom_ipfs": { "version": "0.4.6", "git_commit": "ee6b95c…" }, "kind": "persistent" } }

{ "type": "request", "id": 2, "method": "ipfs.start", "params": {
    "instance": "p-1",                                              // never reused within the process
    "store":   { "kind": "disk", "max_bytes": 268435456 },        // or { "kind": "memory", "max_bytes": 33554432 }
    "routing": { "mode": "auto",
                 "delegated_routers": ["https://delegated-ipfs.dev/routing/v1", "https://cid.contact/routing/v1"],
                 "doh_endpoint": "https://cloudflare-dns.com/dns-query",
                 "dht_query_timeout_s": 3, "dht_max_providers": 32 },
    "gateway": { "max_concurrent_requests": 8, "request_queue_timeout_ms": 15000 },
    "network": { "mode": "direct" } } }                            // or { "mode": "socks5", "ip": "127.0.0.1", "port": 9150 }

{ "type": "request", "id": 41, "method": "ipfs.request", "params": {
    "instance": "p-1", "method": "GET", "path": "/ipfs/bafy…/app.js",
    "headers": [["range", "bytes=0-"]], "headers_ms": 30000 } }
{ "type": "response", "id": 41, "result": {
    "status": 206, "headers": [["content-type", "text/javascript"], …], "body": true } }
{ "type": "cancel", "id": 41 }
```

| Method | Params | Result | Deadline (owned by the service) |
|---|---|---|---|
| `ipfs.hello` | `protocol`, `shell_version`, `frames` | `protocol`, `service_version`, `freedom_ipfs` build info, `kind` (`persistent` or `ephemeral`) | 10 s after spawn |
| `ipfs.start` | `instance`, `store`, `routing`, `gateway`, `network` | `{ instance }` | 10 s |
| `ipfs.stop` | `instance` | `{ instance }`, once [teardown](#instances-and-their-teardown) is complete | 5 s; past it, exit 70 |
| `ipfs.request` | `instance`, `method` (`GET` or `HEAD`), `path`, `headers`, `headers_ms` | the head: `status`, `headers`, `body` | `headers_ms`, until the head |
| `ipfs.stats` | `instance` | [Stats](#stats) | 5 s |
| `ipfs.shutdown` | none | none: the process exits | main kills after 5 s |

- **`ipfs.start`:**
  - The values above are exactly today's (v0.4.6's defaults where the add-on passes 0), sent explicitly.
  - `delegated_routers` serves provider and IPNS lookups alike, as the add-on's one string does. If upstream takes separate IPNS endpoints ([freedom-ipfs#30](https://github.com/solardev-xyz/freedom-ipfs/issues/30)), `routing` gains a list for them.
  - **`doh_endpoint`** is the DoH endpoint that DNSLink and `/dnsaddr` expansion ask. Main sends today's, Cloudflare's, explicitly.
    - It sits in `routing` beside the routers because it is checked and exempted exactly as they are: a [configured target](#the-gate).
  - **The routers and the DoH endpoint** are `http` or `https` URLs, read as the gate reads a configured endpoint: WHATWG, ASCII, no userinfo, a host it classifies, and no fragment.
    - An onion among them needs `socks5`: `direct` has [no route to one](#the-onion-route).
  - **`network`** is one of two forms:
    - `{ "mode": "direct" }`;
    - `{ "mode": "socks5", "ip", "port" }`.
      - `ip` is an IPv4 or IPv6 address written plainly: no brackets, no zone, no shorthand, no hex or octal. An IPv4-mapped IPv6 address is read as the IPv4 address it maps. It may not be unspecified, multicast or broadcast. Loopback and private addresses are allowed, since an external Tor may sit on the LAN.
      - `port` is from 1 to 65535.
      - No credentials are taken: the service makes each instance's own ([The SOCKS contract](#the-gate), *Stream isolation*).
      - `socks5` takes `routing.mode` `delegated` or `offline` only ([Open questions](#open-questions), 4).
  - The persistent process accepts one `disk` instance at a time. The ephemeral process accepts only `memory` instances of at most 32 MiB, and at most 8 of them.
  - A start is admitted only within the free [budget](#budgets). Anything else is `invalid_argument`, or `busy` when the budget isn't free.
- **`ipfs.request`:**
  - The `path` and `headers` are the plan's, passed through.
  - The service builds the gateway request with freedom-ipfs's own native-request parser (an [upstream change](#upstream-changes-in-freedom-ipfs) makes it public), so it treats requests exactly as the add-on does.
  - As main does today, it sets the request ID to the envelope ID and the top-level path to `path`.
  - `body` is false for `HEAD` and for 204, 205 and 304, which is main's rule today. Any bytes the gateway produces then are dropped.
  - A request is one JSON frame, within 0006's bounds of 64 KiB for the URL and 64 KiB for the headers.
    - **Main checks those bounds, the service doesn't.** Main measures them in UTF-16 units and the service would see bytes, so a check here could refuse what main accepted. The 1 MiB frame bound still applies.
    - **Within a frame, the parser refuses more distinct header names than a header map holds** (24,576 in http 1.x) as `invalid_argument`, rather than panicking (freedom-ipfs#39). Main's bound keeps a request well under that: 64 KiB of headers, at 5 or more units each, is at most 13,107.
  - **The parser decides the method,** in any case, as the add-on does: `get` is `GET`.
  - **`headers_ms`** is from 1 to 30,000, the [Bounds](#bounds) table's 30 s. Anything else is `invalid_argument`, as are unknown members. A refusal never quotes the input.
  - **Refusals, in order:** `invalid_argument` for the params, then `busy` at the admission bound, then `stopped` for an instance that isn't live.
- **No caller context.**
  - Every request is main's, for a request main has already admitted and fenced. The service has no per-caller policy.
- **One event from the service:** `ipfs.instance_retired { instance, reason }`, where `reason` is `"panic"`. The service sends it after retiring an instance on its own ([Panics](#crashes-hangs-and-restarts)), once its teardown has proven quiescence. It is never sent for a stop that main asked for.
  - The instance is the only partition. Main picks it from the session's partition, never from page input.

### Instance IDs

- **Never reused.** Main allocates each instance ID from a counter per process generation: `p-1`, `p-2`, … for the persistent instance, and `e-1`, `e-2`, … for private ones. A restart of the persistent instance, for example on a policy change, gets a new ID.
- **Every captured backend binds a pair:** the generation and the instance ID. `ipfsBackend()` captures it at admission, and every continuation carries it: the wait for a plan, the `request()` call, its body.
- **Retirement is synchronous in main.** When a stop, an eviction, a partition close or a policy change begins, main marks the pair retired before sending `ipfs.stop`. A continuation that reaches a retired pair fails at once with `freedom-ipfs native node is not running`, and nothing is sent.
- **The service checks too:** a request naming an ID that is retired or unknown gets `stopped`. A late request from before a change can therefore never reach the instance that replaced it, in either direction.
- **The service can retire an instance itself,** after a request panic. It fences the ID at once, so later requests get `stopped`. On `ipfs.instance_retired`, main marks the pair retired, as it does when it begins a stop. Continuations still holding it fail before sending, and leases on a private instance end as their requests do.

### Cancel, deadlines and admission

- **`cancel`:** see [Order](#frames) for the head and stream cases.
  - Cancellation reaches the work through the request's own token, a child of the instance's root token. That includes a blocking region, through its inner future.
  - The request's admission slot is released only when its work has ended, not when the reply is sent.
- **`headers_ms`:**
  - It runs from admission, so queue time and routing count. On expiry the request's token is cancelled and the reply is `deadline`.
  - A head that is queued, though not yet written, when `headers_ms` runs out is in time: the service's part is done.
  - So is any reply the work gives in a head's place, checked against `headers_ms` as a head is: a memory refusal (`busy`) or a head too large for a frame (`internal`), queued after it, is `deadline`.
  - After the head there is no deadline in the service. Main's 60 s body-idle timer (0006) cancels a stalled body.
- **Admission:** at most 512 requests per process, counting heads, open streams, and work still ending after a cancel. Beyond that the reply is `busy`.
  - **A slot is held until both its work has ended and its terminal is written:** the reply, the stream's `end`, or its abort. That covers "only when its work has ended" and "counting open streams" together.
  - Main sends at most 512 outstanding service requests, retiring ones included ([Frames](#frames)). So `busy` here signals a fault, and the reply is from the reader's bounded refusals.

### Errors

| Code | When | Main's backend rejects or errors with (today's text) |
|---|---|---|
| `invalid_argument` | the request can't be parsed: an unsupported method, path or header | `freedom-ipfs native request could not be started` |
| `stopped` | the instance is retired, unknown or stopping | `freedom-ipfs native node is not running` |
| `deadline` | no head within `headers_ms` | `freedom-ipfs native request timeout` |
| `cancelled` | main's `cancel` | `freedom-ipfs native request aborted` before the head; `…cancelled` for a body |
| `busy` | admission is full, or a reservation can't be had in time ([Budgets](#budgets)), or 4 stats calls are outstanding ([Stats](#stats)) | `BackendBusy`, `freedom-ipfs native node is busy`, which the executor answers 503 (new) |
| `internal` | a panic on the request's task, which then retires its instance | `freedom-ipfs native gateway error` |
| `storage` | `ipfs.start`: the store won't open (`data.kind`) | the manager's `Failed to start freedom-ipfs native node` |
| `protocol_mismatch` | `ipfs.hello` | a startup error; no restart |

- **HTTP failures are heads,** as today: 400, 404, 416, 502, 504, and the 503 `gateway_busy` with `Retry-After: 1` from the 15 s queue. They have bodies, and pass to the plan executor unchanged.
- **A target the gate refuses** fails that retrieval attempt as a connection failure would, so the head is upstream's usual 502 or 504.
- **Abort codes:**
  - `cancelled`;
  - `internal`;
  - `body_stream_error` (upstream's code for a failing body);
  - `stopped`;
  - `busy`: the stream's next block couldn't reserve memory within 10 s.

  Main errors the body with `freedom-ipfs native request cancelled` for the first, and with today's `freedom-ipfs native read failed` for the others.
- **Exit codes:**
  - 0001's: 64, 74, 75 and 76;
  - 70 for `teardown_unproven`, and for a panic or unexpected end outside a request.

### Stats

`ipfs.stats` returns what `getNativeDiagnostics()` shows today, under today's field names:
- **`gateway`:**
  - `active_native_handles` (the open requests);
  - `total_started`, `total_completed`, `total_failed`, `total_cancelled` and `total_freed`;
  - `total_gateway_busy_responses`, `bytes_read` and `max_active_handles`;
  - `last_native_error_code` and `last_native_error_message`.

  The service counts these itself. The event-queue fields go, with the queue: deviation `stats-fields`.
  - A request is started when admitted, and freed when its admission ends.
  - It is completed when its work queues its `end`, or a head without a body.
  - It has failed when the service gives it an error or an abort: `deadline`, `busy`, `internal` or `body_stream_error`. The last error is that failure's code and fixed message, or `gateway_busy` for such a head.
  - It is cancelled on main's `cancel`, whenever the connection accepts one: the request isn't settled, so its admission doesn't end, until the service's cancel callback has run.
  - `bytes_read` counts body bytes as they are queued for main, so a send cut short by a cancel counts what it queued.
  - An outcome is counted as the work ends, a moment after its terminal is queued, and before its admission ends. `started` and `freed` are counted under the admission table's lock, so `max_active_handles` never passes what was admitted.
- **`progress`:** the instance's progress snapshot, as `progressSnapshotJson()` gives it today: its active targets and its latest 512 events. A request's target is its envelope ID, the native request's ID as main sets it today; an event's `request_id` is the gateway's own count.
  - **The persistent process only.** In the ephemeral process, which records nothing, it is `null`.
  - **The reply fits one frame.** A snapshot's events are bounded by count, but neither they nor its active targets are bounded by bytes. If the reply would pass 1 MiB, it keeps as many active targets as fit, in order, then as many of the newest events as fit. `active_count` and `event_count` stay the recorder's, so a reader can tell what was cut.
  - Main has no `clearProgress`, and neither does the service: a target closes when its request ends or its span closes.
- **`store`:** `block_count` and `total_bytes`, or `null` if the store can't say.
- **`budget`:** each [budget's](#budgets) use and limit:
  - `memory` (`used`);
  - `requests` (`admitted`) and `writer` (`queued`);
  - `block_fetches`, `http_provider_requests` and `dht_queries` (`in_flight`), and `bitswap_connections` (`in_use`, `waiting` and `denied`);
  - the instance's `background` queue (`outstanding` and `dropped`).

  Each has its `limit`. All but `background` are the process's, as the budgets are.

The store's figures are SQLite queries, which can wait behind a statement in progress, so they run as a job on the process runtime's blocking pool:
- **The 5 s deadline** runs from when the reader handles the request. The job's reply is queued only before it, checked under the connection's lock as a head is; from then on the reply is `deadline`, whichever of the job and its watcher runs first.
- **At most 4 stats calls are outstanding in the process.** Main asks every 5 s and gives up at 20 s, so it never has more asked. A call counts from its admission until its reply has been written and flushed: the reply holds the call's place, as a head holds its charge ([Pending replies](#budgets)). A call whose job ends without that reply (aborted before it ran, fenced, or answered `deadline`) is freed when the job's closure is dropped. Never just because its job ended or its request was answered. Past the bound, the reply is `busy`. If main stops reading, the writer stall ends the connection, and what is queued goes with it.
- **A cancel or the deadline fences the job,** which then runs no SQL, and aborts it if it hasn't started. A job that starts past its deadline runs no SQL either, and its reply is `deadline`, whether or not its watcher has run. SQL already running finishes, and its reply is checked as above.

The 5 s health check calls `ipfs.stats`. `checkHealth()` stays synchronous, because `ipfsBackend()` calls it at admission. It reads a snapshot that is true while all of these hold:
- the generation is live;
- the instance is started (for the persistent node; private partitions use [readiness per partition](#private-windows));
- the last stats reply is under 15 s old.

## Budgets

Upstream's constants are per instance, and some limit bookkeeping rather than work. So the service enforces its own budgets, **per process, across all of its instances**. Each one says what it charges.

- **Retrieval admission:** each permit is held for the whole operation, including any blocking region. A shared limiter is passed to every instance's builder. The limits:
  - 256 block fetches in flight;
  - 16 HTTP provider requests;
  - 32 Bitswap connections;
  - 4 DHT queries.

  Work beyond them waits, under its request's deadline. Upstream's per-instance limits still apply inside them.
- **Background queues:** an instance's background work (provider lookups, Bitswap wants, DHT queries started without a request) waits in a queue of at most 64 items per instance. When it is full, new background work is dropped, never request work.
  - Upstream's HTML prefetch and warm options stay off, as their defaults are.
- **The memory budget,** one per process: **192 MiB** for the persistent process and **448 MiB** for the ephemeral one.
  - **It is enforced by reservation.** Every accounted allocation reserves its bytes from the budget before it is made, and releases them when it is freed.
  - Reservations are atomic against one counter, so concurrent fetches and puts can't together pass the budget.
  - Nothing is measured after the fact.
- **Fixed reservations,** taken when an instance starts and held until its teardown ends:
  - **its store:**
    - A memory store is opened with `PRAGMA max_page_count`, so SQLite itself refuses growth past the reservation (`SQLITE_FULL`). A private instance reserves 36 MiB: its 32 MiB block target, plus 4 MiB for metadata and b-tree pages.
    - A disk store reserves its page cache, set with `PRAGMA cache_size` to 8 MiB.
  - **its caches:** the hot cache, the gateway's small-body cache (2 MiB) and the UnixFS metadata cache (1 MiB), each built with a fixed capacity and reserved at it.

  An instance starts only if its fixed reservation fits.
  - The service reserves it at admission, before the store opens, from the store's options and the gateway configuration.
  - The hot cache's part is the store's own figure for its options (`StoreOptions::hot_cache_fixed_bytes`): what the opened cache holds, its own structures included, so a target smaller than they are is counted as upstream opens it.
  - The caches' part is handed to upstream's builder, which reserves it again as it builds. If other work takes it in that moment, the start's job fails it with `busy`, and the ID is retired, as after any failed start.
  - The page cap counts SQLite's default 4096-byte pages.
- **In all:**
  - a private instance reserves 43 MiB (36 + 4 + 2 + 1), so eight reserve 344 MiB;
  - the persistent instance reserves 27 MiB (8 + 16 + 2 + 1);
  - with the writer's 16 MiB, that leaves 88 MiB of the ephemeral budget, and 149 MiB of the persistent one, for dynamic reservations.
  - At 2 MiB per fetch, that is about 44 and 74 concurrent block fetches.
- **Dynamic reservations:**
  - **Transient blocks:**
    - Before any block fetch, over HTTP or Bitswap, the fetch reserves the retriever's maximum block size (2 MiB).
    - So the memory budget, not the 256-fetch admission, usually decides how many fetches run at once.
  - **Reservations follow physical allocations:**
    - A reservation is attached to the buffer it pays for, and released when that buffer's last owner drops it, whoever that is.
    - **Truing down:** a 2 MiB reservation shrinks to the block's size only once the block's bytes sit in an allocation of that size, copied out or shrunk in place, and the larger backing has been freed. A small block that still points into a larger receive buffer stays charged for the larger one.
    - **Shared bytes stay charged dynamically:** a block's dynamic reservation lasts until its last owner outside a fixed reservation is gone. Examples:
      - a stream that still holds the block after the put;
      - a stream that holds it after the hot cache evicted it;
      - a block whose put failed or met the page cap.
    - **Moving a charge to a fixed reservation** happens only when the fixed owner covers the allocation for the rest of its life. For example, the hot cache holds the only reference, counted by its backing capacity. Until then, the bytes may be counted twice, which errs on the safe side.
  - **The put into a store:**
    - SQLite copies a block into its own pages, which the store's fixed reservation and page cap cover. The fetched buffer keeps its own dynamic reservation until its last owner drops it.
    - A write that meets the page cap fails with `SQLITE_FULL`, whether it is a block, a name or a provider record, and that entry isn't cached. A block is still served, from its transient buffer.
  - **Pending replies:** each head reserves what it holds, before it is encoded: its JSON, encoded in a buffer of exactly that size, and its frame header. The reservation lasts until the writer has written and flushed the head, or the reply that took its place, and freed its buffers. A head that doesn't fit the writer's 64 KiB buffer is written from its own buffer, never copied. If the writer fails, what is queued is freed first, every head's JSON with it, and the reservations only then; nothing more is queued.
    - Stats replies aren't charged to the memory budget; they are bounded instead. At most 4 stats calls are outstanding, their replies counted until written ([Stats](#stats)), each encoded in a buffer of exactly its length, within one frame (1 MiB). Charging them would fail the health check under memory pressure, exactly when main most needs it.
    - A reply's 1 MiB doesn't bound the memory its job works in. Its progress snapshot is a copy of the whole recorder, taken under the recorder's lock before it is fitted to the frame: library memory outside the budget, as the recorder itself is. What bounds it is what the recorder holds: its latest 512 events and its active targets, one per request in progress (at most the 512 admitted), each with its path.
  - **The writer's data queue:** 16 MiB, reserved at process start.
- **When admitted work can't reserve:**
  - **before its head,** it waits up to its remaining `headers_ms`, then answers `busy` (503).
    - The reply is `busy` when the refusal is queued before `headers_ms` ends, and `deadline` otherwise: the refusal is checked against the head's deadline under the connection's lock, as a head is. Upstream's 503 `memory_budget` is that refusal.
    - The waits end 50 ms before `headers_ms` does (or half way, if less is left), so `busy` is the usual answer. The margin is a scheduling allowance, not a guarantee: a refusal whose work runs late is `deadline`.
    - If upstream moves on to another source after a refusal, as delegated routing's Bitswap fallback does, its answer can come after `headers_ms`. The reply is then `deadline`.
  - **after its head,** a stream's next block fetch waits up to 10 s, then the stream aborts with `busy`, a truncation.
    - The 10 s start with each read of the body, and that read's fetches share them.
    - Upstream gives a body no typed error, so the service tells a refusal by its text (`memory budget`).
  - **background work** is dropped at once.
- **What it doesn't charge:** the disk store's file, which lives on disk, not in memory; a body's chunk while the service sends it; and allocator and library overhead it can't see.
  - A streamed file's chunks and a directory listing are copies upstream makes, not views of its blocks, so they hold no reservation. The service holds one chunk per stream while it is sent.
  - The exception is a whole file of 64 KiB or less served from the gateway's small-body cache: its bytes stay covered by that cache's fixed reservation. A small range of a file, or a body the cache didn't take, is a copy like the rest.
  - **A file's chunk** carries at most 64 KiB of payload, assembled from its blocks' bytes. Its buffer can be larger: it keeps the spare capacity the assembly grew into, about 96 KiB for a 64 KiB chunk built from two 48 KiB leaves. So the files' chunks come to at most 32 MiB of payload across the 512 admitted requests, and more in memory.
  - **A directory listing** is rendered whole and sent as one chunk. Its size follows the directory's links, not the 64 KiB: a directory of 1,024 links with 100-byte names renders to about 320 KiB.
  - Upstream's fix is chunks that are zero-copy views of their blocks (`ChargedBytes`), which keep their reservation until the last of them is dropped, and listings that are reserved as they are rendered.
- **What a store's `max_bytes` means:** a target for block data that drives LRU eviction.
  - On disk it bounds nothing hard. Retained blocks and metadata can pass it, and the file's size follows it only loosely.
  - In memory, the hard bound is the page cap above, and `max_bytes` is the eviction target inside it. Blocks that are retained while being streamed can't be evicted, so when the cap is reached, new blocks go uncached rather than the store growing.
  - Metadata tables have their own rules: names are pruned to 128 rows, while provider and failing-provider records expire. For memory stores, all of it sits inside the page cap.
- **Under pressure:**
  1. new requests get `busy` (503);
  2. idle private instances are evicted first ([Private windows](#private-windows));
  3. admitted work waits, or ends, as above.

  The process doesn't promise a bound on memory it can't account for. An OS-level limit is an [open question](#open-questions).
- **Stopping instances** keep their reservations until their teardown is complete.

## Main's side

`ipfsBackend()` keeps its contract (#704):

```js
ipfsBackend({ partition }) → { ref: { ipfs: 'native', up }, url: null,
                               request({ path, method, headers, signal, headersTimeoutMs }) → Promise<Response>,
                               release() }            // idempotent
```

- **What changes:**
  - It takes the request's partition. `ipfs-protocol.js` already has it, from its `privatePartition` registration.
  - It captures the generation and instance ID ([Instance IDs](#instance-ids)).
  - A private partition gets its own instance, started inside `request()` ([Private windows](#private-windows)).
  - The core still sees only `ref`.
- **The lease:**
  - For a private partition, `ipfsBackend()` pins the partition's instance, or reserves a new one. It returns the pin as `release()`. For the persistent instance, `release()` does nothing.
  - **The handler releases it in one place:** `dweb-handler.js` wraps its whole handling in a `finally` that calls `release()`, unless a body has been handed on. In that case the fetch's `onEnd` calls it.
  - **That covers every exit:**
    - a redirect plan, or an error plan (400, 404, 405, 415, 502, 503);
    - a URL or header refusal;
    - a failed lookup;
    - a core that is unavailable or `busy`;
    - admission's 503;
    - an abort before the fetch;
    - a rejected `request()`;
    - the body's end, error or cancel.
  - `release()` is idempotent, and `closeDwebSession(partition)` releases every lease the partition still holds, as a backstop.
- **Capacity:**
  - When a private partition needs a new instance and none can be reserved, `ipfsBackend()` throws `BackendBusy`.
  - The handler answers it before planning, as it answers `AdmissionFull`: 503 `{ code: 503, message: "Too many private windows are loading IPFS content" }`, the shape of every error body the handler writes.
  - Node readiness stays `ref.up`.
- **The executor:** one change. A `BackendBusy` rejection from `request()` (the service's `busy`) becomes 503 `{ code: 503, message: "freedom-ipfs native node is busy" }`, as `AdmissionFull` does. Every other rejection is the 502 it is today.
- **`request()`:**
  - **An already aborted signal** rejects at once. Nothing is sent, as today. So does a captured pair that has been retired.
  - **Otherwise** it sends `ipfs.request` with `headers_ms: headersTimeoutMs`, and registers one abort listener that sends `cancel`.
  - **On the head** it resolves `new Response(body, { status, headers })`:
    - `body` is `null` when the head says `body: false`;
    - otherwise it is a byte `ReadableStream` whose `pull` takes the next buffered bytes and returns them as credit;
    - its `cancel` starts retirement ([Frames](#frames)).
  - **A rejection** carries today's message ([Errors](#errors)). The executor's `failure()` makes it the same 502 as today.
- **End of a body:**
  - **On `end`,** main only records EOF and keeps the ring. The stream closes, and the ring is freed, when the consumer has read every byte.
  - **On `abort`,** the stream errors at once and its bytes are dropped.
  - **Every terminal path frees:**
    - after `end`, the record and its ring go once the consumer has drained them;
    - after `abort`, a local cancel or the end of the generation, they go at once.

    The executor's `onEnd` releases the admission slot.

  The executor's contract is unchanged: a pull-driven body, truncation surfaced as an error, and nothing started for a signal that is already aborted.
- **The client:**
  - `core-client.js`'s supervision becomes a shared `ServiceClient`: spawn, the handshake, generations, restart back-off, kill, the frame reader and the writer with reserved control room.
  - `freedom-cored`, `freedom-ipfsd` and 0008's `freedom-radicled` each configure their own instance of it.
  - `frame.js` accepts kinds `0x02`–`0x05` only on a connection whose handshake granted `stream`.
- **Main's memory:**
  - stream storage is one 128 KiB ring per live stream, a stream with undrained bytes after EOF included: 32 MiB at 256 active fetches, which is both the live-byte window and the backing storage;
  - the decoder adds at most one partial frame (≤ 1 MiB);
  - retiring streams hold no bytes;
  - this is separate from 0005's chain I/O pool.

## Private windows

- **The decision:** one ephemeral process per profile serves all private windows. It holds **one in-memory instance per private partition**.
- **Rejected alternatives:**
  - **A cache partition in the persistent store:** private loads would write blocks, resolved names and provider records into the profile's SQLite file, where WAL and free pages outlive any deletion.
  - **One instance for all private windows:** Freedom gives every private window its own partition. A shared cache would let one private window probe another's loads by timing.
  - **A process per private window:** separate address spaces as well as separate caches, at the cost of a runtime and a spawn per window. That would contain a memory compromise in one private window, as far as the OS's process protections go. This design accepts a single compromise domain for all private windows instead ([Open questions](#open-questions)).
- **What the instances guarantee, and what they don't:**
  - **They do partition:** each partition has its own store, caches and Bitswap PeerID, so nothing loaded in one is served from or timed against another's cache, or the profile's.
  - **They don't partition memory:** the ephemeral process is one address space and one compromise domain. Process separation is not an OS sandbox.
- **Readiness is per partition** (`ipfsBackend({ partition })`):
  - **`ref.up` is node readiness only:** the profile's IPFS is bundled and `RUNNING`, and the ephemeral process isn't stopped after three crashes. So a cold partition still gets a fetch plan.
  - **A partition with a live or pending instance** pins it and uses it, however many instances are pinned.
  - **A partition without one** needs a new instance, and only then is capacity checked. A slot is reserved if fewer than 8 instances exist, or if one of them is unpinned and can be evicted. The reservation is a pending instance, pinned by this request's lease.
  - **No slot** means all 8 instances are pinned by other partitions. `ipfsBackend()` throws `BackendBusy`, and the handler answers 503 `busy`. That is distinct from the 503 of a node that isn't running ([Main's side](#mains-side)).
- **The cold start runs inside `request()`:**
  - It spawns the ephemeral process if needed (with `ipfs.hello`), then sends `ipfs.start` for the partition's instance, then the request.
  - Each waiting request runs under its own signal and its own `headers_ms`, and the head deadline covers the start.
  - **Concurrent first requests from one partition share one start (single flight).** The start belongs to the partition, not to the request that began it:
    - every waiting request holds a lease on the pending instance;
    - one waiter's abort or deadline rejects that waiter and releases its lease only;
    - the start itself is cancelled when its last lease is released, or when the partition or the generation is retired;
    - a cancelled start retires its pending instance ID first. Each step of the start (the spawn, `ipfs.hello`, `ipfs.start`, then the request) checks the pair before it sends, so nothing is sent late to a retired or evicted ID.
  - When the slot came from an eviction, the new instance's `ipfs.start` waits for the evicted one's teardown to release its reservations, within the same deadline.
- **Pinning is the lease:**
  - A pin is taken in `ipfsBackend()` and released by the handler on every exit ([Main's side](#mains-side)).
  - So a pinned instance is held through planning, preparation and use, and never longer.
  - **Eviction picks only unpinned instances:** the least recently used one with no pins.
- **Fences:**
  - **Eviction and `closeDwebSession(partition)`** retire the instance's ID first, so every continuation that captured it fails before sending. Then comes the [teardown](#instances-and-their-teardown).
  - **A close during the cold start** cancels the start. The instance, if it came up, is torn down.
  - **When the last instance has stopped,** main sends `ipfs.shutdown`, and the process exits with everything it held.
- **Bounds:**
  - at most 8 live instances;
  - each has a 36 MiB page cap with a 32 MiB block target inside it, and a hot cache of 4 MiB (an upstream option), under the process's 448 MiB [memory budget](#budgets).
- **What stays out of the application's files:**
  - `SqliteBlockStore::in_memory`, with `temp_store = MEMORY` ([upstream](#upstream-changes-in-freedom-ipfs)), so SQLite writes no temp files;
  - no data directory and no lock;
  - logs without paths, and panic lines without payloads;
  - no progress recorded: the process installs no tracing subscriber, so no path or CID is recorded, even in memory, and `ipfs.stats` reports `progress: null`;
  - no core dumps ([Spawn](#spawn)).

  The OS's swap and hibernation files are outside this guarantee.
- **Identity:**
  - each instance's Bitswap swarm has its own fresh identity, and DHT queries use a new one each time, as upstream does;
  - so a private partition shares no PeerID with the profile's node or another partition;
  - it does share the machine's IP address, unless the [network policy](#network-policy) sends traffic through Tor.
- **Restarts:** the ephemeral process follows the same rules. Its instances come back lazily, cold and under new IDs. So does a private instance retired after a request panic; the other partitions' instances keep running.
- **The nodes panel** keeps showing the persistent node only.

## Network policy

### What can be honored

- **`reqwest`:**
  - SOCKS5, once its `socks` feature is on.
    - With `socks5://` rather than `socks5h://`, the client resolves the name with its own resolver, which can be replaced (`ClientBuilder::dns_resolver`), and hands the proxy an IP.
    - TLS SNI and `Host` still use the URL's name.
    - **One trap:** in reqwest 0.12.28's SOCKS connector, a resolver that succeeds with no address makes the connector keep the original name and send it to the proxy unresolved (`connect.rs`, lines 1869–1885). So an ordinary name must never resolve to an empty success ([The resolver contract](#the-resolver-contract)).
    - **A second trap:** with hyper-util 0.1.20 and older, a resolved IPv6 address reaches the proxy as a domain, `"[2001:db8::1]"`, because the bracketed host isn't parsed as an address. hyper-util 0.1.21 sends it as an IPv6 address. The network code requires hyper-util 0.1.21 or later.
    - **IP-literal hosts:** under `socks5://` they reach the client's resolver, IPv6 bracketed. Without a proxy they never do: hyper-util's HTTP connector connects to a literal directly. So the gate checks a literal URL host itself, in the redirect loop ([hop check 4](#the-gate)), not only in the resolver.
    - **The resolver sees a name, never its port.** An exemption by exact host and port can't be expressed there, so configured targets are reached through clients of their own ([The gate](#the-gate)).
    - **The connector can't see the destination:** `ClientBuilder::connector_layer` receives it as an opaque type, and under `socks5h://` the resolver isn't called either. A check on an onion client's destination sits in its own send path ([The onion route](#the-onion-route)).
  - Every client must be built with an explicit proxy or with `no_proxy()`. Today none sets either (`ns:828`, `rt:1807`, `rv:11132`), so the environment decides.
  - Redirects can be left to the service: with `Policy::none()`, every 3xx comes back to the caller, which decides each hop itself.
- **libp2p 0.56:**
  - It has no SOCKS transport. TCP, and WebSocket over TCP, can go through a small custom `Transport` over `tokio-socks`. Its `tor` feature also speaks Tor's `RESOLVE` extension.
  - **QUIC can't be proxied:** Tor carries TCP only, and Arti doesn't offer SOCKS5 `UDP ASSOCIATE`.
  - **libp2p's own resolver** (hickory, `ResolverConfig::cloudflare()`, plain DNS to 1.1.1.1 on port 53; `rt:1601`, `rv:8847`) must be off under a proxy.
  - **`/dnsaddr`** needs TXT records. Under a proxy they come from DoH through the proxied client, as Bitswap's address expansion already uses DoH (`rv:9435`).
  - An embedded Tor client (`arti-client`) is not used: Freedom already runs Arti, and a second Tor client in the service would duplicate it.
- **Arti** answers Tor's SOCKS `RESOLVE` extension (command `0xF0`), resolving a name through the Tor network. A qualification test checks the pinned Arti's support before the setting ships ([The gate](#the-gate), *The SOCKS contract*).
- **freedom-ipfs v0.4.6 honors none of this:**
  - the clients and transports are built inside the crates;
  - QUIC is always added (`rt:1597`, `rv:8825`);
  - the DoH resolver is fixed at `mob:2226` and `rv:9436`, `9484` and `9531`;
  - there is no hook where a target can be checked.

### Modes

- **`direct`, the default:** today's transports, behind [the gate](#the-gate). The environment's proxy variables no longer apply (deviation `env-proxy`).
  - **The gate comes to `direct` in two parts.**
    - **With `socks5`, the classification and the capability:** onion targets, and multiaddrs that aren't network targets, are refused before any socket exists; the service's own loop follows redirects (`http` and `https` only, no `Referer`); and revoking the capability stops every later socket, DNS query and hop.
    - **With NAT64 discovery, the address table.** Without discovery, every IPv6 target outside the fixed forms would be refused ([Network-specific NAT64 prefixes](#network-specific-nat64-prefixes)). Until the service learns the prefixes, `direct` resolves and connects as today (the system's resolver for HTTP, libp2p's DNS layer for peers) and applies no address table, so the deviation `address-policy` applies to `socks5` only.

    `socks5` needs no discovery, and ships first ([Implementation steps](#implementation-steps), step 8).
- **`socks5 { ip, port }`:** all of the service's traffic goes through the proxy.
  - **The endpoint is an IP literal,** so reaching the proxy needs no DNS. The service never resolves the proxy's name.
  - **Ordinary names:**
    - They are resolved through the proxy with `RESOLVE`, never by a local resolver.
    - Each answer passes [the gate](#the-gate), and the connection goes to a checked address, as an IP literal in SOCKS `CONNECT`.
    - TLS SNI and HTTP `Host` keep the name.
    - A failed lookup, an empty answer, or an answer whose every address is refused is an error ([The resolver contract](#the-resolver-contract)).
    - `RESOLVE` answers one address and can't ask for a family, so `/dns4` and `/dns6` resolve as `/dns` does.
  - **Onion names** take a separate, explicitly authorized route, and are handed to the proxy as names ([The onion route](#the-onion-route)).
  - **HTTP:** delegated routing, DoH and HTTP providers, all through the proxy this way.
  - **Configured endpoints too:** a router on the local machine or network is reached through the proxy, and fails there unless the proxy can reach it. Nothing is direct in this mode.
  - **Bitswap:** TCP and WebSocket through the SOCKS transport. QUIC and hickory are off.
  - **Routing:** `delegated` by default, since the light DHT dials dozens of peers per query, each through Tor.
  - **Fails closed:**
    - a proxy that is down, or one that refuses `RESOLVE`, fails the attempt, which gets upstream's 502 or 504;
    - nothing falls back to a direct socket;
    - a transport the proxy can't carry (QUIC, or any other non-TCP transport) is refused before any socket exists.
- **Where the proxy comes from:**
  - A new per-profile setting, **Route IPFS through Tor**, off by default, sends Arti's SOCKS endpoint from `tor-manager`, as an IP and port.
  - Today Tor in Freedom means onion access. Clearnet and the dweb protocols stay direct (`docs/features.md`), and this design keeps that default.

### The gate

**One classification, before anything else.** Every target is classified once, before any DNS or TXT expansion, by one function shared by URLs and multiaddrs:
- **Normalization of a host:** lowercase it, remove one trailing dot, and refuse non-ASCII (names must already be in punycode).
  - URL hosts are parsed with the WHATWG rules, so numeric IPv4 forms (`0x7f.1`, `2130706433`) become literals.
  - **An address is classified by its parsed binary value, never by its text.** Every spelling of one address is one target: `[::ffff:a9fe:a9fe]`, `[::ffff:169.254.169.254]`, `[0:0:0:0:0:ffff:a9fe:a9fe]`, upper-case hex, and `/ip6/::ffff:169.254.169.254` in a multiaddr.
  - IPv6 forms that embed an IPv4 address are classified by that address, as [Addresses](#addresses) says.
- **The classes:**
  - **onion:** the last label is `onion`, whether in a URL host or in `/dns`, `/dns4`, `/dns6` or `/dnsaddr`; and every `/onion3` (or `/onion`) multiaddr;
  - **IP literal:** a URL host, or an `/ip4` or `/ip6` component;
  - **name:** everything else.
- **A multiaddr that is dialed** is checked whole, against the shapes the transports support. It has exactly one host component, and it comes first:
  - `/ip4`, `/ip6`, `/dns`, `/dns4` or `/dns6`, then `/tcp/<port>`, optionally followed by WebSocket: `/ws`, `/wss` or `/tls/ws`. `/ws` and `/wss` include their path-carrying forms, `/x-parity-ws/<path>` and `/x-parity-wss/<path>`: the path goes in the WebSocket request and doesn't change the destination;
  - an HTTP provider: `/ip4`, `/ip6`, `/dns`, `/dns4` or `/dns6`, then an optional `/tcp/<port>`, then `/http`, `/https` or `/tls/http`. Without `/tcp`, the port is the scheme's default (80, or 443 for HTTPS), and the configured-target exemption compares that effective port;
  - `/ip4`, `/ip6`, `/dns`, `/dns4` or `/dns6`, then `/udp/<port>/quic-v1`;
  - `/dnsaddr/<name>`, which expansion replaces before any dial;
  - `/onion3/<address>:<port>` (or `/onion`);
  - each optionally ending in one `/p2p/<peer>`.

  Every other sequence is refused, whatever its first component:
  - **A second host component anywhere.** libp2p's TCP transport dials the *last* IP and port in a multiaddr, and its DNS layer resolves *every* DNS component. So `/ip4/8.8.8.8/ip4/127.0.0.1/tcp/8080` would be checked as `8.8.8.8` while it connects to loopback, and `/ip4/8.8.8.8/dns/x.onion/tcp/80` would hide an onion name. The checked target must be the one the transport dials.
  - **`/ip6zone`, anywhere:** it scopes an address to one local link.
  - **`/unix` and `/memory`, anywhere:** they aren't network targets.
  - **`/ipcidr`, `/p2p-circuit`, and any component the shapes above don't name,** an extra trailing component, or a second `/p2p`.
  - **`/sni`, for now.** Neither pinned implementation uses it to name the TLS server: libp2p-websocket recognizes TLS only when `/tls` immediately precedes `/ws`, and freedom-ipfs's HTTP conversion reads `/tls/sni/<name>/http` as plain HTTP. Accepting `/tls/sni/<name>/ws` (AutoTLS peers advertise it) or `/tls/sni/<name>/http` needs that transport and conversion work first, with tests that TLS is used and its server name is the `/sni` name.

  **The same shapes apply after expansion:** every multiaddr a `/dnsaddr` answer yields is checked whole again ([check 2](#the-gate)).

**The policy:**
- **Configured targets** are the delegated routers and DoH endpoint in `ipfs.start` (`routing.delegated_routers` and `routing.doh_endpoint`). They are exempt from the address policy, by exact host (and port), including when one is local.
  - An HTTP client's resolver sees a name, never its port, so configured targets are reached through clients of their own, whose resolver doesn't filter but still never answers empty. The redirect loop picks the client for each hop from its scheme, host and port: a configured host on another port, reached by a redirect, is untrusted.
  - **Arti's endpoint is not a target.** In `socks5` mode it is the transport that every connection goes through, so the service connects to it without asking the gate. A target at its address, as a literal or as a name's answer, is untrusted like any other, so the network can't point the service at the proxy's port.
- **Untrusted targets** are everything learned from the network:
  - provider records and their multiaddrs;
  - HTTP provider URLs built from them;
  - `/dnsaddr` results;
  - DHT peers;
  - redirect targets, even from a configured endpoint.
- **The address policy, by default,** accepts an untrusted target only at a globally reachable unicast address. It refuses, as [Addresses](#addresses) lists them:
  - loopback, "this network" and the unspecified address;
  - private ranges (RFC 1918, `fc00::/7`) and the deprecated site-local `fec0::/10`;
  - link-local (`169.254.0.0/16`, `fe80::/10`);
  - shared address space (CGNAT, `100.64.0.0/10`);
  - multicast, broadcast, and the documentation, benchmarking and reserved ranges;
  - the IETF protocol blocks (`192.0.0.0/24`, `2001::/23`);
  - IPv6 outside global unicast (`2000::/3`);
  - every IPv6 form that reaches the IPv4 address it embeds, when that address is refused or the embedding can't be read ([IPv6 forms that embed IPv4](#ipv6-forms-that-embed-ipv4));
  - while the network's NAT64 prefixes aren't known, IPv6 addresses outside the fixed forms ([Network-specific NAT64 prefixes](#network-specific-nat64-prefixes)).
- **Onion targets:**
  - in `direct` mode, refused before any socket exists, as the session's onion gate refuses them (`OnionGateRefusal`);
  - in `socks5` mode, handed to the proxy as names, never resolved locally. They are the one separately authorized case of a name the service doesn't resolve.

**Where it is applied:**
1. **Before expansion:** the original target is classified, and an onion or a refused literal stops here. Nothing is expanded or resolved for it.
2. **After expansion:** every address that `/dnsaddr` or DNS expansion produces is classified and checked again.
3. **Before each connection,** at the transport, in both modes alike:
   - a name is resolved: locally in `direct` mode, through the proxy's `RESOLVE` in `socks5` mode;
   - every address is checked;
   - the connection is pinned to one that passed: `connect()` in `direct` mode, a SOCKS `CONNECT` to that IP literal in `socks5` mode.

   A name whose answers change between checks can't move a connection, because the address that was checked is the address connected to. Each new connection resolves and checks again.

   **The check wraps the transport,** not the service's dial sites, so it also covers the dials libp2p makes itself: Kademlia's own, and dials to addresses learned through identify, which runs on existing connections and dials nothing itself. In `direct` mode it sits twice: outside libp2p's DNS layer, asking the capability and classifying the target before any query starts, and below it, checking each resolved address before `connect()`.

   **Candidate choice knows the transports.** Where providers' addresses are ranked and cut to two per peer, addresses the policy can't dial (QUIC in `socks5` mode, refused targets) are dropped first, so a peer never keeps only addresses that can't be used. Provider URLs are built from a multiaddr's parsed components, never by joining its text.
4. **On every HTTP redirect hop:**
   - The service follows redirects itself: every client is built with `Policy::none()`.
   - For each hop, its own loop classifies the `Location` target, runs the gate, picks the client again (the ordinary one, or in `socks5` mode the [onion route](#the-onion-route)), and counts the hop against that client's acceptance.
   - That covers delegated routing, DoH and providers. A refused hop fails the attempt.
   - **Schemes:** a `Location` must be `http` or `https`; any other scheme is refused. HTTPS to HTTP is followed, as reqwest's default acceptance follows it today (parity), and like every hop it sends no `Referer`.
   - **IP-literal hosts are checked by the loop itself:** without a proxy, a literal never reaches the client's resolver.
   - **Each hop is a fresh request,** built from the operation's own fixed headers, never by copying the previous hop's. Because the service follows redirects itself, it doesn't rely on reqwest's header stripping:
     - The service sends no request credentials. A configured endpoint can't carry userinfo, `Authorization`, cookies or proxy credentials: a URL with userinfo is refused when the setting is read, and no client has a cookie store.
       - Under `socks5` the instance's SOCKS credentials are a different thing: they go only to the proxy, in its handshake, never in a request header. Every hop carries them, the configured and onion clients' included ([The SOCKS contract](#the-gate), *Stream isolation*).
     - Even so, a hop that changes scheme, host or port drops every header scoped to an authority (`Authorization`, `Cookie`, `Proxy-Authorization`).
     - No hop sends `Referer`.
     - Methods follow reqwest's rules: 303, and 301 or 302 after a `POST`, become a `GET` without a body; 307 and 308 keep the method and body.
     - One hop budget covers the whole chain, including hops that change client between the ordinary and onion routes.

**The SOCKS contract** (a decision):
- **(a), chosen:**
  - resolve ordinary names through the proxy;
  - filter the answers;
  - pin the chosen address for `CONNECT`, keeping SNI and `Host`.

  The address policy is then the same promise in both modes, enforced by the service itself, for every address the service resolves and pins. Translation on the exit's own network is outside it ([What the gate can't see](#what-the-gate-cant-see)).
- **(b), rejected:** delegate the policy to the proxy. Tor's exits refuse private destinations by default, but that is an exit operator's setting and Arti's configuration, neither of which the service can guarantee. And a SOCKS reply doesn't prove which address was connected.
- **If the pinned Arti can't `RESOLVE`,** the setting doesn't ship until it can, unless the user accepts (b) as an explicit deviation ([Open questions](#open-questions)).
- **Stream isolation** (the user's decision, [Open questions](#open-questions), 11): each instance sends SOCKS5 credentials of its own, so Arti keeps its streams on circuits of their own.
  - **Who is kept apart:** the profile's instance and each private window's, from one another, and from other users of the same Arti that send no credentials.
  - **The credentials** (RFC 1929) are made when the instance's network is built: a fixed username, and a password of 128 random bits from the operating system.
    - They live in memory for the network's lifetime, and are never persisted or logged. Their `Debug` form is redacted, and no error carries them. They leave the process only to the proxy.
    - **If the operating system can't supply the randomness,** `ipfs.start` fails with `internal` and a fixed message. No instance is built, and nothing falls back to a fixed password or to no authentication.
  - **Every stream carries them:** `RESOLVE`, the libp2p transport's `CONNECT`, and the HTTP clients', the onion client's included.
  - **No fallback:** each client offers only username/password authentication, so a proxy that won't take it fails closed rather than sharing circuits silently.

#### Addresses

**The rule:** an untrusted target must be a globally reachable unicast address.
- **The source** is IANA's [IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) special-purpose address registries (RFC 6890), as of 2026-10-19:
  - every block whose *Globally Reachable* is False or N/A is refused;
  - so is the multicast space, and the IPv6 space outside global unicast ([IPv6 address space registry](https://www.iana.org/assignments/ipv6-address-space/));
  - where a block's embedding of an IPv4 address can be read, the IPv4 policy decides instead ([below](#ipv6-forms-that-embed-ipv4)).
- **The gate's code holds one table** of the blocks below. Tests are generated from it, and a test pins the table to the lists here.
- **A registry change is a design change:** the table changes only with this section.

##### IPv4

Refused:

| Block | What it is | Reference |
|---|---|---|
| `0.0.0.0/8` | "this network", with `0.0.0.0` ("this host") | RFC 791 §3.2; RFC 1122 §3.2.1.3 |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | private use | RFC 1918 |
| `100.64.0.0/10` | shared address space (CGNAT) | RFC 6598 |
| `127.0.0.0/8` | loopback | RFC 1122 §3.2.1.3 |
| `169.254.0.0/16` | link-local | RFC 3927 |
| `192.0.0.0/24` | IETF protocol assignments, the whole block (see below) | RFC 6890 §2.1 |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | documentation | RFC 5737 |
| `192.88.99.0/24` | the deprecated 6to4 relay anycast prefix, with the 6a44 relay at `192.88.99.2` | RFC 7526; RFC 6751 |
| `198.18.0.0/15` | benchmarking | RFC 2544 |
| `224.0.0.0/4` | multicast | RFC 5771 |
| `240.0.0.0/4` | reserved, with the limited broadcast address `255.255.255.255` | RFC 1112 §4; RFC 919 §7; RFC 8190 |

- **`192.0.0.0/24` is refused whole.** It holds:
  - the service continuity prefix (RFC 7335);
  - the dummy address (RFC 7600);
  - the NAT64 discovery addresses (RFC 7050, RFC 8880);
  - the PCP and TURN anycast addresses (RFC 7723, RFC 8155).

  The two anycast addresses are globally reachable, but no provider or peer is addressed there, and one entry for the block keeps the table simple.
- **Globally reachable registry blocks pass:** AS112 (`192.31.196.0/24`, RFC 7535; `192.175.48.0/24`, RFC 7534) and AMT (`192.52.193.0/24`, RFC 7450).

##### IPv6

Only global unicast, `2000::/3`, can pass (RFC 4291 §2.4). Everything outside it is refused, except as the [embedded-IPv4 rules](#ipv6-forms-that-embed-ipv4) allow. That covers:

| Block | What it is | Reference |
|---|---|---|
| `::/128`, `::1/128` | unspecified; loopback | RFC 4291 §2.5.2, §2.5.3 |
| `::/96` | IPv4-compatible, deprecated | RFC 4291 §2.5.5.1 |
| `::ffff:0:0:0/96` | IPv4-translated | RFC 2765 §2.1 |
| `64:ff9b:1::/48` | local-use IPv4/IPv6 translation | RFC 8215 |
| `100::/64`; `100:0:0:1::/64` | discard-only; the dummy prefix | RFC 6666; RFC 9780 |
| `5f00::/16` | SRv6 segment identifiers | RFC 9602 |
| `fc00::/7` | unique local | RFC 4193 |
| `fe80::/10` | link-local | RFC 4291 §2.5.6 |
| `fec0::/10` | site-local, deprecated | RFC 3879 |
| `ff00::/8` | multicast | RFC 4291 §2.7 |

Refused inside `2000::/3`:

| Block | What it is | Reference |
|---|---|---|
| `2001::/23` | IETF protocol assignments, the whole block (see below) | RFC 2928 |
| `2001:db8::/32`, `3fff::/20` | documentation | RFC 3849; RFC 9637 |

- **`2001::/23` is refused whole.** It holds:
  - Teredo (`2001::/32`, RFC 4380);
  - benchmarking (`2001:2::/48`, RFC 5180);
  - ORCHID and ORCHIDv2 (RFC 4843, RFC 7343) and drone entity tags (RFC 9374), which are identifiers, not locators;
  - the PCP, TURN, DNS-SD and AMT anycast services, and AS112-v6.

  No provider or peer is addressed there.
- **The globally reachable AS112 block `2620:4f:8000::/48`** (RFC 7534) passes.
- **6to4, `2002::/16`,** passes only as the embedded-IPv4 rules below allow.

##### IPv6 forms that embed IPv4

On the right network, each of these forms reaches the IPv4 address it embeds. So the IPv4 policy decides them:

| Form | Where the IPv4 address is | Rule | Reference |
|---|---|---|---|
| IPv4-mapped, `::ffff:0:0/96` | the last 32 bits | **classified as** that IPv4 address; the connection goes to the IPv4 address | RFC 4291 §2.5.5.2 |
| NAT64 with the well-known prefix, `64:ff9b::/96` | the last 32 bits | passes only if the IPv4 address passes; the connection goes to the IPv6 address, through the network's translator | RFC 6052 §2.1, §2.2 |
| NAT64 with a [learned network-specific prefix](#network-specific-nat64-prefixes) | at the place RFC 6052 §2.2 gives for the prefix's length (32, 40, 48, 56, 64 or 96), with bits 64–71 skipped | as for the well-known prefix | RFC 6052 §2.2; RFC 7050 |
| 6to4, `2002::/16` | bits 16–47 | passes only if the IPv4 address passes | RFC 3056 §2 |
| ISATAP: an interface identifier starting `0000:5efe`, `0100:5efe`, `0200:5efe` or `0300:5efe`, under any prefix | the last 32 bits | passes only if the IPv4 address passes **and** the IPv6 address passes on its own | RFC 5214 §6.1 |

**Refused whole,** whatever they embed:
- **IPv4-compatible `::/96`:** deprecated, and stacks differ in what they do with it.
- **IPv4-translated `::ffff:0:0:0/96`:** never a global address.
- **Local-use NAT64 `64:ff9b:1::/48`:** the operator picks the prefix length inside it, so the embedding can't be read.
- **Teredo `2001::/32`:** it embeds a server address and an obfuscated client address and port, and Teredo is out of use.

**Tunnel forms whose embedding depends on configuration** are classified as the IPv6 address alone:
- **6rd** (RFC 5969): the provider's prefix has any length, and the IPv4 bits may be shortened by a prefix common to the domain, so only the provider's configuration says where they are;
- **6over4** (RFC 2529): the interface identifier is the IPv4 address padded with zeros, which an ordinary address such as `2a00:1::1` also looks like;
- **6a44** (RFC 6751): the embedded addresses belong to the provider's relay and its client sites.

Their embedded IPv4 address is a tunnel endpoint inside a provider's or site's network, and the packet is delivered to the IPv6 host. Refusing them would refuse global peers on a guess. 6to4 and ISATAP differ: their embedding sits at a fixed place, and a non-global one means a tunnel into a private network, so the table's rule applies.

**DNS64.** A network with NAT64 often synthesizes AAAA answers for names that have only A records (RFC 6147). An answer under the well-known prefix or a [learned prefix](#network-specific-nat64-prefixes) is classified by its embedded IPv4 address, so a name whose A record is private stays refused through it. Synthesis under a prefix the service can't learn is outside the promise ([What the gate can't see](#what-the-gate-cant-see)).

##### Network-specific NAT64 prefixes

An IPv6-only network can translate through a network-specific prefix of its own (RFC 6052). Addresses under it look like ordinary global unicast, and, unlike the well-known prefix, it may translate to private IPv4 addresses. So in `direct` mode the service learns these prefixes as RFC 7050 describes, and fails closed for IPv6 while it doesn't know them.

- **Discovery asks the access networks.** It sends one query, AAAA for `ipv4only.arpa`, to each resolver it can learn for each interface that is up, and takes the union of the answers, because only an access network's own DNS64 synthesizes for it (RFC 8880 §7.1). The service's other resolvers (hickory's, and the configured DoH endpoint) needn't see that DNS64.
  - **Which resolvers,** per OS. A manual DNS setting, a VPN's resolver or a local recursive resolver can stand in front of an interface's own, so the service reads the interface-learned servers where the OS keeps them, not only the effective list:
    - **Windows:** each adapter's DNS servers (`GetAdaptersAddresses`), and, where a manual setting overrides DHCP, the servers DHCP gave the interface (`DhcpNameServer` under the interface's `Tcpip` parameters);
    - **macOS:** each network service's DNS state in the SystemConfiguration dynamic store (`State:/Network/Service/<id>/DNS`), which holds what the service learned, not only `/etc/resolv.conf`'s primary resolver;
    - **Linux:** `/etc/resolv.conf`, plus, when systemd-resolved runs, the servers it exports to `/run/systemd/resolve/resolv.conf`. That file is a compatibility subset: it leaves out the servers of links that aren't a DNS default route (a split-DNS VPN link, for example) and servers on nonstandard ports, and it doesn't say which link a server belongs to. resolved's D-Bus API lists them all, but the service doesn't become a system-bus client for this: discovery reads files only, by choice. Servers that NetworkManager or another manager learned and didn't publish can't be read portably either.
  - **It is a discovery-only path:** that one name and type, over plain DNS. Each of these resolvers is a configured target for that query alone, as the DoH endpoint is for DoH. Its answers are parsed, never dialed, and the path resolves nothing else.
  - **Each answer** that embeds `192.0.0.170` or `192.0.0.171` at one of RFC 6052's positions gives a prefix and its length. An answer that embeds neither teaches nothing.
  - **The result belongs to the process,** not to an instance: it describes the network, and the query carries nothing of a partition's.
- **The fixed forms** are those whose prefix is fixed: IPv4-mapped, the well-known NAT64 prefix and 6to4. Any other global IPv6 address could sit under a network-specific prefix.
  - **A learned prefix still applies under a fixed form.** An address inside `2002::/16` or `64:ff9b::/96` that also sits under a learned prefix is judged by both readings, and each IPv4 address must pass. Only IPv4-mapped is judged as IPv4 alone, since it connects to that address directly.
- **States:**
  - **pending** until the first query settles. Every IPv6 target but an IPv4-mapped one waits for it, within its own deadline: the first answer may teach a prefix that sits under a fixed form;
  - **known,** once every resolver learned has answered: the union of their prefixes. NODATA or NXDOMAIN from all of them gives an empty set, which means none of them advertises a prefix (RFC 7050 §3), not that no network does. The same holds when the OS lists no resolver;
  - **unknown,** while any resolver learned has failed (a timeout, `SERVFAIL`, a malformed answer). Another's answer doesn't settle it;
  - **incomplete,** when an answer holds more than 16 distinct prefixes.

  In **unknown**, an IPv6 target outside the fixed forms is refused, and `ipfs.stats` says why. IPv4 targets, and IPv6 targets under the fixed forms, are judged as always, with every prefix already learned still applied.

  In **incomplete**, the prefixes past the bound weren't kept, and one of them may cover a fixed form: a learned prefix inside `2002::/16` or over `64:ff9b::/96` reads a different IPv4 address out of the same bits. So every IPv6 target is refused except an IPv4-mapped one, which connects to its IPv4 address, and `ipfs.stats` says why. IPv4 targets are judged as always.

  A dual-stack network keeps IPv4, and an IPv6-only network whose resolver fails couldn't reach much anyway.
- **Learned prefixes are kept** for the process's life, so a refresh adds prefixes and never removes one. A prefix only adds refusals, so keeping an old one, or a false one from the network's resolver, errs on the safe side. The bound of 16 counts all of them; past it, the state is **incomplete** until the process restarts.
- **Refresh:**
  - when the last answer's TTL expires, and at least once a minute, so a network change leaves at most about a minute when a new network's prefix is unknown;
  - after a failure, with backoff from 5 s to 1 min. A failed refresh keeps every known prefix: it never turns a known one back into a native address.
- **A target is judged by the state at its check.** A lookup's check, or a candidate choice's, reads the state once, when all of its answers or candidates are in hand (after any wait for discovery), and judges every one of them against it. So no check reads a state older than the last publication before that read. An attempt that passed may still connect after a later publication: a publication neither waits for the attempts in flight nor cancels them, as it doesn't close connections already open either. Those attempts reach nothing new. Each target passed under the earlier state, and so was reachable for as long as that state stood: normally about a minute after a network change (**Refresh**, above), and longer while failed refreshes keep the state **unknown**, whose fixed-form allowance is deliberate.

###### What the gate can't see

The promise is exact for addresses the service can read: an IPv4 address, or an IPv6 address whose embedding its form or a learned prefix fixes. Translation the service can't read is outside it:
- **a prefix announced only in router advertisements** (PREF64, RFC 8781), which the service can't read portably;
- **a prefix only an unread resolver advertises:** an interface's own resolver that the OS doesn't expose as above, hidden behind a manual setting, a VPN's resolver or a local recursive resolver that doesn't forward to the DNS64. On Linux that includes the servers systemd-resolved leaves out of its exported file (links that aren't a DNS default route, nonstandard ports) and those a network manager didn't publish;
- **explicit address mappings** (SIIT-EAM, RFC 7757);
- **DNS64 that maps different IPv4 ranges to different prefixes** (RFC 7050 §5.1), for example private A records under a prefix the `ipv4only.arpa` answer doesn't show. The heuristic can't find that prefix, and RFC 7050 says so;
- **after a network change,** a new network's prefix, normally for up to a minute, and for longer while failed refreshes keep the state **unknown**;
- **in `socks5` mode,** translation on the exit's network. Nothing is learned there: the exit makes every connection, so the local translator is never used, and the exit's is out of the service's sight. The well-known prefix rule still applies in both modes.

An address under such a prefix is classified as the global unicast address it looks like. The deviation `address-policy` records this limit.

#### The resolver contract

- **The service's resolver** sits under every ordinary name, in both modes. That covers reqwest's `dns_resolver` and the SOCKS transport. In `direct` mode, libp2p resolves its own names with its DNS layer (hickory), and the transport check beneath it holds that layer to this contract: an answer is dialed only at an address that passed, and an empty or wholly refused answer fails the dial ([check 3](#the-gate)). It answers one of two things:
  - **one or more addresses,** every one of which passed the gate;
  - **an error.**
- **It never answers an empty success.** A failed lookup, an empty answer, and an answer whose every address the policy refuses are all errors, and the connection attempt fails.
  - This matters because, in reqwest 0.12.28, an empty success makes the SOCKS connector send the original name to the proxy unresolved. That is the route reserved for onions.
  - Under `socks5://` an IP-literal host reaches the resolver too, IPv6 in brackets. The resolver parses it and judges it as the literal it is, never as a name.
- **Onion names never reach this resolver.** The gate routes them first ([below](#the-onion-route)), and the resolver answers an onion name with an error, in case one ever arrives.

#### The onion route

- **In `direct` mode** there is none: onions are refused before any socket exists.
- **In `socks5` mode,** onion targets have their own explicitly authorized route, which no ordinary name can enter:
  - **HTTP:** a second client, built with `socks5h://` to Arti's endpoint, so the proxy receives the name. It is used only for a URL whose host the gate classified as onion: its send path takes that URL as a type only the classifier constructs, checks the classification again before it sends, and refuses anything else. reqwest's connector can't see the destination, so the check can't sit there.
  - **libp2p:** the SOCKS transport's onion path, taken only for `/onion3` and onion `/dns*` components.
- **Redirects re-select the route:** the service's redirect loop picks the client per hop. An onion URL that redirects to a clearnet name moves to the ordinary client, with `RESOLVE` and the gate. A clearnet URL that redirects to an onion moves to the onion client, in `socks5` mode only.

**Redirect behavior** is part of parity:
- v0.4.6's provider client follows no redirect (`rv:11136`), while its routing and DoH clients follow reqwest's default (`rt:1807`, `ns:828`).
- The service keeps each client's acceptance (the provider client, none; the routing and DoH clients, up to 10 hops, as reqwest's default allows) in its own redirect loop, with the gate on every hop (deviation `redirect-gate`).

### Changing the policy

- **What a change does:** main retires every instance's ID, then each instance is torn down ([teardown](#instances-and-their-teardown)) and started again under a new ID with the new policy.
  - In-flight requests fail with `stopped`.
  - The network capability is revoked first, so nothing can connect under the old policy while the rest ends.
- **The guarantee:** nothing admitted under the old policy outlives the change. If that can't be proven within 5 s, the process restarts.
  - This mirrors `applyOnionProxy`, which calls `closeAllConnections` after `setProxy`.
- **Arti going down** leaves the policy in place, so IPFS fails closed. This matches the PAC kept after an Arti crash.

## Upstream changes in freedom-ipfs

Each is a pull request to freedom-ipfs, and none changes mobile's behavior by default. The service pins the release that carries them. Until then it pins a commit, which `deny.toml` allows (`solardev-xyz`).

1. **A library builder for the online node.**
   - Today's wiring lives in the FFI crate (`mob:2154`–`2249`) and again in the gateway binary (`gateway/src/main.rs:130`–`162`).
   - Move it to a library function, for example `freedom_ipfs_gateway::OnlineNode::builder(store)`, that returns the owned `Instance` of item 7. It takes:
     - the routing mode and routers;
     - the DHT settings;
     - `GatewayConfig`;
     - the network policy (item 3);
     - the shared limiters (item 8).
   - The add-on and the service then wire the same thing.
2. **The native-request parser, public.**
   - The JSON-to-`GatewayCoreRequest` parsing (`mob:2635`–`2689`) moves to a library function, with the same accepted forms and results.
   - The service then treats each path exactly as the add-on does, with no copy to drift.
3. **A network policy.** One `NetworkPolicy` value, threaded through the builder, that supplies the parts below.
   - **The builder's default is today's clients and transports** (legacy), so a host that sets no policy, as mobile and the add-on don't, keeps today's behavior, the system proxy included.
   - **The code lives in a crate of its own,** which namesys, routing and retrieval depend on. Its SOCKS code sits behind a cargo feature, off by default, so mobile builds compile none of it.
   1. **HTTP clients:**
      - a single constructor taking `Option<reqwest::Proxy>` and each client's redirect acceptance (the hop count), built with `Policy::none()`, so the service's own loop follows redirects through the gate (hop check 4);
      - it replaces the three `timeout_http_client` functions (`ns:828`, `rt:1807`, `rv:11132`) and calls `no_proxy()` in `direct` mode;
      - it enables `reqwest`'s `socks` feature, and uses `socks5://` (never `socks5h://`) with the gate's resolver as the client's `dns_resolver`, and requires hyper-util 0.1.21 or later ([What can be honored](#what-can-be-honored)). That resolver resolves locally in `direct` mode and through `RESOLVE` in `socks5` mode, and follows [the resolver contract](#the-resolver-contract): addresses that pass, or an error, never an empty success;
      - in `socks5` mode, a second, onion-only client for [the onion route](#the-onion-route).
   2. **Errors instead of panics:** the three constructors `expect` today (`ns:833`, `rt:1812`, `rv:11138`). With a proxy their configuration can fail, so building a policy's clients returns an error. The legacy defaults keep their infallible constructors, since their configuration has no proxy.
   3. **DoH:** the endpoint and its client come from the policy, at `mob:2226` and `rv:9436`, `9484` and `9531`. DNSLink is already pluggable (`DnsTxtResolver`, `ns:53`); Bitswap's address expansion isn't. Expansion results pass through the gate (check 2).
   4. **Transports:**
      - `build_dht_swarm` (`rt:1588`), `build_bitswap_swarm` (`rv:8816`) and `cloudflare_websocket_transport` (`rv:8847`) take `quic: bool`, `dns: Hickory | None`, and `tcp: Direct | Socks5(addr)`;
      - add a SOCKS5 `Transport` over `tokio-socks` (MIT, with its `tor` feature) for `/ip4`, `/ip6`, `/dns*` and `/onion3` with `/tcp`, and for WebSocket on top of it;
      - it resolves `/dns*` names with `RESOLVE`, checks every answer, and `CONNECT`s to a checked IP literal. A failed, empty or wholly refused answer fails the dial. Only `/onion3` and onion names go to the proxy as names, on their own code path. The WebSocket layer above keeps the name for TLS;
      - in `direct` mode, the TCP and WebSocket transports resolve names themselves and check each address before connecting (check 3);
      - a stack composed by hand needs libp2p's TLS-or-noise selector, which libp2p doesn't export. A local copy, attributed, keeps today's `(tls, noise)` choice.
   5. **The gate:**
      - the classification and the address policy as one function, applied where candidates are chosen (`rt:1491`–`1525`, `rt:1767`–`1805`), after expansion, and at the transport, which covers the dial sites (`rv:7765`, `rv:7949`, `rt:1044`) and the dials libp2p makes itself (check 3);
      - every check asks the instance's network capability, so revoking it refuses everything later.
4. **Progress and stats outside the FFI crate.**
   - Move the progress recorder and `progress_layer` (`mob:552`–`1018`) to a library crate, with a recorder per node rather than the process-global `PROGRESS_RECORDER` (`mob:79`).
   - The service then links no C ABI, and two instances' progress never mixes.
   - If a cancelled request leaves its entry in `active` until `clearProgress`, as the code suggests, close the entry on cancel.
5. **Store options:**
   - `temp_store = MEMORY` for `in_memory` stores;
   - a hot-cache size independent of `max_bytes` (today `min(max_bytes, 16 MiB)`, `st:609`), since a memory store holds the bytes twice;
   - `max_page_count` and `cache_size` set by the host, so a memory store's growth is capped by SQLite itself;
   - a write that meets the cap (`SQLITE_FULL`), whether a block, a name or a provider record, leaves that entry uncached and succeeds for the request;
   - its page use (`page_count × page_size`) as a metric.
6. **Build info:**
   - `buildInfoJson` reads `FREEDOM_IPFS_GIT_COMMIT` and `FREEDOM_IPFS_GIT_DESCRIBE` (`mob:1333`), but the packaging script sets `FREEDOM_IPFS_BUILD_GIT_*`, so both fields are always null.
   - Move the function to a library crate and fix the names. `ipfs.hello` reports it.
7. **Owned instances and cancellation:**
   - **A root cancellation token per instance,** with a child per request. Cancelling a request's token drops its future, which ends every await inside it. The blocking regions (`rv:5448`, `rv:5500`, `rv:5535`) and the spawned tasks hold the token explicitly, so a fetch blocked inside `block_on` ends too.
   - **A spawner handle** in the builder: every task the instance starts goes into its task set, including the shared Bitswap swarm's task (spawned at `rv:7390`, which keeps only a command sender today) and background preconnects.
   - **A runtime per instance,** built by the builder. `Instance::shutdown` drains the task set and blocking regions, then hands the runtime back to its caller for dropping and joining on a teardown thread, and closes the store after. Its quiescence report counts as proof only once that join has returned; a timed runtime shutdown is never reported as quiescent.
   - **A blocking-region counter** around each `block_in_place`.
   - **`Instance::shutdown()`,** which runs steps 2–4 of the [teardown](#instances-and-their-teardown) and reports whether quiescence was reached.
   - **Shutdown after a panic:** `Instance::shutdown` and the store's close work after a request task has panicked. A lock that the panic poisoned is recovered (`PoisonError::into_inner`) for the teardown only, never to serve another request.
8. **Shared limiters and accounting:**
   - the builder takes process-wide limiters for block fetches, HTTP provider requests, Bitswap connections and DHT queries;
   - **a reservation API:**
     - `reserve(bytes)` before every accounted allocation, waiting or failing as the [budget](#budgets) says;
     - a buffer type that carries its reservation, so the reservation is released when the buffer's last owner drops it, after a panic or a cancel too;
     - truing down only by replacing the backing with an allocation of the payload's size;
     - caches that count entries by backing capacity, and take over a charge only when they hold the last reference;
   - **a maximum block size** for every block fetch (2 MiB), on the Bitswap path as on the HTTP one, reserved before the fetch begins;
   - **caches built with a fixed capacity:** the hot cache, the small-body cache and the UnixFS metadata cache, reserved at that capacity;
   - **the background queue bound** of 64.

## Where the code lives

Four options. A new repository is the user's decision; this design recommends the first.

1. **This repository, as `services/freedom-ipfsd`, a separate Cargo workspace** (recommended).
   - **For:**
     - `fc-protocol` by path, so one frame and stream codec;
     - one release workflow, with Linux builds against glibc 2.17, which also closes #350's GLIBC floor ([Open questions](#open-questions));
     - `SHA256SUMS` and attestations;
     - freedom-browser's fetch-and-verify script pattern, extended to a second asset;
     - the same lints, copied into its manifest, since workspace lints don't cross workspaces.
   - **Its own workspace,** excluded from the core's (`exclude = ["services"]`).
   - **Its own `Cargo.lock` and `deny.toml`** keep the core's dependency graph as it is. v0.4.6 alone locks 457 packages, against the core's 134:
     - a libp2p advisory can't block a vault fix;
     - the core's `cargo deny` stays strict;
     - the new graph brings C code (SQLite, `ring`) and at least one license the core doesn't allow: `webpki-roots` 1.x's CDLA-Permissive-2.0, per its published metadata, which `cargo deny` will confirm.
   - **Releases** use their own tag, `ipfsd-vX.Y.Z`, with their own `THIRD-PARTY-NOTICES`.
   - **libradicle's service (4.4, 0008)** sits beside it, in its own workspace.
2. **A member of the core's workspace,** in `crates/`.
   - **For:** simplest to build.
   - **Against:** the lockfile, `cargo deny` and every CI run of the key-holding core would carry libp2p, QUIC, SQLite and `ring`, and their advisories would gate vault work. AGENTS.md describes this repository as keys, vault, signing, naming and profiles; a P2P node is outside that.
   - Workspace membership alone wouldn't link those crates into `freedom-cored` or its notices; each binary's own dependency graph decides that. The cost is in resolution, advisories and CI.
3. **Upstream freedom-ipfs,** as a binary beside `freedom-ipfs-gateway`'s.
   - **For:** the binary lives with the crates it wraps, and is released with them.
   - **Against:**
     - the frame protocol, the lock and the supervision contract are Freedom's, not freedom-ipfs's;
     - freedom-ipfs is dual-licensed MIT or Apache-2.0, while this repository carries no license, so it couldn't depend on `fc-protocol` without a licensing decision, and would copy the codec instead;
     - its crates don't forbid `unsafe`, because the FFI crate needs it.

   Upstream still gets the [hooks above](#upstream-changes-in-freedom-ipfs): they are library changes, useful to any host.
4. **A new repository** (`freedom-ipfsd`): option 1's layout, moved out.
   - **For:** separate access and release cadence.
   - **Against:**
     - one more pipeline and pin, and `fc-protocol` as a git dependency across repositories;
     - it adds governance isolation only with its own permissions and a protected pin of the shared code.
   - Option 1's workspace moves out unchanged if the user prefers this later.

**What the separation is, and isn't:**
- A separate workspace separates dependency resolution and advisory gates. **It is not supply-chain isolation:** build scripts and proc macros still run with the build host's authority.
- So:
  - each service builds in its own disposable CI job and checkout, with its own caches and artifact names, and read-only credentials;
  - publishing runs no dependency or repository code;
  - the service's release can't supply or overwrite core artifacts;
  - changes to the shared `fc-protocol` pass the core's own review and tests, and never enable stream kinds on the core's connections.

## Migration

### Tests first

As 0006's 4.7 did, before anything moves:

- **One backend contract suite** in freedom-browser, parameterized over the backend. Its cases are #704's `ipfs-protocol.native.test.js`:
  - Range in and 206 out, with the page-state headers stripped;
  - HEAD with no body;
  - backpressure: no more than the window read ahead;
  - a failure before the head → 502 with its message;
  - a mid-body failure → a truncation error;
  - a cancel and free on abort mid-body, body cancel, abort of a paused body, abort before start and abort before the head;
  - the exact 30 s head deadline;
  - a paused reader never timed out;
  - a 60 s idle read → `BodyIdleError`;
  - a stopped node → 503 without a request;
  - a backend exit → the open body truncates and the next request gets 503;
  - the `small_text` matrix.

  It lands first and runs against the add-on, through the fake add-on as today. Then it runs against the service, through a scripted fake service in JS and through the real binary.
- **Stream cases,** in `fc-protocol` and through the binary:
  - a paused consumer with a small body whose `end` arrives first: every byte is still delivered;
  - a full data queue, then EOF: `end` comes after the last data;
  - `abort` with data queued: nothing of the stream follows;
  - cancel interleaved with an unwritten head: one reply, no stream;
  - duplicate and excess credit, and credit racing `end` and `abort`;
  - one-byte frames at full window, and repeated cancel and new-request cycles with a paused writer and consumer: allocations stay within the coalescing bound;
  - a saturated reader with a full data queue, with credit, cancel and shutdown behind ordinary traffic: all three take effect.
- **Instance cases:**
  - cancel inside a blocking retrieval, and during background work: no socket is opened after the stop's acknowledgement, checked at the gate and by a canary;
  - a stop whose quiescence is held back past 5 s: exit 70 and a restart;
  - a plan delayed across a stop and start with a different policy: the old continuation fails, and nothing reaches the new instance;
  - a background swarm task panicking: exit 70.
- **Request panic cases,** with a panic injected through the test hooks:
  - **while the task holds the store, a cache, a Bitswap want or an in-flight entry:** the request gets `internal`, the instance's other requests get `stopped`, the teardown proves quiescence, and `ipfs.instance_retired` follows. The replacement instance serves the same CID;
  - **after the head:** the stream aborts with `internal`;
  - **with the head queued but not written:** the head is dropped, and `internal` is the only reply;
  - **with data queued:** the queued data is purged, the abort is written, and credit for the stream is checked against its account until then;
  - **after the terminal is settled** (a panic in a request future's destructor after a cancel, or after `end` was written): the earlier outcome stands, nothing more is sent, and the instance is still retired;
  - **the fence comes first:** with the join handle paused before it queues the reply, a request for the same instance gets `stopped`, and no work for it is admitted;
  - **process-wide state:** admission, retrieval permits and dynamic reservations return to their baseline; the writer's record of the stream, its queued head and data, and its credit account do so once its terminal is written;
  - **in the ephemeral process:** a panic in one partition's instance retires that instance only. Another partition's request in flight completes, and the panicking partition's next request starts a new instance;
  - **a teardown held back past 5 s after a panic:** exit 70;
  - **a panic on a blocking thread a library spawned for a request,** outside the request task: exit 70;
  - **three request panics within 60 s:** the restarts stop, with "Node unavailable. Restart IPFS from the nodes menu.";
  - **the log** has only the hook's fixed line for each panic.
- **Private cases:**
  - a first private load;
  - concurrent first loads in one partition: one start;
  - **waiters with different deadlines:**
    - the first waiter's abort leaves the start running for the others;
    - the last waiter's abort cancels the start;
    - in both cases pin counts return to zero, and nothing is sent late to an evicted ID;
  - a ninth partition evicting during another's planning: only unpinned instances go;
  - a close during the cold start;
  - **all 8 instances pinned:**
    - another request from each of the 8 partitions succeeds;
    - a ninth partition gets 503 `busy`, while `ref.up` stays true;
    - once one lease ends, the ninth succeeds by evicting that instance;
  - exhaustion across all 8 instances: `busy`, and the budget holds;
  - a panic whose payload holds a path: the log has only the fixed line.
- **Lease cases:** every exit of the handler releases the lease exactly once, checked by a pin count that returns to zero:
  - a redirect plan, and each error plan (400, 404, 405, 415, 502, 503);
  - a URL or header refusal;
  - a failed lookup;
  - a core that is unavailable or `busy`;
  - admission's 503;
  - an abort before the fetch;
  - a rejected `request()`;
  - the body's end, error and cancel;
  - a second `release()` is harmless;
  - `closeDwebSession` releases what is left.
- **Budget cases:**
  - many distinct CIDs over a long-lived instance, and over every private instance at once. The memory budget and the retrieval admission hold;
  - **exhaustion during an existing stream:** the stream's next block waits, then aborts with `busy` after 10 s. Other streams continue, and the reserved total never passes the budget;
  - **concurrent growth:** many concurrent fetches into one memory store reach its page cap. Puts fail as uncached, the responses still complete, and the total never passes the budget;
  - **reservations follow allocations:**
    - a small block in a large receive buffer stays charged for the buffer until it is copied out;
    - a failed or full put keeps the block charged until its last owner drops it;
    - a block evicted from the hot cache while a stream holds it stays charged until the stream drops it;
    - a cancel or a panic in the middle of a put returns the counter to its baseline.
- **Ring cases:** one-byte frames and full-window bursts never allocate more than 128 KiB per stream in main.
- **Rust tests through the binary,** using test-only methods behind a cargo feature, as `freedom-cored`'s `testhooks`. These seed a memory or offline instance from CAR fixtures, and inject a panic, a stall or a slow teardown.
  - **The protocol:** frames, credit, cancel races, deadline, and one terminal per request and per stream.
  - **Isolation:** a panic on one request is `internal` for that request, and retires its instance only.
  - **The lock:** contention gives 75, a network filesystem gives 74, and `hold-lock`.
  - **Parent death,** the 5 s exit watchdog, and parent death while the writer is backed up.
  - **The stall:** exit 76.
- **Network policy tests:**
  - **A SOCKS5 test proxy** records every connection, and a canary TCP and UDP listener is advertised in provider records and is the target of a configured router's redirect. In `socks5` mode the canary must see nothing, and the proxy everything.
  - **Expansion and redirects:**
    - a `/dnsaddr` that expands to a loopback address, a name that resolves to a private address, and a configured router that redirects to a private address or to a scheme other than HTTP or HTTPS: each is refused before a socket opens;
    - a configured router that redirects to an onion URL: refused before a socket opens in `direct` mode, and taken by [the onion route](#the-onion-route) in `socks5` mode;
    - a provider that redirects anywhere: the redirect is returned, not followed, since the provider client's acceptance is none.
  - **Canonical forms:**
    - upper case, a trailing dot, numeric IPv4 URL hosts, and `/dns/<x>.onion`;
    - one address in every spelling: `[::ffff:a9fe:a9fe]`, `[::ffff:169.254.169.254]`, `[0:0:0:0:0:ffff:a9fe:a9fe]` and upper-case hex in a URL, and `/ip6/::ffff:169.254.169.254` in a multiaddr, all refused as `169.254.169.254`.
  - **The address table,** with cases generated from the gate's table and checked against [Addresses](#addresses):
    - each refused block's first and last address are refused, and the addresses just outside it pass unless a neighboring block refuses them;
    - the globally reachable blocks named there (AS112, AMT) pass;
    - IPv6 outside `2000::/3` (`1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff`, `4000::`) is refused, and `2000::1` passes.
  - **Embedded IPv4:**
    - the motivating case: a provider record advertising `/ip6/64:ff9b::a9fe:a9fe/tcp/80` is refused before any socket exists, while `/ip6/64:ff9b::808:808/tcp/80` (`8.8.8.8`) passes;
    - 6to4: `2002:a9fe:a9fe::1` and `2002:a00:1::1` are refused, `2002:808:808::1` passes;
    - ISATAP: `2a00:1::200:5efe:a9fe:a9fe` and `2a00:1::5efe:7f00:1` are refused, `2a00:1::200:5efe:808:808` passes;
    - IPv4-compatible `::808:808`, IPv4-translated `::ffff:0:808:808`, local-use NAT64 `64:ff9b:1::808:808` and Teredo `2001:0:4136:e378:8000:63bf:3fff:fdd2` are refused whole;
    - a learned network-specific prefix of each length (32, 40, 48, 56, 64 and 96), with `169.254.169.254` and `8.8.8.8` embedded at RFC 6052's positions: refused and passed;
    - an `ipv4only.arpa` answer that embeds neither well-known address teaches nothing, and NODATA gives a known, empty set;
    - discovery goes only to the resolvers it learned, for `ipv4only.arpa` only, and no answer from it is dialed;
    - **two interfaces:** one interface's resolver advertises a prefix and the other's answers NODATA, as with a VPN beside the physical link: the prefix is known, and an address under it with `169.254.169.254` embedded is refused;
    - **a manual DNS override:** the effective resolver answers NODATA while the interface-learned one (DHCP's on Windows, the service's state on macOS, a default-route link's in systemd-resolved's exported file) advertises a prefix: the prefix is known;
    - **one resolver failing** while another answers: the state stays unknown;
    - **the startup race:** an IPv6 dial made while discovery is pending waits for it, and an address under the prefix that the first answer teaches is refused. That holds under a fixed form too: with `2002:808:808::/48` in the first answer, `2002:808:808:7f00:0:100::` (`8.8.8.8` as 6to4, loopback under the /48) waits, then is refused;
    - **publication and checks:** a publication while a lookup is blocked: its answers are judged against the new state. A publication after a candidate choice has read its state: all of its candidates are judged against that one state. A lookup or choice begun after a publication: the new state. Each with a prefix added, and with a publication of incomplete;
    - **failure:** after a failed query, an IPv6 target outside the fixed forms is refused and an IPv4 one passes; after a failed refresh, every known prefix is still applied;
    - **the bound:** an answer with 17 distinct prefixes makes the state incomplete, and `2a00:1:11::a9fe:a9fe` under the 17th is refused, not passed as global unicast. With a /96 inside `2002::/16` as the 17th, `2002:808:808::7f00:1` is refused too, though its 6to4 reading is `8.8.8.8`; an IPv4-mapped address still passes or fails as its IPv4 address;
    - **a learned prefix over a fixed form:** with `2002:808:808::/48` learned, `2002:808:808:a9fe:a9:fe00::` (169.254.169.254 under the /48, `8.8.8.8` as 6to4) is refused;
    - a refresh that drops a prefix doesn't forget it;
    - 6rd, 6over4 and 6a44 addresses with private embedded addresses (`2a00:1:c0a8:101::1`, `2a00:1::c0a8:101`) are judged as IPv6 alone, and pass;
    - a DNS64 answer `64:ff9b::7f00:1` for an ordinary name, locally and through `RESOLVE`: refused, and no connection is made;
    - `/ip6zone/eth0/ip6/fe80::1` and `/unix/…` multiaddrs are refused;
    - **a second host component:** `/ip4/8.8.8.8/ip4/127.0.0.1/tcp/8080`, the same with `/ipcidr/32`, `/p2p-circuit` or `/ip6zone/eth0` before the private pair, and `/ip4/8.8.8.8/dns/x.onion/tcp/80`, are refused, and a loopback canary sees no connection. For the hidden onion, no DNS or TXT query is made either;
    - **the shapes, as a matrix:** each accepted shape with and without its `/p2p` suffix, HTTP providers with and without `/tcp` (default ports 80 and 443) and the path-carrying WebSocket forms, all accepted; an extra trailing component, a second `/p2p`, and `/tls/sni/<name>/ws` or `/http`, all refused; and a `/dnsaddr` answer that yields a refused shape, refused.
  - **Failures:** an unavailable proxy, a proxy that refuses `RESOLVE` (the attempt fails, and no name is sent in `CONNECT`), and an unsupported transport in `socks5` mode.
  - **A SOCKS fixture with `RESOLVE`:**
    - a name that looks acceptable but resolves to a loopback or private address is refused, and no `CONNECT` is sent;
    - an empty `RESOLVE` answer, and an answer whose every address is refused: the attempt fails, and no `CONNECT` carries the ordinary name;
    - a name whose answer changes from a public address to loopback between checks never connects to loopback, and each `CONNECT` goes to the address that was checked;
    - every `CONNECT` carries an IP literal, except for onions;
    - TLS SNI and HTTP `Host` carry the name, checked by a test server.
  - **The onion route:**
    - an HTTP request to an onion host: one `CONNECT` with the onion name, and no `RESOLVE`;
    - an onion URL that redirects to a clearnet name: the hop goes through `RESOLVE`, the gate and an IP `CONNECT`;
    - a clearnet URL that redirects to an onion: the onion client in `socks5` mode, refused in `direct` mode;
    - an ordinary name handed to the onion client: refused before anything is sent.
  - **Redirect headers:**
    - hops that change host, and hops that change only the port: no `Authorization`, `Cookie`, `Proxy-Authorization` or `Referer` reaches the second server;
    - an HTTPS URL that redirects to HTTP sends no `Referer`;
    - a chain that moves between the ordinary and onion clients is counted against one hop budget, and fails at the limit;
    - an endpoint URL with userinfo is refused when the setting is read.
  - **Arti qualification:** the pinned Arti answers `RESOLVE`, with username/password credentials as well as without, run in the release pipeline before the setting ships.
  - **Stream isolation:**
    - two instances send different credentials;
    - every stream of one instance (`RESOLVE`, libp2p and HTTP `CONNECT`, onion, every redirect hop) sends the same ones;
    - a proxy that selects only no authentication fails the dial;
    - neither the username nor the password appears in any `Debug` output or error;
    - an injected randomness failure refuses the start, with no instance built.
  - **Onion:** `.onion` and `/onion3` targets in `direct` mode open no socket.
- **Live:** `ipfs:native:smoke` re-pointed at the service, with `/ipns/ipfs.tech/` and #102's fan-out of 48 concurrent requests and no `gateway_busy`.

### Parity

| Item | Today | The service |
|---|---|---|
| configuration | `AUTO`, two delegated routers (delegated-ipfs.dev and cid.contact), DHT 3 s, 8 permits, 15 s queue, 256 MiB | the same values, sent explicitly |
| IPNS lookups | both routers, then the DHT; one router's 404 reads as "not found" even when the other failed (freedom-ipfs#30) | the same, until upstream fixes it |
| cache file | `<ipfs-data>/freedom-ipfs/freedom-ipfs.sqlite3` | the same file |
| responses | `GatewayCore` via the C ABI | `GatewayCore` directly: the same status, headers and bytes |
| request ID and top-level path | main's counter, and the path | the envelope ID, and the path |
| head deadline | 30 s, main's timer | 30 s, the service's timer; main's watchdog at 45 s |
| redirects | the provider client follows none; the routing and DoH clients follow reqwest's default | the same acceptance, each hop through the gate (`redirect-gate`) |
| rejection texts | as in [Errors](#errors) | the same, plus `freedom-ipfs service exited` |
| identity | ephemeral libp2p identities | the same |

### Cost

Measured before the default switches, on linux-x64, macOS arm64 and win-x64, against the add-on:
- the time to first byte of a cached 1 KiB file;
- the throughput of a cached 100 MiB file;
- #102's fan-out.

The gates are both of these:
- the median first byte is no more than 5 ms later;
- throughput is at least 80 % of the add-on's.

Every body already passes through main today, so the pipe adds one copy into the kernel and back out.

### Rollback

- The add-on path stays in the tree, selectable in dev builds with `FREEDOM_IPFS_BACKEND=addon`, until the service has shipped in one stable release.
  - While selected, it runs under `freedom-ipfsd hold-lock` on the data directory for its whole lifetime, so it is a writer that takes the gate.
- Then:
  - the add-on and the event worker go;
  - so do `fetch-freedom-ipfs-native.js`, the `freedom-ipfs-node` resources and its `check-binaries.js` rule.
- The cache file is the same, so going back needs no migration.

## Bounds

| Budget | Bound | Exhausted |
|---|---|---|
| handshake; `ipfs.start` | 10 s; 10 s | kill; startup error |
| instance teardown | 5 s to quiescence | exit 70, and a restart |
| request panics | each retires its instance; it counts as a crash for main's back-off | the third within 60 s stops the process, as three crashes do |
| `ipfs.shutdown` | kill 5 s after it | kill (the cache tolerates it) |
| exit after stdin EOF | 5 s, a watchdog thread | `std::process::exit` |
| lock contention | 5 s of retries | exit 75 |
| restarts | 0.5 s, 2 s, 10 s; three crashes in 60 s | stop, and "Restart IPFS" |
| JSON message | 1 MiB (0001) | protocol error |
| `ipfs.request` | 0006's: URL ≤ 64 KiB, headers ≤ 64 KiB | refused in main first |
| admitted requests, per process | 512 (heads, open streams, work still ending) | `busy` |
| main's outstanding service requests | 512, retiring ones included | the fetch waits in main's admission |
| head | the plan's `headers_ms` (≤ 30 s); main's watchdog at + 15 s | `deadline`; on the watchdog, kill |
| stream window | 128 KiB per stream, checked; data frames ≤ 64 KiB, coalesced | the service waits for credit |
| stream storage in main | one 128 KiB ring per live stream: 32 MiB at 256 fetches, both the live-byte window and the backing storage; plus one partial frame (≤ 1 MiB) in the decoder | not reachable: credit |
| data frames queued in the service | 16 MiB | stream producers wait |
| service reader | 256 frames and 16 MiB (0001); controls handled on arrival | stops reading |
| writer stall | 30 s with nothing written (0001) | exit 76 |
| retrieval admission, per process | 256 block fetches, 16 HTTP provider requests, 32 Bitswap connections, 4 DHT queries | work waits under its deadline |
| background queue | 64 items per instance | new background work is dropped |
| memory budget | persistent 192 MiB; ephemeral 448 MiB, by reservation ([Budgets](#budgets)) | new work `busy`; admitted work waits as below; evict idle private instances |
| a reservation for admitted work | before the head: the rest of `headers_ms`; after it: 10 s per block | `busy` (`deadline` if queued after `headers_ms`); a stream aborts with `busy` |
| `ipfs.stats` | 5 s from when the reader handles it; main's watchdog at 20 s | `deadline`; on the watchdog, kill |
| stats calls, per process | 4 outstanding, each until its reply is written, or its job is dropped without one | `busy` |
| abort JSON, after the stream ID | 1 KiB | protocol error |
| persistent cache | 256 MiB of block data on disk (a target), 16 MiB hot | upstream's LRU eviction |
| private instances | 8 per ephemeral process; a 36 MiB page cap (32 MiB block target) and 4 MiB hot each | a new partition evicts an unpinned instance, else 503 `busy`; existing partitions are unaffected |
| gateway | 8 header permits, 15 s queue (today) | 503 `gateway_busy` |
| runtimes | the process: 2 workers. The persistent instance: ≤ 8 workers and a 512-thread blocking cap. Each ephemeral instance: 2 workers and a 64-thread blocking cap (≤ 16 and 512 in total) | tasks wait |

## Deviations

| ID | Today | After | Effect |
|---|---|---|---|
| `crash-domain` | the add-on runs in main and a worker thread of main | a separate process | an IPFS fault fails IPFS requests only, never the browser |
| `auto-restart` | none; the user restarts IPFS from the nodes menu | 0.5 s, 2 s, 10 s; three crashes in 60 s stop | brief outages heal on their own |
| `data-dir-lock` | the profile lock only | an OS lock per data directory, for writers that take it | a second gated owner fails at start (75); old builds sharing the directory are unsupported |
| `network-fs` | the cache opens on any filesystem | a network filesystem is refused (74) | IPFS doesn't start there; WAL isn't safe there anyway |
| `private-windows` | private windows share the profile's node and on-disk cache | an in-memory instance per private partition, in one ephemeral process | private loads leave nothing in the application's files, aren't served from shared caches, and start cold; a ninth partition loading while 8 are busy gets 503 |
| `env-proxy` | `reqwest` reads proxy variables from main's environment; libp2p ignores them | the environment is cleared, and the proxy is configuration | the HTTP half no longer follows `HTTPS_PROXY` and similar |
| `proxy` | none | an optional SOCKS5 policy for all traffic, failing closed | new: Route IPFS through Tor |
| `onion-targets` | no rule for them | refused before any socket in `direct`; through the proxy in `socks5` | a refusal proves nothing was sent |
| `address-policy` | none | untrusted targets refused unless globally reachable unicast, with IPv6 forms that embed IPv4 judged by their IPv4 address; configured endpoints exempt; IPv6 outside the fixed forms refused while NAT64 discovery is unknown, and every IPv6 target but IPv4-mapped while it is incomplete | providers on local networks are unreachable unless configured; translation the service can't read is [not covered](#what-the-gate-cant-see) |
| `redirect-gate` | redirects follow each client's policy | the same acceptance, with every hop through the gate | a redirect to a refused target fails the attempt |
| `read-ahead` | one 64 KiB read in main, plus a two-chunk channel | a 128 KiB window per stream | about the same buffering, now bounded by credit |
| `exit-text` | `Native event dispatcher exited with code N`, `Native gateway stopped unexpectedly` | `freedom-ipfs service exited` | in 502 bodies and logs only |
| `stats-fields` | the event-queue fields in the diagnostics | dropped, with the queue; budget use added | the panel shows the rest |
| `targets` | the add-on ships for darwin-arm64, linux-arm64, linux-x64 and win32-x64, and needs GLIBC ≥ 2.38 | the service builds for the core's five platforms; on Linux, linked dynamically against glibc 2.17, Rust's own floor for these targets, below Electron's 2.25 | IPFS on darwin-x64, and on Linux wherever the browser runs (#350) |

## Implementation steps

1. **Tests first,** in freedom-browser: the backend contract suite, run against the add-on.
2. **Upstream,** in freedom-ipfs, each its own PR:
   - the builder and parser (items 1–2);
   - owned instances and cancellation (item 7);
   - limiters and accounting (item 8);
   - progress and build info (items 4 and 6);
   - store options (item 5);
   - the network policy and gate (item 3).

   The service can start once items 1, 2 and 7 have landed.
3. **`fc-protocol`:** the stream frames, with their order, credit and coalescing rules, and vectors that main's `frame.js` also passes.
4. **`services/freedom-ipfsd`:**
   - the process model: the lock, `hold-lock`, the handshake, the panic hook, hardening, parent death and the exit watchdog;
   - instances with IDs and the teardown;
   - requests, streams, credit, cancel, deadlines and admission;
   - the budgets;
   - `ipfs.stats`;
   - test hooks behind a feature;
   - the Rust tests through the binary.
5. **Release:** the five targets, `SHA256SUMS`, attestations and notices, on `ipfsd-v*` tags, in separate build jobs.
6. **freedom-browser, the persistent node:**
   - `ServiceClient`, extracted from `core-client.js`, and the stream frames and rings in `frame.js`;
   - instance IDs and retirement in `ipfs-manager.js`;
   - the lease and `BackendBusy` in `dweb-handler.js` and the executor;
   - the fetch script and packaging (`mac.binaries` signing);
   - `ipfs-manager.js` on the service, behind `FREEDOM_IPFS_BACKEND` in dev;
   - the contract suite against the real binary;
   - the re-pointed smoke and the [cost](#cost) measurement.

   Then the default switches.
7. **Private windows:** the ephemeral process, readiness per partition, the cold start in `request()`, leases, eviction and fences.
8. **Network policy:** the setting, Arti's endpoint and its `RESOLVE` qualification, policy changes, and the gate, redirect, SOCKS and canary tests. This needs upstream item 3.
   - `socks5` first, with the classification and the capability in `direct` too: none of them needs NAT64 discovery.
   - Then NAT64 discovery in the service, which brings the address table to `direct` ([Modes](#modes)).
9. **Removal,** one stable release later: the add-on, the event worker and their scripts.

## Open questions

1. **Where the code lives:** a separate workspace in this repository (recommended), a member of the core's workspace, upstream, or a new repository (the user's decision).
2. **Private windows:**
   - an in-memory instance per private partition in one process (recommended), one instance shared by all private windows, or a process per window, which would also separate address spaces?
   - are 8 instances under a 448 MiB budget the right bound?
3. **The proxy's scope:**
   - SOCKS5 to Arti only (this design), or also a user's HTTP proxy for the HTTP half? libp2p would need another custom transport for that.
   - Should Route IPFS through Tor follow a future "everything through Tor" mode, and be one switch with 0008's Radicle setting?
4. **Routing under a proxy:** delegated only (recommended), or the light DHT through SOCKS, which costs many Tor circuits per query? And how many IPFS peers accept connections from Tor exits on their ports? That is to be measured before the setting ships.
5. **Local providers:** the address policy refuses untrusted local targets by default. Should a user setting allow providers on the local network?
6. **The musl build:** do SQLite and `ring` build statically for both Linux targets in this repository's release workflow? If not, the Linux builds need a glibc floor of their own, chosen with #350 in mind.
   - **They build, but the Linux builds link glibc 2.17 instead,** for [Cost](#cost).
     - The dry run of #144 built both targets static, with musl's C compiler wrapper, and on x86_64 the service's whole test suite passed against the musl build.
     - But musl's allocator (mallocng) maps and unmaps each large buffer: each 256 KiB block SQLite reads, and the gateway's copies of it. The service spent its time in page faults and `munmap`, and a cached file streamed at about 75 % of the add-on's rate locally and 54 % on the hosted linux-x64 runner, under the 80 % gate.
     - Replacing the static binary's allocator, for C code too, was measured:
       - mimalloc reached about 130 %, but the C source its crate bundles has secure mode fail on 64 KiB pages, and lacks two upstream hardening fixes (ca77e6d, ef3867f), so shipping it meant maintaining patched C;
       - jemalloc reached about 127 %, but bakes the build machine's page size in.
     - **Decision:** link glibc dynamically, no newer than 2.17, Rust's own floor for these targets (`cargo-zigbuild --target <triple>.2.17`, pinned in `release-ipfsd.yml`).
       - A cached file streams at about 132 % of the add-on's rate locally, with a peak RSS near 84 MiB, against musl's 49 MiB.
       - The allocator is the system's, hardened and patched with it.
       - Electron's binary needs GLIBC 2.25 at most, so the service runs wherever the browser does; the add-on needed 2.38 (#350). Distributions on musl, which only a static build would reach, can't run Electron.
     - `release-ipfsd.yml` checks each Linux binary: its highest `GLIBC_` symbol version, the libraries it needs (glibc's and `libgcc_s` only), and its usage exit. On x86_64, the service's whole test suite passed on CentOS 7's glibc 2.17.
7. **Upstream timing:** will freedom-ipfs take items 1–8? Until a release carries them, does the service pin a commit on a branch?
8. **Streams in the core:** should 4.5's protocol version 2 for `freedom-cored` adopt these four frames as they are, with an explicit global credit added?
9. **An OS memory limit:** should each service run under `RLIMIT_AS`, or a Windows job memory limit, as a backstop for what its budget can't see?
10. **If Arti can't `RESOLVE`:** should the Tor setting wait until it can, or ship with the proxy's own policy (option (b)) as an explicit deviation? This design waits (the user's decision).
    - **Moot for now:** the pinned Arti 2.7.0 qualifies (freedom-browser #771). It answers `RESOLVE` with one address, with credentials and without. The qualification runs again whenever the pin moves.
11. **Stream isolation under Tor:** should each instance (the profile's, and each private window's) send SOCKS credentials of its own, so Arti keeps their streams on separate circuits?
    - **Decided (the user, 2026-10-22): yes, isolate** ([The SOCKS contract](#the-gate), *Stream isolation*). It needs `RESOLVE` with authentication, which tokio-socks doesn't offer, so the service uses a small SOCKS5 client of its own.
