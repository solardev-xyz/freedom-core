# 0007: The freedom-ipfs service process

**Status:** proposed. Roadmap Phase 4 (item 4.2). Builds on [0001](0001-freedom-cored.md) (process model, lifetime lock, framing, hardening), [0005](0005-chain-data.md) (credit) and [0006](0006-dweb-transports.md) (plans, and the outline in *Service processes*).

**The references:**
- **freedom-browser** at `c5bd66d5` (#704, `claude/dweb-plans`):
  - `ipfs/freedom-ipfs-native-binding.js`, `ipfs/freedom-ipfs-native-node.js` and `ipfs/freedom-ipfs-event-worker.js`;
  - `ipfs-manager.js` and its `ipfsBackend()`;
  - `dweb/plan-executor.js` and `dweb/fetch-admission.js`;
  - `core/core-client.js` and `core/frame.js`;
  - `scripts/fetch-freedom-ipfs-native.js`.
- **freedom-ipfs** v0.4.5 (`9316571`), the release freedom-browser pins. Line references below are to that tag:
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
  - A panic inside freedom-ipfs on a request's task fails that request only. A panic anywhere else ends the process, through a hook that logs a fixed code and never the payload.
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
- **The plan executor (#704) doesn't change.**
  - `ipfsBackend().request()` keeps its contract: a `Response` whose body is pulled with backpressure.
  - It becomes a client of the service instead of the add-on.
  - The core and the plans don't change either: the backend reference stays `{ ipfs: "native", up }`.
- **Private windows get memory-only nodes.**
  - One ephemeral process serves every private window, with one in-memory instance per private partition.
  - The instance starts on the partition's first request, inside `request()`.
  - Nothing a private window loads reaches the profile's cache or the application's files. The instances partition caches and PeerIDs; they don't partition address spaces.
- **Budgets are process-wide.** Retrieval admission, background queues and one memory budget span every instance in a process. Each budget names what it charges.
- **Network policy becomes configuration, behind one gate.**
  - `direct`, or `socks5` for all of the service's traffic. Under SOCKS, QUIC and the local DNS resolvers are off, and names go to the proxy.
  - Every target is classified once (onion, IP literal or name) before any expansion. The policy is applied again after expansion, before each connection, and on every HTTP redirect hop.
  - By default, loopback, private and link-local targets learned from the network are refused, while configured endpoints are exempt.
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
  - Start is `nodeNewWithDataDirAsync(dataDir, 256 MiB)`, then `nodeStartNativeGatewayOnlineAsync(handle, '', AUTO, 0, 3, 0, 15000)`:
    - the default delegated router (`https://delegated-ipfs.dev/routing/v1`);
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
  - the `FREEDOM_IPFS_*` tuning variables freedom-ipfs's retrieval crate reads.
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
- **`hold-lock`:** `freedom-ipfsd hold-lock --data-dir … --lock-dir …` holds the gate until its stdin closes, as the core's does. Profile delete, profile reset and `ipfs:reset` hold it while they remove the directory.
- **What the lock guarantees, and what it doesn't:**
  - **It excludes only writers that take it:** the service, `hold-lock`, and the dev add-on fallback, which holds `hold-lock` for its whole lifetime ([Rollback](#rollback)).
  - **An older build** runs the add-on with no gate. Old and new builds sharing one data directory, for example through `FREEDOM_IPFS_DATA` or two profiles pointed at one directory, are unsupported.
  - **The profile lock** only excludes two owners of the same profile, as today.
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
  - **Request work** runs on tasks marked as request tasks, built with `panic = "unwind"`. A panic there is caught at its join handle, after the hook's fixed line:
    - before the head, it becomes that request's `internal` error;
    - after the head, the stream's `internal` abort.
  - **Every other task** (swarms, background retrieval, the instance's own tasks) belongs to an instance's task set or to the process ([Instances](#instances-and-their-teardown)). The service observes every such task's end. A panic, or an unexpected end, of a non-request task exits the process with 70, so it is a crash and main restarts it.
  - **A panic on any non-runtime thread** exits with 70 from the hook.
  - The service's own code is under the workspace lints: no `unsafe`, `unwrap`, `expect` or `panic!`.

### Inside the process

- **Runtime:**
  - tokio, multi-threaded. freedom-ipfs requires it: its block provider calls `block_in_place` (`rv:5447`, `rv:5499`, `rv:5534`), which panics on a current-thread runtime.
  - Worker threads: the core count, capped at 8.
  - The blocking pool's thread cap is 512, stated explicitly. Every in-flight block fetch holds a thread. What bounds that work is the process-wide [retrieval admission](#budgets), not this cap or upstream's constants.
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
  - Upstream's tracing feeds only the progress recorder, as the add-on's subscriber does today.

### Instances and their teardown

Aborting a task doesn't stop work that is blocked in `block_in_place`, and work an instance spawns on its own outlives its spawner. So an instance is an **owned group**, and every boundary waits for proof that the group has finished.

- **The group:** upstream's builder returns an `Instance` that owns:
  - **a root cancellation token,** which every operation observes: HTTP requests, DoH and DNS lookups, DHT queries, Bitswap requests, and each `block_on` inside a blocking region;
  - **a task set,** with every task the instance spawns: request work, the shared Bitswap swarm's task (`rv:7390` spawns it today), DHT query swarms, and any background retrieval;
  - **a blocking-region count,** raised and lowered around every `block_in_place`;
  - **a network capability:** the instance's handle on [the gate](#the-gate). Every socket, HTTP attempt and redirect hop asks it first, and revoking it makes every later ask fail.
- **The teardown,** for a stop, an eviction, a policy change and shutdown alike:
  1. **Fence:** the instance's ID is retired at once ([Instance IDs](#instance-ids)), and new requests for it get `stopped`.
  2. **Revoke:** the network capability is revoked, so no new connection can be made, whatever is still running.
  3. **Cancel:**
     - the root token is cancelled and the task set aborted;
     - the swarms are dropped, which closes their connections;
     - in-flight heads are answered `stopped`, and open streams aborted with `stopped`.
  4. **Wait for quiescence:** the task set is empty, the blocking-region count is zero, and the store is closed (`close`, waiting at most 2 s for a statement in progress, as upstream's `close_or_close_later` does).
  5. **Acknowledge:** only then does `ipfs.stop` reply, a replacement start, an eviction count as done, or `ipfs.shutdown` exit.
- **The bound:** the teardown has 5 s. If quiescence isn't proven by then, the service doesn't proceed: it writes `teardown_unproven` and exits 70.
  - Main treats that as a crash and restarts the process.
  - So no surviving work of an old instance can resume after a boundary, and its budget share isn't handed to a new instance while it might still be in use.
- **Charges stay until the end:** a stopping instance keeps its [budget](#budgets) charges until quiescence. A new instance starts only within what is free.

## The protocol

### Frames

0001's frame layer: a `u32` big-endian length, a `u8` kind, then the payload.

- **Kind `0x01`** carries a JSON message of at most 1 MiB, with 0001's envelope: `request`, `response`, `event` and `cancel`, and exactly one terminal response per request.
- **Request IDs strictly increase** within a connection (0001's counter, never reused). The stream rules below rely on it.
- **Kinds `0x02`–`0x05`** are the stream frames, taken from 0001's reserved range.
  - Each payload starts with the stream's 8-byte big-endian ID.
  - The payload length is checked against the kind before anything else is done with the frame.
- **The stream ID is the `ipfs.request`'s envelope ID.** One request has at most one body, so no separate ID space or open frame is needed: the head response opens the stream.

| Kind | Name | Direction | Payload after the ID |
|---|---|---|---|
| `0x02` | data | service → main | 1 to 65 536 body bytes |
| `0x03` | end | service → main | none (exactly 8 bytes in all): the body is complete |
| `0x04` | abort | service → main | JSON `{ code, message }`, ≤ 1 KiB: the body is truncated |
| `0x05` | credit | main → service | a `u32` big-endian, > 0 (exactly 12 bytes in all): bytes main has handed on |

**Order, per stream:**
- **The sequence is fixed:** the head (a `0x01` response), then data, then exactly one terminal (`end` or `abort`). A head that says `body: false` opens no stream.
- **Each stream is a FIFO.** Its head, data and `end` are queued in order, and **`end` is written only after the stream's last data frame has been written**.
- **`abort` is the one frame that jumps the queue.** It purges the stream's queued, unwritten data and is then written. Nothing of the stream is written after it.
- **Cancel against an unwritten head:** when main's `cancel` arrives while the head is queued but not yet written, the head is dropped. `cancelled` is the request's only reply, and no stream opens.
- **Once the head is written,** a cancel gives `abort { code: "cancelled" }`, unless `end` is already written. Then the cancel is late and is ignored, as in 0001.

**Credit:**
- **The window** is 128 KiB per stream, fixed by the handshake.
- **The service's account,** per stream, in checked 64-bit arithmetic:
  - `sent` counts the bytes in data frames queued for the stream;
  - `credited` counts the bytes main has returned.
  - **Debit** happens when a data frame is queued: queuing is allowed only while `sent − credited + len ≤ 128 KiB`.
  - **Refund:** none. A purge by `abort` ends the stream, so its account is dropped with it.
- **Main's account,** per stream:
  - `received` counts data bytes that have arrived;
  - `returned` counts the bytes main has credited.
  - Main credits a chunk's bytes when it hands that chunk to the body's consumer, so `returned ≤ received`.
- **Protocol errors** (0001: log and close):
  - data beyond the window (`received − returned > 128 KiB` in main);
  - credit beyond what was sent (`credited > sent` in the service);
  - an empty data frame;
  - a wrong fixed payload length;
  - a frame for a stream ID above the highest request ID seen;
  - a second terminal frame;
  - stream data sent by main, or credit sent by the service.
- **Late frames:**
  - Credit for a stream ID that was opened and has since ended is late and is ignored: it can cross a terminal frame in flight.
  - Because IDs increase, recognizing it needs no table: an ID at or below the highest seen that isn't live is late.

**Allocation bounds:**
- **Main coalesces.** Received data is appended into owned buffers of 64 KiB per stream, never kept as one object per frame. A 128 KiB window therefore holds at most 3 buffers, whatever the frame sizes.
- **The service coalesces too.** A data frame carries as much of the stream's pending body as the window and the 64 KiB frame limit allow. A frame smaller than 4 KiB is written only when it is all that is pending, or all the credit allows.
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
  "freedom_ipfs": { "version": "0.4.5", "git_commit": "9316571…" }, "kind": "persistent" } }

{ "type": "request", "id": 2, "method": "ipfs.start", "params": {
    "instance": "p-1",                                              // never reused within the process
    "store":   { "kind": "disk", "max_bytes": 268435456 },        // or { "kind": "memory", "max_bytes": 33554432 }
    "routing": { "mode": "auto", "delegated_routers": ["https://delegated-ipfs.dev/routing/v1"],
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
  - The values above are exactly today's (v0.4.5's defaults where the add-on passes 0), sent explicitly.
  - The persistent process accepts one `disk` instance at a time. The ephemeral process accepts only `memory` instances of at most 32 MiB, and at most 8 of them.
  - A start is admitted only within the free [budget](#budgets). Anything else is `invalid_argument`, or `busy` when the budget isn't free.
- **`ipfs.request`:**
  - The `path` and `headers` are the plan's, passed through.
  - The service builds the gateway request with freedom-ipfs's own native-request parser (an [upstream change](#upstream-changes-in-freedom-ipfs) makes it public), so it treats requests exactly as the add-on does.
  - As main does today, it sets the request ID to the envelope ID and the top-level path to `path`.
  - `body` is false for `HEAD` and for 204, 205 and 304, which is main's rule today. Any bytes the gateway produces then are dropped.
  - A request is one JSON frame, within 0006's bounds of 64 KiB for the URL and 64 KiB for the headers.
- **No caller context.**
  - Every request is main's, for a request main has already admitted and fenced. The service has no per-caller policy.
  - The instance is the only partition. Main picks it from the session's partition, never from page input.

### Instance IDs

- **Never reused.** Main allocates each instance ID from a counter per process generation: `p-1`, `p-2`, … for the persistent instance, and `e-1`, `e-2`, … for private ones. A restart of the persistent instance, for example on a policy change, gets a new ID.
- **Every captured backend binds a pair:** the generation and the instance ID. `ipfsBackend()` captures it at admission, and every continuation carries it: the wait for a plan, the `request()` call, its body.
- **Retirement is synchronous in main.** When a stop, an eviction, a partition close or a policy change begins, main marks the pair retired before sending `ipfs.stop`. A continuation that reaches a retired pair fails at once with `freedom-ipfs native node is not running`, and nothing is sent.
- **The service checks too:** a request naming an ID that is retired or unknown gets `stopped`. A late request from before a change can therefore never reach the instance that replaced it, in either direction.

### Cancel, deadlines and admission

- **`cancel`:** see [Order](#frames) for the head and stream cases.
  - Cancellation reaches the work through the request's own token, a child of the instance's root token. That includes a blocking region, through its inner future.
  - The request's admission slot is released only when its work has ended, not when the reply is sent.
- **`headers_ms`:**
  - It runs from admission, so queue time and routing count. On expiry the request's token is cancelled and the reply is `deadline`.
  - After the head there is no deadline in the service. Main's 60 s body-idle timer (0006) cancels a stalled body.
- **Admission:** at most 512 requests per process, counting heads, open streams, and work still ending after a cancel. Beyond that the reply is `busy`.
  - Main sends at most 512 outstanding service requests, retiring ones included ([Frames](#frames)). So `busy` here signals a fault, and the reply is from the reader's bounded refusals.

### Errors

| Code | When | Main's backend rejects or errors with (today's text) |
|---|---|---|
| `invalid_argument` | the request can't be parsed: an unsupported method, path or header | `freedom-ipfs native request could not be started` |
| `stopped` | the instance is retired, unknown or stopping | `freedom-ipfs native node is not running` |
| `deadline` | no head within `headers_ms` | `freedom-ipfs native request timeout` |
| `cancelled` | main's `cancel` | `freedom-ipfs native request aborted` before the head; `…cancelled` for a body |
| `busy` | admission or a budget is full | `freedom-ipfs native node is busy` (new) |
| `internal` | a panic on the request's task | `freedom-ipfs native gateway error` |
| `storage` | `ipfs.start`: the store won't open (`data.kind`) | the manager's `Failed to start freedom-ipfs native node` |
| `protocol_mismatch` | `ipfs.hello` | a startup error; no restart |

- **HTTP failures are heads,** as today: 400, 404, 416, 502, 504, and the 503 `gateway_busy` with `Retry-After: 1` from the 15 s queue. They have bodies, and pass to the plan executor unchanged.
- **A target the gate refuses** fails that retrieval attempt as a connection failure would, so the head is upstream's usual 502 or 504.
- **Abort codes:**
  - `cancelled`;
  - `internal`;
  - `body_stream_error` (upstream's code for a failing body);
  - `stopped`.

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
- **`progress`:** upstream's progress snapshot. The persistent process only.
- **`store`:** `block_count` and `total_bytes`.
- **`budget`:** each [budget's](#budgets) use and limit.

The 5 s health check calls `ipfs.stats`. `checkHealth()` stays synchronous, because `ipfsBackend()` calls it at admission. It reads a snapshot that is true while all of these hold:
- the generation is live;
- the instance is started;
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
- **The memory budget,** one per process:
  - **Persistent:** 128 MiB.
  - **Ephemeral:** 384 MiB.
  - **What it charges:**
    - **memory stores:** SQLite's page use (`page_count × page_size`), which covers blocks and metadata both;
    - **hot caches** and the gateway's small-body caches, at their configured sizes;
    - **transient blocks:** bytes being fetched, verified or held for a stream, charged when a fetch begins at its upper bound (2 MiB for an HTTP provider block) and trued up on arrival;
    - **pending replies:** heads waiting to be written, at their encoded size;
    - **the writer's data queue:** 16 MiB.
  - **What it doesn't charge:** the disk store's file, which upstream's `max_bytes` bounds on disk; and allocator and library overhead it can't see.
- **What a store's `max_bytes` means:** a target for block data that drives LRU eviction, not a hard bound.
  - Blocks that are retained while being streamed can't be evicted, so a store can pass its target until they are released.
  - Metadata tables have their own rules: names are pruned to 128 rows, while provider and failing-provider records expire.
  - The memory budget, not `max_bytes`, is the hard bound for memory stores. A private instance's 32 MiB is its block target. Its charge is its measured page use.
- **Under pressure:**
  1. new requests get `busy` (503);
  2. idle private instances are evicted first ([Private windows](#private-windows));
  3. work already admitted runs on.

  The process doesn't promise a bound on memory it can't account for. An OS-level limit is an [open question](#open-questions).
- **Stopping instances** keep their charges until their teardown is complete.

## Main's side

`ipfsBackend()` keeps its contract (#704):

```js
ipfsBackend({ partition }) → { ref: { ipfs: 'native', up }, url: null,
                               request({ path, method, headers, signal, headersTimeoutMs }) → Promise<Response> }
```

- **What changes:**
  - It takes the request's partition. `ipfs-protocol.js` already has it, from its `privatePartition` registration.
  - It captures the generation and instance ID ([Instance IDs](#instance-ids)).
  - A private partition gets its own instance, started inside `request()` ([Private windows](#private-windows)).
  - The core still sees only `ref`.
- **`request()`:**
  - **An already aborted signal** rejects at once. Nothing is sent, as today. So does a captured pair that has been retired.
  - **Otherwise** it sends `ipfs.request` with `headers_ms: headersTimeoutMs`, and registers one abort listener that sends `cancel`.
  - **On the head** it resolves `new Response(body, { status, headers })`:
    - `body` is `null` when the head says `body: false`;
    - otherwise it is a byte `ReadableStream` whose `pull` takes the next buffered bytes and returns them as credit;
    - its `cancel` starts retirement ([Frames](#frames)).
  - **A rejection** carries today's message ([Errors](#errors)). The executor's `failure()` makes it the same 502 as today.
- **End of a body:**
  - **On `end`,** main records EOF but keeps the buffered bytes. The stream closes when the consumer has read them all.
  - **On `abort`,** the stream errors at once and its bytes are dropped.
  - **Every terminal path frees:** the record and its buffers go once the consumer is done and the terminal has arrived (or the generation has ended). The executor's `onEnd` releases the admission slot.

  The executor's contract is unchanged: a pull-driven body, truncation surfaced as an error, and nothing started for a signal that is already aborted.
- **The client:**
  - `core-client.js`'s supervision becomes a shared `ServiceClient`: spawn, the handshake, generations, restart back-off, kill, the frame reader and the writer with reserved control room.
  - `freedom-cored`, `freedom-ipfsd` and 0008's `freedom-radicled` each configure their own instance of it.
  - `frame.js` accepts kinds `0x02`–`0x05` only on a connection whose handshake granted `stream`.
- **Main's memory:**
  - stream bytes are at most 256 active fetches × 128 KiB = 32 MiB, in at most three 64 KiB buffers per stream;
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
- **The cold start runs inside `request()`:**
  - **Readiness:** for a private partition, `ref.up` reports the manager's readiness, not the instance's. It is true while all of these hold:
    - the profile's IPFS is bundled and `RUNNING`;
    - the ephemeral process isn't stopped after three crashes;
    - fewer than 8 instances are pinned.

    So a cold partition still gets a fetch plan.
  - **`request()` ensures the instance:** it spawns the ephemeral process if needed (with `ipfs.hello`), then sends `ipfs.start` for the partition's instance, then the request.
    - All of it runs under the request's signal and its `headers_ms`. An abort or the deadline stops it, and the head deadline covers the start.
    - Concurrent first requests from one partition share one start (single flight).
- **Pinning:**
  - A pin is taken on the partition's instance (or on its pending start) when `ipfsBackend()` captures it, and released when that request's work ends.
  - So a pinned instance is held through planning, preparation and use.
  - **Eviction picks only unpinned instances:** a ninth partition evicts the least recently used one with no pins. If all 8 are pinned, the new partition's `request()` rejects with `busy`, and main answers 503.
- **Fences:**
  - **Eviction and `closeDwebSession(partition)`** retire the instance's ID first, so every continuation that captured it fails before sending. Then comes the [teardown](#instances-and-their-teardown).
  - **A close during the cold start** cancels the start. The instance, if it came up, is torn down.
  - **When the last instance has stopped,** main sends `ipfs.shutdown`, and the process exits with everything it held.
- **Bounds:**
  - at most 8 live instances;
  - each has a 32 MiB block target and a hot cache of 4 MiB (an upstream option), under the process's 384 MiB [memory budget](#budgets).
- **What stays out of the application's files:**
  - `SqliteBlockStore::in_memory`, with `temp_store = MEMORY` ([upstream](#upstream-changes-in-freedom-ipfs)), so SQLite writes no temp files;
  - no data directory and no lock;
  - logs without paths, and panic lines without payloads;
  - no progress snapshot;
  - no core dumps ([Spawn](#spawn)).

  The OS's swap and hibernation files are outside this guarantee.
- **Identity:**
  - each instance's Bitswap swarm has its own fresh identity, and DHT queries use a new one each time, as upstream does;
  - so a private partition shares no PeerID with the profile's node or another partition;
  - it does share the machine's IP address, unless the [network policy](#network-policy) sends traffic through Tor.
- **Restarts:** the ephemeral process follows the same rules. Its instances come back lazily, cold and under new IDs.
- **The nodes panel** keeps showing the persistent node only.

## Network policy

### What can be honored

- **`reqwest`:**
  - SOCKS5 with remote name resolution (`socks5h://`), once its `socks` feature is on.
  - Every client must be built with an explicit proxy or with `no_proxy()`. Today none sets either (`ns:828`, `rt:1807`, `rv:11132`), so the environment decides.
  - A custom redirect policy can run a check on every hop before it is followed.
- **libp2p 0.56:**
  - It has no SOCKS transport. TCP, and WebSocket over TCP, can go through a small custom `Transport` over `tokio-socks`, which hands the proxy host names rather than addresses.
  - **QUIC can't be proxied:** Tor carries TCP only, and Arti doesn't offer SOCKS5 `UDP ASSOCIATE`.
  - **libp2p's own resolver** (hickory, `ResolverConfig::cloudflare()`, plain DNS to 1.1.1.1 on port 53; `rt:1601`, `rv:8847`) must be off under a proxy.
  - **`/dnsaddr`** needs TXT records. Under a proxy they come from DoH through the proxied client, as Bitswap's address expansion already uses DoH (`rv:9435`).
  - An embedded Tor client (`arti-client`) is not used: Freedom already runs Arti, and a second Tor client in the service would duplicate it.
- **freedom-ipfs v0.4.5 honors none of this:**
  - the clients and transports are built inside the crates;
  - QUIC is always added (`rt:1597`, `rv:8825`);
  - the DoH resolver is fixed at `mob:2226` and `rv:9436`, `9484` and `9531`;
  - there is no hook where a target can be checked.

### Modes

- **`direct`, the default:** today's transports, behind [the gate](#the-gate). The environment's proxy variables no longer apply (deviation `env-proxy`).
- **`socks5 { ip, port }`:** all of the service's traffic goes through the proxy.
  - **The endpoint is an IP literal,** so reaching the proxy needs no DNS. The service never resolves the proxy's name.
  - **HTTP:** delegated routing, DoH and HTTP providers, all over `socks5h`. Names are resolved by the proxy, never locally.
  - **Bitswap:** TCP and WebSocket through the SOCKS transport. QUIC and hickory are off.
  - **Routing:** `delegated` by default, since the light DHT dials dozens of peers per query, each through Tor.
  - **Fails closed:**
    - a proxy that is down fails the attempt, which gets upstream's 502 or 504;
    - nothing falls back to a direct socket;
    - a transport the proxy can't carry (QUIC, or any other non-TCP transport) is refused before any socket exists.
- **Where the proxy comes from:**
  - A new per-profile setting, **Route IPFS through Tor**, off by default, sends Arti's SOCKS endpoint from `tor-manager`, as an IP and port.
  - Today Tor in Freedom means onion access. Clearnet and the dweb protocols stay direct (`docs/features.md`), and this design keeps that default.

### The gate

**One classification, before anything else.** Every target is classified once, before any DNS or TXT expansion, by one function shared by URLs and multiaddrs:
- **Normalization of a host:** lowercase it, remove one trailing dot, and refuse non-ASCII (names must already be in punycode).
  - URL hosts are parsed with the WHATWG rules, so numeric IPv4 forms (`0x7f.1`, `2130706433`) become literals.
  - An IPv4-mapped IPv6 address is classified as its IPv4 address.
- **The classes:**
  - **onion:** the last label is `onion`, whether in a URL host or in `/dns`, `/dns4`, `/dns6` or `/dnsaddr`; and every `/onion3` (or `/onion`) multiaddr;
  - **IP literal:** a URL host, or an `/ip4` or `/ip6` component;
  - **name:** everything else.

**The policy:**
- **Configured targets** are the delegated routers and DoH endpoint in `ipfs.start`, and Arti's endpoint. They are exempt from the address policy, by exact host (and port), including when one is local.
- **Untrusted targets** are everything learned from the network:
  - provider records and their multiaddrs;
  - HTTP provider URLs built from them;
  - `/dnsaddr` results;
  - DHT peers;
  - redirect targets, even from a configured endpoint.
- **The address policy, by default,** refuses untrusted targets in:
  - loopback, `0.0.0.0/8` and `::`;
  - private ranges (RFC 1918, `fc00::/7`);
  - link-local (`169.254.0.0/16`, `fe80::/10`);
  - CGNAT (`100.64.0.0/10`);
  - multicast, broadcast and the documentation ranges.
- **Onion targets:**
  - in `direct` mode, refused before any socket exists, as the session's onion gate refuses them (`OnionGateRefusal`);
  - in `socks5` mode, handed to the proxy as names, never resolved locally.

**Where it is applied:**
1. **Before expansion:** the original target is classified, and an onion or a refused literal stops here. Nothing is expanded or resolved for it.
2. **After expansion:** every address that `/dnsaddr` or DNS expansion produces is classified and checked again.
3. **Before each connection,** at the transport. In `direct` mode, every address a name resolves to is checked, and the connection goes only to one that passes. In `socks5` mode, the check runs on what is handed to the proxy: IP literals are checked, and names go unresolved.
4. **On every HTTP redirect hop:** the redirect policy runs the gate on the `Location` target before following it. That covers delegated routing, DoH and providers. A refused hop fails the attempt.

**Redirect behavior** is part of parity:
- v0.4.5's provider client follows no redirect (`rv:11136`), while its routing and DoH clients follow reqwest's default (`rt:1807`, `ns:828`).
- The service keeps each client's acceptance and adds the gate to every hop (deviation `redirect-gate`).

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
3. **A network policy.** One `NetworkPolicy` value, threaded through the builder, that supplies:
   1. **HTTP clients:**
      - a single constructor taking `Option<reqwest::Proxy>` and each client's redirect acceptance, which wraps every redirect in the gate (hop check 4);
      - it replaces the three `timeout_http_client` functions (`ns:828`, `rt:1807`, `rv:11132`) and calls `no_proxy()` when no proxy is given;
      - it enables `reqwest`'s `socks` feature.
   2. **Errors instead of panics:** the three constructors `expect` today (`ns:833`, `rt:1812`, `rv:11138`). With a proxy their configuration can fail, so they must return an error.
   3. **DoH:** the endpoint and its client come from the policy, at `mob:2226` and `rv:9436`, `9484` and `9531`. DNSLink is already pluggable (`DnsTxtResolver`, `ns:53`); Bitswap's address expansion isn't. Expansion results pass through the gate (check 2).
   4. **Transports:**
      - `build_dht_swarm` (`rt:1588`), `build_bitswap_swarm` (`rv:8816`) and `cloudflare_websocket_transport` (`rv:8847`) take `quic: bool`, `dns: Hickory | None`, and `tcp: Direct | Socks5(addr)`;
      - add a SOCKS5 `Transport` over `tokio-socks` (MIT) for `/ip4`, `/ip6`, `/dns*` and `/onion3` with `/tcp`, and for WebSocket on top of it;
      - in `direct` mode, the TCP and WebSocket transports resolve names themselves and check each address before connecting (check 3).
   5. **The gate:**
      - the classification and the address policy as one function, applied where candidates are chosen (`rt:1491`–`1525`, `rt:1767`–`1805`), after expansion, and at the dial sites (`rv:7765`, `rv:7949`, `rt:1044`);
      - every check asks the instance's network capability, so revoking it refuses everything later.
4. **Progress and stats outside the FFI crate.**
   - Move the progress recorder and `progress_layer` (`mob:552`–`1018`) to a library crate, with a recorder per node rather than the process-global `PROGRESS_RECORDER` (`mob:79`).
   - The service then links no C ABI, and two instances' progress never mixes.
   - If a cancelled request leaves its entry in `active` until `clearProgress`, as the code suggests, close the entry on cancel.
5. **Store options:**
   - `temp_store = MEMORY` for `in_memory` stores;
   - a hot-cache size independent of `max_bytes` (today `min(max_bytes, 16 MiB)`, `st:609`), since a memory store holds the bytes twice;
   - its page use (`page_count × page_size`) as a metric.
6. **Build info:**
   - `buildInfoJson` reads `FREEDOM_IPFS_GIT_COMMIT` and `FREEDOM_IPFS_GIT_DESCRIBE` (`mob:1333`), but the packaging script sets `FREEDOM_IPFS_BUILD_GIT_*`, so both fields are always null.
   - Move the function to a library crate and fix the names. `ipfs.hello` reports it.
7. **Owned instances and cancellation:**
   - **A root cancellation token per instance,** with a child per request, observed by every await in routing, retrieval, namesys and the gateway, including the futures run by `block_on` inside the blocking regions (`rv:5447`, `rv:5499`, `rv:5534`).
   - **A spawner handle** in the builder: every task the instance starts goes into its task set, including the shared Bitswap swarm's task (spawned at `rv:7390`, which keeps only a command sender today) and DHT query swarms.
   - **A blocking-region counter** around each `block_in_place`.
   - **`Instance::shutdown()`,** which runs steps 2–4 of the [teardown](#instances-and-their-teardown) and reports whether quiescence was reached.
8. **Shared limiters and accounting:**
   - the builder takes process-wide limiters for block fetches, HTTP provider requests, Bitswap connections and DHT queries;
   - a byte budget for transient blocks, charged before a fetch begins;
   - the background queue bound of 64;
   - callbacks the service uses to charge caches and stores to its [memory budget](#budgets).

## Where the code lives

Four options. A new repository is the user's decision; this design recommends the first.

1. **This repository, as `services/freedom-ipfsd`, a separate Cargo workspace** (recommended).
   - **For:**
     - `fc-protocol` by path, so one frame and stream codec;
     - one release workflow, with static musl Linux builds, which would also close #350's GLIBC floor if the C dependencies build there ([Open questions](#open-questions));
     - `SHA256SUMS` and attestations;
     - freedom-browser's fetch-and-verify script pattern, extended to a second asset;
     - the same lints, copied into its manifest, since workspace lints don't cross workspaces.
   - **Its own workspace,** excluded from the core's (`exclude = ["services"]`).
   - **Its own `Cargo.lock` and `deny.toml`** keep the core's dependency graph as it is. v0.4.5 alone locks 453 packages, against the core's 133:
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
- **Private cases:**
  - a first private load;
  - concurrent first loads in one partition: one start;
  - a ninth partition evicting during another's planning: only unpinned instances go;
  - a close during the cold start;
  - exhaustion across all 8 instances: `busy`, and the budget holds;
  - a panic whose payload holds a path: the log has only the fixed line.
- **Budget cases:** many distinct CIDs over a long-lived instance, and over every private instance at once. The memory budget and the retrieval admission hold.
- **Rust tests through the binary,** using test-only methods behind a cargo feature, as `freedom-cored`'s `testhooks`. These seed a memory or offline instance from CAR fixtures, and inject a panic, a stall or a slow teardown.
  - **The protocol:** frames, credit, cancel races, deadline, and one terminal per request and per stream.
  - **Isolation:** a panic on one request is `internal` for that request only.
  - **The lock:** contention gives 75, a network filesystem gives 74, and `hold-lock`.
  - **Parent death,** the 5 s exit watchdog, and parent death while the writer is backed up.
  - **The stall:** exit 76.
- **Network policy tests:**
  - **A SOCKS5 test proxy** records every connection, and a canary TCP and UDP listener is advertised as a provider and a router. In `socks5` mode the canary must see nothing, and the proxy everything.
  - **Expansion and redirects:** a `/dnsaddr` that expands to a loopback address, a name that resolves to a private address, and a configured router or provider that redirects to a private address, to an onion URL and to a different scheme. Each is refused before a socket opens.
  - **Canonical forms:** upper case, a trailing dot, an IPv4-mapped IPv6 address, numeric IPv4 URL hosts, and `/dns/<x>.onion`.
  - **Failures:** an unavailable proxy, and an unsupported transport in `socks5` mode.
  - **Onion:** `.onion` and `/onion3` targets in `direct` mode open no socket.
- **Live:** `ipfs:native:smoke` re-pointed at the service, with `/ipns/ipfs.tech/` and #102's fan-out of 48 concurrent requests and no `gateway_busy`.

### Parity

| Item | Today | The service |
|---|---|---|
| configuration | `AUTO`, the default router, DHT 3 s, 8 permits, 15 s queue, 256 MiB | the same values, sent explicitly |
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
| stream bytes in main | 256 active fetches × 128 KiB = 32 MiB, ≤ 3 buffers per stream | not reachable: credit |
| data frames queued in the service | 16 MiB | stream producers wait |
| service reader | 256 frames and 16 MiB (0001); controls handled on arrival | stops reading |
| writer stall | 30 s with nothing written (0001) | exit 76 |
| retrieval admission, per process | 256 block fetches, 16 HTTP provider requests, 32 Bitswap connections, 4 DHT queries | work waits under its deadline |
| background queue | 64 items per instance | new background work is dropped |
| memory budget | persistent 128 MiB; ephemeral 384 MiB, as charged in [Budgets](#budgets) | `busy`; evict idle private instances |
| `ipfs.stats` | 5 s; main's watchdog at 20 s | on the watchdog, kill |
| abort payload | 1 KiB | protocol error |
| persistent cache | 256 MiB of block data on disk (a target), 16 MiB hot | upstream's LRU eviction |
| private instances | 8 per ephemeral process, 32 MiB block target and 4 MiB hot each | evict an unpinned idle instance, else `busy` (503) |
| gateway | 8 header permits, 15 s queue (today) | 503 `gateway_busy` |
| runtime | ≤ 8 workers; a 512-thread blocking cap | tasks wait |

## Deviations

| ID | Today | After | Effect |
|---|---|---|---|
| `crash-domain` | the add-on runs in main and a worker thread of main | a separate process | an IPFS fault fails IPFS requests only, never the browser |
| `auto-restart` | none; the user restarts IPFS from the nodes menu | 0.5 s, 2 s, 10 s; three crashes in 60 s stop | brief outages heal on their own |
| `data-dir-lock` | the profile lock only | an OS lock per data directory, for writers that take it | a second gated owner fails at start (75); old builds sharing the directory are unsupported |
| `network-fs` | the cache opens on any filesystem | a network filesystem is refused (74) | IPFS doesn't start there; WAL isn't safe there anyway |
| `private-windows` | private windows share the profile's node and on-disk cache | an in-memory instance per private partition, in one ephemeral process | private loads leave nothing in the application's files, aren't served from shared caches, and start cold |
| `env-proxy` | `reqwest` reads proxy variables from main's environment; libp2p ignores them | the environment is cleared, and the proxy is configuration | the HTTP half no longer follows `HTTPS_PROXY` and similar |
| `proxy` | none | an optional SOCKS5 policy for all traffic, failing closed | new: Route IPFS through Tor |
| `onion-targets` | no rule for them | refused before any socket in `direct`; through the proxy in `socks5` | a refusal proves nothing was sent |
| `address-policy` | none | untrusted loopback, private and link-local targets refused; configured endpoints exempt | providers on local networks are unreachable unless configured |
| `redirect-gate` | redirects follow each client's policy | the same acceptance, with every hop through the gate | a redirect to a refused target fails the attempt |
| `read-ahead` | one 64 KiB read in main, plus a two-chunk channel | a 128 KiB window per stream | about the same buffering, now bounded by credit |
| `exit-text` | `Native event dispatcher exited with code N`, `Native gateway stopped unexpectedly` | `freedom-ipfs service exited` | in 502 bodies and logs only |
| `stats-fields` | the event-queue fields in the diagnostics | dropped, with the queue; budget use added | the panel shows the rest |
| `targets` | the add-on ships for darwin-arm64, linux-arm64, linux-x64 and win32-x64, and needs GLIBC ≥ 2.38 | the service builds for this repository's five targets, static on Linux | IPFS on darwin-x64 and older distributions (#350), if the musl build holds |

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
   - `ServiceClient`, extracted from `core-client.js`, and the stream frames in `frame.js`;
   - instance IDs and retirement in `ipfs-manager.js`;
   - the fetch script and packaging (`mac.binaries` signing);
   - `ipfs-manager.js` on the service, behind `FREEDOM_IPFS_BACKEND` in dev;
   - the contract suite against the real binary;
   - the re-pointed smoke and the [cost](#cost) measurement.

   Then the default switches.
7. **Private windows:** the ephemeral process, the cold start in `request()`, pins, eviction and fences.
8. **Network policy:** the setting, Arti's endpoint, policy changes, and the gate, redirect, SOCKS and canary tests. This needs upstream item 3.
9. **Removal,** one stable release later: the add-on, the event worker and their scripts.

## Open questions

1. **Where the code lives:** a separate workspace in this repository (recommended), a member of the core's workspace, upstream, or a new repository (the user's decision).
2. **Private windows:**
   - an in-memory instance per private partition in one process (recommended), one instance shared by all private windows, or a process per window, which would also separate address spaces?
   - are 8 instances under a 384 MiB budget the right bound?
3. **The proxy's scope:**
   - SOCKS5 to Arti only (this design), or also a user's HTTP proxy for the HTTP half? libp2p would need another custom transport for that.
   - Should Route IPFS through Tor follow a future "everything through Tor" mode, and be one switch with 0008's Radicle setting?
4. **Routing under a proxy:** delegated only (recommended), or the light DHT through SOCKS, which costs many Tor circuits per query? And how many IPFS peers accept connections from Tor exits on their ports? That is to be measured before the setting ships.
5. **Local providers:** the address policy refuses untrusted local targets by default. Should a user setting allow providers on the local network?
6. **The musl build:** do SQLite and `ring` build statically for both Linux targets in this repository's release workflow? If not, the Linux builds need a glibc floor of their own, chosen with #350 in mind.
7. **Upstream timing:** will freedom-ipfs take items 1–8? Until a release carries them, does the service pin a commit on a branch?
8. **Streams in the core:** should 4.5's protocol version 2 for `freedom-cored` adopt these four frames as they are, with an explicit global credit added?
9. **An OS memory limit:** should each service run under `RLIMIT_AS`, or a Windows job memory limit, as a backstop for what its budget can't see?
