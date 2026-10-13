# 0007: The freedom-ipfs service process

**Status:** proposed. Roadmap Phase 4 (item 4.2). Builds on [0001](0001-freedom-cored.md) (process model, lifetime lock, framing), [0005](0005-chain-data.md) (credit) and [0006](0006-dweb-transports.md) (plans, and the outline in *Service processes*).

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
- **The binary calls the gateway crate directly.** It uses `GatewayCore::handle` with no C ABI, no handles that are raw pointers and no event worker. Its own code forbids `unsafe` and panics. A panic inside freedom-ipfs on a request's task fails that request only.
- **Bodies stream over the same pipe.** Four stream frames from 0001's reserved kinds (`0x02`–`0x05`) carry them, with a 128 KiB credit window per stream. Main's existing admission (256 active fetches) bounds the total at 32 MiB.
- **The plan executor (#704) doesn't change.**
  - `ipfsBackend().request()` keeps its contract: a `Response` whose body is pulled with backpressure.
  - It becomes a client of the service instead of the add-on.
  - The core and the plans don't change either: the backend reference stays `{ ipfs: "native", up }`.
- **Private windows get memory-only nodes.** One ephemeral process serves every private window, with one in-memory instance per private partition. Nothing a private window loads reaches the disk or the profile's cache.
- **Network policy becomes configuration.**
  - `direct`, or `socks5` for all of the service's traffic. Under SOCKS, QUIC and the local DNS resolvers are off and names go to the proxy.
  - `.onion` and `/onion3` targets are dialled only through the proxy.
  - freedom-ipfs has no hook for any of this today, so it needs upstream changes, [listed](#upstream-changes-in-freedom-ipfs) by file and line.
- **The code lives in this repository, in its own Cargo workspace** (`services/freedom-ipfsd`). It shares `fc-protocol`, CI and the release workflow, but not the core's lockfile. A new repository remains the user's call ([Where the code lives](#where-the-code-lives)).
- **Tests come first.** #704's native-backend cases become one contract suite, run against the add-on before anything moves, and then against the service.

## Goals and non-goals

**Goals**
- **Crash isolation:** no IPFS fault can end main. A crashed service is restarted with back-off, and only its in-flight requests fail.
- **Parity:**
  - the same `GatewayCore`, configuration and cache file, so responses are byte-identical;
  - #704's backend contract holds unchanged (see [Main's side](#mains-side));
  - the [deviations](#deviations) are listed.
- **One owner per data directory,** enforced by the OS rather than inferred from the profile lock.
- **Private windows leave nothing behind:** no blocks, names or provider records on disk, and none shared with the profile or with each other.
- **A network policy the node can honor,** failing closed: under a proxy, no direct socket.
- **Bounded memory** across the pipe, in the service and in main.

**Non-goals**
- **Content verification (4.5).** The service returns what `GatewayCore` returns. Main keeps no verifier; 0006's later design covers this.
- **The external gateway path** (`gatewayFetch`) stays as #704 left it, including in private windows.
- **libradicle (4.4):** its own design. This one's process and stream layer are meant to be reused there.
- **Persistent libp2p identity, content providing and a DHT server:** freedom-ipfs is a read-only client, and stays one.
- **Mobile:** iOS and Android keep linking freedom-ipfs in process.

## Today

- **Loading:**
  - `freedom-ipfs-native-binding.js` `require`s `freedom_ipfs_native.node`, an N-API add-on in C++ over the `freedom-ipfs-mobile` static library. It is fetched per target by `fetch-freedom-ipfs-native.js`, with one pinned SHA-256 per asset.
  - The add-on needs GLIBC ≥ 2.38 on Linux (#350).
- **Lifecycle:**
  - `FreedomIpfsNativeNode` serializes `start` and `stop`, and runs the add-on's `*Async` calls on the libuv pool. Start is `nodeNewWithDataDirAsync(dataDir, 256 MiB)`, then `nodeStartNativeGatewayOnlineAsync(handle, '', AUTO, 0, 3, 0, 15000)`:
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

- **One persistent process per profile,** for the profile's IPFS data directory (`getIpfsDataPath()`, unchanged). It is spawned when IPFS starts in bundled mode: at launch if `startIpfsAtLaunch` is set, and from the nodes menu.
- **One ephemeral process per profile,** spawned on the first private-window request ([Private windows](#private-windows)). It takes no data directory and no lock.
- **The binary:**
  - It comes from the app's resources, at `<resources>/freedom-ipfsd/`.
  - `FREEDOM_IPFSD_PATH` is honored only when `!app.isPackaged`, as `FREEDOM_CORED_PATH` is.
- **The environment** is cleared except for `PATH`, `HOME`/`USERPROFILE`, `LANG`, `RUST_LOG` and `SystemRoot` (`core-client.js`'s `scrubbedEnv`). That drops:
  - the proxy variables `reqwest` would otherwise read;
  - the `FREEDOM_IPFS_*` tuning variables freedom-ipfs's retrieval crate reads.
- **Handshake:** `ipfs.hello` must complete within 10 s of spawn. Both sides enforce this, as for `core.hello`.
- **No listening socket.** The service binds nothing. Upstream's loopback HTTP gateway is never started.

### Lifetime lock

0001's lock, with its own namespace:

- **The file:** `<lock-dir>/ipfs-<sha256(canonical data dir)>.lock`.
  - The lock directory is the core's, `<OS app-data>/Freedom/locks`, which is shared by every build and catalog.
  - The prefix keeps the IPFS gate apart from the core's, even if both are pointed at one directory.
- **Taking it:** `File::try_lock`. On contention, retry for 5 s, then exit 75 (`lock_held`).
- **Errors:**
  - any other locking error exits 74 (`storage`);
  - so does a data or lock directory on a network filesystem, under 0001's qualification rules. SQLite's WAL mode isn't safe there in any case.
- **`hold-lock`:** `freedom-ipfsd hold-lock --data-dir … --lock-dir …` holds the gate until its stdin closes, as the core's does. Profile delete, profile reset and `ipfs:reset` hold it while they remove the directory.
- **Why not Myotis's model** (a C supervisor, an owner record, an Electron-as-Node child):
  - Myotis needs a JavaScript host for its add-on, and its directory holds sync state whose interrupted generation must be preserved.
  - Here the binary is plain Rust. The data is a cache in SQLite's WAL mode, so a kill costs at most the last writes.
  - The kernel releases the lock when the process dies, so "lock free" proves "owner gone". No boot witness or recovery record is needed, and `runAsNode` gains no new user.
- **What it adds over today:**
  - exclusion when `FREEDOM_IPFS_DATA` points outside the profile;
  - exclusion against an orphan that outlived a crashed main;
  - exclusion against a second profile process using the same directory.
- **An older build** running the add-on in process takes no lock. Running it on the same profile at the same time is excluded by the profile lock, as today.

### Startup and shutdown

- **Start:**
  1. spawn;
  2. `ipfs.hello`;
  3. `ipfs.start` for the instance ([Methods](#methods)), which opens the store and wires the gateway, with no network traffic yet;
  4. the manager goes to `RUNNING`, and `ipfsBackend()` reports `up`.

  Until then the status is `STARTING`, and plans get the 503 of a node that isn't up, as today.
- **Ordering:**
  - IPFS needs neither the vault nor `freedom-cored`, and starts independently of both.
  - When the profile's IPFS proxy setting is on, main sends `ipfs.start` only once `tor-manager` reports Arti's SOCKS port. Until then IPFS stays `STARTING` ([Network policy](#network-policy)).
- **Stopping an instance** (`ipfs.stop`: a private partition closing, or a [policy change](#changing-the-policy)):
  - in-flight heads are answered `stopped`, and open streams aborted with `stopped`;
  - the instance's swarms are dropped;
  - the store is closed, waiting at most 2 s for a statement in progress, as upstream's `close_or_close_later` does.
- **Stopping the process** (the nodes menu, a profile mode change, or quit):
  1. main sends `ipfs.shutdown` and closes stdin;
  2. the service stops every instance as `ipfs.stop` does, then exits 0;
  3. main kills it 5 s after `ipfs.shutdown`.

  A kill is safe, because the cache tolerates lost writes.
- **Quit:**
  - IPFS stays one leg of the wind-down's `Promise.allSettled`.
  - Its budget grows from 2 s to 5 s. That stays under Tor's 10 s, so `SHUTDOWN_WATCHDOG_MS` (20 s) stands.
- **Parent death:**
  - The I/O task exits on stdin EOF.
  - On Unix, `--parent-pid` with `PR_SET_PDEATHSIG` on Linux, then a 2 s `getppid()` poll, as 0001.
  - A plain watchdog thread, independent of the async runtime, ends the process 5 s after EOF whatever the runtime's state. A wedged orphan therefore can't hold the lock.
  - On Windows, libuv also places the child in main's kill-on-close job object. Only a `detached` child, which Myotis uses, escapes it.

### Crashes, hangs and restarts

- **A crash** is any exit main didn't ask for, other than 64, 74 or 75. Exit 76 (`protocol`, which includes 0001's 30 s writer stall) is a crash too, as it is for the core:
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
- **Panics inside the process:**
  - Request work runs on tokio tasks, built with `panic = "unwind"`.
  - A panic inside freedom-ipfs on a request's task is caught at its join handle. Before the head it becomes that request's `internal` error; after the head, the stream's `internal` abort.
  - A panic anywhere else ends the process (exit 101) and counts as a crash.
  - The service's own code is under the workspace lints: no `unsafe`, `unwrap`, `expect` or `panic!`.

### Inside the process

- **Runtime:**
  - tokio, multi-threaded. freedom-ipfs requires it: its block provider calls `block_in_place` (`rv:5447`, `rv:5499`, `rv:5534`), which panics on a current-thread runtime.
  - Worker threads: the core count, capped at 8.
  - The blocking pool keeps tokio's cap of 512, stated explicitly. Each in-flight block fetch holds a thread, and freedom-ipfs caps those at 256 (`rv:276`).
- **Tasks,** as in `freedom-cored`:
  - one reader;
  - one serialized writer, with reserved room for control frames;
  - one task per request.
- **An instance** is one store, one block provider, one name resolver and one `GatewayCore`, wired as `mob:2154`–`2249` does today. Each instance's Bitswap swarm is its own: upstream builds one per provider (`rv:4297`), with a new identity.
  - **The persistent process** holds exactly one instance, `profile`. Its store is `<data-dir>/freedom-ipfs.sqlite3`, the file the add-on uses, so the cache carries over and nothing migrates either way.
  - **The ephemeral process** holds up to 8 memory instances ([Private windows](#private-windows)).
- **Logs:**
  - JSON lines on stderr, forwarded to main's log.
  - The service logs its own lifecycle and failures with codes, never a path, name or CID.
  - Upstream's tracing feeds only the progress recorder, as the add-on's subscriber does today.

## The protocol

### Frames

0001's frame layer: a `u32` big-endian length, a `u8` kind, then the payload.

- **Kind `0x01`** carries a JSON message of at most 1 MiB, with 0001's envelope: `request`, `response`, `event` and `cancel`, IDs below 2^53, and exactly one terminal response per request.
- **Kinds `0x02`–`0x05`** are the stream frames, taken from 0001's reserved range. Each payload starts with the stream's 8-byte big-endian ID.
- **The stream ID is the `ipfs.request`'s envelope ID.** One request has at most one body, so no separate ID space or open frame is needed: the head response opens the stream.

| Kind | Name | Direction | Payload after the ID |
|---|---|---|---|
| `0x02` | data | service → main | 1 to 65 536 body bytes |
| `0x03` | end | service → main | none: the body is complete |
| `0x04` | abort | service → main | JSON `{ code, message }`, ≤ 1 KiB: the body is truncated |
| `0x05` | credit | main → service | `u32` big-endian, > 0: bytes main will accept |

- **Order:**
  - the head response is written before any frame of its stream;
  - every stream ends with exactly one `end` or `abort`;
  - a request whose head says `body: false` opens no stream.
- **Credit:**
  - A stream starts with a 128 KiB window, granted by the head.
  - The service sends data only within the credit it holds.
  - Main returns a chunk's bytes as credit when it hands that chunk to the body's consumer.
  - So each stream has at most 128 KiB in the pipe and in main's queue together. Today the add-on holds one 64 KiB read in main and two 64 KiB chunks in its channel.
- **Fairness:**
  - The writer serves control frames first: responses, `end`, `abort` and replies to `cancel`.
  - It then writes data round-robin, one frame per stream with credit.
  - It holds at most 16 MiB of data frames. A stream's task waits for room, so a main that stops reading backs the service up rather than growing it.
- **Protocol errors** (0001: log and close):
  - data beyond the stream's credit;
  - an empty data frame;
  - a frame for a stream that was never opened;
  - a second terminal frame;
  - credit sent by the service, or stream data sent by main.

  Credit for a stream that has just ended is ignored: it can cross the `end` in flight. After a `cancel`, main discards data until the stream's terminal frame, then forgets the stream.
- **Why not 0005's fragments:**
  - a fragmented response is one whole message, reassembled before use, at most 32 MiB, and one at a time per direction;
  - a video or a large download would have to be buffered whole, and every body would wait behind it.
- **Why not a second channel,** such as a loopback HTTP server or a second pipe:
  - a loopback port is reachable by every local process, and upstream's axum server checks no `Host`;
  - a second pipe adds handles to supervise for no gain, since control frames already go first.
- **Shared with the core later.** The codec goes in `fc-protocol`, sans-I/O, with vectors that main's `frame.js` also passes. When 4.5 needs streams in `freedom-cored`, its protocol version 2 can adopt these frames, adding the explicit global credit that main's admission provides here.

### Methods

```jsonc
{ "type": "request", "id": 1, "method": "ipfs.hello",
  "params": { "protocol": 1, "shell_version": "0.9.0", "frames": ["stream"] } }
{ "type": "response", "id": 1, "result": { "protocol": 1, "service_version": "0.1.0",
  "freedom_ipfs": { "version": "0.4.5", "git_commit": "9316571…" }, "kind": "persistent" } }

{ "type": "request", "id": 2, "method": "ipfs.start", "params": {
    "instance": "profile",
    "store":   { "kind": "disk", "max_bytes": 268435456 },        // or { "kind": "memory", "max_bytes": 33554432 }
    "routing": { "mode": "auto", "delegated_routers": ["https://delegated-ipfs.dev/routing/v1"],
                 "dht_query_timeout_s": 3, "dht_max_providers": 32 },
    "gateway": { "max_concurrent_requests": 8, "request_queue_timeout_ms": 15000 },
    "network": { "mode": "direct" } } }                            // or { "mode": "socks5", "host": "127.0.0.1", "port": 9150 }

{ "type": "request", "id": 41, "method": "ipfs.request", "params": {
    "instance": "profile", "method": "GET", "path": "/ipfs/bafy…/app.js",
    "headers": [["range", "bytes=0-"]], "headers_ms": 30000 } }
{ "type": "response", "id": 41, "result": {
    "status": 206, "headers": [["content-type", "text/javascript"], …], "body": true } }
{ "type": "cancel", "id": 41 }
```

| Method | Params | Result | Deadline (owned by the service) |
|---|---|---|---|
| `ipfs.hello` | `protocol`, `shell_version`, `frames` | `protocol`, `service_version`, `freedom_ipfs` build info, `kind` (`persistent` or `ephemeral`) | 10 s after spawn |
| `ipfs.start` | `instance`, `store`, `routing`, `gateway`, `network` | `{ instance }` | 10 s |
| `ipfs.stop` | `instance` | `{ closed }`: whether the store closed within its bound | 5 s |
| `ipfs.request` | `instance`, `method` (`GET` or `HEAD`), `path`, `headers`, `headers_ms` | the head: `status`, `headers`, `body` | `headers_ms`, until the head |
| `ipfs.stats` | `instance` | [Stats](#stats) | 5 s |
| `ipfs.shutdown` | none | none: the process exits | main kills after 5 s |

- **`ipfs.start`:**
  - The values above are exactly today's (v0.4.5's defaults where the add-on passes 0), sent explicitly.
  - The persistent process accepts one `disk` instance. The ephemeral process accepts only `memory` instances of at most 32 MiB, and at most 8 of them.
  - Anything else is `invalid_argument`.
  - Starting an instance that is already running is `invalid_argument`. Changing its configuration is `ipfs.stop`, then `ipfs.start`.
  - Instance IDs are opaque ASCII of at most 64 bytes, chosen by main.
- **`ipfs.request`:**
  - The `path` and `headers` are the plan's, passed through.
  - The service builds the gateway request with freedom-ipfs's own native-request parser (an [upstream change](#upstream-changes-in-freedom-ipfs) makes it public), so it treats requests exactly as the add-on does.
  - As main does today, it sets the request ID to the envelope ID and the top-level path to `path`.
  - `body` is false for `HEAD` and for 204, 205 and 304, which is main's rule today. Any bytes the gateway produces then are dropped.
  - A request is one JSON frame, within 0006's bounds of 64 KiB for the URL and 64 KiB for the headers.
- **No caller context.**
  - Every request is main's, for a request main has already admitted and fenced. The service has no per-caller policy.
  - The instance is the only partition, and main picks it.

### Cancel and deadlines

- **`cancel` before the head:** the request's task is aborted, and the reply is `cancelled`.
- **`cancel` after the head:**
  - the task is aborted, and the stream ends with `abort { code: "cancelled" }`;
  - if `end` was already written, the cancel is a late one and is ignored, as in 0001.
- **`headers_ms`:**
  - It runs from admission, so queue time and routing count. On expiry the task is aborted and the reply is `deadline`.
  - After the head there is no deadline in the service. Main's 60 s body-idle timer (0006) cancels a stalled body.
- **Admission:** at most 512 requests per process, counting both heads and open streams. Beyond that the reply is `busy`.
  - Main's own admission allows 256 active fetches, so only requests still winding down after a cancel can take the count past 256.

### Errors

| Code | When | Main's backend rejects or errors with (today's text) |
|---|---|---|
| `invalid_argument` | the request can't be parsed: an unsupported method, path or header | `freedom-ipfs native request could not be started` |
| `stopped` | no such instance, or it is stopping | `freedom-ipfs native node is not running` |
| `deadline` | no head within `headers_ms` | `freedom-ipfs native request timeout` |
| `cancelled` | main's `cancel` | `freedom-ipfs native request aborted` before the head; `…cancelled` for a body |
| `busy` | more than 512 admitted | `freedom-ipfs native node is busy` (new; main's admission prevents it) |
| `internal` | a panic on the request's task | `freedom-ipfs native gateway error` |
| `storage` | `ipfs.start`: the store won't open (`data.kind`) | the manager's `Failed to start freedom-ipfs native node` |
| `protocol_mismatch` | `ipfs.hello` | a startup error; no restart |

- **HTTP failures are heads,** as today: 400, 404, 416, 502, 504, and the 503 `gateway_busy` with `Retry-After: 1` from the 15 s queue. They have bodies, and pass to the plan executor unchanged.
- **Abort codes:**
  - `cancelled`;
  - `internal`;
  - `body_stream_error` (upstream's code for a failing body);
  - `stopped`.

  Main errors the body with `freedom-ipfs native request cancelled` for the first, and with today's `freedom-ipfs native read failed` for the others.

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

The 5 s health check calls `ipfs.stats`. `checkHealth()` stays synchronous, because `ipfsBackend()` calls it at admission. It reads a snapshot that is true while all of these hold:
- the generation is live;
- the instance is started;
- the last stats reply is under 15 s old.

## Main's side

`ipfsBackend()` keeps its contract (#704):

```js
ipfsBackend({ partition }) → { ref: { ipfs: 'native', up }, url: null,
                               request({ path, method, headers, signal, headersTimeoutMs }) → Promise<Response> }
```

- **What changes:**
  - It takes the request's partition. `ipfs-protocol.js` already has it, from its `privatePartition` registration.
  - A private partition gets its own instance ([Private windows](#private-windows)).
  - The core still sees only `ref`.
- **`request()`:**
  - **An already aborted signal** rejects at once. Nothing is sent, as today.
  - **Otherwise** it sends `ipfs.request` with `headers_ms: headersTimeoutMs`, and registers one abort listener that sends `cancel`.
  - **On the head** it resolves `new Response(body, { status, headers })`:
    - `body` is `null` when the head says `body: false`;
    - otherwise it is a byte `ReadableStream` whose `pull` takes the next queued chunk and returns its bytes as credit; `end` becomes `close`, and `abort` becomes `error`;
    - its `cancel` sends `cancel`.
  - **A rejection** carries today's message ([Errors](#errors)). The executor's `failure()` makes it the same 502 as today.
- **Every terminal path frees:**
  - `end`, `abort`, the error reply, the generation's exit, or `cancel` followed by the stream's terminal frame;
  - each releases the stream's queue and credit, and the executor's `onEnd` releases the admission slot.

  The executor's contract is unchanged: a pull-driven body, truncation surfaced as an error, and nothing started for a signal that is already aborted.
- **The client:**
  - `core-client.js`'s supervision becomes a shared `ServiceClient`: spawn, the handshake, generations, restart back-off, kill, the frame reader and the writer with reserved control room.
  - `freedom-cored` and `freedom-ipfsd` each configure their own instance of it.
  - `frame.js` accepts kinds `0x02`–`0x05` only on a connection whose handshake granted `stream`.
- **Main's memory:**
  - stream bytes are at most 256 active fetches × 128 KiB = 32 MiB;
  - data that arrives for a cancelled stream is dropped as it is read;
  - this is separate from 0005's chain I/O pool.

## Private windows

- **The decision:** one ephemeral process per profile serves all private windows. It holds **one in-memory instance per private partition**.
- **Rejected alternatives:**
  - **A cache partition in the persistent store:** private loads would write blocks, resolved names and provider records into the profile's SQLite file, where WAL and free pages outlive any deletion.
  - **One instance for all private windows:** Freedom gives every private window its own partition. A shared cache would let one private window see another's loads by timing.
  - **A process per private window:** the same separation as instances, at the cost of a runtime and a spawn per window. The process boundary would add only crash isolation between private windows.
- **Lifecycle:**
  - The first `ipfs:` or `ipns:` request from a private partition spawns the ephemeral process if needed, then starts the partition's instance. Both happen within that request's `headers_ms`.
  - Private windows use instances only while the profile's IPFS is bundled and `RUNNING`. Otherwise they get today's answer: the external gateway, or a 503.
  - `closeDwebSession(partition)` stops the partition's instance. When the last one stops, main sends `ipfs.shutdown`, and the process exits with everything it held.
- **Bounds:**
  - at most 8 live instances, each with a 32 MiB memory store (an upstream option shrinks its hot cache to 4 MiB);
  - a ninth partition stops the least recently used instance that has no open request, and that partition gets a fresh instance on its next request;
  - if all 8 have open requests, the ninth's request gets `busy`, and main answers 503.
- **What stays in memory only:**
  - `SqliteBlockStore::in_memory`, with `temp_store = MEMORY` ([upstream](#upstream-changes-in-freedom-ipfs)), so SQLite writes no temp files;
  - no data directory and no lock;
  - logs without paths;
  - no progress snapshot.
- **Identity:**
  - each instance's Bitswap swarm has its own fresh identity, and DHT queries use a new one each time, as upstream does;
  - so a private partition shares no PeerID with the profile's node or another partition;
  - it does share the machine's IP address, unless the [network policy](#network-policy) sends traffic through Tor.
- **Restarts:** the ephemeral process follows the same rules. Its instances come back lazily and cold.
- **The nodes panel** keeps showing the persistent node only.

## Network policy

### What can be honored

- **`reqwest`:**
  - SOCKS5 with remote name resolution (`socks5h://`), once its `socks` feature is on.
  - Every client must be built with an explicit proxy or with `no_proxy()`. Today none sets either (`ns:828`, `rt:1807`, `rv:11132`), so the environment decides.
- **libp2p 0.56:**
  - It has no SOCKS transport. TCP, and WebSocket over TCP, can go through a small custom `Transport` over `tokio-socks`, which hands the proxy host names rather than addresses.
  - **QUIC can't be proxied:** Tor carries TCP only, and Arti doesn't offer SOCKS5 `UDP ASSOCIATE`.
  - **libp2p's own resolver** (hickory, `ResolverConfig::cloudflare()`, plain DNS to 1.1.1.1 on port 53; `rt:1601`, `rv:8847`) must be off under a proxy.
  - **`/dnsaddr`** needs TXT records. Under a proxy they come from DoH through the proxied client, as Bitswap's address expansion already does (`rv:9435`).
  - An embedded Tor client (`arti-client`) is not used: Freedom already runs Arti, and a second Tor client in the service would duplicate it.
- **freedom-ipfs v0.4.5 honors none of this:**
  - the clients and transports are built inside the crates;
  - QUIC is always added (`rt:1597`, `rv:8825`);
  - the DoH resolver is fixed at `mob:2226` and `rv:9436`, `9484` and `9531`;
  - there is no dial filter.

### Modes

- **`direct`, the default:** today's transports, except that the environment's proxy variables no longer apply (deviation `env-proxy`).
- **`socks5 { host, port }`:** all of the service's traffic goes through the proxy.
  - **HTTP:** delegated routing, DoH and HTTP providers, all over `socks5h`.
  - **Bitswap:** TCP and WebSocket through the SOCKS transport. QUIC and hickory are off.
  - **Routing:** `delegated` by default, since the light DHT dials dozens of peers per query, each through Tor.
  - **Fails closed:**
    - a proxy that is down fails the request, which gets upstream's 502 or 504;
    - nothing falls back to a direct socket;
    - a dial the transports can't carry is refused before any socket exists.
- **Where the proxy comes from:**
  - A new per-profile setting, **Route IPFS through Tor**, off by default, sends Arti's SOCKS endpoint from `tor-manager`.
  - Today Tor in Freedom means onion access. Clearnet and the dweb protocols stay direct (`docs/features.md`), and this design keeps that default.

### Onion

- **Which targets:** `.onion` hosts (delegated routers, DoH endpoints, HTTP providers) and `/onion3` multiaddrs.
- **The rule:** they are dialled only in `socks5` mode, as a host name handed to the proxy. In `direct` mode they are refused before any socket exists, as the session's onion gate refuses them (`OnionGateRefusal`).

### Changing the policy

- **What a change does:** stop and then start every instance with the new policy.
  - In-flight requests fail with `stopped`.
  - The swarms are dropped, which closes their connections and rotates their identities.
- **The guarantee:** nothing admitted under the old policy outlives the change. This mirrors `applyOnionProxy`, which calls `closeAllConnections` after `setProxy`.
- **Arti going down** leaves the policy in place, so IPFS fails closed. This matches the PAC kept after an Arti crash.

## Upstream changes in freedom-ipfs

Each is a pull request to freedom-ipfs, and none changes mobile's behavior by default. The service pins the release that carries them. Until then it pins a commit, which `deny.toml` allows (`solardev-xyz`).

1. **A library builder for the online node.**
   - Today's wiring lives in the FFI crate (`mob:2154`–`2249`) and again in the gateway binary (`gateway/src/main.rs:130`–`162`).
   - Move it to a library function, for example `freedom_ipfs_gateway::OnlineNode::builder(store)`, that returns the `GatewayCore` and its stats handles. It takes:
     - the routing mode and routers;
     - the DHT settings;
     - `GatewayConfig`;
     - a network policy (item 3).
   - The add-on and the service then wire the same thing.
2. **The native-request parser, public.**
   - The JSON-to-`GatewayCoreRequest` parsing (`mob:2635`–`2689`) moves to a library function, with the same accepted forms and results.
   - The service then treats each path exactly as the add-on does, with no copy to drift.
3. **A network policy.** One `NetworkPolicy` value, threaded through the builder, that supplies:
   1. **HTTP clients:** a single constructor taking `Option<reqwest::Proxy>` and the redirect policy. It replaces the three `timeout_http_client` functions (`ns:828`, `rt:1807`, `rv:11132`) and calls `no_proxy()` when no proxy is given. It enables `reqwest`'s `socks` feature.
   2. **Errors instead of panics:** the three constructors `expect` today (`ns:833`, `rt:1812`, `rv:11138`). With a proxy their configuration can fail, so they must return an error.
   3. **DoH:** the endpoint and its client come from the policy, at `mob:2226` and `rv:9436`, `9484` and `9531`. DNSLink is already pluggable (`DnsTxtResolver`, `ns:53`); Bitswap's address expansion isn't.
   4. **Transports:**
      - `build_dht_swarm` (`rt:1588`), `build_bitswap_swarm` (`rv:8816`) and `cloudflare_websocket_transport` (`rv:8847`) take `quic: bool`, `dns: Hickory | None`, and `tcp: Direct | Socks5(addr)`;
      - add a SOCKS5 `Transport` over `tokio-socks` (MIT) for `/ip4`, `/ip6`, `/dns*` and `/onion3` with `/tcp`, and for WebSocket on top of it.
   5. **A dial filter:**
      - a predicate over multiaddrs and URLs, applied where candidates are chosen (`rt:1491`–`1525`, `rt:1767`–`1805`) and at the dial sites (`rv:7765`, `rv:7949`, `rt:1044`);
      - the service uses it for the onion rule and for the proxy mode's "nothing it can't carry";
      - it can also carry an address policy ([Open questions](#open-questions)).
4. **Progress and stats outside the FFI crate.**
   - Move the progress recorder and `progress_layer` (`mob:552`–`1018`) to a library crate, with a recorder per node rather than the process-global `PROGRESS_RECORDER` (`mob:79`).
   - The service then links no C ABI, and two instances' progress never mixes.
   - If a cancelled request leaves its entry in `active` until `clearProgress`, as the code suggests, close the entry on cancel.
5. **Store options:**
   - `temp_store = MEMORY` for `in_memory` stores;
   - a hot-cache size independent of `max_bytes` (today `min(max_bytes, 16 MiB)`, `st:609`), since a memory store holds the bytes twice.
6. **Build info:**
   - `buildInfoJson` reads `FREEDOM_IPFS_GIT_COMMIT` and `FREEDOM_IPFS_GIT_DESCRIBE` (`mob:1333`), but the packaging script sets `FREEDOM_IPFS_BUILD_GIT_*`, so both fields are always null.
   - Move the function to a library crate and fix the names. `ipfs.hello` reports it.

## Where the code lives

Four options. A new repository is the user's decision; this design recommends the first.

1. **This repository, as `services/freedom-ipfsd`, a separate Cargo workspace** (recommended).
   - **For:**
     - `fc-protocol` by path, so one frame and stream codec;
     - one CI and one release workflow, with static musl Linux builds, which would also close #350's GLIBC floor if the C dependencies build there ([Open questions](#open-questions));
     - `SHA256SUMS` and attestations;
     - freedom-browser's fetch-and-verify script pattern, extended to a second asset;
     - the same lints, copied into its manifest, since workspace lints don't cross workspaces.
   - **Its own workspace,** excluded from the core's (`exclude = ["services"]`).
   - **Its own `Cargo.lock` and `deny.toml`** keep the core's dependency graph as it is. v0.4.5 alone locks 453 packages, against the core's 133:
     - a libp2p advisory can't block a vault fix;
     - the core's `cargo deny` stays strict;
     - the new graph brings C code (SQLite, `ring`) and at least one license the core doesn't allow: `webpki-roots` 1.x's CDLA-Permissive-2.0, per its published metadata, which `cargo deny` will confirm.
   - **Releases** use their own tag, `ipfsd-vX.Y.Z`, with their own `THIRD-PARTY-NOTICES`.
   - **libradicle's service (4.4)** would sit beside it.
2. **A member of the core's workspace,** in `crates/`.
   - **For:** simplest to build.
   - **Against:** the lockfile, `cargo deny`, the notices and every CI run of the key-holding core then carry libp2p, QUIC, SQLite and `ring`, and their advisories gate vault work. AGENTS.md describes this repository as keys, vault, signing, naming and profiles; a P2P node is outside that.
3. **Upstream freedom-ipfs,** as a binary beside `freedom-ipfs-gateway`'s.
   - **For:** the binary lives with the crates it wraps, and is released with them.
   - **Against:**
     - the frame protocol, the lock and the supervision contract are Freedom's, not freedom-ipfs's;
     - freedom-ipfs is dual-licensed MIT or Apache-2.0, while this repository carries no license, so it couldn't depend on `fc-protocol` without a licensing decision, and would copy the codec instead;
     - its crates don't forbid `unsafe`, because the FFI crate needs it.

   Upstream still gets the [hooks above](#upstream-changes-in-freedom-ipfs): they are library changes, useful to any host.
4. **A new repository** (`freedom-ipfsd`): option 1's layout, moved out.
   - **For:** separate access and release cadence.
   - **Against:** one more pipeline and pin, and `fc-protocol` as a git dependency across repositories. Option 1's workspace moves out unchanged if the user prefers this later.

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
- **Rust tests through the binary,** using test-only methods behind a cargo feature, as `freedom-cored`'s `testhooks`. These seed a memory or offline instance from CAR fixtures, and inject a panic or a stall.
  - **The protocol:** frames, credit, cancel races, deadline, and one terminal per request and per stream.
  - **Isolation:** a panic on one request is `internal` for that request only.
  - **The lock:** contention gives 75, a network filesystem gives 74, and `hold-lock`.
  - **Parent death,** and the 5 s exit watchdog.
  - **The stall:** exit 76.
- **Network policy tests:**
  - A SOCKS5 test proxy records every connection.
  - A canary TCP and UDP listener is advertised as a provider and a router.
  - In `socks5` mode the canary must see nothing, and the proxy everything.
  - `.onion` and `/onion3` targets in `direct` mode open no socket.
- **Live:** `ipfs:native:smoke` re-pointed at the service, with `/ipns/ipfs.tech/` and #102's fan-out of 48 concurrent requests and no `gateway_busy`.

### Parity

| Item | Today | The service |
|---|---|---|
| configuration | `AUTO`, the default router, DHT 3 s, 8 permits, 15 s queue, 256 MiB | the same values, sent explicitly |
| cache file | `<ipfs-data>/freedom-ipfs/freedom-ipfs.sqlite3` | the same file |
| responses | `GatewayCore` via the C ABI | `GatewayCore` directly: the same status, headers and bytes |
| request ID and top-level path | main's counter, and the path | the envelope ID, and the path |
| head deadline | 30 s, main's timer | 30 s, the service's timer; main's watchdog at 45 s |
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

- The add-on path stays in the tree, selectable in dev builds with `FREEDOM_IPFS_BACKEND=addon`, until the service has shipped in one stable release. Then:
  - the add-on and the event worker go;
  - so do `fetch-freedom-ipfs-native.js`, the `freedom-ipfs-node` resources and its `check-binaries.js` rule.
- The cache file is the same, so going back needs no migration.

## Bounds

| Budget | Bound | Exhausted |
|---|---|---|
| handshake; `ipfs.start` | 10 s; 10 s | kill; startup error |
| `ipfs.stop`; shutdown | 5 s; kill 5 s after `ipfs.shutdown` | kill (the cache tolerates it) |
| exit after stdin EOF | 5 s, a watchdog thread | `std::process::exit` |
| lock contention | 5 s of retries | exit 75 |
| restarts | 0.5 s, 2 s, 10 s; three crashes in 60 s | stop, and "Restart IPFS" |
| JSON message | 1 MiB (0001) | protocol error |
| `ipfs.request` | 0006's: URL ≤ 64 KiB, headers ≤ 64 KiB | refused in main first |
| admitted requests, per process | 512 (heads and open streams) | `busy` |
| head | the plan's `headers_ms` (≤ 30 s); main's watchdog at + 15 s | `deadline`; on the watchdog, kill |
| stream window | 128 KiB per stream; data frames ≤ 64 KiB | the service waits for credit |
| stream bytes in main | 256 active fetches × 128 KiB = 32 MiB | not reachable: credit |
| data frames queued in the service | 16 MiB | stream tasks wait |
| service reader | 256 frames and 16 MiB (0001) | stops reading |
| writer stall | 30 s with nothing written (0001) | exit 76 |
| `ipfs.stats` | 5 s; main's watchdog at 20 s | on the watchdog, kill |
| abort payload | 1 KiB | protocol error |
| persistent cache | 256 MiB on disk, 16 MiB hot | upstream's LRU eviction |
| private instances | 8 per ephemeral process, 32 MiB store each | evict the idle LRU instance, else `busy` (503) |
| gateway | 8 header permits, 15 s queue (today) | 503 `gateway_busy` |
| runtime | ≤ 8 workers; 512 blocking threads; 256 in-flight block fetches (upstream) | tasks wait |

## Deviations

| ID | Today | After | Effect |
|---|---|---|---|
| `crash-domain` | the add-on runs in main and a worker thread of main | a separate process | an IPFS fault fails IPFS requests only, never the browser |
| `auto-restart` | none; the user restarts IPFS from the nodes menu | 0.5 s, 2 s, 10 s; three crashes in 60 s stop | brief outages heal on their own |
| `data-dir-lock` | the profile lock only | an OS lock per data directory | a second owner fails at start (75) instead of sharing the SQLite file |
| `network-fs` | the cache opens on any filesystem | a network filesystem is refused (74) | IPFS doesn't start there; WAL isn't safe there anyway |
| `private-windows` | private windows share the profile's node and on-disk cache | an in-memory instance per private partition, in its own process | private loads leave nothing on disk, can't be timed from other windows, and start with a cold cache |
| `env-proxy` | `reqwest` reads proxy variables from main's environment; libp2p ignores them | the environment is cleared, and the proxy is configuration | the HTTP half no longer follows `HTTPS_PROXY` and similar |
| `proxy` | none | an optional SOCKS5 policy for all traffic, failing closed | new: Route IPFS through Tor |
| `onion-targets` | no rule for them | refused before any socket in `direct`; through the proxy in `socks5` | a refusal proves nothing was sent |
| `read-ahead` | one 64 KiB read in main, plus a two-chunk channel | a 128 KiB window per stream | about the same buffering, now bounded by credit |
| `exit-text` | `Native event dispatcher exited with code N`, `Native gateway stopped unexpectedly` | `freedom-ipfs service exited` | in 502 bodies and logs only |
| `stats-fields` | the event-queue fields in the diagnostics | dropped, with the queue | the panel shows the rest |
| `targets` | the add-on ships for darwin-arm64, linux-arm64, linux-x64 and win32-x64, and needs GLIBC ≥ 2.38 | the service builds for this repository's five targets, static on Linux | IPFS on darwin-x64 and older distributions (#350), if the musl build holds |

## Implementation steps

1. **Tests first,** in freedom-browser: the backend contract suite, run against the add-on.
2. **Upstream,** in freedom-ipfs: the builder and parser (items 1–2), progress and build info (items 4 and 6), store options (item 5), then the network policy (item 3). Each is its own PR; the service can start once items 1 and 2 have landed.
3. **`fc-protocol`:** the stream frames, with vectors that main's `frame.js` also passes.
4. **`services/freedom-ipfsd`:**
   - the process model: the lock, `hold-lock`, the handshake, parent death and the exit watchdog;
   - instances, requests, streams, credit, cancel and deadlines;
   - `ipfs.stats`;
   - test hooks behind a feature;
   - the Rust tests through the binary.
5. **Release:** the five targets, `SHA256SUMS`, attestations and notices, on `ipfsd-v*` tags.
6. **freedom-browser, the persistent node:**
   - `ServiceClient`, extracted from `core-client.js`, and the stream frames in `frame.js`;
   - the fetch script and packaging (`mac.binaries` signing);
   - `ipfs-manager.js` on the service, behind `FREEDOM_IPFS_BACKEND` in dev;
   - the contract suite against the real binary;
   - the re-pointed smoke and the [cost](#cost) measurement.

   Then the default switches.
7. **Private windows:** the ephemeral process and the partition-to-instance map in main.
8. **Network policy:** the setting, Arti's endpoint, policy changes, and the SOCKS and canary tests. This needs upstream item 3.
9. **Removal,** one stable release later: the add-on, the event worker and their scripts.

## Open questions

1. **Where the code lives:** a separate workspace in this repository (recommended), a member of the core's workspace, upstream, or a new repository (the user's decision).
2. **Private windows:** an in-memory instance per private partition in one process (recommended), one instance shared by all private windows, or a process per window? And are 8 instances of 32 MiB the right bound?
3. **The proxy's scope:**
   - SOCKS5 to Arti only (this design), or also a user's HTTP proxy for the HTTP half? libp2p would need another custom transport for that.
   - Should Route IPFS through Tor follow a future "everything through Tor" mode?
4. **Routing under a proxy:** delegated only (recommended), or the light DHT through SOCKS, which costs many Tor circuits per query? And how many IPFS peers accept connections from Tor exits on their ports? That is to be measured before the setting ships.
5. **An address policy:** should the dial filter restrict which address ranges are dialled in `direct` mode, as Kubo's `server` profile does? The hook makes either answer cheap.
6. **The musl build:** do SQLite and `ring` build statically for both Linux targets in this repository's release workflow? If not, the Linux builds need a glibc floor of their own, chosen with #350 in mind.
7. **Upstream timing:** will freedom-ipfs take items 1–6? Until a release carries them, does the service pin a commit on a branch?
8. **Streams in the core:** should 4.5's protocol version 2 for `freedom-cored` adopt these four frames as they are, with an explicit global credit added?
