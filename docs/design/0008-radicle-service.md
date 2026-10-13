# 0008: The libradicle service process

**Status:** proposed. Roadmap Phase 4 (item 4.4). Builds on [0001](0001-freedom-cored.md) (process model, lifetime lock, node identity writes, process hardening), [0006](0006-dweb-transports.md) (the outline in *Service processes*) and 0007 (#68: the IPFS service, whose process model, stream frames and `ServiceClient` this design reuses).

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

  The difference: **one node per process, and the process is the only teardown.** heartwood's threads can't be cancelled from outside, and a failed start can leave them running. So stopping the node, changing its policy, or recovering from a failed start all end the process, and a restart is always a new generation. Nothing of an old node outlives its process.
- **The state isn't a cache.** The Radicle home holds:
  - the user's signed issues and comments;
  - the seeding policies;
  - the node's key.

  So the service recovers interrupted clones at start, and a write cut off by a crash is reported as **outcome unknown**, never retried.
- **The blob API (0006's requirement):** `rad.blob` returns a blob's **raw bytes**, **chunked** over 0007's stream frames, with an optional **byte range**.
  - The existing JSON endpoint stays byte-identical.
  - A new `rad:` endpoint, `/raw/<rev>/<path>`, serves the bytes themselves, with Range, under conservative headers.
- **Reads become bounded and cancellable:**
  - `rad:` and `radapi:` requests take main's dweb admission;
  - a page's abort reaches the service;
  - reads run on a bounded pool, without today's process-wide mutex.
- **Keys:**
  - The service holds one secret: the user's Radicle node key, which heartwood needs for every connection and signature. It is a separate identity, not a wallet key.
  - It keeps today's source: the key file the core writes (0001's `nodes.write_identity`). The difference is that the service reads it, so main no longer holds the key in memory.
  - Moving to an in-memory host key, with no file at rest, is the user's decision ([Keys](#keys)).
- **Network policy:**
  - heartwood already has a SOCKS5 proxy and onion settings, which libradicle doesn't expose. The service sets them in memory: `direct`, or `socks5` through Arti.
  - It also sets an address policy for addresses learned from peers.
  - The node listens on nothing: no inbound port, and, after an upstream change, no control socket.
- **Private windows** read the profile's node, as today. Reads touch only local storage and send nothing. Private partitions can't seed, sync or write.
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
  - aborts reach the service.
- **One owner per Radicle home,** enforced by the OS before heartwood opens anything.
- **A network policy the node honors,** failing closed: under a proxy, no direct peer socket.
- **Honest key custody:** the key's holders and sources are stated, and anything new is left to the user.

**Non-goals**
- **Planning `rad:` in the core** (0006's model for `bzz:` and `ipfs:`). `serveRepoApi` stays in main. Moving it into `fc-dweb` is a later step, once the service exists.
- **The Radicle provider's consent model** (`window.radicle`): unchanged.
- **New Radicle features:** no patch creation and no repository creation beyond today's `importRepo`.
- **Mobile:** iOS keeps linking libradicle through UniFFI.
- **Content verification (4.5):** not here. heartwood verifies refs against signed sigrefs itself.

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
- **The environment** is cleared, as 0007's is. That drops:
  - `RAD_SOCKET`, `RAD_KEYGEN_SEED`, `RAD_PASSPHRASE`, `RAD_RNG_SEED`, `RAD_LOCAL_TIME`, `GIT_COMMITTER_DATE`, `SSH_AUTH_SOCK` and systemd's `LISTEN_*` variables, all of which heartwood reads;
  - everything else main has.

  `PATH` and `HOME` stay, for `import_repo`'s `git push` and libgit2's configuration lookup.
- **Handshake:** `rad.hello` within 10 s, as 0001.
- **The lock:** `<lock-dir>/radicle-<sha256(canonical home)>.lock`, under 0001's rules.
  - Contention retries for 5 s, then exits 75. Other errors and network filesystems exit 74.
  - **It is taken before libradicle opens anything.** heartwood's own exclusion is the control-socket bind, which comes after its threads have started (`hw/radicle-node/src/runtime.rs:202`–`249`).
  - **It covers only writers that take it:**
    - the service;
    - `hold-lock`;
    - the core's identity write ([Main's side](#mains-side)).

    The `rad` CLI pointed at Freedom's home doesn't take it, and is unsupported, as is any older build sharing the home.
- **`freedom-radicled hold-lock --home … --lock-dir …`** holds the gate until stdin closes, as 0001's does. It is used by:
  - the alias rewrite;
  - the identity wipe;
  - profile delete and reset;
  - `radicle:reset`.
- **Process hardening** is 0001's, because the process holds a key:
  - Linux: `PR_SET_DUMPABLE=0`;
  - macOS: no core files, plus the hardened runtime from signing.

### Start, stop and recovery

- **Start:**
  1. spawn;
  2. `rad.hello`;
  3. **recovery under the lock:**
     - delete `storage/<rid>.<random>.tmp` directories, which are first clones that never renamed into place (`hw/radicle/src/storage/git/temp.rs`);
     - delete libgit2 lock files (`*.lock`) under each repository. A lock file is an update that never committed: the ref keeps its old value.
     - Log the counts only.
  4. `rad.start`, which runs `Embedded::start` with today's options and the [network policy](#network-policy), and returns `{ did, nid, alias }`;
  5. `RUNNING`;
  6. main runs today's background `rad.connect_seeds` and default-repository `rad.clone`.
- **A failed start ends the process.**
  - libradicle can fail after heartwood's threads have started (`lr:777`). Those threads hold each other alive.
  - So the service answers `rad.start` with the error and then exits. Main shows the error and doesn't restart, as a failed start is handled today.
  - The menu's start spawns a fresh process.
- **Stop is the process's end:**
  1. main sends `rad.shutdown` and closes stdin;
  2. the service fences new work, answers waiting requests `stopped`, and calls `Embedded::shutdown`;
  3. it exits 0 when that returns, or after 5 s whatever its state (`lr:1343` joins with no timeout);
  4. main kills it 10 s after `rad.shutdown`.
- **Quit:** Radicle gets a 10 s leg in the wind-down. That equals Tor's, so the 20 s watchdog stands.
- **Kill safety:**
  - SQLite recovers its journals.
  - libgit2 commits each ref by renaming a lock file into place, so a ref is either old or new. Recovery removes leftover lock files at the next start.
  - A first clone in a temporary directory is discarded.
  - **What a kill can't settle is a write in flight:** an issue or comment may or may not exist. See [outcome unknown](#writes).
- **Parent death:**
  - stdin EOF, with `--parent-pid` and `PR_SET_PDEATHSIG` as 0001;
  - a watchdog thread exits the process 5 s after EOF;
  - on Windows, EOF or a writer failure is the guaranteed path. libuv's kill-on-close job object is only a backstop, because libuv carries on when assigning the job fails.

### Crashes and restarts

0007's rules (0001's back-off) and generations, with these differences:

- **The node's own threads.** heartwood's reactor and worker panics are caught by nothing, and `Handle::is_running()` always returns true (`hw/radicle-node/src/runtime/handle.rs:162`).
  - The service watches the node thread itself: an upstream change exposes it ([below](#upstream-changes)).
  - When the node thread has ended, the service answers what is in flight and exits 70 (`node_down`). That is a crash, and main restarts it.
- **Panics on the service's own threads:**
  - A startup panic hook replaces Rust's default. It writes one fixed JSON line to stderr, `{"panic": "<thread kind>"}`, never the payload, and suppresses the backtrace.
  - On a request thread, inside the request's `catch_unwind`, the panic becomes that request's `internal` error, and the service then checks the node thread.
  - On any other thread, the hook ends the process with 70.

  So no panic payload, which can contain a path or a RID, reaches a log.
- **A restart is a new generation.**
  - The node, its policy and its key are re-read from the home.
  - Requests captured by main before the restart fail with the old generation, as 0007's do.
  - There is no in-process restart, so instance epochs aren't needed.

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
- **Allocation:** main coalesces received bytes into owned 64 KiB buffers. A cancelled stream keeps only a retirement record until its terminal frame.
- **Progress under backpressure:**
  - the service's reader never waits on the writer: credit, cancel and shutdown are applied as they are read;
  - main keeps decoding while its own writes wait.

### Methods

| Method | Params | Result | Pool and deadline |
|---|---|---|---|
| `rad.hello` | `protocol`, `shell_version`, `frames` | `protocol`, `service_version`, `libradicle` build info | 10 s after spawn |
| `rad.start` | `alias`, `network` | `did`, `nid`, `alias` | 30 s; on failure, the process exits |
| `rad.stats` | none | `connected_peers`, `node_alive`, pool and budget use | inline; 5 s |
| `rad.shutdown` | none | none: the process exits | main kills after 10 s |
| `rad.read` | `op`, `args` | head `{ content_type: "application/json", bytes }`, then the JSON as a body stream | read pool; 60 s |
| `rad.blob` | `rid`, `revision`, `path`, `range?`, `head_only?` | head `{ oid, size, binary, range }`, then the bytes | read pool; 60 s |
| `rad.connect_seeds` | `timeout_ms` | today's report | network pool; `timeout_ms` + 30 s |
| `rad.clone` | `rid`, `timeout_ms`, `progress` | `{ ok }` or `{ cancelled }`; `rad.progress` events | network pool; `timeout_ms` + 30 s |
| `rad.unseed` | `rid` | `{ unseeded }` | write queue; 60 s |
| `rad.write` | `op` (`create_issue`, `comment_issue`, `edit_issue_state`, `comment_patch`), `args` | today's JSON | write queue; 60 s |
| `rad.import_repo` | `path`, `name`, `description`, `default_branch` | `{ rid }` | write queue; 300 s |

- **`rad.read`'s `op`** is one of today's read exports, with today's arguments:
  - `repo_info`, `tree`, `tree_at`, `blob`, `blob_at`;
  - `commits`, `commit`, `remotes`, `repo_stats`;
  - `issues`, `issue`, `patches`, `patch`;
  - `list_repos`, `list_seeded_repos`;
  - `seeders`, `identity`, `status`.

  Its body is the exact JSON text the v0.8.0 add-on returns for that export ([Parity](#parity)). Main passes it through, or parses it where it does today.
- **Why reads stream:** the 1 MiB JSON frame (0001) is smaller than many results, such as a commit's diff or a large text blob. Streaming also lets a cancel stop the transfer.
- **`rad.progress`** events carry `{ id, event }`, where `event` is today's progress JSON string, unchanged.
  - Per clone, at most 16 unwritten events are held. When more arrive, the oldest `connecting` and `fetching` events are dropped first; `peer-failed` and terminal events are never dropped.
- **Cancel:**
  - The envelope's `cancel` on a `rad.clone` flips its `CancelToken`, which replaces `cancelClone(rid)`. Main maps the RID to the request.
  - libradicle checks the token between candidates, and an in-flight fetch finishes first (`lr:449`). So the reply comes when the clone actually stops.
  - Cancelling a read stops the stream at once. The read's thread stays counted until libgit2 returns.
- **Deadlines:** the service owns them, and main's watchdog is each deadline + 15 s, as 0001.
  - A read past its deadline gets `deadline`. A network operation past its deadline gets `deadline` too, but keeps its slot until libradicle returns.
  - A write past its deadline gets `outcome_unknown` ([Writes](#writes)).

### Errors

| Code | When | Main |
|---|---|---|
| `invalid_argument` | a RID, revision (40 hex), COB ID (6–40 hex), op or range that doesn't parse | 400, today's texts |
| `not_found` | libradicle's not-found errors: the ones today's message test (`/not found\|does not exist\|NotFound/i`) matches | 404 with `{"error": message}` |
| `failed` | any other libradicle error; `message` is its `Display` text, as today | 500 with `{"error": message}` |
| `too_large` | a blob over 64 MiB, or a read whose JSON passes 32 MiB | 413 (new) |
| `range_not_satisfiable` | `range` outside the blob; `data.size` | 416 with `Content-Range: bytes */size` |
| `busy` | a pool's queue is full | 503 |
| `deadline` | past the deadline | 504 for reads; the provider's existing errors for network operations |
| `cancelled` | main's cancel | the request is already gone |
| `outcome_unknown` | a write past its deadline; main also derives it from a crash during a write | provider error -32603 with new text ([Writes](#writes)) |
| `stopped` | shutdown in progress | 503 |
| `internal` | a panic on the request's thread | 500 |
| `start_failed` | `rad.start`; `message` is libradicle's | the manager's error state, with that message |

Exit codes:
- 0001's: 64, 74, 75 and 76;
- 70 for `node_down`, or a panic outside a request.

### Pools and budgets

All bounds are process-wide. The service hosts one node.

- **The read pool:** 4 threads, with 64 queued requests. Beyond that, `busy`.
  - Reads run concurrently, under a shared lock on the node; there is no process-wide mutex.
  - Three methods take `&mut self` and take that lock exclusively: `seeders` (`lr:1143`), `unseed_repo` (`lr:847`) and `import_repo` (`lr:1012`). `seeders` is a short query on the read pool; the other two are on the write queue.
- **The network pool:** 8 threads for `connect_seeds` and `clone`, with 16 queued.
- **The write queue:** one writer, with 16 queued. COB writes, `unseed` and `import_repo` go one at a time, in order, so each write has one outcome to report.
- **The output budget: 256 MiB** for result bytes that have been read but not yet streamed: blob contents and serialized JSON.
  - A blob is charged its size twice while libgit2's buffer and the service's copy both exist, then once until its last byte is written.
  - A request that can't reserve its charge waits in its queue, under its deadline.
  - Per request, a blob is at most 64 MiB and a JSON result at most 32 MiB.
- **What the service can't bound:** heartwood's own buffers:
  - fetch streams of up to 500 MiB each;
  - its reactor queues and per-peer write buffers.

  The service doesn't promise a total memory bound for the process. Whether to add an OS-level limit is an [open question](#open-questions).

## The blob API

0006 requires raw, chunked and ranged bytes. libgit2 can't stream objects from packs (`Odb::reader` works only for loose objects), and fetched data lands in packs, often deltified. So **"chunked" means chunked over the pipe, from one bounded copy in memory**, not streamed from disk.

- **`rad.blob { rid, revision, path, range?, head_only? }`:**
  1. Resolve `path` at the commit, as `read_blob_at` does (`lr:1263`), refusing anything that isn't a blob with today's `NotABlob` message.
  2. `Odb::read_header` gives the size and type without loading the content. Refuse a blob over 64 MiB with `too_large`.
  3. With `head_only`, the head is written now and nothing is loaded. This serves `HEAD` and the length.
  4. Reserve the output budget, load the blob, and compute `binary` with libgit2's rule (`git_blob_is_binary`, the first 8000 bytes).
  5. Validate `range` (`{ start, end? }`, inclusive, as HTTP) against the size.
  6. Write the head `{ oid, size, binary, range }`, then stream `[start, end]` in 64 KiB frames under credit.
- **The JSON endpoint stays:**
  - `/blob/<rev>/<path>` on `rad:` and `radapi:` keeps returning `{ binary, name, content? }`, built by `rad.read`'s `blob_at` with v0.8.0's serializer, byte for byte;
  - that includes `from_utf8_lossy` for text and no content for binary.

  Pages and the viewer keep working unchanged.
- **The new raw endpoint:** `rad://<rid>/raw/<40 hex>/<path>`, and the same under `radapi://local/api/v1/repos/<rid>/raw/…` for the viewer.
  - It passes `serveRepoApi`'s existing checks first.
  - **Statuses:** 200; 206 with `Content-Range` for a single `bytes=` range; 416 for an unsatisfiable range.
    - Multiple ranges are answered with the whole body (200), as a server may.
    - `HEAD` uses `head_only`.
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

## Writes

- **Serialized:** COB writes, `unseed` and `import_repo` go one at a time through the write queue. `unseed_repo` and `import_repo` also need the node exclusively.
- **Outcome unknown:**
  - A COB write signs and commits git objects, updates a ref, re-signs `rad/sigrefs` and announces the change. A crash or a deadline can cut it at any of those steps.
  - So a write whose reply didn't arrive is **`outcome_unknown`**, never "failed". Main never retries one.
  - The provider answers -32603 with "The Radicle node stopped before confirming this write; it may have been recorded." The page must check before writing again.
  - This mirrors 0005's uncertain broadcasts.
- **`import_repo`** spawns `git push` from the working copy, as today (`hw/radicle/src/rad.rs:107`–`120`), with the service's cleared environment plus `PATH` and `HOME`.

## Keys

**What the service holds:**
- **One secret: the user's Radicle node key,** an Ed25519 key.
- heartwood holds it in memory for the node's lifetime, in several clones that each zeroize on drop. It needs it continuously:
  - as the Noise XK static key of every peer connection (the node ID is its public key);
  - to sign node, inventory and refs announcements, `rad/sigrefs`, COB changes, and identity documents on import.
- The service holds no wallet key, no recovery phrase and no vault data, and has no connection to the core.

**Where the key comes from** (unchanged):
- `<home>/keys/radicle`, an unencrypted OpenSSH file with mode `0600`, which `Embedded::start` loads (`lr:723`).
- **On a profile with a vault,** the core's `nodes.write_identity` writes it (0001, *Multi-file writes*), derived from the vault seed at `m/44'/73404'/0'/0'/0'` (SLIP-0010).
  - Ed25519 derivation is hardened at every level, and the file holds no chain code, so the key leads to neither the seed nor any other derived key.
  - It does let anyone holding it act as the user's Radicle identity, which is derived from the wallet and can't be rotated without a new derivation path.
- **On a profile without one,** libradicle generates a random key at first start, as today.

**What changes:**
- The add-on loads the key into main's process today. After this design only the service does, under 0001's process hardening. Main never holds it.

**How this fits AGENTS.md:**
- **Rule 3** ("No raw private key or seed leaves the core"):
  - The Radicle key leaves the core today, as a file, through 0001's `nodes.write_identity`. AGENTS.md's list of exceptions doesn't name node identity writes.
  - This design adds no new release of key material. It moves the file's reader from main to the service.
  - Whether to list node identity writes as an exception is the user's decision ([Open questions](#open-questions)).
- **Rule 4** (atomic `0600` secret files) holds for the core's write. A key libradicle generates on a profile without a vault is written by heartwood's keystore, outside the core.

**Options for the user:**
1. **The key file (this design's default, today's behavior):** no change to the core, no new exception, and the node starts at launch without the vault being unlocked.
2. **A host key with no file at rest:**
   - libradicle v0.8.0 has `Embedded::start_with_key` (`lr:744`): it writes nothing secret and keeps the key in memory. UniFFI exposes it; the add-on doesn't.
   - The key would come from the core, sealed (HPKE, RFC 9180) to an X25519 key the service generates at each start. Main relays only ciphertext.
   - **Costs:**
     - a new core method that releases a node key, sealed. That is a new exception to rule 3, which needs a design change;
     - the node can start only while the vault is unlocked, including every restart after a crash;
     - a compromised main can still ask for the key sealed to a key of its own. Sealing protects against passive exposure (logs, swap, heap dumps), not against main.
3. **Signing in the core:** rejected.
   - The Noise handshake needs the secret for every connection, and heartwood copies it into its reactor and sessions.
   - The core would have to serve network handshakes on demand.

## Main's side

- **`radicle-embedded.js` keeps its exports and their shapes.** It becomes a client of the service (0007's `ServiceClient`), so its callers don't change:
  - `radicle-manager.js`;
  - `radicle-api-protocol.js`;
  - `cob-service.js`;
  - `seed-status.js`;
  - `github-bridge.js`.

  The mapping:
  - `call` and `callRaw` send `rad.read` and collect its body, with today's `{"error"…}` handling;
  - `cloneRepoWithProgress` maps `rad.progress` events to its callback;
  - `cancelClone` cancels the clone's request.
- **Reads take admission and cancel:**
  - `rad:` and `radapi:` requests take main's dweb admission (256 active, 512 waiting), the same one IPFS uses;
  - the request's abort signal sends `cancel`;
  - the blob and JSON bodies are 0007's pull-driven streams, with idle bounds;
  - main holds at most 128 KiB per stream.
- **Readiness:** the node is up while all of these hold:
  - its generation is live;
  - `rad.start` succeeded;
  - the last `rad.stats` says `node_alive` and is under 15 s old.

  `rad.stats` runs every 5 s while the node is `RUNNING`. Today there's no probe.
- **Private partitions are read-only:**
  - main refuses `seed`, `sync`, COB writes and `importRepo` for a private partition before anything is sent;
  - reads go to the profile's node as today.
- **Identity and alias changes run with the service stopped:**
  1. stop the service;
  2. run the change under `hold-lock`: the alias rewrite, and the wipe of `node/`, `cobs/` and `storage/` before an identity change;
  3. start the service again.

  **One core change:** `nodes.write_identity` takes the same `radicle-…` lock for its Radicle writes, in the same lock directory. So the core never writes under a running node.

## Private windows

- **No ephemeral node.**
  - `rad:` reads touch only local storage, and a read never starts a network fetch.
  - A read changes nothing, so there is no cache whose state or timing could carry a private visit to another window.
- **Read-only:** private partitions can't seed, sync or write (above). `window.radicle` isn't injected in private windows today, and that stays.
- **Logs:** main's private-window redaction stays. The service logs no RID or path for any read.

## Network policy

### What heartwood can honor

- **`node.proxy`:**
  - a SOCKS5 proxy, given as an IP and port (`hw/radicle/src/node/config.rs:618`);
  - when it is set, every peer dial goes through it;
  - DNS names travel inside SOCKS5 as names, so the proxy resolves them and there is no local DNS for peer dials (`hw/radicle-node/src/wire.rs:1125`–`1130`).
- **`node.onion`:** `Proxy { address }`, `Forward` or `Drop` (`config.rs:418`–`435`). `Forward` without a global proxy dials `.onion` names as ordinary hosts, for transparent-proxy setups (`wire.rs:1112`). This design never uses it.
- **`listen`:** empty, so the node is outbound only.
- **libradicle exposes none of these.**
  - `Options` has only `home`, `alias` and `listen` (`lr:41`).
  - The node's settings come from `config.json`, whose own `listen` is ignored (`lr:773`).

### Modes

The service sets these in memory, through an [upstream](#upstream-changes) `Options` change. It never rewrites the user's `config.json`.

- **`direct`, the default:**
  - `proxy` unset and `onion: Drop`, which is heartwood's default;
  - today's dials, plus the address policy below.
- **`socks5 { ip, port }`:**
  - `proxy` and `onion: Proxy` are both set to Arti's endpoint, given as an IP literal, so reaching the proxy needs no DNS;
  - every peer dial, `.onion` included, goes through Arti;
  - nothing falls back to a direct socket.
- **The setting:** a per-profile **Route Radicle through Tor**, off by default, using `tor-manager`'s endpoint. Whether it and 0007's IPFS setting become one switch is an [open question](#open-questions).
- **Changing the policy restarts the process.** Nothing of the old policy survives its process.

### The address policy

- **Untrusted targets** are addresses learned from peers: node announcements and the address book they fill.
- **Configured targets** are the shipped seed book, `preferredSeeds` and `connect` in `config.json`, and Arti's endpoint.
- **In `direct` mode**, untrusted targets in these ranges are refused:
  - loopback, `0.0.0.0/8` and `::`;
  - private ranges (RFC 1918, `fc00::/7`);
  - link-local (`169.254.0.0/16`, `fe80::/10`);
  - CGNAT (`100.64.0.0/10`);
  - multicast, broadcast and the documentation ranges.
- **When the check runs:**
  - on IP literals, before the dial;
  - on DNS names, after resolution and before the connection. That needs resolution moved off the reactor thread ([upstream](#upstream-changes)).
  - A configured target is exempt, by exact address, so a user's LAN seed keeps working.
- **In `socks5` mode:**
  - IP-literal untrusted targets get the same check before the SOCKS request;
  - names go to Arti unresolved.
- **Onion targets** are classified the same way everywhere: a host whose last label is `onion`, case-insensitive, trailing dot removed. In `direct` mode they are refused before any socket exists, as heartwood's `Drop` does.

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
1. **Policy in `Options`** (`lr:41`): add `proxy: Option<SocketAddr>`, `onion: AddressConfig`, `control_socket: bool` and an address policy.
   - `run` (`lr:757`–`793`) applies them to `profile.config.node` before `Runtime::init`.
   - Nothing is written to `config.json`.
2. **Node health:** `Embedded::node_alive()`, from the node thread's `JoinHandle::is_finished` (`lr:684`, `lr:781`).
3. **Errors, not panics, at start:** the key-generation `expect` (`lr:706`).
4. **The JSON serializers move out of the add-on.**
   - Today they are written inline in each export (`napi:34`–`216` and every export's `json!`, for example `blob_at` at `napi:742`–`765`).
   - Move them to a library module, so the add-on, UniFFI and the service emit the same bytes.
5. **The blob header:**
   - `Embedded::blob_header(rid, revision, path) -> { oid, size }`, using `Odb::read_header` before any load;
   - `read_blob_at` (`lr:1263`) takes a size cap.
6. **Cancellable walks:** `repo_stats` (`lr:1311`), `list_files` (`lr:1118`), `commits` (`lr:1161`) and `commit` (`lr:1179`) take a `CancelToken`, so a cancelled read frees its thread.
7. **A bounded shutdown:** `shutdown` (`lr:1343`) takes a timeout. The service exits after 5 s anyway.
8. **Features:** depend on `radicle-node` without its default `systemd` feature. Its socket activation reads and removes `LISTEN_*` variables at bind (`hw/radicle-node/src/runtime.rs:314`–`349`), and the service needs none of it.

**heartwood** (the `freedom/embed` fork):

9. **An optional control socket:**
   - `Runtime::init` takes `Option<PathBuf>` (`runtime.rs:202`–`249`, bind at `344`–`359`);
   - `Handle::shutdown` must not need to connect to the socket (`runtime/handle.rs:355`–`374`).
10. **The dial gate:**
    - resolve names on a resolver thread with a deadline rather than on the reactor (`wire.rs:1146`–`1153`);
    - apply the address policy to the resolved addresses before connecting, in `Wire::dial` (`wire.rs:1089`–`1172`);
    - apply the same policy where announced addresses enter the address book.
11. **Errors, not panics:**
    - in the reactor's policy-store calls (`hw/radicle-protocol/src/service.rs:863`–`896`, `1185`, `1556`, `1641`, `2066`);
    - in start-time configuration checks (`service.rs:566`, `service/gossip.rs:12`–`16`, `runtime.rs:163`–`165`).

    A failure there should stop the node with an error the host can see.

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
  - Every read export's output on it is recorded from the v0.8.0 add-on. The service must match every byte.
  - The deliberate differences are:
    - the 70 MiB blob (`too_large`);
    - the error codes (the same message text, a code alongside).
- **The handlers:**
  - `/raw/` with 200, 206, 416 and `HEAD`;
  - the inert-type headers;
  - cancel mid-body, a paused reader, and admission's 503;
  - the service exiting mid-body;
  - private partitions refused for writes.
- **Rust tests through the binary,** with test hooks behind a feature:
  - the lock and `hold-lock`;
  - recovery of `.tmp` clones and lock files;
  - parent death;
  - a failed start that exits;
  - a panic in a read (`internal`, others unaffected, no payload in the log);
  - a killed node thread (exit 70);
  - the 5 s shutdown;
  - a kill during a COB write, after which the issue is either absent or complete and `rad/sigrefs` verifies;
  - 0007's stream cases.
- **Network:**
  - a SOCKS recorder and canary, as 0007: in `socks5` mode no direct peer socket;
  - `.onion` refused in `direct`;
  - a test peer announcing loopback and private addresses, which are never dialled in `direct`.
- **Live:** the packaged `nodes.spec.js` Radicle leg, re-pointed at the service.

### Parity

| Item | Today | The service |
|---|---|---|
| start | `Embedded::start({ home, alias: 'FreedomBrowser', listen: [] })` in main | the same call, in the service |
| key | `keys/radicle`, loaded in main | the same file, loaded in the service |
| read results | the add-on's JSON text | the same bytes, from the shared serializers |
| errors | `{"error": message}`; 404 by message test, else 500 | the same bodies and statuses; a code alongside |
| clone progress | JSON strings through a ThreadsafeFunction | the same strings, in `rad.progress` events |
| `cancelClone` | a token found by RID | `cancel` of that clone's request; the same timing |
| start-up network | `connectSeeds(15000)`, then the default-repository clone | the same |
| alias | `config.json` `node.alias` | the same file, rewritten under `hold-lock` |

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
| handshake; `rad.start` | 10 s; 30 s | kill; error, and the process exits |
| shutdown | the service exits within 5 s of `rad.shutdown`; main kills at 10 s | kill |
| exit after stdin EOF | 5 s, a watchdog thread | `std::process::exit` |
| lock contention | 5 s of retries | exit 75 |
| restarts | 0.5 s, 2 s, 10 s; three crashes in 60 s | stop, and "Restart Radicle" |
| read pool | 4 threads, 64 queued, 60 s each | `busy`; `deadline` |
| network pool | 8 threads, 16 queued; `timeout_ms` + 30 s | `busy`; `deadline`, with the slot held until libradicle returns |
| write queue | 1 at a time, 16 queued; 60 s (300 s for import) | `busy`; `outcome_unknown` |
| output budget | 256 MiB; a blob ≤ 64 MiB (charged twice while loading); JSON ≤ 32 MiB | the request waits under its deadline; `too_large` per request |
| progress events | ≤ 16 unwritten per clone, each ≤ 4 KiB | the oldest `connecting`/`fetching` dropped |
| streams | 0007's: a 128 KiB window, 64 KiB frames, coalesced in main | the service waits for credit |
| admission in main | shared with dweb fetches: 256 active, 512 waiting | 503 |
| health | `rad.stats` every 5 s; main's watchdog at 20 s | kill |
| heartwood internals | not bounded by the service ([Pools and budgets](#pools-and-budgets)) | an [open question](#open-questions) |

## Deviations

| ID | Today | After | Effect |
|---|---|---|---|
| `crash-domain` | the node runs in main | a separate process | a Radicle fault ends Radicle only |
| `auto-restart` | none | 0.5 s, 2 s, 10 s; three in 60 s stop | brief outages heal on their own |
| `home-lock` | the control-socket bind | an OS lock before anything opens | a second owner fails at start (75) |
| `network-fs` | any filesystem | a network filesystem is refused (74) | Radicle doesn't start there |
| `failed-start` | handled in main's process | the process exits after replying | nothing of a failed start survives |
| `control-socket` | `node/control.sock` is bound | none | the `rad` CLI can't attach to Freedom's node |
| `blob-api` | text as lossy JSON; binary dropped | `/raw/` with raw bytes, Range, length, ETag and inert types; `/blob/` unchanged | images and downloads work; the JSON endpoint is the same |
| `size-caps` | no limit | blobs ≤ 64 MiB, JSON ≤ 32 MiB | 413 beyond |
| `rad-admission` | no admission or abort for `rad:` and `radapi:` | dweb admission; aborts cancel | 503 under extreme load; aborted reads stop |
| `read-concurrency` | reads serialized by one mutex | 4 concurrent | reads don't queue behind each other |
| `outcome-unknown` | a write cut off by a fault had no defined answer | `outcome_unknown`, never retried | pages check before writing again |
| `stop-budget` | no Radicle budget | 10 s, then kill | quit can't wait on Radicle |
| `env` | the add-on inherits main's environment | cleared, plus `PATH` and `HOME` | `RAD_*` and `SSH_AUTH_SOCK` no longer apply |
| `proxy` | none | an optional SOCKS5 policy, failing closed | new: Route Radicle through Tor |
| `address-policy` | none | untrusted private, loopback and link-local targets refused in `direct` | configured local seeds still work |
| `health` | none | `rad.stats` every 5 s | a dead node is noticed and restarted |

## Implementation steps

1. **Tests first,** in freedom-browser: the contract suite, the fixture repository and golden vectors from the v0.8.0 add-on.
2. **Upstream:**
   - libradicle items 1–8;
   - heartwood items 9–11, on the `freedom/embed` fork.

   The service can start on items 1, 2, 4 and 9.
3. **The shared service skeleton,** from 0007: the lock, `hold-lock`, the handshake, parent death, the panic hook, hardening and the frame I/O.
4. **`services/freedom-radicled`:**
   - recovery at start;
   - the pools and the output budget;
   - `rad.read` and `rad.blob`;
   - network operations with progress and cancel;
   - the write queue;
   - `rad.stats`;
   - the test hooks and the Rust tests.
5. **Release:** five targets, `SHA256SUMS`, attestations and notices (libgit2's included), on `radicled-v*` tags, in separate build jobs.
6. **freedom-core:** `nodes.write_identity` takes the Radicle lock.
7. **freedom-browser:**
   - `radicle-embedded.js` on the service, behind `FREEDOM_RADICLE_BACKEND` in dev;
   - admission and cancel for `rad:` and `radapi:`;
   - private partitions read-only;
   - `hold-lock` for the alias, the identity wipe and profile removal;
   - the contract suite against the binary, the gates;
   - then the default switches.
8. **The raw endpoint** and the viewer's images and downloads.
9. **Network policy:** the setting, Arti's endpoint, and the SOCKS, canary and address-policy tests.
10. **Removal,** one stable release later.

## Open questions

1. **Where the code lives:** a separate workspace here (recommended), upstream libradicle, or a new repository (the user's decision).
2. **Key custody:** keep the key file (this design), or move to a sealed host key with no file at rest? The latter needs a new exception to rule 3, and an unlocked vault for every start (the user's decision).
3. **AGENTS.md:** should rule 3's exceptions name 0001's node identity writes (Bee and Radicle), which already put node keys on disk? (The user's decision.)
4. **Keys outside the core:** on a profile without a vault, should the core write the random device key, so no key is ever generated outside the core?
5. **The control socket:** is it acceptable that the `rad` CLI can no longer attach to Freedom's node, or should a developer setting keep it?
6. **The raw endpoint for pages:** is the inert-type allowlist right? Should pages get `/raw/` at all, or only the viewer?
7. **Caps:** are 64 MiB per blob and 32 MiB per JSON result right?
8. **The address policy:** are these the right ranges, and is the exact-address exemption for configured seeds enough for LAN setups?
9. **One Tor switch:** should Route Radicle through Tor and 0007's Route IPFS through Tor be one setting?
10. **heartwood's memory:** should the service run under an OS-level limit (`RLIMIT_AS`, or a Windows job memory limit), given that heartwood's own buffers aren't bounded by the service?
11. **Private windows:** is read-only acceptable, or should an internal page in a private window still be able to seed?
