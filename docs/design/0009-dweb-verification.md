# 0009: Verifying dweb content

**Status:** proposed. Roadmap Phase 4 (item 4.5). Builds on [0001](0001-freedom-cored.md) (framing; streams as protocol version 2), [0005](0005-chain-data.md) (requests the core makes, memory reserved before it is allocated), [0006](0006-dweb-transports.md) (plans, main's executor, trust labels, and the prerequisites in *Later designs*) and [0007](0007-ipfs-service.md) (stream frames, credit and rings).

**The references:**
- **freedom-browser** at `aebf5ec9` (`integration/rust-core`):
  - `dweb/dweb-handler.js`, `dweb/plan-executor.js`, `dweb/plan-validation.js` and `dweb/fetch-admission.js`;
  - `swarm/bzz-protocol.js` and `swarm/ant-api-main-dials.js`; `ant-manager.js` (`startExternalAnt` and reused daemons);
  - `ipfs/ipfs-protocol.js`, `ipfs/gateway-transport.js` and `ipfs-manager.js` (`ipfsBackend`, `requestExternalGateway`, `probeExternalGateway`);
  - `swarm/permission-manifests.js`, which reads manifests through the `bzz:` handler.
- **Ant** v0.5.64 (`b14fad3`, freedom-hq/ant), the release freedom-browser pins. `ac`, `ar` and `ag` below are the `src/` directories of `ant-crypto`, `ant-retrieval` and `ant-gateway`.
- **Bee** at `a93fb7a7` (v2.8.2-rc1 and four commits), for the formats Ant reads and writes.
- **freedom-ipfs** v0.4.5 (`9316571`), the native node 0007 moves into `freedom-ipfsd`: `freedom-ipfs-core`, `freedom-ipfs-unixfs` and `freedom-ipfs-gateway` (`GatewayCore`).
- **IPFS specifications,** as published on 2026-10-13: the Trustless Gateway, CAR v1, UnixFS and IPNS Record specifications.

Vectors are generated from the bundled nodes, Ant and freedom-ipfs, as 0003–0006's were generated from the JS ([Tests first](#tests-first)).

## Summary

An external Ant, a node Freedom reuses on the default port, and an external IPFS gateway are trusted blindly today. Their whole answer reaches the page: the bytes, the headers and their own reading of the path. 0006 labels such content `unverified` and leaves checking it to this design.

This design adds a **verified mode** for those backends. In it, the core proves that every byte it lets through belongs to the reference in the URL, or to the reference a name resolved to, or the request fails.

- **The core verifies, main fetches.**
  - `dweb.open` returns a new plan variant, `{ verify }`, for an external backend that verifies. Main checks it and executes it by calling **`dweb.verify`**, which answers with a head and a verified body.
  - While it runs, the core asks main for content-addressed pieces with **`shell.dweb_get`**: a chunk, a ranged byte stream or a CAR. Main fetches each through the backend it captured, on its own transport, under its retry and timers, and streams the answer in.
  - The core opens no sockets. Main keeps the transport, the admission, the Ant guard and the body it hands to Chromium. What changes is that a verified body passes through the core on its way, because the core is the verifier: the case 0006 deferred.
- **Streams in the core** are protocol version 2 (0001): 0007's four frames, sent by whichever side answers a request. Credit bounds every byte in flight, so bulk data never delays a `vault.lock`.
- **Swarm:** the core walks the manifest and the file's chunk tree itself, checking every chunk it fetches (`GET /chunks/<address>`), and reads the file's data as one ranged `GET /bytes/<reference>` stream. It checks every 4 KiB leaf against its address before releasing it. That is two to seven chunk requests per MiB, depending on erasure coding, and one stream, not the 256 requests per MiB 0006 estimated for chunk-by-chunk retrieval. Single-owner chunks are accepted only as feed updates.
- **IPFS:** the core asks the gateway for a trustless CAR of the path and the file, ordered depth-first with duplicates (`?format=car&dag-scope=entity`, `entity-bytes` for ranges). It checks each block against its CID as it arrives and walks the path, HAMT shards and the UnixFS DAG itself. Blocks are at most 2 MiB, as the native node allows, and are released whole.
  - **The CAR is only a block source.** When a gateway's CAR doesn't carry what the walk needs, in its order (some ignore `entity-bytes`; Kubo sends no duplicates unless asked), the core fetches the rest as raw blocks (`?format=raw`), the one response type every trustless gateway must serve.
  - **DNSLink names and RSA-keyed IPNS names** keep today's unverified fetch: `dweb.open` decides it from the name, so no node can steer a request out of verified mode.
- **Heads come from the core,** built from verified data with the bundled node's rules: Ant's for `bzz:`, `GatewayCore`'s for `ipfs:`. Vectors recorded from those nodes pin them. Nothing the external node says reaches the page unchecked, error bodies included. What can't be proven is labelled or answered as the node's word: a "not found", the latest update of a feed or an IPNS name.
- **Failure:** a mismatch before the head is a 502, "Swarm content verification failed" or "IPFS content verification failed". After the head, the body is truncated: the page keeps a prefix of verified bytes, which may end inside a chunk or block that had passed its check. No unverified byte reaches Chromium.
- **Labels:** `verified`, `latest_asserted` (verified against an owner-signed update whose freshness is the node's word), `node_asserted` (the bundled nodes, unchanged) and `unverified`. The address bar's trust panel shows them.
- **Modes:** verification is a per-backend setting, recommended on by default (the user's decision). A gateway's support is probed when it is activated, and a backend never falls back to unverified per request.
- **Budgets,** estimated and measured before the default switches. Measured hashing on the development server this design was written on: a 4 KiB Swarm leaf costs about 55–100 µs on one thread (40–74 MiB/s); SHA-256 runs at 0.7–1.6 GiB/s. Two hashing threads keep verified Swarm bodies above an estimated 80 MiB/s.
- **Tests come first:** vectors recorded from Ant, Bee and freedom-ipfs over fixtures, adversarial vectors from a lying node, and the real-handler harness with a fake Ant and a fake trustless gateway.

## Goals and non-goals

**Goals**
- **No unverified byte in a verified response:** every body byte, and every header that depends on content, is derived from data checked against the root reference. A failure ends the request before the head, or truncates the body after a prefix of verified bytes.
- **Streaming:** verification is incremental. The core holds a 4 KiB Swarm leaf or one IPFS block (at most 2 MiB) at a time, never a whole file.
- **Ranges:** a seek costs one ranged fetch plus the chunks or blocks on its path, not a read from the start.
- **The core opens no sockets** (0003–0006), and main keeps 0006's data path to the node and to Chromium.
- **Parity:** a verified response is what the bundled node would answer for the same request over the same content ([Parity](#parity)). Unverified mode stays exactly today's.
- **One place:** the verifier is sans-I/O in `fc-dweb`, `fc-swarm` and a new `fc-ipfs`, so the Chromium build (Stage 2) and mobile can run it in process.
- **Bounded resources:** every byte the core holds is reserved first, decoders included, which count what a block declares before they build anything ([Bounded decoding](#bounded-decoding)). Every bound has a defined result when exhausted ([Bounds](#bounds)).

**Non-goals**
- **The bundled nodes.** The bundled Ant validates the chunks it retrieves, and the native IPFS node hash-checks blocks. Their content stays `node_asserted`; the core doesn't check it again ([Open questions](#open-questions)).
- **Availability and privacy.** A node can still withhold content, answer "not found", or learn what the user reads. Verification proves integrity, not retrieval.
- **Freshness of mutable pointers.** A feed's or an IPNS name's latest update can't be proven; it is labelled ([Labels](#labels)).
- **Names.** Naming's trust (0004) covers the name; this design covers the content the name points at.
- **`rad:`, `radapi:` and `web3:`.** heartwood verifies refs against signed sigrefs (0008), and `chain.html` has its own trust (0006).
- **The `window.swarm` backend (4.6)** and uploads.
- **Caching content bytes.** Only verified structure is cached, briefly ([The structure cache](#the-structure-cache)).

## Today

- **Backends whose content is `unverified`:**
  - **Ant:** an external API configured per profile (`startExternalAnt`, probed at `/health` and health-checked every 5 s), and a daemon already listening on the default port that Freedom reuses. `antBackend()` reports both as `{ ant: "external" }`; the reused one may be Bee.
  - **IPFS:** an external gateway configured per profile, probed with the empty identity CID `bafkqaaa` and dialled through `gatewayFetch` on the request's session, with manual redirects. It is usually a local Kubo on `127.0.0.1:8080`, but may be any HTTP gateway.
- **What reaches the page:** the node's status, headers and body, after main's response operations. The plan's `trust.content` is `unverified`; main validates it and shows it nowhere yet (0006, open question 5).
- **What reads through these handlers:** pages and their subresources, `http-fetch.js` ("save image"), downloads, and `permission-manifests.js`, which reads Swarm permission manifests through the `bzz:` handler in process.
- **What the core has:** `fc-swarm` computes BMT roots and chunk addresses and signs SOCs, but refuses the empty payload and checks nothing it receives. `fc-dweb` plans, and its response operations run in main. Nothing in the core sees content.

## What verification proves

- **For a hash host** (`bzz://<64 hex>`, `ipfs://<cid>`): every body byte, the length, the range and every header derived from content follow from data whose hashes chain up to the reference in the URL. A node that changes one bit of a chunk, a block, a manifest node, a directory or an intermediate node is caught at that chunk or block. A single-owner chunk is accepted only as a feed update, so a `verified` result rests on content addresses alone.
- **For a name:** the same, for the reference naming resolved. How far the name itself is trusted is naming's label (0004), shown beside the content's.
- **The path is resolved by the core,** from the root, through verified manifest nodes or directory blocks. The response is bound to the root and the path whatever the node's own path handling does.
- **A proven "not found":** when a verified manifest or directory has no entry for the path, the 404 is the core's, and as certain as the content.
- **What stays the node's word,** and is labelled or answered as such:
  - **"Not found" or an error for a piece:** the node may be withholding it. The status is passed on, with a fixed body from the core, never the node's.
  - **The latest update** of a Swarm feed or an IPNS name: the update is checked against its owner's signature, but the node chooses which signed update to serve, so it may serve an old one (`latest_asserted`).
  - **A DNSLink name** under `ipns:`: its root comes from DNS, through the gateway. Checking a DAG against a root the gateway chose would prove nothing about the name, so DNSLink keeps today's fetch, labelled `unverified` ([IPNS and DNSLink](#ipns-and-dnslink)).
- **Out of scope:** a compromised main, which Stage 1 trusts (0001), and a compromised core.

## Where verification runs

**The decision: the core verifies; main fetches and delivers.**

```
Chromium ◀─body── main ◀─verified body (stream)── freedom-cored
                   │                                  │ dweb thread: walk, check, build the head
                   │◀──── shell.dweb_get ─────────────┘ hashing pool: BMT, SHA-256
                   │───── node's answer (stream) ────▶
                   ▼
          external Ant or gateway (main's transport: undici on loopback, the session's stack otherwise)
```

- **Why the core:**
  - **It is the one Rust process always present.** In external modes no service runs: `freedom-ipfsd` serves the native node only (0007), and there is no Swarm service; the external Ant is the node.
  - **The logic belongs in the shared crates.** A sans-I/O verifier in `fc-dweb` is what the Chromium build's URL loaders and mobile can call in process, with the same vectors. On desktop, the core is where those crates run.
  - **0006 anticipated it:** "bytes through a verifier", over protocol version 2's streams, once the core checks them.
- **What it costs, and what bounds it:**
  - **Every verified byte crosses the pipe twice,** in and out. A pipe moves gigabytes per second; hashing moves tens to hundreds of megabytes ([Performance](#performance)), so hashing is the bound, not the pipe (an estimate, measured before the default switches).
  - **The vault shares a process with bulk data.** Credit bounds every byte in flight, the reader never waits on dweb data, and the dweb thread and its hashing pool are separate from the vault loop ([Streams](#streams-in-the-core)). A test pins a `vault.lock` acknowledged on time under full dweb load.
  - **A core restart truncates verified bodies.** 0006 kept bodies out of the core partly for this. Here it is the price of checking them, and listed as deviation `core-data-path`. A restart is a crash, which 0001 restarts with back-off.
- **Main keeps** its transport (loopback undici, or `net.request` on the request's session with the proxy and onion rules), the Ant guard's announcements, fetch admission, plan validation, the response operations, the body idle timer and the stream it hands to Chromium.

**Alternatives considered:**
- **In main, in JavaScript.** Rejected:
  - a second implementation of BMT, mantaray, CAR and UnixFS, outside the shared crates;
  - keccak in JavaScript is slower than in Rust (by how much wasn't measured), and a leaf's 128 hashes would run on main's thread or a worker.
- **In a service process.**
  - **For IPFS,** `freedom-ipfsd` could run an instance whose only provider is the configured gateway, fetched per block with `?format=raw`, as freedom-ipfs already fetches HTTP providers. `GatewayCore` would build the responses, and `verify_block` would check them. Rejected for now:
    - external mode would then need the native node's service running, where today it needs only the gateway;
    - the gateway's dials would move from the session's network stack to the service's policy (0007), changing how `.onion` gateways and proxies work;
    - Swarm would still need the core's verifier, so there would be two verifiers with two stream paths.

    It remains the fallback if the core's IPFS verifier proves too costly to keep in step with `GatewayCore`.
  - **For Swarm,** no service exists besides the node itself. A new verifier process would duplicate the core's stream plumbing and supervision for no gain.
- **Main keeps the bytes and the core returns verdicts.** Main would stream the node's body to the core and release bytes to Chromium as the core confirms them: one pipe crossing instead of two. Rejected: an IPFS body is cut out of CAR blocks, so the core must produce it anyway, and one model for both schemes is simpler to bound and test.
- **Verify the whole file at the end,** by recomputing the root from a plain `/bytes` or path-gateway stream. Rejected: the page would see bytes before they are checked, or the file would be buffered whole.

## The protocol

### Verify plans

- **`backend`** (0006) gains `verify` for an external backend whose verification is on and supported ([Modes](#modes)):
  - `{ ant: "external", up, verify: true }`;
  - `{ ipfs: "gateway", up, verify: true }`.

  `verify` is absent for the bundled nodes and for an external backend that doesn't verify, so those keep their exact two-key form and today's plans.
- **With `verify`, a `{ fetch }` plan becomes a `{ verify }` plan.** Redirect and error plans are unchanged: the same URL checks, name results, 404/415/502 mapping, gateway-form 307s and 503s for a backend that isn't up.

  ```jsonc
  { "verify": {
      "node": "ant",                                    // or "ipfs": a reference, as in a fetch plan
      "root": { "swarm": "<64 or 128 hex>" },           // or { "ipfs": "<CIDv1, base32>" }, { "ipns": "<Ed25519-keyed name>" }
      "path": "/docs/page.html",                        // below the root, normalized, as an HTTP client sends it
      "query": "?state=1",                              // the request's query, for redirects only; "" when none
      "headers": [["range", "bytes=0-"]],               // the request headers the verifier honours
      "retry": { … }, "timers": { … },                  // per piece: today's tables for the backend
      "response": ["canonicalize_redirect", "strip_page_state"],  // operations main runs on the head
      "trust": { "name": "verified", "content": "verified" } } }
  ```

  - **`root`** is the reference the fetch plan's path would have named: a hash host, or a name's resolved contenthash with any published base path moved into `path`.
  - **`path`** passes the same checks as a fetch plan's ([0006, Validation](0006-dweb-transports.md#validation-before-any-dial)), applied to `/<namespace>/<root><path>`. The core decodes its segments itself during the walk.
  - **`query`** is the request URL's query, exactly as main admitted it (`?` and all, or empty). It never takes part in a lookup: Ant's `/bzz` ignores it for content, and `GatewayCore` reads none. It exists for one thing: Ant keeps the query on its directory redirect, so the core's 308 `Location` must carry it too ([Heads](#heads)).
  - **`headers`** keeps only the request headers the bundled node reads: `range` for `bzz:` (Ant handles no conditional request), and `range` and `if-none-match` for IPFS ([Responses](#responses)). Everything else of the request stays in main.
  - **`retry` and `timers`** are the fetch plan's, applied to each piece: Ant's ten attempts on 500, 502, 503 and 504 with 30 s to the headers, and the external gateway's single attempt with no header bound. `body_idle_ms` applies to each piece's stream and to the verified body.
  - **`response`** names the bundled node's operations, as its own plans name them: `canonicalize_redirect` and `strip_page_state` for `bzz:`, since the core writes Ant's redirects in Ant's URL space and main rewrites them as today; `strip_page_state`, and `small_text` for a GET navigation, for IPFS.
  - **`trust.content`** is `verified`: the promise for the mode. The head carries the final label ([Labels](#labels)).
- **Why a plan, then a second call.** `dweb.open` runs on the naming thread, stateless once it answers, and main fences its plans against naming's generations (0006). A verified fetch is long-lived and stateful. Splitting them means a plan overtaken by a naming change is planned again before any piece is fetched, and naming's thread never holds a fetch.
- **Validation** (`validate_plan`, and main's `plan-validation.js`, with the same vectors): `shape`, `node` (the admitted backend, up, with `verify`), `root` (a 64- or 128-hex reference; a CIDv1 in lowercase base32; an IPNS name whose key is Ed25519), `path`, `query` (equal to the admitted URL's query, and within 0006's URL bound), `header`, `retry`, `timers`, `response` and `trust` (`content` is `verified`). A refused plan is a 502 and a logged core fault, as in 0006.

### `dweb.verify`

| Method | Params | Result |
|---|---|---|
| `dweb.verify` | `{ plan, method, partition, private, deadline_ms }` | a head `{ status, headers, body, trust }`, then the verified body as a stream when `body` is true |
| `dweb.forget` | `{ partition }` | `{}`, once the partition's cached structure and IPNS floors are gone; sent when a private partition closes |

- **`plan`** is the `{ verify }` plan as `dweb.open` returned it and main validated it. The core checks it again, against `method` and itself.
- **`method`** is GET or HEAD, as main read it. A HEAD answers the same head with `body: false`.
- **`partition`** is an opaque name for the request's session: `null` for the profile's default session, a private partition's name otherwise. Only the [structure cache](#the-structure-cache) reads it. **`private`** marks a private window's request, so the core never logs its references.
- **`deadline_ms`** bounds the time to the head: 360 s, about today's worst case for one `bzz:` request through its ten attempts (an estimate). After the head there is no core deadline; main's body idle timer ends a stalled body.
- **Caller kinds:** `shell` only, as `dweb.open`.
- **The head** is the core's, built from verified data ([Heads](#heads)). Main runs the plan's response operations on it, the security operations always, then hands Chromium a `Response` whose body reads the stream.
- **`trust`** is `{ name, content }`: the plan's name trust and the final content label.
- **Errors:** `busy` and `deadline` before the head; `cancelled`. Every outcome that reaches the page as HTTP, a verification failure included, is a head with a status, not an error reply ([Failures](#failures)).
- **Thread:** the **dweb thread**, a new thread beside naming's and chain's, runs one sans-I/O machine per request (`fc-dweb`'s verifier). A pool of two hashing threads computes BMT roots and SHA-256 digests for it.

### `shell.dweb_get`

What the core asks main for while a `dweb.verify` runs.

| Method | Params | Main does | Reply |
|---|---|---|---|
| `shell.dweb_get` | `{ for, path, headers, stream, max_bytes }` | one piece through the backend `for`'s request captured, with its plan's retry and timers | `{ status, headers, body_base64 }` whole, or `{ status, headers, body }` and a stream; or `{ failed }` |

- **`for`** is the `dweb.verify` request's envelope ID. Main uses that request's captured backend, session, signal and plan, so the core can't direct a piece to another node, session or retry policy. A `for` that isn't a live `dweb.verify` is `invalid_argument`.
- **`path`** is one of a closed set of forms, checked in main before any dial:
  - Ant: `/chunks/<64 hex>`; `/bytes/<64 hex>`; `/feeds/<40 hex>/<64 hex>`.
  - IPFS: `/ipfs/<cid><path>?format=car&dag-scope=entity`, with an optional `&entity-bytes=<from>:<to>`; `/ipfs/<cid>?format=raw`; `/ipns/<name>?format=ipns-record`.
  - The path below the reference passes 0006's namespace checks.
- **`headers`:**
  - Ant: Swarm's three retrieval headers at the plan's values; `range` for `/bytes`; `swarm-only-root-chunk: true` for `/feeds`;
  - IPFS: `accept`, at exactly `application/vnd.ipld.car; version=1; order=dfs; dups=y`, `application/vnd.ipld.raw` or `application/vnd.ipfs.ipns-record`, and never `range`.
- **`stream`:** false for chunks, feed lookups and IPNS records, whose bodies main reads whole up to `max_bytes` (at most 64 KiB) and returns as base64 in one frame; true for `/bytes`, CARs and raw blocks, whose bodies stream under the core's credit. A streamed piece's `max_bytes` bounds it too: 2 MiB for a raw block; none for `/bytes` and CARs, which the core ends itself when its walk is done.
- **Executing it:** `plan-executor.js`'s dial with the plan's retry, delays and header deadline, on the backend's transport, with the Ant guard's announcement for a non-loopback Ant. A retried attempt's body is cancelled before the next. The body idle timer runs while the core has credit outstanding and no bytes come.
- **The reply's `headers`** are only those the core reads: `content-type`, `content-length`, `content-range` and `swarm-feed-index`, at most 8, each at most 8 KiB, as 0005 bounds Blockscout's.
- **`failed`** is the dial's failure class, which the core maps with `fc-dweb`'s `failure::after_dial` as today: `unreachable` (`ECONNREFUSED`, `ECONNRESET`, `ENOTFOUND`), `error`, or `aborted`.
- **Cancel:** the core sends 0001's `cancel` for a piece it no longer needs, and main aborts the dial or answers the open stream with `abort { code: "cancelled" }`.

### Streams in the core

0001 reserved frame kinds `0x02`–`0x0F` for Phase 4's streams, to come with protocol version 2. 0007 defined four of them for service connections, and #72 implements them in `fc-protocol`. The core adopts the same four frames, unchanged, with one generalization: **a stream is the body of a response, sent by whichever side answers the request.**

- **The handshake:** `core.hello` carries `protocol: 2`, main offers `frames: ["fragment", "stream"]`, and the core's capabilities gain `streams`. Main and the core ship together, so neither falls back to version 1.
- **Who sends what:**
  - the responder sends data, `end` and `abort`; the requester sends credit;
  - the stream ID is the request's envelope ID, in the requester's ID space;
  - so data reaching a side names one of its own requests, and credit reaching it names a request it answered. Each side's IDs strictly increase (0001), so 0007's rules that rely on it (late credit needs no table; a frame for an ID never issued is a protocol error) hold in each direction.
- **Which methods:** `dweb.verify`'s head opens a stream from the core to main; `shell.dweb_get` with `stream: true` opens one from main to the core. Any other stream is a protocol error.
- **0007's rules, per stream:** the head first, then data, then exactly one terminal; `end` only after the last data; `abort` jumps the queue and purges; a cancel against an unwritten head drops it; a 128 KiB window; data frames of 1 to 65,536 bytes, coalesced below 4 KiB; the same protocol errors.
- **The global bound** that 0001 promised:
  - **Credit is granted only for room already reserved,** by the side that will hold the bytes.
  - **Into the core:** at most 128 incoming streams have credit at once, across all requests; a request whose next piece would be the 129th waits for one to end ([Admission](#admission-deadlines-and-cancel)). So at most 16 MiB of node bytes are in flight to the core.
  - **The reader never waits on dweb data.** A data frame within credit goes straight into its stream's reserved buffer, so data can't fill 0001's reader budget (256 frames, 16 MiB). A `vault.lock`, `core.shutdown` or `cancel` behind bulk data is read and handled as soon as the reader reaches it. Data beyond credit is a protocol error.
  - **What credit doesn't remove:** bytes already queued in the pipe ahead of a lock. Credit bounds them at 16 MiB, which the reader copies rather than processes; the vault [gate](#gates) measures the delay.
  - **Out of the core:** at most 64 verified bodies, each with a 128 KiB window. The dweb thread's writer allowance is those windows, 8 MiB, beside the vault loop's and the chain thread's. Control frames still go first.
  - **In main, the rings:** one 128 KiB ring per verified body, as 0007 keeps them. A ring outlives the core's request: after `end`, main keeps it until its consumer has drained it, or frees it on a cancel (0007). So the core's 64 running requests don't bound main's rings.
    - **Main's fetch admission does.** A verified fetch holds its slot until its body ends, and its body ends exactly when the ring is drained or cancelled. An admitted fetch has one body, from the core or from 0007's service, so main holds at most 256 rings in all: 32 MiB, the bound 0007 already states.
    - A page that leaves finished bodies unread therefore holds slots, and new dweb fetches wait in main's admission (512 waiting, then 503), as they do today for any unread body.
  - **In main, the pieces:** for each piece stream, main reads from the node only as the core's credit allows, holding at most one window.
- **`fc-protocol`** (#72) moves the role from the connection to the stream: a connection may both send and receive bodies, while service connections keep one role each. Its vectors gain the core's two directions.

### Admission, deadlines and cancel

- **Admission in the core:** at most 64 running `dweb.verify` requests and 256 waiting; beyond that, `busy`, which main answers 503. Main's own admission (256 active dweb fetches, 0006) applies first; a verified request holds its slot until its body ends.
- **Pieces in flight:** per request, at most 8: a `/bytes` stream and 4 intermediate chunks ahead of it ([Leaves](#leaves)); 8 chunks on the [encrypted path](#encrypted-references); one CAR; or 8 raw blocks ([Raw blocks](#raw-blocks)). Across requests, at most 256 `shell.dweb_get` are outstanding, as 0004 bounds naming's requests to main; more wait in the dweb thread, first in, first out, and their memory counts against their request. So main never dials the node more than 256 times at once for verified requests.
- **Deadlines:** the head's `deadline_ms`; each piece's header deadline and retries in main; main's body idle timer on each piece stream and on the verified body. The external gateway's pieces have no header deadline, as today's gateway requests have none; after the head, a piece that never answers leaves the verified body's read pending, and the body idle timer ends it after 60 s.
- **Cancel:**
  - the page's abort, a body cancelled by Chromium, or the session closing makes main send `cancel` for `dweb.verify`;
  - the core then cancels every piece the request has open, and answers `cancelled` before the head, or `abort { code: "cancelled" }` after it;
  - a request's memory is released when its last piece has ended, not when the reply is sent.
- **A core restart** truncates every verified body and fails every pending head with 503, "The core is unavailable", as 0006 maps `core_unavailable`.

## Swarm

### Chunks

The formats Ant and Bee share, with Ant's reading where they differ, since the bundled Ant is the parity target.

- **A content-addressed chunk (CAC)** is `span ‖ payload`: an 8-byte little-endian span, then 0 to 4,096 bytes (`ac/bmt.rs:179`; Bee `pkg/cac/cac.go:73`).
  - **Its address** is `keccak256(span ‖ bmt_root)`. The BMT root is a binary keccak tree over the payload zero-padded to 4,096 bytes, as 128 segments of 32 bytes (`ac/bmt.rs:33`–`102`).
  - **The check** is that the address matches. Neither node compares the span with the payload's length.
  - **The empty chunk** (span 0, no payload) is valid. Its address, `b34ca8c2…171526`, is also the reference of an empty file. `fc_swarm::bmt_root` refuses an empty payload today; the check accepts it.
- **A single-owner chunk (SOC)** is `id(32) ‖ signature(65) ‖ span(8) ‖ payload`, 105 to 4,201 bytes (`ac/soc.rs:8`–`30`).
  - **Its address** is `keccak256(id ‖ owner)`.
  - **The signature** is over the EIP-191 digest of `keccak256(id ‖ wrapped CAC address)`, as `r ‖ s ‖ v`. The core follows Ant: `v` from 27 to 30, and a high `s` refused (`ac/lib.rs:202`–`227`). That needs signature recovery in `fc-evm`.
  - The wrapped chunk may carry any span, so it can be the root of a larger tree.
- **What `/chunks/<address>` returns:** the chunk's wire bytes, a CAC's or a whole SOC's, as `binary/octet-stream` (`ag/retrieval.rs:307`–`403`). Bee does the same.
- **Where a SOC is accepted: only as a feed update,** at the address the walk computed from the feed's topic, owner and index ([The Swarm walk](#the-swarm-walk)).
  - **Everywhere else** (a root, a manifest node, a file's root, an intermediate chunk, a leaf, an encrypted chunk) the piece must be a CAC whose address is the reference. A SOC there, even a valid one, is `unverifiable` and never followed (deviation `soc-references`).
  - **Why:** a SOC's address commits to its identifier and owner, not to its payload, so its owner can sign different payloads at one address. A result that rested on one couldn't be called `verified` or cached as immutable.
  - **So** every verified result is CAC-addressed from its root down, except one that crossed a feed. That result is labelled `latest_asserted` and sent with `Cache-Control: no-cache`, as Ant sends it, and its SOC is never cached.

### Files

- **Leaves** are consecutive 4,096-byte slices of the file; only the last may be shorter (`ar/splitter.rs:1`–`25`).
- **An intermediate chunk** is `span ‖ references`: the span is the number of file bytes beneath it, and the payload holds 2 to 128 references of 32 bytes. Trailing all-zero references are padding. A chunk whose span is at most its payload's length is a leaf.
- **Geometry:** for a node with `n` data references and span `T`, `branch` is the smallest `4096 · b^k` with `T − (n − 1) · branch ≤ branch`. The first `n − 1` children cover `branch` bytes each, and the last the rest (`ar/joiner.rs:1314`–`1335`). Every leaf but the last is full, so byte `o` of the file is in leaf `⌊o / 4096⌋`.
  - The core takes each child's logical length from this geometry, as Ant's joiner does, never from the child's own span. [The leaf check](#leaves) covers a leaf whose span or payload length differs from the length its parent gives it.
- **Erasure coding:** an intermediate chunk with parities has its span's top byte set to `0x80 | level`, for levels 1 to 4. Its payload is the data references followed by parity references. Their counts come from Bee's `ReferenceCount` (the span, the level and whether the tree is encrypted; `ar/rs.rs:328`–`344`, `ar/joiner.rs:631`–`640`).
  - The core parses this and ignores the parities. It never needs them: a node that recovered a missing chunk from parities serves the original data, which checks against the original address.
  - `/bytes` is unchanged by erasure coding.
  - **It lowers the branching:** an intermediate chunk holds at most 119, 107, 97 or 39 data references at levels 1 to 4 (Bee's table, which Ant follows), so a level-1 chunk covers less of the file ([Performance](#performance)).
- **Depth:** the number of intermediate levels is `⌈log_b(⌈N / 4096⌉)⌉`, with `b` = 128, or the data references above under erasure coding. A 1 GiB file without erasure coding has three levels.

### Manifests and feeds

- **A mantaray node** (`ar/mantaray.rs:1286`–`1470`; Bee `pkg/manifest/mantaray/marshal.go`):
  - a 32-byte obfuscation key in the clear; everything after it XORed with the key, repeated. Bee and bee-js write a zero key for unencrypted manifests;
  - the version hash (the first 31 bytes of `keccak256("mantaray:0.2")`, or of `0.1`);
  - the reference size: 32, 64 in an encrypted manifest, or 0 in an empty node, which Ant accepts and the core reads as Ant does;
  - the node's entry, all zeros when it has none;
  - a 32-byte bitmap of forks, one bit per first byte;
  - each fork, in byte order: a type byte, a prefix length (1 to 30), a 30-byte prefix, the child's reference, and, when the type has bit 16, a 2-byte length and a flat JSON object of strings.
- **A node is stored as a file,** so one larger than 4 KiB is a chunk tree. Ant caps a node at 32 MiB (`ar/mantaray.rs:1001`–`1062`); the core caps it at 1 MiB (deviation `manifest-node-cap`).
- **Lookup:** from the root, take the fork for the path's next byte, require its prefix to begin the rest of the path, load the child, and repeat until the path is used up; the node reached gives the entry and its metadata. A path longer than one prefix is chained across nodes. Each step loads one node: one chunk, usually.
- **The root's metadata** (`website-index-document`, `website-error-document`, and the feed keys) is on its `/` fork.
- **Parity:** the core reads manifests exactly as Ant v0.5.64 reads them, held to vectors from Ant, malformed manifests included.
- **Feeds:** a root whose `/` fork carries `swarm-feed-owner` and `swarm-feed-topic` (and `swarm-feed-type` absent or `Sequence`; Ant refuses epoch feeds) is a feed manifest (`ar/feed.rs:94`–`211`).
  - The update at index `i` is the SOC with `id = keccak256(topic ‖ u64_be(i))` and the feed's owner.
  - **v1 updates** wrap 48 or 80 bytes, `span ‖ timestamp(8, big-endian) ‖ reference`; **v2 updates** wrap the content's root chunk itself. Ant tries v1 first, then fails (`ar/feed.rs:843`–`906`); the core does the same.

### The Swarm walk

For `bzz://<root><path>`, in Ant's resolution order (`ar/mantaray.rs:424`–`528`):

1. **The root:** `/chunks/<root>`, checked as a CAC; and its tree, when the root is an intermediate chunk. If it isn't a manifest, Ant serves the reference's bytes, and so does the core.
2. **A feed root:**
   - main asks `GET /feeds/<owner>/<topic>` with `Swarm-Only-Root-Chunk: true`, and the core reads only `swarm-feed-index` from it: which update is latest is the node's word;
   - then `/chunks/<the update's address>`: the core checks the SOC's address, its identifier for that index, the owner the manifest names, the signature and the wrapped chunk;
   - the update's reference (v1) or root (v2) becomes the manifest's root, and the label becomes `latest_asserted`.
3. **The path,** as Ant resolves it:
   - an empty path is the index document; without one, a 404;
   - the literal path;
   - on a miss, a 308 when the path plus `/` begins an entry;
   - then the path joined with the index document;
   - then the error document, served with 200;
   - otherwise a 404.

   Each node is `/chunks/<reference>`, checked, from the [structure cache](#the-structure-cache) when it is there.
4. **The entry** gives the file's reference and its metadata.

The walk proves both outcomes: the entry found, or its absence from a verified manifest.

### Leaves

1. **The file's root:** `/chunks/<file reference>`, a CAC. Its span, without a level byte, is the file's size. A root that is a leaf is the whole body, the first `span` bytes of its payload as Ant serves them, and nothing more is fetched.
2. **The range** ([Responses](#responses)) maps to leaves `⌊start / 4096⌋` to `⌊end / 4096⌋`.
3. **Intermediate chunks** on the path to the first leaf are fetched in order, then those ahead of the stream, at most two level-1 chunks ahead (1 MiB of body in a plain tree, less with erasure coding), and at most 4 chunk requests at once.
4. **The data:** one `GET /bytes/<file reference>`, with `Range: bytes=<first leaf's start>-<last leaf's end>`.
   - **Each leaf is checked** as its bytes arrive. Its logical length `L` comes from its parent ([Files](#files)); `chunk_address(L, bytes)` must equal the address its parent names. Only then are its bytes, trimmed to the range, released.
   - **A leaf that doesn't match** is fetched once as `/chunks/<address>` and checked as a CAC. Ant serves the first `L` bytes of a leaf's payload, whatever the leaf's own span. So the leaf passes when its authenticated payload has at least `L` bytes and its first `L` equal the streamed bytes. A payload shorter than `L` is a shape the core doesn't support (`unverifiable`). Any other mismatch is a verification failure.
   - **An exact 206:** its `Content-Range` must name exactly the requested interval and the file's verified size, or nothing is used. The interval's bytes are checked leaf by leaf. The piece is complete when the interval's last byte has passed and been released; the core then cancels it. A body that ends before that is a piece failure.
   - **A 200,** from a node or proxy that ignores `Range`, as HTTP allows (RFC 9110, section 14.2): the body is the whole file from byte 0.
     - The core discards the bytes before the first needed leaf, unreleased and unchecked, and checks every leaf through the last needed one.
     - Then it cancels the piece. The rest of the file isn't read and isn't judged: an unneeded suffix is no failure.
     - A 200 that ends before the last needed leaf is a piece failure. Bytes at the needed offsets that don't check are a verification failure.
     - A proxy that drops `Range` costs bandwidth, not correctness.
   - **Any other answer** (another status, or a `Content-Range` for another interval) is a piece failure before any byte is used.
   - **A stall:** while the core still needs bytes, main's body idle timer ends a piece that sends nothing for 60 s. Once the core has what it needs, it has already cancelled the piece, so a stall after that costs nothing.
5. **HEAD** stops after step 1.

Ant's `/bytes` supports a single range on 64-hex references (206 with `Content-Range`), as Bee's does through Go's `ServeContent` (`ag/retrieval.rs:2390`–`2583`).

### Encrypted references

- **The format:** a reference of 64 bytes, the chunk's address and a key. A chunk is `encrypted span ‖ encrypted payload`, the payload always padded to 4,096 bytes. Segment `i` is XORed with `keccak256(keccak256(key ‖ u32_le(i + c)))`, with `c` = 0 for the payload and 128 for the span (`ac/encryption.rs:57`–`96`; Bee `pkg/encryption`). Intermediate chunks hold 64 references of 64 bytes.
- **The plaintext can't be checked against the address.** The padding is random, and so is each chunk's key, so the ciphertext can't be rebuilt from what `/bytes` returns.
- **So the core takes every chunk from `/chunks`,** checks it as a CAC against its address, and decrypts it itself with the key from its reference, up to 8 chunk requests at once. That is about 260 requests per MiB (256 leaves and 4 intermediates).
  - On a loopback node with cached chunks, an estimated 10–30 MiB/s; across a network, far less.
  - Encrypted references are rare in browsing. Whether this path should exist, or encrypted references stay `unverified`, is an [open question](#open-questions).

### The structure cache

- **What it holds:** verified chunks that are structure, never data: manifest node chunks and intermediate chunks. Not leaves, and never SOCs, whose content at an address can change.
- **What an entry is:** the chunk's wire bytes as checked against its address. For an encrypted tree that is the ciphertext; the key from the reference that names it is applied on every use, and plaintext is never cached. So a reference with another key at the same address can't read anything from the cache that it couldn't fetch.
- **Key and bound:** `(partition, address)`; 8 MiB across partitions, least recently used out first.
- **Private partitions:** each has its own entries, dropped when main sends `dweb.forget` for it, with the partition's IPNS floors. Nothing is written to disk. A private window never reads the profile's entries, so it can't time another session's loads.
- **Late results:** `dweb.forget` advances the partition's epoch. A cache insert or a floor update carries the epoch its request started under, and one from an older epoch is dropped, so a piece reply or hashing result that arrives after the forget leaves nothing behind.
- **Why:** a site's subresources share the upper manifest nodes, and a video's seeks share the file's root and upper intermediates. With the cache, a later request costs one or two chunks before its stream.

## IPFS

### Blocks and DAGs

- **A block passes when** its bytes hash to its CID's multihash and it is at most 2 MiB: freedom-ipfs's `verify_block` (`freedom-ipfs-core/src/lib.rs:116`–`143`), which `fc-ipfs` links, so the native node and verified mode accept exactly the same blocks.
  - **Hash functions:** sha2-256 and identity, as the native node. Kubo's default is sha2-256, and other functions are rare in practice (IPIP-0499's survey). Another function is `unverifiable`.
  - **Codecs:** dag-pb and raw, the two `GatewayCore` serves.
  - **A link matches a block** when their codec and multihash agree, so a CIDv0 link inside a DAG and the CIDv1 host 0006 re-encodes it to are the same block.
  - **Identity CIDs** carry their data inline; no gateway sends a block for them (the trustless spec forbids it in CARs).
- **dag-pb and UnixFS** are read by `fc-ipfs`'s own [bounded decoders](#bounded-decoding), to the DAG-PB and UnixFS specifications.
  - **A file's content** is its node's `Data`, then its children in link order; `blocksizes[i]` is the content under link `i`. A raw leaf is its block.
  - **Stricter than the native reader, deliberately:** `blocksizes` must have one entry per link, a raw leaf's length must equal its entry, and the content must add up to `filesize`. A file that fails one is cut at that point as malformed: its author made it inconsistent, and the core doesn't guess which length was meant. The pinned native reader instead slices a child by its declared size (deviation `unixfs-sizes`).
- **HAMT-sharded directories** (fanout 256 only, as the native node; Kubo's default): the core finds a name by its hash, as Kubo's gateway does (boxo `hamt.go:382`–`404`):
  - the first 64 bits of MurmurHash3 x64 128 of the name, seed 0, read big-endian, consumed a byte per level;
  - the shard's bitfield, a big-endian integer right-aligned in `Data`, says whether the bucket is occupied, and the link is chosen by its position among the set bits;
  - a link named by the two-hex-digit bucket alone is a sub-shard; one named bucket-and-name is the entry.

  So the core needs only the shards on the name's path, which is what a gateway's CAR carries. The pinned native reader finds an entry by its name among the shards' links instead. On a well-formed directory both find the same entry; an entry that isn't where its hash and the bitfield point isn't found in verified mode (deviation `hamt-lookup`).
- **Symlinks** are refused, as `GatewayCore` refuses them.

### Bounded decoding

The 2 MiB block limit bounds a block's bytes, not what decoding it allocates: a block of minimal repeated fields can declare far more entries than its size suggests, and nesting can cost stack. So no decoder in the verifier allocates from a count it hasn't checked and reserved, and none recurses.

- **One rule for every decoder:** dag-pb, UnixFS `Data`, the CAR header, the IPNS record and its signed data, mantaray nodes and Swarm intermediate chunks.
  - **Its input is already held and reserved:** a block that passed its hash, a chunk, a record within its cap.
  - **A first pass** validates the structure and counts what the second will keep (links, entries, copied bytes), without allocating.
  - **Each count is checked** against its cap and the request's budget, and its memory reserved (0005's rule), before the second pass builds anything.
  - **Strings and byte fields are views** into the held bytes. One is copied only when an output needs it, such as a listing's names, and reserved first.
  - **Every declared length** is checked against the bytes remaining before it is used.
  - **Nesting** is walked with an explicit stack of fixed depth, never by recursion.
- **Protobuf** (dag-pb, UnixFS `Data`, the IPNS entry):
  - varints of at most 10 bytes; every length within its enclosing message;
  - unknown fields skipped by wire type (varint, 64-bit, length-delimited, 32-bit) without allocating; groups refused. A message of many unknown fields costs time linear in its bytes and no memory;
  - `PBNode`'s fields in either order (IPIP-0550);
  - a `PBLink` without a hash refused in the first pass, before anything is kept.
- **CBOR** (the CAR header, the IPNS record's signed data):
  - definite lengths only, as DAG-CBOR requires, each checked against the bytes remaining;
  - nesting at most 8 levels, on an explicit stack;
  - map keys are strings, without duplicates;
  - unknown keys and the values the reader doesn't need are skipped iteratively, under the same depth bound;
  - tag 42 only where a CID is expected.
- **Caps on decoded structure,** beyond the wire caps:
  - 65,536 links per dag-pb node. A node of real links can't reach it within 2 MiB; only degenerate encodings can;
  - 256 forks per mantaray node (one per first byte), and fork metadata within its 2-byte length, read with `fc-json`'s depth bound. Only a flat object of strings is accepted, and only the keys the walk reads are kept.
- **What this means for sharing code:** `fc-ipfs` can't use `freedom-ipfs-unixfs`'s decoders as they are. They decode with `prost`, which allocates repeated fields while it reads, before any reservation can be made. `fc-ipfs` carries its own bounded decoders, held to vectors from the native reader on the blocks both accept ([Open questions](#open-questions)).

### The CAR request

- **What the core asks:** `GET /ipfs/<cid><path>?format=car&dag-scope=entity`, with `&entity-bytes=<from>:<to>` for a range, and `Accept: application/vnd.ipld.car; version=1; order=dfs; dups=y`.
- **What a conforming gateway sends** (Trustless Gateway spec, IPIP-0402 and IPIP-0412; boxo `backend_blocks.go:440`–`680`):
  - the blocks that resolve the path, root first, then the entity: a file's root, intermediates and leaves, only those covering `entity-bytes`; a directory's block, or all of a HAMT's shards;
  - depth-first, with a repeated block sent again where it repeats (`dups=y`);
  - `Content-Type: application/vnd.ipld.car; version=1; order=dfs; dups=y`.
- **What the core accepts:**
  - a 200 with that type and those parameters;
  - a header of at most 64 KiB, a DAG-CBOR map with `version: 1`. Its roots are ignored, as the spec says clients should;
  - sections of at most 2 MiB plus the CID's length, each length checked before a byte of the block is buffered.
- **Each block** is hashed, then must be the block the core's own walk needs next. The core releases a leaf's content only after both checks.
- **The CAR is a block source, not an authority.** A block that hashes right but isn't the one the walk needs next isn't a lie:
  - the gateway may have ignored `entity-bytes` and sent the whole DAG;
  - it may have sent another order, or no duplicates;
  - it may have read the path differently.

  Then the core cancels the CAR and fetches what its walk still needs as [raw blocks](#raw-blocks). Only a block whose bytes don't hash to its CID is a verification failure.
- **An early end:** the spec lets a gateway end the stream when it loses a child block, and recent boxo appends a marker that breaks the framing. Either way the walk is unfinished: a piece failure, a truncation if the head was sent.
- **A directory URL** costs a second CAR: once the core has the directory and finds `index.html` in it, it asks for that file by its CID (`/ipfs/<cid of index.html>?format=car&dag-scope=entity`), with no path to resolve again.

### Raw blocks

- **What the core asks:** `GET /ipfs/<cid>?format=raw` with `Accept: application/vnd.ipld.raw`, and never `Range`: a partial block can't be checked, and boxo would serve one.
- **When:** for every block when the gateway has no ordered CAR support ([Modes](#modes)), and for the rest of a walk whose CAR stopped being useful.
- **Why it is always there:** raw blocks are the only response type the trustless spec requires of a gateway. A gateway that serves them can always be verified, if slowly.
- **Cost:** one request per block, up to 8 at once per request; with Kubo's default 256 KiB chunks, four per MiB, and one per path segment or HAMT level before the first byte.
- **Memory:** a raw leaf is reserved at its `blocksizes` entry, which its length must equal; any other block at 2 MiB, until it arrives.

### The IPFS walk

For `ipfs://<cid><path>`, with `GatewayCore`'s rules:

1. **The path:** segments decoded and checked as `GatewayCore` decodes and checks them (a `.` or `..` segment is a 400), then resolved from the root, one directory or HAMT at a time.
2. **A missing name in a verified directory** is a proven 404. A gateway that follows boxo sends the CAR up to the parent and stops; the core sees the parent and the name's absence. A 404 status from the gateway, without the parent, is the gateway's word.
3. **A directory:**
   - its `index.html`, when it has one, served as a file whose type comes from the name `index.html`;
   - otherwise `GatewayCore`'s HTML listing, from the directory's links (every shard of a HAMT, which `dag-scope=entity` includes), sizes from the links' `Tsize`, sorted by name.
4. **A file:** its length is `filesize`; then its content, depth-first, as blocks arrive and pass.
5. **HEAD** stops after the file's root, or after its first 513 bytes when the type must be sniffed ([Heads](#heads)).

### IPNS and DNSLink

- **A name with an Ed25519 key** (its key inlined in the name) gets a verify plan:
  - the core asks `GET /ipns/<name>?format=ipns-record` with `Accept: application/vnd.ipfs.ipns-record`, at most 10 KiB;
  - it checks the record as freedom-ipfs's `verify_ipns_record` does (`freedom-ipfs-namesys/src/lib.rs:586`–`649`), with [bounded decoding](#bounded-decoding): the key matches the name, `signatureV2` over `"ipns-signature:" ‖ data` verifies, the DAG-CBOR data parses, the validity type is EOL and the EOL is after now, and the value starts with `/ipfs/` or `/ipns/`;
  - **V2-only records are accepted.** The legacy V1 fields are optional; when present, they must equal the signed ones. Unknown fields in the entry and unknown keys in the signed data are skipped, not refused, as the IPNS record specification allows;
  - the value's path, then the request's path, are walked as above. A value naming another Ed25519-keyed name is followed the same way, at most 4 times in all (`GatewayCore`'s limit on DNSLink chains); one naming a DNSLink or an RSA-keyed name is `unverifiable`.
  - The label is `latest_asserted`: a gateway can serve an older record that hasn't expired yet.
  - **The core keeps a floor in memory:** the highest sequence it has verified per name and partition. A record below the floor is refused while the floor's record is still valid.
    - **Bounds:** at most 1,024 names, least recently used out first. An evicted name has no floor until its next record, so the protection is best-effort, and lost on a restart.
    - **Concurrent requests:** the floor only rises, atomically, to the highest sequence verified. A request that verified its record before a higher one arrived keeps the record it verified; only records checked after the rise are held to it.
    - This narrows rollback within a session; it proves nothing across restarts.
  - **"Now"** is the core's wall clock, passed into the logic crates as a parameter (AGENTS.md rule 2).
- **Names with other keys** (RSA, which needs the record's `pubKey` and an RSA verifier the core doesn't link) and **DNSLink names** (`ipns://example.com`, whose root comes from DNS) get today's fetch plan and the `unverified` label.
  - `dweb.open` decides this from the name itself, so no node can steer a request out of verified mode.
  - Supporting RSA-keyed names is an [open question](#open-questions).

### Gateways in practice

Reported by the research for this design on 2026-10-13, from code and from probes made from one location; unverified elsewhere:
- **Kubo** has served raw blocks and CARs since 0.13, `dag-scope` and `entity-bytes` since 0.21, and `order` and `dups` since 0.22. It answers `dups=n` unless asked for `dups=y`. A local Kubo serves all of it on `127.0.0.1:8080` by default.
- **Public gateways:** ipfs.io and dweb.link were reported retired on 2026-09-21, and trustless-gateway.link was down when probed. Pinata's gateway and ipfs.aleph.cloud honoured `dag-scope` and `entity-bytes`; Filebase and 4everland served raw blocks and CARs but ignored those parameters.
- **So the core never relies on a CAR's shape:** it uses CARs where they help and falls back to raw blocks where they don't.

## Responses

### Heads

The core builds every head from verified data, by the bundled node's rules. The vectors record the bundled node's answers header by header, and the core must reproduce them.

- **`bzz:`, Ant v0.5.64's rules** (`ag/retrieval.rs`, `ant-p2p/src/behaviour.rs`), with Ant configured as Freedom configures it:
  - **`Content-Type`:** the entry's `Content-Type` metadata as written, or `application/octet-stream`. Ant doesn't sniff.
  - **`Content-Disposition`:** `inline; filename="<name>"`, from the `Filename` metadata or else the path's last segment, with `\` and `"` escaped.
  - **`ETag`:** `"<the resolved file reference in hex>"`, feeds included.
  - **`Cache-Control`:** `public, max-age=31536000, immutable`, or `no-cache` when a feed was crossed.
  - **`Accept-Ranges: bytes`** on a GET; **`Content-Length`**; `Content-Range` on a 206.
  - **Redirects:** a 308 whose `Location` is Ant's: `/bzz/<root>/<path>/` followed by the plan's `query`. Main's `canonicalize_redirect` rewrites it as it rewrites Ant's today, so `bzz://<root>/docs?state=1` is redirected to `./docs/?state=1`.
  - **Not found:** a 404 with Ant's JSON body; an error document is served with 200, as Ant serves it.
  - **No conditional requests:** Ant ignores `If-None-Match` and `If-Range`, and so does the core for `bzz:`.
- **`ipfs:` and `ipns:`, `GatewayCore`'s rules** (`freedom-ipfs-gateway/src/lib.rs`):
  - **`Content-Type`:** `mime_guess` by the served path's extension. Without one, the first bytes are sniffed: up to 513, only when there is no range or it starts at 0. Content that begins, after a byte-order mark and whitespace, with `<!doctype html`, `<html`, `<head` or `<body` in any case is `text/html`; anything else is `application/octet-stream` (`lib.rs:1350`–`1437`). The core links the `mime_guess` release freedom-ipfs locks, so the tables agree.
  - **`ETag`:** `"fi1:<root CID>:<served path, or .>:<length>"`, strong (`lib.rs:3289`–`3296`).
  - **`Cache-Control`:** `public, max-age=31536000, immutable` under `/ipfs/`; `no-cache` through an IPNS name.
  - **`Accept-Ranges: bytes`** and **`Content-Length`**; `Content-Range` on a 206.
  - **Listings:** `text/html; charset=utf-8`, with no `ETag` or `Cache-Control`; a range on a listing is a 400.
  - **`If-None-Match`** (`*`, an exact tag, or a weak one) gives a 304 with the `ETag` and `Cache-Control`, only when there is no range.
  - **Not sent,** as `GatewayCore` sends none: `X-Ipfs-Path`, `X-Ipfs-Roots`, `Content-Disposition`. The query isn't read.
  - **Errors the core proves** (a missing name, a `..` segment, a node that isn't a file or directory) carry `GatewayCore`'s status and HTML body.
- **Not reproduced:** headers that describe the node rather than the content, if a vector shows any, are dropped and listed with the vectors. None has been found in Ant's handler.
- **What a reused Bee or a Kubo answered differently** (Bee sniffs types and sends no `Cache-Control`, Kubo writes its own listings and `X-Ipfs-*` headers) no longer shows: deviation `verified-heads`.

### Ranges and conditionals

- **One range** (`bytes=a-b`, `a-`, `-n`) is read as the bundled node reads it: 206 with `Content-Range: bytes a-b/size`; when unsatisfiable, 416, with `Content-Range: bytes */size` from Ant and without one from `GatewayCore`.
- **The fetch is narrowed to the range:** leaf-aligned `/bytes` for Swarm ([Leaves](#leaves)); `entity-bytes`, or only the covering blocks as raw blocks, for IPFS ([The CAR request](#the-car-request)). A seek never reads from the start of the file, unless a proxy drops the range or a gateway ignores `entity-bytes` (then the CAR is dropped for raw blocks).
- **Several ranges:**
  - Ant answers `multipart/byteranges` built from the whole body. The core answers 200 with the whole body instead, as a server may (deviation `multi-range`).
  - `GatewayCore` answers 400, and so does the core.
  - Chromium's media stack sends single ranges.
- **HEAD** answers the GET's head with no body. Ant ignores `Range` on a HEAD, and so does the core for `bzz:`.
- **Conditionals:** `If-None-Match` for IPFS, as above; nothing for `bzz:`, and no `If-Range` for either, as the bundled nodes handle none. The core's `ETag` is strong and derived from verified data, so a 304 is as certain as the content.

## Modes and labels

### Modes

| Backend | Verified mode | Content label |
|---|---|---|
| bundled Ant; native IPFS node | none: they check what they retrieve | `node_asserted`, as today |
| external or reused Ant, verification on | a 64-hex reference, or a name's Swarm contenthash | `verified` |
| | a 128-hex (encrypted) reference | `verified`, on the slow path ([Encrypted references](#encrypted-references)) |
| | a feed manifest anywhere on the path | `latest_asserted` |
| external gateway, verification on and supported | a CID, or a name's IPFS contenthash | `verified` |
| | an IPNS name with an Ed25519 key, directly or as a name's contenthash | `latest_asserted` |
| | a DNSLink name, or an IPNS name with an RSA key | `unverified`: today's fetch plan, decided by the name |
| any external backend, verification off | today's fetch plan | `unverified` |
| external gateway without trustless support | today's fetch plan | `unverified`, and the nodes panel says why |

- **The setting:** per profile and per external backend, "Verify content from this node", in the node's settings beside its endpoint. On by default is the recommendation; the default is the user's decision ([Open questions](#open-questions)).
- **Support is probed once, at activation,** not per request:
  - **The gateway,** after today's `bafkqaaa` probe, two more requests for the same empty identity CID, which needs no retrieval, so each answers at once:
    - `?format=raw` with the raw `Accept`: a 200 of type `application/vnd.ipld.raw` means the gateway can be verified at all;
    - `?format=car&dag-scope=entity` with the CAR `Accept` above: a 200 of type `application/vnd.ipld.car` with `order=dfs` and `dups=y` means CARs are worth asking for. Without it, every block is fetched raw.

    A gateway that fails the first serves `unverified`, and the nodes panel says "This gateway doesn't serve verifiable responses". A probe can't show whether a gateway honours `entity-bytes`; the [CAR request](#the-car-request) copes when one doesn't.
  - **Ant:** no probe. Bee's API, which Ant follows, always serves `/chunks` and `/bytes`, and Bee 2.8 has no restricted mode. A `HEAD /chunks/…` on Ant retrieves from the network, so it would be no cheap probe anyway (`ag/retrieval.rs:307`–`403`). A node that refuses those paths fails each verified request with its own status.
  - The result is fixed for the backend's activation and is part of the backend main captures. A gateway that later stops answering trustless requests fails them; nothing falls back to an unverified fetch per request, which a hostile node could otherwise trigger at will.
- **No new setting for the bundled nodes.**

### Labels

- **`trust.content` values:**
  - **`verified`:** every byte checked against the root the URL or the name names.
  - **`latest_asserted`:** checked against an update its owner signed (a feed's single-owner chunk, an IPNS record); that the update is the latest is the node's word.
  - **`node_asserted`:** the bundled nodes, which check what they retrieve themselves.
  - **`unverified`:** verification is off or unsupported, or the name can't be verified (DNSLink, RSA-keyed IPNS).
- **Where it is decided:** the plan carries `verified`, the mode's promise. The head carries the final label: a walk that crosses a feed or an IPNS record lowers it to `latest_asserted`. Main keeps the head's label for the navigation.
- **Where it is shown** (0006's open question 5): the address bar's trust panel, which today shows a name's trust in rows (`navigation-utils.js`), gains a content row for `bzz:`, `ipfs:` and `ipns:` pages. Proposed wording, the user's to change:
  - `verified`: "Content verified by Freedom";
  - `latest_asserted`: "Content verified; latest version as reported by your node";
  - `node_asserted`: "Content retrieved by Freedom's node";
  - `unverified`: "Content not verified: served by your external node as is".
- **Subresources** get their own label but don't change the tab's; a subresource that fails verification fails or truncates, and its failure is logged with a fixed code.

## Failures

**Before the head,** the page gets a JSON body `{ code, message }` with the status as `code`, as 0006's error plans do. The body is the core's; the node's error body never passes.

| Cause | Status | Message |
|---|---|---|
| a chunk, block, manifest node, directory, CAR or record fails its check | 502 | `Swarm content verification failed` / `IPFS content verification failed` |
| content the core can't check: an unsupported hash function, codec or node type; a single-owner chunk off the feed path; a Swarm leaf shorter than its logical length; a manifest node over 1 MiB; structure past the decoders' caps; a walk past its [bounds](#bounds) or its request's memory | 502 | `This content can't be verified with the external Swarm node` / `… IPFS gateway` |
| content that passes its hashes but is inconsistent: a UnixFS file whose sizes disagree (deviation `unixfs-sizes`) | 502 | `This IPFS content is malformed` |
| the path isn't in a verified manifest or directory | 404, through the bundled node's rules ([Heads](#heads)) | the bundled node's |
| a piece's final answer is 404 | 404 | `Not found on the external Swarm node` / `… IPFS gateway` (node-asserted) |
| a piece's final answer is another 4xx or 5xx | that status | `The external Swarm node answered <status>` / `… IPFS gateway …` |
| a piece's dial failed | as today: 503 or 502 for Ant, 502 for the gateway (`failure::after_dial`) | today's |
| the dweb thread is full, or memory can't be reserved in time | 503 | `Too many requests`, as a `busy` from `dweb.open` reads today |
| no head within `deadline_ms` | 504 | `Deadline passed` |

**After the head,** the body is truncated: the core sends `abort { code, message }`, and main errors the body, as a node's mid-body failure is surfaced today (0006). The codes are `verification_failed`, `unverifiable`, `malformed`, `piece_failed`, `busy` and `cancelled`.

- **What the page has received** is a prefix of the right content: every byte of it came from a chunk or block that passed its check before any of its bytes were released.
  - **The prefix may end anywhere,** inside a checked chunk or block too. A verified block is released in frames as credit allows, and 0007's `abort` purges what is still queued in the core and in main's ring, so the page can see part of a block that passed. The guarantee is about which bytes are released, not where the release stops.
  - **Why not deliver blocks whole:** holding back a checked block until all of it fits the window would need up to 2 MiB of extra credit per stream, and a cancel would still have to purge. Partial delivery of checked bytes loses nothing the guarantee needs.
  - Chromium treats the resource as truncated: a script or image fails, a navigation shows what it had rendered, and a download fails as interrupted.
- **Logging:** a fixed code, the backend's mode and the piece's kind (chunk, stream, CAR, record), never a reference or a path in a private window.
- **The nodes panel** counts verification failures per backend and shows "Your external node served content that failed verification" while any occurred in the last 10 minutes. Whether repeated failures should stop using the node is the user's decision ([Open questions](#open-questions)).

## Main's side

- **`plan-validation.js`:** the `{ verify }` variant, with `fc-dweb`'s vectors.
- **`dweb-handler.js`:** a `{ verify }` plan takes a fetch admission slot, then calls `dweb.verify` through the core client. The head becomes a `Response` after the response operations; its body reads the stream's ring through the body idle wrapper (`idleBoundBody`), whose `onEnd` releases the slot.
- **A verified head is not a gateway response.** `strip_decoded_encoding` exists because the transport has already decoded a gateway's body, so its `Content-Length` and `Content-Encoding` are wrong. A head from the core describes exactly the bytes the core will send. So main picks the operations by the head's source, not by the backend:
  - a core head gets the plan's operations and `strip_page_state`, and never `strip_decoded_encoding`, so its `Content-Length` stays;
  - `small_text` runs for an IPFS GET navigation, as on the native node's answers, which needs that `Content-Length`.

  Handler tests send core heads through main's real response helper and check both.
- **`dweb-shell.js`** (new), registered beside `naming-shell.js` and `chain-shell.js`: it executes `shell.dweb_get`.
  - It checks `for`, the path form and the headers before any dial, and answers a refusal with `invalid_argument`, logged as a core fault.
  - It dials with the plan executor's retry loop and the backend's `request()`, so loopback undici, the session's stack for a remote Ant or gateway, the onion refusal and the Ant guard's announcement all apply unchanged.
  - A whole piece is read up to `max_bytes`; more is `failed: "too_large"`. A streamed piece is pulled only as the core's credit allows.
  - Every terminal path frees the piece's dial and buffers: its end, the core's cancel, the `dweb.verify` request ending, the session closing.
- **`frame.js` and `core-client.js`:** stream frames in both directions on the core's connection ([Streams](#streams-in-the-core)), with 0007's rings for the bodies main receives.
- **`ant-manager.js` and `ipfs-manager.js`:** the setting, the probe, and `verify` in the captured backend. A reused Ant counts as external, as `antBackend()` reports it today, so it verifies too.
- **The trust panel and the nodes panel** in the renderer ([Labels](#labels), [Failures](#failures)).
- **The core's cache:** when a private partition closes, main sends `dweb.forget { partition }`, and the core drops the partition's [structure cache](#the-structure-cache) and IPNS floors.
- **In-process callers** (`permission-manifests.js`, `http-fetch.js`, downloads) go through the same handlers, so they get verified content too: Swarm permission manifests among them. `ens-prefetch.js` keeps warming the node as today; nothing verified depends on it.

## Performance

### Measured

Hashing, in release builds on the development server this design was written on (4 cores of an AMD EPYC Genoa VM, shared with other builds, at a load average of 6 to 10; 64 MiB of input; the range over five runs):

| Work | Throughput, one thread |
|---|---|
| a Swarm leaf's address (`fc_swarm::chunk_address`, 4 KiB leaves) | 40–59 MiB/s |
| the same, with an in-place BMT that allocates nothing | 39–74 MiB/s |
| SHA-256 (`sha2`, with the CPU's SHA extensions), 256 KiB blocks | 0.7–1.6 GiB/s |
| SHA-256, 1 MiB blocks | 1.1–1.5 GiB/s |

- **So a Swarm leaf costs 55–100 µs to check,** 127 keccak hashes of 64 bytes for the tree and one for the address. That is the bound on verified Swarm throughput: 40–74 MiB/s per hashing thread, and an estimated 80–150 MiB/s with the pool's two, if they scale.
- **IPFS's hashing is not a bound.** The CAR's parsing and copying, and the pipe, are (unmeasured).

### Estimates

- **Requests:**
  - **Swarm:** a page's walk costs one chunk per manifest node on the path (two to four for typical sites, an estimate), plus the file's root; then the level-1 intermediate chunks below, and one `/bytes` stream. The structure cache makes a site's second and later subresources cost one or two chunks each.

    | Tree | Data references per intermediate chunk | Level-1 chunks per MiB of body |
    |---|---|---|
    | plain | 128 | 2.0 |
    | erasure coding level 1, the upload default in Ant and Bee | 119 | 2.2 |
    | level 2 / level 3 | 107 / 97 | 2.4 / 2.6 |
    | level 4 | 39 | 6.6 |
    | encrypted | 64 | 4.0, and every leaf as a chunk ([Encrypted references](#encrypted-references)) |

    Higher levels add a chunk per MiB at the next level up too, which is small beside these.
  - **IPFS:** one CAR per request; two for a directory URL served by its `index.html`. On raw blocks, one request per path segment and HAMT level, then one per block, up to 8 at once.
- **Time to first byte,** over today's for the same request:
  - **Swarm, loopback node, chunks cached in the node:** four to seven sequential chunk requests before the first leaf, each well under a millisecond on loopback: a few milliseconds at p50 (an estimate).
  - **Swarm, remote node:** four to seven round trips more than today, since today the node walks the manifest itself. On a 50 ms path, 200–350 ms (an estimate). The structure cache removes most of it after a site's first request.
  - **IPFS, through a CAR:** the first block arrives whole before its first byte is released: at most 2 MiB, usually 256 KiB (Kubo's default chunker; any given content may differ). On a 10 MB/s link, about 25 ms for a 256 KiB block (an estimate).
  - **IPFS, on raw blocks:** one round trip per path segment and HAMT level before the file's root, then the first block's.
- **Throughput:** bounded by hashing for Swarm (above); for IPFS by main's copies and the pipe through a CAR, and by round trips on raw blocks (8 blocks in flight).
- **CPU:** up to two cores while verified bodies stream at full speed. A video at 5 Mbit/s costs about 0.8–1.5 % of one hashing core (an estimate from the measured leaf cost).
- **These are per-step figures, not an end-to-end measurement.** Pipe copies, parsing, main's garbage collection, remote round trips and queueing at 50 and 200 requests are what the [gates](#gates) measure.
- **Memory:** within [Bounds](#bounds); a running request holds about 300 KiB for Swarm, and for IPFS one block (usually 256 KiB, at most 2 MiB) through a CAR or up to 8 MiB of raw blocks in flight.

### Gates

Measured before the default switches, on linux-x64, macOS arm64 and win-x64, verified against unverified on the same node:
- **Swarm, loopback Ant, cached content:** a 1 KB file, a 10 MiB file and a seek into it, at 1, 50 and 200 concurrent requests, for a plain tree, erasure coding at levels 1 and 4, and an encrypted reference. For plain and level-1 trees, verified time to first byte within 10 ms of unverified at p50 one at a time, and throughput of at least 40 MiB/s for the 10 MiB file. Level 4 and encrypted references are measured and reported against those figures.
- **IPFS, loopback Kubo:** the same shapes. Verified throughput at least 80 % of unverified.
- **The vault under load:** with 64 verified bodies streaming at full speed, a `vault.lock` is acknowledged within 50 ms at p99.
- **A real page load** of a Swarm site and an IPFS site, verified against unverified, in Chromium.

If a gate fails, the [open questions](#open-questions) on the default and on the service alternative are revisited with the numbers.

## Tests first

As 0006's 4.7 did, the tests land before the code. Every case pins its failure stage and code, the fixed message, the exact prefix of body bytes released, and the request's reservations back at zero; a case that only checks a hash passing isn't enough.

- **Format vectors** (`vectors/dweb-verify.json`), from the pinned nodes, not from the JavaScript reference: verification reads no user data, and the formats belong to Ant, Bee and IPFS.
  - **The generator:**
    - it drives a pinned Ant and a pinned Kubo on loopback, seeded with the fixtures and cut off from their networks, and runs freedom-ipfs's `GatewayCore` over a memory store seeded the same way (0007's test hooks);
    - it records every exchange, and the core's tests replay them with no node running;
    - **everything that varies is pinned:** the exact Kubo release and the other versions are in the file's `meta`; the clock is fixed, which sets IPNS validity and feed timestamps; and every random input (encryption keys and padding, obfuscation keys, IPNS keys) comes from a seed recorded with the case. The core's tests pass the same `now`.
  - **Swarm,** recorded from Ant v0.5.64's splitter and manifest writer, and cross-checked against Bee's for the formats Bee also writes:
    - files of 0, 1, 4095, 4096, 4097, 524,288, 524,289 and 67,108,865 bytes, from a single chunk to three levels of intermediate chunks;
    - each with erasure coding at every redundancy level, and encrypted;
    - manifests with an index document, an error document, nested paths, a path that is a prefix of another, prefixes longer than one fork can hold, Unicode names, every metadata field Ant reads, an obfuscated node, and an empty node with a zero reference size;
    - a sequence feed with several updates, v1 and v2, and its manifest;
    - for each, every chunk by address, and Ant's answers to a request list (`/bzz/<ref>/<path>` with and without a query, `Range`, `If-Range`, `If-None-Match` and `HEAD`): status, headers and body.
  - **Swarm shapes Ant accepts that a simple reader wouldn't,** recorded from Ant too:
    - a last leaf whose authentic payload is longer than the logical length its parent gives it (the surplus-payload tail). Ant serves the logical prefix, and so must the core;
    - a leaf whose span field differs from its logical length.
- **IPFS: two kinds of expectation, kept apart.**
  - **Native-generated:** recorded from Kubo, for the gateway's CARs and raw blocks, and from `GatewayCore`, for the answers, over the same blocks. The core must reproduce `GatewayCore`'s answers exactly. They cover:
    - files of 0, 1, 262,143, 262,144, 262,145 and 10 MiB, as CIDv0 with dag-pb leaves and CIDv1 with raw leaves, balanced and trickle;
    - directories with and without `index.html`, a HAMT-sharded directory, Unicode names, an identity CID;
    - for each request shape, the CAR Kubo sends (path, `dag-scope=entity`, `entity-bytes`) and the raw blocks;
    - IPNS records: V2-only and with legacy fields, with unknown fields and unknown signed keys, expired, for another key, without `signatureV2`, and with a legacy value that differs from the signed one.
  - **The verifier's own,** marked `deviation` in the file as 0006's are, where the design deliberately differs from the pinned native reader:
    - `unixfs-sizes`: a file whose declared child size disagrees with its raw leaf, and one whose content doesn't add up to `filesize`. The native reader slices by the declared size; the core cuts the body as malformed at that point;
    - `hamt-lookup`: an entry that isn't where its hash and the bitfield point. The native reader finds it by name; the core answers 404.
- **Adversarial vectors,** the design's own: each takes an honest exchange and changes one thing, and states the outcome.
  - **Swarm:**
    - a bit flipped in a leaf, an intermediate chunk, a manifest node, an encrypted chunk and a feed update;
    - a leaf whose authentic payload is shorter than its logical length (`unverifiable`);
    - a chunk over its size limit;
    - a feed update signed by another owner, or at another index;
    - **SOCs off the feed path:** a root, a manifest child and a file's intermediate chunk that are valid SOCs, including two different SOCs one owner signed at the same address. Each is `unverifiable`, and nothing from it is released or cached. A feed update, by contrast, is accepted, labelled `latest_asserted` and sent with `no-cache`.
  - **Swarm ranges:**
    - an exact 206 that is short, or names another interval;
    - a 200 with the whole file for a partial range, whose valid suffix past the needed leaves is not read and is no failure;
    - a 200 that is short, or that holds the range's bytes at offset 0;
    - a source that stalls after the needed prefix (no effect, since the piece is already cancelled) and one that stalls before it (body idle).
  - **IPFS, lies:** a bit flipped in a path block, a HAMT shard, a file node and a leaf; a raw block that isn't its CID's; a block over 2 MiB; a section length past the block limit; an over-long varint; a malformed header; an identity CID whose digest isn't its data; an IPNS record for another key, expired, or below the session's sequence floor.
  - **IPFS, unhelpful but honest:** a CAR that ignores `entity-bytes` and sends the whole DAG; one ordered otherwise, or without duplicates; one that reads the path differently; one that ends early with boxo's marker. Each must still give the right body, through raw blocks, or a piece failure for the early end. Also `blake3`, which is `unverifiable`.
  - **Within the wire caps, against the decoders** ([Bounded decoding](#bounded-decoding)). Each input is within every byte limit, yet would amplify allocation or nesting in a naive decoder. Each must end with its stated failure, or its correct answer, with reservations never above the request's budget:
    - a maximal block of minimal repeated fields, for dag-pb links and for UnixFS `blocksizes`;
    - a maximal block of unknown fields;
    - a directory of as many entries as a block holds, served as a listing;
    - a CAR header and an IPNS record's signed data nested to the depth bound and one past it, and declaring lengths past the bytes remaining;
    - a mantaray node with maximal fork metadata and a deeply nested metadata value.
  - **Both:** the node's error body is never released; no byte of a chunk or block that failed its check reaches the page.
- **Machine tests** (`fc-dweb`, sans-I/O):
  - scripted pieces in every order the protocol allows; cancellation at every step; budgets exhausted at every reservation;
  - ranges at every leaf and block boundary; `HEAD`; `If-None-Match`; `If-Range` ignored as the bundled nodes ignore it;
  - **truncation:** a failure, a cancel and a core restart after part of a verified block was released, and while verified output is queued. The page gets a prefix of verified bytes, possibly inside the block, then the error;
  - **IPNS floors:** eviction at 1,024 names, and concurrent requests verifying records of different sequences;
  - **the structure cache:** an encrypted tree's ciphertext reused under the right key, and nothing from it under another key at the same address;
  - **late results after `dweb.forget`:** a piece reply, a hashing result and a floor update for the forgotten partition leave no entry behind.
- **Stream tests** (`fc-protocol`, and through the binary): both directions on one connection, the global bound, data beyond credit, late credit, and a `vault.lock` behind 128 full incoming windows, acknowledged on time.
- **freedom-browser:**
  - the real-handler harness (0006) gains a fake Ant that serves `/chunks`, `/bytes` with `Range` and `/feeds`, and a fake trustless gateway, each honest or lying per case;
  - 0006's Range, seek, cancel, backpressure and truncation cases run again in verified mode;
  - **piece validation:** every `shell.dweb_get` path form, with namespace and path violations, refused before any dial;
  - **heads:** core heads through main's real response helper keep their `Content-Length`, and an IPFS navigation gets `small_text`;
  - **redirects:** `bzz://<root>/docs?state=1` for a directory answers 308 to `./docs/?state=1`;
  - **rings:** four batches of 64 small verified bodies completed but never read. The core finishes each batch and admits the next; main holds 256 rings and no more, the next fetch waits in admission, and reading or cancelling the bodies frees them;
  - a core restart mid-body truncates; a private partition's cache and floors are dropped on close; the probes (raw and CAR, raw only, neither); the labels.
- **Live:** the `e2e-ant` job gains an external-mode run with verification on, and a Kubo gateway job does the same for IPFS.

## Bounds

| Budget | Bound | Exhausted |
|---|---|---|
| running / waiting `dweb.verify` | 64 / 256 | `busy`: main answers 503 |
| time to the head | `deadline_ms`, 360 s | 504 |
| pieces in flight, per request; outstanding `shell.dweb_get`, all requests | 8; 256 | the machine waits for one to end; the piece waits in the dweb thread's FIFO |
| incoming streams with credit, all requests | 128 | the request waits for one to end |
| a whole piece; a raw block | 64 KiB; 2 MiB | `failed: "too_large"`, a verification failure |
| a piece reply's headers | 8, each ≤ 8 KiB | a malformed reply: the piece fails, logged as a fault in main |
| stream window, each direction | 128 KiB; data frames ≤ 64 KiB | the sender waits for credit |
| node bytes in flight to the core | 128 streams × 128 KiB = 16 MiB | not reachable: credit |
| rings in main | one per admitted fetch's body, verified or from 0007's service, kept until drained or cancelled: 256 × 128 KiB = 32 MiB | not reachable: fetch admission (256 active, 512 waiting, then 503) |
| the dweb writer | 8 MiB of unwritten data | the machines wait for credit |
| memory, per request | 8 MiB, reserved before allocation: its windows, leaves and blocks in flight, the walk's parsed nodes | fewer pieces in flight; a walk that can't fit at all is `unverifiable` |
| memory, the dweb thread | 128 MiB in all, the structure cache included | new requests `busy` (503); admitted work waits up to 10 s, then ends `busy`: 503 before the head, a truncation after |
| the structure cache | 8 MiB, keyed by partition | least recently used first |
| an IPFS block | 2 MiB (freedom-ipfs's limit) | `verification_failed` |
| a Swarm manifest node | 1 MiB (Ant: 32 MiB) | `unverifiable` |
| Swarm walk | 8 levels of intermediate chunks (Bee's cap); 64 manifest nodes per lookup; one feed per walk | `unverifiable` |
| IPFS walk | 64 levels of file DAG; 8 HAMT levels per name (fanout 256); 256 path segments; 4 IPNS hops | `unverifiable` |
| a CAR header; a CAR section | 64 KiB; 2 MiB plus the CID | `verification_failed` |
| decoded structure | 65,536 links per dag-pb node; CBOR nested 8 levels; 256 forks per mantaray node | `unverifiable` |
| an IPNS record | 10 KiB | `verification_failed` |
| IPNS sequence floors | 1,024 names, in memory | least recently used first |
| hashing pool | 2 threads | jobs queue in the dweb thread, under the request's memory |

## Upstream

- **Reusing Ant's crates** (MIT OR Apache-2.0, which `deny.toml` allows from freedom-hq):
  - `ant-crypto` is sans-I/O (k256, sha3, getrandom, thiserror) and has BMT, CAC, SOC and decryption. But it pins k256 0.13 where the core uses 0.14, and `fc-swarm` already has BMT. So `fc-swarm` implements the checks itself and tests them against `ant-crypto` as a dev-dependency.
  - `ant-retrieval`'s joiner, mantaray and feed code is async over tokio, and its parsers are private (`Node::unmarshal`, `parse_intermediate`). `fc-swarm` reimplements them as sans-I/O state, held to vectors from Ant.
- **Ant:** nothing is required. A batch chunk read (several addresses per request), or a ranged read that carries each leaf's chunk path, would cut the walk's round trips. Neither is proposed until the [gates](#gates) show the walk costs users time.
- **freedom-ipfs:**
  - **`fc-ipfs` carries its own bounded decoders** ([Bounded decoding](#bounded-decoding)). The native ones (`freedom-ipfs-unixfs/src/lib.rs:42`–`85`, `1100`–`1110`) are private, and they allocate while decoding, so they couldn't run under the core's reservations even if they were public.
  - Whether the native node should adopt a bounded reader shared with `fc-ipfs`, so both modes read the same way by construction, is an [open question](#open-questions).
- **What `fc-ipfs` takes from freedom-ipfs:** `freedom-ipfs-core`'s `verify_block` and block limit, by a git dependency pinned to v0.4.5 (allowed from solardev-xyz). Not its whole-buffer CAR parser: the core reads CARs as streams. Not `freedom-ipfs-unixfs`'s resolver, which pulls blocks through a synchronous provider, and so can't suspend while main fetches.

## Parity

- **Unverified mode is today's,** byte for byte: verification off, a gateway without support, and every bundled backend plan exactly as 0006 does.
- **A verified response is the bundled node's,** not the external node's: what Ant v0.5.64 answers for `bzz:`, and what freedom-ipfs v0.4.5's `GatewayCore` answers for `ipfs:` and `ipns:`, over the same content. The vectors hold the core to it, header by header, with the exceptions listed in [Heads](#heads).
- **Qualified: for content both accept.** Where the verifier is deliberately stricter than the pinned reader, the difference is a listed deviation with vectors of its own, kept apart from the native-generated ones ([Tests first](#tests-first)):
  - `unixfs-sizes` and `hamt-lookup`, for malformed UnixFS files and HAMT directories;
  - `soc-references`, for single-owner chunks off the feed path;
  - `decoder-caps` and `manifest-node-cap`, for structure past the decoders' caps;
  - a Swarm leaf whose authentic payload is shorter than its logical length, which the core doesn't support.

  On well-formed content these never apply.
  - **Why the bundled node, not the external one:** the external node's headers are the assertions being replaced, and it may be a different implementation (a reused Bee, a Kubo, a public gateway). One rule per scheme, whatever the backend, is also what a user switching modes expects.
- **The same as today, per piece:** the request headers Swarm needs, the retry table and its delays, the header deadline, the body idle bound, the transport and its proxy and onion rules, the Ant guard, fetch admission, the dial failure statuses, and the security response operations.

## Deviations

| ID | Today | After | Effect |
|---|---|---|---|
| `verified-content` | an external node's answer passes whole | checked against the root; a mismatch is a 502 before the head, a truncation after it | a lying or broken node can't change what a page receives |
| `verified-heads` | the external node's headers, after the response operations | the core's, by the bundled node's rules | `Content-Type`, `ETag`, caching headers, listings and redirects follow Ant or `GatewayCore`; the external node's own headers go |
| `node-error-bodies` | a node's error body reaches the page | the core's fixed `{ code, message }`, with the node's status | the status stays; the text is the core's |
| `verified-requests` | one request to the node per page request | chunk, byte-stream and feed requests (Ant); CAR, raw block and record requests (gateway) | more requests reach the node, and its logs show chunk addresses and CIDs |
| `verified-latency` | the node walks the path | the core walks it, piece by piece | time to first byte rises by the walk's round trips ([Performance](#performance)) |
| `core-data-path` | a core restart fails only new plans | it also truncates verified bodies | |
| `verify-head-deadline` | no bound before the head beyond each attempt's (Ant) or none (the gateway) | 360 s to the head | a walk that can't finish in six minutes gets 504 |
| `gateway-probe` | `bafkqaaa` | then a raw and a CAR probe of it, when verification is on | a gateway without raw blocks serves unverified, and the nodes panel says so |
| `structure-cache` | the core holds no content | up to 8 MiB of verified Swarm structure, per partition | |
| `multi-range` | Ant answers several ranges with `multipart/byteranges` | 200 with the whole body | only clients that ask for several ranges see it |
| `manifest-node-cap` | Ant loads a manifest node of up to 32 MiB | 1 MiB | a manifest with a larger node is `unverifiable` |
| `encrypted-chunks` | the node decrypts a 128-hex reference's content and serves the plaintext | the core fetches the chunks and decrypts them | about 260 requests per MiB |
| `ipns-floor` | the gateway resolves an IPNS name as it likes | a record below the highest sequence verified in the session is refused while that one is valid | a gateway that rolls a name back within a session gets a 502 |
| `soc-references` | an external node may answer a reference with a single-owner chunk, and what it serves then rests on that chunk | the core accepts one only as a feed update; elsewhere it is `unverifiable` | content reached through a SOC outside a feed doesn't load in verified mode |
| `unixfs-sizes` | the native reader (the parity target) slices a child by its declared size | a declared size that disagrees with a raw leaf, or content that doesn't add up to `filesize`, cuts the body as malformed | only malformed files differ |
| `hamt-lookup` | the native reader finds a HAMT entry by its name | the core follows the name's hash and the bitfield | an entry that isn't where its hash points is a 404; only malformed directories differ |
| `decoder-caps` | the native reader decodes any structure a block holds | at most 65,536 links per dag-pb node, and CBOR nested at most 8 levels | only degenerate encodings are refused, as `unverifiable` |

## Implementation steps

1. **Tests first:** the generators and `vectors/dweb-verify.json`; the adversarial vectors; the fake Ant and fake trustless gateway in freedom-browser's harness.
2. **Formats, sans-I/O:**
   - `fc-evm`: signature recovery, for single-owner chunks;
   - `fc-swarm`: chunk and SOC checks (the empty chunk included; SOCs only where a feed update is expected), intermediate chunks with erasure coding, logical leaf lengths from the parent, encrypted chunks, mantaray nodes and lookup (empty nodes included), feed identifiers;
   - `fc-ipfs` (new, logic): CIDs and the native node's block check; the bounded protobuf and CBOR readers, with their counting first pass; a streaming CAR reader; dag-pb and UnixFS with the stricter size rules; hash-directed HAMT lookup; offsets; IPNS records, V2-only included;
   - **new dependencies,** each justified in its PR (AGENTS.md rule 7): `freedom-ipfs-core` (git, pinned to v0.4.5) and the `cid`, `multihash` and `unsigned-varint` crates it brings, which `freedom-mobile-ffi` already links through freedom-ipfs; `mime_guess` 2.0.5, for `GatewayCore`'s types; `ed25519-dalek`, already on the preferred list. MurmurHash3 and the DAG-CBOR subset an IPNS record needs are small enough to write, against vectors.
3. **`fc-dweb`:** verify plans (with their `query`) and their validation; the verifier machine, with its walks, heads, ranges (the exact-206 and whole-200 policies), conditionals and failures; the structure cache with its partition epochs; the IPNS floors.
4. **`fc-protocol`:** streams in both directions, protocol version 2 (on #72).
5. **`freedom-cored`:** the dweb thread and hashing pool, `dweb.verify`, `shell.dweb_get`, `dweb.forget`, admission, budgets and cancel, with tests through the binary.
6. **freedom-browser:** verify plans in validation and the handler, `dweb-shell.js`, stream frames on the core's connection, the setting and the probe, the labels and the nodes panel; then the [gates](#gates).
7. **The default** switches only after the gates pass and the user decides it.

## Open questions

1. **The default:** verification on for every external backend (recommended), or opt-in?
2. **A stricter mode:** should a profile be able to refuse unverified external content outright, as `blockUnverifiedEns` gates unverified names? Under it, DNSLink names, RSA-keyed IPNS names and gateways without raw blocks would stop loading.
3. **A node that fails verification:** keep using it and fail only the requests that fail (proposed), or stop using it after repeated failures until the user acts?
4. **Wording and place:** the trust panel's content row ([Labels](#labels)) and the error texts ([Failures](#failures)). Should a failed navigation get an error page instead of today's JSON body?
5. **The user's own node:** a loopback Bee or Kubo the user runs is often as trusted as the bundled node. Verify it anyway (proposed: the cost on loopback is small), or offer "trust this node"?
6. **The bundled nodes:** should the core also check their output, as defense in depth, at the cost above?
7. **DNSLink:** accept the `unverified` label, or have the core resolve DNSLink itself through DNS-over-HTTPS exchanges main performs, so the root comes from a resolver Freedom chooses rather than from the gateway?
8. **Encrypted references:** verify them chunk by chunk ([Encrypted references](#encrypted-references), about 260 requests per MiB), or leave 128-hex references `unverified` until Ant offers something better, such as a batch chunk endpoint?
9. **RSA-keyed IPNS names:** add an RSA verifier, or keep them `unverified`? The `rsa` crate would be a new dependency, and `cargo deny` may need a reviewed exception for its timing advisory (RUSTSEC-2023-0071), which concerns private-key operations, not verification. Whether the current release still carries the advisory, and how many names use RSA keys, are unverified.
10. **Private windows:** a structure cache per private partition (proposed), or none?
11. **Upstream:** `fc-ipfs` can't share the native decoders as they are, since they allocate before anything can be reserved. Should freedom-ipfs adopt a bounded reader shared with `fc-ipfs` (its decoders, and its stricter size and HAMT rules), so both modes read files and directories the same way by construction rather than differing on malformed content?
