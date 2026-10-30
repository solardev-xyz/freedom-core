# 0009: Verifying dweb content

**Status:** decided (the user, 2026-10-23): open questions 1–11, which [Decisions](#decisions) records. Roadmap Phase 4 (item 4.5). Builds on [0001](0001-freedom-cored.md) (framing; streams as protocol version 2), [0005](0005-chain-data.md) (requests the core makes, memory reserved before it is allocated), [0006](0006-dweb-transports.md) (plans, main's executor, trust labels, and the prerequisites in *Later designs*) and [0007](0007-ipfs-service.md) (stream frames, credit and rings).

**The references:**
- **freedom-browser** at `aebf5ec9` (`integration/rust-core`):
  - `dweb/dweb-handler.js`, `dweb/plan-executor.js`, `dweb/plan-validation.js` and `dweb/fetch-admission.js`;
  - `swarm/bzz-protocol.js` and `swarm/ant-api-main-dials.js`; `ant-manager.js` (`startExternalAnt` and reused daemons);
  - `ipfs/ipfs-protocol.js`, `ipfs/gateway-transport.js` and `ipfs-manager.js` (`ipfsBackend`, `requestExternalGateway`, `probeExternalGateway`);
  - `swarm/permission-manifests.js`, which reads manifests through the `bzz:` handler.
- **Ant** v0.5.71 (`910452d`, freedom-hq/ant), the release freedom-browser pins on `integration/rust-core` (`485819a9`). `ac`, `ar` and `ag` below are the `src/` directories of `ant-crypto`, `ant-retrieval` and `ant-gateway`.
- **Bee** at `a93fb7a7` (v2.8.2-rc1 and four commits), for the formats Ant reads and writes.
- **freedom-ipfs** v0.4.6 (`ee6b95c`), the native node 0007 moves into `freedom-ipfsd`: `freedom-ipfs-core`, `freedom-ipfs-unixfs` and `freedom-ipfs-gateway` (`GatewayCore`). The vectors record `GatewayCore` at `e7dcc6f`, the commit `freedom-ipfsd` pins: v0.4.6 with 0007's upstream changes, the native node Freedom ships.
- **IPFS specifications,** as published on 2026-10-13: the Trustless Gateway, CAR v1, UnixFS and IPNS Record specifications.
- **libp2p,** for RSA-keyed IPNS names: the peer-ID specification (libp2p/specs `peer-ids/peer-ids.md`, at `d2106f43`); go-libp2p v0.51.0 (`core/crypto/rsa_common.go` and `rsa_go.go`); and what freedom-ipfs v0.4.6 locks, `libp2p-identity` 0.2.13 (`src/rsa.rs`, `src/keypair.rs`, `src/peer_id.rs`) with ring 0.17.14.

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
  - **Encrypted (128-hex) references** keep today's unverified fetch, decided from the reference: checking one would take every chunk as its own request ([Encrypted references](#encrypted-references)).
- **IPFS:** the core asks the gateway for a trustless CAR of the path and the file, ordered depth-first with duplicates (`?format=car&dag-scope=entity`, `entity-bytes` for ranges). It checks each block against its CID as it arrives and walks the path, HAMT shards and the UnixFS DAG itself. Blocks are at most 2 MiB, as the native node allows, and are released whole.
  - **The CAR is only a block source.** When a gateway's CAR doesn't carry what the walk needs, in its order (some ignore `entity-bytes`; Kubo sends no duplicates unless asked), the core fetches the rest as raw blocks (`?format=raw`), the one response type every trustless gateway must serve.
  - **IPNS names** with an Ed25519 or an RSA key are verified against their signed records. RSA keys need an RSA verifier, which checks signatures only ([IPNS and DNSLink](#ipns-and-dnslink)).
  - **DNSLink names** keep today's unverified fetch: `dweb.open` decides it from the name, so no node can steer a request out of verified mode.
- **Heads come from the core,** built from verified data with the bundled node's rules: Ant's for `bzz:`, `GatewayCore`'s for `ipfs:`. Vectors recorded from those nodes pin them. Nothing the external node says reaches the page unchecked, error bodies included. What can't be proven is labelled or answered as the node's word: a "not found", the latest update of a feed or an IPNS name.
- **Failure:** a mismatch before the head is a 502, "Swarm content verification failed" or "IPFS content verification failed". After the head, the body is truncated: the page keeps a prefix of verified bytes, which may end inside a chunk or block that had passed its check. No unverified byte reaches Chromium.
  - A failed navigation shows an error page in plain words, not the JSON body.
  - A node that fails verification stays in use; only the requests that fail, fail.
- **Labels:** `verified`, `latest_asserted` (verified against an owner-signed update whose freshness is the node's word), `node_asserted` (the bundled nodes, unchanged) and `unverified`. The address bar's trust panel shows them.
- **Modes:**
  - Verification is a per-backend setting, on by default for every external backend, a node on the user's own machine included.
  - A gateway's support is probed when it is activated, and a backend never falls back to unverified per request.
  - A strict mode, a profile setting that is off by default, refuses unverified external content outright.
- **Budgets,** estimated, and measured before verification ships on by default. Measured hashing on the development server this design was written on: a 4 KiB Swarm leaf costs about 55–100 µs on one thread (40–74 MiB/s); SHA-256 runs at 0.7–1.6 GiB/s. Two hashing threads keep verified Swarm bodies above an estimated 80 MiB/s.
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
- **The bundled nodes.** The bundled Ant validates the chunks it retrieves, and the native IPFS node hash-checks blocks. Their content stays `node_asserted`; the core doesn't check it again ([Decisions](#decisions), 6).
- **Availability and privacy.** A node can still withhold content, answer "not found", or learn what the user reads. Verification proves integrity, not retrieval.
- **Freshness of mutable pointers.** A feed's or an IPNS name's latest update can't be proven; it is labelled ([Labels](#labels)).
- **Names.** Naming's trust (0004) covers the name; this design covers the content the name points at.
- **`rad:`, `radapi:` and `web3:`.** heartwood verifies refs against signed sigrefs (0008), and `chain.html` has its own trust (0006).
- **The `window.swarm` backend (4.6)** and uploads.
- **Caching content bytes.** Only verified structure is cached, briefly, and a private window's apart ([The structure cache](#the-structure-cache)).
- **Encrypted Swarm references** from external nodes, for now ([Encrypted references](#encrypted-references)).

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
- **Not checked at all,** and so labelled `unverified` with today's fetch:
  - **an encrypted Swarm reference** (128 hex): its plaintext can't be checked against its address, and checking its ciphertext would take every chunk as its own request ([Encrypted references](#encrypted-references));
  - **an IPNS name with an inlined key other than Ed25519** (secp256k1), which the native node doesn't verify either ([IPNS and DNSLink](#ipns-and-dnslink)).
- **Out of scope:** a compromised main, which Stage 1 trusts (0001), and a compromised core.

## Where verification runs

**The decision: the core verifies; main fetches and delivers.**

```
Chromium ◀─body── main ◀─verified body (stream)── freedom-cored
                   │                                  │ dweb thread: walk, check, build the head
                   │◀──── shell.dweb_get ─────────────┘ hashing pool: BMT, SHA-256, RSA
                   │───── node's answer (stream) ────▶
                   ▼
          external Ant or gateway (main's transport: undici on loopback, the session's stack otherwise)
```

- **Why the core:**
  - **It is the one Rust process always present.** In external modes no service runs: `freedom-ipfsd` serves the native node only (0007), and there is no Swarm service; the external Ant is the node.
  - **The logic belongs in the shared crates.** A sans-I/O verifier in `fc-dweb` is what the Chromium build's URL loaders and mobile can call in process, with the same vectors. On desktop, the core is where those crates run.
  - **0006 anticipated it:** "bytes through a verifier", over protocol version 2's streams, once the core checks them.
- **What it costs, and what bounds it:**
  - **Every verified byte crosses the pipe twice,** in and out. A pipe moves gigabytes per second; hashing moves tens to hundreds of megabytes ([Performance](#performance)), so hashing is the bound, not the pipe (an estimate, measured before verification ships on by default).
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

- **`backend`** (0006) gains two members for an external backend:
  - `verify: true`, when its verification is on and supported ([Modes](#modes));
  - `strict: true`, when the profile's [strict mode](#strict-mode) is on.

  For example `{ ant: "external", up, verify: true }` or `{ ipfs: "gateway", up, verify: true, strict: true }`. Both are absent for the bundled nodes, and each is absent when off, so a backend with neither keeps its exact two-key form and today's plans.
  - **`unsupported: true`** marks a gateway whose verification is on but which the probe found without raw blocks ([Modes](#modes)). It has no `verify`, so its plans stay `{ fetch }`. Strict mode refuses them with the second of its messages, and a backend with neither member gets the first.
- **With `verify`, a `{ fetch }` plan becomes a `{ verify }` plan.** Redirect and error plans are unchanged: the same URL checks, name results, 404/415/502 mapping, gateway-form 307s and 503s for a backend that isn't up.
  - **What stays a `{ fetch }`,** decided from the URL or the name's result before anything is fetched: an encrypted Swarm reference, a DNSLink name, and an IPNS name with an inlined key other than Ed25519 ([Modes](#modes)). Each keeps today's fetch plan, labelled `unverified`.
  - **With `strict`,** any plan whose content would be `unverified` becomes an error plan, a 403 that says why ([Strict mode](#strict-mode)).

  ```jsonc
  { "verify": {
      "node": "ant",                                    // or "ipfs": a reference, as in a fetch plan
      "root": { "swarm": "<64 hex>" },                  // or { "ipfs": "<CIDv1, lowercase base32>" }, { "ipns": "<a name with an Ed25519 or RSA key>" }
      "path": "/docs/page.html",                        // below the root, normalized, as an HTTP client sends it
      "query": "?state=1",                              // the request's query, for redirects only; "" when none
      "headers": [["range", "bytes=0-"]],               // the request headers the verifier honours
      "retry": { … }, "timers": { … },                  // per piece: today's tables for the backend
      "response": ["canonicalize_redirect", "strip_page_state"],  // operations main runs on the head
      "trust": { "name": "verified", "content": "verified" } } }
  ```

  - **`root`** is the reference the fetch plan's path would have named: a hash host, or a name's resolved contenthash with any published base path moved into `path`.
    - **An IPFS root is always canonical:** a CIDv1 in lowercase base32. A CIDv0 (`Qm…`, which an ENS contenthash can decode to) is converted to its CIDv1, as the handler's `cidV0ToV1Base32` converts a host, and base32 in either case is lowercased. Both conversions are lossless, so a site whose contenthash is a CIDv0 still verifies.
    - **A root that is still not in its form** (a name whose result isn't a CID, say) gets the verify plan all the same, and validation refuses it at `root` ([Failures](#failures)). It never falls back to an unverified fetch, so no name result can move a request out of verified mode.
  - **`path`** passes the same checks as a fetch plan's ([0006, Validation](0006-dweb-transports.md#validation-before-any-dial)), applied to `/<namespace>/<root><path>`. The core decodes its segments itself during the walk.
  - **`query`** is the request URL's query, exactly as main admitted it (`?` and all, or empty). It never takes part in a lookup: Ant's `/bzz` ignores it for content, and `GatewayCore` reads none. It exists for one thing: Ant keeps the query on its directory redirect, so the core's 308 `Location` must carry it too ([Heads](#heads)).
  - **`headers`** keeps only the request headers the bundled node reads: `range` for `bzz:` (Ant handles no conditional request), and `range` and `if-none-match` for IPFS ([Responses](#responses)). Everything else of the request stays in main.
  - **`retry` and `timers`** are the fetch plan's, applied to each piece: Ant's ten attempts on 500, 502, 503 and 504 with 30 s to the headers, and the external gateway's single attempt with no header bound. `body_idle_ms` applies to each piece's stream and to the verified body.
  - **`response`** names the bundled node's operations, as its own plans name them: `canonicalize_redirect` and `strip_page_state` for `bzz:`, since the core writes Ant's redirects in Ant's URL space and main rewrites them as today; `strip_page_state`, and `small_text` for a GET navigation, for IPFS.
  - **`trust.content`** is `verified`: the promise for the mode. The head carries the final label ([Labels](#labels)).
- **Why a plan, then a second call.** `dweb.open` runs on the naming thread, stateless once it answers, and main fences its plans against naming's generations (0006). A verified fetch is long-lived and stateful. Splitting them means a plan overtaken by a naming change is planned again before any piece is fetched, and naming's thread never holds a fetch.
- **Validation** (`validate_plan`, and main's `plan-validation.js`, with the same vectors): `shape`, `node` (the admitted backend, up, with `verify`), `root` (a 64-hex reference; a CIDv1 in lowercase base32, at most 269 characters after its `b`, the longest CID's text; an IPNS name whose key is an inlined Ed25519 key, or whose multihash is sha2-256), `path`, `query` (equal to the admitted URL's query, and within 0006's URL bound), `header`, `retry`, `timers`, `response` and `trust` (`content` is `verified`). A refused plan is a 502 and a logged core fault, as in 0006.
  - **What they check, past 0006's:**
    - `root` ties to the request as a fetch plan's target does (0006, #97): for a hash or CID host it is the host's own reference, exactly, in its canonical form; for a name host it is the name's result, which validation can't judge beyond its form.
    - **A `{ fetch }` plan for a hash or CID host the core verifies** is refused at `path`: that request's own plan is a `{ verify }`, so no fetch target ties to it, and a fetch would downgrade verified content to `unverified`.
    - `header`: only the names the bundled node reads, each at most once and in lowercase, with 0006's value rules: `range` for Ant; `range` and `if-none-match` for IPFS.
    - `response`: a subset of the bundled node's operations: `canonicalize_redirect` and `strip_page_state` for Ant; `strip_page_state` and `small_text` for IPFS.
    - `retry` and `timers`: the backend's tables, as for its fetch plans.
  - **Against a strict backend,** 0006's checks change in two places: a `{ fetch }` plan is refused at `trust`, since its content would be `unverified`; and an `error` may also be a 403, with exactly one of strict mode's fixed messages. A 403 for a backend that isn't strict is refused at `error`.

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
- **Thread:** the **dweb thread**, a new thread beside naming's and chain's, runs one sans-I/O machine per request (`fc-dweb`'s verifier). A pool of two hashing threads computes BMT roots and SHA-256 digests, and checks RSA signatures, for it.

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
- **Pieces in flight:** per request, at most 8: a `/bytes` stream and 4 intermediate chunks ahead of it ([Leaves](#leaves)); one CAR; or 8 raw blocks ([Raw blocks](#raw-blocks)). Across requests, at most 256 `shell.dweb_get` are outstanding, as 0004 bounds naming's requests to main; more wait in the dweb thread, first in, first out, and their memory counts against their request. So main never dials the node more than 256 times at once for verified requests.
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
  - **Trailing zeros don't change the address:** the BMT pads the payload with zeros, so the same payload with zero bytes appended, up to 4,096 in all, has the same address, and both nodes accept it. So does the core. A leaf's content is the first bytes its logical length gives ([Leaves](#leaves)), so the extra zeros are never served.
  - **The empty chunk** (span 0, no payload) is valid. Its address, `b34ca8c2…171526`, is also the reference of an empty file. `fc_swarm::bmt_root` refuses an empty payload today; the check accepts it.
- **A single-owner chunk (SOC)** is `id(32) ‖ signature(65) ‖ span(8) ‖ payload`, 105 to 4,201 bytes (`ac/soc.rs:8`–`30`).
  - **Its address** is `keccak256(id ‖ owner)`.
  - **The signature** is over the EIP-191 digest of `keccak256(id ‖ wrapped CAC address)`, as `r ‖ s ‖ v`. The core follows Ant: `v` from 27 to 30, and a high `s` refused (`ac/lib.rs:202`–`227`). That needs signature recovery in `fc-evm`.
  - **The replicas owner:** Bee signs dispersed replicas with a published key, whose address is `0xdc5b…17b5`. Ant accepts a SOC from that owner only when its identifier, after the first byte, equals the wrapped chunk's address (`ac/soc.rs:70`–`75`, `122`–`124`; ethersphere/bee#5640). The core does the same, so no feed of that owner verifies.
  - The wrapped chunk may carry any span, so it can be the root of a larger tree.
- **What `/chunks/<address>` returns:** the chunk's wire bytes, a CAC's or a whole SOC's, as `binary/octet-stream` (`ag/retrieval.rs:307`–`403`). Bee does the same.
- **Where a SOC is accepted: only as a feed update,** at the address the walk computed from the feed's topic, owner and index ([The Swarm walk](#the-swarm-walk)).
  - **Everywhere else** (a root, a manifest node, a file's root, an intermediate chunk, a leaf) the piece must be a CAC whose address is the reference. A SOC there, even a valid one, is `unverifiable` and never followed (deviation `soc-references`).
  - **Why:** a SOC's address commits to its identifier and owner, not to its payload, so its owner can sign different payloads at one address. A result that rested on one couldn't be called `verified` or cached as immutable.
  - **So** every verified result is CAC-addressed from its root down, except one that crossed a feed. That result is labelled `latest_asserted` and sent with `Cache-Control: no-cache`, as Ant sends it, and its SOC is never cached.

### Files

- **Leaves** are consecutive 4,096-byte slices of the file; only the last may be shorter (`ar/splitter.rs:1`–`25`).
- **An intermediate chunk** is `span ‖ references`: the span is the number of file bytes beneath it, and the payload holds references of 32 bytes. Bee writes 2 to 128 of them; the reader also takes a single reference, as Ant reads one, whose child then covers the whole span. Trailing all-zero references are padding. A chunk whose span is at most its payload's length is a leaf.
- **Geometry:** for a node with `n` data references and span `T`, `branch` is the smallest `4096 · b^k` with `T − (n − 1) · branch ≤ branch`. The first `n − 1` children cover `branch` bytes each, and the last the rest (`ar/joiner.rs:1314`–`1335`). Every leaf but the last is full, so byte `o` of the file is in leaf `⌊o / 4096⌋`.
  - The core takes each child's logical length from this geometry, as Ant's joiner does, never from the child's own span. [The leaf check](#leaves) covers a leaf whose span or payload length differs from the length its parent gives it.
- **Erasure coding:** an intermediate chunk with parities has its span's top byte set to `0x80 | level`, for levels 1 to 4. Its payload is the data references followed by parity references. Their counts come from Bee's `ReferenceCount` (the span, the level and whether the tree is encrypted; `ar/rs.rs:315`–`391`, `ar/joiner.rs:631`–`640`).
  - The core parses this and ignores the parities. It never needs them: a node that recovered a missing chunk from parities serves the original data, which checks against the original address.
  - `/bytes` is unchanged by erasure coding.
  - **It lowers the branching:** an intermediate chunk holds at most 119, 107, 97 or 39 data references at levels 1 to 4 (Bee's table, which Ant follows), so a level-1 chunk covers less of the file ([Performance](#performance)).
- **Depth:** the number of intermediate levels is `⌈log_b(⌈N / 4096⌉)⌉`, with `b` = 128, or the data references above under erasure coding. A 1 GiB file without erasure coding has three levels.
- **One shape where Ant's splitter and Bee's differ.** Where a level of the tree ends with a single leftover reference, Bee's hashtrie writer carries it up to the next level unwrapped (`Sum`, Bee `pkg/file/pipeline/hashtrie/hashtrie.go`). Ant v0.5.71's level-0 splitter wraps it in an intermediate chunk of one reference (`StreamingSplitter::finish`, `ar/splitter.rs`). Its erasure-coded splitter carries the reference up, as Bee does.
  - **So the same content has two references.** At 524,289 bytes (129 leaves), Bee's root names the first 128 leaves' chunk and the last leaf. Ant's names that chunk and a chunk of span 1 holding the last leaf's address.
  - **How Ant reads its own shape:** the wrapper's logical length is 1, so Ant's joiner reads it as a leaf, and serves the first byte of its payload (the first byte of the last leaf's address) as the file's last byte. That byte is wrong: it isn't the file's. The bundled Ant serves content Ant uploaded the same way ([freedom-hq/ant#234](https://github.com/freedom-hq/ant/issues/234)).
  - **Verified mode gives Ant's answer:** the wrapper is a valid CAC whose authenticated payload begins with the byte `/bytes` streams, so it passes [the leaf check](#leaves). Bee's tree for the same content is served as its content, by Ant and by the core.
  - The vectors hold both shapes at the sizes where they differ ([Tests first](#tests-first)).

### Manifests and feeds

- **A mantaray node** (`ar/mantaray.rs:1355`–`1543`; Bee `pkg/manifest/mantaray/marshal.go`):
  - a 32-byte obfuscation key in the clear; everything after it XORed with the key, repeated. Bee and bee-js write a zero key for unencrypted manifests;
  - the version hash (the first 31 bytes of `keccak256("mantaray:0.2")`, or of `0.1`);
  - the reference size: 32, 64 in an encrypted manifest, or 0 in an empty node, which Ant accepts and the core reads as Ant does. A node whose references are 64 bytes names encrypted content, which the walk doesn't read: `unverifiable` ([Encrypted references](#encrypted-references));
  - the node's entry, all zeros when it has none;
  - a 32-byte bitmap of forks, one bit per first byte;
  - each fork, in byte order: a type byte, a prefix length (1 to 30), a 30-byte prefix, the child's reference, and, when the type has bit 16, a 2-byte length and a flat JSON object of strings.
- **A node is stored as a file,** so one larger than 4 KiB is a chunk tree. Ant caps a node at 32 MiB (`ar/mantaray.rs:1016`–`1106`); the core caps it at 1 MiB (deviation `manifest-node-cap`).
- **Lookup:** from the root, take the fork for the path's next byte, require its prefix to begin the rest of the path, load the child, and repeat until the path is used up; the node reached gives the entry and its metadata. A path longer than one prefix is chained across nodes. Each step loads one node: one chunk, usually.
- **The root's metadata** (`website-index-document`, `website-error-document`, and the feed keys) is on its `/` fork.
- **Parity:** the core reads manifests exactly as Ant v0.5.71 reads them, held to vectors from Ant, malformed manifests included.
- **Feeds:** a root whose `/` fork carries `swarm-feed-owner` and `swarm-feed-topic` (and `swarm-feed-type` absent or `Sequence`; Ant refuses epoch feeds) is a feed manifest (`ar/feed.rs:95`–`231`).
  - The update at index `i` is the SOC with `id = keccak256(topic ‖ u64_be(i))` and the feed's owner.
  - **v1 updates** wrap 48 or 80 bytes, `span ‖ timestamp(8, big-endian) ‖ reference`; **v2 updates** wrap the content's root chunk itself. Ant tries v1 first, then fails (`ar/feed.rs:1444`–`1511`); the core does the same.
  - An 80-byte v1 update carries a 64-byte, encrypted reference, which the walk doesn't follow: `unverifiable`, never a fallback to an unverified fetch, which the node could otherwise choose by the update it serves.

### The Swarm walk

For `bzz://<root><path>`, in Ant's resolution order (`ar/mantaray.rs:486`–`592`):

1. **The root:** `/chunks/<root>`, checked as a CAC; and its tree, when the root is an intermediate chunk. If it isn't a manifest, Ant serves the reference's bytes, and so does the core.
2. **A feed root:**
   - main asks `GET /feeds/<owner>/<topic>` with `Swarm-Only-Root-Chunk: true`, and the core reads only `swarm-feed-index` from it: which update is latest is the node's word;
   - then `/chunks/<the update's address>`: the core checks the SOC's address, its identifier for that index, the owner the manifest names, the signature and the wrapped chunk;
   - the update's reference (v1) or root (v2) becomes the manifest's root, and the label becomes `latest_asserted`;
   - **when what the update names isn't a manifest,** Ant's fallback for a root that isn't a manifest (step 1) applies to the URL's reference, not to the update's. A bare request is answered with the feed manifest's own bytes, as raw bytes of that reference: `immutable`, its `ETag`, and no feed headers. The content the update names is never served, and a path below it is a 404 ([freedom-hq/ant#235](https://github.com/freedom-hq/ant/issues/235)). The core does the same, labelled `verified`, since those bytes are the URL's reference's own. An update that names an encrypted reference is `unverifiable` instead ([Encrypted references](#encrypted-references)): telling that it isn't a manifest would take decrypting it.
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

Ant's `/bytes` supports a single range on 64-hex references (206 with `Content-Range`), as Bee's does through Go's `ServeContent` (`ag/retrieval.rs:2384`–`2572`).

### Encrypted references

**Decided: encrypted references stay `unverified` from external nodes** ([Decisions](#decisions), 8). The chunk-by-chunk path that would check them isn't built. It is kept in the [appendix](#appendix-the-encrypted-path-not-built), and revisited when Ant can serve many raw chunks in one request ([freedom-hq/ant#233](https://github.com/freedom-hq/ant/issues/233)).

- **Why:** a reference of 64 bytes is the chunk's address and a key. The plaintext `/bytes` returns can't be checked against the address, because each chunk's padding and key are random, so the ciphertext can't be rebuilt from it. Checking means fetching every chunk from `/chunks` and decrypting it in the core: about 260 requests per MiB through Ant's API today.
- **A 128-hex reference in the URL** gets today's fetch plan, labelled `unverified`. (A name can't carry one: naming decodes only 32-byte Swarm contenthashes, and answers any other as unsupported, a 415, as today.) `dweb.open` decides this from the reference before anything is fetched, as it decides DNSLink from the name, so no node can steer a request there.
- **An encrypted reference met inside a verified walk** is `unverifiable` (502), and nothing from it is released:
  - a manifest node whose references are 64 bytes ([Manifests and feeds](#manifests-and-feeds));
  - a feed's v1 update of 80 bytes, which carries a 64-byte reference.

  The plan has already promised verified content, and a node chooses which feed update it serves, so falling back to an unverified fetch here would let the node take the request out of verified mode (deviation `encrypted-in-walk`).
- **Under [strict mode](#strict-mode),** a 128-hex reference is refused with a 403, as any `unverified` external content is.

### The structure cache

- **What it holds:** verified chunks that are structure, never data: manifest node chunks and intermediate chunks. Not leaves, and never SOCs, whose content at an address can change.
- **What an entry is:** the chunk's wire bytes as checked against its address.
- **One cache per partition,** keyed by address, each with its own least-recently-used order and its own allowance. No partition's entries count against another's or evict them:
  - the profile's (the default session's): 8 MiB, about 2,000 chunks;
  - each private window's: 2 MiB, about 500 chunks, which holds a site's upper manifest nodes and a long video's root and upper intermediates;
  - at most 8 private windows have a cache at once, as 0007's ephemeral process holds at most 8 private instances: 16 MiB;
  - so 24 MiB in all, within the dweb thread's 128 MiB ([Bounds](#bounds)).

  A private window that opens while 8 others hold caches gets none until one closes: its requests fetch every chunk, and no other window's entries are touched. Whether it got a cache tells it only that eight other private windows hold caches, not what they load.
- **Private partitions** (decided, [Decisions](#decisions), 10): each private window's partition has its own short-lived cache, as above.
  - Its entries live only while the window does: main sends `dweb.forget` when the partition closes, and they go with the partition's IPNS floors.
  - Nothing is written to disk.
  - A private window never reads the profile's entries or another window's, and its loads can't evict theirs, nor theirs its own. So it can't time another session's loads through the cache.
- **Late results:** `dweb.forget` advances the partition's epoch. A cache insert or a floor update carries the epoch its request started under, and one from an older epoch is dropped, so a piece reply or hashing result that arrives after the forget leaves nothing behind.
- **Why:** a site's subresources share the upper manifest nodes, and a video's seeks share the file's root and upper intermediates. With the cache, a later request costs one or two chunks before its stream.

## IPFS

### Blocks and DAGs

- **A block passes when** its bytes hash to its CID's multihash and it is at most 2 MiB: freedom-ipfs's `verify_block` (`freedom-ipfs-core/src/lib.rs:116`–`143`), which `fc-ipfs` reproduces in its own code, held to the native verdicts the vectors record, so the native node and verified mode accept exactly the same blocks.
  - **Hash functions:** sha2-256 and identity, as the native node. Kubo's default is sha2-256, and other functions are rare in practice (IPIP-0499's survey). Another function is `unverifiable`.
  - **Codecs:** dag-pb and raw, the two `GatewayCore` serves.
  - **A link matches a block** when their codec and multihash agree, so a CIDv0 link inside a DAG and the CIDv1 host 0006 re-encodes it to are the same block.
  - **Identity CIDs** carry their data inline; no gateway sends a block for them (the trustless spec forbids it in CARs).
  - **A CID's varints** (its version, codec, hash function and digest length) are read in their minimal encoding only, as the multiformats varint specification requires; `81 00 55 00 00` is not the empty identity CID.
- **dag-pb and UnixFS** are read by `fc-ipfs`'s own [bounded decoders](#bounded-decoding), to the DAG-PB and UnixFS specifications.
  - **A file's content** is its node's `Data`, then its children in link order; `blocksizes[i]` is the content under link `i`. A raw leaf is its block.
  - **Stricter than the native reader, deliberately:** `blocksizes` must have one entry per link, a raw leaf's length must equal its entry, and the content must add up to `filesize`. A file that fails one is cut at that point as malformed: its author made it inconsistent, and the core doesn't guess which length was meant. The pinned native reader instead slices a child by its declared size (deviation `unixfs-sizes`).
- **HAMT-sharded directories** (fanout 256 only, as the native node; Kubo's default): the core finds a name by its hash, as Kubo's gateway does (boxo `hamt.go:382`–`404`):
  - the first 64 bits of MurmurHash3 x64 128 of the name, seed 0, read big-endian, consumed a byte per level;
  - the shard's bitfield, a big-endian integer right-aligned in `Data`, at most fanout / 8 bytes (32), as boxo's `NewHamtFromDag` reads it, says whether the bucket is occupied, and the link is chosen by its position among the set bits. A longer bitfield, zero padding included, is malformed;
  - a link named by the two-hex-digit bucket alone is a sub-shard; one named bucket-and-name is the entry.

  So the core needs only the shards on the name's path, which is what a gateway's CAR carries. The pinned native reader finds an entry by its name among the shards' links instead. On a well-formed directory both find the same entry; an entry that isn't where its hash and the bitfield point isn't found in verified mode (deviation `hamt-lookup`).
- **Symlinks** are refused, as `GatewayCore` refuses them.

### Bounded decoding

The 2 MiB block limit bounds a block's bytes, not what decoding it allocates: a block of minimal repeated fields can declare far more entries than its size suggests, and nesting can cost stack. So no decoder in the verifier allocates from a count it hasn't checked and reserved, and none recurses.

- **One rule for every decoder:** dag-pb, UnixFS `Data`, the CAR header, the IPNS record and its signed data, an RSA key's protobuf and DER, mantaray nodes and Swarm intermediate chunks.
  - **Its input is already held and reserved:** a block that passed its hash, a chunk, a record within its cap.
  - **A first pass** validates the structure and counts what the second will keep (links, entries, copied bytes), without allocating.
  - **Each count is checked** against its cap and the request's budget, and its memory reserved (0005's rule), before the second pass builds anything.
  - **Strings and byte fields are views** into the held bytes. One is copied only when an output needs it, such as a listing's names, and reserved first.
  - **Every declared length** is checked against the bytes remaining before it is used.
  - **Nesting** is walked with an explicit stack of fixed depth, never by recursion.
- **Protobuf** (dag-pb, UnixFS `Data`, the IPNS entry):
  - varints of at most 10 bytes; every length within its enclosing message;
  - **dag-pb is read strictly,** by DAG-PB's protobuf strictness rules, as go-codec-dagpb (Kubo's and boxo's decoder) reads it: `PBNode` is its `Links`, contiguous, and at most one `Data`, on either side of them (IPIP-0550); `PBLink` is `Hash`, which it must have, then `Name`, then `Tsize`, each at most once. Any other field, a repeated one, or one out of that order is malformed. The pinned Kubo refuses each such block;
  - **unknown fields are skipped only where the format allows them,** in UnixFS `Data` and the IPNS entry: by wire type (varint, 64-bit, length-delimited, 32-bit), without allocating; groups refused. A message of many unknown fields costs time linear in its bytes and no memory;
  - a `PBLink` without a hash refused in the first pass, before anything is kept;
  - an RSA key's `PublicKey` read only in libp2p's deterministic encoding, so no field is skipped there ([IPNS and DNSLink](#ipns-and-dnslink)).
- **DER** (an RSA key's `SubjectPublicKeyInfo`):
  - definite lengths in their shortest form, as DER requires, each checked against the bytes remaining;
  - the key's one fixed structure (the algorithm, then the bit string holding the `RSAPublicKey`) read at a fixed depth, without recursion;
  - integers positive and minimally encoded, the modulus at most 8,192 bits and the exponent at most 33 bits, both checked before a big integer is built.
- **CBOR** (the CAR header, the IPNS record's signed data), in DAG-CBOR's strict profile at every level:
  - definite lengths only, each checked against the bytes remaining; integers, lengths and counts in their shortest form;
  - nesting at most 8 levels, the outermost map or array the first, on an explicit stack;
  - map keys are strings, in canonical order (shorter first, then bytewise), so no key repeats; each key is compared only with the one before it, on the same stack, so the check allocates nothing;
  - floats are 64-bit and finite, and not negative zero; `false`, `true` and `null` the only simple values;
  - unknown keys and the values the reader doesn't need are validated by the same rules and skipped, iteratively, under the same depth bound;
  - **tags:** tag 42 wherever DAG-CBOR allows a link, its content a well-formed CID (a byte string of 0x00 and one complete CID, its varints minimal); every other tag refused, and a tag 42 whose content isn't a CID. A link under an unknown key is skipped, as the IPNS specification skips unknown keys; one where a field must be another type (an IPNS record's `Value`, which is bytes) is refused.
- **Caps on decoded structure,** beyond the wire caps:
  - 65,536 links per dag-pb node. This is a supported-content limit, not a malformedness test. Typical directories and files are far below it, but valid content can exceed it within 2 MiB: compact links, such as identity CIDs with short names, need only about 17 bytes each. Such a node is refused as `unverifiable`, never reported as malformed;
  - as many UnixFS `blocksizes` entries, which a node keeps as numbers. A node with more is refused the same way, before its entries are compared with its links;
  - 256 forks per mantaray node (one per first byte), and fork metadata within its 2-byte length, read with `fc-json`'s depth bound. Only a flat object of strings is accepted, and only the keys the walk reads are kept.
- **What this means for sharing code:** `fc-ipfs` can't use `freedom-ipfs-unixfs`'s decoders as they are. They decode with `prost`, which allocates repeated fields while it reads, before any reservation can be made. `fc-ipfs` carries its own bounded decoders, held to vectors from the native reader on the blocks both accept. freedom-ipfs adopts them later, so there is one reader, not two ([Decisions](#decisions), 11).

### The CAR request

- **What the core asks:** `GET /ipfs/<cid><path>?format=car&dag-scope=entity`, with `&entity-bytes=<from>:<to>` for a range, and `Accept: application/vnd.ipld.car; version=1; order=dfs; dups=y`.
- **What a conforming gateway sends** (Trustless Gateway spec, IPIP-0402 and IPIP-0412; boxo `backend_blocks.go:440`–`680`):
  - the blocks that resolve the path, root first, then the entity: a file's root, intermediates and leaves, only those covering `entity-bytes`; a directory's block, or all of a HAMT's shards;
  - depth-first, with a repeated block sent again where it repeats (`dups=y`);
  - `Content-Type: application/vnd.ipld.car; version=1; order=dfs; dups=y`.
- **What the core accepts:**
  - a 200 with that type and those parameters. A CAR of another type or parameters (`dups=n` among them) isn't read: the core cancels it and fetches raw blocks;
  - a header of at most 64 KiB, a DAG-CBOR map with `version: 1`. Its roots are ignored, as the spec says clients should;
  - sections of at most 2 MiB plus the CID's length, each length checked before a byte of the block is buffered.
- **Each block** is hashed, then must be the block the core's own walk needs next. The core releases a leaf's content only after both checks.
- **The CAR is a block source, not an authority.** A block that hashes right but isn't the one the walk needs next isn't a lie:
  - the gateway may have ignored `entity-bytes` and sent the whole DAG;
  - it may have sent another order, or no duplicates;
  - it may have read the path differently.

  Then the core cancels the CAR and fetches what its walk still needs as [raw blocks](#raw-blocks). Only a block whose bytes don't hash to its CID is a verification failure.
- **A CAR that ends before the walk does:**
  - **ending cleanly,** at a section boundary, is like the shapes above: the core fetches what its walk still needs as raw blocks. A gateway that sent no duplicates ends that way, and so may one that lost a child block, as the spec lets it; the raw request for that block then fails on its own;
  - **ending broken is an early end:** a stream that ends inside a section, or that has boxo's truncation marker where the next section would begin (`\n\n[Gateway Error: CAR stream truncated, response is incomplete]`, ipfs/boxo#1197). The gateway has said it failed, so the walk is unfinished: a piece failure, a truncation if the head was sent;
  - **what is a verification failure instead:** any other framing the reader can't take (a section length past the limit or over 10 bytes, a CID it can't read, a malformed header), and a block that doesn't hash to its CID.
- **A directory URL** costs a second CAR: once the core has the directory and finds `index.html` in it, it asks for that file by its CID (`/ipfs/<cid of index.html>?format=car&dag-scope=entity`), with no path to resolve again.

### Raw blocks

- **What the core asks:** `GET /ipfs/<cid>?format=raw` with `Accept: application/vnd.ipld.raw`, and never `Range`: a partial block can't be checked, and boxo would serve one.
- **When:** for every block when the gateway has no ordered CAR support ([Modes](#modes)), and for the rest of a walk whose CAR stopped being useful.
- **Why it is always there:** raw blocks are the only response type the trustless spec requires of a gateway. A gateway that serves them can always be verified, if slowly.
- **Cost:** one request per block, up to 8 at once per request; with Kubo's default 256 KiB chunks, four per MiB, and one per path segment or HAMT level before the first byte.
- **Memory:** a raw leaf is reserved at its `blocksizes` entry, which its length must equal; any other block at 2 MiB, until it arrives.

### The IPFS walk

For `ipfs://<cid><path>`, with `GatewayCore`'s rules:

1. **The path** is decoded once, then resolved from the root, one directory or HAMT at a time:
   - it is split on `/` first, then each segment is percent-decoded exactly once, as Kubo and HTTP gateways decode it. Nothing is decoded twice;
   - a segment that decodes to `.` or `..`, or to anything containing `/`, `\` or NUL, is a 400, with `GatewayCore`'s body for a refused path. So is a segment that isn't valid UTF-8 once decoded;
   - **where `GatewayCore` differs** (deviation `ipfs-path-decoding`): `freedom-ipfsd` hands the plan's path, percent-encoded as an HTTP client sends it, to freedom-ipfs's native-request parser, which at the pinned `e7dcc6f` doesn't decode it. So on the native node a name with a space or a non-ASCII character isn't found, where the same name unencoded is. The vectors record both. The parser decodes by the same rule from freedom-ipfs `9700f548` (freedom-ipfs#58, on its integration branch); the next `freedom-ipfsd` pin picks it up and closes the deviation.
2. **A missing name in a verified directory** is a proven 404. A gateway that follows boxo sends the CAR up to the parent and stops; the core sees the parent and the name's absence. A 404 status from the gateway, without the parent, is the gateway's word.
3. **A directory:**
   - its `index.html`, when it has one, served as a file whose type comes from the name `index.html`;
   - otherwise `GatewayCore`'s HTML listing, from the directory's links (every shard of a HAMT, which `dag-scope=entity` includes), sizes from the links' `Tsize`, sorted by name.
4. **A file:** its length is `filesize`; then its content, depth-first, as blocks arrive and pass.
5. **HEAD** stops after the file's root, or after its first 513 bytes when the type must be sniffed ([Heads](#heads)).

### IPNS and DNSLink

- **A name with an Ed25519 or an RSA key** gets a verify plan. The name shows which form its key takes (libp2p's peer-ID specification, *Peer Ids*):
  - **an Ed25519 key** is inlined in the name, as the identity multihash of its libp2p `PublicKey` protobuf;
  - **an RSA key** is too large to inline, so the name is the sha2-256 multihash of that protobuf, and the record carries the key in `pubKey` (the IPNS record specification, *Public Key*).

  Every name with a sha2-256 multihash gets a verify plan. Its record's key must then be RSA: any other type (ECDSA, which the native node doesn't verify either) is `unverifiable`, never a fallback to an unverified fetch.
- **The record:**
  - the core asks `GET /ipns/<name>?format=ipns-record` with `Accept: application/vnd.ipfs.ipns-record`, at most 10 KiB;
  - it checks the record as freedom-ipfs's `verify_ipns_record` does (`freedom-ipfs-namesys/src/lib.rs:586`–`649`), with [bounded decoding](#bounded-decoding): the key matches the name, `signatureV2` over `"ipns-signature:" ‖ data` verifies, the DAG-CBOR data parses, the validity type is EOL and the EOL is after now, and the value starts with `/ipfs/` or `/ipns/`;
  - **Who is at fault:** what the gateway controls and gets wrong (the record's framing, a key or signature that doesn't check) is `verification_failed`; signed data that the signature covers but the strict CBOR reader can't take (outside the strict profile, a length past the end, nesting past 8 levels) is `unverifiable`, since its signer made it; a failure after a clean decode (a validity type other than EOL, a value that isn't a path, an expired record, a legacy field that differs) stays `verification_failed`.
  - **Ed25519 signatures are checked non-strictly,** as freedom-ipfs (`ed25519-dalek`'s `verify`) and Go's `crypto/ed25519`, which Kubo uses, check them: `S` must be canonical, and a key of small order isn't refused. That is safe here: an IPNS name commits to its key, so a weak key weakens only its owner's own name. The vectors pin it with the identity point as key, which a signature of `R` the identity and `S` = 0 satisfies for any message;
  - **V2-only records are accepted.** The legacy V1 fields are optional; each one present must equal its signed counterpart. Once `signatureV1` or the legacy `value` is non-empty, all five must, an absent one read as its protobuf default, as the IPNS record specification and boxo's `validation.go` require; the native reader compares only the fields present (deviation `ipns-legacy-fields`). Unknown fields in the entry and unknown keys in the signed data are skipped, not refused, as the IPNS record specification allows;
  - the value's path, then the request's path, are walked as above, except that the value's segments are matched as written, as `GatewayCore` matches them: it decodes none, so an encoded name in a record isn't found, and a segment that is `.` or `..`, as written or percent-encoded, is its 400 `path traversal segments are not allowed`. The segments of every value and the request's are at most 256 in all. A value naming another name with an Ed25519 or RSA key is followed the same way, with at most 4 records in all (`GatewayCore`'s limit on DNSLink chains): `GatewayCore` resolves a fourth name, then answers 400 `dnslink recursion limit exceeded` whatever it names, and so does the core once the fourth record passes. A value naming a DNSLink name, or a name with another inlined key, is `unverifiable`.
  - The label is `latest_asserted`: a gateway can serve an older record that hasn't expired yet.
  - **The core keeps a floor in memory:** the highest sequence it has verified per name and partition. A record below the floor is refused while the floor's record is still valid.
    - **Bounds:** at most 1,024 names, least recently used out first. An evicted name has no floor until its next record, so the protection is best-effort, and lost on a restart.
    - **Concurrent requests:** the floor only rises, atomically, to the highest sequence verified. A request that verified its record before a higher one arrived keeps the record it verified; only records checked after the rise are held to it.
    - This narrows rollback within a session; it proves nothing across restarts.
  - **"Now"** is the core's wall clock, passed into the logic crates as a parameter (AGENTS.md rule 2).
- **RSA keys** (decided, [Decisions](#decisions), 9) are read as libp2p defines them, and checked as the native node checks them except where listed:
  - **Encoding:** `pubKey` is a libp2p `PublicKey` protobuf with `Type` RSA (0), whose `Data` is the key in PKIX form: a DER `SubjectPublicKeyInfo` with the `rsaEncryption` algorithm (OID 1.2.840.113549.1.1.1, NULL parameters), around a PKCS#1 `RSAPublicKey` (libp2p's peer-ID specification, *RSA*; go-libp2p's `UnmarshalRsaPublicKey`, through Go's `x509.ParsePKIXPublicKey`; rust-libp2p's `rsa::PublicKey::try_decode_x509`).
  - **The name binds the bytes:** the name must be the sha2-256 multihash of `pubKey` exactly as it arrived.
    - libp2p requires every key to be encoded deterministically: varints minimal, the fields in tag order, both present, and no others (the peer-ID specification, *Keys*). The core reads only that form, and DER only in its canonical form, so the bytes it hashes are the key it verifies with.
    - The native reader (`libp2p-identity` 0.2.13) instead decodes the key and hashes its own re-encoding, so it also takes a key encoded another way (deviation `rsa-keys`).
  - **The signature:** RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017, section 8.2), over `"ipns-signature:" ‖ data` as for Ed25519, and exactly as long as the modulus. That is libp2p's RSA signature (the peer-ID specification, *RSA*; go-libp2p's `RsaPublicKey.Verify`; rust-libp2p's, through ring's `RSA_PKCS1_2048_8192_SHA256`).
  - **The key's size:** a modulus of 2,048 to 8,192 bits, go-libp2p's `MinRsaKeyBits` and `maxRsaKeyBits`, which rust-libp2p's ring algorithm also bounds. ring counts the minimum in whole bytes, so it also takes a modulus of 2,041 to 2,047 bits, which the core refuses with go-libp2p (deviation `rsa-keys`). The exponent is odd, from 3 to 2^33 − 1, ring's bounds.
  - **A key or signature outside these rules** fails the record's check: `verification_failed`, as a bad Ed25519 signature does.
  - **The verifier is the `rsa` crate, for verification only** ([Upstream](#upstream)). The core builds a public key from the parsed modulus and exponent and checks one signature with it; it never holds an RSA private key, so it never makes a private-key operation.
  - **Cost:** one signature check per record, measured at 0.2–0.3 ms for a 2,048-bit key and under 3 ms for an 8,192-bit key ([Measured](#measured)). It runs on the hashing pool.
- **DNSLink names** (`ipns://example.com`, whose root comes from DNS) and **names with another inlined key** (secp256k1, which the native node doesn't verify either) get today's fetch plan and the `unverified` label. For DNSLink this is decided ([Decisions](#decisions), 7).
  - `dweb.open` decides this from the name itself, so no node can steer a request out of verified mode.
  - **A name is a key only if it decodes to a libp2p-key CID.** Anything else is read as DNSLink, including a name longer than any CID's text: 269 characters after its multibase prefix, the longest CID (four 10-byte varints and a 128-byte digest) in base32, which base36 never exceeds. Such a name isn't decoded at all, since a base36 decode costs the square of its length and a request's URL may be 64 Ki units long.
  - **A possible later step, not planned work:** the core could resolve DNSLink itself, over DNS-over-HTTPS exchanges main performs, with two independent resolvers that must agree. The root would then come from resolvers Freedom chooses, not from the gateway.

### Gateways in practice

Reported by the research for this design on 2026-10-13, from code and from probes made from one location; unverified elsewhere:
- **Kubo** has served raw blocks and CARs since 0.13, `dag-scope` and `entity-bytes` since 0.21, and `order` and `dups` since 0.22. It answers `dups=n` unless asked for `dups=y`. A local Kubo serves all of it on `127.0.0.1:8080` by default.
- **Public gateways:** ipfs.io and dweb.link were reported retired on 2026-09-21, and trustless-gateway.link was down when probed. Pinata's gateway and ipfs.aleph.cloud honoured `dag-scope` and `entity-bytes`; Filebase and 4everland served raw blocks and CARs but ignored those parameters.
- **So the core never relies on a CAR's shape:** it uses CARs where they help and falls back to raw blocks where they don't.

## Responses

### Heads

The core builds every head from verified data, by the bundled node's rules. The vectors record the bundled node's answers header by header, and the core must reproduce them.

**When a head goes out:** a GET's head is sent when a HEAD's would end. For `bzz:`, that is once the walk and the file's root chunk have passed ([The Swarm walk](#the-swarm-walk), [Leaves](#leaves), 5). For `ipfs:` and `ipns:`, it is once the file's root node has passed, or its first 513 bytes when the type must be sniffed ([The IPFS walk](#the-ipfs-walk), 5). So a failure in a manifest, a directory, a record or the file's root is an error with its status. One in an intermediate chunk, a file node below the root or a leaf truncates the body only if the reads before the head have finished; one those reads meet is an error too. They are the first data chunk, which tells a raw `bzz:` reference from a manifest (Ant reads down to it), and the blocks holding the first 513 bytes of a file whose type is sniffed.

- **`bzz:`, Ant v0.5.71's rules** (`ag/retrieval.rs`, `ant-p2p/src/behaviour.rs`), with Ant configured as Freedom configures it:
  - **`Content-Type`:** the entry's `Content-Type` metadata as written, or `application/octet-stream`. Ant doesn't sniff.
  - **`Content-Disposition`:** `inline; filename="<name>"`, from the `Filename` metadata or else the path's last segment, with `\` and `"` escaped.
  - **`ETag`:** `"<the resolved file reference in hex>"`, feeds included.
  - **`Cache-Control`:** `public, max-age=31536000, immutable`, or `no-cache` when a feed was crossed.
  - **Feed headers,** when a feed was crossed and the answer serves content: a 200 (an error document included) or a 206 (zero-length and multipart included), to a GET or a HEAD. They are `swarm-feed-index`, the verified update's index as 16 hex digits; `swarm-feed-resolved-version`, `v1` or `v2`; and `Swarm-Feed-Index` added to `Access-Control-Expose-Headers` (`ag/retrieval.rs:4792`–`4824`). A 308, a 404 and a 416 carry none: Ant returns them before it applies the headers (`ag/retrieval.rs:2804`–`2807`, `2836`–`2843`). The response vectors include a feed-backed 308, 404 and 416.
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
- **Not reproduced:** headers that describe the node rather than the content are dropped, and the vectors list them (`meta.ant.node_headers`). They show one: Ant's router adds `server: ant-gateway/0.5.71` to every answer.
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
| | a feed manifest anywhere on the path | `latest_asserted` |
| | a 128-hex (encrypted) reference | `unverified`: today's fetch plan, decided by the reference ([Encrypted references](#encrypted-references)) |
| | an encrypted reference inside a walk: a manifest node's, a feed update's | none: the request is `unverifiable` (502) |
| external gateway, verification on and supported | a CID, or a name's IPFS contenthash | `verified` |
| | an IPNS name with an Ed25519 or RSA key, directly or as a name's contenthash | `latest_asserted` |
| | a DNSLink name, or an IPNS name with another inlined key | `unverified`: today's fetch plan, decided by the name |
| any external backend, verification off | today's fetch plan | `unverified` |
| external gateway without trustless support | today's fetch plan | `unverified`, and the nodes panel says why |
| any external backend, [strict mode](#strict-mode) on | every row above that is `unverified` becomes a 403 error plan | none |

- **The setting:** per profile and per external backend, "Verify content from this node", in the node's settings beside its endpoint. **On by default** for every external backend (decided, [Decisions](#decisions), 1).
- **The user's own node is verified too** (decided, 5). A loopback Bee, Ant or Kubo the user runs is often as trusted as the bundled node, but the cost of checking it on loopback is small, and there is no "trust this node" switch. Turning verification off for it is the setting above.
- **Support is probed once, at activation,** not per request:
  - **The gateway,** after today's `bafkqaaa` probe, two more requests for the same empty identity CID, which needs no retrieval, so each answers at once:
    - `?format=raw` with the raw `Accept`: a 200 of type `application/vnd.ipld.raw` means the gateway can be verified at all;
    - `?format=car&dag-scope=entity` with the CAR `Accept` above: a 200 of type `application/vnd.ipld.car` with `order=dfs` and `dups=y` means CARs are worth asking for. Without it, every block is fetched raw.

    A gateway that fails the first serves `unverified`, and the nodes panel says "This gateway doesn't serve verifiable responses". A probe can't show whether a gateway honours `entity-bytes`; the [CAR request](#the-car-request) copes when one doesn't.
  - **Ant:** no probe. Bee's API, which Ant follows, always serves `/chunks` and `/bytes`, and Bee 2.8 has no restricted mode. A `HEAD /chunks/…` on Ant retrieves from the network, so it would be no cheap probe anyway (`ag/retrieval.rs:307`–`403`). A node that refuses those paths fails each verified request with its own status.
  - The result is fixed for the backend's activation and is part of the backend main captures. A gateway that later stops answering trustless requests fails them; nothing falls back to an unverified fetch per request, which a hostile node could otherwise trigger at will.
- **No new setting for the bundled nodes.** The core doesn't check their output again (decided, 6).

### Strict mode

- **The setting** (decided, [Decisions](#decisions), 2): per profile, "Load only verified content from external nodes", beside the nodes' verification settings, **off by default**. Where `blockUnverifiedEns` sends an unverified name through an interstitial, strict mode refuses unverified content outright. It doesn't touch the bundled nodes, whose content is `node_asserted`, or a name's own trust, which naming labels (0004).
- **What it refuses:** every request to an external backend whose content would be `unverified`:
  - a DNSLink name, or an IPNS name with an inlined key other than Ed25519;
  - an encrypted (128-hex) Swarm reference;
  - anything from an external backend whose verification is off, or from a gateway the probe found without raw blocks.

  RSA-keyed IPNS names are verified (decision 9), so they still load, as does content labelled `latest_asserted`.
- **The core decides it, from the plan:** main sends `strict: true` in the backend reference it captured ([Verify plans](#verify-plans)). In place of an unverified fetch plan, `dweb.open` returns an error plan, before anything is fetched: status 403 and `code` 403, since this is the profile's refusal, not a node's failure. A strict backend never gets a `{ fetch }` plan, and validation refuses one.
- **Its messages,** fixed, one per cause, the first that applies in this order (proposed wording, the user's to change):
  - `This profile loads only verified content, and verification is off for this node`;
  - `This profile loads only verified content, and this gateway doesn't serve verifiable responses`;
  - `This profile loads only verified content, and a DNSLink name can't be verified`;
  - `This profile loads only verified content, and this IPNS name's key type can't be verified`;
  - `This profile loads only verified content, and an encrypted Swarm reference can't be verified with an external node`.

  A navigation shows them on the [error page](#the-error-page).
- **Binding:** the setting is captured with the backend at admission, so a change applies to requests admitted after it (0006, *Binding*).

### Labels

- **`trust.content` values:**
  - **`verified`:** every byte checked against the root the URL or the name names.
  - **`latest_asserted`:** checked against an update its owner signed (a feed's single-owner chunk, an IPNS record); that the update is the latest is the node's word.
  - **`node_asserted`:** the bundled nodes, which check what they retrieve themselves.
  - **`unverified`:** verification is off or unsupported, the name can't be verified (DNSLink, an IPNS name with another inlined key), or the reference is encrypted.
- **Where it is decided:** the plan carries `verified`, the mode's promise. The head carries the final label: a walk that crosses a feed or an IPNS record lowers it to `latest_asserted`. Main keeps the head's label for the navigation.
- **Where it is shown** (0006's open question 5): the address bar's trust panel, which today shows a name's trust in rows (`navigation-utils.js`), gains a content row for `bzz:`, `ipfs:` and `ipns:` pages. Proposed wording, the user's to change:
  - `verified`: "Content verified by Freedom";
  - `latest_asserted`: "Content verified; latest version as reported by your node";
  - `node_asserted`: "Content retrieved by Freedom's node";
  - `unverified`: "Content not verified: served by your external node as is".
- **Subresources** get their own label but don't change the tab's; a subresource that fails verification fails or truncates, and its failure is logged with a fixed code.

## Failures

**Before the head,** the page gets a JSON body `{ code, message }` with the status as `code`, as 0006's error plans do, and a navigation gets the [error page](#the-error-page) instead. The body is the core's; the node's error body never passes.

| Cause | Status | Message |
|---|---|---|
| a chunk, block, manifest node, directory, CAR or record fails its check (an IPNS record's key or signature outside libp2p's rules included) | 502 | `Swarm content verification failed` / `IPFS content verification failed` |
| content the core can't check: an unsupported hash function, codec or node type; a single-owner chunk off the feed path; an encrypted reference inside a walk; a Swarm leaf shorter than its logical length; a manifest node over 1 MiB; an IPNS record whose key is neither Ed25519 nor RSA; structure past the decoders' caps; a walk past its [bounds](#bounds) or its request's memory | 502 | `This content can't be verified with the external Swarm node` / `… IPFS gateway` |
| content that passes its hashes but can't be decoded or is inconsistent: a dag-pb node or UnixFS `Data` the [bounded decoders](#bounded-decoding) refuse (a link without a hash, a group, an over-long varint, a length past the end), a UnixFS file whose sizes disagree (deviation `unixfs-sizes`) | 502 | `This IPFS content is malformed` |
| the path isn't in a verified manifest or directory | 404, through the bundled node's rules ([Heads](#heads)) | the bundled node's |
| a piece's final answer is 404 | 404 | `Not found on the external Swarm node` / `… IPFS gateway` (node-asserted) |
| a piece's final answer is another 4xx or 5xx | that status | `The external Swarm node answered <status>` / `… IPFS gateway …` |
| a piece's dial failed | as today: 503 or 502 for Ant, 502 for the gateway (`failure::after_dial`) | today's |
| the dweb thread is full, or memory can't be reserved in time | 503 | `Too many requests`, as a `busy` from `dweb.open` reads today |
| no head within `deadline_ms` | 504 | `Deadline passed` |
| [strict mode](#strict-mode) refuses unverified content (an error plan, before `dweb.verify`) | 403 | strict mode's, by cause |
| main refuses the plan ([Verify plans](#verify-plans), Validation), a verify plan whose root isn't in its canonical form included; never an unverified fallback | 502, a logged core fault, as 0006's refused plans | 0006's |

**After the head,** the body is truncated: the core sends `abort { code, message }`, and main errors the body, as a node's mid-body failure is surfaced today (0006). The codes are `verification_failed`, `unverifiable`, `malformed`, `piece_failed`, `busy` and `cancelled`.

- **Each code's message** is its cause's text in the table above. A piece that fails after the head (its body ends early or stalls, its 206 names another interval, or a CAR ends broken) is `piece_failed`, with "The external Swarm node stopped sending" or "The external IPFS gateway stopped sending".

- **What the page has received** is a prefix of the right content: every byte of it came from a chunk or block that passed its check before any of its bytes were released.
  - **The prefix may end anywhere,** inside a checked chunk or block too. A verified block is released in frames as credit allows, and 0007's `abort` purges what is still queued in the core and in main's ring, so the page can see part of a block that passed. The guarantee is about which bytes are released, not where the release stops.
  - **Why not deliver blocks whole:** holding back a checked block until all of it fits the window would need up to 2 MiB of extra credit per stream, and a cancel would still have to purge. Partial delivery of checked bytes loses nothing the guarantee needs.
  - Chromium treats the resource as truncated: a script or image fails, a navigation shows what it had rendered, and a download fails as interrupted.
- **Logging:** a fixed code, the backend's mode and the piece's kind (chunk, stream, CAR, record), never a reference or a path in a private window.
- **A node that fails verification stays in use** (decided, [Decisions](#decisions), 3). Only the requests that fail, fail; its other requests, and its later ones, are verified as usual. Each failure is caught where it happens, so nothing unverified reaches the page either way.
- **The nodes panel** counts verification failures per backend and shows "Your external node served content that failed verification" while any occurred in the last 10 minutes. The notice informs the user; it switches nothing.

### The error page

**Decided: a failed navigation gets an error page in plain words, not the JSON body** ([Decisions](#decisions), 4).

- **Which answers:** a GET request that looks like a navigation (below), whose answer is a `{ code, message }` body written by the core or by main:
  - the failures above, before the head;
  - strict mode's refusals;
  - error plans and main's local failures (0006), in every mode.

  A node's own answer, which unverified mode passes as it is, and the bundled node's bodies the core reproduces in verified mode (Ant's 404 JSON, `GatewayCore`'s HTML errors), are unchanged: parity covers them as content.
- **How main tells a navigation: it can't exactly, so it uses a navigation-like heuristic,** the rule `small_text` reads: a first `Accept` token of exactly `text/html`.
  - **Why no exact signal:** a `protocol.handle` request carries none. Tested with Electron 44.7.0 (Chromium 152.0.7977.130) and Freedom's scheme privileges (`standard`, `secure`, `supportFetchAPI`, `corsEnabled`, `stream`, `allowServiceWorkers`), the handler sees no `Sec-Fetch-*` header at all, and `Request.destination` is `""` and `mode` is `"cors"` for a navigation, a frame, an image and a `fetch` alike. Chromium adds Fetch Metadata in its network service's loader (`SetFetchMetadataHeaders`, called from `services/network/url_loader.cc`), which a request Electron answers through `protocol.handle` doesn't pass through.
  - **So it is navigation-like, not exact:** every navigation and frame sends Chromium's navigation `Accept`, whose first token is `text/html`, and gets the page. So does a `fetch` or a subresource that sends `Accept: text/html` first, as a page can. Every other request (an image, a script, a `fetch` with the default `*/*`) keeps the JSON body, and so does `permission-manifests.js`, which sends no `Accept`.
  - The page and the JSON carry the same status, so a caller that reads only the status is unaffected either way.
- **The page:**
  - the same status, and a fixed template in plain words: what failed, whose node, and what the user can do, with the URL and a "Try again" link;
  - no script, under `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`, and `Cache-Control: no-store`;
  - nothing from the node.

  The handler answers a request, not a tab, so it can't send the tab to the shell's own `pages/error.html`; the page follows that page's look and words.
- **Its texts** are plain-words versions of the messages above, one per cause (proposed, the user's to change). For example, a verification failure reads "The content your external Swarm node sent doesn't match its address, so Freedom didn't show it", and a strict refusal "This profile loads only content Freedom can verify, and this page can't be verified: <cause>".
- **After the head,** a failure truncates the body, and a navigation keeps what it had rendered (above). No page replaces it.

## Main's side

- **`plan-validation.js`:** the `{ verify }` variant, and strict mode's checks, with `fc-dweb`'s vectors.
- **`dweb-handler.js`:** a `{ verify }` plan takes a fetch admission slot, then calls `dweb.verify` through the core client. The head becomes a `Response` after the response operations; its body reads the stream's ring through the body idle wrapper (`idleBoundBody`), whose `onEnd` releases the slot.
  - **The error page:** a navigation-like request's `{ code, message }` answer becomes the [error page](#the-error-page) wherever the handler or the executor would write `jsonErrorResponse`.
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
- **`ant-manager.js` and `ipfs-manager.js`:** the setting, on by default, the probe, and `verify` in the captured backend. A reused Ant counts as external, as `antBackend()` reports it today, so it verifies too, as does any loopback node.
- **Strict mode:** the profile setting, off by default, read when the backend is captured, and `strict` in the backend reference ([Strict mode](#strict-mode)).
- **The trust panel and the nodes panel** in the renderer ([Labels](#labels), [Failures](#failures)); the settings page gains strict mode beside the nodes' verification settings.
- **The core's cache:** when a private partition closes, main sends `dweb.forget { partition }`, and the core drops the partition's [structure cache](#the-structure-cache) and IPNS floors (decision 10).
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

RSA signature checks for IPNS records, in release builds on the same server at a load average of 4.5 to 6 (PKCS#1 v1.5 with SHA-256, keys and signatures made by OpenSSL; the range over two sessions of five runs, each of 200 to 2,000 checks):

| Key | `rsa` 0.9.10 with `u64_digit`, as pinned, one thread | `rsa` 0.10.0-rc.19, for comparison |
|---|---|---|
| 2,048 bits, exponent 65,537 | 0.19–0.31 ms | 0.15–0.16 ms |
| 4,096 bits, exponent 65,537 | 0.69–0.83 ms | 0.60–0.66 ms |
| 8,192 bits, exponent 65,537 | 2.7–2.8 ms | 2.4–2.5 ms |
| 8,192 bits, exponent 2^33 − 1, the largest allowed | 2.7–2.8 ms | 3.7–4.1 ms |

- **So a record costs at most about 3 ms of one hashing thread,** and a request at most 4 records (the IPNS hops): about 12 ms, whatever key sizes a hostile gateway chooses. Kubo made 2,048-bit RSA keys by default, which cost 0.2–0.3 ms.

### Estimates

- **Requests:**
  - **Swarm:** a page's walk costs one chunk per manifest node on the path (two to four for typical sites, an estimate), plus the file's root; then the level-1 intermediate chunks below, and one `/bytes` stream. The structure cache makes a site's second and later subresources cost one or two chunks each.

    | Tree | Data references per intermediate chunk | Level-1 chunks per MiB of body |
    |---|---|---|
    | plain | 128 | 2.0 |
    | erasure coding level 1, the upload default in Ant and Bee | 119 | 2.2 |
    | level 2 / level 3 | 107 / 97 | 2.4 / 2.6 |
    | level 4 | 39 | 6.6 |

    Higher levels add a chunk per MiB at the next level up too, which is small beside these. Encrypted trees aren't walked ([Encrypted references](#encrypted-references)).
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

Measured before verification ships on by default (decision 1), on linux-x64, macOS arm64 and win-x64, verified against unverified on the same node:
- **Swarm, loopback Ant, cached content:** a 1 KB file, a 10 MiB file and a seek into it, at 1, 50 and 200 concurrent requests, for a plain tree and erasure coding at levels 1 and 4. For plain and level-1 trees, verified time to first byte within 10 ms of unverified at p50 one at a time, and throughput of at least 40 MiB/s for the 10 MiB file. Level 4 is measured and reported against those figures.
- **IPFS, loopback Kubo:** the same shapes. Verified throughput at least 80 % of unverified.
- **The vault under load:** with 64 verified bodies streaming at full speed, a `vault.lock` is acknowledged within 50 ms at p99.
- **A real page load** of a Swarm site and an IPFS site, verified against unverified, in Chromium.

If a gate fails, the default ([Decisions](#decisions), 1) and the [service alternative](#where-verification-runs) go back to the user with the numbers.

## Tests first

As 0006's 4.7 did, the tests land before the code. Every case pins its failure stage and code, the fixed message, the exact prefix of body bytes released, and the request's reservations back at zero; a case that only checks a hash passing isn't enough.

- **Format vectors** (`vectors/dweb-verify.json`), from the pinned nodes, not from the JavaScript reference: verification reads no user data, and the formats belong to Ant, Bee and IPFS.
  - **The generator:**
    - **Ant runs in process.** The generator builds Ant's gateway router as antd builds it, configured as Freedom configures Ant. The node-loop arms beneath it, which are private to `ant-p2p`, are ported from `behaviour.rs` at the pinned commit, over a memory chunk source holding the fixtures; a missing chunk is a miss the network corroborated;
    - **for IPFS,** Kubo v0.43.1, offline in a repository of its own, writes the fixtures (`ipfs add`, with the flags each case records) and serves the CARs and raw blocks a trustless gateway sends. freedom-ipfs's `GatewayCore`, at the commit `freedom-ipfsd` pins, answers over a memory provider holding the same blocks, each request through the native-request parser as `freedom-ipfsd` makes it;
    - **IPNS records are the generator's own.** Kubo's `name publish` reads the wall clock, so the generator signs each record itself, with a key from a seed and a validity far from any day it runs (2099, or 2000 for the expired one). freedom-ipfs's verdict on each is recorded;
    - it lives in its own Cargo workspace (`vectors/dweb-verify`), which normal CI never builds. A path-filtered workflow regenerates the file and compares it byte for byte when the generator or the file changes;
    - it records every exchange, and the core's tests replay them with no node running;
    - **everything that varies is pinned:** the exact Kubo release and the other versions are in the file's `meta`; the clock is fixed, which sets IPNS validity and feed timestamps; and every random input (encryption keys and padding, obfuscation keys, IPNS keys) comes from a seed recorded with the case. The core's tests pass the same `now`.
  - **Swarm,** recorded from Ant v0.5.71's splitter and manifest writer, and cross-checked once against Bee's for the formats Bee also writes ([Parity](#parity)):
    - files of 0, 1, 4095, 4096, 4097, 524,288, 524,289 and 67,108,865 bytes, from a single chunk to three levels of intermediate chunks;
    - each with erasure coding at every redundancy level;
    - **both shapes where Ant's splitter and Bee's differ** ([Files](#files)), at 524,289 and 67,108,865 bytes: Ant's tree with its one-reference wrapper, and Bee's tree as a case of its own;
    - manifests with an index document, an error document, nested paths, a path that is a prefix of another, prefixes longer than one fork can hold, Unicode names, every metadata field Ant reads, an obfuscated node, and an empty node with a zero reference size;
    - sequence feeds and their manifests: v1 updates; v2 updates whose latest is a manifest, served with `swarm-feed-resolved-version: v2`; a feed whose latest update names raw bytes; an empty feed;
    - **encrypted content only where the walk meets it:** a feed whose v1 update is 80 bytes, and a manifest node with 64-byte references below a plain root, each `unverifiable` with nothing released ([Encrypted references](#encrypted-references));
    - for each, every chunk by address, and Ant's answers to a request list (`/bzz/<ref>/<path>` with and without a query, `Range`, `If-Range`, `If-None-Match` and `HEAD`): status, headers and body.
  - **Swarm shapes Ant accepts that a simple reader wouldn't,** recorded from Ant too:
    - a last leaf whose authentic payload is longer than the logical length its parent gives it (the surplus-payload tail). Ant serves the logical prefix, and so must the core;
    - a leaf whose span field differs from its logical length.
- **IPFS: two kinds of expectation, kept apart.**
  - **Native-generated:** recorded from Kubo, for the gateway's CARs and raw blocks, and from `GatewayCore`, for the answers, over the same blocks. The core must reproduce `GatewayCore`'s answers exactly. They cover:
    - files of 0, 1, 262,143, 262,144, 262,145 and 10 MiB, as CIDv0 with dag-pb leaves and CIDv1 with raw leaves, balanced and trickle;
    - directories with and without `index.html`, a HAMT-sharded directory, Unicode names, an identity CID; each name with a space or a non-ASCII character requested both percent-encoded and unencoded ([The IPFS walk](#the-ipfs-walk));
    - a file whose leaves repeat, for Kubo's answers with and without `dups`; and Kubo's answers for a block and a name it doesn't hold;
    - for each request shape, the CAR Kubo sends (path, `dag-scope=entity`, `entity-bytes`) and the raw blocks;
    - IPNS records: V2-only and with legacy fields, with unknown fields and unknown signed keys, expired, for another key, without `signatureV2`, and with a legacy value that differs from the signed one;
    - **RSA-keyed IPNS records,** with seeded keys: 2,048 and 4,096 bits with the exponent 65,537, as Kubo makes them, and the bounds, 2,048 and 8,192 bits with the exponents 3 and 2^33 − 1; and a name whose record names another RSA-keyed name.
  - **The verifier's own,** marked `deviation` in the file as 0006's are, where the design deliberately differs from the pinned native reader:
    - `unixfs-sizes`: a file whose declared child size disagrees with its raw leaf, and one whose content doesn't add up to `filesize`. The native reader slices by the declared size; the core cuts the body as malformed at that point;
    - `hamt-lookup`: an entry that isn't where its hash and the bitfield point: moved to another bucket with the bitfield, or another bucket's link at its position. The native reader finds it by name; the core answers 404;
    - `dag-pb-strict`: a dag-pb node outside DAG-PB's strictness rules (an unknown field, a repeated `Data`, split `Links`, a `PBLink` field repeated, out of order or unknown). The native reader serves each, and Kubo and the core refuse it as malformed;
    - `dag-cbor-strict`: an IPNS record's signed data outside DAG-CBOR's strict profile where the native reader's decoder lets it through (an indefinite-length key, keys out of canonical order, an integer or length not in its shortest form, a NaN, an infinity, negative zero, a 32-bit float). The native reader accepts each; the core finds each unverifiable;
    - `rsa-keys`: an RSA key's protobuf encoded otherwise than libp2p's deterministic form (an unknown field, the fields out of order), which the native reader re-encodes and accepts, and a modulus of 2,041 bits, which ring accepts. The core refuses each as a failed check. A long-form DER length both refuse;
    - `ipns-legacy-fields`: a record with a non-empty `signatureV1` and none of the legacy fields. The native reader compares only the legacy fields present and accepts it; the core, as boxo, compares all five with the signed data and refuses it as a failed check.
- **Plan vectors,** which `validate_plan` and main's `plan-validation.js` both pass: `{ verify }` plans and their refusals, and what stays a `{ fetch }`: a 128-hex reference, a DNSLink name, an IPNS name with an inlined secp256k1 key. Each again with `strict`, as its 403 and message, and a `{ fetch }` plan against a strict backend refused at `trust`. A name whose contenthash is a CIDv0, and CID hosts in uppercase base32, show the canonical root; today's `{ fetch }` for a hash, CID or key host the core verifies is refused at `path`.
  - **They are in `vectors/dweb-verify-plans.json`,** written by the JavaScript generator from the cases `dweb.json`'s requests come from. Every case whose plan 0006 accepts runs again on its external backend in four forms: with verification, with verification and strict mode, with strict mode and verification off, and, for IPFS, with strict mode and a gateway without raw blocks.
  - **The expected plans are composed from the reference's outcome on that backend,** by this section's rules. No reference has a verified mode. Validation cases change one member of a plan and name the stage that refuses it.
- **Adversarial vectors,** the design's own: each takes an honest exchange and changes one thing, and states the outcome.
  - **They are in `vectors/dweb-verify-cases.json`,** which the same generator writes. Each outcome is written out by hand, from this design; the generator only lays the bytes out, signs them and checks each case's shape. Beside each, it records what the pinned nodes' own checks say of the same bytes (Ant's `cac_valid` and `soc_valid`; freedom-ipfs's `verify_block`, its CAR parser and `verify_ipns_record`), and a case where the design differs names its deviation.
  - **Checks on single pieces come first,** for `fc-swarm` and `fc-ipfs`: a chunk where a content-addressed one is needed, a feed update, a leaf against its logical length, an intermediate chunk's references, padding, levels and child geometry (checked against Ant's joiner), a mantaray node's decoding within its caps (checked against Ant's lookup), a block against its CID, dag-pb and UnixFS decoding, HAMT lookup by hash (checked against Kubo's own layout, and against GatewayCore where an entry is out of its place), CAR framing and its header's CBOR, and IPNS records with their CBOR and DER.
  - **Whole requests through the verifier follow:** a plan, the honest node of `dweb-verify.json` with one thing changed (a piece flipped, replaced or failed; a stream that ignores `Range`, ends early, stalls or names another interval; a CAR in another shape; a record served), and what the page gets: the head and body, the error before the head, or the head and exactly the bytes released before the abort. A case of several steps shares one partition, for the structure cache and the IPNS floors.
  - **Swarm:**
    - a bit flipped in a leaf, an intermediate chunk, a manifest node and a feed update;
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
  - **IPNS, RSA lies:** a key that doesn't hash to the name; a modulus of 2,040 or 8,193 bits; an even exponent, an exponent of 1, and one of 2^33 + 1; a signature a byte short, one equal to the modulus, and one over the right message with SHA-1; a record whose `pubKey` is absent under a sha2-256 name; and an ECDSA or an Ed25519 key under a sha2-256 name, which is `unverifiable`.
  - **IPNS, chains:** names whose records name the next name: three served; a fourth resolved, then `GatewayCore`'s 400; and a fifth never asked for. `GatewayCore`'s own answer over the same names is recorded beside each.
  - **IPFS, unhelpful but honest:** a CAR that ignores `entity-bytes` and sends the whole DAG; one ordered otherwise, or without duplicates; one that reads the path differently; one that ends early with boxo's marker. Each must still give the right body, through raw blocks, or a piece failure for the early end. Also `blake3`, which is `unverifiable`.
  - **Within the wire caps, against the decoders** ([Bounded decoding](#bounded-decoding)). Each input is within every byte limit, yet would amplify allocation or nesting in a naive decoder. Each must end with its stated failure, or its correct answer, with reservations never above the request's budget:
    - a maximal block of minimal repeated fields, for dag-pb links and for UnixFS `blocksizes`;
    - a valid directory just over the link cap: 65,537 sorted links to the empty identity CID, about 1.1 MiB, refused as `unverifiable` and not as malformed, so the cap's expectation doesn't imply every refusal is malformed content;
    - a maximal block of unknown fields;
    - a directory of as many entries as a block holds, served as a listing;
    - a CAR header and an IPNS record's signed data nested to the depth bound and one past it, and declaring lengths past the bytes remaining;
    - an RSA key's DER declaring lengths past the bytes remaining, and a modulus whose length field claims more than the record holds;
    - a mantaray node with maximal fork metadata and a deeply nested metadata value.
  - **Both:** the node's error body is never released; no byte of a chunk or block that failed its check reaches the page.
- **Machine tests** (`fc-dweb`, sans-I/O):
  - scripted pieces in every order the protocol allows; cancellation at every step; budgets exhausted at every reservation;
  - ranges at every leaf and block boundary; `HEAD`; `If-None-Match`; `If-Range` ignored as the bundled nodes ignore it;
  - **truncation:** a failure, a cancel and a core restart after part of a verified block was released, and while verified output is queued. The page gets a prefix of verified bytes, possibly inside the block, then the error;
  - **IPNS floors:** eviction at 1,024 names, and concurrent requests verifying records of different sequences;
  - **the structure cache, per partition:** a private partition never reads the profile's entries or another partition's; filling one partition's allowance evicts only its own entries; a ninth private partition gets no cache, and its requests fetch every chunk; `dweb.forget` leaves none of the partition's own;
  - **late results after `dweb.forget`:** a piece reply, a hashing result and a floor update for the forgotten partition leave no entry behind.
- **Stream tests** (`fc-protocol`, and through the binary): both directions on one connection, the global bound, data beyond credit, late credit, and a `vault.lock` behind 128 full incoming windows, acknowledged on time.
- **freedom-browser:**
  - the real-handler harness (0006) gains a fake Ant that serves `/chunks`, `/bytes` with `Range` and `/feeds`, and a fake trustless gateway, each honest or lying per case;
  - 0006's Range, seek, cancel, backpressure and truncation cases run again in verified mode;
  - **piece validation:** every `shell.dweb_get` path form, with namespace and path violations, refused before any dial;
  - **heads:** core heads through main's real response helper keep their `Content-Length`, and an IPFS navigation gets `small_text`;
  - **redirects:** `bzz://<root>/docs?state=1` for a directory answers 308 to `./docs/?state=1`;
  - **rings:** four batches of 64 small verified bodies completed but never read. The core finishes each batch and admits the next; main holds 256 rings and no more, the next fetch waits in admission, and reading or cancelling the bodies frees them;
  - a core restart mid-body truncates; a private partition's cache and floors are dropped on close; the probes (raw and CAR, raw only, neither); the labels;
  - **the default:** a new external backend verifies, a loopback one included, until the user turns it off;
  - **strict mode:** off by default; with it on, each refused shape gets its 403 and message, verified and `latest_asserted` content still loads, and the bundled nodes are untouched;
  - **the error page:** a request whose first `Accept` token is `text/html` (a navigation, a frame, and a `fetch` sending that `Accept`) gets the page for an error of the core's or main's, with the same status, in every mode; an image, a `fetch` with the default `Accept` and `permission-manifests.js` get the JSON body; a node's own error answer and a truncation after the head are unchanged;
  - **no exact signal:** a test that pins what the handler receives (no `Sec-Fetch-*` header, `destination` `""`, `mode` `"cors"`), so a later Electron that adds them is noticed and the rule can move to them.
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
| memory, per request | 8 MiB, reserved before allocation: its windows, leaves and blocks in flight, the walk's parsed nodes, its queue of blocks to fetch, a directory's entries and its listing's page, each CAR section's hash job, the path's strings | fewer pieces in flight; a walk that can't fit at all is `unverifiable` |
| memory, the dweb thread | 128 MiB in all, the structure cache included | new requests `busy` (503); admitted work waits up to 10 s, then ends `busy`: 503 before the head, a truncation after |
| the structure cache | one per partition, each its own LRU: the profile's 8 MiB; each private window's 2 MiB, for at most 8 private windows at once (16 MiB); 24 MiB in all | least recently used first, within the partition only; a private window past the eighth has none until one closes; `dweb.forget` drops a partition's |
| an IPFS block | 2 MiB (freedom-ipfs's limit) | `verification_failed` |
| a Swarm manifest node | 1 MiB (Ant: 32 MiB) | `unverifiable` |
| Swarm walk | 8 levels of intermediate chunks (Bee's cap); 64 manifest nodes per lookup; one feed per walk | `unverifiable` |
| IPFS walk | 64 levels of file DAG; 8 HAMT levels per name (fanout 256); 256 path segments; 4 IPNS records | `unverifiable`; past the fourth record, `GatewayCore`'s 400 |
| a CAR header; a CAR section | 64 KiB; 2 MiB plus the CID | `verification_failed` |
| decoded structure | 65,536 links, and as many `blocksizes` entries, per dag-pb node; CBOR nested 8 levels; 256 forks per mantaray node | `unverifiable` |
| an IPNS record | 10 KiB | `verification_failed` |
| an IPNS record's RSA key | a modulus of 2,048 to 8,192 bits; an odd exponent from 3 to 2^33 − 1; one signature check per record | `verification_failed` |
| IPNS sequence floors | 1,024 names, in memory | least recently used first |
| hashing pool | 2 threads | jobs queue in the dweb thread, under the request's memory |

## Upstream

- **Reusing Ant's crates** (MIT OR Apache-2.0, which `deny.toml` allows from freedom-hq):
  - `ant-crypto` is sans-I/O (k256, sha3, getrandom, thiserror) and has BMT, CAC, SOC and decryption. But it pins k256 0.13 where the core uses 0.14, and `fc-swarm` already has BMT. So `fc-swarm` implements the checks itself and tests them against `ant-crypto` as a dev-dependency.
  - `ant-retrieval`'s joiner, mantaray and feed code is async over tokio, and its parsers are private (`Node::unmarshal`, `parse_intermediate`). `fc-swarm` reimplements them as sans-I/O state, held to vectors from Ant.
- **Ant:** nothing is required for what is built.
  - [freedom-hq/ant#233](https://github.com/freedom-hq/ant/issues/233) asks for a way to fetch many raw chunks in one request. It would make the [encrypted path](#appendix-the-encrypted-path-not-built) practical, and cut the plain walk's round trips too. Encrypted references are revisited when it lands (decision 8).
  - A ranged read that carries each leaf's chunk path isn't proposed until the [gates](#gates) show the walk costs users time.
- **freedom-ipfs:**
  - **`fc-ipfs` carries its own bounded decoders** ([Bounded decoding](#bounded-decoding)). The native ones (`freedom-ipfs-unixfs/src/lib.rs:42`–`85`, `1100`–`1110`) are private, and they allocate while decoding, so they couldn't run under the core's reservations even if they were public.
  - **freedom-ipfs adopts the core's reader later** (decided, [Decisions](#decisions), 11), so there is one reader, not two.
    - **What:** `fc-ipfs`'s bounded dag-pb, UnixFS and HAMT reader, with its caps, its strict DAG-PB and its stricter size and HAMT rules. The native node and verified mode then read files and directories the same way by construction, and deviations `unixfs-sizes`, `hamt-lookup`, `dag-pb-strict` and `decoder-caps` describe both.
    - **When:** freedom-ipfs pull requests of their own, into its integration branch, once the reader has merged here ([Implementation steps](#implementation-steps), 8). Whether it changes what the native node answers for malformed content, and how, is that pull request's to state.
- **What `fc-ipfs` takes from freedom-ipfs: nothing at run time** (decided: one freedom-ipfs pin per repo, `freedom-ipfsd`'s). `fc-ipfs` carries its own CID, multihash and block check, which are small, and holds them to `freedom-ipfs-core`'s `verify_block` through the native verdicts the vectors record. That keeps the logic crates free of freedom-ipfs's runtime dependencies, and lets freedom-ipfs adopt the core's reader later (decision 11) without a dependency cycle. It doesn't take freedom-ipfs's whole-buffer CAR parser either: the core reads CARs as streams. Not `freedom-ipfs-unixfs`'s resolver, which pulls blocks through a synchronous provider, and so can't suspend while main fetches.
- **The `rsa` crate** (MIT OR Apache-2.0), for RSA-keyed IPNS names (decided, [Decisions](#decisions), 9):
  - **For verification only.** `fc-ipfs` builds an `RsaPublicKey` from the modulus and exponent its own DER reader parsed, with `RsaPublicKey::new_with_max_size` at 8,192 bits (the crate's own default is 4,096), and checks a signature with `Pkcs1v15Sign` for SHA-256. Nothing in the core generates, loads or holds an RSA private key, so no private-key operation exists to be timed. The crate's default features (`std`, and `pem`, which brings its PEM parsers) are off; `u64_digit`, a speed option, is on.
  - **Pinned exactly, at 0.9.10,** the latest stable release, as `freedom-radicled`'s lock has it:
    - it brings a second RustCrypto generation into the core's graph (`digest` 0.10, `der` 0.7, `spki` 0.7, `pkcs1` 0.7, `pkcs8` 0.10, `signature` 2, `num-bigint-dig`: about two dozen crates). `fc-ipfs` hashes with the core's `sha2` 0.11 and hands the crate the digest with SHA-256's `DigestInfo` prefix, so nothing of the core's moves to the older generation;
    - 0.10.0, on the core's generation, has only release candidates (0.10.0-rc.19, 2026-10-06), which aren't taken. The pin moves to 0.10.0 when it is stable, as a reviewed change of its own.
  - **RUSTSEC-2023-0071** (the Marvin attack: timing that leaks the private key through RSA decryption and signing) covers every release, so `cargo deny` needs a reviewed exception.
    - **No release fixes it,** checked on 2026-10-23. The advisory lists no patched version; on 2026-09-14 it recorded 0.9.10 and the 0.10 release candidates as still affected, and 0.10.0-rc.19, released on 2026-10-06, is too. The tracking issue (RustCrypto/RSA#626) and the two pull requests toward a fix (#680, implicit rejection for PKCS#1 v1.5 decryption; #702, blinding the default decryption paths) are open.
    - **Why the exception holds:** the advisory concerns operations with a private key, and the core makes none. It only checks signatures, with public keys taken from records.
    - **The entry,** in the core's `deny.toml`, worded as `freedom-radicled`'s is: a comment naming the crate, its version and the one use, then `{ id = "RUSTSEC-2023-0071", reason = "no RSA private-key operation is ever made: fc-ipfs only verifies IPNS record signatures with public keys" }`.
    - It is revisited when a fixed release ships, and before the crate is used for anything but verification.

## Parity

- **Unverified mode is today's,** byte for byte: verification off, a gateway without support, an encrypted reference, a DNSLink name, and every bundled backend plan exactly as 0006 does. Two listed deviations change it:
  - strict mode, when the user turns it on, refuses the unverified plans (`strict-mode`);
  - a navigation's error answer from the core or main becomes the error page, in every mode (`navigation-error-page`).
- **Ant's formats are Bee's, checked once, but for one shape.** Bee's own writers at a93fb7a7 reproduce the vectors' references: Bee's pipeline splitting the same content at each redundancy level, and the manifest code of Bee's upload handlers (`bzz.go`, `dirs.go`, `feed.go`). That check is a one-off Go program beside the generator, not run in CI; its result is in the vectors' `meta`. 63 of 65 references agree. The two that don't are the sizes where Ant's level-0 splitter wraps a lone reference ([Files](#files)), and Bee's references for them are the vectors' Bee-shaped cases.
- **A verified response is the bundled node's,** not the external node's: what Ant v0.5.71 answers for `bzz:`, and what freedom-ipfs's `GatewayCore` answers for `ipfs:` and `ipns:` at the commit `freedom-ipfsd` pins, over the same content. The vectors hold the core to it, header by header, with the exceptions listed in [Heads](#heads).
- **Qualified: for content both accept.** Where the verifier is deliberately stricter than the pinned reader, the difference is a listed deviation with vectors of its own, kept apart from the native-generated ones ([Tests first](#tests-first)):
  - `unixfs-sizes` and `hamt-lookup`, for malformed UnixFS files and HAMT directories;
  - `dag-pb-strict` and `dag-cbor-strict`, for dag-pb nodes and IPNS signed data outside their codecs' strictness rules;
  - `soc-references`, for single-owner chunks off the feed path;
  - `decoder-caps` and `manifest-node-cap`, for structure past the decoders' caps;
  - `rsa-keys`, for RSA keys encoded otherwise than libp2p's deterministic form, or of 2,041 to 2,047 bits;
  - `ipns-legacy-fields`, for IPNS records whose legacy fields the native reader compares only where present;
  - `encrypted-in-walk`, for encrypted references a verified walk meets;
  - a Swarm leaf whose authentic payload is shorter than its logical length, which the core doesn't support.

  Within the supported formats and the stated limits, these never apply to well-formed content. Content that is valid but outside them stays `unverifiable`: a SOC off the feed path, an encrypted reference inside a walk, structure past a decoder or manifest cap. It isn't reported as malformed.
  - **Once freedom-ipfs adopts the core's reader** ([Upstream](#upstream)), `unixfs-sizes`, `hamt-lookup`, `dag-pb-strict` and `decoder-caps` describe the native node too, and stop setting the two modes apart. For `dag-pb-strict` that is sooner: freedom-ipfs#72 and #73 make the native decoder strict, and the deviation ends when the `freedom-ipfsd` pin picks them up.
  - **One difference the other way:** verified mode decodes a percent-encoded path, which the native node's request parser, at `freedom-ipfsd`'s current pin, doesn't (`ipfs-path-decoding`, [The IPFS walk](#the-ipfs-walk)). Names the native node misses load in verified mode. It is fixed at freedom-ipfs `9700f548`, which the next `freedom-ipfsd` pin picks up.
  - **Why the bundled node, not the external one:** the external node's headers are the assertions being replaced, and it may be a different implementation (a reused Bee, a Kubo, a public gateway). One rule per scheme, whatever the backend, is also what a user switching modes expects.
- **The same as today, per piece:** the request headers Swarm needs, the retry table and its delays, the header deadline, the body idle bound, the transport and its proxy and onion rules, the Ant guard, fetch admission, the dial failure statuses, and the security response operations.

## Deviations

| ID | Today | After | Effect |
|---|---|---|---|
| `verified-content` | an external node's answer passes whole | checked against the root, by default, for every external node, a loopback one included; a mismatch is a 502 before the head, a truncation after it | a lying or broken node can't change what a page receives |
| `verified-heads` | the external node's headers, after the response operations | the core's, by the bundled node's rules | `Content-Type`, `ETag`, caching headers, listings and redirects follow Ant or `GatewayCore`; the external node's own headers go |
| `node-error-bodies` | a node's error body reaches the page | the core's fixed `{ code, message }`, with the node's status | the status stays; the text is the core's |
| `verified-requests` | one request to the node per page request | chunk, byte-stream and feed requests (Ant); CAR, raw block and record requests (gateway) | more requests reach the node, and its logs show chunk addresses and CIDs |
| `verified-latency` | the node walks the path | the core walks it, piece by piece | time to first byte rises by the walk's round trips ([Performance](#performance)) |
| `core-data-path` | a core restart fails only new plans | it also truncates verified bodies | |
| `verify-head-deadline` | no bound before the head beyond each attempt's (Ant) or none (the gateway) | 360 s to the head | a walk that can't finish in six minutes gets 504 |
| `gateway-probe` | `bafkqaaa` | then a raw and a CAR probe of it, when verification is on | a gateway without raw blocks serves unverified, and the nodes panel says so |
| `structure-cache` | the core holds no content | verified Swarm structure in a cache per partition, each with its own LRU: 8 MiB for the profile, 2 MiB for each of at most 8 private windows, 24 MiB in all | no partition's loads evict another's entries; a ninth private window loads uncached |
| `multi-range` | Ant answers several ranges with `multipart/byteranges` | 200 with the whole body | only clients that ask for several ranges see it |
| `manifest-node-cap` | Ant loads a manifest node of up to 32 MiB | 1 MiB | a manifest with a larger node is `unverifiable` |
| `encrypted-in-walk` | an external node serves the encrypted reference a manifest node or a feed update names | a verified walk that meets one is `unverifiable`; a 128-hex reference in the URL keeps today's fetch, `unverified` | content with encrypted parts below a plain root or a feed doesn't load in verified mode |
| `ipns-floor` | the gateway resolves an IPNS name as it likes | a record below the highest sequence verified in the session is refused while that one is valid | a gateway that rolls a name back within a session gets a 502 |
| `soc-references` | an external node may answer a reference with a single-owner chunk, and what it serves then rests on that chunk | the core accepts one only as a feed update; elsewhere it is `unverifiable` | content reached through a SOC outside a feed doesn't load in verified mode |
| `unixfs-sizes` | the native reader (the parity target) slices a child by its declared size | a declared size that disagrees with a raw leaf, or content that doesn't add up to `filesize`, cuts the body as malformed | only malformed files differ |
| `ipfs-path-decoding` | the native node takes a percent-encoded path undecoded, so a name with a space or a non-ASCII character isn't found | each segment decoded once; one that decodes to `.`, `..`, or to anything holding `/`, `\` or NUL, or to invalid UTF-8, is a 400 | such names load in verified mode; fixed at freedom-ipfs `9700f548` (freedom-ipfs#58), and closes when the next `freedom-ipfsd` pin picks it up |
| `hamt-lookup` | the native reader finds a HAMT entry by its name | the core follows the name's hash and the bitfield | an entry that isn't where its hash points is a 404; only malformed directories differ |
| `ant-lone-reference` | Ant, bundled or external, serves a tree its level-0 splitter wrote with a level's lone reference wrapped, with the wrapper's first payload bytes where the last leaf's content belongs: the wrong bytes ([freedom-hq/ant#234](https://github.com/freedom-hq/ant/issues/234)) | the same answer, verified: the wrapper passes the leaf check | none: parity with the bundled Ant, until Ant's fix ships and the pin moves. Bee's tree for the same content, which carries the reference unwrapped, is served as its content |
| `ant-raw-feed-answer` | Ant answers a bare request for a feed whose latest update names raw bytes with the feed manifest's own node, not the content ([freedom-hq/ant#235](https://github.com/freedom-hq/ant/issues/235)) | the same answer, labelled `verified`: those bytes are the URL's reference's own | none: parity with the bundled Ant, until Ant's fix ships and the pin moves. An update naming an encrypted reference is `unverifiable` instead |
| `dag-pb-strict` | the native reader (`prost`) takes a dag-pb node outside DAG-PB's strictness rules: an unknown field, a repeated `Data`, `Links` on both sides of `Data`, a `PBLink` field repeated, out of order or unknown | refused as malformed, as Kubo (go-codec-dagpb) refuses it ([Bounded decoding](#bounded-decoding)) | only nodes no DAG-PB writer makes differ; ends when freedom-ipfs#72 and #73 reach the `freedom-ipfsd` pin |
| `dag-cbor-strict` | the native reader takes an IPNS record whose signed data is outside DAG-CBOR's strict profile in ways its decoder lets through: an indefinite-length key, keys out of canonical order (in the record's map or a nested one), an integer or a length not in its shortest form, a NaN, an infinity, negative zero, a 32-bit float | the strict profile at every level ([Bounded decoding](#bounded-decoding)); such a record, validly signed, is `unverifiable` | only records no DAG-CBOR writer makes differ |
| `decoder-caps` | the native reader decodes any structure a block holds | at most 65,536 links and `blocksizes` entries per dag-pb node, and CBOR nested at most 8 levels | structure past the caps is refused as `unverifiable`. That is mostly degenerate encodings, but also rare valid content such as a directory of more than 65,536 compact identity-CID links |
| `rsa-keys` | the native reader hashes its own re-encoding of an RSA key, so it takes a key encoded another way; ring takes a modulus of 2,041 to 2,047 bits | the record's `pubKey` must hash to the name as it arrived, in libp2p's deterministic encoding and canonical DER, and the modulus is at least 2,048 bits, as go-libp2p requires | only keys no libp2p implementation writes differ: such a record fails its check |
| `ipns-legacy-fields` | the native reader compares an IPNS record's legacy fields with its signed data only where each is present | once `signatureV1` or the legacy `value` is non-empty, all five must equal the signed data, an absent one read as its protobuf default, as the IPNS record specification and boxo require | only records no IPNS writer makes differ: such a record fails its check |
| `strict-mode` | none | a profile setting, off by default, that answers every unverified external request with a 403 that says why | with it on, DNSLink names, encrypted references, IPNS names with other inlined keys, and backends that don't verify stop loading |
| `navigation-error-page` | a failed navigation shows the `{ code, message }` JSON the core or main wrote | an HTML error page in plain words, with the same status, for a request whose first `Accept` token is `text/html` | every navigation and frame gets the page, and so does a `fetch` or subresource sending that `Accept`; any other request, and `permission-manifests.js`, keeps the JSON; a node's own answers, and the bundled node's bodies the core reproduces, are unchanged |

## Implementation steps

1. **Tests first:** the generators and `vectors/dweb-verify.json`, RSA-keyed records included; the plan vectors, strict mode's among them; the adversarial vectors; the fake Ant and fake trustless gateway in freedom-browser's harness.
2. **Formats, sans-I/O:**
   - `fc-evm`: signature recovery, for single-owner chunks;
   - `fc-swarm`: chunk and SOC checks (the empty chunk included; SOCs only where a feed update is expected), intermediate chunks with erasure coding, logical leaf lengths from the parent, mantaray nodes and lookup (empty nodes included, and 64-byte references recognized so the walk refuses them), feed identifiers. Encrypted chunks aren't built ([Encrypted references](#encrypted-references));
   - `fc-ipfs` (new, logic): CIDs and the native node's block check; the bounded protobuf, CBOR and DER readers, with their counting first pass; a streaming CAR reader; dag-pb and UnixFS with the stricter size rules; hash-directed HAMT lookup; offsets; IPNS records, V2-only included, with Ed25519 and RSA keys;
   - **new dependencies,** each justified in its PR (AGENTS.md rule 7): none for CIDs and blocks, which `fc-ipfs` writes itself (above); `mime_guess` 2.0.5, for `GatewayCore`'s types; `ed25519-dalek`, already on the preferred list; `rsa` 0.9.10, pinned exactly, for verification only, with its `cargo deny` exception ([Upstream](#upstream)). MurmurHash3 and the DAG-CBOR subset an IPNS record needs are small enough to write, against vectors.
3. **`fc-dweb`:** verify plans (with their `query`) and their validation; what stays a `{ fetch }` (encrypted references, DNSLink names, other inlined keys); strict mode's error plans and checks; the verifier machine, with its walks, heads, ranges (the exact-206 and whole-200 policies), conditionals and failures; the structure cache with its partition epochs, one short-lived cache per private window; the IPNS floors.
4. **`fc-protocol`:** streams in both directions, protocol version 2 (on #72).
5. **`freedom-cored`:** the dweb thread and hashing pool, `dweb.verify`, `shell.dweb_get`, `dweb.forget`, admission, budgets and cancel, with tests through the binary.
6. **freedom-browser:**
   - verify plans in validation and the handler, `dweb-shell.js`, and stream frames on the core's connection;
   - the verification setting, on by default, and the probe;
   - strict mode: the profile setting, off by default, and `strict` in the captured backend;
   - the error page for a failed navigation;
   - `dweb.forget` when a private window's partition closes;
   - the labels and the nodes panel;
   - then the [gates](#gates).
7. **The default:** on for every external backend (decided, 1). Verification ships on once the gates pass; a gate that fails brings the default back to the user with its numbers.
8. **freedom-ipfs:** pull requests of its own, into its integration branch, that adopt `fc-ipfs`'s bounded reader once the reader has merged here (decided, 11; [Upstream](#upstream)).

## Decisions

Each was decided by the user on 2026-10-23. The questions and their options stay, as the decisions' rationale.

1. **The default:** verification on for every external backend (recommended), or opt-in?
   - **Decided: on by default, for every external backend** ([Modes](#modes)). It ships on once the [gates](#gates) pass; a gate that fails brings this back to the user with the numbers.
2. **A stricter mode:** should a profile be able to refuse unverified external content outright, as `blockUnverifiedEns` gates unverified names? Under it, DNSLink names, RSA-keyed IPNS names and gateways without raw blocks would stop loading.
   - **Decided: yes, as a profile setting, off by default** ([Strict mode](#strict-mode)). Under it, DNSLink names, encrypted Swarm references, IPNS names with an inlined key other than Ed25519, and backends that don't verify (verification off, or a gateway without raw blocks) stop loading, each with a 403 that says why. RSA-keyed IPNS names are verified (9), so they still load.
3. **A node that fails verification:** keep using it and fail only the requests that fail (proposed), or stop using it after repeated failures until the user acts?
   - **Decided: it stays in use; only its failing requests fail** ([Failures](#failures)). The nodes panel's notice informs; it switches nothing.
4. **Wording and place:** the trust panel's content row ([Labels](#labels)) and the error texts ([Failures](#failures)). Should a failed navigation get an error page instead of today's JSON body?
   - **Decided: a failed navigation shows a proper error page in plain words, not the raw JSON body** ([The error page](#the-error-page)). The trust panel's wording and the texts stay as proposed, the user's to change.
5. **The user's own node:** a loopback Bee or Kubo the user runs is often as trusted as the bundled node. Verify it anyway (proposed: the cost on loopback is small), or offer "trust this node"?
   - **Decided: verified anyway** ([Modes](#modes)). There is no "trust this node" switch; the per-node setting can still turn verification off.
6. **The bundled nodes:** should the core also check their output, as defense in depth, at the cost above?
   - **Decided: no.** The bundled nodes check what they retrieve, and their content stays `node_asserted` ([Goals and non-goals](#goals-and-non-goals)).
7. **DNSLink:** accept the `unverified` label, or have the core resolve DNSLink itself through DNS-over-HTTPS exchanges main performs, so the root comes from a resolver Freedom chooses rather than from the gateway?
   - **Decided: DNSLink names stay `unverified` for now** ([IPNS and DNSLink](#ipns-and-dnslink)). Resolving DNSLink in the core over DNS-over-HTTPS, with two independent resolvers that must agree, is noted as a possible later step, not planned work.
8. **Encrypted references:** verify them chunk by chunk ([Encrypted references](#encrypted-references), about 260 requests per MiB), or leave 128-hex references `unverified` until Ant offers something better, such as a batch chunk endpoint?
   - **Decided: encrypted references stay `unverified` from external nodes** ([Encrypted references](#encrypted-references)). The chunk-by-chunk path isn't built for now; it stays described in the [appendix](#appendix-the-encrypted-path-not-built). [freedom-hq/ant#233](https://github.com/freedom-hq/ant/issues/233) asks Ant for a batch raw-chunk endpoint, and the question is revisited when it lands. An encrypted reference met inside a verified walk is `unverifiable`, never a fallback.
9. **RSA-keyed IPNS names:** add an RSA verifier, or keep them `unverified`? The `rsa` crate would be a new dependency, and `cargo deny` may need a reviewed exception for its timing advisory (RUSTSEC-2023-0071), which concerns private-key operations, not verification. Whether the current release still carries the advisory, and how many names use RSA keys, are unverified.
   - **Decided: add an RSA verifier,** so RSA-keyed names are verified like Ed25519-keyed ones ([IPNS and DNSLink](#ipns-and-dnslink)):
     - the `rsa` crate, for verification only, pinned exactly at 0.9.10, the latest stable release, with a reviewed `cargo deny` exception for RUSTSEC-2023-0071 ([Upstream](#upstream));
     - libp2p's encoding (a PKIX DER key inside the record's `pubKey`), signature scheme (RSASSA-PKCS1-v1_5 with SHA-256) and key sizes (2,048 to 8,192 bits), with the sources [IPNS and DNSLink](#ipns-and-dnslink) cites;
     - **the advisory, checked on 2026-10-23:** no release fixes it. 0.9.10 is the latest stable release and 0.10.0-rc.19 the latest release candidate, and the advisory lists no patched version.

     How many names use RSA keys remains unmeasured; RSA was IPNS's key type before Ed25519 (the IPNS record specification, *Key Types*).
10. **Private windows:** a structure cache per private partition (proposed), or none?
    - **Decided: each private window gets its own short-lived structure cache** ([The structure cache](#the-structure-cache)), with its own allowance and eviction, dropped when the window closes.
11. **Upstream:** `fc-ipfs` can't share the native decoders as they are, since they allocate before anything can be reserved. Should freedom-ipfs adopt a bounded reader shared with `fc-ipfs` (its decoders, and its stricter size and HAMT rules), so both modes read files and directories the same way by construction rather than differing on malformed content?
    - **Decided: yes, later.** freedom-ipfs adopts the core's bounded sans-I/O block reader in freedom-ipfs pull requests of its own, after the core's reader has merged, so there is one reader, not two ([Upstream](#upstream); [Implementation steps](#implementation-steps), 8).

## Appendix: the encrypted path (not built)

Kept for when encrypted references are revisited ([Decisions](#decisions), 8), with [freedom-hq/ant#233](https://github.com/freedom-hq/ant/issues/233) or anything else that makes it practical. Nothing here is built, tested or bounded today.

- **The format:** a reference of 64 bytes, the chunk's address and a key. A chunk is `encrypted span ‖ encrypted payload`, the payload always padded to 4,096 bytes. Segment `i` is XORed with `keccak256(keccak256(key ‖ u32_le(i + c)))`, with `c` = 0 for the payload and 128 for the span (`ac/encryption.rs:57`–`96`; Bee `pkg/encryption`). Intermediate chunks hold 64 references of 64 bytes, so a level-1 chunk covers 256 KiB: 4.0 level-1 chunks per MiB of body.
- **The plaintext can't be checked against the address.** The padding is random, and so is each chunk's key, so the ciphertext can't be rebuilt from what `/bytes` returns.
- **So the core would take every chunk from `/chunks`,** check it as a CAC against its address, and decrypt it itself with the key from its reference, up to 8 chunk requests at once. That is about 260 requests per MiB (256 leaves and 4 intermediates) through today's API. On a loopback node with cached chunks, an estimated 10–30 MiB/s; across a network, far less.
- **The structure cache** would hold an encrypted tree's ciphertext, never its plaintext: the key from the reference that names a chunk is applied on every use. So a reference with another key at the same address couldn't read anything from the cache that it couldn't fetch.
- **What building it would add:**
  - `fc-swarm`: encrypted chunks and 64-byte references, in intermediate chunks, manifest nodes and v1 feed updates;
  - plans: 128-hex references as `{ verify }` plans, labelled `verified`, where they are a `{ fetch }` today; and naming decoding a 64-byte Swarm contenthash, which it answers as unsupported today;
  - vectors: every Swarm format case encrypted too, a bit flipped in an encrypted chunk, and an encrypted tree's ciphertext reused from the cache under the right key and nothing under another key at the same address;
  - a gate: an encrypted reference measured beside the plain tree's figures;
  - a deviation in place of `encrypted-in-walk`: the core fetching an encrypted reference's chunks and decrypting them itself, where the node decrypts today.
