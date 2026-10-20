# 0004: Name resolution sessions in the core

**Status:** proposed. Builds on [0001](0001-freedom-cored.md) (process, framing, deadlines) and [0003](0003-naming.md) (codecs and the resolution architecture). It specifies the protocol that 0003's [architecture](0003-naming.md#resolution-architecture) left open, and answers every item of [What design 0004 must satisfy](0003-naming.md#what-design-0004-must-satisfy) (see [Traceability](#traceability)).

**Ground truth** is the replay harness: `vectors/naming-replay.json` runs the pinned resolvers through scripted worlds, and its scenario IDs are cited below in `code`.
- **The oracle:** freedom-browser `fb540328` (the `meta` of the vectors), with its ethers 6.17.0 and `@sinonjs/fake-timers` 15.4.0.
- **Conflicts:** where this document and a vector disagree, the vector wins and the document has a bug.

## Summary

A name lookup becomes a **session** in `freedom-cored`. The session is a sans-I/O state machine in `fc-naming`:
- **main → core:** a `naming.*` request starts or joins a session.
- **core → main:** the session asks main for each I/O it needs, using 0001's support for requests in both directions:
  - `shell.rpc`, `shell.tezos`, `shell.gateway`: HTTP;
  - `shell.verified`: a whole Myotis or Colibri operation through today's adapters;
  - `shell.prefetch`.
- **The core decides everything else:** which endpoints, which block, deadlines, quarantine, agreement, trust labels, the result, and its cache lifetime.

Main stays a transport and adapter host:
- it maps opaque endpoint references to URLs;
- it performs HTTP through the Electron session's network stack;
- it runs the verifiers' adapters unchanged;
- it turns replies into today's IPC result shapes.

## Goals and non-goals

**Goals**
- **Parity** with the pinned resolvers, observable through the replay vectors: the requests made, their order and timing, cancellations, cache lifetimes, and results with key presence and order.
- **Every deviation** is listed in [Deviations](#deviations) with its failure and cache behavior and a boundary vector.
- **Bounded resources:** every queue, cache, answer, request, decode, session and reply has a byte, count or time bound that sits above every valid case, with a defined result when exhausted.
- **The core is never given an endpoint URL** (0003 decision 3, [as refined below](#secrets)). Server diagnostics stay out of its logs, replies and crash reports.

**Non-goals**
- **New trust semantics** (0003's open question 1), and new record types.
- **Myotis' and Colibri's own networking** (roadmap 3.3): their adapters run in main as today.
- **Mobile drivers.** The machine is platform-neutral; its drivers on iOS and Android come later.

## The protocol

### Methods main calls

All accept caller kinds `chrome` and `shell`. Each resolution carries `private: bool`: the core redacts the name in its logs (`redactForLog`), as today's private-window handlers do.

| Method | Params | Result | Replaces |
|---|---|---|---|
| `naming.configure` | a [configuration snapshot](#configuration) | `{ ens, tezos, lifecycle }` (the new generations; `reset: "providers"` advances the lifecycle) | registry reads, `invalidateCachedProvider` |
| `naming.availability` | `{ ready, enabled }` | `{ lifecycle }` | `myotisManager.onAvailabilityTransition` |
| `naming.resolve_content` | `{ name, private }` | a [resolution reply](#replies) | `resolveEnsContent` |
| `naming.resolve_address` | `{ name, chain_id, private }` | a resolution reply | `resolveEnsAddress` |
| `naming.resolve_reverse` | `{ address, chain_id, private }` | a resolution reply | `resolveEnsReverse` |
| `naming.resolve_tezos` | `{ name, private }` | a resolution reply | `resolveTezosDomain` |
| `naming.invalidate_content` | `{ name }` | `{ evicted: bool }` | `invalidateEnsContent` |
| `naming.invalidate_tezos` | `{ name? }` | `{}` | `invalidateTezosDomain` |

### Admission

This section amends 0001's admission rules for naming.
- **A separate pool:** naming requests don't take 0001's 64 vault-work slots. They have their own limits: at most **32 running sessions** and **256 waiting callers** in all, and at most **64 callers per session**.
- **Every caller counts,** including one answered from the cache or one that joins a running session. The core answers a request over a limit with `busy` at once and keeps nothing for it.
- **The writer:** the naming thread has its own share of 0001's writer, 8 MiB of queued frames, apart from the event loop's. Naming traffic therefore never takes the room that vault and control replies need. Past its share, naming's replies and cancels wait in the naming thread, and its `shell.*` requests wait in their FIFO, where a cancel still removes them; this is never a protocol failure. At shutdown, the event loop closes naming's request admission before it acknowledges, so no `shell.*` request follows the acknowledgement; the waiting replies and cancels still go to the writer, within 0001's bounded drain, and queued requests are dropped unsent. Main itself holds at most 256 naming requests outstanding, which bounds the replies that can wait.
- **The reader:** a frame forwarded to the naming thread keeps its reader credit until that thread has handled it. 0001's bound on unhandled frames therefore covers naming's mailbox too, and that bound counts bytes as well as frames.
- **Arguments:** an `attempts_used` of three or more, or a `deadline_ms` over 120 s, is `invalid_argument`. Main never sends either.
- **One terminal reply per caller:** a result, `resolution_failed`, `cancelled` or `deadline`. The naming thread decides races between `cancel`, the caller's deadline and the result in the order it processes them; the first wins.
- **Two deadlines:**
  - **The caller's:** 120 s from its admission, or the `deadline_ms` it carries ([Generations](#generations)). On expiry that caller alone gets `deadline` and is detached.
  - **The session's:** 120 s from the session's start. On expiry the session ends: its outstanding I/O is cancelled, its remaining callers get `deadline`, and nothing is cached. This is deviation `overall-deadline`; main's hang watchdog follows 0001: deadline + 15 s.
- **Cancel and caller deadlines detach a caller.** The session keeps running without callers, as today's shared promise does, and caches its result within its own deadline and budget. It still counts as a running session.
- **Threading:** the naming machine runs on its own thread in `freedom-cored`, so vault control traffic never waits on naming work. 0001's I/O task only forwards frames.

### Generations

Three counters, each owned by the core and only ever increasing within a core process:

| Generation | Advanced by | Scopes |
|---|---|---|
| `ens` | `naming.configure` with an ENS change | ENS sessions, caches, pool, anchor; `shell.rpc`, `shell.gateway`, `shell.prefetch` |
| `tezos` | `naming.configure` with a Tezos change | Tezos sessions and caches; `shell.tezos` |
| `lifecycle` | `naming.availability`, and `reset: "providers"` (today's `clearEnsResolutionCaches`) | ENS attempts; `shell.verified` |

- **Requests:** every `shell.*` request carries the generations of the attempt that made it. Main answers a request whose generation is no longer current with `stale_generation` and performs nothing. An endpoint removed from the configuration is never contacted again, and a Tezos request is unaffected by an ENS change.
- **A configuration change ends its scope's sessions:** when `naming.configure` advances the ENS (or Tezos) generation, that scope's running sessions end at once. Their outstanding I/O is cancelled, and nothing of theirs runs again, so they write no shared state: caches, quarantine, the anchor, Tezos discovery, the shuffle, prefetches. A late reply can't recreate the state of an endpoint that is gone. Their callers' replies carry the generations they ran under: `resolution_failed`, `Name resolution configuration changed while resolving <name>`, which main discards and resubmits with the attempts left. In the reference, such a resolution runs on, and its result is cached and returned.
- **Replies:** every resolution reply carries the generations its result was computed under, and `attempts`, the lifecycle attempts it used.
- **Attempts:**
  - **One budget:** a caller has three lifecycle attempts in all (`resolveAcrossStableLifecycle`), whether the core restarts an attempt or main sends the request again.
  - **Overtaken replies:** a reply can still be overtaken in the pipe. When a reply's generation is older than main's current one for that scope, main discards it. It sends the request again only with attempts left, carrying `attempts_used` and the caller's remaining `deadline_ms`. Otherwise it reports today's `Myotis availability changed repeatedly while resolving <name>`.
  - **A resubmitted request:** the core starts it with the remaining attempts and deadline. One whose `attempts_used` is already three fails at once with the "changed repeatedly" error, as it would at a restart (Tezos: `Tezos configuration changed repeatedly while resolving <name>`).
  - **Immediate replies** (a cache hit, `busy`, an invalid input) carry the `attempts` the caller came with, so a resubmission never regains spent attempts.
  - **Allowances are per caller.** A caller's attempts are counted from its join point, including the attempt it joined. Before the session starts another attempt, each caller that has used its allowance fails with the "changed repeatedly" error, and other callers are unaffected. The session restarts while any caller has allowance left; without callers it uses its own three attempts from its start.
- **Late replies:** a `shell.*` reply for a request the core has cancelled is valid, because main sends exactly one terminal reply per request. The core drops it. A second reply for one request is a protocol error (0001).
- **A core restart** (crash or hang watchdog) loses the attempt accounting, so nothing is resubmitted:
  - every pending naming request fails with today's thrown-resolution shape, message `Name resolution restarted` (deviation `core-restart`);
  - main sends `naming.configure` and `naming.availability` to the new core before any new request;
  - main abandons the dead core's `shell.*` work and cancels it locally.
  - Resolutions are reads, so there is nothing to reconcile.

### Requests the core makes

Main implements these. Each carries its attempt's generations and a `deadline_ms`, the time left until its session's deadline; a request still queued at that deadline completes in the core as `timeout`, unsent. The core cancels with 0001's `cancel`; main aborts and still sends one terminal reply.

| Method | Params | Main does | Reply |
|---|---|---|---|
| `shell.rpc` | `{ endpoint, body }` | one exchange with ethers' `FetchRequest` policy: redirects, 429 back-off, expiry (see [Transport](#transport)) | `{ status, body }` or a [transport error](#transport-errors) |
| `shell.tezos` | `{ endpoint, method, path, body? }` | GET or POST `endpoint URL + path` | `{ status, body }` or a transport error |
| `shell.gateway` | `{ url, method, body? }` | `netGatewayFetch` with today's flags | `{ status, body }` or a transport error |
| `shell.verified` | a [verified operation](#verified-operations) | today's adapter, whole | the operation's outcome |
| `shell.prefetch` | `{ uri }` | `prefetchGatewayUrl(uri)` | `{}` when it ends (finished, failed, its 10 s timer, or cancelled) |

- **Request bodies** travel as text: JSON-RPC and gateway bodies are ASCII JSON.
- **Response bodies** travel as base64, so the core sees exactly the bytes main received.
- **The message must fit:** the requests whose size an answer can drive are measured before they are made. Those are a CCIP-Read callback (its call data, as a hex string) and a gateway request (its URL and POST body). The core measures those payload strings as serialized JSON strings, plus a 4 KiB reserve. The reserve covers the protocol envelope (method, IDs, generations, deadline) and a callback's fixed JSON-RPC wrapper; it is conservative. A request over 0001's 1 MiB frame by that measure is never made, as `request-size` states (see [Bounds](#bounds)). Every other request (an RPC call built from the core's own small data, a Tezos request, a verified operation) is checked when it is serialized for sending: one over the frame then completes locally as `too_large`.
- **Gateway flags:** `redirect: 'error'` at the fetch level, `credentials: 'omit'`, `useSessionCookies: false`, `cache: 'no-store'`, `bypassCustomProtocolHandlers: true`, and `Accept: application/json`. Every gateway request in the vectors records them.

### Verified operations

Myotis and Colibri keep running in main, through today's adapters, **one whole operation per request**. This is the unit today's code retains a client for, retries, and runs ethers' built-in CCIP-Read inside.

| Operation | Main runs | Reply |
|---|---|---|
| `{ myotis: "record", method, name?, address?, coin_type }` | `resolveMyotisEnsRecord` (`myotis-resolver.js`: the UR over `MyotisProvider`, with its CCIP) | `{ status: "ok" \| "noRecord", data_hex?, address_hex?, name?, verified, block_number }`, `{ revert }` (the operation's revert data), or `{ failure }` |
| `{ myotis: "call", to, data }` | `myotisManager.ethCall` at `latest`, then `getStatus()` | `{ result_hex, optimistic_block_number }` or `{ failure }` |
| `{ colibri: "resolve", name, call_data, resolver }` | `resolveCallViaColibri(name, callData, callResolver)`, where `resolver` (`ur`, `name_nft` or `name_nft_reverse`) picks the call resolver; with today's whole-operation client rebuild and retry (`withColibriClientRetry`) and ethers' built-in CCIP | `{ resolved_data, resolver_address }`, `{ revert }` or `{ failure }` |
| `{ colibri: "reverse", address, coin_type }` | `resolveReverseViaColibri` | `{ name }`, `{ revert }` or `{ failure }` |

- **Main runs no epoch check of its own.** The reply is the outcome the adapter gives, as the reference receives it. A success is forwarded as a success, and `tryMyotisPath`'s check after it is the core's ([Verified methods](#verified-methods)).
- **The adapters guard themselves.** An operation that crosses a change of Myotis availability fails inside the adapter:
  - `verifiedRequest` checks around each raw call and throws `MYOTIS_UNAVAILABLE`, which is `{ failure: "lifecycle" }`;
  - the record operation's `MyotisProvider` checks the epoch it started with before and after each raw call. Its error carries no code, so it is `{ failure: "error" }` (`myotis-lifecycle-between-calls`).
- **`failure`** is a closed set of classes (`unavailable`, `lifecycle`, `timeout`, `too_large`, `invalid_argument`, `error`) and carries no text. `lifecycle` is today's `MYOTIS_UNAVAILABLE` from `verifiedRequest`; `invalid_argument` is ethers' own `INVALID_ARGUMENT`, thrown inside the adapter (`universalResolverCall`'s `dnsEncode(name, 255)` refusing a label over 255 bytes). The method that made the operation handles a failure as today's code handles that adapter's error ([Verified methods](#verified-methods)).
- **Reply size:** main serializes each reply first. One whose response wouldn't fit a frame (1 MiB, the envelope and the largest ID included), such as a large return, revert or name, is replaced by `{ failure: "too_large" }`: a method error, so the order continues (deviation `verified-reply-size`).
- **Revert data** goes as bytes the core reads: `0x` and whole bytes, checked in constant stack. An error carrying anything else (an odd digit, a `0X`) is a failure, classed by the rules above (`error` unless it is `lifecycle`, `timeout` or `invalid_argument`); sent as a revert, the core would refuse it as a malformed reply.
- **Provenance:** a `revert` is the verifier's proven revert data. The core records which verifier produced it.
- **The adapters' own bounds** are unchanged. Main bounds physical work: at most 8 operations per verifier are running, counted until the adapter's promise actually settles, not when the core cancels. Beyond that, main answers `{ failure: "unavailable" }` at once.

### Replies

A resolution reply is one of:
- `{ result, undefined_keys, generations, attempts }`:
  - `result` is today's result object, keys in today's order.
  - `undefined_keys` lists the top-level keys that are present with the value `undefined` (Tezos `ttl`, an address `error`). They appear in `result` as `null` placeholders, and main sets them back to `undefined`. A marker value inside `result` would be ambiguous, because Tezos `ttl` is arbitrary JSON from the chain.
- the error `resolution_failed`, with `data: { message, generations, attempts }`: today's thrown resolution. Main builds today's IPC error object from it:
  - content: `{ type: 'error', name, reason: 'RESOLUTION_ERROR', error }`;
  - address and reverse: the `success: false` shapes;
  - Tezos: `{ type: 'error', reason, system: 'tezos' }`.

**Endpoint references in results.** Where today's results name endpoints, the core writes `{ "ref": "<endpoint>" }` and main substitutes, in exactly these places:
- **ENS** `trust.agreed[]`, `trust.dissented[]`, `trust.queried[]`, `groups[].urls[]`: the host (`hostOf`, today's helper, which returns the input when it doesn't parse).
- **Colibri** `trust.prover`, `trust.agreed[]`, `trust.queried[]`: the prover's host.
- **Tezos** `trust.agreed[]`: the URL, since today's Tezos results carry full URLs. Tezos `groups[].urls[]`: the host.

Literal labels such as Myotis' `myotis-p2p` are plain strings and never substituted. Main keeps a reference's mapping while any request or reply can still name it.

## Configuration

`naming.configure` replaces the whole snapshot and returns the generations. A part that changed advances its own generation.

```jsonc
{ "reset": "providers",            // "none" | "providers": today's invalidateCachedProvider
  "rpc": [ { "endpoint": "e3" }, … ],              // effective order, ≤ 64 entries
  "direct": { "endpoint": "e3", "user_configured": true },   // or null
  "prover": { "endpoint": "p1", "zk": true },                // or null
  "policy": { "order": ["myotis", "colibri", "quorum"], "prefer_verified": false },
  "quorum": { "k": 3, "m": 2, "timeout_ms": 5000, "anchor": "latest", "anchor_ttl_ms": 30000 },
  "myotis_enabled": true,
  "tezos": [ "t1", "t2", "t3" ] }
```

- **Main computes the inputs as today:**
  - `rpc` is `getEffectiveRpcEndpoints()` (with `ETH_RPC` prepended, deduplicated case-insensitively), its first 64 in that order (deviation `rpc-endpoints`): the core refuses a longer list;
  - `direct` is `getDirectRpcCandidate(1)` (the first registry endpoint, ignoring `ETH_RPC`);
  - `policy` is `resolutionPolicy()` (including the legacy `primary` mapping);
  - `quorum` is the raw `network.quorum` values;
  - `tezos` is `getRpcEndpoints()` (with `TEZOS_RPC` prepended).
- **The core applies today's clamps and defaults** where today's code applies them. `resolveViaQuorum` clamps K and M from 1, `getPinnedBlock` from 2, and then the anchor's effective M.
- **References are derived:** a reference is a keyed hash of the URL, under a key main generates per core process. A re-added URL gets back its reference, so quarantine (keyed by reference) survives a list change, as today's URL-keyed map does. Main keeps the reverse mapping for the 1,024 most recent references, which is far more than a configuration ever holds.
- **Reads happen where today's code reads:** a session reads the current snapshot at the same points today's code calls `registry.getNetwork` and `getEndpoints`.
- **The shuffle** is recomputed when the joined `rpc` reference list changes (today's `sourceKey`).
- **`reset: "providers"`** is today's `invalidateCachedProvider`:
  - it clears the shuffle, quarantine and anchor;
  - it clears the content, address and reverse caches and the in-flight table;
  - it advances `lifecycle`;
  - it leaves Tezos alone (`settings-invalidation`).
- **`naming.availability`** is today's Myotis transition listener, for chain 1:
  - it clears the content, address and reverse caches and the in-flight table, and advances `lifecycle`;
  - it keeps the anchor, the shuffle and quarantine, and doesn't touch Tezos (`myotis-ready-mid-flight`, `lifecycle-flapping`).

## The ENS machine

The rules below restate the reference, so a reviewer can check them against the code. The vectors are what the implementation is tested against.

### Pool and quarantine

- **Available endpoints** are the shuffled `rpc` list minus the quarantined ones. Checking an entry deletes it once expired, so its failure count restarts (`quarantine-expiry-resets`).
- **A failure** increments the entry's count and sets its cooldown to `min(60 s × 2^(count−1), 600 s)` from now. Only failures that overlap within one entry's lifetime double it (`quarantine-doubles-on-overlapping-failures`).
- **A success** deletes the entry.
- **The shuffle** is Fisher–Yates over the machine's random source, `j = floor(r × (i + 1))`, from the last index down.
- **The random source is one stream, consumed in the reference's order:** shuffles and ethers' 429 back-off (see [Transport](#transport)). Replay feeds it the recorded seed through mulberry32.

### The anchor

`getPinnedBlock`, run when the quorum method needs a block:
1. **Clamps:** `K = clamp(k or 3, 2, 9)`, `M = clamp(m or 2, 2, K)`. The deadline is `timeout_ms or 5000`. The tag is `anchor or "latest"`, and the TTL is `anchor_ttl_ms` if it is a number, else 30 s.
2. **Cache:** a cached anchor with the same tag and an unexpired TTL is returned.
3. **Too few endpoints:** below 3 available endpoints, there is no anchor (the caller degrades).
4. **Heads:** every available endpoint is asked for its head at once, each request under its own deadline.
   - For `finalized`, the request is `eth_getBlockByNumber("finalized", false)`, and `null` is a failure. Otherwise it is `eth_blockNumber`.
   - A failure marks quarantine. After all settle, each success clears quarantine (`quorum-agree`, `quorum-slow-endpoint-head`).
5. **Median:** below 3 heads, there is no anchor. Otherwise the upper median, `sorted[floor(n/2)]`.
6. **Target:** the median minus the depth: 8 for `latest`, 32 for `latest-32`, 0 for `finalized`, 8 for any other tag.
7. **Hashes:** the head responders are asked for the block hash at the target (`eth_getBlockByNumber(target, false)`). A failure marks quarantine.
8. **Agreement:**
   - **Buckets:** responses are bucketed by hash in response-list order. The winner is the first bucket with the strictly largest size.
   - **Threshold:** `max(min(M, available), floor(hashes/2) + 1)`.
   - **Win:** the winners are marked successful and the anchor is cached.
   - **Otherwise it throws** `Could not reach hash quorum at block N (largest bucket X of Y responses, need ≥T)`, with no fallback (`anchor-hash-split`).

### Legs, waves and agreement

**A leg** is one call to one endpoint at the pinned block hash, under one deadline (`timeout_ms`) that covers the RPC call, its CCIP gateway fetches and its callback calls (`ccip-slow-gateway-then-another-name`). Its outcome follows the [classification](#classification):
- **`data`** (raw return bytes): clears quarantine.
- **`not_found` `NO_RESOLVER`:** a `ResolverNotFound` or `ResolverNotContract` revert. Clears quarantine.
- **`error` without quarantine:** the deadline expired after a gateway was used, or `CCIP_GATEWAY_FAILED` (`ccip-all-gateways-fail`). Quarantine is cleared.
- **`error` with quarantine:** a provider failure, or the deadline before any gateway.
- **`not_found` `NO_CONTENTHASH`** with the error: any other revert or answer. Clears quarantine.

**A wave** runs its legs at once.
- **Early agreement:** after each leg settles, a data bucket of size ≥ M ends the wave as `agreed_data`; otherwise a negative bucket (by reason) of size ≥ M ends it as `agreed_not_found`.
- **Losing legs** are cancelled, and their HTTP requests with them (deviation `abandoned-exchanges`; today they run on).
- **Prefetch:** the first `data` of a wave starts a [prefetch](#prefetch). Any outcome other than `agreed_data` cancels it.

**Without agreement**, the settled wave classifies:
- **`all_errored`:** no semantic answer at all.
- **`unverified_data` / `unverified_not_found`:** exactly one semantic answer.
- **`conflict`:** two or more answers that disagree.

**`resolveViaQuorum`:**
1. **Clamps:** `K = clamp(k or 3, 1, 9)`, `M = clamp(m or 2, 1, K)`. No available endpoint throws `No available RPC providers for ENS consensus resolution`.
2. **Single source:** fewer than 3 available endpoints, `K < 3` or `M < 2` → the [single source](#single-source-and-direct) on the first available endpoint (`single-source-two-endpoints`).
3. **Anchor:** no anchor → single source on the first *now* available endpoint, or the first one from before. A hash split throws.
4. **Refresh:** the available list is re-read. Below 3 → single source as in 3.
5. **First wave:** the first `min(K, available)` endpoints, with `M' = min(M, K')`.
6. **Second wave:** after an `all_errored` or unverified first wave, the endpoints the first wave didn't use (re-read). An `all_errored` wave needs at least 1 of them; an unverified one needs M'. The wave runs with `K'' = min(K, remaining)` and `M'' = min(M, K'')`. It replaces the first wave if the first was `all_errored`, or if the second agrees.
7. **The result** comes from the adopted wave. Trust `k` is that wave's queried count and `m` its M:
   - `agreed_data` → `data`, `verified`;
   - `agreed_not_found` → `not_found`, `verified`, with the first agreer's error;
   - `all_errored` → throws `All N RPC providers failed for <name>`;
   - unverified → that one answer, `unverified`;
   - `conflict` → `conflict` with `dissented` = `queried`.

### Single source and direct

- **Single source:** one endpoint answers the head, then the block at head − depth, under **one** shared deadline, then one leg. The trust is `unverified` (k = m = 1). A leg error throws it; an anchor failure throws `Single-provider anchor fetch failed: …`.
- **`direct`:** the same against the configured direct endpoint, with trust `user-configured` when it is user-configured, else `unverified`. Any failure returns *unavailable*, so the next method runs (`direct-user-configured`, `direct-builtin`).

### Verified methods

- **Myotis:**
  - **When:** enabled and ready.
  - **ENS records** use `{ myotis: "record" }`. A `noRecord` re-encodes to today's empty ABI forms.
  - **WNS/GNS calls** use `{ myotis: "call" }`. Their trust takes the reply's `optimistic_block_number`, as `tryMyotisContractPath` reads it today.
  - **Trust:** `verified`, `method: myotis`, finality `optimistic` unless the record says it is verified (finalized) (`myotis-verified`, `myotis-ccip`).
- **Colibri:**
  - **Calls:** through `{ colibri: … }`, whose single client rebuild and retry wraps the whole operation (`colibri-unavailable-falls-to-quorum`: two verified attempts, then quorum).
  - **Results:** a proven `ResolverNotFound` is a verified `NO_RESOLVER` (`colibri-resolver-not-found`). Any other failure is a method error, and the order continues.
  - **Trust:** `prover` is the prover's host, and `proof` is `ZK sync-committee proof` or `Sync-committee proof` (from `zk`).
- **A Myotis method and its operations:** a method (`tryMyotisPath`, `tryMyotisReverse`) runs one or more operations. A forward lookup runs one. A reverse runs the ENS reverse record and then, for WNS and GNS in turn, a reverse call and a forward check.
  - **A failed operation** is handled where today's code handles that error. A failed WNS or GNS forward check is caught inside the reverse: the claim stays unverified, and the next system is tried. Any other failure leaves the method.
  - **The method-wide check:** when the method ends without an error escaping, the core compares Myotis' readiness and epoch, as the last `naming.availability` gave them, against their values when the method began (today's `MYOTIS_LIFECYCLE_CHANGED` in `tryMyotisPath` and `tryMyotisReverse`). On a change the method order is aborted at once, and the session restarts.
  - **An error that leaves the method** is a method error, and the order continues. If the attempt crossed a change, it is discarded at its end and the session restarts ([Sessions](#sessions)).
- **Lifecycle vectors:**
  - **A forward operation fails on a change:** `myotis-record-lifecycle-mid-operation`, `myotis-call-lifecycle-mid-operation`, `myotis-lifecycle-between-calls`. It falls back to quorum, then restarts.
  - **A reverse's forward check fails on a change:** `myotis-reverse-lifecycle-forward-check`. GNS is tried, the method-wide check fails, and the lookup restarts through Myotis at once with no quorum I/O.
  - **The ordering:** main sends `naming.availability` from the transition itself, ahead of any later reply on the same connection, so the core's check sees every change the reference's would.

### Method order

`consensusResolve`:
- **The order:** each method in `policy.order` runs in turn.
- **Unavailable:** a method that is unavailable (disabled, not ready, not configured) continues the order.
- **A thrown error:** it is recorded and the order continues. A lifecycle change rethrows.
- **`prefer_verified`:** with it set, the first `unverified` answer is held and the order continues. Anything else is accepted at once.
- **The end:** the held answer, else the last error, else `No enabled name-resolution method could resolve <name>` (`prefer-verified-holds-unverified`).

### Content, address and reverse

These follow `doResolveEnsContent`, `doResolveEnsAddress` and `doResolveEnsReverse` exactly. The vectors fix every branch:
- **Content:**
  - NameNFT names (`.wei`, `.gwei`) call their contract directly (`wns-content`, `gns-content`).
  - Conflicts and decoded results are cached.
  - **`NO_CONTENTHASH` with an error is not cached.**
  - The empty contenthash is `EMPTY_CONTENTHASH`.
  - Undecodable or unparseable bytes are `unsupported`.
- **Address:**
  - The coin type is 60 on chain 1, else `0x80000000 + chain`. A NameNFT name off chain 1 is `CHAIN_UNSUPPORTED`, cached, with **no I/O** (`wns-address-on-l2`).
  - `NO_CONTENTHASH` becomes `RESOLUTION_ERROR`, and it **is** cached.
  - The zero address and empty bytes are `NO_ADDRESS` (`address-*`).
- **Reverse:**
  - **ENS:** through the UR's `reverse`, as an `(outcome, detail)` agreement value. A `ReverseAddressMismatch` is `UNVERIFIED` with the claimed name (`reverse-*`).
  - **WNS, then GNS:** on chain 1, an ENS `NO_REVERSE` falls back to WNS, then GNS, through **the same method** that produced the ENS answer. A claim is checked by a forward `addr` through that method too. A failed forward check leaves the claim unverified, and the next system is tried (`reverse-ens-empty-then-wns`, `reverse-ens-and-wns-empty-then-gns`, `reverse-wns-claim-fails-forward-then-gns-empty`; through Myotis, [Verified methods](#verified-methods)).
  - **Provisional:** a result that is `unverified` or `UNVERIFIED`.
  - **Error outcomes** agree by their [agreement identity](#errors-agreement-and-text), not by display text.

### Caches and TTLs

**Lifetimes** (`ttlForResult`; `cache-boundary-*`):

| Result | TTL |
|---|---|
| reason `UNVERIFIED` | 60 s |
| trust `verified` or `user-configured` | 15 min |
| trust `unverified` | 60 s |
| trust `conflict` | 10 s |
| no trust | 15 min |

- **Three caches:** content (by name), address (by `chain:name`, or `name` on chain 1), and reverse (by lowercased address, or `chain:address`).
- **Bounds:** each holds at most 500 entries and 8 MiB. Over either bound, expired entries go first, then the oldest by insertion (`capCache`).
- **A hit** needs `now < expiresAt`, exactly: a hit at +899,999 ms, a miss at +900,000 ms.
- **Caching happens after the reply passes its size check.** A result that can't be sent is never cached.

### Sessions

- **The key** is today's in-flight key, `content|addr|reverse` + the cache key. A same-key lookup joins the running session, and different keys don't share, so content and address of one name each anchor (`dedup-concurrent`).
- **Lifecycle restarts** (`resolveAcrossStableLifecycle`):
  - Attempts follow the [per-caller allowances](#generations): no caller's allowance caps another's.
  - An attempt that crosses a `lifecycle` change, whether it succeeded or threw, is discarded. Its cached result is removed if it is still the cached one, and the session restarts.
  - Past the last attempt, it throws `Myotis availability changed repeatedly while resolving <name>`.
  - The in-flight table is cleared at each change, so a lookup after the change starts a new session rather than joining the old one.
- **Termination:** a session ends at its result, its deadline or its budget ([Admission](#admission), [Bounds](#bounds)). Its outstanding I/O is cancelled then, losing legs included. A surviving prefetch is the exception: it is handed out of the session first ([Prefetch](#prefetch)).
- **Abandoned exchanges:** whenever the core stops waiting for an exchange (agreement, a leg's or a gateway's deadline, the session's end), it cancels it, and main ends it promptly. In the reference, an abandoned ethers request runs on: it can even retry after a 429, after its leg has timed out (deviation `abandoned-exchanges`).
- **Verifier work** keeps counting in main until the adapter settles, whatever the session does.
- **Timers** run on the daemon's monotonic clock and fire without waiting for a message: deadlines, quarantine, cache expiry, the anchor TTL.

### Classification

How a failed exchange is classified. The core's rules are ordered, and the first that matches decides. The reference is freedom-browser `fb540328`, and the node-failure rule is freedom-browser#656 at `e055b4e7`. Rows marked † differ from the reference; they make up deviation `classification`.

**Is it a provider failure?** (the core's replacement for `isProviderError`)

| # | Core rule | The reference |
|---|---|---|
| 1 | Transport `timeout`, `refused`, `too_large`: **yes** | yes (`TIMEOUT`, `SERVER_ERROR`) |
| 2 | Transport `network`, any socket-level failure: **yes** † | yes when the socket error's message matches the text rule (`ECONNREFUSED`, `ENOTFOUND`, `ETIMEDOUT`); otherwise no. A reset (`ECONNRESET`, "socket hang up") is semantic |
| 3 | HTTP non-2xx once ethers' `FetchRequest` is done: **yes** | yes (`SERVER_ERROR`) |
| 4 | Body not UTF-8 or not JSON, no response for the request's id, or an `error` member that isn't an object: **yes** † | no (`UNSUPPORTED_OPERATION`, `BAD_DATA`), unless the composed message matches the text rule below |
| 5 | A node error with code −32603, with or without revert data: **yes** | yes |
| 5a | A call exception with revert data ethers extracted (`spelunkData`): **no** | no, unless the composed message matches the text rule |
| 6 | A node error with revert evidence (code 3 or −32015; `data` as even-length hex or `Reverted 0x…`; a message mentioning a revert): **no** † | yes when its message matches `/no response/` (and #656 keeps that) |
| 7 | A node error whose code is one of #656's node-failure codes, or whose message matches #656's patterns, `/no response/`, or an HTTP status pattern (`502`, `503`, `504`, `429`, `timeout`): **yes** | the pin: only `/no response/` and the text rule; #656: its codes and patterns too |
| 8 | Any other node error (`out of gas`, `invalid opcode`, …): **no** | no, unless the composed message matches the text rule |
| 9 | A result ethers' formatting refuses (not hex, missing, a malformed block): **yes** † | the text rule decides, so `"timeout"` or `"0x429"` counts and `"junk"` doesn't |
| 10 | Anything else: **no** | the text rule decides |

**The reference's text rule:** the pattern `502`, `503`, `504`, `429`, `timeout`, `ECONNREFUSED`, `ENOTFOUND` or `ETIMEDOUT` (case-insensitive) against ethers' composed message, which embeds the request and the offending value. The core matches text only in rule 7: the node's own message, when nothing says the call reverted. Rule 2 uses socket codes, not text.

**Per operation**, in the reference's order:
- **Forward legs** (`runQuorumLeg`):
  1. The deadline after a gateway was used, or `CCIP_GATEWAY_FAILED`: `error` without quarantine.
  2. A resolver-not-found revert: `NO_RESOLVER`. That is the selector `ResolverNotFound` or `ResolverNotContract` in the revert data ethers extracted, else in the node's `data` string. It is also an `Error(string)` reason naming either, which is what the reference's message match can see.
  3. A provider failure, or the leg's deadline before any gateway: `error` with quarantine.
  4. Otherwise `NO_CONTENTHASH`, with the error.
- **The reverse call** (`universalResolverReverseCall`) checks first, then hands to the leg's rules:
  1. A provider failure or `CCIP_GATEWAY_FAILED`: rethrown, to the leg's rules.
  2. A resolver-not-found revert: `noRecord`.
  3. `ReverseAddressMismatch` (the selector, or an `Error(string)` reason naming it): `mismatch`, with the claimed name.
  4. Otherwise an `error` outcome, keyed by its [agreement identity](#errors-agreement-and-text).
- **Anchor requests:** any failure is a failure.
- **Tezos:** any failed request fails that endpoint's step, as today.

**Revert evidence beats text, never codes:** rule 5 (−32603) precedes both extracted revert data and revert evidence, as in the reference and #656.

### Errors: agreement and text

- **Agreement identity.** Legs agree on bytes. Today a reverse `error` outcome encodes ethers' full message. For every error the reverse wrapper encodes (the ones that aren't provider failures), that message is built only from the call and the answer, never from the node's text:
  - **a call exception:** its short message, the revert data ethers extracted, and the failing call's `to` and `data` (the callback, after CCIP-Read);
  - **a deferred ABI error:** where it was accessed (`deferred error during ABI decoding triggered accessing index 0`), not the value inside;
  - **a decoding error:** ethers' message for it, with its value and location;
  - **the resolver's own errors** (`CCIP sender does not match the Universal Resolver`, …): their fixed text.

  The core reproduces that message exactly and encodes it, so legs agree and disagree exactly where the reference's do. Vectors: callbacks with different data, legacy envelopes that differ only in `info.error.data`, and invalid URLs at different indexes.
- **Display text** is separate. Fields that today carry an ethers or node message carry the class's short message instead:
  - sanitized like `sanitizeErrorDetail` (URLs → `<url>`, hex over 64 bytes shortened, 240 characters);
  - never the node's text (deviation `error-text`).
  This applies to `error` on `not_found` and `RESOLUTION_ERROR` results, to reverse `RESOLUTION_ERROR` details, and to `resolution_failed` messages. The reproduced message is used only for agreement, never shown.
- **Server text** is used for rule 7's patterns and then dropped. It is never logged, cached, compared or put into a reply. See [Secrets](#secrets).

### CCIP-Read

- **Pinned legs** (quorum, single source, direct):
  - **The loop:** at most 10 rounds. Each round needs an `OffchainLookup` revert whose sender is the Universal Resolver, else today's error. The callback goes to **the same endpoint at the same block hash** (`ccip-fast-gateway`).
  - **Gateways** are tried in list order, 15 s each, through `shell.gateway`:
    - The [codec](0003-naming.md#codecs) decides a URL's eligibility (`https`, no credentials, not an IP, a dotted host, not `.localhost`/`.local`/`.internal`), the GET or POST shape, and the answer's validity. Main refuses the same URLs again, failing closed.
    - An HTTP error, a redirect or an invalid answer moves on to the next URL (`ccip-gateway-errors-fall-through`).
  - **Bounds:** at most 32 URLs are tried per round (deviation `ccip-urls`).
- **Verified paths** run ethers' built-in loop inside main's adapters, unchanged ([Verified operations](#verified-operations)).
- **NameNFT calls** never use CCIP-Read.

### Prefetch

- **Start:** the first `data` of a content wave starts a prefetch of the decoded `ipfs://` or `bzz://` URI (never `ipns://`). A decoding failure starts nothing.
- **Cancel:** any wave outcome other than `agreed_data` cancels it.
- **Survival:** after `agreed_data`, the prefetch is handed from the session to the machine's own prefetch set, so it survives the session's end. That includes a result that later rejects the answer, and a session deadline. Main bounds it with today's 10 s timer.
- **Bounds:** at most one per wave, and at most 32 in the machine's set. Over that, the oldest is cancelled. It never blocks a session.

## The Tezos machine

`resolveTezosDomain`, with its own caches and sessions (keyed by the lowercased name):
1. **Validation:** an invalid name is `not_found` `invalid .tez domain`, uncached (`tezos-invalid-name`).
2. **Heads:** the first 3 endpoints are asked for `chain_id` and the head header at once, 8 s each. A wrong chain or level ≤ 8 is a failure. No head is the error `all Tezos RPC providers failed`, uncached (`tezos-all-down`).
3. **Head agreement:** heads more than 60 levels from the lower median are excluded. If at most half remain, the result is a head `conflict`, uncached (`tezos-head-outlier`, `tezos-heads-scattered`).
4. **Anchor:**
   - The anchor level is the minimum retained level − 8.
   - **No hash at all** is the error `Tezos RPC providers could not anchor a block`, uncached.
   - **Buckets:** hashes are bucketed in order. If the largest bucket isn't a strict majority, the result is an anchor `conflict`, uncached (`tezos-anchor-split`).
5. **Lookups:** the anchor's endpoints run at once:
   - **Discovery:**
     - the proxy script, then the registry script, each POST with `unparsing_mode: "Readable"`;
     - it is cached per endpoint for 10 min (the second name in `tezos-agree` skips it);
     - a lookup that fails on **cached** discovery drops the entry, rediscovers **once**, and looks up again;
     - an endpoint whose discovery fails drops out of the lookups (`tezos-registry-script-fails`).
   - **The record:** HTTP 404 is `null`, which gives `not_found` `domain record not found` (`tezos-no-record`).
   - **The expiry** is fetched only when `%expiry_key` is `Some` with non-empty bytes.
     - **`None`:** gives `expiry: null` with no request (`tezos-no-website`).
     - **Missing:** a missing expiry record is a failure.
     - **Expired:** an expiry at or before now is `not_found` `domain record expired` (`tezos-expired`).
     - **Unreadable:** an expiry `Date.parse` can't read is ignored (`tezos-expiry-unparseable`).
   - **Website records:** `web:redirect_url` wins over `web:content_url`, then `td:ttl` is read. Undecodable metadata is `unsupported` `invalid Tezos Domains metadata: …`, with the message after the prefix being the core's (0003's codec deviation).
   - **No successful lookup** is the error `Tezos Domains registry lookup failed`, uncached.
6. **Agreement:**
   - **Grouping:** results are grouped by today's semantic key (`type`, `reason`, `protocol`, `uri`, `decoded`, `basePath`, `redirect`, `expiry`, `ttl`).
   - **Conflict:** if several groups exist and the largest isn't a strict majority, the result is a `conflict`, uncached.
   - **Otherwise the winner:** `verified` when ≥ 2 agree, else `unverified`, with `agreed` listing its endpoints.
7. **Cache:**
   - **Non-`ok` results:** 30 s (`tezos-no-record`).
   - **Unverified ones:** 30 s (`tezos-two-down`).
   - **Verified ones:** the record's `td:ttl` seconds when finite and positive, else 5 min, capped at 1 h and at the time left before expiry, and at least 1 s.
   - **Not cached:** errors and conflicts.

**Expiry parsing:** the core accepts the RFC 3339 timestamps Tezos RPC returns in Readable mode. Any other string is treated as unreadable, where V8 would also try its legacy, time-zone-dependent formats (deviation `tezos-expiry`).

## Transport

- **One request per HTTP request:** each JSON-RPC request travels alone. The reference never batches here, because every leg and probe uses its own ephemeral provider.
- **Request bodies:** the core writes them, `{ "jsonrpc": "2.0", "id", "method", "params" }`, with today's params:
  - `eth_blockNumber []`;
  - `eth_getBlockByNumber [hex or tag, false]`;
  - `eth_call [{ to, data }, blockHashOrTag]`.
- **Response handling:** the core parses the body as ethers' `JsonRpcProvider` does, including a batch-shaped array answer, and classifies it as [above](#classification).
- **ethers' `FetchRequest` policy, run by main:** one `shell.rpc` is one exchange. Main runs it in its own loop, not ethers' class, because `FetchRequest.redirect()` builds a new request without its `getUrlFunc`, which would send a redirected hop through Node's networking. The loop reproduces `FetchRequest.#send` exactly:
  - up to 12 attempts;
  - 301/302/307/308 followed with method and body kept, and https → http refused;
  - HTTP 429 retried after `250 × trunc(r × 2^attempt)` ms, or after a positive integer `Retry-After` read as milliseconds;
  - the 300 s expiry checked before each attempt's back-off;
  - 300 s of socket inactivity per attempt.

  Every hop goes through the session's network stack and is checked against the endpoint policy and the onion gate. A refused hop ends the exchange as `refused` (deviation `rpc-redirects`: today hops aren't checked). Main's own tests run the loop against ethers' `FetchRequest` on the same scripted answers.
- **Cancellation is prompt:** a back-off wait is abortable. On `cancel` or the request's deadline, main ends the exchange (socket and timer), then sends the one terminal reply. An exchange counts toward the core's 256 outstanding requests until that reply, so nothing outlives the bound.
- **Random streams:** the shuffle's random source belongs to the core and the back-off's to main. In the reference they are one `Math.random`, so a 429 changes later shuffles; separate streams are deviation `random-streams`. Its vectors give ethers' back-off its own seeded stream in the harness, so replay stays exact.
- **Tezos:**
  - no 429 retry, as today's `fetch`;
  - **redirects are refused** (deviation `tezos-redirects`: today `fetch` follows them).
- **The session's network stack:** main sends `shell.rpc` and `shell.tezos` through the Electron session's network stack, as 0003 decided:
  - **Clearnet:** `DIRECT` under today's PAC.
  - **Onion:** the onion gate applies to every host and hop. There is no empty or `DIRECT` route and no `DIRECT` fallback.
  - **Other protections:** no credentials, no cookies, and no HTTP cache.
  - **What changes:** today these requests leave through Node's own stack (deviation `transport`).

### Secrets

This refines 0003 decision 3. That decision's wording, "the core never sees an endpoint URL", is the configuration rule. 0003 now points here.
- **Configuration:** the core is never given an endpoint URL. It knows endpoints by reference only, and main maps references back.
- **Diagnostics:** a server can return error text containing its own URL or key, for example by echoing the request. No scanner finds those reliably: JSON escapes hide them, and short keys collide with ordinary data. So diagnostic text is confidential in the core. It is used only for [classification](#classification), then dropped, and never logged, cached, compared across requests or put into a reply.
- **Published semantic fields:** a record's own data is published as today, even when it happens to equal an endpoint's URL: a Tezos website URI, a contenthash, a name. The reference does the same, and it isn't the core's to filter.
- **Crashes:** `freedom-cored` disables core dumps, and its crash reports carry no heap contents.

### Transport errors

Main's terminal reply for an I/O request is a result or one of these:
- `timeout`: the request's deadline, which the core sets, or 300 s of inactivity;
- `network`: DNS, connect, TLS or a reset;
- `refused`: the URL or a redirect hop failed main's policy;
- `too_large`: the answer exceeded the request's byte cap;
- `cancelled`;
- `stale_generation`.

No error carries a URL or a server's text.

## Bounds

**Messages and bodies.** Every message fits 0001's 1 MiB frame. For a callback or a gateway request the core measures its payload strings, serialized, plus a 4 KiB reserve; any other request is checked as serialized; for a reply, the serialized result:

| What | Bound | Exhausted |
|---|---|---|
| a CCIP-Read callback (its call data) or gateway request (its URL and POST body) | its payload strings serialized, plus 4 KiB, ≤ 1 MiB | never made: a gateway fails and the next URL is tried; a callback fails its leg as `CCIP_GATEWAY_FAILED`. Today these were sent (deviation `request-size`) |
| any answer body (RPC, Tezos, gateway) | 720 KiB, which is 960 KiB in base64 | `too_large`: a provider failure for RPC, a failed Tezos endpoint, or the next gateway (deviation `response-caps`) |
| a resolution reply, a result or a thrown message | 960 KiB serialized | `resolution_failed: result too large`, never cached (deviation `reply-size`) |

Measured valid answers sit well below the 720 KiB cap:

| Answer | Measured |
|---|---|
| `eth_getBlockByNumber(n, false)`, 10 recent mainnet blocks | 14.7–25.3 KB |
| the same, worst case at today's 60 M gas: ~2,857 transfers | ~200 KB |
| Tezos Domains proxy and registry scripts | 2.5 KB, 22.6 KB |
| CCIP gateway answers | a few KB |

**Shortening in replies.**
- **Conflict groups:** a `resolvedData` longer than 8,192 hex characters is shortened to its first 4,096 and last 4,096 characters. Today's renderer shows only a value's first 16 and last 10 characters, and its exact matches have fixed short lengths, so nothing it shows changes.
- **Unsupported results:** the same applies to `contentHash` (deviation `reply-shortening`).

**Memory.** What a session can come to hold is bounded by what it is charged for, conservatively, from the moment each part arrives or is made until the session ends. A session is charged for:
- **its name and key:** 8 copies of its in-flight key, reserved at admission; a session that can't reserve them doesn't start;
- **its requests:** their payload strings, as each is made; one whose charge crosses is never made;
- **its answers:** each body at what its parsed JSON can hold, counted before it is parsed by a pass that allocates nothing: its bytes, its text's bytes again (more when invalid UTF-8 is replaced), 88 bytes per JSON value or key (an object member's 56-byte slot and a 32-byte allocation), and 80 bytes per escaped surrogate (`\uD800` to `\uDFFF`), as much as a string's list of lone surrogates can hold for each. A text that isn't JSON counts a value per two bytes. A block of 1,000 transaction hashes, about 69 KB, is so charged about 230 KB (its body and a 160 KB parse); the flat 32 bytes per byte this replaced charged 2.2 MB, and eight such blocks ended a lookup (#73). A verifier's result is still charged at 32 bytes per byte of its serialized size;
  - **an anchor answer** (`eth_blockNumber`, `eth_getBlockByNumber`, the only requests that ask for them) is read for a number or a hash as it is taken, and its charge goes then. So the anchor holds one block at a time, whatever the endpoint count: 64 endpoints with the 200 KB worst-case block fit;
  - **one answer charged over 1 MiB** is refused: its request fails as `too_large`, the endpoint's failure, and the session goes on. A valid answer is far below it (the 200 KB block is charged about 660 KB), so only a pathological one meets it, and one lying endpoint can no longer spend a whole lookup's budget (#73);
- **its aliasing decodes' output** (an `OffchainLookup`'s URLs and data);
- **the cached state it copies:** a Tezos discovery taken from the cache, as its tree (the registry's record type is the chain's own JSON), charged before the copy is made;
- **its replies:** each caller's own copy of the result or error message, as the larger of its tree (as allocated) and its serialized form, including the replies a configuration change or a spent lifecycle allowance makes. A reply stays counted as output after its session ends, until it is written. A reply past the budget is `budget` instead. A session that spends its budget, on a reply or anything else, cancels the prefetches it handed off.

Everything a session retains derives from those: copies of its name, values parsed from its answers, and decodes that can't alias, which never outgrow their input:

| Budget | Bound | Exhausted |
|---|---|---|
| one ABI decode with an array (an `OffchainLookup`'s URLs): output bytes | 4 MiB | the decode fails as malformed (`BUFFER_OVERRUN`, "decode budget exceeded"): the leg fails as for any lookup that won't decode (deviation `decode-budget`) |
| one decode: reads | 0003's 1024× ABI read cap, JSON depth 512, Micheline depth and node count | as above |
| one answer: its charge | 1 MiB | the answer is refused: its request fails as `too_large`, a provider failure that quarantines the endpoint; the session goes on |
| one session: its charge | 16 MiB | the session ends at once, its I/O cancelled (a request whose charge crosses is never sent; an answer that crosses is dropped): its callers get `resolution_failed: budget`, and nothing is cached (a result whose replies cross is taken back) |
| all sessions: their charges | 64 MiB | the session whose charge crosses it ends the same way; new sessions get `busy` until the total falls below 48 MiB |
| the writer: naming frames queued for the pipe | 8 MiB | further frames wait in the naming thread, and `shell.*` requests in their FIFO |
| caches | 500 entries and 8 MiB each | eviction (deviation `cache-bytes`) |
| Tezos discovery entries | one per configured endpoint | — |
| endpoint state (quarantine, discovery) for endpoints no longer configured | the 64 most recently retired | the oldest retired entries are dropped (deviation `endpoint-retention`); a re-added endpoint within that bound keeps its state |
| surviving prefetches | 32 | the oldest is cancelled |

**Lifetimes:** a session's charge is released when it ends, however it ends, but its replies stay counted in the total until they are written. The machine counts every reply it makes until the naming thread takes it. The naming thread then reports what waits in its share of the writer (8 MiB) and its own queue before every poll and every admission. Sessions so can't fill the room unwritten replies hold: with the total full, new sessions are `busy` and running ones end with `budget`, both small replies. Separately, past 16 MiB waiting, new lookups get `busy` at once.

The 4 MiB decode budget caps aliasing: an `OffchainLookup` whose URL array repeats one 64 KiB string 2,047 times decodes to about 128 MiB today. The core refuses it. Only an array can alias. Every other decode (an ABI result with one dynamic field, JSON, Micheline, base64, hex) reads its input once, so its output never exceeds its input, which the answer cap bounds.

**Work.**
- **I/O per session** is bounded by its structure:
  - anchor probes ≤ the endpoint count (≤ 64);
  - legs ≤ 9 per wave, two waves;
  - one gateway at a time per leg, ≤ 32 URLs per round, ≤ 10 rounds;
  - ≤ 3 Tezos endpoints, one rediscovery each;
  - one prefetch per wave.
- **Outgoing I/O:** at most 256 core → main requests are outstanding. More wait, first in, first out, in the core, and their bytes count against their session. Their deadlines keep running, and an expired one is never sent.
- **CPU:** each event's work is bounded by the decode budgets. The naming thread keeps it away from vault control.
- **Verifiers:** at most 8 operations each, counted until physical completion ([Verified operations](#verified-operations)).

## Deviations

Each deviation gets a boundary vector in the implementation PR, generated from the same harness with the reference patched in memory where the deviation has no natural trigger. Each patch is recorded in its vector. 0003's codec deviations (`name-length`, `json-depth`, and the core's JSON error text) still apply; its lone-surrogate deviations are gone, as strings now keep them (#95).

| ID | Today | The core | Failure and cache behavior |
|---|---|---|---|
| `overall-deadline` | no overall bound; a stalled Colibri worker can take minutes (a 60 s liveness check, 60 s more before abandonment, then one retry) | 120 s per resolution method | `deadline`; nothing cached |
| `admission` | unbounded callers and lookups | 32 sessions, 256 callers, 64 per session | `busy`; nothing retained |
| `abandoned-exchanges` | an exchange nobody waits for (a losing leg, a timed-out leg) runs on: it finishes, can retry after a 429, and its late settlement still clears or marks quarantine | cancelled when the core stops waiting, with no late requests or health changes | later lookups can see a different quarantine set; requests the reference made after the cancellation don't happen. Vectors: a slow losing leg across three lookups, and a leg timing out during a 429 back-off |
| `rpc-stall` | ethers holds every JSON-RPC request 10 ms (its batch stall) | sent at once | none; replay adds the 10 ms back |
| `request-size` | requests of any size are sent | a callback or gateway request over the frame (its payload strings plus 4 KiB) is never made | the next gateway, or the leg fails as `CCIP_GATEWAY_FAILED`; not cached |
| `response-caps` | none for JSON-RPC; 5 MiB Tezos; 4 MiB gateways | 720 KiB each | `too_large`: a provider failure, a failed endpoint, or the next gateway |
| `reply-size` | unbounded | 960 KiB | `resolution_failed: result too large`; not cached |
| `reply-shortening` | full `resolvedData` and `contentHash` | first + last 4,096 hex characters when longer | none in the renderer |
| `decode-budget` | unbounded | 4 MiB of output per ABI decode with an array | malformed, per the decode's caller |
| `cache-bytes` | 500 entries per cache | also 8 MiB per cache | eviction |
| `ccip-urls` | every URL in the lookup | the first 32 | the rest aren't tried |
| `monotonic-time` | TTLs, quarantine and deadlines on `Date.now()` | the monotonic clock; Tezos expiry still compares wall time | none unless the wall clock jumps |
| `error-text` | ethers' full message, which embeds node text and request data | the class's short message, sanitized | same branches; [agreement](#errors-agreement-and-text) unchanged |
| `classification` | rules 3, 6 and 9 of [Classification](#classification), and text matched in composed messages | the core's rules | a malformed answer quarantines; a revert never does |
| `null-block-hash` | a block whose hash is `null` (ethers' formatter accepts one, for pending blocks) is a hash vote like any other; when the chosen anchor's hash is `null`, the legs call at `latest`, where CCIP-Read takes ethers' built-in path | the hash fetch fails, as for a missing block | that endpoint is out of the hash vote and quarantined; the single-source anchor fails, so `direct` is unavailable |
| `node-failures` | node errors can agree into a verified not-found (`node-errors-agree`) | freedom-browser#656's rule | until the reference pin includes it |
| `transport` | Node's HTTP stack | the session's network stack | `.onion` endpoints work under Tor, and a missing route fails closed (`refused`) |
| `rpc-redirects` | hops followed without checks | each hop checked against the endpoint policy and the onion gate | a refused hop is a provider failure |
| `tezos-redirects` | `fetch` follows redirects | refused | the endpoint fails for that lookup |
| `tezos-expiry` | V8's legacy `Date.parse` formats | RFC 3339 only | an unreadable expiry is ignored, as today's `NaN` |
| `verified-bounds` | no limit on concurrent adapter work | 8 operations per verifier | `{ failure: "unavailable" }`; the order continues |
| `verified-reply-size` | any size | a verified reply whose response wouldn't fit a frame (1 MiB) is `{ failure: "too_large" }` | a method error; the order continues |
| `memory-budgets` | unbounded | 16 MiB charged per session, 64 MiB in all, 1 MiB per answer (charges as in [Bounds](#bounds)), 8 MiB of queued frames | the session ends with `resolution_failed: budget`, or a new one gets `busy`; not cached. An answer over 1 MiB fails its own request as `too_large` instead |
| `rpc-endpoints` | every effective endpoint is in the pool | the first 64, in effective order | the rest are never tried; today's builtin pool is far smaller, so only a user adding more sees it |
| `endpoint-retention` | quarantine and discovery entries live for the process | 64 retired endpoints kept | an endpoint re-added after 64 others were retired has forgotten its quarantine |
| `socket-failures` | a socket reset is semantic; other socket errors count when their message matches | every socket-level failure is a provider failure | the endpoint is quarantined |
| `random-streams` | the 429 back-off and the shuffle draw from one `Math.random` | separate streams | later shuffles don't depend on earlier back-offs; vectors seed the back-off apart |
| `core-restart` | — (no separate process) | pending naming requests fail when the core restarts | `RESOLUTION_ERROR`; nothing cached |
| `prefetch-set` | unbounded | 32 surviving prefetches | the oldest is cancelled |
| `verified-failure-text` | a failed verified operation throws the adapter's own error | the core sees the failure class alone, and the method throws `verified call failed: <class>`; for a name with a label over 255 bytes, an `invalid_argument` from the Myotis record operation or Colibri's `ur` resolver (which `dnsEncode` the name first) is that refusal, whose ethers message the core rebuilds | the same failure, with the class's text where the order ends on it |

## Replay

The Rust machine runs each scenario of `naming-replay.json`:
- **Inputs:** the recorded seed (through mulberry32), the world and the steps;
- **Clock:** a virtual millisecond clock starting at the recorded epoch;
- **Driver:** a test driver that plays main. It answers each request with the recorded `answer` of the reference exchange it matches: endpoint, method and params, at the matching start time. A request the reference never made fails the test.

**The driver reproduces three reference artifacts:**
- **The ethers stall:** it delays a JSON-RPC request's first send by 10 ms before matching it. Retries inside the exchange carry no stall.
- **The exchange loop:** one `shell.rpc` consumes the reference's exchanges for that request, redirects and 429 retries included.
- **Verified operations:** the driver plays the adapter. It answers a `shell.verified` operation with the outcome the reference's adapter returned. The harness records each adapter operation (`resolveRecord`, `ethCall`, `resolveCallViaColibri`, `resolveReverseViaColibri`) and its outcome next to the raw exchanges it made, which is an implementation-step change.
- **Order:** answers are delivered in the reference's timer order, using the executor's external events.

**Compared exactly:**
- every result, with key order and present-`undefined` keys;
- every settlement time;
- every I/O request: endpoint, method, params, start time, and the time it was answered, cancelled or left open.

**Vectors the implementation adds:**
- a redirect followed by a 429 (the retry goes to the redirect target), and concurrent 429s, shuffles and cancellations under deviation `random-streams`;
- reverse error outcomes that differ only in callback data (they conflict), legacy envelopes that differ only in `info.error.data` (they agree), and invalid gateway URLs at different indexes;
- one boundary vector per deviation.

Main's own behavior (pipe overtakes, crashes, per-caller allowances, `FetchRequest` over the session stack) is tested in the daemon and the browser, since the reference has no such seam.

**Compared by rule:**
- **Deviations:** the fields a deviation covers are compared under its rule.
- **Abandoned exchanges:** the end times and rejection records of exchanges the core cancelled are excluded. So are the reference's requests that belong to an exchange the core had already cancelled, such as a 429 retry after a leg's deadline. A scenario where such an exchange would change later quarantine is an `abandoned-exchanges` vector with expected values of its own.
- **Prefetch:** start and the machine's cancellation are compared. End times are main's (the 10 s timer) and are not compared.

## Traceability

Every item of 0003's [What design 0004 must satisfy](0003-naming.md#what-design-0004-must-satisfy):

| 0003 requirement | Here | Vectors |
|---|---|---|
| Result, trust and error schemas with key presence; present `undefined`; TTLs and non-cacheable cases | [Replies](#replies), [Caches and TTLs](#caches-and-ttls), [Tezos](#the-tezos-machine) | every scenario; `cache-boundary-*`, `tezos-no-record`, `tezos-no-website-no-ttl` |
| Frames, queued I/O and drain, decoding budgets, aggregate bounds, vault responsiveness, answer caps | [Admission](#admission), [Bounds](#bounds) | `request-size`, `response-caps`, `reply-size`, `decode-budget` (implementation PR) |
| Anchor: all endpoints, ≥ 3 heads, upper median, hash plurality, single-source fallback, throwing on a split | [The anchor](#the-anchor) | `quorum-agree`, `quorum-slow-endpoint-head`, `anchor-hash-split`, `anchor-finalized` |
| Quarantine: 60 s doubling while an entry lasts, reset on success or expiry; gateway failures don't quarantine | [Pool and quarantine](#pool-and-quarantine), [Legs](#legs-waves-and-agreement) | `quarantine-*`, `ccip-slow-gateway-then-another-name`, `ccip-all-gateways-fail` |
| Second wave, K/M clamps, `direct`, provisional rules, WNS/GNS fallback, chain rules | [Legs](#legs-waves-and-agreement), [Method order](#method-order), [Content, address and reverse](#content-address-and-reverse) | `direct-*`, `prefer-verified-holds-unverified`, `reverse-*`, `wns-*`, `gns-content` |
| Tezos quorum, discovery isolation and caches, expiry | [The Tezos machine](#the-tezos-machine) | `tezos-*` |
| Deadlines: per leg around gateways and callbacks; single source shares one; NameNFT without CCIP | [Legs](#legs-waves-and-agreement), [Single source](#single-source-and-direct), [CCIP-Read](#ccip-read) | `ccip-*`, `direct-*` |
| Security: sender check, callback binding, verified provenance, redacted diagnostics, verifier ownership | [CCIP-Read](#ccip-read), [Verified operations](#verified-operations), [Errors](#errors-agreement-and-text), [Transport errors](#transport-errors) | `ccip-*`, `myotis-ccip` |
| Generations on replies and I/O, retiring dedup entries, three attempts, per-event invalidation | [Generations](#generations), [Configuration](#configuration), [Sessions](#sessions) | `myotis-ready-mid-flight`, `lifecycle-flapping`, `settings-invalidation` |
| Sessions: dedup key, subscriber cancellation, late answers, terminal cancellation, timers without messages, prefetch | [Admission](#admission), [Sessions](#sessions), [Prefetch](#prefetch) | `dedup-concurrent` |
| The full deviation inventory | [Deviations](#deviations) | per deviation (implementation PR) |

## Implementation steps

These refine 0003's step 4:
1. **`fc-naming::session`:** the ENS and Tezos machines, the replay driver and the replay tests. No daemon yet.
   - **Shape:** the machine is `async` Rust driven by a small in-crate executor, with no runtime, threads or `unsafe`. The reference's `Promise.allSettled`, `race` and timeouts map one to one.
   - **Order:** timers fire in (time, creation) order with a poll after each, as JavaScript runs microtasks between callbacks.
   - **I/O:** a request is an effect the driver answers. Dropping one cancels it.
2. **`freedom-cored`:** the `naming.*` methods, the `shell.*` requests, admission, the naming thread and the budgets. Measure cached subresource fan-out under concurrent vault work (0003 decision 4) before committing to core-owned caches.
   - **Measured** (`cached_fanout_under_vault_work`, a release build on a 4-core dev server, 2026-10-12): a page's worth of cache hits, 50 sent at once and repeated 20 times, replies in 1.6 ms median and 3.0 ms p99. With 16 password checks' KDFs in flight (2.9 s of vault work, run one at a time) it is 3.3 ms median and 5.1 ms p99. The naming thread doesn't wait on vault work, so the core keeps the cache.
3. **freedom-browser:** main's executors, the verified operations around today's adapters, and the result mapping. The resolvers become drivers (0003 step 5).

## Open questions

1. **The overall deadline.** Is 120 s right? The worst case today, a reverse lookup with every method failing slowly, is several minutes. Typical lookups take under 1 s.
2. **Shortening versus refusing.** Should an oversized `resolvedData` shorten as above, or make the reply a `RESOLUTION_ERROR`? Shortening keeps today's interstitial.
3. **0003's open questions** (trust semantics, EIP-3668's 4xx rule) remain open. Nothing here depends on them.
