# 0004: Name resolution sessions in the core

**Status:** proposed. Builds on [0001](0001-freedom-cored.md) (process, framing, deadlines) and [0003](0003-naming.md) (codecs and the resolution architecture). It specifies the protocol that 0003's [architecture](0003-naming.md#resolution-architecture) left open, and answers every item of [What design 0004 must satisfy](0003-naming.md#what-design-0004-must-satisfy) (see [Traceability](#traceability)).

**Ground truth** is the replay harness (#24): `vectors/naming-replay.json` runs the pinned resolvers (freedom-browser `fb540328`) through scripted worlds, and its scenario IDs are cited below in `code`. Where this document and a vector disagree, the vector wins and the document has a bug.

## Summary

A name lookup becomes a **session** in `freedom-cored`. The session is a sans-I/O state machine in `fc-naming`:
- **main → core:** a `naming.*` request starts or joins a session;
- **core → main:** the session asks main to perform each request it needs (`shell.rpc`, `shell.gateway`, `shell.tezos`, `shell.verified`, `shell.prefetch`), using 0001's existing support for requests in both directions;
- **the core decides everything else:** which endpoints, which block, deadlines, quarantine, agreement, trust labels, the result, and its cache lifetime.

Main stays a transport: it maps opaque endpoint references to URLs, performs HTTP through the Electron session's network stack with today's bounds and protections, calls the Myotis and Colibri adapters, and turns replies into today's IPC result shapes.

## Goals and non-goals

**Goals**
- **Parity** with the pinned resolvers, observable through the replay vectors: the requests made, their order and timing, cancellations, cache lifetimes, and results with key presence and order.
- **Every deviation** is listed in [Deviations](#deviations) with its failure and cache behavior and a boundary vector.
- **Bounded resources:** every queue, cache, response and reply has a byte or count bound that sits above every valid answer.
- **No endpoint URL in the core** (0003 decision 3), so no API key can reach a log, a crash report or a reply.

**Non-goals**
- **New trust semantics** (0003's open question 1); new record types.
- **Myotis' and Colibri's own networking** (roadmap 3.3). The core calls them through main's adapters.
- **Mobile bindings.** The machine is platform-neutral; its driver on iOS and Android comes later.

## The protocol

### Methods main calls

All accept caller kinds `chrome` and `shell`. Each carries `private: bool`: the core redacts the name in its logs (`redactForLog`), as today's private-window handlers do.

| Method | Params | Result | Replaces |
|---|---|---|---|
| `naming.configure` | a [configuration snapshot](#configuration) | `{ generation }` | registry reads, `invalidateCachedProvider` |
| `naming.availability` | `{ myotis: { enabled, ready, epoch } }` | `{}` | `myotisManager.onAvailabilityTransition` |
| `naming.resolve_content` | `{ name, private }` | a [resolution reply](#replies) | `resolveEnsContent` |
| `naming.resolve_address` | `{ name, chain_id, private }` | a resolution reply | `resolveEnsAddress` |
| `naming.resolve_reverse` | `{ address, chain_id, private }` | a resolution reply | `resolveEnsReverse` |
| `naming.resolve_tezos` | `{ name, private }` | a resolution reply | `resolveTezosDomain` |
| `naming.invalidate_content` | `{ name }` | `{ evicted: bool }` | `invalidateEnsContent` |
| `naming.invalidate_tezos` | `{ name? }` | `{}` | `invalidateTezosDomain` |

- **Admission:** a lookup answered from the cache, or one that joins a running session, is answered without taking one of 0001's 64 slots. A session takes one slot until it ends, however many callers wait on it.
- **Deadline:** 120 s per resolution method (a [deviation](#deviations); today has no overall bound). Main's hang watchdog is 0001's rule: deadline + 15 s.
- **Cancellation:** `cancel` detaches that caller; the caller gets `cancelled`. The session keeps running and caches its result, as today's shared promise does.

### Requests the core makes

Main implements these. Every one carries `generation` (the [configuration](#configuration) it was issued under) and a `deadline_ms`. Main answers a request whose generation is no longer current with `stale_generation` and performs nothing, so an endpoint removed from the configuration is never contacted again. The core cancels with 0001's `cancel`; main aborts the work and still sends one terminal reply.

| Method | Params | Main does | Reply |
|---|---|---|---|
| `shell.rpc` | `{ endpoint, body }` | POST `body` (one JSON-RPC request) to the endpoint's URL through the session stack | `{ status, body }` or a [transport error](#transport-errors) |
| `shell.tezos` | `{ endpoint, method, path, body? }` | GET or POST `endpoint URL + path` | `{ status, body }` or a transport error |
| `shell.gateway` | `{ url, method, body? }` | `netGatewayFetch` with today's flags (below) | `{ status, body }` or a transport error |
| `shell.verified` | `{ verifier, to, data }` | Myotis `ethCall` or Colibri `request('eth_call')` at `latest` | `{ data }`, `{ revert }` or `{ unavailable, reason }` |
| `shell.prefetch` | `{ uri }` | `prefetchGatewayUrl(uri)` | `{}` when it ends (finished, failed, its 10 s timer, or cancelled) |

- **Bodies** travel as base64 in both directions.
- **Gateway flags** are recorded in every gateway request of the vectors: `redirect: 'error'` at the fetch level over the transport's `manual`, `credentials: 'omit'`, `useSessionCookies: false`, `cache: 'no-store'`, `bypassCustomProtocolHandlers: true`, `Accept: application/json`.
- **Verifier ownership:** a `shell.verified` request names its verifier. A CCIP callback goes to the verifier that produced the lookup (see [CCIP-Read](#ccip-read)).

### Replies

A resolution reply is one of:
- `{ result, undefined_keys }`: `result` is today's result object, with its keys in today's order. `undefined_keys` lists the top-level keys that are present with the value `undefined` (Tezos `ttl`, an address `error`); they appear in `result` as `null` placeholders, and main sets them back to `undefined`. A marker value inside `result` would be ambiguous, because Tezos `ttl` is arbitrary JSON from the chain.
- an error `resolution_failed` with `data.message`: today's thrown resolution. Main builds today's IPC error object from it (`{ type: 'error', name, reason: 'RESOLUTION_ERROR', error }` for content, the `success: false` shapes for address and reverse, `{ type: 'error', reason, system: 'tezos' }` for Tezos).

**Endpoint references in results.** Where today's results name endpoints, the core writes `{ "ref": "<endpoint>" }` and main substitutes, in exactly these places:
- ENS: `trust.agreed[]`, `trust.dissented[]`, `trust.queried[]`, `groups[].urls[]`: the host (`hostOf`, today's helper, which returns the input when it doesn't parse);
- Colibri: `trust.prover`, `trust.agreed[]`, `trust.queried[]`: the prover's host;
- Tezos: `trust.agreed[]`: the URL (today's Tezos results carry full URLs); `groups[].urls[]`: the host.

Literal labels such as Myotis' `myotis-p2p` are plain strings and never substituted.

## Configuration

`naming.configure` replaces the whole snapshot and returns its `generation`, which only grows within a core process.

```jsonc
{ "generation": 7,
  "reset": "providers",            // "none" | "providers": today's invalidateCachedProvider
  "rpc": [ { "endpoint": "e3", "user_configured": false }, … ],  // effective order
  "direct": { "endpoint": "e3", "user_configured": true },       // or null
  "prover": { "endpoint": "p1", "zk": true },                    // or null
  "policy": { "order": ["myotis", "colibri", "quorum"], "prefer_verified": false },
  "quorum": { "k": 3, "m": 2, "timeout_ms": 5000, "anchor": "latest", "anchor_ttl_ms": 30000 },
  "tezos": [ "t1", "t2", "t3" ] }
```

- **Main computes the inputs as today:**
  - `rpc` is `getEffectiveRpcEndpoints()` (with `ETH_RPC` prepended, deduplicated case-insensitively);
  - `direct` is `getDirectRpcCandidate(1)` (the first registry endpoint, ignoring `ETH_RPC`);
  - `policy` is `resolutionPolicy()` (including the legacy `primary` mapping);
  - `quorum` is the raw `network.quorum` values;
  - `tezos` is `getRpcEndpoints()` (with `TEZOS_RPC` prepended).
- **The core applies today's clamps and defaults** where today's code applies them. `quorum` stays raw because the reference clamps differently in different places: `resolveViaQuorum` clamps K and M from 1, `getPinnedBlock` from 2, and then the anchor's effective M (`anchor-finalized` and the `quorum-*` scenarios).
- **References are stable:** main assigns one reference per distinct URL and never reuses it for another URL within a core process. Quarantine is keyed by reference, so it survives a list change that keeps the URL, as today's URL-keyed map does.
- **Reads happen where today's code reads:** a session reads the current snapshot at the same points today's code calls `registry.getNetwork` and `getEndpoints`.
- **The shuffle** is recomputed when the joined `rpc` reference list changes (today's `sourceKey`).
- **`reset: "providers"`** is today's `invalidateCachedProvider`, used after a settings edit:
  - it clears the shuffle, quarantine and anchor;
  - it clears the content, address and reverse caches;
  - it advances the lifecycle epoch;
  - it leaves Tezos untouched (`settings-invalidation`).

**`naming.availability`** is today's Myotis transition listener, for chain 1 only:
- it clears the content, address and reverse caches and the in-flight table, and advances the lifecycle epoch;
- it keeps the anchor, the shuffle and quarantine, and doesn't touch Tezos (`myotis-ready-mid-flight`, `lifecycle-flapping`).

## The ENS machine

The rules below restate the reference, so a reviewer can check them against the code. The vectors are what the implementation is tested against.

### Pool and quarantine

- **Available endpoints** are the shuffled `rpc` list minus the quarantined ones. Checking an entry deletes it once expired, so its failure count restarts (`quarantine-expiry-resets`).
- **A failure** increments the entry's count and sets its cooldown to `min(60 s × 2^(count−1), 600 s)` from now. Only failures that overlap within one entry's lifetime double it (`quarantine-doubles-on-overlapping-failures`).
- **A success** deletes the entry.
- **The shuffle** is Fisher–Yates over a uniform `[0, 1)` source, `j = floor(r × (i + 1))`, from the last index down. The machine takes the source as a parameter; replay feeds it the recorded seed through mulberry32.

### The anchor

`getPinnedBlock`, run when the quorum method needs a block:
1. **Clamps:** `K = clamp(k or 3, 2, 9)`, `M = clamp(m or 2, 2, K)`. The deadline is `timeout_ms or 5000`. The tag is `anchor or "latest"`, and the TTL is `anchor_ttl_ms` if it is a number, else 30 s.
2. **Cache:** a cached anchor with the same tag and an unexpired TTL is returned.
3. **Too few endpoints:** below 3 available endpoints, there is no anchor (the caller degrades).
4. **Heads:** every available endpoint is asked for its head at once, each with its own deadline. For `finalized`, the request is `eth_getBlockByNumber("finalized", false)`, and `null` is a failure; otherwise it is `eth_blockNumber`. A failure marks quarantine. After all settle, each success clears quarantine (`quorum-agree`, `quorum-slow-endpoint-head`).
5. **Median:** below 3 heads, there is no anchor. Otherwise the upper median, `sorted[floor(n/2)]`.
6. **Target:** the median minus the depth: 8 for `latest`, 32 for `latest-32`, 0 for `finalized`, 8 for any other tag.
7. **Hashes:** the head responders are asked for the block hash at the target (`eth_getBlockByNumber(target, false)`). A failure marks quarantine.
8. **Agreement:**
   - **Buckets:** responses are bucketed by hash in response-list order. The winner is the first bucket with the strictly largest size.
   - **Threshold:** `max(min(M, available), floor(hashes/2) + 1)`.
   - **Win:** the winners are marked successful and the anchor is cached.
   - **Otherwise it throws** `Could not reach hash quorum at block N (largest bucket X of Y responses, need ≥T)`, with no fallback (`anchor-hash-split`).

### Legs, waves and agreement

**A leg** is one call to one endpoint at the pinned block hash, under one deadline (`timeout_ms`) that covers the RPC call, its CCIP gateway fetches and its callback calls (`ccip-slow-gateway-then-another-name`). Its outcome:
- **`data`** (raw return bytes): clears quarantine.
- **`not_found` `NO_RESOLVER`:** a `ResolverNotFound` or `ResolverNotContract` revert. Clears quarantine.
- **`error` without quarantine:** the deadline expired after a gateway was used, or the gateways all failed. Quarantine is cleared.
- **`error` with quarantine:** a provider failure (see [Classification](#classification)) or the deadline before any gateway.
- **`not_found` `NO_CONTENTHASH`** with the error: any other revert. Clears quarantine.

**A wave** runs its legs at once.
- **Early agreement:** after each leg settles, a data bucket of size ≥ M ends the wave as `agreed_data`; otherwise a negative bucket (by reason) of size ≥ M ends it as `agreed_not_found`. The remaining legs are cancelled.
- **Losing legs:** their HTTP requests are not aborted today. ethers' `destroy()` leaves them to finish, and the vectors record them as `answered` after settlement.
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
  - **Calls:** ENS records through the Universal Resolver's `resolve` at `latest`. WNS/GNS calls go straight to their NameNFT contracts.
  - **The lifecycle guard is the core's:** each step records the availability epoch first, and a changed epoch or a lost readiness afterwards aborts the lookup with a lifecycle change (see [Sessions](#sessions)).
  - **Trust:** `verified`, `method: myotis`, finality `optimistic`, unless Myotis reports a finalized result.
  - **Results:** `noRecord` re-encodes to today's empty ABI forms.
  - (`myotis-verified`, `myotis-ccip`)
- **Colibri:**
  - **Calls:** through main's adapter, which keeps today's single client rebuild and retry (`colibri-unavailable-falls-to-quorum`: two verified requests, then quorum).
  - **Results:** a proven `ResolverNotFound` is a verified `NO_RESOLVER` (`colibri-resolver-not-found`). Any other failure is a method error, and the order continues.
  - **Trust:** `prover` is the prover's host, and `proof` is `ZK sync-committee proof` or `Sync-committee proof` (from `zk`).

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
  - NameNFT names (`.wei`, `.gwei`) call their contract directly (`wns-content`).
  - Conflicts and decoded results are cached.
  - **`NO_CONTENTHASH` with an error is not cached.**
  - The empty contenthash is `EMPTY_CONTENTHASH`.
  - Unparseable contenthash bytes are `unsupported`.
- **Address:**
  - The coin type is 60 on chain 1, else `0x80000000 + chain`. A NameNFT name off chain 1 is `CHAIN_UNSUPPORTED`, cached, with **no I/O** (`wns-address-on-l2`).
  - `NO_CONTENTHASH` becomes `RESOLUTION_ERROR`, and it **is** cached.
  - The zero address and empty bytes are `NO_ADDRESS` (`address-*`).
- **Reverse:**
  - **ENS:** through the UR's `reverse`, encoded as `(uint8 status, string detail)` so legs agree on semantic outcomes. A `ReverseAddressMismatch` is `UNVERIFIED` with the claimed name (`reverse-*`).
  - **WNS, then GNS:** on chain 1, an ENS `NO_REVERSE` falls back to WNS, then GNS, through **the same method** that produced the ENS answer. A claim is checked by a forward `addr` through that method too (`reverse-ens-empty-then-wns`).
  - **Provisional:** a result that is `unverified` or `UNVERIFIED`.

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
- **Bounds:** each holds at most 500 entries. Over that, expired entries go first, then the oldest by insertion (`capCache`). Each cache also has a byte budget (see [Bounds](#bounds)).
- **A hit** needs `now < expiresAt`, exactly: a hit at +899,999 ms, a miss at +900,000 ms.

### Sessions

- **The key** is today's in-flight key, `content|addr|reverse` + the cache key. A same-key lookup joins the running session, and different keys don't share, so content and address of one name each anchor (`dedup-concurrent`).
- **Lifecycle restarts** (`resolveAcrossStableLifecycle`):
  - A session runs at most 3 attempts.
  - An attempt whose lifecycle epoch changed, whether it succeeded or threw, is discarded. Its cached result is removed if it is still the cached one, and the session restarts.
  - After 3 attempts, it throws `Myotis availability changed repeatedly while resolving <name>`.
  - The in-flight table is cleared at each epoch change, so a lookup after the change starts a new session rather than joining the old one.
- **Late and duplicate answers:** a reply for a request the session no longer waits for is dropped. A reply from an earlier core process never arrives, since main binds requests to its child generation (0001).
- **Terminal results** cancel what is outstanding, except the losing legs' HTTP, which today runs to completion. The core cancels it: a [deviation](#deviations) without effect on results.
- **Timers** run on the daemon's monotonic clock and fire without waiting for a message: deadlines, quarantine, cache expiry, the anchor TTL.

### Classification

A leg's error is classified from **structured fields only**:
- the ethers-equivalent code the core assigns from the transport outcome (HTTP status, timeout, network failure, JSON-RPC error);
- the JSON-RPC error code;
- revert data.

The core never matches text that embeds request data or contract-controlled strings. The reference also matches message text in places; the core's narrower rule is a [deviation](#deviations). The node-failure rule from freedom-browser#656 (node errors with no revert evidence are endpoint failures) is adopted as a deviation until the reference pin includes it.

### CCIP-Read

- **Pinned legs** (quorum, single source, direct):
  - **The loop:** at most 10 rounds. Each round needs an `OffchainLookup` revert whose sender is the Universal Resolver, else the leg fails with today's error. The callback goes to **the same endpoint at the same block hash** (`ccip-fast-gateway`).
  - **Gateways** are tried in list order, 15 s each, through `shell.gateway`. The [codec](0003-naming.md#codecs) decides a URL's eligibility (`https`, no credentials, not an IP, a dotted host, not `.localhost`/`.local`/`.internal`), the GET or POST shape, and the answer's validity. Main refuses the same URLs again, failing closed.
  - **All gateways failing** is `CCIP_GATEWAY_FAILED`.
- **Verified paths** (Myotis, Colibri) follow ethers' built-in loop at `latest`, as today. The lookup's callback goes to **the verifier that produced it** (`myotis-ccip`). A verified revert carries its verifier as provenance.
- **NameNFT calls** never use CCIP-Read.

### Prefetch

- **Start:** the first `data` of a content wave starts a prefetch of the decoded `ipfs://` or `bzz://` URI (never `ipns://`). A decoding failure starts nothing.
- **Cancel:** any wave outcome other than `agreed_data` cancels it.
- **Survival:** it survives an agreed answer, including one the result later rejects. Main bounds it with today's 10 s timer.
- **Own bound:** it is a separately bounded effect: at most one per wave, and it never blocks the session.

## The Tezos machine

`resolveTezosDomain`, with its own caches and sessions (keyed by the lowercased name):
1. **Validation:** an invalid name is `not_found` `invalid .tez domain`, uncached (`tezos-invalid-name`).
2. **Heads:** the first 3 endpoints are asked for `chain_id` and the head header at once, 8 s each. A wrong chain or level ≤ 8 is a failure. No head is the error `all Tezos RPC providers failed`, uncached (`tezos-all-down`).
3. **Head agreement:** heads more than 60 levels from the lower median are excluded. If at most half remain, the result is a head `conflict` (`tezos-head-outlier`, `tezos-heads-scattered`).
4. **Anchor:** the minimum retained level − 8 is the anchor level. Its hashes are bucketed, and if the largest bucket isn't a strict majority, the result is an anchor `conflict` (`tezos-anchor-split`).
5. **Lookups:** the anchor's endpoints run at once:
   - **Discovery:** the proxy script, then the registry script, each POST with `unparsing_mode: "Readable"`. It is cached per endpoint for 10 min (the second name in `tezos-agree` skips it). A lookup that fails on cached discovery drops the cache entry and rediscovers. An endpoint whose discovery fails drops out of the lookups (`tezos-registry-script-fails`).
   - **The record**, then **the expiry**. A missing expiry is a failure. An expiry at or before now is `not_found` `domain record expired` (`tezos-expired`). An expiry that `Date.parse` can't read is ignored (`tezos-expiry-unparseable`).
6. **Agreement:** results are grouped by today's semantic key. If several groups exist and the largest isn't a strict majority, the result is a `conflict`. Otherwise the winner, `verified` when ≥ 2 agree, else `unverified`, with `agreed` listing its endpoints.
7. **Cache:**
   - **Non-`ok` results:** 30 s (`tezos-no-record`).
   - **Unverified ones:** 30 s (`tezos-two-down`).
   - **Verified ones:** the record's `td:ttl` seconds when finite and positive, else 5 min, capped at 1 h and at the time left before expiry, and at least 1 s.
   - **Errors and conflicts are not cached.**

**Expiry parsing:** the core accepts what V8's `Date.parse` accepts for the strings Tezos RPC returns (RFC 3339 timestamps, Readable mode). Any other string is a [deviation](#deviations): the core treats it as unparseable, where V8 would apply its legacy, time-zone-dependent formats. The vector uses an RFC 3339 string and an unparseable one.

## Transport

- **One request per HTTP request:** each JSON-RPC request travels alone. The reference never batches here, because every leg and probe uses its own ephemeral provider (`http` differs per request in every vector).
- **Request bodies:** the core writes them, `{ "jsonrpc": "2.0", "id", "method", "params" }`, with today's params:
  - `eth_blockNumber []`;
  - `eth_getBlockByNumber [hex or tag, false]`;
  - `eth_call [{ to, data }, blockHashOrTag]`.
- **Response handling:** the core parses the body and maps failures as ethers' `JsonRpcProvider` does today (HTTP status, invalid JSON, JSON-RPC errors and their revert data), so classification sees the same facts.
- **The session's network stack:** main sends `shell.rpc` and `shell.tezos` through the Electron session's network stack, as 0003 decided:
  - **Clearnet:** `DIRECT` under today's PAC.
  - **Onion:** the onion gate applies to every host. There is no empty or `DIRECT` route and no `DIRECT` fallback.
  - **Other protections:** no credentials, no cookies, no HTTP cache, no custom protocol handlers, and errors on redirect.
  - **What changes:** today these requests leave through Node's own stack (ethers' `getUrl`, and the Tezos resolver's global `fetch`). This is the goal 0003 states.

### Transport errors

Main's terminal reply for an I/O request is a result or one of these:
- `timeout`: the request's own deadline, which the core sets;
- `network`: DNS, connect, TLS or a reset;
- `refused`: the URL failed main's policy;
- `too_large`: the response exceeded the request's byte cap;
- `cancelled`;
- `stale_generation`.

No error carries a URL or a server's text.

## Bounds

**Responses and frames.** Every message fits 0001's 1 MiB frame. A body travels as base64, so each response body is capped at **720 KiB**, which is 960 KiB in base64:

| Answer | Measured | Today's cap | Core cap |
|---|---|---|---|
| `eth_getBlockByNumber(n, false)`, 10 recent mainnet blocks | 14.7–25.3 KB | none | 720 KiB |
| the same, worst case at today's 60 M gas: ~2,857 transfers | ~200 KB | none | 720 KiB |
| Tezos Domains proxy and registry scripts | 2.5 KB, 22.6 KB | 5 MiB | 720 KiB |
| CCIP gateway answers | a few KB | 4 MiB | 720 KiB |

- **Over the cap:** the reply is `too_large`, a provider failure for RPC and Tezos, and a failed gateway for CCIP, which moves on to the next URL as today.
- **Decoding budgets are reserved before allocating:**
  - base64: 720 KiB;
  - JSON: depth 512, with 0003's `json-depth` deviation;
  - ABI reads: 0003's 1024× read cap;
  - hex: the answer's own length.
- **Replies:**
  - **Conflict groups:** a `resolvedData` longer than 8,192 hex characters is shortened to its first 4,096 and last 4,096 characters. Today's renderer shows only a value's first 16 and last 10 characters, and its exact matches have fixed short lengths, so nothing it shows changes.
  - **Unsupported results:** the same applies to `contentHash`.
  - **Too large:** any other reply over 960 KiB becomes `resolution_failed: result too large`.

**Queues:**
- **I/O in flight:** a session's own I/O is bounded by its structure: anchor probes ≤ the endpoint count, legs ≤ 9 per wave, one gateway at a time per leg, ≤ 3 Tezos endpoints, one prefetch per wave.
- **Endpoints:** a configuration holds at most 64 endpoints. Main validates that.
- **Outgoing requests:** at most 256 core → main I/O requests are outstanding. More wait, first in, first out, in the core. Their deadlines keep running, and an expired one is never sent.
- **Control traffic:** 0001's reserved capacity keeps vault control responsive behind naming traffic.
- **Caches:** each holds 500 entries and 8 MiB. Over either bound, the eviction order above applies.

## Deviations

Each deviation gets a boundary vector in the implementation PR. 0003's codec deviations (`name-length`, `json-depth`, `lone-surrogate`, `lone-surrogate-keys`) still apply.

| ID | Today | The core | Failure and cache behavior |
|---|---|---|---|
| `overall-deadline` | no overall bound | 120 s per resolution method | `resolution_failed` "timed out"; not cached |
| `verified-deadline` | Colibri 60 s (its worker); Myotis unbounded at this layer | 60 s per `shell.verified` | a method error; the order continues |
| `losing-legs` | their HTTP finishes after agreement | cancelled at agreement | none: results don't depend on them |
| `rpc-stall` | ethers holds every JSON-RPC request 10 ms (its batch stall) | sent at once | none. Replay adds the 10 ms back (see [Replay](#replay)) |
| `response-caps` | none for JSON-RPC; 5 MiB Tezos; 4 MiB gateways | 720 KiB each | `too_large`: a provider failure, or the next gateway |
| `reply-shortening` | full `resolvedData` and `contentHash` | first + last 4,096 hex characters when longer | none in the renderer |
| `reply-size` | unbounded | 960 KiB | `resolution_failed: result too large`; not cached |
| `cache-bytes` | 500 entries per cache | also 8 MiB per cache | eviction |
| `monotonic-time` | TTLs, quarantine and deadlines on `Date.now()` | the monotonic clock; Tezos expiry still compares wall time | none unless the wall clock jumps |
| `error-text` | ethers' full message, which embeds node text and request data | the class's short message, sanitized like `sanitizeErrorDetail` (URLs → `<url>`, long hex shortened, 240 characters) | same codes and branches; the text differs |
| `classification` | some errors are classified by message text | [structured fields only](#classification) | as [Classification](#classification) |
| `node-failures` | node errors can agree into a verified not-found (`node-errors-agree`) | freedom-browser#656's rule | until the reference pin includes it |
| `transport` | Node's HTTP stack | the session's network stack | `.onion` endpoints work under Tor, and a missing route fails closed |
| `tezos-expiry` | V8's legacy `Date.parse` formats | RFC 3339 only | an unreadable expiry is ignored, as today's `NaN` |

## Replay

The Rust machine runs each scenario of `naming-replay.json`:
- **Inputs:** the recorded seed (through mulberry32), world and steps;
- **Clock:** a virtual clock starting at the recorded epoch;
- **Driver:** a test driver that plays main.

**The driver reproduces two reference artifacts:**
- it delays each JSON-RPC request by 10 ms before the world sees it (ethers' stall);
- it answers Colibri's `eth_chainId` locally, as the client does.

**Compared exactly:**
- every result, with key order and present-`undefined` keys;
- every settlement time;
- every I/O request: endpoint, method, params, start, end, outcome.

**Excepted, by rule:**
- the fields covered by a deviation, compared under that deviation's rule;
- the losing legs' outcomes (`answered` in the reference, `cancelled` in the core).

Deviation vectors come from the same harness with the reference patched in memory where a deviation has no natural trigger. Each such patch is recorded in the vector.

## Traceability

Every item of 0003's [What design 0004 must satisfy](0003-naming.md#what-design-0004-must-satisfy):

| 0003 requirement | Here | Vectors |
|---|---|---|
| Result, trust and error schemas with key presence; present `undefined`; TTLs and non-cacheable cases | [Replies](#replies), [Caches and TTLs](#caches-and-ttls), [Tezos](#the-tezos-machine) | every scenario; `cache-boundary-*`, `tezos-no-record`, `tezos-redirect` |
| Frames, queued I/O and drain, decoding budgets, aggregate bounds, vault responsiveness, answer caps | [Bounds](#bounds) | `response-caps`, `reply-size` (implementation PR) |
| Anchor: all endpoints, ≥ 3 heads, upper median, hash plurality, single-source fallback, throwing on a split | [The anchor](#the-anchor) | `quorum-agree`, `quorum-slow-endpoint-head`, `anchor-hash-split`, `anchor-finalized` |
| Quarantine: 60 s doubling while an entry lasts, reset on success or expiry; gateway failures don't quarantine | [Pool and quarantine](#pool-and-quarantine), [Legs](#legs-waves-and-agreement) | `quarantine-*`, `ccip-slow-gateway-then-another-name` |
| Second wave, K/M clamps, `direct`, provisional rules, WNS/GNS fallback, chain rules | [Legs](#legs-waves-and-agreement), [Method order](#method-order), [Content, address and reverse](#content-address-and-reverse) | `direct-*`, `prefer-verified-holds-unverified`, `reverse-*`, `wns-*` |
| Tezos quorum, discovery isolation and caches, expiry | [The Tezos machine](#the-tezos-machine) | `tezos-*` |
| Deadlines: per leg around gateways and callbacks; single source shares one; NameNFT without CCIP | [Legs](#legs-waves-and-agreement), [Single source](#single-source-and-direct), [CCIP-Read](#ccip-read) | `ccip-*`, `direct-*` |
| Security: sender check, callback binding, verified provenance, redacted diagnostics, verifier ownership | [CCIP-Read](#ccip-read), [Transport errors](#transport-errors), `error-text` | `ccip-*`, `myotis-ccip` |
| Generations on replies and I/O, retiring dedup entries, three attempts, per-event invalidation | [Requests the core makes](#requests-the-core-makes), [Configuration](#configuration), [Sessions](#sessions) | `myotis-ready-mid-flight`, `lifecycle-flapping`, `settings-invalidation` |
| Sessions: dedup key, subscriber cancellation, late answers, terminal cancellation, timers without messages, prefetch | [Sessions](#sessions), [Prefetch](#prefetch) | `dedup-concurrent` |
| The full deviation inventory | [Deviations](#deviations) | per deviation (implementation PR) |

## Implementation steps

These refine 0003's step 4:
1. **`fc-naming::session`:** the ENS and Tezos machines, the replay driver and the replay tests. No daemon yet.
2. **`freedom-cored`:** the `naming.*` methods, the `shell.*` requests, admission and bounds. Measure cached subresource fan-out under concurrent vault work (0003 decision 4) before committing to core-owned caches.
3. **freedom-browser:** main's executors and the result mapping. The resolvers become drivers (0003 step 5).

## Open questions

1. **The overall deadline.** Is 120 s right? The worst case today, a reverse lookup with every method failing slowly, is several minutes. Typical lookups take under 1 s.
2. **Shortening versus refusing.** Should an oversized `resolvedData` shorten as above, or make the reply a `RESOLUTION_ERROR`? Shortening keeps today's interstitial.
3. **0003's open questions** (trust semantics, EIP-3668's 4xx rule) remain open. Nothing here depends on them.
