# 0005: Chain data in the core

**Status:** proposed. Builds on [0001](0001-freedom-cored.md) (process, framing, deadlines), [0002](0002-signing.md) (signing) and [0004](0004-naming-sessions.md) (sessions, `shell.*` requests, verified operations, endpoint references, budgets). It is roadmap item 3.4: freedom-browser's chain-data router moves into the core.

**The reference** is `src/main/networks/chain-data-router.js` at freedom-browser `fb540328`, with `blockscout-logs.js` and the Ant bridge's router options (`swarm/ant-chain-bridge.js`).
- **Ground truth** will be a replay harness, `vectors/chain-replay.json`, built like 0004's: it runs the pinned router through scripted worlds and records every exchange, verifier operation, timing, result and error. Its scenario IDs are cited below once it exists.
- **Conflicts:** where this document and a vector disagree, the vector wins and the document has a bug.

## Summary

A chain read, a fee quote or a broadcast becomes a **request** in `freedom-cored`, run by a sans-I/O machine in a new crate, `fc-chain`. It reuses `fc-naming`'s executor, its `jsjson` codec and 0004's session machinery:
- **main → core:** `chain.request`, `chain.fee_quote` and `chain.broadcast` replace the router's three entry points.
- **core → main:** the request asks main for each I/O it needs:
  - `shell.rpc`: one JSON-RPC exchange with an endpoint, the same executor naming uses;
  - `shell.verified`: a whole Myotis or Colibri operation through today's adapters;
  - `shell.blockscout`: one page of Blockscout's log index.
- **The core decides everything else:** the source order, deadlines, quorum agreement, the hand-off to Direct, log-range learning, the truncation check, Blockscout pairing, fee quotes, broadcast outcomes and trust labels.

Main keeps:
- the wallet IPC surface, the `web3:` handler and the Ant bridge's localhost server, which become drivers;
- endpoint references, mapped to URLs as in 0004;
- HTTP through the Electron session's network stack;
- the verifiers' adapters, unchanged.

Unlike naming, chain data passes **node errors** through to dApps, and its answers **outgrow 0001's 1 MiB frame**. [Frames](#frames) and [Errors](#errors-and-text) settle both.

## Goals and non-goals

**Goals**
- **Parity** with the pinned router, observable through the replay vectors: the requests made, to which endpoint, in which order and at what time; cancellations; results with key order; errors with code, message and data.
- **Every deviation** is listed in [Deviations](#deviations) with its behavior and a boundary vector.
- **Bounded resources:** requests, answers, replies, retained state and time all have bounds, with a defined result when exhausted. Today none exist beyond the verifiers' slots.
- **The core is never given an endpoint URL** (0004's [Secrets](0004-naming-sessions.md#secrets)).
- **No lost broadcasts:** no reply reports a failure for a transaction that may have reached the network ([Broadcast](#broadcast)).

**Non-goals**
- **Pinning chain reads to a block**, and new trust semantics. Today's router reads at the caller's tag and calls m equal answers `verified`. Changing either is roadmap 3.1's decision, not this design's.
- **Nonce management.** Each send still reads the `pending` count. A per-account nonce floor in the core is an [open question](#open-questions).
- **Paths that bypass the router today:** provider-manager's Safe reads and `wallet:test-provider`. Absorbing them is a follow-up; `wallet:proxy-rpc` has no callers and should be deleted.
- **The verifiers' own networking** (roadmap 3.3), as in 0004.
- **Mobile drivers.**

## The protocol

### Methods main calls

All accept caller kinds `chrome` and `shell`.

| Method | Params | Result | Replaces |
|---|---|---|---|
| `chain.configure` | a [snapshot](#configuration) for every configured chain | `{ generation }` | the router's registry reads |
| `chain.availability` | `{ chain_id, ready }` for each Myotis chain | `{}` | the router's live `myotis.isReady()` samples |
| `chain.request` | `{ chain_id, method, params, include_trust, origin?, background, profile }` | `{ result, source, verified, trust? }` | `request()` |
| `chain.fee_quote` | `{ chain_id }` | today's quote shape | `getFeeQuote()` |
| `chain.broadcast` | `{ chain_id, raw }` | `{ hash, source, outcome }` | `broadcastRawTransaction()` |

- **`params`** is the caller's JSON as main serializes it. The core parses it with `jsjson`, keeping JavaScript's property order, which [normalization](#normalization) depends on.
- **`origin`** is the router's routing context: the dApp's permission key or the `web3:` page's. It makes the read *interactive*. The core keeps it only in memory, for the [adaptive bypass](#adaptive-bypass), and never logs it.
- **`profile`** is `default` or `ant_scan`. Callers can't pass functions over the pipe, so the Ant bridge's options (`rankError`, `rangeCapOf`, the exclusions, Blockscout, the widened quorum budget) become one named profile, ported with vectors ([Logs](#logs)).
- **`background`** is the Ant bridge's flag: never queue for Myotis.
- **Cancellation** is 0001's `cancel`, which replaces the router's `AbortSignal` ([Cancellation](#cancellation)).
- **`isReadMethod`** stays in main: it is a constant table, mirrored with a vector.

### Requests the core makes

| Method | Params | Main does | Reply |
|---|---|---|---|
| `shell.rpc` | `{ endpoint, body, policy: "plain", max_bytes, generations, deadline_ms }` | one exchange through the session's stack | `{ status, body }` or a transport error |
| `shell.verified` | a [verified operation](#verified-operations) | today's adapter, whole | the operation's outcome |
| `shell.blockscout` | `{ endpoint, query, max_bytes, generations, deadline_ms }` | one page through `blockscout-logs.js`'s redirect and address policy | `{ status, headers, body }` or a transport error |

- **`shell.rpc`** is naming's executor, with two parameters added:
  - **`policy: "plain"`**: no 429 back-off and no repeated attempts, as today's router does; naming keeps ethers' loop.
  - **`max_bytes`**: the answer cap the core accepts, up to 16 MiB for chain data (naming stays at 720 KiB).
  - Redirects follow naming's rule: each hop is checked against the endpoint policy and the onion gate, and the method and body are kept (deviation `rpc-redirects`).
- **The body** is today's `JSON.stringify({ jsonrpc: '2.0', id, method, params })`, with `id` a per-request counter (deviation `rpc-id`).
- **`shell.blockscout`** keeps main's DNS check: an off-origin redirect must not resolve to a local address. That check needs DNS, which the core doesn't do.

### Frames

Chain-data answers routinely exceed 0001's 1 MiB frame: full-history `eth_getLogs` scans, blocks with their transactions, and `html()` documents of up to 8 MiB, which are 16 MiB as hex.

- **Fragments.** A new frame kind, `0x02`, carries a fragment of one JSON message. A message is any number of `0x02` frames followed by one `0x01` frame with its last part. Every frame stays within 1 MiB.
- **One fragmented message at a time** per direction. Between its fragments, whole messages may still go, so control traffic and other replies aren't held behind it. That is 0001's reserved capacity, unchanged.
- **The message cap** is 24 MiB: a 16 MiB answer is 21.3 MiB as base64. The receiver holds the one partial message against its reader bound, and refuses a larger total as a protocol error.
- **Negotiated** in the handshake. `core.hello`'s capabilities gain `fragments`, and main's hello params gain `frames: ["fragment"]`. A side sends fragments only to a peer that offered them. Main and the core ship together, so neither falls back.
- **Not streams.** Phase 4's streams (0001) remain separate: stream IDs, credit and protocol version 2. Fragments carry one whole message and are parsed only when complete.

### Verified operations

Myotis and Colibri keep running in main through today's adapters, one whole operation per request (0004's rule). The operations the router needs:

| Operation | Main runs | Reply |
|---|---|---|
| `{ myotis: "account", chain_id, address }` | `myotisManager.getAccount` | the payload, plus `optimistic_block_number` before and after |
| `{ myotis: "code", chain_id, address }` | `getCode` | likewise |
| `{ myotis: "storage", chain_id, address, slot }` | `getStorageAt` | likewise |
| `{ myotis: "call_tx", chain_id, tx }` | `ethCallTx` at `latest` | likewise |
| `{ myotis: "estimate_tx", chain_id, tx }` | `estimateGas` at `latest` | likewise |
| `{ myotis: "fee", chain_id }` | `feeEstimate` | likewise |
| `{ myotis: "broadcast", chain_id, raw }` | `sendRawTransaction` | `{ hash }`, `{ rejected: { reason } }`, `{ uncertain }` or `{ not_sent }` |
| `{ colibri: "request", chain_id, method, params, deadline_ms }` | `requestViaColibri` | `{ result }`, `{ error: { code?, message, data? } }` or `{ failure }` |

- **Payloads** are the adapters' own JSON, with 0004's snake_case keys. The core runs `assertMyotisAnswer`'s classification: revert, refusal, infeasible, capability refusal, unavailable.
- **Broadcast classes** are exactly myotis-process's:
  - `not_sent`: queued and expired, or the client wasn't running;
  - `uncertain`: dispatched, then a deadline, an exit or a stop.
- **Admission:** the router's slots stay as the core's admission rules, held until main's terminal reply. Myotis has 1 in flight and 16 waiting per chain, and background callers take only an idle slot. Colibri has 8 in flight, 2 per route.
- **Physical completion:** main replies only when the adapter's promise settles, never early. Main's per-verifier bound (0004: 8 operations) is shared by naming and chain data.

### Replies

- **A result** is `{ result, source, verified, trust? }`, keys in today's order.
  - **`result`** is the answering source's JSON, forwarded as text ([Answers](#answers)). Main parses it with `JSON.parse`, the same parse today's `response.json()` runs.
  - **`source`** stays on every result, so `chain-data-activity`'s watchdog records still work.
- **Endpoint references** in `trust` (`agreed`, `dissented`, `queried`, `prover`) are substituted by main with the host, as 0004 does. One difference: the router's `endpointHost` gives `''` for a URL that doesn't parse and drops it, where naming keeps the input. Main follows the router here.
- **An error** is today's thrown error, rebuilt by main: `{ code, message, data }` ([Errors](#errors-and-text)).

### Generations

- **Configuration:** a `chain.configure` that changes a chain advances that chain's generation. A request carries the generation it started under, and its `shell.*` requests carry it too.
  - Main answers a request whose generation is no longer current with `stale_generation` and performs nothing.
  - A changed chain's running requests aren't ended: today's router runs on with what it read. They do make no further requests to an endpoint that is gone.
- **Lifecycle:** none. The router has no Myotis epoch and no restarts; `chain.availability` only keeps the readiness the router samples.

### Admission

- **A separate pool** from naming's: at most **64 running and 256 waiting** chain requests. A request over the limit is `busy` at once (deviation `admission`).
- **No deduplication:** every caller is its own request, as today.
- **The writer:** chain data shares the naming thread's writer share in the daemon, with its own bound on queued replies.

### Deadlines

- **Per source**, as today:
  - `configured = max(500, quorum.timeout_ms || 5000)`;
  - an interactive read caps a source at 2 s when a later source exists;
  - the quorum's budget is a *verification* budget: when Direct comes next, its members run on to `configured`;
  - Direct gives every endpoint `configured`, walking them one at a time;
  - the Ant profile widens the quorum budget to 30 s.
- **Overall:** 120 s per request (deviation `overall-deadline`). Today a request has no overall bound: an interactive read on chain 1 can take about 39 s, and more with user settings. Past the deadline, the request ends with `deadline`, its I/O is cancelled, and nothing more is asked.
- **Main's watchdog** is the deadline plus 15 s (0001).

### Cancellation

- **A `cancel`** ends the request. Its pending `shell.rpc` and `shell.blockscout` requests are cancelled, quorum members included (deviation `abandoned-exchanges`: today's caller signal doesn't reach the quorum).
- **Verifier work** keeps its slot until main's terminal reply (parity: the router holds Myotis and Colibri slots until the operation physically settles).
- **A broadcast** cancelled after a `shell.rpc` was sent is `uncertain` ([Broadcast](#broadcast)). Today it is an `AbortError`.

## Configuration

`chain.configure` replaces every chain's snapshot:

```jsonc
{ "chains": [ {
    "chain_id": 1,
    "read_order": ["myotis", "colibri", "quorum", "direct"],
    "broadcast_order": ["myotis", "direct"],
    "quorum": { "k": 3, "m": 2, "timeout_ms": 5000 },   // raw, as the registry merges it
    "rpc": [ { "endpoint": "e3", "user_configured": true }, … ],   // registry order, ≤ 64
    "prover": { "endpoint": "p1", "zk": true },                  // or null
    "myotis": true,                                              // Myotis serves this chain
    "blockscout": { "endpoint": "b1" } } ] }                     // the Ant profile's index, or null
```

- **Main computes the inputs as today:** `access.readOrder`/`broadcastOrder` or the defaults, `getEndpoints(chainId, 'rpc')` in registry order, and the first prover.
- **The core applies today's clamps** (`k ≥ 1`, `1 ≤ m ≤ k`, `timeout ≥ 500 ms`) and adds bounds (deviation `quorum-clamps`): `k ≤ 9`, `timeout ≤ 60 s`, and at most 64 endpoints, as 0004.
- **Orders are cleaned at configuration** (deviation `order-validation`): duplicates are dropped and unknown sources removed. Today a duplicate runs twice and an unknown name fails at run time.
- **One snapshot per request** (deviation `config-snapshot`). Today's router re-reads the registry at a dozen points of one request, so a change mid-request is seen piecemeal.
- **When main sends it:** at startup and from `network-ipc`'s `refreshDownstream`, where today only ENS and provider-manager caches are cleared.

## The router machine

The rules below restate the reference so a reviewer can check them against the code. The vectors are what the implementation is tested against.

### Methods and sources

- **Read methods** are the router's `READ_METHODS` plus the single-node methods. Anything else is refused before any I/O, with today's text: `Unsupported read method: <m>`.
- **Capabilities:**

| Source | Doesn't serve | Notes |
|---|---|---|
| myotis | the single-node methods; anything but its seven operations, refused after taking a slot (parity) | `latest` or no tag only |
| colibri | single-node methods, `eth_getLogs` | any success is `verified` |
| quorum | single-node methods | |
| direct | — | |
| blockscout | everything but `eth_getLogs` | opt-in: the Ant profile only |

- **Order:** the read order, with opt-in sources inserted before `quorum`, minus the request's exclusions and the sources that don't serve the method. An empty order fails with today's `No chain source left …` text, naming the exclusions.

### Normalization

`eth_call` and `eth_estimateGas` call objects are normalized as today (`normalizeParams`). The core reproduces JavaScript's `BigInt(string | number)` byte for byte, quirks included, with vectors for each:
- whitespace around a decimal is allowed;
- `0b` and `0o` prefixes parse;
- a negative value gives `0x-1`;
- `0X10` is accepted;
- zero-padded hex is canonicalized;
- an unparseable value is left for the node to refuse.

The `input` alias, field positions and the appended `data` key follow `jsjson`'s property order.

### Answers

The router keeps parsed values; the core keeps **text**.
- **An answer's body** is decoded as UTF-8 with replacement, its BOM stripped, and validated as JSON, as `response.json()` does.
- **Its `result`** is the last `result` member's text, since `JSON.parse` keeps the last of duplicate keys. A body without `result` answers `undefined`, as today; a JSON `null` body fails as today's `TypeError` does, with a fixed message.
- **Agreement** compares the canonical form of each answer, the router's `stableValue`: keys sorted by UTF-16 code units, values as `JSON.stringify` writes them. The core computes it in one streaming pass and keeps only its digest, so no answer is held as a tree.
- **What it retains:** the text of each group's first answer, as the router returns the first-arrived member's value.

### Quorum

- **Members:** the first k endpoints in registry order; fewer than m endpoints is today's `RPC quorum needs <m> endpoints`. All members start at once.
- **Agreement:** the first group to reach m wins. Every other member is cancelled, and the first-arrived member's answer is returned with today's trust.
- **Errors are never grouped**, as today: a revert is a member failure. Grouping identical errors is an [open question](#open-questions).
- **Impossibility, the verification timer and the hand-off to Direct** follow the router exactly:
  - it waits for a still-running member when Direct comes next and nothing has answered;
  - its `directFallback` evidence is the lowest-index member that answered, with its agreeing and dissenting hosts;
  - `directUnansweredUrls` is the members that never answered;
  - the failure kinds are `capacity` and `timeout`.

### Direct

- **Reuse:** with a quorum member's answer waiting, Direct returns it without a new request, with `user-configured` or `unverified` trust.
- **Otherwise** it walks the endpoints the quorum didn't ask, one at a time, each at `configured`. Every error falls through to the next. The last error is thrown.
- **Gnosis without API keys** has no endpoint left after a failed quorum (N = k = 3). Today's `All RPC endpoints failed` stays (parity); whether that is intended is an [open question](#open-questions).

### Myotis

- **Its seven operations,** at `latest` only, with today's gates:
  - verdicts are required for state reads;
  - no state overrides or blob fields on calls;
  - estimates must be safe integers.
- **Outcomes:**

| Outcome | Error | Final? |
|---|---|---|
| a revert | `code 3` with its data | yes |
| an invalid-params refusal | `-32602` | yes |
| infeasible | geth's `-32000` | yes |
| a capability refusal | — | no: the next source |
| unavailable, or no verdict | — | no |
| an unexpected payload | a plain error | no; it becomes the last error |

- **Trust:** the block number is recorded only when it was the same before and after.

### Colibri

- **One operation per request:** `requestViaColibri` with the source's budget. Main keeps its client cache and its one rebuild-and-retry.
- **Any error falls through,** a verified revert included. Its data survives as the last error if later sources fail as unavailable.
- **Trust:** the prover's host, and `ZK sync-committee proof` or `Sync-committee proof`.

### Adaptive bypass

For myotis, colibri and quorum, and only on interactive reads:
- the route key is `[source, chain, origin, method, target]`;
- **timeouts** open the route for 15, 30 and then 60 s;
- **a capacity failure** blocks it for the core process's life;
- **a success** clears it, unless the route is blocked;
- **at most 1024 routes,** evicting the oldest.

The origin is browsing data: it stays in core memory, is never logged and dies with the process.

### Logs

`eth_getLogs` follows the router's three mechanisms, with every regex and constant ported with vectors.
- **The truncation check** (#496): a suspect answer is checked with the same filter, ending just before its oldest log, asked of the same source. Logs found there give today's `-32005` error.
- **Range learning,** in the Ant profile only:
  - per endpoint: caps, slow spans and cooldowns, with their 30 min and 30 s lifetimes;
  - up to two quorum rounds;
  - `query exceeds max block range <n>` when no quorum can serve the span.
  - **State** is kept for configured endpoints plus the 64 most recently retired (deviation `state-retention`). Today it is never pruned.
- **Blockscout pairing,** in the Ant profile, for xBZZ Transfer scans:
  - the RPC half, then Blockscout's pages back from the newest (50 a page, at most 40 pages, 8 MiB a page);
  - field-by-field agreement, then a quorum over the newest blocks;
  - today's cooldowns: the named rate limit clamped to 1–15 min, 5 min after a disagreement, 60 s after an abort, 30 min for a malformed pair.
  - **The Ant profile's error ranking and range-cap parsing** (`rankLogScanError`, `logScanRangeCap`) move into the core. The bridge keeps its localhost server, its reply rewriting and its receipt grace.

### Results and trust

- **Results:** `{ result, source, verified, trust? }`, where `verified` is true for myotis, colibri, quorum and blockscout. `trust` comes only on request.
- **Final failure**, in today's order:
  - the Ant profile's best-ranked error;
  - otherwise the last real error (not an unavailable source);
  - otherwise `All chain sources failed for <m> (<src>: <msg>; …)`, with today's `safeErrorMessage` shortening (hex runs over 128 digits, whitespace, 500 characters).

## Broadcast

The router's broadcast is the riskiest behavior it has:
- **Direct re-sends the same bytes** to every endpoint on any error, and reports the *last* error.
- **A lost reply looks like a failure.** An endpoint that accepted the transaction but answered too slowly, followed by `already known` or `nonce too low` from the next, is reported as a failure. The wallet then says "Transaction failed" while the transaction propagates, and a retry re-signs the intent with a newer nonce: the payment goes twice.

The core keeps the order and the re-sending, which are harmless because the bytes are identical. It replaces the outcome rule (deviation `broadcast-outcome`):

| Outcome | When | Reply |
|---|---|---|
| **sent** | any broadcaster returned the transaction's hash | `{ hash, source, outcome: "sent" }` |
| **uncertain** | no `sent`, and some attempt may have reached the network: a timeout or transport failure after the request went out, Myotis `uncertain`, a cancel after sending | `{ hash, source, outcome: "uncertain" }` |
| **rejected** | every attempt was definitely refused: a node error before any uncertain attempt, Myotis `rejected` | the error, as today |

- **The hash** is computed by the core from the raw transaction (keccak of the signed bytes). A broadcaster returning a different hash is not `sent`, which brings the wallet's mismatch check into the core.
- **Reconciliation:** before reporting `uncertain` or `rejected` after an uncertain attempt, the core asks once whether the hash is known (`eth_getTransactionByHash` through the read order, within the request's deadline). If it is known, the outcome is `sent` with `source: "reconcile"`. This replaces text matching on `already known`: the network, not a message, says whether the transaction exists.
- **Main's drivers:**
  - **The wallet** treats `uncertain` as sent-but-unconfirmed: it records the hash, tracks the receipt as for any send, and must not offer to re-sign the same intent. Its error text for it is a [follow-up](#open-questions).
  - **The Ant bridge** keeps its `Broadcast outcome uncertain; reconcile the signed transaction` reply.
- **Myotis:** `rejected` stays final, with no other broadcaster, and `uncertain` stays final. `not_sent` falls to the next broadcaster, as today.

## Fee quotes

`chain.fee_quote` follows `getFeeQuote` exactly. It walks the read order with no capabilities, exclusions, bypass or Myotis slots.
- **Myotis** answers both components in one operation.
- **Direct** asks one endpoint for both.
- **Other sources** make two requests.
- **The quote:**
  - legacy when there's no priority fee, or when it is negative or above the gas price;
  - otherwise EIP-1559, with `baseFee = gasPrice − priority` and `maxFee = 2·baseFee + priority`;
  - decimal strings, `verified` for myotis, colibri and quorum.

Vectors pin the downgrade boundaries. Whether a derived base fee and a "verified" Myotis fee are right is a product question, not a parity one.

## Errors and text

Naming's rule is that server text never reaches a reply (0004 *Secrets*). Chain data can't follow it: a node's `{ code, message, data }` (revert data, `nonce too low`) is what dApps and the wallet act on.
- **Node errors pass through** as an opaque payload, which the core:
  - caps (message ≤ 1 KiB, data ≤ 256 KiB);
  - may return to the caller of the request it came from;
  - never logs, caches or places in another request's reply.
- **The core's own diagnostics** use the core's text: unavailable sources, aggregates, parse failures. JSON parse failures get a fixed message (deviation `json-parse-text`), where V8's `SyntaxError` embeds a fragment of the body.
- **Aggregates** keep today's text: they name sources and include member messages shortened as today. They reach the caller exactly as now.
- **Logging:** the core logs request outcomes by chain, method and source only, never origins, addresses or messages.

## Transport

`shell.rpc` goes through the session's stack: deviation `transport`, as naming. Today the router uses Node's undici `fetch`, which ignores proxy and Tor settings and resolves `.onion` names through the system resolver.
- **Redirects** follow naming's rule (deviation `rpc-redirects`). Today undici follows up to 20 redirects unchecked, and turns a POST into a GET on 301 and 302.
- **429** is a failure, as today (`policy: "plain"`).
- **Answers** are capped at 16 MiB (deviation `response-caps`). Today there is no cap.
- **Status:** a non-2xx answer is `HTTP <status>`, its body unread, as today.

## Bounds

| Budget | Bound | Exhausted |
|---|---|---|
| running / waiting chain requests | 64 / 256 | `busy` |
| one request | 120 s | `deadline` |
| one answer | 16 MiB | `too_large`: a source failure |
| one message (fragments) | 24 MiB | protocol error (main and the core never send one) |
| quorum k / endpoints | 9 / 64 | clamped at configuration |
| memory, per request | 64 MiB: answer texts, digests' transient state, replies | the request ends with `budget` |
| memory, all chain requests | 256 MiB, with unwritten replies counted until written (0004's rule) | new requests `busy`, running ones `budget` |
| node error payload | message 1 KiB, data 256 KiB | cut / `too_large` |
| adaptive routes | 1024 | the oldest evicted |
| retired endpoint state | 64 | the oldest dropped |

## Deviations

| ID | Today | The core | Effect |
|---|---|---|---|
| `transport` | Node's undici, outside the session | the session's stack | `.onion` RPCs work under Tor; a missing route fails closed |
| `rpc-redirects` | ≤ 20 hops unchecked, POST→GET on 301/302 | each hop checked, method and body kept | a refused hop is a source failure |
| `rpc-id` | `id: Date.now()` | a per-request counter | none for nodes; vectors normalize ids |
| `response-caps` | none | 16 MiB per answer | `too_large`, a source failure |
| `overall-deadline` | none | 120 s | `deadline` |
| `admission` | unbounded | 64 running, 256 waiting | `busy` |
| `quorum-clamps` | `k ≥ 1`, `timeout ≥ 500`, unbounded above | also `k ≤ 9`, `timeout ≤ 60 s`, ≤ 64 endpoints | clamped |
| `order-validation` | duplicates run twice; unknown names fail late | dropped at configuration | |
| `config-snapshot` | registry re-read mid-request | one snapshot per request | a change applies to the next request |
| `abandoned-exchanges` | the caller's signal doesn't reach the quorum | a cancel cancels members | |
| `state-retention` | log-range and pair state never pruned | configured + 64 retired | |
| `json-parse-text` | V8's message with a body fragment | a fixed message | |
| `myotis-readiness` | `isReady()` sampled live | the last `chain.availability` | |
| `memory-budgets` | unbounded | per request and in total | `budget`, `busy` |
| `broadcast-outcome` | the last error wins; lost replies look like failures | `sent` / `uncertain` / `rejected`, with reconciliation | no reported failure for a transaction that may have gone out |
| `monotonic-time` | cooldowns on `Date.now()` | the monotonic clock | |

## Replay

The harness drives the pinned `chain-data-router.js`, with the real `blockscout-logs.js` and the Ant bridge's options, through scripted worlds:
- **World inputs:**
  - a registry snapshot per chain;
  - Myotis readiness and status sequences, and its outcomes per operation;
  - Colibri outcomes;
  - `fetch` exchanges with their delays, statuses and throws;
  - Blockscout pages and DNS answers;
  - fake timers;
  - callers' concurrency, origins, profiles and cancels.
- **Recorded:**
  - every exchange, with the URL, the body with its `id` normalized, its start, and its end or cancel;
  - every verifier operation;
  - each result or error with its key order, code, message and data;
  - the state tables after each step.
- **No randomness** to seed.
- **The existing suites** (`chain-data-router.test.js`, the Ant log-scan and Blockscout suites) define the first scenarios. Deviation vectors patch the reference in memory where a deviation has no natural trigger, as 0004's do.

## Implementation steps

1. **Codecs and vectors:**
   - normalization, `stableValue` over `jsjson` with the streaming canonical digest;
   - `feeQuote`, Myotis payload classification, `blockscout-logs`' mappers and filters;
   - the Ant profile's ranking and cap parsing;
   - byte parity from the pinned JS.
2. **The replay harness** (`vectors/chain-replay.json`).
3. **`fc-chain`:** the machine on `fc-naming`'s executor, replayed.
4. **`freedom-cored`:**
   - fragments in `fc-protocol`;
   - the `chain.*` methods on their own pool;
   - `shell.rpc`'s new parameters;
   - the new verified operations.
5. **freedom-browser:**
   - the executors;
   - the router, the fee quote and the broadcast become drivers;
   - the wallet's `uncertain` handling;
   - delete the JS router.

[0002](0002-signing.md)'s non-goal "nonces, fee estimation, gas limits, broadcasting and receipts stay in main" changes with step 5. Fee quotes, reads and broadcast routing move into the core; nonces and gas limits stay in main.

## Open questions

1. **Nonce floor.** Should the core keep a per-account floor, the highest nonce it broadcast plus one, so that concurrent sends and a retry after `uncertain` can't reuse or skip a nonce?
2. **Revert agreement.** Today reverts never agree in a quorum, so a dApp loses the revert data unless Myotis or Colibri gave it. Should identical error objects (code and data) count as agreement?
3. **Colibri's coverage.** Which methods does Colibri's `VerifiedOnly` client actually prove (`eth_gasPrice`, `eth_feeHistory`, `eth_blockNumber`, `pending` reads)? Today any Colibri success is labelled verified.
4. **Gnosis' Direct after a failed quorum** has nothing to ask without API keys. Intended?
5. **Myotis' head-of-line wait.** Methods Myotis doesn't serve take a slot before being refused. Checking the method first is a pure improvement, but observable in timing.
6. **The wallet's `uncertain` text and UI** (step 5): how to show "sent, unconfirmed" and block a re-sign of the same intent.
7. **Pinning and trust** (roadmap 3.1): whether a quorum of unpinned `latest` reads may be called `verified`.
