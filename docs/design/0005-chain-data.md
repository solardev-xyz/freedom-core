# 0005: Chain data in the core

**Status:** proposed. Builds on [0001](0001-freedom-cored.md) (process, framing, deadlines), [0002](0002-signing.md) (signing) and [0004](0004-naming-sessions.md) (sessions, `shell.*` requests, verified operations, endpoint references, budgets). It is roadmap item 3.4: freedom-browser's chain-data router moves into the core.

**The reference** is `src/main/networks/chain-data-router.js` at freedom-browser `fb540328`, with `blockscout-logs.js` and the Ant bridge's router options (`swarm/ant-chain-bridge.js`).
- **Ground truth** will be a replay harness, `vectors/chain-replay.json`, built like 0004's: it runs the pinned router through scripted worlds and records every exchange, verifier operation, timing, result and error. Its scenario IDs are cited below where a rule depends on them.
- **Conflicts:** where this document and a vector disagree, the vector wins and the document has a bug.

## Summary

A chain read, a fee quote or a broadcast becomes a **request** in `freedom-cored`, run by a sans-I/O machine in a new crate, `fc-chain`, on its own thread (the *chain thread*). It reuses 0004's session machinery:
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
- **No double payments from the wallet's own sends:** the wallet never signs one intent at two nonces, so no broadcast reply, receipt or provider can make it pay twice ([Retrying an intent](#retrying-an-intent) sets the scope).

**Non-goals**
- **Pinning chain reads to a block**, and new trust semantics. Today's router reads at the caller's tag and calls m equal answers `verified`. Changing either is roadmap 3.1's decision, not this design's.
- **Nonce management** stays in main. Main's wallet gains durable intent records and one rule: an intent keeps its nonce for good ([Retrying an intent](#retrying-an-intent)). The core keeps no nonce state.
- **Paths that bypass the router today:** provider-manager's Safe reads and `wallet:test-provider`. Absorbing them is a follow-up; `wallet:proxy-rpc` has no callers and should be deleted.
- **The verifiers' own networking** (roadmap 3.3), as in 0004.
- **Mobile drivers.**

## The protocol

### Methods main calls

All accept caller kinds `chrome` and `shell`.

| Method | Params | Result | Replaces |
|---|---|---|---|
| `chain.configure` | a [snapshot](#configuration) for every configured chain | `{ generations }` | the router's registry reads |
| `chain.availability` | `{ chain_id, ready }` for each Myotis chain | `{}` | the router's live `myotis.isReady()` samples |
| `chain.request` | `{ chain_id, method, params, include_trust, origin?, background, profile, deadline_ms }` | `{ result, source, verified, trust? }` | `request()` |
| `chain.fee_quote` | `{ chain_id, deadline_ms }` | today's quote shape | `getFeeQuote()` |
| `chain.broadcast` | `{ chain_id, raw, deadline_ms }` | `{ hash, source, outcome }` | `broadcastRawTransaction()` |

- **`params`** is the caller's JSON as main serializes it. The core parses it keeping JavaScript's property order, which [normalization](#normalization) depends on.
- **`origin`** is the router's routing context: the dApp's permission key or the `web3:` page's. It makes the read *interactive*. The core keeps it only in memory, for the [adaptive bypass](#adaptive-bypass), and never logs it.
- **`profile`** is `default` or `ant_scan`. Callers can't pass functions over the pipe, so the Ant bridge's options (`rankError`, `rangeCapOf`, the exclusions, Blockscout, the widened quorum budget) become one named profile, ported with vectors ([Logs](#logs)).
- **`background`** is the Ant bridge's flag: never queue for Myotis.
- **`deadline_ms`** is what is left of the caller's overall deadline when main sends the request, as naming's driver does; at most 120 s ([Deadlines](#deadlines)).
- **Cancellation** is 0001's `cancel`, which replaces the router's `AbortSignal` ([Cancellation](#cancellation)).
- **`isReadMethod`** stays in main: it is a constant table, mirrored with a vector.

### Requests the core makes

| Method | Params | Main does | Reply |
|---|---|---|---|
| `shell.rpc` | `{ endpoint, body, policy: "plain", max_bytes, generation, deadline_ms }` | one exchange through the session's stack | `{ status, body }`, `{ not_sent }` or a transport failure |
| `shell.verified` | a [verified operation](#verified-operations) | today's adapter, whole | the operation's outcome |
| `shell.blockscout` | `{ endpoint, query, max_bytes, generation, deadline_ms }` | one page through `blockscout-logs.js`'s redirect and address policy | `{ status, headers, body }` or a transport failure |

- **`shell.rpc`** is naming's executor, with two parameters added:
  - **`policy: "plain"`**: no 429 back-off and no repeated attempts, as today's router does; naming keeps ethers' loop.
  - **`max_bytes`**: the answer cap the core accepts, 18 MiB for chain data ([Transport](#transport)); naming stays at 720 KiB.
  - Redirects follow naming's rule: each hop is checked against the endpoint policy and the onion gate, and the method and body are kept (deviation `rpc-redirects`).
- **`not_sent`** is main's reply when it performed nothing: a stale generation, a cancel before the exchange started, or an endpoint refused before connecting. It proves that no byte of the request left main, which [broadcasts](#broadcast) rely on. Any other failure may have followed a send.
- **The body** is today's `JSON.stringify({ jsonrpc: '2.0', id, method, params })`, with `id` a per-request counter (deviation `rpc-id`).
- **`shell.blockscout`** keeps main's DNS check: an off-origin redirect must not resolve to a local address. That check needs DNS, which the core doesn't do.

### Frames

Chain-data answers routinely exceed 0001's 1 MiB frame: full-history `eth_getLogs` scans, blocks with their transactions, and `html()` documents of up to 8 MiB, which are 16 MiB as hex.

- **Only responses fragment.** Requests stay within one frame. A chain request over 1 MiB, such as an `eth_call` with more than about 500 KiB of call data, fails with `too_large` (deviation `request-size`). Request IDs so keep their write order, and a `cancel` always finds its request. Responses are matched to pending requests in whatever order they arrive.
- **Frame kinds:**
  - `0x12`, **begin**: a header `{ "id": <the request's ID>, "bytes": <the response's total size> }`;
  - `0x10`, a **fragment** of the response's bytes;
  - `0x11`, its **last** fragment;
  - `0x13`, **credit**, empty: the receiver returns the sender's right to begin another fragmented response.

  Kind `0x01` always carries one whole message. Kinds `0x02`–`0x0F` stay reserved for Phase 4's streams.
- **Bulk credit.** Each side holds one credit for the other direction, granted by the handshake.
  - A sender begins a fragmented response only while it holds the credit, and beginning spends it.
  - The receiver returns the credit with a `0x13` frame once the completed response has been handed to its consumer: the pending request's caller in main, the chain thread in the core.
  - A sender waiting for credit keeps sending whole messages, control messages first (0001's reserved capacity). The `0x13` frame is itself a control message.
- **Decoding:**
  - **A begin frame** must name a pending request (otherwise it is an unsolicited response) and a size within the message cap. The receiver reserves that many bytes outside its queued-frame credit. Fragments append; the last fragment completes the response, which must be exactly `bytes` long and is decoded as a `0x01` payload is.
  - **One response in reassembly per direction,** which the credit guarantees. Kind `0x01` frames between fragments are whole messages of their own, decoded at once. The reader never waits on a fragment, because room is already reserved for every byte the credit allows.
  - **Protocol errors** (0001: the receiver logs and closes): a begin while the sender holds no credit, an unknown ID, a size over the cap, an empty fragment, a fragment or last frame with no response in reassembly, and a length mismatch.
  - **EOF** in reassembly is EOF; the partial response is discarded.
  - **A `cancel`** for a request whose response has begun changes nothing: the response completes and the request ends with it, as 0001's races between cancels and responses already allow.
- **Sending:** a side fragments a response only when it exceeds 1 MiB, and only for a peer that offered fragments. Once begun, a response is written to its end; there is no abort.
- **The message cap** is 32 MiB of serialized message. The largest message is a `shell.rpc` reply carrying an 18 MiB answer as base64, about 24 MiB. A response over the cap is never begun: the sender replaces it with a `too_large` failure.
- **Consumers never block on the writer.** The chain thread takes every message as it arrives, whatever the writer's state.
  - When the chain thread's writer allowance is full, its replies wait in its own queue. They count in the chain memory total until written (0004's rule), and new requests are `busy` while that total is full.
  - So writer backpressure can't stop the core from reading, and credit always comes back.
- **The core's writer:** the chain thread has its own allowance of one message cap, apart from the vault loop's and naming's. A fragmented reply is charged at its whole size and released as its fragments are written.
- **Main's side** follows the same rules, and bounds what its executors hold with [its own pool](#mains-pool).
- **Negotiated** in the handshake. `core.hello`'s capabilities gain `fragments`, and main's hello params gain `frames: ["fragment"]`. A side sends fragments only to a peer that offered them. Main and the core ship together, so neither falls back.
- **Not streams.** Phase 4's streams (0001) remain separate: stream IDs, credit and protocol version 2. A fragmented response carries one whole message and is parsed only when complete.

### Main's pool

Main holds what its executors produce until it is written: bodies being read, verifier results, and serialized replies waiting for credit or for the writer. One **chain I/O pool** of 192 MiB bounds them:
- **Charges:** an exchange charges its body as it reads it, and its serialized reply from serialization until written; the body is released once serialized. A verifier operation charges its result the same way.
- **Exhausted:** an exchange ends with the transport failure `busy`. That is a source failure; for a broadcast it is an ambiguous attempt. A verifier reply becomes `{ failure: "busy" }`.
- **What is exempt** is defined by size, not by writer priority. 0001 counts every response as a control message for the writer's reserved capacity; that orders writing and exempts no storage.
  - **Charged:** every response of 64 KiB or more, fragmented or not, from serialization until it is written or dropped.
  - **Exempt:** replies under 64 KiB, which main's limit of 256 outstanding requests (0004) bounds at 16 MiB, and a closed set of control frames, each bounded on its own: `cancel` (one per outstanding request), the `0x13` credit (one per direction) and `core.shutdown`.
  - **A test** stalls the bulk credit until the pool is full, and still sees credit, cancels and small failure replies written.
- **Credit on discard:** a response that arrives for a cancelled or abandoned request is consumed and dropped, and its credit returns as for a delivered one.

### Verified operations

Myotis and Colibri keep running in main through today's adapters, one whole operation per request (0004's rule). The operations the router needs:

| Operation | Main runs | Reply |
|---|---|---|
| `{ myotis: "account", chain_id, address }` | `myotisManager.getAccount` | a [Myotis read outcome](#myotis-read-outcomes) |
| `{ myotis: "code", chain_id, address }` | `getCode` | likewise |
| `{ myotis: "storage", chain_id, address, slot }` | `getStorageAt` | likewise |
| `{ myotis: "call_tx", chain_id, tx }` | `ethCallTx` at `latest` | likewise |
| `{ myotis: "estimate_tx", chain_id, tx }` | `estimateGas` at `latest` | likewise |
| `{ myotis: "fee", chain_id }` | `feeEstimate` | likewise |
| `{ myotis: "broadcast", chain_id, raw }` | `sendRawTransaction` | `{ hash }`, `{ rejected: { reason } }`, `{ uncertain }`, `{ not_sent }` or `{ failure: class }` |
| `{ colibri: "request", chain_id, method, params, deadline_ms }` | `requestViaColibri` | `{ result }`, `{ revert: { data } }` or `{ failure: class }` |

#### Myotis read outcomes

- **`{ payload, block_before, block_after }`:** the adapter's JSON with 0004's snake_case keys, and `optimistic_block_number` before and after. The core runs `assertMyotisAnswer`'s classification on it: revert, refusal, infeasible, capability refusal, unavailable.
- **`{ failure: class }`:** chain data's own closed set of classes, which carry no text. Naming's set (0004) is unchanged. The classes:
  - `not_running` and `not_ready`: `runningInstance`'s two errors;
  - `state_changed`: `verifiedRequest`'s `MYOTIS_UNAVAILABLE`;
  - `queue_full`, `queue_deadline` and `caller_deadline`: myotis-process's rejections of a read:
    - `Myotis request queue is full`;
    - `Myotis queue deadline exceeded`: still queued at the read's 10 s deadline;
    - `Myotis caller deadline exceeded`: dispatched, and still running at that deadline;
  - `too_large` and `busy` ([Main's pool](#mains-pool));
  - `error`: any other throw.

  The core rebuilds the adapter's own errors with their fixed texts, using the chain's display name from configuration: `not_running`, `not_ready`, `state_changed`, `queue_full`, `queue_deadline` and `caller_deadline`. So they can become the last error as today. The last four carry the code `MYOTIS_UNAVAILABLE`, as today (`boundary-myotis-state-changed-last-error`, `boundary-myotis-queue-full-last-error`, `boundary-myotis-queue-deadline-last-error`, `boundary-myotis-caller-deadline-last-error`). Any other throw keeps neither its text nor its code (deviation `adapter-error-text`). That includes the child's other `MYOTIS_UNAVAILABLE` rejections: `Myotis is unavailable`, `Myotis request exceeds size limit`, `Myotis native operation failed`, `Myotis stopped` and `Myotis child exited`.

#### The rest

- **Broadcast classes** are exactly myotis-process's:
  - `not_sent`: queued and expired, or the client wasn't running;
  - `uncertain`: dispatched, then a deadline, an exit or a stop.
- **A broadcast's `{ failure: class }`:** main may also answer a broadcast with a class of the chain set, so that a failure that sent nothing keeps today's text:
  - `not_running`, `not_ready`, `queue_full` and `queue_deadline` count as **not sent**, and the core rebuilds their texts and codes as for a read, so the last error is today's (`boundary-broadcast-myotis-not-running-last-error`: `Gnosis Myotis client is not running`; `boundary-broadcast-myotis-not-sent-then-direct` falls to Direct);
  - every other class is **ambiguous**: the client may have dispatched the transaction.
- **Colibri's outcomes:**
  - **`{ revert: { data } }`:** the worker's error carried code 3 and hex `data`, a revert the prover verified. The core rebuilds it as `execution reverted`, with code 3 and that data.
  - **`{ failure: class }`:** everything else, from the chain set above, plus Colibri's own `capacity`. Its text isn't forwarded whether or not it had a code (deviation `adapter-error-text`): main can't tell a node's error from the SDK's own.
  - **`capacity`** is the one bit of that text the [adaptive bypass](#adaptive-bypass) needs. Main sets it where the router's `isCapacityFailure` pattern, `/out of gas|execution (?:gas|resource) limit|exceeds? (?:the )?(?:gas|execution) limit/i`, matches the adapter's error. As today, it blocks the app's Colibri route for the core process's life (`router-colibri-capacity-demotion`, `boundary-adaptive-capacity-survives-success`, `boundary-adaptive-route-target-case`).
- **Admission:** the router's slots stay as the core's admission rules, held until main's terminal reply. Myotis has 1 in flight and 16 waiting per chain, and background callers take only an idle slot. Colibri has 8 in flight, 2 per route.
- **Physical completion:** main replies only when the adapter's promise settles, never early. Main's per-verifier bound (0004: 8 operations) is shared by naming and chain data.
- **Reply size:** as 0004, main serializes each reply first; one over the message cap is `{ failure: "too_large" }`.

### Replies

- **A result** is `{ result, source, verified, trust? }`, keys in today's order.
  - **`result`** is embedded as **raw JSON**: the core writes the answer's validated `result` text into the reply as is, not as a JSON string. It is never escaped twice, and main's `JSON.parse` of the message yields the value, as today's `response.json()` did.
  - **`undefined`:** a body without `result` answers `undefined`, which JSON can't carry. The reply then omits `result` and lists it in `undefined_keys` (0004's mechanism). Main restores an own `result` property, first in key order, whose value is `undefined`.
  - **`source`** stays on every result, so `chain-data-activity`'s watchdog records still work.
  - **Size:** the core measures the whole serialized reply. One over the message cap fails the request with `too_large`.
- **Every result and error** of `chain.request` and `chain.fee_quote` carries `generation`: the chain's generation it was computed under ([Generations](#generations)).
- **Endpoint references** in `trust` (`agreed`, `dissented`, `queried`, `prover`) are substituted by main with the host, as 0004 does. One difference: the router's `endpointHost` gives `''` for a URL that doesn't parse, where naming keeps the input. Main follows the router here:
  - `''` is dropped from `agreed`, `dissented` and `queried`;
  - Colibri's `prover` keeps `''`;
  - the quorum's k still counts that URL (`boundary-unparseable-endpoint-host`, `boundary-colibri-trust`).
- **An error** is today's thrown error, rebuilt by main from a tagged payload ([Errors](#errors-and-text)).

### Generations

- **Each chain has a generation,** advanced by any `chain.configure` that changes that chain's snapshot. A request runs under the generation it started in, and its `shell.*` requests carry it.
- **A change ends the chain's running requests at once,** as 0004 ends a scope's sessions:
  - **Reads and fee quotes** end with `reconfigured`. Main's driver sends them again, once, under the new configuration and within the caller's remaining deadline. The caller sees no error unless the second attempt also ends `reconfigured`.
  - **Broadcasts** end as [Broadcast](#broadcast) says: `uncertain` if an attempt may have been sent, otherwise a definite `not_sent` failure. They are never re-sent automatically.
  - **Their I/O:** the core cancels the requests' outstanding `shell.rpc` and `shell.blockscout` requests and makes no new ones. Verifier operations keep their slots until main's terminal reply (parity), and their outcomes are dropped. No result built from the old configuration (an endpoint's answer, a prover's trust label) is published after the change.
- **Main** answers a `shell.*` request whose generation is no longer current with `not_sent` and performs nothing.
- **Replies already made aren't recalled:** a read can finish, and its reply be on its way, just before a change. Main's driver therefore fences replies as naming's does (freedom-browser #672):
  - it sends a chain request only while no chain control is in flight, checked with nothing between the check and the send;
  - it judges a reply only while none is in flight, re-checking after every wait, so the last check, the judgment and the result are one step;
  - a read's or fee quote's reply whose `generation` is older than the chain's current one was overtaken. Main sends it again, spending the same single resend as `reconfigured`, within the remaining deadline.
- **Broadcasts are neither fenced nor re-sent:** an outcome is a fact about the network, whatever configuration produced it.
- **`chain.availability`** doesn't end requests. It records the readiness the router samples. Myotis's own epoch check still turns a mid-operation change into `state_changed`.
- **Lifecycle:** none beyond that. The router has no Myotis epoch of its own and no restarts.

### Admission

- **A separate pool** from naming's: at most **64 running and 256 waiting** chain requests. A request over the limit is `busy` at once (deviation `admission`).
- **Memory:** a request is admitted only when what it brings fits: its own strings (method, params, origin, source lists, raw transaction) within its bound and, with everything already held, within the total. They stay charged while it waits and runs (deviation `memory-budgets`).
- **No deduplication:** every caller is its own request, as today.

### Deadlines

- **Per source**, as today:
  - `configured = max(500, quorum.timeout_ms || 5000)`;
  - an interactive read caps a source at 2 s when a later source exists;
  - the quorum's budget is a *verification* budget: when Direct comes next, its members run on to `configured`;
  - Direct gives every endpoint `configured`, walking them one at a time ([Direct](#direct) on the reference's widening);
  - the Ant profile widens the quorum budget to 30 s.
- **Overall:** 120 s per request, or the caller's `deadline_ms` if lower (deviation `overall-deadline`).
  - **Today** a request has no overall bound: an interactive read on chain 1 can take about 39 s, and more with user settings.
  - **Past the deadline,** a read or a fee quote ends with `deadline`, its I/O is cancelled, and nothing more is asked. A call that arrives with no time left (`deadline_ms` 0) replies `deadline` before any I/O, under its chain's current generation.
  - **A broadcast** ends as [Broadcast](#broadcast) says. Its attempts stop 10 s before the deadline, leaving room to [reconcile](#broadcast).
- **Main's watchdog** is the deadline plus 15 s (0001).

### Cancellation

- **A `cancel`** ends the request at once, unless its response has already begun ([Frames](#frames)): a read or a fee quote replies `cancelled` (deviation `cancel-promptly`). Its pending `shell.rpc` and `shell.blockscout` requests are cancelled, quorum members included (deviation `abandoned-exchanges`: today's caller signal doesn't reach the quorum).
  - **Today** the router throws its `AbortError` only at its next check of the signal, so a read waiting on a verifier settles only when that operation does: `cancel-read-no-fallthrough` is aborted at 10 ms and throws at 20 ms, when Myotis's read settles. The core replies at 10 ms.
- **Verifier work** keeps its slot until main's terminal reply (parity: the router holds Myotis and Colibri slots until the operation physically settles). In `cancel-read-no-fallthrough` the Myotis slot is still held when the core replies. A terminal reply too large for its request's budget still frees the slot: its payload is dropped, and the request ends with `budget`.
- **A broadcast** that is cancelled ends as [Broadcast](#broadcast) says. Today it is an `AbortError`.

## Configuration

`chain.configure` replaces every chain's snapshot:

```jsonc
{ "chains": [ {
    "chain_id": 1,
    "display_name": "Ethereum",                                  // Myotis's error texts
    "read_order": ["myotis", "colibri", "quorum", "direct"],
    "broadcast_order": ["myotis", "direct"],
    "quorum": { "k": 3, "m": 2, "timeout_ms": 5000 },   // raw, as the registry merges it
    "rpc": [ { "endpoint": "e3", "user_configured": true }, … ],   // registry order, ≤ 64
    "prover": { "endpoint": "p1", "zk": true },                  // or null
    "myotis": true,                                              // Myotis serves this chain
    "blockscout": { "endpoint": "b1" } } ] }                     // the Ant profile's index, or null
```

- **Main computes the inputs as today:** `access.readOrder`/`broadcastOrder` or the defaults, `getEndpoints(chainId, 'rpc')` in registry order, and the first prover.
- **The core applies today's defaults and clamps** (`boundary-quorum-clamps`):
  - a missing value, `0` or a non-number takes the default: k 3, m 2, timeout 5000 ms;
  - numeric strings count as their numbers;
  - then `k ≥ 1`, `1 ≤ m ≤ k`, `timeout ≥ 500 ms`.

  It also adds bounds (deviation `quorum-clamps`): `k ≤ 9`, `timeout ≤ 60 s`, and at most 64 endpoints, as 0004.
- **Orders are cleaned at configuration** (deviation `order-validation`): duplicates are dropped and unknown sources removed. Today a duplicate runs twice and an unknown name fails at run time.
- **When main sends it:** at startup and from `network-ipc`'s `refreshDownstream`, where today only ENS and provider-manager caches are cleared. Controls queue ahead of later requests, as naming's do.

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

- **Order:** the read order, with opt-in sources inserted before `quorum`, minus the request's exclusions and the sources that don't serve the method. An empty order fails with today's `No chain source left …` text, naming the exclusions. With nothing excluded, that text ends in `null`, as today.

### Normalization

`eth_call` and `eth_estimateGas` call objects are normalized as today (`normalizeParams`). The core reproduces JavaScript's `BigInt(string | number)` byte for byte, quirks included, with vectors for each:
- whitespace around a decimal is allowed;
- `0b` and `0o` prefixes parse;
- a negative value gives `0x-1`;
- `0X10` is accepted;
- zero-padded hex is canonicalized;
- an unparseable value is left for the node to refuse.

The `input` alias, field positions and the appended `data` key follow JavaScript's property order.

### Answers

The router keeps parsed values; the core keeps **text**.
- **Decoding:** an answer's body is decoded as UTF-8 with replacement, its BOM stripped, and validated as JSON, as `response.json()` does.
- **Depth:** the core's parser refuses nesting deeper than 512 levels, where V8 has no fixed limit. A deeper answer is a source failure (deviation `json-depth`).
- **Its `result`** is the last `result` member's text, since `JSON.parse` keeps the last of duplicate keys. A body without `result` answers `undefined`, as today. A JSON `null` body fails as today's `TypeError` does, with a fixed message.
- **Agreement** is equality of the router's `stableValue` string, which the core reproduces and compares by its **SHA-256 digest**:
  - arrays in order;
  - an object's own keys sorted by UTF-16 code units (`Object.keys(…).sort()`), the last of duplicate keys kept, `__proto__` an ordinary key;
  - strings, numbers and `null` as `JSON.stringify` writes the parsed value: numbers as doubles in JavaScript's shortest form (`1e2` → `100`, `-0` → `0`), lone surrogates escaped;
  - `undefined` (a missing `result`) as a tag that no JSON text produces.

  **The method:** the core indexes the answer's spans within the request's budget, then hashes in canonical order. It is not a single pass. Independent equivalence vectors pin it: pairs that must agree and pairs that must not.
- **What it retains,** for a quorum ([Quorum](#quorum)):
  - the text of each group's first-arrived answer, while that group can still reach m;
  - the text of the lowest-index member that answered, for Direct.

  Each text is retained once, even when it serves both purposes.

### Quorum

- **Members:** the first k endpoints in registry order. Fewer than m endpoints is today's `RPC quorum needs <m> endpoints`. All members start at once.
- **Agreement:** the first group to reach m wins. Every other member is cancelled, and the group's first-arrived answer is returned with today's trust.
- **Errors are never grouped**, as today: a revert is a member failure. Grouping identical errors is an [open question](#open-questions).
- **Impossibility, the verification timer and the hand-off to Direct** follow the router exactly:
  - it waits for a still-running member when Direct comes next and nothing has answered;
  - **its `directFallback`** is the lowest-index member that answered, not the first to arrive (`chain-data-router.js:1286`). Its agreeing and dissenting hosts are judged against that member's answer.
  - `directUnansweredUrls` is the members that never answered;
  - **the failure kind** comes only from the members' own errors (`capacity`, `timeout`). A round that ends on its own budget has no kind (`boundary-adaptive-quorum-deadline-not-a-timeout`).
- **A vector** pins the difference. k = m = 3: endpoint 1 answers `{"b":1,"a":2}` first, endpoint 0 answers `{"a":2,"b":1}` later, endpoint 2 fails. Direct returns endpoint 0's text, with key order `a, b`.

### Direct

- **Reuse:** with a quorum's `directFallback` waiting, Direct returns its text without a new request, with `user-configured` or `unverified` trust.
- **Otherwise** it walks the endpoints the quorum didn't ask, one at a time, each at `configured`. Every error falls through to the next. The last error is thrown.
- **Widening:** the reference also takes a `directTimeoutMs` router option that widens each endpoint's budget, and with it retries the members the quorum cut off, after the endpoints it never asked (`cancel-direct-timeout-widened-never-narrowed`; `cancel-range-limit-not-kept-without-rank`: `d`, then `a` again for 60 s). No shipped caller passes it, so the `default` and `ant_scan` profiles keep "each at `configured`". The machine reproduces the option for the replay, but `chain.request` doesn't expose it: a request names only its profile.
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
| `not_running`, `not_ready`, `state_changed` (the adapter's own errors) | their fixed texts | no; it can become the last error, as today |
| an unexpected payload, or `failure: "error"` | a plain error with a fixed text | no; it becomes the last error |

- **Trust:** the block is recorded when the values before and after are strictly equal as JavaScript compares them (`===`), whatever their type. So `"5"`/`"5"` and `false`/`false` count, and so do 2^53+1 and 2^53. The vectors pin it.

### Colibri

- **One operation per request:** `requestViaColibri` with the source's budget. Main keeps its client cache and its one rebuild-and-retry.
- **Any error falls through,** a verified revert included. A `revert` survives as the last error, with its data, if later sources fail as unavailable; a `failure` survives as a fixed text.
- **Trust:** the prover's host, and `ZK sync-committee proof` or `Sync-committee proof`.

### Adaptive bypass

For myotis, colibri and quorum, and only on interactive reads:
- the route key is `[source, chain, origin, method, target]`. A target that lists more than one address is kept as `sha256:` and the SHA-256 of the reference's joined text, in hex: the same routes share a key, and a key is bounded in bytes however long the list (deviation `memory-budgets`; the origin is at most 2,048 UTF-16 units, so 1,024 routes hold at most about 7 MiB);
- **a failure of kind `timeout`** opens the route for 15, 30 and then 60 s (`router-colibri-cooldown-escalation`). A quorum has that kind only when its members time out themselves, which they do when Direct comes next and they run on (`router-quorum-carries-past-deadline`). A quorum cut at its own 2 s budget opens nothing, and is asked again on the next read (`boundary-adaptive-quorum-deadline-not-a-timeout`);
- **a capacity failure** blocks it for the core process's life: an error whose text matches `isCapacityFailure`, a quorum whose members' capacity failures reach m, or Colibri's `capacity` class ([The rest](#the-rest));
- **a success** clears it, unless the route is blocked;
- **at most 1024 routes,** evicting the oldest.

The origin is browsing data: it stays in core memory, is never logged and dies with the process.

### Logs

`eth_getLogs` follows the router's three mechanisms, with every regex and constant ported with vectors.
- **The truncation check** (#496): a suspect answer is checked once, with the same filter ending just before its oldest log, asked of the same source.
  - **Logs found** give today's `-32005` error (`TruncatedLogsError`). It ends the request at once: no later source is tried, and later errors can't replace it.
  - **An empty probe, or a failed one,** accepts the original answer.
  - **No learning:** a quorum's probe runs with `learn: false`, so its failures don't cool or cap endpoints.
  - **Vectors** cover a failed probe, the unlearned quorum probe, and a truncation while Direct is still available.
- **Range learning,** in the Ant profile only:
  - per endpoint: caps, slow spans and cooldowns, with their 30 min and 30 s lifetimes;
  - up to two quorum rounds;
  - `query exceeds max block range <n>` when no quorum can serve the span.
  - **State** is kept for configured endpoints plus the 64 most recently retired (deviation `state-retention`). Today it is never pruned.
- **Blockscout pairing,** in the Ant profile, for xBZZ Transfer scans:
  - the RPC half, then Blockscout's pages back from the newest (50 a page, at most 40 pages). The reference caps a page at 8 Mi UTF-16 units, which can be more than 8 MiB of bytes; the core caps it at 8 MiB of bytes (deviation `blockscout-page-bytes`);
  - field-by-field agreement, then a quorum over the newest blocks;
  - **texts that name the pair:** the reference's `<host> answered the span with a malformed log entry` and `Blockscout (<n> logs) and <host> (<m> logs) disagree` embed an endpoint's host, which the core doesn't know. The core says `the paired endpoint` in its place (deviation `paired-endpoint-text`; the paths of `ant-index-malformed-pair-entry-*` and `ant-index-blockscout-missing-old-log-falls-back`). Both texts stay inside the source's failure, and no vector shows them in a final error;
  - **`shell.blockscout`'s failures** carry no reason: a redirect hop main refuses (off https, a local host, no or a malformed location, too many hops, a name that doesn't resolve) is one `refused`, whose text is `redirected to a refused location`, where the reference names the reason (deviation `adapter-error-text`; `blockscout-redirect-off-https`, `blockscout-redirect-without-location`, `blockscout-redirect-loop`, `blockscout-redirect-local-host-*`, `blockscout-redirect-dns-local`, `blockscout-redirect-dns-fails`). Its cooldown is today's 60 s, and no vector shows the text in a final error;
  - **today's cooldowns:**
    - a 429 that names its reset: that time, clamped to 1–15 min;
    - 5 min for a 429 naming no reset, a throttle in the body, or a disagreement;
    - 30 min for a malformed pair;
    - 60 s after an abort, and after every other failure: an HTTP status, non-JSON, a refusal, a page check, a redirect or DNS refusal, a transport failure, a timeout.

    Scenarios: `blockscout-429-cooldown-bounds`, `blockscout-throttle-in-body`, `blockscout-http-500`, `ant-index-*`.
  - **The Ant profile's error ranking and range-cap parsing** (`rankLogScanError`, `logScanRangeCap`) move into the core. They read errors as received, before any reply is built. The bridge keeps its localhost server, its reply rewriting and its receipt grace.

### Results and trust

- **Results:** `{ result, source, verified, trust? }`, where `verified` is true for myotis, colibri, quorum and blockscout. `trust` comes only on request.
- **Final failure**, in today's order:
  - a truncation, at once ([Logs](#logs));
  - the Ant profile's best-ranked error;
  - otherwise the last real error (not an unavailable source);
  - otherwise `All chain sources failed for <m> (<src>: <msg>; …)`, with today's `safeErrorMessage` shortening (hex runs over 128 digits, whitespace, 500 characters).

## Broadcast

The router's broadcast is the riskiest behavior it has:
- **Direct re-sends the same bytes** to every endpoint on any error, and reports the *last* error.
- **A lost reply looks like a failure.** Say an endpoint accepts the transaction but answers too slowly, and the next one answers `already known` or `nonce too low`. That is reported as a failure. The wallet then says "Transaction failed" while the transaction propagates, and a retry re-signs the intent with a newer nonce: the payment goes twice.

Two facts make this fixable:
- **Re-sending the same signed bytes** is always safe, because they can be mined only once.
- **At most one transaction per nonce** can be mined. Signing an intent again at the *same* nonce therefore can't pay twice either; only a *new* nonce can.

So the design has two parts:
- **The core** classifies each broadcast as honestly as the network allows (deviation `broadcast-outcome`).
- **Main's wallet** never moves an intent to a new nonce because of an outcome ([Retrying an intent](#retrying-an-intent)).

Safety rests on the second part. No outcome authorizes a new nonce, however it was reached, so a classification can be wrong without a payment going twice. The core keeps today's order and re-sending.

### Attempts

Every attempt (a Direct endpoint's `eth_sendRawTransaction`, Myotis's `broadcast`) gets one class:

| Class | When |
|---|---|
| **accepted** | a success whose result is the transaction's hash; Myotis `{ hash }` likewise |
| **refused** | a node error matching a [refusal predicate](#refusals), or Myotis `{ rejected }` |
| **not sent** | main's `not_sent`; Myotis `{ not_sent }`, or its `{ failure }` with `not_running`, `not_ready`, `queue_full` or `queue_deadline`; an attempt the core never sent to main |
| **ambiguous** | everything else: other node errors (`already known` and unrecognized ones), a success with a different, missing or malformed hash, a non-2xx status, a transport failure, a timeout, a cancel or a deadline after the request reached main, Myotis `{ uncertain }` or any other `{ failure }` class |

- **The hash** is computed by the core: keccak-256 of the signed bytes. Hashes compare as 32-byte values, any hex case.
- **An attempt is possibly sent** from the moment the core sends its request to main until main's reply proves otherwise (`not_sent`).

### Refusals

A node's error proves only that *these* bytes weren't admitted by *that* node *now*.
- **Earlier sends can fake a refusal.** Bytes may have been sent before: by an earlier broadcast, or by another wallet holding the same key. A state-dependent refusal (`insufficient funds`, `nonce too low`) can then be caused by that very success. The core can't know every earlier send, so `rejected` means "every node this broadcast reached refused it", not "the transaction is nowhere". The wallet's rule makes that enough.
- **The predicates** are exact. A refusal is a JSON-RPC error whose code is `-32000` (or the client's documented code for it) and whose message starts with one of a fixed list of txpool rejections:
  - insufficient funds;
  - nonce too low;
  - replacement transaction underpriced, and transaction underpriced;
  - intrinsic gas too low, and exceeds block gas limit;
  - max fee per gas less than block base fee, and max priority fee per gas higher than max fee per gas;
  - invalid sender, and invalid chain id;
  - oversized data, and transaction type not supported.

  The vectors (`broadcast_refusals` in `vectors/chain.json`) are the list:
  - **Wordings:** each client's (geth, Nethermind, Erigon, reth, Besu and the large providers), with its source cited.
  - **Codes:** the codes each client documents for each wording.
  - **Matching:** case-sensitive, on `String(error.message)`.

  `already known` is never a refusal, in any client's wording, because it says the bytes exist. Anything unmatched is ambiguous, geth's minimum-tip refusal (`transaction gas price below minimum`) among them. Under the wallet's rule a classification decides only what is shown ([Retrying an intent](#retrying-an-intent)).
- **Myotis `rejected`** counts as a refusal; its reasons include a used nonce.
- **Order doesn't matter.** A refusal after an attempt that may have been sent (an ambiguous one) stops the attempt loop, as Myotis's final verdict does today, but it can't erase that attempt: the outcome table looks at every attempt (`boundary-broadcast-refusal-after-ambiguous`).
- **A refusal with nothing possibly sent** doesn't stop the loop: re-sending continues as today, since another node may admit the bytes (`boundary-broadcast-resends-until-accepted`: `nonce too low` from a, `insufficient funds` from b, accepted by c).

### Outcome

| Outcome | When | Reply |
|---|---|---|
| **sent** | some attempt was accepted, or reconciliation found the transaction | `{ hash, source, outcome: "sent" }`; `source` is `"reconcile"` after a lookup |
| **rejected** | no attempt accepted or ambiguous, and at least one refused | the last refusal, as today's error, tagged `outcome: "rejected"` |
| **not sent** | every attempt not sent, or none made | a failure tagged `outcome: "not_sent"`, with today's text, or `deadline` / `cancelled` / `reconfigured` |
| **uncertain** | otherwise | `{ hash, source, outcome: "uncertain" }` |

- **Every terminal path** goes through this table: the overall deadline, a `cancel`, a configuration change, a budget exhaustion and core shutdown. An outstanding attempt counts as ambiguous once it is possibly sent, so the outcome is then `uncertain`, never `deadline` or `cancelled`.
- **Only `rejected` and `not sent` are failures.** Neither moves the intent to a new nonce; nothing does ([Retrying an intent](#retrying-an-intent)).
- **Reconciliation:** before reporting `uncertain`, the core asks once whether the network knows the hash, within the reconciliation room ([Deadlines](#deadlines)).
  - **The lookup** is `eth_getTransactionByHash(hash)`, run as a non-interactive read through the read order.
  - **A match** is a result object whose `hash` equals the transaction's. A match makes the outcome `sent`.
  - **Anything else** leaves the outcome `uncertain`: `null`, an error, a mismatched or malformed object, or no time left. A lookup never produces `rejected`.
- **Myotis:** `rejected` and `uncertain` end the attempt loop, as today, and `not_sent` falls to the next broadcaster. What the loop ended with is then classified like any other attempt.

### Retrying an intent

Main's wallet chooses nonces for the sends it controls (0002). The guarantee covers what the wallet does on its own and what it offers as a retry. A payment the user starts afresh is a new intent, and theirs to decide.

- **Scope.** The rule covers drivers that choose the nonce and see every attempt's bytes: keys the core signs with, and Ledger devices (main picks the nonce, and the device signs it).
  - **Phone wallets** (the remote signer) sign and broadcast themselves, so main has neither the nonce nor the bytes. Their path stays as today, except that a lost response is shown as unknown, never as failed, and is never retried automatically.
  - **The Ant bridge** returns outcomes to the Ant node, which chooses its own nonces. The bridge keeps its replies: `rejected` as today's error, and `uncertain` as its reconcile reply.
- **One nonce per intent, for good.** An intent signed at nonce N stays at N for its whole life. The wallet never signs an existing intent at another nonce, on its own or as an offered retry.
  - After `rejected`, `not sent` or `uncertain`, it may broadcast the same bytes again, or sign the intent again at N: a replacement, with a higher fee if the network asks.
  - At most one transaction with nonce N can be mined, so nothing the wallet does can pay one intent twice, whatever an outcome, a receipt or a provider said.
- **Labels, not permissions.** The wallet shows each intent's state, read at the chain's **finalized** block (both Ethereum and Gnosis expose one). These labels authorize nothing:
  - **Paid:** one of the intent's own transactions is included at or below the finalized block, with status 1.
  - **Failed:** one is included there with status 0. It consumed N and executed nothing.
  - **Taken:** the finalized nonce, `eth_getTransactionCount(sender, "finalized")`, has passed N, and none of the intent's own transactions is included. Some other transaction used N, possibly a payment of this very intent signed elsewhere, so the payment may or may not have happened.
  - **Held:** anything else. A chain without a finalized block keeps its intents held.
- **Failed and taken go back to the user.** The wallet explains what it knows and offers no retry. A new payment is the user's own act from the send screen: a new intent, with its own nonce and its own confirmation.
- **Inclusion** means that a receipt's block number is at or below the finalized block's, and that its block hash is the canonical hash at that height.
- **Evidence for labels** comes from a verified source: Myotis, Colibri, or a quorum of at least two agreeing endpoints. A quorum with m = 1 counts as Direct. Without such a source, an intent stays held. Since labels authorize nothing, a dishonest provider can mislead the display, but it can't make the wallet pay twice.
- **Records.** Each intent has a durable record in main, separate from the display history, which can be cleared: `{ intent_id, chain_id, sender, nonce, hashes }`. Every hash in it was signed at that one nonce.
  - **Committed first:** the record, with each new hash, is committed (written atomically, with fsync) before those bytes are handed to a broadcaster.
  - **Kept** until the intent is paid, failed or taken at finality, and never removed by clearing the history.
  - **Identity:** `intent_id` is created when the user confirms a send, and retries carry it.
  - **After a restore,** a profile without records has nothing to retry. A request that arrives again (the same dApp call) is a new intent, for the user to confirm.
- **Reservations.** Nonces are reserved per `(chain_id, sender)` under one lock in main, from reading the `pending` count to committing the record. That includes a pending device approval, so two callers can't take the same nonce.
  - **The first free nonce:** a new intent takes the `pending` count, as today, but at least one above every nonce a held intent of that account has.
  - **Release:** a reservation whose signature never happened (the user rejected it on the device) is released, since no bytes exist.

### Main's record

The core can die mid-broadcast: an exit, the watchdog, a protocol error. Main therefore keeps its own record of every `chain.broadcast` in flight: the hash, and whether any attempt is possibly sent.
- **Marking:** main's executors mark the record when they start an exchange whose body is an `eth_sendRawTransaction` of that raw transaction, or a Myotis `broadcast` of it.
- **No reply from the core:** main reports `uncertain` if the record is marked, and `not sent` otherwise. Main never reports `rejected` on its own. Under the wallet's rule, neither can lead to a second payment.
- **The wallet** treats `uncertain` as sent-but-unconfirmed. It records the hash and tracks the receipt as for any send, and offers only what the rule allows. Its text and UI are a [follow-up](#open-questions).

## Fee quotes

`chain.fee_quote` follows `getFeeQuote` exactly. It walks the read order with no capabilities, exclusions, bypass or Myotis slots.
- **Myotis** answers both components in one operation.
- **Direct** asks one endpoint for both.
- **Other sources** make two requests.
- **The quote:**
  - legacy when there's no priority fee, or when it is negative or above the gas price;
  - a priority fee `BigInt` can't parse (such as `-0x1`) doesn't downgrade: it fails that source's quote, and Direct moves on to its next endpoint (`boundary-fee-direct-priority-unparseable`);
  - otherwise EIP-1559, with `baseFee = gasPrice − priority` and `maxFee = 2·baseFee + priority`;
  - decimal strings, `verified` for myotis, colibri and quorum.

Vectors pin the downgrade boundaries. Whether a derived base fee and a "verified" Myotis fee are right is a product question, not a parity one.

## Errors and text

Naming's rule is that server text never reaches a reply (0004 *Secrets*). Chain data can't follow it: a node's `{ code, message, data }`, such as revert data or `nonce too low`, is what dApps and the wallet act on. So errors carry their origin.
- **The wire form:** a `chain.*` request fails with 0001's fixed error code `chain_error`, whose `data` is tagged:

| `data.kind` | Carries | Comes from |
|---|---|---|
| `node` | `code`, `message`, and `data` if the node's error had it | a JSON-RPC error object the core itself parsed out of an answer body (`shell.rpc`) |
| `core` | `message`, and `code` and `data` where today's error has them | the core's own errors, with today's texts: aggregates, truncation (`-32005`), Myotis's and Colibri's reverts and refusals, Myotis's unavailable texts, `Unsupported read method`, parse failures |

  Broadcast failures add `outcome`. 0001's own codes stay for what they mean: `deadline`, `cancelled`, `busy`, `budget`, `too_large`, plus `reconfigured`.
- **Main rebuilds** the error as today's router throws it: an `Error` with that message, with `code` and `data` set only if present, and with the router's extra fields (`directFallback` stays internal to the core).
- **Node errors pass through** unchanged. The core may return one to the caller of the request it came from, and never logs, caches or places it in another request's reply. Their size is bounded by the answer cap, and the reply by the message cap. There is no separate cap, so revert data is never cut.
- **Provenance is structural.** `node` errors come only from bodies the core parsed itself. Verifiers never supply text: the core classifies Myotis's payloads, and Colibri answers with a result, a revert's data or a failure class. Text that main, an SDK or the network stack produced never passes through; it gets the core's fixed text (deviation `adapter-error-text`).
- **Classification** runs on errors as received, before any reply is built: Myotis's verdicts, the Ant profile's ranking, the truncation check and the broadcast classes.
- **The core's own texts** reproduce today's. JSON parse failures get a fixed message (deviation `json-parse-text`), where V8's `SyntaxError` embeds a fragment of the body.
- **Logging:** the core logs request outcomes by chain, method and source only, never origins, addresses or messages.

## Transport

`shell.rpc` goes through the session's stack: deviation `transport`, as naming. Today the router uses Node's undici `fetch`, which ignores proxy and Tor settings and resolves `.onion` names through the system resolver.
- **Redirects** follow naming's rule (deviation `rpc-redirects`). Today undici follows up to 20 redirects unchecked, and turns a POST into a GET on 301 and 302.
- **429** is a failure, as today (`policy: "plain"`).
- **Answers** are capped at 18 MiB (deviation `response-caps`; today there is no cap). The largest answer the reference must accept is an `html()` document at its 8 MiB limit:
  - ABI-encoded and hex, it is 16,777,346 characters;
  - its minimal JSON-RPC answer is 16,777,382 bytes;
  - the cap leaves about 2 MiB for envelopes and whitespace.

  A boundary vector pins it. Larger `eth_getLogs` scans fail with `too_large` from that source; providers' own limits usually apply first. Main enforces the cap; an answer delivered over it anyway is the same `too_large` failure.
- **Status:** a non-2xx answer is `HTTP <status>`, its body unread, as today.

## Bounds

| Budget | Bound | Exhausted |
|---|---|---|
| running / waiting chain requests | 64 / 256 | `busy` |
| one request | 120 s, or the caller's `deadline_ms` | `deadline` (broadcasts: [Outcome](#outcome)) |
| one answer | 18 MiB | `too_large`: a source failure |
| one message | 32 MiB, serialized | the request fails with `too_large`; a received one is a protocol error |
| fragmented responses in flight | one per direction (bulk credit); its bytes reserved at begin, outside the reader's 16 MiB | the sender waits for credit, sending whole messages meanwhile |
| one request message | one frame (1 MiB) | `too_large` |
| the chain writer | one message cap of unwritten bytes | replies wait in the chain thread's queue, counted in the total |
| main's chain I/O pool | 192 MiB: bodies being read, verifier results, replies until written; replies under 64 KiB exempt | the exchange fails `busy` |
| quorum k / endpoints | 9 / 64 | clamped at configuration |
| JSON depth | 512 | a source failure |
| memory, per request | 96 MiB: its call's strings, received messages once handed over, answer texts and their indexes, retained texts and errors, the copies it makes, its requests until the driver takes them, replies | the request ends with `budget` (broadcasts: [Outcome](#outcome)) |
| memory, all chain requests | 256 MiB, with unwritten replies counted until written (0004's rule) | new requests `busy`, running ones `budget` |
| adaptive routes | 1024 | the oldest evicted |
| retired endpoint state | 64 | the oldest dropped |

**Memory is reserved before it is allocated.** Each allocation a request makes is charged first, at an upper bound, and settled to what it holds once made: a request body; a replacement-decoded text's growth over its body (whose charge goes with the body); every index, sized by a counting pass before it is built; a writer's scratch; normalized params, their index and copies (a standing reservation held for the request's life); a node error's or a verifier error's copies, held while any copy lives; Blockscout's pages, their indexes and the transfers they add; joined and agreed results; the reply's copy of a result. A reservation the budget refuses stops the request before the allocation, and it ends with `budget`; a broadcast ends through the [outcome table](#outcome), so an attempt that was outstanding stays possibly sent. A request over its budget is never polled again. Once the driver takes a request or a reply, its bytes leave the request's charge and count in the driver's backlog, which main reports, until written.

**At the cap**, an 8 MiB document through a quorum of three peaks at about 78 MiB in its request:
- one base64 message in hand: 24 MiB;
- its decoded answer and index: about 22 MiB;
- two retained texts: 32 MiB.

## Deviations

| ID | Today | The core | Effect |
|---|---|---|---|
| `transport` | Node's undici, outside the session | the session's stack | `.onion` RPCs work under Tor; a missing route fails closed |
| `rpc-redirects` | ≤ 20 hops unchecked, POST→GET on 301/302 | each hop checked, method and body kept | a refused hop is a source failure |
| `rpc-id` | `id: Date.now()` | a per-request counter | none for nodes; vectors normalize ids |
| `response-caps` | none | 18 MiB per answer | `too_large`, a source failure |
| `request-size` | unbounded | one frame (1 MiB) per chain request | `too_large` |
| `json-depth` | V8's parser, no fixed depth | 512 levels, in answers, Myotis payloads and Blockscout pages | a source failure; a deeper Blockscout page is `answer is not JSON` |
| `bigint-width` | `BigInt` of any decimal width, in time quadratic in its length | decimal input, gas prices and Myotis numbers (balances, nonces, fees, estimates) wider than 4096 bits are refused: such a call-object quantity is left as sent, such a gas price fails its source, and such a Myotis number is a plain error; fees computed from an accepted gas price can print one bit wider | no minutes-long conversions on the chain thread; hex, octal and binary stay exact |
| `blockscout-page-bytes` | a page capped at 8 Mi UTF-16 units | 8 MiB of bytes | a page with many multi-byte characters may fail as too large |
| `overall-deadline` | none | 120 s | `deadline` |
| `admission` | unbounded | 64 running, 256 waiting | `busy` |
| `quorum-clamps` | `k ≥ 1`, `timeout ≥ 500`, unbounded above | also `k ≤ 9`, `timeout ≤ 60 s`, ≤ 64 endpoints | clamped |
| `order-validation` | duplicates run twice; unknown names fail late | dropped at configuration | |
| `config-change` | the registry re-read mid-request; a change applies piecemeal | a change ends the chain's requests; main sends reads and fee quotes again once | callers see the new configuration whole |
| `abandoned-exchanges` | the caller's signal doesn't reach the quorum | a cancel cancels members | |
| `cancel-promptly` | the `AbortError` is thrown at the router's next check, so a read waiting on a verifier settles when that operation does | `cancelled` at once; the verifier's slot is held until main's reply | `cancel-read-no-fallthrough` replies at 10 ms, not 20 |
| `state-retention` | log-range and pair state never pruned | configured + 64 retired | |
| `json-parse-text` | V8's message with a body fragment | a fixed message | |
| `adapter-error-text` | adapter and transport diagnostics' own text and code, Colibri's errors included | the core's fixed text; only errors parsed from node bodies pass through, and the adapter's own known errors keep their texts and codes; Colibri's capacity limit survives as a class; a refused Blockscout redirect is `redirected to a refused location` | another diagnostic loses its text and its code; a Colibri revert's message reads differently; a Blockscout redirect refusal doesn't name its reason (its 60 s cooldown is unchanged) |
| `paired-endpoint-text` | Blockscout's pairing texts name the RPC endpoint's host | `the paired endpoint` | a source failure's text reads differently; no final error shows it |
| `myotis-readiness` | `isReady()` sampled live | the last `chain.availability` | |
| `memory-budgets` | unbounded | per request and in total | `budget`, `busy` |
| `broadcast-outcome` | the last error wins; lost replies look like failures | attempt classes, exact refusals, `sent` / `uncertain` / `rejected` / `not_sent`, reconciliation, main's record | a lost reply is `uncertain`, not a failure |
| `nonce-retry` | a retry re-signs at the `pending` count, possibly a new nonce; history is written after broadcast and can be cleared | durable intent records committed before broadcast; an intent keeps its nonce for good, with retries only as the same bytes or a replacement at that nonce; finalized, verified labels (paid, failed, taken, held) authorize nothing; reservations under a per-account lock | the wallet never pays one intent twice; failed and taken intents go back to the user, who may start a new payment |
| `monotonic-time` | cooldowns on `Date.now()` | the monotonic clock | |

## Replay

The harness drives the pinned `chain-data-router.js`, with the real `blockscout-logs.js` and the Ant bridge's options, through scripted worlds:
- **World inputs:**
  - a registry snapshot per chain;
  - Myotis readiness and status sequences, and its outcomes per operation, its thrown errors included (each recorded with its class);
  - Colibri outcomes, with and without codes;
  - `fetch` exchanges with their delays, statuses and throws;
  - Blockscout pages and DNS answers;
  - fake timers;
  - callers' concurrency, origins, profiles and cancels.
- **Recorded:**
  - every exchange, with the URL, the body with its `id` normalized, its start, and its end or cancel;
  - every verifier operation;
  - each result or error with its key order, code, message and data, `undefined` included;
  - the state tables after each step.
- **No randomness** to seed.
- **The existing suites** (`chain-data-router.test.js`, the Ant log-scan and Blockscout suites) define the first scenarios.
- **Named boundary cases:**
  - the `html()` limit;
  - Direct's lower-index member that answered later;
  - quorum on answers without `result`;
  - truncation probes that fail or come back empty;
  - a refusal after an ambiguous attempt;
  - a repeat broadcast of mined bytes refused with `nonce too low` (freedom-browser's tests cover the wallet's rule: external same-payment replacements, lagging and inconsistent receipts, a reorg before finality, status-0 receipts, a singleton quorum, a crash between dispatch and record, concurrent reservations, and that no path signs an existing intent at a second nonce);
  - a read's reply overtaken by a configuration change after it was made;
  - a truncation with Direct still available;
  - nesting at 512 and 513 levels (`boundary-json-depth-512`, and `boundary-json-depth-513` for deviation `json-depth`);
  - canonical-equivalence pairs through the quorum: duplicate keys, number spellings, `__proto__`, lone surrogates (`boundary-agreement-*`).
- **The harness** (`vectors/generator/chain-replay.js`) has 297 scenarios, each with a stable ID and a `from` field citing its source test or this document.
  - **Values as text:** every value the reference produced or was given is recorded as JSON text, and `undefined` as a field of its own. No value can pass for an encoding, and every value `JSON.parse` makes survives: lone surrogates, any depth, `-0` and infinities.
  - **Large texts:** a text over 64 KiB is stored in its field's repeat form, a repeat unit plus a SHA-256, which keeps the 8 MiB `html()` answers small.
  - **Settle times:** ported scenarios carry the settle times their tests assert, and generation fails if a fixture drifts from them.
- **The machine replays all 297** (`crates/fc-chain/tests/replay.rs`), comparing every I/O request with its time and its cancel, every result and error with its key order and own properties, settle times and the state tables. A driver plays main from the records, delivering answers due in one tick in the reference's microtask order.
  - **17 scenarios show a deviation's difference,** each listed in the test with the reply, the I/O and the state it must show instead: `broadcast-outcome` (13: today's error, or a success with another hash, becomes `uncertain`, with the reconciliation lookups made listed), `config-change` (`boundary-registry-change-mid-request`), `order-validation` (`boundary-order-duplicates-and-unknown`), `json-depth` (`boundary-json-depth-513`) and `cancel-promptly` (`cancel-read-no-fallthrough`).
  - **None is skipped.**
- **Not replayed:** the machine's own tests cover the second and third (`crates/fc-chain/tests/machine.rs` and its unit tests); the first and fourth are main's (step 5):
  - a read's reply overtaken by a configuration change after it was made: that is main's reply fencing ([Generations](#generations)), and the reference has no seam for it;
  - the adaptive table's 1,024-route eviction;
  - a Myotis slot granted in the same turn as its waiter's deadline;
  - Blockscout's opaque redirect, which Node's `fetch` can't produce.
- **Deviation vectors** patch the reference in memory where a deviation has no natural trigger, as 0004's do. Broadcast's classes, outcomes and main's record are deviations, specified by their own vectors.

## Implementation steps

1. **Codecs and vectors:**
   - normalization, and the `stableValue` digest with its equivalence vectors;
   - `feeQuote`, Myotis payload classification, `blockscout-logs`' mappers and filters;
   - the Ant profile's ranking and cap parsing;
   - the broadcast refusal list and transaction hash;
   - byte parity from the pinned JS.
2. **The replay harness** (`vectors/chain-replay.json`).
3. **`fc-chain`:** the machine, replayed.
4. **`freedom-cored`:**
   - fragmented responses and bulk credit in `fc-protocol` and the transport;
   - the chain thread and the `chain.*` methods;
   - `shell.rpc`'s new parameters and `not_sent`;
   - the new verified operations.
5. **freedom-browser:**
   - the executors;
   - main's chain I/O pool and fragment handling;
   - the router, the fee quote and the broadcast become drivers, with main's broadcast record and reply fencing;
   - the wallet's intent records, nonce reservations and retry rule;
   - delete the JS router.

[0002](0002-signing.md)'s non-goal on fee estimation and broadcasting is amended there: fee quotes, reads and broadcast routing move into the core with step 5, while nonces and gas limits stay in main.

## Open questions

1. **Revert agreement.** Today reverts never agree in a quorum, so a dApp loses the revert data unless Myotis or Colibri gave it. Should identical error objects (code and data) count as agreement?
2. **Colibri's coverage.** Which methods does Colibri's `VerifiedOnly` client actually prove (`eth_gasPrice`, `eth_feeHistory`, `eth_blockNumber`, `pending` reads)? Today any Colibri success is labelled verified.
3. **Gnosis' Direct after a failed quorum** has nothing to ask without API keys. Intended?
4. **Myotis' head-of-line wait.** Methods Myotis doesn't serve take a slot before being refused. Checking the method first is a pure improvement, but observable in timing.
5. **The wallet's texts and UI** (step 5): how to show "sent, unconfirmed", unresolved and "taken" intents, and how to offer the same bytes again or a replacement at the same nonce.
6. **HTTP statuses on broadcast.** A 401, 403 or 429 is ambiguous here, although a gateway usually answers it before forwarding. Is a misconfigured key showing `uncertain` acceptable, or should these be refusals?
7. **Pinning and trust** (roadmap 3.1): whether a quorum of unpinned `latest` reads may be called `verified`.
