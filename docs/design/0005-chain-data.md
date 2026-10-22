# 0005: Chain data in the core

**Status:** proposed. Builds on [0001](0001-freedom-cored.md) (process, framing, deadlines), [0002](0002-signing.md) (signing) and [0004](0004-naming-sessions.md) (sessions, `shell.*` requests, verified operations, endpoint references, budgets). It is roadmap item 3.4: freedom-browser's chain-data router moves into the core.

**The reference** is `src/main/networks/chain-data-router.js` at freedom-browser `fb540328`, with `blockscout-logs.js` and the Ant bridge's router options (`swarm/ant-chain-bridge.js`).
- **Ground truth** will be a replay harness, `vectors/chain-replay.json`, built like 0004's: it runs the pinned router through scripted worlds and records every exchange, verifier operation, timing, result and error. Its scenario IDs are cited below where a rule depends on them.
- **Conflicts:** where this document and a vector disagree, the vector wins and the document has a bug.

## Summary

A chain read, a fee quote or a broadcast becomes a **request** in `freedom-cored`, run by a sans-I/O machine in a new crate, `fc-chain`, on its own thread (the *chain thread*). It reuses 0004's session machinery:
- **main → core:** `chain.request`, `chain.fee_quote` and `chain.broadcast` replace the router's three entry points. `chain.fee_reference` is new: the evidence for main's fee check ([Plausibility](#plausibility-decided-92)).
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
- **Pinning chain reads to a block**, and new trust semantics. Today's router reads at the caller's tag and calls m equal answers `verified`; the core keeps that for m of at least 2, and m distinct endpoints (deviations `singleton-quorum` and `endpoint-dedup`). Changing either further is roadmap 3.1's decision, not this design's.
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
| `chain.fee_quote` | `{ chain_id, deadline_ms }` | today's quote shape; Direct's adds `answered` (deviation `fee-combination`) | `getFeeQuote()` |
| `chain.fee_reference` | `{ chain_id, deadline_ms }` | `{ header, lowest_priority, quote, generation }` | nothing: new, the evidence for main's fee check ([A](#a-the-check-at-confirmation)) |
| `chain.broadcast` | `{ chain_id, raw, deadline_ms }` | `{ hash, source, outcome }` | `broadcastRawTransaction()` |

- **`params`** is the caller's JSON as main serializes it. The core parses it keeping JavaScript's property order, which [normalization](#normalization) depends on.
- **`origin`** is the router's routing context: the dApp's permission key or the `web3:` page's. It makes the read *interactive*. The core keeps it only in memory, for the [adaptive bypass](#adaptive-bypass), and never logs it.
- **`profile`** is `default` or `ant_scan`. Callers can't pass functions over the pipe, so the Ant bridge's options (`rankError`, `rangeCapOf`, the exclusions, Blockscout, the widened quorum budget) become one named profile, ported with vectors ([Logs](#logs)).
- **`background`** is the Ant bridge's flag: never queue for Myotis.
- **`deadline_ms`** is what is left of the caller's overall deadline when main sends the request, as naming's driver does; at most 120 s ([Deadlines](#deadlines)).
- **Cancellation** is 0001's `cancel`, which replaces the router's `AbortSignal` ([Cancellation](#cancellation)).
- **`isReadMethod`** stays in main: it is a constant table, mirrored with a vector.
- **`chain.html`** ([0006](0006-dweb-transports.md#chainhtml-43)), the `web3:` handler's `html()` read, is a request on this machine too: a read with its admission, generation, deadline, cancel and budget, whose document the core decodes and charges to the request.

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
- **Fixed-width numbers.** The core makes a request's frame before the request takes its slot at main ([Deadlines](#deadlines)). Its message `id` and its `deadline_ms` are then written into that frame as 20 characters each: spaces, then the digits (`"deadline_ms":                4850`). JSON allows whitespace before a value, so `JSON.parse` reads them as it reads any number.
- **`shell.blockscout`** keeps main's DNS check: an off-origin redirect must not resolve to a local address. That check needs DNS, which the core doesn't do.
  - **Its `headers`** are an object of strings. The core reads three of them, by name with ASCII case ignored: `content-length`, `x-ratelimit-reset` and `retry-after`.
  - **Main sends those three** when the page has them.
  - **The bound:** a reply may carry at most 8 headers. A reply with more is malformed.
  - **Why:** a page's header map is otherwise unbounded, and each header costs the core a vector place and two strings before its reply is charged.

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
| `{ myotis: "broadcast", chain_id, raw }` | `sendRawTransaction` | `{ hash }`, `{ rejected: { reason } }`, `{ rejected: { reason, code: -32602 } }`, `{ uncertain }`, `{ not_sent }` or `{ failure: class }` |
| `{ colibri: "request", chain_id, method, params, deadline_ms }` | `requestViaColibri` | `{ result }`, `{ undefined_keys: ["result"] }`, `{ revert: { data } }`, `{ revert: { data }, capacity: true }` or `{ failure: class }` |

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
- **A broadcast's `{ rejected }`** is one of the adapter's two definite refusals. Neither sent anything, and either ends the attempt loop, as the router's `myotisRefusal` check does. The core rebuilds the adapter's error: the reason, then its code and marker.
  - **`{ rejected: { reason } }`:** the client judged the transaction unpayable or its nonce used, on verified state (Myotis ABI 36). Code `-32000`, `myotisRefusal: "rejected"`.
  - **`{ rejected: { reason, code: -32602 } }`:** bytes that are no transaction Myotis relays (ABI 44), never gossiped. Code `-32602`, `myotisRefusal: "invalid-params"` (`boundary-broadcast-myotis-invalid-params`).
  - **Typed and bounded:** `code` is present only when it is `-32602`; any other value, `-32000` included, is a malformed reply. Nothing else of the adapter's error crosses. The reason is the adapter's own bounded text (`boundedReason`: trimmed, whitespace runs collapsed, at most 300 UTF-16 units).
  - **Negotiated:** `core.hello`'s capabilities gain `myotis_refusal_codes`, and main sends `code` only to a core that offers it. To an older core it sends `{ rejected: { reason } }` for both refusals: the broadcast still ends `rejected` with nothing else asked, but with code `-32000` and `myotisRefusal: "rejected"`.
- **Colibri's outcomes:**
  - **`{ result }`:** the verified result, as JSON.
  - **`{ undefined_keys: ["result"] }`:** the adapter resolved `undefined`, which JSON can't carry, so main sends this instead of a result. It has exactly that one member, and the array is exactly `["result"]`. The read succeeds with an own `result` of `undefined`, `source: "colibri"` and `verified: true`, as the router returns it today. Its reply omits `result` and lists it in `undefined_keys` ([Replies](#replies); `boundary-colibri-undefined-result`).
  - **`{ revert: { data } }`:** the worker's error carried code 3 and hex `data`, a revert the prover verified. The core rebuilds it as `execution reverted`, with code 3 and that data.
  - **`{ revert: { data }, capacity: true }`:** such a revert whose error is also a [capacity failure](#adaptive-bypass), as `capacity` below says. `capacity` is present only when it is `true`.
    - **The router does both:** it rejects with the revert, and `recordAdaptiveFailure` blocks the app's Colibri route for the process's life.
    - **The core does both:** it rebuilds the revert as above and marks the error a capacity failure for the adaptive bypass. With only Colibri configured, two identical `eth_call`s from one origin make one adapter call; the second is `temporarily bypassed for this app workload` (`boundary-colibri-revert-capacity`).
    - **The revert's text** is `execution reverted`, where the router rethrows the adapter's own error with its text (deviation `adapter-error-text`).
  - **`{ failure: class }`:** everything else, from the chain set above, plus Colibri's own `capacity`. Its text isn't forwarded whether or not it had a code (deviation `adapter-error-text`): main can't tell a node's error from the SDK's own.
  - **`capacity`** is the one bit of that text the [adaptive bypass](#adaptive-bypass) needs. Main sets it where the router's `isCapacityFailure(error)` holds for the adapter's error: its own `failureKind` is `capacity`, or the pattern `/out of gas|execution (?:gas|resource) limit|exceeds? (?:the )?(?:gas|execution) limit/i` matches `safeErrorMessage(error)`, the text after hex runs of 128 digits or more are elided, whitespace runs collapse to one space and the result is cut at 500 UTF-16 units (`fc_chain::safe_error_message`). The raw message is never matched: `out  of gas` is a capacity failure, and a phrase past the 500th unit is not. As today, it blocks the app's Colibri route for the core process's life (`router-colibri-capacity-demotion`, `boundary-adaptive-capacity-survives-success`, `boundary-adaptive-route-target-case`, `boundary-adaptive-capacity-whitespace`, `boundary-adaptive-capacity-past-500-units`, `boundary-adaptive-capacity-hex-elided`, `boundary-adaptive-capacity-failure-kind`).
- **Admission:** the router's slots stay as the core's admission rules, held until main's terminal reply. Myotis has 1 in flight and 16 waiting per chain, and background callers take only an idle slot. Colibri has 8 in flight, 2 per route. A request that ends while it waits for a Myotis slot, or after it was granted one but before its operation went out (a cancel, a configuration change, its deadline, its budget), leaves the queue or passes the slot on at once; only a dispatched operation holds it until main's reply.
- **Physical completion:** main replies only when the adapter's promise settles, never early. Main's per-verifier bound (0004: 8 operations) is shared by naming and chain data.
- **Reply size:** as 0004, main serializes each reply first; one over the message cap is `{ failure: "too_large" }`.

### Replies

- **A result** is `{ result, source, verified, trust? }`, keys in today's order.
  - **`result`** is embedded as **raw JSON**: the core writes the answer's validated `result` text into the reply as is, not as a JSON string. It is never escaped twice, and main's `JSON.parse` of the message yields the value, as today's `response.json()` did.
  - **`undefined`:** a body without `result`, or Colibri's `{ undefined_keys: ["result"] }`, answers `undefined`, which JSON can't carry. The reply then omits `result` and lists it in `undefined_keys` (0004's mechanism). Main restores an own `result` property, first in key order, whose value is `undefined`.
  - **`source`** stays on every result, so `chain-data-activity`'s watchdog records still work.
  - **Size:** the core measures the whole serialized reply. One over the message cap fails the request with `too_large`.
- **Every result and error** of `chain.request`, `chain.fee_quote` and `chain.fee_reference` carries `generation`: the chain's generation it was computed under ([Generations](#generations)).
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
  - Direct gives every endpoint `configured`, walking them one at a time ([Direct](#direct) on the reference's widening); a fee quote's Direct asks up to three at once ([B](#b-combining-directs-quotes));
  - the Ant profile widens the quorum budget to 30 s.
- **Overall:** 120 s per request, or the caller's `deadline_ms` if lower (deviation `overall-deadline`).
  - **Today** a request has no overall bound: an interactive read on chain 1 can take about 39 s, and more with user settings.
  - **Past the deadline,** a read or a fee quote ends with `deadline`, its I/O is cancelled, and nothing more is asked. A call that arrives with no time left (`deadline_ms` 0) replies `deadline` before any I/O, under its chain's current generation.
  - **A broadcast** ends as [Broadcast](#broadcast) says. Its attempts stop 10 s before the deadline, leaving room to [reconcile](#broadcast).
- **The latest start** of each request the core makes to main is the earliest of three times:
  - the end of its own exchange, for `shell.rpc`, `shell.blockscout` and Colibri;
  - its chain request's deadline;
  - for a request that sends a transaction (a Direct `eth_sendRawTransaction` or a Myotis `broadcast`), its broadcast's attempt cutoff. Reconciliation reads may still start after the cutoff, until the deadline.
- **The latest start is checked last,** as the final step before the request is handed to the writer.
  - **The check** runs under the gate the core's requests share, once the request's frame is made. Its clock reading is the one that also writes the request's `deadline_ms`.
  - **A request past it** never goes.
    - Past its exchange's end, when that comes before its chain request's deadline, it completes as not sent.
    - Past its chain request's deadline, that request ends with `deadline` (a broadcast, with its outcome) and its unsent I/O retires, freeing a verifier's slot. This holds when its exchange ends at that same instant too: the deadline goes first, so a read replies `deadline`, not a source's failure.
    - Past the cutoff, a transaction's attempt completes as not sent, even at its deadline, so a broadcast attempt that never went counts as not sent.
  - **Its `deadline_ms`** is what is left, at that reading, of the earlier of its exchange's end and its chain request's deadline.
  - **Not covered:** the time a request then spends in the writer's queue and in the pipe. For a broadcast attempt, the 10 s reserve covers that; any request's `deadline_ms` bounds what main does with it. A request is a whole frame, written in the order it comes, and never waits behind a fragmented reply or for main's credit ([Frames](#frames)).
- **Main's watchdog** is the deadline plus 15 s (0001).

### Cancellation

- **A `cancel`** ends the request at once, unless its response has already begun ([Frames](#frames)): a read or a fee quote replies `cancelled` (deviation `cancel-promptly`). Its pending `shell.rpc` and `shell.blockscout` requests are cancelled, quorum members included (deviation `abandoned-exchanges`: today's caller signal doesn't reach the quorum).
  - **Today** the router throws its `AbortError` only at its next check of the signal, so a read waiting on a verifier settles only when that operation does: `cancel-read-no-fallthrough` is aborted at 10 ms and throws at 20 ms, when Myotis's read settles. The core replies at 10 ms.
- **Verifier work** keeps its slot until main's terminal reply (parity: the router holds Myotis and Colibri slots until the operation physically settles). In `cancel-read-no-fallthrough` the Myotis slot is still held when the core replies. A terminal reply too large for its request's budget still frees the slot: its payload is dropped, and the request ends with `budget`. A terminal reply whose request has already ended is dropped as it arrives, and still frees the slot.
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
- **Endpoints are distinct** (deviation `endpoint-dedup`): an endpoint reference listed again is the same endpoint. It keeps its first place, and is user-configured if any of its entries is. The bound of 64 is on the entries main sends for a chain, checked at `chain.configure` before repeats are merged (a 65th entry is `invalid_argument`, even when it repeats an earlier one); so a chain has at most 64 distinct endpoints.
  - **Today** each entry is a quorum member of its own. One endpoint listed twice agrees with itself and reaches m = 2 alone, and its answer is labelled `verified` (`boundary-quorum-duplicate-endpoint`: endpoints a, a, b). Under [Evidence for labels](#evidence-for-labels), such an answer could settle an intent on one node's word.
  - **Main gives one reference per (chain, URL)**, so the core merges exact repeats. It can't see that two URLs reach one node: `https://x.example` and `https://x.example/`, or two API keys at one provider. Main therefore lists each host at most once in a chain's `rpc`, keeping the first in registry order, before it assigns references. A user source that repeats a builtin's URL, which `getEndpoints` keeps today, then adds nothing.
- **When main sends it:** at startup and from `network-ipc`'s `refreshDownstream`, where today only ENS and provider-manager caches are cleared. Controls queue ahead of later requests, as naming's do.

### Endpoints serve their chain (decided, #93)

**Status:** decided (the user, 2026-10-22):
- the check runs in main, before the snapshot;
- main re-checks every endpoint hourly;
- main refuses to save a user source whose endpoint answers another chain.

The options weighed are kept below.

- **Today** nothing asks an endpoint which chain it serves. A user-added RPC that serves another chain answers balances, nonces and receipts for that chain:
  - Direct returns them, labelled `unverified` or `user-configured`;
  - two such endpoints agree with each other, and a quorum of them is labelled `verified`;
  - a broadcast of a chain-bound transaction (EIP-155 legacy, or a typed one) is refused (`invalid chain id`). Every transaction the core signs is chain-bound. Raw bytes a caller passes to `chain.broadcast` need not be: an unprotected legacy transaction can be accepted by another chain's node, and the core doesn't decode a transaction's chain before sending it.
- **Why it matters for money:** [labels](#retrying-an-intent) read from a quorum. Two endpoints of another chain agree on that chain's finalized block, the sender's nonce there and the block that used it. Where the user has used the same account on that chain, the label can read *taken* for an intent still pending on the right chain. That settles the intent and frees its record, and a new send then takes a new nonce while the old bytes can still be mined. Once an endpoint counts once in a quorum and a quorum with m = 1 isn't verified (#90, #91), one misconfigured endpoint can't do this; two can.
- **The rule:** an endpoint takes part in reads, fee quotes and broadcasts for chain C only once `eth_chainId` from it has answered C, within the freshness of the place that checks (below). An answer that differs leaves it out; a failed check leaves it unchecked, and out, until a retry succeeds.
- **Where the check runs:**

| | Main, before the snapshot | The core, before an endpoint's first exchange |
|---|---|---|
| How | Main asks `eth_chainId` of each (chain, URL) through its executor; the snapshot lists only endpoints that answered C. Editing a source shows the user a mismatch at once. | The machine asks `eth_chainId` before an endpoint's first exchange in a generation. A mismatch is that endpoint's failure, with its own text. |
| Freshness | A result holds for one (chain, URL) for the core process's life: a reconfiguration that keeps the URL doesn't repeat it. Adding or editing a source checks it again. A failed check is retried with backoff (30 s, doubling to 10 min). | A result holds for one configuration generation. |
| Cost | Results are coalesced: the first snapshot waits a bounded time (say 3 s) for the startup checks, and later results join in at most one `chain.configure` a minute. Each snapshot that changes a chain advances its generation, which ends the chain's running requests; main sends a read or a fee quote again once. | One round trip more on each endpoint's first use per generation, inside its source's budget. |
| Parity and tests | None of the machine changes; the replay is untouched. | Every replay scenario's first exchanges change: the driver must answer the checks itself, and memory, cancel and broadcast rules need a case for the check (a broadcast attempt whose check failed was never sent). |
| Trust | Main is trusted for configuration already (it names the endpoints). | The core decides, as it decides the rest. |

- **The decision: main, before the snapshot.** The check guards against a misconfigured endpoint, not a malicious one: a lying endpoint answers `eth_chainId` correctly and lies about the rest, which only the quorum and the verifiers bound. A configuration-time check covers the misconfiguration, keeps the machine and its replayed scenarios as they are, and tells the user at the moment they can fix the source.
- **An hourly re-check:** main asks every (chain, URL) again once an hour.
  - A result that hasn't changed does nothing.
  - A changed one joins the coalesced reconfiguration above, at most one `chain.configure` a minute.
  - This narrows the window in which a URL repointed later in the process's life (such as a load balancer) goes unnoticed to about an hour.
- **A user source that answers another chain isn't saved.**
  - When the user adds or edits a source, main checks it before saving. A mismatch refuses the save, with a message that the endpoint serves another chain.
  - A check that merely fails (the endpoint is down, or times out) doesn't refuse it: the source is saved, and stays out until a retry succeeds.
  - A builtin endpoint that answers another chain is left out, as any endpoint is.

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
- **a capacity failure** blocks it for the core process's life: an error for which `isCapacityFailure` holds (its `failureKind`, or the pattern on its `safeErrorMessage`), a quorum whose members' capacity failures reach m, or Colibri's `capacity` class ([The rest](#the-rest));
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

- **Results:** `{ result, source, verified, trust? }`, where `verified` is true for myotis, colibri and blockscout, and for a quorum whose m is more than 1. `trust` comes only on request.
- **A quorum with m = 1** (deviation `singleton-quorum`) is one endpoint's answer, whatever the configuration says. Its reply is not `verified`, and its trust's `level` is Direct's for the endpoint that answered: `user-configured` or `unverified`. Its `method` stays `quorum`, and its `quorum` member still reads `{ k, m: 1, achieved: true }`. A fee quote from such a quorum is not `verified` either. Today all of them are labelled `verified` (`boundary-quorum-singleton-not-verified`), and `onchain-app-protocol.js` and the `web3:` gate read that flag alone.
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
- **Myotis `rejected`** counts as a refusal; its reasons include a used nonce, and bytes Myotis doesn't relay ([The rest](#the-rest)).
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
- **Labels, not permissions.** The wallet shows each intent's state, read at the chain's **finalized** block F (both Ethereum and Gnosis expose one). A label authorizes no retry. Settling an intent on a label does end its record, though: its bytes are forgotten and its key freed, so a later send of the same operation is a new intent at a new nonce. A label must therefore be true of the one finalized chain ([Evidence for labels](#evidence-for-labels)):
  - **Paid:** one of the intent's own transactions is included in a block of the finalized chain, with status 1.
  - **Failed:** one is included there with status 0. It consumed N and executed nothing.
  - **Taken:** another transaction of the sender, in a block of the finalized chain, has nonce N. It may be a payment of this very intent signed elsewhere, so the payment may or may not have happened.
  - **Held:** anything else. A chain without a finalized block keeps its intents held, as does evidence deeper than the bound in rule 2.
- **Failed and taken go back to the user.** The wallet explains what it knows and offers no retry. A new payment is the user's own act from the send screen: a new intent, with its own nonce and its own confirmation.
- <a id="evidence-for-labels"></a>**Evidence for labels.** Every read comes from a verified source: Myotis, Colibri, or a quorum of at least two agreeing endpoints. A quorum with m = 1 counts as Direct. Without such a source, an intent stays held.
  - **The core's labels carry this rule** (deviations `singleton-quorum` and `endpoint-dedup`): a quorum's reply is `verified`, with trust `level: "verified"`, only when m > 1, and its agreeing members are distinct endpoint references. A wallet that checks `level`, `achieved` and `m ≥ 2` therefore never counts one node's answer twice, nor a singleton quorum. Two references can still be one node behind two URLs; main's [configuration](#configuration) lists each host once for that reason.
  - **One finalized view.** Each read is agreed on its own, so two reads can be agreed by different endpoints, each with an honest node's own view: one lagging, one following an unfinalized fork. Mixing them can settle an intent on a fork's receipt (paid while the finalized nonce shows N unused), or read a lagging node's missing receipt as taken. A label therefore rests only on answers that don't depend on a node's view, tied to one finalized block F by its hash. Agreed by any pair that includes one honest node, such an answer is correct. These five rules are the contract:
    1. **The nonce at F.** Read the sender's nonce as `eth_getTransactionCount(sender, { blockHash: F.hash })` (EIP-1898). Every terminal label needs it past N. A node or chain that refuses the block-hash parameter leaves the intent held.
    2. **Inclusion on the finalized chain.** A receipt counts only if its block hash lies on the finalized chain. A walk of headers from F's hash along `parentHash`, down to the receipt's height, establishes that.
       - Headers may be fetched by number, in parallel, each checked against its child's `parentHash`. A header that differs is fetched again by that hash.
       - Verified headers never change, so a client keeps them per chain, shares them among the chain's intents, and extends them each time F moves.
       - The walk is bounded (8192 headers in freedom-browser). Evidence deeper than that leaves the intent held, recorded as unverifiable.
       - **What is retained is bounded too:** per chain, only the window from F down to F − 8192, and only each header's number, hash and `parentHash`. Headers below the window are evicted when F moves, and a chain with no held intents releases its headers.
       - **Re-anchoring:** a new F more than the window above the retained top doesn't link to it, so the segment restarts at the new F. An F older than the retained window, which a lagging agreeing pair can return, leaves the pass's intents held. So does an F whose hash differs from the verified header at its height. Evidence that would need headers outside the window stays held.
    3. **Taken needs positive evidence.** Locate the block that consumed N within those verified headers, by a binary search on the sender's nonce at each block's hash. Read that block with its transactions.
       - If the sender's nonce-N transaction there is none of the intent's hashes, the label is taken.
       - If it is one of them, the label is paid or failed from its receipt, under rule 2.

       The absence of receipts alone never yields taken.
    4. **Well-formed evidence.** Only an explicit `null` receipt means absence. Receipts and blocks must be well formed, with 32-byte hashes, and a block's number must be the height that was asked for. An undefined or malformed answer leaves the intent held.
    5. **Settlement against what was read.** A settlement is conditional on the intent's hashes (or revision) that the label was read for. That condition is checked in line with the record's other writes. If a replacement was committed meanwhile, even one still being written, nothing is settled, and the intent is read again.
  - **What a provider can do.** A dishonest provider, or a pair of them agreeing, can delay a label: withholding evidence keeps an intent held. Forging one takes every member of an agreeing pair lying.
  - <a id="state-history"></a>**State history** (proposed, #94; **needs the user's decision**). Rule 1 and rule 3's search read the sender's nonce at a block's hash, which a node can answer only while it serves that block's state.
    - **What nodes serve:** a node answers state queries for a window W of recent blocks. W depends on the client and its configuration: geth keeps the state of the last 128 blocks by default, and some clients and configurations keep a longer queryable history or all of it. Myotis reads only at `latest`, so these reads come from Colibri, if it proves them (open question 2), or from a quorum, both of whose agreeing members must serve them.
    - **Rule 1** fits a default window, with little room: F is about two epochs (64 to 96 blocks) behind the head on Ethereum, more while finality is delayed.
    - **Rule 3's search** reads the nonce at blocks as deep as the one that used N. The state is a need of that search, not of the evidence: the evidence is the sender's nonce-N transaction in a block of the verified chain. When the probed blocks fall outside W, the search fails and the intent stays held. That fails safe, but *taken* may then never be reached on public endpoints, and the intent's record, bytes and floor stay.
    - **The window limit stays.** Whatever the option below, evidence deeper than 8192 blocks below F stays out of reach (rule 2): an archive node doesn't change that.
    - **Options** (they combine: bracketing first, then a scan or state-serving members):
      - **State-serving members:** Colibri, if it proves these reads, or agreeing endpoints whose W reaches the probed blocks. Few reads, but most public endpoints don't qualify, and the user or the registry has to pick ones that do.
      - **Bracketing:** the search starts above the latest finalized block at which the tracker read the sender's nonce at most N, kept (number and hash) with the intent's record. It costs nothing more, and works while an observation is recent enough: the deepest probe is the head minus F's lag minus the blocks since that observation, and must stay within W. It fails when observations stop for long enough: the browser closed, a pass missed or failed, the system suspended, finality delayed. At the tracker's 10-minute interval a bracket is about 50 blocks on Ethereum and 120 on Gnosis, which with F's lag already reaches past a 128-block window, so a tracker holding such an intent should run at its fast interval.
      - **Block scan:** read the verified blocks between the bracket, or F − 8192, and F with their transactions, and look for the sender's nonce-N transaction. Nodes serve block bodies without historical state. Each block comes from a verified source and is checked against the verified header chain (rule 2), after rule 1 holds. It is costly: up to 8192 blocks with transactions per scan, from every agreeing member, which on Ethereum is gigabytes for the whole window (a short bracket costs a few blocks' worth). One scan serves every held intent of the chain, and it must be bounded per pass, resumable (the scanned range kept with the records) and cancellable.
      - **Stay held,** shown as *can't be confirmed* after a while (say a day of failed searches): its hashes, its nonce and a link to a block explorer. The record, its bytes and the nonce floor stay.
    - **The bracket is verified** like any header: both blocks are finalized, so the earlier one is an ancestor of F, which rule 2's walk checks. A bracket that doesn't verify is dropped, and the search falls back to the window. It is not secret.
    - **Manual settlement**, if offered for an intent that stays held, must keep the evidence rules that make forgetting safe:
      - it requires the verified nonce at F past N (rule 1): N is then used on the finalized chain, so none of the intent's bytes can be mined again;
      - it goes through rule 5's fencing (conditional on the revision the user saw, under the account's reservation lock), and retires the record durably, keeping its hashes, so a recovery can't revive it;
      - the UI warns that settling proves nothing: one of the intent's own transactions, or a copy signed elsewhere, may have paid.
    - **Decision needed:** which of the options, and whether manual settlement is offered, with its text.
- **Records.** Each intent has a durable record in main, separate from the display history, which can be cleared: `{ intent_id, chain_id, sender, nonce, hashes }`. Every hash in it was signed at that one nonce: main decodes each signed transaction before committing it and refuses one whose nonce, chain, sender or hash differs.
  - **What else it holds:** each hash's signed bytes, and the intent's unsigned fields and origin. Then "send again" needs neither the vault nor a device after a restart, and a replacement at N reuses the confirmed content. They are written with the record (mode 0600), never logged, and deleted when the intent settles.
  - **Committed first:** the record, with each new hash, is committed (written atomically, with fsync) before those bytes are handed to a broadcaster.
  - **Kept** until the intent is paid, failed or taken at finality, and never removed by clearing the history.
  - **Handoffs are recorded too.** Before main hands an intent's bytes to a broadcaster, it commits a handoff line naming that broadcast, and later its outcome. A handoff with no recorded outcome (a lost reply, a crash, the core dying) stays possibly sent for good: no later result can clear it.
  - **Void, the one exception:** the user may void an intent only when all of these hold.
    - **Every handoff closed `not_sent`:** every handoff of every one of its hashes has a recorded outcome of `not_sent` (main's `not_sent`, Myotis's `{ not_sent }`, or an attempt the core never sent).
    - **All in this process:** all of those handoffs and outcomes happened in this run of main. An intent recovered at startup is never eligible, because a crash or a restored older copy of the records can hide a handoff. A recovered intent is sent again instead.
    - **The highest nonce:** no other held intent of the account has a higher nonce. Freeing N below a held N+1 would strand N+1, which can't be mined until N is used.
  - **What voiding does:** frees N and forgets the bytes. Nothing was sent, so no copy can be mined, and a later intent at N can't pay twice.
  - **What keeps the record:** any other outcome, `rejected` included, since a refusal proves only that the nodes it reached refused it ([Refusals](#refusals)).
  - **Fencing:** voiding takes the account's reservation lock and is final. A send-again or replacement of that intent takes the same lock, and refuses a voided intent. So a retry already under way can't revive it, and a void can't race a retry.
  - **Identity:** `intent_id` is created when the user confirms a send, and retries carry it.
  - **After a restore,** a profile without records has nothing to retry. A request that arrives again (the same dApp call) is a new intent, for the user to confirm.
- **Reservations.** Nonces are reserved per `(chain_id, sender)` under one lock in main, from reading the `pending` count to committing the record. That includes a pending device approval, so two callers can't take the same nonce.
  - **The first free nonce:** a new intent takes the `pending` count, as today, but at least one above every nonce a held intent of that account has.
  - **The floor's cost:** a held intent that never reached the network (a crash before its broadcast, or a refusal) leaves a gap. Later sends wait behind it until it is sent again, replaced or taken, or, within the narrow conditions above, voided. Main therefore shows held intents, offers "send again" for each, and warns on a new send that would sit behind one.
  - **Send again and replacements** take the account's lock too, but never read `pending`: they keep the intent's N.
  - **Release:** a reservation whose signature never happened (the user rejected it on the device) is released, since no bytes exist.

### Main's record

The core can die mid-broadcast: an exit, the watchdog, a protocol error. Main therefore keeps its own record of every `chain.broadcast` in flight: the hash, and whether any attempt is possibly sent.
- **Marking:** main's executors mark the record when they start an exchange whose body is an `eth_sendRawTransaction` of that raw transaction, or a Myotis `broadcast` of it.
- **No reply from the core:** main reports `uncertain` if the record is marked, and `not sent` otherwise. Main never reports `rejected` on its own. Under the wallet's rule, neither can lead to a second payment.
- **The wallet** treats `uncertain` as sent-but-unconfirmed. It records the hash and tracks the receipt as for any send, and offers only what the rule allows. Its text and UI are a [follow-up](#open-questions).

## Fee quotes

`chain.fee_quote` follows `getFeeQuote` exactly, except in Direct's step, which B changes (deviation `fee-combination`, [B](#b-combining-directs-quotes)). It walks the read order with no capabilities, exclusions, bypass or Myotis slots.
- **Myotis** answers both components in one operation.
- **Direct** asks an endpoint for both. Today it walks them one at a time, and the first quote that answers wins; with B, it asks up to three at once and combines their quotes.
- **Other sources** make two requests.
- **The quote:**
  - legacy when there's no priority fee, or when it is negative or above the gas price;
  - a priority fee `BigInt` can't parse (such as `-0x1`) doesn't downgrade: it fails that source's quote, and Direct moves on to its next endpoint (`boundary-fee-direct-priority-unparseable`);
  - otherwise EIP-1559, with `baseFee = gasPrice − priority` and `maxFee = 2·baseFee + priority`;
  - decimal strings, `verified` for myotis, colibri and quorum; a quorum's only when its m is more than 1 (deviation `singleton-quorum`).

Vectors pin the downgrade boundaries. Whether a derived base fee and a "verified" Myotis fee are right is a product question, not a parity one.

### Plausibility (decided, #92)

**Status:** decided (the user, 2026-10-22):
- **A,** the cap at confirmation, with a threshold relative to the current network fee, not a fixed amount or the value sent;
- **B,** widened from two endpoints to several, keeping the tightest constraints.

C isn't adopted as a cap on quotes, and D isn't adopted.

**Tightened in #109's review** (2026-10-22):
- where a verified header shows the chain takes EIP-1559, mixed quotes combine as EIP-1559;
- a reference that is one endpoint's quote never permits auto-approval.

The options weighed are kept below. [B](#b-combining-directs-quotes) and [A](#a-the-check-at-confirmation) specify what was adopted.

- **Today** the only checks are a gas price above 0, a priority fee at most the gas price, and the 4096-bit width. Nodes rarely agree exactly on `eth_gasPrice`, so the quorum usually misses and Direct quotes, from one endpoint (`router-fee-quote-direct-same-endpoint`).
- **What one endpoint can do:** answer both values with 1e18 wei. The quote becomes EIP-1559 with base fee 0 and a priority fee of 1e18 wei per gas, about 21,000 ETH for a plain transfer, all of it a tip. A node refuses a transaction the sender can't cover, so the real risk is a smaller inflation: ten or fifty times the going rate, which the user pays in full and may not notice.
- **What the wallet shows:** the send screen and a dApp's transaction show an estimated fee, the gas limit times the quote's effective gas price. Nothing says the quote came from one endpoint, or that it is far above the chain's recent fees.
- **Provenance isn't plausibility.** A quote's `verified` names its source (Myotis, Colibri or a quorum), not a check of its value. An honest source can be far off during a spike, and fees can reach a transaction without any quote: a dApp supplies them, or a replacement raises them.
- **Options:**

| Option | Bounds it | Cost |
|---|---|---|
| **A. A cap in the send path (main):** before every signature of a transaction, the confirmation shows the most it can cost (gas limit × max fee per gas, or × gas price) and asks again above a threshold | every transaction the wallet signs, whatever its fees' source: a quote (verified or not), fees a dApp supplied, a replacement. A send above the threshold is never auto-approved | a threshold per chain (absolute, or relative to the value sent): product |
| **B. Two endpoints, the tighter constraints (core):** Direct asks a second endpoint where one exists, and combines the two quotes' constraints (below) | if one of the two is honest and answers, and both quotes are of one type, the transaction never pays more per gas than the honest quote's would at the same base fee, and a dishonest one can only underquote, which delays the payment (it can be replaced at the same nonce). With mixed types only the gas price is bounded, unless a verified header shows EIP-1559 ([B](#b-combining-directs-quotes)) | a second exchange per quote; a deviation from `requestDirectFeeQuote`'s single endpoint; a new replay scenario and a changed one |
| **C. A reference (core):** cap the priority fee by `eth_feeHistory` percentiles and the max fee by the latest block's `baseFeePerGas` | only with a verified, independent reference (below); otherwise a consistency check | several reads per quote; `latest` reads that disagree across nodes; a deviation |
| **D. A configured ceiling (main → core):** the snapshot carries a per-chain maximum fee per gas, and a quote above it fails | quotes only: not fees a caller supplies, nor the gas limit | a number per chain, which a custom chain has no good default for |

- **C's reference.** It bounds a quote only if it is verified and independent of the quote: read from Myotis, from Colibri where it proves those reads, or from a quorum of at least two distinct endpoints, and never from Direct, which may be the quoting endpoint itself. Quorums on `latest` often miss, and a chain without EIP-1559 has no base fee: then C either fails the quote or leaves it to A. Read from the quoting endpoint, C is only a consistency check, which catches a broken node, not a dishonest one.
- **The decision: A owns the problem, and B hardens the core's quotes.** A is the last step before a signature, and covers every transaction, not just quotes. Neither proves a fee honest: B narrows what endpoints can do to a Direct quote, and A's ratio is a confirmation heuristic.

#### B: combining Direct's quotes

Deviation `fee-combination`. A fee quote's Direct step (today's `requestDirectFeeQuote`) asks several endpoints and combines their quotes. Myotis, Colibri and the quorum quote as today.
- **Collection:**
  - **Endpoints:** the chain's `rpc` endpoints in registry order, the quorum's included, as today's Direct quote.
  - **Three at once:** it starts the first three. Each asks `eth_gasPrice`, then, once that has answered, `eth_maxPriorityFeePerGas`, each exchange within `configured`. Each endpoint's quote comes from today's codec:
    - a failed, missing, negative or too-high priority hint gives a legacy quote;
    - a failed gas price, a non-positive one or an unparseable priority hint fails that endpoint.
  - **Replacement:** until a quote has answered, an endpoint that fails is replaced by the next one not yet asked, so every endpoint can still be reached, as today's walk does. Once one has answered, no endpoint starts.
  - **Cutoff:** collection ends when no started endpoint is still running, or 1 s after the first quote answered, whichever is first. Outstanding exchanges are then cancelled, and an endpoint still waiting for either answer hasn't answered. The cutoff goes first in its tick: an answer in that tick is left out, as for a deadline.
  - **A header, for mixed quotes:** where the chain has a prover and its read order includes `colibri`, the collection also starts the verified header read that [A](#a-the-check-at-confirmation)'s evidence uses.
    - **When it is used:** only if the answers are mixed. The combination then waits for it, within Colibri's budget.
    - **Otherwise** nothing waits for it, and its outcome is dropped when it arrives (verifier operations hold their slot until main's reply).
    - **Its age doesn't matter here:** a base fee in a verified header shows the chain takes EIP-1559 transactions.
  - **No quote:** with every endpoint failed, Direct fails with the last error to arrive (in one tick, the higher registry index's). With no endpoint it is today's `No RPC endpoint configured`, and no header is read.
  - **Deadline, cancel and reconfiguration** work as for any fee quote ([Deadlines](#deadlines), [Cancellation](#cancellation), [Generations](#generations)): the request ends, and every outstanding exchange is cancelled.
- **Combination.** Each answered quote is read as two constraints: a max fee per gas M and a priority fee P. An EIP-1559 quote gives its `maxFeePerGas` (2·G − P) and its P; a legacy quote's gas price G gives M = P = G. Under EIP-1559 a transaction pays min(M, base fee + P) per gas.
  - **Not the raw minima:** today's quote derives M = 2·G − P, so the lower G with the lower P can raise M. G = 100, P = 10 gives M = 190; a second answer of G = 100, P = 9 makes the minima give M = 191.
  - **All EIP-1559:** EIP-1559, with the lowest M and the lowest P (which is never above that M).
  - **All legacy:** legacy, at the lowest gas price.
  - **Mixed** (an endpoint gave no valid priority hint), **where EIP-1559 is verified,** that is, the header read has a base fee: EIP-1559, under the all-EIP-1559 rule, a legacy quote counting as M = P = G. So the lowest M and the lowest P.
  - **Mixed, otherwise** (no prover, Colibri out of the read order, a failed or malformed header, or one without a base fee): legacy, at the lowest gas price of all the quotes, an EIP-1559 quote's being its `effectiveGasPrice`. A missing hint alone doesn't show that the chain takes EIP-1559 transactions.
  - **One answer:** that quote, unchanged.
- **What it guarantees,** when an honest endpoint answers before the cutoff:
  - **All EIP-1559, all legacy, or mixed where EIP-1559 is verified:** at every base fee, the transaction pays per gas at most what the honest quote's own transaction would, and can cost at most what that one could. Inflating the fee takes every answering endpoint. A dishonest or broken one can only underquote, which delays the payment; it can be replaced at the same nonce.
  - **The boundary case:** an honest EIP-1559 quote G = 100, P = 1 (M = 199) and another endpoint's legacy G = 1000. Where EIP-1559 is verified, they combine to EIP-1559 with M = 199 and P = 1. If the base fee falls to 1 before inclusion, the transaction pays 2 per gas, as the honest one would.
  - **Mixed, otherwise:** the gas price is at most the honest endpoint's, so the transaction can cost at most what the honest quote's could. But a legacy transaction pays its whole gas price at any base fee, where an honest EIP-1559 one pays less as the base fee falls. Any endpoint can force legacy by withholding its priority hint.
    - **In the boundary case** without a verified header, the quotes combine to legacy G = 100, which pays 100 per gas at a base fee of 1.
    - A doesn't flag this: at confirmation the gas price is the network's current one.
  - **One answer:** no bound. The quote is that endpoint's, as today, and A judges it.
- **The reply** keeps today's shape and key order, with one key added after `verified`: **`answered`**, the number of endpoints whose quotes were combined (1 to 3). `answered: 1` is the single-source marker. `source` stays `direct`, and `verified` stays `false` however many agree. Other sources' quotes keep today's shape exactly, without `answered`.
  - **Legacy:** `gasPrice` and `effectiveGasPrice` are the combined gas price.
  - **EIP-1559:** `maxFeePerGas` is M and `maxPriorityFeePerGas` is P, exactly, since they are what is signed. `baseFee` is ⌊(M − P)/2⌋ and `effectiveGasPrice` is `baseFee` + P: estimates for display, never above any answering endpoint's gas price.
  - **Today's relation `maxFeePerGas = 2·baseFee + maxPriorityFeePerGas`** can't survive independent minima. G/P answers 10/1 and 10/2 combine to M = 18, P = 1, where (M − P)/2 would be 8.5 wei. The quote reads `baseFee` 8 and `effectiveGasPrice` 9, so 2·`baseFee` + P is M or one less. With one answer, M − P is even, and every field is today's.
- **Tests,** required of the implementing PR ([Replay](#replay) lists the scenarios it changes):
  - **The combination:** codec vectors, `fee_combinations` in `vectors/chain.json`. The reference has no counterpart, so their expected values come from this text.
  - **The collection:** machine tests, named `boundary-fee-combine-*`:
    - three successes;
    - independent M and P minima, M − P odd included (10/1 with 10/2), and the raw-minima trap (100/10 with 100/9 gives M = 190, not 191);
    - all legacy;
    - mixed with a verified header (the boundary case pays 2), and mixed without one (it pays 100): no prover, Colibri out of the read order, a failed or malformed header, a header without a base fee;
    - mixed, with the header arriving after the collection ends; and a header read whose outcome is dropped when the answers aren't mixed;
    - partial failures: one fails and two combine; a failure replaced before any answer; an unparseable priority hint on one endpoint;
    - all failing, with the last error;
    - singletons: one endpoint configured, and one of three answering;
    - the cutoff: a third answer after it is cancelled and left out, an endpoint whose priority exchange is outstanding at it is left out, and an answer in its tick;
    - races: the deadline, a `cancel` and a configuration change while exchanges are outstanding.

#### A: the check at confirmation

A runs in main, at the confirmation before every transaction signature: a send the user starts, a dApp's, a replacement, a Ledger signature. Broadcasting the same signed bytes again signs nothing, so A doesn't run for it.
- **What it shows:** the most the transaction can cost, its gas limit × max fee per gas (× gas price, if legacy).
- **The threshold is relative to the current network fee.** A fixed amount per chain can't follow congestion pricing, and a ratio to the value sent means nothing for the many transactions that send no native value.
- **The check:** the confirmation asks again when the transaction's max fee per gas (its gas price, if legacy) is above about 3·R, R being the reference below. It names the ratio ("20× today's network fee"), and such a send is never auto-approved. The multiple is tuned against measured fee spikes before release.
- **Whatever set the fee:** a quote from any source, a dApp's fields or a replacement. The transaction is judged against the same R, which never comes from the transaction itself.
- **The evidence** comes from **`chain.fee_reference`** `{ chain_id, deadline_ms }`, a new core request. It doesn't depend on how the transaction got its fees, or whether any quote was made.
  - **Its rules:** a fee quote's, for admission, deadline, cancel, generation, reply fencing and budget.
  - **Its two parts** run at once.
  - **Only Colibri supplies the verified base fee today.** A Myotis head operation is a follow-up, and needs Myotis support (below).
  - **A verified header:** where the chain has a prover and its read order includes `colibri`, Colibri's `request` operation for `eth_getBlockByNumber` with `["latest", false]`, a method Colibri proves (its light client polls it for the head).
    - **The header** is the result's `number`, `timestamp` and `baseFeePerGas`, which must be quantities. A failed, malformed or `undefined` answer gives no header. A header without `baseFeePerGas` (a chain without EIP-1559) has no base fee.
    - **Myotis** has no operation that returns a header ([Verified operations](#verified-operations)). Its `fee` estimate is a gas price and a priority fee. The base fee a quote derives from them (gas price − priority), Myotis's or any source's, is never taken for a header's.
    - **A later Myotis source:** an operation returning Myotis's verified head (number, timestamp, base fee) would make Myotis a second source of headers. It needs Myotis support, and is a follow-up.
  - **B's quotes:** B's collection, run for the reference itself, where the chain's read order includes `quorum` or `direct`, the sources that reach those endpoints. It runs even when an earlier source (Myotis, Colibri, the quorum) quoted the transaction, and it never asks those sources. Its mixed rule uses this request's own header read.
  - **The reply:** `{ header, lowest_priority, quote, generation }`, numbers as decimal strings:
    - `header`: `{ source: "colibri", number, timestamp, base_fee }`, with `base_fee` null on a chain without one; or null;
    - `lowest_priority`: the lowest priority fee among B's EIP-1559 quotes, or null when none gave a valid hint;
    - `quote`: B's combined quote, with `answered`; or null when no endpoint answered.
  - **Failures:** a part that fails is null. The request fails only as a fee quote can (`deadline`, `cancelled`, `busy`, `budget`, or `reconfigured` after main's one resend), and main then has no reference.
- **The reference R,** per gas, computed by main from the reply:
  1. **Verified:** the header has a base fee B and is fresh, its `timestamp` within 60 s of main's clock either way. R = 2·B + `lowest_priority`, or 2·B when that is null (all of B's quotes legacy on an EIP-1559 chain, or none answered).
  2. **Combined quote:** otherwise, the combined-quote fallback, when B's combined quote is at most 60 s old. R is its `maxFeePerGas`, or its `gasPrice` if legacy. It applies with no prover, Colibri out of the read order or failing, a malformed or stale header, or a chain without EIP-1559.
     - **The quote's age** counts from the moment main sent the `chain.fee_reference` that returned it, not from the reply's arrival. The quote was made after that moment, so its true age is never more.
     - **Everything after counts:** the time the request spent waiting for its header, the transport, and any time main holds the reply.
     - **A slow header part** can therefore deliver a quote that is already too old. If B finishes at 0.1 s and the header fails at 60 s, the quote is past 60 s by the time the reply is used, and this branch doesn't apply.
  3. **None:** otherwise, or when R is 0.
  - **No reference:** the confirmation shows the most the transaction can cost, says it couldn't be compared, and the send isn't auto-approved.
  - **One endpoint's reference:** when R is a combined quote with `answered: 1`, it is that endpoint's word, and a Direct quote from it has a ratio of 1 against it. The confirmation still compares and shows the ratio, and a send above the threshold is still asked again. But no send judged against it is auto-approved: A can't judge it reliably. On a chain with one RPC endpoint and no verified header, no send is auto-approved.
  - **A spike before signing:** the check uses evidence at most 60 s old at the moment of approval, by the user or automatically. A header's age comes from its `timestamp`, a quote's from its request's start. Older evidence is gathered again before the signature, and the user is asked again if the new R puts the send above the threshold.
    - **Reused evidence**, for a later approval or for another transaction's confirmation, keeps those ages.
    - **Evidence gathered again** has a new request start.
    - **A rising base fee** raises R with it.
    - **During a spike** 2·B is headroom, not a forecast. A transaction quoted after the evidence was gathered can be asked about though it would pay little. The multiple and the 60 s are tuned together.
  - **A wrong clock** makes every header stale; R then falls back to the combined quote.
- **What A detects:**
  - **Verified:** a max fee above about 3·R, whoever set it: an inflated base-fee part, a dApp's fee, a replacement's.
    - **Its priority part** comes from B's quotes. A tip that every answering endpoint inflates moves R with it, and isn't detected ([Open questions](#open-questions) 10).
    - **An endpoint that underquotes** can lower R. That costs a question, never a payment.
  - **Combined quote:** R comes from the same endpoints, combined the same way, as a Direct quote. A quote they all inflate has a ratio near 1, so this fallback can't detect inflation of that quote.
    - **What it still detects:** fees set elsewhere far above the endpoints' quotes, a dApp's, a replacement's or another source's.
    - **With one answering endpoint,** R is that endpoint's word, so nothing judged against it is auto-approved (above).
  - **Mixed types without a verified header:** B's legacy excess is below the honest gas price, so it stays within the threshold whichever R applies. Where a header is verified, B combines mixed quotes as EIP-1559, and there is no such excess.
  - **Not a proof:** the ratio is a confirmation heuristic, not proof that a fee is honest.
- **Tests,** required of the implementing PRs:
  - **The core's machine tests for `chain.fee_reference`:**
    - header and quotes;
    - an earlier source's success: a read order that starts with Myotis still gets Colibri's header and B's quotes, with no Myotis `fee`;
    - no prover; Colibri out of the read order; no `quorum` or `direct` in it;
    - Colibri failing or malformed; a header without `baseFeePerGas`;
    - the deadline, a `cancel` and a configuration change.
  - **Main's tests for A** (freedom-browser, step 5):
    - fees from a Myotis, Colibri, quorum and Direct quote, a dApp's EIP-1559 and legacy fields, and a replacement, each judged against the same R;
    - the threshold, at and just above 3·R;
    - all-legacy quotes on an EIP-1559 chain (R = 2·B), and a legacy chain (the combined quote);
    - a quote's derived `baseFee` never used as the header's: a Myotis quote with Colibri down takes the combined quote, or no reference;
    - unavailable and stale header evidence (61 s old, 61 s ahead), with and without B's quote;
    - no reference: the most shown, "couldn't compare", never auto-approved; R of 0 likewise;
    - one endpoint's reference (`answered: 1`): the ratio shown, a send above the threshold asked again, and a send below it still not auto-approved;
    - a base-fee spike before signing: evidence 61 s old gathered again, and the user asked again only when the send is newly above;
    - the quote's age from its request's start:
      - fast quotes with a header that fails, or comes back stale, at 60 s, and an approval 61 s after the request started: no combined-quote reference, though the reply is 1 s old;
      - the same with evidence reused for a later approval and for another transaction;
    - the mixed-type boundary case without a verified header, shown not flagged.

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
| Blockscout page headers | 8 | a malformed reply |
| the chain writer | one message cap of unwritten bytes | replies wait in the chain thread's queue, counted in the total |
| main's chain I/O pool | 192 MiB: bodies being read, verifier results, replies until written; replies under 64 KiB exempt | the exchange fails `busy` |
| quorum k / endpoints | 9 / 64 | clamped at configuration |
| JSON depth | 512 | a source failure |
| memory, per request | 96 MiB: its call's strings, received messages once handed over, answer texts and their indexes, retained texts and errors, the copies it makes, its requests until the driver takes them, replies | the request ends with `budget` (broadcasts: [Outcome](#outcome)) |
| memory, all chain requests | 256 MiB, with unwritten replies counted until written (0004's rule) | new requests `busy`, running ones `budget` |
| adaptive routes | 1024 | the oldest evicted |
| retired endpoint state | 64 | the oldest dropped |

**Memory is reserved before it is allocated.** Each allocation a request makes is charged first, at an upper bound, and settled to what it holds once made: a request body; a replacement-decoded text's growth over its body (whose charge goes with the body); every index, sized by a counting pass before it is built; a writer's scratch; normalized params, their index and copies (a standing reservation held for the request's life); a node error's or a verifier error's copies, held while any copy lives; a decoded answer for as long as its text lives, through a broadcast's classification and the copies of its error; the fee codec's indexes, conversions (`ToPrimitive` text, `BigInt` limbs), messages and quote, a conversion that throws (an object with its own `toString`) being known before any of its text is built; a node error's message, built in a buffer of exactly its length; Blockscout's pages, their indexes and the transfers they add; joined and agreed results; the reply's copy of a result. Some work needs no reservation, because it allocates nothing: a purported transaction hash is read in place into 32 bytes and refused at the first unit that can't belong (its 65th digit included), and a raw transaction is hashed as its hex is read. A reservation the budget refuses stops the request before the allocation, and it ends with `budget`; a broadcast ends through the [outcome table](#outcome), so an attempt that was outstanding stays possibly sent. A request over its budget is never polled again. A reply waiting for the driver counts in the total at what it holds, an error's UTF-16 message included; the message cap is checked on its serialized size, measured without writing it. Once the driver takes a request or a reply, its bytes leave the request's charge and count in the driver's backlog, which main reports, until written.

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
| `endpoint-dedup` | an endpoint listed twice is two quorum members, so it can agree with itself | each endpoint reference once, in its first place; user-configured if any entry is | one endpoint never reaches a quorum alone |
| `singleton-quorum` | a quorum with m = 1 is labelled `verified`, reads and fee quotes alike | `verified: false`, and the trust level Direct gives that endpoint | one endpoint's answer is never verified evidence |
| `config-change` | the registry re-read mid-request; a change applies piecemeal | a change ends the chain's requests; main sends reads and fee quotes again once | callers see the new configuration whole |
| `abandoned-exchanges` | the caller's signal doesn't reach the quorum | a cancel cancels members | |
| `cancel-promptly` | the `AbortError` is thrown at the router's next check, so a read waiting on a verifier settles when that operation does | `cancelled` at once; the verifier's slot is held until main's reply | `cancel-read-no-fallthrough` replies at 10 ms, not 20 |
| `state-retention` | log-range and pair state never pruned | configured + 64 retired | |
| `json-parse-text` | V8's message with a body fragment | a fixed message | |
| `adapter-error-text` | adapter and transport diagnostics' own text and code, Colibri's errors included | the core's fixed text; only errors parsed from node bodies pass through, and the adapter's own known errors keep their texts and codes; Colibri's capacity limit survives as a class, or beside a verified revert; a refused Blockscout redirect is `redirected to a refused location` | another diagnostic loses its text and its code; a Colibri revert's message reads differently; a Blockscout redirect refusal doesn't name its reason (its 60 s cooldown is unchanged) |
| `paired-endpoint-text` | Blockscout's pairing texts name the RPC endpoint's host | `the paired endpoint` | a source failure's text reads differently; no final error shows it |
| `myotis-readiness` | `isReady()` sampled live | the last `chain.availability` | |
| `memory-budgets` | unbounded | per request and in total | `budget`, `busy` |
| `broadcast-outcome` | the last error wins; lost replies look like failures | attempt classes, exact refusals, `sent` / `uncertain` / `rejected` / `not_sent`, reconciliation, main's record | a lost reply is `uncertain`, not a failure |
| `nonce-retry` | a retry re-signs at the `pending` count, possibly a new nonce; history is written after broadcast and can be cleared | durable intent records committed before broadcast; an intent keeps its nonce for good, with retries only as the same bytes or a replacement at that nonce; labels (paid, failed, taken, held) read from verified evidence tied to one finalized block by hash, which authorize no retry; reservations under a per-account lock | the wallet never pays one intent twice; failed and taken intents go back to the user, who may start a new payment |
| `monotonic-time` | cooldowns on `Date.now()` | the monotonic clock | |
| `fee-combination` | a fee quote's Direct step walks the endpoints one at a time, and the first quote that answers wins | up to three endpoints at once, a failure replaced until one answers, a 1 s cutoff after the first answer; their quotes combined by normalized constraints, mixed ones as EIP-1559 where a Colibri header read alongside shows a base fee; the reply marked with `answered` ([B](#b-combining-directs-quotes)) | different requests, starts and cancels, and a Colibri operation where the chain has a prover and `colibri` in its read order; with one type of quote, or mixed ones where EIP-1559 is verified, the transaction pays no more than an honest answering endpoint's would; a combined quote's `baseFee` and `effectiveGasPrice` are rounded estimates |

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
  - canonical-equivalence pairs through the quorum: duplicate keys, number spellings, `__proto__`, lone surrogates (`boundary-agreement-*`);
  - `isCapacityFailure` on Colibri's errors: collapsed whitespace, a phrase past 500 units, elided hex and an error's own `failureKind` (`boundary-adaptive-capacity-*`).
- **The harness** (`vectors/generator/chain-replay.js`) has 306 scenarios, each with a stable ID and a `from` field citing its source test or this document.
  - **Values as text:** every value the reference produced or was given is recorded as JSON text, and `undefined` as a field of its own. No value can pass for an encoding, and every value `JSON.parse` makes survives: lone surrogates, any depth, `-0` and infinities.
  - **Large texts:** a text over 64 KiB is stored in its field's repeat form, a repeat unit plus a SHA-256, which keeps the 8 MiB `html()` answers small.
  - **Settle times:** ported scenarios carry the settle times their tests assert, and generation fails if a fixture drifts from them.
- **The machine replays all 306** (`crates/fc-chain/tests/replay.rs`). A driver plays main from the records: it starts each call when the reference did, and answers each request with the answer its record got, at the time it got it, delivering answers due in one tick in the reference's microtask order (a failed fetch or a non-2xx status settles before a body is read; equal delays settle in registration order). It compares exactly:
  - **every request the core owns** (`shell.rpc`'s endpoint and body with its `id` normalized, a verifier operation and its params, a Blockscout page) with its start, matched to a record of the same call, and **in the reference's order**: no request answers a ledger entry earlier than one already matched. No allowance for unordered concurrency is needed; the order holds across every call of every step. Main's own I/O (Blockscout's hops and DNS lookups, Myotis status samples) feeds the replies main sends instead;
  - **every cancel:** an exchange the reference aborted at T is cancelled at T, and no other is cancelled, except in two permitted races, each counted: a quorum member cancelled when a sibling launched in the same tick answered the same call in the tick both settled (127; the reference's abort came after the member's answer), and a Blockscout page cancelled by the scan's deadline in the tick its own fetch failed with `no answer within` (4). Main never delivers an answer to an exchange the machine cancelled first: it aborted it;
  - **every result and error,** with its settle time: key order, constructor, `name`, message, own properties, `-0` and UTF-16 strings;
  - **the state tables** after each step. Route keys whose target lists several addresses are compared with that list digested ([Adaptive bypass](#adaptive-bypass)).
  - **20 scenarios show a deviation's difference,** each listed in the test with the whole reply, the requests and the state it must show instead, and every field the deviation doesn't change still compared: `broadcast-outcome` (13: today's error, or a success with another hash, becomes `uncertain`, reporting keccak256 of the raw bytes, with each reconciliation lookup made listed with its endpoint and its whole body or params, the hash included), `config-change` (`boundary-registry-change-mid-request`: the three members asked again at 1,000 listed whole, and the one exchange the change moves, Direct's, given its new start), `order-validation` (`boundary-order-duplicates-and-unknown`), `endpoint-dedup` (`boundary-quorum-duplicate-endpoint`: a asked once, its second exchange never made, and the quorum's miss handed to Direct), `singleton-quorum` (`boundary-quorum-singleton-not-verified`: the same requests, two reads and a fee quote labelled as Direct would), `json-depth` (`boundary-json-depth-513`), `cancel-promptly` (`cancel-read-no-fallthrough`) and `adapter-error-text` (`boundary-colibri-revert-capacity`: the revert reads `execution reverted`, its route blocked as today).
  - **`fee-combination`** ([B](#b-combining-directs-quotes)) changes three more when it is implemented.
    - **What each lists:** its whole requests, with their starts and cancels, and its whole reply.
    - **What is compared:** each reply's values and key order, `answered` last.
    - **The inputs stay:** the endpoints' scripted answers are unchanged.

    The three:
    - **`router-fee-quote-direct-same-endpoint`:**
      - both endpoints asked at 0;
      - the inputs: primary answers G = 3773, P = 1 (M = 7545), and secondary answers `0x1` to both (G = 1, P = 1, M = 1);
      - B's reply: `{"type":"eip1559","baseFee":"0","maxPriorityFeePerGas":"1","maxFeePerGas":"1","effectiveGasPrice":"1","source":"direct","verified":false,"answered":2}`;
      - today's is primary's alone: `baseFee` 3772, `maxFeePerGas` 7545, `effectiveGasPrice` 3773.
    - **`boundary-fee-direct-priority-unparseable`:** b asked at once with a, not after it. a fails, and b's legacy quote stands: `{"type":"legacy","gasPrice":"16","effectiveGasPrice":"16","source":"direct","verified":false,"answered":1}`.
    - **`boundary-fee-direct-gas-price-fails-first`:** b asked at once with a. a fails, and b's legacy quote stands: `{"type":"legacy","gasPrice":"1000000000","effectiveGasPrice":"1000000000","source":"direct","verified":false,"answered":1}`.

    The other fee-quote scenarios don't reach Direct with more than one endpoint, and stay as they are. None of the three has `colibri` in its read order, so B's header read adds nothing to them.
  - **None is skipped.**
- **Not replayed:** the machine's own tests cover the second, third, fifth and sixth (`crates/fc-chain/tests/machine.rs` and its unit tests); the first and fourth are main's (step 5):
  - a read's reply overtaken by a configuration change after it was made: that is main's reply fencing ([Generations](#generations)), and the reference has no seam for it;
  - the adaptive table's 1,024-route eviction;
  - a Myotis slot granted in the same turn as its waiter's deadline;
  - Blockscout's opaque redirect, which Node's `fetch` can't produce;
  - B's collection beyond the three scenarios above (`boundary-fee-combine-*`, [B](#b-combining-directs-quotes));
  - `chain.fee_reference`, which the reference doesn't have ([A](#a-the-check-at-confirmation)).
- **Deviation vectors** patch the reference in memory where a deviation has no natural trigger, as 0004's do. Broadcast's classes, outcomes and main's record are deviations, specified by their own vectors.

## Implementation steps

1. **Codecs and vectors:**
   - normalization, and the `stableValue` digest with its equivalence vectors;
   - `feeQuote`, Myotis payload classification, `blockscout-logs`' mappers and filters;
   - B's combination (`fee_combinations`);
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
   - A's check at confirmation, from `chain.fee_reference`;
   - the wallet's intent records, nonce reservations and retry rule;
   - delete the JS router.

[0002](0002-signing.md)'s non-goal on fee estimation and broadcasting is amended there: fee quotes, reads and broadcast routing move into the core with step 5, while nonces and gas limits stay in main.

## Open questions

1. **Revert agreement.** Today reverts never agree in a quorum, so a dApp loses the revert data unless Myotis or Colibri gave it. Should identical error objects (code and data) count as agreement?
2. **Colibri's coverage.** Which methods does Colibri's `VerifiedOnly` client actually prove (`eth_gasPrice`, `eth_feeHistory`, `eth_blockNumber`, `pending` reads)? Today any Colibri success is labelled verified.
3. **Gnosis' Direct after a failed quorum** has nothing to ask without API keys. Intended?
4. **Myotis' head-of-line wait.** Methods Myotis doesn't serve take a slot before being refused. Checking the method first is a pure improvement, but observable in timing.
5. **The wallet's texts and UI** (step 5): how to show "sent, unconfirmed", unresolved and "taken" intents, and how to offer the same bytes again or a replacement at the same nonce. [State history](#state-history) adds one: an intent that can't be confirmed for lack of state, and whether the user may settle it by hand.
6. **HTTP statuses on broadcast.** A 401, 403 or 429 is ambiguous here, although a gateway usually answers it before forwarding. Is a misconfigured key showing `uncertain` acceptable, or should these be refusals?
7. **Pinning and trust** (roadmap 3.1): whether a quorum of unpinned `latest` reads may be called `verified`.
8. **Endpoints' chain** (#93): **decided** (the user, 2026-10-22): in main, re-checked hourly, and a mismatched user source isn't saved. See [Endpoints serve their chain](#endpoints-serve-their-chain-decided-93).
9. **Fee plausibility** (#92): **decided** (the user, 2026-10-22): A, with a threshold relative to the current network fee, and B across several endpoints; tightened in #109's review: mixed quotes combine as EIP-1559 where a verified header shows it, and one endpoint's reference permits no auto-approval. See [Plausibility](#plausibility-decided-92).
10. **An independent tip reference.** In A's verified case, R's priority part comes from B's quotes. The tips paid in Colibri's verified latest block, read with its transactions, would bound it independently. That read is heavier and close to C, which isn't adopted; this is open, not proposed.
