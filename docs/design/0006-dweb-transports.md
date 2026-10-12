# 0006: Dweb transports

**Status:** proposed. Roadmap Phase 4 (items 4.1–4.7). Builds on [0001](0001-freedom-cored.md) (process, framing, crash domain), [0004](0004-naming-sessions.md) (naming, `shell.*`, endpoint references, secrets) and [0005](0005-chain-data.md) (chain data, fragmented responses).

**The reference** is freedom-browser at `fb540328`:
- the protocol handlers `swarm/bzz-protocol.js`, `ipfs/ipfs-protocol.js`, `radicle/rad-protocol.js`, `radicle-api-protocol.js` and `onchain/onchain-app-protocol.js`;
- their helpers `content-name-resolver.js`, `lib/gateway-location.js` and `lib/gateway-response-headers.js`;
- the nodes behind them: `ant-manager.js`, `ipfs/freedom-ipfs-native-node.js` and `radicle-embedded.js`.

Vectors are generated from these files, as for 0003–0005.

## Summary

Freedom serves six custom schemes: `bzz`, `ipfs`, `ipns`, `rad`, `radapi` and `web3`. Each is a `protocol.handle` handler in Electron main. Today they hold the request logic and the trust gates, and in two cases a whole P2P node inside main's own process.

This design settles where each part goes:

- **The core plans, main moves the bytes.** For `bzz:`, `ipfs:` and `ipns:`, one call, `dweb.open`, does the following and returns a **plan**:
  - parses and canonicalizes the URL;
  - resolves a name host;
  - picks the node;
  - fixes the request's headers, retries and deadlines;
  - says how to transform the response head.

  Main executes the plan with its fetchers and streams the body to Chromium. The core keeps no state per request once the plan is returned.
- **Why not bytes through the core:**
  - The core opens no sockets (0003, 0004, 0005). Relaying bodies would copy every byte through the pipe twice and need Phase 4's streams.
  - A core restart, which also locks the vault, would cut every video and download.
  - Today nothing in the core would check those bytes. Relaying them buys nothing until the core verifies content, which gets its own design ([Later designs](#later-designs)).
- **`web3:`** becomes `chain.html` on 0005's machine:
  - the core makes the `html()` call, decodes and caps the document, hashes it, and decides the gate;
  - main keeps the interstitial and the approvals;
  - an aborted navigation now cancels the read.
- **The P2P nodes leave main, but not into the core.** freedom-ipfs (4.2) and libradicle (4.4) become their own supervised service processes, as Myotis did.
  - Putting libp2p or heartwood inside `freedom-cored` would let a transport panic lock the vault. It would also break the core's no-`unsafe` and no-panic rules.
  - Each service gets its own design.
- **Tests come first.** Range and 206 behavior, cancellation and backpressure are barely tested today (4.7). A real-handler harness, with a fake node and Range cases, lands before any handler moves.

## Goals and non-goals

**Goals**
- **One place for dweb request logic**, shared with mobile and with the Chromium shell (Stage 2), where these handlers become `URLLoaderFactory`s. That logic is URL parsing, CID and host canonicalization, header policy, retry policy and response-head transforms. The plan is shaped like a URL loader's request, so the Chromium build calls the same logic in process.
- **Parity:** every request makes the same node request as today, with the same headers, retries and status mapping. The [deviations](#deviations) are listed.
- **One hop:** a named subresource costs one core round trip, as on the integration branch today. A hash host costs one new, small round trip, measured before it ships ([Latency](#latency)).
- **The proxy and onion rules:** `bzz:` moves onto the session's network stack, which closes #360.

**Non-goals**
- **Content verification (4.5)** and the `window.swarm` backend (4.6): later designs, with prerequisites listed [below](#later-designs).
- **`rad:` and `radapi:`:** these stay as they are until libradicle's service process (4.4). Their responses are whole JSON from the add-on, so planning them gains nothing until blob reads stream.
- **The navigation probe** (`swarm-probe.js`) stays in main. It is a polling flow driven by the chrome, not a request.
- **Caching bytes.** The nodes keep their caches. Whether Chromium caches `protocol.handle` responses is measured, not assumed ([Open questions](#open-questions)).

## The protocol

### `dweb.open`

| Method | Params | Result |
|---|---|---|
| `dweb.open` | `{ url, method, headers, navigation, private, deadline_ms }` | a [plan](#plans) |

- **`url`** is the request URL as Chromium hands it to the handler, with the scheme `bzz`, `ipfs` or `ipns`.
- **`method`** is `GET` or `HEAD`; anything else is planned as today's 405.
- **`headers`** are the request's headers as name–value pairs, in order. The core applies the scheme's header policy to them.
- **`navigation`** is true for a main-frame document request, identified as today by `Accept` starting with `text/html`. It selects IPFS's small-text rule.
- **`private`** marks a private window's request. The core passes it to naming and never logs the URL.
- **Caller kinds:** `shell` only. Pages never reach the core directly.
- **Thread:** `dweb.open` runs on the naming thread, under naming's admission (0004). A named host is a naming lookup plus planning. A hash host is planning alone, with no I/O.

### Plans

A plan is one of three things:

- **`{ fetch }`:** what main asks the node, and how to treat the answer.

  ```jsonc
  { "fetch": {
      "node": "ant",                       // or "ipfs"
      "path": "/bzz/<ref>/<path>?<query>", // the node-relative request target
      "headers": [["accept", "…"], ["range", "bytes=0-"], …],
      "retry": { "statuses": [500, 502, 503, 504], "on_error": true,
                 "delays_ms": [500, 1000, 2000, 3000, 5000, 5000, 10000, 10000, 15000] },
      "deadline": { "headers_ms": 30000, "body_idle_ms": 60000 },
      "head": { "redirect_base": "/bzz/<ref>", "strip": ["set-cookie", "set-cookie2", "service-worker-allowed"],
                "small_text": false },
      "trust": { "name": "verified", "content": "node_asserted" } } }
  ```

- **`{ redirect: { status, location } }`:** answered without a node. Today that covers IPFS's gateway-form URLs, which get a 307 to the canonical `ipfs://` form.
- **`{ error: { status, code, message } }`:** answered without a node, as today's 400, 404, 405, 415 and 502 are.

What the fields mean:

- **`node`** is a reference, not an address. Main maps `ant` and `ipfs` to the configured Ant API URL and to the native IPFS node or the external gateway, as 0004 maps endpoint references. The core never learns a node's URL (0004 *Secrets*).
- **Readiness stays in main:** a node that isn't up answers today's immediate 503 ("Swarm node is not ready"), and the core needn't track node state.
- **`retry` and `deadline`** are today's values per scheme: `bzz:` retries for about 50 s, and IPFS doesn't retry.
  - `headers_ms` counts to the response headers, as today.
  - **`body_idle_ms`** is new (deviation `body-idle`). A body that delivers nothing for 60 s fails as a truncated resource, where today it can hang forever.
- **`head`** lists the response-head transforms main applies, mechanically:
  - rewriting gateway-space `Location`s relative to `redirect_base` (#95);
  - stripping the page-state headers (O-12);
  - IPFS's small-text relabelling for navigations.

  They are data, so main's applier is a few lines and its vectors come from `fc-dweb`.
- **`trust`** carries the name's trust from naming, and a **content** label, for display only:
  - `node_asserted`: the bundled Ant, which validates the chunks it fetches, and the native IPFS node, which hash-checks blocks;
  - `unverified`: an external Ant, or an IPFS path gateway.

  Nothing fails on these labels. Verification is a [later design](#later-designs).

### What the core decides

All of this is today's behavior, ported with vectors:

- **`bzz:` hosts:**
  - a 64- or 128-hex reference maps to `/bzz/<ref><path><search>`;
  - a name host (`.eth`, `.wei`, `.gwei`, `.tez`) is resolved through naming, with a published base path joined in;
  - a contenthash for another transport is a 404, an unsupported codec a 415, and a conflict or error a 502;
  - encoded `/` or `\` in the path is a 400.
- **`bzz:` headers:** today's allowlist (`accept*`, the `if-*` validators, `range`, `user-agent`), plus Swarm's retrieval-timeout and redundancy headers.
- **`ipfs:` and `ipns:` hosts:**
  - CIDv0 and base58 CIDv1 re-encode to base32;
  - libp2p-key IPNS names re-encode to base36;
  - a host Chromium's parser has already lowercased beyond recovery gets the actionable 400;
  - gateway-form URLs get the canonical 307, or a 400 when no case-safe form exists;
  - name hosts resolve as for `bzz:`.
- **`ipfs:` headers:** today's strip-list (`host`, `origin`, `referer`, `cookie`, `authorization`, hop-by-hop). The asymmetry with `bzz:`'s allowlist is kept (parity); unifying them is an [open question](#open-questions).
- **Errors:** today's statuses and JSON bodies, `{ code, message }`.

### `chain.html` (4.3)

| Method | Params | Result |
|---|---|---|
| `chain.html` | `{ chain_id, contract, origin, deadline_ms }` | `{ html_base64, hash, source, trust, gate }` |

- **A request on 0005's machine:** an `eth_call` of `html()` (selector `0x33c34ac3`) at `latest`, interactive for `origin`, as today. The core:
  - decodes the ABI string;
  - checks UTF-8;
  - applies the 8 MiB cap: 413 when exceeded;
  - computes `hash = keccak256(utf8(html))`.

  This replaces the worker thread and its ethers decode.
- **`html_base64`** carries the document's UTF-8 bytes. Base64 keeps the reply within 0005's message cap at 10.7 MiB, where a JSON string of control characters could grow six-fold.
- **`gate`** is today's decision, made in the core:
  - **`pass`:** the trust is `verified` or `user-configured`;
  - **`conflict`:** the quorum had dissenters and the trust isn't `verified`. It gets no approval token;
  - **`stage`:** anything else.

  Whether a `verified` quorum with dissenters should still pass is an [open question](#open-questions); the core keeps today's rule.
- **Main keeps** the staged documents, the session's approvals, the 451 and its interstitial, the CSP and the response headers. They all need `webContents` or the session.
- **Cancellation:** main sends 0001's `cancel` when the navigation aborts. Today the chain read runs on (deviation `web3-cancel`).

## Main's executor

- **`bzz:` uses the session's network stack** (`net.fetch` on the request's session) instead of Node's undici (deviation `transport`). An external Ant on a `.onion` host then follows the proxy and the onion gate (#360), as 0004 and 0005 do for RPC. A loopback Ant connects directly, as today.
- **IPFS keeps its dispatch:** the native node's pull reads with real backpressure, or the external gateway through `net.request`.
- **Main applies the plan:**
  - it sends the node request with the plan's headers;
  - it retries and enforces deadlines as the plan says;
  - it transforms the response head;
  - it streams the body as today, cancelling on the page's signal.
- **Hash hosts:** main may plan a hash host locally only if the measurements require it ([Latency](#latency)), and then only with logic generated from the same vectors.
- **Other callers keep working through the handlers:** `http-fetch.js` ("save image"), downloads, `permission-manifests.js` (which calls the `bzz:` handler in process) and `ens-prefetch.js`.

## Latency

- **A named host** costs what it does today on the integration branch: one core round trip. Measured: p50 1.6 ms and p99 3.0 ms at 50 concurrent cache hits, and at most 6.5 ms under 16 KDFs (0004's fan-out measurement). `dweb.open` makes resolution and planning one call, so it adds no second hop.
- **A hash host** gains a round trip with no I/O behind it.
- **The measurement**, before step 4 ships:
  - time to first byte at 50 and 200 concurrent requests, for hash and named hosts, and for 1 KB, 100 KB and 10 MB bodies and a video seek;
  - planned versus today.

  If hash hosts regress noticeably, main plans them locally from the same vectors (above).

## Service processes (4.2, 4.4)

freedom-ipfs and libradicle run inside Electron main today. Any Rust panic in either kills the browser, nothing restarts them, and neither honors a proxy. Each moves to **its own supervised process**, following Myotis:

- **Owner and boundary:**
  - main supervises it, with restart and back-off;
  - one process owns a data directory, closing it before reopening;
  - a small IPC surface: `start`, `stop`, `request` (head, then body in chunks with backpressure), `cancel` and `stats`.
- **The binary:** a Rust service binary linking the upstream crates, rather than the N-API shims. That removes raw-pointer handles and `napi_throw` aborts.
- **Not in `freedom-cored`:**
  - the core's crash domain is the vault (0001: a core restart locks it);
  - its rules forbid `unsafe` and panics;
  - libp2p, tokio and heartwood bring both.

  The core may later verify their output ([Later designs](#later-designs)); it never hosts them.
- **Policy at start:**
  - the proxy and onion configuration, as a new capability for both;
  - an ephemeral node, or a cache partition, for private windows, which today share the persistent IPFS cache;
  - for libradicle, a new blob API returning raw, chunked or ranged bytes, since today's binaries are dropped and text is decoded lossily.
- **Each gets its own design,** written against the pinned upstream source: freedom-ipfs v0.4.5 and libradicle v0.8.0. The research read older sources.

## Tests first (4.7)

Before step 4 moves a handler:

- **A real-handler harness:** the e2e stubs replace the handlers today and ignore Range. The harness runs the real `bzz:` and `ipfs:` handlers against a fake Ant and a fake gateway that serve 200, 206, 416, `If-Range` and redirects.
- **Cases:**
  - Range with `206` and `Content-Range` passing through;
  - `If-Range`;
  - a cancel during a body;
  - backpressure: a slow reader doesn't buffer the whole body;
  - a mid-body error becoming a truncated resource;
  - the retry loop's cancel;
  - the head transforms.
- **Media:** a Chromium video seek test, which issues bursts of cancel and re-request, and a download resumed by Range.
- **Live:** a Range case in the `e2e-ant` job.

## Bounds

| Budget | Bound | Exhausted |
|---|---|---|
| `dweb.open` admission | naming's (0004) | `busy`: main answers 503 |
| per-request state in the core | none after the plan | — |
| body idle (main) | 60 s | the body errors as truncated |
| `chain.html` | 0005's bounds; the document ≤ 8 MiB | 413 |

## Deviations

| ID | Today | After | Effect |
|---|---|---|---|
| `transport` | `bzz:` through undici, outside the session | the session's stack | an external `.onion` Ant follows the proxy and onion gate (#360) |
| `body-idle` | no body idle timeout | 60 s | a stalled body fails as truncated instead of hanging |
| `web3-cancel` | an aborted navigation leaves the chain read running | `cancel` reaches it | |
| `web3-decode` | ethers in a worker | the core | same document, same hash; the worker goes |
| `hash-host-hop` | hash hosts need no lookup | one planning round trip | measured ([Latency](#latency)) |

## Implementation steps

1. **Tests first (4.7):** the real-handler harness and Range, cancel and backpressure cases, in freedom-browser.
2. **`fc-dweb` and vectors:**
   - the URL and host canonicalization for `bzz:`, `ipfs:` and `ipns:`;
   - the header policies;
   - the retry and deadline tables;
   - the response-head transforms (redirect canonicalization, header stripping, small text);
   - the status mapping;
   - the `html()` decode, cap and hash;
   - byte parity with the pinned JS.
3. **`freedom-cored`:** `dweb.open` on the naming thread, and `chain.html` on 0005's machine (after 0005's machine lands).
4. **freedom-browser:**
   - the handlers execute plans;
   - `bzz:` moves onto the session stack;
   - the body idle timeout;
   - `web3:` uses `chain.html`, with cancel;
   - the latency measurement.
5. **Service processes:** the freedom-ipfs and libradicle designs, then their binaries.

## Later designs

- **Content verification (4.5).**
  - **Its point:** an external or remote Ant, or an IPFS path gateway, is trusted blindly today.
  - **What it needs:**
    - bytes through a verifier, so Phase 4 streams (0001's protocol version 2: stream IDs, per-stream and global credit, an aggregate memory bound);
    - `fc-swarm` gaining CAC and SOC validation (accepting the empty chunk, which `bmt_root` refuses today), a joiner and mantaray, from Ant's Apache-2.0 crates where possible;
    - `fc-evm` gaining signature recovery;
    - for IPFS, trustless gateway formats (`application/vnd.ipld.raw`, `car`) and freedom-ipfs's I/O-free `-core` and `-unixfs` crates;
    - a "node-asserted latest" label for feed heads, which can't be proven.
  - **Its cost:** verifying a `bzz:` page through Ant's HTTP API takes about 256 chunk requests per MiB. Ant would have to offer a batch or proof-carrying endpoint first.
- **The `window.swarm` backend (4.6):** about 6.7k lines today, using bee-js with no timeouts or cancellation.
  - **What it needs:** decisions on who owns `feed-store.json` and the Swarm permissions; streaming for publish payloads of up to 50 MB; and keeping everything bound to `webContents` (prompts, subscriptions, navigation epochs) in main.

## Open questions

1. **Hash hosts:** plan them in main from the generated logic if the hop measures badly, or accept the hop?
2. **Chromium's cache:** does it store `protocol.handle` responses that carry `Cache-Control: immutable`? If not, every revisit asks the node again, and a core-side cache of immutable content might pay for itself.
3. **Header policy:** unify `bzz:`'s allowlist and `ipfs:`'s strip-list, or keep the asymmetry?
4. **The `web3:` gate:** should a `verified` quorum with dissenters still pass without the interstitial?
5. **Content trust in the chrome:** where are `node_asserted` and `unverified` shown?
6. **Private windows and IPFS:** an ephemeral node per private window, or one cache partition for all of them?
