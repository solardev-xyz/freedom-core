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
  - names the response operations main runs on the answer.

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
- **One place for dweb request logic**, shared with mobile and with the Chromium shell (Stage 2), where these handlers become `URLLoaderFactory`s. That logic is URL parsing, CID and host canonicalization, header policy, and retry and timer policy. The response operations depend on the bytes, so they stay in main's existing code, with the same vectors as `fc-dweb`'s copy for Stage 2. The plan is shaped like a URL loader's request, so the Chromium build calls the same logic in process.
- **Parity:** every request makes the same node request as today, with the same headers, retries and status mapping. The [deviations](#deviations) are listed.
- **One hop:** a named subresource costs one core round trip, as on the integration branch today. A hash host costs one new, small round trip, measured before it ships ([Latency](#latency)).
- **The proxy and onion rules:** a non-loopback Ant moves onto the session's network stack, with manual redirects and the onion refusal, which closes #360.

**Non-goals**
- **Content verification (4.5)** and the `window.swarm` backend (4.6): later designs, with prerequisites listed [below](#later-designs).
- **`rad:` and `radapi:`:** these stay as they are until libradicle's service process (4.4). Their responses are whole JSON from the add-on, so planning them gains nothing until blob reads stream.
- **The navigation probe** (`swarm-probe.js`) stays in main. It is a polling flow driven by the chrome, not a request.
- **Caching bytes.** The nodes keep their caches. Whether Chromium caches `protocol.handle` responses is measured, not assumed ([Open questions](#open-questions)).

## The protocol

### `dweb.open`

| Method | Params | Result |
|---|---|---|
| `dweb.open` | `{ url, method, headers, backend, private, deadline_ms, attempts_used? }` | a [plan](#plans), with `generations` and `attempts` |

- **`url`** is the request URL as Chromium hands it to the handler, with the scheme `bzz`, `ipfs` or `ipns`.
- **`method`** is `GET` or `HEAD`, read as today's `(method || 'GET').toUpperCase()`, so `get` and an empty method are GET. Anything else is planned as today's 405.
- **`headers`** are the request's headers as name–value pairs, in order. The core applies the scheme's header policy to them. The IPFS small-text rule is chosen from them as today:
  - repeated `Accept` headers are joined with `", "`;
  - the first comma-separated token is trimmed (JavaScript's `trim`, which also strips no-break spaces and a byte-order mark) and lowercased;
  - it must equal `text/html` exactly. A token that merely starts with `text/html`, such as `text/html;q=0.9`, doesn't count.
- **`backend`** is the node main will use, as a reference with no URL: its mode, and whether it is up.
  - For `bzz:`, `{ ant: "bundled" | "external", up }`.
  - For IPFS, `{ ipfs: "native" | "gateway", up }`.

  The core picks timers and the content label from the mode. A backend that isn't up keeps each scheme's order today, and its mode's text:
  - **For `bzz:`,** the method, path and host checks come first. Then an Ant that isn't up, in either mode, is an immediate 503, "Swarm node is not ready", before any name is resolved.
  - **For IPFS,** canonicalization and the name's result come first: a transport mismatch or missing contenthash is still a 404, and an unsupported codec a 415. Only a plan that would reach the node becomes the 503, as at today's dispatch: "freedom-ipfs node is not running" for the native node, and "external IPFS gateway is not running" for the gateway.
- **Binding:** main captures the backend instance when it admits the request and keeps it, retries included, so a settings change mid-request can't redirect the fetch.
- **`private`** marks a private window's request. The core passes it to naming and never logs the URL.
- **`attempts_used`** is naming's resubmission count (0004), sent again when main re-plans an overtaken plan.
- **Caller kinds:** `shell` only. Pages never reach the core directly.
- **Size:** the request must fit one frame. Main refuses a URL over 64 KiB with 414 and headers over 64 KiB in all with 431, before asking.
- **Thread:** `dweb.open` runs on the naming thread, under naming's admission (0004). A named host is a naming lookup plus planning. A hash host is planning alone, with no I/O.
- **Generations:** the result carries the naming generations and attempts a lookup's result carries (0004).
  - Main's driver fences plans exactly as it fences lookups (freedom-browser #672). A plan is sent and judged only with no naming control in flight. An overtaken plan is planned again with `attempts_used`, within the remaining deadline. A plan is bound to the core process that made it, and a restart re-plans nothing.
  - A plan is used once, immediately; main never caches one.

### Plans

A plan is one of three things:

- **`{ fetch }`:** what main asks the node, and how to treat the answer.

  ```jsonc
  { "fetch": {
      "node": "ant",                       // or "ipfs": a reference, never a URL; the method is the request's own
      "path": "/bzz/<ref>/<path>?<query>", // the node-relative request target
      "headers": [["accept", "…"], ["range", "bytes=0-"], …],
      "retry": { "statuses": [500, 502, 503, 504], "on_error": true, "attempts": 10,
                 "delays_ms": [500, 1000, 2000, 3000, 5000, 5000, 10000, 10000, 15000] },
      "timers": { "queue_ms": null, "headers_ms": 30000, "body_idle_ms": 60000 },
      "response": ["canonicalize_redirect", "strip_page_state"],  // operations main runs, in order
      "trust": { "name": "verified", "content": "node_asserted" } } }
  ```

- **`{ redirect: { status, location, headers } }`:** answered without a node. Today that covers IPFS's gateway-form URLs: a 307 to the canonical `ipfs://` form, with `Access-Control-Allow-Origin: *` as today.
- **`{ error: { status, code, message } }`:** answered without a node, as today's 400, 404, 405, 415 and 502 are, and the 503 of a backend that isn't up.

What the fields mean:

- **`node`** is a reference. Main maps `ant` and `ipfs` to the backend it named in the request, as 0004 maps endpoint references. The core never learns a node's URL (0004 *Secrets*).
- **`retry` and `timers`** are today's values for the scheme and backend:
  - **`bzz:`** makes up to ten attempts, each with 30 s to the response headers, separated by about 50 s of back-off in all.
  - **Native IPFS** has a 15 s queue bound and 30 s to the headers, and no retry.
  - **The external IPFS gateway** has no header timeout, as today, and no retry.
  - **`body_idle_ms`** is new for all of them (deviation `body-idle`, [Main's executor](#main-executes-the-plan)).
- **`response`** names the response operations main runs, in order ([below](#response-operations)). They depend on the bytes, so they stay in main. Plans name today's operations in today's order:
  - Ant: `canonicalize_redirect`, then `strip_page_state`;
  - the external IPFS gateway: `strip_decoded_encoding`, `strip_page_state`, then `canonicalize_redirect`;
  - the native IPFS node: `strip_page_state`, then `small_text` for a GET navigation.

  The security operations aren't optional: main runs them on every response, whatever the plan says.
- **`trust`** carries the name's trust from naming and a **content** label from `backend`, for display only:
  - `node_asserted`: the bundled Ant, which validates the chunks it fetches, and the native IPFS node, which hash-checks blocks;
  - `unverified`: an external Ant, or an IPFS path gateway.

  Nothing fails on these labels. Verification is a [later design](#later-designs).

### What the core decides

All of this is today's behavior, ported with vectors:

- **`bzz:` hosts:**
  - a 64- or 128-hex reference maps to `/bzz/<ref><path><search>`;
  - any other host is a name when `(isDwebNameHost(host) || isPotentialEnsName(host)) && !hasEmptyLabel(host)`, and is resolved through naming, with a published base path joined in:
    - `isDwebNameHost` is a `.eth`, `.box`, `.wei`, `.gwei` or `.tez` suffix, in any case, `.tez` only with no empty label;
    - `isPotentialEnsName` is any dotted host with no empty label and no whitespace, `/:@?#%\` or control character, so `bzz://example.com/` asks ENS;
    - a `.tez` name goes to the Tezos resolver, any other to ENS (`resolveContentName`);
    - anything else is a 400;
  - a contenthash for another transport is a 404, an unsupported codec a 415, and a conflict or error a 502;
  - encoded `/` or `\` in the path is a 400.
- **`bzz:` headers:** today's allowlist (`accept`, `accept-encoding`, `accept-language`, the `if-*` validators, `range`, `user-agent`), plus Swarm's retrieval-timeout and redundancy headers (`30s`, `3`, `true`). `accept-charset` isn't forwarded.
- **`ipfs:` and `ipns:` hosts:**
  - CIDv0 and base58 CIDv1 re-encode to base32;
  - libp2p-key IPNS names re-encode to base36;
  - a host Chromium's parser has already lowercased beyond recovery gets the actionable 400;
  - gateway-form URLs get the canonical 307, or a 400 when no case-safe form exists;
  - name hosts resolve as for `bzz:`, except that under `ipns:` only a dweb name (`isDwebNameHost`) resolves. Any other host that fits IPNS's host pattern (a key or a DNSLink name: up to 253 letters, digits, `.`, `_` and `-`, starting with a letter or digit) goes to the node as `/ipns/<host>`.
- **`ipfs:` headers:** today's strip-list (`host`, `origin`, `referer`, `cookie`, `authorization`, hop-by-hop). The asymmetry with `bzz:`'s allowlist is kept (parity); unifying them is an [open question](#open-questions).
- **The response operations** each scheme needs, and in which order.
- **Errors:** today's statuses and JSON bodies, `{ code, message }`.

### `chain.html` (4.3)

| Method | Params | Result |
|---|---|---|
| `chain.html` | `{ chain_id, contract, origin, deadline_ms }` | `{ html_base64, hash, source, trust, class, generation }` |

- **A request on 0005's machine:** an `eth_call` of `html()` (selector `0x33c34ac3`) at `latest`, interactive for `origin`, as today. The core then checks the answer as today's `onchain-html.js` does, with vectors:
  - the encoded answer may be at most `MAX_HTML_BYTES + 95` bytes before any decode, or the result is 413 (`too_large`). The size is read from the answer's length, `(length - 2) / 2`, before the hex check, so an oversized answer that isn't hex is a 413 too;
  - the ABI string is decoded with ethers' function-result rules, then checked as UTF-8;
  - the decoded document may be at most 8 MiB (413);
  - `hash = keccak256(utf8(html))`.

  This replaces the worker thread and its ethers decode.
- **`html_base64`** carries the document's UTF-8 bytes. Base64 keeps the reply within 0005's message cap at 10.7 MiB, where a JSON string of control characters could grow six-fold.
- **`class`** is a stateless classification. It is the gate's input, not its decision. It reads the router's `trust`, or, when that is missing or falsy, `{ level: verified === true ? "verified" : "unverified", dissented: [] }`, and decides in this order:
  - `trusted`: the level is `verified` or `user-configured`. This is checked first, so a `user-configured` result with dissenters is `trusted`;
  - `conflict`: not trusted, and `dissented` is a non-empty array;
  - `untrusted`: anything else.
- **Main decides, in today's order** (`onchain-app-protocol.js:399-470`):
  1. a GET carrying a staged document's approval token serves that document, consuming the token, with no chain read and no core call;
  2. otherwise main asks `chain.html`;
  3. an exactly approved `(chain, contract, hash)` passes, whatever `class` says;
  4. `trusted` passes;
  5. a HEAD that hasn't passed returns 200 with no body, and stages nothing;
  6. `conflict` gets a 451 with no token;
  7. `untrusted` is staged, and gets a 451 with a token and the interstitial.

  Whether a `verified` quorum with dissenters should still pass is an [open question](#open-questions); `class` keeps today's rule.
- **Errors:** a 413 means only that the document is too large. A deadline or a cancel is 504, as today, `busy` is 503, and other failures are 502. 0005's other bounds don't map to 413.
- **Generations:** results and errors carry the chain's generation. Main fences them with 0005's single resend (0005 *Generations*).
- **Cancellation:** main sends 0001's `cancel` when the navigation aborts, and the chain read stops (deviation `web3-cancel`). Cancelling the plan and cancelling the body that follows are separate things: a `chain.html` result is whole when it arrives.

## Main executes the plan

### Validation before any dial

A plan is input to check, not permission to dial. Main refuses a plan unless it passes the checks for its variant. A refused plan gets a 502 and is logged as a core fault.

The plan is checked as the JSON main receives, against the request main admitted (URL, method, `backend`). The first failing check names the refusal, in this order: `shape`, `method`, `node`, `path`, `header`, `retry`, `timers`, `response`, `trust`, `redirect`, `error`. `fc-dweb`'s `validate_plan` and main's executor pass the same vectors.

- **`shape`:** exactly one of `fetch`, `redirect` and `error`, each with exactly the fields shown in [Plans](#plans). The containers have to be of the right type: a string `path`, `headers` as pairs of strings, an array `response`, and objects for `retry`, `timers` and `trust`.
- **`fetch`:**
  - **`method`:** the request's method, uppercased as above, is GET or HEAD. Main sends that method.
  - **`node`:** names the backend main admitted for the scheme (`ant` for `bzz:`, `ipfs` for `ipfs:` and `ipns:`), and that backend is up.
  - **`path`:** normalized, and in the request's own namespace. That rules out any `..` escape, scheme or authority:
    - the path is unchanged when read back as an HTTP client would send it: dot segments resolved, `\` read as `/`, and the path and query sets percent-encoded;
    - for `bzz:`, `/bzz/<64 or 128 hex>` and below, with no encoded `/` or `\` anywhere before the query (`bzz:`'s rule today, applied to the node's path, published base path included);
    - for `ipfs:`, `/ipfs/<ref>` and below; for `ipns:`, `/ipns/<ref>` and below. The reference is letters, digits, `.`, `_` and `-`;
    - **the path also stays within the namespace once decoded:**
      - decode `%2E`, `%2F` and `%5C`, in any case, in a single pass;
      - read both `/` and `\` as separators;
      - no segment may then be `.` or `..`, so the decoded path stays beneath `/<namespace>/<ref>`.

      A normalized path has no literal dot segments, so any found here come from escapes. An encoded separator that doesn't climb, such as `a%2Fb` in a file name, still passes to the IPFS node as today. The query isn't judged;
    - a base path that changes which IPFS reference is asked can't be told from the path; the namespace can.
  - **`header`:**
    - names are lowercase tokens;
    - values are RFC 9110 field values (section 5.5): visible ASCII, spaces, tabs and `obs-text` (0x80 to 0xFF). No other control character is allowed (C0, including NUL, CR and LF, or DEL), and no space or tab at either end;
    - the names are within the scheme's policy: `bzz:`'s allowlist plus Swarm's three headers, each exactly once at its fixed value; anything off IPFS's strip-list.
  - **`retry`:** within today's values:
    - at most 10 attempts;
    - one delay per retry, each a whole number of milliseconds of at most 15 s;
    - statuses only among 500, 502, 503 and 504, each once;
    - IPFS has no retry: one attempt, no statuses, `on_error` false.
  - **`timers`:** each a positive whole number of milliseconds:
    - a queue bound of at most 15 s, or none;
    - at most 30 s to the headers, which only the external gateway may leave unbounded;
    - a body idle of at most 60 s, never unbounded.
  - **`response`:** each operation known and named once, and one the backend allows:
    - Ant: `canonicalize_redirect` and `strip_page_state`;
    - the native node: `strip_page_state` and `small_text`;
    - the external gateway: all four.
  - **`trust`:** `name` is a string or null, and `content` is the backend's label.
- **`redirect`:** only for `ipfs:` and `ipns:`:
  - the status is 307;
  - the `Location` is exactly the canonical form today's `gatewayFormRedirect` gives the request's URL;
  - the only header is `Access-Control-Allow-Origin: *`.

  A backend that isn't up can still redirect.
- **`error`:** the status is one of today's (400, 404, 405, 415, 502, 503), `code` equals it, and the message is a string of at most 131,072 UTF-16 code units (twice the URL bound).

Validation is stricter than today's dialing (deviation `plan-paths`). Today the handlers dial each of these plans; validation refuses them with a 502:
- **For `bzz:`:**
  - a published base path containing `%2F` or `%5C`: today's rule checks only the request URL's path;
  - a relative base path, which glues onto the reference (`/bzz/<ref>docs/page`);
  - a climbing base path, or a resolver `decoded` of `..`, which leave `/bzz/<ref>`;
  - a resolver `decoded` that isn't a 64- or 128-hex reference at all.
- **For either scheme:**
  - literal-backslash dot segments, such as `bzz://<ref>/a/..\..\..\stamps`, dialled today as `/stamps`, or `ipfs://<cid>/a/..\..\..\ipns\x`, dialled today as `/ipns/x`. Node's URL parser keeps a `\` in a path whose scheme isn't special, and the HTTP client then resolves it;
  - a target outside the request's own namespace, including a resolver `decoded` of `../ipns/…`.
- **For IPFS:** an encoded separator that forms a `.` or `..` segment once decoded, such as `..%2F`, `%2E%2E%2F` or `%2E%2E%5C`, in any case. That holds even when the result would stay beneath the reference, as in `a%2F..%2Fb`. (`bzz:` already refuses any encoded separator.)

Pages can't produce the backslash forms, because Chromium canonicalizes standard-scheme URLs first.

Field values are stricter than `Headers` too (deviation `plan-headers`). A request header whose value holds a control character other than an interior tab, such as a vertical tab in `Accept`, is passed on today; validation refuses the plan with a 502.

### Transport

- **A loopback Ant**, bundled or external, is dialled with undici as today. It needs no proxy, and the dial stays outside the session's `webRequest`.
- **A non-loopback Ant** (deviation `transport`, #360) is dialled with `net.request` on the request's session, with the properties `ipfs/gateway-transport.js` already gives the external IPFS gateway:
  - `redirect: "manual"`, so a 3xx comes back and is never followed in main;
  - the onion refusal before dialling when `resolveProxy` would fall back to DIRECT;
  - credentials omitted, a `no-store` cache mode and no custom handlers.

  `net.fetch` can't do this: it follows redirects, or rejects a manual one, and it always uses the default session.
- **The Ant API guard** stays. A frameless dial to the configured Ant is cancelled unless announced (`ant-api-guard.js`). Main announces exactly this content dial, as `ens-prefetch.js` does, and releases it on every terminal path. The node's origin isn't exempted, and neither is frameless traffic.
- **The `web3:` and `radapi:` frame guards** are unchanged.
- **IPFS keeps its dispatch:** the native node's pull reads with real backpressure, or the external gateway through `gatewayFetch`.
- **Logging:** main keeps the private-window log context (`runWithPrivateLogContext`) around the whole execution.

### Response operations

These stay in main, because they depend on the bytes. Each is today's code.

**Always run,** whatever the plan names:
- **`strip_page_state`** (O-12): removes `Set-Cookie`, `Set-Cookie2` and `Service-Worker-Allowed` from every dweb response. Today the native IPFS node's answers pass unstripped (deviation `native-page-state`).
- **`strip_decoded_encoding`**, for every response from the external IPFS gateway: removes the decoded body's `content-encoding` and `content-length` and the hop-by-hop headers.

**Run when the plan names them:**
- **`canonicalize_redirect`** (`lib/gateway-location.js`): rewrites a gateway-space `Location` relative to the gateway request's directory, comparing decoded path segments, and leaves cross-origin and up-directory `Location`s untouched (#95).
  - **Ant:** only a 301, 302, 303, 307 or 308 is rewritten. On a rewrite, `bzz:` cancels and drops the body and removes the length and encoding headers.
  - **The external gateway:** any 3xx is rewritten in place, and the body is kept.
  - **The native node:** today its redirects pass as they are, so its plans don't name the operation.
- **`small_text`** (IPFS navigations only). Plans name it only for the native node. On the external gateway it never fires today, because `ipfs-manager.js` drops `Content-Length` before the rule reads it. It relabels a body as `text/plain` with `nosniff` only when all of these hold:
  - the request is a GET and the status 200;
  - the parsed media type is exactly `application/octet-stream`: the first `;`-separated part, trimmed and lowercased;
  - there is no `X-Content-Type-Options` header at all, no `Content-Disposition` and no `Content-Range` response header;
  - a body is present, with an integer declared length between 1 and 4096 bytes that matches the body at EOF:
    - the length is `Number()`'s reading of the `Content-Length` value, so `0x2`, `2.0`, `2e0` and ` 2 ` all count as 2;
    - a missing header reads as 0;
  - the body is valid UTF-8, without control characters other than tab, line feed, form feed and carriage return.

  Otherwise the buffered bytes are replayed intact.
  - **Its buffer:** the sniff reads until it has more than 4096 bytes or EOF. It holds at most 4 KiB plus one upstream chunk (64 KiB from the native node), because a lying length can deliver a whole chunk at once. Every byte is replayed.
  - **Vectors:** they cover the oversized chunk and the wrong length.

**Unchanged:** statuses with no body, and `206`, `416` and `If-Range`, which pass through as received.

`fc-dweb` carries the same operations with the same vectors, for Stage 2 and mobile. In Electron, main's existing code runs them.

### Deadlines, cancel and bounds

- **Retry:** the retry loop and its back-off stop when the page's signal aborts, as today. A retried attempt's body is cancelled before the next attempt.
- **Body idle (deviation `body-idle`).** Main wraps the body in a `ReadableStream` with `highWaterMark: 0`, so `pull` means a consumer is waiting.
  - **The clock** runs only while Chromium has asked for bytes and none have come. A paused video, which asks for nothing, is never cut off.
  - **On expiry,** a body that leaves a pending read unanswered for 60 s fails as a truncated resource (`controller.error`), and the upstream is aborted and freed.
- **Admission in main:**
  - at most 256 active dweb fetches across sessions, and 512 waiting;
  - a request beyond that gets 503 at once;
  - each fetch owns its node handle, its sniff buffer (at most 4 KiB plus one upstream chunk) and its retry state, and frees them on every terminal path: done, error, cancel, or the session closing;
  - a plan is checked against the generations once more after any wait in main's queue, so a plan that waited is never used stale.
- **Local failures map to HTTP:** `busy` → 503, `deadline` → 504, `too_large` → 414 or 431 as above, and a refused plan → 502.
- **Readiness keeps each scheme's order** (`backend` with `up: false`):
  - **For `bzz:`,** the method, path and host checks come first, so a POST is still a 405 and an encoded separator in a `bzz:` path still a 400 with Ant down. Then an Ant that isn't up, in either mode, is an immediate 503, before any name is resolved.
  - **For IPFS,** the name's result comes first, and only a plan bound for the node gets the 503, with its mode's text. A gateway-form URL still gets its 307.

### Other callers

- **Through the handlers:** `http-fetch.js` ("save image"), downloads, and `permission-manifests.js`, which calls the `bzz:` handler in process and passes its session and private context explicitly.
- **Not through the handlers:** `ens-prefetch.js` warms Ant by calling `gatewayFetch` directly. It keeps its own transport and guard announcement, unchanged by this design.

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
| a `dweb.open` request | one frame; URL ≤ 64 KiB, headers ≤ 64 KiB | 414 / 431 in main, before asking |
| per-request state in the core | none after the plan | — |
| active / waiting dweb fetches (main) | 256 / 512 | 503 at once |
| sniff buffer (main) | 4 KiB plus one upstream chunk per fetch | the body is replayed intact |
| body idle (main) | 60 s with a read pending | the body errors as truncated |
| `chain.html` | 0005's bounds; encoded ≤ `MAX_HTML_BYTES + 95`, document ≤ 8 MiB | 413 for size only |

## Deviations

| ID | Today | After | Effect |
|---|---|---|---|
| `transport` | a non-loopback Ant through undici, outside the session | `net.request` on the request's session, with manual redirects and the onion refusal | an external `.onion` Ant follows the proxy and onion gate (#360) |
| `body-idle` | no body idle timeout | 60 s with a read pending; paused streams untouched | a stalled body fails as truncated instead of hanging |
| `fetch-admission` | unbounded | 256 active, 512 waiting | 503 under extreme load |
| `web3-cancel` | an aborted navigation leaves the chain read running | `cancel` reaches it | |
| `web3-decode` | ethers in a worker | the core | the same document, hash and 413s; the worker goes |
| `hash-host-hop` | hash hosts need no lookup | one planning round trip | measured ([Latency](#latency)) |
| `native-page-state` | the native IPFS node's answers pass with `Set-Cookie`, `Set-Cookie2` and `Service-Worker-Allowed` | stripped, as from Ant and the external gateway | the native node can't set cookies or widen a service worker's scope on the `ipfs://` origin |
| `plan-paths` | dialled: a `bzz:` published base path with an encoded separator, a relative one, or a climbing one; a `bzz:` resolver `decoded` that isn't a 64- or 128-hex reference, `..` included; literal-backslash dot segments; a target outside the request's own namespace, such as a `decoded` of `../ipns/…`; an IPFS path with an encoded separator that forms a `.` or `..` segment once decoded ([Validation](#validation-before-any-dial)) | refused by validation, which judges the path as decoded too | such plans get 502 where today they are dialled. Pages can't produce the backslash forms, because Chromium canonicalizes standard-scheme URLs first |
| `plan-headers` | a header value with a control character other than an interior tab, which `Headers` accepts, is passed on | refused by validation (RFC 9110 field values) | such plans get 502 where today the header is sent |

## Implementation steps

1. **Tests first (4.7):** the real-handler harness and Range, cancel and backpressure cases, in freedom-browser.
2. **`fc-dweb` and vectors:**
   - the URL and host canonicalization for `bzz:`, `ipfs:` and `ipns:`;
   - the header policies;
   - the retry and deadline tables;
   - the response operations (redirect canonicalization, header stripping, small text), pinned by vectors that main's existing code also passes;
   - the status mapping;
   - the `html()` precheck, decode, caps, hash and classification;
   - byte parity with the pinned JS.
3. **`freedom-cored`:** `dweb.open` on the naming thread, and `chain.html` on 0005's machine (after 0005's machine lands).
4. **freedom-browser:**
   - the handlers validate and execute plans, under the naming driver's fence;
   - a non-loopback Ant moves onto the session stack, with the guard's announcement;
   - the body idle timeout and the fetch admission;
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
