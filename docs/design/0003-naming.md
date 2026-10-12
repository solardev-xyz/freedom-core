# 0003: Naming in the core (Phase 3)

**Status:** proposed. Builds on [0001](0001-freedom-cored.md) and [0002](0002-signing.md). Covers roadmap items 1.2 (the naming codec) and 3.2 (resolution) for desktop; mobile links the same crate later.

## Summary

Freedom resolves names in Electron main today. At freedom-browser `fb540328`:

| Module | Lines | Does |
|---|---|---|
| `src/main/ens-resolver.js` | 2,856 | ENS, WNS (`.wei`) and GNS (`.gwei`): content, `addr` and reverse; the quorum, Myotis, Colibri and direct paths; trust labels; caches; IPC |
| `src/main/tezos-domains-resolver.js` | 684 | `.tez`: Tezos RPC quorum, Micheline decoding, `ScriptExpr` hashing |
| `src/main/ens/ccip-fetch.js` | 177 | EIP-3668 gateway fetches and their URL policy |
| `src/shared/cid-utils.js`, `src/shared/blake2b.js` | 344 | CID encodings, BLAKE2b |

iOS (~5,600 lines of Swift) and Android (~6,300 lines of Kotlin) implement the same logic again, and the three platforms already disagree on trust levels.

This design moves naming into a new logic crate, `fc-naming`, which `freedom-cored` serves as `naming.*` methods:

- **Codecs:** ENSIP-15 normalization, namehash and DNS encoding, the Universal Resolver ABI, contenthash, CCIP-Read, and the Tezos encodings.
- **Resolution:** a sans-I/O state machine. It decides every request a resolution needs, main performs each one and hands back the answer, and the core still opens no sockets (0001).

**What changes for users:** the resolver's JSON-RPC calls and CCIP gateway fetches go through the Electron session's network stack, so the session's proxy applies to them. Today ethers' `JsonRpcProvider` sends JSON-RPC through Node's own HTTP stack, outside the session. Colibri's prover traffic (its workers' own `fetch`) and Myotis' peer-to-peer networking don't change here; bridging them is roadmap 3.3.

Everything else is parity with today's desktop resolver for the same network answers: the same results, trust objects, errors and cache lifetimes. Golden vectors from the pinned JS check this, and the [deviations](#deviations-from-the-js) are listed.

## Goals and non-goals

**Goals**
- **One implementation:** desktop now, mobile later through `freedom-mobile-ffi`.
- **Parity** with `ens-resolver.js` and `tezos-domains-resolver.js` at the pinned commit, down to the [result schemas](#result-schemas). Deviations are listed, each with a vector.
- **Bounded work:** every loop, buffer, cache and session has a limit, and the limits add up to a fixed total (see [Budgets](#budgets)), so a hostile endpoint or gateway can neither stall the core nor grow it.
- **No secrets in the core's naming state:** endpoint URLs, which can carry API keys, stay in main. The core sees opaque endpoint references.

**Non-goals**
- **New trust semantics.** Today a quorum agreement is labelled `verified` although it is corroboration, not proof. Android has no `user-configured` level, and iOS adds `anchorDisagreement`. Unifying the platforms is a product decision (roadmap 3.1). This design keeps desktop's semantics exactly; see [Open questions](#open-questions).
- **New record types:** text records, avatars, non-EVM coin types.
- **`chain-data-router.js`** (roadmap 3.4), and the process and network model of Myotis and Colibri (roadmap 3.3). The resolver uses them as transports, through their adapters in main, which keep their retry and client-retention logic.
- **Policy for page access to naming.** As today, names are resolved for the browser chrome and for main's protocol handlers.

## Crate layout

`fc-naming` is a logic crate. It has no I/O, no clock and no randomness of its own: time and randomness come in as parameters and traits, and `freedom-cored` provides them. It compiles for iOS and Android.

| Module | Contents |
|---|---|
| `normalize` | ENSIP-15 through the `ens-normalize` crate; JavaScript's `trim`; Tezos' trim-and-lowercase, with its own 255-code-unit limit (ENSIP-15 never applies to Tezos) |
| `ens` | namehash, `dns_encode` (labels up to 255 bytes, on the Universal Resolver path only; NameNFT calls use the namehash), ENSIP-11 coin types |
| `abi` | the shapes naming decodes, with ethers v6's strict rules: whole-decode failures versus per-field errors that fail only when the field is read, offsets relative to their tuple, unchecked padding, the 1,024× read cap |
| `ur` | Universal Resolver and NameNFT calls, `decodeFunctionResult`'s whole-word rule, revert classification, `OffchainLookup`, callbacks, `ReverseAddressMismatch`, the reverse-outcome codec, name systems by suffix |
| `contenthash` | the decoder and CID encodings, quirks included (CIDv0 kept, the multihash code unchecked, JavaScript's 32-bit varint arithmetic) |
| `ccip` | URL expansion, the gateway policy, POST bodies, answer parsing (lossy UTF-8, then JSON, then `isHexData`) |
| `tezos` | BLAKE2b, base58check, `ScriptExpr`, Micheline decoding, published-URI parsing |
| `trust` | anchors, agreement, conflict groups, trust objects, TTLs, the method policy |
| `machine` | the ENS and Tezos resolution state machines |

**New dependencies:**
- `ens-normalize` 0.1.1 (MIT; only `serde` and `serde_json`): a Rust port of the reference normalizer, built from the same spec data as the JS library Freedom ships (spec 1.11.1, Unicode 17.0.0, CLDR 47). It passes all 38,614 upstream validation cases, and so does the shipped JS library; two independent runs found no mismatch. It is pinned exactly, and CI keeps that corpus as a test. Its only panic sites are the parse of its embedded data at first use and guarded internal lookups; the corpus run exercises them all.
- `url` (WHATWG URL parsing, as Node and Chromium do it), `blake2`, `sha2` (base58check), `serde_json`.

All go through `cargo deny`.

## Sessions and I/O

A resolution is a **session** in the core. Main starts it with `naming.resolve`; the core answers with the I/O it needs, or with the result at once if the result is cached. Main performs the I/O and returns the answers with `naming.continue`; the core answers with more I/O, or with the result.

```
main                                            core
naming.resolve {kind:"content", name}    ──▶    anchor: heads from every available endpoint
                                         ◀──    {session, io:[head e1, head e2, head e3, head e4]}
naming.continue {session, responses:[e1, e3]}
                                         ◀──    {io:[], cancel:[]}             (waits for all heads to settle)
naming.continue {session, responses:[e2, e4]}
                                         ◀──    {io:[hash@N e1 … e4]}          (median head N + 8 back)
…                                                quorum leg: K calls pinned at the anchor
naming.continue {…}                      ◀──    {result:{type:"ok", …}, cancel:[remaining legs]}
```

### I/O requests and answers

Each I/O request has an `id`, unique within its session, and a `deadline_ms` (today's timeout for that request). Every answer names the request's `id`.

| Kind | Request | Answers |
|---|---|---|
| `rpc` (ENS JSON-RPC) | `{ endpoint, method, params }`: `eth_blockNumber`, `eth_getBlockByNumber`, `eth_call` (with a block tag or hash) | `{ result }` · `{ rpc_error: { code, message, data? } }` (the JSON-RPC error object, `message` cut to 1 KiB) · `{ transport: reason }` |
| `http` (Tezos RPC) | `{ endpoint, method: GET\|POST, path, body? }` | `{ status, body }` (body base64) · `{ transport: reason }` |
| `verified_call` | `{ via: "myotis"\|"colibri", to, data }`, always at `latest` | `{ data, meta }` · `{ revert: data }` · `{ failed: class }` |
| `gateway` | `{ url, method, body? }`, built and checked by the core | `{ status, body }` (base64) · `{ transport: reason }` |
| `prefetch` | `{ uri }`: warm the gateway for a first answer | none; the core sends it in `cancel` when the answer loses |

- **`transport` reasons:** `timeout`, `too_large`, `network`, `refused` (the onion gate, below), `aborted`.
- **`verified_call` metadata:**
  - Myotis: `{ finality: "finalized"|"optimistic", block_number: number|null }`.
  - Colibri: `{ prover: endpoint, zk_proof: bool }`, as in effect for that call.
- **`verified_call` failure classes:** `unavailable`, `lifecycle_changed` (Myotis started or stopped mid-call: today's `MYOTIS_LIFECYCLE_CHANGED`), `proof_failed`, `error`. A verified **revert** is not a failure: an `OffchainLookup` or `ResolverNotFound` revert proven by the verifier is answered as `{ revert }`, and the core continues from it, CCIP included.
- **CCIP stays on its path.** Every callback goes to the verifier, or the endpoint and pinned block, that produced the `OffchainLookup`. ethers no longer drives CCIP anywhere: main makes raw calls with CCIP disabled.
- **Errors as ethers saw them.** The JS classifies a failed call from ethers' error object: its revert data, and the error names inside its message. The core gets the raw JSON-RPC error and applies ethers v6's extraction rules to it: where the revert data is found, and what text the message would carry from the endpoint. The vectors pin the result.
- **Main's transport duties are unchanged from today**, and apply to every request it performs for the resolver:
  - timeouts: 5 s for JSON-RPC legs, 8 s for Tezos, 15 s per gateway;
  - the response caps below;
  - no redirects for gateways; no credentials and no HTTP cache for gateway fetches; private-log protections;
  - **the onion gate:** a `.onion` host, for an RPC endpoint as much as for a gateway, is dialled only when the session proxies it (no empty or `DIRECT` route, and no `DIRECT` fallback). Otherwise the answer is `{ transport: "refused" }`.

### Frames and sizes

0001 caps a frame at 1 MiB, and naming fits inside it without chunking, because each answer is capped:

| Answer | Cap | Today |
|---|---|---|
| ENS JSON-RPC response body | 64 KiB | unbounded |
| Tezos RPC response body | 512 KiB | 5 MB |
| Gateway response body | 256 KiB | 4 MB |
| `verified_call` return data | 64 KiB | unbounded |

Real answers are far smaller:
- a Universal Resolver answer is a few hundred bytes, and a block header 1 to 3 KB;
- the largest Tezos answer is a registry contract's script, 22 to 42 KB at the time of writing;
- CCIP gateway answers are a few KB.

These caps bound everything derived from them:
- an `OffchainLookup`'s data, and so a GET URL and a POST body;
- a callback call;
- a conflict result's groups: at most 9 legs × 64 KiB.

Main sends one answer per `naming.continue` whenever a batch wouldn't fit a frame. The core never emits an I/O request or a result larger than 768 KiB encoded. Anything bigger fails its step the way an oversized answer does.

### Ownership

- **One session per query.** Main deduplicates concurrent identical queries, as the JS does with its in-flight map. The core never shares I/O between sessions, so every answer has exactly one owner.
- **Serialized.** The core handles a session's messages in order, one at a time. A late or duplicate answer (an `id` already answered, or cancelled) is ignored.
- **Terminal replies include `cancel`**, listing every outstanding request. Main aborts those transports.
- **A session idle for 60 s is dropped:** no `naming.continue` arrived although none of its requests is past its deadline. A `naming.continue` for an unknown session returns `not_found`, and main then aborts that session's remaining transports. Sessions have no total lifetime: the deadlines of their requests bound them, as the per-call timeouts bound the JS today. CCIP's 10 rounds of 15 s per gateway can take minutes, and that stays possible.
- **No result cache in main.** A protocol handler re-resolves the host on every subresource. A `naming.resolve` the core can answer from its cache costs one pipe round trip, the same order as the normalization the JS cache saves today. So the only result cache is the core's, and no invalidation has to reach two places.

### Generations and invalidation

`naming.configure` carries a `generation`, a counter main increments on every change that today increments the resolver's lifecycle epoch or clears its caches:
- network or verification settings changes;
- Myotis becoming available or unavailable (both directions);
- a core restart: main configures the new process before resolving.

A new generation:
- clears the result caches, the anchor and the provider order;
- keeps quarantine only where today keeps it;
- marks every open session stale.

A stale session's next `naming.continue` restarts it under the new generation (`{ restarted: true, io, cancel }`), at most 3 times per resolution. The next one ends it with today's error, *"… availability changed repeatedly while resolving …"*. A `lifecycle_changed` failure restarts its session the same way.

**Targeted invalidation:**
- `naming.invalidate { kind: "content", name }` is `ens:invalidate-content`: it evicts that name's content entry and returns whether there was one.
- `naming.invalidate { kind: "tezos", name? }` is `tezos-domains:invalidate`. With a name it evicts that name; without one it clears every Tezos result and discovery entry.

What today never caches, the core doesn't cache either:
- a `NO_CONTENTHASH` result that carries an `error`;
- Tezos errors and conflicts;
- `INVALID_ADDRESS`.

### Budgets

| Budget | Value |
|---|---|
| Open sessions | 32; past that, `naming.resolve` returns `busy` |
| Outstanding I/O per session | 32 |
| Answer bytes held per session (until decoded and reduced) | 2 MiB |
| Result caches | 500 entries each (content, address, reverse, Tezos), as `capCache`; 8 MiB in total, evicting expired entries first, then the oldest |
| Endpoints per `naming.configure` | 32 ENS, 8 Tezos |
| Tezos discovery entries | one per endpoint |
| Input before any work | names ≤ 1,024 bytes, addresses ≤ 64 bytes |

Answers are decoded as they arrive, and only the reduced state is kept: heads, hashes, the `resolvedData` per leg. Naming runs on the core's event loop, like signing, and each `naming.continue` does work bounded by the caps above, so the vault's control requests stay responsive.

**Time:**
- `freedom-cored` gives the machine its monotonic clock, for deadlines, idle expiry, cache lifetimes, quarantine and the anchor's 30 s lifetime;
- and its wall clock, only for Tezos expiry timestamps.

Main doesn't pass a time, so it can't move either clock. Randomness for the provider order comes from the OS through the core.

## Configuration

`naming.configure` carries, for chain 1:

- **`endpoints`:** `{ ref, host, source }` per ENS JSON-RPC endpoint, in today's effective order (`ETH_RPC` first, then the registry's `rpc` list, deduplicated as `getEffectiveRpcEndpoints` does).
  - `host` is `new URL(url).host`, which today's trust objects carry.
  - `source` is `builtin`, `user`, `keyed` or `removed`.
  - The first endpoint is the `direct` candidate, `user`-configured when its source says so (`getDirectRpcCandidate`).
- **`verification`:** the network's verification object as stored. The core applies `resolutionPolicy` to it, legacy `primary` included: the method order and `preferVerified`.
- **`quorum`:** `k`, `m`, `timeout_ms`, `anchor` and `anchor_ttl_ms` as stored. The core clamps them as `getPinnedBlock` does (K in 2..9, M in 2..K).
- **`myotis`:** whether it is available. **`colibri`:** whether a prover is configured, and its `ref`.
- **`tezos_endpoints`:** `{ ref }` per Tezos RPC endpoint, in today's fixed order (`TEZOS_RPC` first, then the three defaults, deduplicated), and the proxy contract.

**References are opaque.** Results carry endpoint refs where today's trust objects carry hosts or URLs. When main forwards a result, it maps each ref to the host (ENS: `agreed`, `dissented`, `queried`, conflict `urls`) or to the full normalized URL (Tezos `agreed`), exactly as today. API keys in URLs never reach the core.

## Resolution (ENS, WNS, GNS)

The machine is a port of the JS orchestration, function by function; the replay vectors check it. In brief:

- **Methods:**
  - Each resolution tries the methods of `resolutionPolicy` in order: `myotis`, `colibri`, `quorum` and `direct`, as configured.
  - With `preferVerified`, an `unverified` result, or a reverse `UNVERIFIED` one even when its trust is verified, is held as provisional while later methods run.
  - A method that is unavailable is skipped.
  - When every method fails, the last error is the result's error.
- **Anchor** (`getPinnedBlock`):
  1. Ask **every** available, unquarantined endpoint for its head, and wait for all of them to settle.
  2. With fewer than 3 heads, there is no anchor, and the resolution falls back to a single source.
  3. Otherwise take the median head (`sorted[⌊n/2⌋]`) minus the safety depth (8 for `latest`, 32 for `latest-32`, 0 for `finalized`).
  4. Ask the endpoints that answered for that block's hash.
  5. The largest bucket of identical hashes wins if it reaches max(M, a strict majority of the answers). Ties go to the bucket first seen in provider order. Otherwise there is no quorum.

  The anchor is cached for `anchor_ttl_ms`.
- **Quorum legs** (`runQuorumLeg`, `runConsensusWave`):
  - K endpoints, in the session's shuffled order, call the resolver at the anchor.
  - The wave ends early on M identical answers (or M identical negative reasons).
  - The first data answer triggers a `prefetch`, which is cancelled if that answer doesn't win.
  - Exactly one semantic answer is `unverified`. Disagreement is `conflict`, with groups.
  - One second wave runs when the first errored entirely or was only `unverified`, with the rules `resolveViaQuorum` has today.
- **Quarantine:**
  - an endpoint that fails is quarantined for 60 s;
  - the time doubles for each further failure while the entry lasts, up to 600 s;
  - success removes the entry, and so does expiry, which resets the count.
- **Fallbacks:**
  - Single source when fewer than 3 endpoints are available, K < 3 or M < 2, or no anchor can be corroborated.
  - `direct` gives `user-configured` or `unverified` trust, and a failure makes the method unavailable.
- **Chains:** every EVM read is on chain 1. The destination chain only selects the coin type (ENSIP-11). WNS and GNS address requests for any other chain return `CHAIN_UNSUPPORTED`.
- **Reverse:**
  - ENS first.
  - Only when that is `NO_REVERSE` on chain 1: WNS, then GNS.
  - Each WNS/GNS claim is checked forward, through the same method that produced it. A later verified GNS success beats an earlier `UNVERIFIED`, and a WNS/GNS reverse conflict ends the lookup.
- **CCIP:**
  - Up to 10 callback rounds per call, as today's pinned loop allows, on every path. The core checks that the sender is the contract it called.
  - Gateways are tried in the lookup's order. Any non-2xx answer or unusable body moves on to the next, as today.
  - When none answers, the call fails with `CCIP_GATEWAY_FAILED`, a retryable failure, never a negative answer.

## Resolution (Tezos Domains)

Tezos is its own machine, a port of `resolveTezosDomain`:

- **Endpoints:** up to three, in the configured fixed order (no shuffle), each with an 8 s timeout per request.
- **Head:**
  - Every endpoint's head; heads more than 60 blocks from the lower median (`sorted[⌊(n−1)/2⌋]`, unlike ENS) are dropped.
  - The kept heads must be a strict majority, otherwise the result is a head `conflict`.
  - The anchor is the lowest kept head minus 8. Its block hashes must agree by strict majority, otherwise the result is an anchor `conflict`.
- **Discovery, per endpoint:**
  - Each endpoint discovers the registry's big-map ids itself, from the proxy's storage and the registry's script, at the anchor.
  - It caches them for 10 minutes. A lookup that fails with cached ids rediscovers once.
  - One endpoint's discovery never serves another's legs, so one dishonest endpoint can't choose the ids the others look up.
- **Lookup:** a semantic `404` from a big map means "no record", not a failure. Expiry, `web:redirect_url` before `web:content_url`, and `td:ttl` work as today.
- **Result:** groups by `semanticResultKey`. A strict majority with at least 2 agreeing is `verified`, a single answer `unverified`, anything else `conflict`. TTL follows `cacheDuration`.
- **Names** (`isTezosDomainName`): trimmed and lowercased; ending in `.tez`; at most 255 UTF-16 code units; no whitespace, `/`, `?`, `#` or control characters; no empty label. ENSIP-15 never applies.

## API

| Method | Params → result | Callers |
|---|---|---|
| `naming.configure` | the [configuration](#configuration) and `generation` → `{}` | `shell` |
| `naming.resolve` | `{ kind, name? , address?, chain_id? }` → `{ session, io }` or `{ result }` | `shell` |
| `naming.continue` | `{ session, responses }` → `{ io, cancel }`, `{ restarted: true, io, cancel }` or `{ result, cancel }` | `shell` |
| `naming.cancel` | `{ session }` → `{ cancel }` | `shell` |
| `naming.invalidate` | `{ kind, name? }` → `{ evicted }` | `shell` |

- **`kind`** is one of:
  - `content`: ENS, WNS and GNS content;
  - `address`, with `chain_id`;
  - `reverse`, with `address` and `chain_id`;
  - `tezos`.

  Main routes `.tez` names to `tezos` as `content-name-resolver.js` does.
- **Naming needs no vault.** It works while locked, and no method touches a key.
- **Errors:**
  - `invalid_argument` for malformed parameters;
  - `busy` at the session cap;
  - `not_found` for an unknown or dropped session.

  A failed resolution is a **result**, not a protocol error. Main keeps its IPC handlers and their catch mappings; the next section lists which shapes come from where.

## Result schemas

The core returns exactly the shapes today's resolvers return. Main maps endpoint refs back as described under [Configuration](#configuration) and adds nothing else.

Two distinctions matter to callers, so they are part of the contract and every vector checks them:
- a key that is **absent** versus present with `undefined` or `null`;
- the three forms of `trust.block`.

**Trust:**
```ts
type RpcTrust = {                       // quorum, direct, single source: no `method` key
  level: 'verified' | 'unverified' | 'user-configured' | 'conflict'; system: 'ens'|'wns'|'gns';
  block: { number: number; hash: string };
  agreed: Host[]; dissented: Host[]; queried: Host[];
  quorum: { k: number; m: number; achieved: boolean };   // achieved === (level === 'verified')
};
type MyotisTrust = { level: 'verified'; system; method: 'myotis'; finality: 'finalized'|'optimistic';
  proof: string /* today's two labels */; block: number | null;
  agreed: ['myotis-p2p']; dissented: []; queried: ['myotis-p2p']; quorum: { k: 1; m: 1; achieved: true } };
type ColibriTrust = { level: 'verified'; system; method: 'colibri'; prover: Host | '';
  proof: 'Sync-committee proof' | 'ZK sync-committee proof'; block: null;
  agreed: [prover]; dissented: []; queried: [prover]; quorum: { k: 1; m: 1; achieved: true } };
type EnsConflictGroup =               // data groups first, then negative ones, in arrival order
  | { resolvedData: string /* the raw ABI return, hex */; urls: Host[] }
  | { resolvedData: null; reason: 'NO_RESOLVER' | 'NO_CONTENTHASH'; urls: Host[] };
```

**Content** (`resolveEnsContent`):
```ts
| { type: 'ok'; name; system; codec: 'ipfs-ns'|'ipns-ns'|'swarm-ns'; protocol: 'ipfs'|'ipns'|'bzz'; uri; decoded; trust }
| { type: 'not_found'; reason: 'NO_RESOLVER' | 'NO_CONTENTHASH'; name; system; trust; error?: string }
| { type: 'not_found'; reason: 'EMPTY_CONTENTHASH'; name; system; trust }
| { type: 'unsupported'; reason: 'UNSUPPORTED_CONTENTHASH_FORMAT'; name; system; contentHash: string; trust }
| { type: 'conflict'; name; system; trust: RpcTrust; groups: EnsConflictGroup[] }        // no reason, no error
```

**Address** (`resolveEnsAddress`):
```ts
| { success: true; name; system; address /* EIP-55 */; trust }
| { success: false; name; reason: 'NO_ADDRESS'; error: `No address record set for ${name}`; system; trust }
| { success: false; name; system: 'wns'|'gns'; reason: 'CHAIN_UNSUPPORTED'; error }                // no trust
| { success: false; name; system; reason: 'CONFLICT'; trust: RpcTrust; groups }                    // no error
| { success: false; name; system; reason: 'RESOLUTION_ERROR'; error: string | undefined; trust }   // key always present
```

**Reverse** (`resolveEnsReverse`):
```ts
| { success: false; address /* the input */; reason: 'INVALID_ADDRESS'; error }                    // no system, no trust
| { success: true; address /* lowercase */; name; system; trust }
| { success: false; address; reason: 'NO_REVERSE'; error; trust }                                  // no system
| { success: false; address; system; reason: 'UNVERIFIED'; claimedName: string | null; error; trust }
| { success: false; address; system; reason: 'CONFLICT'; error; trust: RpcTrust; groups }
| { success: false; address; system: 'ens'; reason: 'RESOLUTION_ERROR'; error; trust }
```

**Tezos** (`resolveTezosDomain`): no `name` key, and none of `dissented`, `queried`, `quorum` or `method` in its trust:
```ts
type TezosTrust = { level: 'verified'|'unverified'; system: 'tezos'; block: { number; hash }; k; m; agreed: Url[] };
type TezosConflictTrust = { level: 'conflict'; system: 'tezos'; block: { number; hash } | null; k; m };
| { type: 'ok'; protocol: 'http'|'https'; uri; redirect: boolean; system; expiry: string | null; ttl /* key present, may be undefined */; trust }
| { type: 'ok'; protocol: 'ipfs'|'ipns'; uri; decoded; basePath: string; redirect: false; system; expiry; ttl; trust }
| { type: 'unsupported'; reason /* parsePublishedUri's */; system; expiry; ttl; trust }
| { type: 'unsupported'; reason: `invalid Tezos Domains metadata: …`; system; trust }               // no expiry, no ttl
| { type: 'not_found'; reason: 'domain record not found'; system; trust }
| { type: 'not_found'; reason: 'domain record expired'; expiry; system; trust }                     // no ttl
| { type: 'not_found'; reason: 'domain has no website record'; expiry; ttl; system; trust }
| { type: 'not_found'; reason: 'invalid .tez domain'; system }                                      // no trust
| { type: 'error'; reason: 'all Tezos RPC providers failed' | 'Tezos RPC providers could not anchor a block'
                         | 'Tezos Domains registry lookup failed'; system }
| { type: 'conflict'; reason /* head, anchor or results */; system; groups; trust: TezosConflictTrust }
```

The error strings are today's: `'ENS name is empty'`, ENSIP-15's and ethers' messages, and the method-exhaustion and lifecycle messages. Where the JS threw, the core returns a result `{ thrown: message }`, which main turns into the same rejection its IPC handler maps today.

## Deviations from the JS

Each comes with a vector at its boundary.

| Area | Today | In the core |
|---|---|---|
| ENS normalization | a name that is ASCII once lowercased skips validation, and ethers' `namehash` refuses it later | every name is validated up front. The same names resolve and fail; the message comes from normalization |
| CCIP on the Myotis and Colibri paths | ethers' built-in loop: a lenient parser, 10 fetches and 9 callbacks | the strict decoder and 10 callback rounds, as on the RPC paths today; the vectors list the encodings only the lenient parser took |
| Answer sizes | unbounded for ENS JSON-RPC and verified calls, 5 MB for Tezos, 4 MB for gateways | 64 KiB, 64 KiB, 512 KiB and 256 KiB (see [Frames and sizes](#frames-and-sizes)); an oversized answer fails its request like a transport error |
| Request size | unbounded | 768 KiB encoded; a larger CCIP callback or URL fails that round |
| Input size | none for ENS names | 1,024 bytes |
| Main's caches | a result cache, in-flight deduplication and Tezos discovery, in main | the result cache and Tezos discovery in the core, deduplication in main |
| Proxy | the resolver's JSON-RPC bypasses the session | through the session (the only intended behavior change) |

Not deviations, and kept on purpose:
- per-call CCIP depth, rather than a budget per resolution;
- moving on to the next gateway after a 4xx, although EIP-3668 says a 4xx is final;
- the first-answer prefetch.

## Parity contract and vectors

`vectors/naming.json` comes from the pinned freedom-browser checkout, like `vectors/signing.json`. The generator runs the **original** source, never a copy:

- **Harness:** each JS module runs in a Node `vm` context with test-only exports of its own internal functions, injected by the harness, so no code is duplicated. The environment is stubbed: `electron`, the network registry, Myotis' manager, Colibri's worker host, the prefetch module and the logger.
- **Scripted world:** ethers' `FetchRequest` and the gateway transport answer from a script keyed by the request's signature (endpoint, method, params, URL). The script also sets the clock, `Math.random` and the order in which requests settle. So `queried`, conflict groups, winners and quarantine come out reproducibly. Myotis and Colibri cases use ethers' real ABI and CCIP code behind scripted verifier answers.
- **Codec cases** run each internal function on chosen inputs and record the result or the error:
  - normalization: Freedom's cases (the upstream corpus stays in the crate's tests);
  - namehash and DNS encoding;
  - every ABI rule (whole versus per-field failures, offsets, padding, the read cap);
  - UR answers and every classified revert, `ReverseAddressMismatch`;
  - contenthash, including CIDv0 kept, a multi-byte varint, IPNS as a base58 multihash, and the 32-bit truncation that turns `0xe3010155128180808010ab` into `ipfs://bafkrfamaqcabbky`;
  - CCIP decoding, the forged-sender refusal, URL expansion, all 13 refused URLs from `ccip-fetch.test.js` plus numeric IPv4 forms, and answer parsing;
  - Tezos: `ScriptExpr`, Micheline records, published URIs including the dweb loop guard.
- **Replay cases** drive whole resolutions through the scripted world, for content, address, reverse and Tezos. They cover:
  - agreement, a single answer and conflict;
  - every failure path, the second wave and the single-source fallbacks;
  - CCIP rounds, provisional results and lifecycle restarts;
  - the reverse fallbacks, and Tezos discovery with its rediscovery.

  Each case records the final result, and the **multiset** of requests made: endpoint, method, params and block pinning. It also records which requests were cancelled, what was cached and for how long, and that nothing else was requested. Order within a wave isn't part of the contract.

Rust replays every case, through the crate and through the binary. CI regenerates the vectors in `check` mode against the pinned checkout, as for signing.

## Implementation steps

1. **Codecs** (`fc-naming` without `trust` and `machine`) with the codec vectors. These modules are usable on mobile on their own.
2. **The machines, the caches and the `naming.*` methods**, with the replay vectors. Release.
3. **freedom-browser:**
   - `ens-resolver.js` and `tezos-domains-resolver.js` become drivers. Each IPC call becomes a session, they execute its I/O through the session's network stack with today's transport bounds and the onion gate, and they map endpoint refs back.
   - Myotis and Colibri adapters answer `verified_call` with raw calls (no ethers CCIP), keeping their own retry and client retention.
   - `ccip-fetch.js` keeps only the fetch.
   - Settings, Myotis transitions and core restarts send `naming.configure` with a new generation.

   The PR must pass the existing resolver tests, rewritten against the driver, and the ENS, ENSv2 and Tezos e2e suites, on macOS, Windows and Linux.
4. **Delete** the JS codec and orchestration. `cid-utils.js` stays for the browser's URL handling.

**Rollback:** naming keeps no state on disk, so a browser step can be reverted with no migration.

## Open questions

1. **Trust semantics across platforms (roadmap 3.1).** Should a quorum agreement keep the label `verified`? Should every platform have `user-configured`, and iOS' `anchorDisagreement`? Proposed: ship desktop's semantics now; the product decision then changes `trust` in one place, for every platform.
2. **EIP-3668's 4xx rule.** Stop at the first 4xx, or keep trying the next gateway? Proposed: keep today's behavior until the trust question is settled.
3. **Verifier networking.** Colibri's prover traffic and Myotis' peers stay outside the session proxy until roadmap 3.3.
