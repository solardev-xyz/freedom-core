# 0003: Naming in the core (Phase 3): codecs and architecture

**Status:** proposed. Builds on [0001](0001-freedom-cored.md) and [0002](0002-signing.md). Covers roadmap item 1.2 (the naming codec) and the architecture of item 3.2 (resolution). The resolution protocol itself is design 0004, written with the replay harness in hand. This document lists what 0004 must satisfy.

## Summary

Freedom resolves names in Electron main today. At freedom-browser `fb540328`:

| Module | Lines | Does |
|---|---|---|
| `src/main/ens-resolver.js` | 2,856 | ENS, WNS (`.wei`) and GNS (`.gwei`): content, `addr` and reverse; the quorum, Myotis, Colibri and direct paths; trust labels; caches; IPC |
| `src/main/tezos-domains-resolver.js` | 684 | `.tez`: Tezos RPC quorum, Micheline decoding, `ScriptExpr` hashing |
| `src/main/ens/ccip-fetch.js` | 177 | EIP-3668 gateway fetches and their URL policy |
| `src/shared/cid-utils.js`, `src/shared/blake2b.js` | 344 | CID encodings, BLAKE2b |

iOS (~5,600 lines of Swift) and Android (~6,300 lines of Kotlin) implement the same logic again, and the platforms already disagree on trust levels.

Naming moves into a new logic crate, `fc-naming`, in two parts:

1. **Codecs** (this design; implemented in #23): ENSIP-15 normalization, namehash and DNS encoding, the ABI shapes the resolvers decode, Universal Resolver and NameNFT calls, contenthash, CCIP-Read policy, and the Tezos encodings. They have byte-for-byte parity with the JS, checked by vectors generated from the pinned reference. They are useful on mobile on their own.
2. **Resolution** (design 0004): a sans-I/O state machine served by `freedom-cored`. The core decides every request a resolution needs, and main performs it through the Electron session's network stack. The architecture is fixed [below](#resolution-architecture); the protocol is not.

## Goals and non-goals

**Goals**
- **One implementation:** desktop now, mobile later through `freedom-mobile-ffi`.
- **Parity** with the pinned JS. Every deviation is listed with a vector.
- **Proxy and Tor apply to name resolution:** today ethers' `JsonRpcProvider` sends the resolver's JSON-RPC through Node's own HTTP stack, outside the session's proxy.

**Non-goals**
- **New trust semantics.** Unifying desktop, iOS and Android is a product decision (roadmap 3.1); see [Open questions](#open-questions).
- **New record types:** text records, avatars, non-EVM coin types.
- **Colibri's and Myotis' own networking** (roadmap 3.3), and `chain-data-router.js` (roadmap 3.4).

## Codecs

`fc-naming` is a logic crate: no I/O, no clock, no randomness of its own, and it compiles for iOS and Android.

| Module | Contents | JS it matches |
|---|---|---|
| `normalize` | ENSIP-15 through `ens-normalize`; JavaScript's exact `trim` (Rust's `str::trim` differs on U+FEFF and U+0085); Tezos trim-and-lowercase | `fastNormalize`, ethers' `ensNormalize` |
| `ens` | namehash, `dns_encode` (labels up to 255 bytes; the NameNFT paths don't DNS-encode), ENSIP-11 coin types | ethers' `namehash`/`dnsEncode`, `ensCoinType` |
| `abi` | ethers v6's strict decoder:<ul><li>whole-decode failures: reads past the end, the 1,024× read cap, an offset word above 2^53 − 1;</li><li>deferred per-field errors, raised only when the field is read: invalid UTF-8, an address with high bits set, a length above 2^53 − 1;</li><li>offsets relative to their tuple; unchecked padding.</li></ul> | `AbiCoder.defaultAbiCoder()` |
| `ur` | Universal Resolver and NameNFT calls, `decodeFunctionResult`'s whole-word rule, revert classification by selector, `OffchainLookup` as the pinned RPC path decodes it, callbacks, `ReverseAddressMismatch`, the reverse-outcome codec, name systems by suffix | `ens-resolver.js` |
| `contenthash` | the decoder in the JS's rule order: CIDv0 kept, multihash code unchecked, fall-through between rules, JavaScript's 32-bit varint arithmetic | `parseContentHashBytes`, `cid-utils.js` |
| `ccip` | template expansion, the gateway URL policy on WHATWG hosts, POST bodies, answer parsing (lossy UTF-8, then JSON, then `isHexData`) | `ccip-fetch.js` |
| `tezos` | `ScriptExpr` (BLAKE2b and base58check), `isTezosDomainName`, Micheline walking (iterative, any depth), record maps, metadata, published URIs (with `decodeURIComponent`'s exact failure rule) | `tezos-domains-resolver.js` |
| `jsjson` | JSON as V8's `JSON.parse` reads it:<ul><li>numbers are doubles (`1e400` is `Infinity`; integers above 2^53 lose precision);</li><li>escaped lone surrogates are accepted (and become U+FFFD in Rust strings, as the WHATWG URL parser would make them);</li><li>nesting depth is limited only by the input size;</li><li>a duplicate key keeps its first position and its last value;</li><li>JavaScript's property order (integer keys first).</li></ul>Every JSON the codecs parse goes through it. | `JSON.parse` |

**Dependencies:**
- **`ens-normalize` =0.1.1** (MIT; only `serde` and `serde_json`): a Rust port of the reference normalizer, built from the same spec data as the JS library Freedom ships (spec 1.11.1, Unicode 17.0.0, CLDR 47).
  - It passes all 38,614 upstream validation cases, and so does the shipped JS library; two independent runs found no mismatch. The crate's tests keep that corpus.
  - Its panic sites are the parse of its embedded data at first use and guarded internal lookups; the corpus exercises them.
- **`url`:** WHATWG parsing, as Node and Chromium do it.
- **`blake2`, `sha2`:** the workspace's `digest` 0.11, so no duplicate versions.
- **`serde_json`.**

All pass `cargo deny`.

### Codec deviations

| Area | Today | In the core |
|---|---|---|
| ENS normalization | a name whose lowercase form matches `^[a-z0-9-.]+$` skips ENSIP-15 (`fastNormalize`), and ethers' `namehash` refuses it later | every name is validated up front. The same names resolve and fail. Only names ethers refuses later (`ab--cd.eth`, `xn--x.eth`, `foo..eth`, `.eth`, `eth.`) get the normalizer's message instead of ethers'. Every other refusal message is the JS's own |
| Input size | none for ENS names | 1,024 bytes, before and after normalization |
| Tezos metadata errors | `invalid Tezos Domains metadata: <V8's JSON.parse message>` | the same prefix and the same accept/refuse decision (`jsjson`); only the message after the prefix is the core's own. `Invalid Micheline bytes value` is unchanged |
| JSON lone surrogates | an escaped lone surrogate (`"\ud800"`) stays in the JS string | it becomes U+FFFD. A URL field is unaffected (the WHATWG URL parser makes the same replacement), and a gateway's `data` is refused either way. Only a non-URL metadata string's stored value differs; a vector marks it |
| Micheline depth | `flattenPairLeaves` recurses and throws a stack overflow somewhere past several thousand nested pairs | walked iteratively at any depth, so a storage V8 couldn't walk (past its stack) is walked; real storage nests a handful of levels |

**Kept on purpose:** both `OffchainLookup` decoders exist today, and they differ in both directions.
- The pinned RPC path uses the strict `AbiCoder`, which accepts nonzero padding after the callback selector.
- ethers' built-in parser, on the Myotis and Colibri paths, rejects that padding but tolerates other malformed layouts.

`ur` implements the strict one, the RPC path's. Whether the verified paths keep the other one is for design 0004 to decide. Either way the vectors record both decoders on a set of malformed layouts, so every difference among them is pinned.

### Codec vectors

`vectors/naming.json` comes from the pinned checkout, like `vectors/signing.json`, and runs the **original** source:

- A harness compiles each resolver module with test-only exports of its own internal functions appended, and stubs `electron` and the environment, so no reference code is copied.
- Gateway cases go through `ccipReadFetch` itself, with a fake `net.request`.
- The cases cover:
  - names, with the stage that refuses each one;
  - coin types and contenthash, including the 32-bit truncation that turns `0xe3010155128180808010ab` into `ipfs://bafkrfamaqcabbky`;
  - the ABI rules: whole versus deferred failures, offsets, an aliased string, the 1,024× read cap at its boundary;
  - Universal Resolver results, reverts, calls and callbacks;
  - `OffchainLookup` layouts through both the strict `AbiCoder` and ethers' built-in parser, including nonzero selector padding;
  - the 1,024-byte name limit (a deviation vector);
  - JSON as V8 reads it: huge numbers, lone surrogates, deep nesting, duplicate keys and property order;
  - the 13 refused gateway URLs from `ccip-fetch.test.js` plus numeric IPv4 forms and IDN hosts;
  - gateway answers;
  - the Tezos encodings, Micheline helpers and published URIs.

Rust replays every case. CI regenerates the file in `check` mode against the pinned checkout.

## Resolution architecture

These decisions are fixed; design 0004 specifies the protocol that implements them.

1. **Sans-I/O sessions.** A resolution is a session in the core. The core emits the requests it needs (JSON-RPC, Tezos HTTP, verified calls, gateway fetches), main performs them, and the core continues from the answers. The core opens no sockets (0001).
2. **Two kinds of transport.**
   - **Shell HTTP:** JSON-RPC, Tezos HTTP and CCIP gateways. Main performs these through the Electron session's network stack, with today's bounds, credential, cache and custom-handler protections, and private-log rules.
     - Today's Tor PAC proxies `.onion` hosts and sends clearnet `DIRECT`.
     - The onion gate applies to every shell-HTTP host, RPC endpoints included: no empty or `DIRECT` route, and no `DIRECT` fallback.
   - **Verified calls:** Myotis and Colibri, through their existing adapters, whose own networking (Myotis' P2P, Colibri's worker `fetch`) is unchanged until roadmap 3.3.
3. **Opaque endpoint references.** The core never sees an endpoint URL, which can carry an API key. Main maps references back to today's hosts and URLs when it publishes a result.
4. **The core owns the result cache.** Main keeps no second copy, so invalidation has one place to reach. Before committing to this, the implementation must measure cached subresource fan-out under concurrent vault work.
5. **Parity is checked by replay.** The generator drives the pinned JS resolvers through a scripted world (requests, clock, randomness, settlement order), and Rust drives its machine through the same script.

### What design 0004 must satisfy

Both Codex reviews of this design (on #22) found these. 0004 must answer every one, each with a replay vector where it is observable. Replay checks the requests made (endpoints, methods, params, block pinning), cancellations, cache lifetimes and the absence of unexpected I/O, not only the final result.

- **Results, exactly:**
  - the per-kind result, trust and error schemas of today's resolvers, with key presence;
  - present `undefined` (Tezos `ttl`, an address `error`) needs a tagged representation that main restores;
  - today's TTLs and non-cacheable cases.
- **Frames and budgets:**
  - every outgoing message fits 0001's 1 MiB frame, with excess I/O queued and a defined drain;
  - expansion and decoding budgets are reserved before allocating;
  - aggregate bounds on retained, temporary and transport work;
  - vault control stays responsive;
  - answer caps sit above valid answers: `eth_getBlockByNumber(tag, false)` carries transaction hashes, so either project the needed fields or justify the bound. Today's caps are 5 MiB for Tezos and 4 MiB for gateways.
- **The ENS orchestration, as the reference runs it:**
  - the anchor probes every available endpoint, waits for all heads, needs at least 3, takes the upper median, and requires a hash plurality of max(M, strict majority). Too few heads means single-source fallback; a failed hash quorum throws;
  - refreshed quarantine selection: 60 s doubling only while an entry lasts, reset on success or expiry; a gateway failure doesn't quarantine the RPC endpoint;
  - the second wave picks endpoints the first didn't use, with wave-specific K/M;
  - `resolveViaQuorum` clamps K/M from 1, `getPinnedBlock` from 2, plus the anchor's effective M;
  - the `direct` candidate is the first registry endpoint (ignoring `ETH_RPC`), with its own trust flag;
  - forward and reverse provisional rules;
  - ENS → WNS → GNS reverse fallback with same-method forward checks;
  - every EVM read on chain 1, the destination chain only selecting the coin type, `CHAIN_UNSUPPORTED` for WNS/GNS elsewhere.
- **Tezos:** its own quorum, discovery isolation per endpoint, discovery and result caches, and expiry. Whether expiry parsing restricts `Date.parse` to the ISO format is a 0004 decision, with a deviation vector if it does.
- **Deadlines:**
  - one parent deadline per quorum leg around RPC → gateway → callback (5 s by default);
  - single-source head and hash share one deadline;
  - NameNFT calls don't use CCIP.
- **Security:**
  - the CCIP sender is validated;
  - callbacks stay on the endpoint and pinned block, or the verifier, that produced the lookup;
  - a verified revert carries its provenance and proof mode;
  - failure diagnostics are bounded and redacted: never a raw RPC message, which can echo a keyed URL;
  - a verifier keeps ownership across callbacks and retries.
- **Generations:**
  - every reply and every I/O request carries the configuration generation (and the core process's), so main drops obsolete completions, including one already in the pipe;
  - deduplication entries retire at the boundary;
  - three attempts in total;
  - each event invalidates what it does today: a Myotis transition keeps the anchor and provider order and doesn't touch Tezos.
- **Sessions:**
  - deduplication by a core-produced key (normalized name, kind, chain, generation), with subscriber cancellation;
  - late and duplicate answers ignored;
  - terminal replies cancel what is outstanding;
  - deadline and idle expiry advance on the daemon's clock without waiting for a message;
  - a prefetch is a separately bounded effect with today's survival rules (it survives any agreed-data outcome and has a 10 s timer).
- **Deviations:** the full inventory (cache, session, I/O, endpoint and envelope budgets, monotonic cache time, the address limit), each with its failure and cache behavior and a boundary vector.

## Implementation steps

1. **Codecs**, with the codec vectors (#23).
2. **The replay harness:** the pinned resolvers in a scripted world, measuring the reference's orchestration.
3. **Design 0004**, written from those measurements.
4. **The machines and the `naming.*` methods**, with the replay vectors. Release.
5. **freedom-browser:** the resolvers become drivers of the core's sessions, and their shell HTTP moves to the session's network stack.
6. **Delete** the JS codec and orchestration. `cid-utils.js` stays for the browser's URL handling.

## Open questions

1. **Trust semantics across platforms (roadmap 3.1).** Should a quorum agreement keep the label `verified`? Should every platform have `user-configured`, and iOS' `anchorDisagreement`? Proposed: ship desktop's semantics first, then change `trust` in one place for every platform.
2. **EIP-3668's 4xx rule.** Stop at the first 4xx, or keep trying the next gateway as today? Proposed: keep today's behavior until the trust question is settled.
