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
| `abi` | ethers v6's strict decoder:<ul><li>whole-decode failures: reads past the end, the 1,024× read cap, an offset word above 2^53;</li><li>deferred per-field errors, raised only when the field is read: invalid UTF-8, an address with high bits set, a length above 2^53;</li><li>offsets relative to their tuple; unchecked padding.</li></ul> | `AbiCoder.defaultAbiCoder()` |
| `ur` | Universal Resolver and NameNFT calls, `decodeFunctionResult`'s whole-word rule, revert classification by selector, `OffchainLookup` as the pinned RPC path decodes it, callbacks, `ReverseAddressMismatch`, the reverse-outcome codec, name systems by suffix | `ens-resolver.js` |
| `contenthash` | the decoder in the JS's rule order: CIDv0 kept, multihash code unchecked, fall-through between rules, JavaScript's 32-bit varint arithmetic | `parseContentHashBytes`, `cid-utils.js` |
| `ccip` | template expansion, the gateway URL policy on WHATWG hosts, POST bodies, answer parsing (lossy UTF-8, then JSON, then `isHexData`) | `ccip-fetch.js` |
| `tezos` | `ScriptExpr` (BLAKE2b and base58check), `isTezosDomainName`, Micheline walking, record maps, metadata, published URIs (with `decodeURIComponent`'s exact failure rule) | `tezos-domains-resolver.js` |

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
| Tezos metadata errors | `invalid Tezos Domains metadata: <V8's JSON.parse message>` | the same prefix; the message comes from `serde_json`. `Invalid Micheline bytes value` is unchanged |
| Tezos expiry | `Date.parse`, which also takes non-ISO forms | the ECMAScript ISO format, which is what the Tezos RPC returns; anything else counts as not expired, as an unparseable date does today |

**Kept on purpose:** both `OffchainLookup` decoders exist today, and they differ in both directions.
- The pinned RPC path uses the strict `AbiCoder`, which accepts nonzero padding after the callback selector.
- ethers' built-in parser, on the Myotis and Colibri paths, rejects that padding but tolerates other malformed layouts.

`ur` implements the strict one, the RPC path's. Whether the verified paths keep the other one is for design 0004 to decide. Either way the vectors list every encoding on which the two differ.

### Codec vectors

`vectors/naming.json` comes from the pinned checkout, like `vectors/signing.json`, and runs the **original** source:

- A harness compiles each resolver module with test-only exports of its own internal functions appended, and stubs `electron` and the environment, so no reference code is copied.
- Gateway cases go through `ccipReadFetch` itself, with a fake `net.request`.
- The cases cover:
  - names, with the stage that refuses each one;
  - coin types and contenthash, including the 32-bit truncation that turns `0xe3010155128180808010ab` into `ipfs://bafkrfamaqcabbky`;
  - every ABI rule;
  - Universal Resolver results, reverts, calls and callbacks;
  - the 13 refused gateway URLs from `ccip-fetch.test.js` plus numeric IPv4 forms and IDN hosts;
  - gateway answers;
  - the Tezos encodings, Micheline helpers and published URIs.

Rust replays every case. CI regenerates the file in `check` mode against the pinned checkout.

## Resolution architecture

These decisions are fixed; design 0004 specifies the protocol that implements them.

1. **Sans-I/O sessions.** A resolution is a session in the core. The core emits the requests it needs (JSON-RPC, Tezos HTTP, verified calls, gateway fetches), main performs them, and the core continues from the answers. The core opens no sockets (0001).
2. **Main's transports.** Main performs every request through the Electron session's network stack, with today's bounds, credential rules and private-log protections. The onion gate applies to every host, RPC endpoints included.
3. **Opaque endpoint references.** The core never sees an endpoint URL, which can carry an API key. Main maps references back to today's hosts and URLs when it publishes a result.
4. **The core owns the result cache.** Main keeps no second copy, so invalidation has one place to reach. Before committing to this, the implementation must measure cached subresource fan-out under concurrent vault work.
5. **Parity is checked by replay.** The generator drives the pinned JS resolvers through a scripted world (requests, clock, randomness, settlement order), and Rust drives its machine through the same script.

### What design 0004 must satisfy

Both Codex reviews of this design (on #22) found these. 0004 must answer every one, each with a vector where it is observable:

- **Frames.**
  - Every outgoing message, not each I/O request, must fit 0001's 1 MiB frame, so excess I/O is queued with a defined drain.
  - Expansion and decoding budgets are reserved before allocating.
  - Answer caps must sit above valid answers: `eth_getBlockByNumber(tag, false)` carries transaction hashes, so a large block exceeds 64 KiB. Either project the needed fields or justify the bound. Today's caps are 5 MiB (Tezos) and 4 MiB (gateways).
- **Reference rules stated exactly.**
  - The `direct` candidate is the first *registry* RPC endpoint, ignoring `ETH_RPC`, with its own trust flag.
  - `resolveViaQuorum` clamps K and M from 1, but `getPinnedBlock` clamps from 2 and adjusts M to the available endpoints.
  - Too few heads means no anchor (single-source fallback); a failed hash quorum **throws**.
- **Deadlines.**
  - `runQuorumLeg` puts one deadline around the whole RPC → gateway → callback sequence (5 s by default), and single-source head and hash share one too.
  - Health classification follows today: a gateway failure doesn't quarantine the RPC endpoint.
  - NameNFT calls don't use CCIP.
- **Generations.**
  - Every reply and every I/O request carries the configuration generation, so main can drop an obsolete completion before publishing it, including one already in the pipe.
  - Deduplication entries retire at the boundary.
  - Three attempts in total.
  - Each event invalidates what it does today: a Myotis transition keeps the anchor and provider order, and doesn't touch Tezos.
- **Deduplication key.** The key comes from the core: normalized name, kind, destination chain, generation. Main cannot reproduce ENSIP-15. Subscriber cancellation and cleanup must be specified.
- **Wire presence.** Results have keys present with `undefined` (Tezos `ttl`, an address `error`), which JSON can't carry. They need a tagged representation that main restores, and the vectors must record key presence.
- **Verified answers.**
  - A verified revert carries its provenance and proof mode, so a proved `ResolverNotFound` gets the right Colibri label.
  - Failure answers carry bounded, redacted diagnostics. A raw RPC error message can echo a configured URL with its key, so it is never forwarded as is.
  - Error strings that can't be reproduced are listed as deviations.
  - A verifier keeps ownership across callbacks and retries.
- **Timers and effects.**
  - Deadline and idle expiry advance on the daemon's clock, without waiting for the next message, and tear the session down.
  - A prefetch is a separately bounded effect. Today it survives any agreed-data outcome and has a 10 s timer.
- **Deviations.** The full inventory: cache, session, I/O, endpoint and envelope budgets, monotonic cache time, and the address limit. Each gets its failure and cache behavior and a boundary vector.

## Implementation steps

1. **Codecs**, with the codec vectors (#23).
2. **Design 0004**, then the replay harness, the machines and the `naming.*` methods. Release.
3. **freedom-browser:** the resolvers become drivers of the core's sessions, and their JSON-RPC moves to the session's network stack.
4. **Delete** the JS codec and orchestration. `cid-utils.js` stays for the browser's URL handling.

## Open questions

1. **Trust semantics across platforms (roadmap 3.1).** Should a quorum agreement keep the label `verified`? Should every platform have `user-configured`, and iOS' `anchorDisagreement`? Proposed: ship desktop's semantics first, then change `trust` in one place for every platform.
2. **EIP-3668's 4xx rule.** Stop at the first 4xx, or keep trying the next gateway as today? Proposed: keep today's behavior until the trust question is settled.
