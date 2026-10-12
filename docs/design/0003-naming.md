# 0003: Naming in the core (Phase 3)

**Status:** proposed. Builds on [0001](0001-freedom-cored.md) and [0002](0002-signing.md). Covers roadmap items 1.2 (the naming codec) and 3.2 (resolution) for desktop; mobile links the same crate later.

## Summary

Freedom resolves names in Electron main today:

| Module | Code lines | Does |
|---|---|---|
| `src/main/ens-resolver.js` | ~2,200 | ENS, WNS (`.wei`) and GNS (`.gwei`): content, `addr` and reverse. Quorum, Myotis, Colibri and direct paths; trust labels; caches |
| `src/main/tezos-domains-resolver.js` | ~560 | `.tez`: Tezos RPC quorum, Micheline decoding, `ScriptExpr` hashing |
| `src/main/ens/ccip-fetch.js` | ~90 | EIP-3668 gateway fetches with a URL policy |
| `src/shared/cid-utils.js`, `src/shared/blake2b.js` | ~220 | CID encodings, BLAKE2b |

iOS (~5,600 Swift lines) and Android (~6,300 Kotlin lines) implement the same again, and the three already disagree on trust levels.

This design moves naming into a new logic crate, `fc-naming`, served by `freedom-cored` as `naming.*` methods:

- **Codecs:** ENSIP-15 normalization, namehash, DNS encoding, the Universal Resolver ABI, contenthash, CCIP-Read, and the Tezos encodings.
- **Resolution:** a sans-I/O state machine. It decides every request a resolution needs; main performs each one and returns the bytes. The core still opens no sockets (0001).

**Two things change for users.**
- **Proxy and Tor apply to name resolution.** Today ethers' `JsonRpcProvider` sends the resolver's JSON-RPC calls through Node's own HTTP stack, outside the Electron session's proxy. After the migration, every request goes through main's session-aware transports.
- **Gateway policy lives in one place.** The core builds and checks every CCIP gateway URL. Main only fetches the URLs the core hands it.

Everything else is parity: the same answers, trust levels, errors and cache lifetimes as today's desktop resolver, for the same network responses. Golden vectors from the pinned JS check this.

## Goals and non-goals

**Goals**
- **One implementation:** desktop now, mobile later through `freedom-mobile-ffi`.
- **Parity with desktop:** results, `trust` objects, error reasons and TTLs match `ens-resolver.js` and `tezos-domains-resolver.js` at the pinned commit. Deviations are listed under [Deviations](#deviations-from-the-js) and have vectors.
- **All I/O through main's transports:** the session proxy, Tor, Myotis and Colibri, with today's timeouts and size caps.
- **Bounded work:** every loop, round and buffer has a limit (see [Limits](#limits)), so a hostile RPC endpoint or gateway can't make the core spin or grow without bound.

**Non-goals**
- **New trust semantics.** Today a quorum agreement is labelled `verified` although it is corroboration, not proof; Android has no `user-configured` level; iOS adds `anchorDisagreement`. Unifying them is a product decision (roadmap 3.1). This design keeps desktop's semantics, and the [Open questions](#open-questions) ask for that decision.
- **New record types:** text records, avatars, non-EVM coin types. Freedom doesn't resolve them today.
- **`chain-data-router.js`** (wallet reads and broadcasts; roadmap 3.4) and the process model of Myotis and Colibri (roadmap 3.3). Both stay as they are. The resolver uses them as transports.
- **Policy for page access to naming.** Names are resolved for main, as today.

## Crate layout

`fc-naming` is a logic crate: no I/O, no clock, no randomness of its own. Time arrives as a parameter, and randomness through a trait that the core fills from the OS. It compiles for iOS and Android.

| Module | Contents | JS it replaces |
|---|---|---|
| `normalize` | ENSIP-15 via the `ens-normalize` crate (spec 1.11.1, Unicode 17.0.0, CLDR 47, the same data as the JS `@adraffy/ens-normalize` 1.11.1); Tezos lowercasing | `fastNormalize`, ethers' `ensNormalize` |
| `ens` | namehash, `dns_encode` (labels up to 255 bytes); ENSIP-11 coin types | ethers `namehash`, `dnsEncode`, `ensCoinType` |
| `ur` | the Universal Resolver `resolve(bytes,bytes)` and `reverse(bytes,uint256)`; inner `contenthash`, `addr` and `addr(bytes32,uint256)` calldata; result decoding; error classification by selector; the `REVERSE_OUTCOME` codec; WNS/GNS NameNFT calls | `ens-resolver.js` codec helpers |
| `contenthash` | the decoder and CID encodings, quirks included (see [Parity](#parity-contract-and-vectors)) | `parseContentHashBytes`, `cid-utils.js` |
| `ccip` | `OffchainLookup` decoding, the sender check, URL template expansion, the gateway URL policy, response parsing, callback encoding | the manual CCIP loop, `ccip-fetch.js`'s policy half |
| `tezos` | BLAKE2b, base58check, `ScriptExpr` hashing, Micheline decoding, published-URI parsing | `tezos-domains-resolver.js` codec half, `blake2b.js` |
| `trust` | anchor corroboration, quorum agreement, conflict groups, the trust objects, TTLs, the method order policy | `buildTrust`, `classifyNoAgreement`, `ttlForResult`, `resolutionPolicy`, Tezos' rules |
| `machine` | the resolution state machine | the orchestration in both resolvers |

**New dependencies:**
- `ens-normalize` 0.1.1 (MIT): a Rust port of the reference normalizer, built from the same spec data. It depends only on `serde` and `serde_json`. Its test suite passes all 38,614 upstream validation cases; the JS library Freedom ships agrees with the same file on every case.
- `url` (WHATWG URL parsing, for the gateway policy), `blake2`, `bs58`. Each goes through `cargo-deny`, as for every dependency.

## The resolution machine

A resolution is a session in the core. Main starts it, then answers the I/O requests it emits until it produces a result:

```
main                                     core (fc-naming machine)
naming.resolve {kind, name, …}    ──▶    plan: anchor heads from 3 endpoints
                                  ◀──    { session, io: [rpc#1, rpc#2, rpc#3] }
(performs the three calls)
naming.continue {session, responses: [rpc#1 ok, rpc#2 ok]}
                                  ◀──    { io: [rpc#4 …], cancel: [] }   (a quorum leg)
…
naming.continue {session, responses: […]}
                                  ◀──    { result: { type: "ok", …, trust } }
```

- **I/O requests** have an id, a kind and a deadline:
  - `rpc`: a JSON-RPC request (`eth_call`, `eth_getBlockByNumber`, Tezos RPC paths) to an **endpoint id**. Main maps ids to URLs, so API keys in URLs never reach the core.
  - `verified_call`: an `eth_call` at `latest` through Myotis or Colibri.
  - `gateway`: a CCIP-Read fetch of a URL the core built and checked, with the method (GET or POST) and body.
- **Responses** may arrive in any order and in batches. The machine acts as soon as it can, for example on early M-of-K agreement, and then lists the I/O it no longer needs in `cancel`.
- **Main enforces transport bounds:** today's timeouts and size caps, no redirects for gateways, and the `.onion` rule (only when the session proxies it). An I/O failure is reported as `{ id, error: kind }`, never as an exception that ends the session.
- **Sessions are bounded:** a session holds at most 64 outstanding requests and lives at most 60 s. At most 64 sessions are open at once; past that, `naming.resolve` returns `busy`. A session with no `naming.continue` for 30 s is dropped. `naming.cancel` ends one early.
- **The machine keeps today's cross-request state:**
  - provider health and quarantine (60 s doubling to 600 s);
  - corroborated anchors (30 s);
  - in-flight deduplication: concurrent sessions for the same query share the I/O;
  - the result cache, with today's TTLs.

  All of it is in memory only. Main's lifecycle events (settings changes, `invalidateEnsContent`) map to `naming.invalidate`.
- **Main keeps a thin result cache** keyed by query, with the expiry the core returns. The `bzz:` and `ipfs:` protocol handlers re-resolve the host on every subresource, and one pipe round trip per subresource is not worth paying.

**Configuration** arrives with `naming.configure` whenever main's network settings change:
- endpoint ids with their host (for the trust object's `queried` list) and source (built-in, user-added, keyed, removed);
- the verification order (`myotis`, `colibri`, `quorum`), `preferVerified`;
- the quorum parameters (K = 3, M = 2, 5 s legs, anchor `latest` minus 8 blocks, 30 s anchor lifetime: `chains.json` today);
- whether Myotis and Colibri are available.

The core never reads settings files.

## API

| Method | Params → result | Callers |
|---|---|---|
| `naming.configure` | the configuration above → `{}` | `shell` |
| `naming.resolve` | `{ kind: "content" \| "addr" \| "reverse", name? , address?, chain_id?, now_ms }` → `{ session, io }` or `{ result, expires_ms }` | `shell` |
| `naming.continue` | `{ session, responses, now_ms }` → `{ io, cancel }` or `{ result, expires_ms }` | `shell` |
| `naming.cancel` | `{ session }` → `{}` | `shell` |
| `naming.invalidate` | `{ name? }` → `{}` | `shell` |
| `naming.normalize` | `{ name }` → `{ name }` or `invalid_argument` | `shell` |
| `naming.decode_contenthash` | `{ bytes }` → the content result fields | `shell` |

- **Results** have exactly the shapes main returns over IPC today: `{ type: "ok" \| "not_found" \| "unsupported" \| "error", name, system, protocol, uri, decoded, basePath?, redirect?, reason?, trust }`. Main forwards them unchanged.
- **Naming needs no vault.** It works while locked, and no method touches a key.
- **Errors:** `invalid_argument` for malformed parameters, `busy` at the session cap, `not_found` for an unknown or expired session. A failed resolution is a **result** (`type: "error"`, with today's reasons), not a protocol error.

## Deviations from the JS

Each is listed with its vector.

- **Normalization happens once, up front.** Today an all-ASCII name skips validation (`fastNormalize`), and ethers then fails it inside `namehash`. The core validates every name with ENSIP-15 first. Names that resolve today resolve the same, and names that fail today still fail. The error now comes from normalization instead of hashing, so its message can differ; the vectors pin both.
- **One CCIP decoder.** Today the block-pinned quorum and direct legs use a strict ABI decoder and allow 10 callbacks, while Myotis and Colibri use ethers' built-in, lenient parser, which allows 10 fetches and 9 callbacks. In the core, every path uses the strict decoder and a limit of 10 rounds. The strict decoder refuses some malformed encodings that ethers' parser tolerates on the Myotis and Colibri paths; the vectors list each one.
- **Gateway failures.** Today any non-2xx response moves on to the next URL. EIP-3668 says a 4xx is final. The core keeps today's behavior and lists the EIP's rule under [Open questions](#open-questions).

## Limits

Some of these are new: today has no cap on name length, gateway URLs per lookup or ENS RPC response size. Each is far above real use, and a resolution that hits one fails like any other.

| Limit | Value |
|---|---|
| Name length | 255 bytes per label (DNS encoding), 1,024 bytes total |
| CCIP rounds | 10 per resolution |
| Gateway URLs | 8 per `OffchainLookup`; URL length 2,048 bytes |
| Gateway response | 4 MiB (main checks it too) |
| RPC response | 5 MiB (Tezos uses that today; ENS gets the same) |
| ABI decoding | offsets and lengths checked against the buffer; strings and bytes up to 1 MiB |
| Micheline | depth 64; 10,000 nodes per value |
| Sessions | 64 open, 64 outstanding I/O each, 60 s life, 30 s idle |

## Parity contract and vectors

`vectors/naming.json` comes from the pinned reference checkout, like `vectors/signing.json`. Two kinds of case:

- **Codec cases** run each JS function on chosen inputs and record its result or error:
  - normalization (the upstream validation file stays in the crate's tests; the vectors add Freedom's own cases, such as `fastNormalize` inputs);
  - namehash and DNS encoding;
  - UR encoding and decoding, every classified error selector, and `ReverseAddressMismatch`;
  - contenthash: CIDv0 kept as `Qm…`, CIDv1 multi-byte varints, `ipns-ns` as base58 multihash, `swarm-ns`, `arweave` and `onion` (unsupported), empty (`not_found`), and the quirk that the multihash code isn't checked;
  - CCIP: decoding, the forged-sender refusal, URL expansion, and the policy table (12 refused URLs from `ccip-fetch.test.js` plus IPv4 numeric forms);
  - Tezos: `ScriptExpr`, Micheline records, and published URIs including the dweb loop guard.
- **Replay cases** drive the JS resolver with a scripted transport (fixed responses per endpoint, failures, slow legs, CCIP rounds, disagreeing endpoints, a conflicting anchor) and record the final result. The Rust machine replays the same response script and must produce the same result and TTL. The order of I/O isn't part of the contract, because concurrency makes it vary.

CI checks out freedom-browser at the pinned commit and regenerates the vectors in `check` mode, as for signing.

## Implementation steps

1. **Codecs** (`fc-naming` minus `machine`) with the codec vectors. These modules are usable on mobile on their own.
2. **The machine and the `naming.*` methods**, with the replay vectors. Release.
3. **freedom-browser:**
   - `ens-resolver.js` and `tezos-domains-resolver.js` become drivers. They forward IPC calls to `naming.resolve`, execute I/O and keep the thin result cache.
   - JSON-RPC goes through the session's proxy-aware `net.fetch`, so proxy and Tor apply.
   - Myotis and Colibri become `verified_call` transports; ethers no longer drives their CCIP.
   - `ccip-fetch.js` keeps only the fetch: bounds, transport and the `.onion` rule.

   The PR must pass the existing resolver tests, rewritten against the driver, plus the ENS and ENSv2 e2e suites, on macOS, Windows and Linux.
4. **Delete** the JS codec and orchestration. The browser keeps `cid-utils.js` for its URL handling.

**Rollback:** naming keeps no state on disk, so a browser step can be reverted with no migration.

## Open questions

1. **Trust semantics across platforms (roadmap 3.1).** Should a quorum agreement keep the label `verified`? Should every platform have `user-configured` and iOS' `anchorDisagreement`? Proposed: ship desktop's semantics now; the product decision then changes `trust` in one place for all platforms.
2. **EIP-3668 4xx handling.** Stop at the first 4xx as the EIP says, or keep trying the next gateway? Proposed: keep today's behavior until the trust question is settled.
3. **Text records.** ENS avatars and other text records would be one more `kind`. Not needed for parity.
