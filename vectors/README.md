# Golden vectors from the desktop JavaScript

**These are public test secrets. Never fund these keys, wallets or addresses, and never use these passwords or mnemonics for real data.**

The oracle is Freedom Browser at commit
`fb540328162839e68150fe2c5e517edb86734d1c`. The generator imports its real
`src/main/identity/{derivation,formats,vault}.js` with `createRequire` anchored in
that checkout. It uses the installed packages from that checkout and adds no npm
dependencies. It does not implement derivation, encryption or identity encoding.
One file with no reference needs a construction Node doesn't offer whole:
`keystore.json` seals with HPKE (RFC 9180). `generator/hpke.js` composes it from
`node:crypto`'s primitives alone (X25519 `diffieHellman`, HMAC-SHA256 and AES-GCM),
step by step as the RFC writes it, and implements no primitive of its own.
`check.test.js` pins the composition to the RFC's own test vectors (Appendix A.1.1,
and the AES-256-GCM suite's entry in the JSON file Appendix A cites), and the Rust
replay opens every seal with the `hpke` crate.

The Radicle vectors (`radicle-*.json`) have their own reference: freedom-browser's
`integration/rust-core` at commit `1ea598373fcc406bed8a3df1e54b734dcc4e5ac5`
(`RADICLE_REFERENCE_COMMIT` in `generate.js`). Their generators load that checkout's
main-process modules, whose main the service replaces, and freedom-browser's parity
harness (`src/main/radicle/radicle-vectors.test.js`) replays every recorded `main`
against them. The Radicle reference moves on its own, deliberately, when that main
changes what the vectors record; moving the shared reference instead would re-derive
every other file from another browser and break the random fixtures' `meta`.

`approvals.json` has a third reference, for the same reason: freedom-browser's
`integration/rust-core` at commit `7f85551d82bddb1337df73b331785e969d62d1b9`
(`APPROVALS_REFERENCE_COMMIT` in `generate.js`), which has SEC-1's eleventh token
kind (#1016) and design 0011's page tokens (PRQ-5a). Its generator loads that
checkout's `src/main/wallet/signing-confirmation.js`, which requires only Node's
`crypto` and `src/shared/origin-utils.js`: no package is read, so the checkout needs
no install, and its `meta` names the commit, the Node version and the generator path.

`profiles.json` (design 0013, PRF-3) uses the approvals reference's checkout too
(`PROFILES_REFERENCE_COMMIT` in `generate.js`, the same commit): its profile modules
(`profile-catalog.js`, `profile-resolver.js`, `profile-lock.js`,
`profile-switch-scheme.js`) are byte for byte `integration/rust-core`'s at `2f0c571f`.
They require one package, `proper-lockfile`, which is resolved from the main
reference's install: the same version (4.1.2) and integrity in both lockfiles. Its
`meta` names that package.

| File | Contents |
| --- | --- |
| `keys.json` | Six mnemonic seeds; user and publisher keys at indices 0, 1, 2, 1000 and 2147483647; Bee, Radicle and IPFS keys; exact index errors and special JS inputs for every mnemonic. |
| `mnemonic-validation.json` | Valid 12/15/18/21/24-word phrases, checksum/word/type/case/spacing/Unicode failures, accepted compatibility forms, seeds and wallet 0 for accepted inputs. |
| `signing.json` | Design 0002's signing contract, from the reference's ethers and bee-js: EIP-155 and EIP-1559 transactions (`Wallet.signTransaction`, with `keccak256` hashes), EIP-191 messages, EIP-712 typed data (signature and `TypedDataEncoder.hash`, including the Safe, x402 and Permit2 payloads and every ethers rejection), and single-owner chunks (`makeContentAddressedChunk(…).toSingleOwnerChunk(…)`) for account, Bee wallet and publisher keys (bee-js signs with all three; over the wire the core refuses account keys, design 0002 #89). Inputs are in the core's wire form; `typedDataText` gives typed data as JSON text, which ethers signs as `JSON.parse` reads it (padded ties and halfway subnormals included). Each typed-data case the core accepts records `TypedDataEncoder.getPayload` as `payload`, which the core's view of what is signed reproduces (design 0002, #88); `typedDataReports` adds the `primary_type` and `chain_id` parameters, with ethers' signature and the view's expected `named_type` and `chain` reports, which come from the design text. Cases naming a type or field `__proto__`, which the core refuses (`proto-name`), also record `reference`: ethers' `TypedDataEncoder.hash` and `getPayload` of the input alone. Entries marked `deviation` are signed by ethers but must be rejected by the core. It has its own `meta`, which adds the bee-js packages. |
| `naming.json` | Design 0003's codec contract, from the reference's own `ens-resolver.js`, `tezos-domains-resolver.js` and `ccip-fetch.js`. A harness reaches their internal functions by appending test-only exports to the original source and stubbing Electron, so no reference code is copied. It covers ENS names (trim, `fastNormalize`, ethers' `namehash` and `dnsEncode`, and the stage that refuses a name), coin types, contenthash (quirks included), the ABI rules (whole-decode failures versus deferred field errors), Universal Resolver calls, results, reverts, `OffchainLookup` and callbacks, CCIP gateway policy and answers (through `ccipReadFetch` with a fake transport; hosts with an empty label, which the reference fetches, are marked `deviation: ccip-hosts`), and the Tezos encodings, Micheline helpers and published URIs. Its `meta` adds `@adraffy/ens-normalize`. |
| `naming-replay.json` | Design 0004's replay harness: the pinned `ens-resolver.js` and `tezos-domains-resolver.js` run whole in scripted worlds (endpoints, gateways, the Myotis and Colibri adapters), each scenario's seed, world, steps, results with their settlement times, and every exchange and verifier operation. Scenarios marked `deviation` run the reference patched to do what the core does at one of its bounds. A rule of main's after the pin is a reference patch, which the core shares: `no-colibri-names`, main's #1076 (freedom-browser #1082 at `0da2215b`), takes Colibri out of name resolution, and the scenarios it changes, with the ports of main's tests (`no-colibri-names-*`), record it in `patches` and the pinned reference's results as `unpatched` (design 0004, Reference patches). Generation fails unless each patch changes its scenario. Its `meta` adds `@sinonjs/fake-timers`. |
| `chain.json` | Design 0005's codec contract (step 1), from the reference's own `chain-data-router.js` through the same harness as `naming.json`; the router's modules are stubbed, and observers wrapped around its internal functions record, without changing anything, the errors each source throws. It covers `normalizeParams` for `eth_call` and `eth_estimateGas` (`BigInt` quirks, the `input` alias, property order and `JSON.stringify` output) and the UTF-16 units `BigInt(string)` trims; `stableValue` strings with their SHA-256 and equivalence pairs (duplicate keys, number spellings, `__proto__`, lone surrogates, `undefined`); answers through the real `requestRpcUrl` and Node's `Response` (statuses, BOMs, UTF-8 replacement, V8's grammar, `result`, `error`, bodies that aren't objects); `feeQuote` with its block, the cases main's #749 changes run with the reference patch `fee-headroom` (`patches`, and the pinned router's own answer as `unpatched`; design 0005, Main's #749), and Colibri's with `colibri-unproven` after it, which no longer counts them verified (design 0005, Main's #1046); `safeErrorMessage` and its whitespace; the aggregate errors of `request`, `getFeeQuote` and `broadcastRawTransaction`; ethers' `keccak256` of signed transactions; `READ_METHODS`, the sources' capabilities (with the reference patch `colibri-unproven`: Colibri doesn't serve `eth_gasPrice`, `eth_feeHistory`, `eth_call` or `eth_estimateGas`, its pinned list kept as `unpatched`) and the source order with its `No chain source left …` and `Unsupported read method` texts; Myotis reads through the real `requestMyotis` (the gates, `assertMyotisAnswer`'s classes with each error's code, data and finality, the per-method answers, each payload also in main's snake_case wire form) and `myotisTrust`'s block; the Ant bridge's `rankLogScanError` and `logScanRangeCap` (with every pattern's source and flags) and the range refusal text; and `blockscout-logs.js`'s filter, mappers, agreement, cooldowns and paging through `fetchBlockscoutTransferLogs` with scripted pages (its redirect and DNS policy stays with main). `broadcast_refusals` is the design's own (deviation `broadcast-outcome`): client error wordings with the classes design 0005 gives them, each answer still read by the router's `requestRpcUrl`; the generator cites each client's source. So is `fee_combinations` (deviation `fee-combination`): B's combination of Direct's quotes, each endpoint's quote from the patched router's `feeQuote` and the combined quote, with its `answered`, from design 0005's text. Strings that may hold lone surrogates are recorded as their JSON text (`*_json`). Entries marked `deviation` are where the core differs by design: `json-depth` (more than 512 levels refused), `json-parse-text` (a fixed text instead of V8's `SyntaxError`) and `bigint-width` (decimal conversions stop below 2^4096). It has the shared `meta`; `response.json()` is the undici bundled with the recorded Node version. |
| `chain-replay.json` | Design 0005's replay harness (step 2): the pinned `chain-data-router.js`, with the real `blockscout-logs.js` and the Ant bridge's real router options (`LOG_SCAN_ROUTER_OPTIONS`, `rankLogScanError`, `logScanRangeCap`), run whole in scripted worlds under the reference's own fake timers. Fresh modules per scenario; global `fetch`, the registry, the Myotis manager (its thrown errors by class, with the manager's and child process's texts), Colibri's `requestViaColibri` and Blockscout's DNS lookups are stubbed; no reference code is copied, and the router's state tables are read through accessors appended to its source. Each scenario has a stable `id` and `from` (the suite test it ports, `file:line` at the pinned commit, or the design 0005 section it pins): the ports of `chain-data-router.test.js`, `ant-log-scan-routing.test.js`, `ant-log-index-routing.test.js`, `ant-chain-bridge.router.test.js` and `blockscout-logs.test.js`'s paging, page, cooldown, redirect and DNS cases (through the router), then the design's named boundary cases (`boundary-*`), then the ports of two later rules of main's at `94b0af4e`, #752's (`tx-lookup-*`, `colibri-fault-*` and their `boundary-*` cases) and #749's (`fee-headroom-*`), then those of freedom-browser #1048 at `a515f9a7`, a fix to main not merged yet: Colibri serves no answer it can't prove (#1046), no call (it runs calls on code it doesn't check), and only reads it ties to the requested block (#1060: account reads at `latest`, appended when left out; blocks at `latest`, a number or a hash; no other tag and no non-string block) (`colibri-unproven-*`). Scenarios on Colibri's own handling drive it with an account read, as #1048's tests do. A scenario a later rule changes runs the pinned router with that rule's reference patch (`patches`: `tx-lookups`, `fee-headroom`, `colibri-unproven`, the last always last) and also records the unpatched reference's results (`unpatched`); generation fails if a patch changes nothing, or if `colibri-unproven` changes nothing beside the patches before it. It records its world, steps and calls; every call's result or thrown error (class, name, message and own properties in order) with its settlement time; the state tables after each step (adaptive routes, Myotis slots, Colibri's in-flight work, log-range learning, Blockscout cooldowns; instants in virtual milliseconds); and every I/O request with its call, virtual start and end, outcome and answer: JSON-RPC exchanges (`id` normalized to 0), Myotis and Colibri operations, Myotis status samples, Blockscout reads, pages, HTTP hops and DNS lookups (each `within` the operation it belongs to). Encodings are in its `encodings`. Every value the reference produced or was given (results, thrown properties, operation params and answers, call params) is JSON text in a string field (`*_json`, or `json` in an entry), never a JSON value, so none can pass for an encoding and every value `JSON.parse` makes survives: lone surrogates as escapes, any nesting, `-0` and ±Infinity (written `-0` and `±1e400`). A present `undefined` is a field of its own (`*_undefined: true`). An object the router returned or threw is a list of entries in property order. A text over 64 KiB is written in its field's repeat form (`*_json_repeat`, `body_repeat`: head, unit, count, tail, length and SHA-256), so the `html()` 8 MiB answers stay small. Worlds, steps and state tables are plain JSON. Ported calls carry the settle times their tests assert (`expect_settle_ms`, or a bound), and generation fails if a fixture drifts from them; scripted answers are immediate unless they name a delay, as the suites' mocks are. Ant's scan loops are recorded call by call. Calls with `options` use router options no production caller passes alone. `boundary-json-depth-513` is marked `deviation: json-depth` (the reference reads it; the core refuses the body), `boundary-quorum-duplicate-endpoint` `deviation: endpoint-dedup` (the reference counts an endpoint listed twice as two members; the core asks it once) and `boundary-quorum-singleton-not-verified` `deviation: singleton-quorum` (the reference labels a quorum with m = 1 verified; the core labels it as Direct would); there are no patched deviation vectors yet. Its `meta` adds `@sinonjs/fake-timers`. |
| `dweb.json` | Design 0006's transport contract (step 2), from the reference's own `bzz-protocol.js`, `ipfs-protocol.js`, `ipfs-manager.js`, `content-name-resolver.js`, `lib/gateway-location.js`, `lib/gateway-response-headers.js`, `shared/cid-utils.js`, `shared/origin-utils.js`, `onchain-html.js` and `onchain-app-protocol.js`, through the same harness as `naming.json`. Name resolution is stubbed: each case scripts what the resolver returns or throws, and records which resolver the handler asked. It covers whole requests through the real handlers (`bzz:` hash and name hosts, encoded separators, published base paths, the 404/415/502 mapping, CIDs and IPNS keys in every multibase, lowercased hosts, gateway-form 307s and 400s, both header policies, methods, and backends that aren't up, each mode with its own text; a request's `backend` is `{ ant | ipfs: mode, up }`), whole exchanges with scripted node answers (redirect rewrites, header strips, small text with lying lengths and oversized chunks, counting the reads), `rewriteGatewayLocation` and `decodeURIComponent` directly, the response operations, failures after the dial, the `html()` decode and its caps (8 MiB documents as `recipe`s), and the gate's class. `plan` composes the reference's outcome (`js`) with the tables in `constants`; its response operations, trust labels and `body_idle_ms` are the design's, and so is all of `validation` (`source: design`), which has no reference; there, `{ "$repeat": [text, count] }` stands for a long string. Entries marked `deviation` are where the core differs by design: `native-page-state` (page-state headers are stripped from the native IPFS node's answers too) `plan-paths` (plans whose targets today's handlers dial, which validation refuses, judging paths as decoded too) and `plan-headers` (plans whose header values hold a control character other than an interior tab). It has the shared `meta`. |
| `dweb-verify-plans.json` | Design 0009's verify plans (step 1), the design's: every `dweb.json` case whose plan 0006 accepts, run again through the same reference handlers on its external backend, in four forms (verification on; on with strict mode; strict mode with verification off; and for IPFS, strict mode with a gateway the probe found without raw blocks), with the plan 0009 composes from the reference's outcome: a `{ verify }` plan, the `{ fetch }` that stays (a 128-hex reference, a DNSLink name, an IPNS name with another inlined key), strict mode's 403 with its message, or the redirect or error unchanged. Then requests at the verifier's 8 KiB bound (`*-bound-*`, verification on), on each side of it: a verify plan, or the 414 or 431 `dweb.open` plans in its place; each request whose plan is the 414 or 431 is there again with strict mode, with the same plan. A backend is `dweb.json`'s with `verify`, `strict` and `unsupported`. `validation` changes one member of a plan (root, path, query, headers, retry, timers, response, trust, strict mode's error, the bound's errors) and names the stage that refuses it. Its `formats` and `constants` define every field and the fixed texts. It has the shared `meta`. |
| `streams.json` | Design 0007's stream frames (step 3: order, credit and coalescing), 0009's and 0014's two-way connections, with no reference: freedom-browser's `frame.js` gains the stream kinds later, and is to pass these cases too. Every case and outcome is the design's, written out by hand in `generator/streams.js`, which only lays the bytes out and checks each case's shape; nothing is computed by a model of the rules. `frames` decodes byte strings as each side reads them (main, the service, a `freedom-cored` connection before its hello settles protocol 2, which takes no stream frame, one after it, which takes them both ways, and either end of a two-way service connection), in any chunking, with each failure's category; `encodings` are exact frame bytes and refusals; `sender` scripts the service's side (requests, cancels and credit from main; heads, replies, body bytes, `finish` and `abort` from its producers; then exactly the frames its writer writes, in order) and `receiver` main's (replies and stream frames from the service, pulls with their credit, local cancels, and each record's state and ring); `duplex` scripts `freedom-cored`'s connection at protocol 2 (design 0009), both directions on one connection: main's requests with the sender's steps, the core's own with their replies and stream frames from main, the consumer's releases and the credit the core then owes, the core's cancels, and the frames written, credit first; `service_duplex` scripts a service connection that takes main's bodies (design 0014, COL-3) in `duplex`'s steps, decoded at both ends as `service_streams`: the service's own requests and main's bodies in answer to them, with a service's abort codes for what it sends and a piece's for what main sends, and every `sender` case replayed on it too. Body bytes follow a fixed pattern by stream and offset, so cases state lengths and offsets, never bytes. Its `formats` member defines every step and outcome. It has the shared `meta`. |
| `dweb-verify.json` | Design 0009's verification vectors (step 1), from the pinned nodes rather than the JavaScript reference: verification reads no user data, and the formats are Ant's, Bee's and IPFS's. Its own generator records them (`dweb-verify/`, below). The Swarm half: data trees from Ant v0.5.71's splitter for eight sizes at every erasure-coding level, Bee's tree where Ant's differs, manifests from Ant's writers (single files, directories with index and error documents, Unicode and long names) and the shapes they can't write (an obfuscated node, a node over one chunk, encrypted content below a plain root), sequence feeds (v1, v2 with a manifest and with raw bytes as the latest update, an encrypted v1 update, an empty feed), leaves whose span or payload differs from their logical length, `lookup_path`'s answer for each manifest path, and Ant's gateway's answers to the requests the verifier and the bundled-node parity care about: status, headers and body. The IPFS half: DAGs Kubo v0.43.1 writes from seeded content (six sizes, CIDv0 with dag-pb leaves and CIDv1 with raw leaves, balanced and trickle, a file whose leaves repeat), directories (an index document, a listing, a HAMT, Unicode names, files without an extension), identity CIDs, IPNS records the generator signs (Ed25519 and RSA, with freedom-ipfs's verdict on each), Kubo's trustless answers (CARs with `dag-scope` and `entity-bytes`, raw blocks), and `GatewayCore`'s answers over the same blocks, the parity target. Bodies are slices of seeded content, inline bytes or a length and SHA-256; data leaves are rebuilt from the content. Its `formats` member defines every field. Its `meta` records the pinned commits, the headers Freedom sends, the headers that describe the node, and the Bee cross-check's result. |
| `dweb-verify-cases.json` | Design 0009's own cases (Tests first), written by the same generator: checks on single pieces, then whole requests through the verifier (`requests`: a plan, the honest node of `dweb-verify.json` with one thing changed, and the head and body, the error, or the head and the exact prefix released before the abort, for Swarm, IPFS and IPNS, including steps that share a partition, and two manifests at the edge of a Swarm request's 2 MiB, one served and one refused for its memory; files whose sizes disagree, from the case's own blocks, and IPNS chains past `GatewayCore`'s limit, each with `GatewayCore`'s own answer beside it), and `answers`: `dweb.verify`'s two answers on the wire for four of those requests, a bundled node's own 404 as a head with its trust beside the core's own 404 as an error plan, for each node. The piece checks: A chunk where a content-addressed one is needed (the empty chunk, spans and payloads that differ, zero-extended payloads, flips, single-owner chunks off the feed path), feed updates (v1, v2, v1's length, an encrypted v1, other owners and indices, high-s and every other `v`, no EIP-191 prefix, the replicas owner), leaves against their logical length (Ant's surplus payloads and one-reference wrapper, a payload too short, flipped bytes), intermediate chunks (one to 128 references, zero padding, child geometry over one and two levels, every erasure level's data and parity counts from Ant's own splits, levels no table has, and the shapes Ant's joiner refuses, each read back through Ant's joiner), mantaray nodes (obfuscation, both versions, reference sizes, prefix lengths, 256 forks, a missing fork, metadata at its 65,535-byte maximum on every fork, nested and malformed metadata, the 1 MiB cap and past it, each through Ant's lookup), blocks against their CIDs (identity, 2 MiB and one past, unsupported hashes with honest digests, codecs), dag-pb and UnixFS decoding (either field order, DAG-PB's strictness: unknown, repeated and out-of-order fields and split Links, groups, long varints, the link cap and past it, maximal blocks of minimal fields, inconsistent sizes, HAMT parameters and the bitfield's width), HAMT lookup by hash for every name of `dweb-verify.json`'s HAMT and for entries out of their place (through GatewayCore), CAR framing (headers and their CBOR in the strict profile, section limits, a CID's non-minimal varint, block mismatches, early ends and boxo's truncation marker), and IPNS records (RSA keys outside libp2p's rules or in non-canonical DER, signatures a byte short, equal to the modulus or over SHA-1, a missing key, a validly signed ECDSA record, a small-order Ed25519 key, CBOR depth, lengths, indefinite lengths, key order, shortest forms, floats, keys and tags). Every `expect` is the design's; beside each case are the pinned nodes' own checks on the same bytes, and a case where they differ names its deviation. Its `formats` member defines every field. |
| `radicle-reads.json` | Design 0008's `rad.read` composed ops and the ops main parses and writes again (step 4, item 11), from the reference's own `radicle-embedded.js`, `radicle-api-protocol.js` and `radicle-manager.js` through the same harness as `naming.json`: the add-on is scripted (each export main calls, its arguments and the JSON text it returns, in libradicle's shapes at the service's pin), and nothing of the reference is copied. Each case is an op with the service's `args` (a page's are what `paginate` reads of its `query`), the scripted answers, and main's: the radapi handler's status and body (`serveRepoApi` with `allowPrivate`, or the `/api/v1/repos` listing), the calls main made and what it logged. It covers `readme_at` (every candidate and their order, a directory or submodule with a candidate's name, binary, escapes, lossy text, errors), `repo_meta` (public, private, a seeders failure, the fallbacks of a missing or falsy field), `repos_meta` (order, a seeders failure, the first failure of several), `issues_page` and `patches_page` (every state, `parseInt`'s white space, signs and digits, the clamps, more than 100 items), `issue`, `patch`, `remotes` (a branch named as an index) and `repo_stats`, and what `JSON.parse` then `JSON.stringify` make of numbers (past 2^53 and 2^53 ± 1, floats, halfway cases, where of two decimals of the fewest digits as close to the double main writes the even one, every power of two where the closest such decimal doesn't read back, the range's ends and the exponent form's thresholds, doubles drawn from every magnitude, `-0`, out of range), strings (every escape, lone surrogates), index and repeated keys, whitespace and depth. `node_info`'s body is the design's (`source: design`), and the generator checks that main's `serveNodeApi` and `getConnections` answers rebuild from it. A case marked `synthetic` holds a text libradicle never writes. It has the Radicle reference's `meta`. |
| `radicle-blob.json` | Design 0008's `rad.blob` (step 4, item 12): a fixture of files (text, binary by each of libgit2's rules, empty, one byte, Latin-1, a UTF-8 mark, a symlink, a submodule, exactly 64 MiB and one byte more), each with its blob ID, size and `binary` (libgit2's `git_blob_is_binary`, ported in the generator and checked against libradicle by the service's tests), and main's answer for it today at `/blob/<rev>/<path>`, from the reference's own `radicle-embedded.js` and `radicle-api-protocol.js` through `radicle-reads.json`'s harness with a scripted add-on. The reference has no raw route and reads no Range header, so each case's head (with its `body`: whether a stream follows), bytes and error, and main's HTTP answer on them (status, Content-Length, Content-Range), are the design's (`source: design`): the Range header main gets, the `range` main sends for it, `HEAD` as `head_only`; open-ended, suffix, an end past the blob, a start at or past it, a suffix of 0 and past the size, an empty blob, several ranges and headers that don't parse, the 64 MiB cap from the header. The generator checks them against the browser's pending `blob-api` and `size-caps` contract tests. libradicle's errors (a missing path, a directory, a submodule) are the add-on's v0.8.0 texts, through main's `/blob/` (404 by its message test, else 500); params that don't parse are `invalid_argument`. It has the Radicle reference's `meta`. |
| `radicle-network.json` | Design 0008's network operations (step 4, item 13), from the reference's own `radicle-embedded.js`, `radicle-manager.js` and `radicle/seed-status.js` through the same harness as `radicle-reads.json`, with the add-on scripted in libradicle's shapes at the service's pin (`json::seed_report`, `json::progress`, its `Error` texts) and `Date.now` counting from a fixed instant. `reports`: seed reports (ready, degraded with escapes in reasons, already connected, an empty book, live peers that reach the target, a large `elapsedMs`) and a failure, with what `connectAndSeedDefault` then called and logged; the service answers the report's text byte for byte. `progress`: a clone's events of every phase with each one's text, as `cloneRepoWithProgress` hands it on, and the statuses `seedRepository` published. `queue`: the design's progress queue (`source: design`): scripted emits and writer takes, and every envelope written, exactly (coalescing, the 8 failures and the summary, its folding while it waits, the terminal's slot, the 4 KiB cut at character boundaries with escapes, multi-byte characters and the ID's digits, exactly 4096 bytes and one over, dropped summary reasons, the browser's pending contract scenario). `results`: how a clone libradicle ended is answered (`ok`, `cancelled` by main or not, no seeds, a failed fetch, one that matches today's not-found test, a timeout, the gate's states), with the add-on's text and main's last status. It has the Radicle reference's `meta`. |
| `radicle-stats.json` | Design 0008's `rad.stats` (step 4, item 14). Main at the reference asks for no stats (there is no health probe today), so `cases` are the design's (`source: design`): for each state of the service a case scripts (the node's phase, whether its thread runs where its lock could be tried, the watch's last count of its peers, NAT64 discovery's stats, the repair unit in progress, the quarantine record's count, each pool's use and the output budget's), the result the service writes, byte for byte: before the start, reconciling, starting, running before and after the first count, held exclusively, its thread ended, down, stopped, `socks5`, every pool full, the budget full and shrunk, NAT64 at and past its 16 prefixes and 16 failures (cut to the first 16), and the largest result, within 4 KiB. `connections` ties `connected_peers` to the count main shows today: the reference's own `getConnections` over the add-on's `status`, through the same harness as `radicle-network.json`. freedom-browser's contract suite on `integration/rust-core` reads `budget.output` (its `used` at most its `limit`, its `limit` 256 MiB), which the generator checks every case at the service's budget meets. It has the Radicle reference's `meta`. |
| `radicle-import.json` | Design 0008's import (step 4, item 15; design 0010, D5), from the reference's own `github-bridge.js` (its `importGitHubRepo`, main's one caller of `importRepo`), run whole over the reference's `radicle-embedded.js` and a scripted add-on, through the same harness as `radicle-reads.json`; `git`, GitHub's API, the network check and the profile's temporary directory are scripted, and each case loads the modules afresh. `imports`: four imports (a description, none, a `trunk` branch, a branch `git symbolic-ref` can't name) and main's own refusal of an invalid RID, each with the one `importRepo` call main makes (the clone's path, the name, the description, the default branch: `rad.import_repo`'s `path`, `name`, `description` and `default_branch`), the add-on's answer and what main then did (its result, git commands, HTTPS requests, progress, bridge map, removals, console lines); then each of the service's errors (`source: design`: its code and message), handed to main as the add-on's error text, with what main made of it. The generator checks that only "already exists in storage" trips one of main's readings (`ALREADY_BRIDGED`). It has the Radicle reference's `meta`. |
| `approvals.json` | Design 0012's tokens (APR-1), from the approvals reference's own `signing-confirmation.js`. `bindings`: for each request, as the reference takes it (`kind`, `account`, `payload`, and the `page` main's page issuer binds: its handle and key), `bindingFor`'s facts or its error; `core`, the same request in fc-approval's form (the `sign.*` parameters but the key; a typed-data text as `payload_text`, which the core parses itself; the page as `PageContext`'s origin, frame and navigation with the handle), and `expect`, whether the core issues a token for it. `pairs`: two requests the reference binds, whether a token minted for either spends for the other (`alike`) or not (`apart`), asked of the reference both ways, with the facts that differ (`changed`) and the core's answer (`core`). Each fact of each kind's binding is changed by an apart pair. `runs`: issue, consume, discard and count in order under `_setNow`, with each outcome: the two-minute boundary (`expiresAt <= now`), the cap of 32, burning on a mismatch, an expiry, another kind and a malformed request, a page's token without its page, a Safe send's site and wallet tokens, and a wall clock set back. Where the core differs, the case, pair or step says so (`deviation`, from 0012's Deviations: `token-strict`, `token-clock`, `token-page`, `token-typed-parse` and `token-message-bytes`) and gives the core's answer. `kinds` records the reference's twelve kinds; the cap edit (#1023) is not one of 0012's eleven. `rules.decisions` (APR-2): the standing rules, from the reference's `page-signing.js` and `page-sends.js` driven with injected dependencies over its own `dapp-permissions.js` and `fee-check.js`: runs of requests and grant changes, what the reference did (its rule, its prompt or its error) and the core's answer, `covered` or 0012's reason, against the same grants in Q9's form (`deviation`: `rule-legacy`, `rule-expiry`, `rule-rate`, `rule-value`, `rule-inputs`). It has its own `meta`, which names no package. |
| `profiles.json` | Design 0013's profile catalog (PRF-3), from the profiles reference's `profile-catalog.js` and `profile-resolver.js`. The pure functions: `sanitizeProfileId` with its refusals, `displayNameFromId`, `hashPath` and the checkout id, the dev ports' offset, `getManagedPorts`, `allocateSlot`, and `rebaseNodeConfig` and `fillMissingNodeConfig` (reached through `importProfile` and `ensureProfile`, which use them). `lockStaleness`: proper-lockfile's `checkSync` with `Date.now` held, one millisecond either side of each stale time. `scenarios`: the reference's operations (`resolveProfile`, `createProfile`, `renameProfile`, `importProfile`, `updateProfileNodeConfig`, `getReservedManagedPorts`, `listProfileSummaries`, and `validateProfileDeletion` as `delete-validate`, the delete's refusals, whose value is `valid` where it throws nothing) run in order on one app root under a fixed clock, each step's result or refusal and every file's text and directory after it. They ran in a temp directory, written `/vectors` throughout. A refusal keeps the reference's message; a file that isn't JSON is `unreadable`, a `TypeError` `malformed`. A step where the core answers otherwise has `deviation`, the row of 0013's Deviations table (`profile-delete-overlap`), and `core`, the core's answer, beside the reference's `result`. |
| `secrets.json` | Design 0013's secrets file (PRF-1a), with no reference: no build of the browser reads or writes it. Every case and outcome is the design's (`source`), written by hand in `generator/secrets.js` as plain states, which the generator lays out as `JSON.stringify(file, null, 2)` and whose entries it seals with Node's AES-256-GCM under fixed keys and nonces (public test values), with the associated data the design gives; nothing is computed by a model of the rules. `files`: files in form, each with the items it names (in fc-profile's reading order too: fc-keystore's tests check that fc-profile reads the same), each entry's key, nonce, binding, canonical JSON, associated data and secret, and opens with the caller's name, binding and key: the secret, or `no_entry`, `other_binding` or `refused` (an entry moved from another name, sealed under another binding, key or nonce, or with a changed tag). `malformed`: texts refused, one change each, with the first reason the core finds (form, bounds, duplicate ids and nonces, keys without entries, entries under no key, and every text but the one the core writes). `transitions`: one change each (`begin_create`, `commit` with its re-wrap, `put`, `remove`, `settle`, `forgotten`, `drop_foreign`) with the RNG's draws, and the exact text after it or the refusal: a pending item and a `forget` list at the four-item bound, the fifth refused (`forget_backlog`), DPAPI's blob and no record. Its `formats` member defines every field. It has the shared `meta`. |
| `keystore.json` | Design 0013's key-store helper (PRF-1b), with no reference: no build of the browser runs it. Every case and outcome is the design's (`source`), written by hand in `generator/keystore.js` as plain states; the generator lays each answer out and seals each `key` with HPKE (`generator/hpke.js`: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, `info` `freedom-keystore/1`) under a fixed request key and fixed ephemeral keying material (public test values), with the associated data the design gives (`freedom-keystore/1`, the op, the item, and a DPAPI blob's SHA-256); nothing is computed by a model of the rules. `helper`: requests (argv, stdin, what the OS offers), the one OS call each makes and the store's answer, the RNG's draws, and the exact line the helper writes: create, open and forget, the store's failures, an RNG that fails, every out-of-form request and stdin byte refused with no OS call, and `unsupported`. `answers`: answers main relays, with the core's reading under the request key: the wrapping key (a DPAPI create's blob too), done, or the error: a key sealed for another op, item, blob, recipient or `info`, a changed byte in `enc` or the ciphertext, cut short or a byte long, over 4096 bytes (and exactly 4096, which is in), unknown, duplicate and `null` members, the wrong kind for the op, and each failure answer as the core maps it. Its `formats` member defines every field. It has the shared `meta`. |
| `identity-formats.json` | Deterministic IPFS private-key protobuf/base64 and PeerID; Radicle DID, node ID and public SSH file with default `FreedomBrowser` comment and custom `vector-alias`; `didFromPublicKey`; and `radiclePrivateFiles`, whole private key files with a fixed check integer for aliases around an aligned private section. Those marked `deviation: openssh-padding` carry the reference's full 8-byte padding, which the core omits. |
| `fixtures/vaults.json` | Exact vault file contents from real `importVault`, including timestamps and the embedded encrypted JSON string. Five password/mnemonic cases, parsed payloads, successful unlocks, exact failing files/passwords/outcomes, plus one explicitly synthetic positive legacy vault. |
| `fixtures/bee-keystores.json` | Two actual `createBeeKeystore` outputs, passwords, expected keys/addresses, parsed JSON, KDF parameters and the Unicode password normalization check. |
| `fixtures/radicle-openssh.json` | Twelve actual `createRadicleIdentity` results (six mnemonics, two comments), extracted check integers and padding; checked by parsing and replaying the same check integer through the reference JS. |
| `generator/generate.js` | Plain CommonJS generator and verifier. |
| `generator/signing.js` | The signing cases and their builder, used by `generate.js`. |
| `generator/chain.js` | The chain-data cases and their builder, used by `generate.js`. |
| `generator/chain-replay.js` | The chain-data replay harness and its scenarios, used by `generate.js`. |
| `generator/dweb.js` | The dweb transport cases and their builder, used by `generate.js`. |
| `generator/streams.js` | The stream frame cases, used by `generate.js`. |
| `generator/radicle-reads.js` | The composed reads' harness and cases, used by `generate.js`. |
| `generator/radicle-blob.js` | `rad.blob`'s fixture, cases and the design's rules, over the composed reads' harness, used by `generate.js`. |
| `generator/radicle-network.js` | The network operations' harness, the design's progress queue and the cases, used by `generate.js`. |
| `generator/radicle-stats.js` | The design's `rad.stats` results and main's peer count, used by `generate.js`. |
| `generator/radicle-import.js` | The import's harness over main's GitHub bridge, and the service's answers, used by `generate.js`. |
| `generator/approvals.js` | The token cases, the core's form of each, and the reference's decisions, used by `generate.js`. |
| `generator/approval-decisions.js` | The standing rules' runs over the reference's dispatchers, and the core's answers, used by `approval-rules.js`. |
| `generator/profiles.js` | The profile modules' loader, the pure cases, the lock cases and the scenarios, used by `generate.js`. |
| `generator/secrets.js` | The secrets file's states, malformed texts and transitions, used by `generate.js`. |
| `generator/keystore.js` | The key-store helper's requests, the answers main relays, and their outcomes, used by `generate.js`. |
| `generator/hpke.js` | RFC 9180's HPKE base mode composed from `node:crypto`'s primitives, used by `keystore.js` and pinned to the RFC's vectors by `check.test.js`. |
| `generator/check.test.js` | Integration tests that damage copies of the oracle outputs and require `check` to fail. |
| `generator/interop.test.js` | Design 0013's interop harness: the profiles reference's `createProfile` and `renameProfile` against `freedom-cored`'s catalog subcommands on one app root, and the catalog's write lock held both ways. Needs `FREEDOM_CORED`, a `testhooks` build. |
| `generator/interop-actor.js` | The harness's reference processes: a writer loop, and a holder of the write lock. |

Every JSON file has a `meta` block with the full reference commit, actual installed
package versions, Node version and generator path. The Radicle files' `meta` names the
Radicle reference's commit, the Node version and the generator path: they read no
package of the reference's. So does `approvals.json`'s, for the approvals reference; `profiles.json`'s names proper-lockfile. The deterministic files use
2-space indentation, LF and one trailing newline, with stable key order. The
fixture containers have the same format. Their embedded `fileContents`,
`keystore`, and SSH strings retain the bytes the reference wrote, including the
vault file's **absence** of a trailing newline.

The checked-in run used Node `v24.15.0` and these installed versions:

| Package | Version |
| --- | --- |
| `ethers` | `6.17.0` |
| `@scure/bip39` | `2.4.0` |
| `@scure/base` | `1.2.6` |
| `micro-key-producer` | `0.10.2` |
| `@metamask/browser-passworder` | `6.0.0` |
| `@ethersphere/bee-js` | `13.1.0` (signing only) |
| `@ethersphere/core-sdk` | `0.1.1` (signing only) |
| `@sinonjs/fake-timers` | `15.4.0` (the replays only) |

From clean checkouts at the three commits, install the first two's lockfile
dependencies (this changes no tracked files; the approvals reference needs none):

```sh
cd /root/herdr/freedom-browser
ELECTRON_SKIP_BINARY_DOWNLOAD=1 npm ci --ignore-scripts
cd /root/herdr/freedom-browser-wt/radicle-reference
ELECTRON_SKIP_BINARY_DOWNLOAD=1 npm ci --ignore-scripts
```

Then, from the freedom-core worktree:

```sh
node vectors/generator/generate.js generate --freedom-browser /root/herdr/freedom-browser \
  --radicle-browser /root/herdr/freedom-browser-wt/radicle-reference \
  --approvals-browser /root/herdr/freedom-browser-wt/approvals-reference
node vectors/generator/generate.js check --freedom-browser /root/herdr/freedom-browser \
  --radicle-browser /root/herdr/freedom-browser-wt/radicle-reference \
  --approvals-browser /root/herdr/freedom-browser-wt/approvals-reference
node --test vectors/generator/check.test.js
cargo build -p freedom-cored --features testhooks
FREEDOM_CORED=target/debug/freedom-cored node --test vectors/generator/interop.test.js
```

The integration tests use `/root/herdr/freedom-browser`,
`/root/herdr/freedom-browser-wt/radicle-reference` and
`/root/herdr/freedom-browser-wt/approvals-reference` by default; set
`FREEDOM_BROWSER_CHECKOUT`, `FREEDOM_BROWSER_RADICLE_CHECKOUT` and
`FREEDOM_BROWSER_APPROVALS_CHECKOUT` to use other clean checkouts. Run with the Node
version in `meta`: the runtime version is part of the byte comparison. The
generator refuses a different commit or a dirty checkout, for any reference.

`generate` rewrites the three deterministic files. On the first run it creates
missing random fixture files. On subsequent runs it **preserves and verifies**
existing fixtures; it never silently replaces their salts, IVs, timestamps,
keystore UUIDs or OpenSSH check integers. `check` recomputes deterministic files
and compares bytes, decrypts all vaults and Bee keystores, recomputes all negative
vault outcomes, and parses/replays every OpenSSH file. Any mismatch exits nonzero.
Generated temporary vault files and integration-test copies use
`fs.mkdtempSync(path.join(os.tmpdir(), 'freedom-core-vectors-'))`, outside the
repository tree. Existing ignored `vectors/.scratch/` directories are retained;
no files are deleted. All temporary files contain only public test material.

`legacyFixtures` contains one **synthetic** positive legacy vault. Freedom never
wrote such vaults, but its reader must accept them. The generator encrypts
`{ mnemonic }` with the real passworder at 10000 PBKDF2 iterations, removes
`keyMetadata`, and wraps that payload in an envelope produced by real
`importVault`. Both passworder decryption and real `vault.unlockVault` must
succeed through the metadata-free legacy fallback. Its random bytes are frozen
like every other fixture. `generate` can add this fixture to the original file
once, after asserting all original fixtures are byte-identical; `check` requires
the positive case and verifies it on every run.

**Never edit vectors by hand.** Change the generator if coverage must expand,
generate outputs from the pinned JS, and review the resulting diff. Never change
a vector to make a Rust test pass. Existing random fixture changes require an
explicit regeneration decision, since normal `generate` treats them as frozen.

The standard six mnemonic cases include four familiar BIP-39 phrases and two
phrases generated once by the reference's `createMnemonic(128)` and
`createMnemonic(256)`, then hardcoded in the generator. No BIP-39 passphrase is
used; `getSeed` uses the default empty passphrase. Uint8Array Ed25519 keys and
seeds are serialized as lowercase hex without `0x`; Ethereum key strings retain
the exact `0x` form ethers returns. Secp256k1 public keys are **compressed** (33
bytes). Addresses in key vectors are EIP-55; Bee's JSON keystore address is
lowercase and omits `0x`.

Compatibility findings to preserve:

- Validation applies NFKD, then splits on literal ASCII spaces and checks the
  English wordlist/checksum. Uppercase and mixed case, leading/trailing/double
  spaces, tabs/newlines, 11/13 words, unknown/French words, and malformed Unicode
  fail. NFC/NFKD accented `ábandon` fails in both forms. Fullwidth letters,
  ideographic spaces and nonbreaking spaces succeed: their NFKD forms produce
  the same seed and wallet as the canonical ASCII phrase. Invalid `getSeed`
  inputs throw exactly `Invalid mnemonic`; `isValidMnemonic` returns `false`.
- `deriveUserWallet` selects a **hardened account** index in
  `m/44'/60'/{index}'/0/0`. Bee uses `m/44'/60'/0'/0/1`, so it is not user account
  1. The publisher namespace is `m/44'/73406'/{index}'/0/0`. Radicle/IPFS use
  all-hardened SLIP-10 paths with coin types 73404/73405.
- `2147483647` succeeds. `2147483648` is not caught by the app's index guard;
  ethers throws a `TypeError` whose full message is
  `invalid path index (argument="path[2]", value="2147483648'", code=INVALID_ARGUMENT, version=6.17.0)`.
  Negative/fractional/non-number/NaN/infinite indices throw
  `Account index must be a non-negative integer` or
  `Origin index must be a non-negative integer`. Explicit `undefined` defaults
  user account to zero but fails for publisher origins. Negative zero succeeds
  as zero; JSON serializes the returned index to zero, so inputs are tagged to
  preserve that distinction.
- Vaults contain outer `version`, `encrypted`, `createdAt`; `encrypted` is a
  JSON **string**, not an object. Passworder plaintext is UTF-8 JSON
  `{"mnemonic":"..."}`; encrypted fields are `data`, `iv`, `keyMetadata`, `salt`
  in that order. Salt is 32 bytes, IV is **16 bytes**, and both are padded
  base64. PBKDF2-HMAC-SHA-256 uses 900000 iterations for a 256-bit AES-GCM key;
  `data` is base64 ciphertext followed by the 16-byte tag, with no AAD.
- Removing `keyMetadata` selects passworder's legacy **10000** PBKDF2
  iterations. For a new 900000-iteration fixture it fails, as do changing the
  iterations by one and flipping the first byte of data, IV or salt. Every such
  failure and a wrong password become `Error: Incorrect password`, with an
  `Error: Incorrect password` cause added by the vault wrapper.
- Vault passwords are raw UTF-8, with no Unicode normalization. The Unicode
  NFC fixture fails with the equivalent NFD password. In contrast ethers
  normalizes Bee passwords using **NFKC**, and the NFD password successfully
  decrypts its NFC fixture. Bee uses scrypt `N=131072, r=8, p=1, dklen=32`,
  AES-128-CTR, and a Keccak-256 MAC over the second half of the derived key plus
  ciphertext. (ethers internally derives 64 bytes; the standard JSON field
  advertises 32 and the private-key/MAC path uses the first 32.)
- The password minimum tests JavaScript `password.length`: **UTF-16 code
  units**, not Unicode code points or UTF-8 bytes. Four `🔐` characters pass the
  eight-unit minimum; seven ASCII characters fail with
  `Password must be at least 8 characters`.
- `importVault` writes directly to the final filename with `fs.writeFileSync`
  and supplies no mode. The initial imported fixtures had mode `0644` under
  this machine's `0022` umask. The byte fixtures record file contents; the Rust
  repository's separate atomic-write/`0600` rules still apply to storage.
- IPFS stores an Ed25519 private seed plus public key (64 bytes) in protobuf
  `08 01 12 40 || private || public`, encoded as base64. Its PeerID is an
  **identity multihash**, inlining `08 01 12 20 || public` rather than hashing
  it. Radicle DID uses multicodec bytes `ed 01`; node ID is the same multibase
  string with the `did:key:` prefix removed.
- Radicle private SSH files are unencrypted (`none` cipher/KDF), with a random
  big-endian uint32 repeated twice and private seed concatenated with public
  key. The reference pads with `01,02,...` to an 8-byte boundary (including a
  full eight bytes when already aligned, as specified by its source), wraps
  base64 at **70** characters, and ends both private/public files with a
  newline. Default and custom comments are part of the bytes. Injecting the
  extracted check integer into the reference's only `crypto.randomBytes(4)`
  call reproduces the entire stored identity exactly.

## `dweb-verify.json` and its generator

Design 0009's vectors come from the nodes Freedom reaches, not from the JavaScript
reference, so they have a generator of their own: `vectors/dweb-verify/`, a Cargo
workspace outside the core's. For Swarm, it links Ant v0.5.71 (910452d) by its git tag, and
builds Ant's gateway router in process, as antd builds it, configured as Freedom
configures Ant (no CORS origins). The node loop beneath the router is private to
`ant-p2p`, so the arms these requests reach are ported from its `behaviour.rs` at
the same commit (`src/node.rs`), over a memory chunk source; a missing chunk is a
miss the network corroborated. Every random input comes from a label: content is
`content(seed, n)`, encryption keys `key_stream(label)`, feed owners
`keccak256(label)`, and the clock is fixed (`meta.clock_unix`).

For IPFS, it runs Kubo v0.43.1, the binary `KUBO_BIN` names, offline in a
repository of its own: `ipfs add` writes the fixtures, `ipfs dag export` gives
their blocks, and `ipfs daemon --offline` serves the trustless answers on loopback
(each answer's `Date` header left out). freedom-ipfs's `GatewayCore`, at the
commit `freedom-ipfsd` pins (e7dcc6f), answers over a memory provider holding the
same blocks, each request through the native-request parser as `freedom-ipfsd`
makes it. IPNS records are signed by the generator from seeded keys, with
validities far from any day it runs, and `verify_ipns_record` gives each verdict.
Generation takes about two and a half minutes, most of it the 8,192-bit RSA key.

```sh
cd vectors/dweb-verify
export KUBO_BIN=/path/to/kubo/ipfs  # kubo_v0.43.1_linux-amd64.tar.gz; its SHA-512 is in meta.kubo
cargo run --release -- generate   # rewrites ../dweb-verify.json and ../dweb-verify-cases.json
cargo run --release -- check      # regenerates both in memory and compares bytes
cargo run --release -- cases      # rewrites only the cases, from the committed dweb-verify.json; no node runs
```

The cases (`src/cases/`) are the design's: each outcome is written out by hand,
and the generator only lays the bytes out, signs them, and checks each case's
shape. It also records what Ant's and freedom-ipfs's own checks say of the same
bytes. For chunks, feed updates, blocks and IPNS records it refuses to write a
case where they disagree with `expect` and the case names no deviation (a
block's codec, which `verify_block` doesn't read, aside); freedom-ipfs's CAR
parser, which reads the node's own imports and checks no header field, is
recorded for reference only. It checks its MurmurHash3 against SMHasher's
verification value and against Kubo's HAMT, every name of which must sit where
the hash puts it.

Normal CI reads the committed file and never builds the generator. The
`dweb-verify vectors` workflow builds it and runs `check`, and runs `cargo deny
--locked check` against the generator's own `deny.toml`, only when the generator
or the file changes. That policy is the core's, with the advisories the pinned
nodes' graphs carry, each explained: the generator ships in nothing, and its
only sockets are to the Kubo it starts, offline, on loopback.

`bee-check/` is a one-off cross-check against Bee's own writers at a93fb7a7, not
part of CI. It needs Go 1.26 and Bee's module; run it after `generate`, then
`generate` again, since the generator copies its `result.json` into `meta`:

```sh
cd vectors/dweb-verify/bee-check
go run . ../../dweb-verify.json result.json
```

For each file case it splits the same content with Bee's pipeline at the case's
redundancy level, and for each manifest Bee's upload handlers write (a single file,
a directory, a feed) it repeats what those handlers do, then compares references.
Every case agrees but the two where Ant's level-0 splitter wraps a level's lone
leftover reference, which Bee carries up unwrapped; those sizes also carry Bee's
tree as a `-bee` case, which the check finds equal to Bee's.
