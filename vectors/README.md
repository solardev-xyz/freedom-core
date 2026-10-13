# Golden vectors from the desktop JavaScript

**These are public test secrets. Never fund these keys, wallets or addresses, and never use these passwords or mnemonics for real data.**

The oracle is Freedom Browser at commit
`fb540328162839e68150fe2c5e517edb86734d1c`. The generator imports its real
`src/main/identity/{derivation,formats,vault}.js` with `createRequire` anchored in
that checkout. It uses the installed packages from that checkout and adds no npm
dependencies. It does not implement derivation, encryption or identity encoding.

| File | Contents |
| --- | --- |
| `keys.json` | Six mnemonic seeds; user and publisher keys at indices 0, 1, 2, 1000 and 2147483647; Bee, Radicle and IPFS keys; exact index errors and special JS inputs for every mnemonic. |
| `mnemonic-validation.json` | Valid 12/15/18/21/24-word phrases, checksum/word/type/case/spacing/Unicode failures, accepted compatibility forms, seeds and wallet 0 for accepted inputs. |
| `signing.json` | Design 0002's signing contract, from the reference's ethers and bee-js: EIP-155 and EIP-1559 transactions (`Wallet.signTransaction`, with `keccak256` hashes), EIP-191 messages, EIP-712 typed data (signature and `TypedDataEncoder.hash`, including the Safe, x402 and Permit2 payloads and every ethers rejection), and single-owner chunks (`makeContentAddressedChunk(…).toSingleOwnerChunk(…)`) for account, Bee wallet and publisher keys. Inputs are in the core's wire form. Entries marked `deviation` are signed by ethers but must be rejected by the core. It has its own `meta`, which adds the bee-js packages. |
| `naming.json` | Design 0003's codec contract, from the reference's own `ens-resolver.js`, `tezos-domains-resolver.js` and `ccip-fetch.js`. A harness reaches their internal functions by appending test-only exports to the original source and stubbing Electron, so no reference code is copied. It covers ENS names (trim, `fastNormalize`, ethers' `namehash` and `dnsEncode`, and the stage that refuses a name), coin types, contenthash (quirks included), the ABI rules (whole-decode failures versus deferred field errors), Universal Resolver calls, results, reverts, `OffchainLookup` and callbacks, CCIP gateway policy and answers (through `ccipReadFetch` with a fake transport), and the Tezos encodings, Micheline helpers and published URIs. Its `meta` adds `@adraffy/ens-normalize`. |
| `chain.json` | Design 0005's codec contract (step 1), from the reference's own `chain-data-router.js` through the same harness as `naming.json`; the router's modules are stubbed, and observers wrapped around its internal functions record, without changing anything, the errors each source throws. It covers `normalizeParams` for `eth_call` and `eth_estimateGas` (`BigInt` quirks, the `input` alias, property order and `JSON.stringify` output) and the UTF-16 units `BigInt(string)` trims; `stableValue` strings with their SHA-256 and equivalence pairs (duplicate keys, number spellings, `__proto__`, lone surrogates, `undefined`); answers through the real `requestRpcUrl` and Node's `Response` (statuses, BOMs, UTF-8 replacement, V8's grammar, `result`, `error`, bodies that aren't objects); `feeQuote`; `safeErrorMessage` and its whitespace; the aggregate errors of `request`, `getFeeQuote` and `broadcastRawTransaction`; ethers' `keccak256` of signed transactions; `READ_METHODS`, the sources' capabilities and the source order with its `No chain source left …` and `Unsupported read method` texts; Myotis reads through the real `requestMyotis` (the gates, `assertMyotisAnswer`'s classes with each error's code, data and finality, the per-method answers, each payload also in main's snake_case wire form) and `myotisTrust`'s block; the Ant bridge's `rankLogScanError` and `logScanRangeCap` (with every pattern's source and flags) and the range refusal text; and `blockscout-logs.js`'s filter, mappers, agreement, cooldowns and paging through `fetchBlockscoutTransferLogs` with scripted pages (its redirect and DNS policy stays with main). `broadcast_refusals` is the design's own (deviation `broadcast-outcome`): client error wordings with the classes design 0005 gives them, each answer still read by the router's `requestRpcUrl`; the generator cites each client's source. Strings that may hold lone surrogates are recorded as their JSON text (`*_json`). Entries marked `deviation` are where the core differs by design: `json-depth` (more than 512 levels refused), `json-parse-text` (a fixed text instead of V8's `SyntaxError`) and `bigint-width` (decimal conversions stop below 2^4096). It has the shared `meta`; `response.json()` is the undici bundled with the recorded Node version. |
| `chain-replay.json` | Design 0005's replay harness (step 2): the pinned `chain-data-router.js`, with the real `blockscout-logs.js` and the Ant bridge's real router options (`LOG_SCAN_ROUTER_OPTIONS`, `rankLogScanError`, `logScanRangeCap`), run whole in scripted worlds under the reference's own fake timers. Fresh modules per scenario; global `fetch`, the registry, the Myotis manager (its thrown errors by class, with the manager's and child process's texts), Colibri's `requestViaColibri` and Blockscout's DNS lookups are stubbed; no reference code is copied, and the router's state tables are read through accessors appended to its source. Each scenario has a stable `id` and `from` (the suite test it ports, `file:line` at the pinned commit, or the design 0005 section it pins): the ports of `chain-data-router.test.js`, `ant-log-scan-routing.test.js`, `ant-log-index-routing.test.js`, `ant-chain-bridge.router.test.js` and `blockscout-logs.test.js`'s paging, page, cooldown, redirect and DNS cases (through the router), then the design's named boundary cases (`boundary-*`). It records its world, steps and calls; every call's result or thrown error (class, name, message and own properties in order) with its settlement time; the state tables after each step (adaptive routes, Myotis slots, Colibri's in-flight work, log-range learning, Blockscout cooldowns; instants in virtual milliseconds); and every I/O request with its call, virtual start and end, outcome and answer: JSON-RPC exchanges (`id` normalized to 0), Myotis and Colibri operations, Myotis status samples, Blockscout reads, pages, HTTP hops and DNS lookups (each `within` the operation it belongs to). Encodings are in its `encodings`. Every value the reference produced or was given (results, thrown properties, operation params and answers, call params) is JSON text in a string field (`*_json`, or `json` in an entry), never a JSON value, so none can pass for an encoding and every value `JSON.parse` makes survives: lone surrogates as escapes, any nesting, `-0` and ±Infinity (written `-0` and `±1e400`). A present `undefined` is a field of its own (`*_undefined: true`). An object the router returned or threw is a list of entries in property order. A text over 64 KiB is written in its field's repeat form (`*_json_repeat`, `body_repeat`: head, unit, count, tail, length and SHA-256), so the `html()` 8 MiB answers stay small. Worlds, steps and state tables are plain JSON. Ported calls carry the settle times their tests assert (`expect_settle_ms`, or a bound), and generation fails if a fixture drifts from them; scripted answers are immediate unless they name a delay, as the suites' mocks are. Ant's scan loops are recorded call by call. Calls with `options` use router options no production caller passes alone. `boundary-json-depth-513` is marked `deviation: json-depth` (the reference reads it; the core refuses the body); there are no patched deviation vectors yet. Its `meta` adds `@sinonjs/fake-timers`. |
| `dweb.json` | Design 0006's transport contract (step 2), from the reference's own `bzz-protocol.js`, `ipfs-protocol.js`, `ipfs-manager.js`, `content-name-resolver.js`, `lib/gateway-location.js`, `lib/gateway-response-headers.js`, `shared/cid-utils.js`, `shared/origin-utils.js`, `onchain-html.js` and `onchain-app-protocol.js`, through the same harness as `naming.json`. Name resolution is stubbed: each case scripts what the resolver returns or throws, and records which resolver the handler asked. It covers whole requests through the real handlers (`bzz:` hash and name hosts, encoded separators, published base paths, the 404/415/502 mapping, CIDs and IPNS keys in every multibase, lowercased hosts, gateway-form 307s and 400s, both header policies, methods, and backends that aren't up, each mode with its own text; a request's `backend` is `{ ant | ipfs: mode, up }`), whole exchanges with scripted node answers (redirect rewrites, header strips, small text with lying lengths and oversized chunks, counting the reads), `rewriteGatewayLocation` and `decodeURIComponent` directly, the response operations, failures after the dial, the `html()` decode and its caps (8 MiB documents as `recipe`s), and the gate's class. `plan` composes the reference's outcome (`js`) with the tables in `constants`; its response operations, trust labels and `body_idle_ms` are the design's, and so is all of `validation` (`source: design`), which has no reference; there, `{ "$repeat": [text, count] }` stands for a long string. Entries marked `deviation` are where the core differs by design: `native-page-state` (page-state headers are stripped from the native IPFS node's answers too). It has the shared `meta`. |
| `identity-formats.json` | Deterministic IPFS private-key protobuf/base64 and PeerID; Radicle DID, node ID and public SSH file with default `FreedomBrowser` comment and custom `vector-alias`; `didFromPublicKey`. |
| `fixtures/vaults.json` | Exact vault file contents from real `importVault`, including timestamps and the embedded encrypted JSON string. Five password/mnemonic cases, parsed payloads, successful unlocks, exact failing files/passwords/outcomes, plus one explicitly synthetic positive legacy vault. |
| `fixtures/bee-keystores.json` | Two actual `createBeeKeystore` outputs, passwords, expected keys/addresses, parsed JSON, KDF parameters and the Unicode password normalization check. |
| `fixtures/radicle-openssh.json` | Twelve actual `createRadicleIdentity` results (six mnemonics, two comments), extracted check integers and padding; checked by parsing and replaying the same check integer through the reference JS. |
| `generator/generate.js` | Plain CommonJS generator and verifier. |
| `generator/signing.js` | The signing cases and their builder, used by `generate.js`. |
| `generator/chain.js` | The chain-data cases and their builder, used by `generate.js`. |
| `generator/chain-replay.js` | The chain-data replay harness and its scenarios, used by `generate.js`. |
| `generator/dweb.js` | The dweb transport cases and their builder, used by `generate.js`. |
| `generator/check.test.js` | Integration tests that damage copies of the oracle outputs and require `check` to fail. |

Every JSON file has a `meta` block with the full reference commit, actual installed
package versions, Node version and generator path. The deterministic files use
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

From a clean reference checkout at that commit, install its lockfile dependencies
(this changes no tracked files):

```sh
cd /root/herdr/freedom-browser
ELECTRON_SKIP_BINARY_DOWNLOAD=1 npm ci --ignore-scripts
```

Then, from the freedom-core worktree:

```sh
node vectors/generator/generate.js generate --freedom-browser /root/herdr/freedom-browser
node vectors/generator/generate.js check --freedom-browser /root/herdr/freedom-browser
node --test vectors/generator/check.test.js
```

The integration tests use `/root/herdr/freedom-browser` by default; set
`FREEDOM_BROWSER_CHECKOUT` to use a different clean checkout. Run with the Node
version in `meta`: the runtime version is part of the byte comparison. The
generator refuses a different commit or a dirty reference checkout.

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
