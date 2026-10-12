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
| `chain.json` | Design 0005's codec contract (step 1), from the reference's own `chain-data-router.js` through the same harness as `naming.json`; the router's modules are stubbed, and observers wrapped around its internal functions record, without changing anything, the errors each source throws. It covers `normalizeParams` for `eth_call` and `eth_estimateGas` (`BigInt` quirks, the `input` alias, property order and `JSON.stringify` output) and the UTF-16 units `BigInt(string)` trims; `stableValue` strings with their SHA-256 and equivalence pairs (duplicate keys, number spellings, `__proto__`, lone surrogates, `undefined`); answers through the real `requestRpcUrl` and Node's `Response` (statuses, BOMs, UTF-8 replacement, V8's grammar, `result`, `error`, bodies that aren't objects); `feeQuote`; `safeErrorMessage` and its whitespace; the aggregate errors of `request`, `getFeeQuote` and `broadcastRawTransaction`; and ethers' `keccak256` of signed transactions. Strings that may hold lone surrogates are recorded as their JSON text (`*_json`). Entries marked `deviation` are where the core differs by design: `json-depth` (more than 512 levels refused), `json-parse-text` (a fixed text instead of V8's `SyntaxError`) and `bigint-width` (decimal conversions stop below 2^4096). It has the shared `meta`; `response.json()` is the undici bundled with the recorded Node version. |
| `identity-formats.json` | Deterministic IPFS private-key protobuf/base64 and PeerID; Radicle DID, node ID and public SSH file with default `FreedomBrowser` comment and custom `vector-alias`; `didFromPublicKey`. |
| `fixtures/vaults.json` | Exact vault file contents from real `importVault`, including timestamps and the embedded encrypted JSON string. Five password/mnemonic cases, parsed payloads, successful unlocks, exact failing files/passwords/outcomes, plus one explicitly synthetic positive legacy vault. |
| `fixtures/bee-keystores.json` | Two actual `createBeeKeystore` outputs, passwords, expected keys/addresses, parsed JSON, KDF parameters and the Unicode password normalization check. |
| `fixtures/radicle-openssh.json` | Twelve actual `createRadicleIdentity` results (six mnemonics, two comments), extracted check integers and padding; checked by parsing and replaying the same check integer through the reference JS. |
| `generator/generate.js` | Plain CommonJS generator and verifier. |
| `generator/signing.js` | The signing cases and their builder, used by `generate.js`. |
| `generator/chain.js` | The chain-data cases and their builder, used by `generate.js`. |
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
