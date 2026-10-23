# 0002: Signing in the core (Phase 2)

**Status:** proposed. Builds on [0001](0001-freedom-cored.md). After this phase, no raw signing key leaves the core except through the permanent, user-requested backup exports. The node identities are separate exceptions: Bee's keystore file, and the sealed release of the Radicle node key to its service ([0001](0001-freedom-cored.md), *Deliberate exceptions*).

## Summary

Phase 1 moved the vault and every key into `freedom-cored`. JS still signs with raw keys it fetches through the temporary `compat.*` exports: `compat.private_key` for user accounts, `compat.bee_wallet_key` and `compat.publisher_key` for Swarm. Phase 2 moves every signature made with a vault key into the core and then deletes `compat.*`.

Freedom Browser signs with vault keys in exactly two places:

- **ethers v6** in `src/main/wallet/signers.js` (the vault signer backend):
  - transactions: legacy with EIP-155, and EIP-1559;
  - EIP-191 `personal_sign`;
  - EIP-712 `eth_signTypedData_v4`.

  Its callers are the wallet UI, dApp requests, Safe (SafeTx, EIP-1271 SafeMessage, the executor EOA) and x402 (EIP-3009 TransferWithAuthorization, Permit2 PermitWitnessTransferFrom).
- **bee-js** in `src/main/swarm/{chunk,feed}-service.js`: single-owner chunks (SOC) for `swarm_writeSingleOwnerChunk`, feed updates and feed payloads. The key is the Bee wallet or a per-origin publisher key. A user account (the `ethereum-wallet` identity mode) is a third choice today, which main removes ([Accounts as feed owners](#amendment-accounts-as-feed-owners-89)).

Nothing else signs with a vault key. GSOC signs with keys it mines itself. The Ant node signs postage and cheques with the keystore that `nodes.write_identity` writes. Ledger, phone and Safe accounts keep their own signers.

The core gets five methods:
- four that sign: `sign.transaction`, `sign.message`, `sign.typed_data` and `swarm.sign_soc`;
- one public hash: `typed_data.hash`, so that main never computes an EIP-712 digest that a vault key will sign with weaker rules than the core's.

Each returns exactly the bytes ethers or bee-js return today, and each signing method takes a key **reference**, never key bytes.

## Goals and non-goals

**Goals**
- **No raw signing key outside the core.** After the browser migrates, `compat.*` is removed. Main never holds a vault signing key again, and neither does the Swarm path, which today keeps one alive for seconds while it uploads. The node identities stay outside this goal: Bee's key is written to its node's keystore file, and the Radicle node key goes to its service sealed, so main relays it without reading it ([0001](0001-freedom-cored.md), *Deliberate exceptions*; [0008](0008-radicle-service.md), *Keys*). Main loads the Radicle key itself only while the add-on runs there.
- **Byte-exact parity.**
  - The same key and input give the same raw transaction, signature or SOC as today. ethers and k256 both sign with RFC 6979 deterministic nonces and low-s, so the signatures are identical, not just valid.
  - Golden vectors from the pinned JS check this (see [Parity](#parity-contract-and-vectors)).
  - Where ethers is dangerously lenient, the core is stricter. Every such case is listed under [Deviations](#deviations-from-ethers) and has a vector.
- **Least authority per key.**
  - User accounts sign transactions, messages and typed data.
  - The Bee wallet and publisher keys sign **only** SOCs.
  - A SOC's chunk address is computed in the core from the chunk itself, so every SOC signature is bound to a chunk that actually hashes to that address.
  - **Accounts don't sign SOCs.** An account's 32-byte `sign.message` is exactly a SOC signature, so the binding above holds only for keys that sign nothing else. `swarm.sign_soc` refuses account keys, and main no longer offers accounts as feed owners ([Accounts as feed owners](#amendment-accounts-as-feed-owners-89), decided).

**Non-goals**
- **Approval and policy.** As in 0001's threat model, stage 1 trusts main: it runs the approval UI and decides what gets signed. A compromised main can still:
  - ask for signatures;
  - make a backup export with a password it knows or has recovered;
  - read the Bee node's keystore and its config password.

  Phase 2 removes routine key *exposure*, not main's authority. No signature can be recalled once delivered. Policy moves with the Chromium work.
- **Transaction building:** nonces, gas limits and receipts stay in main. The core signs a fully specified transaction. Fee quotes, chain reads and broadcast routing move into the core with [0005](0005-chain-data.md); until then they stay in main too.
- **Other transaction types:** EIP-2930 access lists, blob (EIP-4844) and set-code (EIP-7702) transactions. Freedom doesn't send them today, and the core rejects them.
- **`eth_sign`** (raw digest signing). Freedom rejects it today and the core doesn't offer it.
- **Ledger, phone and Safe accounts.** Safe owners that are vault accounts sign through the core like any other account.
- **The Ant node's own signing** (postage, cheques) is unaffected. The SOC-only rule for the Bee wallet constrains the core's signing API, not the node.

## Key references, callers and execution

The signing methods take `key`:

| `key` | Key | Derivation (unchanged from 0001) | Allowed in |
|---|---|---|---|
| `{ "kind": "account", "index": n }` | user wallet *n* | `m/44'/60'/n'/0/0` | `sign.transaction`, `sign.message`, `sign.typed_data`; never `swarm.sign_soc` ([#89](#amendment-accounts-as-feed-owners-89)) |
| `{ "kind": "bee_wallet" }` | Bee wallet | `m/44'/60'/0'/0/1`, distinct from every account | `swarm.sign_soc` only |
| `{ "kind": "publisher", "origin_index": n }` | Swarm publisher key for an origin | `m/44'/73406'/n'/0/0` | `swarm.sign_soc` only |

- **Index range:** the same as `compat.private_key` and `compat.publisher_key` (`0..=2147483647`).
- **Wrong method:** a key kind used outside its row returns `invalid_argument`.
- **Main keeps its guards.** Main still refuses hardware-range indices and non-mnemonic wallet records before it asks the core, as `vault-access.js` does today.
- **Callers:** all five methods accept the `chrome` and `shell` callers, like Phase 1. The `page` caller stays reserved: binding a page's approval to a key and an operation belongs to the policy phase, not this one. Main keeps making these requests on a page's behalf after its own approval.
- **Locking and the timer:**
  - The signing methods need an unlocked vault and return `vault_locked` otherwise. `typed_data.hash` is public and works while locked.
  - The signing methods don't touch the auto-lock timer. Main keeps calling `vault.touch` where it does today.

**Execution.** Signing runs inline on the core's event loop, as `compat.*` does today (`vault.rs`), not on the KDF worker. Each method:

1. does all its public work first: parsing and validation, RLP, EIP-712 hashing, BMT. The [limits](#limits) bound this work.
2. then derives the key and makes one signature;
3. then replies.

No secret is held while untrusted input is processed. A request either signs within one turn of the loop or fails before it touches a key. Lock and epoch semantics are therefore those of `compat.*`: a request admitted before a lock completes; any later one returns `vault_locked`.

## API

Byte strings are `0x`-prefixed hex. They are lowercase in replies; requests take either case. Quantities are JSON strings: `[-]` then decimal digits, or `[-]0x` hex digits. Leading zeros are allowed. Transaction quantities are unsigned: no `-` at all, not even `-0`. They are the core's own wire format, which main produces from ethers' parsed values. Unknown fields are rejected, as in 0001.

### `sign.transaction`

`{ key, tx }` → `{ raw, hash }`

| `tx` field | Type | Notes |
|---|---|---|
| `type` | `0` or `2` | legacy (always with EIP-155) or EIP-1559 |
| `chain_id` | quantity ≥ 1 | required. ethers would sign a chain-less legacy transaction when `chainId` is missing; the core never does. For type 0, `chain_id · 2 + 36` must fit in 256 bits (`chain_id ≤ 2^255 − 19`), so that `v` fits for either parity. At `2^255 − 18`, `v` fits only for parity 0; that transaction is valid, but the core still refuses the value. Further above, ethers signs with a `v` wider than 256 bits, which its own `Transaction.from` rejects. For type 2, any uint256 |
| `nonce` | quantity ≤ 2^53 − 1 | ethers keeps the nonce in a JS number and fails above that ("overflow") |
| `gas_limit` | quantity | |
| `to` | address or `null` | `null` creates a contract. Hex only (ethers would try to resolve an ENS name; main resolves before signing) |
| `value` | quantity | |
| `data` | bytes | `"0x"` when empty |
| `gas_price` | quantity | type 0 only |
| `max_fee_per_gas`, `max_priority_fee_per_gas` | quantity | type 2 only. Priority ≤ max, as ethers requires |

- **`raw`:** byte-for-byte `Wallet.signTransaction(tx)`.
  - Type 0: `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])` with `v = chainId·2 + 35 + yParity`, computed in 256 bits.
  - Type 2: `0x02 ‖ rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, [], yParity, r, s])`.
- **Three different "v" values, kept apart:**
  - `yParity` is 0 or 1, and is what type 2 encodes;
  - the legacy `v` is EIP-155's network value above;
  - the 27/28 byte belongs to message signatures only.
- **`hash`:** `keccak256(raw)`, which is what main records before broadcasting.

### `sign.message`

`{ key, message }` → `{ signature }`

- **`message`:** the bytes to sign. Main keeps today's normalization (`signing-utils.js`): a `0x` string is hex-decoded, anything else is signed as UTF-8. It sends the resulting bytes as hex. Main must validate the hex strictly: `Buffer.from(hex, 'hex')` stops silently at the first invalid character.
- **`signature`:** EIP-191 over `"\x19Ethereum Signed Message:\n" ‖ len ‖ message`. It is 65 bytes `r ‖ s ‖ v` with `v ∈ {27, 28}`, byte-for-byte `Wallet.signMessage(bytes)`.

### `sign.typed_data` and `typed_data.hash`

- `sign.typed_data { key, typed_data: { domain, types, message }, expected_hash, primary_type?, chain_id? }` → `{ signature, view }`. It signs only if the digest is `expected_hash`, the hash the user confirmed.
- `typed_data.hash { typed_data, primary_type?, chain_id? }` → `{ hash, view }`: the same digest, with no key. It is public, works while locked, and applies the same validation and limits.
- `view` is what is signed, for the approval UI to render; `primary_type` and `chain_id` are compared with the data and reported in it, and change nothing that is signed ([What the user is shown](#amendment-what-the-user-is-shown-88), decided).

This is EIP-712 with ethers v6 `TypedDataEncoder` semantics, which is what `Wallet.signTypedData(domain, types, message)` does today. Main already strips `EIP712Domain` from `types` and leaves `primaryType` out of `typed_data`; it keeps doing both, and passes the dApp's `primaryType` beside it as `primary_type`.

- **Types:**
  - The primary type is inferred as the single type that no other type references. No root, several roots (unused types count), a cycle reachable from the primary type, a duplicate field name, an unknown type and an ill-formed width (`uint7`, `uint08`, `bytes33`) are errors, as in ethers.
  - A cycle that is *not* reachable from the primary type is accepted, as in ethers.
  - `uint` and `int` mean `uint256` and `int256`, unless a struct with that name exists. Array suffixes keep their written form in `encodeType`, as in ethers.
- **Domain:**
  - The keys `name`, `version` (strings), `chainId` (quantity), `verifyingContract` (address) and `salt` (32 bytes). The domain type is built from the keys present, in that order.
  - A key whose value is `null` is skipped, even an unknown one. Any other key is an error.
- **Values:**
  - `uintN` and `intN` take a quantity string or a JSON number whose value is an integer within ±(2^53 − 1), range-checked for N. A non-integral number or an unsafe integer is an error, as in ethers.
  - **A JSON number is read as `JSON.parse` reads it:** correctly rounded to the nearest double, ties to even, and then judged. So `1e2` and `5.0` are 100 and 5, `4503599627370496.5` (2^52 + ½) is 2^52, and `9007199254740991.5` is 2^53, an unsafe integer. Spelling doesn't matter: `45035996273704965` followed by 752 zeros and `e-753` is the same 2^52 + ½, so 2^52, and 2^-1075, halfway to the smallest subnormal, is 0. Main sends `JSON.stringify` output, which never writes such a literal, but a caller that passes a dApp's own JSON text (the mobile FFI) must get the integer ethers signs and the approval UI shows.
  - **How:** the core reads request text with `fc_evm::parse_json`. serde_json gives the structure; each number it holds as a double (a fraction, an exponent, or an integer past 64 bits) is read again from its own spelling, found through `fc-json`'s index. The spelling is first normalized to `0.d1…dn × 10^E` exactly, with the explicit exponent and the decimal point's position combined in 128-bit arithmetic: past E > 310 it is infinite, below E < −324 it is 0 (under half the smallest subnormal), and otherwise Rust's correctly rounded `f64` parser reads `0.d1…dne<E>`. Neither parser alone will do: serde_json's default one rounds approximately (2^52 + ½ becomes 2^52 + 1), its `float_roundtrip` one misrounds padded spellings and halfway subnormals, and Rust's stops reading an explicit exponent at 0x10000 before adding the point's position, so `0.`, 655,359 zeros and `1e+655360`, exactly 1, would read as 0. `typedDataText` in `vectors/signing.json` pins these cases against ethers, given as text.
  - `bytesN` takes exactly N bytes and `bytes` takes any; both are hex with `0x` or `0X`.
  - `string` takes a JSON string.
  - `address` takes `0x` and 40 hex digits: all-lowercase, all-uppercase, or EIP-55 mixed case with a valid checksum. Without `0x`, ethers tries ENS when signing and fails.
  - Arrays: `T[]` and `T[n]`, with the length checked for `T[n]`. Structs nest.
  - An extra message field is ignored, as in ethers. The approval UI shows the core's view of what is signed, and lists a top-level extra field as sent but not signed ([What the user is shown](#amendment-what-the-user-is-shown-88)).

### `swarm.sign_soc`

`{ key, identifier, span?, payload }` → `{ signature, owner, chunk_address, soc_address, span }`

- **Inputs:**
  - `identifier`: 32 bytes, hex.
  - `payload`: **1–4096** bytes, hex. bee-js rejects an empty payload.
  - `span`: a u64 quantity, optional. If absent or **0**, it is the payload length. This matches bee-js, which treats a `0n` span as omitted, and the browser passes `0n` for a zero span. Any other value is used as given: for the root chunk of a `/bytes` upload, which `writeFeedPayload` wraps, it is the whole content length, and it may even be smaller than the payload, as bee-js allows.
- **Computed in the core (`fc-swarm`):**
  - `chunk_address` = keccak256(`span` as 8 bytes little-endian ‖ BMT root). The BMT root is computed over `payload` alone, zero-padded to 4096 bytes: 128 segments of 32 bytes, hashed pairwise with keccak256. The span is not a leaf.
  - `digest` = keccak256(`identifier` ‖ `chunk_address`).
  - `signature` = EIP-191 over the 32-byte digest, with `v ∈ {27, 28}`.
  - `owner` is the key's address.
  - `soc_address` = keccak256(`identifier` ‖ `owner`).
- **Parity:** the output equals bee-js's `makeContentAddressedChunk(payload, span).toSingleOwnerChunk(identifier, key)`. Main uploads `span ‖ payload` to Bee's `/soc/{owner}/{identifier}?sig=…` as bee-js does today.
- **Why the core computes the chunk address:** an API that took the chunk address from main would let main get the Bee wallet and publisher keys to sign statements about chunks that don't exist (any identifier and chunk-address pair). Hashing the payload in the core binds every SOC signature to a real chunk. Raw-digest signing stays unavailable regardless.
- **No account keys:** that binding holds for the Bee wallet and publisher keys, which only sign SOCs. An account also signs `sign.message`, whose 32-byte case produces exactly a SOC signature, so `swarm.sign_soc` refuses account keys with `invalid_argument` ([Accounts as feed owners](#amendment-accounts-as-feed-owners-89)).

### Errors

- **`invalid_argument`** (0001's code) covers every malformed input: wrong key kind, an invalid quantity, range, length, checksum or type, an unsupported transaction type, a typed-data violation, an oversize payload, or an exceeded limit. It also covers a typed-data digest that isn't `expected_hash`, and typed data whose signing reply wouldn't fit one frame, one bound for both methods ([#88](#amendment-what-the-user-is-shown-88)). It carries a description. Main maps it the way it maps ethers' errors today: a dApp request fails, and no signature is made.
- **Locked vault:** `vault_locked`, as for `compat.*`.

## Deviations from ethers

ethers accepts each input below; the core refuses it. Each is a `deviation` vector, which records that ethers signed it and requires the core to reject it, except `view-size`, whose inputs are too large for a vector and are covered by Rust tests, as the [limits](#limits)' byte caps are.

| Input | ethers | Core |
|---|---|---|
| `bool` given `"false"`, `"0"`, `1`, or another non-boolean | encodes truthiness, so `"false"` signs as **true** | only JSON `true` / `false` |
| `bool` field missing or `null` | encodes **false** | error, like every other missing field |
| quantity string with whitespace, `+`, `0b`/`0o`, or a lone `-` (which ethers reads as 0) | JS `BigInt()` accepts it | only `[-]digits` or `[-]0x hex` |
| a type or field name that isn't an identifier (`[A-Za-z_$][A-Za-z0-9_$]*`, ≤ 256 characters) | any string, so a name containing `(`, `,` or a space can make two different type sets print the same `encodeType` | error |
| a type named like a primitive (`bool`, `uint256`, `bytes32`, even `uint7`) | as the primary type, encoded with the primitive's encoder: a struct `bool` hashes as true | error |
| a struct value that isn't an object: `null`, a string, or missing, for a struct with no fields | reads no fields, so anything passes | error: a struct value must be an object |
| inputs past the [limits](#limits) | no limits; its subtype walk is exponential on diamond-shaped type graphs | error |
| type 0 `chain_id` above 2^255 − 19 | at 2^255 − 18, a valid transaction for parity 0; further above, a `v` wider than 256 bits that ethers itself can't parse | error: the bound guarantees `v` fits for both parities |
| typed data whose signing reply, with its `view` and at the largest ID, wouldn't fit one 1 MiB frame (`view-size`, [#88](#amendment-what-the-user-is-shown-88)) | signs it: ethers has no view and no frame | error, from `typed_data.hash` and `sign.typed_data` alike, at that one bound, measured before any key is derived |
| a type named `EIP712Domain` (`domain-type`, [#88](#amendment-what-the-user-is-shown-88)) | signs it as a struct when the primary type references it, though its own `getPayload` refuses such types | error: there would be no view to match. Main strips the type from a dApp's typed data, so a dApp's request never reaches this |
| a field named `__proto__`, in any struct (`proto-name`, [#88](#amendment-what-the-user-is-shown-88)) | hashes the field, but its visitor assigns it into a plain object, so its `getPayload` omits it; `signTypedData` signs that copy, without the field (as `false` for a `bool`), or fails | error: there would be no view to match, and main, in JavaScript, couldn't carry the key through ordinary objects. A type named `__proto__` is refused too; ethers fails on one |

**Reported, not refused** ([#88](#amendment-what-the-user-is-shown-88)). Two cases sign exactly as ethers signs, and the view reports them for the approval UI to warn:
- **`primary-type`:** a `primary_type` that isn't the inferred root. ethers ignores `primaryType`, and the core signs the inferred root too, byte for byte. Proposed as a refusal; the user decided on a warning, so it isn't a deviation.
- **`chain`:** a domain `chainId` that differs from `chain_id`, or is absent.

Their vectors are parity vectors: ethers' signature, with the view's report as this document gives it.

## Limits

Typed-data work is bounded before any key is touched:

- **Types:**
  - at most 256 types, 256 fields per type, and 1024 fields in total;
  - names of at most 256 characters;
  - at most 32 array dimensions in one type;
  - at most 1 MiB of `encodeType` text in total, counting each struct's text once for itself and once for every struct whose type hash includes it.
- **The message:**
  - nesting depth (struct levels plus array levels) at most 32;
  - at most 100,000 values encoded (fields, array elements, structs);
  - at most 32 MiB hashed. A 1 MiB frame can drive about 22 MiB, so this cap never binds before the others do.

The subtype closure is computed once per type (memoized), and each reachable type's hash is computed once per request, not per instance. The work is therefore linear in the input, within these caps.

**Measured** (release build, this machine):
- The worst accepted request, 99,999 empty struct instances under a type with a 256-character name, takes about 50 ms.
- 99,999 `uint256` values take about 12 ms.
- A realistic request (the Mail example) takes about 8 µs.

That 50 ms is the longest a signing request can hold the core's event loop. Tests check that accepted inputs just under the caps take linear time: each is timed against inputs that linear work takes as long over (the same input in tenths or thirtieths, or a type with a fraction of the text), back to back in the same run, so neither the machine's speed nor its load decides the outcome. They also check the rejections at the caps, and a 40-level diamond type graph, which ethers' walk would take 2^40 steps over.

## Parity contract and vectors

`vectors/signing.json` comes from the pinned reference checkout, like the Phase 1 vectors (#17). It uses that checkout's own ethers 6.17.0 and bee-js 13.1.0, with keys from the Phase 1 test mnemonics. Every case records ethers' or bee-js's actual result: a success, an error, or a success marked as a deviation.

| Area | Cases |
|---|---|
| Transactions | <ul><li>Type 0 and type 2.</li><li>Chain ids 1, 100, 11155111, 2^32, above 2^53 and above 2^64.</li><li>The legacy `chain_id` limit, values above it (deviations), and the type-2 bounds (2^256 − 1 signs; 2^256 is an error).</li><li>Nonce 0, small, and 2^53 − 1; 2^53 is an error.</li><li>Value 0 and 2^256 − 1.</li><li>Empty and long data; contract creation.</li><li>Priority = max; priority > max is an error.</li></ul> |
| EIP-191 | Empty, ASCII, multi-byte UTF-8, binary, SIWE, and 1000 bytes (multi-digit length prefix). |
| EIP-712 | <ul><li>The EIP-712 Mail example; nested structs and arrays of structs, fixed and dynamic.</li><li>The bounds of every `uintN`/`intN` width (8 to 256), and the first value past each; the `uint`/`int` aliases; quantity forms (hex, signed hex, leading zeros, `-0`).</li><li>The limits that ethers accepts and the core refuses: name length, type count, fields per type, array dimensions, depth. The value and byte caps are too large for a vector and are covered by Rust tests.</li><li>`bytesN` and `bytes`; lowercase, uppercase and checksummed addresses; Unicode strings.</li><li>Domain subsets, including a hex-string `chainId`, `salt`, null fields (known and unknown), chain id 0 and an empty domain.</li><li>Empty structs; an unreachable cycle (accepted); extra message fields (ignored).</li><li>The real payloads: Safe 1.4.1 SafeTx and SafeMessage, EIP-3009 TransferWithAuthorization, and Permit2 PermitWitnessTransferFrom with string quantities.</li><li>Every ethers error kind, and every [deviation](#deviations-from-ethers).</li><li>Typed data given as JSON text: ties, padded ties and halfway subnormals, as `JSON.parse` reads them.</li><li>The view ([#88](#amendment-what-the-user-is-shown-88)): `getPayload`'s output for every case that hashes, with `chainId` at 0, 1, 2^53 − 1 and 2^53; the `primary_type` and `chain_id` reports, expected from this text.</li></ul> |
| SOC | <ul><li>Payloads of 1, 32, 33 and 4096 bytes.</li><li>Spans above and below the payload length, and span 0.</li><li>All three key kinds, as bee-js signs with each. `fc-swarm` replays them all; over the wire, an account key's cases must be refused ([#89](#amendment-accounts-as-feed-owners-89)).</li></ul> |

Rust tests replay every case, in the crates (#18) and over the wire through the binary (#19). A CI job checks out freedom-browser at the pinned commit, installs its lockfile, and runs the generator's `check` mode, which re-derives every vector from the reference. A drift on either side fails CI.

## Implementation

- **`fc-evm` (logic crate, no I/O):**
  - a minimal U256;
  - RLP;
  - the two transaction serializations;
  - EIP-191;
  - the EIP-712 encoder above, written from ethers' source because parity, including which inputs are rejected, is the contract;
  - the view of what is signed, built and measured in the pass that hashes ([#88](#amendment-what-the-user-is-shown-88));
  - the signature format.
- **`fc-swarm` (logic crate, no I/O):** the BMT, the chunk address, and SOC signing.
- **Dependencies:** none new. `k256` (RFC 6979, low-s, recovery id), `sha3`, `serde_json` and `thiserror` are already in the workspace, and `fc-evm` reads number spellings with the workspace's own `fc-json`.
- **`freedom-cored`:** the five methods, executed as described in [Execution](#key-references-callers-and-execution), with secrets zeroized after use. Each method is in `fc-protocol`'s method table with its callers (`chrome`, `shell`) and is advertised in `core.hello`'s capabilities.
- Both crates compile for iOS and Android, as CI requires of logic crates.

## Amendment: what the user is shown (#88)

**Status:** decided by the user on 2026-10-22. The core's view of exactly what is signed is built now, not with the policy phase: `typed_data.hash` and `sign.typed_data` return it, the approval UI moves onto it, and `sign.typed_data` refuses any hash other than the one the user confirmed. A view too big for one 1 MiB reply is refused (deviation `view-size`). A `primaryType` that isn't the inferred root is warned about and signed as ethers signs it: the user overrode the proposal to refuse it. A domain `chainId` that is mismatched or absent is warned about, and signed. [Options weighed (#88)](#options-weighed-88) keeps the alternatives, as the decision's rationale.

**Tightened in #112's review** (2026-10-22), consistent with [#89](#amendment-accounts-as-feed-owners-89): a typed-data request with a warning always shows its prompt, even when the site has signing auto-approve.

### Today

The core hashes and signs `{ domain, types, message }`. The approval UI builds its own view from the dApp's JSON (`formatTypedDataForDisplay` in `dapp-sign.js`). The two can differ:

- **Undeclared fields** are shown but not signed, and the hash ignores them silently (ethers parity). A nested struct is shown as JSON, cut at 50 characters with every other value.
- **The domain** is shown partly: `verifyingContract` cut to 10 characters, and `chainId` hidden when it is 0. A domain without `chainId` is never flagged, though its signature is valid on every chain where the verifying contract lives. Nothing compares `chainId` with the dApp's active chain.
- **`primaryType`** is dropped by main, and the core infers the root as ethers does. A request whose `primaryType` names another type means one thing to ethers and another to a wallet that honors `primaryType` (MetaMask's `eth-sig-util` hashes the named type).
- **`personal_sign`** in the reference decodes hex for display pair by pair with `parseInt`, while main signs `Buffer.from(hex, 'hex')`, which stops at the first invalid pair: `0x41zz42` is shown as `A\0B` and signed as `A`. That mismatch is gone once main validates hex strictly ([Migration](#migration-in-freedom-browser) step 1, done on the integration branch), and the core refuses such hex anyway (`parse_bytes`). What remains is that the display decodes its own copy of the message.

### Decision (#88)

1. **The view, now.** `typed_data.hash` and `sign.typed_data` return `view`, the core's account of exactly what is signed, and the approval UI renders it in place of the dApp's JSON. Main gets it before the prompt, and `sign.typed_data` signs only the hash the user confirmed.
2. **A view too big for one reply is refused.** The core measures the reply before it derives any key, and returns `invalid_argument` (deviation `view-size`). Both methods use one bound, the signing reply's, so a request `typed_data.hash` answers is never refused for size once confirmed.
3. **A `primaryType` that isn't the inferred root is warned about, and signed as ethers signs it.** The core signs the inferred root, the view reports the mismatch, and the approval screen warns that the site named a different primary type, and that other wallets could sign something different. The proposal was to refuse it; the user overrode that, so it isn't a deviation.
4. **A domain `chainId` that differs from the dApp's chain, or is absent, is warned about, and signed.**
5. **`personal_sign`** is shown from the bytes main sends, as part of the UI's move.

**Tightened in #112's review,** consistent with #89's 32-byte rule: a request with a warning (a `primaryType` mismatch, or a `chainId` that is mismatched or absent) always shows the approval prompt, even when the site has signing auto-approve. A warning that auto-approve can skip protects nothing.

### What the core does (#88)

- **The API** ([`sign.typed_data` and `typed_data.hash`](#signtyped_data-and-typed_datahash)):
  - `typed_data.hash { typed_data, primary_type?, chain_id? }` → `{ hash, view }`;
  - `sign.typed_data { key, typed_data, expected_hash, primary_type?, chain_id? }` → `{ signature, view }`.
- **The view's content** is ethers' `TypedDataEncoder.getPayload(domain, types, message)`, for the inputs the core accepts ([Deviations](#deviations-from-ethers)):
  - `types`, with the `EIP712Domain` type that `getPayload` adds;
  - `primary_type`: the inferred root, which is what is signed;
  - `domain` with only the fields used, in the domain type's order;
  - `message` with only the declared fields, in declaration order, structs nested.

  Values are normalized as `getPayload` does: integers as decimal strings, bytes and addresses as lowercase hex, and the domain's `chainId` as a hex quantity (`"0x1"`, not `1`: pinned ethers tests `Number.isSafeInteger` on a `BigInt`, which never holds).
- **Three reports** are part of the view too:
  - **`ignored`:** the message's top-level keys the types don't declare, so the UI can say that the dApp sent fields that aren't signed.
  - **`named_type`:** `match` when the `primary_type` parameter is a string equal to the inferred root, `mismatch` for any other value, and `unknown` without the parameter.
    - **Any JSON value is accepted,** and only a string can match. A string is compared exactly, a declared type's name or not.
    - **A non-string is always `mismatch`,** whatever the types: `true`, `false` and `null` are valid struct names, so comparing a non-string's JSON text could match a root of that name. A `null` is such a value, not an absent parameter.
    - **The view doesn't echo it.**
  - **`chain`:** `absent` when the domain has no `chainId`, or a null one, whatever the parameter. Otherwise `match` or `mismatch`, comparing the domain's `chainId` with `chain_id` (a quantity) as numbers, and `unknown` without the parameter, never `match`.
- **Nothing reported changes what is signed.** The hash and the signature are ethers', byte for byte, whatever `primary_type` and `chain_id` say. A mismatch is reported, never refused.
- **Parity:** the reference's `getPayload` gives the view's vectors, as `TypedDataEncoder.hash` does for `hash`, with `chainId` cases at 0, 1, 2^53 − 1 and 2^53. The reports have no counterpart in ethers; their expected values come from this text.
- **The confirmed hash.** `expected_hash` is required. The digest is part of the public work, and one that isn't `expected_hash` is `invalid_argument`, before any key is derived.
- **Size: refused (`view-size`).** The [limits](#limits) bound the hashing work, not the view. Integers become quoted strings, so the view can outgrow its input: a `uint256[]` of 99,000 zeros beside 330,000 bytes of `bytes` is about 858 KB of request and 1,056 KB of `getPayload` output, before the reply's envelope. Signing replies leave through the vault loop, which writes whole frames of at most 1 MiB.
  - **One bound for both methods:** the serialized size of the signing response, `{ "type": "response", "id": …, "result": { "signature": …, "view": … } }`, as the core writes it, with the largest ID a request may have (2^53 − 1, 16 digits, [0001](0001-freedom-cored.md#messages)). It must fit one frame. The signing envelope is the larger: `{ signature, view }` is 71 bytes more than `{ hash, view }` at the same ID.
  - **Measured while encoding,** since each value's normalized length is known then. Both methods refuse a request over the bound with `invalid_argument`, `sign.typed_data` before any key is derived. Neither measures its own reply, nor the request's actual ID.
  - **So the preflight is exact:** `typed_data.hash` refuses exactly the requests `sign.typed_data` would, whatever either request's ID, and main learns before the prompt that one can't be signed.
  - Real payloads are far below the frame.
- **Timing:** `expected_hash` is required from the core release that adds the view. A browser that pins that release must pass it, so main's move onto the view ([Migration](#migration-in-freedom-browser) step 4) lands with that pin, and reverting the move means reverting the pin.

### What main does (#88)

- **Gets the view before the prompt,** from `typed_data.hash`, for every signer kind: vault, Ledger, phone and Safe alike. It needs no key and works while locked. Main passes:
  - **`primary_type`:** the dApp's `primaryType` as it came, whatever its JSON type, when the request has one. A value that isn't a string keeps its type, never converted to text, so it reads `mismatch` and is warned about. A request without one is passed without it, and reads `unknown`: a wallet that honors `primaryType` refuses such a request rather than reading it differently.
  - **`chain_id`:** the dApp's active chain.
- **Renders the view,** every field, untruncated, instead of the dApp's JSON. Keys in `ignored` are listed as sent by the site and not signed.
- **Binds the confirmation to the hash.** The confirmation token binds `hash`, and a vault account's `sign.typed_data` passes it as `expected_hash`. A request that changed after the user confirmed it fails, and nothing is signed.
- **Main's own typed data** is bound the same way: Safe's SafeTx, built from the transaction the user confirmed; Safe's SafeMessage, over the hash of the request the user confirmed; x402's authorizations, from the payment as approved. Main hashes each with `typed_data.hash` before it signs, and passes that hash.
- **Warns, and still signs:**
  - **`named_type: mismatch`:** the screen warns that the site named a different primary type from the one shown and signed, and that other wallets could sign something different. Approving signs the inferred root, as ethers does.
  - **`chain: mismatch`:** the screen warns that the data is for another chain than the site's, naming both.
  - **`chain: absent`:** the screen warns that the signature is valid on every chain where the verifying contract exists.
  - Approving signs in each case. `unknown` is never shown as a match.
- **A refusal for size** fails the dApp's request before the prompt, mapped like any `invalid_argument`. Nothing is shown or signed.
- **`personal_sign`:** main shows the bytes it sends to `sign.message`, decoded from the same strictly validated hex.
- **Auto-approve doesn't apply to a warned request** (tightened in #112's review, consistent with #89). With `named_type: mismatch`, `chain: mismatch` or `chain: absent`, the prompt always appears with its warning, even when the site has signing auto-approve, and nothing is signed until the user approves. A request with no warning is auto-approved as before.

### What the binding doesn't cover

- **Devices** render typed data themselves. For Ledger and phone accounts, the view fixes what main shows, and the device signs what it shows. `expected_hash` binds the core's signatures only.
- **Main itself:** as [Non-goals](#goals-and-non-goals) says, stage 1 trusts main, which can still ask for any hash it chooses. The binding keeps the display and the signature from drifting apart; it doesn't stop a compromised main.

### Tests (#88)

**The core:**
1. **The view is the signed data.** For every EIP-712 vector that hashes, `view` equals the reference's `getPayload`, normalized as above, and `typed_data.hash` and `sign.typed_data` return the same view. Hashing the view's own `types` (less `EIP712Domain`), `domain` and `message` gives the returned hash. Undeclared top-level keys appear only in `ignored`, and undeclared nested ones nowhere.
2. **The confirmed hash:** `sign.typed_data` signs with the hash `typed_data.hash` returned. With any other (one bit changed, another request's hash), it returns `invalid_argument` and no signature, and without one the request is malformed. With the vault locked, these refusals are still `invalid_argument`, not `vault_locked`: they come before the key.
3. **The oversize refusal**, at the one bound:
   - a request whose signing response at ID 2^53 − 1 exactly fills the frame is answered by both methods, and signed at that ID; one byte more is `invalid_argument` from both, with no key derived (likewise `invalid_argument` while locked);
   - a request whose hash reply would fit but whose signing reply wouldn't, by the 71 bytes between the envelopes, is refused by both methods, `typed_data.hash` included;
   - so is one whose signing reply would fit at a short ID but not at 2^53 − 1: `typed_data.hash` at ID 1 refuses it, and `sign.typed_data` refuses it at every ID;
   - the measured size equals the length of the signing response written at ID 2^53 − 1, across the vectors and at the boundary.
4. **The `primaryType` report:** the root gives `match`; another declared type, an undeclared name and `EIP712Domain` give `mismatch`; so do the non-strings `true`, `false` and `null`, each with a struct of that name as the inferred root, and a number, an array and an object; no parameter gives `unknown`. The hash and the signature equal ethers' in every case.
5. **The `chainId` report:** an equal chain gives `match`, with the domain's `chainId` as a number and as a hex string; another chain gives `mismatch`; a domain without `chainId`, or with a null one, gives `absent` with or without the parameter; no parameter otherwise gives `unknown`. The hash and the signature equal ethers' in every case, chain id 0 included.

**Main** (freedom-browser, migration step 4):
1. **The screen shows the view:** every field untruncated, `verifyingContract` and `chainId` whole, and `ignored` keys listed as not signed. Nothing from the dApp's own JSON is rendered.
2. **Every signer kind** gets the view before the prompt: vault, Ledger, phone and Safe.
3. **The binding:** a vault signature passes the confirmed hash, and a request altered after confirmation (a test hook) fails with nothing signed. SafeTx, SafeMessage and x402 signatures pass their own hashes.
4. **The oversize refusal** fails the request before the prompt, mapped like any `invalid_argument`.
5. **The `primaryType` warning** is shown on a mismatch, and not on a match or without one. A non-string `primaryType` is passed with its type and warned about: `true`, `false` and `null`, each with a struct of that name as the root, among them. Approving returns ethers' signature over the inferred root.
6. **The `chainId` warning** is shown on a mismatch, naming both chains, and on an absent `chainId`, and not on a match. Approving signs, and `unknown` is never shown as a match.
7. **`personal_sign`** is shown from the bytes it signs.
8. **A warned request prompts under auto-approve:** with signing auto-approve on, a `primaryType` mismatch, a non-string `primaryType` (`true`, `false` and `null`, each with a struct of that name as the root), a mismatched `chainId` and an absent one each show the prompt with the warning, and nothing is signed until the user approves.
9. **An unwarned request still auto-signs:** with signing auto-approve on, a request whose view reports `named_type` `match` or `unknown`, and `chain` `match` or `unknown`, is signed with no prompt, as before.

### Options weighed (#88)

The write-up set these out before the decision. They stay as its rationale.

| Question | Options | Decided | Rationale |
|---|---|---|---|
| When | now, with the UI moving onto the view; or with the policy phase | now | the display and the signature differ today ([Today](#today)); a view from the core closes that without waiting for approval to move into the core |
| A view over one frame | refusal (`view-size`); or fragmented signing replies from the vault loop, as [0005](0005-chain-data.md#frames) has for chain data | refusal | fragments need bulk credit and a writer allowance in the vault loop, and a fallback for a peer without fragments; real payloads are far below the frame |
| A `primaryType` that isn't the inferred root | refusal (`invalid_argument`, deviation `primary-type`), as proposed, since wallets disagree on what such a request means; or a warning, signing as ethers does | a warning: the user overrode the proposal | refusal breaks a dApp whose request names another type. With the view showing what is signed, whatever the site named, what remains is that other wallets read the request differently, which the warning says |
| A `chainId` mismatched or absent | a warning; or refusal | a warning | some protocols sign for another chain on purpose, and a domain may omit `chainId` |

## Migration in freedom-browser

One PR per step, each after the freedom-core release that provides it.

1. **EVM signing.**
   - `signers.js`'s vault backend calls `sign.transaction`, `sign.message` and `sign.typed_data`.
   - `computeAddress(pk)` gives way to `keys.addresses`.
   - Safe owner signatures, the executor EOA and x402 go through the same backend.
   - x402's `BigInt`s are converted recursively to decimal strings at the vault backend boundary, so Ledger and phone dispatch stays unchanged.
   - **Safe's EIP-1271 SafeMessage:** main hashes the dApp's original request, then signs a SafeMessage over that digest. The inner digest of a typed-data request now comes from `typed_data.hash`, with the same strict rules and limits, instead of ethers' `TypedDataEncoder.hash`. Otherwise a `"false"` the dApp displayed could still be hashed as true and then signed by the core. An inner `personal_sign` digest stays `hashMessage` of the strictly validated bytes.
   - `normalizeMessage` validates hex strictly.
   - Ledger, phone and Safe dispatch is unchanged.
2. **Swarm.**
   - `chunk-service` and `feed-service` stop building bee-js `PrivateKey`s. Main computes identifiers, payloads and next indices, which are public, and gets owners from `keys.addresses`. The core signs (`swarm.sign_soc`) and main uploads the SOC through Bee's HTTP API.
   - `resolveSignerKey` turns into a key-reference resolver, for the Bee wallet and publisher keys only. Main removes the `ethereum-wallet` mode rather than moving it ([Accounts as feed owners](#amendment-accounts-as-feed-owners-89)).
3. **Removal**, in the order 0001 set:
   - `compat.bee_wallet_key` and `compat.publisher_key` go once step 2 has shipped;
   - `compat.private_key` goes once step 1 has shipped and main has removed the `ethereum-wallet` mode, its only other user.

   Each removal is a core release, plus a browser check that no call site is left.
4. **The signed view** ([What the user is shown](#amendment-what-the-user-is-shown-88)), after step 1 and the core release that adds the view: the approval UI renders the core's view of typed data, every `sign.typed_data` passes the confirmed hash, and `personal_sign` is shown from the bytes main sends.

**Rollback:** a browser step can be reverted while the core still has `compat.*`. So `compat.*` leaves the core only in a release after the browser has stopped calling it, and the browser pins that release only once it no longer needs `compat.*`.

## Amendment: accounts as feed owners (#89)

**Status:** decided by the user on 2026-10-22. Accounts no longer own feeds: main removes the `ethereum-wallet` feed mode, and the core refuses account keys in `swarm.sign_soc` (option A, key separation), at once. There is no migration and no ownership record. A dApp's 32-byte `personal_sign` gets a warning, not a refusal (option D). [Options weighed](#options-weighed) keeps the alternatives, as the decision's rationale.

### The collision

- **A SOC signature is a `personal_sign` of 32 bytes.** `swarm.sign_soc` signs EIP-191 over `keccak256(identifier ‖ chunk address)`, which is `"\x19Ethereum Signed Message:\n32" ‖ digest`. `sign.message` of those 32 bytes signs exactly that. The format is Swarm's: Bee recovers a chunk's owner from EIP-191 over that digest, and bee-js signs it the same way. Neither side can add a domain separator.
- **Who can exploit it:** any dApp the user has connected to an account that owns a feed: one made through the `ethereum-wallet` identity mode, until main removes it, or one made outside Freedom.
  1. Feed identifiers are public: a feed's manifest, which a name's contenthash points at, names its owner and topic, and an update's identifier is `keccak256(topic ‖ index)`. The dApp computes the next identifier of the user's feed, picks its own payload, and computes the chunk address and the digest.
  2. It asks for `personal_sign` of the 32-byte digest. The prompt renders a message's bytes as text, and a digest's bytes read as nothing at all: the user can't tell a feed update from any other hash. Today a dApp whose permission has signing auto-approve (`getSigningAutoApprove`) isn't shown a prompt: main signs at once.
  3. The signature is a valid single-owner chunk of the user's feed. The dApp uploads it, and the feed (an ENS-named site, say) serves the dApp's content.
- **Only this one case collides.** Another message length has another EIP-191 prefix, and typed data and transactions have their own (`0x1901`, a type byte or RLP). The other direction is safe too: a SOC request signs `keccak256(identifier ‖ chunk address)` over a real chunk, and making that equal a chosen message needs a keccak preimage.
- **Before this decision** the same was true of bee-js and ethers in main, so the core wasn't a regression. The core's guarantee that every SOC signature is bound to a real chunk only holds for keys that sign nothing else. A test in `fc-swarm` (`a_soc_signature_is_a_personal_sign_of_its_digest`) pins the collision.

### Decision

1. **The `ethereum-wallet` feed mode is removed, for now.** This is A, key separation, in effect at once:
   - main stops offering the mode, and stops advertising it to dApps;
   - new feeds always use keys that sign nothing but SOCs: a per-origin publisher key, or the Bee wallet as today;
   - the core refuses account keys in `swarm.sign_soc`.
2. **No migration and no ownership record.** The user states that no existing user owns a feed with a wallet key. There is nothing to move, so B's and B′'s record, and where it would live, are moot.
3. **A dApp's 32-byte `personal_sign` gets a warning only (D).** Nothing is refused. The approval screen says plainly that a raw 32-byte value is being signed, and that it can authorise things the prompt can't show, such as a Swarm feed update. The prompt always appears, even when the site has signing auto-approve: a warning that auto-approve can skip protects nothing. The user can still approve. Blocking (B, B′ or C) would break dApps that sign a hash, for the rare account that owns a feed created outside Freedom.
4. **Wallet-owned feeds may come back later** (in the user's words, "it enables some amazing features"). Bringing them back needs a new design that avoids the signature collision: a key that answers dApps' 32-byte `personal_sign` can't safely own a feed. One possible direction, not designed here: a wallet-derived account dedicated to feeds and never exposed to dApps.

### What main does

- **Removes the mode.**
  - `swarm_getCapabilities` drops `ethereum-wallet` from `publisherIdentityModes`, and drops `extensions.ethereumWalletPublisherIdentity`.
  - Neither the publisher-identity UI nor the dApp API offers the mode for a feed. The request that creates such an identity goes.
  - A request that still names the mode, and a stored feed identity in it, fail with an error saying the mode isn't available. Nothing falls back to another key: another key is another owner, and so another feed. There is no migration code, since the user states that no such identity exists.
  - The mode's route to an account key goes. After that, `compat.private_key` serves EVM signing alone.
- **Warns on a 32-byte `personal_sign`.**
  - The trigger is a dApp's `personal_sign` whose message is exactly 32 bytes as signed, after main's normalization. A 64-digit hex string and a 32-byte text both count: both get the same EIP-191 prefix.
  - The approval screen shows the bytes as hex. It says plainly that a raw 32-byte value is being signed, and that it can authorise things the prompt can't show, such as a Swarm feed update.
  - The prompt always appears, even when the site has signing auto-approve: auto-approve doesn't apply at exactly 32 bytes. A warning that auto-approve could skip would protect nothing.
  - It appears whatever the account: a Ledger or phone account can own a feed made elsewhere too.
  - Approving signs exactly as before.
- **Nothing else changes.** Other message lengths, typed data, transactions, Safe and x402 behave as they do today, and signing auto-approve still applies to everything but a 32-byte `personal_sign`. (Since [#88](#amendment-what-the-user-is-shown-88), a typed-data request with a warning is excepted too.)

### What the core does

- `swarm.sign_soc` refuses `{ "kind": "account" }` with `invalid_argument`, like any key outside its row. The [key table](#key-references-callers-and-execution)'s account row no longer lists it.
- `fc_swarm::sign_soc` still signs with whatever key it's given. The refusal is the core's key policy, as the Bee wallet's and publisher keys' refusals of the EVM methods are.
- `sign.message` is unchanged, 32 bytes included. The warning is main's policy, as [Non-goals](#goals-and-non-goals) says.
- **Timing:** the refusal ships in the next core release, and doesn't wait for main. A browser build on that release fails an `ethereum-wallet` feed update with `invalid_argument`, and signs nothing. Main's removal lands no later than the browser's pin to that release, so that no build offers a mode the core refuses.

### What stays exposed

D refuses nothing, by design. An account that owns a feed made outside Freedom (in another wallet on the same mnemonic, say) stays exposed: a dApp connected to it can still get a 32-byte `personal_sign` that is a valid update to that feed, if the user approves it. The warning, which auto-approve can't skip, is the only guard.

### Tests

**The core:**
1. `swarm.sign_soc` with an account key returns `invalid_argument` and no signature: at index 0 and at the top of the range, and whether the vault is locked or not. The Bee wallet and publisher keys still sign.
2. The over-the-wire replay of `vectors/signing.json` expects `invalid_argument` for every `socs` case keyed by an account, and still matches bee-js byte for byte for the Bee wallet and publisher cases. The vectors stay as generated: bee-js does sign with an account key, and the vector records that.
3. `fc-swarm`'s own replay keeps all three key kinds, since the chunk format doesn't depend on who signs. `a_soc_signature_is_a_personal_sign_of_its_digest` stays, as the reason for the refusal.
4. The malformed `swarm.sign_soc` cases in `locked_vault_and_malformed_requests` move from an account key to a publisher key, so that each still fails for the malformation it tests, not for the key.
5. **Nothing else changes:** every `sign.message`, `sign.typed_data` and `sign.transaction` vector passes unchanged, the 32-byte `binary-32` message included.

**Main:**
1. `swarm_getCapabilities` lists neither the `ethereum-wallet` mode nor `extensions.ethereumWalletPublisherIdentity`.
2. The publisher-identity UI doesn't offer the mode. A dApp request for it, and a stored feed identity in it, fail with the error, and make no signature with any key.
3. A dApp's `personal_sign` of exactly 32 bytes shows the warning, given as hex or as text; 31 and 33 bytes don't. Approving it returns the same signature as before.
4. **Auto-approve doesn't apply at exactly 32 bytes:** with signing auto-approve on, a 32-byte `personal_sign` still shows the prompt with the warning, and nothing is signed until the user approves. At 31 and 33 bytes, auto-approve still signs with no prompt.
5. **Nothing else in the signing paths changes:** other message lengths, typed data, transactions, Safe, x402 and auto-approve outside the 32-byte case behave as before, and feeds with the Bee wallet and publisher identities sign and upload as before. The existing signing and Swarm suites pass, less the cases for the removed mode.

### Options weighed

The write-up set these out before the decision. They stay as its rationale.

**Constraints:**
- **The 32-byte `personal_sign` is common.** dApps sign a hash with `signMessage(getBytes(hash))`, and contracts check it with OpenZeppelin's `toEthSignedMessageHash`. Neither the core nor main can tell a SOC digest from any other hash.
- **An account-owned feed stays account-owned.** A feed is `(owner, topic)`: its updates can only ever be signed by the owner's key. Moving a user to a publisher key means a new feed, and re-pointing every name and link to it. Re-pointing doesn't retire the old feed: whoever still follows it (an old link, a cache, another name) sees its next update.
- **Ownership outlives every local record.** The owner is the key's address, whatever a profile remembers. The account still owns its feeds after a mnemonic restore (which brings back the keys, not the profile's feed records), in another profile, and in another wallet that holds the same mnemonic. A rule keyed on "this account owns a feed" is only as complete as the record it reads.
- **Scope:** the core's checks cover the keys it holds. Ledger and phone accounts sign on their devices, and the browser never makes them feed identities.
- **The mode is advertised to dApps:** `swarm_getCapabilities` lists `ethereum-wallet` in `publisherIdentityModes`, with `extensions.ethereumWalletPublisherIdentity`. Removing it is visible to them.

| Option | What it closes | What breaks | Where |
|---|---|---|---|
| **A. Key separation** (decided): `swarm.sign_soc` refuses account keys (`invalid_argument`, like any key outside its row) | no new account-owned feed through the core's SOC and feed interface. **Not through `sign.message`:** with the same key it still makes SOC signatures, both for the feeds accounts already own and for the first update of a new feed, with no feed identity recorded anywhere | `ethereum-wallet` mode, and updates to existing account-owned feeds | the core (the key table and one check, with tests), then the browser |
| **B. Known owners:** an account the profile records as a feed owner refuses a dApp's 32-byte `personal_sign`, for good | for the owners the record knows. Not after a restore, in another profile, or with another wallet on the same mnemonic: there the record is missing and the request is signed | 32-byte `personal_sign` from those accounts | main, from its feed records. A core flag set by an account's first SOC would have to be committed durably before that signature is released, and carried in backups, and still misses ownership made elsewhere |
| **B′. Fail-safe:** every account refuses a dApp's 32-byte `personal_sign` unless the record says it never owned a feed: created in this profile and never a feed identity | every core-held account whose history the profile doesn't know, restored ones included. Not an account recorded as clean that later makes a feed's first update anyway, through another wallet on its mnemonic, or through an allowed 32-byte `personal_sign` in this same profile before the record changed. Keeping the record exact would mean treating every 32-byte message signature as potentially forming a feed, which is option C's compatibility cost | 32-byte `personal_sign` from owners, and from restored accounts until the user releases each one | main, with a durable per-account record |
| **C. No 32-byte `personal_sign`:** the core refuses it from every account | every core-held account, whatever its history | every dApp that signs a hash, from any account | the core |
| **D. Warning** (decided): main warns when an account is asked to sign exactly 32 bytes | nothing: an approval still signs a feed update. Releasing an account from B or B′ is this option: the user accepts the risk | nothing | main |

**Why A with D:**
- **A** stops Freedom from making account-owned feeds. Its gap, the feeds accounts already own, which `sign.message` can still update, is empty: the user states that no user owns a feed with a wallet key.
- **B and B′** need a durable record of owners. With no account-owned feeds in Freedom, B's record would be empty. B′ would refuse every restored account's 32-byte `personal_sign`, to protect the rare feed made outside Freedom. The write-up recommended B′ alongside A on the assumption that some accounts already owned feeds; the user's statement removes that case, and with it the question of where the record lives.
- **C** breaks every dApp that signs a hash, from every account.
- **D** breaks nothing, and tells the user what a 32-byte signature can do. Its one cost is a prompt at 32 bytes for a site with signing auto-approve. The rare account that owns a feed made outside Freedom keeps the risk the user accepts by approving.

## Open questions

1. **Auto-lock.** Should signing restart the auto-lock timer itself? Proposed: no. Main keeps calling `vault.touch` where it does today: after vault-account signing, but not after Swarm signing. Revisit with policy.
2. **SOC payloads larger than one chunk.** `writeFeedPayload` uploads big payloads through `/bytes` first, and the core then signs the root chunk. A later phase could chunk and hash the whole payload in the core. That isn't needed for parity.
3. **Error strings.** dApps see main's error mapping, not ethers' exact messages. Do any callers match on ethers' message text? Check during the browser migration.
4. **Wallet-owned feeds** (#89): removed for now. Bringing them back needs a new design that avoids the signature collision ([the amendment](#amendment-accounts-as-feed-owners-89), *Decision*).
5. **What the user is shown** (#88): **decided** (the user, 2026-10-22): the core's view now, with the UI moved onto it and `sign.typed_data` bound to the confirmed hash; a view over one frame refused (`view-size`); a `primaryType` mismatch and a mismatched or absent `chainId` warned about, and signed. Tightened in #112's review, consistent with #89: a warned request always shows its prompt, even under signing auto-approve. See [the amendment](#amendment-what-the-user-is-shown-88).
