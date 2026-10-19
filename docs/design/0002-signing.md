# 0002: Signing in the core (Phase 2)

**Status:** proposed. Builds on [0001](0001-freedom-cored.md). After this phase, no raw private key leaves the core except through the permanent, user-requested backup exports.

## Summary

Phase 1 moved the vault and every key into `freedom-cored`. JS still signs with raw keys it fetches through the temporary `compat.*` exports: `compat.private_key` for user accounts, `compat.bee_wallet_key` and `compat.publisher_key` for Swarm. Phase 2 moves every signature made with a vault key into the core and then deletes `compat.*`.

Freedom Browser signs with vault keys in exactly two places:

- **ethers v6** in `src/main/wallet/signers.js` (the vault signer backend):
  - transactions: legacy with EIP-155, and EIP-1559;
  - EIP-191 `personal_sign`;
  - EIP-712 `eth_signTypedData_v4`.

  Its callers are the wallet UI, dApp requests, Safe (SafeTx, EIP-1271 SafeMessage, the executor EOA) and x402 (EIP-3009 TransferWithAuthorization, Permit2 PermitWitnessTransferFrom).
- **bee-js** in `src/main/swarm/{chunk,feed}-service.js`: single-owner chunks (SOC) for `swarm_writeSingleOwnerChunk`, feed updates and feed payloads. The key is the Bee wallet, a per-origin publisher key, or a user account (the `ethereum-wallet` identity mode).

Nothing else signs with a vault key. GSOC signs with keys it mines itself. The Ant node signs postage and cheques with the keystore that `nodes.write_identity` writes. Ledger, phone and Safe accounts keep their own signers.

The core gets five methods:
- four that sign: `sign.transaction`, `sign.message`, `sign.typed_data` and `swarm.sign_soc`;
- one public hash: `typed_data.hash`, so that main never computes an EIP-712 digest that a vault key will sign with weaker rules than the core's.

Each returns exactly the bytes ethers or bee-js return today, and each signing method takes a key **reference**, never key bytes.

## Goals and non-goals

**Goals**
- **No raw key outside the core.** After the browser migrates, `compat.*` is removed. Main never holds a private key again, and neither does the Swarm path, which today keeps one alive for seconds while it uploads.
- **Byte-exact parity.**
  - The same key and input give the same raw transaction, signature or SOC as today. ethers and k256 both sign with RFC 6979 deterministic nonces and low-s, so the signatures are identical, not just valid.
  - Golden vectors from the pinned JS check this (see [Parity](#parity-contract-and-vectors)).
  - Where ethers is dangerously lenient, the core is stricter. Every such case is listed under [Deviations](#deviations-from-ethers) and has a vector.
- **Least authority per key.**
  - User accounts sign transactions, messages and typed data.
  - The Bee wallet and publisher keys sign **only** SOCs.
  - A SOC's chunk address is computed in the core from the chunk itself, so every SOC signature is bound to a chunk that actually hashes to that address.

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
| `{ "kind": "account", "index": n }` | user wallet *n* | `m/44'/60'/n'/0/0` | all four signing methods |
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

- `sign.typed_data { key, typed_data: { domain, types, message } }` → `{ signature }`.
- `typed_data.hash { typed_data }` → `{ hash }`: the same digest, with no key. It is public, works while locked, and applies the same validation and limits.

This is EIP-712 with ethers v6 `TypedDataEncoder` semantics, which is what `Wallet.signTypedData(domain, types, message)` does today. Main already strips `EIP712Domain` from `types` and drops `primaryType`; it keeps doing both.

- **Types:**
  - The primary type is inferred as the single type that no other type references. No root, several roots (unused types count), a cycle reachable from the primary type, a duplicate field name, an unknown type and an ill-formed width (`uint7`, `uint08`, `bytes33`) are errors, as in ethers.
  - A cycle that is *not* reachable from the primary type is accepted, as in ethers.
  - `uint` and `int` mean `uint256` and `int256`, unless a struct with that name exists. Array suffixes keep their written form in `encodeType`, as in ethers.
- **Domain:**
  - The keys `name`, `version` (strings), `chainId` (quantity), `verifyingContract` (address) and `salt` (32 bytes). The domain type is built from the keys present, in that order.
  - A key whose value is `null` is skipped, even an unknown one. Any other key is an error.
- **Values:**
  - `uintN` and `intN` take a quantity string or a JSON integer within ±(2^53 − 1), range-checked for N. A JSON float or an unsafe integer is an error, as in ethers.
  - `bytesN` takes exactly N bytes and `bytes` takes any; both are hex with `0x` or `0X`.
  - `string` takes a JSON string.
  - `address` takes `0x` and 40 hex digits: all-lowercase, all-uppercase, or EIP-55 mixed case with a valid checksum. Without `0x`, ethers tries ENS when signing and fails.
  - Arrays: `T[]` and `T[n]`, with the length checked for `T[n]`. Structs nest.
  - An extra message field is ignored, as in ethers. The approval UI shows the message main received. [What the user is shown](#amendment-what-the-user-is-shown-88) proposes that it show what was signed instead.

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

### Errors

- **`invalid_argument`** (0001's code) covers every malformed input: wrong key kind, an invalid quantity, range, length, checksum or type, an unsupported transaction type, a typed-data violation, an oversize payload, or an exceeded limit. It carries a description. Main maps it the way it maps ethers' errors today: a dApp request fails, and no signature is made.
- **Locked vault:** `vault_locked`, as for `compat.*`.

## Deviations from ethers

ethers accepts each input below; the core refuses it. Each is a `deviation` vector, which records that ethers signed it and requires the core to reject it.

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
| EIP-712 | <ul><li>The EIP-712 Mail example; nested structs and arrays of structs, fixed and dynamic.</li><li>The bounds of every `uintN`/`intN` width (8 to 256), and the first value past each; the `uint`/`int` aliases; quantity forms (hex, signed hex, leading zeros, `-0`).</li><li>The limits that ethers accepts and the core refuses: name length, type count, fields per type, array dimensions, depth. The value and byte caps are too large for a vector and are covered by Rust tests.</li><li>`bytesN` and `bytes`; lowercase, uppercase and checksummed addresses; Unicode strings.</li><li>Domain subsets, including a hex-string `chainId`, `salt`, null fields (known and unknown), chain id 0 and an empty domain.</li><li>Empty structs; an unreachable cycle (accepted); extra message fields (ignored).</li><li>The real payloads: Safe 1.4.1 SafeTx and SafeMessage, EIP-3009 TransferWithAuthorization, and Permit2 PermitWitnessTransferFrom with string quantities.</li><li>Every ethers error kind, and every [deviation](#deviations-from-ethers).</li></ul> |
| SOC | <ul><li>Payloads of 1, 32, 33 and 4096 bytes.</li><li>Spans above and below the payload length, and span 0.</li><li>All three key kinds.</li></ul> |

Rust tests replay every case, in the crates (#18) and over the wire through the binary (#19). A CI job checks out freedom-browser at the pinned commit, installs its lockfile, and runs the generator's `check` mode, which re-derives every vector from the reference. A drift on either side fails CI.

## Implementation

- **`fc-evm` (logic crate, no I/O):**
  - a minimal U256;
  - RLP;
  - the two transaction serializations;
  - EIP-191;
  - the EIP-712 encoder above, written from ethers' source because parity, including which inputs are rejected, is the contract;
  - the signature format.
- **`fc-swarm` (logic crate, no I/O):** the BMT, the chunk address, and SOC signing.
- **Dependencies:** none new. `k256` (RFC 6979, low-s, recovery id), `sha3`, `serde_json` and `thiserror` are already in the workspace.
- **`freedom-cored`:** the five methods, executed as described in [Execution](#key-references-callers-and-execution), with secrets zeroized after use. Each method is in `fc-protocol`'s method table with its callers (`chrome`, `shell`) and is advertised in `core.hello`'s capabilities.
- Both crates compile for iOS and Android, as CI requires of logic crates.

## Amendment: what the user is shown (#88)

**Status:** proposed; **needs the user's decision.** It adds to the API and moves the approval UI onto the core's view; one part refuses requests ethers accepts.

### Today

The core hashes and signs `{ domain, types, message }`. The approval UI builds its own view from the dApp's JSON (`formatTypedDataForDisplay` in `dapp-sign.js`). The two can differ:

- **Undeclared fields** are shown but not signed, and the hash ignores them silently (ethers parity). A nested struct is shown as JSON, cut at 50 characters with every other value.
- **The domain** is shown partly: `verifyingContract` cut to 10 characters, and `chainId` hidden when it is 0. A domain without `chainId` is never flagged, though its signature is valid on every chain where the verifying contract lives. Nothing compares `chainId` with the dApp's active chain.
- **`primaryType`** is dropped by main, and the core infers the root as ethers does. A request whose `primaryType` names another type means one thing to ethers and another to a wallet that honors `primaryType` (MetaMask's `eth-sig-util` hashes the named type).
- **`personal_sign`** is shown by decoding hex pair by pair with `parseInt`, while main signs `Buffer.from(hex, 'hex')`, which stops at the first invalid pair: `0x41zz42` is shown as `A\0B` and signed as `A`. [Migration](#migration-in-freedom-browser) step 1 already makes main validate hex strictly, and the core refuses such hex (`parse_bytes`).

### Proposal

1. **A view of what was signed.** `typed_data.hash` and `sign.typed_data` also return `view`, and the approval UI renders it instead of the dApp's JSON, every field, untruncated.
   - **Its content** is ethers' `TypedDataEncoder.getPayload(domain, types, message)`, with the core's [deviations](#deviations-from-ethers): `primary_type`; `domain` with only the fields used, in the domain type's order; `message` with only the declared fields, in declaration order, structs nested. Values are normalized as `getPayload` does: integers as decimal strings, bytes and addresses as lowercase hex, and the domain's `chainId` as a number (a hex quantity past 2^53).
   - **Parity:** the reference's `getPayload` gives the vectors, as `TypedDataEncoder.hash` does for `hash`.
   - **Bounds:** each value is at most its own text, or 78 digits for an integer, so the view stays within the [limits](#limits) the hash already enforces.
   - **`ignored`:** the message's top-level keys the types don't declare, so the UI can say that the dApp sent fields that aren't signed.
2. **`primary_type`**, an optional parameter. Main passes the dApp's `primaryType`. One that isn't the inferred root is `invalid_argument` (deviation `primary-type`: ethers ignores it), since wallets disagree on what such a request means.
3. **`chain_id`**, an optional parameter: the dApp's active chain. The view reports `chain` as `match`, `mismatch` or `absent`, and the UI warns on the last two. It isn't refused: some protocols sign for another chain on purpose.
4. **`personal_sign`:** main shows the bytes it sends to `sign.message`, decoded from the same strictly validated hex.

### Decision needed

1. Whether to add `view` now, with the UI moving onto it, or with the policy phase.
2. Whether a `primaryType` mismatch is refused (proposed) or warned.
3. Whether a `chainId` mismatch or absence is warned (proposed) or refused.

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
   - `resolveSignerKey` turns into a key-reference resolver.
3. **Removal**, in the order 0001 set:
   - `compat.bee_wallet_key` and `compat.publisher_key` go once step 2 has shipped;
   - `compat.private_key` goes once steps 1 and 2 have shipped, because Swarm's `ethereum-wallet` mode used it too.

   Each removal is a core release, plus a browser check that no call site is left.

**Rollback:** a browser step can be reverted while the core still has `compat.*`. So `compat.*` leaves the core only in a release after the browser has stopped calling it, and the browser pins that release only once it no longer needs `compat.*`.

## Open questions

1. **Auto-lock.** Should signing restart the auto-lock timer itself? Proposed: no. Main keeps calling `vault.touch` where it does today: after vault-account signing, but not after Swarm signing. Revisit with policy.
2. **SOC payloads larger than one chunk.** `writeFeedPayload` uploads big payloads through `/bytes` first, and the core then signs the root chunk. A later phase could chunk and hash the whole payload in the core. That isn't needed for parity.
3. **Error strings.** dApps see main's error mapping, not ethers' exact messages. Do any callers match on ethers' message text? Check during the browser migration.
