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

The core gets four methods:
- `sign.transaction`
- `sign.message`
- `sign.typed_data`
- `swarm.sign_soc`

Each returns exactly the bytes ethers or bee-js return today, and each takes a key **reference**, never key bytes.

## Goals and non-goals

**Goals**
- **No raw key outside the core.** After the browser migrates, `compat.*` is removed. Main never holds a private key again, and neither does the Swarm path, which today keeps one alive for seconds while it uploads.
- **Byte-exact parity.**
  - The same key and input give the same raw transaction, signature or SOC as today. ethers and k256 both sign with RFC 6979 deterministic nonces and low-s, so the signatures are identical, not just valid.
  - Golden vectors from the pinned JS check this (see [Parity](#parity-contract-and-vectors)).
  - Where ethers is dangerously lenient, the core is stricter, and this document lists every such case.
- **Least authority per key.**
  - User accounts sign transactions, messages and typed data.
  - The Bee wallet and publisher keys sign **only** SOCs.
  - A SOC's digest is computed in the core from the chunk itself, so `swarm.sign_soc` can't be used to sign an arbitrary 32-byte value.

**Non-goals**
- **Approval and policy.** As in 0001's threat model, stage 1 trusts main: it runs the approval UI and decides what gets signed. A compromised main can still ask for signatures. Phase 2 removes key *exposure*, not main's authority. Policy moves with the Chromium work.
- **Transaction building:** nonces, fee estimation, gas limits, broadcasting and receipts stay in main. The core signs a fully specified transaction.
- **Other transaction types:** EIP-2930 access lists, blob (EIP-4844) and set-code (EIP-7702) transactions. Freedom doesn't send them today, and the core rejects them.
- **`eth_sign`** (raw digest signing). Freedom rejects it today and the core doesn't offer it.
- **Ledger, phone and Safe accounts.** Safe owners that are vault accounts sign through the core like any other account.

## Key references

Every signing method takes `key`:

| `key` | Key | Derivation (unchanged from 0001) | Allowed in |
|---|---|---|---|
| `{ "kind": "account", "index": n }` | user wallet *n* | `m/44'/60'/n'/0/0` | all four methods |
| `{ "kind": "bee_wallet" }` | Bee wallet | `m/44'/60'/0'/0/1`, distinct from every account | `swarm.sign_soc` only |
| `{ "kind": "publisher", "origin_index": n }` | Swarm publisher key for an origin | `m/44'/73406'/n'/0/0` | `swarm.sign_soc` only |

- **Index range:** the same as `compat.private_key` and `compat.publisher_key` (`0..=2147483647`, JS's index error strings).
- **Wrong method:** a key kind used outside its row returns `invalid_params`.
- **Main keeps its guards.** Main still refuses hardware-range indices and non-mnemonic wallet records before it asks the core, as `vault-access.js` does today. The core doesn't know about wallet records.

Every method needs an unlocked vault and returns `vault_locked` otherwise. Signing work is admitted against the current epoch, exactly like `compat.*` (0001, "Concurrency, epochs and revocation"). The methods don't touch the auto-lock timer; main keeps calling `vault.touch` where it does today.

## API

Byte strings are `0x`-prefixed lowercase hex, which is not secret data. Quantities are JSON strings, decimal or `0x` hex, because JSON numbers can't carry `uint256`. Unknown fields are rejected, as in 0001.

### `sign.transaction`

`{ key, tx }` → `{ raw, hash }`

| `tx` field | Type | Notes |
|---|---|---|
| `type` | `0` or `2` | legacy (always with EIP-155) or EIP-1559 |
| `chain_id` | quantity ≥ 1 | required. ethers would sign a chain-less legacy transaction when `chainId` is missing; the core never does |
| `nonce` | quantity < 2^64 | |
| `gas_limit` | quantity | |
| `to` | address or `null` | `null` creates a contract. Hex only (ethers would try to resolve an ENS name; main resolves before signing) |
| `value` | quantity | |
| `data` | bytes | `"0x"` when empty |
| `gas_price` | quantity | type 0 only |
| `max_fee_per_gas`, `max_priority_fee_per_gas` | quantity | type 2 only. Priority ≤ max, as ethers requires ("priorityFee cannot be more than maxFee") |

- **`raw`:** byte-for-byte `Wallet.signTransaction(tx)`.
  - Type 0: `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])` with `v = chainId·2 + 35 + yParity`.
  - Type 2: `0x02 ‖ rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, [], yParity, r, s])`.
- **`hash`:** `keccak256(raw)`, which is what main records before broadcasting.

### `sign.message`

`{ key, message }` → `{ signature }`

- **`message`:** the bytes to sign. Main keeps today's normalization (`signing-utils.js`): a `0x` string is hex-decoded, anything else is signed as UTF-8. It sends the resulting bytes as hex.
- **`signature`:** EIP-191 over `"\x19Ethereum Signed Message:\n" ‖ len ‖ message`. It is 65 bytes `r ‖ s ‖ v` with `v ∈ {27, 28}`, byte-for-byte `Wallet.signMessage(bytes)`.

### `sign.typed_data`

`{ key, typed_data: { domain, types, message } }` → `{ signature }`

This is EIP-712 with ethers v6 `TypedDataEncoder` semantics, which is what `Wallet.signTypedData(domain, types, message)` does today. Main already strips `EIP712Domain` from `types` and drops `primaryType`; it keeps doing both.

- **Primary type:** inferred as the single type that no other type references. Ambiguous roots, unused types and cycles are errors, as in ethers.
- **Domain:** the keys `name`, `version` (strings), `chainId` (quantity), `verifyingContract` (address) and `salt` (32 bytes), with the domain type built from the keys present. Any other key is an error ("invalid typed-data domain key").
- **Encoding:**
  - `uintN` and `intN` take a quantity string or a JSON integer within ±(2^53−1), range-checked for N. A JSON float or an unsafe integer is an error.
  - `bytesN` takes exactly N bytes as hex.
  - `bytes` takes hex.
  - `string` takes a JSON string; ethers rejects anything else there too.
  - `address` is hex: all-lowercase, or EIP-55 mixed case with a valid checksum.
  - Arrays: `T[]` and `T[n]`, with the length checked for `T[n]`.
  - Structs nest.
- **Missing and extra fields:** a missing field is an error. An extra message field is ignored, as in ethers. The approval UI shows the message main received.
- **Stricter than ethers:** `bool` takes only JSON `true` or `false`. ethers encodes any truthy value as true, including the strings `"false"` and `"0"`, so a request that *displays* false could be signed as true. The core rejects such requests.
- **Limits:** nesting depth ≤ 32. Total size is bounded by the frame limit.
- **x402:** it passes `BigInt` message values. Main serializes them as decimal strings before calling the core.

### `swarm.sign_soc`

`{ key, identifier, span, payload }` → `{ signature, owner, chunk_address, soc_address }`

- **Inputs:**
  - `identifier`: 32 bytes, hex.
  - `span`: a u64 quantity. For a leaf chunk it equals `payload.length`. For the root chunk of a `/bytes` upload, which `writeFeedPayload` wraps, it is the whole content length.
  - `payload`: 0–4096 bytes, hex.
- **Computed in the core (`fc-swarm`):**
  - `chunk_address` = BMT(`span` as 8 bytes little-endian ‖ `payload`), the content-addressed chunk address. The tree is Swarm's binary Merkle tree: 128 32-byte segments, zero-padded, keccak256.
  - `digest` = keccak256(`identifier` ‖ `chunk_address`).
  - `signature` = EIP-191 over the 32-byte digest, with `v ∈ {27, 28}`.
  - `owner` is the key's address.
  - `soc_address` = keccak256(`identifier` ‖ `owner`).
- **Parity:** the output equals bee-js's `makeContentAddressedChunk(payload, span).toSingleOwnerChunk(identifier, key)`. Main uploads `span ‖ payload` to Bee's `/soc/{owner}/{identifier}?sig=…` as bee-js does today.
- **Why the core computes the chunk address:** if main supplied the chunk address, `swarm.sign_soc` would be an oracle for EIP-191 signatures over arbitrary 32-byte values, made with the Bee wallet and publisher keys. Because the core hashes the chunk itself, only genuine SOC digests get signed.

### Errors

- **Malformed input** returns `invalid_params` with a description: wrong key kind, invalid quantity, range, length, checksum or type, unsupported transaction type, typed-data violation, oversize payload. Main maps it the way it maps ethers' errors today: a dApp request fails, and no signature is made.
- **Locked vault:** `vault_locked`, as for `compat.*`.

## Parity contract and vectors

`vectors/signing.json` comes from the pinned reference checkout, like the Phase 1 vectors. It uses that checkout's own ethers 6.17.0 (`Wallet.signTransaction`, `signMessage`, `signTypedData`, `TypedDataEncoder.hash`) and bee-js (`makeContentAddressedChunk(…).toSingleOwnerChunk(…)`). The keys are the Phase 1 test mnemonics.

| Area | Cases |
|---|---|
| Transactions | <ul><li>Type 0 and type 2.</li><li>Chain ids 1, 100, 11155111 and one above 2^32.</li><li>Nonce 0, small, and 2^64−1.</li><li>Value 0 and 2^256−1.</li><li>Empty and long data; contract creation.</li><li>Priority = max; the error when priority > max.</li><li>The other rejections: missing chain id, other types, an ENS-style `to`.</li></ul> |
| EIP-191 | Empty, ASCII, multi-byte UTF-8, binary, and ≥ 1000 bytes (multi-digit length prefix). |
| EIP-712 | <ul><li>The EIP-712 Mail example.</li><li>Nested structs, and arrays of structs, fixed and dynamic.</li><li>Every `uintN`/`intN` boundary.</li><li>`bytesN` and `bytes`.</li><li>Lowercase and checksummed addresses.</li><li>Unicode strings.</li><li>Every domain subset, including a hex-string `chainId` and `salt`.</li><li>Extra message fields (ignored).</li><li>The three real payloads: Safe 1.4.1 SafeTx, the SafeMessage envelope, EIP-3009 TransferWithAuthorization and Permit2 PermitWitnessTransferFrom with string quantities.</li><li>Every ethers error kind: ambiguous root, unused type, cycle, unknown domain key, out of range, bad length, bad checksum, missing field, float, unsafe integer.</li><li>The strict-`bool` cases, recorded as the core's documented deviation.</li></ul> |
| SOC | <ul><li>Payloads of 0, 1, 32, 33 and 4096 bytes.</li><li>A span above the payload length.</li><li>Feed identifiers (keccak256(topic ‖ uint64BE index)) with feed-update payloads (uint64BE timestamp ‖ reference).</li><li>All three key kinds.</li></ul> |

Rust tests replay every case. The generator's `check` mode re-derives every vector from the reference. CI fails if either side drifts.

## Implementation

- **`fc-evm` (logic crate, no I/O):**
  - an RLP encoder (minimal big-endian integers, the byte-string and list rules);
  - the two transaction serializations;
  - EIP-191;
  - the EIP-712 encoder above;
  - the `r ‖ s ‖ v` signature format.

  It uses `k256` (RFC 6979, low-s, recovery id) and `sha3` (keccak), both already in the workspace. There are no new dependencies. The encoder is written for ethers' semantics rather than taken from a general ABI library, because parity, including which inputs are rejected, is the contract.
- **`fc-swarm` (logic crate, no I/O):** BMT, the content-addressed chunk address, the SOC digest and the SOC address. Single owner chunks only; no network.
- **`freedom-cored`:** the four methods, in the same worker path as `compat.*`: admitted against the epoch, secrets zeroized after use, `vault_locked` on revocation. Signing takes no KDF, so it is fast. It still runs in the worker, so a large typed-data request can't stall the event loop.
- Both crates compile for iOS and Android, as CI requires of logic crates.

## Migration in freedom-browser

One PR per step, each after the freedom-core release that provides it.

1. **EVM signing.**
   - `signers.js`'s vault backend calls `sign.transaction`, `sign.message` and `sign.typed_data`.
   - `computeAddress(pk)` gives way to `keys.addresses`.
   - Safe owner signatures, the executor EOA and x402 go through the same backend. x402's `BigInt`s are serialized as strings.
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

1. **Auto-lock.** Should `sign.*` restart the auto-lock timer itself? Proposed: no. Main keeps calling `vault.touch` where it does today: after vault-account signing, but not after Swarm signing. Revisit with policy.
2. **SOC payloads larger than one chunk.** `writeFeedPayload` uploads big payloads through `/bytes` first, and the core then signs the root chunk. A later phase could chunk and hash the whole payload in the core. That isn't needed for parity.
3. **Error strings.** dApps see main's error mapping, not ethers' exact messages. Do any callers match on ethers' message text? Check during the browser migration.
