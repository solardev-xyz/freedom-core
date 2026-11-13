# 0016: Ledger and Safe in the core

**Status:** proposed. Roadmap items 2.5 (Ledger) and 2.6 (Safe). Builds on [0001](0001-freedom-cored.md) (the process, core-to-main requests, cancel), [0002](0002-signing.md) (signing, and the typed-data view of #88), [0005](0005-chain-data.md) (chain reads, the fee check, the one-nonce rule), [0011](0011-page-requests.md) (handles, the approvals document), [0012](0012-approvals.md) (tokens and grants: it enforces a Safe's vault owners' and executor's signatures from APR-4, through Safe approvals, and lists a Ledger's, a Safe's Ledger owner's included, as "advised until 0016") and [0013](0013-profiles.md) (`vault-meta.json` and `safe-pending.json` in the core). It amends 0002's non-goal on Ledger and Safe accounts ([Amendments](#amendments)). Nothing here is built yet. The user decides the [open questions](#open-questions).

**The references:**
- **freedom-browser** at `32532528` (`integration/rust-core`), in `src/main/`:
  - `wallet/ledger/transport.js` (131 lines), `signer.js` (109), `errors.js` (129) and `ipc.js` (29);
  - `wallet/safe/safe-executor.js` (465), `safe-service.js` (259), `safe-transactions.js` (300), `safe-messages.js` (383), `signature-collection.js` (146), `pending-store.js` (70) and the test helper `__tests__/helpers/stub-chain.js`;
  - their callers: `wallet/signers.js`, `wallet/signing-utils.js`, `wallet/wallet-ipc.js` (the Safe handlers, 810–995), `wallet/signing-confirmation.js` (`bindingFor`), `wallet/transaction-service.js`, `wallet/nonce-reservations.js`, `wallet/provider-manager.js` (`getEip1193Provider`), `wallet/remote/signer.js` and `identity-manager.js` (the device and Safe records);
  - in `src/renderer/lib/`: `wallet/connect-ledger.js`, `wallet/send.js`, `wallet/dapp-tx.js`, `wallet/safe-signing.js` and `dapp-provider.js`.
- **The packages its lockfile pins,** read from their npm tarballs: `@ledgerhq/hw-app-eth` 7.11.1, `@ledgerhq/hw-transport` 6.36.0, `@ledgerhq/hw-transport-node-hid` 6.33.5 (with `-noevents` 6.36.0), `@ledgerhq/evm-tools` 2.0.0, `@safe-global/protocol-kit` 8.0.11 (`dist/cjs/src/index.cjs`), `@safe-global/safe-deployments` 1.37.66, `@x402/evm` 2.29.0 (`dist/cjs/exact/client/index.js`) and `ethers` 6.17.0. The reference checkout's install has hw-app-eth 7.10.0 and protocol-kit 8.0.7. hw-app-eth's `lib/Eth.js` and `lib/modules/EIP712/` are the same in 7.10.0 and 7.11.1.
- **freedom-core** at `06c2335b` (`main`): `fc-evm` (`eip712.rs`, `tx.rs`, `signature.rs`) and `fc-naming` (`abi.rs`).

## Summary

- **Today** main drives the Ledger with hw-app-eth, which builds every APDU. Main builds every Safe transaction, address and calldata with protocol-kit, and reads the Safe's state from the first RPC endpoint that answers. The core signs only for vault accounts: a Safe's vault owners and its executor.
- **Ledger (proposed):** main keeps the USB device and relays APDUs. The core builds every APDU from the approved request, checks every answer, and recovers every signature against the account and the digest the user confirmed before anything leaves it. One core-to-main request, `shell.ledger_apdu`, carries one APDU. Main admits only the APDUs that the open operation's row of a closed [grammar](#the-apdu-grammar) allows, and derives every byte of them itself from the request it sent or the approval it recorded, so a faulty core can't put other bytes on the device. hw-app-eth leaves the browser.
- **Typed data on the device ([Q23](#open-questions)):** field by field, as today. Proposed: refuse the hash-only fallback, which shows the user two hashes and nothing else.
- **Bounds:** one device operation at a time, 15 s for an APDU the user doesn't confirm, 5 minutes for one they do, a Cancel, and a defined end when the device is unplugged. Today a signature can wait forever, and only the device can end it.
- **Safe (proposed, [Q24](#open-questions)):** only the Safes Freedom creates today, Safe 1.4.1 on Gnosis. Their deployment addresses and the factory's proxy code are pinned in a new logic crate, `fc-safe`, which computes the address, the deployment, the SafeTx, its hash, the SafeMessage and the `execTransaction` calldata. The Safe's nonce, owners, threshold and setup are read through 0005's chain machine, must each be verified, and are checked before anyone signs; without that evidence nothing is signed. The executor's transaction is prepared by the core. protocol-kit leaves the browser.
- **Approvals:** a Ledger's signatures, a Safe's Ledger owner's included, become enforced in the core, as 0012's other signatures are. A Safe's vault owners' and executor's already are, from 0012's APR-4, through Safe approvals. A `safe-send` token binds the whole SafeTx the core built, not only its `to`, `value` and `data`.
- **Vectors:** recorded APDU exchanges from the JS reference over a scripted device, and from real devices for a smaller set; Safe vectors from protocol-kit through the browser's own modules.
- **Steps:** LDG-1 to LDG-3 and SAFE-1 to SAFE-3.
- **Found while checking the code:** Ledger signatures are used unchecked (F-1); hw-app-eth sends some typed data wrong (F-2); an added Ledger account's address is the chrome's word (F-3); a Safe's address rests on one endpoint's answer (F-4); and two smaller ones (F-5, F-6). Each is a public browser issue, #1063 to #1068. See [Facts](#facts-found-while-checking-the-code).

## Goals and non-goals

**Goals**
- **Main never chooses a byte the device signs,** but the nonce, which it keeps choosing under the account's lock until 0013 moves the intent journal (0012, *Transaction building*).
- **No device signature is used before the core checks it.**
- **A faulty core can't make the device sign** anything main didn't derive itself from the request it sent or the approval it recorded.
- **No Safe transaction, address or calldata that the core didn't build.**
- **No Safe read on one endpoint's word** where the chain machine can do better.
- **Enforced approvals** for both, as 0012 enforces the vault's, and a Safe's vault owners' and executor's through its Safe approvals.
- **Parity** with the JS reference, shown by vectors, with every [deviation](#deviations) listed.
- **Bounded, cancellable device work.**

**Non-goals**
- **A compromised main.** Stage 1 trusts main (0001). It holds the device, so it can send its own APDUs. The device's screen is the last check.
- **Clear signing with Ledger's metadata services** (token and plugin descriptors, EIP-712 filters). They stay off, as today, since they send the request to hosted services (`signer.js:14–25`). A bundled offline registry is a later decision.
- **Other hardware wallets, Ledger over Bluetooth, and mobile's transport.** `fc-ledger` is sans-I/O, so mobile can drive it later through its own transport.
- **Other Safe versions or chains, Safes made elsewhere, modules and owner changes** ([Q24](#open-questions)).
- **Safe's hosted Transaction Service:** never, as today (`safe-executor.js:11–12`).
- **Phone accounts,** including phone owners of a Safe: 0012's phone jobs.

## Today

### Ledger

- **The transport** (`transport.js`): `@ledgerhq/hw-transport-node-hid` over node-hid. It opens the first Ledger it finds for each operation and closes it after (`TransportNodeHid.open('')`, 81–93), and one queue serializes all device access (66–98). hw-app-eth's `Eth` is built with every hosted lookup off (`OFFLINE_LOAD_CONFIG`, 58–64).
- **Discovery** (`ledger:get-accounts`, `ipc.js:18–26`): `getAddress(path, false)` for 1 to 20 paths (`transport.js:112–129`) of two schemes: `live`, `44'/60'/i'/0/0`, and `legacy`, `44'/60'/0'/i` (35–44). The address is never shown on the device: "verification on-device happens when the user confirms their first signature" (104–107). The connect screen polls it every 1.5 s (`connect-ledger.js:18`), the Safe board every 2 s (`safe-signing.js:504–524`).
- **Adding** (`wallet:add-ledger-wallet`, `identity-manager.js:1653–1660`): the chrome sends a name, an address and a path. Main checks that the address parses (1032) and that the path is a non-empty string (1079–1081), and stores both.
- **Signing** (`signer.js`). Every operation first reads the address at the record's path and refuses another (`LEDGER_WRONG_DEVICE`, 53–60). Then:
  - **a transaction:** ethers' unsigned serialization goes to `signTransaction(path, raw, null)` (65–76). With no resolution a contract call shows as raw data, and the app refuses it unless its blind-signing setting is on (`0x6a80`, `errors.js:61`);
  - **a message:** `signPersonalMessage` (78–85);
  - **typed data:** main first hashes it through the core and compares the hash with the confirmed one (`signers.js:196–206`). Then `signEIP712Message` sends every type and value. On status `0x6d00` (instruction not supported) it falls back to `signEIP712HashedMessage` with ethers' domain separator and struct hash (`signer.js:93–102`). hw-app-eth's own note: the field method "is not compatible with nano S (LNS)" (`Eth.js:318`).
- **The APDUs** hw-app-eth sends for these, with no resolution and no filters:

  | APDU | CLA INS P1 P2 | Data | Sent by |
  |---|---|---|---|
  | get address | `E0 02 00 00` (`01` to display) | path | `Eth.js:102–132` |
  | app name and version | `B0 01 00 00` | — | `EIP712/utils.js:244–258`, typed data only |
  | sign a transaction | `E0 04 00 00`, then `E0 04 80 00` | path ‖ unsigned RLP, in pieces of at most 255 bytes | `Eth.js:147–223`, `utils.js:202–247` |
  | sign a message | `E0 08 00 00`, then `E0 08 80 00` | path ‖ length (4 bytes) ‖ message, at most 150 bytes per APDU | `Eth.js:272–298` |
  | EIP-712 type definitions | `E0 1A 00 00` (a type's name), `E0 1A 00 FF` (a field) | names and type descriptors | `EIP712/index.js:114–129` |
  | EIP-712 values | `E0 1C 00 00` (a root), `E0 1C 00 0F` (an array's length), `E0 1C 01 FF` / `00 FF` (a value's pieces) | the values | `EIP712/index.js:149–190` |
  | EIP-712 sign, fields | `E0 0C 00 01` | path | `EIP712/index.js:396–410` |
  | EIP-712 sign, hash only | `E0 0C 00 00` | path ‖ domain separator ‖ struct hash | `EIP712/index.js:428–452` |

- **App checks:** Freedom checks neither the app's name nor its version. hw-app-eth reads `B0 01` inside `signEIP712Message` only to choose a filter format (`EIP712/index.js:323–325`), and no filter is ever sent, since the lookups are off.
- **Errors:** status words and transport errors map to nine `LEDGER_*` codes with fixed texts (`errors.js:12–81`).
- **Waiting:** nothing has a deadline. node-hid's `exchange` reads until the device answers (`TransportNodeHid.js:132–159`); hw-transport's 15 s `unresponsiveTimeout` only emits an event (`Transport.js:251–290`); and its `close()` waits for the exchange in flight (`TransportNodeHid.js:162–165`). A signature holds the device queue and the account's nonce lock, whose holder "is never cut short" (`nonce-reservations.js:18–19`). The send screen's Ledger state has no Cancel (`send.js:479–486`), and the dApp approval disables Reject and Back while it signs (`dapp-tx.js:613`). Only the device, or unplugging it, ends a signature.
- **Unplugged:** node-hid's read or write fails, which maps to `LEDGER_DISCONNECTED` (`errors.js:73–74`). Nothing is signed, and a send releases its nonce (`nonce-reservations.js:15–17`).

### Safe

- **Which Safes:** version 1.4.1 (`SAFE_VERSION`, `safe-executor.js:55`), created in Freedom with 1 of 2 or 2 of 3 of the user's own accounts (`identity-manager.js:1117–1137`), on Gnosis only (`DEPLOY_CHAIN_ID`, `safe-service.js:43`; sends elsewhere refused, `safe-transactions.js:127–130`). On Gnosis protocol-kit predicts with the L2 singleton (its L1 list is chain 1 only, `index.cjs:197–200`, `2146–2148`) and the canonical `CompatibilityFallbackHandler` (`6710–6720`). The canonical 1.4.1 addresses, the same on every chain (safe-deployments 1.37.66, `assets/v1.4.1/`):

  | Contract | Address |
  |---|---|
  | `SafeL2` | `0x29fcB43b46531BcA003ddC8FCB67FFE91900C762` |
  | `SafeProxyFactory` | `0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67` |
  | `CompatibilityFallbackHandler` | `0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99` |

- **Creating:** main resolves the owners' indexes to their addresses, draws a 128-bit salt (`safe-service.js:46–48`), predicts the CREATE2 address with protocol-kit and stores the record frozen (86–96).
- **Building a SafeTx:** protocol-kit's `createTransaction` with `{ to, value, data }` (`safe-executor.js:201–203`). It sets operation CALL, the three gas fields 0, no gas token or refund receiver, and the nonce from the chain (`standardizeSafeTransactionData`, `index.cjs:5864–5934`). Then `generateTypedData` and ethers' hash (`safe-executor.js:107–122`).
- **Chain reads:** protocol-kit and main read through `getEip1193Provider` (`provider-manager.js:122–140`): the first endpoint that answers, with no quorum and no proof, outside 0005's router (0005, "Paths that bypass the router"). protocol-kit reads `eth_chainId`, `eth_getCode`, `proxyCreationCode()`, `nonce()`, `VERSION()`, `getThreshold()` and `getOwners()` (the surface `stub-chain.js` answers). Main reads `nonce()` before it executes (`safe-transactions.js:48–55`) and `eth_getCode` to learn whether the Safe is deployed (`safe-service.js:103–113`).
- **Approval:** the `safe-send` token binds the Safe's index, the chain, `to`, `value`, `data` and the site (`signing-confirmation.js:331–343`). `wallet:safe-send` spends it and then builds the SafeTx (`wallet-ipc.js:865–888`).
- **Owner signatures:** vault owners sign silently when the SafeTx is made and whenever the board opens (`signature-collection.js:64–85`); a device owner signs when the user taps its row (98–136). Each signature is recovered against its owner (`safe-executor.js:224–238`). Execution needs as many as the record's threshold (`safe-transactions.js:229–233`). The Safe's own owners and threshold are never read.
- **Execution:** the executor is the first vault owner (`safe-executor.js:447–454`). protocol-kit sorts and joins the signatures into `execTransaction`'s calldata (358–399). The executor's fee is judged by 0005's check (260–287), and the transaction goes through transaction-service's journal and broadcast (305–339). A Safe nonce already past the SafeTx's makes it `superseded` (`safe-transactions.js:222–227`).
- **Messages (EIP-1271):** a SafeMessage `{ message: digest }` under the domain `{ chainId: 100, verifyingContract: safe }` (`safe-messages.js:263–273`). The digest is EIP-191's for `personal_sign` and the core's EIP-712 hash for typed data (60–71). Sessions live in memory, bound to the requesting page and a random token (238–317). `buildSignatureBytes` joins the signatures (346–360).
- **The pending store:** `safe-pending.json`, one entry per Safe, written in place (`pending-store.js:41`).

### What the core signs today

- **For a vault account,** under 0002: a Safe's vault owners' SafeTx and SafeMessage signatures (`sign.typed_data`, with the core's own hash as `expected_hash`, `signers.js:117`) and the executor's transaction (`sign.transaction`). The core also hashes a Ledger's typed data before the device is asked (`signers.js:200–205`).
- **Main's:** every APDU, every Ledger signature's assembly, every SafeTx field, the Safe's address, the deployment and the `execTransaction` calldata.
- **0012:** from APR-4 the core enforces every signature it makes for a page (Q8), a Safe's vault owners' and its executor's included, through the Safe approval a `safe-send` or `safe-message` token gives. It asks a Safe approval of the wallet's own Safe send too (0012, *A page's Safe and Swarm signatures*). A Ledger's signature, a Safe's Ledger owner's included, is advised (`approval.spend`) until this design.

### Facts found while checking the code

1. **F-1: Ledger signatures are used unchecked** (freedom-browser #1063). The Ledger backend returns whatever `r`, `s` and `v` the device sends, for a transaction, a message and typed data (`signer.js:65–105`). A signed transaction is committed to the intent journal (`transaction-service.js:581–589`) and broadcast (`:461`), and a message or typed-data signature goes back to the site (`wallet-ipc.js:753–808`). The vault backend recovers every signature against its key (`signers.js:84–89`, `102`, `122`), and so does the phone's (`remote/signer.js:67–104`). A Safe owner's signature is the one Ledger path that is checked (`safe-executor.js:224–237`). So a device or library fault that signs another digest (F-2) reaches the site as the confirmed signature.
2. **F-2: hw-app-eth sends some typed data wrong** (freedom-browser #1064). Four faults in hw-app-eth 7.11.1's `lib/modules/EIP712/`, shown by running its own `signEIP712Message` (7.10.0's identical code, from the reference checkout) against a recording transport:
   - **A value loses its last bytes** when its encoding (a 2-byte length, then the value) is 255·n + 1 to 256·n bytes long: the pieces are counted per 256 bytes but cut per 255 (`index.js:180–182`). A 254-byte string goes as 255 of its 256 bytes, and a 510-byte one as 510 of 512.
   - **An array of more than 255 entries is announced with a wrong count:** the count's hex is cut to one byte (`intAsHexBytes(value, 1)`, `index.js:165`, `utils.js:89`), and `Buffer.from(…, 'hex')` drops the odd digit. 256 entries are announced as 16, and 300 as 18. A fixed array's size and the length of a type or field name over 255 are cut the same way (`EIP712/utils.js:176`, `186`, `193`).
   - **A name of 256 ASCII characters** makes a 259-byte APDU, which hw-transport refuses (`DataLengthTooBig`, `Transport.js:188–191`), so the user sees "Ledger error". That holds for an ASCII name only; for any other name, the next fault decides the length.
   - **A non-ASCII name is announced with its length in UTF-16 units, not bytes:** `makeTypeEntryStructBuffer` writes `name.length` before the name's UTF-8 bytes (`EIP712/utils.js:166–194`). A field named `é` is announced as 1 byte and takes 2, one named `😀` as 2 and takes 4, and a field of a custom type named `Té` names its type as 2 bytes and sends 3. ethers 6.17.0 accepts such names; 0002 refuses them ([Encodings](#the-apdu-grammar)).

   What a device does with the first, second and fourth isn't known without one. If it signs, F-1 returns that signature unchecked, although the device hashed values the browser didn't show. Whether upstream knows of these hasn't been checked.
3. **F-3: an added Ledger account's address is the chrome's word** (freedom-browser #1065). `wallet:add-ledger-wallet` stores the address and path the chrome sends (`identity-manager.js:1653–1660`, `1078–1083`), and never asks the device. A compromised chrome can add a "Ledger" whose address the device doesn't hold. Signing from it fails (`LEDGER_WRONG_DEVICE`), but nothing else needs a signature: the wallet lists it as the user's, and it can be made an owner of a new Safe (`wallet:create-safe`, `wallet-ipc.js:812–820`). As one of a 1-of-2 Safe's owners, that address controls the Safe alone.
4. **F-4: a Safe's address rests on one endpoint's answer** (freedom-browser #1066).
   - protocol-kit computes the CREATE2 address from `proxyCreationCode()`, which it reads from the factory (`index.cjs:6740–6756`, `6859`) through `getEip1193Provider`, at creation (`safe-service.js:86–96`). A wrong answer gives an address no deployment can reach, and funds sent there before activation are lost.
   - Activation deploys at the address the current answer gives, and marks the record deployed without comparing that address with the record's (`safe-service.js:225–247`).
   - `isDeployedOnChain` marks a record deployed for good on one endpoint's `eth_getCode` (103–113). Activation is then never offered again.
   - The code is a constant of the canonical factory: `stub-chain.js` records it, 486 bytes, keccak256 `0x1856e0ee08399d74e0ea0b03adca210aeade6f748969ac023cdcb4dd62dcaf5f`.
5. **F-5: an empty `personal_sign` fails on a Ledger** (freedom-browser #1067), with "Ledger error. Reconnect the device and try again." hw-app-eth's loop sends no APDU for a message of 0 bytes and then reads `response[0]` of nothing (`Eth.js:277–295`), which maps to `LEDGER_UNKNOWN`. Low.
6. **F-6: a torn `safe-pending.json` loses every half-signed Safe transaction** (freedom-browser #1068). It is written in place, and a file that doesn't parse loads as `{}`, which the next write saves (`pending-store.js:28–41`). The device signatures collected for those transactions go with it. 0013 lists the file as written in place; this is the consequence.

## Threat model

Stage 1 trusts main (0001). The attackers are 0011's and 0012's: a compromised chrome renderer, a bug in main, and whoever reaches a signature through one; and for these two features, a site's request, one lying RPC endpoint, a fault in a library or a device, and a faulty core. The core holds the vault's keys, so main can't contain it there; a Ledger's key is the one it doesn't hold, and main's grammar is what keeps a faulty core from using it.

| The attacker wants to | Today | After LDG-3 and SAFE-3 |
|---|---|---|
| Have the device sign bytes the approval didn't cover (a main bug) | Yes: main builds every APDU | No. The core builds them and main derives them again; a main bug that changes one gets a signature the core refuses. The nonce stays main's (0012) |
| Swap the typed data, SafeTx or SafeMessage of a live Ledger signature for another of the same shape (a faulty core) | — (the core sends no APDU today) | No: main derives every APDU byte from the request it sent or the approval it recorded, and refuses any other before the device ([Main's typed-data binding](#mains-typed-data-binding)) |
| Have a Ledger sign another x402 schema, spender or time window (a faulty core) | — (main builds the authorization today) | No: main rebuilds the whole authorization from the accept entry, its own clock and the core's nonce, and sends its own copy ([x402 from a Ledger account](#x402-from-a-ledger-account)) |
| Have a Ledger sign a SafeTx the user discarded, through a stale approval (a faulty core) | — | No: approval records live in main's memory only, and are dropped before a discard reaches the core ([Approval records](#approval-records)) |
| Pass a signature over something else as the confirmed one (F-2, a stale answer, a device fault) | Yes (F-1) | No: recovered against the account and the confirmed digest |
| Get a typed-data signature the device shows only as two hashes (a site that targets a Nano S) | Yes: the fallback | No, if [Q23](#open-questions) is yes |
| List an address the device doesn't hold (chrome) | Yes (F-3) | No: the core reads it from the device |
| Hold the device and the account's sends indefinitely (a request left on the device) | Yes | No: 5 minutes, and a Cancel |
| Make a new Safe's address unreachable (one endpoint) | Yes (F-4) | No: the address uses pinned constants and no chain read |
| Mark an undeployed Safe deployed, or deploy elsewhere (one endpoint) | Yes (F-4) | No on a verified read; otherwise the router's answer, and activation compares the address |
| Have owners sign a SafeTx whose operation, gas, refund or nonce fields the prompt didn't cover (a main bug) | Yes: the token binds only `to`, `value` and `data`, and the Safe pays a refund out of its own balance | No: the token binds the whole SafeTx the core built |
| Execute for a Safe whose owners or threshold were changed elsewhere | The record's owners and threshold count | Refused ([Q24](#open-questions)) |
| Report the record's setup for a Safe that was changed (one lying endpoint) | The setup isn't read | No: every read the decision rests on must be verified, or nothing is signed ([Chain reads](#chain-reads)) |
| Change the Safe's own setup through a site's transaction | Yes, like any call | No, if [question 4](#open-questions) is yes |
| Sign with the executor's key for something other than a ready SafeTx (a main bug) | Yes, under `shell` | No: only the core's prepared send, or an `executor-send` token for a fee the check stopped |
| Act as main | Everything | Everything: main holds the device and relays its answers |

**What stays open:**
- **A compromised main** can drive the device itself, and it sees every answer the device sends.
- **What the device shows** for a contract call is raw data with clear signing off, and needs the app's blind-signing setting. The core can't change that.
- **A user who approves on the device without reading.**
- **The chrome's wallet kinds** until APS-3 (0011, 0012).
- **Unverified reads for display only** (a balance, an activation cost): the router's quorum or one endpoint decides them, as the user's policy sets. No signature or execution rests on one.

## Ledger

### Where the device lives

**Proposed: main keeps the USB HID device, and the core sends it APDUs through main.**
- **Main** keeps `@ledgerhq/hw-transport-node-hid` for the device's HID framing, and drops `@ledgerhq/hw-app-eth` with what it pulls in (`axios`, `@ledgerhq/domain-service`, `@ledgerhq/evm-tools`). It uses three things: `TransportNodeHid.open`, `exchange`, and, to cancel, a close of the node-hid handle. The transport's own `close()` can't cancel, since it waits for the exchange in flight.
- **The core** builds each APDU from the request it authorized and the account's record, reads each answer, and assembles and checks the signature. It holds no key for it.
- **Why not HID in the core:** it would add a C library (hidapi) and per-OS device code to the core, and a device grant to D7's confinement later (0010). Mobile needs Bluetooth and its own transport anyway. And in Stage 1 main is trusted, so taking the device from main protects against nothing that the checks below don't already cover ([Options weighed](#options-weighed)).

### The device lane

- **One operation at a time,** browser-wide, as today's queue. At most 8 wait, in order; a ninth is refused `LEDGER_BUSY`. A wait counts against the operation's 5 minutes.
- **Discovery doesn't wait:** while an operation runs, `ledger.accounts` answers `LEDGER_BUSY` at once (deviation `discovery-busy`). Today a poll waits behind a signature.
- **An operation belongs to one core request,** its parent: a `sign.*` request with a Ledger key, `ledger.accounts`, `ledger.add`, or `safe.sign_owner` for a Ledger owner. Main opens the device at the operation's first APDU and closes it when the parent ends, so Ledger Live can use the device in between, as today.
- **The vault:** no vault key is used, so the core doesn't require it unlocked for a Ledger key. Main's gates before the prompt stay as they are.

### `shell.ledger_apdu`

A core-to-main request, like 0004's `shell.*`:

| Params | Main does | Reply |
|---|---|---|
| `{ for, apdu }`: the parent's envelope ID, and one APDU, hex, 5 to 260 bytes (`CLA INS P1 P2 Lc data`, `Lc` ≤ 255) | checks the APDU against the [grammar](#the-apdu-grammar) for `for` at its step; opens the device on the operation's first APDU; one `exchange`, under the row's deadline | `{ answer }`: hex, 2 to 260 bytes, ending in the status word. Or `{ failed }`: `not_found`, `busy`, `disconnected`, `unresponsive` or `timeout` |

- **Read strictly both ways,** as 0015 reads `shell.swarm_api`: an unknown member, a wrong type or an answer outside its bounds is `invalid_argument` from main, and a protocol error in the core.
- **Main closes the device** when the parent ends, on a cancel, on a `failed`, and on a refused APDU.

### The APDU grammar

**Encodings.** `P` is a path: one byte, the number of elements `n`, then each element as 4 bytes, big-endian, with `0x80000000` set for a hardened one. Only the two schemes' forms are admitted: `44'/60'/i'/0/0` (`n` = 5) and `44'/60'/0'/i` (`n` = 4), with `i` from 0 to 2^31 − 1 (deviation `path-strict`: hw-app-eth's `splitPath` skips an element it can't read, `utils.js:52–67`). `T` is the unsigned serialization of the bound transaction, the payload 0002's `sign.transaction` signs: for type 0, `rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])`; for type 2, `0x02 ‖ rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, []])`. **Names are ASCII:** 0002 refuses a type or field name outside `[A-Za-z_$][A-Za-z0-9_$]*` before anything is hashed, so a name's length in bytes is its length in characters, and its one-byte prefix is that count, at most 255 ([Bounds](#bounds)). hw-app-eth announces a non-ASCII name's length in UTF-16 units (F-2); the core never sends one (deviation `name-ascii`).

**The rows** are normative. Each operation is its APDUs in this order, and no other.

| Operation | APDUs, in order | Bytes, all from | Waits for the user |
|---|---|---|---|
| `ledger.accounts`, `c` from 1 to 20 | `E0 02 00 00` `P(path_k)`, `c` times | the scheme's paths for `start` … `start + c − 1` | no |
| `ledger.add` | `E0 02 01 00` `P` if question 3 is yes, else `E0 02 00 00` `P` | the path asked | yes, with the display |
| every signature, first | `E0 02 00 00` `P`, once | the record's path | no |
| every signature, second | `B0 01 00 00`, no data, once | — | no |
| `sign.transaction` | `E0 04 00 00` with the first piece, then `E0 04 80 00` with each other piece of `P ‖ T` | the bound transaction (nonce included, which main chose). Pieces of 255 bytes; for type 0, the size hw-app-eth's `safeChunkTransaction` picks so that no piece ends where a legacy transaction could (`utils.js:202–247`) | the last piece |
| `sign.message` | `E0 08 00 00` with `P ‖ len(m)` (4 bytes, big-endian) and the first `150 − 5 − 4n` bytes of `m`, then `E0 08 80 00` with each next 150 bytes | the bound bytes `m`, at least 1 (deviation `empty-message`, F-5) | the last |
| `sign.typed_data`: definitions | for each type, its names in ascending order (as `sortObjectAlphabetically` sorts them, evm-tools `message/EIP712/index.js:23–35`): `E0 1A 00 00` its name, then `E0 1A 00 FF` for each field in order | the bound typed data's types, `EIP712Domain` built from the domain's keys, as ethers' `getPayload` builds it | no |
| `sign.typed_data`: values | `E0 1C 00 00` `"EIP712Domain"`; each domain value; `E0 1C 00 00` the primary type's name; each message value, depth first. An array: `E0 1C 00 0F` with its length, then its entries. A value: its encoding (2-byte length ‖ value bytes) in pieces of 255, `E0 1C 01 FF` for each but the last, `E0 1C 00 FF` for the last | the core's parse of the bound values, encoded as hw-app-eth's `EIP712_TYPE_ENCODERS` encode them (`EIP712/utils.js:62–102`), and cut as F-2 says they should be (deviation `field-pieces`) | no |
| `sign.typed_data`: sign | `E0 0C 00 01` `P`, once | the record's path | yes |
| the hash-only form, if Q23 is no | `E0 0C 00 00` `P ‖ domainSeparator ‖ hashStruct(message)`, once, only after `6D00` answered the operation's first `E0 1A` | `fc-evm`'s hashes of the bound typed data, not ethers' in main | yes |
| `safe.sign_owner`, a Ledger owner | as `sign.typed_data`, over the core's SafeTx or SafeMessage | the approved SafeTx or SafeMessage ([Owner signatures](#owner-signatures)), which main derives from its own record ([below](#mains-typed-data-binding)) | yes |

**No free field.** Every byte of every APDU is derived twice: by the core, from the request it authorized and the record's path; and by main, from the request it sent or the approval it recorded, and the same path ([Main's typed-data binding](#mains-typed-data-binding)). Main compares the two byte for byte. No byte comes from an earlier answer of the device. The one value main takes from the core is a Ledger x402 payment's nonce, which names no recipient, amount, spender or time; the payment's times are main's own clock reading, which main sends to the core ([below](#mains-typed-data-binding)).

**What main checks,** for each `shell.ledger_apdu`, from what main itself knows: the parent it sent and its params, and the account's record.
- **The parent** is live and is one of the rows' operations, for a Ledger account.
- **Order and counts:** the APDU is the next its row allows. One at a time per operation.
- **Header and length:** `CLA INS P1 P2` as the row has them; `Lc` ≤ 255, and equal to the data's length.
- **The path** is the record's, wherever the row has `P`.
- **The payload,** for every row: main builds the operation's whole expected stream itself, and each APDU must equal the next one of it, header and data, byte for byte. For a transaction or a message that is `P ‖ T` or `P ‖ len(m) ‖ m` in the row's pieces, built from the parent's params with ethers, as `signing-utils.js` does today. For typed data it is the definitions and values main encodes itself ([below](#mains-typed-data-binding)).
- **The rare ones:** `E0 02 01 00` only under `ledger.add`; `E0 0C 00 00` only after a `6D00` answer to the operation's first `E0 1A`, and never if Q23 is yes.
- **A refused APDU** is answered `invalid_argument` with `data: { rule }` (`parent`, `order`, `header`, `count`, `path`, `payload` or `ended`), before any byte reaches the device. Main logs the rule, never an APDU's bytes, refuses every later APDU of that parent and closes the device. The core ends the parent with `LEDGER_UNKNOWN`.
- **One source:** the grammar is data, `vectors/ledger-grammar.json`: the rows, each row's honest APDUs, which must be admitted, and its nearest forbidden ones, which must be refused. The core's tests and main's relay suite both read it, as 0015's `swarm-grammar.json` is read.

### Main's typed-data binding

Main encodes the whole typed-data stream itself, from what it holds, and compares every APDU with it byte for byte. The encoder is a new module in main (`wallet/ledger/apdu-binding.js`), written from this design, not taken from hw-app-eth.
- **`sign.typed_data`:** from the request main sent. Main first checks with ethers' `TypedDataEncoder.hash` that `typed_data` hashes to `expected_hash`, and refuses before the first APDU if it doesn't. Then it takes ethers' `getPayload`: the types with `EIP712Domain`, the primary type, the domain and the message, with integers as decimal strings. It encodes the definitions with the types in ascending order of their names and each field's descriptor, then the values depth first, each in pieces of 255, as [the rows](#the-apdu-grammar) say. If Q23 is no, it computes the hash-only APDU's two hashes with ethers too.
- **A SafeTx, for a Ledger owner:**
  - **At the approval,** main computes the SafeTx's hash itself, with ethers, from the fields the prompt showed (`safe.prepare`'s result), under the fixed `SafeTx` type and the domain of the Safe's address the prompt named, on chain 100. It requires that hash to equal the core's `safe_tx_hash`, and keeps it as its **approval record**: the Safe's index and address, the chain and the hash, one per Safe, before it sends `safe.propose`.
  - **At a Ledger owner's turn,** main reads the pending entry's fields (`safe.pending`), computes their hash again, and requires its own record's. It encodes the stream from those fields.
  - **The records live in main's memory only,** never in a file ([Approval records](#approval-records)). With no record (after any restart of main, a crash, or an older build run in between), the approvals surface shows the SafeTx, rebuilt by main from the fields, and the user approves it again before the device is asked. That decision records it again.
- **A SafeMessage, for a Ledger owner:** from the page's request main holds (0011's request record): the digest by ethers (`hashMessage` for `personal_sign`, `TypedDataEncoder.hash` for typed data), then `{ message: digest }` under the domain of the Safe's address on chain 100. Sessions live in memory, so nothing is written.
- **An x402 payment from a Ledger account** goes as `sign.typed_data`, under [the x402 reconstruction](#x402-from-a-ledger-account) below: main rebuilds the whole authorization itself and sends its own copy.
- **Two derivations:** main encodes from ethers' parse, the core from `fc-evm`'s. Both must reproduce `ledger.json`'s APDUs, which is their joint contract. Where they would differ for an input the core accepts, main refuses: the operation fails closed with nothing signed, and the case is a vector to raise, not to edit.
- **The vault owners** of a Safe sign in the core, which holds their keys, so main's binding doesn't apply to them.
- **What this stops:** during a live `sign.typed_data` or a Ledger `safe.sign_owner`, a faulty core can't send another schema, message, SafeTx or SafeMessage of the same shape. Any changed byte is a `payload` refusal, before the device.

### Approval records

A record is authority: it decides what a Ledger may sign without another approval. So it follows 0013's set-A rule for such state, a narrowing applied first and nothing restored that was taken away, though main holds it, as its own check on the core, rather than the core.
- **In memory only.** No file, so nothing outlives the process that made it. A stale record can't come back: not after a crash, not from a failed removal on disk, and not after an older build discards the SafeTx (an older build never sees the record, and the next start has none).
- **Narrowing first.** Main drops a Safe's record before it asks the core to discard the SafeTx, when `safe.execute` answers `superseded`, and when it reports `safe.executed`. A failure after that leaves no record. A pending entry the core still holds then needs a new approval before a Ledger signs it.
- **Recording last.** Main records a hash only on the user's decision on the approvals surface (the chrome's until APS-3, the approvals document after, as for every wallet kind), and only once its own hash equals the core's. If `safe.propose` then fails, main drops the record.
- **Bounds:** one record per Safe, as there is one pending SafeTx per Safe: a new approval replaces the Safe's old record. About 100 bytes each.
- **The cost:** after a restart, a Ledger owner's signature on a SafeTx approved before it needs one more approval. Vault owners sign in the core and aren't affected; neither are SafeMessages, whose sessions end with their page.

### x402 from a Ledger account

For a Ledger account, `x402.authorize` (0012's X402-1) checks the cap or the `x402-payment` token and charges the cap as for any account. It takes one more input, `now_s`: main's wall-clock reading in seconds, taken once for this payment. The core refuses a `now_s` more than 30 s from its own clock. Then it returns the authorization as typed data, with the nonce it drew, instead of signing it. Main rebuilds the authorization itself, from the accept entry it holds, `now_s` and that nonce, and requires the core's typed data to equal its own in every type, field and value. It then sends its own copy through `sign.typed_data` with the Ledger key, where the core accepts only the authorization it returned. The device's stream is bound to that copy. A refusal or failure on the device gives the cap's charge back, as 0012's `withheld` does.

The forms, exactly as `@x402/evm` 2.29.0 builds them (`exact/client/index.js`):

| Form | Domain | Types (nothing else) | Message |
|---|---|---|---|
| EIP-3009, x402 version 2: `extra.assetTransferMethod` absent or `eip3009` (940–971, 177–227) | `{ name: extra.name, version: extra.version, chainId, verifyingContract: asset }`, `chainId` read from the network `eip155:<id>` | `TransferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce)` (69–78) | `from` the account; `to` `payTo`; `value` `amount`; `validAfter` 0; `validBefore` `now_s + maxTimeoutSeconds`; `nonce` the core's 32 bytes |
| EIP-3009, x402 version 1 (1009–1069) | the same, `chainId` from the package's version-1 network names (35–66) | the same | `value` `maxAmountRequired`; `validAfter` `now_s − 600`; `validBefore` `now_s + maxTimeoutSeconds`; the rest as above |
| Permit2, x402 version 2: `extra.assetTransferMethod` = `permit2` (246–306) | `{ name: "Permit2", chainId, verifyingContract: 0x000000000022D473030F116dDEE9F6B43aC78BA3 }` (141) | `PermitWitnessTransferFrom(TokenPermissions permitted, address spender, uint256 nonce, uint256 deadline, Witness witness)`, `TokenPermissions(address token, uint256 amount)`, `Witness(address to, uint256 validAfter)` (79–95) | `permitted` `{ token: asset, amount }`; `spender` x402's Permit2 proxy, `0x402085c248EeA27D92E8b30b2C58ed07f9E20001` (142); `nonce` the core's random uint256; `deadline` `now_s + maxTimeoutSeconds`; `witness` `{ to: payTo, validAfter: 0 }` |

- **Only these three.** Any other transfer method, network or extension is refused for a Ledger account before the device, as for any account: Freedom's x402 signer has no `readContract`, so the package's EIP-2612 and ERC-20-approval extensions never run (`x402/client.js:40–42`).
- **The times are main's:** `now_s` is main's reading, so every time byte of the authorization is one main derived. The nonce is the only value main takes from the core: 32 random bytes for EIP-3009, a random uint256 for Permit2. It names no recipient, amount, spender or time.
- **Parity:** main's rebuild must reproduce 0012's `x402` vectors, which are `@x402/evm`'s payloads under a fixed nonce and clock, byte for byte.

### Typed data on the device (Q23)

- **Field by field,** as today. The device receives every type and value, shows each field, and computes the digest itself. The core sends the values it parsed, so what the device shows is what the core's view shows (0002, #88), and the signature is checked against the hash the user confirmed.
- **No filters** (`E0 1E`), as today: they come from Ledger's hosted registry. The device shows raw field names and values.
- **The hash-only form** shows the user two hashes and nothing else. The browser's view is then the only display, and the device can't confirm it.
- **Proposed (Q23 yes): refuse it.** A `6D00` to the first `E0 1A` ends the operation with `LEDGER_TYPED_DATA_UNSUPPORTED`: "This Ledger can't show typed data field by field. Update its Ethereum app, or sign with another account." Nothing is signed. The cost: a Nano S can't sign typed data in Freedom, which means permits, x402 payments, sign-in requests that use typed data, and a Safe owner's SafeTx and SafeMessage.
- **If Q23 is no,** the fallback stays, with `fc-evm`'s hashes, only after that `6D00`, and with a view that warns that the device shows only hashes.
- **Transactions with data** aren't part of Q23. The device itself decides how it shows a contract call, and with clear signing off it shows raw data and asks for its blind-signing setting.

### The app

- **Every signature** reads `B0 01` after the address check (deviation `app-check`: today only typed data reads it). The answer's format byte must be 1, and the name must be the Ethereum app's, `Ethereum` (LDG-3's device recordings pin it). Any other name ends the operation with `LEDGER_ETH_APP_NOT_OPEN`, as today's `6D00` and `6E00` do.
- **The version** is kept for the operation's error report only. Field mode is detected by the device's own answer (`6D00`), as today, not by a version table that differs by model.

### Answers the core checks

- **Status:** `9000` goes on. Any other status ends the operation with today's mapping (`errors.js:52–66`), never retried, except the one `6D00` of [Q23](#typed-data-on-the-device-q23).
- **Lengths:** an answer to an APDU that doesn't sign is exactly its status word, but for:
  - `E0 02`: `65 ‖ key (65 bytes) ‖ 40 ‖ address (40 ASCII hex)`. The address must be the one the key derives (keccak256 of its last 64 bytes; deviation `key-check`), and equal the record's;
  - `B0 01`: format, name and version, each within its length.
- **A signature:** `v ‖ r ‖ s`, 65 bytes. For type 0, `v` is read as hw-app-eth's `getV` reads it: the device keeps one byte of `chainId'·2 + 35 + parity`, where `chainId'` is the chain ID's first four bytes (`utils.js:123–187`). Then:
  - **a transaction:** the core assembles the signed transaction, as hw-app-eth and ethers do, and recovers its sender, which must be the account;
  - **a message:** recovered over its EIP-191 hash;
  - **typed data:** recovered over the hash the token bound, never a hash rebuilt from what the device was sent;
  - `s` must be in the low half, as 0002's signatures are.

  Anything else is `LEDGER_BAD_SIGNATURE`: "The Ledger returned a signature that doesn't match this request. Nothing was sent." (deviation `signature-check`, F-1). Nothing a device sends leaves the core before these checks pass.

### Deadlines, cancel and unplugging

- **An APDU the user doesn't confirm:** 15 s, hw-transport's own `unresponsiveTimeout`, which today only warns. Then `LEDGER_UNRESPONSIVE`: "The Ledger stopped answering. Reconnect it and try again."
- **One the user confirms:** 5 minutes, as a phone job's (`remote/bridge.js:50`). Then `LEDGER_TIMEOUT`: "The Ledger wasn't confirmed in 5 minutes. If it still shows the request, reject it there." (deviation `device-deadlines`). Main enforces both on the exchange; the core's own timer is 1 s longer.
- **Cancel:** the parent's cancel (0001), when the user cancels, the prompt's handle closes (0011) or its document goes. The core cancels its pending `shell.ledger_apdu`; main closes the node-hid handle, which ends the read in flight; the parent replies `cancelled`. Its token was burnt when it was presented, as every token is (0012). The browser gains a Cancel in the send screen's Ledger state, and keeps Reject enabled in the dApp approval while the device waits (deviation `cancel`).
- **Unplugged:** a failed write or read is `{ failed: "disconnected" }`, `LEDGER_DISCONNECTED`. Nothing is signed, and a send releases its nonce, as today.
- **A late answer:** after a timeout or a cancel the handle is closed, so the answer has no reader. The next operation opens a new handle, starts with the address check, and recovers its signature against its own digest. An answer meant for another operation is never taken as this one's.
- **A device still showing an older request:** the new operation's first APDU gets an error status, or no answer in 15 s. It ends `LEDGER_BUSY` or `LEDGER_UNRESPONSIVE`, with nothing signed.
- **The core restarting** mid-operation: main closes the device when the core's connection ends, and the parent fails as any request does then (0001). **Main stopping:** the device keeps its prompt until the user rejects it, and its answer reaches no one.

### Bounds

- **Typed data a Ledger can't carry** is refused before the first APDU, with `LEDGER_TOO_LARGE` (deviation `device-bounds`): an array of more than 255 entries; a fixed array size or a number of dimensions above 255; a type or field name over 255 characters (which are bytes, since names are ASCII, [Encodings](#the-apdu-grammar)); a value whose encoding is over 65,535 bytes; or more than 2,048 APDUs in all.
- **APDUs per operation:** at most 2,048 (proposed), so a message is at most about 300 KiB and a transaction's data about 500 KiB on a Ledger. LDG-3 measures the time per APDU on each model, and replaces the number if needed.
- **Memory:** the core builds each APDU as it goes from the parsed request, which 0002's limits already bound. One APDU and one answer are in flight, at most 260 bytes each. An operation's state is at most 64 KiB beyond its request. Main holds one APDU and one answer.

### Accounts

- **`ledger.accounts { scheme, start, count }`** (chrome, shell) → `{ accounts: [{ path, address }] }`, as `ledger:get-accounts` today: display off, 1 to 20 paths, each address checked against its key.
- **`ledger.add { scheme, index, name? }`** (chrome, shell): the core reads the address at that path from the device itself, with the display if question 3 is yes, and the user confirms there. Then it writes the record through 0013's `accounts.*` once PRF-6(a) has made `vault-meta.json` the core's. Until then it returns `{ path, address }`, and main writes exactly those. The chrome no longer sends an address (deviation `address-from-device`, F-3).
- **The key reference:** 0002's table gains `{ "kind": "ledger", "index": n }`, admitted in `sign.transaction`, `sign.message` and `sign.typed_data`. Until PRF-6(a) it also carries the record's `path` and `address`. From then on the core reads the record, and refuses a key whose `path` or `address` differs.

## Safe

### Which Safes (Q24)

**Proposed: exactly the Safes Freedom creates today.** Anything else is refused with `safe_unsupported`, and supporting it is a design change.
- **Version 1.4.1,** with the three canonical contracts [above](#safe), as safe-deployments 1.37.66 lists them, and the factory's proxy code (F-4: 486 bytes, keccak256 `0x1856…af5f`). `fc-safe` pins all four. SAFE-1 checks them against safe-deployments and the recorded code.
- **On Gnosis** (chain 100) only.
- **Two or three of the user's own accounts as owners,** 1 of 2 or 2 of 3, as `identity-manager.js:1117–1137` allows, set up with no setup call, no payment, no module, no guard and the canonical fallback handler.
- **As Freedom made it, still:** before each owner's signature and before execution, the core reads the Safe's setup ([Owners, threshold and setup](#owners-threshold-and-setup)), and refuses to go on when it isn't the record's.

### Built and hashed in the core

`fc-safe` (logic, no I/O) computes each of these from the record and the request, with no chain read:
- **The address:** CREATE2 from the factory, with salt keccak256(keccak256(`initializer`) ‖ the salt as a uint256) and init code hash keccak256(proxy code ‖ the singleton as a uint256), as protocol-kit's `predictSafeAddress` does (`index.cjs:6837–6895`). `initializer` is `setup(owners, threshold, 0x0, 0x, handler, 0x0, 0, 0x0)` (`encodeSetupCallData`, 6680–6730), owners in the record's order.
- **The deployment:** `createProxyWithNonce(singleton, initializer, salt)` to the factory.
- **The SafeTx:** `{ to, value, data, operation: 0, safeTxGas: 0, baseGas: 0, gasPrice: 0, gasToken: 0x0, refundReceiver: 0x0, nonce }`, today's values, with the nonce from the [chain](#chain-reads). Its typed data under the domain `{ chainId: 100, verifyingContract: safe }`, and its hash through `fc-evm`. A request for any other operation, gas field, gas token or refund receiver is refused; Freedom never makes one.
- **The SafeMessage:** `{ message: digest }` under the same domain. The digest is today's: EIP-191's for `personal_sign`, the core's EIP-712 hash for typed data.
- **The calldata** of `execTransaction`: the signatures sorted by owner address, each 65 bytes `r ‖ s ‖ v`, as `buildSignatureBytes` joins them (`index.cjs:1343–1360`). The ABI encoding uses `fc-naming`'s `abi::encode`.

### Chain reads

- **Through 0005's chain machine,** as the core's own reads, with the chain's sources and labels. Never protocol-kit's first endpoint (deviation `safe-reads`).
- **What is read:** `eth_getCode` at the Safe; `nonce()` (`0xaffed0e0`), `getOwners()` (`0xa0e67e2b`), `getThreshold()` (`0xe75235b8`) and `getModulesPaginated(0x1, 1)` (`0xcc2f8452`) by `eth_call`; and by `eth_getStorageAt`, slot 0 (the singleton), the guard's slot `0x4a20…34c8` and the fallback handler's `0x6c9a…18d5` (keccak256 of `guard_manager.guard.address` and `fallback_manager.handler.address`).
- **Verified, or nothing is signed.** Every read a signing or an execution rests on must come back labelled `verified` by 0005's rules: a verifier's proof (Colibri on Gnosis), or a quorum of at least two distinct endpoints that agree (0005's m ≥ 2, deviations `singleton-quorum` and `endpoint-dedup`). These are the code at the Safe, the nonce, the singleton, the owners, the threshold, the guard, the modules and the handler. If any one of them isn't, `safe.prepare`, `safe.propose`, `safe.sign_owner`, `safe.execute` and `safe.message_start` fail with `safe_unverified`: "Freedom couldn't verify this Safe on Gnosis, so it won't sign. Try again, or add an RPC provider in Settings." Nothing is signed, and no `{ send }` is prepared (deviation `safe-unverified`). A read for display only, such as `safe.status`'s balance and cost, keeps its label and blocks nothing.
- **Deployed:** a record is marked deployed only when the code is at the record's own address, after the receipt of a deployment the core prepared, or on a verified read. An unverified read reports "deployed" for the session without writing it, so a later verified read or a deployment can still decide (deviation `deployed-mark`, F-4).

### Owners, threshold and setup

Before each owner's signature and before execution, the core reads the [setup](#chain-reads), each read verified, and requires:
- the singleton is `SafeL2` 1.4.1;
- the owners, as a set, are the record's owners' addresses;
- the threshold is the record's;
- no guard, no module, and the canonical fallback handler.

Anything else is `safe_changed`: "This Safe was changed outside Freedom, so Freedom can't sign for it." Nothing is signed. The board shows the state and offers only to discard (deviation `safe-setup`). Today Freedom counts the record's owners and threshold and never reads the Safe's.

**A site's transaction to the Safe itself** (`to` is the Safe: an owner, threshold, module, guard or handler change) is refused with `safe_self_call` if question 4 is yes. The wallet's own screens never build one.

### Owner signatures

- **One confirmation covers every local owner,** as today (0012): `safe.propose` spends the `safe-send` token and stores the SafeTx the token bound. `safe.sign_owner` signs only a pending SafeTx that was stored that way, and only for one of the record's owners.
- **A vault owner** signs in the core at once while the vault is unlocked: at `safe.propose`, and when the board opens.
- **A Ledger owner** signs through the [device lane](#the-device-lane), when the user taps its row.
- **A phone owner** signs through 0012's phone job, once PHN-1 exists.
- **Every signature** is recovered over the SafeTx's hash, and must come from an owner in the record and in the Safe's set. Only 65-byte signatures with `v` 27 or 28 are kept: Freedom makes no other kind (deviation `owner-signatures`). A second one from the same owner is dropped.
- **The pending entry is checked again** when it is loaded: its hash must be the hash of its SafeTx fields for the record's Safe. An entry that doesn't recompute is set aside, and nothing signs it.

### The executor

- **The executor is a vault account,** the first vault owner, as today (`pickDefaultExecutor`). The core signs its transaction itself.
- **`safe.execute`** checks the setup and the nonce, builds the calldata from the pending SafeTx and its signatures, and prepares the executor's transaction: `to` the Safe, `value` 0, the gas estimate with 0012's 20% buffer, the fees from the core's quote. It runs 0005's fee check (0012's `fc-approval`). It answers `{ send }`, the transaction without its nonce, as `fc-eip1193` prepares a page's send (0012). Or `{ fee_check }`, for the Safe's screen to confirm the fee with an `executor-send` token, as today. Or `{ superseded }`.
- **Main** chooses the nonce under the executor's lock, has `sign.transaction` sign the prepared transaction with nothing else changed, journals it and broadcasts it, then tells the core with `safe.executed { safe, safe_tx_hash, hash }`. The core clears the pending entry, as today.
- **The nonce:** a Safe nonce past the SafeTx's is `superseded`, as today. One below it is refused with `safe_nonce_behind` (deviation `nonce-behind`: today the estimate fails with the node's text).
- **The deployment** goes the same way: `safe.deploy` → `{ send }` to the factory; main signs, journals and broadcasts; `safe.deployed { safe, hash }` after the receipt, and the core marks the record deployed only if the code is at the record's address.

### Messages (EIP-1271)

- **`safe.message_start`** (page): the core checks the setup, builds the SafeMessage and its hash, spends the `safe-message` token or checks the standing rule as 0012 does, collects the vault owners' signatures, and opens a session bound to the page (`PageContext`) with a session ID of 16 random bytes in place of today's UUID.
- **The board's calls** name the session: `safe.message_sign`, `safe.message_state`, `safe.message_cancel`, and `safe.message_complete`, which returns the joined signatures once the threshold is met. Main cancels a session when its document goes, as `attachRequesterLifecycle` does today.
- **Sessions** stay in memory, one per Safe, as today.

### The pending store

- **`safe-pending.json` becomes the core's** (0013's PRF-6(d)), in today's format, with 0001's atomic writes. A file that doesn't parse is renamed aside and reported, as 0012's files are (deviation `pending-atomic`, F-6).
- **One pending SafeTx per Safe,** as today. Its `data` is at most 64 KiB (proposed), so the executor's calldata stays far below what transaction pools accept. The file is at most 8 MiB; a write past it is refused with `store_full`.
- **`display`,** the chrome's text for the board and the payment record, stays as opaque display data. The board shows the core's view of the SafeTx beside it.

### protocol-kit out of main

After SAFE-3, main's `wallet/safe/` modules are thin clients of the core's `safe.*` methods. `@safe-global/protocol-kit` and `@safe-global/safe-deployments` leave `package.json`, and `@safe-global/types-kit` and `@safe-global/safe-modules-deployments` leave the lockfile with them. `viem` stays, since `@x402/evm` needs it. `stub-chain.js` is retired. The Safe e2e suites keep passing.

## Approvals: enforced

0012 lists a Ledger's signatures, a Safe's Ledger owner's included, as advised until this design, and enforces a Safe's vault owners' and executor's from APR-4, through Safe approvals. From LDG-2 a Ledger's are enforced too, and from SAFE-2 a Safe's tokens bind the SafeTx the core built, under 0012's rules: checked when present at first (APR-3's rule), and required once APR-4's rule applies.
- **A Ledger account** is treated as a vault account is. A page's signature needs a token or a standing rule the core checked for that page; a `chrome` call needs a wallet-kind token; a `shell` call carries none. A standing rule skips the browser's prompt, never the device's. For x402, `x402.authorize` (X402-1) takes main's `now_s` for a Ledger account and returns its authorization as typed data, which main rebuilds, compares and sends through `sign.typed_data` with the Ledger key ([x402 from a Ledger account](#x402-from-a-ledger-account)).
- **`safe-send`** binds the SafeTx the core built at `safe.prepare`: the Safe's address, the chain, all ten fields (the nonce included) and its hash, and, for a site's, the page and the handle (0012). `safe.propose` spends it.
- **Owner signatures** need no token each: the spent `safe-send` authorized every local owner's signature over that SafeTx, as today.
- **The executor's transaction** is signed only as `safe.execute` or `safe.deploy` prepared it, or with an `executor-send` token for a fee the check stopped.
- **`safe-message`** binds the method, a digest of the request, the digest the SafeMessage carries and the SafeMessage's hash, the page and the handle. `safe.message_start` spends it.
- **0012's table** loses its "advised until 0016" row, a Ledger's ([Amendments](#amendments)).

## API

| Method | Callers | Params → result |
|---|---|---|
| `sign.transaction`, `sign.message`, `sign.typed_data` | as 0002 and 0012 | `key: { kind: "ledger", index, path?, address? }` is new; the replies are 0002's |
| `ledger.accounts` | chrome, shell | `{ scheme, start, count }` → `{ accounts: [{ path, address }] }` |
| `ledger.add` | chrome, shell | `{ scheme, index, name? }` → `{ path, address }`, and the record once PRF-6(a) |
| `safe.create` | chrome, shell | `{ name, owners: [index], threshold }` → the record, its address computed in the core |
| `safe.status` | chrome, shell | `{ safe }` → `getSafeStatus`'s fields |
| `safe.deploy`, `safe.deployed` | chrome, shell; `deployed` shell only | `{ safe, fee_ack? }` → `{ send }` or `{ fee_check }`; `{ safe, hash }` → `{ deployed }` |
| `safe.prepare` | page, chrome, shell | `{ safe, chain_id, tx: { to, value, data } }` → `{ safe_tx, safe_tx_hash, view }` |
| `safe.propose` | page (a site's), chrome, shell (the wallet's) | `{ safe, safe_tx_hash, authorization, display? }` → the board's state |
| `safe.sign_owner` | chrome, shell | `{ safe, owner? }` → the board's state; without `owner`, the vault owners |
| `safe.execute`, `safe.executed` | chrome, shell; `executed` shell only | `{ safe, fee_ack? }` → `{ send }`, `{ fee_check }` or `{ superseded }`; `{ safe, safe_tx_hash, hash }` → `{}` |
| `safe.pending`, `safe.discard` | chrome, shell | today's `getAllSafeSendStates` and `cancelSafeSend` |
| `safe.message_start` | page | `{ safe, request, display?, authorization }` → `{ session, state }` |
| `safe.message_sign`, `safe.message_state`, `safe.message_cancel`, `safe.message_complete` | chrome | `{ safe, session, owner? }` → today's shapes |

- **Errors:** a device's failure is `device_failed` with `data.ledger`, today's `LEDGER_*` code or one of the six new ones (`UNRESPONSIVE`, `TIMEOUT`, `TYPED_DATA_UNSUPPORTED`, `TOO_LARGE`, `BAD_SIGNATURE`, `EMPTY_MESSAGE`). Main shows `errors.js`'s text for it. A Safe refusal is `invalid_argument` with `data.safe`: `unsupported`, `changed`, `unverified`, `self_call`, `nonce_behind`, or today's `SAFE_*` codes.
- **Deadlines:** a new class, `device`: no overall deadline while a `shell.ledger_apdu` waits for the user, and the lane's own bounds otherwise. Main's hang watchdog skips such a request, as 0012 has it skip one with an open prompt.
- **0012's `{ device }` result** goes for Ledger accounts: `eip1193.request` drives the device itself. A Safe account's request answers `{ safe: { safe_tx_hash } }`, and the page's answer comes from the board's execution, as `awaitSafeExecution` gives it today (`dapp-tx.js:826`).

## Vectors

From the pinned reference (AGENTS rule 5): the browser at an `integration/rust-core` commit, checked out fresh and installed with `npm ci --ignore-scripts` from its own lockfile, as 0015 has it. Each generator asserts the installed versions from their `package.json` (hw-app-eth 7.11.1, hw-transport 6.36.0, hw-transport-node-hid 6.33.5, protocol-kit 8.0.11, safe-deployments 1.37.66, ethers 6.17.0) and records them in `meta`, so the reference checkout's older install fails rather than generating.

- **`vectors/ledger.json`,** recorded APDU exchanges, by `vectors/generator/ledger.js`: the browser's own `wallet/ledger/signer.js`, `transport.js` and `errors.js`, Electron stubbed, with `TransportNodeHid.open` returning a recording transport over a scripted device. The transport is a subclass of hw-transport's `Transport`, so `send`'s framing and status checks are the real ones. The scripted device:
  - answers `B0 01` with the case's name and version, and `E0 02` with the key of `keys.json`'s test account at that path;
  - signs a transaction or a message the way the app does, over the hash of the pieces it was sent; signs `E0 0C 00 01` over the case's EIP-712 hash (it can't hash fields; LDG-3's device recordings check that a real one gets the same hash); and `E0 0C 00 00` over the two hashes it was sent;
  - answers a case's scripted status at a given APDU, or throws `DisconnectedDeviceDuringOperation` there.

  Each case records the request, the record, every exchange (the APDU and the answer, hex) and the result: the raw transaction, the signature, or the code and text. The cases: types 0 and 2 at chain IDs 1, 100, 137, 2^32 − 1, 2^32, 2^53 and 2^64, both parities; every chunk-size branch of `safeChunkTransaction`; messages of 1, at the first APDU's edge for both path lengths and one past it, 150 more and one past that; 0002's EIP-712 cases that fit, the Safe, x402 and Permit2 payloads among them; the three [x402 forms](#x402-from-a-ledger-account) as `@x402/evm` 2.29.0 builds them under a fixed nonce and clock (the generator asserts the version); values of each type at their edges; F-2's lengths (encodings of 255, 256, 257, 510, 511, 512 and 513 bytes), arrays of 255 and 256 entries; ASCII type and field names of 254, 255 and 256 characters; names holding a 2-byte character (`é`) and a 4-byte one (`😀`) whose UTF-8 lengths are 254, 255 and 256 bytes, for a field and for a custom type, where the reference's length byte counts UTF-16 units and the core refuses (deviation `name-ascii`); each status of `errors.js`'s table at each step; the `6D00` fallback; a disconnect at each step; F-5's empty message; and discovery for both schemes. Cases the core answers differently are marked `deviation`, with the reference's outcome beside the core's.
- **`vectors/ledger-grammar.json`:** [the grammar](#the-apdu-grammar) as data, written by the same generator, which checks every recorded APDU against its row (deviations aside) and writes each row's honest and forbidden APDUs. **The forbidden ones** include, for each typed-data case, every definition and value APDU with one byte of its data changed, header, order and counts kept, each byte in turn; another schema and message of the same shape (each type, field name and value replaced, the same counts); the reference's definitions for the `name-ascii` cases (a length byte in UTF-16 units); and for a SafeTx and a SafeMessage, each of the ten fields, the Safe's address, the chain and the digest changed in turn. For each x402 form, the core's returned authorization with one thing changed and the APDUs made to match it, so that only main's rebuild can catch it: each domain member, the primary type, each type's fields (renamed, retyped, reordered, added, dropped), each message value, the Permit2 and proxy addresses, each time field by one second, and the other form's schema for the same accept entry.
- **`vectors/ledger-devices.json`:** LDG-3's recordings from real devices, with a test seed on the device and its model and app version in each case: replayed by the core, never generated in CI. They include the core's APDUs for ASCII names of 254 and 255 characters, and, to record what a device does with F-2's fault, the reference's APDUs for a field named with `é` and one with `😀` at 254 and 255 UTF-8 bytes, which the core never sends.
- **`vectors/safe.json`,** by `vectors/generator/safe.js`: the browser's own `wallet/safe/safe-executor.js`, `safe-service.js`, `safe-transactions.js`, `safe-messages.js` and `signature-collection.js`, with protocol-kit and safe-deployments from the lockfile, the provider replaced by the browser's own `stub-chain.js`, `transaction-service` stubbed to capture the executor's transaction, and `keys.json`'s accounts as owners. The cases: addresses for owners in each order and salts of 0, 1, 2^128 − 1 and drawn ones; deployment calldata; SafeTx typed data and hashes for values of 0 and 2^256 − 1, empty and long data, nonces of 0 and large; `execTransaction` calldata with 1, 2 and 3 signatures given in each order; SafeMessages for `personal_sign` (hex, UTF-8) and typed data, with their joined signatures; and the reference's errors (the address mismatch, a non-canonical factory). The pinned constants are checked against safe-deployments' files and `stub-chain.js`'s recorded code.

`generate.js check` passes, and `check.test.js`'s damaged copies fail it.

## Deviations

| Id | Today | With the core |
|---|---|---|
| `signature-check` | a device's signature is used as it comes (F-1) | recovered against the account and the confirmed digest, `s` low; otherwise `LEDGER_BAD_SIGNATURE` and nothing returned |
| `field-pieces` | some values lose their last bytes (F-2) | each value in pieces of 255, all of it |
| `device-bounds` | a wrong count, or a failure mid-way (F-2) | refused before the first APDU: arrays and sizes over 255, names over 255 bytes, values over 65,535 bytes, more than 2,048 APDUs |
| `blind-typed-data` | the hash-only fallback after `6D00` | refused, `LEDGER_TYPED_DATA_UNSUPPORTED`, if Q23 is yes |
| `app-check` | `B0 01` for typed data only, and no name check | `B0 01` for every signature, the name `Ethereum` required |
| `key-check` | the address text is trusted | it must be the address the returned key derives |
| `empty-message` | a TypeError, `LEDGER_UNKNOWN` (F-5) | `LEDGER_EMPTY_MESSAGE` before any APDU |
| `path-strict` | `splitPath` skips what it can't read | only the two schemes' forms |
| `address-from-device` | the chrome's address (F-3) | the device's, read by the core |
| `device-deadlines` | none | 15 s and 5 minutes |
| `cancel` | none in the browser | the parent's cancel closes the device |
| `discovery-busy` | a poll waits behind a signature | `LEDGER_BUSY` at once |
| `safe-reads` | the first endpoint that answers | the chain machine |
| `creation-code` | read from the factory (F-4) | pinned |
| `deployed-mark` | one endpoint's code, for good; the deployed address not compared (F-4) | the record's own address, after a prepared deployment or on a verified read |
| `safe-setup` | the record's owners and threshold count | the Safe's setup must be the record's (Q24) |
| `self-call` | allowed | refused, if question 4 is yes |
| `safe-tx-binding` | `safe-send` binds `to`, `value`, `data` | the whole SafeTx and its hash |
| `owner-signatures` | any signature protocol-kit joins | 65 bytes, `v` 27 or 28, an owner's, once each |
| `nonce-behind` | the estimate fails with the node's text | `safe_nonce_behind` |
| `pending-atomic` | written in place; unreadable loads as `{}` (F-6) | atomic; unreadable renamed aside |
| `name-ascii` | a non-ASCII type or field name is announced with its length in UTF-16 units (F-2) | refused before any APDU by 0002's identifier rule; a name is ASCII, and its prefix is its byte count |
| `safe-unverified` | the setup isn't read, and the nonce is one endpoint's | every read a signing or an execution rests on verified (a proof, or a quorum of m ≥ 2), else `safe_unverified` with nothing signed |

Each case has a vector or a test. A vector records what the reference does; the core's expected answer comes from this table.

## Steps

One PR per step: the core's against `main`, the browser's against `integration/rust-core`.

| Step | What | Needs | The tests that prove it |
|---|---|---|---|
| LDG-1 | `fc-ledger` (logic): paths, APDU builders and readers, the per-operation machines (sans-I/O), status mapping, `v`, the checks and the bounds; `vectors/ledger.json` and `ledger-grammar.json` | — | Every `ledger.json` case: the core's APDUs byte for byte and its result from the recorded answers, deviations as their rows say. The grammar both ways: every recorded APDU matches its row, and every row is reached by a case. `v` at each chain ID of the vectors, both parities. Answers: each status at each step; an answer a byte short or long; an address whose text isn't its key's; a signature that recovers to another key, over another digest, or with a high `s`. The bounds at 255 and 256, 65,535 and 65,536, 2,048 and 2,049. **Names:** ASCII names of 255 characters sent with the length byte 255, and of 256 refused `LEDGER_TOO_LARGE`; every `name-ascii` case refused before any APDU. No `unsafe`, no panic. The iOS and Android builds pass |
| LDG-2 | `freedom-cored`: the `ledger` key in `sign.*`, `ledger.accounts`, `ledger.add`, `shell.ledger_apdu`, the device lane, the `device` deadline class, cancel; `x402.authorize`'s Ledger form once X402-1 exists | LDG-1; APR-3; X402-1 for the x402 form | Over the wire, against a scripted main with a scripted device: every vector through `sign.*`. **Authorization** as APR-3 and APR-4 test a vault key. **The lane:** two operations in turn; a ninth waiting refused `LEDGER_BUSY`; discovery `LEDGER_BUSY` while a signature waits. **Cancel** before the first APDU, between two, and during the user's wait: `cancelled`, the pending `shell.ledger_apdu` cancelled, nothing returned, the token burnt. **Unplugged** at each APDU: `LEDGER_DISCONNECTED`. **Deadlines:** no answer in 15 s, `LEDGER_UNRESPONSIVE`; the user's answer at 4:59.999 signs and at 5:00 is `LEDGER_TIMEOUT`, under a fixed clock. **Late and stale answers:** an answer after a cancel never returned; a device that answers with the previous operation's signature refused `LEDGER_BAD_SIGNATURE`. **Device and app:** another address, `LEDGER_WRONG_DEVICE`; another app's name, `LEDGER_ETH_APP_NOT_OPEN`. **Q23:** `6D00` on the first `E0 1A` refused, or, if Q23 is no, the one hash-only APDU. `ledger.add` returns the device's address, never a caller's. A core restart mid-operation: the parent fails. **x402** (with X402-1): a `now_s` 30 s from the core's clock accepted and 31 s refused; each form's typed data as the reconstruction table has it, under a fixed nonce; `sign.typed_data` with the Ledger key refused for any authorization but the one returned; a device refusal or failure gives the cap's charge back |
| LDG-3 | Browser: main's relay (`shell.ledger_apdu` with the grammar), the Ledger backend, discovery and adding through the core; Cancel in the send screen, Reject while the device waits; hw-app-eth removed. Then `vectors/ledger-devices.json` into the core | LDG-2's release pinned | **The relay's refusals,** each before a byte reaches the device and logged with its rule: a parent main didn't send; an instruction outside its row; a second `E0 0C`; another path; one byte changed in an `E0 04` or `E0 08` piece; `E0 02 01 00` outside `ledger.add`; `E0 0C 00 00` without the `6D00`, or with Q23 yes; an APDU after its parent ended; and `ledger-grammar.json`'s lists. **Main's typed-data binding:** for every typed-data case of `ledger.json`, main's own stream equals the vector's APDUs byte for byte; a scripted core that changes one byte of the data of any definition or value APDU, each byte in turn with header, order and counts kept, is refused `payload` before the device; so is one that sends another schema and message of the same shape, and one that sends the reference's `name-ascii` definitions; typed data whose ethers hash isn't `expected_hash` is refused before the first APDU. **x402 from a Ledger account,** for each of the three forms: main's rebuild equals `@x402/evm`'s payload under a fixed nonce and clock; a scripted core that returns the authorization with any one of the grammar file's x402 changes, with APDUs consistent with it, is refused before the first APDU, and nothing is sent to the device; a core that answers with the other form's schema is refused the same way. The device opened per operation and closed at its end; a cancel closes it mid-read. `signer.test.js`'s and `connect-ledger.test.js`'s cases against the core; `send-ledger-confirm.spec.js` and `dapp-tx-ledger-confirm.spec.js` pass. `npm ls` shows no hw-app-eth, `evm-tools` or `domain-service`. **Device recordings,** by hand with a test seed, on a Nano S Plus, a Nano X and a Stax or Flex: a type 0 and a type 2 transaction, a contract call with blind signing off and on, a message, typed data field by field (the Mail example, a SafeTx, an EIP-3009 authorization), a rejection, an unplug mid-signature, and a cancel with a new operation while the old prompt shows; on a Nano S, the `6D00`. The core replays each in CI, and each recorded signature recovers to the test account over the core's own digest. The time per APDU is measured on each model, and the 2,048 bound replaced if needed |
| SAFE-1 | `fc-safe` (logic): the pinned constants, the address, the deployment, the SafeTx and SafeMessage and their hashes, the signature checks, the joined signatures, `execTransaction`'s calldata; `vectors/safe.json` | — | Every `safe.json` case byte for byte. The constants match safe-deployments 1.37.66 and the recorded proxy code. The address of every case with no chain read (the crate does no I/O). A SafeTx with any operation, gas field, gas token or refund receiver other than today's refused. The iOS and Android builds pass |
| SAFE-2 | `freedom-cored`: the `safe.*` methods, the chain reads, the setup check, the executor's prepared send, `safe-pending.json` | SAFE-1; LDG-2 for Ledger owners; APR-3; 0013's PRF-5 (`accounts.*`, `safe_pending.*`) | Over the wire, with a scripted chain. `safe.create` reads nothing. **The token:** `safe-send` refused for a SafeTx with each of its ten fields and its address changed in turn. **Owners:** the vault owners signed at `safe.propose`; a Ledger owner through the lane; a signature from a non-owner, over another hash, or with `v` 0 or 1, refused; a second from one owner dropped. **The setup:** each of a changed singleton, owner set, threshold, guard, handler and an added module refused `safe_changed` with nothing signed, before an owner's signature and before execution. **Unverified:** with only an unverified source (Direct alone, and a quorum answered by one endpoint), each of `safe.prepare`, `safe.propose`, `safe.sign_owner`, `safe.execute` and `safe.message_start` refused `safe_unverified`, with nothing signed and no `{ send }`; the same with every read verified but one, each of the eight answered unverified in turn while it reports the record's value; and with all eight verified from mixed sources (Colibri and a quorum), the step goes on. A self-call refused if question 4 is yes. **The nonce:** past the SafeTx's, `superseded`; below it, `safe_nonce_behind`. **The executor:** `sign.transaction` refuses the prepared send with any field changed but the nonce; a fee the check stops needs an `executor-send` token. **Deployed:** marked only when the code is at the record's address after `safe.deployed`, or on a verified read; an unverified "deployed" not written. **Messages:** a session refused for another page; complete only at the threshold. **The store:** atomic writes; an unreadable file renamed aside; an entry whose hash doesn't recompute set aside and never signed; 8 MiB and a byte past it; a restart reloads. No Safe request leaves except through the chain machine |
| SAFE-3 | Browser: `wallet/safe/` through the core; main's Safe binding and its in-memory approval records, after which the relay admits the `safe.sign_owner` row (LDG-3's relay refuses it until then); protocol-kit and safe-deployments removed | SAFE-2's release pinned; LDG-3; PRF-6(a); PRF-6(d) or this step does it | `safe-executor.test.js`'s, `safe-service.test.js`'s, `safe-transactions.test.js`'s and `safe-messages.test.js`'s cases against the core. `safe-accounts.spec.js`, `safe-dapp.spec.js`, `safe-phone.spec.js` and `safe-send-chain.spec.js` pass. `safe-fork.test.js` against the core on a Gnosis fork. `npm ls` shows no protocol-kit. **Main's Safe binding,** for a Ledger owner: a `safe_tx_hash` from the core that isn't main's own hash of the shown fields refused at the approval, with no record kept; at the owner's turn, a scripted core that changes any of the ten fields, the Safe's address or the chain in the pending entry, or one byte of any definition or value APDU, refused before the device; a SafeMessage whose digest or address isn't main's own refused before the device. **Approval records,** with a hook at each stage: `safe.propose` failing after the record is made drops it; a discard drops it before `safe.discard` is sent, and a `safe.discard` that fails, or a crash just after the drop, leaves no record, so the next Ledger turn needs a new approval; `superseded` and `safe.executed` drop it; a new approval for the Safe replaces the old record. **Restarts:** approve, restart main, and the Ledger owner's turn asks for a new approval before the device; approve, crash at each stage, restart, the same. **Downgrade:** approve SafeTx H in this build, run the reference build (which has no records) and discard H there, return to this build, and have a scripted core present H's fields again: main asks for a new approval and sends nothing to the device. No file is written for the records (an `fs` spy). **Rollback:** the reference's `pending-store.js` reads the core's file and sees the same entries |

- **Rollback:** until the browser pins LDG-2's or SAFE-2's release, each browser step reverts on its own. The files' formats don't change, so an older build reads them at every step.
- **Order:** wave 6 of the roadmap. LDG and SAFE are independent but for SAFE-2's Ledger owners.

## Amendments

Once decided:
- **0002:** the non-goal "Ledger, phone and Safe accounts" reads "Phone accounts (0012's phone jobs)". The key reference table gains `ledger`, for the three EVM signing methods. *Execution* adds: a Ledger key runs on the device lane, not in one turn of the loop.
- **0012:** *What the core enforces* has a Ledger's signatures, a Safe's Ledger owner's included, enforced from LDG-2; a Safe's vault owners' and executor's stay enforced, as from APR-4. The token table: `safe-send` binds the core's SafeTx and its hash; `safe-message` also binds the SafeMessage's digest and hash. `eip1193.request` drives a Ledger itself, and answers a Safe account's request with `{ safe }`. X402-1's `x402.authorize` takes main's `now_s` for a Ledger account and returns its authorization as typed data rather than signing it.
- **0013:** `safe-pending.json`'s codec lives in `fc-safe`, which `fc-wallet-state` uses. PRF-6(d) and SAFE-3 are one move, whichever lands first. Main's SafeTx approval records are set-A state by 0013's test (they decide what a Ledger may sign), held by main as its check on the core, in memory only ([Approval records](#approval-records)); no store is added to either set.
- **0005:** "provider-manager's Safe reads bypass the router" is closed by SAFE-2.
- **0011:** "A Ledger signs in main" reads "A Ledger signs in the core, through main's relay".
- **0001:** `shell.ledger_apdu` joins the core-to-main requests; the `device` deadline class.

## Options weighed

- **HID in the core** (hidapi): a C dependency and per-OS device code in the core, and a device grant for D7. In Stage 1 it protects against nothing the core's checks don't, and mobile needs another transport anyway.
- **A Ledger service process:** the parser surface is a few fixed-size answers; a process would isolate very little.
- **Main relaying HID reports, not APDUs:** main couldn't check anything, and the framing would move into the core for no gain.
- **hw-app-eth kept in main, with the core checking the result:** main would still choose the bytes, and F-2 would stay.
- **Approval records on disk:** they would survive a restart, but an older build never sees them, so it can't remove one when it discards the SafeTx, and a removal that fails on disk leaves one behind. Making that safe needs set A's whole contract plus a marker every older build honors. In memory, a record never outlives its process, for one more approval after a restart.
- **Refusing Permit2 on a Ledger:** simpler, but Ledger users pay with Permit2 today, and the rebuild is one fixed row of a table.
- **The hash-only fallback kept** (Q23 no): Nano S users keep typed data, and see only hashes for it.
- **protocol-kit kept in main, with the core checking its SafeTx:** the address, the deployment and the reads would stay protocol-kit's, which is where F-4 is.
- **Safes made elsewhere, or other versions and chains:** each needs its own deployments, its own setup rules and a way to show them. Q24 keeps them out until a design adds them.

## Open questions

1. **Q23, Ledger typed data:** Should Freedom refuse to sign typed data on a Ledger that can't show its fields (the Nano S shows only two hashes), so you always see what you sign, even though a Nano S then can't sign permits, x402 payments or Safe transactions in Freedom? *Proposed: yes.*
2. **Q24, Safe:** Should Freedom support only the Safes it creates today (Safe 1.4.1 on Gnosis), and refuse to sign for one whose owners, threshold or setup were changed elsewhere? *Proposed: yes.*
3. **A new Ledger account:** When you add a Ledger account, should the Ledger show its address for you to confirm there? *Proposed: yes.*
4. **Safe self-changes:** Should Freedom refuse a site's Safe transaction that would change the Safe itself (its owners, threshold, modules, guard or fallback handler), which Freedom can neither show nor follow? *Proposed: yes.*
