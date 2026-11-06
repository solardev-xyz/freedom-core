# 0012: Approvals and grants in the core

**Status:** proposed. Roadmap items 2.2 (approval tokens, grants, auto-approve and transaction building in the core), 2.4 (x402) and 2.7 (phone signing). Builds on [0001](0001-freedom-cored.md) (the process, the caller context, the threat model), [0002](0002-signing.md) (signing, and the signed view of #88), [0005](0005-chain-data.md) (the fee reference and the one-nonce rule) and [0011](0011-page-requests.md) (the attested requester, `PageContext`, request handles, the page token kinds and the approvals document). It amends 0002's non-goal on approval and policy ([Amendments](#amendments)). Nothing here is built yet. The user decides the [open questions](#open-questions).

**The references:**
- **freedom-browser** at `f19705ad` (`integration/rust-core`), in `src/main/`:
  - `wallet/signing-confirmation.js` (the tokens); `wallet/wallet-ipc.js` (`authorizeSigning`, the standing rules, `handleSendTransaction`, `wallet:confirm-signing`); `wallet/auto-approve-pause.js` (D12); `wallet/fee-check.js` (0005's check A); `wallet/agent-tab-custody.js`;
  - the grant stores `wallet/dapp-permissions.js`, `swarm/swarm-permissions.js`, `radicle/radicle-permissions.js` and `x402/permissions.js`;
  - `wallet/transaction-service.js`, `wallet/nonce-reservations.js`, `wallet/intent-store.js`;
  - `x402/intercept.js`, `x402/sign-flow.js`, `x402/payment-utils.js`, `x402/ipc.js`, `x402/client.js`;
  - `wallet/remote/bridge.js` and `wallet/remote/signer.js` (phone signing).
- **Browser PR #1016** (SEC-1, in review, head `c4f22e10`): the eleventh token kind, `x402-payment`.
- **Browser PR #941** (R-6, approved against main, head `afae7650`, not on integration until SEC-3f merges it): `src/main/radicle/auto-write-limiter.js`.
- **`@x402/evm` 2.28.0**, the reference checkout's: `dist/cjs/exact/client/index.js`.
- **freedom-core:** `CallerKind::Page` and `PageContext` (`crates/fc-protocol/src/message.rs`), `Callers::allow` (`methods.rs`), and the vault's clock (`crates/freedom-cored/src/clock.rs`, #80).

## Summary

- **Today** main holds every approval rule in JS: ten token kinds with a two-minute life, the sites' standing rules, the D12 pause, x402's caps, and four grant files it writes itself. The core signs whatever main asks, as 0002 planned ("Policy moves with the Chromium work").
- **The proposal ([Q3](#open-questions)):** move the policy into the core now, in Stage 1, in steps. Main keeps the prompts (0011's approvals document), the nonces and the intent journal, and stays trusted.
- **Two new logic crates,** built for desktop and mobile alike: `fc-approval` (tokens, grants, standing rules, limits, x402 caps, phone jobs) and `fc-eip1193` (the Ethereum dispatcher, ported from 0011's main JS). Time comes in as a parameter, randomness as an injected RNG.
- **Tokens:** the eleven kinds, each bound to the request in the form the core will sign it. A page kind also binds the attested page (`PageContext`) and 0011's handle.
- **Grants and rules:** today's, ported with vectors: the account check, the 32-byte and warned-typed-data exceptions, the transaction rules, D12's pause, the fee check, Radicle's R-6 limit and x402's caps.
- **Enforced, not advised ([Q8](#open-questions)):** from APR-4 the core refuses a page's signature unless it checked a token or a standing rule for that page itself. Where the core doesn't make the signature (Ledger, Safe, Radicle, Swarm uploads), it advises. [What the core enforces](#what-the-core-enforces) lists each.
- **The files:** the core takes over the four permission files where they are, in today's format, with atomic writes. Older builds still read them ([Q10](#open-questions)), and a new limit is stored so that an older build reads it as no rule. 0013 decides any later move.
- **Transaction building stays in main** in Stage 1. The nonce and the intent journal move with 0013's stores.
- **`fc-eip1193`** runs a page's Ethereum request in the core, and asks main for each prompt with a core-to-main request, `approval.request`.
- **x402:** the core checks the cap or the `x402-payment` token, builds the authorization itself and signs it. [Q11](#open-questions) asks whether today's caps stay.
- **Phone jobs:** the core makes each job from a checked authorization, binds what it signs, and checks the answer, a payment's recipient and amount included.
- **Migration:** APR-1 to APR-6, X402-1 and PHN-1 in the core; APB-1 to APB-4, X402-2 and PHN-2 in the browser.

## Goals and non-goals

**Goals**
- **One copy of the policy,** in logic crates that desktop, mobile and a later Chromium build share.
- **No signature for a page without a check the core made:** a token or a standing rule, for that page and that request.
- **Parity:** the same decisions as today's JS, pinned by vectors from it. Every difference is listed in [Deviations](#deviations).
- **The same files,** readable by older builds.
- **One step at a time,** each revertible on its own until the enforcing release.

**Non-goals**
- **A compromised main.** Main stays trusted in Stage 1 (0001): it fills the caller context, shows the prompts and relays the decisions. A compromised main can mint any token.
- **The approval surface.** 0011's approvals document shows the prompts. The core tells main what to show.
- **Nonces and the intent journal** (`wallet-intents.jsonl`). They stay in main until 0013 moves the stores ([Transaction building](#transaction-building)).
- **Ledger and Safe in the core:** 0016. Until then main checks their tokens through the core, which advises.
- **`swarm-feeds.json` and `swarm-manifest-grants.json`:** 0015 takes the Swarm stores. Until then the manifest store writes its projection through the core.
- **WebRTC for the phone.** The openlv session stays in the chrome renderer.

## Today

### Tokens
`signing-confirmation.js` (security audit O-7):
- **Ten kinds** (lines 74–85): `wallet-send`, `dapp-send`, `sign-message`, `sign-typed-data`, `safe-send`, `safe-message`, `intent-resend`, `intent-replace`, `intent-close`, `executor-send`. PR #1016 adds `x402-payment`.
- **Minting:** the chrome calls `wallet:confirm-signing` with the request as shown (`wallet-ipc.js:621–643`). Main computes `bindingFor` (`signing-confirmation.js:229–311`), digests it as SHA-256 over sorted-key JSON (`stableStringify`, 184–199), and returns 32 random bytes in hex (349).
- **Life:** two minutes of `Date.now()` (68, 93). At most 32 are outstanding, and the oldest is dropped to make room (72, 345–348).
- **Spending:** `consumeConfirmation` burns a token at its first presentation, matched or not (367–368). It refuses an expired token, another kind and another request.
- **What a token doesn't bind:** the tab or the document. A `dapp-send` binds the site, which the chrome names. 0011 adds the handle and the attested key.

### Standing rules
`authorizeSigning` (`wallet-ipc.js:307–322`) signs with a token, or with `{ autoApprove: key, webContentsId }` when `requesterBelongsTo` (239–264) finds the guest in the sending window on that key and main's own reading of the rule covers the request:
- **The account:** a rule answers only for the account the grant exposes (`permissionFor`, 124–128).
- **Messages and typed data:** the grant's `autoApprove.signing` flag (214–219). Never a `personal_sign` of exactly 32 bytes (#89, 174–176), nor typed data whose core view carries a warning (#88, 747–756).
- **Transactions:** a rule `{ to, selector, chainId }` (`dapp-permissions.js:263–279`). A plain transfer has no selector and is never covered (`selectorOf`, `wallet-ipc.js:113–117`). **The amount isn't part of the rule:** a rule made from a send of 0.01 ETH covers the same call with any `value`.
- **"Always allow" for a transaction** is added only from a confirmed `dapp-send` that carried `rememberAutoApprove` (409–421). No IPC adds one (`dapp-permissions.js:392–394`). The flag names its own key, which the chrome chooses: the token's site isn't compared with it.
- **The fee check (0005, A):** a confirmed send is judged when its token is minted (`wallet-ipc.js:623–631`), an auto-approved one as it is signed (377–380). Above 3·R, with no reference, or with one endpoint's reference, it isn't auto-approved (`fee-check.js`). A phone account picks its own fees and isn't judged. A send that names no fee of its own is refused (385).
- **D12, the pause** (`auto-approve-pause.js`): a site's dApp sends take turns until each one's payment is committed. A silent send doesn't wait for a turn, and stops while the site has a payment in Payments waiting (`wallet-ipc.js:386–401`). Records that can't be read pause it (149–151). At most 8 sends wait (38), each for at most 3 minutes (`nonce-reservations.js:25`).
- **Agent custody:** no standing rule answers for a tab the agent holds (`agent-tab-custody.js`).
- **Swarm and Radicle:** flags per site. Swarm has `publish`, `feeds`, `signing` and `messaging`, and the messaging grant. Radicle has `node` and `signing`, and its signing grant. Main reads them for the chrome's `origin` today; 0011 replaces the origin with the attested key.
- **R-6** (PR #941): a Radicle site's COB writes each need a prompt, or its `autoApprove.signing` rule, which `auto-write-limiter.js` limits per site: a burst of 5, then one more per 30 s, at most 50 in any 24 hours. Counted in memory, and forgotten on `radicle_disconnect`.

### x402
- **Caps** (`x402/permissions.js`): keyed `(origin, chainId, asset)`, stored as `origin → "chainId:asset" → { capAmount, spentAmount, createdAt, expiresAt }`, amounts as decimal strings, times as wall-clock seconds (83–89, 115–120). One window per grant, no renewal.
- **The key is the paid URL's origin** (`originKeyForUrl(details.url)`, `intercept.js:867`), not the page's. A paid resource embedded on many sites spends one cap.
- **Auto-pay:** the first `accepts[]` entry, in the seller's order, that an active cap covers is signed with no token (`findCoveringPermission` in `payment-utils.js`; `intercept.js:846–960`). Never for a tab in Agent custody, nor for a request main can't attribute to a live tab (`isUserPageId`, 868).
- **Charged at injection, not at signing:** the cap is charged when the signed header is attached (`consumeOrWithhold`, 1150–1182). Two auto-pays signed together can both pass the coverage check, and the second is withheld at injection. Its signed authorization exists all the same.
- **Manual pay:** `x402:approve` signs on a bare chrome call (`x402/ipc.js:261–340`). SEC-1 (#1016) adds the `x402-payment` token. A cap granted with a payment is written after the payment is signed (`sign-flow.js:198`).
- **Widening a cap:** `x402:update-permission` raises a cap's amount or its window on a bare chrome call (`x402/ipc.js:450–457`).
- **The authorization** is `@x402/evm`'s. It is EIP-3009 `TransferWithAuthorization` by default, Permit2 when the seller's `extra.assetTransferMethod` says so (`exact/client/index.js:931`). Its nonce is 32 random bytes (168–170). It reads the wall clock: `validBefore` is now plus the seller's `maxTimeoutSeconds`, and `validAfter` is `0` (V2, 177–197) or now − 600 (V1, 1001–1011). The EIP-712 domain's `name` and `version` are the seller's `extra`.

### The files
All four live in the profile's `userData`, each one JSON object keyed by permission key, written with `JSON.stringify(…, null, 2)`:

| File | Per key | How it is written |
|---|---|---|
| `dapp-permissions.json` | `{ origin, connectedAt, lastUsed, walletIndex, chainId, autoApprove: { signing, transactions: [{ to, selector, chainId }] } }` | `writeFileSync` in place (`dapp-permissions.js:62`) |
| `swarm-permissions.json` | `{ origin, connectedAt, lastUsed, autoApprove: { publish, feeds, signing, messaging }, messaging?: { grantedAt } }` | a temp file and a rename, no fsync (`swarm-permissions.js:54–64`) |
| `radicle-permissions.json` | `{ origin, connectedAt, lastUsed, signing, autoApprove: { node, signing } }` | `writeFileSync` in place (`radicle-permissions.js:50`); `lastUsed` at most once a minute (117–121) |
| `x402-permissions.json` | `{ "<chainId>:<asset>": { capAmount, spentAmount, createdAt, expiresAt } }` | `writeFileSync` in place (`x402/permissions.js:77`); expired caps dropped on load (47–58) |

- **A file that doesn't parse** loads as `{}` in the dApp, Radicle and x402 stores (`dapp-permissions.js:48–51`), and the next write replaces it: every grant is lost. A torn in-place write does that.
- **Times** are `Date.now()` milliseconds, x402's seconds. **Key order** is the order in which JS inserted the keys.

### Transaction building
- **Main builds every transaction** (`transaction-service.js`): gas from `eth_estimateGas` plus 20% (51), fees from the core's quote (`resolveFeeParams`, 223–248), the type from the fee fields (`buildTransaction`, 136–176).
- **The nonce** is chosen under the account's lock: the larger of `pending` and the highest held nonce + 1 (`nonce-reservations.js:176–183`). The signed bytes are committed to `wallet-intents.jsonl` before they go anywhere (`intent-store.js`; `commitNewIntent`, `transaction-service.js:510–576`). 0005's rule holds: an intent keeps its nonce for good.

### Phone signing
- **The job** goes to the focused window's chrome (`bridge.js:93`), whose openlv session tunnels it to the phone. Main accepts the answer only from that webContents (68), marks a payment possibly sent before it leaves (`remote-signer:request-sent`, 196), and gives up after 5 minutes (50).
- **The answer:** a signature must recover to the account (`verifiedSignature` in `signer.js`). Typed data is checked with ethers' `verifyTypedData` over the dApp's own payload, not over the hash the core showed.
- **A payment** is signed and broadcast by the phone, which picks its own nonce and fees. Main checks only that the reported transaction's `from` is the account, once the transaction is visible (`verifyDeviceBroadcastFrom`, `transaction-service.js:185–201`). So a chrome that relays the job can have the phone send another transaction from the same account, to another recipient or for another amount, and report its hash as the confirmed one. Only the phone's own screen shows the difference.
- **A lost answer** to a payment that may have gone is `REMOTE_OUTCOME_UNKNOWN`, never a failure. Only 4001, 4100 and 4200 mean "not run" (65).

## Threat model

Stage 1 trusts main (0001). To 0011's attackers (a compromised chrome renderer or sub-frame) 0012 adds bugs in main, and whoever reaches a signature through one:

| The attacker wants to | Today | After 0011 (PRQ-9, APS-3) | After APR-4, X402-2, PHN-2 |
|---|---|---|---|
| Sign for a page through a main path that skips the check (the O-7 class; SEC-1's `x402:approve`) | Yes: the core signs what main asks | Yes | No: the core refuses a page's signature without a token or rule it checked |
| Spend one site's or one document's token on another's request | Not another site's (a `dapp-send` binds it); another document's, yes | No: the handle and the attested key | No: checked in the core too, with the frame and the navigation |
| Use a site's rule for another account | No (`permissionFor`) | No | No, in the core |
| Widen an x402 cap without the user (chrome) | Yes: `x402:update-permission` | Yes | No: widening needs a decision |
| Hold a signed x402 authorization beyond the cap | Yes: signed, then withheld at injection | Yes | No: the cap is charged when the core signs |
| Have the phone send another transaction of the account, reported as the confirmed one (chrome) | Yes, unless the user reads the phone | Yes | No, once the transaction is visible: the core checks its fields |
| Lose every grant through a torn write | Yes (three files) | Yes | No: atomic writes |
| Act as main | Everything | Everything | Everything: main fills the caller context |

### What moving the policy protects against
- **Main's bugs, not main.** A signing path that forgets its check (SEC-1 found one) fails in the core instead of signing. The check sits beside the key, where every path must pass.
- **Drift.** Desktop, mobile and a later Chromium build run one copy of the rules, pinned by one set of vectors.
- **Torn files.** The core writes with 0001's atomic writes.

### What stays open
- **A compromised main** can mint any token, name any page, and call as `shell`.
- **Enforcement is per caller.** The core can't see where a request came from, so it holds main to what main declares: a request declared as `page` needs a checked authorization, and one declared as `shell` doesn't. Main's dispatcher is the one sender of page requests, and a browser test pins that it never declares one as `shell` (APB-1).
- **Main's inputs.** Custody, the D12 pause, whether a document is live, and which window hosts a tab are main's state. The core takes each as main sends it, and reads a missing one as "no standing rule".
- **The chrome's wallet kinds** until APS-3 (0011): the chrome still asks for them.
- **0011's scripted pages** ([its open question 4](0011-page-requests.md#open-questions)): a chrome that scripts a page makes a genuine request, which a standing rule can answer.
- **Advised, not enforced:** the effects the core doesn't sign ([What the core enforces](#what-the-core-enforces)).
- **Token eviction:** at most 32 tokens, the oldest dropped. A chrome that mints 32 drops a page's token too. That stops a payment, and signs nothing.

## Policy in the core (Q3)

0002 left approval and policy to main until Chromium ("Policy moves with the Chromium work"). **Proposed: move it now.**
- **0011 brings the decisions into main first,** in JS (PRQ-1 to PRQ-9). That JS becomes the reference, and the core ports it with vectors, as 0002 ported ethers.
- **The core already holds each rule's inputs:** the key and the signature, the typed-data view and its warnings (#88), the fee reference (0005), and naming (0003, 0004) for a name's revalidation.
- **Mobile** links the same crates, and gets the policy with them.
- **The costs:** about fifteen new methods, a grant store the core writes, more vectors, and a time in which main and the core both run rules while the browser moves store by store.

**The alternative, as 0002 planned:** the rules stay in main's JS until the Chromium browser process exists. They are then written twice, and mobile has none until then.

## Enforced or advised (Q8)

**Proposed: enforced.** From APR-4, a signature the core makes for a page needs an authorization the core itself checked, for that `PageContext`:
- **a token** of a page kind, minted for that page and that request, with 0011's handle; or
- **a standing rule,** which the core evaluates against its own grants for `PageContext.origin`.

Anything else is refused with `not_authorized` before a key is touched. A `chrome` caller needs a token of a wallet kind for every signature. Main's own signatures, under `shell`, carry none: no user decision stands behind them (a Safe's executor within the fee check, an x402 auto-pay until X402-2), and main is trusted.

**Advised instead** would mean the core answers "covered" or "not", and main acts on the answer. It's cheaper, but a main path that doesn't ask still signs.

### What the core enforces

| Effect | Who signs | The core's check |
|---|---|---|
| A vault account's transaction, message or typed data | the core | enforced from APR-4 |
| A phone account's job | the phone | enforced from PHN-2: the core makes a job only from a checked authorization, and checks the answer |
| An x402 authorization | the core | enforced from X402-2, when main's x402 path signs only through `x402.authorize` |
| A Ledger account's signature | the device, through main | advised (`approval.spend`) until 0016 |
| A Safe transaction or message | the owners, through the core; the executor | advised until 0016. One confirmation collects every local owner's signature (`wallet-ipc.js:827–830`) |
| A page's Swarm SOC (feed writes) | the core | advised until 0015, which gives the core the site's publisher identity |
| A Radicle COB write | `freedom-radicled` | advised: main asks the core before it forwards the write |
| A Swarm upload or message | the Bee node | advised |
| Sending an intent again, or closing one | main | advised (`approval.spend`): nothing is signed |

## Crates and clocks

- **`fc-approval`** (logic, no I/O): tokens and their bindings; the grant model and the four files' codecs; the standing rules; the R-6 limiter; the fee check's judgement; x402 caps and the authorization builder; phone jobs.
- **`fc-eip1193`** (logic, no I/O): the Ethereum dispatcher, a sans-I/O machine like `fc-chain`'s ([fc-eip1193](#fc-eip1193-and-approvalrequest)).
- **`freedom-cored`:** the methods, the RNG, the clocks, and the files.
- **Both crates compile for iOS and Android,** as CI requires of every logic crate (`.github/workflows/ci.yml`), and `freedom-mobile-ffi` links them later. Mobile brings its own store and prompts behind the same traits.
- **No new dependency:** `sha2`, `sha3`, `k256`, `serde_json` and `rand_core` are in the workspace. JS's key order is kept with `serde_json`'s `preserve_order`, which `freedom-cored` already enables.

**Time and randomness come in** (AGENTS rule 2):
- **`now` is a parameter** of every call that judges time, as in `fc-chain`. There are two clocks:
  - **The vault's clock** (`clock.rs`, #80): milliseconds that count sleep and never run back. A wall clock set forward moves it ahead. Token lives, rate limits, job timeouts and evidence ages use it. A token minted before three days asleep is expired after them. Today a wall clock set back extends a token ([Deviations](#deviations)).
  - **The wall clock,** in seconds, for what is written down or signed: x402's `createdAt` and `expiresAt`, and an authorization's `validBefore`. A wall clock earlier than a cap's `createdAt` expires the cap ([Deviations](#deviations)).
- **Randomness** comes in as `rand_core::TryCryptoRng`, as in `fc-vault`: token bytes, x402 nonces, phone job ids. The daemon passes the OS's (`getrandom`). Tests pass a fixed one, so that a vector can pin a whole x402 payload.

## Tokens

**Who mints them** (`approval.issue`):
- **Page kinds** (`dapp-send`, `sign-message`, `sign-typed-data`, `safe-message`, and a `safe-send` with a site): only the `page` caller, with the request's `PageContext` and 0011's handle. Main's dispatcher asks on the user's approval of an open handle: it is 0011's internal issuer. The core refuses `chrome` for every page kind, as 0011 refuses it from PRQ-5.
- **Wallet kinds** (`wallet-send`, a `safe-send` with no site, `intent-resend`, `intent-replace`, `intent-close`, `executor-send`, `x402-payment`): `chrome` until APS-3, then `shell` only. From APS-3 main asks as `shell` on a decision made in the approvals document.

**What each binds.** The core binds the request in the form it will sign: its own parse of the `sign.*` parameters (0002's wire format), never main's display form. What is confirmed is then what is signed.

| Kind | Binds | Spent by |
|---|---|---|
| `wallet-send` | the account (the one main names as active, as today); the transaction but its nonce: chain, `to`, `value`, `data`, the gas limit and every fee field | `sign.transaction` |
| `dapp-send` | as `wallet-send`, for the request's account; the page; the handle; whether "Always allow" was ticked | `sign.transaction` (page) |
| `sign-message` | the account; the bytes to sign; the page; the handle | `sign.message` (page) |
| `sign-typed-data` | the account; the EIP-712 hash, which the core computes at minting and returns with the view; the page; the handle | `sign.typed_data` (page), whose `expected_hash` must equal it |
| `safe-send` | the Safe and its address; the SafeTx's chain, `to`, `value` and `data`; the site, or none | `approval.spend` (advised, until 0016) |
| `safe-message` | the Safe; the method and a digest of its params; the page; the handle | `approval.spend` (advised, until 0016) |
| `intent-resend` | the intent's id, chain, sender and nonce, and the hash sent again, from main's record | `approval.spend` (advised) |
| `intent-replace` | the intent's id, sender and nonce, the payment it keeps, and the new fees | `sign.transaction`, at that nonce |
| `intent-close` | the intent's id, chain, sender and nonce, and every hash, in order | `approval.spend` (advised) |
| `executor-send` | the executor's account; the transaction but its nonce, with the fees shown | `sign.transaction` |
| `x402-payment` | the account; the tab, the detection id and the URL; the chosen entry (index, scheme, network, asset, amount, `payTo`, a digest of the whole entry); the grant, or none (#1016) | `x402.authorize` |

- **The page** is `PageContext`'s `origin`, `frame` and `navigation` ([PageContext](#pagecontext)). A token presented with another page is refused, so a token can't outlive its document's number, even if main's own check misses.
- **The nonce isn't bound,** except by `intent-replace`. Main chooses it after the confirmation, under the account's lock, until 0013 moves the journal.
- **Life and count:** two minutes of the vault's clock, at most 32 outstanding, the oldest dropped. A token is **burnt** at its first presentation, whatever the outcome, as today. `approval.discard` burns one without spending it (#1016's `discardConfirmation`).
- **A token is a bearer secret.** It is never logged, never in `Debug` output, and compared in constant time.
- **The fee check** runs at minting for `wallet-send`, `dapp-send`, `intent-replace` and `executor-send`, except for a phone account, as `wallet:confirm-signing` does today ([The fee check](#the-fee-check)).

**Parity.** The digest never leaves the core, so its bytes aren't the contract; the decisions are. For each kind, the JS reference's `bindingFor` gives the facts a payload binds, or its error. The core binds every one of those facts, so two payloads JS tells apart never share a token. It may refuse more ([Deviations](#deviations)): JS binds `chainId: true` as chain 1 (`Number(true)`).

## Grants and standing rules

### The model
- **A grant** is a site's entry in one of the four stores, under its permission key: 0011's `key`, which is `PageContext.origin`. x402's key is the paid URL's origin, as today ([x402](#x402)).
- **The core writes a grant only from a decision:** a connect's account and chain, an "Always allow" from a confirmed send (the `dapp-send` token's flag, for the token's page), a Swarm or Radicle tier the user approved. These writes come from the `page` caller, for its own key. An x402 cap comes with its payment, through `x402.authorize`. The chrome may read and narrow (revoke, turn a rule off), as 0011 allows. It can't widen.
- **Main's own writes** come as `shell`: a Swarm manifest's projection (`permission-manifests.js`) until 0015, and an account's deletion (`revokePermissionsForWalletIndex`).
- **Events:** each change sends `approval.changed { store, key }`, so that main can send `accountsChanged` and Swarm's `connect` and `disconnect` to that key's documents (0011's events).

### The rules
Each is today's, evaluated in the core for `PageContext.origin` and pinned by vectors from the JS:

| Request | A standing rule answers when |
|---|---|
| `personal_sign` | the grant exposes the account, its `autoApprove.signing` is on, and the message isn't exactly 32 bytes |
| `eth_signTypedData_v4` | as for `personal_sign`, and the core's view carries no warning |
| `eth_sendTransaction` | the grant exposes the account; a rule matches `to`, the first four bytes of `data` and the chain; the site isn't paused (D12); the fee check allows it; the send names its own fees |
| a Safe message | as a message or typed data, for the Safe's grant (advised) |
| a Swarm publish, feed, signature or message | the grant's flag for that type, and the messaging grant for messages (advised) |
| a Radicle seed or unseed; a COB write | `autoApprove.node`; `autoApprove.signing` within the R-6 limit (advised) |
| an x402 charge | [x402](#x402) |

- **No rule answers in custody.** `PageContext` carries `agent` from APR-3 ([PageContext](#pagecontext)). Main reads it live as it sends each request, as 0011's custody rules require, and a request without it gets no standing rule.
- **The D12 pause stays main's.** Its turns end when the intent journal commits, and the journal is main's. A standing authorization carries `paused`, which main reads in the send's own turn. A missing one reads as paused.
- **R-6 moves as it is:** per key, a burst of 5, one per 30 s, 50 in 24 hours, on the vault's clock, in memory, forgotten on disconnect.
- **"Always allow" has no limits today** but R-6's ([Q9](#open-questions)). If the user wants them, the proposal is: a rule lasts 30 days from when it was given; signing and transaction rules get R-6's rate limit; a transaction rule covers no more `value` than the send it came from. Each is stored so that an older build sees no rule ([The files](#the-files-q10)).

### The fee check
0005's check A moves with the tokens and the rules: `fee-check.js`'s `referenceFee` and `judgeFees`, ported with vectors.
- **The evidence is the core's own:** the newest `chain.fee_reference` reply it served for that chain, aged from when it admitted the request, and at most 60 s old. Main fetches one before the prompt, as it does today. A figure main sends is never used.
- **At minting:** a send above the threshold gets no token without `fee_ack`, and the reply carries the verdict for the screen.
- **Under a standing rule:** a send with no reference, with one endpoint's reference, or with a fee above the threshold isn't covered.

## The files (Q10)

**Proposed: the core takes the four files over in place.**
- **Where:** `core.hello` gains `grant_root`, the profile's `userData` as an absolute path, beside `node_roots`. The core opens the four files there under 0001's reading rules: a regular file the user owns, no symlink, a size bound.
- **The format** is today's, byte for byte: the same keys, `JSON.stringify(…, null, 2)`'s text, and JS's key order (insertion order, as each store's operations leave it). Vectors pin the text after each operation.
- **Writes** are 0001's single-file writes: a temp file, fsync, a rename, the directory flushed, mode `0600`. Each store has one writer: from its APB step on, main reads and writes it only through the core.
- **Bounds** (proposed): 4 MiB per file, 4,096 keys per store, 256 transaction rules per key. A write past them is refused. A file past them is read as unreadable.
- **An unreadable file** is renamed aside once (`<name>.unreadable`), and the store starts empty, so every site asks again. Today the next write overwrites it.
- **Older builds read the files as they are.** A grant revoked in the new build stays revoked after a rollback.
- **New fields fail safe.** Anything that limits a rule (Q9's expiry, rate or value cap) is written where an older build doesn't look, such as `autoApprove.limited`, so an older build sees no rule and prompts. A grant never gains authority in an older build.

**The overlap with 0013.** 0013 decides which stores the core owns in the end (Q14), where they live (`<profile>/freedom/`), and whether that move is one-way (Q12). 0012 moves who writes the files, not where they are. `fc-approval`'s store trait is what 0013 relocates. The intent journal and the nonces are 0013's.

## Transaction building

**Proposed: it stays in main in Stage 1,** as 0002 and 0005 set: the nonce under the account's lock, the intent journal, gas estimation and fee filling.
- **Why not now:** the nonce is chosen from the journal's held nonces, and the journal's rules (a commit before any byte leaves, voiding, retiring) rest on its crash safety. Moving the nonce without the journal moves nothing: the core would take the larger of two numbers main supplies. The journal is a store, so 0013 moves it (Q14).
- **What moves is the binding.** The core signs only the fields a token or rule authorized, so a main bug between the confirmation and the signature can change only the nonce.
- **`fc-eip1193`** prepares a dApp's send itself (the estimate with its 20% buffer, the fees from the core's quote), since both are reads the core already serves. It hands the approved send back to main to sign, record and broadcast.
- **APR-6 is therefore deferred.** It moves with 0013's intent store, if the user agrees there.

## PageContext

0011 fixes four fields. 0012 adds what the core needs to judge a standing rule:

| Field | From | Since |
|---|---|---|
| `origin` | the document's permission key (0011's `key`) | 0011 |
| `top_origin` | `topKey` | 0011 |
| `frame` | `frameTreeNodeId` | 0011 |
| `navigation` | main's document number | 0011 |
| `agent` | `isAgentPage(event.sender)`, read as main sends the request | APR-3 |
| `transport_key` | 0011's `transportKey` | APR-5, for the core's own name check |

- **Required once defined:** a page request without `agent` gets no standing rule. The wire form stays `"context": { "caller": "page", "page": { … } }` (`message.rs`).
- **The core admits `page`** on `approval.issue`, `approval.discard`, `approval.spend`, `approval.check`, `approval.grant`, `approval.revoke`, `approval.touch`, `sign.transaction`, `sign.message`, `sign.typed_data` and `phone.job`, and later on `eip1193.request`. These are the rows 0011 left for 0012 (`Callers::allow`).

## API

Every method is in `fc-protocol`'s table with its callers. A refusal is `not_authorized`, with `data.reason` one of `no_token`, `unknown_token`, `expired`, `mismatch`, `no_rule`, `paused`, `fee_check`, `custody`, `rate_limited`, `cap`, `warning`. Main maps it to today's texts ("Signing was not confirmed: …", `SIGNING_NOT_CONFIRMED`).

| Method | Callers | Params → result |
|---|---|---|
| `approval.issue` | page (page kinds); chrome (wallet kinds, until APS-3); shell (wallet kinds) | `{ kind, account, payload, handle?, fee_ack? }` → `{ token, expires_in_ms, hash?, view?, fee_check? }` |
| `approval.discard` | page, chrome, shell | `{ token }` → `{}` |
| `approval.spend` | the caller kind that minted the token | `{ token, kind, account, payload, handle? }` → `{ bound }`, for the advised kinds |
| `approval.check` | page | `{ request, chain_id, paused }` → `{ covered, reason? }`: whether a standing rule would answer, for the choice between a prompt and none. Advice: `sign.*` decides again |
| `approval.grant` | page; shell (a manifest's projection) | `{ store, change }` → `{ grant }` |
| `approval.revoke` | page, chrome, shell | `{ store, key, what }` → `{ revoked }` |
| `approval.touch` | page | `{ store, chain_id? }` → `{}`: `lastUsed`, and a dApp's chain |
| `approval.grants` | chrome, shell | `{ store, key? }` → the store's records, in today's shapes |
| `approval.forget_account` | shell | `{ wallet_index }` → `{ keys }` |
| `sign.transaction`, `sign.message`, `sign.typed_data` | page (new); chrome; shell | 0002's params, plus `authorization`: `{ token, handle? }` or `{ standing: { paused? } }` |
| `x402.authorize`, `x402.settle` | shell | [x402](#x402) |
| `phone.job`, `phone.sent`, `phone.result` | page; chrome; shell | [Phone jobs](#phone-jobs) |
| `eip1193.request` | page | [fc-eip1193](#fc-eip1193-and-approvalrequest) |

- **APR-3 checks an authorization when one is present,** and still signs without one, as today. **APR-4 requires it.** So the browser can pass authorizations one release before the core insists.
- **Events:** `approval.changed { store, key }`, from the core to main, for each grant written or revoked.
- **The order of work** is 0002's: all public work first, the authorization check included, then the key. A token presented while the vault is locked is still burnt, as today.

## fc-eip1193 and approval.request

APR-5 moves 0011's Ethereum dispatcher (`src/main/page/`, in JS) into the core.
- **`eip1193.request { method, params }`** (page caller): the core runs the request. Reads go to its own chain machine (0005). `eth_accounts` and the connect methods read its grants. Signatures go through its own tokens and rules. Its result is `{ result }`; or `{ error }`, with the EIP-1193 code main returns today; or `{ send }`, an approved transaction with its token, for main to sign, record and broadcast ([Transaction building](#transaction-building)).
- **`approval.request`** is a core-to-main request, like 0004's `shell.*`: `{ page, kind, view, choices }` → `{ approve, choices }`. Main answers `closed` when 0011's handle closes, and `busy` when the window already has a wallet prompt open (the page gets `-32002`). The core builds `view` to 0011's closed schema. Main adds its own fields (the tab, the site's label) and shows it in the approvals document.
- **`approval.recheck`** is another: `{ page }` → `{ live, agent }`, sent just before an effect a standing rule answered, as 0011 reads custody and the document again.
- **Names over IPNS:** with `transport_key`, the core resolves the name itself before each use of its grant, by 0011's table of methods, with its own naming.
- **Deadlines:** a prompt has none (0011). `eip1193.request` gets a new deadline class: no overall deadline while one of its own `approval.request`s is open, and each I/O step keeps its own. Main's hang watchdog skips a request while main is answering one of its prompts.
- **Ledger and Safe accounts** (until 0016): their signing methods come back to main as `{ device }`, with the approved request and its token.
- **Vectors:** `vectors/eip1193.json`, recorded from 0011's JS dispatcher: each request, each effect and its answer, and the result, as `naming-replay.json` records naming.

## x402

X402-1 moves the caps, the `x402-payment` token and the authorization into the core. Main keeps the interception (`webRequest`), the 307 and the header.
- **`x402.authorize { account, detection: { tab, id, url }, requirements, accept_index, grant?, authorization }`** (shell). The `authorization` is `{ token }`, an `x402-payment` token, or `{ cap: { agent, attributable } }`:
  - **Under a cap:** the first entry, in the seller's order, that an active cap covers, as `findCoveringPermission` picks it. None in custody, and none for a request main couldn't attribute.
  - **With a token:** exactly the entry and the grant it binds.
  - **The authorization** is built by the core from that entry, byte for byte as `@x402/evm` 2.28.0 builds it (EIP-3009 for V1 and V2, and Permit2), with the nonce from the RNG and `validBefore` from the wall clock, then signed inline.
  - **The cap is charged when the core signs,** in the same turn. A grant that comes with a payment is written after its signature, as today.
  - The reply is the payment payload and a reservation id.
- **`x402.settle { reservation, outcome }`:** `withheld` gives the amount back, since main dropped the header; `sent` keeps it.
- **Widening a cap** (a higher amount, a longer window) needs a decision, as a new grant does. The activity pane can only narrow one (X402-2).
- **The key stays the paid URL's origin,** main's word from `webRequest`. Keying a cap on the page as well is [Q11](#open-questions)'s alternative.

## Phone jobs

PHN-1 makes the core the job's authority. The openlv session stays in the chrome, and main relays.
- **`phone.job { account, method, payload, authorization }`:** the core checks the authorization as `sign.*` would, then records a job:
  - its id (16 random bytes), the account's index and address;
  - the method and what it binds: the message bytes; the typed data's confirmed hash and its view; a payment's chain, `to`, `value` and `data`;
  - the authorization it came from (its kind, site and handle);
  - five minutes of the vault's clock.

  The reply is the JSON-RPC request to relay. For typed data it carries the core's view, so the phone signs what the user saw ([Deviations](#deviations)).
- **`phone.sent { job }`** marks the job possibly sent, in one turn, as `remote-signer:request-sent` does. It is refused for a settled job.
- **`phone.result { job, result | error }`** is accepted once:
  - **A signature** must be 65 bytes and recover to the account over the bound digest (EIP-191 over the bytes, or the confirmed EIP-712 hash). Otherwise it is refused (`wrong_account`, `bad_response`).
  - **A payment's hash:** the core reads the transaction (`eth_getTransactionByHash`, 0005). If it is visible and its `from`, `to`, `value`, `data` or chain differs from the job's, it is refused (`wrong_transaction`). One not visible yet is accepted, as today, and tracked as any send is.
  - **An error** is mapped as today. After `phone.sent`, a payment's lost or unrecognised answer is unknown. Only 4001, 4100 and 4200 mean "not run".
- **Main still** chooses the window, relays the job, and tells the core which webContents answered. A chrome can drop or delay a job. It can no longer swap one.

## Deviations

| Case | JS today | The core |
|---|---|---|
| `token-clock` | a token lives two minutes of `Date.now()` | two minutes of the vault's clock: sleep counts, and a wall clock set back doesn't extend it |
| `token-strict` | `bindingFor` takes what `BigInt` and `Number` take: `chainId: true`, `" 1"` | the parse `sign.*` uses; such a request gets no token |
| `token-page` | a page kind binds the site the chrome names | it binds `PageContext` and the handle (0011) |
| `token-remember` | `rememberAutoApprove` rides beside a confirmed token and names its own key | the flag is bound in the `dapp-send` token, and the rule is written for the token's page (0011 records it for the requester's key) |
| `rule-inputs` | custody and the pause are read inside main | sent with each request; a missing one reads as no rule |
| `file-unreadable` | loads as `{}`, and the next write overwrites it | renamed aside as `.unreadable` |
| `file-atomic` | written in place (three files), with no fsync (Swarm) | 0001's atomic write, mode `0600` |
| `file-bounds` | none | 4 MiB, 4,096 keys, 256 transaction rules per key |
| `x402-at-sign` | a cap is charged at injection | at signing, and given back on `withheld` |
| `x402-clock-back` | a cap stays valid when the wall clock is set before its `createdAt` | it is expired |
| `x402-asset-case` | revoke and update take the asset as the caller writes it | lowercase everywhere |
| `x402-widen` | `x402:update-permission` raises a cap on a bare call | widening needs a decision |
| `phone-typed-view` | the dApp's own payload goes to the phone, checked with ethers' `verifyTypedData` | the core's view goes, checked against the confirmed hash |
| `phone-tx-fields` | a reported payment is checked for `from` | `from`, `to`, `value`, `data` and the chain, once visible |

Each case has a vector or a test. A vector records what JS does; the core's expected answer comes from this table.

## Vectors

They come from the pinned reference checkout, through a generator `vectors/generator/approvals.js` that stubs Electron as the chain generator does, with a CI `check` mode (AGENTS rule 5):
- **`vectors/approvals.json`:**
  - `tokens`: `bindingFor` for each kind, its facts or its error; payloads that bind alike, and apart; issue and consume runs under `_setNow`, including the boundary (at exactly two minutes a token is expired: `expiresAt <= now`); the cap of 32.
  - `stores`: each store's operations in order, with `Date.now` fixed, and the file's text after each; malformed files, and what each store loads from them.
  - `rules`: each rule's decisions, from `wallet-ipc.js`, `dapp-permissions.js` and the Swarm and Radicle stores; R-6's limiter under its own injected `now`; D12's decisions; `fee-check.js`'s references and verdicts.
  - `x402`: `tupleFromAccept`, `findCoveringPermission`, the cap store under a fixed clock, and `@x402/evm`'s payloads with `getRandomValues` and `Date.now` fixed.
  - `phone`: the bridge's error mapping, and signatures over the reference's payloads.
- **`vectors/eip1193.json`** (APR-5): the dispatcher's recorded exchanges.

## Migration

One PR per step: the core's against `main`, the browser's against `integration/rust-core`.

| Step | What | Needs | The tests that prove it |
|---|---|---|---|
| APR-1 | `fc-approval`: tokens and bindings, the injected clock and RNG; `vectors/approvals.json`'s tokens | SEC-1 (#1016) merged, for the eleventh kind | Every kind binds the reference's facts; payloads JS tells apart get different tokens; the `token-*` deviations are refused. With a fixed clock, a token is valid at 119,999 ms and expired at 120,000. A 33rd token drops the oldest. A token is burnt on a mismatch, an expiry and a wrong kind. A fixed RNG gives a fixed token. The iOS and Android builds pass |
| APR-2 | Grants, the files' codecs, the rules, R-6, the fee check | APR-1 | Each store's file text after every vector's operations, byte for byte; each malformed file; each rule's decision table; R-6's runs (a sixth write at once refused, one more after 30 s, the 51st in a day refused, disconnect forgets); D12's `paused`, and a missing one; the fee verdicts at 3·R, with no reference and with `answered: 1` |
| APR-3 | `approval.*` in `freedom-cored`; `grant_root`; `PageContext.agent`; authorizations checked when present | APR-2 | Over the wire: page kinds refused for `chrome`; grant writes refused for `chrome`, revokes allowed; a token for one page refused for another `frame`, `navigation` or `origin`; files written atomically with mode `0600`, and temp files cleaned at start; an unreadable file renamed aside; a restart reloads; two writes to one store serialize; one `approval.changed` per change |
| APR-4 | `sign.*` require an authorization | APB-1 and APB-2 shipped; PRQ-5 | Each signing method refused without one, with another document's token, another site's, another account's, an expired one, and one spent twice. A standing rule refused in custody, while paused, over the fee threshold, for a warned view, for 32 bytes, for a plain transfer. Refused before any key is derived, and the token burnt while locked. `chrome` refused without a wallet-kind token; `shell` signs as before |
| APR-5 | `fc-eip1193`, `eip1193.request`, `approval.request`, `approval.recheck`, `PageContext.transport_key` | APR-4; PRQ-9 | `vectors/eip1193.json` replayed. A prompt closed by a navigation does nothing. `busy` gives `-32002`. A request a rule answered is rechecked: a tab gone into custody, or a document gone, refuses it with nothing signed. A name moved off its IPNS key refuses every name-revalidated method |
| APR-6 | Transaction building | 0013 decided | Deferred ([Transaction building](#transaction-building)) |
| X402-1 | `x402.authorize`, `x402.settle`, the caps in the core | APR-3 | Payloads byte for byte as `@x402/evm` makes them under a fixed nonce and clock (EIP-3009 V1 and V2, Permit2). Tab A's token refused for tab B, entry 0's for entry 1, and after an account switch. A cap covering one payment signs one of two concurrent charges; `withheld` gives it back. No cap in custody or for an unattributed request. A cap expired, and one behind a clock set back. A grant written only as bound |
| PHN-1 | `phone.job`, `phone.sent`, `phone.result` | APR-4 | A job only from a checked authorization. A result for another job, a second result, and one after expiry refused. A signature recovering to another account refused. Typed data checked against the confirmed hash. A visible transaction with another recipient, amount, data or chain refused; one not yet visible accepted. A payment's timeout after `phone.sent` unknown. 4001, 4100 and 4200 mapped as today |
| APB-1 | Tokens through the core: `wallet:confirm-signing` and main's issuer call `approval.issue`, and every `sign.*` passes its authorization | APR-3's release pinned; PRQ-5 | `signing-confirmation.test.js`'s cases against the core; no token kept in main; page kinds sent under `page`; main's dispatcher sends no page request as `shell` |
| APB-2 | dApp grants and rules through the core; `dapp-permissions.json` becomes the core's | APB-1; PRQ-4 | Main writes the file nowhere (a spy on `fs`); `wallet-ipc.test.js`'s auto-approve cases and the D12 suites pass. Rollback: the reference's `dapp-permissions.js` reads a file the core wrote and sees the same grants |
| APB-3 | Swarm and Radicle grants through the core, R-6 included | APR-3; SEC-3f (#941 on integration) | As APB-2, for both files; R-6's tests; the manifest projection written as `shell` |
| APB-4 | The Ethereum dispatcher replaced by `eip1193.request` | APR-5; PRQ-9 | PRQ-3 to PRQ-6's tests pass unchanged against the core's dispatcher |
| X402-2 | x402 through the core; `x402-permissions.json` becomes the core's; widening needs a decision | X402-1 | #1016's suites against the core; the activity pane can lower a cap and can't raise it |
| PHN-2 | The bridge relays the core's jobs | PHN-1 | `bridge.test.js`'s and `signer.test.js`'s cases against the core; an answer from a webContents the job wasn't sent to refused |

- **Rollback:** until the browser pins APR-4's release, each browser step reverts on its own, and the core still signs without an authorization. After that pin, reverting APB-1 or APB-2 means reverting the pin too. The files' format never changes, so an older build reads them at every step.
- **One writer per store:** a store's APB step stops main's writes in the same PR that starts the core's.

## Amendments

Once decided:
- **0002, Non-goals:** "Approval and policy" reads: "Stage 1 trusts main, which shows the prompts. From 0012 the core keeps the tokens, grants and standing rules, and refuses a page's signature without a check it made itself." "Policy moves with the Chromium work" goes. The *Callers* bullet admits `page` on the three EVM signing methods.
- **0001, Messages:** `page` is admitted on the methods in [PageContext](#pagecontext); `not_authorized` joins the request errors; `core.hello` takes `grant_root`.
- **0011:** `PageContext` gains `agent` and `transport_key`, and its internal issuer becomes a caller of `approval.issue`. A token still never reaches a renderer.

## Options weighed

- **Advise only** (Q8's alternative): one call to ask, and no change to `sign.*`. A path that doesn't ask still signs.
- **New files in the core's own directory,** instead of today's: older builds would read stale grants, and a grant revoked since would come back on a rollback. Only writing both, or a one-way move, avoids that, and 0013 weighs the one-way move.
- **Binding JS's digest byte for byte** (`stableStringify`): it never leaves the process, so only the decision matters, and binding the core's own parse binds what it signs.
- **Moving the nonce now:** without the journal it moves nothing ([Transaction building](#transaction-building)).
- **Custody state kept in the core,** told by events: an event can arrive after the request it should have stopped. Read with each request, it can't.
- **The core fetching its own fee reference** for each check: a second way into the chain machine, for evidence main already fetches before every prompt.
- **WebRTC in the core for the phone:** a large new surface. Checking the answer gives the same assurance about what was signed.

## Open questions

1. **Q3, policy in the core:** Move site approvals and grants into the core now (Electron), instead of waiting for Chromium as 0002 planned? *Proposed: yes.*
2. **Q8, enforced:** Core refuses any dApp signature without an approval/grant it checked itself, though main stays trusted in Stage 1? *Proposed: yes, for every signature the core makes.*
3. **Q9, "Always allow":** "Always allow" in the core: today's rules, or add limits (expiry, spending cap)? *Proposed: add 30 days, R-6's rate, and no more `value` than the send the rule came from.*
4. **Q10, rollback:** Must older builds still read the grant files after the move (rollback)? *Proposed: yes, in Stage 1.*
5. **Q11, x402:** x402 automatic payments: keep today's per-site caps unchanged? *Proposed: yes, keyed as today, with the fixes in [Deviations](#deviations).*
