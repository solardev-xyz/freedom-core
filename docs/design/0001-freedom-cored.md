# 0001: `freedom-cored`, the desktop core process

**Status:** draft, revision 2. It incorporates Codex's review on PR #1. **Scope:** Phase 1 of [freedom-browser#644](https://github.com/solardev-xyz/freedom-browser/issues/644), plus the protocol contract that Phases 2–5 extend.

## Summary

- **One `freedom-cored` process per Freedom profile.** The profile's Electron main process spawns it. It owns the identity vault, the seed, key derivation and the lock state, and in Phase 2 it takes over signing.
- **Transport and messages:**
  - The transport is stdin/stdout with length-prefixed frames. Only the parent holds the pipe, so there is no socket, port or token.
  - Messages are JSON requests, responses and events in both directions, defined in `fc-protocol`. A version handshake comes first. Every request carries a caller context that main fills in.
- **One lock file per identity directory**, held by the core for its whole life. Its rules are in [Lifetime lock](#lifetime-lock).
- **Writes:**
  - Single files are written atomically and durably, and a new vault is checked by decrypting it before it replaces the old one.
  - A write that spans several files (node identities) follows an intent-record protocol that can be redone after a crash.
- **The shell never reports a committed vault change as failed.** Every vault mutation can be reconciled from the vault file's fingerprint.
- **Phase 1 is one slice:**
  - the vault, key derivation and the Bee and Radicle identity writes all move behind the existing `identity:*` channel names;
  - the mnemonic and the derived-key cache stop living in main;
  - JS signing keeps working through a temporary, enumerated `compat.*` API, which Phase 2 deletes.
- **Fixed in the slice:**
  - **K-1:** one lock state, with revocation epochs.
  - **K-2:** durable atomic writes; Unix mode `0600`.
  - **K-4:** throttling that can't be reset from the renderer.
  - **K-3 (partly):** node key files become `0600`.
  - **The JS password-change timer bug** (see the [parity table](#parity-contract)).

**Needs your OK:**
1. The temporary `compat.*` key exports ([Migration](#migration-in-freedom-browser)).
2. Touch ID quick unlock stays in the shell until Phase 5 ([Quick unlock](#quick-unlock)).
3. Packaged builds get no runtime switch back to the JS vault; rollback is a hotfix release ([Rollback](#rollback)).
4. The two intentional behavior changes in the [parity table](#parity-contract).

## Goals and non-goals

**Goals**

- Move the vault, seed and derivation out of Electron main. File formats stay unchanged, and user-visible behavior changes only where the parity table says so.
- Build the process, protocol, packaging and release path once.
- Keep the logic crates free of I/O, so mobile and a later Chromium build can reuse them.

**Non-goals for Phase 1**

- Signing in Rust (Phase 2).
- Naming (Phase 3), transports (Phase 4), profiles, stores and `vault-meta.json` (Phase 5).
- Format or UI changes.
- Mobile bindings.
- An IPFS identity. Desktop deliberately runs IPFS with an ephemeral identity (`identity-manager.js:609`), and Phase 1 keeps that.

## Threat model

Stage 1 trusts Electron main: it holds the pipe, fills in the caller context, and runs the approval UI. The core therefore does **not** defend against a compromised main. A compromised main can ask the core to sign anything, and in Phase 1 it can call `compat.*`.

**What the core does protect against:**

| Threat | Today | With the core |
|---|---|---|
| Compromised renderer reaching the master secret | Main's sender checks (E-1) | The same checks. The mnemonic is no longer resident in main; it passes through main only during onboarding display and user-requested exports |
| Main bugs keeping keys (K-1 class) | Derived keys cached in main's heap until an explicit lock | **Core:** one lock state with revocation epochs. **Main:** holds a borrowed key only for the duration of one operation (Phase 1), then never (Phase 2). Copies already in JS strings and ethers objects can't be wiped, and Phase 1 only stops keeping them |
| Torn or exposed secret files (K-2, K-3) | `writeFileSync` with umask permissions | Durable atomic writes. **Unix:** mode `0600`. **Windows:** files inherit the per-user `%APPDATA%` ACL; an explicit owner-only DACL is a follow-up |
| Password guessing through `identity:unlock` (K-4) | Unthrottled | Throttled in the core. Renderer-supplied input can't crash the core, so a compromised renderer can't reset the counter |
| Another same-user process reading key memory | Main: a large, unhardened process | **macOS:** the hardened runtime blocks `task_for_pid`. **Linux:** `PR_SET_DUMPABLE=0`. **Windows:** no change |

**Not covered:** root or admin malware, a compromised OS, a compromised main, physical attacks on unlocked memory. `mlock` is deferred (see [Secrets in memory](#secrets-in-memory)).

**Deliberate exceptions to "no raw secret leaves the core"** (AGENTS.md rule 3 is amended to match):
- **Permanent:** the user-requested backup exports (`vault.export_mnemonic`, `vault.export_private_key`), and the mnemonic shown during onboarding.
- **Temporary:** the `compat.*` signing exports, removed in Phase 2.

## Process model

```
Electron main (profile P) ──spawn──▶ freedom-cored serve --data-dir <identityDir>
     stdin  ──frames──▶
     stdout ◀──frames──
     stderr ◀──JSON log lines── (forwarded to main's log)
```

- **One core per profile.** Each profile process (`--profile=<id>`) spawns one core for its own `getIdentityDataDir()`.
- **Spawn:**
  - The binary comes from the app's resources. `FREEDOM_CORED_PATH` is honored only when `!app.isPackaged`.
  - The environment is cleared except for `PATH`, `HOME`/`USERPROFILE`, `LANG` and `RUST_LOG`.
  - stdin and stdout are pipes; stderr is a pipe read line by line.
  - Main spawns the core at startup and serves no `identity:*` request until the handshake has succeeded.
- **Handshake:** `core.hello` must complete within 10 s of spawn, or main kills the core and treats it as a startup failure.

### Lifetime lock

- **The lock itself:**
  - The core opens `<identityDir>/freedom-cored.lock` for read and write, creating it if needed, never truncating it, and with close-on-exec, which is Rust's default.
  - It then takes `File::try_lock`, which is `flock` on Unix and `LockFileEx` on Windows.
- **Possible outcomes:**
  - **Contention:** retry for 5 s (Windows can release the lock a little after process exit), then exit 75 (`lock_held`).
  - **Any other error,** such as an unsupported filesystem or I/O failure: exit 74 (`storage`). The core fails closed and never runs without the lock.
- **The lock file is never renamed, unlinked or recreated while the profile exists.** On Unix, a lock protects an inode, not a path. So everything that removes or moves an identity directory must first prove no core holds that lock: profile delete and reset (`profile-catalog.js`) and data migrations. They call `freedom-cored probe-lock --data-dir <dir>`, which tries the lock once and exits 0 if the lock was free, or 75 if it is held.
- **Scope of the guarantee:** mutual exclusion between cores on local filesystems (APFS, ext4/btrfs/xfs, NTFS). Identity directories on network filesystems aren't supported, and the core refuses them when locking reports `Unsupported`.
- **Dev-only shared directories:** two profiles that share an identity directory through `FREEDOM_IDENTITY_DATA` now fail cleanly instead of racing. The second core gets `lock_held`.

### Shutdown, crashes and parent death

- **Shutdown:**
  1. Main sends `core.shutdown`, then closes stdin.
  2. The core revokes the vault epoch (see [Concurrency](#concurrency-epochs-and-revocation)) and finishes or abandons in-flight work according to its commit state.
  3. It exits 0.

  After 3 s, main kills the core. Killing is safe because every write follows [Writes and durability](#writes-and-durability).
- **Parent death:**
  - The core's I/O task, which is independent of vault work, exits on stdin EOF. EOF in the middle of a frame counts as EOF.
  - **Unix backstop:** the core records `getppid()` at start and exits if it changes, checked every 2 s. A PID is never compared against itself, so PID reuse can't fool it.
  - **Windows:** relies on EOF.
- **Crash handling in main:**
  - Pending requests are settled by the [reconciliation rules](#reconciliation), not blanket-rejected.
  - Main treats the vault as locked and restarts the core after 0.5 s, 2 s, then 10 s.
  - Three crashes within 60 s stop the restarts and show an error with **Restart core**.
- **No restart for:**
  - an intentional shutdown;
  - exit 75 (`lock_held`) or 74 (`storage`);
  - a protocol mismatch;
  - app quit.

  These are reported as errors and don't count as crashes. A restarted core must complete a new handshake before main sends it anything.

## Transport and framing

- **Frame:** `u32` big-endian length of the rest, then a `u8` kind, then the payload.
  - **Kind `0x01`:** one JSON message, at most 1 MiB.
  - **Kinds `0x02`–`0x0F`:** reserved for Phase 4 streams.
- **Writer:** each side has one serialized frame writer with a bounded queue. Control messages (`response`, `event`, `cancel`, `core.shutdown`) have reserved capacity, so bulk traffic can't starve them.
- **Protocol errors** are an unknown kind, an oversized frame, invalid JSON, a response that has both or neither of `result` and `error`, or a response to an unknown or already-settled ID. They mean a bug in main or the core: the receiver logs it and closes the connection.
- **Renderer input never causes a protocol error.** Main validates sizes and argument bounds before sending (see [Input validation](#input-validation)).
- **Phase 4:** streams add stream IDs, open/data/end/error frames, per-stream and global credit, and an aggregate memory bound. Phase 4 negotiates them as protocol version 2. This doc doesn't claim they can be added without a version bump.

## Messages

```jsonc
{ "type": "request", "id": 7, "method": "vault.unlock",
  "params": { "password": "…" }, "context": { "caller": "chrome" } }
{ "type": "response", "id": 7, "result": { … } }
{ "type": "response", "id": 7, "error": { "code": "incorrect_password", "message": "Incorrect password" } }
{ "type": "event", "event": "vault.locked", "data": { "reason": "auto", "epoch": 12 } }
{ "type": "cancel", "id": 7 }
```

- **IDs:**
  - Positive integers below 2^53, so JS can represent them exactly. One counter per sender, never reused within a connection.
  - A side only receives responses to its own requests, so the two ID spaces can't collide.
  - Main binds its pending-request map, timers and event handlers to the child's generation, a counter local to main. A late callback from a retired child is ignored.
- **Exactly one terminal response per request:** a result, or an error such as `cancelled` or `deadline`. Late or duplicate responses are protocol errors.
- **Handshake:**
  - The first message must be main's `core.hello`: `{ protocol: 1, shell_version, auto_lock_ms }`.
  - The core replies `{ protocol: 1, core_version, capabilities }`, or with `protocol_mismatch`.
  - Main and core ship pinned together, so a mismatch is a packaging bug, and main fails loudly.
- **Caller context:** main fills it in and never takes it from the renderer. Kinds use shell-neutral names, so a Chromium browser process can fill them in later.
  - `"chrome"`: the browser UI.
  - `"shell"`: main-internal work with no IPC event behind it, such as the x402 client and background jobs.
  - `{ "page": { origin, top_origin, frame, navigation } }`: web content. This is reserved for Phase 2, which also defines how a page's approval binds to a key and an operation.

  Each method declares the caller kinds it accepts, and the core answers anything else with `forbidden`. All Phase 1 methods accept `chrome` and `shell`.
- **Error codes:**
  - **Request errors:** `vault_locked`, `incorrect_password`, `throttled` (with `data.retry_after_ms`), `no_vault`, `vault_exists`, `unsupported_vault_version`, `corrupt_vault`, `invalid_mnemonic`, `invalid_argument`, `weak_password`, `storage` (with `data.kind`).
  - **Protocol-level:** `forbidden`, `busy`, `cancelled`, `deadline`, `internal`.
  - Main maps each code to the exact JS string per method; see [Parity contract](#parity-contract).
- **Schema:**
  - `fc-protocol` defines params, results, errors and the method table (name, caller kinds, mutation or read-only, default deadline).
  - CI regenerates `protocol/schema.json` and fails on any difference from the committed file.
  - freedom-browser's contract test checks its proxy table against that file.

### Concurrency, epochs and revocation

- **Epochs:** the vault state machine has an **epoch** counter. Unlock moves it to a new epoch. Lock, auto-lock, delete and shutdown **revoke** it immediately.
- **Lock is control traffic.** `vault.lock`, the auto-lock timer and `core.shutdown` run on the control path. They never wait behind KDF work or a write. Their acknowledgement means the epoch is revoked and the resident secrets are wiped.
- **Secret-bearing work is tied to its epoch.** Derivations, `compat.*` and node writes are admitted against the current epoch. A worker result from a revoked epoch is wiped, never installed, and returns `vault_locked`. In particular, an unlock whose KDF finishes after a lock does not bring the secrets back.
- **Work that already started** keeps the copy it took (for example, a `compat.private_key` reply being serialized). That's the documented limit: lock stops new use, it can't recall bytes already handed out.
- **Mutations** (create, import, change_password, delete, node writes) are serialized through one vault task.
- **Limits:**
  - At most 64 admitted requests (`busy` beyond that).
  - At most 2 concurrent KDF jobs.
  - A slot is held until the underlying work actually finishes, not when its caller gives up.

### Deadlines, cancellation and commit

- **Deadlines:** a request's deadline is a total budget on a monotonic clock, starting when the request is admitted (queue time included). Defaults: 30 s for KDF methods, 5 s for everything else.
- **Before the commit point,** a deadline or `cancel` stops the operation and returns `deadline` or `cancelled`. Throttle attempts are reserved before a KDF starts, so concurrent guesses can't all slip past the check.
- **After the commit point,** the rename of the vault file or the intent record of a multi-file write, the operation always runs to completion and reports its real outcome, even past the deadline.
- **Read-only operations** can be cancelled at any time.

### Reconciliation

Responses can still go missing if the core crashes, so every mutation is reconcilable:

- `vault.status` returns `{ exists, unlocked, epoch, fingerprint }`, where `fingerprint` is the SHA-256 of the vault file's bytes. Quick unlock already binds its credential to this hash.
- **Before a mutation,** main records the current fingerprint (or "no vault"). If the request ends in anything other than success (crash, deadline, `internal`), main calls `vault.status` on the restarted core, then:
  - **Fingerprint unchanged:** report the original error.
  - **Fingerprint changed:** call `vault.verify_password` with the password the mutation used. If it decrypts, the mutation committed, and main reports success: for create, also `vault.export_mnemonic` so the generated phrase can still be shown; for import, the addresses. If it doesn't decrypt, report `internal` and log both fingerprints. That can only mean another writer, which the lifetime lock rules out.
- **Quick Setup** is covered: the renderer's import call can't get an error back for a vault that was actually written, so it always goes on to store the random password.
- **No accidental rewrites:** the core never rewrites the vault file except through create, import, change_password and delete. Startup, status, unlock and verify read it and never write it, so the quick-unlock binding survives.

## Writes and durability

**Single file** (the vault, the Radicle public key, configs):

1. Create a temp file in the same directory with an exclusive create (`O_EXCL`). On Unix its mode is `0600` from creation.
2. Write it, then `fsync` it. On Windows, `FlushFileBuffers`.
3. **For the vault:** read the temp file back, decrypt it with the new password, and compare the mnemonic before going on. On any mismatch or error, delete the temp file and keep the old vault.
4. Rename it over the target.
5. On Unix, `fsync` the directory.
6. Return errors from any flush; never ignore them.

- **Guarantee:** the vault survives a process crash on every OS, and power loss on local Unix filesystems.
- **Windows:** `MoveFileExW` with `REPLACE_EXISTING | WRITE_THROUGH` is best-effort under power loss.
- **Existing files:** permissions are tightened the first time the core rewrites a file. The core never rewrites a file just to change its mode, because quick unlock's fingerprint must stay stable.

**Multi-file** (Bee: `keys/swarm.key` plus `config.yaml`; Radicle: private key, public key and config):

1. Stage every file as `<name>.freedom-new`, flushed.
2. Write `<dir>/.freedom-identity-intent.json` atomically. It records the node, the staged files and the key's address or DID. This is the commit point.
3. Rename each staged file into place, then `fsync` the directory.
4. Delete the intent record.

- **Recovery:** at startup, or before any node write, the core rolls a leftover intent record forward. This is idempotent; the staged files already hold everything.
- **Torn state:** a staged set without an intent record is deleted.
- **Main restarts a node only** after `nodes.write_identity` has returned success, or after a reconciling `nodes.identity_status` says the files are consistent.
- **Bee's keystore password** still goes into `config.yaml` (K-3, Phase 5). The intent protocol guarantees that the keystore and the password always match.

## Parity contract

Main's proxy has to reproduce each JS handler: argument checks and defaults, the order of checks, exact error strings, and the state before and after. The core implements the checks below, and main maps error codes to the strings shown.

| Method | Check order and errors (JS string) | State after success | Timer |
|---|---|---|---|
| `keys.generate_mnemonic { words }` | — | none | — |
| `vault.create { password, words, user_knows_password }` | `vault_exists` "Vault already exists. Use importVault to replace." → `weak_password` "Password must be at least 8 characters" (counts UTF-16 code units, like JS `length`) | **unlocked**, as today (`identity-manager.js:155`) | starts |
| `vault.import { password, mnemonic, overwrite }` | `invalid_mnemonic` "Invalid mnemonic" → `vault_exists` "Vault already exists. Set overwrite=true to replace." → `weak_password` | **unlocked** (`:191`) | starts |
| `vault.unlock { password }` | `no_vault` "No vault found. Create one first." → `unsupported_vault_version` "Unsupported vault version: N" → `throttled` → `incorrect_password` "Incorrect password" → `corrupt_vault` "Decrypted data is not a valid mnemonic" | unlocked, new epoch | starts |
| `vault.lock` | — | locked, epoch revoked | stops |
| `vault.verify_password { password }` | `no_vault` "No vault found" → `throttled` → `incorrect_password` | **unchanged** (doesn't mutate) | — |
| `vault.change_password { current, new }` | `no_vault` "No vault found. Create one first." → `unsupported_vault_version` → `throttled` → `incorrect_password` → `weak_password` | **lock state unchanged** ⚠ | unchanged ⚠ |
| `vault.delete { password }` | `no_vault` "No vault found. Create one first." → `unsupported_vault_version` → `throttled` → `incorrect_password` | no vault, locked | stops |
| `vault.export_mnemonic { password }` | main: "Password is required to export mnemonic" → `no_vault` "No vault found" → `throttled` → `incorrect_password` → `vault_locked` "Vault is locked" (the password is verified **before** the lock check, as today) | unchanged | — |
| `vault.export_private_key { password, account }` | main: "Password is required to export private key" → main's device and record guards ("This account has no exportable private key — the key never leaves its device") → `no_vault` "No vault found" → `throttled` → `incorrect_password` → `vault_locked` | unchanged | — |

⚠ **Intentional changes, need your OK:**
1. **The password-change timer.** JS `changePassword` calls `unlockVault(…, 0)` (`vault.js:204`). After a password change, the vault is therefore unlocked **with no auto-lock timer**, even if it was locked before, and main's derived-key cache stays empty. The core leaves the lock state and timer as they were.
2. **The lock event.** `vault.locked` is a new internal event. Main uses it to update its own state. The renderer keeps polling `identity:get-status` as it does today, so there is no new renderer event in Phase 1.

**Other parity rules:**
- **Mnemonic acceptance is exactly `@scure/bip39`'s.** It normalizes to NFKD, splits on single spaces, uses the case-sensitive English list and checks the checksum. The phrase is stored exactly as given.
- **`keys.generate_mnemonic`** takes `words: 12 | 24`. Main maps the JS `strength` argument (128 → 12, 256 → 24), with 256 as the default, as in `derivation.js:40`.
- **Vault passwords are raw UTF-8,** with no normalization, so NFC and NFD forms are different passwords.
- **Vault reading accepts both KDF settings:** `keyMetadata` with any iteration count, and a missing `keyMetadata`, which means the legacy 10,000 iterations.
- **Vault writing reproduces the JS envelope** (`{ version: 1, encrypted, createdAt }`, 2-space JSON, no trailing newline) with 900,000 iterations. `vectors/fixtures/vaults.json` is the reference in both directions.
- **Behavior that stays in main** for the vault and keys:
  - `identity:get-vault-meta`;
  - the composition of `identity:get-status` and `identity:inject-all` results;
  - the IPFS ephemeral-mode fields;
  - the wallet-record guards (see below).

## Phase 1 API

| Method | Params → result | Notes |
|---|---|---|
| `core.hello`, `core.shutdown` | see above | not reachable from any renderer channel |
| `vault.status` | → `{ exists, unlocked, epoch, fingerprint }` | |
| `keys.generate_mnemonic`, `keys.validate_mnemonic` | see parity table | |
| `vault.create`, `vault.import`, `vault.unlock`, `vault.lock`, `vault.verify_password`, `vault.change_password`, `vault.delete` | see parity table | create, import and unlock return `addresses` |
| `vault.touch` | → `{}` | restarts the auto-lock timer if unlocked |
| `vault.export_mnemonic`, `vault.export_private_key` | see parity table | permanent, user-requested backup exports |
| `keys.addresses` | `{ accounts?: [u32], publishers?: [u32] }` → `{ user_wallets, bee_wallet, publishers, radicle: { public_key, did, node_id } }` | public data only; needs an unlocked vault |
| `keys.radicle_did` | `{ public_key }` → `{ did }` | public conversion; works while locked (`readRadicleDid`, `identity-manager.js:381`) |
| `nodes.write_identity` | `{ node: "bee" \| "radicle", dir, alias? }` → `{ address \| did }` | multi-file protocol; Bee generates a fresh keystore password, as today |
| `nodes.identity_status` | `{ node, dir }` → `{ consistent, address \| did }` | recovery check after a lost reply |
| `compat.private_key` | `{ account }` → `{ private_key }` | temporary; see Migration |
| `compat.bee_wallet_key` | → `{ private_key }` | temporary |
| `compat.publisher_key` | `{ origin_index }` → `{ private_key }` | temporary |

**Events from the core:** `vault.locked { reason: "manual" | "auto" | "delete" | "shutdown", epoch }` and `vault.unlocked { epoch }`.

### Input validation

Main validates every renderer-supplied argument before it dispatches anything:

| Argument | Limit |
|---|---|
| Passwords | ≤ 1,024 UTF-8 bytes |
| Mnemonics | ≤ 1,024 bytes |
| Aliases | ≤ 64 bytes |
| Indices | integers in `[0, 2^31)` |

- **Out-of-range input** gets the existing JS error string locally and never reaches the core.
- **Defense in depth:** the core applies the same limits and answers `invalid_argument`. A field over its limit is never a protocol error.
- **Renderer access:** `core.hello`, `core.shutdown`, `cancel` and `compat.*` aren't reachable from any renderer channel. Only main-internal adapters call them.

## Migration in freedom-browser

New code goes in `src/main/core/`:

- `core-process.js`: spawn, handshake, restart and generations, log forwarding.
- `core-client.js`: framing, the pending-request map, deadlines, events, reconciliation, error-code-to-string mapping.
- `vault-backend.js`: the single module that every vault and key consumer imports.

**Every direct consumer of the JS identity stack moves to `vault-backend.js`.** A lint rule (or test) forbids importing `identity/vault`, `identity/derivation` or `identity/formats` anywhere else.

| Consumer | Today | Phase 1 route |
|---|---|---|
| `identity-manager.js` create, import, unlock, lock, status, change-password, delete, generate, validate | JS vault plus `derivedKeys` | `vault.*`, `keys.*` |
| `identity-manager.js:263` publisher key; `swarm-provider-ipc.js:1046`, `feed-store.js:549` | `getPublisherKey` | `compat.publisher_key` for signing; `keys.addresses` for owner lookups |
| `swarm-provider-ipc.js:1035`, `feed-store.js:534` (Bee identity) | `getDerivedKeys().beeWallet` | `compat.bee_wallet_key` for signing; `keys.addresses` for owner lookups |
| `swarm-provider-ipc.js:1050` (`ethereum-wallet` identity), `identity-manager.js:281` | `getUserWalletKey` | `compat.private_key`. JS keeps the "existing mnemonic wallet record required" guard |
| `wallet/vault-access.js` → `signers.js`, `x402/client.js`, `wallet-ipc.js`, Safe executor | `exportPrivateKey(walletIndex)` | `compat.private_key`. JS keeps the hardware-range and record-type guards at the adapter entry; Ledger, remote and Safe never touch the core |
| `identity-manager.js:554`, `:630`, `:671` node injection | `injection.js` with `derivedKeys` | `nodes.write_identity` (Bee, Radicle). IPFS stays ephemeral, as today |
| `identity-manager.js:719`, `:751` Radicle DID for status | full key derivation | `keys.addresses` / `keys.radicle_did` |
| `identity-manager.js:987`, `:1216`, `:1407` wallet list, create, active address | `deriveUserWallet` | `keys.addresses` for mnemonic records. Stored addresses keep serving locked and device accounts |
| `identity-manager.js:1547`, `:1563`, `quick-unlock.js:256`, `:276` exports | `verifyPassword` plus `exportMnemonic` / `exportPrivateKey` | `vault.export_*`. The Touch ID path unseals the password, then unlocks and exports, as today |
| `quick-unlock.js:111`, `:174`, `:218` password checks | `vault.verifyPassword` in main | `vault.verify_password` (shares the throttle). The credential binding keeps reading the vault file's hash in main, which is public |
| `vault-timer.js`, Swarm reset points (`swarm-provider-ipc.js:374`–`:420`), `vault-access.js:82` | JS `resetAutoLockTimer` | `vault.touch`, sent without waiting for a reply. Same rule as today: only after a successful operation |

**Steps.** Each is one freedom-browser PR, landing after the matching freedom-core release.

1. **Skeleton (dev builds only).** Main spawns the core, does the handshake and supervises it. No behavior changes. This proves packaging, signing and supervision on all three OSes.
2. **The whole Phase 1 slice in one PR:**
   - every consumer in the table moves to `vault-backend.js`;
   - `derivedKeys` and the JS lock state are deleted;
   - Bee and Radicle injection moves to `nodes.write_identity`.

   This PR has to pass the e2e suite, the migration suite and both onboarding flows (password and Quick Setup) on macOS, Windows and Linux, using the real binary.
3. **Delete** `src/main/identity/{vault,derivation,formats,injection}.js`. `vectors/` keeps checking that nothing drifted.

**Phase 2 removes `compat.*`:**
- A core signer backend replaces the vault backend in `wallet/signers.js`.
- `fc-swarm` takes over SOC and feed signing for all three identity modes.
- Removal order:
  1. `compat.bee_wallet_key` and `compat.publisher_key` go once Swarm signing has moved.
  2. `compat.private_key` goes only after **both** EVM signing and Swarm's `ethereum-wallet` mode have moved.
- Each removal PR includes a check that no call sites are left.

### Rollback

- **No runtime switch in packaged builds.** `FREEDOM_CORE=0` exists only when `!app.isPackaged`. A runtime switch would mean a release in which two writers, the JS vault and the core, share one identity directory without sharing the lock.
- **Rollback is a hotfix release** that reverts step 2. That's safe because the JS reads everything the core writes. `vectors/` checks vault files and Bee keystores written by Rust against the pinned JS, in CI, on every change.

### Quick unlock

Quick unlock stays in the shell for Phase 1:
1. Main does the Touch ID prompt.
2. It unseals the password with `safeStorage`.
3. It sends the password to `vault.unlock` or `vault.verify_password`.

The password crosses the pipe, which is no worse than today, where it is used in main directly. Phase 5 re-wraps it into the OS keychain with biometric access control, and the core then uses it directly. That is also the long-term fix for Quick Setup users, whose only copy of the password is the `safeStorage` blob. **That blob must stay valid until the re-wrap exists.** So the core never rewrites the vault on read (see [Reconciliation](#reconciliation)).

## Crates

| Crate | Kind | Contents |
|---|---|---|
| `fc-keys` | logic | BIP-39 (`@scure/bip39` rules), BIP-32 on `k256` (every intermediate secret zeroized), SLIP-10 Ed25519, the path registry. Encoders: EIP-55, Web3 keystore v3 (scrypt; password NFKC, as ethers does), OpenSSH v1 with an injectable check integer, did:key. The IPFS encoder is kept for the vectors only. |
| `fc-vault` | logic | The passworder v6 format (PBKDF2-SHA-256, iterations from `keyMetadata` or the legacy 10,000; AES-256-GCM, 16-byte IV, 32-byte salt), the vault envelope, the lock state machine with epochs, the throttle policy. Everything is a pure function of (state, event, now), returning the bytes to write. |
| `fc-protocol` | logic | Message types, error codes, the method table, a sans-I/O frame codec, schema generation, secret-aware field types. |
| `freedom-cored` | binary | Stdio transport and writer, control path, vault task, KDF pool, timers, durable writes, the multi-file protocol, the lifetime lock, logging, process hardening, and the `probe-lock` subcommand. |

## Secrets in memory

- **Types:**
  - Inside the core, the mnemonic, seed, private keys, passwords and derived AES keys live only in `Zeroizing` or `secrecy` types.
  - Those types implement no `Debug`, `Display`, `Serialize` or `Clone`.
- **Wire boundary:**
  - Secret fields are decoded straight into `Zeroizing<String>` by a custom deserializer, never through `serde_json::Value`.
  - Raw frame buffers and response buffers are wiped once decoded or written.
  - The only outgoing secrets are the export and `compat` results, serialized by one audited function.
- **Logging:** log lines carry the method name, request ID, duration and error code. They never include a request or response body, and the core has no body-bearing diagnostics.
- **Process hardening:**
  - **Linux:** `PR_SET_DUMPABLE=0`.
  - **macOS:** `RLIMIT_CORE=0` plus the hardened runtime.
  - Both go through `rustix`'s safe wrappers.
- **What isn't guaranteed:** the core can't wipe copies in main. Passwords and mnemonics pass through JS strings, and `compat` keys through ethers objects. Phase 1 stops main from keeping them resident, and Phase 2 removes the key copies.
- **`mlock` is deferred.** If added, it lives in `freedom-cored` only, under a documented exception to the `unsafe_code` lint.

## Packaging and release

- **freedom-core release workflow,** on tag `cored-vX.Y.Z`:
  - builds `freedom-cored` for `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64` and `win-x64`, on native runners per OS, with `--locked`;
  - publishes `SHA256SUMS` and build-provenance attestations.
- **freedom-browser:**
  - `scripts/freedom-cored-release.json` pins the version and a SHA-256 per target, like `myotis-release.json`;
  - `npm run cored:download` fetches and verifies the binary, and `extraResources` ships it;
  - on macOS it goes through `mac.binaries`, signed with the hardened runtime and an empty entitlements plist;
  - Windows stays unsigned until the app itself is;
  - Rust is never compiled inside freedom-browser's `release.yml`.
- **Development:** `FREEDOM_CORED_PATH=…/target/debug/freedom-cored npm start`, honored only in dev builds.

## Testing

- **Logic crates:**
  - `vectors/` as the oracle;
  - `proptest` round trips;
  - `cargo-fuzz` targets for the vault parser, the frame codec, the message decoder and secret-field decoding.
- **Cross-implementation,** in CI on every change: vaults and Bee keystores written by Rust must decrypt in the pinned JS, and OpenSSH files must parse.
- **`freedom-cored` integration tests,** run against the real binary:
  - **Protocol:** the handshake and its timeout, every method, every error code in parity-table order, a protocol error per malformed frame, oversized fields rejected with `invalid_argument`.
  - **Epochs:** lock during an unlock's KDF (the secrets must not come back), auto-lock during a node write.
  - **Deadlines and limits:** a deadline while queued, during the KDF, at commit and while replying; throttle reservation under concurrent guesses.
  - **Crashes:** killed at every commit point of every mutation and node write, each followed by reconciliation and roll-forward.
  - **Lifetime lock:** two processes on one directory, `probe-lock`, an unsupported filesystem, EOF mid-frame, parent death.
- **freedom-browser:**
  - Jest tests for the client against a fake core, including generations, late responses and reconciliation;
  - the proxy contract test against `protocol/schema.json`;
  - the forbidden-import lint;
  - the parity tests from the table;
  - device and deleted-index guards;
  - e2e and migration suites on all three OSes with the real binary before step 2 merges.

## Open questions

1. **Hardware-wallet, phone and Safe accounts:** their records stay in `vault-meta.json`, owned by JS until Phase 5, and they keep working while the vault is locked. Is that acceptable? I think so.
2. **Should `keys.generate_mnemonic` keep the phrase in the core** and hand back a handle? The phrase would then reach the renderer only for display, but it changes the onboarding IPC shapes. Proposed: not in Phase 1.
3. **Windows:** code signing, and an owner-only DACL for secret files. Tracked in #644's decisions.
