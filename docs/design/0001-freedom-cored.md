# 0001: `freedom-cored`, the desktop core process

**Status:** draft, for review. **Scope:** Phase 1 of [freedom-browser#644](https://github.com/solardev-xyz/freedom-browser/issues/644), plus the protocol that Phases 2–5 build on.

## Summary

- **One `freedom-cored` process per Freedom profile.** The profile's Electron main process spawns it. It owns the identity vault, the seed, key derivation, the lock state and, from Phase 2, signing.
- **Transport:** the child's stdin and stdout, carrying length-prefixed frames. Only the parent holds the pipe, so there is no socket, port or token to protect.
- **Messages:** JSON requests, responses and events in both directions, defined as Rust types in `fc-protocol`. A version handshake comes first, and every request carries a caller context attested by main.
- **Lifetime lock:** the core holds an OS file lock in the identity directory for as long as it runs. A new core can't start until the old one has really exited. This replaces the Myotis receipt machinery, which the core doesn't need: it's our own binary, and every write it makes is crash-safe.
- **Phase 1 moves the vault and key derivation into the core, behind the existing IPC channel names.** The mnemonic stops living in main. Signing stays in JS for now, through a temporary, enumerated `compat.*` API that hands main a single derived key per operation. Phase 2 deletes that API method by method, ending with **no raw key leaving the core**.
- **Fixes in the first slice:**
  - K-1, by design: one lock state wipes everything.
  - K-2: atomic writes with mode `0600`.
  - K-4: unlock throttling.
  - Node key files get `0600` permissions, which partly addresses K-3.

**Needs your OK:** the temporary `compat.*` key exports ([Migration](#migration-in-freedom-browser)), and keeping Touch ID quick unlock in the shell until Phase 5 ([Quick unlock](#quick-unlock)).

## Goals and non-goals

**Goals**

- Move the vault, seed and derivation out of Electron main without changing a single user-visible behavior or file format.
- Build the process, protocol, packaging and release path once, so Phases 2–5 only add methods.
- Keep the logic crates free of I/O, so mobile and a later Chromium build can reuse them.

**Non-goals for Phase 1**

- Signing in Rust (Phase 2).
- Naming (Phase 3), transports (Phase 4), profiles and stores (Phase 5).
- Changing the vault format, the derivation paths or the UI.
- Mobile bindings.

## Threat model

Stage 1 trusts Electron main: it holds the pipe, attests callers, and runs the approval UI. So the core does not defend against a compromised main. A compromised main can ask the core to sign anything, and during Phase 1 it can call `compat.*`.

**What the core does protect against:**

| Threat | Today | With the core |
|---|---|---|
| A compromised renderer reaching the master secret | Main's sender checks (E-1) | The same checks, and the mnemonic isn't in main to begin with |
| Main bugs keeping or spilling keys (K-1 class) | Derived keys cached in main's heap until an explicit lock | One lock state in one process. A lock wipes all secrets, and main holds a key only for the duration of one operation (Phase 1), then never (Phase 2) |
| Torn or world-readable secret files (K-2, K-3) | `writeFileSync`, umask permissions | Temp file, fsync, rename, `0600`, in one module |
| Password guessing through `identity:unlock` (K-4) | Unthrottled | Throttled in the core |
| Another process on the same account reading key memory | Main is a large, unhardened process | macOS: the hardened runtime blocks `task_for_pid` without an entitlement. Linux: the core marks itself non-dumpable. Windows: no change |

**Not covered:** malware with root or admin rights, a compromised OS, a compromised main, and physical attacks on unlocked memory. `mlock` is deferred (see [Secrets in memory](#secrets-in-memory)).

## Process model

```
Electron main (profile P) ──spawn──▶ freedom-cored --data-dir <identityDir> --parent-pid <pid>
     stdin  ──frames──▶
     stdout ◀──frames──
     stderr ◀──JSON log lines── (forwarded to main's log)
```

- **One core per profile.** Freedom already runs one app process per profile (`--profile=<id>`), so each process spawns one core for its own `identity` directory (`getIdentityDataDir()`).
- **Spawn:**
  - The binary comes from the app's resources, or from `FREEDOM_CORED_PATH` in dev builds only.
  - Its environment is cleared except for `PATH`, `HOME`/`USERPROFILE`, `LANG` and `RUST_LOG`.
  - stdin and stdout are pipes; stderr is a pipe read line by line.
  - Main spawns it at startup, before any identity IPC is served. Startup costs a few milliseconds and no secrets are touched until unlock, so there is no reason to start it lazily.
- **Lifetime lock:**
  1. On start, the core opens `<identityDir>/freedom-cored.lock` and takes an exclusive lock (`std::fs::File::try_lock`, stable since Rust 1.89).
  2. If the lock is held, it retries for up to 5 s, then exits with status 75 (`lock_held`).
  3. The OS releases the lock on any exit, crashes included.

  So "the old core has exited" is a property the OS proves. Main never needs a PID or a receipt to decide whether a new core may touch the vault.
- **Shutdown:**
  1. Main sends `core.shutdown` and then closes stdin.
  2. The core finishes in-flight writes, wipes its secrets and exits 0.
  3. After 3 s, main kills it.

  Killing is safe because every write the core makes is atomic.
- **Parent death:** the core exits whenever stdin reaches EOF, which also happens when main crashes. As a backstop for a stdin held open by a stray inherited handle, it also polls whether `--parent-pid` is still alive every 2 s.
- **Crash handling in main:**
  - All pending requests are rejected with `core_unavailable`.
  - The vault counts as locked. Main emits the same lock event the UI gets today, so the user just unlocks again.
  - Main restarts the core after 0.5 s, 2 s, then 10 s.
  - Three crashes within 60 s stop the restarts and show an error with **Restart core**.
- **Outcome uncertainty:**
  - Vault writes are all-or-nothing on disk. After a crash during `vault.change_password` or `vault.import`, main calls `vault.status` before telling the user anything, and reports whichever of the two states it finds.
  - Signing has no external effect until main broadcasts, so a lost signing reply is simply a failure.

## Transport and framing

- **Frame:** `u32` big-endian length of the rest, then a `u8` kind, then the payload.

  | Kind | Payload | Limit |
  |---|---|---|
  | `0x01` | One JSON message (UTF-8) | 1 MiB |
  | `0x02`–`0x0F` | Reserved for Phase 4 streams (binary body chunks with credit-based backpressure) | — |

  An unknown kind, an oversized frame or invalid JSON is a protocol error. The receiver logs it and closes the connection. Main then restarts the core, and the core exits. There is no attempt to resync a corrupted stream.
- **Why not newline-delimited JSON:** Phase 4 streams binary bodies, which need length prefixes anyway. One framing from day one avoids a second protocol.
- **Why not a socket:** an anonymous pipe has no name to connect to, so no other process can reach the core, and there is no token to leak. In Stage 2, the Chromium browser process spawns the core the same way.

## Messages

All messages are JSON objects with a `type` field.

```jsonc
// request (either direction)
{ "type": "request", "id": 7, "method": "vault.unlock",
  "params": { "password": "…" }, "context": { "caller": "chrome" }, "deadline_ms": 15000 }
// response
{ "type": "response", "id": 7, "result": { … } }
{ "type": "response", "id": 7, "error": { "code": "incorrect_password", "message": "Incorrect password" } }
// event (either direction, no reply)
{ "type": "event", "event": "vault.locked", "data": { "reason": "auto" } }
// cancel (best effort; the response still arrives, with error.code "cancelled" if it took effect)
{ "type": "cancel", "id": 7 }
```

- **IDs** are `u64` counters, one per sender. A side only ever receives responses to its own requests, so the two ID spaces can't collide.
- **Handshake:**
  - The first message must be main's `core.hello` request: `{ protocol: 1, shell_version, auto_lock_ms }`.
  - The core answers `{ protocol: 1, core_version, capabilities: [...] }`, or `protocol_mismatch`.
  - Main and core ship pinned together, so a mismatch is a packaging bug. Main fails loudly instead of degrading.
- **Caller context:**
  - Main fills `context` from the IPC event it is proxying, never from renderer-supplied values: `"chrome"` for the browser UI, or `{ "page": { "origin", "top_origin", "frame", "web_contents", "navigation" } }` for web content (Phase 2 provider calls).
  - Every method declares which callers it accepts. The core rejects anything else with `forbidden`. This is defense in depth behind main's own sender checks.
  - All Phase 1 methods are chrome-only.
- **Deadlines and limits:**
  - **Deadlines:** a request may carry `deadline_ms`; otherwise a per-method default applies. Unlock and password changes allow 15 s, because PBKDF2 at 900k iterations takes about 0.5–1 s.
  - **Concurrency:** the core runs requests concurrently, but vault mutations are serialized through one vault task.
  - **Queue bound:** at most 64 requests in flight; beyond that, `busy`.
- **Errors:** an error carries a stable `code`, a human-readable `message`, and optional `data`.

  | Code | Meaning | Message main maps it to (unchanged UI) |
  |---|---|---|
  | `vault_locked` | Operation needs an unlocked vault | `Vault is locked` (`VAULT_LOCKED_MESSAGE`) |
  | `incorrect_password` | Decryption failed | `Incorrect password` |
  | `throttled` | Too many failures; `data.retry_after_ms` | new UI string |
  | `no_vault` / `vault_exists` | Wrong state for create, import or unlock | today's strings |
  | `invalid_mnemonic` / `invalid_argument` / `weak_password` | Input validation | today's strings |
  | `storage` | File I/O failed; `data.kind` (`not_found`, `permission`, `no_space`, `other`) | `Storage error: …` |
  | `forbidden` / `busy` / `cancelled` / `deadline` | Protocol-level | — |
  | `internal` | A bug; logged with the request ID | `Internal error` |

  Main maps codes back to today's exact strings, so the renderer, the x402 unlock-resume flow (`isVaultLockedError`) and the e2e suite keep working unchanged.
- **Schema:**
  - `fc-protocol` defines every method's params, result and errors as Rust types, plus a method table (name, allowed callers, default deadline).
  - CI generates `protocol/schema.json` from it and fails if the committed copy differs.
  - freedom-browser's contract test checks its proxy table against that file: every method it calls exists, and every method it exposes is chrome-only where the schema says so.

## Phase 1 API

| Method | Params → result | Replaces |
|---|---|---|
| `core.hello` | see above | — |
| `core.shutdown` | → `{}` | — |
| `vault.status` | → `{ exists, unlocked, auto_lock_ms }` | `identity:has-vault`, `identity:is-unlocked`, `isUnlocked()` |
| `keys.generate_mnemonic` | `{ words: 12 \| 24 }` → `{ mnemonic }` | `identity:generate-mnemonic` |
| `keys.validate_mnemonic` | `{ mnemonic }` → `{ valid }` | `identity:validate-mnemonic` |
| `vault.create` | `{ password, words }` → `{ mnemonic, addresses }` | `createNewVault` |
| `vault.import` | `{ password, mnemonic, overwrite }` → `{ addresses }` | `importExistingMnemonic` |
| `vault.unlock` | `{ password }` → `{ addresses }` | `identity:unlock`, quick-unlock's unlock |
| `vault.lock` | → `{}` | `identity:lock` |
| `vault.touch` | → `{}` | `resetVaultAutoLockTimer()` |
| `vault.verify_password` | `{ password }` → `{}` | `verifyPassword` (export gates) |
| `vault.change_password` | `{ current, new }` → `{}` | `identity:change-password` |
| `vault.delete` | `{ password }` → `{}` | `identity:delete-vault` |
| `vault.export_mnemonic` | `{ password }` → `{ mnemonic }` | `identity:export-mnemonic`, quick-unlock's export |
| `vault.export_private_key` | `{ password, account }` → `{ private_key }` | `identity:export-private-key` |
| `keys.addresses` | `{ accounts?: [u32], publishers?: [u32] }` → `{ user_wallets, bee_wallet, publishers, radicle: { public_key, did, node_id }, ipfs: { public_key, peer_id } }` | the address parts of `deriveAllKeys`, `deriveUserWallet`, `getIdentityStatus` |
| `nodes.write_identity` | `{ node: "bee" \| "ipfs" \| "radicle", dir, options }` → `{ address \| peer_id \| did }` | `injection.js` (writes key files itself; see below) |
| `compat.private_key` | `{ account }` → `{ private_key }` | `withVaultPrivateKey` (temporary) |
| `compat.bee_wallet_key` | → `{ private_key }` | `getDerivedKeys().beeWallet` in Swarm signing (temporary) |
| `compat.publisher_key` | `{ origin_index }` → `{ private_key }` | `getPublisherKey` (temporary) |

**Events from the core:** `vault.locked { reason: "manual" | "auto" | "delete" }` and `vault.unlocked`.

**Notes on these methods:**

- **Exports and onboarding:**
  - Both exports require the vault to be unlocked **and** the password, as today. The Touch ID path already has the password, which it unseals before calling.
  - Onboarding still shows the mnemonic in the renderer, as today, because the user must see it to back it up.
- **`vault-meta.json` stays in JS for Phase 1.** It holds public addresses, the wallet list, hardware-wallet records and `userKnowsPassword`. The core returns the addresses that main writes there today, and Phase 5 moves the store.
- **`nodes.write_identity`** writes every file atomically with mode `0600`:
  - **Bee:** the keystore plus `config.yaml`. The keystore password still sits in `config.yaml`, so K-3 isn't fixed until Phase 5 gives `antd` a better channel; `0600` is what changes now.
  - **IPFS:** read-modify-write of `Identity.PrivKey` and `PeerID`.
  - **Radicle:** the OpenSSH key pair.

  Main still owns stopping and starting the nodes around the write.
- **Auto-lock:**
  - The timer lives in the core and starts at unlock. Its length comes from `core.hello` (`auto_lock_ms`); today that is a fixed 15 minutes, with no user setting.
  - `vault.touch` restarts it. Main calls it wherever `resetVaultAutoLockTimer()` is called today.
  - Expiry wipes the mnemonic, the seed, every derived key and every cache, then emits `vault.locked`.
- **Throttling:**
  - It applies to failed `unlock`, `verify_password`, `change_password`, `delete` and `export_*` attempts, with one counter shared across them.
  - The first 5 failures are free; after that the delay is 2^(n−5) s, capped at 5 min, and a success resets the counter.
  - The counter lives only in memory. A main that can restart the core can also reset it, and main is trusted in Stage 1.

## Migration in freedom-browser

New code goes in `src/main/core/`:

- `core-process.js`: spawn, handshake, restart policy, stderr log forwarding.
- `core-client.js`: framing, request and response bookkeeping, deadlines, events, mapping error codes back to today's error strings.
- `proxies.js`: the existing `identity:*` handlers re-pointed at the core. The channel names and renderer-visible shapes stay unchanged, because the e2e suite stubs `ipcMain` by channel name.

**Steps**, each one PR in freedom-browser. Each lands only after the corresponding freedom-core release.

1. **Skeleton.** Main spawns the core and does the handshake, behind the `FREEDOM_CORE=1` environment variable. The core does nothing yet. This proves packaging, signing and process supervision on all three OSes.
2. **Vault and keys.**
   - `identity-manager.js` calls the core for every vault and derivation operation.
   - `derivedKeys` and the JS lock state go away.
   - `withVaultPrivateKey` uses `compat.private_key`, and Swarm signing uses `compat.bee_wallet_key` and `compat.publisher_key`.
   - Quick unlock passes the password it unsealed to `vault.unlock`, as today.
3. **Node identities** via `nodes.write_identity`; `injection.js` is deleted.
4. **Default on.** The JS path stays available for one release behind `FREEDOM_CORE=0`. In the following release, `src/main/identity/{vault,derivation,formats,injection}.js` are deleted. `vectors/` keeps checking that nothing drifted.

**Phase 2 removes `compat.*`:**

1. A core signer backend (`signTransaction`, `signMessage`, `signTypedData`) joins the vault, Ledger and remote backends in `wallet/signers.js`. `compat.private_key` is deleted.
2. SOC and feed signing move to `fc-swarm`. `compat.bee_wallet_key` and `compat.publisher_key` are deleted.
3. A test in freedom-browser fails if any `compat.*` call site exists. Phase 2 is done when the core's method table has no `compat` namespace left.

**Quick unlock:** stays in the shell for Phase 1. Main does the Touch ID prompt, unseals the password with `safeStorage`, and sends it to `vault.unlock`. The password crosses the pipe, which is no worse than today, where it is used in main directly. Phase 5 re-wraps it into the OS keychain with biometric access control, which the core uses directly. That is also the fix for Quick Setup users, whose only copy of the password is the `safeStorage` blob. **That blob must never be invalidated before the re-wrap exists.**

## Crates

| Crate | Kind | Contents |
|---|---|---|
| `fc-keys` | logic | Mnemonic (BIP-39, English), seed, BIP-32 on `k256`, SLIP-10 Ed25519, the path registry (`m/44'/60'/i'/0/0`, `m/44'/60'/0'/0/1`, `m/44'/73404'/0'/0'/0'`, `m/44'/73405'/0'/0'/0'`, `m/44'/73406'/i'/0/0`), encoders: EIP-55 address, Web3 keystore v3 (scrypt), IPFS `PrivKey`/PeerID, OpenSSH v1 private and public, did:key. Randomness is passed in (`rand_core::CryptoRngCore`). |
| `fc-vault` | logic | The passworder v6 format (PBKDF2-SHA-256 with the iteration count from `keyMetadata`, AES-256-GCM, base64 fields), the `identity-vault.json` envelope, a lock state machine and throttle policy as pure functions of (state, event, now). It returns the bytes to write and never writes them. |
| `fc-protocol` | logic | Message types, error codes, the method table, a sans-I/O frame codec, schema generation. |
| `freedom-cored` | binary | Stdio transport, dispatcher, vault task, timers, atomic file writes, lifetime lock, logging, process hardening. The only crate allowed to do I/O. Uses a `tokio` current-thread runtime, with `spawn_blocking` for the KDF. |

Each logic crate must reproduce `vectors/` exactly. In the other direction, vaults and keystores written by Rust must open in the JS reference. A test in `vectors/generator` runs that check against the pinned freedom-browser commit.

## Secrets in memory

- **Secret types:**
  - The mnemonic, seed, private keys, password buffers and derived AES keys are wrapped in `secrecy::SecretBox` or `Zeroizing`.
  - They have no `Debug`, `Display`, `Serialize` or `Clone`.
  - They are wiped on lock and on drop.
- **Request logging:** request and response bodies of secret-bearing methods are never logged. Log lines carry the method name, request ID, duration and error code only.
- **Process hardening at startup:**
  - **Linux:** `PR_SET_DUMPABLE=0`. That disables core dumps, and same-user processes without `CAP_SYS_PTRACE` can no longer attach with `ptrace` or read `/proc/<pid>/mem`.
  - **macOS:** `RLIMIT_CORE=0`, plus the hardened runtime from code signing.
  - These calls go through `rustix`'s safe wrappers.
- **`mlock` is deferred.** It needs `unsafe` and gives limited protection on desktop OSes. If added later, it lives in `freedom-cored` only, under a documented exception to the `unsafe_code` lint. Logic crates keep `forbid`.

## Packaging and release

- **freedom-core release workflow,** on tag `cored-vX.Y.Z`:
  - **Builds:** `freedom-cored` for `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64` and `win-x64` (the same matrix Freedom ships).
  - **Builders:** native runners per OS, `--locked`, with the toolchain from `rust-toolchain.toml`.
  - **Assets:** `SHA256SUMS` and build-provenance attestations, attached to a GitHub release.
- **freedom-browser:**
  - `scripts/freedom-cored-release.json` pins the version plus a SHA-256 per target, following the `myotis-release.json` pattern.
  - `npm run cored:download` fetches and verifies the binary.
  - electron-builder ships it in `extraResources`.
  - On macOS it goes through `mac.binaries`, signed with the hardened runtime and an empty entitlements plist (no JIT, no `get-task-allow`).
  - Windows stays unsigned until the app itself is.
  - Rust is never compiled inside freedom-browser's `release.yml`.
- **Development:** `FREEDOM_CORED_PATH=/root/herdr/freedom-core/target/debug/freedom-cored npm start`. Release builds ignore the variable.

## Testing

- **Logic crates:**
  - `vectors/` as the oracle;
  - `proptest` round trips (encode/decode, encrypt/decrypt);
  - `cargo-fuzz` targets for the vault JSON parser, the frame codec and the message decoder.
- **Cross-implementation:** the generator's `check` mode, and a Node harness that feeds Rust output (vaults, keystores, OpenSSH files) back into the pinned JS.
- **`freedom-cored`:** integration tests spawn the binary and speak frames. They cover the handshake, every method, every error code, auto-lock with a mocked clock, throttling, the lifetime lock with two processes, EOF shutdown, and a crash during `change_password` (kill between write and rename leaves the old vault intact).
- **freedom-browser:**
  - Jest tests for the client against a fake core;
  - the proxy contract test against `protocol/schema.json`;
  - the existing e2e and migration suites against the real binary, run on all three OSes before step 4 ("default on").

## Open questions

1. **Hardware-wallet and phone accounts** keep their records in `vault-meta.json` and sign outside the vault. They stay entirely in JS until Phase 5. Is that acceptable? (I think so.)
2. **Should `keys.generate_mnemonic` hold the generated mnemonic in the core** and return a handle for `vault.create`, so the phrase crosses into the renderer only for display? It's cleaner, but it changes the onboarding IPC shapes. Proposed: not in Phase 1.
3. **Windows signing.** A new unsigned `.exe` in the bundle is no worse than today, but SmartScreen and antivirus heuristics now see two unsigned binaries. That's tracked in #644's decisions.
