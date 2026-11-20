# 0013: Profiles and Freedom state

**Status:** proposed. Roadmap items 5.1 (profiles in the core), 5.2 (stores), 5.3 (a core for several profiles) and 5.4 (the Stage-2 prerequisites: (a) the key store and the quick-unlock re-wrap, (b) one directory of Freedom data per profile, (c) node keys at rest). Builds on [0001](0001-freedom-cored.md) (the process, the gate, durable writes, quick unlock until Phase 5, Bee's keystore password until Phase 5) and [0010](0010-service-confinement.md) (the protected roots, and D7, confining `freedom-cored`, which waits for this design). It must agree with [0012](0012-approvals.md) (proposed, merged as #264), which owns the four permission files and proposes `phone-payments.json`. It answers 0001's open question 1, on `vault-meta.json`, and proposes an amendment to AGENTS.md rules 3 and 4. Nothing here is built yet. The user decides the [open questions](#open-questions). Amended 2026-11-19 for PRF-5's stores ([Amendments](#amendments)): the coordinator's technical calls, proposed, which the user may veto; what the code leaves open is marked *inferred*.

**The references:**
- **freedom-browser** at `5484f8dd` (`integration/rust-core`), in `src/main/`:
  - profiles: `profile-resolver.js`, `profile-catalog.js`, `profile-paths.js`, `profile-lock.js`, `profile-launcher.js`, `profile-focus-handoff.js`, `profile-instance-handoff.js`, `profile-switch-scheme.js`, `profile-registry-watcher.js`, `profile-external-candidates.js` (about 4.5k lines together), `index.js` (startup), `migrate-user-data.js`, `service-locks.js`, `service-grant.js`, `ipc-handlers.js` (`ensureProfileClosedForDelete`), `ipfs/ipfsd-gate.js`, `core/core-process.js`;
  - quick unlock: `quick-unlock.js`, and the renderer's `src/renderer/lib/onboarding.js` (`performQuickSetup`);
  - the stores listed under [The stores](#the-stores), `identity-manager.js` (`vault-meta.json`), `lib/durable-journal.js`, `ant-manager.js` (`ensureConfig`);
  - RPC API keys: `wallet/rpc-manager.js`, `networks/network-registry.js`, `networks/network-ipc.js`, the chrome's `preload.js`, and the settings page, `src/renderer/pages/scripts/settings.js`.
- **proper-lockfile 4.1.2**, the reference checkout's: `lib/lockfile.js`.
- **`secret-service` 5.2**'s blocking API, which opens a session-bus connection at each `SecretService::connect`.
- **Browser PRs against main:** #943 (K-3 part 1, head `c1cbe568`; `private-files.js`), #945 (K-5, head `eeb6023f`), #946 (K-3 part 2, head `2a260195`; `swarm/ant-keystore-password.js`, `swarm/ant-config-password.js`). SEC-3d (#1029) merges #943 and #945 into integration; SEC-3f adapts #946 after it (the coordinator's decision, Option A of the SEC-2 audit). **Issue #963:** Windows key-file I/O binds to directories by path.
- **For PRF-5's stores, freedom-browser** at `9d4ea625` (`integration/rust-core`), in `src/main/`: `identity-manager.js`, `lib/durable-journal.js`, `wallet/intent-store.js`, `payment-history.js`, `wallet/safe/pending-store.js`, `wallet/rpc-manager.js`, `wallet/rpc-api-key-store.js`, `ipc-sender-policy.js`, `preload.js`, `webview-preload.js` and the IPC handlers that reach the stores; **freedom-core** at `4bff981f`: `serve.rs` (`HelloParams`, `grant_moved`), `vault.rs`, `delete_journal.rs`, `grants.rs`, `.github/workflows/ci.yml`, `release.yml`, `release-ipfsd.yml`, `services/freedom-ipfsd/Cargo.toml`.
- **freedom-core** at `bcc385e9` (`main`): `freedom-cored/src/fsx.rs` (durable writes), `anchor.rs` (handle-relative node files), `nodes.rs` (Bee's `config.yaml`), `exit.rs`, `main.rs` (`hold-lock`), `serve.rs` (`core.hello`), `fc-service/src/gate.rs`, `fc-service/src/confine/`, `fc-seal` (HPKE), `fc-sys`, `fc-protocol/src/lib.rs` (protocol versions) and `message.rs` (`Context`).
- **Design 0012**, proposed, merged into `main` as #264 (`bcc385e9`), and 0010's one-shot Radicle import (D5), the pattern for this design's one-shot processes.
- **Apple's TN3137**, *On Mac keychain APIs and implementations*: the data protection keychain, which biometric access control needs, needs a keychain-access entitlement backed by a provisioning profile.

## Summary

- **Today** each profile is one Electron process. Main picks the profile from argv, the environment and the shared catalog, points `userData` at it (`app.setPath`) before anything else touches storage, and holds a lock directory in it whose mtime it refreshes. Every Freedom store is a JSON, JSONL or SQLite file that main writes itself, most in place.
- **5.1, resolving the profile:** a synchronous subcommand, `freedom-cored profile open`, which main runs with `spawnSync` before `app.setPath`. It applies today's rules and writes the catalog durably. The catalog's other operations are one-shot subcommands too, so the running core never touches the catalog or another profile. Main keeps the argv parsing, the launch and hand-off glue, and the profile lock in today's format, so older builds see an open profile as open. If the subcommand misses its latency budget on any OS, `open` stays in JS, and only the catalog's other operations move.
- **The profile gate:** an OS lock keyed by the profile's `userData`, which a small `hold-profile` process holds for main from before it takes the profile lock until after it lets go. A profile counts as open when its lock is fresh **or** that gate is held, and a delete holds every gate of the profile it removes. That fixes the stale-lease delete, for overridden layouts and for a main that stalls before its core is up too.
- **5.2, the stores ([Q14](#open-questions)):** the core owns the stores that decide or record authority and money: wallet (`vault-meta.json`, the intent journal, pending Safe transactions), permissions (0012's four files and `phone-payments.json`), feeds (0015's), payments, profiles, and the secrets. Each stays in today's format, byte for byte, with 0001's atomic writes. SQLite schemas are kept. Stored RPC API keys reach only the shell, never a renderer. The other Freedom stores stay in main and get durable writes. History, bookmarks and downloads aren't ported. Main hands each store to the core by naming it in `core.hello`'s `store_moved`.
- **5.3, several profiles ([Q15](#open-questions)):** one core per profile while Electron runs one process per profile. The core gains a profile dimension now: per-profile vault, lock state, throttle, gates, stores and secrets, carried in the caller context at a new protocol version, 3, and tested with two profiles over one pipe. The core keeps protocol 2 during the rollout, and `core.hello` settles which one a pair speaks, so the current browser works with the new core and the reverse. One shared core for all profiles comes with Chromium, which has one parent process. The transport stays a pipe in both stages, never a socket.
- **5.4a, the key store ([Q13a, Q13b](#open-questions)):** a `KeyStore` trait in a new logic crate, `fc-keystore`, that makes and keeps 32-byte wrapping keys under one of two policies, `Unattended` or `UserPresence`. Every secret is AES-256-GCM under such a key in one file per profile. Backends: the macOS Keychain (`security-framework`), Windows DPAPI (through `fc-sys`), the Secret Service on Linux (`secret-service`), and Android Keystore and the iOS Keychain through `freedom-mobile-ffi`. On desktop every key-store call runs in a one-shot helper, `freedom-cored keystore`, that main starts for it, so `serve` never connects to a key-store service, before or after it confines itself. An item stays named in a file until its `forget` succeeds: the profile's secrets file, or, after a profile delete, a forget file beside the catalog.
- **The quick-unlock re-wrap comes early (PRF-1, PRF-2).** PRF-2 ships once profile deletes go through the core (PRF-4), so a deleted profile's items are always recorded. At the next Touch ID use, main hands the password it unsealed to the core once. From then on the core holds it, and Quick Setup writes it together with the vault. Once the core confirms it holds the credential, main deletes today's `quick-unlock.dat` (the user's decision of 2026-11-15). After that, an older build asks for the password. Biometric binding in the OS waits for a signing spike, and Touch ID stays main's prompt until then.
- **5.4b, the Freedom directory ([Q12](#open-questions)):** every Freedom-owned entry of a profile moves into `<profile>/freedom/`, and the shell's data stays at the root. A reader release, which reads both layouts and finishes a move it finds, ships first. The move ships late, as the last Stage-1 step. It is one rename per entry (a copy only across devices), journaled, rolled back before its marker and forward after. It runs before main takes its own lock, and holds the profile lock itself in today's format, refreshed from its own thread, so older builds see the profile open however long it takes. Builds older than the reader can't open the moved identity, by design.
- **5.4c, Bee's keystore password ([Q16](#open-questions)):** the core keeps it in the profile's secrets file and writes antd's one-use `--password-file` itself. It reads #946's seals as migration input: main opens the ciphertext, and the core checks it against the keystore. `config.yaml` keeps the password only where the OS has no key store. AGENTS.md rules 3 and 4 change to match. `fc-sys` gains Windows handle-relative file calls, which closes #963 for every file the core writes.
- **`vault-meta.json`** becomes the core's: in place, in today's format, written with the vault as one journaled operation where both change. Device, phone and Safe records stay in it and keep working while the vault is locked (0001's open question 1).
- **0010 and D7:** the protected roots gain `freedom/`'s entries. D7 can confine `serve` to the profile's directory as soon as it is designed, and narrow it to `freedom/` after the move. Before the move that separates a named profile from the others, but not the packaged default profile, whose directory is the app root; after it, both. The catalog and other profiles are the subcommands' work, never `serve`'s. `serve` makes no network connection, and its only local IPC is main's pipe.
- **Facts found:** a stale-looking lock is trusted for deletion; deletion holds only the IPFS gate; on macOS and Windows, deleting the packaged default profile removes the shared lock directory; and the chrome renderer's preload could fetch the RPC pool with the API keys in its URLs (since removed on integration).

## Goals and non-goals

**Goals**
- **One implementation** of the profile rules and of the stores that guard keys and money, in crates that Stage 2 and mobile reuse, proved by vectors from the JS reference (AGENTS.md rule 5).
- **No torn store:** every Freedom store survives a crash at any point of a write.
- **No secret beside what it protects** wherever the OS has a key store.
- **Quick Setup users keep access** across a shell change.
- **One shell-neutral directory of Freedom data per profile,** for Stage 2's importer and for D7.
- **Older builds keep working** at every step before the move, and through the move for every build from the reader release on.

**Non-goals**
- **History, bookmarks, downloads and favicons.** Chromium provides them in Stage 2 (#644's roadmap). Their files stay with the shell's data.
- **Chromium's site data** (cookies, Local Storage, IndexedDB) and its Stage-2 importer.
- **The agent's stores** (`agent-*.sqlite`, `agent/`), which move with the agent's own design (6.2).
- **The semantics of the grant stores** (0012) and of the Swarm stores (0015). 0013 decides who writes them, where they live, and how.
- **A compromised main.** Stage 1 trusts it (0001).
- **Windows Hello and Linux quick unlock,** unless Q13b asks for them.

## Today

### Profiles

- **Resolution runs before `app.setPath`.** `initializeProfile` (`profile-resolver.js:344`) runs at main's top level: `resolveProfile` (180–285) picks the profile, and `applyProfile` (287–292) sets `userData` and `crashDumps`. Before it, `FREEDOM_TEST_USER_DATA` sets `userData` directly (`index.js:63–68`), and packaged builds run `migrateUserData` on the default `userData` (79–81). It must come first because Chromium's storage, every store and Electron's single-instance lock (Linux, `profile-instance-handoff.js`) all live under `userData`.
- **The choice, in order:** `--profile`, an `x-freedom-profile:` switch (Linux; only to a profile that is open), `FREEDOM_PROFILE`, `automation` for `--runtime`, the profile opened last, then `default` or the first registered (`resolveFallbackProfileId`). `--profile-dir` and `FREEDOM_TEST_USER_DATA` bypass the catalog (184–212). A first run registers `default` at slot 0 (248–259). Each opening writes `lastOpenedAt`, except a switch (268).
- **Where profiles live:**
  - the packaged app root is the default `userData`: `<appData>/Freedom`, or `~/.config/freedom` on Linux (`index.js:35–47`);
  - the packaged `default` profile's directory **is the app root** (`profile-resolver.js:244–246`); others are `Profiles/<id>`;
  - dev builds use `<appData>/Freedom Dev/<checkout>/Profiles/<id>`;
  - catalog profiles' Radicle homes are `R/<slot>` outside the profile, because of the control socket's path limit (`profile-paths.js:151–176`, 208–265);
  - the lock directory is `<appData>/Freedom/locks` (`service-locks.js:11–12`).
- **The catalog:** `profile-registry.json` at the app root, `{ version: 1, profiles: [{ id, displayName, dir, slot, createdAt, lastOpenedAt, nodes }] }`, and each profile's `profile.json`, `{ version: 1, id, displayName, createdAt, lastOpenedAt, slot, nodes }` (`profile-catalog.js:637–668`).
  - **Writes:** `writeJsonAtomic` writes `<file>.<pid>.tmp` and renames it, with no fsync (269–274).
  - **The write lock** is proper-lockfile's, on `profile-registry.write.lock`: stale after 30 s, refreshed every 10 s, 5 retries of 50–250 ms (15–21, 340–466).
  - **A catalog that isn't version 1** fails resolution, and nothing opens (473–485).
  - **A slot sets the ports:** Bee API 11633 + slot, P2P 12633 + slot, Tor SOCKS 19150 + slot. In dev builds the bases are 21633, 22633 and 29150, plus (checkout hash mod 100) × 10 (23–84).
- **The profile lock** (`profile-lock.js`):
  - **Format:** proper-lockfile on the target `profile-open`, with the lock directory `profile-open.lock` in the profile's `userData`. It is held by `mkdir`, and kept by refreshing the directory's mtime every 10 s. It is stale after 30 s; dev builds use 1 s and 5 s (5–10, 53–84).
  - **Takeover:** a launch that finds a stale lock removes the directory and takes it (`lib/lockfile.js:24–92`).
  - **The refresh** is an event-loop timer (`setTimeout`, 108). Anything that blocks main's loop stops it, `spawnSync` included, and 30 s later another build can take the lock over.
  - **Compromise:** at a refresh, the holder marks its own lock compromised when the mtime isn't the one it set, or the directory is gone, or the refresh fails past the stale time (99–160), and main's handler then throws (`profile-lock.js:77–80`). A loop that was only blocked, with nobody taking over meanwhile, refreshes again as if nothing happened.
  - **When:** main takes it with `lockSync` at its top level, after `app.setPath` and before `app.whenReady` (`index.js:143–178`). The top level already reads a store before the first window: `loadSettings()`, for Blink's features (546).
- **The core's gate is separate:** `freedom-cored serve` holds `<lock-dir>/<sha256(canonical identity dir)>.lock` for its whole life (0001), freedom-ipfsd holds `ipfs-…` and freedom-radicled `radicle-…` (`fc-service/src/gate.rs`). The core starts after `app.whenReady`. `freedom-cored hold-lock` takes the core's gate, prints `locked`, and holds it until its stdin closes (`main.rs:110–135`).
- **Overrides:** `FREEDOM_IDENTITY_DATA`, `FREEDOM_ANT_DATA`, `FREEDOM_BEE_DATA`, `FREEDOM_IPFS_DATA`, `FREEDOM_TOR_DATA`, `FREEDOM_RADICLE_DATA` and `MYOTIS_DATA_DIR` move a component's directory out of `userData` (`profile-paths.js:17–35`, 284–292). They come from the launching process's environment, and nothing records them, so another process can't know where a running profile keeps its identity.
- **The glue** launches another profile (`profile-launcher.js`), hands focus and URLs to a running one (`profile-focus-handoff.js`, `profile-instance-handoff.js`, `profile-switch-scheme.js`), and watches the catalog (`profile-registry-watcher.js`). The roadmap counts this glue as shell work that stays in Electron.

### The stores

All in the profile's `userData` unless noted. "In place" means `writeFileSync` on the file itself, which a crash can tear. "Rename" means a temp file and a rename with no fsync, which makes a torn file less likely, not impossible.

| Store | File | Format | Written |
|---|---|---|---|
| Vault metadata | `identity/vault-meta.json` | JSON, 2-space: `userKnowsPassword`, `createdAt`, `addresses`, `derivedWallets` (mnemonic, `ledger`, `remote`, `safe` records), `activeWalletIndex`, `nextHardwareWalletIndex` | in place (`identity-manager.js:90–98`); a file that doesn't parse reads as missing (73–85) |
| Quick unlock | `identity/quick-unlock.dat` | `{ version: 2, profileId, userDataDirHash, vaultFingerprint, encrypted, createdAt }`, or legacy raw `safeStorage` ciphertext | in place, mode 0600 (`quick-unlock.js:51–110`); SEC-3d moves it to `private-files.js` |
| Vault, node journal | `identity/identity-vault.json`, `node-identity-*.json` | the core's (0001) | the core, durable |
| Intent journal | `wallet-intents.jsonl` | JSON Lines `{"v":1,"sha256":…,"record":…}` | durable: fsync per append, compaction by rename (`lib/durable-journal.js`) |
| Pending Safe transactions | `safe-pending.json` | JSON | in place (`wallet/safe/pending-store.js:41`) |
| RPC API keys | `rpc-api-keys.json` | JSON | in place (`wallet/rpc-manager.js:65`); #945 makes it owner-only and atomic |
| Grants | `dapp-`, `swarm-`, `radicle-`, `x402-permissions.json` | 0012, *The files* | three in place, Swarm's by rename (0012) |
| Swarm feeds, manifest grants | `swarm-feeds.json`, `swarm-manifest-grants.json` | JSON | rename (`swarm/feed-store.js:394–395`, `swarm/permission-manifests.js:90–91`) |
| Payment history | `payment-history.sqlite` | better-sqlite3, WAL, `user_version` 1, table `payments` (`payment-history.js:65–122`); imports `x402-receipts.json` once | SQLite |
| Publish history | `publish-history.sqlite` | WAL, `user_version` 1, table `publishes` (`swarm/publish-history.js:25–78`) | SQLite |
| Settings | `settings.json` | JSON | in place (`settings-store.js:277`, `:438`) |
| Networks, tokens | `network-config.json`, `custom-chains.json`, `custom-tokens.json` | JSON | in place (`networks/network-registry.js:315`, `:541`, `:557`; `token-registry.js:73`) |
| Site permissions, adblock allowlist | `permissions.json`, `adblock-allowlist.json` | JSON | in place (`permissions/permissions-store.js:63`, `adblock/allowlist-store.js:45`) |
| Caches | `balance-cache.json`, `chain-catalog.json`, `swarm-browsing-credit.json` | JSON | in place, in place, rename |
| Legacy launches' node decisions | `external-node-decisions.json` | JSON | in place (`profile-external-candidates.js:203`) |
| History, downloads, bookmarks | `history.sqlite`, `downloads.sqlite`, `user-bookmarks.json` | SQLite, JSON | not ported (non-goal) |
| Node data | `ant-data/`, `ipfs-data/`, `tor-data/`, `myotis/`, `radicle-data/` (non-catalog), `bee-data/` (legacy) | the nodes' own | the nodes; Ant's `config.yaml` by main |

`config.yaml` holds Bee's keystore password until #946, and `ensureConfig` rewrites it in place at every Ant start (`ant-manager.js:309–360`). A crash in that write loses the password's only copy, and the next start refuses (333–340) until the key is injected again. SEC-3d (#943) writes it through `private-files.js`, which is atomic and durable.

### Quick unlock

- **macOS only.** `canUseTouchId` is false elsewhere (`quick-unlock.js:130–135`), and onboarding offers Quick Setup only with Touch ID (`onboarding.js:65–85`).
- **The credential:**
  - The vault password is encrypted with Electron's `safeStorage`, through the synchronous calls (`quick-unlock.js:52`, 278), which #946 notes are deprecated in Electron 45.
  - It is bound to the profile's id, to the SHA-256 of `userData`'s real path, and to the SHA-256 of the vault file (34–97).
  - Touch ID is main's prompt (`systemPreferences.promptTouchID`, 182 and 276), in front of a key the app can read without it.
  - A legacy credential, raw ciphertext, is upgraded at its next use (281–283).
- **Quick Setup:**
  - The renderer makes a random password the user never sees, imports the mnemonic under it, then enables quick unlock (`onboarding.js:218–249`).
  - If enabling fails, it deletes the vault (248).
  - A lost reply is finished by main (`identity-manager.js:145–148`, 0001's *Reconciliation*).
  - That `safeStorage` blob is the password's only copy, bound to Electron and to the `userData` path. That is the Stage-2 risk the roadmap names.
- **A password change** rewrites the vault, so the credential's fingerprint stops matching, and quick unlock is silently off.
- **With this design** the file goes once the core holds the credential: PRF-2 deletes it after a confirmed enroll ([The re-wrap](#the-re-wrap)).

### Bee's keystore password

- **On integration** the core's `nodes.write_identity` writes `keys/swarm.key` and `config.yaml` with a fresh password, as one journaled operation (`nodes.rs:1–12`). Main reads the password back from `config.yaml` at each start (`ant-manager.js:318`). That is AGENTS.md rule 4's one exception, "until Phase 5".
- **#946 (SEC-3f, adapted)** seals the password with `safeStorage`'s asynchronous API into `ant-data/keys/keystore-password.sealed`, and removes the `password:` line once the seal is verified and published:
  - **The record** is `JSON.stringify({ version: 2, ciphertext, keystoreSha256 })`. `ciphertext` is the base64 of the `safeStorage` ciphertext, and `keystoreSha256` the SHA-256 (hex) of the `swarm.key` bytes it was sealed for, or null (`ant-keystore-password.js:157–197`). A seal for another keystore is a broken pair, never handed to antd.
  - **Linux:** only the `v11` (Secret Service, KWallet) and `v12` (Secret Portal) prefixes count as sealed. `v10`, Chromium's fixed fallback key, leaves the password in the owner-only `config.yaml`. On macOS and Windows, `v10` is keyed.
  - **At each start** the password goes to antd as `--password-file` in `<userData>/run/ant-handoff/password-<random>` (0600, in one 0700 directory), removed once the API answers. Orphans are swept at the next start.
  - **Migration** decodes an old `password:` line as serde_yaml 0.9 does (an 86-case fixture), checks with one scrypt run that it opens `swarm.key`, then seals.
- **#963:** on Windows, `private-files.js` binds each read, temp file and rename to a directory by path, between two identity checks: Node has no handle-relative calls. The core's `anchor.rs` has the same limit on Windows (its header), and `fsx.rs` keeps 0001's identity checks Unix-only.

### Facts found while checking the code

1. **A stale-looking lock is trusted for deletion.** `ensureProfileClosedForDelete` returns at once when the target's lock reads stale (`ipc-handlers.js:525–528`), and `deleteProfile` checks the same lease (`profile-catalog.js:1151–1153`). A live profile whose main loop stalls for more than 30 s can be deleted under itself.
2. **Deletion holds only the IPFS gate.** 0001 says profile delete holds the core's gate (`hold-lock`) for the whole destructive operation. Integration holds freedom-ipfsd's (`profile-catalog.js:1169–1170`), and no other.
3. **Deleting the packaged default profile removes the lock directory, on macOS and Windows.** `<appData>/Freedom/locks` (`service-locks.js:12`) lies inside the packaged app root there, which is the default profile's directory. `removeDefaultProfileDataFromAppRoot` keeps only `APP_ROOT_SHARED_ENTRIES` (`profile-catalog.js:821–853`), and `locks` isn't one of them.
   - 0001 says the lock directory is never deleted, and `gate.rs` that a lock file is never unlinked.
   - Removed, every gate held at that moment by another profile's core or services goes with it, and the next process locks a new file under the same name.
   - Linux is safe: `~/.config/freedom` and `~/.config/Freedom/locks` are different directories.
4. **Fifteen of the Freedom stores' modules write in place, and five by an unflushed rename** (the table above, and the catalog's `profile-catalog.js:269–274`).
5. **The chrome renderer could fetch the RPC API keys, at `5484f8dd`,** which these lines are from. The chrome's preload exposed `rpcManager.getEffectiveUrls` (`preload.js:995–1000`). Its handler returned the chain's RPC pool with each key substituted into its URL (`rpc-manager.js:178–182`, `network-registry.js:475–490`). No renderer code called it: the settings page got only `hasKey` for each keyed provider (`network-ipc.js:108`, `settings.js:3066`), and set, tested or removed a key without reading one back. **The path is gone at `9d4ea625`,** PRF-5's pin: no preload or IPC handler exposes it, and `getEffectiveRpcUrls` serves only main's `wallet:proxy-rpc` allowlist (`isAllowedRpcUrl`).

## Threat model

Stage 1 trusts main (0001). What this design adds protection against:

| Threat | Today | With 0013 |
|---|---|---|
| A torn write loses grants, intents, account records or the catalog | in place or unflushed renames | 0001's durable atomic writes for the core's stores; a durable helper for main's |
| Bee's keystore password beside the keystore (K-3) | `config.yaml`; #946 seals it with `safeStorage` | the core's secrets file under the OS key store; `config.yaml` only where there is none |
| RPC API keys in plain JSON (K-5) | `rpc-api-keys.json` (#945: owner-only) | the secrets file where the OS has a key store; elsewhere the same owner-only file, written by the core. With a key store the file keeps only what an entry can't hold: an id outside the entry form, and keys past the 16-entry bound (`rpc-key-provider-id`, `rpc-keys-bound`) |
| Quick Setup users locked out by a shell change | the only copy is Electron's `safeStorage`, bound to the `userData` path | the core's key store, from PRF-2 |
| A live profile deleted under itself | a stale lock is trusted | a held profile gate means open, from before the lock to after it; deletion holds every gate |
| An older build entering a profile mid-move | — | the move holds the profile lock in today's format, refreshed from its own thread |
| The shared lock directory removed with the default profile | `locks` isn't a shared entry | kept |
| Two writers on one store | the profile lock only | one writer per store, and the core's gate |
| A same-user process swapping a directory on Windows (#963) | checked by path | handle-relative calls for every file the core writes |
| A compromised service reading Freedom data (0010) | protected roots by component | the same, with `freedom/`'s entries |
| A compromised core reaching other profiles, the catalog or the session bus (D7) | not confined | `serve` confined to its profile's data (the default profile only after the move); catalog work in one-shot subcommands; key-store calls in a one-shot helper |
| A compromised chrome renderer reading RPC API keys (0011's adversary) | `rpcManager.getEffectiveUrls` returned them inside URLs (gone on integration since) | plaintext only to the shell; the chrome sees which providers have a key, and can set or remove one |

**Not covered:** a compromised main; a same-user process, which can read the profile's files directly (outside the boundary, as in 0001 and 0010); root, admin and physical attacks. **On Windows and Linux** the `Unattended` key is readable by any process of the user while the session is unlocked (DPAPI, the Secret Service), so it protects against other users and an offline copy of the disk, not against a same-user process. On macOS the Keychain item's access list adds the code signature. **Through the helper,** a compromised `serve` can still have main run key-store calls on its own profile's items: forget them, which sends each secret to its fallback path, or open them, which gives it what it already holds. On Windows it can send a blob of its choice, but the helper opens only blobs made under Freedom's entropy ([DPAPI's blob](#dpapis-blob)). It can't reach the session bus or the Keychain's other items, nor another profile's items wherever D7 keeps that profile's files out of its grant (for the packaged default profile, from D7b on), since their ids are in those files. The forget file lies at the app root, outside a named profile's grant and, from D7b on, the default profile's. Before D7b the default profile's `serve` can read it, as it can every profile's files, and learns only ids already being forgotten. The design calls nothing defense in depth that isn't.

## 5.1 Resolving the profile

**Proposed: `freedom-cored profile open`, a synchronous subcommand that main runs before `app.setPath`.**

```
freedom-cored profile open --app-root <dir> --lock-dir <dir>
    [--dev --checkout-hash <hex8>] [--default-profile-dir <dir>]
    [--profile <id>] [--switch <id>] [--env-profile <id>] [--runtime]
```

- **What it does:** it applies `resolveProfile`'s rules as `fc-profile` ports them (the order above, sanitizing, first-run registration, the fallback, `lastOpenedAt`), creates or updates the catalog record and `profile.json`, and prints one JSON object: `{ outcome: "opened" | "switch_refused", id, display_name, user_data_dir, slot, nodes, switch_only?, lock_fresh, gate_held, layout, forget_pending }`. `layout` is `"root"`, `"freedom"` (the marker exists) or `"pending"` (a move's journal exists), which tells main whether to run `profile migrate` ([The move](#the-move)). `forget_pending` counts the items in the app's forget file, which main forgets after its first window ([Forgetting an item](#forgetting-an-item)). `profile open` never fails over that file: one it can't read counts as pending, and `forget-list` sets it aside.
  - **Exits:** 0 with that object; 74 (`storage`, with the kind on stderr: unreadable or unsupported catalog, a network filesystem, a path that isn't the user's, a symlink below the app root); 75 when the catalog's write lock stays held; 64 for bad arguments.
  - **A switch** to a profile that isn't open answers `switch_refused`, as `PROFILE_SWITCH_REJECTED` does today.
- **What stays in main:**
  - parsing argv and the `x-freedom-profile:` URL, which are Electron's and the OS's;
  - `--profile-dir` and `FREEDOM_TEST_USER_DATA`, which are path arithmetic without a catalog;
  - finding a dev checkout's root;
  - `app.setPath` itself;
  - the error dialogs, the launcher and the hand-off glue.
- **How main calls it:** `spawnSync` with a 5 s timeout and the core's cleared environment (0001's *Spawn*), from the app's resources. It runs before main takes the profile lock, so main holds no lease while it blocks. A failure shows today's "Freedom profile could not open" dialog. There is no JS fallback: the catalog keeps one writer per build, and older builds already coexist through the format and the lock.
- **The catalog's write lock** is proper-lockfile's format exactly: `mkdir`, an mtime that a holder over 10 s refreshes, stale after 30 s, a stale lock taken over by removing it. So the subcommands and an older build exclude each other. `profile open` holds the lock for milliseconds. A subcommand that may hold it longer, as `profile delete` does for the whole delete (`profile-catalog.js:1138–1141`), refreshes it from a thread that does nothing else, and checks at each refresh that the mtime is still the one it set, as proper-lockfile does.
- **Writes:** 0001's durable atomic writes, today's text (`JSON.stringify(…, null, 2)`, JS key order). The temp names keep the `profile-registry.json.` prefix, which `isAppRootSharedEntry` spares (`profile-catalog.js:832–835`).
- **The latency gate (PRF-3):** the subcommand's wall time, measured by main around `spawnSync`, must stay under 100 ms at the 95th percentile on each OS's CI runner, on the optimized binary main ships. The first run of about 100 opens includes the cold start and is reported. If it misses, one warm re-measurement of 100 opens is judged alone: a runner's stall slows one run, and a slow binary slows both. The cold cost a user meets is the first-scan qualification's, below. **On Windows the CI gate reports and doesn't fail while Windows keeps `profile open` in JS** (PRF-4's Windows condition, below): GitHub's Windows runner runs a p95 over 100 ms in some runs with a p50 near 27 ms, and a miss there blocks nothing the browser uses. The PR that moves Windows's `profile open` to the core makes the gate fail there again.
  - **Windows's first scan isn't on CI.** Builds are unsigned today, so the antivirus scan of a new binary's first run counts for users, but GitHub's Windows runners turn real-time scanning off and exclude their drives, and one cold run is at most one sample of a p95. So the CI gate measures start-up and the profile work only.
  - **Before PRF-4 ships `profile open` on Windows,** a qualification on a fresh Windows machine with Defender's real-time scanning on and no exclusions: a newly downloaded release artifact's first `profile open`, and the first after each of several reboots (Defender caches a scanned binary, so repeats in one session don't count), each under 1 s, with the numbers recorded in PRF-4's PR. Over that, `open` stays in JS on Windows, as below.
  - **If an OS misses it,** `open` stays in JS on that OS: it is the one call made before any window. `fc-profile` still backs every other catalog operation, and Stage 2.
  - **The cost of staying in JS everywhere:** two implementations of the catalog until Stage 2, and the port done later, when the reference may be gone.
- **The catalog's other operations are subcommands too,** not methods of the running core: `profile list`, `create`, `rename`, `import`, `delete`, `update-nodes`, `reserved-ports`, `status`, `forget-list` and `forget-done` ([API](#api)).
  - **How main calls them:** with an asynchronous `spawn`, so its own lock keeps refreshing, when the profile manager or the node settings ask through today's IPC, from whichever profile process shows them.
  - **Each is one short run on main's arguments.** It reads nothing a page or the network sent. Each confines itself with 0010's mechanisms before it reads anything (`profile open` included): read-write on the app root, the lock directory and, in dev builds, the `R/` root of the Radicle homes beside the app root; no network; no child process.
  - **Why not methods of `serve`:** catalog work needs the app root, and an import or a delete another profile's directory. D7 keeps both from `serve` ([D7](#effects-on-0010-and-d7)), the long-lived process that parses what pages and the network send.
  - **The grant's limit:** Landlock can't grant a directory without everything below it, and the app root holds every profile, so on Linux each of these runs reaches every profile. That is acceptable for a run that takes only main's arguments and exits.

### The lock

- **The format stays exactly today's,** taken by main in JS as today. Older builds read and honor it, and the new build honors theirs. Moving its refresh into the core was weighed and dropped: proper-lockfile marks a lock whose mtime it didn't set as compromised, so a lock can't pass between processes, and two refreshers break it ([Options weighed](#options-weighed)).
- **The profile gate:** `<lock-dir>/profile-<sha256(canonical userData)>.lock`, in the namespaced form of `fc-service`'s gates (`gate.rs`, `lock_file_name`), with 0001's rules: an OS lock, a file never unlinked.
  - **Why `userData`:** it is the one path every process can name for every profile. The catalog records each profile's directory, and `--profile-dir` and test launches name it. The core's identity gate can't serve: a component override (`FREEDOM_IDENTITY_DATA`, …) moves the identity, and nothing records the environment another profile started with ([Profiles](#profiles)).
  - **Who holds it:** `freedom-cored hold-profile --user-data-dir <dir> --lock-dir <dir> [--app-root <dir> --id <id>]`. It takes the gate, prints `locked`, and holds it until its stdin closes, as `hold-lock` does. For a catalog profile it then checks that the catalog still lists that id at that directory, so a launch that raced a delete fails instead of opening an empty profile. After that it confines itself to its stdin and stdout: no file, no network, no child. It does nothing else, so a stalled or busy main doesn't stall it.
  - **From before the lock to after it:** main starts it after `app.setPath` (and after `profile migrate`, when one runs) and before it takes the profile lock. It waits for `locked` (10 s at most) before it starts the core, any node, any store write or its first window. At quit it closes the holder's stdin only after releasing the lock. So whenever a new build holds the profile lock, the gate is held too: before `serve` starts, while the core restarts after a crash, and while main's loop is stalled. The moment between taking the lock and the holder's `locked` lies inside the lock's first 30 s, while the lock is fresh.
  - **If it can't take the gate** within its 5 s contention retry, another new build has the profile: main lets go of its lock and hands over, or reports the profile busy, as for a fresh lock. If the holder dies while main runs, main starts another at once; the lock, still fresh, covers the moment, and a main that can't take the gate again within 5 s quits, as on a compromised lock.
- **What "open" means, in new builds:** the lock is fresh, **or** the profile gate is held. So a live profile whose main loop has stalled still reads as open, though its lock looks stale, from the moment its main took the lock, its core up or not.
  - **Asking the gate:** `profile open` reports `gate_held` for the chosen profile, and `profile status --user-data-dir <dir>` for any other. Main runs `status` asynchronously, like the other subcommands, and only for a lock that reads stale, since a fresh lock already means open. Each tries the gate's lock without waiting and lets go at once. A holder starting at that moment retries contention for 5 s, so a probe can't make it fail.
  - **Who asks:** `profile open`'s switch check, `isProfileLocked` when the lock reads stale, and a launch about to take a stale lock over (in `profile open`).
  - A stale lock with the gate held is treated as held: the launch hands over or reports the profile busy, as for a fresh one.
- **Older builds** know only the lock. Against them the lock excludes as it does today, and a stalled older build can still be taken over after 30 s, as today ([Failure modes](#failure-modes)).
- **Deletion** (`profile delete`) holds the target's gates for the whole operation: its profile gate, the core's identity gate, freedom-ipfsd's and, for a catalog profile, freedom-radicled's on its home. The last three are taken on the paths the delete removes: inside the profile, and a catalog profile's `R/<slot>` home. Inside the profile, the core's and freedom-ipfsd's are taken by its layout ([Readers, and the downgrade](#readers-and-the-downgrade)), read once the profile gate is held, which a move holds for its whole run: at the profile's directory, and once a move has begun (its journal pending, or the marker there) below `freedom/` too. The root's stay gated after the move, since a build from before the reader release, run after a downgrade, starts its services there; the root's `identity` is then the placeholder, gated at its path. An overridden component lives elsewhere and isn't deleted, and a process using one holds the profile gate anyway. Any one held refuses the delete before anything changes. This is 0001's rule, built at last, and it fixes the stale-lease delete. A directory on the way that was missing when the delete checked the layout is reached again from the last one that was there, so a home a start made meanwhile, before it waited on the gate, goes too. Before taking any gate, the delete also refuses a record whose directory would take the app's data or another profile's with it ([`profile-delete-overlap`](#deviations)): the profiles root or another of the app root's shared entries, or inside one but the profiles root; or at, above or inside another record's directory, where the packaged default profile's is the app root's entries but the shared ones; or a record whose integer slot another record also has, since both have one Radicle home (`R/<slot>`, or a dev build's `R/<checkout>/<slot>`). Names are compared on every OS as no volume tells them apart: canonically decomposed (NFD), since macOS's volumes ignore normalization; case folded at least as widely as a volume folds (each character's uppercase lowercased, until nothing changes, so `É` and `é`, `ß` and `SS`, and the Kelvin sign and `k` match), since macOS's and Windows' default volumes ignore case; and on Windows without trailing dots and spaces. A fold wider than a volume's only refuses more. Before the catalog changes, the delete also records the target's key-store items in the app's forget file ([Forgetting an item](#forgetting-an-item)). The quit request to a running profile stays as it is, before the delete.
- **The core's identity gate stays,** for what 0001 gives it: one core per identity directory, wherever an override puts it.
- **The lock directory is kept:** `locks` joins the app root's shared entries. That is a one-line fix in `profile-catalog.js`, and it should ship now, outside the PRF steps.

## 5.2 Stores (Q14)

### Which stores

**Proposed for Stage 1: the core owns set A. Set B stays in main, with durable writes. Set C is the shell's, and isn't ported.**

| Set | Stores | Why |
|---|---|---|
| **A, the core** | **wallet:** `vault-meta.json`, `wallet-intents.jsonl` (and the nonce reservations, in memory), `safe-pending.json`; **permissions:** 0012's four files and `phone-payments.json`; **feeds:** `swarm-feeds.json`, `swarm-manifest-grants.json`, `publish-history.sqlite` (0015 designs their methods); **payments:** `payment-history.sqlite`; **profiles:** `profile-registry.json`, `profile.json` (through the subcommands, never `serve`); **secrets:** the quick-unlock credential, Bee's keystore password, the RPC API keys | each decides what may be signed or spent, records money that left, or protects a key. A main bug or a torn file there costs funds or authority |
| **B, main, durable** | `settings.json`, `network-config.json`, `custom-chains.json`, `custom-tokens.json`, `permissions.json`, `adblock-allowlist.json`, `external-node-decisions.json`, and the caches `balance-cache.json`, `chain-catalog.json`, `swarm-browsing-credit.json` | settings and caches: losing one costs a preference or a refetch. Several have a native home in Stage 2 (Chromium's preferences and content settings, the native ad blocker) |
| **C, the shell's** | `history.sqlite`, `downloads.sqlite`, `user-bookmarks.json`, and Electron's own files | Chromium-native in Stage 2 (the roadmap's non-goal) |

- **The alternative ([Q14](#open-questions)):** every Freedom store, sets A and B, in the core. That is one more method family per store, for data whose loss is a preference, and some of it Stage 2 may store natively anyway. Set B can still move later, through the same `fc-store`, without a format change.
- **Main keeps the agent's stores** (6.2) and the nodes' own data.

### How the core writes them

- **A crate, `fc-store`** (service), holds what each store shares:
  - 0001's durable atomic write, moved out of `freedom-cored/src/fsx.rs`, and the handle-relative directory of `anchor.rs`;
  - reading under 0001's rules (a regular file the user owns, no symlink, a size bound);
  - renaming an unreadable file aside, as 0012 proposes;
  - the JSON Lines journal.

  SQLite's glue lives in `freedom-cored` instead ([Where SQLite lives](#where-sqlite-lives)).

  Each store's codec, the bytes it reads and writes, lives in a logic crate with its rules: `fc-approval` for 0012's files, and `fc-profile` for the catalog. `vault-meta`'s, the intents' and the payments' go in a new logic crate, `fc-wallet-state`.
- **JSON:** today's text byte for byte: the same keys, `JSON.stringify(…, null, 2)`'s spacing, and JS's insertion order as each operation leaves it, pinned by vectors after every operation. Written by 0001's single-file write: temp file, fsync, rename, directory flushed, mode 0600. 0012's rules for failed and narrowing writes apply to every set-A store.
- **The intent journal** keeps `lib/durable-journal.js`'s format and rules exactly:
  - a line is `{"v":1,"sha256":"<hex>","record":<record>}`, the checksum over the record's exact bytes;
  - each append is synced before it is acknowledged;
  - a whole last record without its newline is accepted;
  - a torn tail is cut off, and a damaged line is skipped and reported;
  - compaction goes through a temp file and a rename;
  - the bound is a parameter: the journal's default is 64 MiB, and the intent store reads at most 16 MiB and keeps its file under 8 MiB (`LIMITS`).

  The core's port reads every file the JS wrote, and the JS reads every file the core writes. APR-6 (0012) builds the nonce and the broadcast on it.
- **SQLite** goes through `rusqlite`, which AGENTS.md rule 7 already lists, with its bundled SQLite:
  - **Schemas are kept:** the same tables, columns, indexes, `user_version` and WAL mode. The core never changes a schema, or the user version, while a build that may still open the file reads the old one. A change needs a design.
  - **`payment-history.sqlite`'s one-shot import** of `x402-receipts.json` (renamed `.migrated` afterwards) is ported too, for a profile that no build since that import has opened.
  - **One writer:** a database is opened by one process at a time, so main stops opening it in the same PR in which the core starts.
- **Main's set B** gets one shared helper with the same steps in JS, `lib/atomic-file.js` (temp file, fsync, rename, directory sync, as `durable-journal.js`'s compaction already does), and each in-place writer moves onto it.

### One writer per store: `store_moved`

**Proposed: main hands each set-A store to the core by naming it in `core.hello`'s `store_moved`, as 0012's `grant_moved` hands over the grant files. Which stores a build names is a property of that build, never a switch it makes at run time, and the core echoes the names it took.**
- **The names**, all known from PRF-5c-1: `vault_meta`, `intents`, `payments`, `safe_pending`, `rpc_api_keys`. A hello naming any other is malformed (`invalid_argument`, and the core exits), as for `grant_moved`. A name given twice counts once. Absent means none.
- **The echo:** the hello's answer gains `store_moved`, the names given whose store this core serves, each once. A known name whose methods arrive in a later step (`payments` before PRF-5g-2, say) isn't echoed, and that store stays as if not named. A core before PRF-5c-1 ignores the field, as it ignores every hello member it doesn't know (`HelloParams`), and its answer has no `store_moved`.
- **A store not named,** or not echoed, stays main's:
  - reads are served where the core can read the file (`accounts.*`, `intents.*` and `safe_pending.*`'s reads). An unreadable file reads as missing and stays in place: only a store's writer sets its file aside. A read that writes in the reference (`accounts.list`'s first-list default) answers the same and writes nothing;
  - every write answers `not_moved` (`data.store`), and nothing is written, renamed or removed;
  - `vault.create`, `vault.import`, `vault.unlock` and `quick_unlock.unlock` write no metadata, as today;
  - the core never opens a SQLite database that isn't named, for reads either, so every `payments.*` method answers `not_moved`. SQLite's one writer needs that;
  - the core never reads or writes `rpc-api-keys.json`, and every `secrets.*` RPC-key method answers `not_moved` ([RPC API keys](#rpc-api-keys)).
- **Each browser step** (PRF-6(a) to (e)) adds its name to every hello in the change that deletes main's writer for that store, and for `payments` main's open of the database. So that build has no main writer to quiesce at a handshake, no open database to close, and nothing to fall back to.
- **Main checks the echo** for the core it writes to. Every request of a moved store, and each request that writes it through the core (for `vault_meta`, `vault.create`, `vault.import` and their `vault.reconcile`), goes with `requires(hello)`, checked against the hello of the very generation the frame is written to (service-client.js, from APB-4e). If that hello doesn't echo the name, as from an older core, the request fails `requirement_unmet` in main and nothing is written. Main keeps no writer for that case, so the store's operations fail closed until a core that echoes it runs. `vault.unlock` and `quick_unlock.unlock` aren't held back: on such a core they unlock, and the address migration waits for one that echoes `vault_meta`.
- **An older browser on a newer core** names nothing. The core serves the reads it can (none for payments or RPC keys), answers every write `not_moved`, writes no metadata, never opens a SQLite database, and never touches `rpc-api-keys.json`. The old main writes each store as today.
- **One main, one core:** the profile lock keeps two mains off one profile in any mix of builds, and the core's gate keeps two cores off one identity ([Failure modes](#failure-modes)). So each store has one main and one core at a time, and that main's build decides which of the two writes it.
- **Unlike 0012**, the hello now answers which names it took. `grant_moved` needs no echo, since every core that serves the grant methods knows all four names, and an older one lacks the methods. Here `vault.create` and `vault.import` exist in every core, and a new main has no metadata writer of its own, so a new browser on an older core could otherwise create a vault without its metadata.
- **At protocol 3 (PRF-8)** `store_moved` stays in `core.hello`, and its echo covers every profile that core opens. Which stores a browser build owns is a property of the build, not of a profile, so one name list serves them all, and `profile.open` carries none. A request for a profile opened on a generation goes with that generation's `requires(hello)`, as at protocol 2.

### Bounds

| Store | Bound | Source |
|---|---|---|
| `vault-meta.json` | 1 MiB; a larger file is unreadable | design |
| `safe-pending.json` | 1 MiB; a larger file is unreadable | design |
| `wallet-intents.jsonl` | read at most 16 MiB, the file kept under 8 MiB; held intents, replacements, open handoffs and tombstones as `intent-store.js`'s `LIMITS`, and its budget | reference |
| The JSON Lines journal | 64 MiB unless its store passes its own | reference (`durable-journal.js`) |
| An RPC API key | 1 to 1,024 bytes, a secrets-file entry's; at most 16 entries; the provider id 1 to 52 bytes, as [RPC API keys](#rpc-api-keys) | design |
| `rpc-api-keys.json` | 1 MiB; a larger file is unreadable | design |

`payment-history.sqlite` keeps the reference's row checks and no file bound, as the reference sets none (*inferred*).

### `vault-meta.json`

**Proposed: the core owns it,** in the identity directory, in today's format, from PRF-6.
- **Methods:** one per change `identity-manager.js` makes today, each pinned by the file's text after it ([Callers](#callers-of-the-store-methods)):
  - `accounts.list` (`getDerivedWallets`, whose first-list default the core writes once moved), `accounts.meta` (`identity:get-vault-meta`), `accounts.active`;
  - `accounts.add_mnemonic`: the core picks the index and derives the address (`keys.addresses`), as `createDerivedWallet` does; the caller gives the name;
  - `accounts.add_ledger`, `accounts.add_remote`: the record main checked against the device or the phone, written with `addressCheck: "matched"`;
  - `accounts.record_address_check`: a matched record stays matched (`recordAddressCheck`);
  - `accounts.add_safe`: main's predicted address, owners and threshold, under `addSafeWallet`'s checks (the preset, duplicate owners, owners that exist, aren't Safes and, for devices, are matched);
  - `accounts.mark_safe_deployed`: `{ verified: true }`, after main's verified read;
  - `accounts.set_active`, `accounts.rename`, `accounts.remove`.

  Device, phone and Safe records are public data main supplies.
- **The unlock's migration:** once `vault_meta` is moved, `vault.unlock` and `quick_unlock.unlock` add missing `addresses` as `afterUnlock` does, from the addresses the unlock derives. The exports migrate nothing, as today. A failed write doesn't fail the unlock: it is logged, and the next unlock tries again (`vault-meta-unlock-migration`).
- **`accounts.remove`** keeps `deleteDerivedWallet`'s refusals and order:
  - **Refused** for index 0, a missing index, a Safe's owner, and an account Swarm feeds still name. Feeds are main's until 0015, so main passes the references it found (`swarm_references`), and the core refuses with today's message when there are any.
  - **Then, in the one request:** for a Safe, every open Safe approval for that Safe is ended, and its `safe-pending.json` entry cleared once `safe_pending` is moved; the record is removed, and the active index reset to 0 if it was this one; then the account's dApp grants are forgotten (`approval.forget_account`). A failed forget is logged, as today.
  - **Main keeps** a Safe's exclusion (`beginDeletion`, `SAFE_BUSY`), taken before the call and released after, and its in-memory SafeMessage session, discarded after a removal. Before `safe_pending` moves, main clears the entry after the core's answer. A crash between leaves an entry for an index the hardware counter never hands out again (*inferred*).
- **With the vault:** once `vault_meta` is moved, `vault.create` and `vault.import` write the vault and `vault-meta.json` as one operation ([The vault and its metadata](#the-vault-and-its-metadata-one-write)), so a crash can't leave a vault without its metadata, or the reverse. That takes the metadata step out of 0001's *Reconciliation*: main no longer writes `vault-meta.json` after a committed result. Other changes write it alone, by 0001's single-file write.
- **`vault.delete` leaves `vault-meta.json` in place,** as the reference does (`deleteVaultData` removes only the vault) and the core's test pins (`tests/vault.rs`, `delete_removes_leftover_copies_of_the_vault`). The next create or import replaces it.
- **`user_knows_password`:** `vault.import` gains it, as `vault.create` has it. Once `vault_meta` is moved both require it (a boolean), since the core writes it as `userKnowsPassword`; before, it is ignored. Today create reads an absent value as `false`, and the reference's default is `true`, so the field is required rather than guessed.
- **An unreadable file** is renamed aside as `vault-meta.json.unreadable` and reported, once moved (`vault-meta-unreadable`). Unreadable means any of: past 1 MiB; not JSON (a byte-order mark included), or nested deeper than fc-json reads (512 levels); not an object; a `derivedWallets` that is truthy and not an array; a record that isn't an object, or whose `index` isn't an integer; an `activeWalletIndex` other than missing, `null` or an integer; a Safe record's `owners` that is truthy and not an array. No reference writer makes any of these; each comes from a damaged or hand-edited file. `fc-wallet-state`'s `VaultMeta::load` is the rule, and `stores.json`'s `vault_meta.malformed` pins each case with what the reference does.
- **0001's open question 1:** device, phone and Safe records stay in `vault-meta.json`, owned by the core, and keep working while the vault is locked. That is acceptable: they are public addresses and settings, and the core's own checks (0012) need to know an account's type.

### The vault and its metadata, one write

**Proposed: with `vault_meta` moved, `vault.create` and `vault.import` (an overwrite included) install the vault and `vault-meta.json` through one journal, `vault-meta-journal.json` in the identity directory, modelled on [the vault delete's](#the-vault-deletes-journal). The journal's write is the commit point. The vault is installed before its metadata, the order today's flow writes them in, so a crash shows an older build only states today's flow can leave ([Downgrade](#downgrade-after-the-commit)).**
- **The steps:**
  1. **Seal:** the new vault file in memory and its SHA-256, as the re-wrap's step 1. The new metadata is `saveNewVaultMeta`'s: `userKnowsPassword`, `createdAt` (the core's clock) and the new vault's `addresses`.
  2. **Quick unlock's entry,** with `quick_unlock: true`: staged, bound to the new digest, as [the re-wrap's step 2](#the-re-wraps-two-entries). The journal records that one was staged (`quick_unlock`), not the entry: its binding already ties it to the vault file.
  3. **Stage:** `identity-vault.json.freedom-new` and `vault-meta.json.freedom-new`: exclusive create, 0600, fsync, read back through the handle that wrote each, directory flush.
  4. **Commit:** the journal, by 0001's single-file write. The vault's commit claim comes right before it (0001: "before the journal write of a multi-file operation").
  5. **Install:** every file is checked before either is renamed. A file is done if it has the journaled digest. Otherwise it can be installed if its staged file has that digest and the target is still the file the operation replaces (`before`). Only when both are done or can be installed is each staged file not yet done renamed over its target, the vault's first, with a directory flush after each.
  6. **Finish:** the journal is unlinked, then the directory flushed (0001's durable remove). Then the re-wrap's step 4 leaves only `quick-unlock`. A finish that runs later, in recovery (after a returned failure or a restart), has neither the password nor the wrapping key, so it can't re-seal a staged credential: the entry's name is part of its associated data (`fc-keystore`'s `file.rs`). It does what the start rule does: it removes the old vault's `quick-unlock` and keeps the new vault's `quick-unlock.next`, until an enroll or a re-wrap folds it into `quick-unlock`, or a disable or the vault delete removes both ([The re-wrap's two entries](#the-re-wraps-two-entries)).
- **The record:** `{ "op": "vault.create" | "vault.import", "quick_unlock": true | false, "files": [ { "target": "identity-vault.json", "staged": "identity-vault.json.freedom-new", "before": "<64 hex>" | null, "sha256": "<64 hex>" }, { "target": "vault-meta.json", "staged": "vault-meta.json.freedom-new", "before": "<64 hex>" | null, "sha256": "<64 hex>" } ] }`. `before` is the digest of the file being replaced, or null where there was none. Fixed names only, in this order, and no member the writer doesn't write.
- **Before the commit,** a failure or a crash changes nothing: the staged files are removed (after a crash, at the next start), and the re-wrap's step 5 takes a staged entry off. The old pair stays: the old vault with its metadata, or no vault.
- **After the commit,** a failure that an install's rename, its directory flush or the finish returns answers the committed result, never an error: `create`'s `{ mnemonic, addresses }` or `import`'s `{ addresses }`, with `durable: false`. The journal stays for recovery, and main writes nothing, as for any committed result. The one exception is the finish's directory flush: it fails after the unlink, so the journal is already gone from the directory. The request still answers `durable: false`, `vault.reconcile` answers `meta: "written"`, and if a crash before a later flush brings the journal back, recovery finds both files done and only removes it.
- **Recovery** runs at start, before `core.hello` is answered, and in `freedom-cored recover`. It also runs first in every read of the vault, every `accounts.*` call and every secrets-file operation, which fail with `storage` while it can't finish. **It runs before the re-wrap's start rule,** so a staged credential finds its vault installed instead of being removed as naming no vault. If recovery can't finish, the start rule leaves the entry bound to the journal's vault. One lock serializes it with the write and with the delete's journal.
- **A record with `quick_unlock: true` whose vault isn't installed yet** installs it only if the secrets file still has an entry bound to the staged vault's digest. An older core removes that entry at its start, as naming no vault ([the start rule](#the-re-wraps-two-entries)). Installing the vault without it would leave a Quick Setup vault that only the recovery phrase opens. So without it the record is set aside as below, and the old pair stays, as the older build showed it.
- **A record that isn't exactly a writer's,** or one with a file that has neither its digest, nor a staged file with it over its `before`, is renamed to `vault-meta-journal.json.corrupt`; its staged files are removed, and nothing else changes. At start, a staged file that no journal names is removed, and so are the journal's temp files.
- **`vault.reconcile`** runs recovery first. While a journal remains, it decides from the journaled vault, the staged file if the vault isn't installed yet, under 0001's checks. Its committed `create` and `import` results gain `meta`: `"written"` once the journal is gone, `"pending"` while it remains after a failed install or finish (recovery finishes it, and main writes nothing). Without `vault_meta` moved there is no `meta`, and main's continuation stays as 0001 has it.
- **The delete's journal stays separate:** a vault delete never touches `vault-meta.json`. The two records share only the vault, and the one lock orders them.

#### Downgrade after the commit

Older builds and cores read none of these names: an older core runs no recovery, and the reference never looks at the journal or the staged files. At each point after the commit, the pair it finds:
- **The journal written, nothing installed:** the old pair, which is no vault after a create or an import, or the replaced vault with its metadata after an overwrite. The older core removes a staged quick-unlock entry, as naming no vault. The reference shows onboarding, or the old vault. Back on a core of this design: if neither target changed and, with `quick_unlock`, the entry is still there, the new pair is installed; otherwise the record is set aside, and what the older build left stays.
- **The vault installed, not its metadata:** the new vault with the old metadata. That is none after a first setup, the deleted vault's after a create or import that followed a delete (the delete leaves `vault-meta.json`), or the replaced vault's after an overwrite. Today's flow leaves the same pair when main dies between the core's commit and `saveNewVaultMeta` (0001, *Reconciliation*), and the reference treats it as it does today:
  - with no metadata, the account list is empty (`getDerivedWallets` answers `[]`), account changes fail with "No vault found", and an unlock works but migrates nothing, since `afterUnlock` needs a file;
  - with a deleted or replaced vault's metadata, that vault's records are listed: mnemonic accounts are derived from the new vault while it is unlocked, and their stored addresses shown while it is locked.

  The older core keeps quick unlock's entry, which is bound to the vault on disk. Back on a core of this design, metadata the older build left unchanged is installed. If it changed the metadata, the record is set aside and its metadata stays.
- **Both installed, the journal left:** the new pair, which the reference reads as after a create. The next core of this design removes the journal, or sets it aside if the older build changed a target since.
- **The boundary:** a downgrade in the second window keeps what today's crash in that window keeps, and this design doesn't repair that for the older build. No order avoids it. Metadata first would show an older build, after an overwrite, new metadata over the old vault, which today's flow never writes and which lists none of the old vault's accounts. [Rollback](#rollback-and-downgrade) says so.

### The intent journal

**Proposed: `intents.*`, shell only: one method per `intent-store.js` write and read, through `fc-store`'s JSON Lines journal and `fc-wallet-state`'s intent rules.**
- **Methods:** `intents.commit`, `.handoff`, `.outcome`, `.settle`, `.void`, `.retire`, `.track` and `.compact`; reads `.get`, `.by_key`, `.held`, `.list`, `.held_nonces`, `.usage` and `.void_refusal`. A write answers the intent as the store holds it after the line.
- **Whose run:** every line carries the run of main that wrote it (`RUN_ID`, one per main process), and a void and an outcome depend on "this run". Main passes its run id as `run` on every write, and the core writes it on the line. A core restart within one main keeps the run; a main restart starts a new one, as today.
- **The account lock** (`nonce-reservations.js`'s `holdsAccountLock`) stays main's until APR-6: main checks it before `void` and `retire`, as the store does today, and the core takes its word ([What stays open](#what-stays-open-at-prf-5)).
- **No events at PRF-5.** Main is the one caller, and calls its own `onChange` listeners after each write it made, as the store does today (a `track` notifies nobody).
- **Rules and bounds as the reference's:** `LIMITS` and the budget; compaction's `held` and `tombstone` lines; replay checking every line as a live write; a damaged file moved aside as `<file>.corrupt-<ts>`.
- **Signed bytes** are checked as the reference checks them (ethers' `Transaction.from`, a canonical re-serialize, the signer), by a signed-transaction decoder `fc-evm` gains (PRF-5e-1).
- **Where:** `wallet-intents.jsonl` at the Freedom root, as today.

### Payment history

**Proposed: `payments.*` over `payment-history.sqlite`, its schema and rows kept.**
- **Methods:** `payments.append`, `.update`, `.mark_confirmed`, `.mark_failed`, `.mark_dropped`, `.set_dropped_seen` (the repoll's write: only while the row is still pending, in one transaction), `.pending` (the repoll's read), `.get_recent`, `.get_by_id`, `.get_count` and `.clear`. `removeById` isn't ported: nothing calls it.
- **Values bound as the reference binds them:** `metadata` is stored as the JSON text JS makes, and `chain_id` as JS binds it, so a non-integer that passes `Number.isFinite` stays a REAL.
- **Events:** none from the core. Every write reaches the core through main (shell writes, and the chrome's `clear` relayed), so main sends `payments:tx-recorded` to every webContents after each, as today.
- **The repoll timers stay main's:** the boot sweep, the dropped-confirm timer, tx-recorder's polls and the intent tracker's settlements call the methods above.
- **The one-shot import** reads `x402-receipts.json` at the profile's `userData` root, as the reference does (`app.getPath('userData')`), never under `freedom/`, and renames it `.migrated`, at the core's first open of the database. Before PRF-9 that root is the hello's `grant_root`; after it, PRF-8's `user_data_dir`.
- **Where:** `payment-history.sqlite` at the Freedom root, WAL, `user_version` 1, as today.

### Pending Safe transactions

**Proposed: `safe_pending.get`, `.set`, `.clear` and `.list`, shell only, over `safe-pending.json` in today's text.** Its keys are wallet indices. JS puts canonical array-index keys (up to 2^32−2) first, in ascending order; a larger wallet index keeps insertion order after them, and clearing then setting one moves it to the end. The core keeps both orders.
- **On the wire:** `get { index } → { entry }`, a falsy entry answered as `null` (the reference's `entry || null`); `list → { indices }`, the keys as numbers in the file's order; `set { index, entry } → { durable }`; `clear { index } → { cleared, durable }`, where `cleared` says the key was in the store (`in`), its value falsy or not, and the file is written only then.
- **The chrome reads none of it directly:** `wallet:safe-state`, `wallet:safe-sign` and `wallet:safe-pending-list` return main's projections, without the signatures or the typed data. Main builds them from these reads.
- **Two deviations:** an unreadable file is renamed aside (`safe-pending-unreadable`, with the rule and the reference's behaviour case by case in its row); and a failed write is reported with the store unchanged (`safe-pending-write-reported`), where the reference logs it and keeps the change in memory as if saved.
- **`accounts.remove`** clears a Safe's entry once both stores are moved.

### RPC API keys

**Proposed: once `rpc_api_keys` is named, the core is the one writer of the profile's RPC API keys. Each key is a secrets-file entry, `rpc-api-key.<id>`, whose secret is the key itself, with the binding `{}`, as the secrets vectors already seal one. What the secrets file can't hold stays in `rpc-api-keys.json`, which the core then reads and writes in the reference's text.**
- **No `enabled` or `addedAt` in an entry:** the reference writes `{ apiKey, enabled: true, addedAt }`, but nothing writes `enabled: false` and nothing reads `addedAt`. An entry present is an enabled key, so `rpc_api_key_status` answers from the entries' names, without opening a key (`rpc-keys-fields`).
- **The provider id:** the registry of keyed providers stays main's (set B), and main checks an id against it first, as today. The reference takes any id there: `networks:upsert-source` checks a source's URLs, not its id, so the chrome can add a keyed provider under any string. The core takes what an entry can name: `rpc-api-key.<id>` must be an entry name (`fc-keystore`'s `EntryName`), so the id is 1 to 52 bytes of lowercase ASCII letters, digits, `.`, `_` or `-`. The built-in providers, `alchemy`, `infura` and `drpc`, fit. A set for another id is `invalid_argument` (`rpc-key-provider-id`).
- **The bound:** at most 16 RPC-key entries. Every secret shares the secrets file's 32 entries (`MAX_ENTRIES`), and this keeps room for quick unlock's two and Bee's password. A set that would add a 17th is `invalid_argument`, with nothing changed; replacing a provider's key at the bound is allowed (`rpc-keys-bound`).
- **Where a key lives,** each provider's in one place, except as the migration below says:
  - **the secrets file,** wherever the core has a key store;
  - **`rpc-api-keys.json`,** at the Freedom root, where the reference keeps it, for what the secrets file can't hold. That is every key where the core has no key store (`key_store_unavailable`: Linux and Windows until PRF-7, and a host without a Secret Service after), and a key already in the file whose id isn't in the entry form, or that is past the bound.

  The core reads the file as `private-files.js` does (a regular file the user owns, no link) up to 1 MiB, and writes it by 0001's single-file write, 0600, in the reference's text: `JSON.stringify(keys, null, 2)`, each key `{ apiKey, enabled: true, addedAt }`. An unreadable file is set aside as `rpc-api-keys.json.unreadable` and reported, where the reference reads `{}` and its next save replaces the file (`rpc-keys-unreadable`).
- **The methods,** once named:
  - `set_rpc_api_key`, with a key store: the entry is written first, then the provider leaves the file, the migration's order. A failure before the entry's write leaves the old key where it was. A crash between the two leaves the old key in the file and the new one in an entry: the file wins, so the key last answered as set stays in use, and the next start's migration replaces the unanswered entry with it. Without a key store, the key is written into the file.
  - `remove_rpc_api_key` takes the key from both places.
  - `rpc_api_keys` (shell) answers each provider's key from the file where the file has one the reference counts (`hasApiKey`: a non-empty `apiKey`, `enabled` truthy), and from its entry otherwise. `rpc_api_key_status` answers presence from the entries' names and the file, opening no key.
- **Migration, by the core, under the name:**
  - **When:** before it answers the first RPC-key request of each start, the core moves every key in the file that the secrets file can hold, in the file's order up to the bound. It moves them in one secrets write, replacing any entry the provider has, then rewrites the file without them, or removes it when nothing is left. Keys it can't hold stay.
  - **Why the file wins:** a key is in both places only after a crash between those two writes, after a set made while the key store was unavailable, or after an older build wrote the file following a downgrade. Each time the file's key is the same, newer, or the last one a set answered.
  - **After a crash** at any step, the next start resumes: no key is lost, and each provider ends with one. Without a key store nothing moves, until a start that has one.
  - **Why the core, and why under the name:** a set answers `not_moved` until the store is named, so main couldn't migrate first without a second way into the secrets file. A host without a key store needs a writer of the file after the move, and only the core can be the single one. And one secrets write moves every key or none. From PRF-6(e) on, main reads and writes neither place.
- **`getEffectiveUrls`** is already gone from the chrome's preload and IPC on integration ([Facts found](#facts-found-while-checking-the-code), 5).

### Where SQLite lives

**Proposed: `rusqlite`, with its bundled SQLite, in the `freedom-cored` binary, not in `fc-store`. The payments codec (rows, checks, the import's mapping) stays pure in `fc-wallet-state`.**
- **Why there:** CI's `mobile-targets` job runs `cargo check --workspace --lib` for iOS and Android, with no Apple SDK or NDK. Bundled SQLite compiles C in a build script, which that job exists to catch, so a SQLite library crate under `crates/` would break it. `freedom-cored` has no library target, so the job stays unchanged.
- **Rule 7** already lists `rusqlite`, which `freedom-mobile-ffi` links. Mobile writes its own glue around the same pure codec.
- **What it costs:**
  - SQLite enters the core's graph, which `freedom-ipfsd` was split off to keep out (its `Cargo.toml`: SQLite and libp2p "never" enter the core's graph, so an advisory can't block a vault fix). A SQLite advisory can now hold a core release at `cargo deny`. Accepted: the store is set A.
  - The core compiles C for the first time (`Cargo.lock` has no `cc` today).
  - **The musl targets need a C compiler:** CI's `release-targets-linux` cross-checks `aarch64-unknown-linux-musl` from x86_64, `profile-gate` builds the x86_64 musl target, and `release.yml` builds both, none with a C toolchain for them. Proposed: Zig as their C compiler, pinned and checksummed as `release-ipfsd.yml` already pins it. The glibc, macOS and Windows runners have theirs.
  - `LIBSQLITE3_SYS_USE_PKG_CONFIG=0` in every job that builds it, as `release-ipfsd.yml` sets, so the bundled SQLite is the one linked; SQLite joins THIRD-PARTY-NOTICES.
  - D7's filters must allow what SQLite calls (file locks, the `-shm` mapping), and its tests open the database after `confine`.
- **Weighed:** a SQLite crate under `crates/`, excluded from `mobile-targets` with a reason. The glue would be reusable, but the job would lose its guarantee that every `crates/*` library builds for mobile.

### What stays open at PRF-5

- **The account reservation lock** is main's until APR-6: the core takes main's word that a `void` or `retire` runs under it.
- **Swarm feed references** are main's until 0015: `accounts.remove` refuses on the references main passes.
- **A phone account's proof** reaches main through the chrome renderer, which runs the phone session (`wallet/remote/bridge.js`). A compromised chrome can answer main's challenge with a key it holds and get a `matched` phone record, which can then own a Safe. `add_remote` being shell only keeps main's check; it doesn't close that.
- **Main's inputs** to the shell-only methods (the address a Ledger showed, a Safe's predicted address, a verified deployment) are its word, as Stage 1 trusts main (0001).
- **Payment rows' display fields** (`to_address`, `amount`, `asset`, `origin`, `metadata`) come from the renderer through main, and the send's token doesn't bind them.
- **The repoll timers and the provider registry** stay main's.

## 5.3 One core, several profiles (Q15)

**Proposed: one core per profile while Electron runs one main per profile. One shared core for all open profiles only once Chromium runs them all in one process. The core gains the profile dimension now.**

- **Why not one core for all now:** Electron's profiles are separate processes, so a shared core would need a rendezvous: a socket or a named pipe that the second main can find. Any process of the same user could find it too. A token for it would sit in a file the same user can read. 0001's property, "only the parent holds the pipe", would be gone, and with it the reason a same-user process can't ask the core to sign. Under Chromium there is one parent again, and the pipe works for every profile.
- **The transport stays a pipe** (0001's stdin and stdout frames) in both stages. No socket, port or token, ever.
- **Per profile,** in one core:
  - the vault and its gate;
  - the lock state with its revocation epochs, auto-lock timer and throttle counter. A lock of one profile never touches another's;
  - the derived-key caches;
  - the stores and their writers;
  - the secrets file and its key-store items;
  - the node journals and `node_roots`, and 0012's `grant_root`;
  - the chain and naming configuration that comes from the profile's settings.

  Only the process, the transport, the threads and the code are shared.
- **In the protocol:**
  - `profile.open { user_data_dir, identity_dir, node_roots, grant_root, … } → { profile }` takes the profile's gates and returns a small handle;
  - `profile.close { profile }` locks the profile's vault, drops its caches and releases its gates;
  - `Context` (`fc-protocol/src/message.rs`) gains `profile`. Every profile-scoped method requires it, events carry it, and a request for a profile not open is refused (`no_profile`).
  - All of this is **protocol 3**. `profile.open` and `profile.close` are rows marked `"protocol": 3` in `protocol/schema.json`, as 0009 marked its protocol-2 rows.
- **In Stage 1** `serve`'s `--data-dir` still names the one profile, opened at start as today, and `core.hello`'s answer carries its handle. The core refuses `profile.open`, except under the test build's flag. PRF-8's tests run two profiles over one pipe: a lock, an unlock, a throttle and a failed write in one leave the other as it was.
- **The rollout, in both directions:** the core keeps protocol 2 beside 3, as it kept 1 beside 2 while 0009's step 6 was built.
  - **At protocol 2,** nothing changes for today's browser: a request names no profile and means the one `serve` opened, a request that carries `profile` is refused (`invalid_argument`), `profile.open` and `profile.close` are unknown, and events carry no `profile`.
  - **The handshake:** main offers `core.hello { protocol: 2, max_protocol: 3, … }`. A core from PRF-8 on answers at 3, with the handle. An older core reads `protocol: 2` and ignores `max_protocol`, as it ignores every hello field it doesn't know (`HelloParams`, `serve.rs:608–625`), and answers at 2. Main speaks the version the answer names.
  - So the current browser runs on the new core at protocol 2, and the new browser on the previous core at 2. Only a pair that both speak 3 sends handles.
  - **Protocol 2 goes** in a follow-up core PR once a browser release on `main` speaks 3, as 0009's follow-up removed protocol 1.
- **Stage 2's open question,** left to it: a crash takes every profile's unlock state with it, and a confined core can't widen its grants for a profile opened later ([D7](#effects-on-0010-and-d7)).

## 5.4a The key store and the quick-unlock re-wrap (Q13a, Q13b)

### The trait

`fc-keystore`, a logic crate (AGENTS.md rule 2: storage comes in as a trait). It builds for iOS and Android, and `freedom-mobile-ffi` implements the trait in Swift and Kotlin through UniFFI callback interfaces (UniFFI 0.32, rule 7).

```rust
pub enum Policy { Unattended, UserPresence }

pub trait KeyStore {
    /// What this device offers, asked once per profile open.
    fn capabilities(&self) -> Capabilities;
    /// Makes a fresh 32-byte wrapping key where it is kept, under `policy`,
    /// and returns it with what the secrets file stores: an item
    /// reference, or an OS blob.
    fn create(&self, policy: Policy, label: &Label) -> Result<(WrapKey, Sealed), KeyStoreError>;
    /// Opens it. `UserPresence` asks the user, with `reason`.
    fn open(&self, sealed: &Sealed, reason: &Reason) -> Result<WrapKey, KeyStoreError>;
    /// Removes the item. A missing item is success.
    fn forget(&self, sealed: &Sealed) -> Result<(), KeyStoreError>;
}

pub enum KeyStoreError { NotFound, Cancelled, Unavailable, Invalidated, Denied, Backend(BackendError) }
```

- **Creating, not storing a given key:** the macOS Keychain and the Secret Service store an item, DPAPI returns a blob, and Android Keystore keeps a key and encrypts with it. `create` and `open` cover all of these. The key is made where it is kept, in the helper on desktop ([The helper](#the-helper-freedom-cored-keystore)), so it reaches the core only sealed to it.
- **Replacing a key** is three calls: `create` a new one, rewrite every entry under it in one atomic write of the secrets file, which also moves the old one into the file's `forget` list, then `forget` the old one.
- **Only wrapping keys** go to the OS: at most two in use per profile, one per policy. An item the profile no longer uses stays named in a file on disk until a `forget` of it succeeds, and a profile's secrets file names at most four items in all ([Forgetting an item](#forgetting-an-item)). `WrapKey` zeroizes on drop and has no `Debug`, `Display`, `Serialize` or `Clone` (rule 3).
- **The secrets file** (`identity/secrets.json`, 0600, 0001's atomic write):

  ```json
  { "version": 1,
    "keys": { "unattended": { "backend": "macos-keychain", "item": "<32 hex>", "sealed": null,
                              "pending": null } },
    "forget": [ { "backend": "macos-keychain", "policy": "user_presence", "item": "<32 hex>" } ],
    "entries": { "<name>": { "key": "unattended", "nonce": "<base64, 12 bytes>",
                             "ciphertext": "<base64>", "binding": { … } } } }
  ```

  Each entry is AES-256-GCM (`aes-gcm`, rule 7) under its key. The associated data is `freedom-secrets/1`, the entry's name and its binding's canonical JSON, so an entry moved to another name or another binding doesn't open. Nonces come from the core's RNG and are never reused under a key.

  `sealed` is what the backend hands back for the file to keep: DPAPI's blob on Windows (`"backend": "dpapi"`), and `null` for the Keychain and the Secret Service, which keep the item and find it by its id ([DPAPI's blob](#dpapis-blob)).
- **Items are named by a random per-profile id,** recorded in the file, not by a path. A profile moved or renamed keeps them. A copy on another machine finds none, and each secret falls back: Bee's password is injected again (#946's path), quick unlock turns off, and RPC API keys must be entered again. Deleting a profile records its items in the app's forget file before the catalog entry goes, and main forgets them right after, or at the next start of any profile ([Forgetting an item](#forgetting-an-item)).

### Backends and dependencies

| OS | `Unattended` | `UserPresence` | Code |
|---|---|---|---|
| macOS | a generic-password item in the login keychain, its access list the signature of `freedom-cored`, the binary the helper runs | the data protection keychain with `SecAccessControl` (`userPresence`), once the core can carry the entitlement | **`security-framework` 3.7** (MIT OR Apache-2.0), pinned exactly: its `passwords` and `access_control` modules. Its unsafe stays inside it, as D6 accepted for `landlock`. Hand-written FFI would rebuild Core Foundation dictionaries call by call |
| Windows | DPAPI, `CryptProtectData` with no UI, its blob kept in the secrets file and its entropy built from the item's id ([DPAPI's blob](#dpapis-blob)) | Windows Hello (`KeyCredentialManager`), only if Q13b says so | **`fc-sys`** (rule 6): `CryptProtectData`, `CryptUnprotectData` and `LocalFree`, each a safe function with its `SAFETY` comment, through `windows-sys`, which `fc-sys` already uses. Hello is WinRT, which needs the `windows` crate (0.62, MIT OR Apache-2.0); not added unless Q13b says Windows too |
| Linux | an item in the Secret Service's default collection | none: no OS biometric binding exists | **`secret-service` 5.2** (MIT OR Apache-2.0), pinned exactly, with `rt-async-io-crypto-rust`, through its blocking API. It brings `zbus` (MIT) and an async-io executor, but no tokio. The step measures the binary's growth, and `cargo deny` must pass. The alternative is `dbus-secret-service`, which links the system's libdbus |
| iOS, Android | Keychain, Android Keystore | Keychain access control, `setUserAuthenticationRequired` | the mobile apps, behind the trait |

- **Not `keyring`** (4.2): it is a facade over the same three. It has no access-control policy and no DPAPI blob of our own, and it would be wrapped again.
- **No backend is ever faked.** A Secret Service that doesn't answer, or no keyring, is `Unavailable`: each secret stays where it is today, with today's owner-only file. That is #946's `v10` rule, kept: the core has no fixed-key fallback.
- **When the OS is asked:**
  - **Unattended keys** are opened when the profile opens, but only if the secrets file holds an entry. On desktops that log in without a password, gnome-keyring asks to be unlocked then. #946 notes the same prompt at Ant's start.
  - **A key is created** when the first secret under it is written: `quick_unlock.enroll`, a `vault.create` or `vault.import` with `quick_unlock: true`, an RPC API key added, a Bee identity written or adopted ([5.4c](#54c-bees-keystore-password-q16)). **It is forgotten** when it is replaced, when quick unlock is disabled or the vault deleted and no other entry is under it, or when the profile is deleted ([Forgetting an item](#forgetting-an-item)). These come at any time while the profile is open, long after D7 has confined `serve`.
  - **`UserPresence`** asks at each quick unlock.
- **The entitlement:** biometric access control needs the data protection keychain, which needs the process to carry a keychain-access entitlement authorized by a provisioning profile (TN3137). `freedom-cored` is a bare executable in the app's resources. PRF-1 spikes signing it as a helper bundle with that entitlement. Until that passes, `UserPresence` is `Unavailable` on macOS, and Touch ID stays main's prompt in front of the core, as today.

### The helper, `freedom-cored keystore`

**Proposed: on every desktop OS, each key-store call runs in a one-shot process that main starts for it. `serve` never calls a key store itself.**

- **Why:** `create` and `forget` are runtime calls (above), and D7 confines `serve` for its whole life.
  - **Linux:** `secret-service` 5.2's blocking API opens a session-bus connection at each connect. 0010 keeps the session bus from every confined process, since it can start programs (0010's threat list; seccomp's socket rule). A connection kept open across `confine` would give a compromised core the bus for the rest of its life.
  - **macOS:** the Keychain needs the Security server's Mach services. They reach every item of the user's keychains that the core's signature may use, not only Freedom's.
  - **Windows:** DPAPI calls the local security authority, which 0010's restricted token (D4) may not reach.
  - One path on every OS keeps `serve`'s confinement free of key storage.
- **The call:** the core's desktop `KeyStore` sends main `shell.keystore { op, policy, item, sealed?, reply_key?, reason? }`, as its HTTP goes through main's `shell.*` executors (0004). `op` is `create`, `open` or `forget`. `item` is the key's random id (32 hex digits), `reply_key` is there for `create` and `open` only, `sealed` is DPAPI's blob, there for an `open` on Windows only ([DPAPI's blob](#dpapis-blob)), and `reason` is one of a fixed list (`quick_unlock`, `export`) for which main supplies the text the OS shows. Main checks the form, then runs `freedom-cored keystore --op <op> --policy <policy> --item <id> [--reply-key <base64>] [--reason <kind>]`, one at a time per profile, and relays its answer. The helper's stdin carries `sealed`'s bytes, and is the null device for every other call. Main also runs `forget` itself, with no core, for a deleted profile's items ([Forgetting an item](#forgetting-an-item)).
- **The secret transfer:**
  - The core makes an X25519 key pair for each request and keeps its private half. `reply_key` is the public half.
  - For `create`, the helper makes the wrapping key from the OS's RNG and stores or seals it in the OS. For `create` and `open`, it returns the key HPKE-sealed to `reply_key`, in `fc-seal`'s suite, as `nodes.seal_radicle_key` seals for the Radicle service. The associated data is `freedom-keystore/1`, the op and the item id, and the SHA-256 of the answer's `sealed` when it carries one. `forget` returns nothing secret.
  - So main relays only ciphertext, and no wrapping key crosses argv, stdin or main's heap. Stdin brings the helper at most one DPAPI blob. The helper zeroizes its copy of the key before it exits.
- **The answer:** one JSON line on stdout, at most 4 KiB. It is `{ ok: true, sealed?, key? }`, where `sealed` is a Windows `create`'s new blob, or `{ ok: false, error, reason? }` where `error` is `not_found`, `cancelled`, `unavailable`, `invalidated`, `denied` or `backend`, mapped onto `KeyStoreError`. Anything else is `Backend`: no line, a longer one, an exit without an answer, or a `key` that doesn't open under the request's key, op, item and the answer's blob.
- **Deadlines:** main kills a helper after 60 s for `create` and `open`, which may wait on gnome-keyring's unlock prompt or on Touch ID, and after 10 s for `forget`. The core then gets `Unavailable`, with `reason: "timeout"`.
- **The failure contract:**
  - Before a `create`, the core writes the new item's id into the secrets file as `pending` under its policy. It makes the key the file's own only after the helper has answered and the entries under it are written, in one atomic write.
  - A failure, a kill or a crash at any point therefore leaves the file's committed keys and entries as they were. The next profile open moves a `pending` item that never committed into the file's `forget` list and forgets it, which also covers a helper killed after the OS stored the item and before it answered.
  - `forget` runs only once the file no longer uses the item, and only while a record still names it: the file's `forget` list, or, for a deleted profile, the app's forget file. A failed `forget` leaves the record, and the call is tried again ([Forgetting an item](#forgetting-an-item)).
  - Nothing is deleted on a failed `open` ([Failure modes](#failure-modes)).
- **The helper's own limits:** it runs no program, and reads or writes no file. It makes one call to the OS's key store and exits. Its environment is the core's cleared one plus what the backend needs: `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` on Linux. How far it confines itself beyond refusing child processes is the qualification gate's to show, per OS, since it must keep its one channel to the key store.
- **Mobile** implements the trait in the app's own process. There is no helper there.

### DPAPI's blob

**Proposed: on Windows the secrets file keeps DPAPI's blob, and the core sends it back with each `open`. The helper reads it on stdin, and DPAPI's entropy is built from the item's id.**

- **Why it travels:** DPAPI keeps nothing in the OS. `CryptProtectData` returns a blob, and only that blob, with the same entropy, opens the key again through `CryptUnprotectData`. The helper reads no file, so the blob has to come with the request.
- **Only on Windows, only for `open`:**
  - **A replace** is a `create` and the write that drops the old blob. **A `forget`** of a DPAPI key makes no call ([Forgetting an item](#forgetting-an-item)). Neither needs the blob.
  - **macOS and Linux** need nothing of the kind: the Keychain and the Secret Service keep the item and find it by its id, for `open` and `forget` alike. Their `sealed` is `null`, and no request carries one.
  - **Windows Hello,** if Q13b adds it, would need its own design of what the file keeps. It would travel the same way.
- **Main relays it** without the key: the blob is ciphertext that only the user's account opens, and main can read it in the file anyway.
- **Not in argv:** Windows lets other processes of the user read a process's command line, and process-creation auditing (event 4688), Sysmon and endpoint tools write it to logs. The item id is already in argv, so the blob there would put everything `CryptUnprotectData` needs into those logs. A replace or a `forget` drops the blob from the file but not from a log, and DPAPI would still open it. Argv keeps only fixed-form fields, which open nothing on their own.
- **On stdin instead:** for a DPAPI `open`, main starts the helper with stdin a pipe, writes the blob's decoded bytes, and closes it. Every other call gets the null device. The helper reads stdin to its end before any OS call, at most 1 KiB and one byte more, so it sees an oversized blob without reading all of it. The request's 60 s deadline covers the read.
- **The bound is 1 KiB, decoded.** DPAPI's blob for a 32-byte key with no description is a few hundred bytes. Its size follows the algorithms Windows picks, so it isn't fixed, and the bound leaves room.
- **Checked three times:**
  - **The core,** reading the file: a `dpapi` key's `sealed` is standard base64, padded, that decodes to 1 to 1024 bytes, and every other backend's is `null`. Anything else is out of form, as any field of the file, and nothing is sent with it.
  - **Main,** before it starts a helper: an `open` under `unattended` on Windows needs `sealed`, in the same form and bound, and no other request may carry one. A request that breaks either rule is refused.
  - **The helper:** a DPAPI `open` needs 1 to 1024 bytes on stdin, and every other call none. Anything else is `{ ok: false, error: "backend", reason: "bad_request" }`, with no OS call. It doesn't parse the blob: `CryptUnprotectData` checks it.
- **The entropy is built from the item's id.** One function of the helper builds it from `--item`, for both calls: the ASCII bytes `freedom-keystore/1 dpapi`, then the id's 16 bytes. `create` runs with the `pending` id, and the write that commits the key stores that same id as the key's `item`, beside its blob, so every `open` passes it again. Both calls pass `CRYPTPROTECT_UI_FORBIDDEN` and no description, in the user's scope.
  - **Why the item's id:** each request already carries it, in a fixed form that main checks, and the HPKE associated data binds it. It lives as long as the key, a replace draws a new one, and it sits in the same record as the blob, so the two can't drift apart. A blob moved under another key's record doesn't open.
  - **Why not the profile's id,** as earlier drafts had it: it would be another field in each request for main to check, and its value is the catalog's, not the secrets file's. The Windows key would then open or not by what the catalog calls the profile, while the Keychain and Secret Service items open by the file's ids alone.
  - **Why the label:** it keeps the helper to Freedom's own blobs. A blob made under other entropy, or none, doesn't open under it, so a compromised `serve` can't have the helper open another program's DPAPI blob. That matters once a restricted token keeps `serve` itself from DPAPI (D4).
  - **Not a secret:** the id is in the file beside the blob, and in argv. The entropy binds a blob to its record and to Freedom. Neither it nor DPAPI hides the key from another process of the user ([Threat model](#threat-model)).
- **`create`'s answer** carries the new blob as `sealed`, in base64, beside the sealed `key`. It is ciphertext, so it isn't sealed again, but the HPKE associated data covers its SHA-256, so a key relayed beside another blob doesn't open. The core checks the blob's form and bound as for the file's, then commits it with the `pending` id. The answer stays well under the helper's 4 KiB.
- **What comes back sealed** is unchanged: only the wrapping key, sealed to `reply_key`. The blob comes in on `open` and goes out on `create`, and is never HPKE-sealed.
- **A blob DPAPI refuses** is `invalidated`: one changed or cut short, one sent with another item's id, or one from another account, or from a machine the account's DPAPI keys don't reach. `CryptUnprotectData` doesn't tell these apart. A security authority it can't reach is `unavailable`. `fc-sys` maps Windows' error codes onto the two, and PRF-7's tests pin the mapping. At an open, `invalidated` deletes nothing ([Failure modes](#failure-modes)), and each secret under the key takes its fallback path, as for a copy that finds no item.

### Forgetting an item

**Proposed: an item stays named in a file on disk until a `forget` of it succeeds. While its profile exists, that file is the profile's secrets file. Once the profile is deleted, it is a forget file beside the catalog.**

- **The `forget` list** of the secrets file holds `{ backend, policy, item }` for each item the profile no longer uses. The write that stops using a key adds it there, in the same atomic write:
  - **a replace:** the write that commits the new key and its entries moves the old key into `forget`;
  - **quick unlock disabled:** the write that removes the entry moves its key, if no other entry is under it;
  - **the vault deleted:** the secrets file joins `vault.delete` in one journaled operation ([The vault delete's journal](#the-vault-deletes-journal)), with the entry removed and its key moved the same way. A crash before the journal commits leaves the vault, the entry and the key in use; after it, none of them, and the key in `forget`;
  - **a `pending` key that never committed:** moved into `forget` at the next open.

  The core then asks main for the `forget` through `shell.keystore`. It writes the file without the record once the answer is `ok` or `not_found`. Anything else leaves the record.
- **Every id is in the file before the OS holds the item,** since `pending` is written before `create` runs. It leaves the file only after its `forget` succeeds, or, at a profile delete, once the forget file holds it. So the committed secrets file names every item of the profile, whatever journal is pending, and a delete can read them there.
- **The forget file,** `profile-registry.json.forget` at the app root, holds deleted profiles' items:
  - **Its format:** `{ "version": 1, "deleted": [ { "id", "dir", "items": [ { "backend", "policy", "item" } ] } ] }`. It follows the catalog's rules: written only by the catalog subcommands, under the catalog's write lock, with 0001's durable write and mode 0600, and read under 0001's rules (a regular file the user owns, no symlink, a size bound). Its temp files keep the same prefix.
  - **Why that name:** every build's default-profile delete spares names that start with `profile-registry.json.` (`isAppRootSharedEntry`, `profile-catalog.js:832–835`), builds from before this design included, and the catalog watcher ignores them (`profile-registry-watcher.js:64`). So a delete of the packaged default profile, by any build, keeps the file.
  - **The handoff in `profile delete`:** once it holds the target's gates, it reads the ids in the target's secrets file, in either layout: the keys in use, `pending` and `forget`. It writes them into the forget file as one record before the catalog changes. Then it removes the catalog record and the data as today, and its result lists the ids.
  - **A record counts once its profile is gone.** A `forget-list` or `delete` run that finds the catalog still listing the record's id at its directory, with a secrets file there that names an item, drops that item from the record without a `forget`. Either the delete stopped before the catalog changed, or the directory was imported again, and in both cases the profile's own file names the item. Every other item in the record is forgotten.
- **Who does what, and when it is tried again:**

  | The change | Records the item | Runs `forget` | Drops the record | Tries again |
  |---|---|---|---|---|
  | a replace, a disable, a vault delete, a `pending` left over | `serve`, in the secrets file, in the write that stops using the key | main's executor, through the helper, on `serve`'s `shell.keystore` | `serve`, after `ok` or `not_found` | `serve`, at the profile's next open (after the open's own key-store calls), and before a `create` that needs room |
  | a profile delete | `profile delete`, in the forget file, before the catalog changes | main, through the helper, for the ids in the delete's result | `profile forget-done`, after `ok` or `not_found` | main, at the next start of any profile under the same app root: `profile open` reports `forget_pending`, and after its first window main runs `profile forget-list`, the helper for each id, then `forget-done` |

  Main runs one helper at a time, each under `forget`'s 10 s deadline, and none on the startup path. Two mains draining at once do no harm: a `forget` of a missing item succeeds, and `forget-done` for an id no longer listed changes nothing. On macOS, the loser of two deletes of one item can get `errSecInvalidRecord` instead of not-found ([freedom-browser#1271](https://github.com/solardev-xyz/freedom-browser/pull/1271)). The backend retries such a delete once after 20 ms. A second one is answered `backend`/`status`, since a damaged record answers the same and may still hold the item. The drain keeps that record. The other main's `forget-done` clears it, or the next drain does, whose `forget` then answers `not_found`. Nothing retries on a timer.
- **An item already gone:** `not_found` counts as success, as the trait says, and the record goes. That covers an item the user removed by hand, a helper killed after the OS removed the item and before it answered, and a second drain. A record of a backend this OS doesn't have, from a profile copied from another OS, is dropped without a call, since its item isn't here. Each `create` draws a fresh 128-bit id, so a record never names a later item of its profile.
- **Windows:** DPAPI keeps no item in the OS. Dropping the blob from the file is the whole `forget`, so no record is made, and no blob is copied into one. The core's `forget` of a DPAPI key returns at once, with no `shell.keystore` call, and a DPAPI `forget` the helper gets anyway answers `ok` with no OS call. A `pending` DPAPI id left over is dropped at the next open the same way: its `create` left nothing in the OS ([DPAPI's blob](#dpapis-blob)).
- **The bounds:**
  - **A secrets file** names at most four items: the keys in use (at most one per policy), the `pending` ones and the `forget` list together. A `create` that would make a fifth first tries the `forget` list again. If that leaves no room, the `create` is refused with `key_store_unavailable` and `reason: "forget_backlog"`, and the secret takes the `Unavailable` path ([Backends](#backends-and-dependencies)). A replace's commit, a disable and a vault delete never need room: they move an item the file already names, and add none.
  - **An item record** is the three fields above, each of a fixed form: `backend` and `policy` from fixed lists, and `item` 32 hex digits.
  - **The forget file** holds at most 16 deleted profiles, with at most four items each, at most 8 KiB per profile and 64 KiB in all. A delete that would pass a bound is refused with `forget_backlog` before anything changes. Main then drains the file and asks once more, and if there is still no room the profile manager says why.
  - **A file past its bounds** is malformed, and nothing it names is forgotten. A malformed forget file is renamed aside under the same prefix and reported, as 0012 does with an unreadable file, and the next delete starts a new one.
- **What this doesn't cover:**
  - **A secrets file the delete can't read** (malformed, unreadable, or past its bounds): the delete goes on, since the user asked for it, and its result says `forget_unknown`. That profile's items stay in the key store, named by nothing.
  - **A profile deleted by an older build, or by hand,** goes with its secrets file, and its items stay. So no build lets the core make an item before its deletes go through `profile delete`: PRF-2, which adds main's executor, needs PRF-4 ([Migration](#migration)).
  - **A copy on this machine,** a profile directory copied into `Profiles/` and imported, names its original's items. A `forget` from either sends the other's secrets to their fallback path, as for a copy on another machine. On Windows each copy has its own blob and drops only that, so the other's key still opens. Telling the two apart would need a binding to the path, which a moved profile can't keep.
- **Mobile** keeps the same `forget` list and runs it in the app's process, at the same moments.

### The vault delete's journal

**Proposed: a vault delete with quick unlock's entry is one journaled operation, in 0001's multi-file steps but with a record of its own, `vault-delete-journal.json` in the identity directory.** It doesn't share 0001's `node-identity-journal.json`: those records are keyed by node, carry main's `op_id` for `nodes.op_status`'s done list, and are recovered under node gates, and a vault delete has none of those.

- **When:** only while the secrets file holds the `quick-unlock` entry. Without it the file doesn't change, and the delete is 0001's unlink. Either way the file must read. A secrets file that doesn't (malformed, past its bound, unreadable), or a staged or journal write that fails, refuses the delete with `storage` (`data.file: "secrets"`), and the vault stays.
- **The steps:**
  1. **Stage:** the secrets file as the delete leaves it (the entry removed, its key moved into `forget`) is written as `secrets.json.freedom-new`: exclusive create, 0600, fsync, read back through the handle that wrote it, directory flush.
  2. **Commit:** `vault-delete-journal.json` is written by 0001's single-file write. The vault's commit claim comes right before its rename, and that claim is the delete's commit point (0001: "before the journal write of a multi-file operation").
  3. **Install:** the secrets file first, then the vault, with a directory flush after each.
     - **The secrets file** is done if it already has the journaled digest. Otherwise the staged file, if it has that digest and is still the file hashed, is renamed over it.
     - **The vault** is done if it is gone, and removed if it has the journaled digest.
  4. **Finish:** the journal is removed, and the directory flushed.
- **The record:** `{ "op": "vault.delete", "files": [ { "target": "secrets.json", "staged": "secrets.json.freedom-new", "sha256": "<64 hex>" }, { "target": "identity-vault.json", "remove": true, "sha256": "<64 hex>" } ] }`. It has fixed names only, and no member the writer doesn't write. The vault's digest is that of the file the password opened.
- **The digest guard:** the vault is removed only while it is that file. Any other file at its name is left, so a journal never removes a vault written after it.
- **Recovery:**
  - **When it runs:** at start, before `core.hello` is answered, and in `freedom-cored recover`. It also runs first in every read of the vault and every secrets-file operation, which fail with `storage` while it can't finish.
  - **An install that fails after the commit** answers `{ durable: false }`, since the delete has committed, and leaves the journal for that recovery.
  - **One lock** serializes the delete and every recovery. Where both are held, it is taken after the secrets file's lock.
  - **At start,** a `secrets.json.freedom-new` that no journal names is removed, and so are the journal's temp files (0001's rule for leftover temp files).
- **A record that isn't exactly a writer's,** or one whose secrets file has neither the journaled digest nor a staged file with it, is renamed to `vault-delete-journal.json.corrupt`. The staged file is removed, and nothing else changes: the vault, the entry and its key stay together.
- **Downgrade:** a core from before PRF-1c reads none of these files, so a journal still pending leaves the vault and the secrets file as its install left them. The next core of this design finishes it, and removes the vault only if it still has the journaled digest. JS-backend builds that run `freedom-cored recover` finish it first.

### The re-wrap

- **PRF-1 (core):**
  - the helper with its macOS backend, and the core's desktop `KeyStore` over `shell.keystore`;
  - `quick_unlock.enroll { password }` checks the password against the vault, sharing 0001's throttle. It then writes the `quick-unlock` entry, bound to the vault file's SHA-256 (today's binding, without the path), under `UserPresence` where available and `Unattended` otherwise.
  - `quick_unlock.unlock {}` unlocks with it, so the password stays in the core. `quick_unlock.export_mnemonic` and `export_private_key` are the Touch ID exports.
  - `quick_unlock.status` and `quick_unlock.disable` complete the set.
  - `vault.create` and `vault.import` gain `quick_unlock: true`. That writes the entry before the vault commits, bound to the new vault's digest, so a Quick Setup vault never exists without its credential. A crash between the two leaves an entry that names no vault, which the core removes at start ([The re-wrap's two entries](#the-re-wraps-two-entries)).
  - `vault.change_password` writes the new vault and the re-wrapped entry as one operation ([The re-wrap's two entries](#the-re-wraps-two-entries)).
- **PRF-2 (browser):**
  - Main's `shell.keystore` executor, which checks the request and runs the helper.
  - At the next Touch ID unlock or export, a profile with only `quick-unlock.dat` goes through it once, as today. Main then sends the password it unsealed to `quick_unlock.enroll`. Later unlocks call `quick_unlock.unlock` behind main's Touch ID prompt.
  - Quick Setup prompts for Touch ID first, then creates with `quick_unlock: true`, and writes no `quick-unlock.dat`.
  - **`quick-unlock.dat` is deleted once the credential is enrolled** (the user's decision of 2026-11-15, which replaces "left byte for byte, for older builds"):
    - **When:** only after a confirmed enroll. The enroll succeeded, and `quick_unlock.status` then reports the credential enabled, which the core answers only for an entry bound to the vault file on disk. A failed enroll, or one the status doesn't confirm, keeps the file for the next Touch ID use.
    - **How:** under the vault's mutation queue, like the enroll before it, so no vault is replaced between the status and the delete. The delete is one unlink through the identity directory's handle, followed by an fsync of the directory.
    - **A crash between the enroll and the delete** leaves the file beside the core's credential. The next unlock or export goes through the core and then deletes it, under the queue and with the status confirming.
    - **A password change** on a profile with only the file enrolls the current password first, deletes the file once that's confirmed, and then changes the password. The re-wrap carries the credential across. An enroll the status doesn't confirm, or a delete that fails, refuses the change under the queue, before anything is written.
    - **Enable** enrolls and writes no file. A file an older build left goes once the status confirms.
    - **Where the core has no key store for quick unlock** (Linux and Windows), nothing enrolls, and main never deletes the file on its own.
    - **Disabling is the one exception, on every platform** (Linux and Windows included): the user asked for quick unlock off, so the file goes too, if one is still there. It goes first, before the core's credential: the same unlink, then the directory's fsync, and only then `quick_unlock.disable`. If either step fails, the disable is refused and the core's credential stays, so a crash can't bring the file back after the credential is gone.
    - **The cost:** after the delete, an older build finds no file and asks for the password. A Quick Setup user has no password, so only the recovery phrase opens the vault there ([Rollback and downgrade](#rollback-and-downgrade)).
  - The release before any shell switch prompts each macOS profile that has a vault but no core credential for Touch ID once, to enroll. A profile never opened in that window keeps only its recovery phrase. The design states that risk; it doesn't hide it.
- **The policy for a Quick Setup vault is `userPresence`,** never `biometryCurrentSet`. The latter destroys the item when a fingerprint is added, and a Quick Setup user has no other copy of the password. Which fallback `userPresence` may use is the [open question](#open-questions) on the Mac's password.
- **The core never reads `quick-unlock.dat`.** Its ciphertext is Electron's: Chromium's keychain item for the app, and the app's signature. Reading it would mean reimplementing `safeStorage` and borrowing the app's keychain access.

### The re-wrap's two entries

**Proposed: a create or import with `quick_unlock: true`, and a password change on a vault with quick unlock, write the new vault's credential before the vault commits, under a second name while the first still holds the old vault's. The vault's rename is the one commit point, and no journal is needed.**

- **The names:** `quick-unlock` and `quick-unlock.next`. Each is the vault password, bound to `{ "vault_fingerprint": <sha256 of the vault file> }`, under the policy's key, as enroll writes it. The credential for a vault is whichever of the two is bound to that vault file's digest, and `quick_unlock.unlock`, the exports and `status` read it there. Once a re-wrap has finished, the file holds only `quick-unlock`.
- **The steps:**
  1. **Seal:** the new vault file is made in memory, in 0001's envelope, and its SHA-256 taken.
  2. **Stage:** the new vault's credential, bound to that digest, is written as `quick-unlock`. When `quick-unlock` holds the credential of the vault being replaced, it is written as `quick-unlock.next` instead.
     - **The key:** the policy's key if it opens. Otherwise a new key, through the `pending` write, `create` and the commit, as for enroll.
     - **A dead key** (`not_found`, `invalidated`) is replaced as enroll replaces it: its entries can't be re-wrapped, and leave in the `pending` write. The old vault then has no credential, as it had none that opened.
     - **The other name,** if it isn't the old vault's credential, names no vault, and leaves in the same write.
  3. **Commit:** the vault's write (0001). Its claim, right before the rename, is the operation's commit point.
  4. **After the commit,** one write leaves only `quick-unlock`, bound to the new digest, and the old vault's entry goes. A credential staged as `quick-unlock.next` is sealed again under `quick-unlock` with the key the job already holds, so no key-store call follows the commit. A failure of this write is logged, not answered, since the commit has happened.
  5. **After a failure before the commit** (the vault's write failing, or its claim refused), one write takes the staged entry off again, and its key goes into `forget` if nothing else is under it.
- **Why no journal:** the binding ties each entry to one vault file. Until the rename the file holds the old vault's credential, and from before it the new one's, so whichever vault is on disk, its credential is there. A crash leaves at most one other entry, which names no vault, and the start rule removes it. The vault delete needs its journal because it removes the credential together with the vault ([The vault delete's journal](#the-vault-deletes-journal)). The re-wrap only adds one before it replaces the vault.
- **The start rule** covers both names: each entry bound to anything but the vault file's digest, or with no vault there, is removed, and its key goes into `forget` if nothing else is under it.
  - **A crash before the rename** leaves the old vault with its credential.
  - **A crash after it** leaves the new vault with its own. That is `quick-unlock.next` until the next write that touches quick unlock: an enroll or a re-wrap folds it into `quick-unlock`, and a disable or the vault delete removes both names.
- **Refusals,** each before anything is written, with the vault and the file as they were:
  - `quick_unlock: true` where the key store offers no policy: `key_store_unavailable` (`unsupported`), after 0001's parity checks;
  - a secrets file that doesn't read (malformed, past its bound, unreadable): `storage` (`data.file: "secrets"`). That covers a create or import with `quick_unlock: true`, and every password change, which can't tell otherwise whether the vault has a credential;
  - a key-store refusal: `key_store_unavailable` (with `timeout`, `forget_backlog`, …) or `key_store_cancelled`;
  - a new password longer than the 1 KiB an entry holds, while quick unlock is on: `invalid_argument`.

  A password change on a vault without quick unlock changes nothing in the file, and asks the key store nothing.
- **Callers:** `vault.create` and `vault.import` keep 0001's, `chrome` and `shell`. Their caller supplies the password the credential holds, so the credential gives it nothing it didn't have.
- **Downgrade:** no release before PRF-1c-2 writes quick unlock's entries, and older builds don't read `secrets.json`.

## 5.4b The Freedom directory (Q12)

### What moves

**Proposed: every Freedom-owned entry of a profile into `<profile>/freedom/`. The shell's entries stay at the root.**

| Moves into `freedom/` | Stays at the root |
|---|---|
| `identity/` (vault, metadata, secrets, node journal); every set-A and set-B store; `wallet-intents.jsonl`; `payment-history.sqlite`, `publish-history.sqlite`; `ant-data/`, `ipfs-data/`, `tor-data/`, `myotis/`, `bee-data/`; `run/` (antd's hand-off) | Electron's and Chromium's files (`Local State`, `Preferences`, `Cookies`, `Local Storage/`, `IndexedDB/`, …); set C; `profile.json`; `profile-open` and `profile-open.lock` (the lock's format); the focus hand-off files; `crash-reports/`; `.migrated-from-freedom-browser`; a non-catalog `radicle-data/`, since `freedom/` would push its control socket past the 100-byte limit (`profile-paths.js:259–264`) |

- **An explicit list in `fc-profile`,** pinned by vectors, decides what moves. A name the list doesn't know stays where it is.
- **Overridden components** (`FREEDOM_IDENTITY_DATA`, …) aren't moved: they live elsewhere.
- **The packaged default profile** gets `<appRoot>/freedom/`, and its delete removes it with the rest.
- **Why move at all:**
  - Stage 2's Chromium puts `Local State` and its profiles in its user data directory, and its importer moves Electron's site data. Freedom's files mixed in among them would be guessed at by name.
  - One subtree is one gate, one grant for D7, one protected root and one unit to back up.
  - It is what the roadmap's Stage-1 definition of done asks: Freedom data in a shell-neutral layout.

### The move

`freedom-cored profile migrate --profile-dir <dir> --lock-dir <dir> [--dev]`, run by main with `spawnSync` after `app.setPath` and **before main starts `hold-profile` or takes its own profile lock**. Main runs it only when `profile open` reported `layout: "pending"`, or, from PRF-9, `"root"`. So it also comes before the core's `serve`, any node and any store.
1. **Its own exclusion, for the whole run:**
   - **The profile gate first,** so a new build sees the profile open.
   - **Then the profile lock, in today's format.** It takes `profile-open.lock` as proper-lockfile does, with `mkdir`. A stale lock is taken over, since holding the gate shows that no live new build has the profile. It refreshes the mtime every 10 s (1 s in dev) from a thread that does nothing else, and checks at each refresh that the mtime is still the one it set. So an older build sees the profile open for the whole run, however long a copy or a held Windows rename takes, and whatever main is doing.
   - **The core's gate and freedom-ipfsd's,** on both the old and the new paths. A gate's name is the digest of a canonical path, so both names are held.
   - **A lock or gate held by another process** ends the run at once with `busy` (exit 75), with nothing changed, and main hands over or reports the profile busy, as for a fresh lock.
   - **It lets go** only after the marker and cleanup, or after a rollback. Main then starts `hold-profile` and takes its own lock, as at any start. A launch that takes the profile in the moment between finds it settled, in one layout or the other.
   - **If its lock is compromised** (the process was frozen past 30 s and another build took the lock over), it changes nothing more and exits 74 with `lock_lost`. The journal stays for the next start. No lease can cover a frozen holder, proper-lockfile's included.
2. **The journal:** `freedom/.move.json` lists the entries present, in order. It is written and synced before the first change.
3. **Each entry is one rename** into `freedom/`. On Windows, a rename refused while an indexer holds the entry (`EPERM`, `EACCES`, `EBUSY`) is retried, as `profile-catalog.js:1053–1086` retries its fence: 10 times, 100 ms apart.
   - **An entry on another device** is copied to `freedom/<name>.moving`, synced, then renamed to its name. That is the roadmap's copy-then-rename. Its source is removed only after step 5.
   - **A symlink** is moved as the link, not its target.
   - **A SQLite database** is first checkpointed and closed (`PRAGMA wal_checkpoint(TRUNCATE)`). A `-wal` that is still not empty stops the move: committed rows would be left behind.
4. **The placeholder:** a regular file named `identity` takes the old directory's place, saying where the data went.
5. **The marker:** `freedom/layout.json`, `{ version: 1, moved_at, by }`, is written durably.
6. **Cleanup:** the journal and the copied sources are removed.

- **Before the marker, a failure rolls back:** the moved entries are renamed back, so the profile opens in the old layout and the move is tried at the next start.
- **After the marker, it rolls forward:** a start that finds the journal and the marker finishes the cleanup.
- **A journal that doesn't parse** stops the profile from opening (exit 74, with a clear message). The core doesn't guess which entries moved.
- **New profiles** created by a build from PRF-9 on start in the new layout.
- **Why the move holds its own lock** rather than running under main's:
  - **`spawnSync` under main's lock** stops main's refresh timer ([Profiles](#profiles)). A run past 30 s lets an older build take the lock over, and the gates the move holds mean nothing to that build.
  - **An asynchronous child under main's lock** keeps the refresh going, but main's top level reads stores before the first window (`loadSettings()`, `index.js:546`) and would race the move. A main that dies or stalls mid-move would also let the lock lapse while the child goes on.
  - **Its own refresher** depends on neither. And `spawnSync` is safe here, since main holds no lease while it waits. A long move shows nothing on screen, as today's `migrateUserData` doesn't (`index.js:79–81`).

### Readers, and the downgrade

- **The reader release (PRF-4):**
  - Every path getter in main and in the core resolves the profile's Freedom root once: `freedom/` if `freedom/layout.json` exists, the root otherwise.
  - When `profile open` reports a journal (`layout: "pending"`), main runs `profile migrate --finish-only` in the same place and under the same exclusion. It completes or rolls back the move it finds, and starts none.
  - It ships long before the move, and the move ships as the last Stage-1 step, just before Stage 2 needs it.
- **Downgrade, [Q12](#open-questions):**
  - **To a build from the reader release on,** everything works, both ways.
  - **To an older build,** the move is one-way. That build looks for its stores at the root and finds none, so it starts like a fresh profile.
  - **The placeholder protects the identity there:** an older core can't use a file as its identity directory and refuses to start, and a JS-vault build's write there fails. So the older build can't make a second vault, inject a second Bee identity, or show the user a wallet that isn't theirs. PRF-9's tests check this against the shipped cores. Its other stores start empty at the root.
  - **Back on a new build,** root entries that appeared after the move are moved, unmerged, into `freedom/downgrade-<n>/`, and the browser says so. Nothing is merged and nothing is deleted.
- **0012's Q10 then reads:** older builds read the grant files at every step up to the move, and every build from the reader release on reads them after it.

## 5.4c Bee's keystore password (Q16)

**Proposed: the core keeps it in the profile's secrets file, and writes antd's one-use password file itself.**
- **`nodes.write_identity`'s Bee form,** where the profile's `Unattended` key is available:
  - it writes `keys/swarm.key` and the `bee-keystore-password` entry, bound to the keystore's SHA-256 as #946's seal is;
  - it writes `config.yaml` with no `password:` line, as #946's `createBeeConfig(dataDir, null, …)` does;
  - it removes any old seal, all as one journaled operation (0001's *Multi-file writes*).

  Where the key isn't available, it writes `config.yaml` with the password, as today.
- **At each Ant start,** before main spawns antd:
  - main calls `nodes.bee_handoff { data_dir }`. The core checks the entry's binding against `swarm.key` as it is now, writes the password to a new 0600 file in the profile's hand-off directory (`run/ant-handoff/`, 0700), and returns its path;
  - main passes it as `--password-file`, and calls `nodes.bee_handoff_done { handoff }` once the API answers or antd exits. The core removes the file;
  - the core sweeps orphans at each profile open.

  The password never enters main's heap or argv.
- **`config.yaml` is no longer a secret file** once the password is out of it. Main still rewrites it at each start, with the ports and endpoints, but `ensureConfig` must never write a `password:` line where the entry exists.

### #946's seal, read by the core

At the first Ant start in PRF-7's release, a profile that has a seal and no core entry is adopted:
1. Main reads `keys/keystore-password.sealed` and opens its ciphertext with `safeStorage`'s asynchronous API, as #946 does.
2. Main sends the password and the record to `nodes.adopt_bee_password { data_dir, record, password }`.
3. **The core checks the record:**
   - it parses `{ version: 2, ciphertext, keystoreSha256 }` exactly as `readSeal` does: version 2, a string ciphertext, a digest of 64 lowercase hex or null; anything else is not a seal;
   - its digest must equal the SHA-256 of `swarm.key` as the core reads it now;
   - one scrypt run with the password must open `swarm.key` to its own `address`.
4. **Then it writes the entry.** It leaves the seal in place, for SEC-3f-era builds. The next identity write removes the seal, which #946 treats as a broken pair anyway.

- **A profile with a `password:` line,** from integration before SEC-3f, or with no keyring, is adopted the same way from the line, decoded as #946's serde_yaml rules decode it (its fixture becomes a vector). The line is then removed.
- **A seal main can't open** (a reset keychain, a copied profile) takes #946's path: "Swarm key needs re-injecting: unlock your vault". The re-injection is a core write as above, and its identity check is #946's: the keystore's `address` must be the vault's derived Swarm address.

### Windows handle I/O (#963)

`fc-sys` gains, each one FFI call behind a safe function with its `SAFETY` comment, through `windows-sys`:
- **opening a child of a held directory handle:** `NtCreateFile` with `OBJECT_ATTRIBUTES.RootDirectory` and `FILE_OPEN_REPARSE_POINT`, then refusing a reparse point from `GetFileInformationByHandleEx(FileAttributeTagInfo)`;
- **renaming relative to it:** `SetFileInformationByHandle(FileRenameInfoEx)` with `RootDirectory`, replace-if-exists and POSIX semantics;
- **deleting by handle:** `FileDispositionInfoEx`;
- **listing by handle:** `FileIdBothDirectoryInfo`;
- **a file's identity:** `FileIdInfo`, the volume serial and the 128-bit file id.

`anchor.rs` and `fc-store` use them on Windows as they use `openat` and `renameat` on Unix. That closes #963 for every file the core writes: the vault, the secrets, the stores, the node key files and the hand-off. It also gives 0001's identity checks a Windows form, which `fsx.rs` lacks today. Main's `private-files.js` keeps its Windows limit only for what main still writes.

### AGENTS.md rules 3 and 4

Once decided, rule 3's Bee exception reads:
> Bee's node keystore, which `nodes.write_identity` writes for the Bee node main runs (0001, "Multi-file writes"), in the format the JS reference writes, mode `0600` on Unix (on Windows it inherits its containing directory's ACL). Its password is sealed in the profile's secrets file under the OS key store (0013), and is released to antd at each start only as a one-use `0600` file in the profile's hand-off directory, which the core removes once the node answers. Where the OS has no key store, it stays in the node's `config.yaml` (0001, K-3).

Rule 4's exception reads:
> Never store a secret next to the thing it protects. The one exception is Bee's keystore password in `config.yaml`, beside `keys/swarm.key`, on a system with no OS key store (0013). No new code may add another.

Rule 4 gains: "OS key-store items hold wrapping keys only, one per profile and policy, never shared between profiles."

## Effects on 0010 and D7

- **The protected roots** (0010, *Main's check*, step 7):
  - `COMPONENT_DATA_DIRS` (`profile-paths.js:284–292`), which feeds `service-grant.js`, gains the `freedom/` prefix for every component that moves, and the stores' names join it. After the move, `freedom/` holds the IPFS grant, so by 0010's rule it isn't a root itself. Its other entries are roots, names not yet created included.
  - The lock directory stays a root. `R/<slot>` homes don't move.
  - A service's grant inside a profile changes path once, at the move. Each spawn's check runs as before.
- **D7, `freedom-cored`'s own confinement,** is `serve`'s. What `serve` needs, as this design leaves it:
  - **Files, before the move (D7a):** read-write on the profile's `userData`, the lock directory, the profile's Radicle home, and each directory the core writes that an override puts outside `userData` (the identity directory, and the node roots of `core.hello`: Ant's or Bee's data). The core writes set-A files at the root of `userData` with atomic renames, so the grant can't be narrower than that directory.
    - **For a named profile,** that keeps a compromised core away from other profiles, the catalog, the user's other files and the places that start programs.
    - **For the packaged default profile it doesn't.** Its `userData` is the app root, which holds `profile-registry.json`, `Profiles/` and `R/`. Landlock's grant on a directory covers everything below it, so on Linux the default profile's core reaches every profile under D7a. Seatbelt can deny paths inside an allowed subtree, so on macOS D7a can take `Profiles/`, the other profiles' `R/` homes, the catalog and its forget file back out; the qualification gate shows whether it does. Windows confines files only once 0010's restricted token qualifies (D4).
  - **Files, after the move (D7b):** read-write on `<profile>/freedom/`, the lock directory, the Radicle home, and the overridden directories. The default profile's `freedom/` holds no other profile, so D7b separates it as D7a separates a named one. Electron's own data in the same profile, its cookies included, leaves the grant, and so does `profile.json` at the profile's root, which only the subcommands write.
  - **The catalog and other profiles** are never `serve`'s: `profile open` and the catalog subcommands do that work ([5.1](#51-resolving-the-profile)), each a short run on main's arguments, confined on its own. `serve` has no catalog method.
  - **Network:** none. Every HTTP request the core makes goes through main's `shell.*` executors (0005, 0006, 0009), so the core needs no socket at all.
  - **Local IPC:** main's pipe, and nothing else, on every OS. Every key-store call goes through the helper ([The helper](#the-helper-freedom-cored-keystore)), so `serve` needs neither the session bus on Linux nor the Security server's Mach services on macOS, and no key-store connection is open across `confine`.
  - **Processes:** none. `hold-lock`, `hold-profile`, `recover`, `profile open`, `profile migrate`, the catalog subcommands and `keystore` are separate runs of the binary by main, not children of `serve`.
  - **D7's own tests,** besides 0010's, run against a `serve` that has confined itself:
    - a named profile's `serve` can't read `profile-registry.json`, the forget file or another profile's directory, and every catalog operation works from that profile's manager meanwhile;
    - connecting to the session bus fails;
    - through the helper, the `Unattended` key is created, opened, replaced and forgotten after `confine`, on every OS that offers it: macOS (a temporary keychain), Windows (DPAPI, each `open` in a fresh helper, with the blob the confined `serve` read from its own secrets file) and Linux (a Secret Service on CI's private session bus). `UserPresence` is tested the same way on macOS once its spike passes.
  - **Stage 2's multi-profile core:** Landlock and Seatbelt can't widen a sandbox, so a profile opened after `confine` needs a new core process or a grant over `Profiles/`. That is left to the Stage-2 design.

## Relation to 0012 and 0015

- **0012's files** keep its rules (format, bounds, failed and narrowing writes, unreadable files set aside), and are set A here.
  - `grant_root` keeps its meaning, "where the grant files are". From PRF-8 it travels in `profile.open`, at protocol 3, and after PRF-9 it names `<profile>/freedom/`.
  - `fc-approval`'s store trait is what `fc-store` implements.
  - `phone-payments.json`, which older builds don't read, moves with the rest at PRF-9.
- **`approval.forget_account` and the end of a Safe's approvals** also run inside `accounts.remove` ([`vault-meta.json`](#vault-metajson)).
- **`store_moved` follows `grant_moved`** (unknown names refused, `not_moved` before a move, the move in the change that stops main's writes) and adds the echo that `grant_moved` doesn't need ([One writer per store](#one-writer-per-store-store_moved)).
- **The intent journal and the nonces** are set A, so 0012's APR-6 (the nonce, the journal and the broadcast) follows PRF-6's intent step.
- **0015** designs the Swarm stores' methods and rules. They use `fc-store` and move at PRF-9 like every set-A store.

## Failure modes

- **A crash in the middle of a store write:** the temp file is left behind and removed at the next start (0001). The store is either the old file or the new one, never torn.
- **A crash in the middle of the move:** the journal is on disk before the first rename. Before the marker the next start rolls back; after it, it finishes. A crash in a cross-device copy leaves only `<name>.moving`, which the rollback removes.
- **A partial move:** a profile is never opened half-moved. Readers decide by the marker, `--finish-only` settles any journal first, and an unreadable journal stops the profile with a message instead of a guess.
- **Two builds at once:**
  - **On one profile:** the profile lock excludes them in any mix of builds, the profile gate excludes two new builds, and the core's gate also excludes two cores.
  - **A stale takeover:** an older build knows no gate, so it can still take over the stale lock of a new build whose main has stalled past 30 s, as it can today. For a pre-core build that is 0001's unsupported pairing of two identity writers, and the release notes keep saying so.
  - **On the catalog:** the subcommands and older builds share proper-lockfile's write lock.
  - **During a move:** the move holds the profile lock itself, in today's format, and refreshes it from its own thread, so an older build on the same profile hands over or reports it busy for the whole move, however long it takes. The profile gate does the same for new builds. Other profiles are untouched.
- **A stale profile lock:**
  - **with the gate held:** the profile is open, so a launch hands over, and a delete or a takeover is refused;
  - **with the gate free:** taken over as today. That is a crashed process, or an older build, which holds no gate. A new build's main holds the gate from before its lock, so its core not being up yet no longer makes it look closed;
  - **a fresh lock that a crashed process left:** a relaunch within 30 s reports the profile busy, as today. A fresh lock with no gate can't be told apart from a profile still starting, so it isn't taken.
- **A main loop stalled past 30 s** keeps its lock if nobody took it over meanwhile. If an older build did, main finds the lock compromised at its next refresh and throws (`profile-lock.js:77–80`), as today. A new build no longer takes it over, since the gate is held.
- **The gate's holder dies while main runs:** main starts another at once. The lock, still fresh, covers the moment, and a main that can't take the gate again within 5 s quits, as on a compromised lock.
- **A key-store helper that fails, hangs or is killed:** the secrets file's committed keys and entries stay as they were, and every item the helper may have made, or failed to remove, stays named: a `pending` item moves into the `forget` list at the next open, and a failed `forget` keeps its record and is tried again. The request fails with `key_store_unavailable` or `key_store_cancelled` ([The helper](#the-helper-freedom-cored-keystore), [Forgetting an item](#forgetting-an-item)).
- **A crash or a kill in a re-wrap** (a create or import with `quick_unlock: true`, a password change with quick unlock): before the vault's rename, the old vault with its credential; after it, the new vault with its own. The next start removes the entry that names no vault ([The re-wrap's two entries](#the-re-wraps-two-entries)).
- **A crash or a kill in a vault create or import with `vault_meta` moved:** before the journal's write, the old vault with its metadata; after it, recovery installs both before anything reads either ([The vault and its metadata](#the-vault-and-its-metadata-one-write)). A failed install after the commit answers the committed result with `durable: false`, and recovery finishes it.
- **A downgrade with the metadata journal pending:** an older build finds the old pair, the new vault with its old metadata (or none), or the new pair, by where the install stopped. The middle one is the pair today's flow leaves when main dies after the core's commit, and the older build lives with it as it does today. Back on a core of this design, the install finishes only over targets the older build left unchanged, and a Quick Setup vault is never installed without its credential ([Downgrade after the commit](#downgrade-after-the-commit)).
- **A write to a store not yet moved:** `not_moved`, and nothing changes; main still writes that store ([`store_moved`](#one-writer-per-store-store_moved)).
- **A browser and a core from different steps:** a newer browser on a core that doesn't echo a store it names fails each of that store's requests with `requirement_unmet`, writing nothing, since it has no writer of its own. An older browser on a newer core names nothing, and keeps writing every store itself.
- **A crash or a kill in a profile delete:** before the catalog changes, the forget record names items that the profile's own file still names, so the next run drops them without a `forget`, and the profile opens as before. After it, every item is in the forget file, and main forgets it at the next start of any profile, whether or not the data's removal finished. A main killed between the helper's answer and `forget-done` leaves a record whose next `forget` answers `not_found`, which counts as success.
- **The key store unavailable or reset:** each secret falls back to its documented path (re-inject, quick unlock off, RPC keys re-entered, into `rpc-api-keys.json` while there is none). Nothing is deleted on a failed open, and a Quick Setup credential is never removed except by an explicit disable or a vault delete (0001: nothing destructive is inferred from a missing credential).
- **A full disk:** a write fails before its rename, and the store is unchanged. A move fails before its marker, and rolls back.

## API

| Method | Caller | Shape |
|---|---|---|
| `profile open` (subcommand) | main, before `app.setPath` | above |
| `profile migrate` (subcommand) | main, after `app.setPath`, before `hold-profile` and its own lock | `--profile-dir`, `--lock-dir`, `--dev`, `--finish-only` → `migrated`, `nothing`, `rolled_back`, `busy`, `lock_lost` or `corrupt` on stdout |
| `hold-profile` (subcommand) | main, from `app.setPath` until after it releases its lock | `--user-data-dir`, `--lock-dir`, `--app-root` and `--id` for a catalog profile → `locked`, then holds the profile gate until stdin closes |
| `profile list`, `create`, `rename`, `import`, `delete` (subcommands) | main, for the profile manager | today's results, as JSON on stdout; `delete --id --confirm-display-name` holds the target's gates, and answers `lock_held` if one is held; its result also lists the key-store ids it recorded (`forget`) or says `forget_unknown`, and it answers `forget_backlog` when the forget file is full |
| `profile forget-list`, `forget-done` (subcommands) | main: `forget-done` after the `forget` calls it runs for a delete's result or a list; `forget-list` after its first window when `profile open` reports `forget_pending`, and before it asks again for a delete refused with `forget_backlog` | `forget-list` → `{ items: [{ policy, item }] }`, the forget file's live items; `forget-done --item <id>`, repeatable, removes them ([Forgetting an item](#forgetting-an-item)) |
| `profile update-nodes`, `reserved-ports` (subcommands) | main, for the node settings | `updateProfileNodeConfig`'s and `getReservedManagedPorts`' |
| `profile status` (subcommand) | main, for a lock that reads stale | `--user-data-dir <dir>`, repeatable → `{ open, lock_fresh, gate_held }` for each |
| `keystore` (subcommand) | main, for `shell.keystore`, and for a deleted profile's `forget` | [The helper](#the-helper-freedom-cored-keystore); stdin carries a DPAPI `open`'s blob, and nothing else ([DPAPI's blob](#dpapis-blob)) |
| `shell.keystore` | the core, to main | `{ op, policy, item, sealed?, reply_key?, reason? }` → the helper's answer; `sealed` is DPAPI's blob, for an `open` on Windows only |
| `core.hello` | shell | gains `max_protocol`; at 3, its answer carries `profile` ([5.3](#53-one-core-several-profiles-q15)); gains `store_moved`, and its answer `store_moved`, the names this core took ([One writer per store](#one-writer-per-store-store_moved)) |
| `profile.open` / `profile.close` | shell, protocol 3 | [5.3](#53-one-core-several-profiles-q15) |
| `accounts.*` | [per method](#callers-of-the-store-methods) | one per `vault-meta.json` change ([`vault-meta.json`](#vault-metajson)) |
| `intents.*` | shell | `intent-store.js`'s record kinds: commit, handoff, outcome, settle, void, retire, track, compaction, and the reads; every write carries main's `run` ([The intent journal](#the-intent-journal)) |
| `payments.*`, `safe_pending.*` | [per method](#callers-of-the-store-methods) | the modules' operations ([Payment history](#payment-history), [Pending Safe transactions](#pending-safe-transactions)) |
| `quick_unlock.enroll`, `.unlock`, `.export_mnemonic`, `.export_private_key`, `.status`, `.disable` | chrome only (after main's Touch ID prompt), except enroll: shell only | [The re-wrap](#the-re-wrap); enroll's `password` travels as `password_b64`, 0001's convention for secret fields |
| `vault.create`, `vault.import` | 0001's: chrome, shell | gain `quick_unlock: true` (a boolean, absent meaning `false`) ([The re-wrap's two entries](#the-re-wraps-two-entries)); `vault.import` gains `user_knows_password`, and both require it once `vault_meta` is moved ([`vault-meta.json`](#vault-metajson)) |
| `vault.reconcile` | 0001's: shell | its committed `create` and `import` results gain `meta`, `"written"` or `"pending"`, once `vault_meta` is moved ([The vault and its metadata](#the-vault-and-its-metadata-one-write)) |
| `vault.change_password` | 0001's: chrome, shell | re-wraps quick unlock's credential; after 0001's errors it may answer `storage` (`data.file: "secrets"`), `key_store_unavailable`, `key_store_cancelled` or `invalid_argument` ([The re-wrap's two entries](#the-re-wraps-two-entries)) |
| `secrets.rpc_api_keys` | shell only | the keys main needs for the requests it runs |
| `secrets.rpc_api_key_status`, `secrets.set_rpc_api_key`, `secrets.remove_rpc_api_key` | chrome, shell | `{ providers: [{ id, present }] }`, never a key; a set replaces any key the provider had ([RPC API keys](#rpc-api-keys)) |
| `nodes.bee_handoff`, `nodes.bee_handoff_done`, `nodes.adopt_bee_password` | shell | [5.4c](#54c-bees-keystore-password-q16) |

New request errors: `not_moved` (with `data.store`: `vault_meta`, `intents`, `payments`, `safe_pending` or `rpc_api_keys`), as 0012's, `no_profile`, `key_store_unavailable` (with `data.reason`: `timeout`, `forget_backlog`, …), `key_store_cancelled`.

**RPC API keys stay out of the renderers.** `secrets.rpc_api_keys` answers only `shell`, and a `chrome` caller gets `forbidden`. The settings page sees which providers have a key, as it does today (`hasKey`), and can set, replace or remove one and test a key the user types, but can't read a stored one back. No product need asks for more: today's page shows nothing but presence ([Facts found](#facts-found-while-checking-the-code), 5). Main substitutes a key only into a request it runs itself.

### Callers of the store methods

A method is `chrome` only if today's IPC lets the chrome cause that exact write or read with no check in main between. The chrome window may send every channel (`ipc-sender-policy.js`, `isSenderAllowed`), and internal pages the channels of their tier. A check main makes that the chrome can't pass for it (a device read, a chain read, an address main computes) makes a method `shell`. A `chrome` call to a `shell` method is `forbidden`.

| Method | Callers | Reached today by | Main's check before the write |
|---|---|---|---|
| `accounts.meta` | chrome, shell | `identity:get-vault-meta` (the whole file; the renderer reads `userKnowsPassword`) | none |
| `accounts.list` | chrome, shell | `wallet:get-derived-wallets`, and main's own callers | none; the first-list default is written |
| `accounts.active` | chrome, shell | `wallet:get-active-index` | none |
| `accounts.set_active` | chrome, shell | `wallet:set-active-wallet` | the index exists (the core's check now) |
| `accounts.add_mnemonic` | chrome, shell | `wallet:create-derived-wallet` | the vault unlocked; the index and address are the core's, the name the caller's |
| `accounts.rename` | chrome, shell | `wallet:rename-wallet` | the index exists |
| `accounts.remove` | chrome, shell | `wallet:delete-wallet` | refusals only, which move to the core; main passes the Swarm references and holds a Safe's exclusion |
| `accounts.add_ledger` | shell | `wallet:add-ledger-wallet` | main reads the address from the device and refuses a mismatch |
| `accounts.add_remote` | shell | `wallet:add-remote-wallet` | main checks the phone's signature over its own challenge, relayed by the chrome ([What stays open](#what-stays-open-at-prf-5)) |
| `accounts.record_address_check` | shell | no channel: a device read at each listing or signature, a phone signature checked against the record | the device, or the signature |
| `accounts.add_safe` | shell | `wallet:create-safe` (a name, owners, a threshold) | main computes the address from its records, its salt and the pinned factory |
| `accounts.mark_safe_deployed` | shell | `wallet:get-safe-status`, `wallet:activate-safe` (an index only) | a verified `eth_getCode` or receipt |
| `intents.*` | shell | no channel: main's send paths | — |
| `payments.get_recent`, `.get_count` | chrome, shell | `payments:get-recent`, `payments:get-count`, `x402:get-receipts` (the chrome, internal pages) | the filters checked |
| `payments.get_by_id` | chrome, shell | `payments:get-by-id` (the chrome) | an integer id |
| `payments.clear` | chrome, shell | `payments:clear` (any internal page) | none, and no prompt |
| `payments.append`, `.update`, `.mark_confirmed`, `.mark_failed`, `.mark_dropped`, `.set_dropped_seen`, `.pending` | shell | no channel: tx-recorder, x402, the repoll | — |
| `safe_pending.*` | shell | no channel returns or writes the file: the chrome gets main's projections, a send needs the approvals prompt, and a cancel passes main's busy check and the approval's end | — |
| `secrets.rpc_api_keys` | shell | no channel | — |
| `secrets.rpc_api_key_status`, `.set_rpc_api_key`, `.remove_rpc_api_key` | chrome, shell | `networks:get-config` (`hasKey`), `networks:set-api-key`, `networks:remove-api-key` (internal pages) | the provider is in main's registry |

## Vectors

From the JS reference (rule 5), each with its own `meta` naming the pinned commit:
- **`profiles.json`:**
  - `sanitizeProfileId` and `displayNameFromId`, including the refusals;
  - `hashPath` and the checkout id; ports by slot, packaged and dev;
  - `allocateSlot`, `rebaseNodeConfig`, `fillMissingNodeConfig` and the IPFS mode's normalization;
  - every resolution order case: argv, switch, environment, runtime, last opened, fallback, first run;
  - the catalog's and `profile.json`'s text after each operation, under a fixed clock;
  - unsupported catalogs;
  - the delete refusals (the last profile, outside the root), and the overlaps the core refuses where the reference doesn't (directories, Unicode-equivalent names, a shared Radicle slot), each such step marked with its deviation and the core's answer;
  - the lock-staleness decision at 29,999, 30,000 and 30,001 ms, and the dev times.
- **`quick-unlock.json`:** the v2 credential's text with a stub `safeStorage`, its binding (the real path's hash, the vault's fingerprint), legacy detection, and the parse failures. These are what main reads until the file is deleted after the enroll (PRF-2).
- **`stores.json`**, new for set A (0012's store vectors are `approvals.json`'s `stores`). It has its own pin, `STORES_REFERENCE_COMMIT`, the integration head when PRF-5a lands (`9d4ea625` as this is written), since `identity-manager.js` changed after the approvals pin (#1065, #1066, #1078). Its sections: `vault_meta`, each `identity-manager.js` change with its text and its result or refusal; `intents`, each record kind, replay, compaction and the bounds, under a fixed `run` and clock; `safe_pending`; `rpc_api_keys`, `rpc-api-keys.json`'s text after the reference's sets and removes. Each malformed file, with what the reference loads from it and the core's verdict.
- **`journal.json`:** `durable-journal.js`'s lines and checksums, a whole last record without its newline, torn tails, a damaged line, compaction, and the bounds (the 64 MiB default, the intent store's 16 MiB). Both directions: the reference's `readJournal` also reads files a testhooks core wrote.
- **`bee-seal.json`:** #946's seal records, valid and not, with `readSeal`'s verdicts; the serde_yaml fixture of `password:` lines with their decoded passwords; and keystore digests.
- **`sqlite.json`:** `sqlite_master`'s rows and `user_version` for both databases as the reference creates them, and the rows after the reference's operations. The generator needs better-sqlite3 built for CI's Node.
- **`signing.json`** gains `transactions`: signed transactions as ethers' `Transaction.from` accepts or refuses them (PRF-5e-1).
- **The design's own,** with no reference (`source: design`): the secrets file under a fixed key and nonce, with the associated-data refusals, a `pending` item and a `forget` list at its bound; the forget file at its bounds, with a record still listed in the catalog and one gone, and one past a bound; the helper's answers under a fixed request key, with the refusals; the profile gate's file name for each kind of profile; the layout list for each kind of profile (packaged default, named, dev, `--profile-dir`, test); and the move journal's states.

## Migration

One PR per step: the core's against `main`, the browser's against `integration/rust-core`.

| Step | Repo | What | Needs | The tests that prove it |
|---|---|---|---|---|
| PRF-1 | core | `fc-keystore` (trait, policies, the secrets file and its `forget` list); the helper, `freedom-cored keystore`, with the macOS `Unattended` backend; the core's desktop `KeyStore` over `shell.keystore`; `quick_unlock.*`; `quick_unlock: true` on create and import; the re-wrap on change of password; the entitlement spike for `UserPresence` | — | Secrets vectors byte for byte; an entry under another name, binding or key refused. On macOS CI, a temporary keychain: create, open, replace and forget through the helper, and `NotFound` after forget. **The helper's contract:** an answer not sealed to the request's key, or sealed for another op or item, is refused; a reply over 4 KiB, no reply, and a helper past its deadline are `Unavailable` or `Backend`; a helper killed after the OS stored the item and before it answered leaves the file's committed state as it was, and the `pending` item moves into `forget` and is forgotten at the next open; no wrapping key appears in argv, stdin or the bytes main relays; bytes on stdin are refused with no OS call; a Keychain key whose `sealed` isn't `null` is out of form. **Forgetting, killed at each step:** for a replace, a quick-unlock disable and a vault delete, a crash hook before and after each write (the `pending` write, the commit or removal that moves a key into `forget`, the record's removal), and the helper killed or held past its deadline at each `create` and `forget`. After a restart at each point, the file names every Freedom item the temporary keychain holds, the committed keys and entries are the old set or the new, and after the next open the keychain holds only the keys in use and the file no record. A record whose item was removed by hand, or whose backend this OS doesn't have, is dropped at the next open without an error. With `forget` made to fail, the `create` that would make a fifth named item is refused with `forget_backlog` and changes nothing, and works once a `forget` succeeds. Enroll refused for a wrong password and throttled with `vault.unlock`. Unlock works locked and unlocked. A failure hook at each step of create-with-credential and of change-password leaves the old pair or the new, never a vault without its credential. An entry naming no vault removed at start. iOS and Android builds pass |
| PRF-2 | browser | Main's `shell.keystore` executor, which runs the helper, and its drain of the forget file after a delete and at start. The re-wrap: enroll at the next Touch ID use; unlock through the core; `quick-unlock.dat` deleted after a confirmed enroll (the user's decision of 2026-11-15); Quick Setup creates with the credential and writes no `quick-unlock.dat`; disable removes the credential, and the file if one is left; the one-time prompt before a shell switch | PRF-1's and PRF-3's releases pinned; PRF-4 shipped, so no build makes a key-store item before its deletes record it | The migration suite: a profile with a v2 and one with a legacy `quick-unlock.dat` unlocks once through it and then through the core. The file is deleted only after a confirmed enroll, and a refused enroll keeps it byte for byte. A crash between the enroll and the delete leaves the file, and the next unlock goes through the core, then deletes it. Where the core has no key store, main never deletes the file on its own. An explicit disable deletes it on every platform, synced before `quick_unlock.disable`, and a failed fsync refuses the disable. Quick Setup writes none. **Downgrade:** the reference `quick-unlock.js` unlocks from the file until the delete; after it, it finds none and asks for the password. A password change keeps quick unlock in the core, and one whose enroll the status doesn't confirm, or whose delete fails, is refused with the vault unchanged. The Quick Setup e2e on macOS with a stubbed Touch ID; Quick Setup's failure path deletes nothing the core committed. **The drain, killed at each step:** main killed after `profile delete` answered and before the helper ran, the helper killed or held past 10 s, and main killed between the helper's answer and `forget-done`. At the next start of another profile the drain runs after the first window, and the temporary keychain holds none of the deleted profile's items. Two profiles' mains draining at once leave neither item in the key store, and each main's counts match its helper's answers. The file keeps only the records no main cleared: on macOS, one whose delete answered the raced `backend`/`status`. The next drain clears them and leaves it empty. A live profile's item, which no record names, survives both mains and that drain. Main killed while a replace, a disable or a vault delete waits on `forget`: the profile's next open finishes it |
| PRF-3 | core | `fc-profile`; `profile open`; the catalog subcommands and `profile status`; `hold-profile` and the profile gate; the catalog's write lock, refreshed by a long holder; deletion under every gate, recording the target's key-store items in the forget file first; `forget-list` and `forget-done`; `locks` kept; `profile migrate --finish-only`, the move's recovery, which starts no move, under the move's own exclusion | — | `profiles.json` replayed. The latency gate on every OS. A Jest harness runs the reference's `createProfile` and `renameProfile` against the subcommands in a loop: the catalog stays valid, and no record is lost. **The write lock both ways:** the reference holds it past 10 s while a subcommand waits, and a subcommand holds it past 10 s while the reference waits; neither takes over a live lock, and each takes over a dead holder's at 30 s, not at 29,999 ms. **The stale-lease case:** a lock backdated 31 s with the target's profile, core, IPFS or Radicle gate held refuses the delete, with nothing changed. `hold-profile` refuses a catalog profile no longer listed at its directory. Each subcommand, confined, can't read outside its grant. The default profile's delete keeps `locks/` and every other shared entry. **The forget file:** a crash hook at each step of a delete (before the record, after it and before the catalog changes, after the catalog changes, mid-removal, before the result). Before the catalog changes, the next `forget-list` drops the record, and the profile's own file still names its items; after, `forget-list` returns every item. A deleted profile imported again from a leftover directory whose secrets file survived keeps its items; one created again under the same id doesn't stop the old ones being forgotten. A full file refuses the delete with nothing changed. A target secrets file that can't be read lets the delete go on, with `forget_unknown`. The default profile's delete keeps the forget file, and so does the reference's `removeDefaultProfileDataFromAppRoot`. A malformed forget file is renamed aside, and nothing it names is forgotten |
| PRF-4 | browser | `profile open` before `app.setPath`; `hold-profile` from `app.setPath` until after the lock's release; the profile manager and node settings through the subcommands; "open" means a fresh lock or a held profile gate; **the reader release**: one Freedom-root resolver, and `profile migrate --finish-only` before the lock when `profile open` reports a journal | PRF-3's release pinned | `npm run test:migration` and the profile e2e specs, unchanged. The stale-lease probe refused. **Overrides:** catalog profiles launched with each of `FREEDOM_IDENTITY_DATA`, `FREEDOM_ANT_DATA`, `FREEDOM_BEE_DATA`, `FREEDOM_IPFS_DATA`, `FREEDOM_TOR_DATA`, `FREEDOM_RADICLE_DATA` and `MYOTIS_DATA_DIR`, their locks backdated 31 s: another profile's manager reads each open, and its delete is refused with nothing changed. **A launch held before `serve`:** a test hook stops main after it takes the lock and before the core starts, for 45 s; a second launch hands over or reports the profile busy, and a delete from another profile is refused. The holder killed while main runs: main takes the gate again, or quits. **Downgrade:** the reference resolver opens a catalog the subcommands wrote. A profile in the moved layout, built from the layout vectors, opens, and so does one with a journal pending before and after its marker. **Windows's first scan** ([the latency gate](#51-resolving-the-profile)): the PR records the Defender-enabled, no-exclusions runs on a fresh machine (a newly downloaded release artifact's first `profile open`, and the first after each of several reboots); if any reaches 1 s, `profile open` stays in JS on Windows |
| PRF-5a | core | `fc-wallet-state` (logic) with the `vault-meta.json` codec, one operation per `identity-manager.js` change; `vectors/stores.json`'s `vault_meta`, pinned by `STORES_REFERENCE_COMMIT` | this amendment | Every `vault_meta` step's text byte for byte, with its result or refusal message; `text(load(t)) == t` for every text in the vectors; each malformed text's verdict, and past 1 MiB unreadable; `generate.js check` in CI; iOS and Android builds pass |
| PRF-5b | core | `fc-store` (service): `fsx.rs` and `anchor.rs` moved out of `freedom-cored`, with `grants.rs`'s bounded read, write and set-aside; failure hooks injected, never read from the environment | — | No behaviour change: every existing suite passes as it is. A hook at each write step (temp write, fsync, rename, directory flush) leaves the file as it was, or reports `durable: false`; temp files removed at start; a bounded read refuses a FIFO, a symlink and an oversize file; iOS and Android builds pass |
| PRF-5c-1 | core | `accounts.*`; `store_moved` in `core.hello`; `vault-meta.json` written alone through `fc-store` | 5a, 5b | Every `vault_meta` vector replayed through the daemon. Each method's callers as [the table](#callers-of-the-store-methods), a `chrome` call to a `shell` method `forbidden`. A hello naming an unknown store refused. The answer's `store_moved` echoes `vault_meta` when it is named, and no name whose methods this build lacks (`intents`, `payments`, …), whose stores stay as if not named. Without `vault_meta` named, reads served and every write `not_moved`, with nothing written (a spy on the core's `fs`). An unreadable file set aside once moved, and left in place before. A failure hook at each write step. `accounts.remove`'s refusals, the Swarm references among them, and a Safe's approvals ended and its grants forgotten in the one request |
| PRF-5c-2 | core | The vault and metadata journal for `vault.create` and `vault.import` with `vault_meta` moved; `user_knows_password` on import; `vault.reconcile`'s `meta`; the unlock's migration | 5c-1 | A crash hook at each step (stage, journal, the vault's install, the metadata's, finish), with and without `quick_unlock: true`: after a restart, the old pair or the new, and the new vault's credential with the new vault. **A returned failure** injected at each step after the commit (the vault's rename and its flush, the metadata's rename and its flush, the journal's unlink): the request answers the committed result, `create`'s and `import`'s, with `durable: false`, never an error; the journal stays; while the hook holds, `accounts.*` and reads of the vault answer `storage`, `vault.reconcile` answers the committed result with `meta: "pending"`, and a restart keeps the staged entry; once the hook is cleared, the next read finishes the install, `vault.reconcile` answers `meta: "written"`, and the files hold the new vault and its metadata, with the new vault's credential only: `quick-unlock` bound to it, or, for an import over a vault that had quick unlock, `quick-unlock.next` bound to it and no `quick-unlock`, until an enroll or a re-wrap folds it into `quick-unlock` (a disable or the vault delete removes both names). **The finish's flush failing** after the unlink (a hook that fails the real flush, after the real unlink, not one that fails before it): the request answers `durable: false`, the journal is gone, `vault.reconcile` answers `meta: "written"`, and a journal put back as a crash would leave it is only removed at the next start, the pair unchanged. **The downgrade,** at each point after the commit (the journal written, the vault installed, both installed), with and without `quick_unlock: true`: the previous core release starts on the files, and the reference's `identity-manager.js` (at `STORES_REFERENCE_COMMIT`, over that core) reads them, with the pair and the results [Downgrade after the commit](#downgrade-after-the-commit) names. The previous core removes the staged entry at the first point only. Then this core restarts: the new pair where the older build changed nothing, except at the first point with `quick_unlock`, where the record is set aside and the new vault isn't installed; a target the older build changed sets the record aside, and its file stays. A record no writer wrote, or a target that is no longer its `before`, set aside as `.corrupt` with nothing else changed, and nothing renamed before both files are checked. `vault.delete` leaves `vault-meta.json`. A missing `user_knows_password` refused once moved. **→ Release R1: PRF-6(a) can start** |
| PRF-5d | core | The JSON Lines journal in `fc-store`; `vectors/journal.json` | 5b | The vectors byte for byte: a whole last record without its newline, torn tails, a damaged line, compaction, the bounds. Both directions: the reference's `readJournal` reads files a testhooks core wrote (`interop.test.js`). A crash hook at each step of an append and of a compaction |
| PRF-5e-1 | core | `fc-evm`'s signed-transaction decoder: types 0 and 2, EIP-155 and earlier `v`, the canonical check by re-encoding, the signer | — | `signing.json`'s `transactions` replayed: accepted as ethers accepts, refused for non-canonical integers, leading zeros, trailing bytes and unknown types |
| PRF-5e-2 | core | The intent rules in `fc-wallet-state`: record kinds, replay, `LIMITS` and the budget, compaction to `held` and `tombstone`, the views; `stores.json`'s `intents` | 5d, 5e-1 | Every `intents` step replayed: the state, the file's text and each refusal, under a fixed `run` and clock; a damaged file's verdict; each bound at and past its limit |
| PRF-5e-3 | core | `intents.*` with `intents` in `store_moved` | 5e-2, 5c-1 | Over the wire: every method `forbidden` for `chrome`; `run` written as main passes it; `not_moved` until named; the vectors' results. **→ Release R2: PRF-6(b), then 0012's APR-6** |
| PRF-5f | core | `safe_pending.*`: the codec, `stores.json`'s `safe_pending` | 5b, 5c-1 | The vectors byte for byte, integer keys first; a malformed file set aside, and a failed write reported, once moved; the 1 MiB bound; `accounts.remove` of a Safe clears its entry once both stores are moved. Ships in R1 or R2 |
| PRF-5g-1 | core | SQLite: `rusqlite` (bundled) in `freedom-cored`; Zig as the musl targets' C compiler in CI and the release; `vectors/sqlite.json` | 5b | CI green on every target, `mobile-targets` unchanged; a release dry run builds and smoke-tests all five archives; `cargo deny` passes; `sqlite.json`'s schema rows and `user_version` equal the reference's |
| PRF-5g-2 | core | The payments codec, `payments.*`, the `x402-receipts.json` import | 5g-1, 5c-1 | The rows after each of the reference's operations; a database each side wrote is read by the other; the import once, renamed `.migrated`; a database not named in `store_moved` never opened, and `payments` echoed once named. **→ Release R3: PRF-6(c)** |
| PRF-5h | core | `secrets.rpc_api_keys` (shell), `rpc_api_key_status`, `set_rpc_api_key`, `remove_rpc_api_key` (chrome, shell) | PRF-1, this amendment | `secrets.rpc_api_keys` from `chrome` is `forbidden`, and `rpc_api_key_status` answers presence and no key bytes, with no key-store call. All four `not_moved` until named, and `rpc-api-keys.json` never opened. Set and remove on macOS's temporary keychain. An id of 52 bytes taken; one of 53, or outside the form, refused. At 16 entries, beside quick unlock's and Bee's, a 17th set refused and a replace taken. **Migration:** a file in the reference's text (`stores.json`'s `rpc_api_keys`) moved in one secrets write, then removed; a crash hook between the secrets write and the file's rewrite, and at each write step of each, resumed at the next start with each provider's key answered once and equal to the file's; a key in both places answered from the file, then moved. **A replacing set** with the old key in the file: a failure injected before the entry's write leaves the old key answered; a crash hook after the entry's write and before the file's rewrite, then a restart: the old key answered, and after the migration only the old key, in an entry; a file with an id outside the form and with 20 keys leaves that id and the four past the bound in the file, answered by `rpc_api_keys`, counted by the status and removable, and a set for that id refused. **No key store** (Linux and Windows until PRF-7): set and remove write the file in the reference's text, which the reference's `readRpcApiKeys` reads back, and nothing moves. An unreadable file set aside. Ships in R1 or R2. **→ PRF-6(e)** |
| PRF-5i | core | The Windows handle-relative calls in `fc-sys`; `fc-store`'s Windows directory and file identity | 5b | On Windows: a directory swapped for a junction between the open and the write is refused, and the file lands nowhere else; a reparse point at a child's name refused; renames and deletes by handle. Ships in whichever release is next, before PRF-5 counts as done |
| PRF-6 | browser | Set A through the core, one store per PR: (a) `vault-meta.json`, (b) the intent journal, then 0012's APR-6, (c) payments, (d) pending Safe transactions, (e) RPC API keys into the secrets file, and the settings page on `rpc_api_key_status`. Each names its store in every hello in the change that deletes main's writer for it (for (c), main's open of the database too), and sends the store's requests, and for (a) `vault.create`, `vault.import` and their reconcile, with `requires` on the echo. Set B onto `lib/atomic-file.js` | The PRF-5 sub-release that serves its store, pinned | Each module's Jest suite against the core. An `fs` spy shows main writes none of the store's files. **Both rollout directions,** for each store: the reference module from before the step against this step's core, where the core writes none of the store's files (their digests unchanged by every core request), answers each write `not_moved`, and for (c) never opens the database; and this step's browser against the previous core release, where every request of the store, and for (a) a create and an import, fails `requirement_unmet` and nothing writes the store. **One process on the database (c):** main's code has no open of `payment-history.sqlite` (a spy on better-sqlite3's constructor sees none across the suites), and on Linux CI, with main and the core running, only the core's process holds the database, its `-wal` or its `-shm` open (`/proc/<pid>/fd`). **Rollback:** the reference module reads the file the core wrote and sees the same state. RPC API keys (e): main opens no `rpc-api-keys.json` (the `fs` spy); the file goes only once its keys are in the secrets file, and with no key store it stays, the core's; no renderer channel returns a key, or a URL with one in it |
| PRF-7 | core, then browser | Bee's keystore password: the helper's Linux and Windows `Unattended` backends, and main's executor passing DPAPI's blob on stdin; `nodes.write_identity` without the line; `bee_handoff`, `bee_handoff_done`, `adopt_bee_password`; the browser's Ant start through them; the AGENTS.md amendment | All of PRF-5; SEC-3f | `bee-seal.json` replayed. Through the helper, on Linux CI's private session bus with a Secret Service and on Windows: create, open, replace and forget; PRF-1's and PRF-2's forgetting tests on the Secret Service, and on Windows a dropped key that leaves no record and copies no blob; **DPAPI's blob, on Windows CI:** `create`, then `open` in a fresh helper once the first has exited, and again after the core restarts, from the blob in the file; a replace is a `create` and one write, with the old blob gone from the file, no helper run for it, and the new key opening in a fresh helper; a DPAPI `forget` makes no call, a stray one answers `ok`, and a `pending` DPAPI id left over is dropped at the next open with no call; refused by the core, by main and by the helper each, before any OS call: a blob missing, of 1 KiB and one byte, or not in base64 form, and a `sealed` or stdin bytes with a `create` or a `forget`; `invalidated`, with nothing deleted and each secret on its fallback path: a blob changed in one byte, cut short, sent with another item's id, or made under no entropy; a `create` answer whose blob is changed on the way doesn't open; the blob never appears in the helper's command line, and a `create` answer with a 1 KiB blob fits in 4 KiB; a locked collection whose prompt is dismissed is `Cancelled`; no Secret Service is `Unavailable`, and each secret stays where it is. Adoption from a seal, and from a `password:` line in every form the fixture holds. Refused for a seal of another keystore, for a password that doesn't open it, and for a keystore changed between the check and the write. The hand-off file is 0600 in a 0700 directory, gone after `done`, and an orphan swept. With no key store, `config.yaml` keeps the line. **Downgrade:** a SEC-3f build starts Ant from the seal the core left |
| PRF-8 | core | The profile dimension at protocol 3: `profile.open` and `profile.close`; `Context.profile`; per-profile state; `core.hello`'s `max_protocol`; protocol 2 kept beside it | All of PRF-5 | Two profiles over one pipe at protocol 3 under the test flag: a lock, an unlock, the throttle, auto-lock and a failed write in one leave the other as it was. At 3, a request without `profile`, or for one not open, refused. A second `profile.open` refused without the flag. At protocol 2, every method served for the start profile, a request carrying `profile` refused, `profile.open` unknown, events without `profile`. A hello with `max_protocol: 3` answered at 3, and one without it at 2. **`store_moved` at 3:** the hello's echo holds for a second profile: a named store is written through the core in both profiles, and an unnamed one answers `not_moved` in both; `profile.open` with a `store_moved` member is `invalid_argument` |
| PRF-8b | browser | `core.hello` with `max_protocol: 3`; at 3, every profile-scoped request carries the hello's handle, and events are read by theirs; at 2, today's requests | PRF-8's release pinned | **Both rollout directions:** the integration browser from before this step, its suites run against PRF-8's core, speaking 2; this step's browser against the previous core release, negotiating 2; and against PRF-8's core, speaking 3, with the same results. The two-profile test above, driven from main's client |
| PRF-9 | core, then browser | The move: `profile migrate` starting moves, under its own lock and gates; the marker; the placeholder; downgrade residue set aside; new profiles in the new layout; 0010's component list with `freedom/` | PRF-4 shipped long enough; Q12 | **A crash hook at every step:** before the marker it rolls back to the old layout, which opens; after it, it finishes. A cross-device entry copied and its source kept until the marker. A symlink to a directory on another device moved as the link, its target untouched. A database with a non-empty `-wal` stops the move. A Windows rename held by another handle retried, then rolled back. **Two real builds, each phase held past 30 s:** a test hook holds the move at each step (the journal written, the renames, a cross-device copy, the placeholder, the marker, the cleanup), and `--finish-only` at each recovery phase (a rollback, a roll-forward), for 45 s. Meanwhile an older build, both the last release before the reader and a reader build, tries to open the profile and, from another profile, to delete it: each finds it open and changes nothing, and the lock's mtime keeps advancing. After the run, main's own lock is taken and stays uncompromised. A move frozen past 30 s while another build takes the lock over exits `lock_lost` when it resumes, and changes nothing more. **Downgrade:** a reader build opens the moved profile. An older build can't create a vault under the placeholder. On re-upgrade, its root entries are set aside, unmerged. Every protected root in `freedom/` is refused as a grant |

**PRF-5's sub-steps ship in three core releases:** R1 is 5a, 5b, 5c-1 and 5c-2 (with 5f and 5h if ready), so no release serves `accounts.*` without the journal; R2 is 5d and 5e-1 to 5e-3; R3 is 5g-1 and 5g-2. 5i goes in whichever release is next. PRF-6(x) needs the PRF-5 sub-release that serves its store; PRF-7 and PRF-8 need all of PRF-5. Each method step touches `methods.rs`, `schema.json`, `CAPABILITIES` and `HelloParams`, so those PRs merge one at a time.

**D7** comes after this design is decided (D7a), and narrows after PRF-9 (D7b). It ships only once [its tests](#effects-on-0010-and-d7) pass: the catalog and other profiles out of `serve`'s reach, and the key store through the helper after `confine`.

## Rollback and downgrade

- **Each core step is additive** until the browser step that uses it. PRF-8 is too: it keeps protocol 2, so the browser before PRF-8b runs on it unchanged, and PRF-8b's browser runs on an older core at 2. Each browser step reverts on its own until the next one builds on it.
- **No format changes before PRF-9,** except the new files (`secrets.json`, the core's credential, `layout.json`, and the vault delete's `vault-delete-journal.json`, `secrets.json.freedom-new` and `vault-delete-journal.json.corrupt`, and the metadata journal's `vault-meta-journal.json`, `vault-meta.json.freedom-new`, `identity-vault.json.freedom-new` and `vault-meta-journal.json.corrupt`), which older builds don't read. A store file set aside as unreadable reads as missing there, as a file that doesn't parse reads today. So an older build reads every store at every step up to the move.
- **The metadata journal's window** is the one exception. A downgrade after a create's or an import's commit and before its metadata is installed shows the older build the new vault with its old metadata, or none: the pair today's flow leaves when main dies after the core's commit, which the older build doesn't repair, as today. Back on a core of this design, the install finishes only over what the older build left unchanged ([Downgrade after the commit](#downgrade-after-the-commit)).
- **Each step's tests read the core's output with the reference's code.** That is the rollback guarantee, as in 0001 and 0012.
- **Key-store items and older builds:** a build before PRF-4 deletes a profile without reading its secrets file, so a profile it deletes after a downgrade leaves its items in the key store, named by nothing. Older builds keep the forget file, since their default-profile delete spares its prefix, and don't read it.
- **Secrets that move out of a file** (RPC API keys, Bee's password) leave behind what older builds need, or nothing they would misread:
  - **RPC API keys:** an older build finds in `rpc-api-keys.json` only the keys the secrets file couldn't hold, all of them where there is no key store, and asks for the others again. A key it then writes there is moved at the next start of this design, replacing the entry;
  - **Bee's password:** a SEC-3f build finds #946's seal until the core next rewrites the identity, and then takes #946's re-inject path. A build before SEC-3f finds no `password:` line, and its `ensureConfig` refuses to mint one beside the keystore (`ant-manager.js:333–340`).
  - **Quick unlock:** once the core confirms its credential, PRF-2 deletes `quick-unlock.dat`. An older build then finds no file and asks for the password. After Quick Setup, whose password nobody knows, only the recovery phrase opens the vault there. Until the delete, an older build still unlocks from the file.

  These are the costs of Q14 and Q16 on a downgrade, and the questions say so. The user accepted the quick-unlock cost in the decision of 2026-11-15.
- **PRF-9 is one-way for builds older than the reader release** (Q12).

## Deviations

| Id | Today | With the core |
|---|---|---|
| `quick-unlock-password-change` | a password change turns quick unlock off silently | the credential is re-wrapped with the new vault |
| `quick-setup-one-write` | the vault first, then the credential; a failure deletes the vault | written together; nothing to delete |
| `quick-unlock-in-core` | the password crosses into main at each unlock | it stays in the core after the one enrollment |
| `quick-unlock-dat-deleted` | `quick-unlock.dat` stays until disable | deleted once the core confirms its credential; an older build then asks for the password |
| `profile-open-gate` | a stale lock is free | free only if the profile gate is free too, which a new build holds from before its lock to after it |
| `profile-delete-gates` | only the IPFS gate is held; a stale lock is trusted | every gate held; any one held refuses |
| `locks-kept` | the default profile's delete removes `locks/` (macOS, Windows) | kept |
| `profile-delete-overlap` | a record's directory is only checked to be inside the app root: one at `Profiles/` or another shared entry, at, above or inside another profile's directory (under any spelling the volume takes for it), or inside the packaged default profile's data, deletes that data with it; so does a record whose slot, and so Radicle home, another record has too | refused before any gate or change |
| `catalog-durable` | renamed without fsync | 0001's durable write |
| `store-durable` | set B in place or unflushed | `lib/atomic-file.js` |
| `vault-meta-unreadable` | no size or nesting limit; what follows depends on the damage. A file that doesn't parse, or `null`, reads as missing. A non-object, or an object with no `derivedWallets` (the pinned oversized and deeply nested examples among them), gets a fresh one-account list written over it at the next list (`getDerivedWallets`' lazy init). A non-array `derivedWallets` or a `null` record makes every list throw a `TypeError`. A non-object record, or a record whose `index` or the file's `activeWalletIndex` isn't an integer, is listed as found, and a lookup by index matches nothing. A Safe record whose `owners` isn't an array is listed, and found by its index, with `owners` as stored | each of these is renamed aside and reported, as 0012's files, and the store reads as no file. The 1 MiB bound and the nesting limit are resource limits (`source: design`); the shape rules keep every record in a form the codec reads and writes back byte for byte, and each case keeps the original bytes in the `.unreadable` file |
| `vault-meta-with-vault` | main writes `vault-meta.json` after the vault commits; a crash between leaves a vault without it | one journaled write |
| `vault-meta-unlock-migration` | a failed write of the unlock's migration rejects an unlock that happened | logged; the next unlock tries again |
| `safe-pending-unreadable` | depends on the damage. A file that doesn't parse reads as `{}`, and the next write replaces it. `null` makes every call throw. An array is the store: `list` answers its occupied indices, `get` an element, a set at an index replaces or extends it (a hole is written as `null`), and a clear of an occupied index deletes it, leaving a hole written as `null` (a clear of an absent one writes nothing). A string is read by index (its characters listed, `get` answering one); a number or a boolean lists nothing and `get` answers `null`; for all three a set rewrites the value unchanged, and a clear throws (`in` needs an object). An object key that isn't a wallet index's decimal text is listed as `Number(key)`. Where `String(Number(key))` is the key itself (`"1.5"`, `"-1"`, `"9007199254740992"`), a call with that number reaches it: `get` finds it, a set replaces it, a clear deletes it. Otherwise (`"01"`, `"abc"`, `""`) no call reaches it. A write at another index keeps it either way | unreadable, renamed aside and reported, and the store reads as empty: a file past 1 MiB, not JSON (a byte-order mark or nesting past 512 levels included), not an object, or with a key that isn't the decimal text of an integer from 0 to 2^53−1. No reference writer makes any of these; the rule keeps every entry reachable by a wallet index, and the original bytes stay in `.unreadable` |
| `safe-pending-write-reported` | a failed write is logged, and the change kept in memory as if saved | reported, with the store unchanged |
| `intent-unserializable` | a type-2 transaction in `wallet-intents.jsonl` that ethers can't serialize (a priority fee above the max fee, or an `s` of 2^255 or more) throws ethers' own error out of `verifySigned`, and the file is moved aside with that error's message as its reason. The message carries the transaction itself, or its `s` | the reason is the fixed text `Invalid wallet intent record: the transaction cannot be serialized`, since the store's reasons name ids and numbers only, never bytes or fields |
| `rpc-keys-fields` | `{ apiKey, enabled: true, addedAt }` | an entry is the key alone, and present means enabled; `rpc-api-keys.json` keeps the reference's fields |
| `sqlite-version` | a database whose `user_version` is above the schema's is opened as it is, and migrated only from below 1 | refused (`user_version N`) before anything is written, its journal mode included: a schema this core doesn't know isn't read or changed by it |
| `sqlite-synchronous` | better-sqlite3 switches a new database to WAL at FULL, and reopens a WAL database at NORMAL (`SQLITE_DEFAULT_WAL_SYNCHRONOUS=1`) | `synchronous` FULL set on every connection: each commit of a money record is synced |
| `rpc-key-provider-id` | any id in main's registry, which a renderer can extend (`networks:upsert-source` checks the URLs, not the id), `__proto__` and `constructor` included | main's registry, then an entry name's form: 1 to 52 bytes of lowercase letters, digits, `.`, `_`, `-`; a stored key with another id stays in `rpc-api-keys.json`, answered and removable, and a set for it refused |
| `rpc-keys-bound` | no count bound | at most 16 keys in the secrets file, of its 32 entries; a set that would add a 17th refused; stored keys past 16 stay in `rpc-api-keys.json`, answered and removable |
| `rpc-keys-unreadable` | a file that doesn't read is `{}`, and the next save replaces it | renamed aside and reported |
| `secrets-sealed` | Bee's password and the RPC API keys in files | in the secrets file, where a key store exists |
| `rpc-keys-shell-only` | main reads the keys from a file (the chrome's `getEffectiveUrls`, which returned them inside URLs, is gone on integration) | the chrome sees presence only; only `shell` reads a key |
| `catalog-out-of-process` | main writes the catalog in-process | one-shot subcommands, never the running core |

## Amendments

**2026-11-19, PRF-5's stores (this design):** the coordinator's technical calls, proposed, which the user may veto. `store_moved`, its echo checked by main's `requires`, and `not_moved` for set A; the vault and metadata journal, vault first, with its downgrade boundary, and `vault.delete` leaving `vault-meta.json` (the earlier text had the delete write both, which neither the reference nor the core does); `user_knows_password` on import; `accounts.*`'s changes, `accounts.remove`'s cross-store steps and the callers of each store method; intents' `run`, lock, events and bounds; payments' methods and events; pending Safe transactions' deviations; RPC keys' entries, their bound, and the core's migration under the name, with `rpc-api-keys.json` kept for what the secrets file can't hold; SQLite in the binary, with Zig for musl; the bounds; `stores.json` new, with its own pin; PRF-5's sub-steps and releases. Where the code contradicted a call, the text follows the code: the unlock's migration runs in `quick_unlock.unlock` too; `removeById` isn't ported; RPC keys keep neither `enabled` nor `addedAt`; `add_remote`'s check passes through the chrome ([What stays open](#what-stays-open-at-prf-5)). After the first review, the RPC keys' migration is the core's rather than main's: a set is `not_moved` before the name, and a host without a key store needs one writer of the file after it.

Once decided:
- **0001:**
  - *Quick unlock*: "Phase 5 re-wraps it" points to 0013's re-wrap.
  - *Open questions* 1 is answered as above.
  - *Lifetime lock*: `profile migrate` and `hold-profile` join `hold-lock` and `recover` as gated subcommands; the profile gate, `profile-…`, joins the lock directory's gates; and the lock directory is listed among the app root's shared entries.
  - *Reconciliation*: once `vault_meta` is moved, the core writes the metadata with the vault, `vault.reconcile` answers `meta`, and main's metadata continuation goes.
  - *Messages*: protocol 3; `core.hello` gains `max_protocol` and `store_moved`, and its answer `store_moved`; `Context` gains `profile`; `profile.open` carries `node_roots` and `grant_root`.
- **0010:**
  - step 7's component directories gain `freedom/` (PRF-9);
  - D7 points here for its grants, its default-profile limit before the move, and its tests;
  - the key-store helper and the catalog subcommands are one-shot processes of the kind D5 chose for the Radicle import.
- **0012:** `grant_root` travels in `profile.open` from PRF-8.
- **AGENTS.md:** rules 3 and 4 as in [5.4c](#agentsmd-rules-3-and-4).

## Options weighed

- **Staying in JS for 5.1:** no spawn before the first window, and no new way for startup to fail. But two catalog writers until Stage 2, and the port done later against a reference that may be gone. Kept as the fallback if the latency gate fails.
- **The core holding the profile lock:**
  - **One holder, the core:** nothing holds the lock before the core is up, and nothing while it restarts after a crash. A main alive through 30 s of core restarts would lose its profile to an older build.
  - **Both refreshing:** proper-lockfile marks its own lock compromised when another process sets the mtime (`lib/lockfile.js:129–138`), so main and the core can't both refresh it.

  The profile gate gives the same answer without touching the format. The move holds the lock itself only while main holds none, so there is still one refresher at a time.
- **The core's identity gate as the sign of "open":** the first draft's choice. An override moves the identity directory and nothing records it, so another process can't name that gate; and nothing holds it before `serve` starts.
- **Passing every resolved root to the catalog instead,** so others can name the identity gate: it closes the first gap, not the second, and records each launch's environment in a shared file.
- **The migration under main's lock:** see [The move](#the-move).
- **Catalog methods on `serve`, with a grant over the app root:** one spawn fewer per action in the profile manager, but a compromised core would reach every profile.
- **A session-bus connection kept across `confine`:** every runtime `create` and `forget` would work in `serve`, but a compromised core would hold the bus, which can start programs, for its whole life.
- **Every key created before `confine`,** so `serve` only opens at runtime: it would ask the Secret Service at each start, for a profile with no secret too, and a key forgotten or replaced at runtime would still need the bus.
- **Forgetting inside `profile delete`:** it starts no child, so it can't run the helper, and a failed call there would still need a record that outlives the profile.
- **Dropping the oldest record when a file is full:** deletes and creates would always work, and the item would be left in the key store with nothing to say so. The design refuses the step that would add a record instead.
- **Sweeping every Freedom item that no file names:** a profile with an overridden identity directory, or run with `--profile-dir`, keeps its secrets file where no sweep can see it, so a sweep would forget keys in use.
- **DPAPI's blob in argv:** no second channel, but Windows shows a command line to the user's other processes, and its logs keep it, item id and all, after a replace or a `forget` has dropped the blob ([DPAPI's blob](#dpapis-blob)).
- **The profile's id as DPAPI's entropy,** earlier drafts' choice: another field in each request, and a binding the catalog keeps, not the file that holds the blob.
- **The helper on Linux only,** the Keychain and DPAPI in `serve`: one spawn fewer per call on macOS and Windows, but `serve` would keep the Security server's Mach services on macOS, and a restricted token on Windows would have to keep DPAPI working.
- **`Context.profile` optional, its absence meaning the start profile:** one dialect instead of two, but a client that forgets the field works until a second profile opens. At protocol 3 its absence is an error from the first request.
- **One shared core for all profiles in Electron, over a socket:** any process of the user can reach it. Peer credentials say only "same user".
- **Main's `safeStorage` as the key store:** the core's secrets would stay tied to Electron, which is the Quick Setup problem itself.
- **Reading `safeStorage` ciphertexts in the core:** it would reimplement Chromium's formats per OS, and need the Electron app's keychain access.
- **`biometryCurrentSet`:** stronger against a new fingerprint, and fatal for a Quick Setup user who adds one.
- **The `keyring` crate:** see [Backends](#backends-and-dependencies).
- **Freedom's data per app** (`<appRoot>/freedom/<id>/`) instead of per profile: one grant would cover every profile, but a profile would no longer be one directory, which `--profile-dir`, import and copies rely on.
- **Leaving Freedom's data in place,** and moving only Chromium's in Stage 2: no move at all, but Freedom's and Chromium's files stay mixed, and D7 can never leave the cookies out.
- **Symlinks at the root for older builds:** atomic writes by rename replace a link with a file, and the copies split.
- **Writing both layouts:** two copies that diverge on the first failed write.

## Open questions

1. **Q12, one-way:** May moving data into `<profile>/freedom/` be one-way? *Proposed: yes. Every build from the reader release on reads both layouts. An older build finds a fresh profile and can't create a second identity, and anything it writes is kept aside, unmerged.*
2. **Q13a, quick unlock now:** Move the Quick Setup password now out of Electron's storage into the core, under an OS key that opens without a prompt, on macOS, with Touch ID still asked by the browser as today? *Proposed: yes, in PRF-1 and PRF-2, so Quick Setup users keep access across the shell change.*
3. **Q13b, Touch ID in the OS, later:** Later, make macOS itself require Touch ID (user presence) to open that key, once a signing spike shows the core can carry the entitlement it needs? And Windows Hello, as its own later step? *Proposed: on macOS yes, if the spike passes; until then Q13a's key stays. Windows Hello only if you want it. Not on Linux, which has no OS biometric binding.*
4. **Q14, stores:** Core owns only wallet/permission/feed/intent stores, or every Freedom store? *Proposed: those, plus payments, profiles and secrets (set A), in Stage 1. Settings and caches (set B) stay in main with crash-safe writes.*
5. **Q15, one core:** One **shared** core process for all open profiles in Electron, or only once Chromium runs all profiles in one process? *Proposed: only once Chromium runs all profiles in one process. The core is built for several profiles now, but each Electron profile keeps its own.*
6. **Q16, Swarm keystore password:** Swarm keystore password out of `config.yaml` into the OS key store via the core? *Proposed: yes. Where the OS has no key store it stays in the owner-only `config.yaml`, and a profile copied to another computer needs one re-injection.*
7. **The Mac's password as a fallback:** once macOS itself guards the Quick Setup password (Q13b), may your Mac's login password open it when Touch ID can't (the lid closed, the sensor failing)? *Proposed: yes. Today such a user has only the recovery phrase.*
