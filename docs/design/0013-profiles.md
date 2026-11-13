# 0013: Profiles and Freedom state

**Status:** proposed. Roadmap items 5.1 (profiles in the core), 5.2 (stores), 5.3 (a core for several profiles) and 5.4 (the Stage-2 prerequisites: (a) the key store and the quick-unlock re-wrap, (b) one directory of Freedom data per profile, (c) node keys at rest). Builds on [0001](0001-freedom-cored.md) (the process, the gate, durable writes, quick unlock until Phase 5, Bee's keystore password until Phase 5) and [0010](0010-service-confinement.md) (the protected roots, and D7, confining `freedom-cored`, which waits for this design). It must agree with [0012](0012-approvals.md) (proposed, merged as #264), which owns the four permission files and proposes `phone-payments.json`. It answers 0001's open question 1, on `vault-meta.json`, and proposes an amendment to AGENTS.md rules 3 and 4. Nothing here is built yet. The user decides the [open questions](#open-questions).

**The references:**
- **freedom-browser** at `5484f8dd` (`integration/rust-core`), in `src/main/`:
  - profiles: `profile-resolver.js`, `profile-catalog.js`, `profile-paths.js`, `profile-lock.js`, `profile-launcher.js`, `profile-focus-handoff.js`, `profile-instance-handoff.js`, `profile-switch-scheme.js`, `profile-registry-watcher.js`, `profile-external-candidates.js` (about 4.5k lines together), `index.js` (startup), `migrate-user-data.js`, `service-locks.js`, `service-grant.js`, `ipc-handlers.js` (`ensureProfileClosedForDelete`), `ipfs/ipfsd-gate.js`, `core/core-process.js`;
  - quick unlock: `quick-unlock.js`, and the renderer's `src/renderer/lib/onboarding.js` (`performQuickSetup`);
  - the stores listed under [The stores](#the-stores), `identity-manager.js` (`vault-meta.json`), `lib/durable-journal.js`, `ant-manager.js` (`ensureConfig`);
  - RPC API keys: `wallet/rpc-manager.js`, `networks/network-registry.js`, `networks/network-ipc.js`, the chrome's `preload.js`, and the settings page, `src/renderer/pages/scripts/settings.js`.
- **proper-lockfile 4.1.2**, the reference checkout's: `lib/lockfile.js`.
- **`secret-service` 5.2**'s blocking API, which opens a session-bus connection at each `SecretService::connect`.
- **Browser PRs against main:** #943 (K-3 part 1, head `c1cbe568`; `private-files.js`), #945 (K-5, head `eeb6023f`), #946 (K-3 part 2, head `2a260195`; `swarm/ant-keystore-password.js`, `swarm/ant-config-password.js`). SEC-3d (#1029) merges #943 and #945 into integration; SEC-3f adapts #946 after it (the coordinator's decision, Option A of the SEC-2 audit). **Issue #963:** Windows key-file I/O binds to directories by path.
- **freedom-core** at `bcc385e9` (`main`): `freedom-cored/src/fsx.rs` (durable writes), `anchor.rs` (handle-relative node files), `nodes.rs` (Bee's `config.yaml`), `exit.rs`, `main.rs` (`hold-lock`), `serve.rs` (`core.hello`), `fc-service/src/gate.rs`, `fc-service/src/confine/`, `fc-seal` (HPKE), `fc-sys`, `fc-protocol/src/lib.rs` (protocol versions) and `message.rs` (`Context`).
- **Design 0012**, proposed, merged into `main` as #264 (`bcc385e9`), and 0010's one-shot Radicle import (D5), the pattern for this design's one-shot processes.
- **Apple's TN3137**, *On Mac keychain APIs and implementations*: the data protection keychain, which biometric access control needs, needs a keychain-access entitlement backed by a provisioning profile.

## Summary

- **Today** each profile is one Electron process. Main picks the profile from argv, the environment and the shared catalog, points `userData` at it (`app.setPath`) before anything else touches storage, and holds a lock directory in it whose mtime it refreshes. Every Freedom store is a JSON, JSONL or SQLite file that main writes itself, most in place.
- **5.1, resolving the profile:** a synchronous subcommand, `freedom-cored profile open`, which main runs with `spawnSync` before `app.setPath`. It applies today's rules and writes the catalog durably. The catalog's other operations are one-shot subcommands too, so the running core never touches the catalog or another profile. Main keeps the argv parsing, the launch and hand-off glue, and the profile lock in today's format, so older builds see an open profile as open. If the subcommand misses its latency budget on any OS, `open` stays in JS, and only the catalog's other operations move.
- **The profile gate:** an OS lock keyed by the profile's `userData`, which a small `hold-profile` process holds for main from before it takes the profile lock until after it lets go. A profile counts as open when its lock is fresh **or** that gate is held, and a delete holds every gate of the profile it removes. That fixes the stale-lease delete, for overridden layouts and for a main that stalls before its core is up too.
- **5.2, the stores ([Q14](#open-questions)):** the core owns the stores that decide or record authority and money: wallet (`vault-meta.json`, the intent journal, pending Safe transactions), permissions (0012's four files and `phone-payments.json`), feeds (0015's), payments, profiles, and the secrets. Each stays in today's format, byte for byte, with 0001's atomic writes. SQLite schemas are kept. Stored RPC API keys reach only the shell, never a renderer. The other Freedom stores stay in main and get durable writes. History, bookmarks and downloads aren't ported.
- **5.3, several profiles ([Q15](#open-questions)):** one core per profile while Electron runs one process per profile. The core gains a profile dimension now: per-profile vault, lock state, throttle, gates, stores and secrets, carried in the caller context at a new protocol version, 3, and tested with two profiles over one pipe. The core keeps protocol 2 during the rollout, and `core.hello` settles which one a pair speaks, so the current browser works with the new core and the reverse. One shared core for all profiles comes with Chromium, which has one parent process. The transport stays a pipe in both stages, never a socket.
- **5.4a, the key store ([Q13a, Q13b](#open-questions)):** a `KeyStore` trait in a new logic crate, `fc-keystore`, that makes and keeps 32-byte wrapping keys under one of two policies, `Unattended` or `UserPresence`. Every secret is AES-256-GCM under such a key in one file per profile. Backends: the macOS Keychain (`security-framework`), Windows DPAPI (through `fc-sys`), the Secret Service on Linux (`secret-service`), and Android Keystore and the iOS Keychain through `freedom-mobile-ffi`. On desktop every key-store call runs in a one-shot helper, `freedom-cored keystore`, that main starts for it, so `serve` never connects to a key-store service, before or after it confines itself. An item stays named in a file until its `forget` succeeds: the profile's secrets file, or, after a profile delete, a forget file beside the catalog.
- **The quick-unlock re-wrap comes early (PRF-1, PRF-2).** PRF-2 ships once profile deletes go through the core (PRF-4), so a deleted profile's items are always recorded. At the next Touch ID use, main hands the password it unsealed to the core once. From then on the core holds it, and Quick Setup writes it together with the vault. Today's `quick-unlock.dat` stays in place for older builds. Biometric binding in the OS waits for a signing spike, and Touch ID stays main's prompt until then.
- **5.4b, the Freedom directory ([Q12](#open-questions)):** every Freedom-owned entry of a profile moves into `<profile>/freedom/`, and the shell's data stays at the root. A reader release, which reads both layouts and finishes a move it finds, ships first. The move ships late, as the last Stage-1 step. It is one rename per entry (a copy only across devices), journaled, rolled back before its marker and forward after. It runs before main takes its own lock, and holds the profile lock itself in today's format, refreshed from its own thread, so older builds see the profile open however long it takes. Builds older than the reader can't open the moved identity, by design.
- **5.4c, Bee's keystore password ([Q16](#open-questions)):** the core keeps it in the profile's secrets file and writes antd's one-use `--password-file` itself. It reads #946's seals as migration input: main opens the ciphertext, and the core checks it against the keystore. `config.yaml` keeps the password only where the OS has no key store. AGENTS.md rules 3 and 4 change to match. `fc-sys` gains Windows handle-relative file calls, which closes #963 for every file the core writes.
- **`vault-meta.json`** becomes the core's: in place, in today's format, written with the vault as one journaled operation where both change. Device, phone and Safe records stay in it and keep working while the vault is locked (0001's open question 1).
- **0010 and D7:** the protected roots gain `freedom/`'s entries. D7 can confine `serve` to the profile's directory as soon as it is designed, and narrow it to `freedom/` after the move. Before the move that separates a named profile from the others, but not the packaged default profile, whose directory is the app root; after it, both. The catalog and other profiles are the subcommands' work, never `serve`'s. `serve` makes no network connection, and its only local IPC is main's pipe.
- **Facts found:** a stale-looking lock is trusted for deletion; deletion holds only the IPFS gate; on macOS and Windows, deleting the packaged default profile removes the shared lock directory; and the chrome renderer's preload can fetch the RPC pool with the API keys in its URLs.

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
5. **The chrome renderer can fetch the RPC API keys.** The chrome's preload exposes `rpcManager.getEffectiveUrls` (`preload.js:995–1000`). Its handler returns the chain's RPC pool with each key substituted into its URL (`rpc-manager.js:178–182`, `network-registry.js:475–490`). No renderer code on integration calls it: the settings page gets only `hasKey` for each keyed provider (`network-ipc.js:108`, `settings.js:3066`), and sets, tests or removes a key without reading one back.

## Threat model

Stage 1 trusts main (0001). What this design adds protection against:

| Threat | Today | With 0013 |
|---|---|---|
| A torn write loses grants, intents, account records or the catalog | in place or unflushed renames | 0001's durable atomic writes for the core's stores; a durable helper for main's |
| Bee's keystore password beside the keystore (K-3) | `config.yaml`; #946 seals it with `safeStorage` | the core's secrets file under the OS key store; `config.yaml` only where there is none |
| RPC API keys in plain JSON (K-5) | `rpc-api-keys.json` (#945: owner-only) | the secrets file |
| Quick Setup users locked out by a shell change | the only copy is Electron's `safeStorage`, bound to the `userData` path | the core's key store, from PRF-2 |
| A live profile deleted under itself | a stale lock is trusted | a held profile gate means open, from before the lock to after it; deletion holds every gate |
| An older build entering a profile mid-move | — | the move holds the profile lock in today's format, refreshed from its own thread |
| The shared lock directory removed with the default profile | `locks` isn't a shared entry | kept |
| Two writers on one store | the profile lock only | one writer per store, and the core's gate |
| A same-user process swapping a directory on Windows (#963) | checked by path | handle-relative calls for every file the core writes |
| A compromised service reading Freedom data (0010) | protected roots by component | the same, with `freedom/`'s entries |
| A compromised core reaching other profiles, the catalog or the session bus (D7) | not confined | `serve` confined to its profile's data (the default profile only after the move); catalog work in one-shot subcommands; key-store calls in a one-shot helper |
| A compromised chrome renderer reading RPC API keys (0011's adversary) | `rpcManager.getEffectiveUrls` returns them inside URLs | plaintext only to the shell; the chrome sees which providers have a key, and can set or remove one |

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
- **The latency gate (PRF-3):** the subcommand's wall time, measured by main around `spawnSync`, must stay under 100 ms at the 95th percentile on each OS's CI runner, cold start included, on the optimized binary main ships.
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
  - the JSON Lines journal;
  - SQLite.

  Each store's codec, the bytes it reads and writes, lives in a logic crate with its rules: `fc-approval` for 0012's files, and `fc-profile` for the catalog. `vault-meta`'s, the intents' and the payments' go in a new logic crate, `fc-wallet-state`.
- **JSON:** today's text byte for byte: the same keys, `JSON.stringify(…, null, 2)`'s spacing, and JS's insertion order as each operation leaves it, pinned by vectors after every operation. Written by 0001's single-file write: temp file, fsync, rename, directory flushed, mode 0600. 0012's rules for failed and narrowing writes apply to every set-A store.
- **The intent journal** keeps `lib/durable-journal.js`'s format and rules exactly:
  - a line is `{"v":1,"sha256":"<hex>","record":<record>}`, the checksum over the record's exact bytes;
  - each append is synced before it is acknowledged;
  - a whole last record without its newline is accepted;
  - a torn tail is cut off, and a damaged line is skipped and reported;
  - compaction goes through a temp file and a rename;
  - the 64 MiB bound stays.

  The core's port reads every file the JS wrote, and the JS reads every file the core writes. APR-6 (0012) builds the nonce and the broadcast on it.
- **SQLite** goes through `rusqlite`, which AGENTS.md rule 7 already lists, with its bundled SQLite:
  - **Schemas are kept:** the same tables, columns, indexes, `user_version` and WAL mode. The core never changes a schema, or the user version, while a build that may still open the file reads the old one. A change needs a design.
  - **`payment-history.sqlite`'s one-shot import** of `x402-receipts.json` (renamed `.migrated` afterwards) is ported too, for a profile that no build since that import has opened.
  - **One writer:** a database is opened by one process at a time, so main stops opening it in the same PR in which the core starts.
- **Main's set B** gets one shared helper with the same steps in JS, `lib/atomic-file.js` (temp file, fsync, rename, directory sync, as `durable-journal.js`'s compaction already does), and each in-place writer moves onto it.

### `vault-meta.json`

**Proposed: the core owns it,** in the identity directory, in today's format, from PRF-6.
- **Methods:** one per change `identity-manager.js` makes today (`accounts.*`: list, add a mnemonic account, add a device or Safe record, rename, set the active one, mark a Safe deployed, remove), each pinned by the file's text after it. The core already derives the mnemonic accounts' addresses (`keys.addresses`), and the other records are public data main supplies.
- **With the vault:** `vault.create`, `vault.import` and `vault.delete` write the vault and `vault-meta.json` as one operation, through 0001's multi-file journal, so a crash can't leave a vault without its metadata, or the reverse. That also takes the metadata step out of 0001's *Reconciliation*. Main no longer writes `vault-meta.json` after a committed result. Other changes write it alone.
- **0001's open question 1:** device, phone and Safe records stay in `vault-meta.json`, owned by the core, and keep working while the vault is locked. That is acceptable: they are public addresses and settings, and the core's own checks (0012) need to know an account's type.

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
  - **the vault deleted:** the secrets file joins `vault.delete`'s journaled operation (0001's multi-file journal), with the entry removed and its key moved the same way. A crash before the journal commits leaves the vault, the entry and the key in use; after it, none of them, and the key in `forget`;
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

  Main runs one helper at a time, each under `forget`'s 10 s deadline, and none on the startup path. Two mains draining at once do no harm: a `forget` of a missing item succeeds, and `forget-done` for an id no longer listed changes nothing. Nothing retries on a timer.
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

### The re-wrap

- **PRF-1 (core):**
  - the helper with its macOS backend, and the core's desktop `KeyStore` over `shell.keystore`;
  - `quick_unlock.enroll { password }` checks the password against the vault, sharing 0001's throttle. It then writes the `quick-unlock` entry, bound to the vault file's SHA-256 (today's binding, without the path), under `UserPresence` where available and `Unattended` otherwise.
  - `quick_unlock.unlock {}` unlocks with it, so the password stays in the core. `quick_unlock.export_mnemonic` and `export_private_key` are the Touch ID exports.
  - `quick_unlock.status` and `quick_unlock.disable` complete the set.
  - `vault.create` and `vault.import` gain `quick_unlock: true`. That writes the entry before the vault commits, bound to the new vault's digest, so a Quick Setup vault never exists without its credential. A crash between the two leaves an entry that names no vault, which the core removes at start.
  - `vault.change_password` writes the new vault and the re-wrapped entry as one operation.
- **PRF-2 (browser):**
  - Main's `shell.keystore` executor, which checks the request and runs the helper.
  - At the next Touch ID unlock or export, a profile with only `quick-unlock.dat` goes through it once, as today. Main then sends the password it unsealed to `quick_unlock.enroll`. Later unlocks call `quick_unlock.unlock` behind main's Touch ID prompt.
  - Quick Setup prompts for Touch ID first, then creates with `quick_unlock: true`, and still writes `quick-unlock.dat` for older builds.
  - `quick-unlock.dat` is left byte for byte. Disabling removes both credentials.
  - The release before any shell switch prompts each macOS profile that has a vault but no core credential for Touch ID once, to enroll. A profile never opened in that window keeps only its recovery phrase. The design states that risk; it doesn't hide it.
- **The policy for a Quick Setup vault is `userPresence`,** never `biometryCurrentSet`. The latter destroys the item when a fingerprint is added, and a Quick Setup user has no other copy of the password. Which fallback `userPresence` may use is the [open question](#open-questions) on the Mac's password.
- **The core never reads `quick-unlock.dat`.** Its ciphertext is Electron's: Chromium's keychain item for the app, and the app's signature. Reading it would mean reimplementing `safeStorage` and borrowing the app's keychain access.

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
- **A crash or a kill in a profile delete:** before the catalog changes, the forget record names items that the profile's own file still names, so the next run drops them without a `forget`, and the profile opens as before. After it, every item is in the forget file, and main forgets it at the next start of any profile, whether or not the data's removal finished. A main killed between the helper's answer and `forget-done` leaves a record whose next `forget` answers `not_found`, which counts as success.
- **The key store unavailable or reset:** each secret falls back to its documented path (re-inject, quick unlock off, RPC keys re-entered). Nothing is deleted on a failed open, and a Quick Setup credential is never removed except by an explicit disable or a vault delete (0001: nothing destructive is inferred from a missing credential).
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
| `core.hello` | shell | gains `max_protocol`; at 3, its answer carries `profile` ([5.3](#53-one-core-several-profiles-q15)) |
| `profile.open` / `profile.close` | shell, protocol 3 | [5.3](#53-one-core-several-profiles-q15) |
| `accounts.*` | chrome, shell | one per `vault-meta.json` change |
| `intents.*` | shell | `intent-store.js`'s record kinds: commit, handoff, outcome, settle, void, retire, track, and the reads |
| `payments.*`, `safe_pending.*` | shell, chrome | the modules' operations |
| `quick_unlock.enroll`, `.unlock`, `.export_mnemonic`, `.export_private_key`, `.status`, `.disable` | chrome (after main's Touch ID prompt), shell (enroll) | [The re-wrap](#the-re-wrap) |
| `secrets.rpc_api_keys` | shell only | the keys main needs for the requests it runs |
| `secrets.rpc_api_key_status`, `secrets.set_rpc_api_key`, `secrets.remove_rpc_api_key` | chrome, shell | `{ providers: [{ id, present }] }`, never a key; a set replaces any key the provider had |
| `nodes.bee_handoff`, `nodes.bee_handoff_done`, `nodes.adopt_bee_password` | shell | [5.4c](#54c-bees-keystore-password-q16) |

New request errors: `no_profile`, `key_store_unavailable` (with `data.reason`: `timeout`, `forget_backlog`, …), `key_store_cancelled`.

**RPC API keys stay out of the renderers.** `secrets.rpc_api_keys` answers only `shell`, and a `chrome` caller gets `forbidden`. The settings page sees which providers have a key, as it does today (`hasKey`), and can set, replace or remove one and test a key the user types, but can't read a stored one back. No product need asks for more: today's page shows nothing but presence ([Facts found](#facts-found-while-checking-the-code), 5). PRF-6(e) also removes the chrome preload's `rpcManager.getEffectiveUrls`, which no renderer calls. Main substitutes a key only into a request it runs itself.

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
- **`quick-unlock.json`:** the v2 credential's text with a stub `safeStorage`, its binding (the real path's hash, the vault's fingerprint), legacy detection, and the parse failures. These are what main keeps reading through PRF-2.
- **`stores.json`** (0012 starts it): each set-A store's text after each operation, `vault-meta.json` through each `identity-manager.js` change, and `safe-pending.json`. Each malformed file, and what the reference loads from it.
- **`journal.json`:** `durable-journal.js`'s lines and checksums, a whole last record without its newline, torn tails, a damaged line, compaction, and the 64 MiB bound.
- **`bee-seal.json`:** #946's seal records, valid and not, with `readSeal`'s verdicts; the serde_yaml fixture of `password:` lines with their decoded passwords; and keystore digests.
- **`sqlite.json`:** `sqlite_master`'s rows and `user_version` for both databases as the reference creates them, and the rows after the reference's operations.
- **The design's own,** with no reference (`source: design`): the secrets file under a fixed key and nonce, with the associated-data refusals, a `pending` item and a `forget` list at its bound; the forget file at its bounds, with a record still listed in the catalog and one gone, and one past a bound; the helper's answers under a fixed request key, with the refusals; the profile gate's file name for each kind of profile; the layout list for each kind of profile (packaged default, named, dev, `--profile-dir`, test); and the move journal's states.

## Migration

One PR per step: the core's against `main`, the browser's against `integration/rust-core`.

| Step | Repo | What | Needs | The tests that prove it |
|---|---|---|---|---|
| PRF-1 | core | `fc-keystore` (trait, policies, the secrets file and its `forget` list); the helper, `freedom-cored keystore`, with the macOS `Unattended` backend; the core's desktop `KeyStore` over `shell.keystore`; `quick_unlock.*`; `quick_unlock: true` on create and import; the re-wrap on change of password; the entitlement spike for `UserPresence` | — | Secrets vectors byte for byte; an entry under another name, binding or key refused. On macOS CI, a temporary keychain: create, open, replace and forget through the helper, and `NotFound` after forget. **The helper's contract:** an answer not sealed to the request's key, or sealed for another op or item, is refused; a reply over 4 KiB, no reply, and a helper past its deadline are `Unavailable` or `Backend`; a helper killed after the OS stored the item and before it answered leaves the file's committed state as it was, and the `pending` item moves into `forget` and is forgotten at the next open; no wrapping key appears in argv, stdin or the bytes main relays; bytes on stdin are refused with no OS call; a Keychain key whose `sealed` isn't `null` is out of form. **Forgetting, killed at each step:** for a replace, a quick-unlock disable and a vault delete, a crash hook before and after each write (the `pending` write, the commit or removal that moves a key into `forget`, the record's removal), and the helper killed or held past its deadline at each `create` and `forget`. After a restart at each point, the file names every Freedom item the temporary keychain holds, the committed keys and entries are the old set or the new, and after the next open the keychain holds only the keys in use and the file no record. A record whose item was removed by hand, or whose backend this OS doesn't have, is dropped at the next open without an error. With `forget` made to fail, the `create` that would make a fifth named item is refused with `forget_backlog` and changes nothing, and works once a `forget` succeeds. Enroll refused for a wrong password and throttled with `vault.unlock`. Unlock works locked and unlocked. A failure hook at each step of create-with-credential and of change-password leaves the old pair or the new, never a vault without its credential. An entry naming no vault removed at start. iOS and Android builds pass |
| PRF-2 | browser | Main's `shell.keystore` executor, which runs the helper, and its drain of the forget file after a delete and at start. The re-wrap: enroll at the next Touch ID use; unlock through the core; Quick Setup creates with the credential and still writes `quick-unlock.dat`; disable removes both; the one-time prompt before a shell switch | PRF-1's and PRF-3's releases pinned; PRF-4 shipped, so no build makes a key-store item before its deletes record it | The migration suite: a profile with a v2 and one with a legacy `quick-unlock.dat` unlocks once through it and then through the core, with the file's bytes unchanged. **Downgrade:** the reference `quick-unlock.js` still unlocks from it. A password change keeps quick unlock in the core. The Quick Setup e2e on macOS with a stubbed Touch ID; Quick Setup's failure path deletes nothing the core committed. **The drain, killed at each step:** main killed after `profile delete` answered and before the helper ran, the helper killed or held past 10 s, and main killed between the helper's answer and `forget-done`. At the next start of another profile the drain runs after the first window, and the temporary keychain holds none of the deleted profile's items. Two profiles' mains draining at once both leave the file empty. Main killed while a replace, a disable or a vault delete waits on `forget`: the profile's next open finishes it |
| PRF-3 | core | `fc-profile`; `profile open`; the catalog subcommands and `profile status`; `hold-profile` and the profile gate; the catalog's write lock, refreshed by a long holder; deletion under every gate, recording the target's key-store items in the forget file first; `forget-list` and `forget-done`; `locks` kept; `profile migrate --finish-only`, the move's recovery, which starts no move, under the move's own exclusion | — | `profiles.json` replayed. The latency gate on every OS. A Jest harness runs the reference's `createProfile` and `renameProfile` against the subcommands in a loop: the catalog stays valid, and no record is lost. **The write lock both ways:** the reference holds it past 10 s while a subcommand waits, and a subcommand holds it past 10 s while the reference waits; neither takes over a live lock, and each takes over a dead holder's at 30 s, not at 29,999 ms. **The stale-lease case:** a lock backdated 31 s with the target's profile, core, IPFS or Radicle gate held refuses the delete, with nothing changed. `hold-profile` refuses a catalog profile no longer listed at its directory. Each subcommand, confined, can't read outside its grant. The default profile's delete keeps `locks/` and every other shared entry. **The forget file:** a crash hook at each step of a delete (before the record, after it and before the catalog changes, after the catalog changes, mid-removal, before the result). Before the catalog changes, the next `forget-list` drops the record, and the profile's own file still names its items; after, `forget-list` returns every item. A deleted profile imported again from a leftover directory whose secrets file survived keeps its items; one created again under the same id doesn't stop the old ones being forgotten. A full file refuses the delete with nothing changed. A target secrets file that can't be read lets the delete go on, with `forget_unknown`. The default profile's delete keeps the forget file, and so does the reference's `removeDefaultProfileDataFromAppRoot`. A malformed forget file is renamed aside, and nothing it names is forgotten |
| PRF-4 | browser | `profile open` before `app.setPath`; `hold-profile` from `app.setPath` until after the lock's release; the profile manager and node settings through the subcommands; "open" means a fresh lock or a held profile gate; **the reader release**: one Freedom-root resolver, and `profile migrate --finish-only` before the lock when `profile open` reports a journal | PRF-3's release pinned | `npm run test:migration` and the profile e2e specs, unchanged. The stale-lease probe refused. **Overrides:** catalog profiles launched with each of `FREEDOM_IDENTITY_DATA`, `FREEDOM_ANT_DATA`, `FREEDOM_BEE_DATA`, `FREEDOM_IPFS_DATA`, `FREEDOM_TOR_DATA`, `FREEDOM_RADICLE_DATA` and `MYOTIS_DATA_DIR`, their locks backdated 31 s: another profile's manager reads each open, and its delete is refused with nothing changed. **A launch held before `serve`:** a test hook stops main after it takes the lock and before the core starts, for 45 s; a second launch hands over or reports the profile busy, and a delete from another profile is refused. The holder killed while main runs: main takes the gate again, or quits. **Downgrade:** the reference resolver opens a catalog the subcommands wrote. A profile in the moved layout, built from the layout vectors, opens, and so does one with a journal pending before and after its marker. **Windows's first scan** ([the latency gate](#51-resolving-the-profile)): the PR records the Defender-enabled, no-exclusions runs on a fresh machine (a newly downloaded release artifact's first `profile open`, and the first after each of several reboots); if any reaches 1 s, `profile open` stays in JS on Windows |
| PRF-5 | core | `fc-store` (JSON, the journal, SQLite); `fc-wallet-state`; `accounts.*`, `intents.*`, `payments.*`, `safe_pending.*`, `secrets.*` (`rpc_api_keys` for `shell` only); vault and metadata as one write; the Windows handle-relative calls in `fc-sys` | PRF-1 | Each store's text after every vector's operation, byte for byte. `secrets.rpc_api_keys` from `chrome` is `forbidden`, and `rpc_api_key_status` answers presence and no key bytes. The journal vectors in both directions. The SQLite schema rows equal the reference's, and a database each side wrote is read by the other. A failure hook at each write step (temp write, fsync, rename, directory flush) leaves the file as it was, or reports `durable: false`. On Windows: a directory swapped for a junction between the open and the write is refused, and the file lands nowhere else; a reparse point at a child's name refused; renames and deletes by handle |
| PRF-6 | browser | Set A through the core, one store per PR: (a) `vault-meta.json`, (b) the intent journal, then 0012's APR-6, (c) payments, (d) pending Safe transactions, (e) RPC API keys into the secrets file, the settings page on `rpc_api_key_status`, and `rpcManager.getEffectiveUrls` removed from the chrome preload. Set B onto `lib/atomic-file.js` | PRF-5's release pinned | Each module's Jest suite against the core. An `fs` spy shows main writes none of the store's files. **Rollback:** the reference module reads the file the core wrote and sees the same state. RPC API keys: the old file is removed only after the entry is written; with no key store it stays, owner-only; no renderer channel returns a key, or a URL with one in it |
| PRF-7 | core, then browser | Bee's keystore password: the helper's Linux and Windows `Unattended` backends, and main's executor passing DPAPI's blob on stdin; `nodes.write_identity` without the line; `bee_handoff`, `bee_handoff_done`, `adopt_bee_password`; the browser's Ant start through them; the AGENTS.md amendment | PRF-5; SEC-3f | `bee-seal.json` replayed. Through the helper, on Linux CI's private session bus with a Secret Service and on Windows: create, open, replace and forget; PRF-1's and PRF-2's forgetting tests on the Secret Service, and on Windows a dropped key that leaves no record and copies no blob; **DPAPI's blob, on Windows CI:** `create`, then `open` in a fresh helper once the first has exited, and again after the core restarts, from the blob in the file; a replace is a `create` and one write, with the old blob gone from the file, no helper run for it, and the new key opening in a fresh helper; a DPAPI `forget` makes no call, a stray one answers `ok`, and a `pending` DPAPI id left over is dropped at the next open with no call; refused by the core, by main and by the helper each, before any OS call: a blob missing, of 1 KiB and one byte, or not in base64 form, and a `sealed` or stdin bytes with a `create` or a `forget`; `invalidated`, with nothing deleted and each secret on its fallback path: a blob changed in one byte, cut short, sent with another item's id, or made under no entropy; a `create` answer whose blob is changed on the way doesn't open; the blob never appears in the helper's command line, and a `create` answer with a 1 KiB blob fits in 4 KiB; a locked collection whose prompt is dismissed is `Cancelled`; no Secret Service is `Unavailable`, and each secret stays where it is. Adoption from a seal, and from a `password:` line in every form the fixture holds. Refused for a seal of another keystore, for a password that doesn't open it, and for a keystore changed between the check and the write. The hand-off file is 0600 in a 0700 directory, gone after `done`, and an orphan swept. With no key store, `config.yaml` keeps the line. **Downgrade:** a SEC-3f build starts Ant from the seal the core left |
| PRF-8 | core | The profile dimension at protocol 3: `profile.open` and `profile.close`; `Context.profile`; per-profile state; `core.hello`'s `max_protocol`; protocol 2 kept beside it | PRF-5 | Two profiles over one pipe at protocol 3 under the test flag: a lock, an unlock, the throttle, auto-lock and a failed write in one leave the other as it was. At 3, a request without `profile`, or for one not open, refused. A second `profile.open` refused without the flag. At protocol 2, every method served for the start profile, a request carrying `profile` refused, `profile.open` unknown, events without `profile`. A hello with `max_protocol: 3` answered at 3, and one without it at 2 |
| PRF-8b | browser | `core.hello` with `max_protocol: 3`; at 3, every profile-scoped request carries the hello's handle, and events are read by theirs; at 2, today's requests | PRF-8's release pinned | **Both rollout directions:** the integration browser from before this step, its suites run against PRF-8's core, speaking 2; this step's browser against the previous core release, negotiating 2; and against PRF-8's core, speaking 3, with the same results. The two-profile test above, driven from main's client |
| PRF-9 | core, then browser | The move: `profile migrate` starting moves, under its own lock and gates; the marker; the placeholder; downgrade residue set aside; new profiles in the new layout; 0010's component list with `freedom/` | PRF-4 shipped long enough; Q12 | **A crash hook at every step:** before the marker it rolls back to the old layout, which opens; after it, it finishes. A cross-device entry copied and its source kept until the marker. A symlink to a directory on another device moved as the link, its target untouched. A database with a non-empty `-wal` stops the move. A Windows rename held by another handle retried, then rolled back. **Two real builds, each phase held past 30 s:** a test hook holds the move at each step (the journal written, the renames, a cross-device copy, the placeholder, the marker, the cleanup), and `--finish-only` at each recovery phase (a rollback, a roll-forward), for 45 s. Meanwhile an older build, both the last release before the reader and a reader build, tries to open the profile and, from another profile, to delete it: each finds it open and changes nothing, and the lock's mtime keeps advancing. After the run, main's own lock is taken and stays uncompromised. A move frozen past 30 s while another build takes the lock over exits `lock_lost` when it resumes, and changes nothing more. **Downgrade:** a reader build opens the moved profile. An older build can't create a vault under the placeholder. On re-upgrade, its root entries are set aside, unmerged. Every protected root in `freedom/` is refused as a grant |

**D7** comes after this design is decided (D7a), and narrows after PRF-9 (D7b). It ships only once [its tests](#effects-on-0010-and-d7) pass: the catalog and other profiles out of `serve`'s reach, and the key store through the helper after `confine`.

## Rollback and downgrade

- **Each core step is additive** until the browser step that uses it. PRF-8 is too: it keeps protocol 2, so the browser before PRF-8b runs on it unchanged, and PRF-8b's browser runs on an older core at 2. Each browser step reverts on its own until the next one builds on it.
- **No format changes before PRF-9,** except the new files (`secrets.json`, the core's credential, `layout.json`), which older builds don't read. So an older build reads every store at every step up to the move.
- **Each step's tests read the core's output with the reference's code.** That is the rollback guarantee, as in 0001 and 0012.
- **Key-store items and older builds:** a build before PRF-4 deletes a profile without reading its secrets file, so a profile it deletes after a downgrade leaves its items in the key store, named by nothing. Older builds keep the forget file, since their default-profile delete spares its prefix, and don't read it.
- **Secrets that move out of a file** (RPC API keys, Bee's password) leave behind what older builds need, or nothing they would misread:
  - **RPC API keys:** an older build finds no `rpc-api-keys.json` and asks for them again;
  - **Bee's password:** a SEC-3f build finds #946's seal until the core next rewrites the identity, and then takes #946's re-inject path. A build before SEC-3f finds no `password:` line, and its `ensureConfig` refuses to mint one beside the keystore (`ant-manager.js:333–340`).

  These are the costs of Q14 and Q16 on a downgrade, and the questions say so.
- **PRF-9 is one-way for builds older than the reader release** (Q12).

## Deviations

| Id | Today | With the core |
|---|---|---|
| `quick-unlock-password-change` | a password change turns quick unlock off silently | the credential is re-wrapped with the new vault |
| `quick-setup-one-write` | the vault first, then the credential; a failure deletes the vault | written together; nothing to delete |
| `quick-unlock-in-core` | the password crosses into main at each unlock | it stays in the core after the one enrollment |
| `profile-open-gate` | a stale lock is free | free only if the profile gate is free too, which a new build holds from before its lock to after it |
| `profile-delete-gates` | only the IPFS gate is held; a stale lock is trusted | every gate held; any one held refuses |
| `locks-kept` | the default profile's delete removes `locks/` (macOS, Windows) | kept |
| `profile-delete-overlap` | a record's directory is only checked to be inside the app root: one at `Profiles/` or another shared entry, at, above or inside another profile's directory (under any spelling the volume takes for it), or inside the packaged default profile's data, deletes that data with it; so does a record whose slot, and so Radicle home, another record has too | refused before any gate or change |
| `catalog-durable` | renamed without fsync | 0001's durable write |
| `store-durable` | set B in place or unflushed | `lib/atomic-file.js` |
| `vault-meta-unreadable` | reads as missing | renamed aside and reported, as 0012's files |
| `secrets-sealed` | Bee's password and the RPC API keys in files | in the secrets file, where a key store exists |
| `rpc-keys-shell-only` | the chrome's preload can fetch the RPC pool with the keys in its URLs | the chrome sees presence only; `getEffectiveUrls` is gone |
| `catalog-out-of-process` | main writes the catalog in-process | one-shot subcommands, never the running core |

## Amendments

Once decided:
- **0001:**
  - *Quick unlock*: "Phase 5 re-wraps it" points to 0013's re-wrap.
  - *Open questions* 1 is answered as above.
  - *Lifetime lock*: `profile migrate` and `hold-profile` join `hold-lock` and `recover` as gated subcommands; the profile gate, `profile-…`, joins the lock directory's gates; and the lock directory is listed among the app root's shared entries.
  - *Messages*: protocol 3; `core.hello` gains `max_protocol`; `Context` gains `profile`; `profile.open` carries `node_roots` and `grant_root`.
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
