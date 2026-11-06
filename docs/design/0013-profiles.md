# 0013: Profiles and Freedom state

**Status:** proposed. Roadmap items 5.1 (profiles in the core), 5.2 (stores), 5.3 (a core for several profiles) and 5.4 (the Stage-2 prerequisites: (a) the key store and the quick-unlock re-wrap, (b) one directory of Freedom data per profile, (c) node keys at rest). Builds on [0001](0001-freedom-cored.md) (the process, the gate, durable writes, quick unlock until Phase 5, Bee's keystore password until Phase 5) and [0010](0010-service-confinement.md) (the protected roots, and D7, confining `freedom-cored`, which waits for this design). It must agree with 0012 (#264, not merged yet), which owns the four permission files and proposes `phone-payments.json`. It answers 0001's open question 1, on `vault-meta.json`, and proposes an amendment to AGENTS.md rules 3 and 4. Nothing here is built yet. The user decides the [open questions](#open-questions).

**The references:**
- **freedom-browser** at `8e15b10a` (`integration/rust-core`), in `src/main/`:
  - profiles: `profile-resolver.js`, `profile-catalog.js`, `profile-paths.js`, `profile-lock.js`, `profile-launcher.js`, `profile-focus-handoff.js`, `profile-instance-handoff.js`, `profile-switch-scheme.js`, `profile-registry-watcher.js`, `profile-external-candidates.js` (about 4.5k lines together), `index.js` (startup), `migrate-user-data.js`, `service-locks.js`, `service-grant.js`, `ipc-handlers.js` (`ensureProfileClosedForDelete`), `ipfs/ipfsd-gate.js`, `core/core-process.js`;
  - quick unlock: `quick-unlock.js`, and the renderer's `src/renderer/lib/onboarding.js` (`performQuickSetup`);
  - the stores listed under [The stores](#the-stores), `identity-manager.js` (`vault-meta.json`), `lib/durable-journal.js`, `ant-manager.js` (`ensureConfig`).
- **proper-lockfile 4.1.2**, the reference checkout's: `lib/lockfile.js`.
- **Browser PRs against main:** #943 (K-3 part 1, head `c1cbe568`; `private-files.js`), #945 (K-5, head `eeb6023f`), #946 (K-3 part 2, head `2a260195`; `swarm/ant-keystore-password.js`, `swarm/ant-config-password.js`). SEC-3d (#1029) merges #943 and #945 into integration; SEC-3f adapts #946 after it (the coordinator's decision, Option A of the SEC-2 audit). **Issue #963:** Windows key-file I/O binds to directories by path.
- **freedom-core** at `506e8474` (`main`): `freedom-cored/src/fsx.rs` (durable writes), `anchor.rs` (handle-relative node files), `nodes.rs` (Bee's `config.yaml`), `exit.rs`, `fc-service/src/gate.rs`, `fc-sys`, `fc-protocol/src/message.rs` (`Context`).
- **Design 0012** at #264's head `8cb3c771`, branch `docs/0012-approvals`.
- **Apple's TN3137**, *On Mac keychain APIs and implementations*: the data protection keychain, which biometric access control needs, needs a keychain-access entitlement backed by a provisioning profile.

## Summary

- **Today** each profile is one Electron process. Main picks the profile from argv, the environment and the shared catalog, points `userData` at it (`app.setPath`) before anything else touches storage, and holds a lock directory in it whose mtime it refreshes. Every Freedom store is a JSON, JSONL or SQLite file that main writes itself, most in place.
- **5.1, resolving the profile:** a synchronous subcommand, `freedom-cored profile open`, which main runs with `spawnSync` before `app.setPath`. It applies today's rules and writes the catalog durably. Main keeps the argv parsing, the launch and hand-off glue, and the profile lock in today's format, so older builds see an open profile as open. A profile counts as open when its lock is fresh **or** its core's gate is held, and a delete holds every gate of the profile it removes. That fixes the stale-lease delete. If the subcommand misses its latency budget on any OS, `open` stays in JS, and only the catalog's other operations move.
- **5.2, the stores ([Q14](#open-questions)):** the core owns the stores that decide or record authority and money: wallet (`vault-meta.json`, the intent journal, pending Safe transactions), permissions (0012's four files and `phone-payments.json`), feeds (0015's), payments, profiles, and the secrets. Each stays in today's format, byte for byte, with 0001's atomic writes. SQLite schemas are kept. The other Freedom stores stay in main and get durable writes. History, bookmarks and downloads aren't ported.
- **5.3, several profiles ([Q15](#open-questions)):** one core per profile while Electron runs one process per profile. The core gains a profile dimension now: per-profile vault, lock state, throttle, gates, stores and secrets, carried in the caller context and tested with two profiles over one pipe. A core for every profile comes with Chromium, which has one parent process. The transport stays a pipe in both stages, never a socket.
- **5.4a, the key store ([Q13](#open-questions)):** a `KeyStore` trait in a new logic crate, `fc-keystore`, that seals 32-byte wrapping keys under one of two policies, `Unattended` or `UserPresence`. Every secret is AES-256-GCM under such a key in one file per profile. Backends: the macOS Keychain (`security-framework`), Windows DPAPI (through `fc-sys`), the Secret Service on Linux (`secret-service`), and Android Keystore and the iOS Keychain through `freedom-mobile-ffi`.
- **The quick-unlock re-wrap comes early (PRF-1, PRF-2).** At the next Touch ID use, main hands the password it unsealed to the core once. From then on the core holds it, and Quick Setup writes it together with the vault. Today's `quick-unlock.dat` stays in place for older builds. Biometric binding in the OS waits for a signing spike, and Touch ID stays main's prompt until then.
- **5.4b, the Freedom directory ([Q12](#open-questions)):** every Freedom-owned entry of a profile moves into `<profile>/freedom/`, and the shell's data stays at the root. A reader release, which reads both layouts and finishes a move it finds, ships first. The move ships late, as the last Stage-1 step. It is one rename per entry (a copy only across devices), journaled, rolled back before its marker and forward after. Builds older than the reader can't open the moved identity, by design.
- **5.4c, Bee's keystore password ([Q16](#open-questions)):** the core keeps it in the profile's secrets file and writes antd's one-use `--password-file` itself. It reads #946's seals as migration input: main opens the ciphertext, and the core checks it against the keystore. `config.yaml` keeps the password only where the OS has no key store. AGENTS.md rules 3 and 4 change to match. `fc-sys` gains Windows handle-relative file calls, which closes #963 for every file the core writes.
- **`vault-meta.json`** becomes the core's: in place, in today's format, written with the vault as one journaled operation where both change. Device, phone and Safe records stay in it and keep working while the vault is locked (0001's open question 1).
- **0010 and D7:** the protected roots gain `freedom/`'s entries. D7 can confine the core to the profile's directory as soon as it is designed, and narrow it to `freedom/` after the move. The core makes no network connection, needs the Keychain's Mach services on macOS, and reads the Secret Service before it confines itself on Linux.
- **Facts found:** a stale-looking lock is trusted for deletion; deletion holds only the IPFS gate; and on macOS and Windows, deleting the packaged default profile removes the shared lock directory.

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
- **Windows Hello and Linux quick unlock,** unless Q13 asks for them.

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
  - **Compromise:** the holder marks its own lock compromised when the mtime isn't the one it set, or a refresh runs past the stale time (99–160), and main's handler then throws (`profile-lock.js:77–80`).
  - **When:** main takes it after `app.setPath` (`index.js:143–178`).
- **The core's gate is separate:** `freedom-cored serve` holds `<lock-dir>/<sha256(canonical identity dir)>.lock` for its whole life (0001), freedom-ipfsd holds `ipfs-…` and freedom-radicled `radicle-…` (`fc-service/src/gate.rs`). The core starts after `app.whenReady`.
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

## Threat model

Stage 1 trusts main (0001). What this design adds protection against:

| Threat | Today | With 0013 |
|---|---|---|
| A torn write loses grants, intents, account records or the catalog | in place or unflushed renames | 0001's durable atomic writes for the core's stores; a durable helper for main's |
| Bee's keystore password beside the keystore (K-3) | `config.yaml`; #946 seals it with `safeStorage` | the core's secrets file under the OS key store; `config.yaml` only where there is none |
| RPC API keys in plain JSON (K-5) | `rpc-api-keys.json` (#945: owner-only) | the secrets file |
| Quick Setup users locked out by a shell change | the only copy is Electron's `safeStorage`, bound to the `userData` path | the core's key store, from PRF-2 |
| A live profile deleted under itself | a stale lock is trusted | a held gate means open; deletion holds every gate |
| The shared lock directory removed with the default profile | `locks` isn't a shared entry | kept |
| Two writers on one store | the profile lock only | one writer per store, and the core's gate |
| A same-user process swapping a directory on Windows (#963) | checked by path | handle-relative calls for every file the core writes |
| A compromised service reading Freedom data (0010) | protected roots by component | the same, with `freedom/`'s entries |

**Not covered:** a compromised main; a same-user process, which can read the profile's files directly (outside the boundary, as in 0001 and 0010); root, admin and physical attacks. **On Windows and Linux** the `Unattended` key is readable by any process of the user while the session is unlocked (DPAPI, the Secret Service), so it protects against other users and an offline copy of the disk, not against a same-user process. On macOS the Keychain item's access list adds the code signature. The design calls nothing defense in depth that isn't.

## 5.1 Resolving the profile

**Proposed: `freedom-cored profile open`, a synchronous subcommand that main runs before `app.setPath`.**

```
freedom-cored profile open --app-root <dir> --lock-dir <dir>
    [--dev --checkout-hash <hex8>] [--default-profile-dir <dir>]
    [--profile <id>] [--switch <id>] [--env-profile <id>] [--runtime]
```

- **What it does:** it applies `resolveProfile`'s rules as `fc-profile` ports them (the order above, sanitizing, first-run registration, the fallback, `lastOpenedAt`), creates or updates the catalog record and `profile.json`, and prints one JSON object: `{ outcome: "opened" | "switch_refused", id, display_name, user_data_dir, slot, nodes, switch_only? }`.
  - **Exits:** 0 with that object; 74 (`storage`, with the kind on stderr: unreadable or unsupported catalog, a network filesystem, a path that isn't the user's); 75 when the catalog's write lock stays held; 64 for bad arguments.
  - **A switch** to a profile that isn't open answers `switch_refused`, as `PROFILE_SWITCH_REJECTED` does today.
- **What stays in main:**
  - parsing argv and the `x-freedom-profile:` URL, which are Electron's and the OS's;
  - `--profile-dir` and `FREEDOM_TEST_USER_DATA`, which are path arithmetic without a catalog;
  - finding a dev checkout's root;
  - `app.setPath` itself;
  - the error dialogs, the launcher and the hand-off glue.
- **How main calls it:** `spawnSync` with a 5 s timeout and the core's cleared environment (0001's *Spawn*), from the app's resources. A failure shows today's "Freedom profile could not open" dialog. There is no JS fallback: the catalog keeps one writer per build, and older builds already coexist through the format and the lock.
- **The catalog's write lock** is proper-lockfile's format exactly: `mkdir`, an mtime that a holder over 10 s refreshes, stale after 30 s, a stale lock taken over by removing it. So the subcommand and an older build exclude each other. It holds the lock for milliseconds.
- **Writes:** 0001's durable atomic writes, today's text (`JSON.stringify(…, null, 2)`, JS key order). The temp names keep the `profile-registry.json.` prefix, which `isAppRootSharedEntry` spares (`profile-catalog.js:832–835`).
- **The latency gate (PRF-3):** the subcommand's wall time, measured by main around `spawnSync`, must stay under 100 ms at the 95th percentile on each OS's CI runner, cold start included. Windows builds are unsigned today, so a first scan there counts.
  - **If an OS misses it,** `open` stays in JS on that OS: it is the one call made before any window. `fc-profile` still backs every other catalog operation, and Stage 2.
  - **The cost of staying in JS everywhere:** two implementations of the catalog until Stage 2, and the port done later, when the reference may be gone.
- **The catalog's other operations** move to `profile.*` methods on the running core: create, rename, delete, import, the node settings and the reserved ports ([API](#api)). The profile manager calls them from whichever profile process shows it.

### The lock

- **The format stays exactly today's,** taken by main in JS as today. Older builds read and honor it, and the new build honors theirs. Moving its refresh into the core was weighed and dropped: proper-lockfile marks a lock whose mtime it didn't set as compromised, so a lock can't pass between processes, and two refreshers break it ([Options weighed](#options-weighed)).
- **What "open" means, in new builds:** the lock is fresh, **or** the profile's core gate is held. The gate is held for the core's whole life, and the core exits when main dies (0001). So a live profile whose main loop has stalled still reads as open, though its lock looks stale.
  - **Asking the gate:** `profile open` reports whether the chosen profile's gate is held (`gate_held` in its answer), and the running core answers `profile.is_open { user_data_dir }` for any other profile. Each tries the gate's lock without waiting and lets go at once. A core starting at that moment retries contention for 5 s (0001), so the probe can't make it fail.
  - **Who asks:** the subcommand's switch check, `isProfileLocked`, and a launch about to take a stale lock over.
  - A stale lock with the gate held is treated as held: the launch hands over or reports the profile busy, as for a fresh one.
- **Deletion** holds the target's gates for the whole operation: the core's identity gate, freedom-ipfsd's and, for a catalog profile, freedom-radicled's on its home. Any one held refuses the delete before anything changes. This is 0001's rule, built at last, and it fixes the stale-lease delete. The quit request to a running profile stays as it is, before the delete.
- **The lock directory is kept:** `locks` joins the app root's shared entries. That is a one-line fix in `profile-catalog.js`, and it should ship now, outside the PRF steps.

## 5.2 Stores (Q14)

### Which stores

**Proposed for Stage 1: the core owns set A. Set B stays in main, with durable writes. Set C is the shell's, and isn't ported.**

| Set | Stores | Why |
|---|---|---|
| **A, the core** | **wallet:** `vault-meta.json`, `wallet-intents.jsonl` (and the nonce reservations, in memory), `safe-pending.json`; **permissions:** 0012's four files and `phone-payments.json`; **feeds:** `swarm-feeds.json`, `swarm-manifest-grants.json`, `publish-history.sqlite` (0015 designs their methods); **payments:** `payment-history.sqlite`; **profiles:** `profile-registry.json`, `profile.json`; **secrets:** the quick-unlock credential, Bee's keystore password, the RPC API keys | each decides what may be signed or spent, records money that left, or protects a key. A main bug or a torn file there costs funds or authority |
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

**Proposed: one core per profile while Electron runs one main per profile. One core for every profile only once Chromium runs them all in one process. The core gains the profile dimension now.**

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
- **In Stage 1** `serve`'s `--data-dir` still names the one profile, opened at start as today, and `core.hello`'s answer carries its handle. The core refuses `profile.open`, except under the test build's flag. PRF-8's tests run two profiles over one pipe: a lock, an unlock, a throttle and a failed write in one leave the other as it was.
- **Stage 2's open question,** left to it: a crash takes every profile's unlock state with it, and a confined core can't widen its grants for a profile opened later ([D7](#effects-on-0010-and-d7)).

## 5.4a The key store and the quick-unlock re-wrap (Q13)

### The trait

`fc-keystore`, a logic crate (AGENTS.md rule 2: storage comes in as a trait). It builds for iOS and Android, and `freedom-mobile-ffi` implements the trait in Swift and Kotlin through UniFFI callback interfaces (UniFFI 0.32, rule 7).

```rust
pub enum Policy { Unattended, UserPresence }

pub trait KeyStore {
    /// What this device offers, asked once per profile open.
    fn capabilities(&self) -> Capabilities;
    /// Seals a fresh 32-byte wrapping key. The result is what the secrets
    /// file stores: an item reference, or an OS blob.
    fn seal(&self, key: &WrapKey, policy: Policy, label: &Label) -> Result<Sealed, KeyStoreError>;
    /// Opens it. `UserPresence` asks the user, with `reason`.
    fn open(&self, sealed: &Sealed, reason: &Reason) -> Result<WrapKey, KeyStoreError>;
    /// Removes the item. A missing item is success.
    fn forget(&self, sealed: &Sealed) -> Result<(), KeyStoreError>;
}

pub enum KeyStoreError { NotFound, Cancelled, Unavailable, Invalidated, Denied, Backend(BackendError) }
```

- **Sealing, not storing:** the macOS Keychain and the Secret Service store an item, DPAPI returns a blob, and Android Keystore keeps a key and encrypts with it. `seal` and `open` cover all of these.
- **Only wrapping keys** go to the OS: two per profile at most, one per policy. `WrapKey` zeroizes on drop and has no `Debug`, `Display`, `Serialize` or `Clone` (rule 3).
- **The secrets file** (`identity/secrets.json`, 0600, 0001's atomic write):

  ```json
  { "version": 1,
    "keys": { "unattended": { "backend": "macos-keychain", "sealed": "<base64>" } },
    "entries": { "<name>": { "key": "unattended", "nonce": "<base64, 12 bytes>",
                             "ciphertext": "<base64>", "binding": { … } } } }
  ```

  Each entry is AES-256-GCM (`aes-gcm`, rule 7) under its key. The associated data is `freedom-secrets/1`, the entry's name and its binding's canonical JSON, so an entry moved to another name or another binding doesn't open. Nonces come from the core's RNG and are never reused under a key.
- **Items are named by a random per-profile id,** recorded in the file, not by a path. A profile moved or renamed keeps them. A copy on another machine finds none, and each secret falls back: Bee's password is injected again (#946's path), quick unlock turns off, and RPC API keys must be entered again. Deleting a profile forgets its items after the catalog entry is gone.

### Backends and dependencies

| OS | `Unattended` | `UserPresence` | Code |
|---|---|---|---|
| macOS | a generic-password item in the login keychain, its access list the core's signature | the data protection keychain with `SecAccessControl` (`userPresence`), once the core can carry the entitlement | **`security-framework` 3.7** (MIT OR Apache-2.0), pinned exactly: its `passwords` and `access_control` modules. Its unsafe stays inside it, as D6 accepted for `landlock`. Hand-written FFI would rebuild Core Foundation dictionaries call by call |
| Windows | DPAPI, `CryptProtectData` with the profile's id as entropy and no UI | Windows Hello (`KeyCredentialManager`), only if Q13 says so | **`fc-sys`** (rule 6): `CryptProtectData`, `CryptUnprotectData` and `LocalFree`, each a safe function with its `SAFETY` comment, through `windows-sys`, which `fc-sys` already uses. Hello is WinRT, which needs the `windows` crate (0.62, MIT OR Apache-2.0); not added unless Q13 says Windows too |
| Linux | an item in the Secret Service's default collection | none: no OS biometric binding exists | **`secret-service` 5.2** (MIT OR Apache-2.0), pinned exactly, with `rt-async-io-crypto-rust`, through its blocking API. It brings `zbus` (MIT) and an async-io executor, but no tokio. The step measures the binary's growth, and `cargo deny` must pass. The alternative is `dbus-secret-service`, which links the system's libdbus |
| iOS, Android | Keychain, Android Keystore | Keychain access control, `setUserAuthenticationRequired` | the mobile apps, behind the trait |

- **Not `keyring`** (4.2): it is a facade over the same three. It has no access-control policy and no DPAPI blob of our own, and it would be wrapped again.
- **No backend is ever faked.** A Secret Service that doesn't answer, or no keyring, is `Unavailable`: each secret stays where it is today, with today's owner-only file. That is #946's `v10` rule, kept: the core has no fixed-key fallback.
- **When the OS is asked:**
  - **Unattended keys** are opened when the profile opens, but only if the secrets file holds an entry. On Linux that is the only D-Bus use, and it comes before D7 confines the core. On desktops that log in without a password, gnome-keyring asks to be unlocked then. #946 notes the same prompt at Ant's start.
  - **`UserPresence`** asks at each quick unlock.
- **The entitlement:** biometric access control needs the data protection keychain, which needs the process to carry a keychain-access entitlement authorized by a provisioning profile (TN3137). `freedom-cored` is a bare executable in the app's resources. PRF-1 spikes signing it as a helper bundle with that entitlement. Until that passes, `UserPresence` is `Unavailable` on macOS, and Touch ID stays main's prompt in front of the core, as today.

### The re-wrap

- **PRF-1 (core):**
  - `quick_unlock.enroll { password }` checks the password against the vault, sharing 0001's throttle. It then writes the `quick-unlock` entry, bound to the vault file's SHA-256 (today's binding, without the path), under `UserPresence` where available and `Unattended` otherwise.
  - `quick_unlock.unlock {}` unlocks with it, so the password stays in the core. `quick_unlock.export_mnemonic` and `export_private_key` are the Touch ID exports.
  - `quick_unlock.status` and `quick_unlock.disable` complete the set.
  - `vault.create` and `vault.import` gain `quick_unlock: true`. That writes the entry before the vault commits, bound to the new vault's digest, so a Quick Setup vault never exists without its credential. A crash between the two leaves an entry that names no vault, which the core removes at start.
  - `vault.change_password` writes the new vault and the re-wrapped entry as one operation.
- **PRF-2 (browser):**
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

`freedom-cored profile migrate --profile-dir <dir> --lock-dir <dir>`, run by main with `spawnSync` right after it takes the profile lock, and before it starts the core's `serve`, any node or any store.
1. **Gates:** it holds the core's gate and freedom-ipfsd's, on both the old and the new paths. A gate's name is the digest of a canonical path, so both names are held.
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

### Readers, and the downgrade

- **The reader release (PRF-4):**
  - Every path getter in main and in the core resolves the profile's Freedom root once: `freedom/` if `freedom/layout.json` exists, the root otherwise.
  - It runs `profile migrate --finish-only`, which completes or rolls back a move it finds, and starts none.
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
- **D7, `freedom-cored`'s own confinement,** gets what it needs from this design:
  - **Files, before the move (D7a):** read-write on the profile's `userData`, the lock directory and the profile's Radicle home. That already keeps a compromised core away from other profiles, the user's files and the places that start programs. The core writes set-A files at the root of `userData` with atomic renames, so the grant can't be narrower than that directory.
  - **Files, after the move (D7b):** read-write on `<profile>/freedom/`, the lock directory and the Radicle home. Electron's own data in the same profile, its cookies included, leaves the grant.
  - **Network:** none. Every HTTP request the core makes goes through main's `shell.*` executors (0005, 0006, 0009), so the core needs no socket at all.
  - **Local IPC:**
    - main's pipe;
    - on macOS, the Security server's Mach services, by name, for the Keychain. The qualification gate names them, as 0010 named mDNSResponder's;
    - on Linux, the Secret Service, read before `confine`, after which no D-Bus socket stays open. The session bus can start programs (0010's threat list), so it is never kept.
  - **Processes:** none. `hold-lock`, `recover`, `profile open` and `profile migrate` are separate runs of the binary by main, not children of `serve`.
  - **Stage 2's multi-profile core:** Landlock and Seatbelt can't widen a sandbox, so a profile opened after `confine` needs a new core process or a grant over `Profiles/`. That is left to the Stage-2 design.

## Relation to 0012 and 0015

- **0012's files** keep its rules (format, bounds, failed and narrowing writes, unreadable files set aside), and are set A here.
  - `grant_root` keeps its meaning, "where the grant files are". From PRF-8 it travels in `profile.open`, and after PRF-9 it names `<profile>/freedom/`.
  - `fc-approval`'s store trait is what `fc-store` implements.
  - `phone-payments.json`, which older builds don't read, moves with the rest at PRF-9.
- **The intent journal and the nonces** are set A, so 0012's APR-6 (the nonce, the journal and the broadcast) follows PRF-6's intent step.
- **0015** designs the Swarm stores' methods and rules. They use `fc-store` and move at PRF-9 like every set-A store.

## Failure modes

- **A crash in the middle of a store write:** the temp file is left behind and removed at the next start (0001). The store is either the old file or the new one, never torn.
- **A crash in the middle of the move:** the journal is on disk before the first rename. Before the marker the next start rolls back; after it, it finishes. A crash in a cross-device copy leaves only `<name>.moving`, which the rollback removes.
- **A partial move:** a profile is never opened half-moved. Readers decide by the marker, `--finish-only` settles any journal first, and an unreadable journal stops the profile with a message instead of a guess.
- **Two builds at once:**
  - **On one profile:** the profile lock excludes them in any mix of builds, and the core's gate also excludes two cores.
  - **A stale takeover:** a pre-core build from main can take a stale lock over without a gate. That is 0001's unsupported pairing of two identity writers, and the release notes keep saying so.
  - **On the catalog:** the subcommand and older builds share proper-lockfile's write lock.
  - **During a move:** the move takes the profile lock first, so an older build on the same profile waits or hands over. Other profiles are untouched.
- **A stale profile lock:**
  - **with the gate held:** the profile is open, so a launch hands over, and a delete or a takeover is refused;
  - **with the gate free:** taken over as today. That is a crashed process, or one whose core isn't up yet;
  - **a fresh lock that a crashed process left:** a relaunch within 30 s reports the profile busy, as today. A fresh lock with no gate can't be told apart from a profile still starting, so it isn't taken.
- **A main loop stalled past 30 s** still finds its own lock compromised, and throws (`profile-lock.js:77–80`), as today. With the gate rule, another new build no longer takes the profile over meanwhile.
- **The key store unavailable or reset:** each secret falls back to its documented path (re-inject, quick unlock off, RPC keys re-entered). Nothing is deleted on a failed open, and a Quick Setup credential is never removed except by an explicit disable or a vault delete (0001: nothing destructive is inferred from a missing credential).
- **A full disk:** a write fails before its rename, and the store is unchanged. A move fails before its marker, and rolls back.

## API

| Method | Caller | Shape |
|---|---|---|
| `profile open` (subcommand) | main, before `app.setPath` | above |
| `profile migrate` (subcommand) | main, after the profile lock | `--profile-dir`, `--lock-dir`, `--finish-only` → `migrated`, `nothing`, `rolled_back` or `corrupt` on stdout |
| `profile.open` / `profile.close` | shell | [5.3](#53-one-core-several-profiles-q15) |
| `profile.list`, `profile.create`, `profile.rename`, `profile.import`, `profile.delete` | chrome | today's results; `delete { id, confirm_display_name }` holds the target's gates, answers `lock_held` if one is held |
| `profile.is_open` | shell | `{ user_data_dir }` → `{ open, lock_fresh, gate_held }` |
| `profile.update_nodes`, `profile.reserved_ports` | shell | `updateProfileNodeConfig`'s and `getReservedManagedPorts`' |
| `accounts.*` | chrome, shell | one per `vault-meta.json` change |
| `intents.*` | shell | `intent-store.js`'s record kinds: commit, handoff, outcome, settle, void, retire, track, and the reads |
| `payments.*`, `safe_pending.*` | shell, chrome | the modules' operations |
| `quick_unlock.enroll`, `.unlock`, `.export_mnemonic`, `.export_private_key`, `.status`, `.disable` | chrome (after main's Touch ID prompt), shell (enroll) | [The re-wrap](#the-re-wrap) |
| `secrets.rpc_api_keys`, `secrets.set_rpc_api_key` | shell, chrome | the keys main needs for the requests it runs |
| `nodes.bee_handoff`, `nodes.bee_handoff_done`, `nodes.adopt_bee_password` | shell | [5.4c](#54c-bees-keystore-password-q16) |

New request errors: `no_profile`, `key_store_unavailable` (with `data.reason`), `key_store_cancelled`.

## Vectors

From the JS reference (rule 5), each with its own `meta` naming the pinned commit:
- **`profiles.json`:**
  - `sanitizeProfileId` and `displayNameFromId`, including the refusals;
  - `hashPath` and the checkout id; ports by slot, packaged and dev;
  - `allocateSlot`, `rebaseNodeConfig`, `fillMissingNodeConfig` and the IPFS mode's normalization;
  - every resolution order case: argv, switch, environment, runtime, last opened, fallback, first run;
  - the catalog's and `profile.json`'s text after each operation, under a fixed clock;
  - unsupported catalogs;
  - the delete refusals (the last profile, outside the root);
  - the lock-staleness decision at 29,999, 30,000 and 30,001 ms, and the dev times.
- **`quick-unlock.json`:** the v2 credential's text with a stub `safeStorage`, its binding (the real path's hash, the vault's fingerprint), legacy detection, and the parse failures. These are what main keeps reading through PRF-2.
- **`stores.json`** (0012 starts it): each set-A store's text after each operation, `vault-meta.json` through each `identity-manager.js` change, and `safe-pending.json`. Each malformed file, and what the reference loads from it.
- **`journal.json`:** `durable-journal.js`'s lines and checksums, a whole last record without its newline, torn tails, a damaged line, compaction, and the 64 MiB bound.
- **`bee-seal.json`:** #946's seal records, valid and not, with `readSeal`'s verdicts; the serde_yaml fixture of `password:` lines with their decoded passwords; and keystore digests.
- **`sqlite.json`:** `sqlite_master`'s rows and `user_version` for both databases as the reference creates them, and the rows after the reference's operations.
- **The design's own,** with no reference (`source: design`): the secrets file under a fixed key and nonce, with the associated-data refusals; the layout list for each kind of profile (packaged default, named, dev, `--profile-dir`, test); and the move journal's states.

## Migration

One PR per step: the core's against `main`, the browser's against `integration/rust-core`.

| Step | Repo | What | Needs | The tests that prove it |
|---|---|---|---|---|
| PRF-1 | core | `fc-keystore` (trait, policies, the secrets file); the macOS `Unattended` backend; `quick_unlock.*`; `quick_unlock: true` on create and import; the re-wrap on change of password; the entitlement spike for `UserPresence` | — | Secrets vectors byte for byte; an entry under another name, binding or key refused. On macOS CI, a temporary keychain: seal, open, forget, and `NotFound` after forget. Enroll refused for a wrong password and throttled with `vault.unlock`. Unlock works locked and unlocked. A failure hook at each step of create-with-credential and of change-password leaves the old pair or the new, never a vault without its credential. An entry naming no vault removed at start. iOS and Android builds pass |
| PRF-2 | browser | The re-wrap: enroll at the next Touch ID use; unlock through the core; Quick Setup creates with the credential and still writes `quick-unlock.dat`; disable removes both; the one-time prompt before a shell switch | PRF-1's release pinned | The migration suite: a profile with a v2 and one with a legacy `quick-unlock.dat` unlocks once through it and then through the core, with the file's bytes unchanged. **Downgrade:** the reference `quick-unlock.js` still unlocks from it. A password change keeps quick unlock in the core. The Quick Setup e2e on macOS with a stubbed Touch ID; Quick Setup's failure path deletes nothing the core committed |
| PRF-3 | core | `fc-profile`; `profile open`; `profile.*` and `profile.is_open`; the catalog's write lock; deletion under every gate; `locks` kept; `profile migrate --finish-only`, the move's recovery, which starts no move | — | `profiles.json` replayed. The latency gate on every OS. A Jest harness runs the reference's `createProfile` and `renameProfile` against the subcommand in a loop: the catalog stays valid, and no record is lost. A stale write lock taken at 30 s, not at 29,999 ms. **The stale-lease case:** a lock backdated 31 s with the target's core, IPFS or Radicle gate held refuses the delete, with nothing changed. The default profile's delete keeps `locks/` and every other shared entry |
| PRF-4 | browser | `profile open` before `app.setPath`; the profile manager through `profile.*`; "open" means a fresh lock or a held gate; **the reader release**: one Freedom-root resolver, and `profile migrate --finish-only` at start | PRF-3's release pinned | `npm run test:migration` and the profile e2e specs, unchanged. The stale-lease probe refused. **Downgrade:** the reference resolver opens a catalog the subcommand wrote. A profile in the moved layout, built from the layout vectors, opens, and so does one with a journal pending before and after its marker |
| PRF-5 | core | `fc-store` (JSON, the journal, SQLite); `fc-wallet-state`; `accounts.*`, `intents.*`, `payments.*`, `safe_pending.*`, `secrets.rpc_api_keys`; vault and metadata as one write; the Windows handle-relative calls in `fc-sys` | PRF-1 | Each store's text after every vector's operation, byte for byte. The journal vectors in both directions. The SQLite schema rows equal the reference's, and a database each side wrote is read by the other. A failure hook at each write step (temp write, fsync, rename, directory flush) leaves the file as it was, or reports `durable: false`. On Windows: a directory swapped for a junction between the open and the write is refused, and the file lands nowhere else; a reparse point at a child's name refused; renames and deletes by handle |
| PRF-6 | browser | Set A through the core, one store per PR: (a) `vault-meta.json`, (b) the intent journal, then 0012's APR-6, (c) payments, (d) pending Safe transactions, (e) RPC API keys into the secrets file. Set B onto `lib/atomic-file.js` | PRF-5's release pinned | Each module's Jest suite against the core. An `fs` spy shows main writes none of the store's files. **Rollback:** the reference module reads the file the core wrote and sees the same state. RPC API keys: the old file is removed only after the entry is written; with no key store it stays, owner-only |
| PRF-7 | core, then browser | Bee's keystore password: the Linux and Windows `Unattended` backends; `nodes.write_identity` without the line; `bee_handoff`, `bee_handoff_done`, `adopt_bee_password`; the browser's Ant start through them; the AGENTS.md amendment | PRF-5; SEC-3f | `bee-seal.json` replayed. Adoption from a seal, and from a `password:` line in every form the fixture holds. Refused for a seal of another keystore, for a password that doesn't open it, and for a keystore changed between the check and the write. The hand-off file is 0600 in a 0700 directory, gone after `done`, and an orphan swept. With no key store, `config.yaml` keeps the line. **Downgrade:** a SEC-3f build starts Ant from the seal the core left |
| PRF-8 | core | The profile dimension: `profile.open` and `profile.close`; `Context.profile`; per-profile state | PRF-5 | Two profiles over one pipe under the test flag: a lock, an unlock, the throttle, auto-lock and a failed write in one leave the other as it was. A request without `profile`, or for one not open, refused. A second `profile.open` refused without the flag |
| PRF-9 | core, then browser | The move: `profile migrate` starting moves; the marker; the placeholder; downgrade residue set aside; new profiles in the new layout; 0010's component list with `freedom/` | PRF-4 shipped long enough; Q12 | **A crash hook at every step:** before the marker it rolls back to the old layout, which opens; after it, it finishes. A cross-device entry copied and its source kept until the marker. A database with a non-empty `-wal` stops the move. A Windows rename held by another handle retried, then rolled back. **Downgrade:** a reader build opens the moved profile. An older build can't create a vault under the placeholder. On re-upgrade, its root entries are set aside, unmerged. Every protected root in `freedom/` is refused as a grant |

**D7** comes after this design is decided (D7a), and narrows after PRF-9 (D7b).

## Rollback and downgrade

- **Each core step is additive** until the browser step that uses it. Each browser step reverts on its own until the next one builds on it.
- **No format changes before PRF-9,** except the new files (`secrets.json`, the core's credential, `layout.json`), which older builds don't read. So an older build reads every store at every step up to the move.
- **Each step's tests read the core's output with the reference's code.** That is the rollback guarantee, as in 0001 and 0012.
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
| `profile-open-gate` | a stale lock is free | free only if the core's gate is free too |
| `profile-delete-gates` | only the IPFS gate is held; a stale lock is trusted | every gate held; any one held refuses |
| `locks-kept` | the default profile's delete removes `locks/` (macOS, Windows) | kept |
| `catalog-durable` | renamed without fsync | 0001's durable write |
| `store-durable` | set B in place or unflushed | `lib/atomic-file.js` |
| `vault-meta-unreadable` | reads as missing | renamed aside and reported, as 0012's files |
| `secrets-sealed` | Bee's password and the RPC API keys in files | in the secrets file, where a key store exists |

## Amendments

Once decided:
- **0001:**
  - *Quick unlock*: "Phase 5 re-wraps it" points to 0013's re-wrap.
  - *Open questions* 1 is answered as above.
  - *Lifetime lock*: `profile migrate` joins `hold-lock` and `recover` as a gated subcommand, and the lock directory is listed among the app root's shared entries.
  - *Messages*: `Context` gains `profile`; `profile.open` carries `node_roots` and `grant_root`.
- **0010:**
  - step 7's component directories gain `freedom/` (PRF-9);
  - D7 points here for its grants.
- **0012:** `grant_root` travels in `profile.open` from PRF-8.
- **AGENTS.md:** rules 3 and 4 as in [5.4c](#agentsmd-rules-3-and-4).

## Options weighed

- **Staying in JS for 5.1:** no spawn before the first window, and no new way for startup to fail. But two catalog writers until Stage 2, and the port done later against a reference that may be gone. Kept as the fallback if the latency gate fails.
- **The core holding the profile lock:**
  - **One holder, the core:** nothing holds the lock before the core is up, and nothing while it restarts after a crash. A main alive through 30 s of core restarts would lose its profile to an older build.
  - **Both refreshing:** proper-lockfile marks its own lock compromised when another process sets the mtime (`lib/lockfile.js:129–138`), so main and the core can't both refresh it.

  The gate gives the same answer without touching the format.
- **One core for every profile in Electron, over a socket:** any process of the user can reach it. Peer credentials say only "same user".
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
2. **Q13, quick unlock:** Touch ID quick unlock into the OS keychain with biometrics; Windows Hello and Linux too? *Proposed: macOS now: the re-wrap in PRF-1 and PRF-2, and biometric binding once the core can be signed for it. Windows Hello later, as its own step, if you want it. Not on Linux, which has no OS biometric binding.*
3. **Q14, stores:** Core owns only wallet/permission/feed/intent stores, or every Freedom store? *Proposed: those, plus payments, profiles and secrets (set A), in Stage 1. Settings and caches (set B) stay in main with crash-safe writes.*
4. **Q15, one core:** One core process for every open profile in Electron, or only once Chromium runs all profiles in one process? *Proposed: only once Chromium runs all profiles in one process. The core is built for several profiles now, but each Electron profile keeps its own.*
5. **Q16, Swarm keystore password:** Swarm keystore password out of `config.yaml` into the OS keychain via the core? *Proposed: yes. Where the OS has no keychain it stays in the owner-only `config.yaml`, and a profile copied to another computer needs one re-injection.*
6. **The Mac's password as a fallback:** once the core holds a Quick Setup password, may your Mac's login password unlock it when Touch ID can't (the lid closed, the sensor failing)? *Proposed: yes. Today such a user has only the recovery phrase.*
