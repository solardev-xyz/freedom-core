# 0001: `freedom-cored`, the desktop core process

**Status:** draft, revision 6. It incorporates Codex's four reviews on PR #1. Revision 6 replaces the core's exit on a full reply queue with backpressure ([Transport and framing](#transport-and-framing)). **Scope:** Phase 1 of [freedom-browser#644](https://github.com/solardev-xyz/freedom-browser/issues/644), plus the protocol contract that Phases 2–5 extend.

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

**Decisions** (accepted by the user, 2026-10-11):
- the temporary `compat.*` key exports ([Migration](#migration-in-freedom-browser));
- Touch ID quick unlock stays in the shell until Phase 5 ([Quick unlock](#quick-unlock));
- packaged builds get no runtime switch back to the JS vault ([Rollback](#rollback));
- the intentional behavior changes in the [parity table](#parity-contract).

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
| Torn or exposed secret files (K-2, K-3) | `writeFileSync` with umask permissions | Durable atomic writes. **Unix:** mode `0600`; existing files are tightened in place on adoption. **Windows:** files in the default profile root inherit the per-user `%APPDATA%` ACL. Alternate roots (`--profile-dir`, `FREEDOM_IDENTITY_DATA`) get no such guarantee, and an explicit owner-only DACL is a follow-up |
| Password guessing through `identity:unlock` (K-4) | Unthrottled | Throttled in the core. Renderer-supplied input can't crash the core, so a compromised renderer can't reset the counter |
| Another same-user process reading key memory | Main: a large, unhardened process | **macOS:** the hardened runtime blocks `task_for_pid`. **Linux:** `PR_SET_DUMPABLE=0`. **Windows:** no change |

**Not covered:** root or admin malware, a compromised OS, a compromised main, physical attacks on unlocked memory. `mlock` is deferred (see [Secrets in memory](#secrets-in-memory)).

**Deliberate exceptions to "no raw secret leaves the core"** (AGENTS.md rule 3 is amended to match):
- **Permanent:** the user-requested backup exports (`vault.export_mnemonic`, `vault.export_private_key`), and the mnemonic shown during onboarding.
- **Temporary:** the `compat.*` signing exports, removed in Phase 2.

## Process model

```
Electron main (profile P) ──spawn──▶ freedom-cored serve --data-dir <identityDir> --lock-dir <locksDir> --parent-pid <main's pid>
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
- **Handshake:** `core.hello` must complete within 10 s of spawn. Both sides enforce this. Main kills the core and treats it as a startup failure. The core exits by itself if no `core.hello` has arrived 10 s after start.
- **Startup recovery:** before answering `core.hello`, the core finishes any interrupted node-identity journal (see [Multi-file writes](#multi-file-writes)). Main starts no node before the handshake has succeeded.

### Lifetime lock

- **Where the lock lives:** in a stable directory that is never deleted, and that every Freedom build and profile catalog of the OS user shares: `<OS app-data dir>/Freedom/locks`, which main passes as `--lock-dir`. The same identity directory therefore gets the same gate, whichever catalog, release or dev checkout opens it. The lock file is `<lock-dir>/<sha256(canonical identity dir)>.lock`.
  - The canonical path resolves symlinks, so aliases of one identity directory share one lock.
  - Deleting, moving or recreating the identity directory can't affect a lock that lives outside it.
  - Bind mounts that give one directory several paths aren't covered, and are documented as unsupported.
- **Taking the lock:**
  - The core opens the file for read and write, creating it if needed, never truncating it, and with close-on-exec, which is Rust's default.
  - It then takes `File::try_lock` (`flock` on Unix, `LockFileEx` on Windows).
- **Outcomes:**
  - **Contention:** retry for 5 s (Windows can release a lock a little after process exit), then exit 75 (`lock_held`).
  - **Any other locking error:** exit 74 (`storage`). The core never runs without the lock.
- **Storage qualification,** independent of whether locking succeeds. `flock` can succeed on network filesystems without excluding other hosts, so before locking, the core checks both the lock directory and the identity directory:
  - **Linux:** `statfs` magic numbers for NFS, SMB/CIFS, AFS, Ceph, 9p and FUSE network filesystems.
  - **macOS:** `f_fstypename` in `nfs`, `smbfs`, `afpfs`, `webdav`, `ftp`.
  - **Windows:** `GetDriveTypeW` returning `DRIVE_REMOTE`.

  A known network type means exit 74 with `storage { kind: "network_filesystem" }`. The guarantee is exclusion between cores on local storage.
- **One gate for every core-format writer.** The same `freedom-cored` binary provides two more subcommands, both of which take the gate under the same rules:
  - **`hold-lock --data-dir … --lock-dir …`** prints `locked`, then holds the gate until its stdin closes. Profile delete and reset (`profile-catalog.js`) and data migrations hold it for the whole destructive operation. The gate lives outside the directory being removed, so no core can start until the operation releases it.
  - **`recover --data-dir … --lock-dir …`** takes the gate, rolls forward any node-identity journal (see [Multi-file writes](#multi-file-writes)), prints `recovered` (or `corrupt` with details), then exits.
- **The JS vault writer** (a step-1 dev build without the `FREEDOM_CORE=1` opt-in, or a hotfix that reverts to the JS vault) can't hold an OS lock itself, because Node has no `flock`. So:
  - **It runs `recover` at startup,** before it starts any node or writes any identity file. A journal that a core left behind is therefore always completed first. Such builds keep shipping the binary for this purpose.
  - **Running the JS writer and a core on the same identity directory at the same time is an unsupported configuration,** not something the design can rule out. Packaged builds have no backend switch, and one profile process runs one backend. But alternate roots (`--profile-dir`, `FREEDOM_IDENTITY_DATA`) and different release versions can still bring the two together. Release notes and the profile docs state the limitation.

### Shutdown, crashes and parent death

- **Shutdown:**
  1. Main sends `core.shutdown`, then closes stdin. The core finds it even behind requests that wait for main to read replies ([Transport](#transport-and-framing)).
  2. The core revokes the vault epoch (see [Concurrency](#concurrency-epochs-and-revocation)) and finishes or abandons in-flight work according to its commit state.
  3. It exits 0.

  After 3 s, main kills the core. Killing is safe because every write follows [Writes and durability](#writes-and-durability).
- **Parent death:**
  - The core's I/O task, which is independent of vault work, exits on stdin EOF. EOF in the middle of a frame counts as EOF.
  - **Unix backstop:** main passes its PID as `--parent-pid`. At start the core exits if `getppid()` differs, which means main has already died. On Linux it then sets `PR_SET_PDEATHSIG` and re-checks `getppid()` to close the race. After that it polls `getppid()` every 2 s.
  - **Windows:** relies on EOF. libuv creates main's end of the pipe non-inheritable, so no other process can hold stdin open.
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
- **Backpressure, not exit.** The core's reader holds at most 256 frames and 16 MiB that aren't handled yet, and stops reading beyond them. The vault loop has its own share of the writer, 256 frames. Main can stop reading for a moment, in a GC pause or on a busy main thread, so a full share is no error:
  - **The loop's replies and events wait in the loop, and it takes no new request.** Requests wait in order, each holding its place in the reader, so the reader soon stops reading stdin: main's writes back up, not the core's memory. Freed room wakes the loop; it never polls.
  - **Everything else goes on.** The loop runs its timers, takes its worker's results, and handles lifecycle events, responses (for naming and chain) and main's events.
  - **The auto-lock fires on time.** It wipes the secrets and revokes admitted work at once. Only its event and the revoked requests' `vault_locked` replies wait, and they carry no secret. They are few: after a lock nothing can unlock until requests are taken again, so one lock event at most waits. Replies made before the lock keep their copy until written, as replies being serialized do ([Concurrency](#concurrency-epochs-and-revocation)).
  - **Control requests don't wait:**
    - **`core.shutdown`** among the waiting requests is handled at once. The requests before it are dropped unanswered: none of them was admitted, so none ran, and main is closing the core. A shutdown still in main's own backed-up writes arrives once main reads again; main's kill after 3 s covers a main that doesn't.
    - **`vault.lock`** locks at once, and is acknowledged in its turn. Until then, whatever the requests before it admit is revoked at once: they are answered as if they came after the lock, so nothing main sent before a lock outlives it.
    - **`cancel`** reaches admitted work at once. One whose request waits too waits behind it.
  - **Requests that waited go one at a time** once there is room, each as if it had just arrived: after the loop's timers, and with whatever main sends meanwhile handled between them. An auto-lock that comes due while they drain therefore locks before the next one, and a `vault.touch` among them can't postpone a lock already due. A cancel or `core.shutdown` sent meanwhile is handled within one request's time, not behind the whole backlog.
  - **Memory stays bounded:** what waits is the frames the reader holds, and for each vault request admitted before the wait (one running, 32 queued) its reply and at most one event.
  - **The core exits only on a stall.** If its frames wait while the writer writes nothing for **30 s**, main has stopped reading: the core logs "main is not reading replies" and exits 76 (`protocol`). Writer progress is any frame written, whoever made it: the 30 s count from the later of the writer's last write and the moment the frames began to wait.
    - **Why 30 s:** it is far above a healthy main's pauses, which last milliseconds to seconds, and waiting costs nothing meanwhile. It is also the longest deadline the core gives a request (the KDF methods'), which puts it between main's [hang watchdogs](#deadlines-cancellation-and-commit): 20 s for a 5 s method, 45 s for a KDF method. So the core never gives up on main sooner than main gives up on a short request, and a main that can no longer run its timers keeps it waiting no longer than main would wait for a KDF reply.
    - **Why not exit at once,** as the core first did: a burst of requests, then a fraction of a second without reading (about 256 small replies), killed the core and locked the vault.
  - **Main must keep reading** whatever the state of its own writes, as 0005 requires of both sides ("consumers never block on the writer"). Otherwise each side's writer could wait on the other.
- **Protocol errors** are an unknown kind, an oversized frame, invalid JSON, a response that has both or neither of `result` and `error`, or an unsolicited or duplicate response. They mean a bug in main or the core: the receiver logs it and closes the connection.
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
- **Exactly one terminal response per request:** a result, or an error such as `cancelled` or `deadline`. The core owns deadlines (see below). Main keeps every pending entry, even after its own caller has gone away, until that terminal response arrives. So a slow reply is never a protocol error; only an unsolicited or a second response is.
- **Handshake:**
  - The first message must be main's `core.hello`: `{ protocol: 1, shell_version, auto_lock_ms }`. Main sends `auto_lock_ms = 900000` (15 minutes), as `vault.js` does today.
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
- **Revocation versus commit:**
  - **Before its commit point,** revocation stops vault work. Every lock (manual, auto, delete, shutdown), even while already locked, revokes all admitted vault work that hasn't reached its commit point, queued or running and of any kind: nothing admitted before a lock acknowledgement runs after it. Results are wiped, nothing is installed, and the reply is `vault_locked`.
  - **After its commit point** (the worker's atomic claim immediately before the vault rename or unlink, or before the node journal write; see [Deadlines, cancellation and commit](#deadlines-cancellation-and-commit)), a transaction finishes with the material it already holds. It wipes that material, reinstalls nothing, and reports its committed public result.
  - **Replies already being serialized,** such as a `compat.private_key` reply, keep the copy they took. Lock stops new use; it can't recall bytes already handed out.
- **Mutations** (create, import, change_password, delete, node writes) are serialized through one vault task.
- **Control messages need no admission.** `vault.lock`, `core.shutdown`, `cancel` and `vault.status` are handled inline on the I/O task:
  - lock and shutdown revoke the epoch and wipe the resident secrets right away;
  - cancel marks the target request;
  - status answers from a snapshot.

  None of them takes a slot, so nothing can crowd them out. Nor can replies main hasn't read: while the loop's replies wait for main to read them, `vault.lock`, `core.shutdown` and `cancel` are still found among the waiting requests ([Transport](#transport-and-framing)). `vault.status` waits for its turn, since its reply needs the room.
- **Limits for everything else:**
  - At most 64 admitted requests; beyond that, `busy`.
  - At most 2 concurrent KDF jobs.
  - A slot is held until the underlying work actually finishes, not when its caller gives up.

### Deadlines, cancellation and commit

- **Deadlines:**
  - A deadline is a total budget on a monotonic clock, starting when the core admits the request (queue time included). Defaults: 30 s for KDF methods, 5 s for everything else.
  - **The core enforces deadlines and always replies.** Main doesn't settle requests on its own timer. It runs only a hang watchdog: core deadline + 15 s. If the watchdog fires, main treats the core as hung, kills it, restarts it and [reconciles](#reconciliation).
- **Before the commit point,** a deadline or `cancel` stops the operation and returns `deadline` or `cancelled`. Throttle attempts are reserved before a KDF starts, so concurrent guesses can't all slip past the check.
- **The commit point** is the worker's atomic claim immediately before the vault rename or unlink, or before the journal write of a multi-file operation. The loop and the worker race on one atomic: either the loop abandons the job first (cancel, deadline or revocation), and the job writes nothing, or the worker claims the commit first, and from then on cancel, deadline and revocation no longer apply.
- **After the commit point,** the reply is the real outcome of the rename or unlink, even past the deadline:
  - **If it happened,** the reply is success. A later failure, such as a directory `fsync` error, doesn't turn into an error reply. It is reported as success with `durable: false`, and logged.
  - **If the rename or unlink itself failed,** nothing changed, and the reply is that error.

  So every error reply means "not committed", and only a missing reply needs reconciliation.
- **Shutdown** revokes everything before its commit point. Work past its commit point finishes and sends its reply before the process exits, within a bounded wait. Main's hang watchdog and reconciliation cover anything slower.
- **Read-only operations** can be cancelled at any time.

### Reconciliation

A reply can still go missing (core crash, hang watchdog), so every mutation can be reconciled. Main runs vault mutations one at a time, which means the state it records before a mutation belongs to exactly that operation.

- **Before a mutation,** main records `vault.status` (`exists`, `fingerprint`, where the fingerprint is the SHA-256 of the vault file). If the mutation ends without a reply (crash or hang), main restarts the core and calls **`vault.reconcile { op, fingerprint_before, password_b64, mnemonic_b64?, install }`**. Error replies are always pre-commit (see above), so they need no reconciliation. The core checks the operation's actual effect:

  | `op` | committed when | then the core |
  |---|---|---|
  | `create` | a vault exists now, it didn't before, and it decrypts with the password | returns `{ mnemonic, addresses }`; unlocks only if `install` |
  | `import` | the fingerprint changed and the vault decrypts with the password to the requested mnemonic | returns `{ addresses }`; unlocks only if `install` |
  | `change_password` | the fingerprint changed and the vault decrypts with the **new** password | returns `{}`; the vault stays locked after the restart |
  | `delete` | a vault existed and is now absent | returns `{}` |

  Otherwise `vault.reconcile` returns `not_committed`, and main reports the original error.
- **A committed result goes back to the original caller as a success.** `identity-manager.js` continues its normal success path: it writes `vault-meta.json`, and in Quick Setup the renderer stores the random password. So a core-only failure can no longer turn a written vault into a reported failure.
- **A crash of main itself** between the core's commit and main's metadata write is the same window JS has today (vault file written, then metadata). It isn't new and isn't addressed here.
- **`install` respects locks that happened since.** Main tracks every lock it requested and every `vault.locked` event, across core generations. It passes `install: true` only if no lock happened after the mutation started. Otherwise the core works out the result with temporary secrets, wipes them, and leaves the vault locked. An acknowledged lock is never undone.
- **If the core can't be restarted:**
  - **The caller waits.** Main keeps retrying the restart for up to 60 s.
  - **After that,** main reports `core_unavailable` and keeps a pending-recovery record in memory: the operation and its parameters, wiped once used. No other vault mutation is accepted until it has been reconciled. When the core is back, main reconciles first and runs the metadata continuation itself, by writing `vault-meta.json`.
  - **Quick Setup:** while the pending record exists, main finishes the operation itself. It reconciles, writes `vault-meta.json`, and keeps the random password so that onboarding can still enable quick unlock when the renderer comes back.
  - **Nothing destructive is ever inferred from metadata or a missing credential.** A Quick Setup vault without its credential may be funded, because users can remove the credential deliberately (`quick-unlock.js:295`). If the pending record is lost too, when main itself dies, the vault stays exactly as it is, as in today's JS. Onboarding shows the normal "vault exists" paths: unlock, or restore with the recovery phrase. Overwriting a vault always remains an explicit user decision.
- **No accidental rewrites:** the core never rewrites the vault file except through create, import, change_password and delete. Startup, status, unlock and verify read it and never write it, so quick unlock's content fingerprint survives. Tightening the file's mode to `0600` changes metadata, not content.
- **`vault.reconcile` doesn't count toward throttling.** It verifies a password main itself sent in the operation it is reconciling.

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
- **Existing files:** at adoption (the first core start on a profile), the core tightens existing secret files to `0600` in place with `chmod`, which doesn't change the content. It first checks that each is a regular file, not a symlink, owned by the current user. This covers the vault, the Bee keystore and config, and the Radicle keys.
- **Delete:** unlink, then `fsync` the directory before replying. A delete commits at the unlink.

### Multi-file writes

This covers node identities. **Bee:** `keys/swarm.key` plus `config.yaml`. **Radicle:** private key, public key and config. Node directories can be outside the profile, so the journal lives in the identity directory, where startup recovery always finds it.

1. **Stage.** For each target, write `<target>.freedom-new` (exclusive create, `0600`, fsync) and compute its SHA-256.
2. **Commit.** Write `<identityDir>/node-identity-journal.json` atomically and durably. It holds `{ op_id, node, files: [{ target, staged, sha256 }] }`, with absolute paths.
3. **Install.** For each file:
   - if the target already has the journaled SHA-256, it's done;
   - otherwise rename the staged file over it.

   Then `fsync` every affected directory.
4. **Finish.** Add `op_id` to `<identityDir>/node-identity-done.json` (the last 32 operations, written atomically), then delete the journal and `fsync`.

- **Recovery** runs before `core.hello` is answered, before any node write, and in `freedom-cored recover`, which JS-backend builds run at startup. For a leftover journal, repeat step 3 for each file:
  - a target with the right digest is done;
  - otherwise a staged file with the right digest is renamed into place;
  - if neither exists, the operation reports `node_identity_corrupt`, which needs a fresh write while unlocked; main shows that as a node error.

  Then do step 4. Staged files without a journal are deleted.
- **Post-commit failures are not "success" here.** A node write reports `installed` only when step 4 has completed. If an install rename or its directory flush fails after the journal commit, the core keeps the journal and replies `pending_recovery`. Main then keeps that node stopped and retries `recover` with backoff. `durable: false` exists only for the single-file vault rename, where the file is already in place.
- **Reconciliation:** `nodes.op_status { op_id }` returns `installed`, `pending_recovery`, `not_committed` or `corrupt` from the done list and the journal. A consistent node directory alone doesn't count, because it could still hold the old identity. Main starts a node only on `installed`.
- **Ordering with the shell:** main stops the node before calling `nodes.write_identity` and starts it only after an `installed` result or reconciliation, as it does today. Ant's own config rewrite at start (`ant-manager.js:815`) therefore always happens after the write.
- **Bee's keystore password** still goes into `config.yaml` (K-3, Phase 5). The journal guarantees that the keystore and the password always match.

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
1. **Lock state after a password change.** JS `changePassword` verifies by calling `unlockVault(dataDir, current, 0)` (`vault.js:204`), and timer 0 starts no timer. What that does depends on the state before:
   - **Locked before:** JS ends **unlocked with no auto-lock timer**, while main's derived-key cache stays empty, so `get-status` disagrees with `vault.js`. The same happens when the new password is then rejected as too short. The core stays locked.
   - **Unlocked before:** JS stays unlocked and the existing timer keeps running. The core does the same.
2. **The lock event.** `vault.locked` is a new internal event. Main uses it to update its own state. The renderer keeps polling `identity:get-status` as it does today, so there is no new renderer event in Phase 1.

**Other parity rules:**
- **Mnemonic acceptance is exactly `@scure/bip39`'s.** It normalizes to NFKD, splits on single spaces, uses the case-sensitive English list and checks the checksum. The phrase is stored exactly as given.
- **`keys.generate_mnemonic`** takes `words: 12 | 15 | 18 | 21 | 24`. Main maps the JS `strength` argument (128, 160, 192, 224, 256), with 256 as the default, as in `derivation.js:40`. Any other strength gets the JS error locally.
- **Vault passwords are raw UTF-8,** with no normalization, so NFC and NFD forms are different passwords. Main produces the bytes with `Buffer.from(password, 'utf8')`, which is what passworder does, so a lone surrogate becomes U+FFFD exactly as today. The 8-character minimum is checked on the UTF-16 length in main and again in the core; replacing a lone surrogate with U+FFFD leaves that length unchanged.
- **Throttling** (new, K-4):
  - One counter is shared by failed `unlock`, `verify_password`, `change_password` (the current password), `delete` and both exports.
  - The first 5 failures are free. After that, each attempt has to wait 2^(n−5) s since the last failure, capped at 5 min, and gets `throttled` with `retry_after_ms`.
  - A success resets the counter.
  - An attempt is reserved before its KDF starts. A cancelled or revoked attempt still counts if its KDF ran.
  - **While the throttle refuses** (#82), a password check still reads the file, but without the password. A missing vault, an unsupported version (unlock, change_password and delete only) or a file that no password could open is reported before `throttled`, in the table's order. Only an attempt that would run the KDF gets `throttled`. As in JS, the version is read before anything else in the envelope, so a later format reports its version whatever its `encrypted` holds.
  - The counter lives in memory. Renderer input can't crash the core, so only main can reset it, and main is trusted.
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
| `keys.generate_mnemonic`, `keys.validate_mnemonic` | see parity table | generate returns `{ mnemonic }` |
| `vault.create`, `vault.import`, `vault.unlock`, `vault.lock`, `vault.verify_password`, `vault.change_password`, `vault.delete` | see parity table | create returns `{ mnemonic, addresses }`; import and unlock return `{ addresses }` |
| `vault.touch` | → `{}` | restarts the auto-lock timer if unlocked |
| `vault.export_mnemonic`, `vault.export_private_key` | see parity table | permanent, user-requested backup exports |
| `keys.addresses` | `{ accounts?: [u32], publishers?: [u32] }` → `{ user_wallets, bee_wallet, publishers, radicle: { public_key, did, node_id } }` | public data only; needs an unlocked vault |
| `keys.radicle_did` | `{ public_key }` → `{ did }` | public conversion; works while locked (`readRadicleDid`, `identity-manager.js:381`) |
| `nodes.write_identity` | `{ op_id, node: "bee", data_dir, api_port, p2p_port }` or `{ op_id, node: "radicle", home, alias }` → `{ address }` or `{ did, node_id }` | [multi-file protocol](#multi-file-writes). Bee generates a fresh keystore password and writes `config.yaml` exactly as `createBeeConfig` does, with main's per-profile ports |
| `nodes.op_status` | `{ op_id }` → `{ status: "installed" \| "pending_recovery" \| "not_committed" \| "corrupt" }` | reconciliation after a lost reply |
| `vault.reconcile` | see [Reconciliation](#reconciliation) | after a lost mutation reply |
| `compat.private_key` | `{ account }` → `{ private_key }` | temporary; see Migration |
| `compat.bee_wallet_key` | → `{ private_key }` | temporary |
| `compat.publisher_key` | `{ origin_index }` → `{ private_key }` | temporary |

**Events from the core:** `vault.locked { reason: "manual" | "auto" | "delete" | "shutdown", epoch }` and `vault.unlocked { epoch }`.

### Input validation and secret fields

- **Secret fields travel as base64** of their UTF-8 bytes: `password_b64`, `new_password_b64`, `mnemonic_b64`, and on the way back `mnemonic_b64` and `private_key_hex`.
  - Base64 and hex contain no JSON escapes, so the core's decoder borrows them straight from the frame buffer. serde_json makes no scratch copy, and the core decodes them into `Zeroizing` buffers.
  - Main builds the bytes exactly as the JS does today:
    - **passwords:** `Buffer.from(p, 'utf8')`;
    - **mnemonics:** rejected locally with "Invalid mnemonic" when `!isWellFormed()`, as `@scure/bip39` rejects them.
- **Main validates every renderer-supplied argument before dispatch:**

  | Argument | Rule |
  |---|---|
  | Non-secret strings | must be well-formed |
  | Indices | integers in `[0, 2^31)` |
  | Aliases | ≤ 64 bytes |
  | Secret fields | ≤ 256 KiB each |

  - **Out-of-range input** gets the JS error string locally and never reaches the core.
  - **The 256 KiB limit** is a deliberate transport limit. JS has no ceiling, but no UI or generated password comes near it. A test keeps a vault with a 1,025-byte password unlockable.
- **Defense in depth:** the core applies the same rules and answers `invalid_argument`. A malformed field is never a protocol error, so renderer input can't crash the core.
- **Error replies stay small** (#86). An error message quotes at most 64 characters of any input string, an identifier included, and at most 8 names of a list. Quoted whole, a field of combining marks or quotes grows several times over, first in Rust's `{:?}` escapes and then in JSON's, and an error reply past one frame ended the core. As a backstop, a vault-loop error reply that still wouldn't fit a frame keeps its code but gets a fixed message and no data.
- **Renderer access:** `core.hello`, `core.shutdown`, `cancel`, `vault.reconcile`, `nodes.op_status` and `compat.*` aren't reachable from any renderer channel. Only main-internal code calls them.

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

- **No runtime switch.** A runtime switch would mean a release in which two writers, the JS vault and the core, share one identity directory without sharing the lock. Step 1's `FREEDOM_CORE=1` opt-in exists only in dev builds (`!app.isPackaged`), while the core does nothing yet. Step 2 removes it: from then on the core always runs, and no JS code path is left to switch back to.
- **Rollback is a hotfix release** that reverts step 2. That's safe because the JS reads everything the core writes. `vectors/` checks vault files and Bee keystores written by Rust against the pinned JS, in CI, on every change.
- **But not a bare revert.** Step 1's code never runs `recover`, but a JS writer must (see [Lifetime lock](#lifetime-lock)). The hotfix keeps shipping the binary and runs `recover` at startup, before it starts any node, so a journal the core left behind is finished first.

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
| `fc-protocol` | logic | Message types, error codes, the method table, a sans-I/O frame codec, schema generation, base64/hex secret field types decoding into `Zeroizing`. |
| `freedom-cored` | binary | Stdio transport and writer, control path, vault task, KDF pool, timers, durable writes, the node journal, the lifetime lock with storage qualification, logging, process hardening, and the `hold-lock` subcommand. |

## Secrets in memory

- **Types:**
  - Inside the core, the mnemonic, seed, private keys, passwords and derived AES keys live only in `Zeroizing` or `secrecy` types.
  - Those types implement no `Debug`, `Display`, `Serialize` or `Clone`.
- **Wire boundary:**
  - Secret fields are base64 or hex (see [Input validation](#input-validation-and-secret-fields)), so the JSON decoder never copies them into its scratch buffer.
  - They are decoded into `Zeroizing` buffers, never through `serde_json::Value`.
  - Raw frame buffers and response buffers are wiped once decoded or written.
  - **Outgoing secrets go through one audited serializer that writes into a `Zeroizing` buffer:**
    - `keys.generate_mnemonic`;
    - `vault.create` and `vault.reconcile` for `create` (the onboarding phrase);
    - `vault.export_*`;
    - `compat.*`.
- **Logging:** log lines carry the method name, request ID, duration and error code. They never include a request or response body, and the core has no body-bearing diagnostics.
- **Process hardening:**
  - **Linux:** `PR_SET_DUMPABLE=0`.
  - **macOS:** `RLIMIT_CORE=0` plus the hardened runtime.
  - Both go through `rustix`'s safe wrappers.
- **What isn't guaranteed:** the core can't wipe copies in main. Passwords and mnemonics pass through JS strings, and `compat` keys through ethers objects. Phase 1 stops main from keeping them resident, and Phase 2 removes the key copies.
- **No `unsafe` in the core** (#103). `freedom-cored` inherits the workspace's `forbid(unsafe_code)`, which no `#[allow]` can lift. The OS calls std lacks are in `fc-sys`, the workspace's only crate with `unsafe` code (AGENTS.md rule 6): each is one reviewed FFI call behind a safe function, today Windows' `GetDriveTypeW` for storage qualification.
- **`mlock` is deferred.** If added, it goes into `fc-sys` too.

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
  - **Lifetime lock:**
    - two processes on one directory, and through a symlink alias;
    - `hold-lock` held across a delete and recreation of the identity directory while a core tries to start;
    - `recover` after a journal left at each install rename;
    - a network-filesystem refusal;
    - EOF mid-frame;
    - parent death before and after the handshake;
    - no `core.hello` within 10 s.
  - **Control path:** lock and shutdown still work with all 64 slots and a burst of status and cancel messages in flight.
  - **Backpressure:**
    - a 1,500-request burst while main reads nothing for 2 s, all answered in order once it reads, with the core taking in stdin only as main reads and its peak memory bounded;
    - the auto-lock landing on time while replies wait: it revokes an export whose job finishes before main reads again;
    - the auto-lock coming due while waiting requests drain, after main reads again: a key request among them gets `vault_locked`, and a `vault.touch` among them doesn't postpone the lock;
    - a cancel and a `core.shutdown` sent while a long backlog drains, each handled before the backlog ends;
    - `core.shutdown`, `vault.lock` and a `cancel` for queued work, each honored behind requests that wait;
    - the stall exit, with an injected clock and, in the binary, with a shortened bound.
  - **Reconciliation:**
    - a lost reply for every mutation, including create and delete, then `vault.reconcile` in each state;
    - an acknowledged lock between commit and the lost reply, after which the vault stays locked;
    - a directory `fsync` failure after rename or unlink, reported as success with `durable: false`;
    - recovery unavailable, then the pending-recovery record is completed after restart.
  - **Node journal:** crashes after each install rename and before and after journal removal; then `nodes.op_status`.
  - **Input:** a 1,025-byte password vault still unlocks; lone surrogates; passwords with quotes and backslashes; the throttle and the core generation survive malformed renderer input.
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
3. **Windows:** code signing, and an owner-only DACL for secret files, which also matters for alternate profile roots. Tracked in #644's decisions.
