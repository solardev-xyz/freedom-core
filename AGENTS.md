# freedom-core: rules for contributors and agents

This repo is the shared Rust core for Freedom Browser: keys, vault, signing, naming, profiles. The plan is in [solardev-xyz/freedom-browser#644](https://github.com/solardev-xyz/freedom-browser/issues/644). Desktop comes first: a `freedom-cored` process under the Electron shell. Mobile links the same crates later through `freedom-mobile-ffi`.

The code holds users' keys and money. Every rule below exists for that reason.

## Hard rules

1. **Never delete files** unless the user asks you to or confirms it.
2. **Logic crates do no I/O.** No files, sockets, env vars, threads, async runtimes, or wall-clock reads. Time, randomness and storage come in as parameters or traits, so tests can inject them. The logic crates are `fc-keys`, `fc-vault`, `fc-evm`, `fc-naming` and the others marked "logic" in #644. They must compile for iOS and Android (CI checks this), and stay usable inside a Chromium build later.
3. **No raw private key or seed leaves the core.**
   - **Exceptions:**
     - user-requested backup exports (`vault.export_*`) and the onboarding display of the mnemonic, which are permanent;
     - the temporary `compat.*` exports listed in `docs/design/0001-freedom-cored.md`, which Phase 2 deletes.
     Any new exception needs a design change.
   - Signing APIs take a key reference, never key bytes.
   - Secret types zeroize on drop.
   - Secret types implement no `Debug`/`Display` that prints the bytes, and no `Serialize`.
   - Secret types implement `Clone` only when it's unavoidable.
4. **Key storage:**
   - One lock state: every cache of derived keys hangs off it, and any lock (auto or manual) wipes all of them.
   - Secret files are written atomically (temp file, fsync, rename) with mode `0600`.
   - A password change keeps the old vault until the new one decrypts.
   - Never store a secret next to the thing it protects.
   - Unlock attempts are throttled.
   These rules come from weaknesses found in the desktop JS code.
5. **The desktop JS implementation is the reference.** Anything that reads or writes user data must reproduce `vectors/` exactly. Never edit a vector to make a test pass. If a vector looks wrong, stop and raise it.
6. **No `unsafe`** (`forbid` at workspace level). **No panics in library code:** `unwrap`, `expect` and `panic!` are linted, so return typed errors instead.
7. **Dependencies:**
   - Prefer crates that `freedom-mobile-ffi` already links: `k256`, `alloy-primitives`, `sha2`, `sha3`, `hmac`, `pbkdf2`, `aes-gcm`, `ed25519-dalek`, `zeroize`, `secrecy`, `rusqlite`.
   - Justify every new dependency in the PR description.
   - `cargo deny check` must pass.
   - When bindings arrive, pin UniFFI to exactly 0.32, the version libradicle uses.

## Workflow

- One branch and one git worktree per task, so agents don't share a checkout. Open a PR into `main`. Nothing is pushed to `main` directly.
- CI must be green before merging.
- Changes to keys, the vault, signing or approvals need two things before merge:
  - **a review by the other model:** Claude reviews Codex's work and Codex reviews Claude's, posted as a PR comment;
  - **the user's approval.**
- Keep PRs small, one concern each. Say in the description what was verified and how.

## Commands

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
```

## Layout

- `crates/fc-*`: library crates. The binary `freedom-cored` arrives with the desktop skeleton.
- `vectors/`: golden test vectors generated from freedom-browser's JS, plus their generator.
- `docs/`: design documents.
