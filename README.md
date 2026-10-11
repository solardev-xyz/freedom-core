# freedom-core

The shared Rust core for [Freedom Browser](https://github.com/solardev-xyz/freedom-browser): key derivation, the identity vault, transaction and message signing, decentralized naming, and profiles.

**Status: early development. Nothing here is used by Freedom yet.**

The plan and rationale are in [freedom-browser#644](https://github.com/solardev-xyz/freedom-browser/issues/644):

- **Desktop first.** The crates run in a separate `freedom-cored` process under the Electron shell. They take over wallet, naming and profile logic from Electron's main process step by step.
- **Mobile later.** The iOS and Android apps link the same crates through [freedom-mobile-ffi](https://github.com/solardev-xyz/freedom-mobile-ffi).
- **Built to outlive Electron.** The logic crates do no I/O, so they could also run inside a Chromium-based desktop build later.

## Layout

| Path | Contents |
|---|---|
| `crates/` | Library crates (`fc-keys`, …) |
| `vectors/` | Golden test vectors generated from the desktop JS implementation |
| `docs/` | Design documents |

## Building

```sh
cargo test --workspace
```

The Rust toolchain is pinned in `rust-toolchain.toml`. See [AGENTS.md](AGENTS.md) for the rules every change follows.

> **The test vectors contain test mnemonics and keys. They are public. Never send funds to any address derived from them.**

No license has been chosen yet.
