# Vendored notice texts

These are license texts for native code that the Rust toolchain links
statically into `freedom-cored` but doesn't ship as source in rust-src.
`scripts/third-party-notices.py` copies them into `THIRD-PARTY-NOTICES`.
They were reviewed for the toolchain named by `TOOLCHAIN` in that script.

| File | What | Source |
|---|---|---|
| `musl-1.2.5-COPYRIGHT` | musl libc, the self-contained C library of Rust's `*-linux-musl` targets | `COPYRIGHT` at musl tag `v1.2.5` (git.musl-libc.org) |
| `llvm-compiler-rt-LICENSE.TXT` | LLVM compiler-rt, the source of the `crtbegin.o`/`crtend.o` objects Rust ships for musl | `compiler-rt/LICENSE.TXT` at rust-lang/llvm-project `1b9c0d5f`, the `src/llvm-project` submodule of rust-lang/rust `1.99.0` |

LLVM libunwind's license is read from the toolchain's rust-src.
