# Vendored notice texts

These are license texts for native code linked statically into a binary
this repository releases, whose source isn't in rust-src: what the Rust
toolchain links into `freedom-cored`, and what Zig links into
`freedom-ipfsd`'s Linux builds. `scripts/third-party-notices.py` copies them
into each binary's `THIRD-PARTY-NOTICES`. They were reviewed for the
toolchain named by `TOOLCHAIN` in that script, and for the Zig
`release-ipfsd.yml` pins.

| File | What | Source |
|---|---|---|
| `musl-1.2.5-COPYRIGHT` | musl libc, the self-contained C library of Rust's `*-linux-musl` targets | `COPYRIGHT` at musl tag `v1.2.5` (git.musl-libc.org) |
| `llvm-compiler-rt-LICENSE.TXT` | LLVM compiler-rt, the source of the `crtbegin.o`/`crtend.o` objects Rust ships for musl | `compiler-rt/LICENSE.TXT` at rust-lang/llvm-project `1b9c0d5f`, the `src/llvm-project` submodule of rust-lang/rust `1.99.0` |
| `glibc-2.17-startup-NOTICE` | The GNU C Library's startup object (`Scrt1.o`) and the `libc_nonshared.a` members `freedom-ipfsd` links, as Zig builds them for a glibc 2.17 target | The files' license notice, from Zig 0.15.2's bundled glibc sources (`lib/libc/glibc`), with the files and their copyright years listed above it |

LLVM libunwind's license is read from the toolchain's rust-src. Zig's copy
of libunwind, which `freedom-ipfsd`'s Linux builds link, carries the same
text.
