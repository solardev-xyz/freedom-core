# Vendored notice texts

These are license texts for native code linked statically into a binary
this repository releases, whose source isn't in rust-src: what the Rust
toolchain links into `freedom-cored`, the C library it bundles, and what
Zig links into the services' Linux builds. `scripts/third-party-notices.py` copies them into
each binary's `THIRD-PARTY-NOTICES`. They were reviewed for the toolchain
named by `TOOLCHAIN` in that script, and for the Zig `release-ipfsd.yml`,
`release-radicled.yml` and `release-colibrid.yml` pin.

| File | What | Source |
|---|---|---|
| `musl-1.2.5-COPYRIGHT` | musl libc, the self-contained C library of Rust's `*-linux-musl` targets | `COPYRIGHT` at musl tag `v1.2.5` (git.musl-libc.org) |
| `llvm-compiler-rt-LICENSE.TXT` | LLVM compiler-rt, the source of the `crtbegin.o`/`crtend.o` objects Rust ships for musl | `compiler-rt/LICENSE.TXT` at rust-lang/llvm-project `1b9c0d5f`, the `src/llvm-project` submodule of rust-lang/rust `1.99.0` |
| `sqlite-3.54.1-NOTICE` | SQLite, which `libsqlite3-sys` 0.39.1 bundles (`bundled`, which `freedom-cored`'s `rusqlite` asks for) and builds into `freedom-cored` on every target | SQLite is in the public domain; the file quotes the dedication its amalgamation carries (the same text as `services/freedom-ipfsd/notices/`) |
| `glibc-2.17-startup-NOTICE` | The GNU C Library's startup object (`Scrt1.o`) and the `libc_nonshared.a` members `freedom-ipfsd` links, as Zig builds them for a glibc 2.17 target | The files' license notice, from Zig 0.15.2's bundled glibc sources (`lib/libc/glibc`), with the files and their copyright years listed above it |
| `glibc-2.17-startup-freedom-radicled-NOTICE` | The same, for `freedom-radicled`, whose binaries link other `libc_nonshared.a` members (`stat`, `fstat`, `lstat` and `fstatat64` besides the 64-bit three, and no `__pthread_atfork`), found in the symbols of unstripped x86_64 and aarch64 release builds | As above |
| `glibc-2.17-startup-freedom-colibrid-NOTICE` | The same, for `freedom-colibrid`, whose binaries link `stat64`, `fstat64`, `lstat64`, `fstat` and `fstatat64` (no `__pthread_atfork`), found in the symbols of unstripped x86_64 and aarch64 release builds | As above |
| `llvm-libcxx-zig-0.15.2-LICENSE.TXT` | LLVM libc++, which Zig links statically into `freedom-colibrid`'s Linux builds for evmone's C++ | `lib/libcxx/LICENSE.TXT` in Zig 0.15.2 (the `ziglang` 0.15.2 wheel) |
| `llvm-libcxxabi-zig-0.15.2-LICENSE.TXT` | LLVM libc++abi, linked the same way | `lib/libcxxabi/LICENSE.TXT` in Zig 0.15.2 |

LLVM libunwind's license is read from the toolchain's rust-src. Zig's copy
of libunwind, which the services' Linux builds link, carries the same
text.
