# Vendored license texts

Some crates freedom-radicled links publish no license file in their crate,
though their licenses require their notices to ship with the binary.
`scripts/third-party-notices.py --binary freedom-radicled` reads each one's
texts from here. `crates.json` names, for each such crate, the repository
and commit the texts come from, and the files here that hold them. The
script fails if an entry goes stale: a crate that ships its own files, or
one the binary no longer links.

Each crate's texts were fetched from its repository at the commit its
published crate records (`.cargo_vcs_info.json`), or, for libradicle, a git
dependency, at the commit `Cargo.lock` pins. They come from the crate's
directory, or the repository's root when the directory has none. Crates of
one repository share a folder: their texts were identical at every commit
listed. `base256emoji` and `const-str` are the same versions as
freedom-ipfsd's, with the same texts.

Exceptions, also noted in `crates.json`:

| Crate | What stands in |
|---|---|
| `base256emoji` 1.0.2, `base45` 3.2.0 | Neither the crate nor its repository carries a license text, at the crate's commit or on its default branch. Each declares MIT, so SPDX's MIT text stands in: `spdx/MIT.txt`, from spdx/license-list-data v3.29.0 (`31ba1a50e5397e00a304dbadc76531740e89ee48`). |
| `libradicle` 0.8.0 | Neither the crate nor solardev-xyz/libradicle carries a license text, at the pinned commit or on `main`. Its manifest and README declare MIT OR Apache-2.0, so SPDX's texts stand in: `spdx/MIT.txt` and `spdx/Apache-2.0.txt`, from the same release. |

The C libraries crates bundle are listed apart, in the script's `NATIVE`:

| Library | Bundled by | Text |
|---|---|---|
| libgit2 1.9.6, with llhttp, xdiff, PCRE2, SHA-1 collision detection and RFC 6234's SHA-256 | `libgit2-sys` 0.18.7+1.9.6 (`vendored`) | `libgit2/COPYING`, read from the crate's source |
| zlib 1.3.2 | `libz-sys` 1.1.31 (`static`, which `Cargo.toml` asks for) | `src/zlib/LICENSE`, read from the crate's source |
| SQLite 3.49.1 | `sqlite3-src` 0.7.0 (`bundled`) | `sqlite-3.49.1-NOTICE` here: SQLite is in the public domain, and the file quotes the dedication its amalgamation carries |

The runtime notices of the Linux builds, which link glibc 2.17 dynamically
through Zig (glibc's startup and `libc_nonshared` objects, and LLVM's
libunwind), come from the repository's top-level `notices/`, as
freedom-ipfsd's do.
