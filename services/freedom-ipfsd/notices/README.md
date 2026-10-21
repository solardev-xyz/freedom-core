# Vendored license texts

Some crates freedom-ipfsd links publish no license file in their crate,
though their licenses require their notices to ship with the binary.
`scripts/third-party-notices.py --binary freedom-ipfsd` reads each one's
texts from here. `crates.json` names, for each such crate, the repository
and commit the texts come from, and the files here that hold them. The
script fails if an entry goes stale: a crate that ships its own files, or
one the binary no longer links.

Each crate's texts were fetched from its repository at the commit its
published crate records (`.cargo_vcs_info.json`), at the crate's directory,
or the repository's root when the directory has none. Crates of one
repository share a folder: their texts were identical at every commit
listed.

Exceptions, also noted in `crates.json`:

| Crate | What stands in |
|---|---|
| `base256emoji` 1.0.2, `cid` 0.11.3, `futures-bounded` 0.2.4, `if-watch` 3.2.2 | Neither the crate nor its repository carries a license text, at the crate's commit or on its default branch. Each declares MIT (`if-watch`: MIT OR Apache-2.0), so SPDX's MIT text stands in: `spdx/MIT.txt`, from spdx/license-list-data v3.29.0 (`31ba1a50e5397e00a304dbadc76531740e89ee48`). |
| `yamux` 0.13.10 | The commit the crate records isn't in its repository; the texts are the release tag `yamux-v0.13.10`'s. |

A crate that ships its own license files but compiles bundled native
code under a license of its own, deeper in its source, has a `bundled`
entry instead: the paths of those files in the crate's source, which ship
next to its own. The script fails if one is missing, or if the binary no
longer links the crate.

| Crate | Bundled |
|---|---|
| `libmimalloc-sys` 0.1.49 | `c_src/mimalloc/v3/LICENSE`: the mimalloc C library it compiles (its default, v3), Microsoft's copyright. The crate's `LICENSE.txt` covers only its Rust bindings. |

The Rust toolchain's own runtime notices (musl, LLVM's libunwind and
compiler-rt) come from the repository's top-level `notices/`, as for
freedom-cored.
