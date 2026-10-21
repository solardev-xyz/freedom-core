# Releasing freedom-cored

Freedom Browser ships `freedom-cored` inside the app. Each freedom-browser
change that needs a newer core pins a freedom-core release (design 0001,
"Migration in freedom-browser").

0. **Notices.** The archives ship two notice files next to the binary.
   - `THIRD-PARTY-NOTICES` is generated and committed. It holds the licenses
     and notices of every crate statically linked into `freedom-cored` on any
     release target, plus the toolchain's runtime: the standard library's
     out-of-tree crates and compiler-builtins, and, on Linux, musl and LLVM's
     libunwind and crt objects (texts in `notices/`).
   - `THIRD-PARTY-NOTICES-rust-std.html` is the Rust project's notice file for
     the standard library, which the release workflow copies from the
     toolchain.

   CI fails when `THIRD-PARTY-NOTICES` is stale. After a dependency change,
   run `cargo fetch --locked && python3 scripts/third-party-notices.py` and
   commit the result. When `rust-toolchain.toml` moves, the script refuses to
   run until the runtime list is re-checked: the musl version Rust bundles,
   the LLVM commit and the std crates. Then update `TOOLCHAIN` in the script.
   Anything that ships the binary, such as Freedom Browser, must ship both
   files with it.
1. **Bump the version** in a PR: `version` under `[workspace.package]` in
   `Cargo.toml`, **and** the lockfile, which records every workspace package's
   version: run `cargo check --workspace` and commit the updated `Cargo.lock`.
   The release builds with `--locked`, so a stale lockfile fails it.
   The repository's other workspaces take workspace crates by path, so
   their lockfiles record those versions too, and CI builds them with
   `--locked`: `fuzz/` (`fc-json`, `fc-keys`, `fc-protocol`, `fc-vault`) and
   each `services/*` (`fc-protocol`, `fc-service`). In each, run
   `cargo update -p <crate> … --offline` for the crates it takes, check
   that `cargo metadata --locked --offline --format-version 1` passes, and
   commit its `Cargo.lock`. `find . -name Cargo.lock -not -path '*/target/*'`
   lists them all.
   `core.hello` reports this version as `core_version`.
2. **Tag the merged commit on `main`** once its CI is green:
   `git tag cored-vX.Y.Z <commit> && git push origin cored-vX.Y.Z`. Only a
   tag push publishes, and only if the tag equals `cored-v` + the workspace
   version. The service binaries get their own tags (`ipfsd-v*`,
   `radicled-v*`; designs 0007 and 0008). Releases up to 0.5.0 were tagged
   `vX.Y.Z`.
3. **The Release workflow** builds every target with a read-only token,
   smoke-tests the four native builds (`x86_64-apple-darwin` is
   cross-compiled on Apple Silicon and only built), and hands the archives to
   the publish job. That job runs no repository code:
   - it checks every archive against its checksum and assembles `SHA256SUMS`;
   - it attests build provenance for every archive and for `SHA256SUMS`
     ([below](#build-provenance));
   - it creates a draft release with all assets (`--verify-tag`), and
     publishes it.

   | Asset | Target |
   |---|---|
   | `freedom-cored-vX.Y.Z-darwin-arm64.tar.gz` | `aarch64-apple-darwin` |
   | `freedom-cored-vX.Y.Z-darwin-amd64.tar.gz` | `x86_64-apple-darwin` |
   | `freedom-cored-vX.Y.Z-linux-amd64.tar.gz` | `x86_64-unknown-linux-musl` (static) |
   | `freedom-cored-vX.Y.Z-linux-arm64.tar.gz` | `aarch64-unknown-linux-musl` (static) |
   | `freedom-cored-vX.Y.Z-windows-amd64.zip` | `x86_64-pc-windows-msvc` (static CRT) |

4. **Pin it in freedom-browser** (`scripts/fetch-freedom-cored.js`): the tag,
   plus the SHA-256 of the release's `SHA256SUMS`, which the publish job
   prints. That digest is the in-repo trust root: a release whose binaries
   and checksums were swapped together no longer matches it. The archive
   names keep `vX.Y.Z` (the table above), so from the first `cored-v*` release
   on, the fetch script derives them from the tag without its `cored-`
   prefix.

**If a run fails:** a failed build publishes nothing. If the publish job fails
after creating the draft, check that the release is still a **draft**, delete
it (`gh release delete cored-vX.Y.Z --yes`, keeping the tag), and re-run the
workflow. Never replace assets of a published release; cut a new version.

**Repository settings:** enable immutable releases, so a published release's
assets and tag can't be changed (enabled), and restrict who can push
`cored-v*` tags (and `ipfsd-v*` and `radicled-v*` later) with a tag ruleset.

The binaries are not code-signed here. freedom-browser's packaging signs
them with the app (macOS) like its other bundled helpers.

A manual run of the workflow (`workflow_dispatch`, on any ref) builds and
smoke-tests every target without publishing.

## Build provenance

The publish job signs SLSA build provenance for each archive and for
`SHA256SUMS` (`actions/attest`, through Sigstore). It ties each file's digest
to this repository, `release.yml`, the tagged commit and the workflow run. So
a file uploaded by hand, or built anywhere else, fails verification even if
its checksum is right. Check a download with:

```sh
gh attestation verify freedom-cored-vX.Y.Z-linux-amd64.tar.gz \
  --repo solardev-xyz/freedom-core \
  --signer-workflow solardev-xyz/freedom-core/.github/workflows/release.yml \
  --source-ref refs/tags/cored-vX.Y.Z \
  --deny-self-hosted-runners
```

- **Releases up to 0.5.0 have no build provenance.** As immutable releases,
  they carry only GitHub's release attestation
  (`https://in-toto.io/attestation/release/v0.2`). That one is signed by
  GitHub's release service. It binds the assets to the tag and its commit,
  but says nothing about what built them.
- **freedom-browser should verify the provenance** of what it fetches, as
  well as the pinned `SHA256SUMS` digest. That is a freedom-browser change.

# Releasing freedom-ipfsd

`services/freedom-ipfsd` (design 0007) is released on its own tags,
`ipfsd-vX.Y.Z`, by `.github/workflows/release-ipfsd.yml`. That workflow has
the same shape as freedom-cored's: build jobs with a read-only token, and one
publish job that runs no repository code.

0. **Notices.** `services/freedom-ipfsd/THIRD-PARTY-NOTICES` is generated and
   committed:
   `(cd services/freedom-ipfsd && cargo fetch --locked) && python3 scripts/third-party-notices.py --binary freedom-ipfsd`.
   CI fails when it is stale. The archives also ship
   `THIRD-PARTY-NOTICES-rust-std.html` from the toolchain that built them.
1. **Bump the version** in a PR: `version` in
   `services/freedom-ipfsd/Cargo.toml`, and its own `Cargo.lock`
   (`cargo check` in `services/freedom-ipfsd`). `ipfs.hello` reports it as
   `service_version`, and it is independent of the core's version.
2. **Tag the merged commit on `main`** once its CI is green:
   `git tag ipfsd-vX.Y.Z <commit> && git push origin ipfsd-vX.Y.Z`. Only a
   tag equal to `ipfsd-v` + that version publishes.
3. **The workflow** builds every target, smoke-tests the four native builds
   (usage exits 64), and checks that the Linux binaries have no program
   interpreter. Then the publish job assembles `SHA256SUMS`, attests every
   archive and `SHA256SUMS`, and publishes.
   - **Linux is static musl.** SQLite and `ring` are C, so the build jobs
     install `musl-tools` and set `CC_<target>=musl-gcc`. The C code compiles
     against the distribution's musl headers. rustc links the toolchain's
     bundled musl, which is the version THIRD-PARTY-NOTICES lists.

   | Asset | Target |
   |---|---|
   | `freedom-ipfsd-vX.Y.Z-darwin-arm64.tar.gz` | `aarch64-apple-darwin` |
   | `freedom-ipfsd-vX.Y.Z-darwin-amd64.tar.gz` | `x86_64-apple-darwin` |
   | `freedom-ipfsd-vX.Y.Z-linux-amd64.tar.gz` | `x86_64-unknown-linux-musl` (static) |
   | `freedom-ipfsd-vX.Y.Z-linux-arm64.tar.gz` | `aarch64-unknown-linux-musl` (static) |
   | `freedom-ipfsd-vX.Y.Z-windows-amd64.zip` | `x86_64-pc-windows-msvc` (static CRT) |

4. **Pin it in freedom-browser**, as for the core: the tag, plus the SHA-256
   of the release's `SHA256SUMS`. The fetch script for the second asset is
   0007's step 6.

Failed runs, immutable releases and the tag ruleset work as for the core
(above). Verify a download's provenance with:

```sh
gh attestation verify freedom-ipfsd-vX.Y.Z-linux-amd64.tar.gz \
  --repo solardev-xyz/freedom-core \
  --signer-workflow solardev-xyz/freedom-core/.github/workflows/release-ipfsd.yml \
  --source-ref refs/tags/ipfsd-vX.Y.Z \
  --deny-self-hosted-runners
```
