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
- **freedom-browser's CI is to verify the provenance** of every pinned
  asset, as above, besides the pinned digests (design 0001, *Packaging and
  release*). That freedom-browser change is pending. The pins remain what
  a local build checks.

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
2. **Tag the merged commit on `main`** once its CI is green and the bump PR
   records a result for every item in step 5a:
   `git tag ipfsd-vX.Y.Z <commit> && git push origin ipfsd-vX.Y.Z`. Only a
   tag equal to `ipfsd-v` + that version publishes.
3. **The workflow** builds every target, smoke-tests the four native builds
   (usage exits 64), and checks that each Linux binary needs glibc 2.17 at
   most and no library but glibc's and `libgcc_s`. Then the publish job
   assembles `SHA256SUMS`, attests every archive and `SHA256SUMS`, and
   publishes.
   - **Linux links glibc 2.17 dynamically** (design 0007, open question 6).
     `cargo-zigbuild` builds with `--target <triple>.2.17`: Zig compiles the
     C code (SQLite, `ring`, BLAKE3) and links against its copy of glibc
     2.17's symbols, adding glibc's startup objects and LLVM's libunwind,
     which THIRD-PARTY-NOTICES lists. The job installs Zig 0.15.2 and
     cargo-zigbuild 0.23.4 from their PyPI wheels, pinned by sha256. When
     the Zig pin moves, re-check what it links statically (`NATIVE` in
     `scripts/third-party-notices.py`).

   | Asset | Target |
   |---|---|
   | `freedom-ipfsd-vX.Y.Z-darwin-arm64.tar.gz` | `aarch64-apple-darwin` |
   | `freedom-ipfsd-vX.Y.Z-darwin-amd64.tar.gz` | `x86_64-apple-darwin` |
   | `freedom-ipfsd-vX.Y.Z-linux-amd64.tar.gz` | `x86_64-unknown-linux-gnu` (glibc ≥ 2.17) |
   | `freedom-ipfsd-vX.Y.Z-linux-arm64.tar.gz` | `aarch64-unknown-linux-gnu` (glibc ≥ 2.17) |
   | `freedom-ipfsd-vX.Y.Z-windows-amd64.zip` | `x86_64-pc-windows-msvc` (static CRT) |

4. **Pin it in freedom-browser**, as for the core: the tag, plus the SHA-256
   of the release's `SHA256SUMS`. The fetch script for the second asset is
   0007's step 6.
5. **Confinement, before shipping** (design 0010, Tests, *Before shipping*).
   CI runs source builds on one recent kernel per architecture. It can't
   show the release binaries, the oldest kernels or the missing-right
   cases. Two lists follow: what must have a result before the tag, and what
   must have one before a signed browser release ships the tag. Note each
   item with its result, "not run" and why, or a finding.

   **5a. Before the tag.** Run these on the release binaries from a manual
   run of `release-ipfsd.yml` on the bump PR's branch, which builds every
   target without publishing. Record the results in the bump PR; step 2
   waits for them. Everything here runs on one Linux x86-64 host and in CI:
   - **The kernel cases,** on the host's kernel and in containers on it. A
     case the host's kernel can't show is simulated by a container's seccomp
     profile, and its result says it is a simulation:
     - without Landlock, simulated by `ENOSYS` for Landlock's calls: `files`
       is `unavailable` and seccomp still holds;
     - before 5.11, simulated by `ENOSYS` for `close_range`, with one
       inherited descriptor: the entry's `fcntl` fallback, and exactly one
       re-exec;
     - in a container whose seccomp filter refuses Landlock's calls
       (`EPERM`): `blocked`, and the service runs;
     - the host's ABI, with its statuses and gaps. From ABI 4, `socks5`
       refuses TCP to any port but the proxy's;
     - ABI 1, 2 and 3: `partial`, with the gaps named, from CI's harness,
       which caps the ABI on a source build.
   - **The release runtime,** in containers: glibc 2.17 (the oldest the
     asset table claims), 2.25 (the oldest the browser runs on), another
     before 2.34, and a current one:
     - each with a first lookup after confinement and none before it, with
       and without `resolve` and `mdns4_minimal` in `nsswitch.conf`;
     - `confinement`'s `resolution` matches what resolves, for every lookup
       the service makes: the gateway's HTTP requests and libp2p's `/dns*`
       dials.
   - **The network:**
     - `socks5` through Arti on loopback, with a reconnect: Arti restarts
       under a running process, and loads resume;
     - `socks5` through a SOCKS proxy on the LAN
       (`--network socks5:<a private address>:<port>`);
     - **direct libp2p TCP and QUIC** to a controlled local peer (an offline
       Kubo, or a second `freedom-ipfsd`), announced by a local delegated
       router, one transport at a time, and checked from the peer's side.
       Public providers often answer over HTTPS, which shows neither
       transport.
   - **SQLite:** the persistent process's store under the release policy,
     with its journal and WAL checkpointed. Also a full store, at the
     browser's 256 MiB target, whose eviction scan spills past the page
     cache and completes in memory (`tests/store_confined.rs` shows the
     control).
   - **An inherited descriptor** without close-on-exec: one re-exec at entry
     ("re-executed once at entry"), and the service serves.
   - **Measured,** all confined: cold start to `ipfs.hello`; a load over TCP
     and one over QUIC from the local peer; a `socks5` load through Arti,
     and how long loads take to resume after Arti restarts.
   - **macOS and Windows, in CI at the bump PR's head,** on source builds:
     - macOS's hello report;
     - fc-service's confinement test, which prints the `KERN_PROCARGS2`
       result and the Mach rights held at the confinement point;
     - Windows's report, which says `unavailable` until its job object
       lands.

     The dry run's native macOS and Windows builds pass the workflow's smoke
     test.

   **5b. Before a signed browser release ships the tag.** Run these on the
   signed, packaged browser that pins the tag, and record the results in
   that browser release's PR. A failure here blocks that browser release,
   and its fix ships as a new tag:
   - **macOS,** on the signed release build, by hand on every supported
     version CI doesn't run (from macOS 12, the browser's floor, to the
     newest; CI runs only `macos-latest`):
     - `confinement` reports `seatbelt` with `files` and `exec` `enforced`,
       `ipc` `partial` with the gap `process_args` (0010's `KERN_PROCARGS2`
       gap, unless the probe below shows the signed build closes it), and
       `network` `none` in `direct` mode, `enforced` in `socks5`;
     - the contract suite confined: DNS, TLS, the store's file
       operations, NAT64 discovery, and `socks5` through Arti on loopback
       and through a LAN proxy;
     - `fc-service`'s confinement test (`cargo test -p fc-service --test
       confine`, with stdio alone), which also prints the Mach rights held
       at the confinement point;
     - whether a confined service can read the running app's arguments and
       environment through `KERN_PROCARGS2`, the gap 0010 records: note the
       answer for the signed, hardened build;
     - Seatbelt's calls are private: a version where the profile no longer
       applies exits 77, and that release waits for a fix.
   - **The packaged app on each OS,** started each way users start it (the
     desktop entry, a terminal, each Linux package format, macOS's Finder
     and Dock):
     - the services' logs show that the entry's re-exec ("re-executed once
       at entry") seldom happens;
     - on Linux, a descriptor the app inherited without close-on-exec
       reaches the services, and each start re-executes once.
   - **Real kernels,** one per Landlock ABI the report distinguishes, on
     x86-64 and on AArch64 where a machine is at hand. They cover what 5a
     simulated or couldn't reach:
     - without Landlock (before 5.13, or Landlock off at boot through
       `lsm=`): `files` is `unavailable` and seccomp still holds;
     - before 5.11: an inherited descriptor takes the entry's `fcntl`
       fallback, and still exactly one re-exec;
     - ABI 1 (5.13), 2 (5.19) and 3 (6.2): `partial`, with the gaps named;
     - ABI 6 (6.12) and later: `ipc` `enforced`.

   `freedom-radicled`'s first release (`radicled-v*`) runs both lists, with
   libgit2's writes in place of SQLite's (a repository created, loose
   objects and packs written, an existing object written again), and
   Radicle's fetch, import and COB writes measured.

Failed runs, immutable releases and the tag ruleset work as for the core
(above). Verify a download's provenance with:

```sh
gh attestation verify freedom-ipfsd-vX.Y.Z-linux-amd64.tar.gz \
  --repo solardev-xyz/freedom-core \
  --signer-workflow solardev-xyz/freedom-core/.github/workflows/release-ipfsd.yml \
  --source-ref refs/tags/ipfsd-vX.Y.Z \
  --deny-self-hosted-runners
```
