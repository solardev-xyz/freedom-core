# Releasing freedom-cored

Freedom Browser ships `freedom-cored` inside the app. Each freedom-browser
change that needs a newer core pins a freedom-core release (design 0001,
"Migration in freedom-browser").

0. **Notices.** The archives ship `THIRD-PARTY-NOTICES` next to the binary:
   the licenses and notices of every crate statically linked into
   `freedom-cored` on any release target. CI fails when it's stale; after a
   dependency change run `cargo fetch --locked && python3
   scripts/third-party-notices.py` and commit the result.
1. **Bump the version** in a PR: `version` under `[workspace.package]` in
   `Cargo.toml`, **and** the lockfile, which records every workspace package's
   version: run `cargo check --workspace` and commit the updated `Cargo.lock`.
   The release builds with `--locked`, so a stale lockfile fails it.
   `core.hello` reports this version as `core_version`.
2. **Tag the merged commit on `main`** once its CI is green:
   `git tag vX.Y.Z <commit> && git push origin vX.Y.Z`. Only a tag push
   publishes, and only if the tag equals `v` + the workspace version.
3. **The Release workflow** builds every target with a read-only token,
   smoke-tests the four native builds (`x86_64-apple-darwin` is
   cross-compiled on Apple Silicon and only built), and hands the archives to
   the publish job. That job runs no repository code: it checks every archive
   against its checksum, assembles `SHA256SUMS`, creates a draft release with
   all assets (`--verify-tag`), and publishes it.

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
   and checksums were swapped together no longer matches it.

**If a run fails:** a failed build publishes nothing. If the publish job fails
after creating the draft, check that the release is still a **draft**, delete
it (`gh release delete vX.Y.Z --yes`, keeping the tag), and re-run the
workflow. Never replace assets of a published release; cut a new version.

**Repository settings:** enable immutable releases, so a published release's
assets and tag can't be changed, and restrict who can push `v*` tags.

The binaries are not code-signed here. freedom-browser's packaging signs
them with the app (macOS) like its other bundled helpers.

A manual run of the workflow (`workflow_dispatch`, on any ref) builds and
smoke-tests every target without publishing.
