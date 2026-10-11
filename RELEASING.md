# Releasing freedom-cored

Freedom Browser ships `freedom-cored` inside the app. Each freedom-browser
change that needs a newer core pins a freedom-core release (design 0001,
"Migration in freedom-browser").

1. **Bump** the workspace version in `Cargo.toml` (`[workspace.package]`) in a
   PR. `core.hello` reports it as `core_version`.
2. **Tag** the merged commit on `main`: `git tag vX.Y.Z && git push origin vX.Y.Z`.
   The tag must match the workspace version, or the workflow stops.
3. **The Release workflow** builds and smoke-tests every target, uploads the
   archives to a draft release, assembles `SHA256SUMS`, and publishes:

   | Asset | Target |
   |---|---|
   | `freedom-cored-vX.Y.Z-darwin-arm64.tar.gz` | `aarch64-apple-darwin` |
   | `freedom-cored-vX.Y.Z-darwin-amd64.tar.gz` | `x86_64-apple-darwin` |
   | `freedom-cored-vX.Y.Z-linux-amd64.tar.gz` | `x86_64-unknown-linux-musl` (static) |
   | `freedom-cored-vX.Y.Z-linux-arm64.tar.gz` | `aarch64-unknown-linux-musl` (static) |
   | `freedom-cored-vX.Y.Z-windows-amd64.zip` | `x86_64-pc-windows-msvc` (static CRT) |

4. **Pin it in freedom-browser:** the release tag, plus the SHA-256 of the
   release's `SHA256SUMS` file (printed by the workflow's last job). That
   digest is the in-repo trust root: a compromised release can't swap the
   binaries and their checksums together.

The binaries are not code-signed here. freedom-browser's packaging signs
them with the app (macOS) like its other bundled helpers.

A manual run of the workflow (`workflow_dispatch`) builds and smoke-tests
every target without publishing anything.
