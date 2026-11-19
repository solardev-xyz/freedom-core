#!/bin/bash
# Installs Zig into <dir> as the C compiler and archiver of freedom-cored's
# *-linux-musl builds (design 0013, "Where SQLite lives"): scripts/zig-cc
# and scripts/zig-ar become CC_<target> and AR_<target> for each target
# named, and Zig goes onto PATH. On GitHub Actions through GITHUB_ENV and
# GITHUB_PATH; elsewhere the exports are printed, for `eval`.
#
#   scripts/zig-install.sh <dir> <target>...
#
# The pin is release-ipfsd.yml's Zig 0.15.2: the same PyPI wheel for the
# runner's architecture, by version and sha256 (a wheel is a zip, so no pip
# is needed). When either moves, move both, and re-check what Zig puts in
# each binary (RELEASING.md).
set -euo pipefail
[ $# -ge 2 ] || { echo "usage: $0 <dir> <target>..." >&2; exit 64; }
mkdir -p "$1"
dir=$(cd "$1" && pwd)
shift
scripts=$(cd "$(dirname "$0")" && pwd)
case "$(uname -m)" in
  x86_64)
    zig_url=https://files.pythonhosted.org/packages/db/81/f9f5c7fd68d80b8edff2a641a1c95ac4125356387d298374227040b8e1e8/ziglang-0.15.2-py3-none-manylinux_2_12_x86_64.manylinux2010_x86_64.musllinux_1_1_x86_64.whl
    zig_sha256=806316453d1ede7174ed3fefb8e5348154629089c3bb5fe812dfd0e172fac130
    ;;
  aarch64)
    zig_url=https://files.pythonhosted.org/packages/53/7d/8c277208250ffa72f12a10f52dfc1d45850f08244093065b40c5f4628260/ziglang-0.15.2-py3-none-manylinux_2_17_aarch64.manylinux2014_aarch64.musllinux_1_1_aarch64.whl
    zig_sha256=edc0aa60ec964a4cf462d40f68d7de242ddf37fd9a80f2afaee6397059463230
    ;;
  *)
    echo "no pinned Zig for $(uname -m)" >&2
    exit 1
    ;;
esac
for target; do
  case "$target" in
    x86_64-unknown-linux-musl | aarch64-unknown-linux-musl) ;;
    *) echo "not a musl target scripts/zig-cc knows: $target" >&2; exit 1 ;;
  esac
done
curl -fsSL -o "$dir/zig.whl" "$zig_url"
printf '%s  %s\n' "$zig_sha256" "$dir/zig.whl" | sha256sum --check >&2
rm -rf "$dir/zig"
unzip -q "$dir/zig.whl" -d "$dir/zig"
rm "$dir/zig.whl"
chmod +x "$dir/zig/ziglang/zig"
"$dir/zig/ziglang/zig" version >&2
lines=()
for target; do
  var=${target//-/_}
  lines+=("CC_$var=$scripts/zig-cc" "AR_$var=$scripts/zig-ar")
done
if [ -n "${GITHUB_ENV:-}" ]; then
  echo "$dir/zig/ziglang" >> "$GITHUB_PATH"
  printf '%s\n' "${lines[@]}" >> "$GITHUB_ENV"
else
  echo "export PATH=\"$dir/zig/ziglang:\$PATH\""
  printf 'export %s\n' "${lines[@]}"
fi
