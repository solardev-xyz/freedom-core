#!/usr/bin/env python3
"""Generates THIRD-PARTY-NOTICES for a binary this repository releases:
freedom-cored (the default), or a service process in its own workspace
under services/ (design 0007), next to its own Cargo.lock.

The binary statically links third-party code whose licenses (MIT,
Apache-2.0, BSD-3-Clause, ...) require their notices to ship with it:

1. Every crate that ends up in the binary on any release target (normal
   dependencies only: build scripts and proc-macros don't ship), with its
   license expression and the license/notice files from its own source. A
   crate from a git repository that keeps its license files only at the
   repository's root (a workspace member) gets the root's. A crate that
   ships none at all gets the texts its repository carries, vendored in its
   workspace's notices/crates.json with their source and commit.
2. The Rust toolchain's runtime: the standard library's out-of-tree crates
   (from the toolchain's rust-src), compiler-builtins, and on Linux the
   statically linked musl libc and LLVM libunwind/crt objects (texts in
   notices/, reviewed for TOOLCHAIN). The Rust project's own notice file for
   the standard library ships next to it, copied from the toolchain by the
   release workflow as THIRD-PARTY-NOTICES-rust-std.html.

A new proc-macro or build script can still emit code into the binary; when
one is added, check where its generated code comes from.

    python3 scripts/third-party-notices.py          # rewrite the file
    python3 scripts/third-party-notices.py --check  # CI: fail if stale
    python3 scripts/third-party-notices.py --binary freedom-ipfsd [--check]

Needs the crates' sources (`cargo fetch --locked`) and the toolchain's
rust-src component (rust-toolchain.toml installs it).
"""

import json
import pathlib
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "THIRD-PARTY-NOTICES"
NOTICES = ROOT / "notices"
BINARY = "freedom-cored"
# Every binary with notices, and the workspace that builds it. Each
# workspace's THIRD-PARTY-NOTICES sits at its root, next to its Cargo.lock.
WORKSPACES = {
    BINARY: ROOT,
    "freedom-ipfsd": ROOT / "services" / "freedom-ipfsd",
}
# Every target the release workflow builds.
TARGETS = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-pc-windows-msvc",
]
LICENSE_PREFIXES = ("license", "licence", "copying", "notice", "unlicense", "copyright")

# The toolchain the runtime notices below were reviewed for. When
# rust-toolchain.toml moves, re-check them: the musl version Rust bundles,
# the LLVM commit, and the standard library's crates.
TOOLCHAIN = "1.99"
# Out-of-tree crates the standard library links on the release targets
# (rust-src library/vendor).
STD_CRATES = [
    "addr2line", "adler2", "cfg-if", "gimli", "hashbrown", "libc", "memchr",
    "miniz_oxide", "object", "rustc-demangle",
]
# Vendored crates whose std libraries never end up in a binary.
STD_NOT_LINKED = {"getopts", "rustc-literal-escaper"}
# Native code statically linked on some targets: (label, license, text).
# Windows links Microsoft's C runtime statically under Microsoft's
# redistribution terms; macOS links its system libraries dynamically.
NATIVE = [
    (
        "musl libc 1.2.5 (C library; Linux)",
        "MIT",
        "notices/musl-1.2.5-COPYRIGHT",
    ),
    (
        "LLVM libunwind (unwinder; Linux)",
        "Apache-2.0 WITH LLVM-exception",
        "rust-src:src/llvm-project/libunwind/LICENSE.TXT",
    ),
    (
        "LLVM compiler-rt crtbegin/crtend (startup objects; Linux)",
        "Apache-2.0 WITH LLVM-exception",
        "notices/llvm-compiler-rt-LICENSE.TXT",
    ),
]


# Licenses whose terms, for an executable, also require telling recipients
# where the covered source is (MPL-2.0 section 3.2(a)): a crate under one of
# them, with no permissive alternative in its expression, gets a source line.
SOURCE_LICENSES = ("MPL-2.0",)


def needs_source_offer(expression):
    """Whether a crate's license expression leaves only alternatives that
    require a source offer: every `OR` alternative names one of
    SOURCE_LICENSES. `MIT OR MPL-2.0` doesn't (MIT is taken); `MPL-2.0` and
    `MPL-2.0 AND MIT` do."""
    if not expression:
        return False
    alternatives = expression.replace("(", " ").replace(")", " ").split(" OR ")
    return all(any(name in alt.split() for name in SOURCE_LICENSES) for alt in alternatives)


def source_location(package):
    """Where a shipped crate's exact source is: its crates.io archive, or its
    git repository at the commit it was built from."""
    name, version, source = package["name"], package["version"], package.get("source") or ""
    if source.startswith("registry+https://github.com/rust-lang/crates.io-index"):
        where = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
    elif source.startswith("git+"):
        url, _, commit = source[len("git+"):].partition("#")
        where = f"{url.split('?')[0]} at commit {commit}"
    else:
        raise NoticeError(f"{name} {version}: no known source location for {source!r}")
    repository = package.get("repository")
    return f"{where} (repository: {repository})" if repository else where


class NoticeError(Exception):
    pass


def output_for(binary):
    return OUTPUT if binary == BINARY else WORKSPACES[binary] / "THIRD-PARTY-NOTICES"


def shipped_packages(target, binary=BINARY):
    meta = json.loads(
        subprocess.check_output(
            [
                "cargo", "metadata", "--locked", "--offline",
                "--format-version", "1", "--filter-platform", target,
            ],
            cwd=WORKSPACES[binary],
        )
    )
    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    root = next(p["id"] for p in meta["packages"] if p["name"] == binary)
    seen, stack = set(), [root]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for dep in nodes[current]["deps"]:
            # Normal dependencies only: build-dependencies and dev-dependencies
            # don't end up in the binary.
            if not any(kind["kind"] is None for kind in dep["dep_kinds"]):
                continue
            package = packages[dep["pkg"]]
            # Proc-macros run at compile time; their code doesn't ship.
            if any("proc-macro" in t["kind"] for t in package["targets"]):
                continue
            stack.append(dep["pkg"])
    return [packages[i] for i in seen if packages[i]["source"] is not None]


def git_checkout_root(directory):
    """The root of the cargo git checkout holding `directory`: the nearest
    ancestor (or itself) that cargo marked with `.cargo-ok`."""
    for candidate in [directory, *directory.parents]:
        if (candidate / ".cargo-ok").is_file():
            return candidate
    return None


def license_files(label, directory, declared, checkout=None, vendored=None):
    """Every license/notice file at the root of a source, plus the declared
    one; for a crate of a git checkout with none of its own, the checkout
    root's; for a crate with none at all, its vendored texts. Missing
    material is an error, never silently skipped."""
    def found(where):
        return sorted(
            f for f in where.iterdir()
            if f.is_file() and f.name.lower().startswith(LICENSE_PREFIXES)
        )
    files = found(directory)
    if not files and not declared and checkout is not None and checkout != directory:
        files = found(checkout)
    if vendored is not None:
        if files or declared:
            raise NoticeError(f"{label} ships its own license files: drop its vendored texts")
        return vendored
    if declared:
        named = directory / declared
        if not named.is_file():
            raise NoticeError(f"{label}: declared license file {declared} is missing")
        if named not in files:
            files.append(named)
    if not files:
        raise NoticeError(f"{label}: no license or notice file in its source")
    return files


def read_text(label, path):
    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as e:
        raise NoticeError(f"{label}: {path.name} is not UTF-8 ({e})") from None
    return text.replace("\r\n", "\n").strip()


def toolchain_sources():
    channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if channel != TOOLCHAIN:
        raise NoticeError(
            f"rust-toolchain.toml is on {channel}, but the runtime notices were reviewed "
            f"for {TOOLCHAIN}: re-check musl, LLVM and STD_CRATES, then update TOOLCHAIN"
        )
    version = subprocess.check_output(["rustc", "--version"], cwd=ROOT, text=True)
    if not version.startswith(f"rustc {TOOLCHAIN}."):
        raise NoticeError(f"rustc is {version.strip()}, expected {TOOLCHAIN}")
    sysroot = pathlib.Path(
        subprocess.check_output(["rustc", "--print", "sysroot"], cwd=ROOT, text=True).strip()
    )
    source = sysroot / "lib" / "rustlib" / "src" / "rust"
    if not (source / "library" / "Cargo.lock").is_file():
        raise NoticeError("the toolchain's rust-src component is missing")
    return sysroot, source


def std_crates(sysroot, source):
    """The standard library's out-of-tree crates, checked against the host
    std's own libraries so a toolchain update can't add one unnoticed."""
    vendor = source / "library" / "vendor"
    vendored = {}
    for directory in vendor.iterdir():
        manifest = tomllib.loads((directory / "Cargo.toml").read_text(encoding="utf-8"))
        vendored[manifest["package"]["name"]] = (directory, manifest["package"])
    host = subprocess.check_output(["rustc", "--print", "host-tuple"], cwd=ROOT, text=True).strip()
    linked = {
        f.name[len("lib"):].rsplit("-", 1)[0]
        for f in (sysroot / "lib" / "rustlib" / host / "lib").glob("lib*.rlib")
    }
    for name in vendored:
        if name.replace("-", "_") in linked and name not in STD_CRATES + list(STD_NOT_LINKED):
            raise NoticeError(f"the standard library now links {name}: add it to STD_CRATES")
    crates = []
    for name in STD_CRATES:
        if name not in vendored:
            raise NoticeError(f"{name} is no longer vendored by the standard library")
        directory, package = vendored[name]
        crates.append((name, package["version"], package.get("license"), directory,
                       package.get("license-file")))
    builtins = source / "library" / "compiler-builtins"
    package = tomllib.loads(
        (builtins / "compiler-builtins" / "Cargo.toml").read_text(encoding="utf-8")
    )["package"]
    # Its notice covers the whole compiler-builtins tree, so it sits at the top.
    crates.append(("compiler_builtins", package["version"], package.get("license"), builtins,
                   None))
    return crates


def vendored_notices(binary):
    """`notices/crates.json` in the binary's workspace, if it has one:
    for each crate that ships no license file, as `"<name> <version>"`, its
    vendored texts (`files`, relative to that notices directory), with the
    repository and commit they come from."""
    directory = WORKSPACES[binary] / "notices"
    manifest = directory / "crates.json"
    if not manifest.is_file():
        return {}
    vendored = {}
    for key, entry in json.loads(manifest.read_text(encoding="utf-8")).items():
        if not entry.get("repository") or not entry.get("commit") or not entry.get("files"):
            raise NoticeError(f"notices/crates.json: {key} needs a repository, a commit and files")
        files = [directory / file for file in entry["files"]]
        for file in files:
            if not file.is_file():
                raise NoticeError(f"notices/crates.json: {key}: {file.name} is missing")
        vendored[key] = files
    return vendored


def header(binary):
    """The file's opening: the core's text, naming `binary`."""
    return [
        f"THIRD-PARTY NOTICES for {binary}",
        "",
        f"{binary} statically links the third-party code listed below: the",
        "crates it depends on, and the runtime of the Rust toolchain it is built",
        "with. Each is listed with its license expression, followed by the",
        "license and notice texts its source distributes. The Rust standard",
        "library's own notices are in THIRD-PARTY-NOTICES-rust-std.html, which",
        "ships next to this file. Generated by scripts/third-party-notices.py;",
        "do not edit.",
    ]


def generate(binary=BINARY):
    crates = {}
    for target in TARGETS:
        for package in shipped_packages(target, binary):
            crates[(package["name"], package["version"])] = package
    sysroot, source = toolchain_sources()
    vendored = vendored_notices(binary)
    lines = [*header(binary), "", "Crates:"]
    texts = {}  # text -> [labels]

    def add(label, files):
        for file in files:
            texts.setdefault(read_text(label, file), []).append(f"{label} ({file.name})")

    for (name, version) in sorted(crates):
        package = crates[(name, version)]
        label = f"{name} {version}"
        lines.append(f"- {label}: {package.get('license') or 'see the license files below'}")
        directory = pathlib.Path(package["manifest_path"]).parent
        checkout = (
            git_checkout_root(directory)
            if (package.get("source") or "").startswith("git+") else None
        )
        add(label, license_files(label, directory, package.get("license_file"), checkout,
                                 vendored.pop(label, None)))
    if vendored:
        raise NoticeError(
            "notices/crates.json vendors texts for crates the binary doesn't ship: "
            + ", ".join(sorted(vendored))
        )
    offered = [
        crates[key] for key in sorted(crates) if needs_source_offer(crates[key].get("license"))
    ]
    if offered:
        lines += [
            "",
            "Source code: these crates are in the binary unmodified, under the",
            "Mozilla Public License 2.0, whose section 3.2(a) asks that recipients",
            "of an executable be told where the source is. Each one's exact source:",
        ]
        for package in offered:
            lines.append(f"- {package['name']} {package['version']}: {source_location(package)}")
    lines += ["", f"Rust {TOOLCHAIN} toolchain runtime:"]
    for (name, version, expression, directory, declared) in std_crates(sysroot, source):
        label = f"{name} {version}"
        lines.append(f"- {label} (Rust standard library): {expression}")
        add(label, license_files(label, directory, declared))
    for (label, expression, text) in NATIVE:
        lines.append(f"- {label}: {expression}")
        path = source / text[len("rust-src:"):] if text.startswith("rust-src:") else ROOT / text
        if not path.is_file():
            raise NoticeError(f"{label}: {text} is missing")
        add(label, [path])
    lines.append("")
    for text, owners in sorted(texts.items(), key=lambda item: item[1][0]):
        lines.append("=" * 72)
        lines.append("Used by: " + ", ".join(owners))
        lines.append("-" * 72)
        lines.append(text)
        lines.append("")
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")


def parse_args(argv):
    """`[--binary <name>] [--check]`: which binary, and whether to check."""
    binary, check, rest = BINARY, False, list(argv)
    while rest:
        arg = rest.pop(0)
        if arg == "--check":
            check = True
        elif arg == "--binary" and rest:
            binary = rest.pop(0)
        else:
            raise NoticeError(f"unknown argument {arg}")
    if binary not in WORKSPACES:
        raise NoticeError(f"no notices for {binary}: one of {', '.join(WORKSPACES)}")
    return binary, check


def main():
    try:
        binary, check = parse_args(sys.argv[1:])
        content = generate(binary)
    except NoticeError as e:
        print(f"third-party-notices: {e}", file=sys.stderr)
        return 1
    output = output_for(binary)
    if check:
        # Byte for byte: LF line endings on every platform.
        if not output.exists() or output.read_bytes() != content:
            rerun = "" if binary == BINARY else f" --binary {binary}"
            print(f"{output.relative_to(ROOT) if output.is_relative_to(ROOT) else output} "
                  f"is stale: run python3 scripts/third-party-notices.py{rerun}",
                  file=sys.stderr)
            return 1
        return 0
    output.write_bytes(content)
    return 0


if __name__ == "__main__":
    sys.exit(main())
