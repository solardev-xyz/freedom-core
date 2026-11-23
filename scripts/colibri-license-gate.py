#!/usr/bin/env python3
"""Design 0014's license gate (COL-2) over the native Colibri build.

Reads the build's compiled-source manifest: every source CMake compiled, from
its compile_commands.json, and every header the compiler's dependency files
(*.d) list. It fails when:

- anything under Colibri's src/server/ is compiled or included;
- anything under src/chains/eth/server/ is compiled or included;
- any prover source is (src/prover/, src/chains/*/prover/): the build is
  verifier-only;
- a tree in the build (Colibri's own, its generated headers, each libs/* and
  _deps/*-src) isn't in the notices
  (services/freedom-colibrid/notices/c-sources.json);
- a compiled source or listed header carries an SPDX identifier that isn't
  one its tree's entry lists, or names PolyForm anywhere, except the files
  the notices name with the reason (src/util/version.c prints the server's
  license; 0014, Licenses), which must stay MIT;
- a third party's tree's LICENSE file isn't the license the notices give it. blst is compiled
  by its own build script, outside CMake's compile commands, so its tree's
  license is what the gate checks for it.

Usage: colibri-license-gate.py <out dir> [--manifest <out.json>]

<out dir> is the OUT_DIR of colibri-stateless's build script for the build
the tests ran, as Cargo reports it (the build-script-executed message of
--message-format=json), not the target directory: a restored cache can hold
the build directories of earlier pins too, and the gate reads exactly one
build. The build must have run with CMAKE_EXPORT_COMPILE_COMMANDS=ON in its
environment (CMake reads it from there), so that CMake wrote
compile_commands.json beside its cache.
"""

import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
NOTICES = os.path.join(HERE, "..", "services", "freedom-colibrid", "notices", "c-sources.json")

FORBIDDEN = [
    ("src/server/", "PolyForm-licensed server code"),
    ("src/chains/eth/server/", "the ETH server handlers (mixed license headers, F-8)"),
    ("src/prover/", "the prover (the build is verifier-only)"),
]
PROVER_CHAIN = re.compile(r"^src/chains/[^/]+/prover/")
# What a whole-tree license file must say, by SPDX identifier.
LICENSE_MARKERS = {
    "Apache-2.0": ["Apache License", "Version 2.0"],
    "MIT": ["Permission is hereby granted"],
}
LICENSE_FILES = ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING")
SPDX = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+\-() ]+?)\s*(?:\*/|-->|$)", re.M)


def depfile_paths(path):
    """The prerequisites of a make-style dependency file."""
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        text = f.read().replace("\\\n", " ")
    out = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        # target: prereq prereq ... (a Windows drive letter isn't a target
        # separator; the targets here are object files)
        _, _, rest = line.partition(": ")
        if not rest:
            continue
        # Make escapes spaces in names with a backslash.
        tokens = re.split(r"(?<!\\)\s+", rest.strip())
        out.extend(t.replace("\\ ", " ") for t in tokens if t)
    return out


def check(out_dir, notices_path=NOTICES):
    """The gate: (errors, manifest, report lines) for the one build under out_dir."""
    with open(notices_path, encoding="utf-8") as f:
        notices = json.load(f)
    allowed = {c["tree"]: set(c["spdx"]) for c in notices["components"]}
    polyform_ok = {e["path"] for e in notices.get("polyform_mentions", [])}
    third_parties = {c["tree"]: c["license"] for c in notices["components"] if c["tree"].startswith("_deps/")}
    out_dir = os.path.realpath(out_dir)

    dbs = glob.glob(os.path.join(out_dir, "**", "compile_commands.json"), recursive=True)
    if not dbs:
        return [f"no compile_commands.json under {out_dir} (build with CMAKE_EXPORT_COMPILE_COMMANDS=ON)"], {}, []
    if len(dbs) > 1:
        return [f"more than one build under {out_dir}: {sorted(os.path.relpath(d, out_dir) for d in dbs)}"], {}, []
    errors = []
    lines = []
    manifest = {"builds": []}
    for db in sorted(dbs):
        build_dir = os.path.dirname(db)
        with open(db, encoding="utf-8") as f:
            entries = json.load(f)
        compiled = set()
        for entry in entries:
            path = entry["file"]
            if not os.path.isabs(path):
                path = os.path.join(entry["directory"], path)
            compiled.add(os.path.realpath(path))
        if not compiled:
            errors.append(f"{db}: no compiled sources")
            continue
        # Colibri's checkout: the tree that holds src/api/colibri.h.
        roots = {p.split("/src/")[0] for p in compiled if "/src/api/" in p}
        if len(roots) != 1:
            errors.append(f"{db}: can't tell Colibri's checkout from {sorted(roots)}")
            continue
        root = roots.pop()
        deps = os.path.join(build_dir, "_deps")
        included = set()
        for d in glob.glob(os.path.join(build_dir, "**", "*.d"), recursive=True):
            for p in depfile_paths(d):
                if not os.path.isabs(p):
                    p = os.path.join(build_dir, p)
                included.add(os.path.realpath(p))
        if not included:
            errors.append(f"{db}: no dependency files listed any header")

        trees = {}
        system = 0
        for path in sorted(compiled | included):
            if path.startswith(root + "/"):
                rel = path[len(root) + 1:]
                tree = "libs/" + rel.split("/")[1] if rel.startswith("libs/") else "colibri"
            elif path.startswith(deps + "/"):
                rel = path[len(deps) + 1:]
                tree = "_deps/" + rel.split("/")[0]
                rel = "/".join(rel.split("/")[1:])
            elif path.startswith(build_dir + "/"):
                rel = path[len(build_dir) + 1:]
                tree = "generated"
            else:
                system += 1  # the compiler's and the OS's own headers
                continue
            if tree in ("colibri", "generated"):
                for prefix, why in FORBIDDEN:
                    if rel.startswith(prefix):
                        errors.append(f"{rel}: {why} is in the build ({'compiled' if path in compiled else 'included'})")
                if PROVER_CHAIN.match(rel):
                    errors.append(f"{rel}: a chain's prover is in the build")
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except OSError as e:
                errors.append(f"{path}: {e}")
                continue
            ids = sorted(set(m.strip() for m in SPDX.findall(content)))
            if "polyform" in content.lower():
                if tree == "colibri" and rel in polyform_ok and ids == ["MIT"]:
                    pass  # named with its reason in the notices
                else:
                    errors.append(f"{tree}/{rel}: names PolyForm")
            if tree not in allowed:
                errors.append(f"{tree}/{rel}: its tree isn't in the notices")
            for spdx in ids:
                if tree in allowed and spdx not in allowed[tree]:
                    errors.append(f"{tree}/{rel}: SPDX-License-Identifier {spdx} isn't one the notices give {tree}")
            t = trees.setdefault(tree, {"files": 0, "compiled": 0, "spdx": {}, "paths": []})
            t["files"] += 1
            t["compiled"] += path in compiled
            t["paths"].append(f"{tree}/{rel}" + (" (compiled)" if path in compiled else ""))
            for spdx in ids or ["(none)"]:
                t["spdx"][spdx] = t["spdx"].get(spdx, 0) + 1
        # Third parties' trees: listed, and under the license the notices give.
        for src in sorted(glob.glob(os.path.join(deps, "*-src"))):
            tree = "_deps/" + os.path.basename(src)
            if tree not in third_parties:
                errors.append(f"{tree}: a third party's tree in the build that the notices don't list")
                continue
            license_files = [os.path.join(src, f) for f in LICENSE_FILES if os.path.isfile(os.path.join(src, f))]
            if not license_files:
                errors.append(f"{tree}: no license file")
                continue
            with open(license_files[0], encoding="utf-8", errors="replace") as f:
                text = f.read()
            markers = LICENSE_MARKERS.get(third_parties[tree], [])
            if not markers or not all(m in text for m in markers):
                errors.append(f"{tree}: {os.path.basename(license_files[0])} isn't {third_parties[tree]}")
        manifest["builds"].append({
            "build": os.path.relpath(build_dir, out_dir),
            "compiled": len(compiled),
            "headers": len(included - compiled),
            "system_headers": system,
            "trees": trees,
        })
        lines.append(f"{os.path.relpath(build_dir, out_dir)}: {len(compiled)} compiled, {len(included - compiled)} headers ({system} the system's)")
        for tree, t in sorted(trees.items()):
            spdx = ", ".join(f"{k} {v}" for k, v in sorted(t["spdx"].items()))
            lines.append(f"  {tree:<24} {t['files']:>5} files ({t['compiled']} compiled)  SPDX: {spdx}")
    return errors, manifest, lines


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    errors, manifest, lines = check(args[0])
    for line in lines:
        print(line)
    if "--manifest" in args and manifest:
        with open(args[args.index("--manifest") + 1], "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
            f.write("\n")
    if errors:
        for e in errors:
            print(f"license gate: {e}", file=sys.stderr)
        sys.exit(1)
    print("license gate: passed")


if __name__ == "__main__":
    main()
