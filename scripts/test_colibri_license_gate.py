"""colibri-license-gate.py over synthetic builds: a verifier-only build
passes; server code, a prover, an unlisted SPDX identifier, PolyForm outside
the notices' exception, a third party's tree the notices don't list or whose
license differs, and a build without a manifest fail."""

import importlib.util
import json
import pathlib
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "gate", pathlib.Path(__file__).with_name("colibri-license-gate.py")
)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

MIT = "/* SPDX-License-Identifier: MIT */\n"


class Gate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = pathlib.Path(self.tmp.name)
        self.target = base / "target"
        self.root = base / "checkout"
        self.build = self.target / "release/build/colibri-stateless-0123/out/cmake/no-op/no-prover"
        self.build.mkdir(parents=True)
        self.notices = base / "notices.json"
        self.notices.write_text(json.dumps({
            "spdx": ["MIT", "Apache-2.0"],
            "polyform_mentions": [{"path": "src/util/version.c", "why": "prints the server's license"}],
            "components": [
                {"name": "Colibri", "license": "MIT", "tree": "colibri"},
                {"name": "blst", "license": "Apache-2.0", "tree": "_deps/blst-src"},
            ],
        }))
        self.compiled = []
        self.write("src/api/colibri.h", MIT)
        self.source("src/api/colibri.c", ["src/api/colibri.h"])
        self.source("src/chains/eth/verifier/eth_verify.c", ["src/api/colibri.h"])
        dep = self.build / "_deps/blst-src/bindings/blst.h"
        dep.parent.mkdir(parents=True)
        dep.write_text("// SPDX-License-Identifier: Apache-2.0\n")
        (self.build / "_deps/blst-src/LICENSE").write_text("Apache License\nVersion 2.0, January 2004\n")
        self.depfile("blst", [str(dep), "/usr/include/stdio.h"])

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, content):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def source(self, rel, headers, content=MIT):
        path = self.write(rel, content)
        self.compiled.append({"directory": str(self.build), "file": str(path), "command": "cc -c"})
        (self.build / "compile_commands.json").write_text(json.dumps(self.compiled))
        self.depfile(rel.replace("/", "_"), [str(path)] + [str(self.root / h) for h in headers])

    def depfile(self, name, prerequisites):
        (self.build / f"{name}.o.d").write_text(f"{name}.o: " + " \\\n  ".join(prerequisites) + "\n")

    def errors(self):
        return gate.check(str(self.target), str(self.notices))[0]

    def test_a_verifier_only_build_passes(self):
        self.assertEqual(self.errors(), [])

    def test_server_code_fails_compiled_or_included(self):
        self.source("src/server/server.c", [])
        self.write("src/chains/eth/server/period_store_files.h", MIT)
        self.source("src/chains/eth/verifier/x.c", ["src/chains/eth/server/period_store_files.h"])
        errors = "\n".join(self.errors())
        self.assertIn("src/server/server.c", errors)
        self.assertIn("src/chains/eth/server/period_store_files.h", errors)

    def test_a_prover_fails(self):
        self.source("src/prover/prover.c", [])
        self.source("src/chains/eth/prover/eth_prover.c", [])
        errors = "\n".join(self.errors())
        self.assertIn("src/prover/prover.c", errors)
        self.assertIn("src/chains/eth/prover/eth_prover.c", errors)

    def test_an_unlisted_spdx_identifier_fails(self):
        self.source("src/util/x.c", [], "// SPDX-License-Identifier: GPL-2.0-only\n")
        self.assertIn("GPL-2.0-only isn't in the notices", "\n".join(self.errors()))

    def test_polyform_anywhere_fails(self):
        self.write("src/util/y.h", "/* Licensed under the PolyForm Noncommercial License 1.0.0 */\n")
        self.source("src/util/y.c", ["src/util/y.h"])
        self.assertIn("names PolyForm", "\n".join(self.errors()))

    def test_version_c_may_name_polyform_while_it_stays_mit(self):
        self.source("src/util/version.c", [], MIT + 'puts("License: PolyForm Noncommercial 1.0.0");\n')
        self.assertEqual(self.errors(), [])
        self.source("src/util/version.c", [], 'puts("License: PolyForm Noncommercial 1.0.0");\n')
        self.assertIn("src/util/version.c: names PolyForm", "\n".join(self.errors()))

    def test_an_unlisted_third_party_fails(self):
        zstd = self.build / "_deps/zstd-src"
        zstd.mkdir(parents=True)
        (zstd / "LICENSE").write_text("BSD License\n")
        self.assertIn("_deps/zstd-src: a third party's tree in the build that the notices don't list", "\n".join(self.errors()))

    def test_a_third_party_under_another_license_fails(self):
        (self.build / "_deps/blst-src/LICENSE").write_text("Permission is hereby granted\n")
        self.assertIn("_deps/blst-src: LICENSE isn't Apache-2.0", "\n".join(self.errors()))

    def test_no_manifest_fails(self):
        (self.build / "compile_commands.json").unlink()
        self.assertIn("no compile_commands.json", "\n".join(self.errors()))


if __name__ == "__main__":
    unittest.main()
