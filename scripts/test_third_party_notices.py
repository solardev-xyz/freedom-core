"""Failure paths and the output-byte policy of third-party-notices.py."""

import importlib.util
import pathlib
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "notices", pathlib.Path(__file__).with_name("third-party-notices.py")
)
notices = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(notices)


class LicenseFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_missing_declared_file_fails(self):
        (self.dir / "LICENSE-MIT").write_text("MIT")
        with self.assertRaisesRegex(notices.NoticeError, "declared license file"):
            notices.license_files("x 1.0", self.dir, "COPYING.custom")

    def test_no_license_material_fails(self):
        (self.dir / "README.md").write_text("no license here")
        with self.assertRaisesRegex(notices.NoticeError, "no license or notice file"):
            notices.license_files("x 1.0", self.dir, None)

    def test_declared_and_discovered_files_are_both_kept(self):
        (self.dir / "LICENSE-MIT").write_text("MIT")
        (self.dir / "terms.txt").write_text("custom")
        files = notices.license_files("x 1.0", self.dir, "terms.txt")
        self.assertEqual([f.name for f in files], ["LICENSE-MIT", "terms.txt"])

    def test_invalid_utf8_fails(self):
        path = self.dir / "LICENSE"
        path.write_bytes(b"Copyright \xff")
        with self.assertRaisesRegex(notices.NoticeError, "not UTF-8"):
            notices.read_text("x 1.0", path)

    def test_crlf_input_is_normalized(self):
        path = self.dir / "LICENSE"
        path.write_bytes(b"line one\r\nline two\r\n")
        self.assertEqual(notices.read_text("x 1.0", path), "line one\nline two")

    def test_a_git_workspace_member_gets_the_checkout_roots_files(self):
        (self.dir / ".cargo-ok").write_text("ok")
        (self.dir / "LICENSE-MIT").write_text("MIT")
        crate = self.dir / "crates" / "member"
        crate.mkdir(parents=True)
        self.assertEqual(notices.git_checkout_root(crate), self.dir)
        files = notices.license_files("x 1.0", crate, None, self.dir)
        self.assertEqual(files, [self.dir / "LICENSE-MIT"])
        # A crate's own files win.
        (crate / "LICENSE").write_text("own")
        self.assertEqual(notices.license_files("x 1.0", crate, None, self.dir), [crate / "LICENSE"])

    def test_outside_a_checkout_there_is_no_root(self):
        self.assertIsNone(notices.git_checkout_root(self.dir))

    def test_vendored_texts_stand_in_only_for_a_crate_with_none(self):
        text = self.dir / "vendored-LICENSE"
        text.write_text("MIT")
        crate = self.dir / "crate"
        crate.mkdir()
        self.assertEqual(notices.license_files("x 1.0", crate, None, None, [text]), [text])
        (crate / "LICENSE").write_text("own")
        with self.assertRaisesRegex(notices.NoticeError, "ships its own license files"):
            notices.license_files("x 1.0", crate, None, None, [text])


class Vendored(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        (self.dir / "notices").mkdir()
        self.saved = dict(notices.WORKSPACES)
        notices.WORKSPACES["svc"] = self.dir

    def tearDown(self):
        notices.WORKSPACES.clear()
        notices.WORKSPACES.update(self.saved)
        self.tmp.cleanup()

    def write(self, manifest):
        (self.dir / "notices" / "crates.json").write_text(notices.json.dumps(manifest))

    def test_no_manifest_vendors_nothing(self):
        self.assertEqual(notices.vendored_notices("svc"), {})

    def test_entries_name_their_files(self):
        (self.dir / "notices" / "repo").mkdir()
        (self.dir / "notices" / "repo" / "LICENSE").write_text("MIT")
        self.write({"x 1.0": {"repository": "https://example/repo", "commit": "abc",
                              "files": ["repo/LICENSE"]}})
        self.assertEqual(notices.vendored_notices("svc"),
                         {"x 1.0": [self.dir / "notices" / "repo" / "LICENSE"]})

    def test_a_missing_file_or_source_fails(self):
        self.write({"x 1.0": {"repository": "https://example/repo", "commit": "abc",
                              "files": ["repo/LICENSE"]}})
        with self.assertRaisesRegex(notices.NoticeError, "is missing"):
            notices.vendored_notices("svc")
        self.write({"x 1.0": {"files": ["repo/LICENSE"]}})
        with self.assertRaisesRegex(notices.NoticeError, "needs a repository"):
            notices.vendored_notices("svc")


class Binaries(unittest.TestCase):
    def test_every_binary_names_its_targets_and_native_code(self):
        self.assertEqual(set(notices.TARGETS), set(notices.WORKSPACES))
        self.assertEqual(set(notices.NATIVE), set(notices.WORKSPACES))
        self.assertLessEqual(set(notices.LINKS_CHECKED), set(notices.WORKSPACES))

    def test_the_services_link_glibc_on_linux_and_the_core_musl(self):
        linux = lambda binary: [t for t in notices.TARGETS[binary] if "linux" in t]
        for service in ("freedom-ipfsd", "freedom-radicled"):
            self.assertEqual(linux(service),
                             ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"])
        self.assertEqual(linux(notices.BINARY),
                         ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"])

    def test_every_native_entry_is_well_formed(self):
        for binary, entries in notices.NATIVE.items():
            for entry in map(lambda e: notices.Native(*e), entries):
                with self.subTest(binary=binary, label=entry.label):
                    self.assertTrue(entry.label and entry.expression and entry.text)
                    if entry.text.startswith("crate:"):
                        self.assertTrue(entry.bundled_by)
                    if entry.bundled_by:
                        name, _, version = entry.bundled_by.partition(" ")
                        self.assertTrue(name and version and " " not in version)

    def test_radicled_lists_libgit2_zlib_and_sqlite_with_libgit2s_source(self):
        bundled = {notices.Native(*e).bundled_by: notices.Native(*e)
                   for e in notices.NATIVE["freedom-radicled"] if len(e) > 3}
        self.assertEqual({b.split(" ")[0] for b in bundled},
                         {"libgit2-sys", "libz-sys", "sqlite3-src"})
        libgit2 = next(e for b, e in bundled.items() if b.startswith("libgit2-sys "))
        self.assertIn("LGPL-2.1-or-later", libgit2.expression)
        self.assertIn("freedom-core", libgit2.source)


class Bundled(unittest.TestCase):
    """C libraries that crates bundle: tied to the crate's exact version,
    their texts read from its source, and every `links` crate accounted
    for."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        crate = self.dir / "libz-sys-1.1.31"
        (crate / "src" / "zlib").mkdir(parents=True)
        (crate / "src" / "zlib" / "LICENSE").write_text("zlib")
        self.crates = {
            ("libz-sys", "1.1.31"): {"manifest_path": str(crate / "Cargo.toml"), "links": "z"},
            ("ring", "0.17.14"): {"manifest_path": "unused", "links": "ring_core"},
            ("serde", "1.0.0"): {"manifest_path": "unused"},
        }
        self.zlib = notices.Native("zlib", "Zlib", "crate:src/zlib/LICENSE", "libz-sys 1.1.31")
        self.saved = dict(notices.LINKS_CHECKED)

    def tearDown(self):
        notices.LINKS_CHECKED.clear()
        notices.LINKS_CHECKED.update(self.saved)
        self.tmp.cleanup()

    def test_a_crate_text_is_read_from_the_bundling_crate(self):
        self.assertEqual(notices.native_text(self.zlib, self.crates, self.dir),
                         self.dir / "libz-sys-1.1.31" / "src" / "zlib" / "LICENSE")

    def test_another_version_of_the_bundling_crate_fails(self):
        moved = self.zlib._replace(bundled_by="libz-sys 1.1.32")
        with self.assertRaisesRegex(notices.NoticeError, "ships libz-sys 1.1.31, not 1.1.32"):
            notices.native_text(moved, self.crates, self.dir)
        gone = self.zlib._replace(bundled_by="libgit2-sys 0.18.7")
        with self.assertRaisesRegex(notices.NoticeError, "doesn't ship libgit2-sys, not 0.18.7"):
            notices.native_text(gone, self.crates, self.dir)

    def test_a_missing_text_or_bundler_fails(self):
        with self.assertRaisesRegex(notices.NoticeError, "is missing"):
            notices.native_text(self.zlib._replace(text="crate:COPYING"), self.crates, self.dir)
        with self.assertRaisesRegex(notices.NoticeError, "needs the crate that bundles it"):
            notices.native_text(self.zlib._replace(bundled_by=None), self.crates, self.dir)

    def test_every_links_crate_is_accounted_for(self):
        notices.LINKS_CHECKED["svc"] = {"ring": "its own files"}
        notices.check_links("svc", self.crates, [self.zlib])
        with self.assertRaisesRegex(notices.NoticeError, "libz-sys 1.1.31 declares links"):
            notices.check_links("svc", self.crates, [])
        notices.LINKS_CHECKED["svc"] = {}
        with self.assertRaisesRegex(notices.NoticeError, "ring 0.17.14 declares links"):
            notices.check_links("svc", self.crates, [self.zlib])

    def test_a_stale_links_entry_fails(self):
        notices.LINKS_CHECKED["svc"] = {"ring": "its own files", "openssl-sys": "gone"}
        with self.assertRaisesRegex(notices.NoticeError, "lists openssl-sys"):
            notices.check_links("svc", self.crates, [self.zlib])

    def test_an_unchecked_binary_is_not_checked(self):
        notices.LINKS_CHECKED.pop("svc", None)
        notices.check_links("svc", self.crates, [])

    def test_the_header_names_bundled_c_only_when_there_is_some(self):
        self.assertNotIn("C libraries", " ".join(notices.header("x")))
        self.assertIn("the C libraries some of them bundle", " ".join(notices.header("x", True)))


class Arguments(unittest.TestCase):
    def test_the_core_by_default(self):
        self.assertEqual(notices.parse_args([]), ("freedom-cored", False))
        self.assertEqual(notices.parse_args(["--check"]), ("freedom-cored", True))

    def test_a_service(self):
        for service in ("freedom-ipfsd", "freedom-radicled"):
            self.assertEqual(notices.parse_args(["--binary", service, "--check"]),
                             (service, True))
            self.assertEqual(notices.output_for(service),
                             notices.ROOT / "services" / service / "THIRD-PARTY-NOTICES")

    def test_refusals(self):
        for argv in (["--binary"], ["--binary", "nope"], ["--frobnicate"]):
            with self.assertRaises(notices.NoticeError, msg=argv):
                notices.parse_args(argv)


class OutputBytes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (notices.OUTPUT, notices.generate, notices.sys.argv)
        notices.OUTPUT = pathlib.Path(self.tmp.name) / "THIRD-PARTY-NOTICES"
        notices.generate = lambda *_: b"one\ntwo\n"

    def tearDown(self):
        notices.OUTPUT, notices.generate, notices.sys.argv = self.saved
        self.tmp.cleanup()

    def run_main(self, *args):
        notices.sys.argv = ["third-party-notices.py", *args]
        return notices.main()

    def test_written_with_lf_on_every_platform(self):
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(notices.OUTPUT.read_bytes(), b"one\ntwo\n")
        self.assertEqual(self.run_main("--check"), 0)

    def test_check_rejects_crlf(self):
        notices.OUTPUT.write_bytes(b"one\r\ntwo\r\n")
        self.assertEqual(self.run_main("--check"), 1)

    def test_errors_fail_without_writing(self):
        def broken(*_):
            raise notices.NoticeError("x 1.0: no license or notice file in its source")
        notices.generate = broken
        self.assertEqual(self.run_main(), 1)
        self.assertFalse(notices.OUTPUT.exists())


if __name__ == "__main__":
    unittest.main()


class SourceOffers(unittest.TestCase):
    def test_only_mpl_without_a_permissive_alternative_needs_one(self):
        for expression, needed in [
            ("MPL-2.0", True),
            ("MPL-2.0 AND MIT", True),
            ("(MPL-2.0 AND MIT)", True),
            ("MIT OR MPL-2.0", False),
            ("MPL-2.0 OR Apache-2.0", False),
            ("MIT", False),
            ("Apache-2.0 OR MIT", False),
            ("", False),
            (None, False),
            # Review of #145: grouping and precedence, as SPDX defines them.
            ("MPL-2.0 AND (MIT OR Apache-2.0)", True),
            ("(MIT OR Apache-2.0) AND MPL-2.0", True),
            ("MIT AND (MPL-2.0 OR Apache-2.0)", False),
            ("(MPL-2.0 AND MIT) OR (MPL-2.0 AND Apache-2.0)", True),
            ("MPL-2.0 AND (Apache-2.0 WITH LLVM-exception OR MIT)", True),
            ("Apache-2.0 WITH LLVM-exception AND MPL-2.0", True),
            ("Apache-2.0 WITH LLVM-exception OR MPL-2.0", False),
            ("MIT OR MPL-2.0 AND Apache-2.0", False),
            ("MPL-2.0 AND MIT OR MPL-2.0 AND Apache-2.0", True),
            # Spellings: whitespace, case, "or later", Cargo's legacy `/`.
            ("MPL-2.0\tOR\tMIT", False),
            ("MPL-2.0+", True),
            ("mpl-2.0", True),
            ("MPL-2.0 and MIT", True),
            ("MIT/MPL-2.0", False),
            ("((MPL-2.0))", True),
        ]:
            self.assertEqual(notices.needs_source_offer(expression), needed, expression)

    def test_an_expression_that_does_not_parse_fails(self):
        for expression in ["MPL-2.0 AND", "(MPL-2.0", "MPL-2.0)", "AND MIT", "MPL-2.0 MIT",
                           "MPL-2.0 WITH", "MPL-2.0 WITH (x)", "()"]:
            with self.assertRaisesRegex(notices.NoticeError, "license expression"):
                notices.needs_source_offer(expression)

    def test_a_registry_crate_points_at_its_crates_io_archive(self):
        package = {
            "name": "attohttpc",
            "version": "0.30.1",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "repository": "https://github.com/sbstp/attohttpc",
        }
        self.assertEqual(
            notices.source_location(package),
            "https://static.crates.io/crates/attohttpc/attohttpc-0.30.1.crate"
            " (repository: https://github.com/sbstp/attohttpc)",
        )

    def test_a_git_crate_points_at_its_commit(self):
        package = {
            "name": "x",
            "version": "1.0.0",
            "source": "git+https://github.com/o/x?rev=abc#abcdef0",
        }
        self.assertEqual(
            notices.source_location(package), "https://github.com/o/x at commit abcdef0"
        )

    def test_an_unknown_source_fails(self):
        with self.assertRaisesRegex(notices.NoticeError, "no known source location"):
            notices.source_location({"name": "x", "version": "1", "source": "path+file:///x"})
