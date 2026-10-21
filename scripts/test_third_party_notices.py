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


class Arguments(unittest.TestCase):
    def test_the_core_by_default(self):
        self.assertEqual(notices.parse_args([]), ("freedom-cored", False))
        self.assertEqual(notices.parse_args(["--check"]), ("freedom-cored", True))

    def test_a_service(self):
        self.assertEqual(notices.parse_args(["--binary", "freedom-ipfsd", "--check"]),
                         ("freedom-ipfsd", True))
        self.assertEqual(notices.output_for("freedom-ipfsd"),
                         notices.ROOT / "services" / "freedom-ipfsd" / "THIRD-PARTY-NOTICES")

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
