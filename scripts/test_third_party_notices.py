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


class OutputBytes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (notices.OUTPUT, notices.generate, notices.sys.argv)
        notices.OUTPUT = pathlib.Path(self.tmp.name) / "THIRD-PARTY-NOTICES"
        notices.generate = lambda: b"one\ntwo\n"

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
        def broken():
            raise notices.NoticeError("x 1.0: no license or notice file in its source")
        notices.generate = broken
        self.assertEqual(self.run_main(), 1)
        self.assertFalse(notices.OUTPUT.exists())


if __name__ == "__main__":
    unittest.main()
