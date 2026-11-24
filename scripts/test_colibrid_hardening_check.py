"""colibrid-hardening-check.py: a build whose sources all carry the flags
passes, one without them fails; a binary that calls the stack protector's
and _FORTIFY_SOURCE's checks passes (Linux's and macOS's listings), one that
doesn't fails; a PE image with Control Flow Guard passes, one without its
header flag or its instrumentation fails."""

import importlib.util
import json
import pathlib
import struct
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "hardening", pathlib.Path(__file__).with_name("colibrid-hardening-check.py")
)
hardening = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hardening)

FLAGS = ["-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-fcf-protection=full"]


def pe_image(guard_cf=True, instrumented=True):
    """A minimal PE32+ image: one section holding the load configuration."""
    pe_offset = 0x40
    optional_size = 240
    table = pe_offset + 24 + optional_size
    raw_offset = 0x200
    image = bytearray(raw_offset + 0x100)
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset:pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into("<HH12xH", image, coff, 0x8664, 1, optional_size)
    optional = coff + 20
    struct.pack_into("<H", image, optional, 0x20B)
    struct.pack_into("<H", image, optional + 70, 0x4000 if guard_cf else 0)
    # The load configuration at RVA 0x1010, 0x100 bytes.
    struct.pack_into("<II", image, optional + 112 + 8 * 10, 0x1010, 0x100)
    struct.pack_into("<IIII", image, table + 8, 0x1000, 0x1000, 0x100, raw_offset - 0x10)
    struct.pack_into("<I", image, raw_offset + 0x90, 0x100 if instrumented else 0)
    return bytes(image)


class CompileCommands(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        (self.dir / "out/build").mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, entries):
        (self.dir / "out/build/compile_commands.json").write_text(json.dumps(entries))

    def test_every_source_with_the_flags_passes(self):
        self.write([
            {"file": "/c/a.c", "command": "cc " + " ".join(FLAGS) + " -c a.c"},
            {"file": "/c/b.cpp", "arguments": ["c++", *FLAGS, "-c", "b.cpp"]},
            {"file": "/c/x.s", "command": "as x.s"},
        ])
        self.assertEqual(hardening.compile_commands(str(self.dir), FLAGS), [])

    def test_a_source_without_a_flag_fails(self):
        self.write([
            {"file": "/c/a.c", "command": "cc " + " ".join(FLAGS) + " -c a.c"},
            {"file": "/c/b.c", "command": "cc -fstack-protector-strong -c b.c"},
            # A prefix of a flag isn't the flag.
            {"file": "/c/d.c", "command": "cc -D_FORTIFY_SOURCE=2 -fstack-protector-strong "
                                          "-fcf-protection=full -c d.c"},
        ])
        errors = hardening.compile_commands(str(self.dir), FLAGS)
        self.assertEqual(len(errors), 2)
        self.assertIn("/c/b.c: compiled without -D_FORTIFY_SOURCE=3 -fcf-protection=full", errors)

    def test_no_build_or_two_fail(self):
        self.assertIn("found 0", hardening.compile_commands(str(self.dir), FLAGS)[0])
        self.write([])
        (self.dir / "other").mkdir()
        (self.dir / "other/compile_commands.json").write_text("[]")
        self.assertIn("found 2", hardening.compile_commands(str(self.dir), FLAGS)[0])


class Symbols(unittest.TestCase):
    LINUX = (
        "0000000000000000      DF *UND*  0000000000000000 (GLIBC_2.4)  __stack_chk_fail\n"
        "0000000000000000      DF *UND*  0000000000000000 (GLIBC_2.3.4) __memcpy_chk\n"
    )
    MACOS = "                 U ___memcpy_chk\n                 U ___stack_chk_fail\n"

    def test_linux_and_macos_listings_pass(self):
        self.assertEqual(hardening.symbols(self.LINUX), [])
        self.assertEqual(hardening.symbols(self.MACOS), [])

    def test_a_missing_check_fails(self):
        self.assertEqual(len(hardening.symbols("U _memcpy\n")), 2)
        only_stack = hardening.symbols("U ___stack_chk_fail\n")
        self.assertEqual(only_stack, ["no __*_chk call: _FORTIFY_SOURCE is off"])
        only_fortify = hardening.symbols("U __memcpy_chk\n")
        self.assertEqual(only_fortify, ["no call to __stack_chk_fail: the stack protector is off"])


class Pe(unittest.TestCase):
    def test_control_flow_guard_passes(self):
        self.assertEqual(hardening.pe(pe_image()), [])

    def test_a_missing_flag_or_instrumentation_fails(self):
        self.assertEqual(hardening.pe(pe_image(guard_cf=False)),
                         ["the PE header has no GUARD_CF flag"])
        self.assertEqual(hardening.pe(pe_image(instrumented=False)),
                         ["the load configuration's guard flags lack CF_INSTRUMENTED"])
        self.assertEqual(hardening.pe(b"MZ" + bytes(10)), ["truncated PE image"])
        self.assertEqual(hardening.pe(bytes(0x40) + b"XX"), ["not a PE image"])


if __name__ == "__main__":
    unittest.main()
