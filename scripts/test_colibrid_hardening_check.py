"""colibrid-hardening-check.py: a build whose sources all carry the flags
passes, one without them fails; so does blst's recorded build, and a
Visual Studio project without Control Flow Guard or with /GS off; a binary that calls the stack protector's
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


class Blst(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_blst_with_every_flag_passes_and_without_one_fails(self):
        (self.dir / "build").mkdir()
        flags = self.dir / "build/blst-build-flags.txt"
        flags.write_text("-fPIC -ffunction-sections " + " ".join(FLAGS) + "\n")
        self.assertEqual(hardening.blst(str(self.dir), FLAGS), [])
        flags.write_text("-fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=3\n")
        self.assertEqual(hardening.blst(str(self.dir), FLAGS),
                         ["blst: built without -fcf-protection=full"])

    def test_no_record_fails(self):
        self.assertIn("found 0", hardening.blst(str(self.dir), FLAGS)[0])


def project(release, compiles=True):
    """A Visual Studio project with Debug and Release compile settings."""
    sources = '<ItemGroup><ClCompile Include="a.c" /></ItemGroup>' if compiles else ""
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        "<ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='Debug|x64'\">"
        "<ClCompile><BufferSecurityCheck>false</BufferSecurityCheck></ClCompile>"
        "</ItemDefinitionGroup>"
        "<ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\">"
        f"<ClCompile>{release}</ClCompile></ItemDefinitionGroup>{sources}</Project>"
    )


class Vcxproj(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        (self.dir / "src").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        (self.dir / "src" / name).write_text(text)

    def test_guarded_projects_pass(self):
        self.write("util.vcxproj", project("<ControlFlowGuard>Guard</ControlFlowGuard>"))
        # Projects that compile nothing (ALL_BUILD, custom targets) are skipped.
        self.write("ALL_BUILD.vcxproj", project("", compiles=False))
        self.assertEqual(hardening.vcxproj(str(self.dir)), [])

    def test_cmakes_own_projects_are_skipped(self):
        self.write("util.vcxproj", project("<ControlFlowGuard>Guard</ControlFlowGuard>"))
        # CMake's compiler identification: compiles, Debug alone.
        ident = self.dir / "CMakeFiles/3.31.6/CompilerIdC"
        ident.mkdir(parents=True)
        (ident / "CompilerIdC.vcxproj").write_text(
            '<?xml version="1.0" encoding="utf-8"?>'
            '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
            "<ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='Debug|x64'\">"
            "<ClCompile /></ItemDefinitionGroup>"
            '<ItemGroup><ClCompile Include="CMakeCCompilerId.c" /></ItemGroup></Project>'
        )
        self.assertEqual(hardening.vcxproj(str(self.dir)), [])

    def test_a_product_project_without_release_settings_fails(self):
        self.write("util.vcxproj", project("").replace("'Release|x64'", "'Debug|Win32'"))
        self.assertEqual(hardening.vcxproj(str(self.dir)),
                         ["src/util.vcxproj: no Release compile settings"])

    def test_an_unguarded_project_or_gs_off_fails(self):
        self.write("util.vcxproj", project(""))
        self.write("api.vcxproj", project(
            "<ControlFlowGuard>Guard</ControlFlowGuard><BufferSecurityCheck>false</BufferSecurityCheck>"
        ))
        errors = hardening.vcxproj(str(self.dir))
        self.assertEqual(sorted(errors), [
            "src/api.vcxproj: compiled with /GS off",
            "src/util.vcxproj: compiled without Control Flow Guard (unset)",
        ])

    def test_no_compiling_project_fails(self):
        self.write("ALL_BUILD.vcxproj", project("", compiles=False))
        self.assertIn("no project compiles", hardening.vcxproj(str(self.dir))[0])


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
