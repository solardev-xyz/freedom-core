#!/usr/bin/env python3
"""Design 0014's hardened build, checked on a freedom-colibrid release.

The release builds Colibri's C core with a stack protector,
_FORTIFY_SOURCE=3 and control-flow protection where the target has it
(release-colibrid.yml's `cflags`). This checks that the protections took:

  colibrid-hardening-check.py compile-commands <build dir> <flags>
      every C and C++ source CMake compiled under <build dir> (its
      compile_commands.json, exactly one) carries each of <flags>;

  colibrid-hardening-check.py blst <build dir> <flags>
      blst, which its own build script compiles outside CMake's compile
      commands, was built with each of <flags>: its blst-build-flags.txt
      (exactly one), which colibri-stateless's CMake records;

  colibrid-hardening-check.py vcxproj <build dir>
      on Windows, every Visual Studio project CMake generated that compiles
      C or C++ (outside CMakeFiles/, CMake's compiler identification and
      try-compiles) does so in its Release configuration with Control Flow Guard
      (ControlFlowGuard: Guard) and without turning /GS off
      (BufferSecurityCheck: false);

  colibrid-hardening-check.py symbols <symbol listing>
      the binary calls the stack protector's check (__stack_chk_fail) and
      _FORTIFY_SOURCE's (a __*_chk function): the listing is `objdump -T`'s
      (Linux) or `nm -u`'s (macOS);

  colibrid-hardening-check.py pe <exe>
      the Windows binary has Control Flow Guard: the PE header's GUARD_CF
      flag, and its load configuration's CF_INSTRUMENTED guard flag.
      /GS, the stack protector, is MSVC's default; Windows has no
      _FORTIFY_SOURCE.

The image-level checks (symbols, pe) can't tell which objects were
hardened; compile-commands, blst and vcxproj check each compile's flags.
"""

import glob
import json
import os
import pathlib
import re
import struct
import sys
import xml.etree.ElementTree as ET

IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
IMAGE_GUARD_CF_INSTRUMENTED = 0x100
LOAD_CONFIG_DIRECTORY = 10


def compile_commands(build_dir, flags):
    """Errors: sources CMake compiled without one of `flags`."""
    dbs = glob.glob(os.path.join(build_dir, "**", "compile_commands.json"), recursive=True)
    if len(dbs) != 1:
        return [f"{build_dir}: expected one compile_commands.json, found {len(dbs)}"]
    with open(dbs[0], encoding="utf-8") as f:
        entries = json.load(f)
    sources = [e for e in entries if e["file"].endswith((".c", ".cc", ".cpp"))]
    if not sources:
        return [f"{dbs[0]}: no C or C++ sources"]
    errors = []
    for entry in sources:
        command = entry.get("command") or " ".join(entry.get("arguments", []))
        words = command.split()
        missing = [flag for flag in flags if flag not in words]
        if missing:
            errors.append(f"{entry['file']}: compiled without {' '.join(missing)}")
    return errors


def blst(build_dir, flags):
    """Errors: blst built without one of `flags`."""
    files = glob.glob(os.path.join(build_dir, "**", "blst-build-flags.txt"), recursive=True)
    if len(files) != 1:
        return [f"{build_dir}: expected one blst-build-flags.txt, found {len(files)}"]
    with open(files[0], encoding="utf-8") as f:
        words = f.read().split()
    missing = [flag for flag in flags if flag not in words]
    return [f"blst: built without {' '.join(missing)}"] if missing else []


MSBUILD = "{http://schemas.microsoft.com/developer/msbuild/2003}"


def vcxproj(build_dir):
    """Errors: Visual Studio projects compiling without Control Flow Guard,
    or with /GS off, in their Release configuration."""
    # CMake's own projects under CMakeFiles/ (compiler identification,
    # try-compiles) build nothing that ships, and define Debug alone.
    projects = [
        path for path in glob.glob(os.path.join(build_dir, "**", "*.vcxproj"), recursive=True)
        if "CMakeFiles" not in pathlib.PurePath(os.path.relpath(path, build_dir)).parts
    ]
    errors = []
    compiling = 0
    for path in sorted(projects):
        root = ET.parse(path).getroot()
        if not root.findall(f".//{MSBUILD}ItemGroup/{MSBUILD}ClCompile"):
            continue
        compiling += 1
        releases = [
            group.find(f"{MSBUILD}ClCompile")
            for group in root.findall(f"{MSBUILD}ItemDefinitionGroup")
            if "'Release|" in (group.get("Condition") or "")
        ]
        releases = [r for r in releases if r is not None]
        name = os.path.relpath(path, build_dir)
        if not releases:
            errors.append(f"{name}: no Release compile settings")
            continue
        for settings in releases:
            guard = settings.findtext(f"{MSBUILD}ControlFlowGuard")
            if guard != "Guard":
                errors.append(f"{name}: compiled without Control Flow Guard ({guard or 'unset'})")
            if (settings.findtext(f"{MSBUILD}BufferSecurityCheck") or "").lower() == "false":
                errors.append(f"{name}: compiled with /GS off")
    if not compiling:
        errors.append(f"{build_dir}: no project compiles C or C++")
    return errors


def symbols(listing):
    """Errors: the stack protector's or _FORTIFY_SOURCE's checks not called."""
    names = set(re.findall(r"\b_?(__\w+)\b", listing))
    errors = []
    if "__stack_chk_fail" not in names:
        errors.append("no call to __stack_chk_fail: the stack protector is off")
    if not any(re.fullmatch(r"__\w+_chk", n) and n != "__stack_chk_fail" for n in names):
        errors.append("no __*_chk call: _FORTIFY_SOURCE is off")
    return errors


def pe(data):
    """Errors: Control Flow Guard missing from PE image `data`."""
    try:
        (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
        if data[pe_offset:pe_offset + 4] != b"PE\0\0":
            return ["not a PE image"]
        coff = pe_offset + 4
        sections, optional_size = struct.unpack_from("<H12xH", data, coff + 2)
        optional = coff + 20
        (magic,) = struct.unpack_from("<H", data, optional)
        if magic != 0x20B:
            return ["not a PE32+ image"]
        (characteristics,) = struct.unpack_from("<H", data, optional + 70)
        errors = []
        if not characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF:
            errors.append("the PE header has no GUARD_CF flag")
        directories = optional + 112
        rva, size = struct.unpack_from("<II", data, directories + 8 * LOAD_CONFIG_DIRECTORY)
        if not rva or size < 0x94:
            return errors + ["no load configuration with guard flags"]
        table = optional + optional_size
        for i in range(sections):
            entry = table + 40 * i
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, entry + 8
            )
            if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                load_config = raw_offset + rva - virtual_address
                break
        else:
            return errors + ["the load configuration is in no section"]
        (guard_flags,) = struct.unpack_from("<I", data, load_config + 0x90)
        if not guard_flags & IMAGE_GUARD_CF_INSTRUMENTED:
            errors.append("the load configuration's guard flags lack CF_INSTRUMENTED")
        return errors
    except struct.error:
        return ["truncated PE image"]


def main(argv):
    if len(argv) == 3 and argv[0] == "compile-commands":
        errors = compile_commands(argv[1], argv[2].split())
    elif len(argv) == 3 and argv[0] == "blst":
        errors = blst(argv[1], argv[2].split())
    elif len(argv) == 2 and argv[0] == "vcxproj":
        errors = vcxproj(argv[1])
    elif len(argv) == 2 and argv[0] == "symbols":
        with open(argv[1], encoding="utf-8", errors="replace") as f:
            errors = symbols(f.read())
    elif len(argv) == 2 and argv[0] == "pe":
        with open(argv[1], "rb") as f:
            errors = pe(f.read())
    else:
        print(__doc__, file=sys.stderr)
        return 64
    for error in errors:
        print(f"hardening: {error}", file=sys.stderr)
    if not errors:
        print(f"hardening: {argv[0]} passed")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
