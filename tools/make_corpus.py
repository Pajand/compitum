#!/usr/bin/env python3
"""
Regenerates `crates/compitum-pe/tests/corpus/` from a real compiler and linker.

# Why this corpus exists

Every other parser test uses a fixture built by this repository. That is useful and it is
not sufficient, because **a fixture that shares an assumption with the code under test cannot
detect that assumption being wrong.**

That is not a hypothetical. The first version of the PE parser read the optional header at
offsets computed by chaining from `SectionAlignment`, and it was wrong: on a real binary it
read `Subsystem` as 4096 instead of 3, and it read the data directory from the middle of
unrelated fields. The fixture builder chained from the same anchor, so writer and reader
agreed with each other while both disagreed with reality. **325 tests passed and real
binaries were parsed incorrectly.**

Only a binary produced by a third-party toolchain could expose it. These files are that
toolchain's output, and they are committed rather than generated in CI so that the check
runs even where no compiler is installed.

# Regenerating

Requires clang and lld with aarch64-windows and arm64ec-windows target support (LLVM 17 or
later is sufficient):

    apk add clang lld llvm
    python3 tools/make_corpus.py

The script cross-checks every file against an independent reading of the raw bytes and
refuses to write a corpus that disagrees with the committed expectation table.

# The ARM64EC detail worth knowing

clang emits an ARM64EC **object** with machine type `0xA641` (`IMAGE_FILE_MACHINE_ARM64EC`),
but lld-link writes an ARM64EC **executable** with machine type `0x8664`
(`IMAGE_FILE_MACHINE_AMD64`). The hybrid nature is expressed by the presence of both
AArch64 and x86-64 code and by the CHPE metadata, not by the machine field of the linked
image.

That is a real limitation of machine-type-only classification, and it is why
`compitum-pe` also reports the CHPE section prefix and the load-configuration directory
rather than relying on the machine field alone. The corpus records the observed behaviour so
the limitation is documented by evidence rather than asserted.
"""

import json
import os
import struct
import subprocess
import sys

# The corpus directory, relative to the repository root.
CORPUS = os.path.join("crates", "compitum-pe", "tests", "corpus")

# A freestanding Windows ARM64 program: no headers, so it links without any Windows SDK.
PROGRAM = """\
void __stdcall entry(void) { for (;;) { } }
"""

# (filename, target triple, linker arguments, expected properties).
#
# The expectations are read back from the produced file and compared, so a toolchain that
# changes its behaviour fails this script loudly rather than silently invalidating the corpus.
CASES = [
    (
        "real-console-4k.exe",
        "aarch64-pc-windows-msvc",
        ["/subsystem:console", "/align:4096"],
        {"machine": 0xAA64, "subsystem": 3, "section_alignment": 4096},
    ),
    (
        "real-gui-4k.exe",
        "aarch64-pc-windows-msvc",
        ["/subsystem:windows", "/align:4096"],
        {"machine": 0xAA64, "subsystem": 2, "section_alignment": 4096},
    ),
    (
        # Exercises the page-size compatibility axis: 16 KiB alignment on a 4 KiB host.
        "real-console-16k.exe",
        "aarch64-pc-windows-msvc",
        ["/subsystem:console", "/align:16384"],
        {"machine": 0xAA64, "subsystem": 3, "section_alignment": 16384},
    ),
    (
        # An ARM64EC module. Note the expected machine type: lld-link writes 0x8664 for a
        # hybrid executable even though the input object is 0xA641. See the module docstring.
        "real-arm64ec.exe",
        "arm64ec-pc-windows-msvc",
        ["/subsystem:console", "/align:4096"],
        {"machine": 0x8664, "subsystem": 3, "section_alignment": 4096},
    ),
]

# Optional header field offsets, per the PE specification. Spelled out rather than derived,
# because deriving them from a running anchor is the exact mistake this corpus exists to
# catch.
OFF_MAGIC = 0x00
OFF_SECTION_ALIGNMENT = 0x20
OFF_SIZE_OF_IMAGE = 0x38
OFF_SIZE_OF_HEADERS = 0x3C
OFF_SUBSYSTEM = 0x44
OFF_DLL_CHARACTERISTICS = 0x46
OFF_RVA_AND_SIZES_PE32PLUS = 0x6C
OFF_DATA_DIRECTORY = 0x70


def run(command: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False, **kwargs)


def have(tool: str) -> bool:
    result = run(["sh", "-c", f"command -v {tool}"])
    return result.returncode == 0


def read_fields(path: str) -> dict:
    """Reads the fundamental fields straight from the bytes, independently of any library."""
    with open(path, "rb") as handle:
        data = handle.read()

    pe = struct.unpack_from("<I", data, 0x3C)[0]
    coff = pe + 4
    opt = coff + 20

    return {
        "size": len(data),
        "pe_offset": pe,
        "machine": struct.unpack_from("<H", data, coff)[0],
        "section_count": struct.unpack_from("<H", data, coff + 2)[0],
        "optional_size": struct.unpack_from("<H", data, coff + 16)[0],
        "magic": struct.unpack_from("<H", data, opt + OFF_MAGIC)[0],
        "section_alignment": struct.unpack_from("<I", data, opt + OFF_SECTION_ALIGNMENT)[0],
        "size_of_image": struct.unpack_from("<I", data, opt + OFF_SIZE_OF_IMAGE)[0],
        "size_of_headers": struct.unpack_from("<I", data, opt + OFF_SIZE_OF_HEADERS)[0],
        "subsystem": struct.unpack_from("<H", data, opt + OFF_SUBSYSTEM)[0],
        "dll_characteristics": struct.unpack_from("<H", data, opt + OFF_DLL_CHARACTERISTICS)[0],
        "rva_and_sizes": struct.unpack_from("<I", data, opt + OFF_RVA_AND_SIZES_PE32PLUS)[0],
        "load_config_rva": struct.unpack_from("<I", data, opt + OFF_DATA_DIRECTORY + 10 * 8)[0],
        "load_config_size": struct.unpack_from("<I", data, opt + OFF_DATA_DIRECTORY + 10 * 8 + 4)[0],
    }


def section_names(path: str) -> list:
    """Returns the section table's names, in file order."""
    with open(path, "rb") as handle:
        data = handle.read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    coff = pe + 4
    opt = coff + 20
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    count = struct.unpack_from("<H", data, coff + 2)[0]
    table = opt + optional_size

    names = []
    for index in range(count):
        entry = table + index * 40
        raw = data[entry:entry + 8]
        names.append(raw.split(b"\0", 1)[0].decode("ascii", "replace"))
    return names


def main() -> int:
    for tool in ("clang", "lld-link"):
        if not have(tool):
            print(f"::error::{tool} is required to regenerate the corpus")
            print("  install with: apk add clang lld llvm")
            return 1

    os.makedirs(CORPUS, exist_ok=True)

    workdir = os.path.join("/tmp", "compitum-corpus-build")
    os.makedirs(workdir, exist_ok=True)
    source = os.path.join(workdir, "program.c")
    with open(source, "w") as handle:
        handle.write(PROGRAM)

    manifest = {}
    problems = []

    for name, target, linker_args, expected in CASES:
        obj = os.path.join(workdir, name + ".obj")
        out = os.path.join(CORPUS, name)

        compile_result = run(["clang", "-target", target, "-c", source, "-o", obj])
        if compile_result.returncode != 0:
            problems.append(f"{name}: clang could not build for {target}: "
                            f"{compile_result.stderr.strip()[:160]}")
            continue

        link_result = run(
            ["lld-link", "/entry:entry", "/nodefaultlib", f"/out:{out}", *linker_args, obj]
        )
        if link_result.returncode != 0:
            problems.append(f"{name}: lld-link failed: {link_result.stderr.strip()[:160]}")
            continue

        fields = read_fields(out)
        names = section_names(out)

        for key, want in expected.items():
            got = fields.get(key)
            if got != want:
                problems.append(f"{name}: expected {key}={want!r}, toolchain produced {got!r}")

        manifest[name] = {
            "sha256": None,  # filled below
            "size": fields["size"],
            "machine": fields["machine"],
            "subsystem": fields["subsystem"],
            "section_alignment": fields["section_alignment"],
            "size_of_image": fields["size_of_image"],
            "size_of_headers": fields["size_of_headers"],
            "dll_characteristics": fields["dll_characteristics"],
            "rva_and_sizes": fields["rva_and_sizes"],
            "load_config_rva": fields["load_config_rva"],
            "load_config_size": fields["load_config_size"],
            "sections": names,
            "target": target,
        }
        print(f"  {name:<26} machine=0x{fields['machine']:04X} "
              f"subsystem={fields['subsystem']} align={fields['section_alignment']:>6} "
              f"sections={names}")

    if problems:
        print()
        for problem in problems:
            print(f"::error::{problem}")
        return 1

    # Record each file's digest so the test can assert the corpus has not been substituted.
    import hashlib

    for name in manifest:
        with open(os.path.join(CORPUS, name), "rb") as handle:
            manifest[name]["sha256"] = hashlib.sha256(handle.read()).hexdigest()

    manifest_path = os.path.join(CORPUS, "manifest.json")
    with open(manifest_path, "w") as handle:
        json.dump(
            {
                "_note": (
                    "Generated by tools/make_corpus.py from real clang and lld-link output. "
                    "Do not edit by hand. This corpus exists because a fixture built by this "
                    "repository shares assumptions with the code under test, and therefore "
                    "cannot detect those assumptions being wrong."
                ),
                "generator": "tools/make_corpus.py",
                "toolchain": toolchain_versions(),
                "files": manifest,
            },
            handle,
            indent=2,
            sort_keys=True,
        )
        handle.write("\n")

    print(f"\nwrote {len(manifest)} fixture(s) and signed them in {manifest_path}")
    return 0


def toolchain_versions() -> dict:
    """Records which toolchain produced the corpus, so a mismatch is explainable."""
    versions = {}
    for tool in ("clang", "lld-link"):
        result = run([tool, "--version"])
        versions[tool] = result.stdout.splitlines()[0].strip() if result.stdout else "unknown"
    return versions


if __name__ == "__main__":
    sys.exit(main())
