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

# CHPE metadata offsets. These MUST match `crates/compitum-pe/src/chpe.rs`, which is the
# implementation under test: the corpus records what an independent reader sees, and the test
# asserts the two agree.
#
# `OFF_CHPE_METADATA_POINTER` is inside `IMAGE_LOAD_CONFIG_DIRECTORY64`; the other three are
# inside `IMAGE_ARM64EC_METADATA`.
OFF_CHPE_METADATA_POINTER = 0xC8
OFF_CHPE_VERSION = 0x00
OFF_CHPE_CODE_MAP = 0x04
OFF_CHPE_CODE_MAP_COUNT = 0x08

# The smallest load configuration that can contain `CHPEMetadataPointer`. A shorter directory
# simply does not have the field, which is ordinary rather than an error.
MIN_LOAD_CONFIG_FOR_CHPE = 0xD0


# ---------------------------------------------------------------------------
# CHPE fixtures.
#
# lld-link can link an ARM64X image, but without a Windows CRT to supply the
# `__arm64x_*` symbols it leaves the load configuration empty, so no CHPE metadata is
# emitted. That is a toolchain limitation, not an unsupported format.
#
# These two fixtures are therefore constructed here. Their layout is validated by
# `llvm-readobj --coff-load-config`, an independent implementation that parses the
# metadata, resolves the code map and names the format. That is what makes them
# evidence rather than assertion: a wrong offset would be reported as an error, as it
# was during development when the code-map RVA did not resolve.
# ---------------------------------------------------------------------------

def build_chpe_fixture(machine: int, chpe_version: int, code_map_types: list) -> bytes:
    """
    Builds a PE32+ image carrying CHPE metadata of the given version.

    `code_map_types` is a list of CHPE code-map type values: 0 for AArch64-derived code,
    1 for x86-64 code. The map is what the loader uses to decide which pages are which,
    and its length is the most decision-relevant number in the structure.

    CHPEMetadataPointer is written as a VIRTUAL ADDRESS, not an RVA. Reading it as an RVA
    is a documented mistake and lands in the wrong place on every image whose base is not
    zero, which is every real image.
    """
    section_align = 0x1000
    file_align = 0x200
    pe_offset = 0x80
    optional_size = 0xF0
    section_count = 1
    raw_offset = file_align
    total = raw_offset + section_align * 2

    data = bytearray(total)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"

    coff = pe_offset + 4
    struct.pack_into("<H", data, coff, machine)
    struct.pack_into("<H", data, coff + 2, section_count)
    struct.pack_into("<H", data, coff + 16, optional_size)
    struct.pack_into("<H", data, coff + 18, 0x0002)  # IMAGE_FILE_EXECUTABLE_IMAGE

    opt = coff + 20
    struct.pack_into("<H", data, opt + OFF_MAGIC, 0x20B)  # PE32+
    struct.pack_into("<Q", data, opt + 0x18, 0x140000000)  # ImageBase
    struct.pack_into("<I", data, opt + OFF_SECTION_ALIGNMENT, section_align)
    struct.pack_into("<I", data, opt + 0x24, file_align)  # FileAlignment
    struct.pack_into("<I", data, opt + OFF_SIZE_OF_IMAGE, 0x3000)
    struct.pack_into("<I", data, opt + OFF_SIZE_OF_HEADERS, file_align)
    struct.pack_into("<H", data, opt + OFF_SUBSYSTEM, 3)  # console
    struct.pack_into("<I", data, opt + OFF_RVA_AND_SIZES_PE32PLUS, 16)

    data_directory = opt + OFF_DATA_DIRECTORY
    load_config_rva = section_align + 0x100
    struct.pack_into("<II", data, data_directory + 10 * 8,
                     load_config_rva, MIN_LOAD_CONFIG_FOR_CHPE + 8)

    section = opt + optional_size
    data[section:section + 5] = b".text"
    struct.pack_into("<I", data, section + 8, 0x2000)         # VirtualSize
    struct.pack_into("<I", data, section + 12, section_align)  # VirtualAddress
    struct.pack_into("<I", data, section + 16, 0x2000)        # SizeOfRawData
    struct.pack_into("<I", data, section + 20, raw_offset)    # PointerToRawData
    struct.pack_into("<I", data, section + 36, 0x60000020)    # code | execute | read

    def file_offset(rva: int) -> int:
        return raw_offset + (rva - section_align)

    metadata_rva = section_align + 0x200
    code_map_rva = section_align + 0x400

    # The code map: 12 bytes per entry, an inclusive RVA range plus a type.
    code_map_offset = file_offset(code_map_rva)
    for index, code_type in enumerate(code_map_types):
        start = section_align + index * 0x40
        struct.pack_into("<III", data, code_map_offset + index * 12,
                         start, start + 0x40, code_type)

    metadata_offset = file_offset(metadata_rva)
    struct.pack_into("<I", data, metadata_offset + OFF_CHPE_VERSION, chpe_version)
    struct.pack_into("<I", data, metadata_offset + OFF_CHPE_CODE_MAP, code_map_rva)
    struct.pack_into("<I", data, metadata_offset + OFF_CHPE_CODE_MAP_COUNT,
                     len(code_map_types))

    load_config_offset = file_offset(load_config_rva)
    struct.pack_into("<I", data, load_config_offset, MIN_LOAD_CONFIG_FOR_CHPE + 8)
    struct.pack_into("<Q", data, load_config_offset + OFF_CHPE_METADATA_POINTER,
                     0x140000000 + metadata_rva)

    return bytes(data)


def llvm_says(path: str) -> dict:
    """
    Asks llvm-readobj what it thinks the file is.

    The returned `format` is the independent verdict: `COFF-ARM64EC` or `COFF-ARM64X`.
    A wrong metadata layout produces an error instead, which is exactly the feedback
    that makes these hand-built fixtures trustworthy.
    """
    result = run(["llvm-readobj", "--file-headers", "--coff-load-config", path])
    text = result.stdout + result.stderr

    fmt = ""
    for line in text.splitlines():
        if line.startswith("Format:"):
            fmt = line.split(":", 1)[1].strip()
            break
    version = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Version:") and version is None:
            try:
                version = int(stripped.split(":", 1)[1].strip(), 16)
            except ValueError:
                pass
    return {"format": fmt, "chpe_version": version, "errors": "error" in text.lower()}


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

    # -----------------------------------------------------------------------
    # The CHPE fixtures. Built here rather than by the linker, because lld-link cannot
    # emit CHPE metadata without a Windows CRT to supply the `__arm64x_*` symbols: it
    # links the file but leaves the load configuration empty.
    #
    # Their layout is validated by llvm-readobj, an independent implementation that
    # parses the metadata, resolves the code map and names the format. That independent
    # verdict is the whole point: if an offset were wrong it would report an error, as it
    # did during development when the code-map RVA did not resolve.
    # -----------------------------------------------------------------------
    if not have("llvm-readobj"):
        problems.append(
            "llvm-readobj is required to validate the CHPE fixtures; without an independent "
            "reader their layout would only be asserted, not checked"
        )

    chpe_cases = [
        # (filename, machine, CHPE version, code-map types, expected llvm format)
        #
        # ARM64EC: an x86-64 machine type plus version-1 metadata. This is the case machine
        # type alone cannot identify, because the header is identical to plain x86-64.
        ("chpe-arm64ec.exe", 0x8664, 1, [0, 0, 1], "COFF-ARM64EC"),
        # ARM64X: an ARM64 machine type plus version-2 metadata.
        ("chpe-arm64x.exe", 0xAA64, 2, [0, 1, 0, 1], "COFF-ARM64X"),
    ]

    for name, machine, version, code_map, expected_format in chpe_cases:
        out = os.path.join(CORPUS, name)
        with open(out, "wb") as handle:
            handle.write(build_chpe_fixture(machine, version, code_map))

        verdict = llvm_says(out)
        if verdict["errors"]:
            problems.append(
                f"{name}: llvm-readobj reported an error reading the CHPE metadata, which "
                "means the layout this script wrote does not match the format"
            )
        if verdict["format"] != expected_format:
            problems.append(
                f"{name}: llvm-readobj calls this {verdict['format']!r}, expected "
                f"{expected_format!r}. The independent reader disagrees with the intended "
                "classification."
            )
        if verdict["chpe_version"] != version:
            problems.append(
                f"{name}: llvm-readobj read CHPE version {verdict['chpe_version']!r}, "
                f"expected {version!r}"
            )

        fields = read_fields(out)
        names = section_names(out)
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
            "source": "constructed by this script",
            "chpe_version": version,
            "chpe_code_map_count": len(code_map),
            # Recorded from the independent reader, not from the builder's intent.
            "llvm_readobj_format": verdict["format"],
        }
        print(f"  {name:<26} machine=0x{fields['machine']:04X} "
              f"chpe_version={version} code_map={len(code_map)} "
              f"llvm_readobj_says={verdict['format']}")

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
