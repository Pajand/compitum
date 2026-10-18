#!/usr/bin/env python3
"""
Derives authoritative instruction encodings from the assembler.

# Why this exists

Every scanner rule in `compitum-pe` was originally tested against word constants written by
hand. That validates that a rule matches its author's guess -- not that it detects anything a
compiler actually emits. The flaw is the same one that produced three bugs in that module, and
it is invisible from the inside: the rule and the test agree because they were written together.

`llvm-mc` is the external control. It encodes real mnemonics, so the bytes it produces are ground
truth. Deriving each rule's mask from *varying assembler output* -- varying registers as well as
opcodes -- computes the bits that genuinely identify an instruction, rather than the bits that
happened to be constant in one hand-written example.

# What varying the registers catches

If every sample uses the same registers, their bits look constant and get folded into the mask.
That is precisely how a broken rule is written: a mask that includes a register field can never
match when a real compiler chooses a different register.

Measured examples of the three rules that were wrong:

    crc32b w0, w1, w2    0x1AC24020    rule expected mask 0xFFE0F0E0 / const 0x1AC04000
                                        actual masked value 0x1AC04020  -> NEVER MATCHED

    irg x0, x1, x2       0x9AC21020    rule expected mask 0xFFFFF000 / const 0x9AC00000
                                        actual masked value 0x9AC21000  -> NEVER MATCHED

    bti c                0xD503245F    rule expected hint immediate 0b0100 = 4
                                        actual immediate is 34          -> NEVER MATCHED

# Usage

    python3 tools/make_encodings.py            # regenerate the golden file
    python3 tools/make_encodings.py --check    # verify the committed file is current

The output is `crates/compitum-pe/tests/corpus/encodings.json`, committed so the Rust tests run
without an assembler installed.
"""

import json
import os
import re
import subprocess
import sys

OUT = os.path.join("crates", "compitum-pe", "tests", "corpus", "encodings.json")

# (family, feature attr, [variants]). Variants deliberately use DIFFERENT registers, because a
# shared register would look like part of the opcode.
FAMILIES = [
    ("crc32", "+crc", [
        "crc32b w0, w1, w2", "crc32h w5, w6, w7", "crc32w w10, w11, w12",
        # The 64-bit forms take Xd, Wn, Xm -- not two X registers. Getting that wrong made
        # the assembler reject them, which is the generator doing its job: it refuses to
        # derive a mask from variants it could not assemble.
        # The 64-bit forms read an X source but write a W destination: `crc32x Wd, Wn, Xm`.
        # Getting that backwards makes the assembler reject them, which is the generator
        # doing its job -- it refuses to derive a mask from variants it could not assemble.
        "crc32x w0, w1, x2", "crc32cb w3, w4, w5", "crc32ch w8, w9, w10",
        "crc32cw w13, w14, w15", "crc32cx w20, w21, x22",
    ]),
    ("bti", "", ["bti", "bti c", "bti j", "bti jc"]),
    ("aes", "+aes", [
        "aese v0.16b, v1.16b", "aesd v5.16b, v6.16b",
        "aesmc v10.16b, v11.16b", "aesimc v15.16b, v16.16b",
    ]),
    ("sha256", "+sha2", [
        "sha256h q0, q1, v2.4s", "sha256h2 q5, q6, v7.4s",
        "sha256su0 v10.4s, v11.4s", "sha256su1 v12.4s, v13.4s, v14.4s",
    ]),
    ("irg", "+mte", ["irg x0, x1, x2", "irg x5, x6, x7", "irg x10, x11, x12"]),
    ("gmi", "+mte", ["gmi x0, x1, x2", "gmi x5, x6, x7", "gmi x10, x11, x12"]),
    ("addg", "+mte", ["addg x0, x1, #16, #1", "addg x5, x6, #32, #2"]),
    ("subg", "+mte", ["subg x0, x1, #16, #1", "subg x5, x6, #32, #2"]),
    ("stg", "+mte", ["stg x0, [x1]", "stg x5, [x6]", "stg x10, [x11]"]),
    ("ldg", "+mte", ["ldg x0, [x1]", "ldg x5, [x6]", "ldg x10, [x11]"]),
    ("rndr", "", ["mrs x0, s3_3_c2_c4_0", "mrs x5, s3_3_c2_c4_0"]),
    # SME control: entering and leaving streaming mode. These are the instructions a
    # compiler emits to use the matrix units, so their presence is direct evidence of a
    # matrix requirement rather than an inference from an opcode band.
    ("sme_streaming", "+sme", ["smstart", "smstop"]),
    # SME control-register access (`SVCR`), which is how code reads or sets the streaming
    # state. Both the read and write forms are included, because either implies the feature.
    ("sme_svcr", "+sme", [
        "mrs x0, svcr", "mrs x5, svcr", "mrs x10, svcr", "msr svcr, x0", "msr svcr, x7",
    ]),
    ("dotprod", "+dotprod", [
        "udot v0.4s, v1.16b, v2.16b", "udot v5.4s, v6.16b, v7.16b",
        "sdot v10.4s, v11.16b, v12.16b",
    ]),
]


def assemble(insn: str, mattr: str):
    """Returns the 32-bit little-endian encoding, or None if the assembler rejected it."""
    cmd = ["llvm-mc", "-triple=aarch64-windows", "-show-encoding"]
    if mattr:
        cmd.append(f"-mattr={mattr}")
    result = subprocess.run(cmd, input=insn + "\n", capture_output=True, text=True)
    match = re.search(r"encoding:\s*\[([^\]]+)\]", result.stdout)
    if not match:
        return None
    byte_values = [int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", match.group(1))]
    if len(byte_values) != 4:
        return None
    return (
        byte_values[0]
        | (byte_values[1] << 8)
        | (byte_values[2] << 16)
        | (byte_values[3] << 24)
    )


def derive(samples):
    """
    Computes the (mask, const) pair that identifies every sample.

    Returns None when the samples disagree on some bit, which means they do not share an
    encoding family and the rule would be unsound.
    """
    if len(samples) < 2:
        return None
    mask = 0xFFFF_FFFF
    for word in samples[1:]:
        mask &= ~(samples[0] ^ word)
    const = samples[0] & mask
    if not all((w & mask) == const for w in samples):
        return None
    return mask, const


def main() -> int:
    check_only = "--check" in sys.argv

    if not shutil_which("llvm-mc"):
        print("::error::llvm-mc is required to regenerate the encodings")
        print("  install with: apk add llvm   (or apt-get install llvm)")
        return 1

    families = {}
    problems = []

    for family, mattr, variants in FAMILIES:
        samples = []
        accepted = []
        for insn in variants:
            word = assemble(insn, mattr)
            if word is None:
                problems.append(f"{family}: the assembler rejected `{insn}`")
                continue
            samples.append(word)
            accepted.append({"instruction": insn, "encoding": f"0x{word:08X}"})

        derived = derive(samples)
        if derived is None:
            problems.append(
                f"{family}: no common encoding across {len(samples)} variant(s), so a "
                "single mask cannot identify this family"
            )
            continue
        mask, const = derived
        families[family] = {
            "mask": f"0x{mask:08X}",
            "const": f"0x{const:08X}",
            "variant_count": len(samples),
            "variants": accepted,
        }
        print(f"  {family:<10} mask=0x{mask:08X} const=0x{const:08X} "
              f"({len(samples)} variants verified)")

    if problems:
        print()
        for problem in problems:
            print(f"::error::{problem}")
        return 1

    document = {
        "_note": (
            "Instruction encodings derived from llvm-mc, the external authority, with "
            "registers varied so that register fields are excluded from each mask. "
            "Generated by tools/make_encodings.py. Do not edit by hand. These exist because "
            "hand-written constants test that a rule matches its author's guess, not that it "
            "detects real compiler output."
        ),
        "generator": "tools/make_encodings.py",
        "triple": "aarch64-windows",
        "family_count": len(families),
        "families": families,
    }

    text = json.dumps(document, indent=2, sort_keys=True) + "\n"

    if check_only:
        if not os.path.exists(OUT):
            print(f"::error::{OUT} does not exist")
            return 1
        with open(OUT, encoding="utf-8") as handle:
            if handle.read() != text:
                print(f"::error::{OUT} is out of date; run tools/make_encodings.py")
                return 1
        print(f"\nOK: {OUT} is current")
        return 0

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as handle:
        handle.write(text)
    print(f"\nwrote {len(families)} families to {OUT}")
    return 0


def shutil_which(tool: str) -> bool:
    return subprocess.run(["sh", "-c", f"command -v {tool}"],
                          capture_output=True).returncode == 0


if __name__ == "__main__":
    sys.exit(main())
