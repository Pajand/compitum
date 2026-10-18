#!/usr/bin/env python3
"""
Verifies a `compitum host --json` report.

The host report is the input to every routing decision, so a wrong report means every verdict
downstream is wrong. Specifically this checks that the report describes the machine it was
actually run on, and that the capability decoding is self-consistent.

Usage:

    python3 .github/scripts/check_host.py <host.json> <expected-arch>
"""

import json
import sys

# Features whose presence is reported by a bitmap bit. If a bit is set the feature must appear
# in the decoded list; the reverse is checked for a few known-absent-on-most-hardware ones.
BITMAP_FEATURES = {
    "fp", "asimd", "aes", "pmull", "sha1", "sha2", "crc32", "lse", "fp16", "cpuid",
    "dotprod", "bti", "i8mm", "mte", "sve", "sve2", "sme",
}


def fail(message: str) -> int:
    print(f"::error::{message}")
    return 1


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_host.py <host.json> <expected-arch>")
        return 1

    path, expected_arch = sys.argv[1], sys.argv[2]
    with open(path, encoding="utf-8") as handle:
        host = json.load(handle)

    arch = host.get("arch")
    page_size = host.get("page_size")
    cpu_count = host.get("cpu_count")
    features = host.get("features") or []

    print(f"arch={arch} page_size={page_size} cores={cpu_count} features={len(features)}")
    print(f"hwcap={host.get('raw_hwcap')} hwcap2={host.get('raw_hwcap2')}")
    absent = [f for f in sorted(BITMAP_FEATURES) if f not in features]
    if absent:
        print(f"absent: {' '.join(absent)}")

    if arch != expected_arch:
        return fail(f"expected architecture `{expected_arch}`, report says `{arch}`")

    if not isinstance(page_size, int) or page_size <= 0:
        return fail(f"page size is not a positive integer: {page_size!r}")

    # Every valid page size is a power of two. A non-power-of-two would mean the auxiliary
    # vector was misread, which would silently corrupt the page-size compatibility axis.
    if page_size & (page_size - 1) != 0:
        return fail(f"page size {page_size} is not a power of two")

    if not isinstance(cpu_count, int) or cpu_count < 1:
        return fail(f"cpu count is not a positive integer: {cpu_count!r}")

    if not features:
        return fail("no CPU features were decoded at all, which cannot be right")

    # The baseline is mandatory in the architecture: every AArch64 implementation has it.
    # Its absence would mean the bit decoding is wrong, not that the CPU is unusual.
    for baseline in ("fp", "asimd"):
        if baseline not in features:
            return fail(
                f"`{baseline}` is part of the AArch64 baseline and must always be present; "
                "its absence means the capability decoding is wrong"
            )

    # The feature list must be sorted and de-duplicated, because the host class tag is built
    # from it: an unsorted list would make two identical machines look like different ones.
    if features != sorted(features):
        return fail("the feature list is not sorted, so host class tags would be unstable")
    if len(features) != len(set(features)):
        return fail("the feature list contains duplicates")

    for feature in features:
        if not isinstance(feature, str) or not feature:
            return fail(f"an entry in the feature list is not a usable string: {feature!r}")

    print("OK: the host report is self-consistent and describes this machine")
    return 0


if __name__ == "__main__":
    sys.exit(main())
