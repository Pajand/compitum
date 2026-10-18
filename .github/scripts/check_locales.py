#!/usr/bin/env python3
"""
Verifies that every shipped translation catalog is usable.

A locale is a data file, so it can be checked without a human reading it. What matters:

* It parses, and reports its own coverage.
* It has no *obsolete* keys, which means a translation that has fallen behind the English
  base. Those are dead weight that mislead the next translator.
* Its coverage is tracked, so progress is visible in the build log.

Missing keys are permitted by design: a partially finished translation must still be usable,
falling back to English per key. Only obsolete keys fail the build.

Usage:

    python3 .github/scripts/check_locales.py ./target/release/compitum
"""

import glob
import json
import os
import subprocess
import sys


def run(binary: str, *args: str) -> tuple[int, str]:
    """Runs the CLI and returns (exit code, stdout)."""
    result = subprocess.run(
        [binary, *args], capture_output=True, text=True, check=False
    )
    return result.returncode, result.stdout


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_locales.py <path-to-compitum-binary>")
        return 1

    binary = sys.argv[1]
    if not os.path.exists(binary):
        print(f"::error::the CLI was not found at {binary}")
        return 1

    files = sorted(glob.glob("locales/*.json"))
    if not files:
        # Not a failure. The English base is compiled into the binary, so the tool is fully
        # functional with no external files at all; that is the documented design.
        print("no locales/ directory yet; only the compiled-in English base is present")
        code, out = run(binary, "locales", "list", "--json")
        if code != 0:
            print("::error::`locales list` failed even with no locale files present")
            print(out)
            return 1
        print("`locales list` succeeded with the English base only")
        return 0

    problems = []
    for path in files:
        tag = os.path.basename(path)[:-len(".json")]
        code, out = run(binary, "locales", "check", tag, "--json")
        if code != 0:
            problems.append(f"{tag}: `locales check` exited {code}")
            continue
        try:
            report = json.loads(out)
        except json.JSONDecodeError as error:
            problems.append(f"{tag}: the report is not valid JSON ({error})")
            continue

        coverage = report.get("coverage_percent", 0)
        missing = report.get("missing_count", 0)
        obsolete = report.get("obsolete_count", 0)
        print(f"{tag}: coverage {coverage}%  missing {missing}  obsolete {obsolete}")

        # A translation with no keys at all is almost certainly a mistake rather than a
        # work-in-progress, because a contributor who starts work translates something.
        if coverage == 0:
            problems.append(f"{tag}: covers 0% of the base, which suggests an empty file")

        if obsolete:
            keys = ", ".join(report.get("obsolete_keys", [])[:5])
            problems.append(
                f"{tag}: {obsolete} obsolete key(s) no longer in the English base: {keys}"
            )

    if problems:
        print()
        for problem in problems:
            print(f"::error::{problem}")
        return 1

    print(f"OK: {len(files)} catalog(s) validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
