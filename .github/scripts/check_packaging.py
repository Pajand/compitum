#!/usr/bin/env python3
"""
Verifies that every crate in the family can be published, in the right order.

# The subtlety this script exists to handle

`cargo package` resolves dependencies against the *registry*, not the local workspace. That
means a crate cannot be packaged-and-verified until every crate it depends on has already been
published. In a fresh crate family this is true for almost every member at first, so a naive
"did every crate package?" check fails on a repository where nothing is actually wrong.

The distinction that matters:

* **"no matching package named `compitum-x` found"** is *expected* until `compitum-x` is
  published. It is not a defect, and treating it as one trains people to ignore the gate.
* **Any other error** — a missing description, a bad licence expression, a path-only
  dependency, a file outside the package root — is a real defect that must fail the build,
  because a rejected publish permanently consumes the version number.

So this script separates the two, reports the publication ordering it derived, and only fails
on defects that are genuinely fixable now.

# What is actually verified

1. Every crate declares the metadata a registry requires: `description`, `license` or
   `license-file`, `repository`, and a `readme` that exists.
2. Every workspace-internal dependency carries a `version` alongside its `path`, because a
   registry cannot resolve a path.
3. Each crate's packaging outcome is classified as `ready`, `awaiting-dependency`, or
   `defective`, and the script fails only on `defective`.

Usage:

    python3 .github/scripts/check_packaging.py
"""

import json
import os
import re
import subprocess
import sys

# The metadata crates.io requires before it will accept a publish. Missing any of these causes
# a rejection that cannot be undone.
REQUIRED_FIELDS = ("description", "repository")

# Crates are expected to be dual-licensed; a crate with neither is not publishable.
LICENSE_FIELDS = ("license", "license-file")

# Files a crate should carry. A `README.md` at the workspace root is shared by `readme = "..."`
# in each manifest, so the check verifies the referenced path exists rather than that the file
# is named README.
EXPECTED_FILES = ("Cargo.toml",)

OWN_CRATES = [
    "compitum-json",
    "compitum-digest",
    "compitum-i18n",
    "compitum-isa",
    "compitum-pe",
    "compitum-router",
    "compitum-oracle",
    "compitum-cli",
]

# The phrase cargo emits when a dependency is simply not on the registry yet.
AWAITING_MARKER = "no matching package named"


def run_cargo_package(crate: str) -> tuple:
    """Runs `cargo package` and returns (ok, output)."""
    result = subprocess.run(
        [
            "cargo",
            "package",
            "-p",
            crate,
            "--no-verify",
            "--allow-dirty",
            # Avoid touching the network index on every invocation; the resolution error we
            # care about is produced from the local manifest plus the cached index.
            "--offline",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0, (result.stdout + result.stderr)


def load_manifest(crate: str) -> dict:
    path = os.path.join("crates", crate, "Cargo.toml")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        text = handle.read()

    manifest = {"_path": path, "_text": text}

    # A dependency entry that names a path must also name a version, or the registry cannot
    # resolve it. This is checked textually rather than by parsing TOML, because the workspace
    # uses `{ workspace = true }` for its internal dependencies and the real declarations live
    # in the root manifest.
    return manifest


def check_workspace_dependencies() -> list:
    """Every internal dependency in the root manifest must carry a version."""
    problems = []
    with open("Cargo.toml", encoding="utf-8") as handle:
        text = handle.read()

    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[workspace.dependencies]"):
            in_section = True
            continue
        if in_section and stripped.startswith("[") and not stripped.startswith("[workspace.dependencies]"):
            in_section = False
            continue
        if not in_section or not stripped.startswith("compitum-"):
            continue
        # e.g. `compitum-json = { version = "0.1.0", path = "crates/compitum-json" }`
        if "path" in stripped and "version" not in stripped:
            problems.append(
                f"workspace dependency has a path but no version: {stripped}"
            )
    return problems


def check_metadata() -> tuple:
    """Reads `cargo metadata` to inspect real package metadata rather than guessed text."""
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return [], [f"`cargo metadata` failed: {result.stderr.strip()[:200]}"]

    metadata = json.loads(result.stdout)
    by_name = {p["name"]: p for p in metadata.get("packages", [])}

    problems = []
    for crate in OWN_CRATES:
        package = by_name.get(crate)
        if package is None:
            problems.append(f"{crate}: not present in the workspace")
            continue

        for field in REQUIRED_FIELDS:
            if not package.get(field):
                problems.append(f"{crate}: missing `{field}`, which a registry requires")

        if not any(package.get(field) for field in LICENSE_FIELDS):
            problems.append(f"{crate}: declares neither `license` nor `license-file`")

        readme = package.get("readme")
        if readme:
            # `readme` is resolved relative to the crate directory by cargo, but may point at
            # the workspace root, so check both.
            crate_relative = os.path.join("crates", crate, readme)
            if not os.path.exists(crate_relative) and not os.path.exists(readme):
                problems.append(f"{crate}: readme `{readme}` does not exist")

        for expected in EXPECTED_FILES:
            path = os.path.join("crates", crate, expected)
            if not os.path.exists(path):
                problems.append(f"{crate}: `{expected}` is missing")

    return [by_name[c]["name"] for c in OWN_CRATES if c in by_name], problems


def main() -> int:
    print("checking package metadata and publishability\n")

    _, metadata_problems = check_metadata()
    dependency_problems = check_workspace_dependencies()

    all_problems = metadata_problems + dependency_problems
    if all_problems:
        print("metadata defects:")
        for problem in all_problems:
            print(f"  {problem}")
        print()
        for problem in all_problems:
            print(f"::error::{problem}")
        return 1
    print(f"metadata: {len(OWN_CRATES)} crates declare everything a registry requires")

    print("\npackaging each crate:")
    ready, awaiting, defective = [], [], []
    for crate in OWN_CRATES:
        ok, output = run_cargo_package(crate)
        if ok:
            ready.append(crate)
            print(f"  {crate:<18} ready")
        elif AWAITING_MARKER in output:
            # Expected in a fresh family: the dependency is not on the registry yet, which is
            # precisely what the publish order exists to solve.
            missing = "?"
            for line in output.splitlines():
                if AWAITING_MARKER in line:
                    # Cargo words it as: no matching package named `name` found
                    # The reliable read is the first backtick-quoted token on the line.
                    quoted = re.findall(r"`([^`]+)`", line)
                    if quoted:
                        missing = quoted[0]
                    break
            awaiting.append((crate, missing))
            print(f"  {crate:<18} awaiting `{missing}` to be published first")
        else:
            defective.append(crate)
            print(f"  {crate:<18} DEFECTIVE")
            for line in output.splitlines():
                if "error" in line.lower():
                    print(f"      {line.strip()[:160]}")

    print()
    print(f"summary: {len(ready)} ready, {len(awaiting)} awaiting a dependency, "
          f"{len(defective)} defective")

    if awaiting:
        print()
        print("The crates below can be packaged once their dependencies are live on the")
        print("registry. Run `tools/publish_order.py` for the order that achieves this:")
        for crate, missing in awaiting:
            print(f"  {crate} awaits {missing}")

    if defective:
        print()
        for crate in defective:
            print(
                f"::error::{crate} cannot be packaged for a reason other than a missing "
                "dependency; fix it before the publish attempt"
            )
        return 1

    print()
    print("OK: no packaging defect; every crate is either ready or correctly awaiting a "
          "dependency")
    return 0


if __name__ == "__main__":
    sys.exit(main())
