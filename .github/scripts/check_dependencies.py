#!/usr/bin/env python3
"""
Fails the build if any third-party crate entered the dependency graph.

COMPITUM's doctrine forbids external dependencies in the core: the workspace must build
offline and stay trivially auditable. That rule is easy to state and easy to break by
accident, because adding a dependency is a one-line change that looks harmless. This script
turns the rule into a build failure.

Run locally:

    cargo metadata --format-version 1 | python3 .github/scripts/check_dependencies.py
"""

import json
import sys

# Every package this workspace is allowed to resolve to. Listed explicitly rather than
# matched by prefix, so that a new crate must be added here deliberately and shows up in a
# review diff rather than appearing silently.
OUR_CRATES = {
    "compitum-json",
    "compitum-digest",
    "compitum-i18n",
    "compitum-isa",
    "compitum-pe",
    "compitum-router",
    "compitum-oracle",
    "compitum-exec",
    "compitum-cli",
}


def main() -> int:
    try:
        metadata = json.load(sys.stdin)
    except json.JSONDecodeError as error:
        print(f"::error::cargo metadata did not produce valid JSON: {error}")
        return 1

    packages = metadata.get("packages", [])
    if not packages:
        print("::error::cargo metadata reported no packages at all")
        return 1

    ours = []
    foreign = []
    for package in packages:
        name = package.get("name", "?")
        version = package.get("version", "?")
        if name in OUR_CRATES:
            ours.append(f"{name} {version}")
        else:
            foreign.append(f"{name} {version}")

    print(f"workspace crates resolved: {len(ours)}")
    for entry in sorted(ours):
        print(f"  {entry}")
    print(f"third-party crates resolved: {len(foreign)}")

    if foreign:
        print()
        for entry in sorted(foreign):
            print(f"::error::third-party dependency entered the graph: {entry}")
        print()
        print(
            "The workspace must build offline with no external crates. If this dependency "
            "is genuinely necessary, it must be justified in the roadmap's decision log and "
            "this script updated deliberately."
        )
        return 1

    # Catch the other half of the rule: a crate that exists on disk but was left out of the
    # workspace members list, which would silently exclude it from every build and test.
    declared = set(metadata.get("workspace_members", []))
    listed = {p["id"] for p in packages if p["name"] in OUR_CRATES}
    missing = listed - declared
    if missing:
        print(f"::error::crates present but not workspace members: {missing}")
        return 1

    print("OK: the dependency graph contains only workspace crates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
