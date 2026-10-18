#!/usr/bin/env python3
"""
Computes the order in which COMPITUM's crates must be published to crates.io.

# Why this exists

A registry cannot resolve a dependency that does not exist yet, so the crate family has to
be published leaf-first. Getting the order wrong causes a rejection, and a *rejected publish
permanently consumes the version number*: crates.io does not let a version be reused, so the
only remedy is to bump and try again. An order computed from the real dependency graph is
therefore worth more than a written-down list that can drift.

# What it does

Reads `cargo metadata`, keeps only this workspace's own crates, and emits a topological
order. Ties are broken alphabetically so the output is deterministic and diffable. It also
reports, for each crate, which of its dependencies must already be live.

Usage:

    cargo metadata --format-version 1 --no-deps \
      | python3 tools/publish_order.py

    # Or let it run cargo itself:
    python3 tools/publish_order.py --run-cargo

    # Emit JSON for a CI job to consume:
    python3 tools/publish_order.py --json
"""

import json
import os
import subprocess
import sys

# Crates published under this prefix are expected to belong to the project. The dependency
# checker in `.github/scripts/` owns the authoritative allow-list; this is the ordering tool's
# own view, which only needs to know which packages are ours.
PREFIX = "compitum-"


def load_metadata(run_cargo: bool) -> dict:
    if run_cargo or sys.stdin.isatty():
        result = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--no-deps"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            print("::error::`cargo metadata` failed", file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            sys.exit(1)
        return json.loads(result.stdout)
    return json.load(sys.stdin)


def topological_order(packages: list) -> tuple:
    """
    Returns (ordered_names, dependencies_by_name).

    Uses Kahn's algorithm with alphabetical tie-breaking, so the result is deterministic.
    Raises on a cycle, because a cycle in the crate graph would make publishing impossible
    and that is worth failing loudly for rather than emitting a wrong order.
    """
    ours = {p["name"]: p for p in packages if p["name"].startswith(PREFIX)}

    # Only dependencies within the family constrain the order; an external crate is already
    # on the registry or the build would not work at all.
    deps = {}
    for name, package in ours.items():
        local = set()
        for dep in package.get("dependencies", []):
            dep_name = dep.get("name")
            # `cargo metadata` reports a renamed dependency under its package name, which is
            # what the registry needs to see.
            if dep_name in ours and dep_name != name:
                local.add(dep_name)
        deps[name] = local

    ordered = []
    remaining = dict(deps)
    while remaining:
        # Every crate whose remaining dependencies are all already emitted.
        ready = sorted(name for name, needed in remaining.items() if not needed - set(ordered))
        if not ready:
            cycle = ", ".join(sorted(remaining))
            raise RuntimeError(
                f"the crate dependency graph contains a cycle among: {cycle}. "
                "Publishing is impossible until it is broken."
            )
        # Emit one at a time so each pass re-evaluates in the correct order.
        ordered.append(ready[0])
        del remaining[ready[0]]

    return ordered, deps


def main() -> int:
    as_json = "--json" in sys.argv
    run_cargo = "--run-cargo" in sys.argv

    metadata = load_metadata(run_cargo)
    packages = metadata.get("packages", [])
    if not packages:
        print("::error::no packages found", file=sys.stderr)
        return 1

    try:
        ordered, deps = topological_order(packages)
    except RuntimeError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1

    if as_json:
        print(
            json.dumps(
                {
                    "count": len(ordered),
                    "order": [
                        {
                            "step": index + 1,
                            "crate": name,
                            "requires_published": sorted(deps[name]),
                        }
                        for index, name in enumerate(ordered)
                    ],
                },
                indent=2,
            )
        )
        return 0

    print(f"publish order for {len(ordered)} crate(s), leaf-first:\n")
    for index, name in enumerate(ordered, start=1):
        needed = sorted(deps[name])
        if needed:
            requires = "requires published first: " + ", ".join(needed)
        else:
            requires = "no workspace dependencies; can go first"
        print(f"  {index}. {name:<18} {requires}")

    print()
    print("Each step must complete before the next is attempted, because a registry cannot")
    print("resolve a dependency that does not exist yet. The first publish of a crate is")
    print("permanent: a rejected attempt consumes the version number, so the version in")
    print("Cargo.toml must be right before the attempt.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
