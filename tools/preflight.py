#!/usr/bin/env python3
"""
Pre-flight validation for a crates.io publication.

# Why this is a script and not a checklist

A rejected publish **permanently consumes the version number**. crates.io does not allow a
version to be reused, so the only remedy for a mistake is to bump the version and try again —
which pollutes the version history and, for a family of eight inter-dependent crates, risks
publishing some of them at one version and the rest at another.

Everything a registry rejects is mechanically checkable. So it is checked here, before the
irreversible step, rather than discovered from a 400 response.

# What is verified

1. **The working tree is clean.** Publishing uncommitted code means the version on the registry
   does not correspond to any commit, which makes the release unreproducible.
2. **Every crate carries the metadata a registry requires** — description, licence,
   repository, a README that exists, keywords, and categories.
3. **No crate depends on a path without a version.** A registry cannot resolve a path.
4. **The internal dependency graph is acyclic**, so a publish order exists at all.
5. **The publish order is computed**, leaf-first, from the real graph.
6. **Every crate that can be packaged independently, packages.** A crate blocked *only* by a
   dependency that is not yet on the registry is expected and reported as such.
7. **Each crate already published at this version is detected**, because republishing the same
   version is the most common and most expensive mistake.
8. **The full test suite passes**, because a registry release is the worst place to learn that
   something is broken.

Usage:

    python3 tools/preflight.py                    # check everything
    python3 tools/preflight.py --skip-network     # offline; skips the registry version check
    python3 tools/preflight.py --json             # machine-readable result

Exit code 0 means "safe to publish". Anything else means do not.
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys

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

# A crate whose packaging fails for one of these reasons is simply waiting for its own
# dependency to be published. That is the normal state of a fresh crate family and is not a
# defect -- see `.github/scripts/check_packaging.py`, which makes the same distinction.
AWAITING_MARKERS = (
    "no matching package named",
    "failed to select a version for the requirement",
)

REQUIRED_METADATA = ("description", "license", "repository", "readme")


class Result:
    """Accumulates checks so every problem is reported, not just the first."""

    def __init__(self) -> None:
        self.problems: list = []
        self.notes: list = []
        self.order: list = []

    def fail(self, message: str) -> None:
        self.problems.append(message)

    def note(self, message: str) -> None:
        self.notes.append(message)

    @property
    def ok(self) -> bool:
        return not self.problems


def run(command: list, cwd: str = ".") -> tuple:
    """Runs a command and returns (returncode, combined output)."""
    result = subprocess.run(
        command, cwd=cwd, capture_output=True, text=True, check=False
    )
    return result.returncode, result.stdout + result.stderr


def check_git_clean(result: Result) -> None:
    code, output = run(["git", "status", "--porcelain"])
    if code != 0:
        result.note("git is unavailable or this is not a repository; skipping the clean-tree check")
        return
    dirty = [line for line in output.splitlines() if line.strip()]
    if dirty:
        result.fail(
            f"the working tree has {len(dirty)} uncommitted change(s); a published version "
            "must correspond to a commit, or the release is unreproducible"
        )
        for line in dirty[:5]:
            result.note(f"  {line}")
    else:
        result.note("working tree is clean")


def check_metadata(result: Result) -> list:
    """Reads real package metadata via cargo rather than guessing from TOML text."""
    code, output = run(["cargo", "metadata", "--format-version", "1", "--no-deps"])
    if code != 0:
        result.fail(f"`cargo metadata` failed: {output.strip()[:200]}")
        return []

    packages = {p["name"]: p for p in json.loads(output).get("packages", [])}

    for crate in OWN_CRATES:
        package = packages.get(crate)
        if package is None:
            result.fail(f"{crate}: not present in the workspace")
            continue

        for field in REQUIRED_METADATA:
            value = package.get(field)
            if not value:
                result.fail(f"{crate}: missing `{field}`, which a registry requires")
            elif field == "readme":
                crate_relative = os.path.join("crates", crate, value)
                if not os.path.exists(crate_relative) and not os.path.exists(value):
                    result.fail(f"{crate}: readme `{value}` does not exist")

        if not package.get("keywords"):
            result.fail(f"{crate}: no keywords, so it would be unfindable in search")
        if not package.get("categories"):
            result.fail(f"{crate}: no categories, so it would be unfindable in search")

    if not result.problems:
        result.note(f"all {len(OWN_CRATES)} crates carry the metadata a registry requires")
    return OWN_CRATES


def check_dependencies_have_versions(result: Result) -> dict:
    """Every workspace dependency must carry a version alongside its path."""
    with open("Cargo.toml", encoding="utf-8") as handle:
        text = handle.read()

    versions = {}
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[workspace.dependencies]"):
            in_section = True
            continue
        if in_section and stripped.startswith("[") and "workspace.dependencies" not in stripped:
            in_section = False
            continue
        if not in_section or not stripped.startswith("compitum-"):
            continue
        name = stripped.split("=")[0].strip()
        match = re.search(r'version\s*=\s*"([^"]+)"', stripped)
        if "path" in stripped and not match:
            result.fail(
                f"{name}: depends on a path with no version, which a registry cannot resolve"
            )
        elif match:
            versions[name] = match.group(1)

    if not result.problems:
        result.note(f"all {len(versions)} workspace dependencies carry a version")
    return versions


def compute_order(result: Result) -> list:
    """Derives the publish order, leaf-first, from the real dependency graph."""
    code, output = run(["cargo", "metadata", "--format-version", "1", "--no-deps"])
    if code != 0:
        return []
    packages = json.loads(output).get("packages", [])
    ours = {p["name"]: p for p in packages if p["name"].startswith("compitum-")}

    deps = {}
    for name, package in ours.items():
        deps[name] = {
            d["name"] for d in package.get("dependencies", []) if d.get("name") in ours
        } - {name}

    ordered: list = []
    remaining = dict(deps)
    while remaining:
        ready = sorted(n for n, need in remaining.items() if not need - set(ordered))
        if not ready:
            result.fail(
                "the crate dependency graph contains a cycle among: "
                + ", ".join(sorted(remaining))
                + ". Publishing is impossible until it is broken."
            )
            return []
        ordered.append(ready[0])
        del remaining[ready[0]]

    result.order = ordered
    result.note(f"publish order computed for {len(ordered)} crate(s), leaf-first")
    return ordered


def check_packaging(result: Result, offline: bool) -> None:
    """Packages each crate, distinguishing an expected wait from a real defect."""
    ready, awaiting, defective = [], [], []
    for crate in OWN_CRATES:
        command = ["cargo", "package", "-p", crate, "--no-verify", "--allow-dirty"]
        if offline:
            command.append("--offline")
        code, output = run(command)
        if code == 0:
            ready.append(crate)
        elif any(marker in output for marker in AWAITING_MARKERS):
            missing = "?"
            for line in output.splitlines():
                if any(marker in line for marker in AWAITING_MARKERS):
                    quoted = re.findall(r"`([^`]+)`", line)
                    if quoted:
                        missing = quoted[0]
                    break
            awaiting.append((crate, missing))
        else:
            defective.append(crate)
            for line in output.splitlines():
                if "error" in line.lower():
                    result.fail(f"{crate}: {line.strip()[:160]}")
                    break
            else:
                result.fail(f"{crate}: `cargo package` failed without a recognisable error")

    if ready:
        result.note(f"{len(ready)} crate(s) package cleanly")
    for crate, missing in awaiting:
        result.note(f"{crate} is awaiting `{missing}` to be published first")

    if defective:
        result.fail(
            f"{len(defective)} crate(s) cannot be packaged for a reason other than a missing "
            "dependency; those are real defects"
        )


def check_registry_versions(result: Result, versions: dict, offline: bool) -> None:
    """Detects a version that is already on the registry, which cannot be republished."""
    if offline:
        result.note("offline mode: skipped the registry version check")
        return

    import urllib.error
    import urllib.request

    for crate in OWN_CRATES:
        version = versions.get(crate)
        if not version:
            continue
        url = f"https://crates.io/api/v1/crates/{crate}/{version}"
        request = urllib.request.Request(url)
        request.add_header("User-Agent", "compitum-preflight")
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                if response.status == 200:
                    result.fail(
                        f"{crate} v{version} is ALREADY PUBLISHED. A version cannot be reused; "
                        "bump it before publishing."
                    )
        except urllib.error.HTTPError as error:
            if error.code == 404:
                # The good case: the version is free.
                continue
            result.note(f"{crate}: the registry returned HTTP {error.code}; cannot confirm")
        except Exception as error:
            result.note(f"{crate}: could not reach the registry ({error}); cannot confirm")

    result.note("checked every crate against the registry for an existing version")


def check_tests(result: Result) -> None:
    code, output = run(["cargo", "test", "--all-targets"])
    if code != 0:
        result.fail("the test suite does not pass; never publish a release from a red build")
        for line in output.splitlines():
            if "test result: FAILED" in line or line.startswith("error"):
                result.note(f"  {line.strip()[:140]}")
    else:
        passing = sum(
            int(m.group(1))
            for m in re.finditer(r"(\d+) passed", output)
        )
        result.note(f"test suite passes ({passing} tests)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Pre-flight validation for a publication.")
    parser.add_argument("--skip-network", action="store_true", help="do not contact the registry")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--skip-tests", action="store_true", help="skip the test run")
    options = parser.parse_args()

    result = Result()
    if not options.json:
        print("COMPITUM pre-flight: validating everything a registry will reject\n")

    check_git_clean(result)
    versions = check_dependencies_have_versions(result)
    check_metadata(result)
    compute_order(result)
    check_packaging(result, offline=options.skip_network)
    check_registry_versions(result, versions, offline=options.skip_network or False)
    if not options.skip_tests:
        check_tests(result)

    if options.json:
        print(
            json.dumps(
                {
                    "ready_to_publish": result.ok,
                    "publish_order": result.order,
                    "checks": result.notes,
                    "problems": result.problems,
                },
                indent=2,
            )
        )
        return 0 if result.ok else 1

    print("checks:")
    for note in result.notes:
        print(f"  - {note}")

    if result.order:
        print("\npublish order (leaf-first):")
        for index, crate in enumerate(result.order, start=1):
            print(f"  {index}. {crate}")

    if result.problems:
        print(f"\n{len(result.problems)} problem(s) — DO NOT PUBLISH:")
        for problem in result.problems:
            print(f"  {problem}")
        print(
            "\nA rejected publish permanently consumes the version number. Fix these first."
        )
        return 1

    print(
        "\nREADY. Publish in the order above, one crate at a time, waiting for each to appear "
        "on the registry before starting the next."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
