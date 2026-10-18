#!/usr/bin/env python3
"""
Verifies that a ledger produced by the CLI contains the real decisions, not guesses.

Written as a script rather than an inline block in the workflow because the check has real
content: it asserts the exact defect that was found and fixed during development, where
`verify` stored a route derived from the ABI family instead of the route it decided, so a
binary refused for missing SME/SVE was recorded as `native`.

A ledger containing a wrong verdict is worse than an empty one, because the entire value of
the asset is that its contents can be trusted. This check is the guard against that
regression reappearing.

Usage:

    python3 .github/scripts/check_ledger.py /tmp/ci-ledger.jsonl
"""

import json
import os
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_ledger.py <ledger.jsonl>")
        return 1

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"::error::the ledger was never written to {path}")
        print("recording silently failed, which would mean the dataset never grows")
        return 1

    rows = []
    unreadable = 0
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                unreadable += 1

    if not rows:
        print("::error::the ledger is empty")
        return 1

    print(f"records: {len(rows)}, unreadable lines: {unreadable}")

    by_route = {}
    for row in rows:
        route = row.get("route", "?")
        by_route[route] = by_route.get(route, 0) + 1
    for route in sorted(by_route):
        print(f"  {route:<16} {by_route[route]}")

    problems = []

    # The refused subject must be stored as refused.
    if "refused" not in by_route:
        problems.append(
            "no record is marked `refused`; the un-runnable subject was probably stored "
            "with a guessed route instead of the actual decision"
        )

    # A route must never be `unknown` for a subject that was actually verified.
    if "unknown" in by_route:
        problems.append(
            "a record has route `unknown`; `verify` must store what it decided, and "
            "`inspect` must store `undecided` rather than guessing from the ABI family"
        )

    # Every record must carry a subject digest and a host snapshot, or it cannot be joined
    # with another observation or replayed against a different machine.
    for index, row in enumerate(rows):
        if len(row.get("subject_sha256", "")) != 64:
            problems.append(f"record {index} has no usable subject digest")
        host = row.get("host") or {}
        if not host.get("arch"):
            problems.append(f"record {index} has no host architecture")
        if "host_class" not in row:
            problems.append(f"record {index} has no host class, so it cannot be reused")

    # A record claiming to be blocked must not also claim to be fully native; the two are
    # mutually exclusive and a record asserting both would be incoherent.
    for index, row in enumerate(rows):
        if row.get("blocked") and row.get("fully_native"):
            problems.append(
                f"record {index} claims both `blocked` and `fully_native`, which cannot "
                "both be true"
            )

    if problems:
        print()
        for problem in problems:
            print(f"::error::{problem}")
        return 1

    print("OK: the ledger records real decisions with reusable provenance")
    return 0


if __name__ == "__main__":
    sys.exit(main())
