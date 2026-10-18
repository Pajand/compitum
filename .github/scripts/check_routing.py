#!/usr/bin/env python3
"""
Verifies that a routing JSON document matches the route the situation demands.

The end-to-end path is the one place where a unit test cannot help: the CLI parses arguments,
reads a file, probes the host, scans instructions, decides, and renders. A mistake anywhere in
that chain produces a confident wrong answer, which is the failure mode this project exists to
eliminate.

Keeping the assertions here rather than inline in the workflow means they can be run locally
against the same fixtures the workflow uses.

Usage:

    python3 .github/scripts/check_routing.py <path-to-plan.json> <expected-route>
"""

import json
import sys

# Routes this project can emit, with the properties each one must satisfy. A route claiming
# to be native must not require a backend, and a refusal must not claim throughput.
NATIVE_ROUTES = {"native", "pick_native_slice"}
TRANSLATING_ROUTES = {"box64_full", "fex_full", "wow64"}
HYBRID_ROUTES = {"fex_partial"}
REFUSAL_ROUTES = {"refused"}

ALL_ROUTES = NATIVE_ROUTES | TRANSLATING_ROUTES | HYBRID_ROUTES | REFUSAL_ROUTES


def fail(message: str) -> int:
    print(f"::error::{message}")
    return 1


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_routing.py <plan.json> <expected-route>")
        return 1

    path, expected = sys.argv[1], sys.argv[2]
    with open(path, encoding="utf-8") as handle:
        plan = json.load(handle)

    route = plan.get("route")
    print(f"route={route} status={plan.get('status')} native={plan.get('fully_native')} "
          f"blocked={plan.get('blocked')} confidence={plan.get('confidence_percent')}%")

    if route not in ALL_ROUTES:
        return fail(f"`{route}` is not a route this project defines")

    if route != expected:
        return fail(f"expected route `{expected}`, got `{route}`")

    # --- Invariants that must hold for every route ---------------------------
    if not plan.get("headline"):
        return fail("the plan carries no headline; an operator would have to read JSON")
    if not plan.get("route_description"):
        return fail("the plan does not explain what the route does")
    if "reasons" not in plan:
        return fail("the plan carries no reasons; a verdict without evidence is an opinion")
    if not isinstance(plan.get("schema_version"), int):
        return fail("the plan has no schema version, so a stored record could not be read back")

    # --- Invariants per route class -----------------------------------------
    if route in NATIVE_ROUTES:
        if not plan.get("fully_native"):
            return fail(f"route `{route}` must be reported as fully native")
        if plan.get("blocked"):
            return fail(f"route `{route}` must not be blocked")
        if plan.get("backend") is not None:
            return fail(
                f"route `{route}` names backend `{plan.get('backend')}`; a native route "
                "must not depend on a translator"
            )
        top = plan.get("expected_throughput_percent") or {}
        if top.get("min") != 100 or top.get("max") != 100:
            return fail(f"route `{route}` must report 100% of native throughput, got {top}")

    if route in HYBRID_ROUTES:
        if plan.get("fully_native"):
            return fail("`fex_partial` translates x86-64 code and must not claim to be native")
        if plan.get("backend") != "fex":
            return fail(
                "a hybrid route needs FEX specifically, because its translator must coexist "
                "with native code in the same process"
            )
        top = plan.get("expected_throughput_percent") or {}
        if top.get("max", 100) >= 100:
            return fail("a hybrid route must not claim native throughput")

    if route in TRANSLATING_ROUTES:
        if plan.get("backend") is None:
            return fail(f"route `{route}` names no backend")
        if plan.get("fully_native"):
            return fail(f"route `{route}` translates every instruction and is not native")

    if route in REFUSAL_ROUTES:
        if not plan.get("blocked"):
            return fail("a refusal must be marked blocked")
        if plan.get("fully_native"):
            return fail("a refusal cannot be fully native")
        if plan.get("backend") is not None:
            return fail("a refusal must not name a backend")
        if plan.get("expected_throughput_percent") is not None:
            return fail("a refusal must not predict throughput")
        if plan.get("blocking_reason_count", 0) < 1:
            return fail("a refusal must name at least one blocking reason")

    print(f"OK: route `{route}` satisfies every invariant for its class")
    return 0


if __name__ == "__main__":
    sys.exit(main())
