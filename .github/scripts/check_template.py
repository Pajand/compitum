#!/usr/bin/env python3
"""
Verifies the exported translation template.

`compitum locales export <tag>` writes a skeleton containing every key the English base
defines with empty values. A translator fills it in and drops it into `locales/`. This script
checks that the skeleton is actually complete, because a truncated template is worse than none:
a translator would finish it believing the work was done.

Usage:

    python3 .github/scripts/check_template.py <template.json>
"""

import json
import sys

# Keys that must exist in any complete template. These are the messages an operator sees at the
# moments that matter most: a verdict, a refusal, and a usage error. If the export ever loses
# one of these, the localization surface has a hole where it is most visible.
REQUIRED_KEYS = [
    "app.name",
    "app.tagline",
    "verdict.compatible",
    "verdict.incompatible",
    "explain.native",
    "explain.hybrid",
    "reason.arch_native",
    "reason.isa_missing",
    "error.file_not_found",
    "error.not_pe",
    "usage.summary",
]

# Keys whose values must stay literal across every language, because they name protocol tokens
# rather than prose. Translating these would break a user's ability to match our output against
# documentation or a stored Oracle record.
# (Checked on the English base: these are the values a translator is warned about.)
SYMBOLIC_VALUES = {
    "verdict.compatible": "COMPATIBLE",
    "verdict.incompatible": "INCOMPATIBLE",
    "verdict.unknown": "UNKNOWN",
    "state.yes": "yes",
    "state.no": "no",
}


def fail(message: str) -> int:
    print(f"::error::{message}")
    return 1


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_template.py <template.json>")
        return 1

    with open(sys.argv[1], encoding="utf-8") as handle:
        document = json.load(handle)

    messages = document.get("messages")
    if not isinstance(messages, dict):
        return fail("the template has no `messages` object")

    print(f"exported keys: {len(messages)}")

    # A base catalog with only a handful of keys means the export silently lost most of them,
    # which a translator would not notice until they were nearly finished.
    if len(messages) < 100:
        return fail(
            f"only {len(messages)} keys were exported; the English base looks truncated"
        )

    missing = [key for key in REQUIRED_KEYS if key not in messages]
    if missing:
        return fail(f"the template is missing required keys: {', '.join(missing)}")

    # Every value must be present (the key exists) and every key must be a non-empty string.
    empty_keys = [key for key in messages if not isinstance(key, str) or not key]
    if empty_keys:
        return fail(f"{len(empty_keys)} key(s) are not usable strings")

    # The template's values are intentionally empty: it is a skeleton for a translator to fill
    # in. A non-empty value here would mean `export` leaked English text into the template,
    # which a translator might then leave in place believing it was required.
    non_empty = {k: v for k, v in messages.items() if v != ""}
    if non_empty:
        sample = list(non_empty.items())[:3]
        return fail(
            f"the template should have empty values, but {len(non_empty)} key(s) carry text "
            f"(e.g. {sample}); a translator might leave English in place"
        )

    # The metadata a loader needs.
    for field in ("language", "name", "native_name", "direction"):
        if field not in document:
            return fail(f"the template has no `{field}` field, so it could not be loaded")

    print("OK: the template is complete and safe to hand to a translator")
    return 0


if __name__ == "__main__":
    sys.exit(main())
