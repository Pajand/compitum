#!/usr/bin/env python3
"""
Namespace availability probe for COMPITUM.

Checks a candidate handle across every namespace the project needs to hold, using the
registry APIs directly rather than shell-parsed headers. A shell version of this probe
earlier reported "server" instead of an HTTP status because a header value containing the
word "server" defeated the awk field extraction -- a reminder that a measurement tool
which is not itself verified will happily produce confident nonsense.

A 404 means the name is unclaimed in that namespace.
"""

import json
import os
import urllib.error
import urllib.request

TIMEOUT = 25

# (label, url template). 404 = free, 200 = taken.
NAMESPACES = [
    ("github", "https://api.github.com/users/{name}"),
    ("npm", "https://registry.npmjs.org/{name}"),
    ("pypi", "https://pypi.org/pypi/{name}/json"),
    ("crates.io", "https://crates.io/api/v1/crates/{name}"),
    ("dockerhub", "https://hub.docker.com/v2/users/{name}/"),
]


def probe(url: str, token: str = "") -> int:
    request = urllib.request.Request(url)
    request.add_header("User-Agent", "compitum-namespace-probe")
    request.add_header("Accept", "application/json")
    if token and "api.github.com" in url:
        request.add_header("Authorization", f"token {token}")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except Exception as error:
        print(f"      ! probe failed: {error}")
        return 0


def verdict(status: int) -> str:
    if status == 404:
        return "FREE"
    if status == 200:
        return "TAKEN"
    if status == 0:
        return "UNKNOWN (network)"
    return f"UNKNOWN (HTTP {status})"


def main() -> None:
    token = os.environ.get("GH_TOKEN", "")
    candidates = ["compitum", "compitum-dev", "compitumdev"]

    for name in candidates:
        print(f"\n=== handle: {name} ===")
        taken = []
        for label, template in NAMESPACES:
            status = probe(template.format(name=name), token)
            v = verdict(status)
            if v == "TAKEN":
                taken.append(label)
            print(f"  {label:<11} {v}")
        print(f"  --> {'ALL CLEAR' if not taken else 'CONFLICTS: ' + ', '.join(taken)}")


if __name__ == "__main__":
    main()
