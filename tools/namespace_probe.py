#!/usr/bin/env python3
"""
Namespace availability probe for COMPITUM.

Checks a candidate handle across every namespace the project needs to hold, using the
registry APIs directly rather than shell-parsed headers. The shell version of this probe
reported "server" instead of an HTTP status because a header value containing the word
"server" defeated the awk field extraction -- a reminder that a measurement tool which
is not itself verified will happily produce confident nonsense.

A 404 means the name is unclaimed in that namespace.
"""

import json
import urllib.error
import urllib.request

TIMEOUT = 20

# Namespaces the project must control. Each entry is (label, url template).
NAMESPACES = [
    ("github", "https://api.github.com/users/{name}"),
    ("npm", "https://registry.npmjs.org/{name}"),
    ("pypi", "https://pypi.org/pypi/{name}/json"),
    ("crates", "https://crates.io/api/v1/crates/{name}"),
    ("dockerhub", "https://hub.docker.com/v2/repositories/{name}/"),
]


def probe(url: str, token: str | None = None) -> int:
    """Returns the HTTP status, or 0 when the request could not be completed."""
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
    except Exception as error:  # network failure, DNS failure, timeout
        print(f"      ! probe failed for {url}: {error}")
        return 0


def verdict(status: int) -> str:
    if status == 404:
        return "FREE"
    if status == 200:
        return "TAKEN"
    if status == 0:
        return "UNKNOWN (probe error)"
    return f"UNKNOWN (HTTP {status})"


def main() -> None:
    import os

    token = os.environ.get("GH_TOKEN", "")
    candidates = ["compitum", "compitum-dev", "compitumdev", "compitum-arm64", "compitumhq"]

    for name in candidates:
        print(f"\n=== handle: {name} ===")
        row = {}
        for label, template in NAMESPACES:
            url = template.format(name=name)
            status = probe(url, token)
            row[label] = verdict(status)
            print(f"  {label:<11} {row[label]}")
        # A handle is "clean" when every namespace is free or unknown-but-not-taken.
        taken = [k for k, v in row.items() if v == "TAKEN"]
        print(f"  --> {'ALL CLEAR' if not taken else 'CONFLICTS: ' + ', '.join(taken)}")

    print("\n=== domain availability (NS delegation) ===")
    for domain in [
        "compitum.dev",
        "compitum-dev.com",
        "compitumdev.com",
        "compitum-dev.dev",
        "compitumdev.dev",
        "compitum.org",
    ]:
        url = f"https://dns.google/resolve?name={domain}&type=NS"
        try:
            with urllib.request.urlopen(url, timeout=TIMEOUT) as response:
                data = json.load(response)
            registered = bool(data.get("Answer"))
            print(f"  {domain:<20} {'REGISTERED' if registered else 'no delegation (likely AVAILABLE)'}")
        except Exception as error:
            print(f"  {domain:<20} probe error: {error}")


if __name__ == "__main__":
    main()
