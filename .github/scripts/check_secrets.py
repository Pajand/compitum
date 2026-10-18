#!/usr/bin/env python3
"""
Fails the build if a credential-shaped string has been committed.

A leaked token in a public repository is compromised within minutes, because scrapers watch
public pushes specifically for them. This check is cheap and runs on every push, which is the
only reliable defence: a human reviewer will eventually miss one.

Deliberately conservative about false positives. It looks for the *prefixes and shapes* that
real credentials use, not for high-entropy strings, so ordinary code and documentation do not
trip it.

Usage:

    python3 .github/scripts/check_secrets.py .
"""

import os
import re
import sys

# (name, compiled pattern). Each pattern matches a credential's documented shape.
PATTERNS = [
    ("GitHub personal access token (classic)", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub OAuth token", re.compile(r"gho_[A-Za-z0-9]{36}")),
    ("GitHub user-to-server token", re.compile(r"ghu_[A-Za-z0-9]{36}")),
    ("GitHub server-to-server token", re.compile(r"ghs_[A-Za-z0-9]{36}")),
    ("GitHub refresh token", re.compile(r"ghr_[A-Za-z0-9]{76}")),
    ("GitHub fine-grained token", re.compile(r"github_pat_[A-Za-z0-9_]{82}")),
    ("npm access token", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("PyPI upload token", re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}")),
    ("crates.io API token", re.compile(r"\bcio[A-Za-z0-9]{32}\b")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Stripe live secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("Cloudflare API token", re.compile(r"\b[A-Za-z0-9_-]{40}\b(?=.*cloudflare)", re.IGNORECASE)),
]

# Directories that cannot contain a committed secret, or that would produce enormous noise.
SKIP_DIRS = {".git", "target", "node_modules", ".cargo", "vendor", "dist", "build"}

# Binary and archive extensions worth skipping: secrets do not leak usefully through these,
# and reading them wastes time.
SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".pdf", ".zip", ".gz", ".xz",
    ".tar", ".whl", ".exe", ".dll", ".so", ".a", ".rlib", ".rmeta", ".woff", ".woff2",
}

# Files whose whole purpose is to contain these patterns. A secret scanner that flags its own
# test fixtures is a scanner people learn to ignore.
SKIP_FILES = {"check_secrets.py"}

# An occurrence preceded by one of these markers is an intentional example, and the project's
# own documentation uses them when explaining the token format.
ALLOW_MARKERS = ("example", "EXAMPLE", "REDACTED", "PLACEHOLDER", "your_token", "<token>", "xxx")


def looks_like_example(line: str) -> bool:
    return any(marker in line for marker in ALLOW_MARKERS)


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    findings = []
    scanned = 0

    for directory, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if filename in SKIP_FILES:
                continue
            if os.path.splitext(filename)[1].lower() in SKIP_SUFFIXES:
                continue
            path = os.path.join(directory, filename)
            try:
                with open(path, encoding="utf-8", errors="ignore") as handle:
                    for number, line in enumerate(handle, start=1):
                        scanned += 1
                        if looks_like_example(line):
                            continue
                        for name, pattern in PATTERNS:
                            if pattern.search(line):
                                findings.append((path, number, name))
            except (OSError, UnicodeDecodeError):
                continue

    print(f"scanned {scanned} line(s) across the tree")

    if findings:
        print()
        for path, number, name in findings:
            # Report the location and the kind, never the value itself: echoing it into a CI
            # log would spread it further than the commit did.
            print(f"::error file={path},line={number}::{name} detected")
        print()
        print(
            "A credential-shaped string is committed. Rotate the credential first, then "
            "remove it from the history: deleting the line is not enough, because the value "
            "remains reachable in the object database."
        )
        return 1

    print("OK: no credential-shaped strings found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
