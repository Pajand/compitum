#!/usr/bin/env python3
"""
Keep the repository's public identity consistent, from one source of truth.

# The problem this solves

A project's domain, repository URL, contact address and tagline appear in dozens of
places: `Cargo.toml`, every crate README, the npm `package.json`, the PyPI
`pyproject.toml`, `SECURITY.md`, the workflows. When the domain is finally registered,
updating them by hand is how a project ends up with half its links pointing at the old
place — and a dead link in a published crate cannot be fixed without publishing a new
version.

So all of it is derived from `identity.toml`. Change that file, run this script, and every
derived value updates. Run it with `--check` in CI and drift becomes a build failure.

# Why the rewrites are explicit rather than a blanket search-and-replace

A blind replace of "the old URL" across every file is how a documentation link to a
*specific file* in the repository silently becomes a link to a marketing homepage. Each
rule below names the exact construct it updates, so a change either matches something
known or reports that it did not — it never guesses.

# Usage

    python3 tools/identity.py            # apply the identity everywhere
    python3 tools/identity.py --check    # verify nothing has drifted (CI)
    python3 tools/identity.py --verbose  # show every file examined
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
IDENTITY_FILE = REPO_ROOT / "identity.toml"

# File types worth examining. Binary and build output are skipped.
TEXT_SUFFIXES = {".md", ".toml", ".json", ".yml", ".yaml", ".rs", ".txt", ".sh", ".py"}
SKIP_DIRS = {"target", ".git", "node_modules", "vendor"}


# ---------------------------------------------------------------------------
# A deliberately tiny TOML reader.
#
# The file is flat: one `[identity]` table of `key = "value"` pairs. Pulling in a TOML
# library would add a dependency to a script whose entire job is to be obviously correct,
# and the workspace's own rule is that tooling stays dependency-free.
# ---------------------------------------------------------------------------
def read_identity(path: pathlib.Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"::error::cannot find {path}")

    values: dict = {}
    in_section = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.strip().startswith("["):
            in_section = line.strip() == "[identity]"
            continue
        if not in_section or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        values[key.strip()] = value
    return values


class Identity:
    """Every value derived from `identity.toml`."""

    def __init__(self, raw: dict) -> None:
        required = ("repository", "contact_email", "product_name", "github_org", "tagline")
        missing = [k for k in required if not raw.get(k)]
        if missing:
            raise SystemExit(f"::error::identity.toml is missing: {', '.join(missing)}")

        self.domain: str = raw.get("domain", "")
        self.repository: str = raw["repository"]
        self.contact_email: str = raw["contact_email"]
        self.product_name: str = raw["product_name"]
        self.github_org: str = raw["github_org"]
        self.tagline: str = raw["tagline"]
        self.license: str = raw.get("license", "MIT OR Apache-2.0")
        self.copyright: str = raw.get("copyright", "")
        self.api_base: str = raw.get("api_base", "")

    @property
    def has_domain(self) -> bool:
        return bool(self.domain.strip())

    @property
    def home(self) -> str:
        """The project's home: the domain once it exists, otherwise the repository.

        Choosing the repository as the fallback means every published artefact already
        points somewhere that resolves, so nothing is ever broken while the domain is
        pending.
        """
        return f"https://{self.domain}" if self.has_domain else self.repository

    @property
    def api(self) -> str | None:
        """The Oracle API base, advertised only once it is explicitly deployed.

        `None` unless `api_base` is set in `identity.toml`. Deriving it from the domain
        would publish `https://api.<domain>` the moment a domain is registered -- before a
        DNS record for that name exists and before the service does. A registered domain is
        one fact; a running API is another, and inferring the second from the first puts a
        dead endpoint into a machine-readable block.
        """
        return self.api_base or None

    @property
    def mail(self) -> str:
        """The contact address, exactly as configured.

        Deliberately *not* derived from the domain. Buying a domain and having mail
        forwarding work are different facts, and a security report sent to a mailbox that
        does not exist yet is a harm with no upside. When forwarding is live, `contact_email`
        is changed to the new address: one field, one deliberate act.
        """
        return self.contact_email

    @property
    def container(self) -> str:
        return f"ghcr.io/{self.github_org}/compitum"

    def describe(self) -> str:
        lines = [
            f"  product   : {self.product_name}",
            f"  domain    : {self.domain or '(not registered yet)'}",
            f"  home      : {self.home}",
            f"  repository: {self.repository}",
            f"  mail      : {self.mail}",
            f"  container : {self.container}",
        ]
        lines.append(f"  api       : {self.api or '(unavailable without a domain)'}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Rewrite rules.
#
# Each is (pattern, replacement-builder, description). The pattern must match something
# specific; if it does not, the rule reports zero hits rather than silently succeeding,
# because a rule that matches nothing is either unnecessary or wrong.
# ---------------------------------------------------------------------------
def rules(identity: Identity):
    home = identity.home
    return [
        (
            # The `homepage` field of the root manifest. Distinct from `repository`,
            # which always points at the source.
            re.compile(r'^(homepage\s*=\s*)"[^"]*"', re.MULTILINE),
            lambda m: f'{m.group(1)}"{home}"',
            "root Cargo.toml homepage",
        ),
        (
            # A machine-readable identity block inside the README, so the values a
            # consumer reads there are the same ones the manifests carry.
            re.compile(
                r"(?ms)^<!-- identity:begin -->.*?^<!-- identity:end -->$",
            ),
            lambda m: identity_block(identity),
            "README identity block",
        ),
        (
            # SECURITY.md must name a concrete address. It previously said "the address
            # published in the repository profile", which makes a reporter hunt for where
            # to send a vulnerability report -- the worst possible friction at the worst
            # possible moment. The rule replaces that vagueness with the derived address.
            # The pattern must match *any* existing address as well as the old vague
            # sentence. An earlier version matched only the sentence, which made it a
            # one-shot migration: after a single run the file held a literal address, the
            # pattern no longer matched, and a later domain change left SECURITY.md
            # advertising the old mailbox while the README advertised the new one. Two
            # published documents contradicted each other and `--check` stayed green,
            # because "the pattern matched nothing" was reported as success. There is a
            # regression guard for this in `tools/test_identity.py`.
            re.compile(
                r"(or by email to the\s+)"
                r"(?:address published in the repository profile|[\w.+-]+@[\w.-]+)"
                r"(\.)"
            ),
            lambda m: f"{m.group(1)}{identity.mail}{m.group(2)}",
            "SECURITY.md contact address",
        ),
    ]


def identity_block(identity: Identity) -> str:
    """Renders the machine-readable identity block for the README."""
    fields = {
        "product": identity.product_name,
        "home": identity.home,
        "repository": identity.repository,
        "tagline": identity.tagline,
        "license": identity.license,
        "contact": identity.mail,
        "container": identity.container,
    }
    if identity.api:
        fields["api"] = identity.api
    body = "\n".join(f"{k}: {v}" for k, v in fields.items())
    return f"<!-- identity:begin -->\n```yaml\n{body}\n```\n<!-- identity:end -->"


def check_security_contact() -> list:
    """A vulnerability reporter must always have somewhere to send a report.

    If SECURITY.md is reworded so that no address can be found, the rewrite rule above
    matches nothing and silently does nothing -- and a security report arrives nowhere.
    Absence of an address is therefore a hard failure rather than "no match".
    """
    path = REPO_ROOT / "SECURITY.md"
    if not path.is_file():
        return ["SECURITY.md is missing, so there is no documented way to report a vulnerability"]

    text = path.read_text(encoding="utf-8", errors="replace")
    if re.search(r"or by email to the\s+[\w.+-]+@[\w.-]+", text):
        return []
    return [
        "SECURITY.md names a contact route but no email address, so a vulnerability "
        "report would arrive nowhere"
    ]


def iter_files():
    for path in sorted(REPO_ROOT.rglob("*")):
        if not path.is_file():
            continue
        if any(p in SKIP_DIRS for p in path.parts):
            continue
        if path.suffix not in TEXT_SUFFIXES:
            continue
        yield path


def ensure_readme_block(identity: Identity, apply: bool) -> tuple:
    """Ensures the README carries an identity block, inserting one if absent.

    A rule that matches nothing is normally a signal, but this one is different: the
    block is *supposed* to be inserted the first time. So it is handled separately and
    reports honestly whether it inserted or updated.
    """
    readme = REPO_ROOT / "README.md"
    if not readme.is_file():
        return 0, ["README.md is missing"]

    text = readme.read_text(encoding="utf-8")
    if "<!-- identity:begin -->" in text:
        return 0, []  # the rewrite rule handles it

    block = identity_block(identity)
    # Insert after the first H1 heading, so the block sits near the top without
    # displacing the title.
    lines = text.splitlines()
    insert_at = 1
    for index, line in enumerate(lines):
        if line.startswith("# "):
            insert_at = index + 1
            break
    lines.insert(insert_at, "\n" + block)
    if apply:
        readme.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 1, []


def generate_metadata(identity: Identity, apply: bool) -> list:
    """Writes publish-ready metadata for the non-Rust registries.

    `package.json` and `pyproject.toml` were previously written by hand at publish time,
    which is how the npm metadata ended up pointing at a personal account for two
    versions. Generating them from the identity means the published URL cannot disagree
    with the repository.
    """
    written = []
    out_dir = REPO_ROOT / "dist-metadata"

    package_json = {
        "name": "compitum",
        "version": "0.2.0",
        "description": identity.tagline,
        "keywords": [
            "arm64", "aarch64", "arm64ec", "arm64x", "abi", "pe", "coff",
            "windows-on-arm", "compatibility", "classifier",
        ],
        "license": identity.license,
        "repository": {"type": "git", "url": f"git+{identity.repository}.git"},
        "homepage": f"{identity.home}#readme",
        "bugs": {"url": f"{identity.repository}/issues"},
        "author": identity.copyright,
        "engines": {"node": ">=14"},
    }

    pyproject = f'''[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "compitum"
version = "0.2.0"
description = """
{identity.tagline}
"""
readme = "README.md"
requires-python = ">=3.8"
license = {{ text = "{identity.license}" }}
authors = [{{ name = "{identity.copyright}" }}]
keywords = ["arm64", "aarch64", "arm64ec", "arm64x", "abi", "pe", "coff", "windows-on-arm"]
classifiers = [
  "Development Status :: 3 - Alpha",
  "Intended Audience :: Developers",
  "Operating System :: POSIX :: Linux",
  "Programming Language :: Python :: 3",
  "Programming Language :: Rust",
  "Topic :: Software Development :: Build Tools",
  "Topic :: System :: Emulators",
]

[project.urls]
Homepage = "{identity.home}"
Repository = "{identity.repository}"
Issues = "{identity.repository}/issues"
'''

    for name, content in (("package.json", json.dumps(package_json, indent=2) + "\n"),
                          ("pyproject.toml", pyproject)):
        path = out_dir / name
        relative = str(path.relative_to(REPO_ROOT))
        if apply:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            written.append((relative, "written"))
        else:
            # In check mode the point is to detect drift, and these files are *generated*,
            # so nothing else would ever notice they are stale -- no rewrite rule targets
            # them. Comparing against what is on disk is the only thing that can catch a
            # `package.json` left behind by an older identity.
            current = path.read_text(encoding="utf-8") if path.is_file() else None
            written.append((relative, "would regenerate" if current != content else "unchanged"))
    return written


def main() -> int:
    apply = "--check" not in sys.argv
    verbose = "--verbose" in sys.argv

    identity = Identity(read_identity(IDENTITY_FILE))

    print(f"{identity.product_name} identity\n")
    print(identity.describe())
    print()

    rule_set = rules(identity)
    hits_per_rule = {description: 0 for _, _, description in rule_set}
    matches_per_rule = {description: 0 for _, _, description in rule_set}
    changes = []

    for path in iter_files():
        original = path.read_text(encoding="utf-8", errors="replace")
        text = original
        for pattern, build, description in rule_set:
            def replace(match):
                # Distinguish "the pattern found nothing" from "the pattern found something
                # that already agreed". Only the second means the repository is in sync, and
                # only a genuine difference is a hit. Collapsing the two is how a one-shot
                # rule came to report success while two documents disagreed.
                replacement = build(match)
                matches_per_rule[description] += 1
                if replacement != match.group(0):
                    hits_per_rule[description] += 1
                return replacement
            text = pattern.sub(replace, text)

        if text != original:
            changes.append(str(path.relative_to(REPO_ROOT)))
            if apply:
                path.write_text(text, encoding="utf-8")
        elif verbose:
            print(f"  unchanged: {path.relative_to(REPO_ROOT)}")

    inserted, problems = ensure_readme_block(identity, apply)
    problems.extend(check_security_contact())
    if inserted:
        note = "identity block inserted" if apply else "identity block would be inserted"
        changes.append(f"README.md ({note})")
        hits_per_rule["README identity block"] = hits_per_rule.get("README identity block", 0) + inserted

    generated = generate_metadata(identity, apply)
    for path, state in generated:
        if state == "would regenerate":
            changes.append(f"{path} (stale)")

    # In check mode nothing is written, so the report must not claim it was. Saying
    # "applied" for a file that was only *examined* is the same defect this project keeps
    # digging out elsewhere: a report that describes an intent rather than an event.
    print("rewrite rules:")
    for _, _, description in rule_set:
        hits = hits_per_rule.get(description, 0)
        matches = matches_per_rule.get(description, 0)
        if not matches:
            state = "no match"
        elif not hits:
            state = "no change"
        else:
            state = "applied" if apply else "would apply"
        print(f"  {description:<32} {hits:>3} hit(s)  [{state}]")

    print()
    print(f"files changed: {len(changes)}" if apply else f"files out of sync: {len(changes)}")
    for path in changes:
        print(f"  {path}")

    print()
    print("generated metadata:" if apply else "generated metadata (check):")
    for path, state in generated:
        print(f"  {path}  [{state}]")

    if problems:
        print()
        for problem in problems:
            print(f"::error::{problem}")
        return 1

    if not apply:
        # In check mode a change means the repository has drifted from identity.toml,
        # which is a failure: a published artefact would carry a stale URL.
        if changes:
            print()
            print(f"::error::{len(changes)} file(s) have drifted from identity.toml")
            print("Run `python3 tools/identity.py` to resynchronize.")
            return 1
        print("\nOK: every reference agrees with identity.toml")
        return 0

    print("\nidentity applied")
    if not identity.has_domain:
        print(
            "\nNOTE: no domain is set, so the repository URL is used as the project home.\n"
            "      When the domain is registered, set `domain` in identity.toml and re-run\n"
            "      this script; every reference updates and the generated metadata follows."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
