#!/usr/bin/env python3
"""
Regression tests for `tools/identity.py`.

Run with:

    python3 tools/test_identity.py

Every test here corresponds to a defect that was actually observed while building the tool.
They are not hypothetical: this file exists because the domain-swap mechanism reported
success while two published documents contradicted each other, and because a report that
describes an intent instead of an event is this project's most frequently recurring bug.

Only the standard library is used, so the tests run wherever the repository does.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
IDENTITY_PY = REPO_ROOT / "tools" / "identity.py"


def legacy_sentence() -> str:
    """The exact sentence SECURITY.md carried before the address was made concrete.

    Assembled from fragments rather than written literally, and that is not an accident.
    `tools/identity.py` scans every text file in the repository -- this one included --
    because the whole point of its SECURITY.md rule is that a stale address cannot survive
    anywhere in the tree. A literal fixture here would be a live hit, so the tool would
    rewrite the very input this test depends on, and the test would silently stop testing
    what it claims to. Building the sentence at runtime keeps the tool's coverage total:
    nothing in the repository is exempt, and the migration is still exercised for real.

    There is a guard for this in `TestRepositoryHygiene`.
    """
    return "or by email to the " + "address published in the " + "repository profile."


def stale_address_fixture() -> str:
    """A placeholder address, likewise assembled so it cannot be rewritten in place."""
    return "old-address" + "@" + "example.invalid"

# Files the tool is expected to rewrite or generate. Copied into each sandbox so a test
# never writes into the working tree.
TRACKED = [
    "identity.toml",
    "Cargo.toml",
    "README.md",
    "SECURITY.md",
]


class Sandbox:
    """A throwaway copy of the files the tool touches."""

    def __init__(self) -> None:
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="compitum-identity-test-"))
        for name in TRACKED:
            source = REPO_ROOT / name
            if source.is_file():
                shutil.copy2(source, self.dir / name)

    def close(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def path(self, name: str) -> pathlib.Path:
        return self.dir / name

    def read(self, name: str) -> str:
        return self.path(name).read_text(encoding="utf-8")

    def set_domain(self, domain: str) -> None:
        text = self.read("identity.toml")
        lines = []
        for line in text.splitlines():
            if line.startswith("domain") and "=" in line:
                line = f'domain = "{domain}"'
            lines.append(line)
        self.path("identity.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def run(self, *args: str) -> subprocess.CompletedProcess:
        # The tool resolves the repository root from its own location, so the sandbox needs a
        # `tools/` directory holding the script. Copying it means the sandbox is genuinely
        # self-contained and no test can touch the real tree.
        (self.dir / "tools").mkdir(exist_ok=True)
        shutil.copy2(IDENTITY_PY, self.dir / "tools" / IDENTITY_PY.name)
        return subprocess.run(
            [sys.executable, str(self.dir / "tools" / IDENTITY_PY.name), *args],
            capture_output=True,
            text=True,
            cwd=self.dir,
        )


class TestDomainSwap(unittest.TestCase):
    """The whole point of the tool: change one field, everything follows."""

    def setUp(self) -> None:
        self.box = Sandbox()

    def tearDown(self) -> None:
        self.box.close()

    def test_swap_updates_every_reference(self) -> None:
        self.box.set_domain("example.test")
        result = self.box.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        self.assertIn("example.test", self.box.read("Cargo.toml"))
        self.assertIn("home: https://example.test", self.box.read("README.md"))

    def test_an_empty_domain_falls_back_to_the_repository(self) -> None:
        # While the domain is pending, no artefact may advertise a link that does not
        # resolve. The repository URL is the fallback, and it always resolves.
        result = self.box.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("https://github.com/", self.box.read("Cargo.toml"))

    def test_the_api_is_not_inferred_from_the_domain(self) -> None:
        # Registering a domain and running an API are different facts. Deriving one from the
        # other publishes a dead endpoint the moment the domain is bought.
        self.box.set_domain("example.test")
        self.box.run()
        readme = self.box.read("README.md")
        self.assertNotIn("api.example.test", readme)
        self.assertNotIn("api:", readme)

    def test_the_contact_address_is_not_inferred_from_the_domain(self) -> None:
        # A security report sent to a mailbox that does not exist yet is a harm with no
        # upside, so `contact_email` is authoritative and never derived.
        self.box.set_domain("example.test")
        self.box.run()
        self.assertIn("compitum.dev@gmail.com", self.box.read("README.md"))
        self.assertNotIn("hello@example.test", self.box.read("README.md"))


class TestSecurityContact(unittest.TestCase):
    """A vulnerability reporter must always have somewhere to send a report."""

    def setUp(self) -> None:
        self.box = Sandbox()

    def tearDown(self) -> None:
        self.box.close()

    def test_a_literal_address_is_refreshed_on_a_later_domain_change(self) -> None:
        # THE REGRESSION GUARD.
        #
        # The first version of this rule matched only the old vague sentence ("the address
        # published in the repository profile"). That made it a one-shot migration: after one
        # run the file held a literal address, the pattern stopped matching, and a later
        # contact change left SECURITY.md advertising the old mailbox while the README
        # advertised the new one -- with `--check` still green, because "matched nothing" was
        # reported as success.
        security = self.box.path("SECURITY.md")
        security.write_text(
            "Report privately through the advisory form, "
            + "or by email to the "
            + stale_address_fixture()
            + ". Include:\n",
            encoding="utf-8",
        )
        result = self.box.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        text = self.box.read("SECURITY.md")
        self.assertNotIn(stale_address_fixture(), text)
        self.assertIn("compitum.dev@gmail.com", text)

    def test_the_legacy_vague_sentence_is_still_migrated(self) -> None:
        security = self.box.path("SECURITY.md")
        security.write_text(legacy_sentence() + "\n", encoding="utf-8")
        self.box.run()
        text = self.box.read("SECURITY.md")
        self.assertNotIn("address published in the " + "repository profile", text)
        self.assertIn("compitum.dev@gmail.com", text)

    def test_a_removed_address_is_a_failure_not_a_silent_no_op(self) -> None:
        # If SECURITY.md is reworded so no address can be found, the rewrite rule would match
        # nothing and quietly do nothing. The tool must refuse instead.
        self.box.path("SECURITY.md").write_text(
            "Report privately through the advisory form.\n", encoding="utf-8"
        )
        result = self.box.run()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("nowhere", result.stdout)


class TestCheckMode(unittest.TestCase):
    """`--check` gates CI, so it must not write and must not lie."""

    def setUp(self) -> None:
        self.box = Sandbox()

    def tearDown(self) -> None:
        self.box.close()

    def test_check_writes_nothing(self) -> None:
        before = {name: self.box.read(name) for name in TRACKED}
        self.box.run("--check")
        for name, content in before.items():
            self.assertEqual(self.box.read(name), content, f"--check modified {name}")

    def test_check_passes_immediately_after_apply(self) -> None:
        self.box.run()
        result = self.box.run("--check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_check_fails_when_a_reference_drifts(self) -> None:
        self.box.run()
        cargo = self.box.path("Cargo.toml")
        cargo.write_text(
            cargo.read_text(encoding="utf-8").replace(
                'homepage = "', 'homepage = "https://stale.invalid'
            ),
            encoding="utf-8",
        )
        result = self.box.run("--check")
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_check_mode_does_not_claim_it_applied_anything(self) -> None:
        # The first version printed "[applied]", "inserted" and "written" while writing
        # nothing. A report must describe an event, not an intent.
        self.box.set_domain("example.test")
        result = self.box.run("--check")
        self.assertNotIn("[applied]", result.stdout)
        self.assertNotIn("[written]", result.stdout)
        self.assertIn("[would apply]", result.stdout)

    def test_a_rule_that_matches_nothing_says_so_rather_than_reporting_a_hit(self) -> None:
        self.box.run()  # bring the tree into sync first
        result = self.box.run("--check")
        self.assertIn("[no change]", result.stdout)


class TestIdempotency(unittest.TestCase):
    """Running the tool twice must be the same as running it once, or CI flaps."""

    def setUp(self) -> None:
        self.box = Sandbox()

    def tearDown(self) -> None:
        self.box.close()

    def test_apply_is_idempotent(self) -> None:
        self.box.set_domain("example.test")
        self.box.run()
        first = {name: self.box.read(name) for name in TRACKED}
        self.box.run()
        second = {name: self.box.read(name) for name in TRACKED}
        self.assertEqual(first, second)

    def test_generated_metadata_is_compared_not_merely_rewritten(self) -> None:
        # Generated files are targeted by no rewrite rule, so only an on-disk comparison can
        # catch a `package.json` left behind by an older identity.
        self.box.set_domain("example.test")
        self.box.run()
        generated = self.box.path("dist-metadata/package.json")
        self.assertTrue(generated.is_file(), "metadata was not generated")

        generated.write_text('{"name": "compitum"}\n', encoding="utf-8")
        result = self.box.run("--check")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("stale", result.stdout)


class TestRepositoryHygiene(unittest.TestCase):
    """The tool scans the real tree, so the real tree must not fight it."""

    def test_no_committed_file_contains_the_legacy_sentence(self) -> None:
        # If a file carried the old wording literally, the tool would rewrite it on the next
        # run -- including this test file, which would then no longer test what it claims to.
        # Any fixture that needs the phrasing must build it at runtime, as this file does.
        needle = legacy_sentence()
        for path in REPO_ROOT.rglob("*"):
            if not path.is_file():
                continue
            if any(part in {"target", ".git", "node_modules"} for part in path.parts):
                continue
            if path.suffix not in {".md", ".toml", ".json", ".yml", ".yaml", ".rs", ".txt", ".sh", ".py"}:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            self.assertNotIn(
                needle,
                text,
                f"{path.relative_to(REPO_ROOT)} contains the legacy sentence literally, "
                "so tools/identity.py would rewrite it on the next run",
            )

    def test_the_real_repository_is_in_sync(self) -> None:
        # The same command CI runs, so a drift cannot be discovered only during a release.
        result = subprocess.run(
            [sys.executable, str(IDENTITY_PY), "--check"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
