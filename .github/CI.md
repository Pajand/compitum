# CI gate reference

The workflow in `.github/workflows/ci.yml` is the only thing standing between a change and a
confident wrong answer. This file explains what each gate is actually protecting, so that a
future maintainer does not delete one thinking it is ceremony.

Run the whole gate locally before pushing:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo metadata --format-version 1 | python3 .github/scripts/check_dependencies.py
python3 .github/scripts/check_secrets.py .
```

---

## Why each gate exists

### `cargo fmt --check`

Not stylistic preference. A diff dominated by unrelated reflowing hides the one line that
matters, and this project's correctness rests on reviewers noticing small things — a bit mask,
a comparison direction, a severity classification.

### `cargo clippy -- -D warnings`

Denied rather than advisory, because clippy has already found **two real bugs** here that no
test caught:

1. **An unsatisfiable bit mask.** The scanner's SME "vector select" check was
   `word & 0xFFE0_FC00 == 0xC002_0000`. The mask discards bit 17, which the constant sets, so
   the comparison could never be true. The check was dead code pretending to detect something.
   Clippy proved it statically.

2. **A `to_owned()` on an already-owned value**, masking an inefficient copy in a hot path.

The first is the important one. It is the same class of mistake as an earlier fabricated SVE2
marker: a plausible-looking encoding check that was never validated. A linter does not know
the ARM architecture reference, but it does know when a comparison is impossible, and that is
enough to catch a guess that was never testable.

### `cargo test`

312 tests. The ones that carry the most weight are not the happy paths:

| Test | What it prevents |
|---|---|
| `decodes_the_real_reference_device` | A shifted `HWCAP2` table reporting CPU features the hardware lacks |
| `failure_direction_is_correct` | The inverted failure-transfer logic, which made every genuine failure untransferable |
| `sve2_is_deliberately_not_claimed` | Manufactured precision reappearing where the evidence does not support it |
| `fuzzing_like_mutations_never_panic` | A crafted PE header aborting the process |
| `overflow_offsets_do_not_panic` | Offset arithmetic wrapping and reading attacker-chosen bytes |
| `an_unknown_option_is_an_error_never_ignored` | Silently ignoring `--hedless` and producing a verdict the user did not ask for |

### `check_dependencies.py`

The workspace must contain **zero** third-party crates: the build works offline and the supply
chain has nothing to compromise. That rule is one line to break by accident, so it is a build
failure rather than a convention.

### E2E routing checks (`check_routing.py`)

Four fixtures, four distinct routes, and a per-class invariant suite. The invariant that earns
its keep: **a route claiming to be native must name no backend.** That is the property the
whole project optimises for, and a regression that quietly loaded a translator for a native
binary would be invisible in the output while destroying the value proposition.

### Exit-code contract

`verify` distinguishes *"it will not run here"* (exit 2) from *"I could not tell you"*
(exit 1). A pipeline must be able to tell those apart; treating an unfavourable verdict as a
failure would make the tool unusable in CI, and treating a refusal to answer as a verdict
would make it dangerous.

### `check_ledger.py`

Asserts the defect found during development: `verify` stored a route derived from the ABI
family rather than the route it decided, so a binary **refused** for missing SME/SVE was
recorded as `native`. A ledger containing a wrong verdict is worse than an empty one. The
script also rejects a record that claims both `blocked` and `fully_native`, which cannot both
be true.

### `check_host.py`

The host report is the input to every decision. The check enforces that page size is a power
of two (a misread auxiliary vector would corrupt the page-size compatibility axis), that the
AArch64 baseline is always present (its absence means the decoding is wrong, not that the CPU
is unusual), and that the feature list is sorted and de-duplicated — because the host class tag
is computed from it, and an unsorted list would make two identical machines look different.

### `check_locales.py` and `check_template.py`

A locale is data, so it can be validated without a human reading it. Missing keys are
**permitted**: a partially finished translation must stay usable, falling back to English per
key. Only *obsolete* keys fail the build, because those mislead the next translator.

The template check is subtler. `locales export` must emit **empty** values. A non-empty value
would leak English text into the skeleton, and a translator would leave it in place believing
it was required — producing a "translation" that is silently still English.

### `check_secrets.py`

A token pushed to a public repository is compromised within minutes, because scrapers watch
public pushes specifically for them. The check is conservative on purpose: it matches
credential *shapes*, not high-entropy strings, and it skips its own test fixtures, because a
scanner people learn to ignore is a scanner that gets disabled.

---

## Publish order

`tools/publish_order.py` computes the order crates must be published in, from the real
dependency graph:

```
1. compitum-digest     no workspace dependencies
2. compitum-json       no workspace dependencies
3. compitum-i18n       requires compitum-json
4. compitum-isa        requires compitum-json
5. compitum-pe         requires compitum-isa, compitum-json
6. compitum-router     requires compitum-isa, compitum-json, compitum-pe
7. compitum-oracle     requires compitum-digest, compitum-isa, compitum-json,
                       compitum-pe, compitum-router
8. compitum-cli        requires everything above
```

**The order is load-bearing.** crates.io cannot resolve a dependency that does not exist yet,
and a rejected publish permanently consumes the version number — there is no retry under the
same version. Computing the order rather than remembering it is the difference between one
attempt and a string of burned versions.

---

## What CI deliberately does not do

- **It does not run emulators.** This project classifies and decides; it does not execute. A
  gate that installed FEX and Box64 would be testing those projects, not this one.
- **It does not require a Windows machine or a real `.exe`.** The fixtures are structurally
  valid PE images, so the parser is exercised against real structure without needing a
  Microsoft toolchain in CI.
- **It does not publish.** Publishing is manual and irreversible; a workflow that could
  publish by accident is a workflow that eventually will.
