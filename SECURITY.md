# Security Policy

## Reporting a vulnerability

Do **not** open a public issue for a security problem.

Report privately through GitHub's [security advisory
form](https://github.com/Pajand/compitum/security/advisories/new), or by email to the
address published in the repository profile. Include:

- what you can do that you should not be able to,
- the smallest input that demonstrates it,
- the commit or version you tested,
- and your assessment of impact.

You will get an acknowledgement, an honest assessment of severity, and credit in the
advisory unless you prefer otherwise.

## Threat model

COMPITUM processes **untrusted binary input**. That fact drives the entire security
posture, and it is worth stating plainly what is and is not in scope.

### In scope

| Threat | Why it matters | Control |
|---|---|---|
| A malformed PE file panics the parser | A compatibility tool that crashes cannot even report *why* it failed | Every read is bounds-checked; no `unsafe`; no indexing that can panic |
| A crafted header causes an integer overflow | In release builds an overflow wraps silently and could read attacker-chosen memory | All range arithmetic is checked; see `reader::checked_end` |
| A huge file exhausts memory | Denial of service against a CI runner | The parser reads a caller-provided slice and never allocates proportionally to a declared size |
| A crafted import table causes unbounded work | Denial of service | Thunk walks are capped; descriptor walks are capped |
| Path traversal when writing Oracle records | Writing outside the intended ledger | Record paths are constructed, never taken verbatim from input |

### Out of scope

- **Executing** the binaries COMPITUM classifies. This tool reads and reports; it never
  loads or runs an image, and it does not include an emulator.
- The security of the emulators and compatibility layers COMPITUM *routes to*. Those are
  separate projects with their own policies.
- Denial of service by supplying an absurdly large **number** of valid files.

## Guarantees the code makes

These are enforced mechanically, not by good intentions:

1. **No `unsafe` code.** Every crate begins with `#![forbid(unsafe_code)]`. A build that
   adds an `unsafe` block fails.
2. **No panics on malformed input.** The test suite includes mutation testing that feeds
   hundreds of deliberately corrupted headers through the parser.
3. **Zero third-party dependencies.** There is no supply chain to compromise: the
   workspace builds offline with `cargo build` and pulls nothing.
4. **No network access at parse time.** Classification is a pure function of bytes.

## Dependencies

COMPITUM has **no** runtime dependencies, by design. There is no transitive tree to audit
and no automatic update path that could introduce one.

If that ever changes, the change must be justified in the roadmap's decision log and must
state why the functionality could not be written in a few hundred lines.

## Supply-chain hardening for maintainers

- Hardware-key two-factor authentication is required on every namespace account:
  crates.io, npm, PyPI, and the domain registrar.
- Recovery codes are stored in an encrypted vault, never in the repository.
- Publishing credentials are injected as environment variables at publish time and are
  never written to a file that is committed.
- `cargo publish` is run from a clean checkout of a tagged commit.
