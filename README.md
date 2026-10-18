# COMPITUM

**The universal ARM64 compatibility layer.**

COMPITUM answers one question no tool in the world answers today:

> *Will this Windows ARM64 binary run natively on this machine, or does it need translation?*

And then it tells you exactly why.

```console
$ compitum verify ./native-arm64.exe
COMPITUM — ./native-arm64.exe
Verdict
  Route        NATIVE
  internal       native
  Confidence     100%
  Emulation      none
  expected       100% of native
Explanation
  Runs natively: every CPU feature this image requires is present, so no instruction is
  translated.
  Execute directly on the CPU. No translator is loaded, so every instruction runs at
  hardware speed.

$ compitum verify ./hybrid-arm64ec.exe
COMPITUM — ./hybrid-arm64ec.exe
Verdict
  Route        HYBRID
  internal       fex_partial
  Confidence     100%
  Emulation      fex
  expected       70-90% of native
Explanation
  Runs hybrid: the ARM64 functions execute natively and the x86-64 functions embedded in
  the same image are translated on demand.
Reason codes
  [!] architecture_hybrid: the AArch64 functions run natively; the embedded x86-64
      functions require a translator
```

---

## Why this exists

On **2026-10-16** NVIDIA shipped RTX Spark — the first serious ARM64 desktop CPU in the Windows
ecosystem. Overnight, a large fraction of future Windows software began moving to ARM64.

But "ARM64 binary" is not one thing. It is three structurally different things:

| Flavour | `Machine` | Contains | Executes natively? |
|---|---|---|---|
| ARM64 | `0xAA64` | pure AArch64 | **yes** |
| ARM64EC | `0xA641` | AArch64 **and x86-64** | no — hybrid |
| ARM64X | `0xA64E` | both slices, load-time dispatch | yes, after slice selection |
| AMD64 | `0x8664` | x86-64 only | no |

Every compatibility tool in this space collapses that table to a single row. COMPITUM does not.

**COMPITUM makes a routing decision. Everyone else has a single path.**

### What that decision is worth

An ARM64EC image contains AArch64 code *and* x86-64 code in one file. NVIDIA's own porting
guide describes the mechanism:

> "When execution transfers between A.cpp and x86_64-compiled B.cpp, marshalling code maintains
> compatibility."

So an ARM64EC binary genuinely cannot run natively — but it is *also* not an x86-64 binary,
because most of its code is already ARM64. A tool that treats "hybrid" as "emulate everything"
translates code that was already native, and loses most of the available performance.

| Route | What gets translated | Expected throughput |
|---|---|---|
| `native` | nothing | **100%** |
| `pick_native_slice` | nothing, after slice selection | **100%** |
| `fex_partial` | only the x86-64 blocks | 70-90% |
| `box64_full` / `fex_full` | every instruction | 20-60% |
| `wow64` | every instruction, 32-bit | 20-40% |
| `refused` | impossible — with a reason naming the obstacle | — |

Keeping `fex_partial` distinct from `fex_full` is where the performance comes from. It is the
difference between a tool that classifies a binary and a tool that understands it.

Every route carries its reasons as machine-readable codes plus an English sentence, so a verdict
can be **audited rather than merely believed**.

---

## The three things nobody else does

**1. PE-aware ABI classification** — reads the real `IMAGE_FILE_MACHINE` type, import table,
subsystem and ISA usage out of the binary, keeping the three ARM64 flavours distinct.

**2. Host capability oracle** — probes the *actual* CPU feature set, memory page size and kernel
ABI, then compares it against what the binary requires. A refusal names the missing feature
rather than emitting a mystery fault.

**3. Evidence-based routing, and the Oracle** — every decision is justified and recorded. That
compatibility dataset is the durable asset, and it grows from ordinary use.

### Measured divergence

The development device and the reference target do not agree:

```text
HOST (an ordinary ARM64 phone)
  HWCAP  = 0x00000000ffbfffff
  HWCAP2 = 0x0000000000022181
  has  : I8MM, BTI, FRINT, DCPODP, FLAGM2
  lacks: SVE, SVE2, SME, MTE, BF16

TARGET (NVIDIA RTX Spark, from its porting guide)
  has  : SVE2, SME, MTE, VIRT
```

A binary compiled with SME matrix instructions for RTX Spark **faults** on a device like this
one. COMPITUM reports that before you run it:

```console
$ compitum verify ./needs-sve-sme.exe --verbose
  Route        REFUSED
  Confidence     60%
  Cannot run: isa features missing. this host does not implement: sve, sme.
Reason codes
  [x] isa_features_missing: this host does not implement: sve, sme (60% confidence)
  [!] isa_evidence_weak: the missing features were identified by scanning machine code
      rather than from metadata, so this verdict may be a false negative
```

Note the honesty: the verdict is **60% confident**, because the finding came from scanning code
rather than from declared metadata. A scan cannot see run-time-generated code, and the tool says
so instead of presenting a guess as a fact.

---

## Commands

| Command | Purpose |
|---|---|
| `compitum host` | Report this machine's ARM64 capabilities, and which are absent |
| `compitum inspect <binary>` | Classify a binary without consulting the host |
| `compitum verify <binary>` | Decide whether it can run here, and why |
| `compitum oracle <sub>` | Read and write the compatibility ledger |
| `compitum locales <sub>` | List, check and export translation catalogs |

Machine-readable output for a pipeline:

```console
$ compitum verify ./app.exe --json | jq -r .route
native
```

### Exit codes

A tool used in CI must communicate its finding through its status, not only its text.

| Code | Meaning |
|---|---|
| `0` | Succeeded; the verdict was favourable or not required |
| `1` | Could not be carried out — bad input, unreadable file, unknown option |
| `2` | `verify` ran successfully and the verdict was **not** favourable |

Distinguishing `1` from `2` matters: *"it will not run here"* is a result, while *"I could not
tell you"* is a failure.

---

## Guarantees

- **English-only product surface.** All code, output and documentation is English.
- **Full localization engine.** Every human-facing string is translatable; adding a language
  means dropping a JSON file into `locales/`. No recompilation. Machine output is never
  translated, so a consumer parsing `route` cannot break when a language is added.
- **Zero third-party dependencies.** `cargo build` works fully offline, and CI fails if a
  dependency ever enters the graph.
- **No `unsafe`.** `#![forbid(unsafe_code)]` in every crate, enforced by the compiler.
- **No panics on malformed input.** A PE file is hostile input; 500 deliberately corrupted
  headers are fed through the parser by the test suite.
- **Honest failure.** Never a bare `SIGILL`. Always a reason code, a confidence level, and a
  sentence naming the obstacle.

### Verified

```console
$ cargo test
  325 tests passing, including 19 doctests
$ cargo clippy --all-targets --all-features -- -D warnings
  0 diagnostics
$ cargo build --release
  0 warnings
```

CI runs on **ARM64 and x86_64**, and every route is checked against a per-class invariant suite:
a route claiming to be native must name no translation backend, and a refusal must not predict
throughput.

---

## Building

Requires Rust 1.78 or later. No network access is needed.

```console
$ cargo build --release
$ ./target/release/compitum --help
```

---

## Architecture

```text
compitum (CLI)
  ├── compitum-oracle    compatibility ledger   (the moat)
  ├── compitum-router    ABI routing engine     (the decision)
  │     ├── compitum-pe    PE classification    (the facts)
  │     └── compitum-isa   host capability      (the reality)
  ├── compitum-digest    SHA-256                (content addressing)
  ├── compitum-json      dependency-free JSON   (the format)
  └── compitum-i18n      localization engine    (the reach)
```

### Documentation

| Document | Contents |
|---|---|
| [`docs/RELEASE.md`](docs/RELEASE.md) | The release procedure, and why the publish order is load-bearing |
| [`docs/NAMING.md`](docs/NAMING.md) | Why the project is called COMPITUM, and the evidence against the alternatives |
| [`docs/NAME-ACQUISITION.md`](docs/NAME-ACQUISITION.md) | How to claim and defend the name across every registry |
| [`.github/CI.md`](.github/CI.md) | What each CI gate protects, and what it deliberately does not do |
| [`roadmap/ROADMAP.md`](roadmap/ROADMAP.md) | The plan, the proof-of-work log, and the decision log |
| [`SECURITY.md`](SECURITY.md) | Threat model for a tool that processes untrusted binaries |
| [`TRADEMARK.md`](TRADEMARK.md) | What you may do with the name |

---

## Status

**Phase 0 complete** — six implemented crates, 325 tests, a green CI gate on ARM64 and x86_64,
and no third-party dependencies.

The next phase integrates the execution bridge: Wine (bionic-native) for NT system-call
translation, and FEX as the ARM64EC x86-64 backend.

---

## License

Dual-licensed under Apache-2.0 OR MIT, at your option.
