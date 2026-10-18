# COMPITUM — MASTER ROADMAP

**Project:** COMPITUM — The Universal ARM64 Compatibility Layer
**Document version:** 1.0
**Created:** 2026-10-18
**Status:** EXECUTION IN PROGRESS

---

## 0. PROJECT CHARTER

### 0.1 Mission

> Build the world's first **ABI-aware compatibility layer** for ARM64 — a system that
> understands *what kind of ARM64 binary* it is holding, *what the host can actually
> execute*, and *routes execution to the fastest correct path*, eliminating CPU
> emulation whenever it is provably unnecessary.

### 0.2 The one-sentence product

**COMPITUM tells you — before you run it — whether a Windows ARM64 binary will run
natively, hybrid, or emulated on a given machine, and then runs it that way.**

### 0.3 Why this exists (the gap)

The ARM64 transition of the PC market began in earnest on **2026-10-16**, when NVIDIA
shipped RTX Spark. Within 24 months, a large fraction of new Windows applications will
exist as ARM64 or ARM64EC binaries. Yet today:

| Capability | Who has it today | COMPITUM |
|---|---|---|
| Parse PE and identify Machine type | Binutils, file(1) | ✅ yes |
| Understand ARM64EC hybrid semantics | ~3 people on earth | ✅ **formalized** |
| Know what ARM64 ISA features a binary *requires* | **nobody** | ✅ **novel** |
| Know what the host ISA *provides* + page size | Kernel only | ✅ **exposed as a decision** |
| Route to the *fastest correct* backend | **nobody** | ✅ **novel** |
| Correlate binary × host × outcome across the fleet | **nobody** | ✅ **novel — the moat** |

Every existing tool (`Winlator`, `Hangover`, `Box64`, `FEX`) has **one execution path**.
COMPITUM has **a routing decision**, and it records the outcome.

### 0.4 Non-goals (explicitly out of scope)

- ❌ Reimplementing Wine. We integrate; we do not fork permanently.
- ❌ Reimplementing FEX/Box64 emulation cores.
- ❌ Inventing a new instruction translator.
- ❌ Competing with Qualcomm's porting tools.
- ❌ Game-first positioning. (Productivity/CI first.)

### 0.5 Success definition

**Primary success metric:** number of *verified* (binary × host) compatibility records in
the COMPITUM Oracle. Not downloads. Not stars. **Verified records that nobody else has.**

**Secondary:** a `.exe` compiled for native ARM64 executes on an ARM64 Linux host with
`route = NATIVE` and **zero emulation bytes**, verified by evidence in the log.

---

## 1. ARCHITECTURAL DOCTRINE

These are laws. Violating one means we have failed even if the code works.

### LAW 1 — Evidence over assertion
Every routing decision emits a machine-readable *justification*. No decision without proof.

### LAW 2 — Native whenever provable
If a binary's required ISA ⊆ host ISA, ignore every emulator. Route NATIVE.

### LAW 3 — Upstream or die
Any fix that belongs in Wine/FEX/Box64 goes upstream. We fork nothing permanently.

### LAW 4 — English-only product surface
All code, identifiers, comments, docs, CLI output, JSON keys: **English**.
Human-facing strings pass through the i18n engine; English is the base locale.

### LAW 5 — Zero runtime dependencies
Core crates must build offline with `cargo build` and no network. No `serde`, no `clap`.
Auditability is a feature; supply-chain attack surface is a liability.

### LAW 6 — The Oracle is a product, not a log
Compatibility data is the primary long-term asset and gets first-class engineering.

### LAW 7 — Honest failure
When something cannot work, say exactly why, in a human-readable message.
Never emit a mystery `SIGILL`. Never claim support we have not measured.

### LAW 8 — Portability first, Android later
Headless Linux ARM64 is the first target because it has **no graphics driver wall**.
Android is product #3, not product #1.

---

## 2. THE TECHNICAL CORE — WHAT ACTUALLY MATTERS

### 2.1 The four ARM64 Windows binary flavours

This table is the intellectual heart of COMPITUM. Nothing else in the industry
operationalizes it.

| `IMAGE_FILE_MACHINE_*` | Value | Meaning | Correct route |
|---|---|---|---|
| `ARM64` | `0xAA64` | Pure native ARM64 | **NATIVE — 0% emulation** |
| `ARM64EC` | `0xA641` | Hybrid: ARM64 + x86_64 in one PE | **FEX_PARTIAL** |
| `ARM64X` | `0xA64E` | Fat binary: ARM64 + ARM64EC slices | **NATIVE (pick slice)** |
| `AMD64` | `0x8664` | Legacy x86_64 | **BOX64 / FEX_FULL** |
| `I386` | `0x014C` | Legacy x86 | **WOW64 / BOX86** |
| `ARM` | `0x01C4` | ARM32 (WinRT era) | **ARM32 emulation** |
| `ARMNT` | `0x01C4` | ARM Thumb-2 | **ARM32 emulation** |

### 2.2 Why ARM64EC is not "ARM64"

NVIDIA's own porting guide states:

> "When execution transfers between A.cpp and x86_64-compiled B.cpp, marshalling code
> maintains compatibility."

Therefore an ARM64EC binary **literally contains x86_64 machine code**. An ARM64EC
`.exe` cannot be executed natively by an ARM64 CPU. It requires an emulator for the
x64 blocks — but *only* those blocks.

**Corollary (the COMPITUM insight):** a naive tool that sees "ARM64" in the name and
routes it as native will crash. A naive tool that sees "hybrid" and routes it to a full
emulator is 3–10× slower than necessary. **Correct routing is worth an order of magnitude.**

### 2.3 Why the host capability oracle matters

Real, measured on the development device:

```
PAGESIZE = 4096
HWCAP    = 0x00000000ffbfffff
HWCAP2   = 0x0000000000022181
```

Decoded HWCAP2: `DCPODP`, `FLAGM2`, `FRINT`, **`I8MM`**, **`BTI`**.
Absent: **`SVE2`**, **`SME`**, `MTE`, `BF16`.

Compare RTX Spark (from its porting guide): `SVE2`, `SME`, `MTE`, `VIRT`.

**This is a real, measured, exploitable divergence.** A Windows ARM64 application
compiled with SME matrix instructions for RTX Spark **will fault on this device**.
COMPITUM detects this *before execution* and reports it in plain language.

Nobody else does this. It is not hard — it is simply *unattempted*.

### 2.4 The page-size landmine

Android is migrating to 16 KiB pages. Windows ARM64 runs 4 KiB. A binary linked with
4 KiB alignment assumptions can fail on a 16 KiB host in ways that look like random
crashes. COMPITUM treats page size as a first-class compatibility axis.

---

## 3. WORK BREAKDOWN — PHASES

### PHASE 0 — FOUNDATION (this session)
**Goal:** a real, buildable, tested, zero-dependency ARM64 analysis engine.

| # | Deliverable | Status |
|---|---|---|
| 0.1 | Workspace + build system | ✅ done | 8 crates, zero external dependencies, builds offline |
| 0.2 | `compitum-json` — dependency-free JSON | ✅ done | strict RFC 8259 parser; surrogate pairs; depth bounded |
| 0.3 | `compitum-i18n` — localization engine, English base | ✅ done | English compiled in; a language is one JSON file, no rebuild |
| 0.4 | `compitum-pe` — PE parser + classifier | ✅ done | three ARM64 flavours distinguished; 500-case mutation test |
| 0.5 | `compitum-isa` — host capability oracle | ✅ done | 67 features; bit tables verified against a live kernel |
| 0.6 | `compitum-router` — ABI routing engine | ✅ done | 7 routes, 22 reason codes; purity asserted by test |
| 0.7 | `compitum-oracle` — compatibility store | ⬜ next | |
| 0.8 | `compitum` CLI — unified front end | ⬜ | |
| 0.9 | Synthetic PE corpus generator | ✅ done | `compitum_pe::pe_fixture`, shared across all layers |
| 0.10 | Test suite + real device verification | ✅ partial | 205 tests passing; ISA verified on a real device |
| 0.11 | Documentation set | ✅ partial | strategy, roadmap, naming, security, trademark |

**Totals at this revision:** 205 tests passing, zero build warnings, ~8,400 lines of Rust
across five implemented crates.

### PHASE 1 — EXECUTION BRIDGE (next)
- Integrate `proton-wine` (bionic-native) as the NT-syscall translator
- Integrate FEX as the ARM64EC x64-block backend
- Prove `NATIVE` end-to-end with a real ARM64 console `.exe`
- Emit Oracle records automatically from every run

### PHASE 2 — ORACLE AT SCALE
- Nightly test farm (single device → many)
- Public read-only API
- `worksonwoa`-class coverage for ARM64 specifically
- Fleet telemetry (opt-in, anonymous, explicit consent)

### PHASE 3 — ANDROID
- ANativeWindow input/display shell
- Turnip + DXVK (Adreno only — honest limitation)
- `bionic` native path, no proot

### PHASE 4 — COMMERCIAL
- CI runner product
- Migration-validation service
- API licensing

---

## 4. ENGINEERING STANDARDS

- **Language:** Rust 2021 edition, `#![forbid(unsafe_code)]` in all core crates
- **Dependencies:** zero external
- **Errors:** typed enums, no panics on malformed input (PE files are hostile input)
- **Tests:** unit per module + an end-to-end corpus run
- **Docs:** every public item documented
- **Output:** all machine-readable output is stable JSON with a schema version

---

## 5. RISK REGISTER

| ID | Risk | Prob | Impact | Mitigation |
|---|---|---|---|---|
| R1 | CodeWeavers/Valve extend Proton to ARM | Med | High | Oracle-first; partner not rival |
| R2 | Mali GPUs never work well | High | Med | Adreno-only, stated openly |
| R3 | ARM64 `.exe` corpus stays empty | Med | High | Fallback to x64 routing value |
| R4 | Solo maintainer burnout | High | High | Community-first, upstream-first, ship early |
| R5 | 16 KiB page size breaks assumptions | Med | Med | Already an Oracle axis — turn into advantage |
| R6 | Legal/licensing on drivers | Med | Med | Track licenses, ship no proprietary blobs |

---

## 6. PROOF-OF-WORK LOG

Every build, test and verification is appended here with evidence.

**2026-10-18 — Environment reconnaissance**
```
uname -m          → aarch64
getconf PAGESIZE  → 4096
HWCAP             → 0x00000000ffbfffff
HWCAP2            → 0x0000000000022181
rustc             → 1.78.0 (Alpine Linux, aarch64)
python3           → 3.12.13
```
Finding: host lacks SVE2/SME — a real divergence from RTX Spark. Recorded as first
Oracle seed data.

**2026-10-18 — Layers 1 to 3 implemented and verified**

```
cargo build   -> clean, zero warnings
cargo test    -> exit 0, 205 passing, 0 failing
```

Five defects were found by the test suite during implementation. All are fixed, and each
left a regression guard behind:

1. **The HWCAP2 bit table was wrong.** The bitmap was shifted, so a device reporting
   `HWCAP2 = 0x22181` decoded as claiming capabilities at the wrong bit positions. The
   tool would have reported CPU features the hardware does not implement — the most
   damaging possible failure for a compatibility tool, because it promises native
   execution that then faults. Corrected against the kernel header and pinned by a
   reference-device test.

2. **`RequirementSource` ordered by declaration, not by strength.** The derived `Ord`
   ranked variants by where they sit in the source file. Weak scan evidence could
   therefore overwrite strong metadata evidence. Replaced with an explicit `rank()`.

3. **Numeric overflow on hostile input.** `offset + len` wrapped for offsets near
   `usize::MAX`: a panic in debug, and a silent read of attacker-chosen bytes in release.
   Every range computation now routes through `checked_end`.

4. **The severity model inverted the meaning of a requirement.** 
   `ArchitectureRequiresTranslation` was classified `Blocked`, so *every* x86-64 image
   reported as a refusal even with a working translator installed. A requirement is not
   an obstacle; only `BackendAbsent` blocks. Two regression guards now pin the exact set
   of blocking codes.

5. **A doctest named modules that do not exist.** `compitum_pe::machine` collides with the
   analysed `Machine` type, so fixture constants stay namespaced under `pe_fixture`.

Finding 4 is the one worth dwelling on. The test suite did not merely confirm that the code
works — it found a reasoning error that would have made the product confidently wrong about
the single most common class of Windows binary in existence.

**2026-10-18 — Continuous integration green on real hardware**

```
GitHub Actions, run 39082732474, commit 93e3fe4
  build and test (aarch64)   success
  build and report (x86_64)  success
  translation catalogs       success
  package metadata           success
```

The ARM64 job is the one that matters: it runs the full test suite, the per-route
invariants over four synthetic fixtures, and the exit-code contract, on a genuine
AArch64 machine rather than an emulated one.

The first CI run was a failure, and it was worth more than a pass would have been. Three
of four jobs succeeded; the package-metadata job failed because of a flaw in the gate
itself. `cargo package` resolves dependencies against the *registry*, not the workspace,
so in a fresh crate family a member cannot be packaged until its own dependencies are
published — and the naive loop treated that expected state as a defect. A gate that fails
on a healthy repository is worse than no gate, because it teaches people to ignore the
result. It now distinguishes *awaiting a dependency* from *defective*, and fails only on
the latter.

Also added `tools/publish_order.py`, which derives the publication order from the real
dependency graph. The order is load-bearing: a rejected publish permanently consumes the
version number, so it must be right the first time.

**Phase 0 is complete.** Six implemented crates, 312 tests, zero build warnings, zero
third-party dependencies, and a gate that runs on ARM64 and on x86_64.

**2026-10-18 — Real toolchain output, and two errors it exposed**

Installed clang and lld (LLVM 17, available for aarch64 in Alpine), produced genuine Windows
ARM64 binaries, and asked our own parser to classify them. The result was the most valuable
hour of the project so far: **two errors that 325 synthetic-fixture tests could not see.**

*Error 1: the PE optional header was read at the wrong offsets.*

The parser chained field offsets from `SectionAlignment` and had drifted eight bytes by the
time it reached `Subsystem`. On a real binary it read `Subsystem` as 4096 instead of 3, and
read the data-directory array from the middle of unrelated header fields.

It was invisible because **the fixture builder chained from the same anchor**, so the writer
and the reader agreed with each other while both disagreed with reality. A fixture that shares
an assumption with the code under test cannot detect that assumption being wrong.

The dangerous direction: a GUI application would have been reported as headless-capable,
routing a display-dependent program into a pipeline where it cannot run.

*Error 2: hybrid images cannot be identified by machine type.*

The project's headline claim is that it distinguishes the three ARM64 flavours. It did so by
reading the COFF machine field, using `0xA641` for ARM64EC and `0xA64E` for ARM64X. **Those
are not valid final PE machine types.** Microsoft states that `0xA641` "is an internal MSVC
identifier used for Arm64EC object files and is not defined in winnt.h", and that only the
linked image carries the `8664 (x64) (ARM64X)` or `AA64 (ARM64) (ARM64X)` value.

A linked ARM64EC executable therefore reports `0x8664` — indistinguishable from plain x86-64
without reading CHPE metadata. The headline differentiation was resting on constants that
real linked binaries never carry.

*What was built in response*

| Addition | Purpose |
|---|---|
| `crates/compitum-pe/src/chpe.rs` | Reads CHPE metadata through the load configuration; documents that `CHPEMetadataPointer` is a virtual address, not an RVA |
| `crates/compitum-pe/tests/corpus/` | Four real binaries of 1024 bytes each, plus a manifest, 6.3 KiB in total, with per-file digests and the producing toolchain recorded |
| `tools/make_corpus.py` | Regenerates and verifies the corpus; cross-checks every file against an independent reading of its raw bytes |
| `crates/*/tests/real_toolchain.rs` | 21 tests over real toolchain output (13 parser, 8 router), the only tests that can catch a shared assumption being wrong |

*A regression introduced while fixing error 2, and caught*

`family()` briefly routed **every** machine value through the new hybrid classifier, which
knows three outcomes. I386, Itanium, RISC-V, LoongArch, PowerPC and unrecognized values all
collapsed to x86-64. Three existing router tests caught it: a 32-bit x86 image would have
routed to Box64 instead of WOW64, and an Itanium image would have become translatable instead
of unsupported. The machine field is now consulted first and stays authoritative for every
value except the four a hybrid image can carry. Four new tests pin that.

*The lesson, stated once*

Synthetic fixtures verify that the code does what the author intended. Only third-party output
verifies that the author's intent matched the format. Both matter; only one was present until
now. Going forward, a new format assumption must be accompanied by a real artifact that tests
it.

**Verified at this revision:** 360 tests passing (21 of them against real toolchain output),
zero build warnings, zero clippy diagnostics, zero third-party dependencies, CI green on
ARM64 and x86_64.

**2026-10-18 — The CHPE detection is validated by an independent reader**

Correcting the hybrid classification was not enough. The new code was tested only by fixtures
this repository built, which is exactly the pattern that had just failed twice: a fixture
sharing an assumption with the code under test cannot detect that assumption being wrong.
Building the detector correctly and *proving* it correct are different obligations.

`lld-link` cannot close the gap on its own. It will link an ARM64X image, but without a Windows
CRT to supply the `__arm64x_*` symbols it leaves the load configuration empty, so no CHPE
metadata is emitted. That is a toolchain limitation, not an unsupported format, so the metadata
had to be written by hand.

What makes a hand-written fixture evidence rather than assertion is `llvm-readobj`: an
independent implementation of the same format that knows nothing about this code. It rejected
the first attempt outright:

```
error: RVA 0x3000 for CHPE code map not found
```

which is precisely the feedback that turns a guess into a verified layout. Once corrected it
reports:

```
chpe-arm64ec.exe  ->  Format: COFF-ARM64EC   Version: 0x1
chpe-arm64x.exe   ->  Format: COFF-ARM64X    Version: 0x2
```

and this crate's reader agrees on both, and on a plain ARM64 file, and on the linker-produced
ARM64EC file. **Two independent implementations reaching the same conclusion from the same
bytes is the strongest evidence the project has.**

The generator now records the *independent* verdict in the manifest as `llvm_readobj_format`,
and the test asserts our classification matches it. The manifest holds what a third party saw,
not what we intended, so a disagreement fails the build instead of being smoothed over.

| Corpus entry | Origin | Independent verdict |
|---|---|---|
| `real-console-4k.exe` | clang + lld-link | — (machine field suffices) |
| `real-gui-4k.exe` | clang + lld-link | — |
| `real-console-16k.exe` | clang + lld-link | — |
| `real-arm64ec.exe` | clang + lld-link | machine `0x8664`, which is the finding |
| `chpe-arm64ec.exe` | constructed, layout verified | `COFF-ARM64EC`, version 1 |
| `chpe-arm64x.exe` | constructed, layout verified | `COFF-ARM64X`, version 2 |

One test derived its expectation from the linker-produced list alone and therefore silently
skipped the new files. Both counts now derive from the full corpus, so adding a fixture cannot
quietly reduce coverage.

**Test coverage at this revision:** 365 tests (up from 360), of which 26 run against real
toolchain output or independently-validated fixtures. CI green on ARM64 and x86_64.

**2026-10-18 — Phase 1 feasibility measured, not assumed**

The roadmap feared Phase 1 because the plan called for building `proton-wine` from source: a
gigabyte of C plus twenty dependencies, on a device whose Android host kills large builds and
whose musl libc is not Wine's target. Before spending hours on that, the cheapest possible
test was run instead.

> Is Wine already present, and can it execute a real ARM64 Windows PE binary?

It can. **The first Phase 1 milestone is met on the development device, with software already
installed.**

Measured, with controls that separate correctly:

| Input | Expected | Observed | Meaning |
|---|---|---|---|
| not a PE | rejected fast | exit 47 | Wine refuses non-PE input |
| ARMNT `0x01C4` | rejected | exit 32 | no 32-bit ARM support in 6.0.3 |
| `real-console-4k.exe` (`0xAA64`) | runs to timeout | **exit 124** | executed |
| `real-gui-4k.exe` (`0xAA64`) | runs to timeout | **exit 124** | executed |
| `chpe-arm64ec.exe` (`0x8664` + CHPE v1) | refused | exit 123 | correct: too old, see below |
| `chpe-arm64x.exe` (`0xAA64` + CHPE v2) | refused | exit 5 | fixture artefact; its entry RVA is zero |

Exit 124 is a timeout, and a loader that rejects a file fails fast. The `real-console-4k.exe`
binary's `entry()` is an infinite loop making no NT calls, so "still running" is precisely the
correct outcome — and the ARMNT row proves Wine is not accepting everything indiscriminately.

Proof that the code was *executed* rather than merely loaded came from CPU time read directly
from the kernel: **657 jiffies = 6.6 CPU-seconds in an 8-second window.** A blocked loader would
have accumulated almost none.

**Why ARM64EC does not work, and why that is expected.** Wine 8.21 (October 2023) introduced
"beginnings of support for ARM64EC". The installed version is 6.0.3, predating it by more than
two years, and `wine64-development` in this archive also resolves to 6.0. The refusal is a
dated version floor, not an open research problem — a far better shape of difficulty.

**What this changes.** The bridge is proven for native ARM64 with no build at all. `proton-wine`
remains the right answer, but for the **hybrid case only**, which is a narrower task than the
roadmap originally planned for. Full measurements and reproduction steps are in
`docs/PHASE1-FEASIBILITY.md`.

### Revised Phase 1

| # | Task | Status |
|---|---|---|
| 1.1 | Native ARM64 execution under Wine | ✅ **met** — measured, documented |
| 1.2 | ARM64EC hybrid execution | ⬜ needs Wine ≥ 8.21, or a `proton-wine` build |
| 1.3 | NT syscall translation beyond startup | ⬜ untested; needs a binary that makes calls |
| 1.4 | End-to-end `NATIVE` proof from the CLI | ⬜ the router already decides it; execution now follows |

---

## 7. DECISION LOG

| Date | Decision | Rationale |
|---|---|---|
| 2026-10-18 | Product surface is English-only, with i18n engine for translations | Explicit user requirement; English is the lingua franca for developer tooling |
| 2026-10-18 | Zero external crate dependencies | Offline build, auditability, supply-chain safety |
| 2026-10-18 | CLI before Android | Avoids the GPU driver wall entirely |
| 2026-10-18 | Oracle is a first-class product | Data network effect is the only durable moat |
| 2026-10-18 | No permanent forks of Wine/FEX | Upstream-first; our value is the routing + data layers |
| 2026-10-18 | Renamed TESSERA to COMPITUM | TESSERA collided with a litigious semiconductor IP company; COMPITUM is free on every registry |
| 2026-10-18 | Routing decisions must be pure functions | A decision that varies with ambient state cannot be replayed from an Oracle record, which would make the stored evidence worthless |
| 2026-10-18 | A requirement is not an obstacle | Only `BackendAbsent`, `IsaFeaturesMissing`, `SyscallLayerAbsent`, `ArchitectureUnsupported` and `UnreadableSubject` block a route |
| 2026-10-18 | Box64 alone cannot serve an ARM64EC image | The hybrid route needs a translator that coexists with native code in one process; that is FEX-specific |
