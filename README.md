# COMPITUM

**The universal ARM64 compatibility layer.**

COMPITUM answers one question that no tool in the world answers today:

> *Will this Windows ARM64 binary run natively on this machine, or does it need emulation?*

And then it acts on the answer.

```
$ compitum inspect app.exe
  machine      : ARM64EC  (hybrid ARM64 + x86_64)
  route        : FEX_PARTIAL
  confidence   : high
  ...

$ compitum verify app.exe
  verdict      : COMPATIBLE
  route        : NATIVE
  emulation    : 0 bytes
```

---

## Why this exists

On **2026-10-16** NVIDIA shipped RTX Spark — the first serious ARM64 desktop CPU in the
Windows ecosystem. Overnight, a large fraction of future Windows software began moving to
ARM64. But ARM64 binaries are not one thing:

| Flavour | Contains | Runs natively? |
|---|---|---|
| `ARM64`   (`0xAA64`) | pure AArch64 | **yes** |
| `ARM64EC` (`0xA641`) | AArch64 **and x86_64** | no — hybrid |
| `ARM64X`  (`0xA64E`) | both slices in one file | yes, if you pick the right slice |
| `AMD64`   (`0x8664`) | x86_64 only | no |

Every existing compatibility tool treats them the same way. COMPITUM does not.

**COMPITUM has a routing decision. Everyone else has a single path.**

### What that decision is worth

An ARM64EC image contains AArch64 code *and* x86-64 code in one file. A tool that knows
only "this is a hybrid, therefore emulate it" sends it to a full translator and ends up
translating code that was already native.

| Route | What gets translated | Expected throughput |
|---|---|---|
| `native` | nothing | 100% |
| `pick_native_slice` | nothing, after slice selection | 100% |
| `fex_partial` | only the x86-64 blocks | 70-90% |
| `box64_full` / `fex_full` | every instruction | 30-60% |
| `wow64` | every instruction, 32-bit | 20-40% |
| `refused` | nothing — impossible, with a reason naming the obstacle | — |

Keeping `fex_partial` distinct from `fex_full` is where the performance comes from. It is
the difference between a tool that classifies a binary and a tool that understands it.

Every route carries its reasons as machine-readable codes plus an English sentence, so a
verdict can be audited rather than merely believed.

---

## The three things nobody else does

1. **PE-aware ABI classification** — reads the real `IMAGE_FILE_MACHINE` type, import
   table, subsystem and ISA usage features out of the binary itself.
2. **Host ISA oracle** — probes the *actual* CPU capability set (`HWCAP`/`HWCAP2`),
   memory page size and kernel ABI, then checks it against what the binary requires.
3. **Evidence-based routing + the Oracle** — every decision is justified and recorded.
   The resulting compatibility dataset is the durable asset.

Measured divergence on the reference device:

```
HOST (development device)     HWCAP2 = 0x0000000000022181
  has : I8MM, BTI, FRINT, DCPODP, FLAGM2
  lacks: SVE2, SME, MTE, BF16

TARGET (NVIDIA RTX Spark)     SVE2, SME, MTE, VIRT
```

A binary compiled with SME matrix instructions for RTX Spark **faults on this device**.
COMPITUM tells you that *before* you run it, in plain language, with a reason code.

---

## Guarantees

- **English-only product surface.** All code, output and documentation is English.
- **Full localization engine.** Every human-facing string is translatable; adding a
  language is dropping a JSON file into `locales/`. No recompilation.
- **Zero external crate dependencies.** `cargo build` works fully offline.
- **No `unsafe`.** `#![forbid(unsafe_code)]` in every core crate.
- **Honest failure.** Never a bare `SIGILL`. Always a reason code and a sentence.

---

## Building

Requires Rust 1.78+. No network access needed.

```bash
cargo build --release
./target/release/compitum --help
```

---

## Architecture

```
compitum (CLI)
  ├── compitum-oracle    compatibility store  (the moat)
  ├── compitum-router    ABI routing engine   (the decision)
  │     ├── compitum-pe    PE classification  (the facts)
  │     └── compitum-isa   host capability    (the reality)
  ├── compitum-json      dependency-free JSON (the format)
  └── compitum-i18n      localization engine  (the reach)
```

---

## License

Dual-licensed under Apache-2.0 OR MIT, at your option.
