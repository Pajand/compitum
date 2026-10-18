# compitum-isa

The ARM64 instruction-set vocabulary, and an oracle that reports what *this* machine can
actually execute.

Part of [COMPITUM](https://github.com/Pajand/compitum), an ABI-aware ARM64 compatibility layer.

## The problem this solves

Nothing in the ecosystem exposes the comparison this crate exists for. `file(1)` reports
"ARM aarch64" for every ARM64 binary regardless of whether it needs SME matrix units that half
of ARM64 silicon does not implement. The result is a program that loads cleanly and then faults
on its first matrix instruction — discovered late, and looking like a crash rather than a
compatibility problem.

This crate answers the two halves separately so they can be compared:

* **What a binary requires**, with provenance and a confidence level.
* **What a host provides**, read from the kernel's own reporting interfaces.

## Measured divergence

A real ARM64 device reports:

```text
HWCAP  = 0x00000000ffbfffff
HWCAP2 = 0x0000000000022181
```

Which decodes to: every base extension present, **I8MM** and **BTI** supported, and
**SVE2, SME, MTE and BF16 absent**. NVIDIA's RTX Spark implements all four of those.

So a binary compiled with SME matrix instructions for RTX Spark **faults** on a device like
this one. That is a real, measured, exploitable divergence — and the reason the feature set is
treated as first-class data rather than as trivia.

## Example

```rust
use compitum_isa::{FeatureSet, HostProfile, IsaFeature};

let host = HostProfile::synthetic("aarch64", 4096, 8, FeatureSet::all());
assert!(host.is_arm64());
assert!(!host.has_non_windows_page_size());
assert!(host.features.contains(IsaFeature::Sme));

// The operation the whole project rests on: what does this binary need that this
// machine cannot do?
let host = FeatureSet::new().with(IsaFeature::Sve2);
let needed = FeatureSet::new()
    .with(IsaFeature::Sve2)
    .with(IsaFeature::Sme)
    .with(IsaFeature::Mte);
assert_eq!(needed.difference(host).ids(), vec!["sme", "mte"]);
```

Requirements carry their provenance, because a declared fact is not the same as a static guess:

```rust
use compitum_isa::{Confidence, IsaFeature, Requirement, RequirementSource};

let guess = Requirement::new(
    IsaFeature::Sme,
    RequirementSource::InstructionScan,
    Some(0x1000),
    "pattern hit",
);
// A scan cannot see run-time-generated code, and a rare encoding can occur by
// coincidence, so the finding is reported with less than certainty.
assert!(guess.confidence.permille() <= Confidence::MEDIUM.permille());
```

## Notable details

* **Two sources, cross-checked.** Capability bitmaps come from `/proc/self/auxv`; feature names
  come from `/proc/cpuinfo`. A *set* bit is strong evidence of presence, an *unset* bit is weak
  evidence of absence — the kernel has historically renumbered upper `HWCAP2` bits. Where the
  two disagree, the names win.
* **Heterogeneous cores are handled.** On a big.LITTLE SoC a thread can be scheduled anywhere,
  so `guaranteed_features()` intersects the capability set across every core rather than
  reporting the union.
* **Page size is a first-class axis.** Windows on ARM uses 4 KiB pages; Android is migrating to
  16 KiB. A 4 KiB binary on a 16 KiB host can fail in ways that look intermittent.
* **No `unsafe`.** Reading the auxiliary vector from `/proc` rather than calling `getauxval(3)`
  makes the whole crate safe Rust, and makes the parser testable as a pure function over bytes.
* **67 features**, each with a stable identifier that never changes and is never translated.

## Licence

Apache-2.0 OR MIT, at your option.
