# compitum-router

The ABI routing engine: layer 3 of [COMPITUM](https://github.com/compitum-dev/compitum), and the
decision the product exists to make.

## The question

Given a parsed binary and a probed host, **which execution path is correct, and why?**

The answer is a `Plan`: a `Route`, the `Reasons` that justify it, and a `Confidence` that is
honest about how good the evidence was.

## The decision, at a glance

| Image family | Host implements the required ISA features? | Required backend present? | Route |
|---|---|---|---|
| pure ARM64 | yes | — | `native` |
| ARM64X (fat) | yes | — | `pick_native_slice` |
| ARM64EC (hybrid) | yes | FEX | `fex_partial` |
| x86-64 | yes | Box64 or FEX | `box64_full` / `fex_full` |
| x86 (32-bit) | yes | Box86 | `wow64` |
| anything else | — | — | `refused` |

## The row that matters most

An ARM64EC image contains both AArch64 and x86-64 code. A tool that knows only *"this is a
hybrid, therefore emulate it"* sends it to a full translator and translates code that was
already native.

| Route | What gets translated | Expected throughput |
|---|---|---|
| `native` | nothing | 100% |
| `pick_native_slice` | nothing, after slice selection | 100% |
| `fex_partial` | only the x86-64 blocks | 70-90% |
| `fex_full` | every instruction | 30-60% |
| `box64_full` | every instruction | 20-50% |
| `wow64` | every instruction, 32-bit | 20-40% |

Keeping `fex_partial` distinct from `fex_full` is where the performance comes from, and it is
the difference between a tool that classifies a binary and a tool that understands it.

## Example

```rust
use compitum_isa::{FeatureSet, HostProfile, IsaFeature};
use compitum_pe::{parse, pe_fixture};
use compitum_router::{decide, BackendSet, Request, Route};

// A pure ARM64 console image.
let bytes = pe_fixture::synthetic(
    pe_fixture::machine::ARM64,
    pe_fixture::subsystem::CONSOLE,
    false,
);
let image = parse(&bytes).unwrap();

// A host implementing exactly the features the image needs.
let host = HostProfile::synthetic(
    "aarch64",
    4096,
    8,
    FeatureSet::new().with(IsaFeature::Fp).with(IsaFeature::Asimd),
);

let plan = decide(&Request::new(image, host, BackendSet::all()));
assert_eq!(plan.route, Route::Native);
assert!(plan.is_fully_native());
```

A refusal is specific rather than vague. When the host lacks a required CPU feature, the reason
names it:

```rust
use compitum_isa::{FeatureSet, HostProfile, IsaFeature, Requirement, RequirementSource};
use compitum_pe::{parse, pe_fixture};
use compitum_router::{decide, BackendSet, Request};

let bytes = pe_fixture::synthetic(
    pe_fixture::machine::ARM64,
    pe_fixture::subsystem::CONSOLE,
    false,
);
let image = parse(&bytes).unwrap();
let host = HostProfile::synthetic(
    "aarch64",
    4096,
    8,
    FeatureSet::new().with(IsaFeature::Fp).with(IsaFeature::Asimd),
);

let requirement = Requirement::new(
    IsaFeature::Sme,
    RequirementSource::Metadata,
    None,
    "declared use of matrix units",
);
let plan = decide(
    &Request::new(image, host, BackendSet::all()).with_requirements(vec![requirement]),
);

assert!(plan.is_blocked());
// The operator learns which feature is missing, not merely that something is.
assert!(plan.headline().contains("sme"));
```

## Design constraints

* **Purity.** `decide` performs no I/O and consults no ambient state, so a decision can be
  reproduced exactly from a stored Oracle record. A decision that varied with ambient state
  would make recorded evidence worthless precisely when it is most needed — when someone is
  trying to explain a failure from last month.
* **No execution.** This crate decides; it never loads, maps, or runs an image.
* **Honest refusals.** Only five things block a route: an unsupported architecture, a missing
  CPU feature, an absent backend, an absent NT system-call layer, or an unreadable file. A
  *requirement* is not an obstacle, and an earlier revision that conflated the two reported
  every x86-64 image as a refusal.
* **Each route is one of four mutually exclusive classes:** fully native, hybrid, fully
  translated, or refused. Asserted by test, so a route cannot quietly belong to two.

## Licence

Apache-2.0 OR MIT, at your option.
