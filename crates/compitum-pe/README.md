# compitum-pe

PE/COFF parsing and ARM64 binary classification: layer 1 of
[COMPITUM](https://github.com/compitum-dev/compitum).

## The problem this solves

"ARM64 binary" names three structurally different things, and mistaking one for another
produces either a crash or a large performance loss:

| Flavour | `Machine` | Contains | Executes natively? |
|---|---|---|---|
| ARM64 | `0xAA64` | pure AArch64 | **yes** |
| ARM64EC | `0xA641` | AArch64 **and x86-64** | no — hybrid |
| ARM64X | `0xA64E` | both slices, load-time dispatch | yes, after slice selection |
| AMD64 | `0x8664` | x86-64 only | no |

Every other tool in this space collapses that table to a single row. This crate keeps the three
ARM64 flavours distinct, because the difference between them is the difference between native
execution and translation.

The ARM64EC case matters most. NVIDIA's own porting guide describes the mechanism:

> "When execution transfers between A.cpp and x86_64-compiled B.cpp, marshalling code maintains
> compatibility."

An ARM64EC binary therefore **literally contains x86-64 machine code**. It cannot run natively.
But it is also not equivalent to an x86-64 binary, because most of its code is already ARM64 —
which is why routing it to a full emulator wastes most of the available performance.

## Example

```rust
use compitum_pe::{parse, pe_fixture};

let bytes = pe_fixture::synthetic(
    pe_fixture::machine::ARM64EC,
    pe_fixture::subsystem::CONSOLE,
    false,
);
let image = parse(&bytes).expect("well-formed image");

assert_eq!(image.family().id(), "arm64ec");
assert!(image.family().needs_partial_translation());
assert!(!image.family().is_fully_native_on_arm64());

// The crate states plainly what the classification means for execution.
assert!(image.family().execution_semantics().contains("x86-64"));
```

## Safety posture

**A PE file is hostile input.** Nothing here can panic on malformed data:

* every read is bounds-checked, and every range computation uses checked arithmetic;
* offsets arriving from the file are validated before use;
* the test suite includes mutation testing that feeds 500 deliberately corrupted headers
  through the parser.

A compatibility tool that crashes on a hostile binary cannot even report *why* it failed, which
makes it useless precisely when it is needed.

## Instruction scanning

`scan_image` reads machine code looking for optional instructions the header cannot declare —
SME, SVE, MTE, BTI, LSE, AES, SHA-2, CRC-32, RNG. Findings are reported at
`Confidence::MEDIUM`, never certainty, and the limitation is stated:

```rust
use compitum_pe::scan_code;

let report = scan_code(&0x0420_0002u32.to_le_bytes(), 0x1000);
assert!(report.features().iter().any(|f| f.id() == "sve"));
// A clean scan is not a guarantee, and the crate says so.
assert!(report.caveat().contains("cannot see run-time-generated code"));
```

**SVE2 is deliberately not reported.** It shares SVE's encoding space, and separating the two
needs bit-field definitions this crate has not validated against the architecture reference.
Rather than guess, the scanner reports SVE and records the gap in `caveat()`. The direction of
the resulting uncertainty is documented: a binary needing SVE2 may be reported as needing only
SVE, which could produce a false *compatible* verdict on a host with SVE but not SVE2. That is
the unsafe direction, which is why it is flagged rather than silently accepted.

## For testing

`pe_fixture::synthetic` builds structurally valid PE images in memory, so the parser can be
exercised against real structure without a Windows machine or a genuine `.exe`. It is public
rather than `#[cfg(test)]` so that the router's tests use the same fixture bytes — a fixture
that drifts between crates is worse than no fixture.

## Licence

Apache-2.0 OR MIT, at your option.
