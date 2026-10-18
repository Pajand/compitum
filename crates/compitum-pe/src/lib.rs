//! PE/COFF parsing and ARM64 binary classification — COMPITUM's layer 1.
//!
//! This crate answers the first question in COMPITUM's chain of reasoning: **what kind of
//! ARM64 binary am I holding?** The answer is a full [`PeImage`] description, of which
//! the [`Machine`] field is the decisive part.
//!
//! # The problem this crate solves
//!
//! "ARM64 binary" names three structurally different things, and mistaking one for
//! another produces either a crash or a large performance loss:
//!
//! | Flavour | Machine | Contains | Runs natively? |
//! |---|---|---|---|
//! | ARM64 | `0xAA64` | pure AArch64 | **yes** |
//! | ARM64EC | `0xA641` | AArch64 **and x86-64** | no — hybrid |
//! | ARM64X | `0xA64E` | both slices, load-time dispatch | yes, after slice selection |
//!
//! Every other tool in this space collapses the table to a single row. This crate keeps
//! it separate.
//!
//! # Safety posture
//!
//! A PE file is hostile input. Nothing here can panic on malformed data: every read is
//! bounds-checked, every field is validated, and the test suite includes mutation testing
//! that feeds 500 deliberately corrupted headers through the parser to prove it.
//!
//! # Example
//!
//! ```
//! use compitum_pe::{parse, AbiFamily, Machine};
//!
//! // A minimal PE32+ image declaring pure ARM64 and the console subsystem.
//! let mut data = vec![0u8; 0x400];
//! data[0] = b'M';
//! data[1] = b'Z';
//! data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
//! data[0x80..0x84].copy_from_slice(b"PE\0\0");
//! data[0x84..0x86].copy_from_slice(&0xAA64u16.to_le_bytes()); // Machine = ARM64
//! // Leave SizeOfOptionalHeader at zero: this image has no optional header.
//!
//! let image = parse(&data).expect("well-formed header");
//! assert_eq!(image.coff.machine, Machine::ARM64);
//! assert_eq!(image.family(), AbiFamily::Arm64Native);
//! assert!(image.family().is_fully_native_on_arm64());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// The crate README is included as documentation, which makes every Rust example in it a
// compiled doctest. An example that is not compiled is an example that silently rots, and a
// wrong example on a crate page is worse than no example at all.
#![doc = include_str!("../README.md")]

pub mod chpe;
pub mod error;
pub mod fixture;
pub mod machine;
pub mod parser;
pub mod reader;
pub mod scanner;

pub use chpe::{
    classify_image, read_hybrid_metadata, Classified, HybridKind, HybridMetadata,
    MIN_LOAD_CONFIG_FOR_CHPE,
};
pub use error::{PeError, Result};
pub use machine::{AbiFamily, Machine};
pub use parser::{
    looks_like_pe, parse, CoffHeader, ImportedModule, OptionalHeader, PeImage, Section, Subsystem,
};
pub use scanner::{scan_code, scan_image, ScanReport, MAX_SCAN_BYTES};

/// Synthetic PE construction, re-exported under a descriptive name.
///
/// The module is also available as [`fixture`]; this alias exists so call sites read as
/// `pe_fixture::synthetic(...)`, which is unambiguous about what is being built.
pub use fixture as pe_fixture;

/// The fixture module's machine-type and subsystem constants are reached through
/// [`pe_fixture`], for example `pe_fixture::machine::ARM64` and
/// `pe_fixture::subsystem::CONSOLE`.
///
/// They are deliberately *not* re-exported at the crate root: the root already has a
/// [`machine`] module holding the analysed [`Machine`] type, and two modules with the
/// same name in one namespace is a compile error rather than a convenience.
pub use fixture as _fixture_constants_marker;
