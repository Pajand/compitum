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

pub mod error;
pub mod machine;
pub mod parser;
pub mod reader;

pub use error::{PeError, Result};
pub use machine::{AbiFamily, Machine};
pub use parser::{
    looks_like_pe, parse, CoffHeader, ImportedModule, OptionalHeader, PeImage, Section, Subsystem,
};
