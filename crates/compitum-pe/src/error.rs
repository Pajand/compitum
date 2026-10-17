//! PE parsing errors.
//!
//! Every failure mode is a distinct variant carrying enough context to write a precise
//! sentence. This is deliberate: LAW 7 of the project's doctrine is *honest failure* —
//! when a file cannot be classified, the operator must learn exactly what was wrong with
//! it, not merely that something was.

use std::fmt;

/// A PE parsing failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeError {
    /// The file is smaller than the minimum viable PE image.
    TooSmall {
        /// Actual file size in bytes.
        size: usize,
    },
    /// The `MZ` signature is absent, so this is not a DOS/PE image at all.
    NotMz,
    /// The `e_lfanew` field points outside the file.
    BadLfanew {
        /// The offending offset.
        offset: u32,
    },
    /// The `PE\0\0` signature is absent at the offset the DOS header named.
    NotPe,
    /// A read ran past the end of the data.
    Truncated {
        /// Offset at which the read was attempted.
        offset: usize,
        /// Number of bytes the read required.
        needed: usize,
    },
    /// The optional header magic is neither `PE32` nor `PE32+`.
    UnknownOptionalHeader {
        /// The magic value encountered.
        magic: u16,
    },
    /// A numeric field holds a value that is structurally impossible.
    InvalidField {
        /// Field name.
        field: &'static str,
        /// Observed value.
        value: u64,
    },
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeError::TooSmall { size } => write!(
                f,
                "file is {size} bytes, which is too small to contain a PE image"
            ),
            PeError::NotMz => f.write_str(
                "missing the MZ signature, so this is not a Portable Executable image",
            ),
            PeError::BadLfanew { offset } => write!(
                f,
                "the DOS header points to offset {offset}, which is outside the file"
            ),
            PeError::NotPe => {
                f.write_str("missing the PE signature at the offset the DOS header named")
            }
            PeError::Truncated { offset, needed } => write!(
                f,
                "file is truncated: needed {needed} bytes at offset {offset}"
            ),
            PeError::UnknownOptionalHeader { magic } => write!(
                f,
                "unrecognized optional header magic 0x{magic:04X}; expected PE32 (0x010B) or PE32+ (0x020B)"
            ),
            PeError::InvalidField { field, value } => {
                write!(f, "field `{field}` holds an impossible value: {value}")
            }
        }
    }
}

impl std::error::Error for PeError {}

/// Convenience result type for PE parsing.
pub type Result<T> = std::result::Result<T, PeError>;
