//! Little-endian and range-checked readers over a byte slice.
//!
//! A PE file is untrusted input: it may be truncated, deliberately malformed, or
//! crafted to make a naive parser read outside its buffer. Every read in this module is
//! bounds-checked and returns a typed error rather than panicking, because a
//! compatibility tool that crashes on a hostile binary is worse than useless — it
//! cannot even report *why* it failed.
//!
//! # Design
//!
//! Readers are free functions taking `&[u8]` plus an offset, rather than a stateful
//! cursor. This makes every access site explicit about where it is reading from, which
//! matters when the offsets themselves come from the file being parsed.

use crate::error::{PeError, Result};

/// Reads a `u8` at `offset`.
///
/// # Errors
///
/// Returns [`PeError::Truncated`] when the offset lies at or beyond the end of the data.
pub fn u8_at(data: &[u8], offset: usize) -> Result<u8> {
    data.get(offset)
        .copied()
        .ok_or(PeError::Truncated { offset, needed: 1 })
}

/// Computes `offset + len` without wrapping.
///
/// A PE file is hostile input: a crafted header can name an offset close to `usize::MAX`,
/// and the resulting overflow would panic in a debug build (aborting the process and
/// losing the diagnosis) or, worse, wrap to a small value in a release build and read
/// attacker-chosen bytes. Every range computation in this module routes through here.
fn checked_end(offset: usize, len: usize) -> Option<usize> {
    offset.checked_add(len)
}

/// Reads a little-endian `u16` at `offset`.
///
/// # Errors
///
/// Returns [`PeError::Truncated`] when fewer than two bytes remain.
pub fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    let end = checked_end(offset, 2).ok_or(PeError::Truncated { offset, needed: 2 })?;
    let bytes = data
        .get(offset..end)
        .ok_or(PeError::Truncated { offset, needed: 2 })?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Reads a little-endian `u32` at `offset`.
///
/// # Errors
///
/// Returns [`PeError::Truncated`] when fewer than four bytes remain.
pub fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    let end = checked_end(offset, 4).ok_or(PeError::Truncated { offset, needed: 4 })?;
    let bytes = data
        .get(offset..end)
        .ok_or(PeError::Truncated { offset, needed: 4 })?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Reads a little-endian `u64` at `offset`.
///
/// # Errors
///
/// Returns [`PeError::Truncated`] when fewer than eight bytes remain.
pub fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    let end = checked_end(offset, 8).ok_or(PeError::Truncated { offset, needed: 8 })?;
    let bytes = data
        .get(offset..end)
        .ok_or(PeError::Truncated { offset, needed: 8 })?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// Borrows a fixed-length byte range.
///
/// # Errors
///
/// Returns [`PeError::Truncated`] when the range is not fully present.
pub fn bytes_at(data: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    let end = checked_end(offset, len).ok_or(PeError::Truncated {
        offset,
        needed: len,
    })?;
    data.get(offset..end).ok_or(PeError::Truncated {
        offset,
        needed: len,
    })
}

/// Reads a NUL-terminated ASCII string starting at `offset`, capped at `max_len` bytes.
///
/// PE section names are an 8-byte field that is *not* guaranteed to be NUL-terminated
/// when exactly eight characters are used, so callers pass the field width and this
/// function handles both cases. Non-ASCII bytes are replaced rather than rejected,
/// because a section name is diagnostic information, not something to refuse a file over.
///
/// # Errors
///
/// Returns [`PeError::Truncated`] when the field itself is not present.
pub fn fixed_ascii(data: &[u8], offset: usize, max_len: usize) -> Result<String> {
    let field = bytes_at(data, offset, max_len)?;
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    Ok(field[..end]
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '\u{FFFD}'
            }
        })
        .collect())
}

/// Returns `true` when `value` is a power of two, which every valid page size must be.
#[must_use]
pub fn is_power_of_two(value: u32) -> bool {
    value != 0 && value.is_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_scalars() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(u8_at(&data, 0).unwrap(), 0x01);
        assert_eq!(u16_at(&data, 0).unwrap(), 0x0201);
        assert_eq!(u32_at(&data, 0).unwrap(), 0x04030201);
        assert_eq!(u64_at(&data, 0).unwrap(), 0x0807060504030201);
    }

    #[test]
    fn rejects_out_of_bounds_reads() {
        let data = [0u8; 4];
        assert!(u8_at(&data, 4).is_err());
        assert!(u16_at(&data, 3).is_err());
        assert!(u32_at(&data, 1).is_err());
        assert!(u64_at(&data, 0).is_err());
        assert!(bytes_at(&data, 2, 5).is_err());
    }

    #[test]
    fn truncated_error_reports_the_offset() {
        let data = [0u8; 2];
        match u32_at(&data, 1) {
            Err(PeError::Truncated { offset, needed }) => {
                assert_eq!(offset, 1);
                assert_eq!(needed, 4);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn overflow_offsets_do_not_panic() {
        let data = [0u8; 8];
        // Every one of these would wrap in an unchecked implementation: the add would
        // panic in debug and silently read the wrong location in release.
        for offset in [
            usize::MAX,
            usize::MAX - 1,
            usize::MAX - 3,
            usize::MAX / 2 + 1,
        ] {
            assert!(u8_at(&data, offset).is_err(), "u8 at {offset}");
            assert!(u16_at(&data, offset).is_err(), "u16 at {offset}");
            assert!(u32_at(&data, offset).is_err(), "u32 at {offset}");
            assert!(u64_at(&data, offset).is_err(), "u64 at {offset}");
            assert!(bytes_at(&data, offset, 4).is_err(), "bytes at {offset}");
            assert!(fixed_ascii(&data, offset, 8).is_err(), "ascii at {offset}");
        }
    }

    #[test]
    fn reads_fixed_ascii_with_nul_terminator() {
        let data = b".text\0\0\0";
        assert_eq!(fixed_ascii(data, 0, 8).unwrap(), ".text");
    }

    #[test]
    fn reads_fixed_ascii_filled_completely() {
        // Exactly eight characters, no NUL: a real pattern in PE section names.
        let data = b"12345678";
        assert_eq!(fixed_ascii(data, 0, 8).unwrap(), "12345678");
    }

    #[test]
    fn replaces_non_ascii_in_names() {
        let data = [0xFF, 0x41, 0x00, 0x00];
        let name = fixed_ascii(&data, 0, 4).unwrap();
        assert!(name.ends_with('A'));
        assert!(name.contains('\u{FFFD}'));
    }

    #[test]
    fn rejects_fixed_ascii_beyond_end() {
        assert!(fixed_ascii(&[0u8; 2], 0, 8).is_err());
    }

    #[test]
    fn power_of_two_detection() {
        assert!(is_power_of_two(4096));
        assert!(is_power_of_two(16384));
        assert!(!is_power_of_two(0));
        assert!(!is_power_of_two(4097));
    }
}
