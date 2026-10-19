//! Turning a verdict into a byte-level edit, and refusing when that cannot be safe.
//!
//! # What this module is, and what it deliberately is not
//!
//! It is a **metadata patcher**. It changes fields in a PE file that describe how the image
//! should be treated, and nothing else. It does not touch a single instruction byte.
//!
//! That restriction is the whole design. The obvious ambition for a migration tool is "port my
//! x86 app to Arm64 automatically", and it cannot be delivered honestly: rewriting x86-64
//! machine code into AArch64 is a *recompiler*, not a patcher — months of work, and its output
//! is wrong for self-modifying code, for unwinding, and for anything that inspects its own
//! instructions. Worse, changing the `Machine` field of a native x86 image produces a file that
//! **loads and then crashes**, because every instruction in it is still x86. A tool that did that
//! would be worse than no tool: it would convert a build error into a production incident, and
//! it would be caught doing so once.
//!
//! # The case that genuinely works
//!
//! .NET assemblies carry **Intermediate Language**, which is architecture-neutral: the CLR
//! compiles it to the host's own instructions at load time. So a managed assembly's `Machine`
//! field describes the platform it was *built* for, not what will execute. What actually stops
//! such an assembly from running as native Arm64 is a **flag**.
//!
//! `COMIMAGE_FLAGS_32BITREQUIRED` forces the assembly to load into a 32-bit process. Clearing
//! that one bit is exactly what Microsoft's own `corflags /32BITREQ-` does, and what the .NET
//! documentation means by "AnyCPU". Nothing else changes — no instruction, no section, no
//! import — so the edit is provably safe and trivially reversible.
//!
//! This is a real and common situation. A component built years ago with "x86" selected in a
//! project file is pinned to 32-bit for no reason anyone remembers, and removing the pin is the
//! entire migration.
//!
//! # The cases that are refused, and why refusing is the product
//!
//! * **A native x86 or x86-64 image.** It needs a recompiler. Saying so is the honest answer;
//!   pretending otherwise breaks the file.
//! * **Mixed-mode assemblies.** `COMIMAGE_FLAGS_ILONLY` is not set, which means the image
//!   contains native x86 code inside a managed wrapper. Its IL is portable and its native half
//!   is not, and no flag change fixes the second half.
//! * **An assembly that is already AnyCPU.** Nothing to do, and saying "ported" would be a lie.
//! * **An image whose CLR header cannot be read.** A patch planned against a field that could not
//!   be located is a guess.
//!
//! # Why the caller gets edits rather than a new file
//!
//! [`PortVerdict`] describes *what would change*, with the before and after bytes for every
//! field. A caller can therefore show the operator exactly which bytes move before anything is
//! written, and the CLI defaults to that dry run. An automatic tool that rewrites customer
//! binaries without showing what it changed is not one anybody should run.

use crate::parser::PeImage;

/// `COMIMAGE_FLAGS_ILONLY` — the image contains only IL, with no native code.
///
/// The definitive answer to "can this be ported by flags alone". When it is clear, the assembly
/// carries native machine code somewhere, and no metadata edit can move that code to Arm64.
pub const COR_ILONLY: u32 = 0x0000_0001;
/// `COMIMAGE_FLAGS_32BITREQUIRED` — the assembly must load into a 32-bit process.
///
/// This is the flag a migration actually removes. Microsoft's `corflags /32BITREQ-` clears it
/// and nothing else.
pub const COR_32BITREQUIRED: u32 = 0x0000_0002;
/// `COMIMAGE_FLAGS_32BITPREFERRED` — prefer 32-bit, but allow 64-bit.
///
/// Not an obstacle: a 64-bit host may run it. Recorded so a report can mention it without
/// treating it as work.
pub const COR_32BITPREFERRED: u32 = 0x0002_0000;
/// `COMIMAGE_FLAGS_NATIVE_ENTRYPOINT` — the entry point is native code, not IL.
pub const COR_NATIVE_ENTRYPOINT: u32 = 0x0000_0010;

/// Offset of `Flags` within `IMAGE_COR20_HEADER`.
const COR20_FLAGS_OFFSET: usize = 16;
/// Declared size of `IMAGE_COR20_HEADER` this reader understands.
const COR20_MIN_SIZE: u32 = 72;

/// The parts of `IMAGE_COR20_HEADER` that decide whether a port is possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClrHeader {
    /// `COMIMAGE_FLAGS_*` bits.
    pub cor_flags: u32,
    /// RVA of the metadata blob.
    pub metadata_rva: u32,
    /// Size of the metadata blob.
    pub metadata_size: u32,
    /// CLR major runtime version the image was built against.
    pub runtime_major: u16,
    /// CLR minor runtime version.
    pub runtime_minor: u16,
    /// Entry-point token, or an RVA when [`COR_NATIVE_ENTRYPOINT`] is set.
    pub entry_point: u32,
    /// File offset of the `Flags` field, so a patch can address it exactly.
    pub flags_file_offset: usize,
}

impl ClrHeader {
    /// Returns `true` when the assembly contains only IL.
    #[must_use]
    pub fn is_il_only(&self) -> bool {
        self.cor_flags & COR_ILONLY != 0
    }

    /// Returns `true` when the assembly is pinned to a 32-bit process.
    #[must_use]
    pub fn is_32bit_required(&self) -> bool {
        self.cor_flags & COR_32BITREQUIRED != 0
    }

    /// Returns `true` when the assembly merely prefers 32-bit.
    #[must_use]
    pub fn is_32bit_preferred(&self) -> bool {
        self.cor_flags & COR_32BITPREFERRED != 0
    }

    /// Returns `true` when the entry point is native code rather than IL.
    #[must_use]
    pub fn has_native_entry_point(&self) -> bool {
        self.cor_flags & COR_NATIVE_ENTRYPOINT != 0
    }
}

impl PeImage {
    /// Reads the CLR header of a managed image.
    ///
    /// Returns `None` when the image is not managed, when the CLR directory is unusable, or when
    /// the header is shorter than this reader understands. All three are the same answer to the
    /// only question that matters — "can a patch be planned against a field I could not locate?"
    /// — and the answer is no.
    #[must_use]
    pub fn clr_header(&self, data: &[u8]) -> Option<ClrHeader> {
        let optional = self.optional.as_ref()?;
        let rva = optional.clr_header_rva;
        if rva == 0 {
            return None;
        }
        let start = self.rva_to_offset(rva)?;

        let cb = u32::from_le_bytes(read4(data, start)?);
        if cb < COR20_MIN_SIZE {
            return None;
        }

        let runtime_major = u16::from_le_bytes(read2(data, start + 4)?);
        let runtime_minor = u16::from_le_bytes(read2(data, start + 6)?);
        let metadata_rva = u32::from_le_bytes(read4(data, start + 8)?);
        let metadata_size = u32::from_le_bytes(read4(data, start + 12)?);
        let cor_flags = u32::from_le_bytes(read4(data, start + COR20_FLAGS_OFFSET)?);
        let entry_point = u32::from_le_bytes(read4(data, start + 20)?);

        Some(ClrHeader {
            cor_flags,
            metadata_rva,
            metadata_size,
            runtime_major,
            runtime_minor,
            entry_point,
            flags_file_offset: start + COR20_FLAGS_OFFSET,
        })
    }
}

/// One field that would change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    /// File offset of the first changed byte.
    pub offset: usize,
    /// The bytes as they are now.
    pub before: Vec<u8>,
    /// The bytes they would become.
    pub after: Vec<u8>,
    /// What the field is, in words an operator can check.
    pub what: String,
}

impl Edit {
    /// A one-line rendering of the change, for a dry run.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{} at 0x{:X}: {} -> {}",
            self.what,
            self.offset,
            hex(&self.before),
            hex(&self.after)
        )
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// What a port would do, or why it cannot be done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortVerdict {
    /// A safe, metadata-only change is available.
    Safe {
        /// The edits, in file order.
        edits: Vec<Edit>,
        /// Why this is safe, in one sentence a non-specialist can check.
        rationale: String,
    },
    /// Nothing to do: the image already runs as native Arm64.
    AlreadyPortable {
        /// Why it is already fine.
        rationale: String,
    },
    /// Not possible by patching, with the reason named.
    Refused {
        /// A short identifier for the reason.
        reason: &'static str,
        /// A sentence explaining it, in terms of what would go wrong.
        detail: String,
    },
}

/// Plans a port of one image, touching only metadata.
///
/// `target_arm64` is whether the destination is Arm64 at all — a port is only meaningful when it
/// is, and asking for one towards Arm32 or x86 is a caller error rather than a finding.
#[must_use]
pub fn plan_port(data: &[u8], image: &PeImage, target_arm64: bool) -> PortVerdict {
    if !target_arm64 {
        return PortVerdict::Refused {
            reason: "destination-not-arm64",
            detail: "the destination is not an Arm64 platform, so there is no Arm64 port to \
                     make"
                .to_owned(),
        };
    }

    // A native image needs a recompiler. This is the refusal that matters most, because it is
    // the one a customer will ask for.
    if !image.is_managed() {
        return PortVerdict::Refused {
            reason: "native-code-needs-recompilation",
            detail: format!(
                "this is a native {} image, so porting it means translating its machine code to \
                 AArch64. That is a recompiler's job, not a metadata patch: rewriting the \
                 machine field alone would produce a file that loads and then crashes, because \
                 every instruction would still be {}. It has to be rebuilt from source.",
                image.family().id(),
                image.family().id()
            ),
        };
    }

    let Some(clr) = image.clr_header(data) else {
        return PortVerdict::Refused {
            reason: "unreadable-clr-header",
            detail: "the image is marked as managed but its CLR header could not be read, so \
                     no patch can be planned against a field whose position is unknown"
                .to_owned(),
        };
    };

    // Mixed-mode: IL plus native code in one image. The IL half is portable and the native half
    // is not, and no flag expresses that.
    if !clr.is_il_only() {
        return PortVerdict::Refused {
            reason: "mixed-mode-assembly",
            detail: "this assembly is not IL-only: it embeds native machine code alongside its \
                     IL (likely C++/CLI). Its managed half would move to Arm64 and its native \
                     half would not, so it has to be rebuilt without the native component."
                .to_owned(),
        };
    }
    if clr.has_native_entry_point() {
        return PortVerdict::Refused {
            reason: "native-entry-point",
            detail: "this assembly's entry point is native machine code rather than IL, so it \
                     cannot be reached through flags alone"
                .to_owned(),
        };
    }

    if !clr.is_32bit_required() {
        return PortVerdict::AlreadyPortable {
            rationale: if clr.is_32bit_preferred() {
                "this assembly is already AnyCPU and only *prefers* 32-bit: a 64-bit Arm host \
                 may load it, and the preference does not prevent that. No change is needed."
                    .to_owned()
            } else {
                "this assembly is already AnyCPU: its IL is compiled by the CLR for whatever \
                 processor it runs on, so it needs no port."
                    .to_owned()
            },
        };
    }

    // The one safe edit. Clearing 32BITREQUIRED is what `corflags /32BITREQ-` does; it removes
    // the pin to a 32-bit process and changes nothing else.
    let after = clr.cor_flags & !COR_32BITREQUIRED;
    let edit = Edit {
        offset: clr.flags_file_offset,
        before: clr.cor_flags.to_le_bytes().to_vec(),
        after: after.to_le_bytes().to_vec(),
        what: "COMIMAGE_FLAGS_32BITREQUIRED".to_owned(),
    };

    PortVerdict::Safe {
        edits: vec![edit],
        rationale: format!(
            "this assembly is IL-only and pinned to a 32-bit process. Clearing 32BITREQUIRED \
             makes it AnyCPU, so the CLR will compile its IL for Arm64 and it runs natively. \
             One flag changes; no instruction, section or import does. This is what \
             `corflags /32BITREQ-` performs, and it is reversible by setting the bit again. \
             (CorFlags 0x{:08X} -> 0x{after:08X})",
            clr.cor_flags
        ),
    }
}

/// Why an edit could not be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchError {
    /// An edit addresses bytes past the end of the file.
    OutOfRange {
        /// The offset that was out of range.
        offset: usize,
        /// How long the file actually is.
        len: usize,
    },
    /// The bytes at an edit's offset are not what the plan said they were.
    ///
    /// Checked because a patch computed from one file and applied to another would corrupt it,
    /// and because a caller that edited the file in between must not be silently overwritten.
    UnexpectedBytes {
        /// The offset whose content differed.
        offset: usize,
        /// What the plan expected.
        expected: Vec<u8>,
        /// What was actually there.
        found: Vec<u8>,
    },
}

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatchError::OutOfRange { offset, len } => write!(
                f,
                "the patch targets offset 0x{offset:X} but the file is only {len} bytes"
            ),
            PatchError::UnexpectedBytes {
                offset,
                expected,
                found,
            } => write!(
                f,
                "at offset 0x{offset:X} the plan expected {} but the file contains {}; the file \
                 may have been modified since the plan was made",
                hex(expected),
                hex(found)
            ),
        }
    }
}

impl std::error::Error for PatchError {}

/// Applies edits in place, after verifying every one of them.
///
/// # Why the pre-image is checked
///
/// A plan computed from one file and applied to another is the same shape of mistake as a
/// measurement made on one machine and reported about another, which this project has had to
/// correct before. Verifying the bytes first turns that class of error into a refusal instead of
/// a corrupted binary.
///
/// # Errors
///
/// Returns [`PatchError`] when an edit is out of range or when the bytes differ from the plan.
pub fn apply_edits(data: &mut [u8], edits: &[Edit]) -> Result<(), PatchError> {
    // Verify everything before writing anything, so a plan that fails halfway cannot leave the
    // file partially patched.
    for edit in edits {
        let end = edit.offset.saturating_add(edit.before.len());
        if end > data.len() {
            return Err(PatchError::OutOfRange {
                offset: edit.offset,
                len: data.len(),
            });
        }
        let found = &data[edit.offset..end];
        if found != edit.before.as_slice() {
            return Err(PatchError::UnexpectedBytes {
                offset: edit.offset,
                expected: edit.before.clone(),
                found: found.to_vec(),
            });
        }
    }

    for edit in edits {
        let end = edit.offset + edit.after.len();
        data[edit.offset..end].copy_from_slice(&edit.after);
    }
    Ok(())
}

fn read2(data: &[u8], at: usize) -> Option<[u8; 2]> {
    data.get(at..at + 2)?.try_into().ok()
}

fn read4(data: &[u8], at: usize) -> Option<[u8; 4]> {
    data.get(at..at + 4)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{machine, subsystem};
    use crate::pe_fixture;

    /// Builds a managed fixture with real CLR-header content, since the generic fixture only
    /// sets the directory and leaves the header zeroed.
    ///
    /// A patch cannot be planned against a header that is not there, so the tests that exercise
    /// porting need one — and building it here rather than weakening the checks is the point.
    fn managed_with_flags(cor_flags: u32, machine_value: u16) -> (Vec<u8>, PeImage) {
        // `synthetic` forwards `managed: false` unconditionally, so it produces an image with a
        // CLR directory of zero — not a managed one at all. Using it here made every porting test
        // fail at the first step with "CLR rva must map", which looked like a defect in the
        // patch code and was a fixture built against the wrong premise.
        let mut bytes = pe_fixture::synthetic_advanced(
            machine_value,
            subsystem::CONSOLE,
            false,
            &[],
            0x1000,
            true,
            0,
        );
        let image = crate::parse(&bytes).unwrap();

        // Write a plausible IMAGE_COR20_HEADER at the directory the fixture declared.
        let rva = image.optional.as_ref().unwrap().clr_header_rva;
        let start = image.rva_to_offset(rva).expect("CLR rva must map");
        bytes[start..start + 4].copy_from_slice(&COR20_MIN_SIZE.to_le_bytes());
        bytes[start + 4..start + 6].copy_from_slice(&2u16.to_le_bytes()); // major
        bytes[start + 6..start + 8].copy_from_slice(&5u16.to_le_bytes()); // minor
        bytes[start + 8..start + 12].copy_from_slice(&0x1200u32.to_le_bytes()); // metadata rva
        bytes[start + 12..start + 16].copy_from_slice(&0x200u32.to_le_bytes()); // metadata size
        bytes[start + COR20_FLAGS_OFFSET..start + COR20_FLAGS_OFFSET + 4]
            .copy_from_slice(&cor_flags.to_le_bytes());
        bytes[start + 20..start + 24].copy_from_slice(&0x0600_0001u32.to_le_bytes()); // entry

        let image = crate::parse(&bytes).unwrap();
        (bytes, image)
    }

    #[test]
    fn the_clr_header_is_read_from_the_directory_the_parser_holds() {
        let (bytes, image) = managed_with_flags(COR_ILONLY | COR_32BITREQUIRED, machine::I386);
        let clr = image
            .clr_header(&bytes)
            .expect("a managed image has a CLR header");

        assert_eq!(clr.cor_flags, COR_ILONLY | COR_32BITREQUIRED);
        assert!(clr.is_il_only());
        assert!(clr.is_32bit_required());
        assert!(!clr.has_native_entry_point());
        assert_eq!(clr.runtime_major, 2);
        assert_eq!(clr.metadata_size, 0x200);
    }

    #[test]
    fn a_native_image_is_refused_and_told_it_needs_a_recompiler() {
        // The refusal that matters most: this is what a customer asks for first.
        let bytes = pe_fixture::synthetic(machine::I386, subsystem::CONSOLE, false);
        let image = crate::parse(&bytes).unwrap();

        match plan_port(&bytes, &image, true) {
            PortVerdict::Refused { reason, detail } => {
                assert_eq!(reason, "native-code-needs-recompilation");
                assert!(
                    detail.contains("recompiler"),
                    "the reference must name what would actually be required: {detail}"
                );
                assert!(
                    detail.contains("crashes"),
                    "the reference must say what a flag-only change would cause: {detail}"
                );
            }
            other => panic!("a native image must be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_32bit_required_il_only_assembly_is_portable_by_one_flag() {
        let (bytes, image) = managed_with_flags(COR_ILONLY | COR_32BITREQUIRED, machine::I386);

        match plan_port(&bytes, &image, true) {
            PortVerdict::Safe { edits, rationale } => {
                assert_eq!(edits.len(), 1, "exactly one field changes");
                let edit = &edits[0];
                assert_eq!(edit.what, "COMIMAGE_FLAGS_32BITREQUIRED");
                assert_eq!(
                    u32::from_le_bytes(edit.after.clone().try_into().unwrap()),
                    COR_ILONLY,
                    "only the 32-bit-required bit is cleared"
                );
                assert!(rationale.contains("corflags"), "{rationale}");
            }
            other => panic!("expected a safe port, got {other:?}"),
        }
    }

    #[test]
    fn applying_the_edit_makes_the_image_anycpu_and_nothing_else_changes() {
        let (mut bytes, image) = managed_with_flags(COR_ILONLY | COR_32BITREQUIRED, machine::I386);
        let before_len = bytes.len();
        let original = bytes.clone();

        let PortVerdict::Safe { edits, .. } = plan_port(&bytes, &image, true) else {
            panic!("expected a safe port");
        };
        apply_edits(&mut bytes, &edits).expect("the edit applies");

        // Re-parse: the file must still be a valid image, and the flag must be the only change.
        let patched = crate::parse(&bytes).expect("the patched file must still parse");
        let clr = patched.clr_header(&bytes).expect("still managed");
        assert!(!clr.is_32bit_required(), "the pin must be gone");
        assert!(clr.is_il_only(), "ILONLY must be preserved");
        assert_eq!(bytes.len(), before_len, "a metadata edit changes no size");

        // Exactly one nibble of difference: the 0x2 bit.
        let differing: Vec<usize> = original
            .iter()
            .zip(bytes.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(index, _)| index)
            .collect();
        assert_eq!(differing.len(), 1, "exactly one byte may change");
        assert_eq!(
            original[differing[0]] ^ bytes[differing[0]],
            COR_32BITREQUIRED as u8
        );
    }

    #[test]
    fn an_already_anycpu_assembly_reports_nothing_to_do() {
        let (bytes, image) = managed_with_flags(COR_ILONLY, machine::I386);
        match plan_port(&bytes, &image, true) {
            PortVerdict::AlreadyPortable { rationale } => {
                assert!(rationale.contains("AnyCPU"), "{rationale}")
            }
            other => panic!("expected already portable, got {other:?}"),
        }
    }

    #[test]
    fn a_32bit_preferred_assembly_needs_no_change_but_says_why() {
        // 32BITPREFERRED is not a pin: a 64-bit host may still load it. Reporting it as work
        // would send a customer to their build system for nothing.
        let (bytes, image) = managed_with_flags(COR_ILONLY | COR_32BITPREFERRED, machine::I386);
        match plan_port(&bytes, &image, true) {
            PortVerdict::AlreadyPortable { rationale } => {
                assert!(rationale.contains("prefer"), "{rationale}")
            }
            other => panic!("expected already portable, got {other:?}"),
        }
    }

    #[test]
    fn a_mixed_mode_assembly_is_refused_rather_than_half_ported() {
        // ILONLY clear means native code hides in the image. Clearing a flag here would produce
        // a file whose managed half moves and whose native half does not.
        let (bytes, image) = managed_with_flags(COR_32BITREQUIRED, machine::I386);
        match plan_port(&bytes, &image, true) {
            PortVerdict::Refused { reason, .. } => assert_eq!(reason, "mixed-mode-assembly"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_native_entry_point_is_refused() {
        let (bytes, image) = managed_with_flags(
            COR_ILONLY | COR_32BITREQUIRED | COR_NATIVE_ENTRYPOINT,
            machine::I386,
        );
        match plan_port(&bytes, &image, true) {
            PortVerdict::Refused { reason, .. } => assert_eq!(reason, "native-entry-point"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_non_arm64_destination_has_nothing_to_port() {
        let (bytes, image) = managed_with_flags(COR_ILONLY | COR_32BITREQUIRED, machine::I386);
        match plan_port(&bytes, &image, false) {
            PortVerdict::Refused { reason, .. } => assert_eq!(reason, "destination-not-arm64"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_unreadable_clr_header_is_refused_not_guessed() {
        // A managed image whose header is all zeroes: the directory points somewhere, but the
        // declared size is not one this reader understands.
        let bytes = pe_fixture::synthetic_advanced(
            machine::I386,
            subsystem::CONSOLE,
            false,
            &[],
            0x1000,
            true,
            0,
        );
        let image = crate::parse(&bytes).unwrap();
        match plan_port(&bytes, &image, true) {
            PortVerdict::Refused { reason, .. } => assert_eq!(reason, "unreadable-clr-header"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn applying_to_the_wrong_file_is_refused_rather_than_corrupting_it() {
        // The same shape of error as measuring one machine and reporting about another: a plan
        // made against one file must not be applied to a different one.
        let (bytes, image) = managed_with_flags(COR_ILONLY | COR_32BITREQUIRED, machine::I386);
        let PortVerdict::Safe { edits, .. } = plan_port(&bytes, &image, true) else {
            panic!("expected a safe port");
        };

        let mut other = bytes.clone();
        other[edits[0].offset] ^= 0xFF;
        match apply_edits(&mut other, &edits) {
            Err(PatchError::UnexpectedBytes { offset, .. }) => {
                assert_eq!(offset, edits[0].offset)
            }
            other => panic!("expected a byte-mismatch refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_out_of_range_edit_is_refused() {
        let edit = Edit {
            offset: 1_000_000,
            before: vec![0, 0, 0, 0],
            after: vec![1, 0, 0, 0],
            what: "test".to_owned(),
        };
        let mut data = vec![0u8; 16];
        assert!(matches!(
            apply_edits(&mut data, &[edit]),
            Err(PatchError::OutOfRange { .. })
        ));
    }

    #[test]
    fn a_failing_edit_leaves_no_partial_change() {
        // Verify-all before write-any: a plan whose second edit is wrong must not leave the
        // first one applied.
        let (bytes, image) = managed_with_flags(COR_ILONLY | COR_32BITREQUIRED, machine::I386);
        let PortVerdict::Safe { edits, .. } = plan_port(&bytes, &image, true) else {
            panic!("expected a safe port");
        };
        let mut good = edits[0].clone();
        let bad = Edit {
            offset: edits[0].offset + 1,
            before: vec![0xFF],
            after: vec![0x00],
            what: "deliberately wrong".to_owned(),
        };

        let mut data = bytes.clone();
        assert!(apply_edits(&mut data, &[good.clone(), bad]).is_err());
        assert_eq!(data, bytes, "nothing may have been written");

        // And with only the good edit it does apply, so the test is not passing vacuously.
        assert!(apply_edits(&mut data, &[good.clone()]).is_ok());
        assert_ne!(data, bytes);
        good.after.clear();
    }
}
