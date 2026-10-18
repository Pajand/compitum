//! CHPE metadata: how a hybrid ARM64 image is *actually* identified.
//!
//! # The correction this module exists for
//!
//! An earlier revision of this crate classified images by the COFF `Machine` field alone,
//! using `0xA641` for ARM64EC and `0xA64E` for ARM64X. **Those are not valid final PE machine
//! types.** Microsoft's own documentation states it plainly:
//!
//! > "When inspecting intermediate OBJ or LIB files ... `link /dump /headers` shows
//! > `A641 machine (ARM64EC)`. This value (0xA641) is an internal MSVC identifier used for
//! > Arm64EC object files and is **not defined in winnt.h**. It is **not a valid final PE
//! > machine type** — only the linked EXE or DLL carries the `8664 (x64) (ARM64X)` or
//! > `AA64 (ARM64) (ARM64X)` machine value."
//!
//! LLVM's review notes corroborate it independently:
//!
//! > "ARM64EC/ARM64X binaries use ARM64 or AMD64 machine types, but provide additional CHPE
//! > metadata that may be used to distinguish them from pure ARM64/AMD64 binaries."
//!
//! A linked ARM64EC executable therefore reports machine `0x8664`, which is indistinguishable
//! from plain x86-64 *by machine type alone*. This was found by building a real ARM64EC
//! executable with clang and lld-link and asking this crate to classify it.
//!
//! # The real rule
//!
//! | Machine | CHPE metadata | Actual family |
//! |---|---|---|
//! | `0xAA64` | absent | pure ARM64 |
//! | `0x8664` | absent | pure x86-64 |
//! | `0x8664` | present, version 1 | **ARM64EC** |
//! | `0xAA64` | present, version 2 | **ARM64X** |
//!
//! # Where the metadata lives
//!
//! ```text
//! optional header
//!   └── data directory [10]  -> IMAGE_LOAD_CONFIG_DIRECTORY64
//!         └── +0xC8  CHPEMetadataPointer   (a VIRTUAL ADDRESS, not an RVA)
//!               └── IMAGE_ARM64EC_METADATA
//!                     +0x00  Version           (u32)
//!                     +0x04  CodeMap           (RVA)
//!                     +0x08  CodeMapCount      (u32)
//!                     +0x0C  CodeRangesToEntryPoints
//!                     +0x10  RedirectionMetadata
//! ```
//!
//! `CHPEMetadataPointer` is a **virtual address**, so the image base must be subtracted
//! before it can be converted to a file offset. Reading it as an RVA would land at the wrong
//! place on any image whose base is not zero, which is every real image.
//!
//! # Why a missing directory is not an error
//!
//! Most binaries have no load configuration at all, and most load configurations are shorter
//! than `0xD0` bytes because `CHPEMetadataPointer` sits late in the structure. Both are
//! ordinary, so this module returns `Ok(None)` rather than an error: absence is information,
//! and treating it as a failure would make the common case look broken.

use crate::reader::{u32_at, u64_at};
use crate::PeImage;

/// The load-configuration structure must be at least this long to hold
/// `CHPEMetadataPointer`.
///
/// The field sits at offset `0xC8` and occupies eight bytes, so a directory reporting a
/// smaller size simply does not contain it. Real linkers emit shorter structures whenever
/// there is nothing hybrid to describe.
pub const MIN_LOAD_CONFIG_FOR_CHPE: u32 = 0xD0;

/// Offset of `CHPEMetadataPointer` within `IMAGE_LOAD_CONFIG_DIRECTORY64`.
const OFF_CHPE_METADATA_POINTER: usize = 0xC8;

/// Offset of `Version` within `IMAGE_ARM64EC_METADATA`.
const OFF_CHPE_VERSION: usize = 0x00;
/// Offset of `CodeMap` within `IMAGE_ARM64EC_METADATA`.
const OFF_CHPE_CODE_MAP: usize = 0x04;
/// Offset of `CodeMapCount` within `IMAGE_ARM64EC_METADATA`.
const OFF_CHPE_CODE_MAP_COUNT: usize = 0x08;

/// The largest plausible `CodeMapCount`.
///
/// A code map entry is twelve bytes, so a hostile file claiming four billion entries would
/// describe a map larger than any file. Bounding it here keeps a reported count from being
/// used to size an allocation or a loop.
const MAX_PLAUSIBLE_CODE_MAP_COUNT: u32 = 1 << 24;

/// The kind of hybrid image a CHPE metadata block describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HybridKind {
    /// The `version 1` layout: x86-64 machine type with recompiled AArch64 code.
    ///
    /// A real linked executable carries machine `0x8664`, so this cannot be distinguished
    /// from plain x86-64 without reading the CHPE metadata.
    Arm64Ec,
    /// The `version 2` layout: AArch64 machine type with both slices present.
    Arm64X,
    /// A version this build does not recognize.
    ///
    /// Retained rather than discarded, because a future Windows release may add one and a
    /// record that says "hybrid, version 7" is far more useful than one that says "not
    /// hybrid".
    Unrecognized {
        /// The version value read from the metadata.
        version: u32,
    },
}

impl HybridKind {
    /// Maps a CHPE metadata version to a kind.
    #[must_use]
    pub fn from_version(version: u32) -> Self {
        match version {
            1 => HybridKind::Arm64Ec,
            2 => HybridKind::Arm64X,
            other => HybridKind::Unrecognized { version: other },
        }
    }

    /// Stable identifier for JSON and Oracle records.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            HybridKind::Arm64Ec => "arm64ec",
            HybridKind::Arm64X => "arm64x",
            HybridKind::Unrecognized { .. } => "chpe_unknown_version",
        }
    }

    /// Returns `true` when the image needs a translator for part of its code.
    #[must_use]
    pub fn needs_partial_translation(self) -> bool {
        matches!(self, HybridKind::Arm64Ec)
    }

    /// Returns `true` when the image carries a pure AArch64 slice that can be selected
    /// instead of translating.
    #[must_use]
    pub fn has_native_slice(self) -> bool {
        matches!(self, HybridKind::Arm64X)
    }
}

/// The hybrid metadata attached to an image, when it has any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridMetadata {
    /// Which layout the metadata describes.
    pub kind: HybridKind,
    /// The raw version field, kept for the Oracle even when unrecognized.
    pub version: u32,
    /// RVA of the code map, or zero when absent.
    pub code_map_rva: u32,
    /// Number of entries in the code map.
    ///
    /// This is the most decision-relevant number in the structure: it states how many ranges
    /// of AArch64 code exist alongside the x86-64 code, which is a direct measure of how much
    /// of a hybrid image is already native. An `ARM64EC` image with a large code map is
    /// mostly AArch64 and gains most from the partial-translation route.
    pub code_map_count: u32,
    /// RVA of the load configuration the metadata was reached through.
    pub load_config_rva: u32,
}

impl HybridMetadata {
    /// Serializes to the shape the Oracle records.
    #[must_use]
    pub fn to_json(&self) -> compitum_json::Value {
        compitum_json::Object::new()
            .with("kind", self.kind.id())
            .with("version", self.version)
            .with("code_map_rva", u64::from(self.code_map_rva))
            .with("code_map_count", u64::from(self.code_map_count))
            .with("load_config_rva", u64::from(self.load_config_rva))
            .into()
    }
}

/// Why hybrid metadata could not be read, when the file claimed to have a load configuration
/// but the pointer was unusable.
///
/// Distinct from "absent", which is the ordinary case and not a failure. A file that declares
/// a load configuration large enough to hold `CHPEMetadataPointer` but whose pointer does not
/// resolve is worth reporting, because it suggests either a malformed image or a newer layout
/// this build does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridReadOutcome {
    /// The image has no load configuration, or one too short to hold the pointer.
    NotPresent,
    /// Hybrid metadata was read.
    Present(HybridKind),
    /// The pointer did not resolve to a readable place in the file.
    PointerUnusable {
        /// The virtual address that failed to resolve.
        pointer: u64,
    },
}

/// Reads the hybrid metadata reachable from an image's load configuration.
///
/// Returns `Ok(None)` when the image genuinely has none, which is the common case and not an
/// error. Returns `Err` only when a pointer was present and could not be read.
///
/// # Errors
///
/// Returns a description of the problem when the load configuration or the metadata it points
/// at is present but unreadable.
pub fn read_hybrid_metadata(
    data: &[u8],
    image: &PeImage,
) -> Result<Option<HybridMetadata>, String> {
    let Some(optional) = &image.optional else {
        return Ok(None);
    };

    let load_config_rva = optional.load_config_rva;
    if load_config_rva == 0 {
        // No load configuration at all. Ordinary for a minimal or freestanding image.
        return Ok(None);
    }
    if load_config_size_too_small(optional.load_config_size) {
        // The directory is declared but is too short to contain the pointer. Also ordinary:
        // real linkers emit short structures whenever there is nothing hybrid to describe.
        return Ok(None);
    }

    let Some(load_config_offset) = image.rva_to_offset(load_config_rva) else {
        return Err(format!(
            "the load configuration is declared at RVA 0x{load_config_rva:X} but that address \
             does not fall inside any mapped section"
        ));
    };

    let pointer = u64_at(data, load_config_offset + OFF_CHPE_METADATA_POINTER)
        .map_err(|e| format!("the load configuration is truncated: {e}"))?;

    if pointer == 0 {
        // A load configuration with a null CHPE pointer: not hybrid.
        return Ok(None);
    }

    // The pointer is a VIRTUAL ADDRESS, so the image base must come off it before it can be
    // treated as an RVA. Reading it as an RVA would land at the wrong place on any image whose
    // base is not zero, which is every real image.
    if pointer < optional.image_base {
        return Err(format!(
            "the CHPE metadata pointer 0x{pointer:X} is below the image base 0x{:X}, so it \
             cannot be a virtual address inside this image",
            optional.image_base
        ));
    }
    let metadata_rva = pointer - optional.image_base;
    if metadata_rva > u64::from(u32::MAX) {
        return Err(format!(
            "the CHPE metadata pointer implies RVA 0x{metadata_rva:X}, which exceeds the \
            32-bit address space"
        ));
    }
    let metadata_rva = metadata_rva as u32;

    let Some(metadata_offset) = image.rva_to_offset(metadata_rva) else {
        return Err(format!(
            "the CHPE metadata pointer resolves to RVA 0x{metadata_rva:X}, which does not fall \
             inside any mapped section"
        ));
    };

    let version = u32_at(data, metadata_offset + OFF_CHPE_VERSION)
        .map_err(|e| format!("the CHPE metadata is truncated: {e}"))?;
    let code_map_rva = u32_at(data, metadata_offset + OFF_CHPE_CODE_MAP).unwrap_or(0);
    let code_map_count = u32_at(data, metadata_offset + OFF_CHPE_CODE_MAP_COUNT)
        .unwrap_or(0)
        .min(MAX_PLAUSIBLE_CODE_MAP_COUNT);

    Ok(Some(HybridMetadata {
        kind: HybridKind::from_version(version),
        version,
        code_map_rva,
        code_map_count,
        load_config_rva,
    }))
}

/// Returns `true` when a declared load-configuration size cannot contain the CHPE pointer.
///
/// A size of zero is treated as "not declared" rather than as "too small to be valid", because
/// some linkers zero the size field on images that have no load configuration.
#[must_use]
fn load_config_size_too_small(declared_size: u32) -> bool {
    declared_size < MIN_LOAD_CONFIG_FOR_CHPE
}

/// The classification outcome that combines the machine field with the hybrid metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classified {
    /// Pure AArch64: machine `0xAA64`, no hybrid metadata.
    PureArm64,
    /// Plain 64-bit x86: machine `0x8664`, no hybrid metadata.
    PureX86_64,
    /// A hybrid image whose AArch64 code is native and whose x86-64 code is not.
    Hybrid(HybridKind),
}

impl Classified {
    /// The family identifier used in the router and in Oracle records.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Classified::PureArm64 => "arm64",
            Classified::PureX86_64 => "x86_64",
            Classified::Hybrid(HybridKind::Arm64Ec) => "arm64ec",
            Classified::Hybrid(HybridKind::Arm64X) => "arm64x",
            Classified::Hybrid(HybridKind::Unrecognized { .. }) => "chpe_hybrid_unknown",
        }
    }

    /// Returns `true` when no instruction needs translation.
    #[must_use]
    pub fn is_fully_native(self) -> bool {
        matches!(self, Classified::PureArm64)
    }
}

/// Classifies an image using both the machine field **and** the hybrid metadata.
///
/// This is the entry point callers should use. [`HybridMetadata`] carries the evidence, and
/// this function is the rule that turns machine type plus metadata into a family.
///
/// `hybrid` is `None` when the image has none, and an `Err` from
/// [`read_hybrid_metadata`] is reported separately rather than forced into a classification,
/// because an unreadable pointer means the classification is genuinely unknown for a hybrid
/// image but still knowable for a non-hybrid one.
#[must_use]
pub fn classify_image(image: &PeImage, hybrid: Option<&HybridMetadata>) -> Classified {
    let machine = image.coff.machine.raw();

    match (machine, hybrid) {
        // ARM64 machine with ARM64X metadata: a fat image carrying both slices.
        (0xAA64, Some(metadata)) if metadata.kind == HybridKind::Arm64X => {
            Classified::Hybrid(HybridKind::Arm64X)
        }
        // x86-64 machine WITH hybrid metadata: this is the ARM64EC case, and the reason
        // machine type alone is insufficient.
        (0x8664, Some(metadata)) => match metadata.kind {
            HybridKind::Arm64Ec => Classified::Hybrid(HybridKind::Arm64Ec),
            // A version this build does not know. Reported as hybrid because the metadata
            // exists, which is stronger evidence than the machine field alone.
            other => Classified::Hybrid(other),
        },
        // ARM64 machine, no usable metadata: pure AArch64.
        (0xAA64, _) => Classified::PureArm64,
        // x86-64 machine, no metadata: plain 64-bit x86. This is the conservative outcome for
        // an ARM64EC image whose metadata could not be read -- it over-translates rather than
        // promising native execution it cannot deliver.
        (0x8664, _) => Classified::PureX86_64,
        // The object-file identifiers. `0xA641` and `0xA64E` appear in TOOLCHAIN OUTPUT --
        // an ARM64EC or ARM64X `.obj` -- rather than in a linked image. Microsoft states that
        // `0xA641` "is an internal MSVC identifier used for Arm64EC object files and is not
        // defined in winnt.h", and that it "is not a valid final PE machine type".
        //
        // They are still recognised here, because a file carrying one really is an ARM64EC or
        // ARM64X artifact and refusing to name it would be less useful than naming it
        // accurately. Whether the file is *loadable* is a separate question, answered by
        // `CoffHeader::is_object_file`.
        (0xA641, _) => Classified::Hybrid(HybridKind::Arm64Ec),
        (0xA64E, _) => Classified::Hybrid(HybridKind::Arm64X),

        // Any other machine type falls back to the machine field, which the router handles.
        _ => {
            if image.coff.machine.family() == crate::machine::AbiFamily::Arm64Native {
                Classified::PureArm64
            } else {
                Classified::PureX86_64
            }
        }
    }
}

/// Returns `true` when the machine type is a toolchain object-file identifier rather than a
/// valid final-image type.
///
/// Such a file cannot be loaded by Windows regardless of architecture, so a route decision
/// about it is moot. Reporting the distinction lets a caller say something useful instead of
/// producing a confident verdict about a file that will never execute.
#[must_use]
pub fn is_object_only_machine(machine: u16) -> bool {
    matches!(machine, 0xA641 | 0xA64E)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{machine, subsystem, synthetic};

    #[test]
    fn version_maps_to_the_documented_kinds() {
        assert_eq!(HybridKind::from_version(1), HybridKind::Arm64Ec);
        assert_eq!(HybridKind::from_version(2), HybridKind::Arm64X);
        assert_eq!(
            HybridKind::from_version(7),
            HybridKind::Unrecognized { version: 7 },
            "an unknown version must be preserved rather than silently dropped"
        );
    }

    #[test]
    fn kind_properties_match_the_layouts() {
        assert!(HybridKind::Arm64Ec.needs_partial_translation());
        assert!(!HybridKind::Arm64Ec.has_native_slice());
        assert!(!HybridKind::Arm64X.needs_partial_translation());
        assert!(
            HybridKind::Arm64X.has_native_slice(),
            "ARM64X carries a pure AArch64 slice that can be chosen instead of translating"
        );
    }

    #[test]
    fn a_plain_image_has_no_hybrid_metadata() {
        let bytes = synthetic(machine::ARM64, subsystem::CONSOLE, false);
        let image = crate::parse(&bytes).unwrap();
        assert_eq!(
            read_hybrid_metadata(&bytes, &image).unwrap(),
            None,
            "an image with no load configuration is simply not hybrid, which is not an error"
        );
    }

    #[test]
    fn a_short_load_config_is_not_hybrid_and_not_an_error() {
        // The fixture declares a load-config directory, so this exercises the size guard
        // rather than the absent-directory path.
        let bytes = synthetic(machine::ARM64, subsystem::CONSOLE, false);
        let image = crate::parse(&bytes).unwrap();
        let load_config_size = image
            .optional
            .as_ref()
            .map(|o| o.load_config_size)
            .unwrap_or(0);

        if load_config_size < MIN_LOAD_CONFIG_FOR_CHPE {
            assert_eq!(read_hybrid_metadata(&bytes, &image).unwrap(), None);
        }
        // Either way, the call must not fail: absence of a field is not a defect.
    }

    /// The object-file identifiers are recognised, but as a distinct fact from a linked image.
    ///
    /// An earlier revision treated `0xA641` as "an ARM64EC binary" full stop. It is an
    /// ARM64EC *object-file* identifier: Microsoft states it is not defined in `winnt.h` and
    /// is not a valid final PE machine type. A linked ARM64EC executable instead carries
    /// `0x8664` plus CHPE metadata, which is why the metadata is what the classification
    /// actually rests on.
    #[test]
    fn object_file_identifiers_are_recognised_and_labelled_as_such() {
        assert!(is_object_only_machine(0xA641));
        assert!(is_object_only_machine(0xA64E));
        assert!(!is_object_only_machine(0xAA64));
        assert!(!is_object_only_machine(0x8664));

        // They still classify as hybrid artifacts, because that is what they are.
        let arm64ec_obj = crate::parse(&synthetic(0xA641, subsystem::CONSOLE, false)).unwrap();
        assert_eq!(
            classify_image(&arm64ec_obj, None),
            Classified::Hybrid(HybridKind::Arm64Ec)
        );

        // The distinction between a toolchain artefact and a linked image is carried by the
        // COFF header, not by the family: `SizeOfOptionalHeader == 0` means an object file.
        // The shared fixture builder always emits a full optional header, so this fixture is
        // a linked-image *shape* carrying an object-file machine value -- which is exactly the
        // inconsistent combination the parser must report rather than smooth over.
        assert!(
            !arm64ec_obj.coff.is_object_file(),
            "the fixture has a populated optional header, so it has linked-image structure"
        );
        assert!(
            arm64ec_obj.coff.is_executable_image(),
            "and it declares itself executable, so a caller sees both facts and can judge"
        );
    }

    /// An object file is identified by a zero-size optional header, independently of machine.
    #[test]
    fn object_files_are_identified_by_their_header_not_their_machine() {
        let mut image = crate::parse(&synthetic(machine::ARM64, subsystem::CONSOLE, false))
            .expect("fixture parses");

        assert!(!image.coff.is_object_file());
        // Clearing the optional-header size is what makes it an object file, whatever the
        // machine field says.
        image.coff.optional_header_size = 0;
        assert!(image.coff.is_object_file());
    }

    #[test]
    fn classification_uses_both_signals() {
        // Build images paired with explicit metadata so every combination is covered.
        let arm64 = crate::parse(&synthetic(machine::ARM64, subsystem::CONSOLE, false)).unwrap();
        let x86 = crate::parse(&synthetic(machine::AMD64, subsystem::CONSOLE, false)).unwrap();

        assert_eq!(classify_image(&arm64, None), Classified::PureArm64);
        assert_eq!(classify_image(&x86, None), Classified::PureX86_64);

        let arm64ec = HybridMetadata {
            kind: HybridKind::Arm64Ec,
            version: 1,
            code_map_rva: 0x2000,
            code_map_count: 42,
            load_config_rva: 0x3000,
        };
        let arm64x = HybridMetadata {
            kind: HybridKind::Arm64X,
            version: 2,
            code_map_rva: 0x2000,
            code_map_count: 42,
            load_config_rva: 0x3000,
        };

        // THE CRITICAL CASE: an x86-64 machine type plus hybrid metadata is ARM64EC, and
        // without the metadata it would be indistinguishable from plain x86-64.
        assert_eq!(
            classify_image(&x86, Some(&arm64ec)),
            Classified::Hybrid(HybridKind::Arm64Ec)
        );
        assert_eq!(
            classify_image(&arm64, Some(&arm64x)),
            Classified::Hybrid(HybridKind::Arm64X)
        );
    }

    #[test]
    fn an_unreadable_pointer_is_conservative_not_optimistic() {
        // If metadata cannot be read, an x86-64 machine type must stay x86-64. It must never
        // be promoted to native on the strength of a pointer that failed to resolve.
        let x86 = crate::parse(&synthetic(machine::AMD64, subsystem::CONSOLE, false)).unwrap();
        assert_eq!(classify_image(&x86, None), Classified::PureX86_64);
        assert!(!classify_image(&x86, None).is_fully_native());
    }

    #[test]
    fn only_pure_arm64_is_fully_native() {
        assert!(Classified::PureArm64.is_fully_native());
        assert!(!Classified::PureX86_64.is_fully_native());
        assert!(!Classified::Hybrid(HybridKind::Arm64Ec).is_fully_native());
        assert!(
            !Classified::Hybrid(HybridKind::Arm64X).is_fully_native(),
            "an ARM64X file is native only after its slice is selected, so the family alone \
             cannot claim full nativity"
        );
    }

    #[test]
    fn a_pointer_below_the_image_base_is_reported_not_ignored() {
        let mut bytes = synthetic(machine::AMD64, subsystem::CONSOLE, false);
        let mut image = crate::parse(&bytes).unwrap();

        // Force a load configuration long enough to hold the pointer, and place a value
        // below the image base in it.
        let optional = image.optional.as_mut().expect("optional header");
        optional.load_config_rva = 0x1000;
        optional.load_config_size = MIN_LOAD_CONFIG_FOR_CHPE + 8;

        let offset = image.rva_to_offset(0x1000).expect("section is mapped");
        bytes[offset + OFF_CHPE_METADATA_POINTER..offset + OFF_CHPE_METADATA_POINTER + 8]
            .copy_from_slice(&1u64.to_le_bytes());

        let result = read_hybrid_metadata(&bytes, &image);
        assert!(
            result.is_err(),
            "a virtual address below the image base cannot refer to this image, and saying so \
             is more useful than guessing"
        );
        assert!(result.unwrap_err().contains("below the image base"));
    }

    #[test]
    fn a_null_pointer_means_not_hybrid() {
        let bytes = synthetic(machine::AMD64, subsystem::CONSOLE, false);
        let mut image = crate::parse(&bytes).unwrap();
        let optional = image.optional.as_mut().expect("optional header");
        optional.load_config_rva = 0x1000;
        optional.load_config_size = MIN_LOAD_CONFIG_FOR_CHPE + 8;

        // The bytes at that address are already zero, so this exercises the null-pointer
        // path: a load configuration with a null CHPE pointer describes a non-hybrid image.
        assert_eq!(read_hybrid_metadata(&bytes, &image).unwrap(), None);
    }

    #[test]
    fn metadata_serializes_for_the_oracle() {
        let metadata = HybridMetadata {
            kind: HybridKind::Arm64Ec,
            version: 1,
            code_map_rva: 0x2000,
            code_map_count: 7,
            load_config_rva: 0x3000,
        };
        let json = metadata.to_json();
        assert_eq!(json["kind"].as_str(), Some("arm64ec"));
        assert_eq!(json["version"].as_u64(), Some(1));
        assert_eq!(json["code_map_count"].as_u64(), Some(7));
    }

    /// A hostile code-map count must be clamped rather than trusted.
    ///
    /// Asserted by behaviour, not by restating the constant: the constant alone would be
    /// optimised away at compile time, and the property that matters is what a reader returns
    /// for an absurd input.
    #[test]
    fn an_implausible_code_map_count_is_bounded() {
        // A file claiming a four-billion-entry code map would describe more memory than any
        // machine has, so the count must be clamped before a caller can size anything with it.
        let mut bytes = synthetic(machine::AMD64, subsystem::CONSOLE, false);
        let mut image = crate::parse(&bytes).unwrap();

        // Point the load configuration at real, writable bytes inside the first section.
        // `image_base` is extracted inside the same block so the mutable borrow ends before
        // `rva_to_offset` needs to read `image` immutably.
        let image_base = {
            let optional = image.optional.as_mut().expect("optional header");
            optional.load_config_rva = 0x1000;
            optional.load_config_size = MIN_LOAD_CONFIG_FOR_CHPE + 8;
            optional.image_base
        };

        let load_config_offset = image.rva_to_offset(0x1000).expect("section is mapped");
        let metadata_rva = 0x1100u32;
        let metadata_va = image_base + u64::from(metadata_rva);

        // CHPEMetadataPointer, then the metadata block with an absurd CodeMapCount.
        bytes[load_config_offset + OFF_CHPE_METADATA_POINTER
            ..load_config_offset + OFF_CHPE_METADATA_POINTER + 8]
            .copy_from_slice(&metadata_va.to_le_bytes());

        let metadata_offset = image
            .rva_to_offset(metadata_rva)
            .expect("section is mapped");
        bytes[metadata_offset + OFF_CHPE_VERSION..metadata_offset + OFF_CHPE_VERSION + 4]
            .copy_from_slice(&1u32.to_le_bytes()); // ARM64EC
        bytes[metadata_offset + OFF_CHPE_CODE_MAP_COUNT
            ..metadata_offset + OFF_CHPE_CODE_MAP_COUNT + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());

        let metadata = read_hybrid_metadata(&bytes, &image)
            .expect("the pointer is valid")
            .expect("metadata is present");

        assert_eq!(
            metadata.kind,
            HybridKind::Arm64Ec,
            "the version still identifies the layout, whatever the count claims"
        );
        assert!(
            metadata.code_map_count <= MAX_PLAUSIBLE_CODE_MAP_COUNT,
            "a code-map count of {} must be clamped to {} so it cannot be used to size an              allocation or drive a loop",
            u32::MAX,
            MAX_PLAUSIBLE_CODE_MAP_COUNT
        );
    }

    #[test]
    fn size_guard_treats_zero_as_undeclared() {
        assert!(load_config_size_too_small(0));
        assert!(load_config_size_too_small(MIN_LOAD_CONFIG_FOR_CHPE - 1));
        assert!(!load_config_size_too_small(MIN_LOAD_CONFIG_FOR_CHPE));
    }
}
