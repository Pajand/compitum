//! The `IMAGE_FILE_MACHINE` vocabulary and ABI classification.
//!
//! This is the first and most consequential decision COMPITUM makes. Every routing
//! choice, every compatibility verdict, and every Oracle record descends from correctly
//! reading one 16-bit field in the COFF header.
//!
//! # Why "ARM64" is not one thing
//!
//! The single most common mistake in this problem space is to treat every binary that
//! mentions ARM64 as native ARM64. It is not true. There are three distinct ARM64
//! flavours, and they behave completely differently:
//!
//! * **ARM64** (`0xAA64`) — pure AArch64. Executes natively on an ARM64 CPU. No
//!   translation of any kind is required.
//!
//! * **ARM64EC** (`0xA641`) — "Emulation Compatible". A *hybrid* image that contains
//!   both AArch64 code **and x86-64 code in the same file**. NVIDIA's own Windows-on-ARM
//!   porting guide describes the mechanism: when execution transfers from an ARM64EC
//!   function into a module compiled for x86-64, marshalling code maintains
//!   compatibility. The practical consequence is unavoidable: **an ARM64EC binary cannot
//!   execute on an ARM64 CPU without a translator for its x86-64 portions.** However —
//!   and this is where COMPITUM earns its keep — an ARM64EC binary is *not* equivalent
//!   to a plain x86-64 binary either. Routing it to a full emulator wastes most of the
//!   available performance, because the majority of its code is already native ARM64.
//!
//! * **ARM64X** (`0xA64E`) — a *fat* binary carrying both an ARM64 slice and an ARM64EC
//!   slice in one file, with a dispatch mechanism selecting between them at load time.
//!   Correct handling means choosing the ARM64 slice and never entering the hybrid path.
//!
//! A tool that collapses these three into one bucket will be wrong in one direction or
//! the other on almost every real-world binary.

use std::fmt;

/// The `IMAGE_FILE_MACHINE` value from a PE COFF header.
///
/// Preserves the raw 16-bit value, because a file can legitimately carry a machine type
/// COMPITUM does not yet know how to route, and silently mapping that to "unknown" would
/// lose information an Oracle record needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Machine(pub u16);

impl Machine {
    /// `IMAGE_FILE_MACHINE_UNKNOWN`
    pub const UNKNOWN: Machine = Machine(0x0000);
    /// `IMAGE_FILE_MACHINE_I386` — 32-bit x86.
    pub const I386: Machine = Machine(0x014C);
    /// `IMAGE_FILE_MACHINE_AMD64` — 64-bit x86 (x86-64).
    pub const AMD64: Machine = Machine(0x8664);
    /// `IMAGE_FILE_MACHINE_IA64` — Itanium.
    pub const IA64: Machine = Machine(0x0200);
    /// `IMAGE_FILE_MACHINE_ARM` — 32-bit ARM, little endian.
    pub const ARM: Machine = Machine(0x01C0);
    /// `IMAGE_FILE_MACHINE_ARMNT` — 32-bit ARM Thumb-2.
    pub const ARMNT: Machine = Machine(0x01C4);
    /// `IMAGE_FILE_MACHINE_ARM64` — pure 64-bit ARM (AArch64).
    pub const ARM64: Machine = Machine(0xAA64);
    /// The MSVC **object-file** identifier for ARM64EC: `0xA641`.
    ///
    /// This is **not** a valid final PE machine type and is not defined in `winnt.h`.
    /// Microsoft's documentation states it "is an internal MSVC identifier used for Arm64EC
    /// object files", and that "only the linked EXE or DLL carries the `8664 (x64) (ARM64X)`
    /// or `AA64 (ARM64) (ARM64X)` machine value".
    ///
    /// A linked ARM64EC executable therefore reports [`Machine::AMD64`], and is distinguished
    /// from plain x86-64 only by its CHPE metadata. See [`crate::chpe`].
    pub const ARM64EC: Machine = Machine(0xA641);
    /// The MSVC **object-file** identifier for ARM64X: `0xA64E`.
    ///
    /// Like [`Machine::ARM64EC`], this appears in toolchain output rather than in a linked
    /// image. A real ARM64X executable carries [`Machine::ARM64`] plus CHPE metadata.
    pub const ARM64X: Machine = Machine(0xA64E);
    /// `IMAGE_FILE_MACHINE_CHPE_X86` — Compiled Hybrid Portable Executable.
    pub const CHPE_X86: Machine = Machine(0x3A64);
    /// `IMAGE_FILE_MACHINE_RISCV64` — 64-bit RISC-V.
    pub const RISCV64: Machine = Machine(0x5064);
    /// `IMAGE_FILE_MACHINE_RISCV32` — 32-bit RISC-V.
    pub const RISCV32: Machine = Machine(0x5032);
    /// `IMAGE_FILE_MACHINE_LOONGARCH64` — 64-bit LoongArch.
    pub const LOONGARCH64: Machine = Machine(0x6264);
    /// `IMAGE_FILE_MACHINE_POWERPC` — 32-bit PowerPC.
    pub const POWERPC: Machine = Machine(0x01F0);

    /// The raw value, as it appears in the file.
    #[must_use]
    pub fn raw(self) -> u16 {
        self.0
    }

    /// Classifies the raw value into an [`AbiFamily`].
    #[must_use]
    pub fn family(self) -> AbiFamily {
        match self.0 {
            0x014C => AbiFamily::X86,
            0x8664 => AbiFamily::X86_64,
            0xAA64 => AbiFamily::Arm64Native,
            0xA641 => AbiFamily::Arm64Hybrid,
            0xA64E => AbiFamily::Arm64Fat,
            0x3A64 => AbiFamily::X86Hybrid,
            0x01C0 | 0x01C2 | 0x01C4 => AbiFamily::Arm32,
            0x0200 => AbiFamily::Itanium,
            0x5032 | 0x5064 | 0x5128 => AbiFamily::RiscV,
            0x6232 | 0x6264 => AbiFamily::LoongArch,
            0x01F0 | 0x01F1 => AbiFamily::PowerPc,
            0x0000 => AbiFamily::Unknown,
            _ => AbiFamily::Other,
        }
    }

    /// The canonical uppercase name, as Microsoft's headers spell it.
    ///
    /// Returns `None` for values COMPITUM does not recognize; callers should render the
    /// raw hex instead of inventing a name.
    #[must_use]
    pub fn canonical_name(self) -> Option<&'static str> {
        Some(match self.0 {
            0x0000 => "IMAGE_FILE_MACHINE_UNKNOWN",
            0x014C => "IMAGE_FILE_MACHINE_I386",
            0x8664 => "IMAGE_FILE_MACHINE_AMD64",
            0x0200 => "IMAGE_FILE_MACHINE_IA64",
            0x01C0 => "IMAGE_FILE_MACHINE_ARM",
            0x01C2 => "IMAGE_FILE_MACHINE_THUMB",
            0x01C4 => "IMAGE_FILE_MACHINE_ARMNT",
            0xAA64 => "IMAGE_FILE_MACHINE_ARM64",
            0xA641 => "IMAGE_FILE_MACHINE_ARM64EC",
            0xA64E => "IMAGE_FILE_MACHINE_ARM64X",
            0x3A64 => "IMAGE_FILE_MACHINE_CHPE_X86",
            0x5032 => "IMAGE_FILE_MACHINE_RISCV32",
            0x5064 => "IMAGE_FILE_MACHINE_RISCV64",
            0x5128 => "IMAGE_FILE_MACHINE_RISCV128",
            0x6232 => "IMAGE_FILE_MACHINE_LOONGARCH32",
            0x6264 => "IMAGE_FILE_MACHINE_LOONGARCH64",
            0x01F0 => "IMAGE_FILE_MACHINE_POWERPC",
            0x01F1 => "IMAGE_FILE_MACHINE_POWERPCFP",
            _ => return None,
        })
    }

    /// The short name used in COMPITUM's own output and JSON keys.
    ///
    /// Protocol value: never translated, never changed. These strings appear in Oracle
    /// records, so stability across versions matters more than readability.
    #[must_use]
    pub fn short_name(self) -> &'static str {
        match self.family() {
            AbiFamily::X86 => "x86",
            AbiFamily::X86_64 => "x86_64",
            AbiFamily::Arm64Native => "arm64",
            AbiFamily::Arm64Hybrid => "arm64ec",
            AbiFamily::Arm64Fat => "arm64x",
            AbiFamily::X86Hybrid => "chpe_x86",
            AbiFamily::Arm32 => "arm32",
            AbiFamily::Itanium => "ia64",
            AbiFamily::RiscV => "riscv",
            AbiFamily::LoongArch => "loongarch",
            AbiFamily::PowerPc => "powerpc",
            AbiFamily::Unknown => "unknown",
            AbiFamily::Other => "other",
        }
    }

    /// Returns `true` when the machine type is one of the three ARM64 flavours.
    #[must_use]
    pub fn is_arm64_flavour(self) -> bool {
        matches!(
            self.family(),
            AbiFamily::Arm64Native | AbiFamily::Arm64Hybrid | AbiFamily::Arm64Fat
        )
    }
}

impl fmt::Display for Machine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.canonical_name() {
            Some(name) => f.write_str(name),
            None => write!(f, "0x{:04X}", self.0),
        }
    }
}

/// The ABI family a [`Machine`] belongs to.
///
/// This is the value the routing engine actually switches on, because what matters for
/// execution is not the exact machine number but which class of translation (if any) is
/// required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AbiFamily {
    /// Not a recognized machine type.
    Unknown,
    /// 32-bit x86.
    X86,
    /// 64-bit x86.
    X86_64,
    /// Pure 64-bit ARM. The only family that needs no translation at all.
    Arm64Native,
    /// Hybrid ARM64 + x86-64 in one image (ARM64EC).
    Arm64Hybrid,
    /// Fat binary containing both ARM64 and ARM64EC slices.
    Arm64Fat,
    /// Compiled Hybrid PE, the x86 side of the hybrid scheme.
    X86Hybrid,
    /// 32-bit ARM.
    Arm32,
    /// Itanium.
    Itanium,
    /// RISC-V, any width.
    RiscV,
    /// LoongArch, any width.
    LoongArch,
    /// PowerPC.
    PowerPc,
    /// A valid but unrecognized machine value.
    Other,
}

impl AbiFamily {
    /// Stable identifier for JSON and Oracle records.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            AbiFamily::Unknown => "unknown",
            AbiFamily::X86 => "x86",
            AbiFamily::X86_64 => "x86_64",
            AbiFamily::Arm64Native => "arm64",
            AbiFamily::Arm64Hybrid => "arm64ec",
            AbiFamily::Arm64Fat => "arm64x",
            AbiFamily::X86Hybrid => "chpe_x86",
            AbiFamily::Arm32 => "arm32",
            AbiFamily::Itanium => "ia64",
            AbiFamily::RiscV => "riscv",
            AbiFamily::LoongArch => "loongarch",
            AbiFamily::PowerPc => "powerpc",
            AbiFamily::Other => "other",
        }
    }

    /// Returns `true` when the image's own code executes on an ARM64 CPU as-is.
    ///
    /// Only pure ARM64 qualifies. ARM64EC does **not**, because it genuinely contains
    /// x86-64 code; ARM64X does, but only after its ARM64 slice is selected, so the
    /// answer depends on the loader rather than on the file alone.
    #[must_use]
    pub fn is_fully_native_on_arm64(self) -> bool {
        matches!(self, AbiFamily::Arm64Native)
    }

    /// Returns `true` when translation of *some* of the image is required on ARM64.
    #[must_use]
    pub fn needs_partial_translation(self) -> bool {
        matches!(self, AbiFamily::Arm64Hybrid | AbiFamily::Arm64Fat)
    }

    /// Returns `true` when the whole image needs translation on an ARM64 host.
    #[must_use]
    pub fn needs_full_translation(self) -> bool {
        matches!(
            self,
            AbiFamily::X86
                | AbiFamily::X86_64
                | AbiFamily::X86Hybrid
                | AbiFamily::Arm32
                | AbiFamily::Itanium
        )
    }

    /// A precise English explanation of what this family implies for execution.
    ///
    /// This is the text an operator reads when a binary does not run. It is deliberately
    /// specific rather than reassuring: a vague message here is what produces support
    /// requests that cannot be answered.
    #[must_use]
    pub fn execution_semantics(self) -> &'static str {
        match self {
            AbiFamily::Arm64Native => {
                "Pure AArch64. Every instruction in this image is directly executable by \
                 an ARM64 CPU; no translator is involved at any point."
            }
            AbiFamily::Arm64Hybrid => {
                "Hybrid AArch64 and x86-64 in one image (ARM64EC). The AArch64 functions \
                 run natively, but the x86-64 functions embedded in the same file must be \
                 translated. Routing this to a full emulator discards most of the \
                 available performance, and routing it to nothing faults on first entry \
                 into an x86-64 block."
            }
            AbiFamily::Arm64Fat => {
                "Fat image carrying both an ARM64 slice and an ARM64EC slice (ARM64X), \
                 with load-time dispatch between them. Correct handling selects the ARM64 \
                 slice; entering the hybrid path would needlessly require translation."
            }
            AbiFamily::X86Hybrid => {
                "The x86 side of a compiled hybrid image (CHPE). This half is what the \
                 ARM64EC marshalling layer calls into."
            }
            AbiFamily::X86_64 => {
                "64-bit x86. No instruction in this image is executable on an ARM64 CPU \
                 without a full user-mode binary translator."
            }
            AbiFamily::X86 => {
                "32-bit x86. Requires a full 32-bit translator, and on a 64-bit host also \
                 requires a WOW64-style environment."
            }
            AbiFamily::Arm32 => {
                "32-bit ARM. A 64-bit ARM64 CPU cannot execute AArch32 code unless it is \
                 running in 32-bit mode, so this needs dedicated handling."
            }
            AbiFamily::Itanium => {
                "Intel Itanium. No ARM64 host can execute this under any configuration."
            }
            AbiFamily::RiscV | AbiFamily::LoongArch | AbiFamily::PowerPc => {
                "A non-ARM, non-x86 architecture. Executing this on ARM64 would require \
                 full-system emulation, not a user-mode translator."
            }
            AbiFamily::Unknown => {
                "The machine field is zero, which is not a valid executable image."
            }
            AbiFamily::Other => {
                "An unrecognized machine type. COMPITUM cannot predict execution \
                 behaviour for an unknown architecture."
            }
        }
    }
}

impl fmt::Display for AbiFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_arm64_flavours_are_distinct() {
        assert_eq!(Machine::ARM64.family(), AbiFamily::Arm64Native);
        assert_eq!(Machine::ARM64EC.family(), AbiFamily::Arm64Hybrid);
        assert_eq!(Machine::ARM64X.family(), AbiFamily::Arm64Fat);

        // This is the distinction the whole product rests on.
        assert_ne!(Machine::ARM64.family(), Machine::ARM64EC.family());
        assert_ne!(Machine::ARM64EC.family(), Machine::ARM64X.family());
    }

    #[test]
    fn raw_values_match_microsoft_headers() {
        assert_eq!(Machine::ARM64.raw(), 0xAA64);
        assert_eq!(Machine::ARM64EC.raw(), 0xA641);
        assert_eq!(Machine::ARM64X.raw(), 0xA64E);
        assert_eq!(Machine::AMD64.raw(), 0x8664);
        assert_eq!(Machine::I386.raw(), 0x014C);
        assert_eq!(Machine::CHPE_X86.raw(), 0x3A64);
    }

    #[test]
    fn only_pure_arm64_is_fully_native() {
        assert!(AbiFamily::Arm64Native.is_fully_native_on_arm64());
        assert!(!AbiFamily::Arm64Hybrid.is_fully_native_on_arm64());
        assert!(!AbiFamily::Arm64Fat.is_fully_native_on_arm64());
        assert!(!AbiFamily::X86_64.is_fully_native_on_arm64());
    }

    #[test]
    fn hybrid_and_fat_need_partial_translation() {
        assert!(AbiFamily::Arm64Hybrid.needs_partial_translation());
        assert!(AbiFamily::Arm64Fat.needs_partial_translation());
        assert!(!AbiFamily::Arm64Native.needs_partial_translation());
    }

    #[test]
    fn legacy_families_need_full_translation() {
        assert!(AbiFamily::X86_64.needs_full_translation());
        assert!(AbiFamily::X86.needs_full_translation());
        assert!(AbiFamily::Arm32.needs_full_translation());
        assert!(!AbiFamily::Arm64Hybrid.needs_full_translation());
    }

    #[test]
    fn translation_flags_are_mutually_exclusive_for_native() {
        let native = AbiFamily::Arm64Native;
        assert!(!native.needs_partial_translation());
        assert!(!native.needs_full_translation());

        // Nothing may be both partially and fully translated.
        for family in [
            AbiFamily::Arm64Native,
            AbiFamily::Arm64Hybrid,
            AbiFamily::Arm64Fat,
            AbiFamily::X86_64,
            AbiFamily::X86,
            AbiFamily::Arm32,
        ] {
            assert!(
                !(family.needs_partial_translation() && family.needs_full_translation()),
                "{family} claims both partial and full translation"
            );
        }
    }

    #[test]
    fn arm64_flavour_predicate() {
        assert!(Machine::ARM64.is_arm64_flavour());
        assert!(Machine::ARM64EC.is_arm64_flavour());
        assert!(Machine::ARM64X.is_arm64_flavour());
        assert!(!Machine::AMD64.is_arm64_flavour());
        assert!(!Machine::ARMNT.is_arm64_flavour());
    }

    #[test]
    fn canonical_names_are_accurate() {
        assert_eq!(
            Machine::ARM64.canonical_name(),
            Some("IMAGE_FILE_MACHINE_ARM64")
        );
        assert_eq!(
            Machine::ARM64EC.canonical_name(),
            Some("IMAGE_FILE_MACHINE_ARM64EC")
        );
        assert_eq!(
            Machine::ARM64X.canonical_name(),
            Some("IMAGE_FILE_MACHINE_ARM64X")
        );
        assert_eq!(Machine(0x1234).canonical_name(), None);
    }

    #[test]
    fn unknown_machine_displays_as_hex_not_a_fabricated_name() {
        assert_eq!(Machine(0x1234).to_string(), "0x1234");
        assert_eq!(Machine::ARM64.to_string(), "IMAGE_FILE_MACHINE_ARM64");
    }

    #[test]
    fn short_names_are_protocol_stable() {
        assert_eq!(Machine::ARM64.short_name(), "arm64");
        assert_eq!(Machine::ARM64EC.short_name(), "arm64ec");
        assert_eq!(Machine::ARM64X.short_name(), "arm64x");
        assert_eq!(Machine::AMD64.short_name(), "x86_64");
        assert_eq!(Machine::I386.short_name(), "x86");
    }

    #[test]
    fn every_family_has_a_stable_id_and_a_non_trivial_explanation() {
        let families = [
            AbiFamily::Unknown,
            AbiFamily::X86,
            AbiFamily::X86_64,
            AbiFamily::Arm64Native,
            AbiFamily::Arm64Hybrid,
            AbiFamily::Arm64Fat,
            AbiFamily::X86Hybrid,
            AbiFamily::Arm32,
            AbiFamily::Itanium,
            AbiFamily::RiscV,
            AbiFamily::LoongArch,
            AbiFamily::PowerPc,
            AbiFamily::Other,
        ];
        for family in families {
            assert!(!family.id().is_empty());
            // An explanation shorter than this would be useless to an operator.
            assert!(
                family.execution_semantics().len() > 60,
                "{family} has an unhelpfully short explanation"
            );
        }
    }

    #[test]
    fn arm64ec_explanation_mentions_why_it_is_not_native() {
        // The single most important sentence in the product's documentation.
        let text = AbiFamily::Arm64Hybrid.execution_semantics();
        assert!(text.contains("x86-64"));
        assert!(text.contains("native"));
    }

    #[test]
    fn riscv_widths_map_to_one_family() {
        assert_eq!(Machine::RISCV32.family(), AbiFamily::RiscV);
        assert_eq!(Machine::RISCV64.family(), AbiFamily::RiscV);
    }

    #[test]
    fn arm32_variants_map_to_one_family() {
        assert_eq!(Machine::ARM.family(), AbiFamily::Arm32);
        assert_eq!(Machine::ARMNT.family(), AbiFamily::Arm32);
    }
}
