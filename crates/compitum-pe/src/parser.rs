//! The PE/COFF header parser.
//!
//! Reads the parts of a Portable Executable image that COMPITUM can use to make a routing
//! decision, and nothing else. This is not a loader: it never maps sections, never
//! resolves imports to actual addresses, and never executes anything.
//!
//! # What is read, and why
//!
//! | Structure | Used for |
//! |---|---|
//! | DOS header | locating the PE header via `e_lfanew` |
//! | COFF file header | the `Machine` field — the primary routing input |
//! | Optional header | magic (PE32 vs PE32+), subsystem, section/file alignment |
//! | Section table | detecting ARM64X dispatch sections, executable-code inventory |
//! | Import directory | which subsystems (graphics, CLR) the image binds against |
//! | Load configuration | the ARM64X dynamic-relocation entry point, when present |
//! | CLR header | managed (.NET) images, which need no ISA translation at all |
//!
//! # Notable details
//!
//! * **The operating-system version field is not the ABI version.** It is read and
//!   reported, but never used to infer architecture.
//! * **`SectionAlignment` and `FileAlignment` differ between PE32 and PE32+ layouts**,
//!   and their *values* determine how the in-memory page size interacts with the file.
//!   This is the field that makes the 4 KiB-versus-16 KiB page-size question answerable
//!   from the file itself.
//! * **ARM64X detection is not purely the machine field.** An ARM64X image is
//!   identified by the `CHPE` metadata in its load configuration; the machine field
//!   alone can read as plain `ARM64`. Both signals are therefore reported.

use crate::error::{PeError, Result};
use crate::machine::{AbiFamily, Machine};
use crate::reader::{fixed_ascii, u16_at, u32_at, u64_at};

/// `IMAGE_DOS_HEADER` size in bytes; `e_lfanew` lives at offset 0x3C.
const DOS_HEADER_MIN: usize = 0x40;
/// The `PE\0\0` signature that follows the COFF header.
const PE_SIGNATURE: u32 = 0x0000_4550;
/// `PE32` optional header magic.
pub const MAGIC_PE32: u16 = 0x010B;
/// `PE32+` optional header magic.
pub const MAGIC_PE32_PLUS: u16 = 0x020B;
/// Size of the COFF file header.
const COFF_HEADER_SIZE: usize = 20;
/// Size of the section table entry.
const SECTION_HEADER_SIZE: usize = 40;
/// Size of one data-directory entry: a relative virtual address followed by a size.
const DATA_DIRECTORY_ENTRY_SIZE: usize = 8;
/// Number of data directories a well-formed optional header declares.
const DATA_DIRECTORY_COUNT: usize = 16;
/// `IMAGE_DIRECTORY_ENTRY_IMPORT`.
const DIR_IMPORT: usize = 1;
/// `IMAGE_DIRECTORY_ENTRY_RESOURCE`.
const DIR_RESOURCE: usize = 2;
/// `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG`.
const DIR_LOAD_CONFIG: usize = 10;
/// `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` — the CLR runtime header.
const DIR_CLR: usize = 14;

/// `IMAGE_SUBSYSTEM_*` values COMPITUM distinguishes.
///
/// Only the console/non-console distinction affects routing, but all common values are
/// named so reports are readable rather than numeric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subsystem(pub u16);

impl Subsystem {
    /// No subsystem is specified.
    pub const UNKNOWN: Subsystem = Subsystem(0);
    /// Native, no Win32 environment.
    pub const NATIVE: Subsystem = Subsystem(1);
    /// Windows graphical application.
    pub const WINDOWS_GUI: Subsystem = Subsystem(2);
    /// Character-mode console application.
    pub const WINDOWS_CUI: Subsystem = Subsystem(3);
    /// POSIX character-mode (historical).
    pub const POSIX_CUI: Subsystem = Subsystem(7);
    /// EFI application.
    pub const EFI_APPLICATION: Subsystem = Subsystem(10);
    /// Windows boot application.
    pub const WINDOWS_BOOT: Subsystem = Subsystem(16);

    /// The identifier used in JSON.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self.0 {
            0 => "unknown",
            1 => "native",
            2 => "windows_gui",
            3 => "windows_console",
            5 => "os2_console",
            7 => "posix_console",
            8 => "native_windows",
            9 => "windows_ce_gui",
            10 => "efi_application",
            11 => "efi_boot_service",
            12 => "efi_runtime",
            13 => "efi_rom",
            14 => "xbox",
            16 => "windows_boot",
            17 => "xbox_code_catalog",
            _ => "other",
        }
    }

    /// Returns `true` when the image expects a graphical environment.
    ///
    /// This is the field that decides whether headless execution is conceivable. A
    /// console image on a machine with no display server is a realistic deployment; a
    /// GUI image is not. COMPITUM's whole first product line depends on that difference.
    #[must_use]
    pub fn requires_display(self) -> bool {
        matches!(self.0, 2 | 9 | 10 | 14)
    }

    /// A plain-language description for reports.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self.0 {
            0 => "no subsystem declared",
            1 => "native, without a Win32 environment",
            2 => "Windows graphical application; needs a display",
            3 => "Windows console application; can run headless",
            5 => "OS/2 console (historical)",
            7 => "POSIX console (historical)",
            8 => "native Windows driver environment",
            9 => "Windows CE graphical application",
            10 => "EFI application; needs firmware services, not a display",
            11 => "EFI boot-service driver",
            12 => "EFI runtime driver",
            13 => "EFI ROM image",
            14 => "Xbox application",
            16 => "Windows boot application",
            17 => "Xbox code catalog",
            _ => "an unrecognized subsystem",
        }
    }
}

impl Default for Subsystem {
    fn default() -> Self {
        Subsystem::UNKNOWN
    }
}

/// The COFF file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffHeader {
    /// The architecture identifier — the primary routing input.
    pub machine: Machine,
    /// Number of entries in the section table.
    pub section_count: u16,
    /// Seconds since the Unix epoch, as recorded by the toolchain.
    ///
    /// Reported but never trusted for provenance: it is trivially forged and widely
    /// used for reproducible-build timestamp clamping.
    pub timestamp: u32,
    /// File offset of the symbol table, or zero.
    pub symbol_table_offset: u32,
    /// Number of symbols.
    pub symbol_count: u32,
    /// Size of the optional header; `0` means an object file rather than an image.
    pub optional_header_size: u16,
    /// `IMAGE_FILE_*` characteristic flags.
    pub characteristics: u16,
}

impl CoffHeader {
    /// Returns `true` when this is a relocatable object file, not a linked image.
    #[must_use]
    pub fn is_object_file(&self) -> bool {
        self.optional_header_size == 0
    }

    /// Returns `true` when the image can be executed as a program or loaded as a DLL.
    #[must_use]
    pub fn is_executable_image(&self) -> bool {
        self.characteristics & 0x0002 != 0
    }

    /// Returns `true` when the file is a DLL (`IMAGE_FILE_DLL`).
    #[must_use]
    pub fn is_dll(&self) -> bool {
        self.characteristics & 0x2000 != 0
    }

    /// Returns `true` when the file claims to be a 32-bit-capable image
    /// (`IMAGE_FILE_32BIT_MACHINE`).
    #[must_use]
    pub fn prefers_32bit(&self) -> bool {
        self.characteristics & 0x0100 != 0
    }

    /// Returns `true` when relocations were stripped (`IMAGE_FILE_RELOCS_STRIPPED`).
    ///
    /// Relevant to the Oracle: an image without relocations cannot be loaded at an
    /// arbitrary base, which constrains some translation strategies.
    #[must_use]
    pub fn relocations_stripped(&self) -> bool {
        self.characteristics & 0x0001 != 0
    }

    /// Returns `true` when the image declares itself large-address aware.
    #[must_use]
    pub fn large_address_aware(&self) -> bool {
        self.characteristics & 0x0020 != 0
    }
}

/// The optional header, normalized across the PE32 and PE32+ layouts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader {
    /// The raw magic: [`MAGIC_PE32`] or [`MAGIC_PE32_PLUS`].
    pub magic: u16,
    /// Linker major version.
    pub linker_major: u8,
    /// Linker minor version.
    pub linker_minor: u8,
    /// Declared minimum operating-system version.
    pub os_version: (u16, u16),
    /// Preferred load address. 32-bit for PE32, 64-bit for PE32+.
    pub image_base: u64,
    /// Section alignment in memory, in bytes.
    pub section_alignment: u32,
    /// File alignment on disk, in bytes.
    pub file_alignment: u32,
    /// The subsystem.
    pub subsystem: Subsystem,
    /// `DllCharacteristics` flags, including the CET/CFG bits.
    pub dll_characteristics: u16,
    /// Size of the loaded image.
    pub size_of_image: u32,
    /// Size of all headers.
    pub size_of_headers: u32,
    /// RVA of the import directory.
    pub import_directory_rva: u32,
    /// Size of the import directory.
    pub import_directory_size: u32,
    /// RVA of the resource directory.
    pub resource_directory_rva: u32,
    /// RVA of the load-configuration directory.
    pub load_config_rva: u32,
    /// Size of the load-configuration directory.
    pub load_config_size: u32,
    /// RVA of the CLR runtime header, non-zero for managed images.
    pub clr_header_rva: u32,
}

impl OptionalHeader {
    /// Returns `true` when this is the 64-bit optional-header layout.
    #[must_use]
    pub fn is_pe32_plus(&self) -> bool {
        self.magic == MAGIC_PE32_PLUS
    }

    /// Returns `true` when the image is managed code running on the CLR.
    ///
    /// This is routing-relevant in a way that is easy to miss: a .NET image whose
    /// IL is JIT-compiled by a native ARM64 runtime needs **no binary translation at
    /// all**, even if its machine field says `I386` or `AMD64`. The machine field
    /// describes the host a ready-to-run image was built for; for managed assemblies it
    /// is frequently a legacy value that no longer reflects what will execute.
    #[must_use]
    pub fn is_managed(&self) -> bool {
        self.clr_header_rva != 0
    }

    /// Returns `true` when Control Flow Guard is enabled (`IMAGE_DLLCHARACTERISTICS_GUARD_CF`).
    #[must_use]
    pub fn has_control_flow_guard(&self) -> bool {
        self.dll_characteristics & 0x4000 != 0
    }

    /// Returns `true` when CET shadow-stack / indirect-branch tracking is declared.
    ///
    /// On ARM64 the analogous mechanism is BTI, which is why this flag interacts with the
    /// ISA oracle: an image built with hardware-enforced control-flow integrity may
    /// require the `BTI` feature that a given core might not implement.
    #[must_use]
    pub fn has_cet(&self) -> bool {
        self.dll_characteristics & 0xC000 == 0xC000
    }

    /// Returns `true` when the image is position-independent and can be relocated.
    #[must_use]
    pub fn is_dynamic_base(&self) -> bool {
        self.dll_characteristics & 0x0040 != 0
    }

    /// Returns the page size implied by the section alignment.
    ///
    /// This is the value to compare against the host's memory page size. Windows on
    /// ARM64 uses 4 KiB; Android is migrating to 16 KiB. A mismatch is a real
    /// compatibility axis, not a theoretical one.
    #[must_use]
    pub fn implied_page_size(&self) -> u32 {
        self.section_alignment
    }
}

/// One entry from the section table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The section name, at most eight bytes.
    pub name: String,
    /// Virtual size in memory.
    pub virtual_size: u32,
    /// Virtual address, relative to the image base.
    pub virtual_address: u32,
    /// Size of the raw data on disk.
    pub raw_size: u32,
    /// File offset of the raw data.
    pub raw_offset: u32,
    /// Section flags.
    pub characteristics: u32,
}

impl Section {
    /// Returns `true` when the section claims to contain executable code.
    #[must_use]
    pub fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    /// Returns `true` when the section is initialized data.
    #[must_use]
    pub fn is_initialized_data(&self) -> bool {
        self.characteristics & 0x0000_0040 != 0
    }

    /// Returns `true` when the section is uninitialized data (`.bss`-like).
    #[must_use]
    pub fn is_uninitialized_data(&self) -> bool {
        self.characteristics & 0x0000_0080 != 0
    }

    /// Returns the RVA range this section covers.
    #[must_use]
    pub fn rva_range(&self) -> std::ops::Range<u32> {
        let start = self.virtual_address;
        let span = self.virtual_size.max(self.raw_size);
        start..start.saturating_add(span)
    }

    /// Returns `true` when `rva` falls inside this section.
    #[must_use]
    pub fn contains_rva(&self, rva: u32) -> bool {
        self.rva_range().contains(&rva)
    }
}

/// A name from the import directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedModule {
    /// The DLL name, lowercase-normalized for stable comparison.
    pub name: String,
    /// Number of imported symbols, when countable.
    pub symbol_count: usize,
}

impl ImportedModule {
    /// Returns `true` when this module is a graphics API.
    ///
    /// Routing-relevant because a graphics-importing image needs a rendering backend,
    /// which is the single largest engineering obstacle in the Android product line and
    /// is entirely absent in the headless Linux one.
    #[must_use]
    pub fn is_graphics(&self) -> bool {
        let n = self.name.as_str();
        n.starts_with("d3d") || n == "dxgi.dll" || n == "opengl32.dll" || n == "vulkan-1.dll"
    }

    /// Returns `true` when this module is a recent Direct3D version.
    #[must_use]
    pub fn is_direct3d(&self) -> bool {
        self.name.starts_with("d3d")
    }

    /// Returns `true` when this module is the Windows kernel itself.
    ///
    /// # Why this is the signal for a kernel driver
    ///
    /// A kernel driver links against `ntoskrnl.exe`, because it runs in kernel mode and uses
    /// the kernel's exported routines rather than the Win32 API. Importing it is therefore
    /// evidence about where the image executes, not merely about what it links to.
    ///
    /// # Why the subsystem is not the signal
    ///
    /// The obvious candidate is the PE subsystem, and it does not work. Measured across the
    /// 27 drivers in a real Wine distribution built by a real toolchain:
    ///
    ///   * 20 carry `IMAGE_SUBSYSTEM_NATIVE` (1), and
    ///   * 7 carry `IMAGE_SUBSYSTEM_WINDOWS_CUI` (3).
    ///
    /// Meanwhile 655 ordinary DLLs and applications carry `windows_console` too, so the field
    /// separates nothing in either direction. An earlier attempt to classify by subsystem alone
    /// would have been wrong for both halves of the question, which is why this reads the
    /// import table instead.
    #[must_use]
    pub fn is_kernel(&self) -> bool {
        self.name == "ntoskrnl.exe"
    }
}

/// Every fact COMPITUM extracts from a PE image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImage {
    /// The COFF file header.
    pub coff: CoffHeader,
    /// The optional header, when present.
    pub optional: Option<OptionalHeader>,
    /// The section table, in file order.
    pub sections: Vec<Section>,
    /// Modules named in the import directory.
    pub imports: Vec<ImportedModule>,
    /// Total number of imported symbols across all modules.
    pub import_symbol_total: usize,
    /// CHPE hybrid metadata, when the image carries any.
    ///
    /// **This is what identifies a hybrid image.** A linked ARM64EC executable reports
    /// machine type `0x8664`, which is indistinguishable from plain x86-64 without reading
    /// this metadata; `0xA641` is an internal MSVC object-file identifier and is not a valid
    /// final PE machine type. See [`crate::chpe`] for the evidence.
    pub hybrid: Option<crate::chpe::HybridMetadata>,
    /// Set when the image declared a load configuration whose CHPE pointer could not be read.
    ///
    /// Kept separately from `hybrid` because the two mean different things: `hybrid: None`
    /// with `hybrid_error: None` is "definitely not hybrid", whereas an error here is "could
    /// not tell". Conflating them would let an unreadable pointer be mistaken for evidence of
    /// a pure image, which is the optimistic direction and therefore the dangerous one.
    pub hybrid_error: Option<String>,
}

impl PeImage {
    /// The ABI family of this image.
    #[must_use]
    pub fn family(&self) -> AbiFamily {
        // The machine field is authoritative for every architecture except the two where
        // CHPE metadata can change the answer.
        //
        // ARM64 and AMD64 are the only machine types a hybrid image can carry, because those
        // are the two ABIs ARM64EC and ARM64X combine. For everything else -- I386, Itanium,
        // RISC-V, LoongArch, PowerPC, or an unrecognized value -- the machine field already
        // says what the image is, and consulting the hybrid classification would only lose
        // information.
        //
        // An earlier revision of this method routed *every* machine through the hybrid
        // classifier, which knows three outcomes and therefore collapsed six distinct
        // architectures into x86-64. Three router tests caught it: a 32-bit x86 image routed
        // to Box64 instead of WOW64, and an Itanium image became translatable instead of
        // unsupported. The machine field is consulted first for exactly that reason.
        let raw = self.coff.machine.raw();
        if !matches!(raw, 0xAA64 | 0x8664 | 0xA641 | 0xA64E) {
            return self.coff.machine.family();
        }

        // The conservative direction matters here: when the metadata is absent or unreadable,
        // an x86-64 machine type stays x86-64. That over-translates, which costs performance,
        // rather than promising native execution that would fault.
        match crate::chpe::classify_image(self, self.hybrid.as_ref()) {
            crate::chpe::Classified::PureArm64 => AbiFamily::Arm64Native,
            crate::chpe::Classified::PureX86_64 => AbiFamily::X86_64,
            crate::chpe::Classified::Hybrid(crate::chpe::HybridKind::Arm64Ec) => {
                AbiFamily::Arm64Hybrid
            }
            crate::chpe::Classified::Hybrid(crate::chpe::HybridKind::Arm64X) => AbiFamily::Arm64Fat,
            crate::chpe::Classified::Hybrid(crate::chpe::HybridKind::Unrecognized { .. }) => {
                AbiFamily::Arm64Hybrid
            }
        }
    }

    /// Returns `true` when the image carries CHPE hybrid metadata.
    ///
    /// Distinct from [`PeImage::family`], which folds the metadata into a routing decision.
    /// This reports the raw evidence.
    #[must_use]
    pub fn is_hybrid(&self) -> bool {
        self.hybrid.is_some()
    }

    /// Returns `true` when the image declared a load configuration whose CHPE pointer could
    /// not be read, so the classification is genuinely unknown rather than known-pure.
    #[must_use]
    pub fn has_unresolved_hybrid_metadata(&self) -> bool {
        self.hybrid_error.is_some()
    }

    /// The subsystem, defaulting to unknown when there is no optional header.
    #[must_use]
    pub fn subsystem(&self) -> Subsystem {
        self.optional
            .as_ref()
            .map_or(Subsystem::UNKNOWN, |o| o.subsystem)
    }

    /// Returns `true` when the image can plausibly run without a display.
    #[must_use]
    pub fn is_headless_capable(&self) -> bool {
        let subsystem = self.subsystem();
        // A native or console image needs no display. An image with no declared
        // subsystem is treated as headless-capable because it makes no claim to the
        // contrary, and the router reports the uncertainty separately.
        !subsystem.requires_display()
    }

    /// Returns `true` when the image imports a graphics API.
    #[must_use]
    pub fn imports_graphics(&self) -> bool {
        self.imports.iter().any(ImportedModule::is_graphics)
    }

    /// Returns `true` when the image is a Windows kernel driver.
    ///
    /// # Why COMPITUM needs this
    ///
    /// A kernel driver is pure AArch64 on an ARM64 build, so every architecture-level question
    /// answers "runs natively, no translation needed, 100% of native speed". All of that is
    /// true and all of it is useless: the image cannot be loaded by a user-mode compatibility
    /// layer at all, because it expects to be mapped by the kernel and to call kernel routines.
    ///
    /// Without this distinction a scan of a real Windows distribution reports a kernel driver
    /// as a perfectly healthy native binary. In a migration report that is the difference
    /// between "port this one, it is nearly free" and "this one needs a driver rewrite", and a
    /// customer acting on the first answer wastes the work.
    ///
    /// Measured on 747 images from a real Wine build: 18 import `ntoskrnl.exe`, of which 16 are
    /// `.sys` files, one is `hal.dll` and one is `winedevice.exe` — all genuinely kernel-side.
    #[must_use]
    pub fn is_kernel_driver(&self) -> bool {
        self.imports.iter().any(ImportedModule::is_kernel)
    }

    /// Returns `true` when the image is managed code.
    #[must_use]
    pub fn is_managed(&self) -> bool {
        self.optional
            .as_ref()
            .is_some_and(OptionalHeader::is_managed)
    }

    /// Total bytes of executable code across all executable sections.
    #[must_use]
    pub fn executable_bytes(&self) -> u64 {
        self.sections
            .iter()
            .filter(|s| s.is_executable())
            .map(|s| u64::from(s.raw_size))
            .sum()
    }

    /// The page size implied by the section alignment, when declared.
    #[must_use]
    pub fn implied_page_size(&self) -> Option<u32> {
        self.optional
            .as_ref()
            .map(OptionalHeader::implied_page_size)
    }

    /// Returns the section containing `rva`, when any.
    #[must_use]
    pub fn section_for_rva(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    /// Converts a relative virtual address to a file offset.
    ///
    /// Returns `None` when the address does not lie in a mapped, file-backed section —
    /// which is the correct answer for `.bss`-style uninitialized data and for addresses
    /// outside the image entirely.
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        let section = self.section_for_rva(rva)?;
        let delta = rva.checked_sub(section.virtual_address)?;
        if delta >= section.raw_size {
            return None;
        }
        Some(section.raw_offset as usize + delta as usize)
    }

    /// Returns `true` when the machine field indicates an ARM64 flavour.
    #[must_use]
    pub fn is_arm64_flavour(&self) -> bool {
        self.coff.machine.is_arm64_flavour()
    }

    /// Detects an ARM64X image.
    ///
    /// An ARM64X image carries both an ARM64 and an ARM64EC slice. The machine field
    /// alone can read as `ARM64`, so this also considers the presence of sections named
    /// with the `CHPE` prefix, which is how the hybrid slice is distinguished. Returns
    /// `true` when either signal is present.
    #[must_use]
    pub fn has_arm64x_slices(&self) -> bool {
        self.coff.machine.family() == AbiFamily::Arm64Fat
            || self
                .sections
                .iter()
                .any(|s| s.name.starts_with("chpe") || s.name.starts_with("CHPE"))
    }

    /// Returns a one-line English summary suitable for a report header.
    #[must_use]
    pub fn summary_line(&self) -> String {
        let kind = if self.coff.is_dll() {
            "DLL"
        } else if self.coff.is_object_file() {
            "object"
        } else {
            "executable"
        };
        format!(
            "{} {} / {} / {} sections",
            self.coff.machine.short_name(),
            kind,
            self.subsystem().id(),
            self.sections.len()
        )
    }
}

/// Whether a byte slice looks like a PE image, without fully parsing it.
///
/// Used to reject non-PE input early. This is a cheap signature check and deliberately
/// does **not** validate the rest of the header.
#[must_use]
pub fn looks_like_pe(data: &[u8]) -> bool {
    if data.len() < DOS_HEADER_MIN {
        return false;
    }
    if data[0] != b'M' || data[1] != b'Z' {
        return false;
    }
    let Ok(raw) = u32_at(data, 0x3C) else {
        return false;
    };
    let offset = raw as usize;
    u32_at(data, offset).is_ok_and(|sig| sig == PE_SIGNATURE)
}

/// Parses a PE image.
///
/// # Errors
///
/// Returns a [`PeError`] describing the first structural problem. A truncated or
/// maliciously malformed file produces a specific error, never a panic and never a
/// partially-populated result.
pub fn parse(data: &[u8]) -> Result<PeImage> {
    if data.len() < DOS_HEADER_MIN {
        return Err(PeError::TooSmall { size: data.len() });
    }
    if data[0] != b'M' || data[1] != b'Z' {
        return Err(PeError::NotMz);
    }

    let lfanew = u32_at(data, 0x3C)?;
    let pe_offset = lfanew as usize;
    if pe_offset >= data.len() || u32_at(data, pe_offset).is_err() {
        return Err(PeError::BadLfanew { offset: lfanew });
    }
    if u32_at(data, pe_offset)? != PE_SIGNATURE {
        return Err(PeError::NotPe);
    }

    let coff_offset = pe_offset + 4;
    let coff = parse_coff(data, coff_offset)?;
    let optional_offset = coff_offset + COFF_HEADER_SIZE;
    let optional = if coff.optional_header_size == 0 {
        None
    } else {
        Some(parse_optional(
            data,
            optional_offset,
            coff.optional_header_size,
        )?)
    };

    let section_offset = optional_offset + usize::from(coff.optional_header_size);
    let sections = parse_sections(data, section_offset, coff.section_count)?;

    let mut image = PeImage {
        coff,
        optional,
        sections,
        imports: Vec::new(),
        import_symbol_total: 0,
        hybrid: None,
        hybrid_error: None,
    };
    image.imports = parse_imports(data, &image);
    image.import_symbol_total = image.imports.iter().map(|m| m.symbol_count).sum();

    // Read the hybrid metadata last, because reaching it requires the section table that was
    // just parsed. An error here is recorded rather than returned: the image is still fully
    // classified as a non-hybrid file, and discarding that classification because a pointer
    // in an optional structure was unreadable would lose usable information.
    match crate::chpe::read_hybrid_metadata(data, &image) {
        Ok(metadata) => image.hybrid = metadata,
        Err(reason) => image.hybrid_error = Some(reason),
    }

    Ok(image)
}

fn parse_coff(data: &[u8], offset: usize) -> Result<CoffHeader> {
    let machine = Machine(u16_at(data, offset)?);
    let section_count = u16_at(data, offset + 2)?;
    let timestamp = u32_at(data, offset + 4)?;
    let symbol_table_offset = u32_at(data, offset + 8)?;
    let symbol_count = u32_at(data, offset + 12)?;
    let optional_header_size = u16_at(data, offset + 16)?;
    let characteristics = u16_at(data, offset + 18)?;
    Ok(CoffHeader {
        machine,
        section_count,
        timestamp,
        symbol_table_offset,
        symbol_count,
        optional_header_size,
        characteristics,
    })
}

fn parse_optional(data: &[u8], offset: usize, size: u16) -> Result<OptionalHeader> {
    let magic = u16_at(data, offset)?;
    let is_plus = match magic {
        MAGIC_PE32 => false,
        MAGIC_PE32_PLUS => true,
        other => return Err(PeError::UnknownOptionalHeader { magic: other }),
    };

    // Field offsets within the optional header, numbered exactly as the PE specification
    // numbers them from the start of that header.
    //
    // These are named constants rather than arithmetic chained from a running anchor,
    // because an earlier revision did the latter and was wrong. On a real
    // compiler-produced binary it read `Subsystem` as 4096 instead of 3, and read the data
    // directory from the middle of unrelated fields. The chained arithmetic looked
    // plausible and produced a self-consistent answer -- which is precisely why synthetic
    // fixtures never caught it: the fixture builder used the *same* wrong anchor, so the
    // writer and the reader agreed with each other while both disagreed with reality. Only
    // a binary from a real toolchain exposed it.
    //
    // Named offsets can be checked against the specification by reading them, which is the
    // only defence that scales.
    //
    // Layout fact that the earlier revision got wrong: everything up to and including
    // `DllCharacteristics` sits at the *same* offset in both PE32 and PE32+. The layouts
    // diverge only at `SizeOfStackReserve` (0x48), which is 64-bit in PE32+ and pushes the
    // remaining fields eight bytes later. So only `NumberOfRvaAndSizes` and the data
    // directory need a per-layout position -- not the subsystem, and not the image size.
    //
    // Verified field by field against a real PE32+ image produced by clang and lld-link
    // and cross-checked with `llvm-readobj`:
    //
    //   0x00 Magic = 0x20B                 0x20 SectionAlignment = 0x1000
    //   0x18 ImageBase = 0x140000000       0x38 SizeOfImage = 0x2000
    //   0x3C SizeOfHeaders = 0x200         0x44 Subsystem = 3 (console)
    //   0x46 DllCharacteristics = 0x8160   0x6C NumberOfRvaAndSizes = 16
    const OFF_LINKER_MAJOR: usize = 0x02;
    const OFF_LINKER_MINOR: usize = 0x03;
    const OFF_OS_MAJOR: usize = 0x28;
    const OFF_OS_MINOR: usize = 0x2A;
    const OFF_IMAGE_BASE_PE32: usize = 0x1C;
    const OFF_IMAGE_BASE_PE32PLUS: usize = 0x18;
    const OFF_SECTION_ALIGNMENT: usize = 0x20;
    const OFF_FILE_ALIGNMENT: usize = 0x24;
    const OFF_SIZE_OF_IMAGE: usize = 0x38;
    const OFF_SIZE_OF_HEADERS: usize = 0x3C;
    const OFF_SUBSYSTEM: usize = 0x44;
    const OFF_DLL_CHARACTERISTICS: usize = 0x46;
    const OFF_RVA_AND_SIZES_PE32: usize = 0x5C;
    const OFF_RVA_AND_SIZES_PE32PLUS: usize = 0x6C;

    let linker_major = crate::reader::u8_at(data, offset + OFF_LINKER_MAJOR)?;
    let linker_minor = crate::reader::u8_at(data, offset + OFF_LINKER_MINOR)?;
    let os_major = u16_at(data, offset + OFF_OS_MAJOR)?;
    let os_minor = u16_at(data, offset + OFF_OS_MINOR)?;

    // PE32 stores `ImageBase` as a 32-bit field at 0x1C, preceded by `BaseOfData` at 0x18.
    // PE32+ widens it to 64 bits at 0x18 and drops `BaseOfData`. This is the first and only
    // genuine divergence in the header prefix.
    let image_base = if is_plus {
        u64_at(data, offset + OFF_IMAGE_BASE_PE32PLUS)?
    } else {
        u64::from(u32_at(data, offset + OFF_IMAGE_BASE_PE32)?)
    };

    let section_alignment = u32_at(data, offset + OFF_SECTION_ALIGNMENT)?;
    let file_alignment = u32_at(data, offset + OFF_FILE_ALIGNMENT)?;
    let size_of_image = u32_at(data, offset + OFF_SIZE_OF_IMAGE)?;
    let size_of_headers = u32_at(data, offset + OFF_SIZE_OF_HEADERS)?;
    let subsystem = Subsystem(u16_at(data, offset + OFF_SUBSYSTEM)?);
    let dll_characteristics = u16_at(data, offset + OFF_DLL_CHARACTERISTICS)?;

    // `NumberOfRvaAndSizes` is the last fixed field, and the data directory begins
    // immediately after it. Only this position differs between the two layouts.
    let rva_and_sizes_offset = if is_plus {
        OFF_RVA_AND_SIZES_PE32PLUS
    } else {
        OFF_RVA_AND_SIZES_PE32
    };
    let data_directory_offset = offset + rva_and_sizes_offset + 4;

    if !crate::reader::is_power_of_two(section_alignment) && section_alignment != 0 {
        return Err(PeError::InvalidField {
            field: "SectionAlignment",
            value: u64::from(section_alignment),
        });
    }

    let directory = |index: usize| -> Result<(u32, u32)> {
        let base = data_directory_offset + index * DATA_DIRECTORY_ENTRY_SIZE;
        Ok((u32_at(data, base)?, u32_at(data, base + 4)?))
    };

    let (import_directory_rva, import_directory_size) = directory(DIR_IMPORT)?;
    let (resource_directory_rva, _) = directory(DIR_RESOURCE)?;
    let (load_config_rva, load_config_size) = directory(DIR_LOAD_CONFIG)?;
    let (clr_header_rva, _) = directory(DIR_CLR)?;

    // Guard against a header that claims to be larger than the space actually reserved
    // for it. This is the check that stops a crafted `SizeOfOptionalHeader` from making
    // a later read walk into the section table.
    let needed = data_directory_offset + DATA_DIRECTORY_COUNT * DATA_DIRECTORY_ENTRY_SIZE;
    let available = offset + usize::from(size);
    if needed > available {
        return Err(PeError::Truncated {
            offset: needed,
            needed: needed.saturating_sub(available),
        });
    }

    Ok(OptionalHeader {
        magic,
        linker_major,
        linker_minor,
        os_version: (os_major, os_minor),
        image_base,
        section_alignment,
        file_alignment,
        subsystem,
        dll_characteristics,
        size_of_image,
        size_of_headers,
        import_directory_rva,
        import_directory_size,
        resource_directory_rva,
        load_config_rva,
        load_config_size,
        clr_header_rva,
    })
}

fn parse_sections(data: &[u8], offset: usize, count: u16) -> Result<Vec<Section>> {
    let mut sections = Vec::with_capacity(usize::from(count));
    for index in 0..usize::from(count) {
        let base = offset + index * SECTION_HEADER_SIZE;
        sections.push(Section {
            name: fixed_ascii(data, base, 8)?,
            virtual_size: u32_at(data, base + 8)?,
            virtual_address: u32_at(data, base + 12)?,
            raw_size: u32_at(data, base + 16)?,
            raw_offset: u32_at(data, base + 20)?,
            characteristics: u32_at(data, base + 36)?,
        });
    }
    Ok(sections)
}

/// Reads the import directory.
///
/// This is best-effort by design: a malformed import table is a strong signal about a
/// file's provenance, but it does not change the *architecture* answer. Returning an
/// empty list rather than an error keeps classification available for images whose
/// import metadata is damaged.
fn parse_imports(data: &[u8], image: &PeImage) -> Vec<ImportedModule> {
    let Some(optional) = &image.optional else {
        return Vec::new();
    };
    if optional.import_directory_rva == 0 || optional.import_directory_size == 0 {
        return Vec::new();
    }

    let mut modules = Vec::new();
    // An import descriptor is 20 bytes: OriginalFirstThunk, TimeDateStamp, ForwarderChain,
    // Name, FirstThunk. The table is terminated by an all-zero descriptor.
    let mut index = 0usize;
    while index < 4096 {
        let Some(descriptor_offset) =
            image.rva_to_offset(optional.import_directory_rva + (index as u32) * 20)
        else {
            break;
        };
        let Ok(name_rva) = u32_at(data, descriptor_offset + 12) else {
            break;
        };
        if name_rva == 0 {
            break;
        }
        let Some(name_offset) = image.rva_to_offset(name_rva) else {
            break;
        };
        if name_offset >= data.len() {
            break;
        }
        let raw = &data[name_offset..];
        let end = raw.iter().position(|b| *b == 0).unwrap_or(0);
        if end == 0 {
            break;
        }
        let name: String = raw[..end]
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() {
                    (*b as char).to_ascii_lowercase()
                } else {
                    '\u{FFFD}'
                }
            })
            .collect();

        modules.push(ImportedModule {
            name,
            symbol_count: count_thunks(data, image, descriptor_offset),
        });
        index += 1;
    }
    modules
}

/// Counts entries in an import thunk table, capped to bound work on a hostile file.
fn count_thunks(data: &[u8], image: &PeImage, descriptor_offset: usize) -> usize {
    let Ok(first_thunk) = u32_at(data, descriptor_offset + 16) else {
        return 0;
    };
    if first_thunk == 0 {
        return 0;
    }
    let entry_size = if image
        .optional
        .as_ref()
        .is_some_and(OptionalHeader::is_pe32_plus)
    {
        8
    } else {
        4
    };
    let mut count = 0usize;
    while count < 100_000 {
        let Some(offset) = image.rva_to_offset(first_thunk + (count as u32) * entry_size) else {
            break;
        };
        let value = if entry_size == 8 {
            u64_at(data, offset).unwrap_or(0)
        } else {
            u64::from(u32_at(data, offset).unwrap_or(0))
        };
        if value == 0 {
            break;
        }
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Offset of the data-directory array within a PE32+ optional header.
    ///
    /// Builds a syntactically valid PE image with the given machine type and subsystem.
    ///
    /// Delegates to the shared [`crate::fixture`] module rather than maintaining a second
    /// copy of the construction logic. An earlier revision had a private builder here with
    /// its own hard-coded optional-header offsets, and when those offsets were corrected in
    /// the parser this copy silently kept the old ones -- four tests failed, and the cause
    /// was the duplication rather than either implementation.
    ///
    /// The deeper lesson is recorded in `fixture.rs`: a fixture that shares an assumption
    /// with the code under test cannot detect that assumption being wrong. Keeping one
    /// builder does not solve that, but it does guarantee that a fix lands everywhere at
    /// once. Detecting the *assumption* needs a binary from a real toolchain, which is what
    /// `real_toolchain_output_is_parsed_correctly` below provides.
    fn synthetic_pe(machine: u16, subsystem: u16, is_dll: bool) -> Vec<u8> {
        crate::fixture::synthetic(machine, subsystem, is_dll)
    }

    /// Builds an image with an import directory, delegating to the shared builder.
    fn synthetic_pe_with(
        machine: u16,
        subsystem: u16,
        is_dll: bool,
        extra_import: &[&str],
        section_alignment: u32,
    ) -> Vec<u8> {
        crate::fixture::synthetic_advanced(
            machine,
            subsystem,
            is_dll,
            extra_import,
            section_alignment,
            false,
            0,
        )
    }

    #[test]
    fn parses_a_minimal_arm64_image() {
        let data = synthetic_pe(0xAA64, 3, false);
        let image = parse(&data).unwrap();
        assert_eq!(image.coff.machine, Machine::ARM64);
        assert_eq!(image.family(), AbiFamily::Arm64Native);
        assert_eq!(image.subsystem(), Subsystem::WINDOWS_CUI);
        assert!(image.is_headless_capable());
        assert!(!image.coff.is_dll());
        assert!(image.coff.is_executable_image());
    }

    #[test]
    fn parses_each_arm64_flavour_distinctly() {
        for (raw, family) in [
            (0xAA64u16, AbiFamily::Arm64Native),
            (0xA641, AbiFamily::Arm64Hybrid),
            (0xA64E, AbiFamily::Arm64Fat),
        ] {
            let image = parse(&synthetic_pe(raw, 3, false)).unwrap();
            assert_eq!(image.family(), family, "machine 0x{raw:04X}");
        }
    }

    #[test]
    fn detects_dll() {
        let image = parse(&synthetic_pe(0xAA64, 3, true)).unwrap();
        assert!(image.coff.is_dll());
    }

    #[test]
    fn gui_images_are_not_headless_capable() {
        let gui = parse(&synthetic_pe(0xAA64, 2, false)).unwrap();
        assert!(!gui.is_headless_capable());
        assert!(gui.subsystem().requires_display());

        let console = parse(&synthetic_pe(0xAA64, 3, false)).unwrap();
        assert!(console.is_headless_capable());
    }

    #[test]
    fn reads_section_table() {
        let image = parse(&synthetic_pe(0xAA64, 3, false)).unwrap();
        assert_eq!(image.sections.len(), 1);
        let text = &image.sections[0];
        assert_eq!(text.name, ".text");
        assert!(text.is_executable());
        assert_eq!(image.executable_bytes(), 0x400);
    }

    #[test]
    fn converts_rva_to_file_offset() {
        let image = parse(&synthetic_pe(0xAA64, 3, false)).unwrap();
        // Section starts at RVA 0x1000 and file offset 0x200.
        assert_eq!(image.rva_to_offset(0x1000), Some(0x200));
        assert_eq!(image.rva_to_offset(0x1100), Some(0x300));
        // Beyond the raw data of the section.
        assert_eq!(image.rva_to_offset(0x1800), None);
        // Outside any section.
        assert_eq!(image.rva_to_offset(0x9000), None);
    }

    #[test]
    fn implied_page_size_comes_from_section_alignment() {
        let four_k = parse(&synthetic_pe_with(0xAA64, 3, false, &[], 0x1000)).unwrap();
        assert_eq!(four_k.implied_page_size(), Some(4096));

        let sixteen_k = parse(&synthetic_pe_with(0xAA64, 3, false, &[], 0x4000)).unwrap();
        assert_eq!(sixteen_k.implied_page_size(), Some(16384));
    }

    #[test]
    fn rejects_non_pe_input() {
        assert_eq!(parse(b"MZ").unwrap_err(), PeError::TooSmall { size: 2 });
        assert_eq!(parse(&[0u8; 64]).unwrap_err(), PeError::NotMz);
    }

    #[test]
    fn rejects_bad_lfanew() {
        let mut data = vec![0u8; 0x100];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C..0x40].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
        assert!(matches!(parse(&data), Err(PeError::BadLfanew { .. })));
    }

    #[test]
    fn rejects_missing_pe_signature() {
        let mut data = vec![0u8; 0x100];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // Signature left as zeroes.
        assert_eq!(parse(&data).unwrap_err(), PeError::NotPe);
    }

    #[test]
    fn rejects_unknown_optional_header_magic() {
        let mut data = synthetic_pe(0xAA64, 3, false);
        let opt = 0x80 + 4 + 20;
        data[opt..opt + 2].copy_from_slice(&0xDEADu16.to_le_bytes());
        assert!(matches!(
            parse(&data),
            Err(PeError::UnknownOptionalHeader { magic: 0xDEAD })
        ));
    }

    #[test]
    fn looks_like_pe_is_cheap_and_correct() {
        let good = synthetic_pe(0xAA64, 3, false);
        assert!(looks_like_pe(&good));
        assert!(!looks_like_pe(b"not a pe"));
        assert!(!looks_like_pe(&[0u8; 128]));
    }

    #[test]
    fn reads_import_modules() {
        let data = synthetic_pe_with(0xAA64, 3, false, &["kernel32.dll", "d3d12.dll"], 0x1000);
        let image = parse(&data).unwrap();
        let names: Vec<&str> = image.imports.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"kernel32.dll"), "got {names:?}");
        assert!(names.contains(&"d3d12.dll"), "got {names:?}");
        assert!(image.imports_graphics());
        assert!(image.import_symbol_total > 0);
    }

    #[test]
    fn graphics_detection_is_specific() {
        assert!(ImportedModule {
            name: "d3d12.dll".into(),
            symbol_count: 1
        }
        .is_graphics());
        assert!(ImportedModule {
            name: "dxgi.dll".into(),
            symbol_count: 1
        }
        .is_graphics());
        assert!(!ImportedModule {
            name: "kernel32.dll".into(),
            symbol_count: 1
        }
        .is_graphics());
    }

    #[test]
    fn subsystem_classification_is_exhaustive_for_known_values() {
        assert_eq!(Subsystem(2).id(), "windows_gui");
        assert_eq!(Subsystem(3).id(), "windows_console");
        assert_eq!(Subsystem(1).id(), "native");
        assert_eq!(Subsystem(999).id(), "other");
        for value in [0u16, 1, 2, 3, 5, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 999] {
            assert!(!Subsystem(value).description().is_empty());
        }
    }

    #[test]
    fn arm64x_detection_uses_section_names() {
        let mut data = synthetic_pe(0xAA64, 3, false);
        // Rename the single section to the CHPE prefix the hybrid slice uses.
        let sect = 0x80 + 4 + 20 + 0xF0;
        data[sect..sect + 4].copy_from_slice(b"chpe");
        let image = parse(&data).unwrap();
        assert!(image.has_arm64x_slices());
    }

    #[test]
    fn non_arm64x_image_is_not_reported_as_fat() {
        let image = parse(&synthetic_pe(0xAA64, 3, false)).unwrap();
        assert!(!image.has_arm64x_slices());
    }

    #[test]
    fn summary_line_is_informative() {
        let image = parse(&synthetic_pe(0xA641, 3, false)).unwrap();
        let line = image.summary_line();
        assert!(line.contains("arm64ec"));
        assert!(line.contains("windows_console"));
    }

    #[test]
    fn truncated_file_reports_truncation_not_panic() {
        let full = synthetic_pe(0xAA64, 3, false);
        for cut in [0x40, 0x90, 0xA0, 0x100, 0x200] {
            // Must never panic, whether it errors or parses.
            let _ = parse(&full[..cut.min(full.len())]);
        }
    }

    #[test]
    fn fuzzing_like_mutations_never_panic() {
        let base = synthetic_pe(0xAA64, 3, false);
        // Deterministic pseudo-random mutations over header bytes.
        let mut state = 0x1234_5678u32;
        for _ in 0..500 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let index = (state as usize) % base.len();
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let value = (state & 0xFF) as u8;
            let mut mutated = base.clone();
            mutated[index] = value;
            let _ = parse(&mutated);
        }
    }
}
