//! Synthetic PE image construction, for tests and for the Oracle's fixture corpus.
//!
//! This module builds **syntactically valid** PE images in memory. It exists so that the
//! parser, the classifier and the router can all be exercised against real structure
//! rather than against a shortcut, and so that a fixture used by one crate is byte-identical
//! to the fixture used by another.
//!
//! # Why this is production code and not `#[cfg(test)]`
//!
//! Three reasons:
//!
//! 1. `compitum-router`'s tests need the same fixtures, and a `#[cfg(test)]` module is
//!    invisible across crate boundaries. Duplicating the builder would let the two copies
//!    drift, and a drifted fixture is worse than no fixture.
//! 2. The Oracle's corpus needs to be reproducible from source, so that a compatibility
//!    record can be re-derived years later rather than trusted.
//! 3. A documented builder is also documentation: the layout constants below are the most
//!    compact description of the PE header structure in this repository.
//!
//! # Fidelity
//!
//! The field offsets follow the PE specification exactly, including the PE32/PE32+ layout
//! divergence (the optional header's `ImageBase` is 32-bit in PE32 and 64-bit in PE32+,
//! which shifts every subsequent field by eight bytes). Only PE32+ images are produced,
//! because that is what every ARM64 binary uses.

/// `IMAGE_FILE_MACHINE_*` values published for convenient use in tests.
pub mod machine {
    /// Pure 64-bit ARM.
    pub const ARM64: u16 = 0xAA64;
    /// Hybrid AArch64 plus x86-64.
    pub const ARM64EC: u16 = 0xA641;
    /// Fat image carrying both slices.
    pub const ARM64X: u16 = 0xA64E;
    /// 64-bit x86.
    pub const AMD64: u16 = 0x8664;
    /// 32-bit x86.
    pub const I386: u16 = 0x014C;
    /// 32-bit ARM Thumb-2.
    pub const ARMNT: u16 = 0x01C4;
}

/// `IMAGE_SUBSYSTEM_*` values published for convenient use in tests.
pub mod subsystem {
    /// Windows graphical application.
    pub const GUI: u16 = 2;
    /// Windows console application.
    pub const CONSOLE: u16 = 3;
    /// Native, without a Win32 environment.
    pub const NATIVE: u16 = 1;
}

/// Offset of the PE signature within a synthetic image.
const PE_OFFSET: usize = 0x80;
/// Size of the optional header written by [`synthetic_advanced`].
const OPTIONAL_SIZE: usize = 0xF0;
/// Size of one section table entry.
const SECTION_HEADER_SIZE: usize = 40;
/// Size of the synthetic `.text` section's raw data.
const TEXT_RAW_SIZE: usize = 0x400;
/// File offset of the synthetic `.text` section's raw data.
const TEXT_RAW_OFFSET: usize = 0x200;

/// Builds a minimal, valid PE32+ image with a single executable `.text` section.
///
/// `machine` is an `IMAGE_FILE_MACHINE_*` value, `subsystem` an `IMAGE_SUBSYSTEM_*` value.
///
/// # Example
///
/// ```
/// use compitum_pe::{parse, pe_fixture};
///
/// let bytes = pe_fixture::synthetic(pe_fixture::machine::ARM64, pe_fixture::subsystem::CONSOLE, false);
/// let image = parse(&bytes).expect("valid synthetic image");
/// assert_eq!(image.coff.machine.raw(), 0xAA64);
/// ```
#[must_use]
pub fn synthetic(machine: u16, subsystem: u16, is_dll: bool) -> Vec<u8> {
    synthetic_advanced(machine, subsystem, is_dll, &[], 0x1000, false, 0)
}

/// Builds a synthetic image with every parameter exposed.
///
/// * `imports` — module names to place in a well-formed import directory.
/// * `section_alignment` — the alignment that determines implied page size.
/// * `managed` — when true, sets the CLR runtime header directory to a non-zero RVA.
/// * `timestamp` — the COFF timestamp field.
#[must_use]
pub fn synthetic_advanced(
    machine: u16,
    subsystem: u16,
    is_dll: bool,
    imports: &[&str],
    section_alignment: u32,
    managed: bool,
    timestamp: u32,
) -> Vec<u8> {
    let optional_size = OPTIONAL_SIZE;
    let section_count = 1usize;
    let total = PE_OFFSET
        + 4
        + 20
        + optional_size
        + section_count * SECTION_HEADER_SIZE
        + TEXT_RAW_SIZE
        + 0x800;

    let mut data = vec![0u8; total];

    // ---- DOS header -------------------------------------------------------
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&(PE_OFFSET as u32).to_le_bytes());

    // ---- PE signature -----------------------------------------------------
    data[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

    // ---- COFF file header -------------------------------------------------
    let coff = PE_OFFSET + 4;
    data[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
    data[coff + 2..coff + 4].copy_from_slice(&(section_count as u16).to_le_bytes());
    data[coff + 4..coff + 8].copy_from_slice(&timestamp.to_le_bytes());
    data[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
    let mut characteristics = 0x0002u16; // IMAGE_FILE_EXECUTABLE_IMAGE
    if is_dll {
        characteristics |= 0x2000; // IMAGE_FILE_DLL
    }
    data[coff + 18..coff + 20].copy_from_slice(&characteristics.to_le_bytes());

    // ---- Optional header (PE32+ layout) -----------------------------------
    let opt = coff + 20;
    data[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+ magic
    data[opt + 2] = 14; // linker major
    data[opt + 3] = 0; // linker minor
                       // SizeOfCode at +4, SizeOfInitializedData at +8: left zero, not load-bearing here.
                       // AddressOfEntryPoint at +16: zero, which is valid for a DLL.
                       // BaseOfCode at +20: zero.
                       // Field offsets per the PE specification, numbered from the start of the optional
                       // header.
                       //
                       // Every value below is a documented field position rather than arithmetic chained from
                       // a running anchor. The previous revision chained from `SectionAlignment` and had
                       // drifted eight bytes by the time it reached `Subsystem`, writing `40` where a real
                       // toolchain writes the subsystem constant. Because the *parser* chained from the same
                       // anchor, writer and reader agreed with each other while both disagreed with reality --
                       // which is why the test suite passed and a real compiler-produced binary was read
                       // incorrectly. Only a binary from a third-party toolchain could expose it.
    const OFF_OS_MAJOR: usize = 0x28;
    const OFF_OS_MINOR: usize = 0x2A;
    const OFF_SUBSYSTEM_MAJOR: usize = 0x30;
    const OFF_SIZE_OF_IMAGE: usize = 0x38;
    const OFF_SIZE_OF_HEADERS: usize = 0x3C;
    const OFF_SUBSYSTEM: usize = 0x44;
    const OFF_DLL_CHARACTERISTICS: usize = 0x46;
    const OFF_RVA_AND_SIZES_PE32PLUS: usize = 0x6C;
    const OFF_DATA_DIRECTORY: usize = 0x70;

    data[opt + 0x18..opt + 0x20].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes()); // ImageBase
    data[opt + 0x20..opt + 0x24].copy_from_slice(&section_alignment.to_le_bytes());
    data[opt + 0x24..opt + 0x28].copy_from_slice(&512u32.to_le_bytes()); // FileAlignment
    data[opt + OFF_OS_MAJOR..opt + OFF_OS_MAJOR + 2].copy_from_slice(&10u16.to_le_bytes());
    data[opt + OFF_OS_MINOR..opt + OFF_OS_MINOR + 2].copy_from_slice(&0u16.to_le_bytes());
    data[opt + OFF_SUBSYSTEM_MAJOR..opt + OFF_SUBSYSTEM_MAJOR + 2]
        .copy_from_slice(&10u16.to_le_bytes());
    data[opt + OFF_SIZE_OF_IMAGE..opt + OFF_SIZE_OF_IMAGE + 4]
        .copy_from_slice(&0x2000u32.to_le_bytes());
    data[opt + OFF_SIZE_OF_HEADERS..opt + OFF_SIZE_OF_HEADERS + 4]
        .copy_from_slice(&0x200u32.to_le_bytes());
    data[opt + OFF_SUBSYSTEM..opt + OFF_SUBSYSTEM + 2].copy_from_slice(&subsystem.to_le_bytes());
    // IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE | NX_COMPAT | DYNAMIC_BASE, which is
    // what a real linker emits by default.
    data[opt + OFF_DLL_CHARACTERISTICS..opt + OFF_DLL_CHARACTERISTICS + 2]
        .copy_from_slice(&0x8160u16.to_le_bytes());
    data[opt + OFF_RVA_AND_SIZES_PE32PLUS..opt + OFF_RVA_AND_SIZES_PE32PLUS + 4]
        .copy_from_slice(&16u32.to_le_bytes());

    // Data directories begin at opt + 0x70; each entry is 8 bytes (RVA, size).
    const DIR_IMPORT: usize = 1;
    const DIR_LOAD_CONFIG: usize = 10;
    const DIR_CLR: usize = 14;

    if managed {
        let dir = opt + OFF_DATA_DIRECTORY + DIR_CLR * 8;
        data[dir..dir + 4].copy_from_slice(&0x1100u32.to_le_bytes());
        data[dir + 4..dir + 8].copy_from_slice(&72u32.to_le_bytes());
    }

    if !imports.is_empty() {
        let import_rva = section_alignment + 0x100;
        let descriptor_bytes = (imports.len() + 1) * 20;
        let dir = opt + OFF_DATA_DIRECTORY + DIR_IMPORT * 8;
        data[dir..dir + 4].copy_from_slice(&import_rva.to_le_bytes());
        data[dir + 4..dir + 8].copy_from_slice(&(descriptor_bytes as u32).to_le_bytes());

        let import_file = TEXT_RAW_OFFSET + 0x100;
        let mut cursor = import_file + descriptor_bytes;

        for (index, module) in imports.iter().enumerate() {
            let descriptor = import_file + index * 20;
            let name_rva = import_rva + (cursor - import_file) as u32;
            data[descriptor + 12..descriptor + 16].copy_from_slice(&name_rva.to_le_bytes());

            let name_file = cursor;
            data[name_file..name_file + module.len()].copy_from_slice(module.as_bytes());
            cursor += module.len() + 1;

            // A thunk table with one real entry and a terminating zero entry.
            let thunk_file = cursor;
            let thunk_rva = import_rva + (thunk_file - import_file) as u32;
            data[descriptor + 16..descriptor + 20].copy_from_slice(&thunk_rva.to_le_bytes());
            data[thunk_file..thunk_file + 8].copy_from_slice(&0x1234u64.to_le_bytes());
            data[thunk_file + 8..thunk_file + 16].copy_from_slice(&0u64.to_le_bytes());
            cursor += 16;
        }
    }

    // A non-zero load-configuration RVA, so the parser's load-config handling is exercised.
    let load_config_dir = opt + OFF_DATA_DIRECTORY + DIR_LOAD_CONFIG * 8;
    data[load_config_dir..load_config_dir + 4].copy_from_slice(&0x1200u32.to_le_bytes());
    data[load_config_dir + 4..load_config_dir + 8].copy_from_slice(&0x100u32.to_le_bytes());

    // ---- Section table ----------------------------------------------------
    let section = opt + optional_size;
    data[section..section + 5].copy_from_slice(b".text");
    data[section + 8..section + 12].copy_from_slice(&(TEXT_RAW_SIZE as u32).to_le_bytes());
    data[section + 12..section + 16].copy_from_slice(&section_alignment.to_le_bytes());
    data[section + 16..section + 20].copy_from_slice(&(TEXT_RAW_SIZE as u32).to_le_bytes());
    data[section + 20..section + 24].copy_from_slice(&(TEXT_RAW_OFFSET as u32).to_le_bytes());
    // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
    data[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    data
}

/// Builds an image whose `.text` section contains the given bytes.
///
/// Used to exercise the instruction scanner: the caller supplies the machine code it wants
/// analysed, and this places it at a known RVA (`section_alignment + 0`) so that expected
/// evidence offsets can be asserted exactly.
#[must_use]
pub fn synthetic_with_code(machine: u16, code: &[u8], section_alignment: u32) -> Vec<u8> {
    let mut data = synthetic_advanced(
        machine,
        subsystem::CONSOLE,
        false,
        &[],
        section_alignment,
        false,
        0,
    );
    let limit = code.len().min(TEXT_RAW_SIZE);
    data[TEXT_RAW_OFFSET..TEXT_RAW_OFFSET + limit].copy_from_slice(&code[..limit]);
    data
}

/// Builds an image whose single section carries a name of the caller's choosing.
///
/// Used to exercise ARM64X detection, which considers the `chpe` section prefix as well as
/// the machine field.
#[must_use]
pub fn synthetic_with_section_name(machine: u16, name: &str) -> Vec<u8> {
    let mut data = synthetic(machine, subsystem::CONSOLE, false);
    let section = PE_OFFSET + 4 + 20 + OPTIONAL_SIZE;
    // The field is exactly eight bytes and is not required to be NUL-terminated.
    let bytes = name.as_bytes();
    let limit = bytes.len().min(8);
    data[section..section + 8].fill(0);
    data[section..section + limit].copy_from_slice(&bytes[..limit]);
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    #[test]
    fn produces_a_parseable_image() {
        let bytes = synthetic(machine::ARM64, subsystem::CONSOLE, false);
        let image = parse(&bytes).expect("must parse");
        assert_eq!(image.coff.machine.raw(), 0xAA64);
        assert_eq!(image.subsystem().id(), "windows_console");
        assert_eq!(image.sections.len(), 1);
        assert_eq!(image.sections[0].name, ".text");
        assert!(image.sections[0].is_executable());
    }

    #[test]
    fn every_machine_value_is_preserved_exactly() {
        for raw in [0xAA64u16, 0xA641, 0xA64E, 0x8664, 0x014C, 0x01C4] {
            let bytes = synthetic(raw, subsystem::CONSOLE, false);
            let image = parse(&bytes).expect("must parse");
            assert_eq!(image.coff.machine.raw(), raw, "machine 0x{raw:04X}");
        }
    }

    #[test]
    fn dll_flag_is_set_and_cleared() {
        assert!(parse(&synthetic(machine::ARM64, subsystem::CONSOLE, true))
            .unwrap()
            .coff
            .is_dll());
        assert!(
            !parse(&synthetic(machine::ARM64, subsystem::CONSOLE, false))
                .unwrap()
                .coff
                .is_dll()
        );
    }

    #[test]
    fn section_alignment_drives_page_size() {
        let four_k = synthetic_advanced(0xAA64, subsystem::CONSOLE, false, &[], 0x1000, false, 0);
        assert_eq!(parse(&four_k).unwrap().implied_page_size(), Some(4096));

        let sixteen_k =
            synthetic_advanced(0xAA64, subsystem::CONSOLE, false, &[], 0x4000, false, 0);
        assert_eq!(parse(&sixteen_k).unwrap().implied_page_size(), Some(16384));
    }

    #[test]
    fn imports_are_read_back_correctly() {
        let bytes = synthetic_advanced(
            0xAA64,
            subsystem::CONSOLE,
            false,
            &["kernel32.dll", "d3d12.dll", "dxgi.dll"],
            0x1000,
            false,
            0,
        );
        let image = parse(&bytes).expect("must parse");
        let names: Vec<&str> = image.imports.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"kernel32.dll"), "{names:?}");
        assert!(names.contains(&"d3d12.dll"), "{names:?}");
        assert!(names.contains(&"dxgi.dll"), "{names:?}");
        assert!(image.imports_graphics());
        assert_eq!(image.import_symbol_total, 3);
    }

    #[test]
    fn no_imports_when_none_requested() {
        let image = parse(&synthetic(0xAA64, subsystem::CONSOLE, false)).unwrap();
        assert!(image.imports.is_empty());
        assert!(!image.imports_graphics());
    }

    #[test]
    fn managed_flag_sets_the_clr_directory() {
        let managed = synthetic_advanced(0x8664, subsystem::CONSOLE, false, &[], 0x1000, true, 0);
        assert!(parse(&managed).unwrap().is_managed());

        let native = synthetic(0x8664, subsystem::CONSOLE, false);
        assert!(!parse(&native).unwrap().is_managed());
    }

    #[test]
    fn timestamp_is_recorded_verbatim() {
        let bytes = synthetic_advanced(
            0xAA64,
            subsystem::CONSOLE,
            false,
            &[],
            0x1000,
            false,
            1_700_000_000,
        );
        assert_eq!(parse(&bytes).unwrap().coff.timestamp, 1_700_000_000);
    }

    #[test]
    fn section_name_can_be_chpe_for_arm64x_detection() {
        let bytes = synthetic_with_section_name(machine::ARM64, "chpe32");
        let image = parse(&bytes).unwrap();
        assert!(image.has_arm64x_slices());
    }

    #[test]
    fn code_bytes_land_at_the_expected_rva() {
        let bytes = synthetic_with_code(0xAA64, &[0x1F, 0x20, 0x03, 0xD5], 0x1000);
        let image = parse(&bytes).unwrap();
        // The section starts at RVA 0x1000 and file offset 0x200.
        assert_eq!(image.rva_to_offset(0x1000), Some(TEXT_RAW_OFFSET));
        assert_eq!(
            &bytes[TEXT_RAW_OFFSET..TEXT_RAW_OFFSET + 4],
            &[0x1F, 0x20, 0x03, 0xD5]
        );
    }

    #[test]
    fn gui_subsystem_is_represented() {
        let image = parse(&synthetic(machine::ARM64, subsystem::GUI, false)).unwrap();
        assert!(image.subsystem().requires_display());
        assert!(!image.is_headless_capable());
    }
}
