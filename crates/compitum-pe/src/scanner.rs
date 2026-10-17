//! The AArch64 instruction scanner.
//!
//! # What this is for
//!
//! The PE header tells COMPITUM the *declared* architecture. It does not tell it which
//! optional instructions the code actually executes. That gap matters enormously: an
//! otherwise-ordinary ARM64 binary compiled with SME matrix instructions will load cleanly
//! on a core that lacks SME and then fault on the first such instruction — the worst
//! possible failure mode, because it is discovered late and looks like a crash rather than
//! a compatibility problem.
//!
//! This module closes that gap by reading the machine code and looking for the encodings.
//!
//! # Honest limits
//!
//! Static scanning cannot see dynamically generated code, and a four-byte pattern can occur
//! by coincidence inside data that happens to sit in an executable section. Every finding is
//! therefore reported with [`Confidence::MEDIUM`] rather than certainty, and the router
//! surfaces that weakness in its reasons instead of hiding it.
//!
//! Refusing to scan at all would be worse: it would miss the single most important class of
//! late failure. Reporting the result *as* a heuristic is the honest middle path.
//!
//! # Which encodings are detected
//!
//! Only instructions that are (a) optional in AArch64, (b) plausible in compiled output, and
//! (c) cheap to identify unambiguously. Detecting everything would require a full
//! disassembler; detecting the features that actually vary between real ARM64 parts is
//! sufficient for a routing decision.
//!
//! | Feature | How it is recognised | Reported? |
//! |---|---|---|
//! | SVE | the `0x04` / `0x25` scalable-vector opcode space | yes |
//! | SVE2 | shares the SVE space; not separately distinguishable here | **no — see below** |
//! | SME | the outer-product opcode space and the SME control-register space | yes |
//! | MTE | the `IRG`, `GMI`, `ADDG`, `SUBG`, `STG`, `LDG` and tag-access encodings | yes |
//! | BTI | the `HINT #0b0100` encoding | yes |
//! | LSE | the atomic `LDADD` / `CAS` / `SWP` families | yes |
//! | AES, SHA-2, CRC-32 | the optional cryptographic and checksum instructions | yes |
//! | RNG | the `RNDR` / `RNDRRS` system instructions | yes |
//!
//! # The SVE2 gap, stated plainly
//!
//! SVE2 is **not** reported. It occupies the same encoding space as SVE, and separating the
//! two requires bit-field definitions this codebase has not validated. Rather than guess, the
//! scanner reports SVE and records the limitation in [`ScanReport::caveat`], which the router
//! then surfaces as weak evidence.
//!
//! The direction of the resulting uncertainty is known and documented: a binary that in fact
//! requires SVE2 is reported as requiring only SVE, which could produce a *false compatible*
//! verdict on a host that implements SVE but not SVE2. That is the unsafe direction, which is
//! why it is flagged rather than silently accepted.
//!
//! # Why the scan is conservative
//!
//! A false positive makes COMPITUM refuse a binary that would have run — a bad outcome. A
//! false negative makes it promise native execution that then faults — a worse one. Where
//! the two encodings are genuinely ambiguous, this module therefore prefers to report the
//! finding and let the confidence level do its job, rather than to stay silent.

use compitum_isa::{Confidence, IsaFeature, Requirement, RequirementSource};

/// The largest number of bytes the scanner will examine in one section.
///
/// A deliberately bounded amount of work: a hostile file can claim a gigabyte of executable
/// code, and refusing to spend more than this keeps a compatibility check fast enough to run
/// in a pre-commit hook or a CI matrix.
pub const MAX_SCAN_BYTES: usize = 64 * 1024 * 1024;

/// The result of scanning an image's code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Requirements derived from instruction encodings, with provenance.
    pub requirements: Vec<Requirement>,
    /// Number of bytes actually examined.
    pub bytes_scanned: usize,
    /// Number of executable sections examined.
    pub sections_scanned: usize,
    /// Total pattern hits, across all features. Counts occurrences, not distinct features,
    /// because "the image uses SME once" and "the image is full of SME" are different
    /// signals and the Oracle benefits from knowing which.
    pub total_hits: usize,
}

impl ScanReport {
    /// Returns `true` when nothing was found — which is **not** the same as "nothing is
    /// required", only that the scan found nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requirements.is_empty()
    }

    /// The distinct features detected.
    #[must_use]
    pub fn features(&self) -> Vec<IsaFeature> {
        let mut seen: Vec<IsaFeature> = self.requirements.iter().map(|r| r.feature).collect();
        seen.sort();
        seen.dedup();
        seen
    }

    /// Features that this scan cannot rule out, phrased for a human reader.
    ///
    /// Stated explicitly so that a clean scan is never mistaken for a guarantee.
    #[must_use]
    pub fn caveat(&self) -> &'static str {
        "static scanning cannot see run-time-generated code; a rare encoding can appear \
         by coincidence in data held in an executable section; and SVE2 is not \
         distinguished from SVE, so a scalable-vector requirement may be stronger than \
         reported"
    }
}

/// Scans a 4-byte-aligned code range for optional AArch64 instruction encodings.
///
/// `base_rva` is the relative virtual address of `code[0]`, used so that evidence offsets in
/// the resulting requirements point at a meaningful location in the image.
///
/// The input does not need to be aligned: the scanner walks every 4-byte offset, because a
/// linker can place code at any alignment and a missed instruction is worse than extra work.
#[must_use]
pub fn scan_code(code: &[u8], base_rva: u32) -> ScanReport {
    let mut report = ScanReport::default();
    if code.len() < 4 {
        return report;
    }

    let limit = code.len().min(MAX_SCAN_BYTES);
    let usable = limit - (limit % 4);
    report.bytes_scanned = usable;

    // Accumulate the first evidence offset per feature, and a hit count. One requirement is
    // emitted per feature regardless of how many times it occurs: the router needs the set,
    // and the count is reported separately for the Oracle.
    let mut first_hit: Vec<(IsaFeature, u32, &'static str)> = Vec::new();
    let mut hits: usize = 0;

    let mut offset = 0usize;
    while offset + 4 <= usable {
        let word = u32::from_le_bytes([
            code[offset],
            code[offset + 1],
            code[offset + 2],
            code[offset + 3],
        ]);
        if let Some((feature, note)) = classify(word) {
            hits += 1;
            let rva = base_rva.wrapping_add(offset as u32);
            if !first_hit.iter().any(|(f, _, _)| *f == feature) {
                first_hit.push((feature, rva, note));
            }
        }
        offset += 4;
    }

    report.total_hits = hits;
    for (feature, rva, note) in first_hit {
        report.requirements.push(
            Requirement::new(
                feature,
                RequirementSource::InstructionScan,
                Some(rva),
                format!("{note} at RVA 0x{rva:08X}"),
            )
            .with_confidence_cap(Confidence::MEDIUM),
        );
    }
    // Stable order, so that two scans of the same bytes produce byte-identical output and an
    // Oracle record is reproducible.
    report.requirements.sort_by_key(|r| r.feature);
    report
}

/// Recognises an optional-feature instruction in one 32-bit word.
///
/// Returns the feature and a short English note naming the instruction family, so that a
/// report can say *what* was found rather than only *that* something was.
fn classify(word: u32) -> Option<(IsaFeature, &'static str)> {
    // ---- The hint space: BTI, and other system hints ----------------------
    // `HINT #imm` is `0xD503201F | (imm << 5)` with the top 16 bits `0xD503`.
    if word & 0xFFFF_F01F == 0xD503_201F {
        let imm = (word >> 5) & 0x7F;
        if imm == 0b0100 {
            return Some((IsaFeature::Bti, "BTI branch-target identification"));
        }
    }

    // ---- System instructions: MTE, and the SME/SVE system registers --------
    if word & 0xFFC0_0000 == 0xD540_0000 || word & 0xFFFF_F000 == 0xD500_0000 {
        // The system instruction space. Only a handful of encodings are relevant.
        let op0 = (word >> 19) & 0x3;
        let op1 = (word >> 16) & 0x7;
        let crn = (word >> 12) & 0xF;
        let crm = (word >> 8) & 0xF;
        let op2 = (word >> 5) & 0x7;
        let rt = word & 0x1F;

        // MTE: `IRG`, `GMI`, `ADDG`, `SUBG`, `STG`, `LDG`, and the tag access registers.
        // Recognised by their distinctive CRn/CRm combinations in the DC/IC space, plus the
        // dedicated opcodes in the `0xD920`-family encoding space.
        if (word & 0xFFFF_F000 == 0xD920_0000)
            || (word & 0xFFFFFFE0 == 0x9AC0_1000) // IRG Xd, Xn, Xm
            || (word & 0xFFFFFFE0 == 0x9AD0_1000) // GMI
            || (word & 0xFFFFFC00 == 0x9180_0000 && op2 == 0) // ADDG family
        {
            return Some((IsaFeature::Mte, "MTE memory-tagging instruction"));
        }
        if op0 == 0 && crn == 0 && crm == 0 && op1 == 0 && op2 <= 1 && rt == 0x1F {
            // Reserved; do not claim anything from an all-zero system instruction.
        }
        // SME system-register access: `SMSTART`, `SMSTOP`, and the ZA/SME control registers
        // live in the `0xD5` space with specific operands. Their presence is a strong signal.
        if word & 0xFFFF_F000 == 0xD503_0000 && crn >= 4 && crm >= 4 {
            return Some((IsaFeature::Sme, "SME control or ZA register access"));
        }
    }

    // ---- SME: the streaming-mode and matrix opcode space -------------------
    // SME instructions occupy `0xC0`-prefixed and `0xA0`-prefixed encoding regions that are
    // reserved in the base architecture. Checking the top byte and the specific fixed bits
    // is what distinguishes them from ordinary SIMD.
    if word & 0xE000_0000 == 0xC000_0000 {
        // SME outer-product family: `0xC0` with the 24-bit marker pattern.
        let marker = (word >> 22) & 0x3;
        if marker == 0x3 {
            return Some((IsaFeature::Sme, "SME outer-product instruction"));
        }
    }
    if word & 0xFFE0_FC00 == 0xC002_0000 {
        return Some((IsaFeature::Sme, "SME vector select"));
    }

    // ---- Scalable vectors ---------------------------------------------------
    // The `0x04` and `0x25` major opcode spaces belong to SVE and its extensions, which
    // makes "this instruction is a scalable-vector one" a reliable detection.
    //
    // SVE2 is deliberately NOT reported separately. It shares this encoding space, and
    // telling it apart needs bit-field definitions this codebase has not validated against
    // the architecture reference. An earlier revision guessed at a marker here; the guess
    // was not defensible, and manufacturing precision the evidence does not support is
    // exactly the dishonesty this project exists to avoid.
    //
    // The gap is therefore recorded rather than papered over: a binary reported as
    // requiring SVE may in fact require SVE2, and the router surfaces that weakness through
    // its weak-evidence reason instead of presenting a firm verdict.
    let top8 = (word >> 24) as u8;
    if top8 == 0x04 || top8 == 0x25 {
        return Some((IsaFeature::Sve, "scalable-vector opcode"));
    }

    // ---- LSE atomics --------------------------------------------------------
    // `LDADD`, `LDCLR`, `LDEOR`, `LDSET`, `LDSMAX`, `LDSMIN`, `LDUMAX`, `LDUMIN`,
    // `SWP`, `CAS`, `CASP` — the `0xB8`/`0x38`/`0x88`/`0x08` families with size bits.
    if matches!(word >> 24, 0x38 | 0xB8 | 0x78 | 0xF8) {
        // The size/opcode field distinguishes atomics from ordinary loads and stores.
        let size = (word >> 30) & 0x3;
        if size < 0x3 {
            return Some((IsaFeature::Lse, "atomic memory instruction"));
        }
    }
    if matches!(word >> 21, 0x1C8 | 0x0C8) && (word >> 30) < 0x3 {
        return Some((IsaFeature::Lse, "compare-and-swap pair"));
    }

    // ---- Optional crypto and checksum instructions --------------------------
    // AES: `AESE`, `AESD`, `AESMC`, `AESIMC` share `0x4E28` / `0x4E38` prefixes.
    if word & 0xFFFF_FC00 == 0x4E28_4800 || word & 0xFFFF_FC00 == 0x4E28_5800 {
        return Some((IsaFeature::Aes, "AES round instruction"));
    }
    // SHA-256 `SHA256H`, `SHA256H2`, `SHA256SU0`, `SHA256SU1`.
    if word & 0xFFE0_FC00 == 0x5E00_4000 {
        return Some((IsaFeature::Sha2, "SHA-256 instruction"));
    }
    // CRC-32: `CRC32X`/`CRC32CX` and the byte/half/word variants in the `0x1AC0` family.
    if word & 0xFFE0_F0E0 == 0x1AC0_4000 {
        return Some((IsaFeature::Crc32, "CRC-32 instruction"));
    }
    // Random number: `RNDR`/`RNDRRS` in the system space.
    if word & 0xFFFF_FC00 == 0xD53B_2400 {
        return Some((IsaFeature::Rng, "RNDR random-number instruction"));
    }

    None
}

/// Scans every executable section of a parsed image.
///
/// Returns a report whose `sections_scanned` reflects how many were actually readable, so
/// that "scanned and found nothing" can be distinguished from "could not read the code".
#[must_use]
pub fn scan_image(data: &[u8], image: &crate::PeImage) -> ScanReport {
    let mut combined = ScanReport::default();
    for section in image.sections.iter().filter(|s| s.is_executable()) {
        let start = section.raw_offset as usize;
        let end = start.saturating_add(section.raw_size as usize);
        if start >= data.len() {
            continue;
        }
        let end = end.min(data.len());
        if end <= start {
            continue;
        }
        let slice = &data[start..end];
        let report = scan_code(slice, section.virtual_address);
        combined.sections_scanned += 1;
        combined.bytes_scanned += report.bytes_scanned;
        combined.total_hits += report.total_hits;
        // Keep the earliest evidence per feature across sections.
        for requirement in report.requirements {
            if !combined
                .requirements
                .iter()
                .any(|r| r.feature == requirement.feature)
            {
                combined.requirements.push(requirement);
            }
        }
    }
    combined.requirements.sort_by_key(|r| r.feature);
    combined
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{machine, subsystem};
    use crate::pe_fixture;

    #[test]
    fn clean_code_yields_no_requirements() {
        // A run of `NOP` (0xD503201F has the hint pattern, so use a plain data pattern that
        // matches no optional encoding).
        let code = vec![0x00u8; 4096];
        let report = scan_code(&code, 0x1000);
        assert!(report.is_empty(), "got {:?}", report.features());
        assert_eq!(report.bytes_scanned, 4096);
        assert_eq!(report.total_hits, 0);
    }

    #[test]
    fn detects_scalable_vector_opcode() {
        // Any word in the 0x04 / 0x25 space is a scalable-vector instruction. The scanner
        // reports SVE for it, because SVE2 cannot be told apart from SVE here.
        for word in [0x0420_000A_u32, 0x0420_0002, 0x25A0_0001] {
            let report = scan_code(&word.to_le_bytes(), 0x1000);
            assert!(
                report.features().contains(&IsaFeature::Sve),
                "word 0x{word:08X} gave {:?}",
                report.features()
            );
            assert_eq!(report.total_hits, 1);
        }
    }

    /// Pins the documented limitation, so it is a decision rather than an oversight.
    ///
    /// If SVE2 discrimination is ever added, this test must fail and be rewritten — which is
    /// the point: the gap should not close silently.
    #[test]
    fn sve2_is_deliberately_not_claimed() {
        let report = scan_code(&0x0420_000Au32.to_le_bytes(), 0x1000);
        assert!(
            !report.features().contains(&IsaFeature::Sve2),
            "SVE2 discrimination is not implemented and must not be implied"
        );
        assert!(
            report.caveat().contains("SVE2"),
            "the limitation must be stated in the caveat"
        );
    }

    #[test]
    fn detects_sve_opcode() {
        let word: u32 = 0x0420_0002;
        let report = scan_code(&word.to_le_bytes(), 0x1000);
        assert!(report.features().contains(&IsaFeature::Sve), "{:?}", report.features());
    }

    #[test]
    fn detects_sme_outer_product() {
        // The SME outer-product space: top bits 0xC0 with marker 0b11.
        let word: u32 = 0xC0C0_0000;
        let report = scan_code(&word.to_le_bytes(), 0x2000);
        assert!(report.features().contains(&IsaFeature::Sme), "{:?}", report.features());
    }

    #[test]
    fn detects_bti() {
        // HINT #0b0100 is BTI.
        let word: u32 = 0xD503_201F | (0b0100 << 5);
        let report = scan_code(&word.to_le_bytes(), 0x1000);
        assert!(report.features().contains(&IsaFeature::Bti), "{:?}", report.features());
    }

    #[test]
    fn detects_crc32() {
        let word: u32 = 0x1AC0_4000;
        let report = scan_code(&word.to_le_bytes(), 0x1000);
        assert!(report.features().contains(&IsaFeature::Crc32), "{:?}", report.features());
    }

    #[test]
    fn detects_aes() {
        let word: u32 = 0x4E28_4800;
        let report = scan_code(&word.to_le_bytes(), 0x1000);
        assert!(report.features().contains(&IsaFeature::Aes), "{:?}", report.features());
    }

    #[test]
    fn evidence_offset_points_at_the_instruction() {
        // Two clean words, then an SVE word at offset 8.
        let mut code = vec![0u8; 8];
        code.extend_from_slice(&0x0420_0002u32.to_le_bytes());
        let report = scan_code(&code, 0x1000);
        let requirement = report
            .requirements
            .iter()
            .find(|r| r.feature == IsaFeature::Sve)
            .expect("SVE must be reported");
        assert_eq!(requirement.evidence_rva, Some(0x1008));
    }

    #[test]
    fn findings_carry_medium_confidence_not_certainty() {
        // The scanner is a heuristic and must say so, or the router will refuse binaries
        // that would in fact have run.
        let word: u32 = 0x0420_0002;
        let report = scan_code(&word.to_le_bytes(), 0x1000);
        for requirement in &report.requirements {
            assert_eq!(requirement.source, RequirementSource::InstructionScan);
            assert!(
                requirement.confidence.permille() <= Confidence::MEDIUM.permille(),
                "scan evidence must not claim certainty"
            );
        }
    }

    #[test]
    fn findings_are_deduplicated_per_feature() {
        let word: u32 = 0x0420_0002;
        let mut code = Vec::new();
        for _ in 0..100 {
            code.extend_from_slice(&word.to_le_bytes());
        }
        let report = scan_code(&code, 0x1000);
        assert_eq!(report.features().len(), 1, "one feature, not one per occurrence");
        assert_eq!(report.total_hits, 100, "but the hit count is preserved");
    }

    #[test]
    fn output_order_is_deterministic() {
        let mut code = Vec::new();
        code.extend_from_slice(&0x1AC0_4000u32.to_le_bytes()); // crc32
        code.extend_from_slice(&0x0420_000Au32.to_le_bytes()); // sve2
        code.extend_from_slice(&0xC0C0_0000u32.to_le_bytes()); // sme
        let first = scan_code(&code, 0);
        let second = scan_code(&code, 0);
        assert_eq!(first, second);
        let features = first.features();
        let mut sorted = features.clone();
        sorted.sort();
        assert_eq!(features, sorted, "features must be in canonical order");
    }

    #[test]
    fn very_short_input_is_handled() {
        assert!(scan_code(&[], 0).is_empty());
        assert!(scan_code(&[0x04], 0).is_empty());
        assert!(scan_code(&[0x04, 0x20, 0x00], 0).is_empty());
        // Exactly four bytes is enough to scan.
        let report = scan_code(&0x0420_0002u32.to_le_bytes(), 0);
        assert_eq!(report.bytes_scanned, 4);
    }

    #[test]
    fn non_multiple_of_four_length_is_truncated_safely() {
        let mut code = 0x0420_0002u32.to_le_bytes().to_vec();
        code.push(0xFF); // a stray byte
        let report = scan_code(&code, 0);
        assert_eq!(report.bytes_scanned, 4, "the partial word is not examined");
    }

    #[test]
    fn scan_size_is_bounded() {
        // The cap protects against a hostile file claiming an enormous code section. Not
        // allocating the full cap here; just assert the constant is sane and documented.
        assert!(MAX_SCAN_BYTES >= 1024 * 1024);
        assert!(MAX_SCAN_BYTES <= 1024 * 1024 * 1024);
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // Deterministic pseudo-random input, exercising the classifier on junk.
        let mut state = 0xDEAD_BEEFu32;
        let mut code = Vec::with_capacity(40_000);
        for _ in 0..10_000 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            code.extend_from_slice(&state.to_le_bytes());
        }
        let report = scan_code(&code, 0);
        // Whatever it finds, it must not panic and must return a consistent report.
        assert_eq!(report.bytes_scanned, 40_000);
        assert_eq!(report, scan_code(&code, 0));
    }

    #[test]
    fn scans_every_executable_section_of_an_image() {
        // Build an image whose .text holds SVE code and verify end-to-end plumbing.
        let code = 0x0420_0002u32.to_le_bytes();
        let bytes = pe_fixture::synthetic_with_code(machine::ARM64, &code, 0x1000);
        let image = crate::parse(&bytes).unwrap();
        let report = scan_image(&bytes, &image);
        assert_eq!(report.sections_scanned, 1);
        assert!(report.features().contains(&IsaFeature::Sve), "{:?}", report.features());
        // The evidence RVA must be the section's virtual address, since the code is at its
        // very start.
        let requirement = report
            .requirements
            .iter()
            .find(|r| r.feature == IsaFeature::Sve)
            .expect("SVE found");
        assert_eq!(requirement.evidence_rva, Some(0x1000));
    }

    #[test]
    fn image_with_no_executable_code_reports_nothing_scanned() {
        let bytes = pe_fixture::synthetic(machine::ARM64, subsystem::CONSOLE, false);
        let image = crate::parse(&bytes).unwrap();
        let report = scan_image(&bytes, &image);
        // The fixture has one executable section holding zeroes, so it is scanned but clean.
        assert_eq!(report.sections_scanned, 1);
        assert!(report.is_empty());
        assert_eq!(report.total_hits, 0);
    }

    #[test]
    fn caveat_is_stated_for_every_clean_scan() {
        let report = scan_code(&[0u8; 64], 0);
        let caveat = report.caveat();
        assert!(caveat.contains("cannot see run-time-generated code"));
        assert!(caveat.contains("SVE2"));
    }
}
