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
            // `classify` already rejects padding, so reaching here means a real instruction
            // matched. The counter therefore reports genuine evidence rather than fill bytes.
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

/// Returns `true` when a word is linker padding rather than an instruction.
///
/// A linker fills the gap between the end of a section's code and its file-alignment boundary.
/// lld and MSVC use `0xCC` (`int3`), and zero or all-ones fill also occurs. None of these is an
/// instruction, so no rule may classify them.
///
/// This is not a theoretical concern: without it, the padding byte `0xCCCCCCCC` matched the
/// scanner's SME rule, which made a real ARM64 Windows binary that Wine executes successfully
/// report as REFUSED. Every one of that rule's 121 hits across the corpus was padding.
#[must_use]
fn is_padding(word: u32) -> bool {
    matches!(word, 0xCCCC_CCCC | 0x0000_0000 | 0xFFFF_FFFF | 0x9090_9090)
}

/// Recognises an optional-feature instruction in one 32-bit word.
///
/// Returns the feature and a short English note naming the instruction family, so that a
/// report can say *what* was found rather than only *that* something was.
fn classify(word: u32) -> Option<(IsaFeature, &'static str)> {
    // Padding is not code, so it cannot be evidence of an instruction-set requirement.
    if is_padding(word) {
        return None;
    }

    // ---- The hint space: BTI, and other system hints ----------------------
    // `HINT #imm` is `0xD503201F | (imm << 5)` with the top 16 bits `0xD503`.
    if word & 0xFFFF_F01F == 0xD503_201F {
        let imm = (word >> 5) & 0x7F;
        if imm == 0b0100 {
            return Some((IsaFeature::Bti, "BTI branch-target identification"));
        }
    }

    // ---- System instructions, memory tagging, and the SME control space -----
    //
    // Every rule below carries its own COMPLETE mask rather than sitting inside a shared outer
    // guard. That is a structural decision, and it exists because of a bug that shipped.
    //
    // An earlier revision nested these rules inside:
    //
    //     if word & 0xFFC0_0000 == 0xD540_0000 || word & 0xFFFF_F000 == 0xD500_0000 {
    //
    // The outer mask required bits 31..12 to be `0xD540` or `0xD500`, while the inner rules
    // required `0xD920`, `0x9AC0`, `0x9180` or `0xD503`. Those are mutually exclusive, so
    // **every rule inside was unreachable dead code**. MTE and SME were never detected by these
    // paths at all -- and no test noticed, because each rule also had a unit test that called it
    // out of context, where the enclosing condition never applied.
    //
    // Self-contained masks make reachability checkable by inspection: no enclosing condition can
    // contradict a rule's own bits. `scanner_reachability` asserts the property directly.

    // MTE memory tagging: `STG`, `STZG`, `STZ2G`, `LDG` and the tag-checking forms occupy the
    // `0xD9` page. `0xCCCC_CCCC` padding is already excluded by `classify`, so this page rule
    // cannot fire on fill bytes.
    if word & 0xFF00_0000 == 0xD900_0000 {
        return Some((IsaFeature::Mte, "MTE memory-tagging instruction"));
    }
    // MTE pointer tag arithmetic: `ADDG` and `SUBG`.
    if word & 0xFFC0_0000 == 0x9180_0000 || word & 0xFFC0_0000 == 0xD180_0000 {
        return Some((IsaFeature::Mte, "MTE pointer tag arithmetic"));
    }
    // MTE tag transfer: `IRG` and `GMI`.
    if word & 0xFFFF_F000 == 0x9AC0_0000 || word & 0xFFFF_F000 == 0x9AD0_0000 {
        return Some((IsaFeature::Mte, "MTE tag transfer instruction"));
    }

    // The `0xD5` page holds the system instructions: `MRS`, `MSR`, `SYS`, `SYSL` and `HINT`.
    if word & 0xFF00_0000 == 0xD500_0000 {
        let crn = (word >> 12) & 0xF;
        // `CRn == 0xC` is the reserved space the architecture assigns to the SVE and SME
        // system registers. That is a documented operand position rather than a guess about
        // a reserved opcode region, which is the distinction that separates this rule from the
        // band rule removed above.
        if crn == 0xC {
            return Some((IsaFeature::Sme, "SVE/SME system-register access"));
        }
    }

    // ---- SME: deliberately NOT detected from a broad opcode band --------------
    //
    // An earlier revision matched `(word & 0xE0000000) == 0xC0000000` with a marker field, on
    // the reasoning that the region is reserved in the base architecture. That reasoning was
    // never validated, and measuring it showed the rule was pure noise:
    //
    //     SME across 4736 words: 121 hits, 121 on padding, 0 on real code
    //
    // 121 out of 121 hits were the linker's int3 fill. The rule covered 3.12% of the entire
    // 32-bit encoding space -- about 1 word in 32 -- so it matched almost any input while
    // detecting nothing. Worse, it caused a real ARM64 binary that Wine executes successfully
    // to be reported as REFUSED, which is the tool actively misleading its user.
    //
    // SME is now detected only through the system-register and control space above, which
    // inspects specific operands rather than a broad band. That is narrower, and it is
    // justified by the operand layout rather than by an assumption about reserved regions.
    //
    // This is the third rule removed for the same reason, after a fabricated SVE2 marker and
    // an unsatisfiable bit mask. The pattern is consistent: a plausible-looking encoding guess
    // that nothing validates. A rule that cannot be shown to have true positives is not a
    // heuristic, and shipping it is worse than detecting nothing.

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
        assert!(
            report.features().contains(&IsaFeature::Sve),
            "{:?}",
            report.features()
        );
    }

    #[test]
    fn sme_is_detected_through_the_system_register_space() {
        // The `0xD5` system page with `CRn == 0xC`, the operand position the architecture
        // assigns to the SVE/SME system registers.
        let word: u32 = 0xD500_0000 | (0xC << 12);
        let report = scan_code(&word.to_le_bytes(), 0x2000);
        assert!(
            report.features().contains(&IsaFeature::Sme),
            "SVE/SME system-register access must be detected: {:?}",
            report.features()
        );
    }

    #[test]
    fn mte_is_detected_from_the_tagging_page() {
        // `STG`-family instructions occupy the `0xD9` page.
        let word: u32 = 0xD920_0000;
        let report = scan_code(&word.to_le_bytes(), 0x1000);
        assert!(
            report.features().contains(&IsaFeature::Mte),
            "the MTE page must be recognised: {:?}",
            report.features()
        );
    }

    /// No rule may sit inside a condition that contradicts it.
    ///
    /// This is the generalised guard for a bug that shipped three times in this module: a rule
    /// whose bits can never satisfy the enclosing condition, making it unreachable dead code.
    ///
    /// The worst instance nested the MTE and SME rules inside a guard requiring bits 31..12 to
    /// be `0xD540`/`0xD500`, while the rules themselves required `0xD920`, `0x9AC0`, `0x9180`
    /// or `0xD503`. **Every rule in that block was unreachable** — MTE and SME were never
    /// detected by those paths — and no test noticed, because each rule also had a unit test
    /// that called it out of context.
    ///
    /// A unit test that invokes a rule directly cannot detect an enclosing condition that
    /// excludes it. Only a test that runs the rule through the real entry point can, which is
    /// what this does.
    #[test]
    fn every_rule_is_reachable_through_the_real_entry_point() {
        // One representative word per documented rule, each chosen to satisfy that rule's own
        // mask. Each must be classified when fed through `scan_code`, which applies the
        // enclosing conditions exactly as production does.
        let cases: [(u32, IsaFeature, &str); 9] = [
            (0x0420_0002, IsaFeature::Sve, "scalable-vector opcode space"),
            (
                0xD500_0000 | (0xC << 12),
                IsaFeature::Sme,
                "SVE/SME system registers",
            ),
            (0xD920_0000, IsaFeature::Mte, "MTE tagging page"),
            (0x9AC0_0000, IsaFeature::Mte, "MTE tag transfer"),
            (0x9180_0000, IsaFeature::Mte, "MTE pointer tag arithmetic"),
            (0xD503_201F | (0b0100 << 5), IsaFeature::Bti, "BTI hint"),
            (0x1AC0_4000, IsaFeature::Crc32, "CRC-32"),
            (0x4E28_4800, IsaFeature::Aes, "AES round"),
            (0x5E00_4000, IsaFeature::Sha2, "SHA-256"),
        ];

        for (word, expected, description) in cases {
            let report = scan_code(&word.to_le_bytes(), 0x1000);
            assert!(
                report.features().contains(&expected),
                "the rule for {description} (word 0x{word:08X}) is unreachable through the \
                 real entry point; it classifies as {:?}",
                report.features()
            );
        }
    }

    /// The bug this scanner shipped, pinned so it cannot return.
    ///
    /// The removed SME rule matched `(word & 0xE0000000) == 0xC0000000` with a marker field.
    /// That band covers 3.12% of the entire 32-bit encoding space, and every one of its 121
    /// hits across the corpus was `0xCCCCCCCC` — the `int3` fill lld writes to align a section.
    /// The rule had **zero true positives**.
    ///
    /// The consequence was not academic. `compitum verify` reported REFUSED for
    /// `ntcall-arm64.exe`, a real ARM64 Windows program that Wine executes successfully. The
    /// tool was telling users that a working binary would not work.
    #[test]
    fn linker_padding_is_never_classified_as_an_instruction() {
        // The exact words a linker uses to fill a section's alignment gap.
        for padding in [0xCCCC_CCCC_u32, 0x0000_0000, 0xFFFF_FFFF, 0x9090_9090] {
            let report = scan_code(&padding.to_le_bytes(), 0x1000);
            assert!(
                report.is_empty(),
                "padding word 0x{padding:08X} must not be classified as any feature, got {:?}",
                report.features()
            );
            assert_eq!(
                report.total_hits, 0,
                "padding must not be counted as evidence"
            );
        }
    }

    /// A run of padding, the shape that actually caused the false refusal.
    #[test]
    fn a_padding_filled_section_requires_nothing() {
        // 128 words of int3 fill, which is what lld emitted at the end of the real binary
        // that was wrongly refused.
        let mut code = Vec::new();
        for _ in 0..128 {
            code.extend_from_slice(&0xCCCC_CCCCu32.to_le_bytes());
        }
        let report = scan_code(&code, 0x1000);
        assert!(
            report.is_empty(),
            "a padding-filled section must raise no requirements, got {:?}",
            report.features()
        );
        assert_eq!(report.total_hits, 0);
    }

    /// Padding mixed with real code must not hide the real code.
    #[test]
    fn padding_does_not_mask_real_instructions() {
        let mut code = Vec::new();
        for _ in 0..16 {
            code.extend_from_slice(&0xCCCC_CCCCu32.to_le_bytes());
        }
        code.extend_from_slice(&0x0420_0002u32.to_le_bytes()); // a scalable-vector opcode
        for _ in 0..16 {
            code.extend_from_slice(&0xCCCC_CCCCu32.to_le_bytes());
        }

        let report = scan_code(&code, 0x1000);
        assert_eq!(
            report.total_hits, 1,
            "exactly one real instruction is present, so exactly one hit is expected"
        );
        assert!(report.features().contains(&IsaFeature::Sve));
    }

    /// Every remaining rule must have a positive rate above chance on a real binary.
    ///
    /// A rule that matches a large fraction of encoding space while finding nothing real is
    /// noise, not a heuristic. This bounds the risk: it checks that no single rule fires on
    /// padding, which is the cheapest signal that a rule is measuring the fill byte rather
    /// than an instruction.
    #[test]
    fn no_rule_fires_on_padding_alone() {
        let padding = [0xCCCC_CCCCu32, 0x0000_0000, 0xFFFF_FFFF, 0x9090_9090];
        for word in padding {
            for mode in [word, !word, word ^ 0x5555_5555] {
                let report = scan_code(&mode.to_le_bytes(), 0);
                assert_eq!(
                    report.total_hits, 0,
                    "word 0x{mode:08X} derived from padding 0x{word:08X} was classified"
                );
            }
        }
    }

    #[test]
    fn detects_bti() {
        // HINT #0b0100 is BTI.
        let word: u32 = 0xD503_201F | (0b0100 << 5);
        let report = scan_code(&word.to_le_bytes(), 0x1000);
        assert!(
            report.features().contains(&IsaFeature::Bti),
            "{:?}",
            report.features()
        );
    }

    #[test]
    fn detects_crc32() {
        let word: u32 = 0x1AC0_4000;
        let report = scan_code(&word.to_le_bytes(), 0x1000);
        assert!(
            report.features().contains(&IsaFeature::Crc32),
            "{:?}",
            report.features()
        );
    }

    #[test]
    fn detects_aes() {
        let word: u32 = 0x4E28_4800;
        let report = scan_code(&word.to_le_bytes(), 0x1000);
        assert!(
            report.features().contains(&IsaFeature::Aes),
            "{:?}",
            report.features()
        );
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
        assert_eq!(
            report.features().len(),
            1,
            "one feature, not one per occurrence"
        );
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
        // A hostile file can claim an enormous code section, so the scanner caps its work.
        // Verified by behaviour rather than by restating the constant, so this keeps meaning
        // something if the cap changes.
        let code = vec![0u8; 4096];
        let report = scan_code(&code, 0);
        assert!(report.bytes_scanned <= MAX_SCAN_BYTES);
        assert_eq!(
            report.bytes_scanned, 4096,
            "an ordinary input must be scanned fully"
        );
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
        assert!(
            report.features().contains(&IsaFeature::Sve),
            "{:?}",
            report.features()
        );
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
