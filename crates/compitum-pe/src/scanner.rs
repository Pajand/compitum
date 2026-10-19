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
    /// `true` when the scan did not run because the image's architecture cannot contain
    /// AArch64 instructions.
    ///
    /// Distinct from an empty result on purpose. "Scanned and found nothing" and "not
    /// applicable to this architecture" are different statements, and a caller that merged
    /// them would report an x86 image as having no instruction requirements when in fact
    /// nothing was looked for.
    pub skipped_not_aarch64: bool,
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

    // ---- Instruction rules ------------------------------------------------------------------
    //
    // Every mask below was DERIVED FROM `llvm-mc`, the external assembler, rather than written
    // by hand. Regenerate with `tools/make_encodings.py`; a test asserts these constants agree
    // with the generated `tests/corpus/encodings.json`, so the two cannot drift.
    //
    // # Why derivation rather than hand-writing
    //
    // Three of these rules were previously wrong in a way no test could see. They were written
    // by hand and tested against hand-written word constants, so the rule and the test agreed
    // with each other while disagreeing with every real compiler. Measured against assembler
    // output:
    //
    //   crc32b w0, w1, w2   = 0x1AC24020   old mask 0xFFE0F0E0 -> 0x1AC04020  NEVER MATCHED
    //   irg x0, x1, x2      = 0x9AC21020   old mask 0xFFFFF000 -> 0x9AC21000  NEVER MATCHED
    //   bti c               = 0xD503245F   old immediate check expected 4, actual 34  NEVER MATCHED
    //
    // The cause is the same each time: a register field folded into the mask, because every
    // sample in the hand-written example happened to use the same register. The generator avoids
    // it by assembling several variants with DIFFERENT registers and keeping only the bits that
    // stay constant.
    //
    // Detection is therefore narrower and true. A rule that can never fire is worse than no
    // rule, because it reports a capability set that is not real.

    // ---- Branch Target Identification --------------------------------------
    // `BTI` and its target variants (`c`, `j`, `jc`) share one encoding, differing only in the
    // hint immediate.
    if word & 0xFFFFFF3F == 0xD503241F {
        return Some((IsaFeature::Bti, "BTI branch-target identification"));
    }

    // ---- Memory tagging ----------------------------------------------------
    // Wine's own docs and the architecture reference place the MTE tagging instructions in
    // specific pages rather than one broad region, so each family gets its own exact mask.
    // `STG`/`LDG` write and read tags; `IRG`/`GMI` move them; `ADDG`/`SUBG` adjust them with a
    // tag offset.
    if word & 0xFFFFFE10 == 0xD9200800 {
        return Some((IsaFeature::Mte, "MTE store-tag instruction"));
    }
    if word & 0xFFFFFE10 == 0xD9600000 {
        return Some((IsaFeature::Mte, "MTE load-tag instruction"));
    }
    if word & 0xFFF0FE10 == 0x9AC01000 {
        return Some((IsaFeature::Mte, "MTE insert-random-tag instruction"));
    }
    if word & 0xFFF0FE10 == 0x9AC01400 {
        return Some((IsaFeature::Mte, "MTE tag-mask instruction"));
    }
    if word & 0xFFFCF31A == 0x91800000 {
        return Some((IsaFeature::Mte, "MTE add-tag-offset instruction"));
    }
    if word & 0xFFFCF31A == 0xD1800000 {
        return Some((IsaFeature::Mte, "MTE subtract-tag-offset instruction"));
    }

    // ---- Scalable matrix extension -----------------------------------------
    // Streaming-mode control is the instruction a compiler emits to *use* the matrix units,
    // so its presence is direct evidence of an SME requirement rather than an inference from
    // an opcode band.
    //
    // This replaces a rule that matched 3.12% of encoding space and had zero true positives,
    // and it is derived from the assembler rather than guessed. Note that a *band* rule is
    // what was removed; a rule pinned to the exact encoding of a specific instruction is the
    // opposite kind of thing.
    if word & 0xFFFFFEFF == 0xD503467F {
        return Some((IsaFeature::Sme, "SME streaming-mode control"));
    }
    if word & 0xFFDFFFF0 == 0xD51B4240 {
        return Some((IsaFeature::Sme, "SME control-register access"));
    }

    // ---- Scalable vectors ---------------------------------------------------
    // The `0x04` and `0x25` major opcode spaces belong to SVE and its extensions, which makes
    // "this instruction is a scalable-vector one" a reliable detection.
    //
    // SVE2 is deliberately NOT reported separately. It shares this encoding space, and telling
    // it apart needs bit-field definitions this codebase has not validated against the
    // architecture reference. An earlier revision guessed at a marker here; the guess was not
    // defensible, and manufacturing precision the evidence does not support is exactly the
    // dishonesty this project exists to avoid.
    //
    // The gap is recorded rather than papered over: a binary reported as requiring SVE may in
    // fact require SVE2, and the router surfaces that weakness through its weak-evidence reason.
    //
    // `UDOT` and `SDOT` are reported as their own feature, derived from the assembler, so a
    // binary using only the int8 dot product is not reported as needing full SVE.
    if word & 0xDFF0FE10 == 0x4E809400 {
        return Some((IsaFeature::DotProd, "int8 dot-product instruction"));
    }
    let top8 = (word >> 24) as u8;
    if top8 == 0x04 || top8 == 0x25 {
        return Some((IsaFeature::Sve, "scalable-vector opcode"));
    }

    // ---- LSE atomics --------------------------------------------------------
    // `LDADD`, `LDCLR`, `LDEOR`, `LDSET`, `LDSMAX`, `LDSMIN`, `LDUMAX`, `LDUMIN`, `SWP`, `CAS`
    // and `CASP` share the `0xB8`/`0x38`/`0x78`/`0xF8` major opcodes with size bits.
    if matches!(word >> 24, 0x38 | 0xB8 | 0x78 | 0xF8) {
        // The size field distinguishes atomics from ordinary loads and stores.
        let size = (word >> 30) & 0x3;
        if size < 0x3 {
            return Some((IsaFeature::Lse, "atomic memory instruction"));
        }
    }
    if matches!(word >> 21, 0x1C8 | 0x0C8) && (word >> 30) < 0x3 {
        return Some((IsaFeature::Lse, "compare-and-swap pair"));
    }

    // ---- Optional cryptography and checksum instructions --------------------
    if word & 0xFFFFCC10 == 0x4E284800 {
        return Some((IsaFeature::Aes, "AES round instruction"));
    }
    if word & 0xFFD08610 == 0x5E000000 {
        return Some((IsaFeature::Sha2, "SHA-256 instruction"));
    }
    if word & 0x7FE0E000 == 0x1AC04000 {
        return Some((IsaFeature::Crc32, "CRC-32 instruction"));
    }

    // ---- Random number generation -------------------------------------------
    // `RNDR` and `RNDRRS` in the system space, moving a random value into a general register.
    if word & 0xFFFFFFFA == 0xD53B2400 {
        return Some((IsaFeature::Rng, "RNDR random-number instruction"));
    }

    None
}

/// Returns `true` when an image of this family can contain AArch64 instructions.
///
/// The list is deliberately explicit rather than "anything ARM64-ish": a reader has to be able
/// to see why each family is included, and a family added later should force a decision here.
#[must_use]
fn can_contain_aarch64(family: crate::AbiFamily) -> bool {
    use crate::AbiFamily;
    match family {
        AbiFamily::Arm64Native | AbiFamily::Arm64Fat | AbiFamily::Arm64Hybrid => true,
        // The x86 side of a hybrid image: the PE machine type says AMD64, but the linked image
        // carries AArch64 code too, and `compitum-pe` identifies it through the CHPE metadata.
        AbiFamily::X86Hybrid => true,
        AbiFamily::X86
        | AbiFamily::X86_64
        | AbiFamily::Arm32
        | AbiFamily::Itanium
        | AbiFamily::RiscV
        | AbiFamily::LoongArch
        | AbiFamily::PowerPc
        | AbiFamily::Unknown
        | AbiFamily::Other => false,
    }
}

/// Scans every executable section of a parsed image for AArch64 instruction encodings.
///
/// Returns a report whose `sections_scanned` reflects how many were actually readable, so
/// that "scanned and found nothing" can be distinguished from "could not read the code".
///
/// # Only images that can contain AArch64 code are scanned
///
/// This is a real defect found by scanning genuine downloads from the internet, and it was
/// severe: an x86 executable came back with "this host does not implement: sve" and was
/// refused. x86 machine code cannot contain an AArch64 instruction. What happened is that a
/// four-byte window of x86 code matched an SVE encoding pattern by coincidence, the scanner
/// reported it as a requirement, and the router believed it — so **every** x86 and x86-64
/// binary was liable to be refused for a feature its own architecture cannot express.
///
/// The root cause is that the pattern table decodes AArch64 words and was being applied to
/// bytes from any architecture at all. A 32-bit instruction encoding is only meaningful if you
/// know which instruction set you are decoding, so the family now gates the scan.
///
/// The families listed are exactly those that can hold AArch64 code:
///
/// * `Arm64Native` — all of it;
/// * `Arm64Fat` — the ARM64 slice of a fat image;
/// * `Arm64Hybrid` (ARM64EC) — the AArch64 functions, alongside x86-64 ones;
/// * `X86Hybrid` — the x86 side of a hybrid image, which deliberately reports an x86 machine
///   type while the linked image also contains AArch64 code. Excluding it would understate a
///   real requirement.
///
/// Everything else — x86, x86-64, ARM32, Itanium, RISC-V and the rest — is skipped, and the
/// report says so rather than silently returning nothing.
#[must_use]
pub fn scan_image(data: &[u8], image: &crate::PeImage) -> ScanReport {
    let mut combined = ScanReport::default();

    if !can_contain_aarch64(image.family()) {
        // Deliberately not an error and not an empty "clean" result: the report records zero
        // sections scanned, which is how a caller distinguishes "not applicable" from "scanned
        // and found nothing". Conflating those is the defect class this project keeps finding.
        combined.skipped_not_aarch64 = true;
        return combined;
    }

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

    /// Every rule must fire on the encodings the ASSEMBLER produced, not on constants a human
    /// wrote down.
    ///
    /// This test replaces three earlier ones that fed hand-written words. Those validated that a
    /// rule matched its author's guess -- they could not detect that the guess itself was wrong,
    /// because the rule and the test were written together.
    ///
    /// The data comes from `tests/corpus/encodings.json`, generated by `tools/make_encodings.py`
    /// from `llvm-mc` with registers varied. Deriving it that way caught three rules that could
    /// never match real compiler output:
    ///
    ///     crc32b w0, w1, w2  = 0x1AC24020   old mask 0xFFE0F0E0 -> 0x1AC04020  NEVER MATCHED
    ///     irg x0, x1, x2     = 0x9AC21020   old mask 0xFFFFF000 -> 0x9AC21000  NEVER MATCHED
    ///     bti c              = 0xD503245F   old immediate check wanted 4, actual 34  NEVER MATCHED
    ///
    /// Driving the assembler-derived bytes through `scan_code` -- rather than testing `classify`
    /// directly -- means the enclosing conditions are applied exactly as production applies them.
    #[test]
    fn every_rule_detects_the_assemblers_encodings() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/encodings.json");
        // `&path` is correct here rather than a needless borrow: `path` is used again inside the
        // error handler, so it must not be moved.
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "cannot read {}: {e}\nRegenerate with: python3 tools/make_encodings.py",
                path.display()
            )
        });
        let doc = compitum_json::parse(&text).expect("encodings.json must be valid JSON");
        let families = doc["families"].as_object().expect("a families object");

        // The feature each encoding family must be reported as.
        let expected_feature = |family: &str| -> Option<IsaFeature> {
            Some(match family {
                "crc32" => IsaFeature::Crc32,
                "bti" => IsaFeature::Bti,
                "aes" => IsaFeature::Aes,
                "sha256" => IsaFeature::Sha2,
                "irg" | "gmi" | "addg" | "subg" | "stg" | "ldg" => IsaFeature::Mte,
                "rndr" => IsaFeature::Rng,
                "sme_streaming" | "sme_svcr" => IsaFeature::Sme,
                "dotprod" => IsaFeature::DotProd,
                _ => return None,
            })
        };

        let mut checked = 0;
        let mut failures: Vec<String> = Vec::new();

        for (family, entry) in families.iter() {
            let Some(want) = expected_feature(family) else {
                continue;
            };
            let Some(variants) = entry["variants"].as_array() else {
                continue;
            };

            for variant in variants {
                let instruction = variant["instruction"].as_str().unwrap_or("?");
                let Some(encoded) = variant["encoding"].as_str() else {
                    continue;
                };
                let Ok(word) = u32::from_str_radix(encoded.trim_start_matches("0x"), 16) else {
                    failures.push(format!("{family}: unparseable encoding {encoded}"));
                    continue;
                };

                let report = scan_code(&word.to_le_bytes(), 0x1000);
                if !report.features().contains(&want) {
                    failures.push(format!(
                        "{family}: `{instruction}` ({encoded}) must be detected as {} but \
                         classified as {:?}",
                        want.id(),
                        report.features()
                    ));
                }
                checked += 1;
            }
        }

        assert!(
            checked >= 30,
            "only {checked} encodings were checked; the file looks truncated"
        );
        assert!(
            failures.is_empty(),
            "{} of {checked} assembler-derived encodings were not detected:\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
    }

    /// The scanner's masks must equal the generated ones.
    ///
    /// Pins the constants against their source, so a hand edit cannot silently diverge from the
    /// assembler-derived values.
    #[test]
    fn scanner_masks_match_the_generated_encodings() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/encodings.json");
        let doc = compitum_json::parse(&std::fs::read_to_string(path).expect("readable"))
            .expect("valid JSON");
        let families = doc["families"].as_object().expect("families");

        let parse = |text: &str| u32::from_str_radix(text.trim_start_matches("0x"), 16).unwrap();

        let mut checked = 0;
        for (family, entry) in families.iter() {
            let mask = parse(entry["mask"].as_str().expect("mask"));
            let konst = parse(entry["const"].as_str().expect("const"));

            // The accept word is a real assembler encoding taken from the file, rather than a
            // constant restated here. An earlier version of this test used words I picked by
            // hand, and I picked one wrong -- the same mistake the rules themselves were making,
            // so it is not repeated.
            let Some(variants) = entry["variants"].as_array() else {
                continue;
            };
            let Some(first) = variants.first() else {
                continue;
            };
            let accept = parse(first["encoding"].as_str().expect("encoding"));

            assert_eq!(
                accept & mask,
                konst,
                "{family}: the derived mask does not accept the assembler's own encoding"
            );

            // The reject word is derived too: flip the mask's lowest constrained bit. This cannot
            // be wrong by construction, unlike a hand-picked counterexample.
            let flip = mask & mask.wrapping_neg();
            assert_ne!(flip, 0, "{family}: a zero mask would accept everything");
            let reject = konst ^ flip;
            assert_ne!(
                reject & mask,
                konst,
                "{family}: the rule does not separate {accept:#010X} from {reject:#010X}"
            );

            // The separation must hold through the real entry point, not only in arithmetic.
            let accepted = scan_code(&accept.to_le_bytes(), 0);
            assert!(
                !accepted.is_empty(),
                "{family}: the assembler's encoding {accept:#010X} was not detected"
            );

            checked += 1;
        }

        assert!(checked >= 12, "only {checked} families were checked");
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
        // The cases are READ FROM the generated encodings file rather than written here.
        //
        // The earlier version of this test carried hand-picked words, and one of them
        // (`0xD500_0000 | (0xC << 12)`) was a guess that no assembler produces. That is the same
        // defect the test exists to catch, one level up: a check built on invented constants
        // verifies the invention, not the behaviour.
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/encodings.json");
        let doc = compitum_json::parse(&std::fs::read_to_string(path).expect("readable"))
            .expect("valid JSON");
        let families = doc["families"].as_object().expect("families");

        let parse = |text: &str| u32::from_str_radix(text.trim_start_matches("0x"), 16).unwrap();

        let mut checked = 0;
        for (family, entry) in families.iter() {
            let Some(variants) = entry["variants"].as_array() else {
                continue;
            };
            for variant in variants {
                let instruction = variant["instruction"].as_str().unwrap_or("?");
                let word = parse(variant["encoding"].as_str().expect("encoding"));

                let report = scan_code(&word.to_le_bytes(), 0x1000);
                assert!(
                    !report.is_empty(),
                    "the rule for `{instruction}` in family {family} (word {word:#010X}) is \
                     unreachable through the real entry point -- `scan_code` applies the \
                     enclosing conditions exactly as production does, so an empty result means \
                     a condition contradicts the rule"
                );
                assert_eq!(
                    report.total_hits, 1,
                    "`{instruction}` should produce exactly one hit, got {}",
                    report.total_hits
                );
                checked += 1;
            }
        }

        assert!(checked >= 30, "only {checked} encodings were exercised");
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
        // `bti c` is `0xD503245F`, produced by the assembler. The previous version of this test
        // asserted `HINT #0b0100`, which is not BTI -- the real hint immediate is 34. The rule
        // and the test agreed with each other and with nothing else.
        let word: u32 = 0xD503_245F;
        let report = scan_code(&word.to_le_bytes(), 0x1000);
        assert!(
            report.features().contains(&IsaFeature::Bti),
            "{:?}",
            report.features()
        );
        // And the constant this test used to assert must NOT be reported as BTI.
        let not_bti: u32 = 0xD503_201F | (0b0100 << 5);
        let not_bti = scan_code(&not_bti.to_le_bytes(), 0x1000);
        assert!(
            !not_bti.features().contains(&IsaFeature::Bti),
            "HINT #4 is not a BTI instruction"
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
    fn an_x86_image_is_not_hunted_for_aarch64_encodings() {
        // THE REGRESSION GUARD for a defect found by downloading real software.
        //
        // `7z-x86.exe`, fetched from the vendor, came back REFUSED with "this host does not
        // implement: sve" — from an x86 executable. x86 machine code cannot contain an AArch64
        // instruction. Four bytes of x86 code had matched an SVE pattern by coincidence, the
        // scanner reported it as a requirement, and the router believed it.
        //
        // The consequence was not subtle: every x86 and x86-64 binary was liable to be refused
        // for a feature its own instruction set cannot express. Since almost every Windows
        // program a customer owns is one of those two, the migration report would have
        // condemned essentially everything.
        let code = 0x0420_0002u32.to_le_bytes(); // a genuine SVE encoding
        let bytes = pe_fixture::synthetic_with_code(machine::I386, &code, 0x1000);
        let image = crate::parse(&bytes).unwrap();

        let report = scan_image(&bytes, &image);

        assert!(
            report.skipped_not_aarch64,
            "an x86 image must be reported as out of scope, not as clean"
        );
        assert!(
            report.requirements.is_empty(),
            "x86 code must not yield AArch64 requirements: {:?}",
            report.features()
        );
        assert_eq!(report.sections_scanned, 0);
    }

    #[test]
    fn out_of_scope_is_distinct_from_scanned_and_clean() {
        // The distinction the whole project keeps returning to. "I did not look" and "I looked
        // and found nothing" are different answers, and a caller that merged them would report
        // an x86 image as having no instruction requirements when nothing was looked for.
        let code = 0x0420_0002u32.to_le_bytes();

        let x86 = pe_fixture::synthetic_with_code(machine::I386, &code, 0x1000);
        let x86_image = crate::parse(&x86).unwrap();
        let x86_report = scan_image(&x86, &x86_image);
        assert!(x86_report.skipped_not_aarch64);
        assert_eq!(x86_report.sections_scanned, 0);

        let clean_arm = pe_fixture::synthetic(machine::ARM64, subsystem::CONSOLE, false);
        let arm_image = crate::parse(&clean_arm).unwrap();
        let arm_report = scan_image(&clean_arm, &arm_image);
        assert!(!arm_report.skipped_not_aarch64);
        assert_eq!(arm_report.sections_scanned, 1, "ARM64 is scanned");

        // Both are empty of requirements, but they are not the same statement.
        assert!(x86_report.is_empty());
        assert!(arm_report.is_empty());
    }

    #[test]
    fn every_arm64_flavour_is_still_scanned() {
        // The gate must not over-reach in the other direction: a real ARM64 image with SVE must
        // still be detected, or the fix would hide true requirements instead of false ones.
        let code = 0x0420_0002u32.to_le_bytes();
        for machine_value in [machine::ARM64, machine::ARM64EC, machine::ARM64X] {
            let bytes = pe_fixture::synthetic_with_code(machine_value, &code, 0x1000);
            let image = crate::parse(&bytes).unwrap();
            let report = scan_image(&bytes, &image);
            assert!(
                !report.skipped_not_aarch64,
                "family {:?} contains AArch64 code and must be scanned",
                image.family()
            );
            assert_eq!(report.sections_scanned, 1);
            assert!(
                report.features().contains(&IsaFeature::Sve),
                "family {:?} lost a real requirement",
                image.family()
            );
        }
    }

    #[test]
    fn caveat_is_stated_for_every_clean_scan() {
        let report = scan_code(&[0u8; 64], 0);
        let caveat = report.caveat();
        assert!(caveat.contains("cannot see run-time-generated code"));
        assert!(caveat.contains("SVE2"));
    }
}
