//! The ARM64 instruction-set vocabulary.
//!
//! COMPITUM needs one shared language for two very different facts:
//!
//! * what a **binary requires** (extracted by `compitum-pe`), and
//! * what a **host provides** (extracted by [`crate::host`]).
//!
//! This module defines that language. Every feature here corresponds to something a
//! compiler can emit and something a CPU can or cannot execute. The distinction
//! matters because it is the entire basis of COMPITUM's routing decision: an ARM64
//! binary whose required features are a subset of the host's set runs **natively with
//! zero emulation**; one feature missing means a fault at the first such instruction.
//!
//! # Why this is novel
//!
//! Nothing in the ecosystem exposes this comparison. `file(1)` reports "ARM aarch64"
//! for every binary regardless of whether it needs SME matrix units that half of
//! ARM64 silicon does not implement.

use std::fmt;

/// A single ARM64 CPU feature.
///
/// Ordered roughly by introduction, which also makes the numeric discriminants a
/// stable, meaningful ordering for reports and Oracle records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IsaFeature {
    // ---- Baseline AArch64 --------------------------------------------------
    /// Floating point.
    Fp,
    /// Advanced SIMD (NEON).
    Asimd,

    // ---- Common extensions -------------------------------------------------
    /// AES instructions.
    Aes,
    /// Polynomial multiply long.
    Pmull,
    /// SHA-1 instructions.
    Sha1,
    /// SHA-2 instructions.
    Sha2,
    /// CRC-32 instructions.
    Crc32,
    /// Large System Extensions: atomic compare-and-swap in hardware.
    Lse,
    /// Half-precision floating point.
    Fp16,
    /// CPU identification registers accessible from userspace.
    Cpuid,
    /// Advanced SIMD reciprocal square root / distance.
    AsimdRdm,
    /// JavaScript float-to-int conversion.
    Jscvt,
    /// Floating-point complex multiply-accumulate.
    Fcma,
    /// Load-acquire / store-release, RCpc variant.
    Lrcpc,
    /// Dot product instructions (int8 dot).
    DotProd,
    /// Cryptographic hash: SHA-3.
    Sha3,
    /// Cryptographic hash: SM3.
    Sm3,
    /// Block cipher: SM4.
    Sm4,
    /// SHA-512 instructions.
    Sha512,
    /// Half-precision fused multiply-add.
    F16MulAdd,
    /// Data independent timing.
    Dit,
    /// Unprivileged store with cache clean (non-temporal stores).
    Uscat,
    /// Load-acquire RCpc with immediate.
    Ilrcpc,
    /// Flag manipulation instructions.
    FlagM,
    /// Speculative store bypass safe.
    Ssbs,
    /// Speculation barrier.
    Sb,
    /// Pointer authentication (address).
    PaAuth,
    /// Pointer authentication (generic).
    PaAuthGen,
    /// Flag manipulation v2.
    FlagM2,
    /// Floating-point rounding to integer instructions.
    Frint,
    /// Random number generation.
    Rng,
    /// Branch Target Identification — protects against JOP attacks.
    Bti,
    /// Enhanced counter virtualization.
    Ecv,
    /// Alternate floating-point behaviour.
    Afp,
    /// Rounding double-precision. (RPRES)
    Rpres,

    // ---- Scalable vectors --------------------------------------------------
    /// Scalable Vector Extension — variable-length SIMD.
    Sve,
    /// Scalable Vector Extension 2.
    Sve2,
    /// SVE AES.
    SveAes,
    /// SVE polynomial multiply.
    SvePmull,
    /// SVE bit permutation.
    SveBitPerm,
    /// SVE SHA-3.
    SveSha3,
    /// SVE SM4.
    SveSm4,
    /// SVE int8 matrix multiply.
    SveI8mm,
    /// SVE 32-bit float matrix multiply.
    SveF32mm,
    /// SVE 64-bit float matrix multiply.
    SveF64mm,
    /// SVE bfloat16.
    SveBf16,

    // ---- Matrix ------------------------------------------------------------
    /// Scalable Matrix Extension — outer-product matrix units.
    Sme,
    /// SME int16-to-int64.
    SmeI16i64,
    /// SME double-precision matrix.
    SmeF64f64,
    /// SME int8-to-int32.
    SmeI8i32,
    /// SME fp16-to-fp32.
    SmeF16f32,
    /// SME bf16-to-fp32.
    SmeB16f32,
    /// SME fp32 outer product.
    SmeF32f32,
    /// SME full A64 instruction set inside streaming mode.
    SmeFa64,

    // ---- Memory tagging ----------------------------------------------------
    /// Memory Tagging Extension — hardware memory safety.
    Mte,
    /// MTE asymmetric / store-only variant.
    Mte3,

    // ---- Misc --------------------------------------------------------------
    /// Int8 matrix multiplication (the non-SVE form, `HWCAP2` bit 13).
    ///
    /// Distinct from [`IsaFeature::SveI8mm`]: this is the plain Advanced SIMD matrix
    /// multiply that most contemporary phone and server cores implement.
    I8mm,
    /// Bfloat16 arithmetic.
    Bf16,
    /// Data gathering hint.
    Dgh,
    /// Data cache clean to point of persistence.
    DcPop,
    /// DcPop double-word.
    DcPopDp,
    /// Wait for event with timeout.
    Wfxt,
    /// Virtualization extensions exposed to userspace.
    Virt,
}

impl IsaFeature {
    /// Every feature COMPITUM knows about, in canonical order.
    pub const ALL: &'static [IsaFeature] = &[
        IsaFeature::Fp, IsaFeature::Asimd,
        IsaFeature::Aes, IsaFeature::Pmull, IsaFeature::Sha1, IsaFeature::Sha2,
        IsaFeature::Crc32, IsaFeature::Lse, IsaFeature::Fp16, IsaFeature::Cpuid,
        IsaFeature::AsimdRdm, IsaFeature::Jscvt, IsaFeature::Fcma, IsaFeature::Lrcpc,
        IsaFeature::DotProd, IsaFeature::Sha3, IsaFeature::Sm3, IsaFeature::Sm4,
        IsaFeature::Sha512, IsaFeature::F16MulAdd, IsaFeature::Dit, IsaFeature::Uscat,
        IsaFeature::Ilrcpc, IsaFeature::FlagM, IsaFeature::Ssbs, IsaFeature::Sb,
        IsaFeature::PaAuth, IsaFeature::PaAuthGen, IsaFeature::FlagM2, IsaFeature::Frint,
        IsaFeature::Rng, IsaFeature::Bti, IsaFeature::Ecv, IsaFeature::Afp, IsaFeature::Rpres,
        IsaFeature::Sve, IsaFeature::Sve2, IsaFeature::SveAes, IsaFeature::SvePmull,
        IsaFeature::SveBitPerm, IsaFeature::SveSha3, IsaFeature::SveSm4, IsaFeature::SveI8mm,
        IsaFeature::SveF32mm, IsaFeature::SveF64mm, IsaFeature::SveBf16,
        IsaFeature::Sme, IsaFeature::SmeI16i64, IsaFeature::SmeF64f64, IsaFeature::SmeI8i32,
        IsaFeature::SmeF16f32, IsaFeature::SmeB16f32, IsaFeature::SmeF32f32, IsaFeature::SmeFa64,
        IsaFeature::Mte, IsaFeature::Mte3,
        IsaFeature::I8mm, IsaFeature::Bf16, IsaFeature::Dgh,
        IsaFeature::DcPop, IsaFeature::DcPopDp,
        IsaFeature::Wfxt, IsaFeature::Virt,
    ];

    /// The stable machine identifier, used in JSON and Oracle records.
    ///
    /// These strings are **protocol** and must never change or be translated.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            IsaFeature::Fp => "fp",
            IsaFeature::Asimd => "asimd",
            IsaFeature::Aes => "aes",
            IsaFeature::Pmull => "pmull",
            IsaFeature::Sha1 => "sha1",
            IsaFeature::Sha2 => "sha2",
            IsaFeature::Crc32 => "crc32",
            IsaFeature::Lse => "lse",
            IsaFeature::Fp16 => "fp16",
            IsaFeature::Cpuid => "cpuid",
            IsaFeature::AsimdRdm => "asimdrdm",
            IsaFeature::Jscvt => "jscvt",
            IsaFeature::Fcma => "fcma",
            IsaFeature::Lrcpc => "lrcpc",
            IsaFeature::DotProd => "dotprod",
            IsaFeature::Sha3 => "sha3",
            IsaFeature::Sm3 => "sm3",
            IsaFeature::Sm4 => "sm4",
            IsaFeature::Sha512 => "sha512",
            IsaFeature::F16MulAdd => "fhm",
            IsaFeature::Dit => "dit",
            IsaFeature::Uscat => "uscat",
            IsaFeature::Ilrcpc => "ilrcpc",
            IsaFeature::FlagM => "flagm",
            IsaFeature::Ssbs => "ssbs",
            IsaFeature::Sb => "sb",
            IsaFeature::PaAuth => "paca",
            IsaFeature::PaAuthGen => "pacg",
            IsaFeature::FlagM2 => "flagm2",
            IsaFeature::Frint => "frint",
            IsaFeature::Rng => "rng",
            IsaFeature::Bti => "bti",
            IsaFeature::Ecv => "ecv",
            IsaFeature::Afp => "afp",
            IsaFeature::Rpres => "rpres",
            IsaFeature::Sve => "sve",
            IsaFeature::Sve2 => "sve2",
            IsaFeature::SveAes => "sveaes",
            IsaFeature::SvePmull => "svepmull",
            IsaFeature::SveBitPerm => "svebitperm",
            IsaFeature::SveSha3 => "svesha3",
            IsaFeature::SveSm4 => "svesm4",
            IsaFeature::SveI8mm => "svei8mm",
            IsaFeature::SveF32mm => "svef32mm",
            IsaFeature::SveF64mm => "svef64mm",
            IsaFeature::SveBf16 => "svebf16",
            IsaFeature::Sme => "sme",
            IsaFeature::SmeI16i64 => "sme_i16i64",
            IsaFeature::SmeF64f64 => "sme_f64f64",
            IsaFeature::SmeI8i32 => "sme_i8i32",
            IsaFeature::SmeF16f32 => "sme_f16f32",
            IsaFeature::SmeB16f32 => "sme_b16f32",
            IsaFeature::SmeF32f32 => "sme_f32f32",
            IsaFeature::SmeFa64 => "sme_fa64",
            IsaFeature::Mte => "mte",
            IsaFeature::Mte3 => "mte3",
            IsaFeature::I8mm => "i8mm",
            IsaFeature::Bf16 => "bf16",
            IsaFeature::Dgh => "dgh",
            IsaFeature::DcPop => "dcpop",
            IsaFeature::DcPopDp => "dcpodp",
            IsaFeature::Wfxt => "wfxt",
            IsaFeature::Virt => "virt",
        }
    }

    /// The English human-readable name, used in reports.
    ///
    /// Returns a translation-catalog key; callers pass it through `compitum-i18n`.
    #[must_use]
    pub fn message_key(self) -> &'static str {
        match self {
            IsaFeature::Sve => "feature.sve",
            IsaFeature::Sve2 => "feature.sve2",
            IsaFeature::Sme => "feature.sme",
            IsaFeature::Mte => "feature.mte",
            IsaFeature::Bf16 => "feature.bf16",
            IsaFeature::DotProd => "feature.dotprod",
            IsaFeature::Bti => "feature.bti",
            IsaFeature::Lse => "feature.lse",
            IsaFeature::Crc32 => "feature.crc32",
            IsaFeature::Fp16 => "feature.fp16",
            IsaFeature::Aes => "feature.aes",
            IsaFeature::Sha2 => "feature.sha2",
            IsaFeature::Rng => "feature.rng",
            IsaFeature::Sb => "feature.sb",
            IsaFeature::Ssbs => "feature.ssbs",
            // Features without a dedicated catalog entry fall back to their id.
            _ => "",
        }
    }

    /// A short English description independent of the translation catalog.
    ///
    /// This is the technical gloss used in `--verbose` output and documentation where
    /// precision matters more than localization.
    #[must_use]
    pub fn technical_note(self) -> &'static str {
        match self {
            IsaFeature::Fp => "AArch64 floating point (mandatory baseline)",
            IsaFeature::Asimd => "AArch64 Advanced SIMD / NEON (mandatory baseline)",
            IsaFeature::Aes => "AES round instructions",
            IsaFeature::Pmull => "Polynomial multiply long",
            IsaFeature::Sha1 => "SHA-1 accelerated instructions",
            IsaFeature::Sha2 => "SHA-256 accelerated instructions",
            IsaFeature::Crc32 => "CRC-32 checksum instructions",
            IsaFeature::Lse => "Hardware atomics (LSE); absence forces LL/SC fallback",
            IsaFeature::Fp16 => "Half-precision (f16) floating point",
            IsaFeature::Cpuid => "Userspace-readable ID registers",
            IsaFeature::AsimdRdm => "SIMD rounding double multiply",
            IsaFeature::Jscvt => "Float to integer conversion (JS semantics)",
            IsaFeature::Fcma => "Complex multiply-accumulate",
            IsaFeature::Lrcpc => "RCpc load-acquire / store-release",
            IsaFeature::DotProd => "Int8 dot product",
            IsaFeature::Sha3 => "SHA-3 instructions",
            IsaFeature::Sm3 => "SM3 hash instructions",
            IsaFeature::Sm4 => "SM4 block cipher instructions",
            IsaFeature::Sha512 => "SHA-512 accelerated instructions",
            IsaFeature::F16MulAdd => "f16 fused multiply-add",
            IsaFeature::Dit => "Data independent timing",
            IsaFeature::Uscat => "Non-temporal store",
            IsaFeature::Ilrcpc => "Load-acquire RCpc with immediate",
            IsaFeature::FlagM => "Condition flag manipulation",
            IsaFeature::Ssbs => "Speculative store bypass safe",
            IsaFeature::Sb => "Speculation barrier instruction",
            IsaFeature::PaAuth => "Pointer authentication (address key)",
            IsaFeature::PaAuthGen => "Pointer authentication (generic key)",
            IsaFeature::FlagM2 => "Condition flag manipulation v2",
            IsaFeature::Frint => "FP rounding to integer",
            IsaFeature::Rng => "Hardware random number generation",
            IsaFeature::Bti => "Branch Target Identification",
            IsaFeature::Ecv => "Enhanced counter virtualization",
            IsaFeature::Afp => "Alternate floating-point behaviour",
            IsaFeature::Rpres => "Reciprocal estimate precision",
            IsaFeature::Sve => "Scalable vector extension (variable length SIMD)",
            IsaFeature::Sve2 => "Scalable vector extension 2",
            IsaFeature::SveAes => "SVE AES",
            IsaFeature::SvePmull => "SVE polynomial multiply long",
            IsaFeature::SveBitPerm => "SVE bit permutation",
            IsaFeature::SveSha3 => "SVE SHA-3",
            IsaFeature::SveSm4 => "SVE SM4",
            IsaFeature::SveI8mm => "SVE int8 matrix multiply",
            IsaFeature::SveF32mm => "SVE fp32 matrix multiply",
            IsaFeature::SveF64mm => "SVE fp64 matrix multiply",
            IsaFeature::SveBf16 => "SVE bfloat16",
            IsaFeature::Sme => "Scalable matrix extension (outer-product matrix units)",
            IsaFeature::SmeI16i64 => "SME int16 -> int64",
            IsaFeature::SmeF64f64 => "SME fp64 matrix ops",
            IsaFeature::SmeI8i32 => "SME int8 -> int32",
            IsaFeature::SmeF16f32 => "SME fp16 -> fp32",
            IsaFeature::SmeB16f32 => "SME bf16 -> fp32",
            IsaFeature::SmeF32f32 => "SME fp32 outer product",
            IsaFeature::SmeFa64 => "SME full A64 instruction set in streaming mode",
            IsaFeature::Mte => "Memory tagging extension",
            IsaFeature::Mte3 => "Memory tagging, store-only variant",
            IsaFeature::I8mm => "Int8 matrix multiply (Advanced SIMD form)",
            IsaFeature::Bf16 => "Bfloat16 arithmetic",
            IsaFeature::Dgh => "Data gathering hint",
            IsaFeature::DcPop => "Cache clean to point of persistence",
            IsaFeature::DcPopDp => "DcPop double-word variant",
            IsaFeature::Wfxt => "Wait-for-event with timeout",
            IsaFeature::Virt => "Virtualization exposed to userspace",
        }
    }

    /// Parses a feature from its stable id.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|f| f.id() == id)
    }

    /// Returns `true` when this feature is part of the mandatory AArch64 baseline.
    ///
    /// Baseline features are guaranteed by the architecture and never the cause of a
    /// compatibility failure; reporting them separately keeps the interesting gaps
    /// visible.
    #[must_use]
    pub fn is_baseline(self) -> bool {
        matches!(self, IsaFeature::Fp | IsaFeature::Asimd)
    }
}

impl fmt::Display for IsaFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// A set of [`IsaFeature`] values, stored as a bitmask.
///
/// The mask is a `u128`, comfortably larger than the current feature count, so new
/// features can be added without changing the representation. Bit indices are derived
/// from the position of a feature in [`IsaFeature::ALL`], which makes them stable as
/// long as features are appended rather than reordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FeatureSet(u128);

impl FeatureSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        FeatureSet(0)
    }

    /// A set containing every known feature.
    #[must_use]
    pub fn all() -> Self {
        let mut set = FeatureSet::new();
        for feature in IsaFeature::ALL {
            set.insert(*feature);
        }
        set
    }

    /// Returns the bit index of a feature.
    fn bit_of(feature: IsaFeature) -> u32 {
        IsaFeature::ALL
            .iter()
            .position(|f| *f == feature)
            .unwrap_or(0) as u32
    }

    /// Adds a feature to the set.
    pub fn insert(&mut self, feature: IsaFeature) {
        self.0 |= 1u128 << Self::bit_of(feature);
    }

    /// Removes a feature from the set.
    pub fn remove(&mut self, feature: IsaFeature) {
        self.0 &= !(1u128 << Self::bit_of(feature));
    }

    /// Returns `true` when the set contains the feature.
    #[must_use]
    pub fn contains(self, feature: IsaFeature) -> bool {
        self.0 & (1u128 << Self::bit_of(feature)) != 0
    }

    /// Returns a set with `feature` added (builder style).
    #[must_use]
    pub fn with(mut self, feature: IsaFeature) -> Self {
        self.insert(feature);
        self
    }

    /// The union of two sets.
    #[must_use]
    pub fn union(self, other: Self) -> Self {
        FeatureSet(self.0 | other.0)
    }

    /// The intersection of two sets.
    #[must_use]
    pub fn intersection(self, other: Self) -> Self {
        FeatureSet(self.0 & other.0)
    }

    /// The features in `self` that are absent from `other`.
    ///
    /// This is the single most important operation in COMPITUM: it answers
    /// *"what does the binary need that this host cannot do?"*
    #[must_use]
    pub fn difference(self, other: Self) -> Self {
        FeatureSet(self.0 & !other.0)
    }

    /// Returns `true` when every feature of `self` is present in `other`.
    #[must_use]
    pub fn is_subset_of(self, other: Self) -> bool {
        self.difference(other).is_empty()
    }

    /// Returns `true` when the set holds no features.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Number of features in the set.
    #[must_use]
    pub fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Iterates over the contained features in canonical order.
    pub fn iter(self) -> impl Iterator<Item = IsaFeature> {
        IsaFeature::ALL.iter().copied().filter(move |f| self.contains(*f))
    }

    /// Returns the contained features as stable ids, in canonical order.
    #[must_use]
    pub fn ids(self) -> Vec<&'static str> {
        self.iter().map(IsaFeature::id).collect()
    }
}

impl FromIterator<IsaFeature> for FeatureSet {
    fn from_iter<T: IntoIterator<Item = IsaFeature>>(iter: T) -> Self {
        let mut set = FeatureSet::new();
        for feature in iter {
            set.insert(feature);
        }
        set
    }
}

impl fmt::Display for FeatureSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ids = self.ids();
        if ids.is_empty() {
            return f.write_str("(none)");
        }
        f.write_str(&ids.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_features_have_unique_ids() {
        let mut seen = std::collections::BTreeSet::new();
        for feature in IsaFeature::ALL {
            assert!(seen.insert(feature.id()), "duplicate id: {}", feature.id());
        }
    }

    #[test]
    fn feature_ids_round_trip() {
        for feature in IsaFeature::ALL {
            assert_eq!(IsaFeature::from_id(feature.id()), Some(*feature));
        }
        assert_eq!(IsaFeature::from_id("nope"), None);
    }

    #[test]
    fn empty_set_is_empty() {
        let set = FeatureSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert_eq!(set.to_string(), "(none)");
    }

    #[test]
    fn insert_and_contains() {
        let set = FeatureSet::new().with(IsaFeature::Sve2).with(IsaFeature::Sme);
        assert!(set.contains(IsaFeature::Sve2));
        assert!(set.contains(IsaFeature::Sme));
        assert!(!set.contains(IsaFeature::Mte));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn all_set_contains_everything() {
        let set = FeatureSet::all();
        assert_eq!(set.len(), IsaFeature::ALL.len());
        for feature in IsaFeature::ALL {
            assert!(set.contains(*feature));
        }
    }

    #[test]
    fn subset_check_is_the_core_decision() {
        let host = FeatureSet::new()
            .with(IsaFeature::Sve2)
            .with(IsaFeature::Sme)
            .with(IsaFeature::DotProd);
        let pure_arm64 = FeatureSet::new().with(IsaFeature::DotProd);
        let needs_sme = FeatureSet::new().with(IsaFeature::Sme);
        let needs_mte = FeatureSet::new().with(IsaFeature::Mte);

        assert!(pure_arm64.is_subset_of(host));
        assert!(needs_sme.is_subset_of(host));
        assert!(!needs_mte.is_subset_of(host));
    }

    #[test]
    fn difference_reports_missing_features() {
        let host = FeatureSet::new().with(IsaFeature::Sve2);
        let needs = FeatureSet::new()
            .with(IsaFeature::Sve2)
            .with(IsaFeature::Sme)
            .with(IsaFeature::Mte);
        let missing = needs.difference(host);
        assert_eq!(missing.ids(), vec!["sme", "mte"]);
    }

    #[test]
    fn intersection_works() {
        let a = FeatureSet::new().with(IsaFeature::Sve2).with(IsaFeature::Sme);
        let b = FeatureSet::new().with(IsaFeature::Sve2).with(IsaFeature::Mte);
        assert_eq!(a.intersection(b).ids(), vec!["sve2"]);
    }

    #[test]
    fn remove_works() {
        let mut set = FeatureSet::new().with(IsaFeature::Sve2).with(IsaFeature::Sme);
        set.remove(IsaFeature::Sve2);
        assert_eq!(set.ids(), vec!["sme"]);
    }

    #[test]
    fn baseline_features_are_identified() {
        assert!(IsaFeature::Fp.is_baseline());
        assert!(IsaFeature::Asimd.is_baseline());
        assert!(!IsaFeature::Sve2.is_baseline());
    }

    #[test]
    fn from_iterator_builds_set() {
        let set: FeatureSet = [IsaFeature::Sve, IsaFeature::Sve2].into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn display_lists_ids_in_canonical_order() {
        let set = FeatureSet::new().with(IsaFeature::Mte).with(IsaFeature::Sve);
        assert_eq!(set.to_string(), "sve, mte");
    }

    #[test]
    fn every_non_baseline_feature_has_a_technical_note() {
        for feature in IsaFeature::ALL {
            assert!(
                !feature.technical_note().is_empty(),
                "{} has no technical note",
                feature.id()
            );
        }
    }
}
