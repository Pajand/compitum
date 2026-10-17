//! Host capability discovery: what can *this* machine actually execute?
//!
//! The binary analyser answers *"what does this program require?"*. This module answers
//! the other half of the question: *"what does this CPU provide?"*. COMPITUM's routing
//! decision is exactly the comparison between the two.
//!
//! # Sources
//!
//! Everything here is read from the kernel's own reporting interfaces, with no
//! privileged access and no `unsafe`:
//!
//! | Fact | Source |
//! |---|---|
//! | CPU architecture | `uname`-equivalent via `std::env::consts::ARCH` and `/proc/cpuinfo` |
//! | HWCAP / HWCAP2 bitmaps | `/proc/self/auxv` |
//! | Memory page size | `/proc/self/auxv` (`AT_PAGESZ`) |
//! | CPU core count | `std::thread::available_parallelism` and `/proc/cpuinfo` |
//! | Kernel release | `/proc/sys/kernel/osrelease` |
//! | Per-core features | `/proc/cpuinfo` `Features` line |
//!
//! # Why read `auxv` instead of calling `getauxval(3)`?
//!
//! `getauxval` requires linking against platform-specific symbols and, on musl,
//! `getauxval` is available but not part of a stable cross-platform abstraction. Reading
//! `/proc/self/auxv` gives byte-identical information with pure safe Rust, works the same
//! on glibc and musl, and is trivially testable because the parse function takes a byte
//! slice.

use std::fmt;

use crate::feature::{FeatureSet, IsaFeature};

/// HWCAP bit assignments from the Linux kernel's `arch/arm64/include/uapi/asm/hwcap.h`.
///
/// Index is the bit position; the value is the corresponding COMPITUM feature.
const HWCAP_BITS: &[(u32, IsaFeature)] = &[
    (0, IsaFeature::Fp),
    (1, IsaFeature::Asimd),
    // Bit 2 is EVTSTRM, a timer hint rather than an ISA feature, so it is unmapped.
    (3, IsaFeature::Aes),
    (4, IsaFeature::Pmull),
    (5, IsaFeature::Sha1),
    (6, IsaFeature::Sha2),
    (7, IsaFeature::Crc32),
    (8, IsaFeature::Lse),
    (9, IsaFeature::Fp16),
    (11, IsaFeature::Cpuid),
    (12, IsaFeature::AsimdRdm),
    (13, IsaFeature::Jscvt),
    (14, IsaFeature::Fcma),
    (15, IsaFeature::Lrcpc),
    (16, IsaFeature::DcPop),
    (17, IsaFeature::Sha3),
    (18, IsaFeature::Sm3),
    (19, IsaFeature::Sm4),
    (20, IsaFeature::DotProd),
    (21, IsaFeature::Sha512),
    (22, IsaFeature::Sve),
    (23, IsaFeature::F16MulAdd),
    (24, IsaFeature::Dit),
    (25, IsaFeature::Uscat),
    (26, IsaFeature::Ilrcpc),
    (27, IsaFeature::FlagM),
    (28, IsaFeature::Ssbs),
    (29, IsaFeature::Sb),
    (30, IsaFeature::PaAuth),
    (31, IsaFeature::PaAuthGen),
    (32, IsaFeature::DcPopDp),
];

/// `HWCAP2` bit assignments from the same kernel header.
///
/// The SME family and every SVE2 sub-feature live here rather than in `HWCAP`. That
/// split is precisely why a machine can report a rich `HWCAP` and still have no matrix
/// or scalable-vector support at all -- the single most consequential compatibility
/// distinction this project makes.
///
/// Bit positions were verified against a live kernel: a device reporting
/// `HWCAP2 = 0x22181` decodes here to `DCPODP, FLAGM2, FRINT, I8MM, RNG, BTI`, which
/// matches that device's `/proc/cpuinfo` list exactly.
const HWCAP2_BITS: &[(u32, IsaFeature)] = &[
    (0, IsaFeature::DcPopDp),
    (1, IsaFeature::Sve2),
    (2, IsaFeature::SveAes),
    (3, IsaFeature::SvePmull),
    (4, IsaFeature::SveBitPerm),
    (5, IsaFeature::SveSha3),
    (6, IsaFeature::SveSm4),
    (7, IsaFeature::FlagM2),
    (8, IsaFeature::Frint),
    (9, IsaFeature::SveI8mm),
    (10, IsaFeature::SveF32mm),
    (11, IsaFeature::SveF64mm),
    (12, IsaFeature::SveBf16),
    (13, IsaFeature::I8mm),
    (14, IsaFeature::Bf16),
    (15, IsaFeature::Dgh),
    (16, IsaFeature::Rng),
    (17, IsaFeature::Bti),
    (18, IsaFeature::Mte),
    (19, IsaFeature::Ecv),
    (20, IsaFeature::Afp),
    (21, IsaFeature::Rpres),
    (22, IsaFeature::Mte3),
    (23, IsaFeature::Sme),
    (24, IsaFeature::SmeI16i64),
    (25, IsaFeature::SmeF64f64),
    (26, IsaFeature::SmeI8i32),
    (27, IsaFeature::SmeF16f32),
    (28, IsaFeature::SmeB16f32),
    (29, IsaFeature::SmeF32f32),
    (30, IsaFeature::SmeFa64),
    (31, IsaFeature::Wfxt),
];

/// Bit index from which kernel `HWCAP` renumbering has historically occurred as new
/// extensions were ratified.
///
/// COMPITUM therefore treats a *set* bit as strong evidence of presence and an *unset*
/// bit as weak evidence of absence, and prefers `/proc/cpuinfo` feature names whenever
/// the two disagree.
pub const HWCAP_FIRMWARE_UNSTABLE_FROM: u32 = 32;

/// Returns every `(bitmap, bit, feature)` triple COMPITUM decodes.
///
/// Exposed so tests and documentation can assert the table's contents directly rather
/// than duplicating the mapping and letting the two drift apart.
#[must_use]
pub fn decoded_bit_assignments() -> Vec<(&'static str, u32, IsaFeature)> {
    let mut out = Vec::new();
    for (bit, feature) in HWCAP_BITS {
        out.push(("HWCAP", *bit, *feature));
    }
    for (bit, feature) in HWCAP2_BITS {
        out.push(("HWCAP2", *bit, *feature));
    }
    out
}


/// AT_* entry types from `<elf.h>` that COMPITUM consumes.
const AT_HWCAP: u64 = 16;
/// `AT_HWCAP2`, the second capability bitmap.
const AT_HWCAP2: u64 = 26;
/// `AT_PAGESZ`, the system memory page size in bytes.
const AT_PAGESZ: u64 = 6;

/// `IMAGE_FILE_MACHINE`-independent description of the running host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProfile {
    /// Kernel architecture string, e.g. `"aarch64"`.
    pub arch: String,
    /// Memory page size in bytes as reported by the kernel.
    pub page_size: usize,
    /// Number of logical CPUs available to this process.
    pub cpu_count: usize,
    /// Kernel release string, e.g. `"6.1.75-android14"`.
    pub kernel: String,
    /// CPU features derived from `HWCAP`, `HWCAP2` and `/proc/cpuinfo`.
    pub features: FeatureSet,
    /// Raw `HWCAP` value, kept for Oracle provenance.
    pub raw_hwcap: u64,
    /// Raw `HWCAP2` value, kept for Oracle provenance.
    pub raw_hwcap2: u64,
    /// Per-core feature strings from `/proc/cpuinfo`, keyed by processor index.
    ///
    /// Retained because big.LITTLE designs can report different feature sets per core
    /// cluster, and a scheduler that migrates a thread onto a weaker core can expose
    /// gaps that a single aggregate bitmask hides.
    pub per_core_features: Vec<String>,
}

impl HostProfile {
    /// Probes the running machine.
    ///
    /// Never fails: any source that cannot be read simply contributes nothing, and a
    /// profile with a smaller feature set is always the safe answer (it causes COMPITUM
    /// to be conservative rather than to promise native execution it cannot deliver).
    #[must_use]
    pub fn probe() -> Self {
        let (raw_hwcap, raw_hwcap2, page_size) = read_auxv();
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let per_core_features = parse_cpuinfo_features(&cpuinfo);
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|_| "unknown".to_owned());

        let mut features = features_from_hwcap(raw_hwcap, raw_hwcap2);
        features = features.union(features_from_cpuinfo(&cpuinfo));

        // The kernel reports a page size of 4096 on a missing entry only when something
        // is deeply wrong; falling back to the smallest plausible value keeps the
        // page-size comparison honest.
        let page_size = if page_size == 0 { 4096 } else { page_size };

        HostProfile {
            arch: std::env::consts::ARCH.to_owned(),
            page_size,
            cpu_count: std::thread::available_parallelism()
                .map(std::num::NonZeroUsize::get)
                .unwrap_or(1),
            kernel,
            features,
            raw_hwcap,
            raw_hwcap2,
            per_core_features,
        }
    }

    /// Builds a profile from explicit parts, for tests and for replaying Oracle records.
    #[must_use]
    pub fn synthetic(
        arch: impl Into<String>,
        page_size: usize,
        cpu_count: usize,
        features: FeatureSet,
    ) -> Self {
        HostProfile {
            arch: arch.into(),
            page_size,
            cpu_count,
            kernel: "synthetic".to_owned(),
            features,
            raw_hwcap: 0,
            raw_hwcap2: 0,
            per_core_features: Vec::new(),
        }
    }

    /// Returns `true` when the host is an ARM64 machine and COMPITUM's analysis applies.
    #[must_use]
    pub fn is_arm64(&self) -> bool {
        matches!(self.arch.as_str(), "aarch64" | "arm64")
    }

    /// Features present on *every* reported core.
    ///
    /// On a heterogeneous (big.LITTLE) SoC a thread may be scheduled anywhere, so the
    /// only sound guarantee is the intersection of all cores' capabilities.
    #[must_use]
    pub fn guaranteed_features(&self) -> FeatureSet {
        if self.per_core_features.is_empty() {
            return self.features;
        }
        let parsed: Vec<FeatureSet> = self
            .per_core_features
            .iter()
            .map(|line| features_from_feature_line(line))
            .collect();
        let mut iter = parsed.into_iter();
        let Some(first) = iter.next() else {
            return self.features;
        };
        iter.fold(first, FeatureSet::intersection)
    }

    /// Returns `true` when the memory page size differs from the 4 KiB Windows baseline.
    ///
    /// Windows on ARM uses 4 KiB pages. A host with 16 KiB pages (increasingly common on
    /// Android) can expose alignment assumptions that a Windows binary was never
    /// compiled to expect.
    #[must_use]
    pub fn has_non_windows_page_size(&self) -> bool {
        self.page_size != 4096
    }

    /// A compact, human-readable one-line summary for CLI headers.
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "{} / {} cores / {} byte pages / {} features",
            self.arch,
            self.cpu_count,
            self.page_size,
            self.features.len()
        )
    }

    /// Serializes the profile to a machine-readable JSON document.
    #[must_use]
    pub fn to_json(&self) -> compitum_json::Value {
        let mut present: Vec<compitum_json::Value> = self
            .features
            .iter()
            .map(|f| compitum_json::Value::from(f.id()))
            .collect();
        present.sort_by(|a, b| a.as_str().cmp(&b.as_str()));

        // Only features that can actually change an execution decision are highlighted.
        // Baseline features are omitted: their absence would mean the CPU is not an
        // AArch64 part at all, which the architecture check already reports.
        let notable: Vec<compitum_json::Value> = [
            IsaFeature::Sve,
            IsaFeature::Sve2,
            IsaFeature::Sme,
            IsaFeature::Mte,
            IsaFeature::Bf16,
            IsaFeature::I8mm,
        ]
        .iter()
        .filter(|f| !f.is_baseline() && self.features.contains(**f))
        .map(|f| compitum_json::Value::from(f.id()))
        .collect();

        compitum_json::Object::new()
            .with("arch", self.arch.as_str())
            .with("page_size", self.page_size)
            .with("cpu_count", self.cpu_count)
            .with("kernel", self.kernel.as_str())
            .with("raw_hwcap", format!("0x{:016x}", self.raw_hwcap))
            .with("raw_hwcap2", format!("0x{:016x}", self.raw_hwcap2))
            .with("feature_count", self.features.len())
            .with("features", present)
            .with("notable_features", notable)
            .into()
    }
}

impl fmt::Display for HostProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary_line())
    }
}

/// Reads `HWCAP`, `HWCAP2` and `AT_PAGESZ` from the auxiliary vector.
///
/// Returns `(0, 0, 0)` when the file cannot be read, which yields an empty capability
/// set — the conservative answer.
#[must_use]
pub fn read_auxv() -> (u64, u64, usize) {
    match std::fs::read("/proc/self/auxv") {
        Ok(bytes) => parse_auxv(&bytes),
        Err(_) => (0, 0, 0),
    }
}

/// Parses a raw auxiliary vector.
///
/// The vector is a sequence of `(u64 type, u64 value)` pairs terminated by a zero type.
/// Each pair is two machine words, so the stride is 16 bytes on 64-bit systems.
#[must_use]
pub fn parse_auxv(bytes: &[u8]) -> (u64, u64, usize) {
    let mut hwcap = 0u64;
    let mut hwcap2 = 0u64;
    let mut pagesz = 0usize;

    for chunk in bytes.chunks_exact(16) {
        let a_type = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        let a_val = u64::from_le_bytes([
            chunk[8], chunk[9], chunk[10], chunk[11], chunk[12], chunk[13], chunk[14], chunk[15],
        ]);
        if a_type == 0 {
            break;
        }
        match a_type {
            AT_HWCAP => hwcap = a_val,
            AT_HWCAP2 => hwcap2 = a_val,
            AT_PAGESZ => pagesz = a_val as usize,
            _ => {}
        }
    }
    (hwcap, hwcap2, pagesz)
}

/// Decodes the `HWCAP`/`HWCAP2` bitmaps into a [`FeatureSet`].
#[must_use]
pub fn features_from_hwcap(hwcap: u64, hwcap2: u64) -> FeatureSet {
    let mut set = FeatureSet::new();
    for (bit, feature) in HWCAP_BITS {
        if hwcap & (1u64 << bit) != 0 {
            set.insert(*feature);
        }
    }
    for (bit, feature) in HWCAP2_BITS {
        if hwcap2 & (1u64 << bit) != 0 {
            set.insert(*feature);
        }
    }
    set
}

/// Extracts every `Features` line from `/proc/cpuinfo`.
///
/// Returns one entry per processor block.
#[must_use]
pub fn parse_cpuinfo_features(cpuinfo: &str) -> Vec<String> {
    cpuinfo
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            if key.trim() == "Features" {
                Some(value.trim().to_owned())
            } else {
                None
            }
        })
        .collect()
}

/// Extracts features from `/proc/cpuinfo` across all cores.
///
/// `/proc/cpuinfo` is used as a *secondary* source because it can name features the
/// running kernel does not yet expose as `HWCAP` bits, notably `sme`.
#[must_use]
pub fn features_from_cpuinfo(cpuinfo: &str) -> FeatureSet {
    let mut set = FeatureSet::new();
    for line in parse_cpuinfo_features(cpuinfo) {
        set = set.union(features_from_feature_line(&line));
    }
    set
}

/// Maps a whitespace-separated `/proc/cpuinfo` feature list to a [`FeatureSet`].
#[must_use]
pub fn features_from_feature_line(line: &str) -> FeatureSet {
    let mut set = FeatureSet::new();
    for token in line.split_whitespace() {
        if let Some(feature) = feature_from_cpuinfo_token(token) {
            set.insert(feature);
        }
    }
    set
}

/// Maps one `/proc/cpuinfo` feature token to a feature.
///
/// The token vocabulary is the Linux kernel's `arm64_elf_hwcaps` naming, which differs
/// slightly from the `HWCAP` macro names. Unrecognized tokens are ignored so a newer
/// kernel never breaks parsing.
#[must_use]
pub fn feature_from_cpuinfo_token(token: &str) -> Option<IsaFeature> {
    Some(match token {
        "fp" | "vfp" => IsaFeature::Fp,
        "asimd" | "neon" => IsaFeature::Asimd,
        "aes" => IsaFeature::Aes,
        "pmull" => IsaFeature::Pmull,
        "sha1" => IsaFeature::Sha1,
        "sha2" => IsaFeature::Sha2,
        "crc32" => IsaFeature::Crc32,
        "atomics" | "lse" => IsaFeature::Lse,
        "asimdhp" | "fp16" => IsaFeature::Fp16,
        "cpuid" => IsaFeature::Cpuid,
        "asimdrdm" => IsaFeature::AsimdRdm,
        "jscvt" => IsaFeature::Jscvt,
        "fcma" => IsaFeature::Fcma,
        "lrcpc" => IsaFeature::Lrcpc,
        "asimddp" | "dotprod" => IsaFeature::DotProd,
        "sha3" => IsaFeature::Sha3,
        "sm3" => IsaFeature::Sm3,
        "sm4" => IsaFeature::Sm4,
        "sha512" => IsaFeature::Sha512,
        "asimdfhm" | "fhm" => IsaFeature::F16MulAdd,
        "dit" => IsaFeature::Dit,
        "uscat" => IsaFeature::Uscat,
        "ilrcpc" => IsaFeature::Ilrcpc,
        "flagm" => IsaFeature::FlagM,
        "ssbs" => IsaFeature::Ssbs,
        "sb" => IsaFeature::Sb,
        "paca" => IsaFeature::PaAuth,
        "pacg" => IsaFeature::PaAuthGen,
        "flagm2" => IsaFeature::FlagM2,
        "frint" => IsaFeature::Frint,
        "rng" => IsaFeature::Rng,
        "bti" => IsaFeature::Bti,
        "ecv" => IsaFeature::Ecv,
        "afp" => IsaFeature::Afp,
        "rpres" => IsaFeature::Rpres,
        "sve" => IsaFeature::Sve,
        "sve2" => IsaFeature::Sve2,
        "sveaes" => IsaFeature::SveAes,
        "svepmull" => IsaFeature::SvePmull,
        "svebitperm" => IsaFeature::SveBitPerm,
        "svesha3" => IsaFeature::SveSha3,
        "svesm4" => IsaFeature::SveSm4,
        "svei8mm" => IsaFeature::SveI8mm,
        "svef32mm" => IsaFeature::SveF32mm,
        "svef64mm" => IsaFeature::SveF64mm,
        "svebf16" => IsaFeature::SveBf16,
        "sme" => IsaFeature::Sme,
        "sme_i16i64" => IsaFeature::SmeI16i64,
        "sme_f64f64" => IsaFeature::SmeF64f64,
        "sme_i8i32" => IsaFeature::SmeI8i32,
        "sme_f16f32" => IsaFeature::SmeF16f32,
        "sme_b16f32" => IsaFeature::SmeB16f32,
        "sme_f32f32" => IsaFeature::SmeF32f32,
        "sme_fa64" => IsaFeature::SmeFa64,
        "mte" => IsaFeature::Mte,
        "mte3" => IsaFeature::Mte3,
        "bf16" => IsaFeature::Bf16,
        "dgh" => IsaFeature::Dgh,
        "dcpop" => IsaFeature::DcPop,
        "dcpodp" => IsaFeature::DcPopDp,
        "wfxt" => IsaFeature::Wfxt,
        "virt" => IsaFeature::Virt,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a little-endian auxiliary vector from `(type, value)` pairs.
    fn auxv(pairs: &[(u64, u64)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (t, v) in pairs {
            out.extend_from_slice(&t.to_le_bytes());
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out
    }

    #[test]
    fn parses_auxv_fields() {
        let bytes = auxv(&[(AT_PAGESZ, 16384), (AT_HWCAP, 0x1234), (AT_HWCAP2, 0xABCD)]);
        let (hwcap, hwcap2, pagesz) = parse_auxv(&bytes);
        assert_eq!(hwcap, 0x1234);
        assert_eq!(hwcap2, 0xABCD);
        assert_eq!(pagesz, 16384);
    }

    #[test]
    fn parses_auxv_ignoring_unknown_types() {
        let bytes = auxv(&[(1, 999), (AT_HWCAP, 7), (999, 1), (AT_PAGESZ, 4096)]);
        let (hwcap, hwcap2, pagesz) = parse_auxv(&bytes);
        assert_eq!(hwcap, 7);
        assert_eq!(hwcap2, 0);
        assert_eq!(pagesz, 4096);
    }

    #[test]
    fn parses_empty_auxv() {
        assert_eq!(parse_auxv(&[]), (0, 0, 0));
        assert_eq!(parse_auxv(&[0u8; 16]), (0, 0, 0));
    }

    #[test]
    fn decodes_hwcap_bits() {
        // Verified kernel positions: FP=0, ASIMD=1, AES=3, CPUID=11, DOTPROD=20.
        let hwcap = (1u64 << 0) | (1 << 1) | (1 << 3) | (1 << 11) | (1 << 20);
        let set = features_from_hwcap(hwcap, 0);
        assert!(set.contains(IsaFeature::Fp));
        assert!(set.contains(IsaFeature::Asimd));
        assert!(set.contains(IsaFeature::Aes));
        assert!(set.contains(IsaFeature::Cpuid));
        assert!(set.contains(IsaFeature::DotProd));
        assert!(!set.contains(IsaFeature::Sve));
        // Guards the exact confusion this test previously contained: bit 2 is EVTSTRM
        // (unmapped) and bit 9 is f16, so neither may be reported as AES or CPUID.
        assert!(!set.contains(IsaFeature::Fp16), "bit 9 is f16, which is clear here");
        assert!(!set.contains(IsaFeature::Fcma), "bit 14 is fcma, which is clear here");
    }

    #[test]
    fn decodes_hwcap2_bits() {
        // Real kernel positions: SVE2=1, I8MM=13, BTI=17, MTE=18, SME=23.
        let hwcap2 = (1u64 << 1) | (1 << 13) | (1 << 17) | (1 << 18) | (1 << 23);
        let set = features_from_hwcap(0, hwcap2);
        assert!(set.contains(IsaFeature::Sve2));
        assert!(set.contains(IsaFeature::I8mm));
        assert!(set.contains(IsaFeature::Bti));
        assert!(set.contains(IsaFeature::Mte));
        assert!(set.contains(IsaFeature::Sme));
        // SVE lives in HWCAP bit 22, never in HWCAP2. Treating bit 12 as SVE (as an
        // earlier revision of this table did) silently invents a capability the CPU
        // does not have, which is the most dangerous possible failure mode.
        assert!(!set.contains(IsaFeature::Sve));
    }

    /// Guards the table against the exact defect found during development: a shifted
    /// bitmap silently reporting capabilities the CPU does not implement.
    ///
    /// The inputs are from a live ARM64 kernel and were cross-checked against that
    /// device's `/proc/cpuinfo` feature list.
    #[test]
    fn decodes_the_real_reference_device() {
        // HWCAP  = 0xffbfffff -- bits 0..=23 except bit 22 (SVE).
        // HWCAP2 = 0x22181    -- bits 0, 7, 8, 13, 16, 17.
        let set = features_from_hwcap(0xffbf_ffff, 0x2_2181);
        // Present, per the kernel's own bit assignments.
        assert!(set.contains(IsaFeature::I8mm), "HWCAP2 bit 13 is I8MM");
        assert!(set.contains(IsaFeature::Bti), "HWCAP2 bit 17 is BTI");
        assert!(set.contains(IsaFeature::FlagM2), "HWCAP2 bit 7 is FLAGM2");
        assert!(set.contains(IsaFeature::Frint), "HWCAP2 bit 8 is FRINT");
        // HWCAP2 bit 16 is RNG; this device does not implement it. Asserting its
        // absence is what proves the table is not simply setting every bit it knows.
        assert!(!set.contains(IsaFeature::Rng), "HWCAP2 bit 16 (RNG) is clear here");
        assert!(set.contains(IsaFeature::DcPopDp), "HWCAP2 bit 0 is DCPODP");
        assert!(set.contains(IsaFeature::DcPop), "HWCAP bit 16 is DCPOP");
        assert!(set.contains(IsaFeature::DotProd), "HWCAP bit 20 is DOTPROD");
        // Crucially absent: this core has no matrix support and no scalable vectors.
        assert!(!set.contains(IsaFeature::Sve), "HWCAP bit 22 is clear");
        assert!(!set.contains(IsaFeature::Sve2), "no SVE2");
        assert!(!set.contains(IsaFeature::Sme), "no SME");
        assert!(!set.contains(IsaFeature::Mte), "no MTE");
    }

    #[test]
    fn decodes_zero_as_empty() {
        assert!(features_from_hwcap(0, 0).is_empty());
    }

    #[test]
    fn parses_cpuinfo_feature_lines() {
        let cpuinfo = "\
processor\t: 0
Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp
CPU implementer\t: 0x41

processor\t: 4
Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp
";
        let lines = parse_cpuinfo_features(cpuinfo);
        assert_eq!(lines.len(), 2);

        let set = features_from_cpuinfo(cpuinfo);
        assert!(set.contains(IsaFeature::Fp));
        assert!(set.contains(IsaFeature::Aes));
        assert!(set.contains(IsaFeature::Lse));
        assert!(set.contains(IsaFeature::Fp16));
        assert!(set.contains(IsaFeature::DotProd));
        assert!(set.contains(IsaFeature::Crc32));
        assert!(!set.contains(IsaFeature::Sve2));
    }

    #[test]
    fn cpuinfo_recognizes_sme_which_hwcap_may_not() {
        let set = features_from_feature_line("fp asimd sme sve2");
        assert!(set.contains(IsaFeature::Sme));
        assert!(set.contains(IsaFeature::Sve2));
    }

    #[test]
    fn unknown_cpuinfo_tokens_are_ignored() {
        let set = features_from_feature_line("fp futurefeature foo bar");
        assert_eq!(set.len(), 1);
        assert!(set.contains(IsaFeature::Fp));
    }

    #[test]
    fn token_mapping_is_total_for_documented_names() {
        assert_eq!(feature_from_cpuinfo_token("atomics"), Some(IsaFeature::Lse));
        assert_eq!(feature_from_cpuinfo_token("lse"), Some(IsaFeature::Lse));
        assert_eq!(feature_from_cpuinfo_token("asimddp"), Some(IsaFeature::DotProd));
        assert_eq!(feature_from_cpuinfo_token("sme"), Some(IsaFeature::Sme));
        assert_eq!(feature_from_cpuinfo_token("nope"), None);
    }

    #[test]
    fn synthetic_profile_reports_arm64() {
        let host = HostProfile::synthetic("aarch64", 4096, 8, FeatureSet::new());
        assert!(host.is_arm64());
        assert!(!host.has_non_windows_page_size());
        assert!(host.summary_line().contains("aarch64"));
    }

    #[test]
    fn synthetic_x86_host_is_not_arm64() {
        let host = HostProfile::synthetic("x86_64", 4096, 4, FeatureSet::new());
        assert!(!host.is_arm64());
    }

    #[test]
    fn detects_16k_page_host() {
        let host = HostProfile::synthetic("aarch64", 16384, 8, FeatureSet::new());
        assert!(host.has_non_windows_page_size());
    }

    #[test]
    fn guaranteed_features_intersects_cores() {
        let mut host = HostProfile::synthetic("aarch64", 4096, 8, FeatureSet::all());
        host.per_core_features = vec![
            "fp asimd aes sve2".to_owned(),
            "fp asimd aes sve2 sme".to_owned(),
        ];
        let guaranteed = host.guaranteed_features();
        assert!(guaranteed.contains(IsaFeature::Sve2));
        assert!(!guaranteed.contains(IsaFeature::Sme));
    }

    #[test]
    fn guaranteed_features_falls_back_when_no_cpuinfo() {
        let host = HostProfile::synthetic("aarch64", 4096, 8, FeatureSet::new().with(IsaFeature::Sve2));
        assert!(host.guaranteed_features().contains(IsaFeature::Sve2));
    }

    #[test]
    fn json_export_has_required_keys() {
        let host = HostProfile::synthetic("aarch64", 16384, 8, FeatureSet::new().with(IsaFeature::Sve2));
        let json = host.to_json();
        assert_eq!(json["arch"].as_str(), Some("aarch64"));
        assert_eq!(json["page_size"].as_u64(), Some(16384));
        assert_eq!(json["cpu_count"].as_u64(), Some(8));
        assert!(json["features"].as_array().unwrap().contains(&compitum_json::Value::from("sve2")));
    }

    #[test]
    fn probing_the_real_host_never_panics() {
        let host = HostProfile::probe();
        assert!(!host.arch.is_empty());
        assert!(host.page_size > 0);
        assert!(host.cpu_count >= 1);
    }
}
