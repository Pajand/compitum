//! Provenance-aware requirements.
//!
//! A [`Requirement`] is a statement that a binary *needs* something from the CPU.
//! COMPITUM records not just *what* is needed but *how we know* and *how sure we are*,
//! because the two available evidence paths have very different reliability:
//!
//! | Source | Basis | Typical confidence |
//! |---|---|---|
//! | [`RequirementSource::MachineType`] | the PE `Machine` field | certainty — it is a declared fact |
//! | [`RequirementSource::Metadata`] | import tables, load config, CLR header | high — declared or linked metadata |
//! | [`RequirementSource::InstructionScan`] | pattern-matching machine code | medium — a static heuristic |
//! | [`RequirementSource::UserDeclared`] | an explicit override from the operator | high |
//!
//! # Why this matters
//!
//! Declaring "this binary needs SME" with no qualification would be dishonest: static
//! scanning cannot see dynamically generated code, and a byte pattern can occur by
//! coincidence. Equally, refusing to look at code at all would miss the single most
//! important class of failure — a program that loads fine and then faults on its first
//! matrix instruction.
//!
//! COMPITUM therefore reports both, weighted, and lets the consumer decide. A
//! confidence below [`Confidence::CERTAIN`] is surfaced in the CLI as a caveat rather
//! than hidden.

use std::fmt;

use crate::feature::IsaFeature;

/// How a requirement was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequirementSource {
    /// Derived from the PE `Machine` field. This is a declared property of the file.
    MachineType,
    /// Derived from linked metadata: import tables, load configuration, CLR header,
    /// section flags, optional-header fields.
    Metadata,
    /// Derived from scanning machine code for instruction encodings.
    InstructionScan,
    /// Declared by the operator via a command-line override or a manifest.
    UserDeclared,
}

impl RequirementSource {
    /// Evidential strength, used to decide which of two conflicting claims about the
    /// same feature survives.
    ///
    /// This is deliberately **not** the declaration order of the enum. Deriving `Ord`
    /// would rank by where a variant happens to sit in the source file, which is
    /// meaningless; what matters is how much a claim can be trusted.
    ///
    /// Ordering, strongest first:
    ///
    /// 1. [`RequirementSource::MachineType`] -- a declared property of the file.
    /// 2. [`RequirementSource::UserDeclared`] -- an explicit operator statement.
    /// 3. [`RequirementSource::Metadata`] -- recorded by a toolchain.
    /// 4. [`RequirementSource::InstructionScan`] -- a static heuristic.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            RequirementSource::MachineType => 4,
            RequirementSource::UserDeclared => 3,
            RequirementSource::Metadata => 2,
            RequirementSource::InstructionScan => 1,
        }
    }

    /// Stable machine identifier for JSON and Oracle records.
    ///
    /// Protocol value: never translated, never changed.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            RequirementSource::MachineType => "machine_type",
            RequirementSource::Metadata => "metadata",
            RequirementSource::InstructionScan => "instruction_scan",
            RequirementSource::UserDeclared => "user_declared",
        }
    }

    /// The default confidence associated with this evidence path.
    #[must_use]
    pub fn default_confidence(self) -> Confidence {
        match self {
            RequirementSource::MachineType => Confidence::CERTAIN,
            RequirementSource::Metadata => Confidence::HIGH,
            RequirementSource::InstructionScan => Confidence::MEDIUM,
            RequirementSource::UserDeclared => Confidence::HIGH,
        }
    }

    /// A short English explanation of what this evidence path can and cannot prove.
    #[must_use]
    pub fn limitation(self) -> &'static str {
        match self {
            RequirementSource::MachineType => {
                "The PE machine field is a declared fact and is always trustworthy."
            }
            RequirementSource::Metadata => {
                "Linked metadata is authoritative for what the linker recorded, but \
                 says nothing about hand-written assembly or run-time-generated code."
            }
            RequirementSource::InstructionScan => {
                "Static scanning cannot see dynamically generated code, and a rare \
                 encoding can appear by coincidence in data embedded in a code section."
            }
            RequirementSource::UserDeclared => {
                "Operator-supplied; trusted as given, and not independently verified."
            }
        }
    }
}

impl fmt::Display for RequirementSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// A coarse confidence level, represented in permille for stable arithmetic.
///
/// Integer permille avoids floating-point comparison problems in Oracle records and
/// makes JSON output deterministic across platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Confidence(u16);

impl Confidence {
    /// A declared fact, such as the PE machine type. 1000‰.
    pub const CERTAIN: Confidence = Confidence(1000);
    /// Recorded by a toolchain in metadata. 950‰.
    pub const HIGH: Confidence = Confidence(950);
    /// A conservative static heuristic. 600‰.
    pub const MEDIUM: Confidence = Confidence(600);
    /// A weak signal that warrants a caveat. 300‰.
    pub const LOW: Confidence = Confidence(300);

    /// Builds a confidence from permille, clamping to `[0, 1000]`.
    #[must_use]
    pub fn from_permille(value: u16) -> Self {
        Confidence(value.min(1000))
    }

    /// The value in permille, in `[0, 1000]`.
    #[must_use]
    pub fn permille(self) -> u16 {
        self.0
    }

    /// The value as a percentage, rounded down.
    #[must_use]
    pub fn percent(self) -> u16 {
        self.0 / 10
    }

    /// Returns `true` when this is the highest possible confidence.
    #[must_use]
    pub fn is_certain(self) -> bool {
        self.0 == 1000
    }

    /// Returns the weaker of two confidences.
    #[must_use]
    pub fn min(self, other: Self) -> Self {
        Confidence(self.0.min(other.0))
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Confidence::MEDIUM
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}%", self.percent())
    }
}

/// A single, justified statement that a binary needs a CPU feature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// The feature required.
    pub feature: IsaFeature,
    /// How the requirement was established.
    pub source: RequirementSource,
    /// How much the claim can be trusted.
    pub confidence: Confidence,
    /// Where in the file the evidence was found, when that is meaningful.
    ///
    /// For a scan hit this is the RVA of the offending instruction; for metadata it is
    /// the RVA of the directory that named the dependency.
    pub evidence_rva: Option<u32>,
    /// Free-form, English, human-readable detail for `--verbose` output and the Oracle.
    pub detail: String,
}

impl Requirement {
    /// Creates a requirement using the default confidence for its source.
    #[must_use]
    pub fn new(
        feature: IsaFeature,
        source: RequirementSource,
        evidence_rva: Option<u32>,
        detail: impl Into<String>,
    ) -> Self {
        Requirement {
            feature,
            source,
            confidence: source.default_confidence(),
            evidence_rva,
            detail: detail.into(),
        }
    }

    /// Overrides the confidence, keeping the lower of the two.
    ///
    /// Downgrading is always permitted; upgrading is not, because new evidence can
    /// weaken a claim but never strengthen one that was already weak.
    #[must_use]
    pub fn with_confidence_cap(mut self, cap: Confidence) -> Self {
        self.confidence = self.confidence.min(cap);
        self
    }
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (via {}, {} confidence)",
            self.feature.id(),
            self.source.id(),
            self.confidence
        )
    }
}

/// A collection of requirements with de-duplication and set extraction.
#[derive(Debug, Clone, Default)]
pub struct RequirementSet {
    items: Vec<Requirement>,
}

impl RequirementSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        RequirementSet { items: Vec::new() }
    }

    /// Adds a requirement.
    ///
    /// If the same feature is already present from a *weaker or equal* source, the new
    /// one replaces it. If it is already present from a stronger source, the existing
    /// entry is kept but its detail is merged, so the report shows every reason the
    /// feature is believed to be needed.
    pub fn add(&mut self, requirement: Requirement) {
        if let Some(existing) = self
            .items
            .iter_mut()
            .find(|r| r.feature == requirement.feature)
        {
            let existing_strength = (existing.source.rank(), existing.confidence);
            let new_strength = (requirement.source.rank(), requirement.confidence);
            if new_strength > existing_strength {
                let merged_detail = if existing.detail == requirement.detail {
                    requirement.detail.clone()
                } else {
                    format!("{}; also: {}", requirement.detail, existing.detail)
                };
                *existing = Requirement {
                    detail: merged_detail,
                    ..requirement
                };
            } else if existing.detail != requirement.detail {
                existing.detail = format!("{}; also: {}", existing.detail, requirement.detail);
            }
            return;
        }
        self.items.push(requirement);
    }

    /// Adds a requirement with default confidence for its source.
    pub fn require(
        &mut self,
        feature: IsaFeature,
        source: RequirementSource,
        evidence_rva: Option<u32>,
        detail: impl Into<String>,
    ) {
        self.add(Requirement::new(feature, source, evidence_rva, detail));
    }

    /// Returns `true` when the feature is required.
    #[must_use]
    pub fn contains(&self, feature: IsaFeature) -> bool {
        self.items.iter().any(|r| r.feature == feature)
    }

    /// Every requirement, in insertion order.
    #[must_use]
    pub fn items(&self) -> &[Requirement] {
        &self.items
    }

    /// Number of requirements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` when nothing is required.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The set of features required, discarding provenance.
    #[must_use]
    pub fn feature_set(&self) -> crate::feature::FeatureSet {
        self.items.iter().map(|r| r.feature).collect()
    }

    /// Only those requirements that would be satisfied by the given host set.
    #[must_use]
    pub fn satisfied_by(&self, host: crate::feature::FeatureSet) -> Vec<&Requirement> {
        self.items
            .iter()
            .filter(|r| host.contains(r.feature))
            .collect()
    }

    /// Only those requirements that the given host set cannot satisfy.
    #[must_use]
    pub fn unsatisfied_by(&self, host: crate::feature::FeatureSet) -> Vec<&Requirement> {
        self.items
            .iter()
            .filter(|r| !host.contains(r.feature))
            .collect()
    }

    /// The weakest confidence in the set, or [`Confidence::CERTAIN`] when empty.
    ///
    /// A report that rests on any weak evidence should be presented as uncertain, so
    /// consumers can call this once rather than inspecting every entry.
    #[must_use]
    pub fn weakest_confidence(&self) -> Confidence {
        self.items
            .iter()
            .map(|r| r.confidence)
            .min()
            .unwrap_or(Confidence::CERTAIN)
    }

    /// Sorts requirements by confidence descending, then by stable feature order.
    ///
    /// Produces deterministic output for snapshots and Oracle records.
    pub fn sort(&mut self) {
        self.items.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.feature.cmp(&b.feature))
        });
    }

    /// Serializes the requirements as a JSON array.
    #[must_use]
    pub fn to_json(&self) -> compitum_json::Value {
        let items: Vec<compitum_json::Value> = self
            .items
            .iter()
            .map(|r| {
                compitum_json::Object::new()
                    .with("feature", r.feature.id())
                    .with("source", r.source.id())
                    .with("confidence_permille", r.confidence.permille())
                    .with("evidence_rva", r.evidence_rva.map(u64::from))
                    .with("detail", r.detail.as_str())
                    .into()
            })
            .collect();
        compitum_json::Value::from(items)
    }
}

impl FromIterator<Requirement> for RequirementSet {
    fn from_iter<T: IntoIterator<Item = Requirement>>(iter: T) -> Self {
        let mut set = RequirementSet::new();
        for requirement in iter {
            set.add(requirement);
        }
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_ids_are_stable() {
        assert_eq!(RequirementSource::MachineType.id(), "machine_type");
        assert_eq!(RequirementSource::Metadata.id(), "metadata");
        assert_eq!(RequirementSource::InstructionScan.id(), "instruction_scan");
        assert_eq!(RequirementSource::UserDeclared.id(), "user_declared");
    }

    #[test]
    fn every_source_has_a_limitation_note() {
        for source in [
            RequirementSource::MachineType,
            RequirementSource::Metadata,
            RequirementSource::InstructionScan,
            RequirementSource::UserDeclared,
        ] {
            assert!(!source.limitation().is_empty());
        }
    }

    #[test]
    fn confidence_is_clamped_and_formatted() {
        assert_eq!(Confidence::from_permille(5000).permille(), 1000);
        assert_eq!(Confidence::CERTAIN.percent(), 100);
        assert_eq!(Confidence::MEDIUM.percent(), 60);
        assert!(Confidence::CERTAIN.is_certain());
        assert!(!Confidence::LOW.is_certain());
    }

    #[test]
    fn confidence_min_returns_weaker() {
        assert_eq!(Confidence::CERTAIN.min(Confidence::LOW), Confidence::LOW);
        assert_eq!(Confidence::LOW.min(Confidence::HIGH), Confidence::LOW);
    }

    #[test]
    fn confidence_can_only_be_downgraded() {
        let requirement = Requirement::new(
            IsaFeature::Sve2,
            RequirementSource::InstructionScan,
            Some(0x1234),
            "found SVE encoding",
        );
        assert_eq!(requirement.confidence, Confidence::MEDIUM);
        let capped = requirement.with_confidence_cap(Confidence::CERTAIN);
        assert_eq!(capped.confidence, Confidence::MEDIUM);
        let lowered = capped.with_confidence_cap(Confidence::LOW);
        assert_eq!(lowered.confidence, Confidence::LOW);
    }

    #[test]
    fn stronger_evidence_replaces_weaker() {
        let mut set = RequirementSet::new();
        set.require(
            IsaFeature::Sve2,
            RequirementSource::InstructionScan,
            Some(0x100),
            "scan",
        );
        set.require(
            IsaFeature::Sve2,
            RequirementSource::Metadata,
            Some(0x200),
            "metadata",
        );
        assert_eq!(set.len(), 1);
        let item = &set.items()[0];
        assert_eq!(item.source, RequirementSource::Metadata);
        assert_eq!(item.confidence, Confidence::HIGH);
    }

    #[test]
    fn weaker_evidence_does_not_replace_stronger_but_is_recorded() {
        let mut set = RequirementSet::new();
        set.require(
            IsaFeature::Sme,
            RequirementSource::Metadata,
            Some(0x10),
            "declared by linker",
        );
        set.require(
            IsaFeature::Sme,
            RequirementSource::InstructionScan,
            Some(0x20),
            "scan hit",
        );
        assert_eq!(set.len(), 1);
        let item = &set.items()[0];
        assert_eq!(item.source, RequirementSource::Metadata);
        assert!(item.detail.contains("declared by linker"));
        assert!(item.detail.contains("scan hit"));
    }

    #[test]
    fn duplicate_identical_detail_is_not_repeated() {
        let mut set = RequirementSet::new();
        set.require(IsaFeature::Sve, RequirementSource::Metadata, None, "same");
        set.require(IsaFeature::Sve, RequirementSource::Metadata, None, "same");
        assert_eq!(set.len(), 1);
        assert_eq!(set.items()[0].detail, "same");
    }

    #[test]
    fn satisfied_and_unsatisfied_partition_the_set() {
        let mut set = RequirementSet::new();
        set.require(IsaFeature::Sve2, RequirementSource::Metadata, None, "a");
        set.require(IsaFeature::Mte, RequirementSource::Metadata, None, "b");
        let host = crate::feature::FeatureSet::new().with(IsaFeature::Sve2);

        assert_eq!(set.satisfied_by(host).len(), 1);
        assert_eq!(set.unsatisfied_by(host).len(), 1);
        assert_eq!(set.unsatisfied_by(host)[0].feature, IsaFeature::Mte);
    }

    #[test]
    fn feature_set_discards_provenance() {
        let mut set = RequirementSet::new();
        set.require(IsaFeature::Sve2, RequirementSource::Metadata, None, "a");
        set.require(
            IsaFeature::Sme,
            RequirementSource::InstructionScan,
            None,
            "b",
        );
        assert_eq!(set.feature_set().len(), 2);
    }

    #[test]
    fn weakest_confidence_reports_the_floor() {
        let mut set = RequirementSet::new();
        set.require(IsaFeature::Sve2, RequirementSource::Metadata, None, "a");
        set.require(
            IsaFeature::Mte,
            RequirementSource::InstructionScan,
            None,
            "b",
        );
        assert_eq!(set.weakest_confidence(), Confidence::MEDIUM);
        assert_eq!(
            RequirementSet::new().weakest_confidence(),
            Confidence::CERTAIN
        );
    }

    #[test]
    fn sort_is_by_confidence_then_feature() {
        let mut set = RequirementSet::new();
        set.require(
            IsaFeature::Mte,
            RequirementSource::InstructionScan,
            None,
            "weak",
        );
        set.require(
            IsaFeature::Sve2,
            RequirementSource::Metadata,
            None,
            "strong",
        );
        set.sort();
        assert_eq!(set.items()[0].feature, IsaFeature::Sve2);
        assert_eq!(set.items()[1].feature, IsaFeature::Mte);
    }

    #[test]
    fn json_export_is_well_formed() {
        let mut set = RequirementSet::new();
        set.require(
            IsaFeature::Sme,
            RequirementSource::InstructionScan,
            Some(0x1000),
            "matrix op",
        );
        let json = set.to_json();
        let array = json.as_array().unwrap();
        assert_eq!(array.len(), 1);
        assert_eq!(array[0]["feature"].as_str(), Some("sme"));
        assert_eq!(array[0]["source"].as_str(), Some("instruction_scan"));
        assert_eq!(array[0]["evidence_rva"].as_u64(), Some(0x1000));
    }

    #[test]
    fn null_rva_serializes_as_null() {
        let mut set = RequirementSet::new();
        set.require(IsaFeature::Sve2, RequirementSource::Metadata, None, "x");
        // `Value` indexes by key, not by position, so reach into the array explicitly.
        let json = set.to_json();
        let first = &json.as_array().expect("array")[0];
        assert!(first["evidence_rva"].is_null());
    }

    #[test]
    fn from_iterator_collects() {
        let items = vec![
            Requirement::new(IsaFeature::Sve2, RequirementSource::Metadata, None, "a"),
            Requirement::new(IsaFeature::Sme, RequirementSource::Metadata, None, "b"),
        ];
        let set: RequirementSet = items.into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn display_includes_provenance() {
        let requirement = Requirement::new(
            IsaFeature::Sme,
            RequirementSource::InstructionScan,
            None,
            "x",
        );
        let text = requirement.to_string();
        assert!(text.contains("sme"));
        assert!(text.contains("instruction_scan"));
        assert!(text.contains("60%"));
    }
}
