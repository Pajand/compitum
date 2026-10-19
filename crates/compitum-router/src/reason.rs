//! Reason codes: the evidence attached to every routing decision.
//!
//! COMPITUM's first law of doctrine is **evidence over assertion**. A route without its
//! reasons is an opinion. This module defines the closed set of facts a decision can rest
//! on, so that:
//!
//! * an operator can see *why* a binary was routed as it was,
//! * the Oracle can correlate outcomes against specific reasons rather than against
//!   opaque verdicts,
//! * and a regression in reasoning shows up in a diff rather than in a support ticket.
//!
//! # Structure
//!
//! A [`Reason`] carries a [`ReasonCode`], a [`Severity`], and an optional English detail
//! string. The code is the protocol value and never changes; the detail is human-facing
//! and may contain specifics such as which features were missing.
//!
//! # Why severity is separate from the code
//!
//! The same code can mean different things at different weights. `Blocked` means the route
//! is impossible; `Caution` means it will work but something about it is worth knowing;
//! `Supporting` is evidence *for* the chosen route. Collapsing these into one enum would
//! force callers to compare codes against a list, which is exactly the kind of implicit
//! knowledge that rots.

use std::fmt;

use compitum_isa::{Confidence, IsaFeature};

/// How strongly a reason bears on the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Evidence in favour of the chosen route.
    Supporting,
    /// The route will work, but something warrants attention.
    Caution,
    /// The route is impossible without a change of circumstances.
    Blocked,
}

impl Severity {
    /// Stable identifier for JSON and Oracle records.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Severity::Supporting => "supporting",
            Severity::Caution => "caution",
            Severity::Blocked => "blocked",
        }
    }

    /// A single-character marker for compact console output.
    #[must_use]
    pub fn marker(self) -> char {
        match self {
            Severity::Supporting => '+',
            Severity::Caution => '!',
            Severity::Blocked => 'x',
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// The closed set of facts a routing decision can rest on.
///
/// Each code names one proposition. They are grouped by what they are evidence *of*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReasonCode {
    // ---- Architecture ------------------------------------------------------
    /// The image is pure AArch64, so every instruction is directly executable.
    ArchitectureNative,
    /// The image contains x86-64 code alongside AArch64.
    ArchitectureHybrid,
    /// The image carries both a native and a hybrid slice.
    ArchitectureFat,
    /// The image is x86-64 and cannot execute natively on ARM64.
    ArchitectureRequiresTranslation,
    /// The image is 32-bit and needs a 32-bit path.
    ArchitectureRequiresWow64,
    /// The image targets an architecture no route can handle here.
    ArchitectureUnsupported,

    // ---- Instruction set ---------------------------------------------------
    /// Every CPU feature the image requires is implemented by this host.
    IsaSubsetSatisfied,
    /// One or more required CPU features are absent.
    IsaFeaturesMissing,
    /// Low-confidence ISA evidence was found by scanning, not by metadata.
    IsaEvidenceWeak,

    // ---- Memory model ------------------------------------------------------
    /// The image's implied page size agrees with the host's.
    PageSizeMatches,
    /// The image's implied page size differs from the host's.
    PageSizeMismatch,

    // ---- Subsystem and presentation ---------------------------------------
    /// The image declares a console or native subsystem, so no display is needed.
    SubsystemHeadlessCapable,
    /// The image declares a graphical subsystem, so a display layer is required.
    SubsystemRequiresDisplay,
    /// The image imports a graphics API and therefore needs a rendering backend.
    GraphicsBackendRequired,

    // ---- Managed code ------------------------------------------------------
    /// The image is managed (.NET) code, so its IL is JIT-compiled to host instructions
    /// and the recorded machine type may not describe what actually executes.
    SubjectIsManagedCode,

    // ---- Backend availability ---------------------------------------------
    /// A required translation backend is present on this host.
    BackendPresent,
    /// A required translation backend is absent.
    BackendAbsent,
    /// The NT system-call layer is present, without which no Windows image can run.
    SyscallLayerPresent,
    /// The NT system-call layer is absent.
    SyscallLayerAbsent,

    // ---- Migration target --------------------------------------------------
    /// The destination supplies a translation layer the image needs.
    ///
    /// The clear case is ARM64EC on Windows on Arm, where the operating system itself
    /// implements the AArch64/x86-64 boundary, so no separate translator is loaded.
    TargetProvidesTranslation,
    /// The destination supplies the NT system-call layer itself.
    ///
    /// On Windows this is the operating system; on Linux it is Wine, a package the operator
    /// must install. Reporting the Linux case as "the binary cannot run" confuses a missing
    /// dependency with a defect in the software.
    TargetSuppliesSyscallLayer,
    /// A kernel driver would have to be emulated, which no target supports.
    ///
    /// Microsoft states that emulation covers user-mode code only and that kernel components
    /// must be built for Arm64; on Linux a Windows driver cannot load at all. Either way the
    /// answer is a rewrite rather than a port.
    KernelDriverEmulated,
    /// A kernel driver is native for the destination and loads normally.
    ///
    /// An Arm64 driver on Windows on Arm is ordinary native kernel code. Conflating this with
    /// the emulated case would tell a customer to rewrite a driver that already works.
    KernelDriverNative,

    // ---- Cross-cutting -----------------------------------------------------
    /// The host is not an ARM64 machine, so this analysis does not describe it.
    HostIsNotArm64,
    /// The decision had to be made without complete information.
    InsufficientInformation,
    /// The file could not be parsed, so only the failure is known.
    UnreadableSubject,
}

impl ReasonCode {
    /// Stable identifier. Protocol value: never translated, never changed.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            ReasonCode::ArchitectureNative => "architecture_native",
            ReasonCode::ArchitectureHybrid => "architecture_hybrid",
            ReasonCode::ArchitectureFat => "architecture_fat",
            ReasonCode::ArchitectureRequiresTranslation => "architecture_requires_translation",
            ReasonCode::ArchitectureRequiresWow64 => "architecture_requires_wow64",
            ReasonCode::ArchitectureUnsupported => "architecture_unsupported",
            ReasonCode::IsaSubsetSatisfied => "isa_subset_satisfied",
            ReasonCode::IsaFeaturesMissing => "isa_features_missing",
            ReasonCode::IsaEvidenceWeak => "isa_evidence_weak",
            ReasonCode::PageSizeMatches => "page_size_matches",
            ReasonCode::PageSizeMismatch => "page_size_mismatch",
            ReasonCode::SubsystemHeadlessCapable => "subsystem_headless_capable",
            ReasonCode::SubsystemRequiresDisplay => "subsystem_requires_display",
            ReasonCode::GraphicsBackendRequired => "graphics_backend_required",
            ReasonCode::SubjectIsManagedCode => "subject_is_managed_code",
            ReasonCode::BackendPresent => "backend_present",
            ReasonCode::BackendAbsent => "backend_absent",
            ReasonCode::SyscallLayerPresent => "syscall_layer_present",
            ReasonCode::SyscallLayerAbsent => "syscall_layer_absent",
            ReasonCode::HostIsNotArm64 => "host_is_not_arm64",
            ReasonCode::InsufficientInformation => "insufficient_information",
            ReasonCode::UnreadableSubject => "unreadable_subject",
            ReasonCode::TargetProvidesTranslation => "target_provides_translation",
            ReasonCode::TargetSuppliesSyscallLayer => "target_supplies_syscall_layer",
            ReasonCode::KernelDriverEmulated => "kernel_driver_emulated",
            ReasonCode::KernelDriverNative => "kernel_driver_native",
        }
    }

    /// The default severity this code carries.
    ///
    /// A caller may override it, but the default encodes what the fact usually means, so
    /// the common case needs no thought.
    #[must_use]
    pub fn default_severity(self) -> Severity {
        match self {
            ReasonCode::ArchitectureNative
            | ReasonCode::IsaSubsetSatisfied
            | ReasonCode::PageSizeMatches
            | ReasonCode::SubsystemHeadlessCapable
            | ReasonCode::BackendPresent
            | ReasonCode::SyscallLayerPresent => Severity::Supporting,

            ReasonCode::ArchitectureHybrid
            | ReasonCode::ArchitectureFat
            | ReasonCode::IsaEvidenceWeak
            | ReasonCode::SubsystemRequiresDisplay
            | ReasonCode::GraphicsBackendRequired
            | ReasonCode::PageSizeMismatch
            | ReasonCode::InsufficientInformation => Severity::Caution,

            // These describe a requirement, not an obstacle. An x86-64 image is only
            // un-runnable when no translator is installed, which `BackendAbsent` reports.
            // Classifying them as Blocked made every translatable image look like a
            // refusal -- the exact opposite of the truth, and a bug this test caught.
            ReasonCode::ArchitectureRequiresTranslation | ReasonCode::ArchitectureRequiresWow64 => {
                Severity::Caution
            }

            // These genuinely prevent execution.
            ReasonCode::ArchitectureUnsupported
            | ReasonCode::IsaFeaturesMissing
            | ReasonCode::BackendAbsent
            | ReasonCode::UnreadableSubject => Severity::Blocked,

            // A missing syscall layer blocks a Windows image even when the architecture
            // would have run natively.
            ReasonCode::SyscallLayerAbsent => Severity::Blocked,

            // Managed code is informational: it changes what the machine field means, but
            // it is neither a problem nor an advantage on its own.
            ReasonCode::SubjectIsManagedCode => Severity::Supporting,
            // A non-ARM64 host makes this whole analysis inapplicable, which is a caution
            // rather than a defect in the subject.
            ReasonCode::HostIsNotArm64 => Severity::Caution,

            // The destination supplying something the image needs is good news, and worth
            // showing: it is the difference between "install a translator" and "it just runs".
            ReasonCode::TargetProvidesTranslation
            | ReasonCode::TargetSuppliesSyscallLayer
            | ReasonCode::KernelDriverNative => Severity::Supporting,

            // A driver that would have to be emulated is not a warning: no target emulates
            // kernel-mode code, so this is a rewrite and must block a port.
            ReasonCode::KernelDriverEmulated => Severity::Blocked,
        }
    }

    /// Every code, for exhaustive iteration in tests and reports.
    pub const ALL: &'static [ReasonCode] = &[
        ReasonCode::ArchitectureNative,
        ReasonCode::ArchitectureHybrid,
        ReasonCode::ArchitectureFat,
        ReasonCode::ArchitectureRequiresTranslation,
        ReasonCode::ArchitectureRequiresWow64,
        ReasonCode::ArchitectureUnsupported,
        ReasonCode::IsaSubsetSatisfied,
        ReasonCode::IsaFeaturesMissing,
        ReasonCode::IsaEvidenceWeak,
        ReasonCode::PageSizeMatches,
        ReasonCode::PageSizeMismatch,
        ReasonCode::SubsystemHeadlessCapable,
        ReasonCode::SubsystemRequiresDisplay,
        ReasonCode::GraphicsBackendRequired,
        ReasonCode::SubjectIsManagedCode,
        ReasonCode::BackendPresent,
        ReasonCode::BackendAbsent,
        ReasonCode::SyscallLayerPresent,
        ReasonCode::SyscallLayerAbsent,
        ReasonCode::TargetProvidesTranslation,
        ReasonCode::TargetSuppliesSyscallLayer,
        ReasonCode::KernelDriverEmulated,
        ReasonCode::KernelDriverNative,
        ReasonCode::HostIsNotArm64,
        ReasonCode::InsufficientInformation,
        ReasonCode::UnreadableSubject,
    ];
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// One piece of evidence for or against a routing decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    /// What proposition this evidence supports.
    pub code: ReasonCode,
    /// How strongly it bears on the decision.
    pub severity: Severity,
    /// How confident the evidence is. Weak scan-derived evidence is flagged, not hidden.
    pub confidence: Confidence,
    /// Optional English detail naming specifics, such as which features were missing.
    pub detail: Option<String>,
}

impl Reason {
    /// Creates a reason with the code's default severity and certain confidence.
    #[must_use]
    pub fn new(code: ReasonCode) -> Self {
        Reason {
            code,
            severity: code.default_severity(),
            confidence: Confidence::CERTAIN,
            detail: None,
        }
    }

    /// Creates a reason carrying a specific detail string.
    #[must_use]
    pub fn with_detail(code: ReasonCode, detail: impl Into<String>) -> Self {
        Reason {
            code,
            severity: code.default_severity(),
            confidence: Confidence::CERTAIN,
            detail: Some(detail.into()),
        }
    }

    /// Overrides the severity.
    #[must_use]
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Overrides the confidence.
    #[must_use]
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Builds the reason for a set of features the host cannot provide.
    ///
    /// Extracted because formatting a feature list consistently is exactly the sort of
    /// thing that drifts between call sites, and the message is one an operator will read
    /// at their most frustrated.
    #[must_use]
    pub fn missing_features(features: &[IsaFeature], confidence: Confidence) -> Self {
        let names: Vec<&str> = features.iter().map(|f| f.id()).collect();
        Reason {
            code: ReasonCode::IsaFeaturesMissing,
            severity: Severity::Blocked,
            confidence,
            detail: Some(format!(
                "this host does not implement: {}",
                names.join(", ")
            )),
        }
    }

    /// Serializes to the Oracle's JSON shape.
    #[must_use]
    pub fn to_json(&self) -> compitum_json::Value {
        compitum_json::Object::new()
            .with("code", self.code.id())
            .with("severity", self.severity.id())
            .with("confidence_permille", self.confidence.permille())
            .with("detail", self.detail.as_deref())
            .into()
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.severity.marker(), self.code.id())?;
        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }
        if !self.confidence.is_certain() {
            write!(f, " ({} confidence)", self.confidence)?;
        }
        Ok(())
    }
}

/// An ordered collection of reasons.
///
/// Comparison is structural and order-sensitive: two collections with the same reasons in
/// a different order are not equal. That is deliberate, because reason order reflects the
/// order in which the engine evaluated its rules, and a change in that order is a change
/// in the reasoning worth noticing in a test diff.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reasons {
    items: Vec<Reason>,
}

impl Reasons {
    /// An empty collection.
    #[must_use]
    pub fn new() -> Self {
        Reasons { items: Vec::new() }
    }

    /// Adds a reason.
    pub fn push(&mut self, reason: Reason) {
        self.items.push(reason);
    }

    /// Adds a reason from a code, with the code's default severity.
    pub fn add(&mut self, code: ReasonCode) {
        self.push(Reason::new(code));
    }

    /// Adds a reason from a code and a detail string.
    pub fn add_detail(&mut self, code: ReasonCode, detail: impl Into<String>) {
        self.push(Reason::with_detail(code, detail));
    }

    /// All reasons, in insertion order.
    #[must_use]
    pub fn items(&self) -> &[Reason] {
        &self.items
    }

    /// Number of reasons.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` when there is no evidence at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns `true` when any reason blocks the route.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.items.iter().any(|r| r.severity == Severity::Blocked)
    }

    /// Returns `true` when any reason warrants a caution.
    #[must_use]
    pub fn has_caution(&self) -> bool {
        self.items.iter().any(|r| r.severity == Severity::Caution)
    }

    /// Only the blocking reasons.
    #[must_use]
    pub fn blocking(&self) -> Vec<&Reason> {
        self.items
            .iter()
            .filter(|r| r.severity == Severity::Blocked)
            .collect()
    }

    /// Only the reasons supporting the decision.
    #[must_use]
    pub fn supporting(&self) -> Vec<&Reason> {
        self.items
            .iter()
            .filter(|r| r.severity == Severity::Supporting)
            .collect()
    }

    /// Returns `true` when the code is present.
    #[must_use]
    pub fn contains(&self, code: ReasonCode) -> bool {
        self.items.iter().any(|r| r.code == code)
    }

    /// The weakest confidence across all reasons, or certain when empty.
    #[must_use]
    pub fn weakest_confidence(&self) -> Confidence {
        self.items
            .iter()
            .map(|r| r.confidence)
            .min()
            .unwrap_or(Confidence::CERTAIN)
    }

    /// Serializes the collection.
    #[must_use]
    pub fn to_json(&self) -> compitum_json::Value {
        let items: Vec<compitum_json::Value> = self.items.iter().map(Reason::to_json).collect();
        compitum_json::Value::from(items)
    }
}

impl FromIterator<Reason> for Reasons {
    fn from_iter<T: IntoIterator<Item = Reason>>(iter: T) -> Self {
        Reasons {
            items: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_a_unique_stable_id() {
        let mut seen = std::collections::BTreeSet::new();
        for code in ReasonCode::ALL {
            assert!(seen.insert(code.id()), "duplicate id: {}", code.id());
        }
    }

    #[test]
    fn every_code_has_a_default_severity_consistent_with_its_meaning() {
        // Blocking codes must genuinely prevent execution.
        for code in [
            ReasonCode::ArchitectureUnsupported,
            ReasonCode::IsaFeaturesMissing,
            ReasonCode::BackendAbsent,
            ReasonCode::SyscallLayerAbsent,
            ReasonCode::UnreadableSubject,
        ] {
            assert_eq!(
                code.default_severity(),
                Severity::Blocked,
                "{code} should block"
            );
        }
        // Native compatibility must be supportive, not merely neutral.
        assert_eq!(
            ReasonCode::ArchitectureNative.default_severity(),
            Severity::Supporting
        );
    }

    #[test]
    fn hybrid_is_a_caution_not_a_block() {
        // An ARM64EC image *does* run; it just needs translation. Classifying it as
        // blocked would tell the operator to give up on a working program.
        assert_eq!(
            ReasonCode::ArchitectureHybrid.default_severity(),
            Severity::Caution
        );
    }

    #[test]
    fn describing_a_requirement_is_never_a_block() {
        // Regression guard. These codes state a property of the image, not an obstacle to
        // running it. Treating them as blocking made every x86-64 image report as a
        // refusal even when a translator was installed and working.
        for code in [
            ReasonCode::ArchitectureRequiresTranslation,
            ReasonCode::ArchitectureRequiresWow64,
            ReasonCode::ArchitectureHybrid,
            ReasonCode::ArchitectureFat,
        ] {
            assert_ne!(
                code.default_severity(),
                Severity::Blocked,
                "{code} describes a requirement and must not block on its own"
            );
        }
    }

    #[test]
    fn only_genuine_obstacles_block() {
        let blocking: Vec<&str> = ReasonCode::ALL
            .iter()
            .filter(|c| c.default_severity() == Severity::Blocked)
            .map(|c| c.id())
            .collect();
        // A closed, deliberately small set. Adding to it should require justification, which
        // is exactly what this assertion just forced: `kernel_driver_emulated` was added for
        // the following reason.
        //
        // A kernel driver whose architecture the destination cannot execute has no route at
        // all. Microsoft states that emulation covers user-mode code only, so an x86 driver
        // cannot be emulated on Windows on Arm; on Linux no Windows driver loads at any
        // architecture. The honest answer is "this needs a driver rewrite", and presenting it
        // as anything softer would send a customer to schedule a port that cannot succeed.
        //
        // Note what is NOT in this list: `kernel_driver_native`. An Arm64 driver on Windows on
        // Arm is ordinary native kernel code and must not block — the first implementation of
        // that distinction got it backwards and would have told a customer to rewrite a driver
        // that already works.
        assert_eq!(
            blocking,
            vec![
                "architecture_unsupported",
                "isa_features_missing",
                "backend_absent",
                "syscall_layer_absent",
                "kernel_driver_emulated",
                "unreadable_subject",
            ]
        );
    }

    #[test]
    fn severity_markers_are_distinct() {
        let markers: Vec<char> = [Severity::Supporting, Severity::Caution, Severity::Blocked]
            .iter()
            .map(|s| s.marker())
            .collect();
        let unique: std::collections::BTreeSet<char> = markers.iter().copied().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn severity_orders_from_supporting_to_blocked() {
        assert!(Severity::Supporting < Severity::Caution);
        assert!(Severity::Caution < Severity::Blocked);
    }

    #[test]
    fn collection_classifies_its_contents() {
        let mut reasons = Reasons::new();
        reasons.add(ReasonCode::ArchitectureNative);
        assert!(!reasons.is_blocked());
        assert!(!reasons.has_caution());
        assert_eq!(reasons.supporting().len(), 1);

        reasons.add(ReasonCode::PageSizeMismatch);
        assert!(reasons.has_caution());

        reasons.add(ReasonCode::IsaFeaturesMissing);
        assert!(reasons.is_blocked());
        assert_eq!(reasons.blocking().len(), 1);
    }

    #[test]
    fn missing_features_reason_names_the_features() {
        let reason =
            Reason::missing_features(&[IsaFeature::Sme, IsaFeature::Sve2], Confidence::HIGH);
        assert_eq!(reason.code, ReasonCode::IsaFeaturesMissing);
        assert_eq!(reason.severity, Severity::Blocked);
        let detail = reason.detail.unwrap();
        assert!(detail.contains("sme"));
        assert!(detail.contains("sve2"));
        // The message must name the problem, not merely assert one exists.
        assert!(detail.len() > 20);
    }

    #[test]
    fn weak_confidence_is_rendered_not_hidden() {
        let reason = Reason::new(ReasonCode::IsaEvidenceWeak).confidence(Confidence::MEDIUM);
        let text = reason.to_string();
        assert!(text.contains("60%"), "got: {text}");
    }

    #[test]
    fn certain_confidence_is_not_cluttered_into_the_output() {
        let reason = Reason::new(ReasonCode::ArchitectureNative);
        assert!(!reason.to_string().contains("confidence"));
    }

    #[test]
    fn display_shows_severity_marker_code_and_detail() {
        let reason = Reason::with_detail(ReasonCode::BackendAbsent, "fex is not installed");
        let text = reason.to_string();
        assert!(text.starts_with("[x]"));
        assert!(text.contains("backend_absent"));
        assert!(text.contains("fex is not installed"));
    }

    #[test]
    fn weakest_confidence_is_the_floor() {
        let mut reasons = Reasons::new();
        reasons.push(Reason::new(ReasonCode::ArchitectureNative));
        reasons.push(Reason::new(ReasonCode::IsaEvidenceWeak).confidence(Confidence::MEDIUM));
        assert_eq!(reasons.weakest_confidence(), Confidence::MEDIUM);
        assert_eq!(Reasons::new().weakest_confidence(), Confidence::CERTAIN);
    }

    #[test]
    fn json_export_is_well_formed() {
        let mut reasons = Reasons::new();
        reasons.push(Reason::with_detail(
            ReasonCode::ArchitectureHybrid,
            "ARM64EC",
        ));
        let json = reasons.to_json();
        let array = json.as_array().unwrap();
        assert_eq!(array.len(), 1);
        assert_eq!(array[0]["code"].as_str(), Some("architecture_hybrid"));
        assert_eq!(array[0]["severity"].as_str(), Some("caution"));
        assert_eq!(array[0]["detail"].as_str(), Some("ARM64EC"));
    }

    #[test]
    fn absent_detail_serializes_as_null() {
        let json = Reason::new(ReasonCode::ArchitectureNative).to_json();
        assert!(json["detail"].is_null());
    }

    #[test]
    fn contains_finds_a_code() {
        let mut reasons = Reasons::new();
        reasons.add(ReasonCode::GraphicsBackendRequired);
        assert!(reasons.contains(ReasonCode::GraphicsBackendRequired));
        assert!(!reasons.contains(ReasonCode::PageSizeMismatch));
    }
}
