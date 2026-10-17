//! One compatibility observation.
//!
//! A [`Record`] is the atomic unit of COMPITUM's data asset: the statement *"this exact
//! binary, identified by SHA-256, was analysed against a host with these capabilities, and
//! the verdict was this."*
//!
//! # Why content addressing
//!
//! The subject is keyed on a hash of its bytes rather than on a filename or a version
//! string. That means two people who analyse the same release independently produce records
//! that join, and a record written today still refers to the same bytes in five years when
//! every filename and version number has changed.
//!
//! # What makes a record reusable
//!
//! A record is only useful to a second party if it captures *enough about the host* to
//! predict what will happen on a different one. Recording "it worked" is worthless.
//! Recording the host's architecture, page size, and exact capability set makes the
//! observation transferable: a future host can compute for itself whether its own
//! capabilities are a superset, and therefore whether the recorded verdict applies.
//!
//! That is the property [`Record::applies_to`] exists to provide.

use compitum_digest::{sha256_file, Digest};
use compitum_isa::{FeatureSet, HostProfile, IsaFeature};
use compitum_json::{Object, Value};

/// How an observation was obtained. Provenance is recorded because it determines how much
/// weight the observation deserves when it is reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Provenance {
    /// COMPITUM's own analysis, with no execution.
    ///
    /// The verdict is a prediction, derived from the binary's stated requirements and the
    /// host's stated capabilities. It is reproducible and requires no test subject to run.
    StaticAnalysis,
    /// The binary was actually executed on the recorded host and produced this outcome.
    ///
    /// Stronger evidence than [`Provenance::StaticAnalysis`] for the specific host recorded,
    /// but it observes one path rather than all paths, so it can miss a failure that a
    /// different input would trigger.
    ObservedExecution,
    /// Reported by a third party — an issue tracker, a forum post, a vendor statement.
    ///
    /// Weakest, and recorded separately so it can be excluded from statistical claims while
    /// still being visible to a human searching for "does this work anywhere".
    Reported,
}

impl Provenance {
    /// Stable identifier. Protocol value: never translated, never changed.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Provenance::StaticAnalysis => "static_analysis",
            Provenance::ObservedExecution => "observed_execution",
            Provenance::Reported => "reported",
        }
    }

    /// Parses a provenance tag.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "static_analysis" => Some(Provenance::StaticAnalysis),
            "observed_execution" => Some(Provenance::ObservedExecution),
            "reported" => Some(Provenance::Reported),
            _ => None,
        }
    }

    /// How much a reused observation should be trusted, as a permille weight.
    ///
    /// Used when aggregating many records about one binary into a single confidence. An
    /// observation from a person who ran the program counts for more than a report that it
    /// "should work".
    #[must_use]
    pub fn weight_permille(self) -> u16 {
        match self {
            Provenance::ObservedExecution => 1000,
            Provenance::StaticAnalysis => 700,
            Provenance::Reported => 300,
        }
    }
}

/// The outcome of an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// The route was carried out and the program behaved as intended.
    Success,
    /// The route was carried out, but something was wrong: a warning, a degraded path, a
    /// feature that did not work.
    Partial,
    /// The route could not be carried out, or the program failed.
    Failure,
    /// Not yet determined. Recorded so that a subject can be tracked before it is tested.
    Unknown,
}

impl Outcome {
    /// Stable identifier.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Partial => "partial",
            Outcome::Failure => "failure",
            Outcome::Unknown => "unknown",
        }
    }

    /// Parses an outcome tag.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "success" => Some(Outcome::Success),
            "partial" => Some(Outcome::Partial),
            "failure" => Some(Outcome::Failure),
            "unknown" => Some(Outcome::Unknown),
            _ => None,
        }
    }

    /// A single-character marker for compact tabular output.
    #[must_use]
    pub fn marker(self) -> char {
        match self {
            Outcome::Success => 'Y',
            Outcome::Partial => '~',
            Outcome::Failure => 'N',
            Outcome::Unknown => '?',
        }
    }
}

/// A host's identity and capabilities, captured at the time of observation.
///
/// Deliberately a *snapshot* rather than a reference to the live machine: the machine will
/// be replaced, and the record must outlive it. Only the fields that affect routing are
/// stored, because storing more would make records larger and less reusable without making
/// them more predictive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSnapshot {
    /// Architecture string, e.g. `"aarch64"`.
    pub arch: String,
    /// Memory page size in bytes — a genuine compatibility axis, not trivia.
    pub page_size: usize,
    /// Number of logical CPUs.
    pub cpu_count: usize,
    /// Kernel release string, for correlating kernel-specific behaviours.
    pub kernel: String,
    /// The exact CPU capability set, as stable feature identifiers.
    ///
    /// Stored as a sorted list of ids rather than as raw `HWCAP` bitmaps, because the
    /// bitmaps are renumbered by the kernel over time while the names are stable.
    pub features: Vec<String>,
}

impl HostSnapshot {
    /// Captures a host profile.
    #[must_use]
    pub fn capture(host: &HostProfile) -> Self {
        let mut features: Vec<String> = host
            .guaranteed_features()
            .iter()
            .map(|f| f.id().to_owned())
            .collect();
        features.sort();
        features.dedup();
        HostSnapshot {
            arch: host.arch.clone(),
            page_size: host.page_size,
            cpu_count: host.cpu_count,
            kernel: host.kernel.clone(),
            features,
        }
    }

    /// The recorded capabilities as a [`FeatureSet`].
    #[must_use]
    pub fn feature_set(&self) -> FeatureSet {
        self.features
            .iter()
            .filter_map(|id| IsaFeature::from_id(id))
            .collect()
    }

    /// A compact identity for grouping records by machine class.
    ///
    /// Two hosts with the same tag will produce the same routing decision for the same
    /// binary, so a record can be applied to both. Built from the properties that actually
    /// affect a decision: architecture, page size, and the capability set.
    #[must_use]
    pub fn class_tag(&self) -> String {
        let mut features = self.features.clone();
        features.sort();
        features.dedup();
        // A cheap structural digest. Not cryptographic: it is an index key, not a security
        // boundary, and collision would merely merge two similar host classes.
        let mut accumulator: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in self.arch.bytes().chain(self.page_size.to_le_bytes()) {
            accumulator ^= u64::from(byte);
            accumulator = accumulator.wrapping_mul(0x1000_0000_01b3);
        }
        for feature in &features {
            for byte in feature.bytes() {
                accumulator ^= u64::from(byte);
                accumulator = accumulator.wrapping_mul(0x1000_0000_01b3);
            }
        }
        format!(
            "{}-p{}-{:016x}",
            self.arch.replace('_', ""),
            self.page_size,
            accumulator
        )
    }

    /// Returns `true` when this snapshot's capabilities are a superset of `required`.
    ///
    /// The basis of reuse: if a recorded host had everything a binary needs and reported
    /// success, then a host with a superset of those capabilities will also succeed, and the
    /// record transfers without re-testing.
    #[must_use]
    pub fn satisfies(&self, required: &[String]) -> bool {
        let available = self.feature_set();
        required
            .iter()
            .filter_map(|id| IsaFeature::from_id(id))
            .all(|feature| available.contains(feature))
    }

    /// Returns `true` when this snapshot can explain a result about `required`, even if it
    /// is not a superset.
    ///
    /// A host *missing* a required feature is also informative: it tells us the binary needs
    /// that feature, which is exactly the fact a different host needs in order to decide.
    #[must_use]
    pub fn is_relevant_to(&self, required: &[String]) -> bool {
        required.iter().any(|id| self.features.contains(id))
            || required.is_empty()
            || self.arch.starts_with("aarch64")
    }

    /// Serializes the snapshot.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Object::new()
            .with("arch", self.arch.as_str())
            .with("page_size", self.page_size)
            .with("cpu_count", self.cpu_count)
            .with("kernel", self.kernel.as_str())
            .with("features", self.features.clone())
            .with("class_tag", self.class_tag())
            .into()
    }

    /// Parses a snapshot from JSON.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        let arch = value["arch"].as_str()?.to_owned();
        let page_size = value["page_size"].as_u64().unwrap_or(4096) as usize;
        let cpu_count = value["cpu_count"].as_u64().unwrap_or(1) as usize;
        let kernel = value["kernel"].as_str().unwrap_or("unknown").to_owned();
        let features = value["features"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        Some(HostSnapshot {
            arch,
            page_size,
            cpu_count,
            kernel,
            features,
        })
    }
}

/// One observation, ready to be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Schema version of the record itself, so old records stay interpretable.
    pub schema_version: u32,
    /// SHA-256 of the analysed binary. The primary key.
    pub subject_sha256: Digest,
    /// Size of the binary in bytes, a cheap secondary check on identity.
    pub subject_size: u64,
    /// A human-friendly label, typically a filename. **Not** part of the identity, because
    /// two people will name the same download differently.
    pub subject_label: Option<String>,
    /// The ABI family, as a stable id.
    pub abi_family: String,
    /// The route the router chose, as a stable id.
    pub route: String,
    /// Whether the plan was blocked.
    pub blocked: bool,
    /// Whether the route requires no translation at all.
    pub fully_native: bool,
    /// Plan confidence in permille.
    pub confidence_permille: u16,
    /// The capability set the router believed the binary requires.
    pub required_features: Vec<String>,
    /// A stable identity for the host class this was observed on.
    pub host_class: String,
    /// The host snapshot.
    pub host: HostSnapshot,
    /// The outcome.
    pub outcome: Outcome,
    /// How the observation was obtained.
    pub provenance: Provenance,
    /// Unix timestamp in seconds, or zero when unknown.
    ///
    /// Zero is used rather than an invented value because a fabricated timestamp would be
    /// worse than an absent one: it would appear in ordering and age calculations as though
    /// it were real.
    pub observed_at: i64,
    /// One-line English note from the operator, for the human reading the ledger.
    pub note: Option<String>,
}

/// The record schema version written by this build.
pub const RECORD_SCHEMA_VERSION: u32 = 1;

impl Record {
    /// Builds a record for a completed static analysis.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn statically_analysed(
        subject_sha256: Digest,
        subject_size: u64,
        subject_label: Option<String>,
        abi_family: &str,
        route: &str,
        blocked: bool,
        fully_native: bool,
        confidence_permille: u16,
        required_features: Vec<String>,
        host: HostSnapshot,
        observed_at: i64,
    ) -> Self {
        Record {
            schema_version: RECORD_SCHEMA_VERSION,
            subject_sha256,
            subject_size,
            subject_label,
            abi_family: abi_family.to_owned(),
            route: route.to_owned(),
            blocked,
            fully_native,
            confidence_permille,
            required_features,
            host_class: host.class_tag(),
            host,
            outcome: Outcome::Unknown,
            provenance: Provenance::StaticAnalysis,
            observed_at,
            note: None,
        }
    }

    /// Records an observed execution outcome.
    #[must_use]
    pub fn with_outcome(mut self, outcome: Outcome, provenance: Provenance, note: Option<String>) -> Self {
        self.outcome = outcome;
        self.provenance = provenance;
        self.note = note;
        self
    }

    /// Returns `true` when this record's verdict can be reused for the given host.
    ///
    /// Reuse requires three things: the recorded host must have implemented everything the
    /// binary requires, the outcome must have been a success, and the new host must be at
    /// least as capable. Anything else is a new question, not an answered one.
    ///
    /// A `Failure` on a host *missing* a feature is also reusable in the negative direction:
    /// it proves that feature is required, which tells a new host to check for it.
    #[must_use]
    pub fn applies_to(&self, candidate: &HostSnapshot) -> bool {
        if self.outcome == Outcome::Success {
            // A success transfers upward: a more capable host will also succeed, provided
            // the architectural and page-size assumptions are unchanged.
            return candidate.arch == self.host.arch
                && candidate.page_size == self.host.page_size
                && self.host.satisfies(&self.required_features)
                && candidate.satisfies(&self.required_features);
        }
        if self.outcome == Outcome::Failure {
            // A recorded failure is reusable only when we can say *why* it failed and the
            // candidate fails for the same reason.
            //
            // The cause is the set of required features the recorded host did not
            // implement. An earlier revision of this function computed the opposite —
            // features the recorded host *had* that the candidate lacks — which answers a
            // different question entirely and made every genuine failure untransferable.
            // The test suite caught it; see `failure_direction_is_correct`.
            let required = self.required_feature_set();
            let recorded_lacked = required.difference(self.host.feature_set());

            if recorded_lacked.is_empty() {
                // The recorded host implemented everything the binary required, so the
                // failure had some other cause. That is not evidence of a capability gap,
                // and must not be presented as one.
                return false;
            }

            // The candidate reproduces the failure exactly when it lacks every feature the
            // recorded host lacked.
            let candidate_lacks = recorded_lacked.difference(candidate.feature_set());
            return candidate.arch == self.host.arch && candidate_lacks == recorded_lacked;
        }
        false
    }

    /// The required features as a set, for capability arithmetic.
    #[must_use]
    pub fn required_feature_set(&self) -> FeatureSet {
        self.required_features
            .iter()
            .filter_map(|id| IsaFeature::from_id(id))
            .collect()
    }

    /// The ledger key, which is the subject digest.
    #[must_use]
    pub fn key(&self) -> String {
        self.subject_sha256.to_hex()
    }

    /// Serializes the record to one line of JSON.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Object::new()
            .with("schema_version", self.schema_version)
            .with("subject_sha256", self.subject_sha256.to_hex())
            .with("subject_size", self.subject_size)
            .with("subject_label", self.subject_label.as_deref())
            .with("abi_family", self.abi_family.as_str())
            .with("route", self.route.as_str())
            .with("blocked", self.blocked)
            .with("fully_native", self.fully_native)
            .with("confidence_permille", self.confidence_permille)
            .with("required_features", self.required_features.clone())
            .with("host_class", self.host_class.as_str())
            .with("host", self.host.to_json())
            .with("outcome", self.outcome.id())
            .with("provenance", self.provenance.id())
            .with("observed_at", self.observed_at)
            .with("note", self.note.as_deref())
            .into()
    }

    /// Parses a record from JSON.
    ///
    /// Returns `None` for a record that cannot be interpreted, so that one corrupt line in
    /// a ledger does not make the whole file unreadable. A ledger is expected to accumulate
    /// records across versions, and refusing to read it because of one bad entry would
    /// defeat its purpose.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        let digest = Digest::from_hex(value["subject_sha256"].as_str()?).ok()?;
        let host = HostSnapshot::from_json(&value["host"])?;
        Some(Record {
            schema_version: value["schema_version"].as_u64().unwrap_or(1) as u32,
            subject_sha256: digest,
            subject_size: value["subject_size"].as_u64().unwrap_or(0),
            subject_label: value["subject_label"].as_str().map(str::to_owned),
            abi_family: value["abi_family"].as_str().unwrap_or("unknown").to_owned(),
            route: value["route"].as_str().unwrap_or("refused").to_owned(),
            blocked: value["blocked"].as_bool().unwrap_or(false),
            fully_native: value["fully_native"].as_bool().unwrap_or(false),
            confidence_permille: value["confidence_permille"].as_u64().unwrap_or(0) as u16,
            required_features: value["required_features"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            host_class: value["host_class"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| host.class_tag()),
            host,
            outcome: value["outcome"]
                .as_str()
                .and_then(Outcome::from_id)
                .unwrap_or(Outcome::Unknown),
            provenance: value["provenance"]
                .as_str()
                .and_then(Provenance::from_id)
                .unwrap_or(Provenance::StaticAnalysis),
            observed_at: value["observed_at"].as_i64().unwrap_or(0),
            note: value["note"].as_str().map(str::to_owned),
        })
    }

    /// Renders one human-readable line for the CLI's table output.
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "{} {} {} {:24} {:22} {}",
            self.subject_sha256.short(),
            self.outcome.marker(),
            if self.blocked { "blocked" } else { "       " },
            self.abi_family,
            self.route,
            self.subject_label.as_deref().unwrap_or("(unlabelled)")
        )
    }
}

/// Computes the identity of a file for storage as a record key.
///
/// # Errors
///
/// Returns a description of the I/O failure.
pub fn identify(path: &std::path::Path) -> Result<(Digest, u64), String> {
    let digest = sha256_file(path)?;
    let size = std::fs::metadata(path)
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?
        .len();
    Ok((digest, size))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_with(features: &[&str]) -> HostSnapshot {
        HostSnapshot {
            arch: "aarch64".to_owned(),
            page_size: 4096,
            cpu_count: 8,
            kernel: "6.1.0-test".to_owned(),
            features: features.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn digest_of(text: &str) -> Digest {
        compitum_digest::sha256(text.as_bytes())
    }

    #[test]
    fn provenance_weights_rank_observation_highest() {
        assert!(
            Provenance::ObservedExecution.weight_permille()
                > Provenance::StaticAnalysis.weight_permille()
        );
        assert!(
            Provenance::StaticAnalysis.weight_permille() > Provenance::Reported.weight_permille()
        );
    }

    #[test]
    fn provenance_and_outcome_round_trip_through_ids() {
        for provenance in [
            Provenance::StaticAnalysis,
            Provenance::ObservedExecution,
            Provenance::Reported,
        ] {
            assert_eq!(Provenance::from_id(provenance.id()), Some(provenance));
        }
        for outcome in [
            Outcome::Success,
            Outcome::Partial,
            Outcome::Failure,
            Outcome::Unknown,
        ] {
            assert_eq!(Outcome::from_id(outcome.id()), Some(outcome));
        }
        assert_eq!(Provenance::from_id("nonsense"), None);
        assert_eq!(Outcome::from_id("nonsense"), None);
    }

    #[test]
    fn outcome_markers_are_distinct() {
        let markers: Vec<char> = [Outcome::Success, Outcome::Partial, Outcome::Failure, Outcome::Unknown]
            .iter()
            .map(|o| o.marker())
            .collect();
        let unique: std::collections::BTreeSet<char> = markers.iter().copied().collect();
        assert_eq!(unique.len(), 4);
    }

    #[test]
    fn host_class_tag_is_stable_and_sensitive() {
        let a = host_with(&["fp", "asimd", "sve2"]);
        let b = host_with(&["sve2", "asimd", "fp"]); // same set, different order
        assert_eq!(a.class_tag(), b.class_tag(), "order must not matter");

        let c = host_with(&["fp", "asimd"]);
        assert_ne!(a.class_tag(), c.class_tag(), "a missing feature must change the class");

        // Page size is a real compatibility axis and must affect the class.
        let mut d = a.clone();
        d.page_size = 16384;
        assert_ne!(a.class_tag(), d.class_tag());
    }

    #[test]
    fn satisfies_checks_feature_superset() {
        let host = host_with(&["fp", "asimd", "sve2"]);
        assert!(host.satisfies(&["fp".to_owned()]));
        assert!(host.satisfies(&["fp".to_owned(), "sve2".to_owned()]));
        assert!(!host.satisfies(&["sme".to_owned()]));
        // An empty requirement is trivially satisfied.
        assert!(host.satisfies(&[]));
    }

    #[test]
    fn success_transfers_to_a_more_capable_host() {
        let recorded = host_with(&["fp", "asimd"]);
        let record = Record::statically_analysed(
            digest_of("x"),
            10,
            None,
            "arm64",
            "native",
            false,
            true,
            1000,
            vec!["fp".to_owned()],
            recorded.clone(),
            0,
        )
        .with_outcome(Outcome::Success, Provenance::ObservedExecution, None);

        let better = host_with(&["fp", "asimd", "sve2"]);
        assert!(record.applies_to(&better), "a superset host must inherit a success");

        let worse = host_with(&["asimd"]);
        assert!(!record.applies_to(&worse), "a host missing a required feature must not");
    }

    #[test]
    fn success_does_not_transfer_across_page_size() {
        let recorded = host_with(&["fp", "asimd"]);
        let record = Record::statically_analysed(
            digest_of("x"),
            10,
            None,
            "arm64",
            "native",
            false,
            true,
            1000,
            vec!["fp".to_owned()],
            recorded,
            0,
        )
        .with_outcome(Outcome::Success, Provenance::ObservedExecution, None);

        let mut different = host_with(&["fp", "asimd"]);
        different.page_size = 16384;
        assert!(
            !record.applies_to(&different),
            "a different page size is a different question"
        );
    }

    #[test]
    fn failure_transfers_downward_when_the_same_feature_is_missing() {
        // The recorded host was missing SME, which is why the binary was refused.
        let recorded = host_with(&["fp", "asimd", "sve2"]);
        let record = Record::statically_analysed(
            digest_of("y"),
            10,
            None,
            "arm64",
            "refused",
            true,
            false,
            900,
            vec!["sme".to_owned()],
            recorded,
            0,
        )
        .with_outcome(Outcome::Failure, Provenance::ObservedExecution, None);

        // A host that also lacks SME must be predicted to fail the same way.
        let also_missing = host_with(&["fp", "asimd"]);
        assert!(record.applies_to(&also_missing));

        // A host that *has* SME is a genuinely open question, not a known failure.
        let has_it = host_with(&["fp", "asimd", "sme"]);
        assert!(
            !record.applies_to(&has_it),
            "a more capable host is a new question, not an inherited failure"
        );
    }

    /// Regression guard for the inverted-direction bug.
    ///
    /// The first implementation asked "does the recorded host have something the candidate
    /// lacks", which is the reverse of "did the recorded host lack something the binary
    /// needed". Under that version a failure never transferred to the host that would
    /// actually reproduce it, while a host with an *extra* feature could appear to.
    #[test]
    fn failure_direction_is_correct() {
        let recorded = host_with(&["fp", "asimd"]); // lacks sve2
        let record = Record::statically_analysed(
            digest_of("direction"),
            1,
            None,
            "arm64",
            "refused",
            true,
            false,
            900,
            vec!["sve2".to_owned()],
            recorded,
            0,
        )
        .with_outcome(Outcome::Failure, Provenance::ObservedExecution, None);

        // Lacks the same feature: the failure applies.
        assert!(record.applies_to(&host_with(&["fp"])));
        // Has the missing feature: it does not.
        assert!(!record.applies_to(&host_with(&["fp", "asimd", "sve2"])));
        // A superset of the recorded host that still lacks sve2: the failure applies,
        // because a host having *more* unrelated features does not change the cause.
        assert!(record.applies_to(&host_with(&["fp", "asimd", "crc32"])));
    }

    #[test]
    fn a_failure_with_no_capability_gap_does_not_transfer() {
        // The recorded host implemented everything required, so the failure had another
        // cause. Claiming it transfers would be presenting an unknown as a prediction.
        let record = Record::statically_analysed(
            digest_of("nogap"),
            1,
            None,
            "arm64",
            "native",
            false,
            true,
            1000,
            vec!["fp".to_owned()],
            host_with(&["fp", "asimd"]),
            0,
        )
        .with_outcome(Outcome::Failure, Provenance::ObservedExecution, None);

        assert!(!record.applies_to(&host_with(&["fp", "asimd", "sve2"])));
        assert!(!record.applies_to(&host_with(&["fp"])));
    }

    #[test]
    fn unknown_outcome_never_applies() {
        let host = host_with(&["fp"]);
        let record = Record::statically_analysed(
            digest_of("z"),
            10,
            None,
            "arm64",
            "native",
            false,
            true,
            1000,
            vec!["fp".to_owned()],
            host.clone(),
            0,
        );
        assert_eq!(record.outcome, Outcome::Unknown);
        assert!(!record.applies_to(&host), "an undetermined record answers nothing");
    }

    #[test]
    fn record_json_round_trips() {
        let host = host_with(&["fp", "asimd", "i8mm"]);
        let original = Record::statically_analysed(
            digest_of("round-trip"),
            42,
            Some("app.exe".to_owned()),
            "arm64ec",
            "fex_partial",
            false,
            false,
            700,
            vec!["fp".to_owned(), "i8mm".to_owned()],
            host,
            1_700_000_000,
        )
        .with_outcome(Outcome::Partial, Provenance::ObservedExecution, Some("sound missing".to_owned()));

        let json = original.to_json();
        let restored = Record::from_json(&json).expect("must round-trip");
        assert_eq!(restored, original);
    }

    #[test]
    fn json_uses_the_documented_protocol_keys() {
        let record = Record::statically_analysed(
            digest_of("keys"),
            7,
            None,
            "arm64",
            "native",
            false,
            true,
            1000,
            vec![],
            host_with(&["fp"]),
            0,
        );
        let json = record.to_json();
        assert_eq!(json["schema_version"].as_u64(), Some(1));
        assert_eq!(json["abi_family"].as_str(), Some("arm64"));
        assert_eq!(json["route"].as_str(), Some("native"));
        assert_eq!(json["fully_native"].as_bool(), Some(true));
        assert_eq!(json["outcome"].as_str(), Some("unknown"));
        assert_eq!(json["provenance"].as_str(), Some("static_analysis"));
        assert_eq!(json["subject_sha256"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn a_corrupt_record_does_not_poison_parsing() {
        // Missing the digest entirely: uninterpretable, must return None rather than panic.
        assert!(Record::from_json(&Value::object()).is_none());
        // A bad digest string.
        let mut obj = Object::new();
        obj.insert("subject_sha256", "not-a-digest");
        obj.insert("host", Object::new().with("arch", "aarch64"));
        assert!(Record::from_json(&Value::Object(obj)).is_none());
    }

    #[test]
    fn unknown_enums_in_stored_json_degrade_rather_than_fail() {
        // A ledger written by a future version may name an outcome this build does not know.
        // Reading it as Unknown keeps the record visible instead of discarding it.
        let mut json = Record::statically_analysed(
            digest_of("future"),
            1,
            None,
            "arm64",
            "native",
            false,
            true,
            1000,
            vec![],
            host_with(&["fp"]),
            0,
        )
        .to_json();
        if let Some(obj) = json.as_object_mut() {
            obj.insert("outcome", "something_new");
        }
        let restored = Record::from_json(&json).expect("must still parse");
        assert_eq!(restored.outcome, Outcome::Unknown);
    }

    #[test]
    fn timestamp_zero_is_preserved_not_invented() {
        let record = Record::statically_analysed(
            digest_of("ts"),
            1,
            None,
            "arm64",
            "native",
            false,
            true,
            1000,
            vec![],
            host_with(&["fp"]),
            0,
        );
        assert_eq!(record.observed_at, 0);
        assert_eq!(Record::from_json(&record.to_json()).unwrap().observed_at, 0);
    }

    #[test]
    fn key_is_the_full_hex_digest() {
        let record = Record::statically_analysed(
            digest_of("key"),
            1,
            None,
            "arm64",
            "native",
            false,
            true,
            1000,
            vec![],
            host_with(&["fp"]),
            0,
        );
        assert_eq!(record.key().len(), 64);
        assert_eq!(record.key(), record.subject_sha256.to_hex());
    }

    #[test]
    fn summary_line_is_readable() {
        let record = Record::statically_analysed(
            digest_of("summary"),
            1,
            Some("tool.exe".to_owned()),
            "arm64",
            "native",
            false,
            true,
            1000,
            vec![],
            host_with(&["fp"]),
            0,
        )
        .with_outcome(Outcome::Success, Provenance::ObservedExecution, None);
        let line = record.summary_line();
        assert!(line.contains("Y"));
        assert!(line.contains("arm64"));
        assert!(line.contains("native"));
        assert!(line.contains("tool.exe"));
    }

    #[test]
    fn identify_matches_a_direct_hash() {
        let dir = std::env::temp_dir().join("compitum-oracle-identify");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("subject.bin");
        std::fs::write(&path, b"abc").unwrap();

        let (digest, size) = identify(&path).unwrap();
        assert_eq!(digest, compitum_digest::sha256(b"abc"));
        assert_eq!(size, 3);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn identify_reports_a_missing_file_clearly() {
        let error = identify(std::path::Path::new("/nonexistent/x.bin")).unwrap_err();
        assert!(error.contains("cannot open"));
    }
}
