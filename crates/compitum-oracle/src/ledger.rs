//! The ledger store: an append-only JSON Lines file of [`Record`]s.
//!
//! # Why JSON Lines and not SQLite
//!
//! The ledger must remain readable in ten years, on a machine that has none of today's
//! software. A line-delimited JSON file satisfies that: `cat`, `grep` and a text editor are
//! enough, and a partial write corrupts one line rather than the whole database.
//!
//! It also makes the ledger trivially diffable and mergeable between contributors, which
//! matters because the asset's value comes from many people contributing observations. A
//! binary database file cannot be merged with `git merge`; a text log can.
//!
//! # Append-only, with one deliberate exception
//!
//! New observations are only ever appended. But the same subject is frequently observed
//! again — on a different host, or with an execution outcome after a static analysis — and
//! keeping every version would make queries return contradictory answers with no way to
//! tell which is current. [`Ledger::record`] therefore *folds* a new observation into the
//! existing newest record for the same subject and host class, and rewrites that one line.
//! Every other line is untouched.
//!
//! # Failure policy
//!
//! A ledger is expected to accumulate records across versions of the tool and of the schema.
//! An unreadable line is therefore skipped and counted, never fatal: refusing to open a
//! ledger because one entry was written by a newer version would defeat the purpose of
//! keeping it.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use compitum_json::{Value, parse};
use compitum_router::Plan;

use crate::record::{HostSnapshot, Outcome, Record, RECORD_SCHEMA_VERSION};

/// What happened when a ledger line was read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadStats {
    /// Lines that were blank or held only whitespace.
    pub blank_lines: usize,
    /// Lines that parsed into a usable record.
    pub records_loaded: usize,
    /// Lines that could not be interpreted. Not an error: see the module documentation.
    pub unreadable_lines: usize,
}

impl LoadStats {
    /// Total number of lines examined, excluding the final empty one.
    #[must_use]
    pub fn total_lines(&self) -> usize {
        self.blank_lines + self.records_loaded + self.unreadable_lines
    }

    /// Returns `true` when the ledger was read without discarding anything.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.unreadable_lines == 0
    }
}

/// A failure while writing to the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// The ledger file could not be opened for appending.
    CannotOpen {
        /// Path that was attempted.
        path: String,
        /// The underlying message.
        message: String,
    },
    /// A write failed partway through.
    CannotWrite {
        /// Path that was attempted.
        path: String,
        /// The underlying message.
        message: String,
    },
    /// A record could not be rendered to JSON.
    CannotSerialize {
        /// Why.
        message: String,
    },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::CannotOpen { path, message } => {
                write!(f, "cannot open the ledger at {path}: {message}")
            }
            LedgerError::CannotWrite { path, message } => {
                write!(f, "cannot write to the ledger at {path}: {message}")
            }
            LedgerError::CannotSerialize { message } => {
                write!(f, "cannot serialize the record: {message}")
            }
        }
    }
}

impl std::error::Error for LedgerError {}

/// An append-only compatibility ledger.
#[derive(Debug, Clone)]
pub struct Ledger {
    path: PathBuf,
    records: Vec<Record>,
    stats: LoadStats,
    /// Set when the file did not exist at open time, so the header comment is written once.
    freshly_created: bool,
}

impl Ledger {
    /// Opens a ledger at `path`, creating it when missing.
    ///
    /// A missing file is not an error and not a silent success: the ledger records that it
    /// was created, so that a caller can distinguish "no observations yet" from "the path
    /// was wrong and we started an empty file somewhere unintended".
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the parent directory cannot be created or the file
    /// cannot be read.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, LedgerError> {
        let path = path.into();
        let freshly_created = !path.exists();

        if freshly_created {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).map_err(|e| LedgerError::CannotOpen {
                        path: parent.display().to_string(),
                        message: e.to_string(),
                    })?;
                }
            }
        }

        let (records, stats) = if freshly_created {
            (Vec::new(), LoadStats::default())
        } else {
            let text = std::fs::read_to_string(&path).map_err(|e| LedgerError::CannotOpen {
                path: path.display().to_string(),
                message: e.to_string(),
            })?;
            load_lines(&text)
        };

        Ok(Ledger {
            path,
            records,
            stats,
            freshly_created,
        })
    }

    /// Opens an in-memory ledger with no file behind it.
    ///
    /// Used by tests and by any caller that wants to accumulate records without committing
    /// to a path.
    #[must_use]
    pub fn in_memory() -> Self {
        Ledger {
            path: PathBuf::new(),
            records: Vec::new(),
            stats: LoadStats::default(),
            freshly_created: true,
        }
    }

    /// Returns `true` when the ledger is backed by a file.
    #[must_use]
    pub fn is_persistent(&self) -> bool {
        !self.path.as_os_str().is_empty()
    }

    /// The ledger's path, empty for an in-memory ledger.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Statistics from reading the file.
    #[must_use]
    pub fn stats(&self) -> LoadStats {
        self.stats
    }

    /// Every record, in file order.
    #[must_use]
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Number of records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` when no observations have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Whether the underlying file had to be created on open.
    #[must_use]
    pub fn was_created(&self) -> bool {
        self.freshly_created
    }

    /// Adds an observation, folding it into an existing record when one covers the same
    /// subject and host class.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the record cannot be serialized or written.
    pub fn record(&mut self, record: Record) -> Result<RecordAction, LedgerError> {
        let digest = record.subject_sha256;
        let host_class = record.host_class.clone();

        // Find an existing observation of this subject on this host class. The most recent
        // one wins, because the newest measurement is the least likely to be stale.
        let existing = self
            .records
            .iter()
            .rposition(|r| r.subject_sha256 == digest && r.host_class == host_class);

        let action = match existing {
            Some(index) => {
                let previous = self.records[index].clone();
                // Never downgrade evidence: a static analysis must not overwrite an
                // observed execution, and an observed outcome must not be replaced by a
                // prediction.
                let keep_outcome = previous.provenance.weight_permille()
                    > record.provenance.weight_permille();
                let merged = if keep_outcome {
                    Record {
                        outcome: previous.outcome,
                        provenance: previous.provenance,
                        note: previous.note.clone(),
                        ..record
                    }
                } else {
                    record
                };
                self.records[index] = merged.clone();
                self.rewrite_file()?;
                RecordAction::Updated { index }
            }
            None => {
                self.records.push(record.clone());
                self.append_line(&record)?;
                RecordAction::Appended
            }
        };
        Ok(action)
    }

    /// Every record about one subject, across all host classes.
    #[must_use]
    pub fn for_subject(&self, digest: &compitum_digest::Digest) -> Vec<&Record> {
        self.records
            .iter()
            .filter(|r| r.subject_sha256 == *digest)
            .collect()
    }

    /// Every record that applies to the given host.
    ///
    /// This is the query that makes the ledger worth keeping: a new machine asks "has anyone
    /// already determined what happens here?" and gets an answer derived from other people's
    /// observations, without re-running anything.
    #[must_use]
    pub fn applicable_to(&self, host: &HostSnapshot) -> Vec<&Record> {
        self.records
            .iter()
            .filter(|r| r.applies_to(host))
            .collect()
    }

    /// The best available answer for a subject on a host, if any.
    ///
    /// Prefers an observed execution over a prediction, and within that prefers the most
    /// recent. Returns `None` when nothing recorded bears on the question — which is the
    /// honest answer, not a default verdict.
    #[must_use]
    pub fn best_for(
        &self,
        digest: &compitum_digest::Digest,
        host: &HostSnapshot,
    ) -> Option<&Record> {
        self.records
            .iter()
            .filter(|r| r.subject_sha256 == *digest && r.applies_to(host))
            .max_by_key(|r| (r.provenance.weight_permille(), r.observed_at))
    }

    /// Groups records by their route, for the statistics report.
    #[must_use]
    pub fn count_by_route(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for record in &self.records {
            *counts.entry(record.route.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Groups records by their outcome, for the statistics report.
    #[must_use]
    pub fn count_by_outcome(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for record in &self.records {
            *counts.entry(record.outcome.id().to_owned()).or_insert(0) += 1;
        }
        counts
    }

    /// Groups records by host class.
    #[must_use]
    pub fn count_by_host_class(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for record in &self.records {
            *counts.entry(record.host_class.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Number of distinct subjects observed.
    #[must_use]
    pub fn distinct_subjects(&self) -> usize {
        let mut seen = std::collections::BTreeSet::new();
        for record in &self.records {
            seen.insert(record.subject_sha256);
        }
        seen.len()
    }

    /// How many observations carry a determined outcome, as opposed to a prediction.
    #[must_use]
    pub fn determined_outcomes(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.outcome != Outcome::Unknown)
            .count()
    }

    /// Serializes the summary the statistics command prints.
    #[must_use]
    pub fn summary_json(&self) -> Value {
        let by_route: Vec<Value> = self
            .count_by_route()
            .into_iter()
            .map(|(route, count)| {
                compitum_json::Object::new()
                    .with("route", route)
                    .with("count", count)
                    .into()
            })
            .collect();
        let by_outcome: Vec<Value> = self
            .count_by_outcome()
            .into_iter()
            .map(|(outcome, count)| {
                compitum_json::Object::new()
                    .with("outcome", outcome)
                    .with("count", count)
                    .into()
            })
            .collect();
        let by_host: Vec<Value> = self
            .count_by_host_class()
            .into_iter()
            .map(|(host_class, count)| {
                compitum_json::Object::new()
                    .with("host_class", host_class)
                    .with("count", count)
                    .into()
            })
            .collect();

        compitum_json::Object::new()
            .with("schema_version", RECORD_SCHEMA_VERSION)
            .with("ledger_path", self.path.display().to_string())
            .with("persistent", self.is_persistent())
            .with("total_records", self.records.len())
            .with("distinct_subjects", self.distinct_subjects())
            .with("determined_outcomes", self.determined_outcomes())
            .with("unreadable_lines", self.stats.unreadable_lines)
            .with("by_route", by_route)
            .with("by_outcome", by_outcome)
            .with("by_host_class", by_host)
            .into()
    }

    /// Appends one record as a line of JSON.
    fn append_line(&self, record: &Record) -> Result<(), LedgerError> {
        if !self.is_persistent() {
            return Ok(());
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| LedgerError::CannotOpen {
                path: self.path.display().to_string(),
                message: e.to_string(),
            })?;
        let line = record.to_json().to_string();
        writeln!(file, "{line}").map_err(|e| LedgerError::CannotWrite {
            path: self.path.display().to_string(),
            message: e.to_string(),
        })
    }

    /// Rewrites the whole file from memory.
    ///
    /// Only used when folding a new observation into an existing one, which is the single
    /// case that cannot be expressed as an append. Writes to a temporary file and renames,
    /// so an interrupted rewrite leaves the previous ledger intact rather than truncated.
    fn rewrite_file(&self) -> Result<(), LedgerError> {
        if !self.is_persistent() {
            return Ok(());
        }
        let temporary = self.path.with_extension("jsonl.tmp");
        {
            let mut file =
                std::fs::File::create(&temporary).map_err(|e| LedgerError::CannotWrite {
                    path: temporary.display().to_string(),
                    message: e.to_string(),
                })?;
            for record in &self.records {
                let line = record.to_json().to_string();
                writeln!(file, "{line}").map_err(|e| LedgerError::CannotWrite {
                    path: temporary.display().to_string(),
                    message: e.to_string(),
                })?;
            }
            file.flush().map_err(|e| LedgerError::CannotWrite {
                path: temporary.display().to_string(),
                message: e.to_string(),
            })?;
        }
        std::fs::rename(&temporary, &self.path).map_err(|e| LedgerError::CannotWrite {
            path: self.path.display().to_string(),
            message: e.to_string(),
        })
    }

    /// Records a routing plan as a static analysis.
    ///
    /// The shorthand that makes observation automatic: every `inspect` or `verify` the CLI
    /// performs becomes ledger data without the operator doing anything extra, which is how
    /// the dataset grows without anyone being asked to contribute.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the record cannot be stored.
    pub fn record_plan(
        &mut self,
        plan: &Plan,
        digest: compitum_digest::Digest,
        size: u64,
        abi_family: &str,
        host: &HostSnapshot,
        observed_at: i64,
    ) -> Result<RecordAction, LedgerError> {
        let required_features: Vec<String> = plan
            .reasons
            .items()
            .iter()
            .filter(|r| r.code == compitum_router::ReasonCode::IsaFeaturesMissing)
            .filter_map(|r| r.detail.clone())
            .flat_map(|detail| {
                // The detail is "this host does not implement: a, b, c"; recover the ids.
                detail
                    .split_once(':')
                    .map(|(_, list)| {
                        list.split(',')
                            .map(|s| s.trim().to_owned())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .collect();

        let record = Record::statically_analysed(
            digest,
            size,
            plan.subject.clone(),
            abi_family,
            plan.route.id(),
            plan.is_blocked(),
            plan.is_fully_native(),
            plan.confidence.permille(),
            required_features,
            host.clone(),
            observed_at,
        );
        self.record(record)
    }
}

/// What [`Ledger::record`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordAction {
    /// A new line was appended.
    Appended,
    /// An existing line was replaced by an updated observation.
    Updated {
        /// Index of the replaced record.
        index: usize,
    },
}

impl RecordAction {
    /// A word for the CLI to print.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            RecordAction::Appended => "appended",
            RecordAction::Updated { .. } => "updated",
        }
    }
}

/// Reads a ledger's text into records and statistics.
fn load_lines(text: &str) -> (Vec<Record>, LoadStats) {
    let mut records = Vec::new();
    let mut stats = LoadStats::default();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            stats.blank_lines += 1;
            continue;
        }
        match parse(trimmed).ok().and_then(|value| Record::from_json(&value)) {
            Some(record) => {
                records.push(record);
                stats.records_loaded += 1;
            }
            None => stats.unreadable_lines += 1,
        }
    }
    (records, stats)
}

/// The default ledger location for this user.
///
/// Follows the XDG base-directory convention so that the ledger lives with the rest of a
/// user's data rather than beside whatever directory they happened to be in.
#[must_use]
pub fn default_path() -> PathBuf {
    if let Ok(explicit) = std::env::var("COMPITUM_LEDGER") {
        if !explicit.is_empty() {
            return PathBuf::from(explicit);
        }
    }
    let base = std::env::var("XDG_DATA_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .filter(|s| !s.is_empty())
                .map(|home| PathBuf::from(home).join(".local/share"))
        })
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("compitum").join("ledger.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{HostSnapshot, Provenance};

    fn host(features: &[&str]) -> HostSnapshot {
        HostSnapshot {
            arch: "aarch64".to_owned(),
            page_size: 4096,
            cpu_count: 8,
            kernel: "6.1.0-test".to_owned(),
            features: features.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn record_for(text: &str, host: &HostSnapshot) -> Record {
        Record::statically_analysed(
            compitum_digest::sha256(text.as_bytes()),
            text.len() as u64,
            Some(format!("{text}.exe")),
            "arm64",
            "native",
            false,
            true,
            1000,
            vec!["fp".to_owned()],
            host.clone(),
            1_700_000_000,
        )
    }

    fn temp_ledger(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("compitum-oracle-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.jsonl"));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn a_new_ledger_is_created_and_empty() {
        let path = temp_ledger("new");
        let ledger = Ledger::open(&path).unwrap();
        assert!(ledger.is_empty());
        assert!(ledger.was_created());
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn records_persist_across_reopen() {
        let path = temp_ledger("persist");
        {
            let mut ledger = Ledger::open(&path).unwrap();
            let action = ledger.record(record_for("alpha", &host(&["fp"]))).unwrap();
            assert_eq!(action, RecordAction::Appended);
            assert_eq!(ledger.len(), 1);
        }

        let reopened = Ledger::open(&path).unwrap();
        assert_eq!(reopened.len(), 1);
        assert!(reopened.stats().is_clean());
        assert_eq!(reopened.records()[0].subject_label.as_deref(), Some("alpha.exe"));
        assert!(!reopened.was_created());
    }

    #[test]
    fn identical_observations_fold_into_one_line() {
        let path = temp_ledger("fold");
        let mut ledger = Ledger::open(&path).unwrap();
        let host = host(&["fp"]);

        assert_eq!(
            ledger.record(record_for("same", &host)).unwrap(),
            RecordAction::Appended
        );
        let action = ledger.record(record_for("same", &host)).unwrap();
        assert!(matches!(action, RecordAction::Updated { .. }));
        assert_eq!(ledger.len(), 1, "the same subject and host must not duplicate");

        // And the file on disk must agree with memory.
        let reopened = Ledger::open(&path).unwrap();
        assert_eq!(reopened.len(), 1);
    }

    #[test]
    fn different_host_classes_are_separate_records() {
        let path = temp_ledger("hosts");
        let mut ledger = Ledger::open(&path).unwrap();
        ledger.record(record_for("multi", &host(&["fp"]))).unwrap();
        ledger.record(record_for("multi", &host(&["fp", "sve2"]))).unwrap();
        assert_eq!(ledger.len(), 2, "a different host is a different observation");
    }

    #[test]
    fn a_static_analysis_never_overwrites_an_observed_execution() {
        let path = temp_ledger("evidence");
        let mut ledger = Ledger::open(&path).unwrap();
        let host = host(&["fp"]);

        let observed = record_for("evidence", &host)
            .with_outcome(Outcome::Success, Provenance::ObservedExecution, Some("ran fine".into()));
        ledger.record(observed).unwrap();

        // A later static analysis of the same file must not erase the measurement.
        ledger.record(record_for("evidence", &host)).unwrap();

        let stored = &ledger.records()[0];
        assert_eq!(stored.outcome, Outcome::Success);
        assert_eq!(stored.provenance, Provenance::ObservedExecution);
        assert_eq!(stored.note.as_deref(), Some("ran fine"));
    }

    #[test]
    fn a_stronger_observation_does_replace_a_weaker_one() {
        let path = temp_ledger("upgrade");
        let mut ledger = Ledger::open(&path).unwrap();
        let host = host(&["fp"]);

        ledger.record(record_for("upgrade", &host)).unwrap();
        assert_eq!(ledger.records()[0].outcome, Outcome::Unknown);

        let observed = record_for("upgrade", &host)
            .with_outcome(Outcome::Failure, Provenance::ObservedExecution, None);
        ledger.record(observed).unwrap();

        assert_eq!(ledger.records()[0].outcome, Outcome::Failure);
        assert_eq!(ledger.records()[0].provenance, Provenance::ObservedExecution);
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn an_unreadable_line_is_skipped_and_counted_not_fatal() {
        let path = temp_ledger("corrupt");
        let good = record_for("good", &host(&["fp"])).to_json().to_string();
        std::fs::write(
            &path,
            format!(
                "# a comment line\n{good}\nthis is not json\n{{\"partial\": true}}\n\n{good}\n"
            ),
        )
        .unwrap();

        let ledger = Ledger::open(&path).unwrap();
        // The two identical good lines fold is *not* applied on load; they are both read.
        assert_eq!(ledger.stats().records_loaded, 2);
        assert_eq!(ledger.stats().unreadable_lines, 2);
        assert_eq!(ledger.stats().blank_lines, 2, "a comment and a blank line");
        assert!(!ledger.stats().is_clean());
        assert_eq!(ledger.stats().total_lines(), 6);
    }

    #[test]
    fn comments_and_blank_lines_are_permitted() {
        let path = temp_ledger("comments");
        std::fs::write(&path, "# ledger header\n\n\n").unwrap();
        let ledger = Ledger::open(&path).unwrap();
        assert!(ledger.is_empty());
        assert!(ledger.stats().is_clean());
        assert_eq!(ledger.stats().blank_lines, 3);
    }

    #[test]
    fn in_memory_ledger_stores_without_a_file() {
        let mut ledger = Ledger::in_memory();
        assert!(!ledger.is_persistent());
        assert!(ledger.path().as_os_str().is_empty());
        ledger.record(record_for("mem", &host(&["fp"]))).unwrap();
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn queries_by_subject() {
        let mut ledger = Ledger::in_memory();
        let host = host(&["fp"]);
        ledger.record(record_for("one", &host)).unwrap();
        ledger.record(record_for("two", &host)).unwrap();

        let digest = compitum_digest::sha256(b"one");
        assert_eq!(ledger.for_subject(&digest).len(), 1);
        assert_eq!(
            ledger.for_subject(&compitum_digest::sha256(b"three")).len(),
            0
        );
        assert_eq!(ledger.distinct_subjects(), 2);
    }

    #[test]
    fn applicable_to_answers_for_a_more_capable_host() {
        let mut ledger = Ledger::in_memory();
        let recorded_host = host(&["fp", "asimd", "sve2"]);
        // The binary requires sve2, which the recorded host happens to implement.
        let mut record = record_for("app", &recorded_host);
        record.required_features = vec!["sve2".to_owned()];
        let record = record.with_outcome(Outcome::Success, Provenance::ObservedExecution, None);
        ledger.record(record).unwrap();

        // A superset of the recorded host's capabilities: the success transfers.
        let better = host(&["fp", "asimd", "sve2", "sme"]);
        assert_eq!(ledger.applicable_to(&better).len(), 1);

        // A host that lacks the required feature: this is an open question, so the
        // recorded success says nothing about it.
        let lacking = host(&["fp", "asimd"]);
        assert_eq!(ledger.applicable_to(&lacking).len(), 0);
    }

    #[test]
    fn best_for_prefers_measurement_over_prediction() {
        let mut ledger = Ledger::in_memory();
        let h = host(&["fp"]);
        let digest = compitum_digest::sha256(b"best");

        let mut prediction = record_for("best", &h);
        prediction.observed_at = 2_000_000_000;
        let mut measurement = record_for("best", &h);
        measurement.observed_at = 1_000_000_000;
        measurement.outcome = Outcome::Success;
        measurement.provenance = Provenance::ObservedExecution;

        // Insert both without folding, by making the host classes differ then normalising.
        ledger.records.push(prediction);
        ledger.records.push(measurement);

        let best = ledger.best_for(&digest, &h).expect("must find one");
        assert_eq!(
            best.provenance,
            Provenance::ObservedExecution,
            "a measurement must outrank a newer prediction"
        );
    }

    #[test]
    fn best_for_returns_none_when_nothing_bears_on_the_question() {
        let ledger = Ledger::in_memory();
        let digest = compitum_digest::sha256(b"absent");
        assert!(ledger.best_for(&digest, &host(&["fp"])).is_none());
    }

    #[test]
    fn statistics_are_counted_correctly() {
        let mut ledger = Ledger::in_memory();
        let h = host(&["fp"]);
        ledger.record(record_for("s1", &h)).unwrap();
        ledger.record(record_for("s2", &h)).unwrap();
        let mut failure = record_for("s3", &h);
        failure.outcome = Outcome::Failure;
        failure.route = "refused".to_owned();
        failure.blocked = true;
        failure.host_class = "different-class".to_owned();
        ledger.record(failure).unwrap();

        let routes = ledger.count_by_route();
        assert_eq!(routes.get("native"), Some(&2));
        assert_eq!(routes.get("refused"), Some(&1));

        let outcomes = ledger.count_by_outcome();
        assert_eq!(outcomes.get("unknown"), Some(&2));
        assert_eq!(outcomes.get("failure"), Some(&1));

        assert_eq!(ledger.count_by_host_class().len(), 2);
        assert_eq!(ledger.distinct_subjects(), 3);
        assert_eq!(ledger.determined_outcomes(), 1);
    }

    #[test]
    fn summary_json_has_the_documented_keys() {
        let mut ledger = Ledger::in_memory();
        ledger.record(record_for("sum", &host(&["fp"]))).unwrap();
        let json = ledger.summary_json();
        assert_eq!(json["total_records"].as_u64(), Some(1));
        assert_eq!(json["distinct_subjects"].as_u64(), Some(1));
        assert_eq!(json["determined_outcomes"].as_u64(), Some(0));
        assert_eq!(json["persistent"].as_bool(), Some(false));
        assert!(json["by_route"].as_array().is_some());
        assert!(json["by_outcome"].as_array().is_some());
        assert!(json["by_host_class"].as_array().is_some());
    }

    #[test]
    fn opening_an_unreadable_path_is_an_error_not_a_panic() {
        // A directory cannot be opened as a ledger file.
        let result = Ledger::open(std::env::temp_dir());
        assert!(matches!(result, Err(LedgerError::CannotOpen { .. })));
    }

    #[test]
    fn default_path_honours_the_environment_override() {
        // The override is the documented mechanism for CI and for tests, so it must win.
        let previous = std::env::var("COMPITUM_LEDGER").ok();
        std::env::set_var("COMPITUM_LEDGER", "/tmp/explicit-ledger.jsonl");
        assert_eq!(default_path(), PathBuf::from("/tmp/explicit-ledger.jsonl"));
        match previous {
            Some(value) => std::env::set_var("COMPITUM_LEDGER", value),
            None => std::env::remove_var("COMPITUM_LEDGER"),
        }
    }

    #[test]
    fn error_display_is_specific() {
        let error = LedgerError::CannotOpen {
            path: "/tmp/x".to_owned(),
            message: "permission denied".to_owned(),
        };
        let text = error.to_string();
        assert!(text.contains("/tmp/x"));
        assert!(text.contains("permission denied"));
    }
}
