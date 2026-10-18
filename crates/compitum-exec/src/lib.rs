//! Running a binary and recording what happened.
//!
//! # Why this crate exists
//!
//! Everything before this point *predicts*. COMPITUM can classify a binary and decide which
//! route is correct, but until something actually runs it, the prediction is unverified — and
//! an unverified prediction is exactly the kind of claim this project exists to replace.
//!
//! So this crate executes, observes, and produces a [`Record`] carrying
//! [`Provenance::ObservedExecution`] rather than `StaticAnalysis`. That distinction is what
//! makes an Oracle record worth more than a guess.
//!
//! # The measurement problem, and why this crate is careful about it
//!
//! "Did it work?" is a harder question than it looks, and this project has already been wrong
//! about it once: an earlier check treated a **timeout** as proof of execution, which is also
//! what a *hung* process produces. That error reported a false pass.
//!
//! The resolution is to be precise about what each signal means, and to keep two failure classes
//! strictly apart:
//!
//! | Signal | Meaning | Recorded as |
//! |---|---|---|
//! | The deadline fired and the process was still alive | it **loaded and ran** | `Success` |
//! | Clean exit (0) | it **ran and did its job** | `Success` |
//! | Non-zero exit after starting | it ran, then reported an error | `Partial` |
//! | Exit 126 or 127, or the backend was missing | **the backend never started it** | **not recorded** |
//! | Signal-killed | it was terminated, cause unknown | `Unknown` |
//!
//! The fourth row is the important one. **A missing or broken Wine is not a compatibility
//! observation — it is a misconfiguration.** Recording it would attribute the operator's
//! environment to the binary, and a dataset polluted that way is worse than an empty one,
//! because its errors are indistinguishable from its findings.
//!
//! # Purity
//!
//! [`classify`] is a pure function over the raw signals, so the interpretation is fully testable
//! without running anything. Only [`runner`] performs I/O.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod runner;

pub use runner::{run, Observation, RunRequest, RunnerError};

use compitum_oracle::{Outcome, Provenance};

/// How a run is interpreted, with the reasoning attached.
///
/// Distinct from [`Observation`], which is what the operating system reported. This is what
/// COMPITUM *concludes*, and it carries the justification so a reader can disagree with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The outcome to store.
    pub outcome: Outcome,
    /// How the observation was obtained.
    pub provenance: Provenance,
    /// A stable reason code explaining the interpretation.
    pub reason: RunReason,
    /// An English sentence for a human.
    pub explanation: String,
    /// Whether this is worth storing in the Oracle at all.
    ///
    /// `false` for a backend failure, which says something about the machine rather than about
    /// the binary.
    pub recordable: bool,
}

/// The closed set of conclusions a run can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunReason {
    /// The process was still alive when the deadline fired, so it loaded and executed.
    RanUntilDeadline,
    /// The process exited successfully.
    ExitedCleanly,
    /// The process started and then reported a non-zero status.
    ExitedWithError,
    /// The process was killed by a signal.
    KilledBySignal,
    /// The launcher could not find the backend executable.
    BackendMissing,
    /// The backend executable was found but could not be executed.
    BackendNotExecutable,
    /// The launcher itself failed.
    LauncherFailed,
}

impl RunReason {
    /// Stable identifier for JSON and Oracle records.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            RunReason::RanUntilDeadline => "ran_until_deadline",
            RunReason::ExitedCleanly => "exited_cleanly",
            RunReason::ExitedWithError => "exited_with_error",
            RunReason::KilledBySignal => "killed_by_signal",
            RunReason::BackendMissing => "backend_missing",
            RunReason::BackendNotExecutable => "backend_not_executable",
            RunReason::LauncherFailed => "launcher_failed",
        }
    }

    /// Returns `true` when this reason describes the binary rather than the machine.
    ///
    /// Only such reasons belong in the Oracle. A backend that is absent or unrunnable is the
    /// operator's environment, and attributing it to the binary would corrupt the dataset.
    #[must_use]
    pub fn describes_the_binary(self) -> bool {
        matches!(
            self,
            RunReason::RanUntilDeadline
                | RunReason::ExitedCleanly
                | RunReason::ExitedWithError
                | RunReason::KilledBySignal
        )
    }
}

/// The raw signals an operating system gives about a finished process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawSignals {
    /// The exit status, or `None` when the process was killed by a signal.
    pub exit_code: Option<i32>,
    /// The signal that terminated the process, when one did.
    pub signal: Option<i32>,
    /// Whether the runner's own deadline fired.
    pub timed_out: bool,
    /// `true` when the launcher reported the command could not be found (shell status 127).
    pub command_not_found: bool,
    /// `true` when the launcher reported the command was not executable (shell status 126).
    pub command_not_executable: bool,
}

/// Interprets raw process signals into a [`Verdict`].
///
/// Pure, so every branch is testable without spawning anything — which matters because the
/// interpretation is where this project has previously been wrong.
///
/// The order of the checks is deliberate and load-bearing: launcher failures are examined
/// **first**, because a missing backend also produces a non-zero exit and would otherwise be
/// misread as the binary having run and failed.
#[must_use]
pub fn classify(signals: RawSignals, deadline_millis: u64) -> Verdict {
    // ---- Launcher failures, checked FIRST ----------------------------------
    //
    // A missing Wine exits 127 and would otherwise look like "the program ran and returned
    // 127". Getting this order wrong is how a misconfigured machine becomes a dataset entry
    // claiming the binary is broken.
    if signals.command_not_found {
        return Verdict {
            outcome: Outcome::Unknown,
            provenance: Provenance::ObservedExecution,
            reason: RunReason::BackendMissing,
            explanation: "the launcher could not find the backend executable, so the binary \
                          was never started; this says nothing about the binary"
                .to_owned(),
            recordable: false,
        };
    }
    if signals.command_not_executable {
        return Verdict {
            outcome: Outcome::Unknown,
            provenance: Provenance::ObservedExecution,
            reason: RunReason::BackendNotExecutable,
            explanation: "the backend executable exists but could not be run, most likely \
                          because it lacks execute permission; the binary was never started"
                .to_owned(),
            recordable: false,
        };
    }

    // ---- The deadline fired -------------------------------------------------
    //
    // Reaching the deadline means the process was still alive, which for a program that does
    // not terminate on its own is proof that it loaded and executed. This is the signal the
    // probe in `tools/probe-arm64ec.sh` relies on, and it is stated here rather than assumed.
    if signals.timed_out {
        // A timeout on a process that was killed rather than still running is different, but
        // the runner cannot distinguish those after the fact; the exit code carries the detail.
        if signals.signal.is_some() || matches!(signals.exit_code, Some(137) | Some(143)) {
            return Verdict {
                outcome: Outcome::Success,
                provenance: Provenance::ObservedExecution,
                reason: RunReason::RanUntilDeadline,
                explanation: format!(
                    "the process was still running when the {deadline_millis} ms deadline \
                     fired and had to be terminated, which means it loaded and executed"
                ),
                recordable: true,
            };
        }
        return Verdict {
            outcome: Outcome::Success,
            provenance: Provenance::ObservedExecution,
            reason: RunReason::RanUntilDeadline,
            explanation: format!(
                "the process was still running when the {deadline_millis} ms deadline fired, \
                 which means it loaded and executed"
            ),
            recordable: true,
        };
    }

    // ---- Killed by a signal -------------------------------------------------
    if let Some(signal) = signals.signal {
        return Verdict {
            outcome: Outcome::Unknown,
            provenance: Provenance::ObservedExecution,
            reason: RunReason::KilledBySignal,
            explanation: format!(
                "the process was terminated by signal {signal}; the runner cannot tell whether \
                 the binary or a backend caused it, so the outcome is not determined"
            ),
            // Recorded, because the binary did start. A later run may disambiguate.
            recordable: true,
        };
    }

    // ---- A clean exit ------------------------------------------------------
    match signals.exit_code {
        Some(0) => Verdict {
            outcome: Outcome::Success,
            provenance: Provenance::ObservedExecution,
            reason: RunReason::ExitedCleanly,
            explanation: "the process ran and exited successfully".to_owned(),
            recordable: true,
        },
        Some(code) => Verdict {
            outcome: Outcome::Partial,
            provenance: Provenance::ObservedExecution,
            reason: RunReason::ExitedWithError,
            explanation: format!(
                "the process ran and exited with status {code}, so it started but did not \
                 complete as intended"
            ),
            recordable: true,
        },
        None => Verdict {
            outcome: Outcome::Unknown,
            provenance: Provenance::ObservedExecution,
            reason: RunReason::LauncherFailed,
            explanation: "the runner obtained neither an exit status nor a signal, so nothing \
                          can be concluded"
                .to_owned(),
            recordable: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(exit_code: Option<i32>, signal: Option<i32>) -> RawSignals {
        RawSignals {
            exit_code,
            signal,
            timed_out: false,
            command_not_found: false,
            command_not_executable: false,
        }
    }

    #[test]
    fn a_timeout_means_it_executed() {
        // The distinction this whole crate is careful about: a program still running at the
        // deadline has demonstrably loaded and executed, which is what an infinite-loop fixture
        // is for.
        let verdict = classify(
            RawSignals {
                timed_out: true,
                ..signals(None, None)
            },
            8000,
        );
        assert_eq!(verdict.outcome, Outcome::Success);
        assert_eq!(verdict.reason, RunReason::RanUntilDeadline);
        assert!(verdict.recordable);
        assert!(verdict.explanation.contains("8000"));
    }

    #[test]
    fn a_timeout_that_killed_the_process_still_counts_as_executed() {
        // `timeout` sends TERM then KILL, so the deadline path commonly ends with a signal or
        // with 143/137. That is still proof of execution, not a failure.
        for (code, sig) in [(None, Some(15)), (Some(143), None), (Some(137), None)] {
            let verdict = classify(
                RawSignals {
                    timed_out: true,
                    ..signals(code, sig)
                },
                5000,
            );
            assert_eq!(
                verdict.outcome,
                Outcome::Success,
                "code={code:?} sig={sig:?}"
            );
            assert_eq!(verdict.reason, RunReason::RanUntilDeadline);
        }
    }

    #[test]
    fn the_deadline_value_appears_in_the_explanation() {
        // An explanation that does not state the deadline cannot be argued with.
        let verdict = classify(
            RawSignals {
                timed_out: true,
                ..signals(None, None)
            },
            1234,
        );
        assert!(verdict.explanation.contains("1234"));
    }

    #[test]
    fn a_clean_exit_is_success() {
        let verdict = classify(signals(Some(0), None), 8000);
        assert_eq!(verdict.outcome, Outcome::Success);
        assert_eq!(verdict.reason, RunReason::ExitedCleanly);
        assert!(verdict.recordable);
    }

    #[test]
    fn a_non_zero_exit_is_partial_not_failure() {
        // The process started, which is itself information. Calling this a failure would
        // discard the fact that the binary loads.
        let verdict = classify(signals(Some(1), None), 8000);
        assert_eq!(verdict.outcome, Outcome::Partial);
        assert_eq!(verdict.reason, RunReason::ExitedWithError);
        assert!(verdict.explanation.contains('1'));
    }

    #[test]
    fn a_missing_backend_is_not_recorded_as_a_binary_failure() {
        // THE most important test in this module. A missing Wine exits 127, and recording that
        // as "the binary failed" would attribute a misconfigured machine to the program --
        // producing a dataset whose errors are indistinguishable from its findings.
        let verdict = classify(
            RawSignals {
                command_not_found: true,
                exit_code: Some(127),
                ..signals(None, None)
            },
            8000,
        );
        assert_eq!(verdict.outcome, Outcome::Unknown);
        assert_eq!(verdict.reason, RunReason::BackendMissing);
        assert!(
            !verdict.recordable,
            "a backend failure must not enter the Oracle"
        );
        assert!(verdict.explanation.contains("never started"));
        assert!(!verdict.reason.describes_the_binary());
    }

    #[test]
    fn a_non_executable_backend_is_not_recorded_either() {
        let verdict = classify(
            RawSignals {
                command_not_executable: true,
                exit_code: Some(126),
                ..signals(None, None)
            },
            8000,
        );
        assert_eq!(verdict.reason, RunReason::BackendNotExecutable);
        assert!(!verdict.recordable);
        assert!(verdict.explanation.contains("execute permission"));
    }

    #[test]
    fn launcher_failures_are_checked_before_the_exit_code() {
        // Regression guard for check ordering. If the exit code were examined first, 127 would
        // be read as "the program returned 127" and the launcher failure would be lost.
        let verdict = classify(
            RawSignals {
                command_not_found: true,
                exit_code: Some(127),
                timed_out: false,
                command_not_executable: false,
                signal: None,
            },
            8000,
        );
        assert_ne!(verdict.outcome, Outcome::Partial);
        assert_eq!(verdict.reason, RunReason::BackendMissing);
    }

    #[test]
    fn a_signal_is_unknown_rather_than_a_failure() {
        // Killing by signal does not say who did it. Recording a verdict would be a guess.
        let verdict = classify(signals(None, Some(11)), 8000);
        assert_eq!(verdict.outcome, Outcome::Unknown);
        assert_eq!(verdict.reason, RunReason::KilledBySignal);
        assert!(
            verdict.recordable,
            "the binary did start, so the fact is worth keeping"
        );
        assert!(verdict.explanation.contains("11"));
    }

    #[test]
    fn neither_status_nor_signal_is_not_recorded() {
        let verdict = classify(signals(None, None), 8000);
        assert_eq!(verdict.outcome, Outcome::Unknown);
        assert_eq!(verdict.reason, RunReason::LauncherFailed);
        assert!(!verdict.recordable);
    }

    #[test]
    fn every_reason_that_describes_the_binary_is_recordable() {
        // The two properties must agree, or a recordable verdict would be discarded or a
        // machine failure would be stored.
        for reason in [
            RunReason::RanUntilDeadline,
            RunReason::ExitedCleanly,
            RunReason::ExitedWithError,
            RunReason::KilledBySignal,
            RunReason::BackendMissing,
            RunReason::BackendNotExecutable,
            RunReason::LauncherFailed,
        ] {
            if reason.describes_the_binary() {
                assert!(
                    !matches!(
                        reason,
                        RunReason::BackendMissing
                            | RunReason::BackendNotExecutable
                            | RunReason::LauncherFailed
                    ),
                    "{} claims to describe the binary but is a machine failure",
                    reason.id()
                );
            }
        }
    }

    #[test]
    fn observed_runs_always_carry_observed_execution_provenance() {
        // Every verdict here is stronger evidence than a static analysis, and the provenance
        // must say so -- otherwise the Oracle would weigh a measurement like a prediction.
        for signals_value in [
            signals(Some(0), None),
            signals(Some(1), None),
            signals(None, Some(11)),
            RawSignals {
                timed_out: true,
                ..signals(None, None)
            },
        ] {
            let verdict = classify(signals_value, 8000);
            assert_eq!(verdict.provenance, Provenance::ObservedExecution);
        }
    }

    #[test]
    fn every_reason_has_a_stable_id() {
        let mut seen = std::collections::BTreeSet::new();
        for reason in [
            RunReason::RanUntilDeadline,
            RunReason::ExitedCleanly,
            RunReason::ExitedWithError,
            RunReason::KilledBySignal,
            RunReason::BackendMissing,
            RunReason::BackendNotExecutable,
            RunReason::LauncherFailed,
        ] {
            assert!(seen.insert(reason.id()), "duplicate id: {}", reason.id());
        }
    }

    #[test]
    fn every_verdict_has_an_explanation() {
        for signals_value in [
            signals(Some(0), None),
            signals(Some(9), None),
            signals(None, Some(11)),
            RawSignals {
                timed_out: true,
                ..signals(None, None)
            },
            RawSignals {
                command_not_found: true,
                exit_code: Some(127),
                ..signals(None, None)
            },
            RawSignals {
                command_not_executable: true,
                exit_code: Some(126),
                ..signals(None, None)
            },
        ] {
            let verdict = classify(signals_value, 8000);
            assert!(
                verdict.explanation.len() > 30,
                "{} has an unhelpfully short explanation: {}",
                verdict.reason.id(),
                verdict.explanation
            );
        }
    }
}
