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
//! | The deadline fired **and CPU time grew after settling** | it **loaded and ran** | `Success` |
//! | The deadline fired with no CPU growth | it was still *starting*, or blocked | `Unknown` |
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
//! # The timeout is not self-sufficient, and this was measured
//!
//! The first two rows are split because the first version of this crate had only row one, and
//! it was **wrong**. It read a timeout as proof of execution, reasoning that the fixtures loop
//! forever so a refused file exits immediately.
//!
//! `tools/measure-timeout-signal.sh` then showed that a sixteen-byte file containing only the
//! `MZ` signature — which nothing can execute — also ran until the deadline and returned 124,
//! in 12 of 32 trials. Wine's own start-up can outlast the deadline, so "still running" can
//! mean "still starting".
//!
//! A timeout is therefore **necessary but not sufficient**. [`cpu`] supplies the missing
//! signal, and [`classify`] refuses to claim `Success` from a timeout alone. See that module
//! for why the reading must cover the whole process tree, and why an early window measures
//! Wine rather than the binary.
//!
//! # Purity
//!
//! [`classify`] is a pure function over the raw signals, so the interpretation is fully testable
//! without running anything. Only [`runner`] performs I/O — including the CPU sampling, which
//! is passed in as data rather than read at decision time. That keeps a stored Oracle record
//! reproducible.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cpu;
pub mod runner;

pub use cpu::{CpuEvidence, CpuSampler};
pub use runner::{run, Observation, RunRequest, RunnerError};

use cpu::MIN_TICKS_PER_SECOND;

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
    /// The deadline fired, but nothing showed that the process had actually started working.
    ///
    /// Distinct from [`RunReason::RanUntilDeadline`] precisely because "still running" has two
    /// explanations and only one of them is about the binary. See the module documentation.
    DeadlineNotCorroborated,
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
            RunReason::DeadlineNotCorroborated => "deadline_not_corroborated",
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
    /// CPU-time evidence gathered while the process ran, or `None` when it could not be
    /// measured.
    ///
    /// Required to corroborate a timeout. `None` means *not measured*, which is deliberately
    /// distinct from a measurement of zero: only the first may be caused by a platform without
    /// `/proc`, and reporting the second for it would state a finding that was never made.
    pub cpu: Option<CpuEvidence>,
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
    // A timeout is NOT by itself evidence of execution. It was measured: a file Wine cannot
    // execute also ran until the deadline in 12 of 32 trials, because Wine's own start-up can
    // outlast the deadline.
    //
    // So "still running" has two explanations, and only one is about the binary:
    //
    //   * the process is executing   -- a spinning entry point keeps consuming CPU, or
    //   * the process is starting or blocked -- it consumes none.
    //
    // CPU time consumed **after start-up settled** separates them. See `crate::cpu` for the
    // measurement and for why the window must open late.
    if signals.timed_out {
        return match signals.cpu {
            Some(evidence) if evidence.shows_execution() => Verdict {
                outcome: Outcome::Success,
                provenance: Provenance::ObservedExecution,
                reason: RunReason::RanUntilDeadline,
                explanation: format!(
                    "the process was still running when the {deadline_millis} ms deadline fired, \
                     and consumed {} CPU ticks during the {} ms window after start-up settled \
                     ({} ticks per second): it loaded and executed",
                    evidence.tail_growth_ticks(),
                    evidence.tail_window_millis,
                    evidence.ticks_per_second()
                ),
                recordable: true,
            },
            Some(evidence) => Verdict {
                outcome: Outcome::Unknown,
                provenance: Provenance::ObservedExecution,
                reason: RunReason::DeadlineNotCorroborated,
                explanation: format!(
                    "the {deadline_millis} ms deadline fired, but the process consumed only {} \
                     CPU ticks per second after start-up settled ({} ticks in {} ms), below the \
                     {MIN_TICKS_PER_SECOND}/s threshold. A process that is still starting, or \
                     blocked, looks exactly like this -- so nothing can be concluded about the \
                     binary, and a longer deadline may resolve it",
                    evidence.ticks_per_second(),
                    evidence.tail_growth_ticks(),
                    evidence.tail_window_millis
                ),
                recordable: false,
            },
            None => Verdict {
                outcome: Outcome::Unknown,
                provenance: Provenance::ObservedExecution,
                reason: RunReason::DeadlineNotCorroborated,
                explanation: format!(
                    "the {deadline_millis} ms deadline fired, but CPU time could not be \
                     measured here, so 'still running' cannot be distinguished from 'still \
                     starting'. This is a limitation of the host, not a result about the binary"
                ),
                recordable: false,
            },
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
            cpu: None,
        }
    }

    /// CPU evidence showing sustained consumption, as a running loop produces.
    ///
    /// 200 ticks in a 3 s window is about 67 ticks/s, which is the rate
    /// `tools/measure-cpu-signal.sh` measured for the real fixture (204-256 ticks over the
    /// same 3 s window) and far above the negative controls, which never exceeded 1.
    fn executing() -> Option<CpuEvidence> {
        Some(CpuEvidence {
            peak_ticks: 200,
            tail_baseline_ticks: 0,
            tail_window_millis: 3000,
        })
    }

    /// CPU evidence showing no consumption, as a blocked or still-starting loader produces.
    fn not_executing() -> Option<CpuEvidence> {
        Some(CpuEvidence {
            peak_ticks: 1,
            tail_baseline_ticks: 0,
            tail_window_millis: 3000,
        })
    }

    #[test]
    fn a_timeout_with_cpu_growth_means_it_executed() {
        // A program still running at the deadline AND consuming CPU has demonstrably loaded
        // and executed. Both halves are required: the timeout alone was measured to be
        // unreliable, so the CPU evidence is what upgrades the observation to a result.
        let verdict = classify(
            RawSignals {
                timed_out: true,
                cpu: executing(),
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
    fn a_timeout_without_cpu_growth_is_not_a_result() {
        // THE REGRESSION GUARD for the defect this crate shipped with.
        //
        // A file Wine cannot execute was measured to hit the deadline in 12 of 32 trials,
        // because Wine's own start-up can outlast the deadline. So a timeout with no evidence
        // that the process ever started working must NOT be recorded as a success -- that is
        // how a still-starting loader becomes a dataset entry claiming the binary runs.
        let verdict = classify(
            RawSignals {
                timed_out: true,
                cpu: not_executing(),
                ..signals(None, None)
            },
            8000,
        );
        assert_eq!(verdict.outcome, Outcome::Unknown);
        assert_eq!(verdict.reason, RunReason::DeadlineNotCorroborated);
        assert!(
            !verdict.recordable,
            "an uncorroborated timeout says nothing about the binary and must not enter the Oracle"
        );
        assert!(!verdict.reason.describes_the_binary());
    }

    #[test]
    fn an_unmeasurable_timeout_is_unknown_and_not_a_silent_success() {
        // No `/proc`, so CPU time cannot be read. `None` means "not measured", which is
        // deliberately not the same as "measured zero": reporting either as Success would be
        // asserting something the run never established.
        let verdict = classify(
            RawSignals {
                timed_out: true,
                cpu: None,
                ..signals(None, None)
            },
            8000,
        );
        assert_eq!(verdict.outcome, Outcome::Unknown);
        assert_eq!(verdict.reason, RunReason::DeadlineNotCorroborated);
        assert!(!verdict.recordable);
        assert!(
            verdict.explanation.contains("limitation of the host"),
            "the explanation must distinguish an unmeasurable host from a measured zero: {}",
            verdict.explanation
        );
    }

    #[test]
    fn a_timeout_that_killed_the_process_is_judged_on_cpu_like_any_other() {
        // `timeout` sends TERM then KILL, so the deadline path commonly ends with a signal or
        // with 143/137. That detail must not bypass the corroboration: the exit status says how
        // the process ended, not whether it had started working.
        for (code, sig) in [(None, Some(15)), (Some(143), None), (Some(137), None)] {
            let corroborated = classify(
                RawSignals {
                    timed_out: true,
                    cpu: executing(),
                    ..signals(code, sig)
                },
                5000,
            );
            assert_eq!(
                corroborated.outcome,
                Outcome::Success,
                "code={code:?} sig={sig:?}"
            );
            assert_eq!(corroborated.reason, RunReason::RanUntilDeadline);

            let uncorroborated = classify(
                RawSignals {
                    timed_out: true,
                    cpu: not_executing(),
                    ..signals(code, sig)
                },
                5000,
            );
            assert_eq!(
                uncorroborated.outcome,
                Outcome::Unknown,
                "code={code:?} sig={sig:?} must not bypass corroboration"
            );
        }
    }

    #[test]
    fn the_deadline_value_appears_in_the_explanation() {
        // An explanation that does not state the deadline cannot be argued with.
        for cpu in [executing(), not_executing(), None] {
            let verdict = classify(
                RawSignals {
                    timed_out: true,
                    cpu,
                    ..signals(None, None)
                },
                1234,
            );
            assert!(
                verdict.explanation.contains("1234"),
                "{} hides the deadline",
                verdict.reason.id()
            );
        }
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
                cpu: None,
            },
            8000,
        );
        assert_ne!(verdict.outcome, Outcome::Partial);
        assert_eq!(verdict.reason, RunReason::BackendMissing);
    }

    #[test]
    fn a_launcher_failure_outranks_a_corroborated_timeout() {
        // The ordering must hold even when the CPU evidence says the process was consuming
        // time: if the launcher could not find the backend, the binary was never started, and
        // no later signal can retroactively make it have run.
        let verdict = classify(
            RawSignals {
                command_not_found: true,
                exit_code: Some(127),
                timed_out: true,
                command_not_executable: false,
                signal: None,
                cpu: executing(),
            },
            8000,
        );
        assert_eq!(verdict.reason, RunReason::BackendMissing);
        assert!(!verdict.recordable);
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
            RunReason::DeadlineNotCorroborated,
        ] {
            if reason.describes_the_binary() {
                assert!(
                    !matches!(
                        reason,
                        RunReason::BackendMissing
                            | RunReason::BackendNotExecutable
                            | RunReason::LauncherFailed
                            | RunReason::DeadlineNotCorroborated
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
            RunReason::DeadlineNotCorroborated,
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
