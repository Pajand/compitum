//! Executing a program and observing what the operating system reported.
//!
//! # The one design decision that matters here
//!
//! Child process output is redirected to a **temporary file**, not to a pipe.
//!
//! A pipe seems simpler and is what most code does, but it deadlocks: the parent only reads
//! after the child exits, while the child blocks writing once the pipe buffer fills. For a
//! program that prints a lot — or one that prints nothing and runs forever — the parent waits
//! for an exit that never comes, and the observed result is a timeout that says nothing about
//! the binary.
//!
//! A temporary file has no buffer limit, so the child never blocks, and the output can be read
//! after the process is gone. The file is deleted afterwards.
//!
//! # Reading the outcome
//!
//! The process is polled rather than waited on, so a deadline can be enforced without relying
//! on an external `timeout` binary being present. Polling costs a wakeup every few milliseconds
//! and removes a dependency on the host's coreutils.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::{classify, CpuEvidence, CpuSampler, RawSignals, Verdict};

/// Polling interval while waiting for a child process.
///
/// Weeks of responsiveness versus overhead: 20 ms is far below human perception and is a
/// negligible fraction of any deadline this tool enforces.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// The number of bytes of child output retained.
///
/// A build tool or a runaway program can produce megabytes. The report needs the beginning,
/// where the error usually is, and a bounded amount keeps memory predictable.
const MAX_CAPTURED_OUTPUT: usize = 64 * 1024;

/// What to run and how long to allow.
#[derive(Debug, Clone)]
pub struct RunRequest {
    /// The program to launch — a backend such as `wine`, or a binary directly.
    pub program: PathBuf,
    /// Arguments in order.
    pub args: Vec<String>,
    /// Working directory, when one should be set explicitly.
    pub working_directory: Option<PathBuf>,
    /// How long the process may run before it is terminated.
    pub deadline: Duration,
}

impl RunRequest {
    /// A request with a deadline in milliseconds.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>, deadline_millis: u64) -> Self {
        RunRequest {
            program: program.into(),
            args: Vec::new(),
            working_directory: None,
            deadline: Duration::from_millis(deadline_millis),
        }
    }

    /// Appends an argument.
    #[must_use]
    pub fn arg(mut self, value: impl Into<String>) -> Self {
        self.args.push(value.into());
        self
    }

    /// Sets the working directory.
    #[must_use]
    pub fn in_directory(mut self, path: impl Into<PathBuf>) -> Self {
        self.working_directory = Some(path.into());
        self
    }

    /// Renders the command as it would be typed, for a report.
    #[must_use]
    pub fn command_line(&self) -> String {
        let mut parts = vec![self.program.display().to_string()];
        parts.extend(self.args.iter().cloned());
        parts.join(" ")
    }
}

/// What the operating system reported about the finished process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The interpreted verdict.
    pub verdict: Verdict,
    /// The raw signals, retained so a reader can disagree with the interpretation.
    pub signals: RawSignals,
    /// The command that was run.
    pub command: String,
    /// How long the process actually ran, in milliseconds.
    pub elapsed_millis: u64,
    /// The beginning of the child's combined output, possibly truncated.
    pub output: String,
    /// `true` when the output was longer than [`MAX_CAPTURED_OUTPUT`] and was cut.
    pub output_truncated: bool,
    /// `true` when the process had to be terminated at the deadline.
    pub terminated: bool,
    /// The CPU-time evidence gathered, or `None` when it could not be measured.
    ///
    /// Kept separately from [`Observation::signals`] because it is the corroboration for a
    /// timeout: a reader must be able to see that the deadline fired *and* what the CPU time
    /// said, rather than only the verdict those two produced.
    pub cpu: Option<CpuEvidence>,
    /// How many CPU samples were taken, so a report can show whether sampling was even active.
    pub cpu_samples: u64,
}

impl Observation {
    /// A machine-readable record of the run, for the Oracle and for reports.
    ///
    /// Note that `recordable` is carried explicitly: a backend failure is a real observation
    /// that must **not** enter the compatibility dataset, and a consumer needs to see that
    /// decision rather than infer it from the outcome.
    #[must_use]
    pub fn to_json(&self) -> compitum_json::Value {
        compitum_json::Object::new()
            .with("command", self.command.as_str())
            .with("outcome", self.verdict.outcome.id())
            .with("provenance", self.verdict.provenance.id())
            .with("reason", self.verdict.reason.id())
            .with("explanation", self.verdict.explanation.as_str())
            .with("recordable", self.verdict.recordable)
            .with("elapsed_millis", self.elapsed_millis)
            .with("terminated_at_deadline", self.terminated)
            .with("exit_code", self.signals.exit_code.map(i64::from))
            .with("signal", self.signals.signal.map(i64::from))
            // The evidence behind a timeout verdict, reported alongside it so a consumer can
            // disagree with the interpretation instead of having to trust it. `null` means the
            // CPU time could not be measured, which is a different statement from a measured
            // zero and must not be collapsed with it.
            .with(
                "cpu_peak_ticks",
                self.cpu.map(|e| e.peak_ticks).map(|v| v as i64),
            )
            .with(
                "cpu_tail_growth_ticks",
                self.cpu.map(|e| e.tail_growth_ticks()).map(|v| v as i64),
            )
            .with(
                "cpu_ticks_per_second",
                self.cpu.map(|e| e.ticks_per_second()).map(|v| v as i64),
            )
            .with(
                "cpu_tail_window_millis",
                self.cpu.map(|e| e.tail_window_millis).map(|v| v as i64),
            )
            .with("cpu_samples", self.cpu_samples as i64)
            .with("output_truncated", self.output_truncated)
            .with("output", self.output.as_str())
            .into()
    }
}

/// Why a run could not be performed at all.
///
/// Distinct from a [`Verdict`], which describes a process that did start. These are cases where
/// nothing was observed, so there is nothing to interpret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerError {
    /// The backend executable does not exist.
    ProgramNotFound {
        /// The path that was attempted.
        program: String,
    },
    /// The executable exists but cannot be run.
    ProgramNotExecutable {
        /// The path that was attempted.
        program: String,
        /// The underlying message.
        message: String,
    },
    /// The process could not be started for any other reason.
    SpawnFailed {
        /// The path that was attempted.
        program: String,
        /// The underlying message.
        message: String,
    },
    /// The temporary file for child output could not be created.
    TempFileFailed {
        /// The underlying message.
        message: String,
    },
}

impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunnerError::ProgramNotFound { program } => write!(
                f,
                "no such program: {program}; nothing was executed and nothing can be concluded"
            ),
            RunnerError::ProgramNotExecutable { program, message } => write!(
                f,
                "cannot execute {program}: {message}; nothing was executed"
            ),
            RunnerError::SpawnFailed { program, message } => {
                write!(f, "failed to start {program}: {message}")
            }
            RunnerError::TempFileFailed { message } => {
                write!(
                    f,
                    "cannot create a temporary file for the output: {message}"
                )
            }
        }
    }
}

impl std::error::Error for RunnerError {}

/// Runs a program, enforces the deadline, and interprets the outcome.
///
/// # Errors
///
/// Returns [`RunnerError`] when nothing could be executed, so the caller does not mistake a
/// missing backend for a compatibility result.
pub fn run(request: &RunRequest) -> Result<Observation, RunnerError> {
    let output_path = temporary_output_path()?;

    let mut command = Command::new(&request.program);
    command
        .args(&request.args)
        // A file rather than a pipe: a full pipe buffer would block the child and turn
        // "produced a lot of output" into an apparent hang. See the module documentation.
        .stdout(Stdio::from(std::fs::File::create(&output_path).map_err(
            |e| RunnerError::TempFileFailed {
                message: e.to_string(),
            },
        )?))
        .stderr(Stdio::from(
            std::fs::File::create(output_path.with_extension("err")).map_err(|e| {
                RunnerError::TempFileFailed {
                    message: e.to_string(),
                }
            })?,
        ))
        // No stdin: a program waiting for input would otherwise hang until the deadline and
        // be recorded as "it ran", which would be wrong.
        .stdin(Stdio::null());

    if let Some(directory) = &request.working_directory {
        command.current_dir(directory);
    }

    let started = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| spawn_error(request, &error))?;

    // CPU sampling covers the whole descendant tree, not just this child: under Wine the child
    // is a thin launcher and every reading of it alone is zero. See `crate::cpu`.
    let mut sampler = CpuSampler::new(child.id());
    let _ = sampler.sample();

    // The tail window opens half way through the allowance.
    //
    // It must not open at process start: Wine's own initialisation is CPU-heavy and unrelated
    // to the binary, and a first attempt at this measurement that sampled from 1.5 s produced
    // 26 ticks for a binary that was demonstrably looping -- overlapping the negative
    // controls, which reached 1. Starting at the half-way point makes the window scale with
    // the deadline the operator chose, so a longer allowance gives a longer and later window.
    let tail_opens_at = request.deadline / 2;
    let mut tail_opened_at: Option<Instant> = None;

    let deadline = started + request.deadline;
    let mut terminated = false;
    let mut polls: u64 = 0;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                // Sampling every poll would read all of `/proc` fifty times a second for no
                // added information. Every fifth poll is 100 ms at the default interval, which
                // resolves a rate over a multi-second window with room to spare.
                polls += 1;
                if polls % 5 == 0 {
                    let _ = sampler.sample();
                }

                let elapsed = started.elapsed();
                if tail_opened_at.is_none() && elapsed >= tail_opens_at {
                    sampler.begin_tail_window();
                    tail_opened_at = Some(Instant::now());
                }

                if Instant::now() >= deadline {
                    // One last reading before terminating. The process is at its busiest here,
                    // and it is the reading that best shows a loop still running.
                    let _ = sampler.sample();

                    // Terminate, then reap. `kill` can fail if the process exited between the
                    // poll and the call, which is not an error worth surfacing.
                    let _ = child.kill();
                    terminated = true;
                    break child.wait().map_err(|error| RunnerError::SpawnFailed {
                        program: request.program.display().to_string(),
                        message: error.to_string(),
                    })?;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => {
                return Err(RunnerError::SpawnFailed {
                    program: request.program.display().to_string(),
                    message: error.to_string(),
                })
            }
        }
    };

    let elapsed_millis = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let (output, output_truncated) = read_output(&output_path);

    // The measured length of the tail window, taken from the clock rather than from the
    // nominal deadline, so a process that exited early reports the window it actually had.
    let tail_window_millis = tail_opened_at
        .map(|opened| opened.elapsed().as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0);
    let cpu = sampler.evidence(tail_window_millis);

    // `ExitStatusExt::signal` is a safe accessor on Unix; no unsafe is required.
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    };
    #[cfg(not(unix))]
    let signal: Option<i32> = None;

    let signals = RawSignals {
        exit_code: if signal.is_none() {
            status.code()
        } else {
            None
        },
        signal,
        timed_out: terminated,
        // A shell reports 127 for "command not found". Spawning directly never produces this,
        // but a request may legitimately go through a shell wrapper, so it is still honoured.
        command_not_found: status.code() == Some(127),
        command_not_executable: status.code() == Some(126),
        // `None` when `/proc` was unreadable. Passing it through rather than substituting a
        // zero keeps "not measured" distinct from "measured no CPU", which is the difference
        // between a host limitation and a finding about the binary.
        cpu,
    };

    let verdict = classify(signals, request.deadline.as_millis() as u64);

    let _ = std::fs::remove_file(&output_path);
    let _ = std::fs::remove_file(output_path.with_extension("err"));

    Ok(Observation {
        verdict,
        signals,
        command: request.command_line(),
        elapsed_millis,
        output,
        output_truncated,
        terminated,
        cpu,
        cpu_samples: sampler.sample_count(),
    })
}

/// Maps a spawn failure to a specific error, so a missing executable is never confused with a
/// binary that ran and failed.
fn spawn_error(request: &RunRequest, error: &std::io::Error) -> RunnerError {
    let program = request.program.display().to_string();
    match error.kind() {
        std::io::ErrorKind::NotFound => RunnerError::ProgramNotFound { program },
        std::io::ErrorKind::PermissionDenied => RunnerError::ProgramNotExecutable {
            program,
            message: error.to_string(),
        },
        _ => RunnerError::SpawnFailed {
            program,
            message: error.to_string(),
        },
    }
}

/// A unique path for a run's captured output.
///
/// Combines the process id with a monotonically increasing counter, because two runs in the
/// same process could otherwise collide, and two processes sharing a temporary directory would
/// otherwise overwrite each other's output.
fn temporary_output_path() -> Result<PathBuf, RunnerError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let mut path = std::env::temp_dir();
    path.push(format!("compitum-run-{pid}-{unique}.out"));

    // Touch the file so a failure to write is discovered here rather than mid-run.
    std::fs::write(&path, b"").map_err(|e| RunnerError::TempFileFailed {
        message: e.to_string(),
    })?;
    Ok(path)
}

/// Reads the captured output, bounded and marked when truncated.
fn read_output(path: &std::path::Path) -> (String, bool) {
    let mut buffer = Vec::new();
    let truncated = match std::fs::File::open(path) {
        Ok(mut file) => {
            let mut limited = (&mut file).take((MAX_CAPTURED_OUTPUT + 1) as u64);
            let _ = limited.read_to_end(&mut buffer);
            buffer.len() > MAX_CAPTURED_OUTPUT
        }
        Err(_) => return (String::new(), false),
    };
    buffer.truncate(MAX_CAPTURED_OUTPUT);
    let text = String::from_utf8_lossy(&buffer).into_owned();

    // stderr often carries the real message; append it when present.
    let error_path = path.with_extension("err");
    let mut combined = text;
    if let Ok(stderr) = std::fs::read_to_string(error_path) {
        if !stderr.trim().is_empty() {
            if !combined.is_empty() && !combined.ends_with('\n') {
                combined.push('\n');
            }
            combined.push_str(&stderr);
        }
    }
    let truncated = truncated || combined.len() > MAX_CAPTURED_OUTPUT;
    combined.truncate(MAX_CAPTURED_OUTPUT);
    (combined, truncated)
}

/// Locates a shell for tests, preferring one that certainly exists.
#[cfg(test)]
fn shell() -> PathBuf {
    for candidate in ["/bin/sh", "/usr/bin/sh"] {
        if std::path::Path::new(candidate).exists() {
            return PathBuf::from(candidate);
        }
    }
    PathBuf::from("sh")
}

#[cfg(test)]
mod tests {
    use super::*;
    use compitum_oracle::Outcome;

    #[test]
    fn a_clean_exit_is_observed_as_success() {
        let request = RunRequest::new(shell(), 10_000).arg("-c").arg("exit 0");
        let observation = run(&request).expect("must run");
        assert_eq!(observation.verdict.outcome, Outcome::Success);
        assert_eq!(observation.signals.exit_code, Some(0));
        assert!(!observation.terminated);
        assert!(observation.verdict.recordable);
    }

    #[test]
    fn a_non_zero_exit_is_partial_and_its_code_is_preserved() {
        let request = RunRequest::new(shell(), 10_000).arg("-c").arg("exit 7");
        let observation = run(&request).expect("must run");
        assert_eq!(observation.verdict.outcome, Outcome::Partial);
        assert_eq!(observation.signals.exit_code, Some(7));
        assert!(observation.verdict.explanation.contains('7'));
    }

    #[test]
    fn a_cpu_consuming_process_that_outlives_the_deadline_is_a_success() {
        // A busy loop is the shape the corpus fixtures have, and it is what the ARM64EC probe
        // relies on: the entry point spins forever, so a loaded program keeps consuming CPU
        // until the deadline. The deadline firing *and* CPU growth together are the two halves
        // of the evidence, and neither alone is sufficient.
        let request = RunRequest::new(shell(), 3000)
            .arg("-c")
            .arg("while :; do :; done");
        let observation = run(&request).expect("must run");
        assert!(
            observation.terminated,
            "the runner must terminate the process itself"
        );
        assert_eq!(
            observation.verdict.reason,
            crate::RunReason::RanUntilDeadline,
            "reason was {:?} with CPU evidence {:?}",
            observation.verdict.reason,
            observation.cpu
        );
        assert_eq!(observation.verdict.outcome, Outcome::Success);
        assert!(observation.verdict.recordable);
        // It must not have waited for anything longer than the deadline.
        assert!(
            observation.elapsed_millis < 10_000,
            "deadline not enforced: ran {} ms",
            observation.elapsed_millis
        );
    }

    #[test]
    fn a_sleeping_process_that_outlives_the_deadline_is_unknown_not_a_success() {
        // A REAL LIMITATION, recorded deliberately rather than hidden.
        //
        // `sleep` consumes no CPU, so CPU time cannot distinguish "executing and idle" from
        // "blocked before starting". Both produce the same reading, and the same reading also
        // comes from a file Wine cannot execute at all -- which is precisely the case that must
        // not be recorded as a success.
        //
        // `Unknown` is therefore the honest answer. It costs a result that a sleeping binary
        // would have earned, and that is the correct trade: a false `Success` corrupts the
        // dataset this project exists to build, while a false `Unknown` only loses one entry.
        //
        // This test asserts the limitation so that removing it requires a deliberate decision.
        let request = RunRequest::new(shell(), 3000).arg("-c").arg("sleep 30");
        let observation = run(&request).expect("must run");
        assert!(
            observation.terminated,
            "the deadline must still be enforced"
        );
        assert_eq!(
            observation.verdict.reason,
            crate::RunReason::DeadlineNotCorroborated
        );
        assert_eq!(observation.verdict.outcome, Outcome::Unknown);
        assert!(
            !observation.verdict.recordable,
            "an uncorroborated timeout must not enter the Oracle"
        );
    }

    #[test]
    fn output_is_captured() {
        let request = RunRequest::new(shell(), 10_000)
            .arg("-c")
            .arg("echo hello-from-child");
        let observation = run(&request).expect("must run");
        assert!(observation.output.contains("hello-from-child"));
        assert!(!observation.output_truncated);
    }

    #[test]
    fn stderr_is_captured_too() {
        let request = RunRequest::new(shell(), 10_000)
            .arg("-c")
            .arg("echo problem 1>&2");
        let observation = run(&request).expect("must run");
        assert!(observation.output.contains("problem"));
    }

    #[test]
    fn a_missing_program_is_an_error_not_a_verdict() {
        // The distinction the whole crate rests on: this must NOT produce an Observation
        // saying the binary failed, because nothing was executed.
        let request = RunRequest::new("/definitely/not/a/program", 5_000);
        match run(&request) {
            Err(RunnerError::ProgramNotFound { program }) => {
                assert!(program.contains("definitely"));
            }
            other => panic!("expected ProgramNotFound, got {other:?}"),
        }
    }

    #[test]
    fn runner_errors_explain_that_nothing_was_executed() {
        let error = RunnerError::ProgramNotFound {
            program: "/x".to_owned(),
        };
        let text = error.to_string();
        assert!(text.contains("no such program"));
        assert!(
            text.contains("nothing can be concluded"),
            "the message must not imply the binary failed: {text}"
        );
    }

    #[test]
    fn a_large_output_stream_does_not_deadlock() {
        // The reason output goes to a file rather than a pipe. A few megabytes through a pipe
        // would fill the buffer, block the child, and appear as a timeout that says nothing
        // about the binary.
        let request = RunRequest::new(shell(), 30_000)
            .arg("-c")
            .arg("head -c 3000000 /dev/zero | tr '\\0' 'x'");
        let observation = run(&request).expect("must run");
        assert!(
            !observation.terminated,
            "a large output stream must not cause an apparent hang"
        );
        assert!(
            observation.output_truncated,
            "output should be marked truncated"
        );
        assert!(observation.output.len() <= MAX_CAPTURED_OUTPUT);
    }

    #[test]
    fn a_program_waiting_on_input_does_not_hang() {
        // Stdin is /dev/null, so a reader sees EOF immediately and exits rather than waiting
        // until the deadline and being recorded as having run.
        let request = RunRequest::new(shell(), 3_000).arg("-c").arg("cat");
        let observation = run(&request).expect("must run");
        assert!(!observation.terminated, "cat should have seen EOF at once");
        assert_eq!(observation.verdict.outcome, Outcome::Success);
    }

    #[test]
    fn the_working_directory_is_honoured() {
        let directory = std::env::temp_dir();
        let request = RunRequest::new(shell(), 10_000)
            .arg("-c")
            .arg("pwd")
            .in_directory(&directory);
        let observation = run(&request).expect("must run");
        let reported = observation.output.trim();
        assert!(
            reported.contains(&directory.display().to_string())
                || directory.display().to_string().ends_with(reported),
            "expected the temporary directory, got {reported:?}"
        );
    }

    #[test]
    fn the_command_line_renders_readably() {
        let request = RunRequest::new("/usr/bin/wine", 1000)
            .arg("/tmp/app.exe")
            .arg("--flag");
        assert_eq!(request.command_line(), "/usr/bin/wine /tmp/app.exe --flag");
    }

    #[test]
    fn json_carries_the_recordable_decision() {
        let request = RunRequest::new(shell(), 10_000).arg("-c").arg("exit 0");
        let observation = run(&request).expect("must run");
        let json = observation.to_json();
        assert_eq!(json["outcome"].as_str(), Some("success"));
        assert_eq!(json["recordable"].as_bool(), Some(true));
        assert_eq!(json["exit_code"].as_u64(), Some(0));
        assert_eq!(json["provenance"].as_str(), Some("observed_execution"));
        assert!(json["command"].as_str().is_some());
    }

    #[test]
    fn temporary_paths_are_unique_between_calls() {
        let first = temporary_output_path().expect("must create");
        let second = temporary_output_path().expect("must create");
        assert_ne!(first, second, "two runs must not share an output file");
        let _ = std::fs::remove_file(first);
        let _ = std::fs::remove_file(second);
    }

    #[test]
    fn a_truncated_output_is_flagged_not_silently_cut() {
        // A reader must be able to tell that something was omitted, otherwise a report could
        // omit the very line that explains a failure.
        let directory = std::env::temp_dir().join("compitum-output-test");
        let _ = std::fs::create_dir_all(&directory);
        let path = directory.join("sample.out");
        let _ = std::fs::write(&path, "x".repeat(MAX_CAPTURED_OUTPUT + 100));
        let (text, truncated) = read_output(&path);
        assert!(truncated);
        assert_eq!(text.len(), MAX_CAPTURED_OUTPUT);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_missing_output_file_yields_empty_not_an_error() {
        let (text, truncated) = read_output(std::path::Path::new("/definitely/absent.out"));
        assert!(text.is_empty());
        assert!(!truncated);
    }
}
