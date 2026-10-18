//! Measuring how much CPU a process tree actually consumed.
//!
//! # Why this module exists
//!
//! [`crate::classify`] used to read a timeout as proof that a binary executed. The reasoning
//! was that the corpus fixtures loop forever, so a fixture that loads runs until the deadline
//! fires while one that is refused exits immediately.
//!
//! That reasoning is unsound, and it was **measured** rather than argued. A sixteen-byte file
//! containing only the `MZ` signature — which nothing can execute — also ran until the
//! deadline and returned 124, in 12 of 32 trials. Wine's own start-up can outlast the
//! deadline, so "still running" can mean "still starting".
//!
//! `tools/measure-timeout-signal.sh` reproduces that measurement; it is what turned this from
//! a suspicion into a defect.
//!
//! # The missing signal, and the trap in reading it
//!
//! The signal is CPU time. A spinning entry point consumes CPU, a blocked loader does not.
//! That is the reasoning `tools/loopcheck.sh` used, and its failure was recorded here as
//! "`/proc` does not work in this container". **That conclusion was too broad.**
//!
//! `loopcheck.sh` took a *host-wide* reading through `ps`, which in this container sees
//! nothing. This module reads `/proc/<pid>/stat` for a process it spawned itself. Different
//! measurements — only the first was shown to be broken.
//!
//! There is a second trap, and it fails in a way that looks like success: reading only the
//! **direct child**. Under Wine the child is a thin launcher; the work happens in a loader
//! whose parent chain runs through `wineserver`, and that daemon **reparents itself**. So a
//! child-only reading returns `0` every time — including for a binary already proven to
//! execute. This module sums the **whole descendant tree**, remembering pids it has seen so
//! a reparented descendant is not silently dropped.
//!
//! # What it cannot establish
//!
//! A binary that loads and then *sleeps* consumes no CPU either. Absence of CPU evidence
//! therefore does not prove failure — it means execution was not demonstrated, and
//! [`crate::classify`] reports `Unknown` rather than `Success` for that case.

use std::collections::BTreeSet;

/// CPU ticks per second of sustained growth required to conclude a process is executing.
///
/// # How this number was chosen
///
/// `tools/measure-cpu-signal.sh` measures the same quantity on this machine, sampling the
/// process tree at 1 s and again at 4 s of an 8 s run, so the window is **3 s** and it starts
/// **after** Wine has finished starting. Measured growth across that window:
///
/// | Subject | Tail growth over 3 s |
/// |---|---|
/// | the real ARM64 fixture (infinite loop) | 256, 253, 242, 204, and once 0 |
/// | a file containing only `MZ` | never above 1 |
///
/// So a running loop sustains roughly 68-85 ticks per second here, while a refused file
/// sustains effectively none. Five ticks per second sits more than an order of magnitude below
/// the observed signal and well above the observed noise, which is the margin a threshold needs
/// if it is not to be calibrated to one machine's exact speed.
///
/// Note the `0` in the first row. It is recorded rather than smoothed away: a single sampling
/// window can miss, which is why [`CpuSampler`] keeps a **peak** across many samples instead
/// of differencing two points. Even so, a fixture that loads can occasionally read as idle,
/// and the cost of that is a lost entry in the dataset rather than a wrong one.
///
/// It is deliberately not tuned tighter. A false `Success` corrupts the dataset this project
/// exists to accumulate, and the cost of a false `Unknown` is only that a run has to be
/// repeated.
pub const MIN_TICKS_PER_SECOND: u64 = 5;

/// CPU-time evidence gathered while a process ran.
///
/// Carried as data so [`crate::classify`] stays pure: the interpretation must be reproducible
/// from a stored record, which it cannot be if the decision depends on reading `/proc` at
/// decision time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuEvidence {
    /// The largest tree total observed over the whole run, in clock ticks.
    pub peak_ticks: u64,
    /// The tree total at the moment the tail window opened, in clock ticks.
    pub tail_baseline_ticks: u64,
    /// How long the tail window lasted, in milliseconds.
    pub tail_window_millis: u64,
}

impl CpuEvidence {
    /// CPU ticks accumulated during the tail window.
    ///
    /// Saturates at zero: the tree total can legitimately *fall* when a descendant exits, and
    /// a negative "growth" is not a quantity worth propagating.
    #[must_use]
    pub fn tail_growth_ticks(&self) -> u64 {
        self.peak_ticks.saturating_sub(self.tail_baseline_ticks)
    }

    /// Sustained CPU consumption during the tail window, in ticks per second.
    ///
    /// Returns `0` when the window has no measurable length, rather than dividing by zero or
    /// inventing a rate from a single sample.
    #[must_use]
    pub fn ticks_per_second(&self) -> u64 {
        if self.tail_window_millis == 0 {
            return 0;
        }
        let growth = self.tail_growth_ticks();
        // Multiply before dividing so a short window does not truncate the rate to zero.
        growth.saturating_mul(1000) / self.tail_window_millis
    }

    /// Returns `true` when the process demonstrably consumed CPU after settling.
    ///
    /// This is corroboration, not proof: a loaded program that idles would fail it. See the
    /// module documentation.
    #[must_use]
    pub fn shows_execution(&self) -> bool {
        self.ticks_per_second() >= MIN_TICKS_PER_SECOND
    }
}

/// Samples the CPU time consumed by a process and its descendants.
#[derive(Debug, Clone)]
pub struct CpuSampler {
    root: u32,
    /// The largest tree total seen. A peak, not a final reading: the process is killed at the
    /// deadline and its `/proc` entry vanishes, so a final reading is frequently zero for the
    /// very reason under investigation.
    peak: u64,
    /// Total at the moment the tail window opened, or `None` while it has not opened yet.
    tail_baseline: Option<u64>,
    /// `true` once at least one sample succeeded.
    measured: bool,
    /// Process ids ever seen in the subtree, so a descendant that reparents is still counted.
    seen: BTreeSet<u32>,
    samples: u64,
}

impl CpuSampler {
    /// Begins sampling for a spawned process.
    #[must_use]
    pub fn new(root: u32) -> Self {
        CpuSampler {
            root,
            peak: 0,
            tail_baseline: None,
            measured: false,
            seen: BTreeSet::new(),
            samples: 0,
        }
    }

    /// The process being observed.
    #[must_use]
    pub fn root(&self) -> u32 {
        self.root
    }

    /// Takes one reading and folds the tree total into the peak.
    ///
    /// Returns the total for this sample, or `None` when `/proc` could not be read. `None` is
    /// deliberately distinct from `Some(0)`: the first means the instrument was unavailable,
    /// the second means it worked and observed no CPU consumption.
    pub fn sample(&mut self) -> Option<u64> {
        self.samples += 1;
        let total = subtree_ticks(self.root, &mut self.seen)?;
        self.measured = true;
        if total > self.peak {
            self.peak = total;
        }
        Some(total)
    }

    /// Marks the start of the tail window, using the most recent sample.
    ///
    /// Called once, after start-up has settled. Measuring from process start would include
    /// Wine's own initialisation, which is CPU-heavy and has nothing to do with the binary —
    /// the first attempt at this measurement did exactly that and produced a real fixture
    /// reading of 26 ticks, overlapping the negative controls.
    pub fn begin_tail_window(&mut self) {
        if self.tail_baseline.is_none() {
            self.tail_baseline = Some(self.peak);
        }
    }

    /// How many samples were taken, for diagnostics.
    #[must_use]
    pub fn sample_count(&self) -> u64 {
        self.samples
    }

    /// The evidence gathered, or `None` when no sample ever succeeded.
    ///
    /// `None` is the honest answer when `/proc` is unavailable, and the caller must not read
    /// it as "measured zero CPU".
    #[must_use]
    pub fn evidence(&self, tail_window_millis: u64) -> Option<CpuEvidence> {
        if !self.measured {
            return None;
        }
        Some(CpuEvidence {
            peak_ticks: self.peak,
            // Without an explicit tail baseline, the peak is the baseline: that yields zero
            // growth, which reports "not demonstrated" rather than inventing a signal.
            tail_baseline_ticks: self.tail_baseline.unwrap_or(self.peak),
            tail_window_millis,
        })
    }
}

/// Parses one `/proc/<pid>/stat` into `(ppid, cpu_ticks)`.
///
/// Pure, so the field arithmetic can be tested directly. The process name sits in parentheses
/// and **may contain spaces**, so fields are counted from after the final `)` rather than by
/// splitting the whole line. Splitting naively reads the wrong field for any process whose
/// name contains a space, and the resulting error is silent — it yields a plausible number.
///
/// From `proc(5)`: after the closing parenthesis, token 1 is `state` (field 3), token 2 is
/// `ppid` (field 4), and `utime`/`stime` are fields 14 and 15 — tokens 12 and 13.
#[must_use]
pub fn parse_stat(text: &str) -> Option<(u32, u64)> {
    let rest = text.rsplit_once(')')?.1;

    let mut fields = rest.split_whitespace();
    fields.next()?; // state
    let parent = fields.next()?.parse::<u32>().ok()?;

    let mut utime = 0u64;
    let mut stime = 0u64;
    for (index, field) in fields.enumerate() {
        // The iterator now begins at field 5 (pgrp), so the field number is index + 5.
        match index + 5 {
            14 => utime = field.parse().unwrap_or(0),
            15 => stime = field.parse().unwrap_or(0),
            _ => {}
        }
    }

    Some((parent, utime + stime))
}

/// Sums the CPU ticks of a process and every descendant.
///
/// Returns `None` when `/proc` is unreadable, which is a different answer from a sum of zero.
fn subtree_ticks(root: u32, seen: &mut BTreeSet<u32>) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let entries = read_process_table()?;

        seen.insert(root);

        // Fixed-point closure rather than recursion: the table is unordered, so a child can
        // appear before its parent and a single pass would miss it.
        loop {
            let mut grew = false;
            for (pid, parent, _) in &entries {
                if (seen.contains(parent) || *pid == root) && seen.insert(*pid) {
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }

        let total: u64 = entries
            .iter()
            .filter(|(pid, _, _)| seen.contains(pid))
            .map(|(_, _, ticks)| ticks)
            .sum();
        Some(total)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // No `/proc`. `None` means "not measured"; the caller must not read it as zero.
        let _ = (root, seen);
        None
    }
}

/// Reads `(pid, ppid, ticks)` for every process currently in `/proc`.
#[cfg(target_os = "linux")]
fn read_process_table() -> Option<Vec<(u32, u32, u64)>> {
    let directory = std::fs::read_dir("/proc").ok()?;
    let mut table = Vec::new();

    for entry in directory.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|text| text.parse::<u32>().ok()) else {
            continue;
        };
        if let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            if let Some((parent, ticks)) = parse_stat(&text) {
                table.push((pid, parent, ticks));
            }
        }
    }

    Some(table)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stat_line_with_a_spaced_process_name_still_parses() {
        // Wine's loader is reported as `wine64-preloader` on some systems, and a naive
        // `split_whitespace` on the whole line would then read the wrong fields entirely —
        // silently, producing a plausible number. Fields start after the final ')'.
        let line = "4211 (some proc (name)) R 900 4211 4211 0 -1 4194560 0 0 0 0 \
                    700 300 0 0 20 0 1 0 12345 6789 0";
        let (parent, ticks) = parse_stat(line).expect("must parse");
        assert_eq!(parent, 900);
        assert_eq!(ticks, 1000, "utime(700) + stime(300)");
    }

    #[test]
    fn a_malformed_line_is_rejected_rather_than_guessed_at() {
        // A line with no parenthesis has no process name, so the field positions are unknown.
        // Returning a number here would be inventing data.
        assert!(parse_stat("nonsense without parens").is_none());
        assert!(parse_stat("").is_none());
        assert!(parse_stat("1 (x) R").is_none());
    }

    #[test]
    fn ticks_per_second_multiplies_before_dividing() {
        // 40 ticks in a 4 s window is 10 ticks/s. Dividing first would give 40/4000 = 0 and
        // silently report a running process as idle.
        let evidence = CpuEvidence {
            peak_ticks: 40,
            tail_baseline_ticks: 0,
            tail_window_millis: 4000,
        };
        assert_eq!(evidence.ticks_per_second(), 10);
        assert!(evidence.shows_execution());
    }

    #[test]
    fn a_zero_length_window_reports_zero_instead_of_dividing_by_zero() {
        let evidence = CpuEvidence {
            peak_ticks: 500,
            tail_baseline_ticks: 0,
            tail_window_millis: 0,
        };
        assert_eq!(evidence.ticks_per_second(), 0);
        assert!(!evidence.shows_execution());
    }

    #[test]
    fn a_tree_total_that_falls_is_not_reported_as_negative_growth() {
        // A descendant exiting lowers the tree total. That is not evidence of anything.
        let evidence = CpuEvidence {
            peak_ticks: 100,
            tail_baseline_ticks: 150,
            tail_window_millis: 1000,
        };
        assert_eq!(evidence.tail_growth_ticks(), 0);
        assert!(!evidence.shows_execution());
    }

    #[test]
    fn the_measured_thresholds_are_separated_by_the_constant() {
        // The two numbers this threshold exists to separate, taken from
        // `tools/measure-cpu-signal.sh` and converted to a rate over its 3 s window:
        //
        //   a file Wine cannot execute : never above 1 tick over the window = 0 ticks/s
        //   the real ARM64 fixture     : 204 ticks at the lowest             = 68 ticks/s
        //
        // Both must land on the correct side, with the threshold strictly between them. A
        // threshold outside that interval would either accept a blocked loader or reject a
        // running loop, and those are the two errors this constant exists to prevent.
        let refused = CpuEvidence {
            peak_ticks: 1,
            tail_baseline_ticks: 0,
            tail_window_millis: 3000,
        };
        let executing = CpuEvidence {
            peak_ticks: 204,
            tail_baseline_ticks: 0,
            tail_window_millis: 3000,
        };
        assert_eq!(refused.ticks_per_second(), 0);
        assert_eq!(executing.ticks_per_second(), 68);
        assert!(!refused.shows_execution());
        assert!(executing.shows_execution());
        assert!(MIN_TICKS_PER_SECOND > refused.ticks_per_second());
        assert!(MIN_TICKS_PER_SECOND < executing.ticks_per_second());
    }

    #[test]
    fn an_unmeasured_sampler_reports_none_rather_than_zero() {
        // The distinction the whole module rests on: "I did not look" is not "I looked and
        // found nothing", and collapsing them is how a check reports a fact it never had.
        let sampler = CpuSampler::new(std::process::id());
        assert_eq!(sampler.evidence(1000), None);
        assert_eq!(sampler.sample_count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_busy_child_process_accumulates_cpu_in_its_tree() {
        // The sampler must work on a real child process before its readings mean anything about
        // Wine, and the shape matters: this is exactly production, where the sampled process is
        // a child rather than the current thread.
        //
        // An earlier version of this test burned CPU in the test thread itself with a counting
        // loop, and it passed in debug and failed in `--release` on CI. The optimiser folded the
        // loop into a constant, so no CPU was burned, the reading was genuinely zero, and the
        // assertion fired. The test was measuring the compiler, not the sampler.
        //
        // Two further reasons to spawn rather than self-sample: `cargo test` runs tests in
        // threads, and whether `/proc/<tgid>/stat` aggregates thread time is not something this
        // test should depend on; and a child is what the runner actually observes.
        use std::process::{Command, Stdio};
        use std::time::Duration;

        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("while :; do :; done")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("/bin/sh must exist for this test");

        let mut sampler = CpuSampler::new(child.id());
        sampler.sample().expect("/proc must be readable");

        // Long enough to accumulate several ticks at any plausible HZ, without making the suite
        // slow: Linux counts in 100 Hz ticks by default, so 400 ms is about 40 of them.
        std::thread::sleep(Duration::from_millis(400));
        sampler.sample().expect("/proc must be readable");

        let peak_while_running = sampler.evidence(400).expect("measured").peak_ticks;

        let _ = child.kill();
        let _ = child.wait();

        assert!(
            peak_while_running > 0,
            "a busy child consumed CPU, so a peak of zero means the sampler is broken"
        );

        // The process is gone now. A further sample must not reduce the peak: the process is
        // killed at the deadline in production, so a final reading is frequently zero for
        // exactly the case the peak exists to survive.
        sampler.sample();
        assert!(
            sampler.evidence(400).expect("measured").peak_ticks >= peak_while_running,
            "the peak must not fall when the process disappears"
        );
    }

    #[test]
    fn a_sampler_that_never_sampled_reports_none_not_zero() {
        // "I did not look" is not "I looked and found nothing". A sampler whose `/proc` reads
        // all failed must not become indistinguishable from one that measured real silence.
        let sampler = CpuSampler::new(std::process::id());
        assert_eq!(sampler.evidence(1000), None);
        assert_eq!(sampler.sample_count(), 0);
    }

    #[test]
    fn an_impossible_pid_is_a_measurement_not_a_failure() {
        // `/proc` is readable, the pid simply is not there. That is a successful measurement of
        // an empty tree, so it is `Some(0)` rather than `None` -- the distinction the caller
        // relies on to tell a broken instrument from an absent process.
        let mut sampler = CpuSampler::new(4_000_000_000);
        assert_eq!(sampler.sample(), Some(0));
        let evidence = sampler.evidence(500).expect("measured");
        assert_eq!(evidence.peak_ticks, 0);
        assert!(!evidence.shows_execution());
    }

    #[test]
    fn a_tail_baseline_is_taken_only_once() {
        // A second call must not move the baseline forward, which would shrink the window
        // each time and eventually report a running process as idle.
        let mut sampler = CpuSampler::new(std::process::id());
        sampler.sample().expect("readable");
        sampler.begin_tail_window();
        let first = sampler
            .evidence(1000)
            .expect("measured")
            .tail_baseline_ticks;

        let mut spin = 0u64;
        for i in 0..30_000_000u64 {
            spin = spin.wrapping_add(i);
        }
        sampler.sample().expect("readable");
        sampler.begin_tail_window();
        let second = sampler
            .evidence(1000)
            .expect("measured")
            .tail_baseline_ticks;
        assert_eq!(first, second, "the tail window must not be restarted");
    }
}
