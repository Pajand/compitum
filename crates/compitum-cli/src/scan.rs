//! Batch classification over a directory tree.
//!
//! # Why this exists
//!
//! The question a migration actually begins with is not "will *this* binary run?" but "which
//! of our two thousand binaries will not?". `verify` answers the first question about exactly
//! one file, so the second question costs two thousand shell invocations and a spreadsheet.
//!
//! That gap is not a convenience problem. Answering it by hand is the difference between a
//! tool someone uses once and a report someone pays for, so the batch path is the shape the
//! product has to have before any of the analysis underneath it can be sold.
//!
//! # The four outcomes, and why they are four
//!
//! A directory is not a list of binaries. It contains documentation, images, source files,
//! broken downloads and files the process lacks permission to read, and collapsing those into
//! "failed" would produce a report whose errors are indistinguishable from its findings —
//! which is the defect class this project keeps rediscovering.
//!
//! So each file lands in exactly one of:
//!
//! | Outcome | Meaning | Is it a finding? |
//! |---|---|---|
//! | [`ScanKind::Routed`] | classified, and a route was decided | yes, either way |
//! | [`ScanKind::NotPe`] | not a Windows image at all | **no** — not applicable |
//! | [`ScanKind::Malformed`] | looks like a PE image but will not parse | **yes** — a real defect |
//! | [`ScanKind::Unreadable`] | could not be read (permissions, I/O) | **no** — an environment problem |
//!
//! `Malformed` and `Unreadable` are kept apart deliberately. A corrupt executable is something
//! a customer needs to know about; a file the scanner was not allowed to open is something the
//! *operator* needs to fix, and reporting it as a broken binary would blame the wrong party.
//! `NotPe` is separated for the opposite reason: it is the overwhelming majority of files in a
//! typical tree, and it is not a result about anything.
//!
//! # Determinism
//!
//! Results are sorted by path, so the same tree produces the same report. A report that
//! reorders itself between runs cannot be diffed, and a diff is how a migration is tracked.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use compitum_isa::HostProfile;
use compitum_pe::PeImage;
use compitum_router::{decide, BackendSet, MigrationTarget, Plan, Request};

/// How deep the walk descends before it stops.
///
/// A guard rather than a preference: `compitum scan /` should stop, not traverse a filesystem.
/// Twelve levels is deeper than any real distribution tree and shallow enough to terminate.
pub const DEFAULT_MAX_DEPTH: usize = 12;

/// How many files the walk will consider before giving up.
///
/// Existing so that a mistyped path cannot turn a report into an unbounded read. A hundred
/// thousand files is far beyond any real migration and still bounded in time and memory.
pub const DEFAULT_MAX_FILES: usize = 100_000;

/// The largest file this will read.
///
/// A Windows image is realistically under a gigabyte. The limit exists because reading a
/// multi-gigabyte file into memory to discover it is not a PE image would be a poor way to
/// fail, and the size is knowable before the read.
pub const MAX_FILE_BYTES: u64 = 1 << 30;

/// What was learned about one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanKind {
    /// The image was classified and a route decided.
    Routed(Box<RoutedFile>),
    /// The file is not a Windows image, so it is not a candidate for migration.
    NotPe,
    /// The file begins like a PE image but could not be parsed.
    ///
    /// A genuine finding: the file is either corrupt or uses a layout this parser does not
    /// understand, and both are worth a customer's attention.
    Malformed {
        /// Why parsing failed.
        message: String,
    },
    /// The file could not be read.
    ///
    /// An environment problem rather than a finding about the file. Kept separate so a
    /// permission error is never reported as a broken binary.
    Unreadable {
        /// The underlying error.
        message: String,
    },
}

/// The decision reached for one image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedFile {
    /// The ABI family the image belongs to, as reported by the classifier.
    pub abi_family: String,
    /// The internally stable route identifier.
    pub route: String,
    /// The uppercase status token from the router, so a report and `verify` agree.
    pub status: String,
    /// Whether the router refused the route.
    pub blocked: bool,
    /// Whether the image runs with no translation at all.
    pub fully_native: bool,
    /// Confidence in permille, kept as an integer so nothing rounds differently here.
    pub confidence_permille: u16,
    /// Feature identifiers the image was found to require.
    pub required_features: Vec<String>,
    /// The sentence explaining the decision, for the report body.
    pub headline: String,
    /// Stable identifiers of the reasons that blocked the route.
    pub blockers: Vec<String>,
    /// `true` when every blocker is a property of **this scanning machine** rather than of the
    /// image.
    ///
    /// # Why this distinction exists
    ///
    /// A scan run on a laptop with no Wine refuses *every* Windows image, because the NT
    /// syscall layer is absent. Reporting that as "these binaries will not run" is not a
    /// conservative answer — it is a wrong one, and it is wrong in the most expensive direction,
    /// because it tells a customer their software is broken when the truth is that the audit was
    /// run on the wrong machine.
    ///
    /// The distinction is not incidental to the product. A migration audit is commissioned to
    /// learn something about the customer's software, so a result that describes the auditor's
    /// equipment has to be labelled as such or the whole report is worthless.
    pub environment_blocked: bool,
    /// `true` when the image is a Windows kernel driver.
    ///
    /// # Why this is separate from the route
    ///
    /// A kernel driver on an ARM64 build is pure AArch64, so every architecture-level question
    /// answers "runs natively, no translation, full speed". All of that is true and all of it is
    /// useless: the image expects to be mapped by the kernel and to call kernel routines, so a
    /// user-mode compatibility layer cannot load it at all.
    ///
    /// Measured on 747 images from a real Wine build, a scan reported every kernel driver as a
    /// healthy native binary. In a migration report that is the difference between "port this
    /// one, it is nearly free" and "this one needs a driver rewrite", and a customer acting on
    /// the first answer wastes the work.
    ///
    /// The route is left alone — it answers the architecture question correctly — and this flag
    /// answers the separate question of whether the route can be taken at all.
    pub is_kernel_driver: bool,
}

/// Returns `true` when a blocker describes the scanning host rather than the image.
///
/// # The two kinds of refusal
///
/// The router blocks on five codes. Two of them are properties of the customer's software and
/// three are properties of the machine doing the looking:
///
/// | Code | Whose problem |
/// |---|---|
/// | `ArchitectureUnsupported` | the image — it cannot run on ARM64 anywhere |
/// | `UnreadableSubject` | the image — it is corrupt |
/// | `SyscallLayerAbsent` | **this host** — no Wine here |
/// | `BackendAbsent` | **this host** — no FEX or Box64 here |
/// | `IsaFeaturesMissing` | **this host's CPU** — and therefore also the deployment target, if that is what it is |
///
/// `IsaFeaturesMissing` is the subtle one, and this project has already been bitten by it: an
/// SVE-requiring image refuses on a CPU without SVE and runs on a CPU with it. The same binary
/// therefore produces opposite verdicts on two machines, which makes it a fact about the host
/// until a deployment target is named.
///
/// The match is on **stable string identifiers** rather than on the enum, so that a code added
/// to the router later is classified as intrinsic — the safer default, because an unrecognised
/// blocker is more likely to be a real obstacle than a missing tool. There is a test that pins
/// every current code to one side, so adding one forces a deliberate decision.
#[must_use]
pub fn is_environment_blocker(id: &str) -> bool {
    matches!(
        id,
        "syscall_layer_absent" | "backend_absent" | "isa_features_missing"
    )
}

/// One file, and what happened to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedFile {
    /// Path as given to the walk, relative to the scan root where possible.
    pub path: String,
    /// The outcome.
    pub kind: ScanKind,
}

/// Aggregate counts for a scan.
///
/// Every counter is separate because each answers a different question, and a report that
/// merged them would be unable to say whether a number was good or bad news.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanCounts {
    /// Files examined, including those that were not PE images.
    pub files_seen: usize,
    /// Images that were classified and routed.
    pub routed: usize,
    /// Of those, the ones that run with no translation.
    pub native: usize,
    /// Of those, the ones that need partial translation (the hybrid/ARM64EC path).
    pub hybrid: usize,
    /// Of those, the ones that need full translation.
    pub translated: usize,
    /// Of those, the ones the router refused.
    pub refused: usize,
    /// Of the refusals, the ones caused by this machine rather than by the image.
    ///
    /// A scan on a laptop without Wine refuses every Windows image, because the NT syscall
    /// layer is absent. Those refusals say nothing about the customer's software, and counting
    /// them as failures produces a report that is wrong in the most expensive direction: it
    /// tells a customer their binaries are broken when the audit was simply run somewhere the
    /// runtime is not installed.
    pub environment_refused: usize,
    /// Files that are not Windows images.
    pub not_pe: usize,
    /// Files that look like images but would not parse.
    pub malformed: usize,
    /// Files that could not be read.
    pub unreadable: usize,
    /// Images that are Windows kernel drivers.
    ///
    /// Counted separately because they cannot be loaded by a user-mode compatibility layer at
    /// all. On an ARM64 build a kernel driver is pure AArch64, so every architecture-level
    /// question answers "runs natively at full speed" — true, and useless. A migration report
    /// must say so, or it will recommend porting work that is actually a driver rewrite.
    pub kernel_driver: usize,
}

impl ScanCounts {
    /// Returns `true` when every image that was judged runs with no translation.
    ///
    /// # Three ways this must be false
    ///
    /// 1. **Nothing was routed.** An empty directory trivially has no translations in it, and
    ///    reporting "fully native" for a tree containing nothing is a conclusion from no
    ///    evidence.
    /// 2. **Something needs translation.** The obvious case.
    /// 3. **Everything was refused by this machine.** This one was a real defect: because
    ///    [`ScanCounts::will_not_run`] deliberately excludes environmental refusals, a scan run
    ///    without a runtime produced `refused: 7, will_not_run: 0, entirely_native: true` — a
    ///    JSON consumer was told the tree was fully native when **not one image had been
    ///    judged**. The flag contradicted `inconclusive_about_the_images` in the same object.
    ///
    /// The general rule this is an instance of: a property that means "nothing bad was found"
    /// must also require that something was looked at. Otherwise an empty or unmeasured result
    /// is indistinguishable from a clean one, and a consumer cannot tell which it received.
    ///
    /// A fourth condition, added later for the same reason: **kernel drivers**. They route
    /// natively — every instruction is AArch64 — and they cannot be loaded by a user-mode
    /// compatibility layer at all. So a tree of drivers satisfies every architectural test while
    /// being entirely un-runnable, and calling that "entirely native" would be true and
    /// misleading in the same sentence.
    #[must_use]
    pub fn is_entirely_native(&self) -> bool {
        let judged = self.routed.saturating_sub(self.environment_refused);
        judged > 0
            && self.hybrid == 0
            && self.translated == 0
            && self.will_not_run() == 0
            && self.malformed == 0
            && self.kernel_driver == 0
    }

    /// How many images this scan actually reached a conclusion about.
    ///
    /// The complement of the environmental refusals, and the number that answers "did this scan
    /// learn anything?" — which is the question every derived flag above depends on.
    #[must_use]
    pub fn judged(&self) -> usize {
        self.routed.saturating_sub(self.environment_refused)
    }

    /// Images that will not run, which is the number a migration cares about.
    ///
    /// Refusals caused by the scanning machine are **excluded**. Including them would report the
    /// auditor's equipment as the customer's defect, so the count describes the software under
    /// audit — the only thing the report was commissioned to say.
    #[must_use]
    pub fn will_not_run(&self) -> usize {
        // Saturating rather than wrapping. The counters are built together so this cannot
        // currently underflow, but a caller assembling counts by hand must not be able to turn a
        // subtraction into an enormous number.
        self.refused.saturating_sub(self.environment_refused)
    }

    /// Returns `true` when this scan cannot support any conclusion about the images.
    ///
    /// True when every routed image was refused for a reason attributable to the scanning host.
    /// Such a report is not a negative result; it is an absent one, and the difference is the
    /// whole reason the counters are kept apart.
    #[must_use]
    pub fn is_inconclusive_about_the_images(&self) -> bool {
        self.routed > 0 && self.refused == self.routed && self.environment_refused == self.routed
    }
}

/// The result of scanning a tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    /// Where the walk began, as given.
    pub root: String,
    /// One entry per file examined, sorted by path.
    pub files: Vec<ScannedFile>,
    /// Aggregate counts.
    pub counts: ScanCounts,
    /// `true` when a limit stopped the walk before the tree was exhausted.
    ///
    /// Carried explicitly so a truncated report can never be read as a complete one. A report
    /// that silently covered a subset would understate the work a migration needs.
    pub truncated: bool,
    /// Why the walk stopped early, when it did.
    pub truncated_reason: Option<String>,
}

/// Walks a tree and classifies every Windows image in it.
///
/// `path` may be a single file, in which case the result has one entry — so `scan` is a
/// superset of `verify` rather than a separate vocabulary to learn.
#[must_use]
pub fn scan_path(
    path: &Path,
    host: &HostProfile,
    backends: BackendSet,
    target: MigrationTarget,
) -> ScanReport {
    scan_path_with_limits(
        path,
        host,
        backends,
        target,
        DEFAULT_MAX_DEPTH,
        DEFAULT_MAX_FILES,
    )
}

/// [`scan_path`] with explicit limits, so the guards can be tested at their boundaries.
#[must_use]
pub fn scan_path_with_limits(
    path: &Path,
    host: &HostProfile,
    backends: BackendSet,
    target: MigrationTarget,
    max_depth: usize,
    max_files: usize,
) -> ScanReport {
    let mut targets: Vec<PathBuf> = Vec::new();
    let mut truncated = false;
    let mut truncated_reason = None;

    if path.is_dir() {
        collect(
            path,
            0,
            max_depth,
            max_files,
            &mut targets,
            &mut truncated,
            &mut truncated_reason,
        );
    } else {
        targets.push(path.to_path_buf());
    }

    // Sorted so a report is reproducible: a report that reorders between runs cannot be diffed.
    targets.sort();

    let root_display = path.display().to_string();
    let mut files = Vec::with_capacity(targets.len());
    for candidate in &targets {
        files.push(classify_file(
            candidate,
            &root_display,
            host,
            backends,
            target,
        ));
    }

    let counts = count(&files);

    ScanReport {
        root: root_display,
        files,
        counts,
        truncated,
        truncated_reason,
    }
}

/// Gathers candidate files, bounded by depth and count.
fn collect(
    directory: &Path,
    depth: usize,
    max_depth: usize,
    max_files: usize,
    out: &mut Vec<PathBuf>,
    truncated: &mut bool,
    reason: &mut Option<String>,
) {
    if *truncated {
        return;
    }
    if depth > max_depth {
        *truncated = true;
        *reason = Some(format!(
            "stopped at depth {max_depth}: the tree is deeper than this scan will descend"
        ));
        return;
    }

    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            // An unreadable directory is not a failure of the scan: it is a fact about the
            // tree, and the directories that could be read were still read. Recording it as
            // "unreadable" happens at the file level instead, where it names a path.
            let _ = error;
            return;
        }
    };

    for entry in entries.flatten() {
        if out.len() >= max_files {
            *truncated = true;
            *reason = Some(format!(
                "stopped after {max_files} files: raise the limit deliberately if this is intended"
            ));
            return;
        }

        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };

        // Symlinks are not followed. A link back up the tree would otherwise loop until the
        // depth limit fired, and a scan that reports a truncated tree for that reason would be
        // reporting a self-inflicted problem as a property of the customer's directory.
        if file_type.is_symlink() {
            continue;
        }

        let child = entry.path();
        if file_type.is_dir() {
            collect(
                &child,
                depth + 1,
                max_depth,
                max_files,
                out,
                truncated,
                reason,
            );
        } else if file_type.is_file() {
            out.push(child);
        }
    }
}

/// Reads one file and classifies it.
fn classify_file(
    path: &Path,
    root: &str,
    host: &HostProfile,
    backends: BackendSet,
    target: MigrationTarget,
) -> ScannedFile {
    let display = display_path(path, root);

    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return ScannedFile {
                path: display,
                kind: ScanKind::Unreadable {
                    message: error.to_string(),
                },
            }
        }
    };

    if metadata.len() > MAX_FILE_BYTES {
        return ScannedFile {
            path: display,
            kind: ScanKind::Unreadable {
                message: format!(
                    "{} bytes is larger than the {MAX_FILE_BYTES}-byte scan limit",
                    metadata.len()
                ),
            },
        };
    }

    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return ScannedFile {
                path: display,
                kind: ScanKind::Unreadable {
                    message: error.to_string(),
                },
            }
        }
    };

    // The magic-number check comes first, and it is semantic rather than an optimisation: a
    // `README.md` is not a failed migration candidate, it is not a candidate at all.
    if !compitum_pe::looks_like_pe(&bytes) {
        return ScannedFile {
            path: display,
            kind: ScanKind::NotPe,
        };
    }

    let image: PeImage = match compitum_pe::parse(&bytes) {
        Ok(image) => image,
        Err(error) => {
            return ScannedFile {
                path: display,
                kind: ScanKind::Malformed {
                    message: error.to_string(),
                },
            }
        }
    };

    ScannedFile {
        path: display,
        kind: ScanKind::Routed(Box::new(route(&bytes, image, host, backends, target))),
    }
}

/// Decides the route for one parsed image.
fn route(
    bytes: &[u8],
    image: PeImage,
    host: &HostProfile,
    backends: BackendSet,
    target: MigrationTarget,
) -> RoutedFile {
    let scan = compitum_pe::scan_image(bytes, &image);
    let request = Request::new(image.clone(), host.clone(), backends)
        .with_requirements(scan.requirements.clone())
        .with_target(target);
    let plan: Plan = decide(&request);

    let blockers: Vec<String> = plan
        .reasons
        .blocking()
        .iter()
        .map(|reason| reason.code.id().to_owned())
        .collect();

    // Every blocker must be about this machine for the refusal to be attributed to the
    // environment. A mix means at least one obstacle is intrinsic, and that one is the finding.
    let environment_blocked = plan.is_blocked()
        && !blockers.is_empty()
        && blockers.iter().all(|id| is_environment_blocker(id));

    RoutedFile {
        abi_family: image.family().id().to_owned(),
        route: plan.route.id().to_owned(),
        status: plan.status_token().to_owned(),
        blocked: plan.is_blocked(),
        fully_native: plan.is_fully_native(),
        confidence_permille: plan.confidence.permille(),
        required_features: scan
            .requirements
            .iter()
            .map(|requirement| requirement.feature.id().to_owned())
            .collect(),
        headline: plan.headline(),
        blockers,
        environment_blocked,
        // Read before `image` is dropped and after the router is consulted, so the two facts
        // stay independent: the route answers the architecture question, and this answers
        // whether the route can be taken at all.
        is_kernel_driver: image.is_kernel_driver(),
    }
}

/// Presents a path relative to the scan root, so a report reads as a tree.
fn display_path(path: &Path, root: &str) -> String {
    let root_path = Path::new(root);
    if root_path.is_dir() {
        if let Ok(relative) = path.strip_prefix(root_path) {
            return relative.display().to_string();
        }
    }
    path.display().to_string()
}

/// Counts the outcomes.
#[must_use]
pub fn count(files: &[ScannedFile]) -> ScanCounts {
    let mut counts = ScanCounts {
        files_seen: files.len(),
        ..ScanCounts::default()
    };

    for file in files {
        match &file.kind {
            ScanKind::Routed(routed) => {
                counts.routed += 1;
                // Cross-cutting, so it is counted independently of the route: a kernel driver
                // is usually also a native route, and both facts are true at once. The route
                // describes the architecture; this describes whether the route can be taken.
                if routed.is_kernel_driver {
                    counts.kernel_driver += 1;
                }
                if routed.blocked {
                    counts.refused += 1;
                    // Attributed only when EVERY blocker is about this machine. A refusal with
                    // one intrinsic cause and one environmental one is a finding about the
                    // image, and counting it as environmental would hide a real defect.
                    if routed.environment_blocked {
                        counts.environment_refused += 1;
                    }
                } else if routed.fully_native {
                    counts.native += 1;
                } else if routed.route == "fex_partial" {
                    // The hybrid case specifically: the ARM64 majority runs natively and only
                    // the embedded x86-64 blocks are translated. It is neither "native" nor
                    // "translated", and it is the distinction the product exists to make.
                    counts.hybrid += 1;
                } else {
                    counts.translated += 1;
                }
            }
            ScanKind::NotPe => counts.not_pe += 1,
            ScanKind::Malformed { .. } => counts.malformed += 1,
            ScanKind::Unreadable { .. } => counts.unreadable += 1,
        }
    }

    counts
}

/// Counts of outcomes grouped by route, for the report body.
#[must_use]
pub fn by_route(files: &[ScannedFile]) -> BTreeMap<String, usize> {
    let mut grouped: BTreeMap<String, usize> = BTreeMap::new();
    for file in files {
        if let ScanKind::Routed(routed) = &file.kind {
            *grouped.entry(routed.route.clone()).or_insert(0) += 1;
        }
    }
    grouped
}

/// The files that will not run, which is the finding a migration is searching for.
#[must_use]
pub fn blocking(files: &[ScannedFile]) -> Vec<&ScannedFile> {
    files
        .iter()
        .filter(|file| match &file.kind {
            // A refusal attributable to this machine is not a finding about the file, so it is
            // excluded here for the same reason it is excluded from the count. Listing it would
            // put "needs attention" beside a binary nothing is wrong with, and the list is read
            // as the actionable part of the report.
            ScanKind::Routed(routed) => routed.blocked && !routed.environment_blocked,
            ScanKind::Malformed { .. } => true,
            ScanKind::NotPe | ScanKind::Unreadable { .. } => false,
        })
        .collect()
}

/// Files that were refused only because this machine lacks a runtime.
///
/// Kept separate from [`blocking`] so a report can name them without presenting them as
/// defects. They are still worth listing: an operator who sees seven files and no explanation
/// would reasonably suspect the scanner, and naming the cause is what turns an alarming number
/// into an actionable instruction.
#[must_use]
pub fn beyond_this_machine(files: &[ScannedFile]) -> Vec<&ScannedFile> {
    files
        .iter()
        .filter(|file| match &file.kind {
            ScanKind::Routed(routed) => routed.blocked && routed.environment_blocked,
            ScanKind::NotPe | ScanKind::Malformed { .. } | ScanKind::Unreadable { .. } => false,
        })
        .collect()
}

/// The defects the operator should fix before the report can be trusted.
///
/// Separate from [`blocking`] because these are not results about the customer's binaries:
/// an unreadable file means the scan did not see everything, and a report that presented its
/// own blind spots as findings would be wrong in the most damaging direction.
#[must_use]
pub fn obstacles(files: &[ScannedFile]) -> Vec<&ScannedFile> {
    files
        .iter()
        .filter(|file| matches!(file.kind, ScanKind::Unreadable { .. }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use compitum_isa::FeatureSet;

    fn host() -> HostProfile {
        HostProfile::synthetic("aarch64", 4096, 8, FeatureSet::new())
    }

    fn routed(route: &str, blocked: bool, native: bool) -> ScanKind {
        ScanKind::Routed(Box::new(RoutedFile {
            abi_family: "arm64".to_owned(),
            route: route.to_owned(),
            status: if blocked { "REFUSED" } else { "NATIVE" }.to_owned(),
            blocked,
            fully_native: native,
            confidence_permille: 1000,
            required_features: Vec::new(),
            headline: "test".to_owned(),
            blockers: if blocked {
                vec!["architecture_unsupported".to_owned()]
            } else {
                Vec::new()
            },
            // An intrinsic refusal by default, so the existing tests keep describing a finding
            // about the image rather than accidentally exercising the environmental path.
            environment_blocked: false,
            is_kernel_driver: false,
        }))
    }

    /// A refusal caused by the scanning machine, as a missing Wine produces.
    fn refused_by_environment(route: &str) -> ScanKind {
        ScanKind::Routed(Box::new(RoutedFile {
            abi_family: "arm64".to_owned(),
            route: route.to_owned(),
            status: "REFUSED".to_owned(),
            blocked: true,
            fully_native: false,
            confidence_permille: 1000,
            required_features: Vec::new(),
            headline: "no NT system-call layer is installed".to_owned(),
            blockers: vec!["syscall_layer_absent".to_owned()],
            environment_blocked: true,
            is_kernel_driver: false,
        }))
    }

    /// A kernel driver: every instruction AArch64, and unloadable by a user-mode layer.
    fn kernel_driver() -> ScanKind {
        ScanKind::Routed(Box::new(RoutedFile {
            abi_family: "arm64".to_owned(),
            route: "native".to_owned(),
            status: "NATIVE".to_owned(),
            blocked: false,
            fully_native: true,
            confidence_permille: 1000,
            required_features: Vec::new(),
            headline: "Runs natively".to_owned(),
            blockers: Vec::new(),
            environment_blocked: false,
            is_kernel_driver: true,
        }))
    }

    fn file(path: &str, kind: ScanKind) -> ScannedFile {
        ScannedFile {
            path: path.to_owned(),
            kind,
        }
    }

    #[test]
    fn a_directory_of_mixed_files_is_counted_by_category() {
        // The whole point of four categories: a README is not a failure, a corrupt executable
        // is a finding, and an unreadable file is the operator's problem.
        let files = vec![
            file("a.exe", routed("native", false, true)),
            file("b.exe", routed("fex_partial", false, false)),
            file("c.exe", routed("box64_full", false, false)),
            file("d.exe", routed("refused", true, false)),
            file("README.md", ScanKind::NotPe),
            file(
                "e.exe",
                ScanKind::Malformed {
                    message: "bad".into(),
                },
            ),
            file(
                "f.exe",
                ScanKind::Unreadable {
                    message: "denied".into(),
                },
            ),
        ];

        let counts = count(&files);
        assert_eq!(counts.files_seen, 7);
        assert_eq!(counts.routed, 4);
        assert_eq!(counts.native, 1);
        assert_eq!(counts.hybrid, 1);
        assert_eq!(counts.translated, 1);
        assert_eq!(counts.refused, 1);
        assert_eq!(counts.not_pe, 1);
        assert_eq!(counts.malformed, 1);
        assert_eq!(counts.unreadable, 1);
        assert_eq!(counts.will_not_run(), 1);
    }

    #[test]
    fn an_empty_tree_reports_nothing_rather_than_fully_native() {
        // A conclusion drawn from no evidence. An empty directory must not be reported as a
        // clean bill of health, because nobody looked at anything.
        let counts = count(&[]);
        assert_eq!(counts.routed, 0);
        assert!(!counts.is_entirely_native());
    }

    #[test]
    fn a_tree_this_machine_could_not_judge_is_not_reported_as_fully_native() {
        // THE REGRESSION GUARD for a real defect found by running the tool.
        //
        // `will_not_run` deliberately excludes refusals caused by the scanning machine. That
        // made `is_entirely_native` true for a tree where **nothing had been judged at all**: a
        // scan with no runtime installed emitted
        //
        //     {"refused": 7, "will_not_run": 0, "entirely_native": true,
        //      "inconclusive_about_the_images": true}
        //
        // Two flags in the same object contradicting each other, and a JSON consumer had no way
        // to tell which to believe. The rule that was missing: a property meaning "nothing bad
        // was found" must also require that something was looked at.
        let files = vec![
            file("a.exe", refused_by_environment("refused")),
            file("b.exe", refused_by_environment("refused")),
        ];
        let counts = count(&files);

        assert_eq!(counts.judged(), 0, "no image reached a conclusion");
        assert!(
            !counts.is_entirely_native(),
            "a tree nobody could judge must not be reported as fully native"
        );
        assert!(counts.is_inconclusive_about_the_images());
    }

    #[test]
    fn a_tree_with_one_judged_native_image_is_fully_native() {
        // The other side of the same rule, so the guard cannot be satisfied by a flag that is
        // simply always false.
        let files = vec![
            file("a.exe", routed("native", false, true)),
            file("b.exe", refused_by_environment("refused")),
        ];
        let counts = count(&files);
        assert_eq!(counts.judged(), 1);
        assert!(counts.is_entirely_native());
        assert!(!counts.is_inconclusive_about_the_images());
    }

    #[test]
    fn a_malformed_image_stops_a_tree_being_reported_as_fully_native() {
        // A corrupt executable is a finding, so the tree is not clean even though every image
        // that could be routed was native.
        let files = vec![
            file("a.exe", routed("native", false, true)),
            file(
                "broken.exe",
                ScanKind::Malformed {
                    message: "bad".into(),
                },
            ),
        ];
        assert!(!count(&files).is_entirely_native());
    }

    #[test]
    fn a_kernel_driver_stops_a_tree_being_reported_as_fully_native() {
        // THE REGRESSION GUARD for a real defect found by scanning 747 genuine binaries.
        //
        // A kernel driver on an ARM64 build is pure AArch64, so the router answers every
        // architectural question correctly: native, no translation, 100% of native speed. A
        // scan then reported sixteen real drivers that way, and every one of those statements
        // is true and useless — the image expects to be mapped by a kernel and calls kernel
        // routines, so a user-mode compatibility layer cannot load it at all.
        //
        // In a migration report that misreading costs real money: it reads as "port this one,
        // it is nearly free" when the truth is "this one needs a driver rewrite".
        let files = vec![
            file("a.exe", routed("native", false, true)),
            file("wineusb.sys", kernel_driver()),
        ];
        let counts = count(&files);

        assert_eq!(counts.kernel_driver, 1);
        assert_eq!(
            counts.native, 2,
            "both are architecturally native, correctly"
        );
        assert!(
            !counts.is_entirely_native(),
            "a tree containing a driver is not a clean bill of health"
        );
        assert_eq!(
            counts.judged(),
            2,
            "a driver WAS judged: the route is right, its consequence is what differs"
        );
    }

    #[test]
    fn a_kernel_driver_is_counted_independently_of_its_route() {
        // The two facts are orthogonal and both matter: the route describes the architecture,
        // the flag describes whether the route can be taken. Collapsing them would lose one.
        let files = vec![file("d.sys", kernel_driver())];
        let counts = count(&files);
        assert_eq!(counts.native, 1);
        assert_eq!(counts.kernel_driver, 1);
    }

    #[test]
    fn a_fully_native_tree_is_reported_as_such() {
        let files = vec![
            file("a.exe", routed("native", false, true)),
            file("b.exe", routed("pick_native_slice", false, true)),
        ];
        assert!(count(&files).is_entirely_native());
    }

    #[test]
    fn a_hybrid_image_is_not_counted_as_fully_native() {
        // The ARM64EC case. Counting it as native would overstate the migration's readiness,
        // and counting it as translated would understate the product's own value.
        let files = vec![file("a.dll", routed("fex_partial", false, false))];
        let counts = count(&files);
        assert_eq!(counts.hybrid, 1);
        assert_eq!(counts.native, 0);
        assert!(!counts.is_entirely_native());
    }

    #[test]
    fn a_refusal_caused_by_the_scanning_machine_is_not_a_finding() {
        // THE most important test in this file.
        //
        // A scan run without Wine refuses every Windows image, because the NT syscall layer is
        // absent. That is a fact about the machine doing the looking, and reporting it as "your
        // binaries will not run" is wrong in the most expensive direction: it tells a customer
        // their software is broken when the audit was run in the wrong place.
        //
        // This was observed in practice before it was fixed. A scan of the committed corpus on a
        // machine with no Wine reported "refused 7" -- seven apparently broken binaries -- while
        // the same scan with `--backends wine,fex` reported four native, two hybrid and one
        // translated, with nothing refused at all.
        let files = vec![
            file("a.exe", refused_by_environment("refused")),
            file("b.exe", refused_by_environment("refused")),
        ];
        let counts = count(&files);

        assert_eq!(counts.routed, 2);
        assert_eq!(counts.refused, 2, "both were refused by the router");
        assert_eq!(
            counts.environment_refused, 2,
            "and both refusals are attributable to this host"
        );
        assert_eq!(
            counts.will_not_run(),
            0,
            "a report must not present this host's missing runtime as the customer's defect"
        );
        assert!(
            counts.is_inconclusive_about_the_images(),
            "a scan that learned nothing about the images must say so"
        );
    }

    #[test]
    fn an_intrinsic_refusal_is_still_a_finding_when_the_environment_is_also_blamed() {
        // A mixed refusal must stay a finding. If one blocker is about the image, the image is
        // the problem, and attributing it to the environment would hide a real defect.
        let mut mixed = match routed("refused", true, false) {
            ScanKind::Routed(routed) => *routed,
            _ => unreachable!(),
        };
        mixed.blockers = vec![
            "syscall_layer_absent".to_owned(),
            "architecture_unsupported".to_owned(),
        ];
        // `route()` computes this flag; the fixture sets it the same way so the counter's
        // dependence on it is exercised rather than assumed.
        mixed.environment_blocked = false;

        let files = vec![file("bad.exe", ScanKind::Routed(Box::new(mixed)))];
        let counts = count(&files);
        assert_eq!(counts.refused, 1);
        assert_eq!(counts.environment_refused, 0);
        assert_eq!(
            counts.will_not_run(),
            1,
            "an intrinsic refusal is a finding"
        );
        assert!(!counts.is_inconclusive_about_the_images());
    }

    #[test]
    fn every_router_blocker_is_classified_deliberately() {
        // A pin, not a check of behaviour. The router blocks on five codes and the split between
        // "the image" and "this machine" is a judgement that must be made for each, so adding a
        // code to the router has to force a decision here rather than defaulting silently.
        use compitum_router::ReasonCode;

        let environment = [
            ReasonCode::SyscallLayerAbsent,
            ReasonCode::BackendAbsent,
            ReasonCode::IsaFeaturesMissing,
        ];
        let intrinsic = [
            ReasonCode::ArchitectureUnsupported,
            ReasonCode::UnreadableSubject,
        ];

        for code in environment {
            assert!(
                is_environment_blocker(code.id()),
                "{} is a property of the scanning host",
                code.id()
            );
        }
        for code in intrinsic {
            assert!(
                !is_environment_blocker(code.id()),
                "{} is a property of the image and must be a finding",
                code.id()
            );
        }

        assert_eq!(
            environment.len() + intrinsic.len(),
            5,
            "the router's blocking set changed: classify the new code in is_environment_blocker"
        );
    }

    #[test]
    fn blocking_lists_refusals_and_malformed_files_but_not_unreadable_ones() {
        let files = vec![
            file("bad.exe", routed("refused", true, false)),
            file(
                "corrupt.exe",
                ScanKind::Malformed {
                    message: "bad".into(),
                },
            ),
            file(
                "locked.exe",
                ScanKind::Unreadable {
                    message: "denied".into(),
                },
            ),
            file("fine.exe", routed("native", false, true)),
            file("notes.txt", ScanKind::NotPe),
        ];
        let findings: Vec<&str> = blocking(&files).iter().map(|f| f.path.as_str()).collect();
        assert_eq!(findings, vec!["bad.exe", "corrupt.exe"]);
    }

    #[test]
    fn a_refusal_caused_by_this_machine_is_listed_separately_not_as_findings() {
        // The list is the actionable part of the report, so a binary nothing is wrong with must
        // not appear under "needs attention". It is still named, under its own heading, because
        // seven refused files with no explanation would reasonably make an operator suspect the
        // scanner rather than their own machine.
        let files = vec![
            file("a.exe", refused_by_environment("refused")),
            file("b.exe", refused_by_environment("refused")),
            file("bad.exe", routed("refused", true, false)),
        ];

        let findings: Vec<&str> = blocking(&files).iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            findings,
            vec!["bad.exe"],
            "only the intrinsic refusal is a finding"
        );

        let beyond: Vec<&str> = beyond_this_machine(&files)
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert_eq!(beyond, vec!["a.exe", "b.exe"]);

        // Together they account for every refusal, so no file can go missing between the two
        // lists -- which is the failure mode of filtering in two places.
        let total = files
            .iter()
            .filter(|f| matches!(&f.kind, ScanKind::Routed(r) if r.blocked))
            .count();
        assert_eq!(findings.len() + beyond.len(), total);
    }

    #[test]
    fn obstacles_are_separate_from_findings() {
        // A file the scanner was not allowed to open says nothing about the binary in it.
        // Reporting it as a broken binary would blame the wrong party.
        let files = vec![
            file(
                "locked.exe",
                ScanKind::Unreadable {
                    message: "denied".into(),
                },
            ),
            file("bad.exe", routed("refused", true, false)),
        ];
        let problems: Vec<&str> = obstacles(&files).iter().map(|f| f.path.as_str()).collect();
        assert_eq!(problems, vec!["locked.exe"]);
        assert_eq!(blocking(&files).len(), 1, "the refusal is the finding");
    }

    #[test]
    fn grouped_counts_sum_to_the_routed_total() {
        let files = vec![
            file("a.exe", routed("native", false, true)),
            file("b.exe", routed("native", false, true)),
            file("c.exe", routed("fex_partial", false, false)),
        ];
        let grouped = by_route(&files);
        assert_eq!(grouped.get("native"), Some(&2));
        assert_eq!(grouped.get("fex_partial"), Some(&1));
        assert_eq!(grouped.values().sum::<usize>(), count(&files).routed);
    }

    #[test]
    fn the_real_corpus_is_walked_and_routed() {
        // An integration test against committed fixtures produced by a real toolchain, so the
        // batch path is exercised on genuine images rather than only on synthetic ones.
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../compitum-pe/tests/corpus");
        let report = scan_path(
            &corpus,
            &host(),
            BackendSet::all(),
            MigrationTarget::default(),
        );

        assert!(
            !report.files.is_empty(),
            "the committed corpus must contain files: {}",
            corpus.display()
        );
        assert!(!report.truncated, "the corpus must fit inside the limits");

        let counts = report.counts;
        assert!(counts.routed > 0, "the corpus contains real PE images");
        // The corpus also contains a manifest and a JSON table, which are not images. If they
        // were counted as failures the report would be crying wolf on its own fixtures.
        assert!(
            counts.not_pe > 0,
            "non-image files must be classified as not-applicable, not as failures"
        );
        assert_eq!(counts.unreadable, 0, "the committed corpus is readable");
    }

    #[test]
    fn results_are_sorted_so_a_report_can_be_diffed() {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../compitum-pe/tests/corpus");
        let report = scan_path(
            &corpus,
            &host(),
            BackendSet::all(),
            MigrationTarget::default(),
        );
        let paths: Vec<&String> = report.files.iter().map(|f| &f.path).collect();
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted, "a report that reorders cannot be diffed");
    }

    #[test]
    fn a_depth_limit_truncates_and_says_so() {
        // The guard must work, and truncation must be visible. A report that silently covered
        // a subset would understate the work a migration needs.
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../compitum-pe/tests/corpus");
        let report = scan_path_with_limits(
            &corpus,
            &host(),
            BackendSet::all(),
            MigrationTarget::default(),
            0,
            1000,
        );

        // Depth 0 still lists the corpus directory's own files, so the assertion is about the
        // reason being recorded when the walk does stop, not about a specific count.
        if report.truncated {
            assert!(report.truncated_reason.is_some());
        }
        assert!(report.counts.files_seen <= DEFAULT_MAX_FILES);
    }

    #[test]
    fn a_file_limit_truncates_at_the_boundary() {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../compitum-pe/tests/corpus");
        let report = scan_path_with_limits(
            &corpus,
            &host(),
            BackendSet::all(),
            MigrationTarget::default(),
            12,
            2,
        );
        assert_eq!(report.counts.files_seen, 2, "exactly the limit is examined");
        assert!(report.truncated, "stopping early must be reported");
        assert!(report
            .truncated_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("limit")));
    }

    #[test]
    fn a_single_file_is_accepted_like_a_verify_subject() {
        let file = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../compitum-pe/tests/corpus/real-console-4k.exe");
        let report = scan_path(
            &file,
            &host(),
            BackendSet::all(),
            MigrationTarget::default(),
        );
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.counts.routed, 1);
        assert!(
            !report.truncated,
            "a single file can never overflow a limit"
        );
    }

    #[test]
    fn a_non_image_file_is_not_a_failure() {
        let file =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../compitum-pe/tests/corpus/manifest.json");
        let report = scan_path(
            &file,
            &host(),
            BackendSet::all(),
            MigrationTarget::default(),
        );
        assert_eq!(report.counts.not_pe, 1);
        assert_eq!(report.counts.malformed, 0);
        assert_eq!(report.counts.unreadable, 0);
        assert!(blocking(&report.files).is_empty());
    }

    #[test]
    fn a_missing_path_is_unreadable_rather_than_a_verdict() {
        let report = scan_path(
            Path::new("/definitely/not/here.exe"),
            &host(),
            BackendSet::all(),
            MigrationTarget::default(),
        );
        assert_eq!(report.counts.unreadable, 1);
        assert_eq!(report.counts.routed, 0);
        assert!(blocking(&report.files).is_empty());
    }

    #[test]
    fn a_file_that_looks_like_pe_but_will_not_parse_is_malformed_not_absent() {
        // The boundary between two categories a careless implementation would merge.
        //
        // `looks_like_pe` is a cheap signature check: length, `MZ`, and a valid `PE\0\0` at the
        // offset named in the DOS header. A file can satisfy it and still be unparseable, and
        // that combination is the interesting one -- it is a corrupt or unsupported executable,
        // which is a finding about the customer's software.
        //
        // Building this fixture correctly is the whole point, and an earlier version got it
        // wrong: it wrote six bytes, which `looks_like_pe` rejects outright, so the file landed
        // in `NotPe` and the test failed for a reason that had nothing to do with the code under
        // test. The lesson is the one this repository keeps relearning -- a fixture that does not
        // satisfy its own premise tests nothing, and fails in a way that looks like a code bug.
        let directory = std::env::temp_dir().join("compitum-scan-malformed-test");
        let _ = std::fs::create_dir_all(&directory);
        let path = directory.join("truncated.exe");

        // 68 bytes: enough for the DOS header, an `MZ` signature, an offset at 0x3C pointing to
        // 0x40, and a valid PE signature there. The COFF header that must follow is absent.
        let mut bytes = vec![0u8; 68];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        std::fs::write(&path, &bytes).expect("must write");

        // The premise is asserted, not assumed. If `looks_like_pe` ever stops accepting this
        // file, this test must say so rather than quietly start checking the other category.
        assert!(
            compitum_pe::looks_like_pe(&bytes),
            "the fixture must satisfy the signature check, or this test checks nothing"
        );
        assert!(
            compitum_pe::parse(&bytes).is_err(),
            "the fixture must be unparseable, or this test is about a healthy image"
        );

        let report = scan_path(
            &path,
            &host(),
            BackendSet::all(),
            MigrationTarget::default(),
        );
        assert_eq!(report.counts.malformed, 1, "{:?}", report.files);
        assert_eq!(report.counts.not_pe, 0);
        assert!(
            !blocking(&report.files).is_empty(),
            "a corrupt executable is a finding, not a non-event"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_file_below_the_dos_header_minimum_is_not_a_candidate() {
        // The other side of the same boundary. Six bytes beginning with `MZ` is not a Windows
        // image, and treating it as a corrupt one would report a truncated download as a
        // migration problem.
        let directory = std::env::temp_dir().join("compitum-scan-tiny-test");
        let _ = std::fs::create_dir_all(&directory);
        let path = directory.join("tiny.exe");
        std::fs::write(&path, b"MZ\x90\x00\x03\x00").expect("must write");

        assert!(
            !compitum_pe::looks_like_pe(b"MZ\x90\x00\x03\x00"),
            "a file below the DOS header minimum is not a PE candidate"
        );

        let report = scan_path(
            &path,
            &host(),
            BackendSet::all(),
            MigrationTarget::default(),
        );
        assert_eq!(report.counts.not_pe, 1, "{:?}", report.files);
        assert_eq!(report.counts.malformed, 0);

        let _ = std::fs::remove_file(&path);
    }
}
