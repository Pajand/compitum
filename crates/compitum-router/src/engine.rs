//! The decision engine.
//!
//! A pure function from facts to a [`Plan`]. Everything else in this crate exists to
//! define its vocabulary; this module contains the reasoning.
//!
//! # Why purity matters here
//!
//! [`decide`] takes a [`Request`] and returns a [`Plan`]. It performs no I/O, reads no
//! environment, and consults no clock. That is a deliberate constraint: a routing decision
//! that varies with ambient state cannot be reproduced from an Oracle record, which would
//! make the recorded evidence worthless exactly when it is most needed — when someone is
//! trying to explain a failure from last month.
//!
//! # The decision order
//!
//! The rules are evaluated in a fixed order, most fundamental first. Each step can only
//! narrow the outcome, never widen it, which keeps the reasoning explainable:
//!
//! 1. **Is the subject readable at all?** An unparseable image is refused with the parse
//!    error as the reason, rather than silently reported as unknown.
//! 2. **Is the host an ARM64 machine?** If not, the analysis does not describe it. This is
//!    a caution, not a block — the tool is being used to inspect a foreign binary, which is
//!    legitimate.
//! 3. **Which ABI family is the image?** This selects the candidate routes.
//! 4. **Does the host implement the CPU features the image requires?** This can only take
//!    a native or hybrid route away; it never grants one.
//! 5. **Are the required backends installed?** A route that needs a translator the host
//!    lacks cannot be taken.
//! 6. **Are there cautions worth recording?** Page size, display requirements, weak
//!    evidence. These annotate the plan without changing the route.

use compitum_isa::{Confidence, FeatureSet, HostProfile, IsaFeature};
use compitum_pe::{AbiFamily, PeImage};

use crate::plan::Plan;
use crate::reason::{Reason, ReasonCode, Reasons};
use crate::route::{Backend, BackendSet, Route};
use crate::target::MigrationTarget;

/// Everything the engine needs to reach a decision.
///
/// Constructed by the CLI from a parsed image, a probed host, and the operator's
/// environment. Bundling it means the engine never has to reach for anything.
#[derive(Debug, Clone)]
pub struct Request {
    /// The parsed subject image, or the reason it could not be parsed.
    pub subject: Subject,
    /// The probed host, or `None` when the host could not be probed.
    pub host: Option<HostProfile>,
    /// Translation backends present on this host.
    pub backends: BackendSet,
    /// CPU features the image requires, with provenance.
    ///
    /// Empty when no instruction-level analysis was performed, which is the honest
    /// representation of "we did not look" as distinct from "we looked and found nothing".
    pub requirements: Vec<compitum_isa::Requirement>,
    /// Set when the operator asked for a headless-only evaluation, so that a display
    /// requirement becomes a blocker rather than a caution.
    pub headless_only: bool,
    /// Where the software is going.
    ///
    /// A route is only meaningful relative to a destination: the same binary can be native on
    /// one target and need a translator on another. Before this existed, the destination was
    /// implicitly "this machine with whatever was installed here", which is a compatibility
    /// check rather than a migration analysis.
    ///
    /// Defaults to [`MigrationTarget::LinuxWithWine`], so every caller that does not state a
    /// target keeps the behaviour it already had.
    pub target: MigrationTarget,
}

/// The subject of a routing decision.
#[derive(Debug, Clone)]
pub enum Subject {
    /// A successfully parsed image.
    Image(Box<PeImage>),
    /// An image that could not be parsed.
    Unreadable {
        /// A human-readable description of the file, typically the path.
        label: String,
        /// Why parsing failed.
        error: String,
    },
}

impl Request {
    /// A request for a parsed image on a probed host.
    #[must_use]
    pub fn new(image: PeImage, host: HostProfile, backends: BackendSet) -> Self {
        Request {
            subject: Subject::Image(Box::new(image)),
            host: Some(host),
            backends,
            requirements: Vec::new(),
            headless_only: false,
            target: MigrationTarget::default(),
        }
    }

    /// A request for an image that could not be parsed.
    #[must_use]
    pub fn unreadable(label: impl Into<String>, error: impl Into<String>) -> Self {
        Request {
            subject: Subject::Unreadable {
                label: label.into(),
                error: error.into(),
            },
            host: None,
            backends: BackendSet::none(),
            requirements: Vec::new(),
            headless_only: false,
            target: MigrationTarget::default(),
        }
    }

    /// States where the software is going.
    #[must_use]
    pub fn with_target(mut self, target: MigrationTarget) -> Self {
        self.target = target;
        self
    }

    /// Attaches instruction-level requirements discovered by scanning.
    #[must_use]
    pub fn with_requirements(mut self, requirements: Vec<compitum_isa::Requirement>) -> Self {
        self.requirements = requirements;
        self
    }

    /// Requires that the plan work without a display.
    #[must_use]
    pub fn headless_only(mut self, headless_only: bool) -> Self {
        self.headless_only = headless_only;
        self
    }

    /// The label describing the subject, for the Oracle record.
    #[must_use]
    pub fn label(&self) -> Option<String> {
        match &self.subject {
            Subject::Image(_) => None,
            Subject::Unreadable { label, .. } => Some(label.clone()),
        }
    }

    /// The parsed image, when there is one.
    #[must_use]
    pub fn image(&self) -> Option<&PeImage> {
        match &self.subject {
            Subject::Image(image) => Some(image),
            Subject::Unreadable { .. } => None,
        }
    }
}

/// Reaches a routing decision.
///
/// See the module documentation for the order in which rules are applied.
#[must_use]
pub fn decide(request: &Request) -> Plan {
    let mut reasons = Reasons::new();

    // ---- Rule 1: can the subject be read at all? ---------------------------
    let image = match &request.subject {
        Subject::Image(image) => image,
        Subject::Unreadable { label, error } => {
            return Plan::refused(
                Reason::with_detail(ReasonCode::UnreadableSubject, error.clone()),
                Some(label.clone()),
            );
        }
    };

    let subject_label = None;

    // ---- Rule 2: is this even an ARM64 host? -------------------------------
    let host = match &request.host {
        Some(host) => host,
        None => {
            reasons.add(ReasonCode::InsufficientInformation);
            return Plan::new(Route::Refused, reasons, subject_label);
        }
    };
    if !host.is_arm64() {
        reasons.add_detail(
            ReasonCode::HostIsNotArm64,
            format!("this host reports architecture `{}`", host.arch),
        );
    }

    // Managed images need a special note before anything else, because the machine field
    // of a managed assembly frequently does not describe what will actually execute.
    if image.is_managed() {
        reasons.add_detail(
            ReasonCode::SubjectIsManagedCode,
            "the recorded machine type describes the host the assembly was built for, not \
             the code that will run; the CLR compiles it for this CPU",
        );
    }

    // ---- Managed code: the machine type must not decide the route -----------
    //
    // A .NET assembly records the platform it was BUILT for, and the CLR compiles its IL to
    // the host's own instructions when it loads. So a managed image marked x86-64 or even
    // 32-bit x86 becomes native ARM64 code by the time any of it runs, and judging it by its
    // recorded machine type is exactly the mistake the note above already warns about.
    //
    // This was a real defect: `managed-dotnet.exe` came out REFUSED with "no 32-bit x86
    // translator is installed", which is doubly wrong. The image needs no translator at all,
    // and the answer a migration cares about — "your oldest, ugliest .NET component is
    // already fine on Arm64" — was the opposite of what the tool said.
    //
    // The route is Native because after JIT compilation that is literally what executes. The
    // confidence stays honest via the `subject_is_managed_code` reason already recorded above,
    // which says the machine field describes the build host rather than the code.
    if image.is_managed() {
        reasons.add_detail(
            ReasonCode::ArchitectureNative,
            "managed code: the CLR compiles this assembly's IL to the host's own instructions \
             at load time, so its recorded machine type does not determine what executes",
        );
        if !isa_satisfied(host, &request.requirements, &mut reasons) {
            return Plan::new(Route::Refused, reasons, subject_label);
        }
        annotate_cautions(image, host, request, &mut reasons);
        return Plan::new(Route::Native, reasons, subject_label);
    }

    let family = image.family();
    let route = select_route(
        family,
        image,
        host,
        &request.requirements,
        request,
        &mut reasons,
    );

    // ---- Rule 6: cautions --------------------------------------------------
    annotate_cautions(image, host, request, &mut reasons);

    Plan::new(route, reasons, subject_label)
}

/// Chooses the route from the ABI family and the available evidence.
fn select_route(
    family: AbiFamily,
    image: &PeImage,
    host: &HostProfile,
    requirements: &[compitum_isa::Requirement],
    request: &Request,
    reasons: &mut Reasons,
) -> Route {
    match family {
        // ---- Pure ARM64: the only family that can be fully native --------------
        AbiFamily::Arm64Native => {
            reasons.add(ReasonCode::ArchitectureNative);
            if isa_satisfied(host, requirements, reasons) {
                Route::Native
            } else {
                Route::Refused
            }
        }

        // ---- ARM64X: pick the native slice ------------------------------------
        // Routing this to the hybrid path would needlessly demand a translator for code
        // that has a native equivalent sitting in the same file.
        AbiFamily::Arm64Fat => {
            reasons.add_detail(
                ReasonCode::ArchitectureFat,
                "a fat image carries both slices; the ARM64 one is selected",
            );
            if isa_satisfied(host, requirements, reasons) {
                Route::PickNativeSlice
            } else {
                Route::Refused
            }
        }

        // ---- ARM64EC: the hybrid case this project exists for -----------------
        AbiFamily::Arm64Hybrid => {
            reasons.add(ReasonCode::ArchitectureHybrid);
            if !isa_satisfied(host, requirements, reasons) {
                return Route::Refused;
            }
            // THE TARGET DECIDES THIS, and it was the single biggest error in this router.
            //
            // On Windows on Arm, ARM64EC *is* the native ABI: Microsoft designed it so that
            // AArch64 and x86-64 code share a process, and the operating system implements the
            // boundary. Reporting it as "hybrid, FEX required, 70-90% of native" was correct
            // for Linux and wrong for the platform a migration is actually headed to — and it
            // understated the product's own best case by 10-30%.
            let route = request.target.arm64ec_route();
            match route {
                Route::Native => {
                    reasons.add_detail(
                        ReasonCode::TargetProvidesTranslation,
                        format!(
                            "on {}, ARM64EC is the native ABI: the operating system implements \
                             the AArch64/x86-64 boundary, so no translator is loaded and every \
                             instruction runs at hardware speed",
                            request.target.id()
                        ),
                    );
                    Route::Native
                }
                _ => {
                    reasons.add_detail(
                        ReasonCode::ArchitectureHybrid,
                        "the AArch64 functions run natively; the embedded x86-64 functions \
                         require a translator",
                    );
                    // FEX provides the ARM64EC-compatible mode that allows a translator to
                    // coexist with native code in one process. Box64 does not, so a host with
                    // only Box64 cannot take this route correctly.
                    if request.backends.contains(Backend::Fex) {
                        reasons.add(ReasonCode::BackendPresent);
                        Route::FexPartial
                    } else {
                        reasons.add_detail(
                            ReasonCode::BackendAbsent,
                            "an ARM64EC image needs FEX specifically, because its translator \
                             must coexist with native code in the same process; Box64 does not \
                             offer that mode",
                        );
                        Route::Refused
                    }
                }
            }
        }

        // ---- x86-64: full translation, backend chosen by preference -----------
        AbiFamily::X86_64 => {
            reasons.add(ReasonCode::ArchitectureRequiresTranslation);
            if !isa_satisfied(host, requirements, reasons) {
                return Route::Refused;
            }
            // A destination that emulates this architecture itself changes the answer
            // completely, and it is the answer a migration cares about most.
            //
            // Windows 11 on Arm ships Prism and runs x86-64 with no additional component, so
            // such an image does work on the destination. Saying "REFUSED — install Box64"
            // was doubly wrong: Box64 does not exist on Windows, and the application runs
            // anyway. What the customer actually needs to hear is that it works and is
            // therefore still paying for translation.
            if request.target.emulates_x86_64_natively() {
                reasons.add_detail(
                    ReasonCode::TargetProvidesTranslation,
                    format!(
                        "{} emulates x86-64 itself, so this image runs without anything being \
                         installed — but every instruction is translated, and rebuilding for \
                         Arm64 is what removes that cost",
                        request.target.id()
                    ),
                );
                return Route::DestinationEmulates;
            }
            if request.backends.contains(Backend::Box64) {
                reasons.add(ReasonCode::BackendPresent);
                Route::Box64Full
            } else if request.backends.contains(Backend::Fex) {
                reasons.add(ReasonCode::BackendPresent);
                Route::FexFull
            } else {
                reasons.add_detail(
                    ReasonCode::BackendAbsent,
                    "no x86-64 translator is installed on this host",
                );
                Route::Refused
            }
        }

        // ---- 32-bit x86: needs the 32-bit path --------------------------------
        AbiFamily::X86 | AbiFamily::X86Hybrid => {
            reasons.add(ReasonCode::ArchitectureRequiresWow64);
            if !isa_satisfied(host, requirements, reasons) {
                return Route::Refused;
            }
            // The same correction as x86-64, and it matters more here: Windows on Arm has
            // emulated 32-bit x86 since the first release, through WOW64 plus the emulator.
            // No separate component, and certainly not Box86, which is a Linux program.
            if request.target.emulates_x86_64_natively() {
                reasons.add_detail(
                    ReasonCode::TargetProvidesTranslation,
                    format!(
                        "{} runs 32-bit x86 through WOW64 and its own emulator, so this image \
                         runs without anything being installed — rebuilding for Arm64 is what \
                         removes the translation cost",
                        request.target.id()
                    ),
                );
                return Route::DestinationEmulates;
            }
            if request.backends.contains(Backend::Box86) {
                reasons.add(ReasonCode::BackendPresent);
                Route::Wow64
            } else {
                reasons.add_detail(
                    ReasonCode::BackendAbsent,
                    "no 32-bit x86 translator is installed on this host",
                );
                Route::Refused
            }
        }

        // ---- Everything else is out of reach ----------------------------------
        AbiFamily::Arm32 => {
            // A 64-bit ARM64 CPU cannot execute AArch32 code from 64-bit mode without
            // hardware support that many SoCs disable. Refusing is honest.
            reasons.add_detail(
                ReasonCode::ArchitectureUnsupported,
                "32-bit ARM code cannot be executed from 64-bit mode on this CPU, and no \
                 route provides that transition",
            );
            Route::Refused
        }
        AbiFamily::Unknown => {
            reasons.add_detail(
                ReasonCode::ArchitectureUnsupported,
                format!(
                    "the machine field holds 0x{:04X}, which is not a valid image type",
                    image.coff.machine.raw()
                ),
            );
            Route::Refused
        }
        AbiFamily::Itanium | AbiFamily::RiscV | AbiFamily::LoongArch | AbiFamily::PowerPc => {
            reasons.add_detail(
                ReasonCode::ArchitectureUnsupported,
                format!(
                    "this image targets {family}; executing it on ARM64 would require \
                     full-system emulation rather than a user-mode translator"
                ),
            );
            Route::Refused
        }
        AbiFamily::Other => {
            reasons.add_detail(
                ReasonCode::ArchitectureUnsupported,
                format!(
                    "unrecognized machine type 0x{:04X}",
                    image.coff.machine.raw()
                ),
            );
            Route::Refused
        }
    }
}

/// Checks whether the host implements every feature the image requires.
///
/// Returns `true` when the requirement set is satisfied. Records the outcome in `reasons`
/// either way, because both the positive and negative result are evidence.
///
/// Uses [`HostProfile::guaranteed_features`] rather than the aggregate feature set: on a
/// heterogeneous SoC a thread can be scheduled onto any core, so the only sound guarantee
/// is the intersection across all of them.
fn isa_satisfied(
    host: &HostProfile,
    requirements: &[compitum_isa::Requirement],
    reasons: &mut Reasons,
) -> bool {
    if requirements.is_empty() {
        // No instruction scan was performed. Not the same as "nothing is required", but
        // the honest position is to proceed and say so rather than to refuse on a gap in
        // our own analysis.
        return true;
    }

    let available = host.guaranteed_features();
    let required = FeatureSet::from_iter(requirements.iter().map(|r| r.feature));
    let missing = required.difference(available);

    if missing.is_empty() {
        reasons.add_detail(
            ReasonCode::IsaSubsetSatisfied,
            format!(
                "all {} required feature(s) are present on every core",
                required.len()
            ),
        );
        return true;
    }

    let missing_list: Vec<IsaFeature> = missing.iter().collect();

    // If the only evidence is a scan, say so: a false negative here would refuse a binary
    // that would in fact have run, because a byte pattern can match by coincidence.
    let confidence = requirements
        .iter()
        .filter(|r| missing.contains(r.feature))
        .map(|r| r.confidence)
        .min()
        .unwrap_or(Confidence::CERTAIN);

    reasons.push(Reason::missing_features(&missing_list, confidence));

    if confidence.permille() < Confidence::HIGH.permille() {
        reasons.add_detail(
            ReasonCode::IsaEvidenceWeak,
            "the missing features were identified by scanning machine code rather than \
             from metadata, so this verdict may be a false negative",
        );
    }
    false
}

/// Adds cautions that do not change the route but that an operator should see.
fn annotate_cautions(
    image: &PeImage,
    host: &HostProfile,
    request: &Request,
    reasons: &mut Reasons,
) {
    // ---- Page size ---------------------------------------------------------
    if let Some(implied) = image.implied_page_size() {
        if implied == host.page_size as u32 {
            reasons.add_detail(
                ReasonCode::PageSizeMatches,
                format!("both the image and the host use {implied}-byte pages"),
            );
        } else {
            reasons.add_detail(
                ReasonCode::PageSizeMismatch,
                format!(
                    "the image implies {implied}-byte pages but this host uses {}; a 4 KiB \
                     Windows image on a 16 KiB host can fail in ways that look \
                     intermittent",
                    host.page_size
                ),
            );
        }
    }

    // ---- Display -----------------------------------------------------------
    let subsystem = image.subsystem();
    if subsystem.requires_display() {
        if request.headless_only {
            reasons.push(
                Reason::with_detail(
                    ReasonCode::SubsystemRequiresDisplay,
                    "a display was explicitly disallowed for this evaluation",
                )
                .severity(crate::reason::Severity::Blocked),
            );
        } else {
            reasons.add_detail(
                ReasonCode::SubsystemRequiresDisplay,
                subsystem.description(),
            );
        }
    } else {
        reasons.add_detail(
            ReasonCode::SubsystemHeadlessCapable,
            subsystem.description(),
        );
    }

    // ---- Graphics ----------------------------------------------------------
    if image.imports_graphics() {
        let modules: Vec<&str> = image
            .imports
            .iter()
            .filter(|m| m.is_graphics())
            .map(|m| m.name.as_str())
            .collect();
        reasons.add_detail(
            ReasonCode::GraphicsBackendRequired,
            format!(
                "imports {}; running the graphical path needs a Direct3D-to-Vulkan \
                 translation layer and a working Vulkan driver",
                modules.join(", ")
            ),
        );
    }

    // ---- Kernel-mode drivers -----------------------------------------------
    //
    // Found by scanning 747 genuine binaries from a real Wine distribution: sixteen kernel
    // drivers came out as clean native ports. Every architectural statement about them was
    // true — on an Arm64 build a driver is pure AArch64 — and all of it missed the point,
    // because a user-mode compatibility layer cannot load a kernel driver at all.
    //
    // The answer depends on the destination and on the driver's own architecture, and both
    // halves matter:
    //
    //   * an Arm64 driver on Windows on Arm is ordinary native kernel code and loads
    //     normally. Telling that customer to rewrite it would waste real money;
    //   * an x86 or x86-64 driver cannot run anywhere, because Microsoft's emulator covers
    //     user-mode code only and a kernel component must be built for Arm64.
    //
    // `is_fully_native_on_arm64` is the driver's architecture: a pure Arm64 image is native,
    // a hybrid one contains translated code and therefore cannot be a kernel component.
    if image.is_kernel_driver() {
        let arm64 = image.family().is_fully_native_on_arm64();
        if request.target.loads_kernel_drivers(arm64) {
            reasons.add_detail(
                ReasonCode::KernelDriverNative,
                format!(
                    "this is a kernel-mode driver built for Arm64, so {} loads it as native \
                     kernel code; no port is needed",
                    request.target.id()
                ),
            );
        } else {
            reasons.add_detail(
                ReasonCode::KernelDriverEmulated,
                format!(
                    "this is a kernel-mode driver and {} cannot load it: emulation covers \
                     user-mode code only, so a kernel component must be rebuilt for Arm64",
                    request.target.id()
                ),
            );
        }
    }

    // ---- System-call layer -------------------------------------------------
    //
    // No Windows image can run without an NT syscall layer, including fully native ARM64
    // ones. But WHO supplies it depends entirely on the destination, and this annotation used
    // to assume the destination was always "this Linux machine":
    //
    //   * On Windows on Arm the operating system supplies it. Wine is not involved and its
    //     absence is not a defect — reporting it as one made a pure ARM64 binary that runs
    //     natively on Windows come out as REFUSED, which is the single clearest symptom of the
    //     router having no concept of a destination.
    //   * On Linux it is Wine, a package the operator must install, and its absence genuinely
    //     does block every Windows image.
    if request.target.supplies_syscall_layer() {
        reasons.add_detail(
            ReasonCode::TargetSuppliesSyscallLayer,
            format!(
                "{} supplies the NT system-call layer itself, so no compatibility layer is \
                 needed for it",
                request.target.id()
            ),
        );
    } else if request.backends.contains(Backend::Wine) {
        reasons.add(ReasonCode::SyscallLayerPresent);
    } else {
        reasons.add_detail(
            ReasonCode::SyscallLayerAbsent,
            "no NT system-call layer is installed; a native ARM64 Windows image still \
             issues NT syscalls that this kernel does not implement",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::Backend;
    use compitum_pe::{pe_fixture, AbiFamily};

    /// A host with a broad capability set and no matrix units, matching the reference
    /// development device.
    fn reference_host() -> HostProfile {
        HostProfile::synthetic(
            "aarch64",
            4096,
            8,
            FeatureSet::new()
                .with(IsaFeature::Fp)
                .with(IsaFeature::Asimd)
                .with(IsaFeature::Aes)
                .with(IsaFeature::DotProd)
                .with(IsaFeature::I8mm)
                .with(IsaFeature::Bti),
        )
    }

    fn full_backends() -> BackendSet {
        BackendSet::all()
    }

    /// Builds a parsed image for a given machine type.
    ///
    /// The fixture module produces bytes, because that is what a caller on disk would have;
    /// parsing them here means every engine test exercises the real parser rather than a
    /// hand-built struct that could drift from the file format.
    fn image(machine: u16) -> PeImage {
        let bytes = pe_fixture::synthetic(machine, 3, false);
        compitum_pe::parse(&bytes).expect("synthetic fixture must parse")
    }

    #[test]
    fn pure_arm64_routes_native() {
        let request = Request::new(image(0xAA64), reference_host(), full_backends());
        let plan = decide(&request);
        assert_eq!(plan.route, Route::Native);
        assert!(plan.is_fully_native());
        assert!(!plan.is_blocked());
    }

    #[test]
    fn arm64x_picks_the_native_slice_not_the_hybrid_path() {
        let request = Request::new(image(0xA64E), reference_host(), full_backends());
        let plan = decide(&request);
        assert_eq!(plan.route, Route::PickNativeSlice);
        assert!(
            plan.is_fully_native(),
            "slice selection must avoid translation"
        );
        assert_eq!(plan.required_backend(), None);
    }

    #[test]
    fn arm64ec_routes_partial_not_full_translation() {
        let request = Request::new(image(0xA641), reference_host(), full_backends());
        let plan = decide(&request);
        assert_eq!(plan.route, Route::FexPartial);
        assert!(plan.route.is_hybrid());
        assert!(!plan.route.is_fully_translated());
        assert_eq!(plan.required_backend(), Some(Backend::Fex));
    }

    #[test]
    fn arm64ec_without_fex_is_refused_with_a_specific_reason() {
        // Box64 alone cannot take the hybrid route: the translator must coexist with
        // native code in one process, which is a FEX-specific capability.
        let backends = BackendSet::none().with(Backend::Wine).with(Backend::Box64);
        let request = Request::new(image(0xA641), reference_host(), backends);
        let plan = decide(&request);
        assert_eq!(plan.route, Route::Refused);
        assert!(plan.reasons.contains(ReasonCode::BackendAbsent));
        assert!(plan.headline().contains("FEX") || plan.headline().contains("fex"));
    }

    #[test]
    fn x86_64_prefers_box64_when_available() {
        let request = Request::new(image(0x8664), reference_host(), full_backends());
        let plan = decide(&request);
        assert_eq!(plan.route, Route::Box64Full);
        assert!(plan.route.is_fully_translated());
        assert_eq!(plan.required_backend(), Some(Backend::Box64));
    }

    #[test]
    fn x86_64_falls_back_to_fex() {
        let backends = BackendSet::none().with(Backend::Wine).with(Backend::Fex);
        let request = Request::new(image(0x8664), reference_host(), backends);
        assert_eq!(decide(&request).route, Route::FexFull);
    }

    #[test]
    fn x86_64_without_any_translator_is_refused() {
        let request = Request::new(image(0x8664), reference_host(), BackendSet::none());
        let plan = decide(&request);
        assert_eq!(plan.route, Route::Refused);
        assert!(plan.reasons.contains(ReasonCode::BackendAbsent));
    }

    #[test]
    fn missing_cpu_feature_blocks_a_native_route() {
        let requirements = vec![compitum_isa::Requirement::new(
            IsaFeature::Sme,
            compitum_isa::RequirementSource::Metadata,
            None,
            "declared use of matrix units",
        )];
        let request = Request::new(image(0xAA64), reference_host(), full_backends())
            .with_requirements(requirements);
        let plan = decide(&request);
        assert_eq!(plan.route, Route::Refused);
        assert!(plan.reasons.contains(ReasonCode::IsaFeaturesMissing));
        let headline = plan.headline();
        assert!(
            headline.contains("sme"),
            "headline must name the missing feature: {headline}"
        );
    }

    #[test]
    fn satisfied_features_keep_the_native_route() {
        let requirements = vec![compitum_isa::Requirement::new(
            IsaFeature::DotProd,
            compitum_isa::RequirementSource::Metadata,
            None,
            "dot product",
        )];
        let request = Request::new(image(0xAA64), reference_host(), full_backends())
            .with_requirements(requirements);
        let plan = decide(&request);
        assert_eq!(plan.route, Route::Native);
        assert!(plan.reasons.contains(ReasonCode::IsaSubsetSatisfied));
    }

    #[test]
    fn weak_scan_evidence_is_flagged_not_hidden() {
        let requirements = vec![compitum_isa::Requirement::new(
            IsaFeature::Sme,
            compitum_isa::RequirementSource::InstructionScan,
            Some(0x1000),
            "pattern hit",
        )];
        let request = Request::new(image(0xAA64), reference_host(), full_backends())
            .with_requirements(requirements);
        let plan = decide(&request);
        assert!(plan.reasons.contains(ReasonCode::IsaEvidenceWeak));
        assert!(plan.confidence.permille() < 1000);
    }

    #[test]
    fn unreadable_subject_is_refused_with_the_parse_error() {
        let request = Request::unreadable("/tmp/broken.exe", "file is truncated");
        let plan = decide(&request);
        assert_eq!(plan.route, Route::Refused);
        assert!(plan.reasons.contains(ReasonCode::UnreadableSubject));
        assert!(plan.headline().contains("truncated"));
    }

    #[test]
    fn a_foreign_host_is_a_caution_not_a_refusal() {
        let host = HostProfile::synthetic("x86_64", 4096, 8, FeatureSet::new());
        let request = Request::new(image(0xAA64), host, full_backends());
        let plan = decide(&request);
        assert!(plan.reasons.contains(ReasonCode::HostIsNotArm64));
        // Inspecting a binary for another architecture is legitimate, so the route stands.
        assert_eq!(plan.route, Route::Native);
    }

    #[test]
    fn page_size_mismatch_is_recorded() {
        let host = HostProfile::synthetic("aarch64", 16384, 8, FeatureSet::all());
        let request = Request::new(image(0xAA64), host, full_backends());
        let plan = decide(&request);
        assert!(plan.reasons.contains(ReasonCode::PageSizeMismatch));
        assert!(plan.reasons.has_caution());
    }

    #[test]
    fn headless_only_turns_a_display_requirement_into_a_blocker() {
        let gui = compitum_pe::parse(&pe_fixture::synthetic(0xAA64, 2, false))
            .expect("synthetic fixture must parse");
        let request = Request::new(gui, reference_host(), full_backends()).headless_only(true);
        let plan = decide(&request);
        assert!(plan.is_blocked());
        assert!(plan.reasons.contains(ReasonCode::SubsystemRequiresDisplay));
    }

    #[test]
    fn console_images_are_reported_as_headless_capable() {
        let request = Request::new(image(0xAA64), reference_host(), full_backends());
        let plan = decide(&request);
        assert!(plan.reasons.contains(ReasonCode::SubsystemHeadlessCapable));
    }

    #[test]
    fn missing_syscall_layer_is_recorded_for_every_family() {
        let request = Request::new(image(0xAA64), reference_host(), BackendSet::none());
        let plan = decide(&request);
        assert!(plan.reasons.contains(ReasonCode::SyscallLayerAbsent));
    }

    #[test]
    fn unsupported_architectures_are_refused_with_an_explanation() {
        for machine in [0x01C4u16, 0x0200, 0x5064, 0x6264, 0x01F0] {
            let request = Request::new(image(machine), reference_host(), full_backends());
            let plan = decide(&request);
            assert_eq!(plan.route, Route::Refused, "machine 0x{machine:04X}");
            assert!(plan.reasons.contains(ReasonCode::ArchitectureUnsupported));
        }
    }

    #[test]
    fn machine_zero_is_refused_as_an_invalid_image() {
        let request = Request::new(image(0x0000), reference_host(), full_backends());
        let plan = decide(&request);
        assert_eq!(plan.route, Route::Refused);
        assert!(plan.headline().contains("not a valid image type"));
    }

    #[test]
    fn decision_is_deterministic() {
        // Purity is a documented guarantee: the same facts must produce the same plan,
        // or an Oracle record cannot be replayed.
        let request = Request::new(image(0xA641), reference_host(), full_backends());
        let first = decide(&request);
        let second = decide(&request);
        assert_eq!(first.route, second.route);
        assert_eq!(first.to_json().to_string(), second.to_json().to_string());
    }

    #[test]
    fn every_route_a_plan_can_name_has_a_headline() {
        let families_and_expectations = [
            (0xAA64u16, Route::Native),
            (0xA64E, Route::PickNativeSlice),
            (0xA641, Route::FexPartial),
            (0x8664, Route::Box64Full),
            (0x014C, Route::Wow64),
        ];
        for (machine, expected) in families_and_expectations {
            let mut backends = full_backends();
            backends.insert(Backend::Box86);
            let request = Request::new(image(machine), reference_host(), backends);
            let plan = decide(&request);
            assert_eq!(plan.route, expected, "machine 0x{machine:04X}");
            assert!(!plan.headline().is_empty());
        }
    }

    #[test]
    fn abi_family_of_each_arm64_flavour_is_distinguished_end_to_end() {
        assert_eq!(image(0xAA64).family(), AbiFamily::Arm64Native);
        assert_eq!(image(0xA641).family(), AbiFamily::Arm64Hybrid);
        assert_eq!(image(0xA64E).family(), AbiFamily::Arm64Fat);
    }
}
