//! Execution routes and the translation backends that implement them.
//!
//! A [`Route`] is COMPITUM's answer to *"how should this binary be executed here?"*.
//! It is deliberately a small, closed set, because the value of the answer comes from
//! being unambiguous: every route maps to exactly one execution strategy, and every
//! strategy has a measurable cost.
//!
//! # The routes, in order of cost
//!
//! | Route | Translation | Relative speed | Correct for |
//! |---|---|---|---|
//! | [`Route::Native`] | **none** | 1.0x (baseline) | pure ARM64 |
//! | [`Route::PickNativeSlice`] | none, after selection | 1.0x | ARM64X fat images |
//! | [`Route::FexPartial`] | x86-64 blocks only | ~0.7-0.9x | ARM64EC hybrids |
//! | [`Route::Box64Full`] | every instruction | ~0.2-0.5x | x86-64 images |
//! | [`Route::FexFull`] | every instruction | ~0.3-0.6x | x86-64 images |
//! | [`Route::Wow64`] | every instruction, 32-bit | ~0.2-0.4x | x86 images |
//! | [`Route::Refused`] | not possible | — | unsupported architectures |
//!
//! The speed factors are order-of-magnitude guidance, not measurements, and they are
//! labelled as such wherever they are rendered. Publishing a made-up number as if it were
//! a benchmark would be exactly the kind of dishonesty this project exists to avoid.
//!
//! # Why `FexPartial` exists as its own route
//!
//! This is the single most important row in the table. An ARM64EC image contains both
//! AArch64 and x86-64 code. Sending it to [`Route::FexFull`] — which is what a tool that
//! only knows "this is a hybrid, therefore emulate it" will do — translates code that was
//! already native. Keeping the two cases distinct is where the performance comes from.

use std::fmt;

/// How a binary should be executed on a given host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Route {
    /// Runs directly on the CPU. No translator is loaded at any point.
    Native,
    /// A fat image (ARM64X) from which the pure ARM64 slice must be selected before
    /// execution. Once selected, execution is fully native.
    PickNativeSlice,
    /// A hybrid image (ARM64EC) whose AArch64 functions run natively and whose embedded
    /// x86-64 functions are translated on demand by FEX.
    FexPartial,
    /// A 64-bit x86 image translated in full by Box64.
    Box64Full,
    /// A 64-bit x86 image translated in full by FEX.
    FexFull,
    /// A 32-bit x86 image translated in full, inside a WOW64-style environment.
    Wow64,
    /// Execution is not possible on this host with the backends available.
    Refused,
}

impl Route {
    /// Stable machine identifier. Protocol value: never translated, never changed.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Route::Native => "native",
            Route::PickNativeSlice => "pick_native_slice",
            Route::FexPartial => "fex_partial",
            Route::Box64Full => "box64_full",
            Route::FexFull => "fex_full",
            Route::Wow64 => "wow64",
            Route::Refused => "refused",
        }
    }

    /// Returns `true` when **no** instruction is translated at run time.
    ///
    /// This is the property the whole project optimises for, and the one worth asserting
    /// in a test: a route that claims to be native must not secretly depend on a
    /// translator.
    #[must_use]
    pub fn is_fully_native(self) -> bool {
        matches!(self, Route::Native | Route::PickNativeSlice)
    }

    /// Returns `true` when some translation happens, but not of the entire image.
    #[must_use]
    pub fn is_hybrid(self) -> bool {
        matches!(self, Route::FexPartial)
    }

    /// Returns `true` when the entire image must be translated.
    #[must_use]
    pub fn is_fully_translated(self) -> bool {
        matches!(self, Route::Box64Full | Route::FexFull | Route::Wow64)
    }

    /// Returns `true` when execution cannot proceed.
    #[must_use]
    pub fn is_refusal(self) -> bool {
        matches!(self, Route::Refused)
    }

    /// The backend required to take this route, or `None` for the native routes.
    #[must_use]
    pub fn required_backend(self) -> Option<Backend> {
        match self {
            Route::Native | Route::PickNativeSlice | Route::Refused => None,
            Route::FexPartial | Route::FexFull => Some(Backend::Fex),
            Route::Box64Full => Some(Backend::Box64),
            Route::Wow64 => Some(Backend::Box86),
        }
    }

    /// A coarse, honestly-labelled performance expectation.
    ///
    /// Returned as a range because a single number would be false precision. The caller
    /// is expected to render this as an expectation, never as a benchmark result.
    #[must_use]
    pub fn expected_throughput(self) -> Option<ThroughputExpectation> {
        match self {
            Route::Native | Route::PickNativeSlice => Some(ThroughputExpectation {
                min_percent: 100,
                max_percent: 100,
                basis: "no instruction is translated",
            }),
            Route::FexPartial => Some(ThroughputExpectation {
                min_percent: 70,
                max_percent: 90,
                basis: "only the x86-64 blocks are translated; the AArch64 majority runs \
                        at full speed",
            }),
            Route::FexFull => Some(ThroughputExpectation {
                min_percent: 30,
                max_percent: 60,
                basis: "every instruction is translated; heavy x86 SIMD and vectorised \
                        loops are the worst affected",
            }),
            Route::Box64Full => Some(ThroughputExpectation {
                min_percent: 20,
                max_percent: 50,
                basis: "every instruction is translated by a dynamic recompiler",
            }),
            Route::Wow64 => Some(ThroughputExpectation {
                min_percent: 20,
                max_percent: 40,
                basis: "32-bit translation inside an additional WOW64 environment",
            }),
            Route::Refused => None,
        }
    }

    /// A sentence describing what taking this route actually does.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Route::Native => {
                "Execute directly on the CPU. No translator is loaded, so every \
                 instruction runs at hardware speed."
            }
            Route::PickNativeSlice => {
                "Select the pure ARM64 slice from this fat image and execute it directly, \
                 bypassing the hybrid dispatcher entirely."
            }
            Route::FexPartial => {
                "Run the AArch64 functions natively and translate only the x86-64 \
                 functions embedded in the same image, on demand, as FEX."
            }
            Route::Box64Full => {
                "Translate every instruction to AArch64 with Box64 before executing it."
            }
            Route::FexFull => {
                "Translate every instruction to AArch64 with FEX before executing it."
            }
            Route::Wow64 => {
                "Translate this 32-bit image and run it inside a WOW64 compatibility \
                 environment."
            }
            Route::Refused => {
                "Do not execute. No route on this host can run this image correctly, and \
                 attempting one would produce a misleading failure."
            }
        }
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// An explicitly approximate performance expectation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThroughputExpectation {
    /// Lower bound, as a percentage of native speed.
    pub min_percent: u16,
    /// Upper bound, as a percentage of native speed.
    pub max_percent: u16,
    /// What the estimate is based on, so the reader can judge it.
    pub basis: &'static str,
}

impl ThroughputExpectation {
    /// Renders as a range, e.g. `"70-90% of native"`.
    #[must_use]
    pub fn render(self) -> String {
        if self.min_percent == self.max_percent {
            format!("{}% of native", self.min_percent)
        } else {
            format!("{}-{}% of native", self.min_percent, self.max_percent)
        }
    }
}

/// A translation backend that may or may not be present on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Backend {
    /// FEX-Emu: a user-mode x86/x86-64 translator with an ARM64EC-compatible mode.
    Fex,
    /// Box64: a user-mode x86-64 translator.
    Box64,
    /// Box86, or a WOW64 layer, for 32-bit x86.
    Box86,
    /// Wine, providing the NT system-call translation. Needed for *any* Windows binary,
    /// including fully native ARM64 ones, because a native ARM64 `.exe` still issues NT
    /// syscalls that a Linux kernel does not implement.
    Wine,
}

impl Backend {
    /// Every backend COMPITUM knows about.
    pub const ALL: &'static [Backend] =
        &[Backend::Wine, Backend::Fex, Backend::Box64, Backend::Box86];

    /// Stable identifier for JSON and Oracle records.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Backend::Fex => "fex",
            Backend::Box64 => "box64",
            Backend::Box86 => "box86",
            Backend::Wine => "wine",
        }
    }

    /// The project that provides it, for attribution and for the Oracle record.
    #[must_use]
    pub fn upstream(self) -> &'static str {
        match self {
            Backend::Fex => "https://github.com/FEX-Emu/FEX",
            Backend::Box64 => "https://github.com/ptitSeb/box64",
            Backend::Box86 => "https://github.com/ptitSeb/box86",
            Backend::Wine => "https://www.winehq.org",
        }
    }

    /// What this backend contributes to the execution path.
    #[must_use]
    pub fn role(self) -> &'static str {
        match self {
            Backend::Fex => {
                "user-mode translation of x86 and x86-64 instructions to AArch64, with an \
                 ARM64EC-compatible mode that allows mixing with native code in one process"
            }
            Backend::Box64 => "user-mode translation of x86-64 instructions to AArch64",
            Backend::Box86 => "user-mode translation of 32-bit x86 instructions to AArch64",
            Backend::Wine => {
                "translation of Windows NT system calls to the host operating system; \
                 required for every Windows image, including natively-executing ones"
            }
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// The set of translation backends present on a host.
///
/// Modelled as an explicit set rather than four booleans so that iterating, reporting and
/// extending stay trivial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackendSet(u8);

impl BackendSet {
    /// An empty set: nothing is installed.
    #[must_use]
    pub fn none() -> Self {
        BackendSet(0)
    }

    /// A set containing every backend.
    #[must_use]
    pub fn all() -> Self {
        let mut set = BackendSet::none();
        for backend in Backend::ALL {
            set.insert(*backend);
        }
        set
    }

    fn bit(backend: Backend) -> u8 {
        match backend {
            Backend::Wine => 1 << 0,
            Backend::Fex => 1 << 1,
            Backend::Box64 => 1 << 2,
            Backend::Box86 => 1 << 3,
        }
    }

    /// Marks a backend as present.
    pub fn insert(&mut self, backend: Backend) {
        self.0 |= Self::bit(backend);
    }

    /// Returns a set with the backend added.
    #[must_use]
    pub fn with(mut self, backend: Backend) -> Self {
        self.insert(backend);
        self
    }

    /// Returns `true` when the backend is present.
    #[must_use]
    pub fn contains(self, backend: Backend) -> bool {
        self.0 & Self::bit(backend) != 0
    }

    /// Returns `true` when the set holds no backends.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Number of backends present.
    #[must_use]
    pub fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Iterates over the present backends in a stable order.
    pub fn iter(self) -> impl Iterator<Item = Backend> {
        Backend::ALL
            .iter()
            .copied()
            .filter(move |b| self.contains(*b))
    }

    /// The present backends as stable identifiers.
    #[must_use]
    pub fn ids(self) -> Vec<&'static str> {
        self.iter().map(Backend::id).collect()
    }
}

impl FromIterator<Backend> for BackendSet {
    fn from_iter<T: IntoIterator<Item = Backend>>(iter: T) -> Self {
        let mut set = BackendSet::none();
        for backend in iter {
            set.insert(backend);
        }
        set
    }
}

impl fmt::Display for BackendSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ids = self.ids();
        if ids.is_empty() {
            return f.write_str("(none)");
        }
        f.write_str(&ids.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_classification_is_mutually_exclusive() {
        for route in [
            Route::Native,
            Route::PickNativeSlice,
            Route::FexPartial,
            Route::Box64Full,
            Route::FexFull,
            Route::Wow64,
            Route::Refused,
        ] {
            let categories = [
                route.is_fully_native(),
                route.is_hybrid(),
                route.is_fully_translated(),
                route.is_refusal(),
            ];
            let count = categories.iter().filter(|x| **x).count();
            assert_eq!(
                count, 1,
                "{route} falls into {count} categories, expected exactly 1"
            );
        }
    }

    #[test]
    fn native_routes_need_no_backend() {
        assert_eq!(Route::Native.required_backend(), None);
        assert_eq!(Route::PickNativeSlice.required_backend(), None);
        assert_eq!(Route::Refused.required_backend(), None);
    }

    #[test]
    fn translation_routes_name_their_backend() {
        assert_eq!(Route::FexPartial.required_backend(), Some(Backend::Fex));
        assert_eq!(Route::FexFull.required_backend(), Some(Backend::Fex));
        assert_eq!(Route::Box64Full.required_backend(), Some(Backend::Box64));
        assert_eq!(Route::Wow64.required_backend(), Some(Backend::Box86));
    }

    #[test]
    fn native_is_always_the_fastest_expectation() {
        let native = Route::Native.expected_throughput().unwrap();
        assert_eq!(native.min_percent, 100);
        assert_eq!(native.max_percent, 100);

        for slower in [
            Route::FexPartial,
            Route::FexFull,
            Route::Box64Full,
            Route::Wow64,
        ] {
            let expectation = slower.expected_throughput().unwrap();
            assert!(
                expectation.max_percent < 100,
                "{slower} must not claim native speed"
            );
        }
    }

    #[test]
    fn partial_translation_beats_full_translation() {
        // The economic argument for this entire project, asserted as a property.
        let partial = Route::FexPartial.expected_throughput().unwrap();
        let full = Route::FexFull.expected_throughput().unwrap();
        assert!(
            partial.min_percent > full.max_percent,
            "partial translation must be strictly better than full translation"
        );
    }

    #[test]
    fn refusal_has_no_expectation() {
        assert!(Route::Refused.expected_throughput().is_none());
    }

    #[test]
    fn every_route_has_a_substantive_description() {
        for route in [
            Route::Native,
            Route::PickNativeSlice,
            Route::FexPartial,
            Route::Box64Full,
            Route::FexFull,
            Route::Wow64,
            Route::Refused,
        ] {
            assert!(
                route.description().len() > 40,
                "{route} has an unhelpfully short description"
            );
        }
    }

    #[test]
    fn expectation_renders_as_a_range() {
        assert_eq!(
            Route::Native.expected_throughput().unwrap().render(),
            "100% of native"
        );
        assert_eq!(
            Route::FexPartial.expected_throughput().unwrap().render(),
            "70-90% of native"
        );
    }

    #[test]
    fn expectations_carry_their_basis() {
        for route in [Route::FexPartial, Route::FexFull, Route::Box64Full] {
            let e = route.expected_throughput().unwrap();
            assert!(
                !e.basis.is_empty(),
                "{route} gives no basis for its estimate"
            );
        }
    }

    #[test]
    fn backend_set_operations() {
        let set = BackendSet::none().with(Backend::Wine).with(Backend::Fex);
        assert!(set.contains(Backend::Wine));
        assert!(set.contains(Backend::Fex));
        assert!(!set.contains(Backend::Box64));
        assert_eq!(set.len(), 2);
        assert_eq!(set.ids(), vec!["wine", "fex"]);
    }

    #[test]
    fn empty_backend_set_is_reported_clearly() {
        assert!(BackendSet::none().is_empty());
        assert_eq!(BackendSet::none().to_string(), "(none)");
    }

    #[test]
    fn all_backends_set_contains_everything() {
        let set = BackendSet::all();
        assert_eq!(set.len(), Backend::ALL.len());
        for backend in Backend::ALL {
            assert!(set.contains(*backend));
        }
    }

    #[test]
    fn every_backend_has_attribution_and_role() {
        for backend in Backend::ALL {
            assert!(backend.upstream().starts_with("https://"), "{backend}");
            assert!(backend.role().len() > 20, "{backend}");
        }
    }

    #[test]
    fn from_iterator_builds_set() {
        let set: BackendSet = [Backend::Fex, Backend::Box64].into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn route_ids_are_stable_protocol_values() {
        assert_eq!(Route::Native.id(), "native");
        assert_eq!(Route::FexPartial.id(), "fex_partial");
        assert_eq!(Route::PickNativeSlice.id(), "pick_native_slice");
    }
}
