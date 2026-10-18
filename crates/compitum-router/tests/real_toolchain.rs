//! Routing decisions verified against binaries produced by a real compiler and linker.
//!
//! # Why this lives in `compitum-router`
//!
//! The routing tests need the router, the ISA oracle and the parser together, and only this
//! crate depends on all three. Placing them here rather than in `compitum-pe` keeps the
//! dependency graph acyclic and gives each crate's test suite a single subject: the parser
//! tests the parser, and this tests the decision.
//!
//! # Why real binaries matter
//!
//! A fixture built by this repository shares its assumptions with the code under test, so it
//! cannot detect those assumptions being wrong. That is not hypothetical: the parser's
//! optional-header offsets were wrong by eight bytes, and because the fixture builder chained
//! from the same anchor, the writer and the reader agreed with each other while both
//! disagreed with reality. **325 tests passed and real binaries were classified
//! incorrectly.** Only third-party output exposed it.
//!
//! The corpus in `crates/compitum-pe/tests/corpus/` is that third-party output. These tests
//! exercise the routing decision against it.
//!
//! # The ARM64EC finding
//!
//! `arm64ec_executable_is_indistinguishable_by_machine_type` records a genuine limitation
//! discovered here: lld-link writes machine type `0x8664` (AMD64) for a linked ARM64EC
//! executable, so a machine-type-only classifier cannot tell it from a plain x86-64 binary.
//! The test documents the limitation with evidence rather than asserting it in prose.

use std::path::PathBuf;

use compitum_isa::{FeatureSet, HostProfile, IsaFeature};
use compitum_pe::{parse, AbiFamily, PeImage};
use compitum_router::{decide, BackendSet, ReasonCode, Request, Route};

/// The corpus directory, relative to the `compitum-pe` crate.
fn corpus_dir() -> PathBuf {
    // `CARGO_MANIFEST_DIR` here is `compitum-router`, so walk to the sibling crate. Using the
    // real path rather than copying the files keeps one corpus authoritative.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .expect("crates/ directory")
        .join("compitum-pe/tests/corpus")
}

/// Reads one corpus file, failing with a useful message when it is missing.
fn corpus(name: &str) -> Vec<u8> {
    let path = corpus_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "corpus file {} could not be read: {error}\n\
             Regenerate it with: python3 tools/make_corpus.py",
            path.display()
        )
    })
}

/// Parses one corpus file.
fn parse_corpus(name: &str) -> PeImage {
    let bytes = corpus(name);
    parse(&bytes).unwrap_or_else(|error| panic!("{name} failed to parse: {error}"))
}

/// A host implementing the AArch64 baseline, which every ARM64 CPU provides.
fn baseline_host() -> HostProfile {
    HostProfile::synthetic(
        "aarch64",
        4096,
        8,
        FeatureSet::new()
            .with(IsaFeature::Fp)
            .with(IsaFeature::Asimd),
    )
}

// ===========================================================================
// Routing real ARM64 binaries.
// ===========================================================================

/// Real ARM64 executables must route native, naming no translation backend.
#[test]
fn real_arm64_executables_route_natively() {
    for name in [
        "real-console-4k.exe",
        "real-gui-4k.exe",
        "real-console-16k.exe",
    ] {
        let image = parse_corpus(name);
        assert_eq!(image.family(), AbiFamily::Arm64Native, "{name}");

        let plan = decide(&Request::new(image, baseline_host(), BackendSet::all()));
        assert_eq!(
            plan.route,
            Route::Native,
            "{name}: pure ARM64 must route native"
        );
        assert!(
            plan.is_fully_native(),
            "{name}: nothing should be translated"
        );
        assert_eq!(
            plan.required_backend(),
            None,
            "{name}: a native route must not depend on a translator"
        );
        assert_eq!(plan.status_token(), "NATIVE");
    }
}

/// The end-to-end property this whole project optimises for.
///
/// A route claiming to be fully native must name no backend and must not claim any
/// translation. Asserted here against real binaries, because a regression that quietly loaded
/// a translator for a native binary would be invisible in the output while destroying the
/// value proposition.
#[test]
fn native_routes_on_real_binaries_are_genuinely_native() {
    for name in ["real-console-4k.exe", "real-gui-4k.exe"] {
        let plan = decide(&Request::new(
            parse_corpus(name),
            baseline_host(),
            BackendSet::all(),
        ));

        let throughput = plan
            .throughput
            .expect("a runnable plan predicts throughput");
        assert_eq!(
            (throughput.min_percent, throughput.max_percent),
            (100, 100),
            "{name}: a native route runs at hardware speed"
        );

        let json = plan.to_json();
        assert_eq!(json["fully_native"].as_bool(), Some(true), "{name}");
        assert!(
            json["backend"].is_null(),
            "{name}: native must name no backend"
        );
        assert!(
            json["reasons"]
                .as_array()
                .expect("reasons are recorded")
                .iter()
                .any(|r| r["code"].as_str() == Some("architecture_native")),
            "{name}: the decision must carry its evidence"
        );
    }
}

/// A real 16 KiB-aligned image must be flagged against a 4 KiB host.
///
/// The page-size axis is easy to overlook and produces failures that look intermittent rather
/// than systematic, so the router must state it explicitly.
#[test]
fn real_16k_image_is_flagged_against_a_4k_host() {
    let host = HostProfile::synthetic(
        "aarch64",
        4096,
        8,
        FeatureSet::new()
            .with(IsaFeature::Fp)
            .with(IsaFeature::Asimd),
    );

    let plan = decide(&Request::new(
        parse_corpus("real-console-16k.exe"),
        host,
        BackendSet::all(),
    ));

    assert!(
        plan.reasons.contains(ReasonCode::PageSizeMismatch),
        "an image aligned to 16 KiB on a 4 KiB host is a real compatibility question, and the \
         router must say so rather than staying silent"
    );
    assert!(plan.reasons.has_caution());
    // It is still runnable: a page-size difference is a caution, not a refusal.
    assert!(!plan.is_blocked());
}

/// A 4 KiB image against a 4 KiB host must not raise a spurious caution.
///
/// The negative direction matters as much as the positive one: a caution that fires on every
/// file is noise that trains operators to ignore cautions.
#[test]
fn real_4k_image_matches_a_4k_host_without_a_caution() {
    let plan = decide(&Request::new(
        parse_corpus("real-console-4k.exe"),
        baseline_host(),
        BackendSet::all(),
    ));

    assert!(!plan.reasons.contains(ReasonCode::PageSizeMismatch));
    assert!(plan.reasons.contains(ReasonCode::PageSizeMatches));
}

/// A graphical real binary must route as needing a display, and must be refused in a
/// headless-only evaluation.
#[test]
fn real_gui_binary_is_refused_when_a_display_is_disallowed() {
    let plan = decide(
        &Request::new(
            parse_corpus("real-gui-4k.exe"),
            baseline_host(),
            BackendSet::all(),
        )
        .headless_only(true),
    );

    assert!(
        plan.is_blocked(),
        "a graphical application cannot satisfy a headless-only requirement"
    );
    assert!(plan.reasons.contains(ReasonCode::SubsystemRequiresDisplay));

    let json = plan.to_json();
    assert_eq!(json["blocked"].as_bool(), Some(true));
    assert!(
        json["blocking_reason_count"].as_u64().unwrap_or(0) >= 1,
        "a refusal must name at least one blocking reason"
    );
}

/// A console real binary must be accepted in the same headless-only evaluation.
#[test]
fn real_console_binary_is_accepted_when_a_display_is_disallowed() {
    let plan = decide(
        &Request::new(
            parse_corpus("real-console-4k.exe"),
            baseline_host(),
            BackendSet::all(),
        )
        .headless_only(true),
    );

    assert!(!plan.is_blocked(), "a console application needs no display");
    assert_eq!(plan.route, Route::Native);
}

// ===========================================================================
// The documented ARM64EC limitation.
// ===========================================================================

/// Records the observed behaviour: a linked ARM64EC executable carries machine type `0x8664`.
///
/// clang emits an ARM64EC **object** with machine type `0xA641`
/// (`IMAGE_FILE_MACHINE_ARM64EC`), but lld-link writes an ARM64EC **executable** with machine
/// type `0x8664` (`IMAGE_FILE_MACHINE_AMD64`). The hybrid nature is expressed by the mixture
/// of code and by the CHPE metadata, not by the machine field of the linked image.
///
/// This is a genuine limitation of classifying by machine type alone, documented here **with
/// evidence** rather than in prose. It is also why `compitum-pe` reports the CHPE section
/// prefix and the load-configuration directory as additional signals instead of trusting the
/// machine field on its own.
#[test]
fn arm64ec_executable_is_indistinguishable_by_machine_type() {
    let image = parse_corpus("real-arm64ec.exe");

    assert_eq!(
        image.coff.machine.raw(),
        0x8664,
        "lld-link writes IMAGE_FILE_MACHINE_AMD64 for a linked ARM64EC executable; if this \
         ever changes, the classification logic and this test must change together"
    );
    assert_eq!(
        image.family(),
        AbiFamily::X86_64,
        "by machine type alone this is indistinguishable from a plain x86-64 image, which is \
         exactly the limitation this test documents"
    );
    assert!(
        !image.has_arm64x_slices(),
        "this file carries no CHPE sections either, so the limitation cannot be resolved from \
         the section table"
    );

    // The consequence for the caller: routing falls back to full translation, which is
    // correct-but-pessimistic. Recording it as a known cost is better than silently
    // mis-classifying it as native.
    let plan = decide(&Request::new(image, baseline_host(), BackendSet::all()));
    assert_eq!(
        plan.route,
        Route::Box64Full,
        "an image that cannot be distinguished from x86-64 is routed as x86-64, which \
         over-translates but never under-translates"
    );
    assert!(
        plan.route.is_fully_translated(),
        "the conservative choice translates everything, which is safe in the direction that \
         matters: it never promises native execution it cannot deliver"
    );
}

// ===========================================================================
// Determinism, which the Oracle depends on.
// ===========================================================================

/// The same real binary and host must produce byte-identical output.
///
/// A routing decision that is not reproducible cannot be recorded and replayed, which would
/// make the Oracle's stored evidence worthless precisely when it is most needed -- when
/// someone is trying to explain a failure from last month.
#[test]
fn decisions_on_real_binaries_are_reproducible() {
    for name in ["real-console-4k.exe", "real-gui-4k.exe", "real-arm64ec.exe"] {
        let first = decide(&Request::new(
            parse_corpus(name),
            baseline_host(),
            BackendSet::all(),
        ));
        let second = decide(&Request::new(
            parse_corpus(name),
            baseline_host(),
            BackendSet::all(),
        ));

        assert_eq!(
            first.to_json().to_string(),
            second.to_json().to_string(),
            "{name}: the decision must be a pure function of the facts, or a stored record \
             could not be replayed"
        );
    }
}
