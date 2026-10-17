//! The routing plan: COMPITUM's final answer about a binary-host pair.
//!
//! A [`Plan`] is what every other component exists to produce. It bundles the chosen
//! [`Route`], the [`Reasons`] that justify it, and an overall [`Confidence`] — and it
//! serializes to a stable JSON document so the Oracle, the CLI and any future API all
//! speak about decisions in exactly the same terms.
//!
//! # What a plan is *not*
//!
//! It is not an instruction to execute anything. COMPITUM classifies and decides; it does
//! not load, map, or run images. A plan is advisory in the precise sense that it states
//! what would happen and why, with evidence, and leaves the doing to the operator or to a
//! separate runner.
//!
//! # The headline
//!
//! Every plan renders a single `headline`: one English sentence an operator can act on
//! without reading the JSON. If the headline is not sufficient to explain the situation,
//! that is a bug in the headline, not a reason to read the detail.

use std::fmt;

use compitum_isa::Confidence;

use crate::reason::{Reason, Reasons, Severity};
use crate::route::{Backend, Route, ThroughputExpectation};

/// The complete result of routing one binary against one host.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// The chosen execution route.
    pub route: Route,
    /// Every piece of evidence bearing on the choice.
    pub reasons: Reasons,
    /// How much the whole plan can be trusted.
    pub confidence: Confidence,
    /// An identifier for the subject — typically a path, for the Oracle record.
    pub subject: Option<String>,
    /// Present only when the route can actually proceed.
    pub throughput: Option<ThroughputExpectation>,
}

impl Plan {
    /// Builds a plan from a route and its supporting reasons.
    ///
    /// The plan's confidence is the weakest confidence among its reasons: a conclusion is
    /// only as certain as the shakiest evidence it rests on, and quietly averaging would
    /// hide exactly the case an operator needs to know about.
    #[must_use]
    pub fn new(route: Route, reasons: Reasons, subject: Option<String>) -> Self {
        let confidence = reasons.weakest_confidence();
        let throughput = route.expected_throughput();
        Plan {
            route,
            reasons,
            confidence,
            subject,
            throughput,
        }
    }

    /// Builds a refusal plan from a single reason.
    #[must_use]
    pub fn refused(reason: Reason, subject: Option<String>) -> Self {
        let mut reasons = Reasons::new();
        reasons.push(reason);
        Plan::new(Route::Refused, reasons, subject)
    }

    /// Returns `true` when no instruction will be translated at run time.
    #[must_use]
    pub fn is_fully_native(&self) -> bool {
        self.route.is_fully_native() && !self.reasons.is_blocked()
    }

    /// Returns `true` when the subject cannot be executed on this host.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.route.is_refusal() || self.reasons.is_blocked()
    }

    /// The backend required to carry out this plan, if any.
    #[must_use]
    pub fn required_backend(&self) -> Option<Backend> {
        if self.is_blocked() {
            return None;
        }
        self.route.required_backend()
    }

    /// A single actionable English sentence.
    ///
    /// Written to be read by someone who is looking at a failing deployment and does not
    /// want to parse JSON.
    #[must_use]
    pub fn headline(&self) -> String {
        if self.is_blocked() {
            let blockers = self.reasons.blocking();
            if let Some(first) = blockers.first() {
                let extra = if blockers.len() > 1 {
                    format!(
                        " ({} further blocking reasons; run with --json for all)",
                        blockers.len() - 1
                    )
                } else {
                    String::new()
                };
                let detail = first
                    .detail
                    .as_deref()
                    .map(|d| format!(" {d}."))
                    .unwrap_or_default();
                return format!(
                    "Cannot run: {}.{detail}{extra}",
                    first.code.id().replace('_', " ")
                );
            }
            return "Cannot run: the reason was not recorded, which is itself a defect".to_owned();
        }

        match self.route {
            Route::Native => {
                "Runs natively: every CPU feature this image requires is present, so no \
                 instruction is translated."
                    .to_owned()
            }
            Route::PickNativeSlice => {
                "Runs natively after slice selection: this fat image carries a pure ARM64 \
                 slice, and choosing it avoids the hybrid path entirely."
                    .to_owned()
            }
            Route::FexPartial => {
                "Runs hybrid: the ARM64 functions execute natively and the x86-64 \
                 functions embedded in the same image are translated on demand."
                    .to_owned()
            }
            Route::Box64Full => {
                "Runs translated: this is an x86-64 image, so every instruction is \
                 translated to AArch64."
                    .to_owned()
            }
            Route::FexFull => {
                "Runs translated: this is an x86-64 image, so every instruction is \
                 translated to AArch64."
                    .to_owned()
            }
            Route::Wow64 => {
                "Runs translated in 32-bit mode: this image additionally requires a WOW64 \
                 compatibility environment."
                    .to_owned()
            }
            Route::Refused => "Cannot run.".to_owned(),
        }
    }

    /// A compact multi-line rendering for a terminal.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("route      : {}\n", self.route.id()));
        out.push_str(&format!("confidence : {}\n", self.confidence));
        if let Some(throughput) = self.throughput {
            if !self.is_blocked() {
                out.push_str(&format!(
                    "expected   : {} ({})\n",
                    throughput.render(),
                    throughput.basis
                ));
            }
        }
        if let Some(backend) = self.required_backend() {
            out.push_str(&format!("backend    : {}\n", backend.id()));
        }
        out.push_str(&format!("verdict    : {}\n", self.headline()));
        if !self.reasons.is_empty() {
            out.push_str("reasons:\n");
            for reason in self.reasons.items() {
                out.push_str(&format!("  {reason}\n"));
            }
        }
        out
    }

    /// A one-line status token suitable for a report column or a CI gate.
    ///
    /// Intentionally terse and uppercase so that it is greppable and stable.
    #[must_use]
    pub fn status_token(&self) -> &'static str {
        if self.is_blocked() {
            return "REFUSED";
        }
        match self.route {
            Route::Native | Route::PickNativeSlice => "NATIVE",
            Route::FexPartial => "HYBRID",
            Route::Box64Full | Route::FexFull => "TRANSLATED",
            Route::Wow64 => "WOW64",
            Route::Refused => "REFUSED",
        }
    }

    /// Serializes the plan to the Oracle's canonical JSON shape.
    ///
    /// Field names are protocol: they appear in stored records and in any API, so they are
    /// English, lowercase, snake_case, and never translated.
    #[must_use]
    pub fn to_json(&self) -> compitum_json::Value {
        let reasons_json = self.reasons.to_json();
        compitum_json::Object::new()
            .with("schema_version", SCHEMA_VERSION)
            .with("subject", self.subject.as_deref())
            .with("route", self.route.id())
            .with("route_description", self.route.description())
            .with("status", self.status_token())
            .with("fully_native", self.is_fully_native())
            .with("blocked", self.is_blocked())
            .with("confidence_permille", self.confidence.permille())
            .with("confidence_percent", self.confidence.percent())
            .with("backend", self.required_backend().map(Backend::id))
            .with(
                "expected_throughput_percent",
                self.throughput.map(throughput_to_json),
            )
            .with("headline", self.headline())
            .with("blocking_reason_count", self.reasons.blocking().len())
            .with("caution_count", self.reasons.items().iter().filter(|r| r.severity == Severity::Caution).count())
            .with("reasons", reasons_json)
            .into()
    }
}

/// Renders a throughput expectation as a JSON object.
///
/// Extracted so the `.into()` target type is unambiguous at the call site; inferring it
/// inside a closure that returns a generic conversion is exactly the kind of ambiguity
/// the compiler rightly refuses.
#[must_use]
fn throughput_to_json(t: ThroughputExpectation) -> compitum_json::Value {
    compitum_json::Object::new()
        .with("min", t.min_percent)
        .with("max", t.max_percent)
        .with("basis", t.basis)
        .into()
}

/// The JSON schema version emitted by [`Plan::to_json`].
///
/// Bumped only for breaking changes. The Oracle stores records against this value so that
/// old observations remain interpretable after the schema evolves.
pub const SCHEMA_VERSION: u32 = 1;

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reason::ReasonCode;

    fn native_plan() -> Plan {
        let mut reasons = Reasons::new();
        reasons.add(ReasonCode::ArchitectureNative);
        reasons.add(ReasonCode::IsaSubsetSatisfied);
        Plan::new(Route::Native, reasons, Some("/tmp/app.exe".to_owned()))
    }

    #[test]
    fn native_plan_is_native_and_not_blocked() {
        let plan = native_plan();
        assert!(plan.is_fully_native());
        assert!(!plan.is_blocked());
        assert_eq!(plan.status_token(), "NATIVE");
        assert_eq!(plan.required_backend(), None);
    }

    #[test]
    fn confidence_is_the_weakest_reason() {
        let mut reasons = Reasons::new();
        reasons.push(Reason::new(ReasonCode::ArchitectureNative));
        reasons.push(
            Reason::new(ReasonCode::IsaEvidenceWeak).confidence(Confidence::MEDIUM),
        );
        let plan = Plan::new(Route::Native, reasons, None);
        assert_eq!(plan.confidence, Confidence::MEDIUM);
    }

    #[test]
    fn blocked_plan_is_refused_and_has_no_backend() {
        let plan = Plan::refused(
            Reason::with_detail(ReasonCode::IsaFeaturesMissing, "sme absent"),
            None,
        );
        assert!(plan.is_blocked());
        assert!(!plan.is_fully_native());
        assert_eq!(plan.required_backend(), None);
        assert_eq!(plan.status_token(), "REFUSED");
    }

    #[test]
    fn headline_for_native_mentions_no_translation() {
        let headline = native_plan().headline();
        assert!(headline.contains("natively"));
        assert!(headline.contains("no instruction is translated") || headline.contains("translated"));
    }

    #[test]
    fn headline_for_blocked_names_the_blocking_reason() {
        let plan = Plan::refused(
            Reason::with_detail(ReasonCode::BackendAbsent, "fex is not installed"),
            None,
        );
        let headline = plan.headline();
        assert!(headline.starts_with("Cannot run:"));
        assert!(headline.contains("backend absent"));
        assert!(headline.contains("fex is not installed"));
    }

    #[test]
    fn headline_counts_further_blockers() {
        let mut reasons = Reasons::new();
        reasons.add_detail(ReasonCode::BackendAbsent, "fex missing");
        reasons.add_detail(ReasonCode::SyscallLayerAbsent, "wine missing");
        let plan = Plan::new(Route::Refused, reasons, None);
        assert!(plan.headline().contains("1 further blocking reason"));
    }

    #[test]
    fn hybrid_plan_names_fex_and_is_not_native() {
        let mut reasons = Reasons::new();
        reasons.add(ReasonCode::ArchitectureHybrid);
        let plan = Plan::new(Route::FexPartial, reasons, None);
        assert!(!plan.is_fully_native());
        assert!(!plan.is_blocked());
        assert_eq!(plan.required_backend(), Some(Backend::Fex));
        assert_eq!(plan.status_token(), "HYBRID");
    }

    #[test]
    fn translated_plans_report_the_right_token() {
        let mut reasons = Reasons::new();
        reasons.add(ReasonCode::ArchitectureRequiresTranslation);
        assert_eq!(
            Plan::new(Route::Box64Full, reasons, None).status_token(),
            "TRANSLATED"
        );
        let mut wow = Reasons::new();
        wow.add(ReasonCode::ArchitectureRequiresWow64);
        assert_eq!(Plan::new(Route::Wow64, wow, None).status_token(), "WOW64");
    }

    #[test]
    fn render_includes_route_reasons_and_verdict() {
        let text = native_plan().render();
        assert!(text.contains("route      : native"));
        assert!(text.contains("confidence"));
        assert!(text.contains("reasons:"));
        assert!(text.contains("architecture_native"));
    }

    #[test]
    fn render_omits_throughput_for_blocked_plans() {
        let plan = Plan::refused(Reason::new(ReasonCode::ArchitectureUnsupported), None);
        assert!(!plan.render().contains("expected"));
    }

    #[test]
    fn json_has_the_documented_protocol_keys() {
        let json = native_plan().to_json();
        assert_eq!(json["schema_version"].as_u64(), Some(1));
        assert_eq!(json["route"].as_str(), Some("native"));
        assert_eq!(json["status"].as_str(), Some("NATIVE"));
        assert_eq!(json["fully_native"].as_bool(), Some(true));
        assert_eq!(json["blocked"].as_bool(), Some(false));
        assert_eq!(json["confidence_percent"].as_u64(), Some(100));
        assert_eq!(json["subject"].as_str(), Some("/tmp/app.exe"));
        assert!(json["backend"].is_null());
        assert!(json["reasons"].as_array().is_some());
    }

    #[test]
    fn json_records_blocking_and_caution_counts() {
        let mut reasons = Reasons::new();
        reasons.add(ReasonCode::ArchitectureHybrid); // caution
        reasons.add(ReasonCode::PageSizeMismatch); // caution
        reasons.add(ReasonCode::BackendAbsent); // blocked
        let plan = Plan::new(Route::Refused, reasons, None);
        let json = plan.to_json();
        assert_eq!(json["blocking_reason_count"].as_u64(), Some(1));
        assert_eq!(json["caution_count"].as_u64(), Some(2));
    }

    #[test]
    fn throughput_is_present_for_runnable_plans_and_absent_for_refusals() {
        assert!(native_plan().to_json()["expected_throughput_percent"].as_object().is_some());
        let refused = Plan::refused(Reason::new(ReasonCode::ArchitectureUnsupported), None);
        assert!(refused.to_json()["expected_throughput_percent"].is_null());
    }

    #[test]
    fn display_matches_render() {
        let plan = native_plan();
        assert_eq!(plan.to_string(), plan.render());
    }
}
