//! Human and machine output rendering.
//!
//! Two rendering paths, deliberately kept apart:
//!
//! * **Human output** goes through the [`Translator`], so every sentence an operator reads is
//!   localizable. The English text is compiled into the binary, so it always works.
//! * **Machine output** is JSON with protocol-stable English keys and enum values. It is
//!   **never** translated, because a consumer that parses `route` would break the moment
//!   somebody added a translation.
//!
//! That split is the whole reason the localization engine can exist without endangering the
//! Oracle's schema.

use std::fmt::Write as _;

use compitum_i18n::Translator;
use compitum_isa::HostProfile;
use compitum_json::{to_pretty, Value};
use compitum_pe::PeImage;
use compitum_router::{Plan, Severity};

use crate::scan::{ScanKind, ScanReport};

use compitum_pe::patch::PortVerdict;

/// The width at which a label column is padded in human output.
const LABEL_WIDTH: usize = 14;

/// Renders a `label  value` line.
#[must_use]
pub fn field(label: &str, value: impl std::fmt::Display) -> String {
    format!("  {label:<width$} {value}\n", width = LABEL_WIDTH)
}

/// Renders a section heading.
#[must_use]
pub fn heading(text: &str) -> String {
    format!("\n{text}\n")
}

/// Renders the host capabilities report.
#[must_use]
pub fn render_host(host: &HostProfile, translator: &Translator, json: bool) -> String {
    if json {
        return to_pretty(&host.to_json()) + "\n";
    }

    let mut out = String::new();
    out.push_str(&format!(
        "{} — {}\n",
        translator.text("app.name"),
        translator.text("cmd.host")
    ));
    out.push_str(&heading(&translator.text("section.host")));
    out.push_str(&field(&translator.text("field.arch"), &host.arch));
    out.push_str(&field(&translator.text("field.cores"), host.cpu_count));
    out.push_str(&field(
        &translator.text("field.page_size"),
        format!("{} bytes", host.page_size),
    ));
    out.push_str(&field(&translator.text("field.kernel"), &host.kernel));
    out.push_str(&field("hwcap", format!("0x{:016x}", host.raw_hwcap)));
    out.push_str(&field("hwcap2", format!("0x{:016x}", host.raw_hwcap2)));

    out.push_str(&heading(&translator.text("section.capabilities")));
    let present: Vec<&str> = host.features.iter().map(|f| f.id()).collect();
    out.push_str(&format!(
        "  {} features: {}\n",
        present.len(),
        present.join(" ")
    ));

    // Call out the features that actually change a routing decision, and just as importantly
    // the ones that are absent. "SVE2 and SME are missing" is the single most useful sentence
    // this command can print for a device of this class.
    let watched = [
        compitum_isa::IsaFeature::Sve,
        compitum_isa::IsaFeature::Sve2,
        compitum_isa::IsaFeature::Sme,
        compitum_isa::IsaFeature::Mte,
        compitum_isa::IsaFeature::Bf16,
        compitum_isa::IsaFeature::I8mm,
    ];
    let missing: Vec<&str> = watched
        .iter()
        .filter(|f| !host.features.contains(**f))
        .map(|f| f.id())
        .collect();
    if !missing.is_empty() {
        out.push_str(&format!(
            "  {}: {}\n",
            translator.text("field.missing"),
            missing.join(" ")
        ));
    }

    if !host.is_arm64() {
        out.push_str(&format!(
            "\n  ! {}\n",
            translator.text("reason.host_not_arm64")
        ));
    }
    if host.has_non_windows_page_size() {
        out.push_str(&format!(
            "  ! {}: {} bytes, so 4 KiB Windows images are a separate compatibility question\n",
            translator.text("reason.page_size_mismatch"),
            host.page_size
        ));
    }
    out
}

/// Renders a binary classification, without a routing decision.
#[must_use]
pub fn render_inspect(
    image: &PeImage,
    label: &str,
    digest: Option<&compitum_digest::Digest>,
    size: u64,
    translator: &Translator,
    json: bool,
    verbose: bool,
) -> String {
    if json {
        return to_pretty(&inspect_json(image, label, digest, size, verbose)) + "\n";
    }

    let mut out = String::new();
    out.push_str(&format!("{} — {}\n", translator.text("app.name"), label));
    out.push_str(&heading(&translator.text("section.binary")));
    out.push_str(&field(
        &translator.text("field.size"),
        format!("{size} bytes"),
    ));
    if let Some(digest) = digest {
        out.push_str(&field(&translator.text("field.sha256"), digest.to_hex()));
    }
    out.push_str(&field(
        &translator.text("field.machine_raw"),
        format!(
            "0x{:04X}  ({})",
            image.coff.machine.raw(),
            image.coff.machine.short_name()
        ),
    ));
    out.push_str(&field(&translator.text("field.arch"), image.family().id()));
    out.push_str(&field(
        &translator.text("field.subsystem"),
        format!(
            "{}  ({})",
            image.subsystem().id(),
            image.subsystem().description()
        ),
    ));
    out.push_str(&field(
        &translator.text("field.kind"),
        if image.is_kernel_driver() {
            // Reported first, because it overrides the DLL/EXE distinction that follows for
            // every practical purpose: a driver is loaded by the kernel, not by a loader.
            "kernel driver"
        } else if image.coff.is_dll() {
            "DLL"
        } else if image.coff.is_object_file() {
            "object file (not linked)"
        } else {
            "executable"
        },
    ));
    if let Some(page) = image.implied_page_size() {
        out.push_str(&field(
            &translator.text("field.page_size"),
            format!("{page} bytes"),
        ));
    }
    out.push_str(&field(
        "managed",
        if image.is_managed() {
            "yes (.NET)"
        } else {
            "no"
        },
    ));
    out.push_str(&field(
        "headless",
        if image.is_headless_capable() {
            "capable"
        } else {
            "needs a display"
        },
    ));
    out.push_str(&field(
        "exec code",
        format!("{} bytes", image.executable_bytes()),
    ));

    // The explanation of what this ABI family means is the most valuable output of the
    // command, so it is always shown, not gated behind --verbose.
    out.push_str(&heading(&translator.text("section.notes")));
    out.push_str(&format!("  {}\n", image.family().execution_semantics()));

    if !image.imports.is_empty() {
        out.push_str(&heading(&translator.text("section.imports")));
        let mut names: Vec<&str> = image.imports.iter().map(|m| m.name.as_str()).collect();
        names.sort();
        for name in names {
            out.push_str(&format!("  {name}\n"));
        }
    }

    if verbose {
        out.push_str(&heading(&translator.text("section.details")));
        for section in &image.sections {
            out.push_str(&format!(
                "  {:8} va=0x{:08X} raw=0x{:08X} size=0x{:X} {}{}\n",
                section.name,
                section.virtual_address,
                section.raw_offset,
                section.raw_size,
                if section.is_executable() { "X" } else { "-" },
                if section.is_initialized_data() {
                    "D"
                } else {
                    "-"
                },
            ));
        }
    }
    out
}

/// The JSON shape for `inspect`.
#[must_use]
pub fn inspect_json(
    image: &PeImage,
    label: &str,
    digest: Option<&compitum_digest::Digest>,
    size: u64,
    verbose: bool,
) -> Value {
    let imports: Vec<Value> = image
        .imports
        .iter()
        .map(|m| {
            compitum_json::Object::new()
                .with("module", m.name.as_str())
                .with("symbols", m.symbol_count)
                .with("graphics", m.is_graphics())
                .into()
        })
        .collect();

    let mut doc = compitum_json::Object::new()
        .with("schema_version", 1u32)
        .with("subject_label", label)
        .with("subject_size", size)
        .with(
            "subject_sha256",
            digest.map(compitum_digest::Digest::to_hex),
        )
        .with("machine_raw", u64::from(image.coff.machine.raw()))
        .with("machine_name", image.coff.machine.canonical_name())
        .with("abi_family", image.family().id())
        .with("execution_semantics", image.family().execution_semantics())
        .with("subsystem", image.subsystem().id())
        .with(
            "subsystem_requires_display",
            image.subsystem().requires_display(),
        )
        .with("is_dll", image.coff.is_dll())
        // Emitted next to `is_dll` because it overrides it in practice: a kernel driver is
        // usually also marked as a DLL, and a consumer that only reads `is_dll` will classify a
        // driver as an ordinary library. Machine-readable output has to carry the distinction
        // the human report already makes.
        .with("is_kernel_driver", image.is_kernel_driver())
        .with("is_managed", image.is_managed())
        .with("headless_capable", image.is_headless_capable())
        .with("imports_graphics", image.imports_graphics())
        .with("executable_bytes", image.executable_bytes())
        .with(
            "implied_page_size",
            image.implied_page_size().map(u64::from),
        )
        .with("arm64x_slices", image.has_arm64x_slices())
        .with("section_count", image.sections.len())
        .with("imports", imports);

    if verbose {
        let sections: Vec<Value> = image
            .sections
            .iter()
            .map(|s| {
                compitum_json::Object::new()
                    .with("name", s.name.as_str())
                    .with("virtual_address", u64::from(s.virtual_address))
                    .with("raw_offset", u64::from(s.raw_offset))
                    .with("raw_size", u64::from(s.raw_size))
                    .with("executable", s.is_executable())
                    .into()
            })
            .collect();
        doc.insert("sections", sections);
    }
    doc.into()
}

/// Renders a routing plan.
#[must_use]
pub fn render_plan(
    plan: &Plan,
    label: &str,
    translator: &Translator,
    json: bool,
    verbose: bool,
) -> String {
    if json {
        return to_pretty(&plan.to_json()) + "\n";
    }

    let mut out = String::new();
    out.push_str(&format!("{} — {label}\n", translator.text("app.name")));
    out.push_str(&heading(&translator.text("section.verdict")));

    // The verdict token is uppercase and column-stable so it can be grepped out of a CI log.
    out.push_str(&format!(
        "  {:<12} {}\n",
        translator.text("field.route"),
        plan.status_token()
    ));
    out.push_str(&field("internal", plan.route.id()));
    out.push_str(&field(
        &translator.text("field.confidence"),
        format!("{}%", plan.confidence.percent()),
    ));
    if let Some(backend) = plan.required_backend() {
        out.push_str(&field(&translator.text("field.emulation"), backend.id()));
    } else if plan.is_fully_native() {
        out.push_str(&field(&translator.text("field.emulation"), "none"));
    }
    if let Some(throughput) = plan.throughput {
        if !plan.is_blocked() {
            out.push_str(&field("expected", throughput.render()));
        }
    }

    out.push_str(&heading(&translator.text("field.explanation")));
    out.push_str(&format!("  {}\n", plan.headline()));
    out.push_str(&format!("  {}\n", plan.route.description()));

    out.push_str(&heading(&translator.text("field.reasons")));
    for reason in plan.reasons.items() {
        // Supporting reasons are noise unless the operator asked for them; blockers and
        // cautions always matter.
        if reason.severity == Severity::Supporting && !verbose {
            continue;
        }
        out.push_str(&format!("  {reason}\n"));
    }
    if verbose {
        out.push_str(&heading("supporting"));
        for reason in plan.reasons.supporting() {
            out.push_str(&format!("  {reason}\n"));
        }
    }
    out
}

/// Renders the ledger summary.
#[must_use]
pub fn render_ledger_summary(summary: &Value, translator: &Translator, json: bool) -> String {
    if json {
        return to_pretty(summary) + "\n";
    }
    let mut out = String::new();
    out.push_str(&format!(
        "{} — {}\n",
        translator.text("app.name"),
        translator.text("cmd.oracle")
    ));
    out.push_str(&heading(&translator.text("section.details")));
    out.push_str(&field(
        "ledger",
        summary["ledger_path"].as_str().unwrap_or("(memory)"),
    ));
    out.push_str(&field(
        &translator.text("field.records"),
        summary["total_records"].as_u64().unwrap_or(0),
    ));
    out.push_str(&field(
        "subjects",
        summary["distinct_subjects"].as_u64().unwrap_or(0),
    ));
    out.push_str(&field(
        "determined",
        summary["determined_outcomes"].as_u64().unwrap_or(0),
    ));

    let unreadable = summary["unreadable_lines"].as_u64().unwrap_or(0);
    if unreadable > 0 {
        out.push_str(&format!(
            "  ! {unreadable} line(s) in the ledger could not be read and were skipped\n"
        ));
    }

    let render_counts = |out: &mut String, title: &str, key: &str, value_key: &str| {
        if let Some(items) = summary[key].as_array() {
            if items.is_empty() {
                return;
            }
            out.push_str(&heading(title));
            for item in items {
                out.push_str(&format!(
                    "  {:<24} {}\n",
                    item[value_key].as_str().unwrap_or("?"),
                    item["count"].as_u64().unwrap_or(0)
                ));
            }
        }
    };
    render_counts(&mut out, "by route", "by_route", "route");
    render_counts(&mut out, "by outcome", "by_outcome", "outcome");
    render_counts(&mut out, "by host class", "by_host_class", "host_class");
    out
}

/// Renders a table of ledger records.
#[must_use]
pub fn render_records(
    records: &[&compitum_oracle::Record],
    translator: &Translator,
    json: bool,
) -> String {
    if json {
        let items: Vec<Value> = records.iter().map(|r| r.to_json()).collect();
        return to_pretty(&Value::from(items)) + "\n";
    }
    let mut out = String::new();
    out.push_str(&format!(
        "{} — {} ({} {})\n",
        translator.text("app.name"),
        translator.text("cmd.oracle"),
        records.len(),
        translator.text("field.records")
    ));
    out.push_str(&format!(
        "\n  {:<8} {:<3} {:<8} {:<24} {:<22} {}\n",
        "sha256", "out", "state", "family", "route", "subject"
    ));
    for record in records {
        out.push_str(&format!("  {}\n", record.summary_line()));
    }
    out
}

/// Renders the locale inventory.
#[must_use]
pub fn render_locales(
    active: &str,
    available: &[(String, u32, String)],
    translator: &Translator,
    json: bool,
) -> String {
    if json {
        let items: Vec<Value> = available
            .iter()
            .map(|(tag, coverage, native_name)| {
                compitum_json::Object::new()
                    .with("tag", tag.as_str())
                    .with("coverage_percent", *coverage)
                    .with("native_name", native_name.as_str())
                    .with("active", tag == active)
                    .into()
            })
            .collect();
        return to_pretty(
            &compitum_json::Object::new()
                .with("active", active)
                .with("count", available.len())
                .with("locales", items)
                .into(),
        ) + "\n";
    }

    let mut out = String::new();
    out.push_str(&format!(
        "{} — {}\n",
        translator.text("app.name"),
        translator.text("cmd.locales.list")
    ));
    out.push_str(&heading(&translator.text("section.details")));
    out.push_str(&field(&translator.text("field.locale"), active));
    if available.is_empty() {
        out.push_str("\n  Only the compiled-in English base is available.\n");
        out.push_str("  Add a language by placing `<tag>.json` in a `locales/` directory,\n");
        out.push_str("  or by setting COMPITUM_LOCALES to point at one.\n");
        return out;
    }
    out.push_str(&format!(
        "\n  {:<10} {:<8} {}\n",
        "tag", "coverage", "language"
    ));
    for (tag, coverage, native_name) in available {
        let marker = if tag == active { "*" } else { " " };
        out.push_str(&format!(
            "  {marker}{:<9} {:>6}%  {}\n",
            tag, coverage, native_name
        ));
    }
    out
}

/// Renders the translation-gap report.
#[must_use]
pub fn render_locale_check(
    tag: &str,
    coverage: u32,
    missing: &[String],
    obsolete: &[String],
    translator: &Translator,
    json: bool,
) -> String {
    if json {
        return to_pretty(
            &compitum_json::Object::new()
                .with("locale", tag)
                .with("coverage_percent", coverage)
                .with("missing_count", missing.len())
                .with("obsolete_count", obsolete.len())
                .with("missing_keys", missing.to_vec())
                .with("obsolete_keys", obsolete.to_vec())
                .into(),
        ) + "\n";
    }

    let mut out = String::new();
    out.push_str(&format!(
        "{} — {} {tag}\n",
        translator.text("app.name"),
        translator.text("cmd.locales.check")
    ));
    out.push_str(&heading(&translator.text("section.details")));
    out.push_str(&field(
        &translator.text("field.coverage"),
        format!("{coverage}%"),
    ));
    out.push_str(&field(&translator.text("field.missing"), missing.len()));
    out.push_str(&field("obsolete", obsolete.len()));

    if !missing.is_empty() {
        out.push_str(&heading("missing keys (fall back to English)"));
        for key in missing {
            out.push_str(&format!("  {key}\n"));
        }
    }
    if !obsolete.is_empty() {
        out.push_str(&heading("obsolete keys (no longer used)"));
        for key in obsolete {
            out.push_str(&format!("  {key}\n"));
        }
    }
    if missing.is_empty() && obsolete.is_empty() {
        out.push_str("\n  This locale is complete.\n");
    }
    out
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

/// Renders a batch scan for a human reader.
///
/// # What this report is for
///
/// This is the artefact a migration is decided from, so it leads with the number that decides
/// it — how many images will not run — and only then shows the detail. The four outcome
/// categories are reported separately and never summed into one figure, because "not a Windows
/// image" and "a corrupt executable" are not the same kind of news.
///
/// `all` controls whether every scanned file is listed. The default shows only files that need
/// attention, because a report over two thousand files is read for its exceptions.
#[must_use]
pub fn render_scan(report: &ScanReport, translator: &Translator, json: bool, all: bool) -> String {
    if json {
        return to_pretty(&scan_json(report, all)) + "\n";
    }

    let counts = report.counts;
    let mut out = String::new();
    out.push_str(&format!(
        "{} — {}\n",
        translator.text("app.name"),
        report.root
    ));
    out.push_str(&heading("Summary"));

    out.push_str(&field("files", counts.files_seen));
    out.push_str(&field("images", counts.routed));

    // Reported only when it is non-zero. A line that usually reads "native 0" trains a reader
    // to skim the block, and this block is the point of the whole report.
    if counts.native > 0 {
        out.push_str(&field("native", counts.native));
    }
    if counts.hybrid > 0 {
        out.push_str(&field("hybrid", counts.hybrid));
    }
    if counts.translated > 0 {
        out.push_str(&field("translated", counts.translated));
    }
    if counts.not_pe > 0 {
        out.push_str(&field("not an image", counts.not_pe));
    }
    if counts.kernel_driver > 0 {
        out.push_str(&field("kernel driver", counts.kernel_driver));
    }

    // Given their own section rather than a line in the summary, because the consequence is not
    // obvious from the numbers: a driver routes natively, so every architectural figure above
    // says "fine", and none of them says whether the destination can load it.
    //
    // The verdict depends on the destination, and stating it unconditionally was a defect: the
    // terminal summary told a Windows assessment to "expect a driver rewrite" while the HTML
    // report generated from the same run correctly listed those drivers as needing no work.
    // Two outputs of one analysis must not disagree.
    if counts.kernel_driver > 0 {
        out.push_str(&heading("Kernel drivers"));
        if report.target.loads_kernel_drivers(true) {
            out.push_str(&format!(
                "  {} image(s) import ntoskrnl.exe and are built for Arm64, so {} loads them\n \
                 \x20 as native kernel code. No port is needed.\n",
                counts.kernel_driver,
                report.target.id()
            ));
        } else {
            out.push_str(&format!(
                "  {} image(s) import ntoskrnl.exe, so they run in kernel mode, which {} cannot\n \
                 \x20 load: emulation covers user-mode code only. Their native route is correct\n \
                 \x20 and does not mean they will run here — expect a driver rewrite, not a port.\n",
                counts.kernel_driver,
                report.target.id()
            ));
        }
    }

    out.push_str(&heading("Will not run"));
    let intrinsic = counts.will_not_run();
    if intrinsic == 0 && counts.malformed == 0 {
        if counts.routed == 0 {
            // A conclusion drawn from no evidence. Saying "everything runs" about a directory
            // containing no images would be the most confidently wrong sentence in the report.
            out.push_str("  no Windows images were found, so nothing was decided\n");
        } else if counts.environment_refused > 0 {
            // THE case this section exists to get right.
            //
            // Every refusal was caused by this machine, so the scan learned nothing about the
            // images. Printing "none refused" here would read as a clean bill of health and
            // printing "refused" would read as a defect in the customer's software. Neither is
            // true, and both are worse than saying nothing.
            out.push_str(&format!(
                "  undetermined: all {} image(s) were refused for reasons about THIS machine\n",
                counts.environment_refused
            ));
            out.push_str(
                "  no NT system-call layer or translator was available here, so the images were\n \
                 \x20 never judged. Install the runtime, or declare one with --backends, and run\n \
                 \x20 the scan again before drawing a conclusion.\n",
            );
        } else {
            out.push_str(&format!(
                "  none of the {} image(s) examined was refused\n",
                counts.routed
            ));
        }
    } else {
        out.push_str(&field("will not run", intrinsic));
        if counts.malformed > 0 {
            out.push_str(&field("unparseable", counts.malformed));
        }
    }

    // Environmental refusals are reported separately from findings, and never folded into the
    // count above. A reader has to be able to see that a number describes the machine rather
    // than the software.
    if counts.environment_refused > 0 && intrinsic > 0 {
        out.push_str(&heading("Beyond this machine"));
        out.push_str(&field("refused", counts.environment_refused));
        out.push_str(
            "  these were refused because this machine lacks a runtime, not because of the\n \
             \x20 image itself; they are excluded from the count above\n",
        );
    } else if counts.environment_refused > 0 {
        out.push_str(&heading("Beyond this machine"));
        out.push_str(&field("refused", counts.environment_refused));
        out.push_str("  this machine lacks a runtime, so these images were not judged\n");
    }

    // Obstacles are separated from findings, and this is the distinction that keeps the report
    // honest: an unreadable file means the scan did not see everything, which is a problem with
    // the run rather than a result about the customer's software.
    if counts.unreadable > 0 {
        out.push_str(&heading("Not examined"));
        out.push_str(&field("unreadable", counts.unreadable));
        out.push_str("  these files were skipped, so the summary above is incomplete\n");
    }

    // Truncation is stated in the body, not only in the JSON, because a reader who trusts a
    // partial report will underestimate the work a migration needs.
    if report.truncated {
        out.push_str(&heading("Truncated"));
        out.push_str(&format!(
            "  {}\n",
            report
                .truncated_reason
                .as_deref()
                .unwrap_or("the scan stopped before the tree was exhausted")
        ));
    }

    let shown: Vec<&crate::scan::ScannedFile> = if all {
        report.files.iter().collect()
    } else {
        crate::scan::blocking(&report.files)
    };

    if !shown.is_empty() {
        out.push_str(&heading(if all {
            "Files"
        } else {
            "Files needing attention"
        }));
        for file in shown {
            out.push_str(&format!("  {:<48} {}\n", file.path, describe(&file.kind)));
        }
    }

    // Named, but under their own heading. An operator who saw seven refused files and no
    // explanation would reasonably suspect the scanner, and the list is what turns an alarming
    // number into an instruction: install the runtime and run the scan again.
    if !all {
        let beyond = crate::scan::beyond_this_machine(&report.files);
        if !beyond.is_empty() {
            out.push_str(&heading("Files not judged (this machine)"));
            for file in beyond {
                out.push_str(&format!("  {:<48} {}\n", file.path, describe(&file.kind)));
            }
        }
    }

    if !all && counts.unreadable > 0 {
        out.push_str(&heading("Files not examined"));
        for file in crate::scan::obstacles(&report.files) {
            out.push_str(&format!("  {:<48} {}\n", file.path, describe(&file.kind)));
        }
    }

    if all {
        // Grouped counts, so the route vocabulary is visible without reading every line.
        let grouped = crate::scan::by_route(&report.files);
        if !grouped.is_empty() {
            out.push_str(&heading("By route"));
            for (route, count) in grouped {
                out.push_str(&field(&route, count));
            }
        }
    }

    out
}

/// A one-line description of what happened to a file.
fn describe(kind: &ScanKind) -> String {
    match kind {
        ScanKind::Routed(routed) => {
            // A driver is named explicitly rather than shown as a bare `NATIVE`, because the
            // route is the one thing about it that is misleading. A reader scanning this column
            // for work to schedule must not see a kernel driver described as a clean native
            // image.
            if routed.is_kernel_driver {
                format!("{}  ({})  KERNEL DRIVER", routed.status, routed.route)
            } else {
                format!("{}  ({})", routed.status, routed.route)
            }
        }
        ScanKind::NotPe => "not-a-windows-image".to_owned(),
        ScanKind::Malformed { message } => format!("unparseable: {message}"),
        ScanKind::Unreadable { message } => format!("unreadable: {message}"),
    }
}

/// The machine-readable form of a scan.
///
/// `counts` is always complete; `files` respects `all`, because a JSON report over two thousand
/// files is usually wanted for its summary and its exceptions.
#[must_use]
pub fn scan_json(report: &ScanReport, all: bool) -> Value {
    let counts = report.counts;
    let counts_json = compitum_json::Object::new()
        .with("files_seen", counts.files_seen)
        .with("routed", counts.routed)
        // Emitted because every derived flag below depends on it, and a consumer cannot compute
        // it without knowing that `will_not_run` excludes environmental refusals. Making the
        // question "did this scan learn anything?" explicit is what stops a consumer reading an
        // unmeasured result as a clean one.
        .with("judged", counts.judged())
        .with("native", counts.native)
        .with("hybrid", counts.hybrid)
        .with("translated", counts.translated)
        .with("refused", counts.refused)
        // Emitted alongside `refused` so a consumer never has to re-derive the subtraction and
        // get the attribution wrong. `will_not_run` is the number a migration quotes; `refused`
        // is the router's raw count and includes refusals caused by the scanning machine.
        .with("environment_refused", counts.environment_refused)
        .with("will_not_run", counts.will_not_run())
        .with("not_pe", counts.not_pe)
        .with("malformed", counts.malformed)
        .with("unreadable", counts.unreadable)
        // Emitted because a consumer reading only the route would conclude a kernel driver is a
        // clean, cheap port. It routes natively and cannot be loaded by a user-mode layer, so
        // the machine-readable output has to carry the distinction the human report makes.
        .with("kernel_driver", counts.kernel_driver)
        // Derived booleans, emitted so a consumer does not have to re-derive the rules and get
        // the empty-tree and all-environmental cases wrong.
        .with("entirely_native", counts.is_entirely_native())
        .with(
            "inconclusive_about_the_images",
            counts.is_inconclusive_about_the_images(),
        );

    let selected: Vec<Value> = if all {
        report.files.iter().map(file_json).collect()
    } else {
        crate::scan::blocking(&report.files)
            .into_iter()
            .chain(crate::scan::obstacles(&report.files))
            .map(file_json)
            .collect()
    };

    compitum_json::Object::new()
        .with("root", report.root.as_str())
        .with("counts", counts_json)
        .with("truncated", report.truncated)
        .with("truncated_reason", report.truncated_reason.as_deref())
        .with("files", Value::Array(selected))
        .into()
}

/// One file as JSON.
fn file_json(file: &crate::scan::ScannedFile) -> Value {
    let mut object = compitum_json::Object::new()
        .with("path", file.path.as_str())
        .with("outcome", outcome_id(&file.kind));

    if let ScanKind::Routed(routed) = &file.kind {
        object.insert("abi_family", routed.abi_family.as_str());
        object.insert("route", routed.route.as_str());
        object.insert("status", routed.status.as_str());
        object.insert("blocked", routed.blocked);
        object.insert("fully_native", routed.fully_native);
        object.insert("confidence_permille", routed.confidence_permille);
        object.insert(
            "required_features",
            Value::Array(
                routed
                    .required_features
                    .iter()
                    .map(|id| Value::String(id.clone()))
                    .collect(),
            ),
        );
        object.insert("headline", routed.headline.as_str());
        // Per-file, because a report is read file by file when deciding what to schedule. A
        // driver listed as a plain native image would be scheduled as a cheap port.
        object.insert("is_kernel_driver", routed.is_kernel_driver);
    }

    match &file.kind {
        ScanKind::Malformed { message } | ScanKind::Unreadable { message } => {
            object.insert("message", message.as_str());
        }
        ScanKind::Routed(_) | ScanKind::NotPe => {}
    }

    object.into()
}

/// The stable identifier for an outcome, for JSON consumers.
fn outcome_id(kind: &ScanKind) -> &'static str {
    match kind {
        ScanKind::Routed(_) => "routed",
        ScanKind::NotPe => "not_pe",
        ScanKind::Malformed { .. } => "malformed",
        ScanKind::Unreadable { .. } => "unreadable",
    }
}

// ---------------------------------------------------------------------------
// port
// ---------------------------------------------------------------------------

/// Renders a port plan for a human reader.
///
/// # What this has to communicate, in this order
///
/// 1. **Whether anything can be done**, and if not, why not — in terms of what would actually go
///    wrong, because "unsupported architecture" tells a customer nothing they can act on.
/// 2. **Exactly which bytes change**, for a dry run. An operator approving an automatic rewrite
///    of their own binary is entitled to see the diff before it happens.
/// 3. **That the change is reversible and narrow**, because the whole objection to automatic
///    porting is that it silently breaks things.
#[must_use]
pub fn render_port(
    path: &str,
    verdict: &PortVerdict,
    translator: &Translator,
    applied: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("{} — {path}\n", translator.text("app.name")));

    match verdict {
        PortVerdict::Safe { edits, rationale } => {
            out.push_str(&heading("Port available"));
            out.push_str(&field("change", "metadata only"));
            out.push_str(&field("edits", edits.len()));
            out.push_str(&heading("Why this is safe"));
            out.push_str(&format!("  {rationale}\n"));

            out.push_str(&heading("What would change"));
            for edit in edits {
                let _ = writeln!(&mut out, "  {}", edit.describe());
            }
            // The hint must match what actually happened. Telling an operator who just ran
            // `--apply` to run `--apply` reads as though the command ignored them, which is the
            // worst impression an automatic patcher can give.
            match applied {
                Some(destination) => {
                    let _ = writeln!(
                        out,
                        "\n  Written to {destination}; the original was left untouched."
                    );
                }
                None => {
                    out.push_str(
                        "\n  Run with --apply to write the patched file; the original is left \
                         untouched.\n",
                    );
                }
            }
        }
        PortVerdict::AlreadyPortable { rationale } => {
            out.push_str(&heading("No port needed"));
            out.push_str(&field("state", "already portable"));
            out.push_str(&format!("  {rationale}\n"));
        }
        PortVerdict::Refused { reason, detail } => {
            out.push_str(&heading("Cannot be ported by patching"));
            out.push_str(&field("reason", *reason));
            out.push_str(&format!("  {detail}\n"));
            out.push_str(&heading("What that means"));
            out.push_str(
                "  A patch changes only metadata: flags and header fields. It cannot change \
                 machine code.\n \
                 \x20 Porting this file therefore needs a rebuild from source, or a \n \
                 \x20 recompiler — not this tool. Reporting it as portable would produce a \n \
                 \x20 binary that loads and then fails, which is worse than saying so now.\n",
            );
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use compitum_isa::{FeatureSet, IsaFeature};
    use compitum_pe::pe_fixture;
    use compitum_pe::pe_fixture::{machine, subsystem};
    use compitum_router::{decide, BackendSet, Request, Route};

    fn translator() -> Translator {
        Translator::english_only()
    }

    fn an_image() -> PeImage {
        compitum_pe::parse(&pe_fixture::synthetic(
            machine::ARM64,
            subsystem::CONSOLE,
            false,
        ))
        .unwrap()
    }

    fn a_plan() -> Plan {
        let host = HostProfile::synthetic(
            "aarch64",
            4096,
            8,
            FeatureSet::new()
                .with(IsaFeature::Fp)
                .with(IsaFeature::Asimd),
        );
        decide(&Request::new(an_image(), host, BackendSet::all()))
    }

    #[test]
    fn field_pads_a_stable_label_column() {
        let a = field("route", "native");
        let b = field("confidence", "100%");
        // Both values must begin at the same column, or a table cannot be scanned.
        assert_eq!(a.find("native"), b.find("100%"));
    }

    #[test]
    fn host_human_output_names_the_arch_and_page_size() {
        let host = HostProfile::synthetic(
            "aarch64",
            16384,
            8,
            FeatureSet::new().with(IsaFeature::Sve2),
        );
        let text = render_host(&host, &translator(), false);
        assert!(text.contains("aarch64"));
        assert!(text.contains("16384"));
        // A non-Windows page size must be called out as a compatibility question.
        assert!(text.contains("4 KiB"));
    }

    #[test]
    fn host_output_lists_missing_watched_features() {
        let host =
            HostProfile::synthetic("aarch64", 4096, 8, FeatureSet::new().with(IsaFeature::Fp));
        let text = render_host(&host, &translator(), false);
        // The absence of SME is the single most decision-relevant fact about most ARM64
        // phones, so it must appear.
        assert!(text.contains("sme"), "got:\n{text}");
    }

    #[test]
    fn host_json_is_valid_and_keyed() {
        let host = HostProfile::synthetic("aarch64", 4096, 8, FeatureSet::all());
        let text = render_host(&host, &translator(), true);
        let value = compitum_json::parse(&text).expect("must be valid JSON");
        assert_eq!(value["arch"].as_str(), Some("aarch64"));
        assert_eq!(value["page_size"].as_u64(), Some(4096));
    }

    #[test]
    fn inspect_human_output_states_the_execution_semantics() {
        let image = an_image();
        let text = render_inspect(&image, "app.exe", None, 1024, &translator(), false, false);
        assert!(text.contains("app.exe"));
        assert!(text.contains("arm64"));
        assert!(text.contains("windows_console"));
        // The plain-language meaning of the ABI family must always be shown.
        assert!(text.contains("directly executable") || text.contains("AArch64"));
    }

    #[test]
    fn inspect_verbose_shows_the_section_table() {
        let image = an_image();
        let brief = render_inspect(&image, "x", None, 1, &translator(), false, false);
        let verbose = render_inspect(&image, "x", None, 1, &translator(), false, true);
        assert!(verbose.len() > brief.len());
        assert!(verbose.contains(".text"));
        assert!(!brief.contains(".text  "));
    }

    #[test]
    fn inspect_json_round_trips_and_carries_the_family() {
        let image = an_image();
        let text = render_inspect(&image, "x", None, 42, &translator(), true, false);
        let value = compitum_json::parse(&text).unwrap();
        assert_eq!(value["abi_family"].as_str(), Some("arm64"));
        assert_eq!(value["subject_size"].as_u64(), Some(42));
        assert_eq!(value["is_dll"].as_bool(), Some(false));
        assert_eq!(value["headless_capable"].as_bool(), Some(true));
    }

    #[test]
    fn inspect_json_includes_the_digest_when_known() {
        let image = an_image();
        let digest = compitum_digest::sha256(b"x");
        let text = render_inspect(&image, "x", Some(&digest), 1, &translator(), true, false);
        let value = compitum_json::parse(&text).unwrap();
        assert_eq!(
            value["subject_sha256"].as_str(),
            Some(digest.to_hex().as_str())
        );
    }

    #[test]
    fn plan_human_output_shows_the_verdict_first() {
        let plan = a_plan();
        let text = render_plan(&plan, "app.exe", &translator(), false, false);
        assert!(text.contains("NATIVE"));
        assert!(text.contains("100%"));
        assert!(
            text.contains("none"),
            "a native route must report no emulation"
        );
        assert!(text.contains("app.exe"));
    }

    #[test]
    fn plan_human_output_hides_supporting_reasons_unless_verbose() {
        let plan = a_plan();
        let brief = render_plan(&plan, "x", &translator(), false, false);
        let verbose = render_plan(&plan, "x", &translator(), false, true);
        assert!(!brief.contains("architecture_native"));
        assert!(verbose.contains("architecture_native"));
        assert!(verbose.len() > brief.len());
    }

    #[test]
    fn blocked_plan_names_the_obstacle() {
        let host = HostProfile::synthetic(
            "aarch64",
            4096,
            8,
            FeatureSet::new()
                .with(IsaFeature::Fp)
                .with(IsaFeature::Asimd),
        );
        let requirements = vec![compitum_isa::Requirement::new(
            IsaFeature::Sme,
            compitum_isa::RequirementSource::Metadata,
            None,
            "matrix use",
        )];
        let plan = decide(
            &Request::new(an_image(), host, BackendSet::all()).with_requirements(requirements),
        );
        assert_eq!(plan.route, Route::Refused);
        let text = render_plan(&plan, "x", &translator(), false, false);
        assert!(text.contains("REFUSED"));
        assert!(
            text.contains("sme"),
            "the missing feature must be named:\n{text}"
        );
    }

    #[test]
    fn plan_json_is_the_canonical_protocol_document() {
        let plan = a_plan();
        let text = render_plan(&plan, "x", &translator(), true, false);
        let value = compitum_json::parse(&text).unwrap();
        // These key names are protocol: they appear in Oracle records and must not drift.
        assert_eq!(value["route"].as_str(), Some("native"));
        assert_eq!(value["schema_version"].as_u64(), Some(1));
        assert!(value["reasons"].as_array().is_some());
    }

    #[test]
    fn ledger_summary_reports_counts_and_flags_unreadable_lines() {
        let summary = compitum_json::Object::new()
            .with("ledger_path", "/tmp/x.jsonl")
            .with("total_records", 3u64)
            .with("distinct_subjects", 2u64)
            .with("determined_outcomes", 1u64)
            .with("unreadable_lines", 2u64)
            .with(
                "by_route",
                vec![Value::from(
                    compitum_json::Object::new()
                        .with("route", "native")
                        .with("count", 3u64),
                )],
            )
            .with("by_outcome", Vec::<Value>::new())
            .with("by_host_class", Vec::<Value>::new())
            .into();
        let text = render_ledger_summary(&summary, &translator(), false);
        assert!(text.contains("/tmp/x.jsonl"));
        assert!(text.contains("could not be read"));
        assert!(text.contains("native"));
    }

    #[test]
    fn locale_listing_explains_how_to_add_a_language() {
        let text = render_locales("en", &[], &translator(), false);
        assert!(text.contains("locales/"));
        assert!(text.contains("COMPITUM_LOCALES"));
    }

    #[test]
    fn locale_listing_marks_the_active_one() {
        let available = vec![
            ("en".to_owned(), 100u32, "English".to_owned()),
            ("fa".to_owned(), 42, "Persian".to_owned()),
        ];
        let text = render_locales("fa", &available, &translator(), false);
        assert!(text.contains("*fa"));
        assert!(text.contains("42%"));
        assert!(text.contains("Persian"));
    }

    #[test]
    fn locale_json_is_machine_readable() {
        let available = vec![("fa".to_owned(), 42u32, "Persian".to_owned())];
        let text = render_locales("en", &available, &translator(), true);
        let value = compitum_json::parse(&text).unwrap();
        assert_eq!(value["active"].as_str(), Some("en"));
        assert_eq!(value["count"].as_u64(), Some(1));
        assert_eq!(
            value["locales"].as_array().unwrap()[0]["tag"].as_str(),
            Some("fa")
        );
    }

    #[test]
    fn locale_check_lists_gaps_and_says_when_complete() {
        let text = render_locale_check(
            "fa",
            40,
            &["a.b".to_owned()],
            &["old.key".to_owned()],
            &translator(),
            false,
        );
        assert!(text.contains("40%"));
        assert!(text.contains("a.b"));
        assert!(text.contains("old.key"));

        let complete = render_locale_check("fa", 100, &[], &[], &translator(), false);
        assert!(complete.contains("complete"));
    }
}
