//! The deliverable: a migration report a customer can read, archive and act on.
//!
//! # What this file is for
//!
//! Everything else in this workspace produces *analysis*. This produces the **artefact** — the
//! document a consultant hands to a customer's technical lead, and the one an auditor is asked
//! to produce a year later when they want to know what was actually said.
//!
//! That changes the requirements completely. A terminal summary is read once, by the person who
//! ran the command. A delivered report is read by people who did not run it, forwarded to people
//! who have never heard of the tool, and filed. So it has to stand alone.
//!
//! # The four decisions that shape it
//!
//! **Self-contained, with no external anything.** No font, no script, no stylesheet, no image,
//! no tracker. A report is opened on an air-gapped machine, stored in a document management
//! system, or e-mailed as an attachment, and any of those turns an external reference into a
//! broken page or a leak. The whole document is one file with inline CSS and no JavaScript at
//! all — which also means there is nothing in it that can fail to run.
//!
//! **The number that decides the project comes first.** A migration is scoped from "how much of
//! this is already done". So the first thing on the page is the count of images that need no
//! work, expressed as a fraction of those that were actually judged, and not of everything on
//! disk — a `README.md` is not a migration task.
//!
//! **Four actions, because "will it run" is not what a customer acts on.** They act on "nothing
//! to do", "rebuild", "rewrite", "unknown". Those are different budgets, different teams and
//! different timelines, and a report that merged them would be accurate and useless.
//!
//! **Every limitation is stated in the document.** Truncation, unreadable files, an environment
//! that could not measure, the bounds of static analysis. A report that hides its own blind
//! spots is worse than one that does not exist, because the reader cannot tell what it did not
//! check.
//!
//! # Escaping
//!
//! Every string that reaches the document is escaped. Filenames are customer input, so they are
//! untrusted: a file called `<script>.exe` must not be able to run code in the document that
//! reports on it. That is not a hypothetical — archives extracted from the internet routinely
//! contain hostile names, and a report generator is exactly where they would be displayed.

use std::fmt::Write as _;

use compitum_router::MigrationTarget;

use crate::scan::{ScanKind, ScanReport, ScannedFile};

/// What the customer has to do about one file.
///
/// Deliberately four, and deliberately not the route names. A route answers "how does this
/// execute"; an action answers "what does this cost me". They are different questions with
/// different audiences, and the second is the one a migration is planned from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    /// Runs natively on the destination. No work at all.
    Ready,
    /// Runs, but under the destination's own emulator. Rebuilding for Arm64 removes that cost.
    Rebuild,
    /// Cannot load on the destination and has to be rewritten rather than rebuilt.
    Rewrite,
    /// The analysis could not decide, because something about the *environment* was missing.
    ///
    /// Kept separate from [`Action::Rewrite`] because it is not a finding about the software,
    /// and a report that presented it as one would be wrong in the direction that costs a
    /// customer the most.
    Unknown,
    /// Not a Windows image, so not a migration task.
    NotApplicable,
    /// A Windows image that could not be parsed — corrupt or unsupported.
    Unusable,
}

impl Action {
    /// A short heading suitable for a section or a table column.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Action::Ready => "No work needed",
            Action::Rebuild => "Rebuild for Arm64",
            Action::Rewrite => "Rewrite or replace",
            Action::Unknown => "Not determined",
            Action::NotApplicable => "Not a Windows image",
            Action::Unusable => "Unusable",
        }
    }

    /// One sentence saying what the action means and why.
    #[must_use]
    pub fn explanation(self) -> &'static str {
        match self {
            Action::Ready => {
                "Executes natively on the destination. No instruction is translated, so there \
                 is nothing to port."
            }
            Action::Rebuild => {
                "Runs today only because the destination emulates its architecture. Every \
                 instruction is translated, so it works but pays a performance cost that a \
                 rebuild for Arm64 removes."
            }
            Action::Rewrite => {
                "Cannot run on the destination at all. Emulation covers user-mode code only, so \
                 a kernel component must be rebuilt for Arm64, and an unsupported architecture \
                 has no route anywhere."
            }
            Action::Unknown => {
                "The analysis could not decide, because a component needed to answer was not \
                 present where the report was produced. This is a limitation of the audit, not \
                 a verdict about the software."
            }
            Action::NotApplicable => {
                "Not a Windows executable or library, so it is not part of the migration."
            }
            Action::Unusable => {
                "A Windows image that could not be read or parsed. It may be corrupt, or it may \
                 use a layout this analyser does not understand."
            }
        }
    }

    /// The stable identifier used in the CSV and in anchors.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Action::Ready => "ready",
            Action::Rebuild => "rebuild",
            Action::Rewrite => "rewrite",
            Action::Unknown => "unknown",
            Action::NotApplicable => "not-applicable",
            Action::Unusable => "unusable",
        }
    }

    /// Every action, in the order a report presents them: good news first, then work, then gaps.
    pub const ALL: &'static [Action] = &[
        Action::Ready,
        Action::Rebuild,
        Action::Rewrite,
        Action::Unknown,
        Action::Unusable,
        Action::NotApplicable,
    ];

    /// `true` when this action counts towards the migration's scope.
    ///
    /// A non-Windows file does not: it is not a task, and including it would dilute the
    /// denominator and make every migration look further from done than it is.
    #[must_use]
    pub fn is_in_scope(self) -> bool {
        !matches!(self, Action::NotApplicable)
    }
}

/// The action for one file against one destination.
#[must_use]
pub fn action_for(file: &ScannedFile, target: MigrationTarget) -> Action {
    match &file.kind {
        ScanKind::NotPe => Action::NotApplicable,
        ScanKind::Malformed { .. } => Action::Unusable,
        ScanKind::Unreadable { .. } => Action::Unknown,
        ScanKind::Routed(routed) => {
            // An environment refusal first: it is the one case where the route says "refused"
            // and the truth is "not measured". Reporting it as Rewrite would blame the
            // customer's software for a missing component on the audit machine.
            if routed.blocked && routed.environment_blocked {
                return Action::Unknown;
            }
            if routed.blocked {
                return Action::Rewrite;
            }
            // A kernel driver that the destination can load is Ready; one it cannot is Rewrite.
            // The route cannot express this because the route is correct: an Arm64 driver
            // routes natively and still cannot be loaded by a user-mode layer.
            if routed.is_kernel_driver && !target.loads_kernel_drivers(true) {
                return Action::Rewrite;
            }
            if routed.fully_native {
                return Action::Ready;
            }
            // `destination_emulates` and the translator routes both mean "works, but translated".
            Action::Rebuild
        }
    }
}

/// Counts per action, in [`Action::ALL`] order.
#[must_use]
pub fn action_counts(report: &ScanReport) -> Vec<(Action, usize)> {
    Action::ALL
        .iter()
        .map(|action| {
            let count = report
                .files
                .iter()
                .filter(|file| action_for(file, report.target) == *action)
                .count();
            (*action, count)
        })
        .collect()
}

/// How many files are in scope for the migration.
#[must_use]
pub fn in_scope(report: &ScanReport) -> usize {
    report
        .files
        .iter()
        .filter(|file| action_for(file, report.target).is_in_scope())
        .count()
}

/// How many files a determination was actually reached about.
///
/// # Why this is not the same as [`in_scope`]
///
/// A file whose verdict is [`Action::Unknown`] is in scope — it is a Windows image and part of
/// the migration — but nothing was decided about it. Readiness must be a fraction of what was
/// *judged*, not of what was *found*.
///
/// With the wider denominator, a tree where the analysis learned nothing at all reports "0%
/// ready", which reads as "the migration has not started". That is a confident statement about
/// something nobody examined, and it arrives precisely when the environment was inadequate —
/// which is when a wrong number does the most damage, because the customer would commission work
/// based on a failure of the audit rather than a property of their own software.
#[must_use]
pub fn determined(report: &ScanReport) -> usize {
    report
        .files
        .iter()
        .filter(|file| {
            matches!(
                action_for(file, report.target),
                Action::Ready | Action::Rebuild | Action::Rewrite
            )
        })
        .count()
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

/// Renders the report as CSV, one row per file.
///
/// # Why CSV and not only HTML
///
/// A customer's engineering team does not plan work from a document; they import a list into a
/// tracker or a spreadsheet. The HTML report is the artefact that gets signed, and the CSV is
/// the one that gets worked from.
///
/// Quoting follows RFC 4180: a field containing a comma, a quote or a newline is enclosed in
/// double quotes with any internal quote doubled. A filename may legally contain all three, and
/// getting this wrong silently corrupts the row rather than failing loudly.
#[must_use]
pub fn render_csv(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("path,action,status,route,abi_family,kernel_driver,confidence_permille,detail\n");

    for file in &report.files {
        let action = action_for(file, report.target);
        let (status, route, family, driver, confidence, detail) = match &file.kind {
            ScanKind::Routed(routed) => (
                routed.status.as_str(),
                routed.route.as_str(),
                routed.abi_family.as_str(),
                if routed.is_kernel_driver { "yes" } else { "no" },
                routed.confidence_permille.to_string(),
                routed.headline.clone(),
            ),
            ScanKind::NotPe => ("NOT_PE", "", "", "no", String::new(), String::new()),
            ScanKind::Malformed { message } => {
                ("MALFORMED", "", "", "no", String::new(), message.clone())
            }
            ScanKind::Unreadable { message } => {
                ("UNREADABLE", "", "", "no", String::new(), message.clone())
            }
        };

        let fields = [
            file.path.clone(),
            action.id().to_owned(),
            status.to_owned(),
            route.to_owned(),
            family.to_owned(),
            driver.to_owned(),
            confidence,
            detail,
        ];
        let quoted: Vec<String> = fields.iter().map(|field| csv_field(field)).collect();
        out.push_str(&quoted.join(","));
        out.push('\n');
    }

    out
}

/// Quotes one CSV field when RFC 4180 requires it.
fn csv_field(value: &str) -> String {
    let needs =
        value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r');
    if !needs {
        return value.to_owned();
    }
    format!("\"{}\"", value.replace('"', "\"\""))
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

/// Escapes text for HTML.
///
/// Applied to every value that reaches the document. Filenames are customer input and therefore
/// untrusted: an archive extracted from the internet can contain a file named
/// `<script>alert(1)</script>.exe`, and a report generator is exactly where such a name gets
/// displayed.
#[must_use]
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Formats a percentage from a numerator and denominator, refusing to invent one.
///
/// Returns `None` when the denominator is zero. "0 of 0 already done" is not 0% and it is not
/// 100% — it is a question that was not asked, and a report must not answer it.
#[must_use]
pub fn percent(part: usize, whole: usize) -> Option<u32> {
    if whole == 0 {
        return None;
    }
    // Integer arithmetic; a migration report does not need a fraction of a percent and rounding
    // here avoids a float that could print as 33.000000000000004.
    Some(((part.saturating_mul(100)) / whole) as u32)
}

/// Renders a complete, self-contained HTML report.
///
/// `generated_at` is passed in rather than read from the clock, so the output is a pure function
/// of its inputs and a test can assert on the exact bytes. A report that embeds the current time
/// cannot be diffed, and diffing two reports is how a migration is tracked over time.
#[must_use]
pub fn render_html(report: &ScanReport, generated_at: &str, version: &str) -> String {
    let counts = action_counts(report);
    let total_in_scope = in_scope(report);
    let ready = counts
        .iter()
        .find(|(action, _)| *action == Action::Ready)
        .map(|(_, count)| *count)
        .unwrap_or(0);
    let rebuild = counts
        .iter()
        .find(|(action, _)| *action == Action::Rebuild)
        .map(|(_, count)| *count)
        .unwrap_or(0);
    let rewrite = counts
        .iter()
        .find(|(action, _)| *action == Action::Rewrite)
        .map(|(_, count)| *count)
        .unwrap_or(0);
    let unknown = counts
        .iter()
        .find(|(action, _)| *action == Action::Unknown)
        .map(|(_, count)| *count)
        .unwrap_or(0);

    let mut doc = String::with_capacity(16_384);

    doc.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    doc.push_str("<meta charset=\"utf-8\">\n");
    doc.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    doc.push_str(&format!(
        "<title>Arm64 migration assessment — {}</title>\n",
        escape(&report.root)
    ));
    doc.push_str(&format!(
        "<meta name=\"generator\" content=\"COMPITUM {}\">\n",
        escape(version)
    ));
    doc.push_str(&format!(
        "<meta name=\"description\" content=\"Readiness of {} file(s) under {} for {}\">\n",
        report.files.len(),
        escape(&report.root),
        escape(report.target.id())
    ));
    doc.push_str(STYLE);
    doc.push_str("</head>\n<body>\n<main>\n");

    // ---- Header ----------------------------------------------------------
    doc.push_str("<header>\n");
    doc.push_str("<p class=\"eyebrow\">Arm64 migration assessment</p>\n");
    doc.push_str(&format!("<h1>{}</h1>\n", escape(&report.root)));
    doc.push_str("<dl class=\"meta\">\n");
    let _ = writeln!(
        doc,
        "<div><dt>Destination</dt><dd>{} <span class=\"muted\">({})</span></dd></div>",
        escape(report.target.id()),
        escape(report.target.description())
    );
    let _ = writeln!(
        doc,
        "<div><dt>Produced</dt><dd>{}</dd></div>",
        escape(generated_at)
    );
    let _ = writeln!(
        doc,
        "<div><dt>Analyser</dt><dd>COMPITUM {}</dd></div>",
        escape(version)
    );
    let _ = writeln!(
        doc,
        "<div><dt>Files examined</dt><dd>{}</dd></div>",
        report.files.len()
    );
    doc.push_str("</dl>\n</header>\n");

    // ---- Headline --------------------------------------------------------
    doc.push_str("<section class=\"headline\" aria-labelledby=\"headline-h\">\n");
    doc.push_str("<h2 id=\"headline-h\">Readiness</h2>\n");
    match percent(ready, determined(report)) {
        Some(pct) => {
            let _ = writeln!(
                doc,
                "<p class=\"big\"><strong>{pct}%</strong> <span class=\"of\">of judged files need no work</span></p>\n\
                 <p class=\"sub\">{} of {} judged file(s) already run natively on the destination.</p>",
                ready,
                determined(report)
            );
        }
        None => {
            doc.push_str(
                "<p class=\"big unavailable\">Not determinable</p>\n\
                 <p class=\"sub\">No Windows image in this tree was judged, so readiness cannot be stated. \
                 See “Limitations” below.</p>\n",
            );
        }
    }
    doc.push_str("</section>\n");

    // ---- Scorecard -------------------------------------------------------
    doc.push_str(
        "<section aria-labelledby=\"score-h\">\n<h2 id=\"score-h\">What has to happen</h2>\n",
    );
    doc.push_str("<table class=\"score\">\n<thead><tr><th scope=\"col\">Action</th><th scope=\"col\" class=\"num\">Files</th><th scope=\"col\">Meaning</th></tr></thead>\n<tbody>\n");
    for (action, count) in &counts {
        if *action == Action::NotApplicable || *count == 0 {
            continue;
        }
        let _ = writeln!(
            doc,
            "<tr class=\"row-{}\"><th scope=\"row\"><span class=\"badge b-{}\">{}</span></th>\
             <td class=\"num\">{}</td><td>{}</td></tr>",
            action.id(),
            action.id(),
            escape(action.title()),
            count,
            escape(action.explanation())
        );
    }
    // Not-applicable is summarised rather than listed: it is a non-finding.
    if let Some((_, count)) = counts
        .iter()
        .find(|(action, _)| *action == Action::NotApplicable)
    {
        if *count > 0 {
            let _ = writeln!(
                doc,
                "<tr class=\"row-muted\"><th scope=\"row\"><span class=\"badge b-na\">Not a Windows image</span></th>\
                 <td class=\"num\">{}</td><td>{}</td></tr>",
                count,
                escape(Action::NotApplicable.explanation())
            );
        }
    }
    doc.push_str("</tbody>\n</table>\n</section>\n");

    // ---- Limitations before detail ---------------------------------------
    //
    // Deliberately placed above the file list. A reader who stops scrolling has to have seen
    // what the report could not establish; putting it at the bottom is how caveats get skipped.
    let mut limitations: Vec<String> = Vec::new();
    if report.truncated {
        limitations.push(format!(
            "The scan stopped before the tree was exhausted: {}",
            escape(
                report
                    .truncated_reason
                    .as_deref()
                    .unwrap_or("a limit was reached")
            )
        ));
    }
    if unknown > 0 {
        limitations.push(format!(
            "{unknown} file(s) could not be judged because a component needed to answer was \
             absent where this report was produced. Their verdict is unknown, not negative."
        ));
    }
    let unreadable = counts
        .iter()
        .find(|(action, _)| *action == Action::Unusable)
        .map(|(_, count)| *count)
        .unwrap_or(0);
    if unreadable > 0 {
        limitations.push(format!(
            "{unreadable} Windows image(s) could not be parsed, so they are reported as unusable \
             rather than judged."
        ));
    }
    limitations.push(
        "Static analysis reads the file's structure and instruction encodings. It cannot see \
         code generated at run time, and a rare encoding can appear by coincidence inside data \
         held in an executable section."
            .to_owned(),
    );
    if report.target == MigrationTarget::LinuxWithWine {
        limitations.push(
            "This assessment was made for Linux with Wine, not for Windows on Arm. Pass \
             --target windows-on-arm for the destination a migration usually has in mind."
                .to_owned(),
        );
    }

    doc.push_str("<section class=\"limits\" aria-labelledby=\"limits-h\">\n<h2 id=\"limits-h\">Limitations</h2>\n<ul>\n");
    for limitation in &limitations {
        let _ = writeln!(doc, "<li>{limitation}</li>");
    }
    doc.push_str("</ul>\n</section>\n");

    // ---- Per-action detail ------------------------------------------------
    for action in Action::ALL {
        if *action == Action::NotApplicable {
            continue;
        }
        let items: Vec<&ScannedFile> = report
            .files
            .iter()
            .filter(|file| action_for(file, report.target) == *action)
            .collect();
        if items.is_empty() {
            continue;
        }

        let _ = writeln!(
            doc,
            "<section class=\"detail\" aria-labelledby=\"h-{}\">\n<h2 id=\"h-{}\">{} <span class=\"count\">({})</span></h2>\n<p class=\"lede\">{}</p>",
            action.id(),
            action.id(),
            escape(action.title()),
            items.len(),
            escape(action.explanation())
        );

        doc.push_str("<table class=\"files\">\n<thead><tr>");
        doc.push_str("<th scope=\"col\">File</th><th scope=\"col\">Architecture</th><th scope=\"col\">Route</th><th scope=\"col\">Why</th>");
        doc.push_str("</tr></thead>\n<tbody>\n");
        for file in &items {
            let (family, route, why) = match &file.kind {
                ScanKind::Routed(routed) => (
                    routed.abi_family.clone(),
                    routed.route.clone(),
                    routed.headline.clone(),
                ),
                ScanKind::Malformed { message } => {
                    ("—".to_owned(), "malformed".to_owned(), message.clone())
                }
                ScanKind::Unreadable { message } => {
                    ("—".to_owned(), "unreadable".to_owned(), message.clone())
                }
                ScanKind::NotPe => ("—".to_owned(), "not-pe".to_owned(), String::new()),
            };
            let driver = match &file.kind {
                ScanKind::Routed(routed) if routed.is_kernel_driver => {
                    " <span class=\"tag\">kernel driver</span>"
                }
                _ => "",
            };
            let _ = writeln!(
                doc,
                "<tr><td class=\"path\"><code>{}</code>{}</td><td>{}</td><td><code>{}</code></td><td class=\"why\">{}</td></tr>",
                escape(&file.path),
                driver,
                escape(&family),
                escape(&route),
                escape(&why)
            );
        }
        doc.push_str("</tbody>\n</table>\n</section>\n");
    }

    // ---- Footer ----------------------------------------------------------
    doc.push_str("<footer>\n");
    let _ = writeln!(
        doc,
        "<p>Produced by COMPITUM {} for destination <code>{}</code>. This document is \
         self-contained: it loads nothing from the network and contains no executable content.</p>",
        escape(version),
        escape(report.target.id())
    );
    let _ = writeln!(
        doc,
        "<p class=\"muted\">Counts: {} ready, {} to rebuild, {} to rewrite, {} undetermined, \
         {} out of scope.</p>",
        ready,
        rebuild,
        rewrite,
        unknown,
        report.files.len().saturating_sub(total_in_scope)
    );
    doc.push_str("</footer>\n</main>\n</body>\n</html>\n");

    doc
}

/// The stylesheet, inline.
///
/// System font stack only, no web fonts: a report must render identically on a machine with no
/// network and no installed families. Print rules come first in spirit — this document's primary
/// destination is a PDF attached to a decision.
const STYLE: &str = r#"<style>
:root{
  --ink:#14161a; --muted:#5b6470; --rule:#e2e6ec; --bg:#ffffff; --wash:#f7f9fc;
  --ready:#0f7b4f; --ready-bg:#e8f6ef;
  --rebuild:#8a5300; --rebuild-bg:#fdf3e2;
  --rewrite:#a32020; --rewrite-bg:#fdecec;
  --unknown:#3d4a5c; --unknown-bg:#eef1f6;
  --unusable:#6b2d5c; --unusable-bg:#f7ecf4;
  --na:#6b7280; --na-bg:#f3f4f6;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; background:var(--bg); color:var(--ink);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  font-size:15px; line-height:1.6;
}
main{max-width:60rem;margin:0 auto;padding:2.5rem 1.5rem 4rem}
h1{font-size:1.9rem;line-height:1.2;margin:.2rem 0 .9rem;letter-spacing:-.02em;word-break:break-word}
h2{font-size:1.15rem;margin:2.6rem 0 .6rem;letter-spacing:-.01em}
p{margin:.6rem 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.86em}
.muted,.of{color:var(--muted);font-weight:400}
.eyebrow{text-transform:uppercase;letter-spacing:.09em;font-size:.72rem;color:var(--muted);margin:0}
header{border-bottom:2px solid var(--ink);padding-bottom:1.2rem}
dl.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));gap:.9rem 1.6rem;margin:1.2rem 0 0}
dl.meta div{margin:0}
dl.meta dt{font-size:.7rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}
dl.meta dd{margin:.1rem 0 0;font-size:.9rem}
.headline{margin-top:2rem;padding:1.4rem 1.6rem;background:var(--wash);border:1px solid var(--rule);border-radius:8px}
.headline h2{margin:0 0 .3rem;font-size:.72rem;text-transform:uppercase;letter-spacing:.09em;color:var(--muted)}
.big{margin:.1rem 0 .3rem;font-size:1.05rem}
.big strong{font-size:2.6rem;line-height:1;letter-spacing:-.03em;vertical-align:-.08em}
.big.unavailable{font-size:1.5rem;font-weight:600;color:var(--unknown)}
.sub{margin:0;color:var(--muted);font-size:.9rem}
table{width:100%;border-collapse:collapse;margin:.8rem 0 0;font-size:.9rem}
th,td{text-align:left;vertical-align:top;padding:.55rem .7rem;border-bottom:1px solid var(--rule)}
thead th{font-size:.7rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);border-bottom:1px solid var(--ink);white-space:nowrap}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
table.score td:nth-child(3){color:var(--muted);font-size:.86rem}
table.files td.path{max-width:22rem;word-break:break-all}
table.files td.why{color:var(--muted);font-size:.84rem}
tbody tr:last-child td,tbody tr:last-child th{border-bottom:1px solid var(--rule)}
.badge{display:inline-block;padding:.12rem .5rem;border-radius:999px;font-size:.78rem;font-weight:600;white-space:nowrap}
.b-ready{background:var(--ready-bg);color:var(--ready)}
.b-rebuild{background:var(--rebuild-bg);color:var(--rebuild)}
.b-rewrite{background:var(--rewrite-bg);color:var(--rewrite)}
.b-unknown{background:var(--unknown-bg);color:var(--unknown)}
.b-unusable{background:var(--unusable-bg);color:var(--unusable)}
.b-na{background:var(--na-bg);color:var(--na)}
.row-muted td,.row-muted th{color:var(--muted)}
.tag{display:inline-block;margin-left:.35rem;padding:.05rem .4rem;border:1px solid var(--rule);border-radius:4px;font-size:.7rem;color:var(--muted);white-space:nowrap}
.limits{background:var(--rebuild-bg);border:1px solid #e8d5b0;border-radius:8px;padding:.4rem 1.4rem 1rem}
.limits h2{color:var(--rebuild)}
.limits ul{margin:.4rem 0 0;padding-left:1.1rem}
.limits li{margin:.35rem 0;font-size:.88rem}
.lede{color:var(--muted);font-size:.88rem;margin:.2rem 0 0}
.count{color:var(--muted);font-weight:400}
footer{margin-top:3.5rem;padding-top:1.2rem;border-top:1px solid var(--rule);font-size:.82rem;color:var(--muted)}
@media print{
  body{font-size:10.5pt}
  main{max-width:none;padding:0}
  .headline,.limits{break-inside:avoid}
  section.detail{break-before:auto}
  table.files tr{break-inside:avoid}
  thead{display:table-header-group}
  a{color:inherit;text-decoration:none}
}
</style>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{RoutedFile, ScanReport};

    fn routed(
        path: &str,
        route: &str,
        blocked: bool,
        native: bool,
        driver: bool,
        environment: bool,
    ) -> ScannedFile {
        ScannedFile {
            path: path.to_owned(),
            kind: ScanKind::Routed(Box::new(RoutedFile {
                abi_family: "arm64".to_owned(),
                route: route.to_owned(),
                status: if blocked { "REFUSED" } else { "NATIVE" }.to_owned(),
                blocked,
                fully_native: native,
                confidence_permille: 1000,
                required_features: Vec::new(),
                headline: "test".to_owned(),
                blockers: Vec::new(),
                environment_blocked: environment,
                is_kernel_driver: driver,
            })),
        }
    }

    fn report(files: Vec<ScannedFile>, target: MigrationTarget) -> ScanReport {
        let counts = crate::scan::count(&files);
        ScanReport {
            root: "dist".to_owned(),
            target,
            files,
            counts,
            truncated: false,
            truncated_reason: None,
        }
    }

    #[test]
    fn a_native_image_needs_no_work() {
        let file = routed("a.exe", "native", false, true, false, false);
        assert_eq!(
            action_for(&file, MigrationTarget::WindowsOnArm),
            Action::Ready
        );
    }

    #[test]
    fn an_emulated_image_must_be_rebuilt_not_rewritten() {
        // The distinction a migration budget depends on: it works today, so this is an
        // optimisation, not a rescue.
        let file = routed(
            "old.exe",
            "destination_emulates",
            false,
            false,
            false,
            false,
        );
        assert_eq!(
            action_for(&file, MigrationTarget::WindowsOnArm),
            Action::Rebuild
        );
    }

    #[test]
    fn an_environment_refusal_is_unknown_not_a_rewrite() {
        // THE case that would otherwise libel the customer's software. A refusal caused by the
        // audit machine says nothing about the binary.
        let file = routed("a.exe", "refused", true, false, false, true);
        assert_eq!(
            action_for(&file, MigrationTarget::WindowsOnArm),
            Action::Unknown
        );
    }

    #[test]
    fn an_intrinsic_refusal_is_a_rewrite() {
        let file = routed("ia64.exe", "refused", true, false, false, false);
        assert_eq!(
            action_for(&file, MigrationTarget::WindowsOnArm),
            Action::Rewrite
        );
    }

    #[test]
    fn a_kernel_driver_is_ready_on_windows_and_a_rewrite_on_linux() {
        // The route is identical in both cases — native — so only the action can say that one
        // of them cannot load at all.
        let driver = routed("wineusb.sys", "native", false, true, true, false);
        assert_eq!(
            action_for(&driver, MigrationTarget::WindowsOnArm),
            Action::Ready,
            "an Arm64 driver is native kernel code on Windows on Arm"
        );
        assert_eq!(
            action_for(&driver, MigrationTarget::LinuxWithWine),
            Action::Rewrite,
            "no Windows driver loads on Linux at any architecture"
        );
    }

    #[test]
    fn a_non_image_is_out_of_scope_rather_than_a_task() {
        let file = ScannedFile {
            path: "README.md".to_owned(),
            kind: ScanKind::NotPe,
        };
        assert_eq!(
            action_for(&file, MigrationTarget::WindowsOnArm),
            Action::NotApplicable
        );
        assert!(!Action::NotApplicable.is_in_scope());
    }

    #[test]
    fn readiness_excludes_files_that_are_not_migration_tasks() {
        // The denominator must be the work, not everything on disk. A tree of one binary and
        // ninety-nine READMEs is a migration that is either done or not — not 1%.
        let files = vec![
            routed("a.exe", "native", false, true, false, false),
            ScannedFile {
                path: "README.md".to_owned(),
                kind: ScanKind::NotPe,
            },
            ScannedFile {
                path: "notes.txt".to_owned(),
                kind: ScanKind::NotPe,
            },
        ];
        let report = report(files, MigrationTarget::WindowsOnArm);
        assert_eq!(in_scope(&report), 1);
        assert_eq!(percent(1, in_scope(&report)), Some(100));
    }

    #[test]
    fn a_percentage_from_no_data_is_none_not_zero() {
        // "0 of 0 done" answers a question nobody asked. Reporting 0% would say the migration
        // is untouched; reporting 100% would say it is finished.
        assert_eq!(percent(0, 0), None);
        assert_eq!(percent(5, 0), None);
    }

    #[test]
    fn percentage_uses_integer_arithmetic() {
        assert_eq!(percent(1, 3), Some(33));
        assert_eq!(percent(2, 3), Some(66));
        assert_eq!(percent(3, 3), Some(100));
        assert_eq!(percent(0, 7), Some(0));
    }

    #[test]
    fn a_hostile_filename_cannot_inject_markup() {
        // Archives from the internet contain names like this, and the report is where they get
        // displayed. Untrusted input must never become executable content.
        let hostile = r#"<script>alert('x')</script>.exe"#;
        let files = vec![routed(hostile, "native", false, true, false, false)];
        let html = render_html(
            &report(files, MigrationTarget::WindowsOnArm),
            "2026-10-19",
            "0.1.0",
        );

        assert!(
            !html.contains("<script>alert"),
            "script tag survived escaping"
        );
        assert!(!html.contains("</script>.exe"), "raw tag survived");
        assert!(
            html.contains("&lt;script&gt;"),
            "the name must still be readable"
        );
    }

    #[test]
    fn every_escaped_character_is_covered() {
        assert_eq!(escape("<&>\"'"), "&lt;&amp;&gt;&quot;&#39;");
        assert_eq!(escape("plain"), "plain");
    }

    #[test]
    fn the_document_is_self_contained() {
        let files = vec![routed("a.exe", "native", false, true, false, false)];
        let html = render_html(
            &report(files, MigrationTarget::WindowsOnArm),
            "2026-10-19",
            "0.1.0",
        );
        // No external resource of any kind: no fetch, no font, no image, no script. A report is
        // opened air-gapped, filed, and e-mailed, and each of those breaks an external reference.
        for forbidden in [
            "<script", "http://", "https://", "<link", "@import", "<img", "src=",
        ] {
            assert!(
                !html.contains(forbidden),
                "the report must not contain `{forbidden}`"
            );
        }
        assert!(html.contains("<style>"), "styles must be inline");
    }

    #[test]
    fn limitations_are_stated_before_the_file_detail() {
        // A reader who stops scrolling has to have seen what could not be established. Putting
        // caveats below a thousand rows is how they get skipped.
        let files = vec![routed("blocked.exe", "refused", true, false, false, true)];
        let html = render_html(
            &report(files, MigrationTarget::WindowsOnArm),
            "2026-10-19",
            "0.1.0",
        );
        let limits = html.find("Limitations").expect("a limitations section");
        let detail = html
            .find("id=\"h-unknown\"")
            .expect("the unknown detail section");
        assert!(
            limits < detail,
            "limitations must precede the detail tables"
        );
    }

    #[test]
    fn an_undetermined_tree_does_not_claim_a_percentage() {
        let files = vec![routed("a.exe", "refused", true, false, false, true)];
        let html = render_html(
            &report(files, MigrationTarget::WindowsOnArm),
            "2026-10-19",
            "0.1.0",
        );
        assert!(html.contains("Not determinable"));
        assert!(
            !html.contains("0% "),
            "must not answer a question it could not ask"
        );
    }

    #[test]
    fn the_target_is_named_on_the_document() {
        // A verdict without a destination is not a verdict, and the reader may not be the person
        // who ran the command.
        let files = vec![routed("a.exe", "native", false, true, false, false)];
        for target in [
            MigrationTarget::WindowsOnArm,
            MigrationTarget::LinuxWithWine,
        ] {
            let html = render_html(&report(files.clone(), target), "2026-10-19", "0.1.0");
            assert!(html.contains(target.id()), "{} must be named", target.id());
        }
    }

    #[test]
    fn a_linux_assessment_warns_that_it_is_not_the_windows_question() {
        // The default target is Linux+Wine, and a migration is usually about Windows. Saying so
        // in the document is what stops a stale default from being read as an answer.
        let files = vec![routed("a.exe", "native", false, true, false, false)];
        let html = render_html(
            &report(files, MigrationTarget::LinuxWithWine),
            "2026-10-19",
            "0.1.0",
        );
        assert!(html.contains("--target windows-on-arm"));
    }

    #[test]
    fn csv_quotes_a_field_containing_a_comma() {
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("plain"), "plain");
    }

    #[test]
    fn csv_doubles_an_internal_quote() {
        assert_eq!(csv_field(r#"a"b"#), r#""a""b""#);
    }

    #[test]
    fn csv_quotes_a_field_containing_a_newline() {
        assert_eq!(csv_field("a\nb"), "\"a\nb\"");
    }

    #[test]
    fn csv_has_one_row_per_file_and_a_header() {
        let files = vec![
            routed("a.exe", "native", false, true, false, false),
            routed("b.exe", "destination_emulates", false, false, false, false),
        ];
        let csv = render_csv(&report(files, MigrationTarget::WindowsOnArm));
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 3, "header plus two rows");
        assert!(lines[0].starts_with("path,action,"));
        assert!(lines[1].contains(",ready,"));
        assert!(lines[2].contains(",rebuild,"));
    }

    #[test]
    fn csv_records_the_kernel_driver_flag() {
        let files = vec![routed("d.sys", "native", false, true, true, false)];
        let csv = render_csv(&report(files, MigrationTarget::WindowsOnArm));
        assert!(csv.lines().nth(1).expect("a row").contains(",yes,"));
    }

    #[test]
    fn every_action_has_a_title_an_explanation_and_an_id() {
        for action in Action::ALL {
            assert!(!action.title().is_empty(), "{:?}", action);
            assert!(!action.id().is_empty(), "{:?}", action);
            assert!(
                action.explanation().len() > 40,
                "{:?} needs a real explanation",
                action
            );
        }
    }

    #[test]
    fn action_ids_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for action in Action::ALL {
            assert!(seen.insert(action.id()), "duplicate id: {}", action.id());
        }
    }

    #[test]
    fn the_report_is_a_pure_function_of_its_inputs() {
        // The timestamp is a parameter rather than a clock read, so two runs over the same tree
        // produce identical bytes and a report can be diffed against last month's.
        let files = vec![routed("a.exe", "native", false, true, false, false)];
        let report = report(files, MigrationTarget::WindowsOnArm);
        let first = render_html(&report, "2026-10-19T00:00:00Z", "0.1.0");
        let second = render_html(&report, "2026-10-19T00:00:00Z", "0.1.0");
        assert_eq!(first, second);
    }
}
