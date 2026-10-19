//! COMPITUM's command-line interface.
//!
//! The layer that turns the analysis engine into something a person or a CI job can use.
//! Everything below it is a library; this is where the pieces are joined.
//!
//! # Command flow
//!
//! Each command follows the same shape, which is what makes the behaviour predictable:
//!
//! 1. Parse the command line. A malformed invocation fails before anything is read.
//! 2. Resolve the locale, falling back to English silently.
//! 3. Probe the host, once, and reuse the result for the whole run.
//! 4. Read and classify the subject, if the command has one.
//! 5. Decide, render, and record.
//!
//! # Exit codes
//!
//! A command-line tool that is used in CI has to communicate its finding through its exit
//! status, not only through its text. The scheme is deliberately coarse:
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | The command succeeded and the verdict was favourable, or none was required |
//! | 1 | The command could not be carried out (bad input, unreadable file, bad option) |
//! | 2 | `verify` ran successfully and the verdict was **not** favourable |
//!
//! Distinguishing 1 from 2 matters: "the binary will not run here" is a result, while "I
//! could not tell you" is a failure, and a CI pipeline needs to treat them differently.
//!
//! # Ledger recording
//!
//! `inspect` and `verify` record a static analysis observation automatically unless
//! `--no-record` is passed. The dataset grows from ordinary use, without anyone being asked
//! to contribute — which is the only way such a corpus ever accumulates.
//!
//! Recording failures are reported but never fatal. A read-only filesystem or a missing home
//! directory must not stop a user from learning whether their binary will run.

#![forbid(unsafe_code)]

mod args;
mod render;
mod report;
mod scan;

use std::process::ExitCode;

use args::{Command, Invocation, Options};
use compitum_digest::Digest;
use compitum_i18n::{Catalog, LocaleStore, Translator};
use compitum_isa::{HostProfile, IsaFeature, Requirement, RequirementSource};
use compitum_json::{to_pretty, Value};
use compitum_oracle::{default_path, HostSnapshot, Ledger, Outcome, Provenance, Record};
use compitum_pe::patch::{apply_edits, plan_port, PortVerdict};
use compitum_pe::PeImage;
use compitum_router::{decide, Backend, BackendSet, MigrationTarget, Request};

/// Exit code for a completed run with a favourable or unneeded verdict.
const EXIT_OK: u8 = 0;
/// Exit code for a run that could not be carried out.
const EXIT_ERROR: u8 = 1;
/// Exit code for a completed `verify` whose verdict was unfavourable.
const EXIT_INCOMPATIBLE: u8 = 2;

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();

    // The locale is resolved before parsing so that a usage error can be reported in the
    // user's own language. `--lang` is therefore re-read from the raw arguments here; this is
    // the only place the command line is inspected twice, and it buys a localized error path
    // for the one class of failure a new user is most likely to hit.
    let translator = build_translator(raw_lang(&raw));

    let invocation = match args::parse(&raw) {
        Ok(invocation) => invocation,
        Err(error) => {
            // The specific text names the offending option and is deliberately NOT
            // translated: translating it would mean replacing a precise diagnostic with a
            // generic one. The localized hint is printed *in addition*, not instead.
            eprintln!("compitum: {error}");
            let hint = translator.text(error.message_key());
            if hint != error.to_string() {
                eprintln!("compitum: {hint}");
            }
            return ExitCode::from(EXIT_ERROR);
        }
    };

    match run(&invocation, &translator) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("compitum: {message}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

/// Extracts `--lang` from raw arguments without full parsing.
///
/// Exists so that a usage error can be reported in the right language: parsing has already
/// failed by then, so the normal option plumbing is unavailable. Deliberately minimal — it
/// looks for the flag and takes the next argument, and anything malformed simply yields
/// `None`, falling back to the environment and then to English.
fn raw_lang(raw: &[String]) -> Option<&str> {
    raw.iter()
        .position(|arg| arg == "--lang")
        .and_then(|index| raw.get(index + 1))
        .map(String::as_str)
}

/// Resolves the display locale, always returning a usable catalog.
fn build_translator(requested: Option<&str>) -> Translator {
    let store = LocaleStore::discover();
    let catalog = store.resolve(requested);
    Translator::new(catalog)
}

/// Errors that abort a command.
type CliResult = Result<u8, String>;

fn run(invocation: &Invocation, translator: &Translator) -> CliResult {
    match invocation.command {
        Command::Help => {
            print!("{}", args::usage());
            Ok(EXIT_OK)
        }
        Command::Version => {
            println!("compitum {}", env!("CARGO_PKG_VERSION"));
            Ok(EXIT_OK)
        }
        Command::Host => command_host(invocation, translator),
        Command::Inspect => command_inspect(invocation, translator),
        Command::Verify => command_verify(invocation, translator),
        Command::Scan => command_scan(invocation, translator),
        Command::Port => command_port(invocation, translator),
        Command::Oracle => command_oracle(invocation, translator),
        Command::Locales => command_locales(invocation, translator),
    }
}

// ---------------------------------------------------------------------------
// host
// ---------------------------------------------------------------------------

fn command_host(invocation: &Invocation, translator: &Translator) -> CliResult {
    let host = HostProfile::probe();
    let text = render::render_host(&host, translator, invocation.options.json);
    print!("{text}");
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

fn command_inspect(invocation: &Invocation, translator: &Translator) -> CliResult {
    let path = require_operand(invocation, 0, "a binary path")?;
    let (image, digest, size) = load_subject(&path)?;

    let text = render::render_inspect(
        &image,
        &path,
        Some(&digest),
        size,
        translator,
        invocation.options.json,
        invocation.options.verbose,
    );
    print!("{text}");

    // `inspect` classifies without routing, so there is no decision to record. Passing
    // `None` stores the honest `undecided` rather than inferring a route from the ABI
    // family, which would put an unverified claim into the ledger.
    record_plan_if_requested(
        invocation,
        translator,
        &digest,
        size,
        Some(path.clone()),
        &image,
        None,
    );
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn command_verify(invocation: &Invocation, translator: &Translator) -> CliResult {
    let path = require_operand(invocation, 0, "a binary path")?;
    let (image, digest, size) = load_subject(&path)?;

    let host = HostProfile::probe();
    let backends = resolve_backends(&invocation.options);
    let target = resolve_target(&invocation.options)?;

    // Instruction-level analysis is what turns "declared architecture" into "actually
    // requires SME", so it runs on every verify.
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let scan = compitum_pe::scan_image(&bytes, &image);

    let mut requirements = scan.requirements.clone();
    requirements.extend(declared_requirements(&invocation.options)?);

    let request = Request::new(image.clone(), host.clone(), backends)
        .with_requirements(requirements)
        .with_target(target)
        .headless_only(invocation.options.headless_only);

    let plan = decide(&request);

    let text = render::render_plan(
        &plan,
        &path,
        translator,
        invocation.options.json,
        invocation.options.verbose,
    );
    print!("{text}");

    if invocation.options.verbose && !invocation.options.json {
        // Stating what was scanned, and what could not be concluded from it, keeps a clean
        // verdict from being read as a guarantee.
        println!();
        println!(
            "  scanned {} byte(s) in {} executable section(s); {} pattern hit(s)",
            scan.bytes_scanned, scan.sections_scanned, scan.total_hits
        );
        println!("  note: {}", scan.caveat());
    }

    // The decided route and its evidence go into the ledger verbatim, including for a
    // refusal. A record that claimed `native` for a binary this machine cannot run would
    // corrupt the one asset whose value depends on being correct.
    record_plan_if_requested(
        invocation,
        translator,
        &digest,
        size,
        Some(path.clone()),
        &image,
        Some(&plan),
    );

    if plan.is_blocked() {
        Ok(EXIT_INCOMPATIBLE)
    } else {
        Ok(EXIT_OK)
    }
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

/// Classifies every Windows image under a path.
///
/// # Why this is a command and not a flag on `verify`
///
/// `verify` answers a question about one file and reports it in full, with the reasoning and
/// the ledger record. A scan answers a question about a *tree* and reports a summary, because
/// the reader is deciding what work to schedule rather than judging one binary. Folding the two
/// together would make each produce output that is wrong for the other's purpose.
///
/// The exit code follows `verify`'s contract so a CI pipeline treats them the same way: **2**
/// when at least one image was examined and at least one of them will not run, which is an
/// answer rather than a failure.
///
/// # What is deliberately not done here
///
/// Nothing is written to the ledger. A tree walk reads files the operator has not vouched for,
/// and a scan of a stray directory should not be able to add hundreds of rows to the dataset.
/// Recording stays an explicit act, which is the same reason `--no-record` exists.
fn command_scan(invocation: &Invocation, translator: &Translator) -> CliResult {
    let target = require_operand(invocation, 0, "a file or directory to scan")?;
    let path = std::path::Path::new(&target);

    if !path.exists() {
        return Err(format!("{target} does not exist"));
    }

    let depth = parse_bound(
        &invocation.options.depth,
        "--depth",
        scan::DEFAULT_MAX_DEPTH,
    )?;
    let limit = parse_bound(
        &invocation.options.limit,
        "--limit",
        scan::DEFAULT_MAX_FILES,
    )?;

    let host = HostProfile::probe();
    let backends = resolve_backends(&invocation.options);
    let target = resolve_target(&invocation.options)?;

    // The plain entry point is used when the operator asked for nothing special, so the common
    // case exercises the same code path the library exposes to every other caller.
    let report = if invocation.options.depth.is_none() && invocation.options.limit.is_none() {
        scan::scan_path(path, &host, backends, target)
    } else {
        scan::scan_path_with_limits(path, &host, backends, target, depth, limit)
    };
    // ---- Deliverables ----------------------------------------------------
    //
    // Written BEFORE stdout, because these are the artefacts the engagement is judged on. If
    // something fails while writing them the operator must see it as an error, not discover a
    // missing report later; printing the summary first would make a failed write look like a
    // successful run.
    if let Some(destination) = &invocation.options.html_path {
        let generated_at = format_utc(now_unix()).unwrap_or_else(|| "unknown".to_owned());
        let document = report::render_html(&report, &generated_at, env!("CARGO_PKG_VERSION"));
        std::fs::write(destination, document)
            .map_err(|error| format!("cannot write {destination}: {error}"))?;
        eprintln!("compitum: wrote HTML assessment to {destination}");
    }

    if let Some(destination) = &invocation.options.csv_path {
        let table = report::render_csv(&report);
        std::fs::write(destination, table)
            .map_err(|error| format!("cannot write {destination}: {error}"))?;
        eprintln!("compitum: wrote CSV inventory to {destination}");
    }

    let text = render::render_scan(
        &report,
        translator,
        invocation.options.json,
        invocation.options.all,
    );
    print!("{text}");

    // A run that could not examine everything has not answered the question it was asked, so it
    // is reported as an incomplete result rather than as a decision. This is the same
    // distinction the exit-code contract draws between "an answer" and "could not answer".
    if report.truncated {
        eprintln!(
            "compitum: the scan was truncated, so the summary above is incomplete; \
             raise --limit or lower --depth if the whole tree matters"
        );
        return Ok(EXIT_ERROR);
    }

    if report.counts.routed > 0 && report.counts.will_not_run() > 0 {
        Ok(EXIT_INCOMPATIBLE)
    } else {
        Ok(EXIT_OK)
    }
}

// ---------------------------------------------------------------------------
// port
// ---------------------------------------------------------------------------

/// Makes a metadata-only Arm64 port of a managed assembly, or says why it cannot.
///
/// # Why this command refuses so often
///
/// The tempting product is "port my x86 app to Arm64 automatically". It cannot be delivered
/// honestly: turning x86-64 machine code into AArch64 is a recompiler's job, and flipping the
/// `Machine` field alone produces a file that loads and then executes x86 instructions on an
/// Arm64 processor. That is not a partial success, it is a corrupted binary — and a tool caught
/// doing it once is finished.
///
/// What *can* be done honestly is narrower and real. A .NET assembly carries Intermediate
/// Language, which the CLR compiles for whatever processor it runs on. What pins such an
/// assembly to 32-bit is one flag, `COMIMAGE_FLAGS_32BITREQUIRED`, and clearing it is exactly
/// what Microsoft's own `corflags /32BITREQ-` does. No instruction, no section and no import
/// changes, so the edit is provably safe and trivially reversible.
///
/// # Why the default is a dry run
///
/// Rewriting a customer's binary is an action that has to be deliberate. Without `--apply` the
/// command prints every byte it would change and writes nothing; with it, the output goes to a
/// **new** file so the original survives a wrong decision.
///
/// # Exit codes
///
/// Follows the same contract as `verify`: `0` when the image is portable or already portable,
/// `2` when a port is possible but was not applied (so CI can distinguish "needs action" from
/// "failed"), and `1` when the command could not be carried out.
fn command_port(invocation: &Invocation, translator: &Translator) -> CliResult {
    let path = require_operand(invocation, 0, "a managed assembly path")?;
    if !std::path::Path::new(&path).exists() {
        return Err(format!("{path} does not exist"));
    }

    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let image =
        compitum_pe::parse(&bytes).map_err(|e| format!("{path} could not be classified: {e}"))?;

    // `port` is only meaningful towards Arm64, so it does not inherit the global default.
    //
    // Inheriting `linux-wine` made the command report "destination-not-arm64" for a file whose
    // real obstacle was that it is native x86 — a true statement about the wrong thing, and the
    // reader would have concluded the tool could not port anything. A command called `port`
    // defaults to the destination a port exists for, and an explicit `--target linux-wine` is
    // still honoured so the caller can see that answer if they ask for it.
    let target = match &invocation.options.target {
        Some(text) => MigrationTarget::from_id(text).ok_or_else(|| {
            format!("`{text}` is not a migration target; expected `windows-on-arm` or `linux-wine`")
        })?,
        None => MigrationTarget::WindowsOnArm,
    };
    let target_arm64 = matches!(target, MigrationTarget::WindowsOnArm);
    let verdict = plan_port(&bytes, &image, target_arm64);

    // Applying happens BEFORE rendering, so the report can state what actually occurred rather
    // than what could occur. Printing "run with --apply" to somebody who just did is the kind of
    // small lie that makes an operator distrust the whole tool.
    let mut written_to: Option<String> = None;
    let mut exit = match verdict {
        PortVerdict::Refused { .. } => EXIT_INCOMPATIBLE,
        PortVerdict::AlreadyPortable { .. } => EXIT_OK,
        // A dry run is not a failure: it succeeded at answering what would change. The exit code
        // says "action available" so a pipeline can react without parsing prose.
        PortVerdict::Safe { .. } => EXIT_INCOMPATIBLE,
    };

    if let PortVerdict::Safe { edits, .. } = &verdict {
        if invocation.options.apply {
            let destination = invocation
                .options
                .output
                .clone()
                .unwrap_or_else(|| format!("{path}.arm64"));

            // The original file is never the destination. A patch that turns out to be wrong
            // must not have destroyed the thing the tool was hired to preserve.
            if destination == path {
                return Err(
                    "refusing to overwrite the input: a patch that turns out to be wrong must \
                     not have destroyed the original. Use --output to choose a new path."
                        .to_owned(),
                );
            }

            let mut patched = bytes.clone();
            apply_edits(&mut patched, edits).map_err(|error| error.to_string())?;

            // Re-parse before writing. A patch that produced an unreadable file must never reach
            // the disk where a customer's build could pick it up.
            compitum_pe::parse(&patched).map_err(|error| {
                format!(
                    "the patch produced a file that no longer parses ({error}); nothing was \
                     written"
                )
            })?;

            std::fs::write(&destination, &patched)
                .map_err(|error| format!("cannot write {destination}: {error}"))?;
            written_to = Some(destination);
            exit = EXIT_OK;
        }
    }

    if invocation.options.json {
        println!(
            "{}",
            to_pretty(&port_json(&path, &verdict, written_to.as_deref()))
        );
    } else {
        print!(
            "{}",
            render::render_port(&path, &verdict, translator, written_to.as_deref())
        );
    }

    Ok(exit)
}

/// The machine-readable form of a port plan.
fn port_json(path: &str, verdict: &PortVerdict, written_to: Option<&str>) -> Value {
    let mut doc = compitum_json::Object::new().with("path", path);
    // `applied` is emitted for every outcome, so a consumer never has to infer whether a patch
    // was written from the absence of a field.
    doc.insert("applied", written_to.is_some());
    if let Some(destination) = written_to {
        doc.insert("output", destination);
    }

    match verdict {
        PortVerdict::Safe { edits, rationale } => {
            doc.insert("outcome", "safe");
            doc.insert("rationale", rationale.as_str());
            let items: Vec<Value> = edits
                .iter()
                .map(|edit| {
                    compitum_json::Object::new()
                        .with("offset", edit.offset)
                        .with("field", edit.what.as_str())
                        .with("before", hex_bytes(&edit.before))
                        .with("after", hex_bytes(&edit.after))
                        .into()
                })
                .collect();
            doc.insert("edits", Value::Array(items));
        }
        PortVerdict::AlreadyPortable { rationale } => {
            doc.insert("outcome", "already_portable");
            doc.insert("rationale", rationale.as_str());
        }
        PortVerdict::Refused { reason, detail } => {
            doc.insert("outcome", "refused");
            doc.insert("reason", *reason);
            doc.insert("detail", detail.as_str());
        }
    }

    doc.into()
}

/// Renders bytes as uppercase hex, space separated.
fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parses a numeric option, refusing anything that is not a plain count.
///
/// A silent fallback to the default would mean a typo in `--limit 0` quietly widened the scan
/// instead of narrowing it, and the operator would read a complete-looking report that was not
/// the one they asked for.
fn parse_bound(value: &Option<String>, name: &str, default: usize) -> Result<usize, String> {
    let Some(text) = value else {
        return Ok(default);
    };
    text.trim()
        .parse::<usize>()
        .map_err(|_| format!("{name} needs a whole number, got `{text}`"))
}

// ---------------------------------------------------------------------------
// oracle
// ---------------------------------------------------------------------------

fn command_oracle(invocation: &Invocation, translator: &Translator) -> CliResult {
    let subcommand = invocation
        .operands
        .first()
        .map(String::as_str)
        .unwrap_or("stats");

    let ledger_path = invocation
        .options
        .ledger_path
        .clone()
        .unwrap_or_else(|| default_path().display().to_string());
    let mut ledger = Ledger::open(ledger_path.clone()).map_err(|error| error.to_string())?;

    match subcommand {
        "stats" | "summary" => {
            let text = render::render_ledger_summary(
                &ledger.summary_json(),
                translator,
                invocation.options.json,
            );
            print!("{text}");
            Ok(EXIT_OK)
        }
        "list" => {
            let filtered: Vec<&Record> = ledger
                .records()
                .iter()
                .filter(|record| match &invocation.options.outcome {
                    Some(wanted) => record.outcome.id() == wanted,
                    None => true,
                })
                .collect();
            let text = render::render_records(&filtered, translator, invocation.options.json);
            print!("{text}");
            Ok(EXIT_OK)
        }
        "show" => {
            let digest_text = invocation
                .options
                .subject
                .clone()
                .or_else(|| invocation.operands.get(1).cloned())
                .ok_or_else(|| {
                    "oracle show needs a subject: pass a SHA-256 hex digest".to_owned()
                })?;
            let digest = Digest::from_hex(&digest_text)?;
            let found = ledger.for_subject(&digest);
            if found.is_empty() {
                // Not an error: nobody has looked at this binary yet, which is a legitimate
                // and common answer.
                println!("no observations recorded for {}", digest.to_hex());
                return Ok(EXIT_OK);
            }
            let text = render::render_records(&found, translator, invocation.options.json);
            print!("{text}");
            Ok(EXIT_OK)
        }
        "record" => {
            let path = invocation
                .operands
                .get(1)
                .cloned()
                .ok_or_else(|| "oracle record needs a binary path".to_owned())?;
            let (image, digest, size) = load_subject(&path)?;
            let host_snapshot = HostSnapshot::capture(&HostProfile::probe());

            let outcome = match invocation.options.record_outcome.as_deref() {
                None => Outcome::Unknown,
                Some(word) => Outcome::from_id(word).ok_or_else(|| {
                    format!(
                        "unknown outcome `{word}`; expected success, partial, failure or unknown"
                    )
                })?,
            };
            let provenance = if outcome == Outcome::Unknown {
                Provenance::StaticAnalysis
            } else {
                Provenance::ObservedExecution
            };

            let record = Record::statically_analysed(
                digest,
                size,
                Some(path.clone()),
                image.family().id(),
                // Without a full routing pass the route is not known, so the honest value is
                // the one the analyser can justify from the ABI family alone.
                if image.family().is_fully_native_on_arm64() {
                    "native"
                } else {
                    "unknown"
                },
                false,
                image.family().is_fully_native_on_arm64(),
                1000,
                Vec::new(),
                host_snapshot,
                now_unix(),
            )
            .with_outcome(outcome, provenance, invocation.options.note.clone());

            let action = ledger
                .record(record.clone())
                .map_err(|error| error.to_string())?;
            if invocation.options.json {
                println!(
                    "{}",
                    to_pretty(
                        &compitum_json::Object::new()
                            .with("action", action.id())
                            .with("ledger", ledger.path().display().to_string())
                            .with("record", record.to_json())
                            .into()
                    )
                );
            } else {
                println!(
                    "{} {} ({})\n  ledger: {}",
                    action.id(),
                    digest.short(),
                    outcome.id(),
                    ledger.path().display()
                );
            }
            Ok(EXIT_OK)
        }
        other => Err(format!(
            "unknown oracle subcommand `{other}`; try stats, list, show or record"
        )),
    }
}

// ---------------------------------------------------------------------------
// locales
// ---------------------------------------------------------------------------

fn command_locales(invocation: &Invocation, translator: &Translator) -> CliResult {
    let subcommand = invocation
        .operands
        .first()
        .map(String::as_str)
        .unwrap_or("list");
    let store = LocaleStore::discover();

    match subcommand {
        "list" | "ls" => {
            let active = translator.language().to_owned();
            let mut rows: Vec<(String, u32, String)> = Vec::new();
            for tag in store.available() {
                if let Ok(catalog) = store.load(&tag) {
                    let coverage = Translator::new(catalog.clone()).coverage_percent();
                    rows.push((tag, coverage, catalog.native_name().to_owned()));
                }
            }
            let text = render::render_locales(&active, &rows, translator, invocation.options.json);
            print!("{text}");
            Ok(EXIT_OK)
        }
        "check" => {
            let requested = invocation
                .options
                .lang
                .clone()
                .or_else(|| invocation.operands.get(1).cloned())
                .ok_or_else(|| "locales check needs a locale tag, or --lang".to_owned())?;
            let catalog = store.load(&requested).map_err(|_| {
                format!(
                    "locale `{requested}` was not found in: {}",
                    store
                        .roots()
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
            let active = Translator::new(catalog);
            let text = render::render_locale_check(
                active.language(),
                active.coverage_percent(),
                &active.missing_keys(),
                &active.obsolete_keys(),
                translator,
                invocation.options.json,
            );
            print!("{text}");
            Ok(EXIT_OK)
        }
        "export" => {
            // Writes an empty template containing every key the English base defines, so a
            // translator starts from the complete list rather than discovering it by
            // running the tool and watching for fallbacks.
            let base = Catalog::english();
            let requested = invocation
                .operands
                .get(1)
                .cloned()
                .unwrap_or_else(|| "xx".to_owned());
            let mut messages = compitum_json::Object::new();
            let mut keys: Vec<&str> = base.keys().collect();
            keys.sort();
            for key in keys {
                messages.insert(key, "");
            }
            let document = compitum_json::Object::new()
                .with("language", requested.as_str())
                .with("name", "TRANSLATE ME")
                .with("native_name", "TRANSLATE ME")
                .with("direction", "ltr")
                .with("messages", messages)
                .with(
                    "_note",
                    "Fill in the values. Any key left empty falls back to English. \
                     Keys you do not translate are still counted in the coverage figure.",
                );
            println!("{}", to_pretty(&document.into()));
            Ok(EXIT_OK)
        }
        other => Err(format!(
            "unknown locales subcommand `{other}`; try list, check or export"
        )),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Fetches a required positional operand.
fn require_operand(invocation: &Invocation, index: usize, what: &str) -> Result<String, String> {
    invocation
        .operands
        .get(index)
        .cloned()
        .ok_or_else(|| format!("this command needs {what}"))
}

/// Reads, hashes and classifies a file.
fn load_subject(path: &str) -> Result<(PeImage, Digest, u64), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let size = bytes.len() as u64;
    let digest = compitum_digest::sha256(&bytes);
    let image =
        compitum_pe::parse(&bytes).map_err(|e| format!("{path} could not be classified: {e}"))?;
    Ok((image, digest, size))
}

/// Turns `--require` and `--backends` into the types the router wants.
fn declared_requirements(options: &Options) -> Result<Vec<Requirement>, String> {
    let mut out = Vec::new();
    for id in &options.require_feature {
        let feature = IsaFeature::from_id(id).ok_or_else(|| {
            format!(
                "`{id}` is not a known ARM64 feature id; run `compitum host` for the vocabulary"
            )
        })?;
        out.push(Requirement::new(
            feature,
            RequirementSource::UserDeclared,
            None,
            "declared on the command line",
        ));
    }
    Ok(out)
}

/// Resolves which translation backends are available.
///
/// # Why this looks instead of assuming
///
/// An earlier revision defaulted to "Wine is installed" and required the operator to correct it
/// with `--backends`. That default was chosen deliberately — discovering the truth "varies by
/// distribution, and a false positive would make COMPITUM promise a route it cannot take" — and
/// the reasoning identified the right risk while reaching the wrong remedy. The answer to
/// "guessing might be wrong" is to **look**, not to guess pessimistically.
///
/// So discovery runs by default. `--backends` still overrides it, for a machine where the
/// backends are somewhere discovery does not search, and `--assume-backends` remains for
/// deliberately evaluating a hypothetical host.
fn resolve_backends(options: &Options) -> BackendSet {
    if options.assume_backends {
        return BackendSet::all();
    }
    if let Some(list) = &options.backends {
        let mut set = BackendSet::none();
        for word in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match word {
                "wine" => set.insert(Backend::Wine),
                "fex" | "fex-emu" => set.insert(Backend::Fex),
                "box64" => set.insert(Backend::Box64),
                "box86" => set.insert(Backend::Box86),
                _ => {}
            }
        }
        return set;
    }
    compitum_router::discover().backend_set()
}

/// Resolves where the software is going.
///
/// # Why an unknown destination is an error rather than a default
///
/// A mistyped `--target` that silently fell back to the default would produce a confident
/// analysis of **the wrong platform**. For a migration report that is the worst possible
/// failure: the customer would receive a defect list for a destination they are not moving to,
/// or worse, a clean bill of health for one they are.
///
/// A silent default is acceptable for a value the operator did not mention. It is not
/// acceptable for one they did mention and got wrong.
fn resolve_target(options: &Options) -> Result<MigrationTarget, String> {
    let Some(text) = &options.target else {
        return Ok(MigrationTarget::default());
    };
    MigrationTarget::from_id(text).ok_or_else(|| {
        format!("`{text}` is not a migration target; expected `windows-on-arm` or `linux-wine`")
    })
}

/// Records a static analysis observation, unless `--no-record` was passed.
///
/// Recording is controlled by the explicit `--no-record` flag and by nothing else. In
/// particular it is **not** suppressed by `--json`: the output format must never silently
/// change a side effect, because the visible output would be identical either way and a user
/// who stopped contributing to the dataset would never find out.
///
/// Failures are printed to stderr and never abort. A user on a read-only filesystem must still
/// get their verdict, and stdout must stay valid for a JSON consumer.
fn record_plan_if_requested(
    invocation: &Invocation,
    _translator: &Translator,
    digest: &Digest,
    size: u64,
    label: Option<String>,
    image: &PeImage,
    plan: Option<&compitum_router::Plan>,
) {
    if invocation.options.no_record {
        return;
    }
    let path = invocation
        .options
        .ledger_path
        .clone()
        .unwrap_or_else(|| default_path().display().to_string());

    let host_snapshot = HostSnapshot::capture(&HostProfile::probe());

    // Derive the stored fields from the actual decision when one was made. When no routing
    // pass ran — `inspect` does not perform one — the route is recorded as `undecided`
    // rather than guessed from the ABI family, because a guess stored in the ledger would
    // later be indistinguishable from a measurement.
    let (route, blocked, fully_native, confidence, required_features) = match plan {
        Some(plan) => (
            plan.route.id(),
            plan.is_blocked(),
            plan.is_fully_native(),
            plan.confidence.permille(),
            plan.reasons
                .items()
                .iter()
                .filter(|r| r.code == compitum_router::ReasonCode::IsaFeaturesMissing)
                .filter_map(|r| r.detail.as_deref())
                .flat_map(|detail| {
                    // The detail reads "this host does not implement: a, b, c"; recover the ids
                    // so the Oracle can perform capability arithmetic on them.
                    detail
                        .split_once(':')
                        .map(|(_, list)| {
                            list.split(',')
                                .map(|s| s.trim().to_owned())
                                .filter(|s| !s.is_empty())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>(),
        ),
        None => ("undecided", false, false, 0, Vec::new()),
    };

    let record = Record::statically_analysed(
        *digest,
        size,
        label,
        image.family().id(),
        route,
        blocked,
        fully_native,
        confidence,
        required_features,
        host_snapshot,
        now_unix(),
    );

    match Ledger::open(path).and_then(|mut ledger| ledger.record(record)) {
        Ok(_) => {}
        Err(error) => {
            eprintln!("compitum: not recorded: {error}");
        }
    }
}

/// The current Unix time in seconds.
///
/// Returns zero when the clock is unreadable, rather than inventing a plausible-looking
/// timestamp that would then appear in ordering and age calculations as though it were real.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Formats a Unix timestamp as an ISO-8601 UTC date and time.
///
/// # Why this is hand-written
///
/// A date library would be the first third-party dependency in the workspace, and the whole
/// supply-chain argument for this project rests on there being none. The conversion is a
/// well-defined calendar calculation, so it is written out rather than pulled in — and a report
/// timestamp does not need time zones, leap seconds or locale.
///
/// Returns `None` for a timestamp outside the range this can represent, rather than inventing a
/// plausible-looking date. A report that states a wrong date is worse than one that states none.
#[must_use]
fn format_utc(unix: i64) -> Option<String> {
    if unix < 0 {
        // A pre-1970 timestamp means the clock is wrong, and a report must not pretend otherwise.
        return None;
    }
    let seconds = unix as u64;
    let days = seconds / 86_400;
    let remainder = seconds % 86_400;
    let hour = remainder / 3_600;
    let minute = (remainder % 3_600) / 60;
    let second = remainder % 60;

    // Civil-from-days, from Howard Hinnant's algorithm. Shifting the epoch to 0000-03-01 makes
    // the leap-year rule a single division, which avoids a loop over years.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    if year > 9999 {
        return None;
    }

    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// Convenience for tests and future embedded use.
#[allow(dead_code)]
fn json_value_of(text: &str) -> Option<Value> {
    compitum_json::parse(text).ok()
}
