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

use std::process::ExitCode;

use args::{Command, Invocation, Options};
use compitum_digest::Digest;
use compitum_i18n::{Catalog, LocaleStore, Translator};
use compitum_isa::{HostProfile, IsaFeature, Requirement, RequirementSource};
use compitum_json::{to_pretty, Value};
use compitum_oracle::{default_path, HostSnapshot, Ledger, Outcome, Provenance, Record};
use compitum_pe::PeImage;
use compitum_router::{decide, Backend, BackendSet, Request};

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

    // Instruction-level analysis is what turns "declared architecture" into "actually
    // requires SME", so it runs on every verify.
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let scan = compitum_pe::scan_image(&bytes, &image);

    let mut requirements = scan.requirements.clone();
    requirements.extend(declared_requirements(&invocation.options)?);

    let request = Request::new(image.clone(), host.clone(), backends)
        .with_requirements(requirements)
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

/// Convenience for tests and future embedded use.
#[allow(dead_code)]
fn json_value_of(text: &str) -> Option<Value> {
    compitum_json::parse(text).ok()
}
