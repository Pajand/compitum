//! Argument parsing.
//!
//! Hand-written rather than pulled from a crate, for the same reason as everything else in
//! this workspace: no third-party dependencies in the core. The surface is small enough that
//! a parser is a few hundred lines, and writing it means the help text, the error messages
//! and the localization keys stay in one place instead of being split between a library's
//! conventions and our own.
//!
//! # Behaviour
//!
//! * Every command has a long form and a one-or-two-letter alias.
//! * Options may appear before or after positional arguments.
//! * `--help` and `--version` are recognized anywhere and pre-empt everything.
//! * An unknown option is an error naming the option, never a silently ignored argument. A
//!   compatibility tool that quietly ignores `--hedless` would be actively dangerous.

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// The subcommand.
    pub command: Command,
    /// Positional operands, in order.
    pub operands: Vec<String>,
    /// Options.
    pub options: Options,
}

/// The subcommand selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Print usage.
    Help,
    /// Print the version.
    Version,
    /// Report the host's ARM64 capabilities.
    Host,
    /// Classify a binary without consulting the host.
    Inspect,
    /// Classify a binary and decide whether it can run here.
    Verify,
    /// Classify every Windows image under a path.
    Scan,
    /// Read and write the compatibility ledger.
    Oracle,
    /// Work with translation catalogs.
    Locales,
}

/// Options accepted across commands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Emit machine-readable JSON instead of human output.
    pub json: bool,
    /// Show every reason, including supporting ones.
    pub verbose: bool,
    /// Require that the subject run without a display.
    pub headless_only: bool,
    /// Do not write to the ledger.
    pub no_record: bool,
    /// Path to the ledger, overriding the default.
    pub ledger_path: Option<String>,
    /// Locale override.
    pub lang: Option<String>,
    /// Declare an additional required CPU feature by id, repeatable.
    pub require_feature: Vec<String>,
    /// Override the ledger query with a subject digest.
    pub subject: Option<String>,
    /// Restrict an Oracle query by outcome.
    pub outcome: Option<String>,
    /// A note to attach to a recorded observation.
    pub note: Option<String>,
    /// An explicit outcome for a recorded observation.
    pub record_outcome: Option<String>,
    /// Comma-separated list of installed translation backends.
    pub backends: Option<String>,
    /// Treat all known backends as installed.
    pub assume_backends: bool,
    /// Which Oracle store to read or write: `community` (the default) or `verified`.
    ///
    /// The two stores are licensed differently and are never combined — not on disk, and not in
    /// a query — so which one is being written to is a decision an operator should make
    /// explicitly rather than inherit invisibly.
    pub store: Option<String>,
    /// Where the software is going: `windows-on-arm` or `linux-wine`.
    ///
    /// A route is only meaningful relative to a destination. This router used to assume the
    /// destination was always "this machine with whatever is installed here", which turned a
    /// migration question into a Wine compatibility check.
    pub target: Option<String>,
    /// How deep `scan` descends into a directory tree.
    pub depth: Option<String>,
    /// How many files `scan` will examine before it stops.
    pub limit: Option<String>,
    /// List every scanned file, not only the ones that need attention.
    pub all: bool,
    /// Write a self-contained HTML report to this path.
    ///
    /// The document a migration is decided from: opened by people who did not run the command,
    /// forwarded, filed, and printed. It carries the destination, the readiness figure, the four
    /// actions, and every limitation of the analysis.
    pub html_path: Option<String>,
    /// Write a CSV of one row per file to this path.
    ///
    /// The form a customer's engineering team works from: imported into a tracker or a
    /// spreadsheet rather than read.
    pub csv_path: Option<String>,
}

/// Why parsing failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// An option that is not recognized.
    UnknownOption {
        /// The offending flag.
        option: String,
    },
    /// An option that requires a value did not get one.
    MissingValue {
        /// The offending flag.
        option: String,
    },
    /// A subcommand is required but was not supplied.
    NoCommand,
    /// A subcommand this build does not implement.
    UnknownCommand {
        /// The offending word.
        word: String,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::UnknownOption { option } => write!(
                f,
                "unrecognized option `{option}`; run `compitum --help` for the list"
            ),
            ParseError::MissingValue { option } => {
                write!(f, "option `{option}` requires a value")
            }
            ParseError::NoCommand => {
                f.write_str("a subcommand is required; run `compitum --help` for the list")
            }
            ParseError::UnknownCommand { word } => write!(
                f,
                "unrecognized subcommand `{word}`; run `compitum --help` for the list"
            ),
        }
    }
}

impl ParseError {
    /// The translation key describing this error, for the localized surface.
    #[must_use]
    pub fn message_key(&self) -> &'static str {
        "error.usage"
    }
}

/// Parses a command line, excluding the program name.
///
/// # Errors
///
/// Returns a [`ParseError`] describing the first problem. Parsing never partially succeeds:
/// a malformed invocation produces no [`Invocation`] at all.
pub fn parse(args: &[String]) -> Result<Invocation, ParseError> {
    // `--help` and `--version` win wherever they appear, so that a user who mistypes the
    // rest of the line still gets guidance instead of an error about their typo.
    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => {
                return Ok(Invocation {
                    command: Command::Help,
                    operands: Vec::new(),
                    options: Options::default(),
                })
            }
            "--version" | "-V" => {
                return Ok(Invocation {
                    command: Command::Version,
                    operands: Vec::new(),
                    options: Options::default(),
                })
            }
            _ => {}
        }
    }

    let mut options = Options::default();
    let mut operands: Vec<String> = Vec::new();
    let mut command: Option<Command> = None;
    let mut index = 0usize;

    while index < args.len() {
        let arg = &args[index];
        // A value-taking option consumes the next argument even if it begins with a dash,
        // because a path or a feature id legitimately might.
        let mut take_value = |name: &str| -> Result<String, ParseError> {
            index += 1;
            args.get(index)
                .cloned()
                .ok_or_else(|| ParseError::MissingValue {
                    option: name.to_owned(),
                })
        };

        match arg.as_str() {
            "--json" => options.json = true,
            "--verbose" | "-v" => options.verbose = true,
            "--headless" => options.headless_only = true,
            "--no-record" => options.no_record = true,
            "--assume-backends" => options.assume_backends = true,
            "--store" => options.store = Some(take_value("--store")?),
            "--target" => options.target = Some(take_value("--target")?),
            "--depth" => options.depth = Some(take_value("--depth")?),
            "--limit" => options.limit = Some(take_value("--limit")?),
            "--all" => options.all = true,
            "--html" => options.html_path = Some(take_value("--html")?),
            "--csv" => options.csv_path = Some(take_value("--csv")?),
            "--ledger" => options.ledger_path = Some(take_value("--ledger")?),
            "--lang" => options.lang = Some(take_value("--lang")?),
            "--require" => options.require_feature.push(take_value("--require")?),
            "--subject" => options.subject = Some(take_value("--subject")?),
            "--outcome" => options.outcome = Some(take_value("--outcome")?),
            "--note" => options.note = Some(take_value("--note")?),
            "--record-outcome" => options.record_outcome = Some(take_value("--record-outcome")?),
            "--backends" => options.backends = Some(take_value("--backends")?),
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(ParseError::UnknownOption {
                    option: other.to_owned(),
                })
            }
            other => {
                if command.is_none() {
                    command =
                        Some(
                            parse_command(other).ok_or_else(|| ParseError::UnknownCommand {
                                word: other.to_owned(),
                            })?,
                        );
                } else {
                    operands.push(other.to_owned());
                }
            }
        }
        index += 1;
    }

    Ok(Invocation {
        command: command.ok_or(ParseError::NoCommand)?,
        operands,
        options,
    })
}

/// Maps a word to a subcommand, accepting aliases.
fn parse_command(word: &str) -> Option<Command> {
    Some(match word {
        "host" | "h" => Command::Host,
        "inspect" | "i" => Command::Inspect,
        "verify" | "v" => Command::Verify,
        "scan" | "s" => Command::Scan,
        "oracle" | "o" => Command::Oracle,
        "locales" | "l" => Command::Locales,
        "help" => Command::Help,
        "version" => Command::Version,
        _ => return None,
    })
}

/// The full usage text.
#[must_use]
pub fn usage() -> String {
    format!(
        "\
COMPITUM {version} — ABI-aware ARM64 compatibility layer

USAGE
  compitum <command> [operands] [options]

COMMANDS
  host                     Report this machine's ARM64 capabilities and Linux ABI
  inspect <binary>         Classify a binary: ABI family, requirements, likely route
  verify  <binary>         Decide whether a binary can run on this machine, and why
  scan    <path>           Classify every Windows image under a file or directory
  oracle  <subcommand>     Read and write the compatibility ledger
  locales <subcommand>     List, check and export translation catalogs

ORACLE SUBCOMMANDS
  stats                    Summarize the ledger
  list                     List recorded observations
  show <sha256>            Show every observation about one subject
  record <binary>          Record an observation about a binary

LOCALES SUBCOMMANDS
  list                     List available locales and their coverage
  check [tag]              Report missing and obsolete translation keys
  export <tag>             Write a translation template for a locale

OPTIONS
  --json                   Emit machine-readable JSON
  --verbose, -v            Show every reason, including supporting ones
  --all                    With scan, list every file rather than only the findings
  --html <path>            With scan, write a self-contained HTML assessment report
  --csv <path>             With scan, write one row per file as CSV
  --depth <n>              With scan, how deep to descend (default 12)
  --limit <n>              With scan, how many files to examine (default 100000)
  --headless               Require the subject to run without a display
  --require <feature>      Declare a required CPU feature (repeatable)
  --target <destination>   Where the software is going:
                             windows-on-arm  the OS supplies NT, Prism and ARM64EC
                             linux-wine      this machine, with Wine installed (default)
  --backends <list>        Installed backends, comma separated
                           (wine, fex, box64, box86)
  --assume-backends        Treat every known backend as installed
  --ledger <path>          Use a specific ledger file
  --no-record              Do not write to the ledger
  --lang <tag>             Show output in this language
  --subject <sha256>       Restrict an Oracle query to one subject
  --outcome <kind>         Restrict an Oracle query: success, partial, failure, unknown
  --note <text>            Attach a note to a recorded observation
  --record-outcome <kind>  Record an outcome rather than a prediction
  --help, -h               Show this text
  --version, -V            Show the version

EXAMPLES
  compitum host
  compitum host --json
  compitum verify ./app.exe
  compitum verify ./app.exe --headless --backends wine,fex
  compitum scan ./dist
  compitum scan ./dist --json > migration-report.json
  compitum oracle record ./app.exe --record-outcome success --note 'ran fine'
  compitum oracle show 9f4390f8d30c2dd9...
",
        version = env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_a_bare_command() {
        let invocation = parse(&args(&["host"])).unwrap();
        assert_eq!(invocation.command, Command::Host);
        assert!(invocation.operands.is_empty());
        assert_eq!(invocation.options, Options::default());
    }

    #[test]
    fn parses_operands_after_the_command() {
        let invocation = parse(&args(&["verify", "./app.exe"])).unwrap();
        assert_eq!(invocation.command, Command::Verify);
        assert_eq!(invocation.operands, vec!["./app.exe".to_owned()]);
    }

    #[test]
    fn accepts_aliases() {
        assert_eq!(parse(&args(&["h"])).unwrap().command, Command::Host);
        assert_eq!(parse(&args(&["i", "x"])).unwrap().command, Command::Inspect);
        assert_eq!(parse(&args(&["v", "x"])).unwrap().command, Command::Verify);
        assert_eq!(
            parse(&args(&["o", "stats"])).unwrap().command,
            Command::Oracle
        );
    }

    #[test]
    fn parses_flags_in_any_position() {
        let before = parse(&args(&["--json", "host"])).unwrap();
        let after = parse(&args(&["host", "--json"])).unwrap();
        assert_eq!(before, after);
        assert!(before.options.json);

        let combined = parse(&args(&["--verbose", "verify", "--json", "x", "--headless"])).unwrap();
        assert!(combined.options.verbose);
        assert!(combined.options.json);
        assert!(combined.options.headless_only);
        assert_eq!(combined.operands, vec!["x".to_owned()]);
    }

    #[test]
    fn help_and_version_pre_empt_everything() {
        // Even alongside an unknown option, because a user who mistyped the rest of the line
        // most needs the guidance.
        assert_eq!(
            parse(&args(&["--bogus", "--help"])).unwrap().command,
            Command::Help
        );
        assert_eq!(
            parse(&args(&["verify", "-V", "x"])).unwrap().command,
            Command::Version
        );
    }

    #[test]
    fn value_options_consume_the_next_argument() {
        let invocation = parse(&args(&[
            "verify",
            "x",
            "--ledger",
            "/tmp/led.jsonl",
            "--lang",
            "fa",
        ]))
        .unwrap();
        assert_eq!(
            invocation.options.ledger_path.as_deref(),
            Some("/tmp/led.jsonl")
        );
        assert_eq!(invocation.options.lang.as_deref(), Some("fa"));
    }

    #[test]
    fn a_value_may_begin_with_a_dash() {
        // Paths and feature ids legitimately do, so the parser must not treat this as a flag.
        let invocation = parse(&args(&["verify", "x", "--ledger", "-weird-name"])).unwrap();
        assert_eq!(
            invocation.options.ledger_path.as_deref(),
            Some("-weird-name")
        );
    }

    #[test]
    fn a_missing_value_is_an_error_naming_the_option() {
        let error = parse(&args(&["verify", "x", "--ledger"])).unwrap_err();
        assert_eq!(
            error,
            ParseError::MissingValue {
                option: "--ledger".to_owned()
            }
        );
        assert!(error.to_string().contains("--ledger"));
    }

    #[test]
    fn an_unknown_option_is_an_error_never_ignored() {
        // Silently ignoring `--hedless` would produce a verdict the user did not ask for,
        // which for a compatibility tool is worse than refusing to run.
        let error = parse(&args(&["verify", "x", "--hedless"])).unwrap_err();
        assert_eq!(
            error,
            ParseError::UnknownOption {
                option: "--hedless".to_owned()
            }
        );
        assert!(error.to_string().contains("--hedless"));
    }

    #[test]
    fn an_unknown_command_is_an_error() {
        let error = parse(&args(&["frobnicate"])).unwrap_err();
        assert_eq!(
            error,
            ParseError::UnknownCommand {
                word: "frobnicate".to_owned()
            }
        );
    }

    #[test]
    fn no_arguments_requires_a_command() {
        assert_eq!(parse(&[]).unwrap_err(), ParseError::NoCommand);
        assert_eq!(
            parse(&args(&["--json"])).unwrap_err(),
            ParseError::NoCommand
        );
    }

    #[test]
    fn repeatable_options_accumulate() {
        let invocation = parse(&args(&[
            "verify",
            "x",
            "--require",
            "sme",
            "--require",
            "sve2",
        ]))
        .unwrap();
        assert_eq!(invocation.options.require_feature, vec!["sme", "sve2"]);
    }

    #[test]
    fn record_options_parse() {
        let invocation = parse(&args(&[
            "oracle",
            "record",
            "app.exe",
            "--record-outcome",
            "success",
            "--note",
            "ran fine",
        ]))
        .unwrap();
        assert_eq!(invocation.command, Command::Oracle);
        assert_eq!(invocation.operands, vec!["record", "app.exe"]);
        assert_eq!(
            invocation.options.record_outcome.as_deref(),
            Some("success")
        );
        assert_eq!(invocation.options.note.as_deref(), Some("ran fine"));
    }

    #[test]
    fn usage_documents_every_command_and_option() {
        let text = usage();
        for word in [
            "host",
            "inspect",
            "verify",
            "oracle",
            "locales",
            "--json",
            "--verbose",
            "--headless",
            "--require",
            "--backends",
            "--ledger",
            "--no-record",
            "--lang",
            "--help",
            "--version",
        ] {
            assert!(text.contains(word), "usage does not mention `{word}`");
        }
    }

    #[test]
    fn every_parse_error_has_a_message_key() {
        for error in [
            ParseError::UnknownOption {
                option: "-x".to_owned(),
            },
            ParseError::MissingValue {
                option: "--x".to_owned(),
            },
            ParseError::NoCommand,
            ParseError::UnknownCommand {
                word: "x".to_owned(),
            },
        ] {
            assert!(!error.message_key().is_empty());
            assert!(!error.to_string().is_empty());
        }
    }
}
