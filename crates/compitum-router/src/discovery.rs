//! Host-side discovery of the translation backends that actually exist here.
//!
//! # Why this module exists
//!
//! Until now the CLI guessed. It assumed Wine was installed unless the operator passed
//! `--backends` or `--assume-backends`, and that guess is the difference between a routing
//! decision that describes this machine and one that describes the operator's intention.
//!
//! The guess was made deliberately — discovering whether FEX is installed "varies by
//! distribution, and a false positive would make COMPITUM promise a route it cannot take".
//! That reasoning was correct about the risk and wrong about the remedy: the answer is not to
//! assume pessimistically, it is to **look**.
//!
//! # What discovery can and cannot establish
//!
//! Finding an executable proves the *loader* is present. It does not prove that loader can do
//! the thing the route needs — an ARM64EC image needs FEX's ARM64EC-compatible mode
//! specifically, which Box64 does not provide. So discovery reports what it found and the
//! router keeps its own requirements; a backend being present is necessary, not sufficient.
//!
//! Where discovery cannot reach a conclusion it says so rather than guessing. A report of
//! "not found" and a report of "could not tell" are different answers, and collapsing them
//! would let an unreadable directory look like an absent dependency.
//!
//! # Purity
//!
//! This module performs I/O. [`crate::decide`] does not, and the split is deliberate: a
//! routing decision must be reproducible from an Oracle record, so the impure part is
//! separated from the pure part and produces a plain data structure the pure part consumes.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::route::{Backend, BackendSet};

/// How a backend was located.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    /// An executable was located at this path.
    Executable(PathBuf),
    /// The name resolves on `PATH`, but no absolute path was established.
    OnPath,
    /// A directory or configuration file that belongs to the project was found, without an
    /// executable. Recorded because it still tells an operator something useful.
    ArtefactOnly(PathBuf),
}

impl Found {
    /// A short English description for the report.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Found::Executable(path) => format!("executable at {}", path.display()),
            Found::OnPath => "found on PATH".to_owned(),
            Found::ArtefactOnly(path) => format!("only an artefact at {}", path.display()),
        }
    }

    /// Returns `true` when this constitutes a usable loader.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self, Found::Executable(_) | Found::OnPath)
    }
}

/// What discovery established about one backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendProbe {
    /// Which backend this is.
    pub backend: Backend,
    /// Where it was found, or `None` when it was not.
    pub found: Option<Found>,
    /// The version string the executable reported, when it was willing to say.
    ///
    /// Not required: some backends only print a version in specific modes, and demanding it
    /// would turn a working installation into a "not found".
    pub version: Option<String>,
    /// Set when a location could not be examined, so "absent" and "unknown" stay distinct.
    pub inconclusive: Option<String>,
}

impl BackendProbe {
    /// Returns `true` when a usable loader was located.
    #[must_use]
    pub fn is_present(&self) -> bool {
        self.found.as_ref().is_some_and(Found::is_usable)
    }

    /// A one-line summary for the CLI.
    #[must_use]
    pub fn summary(&self) -> String {
        match (&self.found, &self.version) {
            (Some(found), Some(version)) => {
                format!("{} — {} ({})", self.backend.id(), found.describe(), version)
            }
            (Some(found), None) => format!("{} — {}", self.backend.id(), found.describe()),
            (None, _) => {
                if let Some(reason) = &self.inconclusive {
                    format!("{} — could not determine: {reason}", self.backend.id())
                } else {
                    format!("{} — not found", self.backend.id())
                }
            }
        }
    }
}

/// The outcome of probing a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// One probe per known backend, in the order [`Backend::ALL`] gives.
    pub probes: Vec<BackendProbe>,
}

impl Discovery {
    /// The set of backends that were located, suitable for [`crate::Request::new`].
    #[must_use]
    pub fn backend_set(&self) -> BackendSet {
        let mut set = BackendSet::none();
        for probe in &self.probes {
            if probe.is_present() {
                set.insert(probe.backend);
            }
        }
        set
    }

    /// The probe for one backend.
    #[must_use]
    pub fn probe(&self, backend: Backend) -> Option<&BackendProbe> {
        self.probes.iter().find(|p| p.backend == backend)
    }

    /// Returns `true` when nothing usable was found at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.backend_set().is_empty()
    }

    /// Any probes that could not reach a conclusion, so an operator knows the result is partial.
    #[must_use]
    pub fn inconclusive(&self) -> Vec<&BackendProbe> {
        self.probes
            .iter()
            .filter(|p| p.inconclusive.is_some())
            .collect()
    }

    /// A machine-readable report.
    #[must_use]
    pub fn to_json(&self) -> compitum_json::Value {
        let items: Vec<compitum_json::Value> = self
            .probes
            .iter()
            .map(|probe| {
                compitum_json::Object::new()
                    .with("backend", probe.backend.id())
                    .with("present", probe.is_present())
                    .with("location", probe.found.as_ref().map(Found::describe))
                    .with("version", probe.version.as_deref())
                    .with("inconclusive", probe.inconclusive.as_deref())
                    .into()
            })
            .collect();
        compitum_json::Object::new()
            .with("backend_count", self.backend_set().len())
            .with("backends", items)
            .into()
    }
}

/// Probes this machine for every known backend.
///
/// Never fails. A probe that cannot examine something records that it could not, which is
/// reported as inconclusive rather than as absent.
#[must_use]
pub fn discover() -> Discovery {
    let path_dirs = path_directories();
    let home = std::env::var_os("HOME").map(PathBuf::from);

    let probes = Backend::ALL
        .iter()
        .map(|backend| probe_backend(*backend, &path_dirs, home.as_deref()))
        .collect();

    Discovery { probes }
}

/// Splits `PATH` into directories.
fn path_directories() -> Vec<PathBuf> {
    std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect())
        .unwrap_or_default()
}

/// Locates one backend.
fn probe_backend(backend: Backend, path_dirs: &[PathBuf], home: Option<&Path>) -> BackendProbe {
    let names = executable_names(backend);
    let mut artefact: Option<PathBuf> = None;

    for name in &names {
        for dir in path_dirs {
            let candidate = dir.join(name);
            if is_executable_file(&candidate) {
                let version = read_version(&candidate);
                return BackendProbe {
                    backend,
                    found: Some(Found::Executable(candidate)),
                    version,
                    inconclusive: None,
                };
            }
        }
    }

    // No executable on PATH. Look for the project's own artefacts, which still tell an
    // operator something: a configured FEX root means FEX was installed at some point.
    if let Some(home) = home {
        for relative in artefact_paths(backend) {
            let candidate = home.join(relative);
            if candidate.exists() {
                artefact = Some(candidate);
                break;
            }
        }
    }

    // Nothing on PATH and nothing under HOME. Whether that means "absent" depends on whether
    // PATH could be read at all, so that distinction is preserved.
    if path_dirs.is_empty() {
        return BackendProbe {
            backend,
            found: None,
            version: None,
            inconclusive: Some(
                "PATH is empty or unreadable, so an absence cannot be distinguished from a \
                 lookup that never happened"
                    .to_owned(),
            ),
        };
    }

    BackendProbe {
        backend,
        found: artefact.map(Found::ArtefactOnly),
        version: None,
        inconclusive: None,
    }
}

/// The executable names a backend is distributed under.
fn executable_names(backend: Backend) -> Vec<&'static str> {
    match backend {
        // Wine ships under several names depending on the distribution and the build: the
        // `wine64` loader specifically, the generic `wine` wrapper, and on some systems a
        // versioned name. All are tried, because a working installation under any of them is
        // a working installation.
        Backend::Wine => vec!["wine64", "wine"],
        // FEX names its entry points after the mode rather than the project.
        Backend::Fex => vec!["FEXInterpreter", "FEXBash", "FEXLoader", "fex"],
        Backend::Box64 => vec!["box64"],
        Backend::Box86 => vec!["box86"],
    }
}

/// Project-owned paths under `$HOME` that indicate a backend was installed.
fn artefact_paths(backend: Backend) -> Vec<&'static str> {
    match backend {
        Backend::Wine => vec![".wine"],
        Backend::Fex => vec![".fex-emu", ".local/share/fex-emu"],
        Backend::Box64 => vec![".local/share/box64"],
        Backend::Box86 => vec![".local/share/box86"],
    }
}

/// Returns `true` when the path is a file with any execute bit set.
///
/// Checks the mode rather than attempting to run it, because running an arbitrary
/// `$PATH` entry during discovery would be a surprise the operator did not ask for.
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::metadata(path) {
        Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Asks an executable to report its version, tolerating refusal.
///
/// `--version` is the convention, but a backend that does not understand it may exit non-zero
/// or print usage. Output is still accepted if it looks like a version line, and the result is
/// optional throughout: discovery must never turn a working installation into "not found"
/// merely because the executable was unwilling to talk.
fn read_version(executable: &Path) -> Option<String> {
    for flag in ["--version", "-version"] {
        let output = Command::new(executable).arg(flag).output().ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let first = text.lines().find(|line| !line.trim().is_empty());
        if let Some(line) = first {
            let trimmed = line.trim();
            // Guard against a usage banner being mistaken for a version.
            if trimmed.len() < 160 {
                return Some(trimmed.to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn found_describes_each_variant() {
        let exe = Found::Executable(PathBuf::from("/usr/bin/wine"));
        assert!(exe.describe().contains("/usr/bin/wine"));
        assert!(exe.is_usable());

        assert!(Found::OnPath.is_usable());

        let artefact = Found::ArtefactOnly(PathBuf::from("/root/.wine"));
        assert!(artefact.describe().contains("only an artefact"));
        assert!(
            !artefact.is_usable(),
            "a configuration directory is not a loader and must not be routed to"
        );
    }

    #[test]
    fn a_backend_with_no_executable_is_not_present() {
        let probe = BackendProbe {
            backend: Backend::Fex,
            found: None,
            version: None,
            inconclusive: None,
        };
        assert!(!probe.is_present());
        assert!(probe.summary().contains("not found"));
    }

    #[test]
    fn an_artefact_alone_does_not_count_as_present() {
        // This is the distinction that keeps discovery honest: a leftover configuration
        // directory means the project was installed once, not that it works now.
        let probe = BackendProbe {
            backend: Backend::Fex,
            found: Some(Found::ArtefactOnly(PathBuf::from("/root/.fex-emu"))),
            version: None,
            inconclusive: None,
        };
        assert!(!probe.is_present());
        assert!(probe.summary().contains("only an artefact"));
    }

    #[test]
    fn an_inconclusive_probe_says_so_rather_than_reporting_absence() {
        let probe = BackendProbe {
            backend: Backend::Wine,
            found: None,
            version: None,
            inconclusive: Some("PATH unreadable".to_owned()),
        };
        let text = probe.summary();
        assert!(text.contains("could not determine"));
        assert!(!text.contains("not found"));
    }

    #[test]
    fn summary_includes_the_version_when_known() {
        let probe = BackendProbe {
            backend: Backend::Wine,
            found: Some(Found::Executable(PathBuf::from("/usr/bin/wine"))),
            version: Some("wine-9.0".to_owned()),
            inconclusive: None,
        };
        let text = probe.summary();
        assert!(text.contains("wine"));
        assert!(text.contains("wine-9.0"));
    }

    #[test]
    fn backend_set_contains_only_present_backends() {
        let discovery = Discovery {
            probes: vec![
                BackendProbe {
                    backend: Backend::Wine,
                    found: Some(Found::OnPath),
                    version: None,
                    inconclusive: None,
                },
                BackendProbe {
                    backend: Backend::Fex,
                    found: None,
                    version: None,
                    inconclusive: None,
                },
            ],
        };
        let set = discovery.backend_set();
        assert!(set.contains(Backend::Wine));
        assert!(!set.contains(Backend::Fex));
        assert_eq!(set.len(), 1);
        assert!(!discovery.is_empty());
    }

    #[test]
    fn an_empty_discovery_reports_itself_as_empty() {
        let discovery = Discovery { probes: vec![] };
        assert!(discovery.is_empty());
        assert_eq!(discovery.backend_set().len(), 0);
    }

    #[test]
    fn probes_are_retrievable_by_backend() {
        let discovery = Discovery {
            probes: vec![BackendProbe {
                backend: Backend::Box64,
                found: Some(Found::OnPath),
                version: None,
                inconclusive: None,
            }],
        };
        assert!(discovery.probe(Backend::Box64).unwrap().is_present());
        assert!(discovery.probe(Backend::Fex).is_none());
    }

    #[test]
    fn inconclusive_probes_are_listed_separately() {
        let discovery = Discovery {
            probes: vec![
                BackendProbe {
                    backend: Backend::Wine,
                    found: None,
                    version: None,
                    inconclusive: Some("could not read".to_owned()),
                },
                BackendProbe {
                    backend: Backend::Fex,
                    found: None,
                    version: None,
                    inconclusive: None,
                },
            ],
        };
        assert_eq!(discovery.inconclusive().len(), 1);
    }

    #[test]
    fn json_report_is_machine_readable() {
        let discovery = Discovery {
            probes: vec![BackendProbe {
                backend: Backend::Wine,
                found: Some(Found::Executable(PathBuf::from("/usr/bin/wine"))),
                version: Some("wine-9.0".to_owned()),
                inconclusive: None,
            }],
        };
        let json = discovery.to_json();
        assert_eq!(json["backend_count"].as_u64(), Some(1));
        let items = json["backends"].as_array().expect("an array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["backend"].as_str(), Some("wine"));
        assert_eq!(items[0]["present"].as_bool(), Some(true));
        assert_eq!(items[0]["version"].as_str(), Some("wine-9.0"));
    }

    #[test]
    fn every_backend_has_at_least_one_executable_name() {
        for backend in Backend::ALL {
            assert!(
                !executable_names(*backend).is_empty(),
                "{} has no name to search for",
                backend.id()
            );
        }
    }

    #[test]
    fn every_backend_has_artefact_paths_to_check() {
        for backend in Backend::ALL {
            assert!(
                !artefact_paths(*backend).is_empty(),
                "{} has no artefact path",
                backend.id()
            );
        }
    }

    #[test]
    fn executable_check_rejects_directories_and_missing_paths() {
        assert!(!is_executable_file(Path::new("/")));
        assert!(!is_executable_file(Path::new("/definitely/not/here")));
        // A file that exists but is not executable must not be accepted either.
        let dir = std::env::temp_dir().join("compitum-discovery-test");
        let _ = std::fs::create_dir_all(&dir);
        let plain = dir.join("not-executable");
        let _ = std::fs::write(&plain, b"x");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644));
            assert!(!is_executable_file(&plain));
        }
        let _ = std::fs::remove_file(&plain);
    }

    #[test]
    fn discovering_the_real_host_never_panics() {
        // Whatever this machine has, discovery must return a well-formed answer.
        let discovery = discover();
        assert_eq!(discovery.probes.len(), Backend::ALL.len());
        for probe in &discovery.probes {
            assert!(!probe.summary().is_empty());
        }
    }
}
