//! COMPITUM's localization engine.
//!
//! # Design contract
//!
//! * **English is the base locale.** Every user-facing message exists in English first
//!   and that text is compiled into the binary, so the tool is fully functional with
//!   zero external files and zero configuration.
//! * **Translations are data, never code.** Adding a language means dropping a
//!   `locales/<tag>.json` file next to the executable (or pointing `COMPITUM_LOCALES`
//!   at a directory). No recompilation, no rebuild, no source change.
//! * **Missing translations degrade gracefully.** A key missing from a locale falls
//!   back to English, and if somehow absent there too, the raw key is shown rather
//!   than an empty string or a panic. A half-finished community translation is
//!   therefore always usable.
//! * **Machine output is never translated.** JSON keys and enum values stay English
//!   and stable forever; only human-readable *presentation* strings are localized.
//!   This keeps the Oracle schema immutable across languages.
//!
//! # Locale file format
//!
//! ```json
//! {
//!   "language": "fa",
//!   "name": "Persian",
//!   "native_name": "فارسی",
//!   "direction": "rtl",
//!   "messages": {
//!     "route.native.label": "بومی",
//!     "verdict.compatible": "سازگار"
//!   }
//! }
//! ```
//!
//! Only `messages` is required. Unknown keys are ignored, which lets a translation be
//! written against a newer COMPITUM without breaking an older one.
//!
//! # Example
//!
//! ```
//! use compitum_i18n::{Catalog, Translator};
//!
//! // The English base catalog is compiled in and always available.
//! let catalog = Catalog::english();
//! assert_eq!(catalog.language(), "en");
//! assert!(catalog.has("verdict.compatible"));
//!
//! // A translator adds locale fallback behaviour on top of a catalog.
//! let translator = Translator::english_only();
//! assert_eq!(translator.text("verdict.compatible"), "COMPATIBLE");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use compitum_json::{parse, Value};

/// Text direction of a locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    /// Left-to-right (English, German, Japanese, …).
    #[default]
    Ltr,
    /// Right-to-left (Persian, Arabic, Hebrew, …).
    Rtl,
}

impl Direction {
    /// Parses a direction tag, defaulting to left-to-right for anything unrecognized.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        match text.trim().to_ascii_lowercase().as_str() {
            "rtl" => Direction::Rtl,
            _ => Direction::Ltr,
        }
    }

    /// Returns the canonical tag: `"ltr"` or `"rtl"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Ltr => "ltr",
            Direction::Rtl => "rtl",
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of a lookup, carrying provenance so callers can report translation gaps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// Found in the active locale.
    Exact(String),
    /// Not in the active locale; fell back to the English base text.
    FallbackEnglish(String),
    /// Not found anywhere; the key itself is returned so output is never blank.
    MissingKey(String),
}

impl Lookup {
    /// The text to display, regardless of where it came from.
    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            Lookup::Exact(s) | Lookup::FallbackEnglish(s) | Lookup::MissingKey(s) => s,
        }
    }

    /// Returns `true` when this lookup came from the English base locale.
    #[must_use]
    pub fn is_fallback(&self) -> bool {
        matches!(self, Lookup::FallbackEnglish(_))
    }

    /// Returns `true` when the key was not found anywhere.
    #[must_use]
    pub fn is_missing(&self) -> bool {
        matches!(self, Lookup::MissingKey(_))
    }
}

/// A loaded locale catalog.
#[derive(Debug, Clone)]
pub struct Catalog {
    language: String,
    name: String,
    native_name: String,
    direction: Direction,
    messages: BTreeMap<String, String>,
}

impl Catalog {
    /// Builds a catalog from parts. Used by [`Catalog::english`] and the loader.
    #[must_use]
    pub fn new(
        language: impl Into<String>,
        name: impl Into<String>,
        native_name: impl Into<String>,
        direction: Direction,
        messages: BTreeMap<String, String>,
    ) -> Self {
        Catalog {
            language: language.into(),
            name: name.into(),
            native_name: native_name.into(),
            direction,
            messages,
        }
    }

    /// The English base catalog, compiled into the binary.
    ///
    /// This is the canonical source of every message key COMPITUM emits.
    #[must_use]
    pub fn english() -> Self {
        let mut messages = BTreeMap::new();
        for (key, text) in BASE_ENGLISH {
            messages.insert((*key).to_owned(), (*text).to_owned());
        }
        Catalog::new("en", "English", "English", Direction::Ltr, messages)
    }

    /// Builds a catalog from a JSON document.
    ///
    /// # Errors
    ///
    /// Returns a message describing the first structural problem encountered.
    pub fn from_json(source: &str) -> Result<Self, String> {
        let doc = parse(source).map_err(|e| e.to_string())?;
        let language = doc["language"].as_str().unwrap_or("und").to_owned();
        let name = doc["name"].as_str().unwrap_or(&language).to_owned();
        let native_name = doc["native_name"].as_str().unwrap_or(&name).to_owned();
        let direction = Direction::parse(doc["direction"].as_str().unwrap_or("ltr"));

        let mut messages = BTreeMap::new();
        if let Some(object) = doc["messages"].as_object() {
            for (key, value) in object.iter() {
                if let Some(text) = value.as_str() {
                    messages.insert(key.to_owned(), text.to_owned());
                }
            }
        }
        if messages.is_empty() {
            return Err(format!(
                "locale `{language}` contains no usable `messages` entries"
            ));
        }
        Ok(Catalog::new(
            language,
            name,
            native_name,
            direction,
            messages,
        ))
    }

    /// Loads a locale from a file path.
    ///
    /// # Errors
    ///
    /// Returns a message if the file cannot be read or does not parse.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let source = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        Catalog::from_json(&source)
    }

    /// The BCP-47-ish language tag, e.g. `"en"` or `"fa"`.
    #[must_use]
    pub fn language(&self) -> &str {
        &self.language
    }

    /// The English name of the language, e.g. `"Persian"`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The language's own name for itself, e.g. `"فارسی"`.
    #[must_use]
    pub fn native_name(&self) -> &str {
        &self.native_name
    }

    /// The writing direction.
    #[must_use]
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Number of translated messages in this catalog.
    #[must_use]
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Returns `true` when the catalog holds no messages.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Returns `true` when this locale defines the given key.
    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        self.messages.contains_key(key)
    }

    /// Looks up a key within this catalog only, falling back to the English base text.
    fn lookup_within(&self, base: &BTreeMap<String, String>, key: &str) -> Lookup {
        if let Some(text) = self.messages.get(key) {
            return Lookup::Exact(text.clone());
        }
        match base.get(key) {
            Some(text) => Lookup::FallbackEnglish(text.clone()),
            None => Lookup::MissingKey(key.to_owned()),
        }
    }

    /// Iterates over every key defined in this catalog.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.messages.keys().map(String::as_str)
    }
}

/// The translation catalog set: one active locale plus the English base.
#[derive(Debug, Clone)]
pub struct Translator {
    base: Catalog,
    active: Catalog,
}

impl Default for Translator {
    fn default() -> Self {
        Translator::new(Catalog::english())
    }
}

impl Translator {
    /// Creates a translator with `active` as the display locale and English as fallback.
    #[must_use]
    pub fn new(active: Catalog) -> Self {
        Translator {
            base: Catalog::english(),
            active,
        }
    }

    /// Creates a translator that disables localization by using English for everything.
    #[must_use]
    pub fn english_only() -> Self {
        let catalog = Catalog::english();
        Translator {
            base: catalog.clone(),
            active: catalog,
        }
    }

    /// The active locale's tag.
    #[must_use]
    pub fn language(&self) -> &str {
        self.active.language()
    }

    /// The active locale.
    #[must_use]
    pub fn active(&self) -> &Catalog {
        &self.active
    }

    /// The English base locale.
    #[must_use]
    pub fn base(&self) -> &Catalog {
        &self.base
    }

    /// Looks up a key, returning the text with provenance.
    #[must_use]
    pub fn lookup(&self, key: &str) -> Lookup {
        let base_messages = &self.base.messages;
        self.active.lookup_within(base_messages, key)
    }

    /// Looks up a key and returns only the displayable text.
    #[must_use]
    pub fn text(&self, key: &str) -> String {
        self.lookup(key).text().to_owned()
    }

    /// Looks up a key, substituting `{name}` placeholders.
    ///
    /// Placeholders not present in `args` are left untouched, which makes a partially
    /// translated string safe: the reader still sees which value belongs where.
    #[must_use]
    pub fn format(&self, key: &str, args: &[(&str, &str)]) -> String {
        let mut out = self.text(key);
        for (name, value) in args {
            let needle = format!("{{{name}}}");
            if out.contains(&needle) {
                out = out.replace(&needle, value);
            }
        }
        out
    }

    /// Reports which keys of the English base are absent from the active locale.
    ///
    /// Used by `compitum locales check` so a translation can be validated in CI, and by
    /// contributors who want to see their remaining work.
    #[must_use]
    pub fn missing_keys(&self) -> Vec<String> {
        self.base
            .messages
            .keys()
            .filter(|key| !self.active.messages.contains_key(*key))
            .cloned()
            .collect()
    }

    /// Reports keys defined in the active locale that no longer exist in English.
    ///
    /// These are typically leftovers from an older COMPITUM version.
    #[must_use]
    pub fn obsolete_keys(&self) -> Vec<String> {
        self.active
            .messages
            .keys()
            .filter(|key| !self.base.messages.contains_key(*key))
            .cloned()
            .collect()
    }

    /// Percentage of the English base that the active locale covers, in `[0, 100]`.
    #[must_use]
    pub fn coverage_percent(&self) -> u32 {
        let total = self.base.messages.len();
        if total == 0 {
            return 100;
        }
        let translated = self
            .base
            .messages
            .keys()
            .filter(|key| self.active.messages.contains_key(*key))
            .count();
        ((translated * 100) / total) as u32
    }

    /// Produces a machine-readable report about the active locale, for the Oracle and CI.
    #[must_use]
    pub fn report(&self) -> Value {
        let missing = self.missing_keys();
        let obsolete = self.obsolete_keys();
        compitum_json::Object::new()
            .with("language", self.active.language())
            .with("name", self.active.name())
            .with("native_name", self.active.native_name())
            .with("direction", self.active.direction().as_str())
            .with("base_language", self.base.language())
            .with("base_message_count", self.base.messages.len())
            .with("translated_message_count", self.active.messages.len())
            .with("coverage_percent", self.coverage_percent())
            .with("missing_keys", missing)
            .with("obsolete_keys", obsolete)
            .into()
    }
}

/// Locates and loads locale catalogs from the filesystem.
///
/// Search order, first hit wins per language:
///
/// 1. `$COMPITUM_LOCALES` — an explicit directory override, used by tests and packaging.
/// 2. `./locales` — relative to the working directory, for development.
/// 3. `<dir of the executable>/locales` — for installed distributions.
#[derive(Debug, Clone)]
pub struct LocaleStore {
    roots: Vec<PathBuf>,
}

impl Default for LocaleStore {
    fn default() -> Self {
        LocaleStore::discover()
    }
}

impl LocaleStore {
    /// Builds a store from an explicit list of directories.
    #[must_use]
    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        LocaleStore { roots }
    }

    /// Discovers locale directories using the documented search order.
    #[must_use]
    pub fn discover() -> Self {
        let mut roots = Vec::new();
        if let Ok(dir) = std::env::var("COMPITUM_LOCALES") {
            if !dir.is_empty() {
                roots.push(PathBuf::from(dir));
            }
        }
        roots.push(PathBuf::from("locales"));
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                roots.push(parent.join("locales"));
                roots.push(parent.join("../share/compitum/locales"));
            }
        }
        LocaleStore { roots }
    }

    /// The directories this store searches, in order.
    #[must_use]
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Lists every locale tag available across all search roots.
    #[must_use]
    pub fn available(&self) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        for root in &self.roots {
            let Ok(entries) = std::fs::read_dir(root) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    let tag = stem.to_owned();
                    if !found.contains(&tag) {
                        found.push(tag);
                    }
                }
            }
        }
        found.sort();
        found
    }

    /// Loads a locale by tag.
    ///
    /// # Errors
    ///
    /// Returns a message when the tag is malformed or no file parses successfully.
    pub fn load(&self, tag: &str) -> Result<Catalog, String> {
        if tag.is_empty()
            || !tag
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!("invalid locale tag `{tag}`"));
        }
        for root in &self.roots {
            let path = root.join(format!("{tag}.json"));
            if path.is_file() {
                return Catalog::from_file(&path);
            }
        }
        Err(format!(
            "locale `{tag}` not found in: {}",
            self.roots
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }

    /// Resolves a locale from an environment-driven preference chain.
    ///
    /// Priority: explicit `requested` argument, then `$COMPITUM_LANG`, then `$LANG`,
    /// then English. Region suffixes are stripped progressively, so `fa_IR.UTF-8`
    /// resolves to a `fa.json` file when `fa_IR.json` does not exist.
    #[must_use]
    pub fn resolve(&self, requested: Option<&str>) -> Catalog {
        let candidates: Vec<String> = requested
            .map(str::to_owned)
            .or_else(|| std::env::var("COMPITUM_LANG").ok())
            .or_else(|| std::env::var("LANG").ok())
            .into_iter()
            .flat_map(|raw| expand_tag(&raw))
            .collect();

        for tag in candidates {
            if tag == "en" {
                return Catalog::english();
            }
            if let Ok(catalog) = self.load(&tag) {
                return catalog;
            }
        }
        Catalog::english()
    }
}

/// Expands a locale identifier into progressively simpler candidates.
///
/// `fa_IR.UTF-8@euro` becomes `["fa_IR", "fa"]`.
fn expand_tag(raw: &str) -> Vec<String> {
    let cleaned = raw.split('.').next().unwrap_or(raw);
    let cleaned = cleaned.split('@').next().unwrap_or(cleaned);
    let parts: Vec<&str> = cleaned.split(['_', '-']).collect();
    let mut out = Vec::new();
    if parts.is_empty() || parts[0].is_empty() || parts[0] == "C" || parts[0] == "POSIX" {
        return out;
    }
    out.push(parts[0].to_owned());
    if parts.len() > 1 && !parts[1].is_empty() {
        out.insert(0, format!("{}_{}", parts[0], parts[1]));
    }
    out
}

/// Every English message key COMPITUM knows about.
///
/// This table is the contract: the machine-readable surface (JSON keys, reason codes,
/// route names) is deliberately *not* here, because those are protocol and must never
/// be translated. Only human-facing presentation text lives in this table.
pub const BASE_ENGLISH: &[(&str, &str)] = &[
    // ---- Application shell -------------------------------------------------
    ("app.name", "COMPITUM"),
    ("app.tagline", "ABI-aware ARM64 compatibility layer"),
    ("app.about", "COMPITUM classifies ARM64 Windows binaries, inspects the host CPU, and routes execution to the fastest correct path."),

    // ---- Commands ----------------------------------------------------------
    ("cmd.inspect", "Classify a binary and report its ABI family and requirements"),
    ("cmd.verify", "Compare a binary against this host and decide if it can run"),
    ("cmd.host", "Report this machine's ARM64 capabilities and Linux ABI"),
    ("cmd.locales", "List, check or inspect translation catalogs"),
    ("cmd.locales.list", "List every locale found and its coverage"),
    ("cmd.locales.check", "Report missing and obsolete keys for a locale"),
    ("cmd.locales.export", "Write the English base catalog as a translation template"),
    ("cmd.oracle", "Record or query the compatibility ledger"),
    ("cmd.oracle.record", "Store a binary-versus-host observation"),
    ("cmd.oracle.query", "Search recorded observations"),
    ("cmd.oracle.stats", "Summarize the compatibility ledger"),

    // ---- Section headings --------------------------------------------------
    ("section.binary", "Binary"),
    ("section.host", "Host"),
    ("section.verdict", "Verdict"),
    ("section.details", "Details"),
    ("section.notes", "Notes"),
    ("section.machine", "Machine"),
    ("section.imports", "Imported modules"),
    ("section.requirements", "Requirements"),
    ("section.capabilities", "Capabilities"),

    // ---- Field labels ------------------------------------------------------
    ("field.path", "Path"),
    ("field.size", "Size"),
    ("field.sha256", "SHA-256"),
    ("field.format", "Format"),
    ("field.arch", "Architecture"),
    ("field.machine_raw", "Machine value"),
    ("field.subsystem", "Subsystem"),
    ("field.kind", "Kind"),
    ("field.mode", "Mode"),
    ("field.version", "Version"),
    ("field.cores", "CPU cores"),
    ("field.page_size", "Memory page size"),
    ("field.kernel", "Kernel"),
    ("field.features", "CPU features"),
    ("field.missing", "Missing"),
    ("field.present", "Present"),
    ("field.route", "Route"),
    ("field.confidence", "Confidence"),
    ("field.emulation", "Emulation"),
    ("field.reasons", "Reason codes"),
    ("field.explanation", "Explanation"),
    ("field.locale", "Locale"),
    ("field.direction", "Text direction"),
    ("field.coverage", "Coverage"),
    ("field.records", "Records"),
    ("field.observed", "Observed"),
    ("field.source", "Source"),

    // ---- Verdicts ----------------------------------------------------------
    ("verdict.compatible", "COMPATIBLE"),
    ("verdict.compatible_native", "COMPATIBLE — runs natively"),
    ("verdict.compatible_hybrid", "COMPATIBLE — runs hybrid (partial translation)"),
    ("verdict.compatible_emulated", "COMPATIBLE — runs emulated"),
    ("verdict.incompatible", "INCOMPATIBLE"),
    ("verdict.unknown", "UNKNOWN"),
    ("verdict.undetermined", "UNDETERMINED — insufficient information"),

    // ---- Explanations ------------------------------------------------------
    ("explain.native", "This binary is pure ARM64 and requires no CPU emulation here. Every CPU feature it needs is present on this host."),
    ("explain.hybrid", "This binary is ARM64EC: it contains both ARM64 and x86_64 code in a single image. The ARM64 portions run natively; the x86_64 portions must be translated at run time by FEX."),
    ("explain.emulated", "This binary is x86_64 and cannot execute natively on an ARM64 host. It requires a full user-mode binary translator such as Box64 or FEX."),
    ("explain.arm32", "This binary targets 32-bit ARM and requires a 32-bit translation layer."),
    ("explain.unsupported", "This binary targets an architecture COMPITUM cannot route."),
    ("explain.missing_features", "The binary uses CPU features that this host does not implement. Executing it natively would fault at the first such instruction."),
    ("explain.page_size_risk", "The binary was linked for a different memory page size than this host provides. This can cause failures that appear intermittent."),
    ("explain.no_emulator", "No suitable translation backend is installed on this host, so the required route cannot be taken."),

    // ---- Reason codes (human descriptions) ---------------------------------
    ("reason.arch_native", "architecture executes natively on this CPU"),
    ("reason.arch_requires_translation", "architecture requires binary translation"),
    ("reason.isa_subset_ok", "every required CPU feature is available"),
    ("reason.isa_missing", "one or more required CPU features are absent"),
    ("reason.page_size_match", "memory page size matches the host"),
    ("reason.page_size_mismatch", "memory page size differs from the host"),
    ("reason.subsystem_console", "console subsystem — suitable for headless execution"),
    ("reason.subsystem_gui", "graphical subsystem — requires a display layer"),
    ("reason.graphics_required", "imports a graphics API and needs a rendering backend"),

    // ---- Feature names -----------------------------------------------------
    ("feature.sve", "Scalable Vector Extension"),
    ("feature.sve2", "Scalable Vector Extension 2"),
    ("feature.sme", "Scalable Matrix Extension"),
    ("feature.mte", "Memory Tagging Extension"),
    ("feature.bf16", "Bfloat16 arithmetic"),
    ("feature.i8mm", "Int8 matrix multiplication"),
    ("feature.bti", "Branch Target Identification"),
    ("feature.lse", "Large System Extensions (atomics)"),
    ("feature.crc32", "CRC-32 instructions"),
    ("feature.fp16", "Half-precision floating point"),
    ("feature.dotprod", "Dot product instructions"),
    ("feature.aes", "AES instructions"),
    ("feature.sha2", "SHA-2 instructions"),
    ("feature.rng", "Random number generation"),
    ("feature.sb", "Speculation barrier"),
    ("feature.ssbs", "Speculative Store Bypass Safe"),

    // ---- Generic -----------------------------------------------------------
    ("state.yes", "yes"),
    ("state.no", "no"),
    ("state.unknown", "unknown"),
    ("state.none", "none"),
    ("state.ready", "ready"),
    ("label.key", "Key"),
    ("label.value", "Value"),
    ("label.total", "Total"),
    ("label.language", "Language"),
    ("label.native_name", "Native name"),

    // ---- Errors ------------------------------------------------------------
    ("error.file_not_found", "File not found: {path}"),
    ("error.not_pe", "Not a Portable Executable image: {path}"),
    ("error.truncated", "File is truncated; the header claims more data than is present"),
    ("error.unsupported_arch", "Unrecognized machine type 0x{value}"),
    ("error.locale_not_found", "Locale not found: {tag}"),
    ("error.oracle_path", "Cannot open the compatibility ledger at {path}"),
    ("error.usage", "Invalid command. Run `compitum --help` for usage."),

    // ---- Usage -------------------------------------------------------------
    ("usage.summary", "Usage: compitum <command> [options]"),
    ("usage.commands", "Commands"),
    ("usage.options", "Options"),
    ("usage.examples", "Examples"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_catalog_is_populated() {
        let catalog = Catalog::english();
        assert_eq!(catalog.language(), "en");
        assert_eq!(catalog.direction(), Direction::Ltr);
        assert!(!catalog.is_empty());
        assert!(catalog.has("verdict.compatible"));
        assert!(catalog.has("explain.native"));
    }

    #[test]
    fn english_has_no_duplicate_keys() {
        let mut seen = std::collections::BTreeSet::new();
        for (key, _) in BASE_ENGLISH {
            assert!(seen.insert(*key), "duplicate message key: {key}");
        }
    }

    #[test]
    fn lookup_returns_english_for_base_locale() {
        let translator = Translator::english_only();
        assert_eq!(
            translator.lookup("verdict.compatible"),
            Lookup::Exact("COMPATIBLE".into())
        );
        assert!(!translator.lookup("verdict.compatible").is_fallback());
    }

    #[test]
    fn missing_key_is_reported_not_blank() {
        let translator = Translator::english_only();
        let lookup = translator.lookup("does.not.exist");
        assert!(lookup.is_missing());
        assert_eq!(lookup.text(), "does.not.exist");
    }

    #[test]
    fn parses_locale_json() {
        let source = r#"{
            "language": "fa",
            "name": "Persian",
            "native_name": "Persian",
            "direction": "rtl",
            "messages": { "verdict.compatible": "COMPATIBLE-FA" }
        }"#;
        let catalog = Catalog::from_json(source).unwrap();
        assert_eq!(catalog.language(), "fa");
        assert_eq!(catalog.direction(), Direction::Rtl);
        assert_eq!(catalog.native_name(), "Persian");
        assert_eq!(catalog.len(), 1);
    }

    #[test]
    fn translation_overrides_and_falls_back() {
        let source = r#"{
            "language": "xx",
            "name": "Test",
            "messages": { "verdict.compatible": "OVERRIDDEN" }
        }"#;
        let catalog = Catalog::from_json(source).unwrap();
        let translator = Translator::new(catalog);

        assert_eq!(
            translator.lookup("verdict.compatible"),
            Lookup::Exact("OVERRIDDEN".into())
        );
        let fallback = translator.lookup("verdict.incompatible");
        assert!(fallback.is_fallback());
        assert_eq!(fallback.text(), "INCOMPATIBLE");
    }

    #[test]
    fn computes_missing_and_obsolete_keys() {
        let source = r#"{
            "language": "xx",
            "name": "Test",
            "messages": { "verdict.compatible": "A", "no.longer.used": "B" }
        }"#;
        let translator = Translator::new(Catalog::from_json(source).unwrap());
        assert!(translator
            .missing_keys()
            .contains(&"explain.native".to_owned()));
        assert_eq!(
            translator.obsolete_keys(),
            vec!["no.longer.used".to_owned()]
        );
    }

    #[test]
    fn coverage_is_percentage_of_base() {
        let translator = Translator::english_only();
        assert_eq!(translator.coverage_percent(), 100);

        let empty_ish = r#"{"language":"xx","name":"T","messages":{"verdict.compatible":"A"}}"#;
        let partial = Translator::new(Catalog::from_json(empty_ish).unwrap());
        assert!(partial.coverage_percent() < 100);
    }

    #[test]
    fn format_substitutes_placeholders() {
        let translator = Translator::english_only();
        let text = translator.format("error.file_not_found", &[("path", "/tmp/x.exe")]);
        assert_eq!(text, "File not found: /tmp/x.exe");
    }

    #[test]
    fn format_leaves_unknown_placeholders() {
        let translator = Translator::english_only();
        let text = translator.format("error.file_not_found", &[]);
        assert!(text.contains("{path}"));
    }

    #[test]
    fn rejects_locale_without_messages() {
        assert!(Catalog::from_json(r#"{"language":"xx","messages":{}}"#).is_err());
        assert!(Catalog::from_json("not json").is_err());
    }

    #[test]
    fn expands_language_tags() {
        assert_eq!(
            expand_tag("fa_IR.UTF-8"),
            vec!["fa_IR".to_owned(), "fa".to_owned()]
        );
        assert_eq!(expand_tag("en"), vec!["en".to_owned()]);
        assert_eq!(
            expand_tag("de-DE"),
            vec!["de_DE".to_owned(), "de".to_owned()]
        );
        assert!(expand_tag("C").is_empty());
        assert!(expand_tag("POSIX").is_empty());
    }

    #[test]
    fn default_translator_is_english() {
        let translator = Translator::default();
        assert_eq!(translator.language(), "en");
        assert_eq!(translator.coverage_percent(), 100);
    }

    #[test]
    fn report_is_machine_readable() {
        let report = Translator::english_only().report();
        assert_eq!(report["language"].as_str(), Some("en"));
        assert_eq!(report["coverage_percent"].as_u64(), Some(100));
        assert!(report["missing_keys"].as_array().is_some());
    }

    #[test]
    fn store_reports_unknown_locale() {
        let store = LocaleStore::with_roots(vec![PathBuf::from("/nonexistent-locale-dir")]);
        assert!(store.load("zz").is_err());
        assert!(store.available().is_empty());
    }

    #[test]
    fn store_rejects_bad_tag() {
        let store = LocaleStore::with_roots(vec![]);
        assert!(store.load("../etc/passwd").is_err());
        assert!(store.load("").is_err());
    }

    #[test]
    fn store_falls_back_to_english() {
        let store = LocaleStore::with_roots(vec![PathBuf::from("/nonexistent-locale-dir")]);
        let catalog = store.resolve(Some("zz_ZZ"));
        assert_eq!(catalog.language(), "en");
    }

    #[test]
    fn direction_parsing() {
        assert_eq!(Direction::parse("RTL"), Direction::Rtl);
        assert_eq!(Direction::parse("ltr"), Direction::Ltr);
        assert_eq!(Direction::parse("nonsense"), Direction::Ltr);
        assert_eq!(Direction::Rtl.as_str(), "rtl");
    }
}
