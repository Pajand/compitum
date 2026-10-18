# compitum-i18n

A localization engine whose base language is compiled in, and where adding a language means
dropping a JSON file rather than rebuilding the program.

Part of [COMPITUM](https://github.com/Pajand/compitum).

## The design contract

1. **English is compiled in.** The tool is fully functional with no external files and no
   configuration. A missing `locales/` directory is not an error.
2. **Translations are data, never code.** Adding a language means placing `<tag>.json` next to
   the executable, or pointing `COMPITUM_LOCALES` at a directory.
3. **Missing translations degrade gracefully.** A key absent from a locale falls back to
   English, and if somehow absent there too, the raw key is shown rather than an empty string.
   A half-finished community translation is therefore always usable.
4. **Machine output is never translated.** JSON keys and enum values stay English and stable
   forever. Only human-readable presentation strings are localized — otherwise a consumer
   parsing `route` would break the moment somebody added a language.

## Example

```rust
use compitum_i18n::{Catalog, Translator};

// The English base is always available.
let catalog = Catalog::english();
assert_eq!(catalog.language(), "en");
assert!(catalog.has("verdict.compatible"));

// A translator adds per-key fallback on top of a catalog.
let translator = Translator::english_only();
assert_eq!(translator.text("verdict.compatible"), "COMPATIBLE");
```

## Adding a language

Generate a complete skeleton containing every key, with empty values:

```console
$ compitum locales export fa > locales/fa.json
```

Fill in the values. Anything left empty falls back to English. Then check your progress:

```console
$ compitum locales check fa
```

Missing keys are permitted; **obsolete** keys fail the build, because a key the English base no
longer defines is dead weight that misleads the next translator.

## Why English is not translated

The base catalogue deliberately holds no protocol values. Route names such as `fex_partial`,
reason codes such as `isa_features_missing`, and JSON keys are *protocol*: they appear in stored
Oracle records and in other people's CI configuration. Translating them would break that.

## Licence

Apache-2.0 OR MIT, at your option.
