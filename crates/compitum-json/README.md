# compitum-json

A minimal, dependency-free JSON implementation: value type, strict RFC 8259 parser, and a
deterministic serializer.

Part of [COMPITUM](https://github.com/compitum-dev/compitum), an ABI-aware ARM64 compatibility layer.
This crate has no dependencies and no knowledge of ARM64; it exists because the project's
doctrine forbids third-party crates in the core, and JSON is needed for the compatibility
ledger.

## Why this exists

Two properties matter more than features here:

* **Nothing to compromise.** Zero dependencies means zero supply chain. The workspace builds
  offline.
* **A parser that cannot be crashed.** Input is frequently a ledger written by a different
  version of the tool, or a crafted file. Every read is bounds-checked and nesting depth is
  bounded, so malformed input produces an error rather than a panic or a stack overflow.

## Example

```rust
use compitum_json::{Value, parse};

let value = parse(r#"{"machine":"ARM64","cores":20}"#).unwrap();
assert_eq!(value["machine"].as_str(), Some("ARM64"));
assert_eq!(value["cores"].as_u64(), Some(20));
assert_eq!(value.to_string(), r#"{"machine":"ARM64","cores":20}"#);
```

Missing keys return `null` rather than failing, so nested access chains are panic-free:

```rust
use compitum_json::parse;

let doc = parse(r#"{"a":1}"#).unwrap();
assert!(doc["missing"]["deeper"].is_null());
```

## Behaviour worth knowing

| Aspect | Behaviour |
|---|---|
| Key order | Preserved as first inserted, so emitted documents are stable and diff-friendly |
| Non-finite floats | Serialized as `null`, because JSON cannot represent them |
| Trailing content | An error, so a truncated or concatenated document is never silently accepted |
| Nesting depth | Bounded at 128, avoiding a stack overflow on hostile input |
| Surrogate pairs | Handled, including the rejection of unpaired surrogates |
| Duplicate keys | Last value wins, matching common practice |

## Licence

Apache-2.0 OR MIT, at your option.
