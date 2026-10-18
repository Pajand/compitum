# compitum-digest

SHA-256 (FIPS 180-4) with a streaming interface, implemented from the specification with no
external dependencies.

Part of [COMPITUM](https://github.com/compitum-dev/compitum). This crate exists to content-address
binaries in the compatibility ledger: a record must still refer to the same code in five years,
after every filename and version number has changed.

## What this is, and is not

This is a **content-addressing primitive**, not a cryptography library.

* It is safe to hand-write: SHA-256 is fully specified, has published test vectors, and has no
  secret inputs to leak.
* It is verified against the three FIPS 180-4 vectors and the padding edge cases at 55, 56, 63
  and 64 bytes, with every expected value taken from GNU coreutils rather than from memory.
* It provides **no** authentication, no key derivation, and no protection against a deliberate
  collision attack by a well-resourced adversary. It identifies bytes, nothing more.

## Example

```rust
use compitum_digest::sha256;

assert_eq!(
    sha256(b"abc").to_hex(),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
);
```

Streaming, for a binary too large to hold in memory — which every real Windows executable is:

```rust
use compitum_digest::Hasher;

let mut hasher = Hasher::new();
hasher.update(b"The quick brown ");
hasher.update(b"fox jumps over the lazy dog");
assert_eq!(
    hasher.finalize().to_hex(),
    "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
);
```

Hashing a file reads in 64 KiB chunks, so a multi-gigabyte image does not exhaust memory:

```rust
use compitum_digest::sha256_file;

let digest = sha256_file(std::path::Path::new("/bin/sh")).unwrap();
assert_eq!(digest.to_hex().len(), 64);
```

## Licence

Apache-2.0 OR MIT, at your option.
