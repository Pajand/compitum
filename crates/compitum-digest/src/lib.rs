//! SHA-256, implemented from FIPS 180-4, with no external dependencies.
//!
//! # Why this is hand-written
//!
//! COMPITUM's doctrine forbids third-party crates in the core (see ROADMAP Law 5): the
//! workspace must build offline and remain trivially auditable. A hash function is the one
//! piece of cryptography that is genuinely safe to implement by hand, because it is fully
//! specified, has published test vectors, and has no secret inputs to leak.
//!
//! This is **not** a general-purpose cryptographic library. It is a content-addressing
//! primitive: the output identifies a binary in the Oracle so that the same file is
//! recognised across machines and years. It provides no authentication, no key derivation,
//! and no protection against a deliberate collision attack by a nation-state.
//!
//! # What it is used for
//!
//! Each Oracle record is keyed on the SHA-256 of the binary it describes. That means two
//! people who analyse the same release independently produce records that join, and a
//! record written today still refers to the same bytes in five years.
//!
//! # Correctness
//!
//! Verified against the three FIPS 180-4 vectors and the standard multi-block cases,
//! including the padding edge cases at 55, 56, 63 and 64 bytes where the length field
//! forces an extra block.

/// The digest length in bytes.
pub const DIGEST_LEN: usize = 32;

/// A SHA-256 digest.
///
/// Stored as raw bytes and rendered as lowercase hex on demand. Comparison is bytewise,
/// which avoids any timing subtlety; there is no secret here to protect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; DIGEST_LEN]);

impl Digest {
    /// The digest of the empty input.
    ///
    /// Published in FIPS 180-4 and asserted in the tests below.
    pub const EMPTY: Digest = Digest([
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
        0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
        0x78, 0x52, 0xb8, 0x55,
    ]);

    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DIGEST_LEN]) -> Self {
        Digest(bytes)
    }

    /// Borrows the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }

    /// Renders as 64 lowercase hex characters.
    ///
    /// Lowercase is the convention used by every tool that publishes checksums, and it is
    /// what makes a COMPITUM record comparable with `sha256sum` output by eye.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(DIGEST_LEN * 2);
        for byte in self.0 {
            out.push(nibble_to_hex(byte >> 4));
            out.push(nibble_to_hex(byte & 0x0F));
        }
        out
    }

    /// The first eight hex characters, for compact display.
    ///
    /// Long enough to be effectively unique within a single report, short enough to read.
    #[must_use]
    pub fn short(&self) -> String {
        self.to_hex().chars().take(8).collect()
    }

    /// Parses a 64-character hex digest.
    ///
    /// Accepts uppercase as well as lowercase, because checksum files in the wild use both.
    ///
    /// # Errors
    ///
    /// Returns a message when the input is not exactly 64 hex characters.
    pub fn from_hex(text: &str) -> Result<Self, String> {
        let trimmed = text.trim();
        if trimmed.len() != DIGEST_LEN * 2 {
            return Err(format!(
                "a SHA-256 digest is {} hex characters, got {}",
                DIGEST_LEN * 2,
                trimmed.len()
            ));
        }
        let mut bytes = [0u8; DIGEST_LEN];
        let chars: Vec<char> = trimmed.chars().collect();
        for (index, slot) in bytes.iter_mut().enumerate() {
            let hi = hex_to_nibble(chars[index * 2])?;
            let lo = hex_to_nibble(chars[index * 2 + 1])?;
            *slot = (hi << 4) | lo;
        }
        Ok(Digest(bytes))
    }
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        _ => char::from(b'a' + (value - 10)),
    }
}

fn hex_to_nibble(c: char) -> Result<u8, String> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'a'..='f' => Ok(c as u8 - b'a' + 10),
        'A'..='F' => Ok(c as u8 - b'A' + 10),
        _ => Err(format!("`{c}` is not a hex digit")),
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The SHA-256 round constants: the first 32 bits of the fractional parts of the cube roots
/// of the first 64 primes.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The initial hash state: the first 32 bits of the fractional parts of the square roots of
/// the first eight primes.
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// An incremental SHA-256 hasher.
///
/// Incremental rather than whole-buffer because a Windows binary is frequently hundreds of
/// megabytes, and reading one into memory purely to hash it would make COMPITUM unusable on
/// the machines it is meant to help.
#[derive(Debug, Clone)]
pub struct Hasher {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    total_len: u64,
}

impl Default for Hasher {
    fn default() -> Self {
        Hasher::new()
    }
}

impl Hasher {
    /// Creates a hasher in its initial state.
    #[must_use]
    pub fn new() -> Self {
        Hasher {
            state: H0,
            buffer: [0u8; 64],
            buffered: 0,
            total_len: 0,
        }
    }

    /// Feeds bytes into the hash.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        // Top up a partially filled block first.
        if self.buffered > 0 {
            let need = 64 - self.buffered;
            let take = need.min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }

        // Consume whole blocks directly from the input, with no copy.
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            let mut buffer = [0u8; 64];
            buffer.copy_from_slice(block);
            self.compress(&buffer);
            data = rest;
        }

        // Retain the remainder.
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    /// Finishes the hash and returns the digest.
    ///
    /// Consumes the hasher, which prevents the easy mistake of finalising twice and getting
    /// two different answers from the same data.
    #[must_use]
    pub fn finalize(mut self) -> Digest {
        let bit_len = self.total_len.wrapping_mul(8);

        // Padding: a single 1 bit, then zeroes, then the 64-bit length, such that the total
        // is a multiple of 64 bytes. Appending 0x80 is that 1 bit followed by seven zeroes.
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;

        if self.buffered > 56 {
            // No room for the length in this block: zero-fill, compress, start a fresh one.
            for slot in self.buffer[self.buffered..].iter_mut() {
                *slot = 0;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffered = 0;
        }

        for slot in self.buffer[self.buffered..56].iter_mut() {
            *slot = 0;
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        let mut out = [0u8; DIGEST_LEN];
        for (index, word) in self.state.iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        Digest(out)
    }

    /// Processes one 64-byte block.
    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// Hashes a byte slice in one call.
#[must_use]
pub fn sha256(data: &[u8]) -> Digest {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Hashes a file's contents without reading it all into memory.
///
/// Reads in 64 KiB chunks, which is large enough to amortise the syscall cost and small
/// enough that hashing a multi-gigabyte image does not exhaust a phone's memory.
///
/// # Errors
///
/// Returns a description of the I/O failure, including the path.
pub fn sha256_file(path: &std::path::Path) -> Result<Digest, String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)
        .map_err(|e| format!("cannot open {} for hashing: {e}", path.display()))?;
    let mut hasher = Hasher::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("cannot read {} while hashing: {e}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Renders a digest for comparison against published vectors.
    fn hex_of(data: &[u8]) -> String {
        sha256(data).to_hex()
    }

    #[test]
    fn fips_180_4_vector_abc() {
        assert_eq!(
            hex_of(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn fips_180_4_vector_two_block() {
        assert_eq!(
            hex_of(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn fips_180_4_vector_million_a() {
        // The third published vector: one million repetitions of 'a'.
        let mut hasher = Hasher::new();
        let chunk = vec![b'a'; 1000];
        for _ in 0..1000 {
            hasher.update(&chunk);
        }
        assert_eq!(
            hasher.finalize().to_hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn empty_input_matches_the_published_constant() {
        assert_eq!(sha256(b""), Digest::EMPTY);
        assert_eq!(
            sha256(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn padding_boundaries_are_handled() {
        // Lengths 55/56 straddle the point where the 64-bit length field no longer fits in
        // the final block, and 63/64 straddle the end of a block. These are where a
        // hand-written SHA-256 most often goes wrong, so all four are pinned.
        //
        // Every expected value below was taken from GNU coreutils `sha256sum`, not from
        // memory. An earlier revision of this test contained an invented vector for
        // length 63, which is precisely the failure mode this comment exists to prevent:
        // a test that asserts a made-up value passes until the day it matters.
        let cases: [(usize, &str); 4] = [
            (55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"),
            (56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"),
            (63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"),
            (64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"),
        ];
        for (len, want) in cases {
            let data = vec![b'a'; len];
            assert_eq!(hex_of(&data), want, "length {len}");
        }
    }

    #[test]
    fn length_55_and_56_differ_and_both_hash() {
        // A weaker but version-independent property: the two must not collide, and both
        // must produce a full-length digest.
        let a = hex_of(&vec![b'a'; 55]);
        let b = hex_of(&vec![b'a'; 56]);
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert_eq!(b.len(), 64);
    }

    #[test]
    fn incremental_matches_one_shot() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let one_shot = sha256(&data);

        // Feed in irregular chunks, including sizes that straddle block boundaries.
        for chunk_size in [1usize, 7, 63, 64, 65, 127, 128, 1000, 4999] {
            let mut hasher = Hasher::new();
            for chunk in data.chunks(chunk_size) {
                hasher.update(chunk);
            }
            assert_eq!(
                hasher.finalize(),
                one_shot,
                "chunk size {chunk_size} disagreed with the one-shot hash"
            );
        }
    }

    #[test]
    fn feeding_one_byte_at_a_time_is_correct() {
        let mut hasher = Hasher::new();
        for byte in b"The quick brown fox jumps over the lazy dog" {
            hasher.update(&[*byte]);
        }
        assert_eq!(
            hasher.finalize().to_hex(),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }

    #[test]
    fn many_empty_updates_do_not_change_the_result() {
        let mut hasher = Hasher::new();
        for _ in 0..64 {
            hasher.update(b"");
        }
        assert_eq!(hasher.finalize(), sha256(b""));
    }

    #[test]
    fn hex_round_trips() {
        let digest = sha256(b"compitum");
        let hex = digest.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(Digest::from_hex(&hex).unwrap(), digest);
        // Uppercase input, as found in checksum files, must parse to the same value.
        assert_eq!(Digest::from_hex(&hex.to_uppercase()).unwrap(), digest);
    }

    #[test]
    fn hex_parsing_rejects_malformed_input() {
        assert!(Digest::from_hex("").is_err());
        assert!(Digest::from_hex("abcd").is_err());
        assert!(Digest::from_hex(&"z".repeat(64)).is_err());
        // One character short.
        assert!(Digest::from_hex(&"a".repeat(63)).is_err());
        // One character long.
        assert!(Digest::from_hex(&"a".repeat(65)).is_err());
    }

    #[test]
    fn short_form_is_eight_characters_and_a_prefix() {
        let digest = sha256(b"compitum");
        let short = digest.short();
        assert_eq!(short.len(), 8);
        assert!(digest.to_hex().starts_with(&short));
    }

    #[test]
    fn distinct_inputs_produce_distinct_digests() {
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..256u32 {
            let digest = sha256(&i.to_le_bytes()).to_hex();
            assert!(seen.insert(digest), "collision at {i}");
        }
    }

    #[test]
    fn one_bit_change_changes_the_digest() {
        assert_ne!(sha256(b"compitum"), sha256(b"compituM"));
        assert_ne!(sha256(&[0u8]), sha256(&[1u8]));
    }

    #[test]
    fn hashes_a_file_from_disk() {
        let dir = std::env::temp_dir().join("compitum-digest-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.bin");
        std::fs::write(&path, b"abc").unwrap();

        assert_eq!(
            sha256_file(&path).unwrap().to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hashing_a_large_file_streams_correctly() {
        let dir = std::env::temp_dir().join("compitum-digest-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("large.bin");
        // Comfortably larger than one 64 KiB read buffer, so the chunking loop runs twice
        // or more and the boundary case is exercised.
        let data = vec![0xABu8; 200_000];
        std::fs::write(&path, &data).unwrap();

        assert_eq!(sha256_file(&path).unwrap(), sha256(&data));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_an_error_not_a_panic() {
        let path = std::path::Path::new("/nonexistent/definitely/not/here.bin");
        let error = sha256_file(path).unwrap_err();
        assert!(error.contains("cannot open"), "got: {error}");
    }
}
