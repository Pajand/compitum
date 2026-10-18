//! A minimal, dependency-free JSON implementation.
//!
//! COMPITUM deliberately avoids third-party crates (see ROADMAP Law 5): the whole
//! workspace must build offline and remain trivially auditable. This module provides
//! exactly the JSON surface the project needs, and nothing more.
//!
//! # Scope
//!
//! * A [`Value`] enum covering the six JSON types.
//! * A strict RFC 8259 parser with useful, line-aware error messages.
//! * A deterministic serializer (stable key order on write, insertion order kept).
//!
//! # Non-goals
//!
//! * Streaming / incremental parsing.
//! * `serde` compatibility or derive macros.
//! * Arbitrary-precision numbers.
//!
//! # Example
//!
//! ```
//! use compitum_json::{Value, parse};
//!
//! let value = parse(r#"{"machine":"ARM64","cores":20}"#).unwrap();
//! assert_eq!(value["machine"].as_str(), Some("ARM64"));
//! assert_eq!(value["cores"].as_u64(), Some(20));
//! assert_eq!(value.to_string(), r#"{"machine":"ARM64","cores":20}"#);
//! ```

#![forbid(unsafe_code)]
// The crate README is included as documentation, which makes every Rust example in it a
// compiled doctest. An example that is not compiled is an example that silently rots, and a
// wrong example on a crate page is worse than no example at all.
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use std::fmt::{self, Display, Write as _};

/// A JSON value.
///
/// Objects preserve insertion order while being built, and are serialized in the
/// order the keys were first inserted. This keeps COMPITUM's emitted documents
/// stable and diff-friendly across runs.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`
    Null,
    /// `true` or `false`
    Bool(bool),
    /// A signed or unsigned integer that fits in `i64`.
    Int(i64),
    /// A floating point number.
    Float(f64),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object.
    Object(Object),
}

impl Value {
    /// Creates an empty object.
    #[must_use]
    pub fn object() -> Self {
        Value::Object(Object::new())
    }

    /// Creates an empty array.
    #[must_use]
    pub fn array() -> Self {
        Value::Array(Vec::new())
    }

    /// Returns `true` if this value is `null`.
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Borrows this value as a string slice.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// Borrows this value as a boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns this value as an unsigned integer.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Int(i) if *i >= 0 => Some(*i as u64),
            _ => None,
        }
    }

    /// Returns this value as a signed integer.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns this value as a float, widening integers.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            Value::Int(i) => Some(*i as f64),
            _ => None,
        }
    }

    /// Borrows this value as an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Mutably borrows this value as an array.
    #[must_use]
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Borrows this value as an object.
    #[must_use]
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Mutably borrows this value as an object.
    #[must_use]
    pub fn as_object_mut(&mut self) -> Option<&mut Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Looks up a key, returning [`Value::Null`] when absent.
    ///
    /// This makes nested access chains ergonomic and panic-free:
    /// `doc["host"]["cpu"]["cores"]` is `null` rather than an error when any level is
    /// missing. Reading configuration and Oracle records should never be able to abort
    /// the process.
    #[must_use]
    pub fn get(&self, key: &str) -> &Value {
        match self {
            Value::Object(o) => o.get(key).unwrap_or(&NULL),
            _ => &NULL,
        }
    }
}

/// A shared `null` value, so [`Value::get`] can return a reference without allocating.
static NULL: Value = Value::Null;

impl std::ops::Index<&str> for Value {
    type Output = Value;

    fn index(&self, key: &str) -> &Self::Output {
        self.get(key)
    }
}

/// A JSON object with stable insertion-ordered keys.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Object {
    entries: Vec<(String, Value)>,
}

impl Object {
    /// Creates an empty object.
    #[must_use]
    pub fn new() -> Self {
        Object {
            entries: Vec::new(),
        }
    }

    /// Inserts or replaces a key, preserving first-insertion position.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) {
        let key = key.into();
        let value = value.into();
        if let Some(slot) = self.entries.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
            return;
        }
        self.entries.push((key, value));
    }

    /// Builder-style insert.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.insert(key, value);
        self
    }

    /// Looks up a key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Returns `true` when the key is present.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.iter().any(|(k, _)| k == key)
    }

    /// Iterates over the entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::String(v.to_owned())
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::String(v)
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::Int(v)
    }
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Int(i64::from(v))
    }
}

impl From<u32> for Value {
    fn from(v: u32) -> Self {
        Value::Int(i64::from(v))
    }
}

impl From<u64> for Value {
    fn from(v: u64) -> Self {
        match i64::try_from(v) {
            Ok(i) => Value::Int(i),
            Err(_) => Value::Float(v as f64),
        }
    }
}

impl From<usize> for Value {
    fn from(v: usize) -> Self {
        Value::from(v as u64)
    }
}

impl From<u16> for Value {
    fn from(v: u16) -> Self {
        Value::Int(i64::from(v))
    }
}

impl From<u8> for Value {
    fn from(v: u8) -> Self {
        Value::Int(i64::from(v))
    }
}

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Float(v)
    }
}

/// Converts any homogeneous vector whose element type is itself convertible into a JSON
/// array.
///
/// This is what lets `Object::with("missing_keys", vec_of_strings)` work without every
/// call site hand-building a `Vec<Value>` first.
impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Value::Array(v.into_iter().map(Into::into).collect())
    }
}

impl From<Object> for Value {
    fn from(v: Object) -> Self {
        Value::Object(v)
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(inner) => inner.into(),
            None => Value::Null,
        }
    }
}

/// Serializes a value as compact JSON.
impl Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_compact(self, f)
    }
}

fn write_compact(value: &Value, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match value {
        Value::Null => f.write_str("null"),
        Value::Bool(true) => f.write_str("true"),
        Value::Bool(false) => f.write_str("false"),
        Value::Int(i) => write!(f, "{i}"),
        Value::Float(x) => write_float(*x, f),
        Value::String(s) => write_string(s, f),
        Value::Array(items) => {
            f.write_char('[')?;
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    f.write_char(',')?;
                }
                write_compact(item, f)?;
            }
            f.write_char(']')
        }
        Value::Object(obj) => {
            f.write_char('{')?;
            for (idx, (key, val)) in obj.entries.iter().enumerate() {
                if idx > 0 {
                    f.write_char(',')?;
                }
                write_string(key, f)?;
                f.write_char(':')?;
                write_compact(val, f)?;
            }
            f.write_char('}')
        }
    }
}

/// Writes a float in a way that round-trips and never emits `NaN`/`inf`,
/// which are not representable in JSON.
fn write_float(x: f64, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if x.is_nan() || x.is_infinite() {
        return f.write_str("null");
    }
    if x == x.trunc() && x.abs() < 1e15 {
        return write!(f, "{x:.1}");
    }
    write!(f, "{x}")
}

/// Appends the JSON-quoted form of `s` (including the surrounding quotes) to `out`.
///
/// This is the single source of truth for string escaping; both the compact and the
/// pretty serializer route through it, so they can never disagree.
fn escape_into(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u");
                for nibble in [12u32, 8, 4, 0] {
                    let digit = (c as u32 >> nibble) & 0xF;
                    out.push(char::from_digit(digit, 16).unwrap_or('0'));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_string(s: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut buf = String::with_capacity(s.len() + 2);
    escape_into(s, &mut buf);
    f.write_str(&buf)
}

/// Serializes a value to a `String` of compact JSON.
#[must_use]
pub fn to_string(value: &Value) -> String {
    value.to_string()
}

/// Serializes a value, indenting nested structures with two spaces.
///
/// Used for the human-readable CLI output; machine consumers should use
/// [`to_string`] instead.
#[must_use]
pub fn to_pretty(value: &Value) -> String {
    let mut out = String::new();
    write_pretty(value, 0, &mut out);
    out
}

fn write_pretty(value: &Value, depth: usize, out: &mut String) {
    let pad = |n: usize, out: &mut String| {
        for _ in 0..n {
            out.push_str("  ");
        }
    };
    match value {
        Value::Array(items) if !items.is_empty() => {
            out.push_str("[\n");
            for (idx, item) in items.iter().enumerate() {
                pad(depth + 1, out);
                write_pretty(item, depth + 1, out);
                if idx + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            pad(depth, out);
            out.push(']');
        }
        Value::Object(obj) if !obj.is_empty() => {
            out.push_str("{\n");
            for (idx, (key, val)) in obj.entries.iter().enumerate() {
                pad(depth + 1, out);
                escape_into(key, out);
                out.push_str(": ");
                write_pretty(val, depth + 1, out);
                if idx + 1 < obj.entries.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            pad(depth, out);
            out.push('}');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// A parse error, with a byte offset and a human-readable reason.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    /// Byte offset into the input where the problem was detected.
    pub offset: usize,
    /// Human-readable description of the problem.
    pub message: String,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "JSON parse error at byte {}: {}",
            self.offset, self.message
        )
    }
}

impl std::error::Error for ParseError {}

/// Parses a complete JSON document.
///
/// Trailing whitespace is permitted; trailing non-whitespace is an error, so a
/// truncated or concatenated document is never silently accepted.
///
/// # Errors
///
/// Returns a [`ParseError`] describing the first structural or lexical problem.
pub fn parse(input: &str) -> Result<Value, ParseError> {
    let mut parser = Parser {
        bytes: input.as_bytes(),
        pos: 0,
        depth: 0,
    };
    parser.skip_ws();
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(parser.err("unexpected trailing content"));
    }
    Ok(value)
}

/// Maximum nesting depth accepted by the parser, to bound recursion.
const MAX_DEPTH: usize = 128;

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, message: impl Into<String>) -> ParseError {
        ParseError {
            offset: self.pos,
            message: message.into(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), ParseError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(format!("expected '{}'", byte as char)))
        }
    }

    fn parse_value(&mut self) -> Result<Value, ParseError> {
        if self.depth > MAX_DEPTH {
            return Err(self.err("maximum nesting depth exceeded"));
        }
        match self.peek() {
            None => Err(self.err("unexpected end of input")),
            Some(b'n') => self.parse_literal("null", Value::Null),
            Some(b't') => self.parse_literal("true", Value::Bool(true)),
            Some(b'f') => self.parse_literal("false", Value::Bool(false)),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(other) => Err(self.err(format!("unexpected character '{}'", other as char))),
        }
    }

    fn parse_literal(&mut self, word: &str, value: Value) -> Result<Value, ParseError> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.err(format!("expected literal `{word}`")))
        }
    }

    fn parse_array(&mut self) -> Result<Value, ParseError> {
        self.expect(b'[')?;
        self.depth += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(self.err("expected ',' or ']' in array")),
            }
        }
        self.depth -= 1;
        Ok(Value::Array(items))
    }

    fn parse_object(&mut self) -> Result<Value, ParseError> {
        self.expect(b'{')?;
        self.depth += 1;
        let mut obj = Object::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Value::Object(obj));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected string key in object"));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.parse_value()?;
            obj.insert(key, value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(self.err("expected ',' or '}' in object")),
            }
        }
        self.depth -= 1;
        Ok(Value::Object(obj))
    }

    fn parse_string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let byte = match self.peek() {
                Some(b) => b,
                None => return Err(self.err("unterminated string")),
            };
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let esc = self.peek().ok_or_else(|| self.err("unterminated escape"))?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.parse_unicode_escape()?),
                        other => {
                            return Err(
                                self.err(format!("invalid escape sequence '\\{}'", other as char))
                            )
                        }
                    }
                }
                _ if byte < 0x20 => {
                    return Err(self.err("raw control character in string"));
                }
                _ => {
                    // Decode one UTF-8 scalar starting at the current position.
                    let rest = &self.bytes[self.pos..];
                    let decoded = std::str::from_utf8(rest)
                        .map_err(|_| self.err("invalid UTF-8 in string"))?;
                    let ch = decoded
                        .chars()
                        .next()
                        .ok_or_else(|| self.err("empty string"))?;
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, ParseError> {
        let hi = self.parse_hex4()?;
        // Surrogate pair handling: high surrogate must be followed by \uDC00-\uDFFF.
        if (0xD800..=0xDBFF).contains(&hi) {
            if self.peek() == Some(b'\\') {
                self.pos += 1;
                self.expect(b'u')?;
                let lo = self.parse_hex4()?;
                if (0xDC00..=0xDFFF).contains(&lo) {
                    let combined = 0x1_0000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                    return char::from_u32(combined)
                        .ok_or_else(|| self.err("invalid surrogate pair"));
                }
                return Err(self.err("unpaired high surrogate"));
            }
            return Err(self.err("unpaired high surrogate"));
        }
        char::from_u32(hi).ok_or_else(|| self.err("invalid unicode escape"))
    }

    fn parse_hex4(&mut self) -> Result<u32, ParseError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let byte = self
                .peek()
                .ok_or_else(|| self.err("truncated \\u escape"))?;
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a') + 10,
                b'A'..=b'F' => u32::from(byte - b'A') + 10,
                _ => return Err(self.err("invalid hex digit in \\u escape")),
            };
            value = value * 16 + digit;
            self.pos += 1;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        // Integer part.
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.err("invalid number")),
        }
        let mut is_float = false;
        // Fraction.
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("expected digit after decimal point"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        // Exponent.
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("expected digit in exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.err("invalid number encoding"))?;
        if is_float {
            text.parse::<f64>()
                .map(Value::Float)
                .map_err(|_| self.err("number out of range"))
        } else {
            match text.parse::<i64>() {
                Ok(i) => Ok(Value::Int(i)),
                Err(_) => text
                    .parse::<f64>()
                    .map(Value::Float)
                    .map_err(|_| self.err("number out of range")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scalars() {
        assert_eq!(parse("null").unwrap(), Value::Null);
        assert_eq!(parse("true").unwrap(), Value::Bool(true));
        assert_eq!(parse("false").unwrap(), Value::Bool(false));
        assert_eq!(parse("42").unwrap(), Value::Int(42));
        assert_eq!(parse("-7").unwrap(), Value::Int(-7));
        assert_eq!(parse("3.5").unwrap(), Value::Float(3.5));
        assert_eq!(parse("1e3").unwrap(), Value::Float(1000.0));
        assert_eq!(parse(r#""hi""#).unwrap(), Value::String("hi".into()));
    }

    #[test]
    fn parses_nested_structures() {
        let v = parse(r#"{"a":[1,2,{"b":true}],"c":null}"#).unwrap();
        assert_eq!(v["a"].as_array().unwrap().len(), 3);
        assert_eq!(v["a"].as_array().unwrap()[2]["b"].as_bool(), Some(true));
        assert!(v["c"].is_null());
    }

    #[test]
    fn handles_string_escapes() {
        let v = parse(r#""a\nb\t\"c\\d\u0041""#).unwrap();
        assert_eq!(v.as_str(), Some("a\nb\t\"c\\dA"));
    }

    #[test]
    fn handles_surrogate_pairs() {
        // U+1F600 GRINNING FACE as a surrogate pair.
        let v = parse(r#""\uD83D\uDE00""#).unwrap();
        assert_eq!(v.as_str(), Some("\u{1F600}"));
    }

    #[test]
    fn rejects_unpaired_surrogate() {
        assert!(parse(r#""\uD83D""#).is_err());
    }

    #[test]
    fn rejects_trailing_content() {
        assert!(parse("{} {}").is_err());
        assert!(parse("1 2").is_err());
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse("").is_err());
        assert!(parse("{").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("{\"a\"}").is_err());
        assert!(parse("01").is_err());
        assert!(parse("1.").is_err());
    }

    #[test]
    fn rejects_deep_nesting() {
        let deep = "[".repeat(200);
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn round_trips_compact() {
        let src = r#"{"machine":"ARM64","cores":20,"native":true,"ratio":2.5}"#;
        let v = parse(src).unwrap();
        assert_eq!(v.to_string(), src);
    }

    #[test]
    fn preserves_insertion_order() {
        let v = parse(r#"{"z":1,"a":2,"m":3}"#).unwrap();
        assert_eq!(v.to_string(), r#"{"z":1,"a":2,"m":3}"#);
    }

    #[test]
    fn serializes_pretty() {
        let v = parse(r#"{"a":[1,2]}"#).unwrap();
        let pretty = to_pretty(&v);
        assert!(pretty.contains('\n'));
        assert!(pretty.contains("\"a\": ["));
    }

    #[test]
    fn escapes_control_characters() {
        let v = Value::String("a\u{1}b".to_string());
        assert_eq!(v.to_string(), r#""a\u0001b""#);
    }

    #[test]
    fn non_finite_floats_become_null() {
        assert_eq!(Value::Float(f64::NAN).to_string(), "null");
        assert_eq!(Value::Float(f64::INFINITY).to_string(), "null");
    }

    #[test]
    fn object_get_missing_is_null() {
        let v = parse(r#"{"a":1}"#).unwrap();
        assert!(v["missing"]["deeper"].is_null());
    }

    #[test]
    fn rejects_control_char_in_string() {
        assert!(parse("\"a\u{1}b\"").is_err());
    }
}
