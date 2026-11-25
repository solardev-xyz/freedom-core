//! The reader under every typed reader of a node's JSON reply (design 0015,
//! "JSON replies"): it reads the bytes once, front to back, and keeps
//! nothing itself. A typed reader pulls the values it wants and skips the
//! rest; a skipped value costs no memory, whatever its size.
//!
//! - **Grammar:** V8's `JSON.parse`, over the text the reference parses.
//!   The reference decodes a reply as UTF-8 first (`Response.text()` or
//!   `Buffer.toString`), each bad sequence becoming U+FFFD, and JSON allows
//!   anything but ASCII only inside strings: so the reader takes the bytes,
//!   refuses a byte of 0x80 or more outside a string, as `JSON.parse`
//!   refuses the character it decodes to, and decodes a string's bytes as
//!   the reference does when the string is read ([`RawStr::decode`]).
//! - **Nesting:** at most [`MAX_NESTING`] containers open at once (every
//!   container is a level, an empty one included); one more is
//!   [`ReadError::TooDeep`], which the call answers `error` (deviation
//!   `reply-bounds`).
//! - **Numbers** are doubles, as `JSON.parse` reads them (correctly
//!   rounded; out of range is infinite); **strings** are JavaScript's,
//!   UTF-16 with lone surrogates kept ([`fc_json::JsString`]).

use fc_json::JsString;

/// The deepest a node's reply may nest (design 0015, "JSON replies").
pub const MAX_NESTING: usize = 64;

/// Why a reply isn't read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    /// Not JSON at this byte, as `JSON.parse` would throw.
    #[error("invalid JSON at byte {0}")]
    Syntax(usize),
    /// Nested deeper than [`MAX_NESTING`].
    #[error("JSON nested deeper than {MAX_NESTING} levels")]
    TooDeep,
}

/// A string literal's content, between its quotes, as it stands in the
/// reply: its escapes checked, not yet decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawStr<'a>(&'a [u8]);

/// The start of a value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Token<'a> {
    /// `{`: its members follow ([`Reader::next_key`]).
    Object,
    /// `[`: its elements follow ([`Reader::next_element`]).
    Array,
    String(RawStr<'a>),
    Number(f64),
    Bool(bool),
    Null,
}

/// A pull reader over a JSON text's bytes.
pub struct Reader<'a> {
    s: &'a [u8],
    i: usize,
    /// Open containers.
    depth: usize,
    /// Bit `d` is set when the container at depth `d + 1` is an object.
    objects: u64,
    /// The innermost container has just opened: no member read yet.
    fresh: bool,
}

impl<'a> Reader<'a> {
    pub fn new(text: &'a [u8]) -> Self {
        Self {
            s: text,
            i: 0,
            depth: 0,
            objects: 0,
            fresh: false,
        }
    }

    /// Containers open now.
    pub fn depth(&self) -> usize {
        self.depth
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn syntax<T>(&self) -> Result<T, ReadError> {
        Err(ReadError::Syntax(self.i))
    }

    fn open(&mut self, object: bool) -> Result<(), ReadError> {
        if self.depth >= MAX_NESTING {
            return Err(ReadError::TooDeep);
        }
        if object {
            self.objects |= 1 << self.depth;
        } else {
            self.objects &= !(1 << self.depth);
        }
        self.depth += 1;
        self.i += 1;
        self.fresh = true;
        Ok(())
    }

    fn close(&mut self) {
        self.i += 1;
        self.depth -= 1;
        self.fresh = false;
    }

    /// Whether the innermost open container is an object.
    pub fn in_object(&self) -> bool {
        self.depth > 0 && self.objects & (1 << (self.depth - 1)) != 0
    }

    /// The next value's start. A container is opened; its members or
    /// elements follow.
    pub fn token(&mut self) -> Result<Token<'a>, ReadError> {
        self.ws();
        let token = match self.peek() {
            Some(b'{') => {
                self.open(true)?;
                return Ok(Token::Object);
            }
            Some(b'[') => {
                self.open(false)?;
                return Ok(Token::Array);
            }
            Some(b'"') => Token::String(self.string()?),
            Some(b't') => self.literal(b"true", Token::Bool(true))?,
            Some(b'f') => self.literal(b"false", Token::Bool(false))?,
            Some(b'n') => self.literal(b"null", Token::Null)?,
            Some(b'-' | b'0'..=b'9') => Token::Number(self.number()?),
            _ => return self.syntax(),
        };
        self.fresh = false;
        Ok(token)
    }

    /// In an object: the next member's key, its `:` read, or `None` once the
    /// object has closed.
    pub fn next_key(&mut self) -> Result<Option<RawStr<'a>>, ReadError> {
        if !self.in_object() {
            return self.syntax();
        }
        self.ws();
        match self.peek() {
            Some(b'}') => {
                self.close();
                return Ok(None);
            }
            Some(b',') if !self.fresh => {
                self.i += 1;
                self.ws();
            }
            Some(b'"') if self.fresh => {}
            _ => return self.syntax(),
        }
        if self.peek() != Some(b'"') {
            return self.syntax();
        }
        let key = self.string()?;
        self.ws();
        if self.peek() != Some(b':') {
            return self.syntax();
        }
        self.i += 1;
        self.fresh = false;
        Ok(Some(key))
    }

    /// In an array: whether another element follows (its value is next), or
    /// `false` once the array has closed.
    pub fn next_element(&mut self) -> Result<bool, ReadError> {
        if self.depth == 0 || self.in_object() {
            return self.syntax();
        }
        self.ws();
        match self.peek() {
            Some(b']') => {
                self.close();
                Ok(false)
            }
            Some(b',') if !self.fresh => {
                self.i += 1;
                self.fresh = false;
                Ok(true)
            }
            Some(_) if self.fresh => {
                self.fresh = false;
                Ok(true)
            }
            _ => self.syntax(),
        }
    }

    /// Skips the rest of the value `token` began: a container's members or
    /// elements, nested ones included, read and kept nowhere.
    pub fn skip(&mut self, token: Token<'_>) -> Result<(), ReadError> {
        if !matches!(token, Token::Object | Token::Array) {
            return Ok(());
        }
        let target = self.depth - 1;
        loop {
            let more = if self.in_object() {
                self.next_key()?.is_some()
            } else {
                self.next_element()?
            };
            if !more {
                if self.depth == target {
                    return Ok(());
                }
                continue;
            }
            self.token()?;
        }
    }

    /// Reads one whole value and skips it.
    pub fn skip_value(&mut self) -> Result<(), ReadError> {
        let token = self.token()?;
        self.skip(token)
    }

    /// The end of the text: only whitespace may follow the value.
    pub fn finish(&mut self) -> Result<(), ReadError> {
        self.ws();
        if self.depth != 0 || self.i != self.s.len() {
            return self.syntax();
        }
        Ok(())
    }

    fn literal(&mut self, word: &[u8], token: Token<'a>) -> Result<Token<'a>, ReadError> {
        if self.s.get(self.i..self.i + word.len()) == Some(word) {
            self.i += word.len();
            Ok(token)
        } else {
            self.syntax()
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<f64, ReadError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return self.syntax(),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return self.syntax();
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return self.syntax();
            }
        }
        // ASCII by the grammar above. Correctly rounded, as V8; out of
        // range is infinite.
        std::str::from_utf8(&self.s[start..self.i])
            .ok()
            .and_then(|text| text.parse::<f64>().ok())
            .ok_or(ReadError::Syntax(start))
    }

    fn string(&mut self) -> Result<RawStr<'a>, ReadError> {
        self.i += 1; // the opening quote
        let start = self.i;
        loop {
            match self.peek() {
                Some(b'"') => {
                    let raw = RawStr(&self.s[start..self.i]);
                    self.i += 1;
                    return Ok(raw);
                }
                Some(b'\\') => {
                    self.i += 1;
                    match self.peek() {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                            self.i += 1;
                        }
                        Some(b'u') => {
                            let hex = self.s.get(self.i + 1..self.i + 5);
                            if !hex.is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)) {
                                return self.syntax();
                            }
                            self.i += 5;
                        }
                        _ => return self.syntax(),
                    }
                }
                // A raw control character, or the end of the text.
                Some(0x00..=0x1f) | None => return self.syntax(),
                Some(_) => self.i += 1,
            }
        }
    }
}

impl<'a> RawStr<'a> {
    /// The literal's bytes, escapes and all, between its quotes.
    pub fn raw(&self) -> &'a [u8] {
        self.0
    }

    /// Whether the decoded string is `key` (ASCII). No allocation unless the
    /// literal holds an escape.
    pub fn is(&self, key: &str) -> bool {
        if !self.0.contains(&b'\\') {
            // Without escapes, an ASCII key's bytes are its only spelling.
            return self.0 == key.as_bytes();
        }
        // Each unit takes at least one byte, and at most six.
        if self.0.len() > key.len() * 6 {
            return false;
        }
        decode_units(self.0).iter().copied().eq(key.encode_utf16())
    }

    /// The string `JSON.parse` gives for the literal: its escapes decoded,
    /// lone surrogates kept, each bad UTF-8 sequence U+FFFD.
    pub fn decode(&self) -> JsString {
        decode_raw(self.0)
    }
}

/// A checked literal's content as a JavaScript string.
pub fn decode_raw(raw: &[u8]) -> JsString {
    if !raw.contains(&b'\\') {
        return JsString::from(String::from_utf8_lossy(raw).into_owned());
    }
    JsString::from_units(&decode_units(raw))
}

/// A checked literal's content as UTF-16 units.
fn decode_units(raw: &[u8]) -> Vec<u16> {
    let mut units = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let run_end = raw[i..]
            .iter()
            .position(|&b| b == b'\\')
            .map_or(raw.len(), |p| i + p);
        // A run without escapes: decoded on its own, which is what decoding
        // the whole text gives, as no bad sequence takes in an ASCII byte.
        for chunk in raw[i..run_end].utf8_chunks() {
            units.extend(chunk.valid().encode_utf16());
            if !chunk.invalid().is_empty() {
                units.push(0xfffd);
            }
        }
        i = run_end;
        if i >= raw.len() {
            break;
        }
        // An escape, checked when the literal was read.
        let unit = match raw.get(i + 1) {
            Some(b'"') => 0x22,
            Some(b'\\') => 0x5c,
            Some(b'/') => 0x2f,
            Some(b'b') => 0x08,
            Some(b'f') => 0x0c,
            Some(b'n') => 0x0a,
            Some(b'r') => 0x0d,
            Some(b't') => 0x09,
            Some(b'u') => {
                let hex = raw.get(i + 2..i + 6).unwrap_or_default();
                let unit = hex.iter().fold(0u16, |acc, &h| {
                    let digit = match h {
                        b'0'..=b'9' => h - b'0',
                        b'a'..=b'f' => h - b'a' + 10,
                        b'A'..=b'F' => h - b'A' + 10,
                        _ => 0,
                    };
                    (acc << 4) | u16::from(digit)
                });
                i += 4;
                unit
            }
            _ => 0xfffd,
        };
        units.push(unit);
        i += 2;
    }
    units
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(text: &str) -> Result<(), ReadError> {
        let mut r = Reader::new(text.as_bytes());
        r.skip_value()?;
        r.finish()
    }

    #[test]
    fn grammar_is_json_parse() {
        for ok in [
            "0",
            "-0",
            "1.5e+3",
            "\"\"",
            "[]",
            "{}",
            " [ 1 , { \"a\" : [ ] } , null , true , false ] ",
            "{\"a\":1,\"a\":2}",
            "\"\\ud800\\u00e9\\/\"",
            "1e400",
        ] {
            assert_eq!(read_all(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            " ",
            "01",
            "1.",
            ".5",
            "1e",
            "+1",
            "[1,]",
            "[,1]",
            "{\"a\":1,}",
            "{,}",
            "{\"a\" 1}",
            "{1:2}",
            "\"\\x\"",
            "\"\\u12g4\"",
            "\"a\u{1}\"",
            "\"open",
            "[1 2]",
            "nul",
            "1 2",
            "\u{FEFF}1",
            "[1}",
            "{\"a\":1]",
        ] {
            assert!(
                matches!(read_all(bad), Err(ReadError::Syntax(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn nesting_stops_at_the_limit() {
        let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert_eq!(read_all(&deep(MAX_NESTING)), Ok(()));
        assert_eq!(read_all(&deep(MAX_NESTING + 1)), Err(ReadError::TooDeep));
        let objects = |n: usize| format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n));
        assert_eq!(read_all(&objects(MAX_NESTING)), Ok(()));
        assert_eq!(read_all(&objects(MAX_NESTING + 1)), Err(ReadError::TooDeep));
    }

    #[test]
    fn strings_decode_as_json_parse() {
        let decode = |text: &[u8]| {
            let mut r = Reader::new(text);
            match r.token() {
                Ok(Token::String(s)) => s.decode(),
                other => panic!("{other:?}"),
            }
        };
        assert_eq!(decode(b"\"a\\u0062\\n\""), "ab\n");
        assert_eq!(
            decode(b"\"\\ud800x\"").units().collect::<Vec<_>>(),
            vec![0xd800, 0x78]
        );
        assert_eq!(decode(b"\"\\ud83d\\ude00\""), "\u{1F600}");
        assert_eq!(decode(b"\"hi\xFF\\n\xC3\""), "hi\u{FFFD}\n\u{FFFD}");
        fn key(text: &[u8]) -> RawStr<'_> {
            match Reader::new(text).token() {
                Ok(Token::String(s)) => s,
                other => panic!("{other:?}"),
            }
        }
        assert!(key(b"\"label\"").is("label"));
        assert!(key(b"\"lab\\u0065l\"").is("label"));
        assert!(!key(b"\"labels\"").is("label"));
        assert!(!key(b"\"lab\\u0065\"").is("label"));
    }
}
