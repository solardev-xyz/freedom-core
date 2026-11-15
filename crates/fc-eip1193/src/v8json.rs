//! `JSON.parse(text)` for a page's typed data sent as a string, with the
//! `SyntaxError` message V8 throws for text that isn't JSON (Node 24, the
//! vectors' runtime): the reference answers that message as the request's
//! `-32603` (`page-signing.js`'s `failure`), so a dApp reads the same text
//! from the core.
//!
//! The text is scanned first, by UTF-16 unit as V8 reads it, for the first
//! error and its message; text that scans clean is parsed by `fc-json`,
//! which reads JSON as V8 does.

use fc_json::{JsString, JsValue};

/// V8's `kMaxContextCharacters`: an unexpected token's context on each side.
const CONTEXT: usize = 10;
/// V8's `kMinOriginalSourceLengthForContext`: shorter text is quoted whole.
const MIN_LENGTH_FOR_CONTEXT: usize = CONTEXT * 2 + 1;

/// `JSON.parse(text)`, or the message of what it throws. Text nested
/// deeper than `fc-json` reads (which V8 accepts) gets the core's own
/// refusal of such params, `Invalid parameters` (*inferred*).
pub(crate) fn parse(text: &JsString) -> Result<JsValue, JsString> {
    let units: Vec<u16> = text.units().collect();
    if let Some(message) = syntax_error(&units) {
        return Err(message);
    }
    fc_json::parse(text.as_str()).map_err(|_| JsString::from("Invalid parameters"))
}

/// Where scanning stopped.
enum Stop {
    /// The text ended where a value was due.
    End,
    /// A token that can't start or continue a value here.
    Token(usize),
    /// A number where none may be (a leading zero's next digit).
    Number(usize),
    /// One of V8's own messages, at a position.
    At(&'static str, usize),
    /// Something after the value.
    Trailing(usize),
}

/// What the scanner is inside.
enum Open {
    Array,
    Object,
}

fn is_space(unit: u16) -> bool {
    matches!(unit, 0x20 | 0x09 | 0x0a | 0x0d)
}

fn is_digit(unit: u16) -> bool {
    (u16::from(b'0')..=u16::from(b'9')).contains(&unit)
}

fn is_hex(unit: u16) -> bool {
    is_digit(unit)
        || (u16::from(b'a')..=u16::from(b'f')).contains(&unit)
        || (u16::from(b'A')..=u16::from(b'F')).contains(&unit)
}

const fn unit(byte: u8) -> u16 {
    byte as u16
}

struct Scan<'a> {
    s: &'a [u16],
    i: usize,
}

impl Scan<'_> {
    fn peek(&self) -> Option<u16> {
        self.s.get(self.i).copied()
    }

    fn skip_space(&mut self) {
        while self.peek().is_some_and(is_space) {
            self.i += 1;
        }
    }

    /// A string, from its opening quote.
    fn string(&mut self) -> Result<(), Stop> {
        self.i += 1;
        loop {
            let Some(c) = self.peek() else {
                return Err(Stop::At("Unterminated string", self.i));
            };
            match c {
                0x22 => {
                    self.i += 1;
                    return Ok(());
                }
                0x5c => {
                    let Some(escape) = self.s.get(self.i + 1).copied() else {
                        return Err(Stop::End);
                    };
                    if escape == unit(b'u') {
                        for k in 0..4 {
                            let at = self.i + 2 + k;
                            if !self.s.get(at).copied().is_some_and(is_hex) {
                                return Err(Stop::At("Bad Unicode escape", at));
                            }
                        }
                        self.i += 6;
                    } else if b"\"\\/bfnrt".iter().any(|&b| unit(b) == escape) {
                        self.i += 2;
                    } else {
                        return Err(Stop::At("Bad escaped character", self.i + 1));
                    }
                }
                c if c < 0x20 => {
                    return Err(Stop::At("Bad control character in string literal", self.i));
                }
                _ => self.i += 1,
            }
        }
    }

    fn digits(&mut self) {
        while self.peek().is_some_and(is_digit) {
            self.i += 1;
        }
    }

    /// A number, from its first unit (`-` or a digit).
    fn number(&mut self) -> Result<(), Stop> {
        if self.peek() == Some(unit(b'-')) {
            self.i += 1;
        }
        match self.peek() {
            Some(c) if c == unit(b'0') => {
                self.i += 1;
                if self.peek().is_some_and(is_digit) {
                    return Err(Stop::Number(self.i));
                }
            }
            Some(c) if is_digit(c) => self.digits(),
            _ => return Err(Stop::At("No number after minus sign", self.i)),
        }
        if self.peek() == Some(unit(b'.')) {
            self.i += 1;
            if !self.peek().is_some_and(is_digit) {
                return Err(Stop::At("Unterminated fractional number", self.i));
            }
            self.digits();
        }
        if matches!(self.peek(), Some(c) if c == unit(b'e') || c == unit(b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(c) if c == unit(b'+') || c == unit(b'-')) {
                self.i += 1;
            }
            if !self.peek().is_some_and(is_digit) {
                return Err(Stop::At("Exponent part is missing a number", self.i));
            }
            self.digits();
        }
        Ok(())
    }

    /// `true`, `false` or `null`, from its first letter.
    fn literal(&mut self, word: &[u8]) -> Result<(), Stop> {
        for &expected in word {
            match self.peek() {
                None => return Err(Stop::End),
                Some(c) if c == unit(expected) => self.i += 1,
                Some(_) => return Err(Stop::Token(self.i)),
            }
        }
        Ok(())
    }

    /// An object's property name and its colon, at the opening quote.
    fn property(&mut self) -> Result<(), Stop> {
        self.string()?;
        self.skip_space();
        if self.peek() != Some(unit(b':')) {
            return Err(Stop::At("Expected ':' after property name", self.i));
        }
        self.i += 1;
        Ok(())
    }

    /// The whole text: one value and nothing after it but whitespace.
    fn document(&mut self) -> Result<(), Stop> {
        let mut stack: Vec<Open> = Vec::new();
        loop {
            // A value is due.
            self.skip_space();
            let Some(c) = self.peek() else {
                return Err(Stop::End);
            };
            match c {
                0x22 => self.string()?,
                c if c == unit(b'-') || is_digit(c) => self.number()?,
                c if c == unit(b't') => self.literal(b"true")?,
                c if c == unit(b'f') => self.literal(b"false")?,
                c if c == unit(b'n') => self.literal(b"null")?,
                c if c == unit(b'[') => {
                    self.i += 1;
                    self.skip_space();
                    if self.peek() == Some(unit(b']')) {
                        self.i += 1;
                    } else {
                        stack.push(Open::Array);
                        continue;
                    }
                }
                c if c == unit(b'{') => {
                    self.i += 1;
                    self.skip_space();
                    match self.peek() {
                        Some(c) if c == unit(b'}') => self.i += 1,
                        Some(0x22) => {
                            self.property()?;
                            stack.push(Open::Object);
                            continue;
                        }
                        _ => return Err(Stop::At("Expected property name or '}'", self.i)),
                    }
                }
                _ => return Err(Stop::Token(self.i)),
            }
            // A value ended: close what it ends, or go on to the next.
            loop {
                self.skip_space();
                let Some(open) = stack.last() else {
                    if self.i < self.s.len() {
                        return Err(Stop::Trailing(self.i));
                    }
                    return Ok(());
                };
                let c = self.peek();
                match open {
                    Open::Array => match c {
                        Some(c) if c == unit(b',') => {
                            self.i += 1;
                            break;
                        }
                        Some(c) if c == unit(b']') => {
                            self.i += 1;
                            stack.pop();
                        }
                        _ => {
                            return Err(Stop::At(
                                "Expected ',' or ']' after array element",
                                self.i,
                            ));
                        }
                    },
                    Open::Object => match c {
                        Some(c) if c == unit(b',') => {
                            self.i += 1;
                            self.skip_space();
                            if self.peek() != Some(0x22) {
                                return Err(Stop::At(
                                    "Expected double-quoted property name",
                                    self.i,
                                ));
                            }
                            self.property()?;
                            break;
                        }
                        Some(c) if c == unit(b'}') => {
                            self.i += 1;
                            stack.pop();
                        }
                        _ => {
                            return Err(Stop::At(
                                "Expected ',' or '}' after property value",
                                self.i,
                            ));
                        }
                    },
                }
            }
        }
    }
}

/// The message `JSON.parse(units)` throws, or `None` when it parses.
pub(crate) fn syntax_error(units: &[u16]) -> Option<JsString> {
    let mut scan = Scan { s: units, i: 0 };
    let stop = scan.document().err()?;
    let at = |message: &str, pos: usize| {
        let (line, column) = line_column(units, pos);
        JsString::from(format!(
            "{message} at position {pos} (line {line} column {column})"
        ))
    };
    Some(match stop {
        Stop::End => JsString::from("Unexpected end of JSON input"),
        Stop::Number(pos) => at("Unexpected number in JSON", pos),
        Stop::At(message, pos) => at(&format!("{message} in JSON"), pos),
        Stop::Trailing(pos) => at("Unexpected non-whitespace character after JSON", pos),
        Stop::Token(pos) => unexpected_token(units, pos),
    })
}

/// `line` and `column`, from 1: CR, LF and CRLF each end a line.
fn line_column(units: &[u16], pos: usize) -> (usize, usize) {
    let (mut line, mut start, mut i) = (1, 0, 0);
    while i < pos.min(units.len()) {
        match units[i] {
            0x0d if units.get(i + 1) == Some(&0x0a) && i + 1 < pos => {
                i += 2;
                line += 1;
                start = i;
            }
            0x0a | 0x0d => {
                i += 1;
                line += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    (line, pos - start + 1)
}

/// V8's message for an unexpected token: the text quoted whole when it is
/// short, or the token's context, ten units on either side.
fn unexpected_token(units: &[u16], pos: usize) -> JsString {
    let text = |range: std::ops::Range<usize>| units.get(range).unwrap_or_default();
    let whole = text(0..units.len());
    // `IsSpecialString`: what `JSON.parse` of these values' strings reads.
    for special in ["undefined", "NaN", "Infinity", "[object Object]"] {
        if whole.iter().copied().eq(special.encode_utf16()) {
            return JsString::from_units(&compose(&[&quote(whole), &utf16(" is not valid JSON")]));
        }
    }
    let token = text(pos..pos + 1);
    let head = compose(&[&utf16("Unexpected token '"), token, &utf16("', ")]);
    let n = units.len();
    let (before, quoted, after) = if n < MIN_LENGTH_FOR_CONTEXT {
        ("", whole, "")
    } else if pos < CONTEXT {
        ("", text(0..pos + CONTEXT), "...")
    } else if pos < n - CONTEXT {
        ("...", text(pos - CONTEXT..pos + CONTEXT), "...")
    } else {
        ("...", text(pos - CONTEXT..n), "")
    };
    JsString::from_units(&compose(&[
        head.as_slice(),
        &utf16(before),
        &quote(quoted),
        &utf16(after),
        &utf16(" is not valid JSON"),
    ]))
}

fn utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn quote(units: &[u16]) -> Vec<u16> {
    let mut out = Vec::with_capacity(units.len() + 2);
    out.push(0x22);
    out.extend_from_slice(units);
    out.push(0x22);
    out
}

fn compose(parts: &[&[u16]]) -> Vec<u16> {
    parts.iter().flat_map(|part| part.iter().copied()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(text: &str) -> Option<String> {
        syntax_error(&utf16(text)).map(|m| m.as_str().to_owned())
    }

    /// Each checked against Node 24.15's `JSON.parse`.
    #[test]
    fn the_messages_are_v8s() {
        let cases: &[(&str, &str)] = &[
            (
                "{not json",
                "Expected property name or '}' in JSON at position 1 (line 1 column 2)",
            ),
            ("", "Unexpected end of JSON input"),
            (" ", "Unexpected end of JSON input"),
            (
                "{",
                "Expected property name or '}' in JSON at position 1 (line 1 column 2)",
            ),
            ("[", "Unexpected end of JSON input"),
            (
                "[1",
                "Expected ',' or ']' after array element in JSON at position 2 (line 1 column 3)",
            ),
            ("[1,", "Unexpected end of JSON input"),
            ("[1, ", "Unexpected end of JSON input"),
            (
                "{\"a\"",
                "Expected ':' after property name in JSON at position 4 (line 1 column 5)",
            ),
            ("{\"a\":", "Unexpected end of JSON input"),
            (
                "{\"a\":1",
                "Expected ',' or '}' after property value in JSON at position 6 (line 1 column 7)",
            ),
            (
                "{\"a\":1,",
                "Expected double-quoted property name in JSON at position 7 (line 1 column 8)",
            ),
            (
                "{\"a\":1, ",
                "Expected double-quoted property name in JSON at position 8 (line 1 column 9)",
            ),
            (
                "{\"a\":1,}",
                "Expected double-quoted property name in JSON at position 7 (line 1 column 8)",
            ),
            ("[1,]", "Unexpected token ']', \"[1,]\" is not valid JSON"),
            ("[,1]", "Unexpected token ',', \"[,1]\" is not valid JSON"),
            ("tru", "Unexpected end of JSON input"),
            ("trux", "Unexpected token 'x', \"trux\" is not valid JSON"),
            (
                "{\"a\":tru}",
                "Unexpected token '}', \"{\"a\":tru}\" is not valid JSON",
            ),
            (
                "\"abc",
                "Unterminated string in JSON at position 4 (line 1 column 5)",
            ),
            ("\"abc\\", "Unexpected end of JSON input"),
            (
                "\"a\\x\"",
                "Bad escaped character in JSON at position 3 (line 1 column 4)",
            ),
            (
                "\"\\u12g4\"",
                "Bad Unicode escape in JSON at position 5 (line 1 column 6)",
            ),
            (
                "\"\\u12",
                "Bad Unicode escape in JSON at position 5 (line 1 column 6)",
            ),
            (
                "\"a\u{1}\"",
                "Bad control character in string literal in JSON at position 2 (line 1 column 3)",
            ),
            (
                "-",
                "No number after minus sign in JSON at position 1 (line 1 column 2)",
            ),
            (
                "-Infinity",
                "No number after minus sign in JSON at position 1 (line 1 column 2)",
            ),
            (
                "1e+",
                "Exponent part is missing a number in JSON at position 3 (line 1 column 4)",
            ),
            (
                "1.e5",
                "Unterminated fractional number in JSON at position 2 (line 1 column 3)",
            ),
            (
                "{\"a\":01}",
                "Unexpected number in JSON at position 6 (line 1 column 7)",
            ),
            (
                "1 2",
                "Unexpected non-whitespace character after JSON at position 2 (line 1 column 3)",
            ),
            (
                "0x10",
                "Unexpected non-whitespace character after JSON at position 1 (line 1 column 2)",
            ),
            ("undefined", "\"undefined\" is not valid JSON"),
            ("[object Object]", "\"[object Object]\" is not valid JSON"),
            (
                "\t\r\n{",
                "Expected property name or '}' in JSON at position 4 (line 2 column 2)",
            ),
            (
                "\r{",
                "Expected property name or '}' in JSON at position 2 (line 2 column 2)",
            ),
            (
                "\r\n\r\n{",
                "Expected property name or '}' in JSON at position 5 (line 3 column 2)",
            ),
            (
                "aaaaaaaaaaaaaaaaaaaa",
                "Unexpected token 'a', \"aaaaaaaaaaaaaaaaaaaa\" is not valid JSON",
            ),
            (
                "aaaaaaaaaaaaaaaaaaaaa",
                "Unexpected token 'a', \"aaaaaaaaaa\"... is not valid JSON",
            ),
            (
                "[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,x,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]",
                "Unexpected token 'x', ...\"1,1,1,1,1,x,1,1,1,1,\"... is not valid JSON",
            ),
            (
                "[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,x]",
                "Unexpected token 'x', ...\"1,1,1,1,1,x]\" is not valid JSON",
            ),
            (
                "[1.5x]",
                "Expected ',' or ']' after array element in JSON at position 4 (line 1 column 5)",
            ),
            (
                "\u{a0}",
                "Unexpected token '\u{a0}', \"\u{a0}\" is not valid JSON",
            ),
        ];
        for (text, expected) in cases {
            assert_eq!(message(text).as_deref(), Some(*expected), "{text:?}");
        }
        for text in [
            "-0.0e-0",
            "1E+5",
            "{\"a\":1,\"a\":2}",
            "\"\\uD800\"",
            " [ ] ",
        ] {
            assert_eq!(message(text), None, "{text:?}");
        }
    }

    #[test]
    fn a_token_is_one_utf16_unit() {
        // "😀" is two units: the token is the lone high surrogate.
        let got = syntax_error(&utf16("😀")).unwrap();
        let mut expected = utf16("Unexpected token '");
        expected.push(0xd83d);
        expected.extend(utf16("', \"😀\" is not valid JSON"));
        assert_eq!(got.units().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn text_that_scans_clean_parses() {
        let parsed = parse(&JsString::from("{\"b\":1,\"2\":[true,null]}")).unwrap();
        assert_eq!(parsed.stringify(), "{\"2\":[true,null],\"b\":1}");
    }
}
