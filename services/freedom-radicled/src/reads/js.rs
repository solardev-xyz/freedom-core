//! JSON as main's JavaScript reads it and writes it again, done on the
//! text itself (design 0008, "JSON results": the service writes the bytes
//! main's `JSON.stringify` writes today). [`write`] writes what
//! `JSON.stringify(JSON.parse(text))` makes of a value; [`Value::get`],
//! [`Value::truthy`] and [`Value::is_str`] are the reads main's
//! compositions make of a parsed value; [`parse_int`] is `Number.parseInt`
//! with radix 10. `vectors/radicle-reads.json`, which main's own code at
//! the reference recorded, pins each.
//!
//! **What `JSON.parse`, then `JSON.stringify`, change:**
//! - whitespace between tokens is dropped;
//! - a number is read as the nearest double, and written as JavaScript's
//!   `Number.prototype.toString` writes it: the shortest digits that read
//!   back, plainly below 1e21 (so an integer past 2^53 loses its low
//!   digits: 18446744073709551615 is 18446744073709552000), in exponent
//!   form from 1e21 and below 1e-6 (`1e+21`, `1e-7`); `-0` is `0`, and a
//!   number past the doubles' range (`1e400`) is `null`;
//! - a string's escapes are decoded, and written again as JavaScript
//!   writes a string: `\b \t \n \f \r \" \\`, `\u00xx` (lowercase) for the
//!   other control characters and for a lone surrogate, and everything
//!   else as itself (`\/` is `/`, `\u00e9` is `é`);
//! - an object's members: a key repeated keeps its first place and takes
//!   its last value; then the keys that are array indices (`0` to
//!   4294967294, written canonically: not `01`, `-1` or `1.5`) come first,
//!   in increasing order, and the others keep their order.
//!
//! libradicle's serializers write no whitespace, no repeated key, and only
//! the escapes JavaScript writes. What does reach main's pages is an
//! integer past 2^53 (a COB's timestamp, which its author chooses) and a
//! key that is an index (a branch named `1`, in a remote's heads).
//!
//! **Bounds:** a text is checked once ([`parse`]): UTF-8, then serde_json's
//! parser. Its values are then read where they lie, never copied, and
//! written at most [`DEPTH`] deep. Nothing here allocates but an object's
//! members as it is written: counted first, then charged to the
//! composition's working set ([`Work`]) before they are allocated, and
//! given back once the object is written. So the set holds the members of
//! the objects being written, one per level.

use std::cmp::Ordering;
use std::io::{self, Write};

/// The deepest a value is written: deeper is [`Error::Malformed`], as no
/// libradicle shape comes near it.
pub const DEPTH: usize = 128;

/// Why a composition stopped.
#[derive(Debug)]
pub enum Error {
    /// Its working set would pass its limit: `size` bytes, over `limit`.
    TooLarge { size: u64, limit: u64 },
    /// A text that isn't what libradicle's serializer writes: never
    /// expected, so an internal error, by what it was.
    Malformed(&'static str),
    /// The output's own error: its writer refused (see
    /// [`crate::output::Json`]).
    Write(io::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Write(error)
    }
}

fn malformed() -> Error {
    Error::Malformed("the text")
}

/// A composition's working set: what the objects it writes hold.
#[derive(Debug)]
pub struct Work {
    limit: u64,
    held: u64,
}

impl Work {
    /// A working set of at most `limit` bytes, none held.
    pub fn new(limit: u64) -> Self {
        Self { limit, held: 0 }
    }

    /// The bytes held now.
    #[cfg(test)]
    pub fn held(&self) -> u64 {
        self.held
    }

    fn take(&mut self, bytes: u64) -> Result<(), Error> {
        let size = self.held.saturating_add(bytes);
        if size > self.limit {
            return Err(Error::TooLarge {
                size,
                limit: self.limit,
            });
        }
        self.held = size;
        Ok(())
    }

    fn give(&mut self, bytes: u64) {
        self.held = self.held.saturating_sub(bytes);
    }
}

/// One value of a checked text: its bytes, with no whitespace around it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Value<'a>(&'a [u8]);

/// The value `text` holds, once it is checked to be JSON: UTF-8, then
/// serde_json's parser.
pub fn parse(text: &[u8]) -> Result<Value<'_>, Error> {
    std::str::from_utf8(text).map_err(|_| Error::Malformed("a text that isn't UTF-8"))?;
    // First its depth, so that serde_json's check holds no more than it.
    within_depth(text)?;
    serde_json::from_slice::<serde::de::IgnoredAny>(text)
        .map_err(|_| Error::Malformed("a text that isn't JSON"))?;
    let start = skip_ws(text, 0);
    let end = value_end(text, start)?;
    text.get(start..end).map(Value).ok_or_else(malformed)
}

/// Whether `text` nests at most [`DEPTH`] deep, its strings skipped.
fn within_depth(text: &[u8]) -> Result<(), Error> {
    let mut depth = 0usize;
    let mut i = 0;
    while let Some(&byte) = text.get(i) {
        match byte {
            b'"' => {
                i = string_end(text, i)?;
                continue;
            }
            b'{' | b'[' => {
                depth += 1;
                if depth > DEPTH {
                    return Err(Error::Malformed("a value nested too deep"));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    Ok(())
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while matches!(b.get(i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        i += 1;
    }
    i
}

/// Past the closing quote of the string whose opening quote is at `i`.
fn string_end(b: &[u8], i: usize) -> Result<usize, Error> {
    let mut j = i + 1;
    loop {
        match b.get(j) {
            Some(b'"') => return Ok(j + 1),
            Some(b'\\') => j += 2,
            Some(_) => j += 1,
            None => return Err(malformed()),
        }
    }
}

/// Past the end of the value that starts at `i`.
fn value_end(b: &[u8], i: usize) -> Result<usize, Error> {
    match b.get(i) {
        Some(b'"') => string_end(b, i),
        Some(b'{' | b'[') => {
            let mut depth = 0usize;
            let mut j = i;
            loop {
                match b.get(j) {
                    Some(b'"') => {
                        j = string_end(b, j)?;
                        continue;
                    }
                    Some(b'{' | b'[') => depth += 1,
                    Some(b'}' | b']') => {
                        depth = depth.checked_sub(1).ok_or_else(malformed)?;
                        if depth == 0 {
                            return Ok(j + 1);
                        }
                    }
                    Some(_) => {}
                    None => return Err(malformed()),
                }
                j += 1;
            }
        }
        Some(b't' | b'n') => Ok(i + 4),
        Some(b'f') => Ok(i + 5),
        Some(_) => {
            let mut j = i;
            while matches!(
                b.get(j),
                Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
            ) {
                j += 1;
            }
            if j == i { Err(malformed()) } else { Ok(j) }
        }
        None => Err(malformed()),
    }
}

/// The items of an array, or the members of an object, in order: the
/// values between its brackets, each a key's string first for an object.
struct Items<'a> {
    b: &'a [u8],
    i: usize,
    close: u8,
    done: bool,
}

impl<'a> Items<'a> {
    fn new(b: &'a [u8], open: u8, close: u8) -> Result<Self, Error> {
        if b.first() != Some(&open) {
            return Err(malformed());
        }
        let i = skip_ws(b, 1);
        let done = b.get(i) == Some(&close);
        Ok(Self { b, i, close, done })
    }

    fn value(&mut self) -> Result<&'a [u8], Error> {
        let start = self.i;
        let end = value_end(self.b, start)?;
        self.i = skip_ws(self.b, end);
        self.b.get(start..end).ok_or_else(malformed)
    }

    /// After an item: the comma, or the closing bracket.
    fn next_item(&mut self) -> Result<(), Error> {
        match self.b.get(self.i) {
            Some(b',') => {
                self.i = skip_ws(self.b, self.i + 1);
                Ok(())
            }
            Some(&c) if c == self.close => {
                self.done = true;
                Ok(())
            }
            _ => Err(malformed()),
        }
    }

    fn element(&mut self) -> Option<Result<Value<'a>, Error>> {
        if self.done {
            return None;
        }
        let item = self
            .value()
            .and_then(|v| self.next_item().map(|()| Value(v)));
        if item.is_err() {
            self.done = true;
        }
        Some(item)
    }

    fn member(&mut self) -> Option<Result<(Key<'a>, Value<'a>), Error>> {
        if self.done {
            return None;
        }
        let member = (|| {
            let key = self.value()?;
            if self.b.get(self.i) != Some(&b':') {
                return Err(malformed());
            }
            self.i = skip_ws(self.b, self.i + 1);
            let value = self.value()?;
            self.next_item()?;
            let inner = key
                .get(1..key.len().saturating_sub(1))
                .ok_or_else(malformed)?;
            Ok((Key(inner), Value(value)))
        })();
        if member.is_err() {
            self.done = true;
        }
        Some(member)
    }
}

/// An array's elements, in order.
pub struct Elements<'a>(Items<'a>);

impl<'a> Iterator for Elements<'a> {
    type Item = Result<Value<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.element()
    }
}

/// An object's members, in order, as the text has them.
pub struct Members<'a>(Items<'a>);

impl<'a> Iterator for Members<'a> {
    type Item = Result<(Key<'a>, Value<'a>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.member()
    }
}

/// A member's key: the bytes between its quotes, escapes and all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key<'a>(&'a [u8]);

impl Key<'_> {
    /// Whether it is `key`, decoded.
    fn is(self, key: &str) -> bool {
        Decoded::new(self.0).eq(key.bytes())
    }

    /// Its array index, if it is one: `0`, or a digit from 1 to 9 and up to
    /// nine more, at most 4294967294.
    fn index(self) -> Option<u32> {
        let mut digits = [0u8; 10];
        let mut len = 0;
        for byte in Decoded::new(self.0) {
            if !byte.is_ascii_digit() || len == digits.len() {
                return None;
            }
            digits[len] = byte;
            len += 1;
        }
        let digits = digits.get(..len)?;
        if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') {
            return None;
        }
        let value = digits
            .iter()
            .fold(0u64, |n, d| n * 10 + u64::from(d - b'0'));
        u32::try_from(value).ok().filter(|&n| n != u32::MAX)
    }

    fn cmp_decoded(self, other: Key<'_>) -> Ordering {
        Decoded::new(self.0).cmp(Decoded::new(other.0))
    }
}

impl<'a> Value<'a> {
    fn first(self) -> Option<u8> {
        self.0.first().copied()
    }

    /// Whether it is an object.
    pub fn is_object(self) -> bool {
        self.first() == Some(b'{')
    }

    /// Whether it is `null`.
    pub fn is_null(self) -> bool {
        self.first() == Some(b'n')
    }

    /// Its elements, if it is an array.
    pub fn elements(self) -> Result<Elements<'a>, Error> {
        Items::new(self.0, b'[', b']').map(Elements)
    }

    /// Its members, if it is an object.
    pub fn members(self) -> Result<Members<'a>, Error> {
        Items::new(self.0, b'{', b'}').map(Members)
    }

    /// `value.key`, as JavaScript reads it of the parsed value: the last
    /// member of that key, decoded, if it is an object; `None` (undefined)
    /// otherwise.
    pub fn get(self, key: &str) -> Result<Option<Value<'a>>, Error> {
        if !self.is_object() {
            return Ok(None);
        }
        let mut found = None;
        for member in self.members()? {
            let (k, v) = member?;
            if k.is(key) {
                found = Some(v);
            }
        }
        Ok(found)
    }

    /// Whether JavaScript takes it as true: all but `null`, `false`, `0`
    /// (and `-0`) and `""`.
    pub fn truthy(self) -> bool {
        match self.first() {
            Some(b'n' | b'f') => false,
            Some(b'"') => self.0.len() > 2,
            Some(b'{' | b'[' | b't') => true,
            _ => std::str::from_utf8(self.0)
                .ok()
                .and_then(|n| n.parse::<f64>().ok())
                .is_some_and(|n| n != 0.0),
        }
    }

    /// Whether it is the string `s`, decoded: JavaScript's `===`.
    pub fn is_str(self, s: &str) -> bool {
        self.first() == Some(b'"')
            && self
                .0
                .get(1..self.0.len().saturating_sub(1))
                .is_some_and(|inner| Decoded::new(inner).eq(s.bytes()))
    }
}

/// A code unit or point of the escape at `b[i]`, a backslash, and where
/// the text goes on: a surrogate pair escaped as two is one point; a lone
/// surrogate is itself.
fn escape_at(b: &[u8], i: usize) -> Option<(u32, usize)> {
    let hex = |at: usize| -> Option<u32> {
        let digits = std::str::from_utf8(b.get(at..at + 4)?).ok()?;
        u32::from_str_radix(digits, 16).ok()
    };
    let point = match b.get(i + 1)? {
        b'"' => 0x22,
        b'\\' => 0x5c,
        b'/' => 0x2f,
        b'b' => 0x08,
        b'f' => 0x0c,
        b'n' => 0x0a,
        b'r' => 0x0d,
        b't' => 0x09,
        b'u' => {
            let unit = hex(i + 2)?;
            if (0xd800..0xdc00).contains(&unit)
                && b.get(i + 6..i + 8) == Some(b"\\u")
                && let Some(low) = hex(i + 8).filter(|low| (0xdc00..0xe000).contains(low))
            {
                let point = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                return Some((point, i + 12));
            }
            return Some((unit, i + 6));
        }
        _ => return None,
    };
    Some((point, i + 2))
}

/// A string's bytes, decoded: its escapes as UTF-8, a lone surrogate as
/// UTF-8 would encode it, so that two strings' bytes are equal when, and
/// only when, JavaScript's strings are.
struct Decoded<'a> {
    b: &'a [u8],
    i: usize,
    pending: [u8; 4],
    at: usize,
    len: usize,
}

impl<'a> Decoded<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self {
            b,
            i: 0,
            pending: [0; 4],
            at: 0,
            len: 0,
        }
    }
}

/// `point` as UTF-8 would encode it, a surrogate too: its length.
fn encode(point: u32, out: &mut [u8; 4]) -> usize {
    let p = point;
    if p < 0x80 {
        out[0] = p as u8;
        1
    } else if p < 0x800 {
        out[0] = 0xc0 | (p >> 6) as u8;
        out[1] = 0x80 | (p & 0x3f) as u8;
        2
    } else if p < 0x10000 {
        out[0] = 0xe0 | (p >> 12) as u8;
        out[1] = 0x80 | ((p >> 6) & 0x3f) as u8;
        out[2] = 0x80 | (p & 0x3f) as u8;
        3
    } else {
        out[0] = 0xf0 | (p >> 18) as u8;
        out[1] = 0x80 | ((p >> 12) & 0x3f) as u8;
        out[2] = 0x80 | ((p >> 6) & 0x3f) as u8;
        out[3] = 0x80 | (p & 0x3f) as u8;
        4
    }
}

impl Iterator for Decoded<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.at < self.len {
            self.at += 1;
            return self.pending.get(self.at - 1).copied();
        }
        let byte = *self.b.get(self.i)?;
        if byte != b'\\' {
            self.i += 1;
            return Some(byte);
        }
        let (point, next) = escape_at(self.b, self.i)?;
        self.i = next;
        self.len = encode(point, &mut self.pending);
        self.at = 1;
        self.pending.first().copied()
    }
}

/// The string whose bytes between its quotes are `inner`, as JavaScript
/// writes it (see the module's doc).
fn write_string(inner: &[u8], out: &mut impl Write) -> Result<(), Error> {
    out.write_all(b"\"")?;
    let mut run = 0;
    let mut i = 0;
    while let Some(&byte) = inner.get(i) {
        if byte != b'\\' {
            i += 1;
            continue;
        }
        out.write_all(inner.get(run..i).ok_or_else(malformed)?)?;
        let (point, next) = escape_at(inner, i).ok_or_else(malformed)?;
        write_point(point, out)?;
        i = next;
        run = next;
    }
    out.write_all(inner.get(run..).ok_or_else(malformed)?)?;
    out.write_all(b"\"")?;
    Ok(())
}

/// One code point, or lone surrogate, as JavaScript's `JSON.stringify`
/// writes it in a string.
fn write_point(point: u32, out: &mut impl Write) -> Result<(), Error> {
    let short: &[u8] = match point {
        0x08 => b"\\b",
        0x09 => b"\\t",
        0x0a => b"\\n",
        0x0c => b"\\f",
        0x0d => b"\\r",
        0x22 => b"\\\"",
        0x5c => b"\\\\",
        p if p < 0x20 || (0xd800..0xe000).contains(&p) => {
            write!(out, "\\u{p:04x}")?;
            return Ok(());
        }
        p => {
            let mut bytes = [0; 4];
            let len = encode(p, &mut bytes);
            out.write_all(bytes.get(..len).ok_or_else(malformed)?)?;
            return Ok(());
        }
    };
    out.write_all(short)?;
    Ok(())
}

/// `n` as JavaScript's `Number.prototype.toString` writes it, or `null`,
/// as `JSON.stringify` writes a number that isn't finite.
pub fn js_number(n: f64) -> Option<String> {
    if !n.is_finite() {
        return Some("null".into());
    }
    if n == 0.0 {
        return Some("0".into());
    }
    // The shortest digits that read back, and their exponent.
    let shortest = format!("{:e}", n.abs());
    let (mantissa, exponent) = shortest.split_once('e')?;
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = i32::try_from(digits.len()).ok()?;
    let point = exponent.parse::<i32>().ok()? + 1;
    let mut s = String::new();
    if n < 0.0 {
        s.push('-');
    }
    let zeros = |s: &mut String, n: i32| s.extend(std::iter::repeat_n('0', n.max(0) as usize));
    if k <= point && point <= 21 {
        s.push_str(&digits);
        zeros(&mut s, point - k);
    } else if 0 < point && point <= 21 {
        let (whole, fraction) = digits.split_at(usize::try_from(point).ok()?);
        s.push_str(whole);
        s.push('.');
        s.push_str(fraction);
    } else if -6 < point && point <= 0 {
        s.push_str("0.");
        zeros(&mut s, -point);
        s.push_str(&digits);
    } else {
        let exponent = point - 1;
        let (first, rest) = digits.split_at(1);
        s.push_str(first);
        if !rest.is_empty() {
            s.push('.');
            s.push_str(rest);
        }
        s.push('e');
        s.push(if exponent < 0 { '-' } else { '+' });
        s.push_str(&exponent.unsigned_abs().to_string());
    }
    Some(s)
}

/// A number's text, as JavaScript writes it again.
fn write_number(text: &[u8], out: &mut impl Write) -> Result<(), Error> {
    let digits = text.strip_prefix(b"-").unwrap_or(text);
    // Up to 15 digits is exact in a double, and written as it is: but `-0`.
    if !digits.is_empty() && digits.len() <= 15 && digits.iter().all(u8::is_ascii_digit) {
        out.write_all(if digits == b"0" { b"0" } else { text })?;
        return Ok(());
    }
    let n = std::str::from_utf8(text)
        .ok()
        .and_then(|n| n.parse::<f64>().ok())
        .ok_or_else(malformed)?;
    out.write_all(js_number(n).ok_or_else(malformed)?.as_bytes())?;
    Ok(())
}

/// What `JSON.stringify(JSON.parse(text))` writes for `value`, a value of
/// a checked text (see the module's doc), within `work`.
pub fn write(value: Value<'_>, out: &mut impl Write, work: &mut Work) -> Result<(), Error> {
    write_value(value, out, work, 0)
}

fn write_value(
    value: Value<'_>,
    out: &mut impl Write,
    work: &mut Work,
    depth: usize,
) -> Result<(), Error> {
    if depth >= DEPTH {
        return Err(Error::Malformed("a value nested too deep"));
    }
    match value.first() {
        Some(b'"') => write_string(
            value
                .0
                .get(1..value.0.len().saturating_sub(1))
                .ok_or_else(malformed)?,
            out,
        ),
        Some(b'{') => write_object(value, out, work, depth),
        Some(b'[') => {
            out.write_all(b"[")?;
            for (n, element) in value.elements()?.enumerate() {
                if n > 0 {
                    out.write_all(b",")?;
                }
                write_value(element?, out, work, depth + 1)?;
            }
            out.write_all(b"]")?;
            Ok(())
        }
        Some(b't' | b'f' | b'n') => {
            out.write_all(value.0)?;
            Ok(())
        }
        Some(_) => write_number(value.0, out),
        None => Err(malformed()),
    }
}

/// One member of an object being written: where its key and value lie in
/// the object's bytes.
#[derive(Debug, Clone, Copy)]
struct Member {
    key: (u32, u32),
    value: (u32, u32),
    index: Option<u32>,
    live: bool,
}

/// What each member costs the working set: itself, and its place in the
/// order.
const MEMBER: u64 = (size_of::<Member>() + size_of::<u32>()) as u64;

fn span(of: &[u8], part: &[u8]) -> Result<(u32, u32), Error> {
    let start = (part.as_ptr() as usize)
        .checked_sub(of.as_ptr() as usize)
        .ok_or_else(malformed)?;
    let start = u32::try_from(start).map_err(|_| malformed())?;
    let end = u32::try_from(part.len())
        .ok()
        .and_then(|len| start.checked_add(len))
        .ok_or_else(malformed)?;
    Ok((start, end))
}

fn part(of: &[u8], (start, end): (u32, u32)) -> Result<&[u8], Error> {
    of.get(start as usize..end as usize).ok_or_else(malformed)
}

fn write_object(
    value: Value<'_>,
    out: &mut impl Write,
    work: &mut Work,
    depth: usize,
) -> Result<(), Error> {
    let mut count = 0usize;
    for member in value.members()? {
        member?;
        count += 1;
    }
    if count == 0 {
        out.write_all(b"{}")?;
        return Ok(());
    }
    let cost = (count as u64).saturating_mul(MEMBER);
    work.take(cost)?;
    let written = write_members(value, count, out, work, depth);
    work.give(cost);
    written
}

fn write_members(
    value: Value<'_>,
    count: usize,
    out: &mut impl Write,
    work: &mut Work,
    depth: usize,
) -> Result<(), Error> {
    let of = value.0;
    let mut members: Vec<Member> = Vec::new();
    members
        .try_reserve_exact(count)
        .map_err(|_| Error::Malformed("an object's members, unallocated"))?;
    for member in value.members()? {
        let (key, value) = member?;
        members.push(Member {
            key: span(of, key.0)?,
            value: span(of, value.0)?,
            index: key.index(),
            live: true,
        });
    }
    fn key<'a>(of: &'a [u8], members: &[Member], n: u32) -> Key<'a> {
        Key(members
            .get(n as usize)
            .and_then(|m| part(of, m.key).ok())
            .unwrap_or_default())
    }
    let mut order: Vec<u32> = Vec::new();
    order
        .try_reserve_exact(count)
        .map_err(|_| Error::Malformed("an object's members, unallocated"))?;
    order.extend(0..u32::try_from(count).map_err(|_| malformed())?);
    // A repeated key: its first place, its last value.
    if count > 1 {
        order.sort_by(|&a, &b| {
            key(of, &members, a)
                .cmp_decoded(key(of, &members, b))
                .then(a.cmp(&b))
        });
        let mut start = 0;
        while start < order.len() {
            let first = order[start];
            let mut end = start + 1;
            while end < order.len()
                && key(of, &members, first).cmp_decoded(key(of, &members, order[end]))
                    == Ordering::Equal
            {
                end += 1;
            }
            if end - start > 1 {
                let last = order[end - 1];
                let value = members[last as usize].value;
                members[first as usize].value = value;
                for &later in &order[start + 1..end] {
                    members[later as usize].live = false;
                }
            }
            start = end;
        }
    }
    // The indices first, in increasing order; then the others, in theirs.
    order.clear();
    order.extend((0..members.len() as u32).filter(|&n| {
        let m = members[n as usize];
        m.live && m.index.is_some()
    }));
    order.sort_by_key(|&n| members[n as usize].index);
    order.extend((0..members.len() as u32).filter(|&n| {
        let m = members[n as usize];
        m.live && m.index.is_none()
    }));
    out.write_all(b"{")?;
    for (n, &at) in order.iter().enumerate() {
        if n > 0 {
            out.write_all(b",")?;
        }
        let member = members[at as usize];
        write_string(part(of, member.key)?, out)?;
        out.write_all(b":")?;
        write_value(Value(part(of, member.value)?), out, work, depth + 1)?;
    }
    out.write_all(b"}")?;
    Ok(())
}

/// Whether `c` is white space to JavaScript's `parseInt`: its WhiteSpace
/// and LineTerminator (not U+0085 or U+180E, which Unicode's White_Space
/// has or had).
fn js_space(c: char) -> bool {
    matches!(
        c,
        '\u{9}'..='\u{d}'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// `Number.parseInt(s, 10)`: white space skipped, a sign, then the
/// longest run of decimal digits, as the nearest double (`NaN` without
/// one, `-0` for a negative zero).
pub fn parse_int(s: &str) -> f64 {
    let s = s.trim_start_matches(js_space);
    let (negative, s) = match s.as_bytes().first() {
        Some(b'-') => (true, s.get(1..).unwrap_or_default()),
        Some(b'+') => (false, s.get(1..).unwrap_or_default()),
        _ => (false, s),
    };
    let len = s.bytes().take_while(u8::is_ascii_digit).count();
    let Some(n) = s.get(..len).filter(|d| !d.is_empty()) else {
        return f64::NAN;
    };
    let n = n.parse::<f64>().unwrap_or(f64::NAN);
    if negative { -n } else { n }
}

/// The window main's `paginate` takes of the filtered items, `[start,
/// end)`, from its query's raw `page` and `perPage` (`null` for absent):
/// `page` from `parseInt`, at least 0; `perPage` clamped to 1–100, 30 by
/// default; a value `parseInt` makes 0 or `NaN` of, or an empty one, is
/// the default.
pub fn window(page: Option<&str>, per_page: Option<&str>) -> (f64, f64) {
    fn given<'a>(s: Option<&'a str>, default: &'a str) -> &'a str {
        s.filter(|s| !s.is_empty()).unwrap_or(default)
    }
    let or = |n: f64, default: f64| if n.is_nan() || n == 0.0 { default } else { n };
    let page = or(parse_int(given(page, "0")), 0.0).max(0.0);
    let per_page = or(parse_int(given(per_page, "30")), 30.0).clamp(1.0, 100.0);
    (page * per_page, (page + 1.0) * per_page)
}

/// What main's `paginate` writes of `items`, an array: those whose
/// `item?.state?.status` is `status` (all of them for no status, or an
/// empty one), then the `window` of them, each written again.
pub fn page(
    items: Value<'_>,
    status: Option<&str>,
    (start, end): (f64, f64),
    out: &mut impl Write,
    work: &mut Work,
) -> Result<(), Error> {
    let status = status.filter(|s| !s.is_empty());
    let mut at: u64 = 0;
    let mut first = true;
    out.write_all(b"[")?;
    for item in items.elements()? {
        let item = item?;
        if let Some(status) = status {
            let state = item.get("state")?;
            let is = match state {
                Some(state) => state.get("status")?.is_some_and(|s| s.is_str(status)),
                None => false,
            };
            if !is {
                continue;
            }
        }
        let n = at as f64;
        if n >= end {
            break;
        }
        if n >= start {
            if std::mem::take(&mut first) {
            } else {
                out.write_all(b",")?;
            }
            write(item, out, work)?;
        }
        at += 1;
    }
    out.write_all(b"]")?;
    Ok(())
}

/// What seeders answered, for [`repo_meta`].
#[derive(Debug, Clone, Copy)]
pub enum Seeding<'a> {
    /// Its text's value.
    Answered(Value<'a>),
    /// It failed: main's `seeding` stays 0.
    Failed,
}

/// Opens a member, with the comma before all but the first.
fn member(out: &mut impl Write, first: &mut bool, key: &str) -> Result<(), Error> {
    if !std::mem::take(first) {
        out.write_all(b",")?;
    }
    write_string(key.as_bytes(), out)?;
    out.write_all(b":")?;
    Ok(())
}

/// A member whose value is `value`, written again, if it is defined.
fn defined(
    out: &mut impl Write,
    first: &mut bool,
    key: &str,
    value: Option<Value<'_>>,
    work: &mut Work,
) -> Result<(), Error> {
    if let Some(value) = value {
        member(out, first, key)?;
        write(value, out, work)?;
    }
    Ok(())
}

/// What main's `buildRepoMeta` makes of `repoInfo`'s value `info`, an
/// object, and of `seeders`', as `JSON.stringify` writes it: a member whose
/// value is undefined is left out; `delegates` is `[]` unless truthy,
/// `threshold` 1 if null or undefined, `visibility` `{"type":"public"}`
/// unless truthy; `seeding` is 0 when seeders failed, or answered `null`
/// (main's property read throws, and is caught), and otherwise its
/// `seeding`, left out when undefined.
pub fn repo_meta(
    info: Value<'_>,
    seeding: Seeding<'_>,
    out: &mut impl Write,
    work: &mut Work,
) -> Result<(), Error> {
    if !info.is_object() {
        return Err(Error::Malformed("repo_info that isn't an object"));
    }
    let field = |key: &str| info.get(key);
    out.write_all(b"{")?;
    let mut first = true;
    defined(out, &mut first, "rid", field("rid")?, work)?;
    member(out, &mut first, "payloads")?;
    out.write_all(br#"{"xyz.radicle.project":{"data":{"#)?;
    let mut inner = true;
    defined(out, &mut inner, "name", field("name")?, work)?;
    defined(out, &mut inner, "description", field("description")?, work)?;
    defined(
        out,
        &mut inner,
        "defaultBranch",
        field("defaultBranch")?,
        work,
    )?;
    out.write_all(br#"},"meta":{"#)?;
    let mut inner = true;
    defined(out, &mut inner, "head", field("head")?, work)?;
    member(out, &mut inner, "issues")?;
    out.write_all(b"{")?;
    defined(out, &mut true, "open", field("issuesOpen")?, work)?;
    out.write_all(b"}")?;
    member(out, &mut inner, "patches")?;
    out.write_all(b"{")?;
    defined(out, &mut true, "open", field("patchesOpen")?, work)?;
    out.write_all(b"}}}}")?;
    member(out, &mut first, "delegates")?;
    match field("delegates")?.filter(|v| v.truthy()) {
        Some(delegates) => write(delegates, out, work)?,
        None => out.write_all(b"[]")?,
    }
    member(out, &mut first, "threshold")?;
    match field("threshold")?.filter(|v| !v.is_null()) {
        Some(threshold) => write(threshold, out, work)?,
        None => out.write_all(b"1")?,
    }
    member(out, &mut first, "visibility")?;
    match field("visibility")?.filter(|v| v.truthy()) {
        Some(visibility) => write(visibility, out, work)?,
        None => out.write_all(br#"{"type":"public"}"#)?,
    }
    match seeding {
        Seeding::Answered(seeders) if !seeders.is_null() => {
            defined(out, &mut first, "seeding", seeders.get("seeding")?, work)?;
        }
        Seeding::Answered(_) | Seeding::Failed => {
            member(out, &mut first, "seeding")?;
            out.write_all(b"0")?;
        }
    }
    out.write_all(b"}")?;
    Ok(())
}

/// The README candidates, in main's order (`README_CANDIDATES`).
pub const README: [&str; 5] = [
    "README.md",
    "README.markdown",
    "README.txt",
    "README",
    "readme.md",
];

/// The README main's `findReadme` picks from the names of a root tree's
/// blobs: the first candidate among them.
pub fn readme<'n>(blobs: impl Iterator<Item = &'n str> + Clone) -> Option<&'static str> {
    README
        .into_iter()
        .find(|candidate| blobs.clone().any(|name| name == *candidate))
}

/// Writes a blob's JSON with `"path"` spliced in before its closing brace,
/// as main's `readmeAtRaw` does (`raw.slice(0, end) + ',"path":' + …`): the
/// text goes through as it is written, but for its last byte, held back.
/// [`Spliced::finish`] checks it is the object a blob always is, `{"` to
/// `}`, then writes the path and the brace.
pub struct Spliced<'w, W> {
    out: &'w mut W,
    path: &'static str,
    start: [u8; 2],
    seen: usize,
    held: Option<u8>,
}

impl<'w, W: Write> Spliced<'w, W> {
    pub fn new(out: &'w mut W, path: &'static str) -> Self {
        Self {
            out,
            path,
            start: [0; 2],
            seen: 0,
            held: None,
        }
    }

    /// The path, then the brace.
    pub fn finish(self) -> Result<(), Error> {
        if self.start != *b"{\"" || self.held != Some(b'}') {
            return Err(Error::Malformed("a blob that isn't an object"));
        }
        self.out.write_all(b",\"path\":")?;
        write_string(self.path.as_bytes(), self.out)?;
        self.out.write_all(b"}")?;
        Ok(())
    }
}

impl<W: Write> Write for Spliced<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some((&last, rest)) = buf.split_last() else {
            return Ok(0);
        };
        for &byte in buf.iter().take(2usize.saturating_sub(self.seen)) {
            if let Some(slot) = self.start.get_mut(self.seen) {
                *slot = byte;
            }
            self.seen += 1;
        }
        if let Some(held) = self.held.take() {
            self.out.write_all(&[held])?;
        }
        self.out.write_all(rest)?;
        self.held = Some(last);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
