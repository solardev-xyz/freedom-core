//! JSON as V8's `JSON.parse` reads it, for the documents the core parses
//! (the resolvers' gateway answers and Tezos metadata, RPC bodies), so the
//! core accepts and refuses exactly what the JS does:
//!
//! - numbers are doubles: `1e400` is infinite, and integers above 2^53 lose
//!   precision;
//! - escaped lone surrogates are accepted. Rust strings can't hold them, so
//!   they become U+FFFD, which is also what the WHATWG URL parser makes of
//!   them;
//! - nesting deeper than [`MAX_DEPTH`] is refused (`TooDeep`), where V8
//!   accepts any depth. That bound keeps every walk, comparison, copy and
//!   drop of a value within a small stack (design 0003, Codec deviations);
//! - a duplicate key keeps its first position and its last value, and
//!   objects keep JavaScript's property order: array-index keys first, in
//!   numeric order, then the others in insertion order;
//! - only JSON whitespace (tab, LF, CR, space) is allowed around tokens, so
//!   a byte-order mark is an error, as in V8.

/// A parsed JSON value with JavaScript's semantics.
#[derive(Debug, Clone, PartialEq)]
pub enum JsValue {
    /// `undefined`: never parsed from JSON; a present-undefined property
    /// in a result (Tezos' `ttl`).
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsValue>),
    /// Properties in JavaScript's order, each key once.
    Object(Vec<(String, JsValue)>),
}

/// Dropped without recursion: children go onto an explicit stack, so no
/// value, however deep, can overflow the stack when it is freed.
impl Drop for JsValue {
    fn drop(&mut self) {
        let mut stack = Vec::new();
        take_children(self, &mut stack);
        while let Some(mut value) = stack.pop() {
            take_children(&mut value, &mut stack);
            // `value` has no children left; dropping it doesn't recurse.
        }
    }
}

fn take_children(value: &mut JsValue, stack: &mut Vec<JsValue>) {
    match value {
        JsValue::Array(items) => stack.append(items),
        JsValue::Object(props) => stack.extend(std::mem::take(props).into_iter().map(|(_, v)| v)),
        _ => {}
    }
}

/// What an allocation of `size` bytes takes, as an allocator lays it out:
/// an 8-byte header, 16-byte steps, 32 bytes at least (`memory-budgets`).
pub fn allocation(size: usize) -> usize {
    if size == 0 {
        0
    } else {
        size.saturating_add(8)
            .div_ceil(16)
            .saturating_mul(16)
            .max(32)
    }
}

impl JsValue {
    /// What the value holds on the heap, as an allocator lays it out (an
    /// 8-byte header, 16-byte steps, 32 bytes at least), not counting its
    /// own 32-byte slot: what a copy of it costs (`memory-budgets`).
    pub fn held(&self) -> usize {
        let block = allocation;
        // Iterative: a value can be as deep as the parser allows.
        let mut held = 0usize;
        let mut stack = vec![self];
        while let Some(value) = stack.pop() {
            match value {
                Self::String(text) => held = held.saturating_add(block(text.capacity())),
                Self::Array(items) => {
                    held = held.saturating_add(block(
                        items.capacity().saturating_mul(std::mem::size_of::<Self>()),
                    ));
                    stack.extend(items.iter());
                }
                Self::Object(props) => {
                    held = held.saturating_add(block(
                        props
                            .capacity()
                            .saturating_mul(std::mem::size_of::<(String, Self)>()),
                    ));
                    for (key, value) in props {
                        held = held.saturating_add(block(key.capacity()));
                        stack.push(value);
                    }
                }
                _ => {}
            }
        }
        held
    }

    /// A property, as `object[key]` reads it (`None` when absent or when this
    /// isn't an object).
    pub fn get(&self, key: &str) -> Option<&JsValue> {
        match self {
            JsValue::Object(props) => props.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[JsValue]> {
        match self {
            JsValue::Array(items) => Some(items),
            _ => None,
        }
    }

    /// `!!value`: JavaScript truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            JsValue::Undefined | JsValue::Null => false,
            JsValue::Bool(b) => *b,
            JsValue::Number(n) => *n != 0.0 && !n.is_nan(),
            JsValue::String(s) => !s.is_empty(),
            JsValue::Array(_) | JsValue::Object(_) => true,
        }
    }

    /// `String(value)`. An object with an own `toString` key throws, as in
    /// JavaScript: no JSON value is callable, so `ToPrimitive` finds neither
    /// a usable `toString` nor a primitive `valueOf`.
    pub fn js_string(&self) -> Result<String, ToPrimitiveError> {
        Ok(match self {
            JsValue::Undefined => "undefined".into(),
            JsValue::Null => "null".into(),
            JsValue::Bool(b) => b.to_string(),
            JsValue::Number(n) => number_to_string(*n),
            JsValue::String(s) => s.clone(),
            JsValue::Array(items) => join_arrays(items)?,
            JsValue::Object(_) if self.get("toString").is_some() => return Err(ToPrimitiveError),
            JsValue::Object(_) => "[object Object]".into(),
        })
    }

    /// `JSON.stringify(value)`.
    pub fn stringify(&self) -> String {
        let mut out = String::new();
        stringify_into(self, &mut out);
        out
    }
}

/// `Array.prototype.join(',')`, nested arrays included, without recursion:
/// null elements are empty, arrays join their own elements.
fn join_arrays(root: &[JsValue]) -> Result<String, ToPrimitiveError> {
    let mut stack: Vec<(std::slice::Iter<'_, JsValue>, Vec<String>)> =
        vec![(root.iter(), Vec::new())];
    loop {
        let Some((items, parts)) = stack.last_mut() else {
            return Ok(String::new());
        };
        match items.next() {
            Some(JsValue::Array(inner)) => stack.push((inner.iter(), Vec::new())),
            Some(JsValue::Undefined | JsValue::Null) => parts.push(String::new()),
            Some(item) => parts.push(item.js_string()?),
            None => {
                let joined = stack
                    .pop()
                    .map(|(_, parts)| parts.join(","))
                    .unwrap_or_default();
                match stack.last_mut() {
                    Some((_, parent)) => parent.push(joined),
                    None => return Ok(joined),
                }
            }
        }
    }
}

/// `String(value)` would throw a `TypeError` ("Cannot convert object to
/// primitive value").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Cannot convert object to primitive value")]
pub struct ToPrimitiveError;

/// The deepest nesting the core accepts.
pub const MAX_DEPTH: usize = 512;

/// Why a document isn't accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JsonError {
    #[error("invalid JSON at byte {0}")]
    Syntax(usize),
    #[error("JSON nested deeper than {MAX_DEPTH} levels")]
    TooDeep,
}

enum Frame {
    Array(Vec<JsValue>),
    /// Properties, their index by key, and the key awaiting its value.
    Object(
        Vec<(String, JsValue)>,
        std::collections::BTreeMap<String, usize>,
        Option<String>,
    ),
}

/// `JSON.parse(text)`.
pub fn parse(text: &str) -> Result<JsValue, JsonError> {
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
    };
    let mut stack: Vec<Frame> = Vec::new();
    p.ws();
    loop {
        // Parse one value, or open a container.
        // Every container is a level, an empty one included.
        if matches!(p.peek(), Some(b'{' | b'[')) && stack.len() >= MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        let mut value = match p.peek() {
            Some(b'{') => {
                p.i += 1;
                p.ws();
                if p.peek() == Some(b'}') {
                    p.i += 1;
                    JsValue::Object(Vec::new())
                } else {
                    let key = p.key()?;
                    stack.push(Frame::Object(Vec::new(), Default::default(), Some(key)));
                    p.ws();
                    continue;
                }
            }
            Some(b'[') => {
                p.i += 1;
                p.ws();
                if p.peek() == Some(b']') {
                    p.i += 1;
                    JsValue::Array(Vec::new())
                } else {
                    stack.push(Frame::Array(Vec::new()));
                    continue;
                }
            }
            _ => p.scalar()?,
        };
        // Attach it, closing every container it completes.
        loop {
            p.ws();
            match stack.last_mut() {
                None => {
                    return if p.i == p.s.len() {
                        Ok(value)
                    } else {
                        Err(JsonError::Syntax(p.i))
                    };
                }
                Some(Frame::Array(items)) => {
                    items.push(value);
                    match p.next() {
                        Some(b',') => {
                            p.ws();
                            break;
                        }
                        Some(b']') => {
                            let Some(Frame::Array(mut items)) = stack.pop() else {
                                return Err(JsonError::Syntax(p.i));
                            };
                            // Closed, it keeps only its length: a growing
                            // vector's spare room never outlives the parse
                            // (`memory-budgets`).
                            items.shrink_to_fit();
                            value = JsValue::Array(items);
                        }
                        _ => return Err(JsonError::Syntax(p.i)),
                    }
                }
                Some(Frame::Object(props, index, pending)) => {
                    let key = pending.take().ok_or(JsonError::Syntax(p.i))?;
                    set_property(props, index, key, value);
                    match p.next() {
                        Some(b',') => {
                            p.ws();
                            *pending = Some(p.key()?);
                            p.ws();
                            break;
                        }
                        Some(b'}') => {
                            let Some(Frame::Object(props, _, _)) = stack.pop() else {
                                return Err(JsonError::Syntax(p.i));
                            };
                            let mut props = order_properties(props);
                            props.shrink_to_fit();
                            value = JsValue::Object(props);
                        }
                        _ => return Err(JsonError::Syntax(p.i)),
                    }
                }
            }
        }
    }
}

/// `CreateDataProperty` (a repeated key keeps its place and takes the
/// value), indexed so many keys stay linear.
fn set_property(
    props: &mut Vec<(String, JsValue)>,
    index: &mut std::collections::BTreeMap<String, usize>,
    key: String,
    value: JsValue,
) {
    if let Some(&i) = index.get(&key) {
        props[i].1 = value;
    } else {
        index.insert(key.clone(), props.len());
        props.push((key, value));
    }
}

/// An array index: the canonical decimal form of an integer below 2^32 - 1.
fn array_index(key: &str) -> Option<u32> {
    let value: u32 = key.parse().ok()?;
    (value != u32::MAX && value.to_string() == key).then_some(value)
}

/// JavaScript's own-property order: array indices ascending, then strings
/// in insertion order.
fn order_properties(props: Vec<(String, JsValue)>) -> Vec<(String, JsValue)> {
    let (mut indices, strings): (Vec<_>, Vec<_>) = props
        .into_iter()
        .partition(|(k, _)| array_index(k).is_some());
    indices.sort_by_key(|(k, _)| array_index(k));
    indices.into_iter().chain(strings).collect()
}

/// Two ASCII hex digits as a byte. (`u8::from_str_radix` would also take a
/// sign, which JSON's `\u` escapes don't allow.)
fn hex_byte(pair: &[u8]) -> Option<u8> {
    match pair {
        [hi, lo] if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
            u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()
        }
        _ => None,
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.i += 1;
        Some(b)
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn key(&mut self) -> Result<String, JsonError> {
        if self.peek() != Some(b'"') {
            return Err(JsonError::Syntax(self.i));
        }
        let key = self.string()?;
        self.ws();
        if self.next() != Some(b':') {
            return Err(JsonError::Syntax(self.i));
        }
        self.ws();
        Ok(key)
    }

    fn literal(&mut self, word: &[u8], value: JsValue) -> Result<JsValue, JsonError> {
        if self.s.get(self.i..self.i + word.len()) == Some(word) {
            self.i += word.len();
            Ok(value)
        } else {
            Err(JsonError::Syntax(self.i))
        }
    }

    fn scalar(&mut self) -> Result<JsValue, JsonError> {
        match self.peek() {
            Some(b'"') => Ok(JsValue::String(self.string()?)),
            Some(b't') => self.literal(b"true", JsValue::Bool(true)),
            Some(b'f') => self.literal(b"false", JsValue::Bool(false)),
            Some(b'n') => self.literal(b"null", JsValue::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(JsonError::Syntax(self.i)),
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<JsValue, JsonError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(JsonError::Syntax(self.i)),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return Err(JsonError::Syntax(self.i));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(JsonError::Syntax(self.i));
            }
        }
        // Correctly rounded, as V8; out of range is infinite.
        let text =
            std::str::from_utf8(&self.s[start..self.i]).map_err(|_| JsonError::Syntax(start))?;
        text.parse::<f64>()
            .map(JsValue::Number)
            .map_err(|_| JsonError::Syntax(start))
    }

    fn hex4(&mut self) -> Result<u16, JsonError> {
        let hex = self
            .s
            .get(self.i..self.i + 4)
            .ok_or(JsonError::Syntax(self.i))?;
        let (Some(hi), Some(lo)) = (hex_byte(&hex[..2]), hex_byte(&hex[2..])) else {
            return Err(JsonError::Syntax(self.i));
        };
        let unit = u16::from_be_bytes([hi, lo]);
        self.i += 4;
        Ok(unit)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.i += 1; // the opening quote
        let mut units: Vec<u16> = Vec::new();
        loop {
            let start = self.i;
            // A run of plain characters, copied as UTF-16.
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.i += 1;
            }
            let run = std::str::from_utf8(&self.s[start..self.i])
                .map_err(|_| JsonError::Syntax(start))?;
            units.extend(run.encode_utf16());
            match self.next() {
                Some(b'"') => {
                    let mut text = String::from_utf16_lossy(&units);
                    text.shrink_to_fit();
                    return Ok(text);
                }
                Some(b'\\') => {
                    let unit = match self.next() {
                        Some(b'"') => 0x22,
                        Some(b'\\') => 0x5c,
                        Some(b'/') => 0x2f,
                        Some(b'b') => 0x08,
                        Some(b'f') => 0x0c,
                        Some(b'n') => 0x0a,
                        Some(b'r') => 0x0d,
                        Some(b't') => 0x09,
                        Some(b'u') => self.hex4()?,
                        _ => return Err(JsonError::Syntax(self.i)),
                    };
                    units.push(unit);
                }
                // A raw control character, or the end of the input.
                _ => return Err(JsonError::Syntax(self.i)),
            }
        }
    }
}

/// JavaScript's `Number.prototype.toString()` for a double.
pub fn number_to_string(n: f64) -> String {
    if n.is_nan() {
        return "NaN".into();
    }
    if n == 0.0 {
        return "0".into();
    }
    if n.is_infinite() {
        return if n > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        };
    }
    let sign = if n < 0.0 { "-" } else { "" };
    // The fewest digits that round-trip (Rust's `{:e}`), and of those
    // ECMAScript takes the decimal closest to the value, ties to even. The
    // nearest decimal with that many digits is correctly rounded by `{:.*e}`;
    // it is the answer whenever it round-trips, which fails only at the
    // asymmetric rounding interval of a power of two.
    let shortest = format!("{:e}", n.abs());
    let k = shortest.split_once('e').map_or(shortest.len(), |(m, _)| {
        m.chars().filter(char::is_ascii_digit).count()
    });
    let nearest = format!("{:.*e}", k.saturating_sub(1), n.abs());
    let sci = if nearest.parse::<f64>() == Ok(n.abs()) {
        nearest
    } else {
        shortest
    };
    let (mantissa, exponent) = sci.split_once('e').unwrap_or((&sci, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let k = digits.len() as i64;
    let n_exp = exponent.parse::<i64>().unwrap_or(0) + 1;
    let body = if k <= n_exp && n_exp <= 21 {
        format!("{digits}{}", "0".repeat((n_exp - k) as usize))
    } else if 0 < n_exp && n_exp <= 21 {
        format!(
            "{}.{}",
            &digits[..n_exp as usize],
            &digits[n_exp as usize..]
        )
    } else if -6 < n_exp && n_exp <= 0 {
        format!("0.{}{digits}", "0".repeat((-n_exp) as usize))
    } else {
        let e = n_exp - 1;
        let exp = if e >= 0 {
            format!("e+{e}")
        } else {
            format!("e-{}", -e)
        };
        if k == 1 {
            format!("{digits}{exp}")
        } else {
            format!("{}.{}{exp}", &digits[..1], &digits[1..])
        }
    };
    format!("{sign}{body}")
}

/// `JSON.stringify`, without recursion: pending pieces on an explicit stack.
fn stringify_into(value: &JsValue, out: &mut String) {
    enum Piece<'a> {
        Value(&'a JsValue),
        Key(&'a str),
        Text(&'static str),
    }
    let mut stack = vec![Piece::Value(value)];
    while let Some(piece) = stack.pop() {
        match piece {
            Piece::Text(text) => out.push_str(text),
            Piece::Key(key) => {
                quote(key, out);
                out.push(':');
            }
            // `undefined` is `null` in an array; object members holding it
            // are skipped below.
            Piece::Value(JsValue::Undefined | JsValue::Null) => out.push_str("null"),
            Piece::Value(JsValue::Bool(b)) => out.push_str(if *b { "true" } else { "false" }),
            Piece::Value(JsValue::Number(n)) => {
                out.push_str(&if n.is_finite() {
                    number_to_string(*n)
                } else {
                    "null".into()
                });
            }
            Piece::Value(JsValue::String(s)) => quote(s, out),
            Piece::Value(JsValue::Array(items)) => {
                out.push('[');
                stack.push(Piece::Text("]"));
                for (i, item) in items.iter().enumerate().rev() {
                    stack.push(Piece::Value(item));
                    if i > 0 {
                        stack.push(Piece::Text(","));
                    }
                }
            }
            Piece::Value(JsValue::Object(props)) => {
                out.push('{');
                stack.push(Piece::Text("}"));
                let props: Vec<&(String, JsValue)> = props
                    .iter()
                    .filter(|(_, v)| !matches!(v, JsValue::Undefined))
                    .collect();
                for (i, (key, item)) in props.iter().enumerate().rev() {
                    stack.push(Piece::Value(item));
                    stack.push(Piece::Key(key));
                    if i > 0 {
                        stack.push(Piece::Text(","));
                    }
                }
            }
        }
    }
}

fn quote(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_like_v8() {
        assert_eq!(
            parse(r#"{"data":"0x01","ignored":1e400}"#)
                .unwrap()
                .get("ignored"),
            Some(&JsValue::Number(f64::INFINITY))
        );
        assert_eq!(
            parse(r#"{"x":"\ud800","data":"0x01"}"#).unwrap().get("x"),
            Some(&JsValue::String("\u{FFFD}".into()))
        );
        // Depth is bounded: 1,024 levels parse, 1,025 are refused.
        let nest = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(parse(&nest(MAX_DEPTH)).is_ok());
        assert_eq!(parse(&nest(MAX_DEPTH + 1)), Err(JsonError::TooDeep));
        // Far deeper input never touches the stack: refused, dropped safely.
        assert_eq!(
            parse(&format!(r#"{{"data":"0x01","x":{}}}"#, nest(100_000))),
            Err(JsonError::TooDeep)
        );
        assert_eq!(
            parse(r#"{"a":1,"a":2}"#).unwrap(),
            JsValue::Object(vec![("a".into(), JsValue::Number(2.0))])
        );
        let ordered = parse(r#"{"b":1,"2":0,"a":3,"1":4,"01":5}"#).unwrap();
        assert_eq!(ordered.stringify(), r#"{"1":4,"2":0,"b":1,"a":3,"01":5}"#);
        assert_eq!(
            parse("9007199254740993").unwrap(),
            JsValue::Number(9007199254740992.0)
        );
        for bad in [
            "\u{FEFF}{}",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "01",
            "1.",
            "-",
            "\"\u{1}\"",
            "nul",
            "[1] x",
            "\u{a0}1",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_deepest_value_is_stack_safe() {
        // Parsing, lookups, stringify, String() and drop never recurse, so
        // the deepest accepted value, and far deeper rejected input, fit a
        // 64 KiB stack even unoptimized, on every platform.
        let handle = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let text = format!(
                    "{}{}",
                    r#"{"a":["#.repeat(MAX_DEPTH / 2),
                    "]}".repeat(MAX_DEPTH / 2)
                );
                let value = parse(&text).unwrap();
                assert_eq!(value.stringify().len(), text.len());
                assert_eq!(value.js_string().unwrap(), "[object Object]");
                let arrays = parse(&format!(
                    "{}{}",
                    "[".repeat(MAX_DEPTH),
                    "]".repeat(MAX_DEPTH)
                ))
                .unwrap();
                assert_eq!(arrays.js_string().unwrap(), "");
                drop((value, arrays));
                assert_eq!(parse(&"[".repeat(200_000)), Err(JsonError::TooDeep));
            })
            .unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn many_keys_stay_linear() {
        let keys: Vec<String> = (0..50_000).map(|i| format!(r#""k{i}":{i}"#)).collect();
        let started = std::time::Instant::now();
        let parsed = parse(&format!("{{{}}}", keys.join(","))).unwrap();
        let JsValue::Object(props) = &parsed else {
            panic!()
        };
        assert_eq!(props.len(), 50_000);
        assert!(started.elapsed().as_secs() < 2, "{:?}", started.elapsed());
    }

    #[test]
    fn hex_escapes_have_no_sign() {
        assert!(parse(r#""\u+041""#).is_err());
        assert!(parse(r#""\u-041""#).is_err());
        assert_eq!(parse(r#""\u0041""#).unwrap(), JsValue::String("A".into()));
    }

    #[test]
    fn numbers_print_like_javascript() {
        for (n, text) in [
            (1.0, "1"),
            (-0.0, "0"),
            (0.1, "0.1"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (1.5e-7, "1.5e-7"),
            (0.000001, "0.000001"),
            (123.456, "123.456"),
            (f64::INFINITY, "Infinity"),
            (9007199254740993.0, "9007199254740992"),
            // Of the shortest digit strings, ECMAScript takes the closest.
            (-1221953339504170.3, "-1221953339504170.2"),
            // 137839762462415.625, an exact midpoint between the two shortest
            // candidates: the even one.
            (f64::from_bits(0x42df_5754_84f5_b3e8), "137839762462415.62"),
        ] {
            assert_eq!(number_to_string(n), text, "{n}");
        }
    }

    #[test]
    fn strings_of_values() {
        let v = parse(r#"[["PAIR"],null,1.5,true,{"a":1}]"#).unwrap();
        assert_eq!(v.js_string().unwrap(), "PAIR,,1.5,true,[object Object]");
        // An own toString key: ToPrimitive throws.
        assert_eq!(
            parse(r#"{"toString":1}"#).unwrap().js_string(),
            Err(ToPrimitiveError)
        );
        assert_eq!(
            parse(r#"[[{"toString":1}]]"#).unwrap().js_string(),
            Err(ToPrimitiveError)
        );
    }
}
