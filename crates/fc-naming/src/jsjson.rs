//! JSON as V8's `JSON.parse` reads it, for the documents the resolvers
//! parse (gateway answers, Tezos metadata, and later RPC bodies), so the
//! core accepts and refuses exactly what the JS does:
//!
//! - numbers are doubles: `1e400` is infinite, and integers above 2^53 lose
//!   precision;
//! - escaped lone surrogates are accepted. Rust strings can't hold them, so
//!   they become U+FFFD, which is also what the WHATWG URL parser makes of
//!   them;
//! - nesting depth is limited only by the input (the parser is iterative);
//! - a duplicate key keeps its first position and its last value, and
//!   objects keep JavaScript's property order: array-index keys first, in
//!   numeric order, then the others in insertion order;
//! - only JSON whitespace (tab, LF, CR, space) is allowed around tokens, so
//!   a byte-order mark is an error, as in V8.

/// A parsed JSON value with JavaScript's semantics.
#[derive(Debug, Clone, PartialEq)]
pub enum JsValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsValue>),
    /// Properties in JavaScript's order, each key once.
    Object(Vec<(String, JsValue)>),
}

impl JsValue {
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
            JsValue::Null => false,
            JsValue::Bool(b) => *b,
            JsValue::Number(n) => *n != 0.0 && !n.is_nan(),
            JsValue::String(s) => !s.is_empty(),
            JsValue::Array(_) | JsValue::Object(_) => true,
        }
    }

    /// `String(value)`.
    pub fn js_string(&self) -> String {
        match self {
            JsValue::Null => "null".into(),
            JsValue::Bool(b) => b.to_string(),
            JsValue::Number(n) => number_to_string(*n),
            JsValue::String(s) => s.clone(),
            // `Array.prototype.join(',')`, where null elements are empty.
            JsValue::Array(items) => items
                .iter()
                .map(|item| {
                    if matches!(item, JsValue::Null) {
                        String::new()
                    } else {
                        item.js_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(","),
            JsValue::Object(_) => "[object Object]".into(),
        }
    }

    /// `JSON.stringify(value)`.
    pub fn stringify(&self) -> String {
        let mut out = String::new();
        stringify_into(self, &mut out);
        out
    }
}

/// Why a document isn't JSON.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid JSON at byte {0}")]
pub struct JsonError(pub usize);

enum Frame {
    Array(Vec<JsValue>),
    Object(Vec<(String, JsValue)>, Option<String>),
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
        let mut value = match p.peek() {
            Some(b'{') => {
                p.i += 1;
                p.ws();
                if p.peek() == Some(b'}') {
                    p.i += 1;
                    JsValue::Object(Vec::new())
                } else {
                    let key = p.key()?;
                    stack.push(Frame::Object(Vec::new(), Some(key)));
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
                        Err(JsonError(p.i))
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
                            let Some(Frame::Array(items)) = stack.pop() else {
                                return Err(JsonError(p.i));
                            };
                            value = JsValue::Array(items);
                        }
                        _ => return Err(JsonError(p.i)),
                    }
                }
                Some(Frame::Object(props, pending)) => {
                    let key = pending.take().ok_or(JsonError(p.i))?;
                    set_property(props, key, value);
                    match p.next() {
                        Some(b',') => {
                            p.ws();
                            *pending = Some(p.key()?);
                            p.ws();
                            break;
                        }
                        Some(b'}') => {
                            let Some(Frame::Object(props, _)) = stack.pop() else {
                                return Err(JsonError(p.i));
                            };
                            value = JsValue::Object(order_properties(props));
                        }
                        _ => return Err(JsonError(p.i)),
                    }
                }
            }
        }
    }
}

/// `CreateDataProperty`: a repeated key keeps its place, takes the value.
fn set_property(props: &mut Vec<(String, JsValue)>, key: String, value: JsValue) {
    if let Some(slot) = props.iter_mut().find(|(k, _)| *k == key) {
        slot.1 = value;
    } else {
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
            return Err(JsonError(self.i));
        }
        let key = self.string()?;
        self.ws();
        if self.next() != Some(b':') {
            return Err(JsonError(self.i));
        }
        self.ws();
        Ok(key)
    }

    fn literal(&mut self, word: &[u8], value: JsValue) -> Result<JsValue, JsonError> {
        if self.s.get(self.i..self.i + word.len()) == Some(word) {
            self.i += word.len();
            Ok(value)
        } else {
            Err(JsonError(self.i))
        }
    }

    fn scalar(&mut self) -> Result<JsValue, JsonError> {
        match self.peek() {
            Some(b'"') => Ok(JsValue::String(self.string()?)),
            Some(b't') => self.literal(b"true", JsValue::Bool(true)),
            Some(b'f') => self.literal(b"false", JsValue::Bool(false)),
            Some(b'n') => self.literal(b"null", JsValue::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(JsonError(self.i)),
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
            _ => return Err(JsonError(self.i)),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return Err(JsonError(self.i));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(JsonError(self.i));
            }
        }
        // Correctly rounded, as V8; out of range is infinite.
        let text = std::str::from_utf8(&self.s[start..self.i]).map_err(|_| JsonError(start))?;
        text.parse::<f64>()
            .map(JsValue::Number)
            .map_err(|_| JsonError(start))
    }

    fn hex4(&mut self) -> Result<u16, JsonError> {
        let hex = self.s.get(self.i..self.i + 4).ok_or(JsonError(self.i))?;
        let text = std::str::from_utf8(hex).map_err(|_| JsonError(self.i))?;
        let unit = u16::from_str_radix(text, 16).map_err(|_| JsonError(self.i))?;
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
            let run = std::str::from_utf8(&self.s[start..self.i]).map_err(|_| JsonError(start))?;
            units.extend(run.encode_utf16());
            match self.next() {
                Some(b'"') => return Ok(String::from_utf16_lossy(&units)),
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
                        _ => return Err(JsonError(self.i)),
                    };
                    units.push(unit);
                }
                // A raw control character, or the end of the input.
                _ => return Err(JsonError(self.i)),
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
    // Rust's `{:e}` gives the shortest round-trip digits, as JavaScript uses.
    let sci = format!("{:e}", n.abs());
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

fn stringify_into(value: &JsValue, out: &mut String) {
    match value {
        JsValue::Null => out.push_str("null"),
        JsValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JsValue::Number(n) => out.push_str(&if n.is_finite() {
            number_to_string(*n)
        } else {
            "null".into()
        }),
        JsValue::String(s) => quote(s, out),
        JsValue::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                stringify_into(item, out);
            }
            out.push(']');
        }
        JsValue::Object(props) => {
            out.push('{');
            for (i, (key, item)) in props.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                quote(key, out);
                out.push(':');
                stringify_into(item, out);
            }
            out.push('}');
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
        let deep = format!("{}{}", "[".repeat(5000), "]".repeat(5000));
        assert!(parse(&deep).is_ok());
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
        ] {
            assert_eq!(number_to_string(n), text, "{n}");
        }
    }

    #[test]
    fn strings_of_values() {
        let v = parse(r#"[["PAIR"],null,1.5,true,{"a":1}]"#).unwrap();
        assert_eq!(v.js_string(), "PAIR,,1.5,true,[object Object]");
    }
}
