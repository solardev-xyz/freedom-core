//! [`JsString`]: a JavaScript string, lone surrogates included (#95).

use std::fmt;
use std::ops::Deref;

/// A JavaScript string: UTF-16 code units, lone surrogates included, as
/// `JSON.parse` makes them (#95).
///
/// - **As a Rust string** ([`JsString::as_str`], `Deref<Target = str>`), each
///   lone surrogate reads as U+FFFD: what a `str` can hold, and what the
///   WHATWG URL parser and `TextEncoder` make of one.
/// - **As JavaScript sees it,** every unit counts: equality, order and
///   hashing tell `"\ud800"`, `"\udc00"` and `"�"` apart, as `===`
///   does, so neither object keys nor compared values merge. [`JsString::units`]
///   gives the units back, and `JSON.stringify` writes a lone surrogate as
///   its `\uXXXX` escape.
///
/// A string without lone surrogates (the common case) holds its text and
/// nothing else: no allocation beyond the text.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct JsString {
    /// The text, each lone surrogate as U+FFFD.
    text: Box<str>,
    /// Which of those U+FFFDs are lone surrogates, and which.
    lone: Option<Box<LoneUnits>>,
}

/// Lone surrogates: the byte offset in the text of the U+FFFD that stands
/// for each, and the surrogate, in order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct LoneUnits(Vec<(u32, u16)>);

impl JsString {
    /// A string from its UTF-16 code units, lone surrogates kept.
    pub fn from_units(units: &[u16]) -> Self {
        let mut text = String::with_capacity(units.len());
        let mut lone = Vec::new();
        for decoded in char::decode_utf16(units.iter().copied()) {
            match decoded {
                Ok(c) => text.push(c),
                Err(e) => {
                    // Texts are bounded far below 4 GiB (frames, 1 MiB); an
                    // offset past u32 would be one no input can reach.
                    let at = u32::try_from(text.len()).unwrap_or(u32::MAX);
                    lone.push((at, e.unpaired_surrogate()));
                    text.push(char::REPLACEMENT_CHARACTER);
                }
            }
        }
        JsString {
            text: text.into_boxed_str(),
            lone: (!lone.is_empty()).then(|| Box::new(LoneUnits(lone))),
        }
    }

    /// The text, each lone surrogate as U+FFFD.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether it holds no lone surrogate (JavaScript's `isWellFormed()`).
    pub fn is_well_formed(&self) -> bool {
        self.lone.is_none()
    }

    /// Its UTF-16 code units, lone surrogates as they are.
    pub fn units(&self) -> Units<'_> {
        Units {
            text: &self.text,
            at: 0,
            lone: self.lone.as_deref().map_or(&[], |l| l.0.as_slice()),
            pending: None,
        }
    }

    /// Its length in UTF-16 code units (JavaScript's `length`).
    pub fn utf16_len(&self) -> usize {
        // A lone surrogate is one unit, as its U+FFFD is.
        self.text.encode_utf16().count()
    }

    /// The text, each lone surrogate as U+FFFD.
    pub fn into_string(self) -> String {
        self.text.into_string()
    }

    /// What it holds on the heap: its text, and its lone surrogates' list.
    pub fn heap_bytes(&self) -> usize {
        self.allocations().iter().sum()
    }

    /// The sizes of its separate heap allocations: the text, and, when it
    /// holds lone surrogates, their box and that list's buffer. Each is a
    /// separate allocation, so each is charged on its own
    /// ([`crate::allocation`]). An absent one is 0.
    pub fn allocations(&self) -> [usize; 3] {
        let (boxed, buffer) = self.lone.as_deref().map_or((0, 0), |l| {
            (
                std::mem::size_of::<LoneUnits>(),
                l.0.capacity()
                    .saturating_mul(std::mem::size_of::<(u32, u16)>()),
            )
        });
        [self.text.len(), boxed, buffer]
    }

    /// Whether the U+FFFD at byte `at` stands for a lone surrogate.
    fn lone_at(&self, at: usize) -> Option<u16> {
        let lone = self.lone.as_deref()?;
        let at = u32::try_from(at).ok()?;
        lone.0
            .binary_search_by_key(&at, |(offset, _)| *offset)
            .ok()
            .map(|i| lone.0[i].1)
    }

    /// `JSON.stringify`'s quoting (well-formed, as since ES2019): `"`, `\` and
    /// control characters escaped, a lone surrogate as `\uXXXX`, everything
    /// else as it is.
    pub fn quote_into(&self, out: &mut String) {
        out.push('"');
        for (at, c) in self.text.char_indices() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\u{08}' => out.push_str("\\b"),
                '\u{0c}' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                char::REPLACEMENT_CHARACTER => match self.lone_at(at) {
                    Some(unit) => out.push_str(&format!("\\u{unit:04x}")),
                    None => out.push(c),
                },
                c => out.push(c),
            }
        }
        out.push('"');
    }
}

/// [`JsString::units`].
pub struct Units<'a> {
    text: &'a str,
    at: usize,
    lone: &'a [(u32, u16)],
    /// The low half of a pair already begun.
    pending: Option<u16>,
}

impl Iterator for Units<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        if let Some(low) = self.pending.take() {
            return Some(low);
        }
        let c = self.text[self.at..].chars().next()?;
        let at = self.at;
        self.at += c.len_utf8();
        if c == char::REPLACEMENT_CHARACTER
            && let Some(&(offset, unit)) = self.lone.first()
            && usize::try_from(offset).ok() == Some(at)
        {
            self.lone = &self.lone[1..];
            return Some(unit);
        }
        let mut pair = [0u16; 2];
        let encoded = c.encode_utf16(&mut pair);
        if let [high, low] = encoded {
            self.pending = Some(*low);
            Some(*high)
        } else {
            Some(encoded[0])
        }
    }
}

/// JavaScript's order: by UTF-16 code units, as `<` compares strings.
impl Ord for JsString {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.units().cmp(other.units())
    }
}

impl PartialOrd for JsString {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Deref for JsString {
    type Target = str;

    fn deref(&self) -> &str {
        &self.text
    }
}

impl AsRef<str> for JsString {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for JsString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl fmt::Debug for JsString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.lone {
            None => fmt::Debug::fmt(&self.text, f),
            Some(lone) => write!(f, "{:?} (lone surrogates {:?})", self.text, lone.0),
        }
    }
}

impl From<&str> for JsString {
    fn from(text: &str) -> Self {
        JsString {
            text: text.into(),
            lone: None,
        }
    }
}

impl From<String> for JsString {
    fn from(text: String) -> Self {
        JsString {
            text: text.into_boxed_str(),
            lone: None,
        }
    }
}

impl From<&String> for JsString {
    fn from(text: &String) -> Self {
        Self::from(text.as_str())
    }
}

impl PartialEq<str> for JsString {
    /// Equal to a Rust string only when well formed: a `str` holds no lone
    /// surrogate, so `"\ud800"` is never `"\u{FFFD}"`.
    fn eq(&self, other: &str) -> bool {
        self.is_well_formed() && *self.text == *other
    }
}

impl PartialEq<&str> for JsString {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

impl PartialEq<String> for JsString {
    fn eq(&self, other: &String) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<JsString> for str {
    fn eq(&self, other: &JsString) -> bool {
        other == self
    }
}

impl PartialEq<JsString> for &str {
    fn eq(&self, other: &JsString) -> bool {
        other == *self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn lone_surrogates_stay_distinct() {
        let high = JsString::from_units(&[0xd800]);
        let low = JsString::from_units(&[0xdc00]);
        let replacement = JsString::from_units(&[0xfffd]);
        assert_ne!(high, low);
        assert_ne!(high, replacement);
        assert_eq!(high.as_str(), "\u{FFFD}");
        assert_eq!(replacement, "\u{FFFD}");
        assert!(high != "\u{FFFD}");
        assert!(!high.is_well_formed());
        assert_eq!(high, JsString::from_units(&[0xd800]));
    }

    #[test]
    fn units_round_trip() {
        for input in [
            units("plain"),
            units("a\u{1F600}b\u{FFFD}"),
            vec![0xd800],
            vec![0x61, 0xdc00, 0x62, 0xd83d, 0xde00, 0xd83d],
            vec![0xfffd, 0xd800, 0xfffd, 0xdfff],
            vec![],
        ] {
            let s = JsString::from_units(&input);
            assert_eq!(s.units().collect::<Vec<_>>(), input);
            assert_eq!(s.utf16_len(), input.len());
        }
    }

    #[test]
    fn quoting_is_json_stringify() {
        let quote = |units: &[u16]| {
            let mut out = String::new();
            JsString::from_units(units).quote_into(&mut out);
            out
        };
        assert_eq!(quote(&[0xd800]), r#""\ud800""#);
        assert_eq!(quote(&[0xfffd, 0xdc00]), "\"\u{FFFD}\\udc00\"");
        assert_eq!(quote(&units("a\"\\\n\u{1}")), r#""a\"\\\n\u0001""#);
    }

    #[test]
    fn order_is_utf16_order() {
        let s = |units: &[u16]| JsString::from_units(units);
        // As in V8: '\ud800' < '\ufffd', and '\u{10000}' < '\ue000'.
        assert!(s(&[0xd800]) < s(&[0xfffd]));
        assert!(s(&[0xd800, 0xdc00]) < s(&[0xe000]));
        assert!(s(&[0xdc00]) > s(&[0xd800]));
        assert!(s(&[0x61]) < s(&[0x61, 0xd800]));
        // Order agrees with equality for every single unit.
        let all: Vec<JsString> = (0..=u16::MAX).map(|u| s(&[u])).collect();
        assert!(all.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn each_allocation_is_counted() {
        let plain = JsString::from("abc");
        assert_eq!(plain.allocations(), [3, 0, 0]);
        let lone = JsString::from_units(&[0xd800]);
        let [text, boxed, buffer] = lone.allocations();
        assert_eq!(text, 3);
        assert_eq!(boxed, std::mem::size_of::<LoneUnits>());
        assert!(buffer >= std::mem::size_of::<(u32, u16)>());
        assert_eq!(lone.heap_bytes(), text + boxed + buffer);
    }
}
