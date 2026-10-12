//! The reference's regular expressions, matched as JavaScript matches them.
//!
//! Each pattern keeps the reference's own source and flags (the vectors pin
//! both) and is compiled by the `regex` crate in ASCII mode. There `\d`,
//! `\w`, `\b` and the `i` flag are ASCII-only, as they are in a JavaScript
//! pattern without the `u` flag. The text is the JavaScript string's UTF-16
//! code units, one byte for each:
//! - ASCII stays as it is;
//! - the other units JavaScript's `\s` matches (U+00A0, U+2028, U+FEFF and
//!   the rest) become U+000B, which matches `\s` and nothing else in these
//!   patterns;
//! - every other unit, a lone surrogate included, becomes U+0000, which
//!   matches nothing in them.
//!
//! So the match, and each capture, is JavaScript's, at the same UTF-16
//! offsets. That holds for patterns without `.` and without negated classes,
//! which a test checks for every pattern here.
//!
//! The `regex` crate matches in linear time. An error message can be as
//! long as an answer (18 MiB), where a backtracking engine could take
//! quadratic time.

use std::sync::OnceLock;

use regex::Regex;

use crate::js::is_js_whitespace;

/// A JavaScript regular expression: its source and flags (`i` or none).
pub(crate) struct JsPattern {
    pub(crate) source: &'static str,
    pub(crate) flags: &'static str,
    compiled: OnceLock<Option<Regex>>,
}

impl JsPattern {
    pub(crate) const fn new(source: &'static str, flags: &'static str) -> Self {
        Self {
            source,
            flags,
            compiled: OnceLock::new(),
        }
    }

    /// The compiled pattern. `None` only for a source the crate refuses or a
    /// flag other than `i`, which the tests rule out; it then matches
    /// nothing.
    fn regex(&self) -> Option<&Regex> {
        self.compiled
            .get_or_init(|| {
                let flags = match self.flags {
                    "i" => "i-u",
                    "" => "-u",
                    _ => return None,
                };
                Regex::new(&format!("(?{flags}:{})", self.source)).ok()
            })
            .as_ref()
    }

    /// `pattern.test(text)`.
    pub(crate) fn test(&self, text: &MatchText) -> bool {
        self.regex().is_some_and(|regex| regex.is_match(&text.0))
    }

    #[cfg(test)]
    pub(crate) fn compiles(&self) -> bool {
        self.regex().is_some()
    }
}

/// A JavaScript string as the patterns read it: one byte per UTF-16 unit.
pub(crate) struct MatchText(String);

impl MatchText {
    pub(crate) fn new(units: &[u16]) -> Self {
        Self(
            units
                .iter()
                .map(|&unit| match u8::try_from(unit) {
                    Ok(byte) if byte.is_ascii() => char::from(byte),
                    _ if is_js_whitespace(unit) => '\u{B}',
                    _ => '\0',
                })
                .collect(),
        )
    }
}

/// A pattern is safe to run on [`MatchText`] when no `.` and no
/// negated class could match the stand-ins.
#[cfg(test)]
pub(crate) fn safe_source(source: &str) -> bool {
    let mut chars = source.chars();
    let mut in_class = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '[' if !in_class => {
                in_class = true;
                if chars.clone().next() == Some('^') {
                    return false;
                }
            }
            ']' if in_class => in_class = false,
            '.' if !in_class => return false,
            _ => {}
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> MatchText {
        MatchText::new(&s.encode_utf16().collect::<Vec<_>>())
    }

    #[test]
    fn javascript_semantics() {
        let range = JsPattern::new(r"(?:max(?:imum)?|allowed) (?:block )?range", "i");
        assert!(range.test(&text("MAX block range")));
        // The Kelvin sign is not `k` without the `u` flag.
        assert!(!range.test(&text("max bloc\u{212A} range")));
        // A literal space is U+0020 only.
        assert!(!range.test(&text("max\u{A0}block range")));
        let space = JsPattern::new(r"time(?:d)?[\s-]?out", "i");
        assert!(space.test(&text("time\u{FEFF}out")));
        assert!(space.test(&text("TIME\u{2028}OUT")));
        assert!(!space.test(&text("time\u{85}out")));
        assert!(!space.test(&text("time\u{180E}out")));
        let word = JsPattern::new(r"\b429\b", "i");
        assert!(word.test(&text("HTTP 429")));
        assert!(!word.test(&text("x429")));
        assert!(word.test(&text("\u{E9}429")));
        assert!(word.test(&MatchText::new(&[0xD800, 0x34, 0x32, 0x39])));
        assert!(!JsPattern::new("a", "g").test(&text("a")));
    }

    #[test]
    fn negated_classes_and_dots_are_refused() {
        assert!(safe_source(r"a[\w,.]+b\.c"));
        assert!(!safe_source(r"a.b"));
        assert!(!safe_source(r"[^a]"));
    }
}
