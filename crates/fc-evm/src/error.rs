/// Why an input can't be signed. Messages describe the input, never a key,
/// and quote at most a bounded part of it ([`quoted`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid transaction: {0}")]
    Transaction(String),
    #[error("invalid typed data: {0}")]
    TypedData(String),
    #[error("invalid {0}")]
    Value(String),
    #[error("signing failed")]
    Signing,
}

/// The most characters of an input an error message quotes.
pub const MAX_QUOTED_CHARS: usize = 64;

/// Input text quoted for an error message, as Rust's `{:?}` writes it, but
/// at most [`MAX_QUOTED_CHARS`] characters of it, then `…` (#86). Quoted
/// whole, a field of combining marks or quotes from a dApp grows several
/// times over in `{:?}`'s escapes and again in JSON's, and an error reply
/// past one frame would end the core.
pub fn quoted(text: &str) -> String {
    match text.char_indices().nth(MAX_QUOTED_CHARS) {
        None => format!("{text:?}"),
        Some((cut, _)) => format!("{:?}…", &text[..cut]),
    }
}

/// The most names of a list an error message quotes.
pub const MAX_QUOTED_NAMES: usize = 8;

/// A list of input names quoted for an error message, as `{:?}` writes a
/// list, but each name [`quoted`], and at most [`MAX_QUOTED_NAMES`] of them,
/// then `…`.
pub fn quoted_list(names: &[&str]) -> String {
    let mut shown: Vec<String> = names
        .iter()
        .take(MAX_QUOTED_NAMES)
        .map(|n| quoted(n))
        .collect();
    if names.len() > MAX_QUOTED_NAMES {
        shown.push("…".to_owned());
    }
    format!("[{}]", shown.join(", "))
}

/// Input text shown as it is (no quotes or escapes), at most
/// [`MAX_QUOTED_CHARS`] characters of it, then `…` (#86).
pub fn shortened(text: &str) -> std::borrow::Cow<'_, str> {
    match text.char_indices().nth(MAX_QUOTED_CHARS) {
        None => std::borrow::Cow::Borrowed(text),
        Some((cut, _)) => std::borrow::Cow::Owned(format!("{}…", &text[..cut])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_is_bounded() {
        assert_eq!(quoted("0x12"), r#""0x12""#);
        let exact = "a".repeat(MAX_QUOTED_CHARS);
        assert_eq!(quoted(&exact), format!("{exact:?}"));
        let long = "\u{300}".repeat(300_000);
        let shown = quoted(&long);
        assert!(shown.ends_with('…'));
        assert_eq!(shown, format!("{:?}…", "\u{300}".repeat(MAX_QUOTED_CHARS)));
        assert!(shown.len() < 1024, "{}", shown.len());
        // Cut on a character boundary.
        let mixed = format!("{}é{}", "a".repeat(MAX_QUOTED_CHARS - 1), "b".repeat(10));
        assert_eq!(
            quoted(&mixed),
            format!("{:?}…", format!("{}é", "a".repeat(MAX_QUOTED_CHARS - 1)))
        );
        assert_eq!(quoted_list(&["A", "B"]), format!("{:?}", ["A", "B"]));
        let many: Vec<String> = (0..20).map(|i| format!("{}{i}", "T".repeat(300))).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let list = quoted_list(&many);
        assert!(list.ends_with(", …]"), "{list}");
        assert_eq!(list.matches('…').count(), MAX_QUOTED_NAMES + 1);
        assert_eq!(shortened("gas"), "gas");
        assert_eq!(
            shortened(&mixed),
            format!("{}é…", "a".repeat(MAX_QUOTED_CHARS - 1))
        );
    }
}

/// Review of #116: identifiers pass `is_identifier` up to 256 characters,
/// so every error that names a type or a field bounds it too.
#[cfg(test)]
mod identifier_tests {
    use serde_json::{Value, json};

    use super::MAX_QUOTED_CHARS;
    use crate::typed_data_hash;

    /// The message of each identifier error for a type name and a field
    /// name of `len` characters each.
    fn messages(len: usize) -> Vec<String> {
        let t = "T".repeat(len);
        let f = "f".repeat(len);
        let uint = format!("uint{}", "8".repeat(len - 4));
        let u = json!("uint8");
        let cases: Vec<(Value, Value)> = vec![
            // A primitive-looking type name.
            (json!({ &uint: [] }), json!({})),
            // Not a field list.
            (json!({ &t: 0 }), json!({})),
            // A field without a string type.
            (json!({ &t: [{ "name": &f }] }), json!({})),
            // A duplicate field.
            (
                json!({ &t: [{ "name": &f, "type": u }, { "name": &f, "type": u }] }),
                json!({}),
            ),
            // Too many array dimensions.
            (
                json!({ &t: [{ "name": &f, "type": format!("uint8{}", "[]".repeat(40)) }] }),
                json!({}),
            ),
            // A type referring to itself.
            (json!({ &t: [{ "name": &f, "type": &t }] }), json!({})),
            // Two roots.
            (json!({ &t: [], format!("{t}2"): [] }), json!({})),
            // A struct value that isn't an object, and a missing field.
            (json!({ &t: [{ "name": &f, "type": u }] }), json!(0)),
            (json!({ &t: [{ "name": &f, "type": u }] }), json!({})),
        ];
        cases
            .into_iter()
            .map(|(types, message)| {
                let error = typed_data_hash(&json!({ "name": "x" }), &types, &message)
                    .expect_err("an identifier error");
                error.to_string()
            })
            .collect()
    }

    /// The longest run of `c` in `text`.
    fn run(text: &str, c: char) -> usize {
        text.split(|x| x != c).map(str::len).max().unwrap_or(0)
    }

    #[test]
    fn identifier_errors_quote_at_most_64_characters() {
        for len in [MAX_QUOTED_CHARS, MAX_QUOTED_CHARS + 1, 256] {
            for message in messages(len) {
                for c in ['T', 'f', '8'] {
                    assert!(run(&message, c) <= MAX_QUOTED_CHARS, "{len}: {message}");
                }
                assert!(message.len() < 1024, "{len}: {message}");
                if len > MAX_QUOTED_CHARS {
                    assert!(message.contains('…'), "{len}: {message}");
                }
            }
        }
        // At 64, a name shows whole, as before.
        let whole = "T".repeat(MAX_QUOTED_CHARS);
        assert!(
            messages(MAX_QUOTED_CHARS)
                .iter()
                .any(|m| m.contains(&format!("{whole:?}")))
        );
    }
}
