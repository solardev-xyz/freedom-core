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
        assert_eq!(shortened("gas"), "gas");
        assert_eq!(
            shortened(&mixed),
            format!("{}é…", "a".repeat(MAX_QUOTED_CHARS - 1))
        );
    }
}
