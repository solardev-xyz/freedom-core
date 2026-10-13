//! Answer texts a request keeps (design 0005, Answers): the router keeps
//! parsed values, the core keeps the text with the span of its `result`.

use std::fmt;
use std::ops::Range;

use super::budget::Charge;

/// A result's JSON text: the decoded body it came in, kept whole (the
/// decoded text reuses the body's buffer), and the result's span in it.
/// Its charge covers the body until it is dropped.
pub(crate) struct Retained {
    text: String,
    span: Range<usize>,
    _charge: Charge,
}

impl Retained {
    pub(crate) fn new(text: String, span: Range<usize>, charge: Charge) -> Self {
        Self {
            text,
            span,
            _charge: charge,
        }
    }

    /// The result's JSON text.
    pub(crate) fn json(&self) -> &str {
        self.text.get(self.span.clone()).unwrap_or("")
    }
}

impl PartialEq for Retained {
    fn eq(&self, other: &Self) -> bool {
        self.json() == other.json()
    }
}

impl fmt::Debug for Retained {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = self.json();
        if json.len() > 64 {
            write!(
                f,
                "Retained({}… {} bytes)",
                &json[..json.floor_char_boundary(64)],
                json.len()
            )
        } else {
            write!(f, "Retained({json})")
        }
    }
}
