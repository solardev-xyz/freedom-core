//! bee-js's schema refusals, as a page reads them. bee-js 13.2.0 checks each
//! JSON reply with zod 4 (`GetAllPostageBatchesResponse.parse`, and the
//! tag and address schemas), and a reply that fails throws a `ZodError`
//! whose message reaches the page through `nodeWriteError` as -32603
//! (`methods`' `publish-data-stamps-malformed`). The message is
//! `JSON.stringify(issues, null, 2)`, every issue zod collects in order:
//! the schema's keys in declaration order, array elements in index order.
//!
//! Only `invalid_type` issues arise from the schemas the core reads (plain
//! objects, arrays, strings, numbers and booleans, unknown keys stripped).
//! An issue's keys are zod's: `expected`, `code`, `received` (only for a
//! non-finite number: `Infinity` or `-Infinity`), `path`, `message`.
//!
//! **The bound:** a reply of a few bytes per element can make an issue of
//! some 200 bytes per field, so the message is held to a cap (the reply
//! form's own): past it the call fails `too_large`, as any reply past its
//! cap does (deviation `reply-bounds`).

use fc_json::number_to_string;

/// The type a schema expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected {
    String,
    Number,
    Boolean,
    Object,
    Array,
}

impl Expected {
    fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::Object => "object",
            Self::Array => "array",
        }
    }
}

/// What a JSON value was, as zod names it (`util.parsedType`, and
/// `String(n)` for a number that isn't finite).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    /// A missing key.
    Undefined,
    Null,
    Boolean,
    Number,
    String,
    Array,
    Object,
    /// `1e400`, which `JSON.parse` reads as Infinity.
    Infinity,
    NegInfinity,
    /// A coerced number that isn't one (`z.coerce.number()` over text that
    /// `Number()` reads as `NaN`).
    NaN,
}

impl Received {
    fn name(self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Null => "null",
            Self::Boolean => "boolean",
            Self::Number => "number",
            Self::String => "string",
            Self::Array => "array",
            Self::Object => "object",
            Self::Infinity => "Infinity",
            Self::NegInfinity => "-Infinity",
            Self::NaN => "NaN",
        }
    }

    /// zod's `received` key, which only a non-finite number has.
    fn key(self) -> Option<&'static str> {
        matches!(self, Self::Infinity | Self::NegInfinity | Self::NaN).then(|| self.name())
    }

    /// A number's kind: finite, `NaN`, or which infinity.
    pub fn of_number(n: f64) -> Self {
        if n.is_nan() {
            Self::NaN
        } else if n == f64::INFINITY {
            Self::Infinity
        } else if n == f64::NEG_INFINITY {
            Self::NegInfinity
        } else {
            Self::Number
        }
    }
}

/// One step of an issue's path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    Key(&'static str),
    Index(u32),
}

/// The deepest path the core's schemas have.
const MAX_PATH: usize = 3;

/// One `invalid_type` issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Issue {
    pub expected: Expected,
    pub received: Received,
    path: [Option<Segment>; MAX_PATH],
}

impl Issue {
    /// An issue at `path` (at most three steps; more are dropped, which no
    /// schema here reaches).
    pub fn new(expected: Expected, received: Received, path: &[Segment]) -> Self {
        let mut steps = [None; MAX_PATH];
        for (slot, segment) in steps.iter_mut().zip(path) {
            *slot = Some(*segment);
        }
        Self {
            expected,
            received,
            path: steps,
        }
    }

    pub fn path(&self) -> impl Iterator<Item = Segment> + '_ {
        self.path.iter().map_while(|s| *s)
    }

    /// zod's message: `Invalid input: expected <t>, received <r>`.
    pub fn message(&self) -> String {
        format!(
            "Invalid input: expected {}, received {}",
            self.expected.name(),
            self.received.name()
        )
    }

    /// The issue as `JSON.stringify(issues, null, 2)` writes it, one level
    /// into the array.
    fn write(&self, out: &mut String) {
        out.push_str("  {\n    \"expected\": \"");
        out.push_str(self.expected.name());
        out.push_str("\",\n    \"code\": \"invalid_type\",\n");
        if let Some(received) = self.received.key() {
            out.push_str("    \"received\": \"");
            out.push_str(received);
            out.push_str("\",\n");
        }
        let mut steps = self.path().peekable();
        if steps.peek().is_none() {
            out.push_str("    \"path\": [],\n");
        } else {
            out.push_str("    \"path\": [\n");
            while let Some(step) = steps.next() {
                out.push_str("      ");
                match step {
                    // Schema keys: plain ASCII names, which need no escape.
                    Segment::Key(key) => {
                        out.push('"');
                        out.push_str(key);
                        out.push('"');
                    }
                    Segment::Index(i) => out.push_str(&number_to_string(f64::from(i))),
                }
                out.push_str(if steps.peek().is_some() { ",\n" } else { "\n" });
            }
            out.push_str("    ],\n");
        }
        out.push_str("    \"message\": \"");
        out.push_str(&self.message());
        out.push_str("\"\n  }");
    }

    /// The length of [`Issue::write`]'s text, without writing it.
    fn written_len(&self) -> usize {
        let mut out = String::new();
        self.write(&mut out);
        out.len()
    }
}

/// The issues of one reply, their message's length held to a cap.
#[derive(Debug, Clone, Default)]
pub struct Issues {
    list: Vec<Issue>,
    /// The message's length with the issues so far.
    text_len: usize,
}

/// The message would pass its cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLong;

impl Issues {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an issue, unless the message would then be longer than `cap`
    /// bytes.
    pub fn push(&mut self, issue: Issue, cap: usize) -> Result<(), TooLong> {
        // "[\n" + issues joined by ",\n" + "\n]".
        let added = issue.written_len() + if self.list.is_empty() { 4 } else { 2 };
        let len = self.text_len.saturating_add(added);
        if len > cap {
            return Err(TooLong);
        }
        self.list.push(issue);
        self.text_len = len;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Issue> {
        self.list.iter()
    }

    /// Drops every issue (a repeated key's earlier value, which `JSON.parse`
    /// overwrites).
    pub fn clear(&mut self) {
        self.list.clear();
        self.text_len = 0;
    }

    /// The `ZodError`'s message.
    pub fn message(&self) -> String {
        let mut out = String::with_capacity(self.text_len);
        out.push_str("[\n");
        for (i, issue) in self.list.iter().enumerate() {
            if i > 0 {
                out.push_str(",\n");
            }
            issue.write(&mut out);
        }
        out.push_str("\n]");
        out
    }

    /// What the list holds on the heap.
    pub fn heap_bytes(&self) -> usize {
        self.list.capacity() * std::mem::size_of::<Issue>()
    }

    pub(crate) fn shrink(&mut self) {
        self.list.shrink_to_fit();
    }
}

/// zod 4's refusal of a number below an inclusive `minimum` at the
/// schema's root (`z.number().min(minimum)`): one `too_small` issue, as
/// the `ZodError`'s message writes it.
pub fn too_small_number(minimum: f64) -> String {
    let minimum = number_to_string(minimum);
    format!(
        "[\n  {{\n    \"origin\": \"number\",\n    \"code\": \"too_small\",\n    \"minimum\": {minimum},\n    \"inclusive\": true,\n    \"path\": [],\n    \"message\": \"Too small: expected number to be >={minimum}\"\n  }}\n]"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_coerced_number_reads_as_zods() {
        // bee-js 13.2.0's `makeTagUid` (`z.coerce.number().min(0)`) over
        // `abc` and `-1`, as the reference's install throws them.
        let mut issues = Issues::new();
        issues
            .push(
                Issue::new(Expected::Number, Received::of_number(f64::NAN), &[]),
                usize::MAX,
            )
            .unwrap();
        assert_eq!(
            issues.message(),
            "[\n  {\n    \"expected\": \"number\",\n    \"code\": \"invalid_type\",\n    \"received\": \"NaN\",\n    \"path\": [],\n    \"message\": \"Invalid input: expected number, received NaN\"\n  }\n]"
        );
        assert_eq!(
            too_small_number(0.0),
            "[\n  {\n    \"origin\": \"number\",\n    \"code\": \"too_small\",\n    \"minimum\": 0,\n    \"inclusive\": true,\n    \"path\": [],\n    \"message\": \"Too small: expected number to be >=0\"\n  }\n]"
        );
    }

    #[test]
    fn message_is_zods() {
        let mut issues = Issues::new();
        issues
            .push(
                Issue::new(
                    Expected::String,
                    Received::Undefined,
                    &[
                        Segment::Key("stamps"),
                        Segment::Index(0),
                        Segment::Key("label"),
                    ],
                ),
                usize::MAX,
            )
            .unwrap();
        // methods' publish-data-stamps-malformed, as the page reads it.
        assert_eq!(
            issues.message(),
            "[\n  {\n    \"expected\": \"string\",\n    \"code\": \"invalid_type\",\n    \"path\": [\n      \"stamps\",\n      0,\n      \"label\"\n    ],\n    \"message\": \"Invalid input: expected string, received undefined\"\n  }\n]"
        );
        assert_eq!(issues.message().len(), issues.text_len);
        issues
            .push(
                Issue::new(Expected::Object, Received::Array, &[]),
                usize::MAX,
            )
            .unwrap();
        issues
            .push(
                Issue::new(
                    Expected::Number,
                    Received::NegInfinity,
                    &[Segment::Key("depth")],
                ),
                usize::MAX,
            )
            .unwrap();
        let text = issues.message();
        assert_eq!(text.len(), issues.text_len);
        assert!(text.contains(
            "  {\n    \"expected\": \"object\",\n    \"code\": \"invalid_type\",\n    \"path\": [],\n    \"message\": \"Invalid input: expected object, received array\"\n  },\n"
        ));
        assert!(text.ends_with(
            "  {\n    \"expected\": \"number\",\n    \"code\": \"invalid_type\",\n    \"received\": \"-Infinity\",\n    \"path\": [\n      \"depth\"\n    ],\n    \"message\": \"Invalid input: expected number, received -Infinity\"\n  }\n]"
        ));
    }

    #[test]
    fn the_cap_holds() {
        let issue = Issue::new(Expected::Boolean, Received::Null, &[Segment::Key("usable")]);
        let one = issue.written_len() + 4;
        let mut issues = Issues::new();
        assert_eq!(issues.push(issue, one - 1), Err(TooLong));
        assert_eq!(issues.push(issue, one), Ok(()));
        assert_eq!(
            issues.push(issue, one + issue.written_len() + 1),
            Err(TooLong)
        );
        assert_eq!(issues.message().len(), one);
    }
}
