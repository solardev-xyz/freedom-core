//! The router's texts: `safeErrorMessage`, and the aggregate errors when
//! every source fails.

use crate::js::{JsString, is_js_whitespace};

/// `safeErrorMessage(error)`, for an error with this name and message:
/// - `error.message || String(error)` (an empty message gives the name);
/// - each `0x` and 128 or more hex digits becomes its first ten characters,
///   `…(` and half its digits ` bytes)`;
/// - each run of whitespace becomes one space;
/// - the first 500 UTF-16 code units, even through a surrogate pair.
pub fn safe_error_message(name: &str, message: &[u16]) -> JsString {
    let named: Vec<u16>;
    let text = if message.is_empty() {
        named = name.encode_utf16().collect();
        &named[..]
    } else {
        message
    };
    let is_hex = |u: &u16| char::from_u32(u32::from(*u)).is_some_and(|c| c.is_ascii_hexdigit());
    let mut shortened: Vec<u16> = Vec::with_capacity(text.len());
    let mut i = 0;
    while let Some(&unit) = text.get(i) {
        if let [0x30, 0x78, rest @ ..] = &text[i..] {
            let digits = rest.iter().take_while(|u| is_hex(u)).count();
            if digits >= 128 {
                shortened.extend_from_slice(text.get(i..i + 10).unwrap_or_default());
                shortened.extend(format!("\u{2026}({} bytes)", digits / 2).encode_utf16());
                i += 2 + digits;
                continue;
            }
        }
        shortened.push(unit);
        i += 1;
    }
    let mut out: Vec<u16> = Vec::with_capacity(shortened.len().min(500));
    let mut in_space = false;
    for unit in shortened {
        if is_js_whitespace(unit) {
            if !in_space {
                out.push(0x20);
            }
            in_space = true;
        } else {
            out.push(unit);
            in_space = false;
        }
    }
    out.truncate(500);
    JsString::from_units(out)
}

/// One source's part of a read's aggregate error.
#[derive(Debug, Clone, Copy)]
pub enum SourceFailure<'a> {
    /// `<source>: <safeErrorMessage(error)>`.
    Failed {
        source: &'a str,
        name: &'a str,
        message: &'a [u16],
    },
    /// `<source>: temporarily bypassed for this app workload`.
    Bypassed { source: &'a str },
}

/// A read's error when every source failed and none gave a node error:
/// `All chain sources failed for <method> (<failures>; excluded for this
/// request: <sources>)`.
pub fn request_failure_text(
    method: &str,
    failures: &[SourceFailure<'_>],
    excluded: &[&str],
) -> JsString {
    let mut parts: Vec<JsString> = failures
        .iter()
        .map(|failure| match failure {
            SourceFailure::Failed {
                source,
                name,
                message,
            } => {
                let mut part = JsString::from(*source);
                part.push_str(": ");
                part.push_units(safe_error_message(name, message).units());
                part
            }
            SourceFailure::Bypassed { source } => JsString::from(
                format!("{source}: temporarily bypassed for this app workload").as_str(),
            ),
        })
        .collect();
    if !excluded.is_empty() {
        parts.push(JsString::from(
            format!("excluded for this request: {}", excluded.join(", ")).as_str(),
        ));
    }
    aggregate(&format!("All chain sources failed for {method}"), &parts)
}

/// A fee quote's error when every source failed: the messages as they are.
pub fn fee_quote_failure_text(failures: &[(&str, &[u16])]) -> JsString {
    aggregate(
        "All chain sources failed for fee quote",
        &raw_parts(failures),
    )
}

/// A broadcast's error when every broadcaster failed: the messages as they
/// are.
pub fn broadcast_failure_text(failures: &[(&str, &[u16])]) -> JsString {
    aggregate("All transaction broadcasters failed", &raw_parts(failures))
}

fn raw_parts(failures: &[(&str, &[u16])]) -> Vec<JsString> {
    failures
        .iter()
        .map(|(source, message)| {
            let mut part = JsString::from(*source);
            part.push_str(": ");
            part.push_units(message);
            part
        })
        .collect()
}

/// `${prefix} (${parts.join('; ')})`.
fn aggregate(prefix: &str, parts: &[JsString]) -> JsString {
    let mut out = JsString::from(prefix);
    out.push_str(" (");
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            out.push_str("; ");
        }
        out.push_units(part.units());
    }
    out.push_str(")");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn safe(message: &str) -> String {
        let units: Vec<u16> = message.encode_utf16().collect();
        safe_error_message("Error", &units).to_string_lossy()
    }

    #[test]
    fn shortens_like_the_router() {
        assert_eq!(safe(""), "Error");
        assert_eq!(
            safe(&format!("a 0x{} b", "c".repeat(128))),
            "a 0xcccccccc\u{2026}(64 bytes) b"
        );
        assert_eq!(safe(&format!("0x{}", "c".repeat(127))).len(), 129);
        // The run swallows the 0 of a following 0x.
        assert_eq!(
            safe(&format!("0x{}0x{}", "a".repeat(130), "b".repeat(3))),
            "0xaaaaaaaa\u{2026}(65 bytes)xbbb"
        );
        assert_eq!(safe(" \t\u{3000}a\u{85}\n\n"), " a\u{85} ");
        assert_eq!(safe(&"x".repeat(600)).len(), 500);
        let cut = safe_error_message(
            "Error",
            &format!("{}😀", "x".repeat(499))
                .encode_utf16()
                .collect::<Vec<_>>(),
        );
        assert_eq!(cut.units().last(), Some(&0xD83D));
    }
}
