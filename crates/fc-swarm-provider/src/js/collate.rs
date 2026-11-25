//! `String.prototype.localeCompare` as the reference calls it (no locales,
//! no options: ICU's collation for the process's locale, which for English
//! is CLDR's root collation, `Intl.Collator('und')`), ported for the
//! printable ASCII that permission keys are written in (design 0015, SWM-4's
//! D8).
//!
//! **Printable ASCII** (U+0020 to U+007E): root collation at its default
//! strength (tertiary) with punctuation not ignorable. Every such character
//! is one collation element with a primary weight of its own, except that a
//! letter's two cases share one; no two characters share a secondary
//! weight that differs, and the tertiary weight tells only case apart, the
//! small letter first. So two strings compare by their primary weights
//! first (whitespace, punctuation and symbols in ICU's order, then the
//! digits, then the letters, case-blind), and only where those are all
//! equal (the same string up to case) by the first letter whose case
//! differs, small before capital. No two different strings compare equal.
//! `tests/data/icu-root-ascii.json`, which node's ICU recorded
//! (`tests/data/icu-root-ascii.js`), holds the order this follows.
//!
//! **Anything else** (a string with a character outside printable ASCII:
//! a control character, which ICU ignores, or any non-ASCII text, which
//! it orders by the full table) compares by UTF-16 code unit, as `<` does:
//! D8's named deviation, `collation`, leaves the rest of ICU's table out.
//! Such a comparison is between two strings of which at least one isn't
//! printable ASCII.

use std::cmp::Ordering;

use fc_json::JsString;

/// Printable ASCII in root collation's primary order, each letter once
/// (both cases have its weight). Node's ICU wrote it
/// (`tests/data/icu-root-ascii.js`), and the tests check every pair of
/// printable characters against that recording.
const PRIMARY_ORDER: &[u8; 69] =
    b" _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789abcdefghijklmnopqrstuvwxyz";

/// Each printable character's primary weight: its place in
/// [`PRIMARY_ORDER`], a capital letter its small one's.
const PRIMARY: [u8; 128] = primary_table();

const fn primary_table() -> [u8; 128] {
    let mut table = [u8::MAX; 128];
    let mut at = 0;
    while at < PRIMARY_ORDER.len() {
        let byte = PRIMARY_ORDER[at];
        // At most 69 places: each fits a u8.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "69 places, each below u8::MAX"
        )]
        let weight = at as u8;
        table[byte as usize] = weight;
        if byte.is_ascii_lowercase() {
            table[byte.to_ascii_uppercase() as usize] = weight;
        }
        at += 1;
    }
    table
}

/// The text as bytes when every character is printable ASCII.
fn printable(s: &JsString) -> Option<&[u8]> {
    let bytes = s.as_str().as_bytes();
    (s.is_well_formed() && bytes.iter().all(|b| (0x20..=0x7e).contains(b))).then_some(bytes)
}

/// `a.localeCompare(b)`'s sign: root collation for two strings of
/// printable ASCII, UTF-16 code-unit order otherwise (deviation
/// `collation`, the module's docs).
pub fn locale_compare(a: &JsString, b: &JsString) -> Ordering {
    match (printable(a), printable(b)) {
        (Some(a), Some(b)) => root_ascii(a, b),
        _ => a.cmp(b),
    }
}

/// Root collation over printable ASCII.
fn root_ascii(a: &[u8], b: &[u8]) -> Ordering {
    fn primary(s: &[u8]) -> impl Iterator<Item = u8> + '_ {
        s.iter().map(|&c| PRIMARY[usize::from(c & 0x7f)])
    }
    fn case(s: &[u8]) -> impl Iterator<Item = bool> + '_ {
        s.iter().map(u8::is_ascii_uppercase)
    }
    // Where the primary weights are all equal (the same letters and the
    // same other characters in the same places), the first letter whose
    // case differs decides, the small one first.
    primary(a)
        .cmp(primary(b))
        .then_with(|| case(a).cmp(case(b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        locale_compare(&JsString::from(a), &JsString::from(b))
    }

    #[test]
    fn every_printable_character_has_a_weight() {
        for byte in 0x20u8..=0x7e {
            assert_ne!(PRIMARY[usize::from(byte)], u8::MAX, "{:?}", byte as char);
        }
        // Each weight but a letter's is one character's.
        let mut seen = [0u8; 69];
        for byte in 0x20u8..=0x7e {
            seen[usize::from(PRIMARY[usize::from(byte)])] += 1;
        }
        let letters = seen.iter().filter(|&&n| n == 2).count();
        assert_eq!(letters, 26);
        assert!(seen.iter().all(|&n| n == 1 || n == 2));
    }

    #[test]
    fn primary_then_case() {
        assert_eq!(cmp("a", "A"), Ordering::Less);
        assert_eq!(cmp("A", "b"), Ordering::Less);
        assert_eq!(cmp("aB", "Ab"), Ordering::Less);
        assert_eq!(cmp("Ab", "aBc"), Ordering::Less);
        assert_eq!(cmp("_", "-"), Ordering::Less);
        assert_eq!(cmp("9", "a"), Ordering::Less);
        assert_eq!(cmp("$", "0"), Ordering::Less);
        assert_eq!(cmp("", " "), Ordering::Less);
        assert_eq!(cmp("ab", "ab"), Ordering::Equal);
        // Where code units put a capital first, ICU puts the small one.
        assert_eq!(cmp("https://b.example", "https://A.example"), Ordering::Greater);
    }

    fn strings(value: &fc_json::JsValue) -> Vec<JsString> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_js_string().unwrap().clone())
            .collect()
    }

    fn sign(ordering: Ordering) -> f64 {
        match ordering {
            Ordering::Less => -1.0,
            Ordering::Equal => 0.0,
            Ordering::Greater => 1.0,
        }
    }

    /// Node's ICU recorded these (`tests/data/icu-root-ascii.js`): every
    /// list sorts to the same order, each neighbour strictly before the
    /// next, and every recorded comparison has the same sign.
    #[test]
    fn root_order_as_node_recorded_it() {
        let text = include_str!("../../tests/data/icu-root-ascii.json");
        let root = fc_json::parse(text).unwrap();
        for list in ["singles", "pairs", "triples", "strings"] {
            let want = strings(root.get(list).unwrap());
            for pair in want.windows(2) {
                assert_eq!(
                    locale_compare(&pair[0], &pair[1]),
                    Ordering::Less,
                    "{list}: {:?} before {:?}",
                    pair[0].as_str(),
                    pair[1].as_str()
                );
            }
            // Sorted from a fixed shuffle: odd places reversed, then the
            // even ones.
            let mut got: Vec<&JsString> = want.iter().skip(1).step_by(2).rev().collect();
            got.extend(want.iter().step_by(2));
            crate::js::sort(&mut got, |a, b| sign(locale_compare(a, b)));
            let got: Vec<&str> = got.iter().map(|s| s.as_str()).collect();
            let want: Vec<&str> = want.iter().map(|s| s.as_str()).collect();
            assert_eq!(got, want, "{list}");
        }
        let compared = root.get("compared").unwrap().as_array().unwrap();
        assert_eq!(compared.len(), 1500);
        for row in compared {
            let row = row.as_array().unwrap();
            let (a, b) = (row[0].as_js_string().unwrap(), row[1].as_js_string().unwrap());
            assert_eq!(
                fc_json::JsValue::Number(sign(locale_compare(a, b))),
                row[2],
                "{:?} against {:?}",
                a.as_str(),
                b.as_str()
            );
        }
    }

    /// Outside printable ASCII the core compares by code unit, which
    /// differs from ICU's recorded sign for most of these (deviation
    /// `collation`).
    #[test]
    fn outside_printable_ascii_is_the_deviation() {
        let text = include_str!("../../tests/data/icu-root-ascii.json");
        let root = fc_json::parse(text).unwrap();
        let mut differs = 0;
        for row in root.get("outside").unwrap().as_array().unwrap() {
            let row = row.as_array().unwrap();
            let (a, b) = (row[0].as_js_string().unwrap(), row[1].as_js_string().unwrap());
            assert!(printable(a).is_none() || printable(b).is_none());
            assert_eq!(locale_compare(a, b), a.cmp(b));
            if fc_json::JsValue::Number(sign(a.cmp(b))) != row[2] {
                differs += 1;
            }
        }
        assert!(differs >= 5, "{differs}");
    }

    #[test]
    fn anything_else_by_code_unit() {
        // ICU: "é" sorts with "e", before "f"; by code unit it is last.
        assert_eq!(cmp("é", "f"), Ordering::Greater);
        // ICU ignores a control character; by code unit "\t" is first.
        assert_eq!(cmp("a\tb", "a"), Ordering::Greater);
        assert_eq!(cmp("B", "aé"), Ordering::Less);
        let lone = JsString::from_units(&[0xd800]);
        assert_eq!(locale_compare(&lone, &JsString::from("a")), Ordering::Greater);
    }
}
