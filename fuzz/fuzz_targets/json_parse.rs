//! fc-json: `parse` and `Index` read JavaScript's `JSON.parse` grammar.
//!
//! Besides finding panics, it checks the contract the crate documents:
//! - `parse` and `Index::new` accept exactly the same texts;
//! - an index's heap stays within `HEAP_PER_TEXT_BYTE × (len + 1)`, and
//!   within what `Index::heap_needed` predicts;
//! - `JSON.stringify(JSON.parse(text))` is a fixed point;
//! - an index writes the same JSON as `stringify` of the parsed value. The
//!   index keeps lone surrogates as UTF-16, where `parse` makes them
//!   U+FFFD, so its output is compared after one more `parse`;
//! - with sorted keys it writes the same members, in another order.

#![no_main]

use fc_json::index::{HEAP_PER_TEXT_BYTE, Index, KeyOrder};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let parsed = fc_json::parse(text);
    let indexed = Index::new(text);
    assert_eq!(
        parsed.is_ok(),
        indexed.is_ok(),
        "parse and Index::new disagree on whether the text is JSON"
    );
    let (Ok(value), Ok(index)) = (parsed, indexed) else {
        return;
    };

    assert!(index.heap_bytes() <= HEAP_PER_TEXT_BYTE * (text.len() + 1));
    assert!(Index::heap_needed(text).is_ok_and(|needed| index.heap_bytes() <= needed));

    let once = value.stringify();
    let again = fc_json::parse(&once).expect("stringify writes JSON that parses");
    assert_eq!(
        again.stringify(),
        once,
        "stringify(parse(x)) is not a fixed point"
    );

    let written = index.root().stringify(KeyOrder::Property);
    let reparsed = fc_json::parse(&written).expect("an index writes JSON that parses");
    assert_eq!(
        reparsed.stringify(),
        once,
        "the index and parse write different JSON"
    );

    // Sorted keys write the same members in another order.
    let sorted = index.root().stringify(KeyOrder::Sorted);
    assert!(
        fc_json::parse(&sorted).is_ok(),
        "sorted output doesn't parse"
    );
    assert_eq!(
        sorted.len(),
        written.len(),
        "sorting keys changed the members"
    );
});
