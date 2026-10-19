//! fc-json: `parse` and `Index` read JavaScript's `JSON.parse` grammar.
//!
//! Besides finding panics, it checks the contract the crate documents:
//! - `parse` and `Index::new` accept exactly the same texts;
//! - an index's heap stays within `HEAP_PER_TEXT_BYTE × (len + 1)`, and
//!   within what `Index::heap_needed` predicts;
//! - `JSON.stringify(JSON.parse(text))` is a fixed point;
//! - an index writes the same JSON as `stringify` of the parsed value. The
//!   index keeps lone surrogates as UTF-16, where `parse` makes them
//!   U+FFFD, so its output is compared after one more `parse`. `parse`
//!   replaces them before it merges duplicate keys, and the index merges
//!   keys as UTF-16, so the two are compared only when no object has two
//!   keys that U+FFFD makes equal;
//! - with sorted keys it writes the same members, in another order:
//!   indexing either output and writing it sorted gives the sorted output.

#![no_main]

use std::collections::HashMap;

use fc_json::index::{HEAP_PER_TEXT_BYTE, Index, KeyOrder, Kind, Value};
use libfuzzer_sys::fuzz_target;

/// Whether some object has two keys, different as UTF-16, that are equal
/// once lone surrogates become U+FFFD.
fn lossy_keys_collide(root: Value<'_, '_>) -> bool {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        if value.kind() == Kind::Object {
            let mut keys: HashMap<String, Vec<u16>> = HashMap::new();
            for (key, _) in value.members() {
                let units: Vec<u16> = key.units().collect();
                let lossy = String::from_utf16_lossy(&units);
                if keys.get(&lossy).is_some_and(|seen| *seen != units) {
                    return true;
                }
                keys.insert(lossy, units);
            }
        }
        stack.extend(value.children());
    }
    false
}

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
    if !lossy_keys_collide(index.root()) {
        assert_eq!(
            reparsed.stringify(),
            once,
            "the index and parse write different JSON"
        );
    }

    // Sorted keys write the same members in another order.
    let sorted = index.root().stringify(KeyOrder::Sorted);
    for output in [&sorted, &written] {
        let again = Index::new(output).expect("an index writes JSON that indexes");
        assert_eq!(
            again.root().stringify(KeyOrder::Sorted),
            sorted,
            "sorting keys changed the members"
        );
    }
});
