//! A fee value whose conversion throws is refused before any of its text is
//! built (PR #55's third safety review). Its own process, so the peak
//! resident size it measures is this test's alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// The process's peak resident size, where Linux reports it.
fn peak() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kib: usize = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

#[test]
fn a_throwing_conversion_builds_nothing() {
    const MIB: usize = 1024 * 1024;
    // 16 MiB of string, then an object with its own `toString`: the join
    // throws at the object, a TypeError.
    let mut gas = String::with_capacity(16 * MIB + 32);
    gas.push_str("[\"");
    gas.extend(std::iter::repeat_n('a', 16 * MIB));
    gas.push_str("\",{\"toString\":null}]");
    let mut asked = 0usize;
    let before = peak();
    let quoted = fc_chain::fee_quote_values_reserving("direct", Some(&gas), None, None, |bytes| {
        asked += bytes;
        Ok::<(), ()>(())
    })
    .unwrap();
    let after = peak();
    let fc_chain::FeeOutcome::Error(error) = quoted else {
        panic!("{quoted:?}");
    };
    assert_eq!(error.name, "TypeError");
    assert_eq!(
        error.message.to_string_lossy(),
        "Cannot convert object to primitive value"
    );
    // Nothing of the string was asked for, or built.
    assert!(asked < MIB, "{asked}");
    if let (Some(before), Some(after)) = (before, after) {
        assert!(
            after.saturating_sub(before) < 8 * MIB,
            "the conversion raised the peak by {} bytes",
            after.saturating_sub(before)
        );
    }
}
