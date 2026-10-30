//! Reading an IPNS name's text scales with the name, not its square
//! (#227 review, Major): base36 is a big-number base change, quadratic in
//! the text's length, and a request's URL may be 64 Ki UTF-16 units long.
//! A name past the longest CID's text is refused before any conversion.
//!
//! A scaling check, not a time limit: the cost of refusing a name of 64 Ki
//! characters against one of 8 Ki, in this thread's own CPU time. Refusing
//! by length costs the same for both; converting first costs 64 times as
//! much for 8 times the text. Its own process, so the thread's accounting
//! is this test's alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::OnceLock;
use std::time::Instant;

use fc_ipfs::cid::{self, MAX_CID, MAX_CID_TEXT};

/// The CPU time this thread has used, in nanoseconds: Linux's scheduler
/// accounting, which other processes' load doesn't inflate; elsewhere, the
/// time since the first call.
fn cpu_ns() -> u128 {
    static START: OnceLock<Instant> = OnceLock::new();
    std::fs::read_to_string("/proc/thread-self/schedstat")
        .ok()
        .and_then(|stat| stat.split_whitespace().next()?.parse().ok())
        .unwrap_or_else(|| START.get_or_init(Instant::now).elapsed().as_nanos())
}

/// What one read of `text` costs in CPU time, in nanoseconds, repeated
/// until 200 ms are used, since the scheduler brings a running thread's
/// account up to date only at its ticks.
fn cost(text: &str) -> f64 {
    let start = cpu_ns();
    let mut runs = 0u32;
    loop {
        let read = if text.starts_with('k') {
            cid::from_key_text(text)
        } else {
            cid::from_base32(text)
        };
        assert!(read.is_none());
        runs += 1;
        let spent = cpu_ns() - start;
        if spent >= 200_000_000 {
            return spent as f64 / f64::from(runs);
        }
    }
}

#[test]
fn a_long_name_is_refused_by_its_length() {
    // The longest name a request carries: its URL's 64 Ki units.
    const LONG: usize = 64 * 1024;
    for prefix in ["k", "b"] {
        let small = format!("{prefix}{}", "z".repeat(LONG / 8 - 1));
        let large = format!("{prefix}{}", "z".repeat(LONG - 1));
        let (n, eight_n) = (cost(&small), cost(&large));
        let ratio = eight_n / n;
        assert!(
            ratio < 4.0,
            "{prefix}: {} characters cost {n:.0} ns, {} cost {eight_n:.0} ns: {ratio:.1} times as much",
            small.len(),
            large.len()
        );
    }
}

/// Multibase base36 of `bytes`, for the test: leading zero bytes as `0`s.
fn base36(bytes: &[u8]) -> String {
    const A: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &b in &bytes[zeros..] {
        let mut carry = u32::from(b);
        for d in &mut digits {
            carry += u32::from(*d) << 8;
            *d = (carry % 36) as u8;
            carry /= 36;
        }
        while carry > 0 {
            digits.push((carry % 36) as u8);
            carry /= 36;
        }
    }
    let mut out = "0".repeat(zeros);
    out.extend(digits.iter().rev().map(|&d| char::from(A[usize::from(d)])));
    out
}

#[test]
fn the_bound_holds_the_longest_cid() {
    // A libp2p-key CID with the longest digest; and the longest binary CID
    // (a codec and hash of ten-byte varints), in base32.
    let mut key = vec![0x01, 0x72, 0x00, 0x80, 0x01];
    key.extend_from_slice(&[0xab; 128]);
    let k = format!("k{}", base36(&key));
    assert!(k.len() - 1 <= MAX_CID_TEXT, "{}", k.len());
    assert_eq!(cid::from_key_text(&k), Some(key.clone()));
    let b = cid::to_text(&cid::parse(&key).unwrap());
    assert_eq!(cid::from_key_text(&b), Some(key));

    let mut longest = vec![0x01];
    longest.extend_from_slice(&[0xff; 9]);
    longest.push(0x01);
    longest.extend_from_slice(&[0xff; 9]);
    longest.push(0x01);
    longest.extend_from_slice(&[0x80, 0x01]);
    longest.extend_from_slice(&[0xcd; 128]);
    assert!(longest.len() <= MAX_CID);
    let text = cid::to_text(&cid::parse(&longest).unwrap());
    assert!(text.len() - 1 <= MAX_CID_TEXT);
    assert_eq!(cid::from_base32(&text), Some(longest));

    // One character past the bound is refused, whatever it would decode to.
    let past = format!("k{}", "1".repeat(MAX_CID_TEXT + 1));
    assert_eq!(cid::from_key_text(&past), None);
}
