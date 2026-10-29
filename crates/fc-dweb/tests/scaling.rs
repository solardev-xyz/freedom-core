//! Planning scales with the request's headers (PR #62 security review,
//! M1): `dweb.open` plans on the naming thread, and a request may carry
//! thousands of distinct headers within its 64 KiB bound (about 9,000
//! with three-letter names). Grouping them must not rescan the list for
//! each name.
//!
//! A scaling check, not a time limit: the cost of planning 8n headers
//! against n, in this thread's own CPU time. Grouping in one pass (one
//! sort) costs about 8 to 10 times as much for 8 times the headers;
//! rescanning per name costs 64 times as much. Its own process, so the
//! thread's accounting is this test's alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::OnceLock;
use std::time::Instant;

use fc_dweb::{Ant, Backend, Ipfs, Opening, Plan, Request, open};

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

/// `count` distinct short header names with empty values.
fn distinct(count: usize) -> Vec<(String, String)> {
    (0..count)
        .map(|i| (format!("x-{i:05}"), String::new()))
        .collect()
}

/// What one plan of `url` with `headers` costs in CPU time, in
/// nanoseconds: plans repeated until they have used 200 ms, since the
/// scheduler brings a running thread's account up to date only at its
/// ticks; over that span the ticks at either end are a few percent.
fn cost(url: &str, backend: Backend, headers: &[(String, String)]) -> f64 {
    let start = cpu_ns();
    let mut runs = 0u32;
    loop {
        let opening = open(&Request {
            url,
            method: "GET",
            headers,
            backend,
        });
        assert!(matches!(opening, Ok(Opening::Plan(Plan::Fetch(_)))));
        runs += 1;
        let spent = cpu_ns() - start;
        if spent >= 200_000_000 {
            return spent as f64 / f64::from(runs);
        }
    }
}

#[test]
fn planning_cost_grows_with_the_headers_not_their_square() {
    const N: usize = 1_500;
    let reference = "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeebeef";
    let cid = "bafybeidon73zkcrwdb5iafqtijxildoonbwnpv7dyd6ef3qdgads2jc4su";
    let cases = [
        // bzz:'s allowlist drops them all, after grouping them.
        (
            format!("bzz://{reference}/"),
            Backend::ant(Ant::Bundled, true),
        ),
        // IPFS's strip-list keeps them all.
        (format!("ipfs://{cid}/"), Backend::ipfs(Ipfs::Native, true)),
    ];
    let (small, large) = (distinct(N), distinct(8 * N));
    for (url, backend) in cases {
        let n = cost(&url, backend, &small);
        let eight_n = cost(&url, backend, &large);
        let ratio = eight_n / n;
        assert!(
            ratio < 24.0,
            "{url}: {N} headers cost {n:.0} ns, {} cost {eight_n:.0} ns: {ratio:.1} times as much",
            8 * N
        );
    }
}

#[test]
fn grouped_headers_keep_fetch_semantics() {
    // Repeated names joined in their order, set-cookie kept apart, names
    // folded and sorted, values trimmed, among many distinct names.
    let mut pairs = distinct(3_000);
    pairs.splice(
        1_000..1_000,
        [
            ("Accept", " text/html "),
            ("x-01500", "late"),
            ("Set-Cookie", "a=1"),
            ("ACCEPT", "*/*"),
            ("set-cookie", "b=2"),
        ]
        .map(|(n, v)| (n.to_owned(), v.to_owned())),
    );
    let headers = fc_dweb::Headers::from_pairs(pairs.iter().map(|(n, v)| (n, v)));
    let entries = headers.entries();
    assert_eq!(entries.len(), 3_000 + 1 + 2);
    let find = |name: &str| -> Vec<&str> {
        entries
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    };
    assert_eq!(find("accept"), ["text/html, */*"]);
    // Its generated, empty value comes after the one inserted earlier.
    assert_eq!(find("x-01500"), ["late, "]);
    assert_eq!(find("set-cookie"), ["a=1", "b=2"]);
    assert!(entries.windows(2).all(|pair| pair[0].0 <= pair[1].0));
}
