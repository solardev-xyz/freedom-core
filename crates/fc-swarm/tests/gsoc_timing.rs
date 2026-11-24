//! GSOC mining's cost (design 0015, SWM-2's done-when): a batch of 256
//! candidates, the mining lane's unit, and a search to bee-js's cap of
//! 65,535 candidates, with a typical proximity-12 search beside them. The
//! numbers are printed (`--nocapture`) for each OS's CI log and job
//! summary. A batch past 10 ms or a cap past 2 s, the design's estimates,
//! is reported as past the estimate rather than failed: a shared runner's
//! noise shouldn't fail a build, and the lane's watchdog (1 s a batch) is
//! SWM-4's.
#![allow(clippy::print_stderr, clippy::unwrap_used)]

use std::time::{Duration, Instant};

use fc_evm::keccak256;
use fc_swarm::gsoc::{self, BATCH, CANDIDATES, Miner, Step};

const BATCH_ESTIMATE: Duration = Duration::from_millis(10);
const CAP_ESTIMATE: Duration = Duration::from_secs(2);
const TYPICAL_ESTIMATE: Duration = Duration::from_millis(100);

fn ms(d: Duration) -> String {
    format!("{:.2} ms", d.as_secs_f64() * 1e3)
}

fn report(what: &str, took: Duration, estimate: Duration) -> String {
    let flag = if took > estimate {
        "PAST THE ESTIMATE "
    } else {
        ""
    };
    format!("{flag}{what}: {} (estimate {})", ms(took), ms(estimate))
}

#[test]
fn gsoc_mining_timing() {
    let platform = format!(
        "{}/{}, {}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        if cfg!(debug_assertions) {
            "test profile, optimized"
        } else {
            "release"
        }
    );
    // A search nothing matches (past 256 bits): every batch runs to its
    // 256th candidate, and the search to the cap.
    let (target, identifier) = ([0u8; 32], [1u8; 32]);
    let mut miner = Miner::new(&target, &identifier, 257);
    let mut batches = Vec::new();
    let started = Instant::now();
    loop {
        let t = Instant::now();
        let step = miner.step(BATCH);
        batches.push(t.elapsed());
        if step == Step::Exhausted {
            break;
        }
    }
    let stepped_cap = started.elapsed();
    assert_eq!(miner.tried(), CANDIDATES);
    assert_eq!(batches.len(), CANDIDATES.div_ceil(BATCH) as usize);
    let t = Instant::now();
    assert_eq!(gsoc::mine(&target, &identifier, 257), None);
    let mined_cap = t.elapsed();
    batches.sort();
    let median = batches[batches.len() / 2];
    let max = *batches.last().unwrap();

    // Freedom's rooms: proximity 12 over sixteen topics.
    let mut typical = Vec::new();
    for i in 0..16 {
        let topic = format!("timing-room-{i}");
        let target = keccak256(format!("freedom-gsoc-v1:{topic}").as_bytes());
        let t = Instant::now();
        let signer = gsoc::mine(&target, &keccak256(topic.as_bytes()), 12);
        typical.push((t.elapsed(), signer.map(|s| s.index())));
    }
    let typical_max = typical.iter().map(|(d, _)| *d).max().unwrap();
    let typical_mean = typical.iter().map(|(d, _)| *d).sum::<Duration>() / typical.len() as u32;

    let lines = [
        format!("gsoc timing ({platform})"),
        format!(
            "gsoc timing: {}",
            report("batch of 256, median", median, BATCH_ESTIMATE)
        ),
        format!(
            "gsoc timing: {}",
            report("batch of 256, slowest", max, BATCH_ESTIMATE)
        ),
        format!(
            "gsoc timing: {}",
            report(
                "the cap (65,535 candidates) by Miner::step",
                stepped_cap,
                CAP_ESTIMATE
            )
        ),
        format!(
            "gsoc timing: {}",
            report(
                "the cap (65,535 candidates) by gsoc::mine",
                mined_cap,
                CAP_ESTIMATE
            )
        ),
        format!(
            "gsoc timing: {}",
            report(
                "proximity 12, slowest of 16 topics",
                typical_max,
                TYPICAL_ESTIMATE
            )
        ),
        format!(
            "gsoc timing: proximity 12, mean of 16 topics: {}; candidates tried: {:?}",
            ms(typical_mean),
            typical
                .iter()
                .map(|(_, i)| i.map_or(CANDIDATES, |i| i + 1))
                .collect::<Vec<_>>()
        ),
    ];
    for line in lines {
        eprintln!("{line}");
    }
}
