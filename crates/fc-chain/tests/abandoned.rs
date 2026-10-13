//! A verifier's answer to a request that has ended is dropped at once
//! (`memory-budgets`, PR #55's second safety review): it would otherwise sit
//! uncharged in the executor until the next poll. Its own process, so the
//! resident size it measures is this test's alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_chain::machine::{
    Answer, Bounds, Call, ChainConfig, ColibriReply, Effect, Machine, Prover, QuorumConfig,
    ReadOptions, RpcEndpoint,
};

/// The process's resident size, where Linux reports it.
fn resident() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kib: usize = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

#[test]
fn answers_to_ended_callers_are_dropped_at_once() {
    const MIB: usize = 1024 * 1024;
    let config = ChainConfig {
        chain_id: 1,
        display_name: "Ethereum".into(),
        read_order: vec!["colibri".into()],
        broadcast_order: vec!["direct".into()],
        quorum: QuorumConfig {
            k: None,
            m: None,
            timeout_ms: None,
        },
        rpc: vec![RpcEndpoint {
            endpoint: "a".into(),
            user_configured: false,
        }],
        prover: Some(Prover {
            endpoint: "p".into(),
            zk: true,
        }),
        myotis: false,
        blockscout: None,
    };
    let bounds = Bounds {
        request_bytes: 16 * MIB,
        total_bytes: 16 * MIB,
        ..Bounds::default()
    };
    let mut machine = Machine::new(0, bounds);
    machine.configure(&[config]);
    let mut operations = Vec::new();
    for i in 0..8 {
        let id = machine.submit(
            Call::Read {
                chain_id: 1,
                method: "eth_call".into(),
                params: r#"[{"to":"0xabc"},"latest"]"#.into(),
                options: ReadOptions {
                    origin: Some(format!("https://app{i}.example")),
                    ..ReadOptions::default()
                },
            },
            None,
        );
        machine.poll();
        machine.cancel(id);
        machine.poll();
        for emitted in machine.take_effects() {
            if let Effect::Request { id, .. } = emitted.effect {
                operations.push(id);
            }
        }
        machine.take_replies();
    }
    assert_eq!(operations.len(), 8);
    assert_eq!(machine.state_tables().colibri_in_flight, 8);
    let before = resident();
    for io in operations {
        let mut text = String::with_capacity(8 * MIB + 2);
        text.push('"');
        text.extend(std::iter::repeat_n('a', 8 * MIB));
        text.push('"');
        // Main's terminal reply completes the operation.
        assert!(machine.complete(io, Answer::Colibri(ColibriReply::Result(text))));
    }
    let queued = resident();
    assert_eq!(machine.held(), 0);
    machine.poll();
    // Every slot is free again.
    assert_eq!(machine.state_tables().colibri_in_flight, 0);
    // 64 MiB of answers arrived; none is kept.
    if let (Some(before), Some(queued)) = (before, queued) {
        assert!(
            queued.saturating_sub(before) < 24 * MIB,
            "kept {} bytes of answers nobody reads",
            queued.saturating_sub(before)
        );
    }
}
