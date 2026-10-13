//! A purported transaction hash is read in place (PR #55's third safety
//! review): an answer whose result is 16 MiB of hex costs its classification
//! nothing beyond the answer itself. Its own process, so the peak resident
//! size it measures is this test's alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_chain::machine::{
    Answer, Bounds, BroadcastOutcome, Call, ChainConfig, ChainError, Effect, Machine, QuorumConfig,
    Request, RpcEndpoint, Success,
};

/// The process's peak resident size, where Linux reports it.
fn peak() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kib: usize = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

/// The RPC requests the machine made since the last call.
fn rpcs(machine: &mut Machine) -> Vec<(u64, String)> {
    machine
        .take_effects()
        .into_iter()
        .filter_map(|emitted| match emitted.effect {
            Effect::Request {
                id,
                request: Request::Rpc { body, .. },
                ..
            } => Some((id, body)),
            _ => None,
        })
        .collect()
}

#[test]
fn an_oversized_hash_is_refused_without_copies() {
    const MIB: usize = 1024 * 1024;
    let config = ChainConfig {
        chain_id: 1,
        display_name: "Ethereum".into(),
        read_order: vec!["direct".into()],
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
        prover: None,
        myotis: false,
        blockscout: None,
    };
    let bounds = Bounds {
        request_bytes: 32 * MIB,
        total_bytes: 64 * MIB,
        ..Bounds::default()
    };
    let mut machine = Machine::new(0, bounds);
    machine.configure(&[config]);
    // A signed transaction (vectors/chain.json).
    let raw = "0xf85f8001825208941111111111111111111111111111111111111111018026a045df4733a45ed06c5628f22221a73e0b2faa3959f649cc47e6c2a15c9792ae07a00ea422e4923de6e5b4c52d7fbd39046e96acf73b2037a5f11918ec6c2a64b40a";
    let id = machine.submit(
        Call::Broadcast {
            chain_id: 1,
            raw: raw.into(),
        },
        None,
    );
    machine.poll();
    let sent = rpcs(&mut machine);
    assert_eq!(sent.len(), 1);
    let prefix = br#"{"jsonrpc":"2.0","id":1,"result":"0x"#;
    let mut body = Vec::with_capacity(prefix.len() + 16 * MIB + 2);
    body.extend_from_slice(prefix);
    body.extend(std::iter::repeat_n(b'a', 16 * MIB));
    body.extend_from_slice(br#""}"#);
    assert!(machine.complete(sent[0].0, Answer::Rpc { status: 200, body }));
    let before = peak();
    machine.poll();
    let after = peak();
    // Another hash: ambiguous, so the core reconciles; the network doesn't
    // know the hash.
    let lookups = rpcs(&mut machine);
    assert_eq!(lookups.len(), 1);
    assert!(lookups[0].1.contains("eth_getTransactionByHash"));
    let null = br#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_vec();
    machine.complete(
        lookups[0].0,
        Answer::Rpc {
            status: 200,
            body: null,
        },
    );
    machine.poll();
    let replies = machine.take_replies();
    let reply = replies.iter().find(|r| r.id == id).unwrap();
    match &reply.result {
        Ok(Success::Broadcast { outcome, .. }) => assert_eq!(*outcome, BroadcastOutcome::Uncertain),
        Err(ChainError::Protocol(code)) => panic!("{}", code.as_str()),
        other => panic!("{other:?}"),
    }
    // Reading the hash copied none of its 16 MiB.
    if let (Some(before), Some(after)) = (before, after) {
        assert!(
            after.saturating_sub(before) < 8 * MIB,
            "classifying the answer raised the peak by {} bytes",
            after.saturating_sub(before)
        );
    }
}
