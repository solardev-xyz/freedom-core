//! `chain.html` decodes an 8 MiB document into one buffer, the document
//! itself (design 0006, `chain.html`; 0005, Bounds): the answer's text is
//! read in place, and the document is cut from the decoded bytes, not
//! copied out of them. Its own process, so the peak resident size it
//! measures is this test's alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_chain::machine::{
    Answer, Bounds, Call, ChainConfig, Effect, Machine, QuorumConfig, RpcEndpoint, Success,
};

/// The process's peak resident size, where Linux reports it.
fn peak() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kib: usize = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

#[test]
fn an_8_mib_document_costs_one_buffer() {
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
    let mut machine = Machine::new(0, Bounds::default());
    machine.configure(&[config]);
    let id = machine.submit(
        Call::Html {
            chain_id: 1,
            contract: "0x5555555555555555555555555555555555555555".into(),
            origin: "web3://0x5555555555555555555555555555555555555555:1".into(),
        },
        None,
    );
    machine.poll();
    let io = machine
        .take_effects()
        .into_iter()
        .find_map(|e| match e.effect {
            Effect::Request { id, .. } => Some(id),
            Effect::Cancel { .. } => None,
        })
        .unwrap();
    // `{"jsonrpc":"2.0","id":1,"result":"0x<offset><length><8 MiB of 'a'>"}`.
    let mut body = Vec::with_capacity(16 * MIB + 256);
    body.extend_from_slice(br#"{"jsonrpc":"2.0","id":1,"result":"0x"#);
    body.extend_from_slice(format!("{:064x}{:064x}", 32, 8 * MIB).as_bytes());
    for _ in 0..8 * MIB {
        body.extend_from_slice(b"61");
    }
    body.extend_from_slice(br#""}"#);
    assert!(machine.complete(io, Answer::Rpc { status: 200, body }));
    let before = peak();
    machine.poll();
    let after = peak();
    let replies = machine.take_replies();
    let reply = replies.iter().find(|r| r.id == id).unwrap();
    match &reply.result {
        Ok(Success::Html { html, .. }) => assert_eq!(html.len(), 8 * MIB),
        other => panic!("{other:?}"),
    }
    // One 8 MiB buffer, which the reply holds; two copies would be 16 MiB.
    if let (Some(before), Some(after)) = (before, after) {
        assert!(
            after.saturating_sub(before) < 12 * MIB,
            "decoding raised the peak by {} bytes",
            after.saturating_sub(before)
        );
    }
}
