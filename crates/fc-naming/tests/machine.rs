//! The machine's sessions through its public API.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_naming::jsjson::JsValue;
use fc_naming::session::ens::Config;
use fc_naming::session::machine::Machine;
use fc_naming::session::random::Mulberry32;

fn machine() -> Machine {
    Machine::new(0, machine_config(), Box::new(Mulberry32::new(7)))
}

fn machine_config() -> Config {
    Config {
        rpc: vec!["https://a.rpc.example".into()],
        direct: None,
        order: vec!["quorum".into()],
        prefer_verified: false,
        quorum: JsValue::Null,
        myotis_enabled: false,
        prover: None,
        tezos: vec!["https://t1.tez.example".into()],
        bounds: fc_naming::session::bounds::Bounds::default(),
    }
}

/// ENS events (a Myotis transition, `reset: "providers"`) retire ENS
/// sessions' in-flight keys; Tezos has its own table and keeps sharing.
#[test]
fn ens_events_leave_tezos_lookups_shared() {
    let mut machine = machine();
    machine.resolve_tezos("alice.tez");
    machine.poll();
    assert_eq!(machine.running(), 1);
    machine.availability(true);
    machine.invalidate_providers();
    machine.resolve_tezos("alice.tez");
    machine.poll();
    assert_eq!(machine.running(), 1, "the second lookup joined the first");
    // An ENS lookup after the same events starts afresh, as today.
    machine.resolve_content("vitalik.eth");
    machine.poll();
    machine.availability(false);
    machine.resolve_content("vitalik.eth");
    machine.poll();
    assert_eq!(machine.running(), 3);
}

/// Deviation `reply-size` holds for replies made at once too: an invalid
/// address is echoed back, and a huge one would outgrow the frame.
#[test]
fn immediate_replies_obey_the_reply_size() {
    let mut machine = machine();
    let address = "x".repeat(600_000);
    machine.resolve_reverse(&address, 1.0);
    let replies = machine.take_replies();
    assert_eq!(
        replies[0]
            .outcome
            .as_ref()
            .err()
            .map(|e| e.message.as_str()),
        Some("result too large")
    );
}

/// A session needs room for its first caller: none per session admits none.
#[test]
fn zero_callers_per_session_admits_none() {
    let mut config = machine_config();
    config.bounds.callers_per_session = 0;
    let mut machine = Machine::new(0, config, Box::new(Mulberry32::new(7)));
    machine.resolve_content("vitalik.eth");
    let replies = machine.take_replies();
    assert_eq!(
        replies[0].outcome.as_ref().err().and_then(|e| e.code),
        Some("busy")
    );
    assert_eq!(machine.running(), 0);
}
