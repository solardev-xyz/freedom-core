//! The machine's sessions through its public API.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_naming::jsjson::JsValue;
use fc_naming::session::ens::Config;
use fc_naming::session::machine::Machine;
use fc_naming::session::random::Mulberry32;

fn machine() -> Machine {
    let config = Config {
        rpc: vec!["https://a.rpc.example".into()],
        direct: None,
        order: vec!["quorum".into()],
        prefer_verified: false,
        quorum: JsValue::Null,
        myotis_enabled: false,
        prover: None,
        tezos: vec!["https://t1.tez.example".into()],
    };
    Machine::new(0, config, Box::new(Mulberry32::new(7)))
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
