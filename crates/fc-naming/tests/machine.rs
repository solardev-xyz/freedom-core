//! The machine's sessions through its public API.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_naming::jsjson::JsValue;
use fc_naming::session::ens::{Config, Request, VerifiedOp};
use fc_naming::session::exec::Effect;
use fc_naming::session::machine::{CallOptions, Machine};
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

/// Each verified operation's request, with the callers it serves now.
fn verified_ops(machine: &mut Machine) -> Vec<(u64, Option<String>)> {
    machine.poll();
    machine
        .take_effects()
        .into_iter()
        .filter_map(|emitted| match emitted.effect {
            Effect::Request {
                id,
                request: Request::Verified(VerifiedOp::MyotisRecord { name, .. }),
                ..
            } => Some((id, name)),
            _ => None,
        })
        .collect()
}

/// `callers_of` names the callers a request serves now (freedom-core
/// #285): those waiting on the session whose attempt made it, in the order
/// they came. One that joins the session is named; one that leaves (a
/// cancel, its own deadline) is not, from its reply on; lookups of other
/// names never share a request; and one no caller waits for names none.
#[test]
fn a_request_serves_the_callers_waiting_on_its_session() {
    let mut config = machine_config();
    config.order = vec!["myotis".into()];
    config.myotis_enabled = true;
    let mut machine = Machine::new(0, config, Box::new(Mulberry32::new(7)));
    machine.availability(true);
    let first = machine.resolve_content("a.eth");
    let ops = verified_ops(&mut machine);
    assert_eq!(ops.len(), 1, "{ops:?}");
    let (a, ref name) = ops[0];
    assert_eq!(name.as_deref(), Some("a.eth"));
    assert_eq!(machine.callers_of(a), vec![first]);
    // A second lookup of the name joins the session; another name has its
    // own.
    let joined = machine.resolve_content_with(
        "a.eth",
        CallOptions {
            attempts_used: 0,
            deadline_ms: Some(1_000),
        },
    );
    let other = machine.resolve_content("b.eth");
    let ops = verified_ops(&mut machine);
    assert_eq!(ops.len(), 1, "{ops:?}");
    let (b, ref name) = ops[0];
    assert_eq!(name.as_deref(), Some("b.eth"));
    assert_eq!(machine.callers_of(a), vec![first, joined]);
    assert_eq!(machine.callers_of(b), vec![other]);
    // The first leaves: the session runs on for the one that joined.
    assert!(machine.cancel(first));
    assert_eq!(machine.callers_of(a), vec![joined]);
    // The one that joined reaches its own deadline: it is answered, and the
    // session, which no caller waits for any more, runs on.
    while machine.fire_next(1_000).is_some() {
        machine.poll();
    }
    machine.poll();
    let replies = machine.take_replies();
    assert!(replies.iter().any(|r| r.caller == joined), "{replies:?}");
    assert!(machine.callers_of(a).is_empty());
    assert_eq!(machine.running(), 2);
    assert_eq!(machine.callers_of(b), vec![other]);
    // A request the machine never made serves nobody.
    assert!(machine.callers_of(a.max(b) + 100).is_empty());
}
