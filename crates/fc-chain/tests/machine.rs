//! The chain machine's deviations, bounds and broadcast outcomes, each
//! tested directly (design 0005, Deviations and Bounds). The replay
//! (`tests/replay.rs`) holds the machine to the reference; these tests hold
//! it to what the design changes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_chain::FeeQuote;
use fc_chain::machine::{
    Answer, Bounds, BroadcastOutcome, Call, ChainConfig, ChainError, ColibriReply, Effect, Emitted,
    FeeReference, Header, Machine, MyotisClass, MyotisRejection, MyotisReply, Prop, Protocol,
    Prover, QuorumConfig, ReadOptions, Reply, Request, RpcEndpoint, Success, Transport, VerifiedOp,
};

/// A test world: the machine and everything it emitted.
struct World {
    machine: Machine,
    /// Every request the machine made: `(io id, at, request, generation)`.
    requests: Vec<(u64, u64, Request, Option<u64>)>,
    /// Every cancel: `(io id, at)`.
    cancels: Vec<(u64, u64)>,
    replies: Vec<Reply>,
}

impl World {
    fn new(bounds: Bounds, chains: &[ChainConfig]) -> Self {
        let mut machine = Machine::new(0, bounds);
        machine.configure(chains);
        Self {
            machine,
            requests: Vec::new(),
            cancels: Vec::new(),
            replies: Vec::new(),
        }
    }

    fn collect(&mut self) {
        self.machine.poll();
        for Emitted {
            effect, generation, ..
        } in self.machine.take_effects()
        {
            match effect {
                Effect::Request {
                    id, at, request, ..
                } => self.requests.push((id, at, request, generation)),
                Effect::Cancel { id, at } => self.cancels.push((id, at)),
            }
        }
        self.replies.extend(self.machine.take_replies());
    }

    /// Runs the machine to `until`, firing every timer on the way.
    fn run(&mut self, until: u64) {
        loop {
            self.collect();
            if self.machine.fire_next(until).is_none() {
                break;
            }
        }
        self.collect();
    }

    fn submit(&mut self, call: Call, deadline: Option<u64>) -> u64 {
        let id = self.machine.submit(call, deadline);
        self.collect();
        id
    }

    fn answer(&mut self, io: u64, answer: Answer) -> bool {
        let taken = self.machine.complete(io, answer);
        self.collect();
        taken
    }

    fn reply(&self, id: u64) -> &Reply {
        self.replies
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("no reply for {id}"))
    }

    fn replied(&self, id: u64) -> bool {
        self.replies.iter().any(|r| r.id == id)
    }

    /// The RPC requests made, as `(io id, at, endpoint, method)`.
    fn rpcs(&self) -> Vec<(u64, u64, String, String)> {
        self.requests
            .iter()
            .filter_map(|(id, at, request, _)| match request {
                Request::Rpc { endpoint, body, .. } => {
                    let method = body
                        .split("\"method\":\"")
                        .nth(1)
                        .and_then(|rest| rest.split('"').next())
                        .unwrap_or("")
                        .to_owned();
                    Some((*id, *at, endpoint.clone(), method))
                }
                _ => None,
            })
            .collect()
    }

    fn cancelled(&self, io: u64) -> Option<u64> {
        self.cancels
            .iter()
            .find(|(id, _)| *id == io)
            .map(|(_, at)| *at)
    }
}

fn chain(id: u64, read: &[&str], rpc: &[&str], quorum: (&str, &str, &str)) -> ChainConfig {
    ChainConfig {
        chain_id: id,
        display_name: "Ethereum".into(),
        read_order: read.iter().map(|s| (*s).to_owned()).collect(),
        broadcast_order: vec!["myotis".into(), "direct".into()],
        quorum: QuorumConfig {
            k: Some(quorum.0.into()),
            m: Some(quorum.1.into()),
            timeout_ms: Some(quorum.2.into()),
        },
        rpc: rpc
            .iter()
            .map(|e| RpcEndpoint {
                endpoint: (*e).to_owned(),
                user_configured: false,
            })
            .collect(),
        prover: None,
        myotis: true,
        blockscout: None,
    }
}

fn read(chain_id: u64, method: &str, params: &str) -> Call {
    Call::Read {
        chain_id,
        method: method.into(),
        params: params.into(),
        options: ReadOptions::default(),
    }
}

/// A body held at exactly its length: the budget counts what a buffer
/// holds, so the bounds below read in answer sizes.
fn exact(text: String) -> Vec<u8> {
    text.into_bytes().into_boxed_slice().into_vec()
}

fn ok(result: &str) -> Answer {
    Answer::Rpc {
        status: 200,
        body: exact(format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#)),
    }
}

fn node_error(code: i64, message: &str) -> Answer {
    Answer::Rpc {
        status: 200,
        body: exact(format!(
            r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":{code},"message":"{message}"}}}}"#
        )),
    }
}

fn protocol(reply: &Reply) -> Option<Protocol> {
    match &reply.result {
        Err(ChainError::Protocol(code)) => Some(*code),
        _ => None,
    }
}

fn result(reply: &Reply) -> Option<&str> {
    match &reply.result {
        Ok(Success::Read { result, .. }) => result.as_deref(),
        _ => None,
    }
}

const CALL: &str = r#"[{"to":"0xabc"},"latest"]"#;

// ---------------------------------------------------------------------------
// overall-deadline

#[test]
fn a_read_ends_at_its_overall_deadline_and_asks_nothing_more() {
    // Direct with a 60 s budget per endpoint, two endpoints: today ~120 s.
    let bounds = Bounds {
        deadline_ms: 90_000,
        ..Bounds::default()
    };
    let mut world = World::new(
        bounds,
        &[chain(1, &["direct"], &["a", "b"], ("3", "2", "60000"))],
    );
    let id = world.submit(read(1, "eth_call", CALL), None);
    world.run(89_999);
    // a timed out at 60 s, b was asked then.
    let rpcs = world.rpcs();
    assert_eq!(rpcs.len(), 2);
    assert_eq!((rpcs[1].1, rpcs[1].2.as_str()), (60_000, "b"));
    assert!(!world.replied(id));
    world.run(90_000);
    let reply = world.reply(id);
    assert_eq!(
        (protocol(reply), reply.settled),
        (Some(Protocol::Deadline), 90_000)
    );
    // Its exchange is cancelled at the deadline, and nothing more is asked.
    assert_eq!(world.cancelled(rpcs[1].0), Some(90_000));
    world.run(500_000);
    assert_eq!(world.rpcs().len(), 2);
}

#[test]
fn the_callers_deadline_applies_when_lower() {
    let mut world = World::new(
        Bounds::default(),
        &[chain(1, &["direct"], &["a", "b"], ("3", "2", "60000"))],
    );
    let id = world.submit(read(1, "eth_call", CALL), Some(4_000));
    world.run(10_000);
    let reply = world.reply(id);
    assert_eq!(
        (protocol(reply), reply.settled),
        (Some(Protocol::Deadline), 4_000)
    );
    // A caller can't extend the bound: 120 s, though b's attempt would end
    // at that very instant.
    let id = world.submit(read(1, "eth_call", CALL), Some(500_000));
    world.run(200_000);
    let reply = world.reply(id);
    assert_eq!(
        (protocol(reply), reply.settled),
        (Some(Protocol::Deadline), 10_000 + 120_000)
    );
    let fee = world.submit(Call::FeeQuote { chain_id: 1 }, Some(1_000));
    world.run(200_000 + 1_000);
    assert_eq!(protocol(world.reply(fee)), Some(Protocol::Deadline));
}

// ---------------------------------------------------------------------------
// admission

#[test]
fn admission_bounds_running_and_waiting_requests() {
    let bounds = Bounds {
        running: 2,
        waiting: 1,
        ..Bounds::default()
    };
    let mut world = World::new(
        bounds,
        &[chain(1, &["direct"], &["a"], ("3", "2", "60000"))],
    );
    let first = world.submit(read(1, "eth_call", CALL), None);
    let second = world.submit(read(1, "eth_call", CALL), None);
    let third = world.submit(read(1, "eth_call", CALL), Some(10_000));
    let fourth = world.submit(read(1, "eth_call", CALL), None);
    // Two run, one waits, the fourth is busy at once.
    assert_eq!((world.machine.running(), world.machine.waiting()), (2, 1));
    assert_eq!(protocol(world.reply(fourth)), Some(Protocol::Busy));
    assert_eq!(world.reply(fourth).settled, 0);
    // Under the chain's current generation, like every reply: main's fence
    // must not take it for an overtaken one.
    assert_eq!(world.reply(fourth).generation, 1);
    assert_eq!(world.rpcs().len(), 2);
    // The first finishes at 1 s: the waiting one starts then.
    world.run(1_000);
    let (io, ..) = world.rpcs()[0].clone();
    world.answer(io, ok("\"0x1\""));
    assert_eq!(result(world.reply(first)), Some("\"0x1\""));
    assert_eq!(world.rpcs().len(), 3);
    assert_eq!(world.rpcs()[2].1, 1_000);
    // Its deadline counted from its arrival.
    world.run(10_000);
    assert_eq!(protocol(world.reply(third)), Some(Protocol::Deadline));
    assert_eq!(world.reply(third).settled, 10_000);
    assert!(!world.replied(second));
}

#[test]
fn replies_made_at_once_carry_the_current_generation() {
    let config = chain(1, &["direct"], &["a"], ("3", "2", "5000"));
    let mut world = World::new(Bounds::default(), std::slice::from_ref(&config));
    let mut changed = config;
    changed.rpc.clear();
    world.machine.configure(&[changed]);
    // An unsupported method and a call with no time left, under generation
    // 2; a chain not configured has none.
    let refused = world.submit(read(1, "eth_sign", "[]"), None);
    let expired = world.submit(read(1, "eth_call", CALL), Some(0));
    let unknown = world.submit(read(5, "eth_call", CALL), None);
    assert_eq!(world.reply(refused).generation, 2);
    assert_eq!(
        (
            protocol(world.reply(expired)),
            world.reply(expired).generation
        ),
        (Some(Protocol::Deadline), 2)
    );
    assert_eq!(world.reply(unknown).generation, 0);
    assert!(world.requests.is_empty());
}

#[test]
fn a_waiting_request_can_expire_before_it_starts() {
    let bounds = Bounds {
        running: 1,
        waiting: 4,
        ..Bounds::default()
    };
    let mut world = World::new(
        bounds,
        &[chain(1, &["direct"], &["a"], ("3", "2", "60000"))],
    );
    world.submit(read(1, "eth_call", CALL), None);
    let waiting = world.submit(read(1, "eth_call", CALL), Some(2_000));
    world.run(2_000);
    let reply = world.reply(waiting);
    assert_eq!(
        (protocol(reply), reply.settled),
        (Some(Protocol::Deadline), 2_000)
    );
    assert_eq!(world.rpcs().len(), 1);
    // A cancel of a waiting request answers it at once.
    let cancelled = world.submit(read(1, "eth_call", CALL), None);
    assert!(world.machine.cancel(cancelled));
    world.collect();
    assert_eq!(protocol(world.reply(cancelled)), Some(Protocol::Cancelled));
}

// ---------------------------------------------------------------------------
// abandoned-exchanges, and cancellation

#[test]
fn a_cancel_cancels_the_quorums_members() {
    let mut world = World::new(
        Bounds::default(),
        &[chain(
            1,
            &["quorum", "direct"],
            &["a", "b", "c"],
            ("3", "2", "5000"),
        )],
    );
    let id = world.submit(read(1, "eth_call", CALL), None);
    assert_eq!(world.rpcs().len(), 3);
    world.run(1_200);
    assert!(world.machine.cancel(id));
    world.collect();
    let reply = world.reply(id);
    assert_eq!(
        (protocol(reply), reply.settled),
        (Some(Protocol::Cancelled), 1_200)
    );
    // Today the members run on to their timeout; the core cancels them.
    for (io, ..) in world.rpcs() {
        assert_eq!(world.cancelled(io), Some(1_200));
    }
    // A late answer is dropped.
    assert!(!world.answer(world.rpcs()[0].0, ok("\"0x1\"")));
    world.run(60_000);
    assert_eq!(world.rpcs().len(), 3);
    assert!(!world.machine.cancel(id));
}

#[test]
fn verifier_work_keeps_its_slot_after_a_cancel() {
    let mut world = World::new(
        Bounds::default(),
        &[chain(1, &["myotis", "direct"], &["a"], ("3", "2", "5000"))],
    );
    world.machine.availability(1, true);
    let first = world.submit(read(1, "eth_call", CALL), None);
    let ops: Vec<u64> = world
        .requests
        .iter()
        .filter(|(_, _, r, _)| matches!(r, Request::Verified(_)))
        .map(|(id, ..)| *id)
        .collect();
    assert_eq!(ops.len(), 1);
    world.machine.cancel(first);
    world.collect();
    // The operation is never cancelled: main can't abort an adapter's work.
    assert!(world.cancels.is_empty());
    assert_eq!(world.machine.state_tables().myotis_slots, [(1, 1, 0)]);
    // A second read waits for the slot until main's terminal reply.
    let second = world.submit(read(1, "eth_call", CALL), None);
    assert_eq!(world.machine.state_tables().myotis_slots, [(1, 1, 1)]);
    world.run(1_000);
    world.answer(
        ops[0],
        Answer::Myotis(MyotisReply::Read {
            payload: r#"{"result_hex":"0x1"}"#.into(),
            block_before: None,
            block_after: None,
        }),
    );
    // The slot passes to the waiter, whose own operation is now made.
    let ops: Vec<u64> = world
        .requests
        .iter()
        .filter(|(_, at, r, _)| matches!(r, Request::Verified(_)) && *at == 1_000)
        .map(|(id, ..)| *id)
        .collect();
    assert_eq!(ops.len(), 1);
    world.answer(
        ops[0],
        Answer::Myotis(MyotisReply::Read {
            payload: r#"{"result_hex":"0x2"}"#.into(),
            block_before: None,
            block_after: None,
        }),
    );
    assert_eq!(result(world.reply(second)), Some("\"0x2\""));
    assert!(world.machine.state_tables().myotis_slots.is_empty());
}

// ---------------------------------------------------------------------------
// order-validation and quorum-clamps

#[test]
fn a_duplicate_source_is_tried_once() {
    let mut world = World::new(
        Bounds::default(),
        &[chain(
            1,
            &["direct", "nope", "direct"],
            &["a"],
            ("3", "2", "5000"),
        )],
    );
    let id = world.submit(read(1, "eth_call", CALL), None);
    let (io, ..) = world.rpcs()[0].clone();
    world.answer(io, node_error(-32000, "boom"));
    // Today Direct runs twice and `nope` fails late.
    assert_eq!(world.rpcs().len(), 1);
    match &world.reply(id).result {
        Err(ChainError::Thrown(thrown)) => assert_eq!(thrown.message.to_string_lossy(), "boom"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_cores_quorum_bounds() {
    let endpoints: Vec<String> = (0..12).map(|i| format!("e{i}")).collect();
    let refs: Vec<&str> = endpoints.iter().map(String::as_str).collect();
    let mut world = World::new(
        Bounds::default(),
        &[chain(1, &["quorum", "direct"], &refs, ("50", "40", "1e9"))],
    );
    let id = world.submit(read(1, "eth_call", CALL), None);
    // k is at most 9 (and m at most k), and the timeout at most 60 s.
    assert_eq!(world.rpcs().len(), 9);
    world.run(59_999);
    assert!(!world.replied(id));
    world.run(60_000);
    let rpcs = world.rpcs();
    for (io, ..) in &rpcs[..9] {
        assert_eq!(world.cancelled(*io), Some(60_000));
    }
    // Direct asks the first endpoint the quorum didn't.
    assert_eq!((rpcs[9].1, rpcs[9].2.as_str()), (60_000, "e9"));
}

#[test]
fn at_most_64_endpoints_are_configured() {
    let endpoints: Vec<String> = (0..80).map(|i| format!("e{i}")).collect();
    let refs: Vec<&str> = endpoints.iter().map(String::as_str).collect();
    let mut world = World::new(
        Bounds::default(),
        &[chain(1, &["direct"], &refs, ("3", "2", "500"))],
    );
    let id = world.submit(read(1, "eth_call", CALL), None);
    world.run(100_000);
    // Direct walks every endpoint, 500 ms each: the first 64 only.
    let asked: Vec<String> = world.rpcs().into_iter().map(|(_, _, e, _)| e).collect();
    assert_eq!(asked, endpoints[..64]);
    assert_eq!(world.reply(id).settled, 64 * 500);
}

// ---------------------------------------------------------------------------
// config-change and generations

#[test]
fn a_configuration_change_ends_the_chains_requests() {
    let a = chain(
        1,
        &["quorum", "direct"],
        &["a", "b", "c"],
        ("3", "2", "5000"),
    );
    let other = chain(100, &["direct"], &["x"], ("3", "2", "5000"));
    let mut world = World::new(Bounds::default(), &[a.clone(), other.clone()]);
    let on_one = world.submit(read(1, "eth_call", CALL), None);
    let on_hundred = world.submit(read(100, "eth_call", CALL), None);
    assert!(world.requests.iter().all(|(.., g)| *g == Some(1)));
    world.run(1_000);
    let changed = ChainConfig {
        rpc: vec![RpcEndpoint {
            endpoint: "e".into(),
            user_configured: true,
        }],
        ..a.clone()
    };
    let generations = world.machine.configure(&[changed, other.clone()]);
    world.collect();
    assert_eq!(generations.get(&1), Some(&2));
    assert_eq!(generations.get(&100), Some(&1));
    // The read on the changed chain ends at once under its old generation,
    // its members cancelled; the other chain's runs on.
    let reply = world.reply(on_one);
    assert_eq!(
        (protocol(reply), reply.settled, reply.generation),
        (Some(Protocol::Reconfigured), 1_000, 1)
    );
    for (io, _, endpoint, _) in world.rpcs() {
        if endpoint != "x" {
            assert_eq!(world.cancelled(io), Some(1_000));
        }
    }
    assert!(!world.replied(on_hundred));
    // A new request runs under the new generation.
    world.submit(read(1, "eth_call", CALL), None);
    let (.., generation) = world.requests.last().unwrap();
    assert_eq!(*generation, Some(2));
    // The same snapshot again changes nothing.
    let same = world.machine.configure(&[
        ChainConfig {
            rpc: vec![RpcEndpoint {
                endpoint: "e".into(),
                user_configured: true,
            }],
            ..a
        },
        other,
    ]);
    assert_eq!(same.get(&1), Some(&2));
}

#[test]
fn a_broadcast_ended_by_a_change_is_uncertain_once_sent() {
    let mut config = chain(1, &["direct"], &["a"], ("3", "2", "5000"));
    config.broadcast_order = vec!["direct".into()];
    let mut world = World::new(Bounds::default(), std::slice::from_ref(&config));
    let raw = "0x02f86f";
    let id = world.submit(
        Call::Broadcast {
            chain_id: 1,
            raw: raw.into(),
        },
        None,
    );
    world.run(10);
    world.machine.configure(&[ChainConfig {
        rpc: vec![RpcEndpoint {
            endpoint: "b".into(),
            user_configured: false,
        }],
        ..config
    }]);
    world.collect();
    match &world.reply(id).result {
        Ok(Success::Broadcast { outcome, .. }) => assert_eq!(*outcome, BroadcastOutcome::Uncertain),
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// memory-budgets

#[test]
fn an_answer_over_the_requests_budget_ends_it() {
    let bounds = Bounds {
        request_bytes: 1_000,
        ..Bounds::default()
    };
    let mut world = World::new(bounds, &[chain(1, &["direct"], &["a"], ("3", "2", "5000"))]);
    let id = world.submit(read(1, "eth_call", CALL), None);
    let (io, ..) = world.rpcs()[0].clone();
    let big = format!("\"0x{}\"", "ab".repeat(600));
    assert!(!world.answer(io, ok(&big)));
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Budget));
    // What it held is free again.
    world.machine.set_output_backlog(0);
    world.collect();
    assert_eq!(world.machine.held(), 0);
    // An answer within the budget is fine.
    let id = world.submit(read(1, "eth_call", CALL), None);
    let (io, ..) = world.rpcs()[1].clone();
    assert!(world.answer(io, ok("\"0x1\"")));
    assert_eq!(result(world.reply(id)), Some("\"0x1\""));
}

#[test]
fn a_driver_reserves_before_it_reads_a_reply() {
    let bounds = Bounds {
        request_bytes: 10_000,
        ..Bounds::default()
    };
    let mut world = World::new(bounds, &[chain(1, &["direct"], &["a"], ("3", "2", "5000"))]);
    let id = world.submit(read(1, "eth_call", CALL), None);
    let (io, ..) = world.rpcs()[0].clone();
    assert!(world.machine.wants(io));
    // What reading main's message takes, reserved first; the answer's
    // charge is the reservation, settled to what the answer holds.
    let before = world.machine.held();
    let mut reading = world.machine.reserve_reply(io, 6_000).unwrap();
    assert_eq!(world.machine.held(), before + 6_000);
    reading.settle(3_000).unwrap();
    assert_eq!(world.machine.held(), before + 3_000);
    let answer = ok("\"0x1\"");
    let bytes = answer.bytes();
    let decoded = world.machine.reserve_reply(io, bytes).unwrap();
    drop(reading);
    assert!(world.machine.complete_reserved(io, answer, decoded));
    world.collect();
    assert_eq!(result(world.reply(id)), Some("\"0x1\""));
    // A reservation over the request's bound ends it with `budget`, unread.
    let id = world.submit(read(1, "eth_call", CALL), None);
    let (io, ..) = world.rpcs()[1].clone();
    assert_eq!(
        world.machine.reserve_reply(io, 20_000).err(),
        Some(fc_chain::machine::OverBudget)
    );
    world.machine.complete_unread(io);
    world.collect();
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Budget));
    // Its I/O is wanted no more, and a reservation for it charges nothing.
    assert!(!world.machine.wants(io));
    let nothing = world.machine.reserve_reply(io, usize::MAX).unwrap();
    assert_eq!(nothing.bytes(), 0);
    world.machine.set_output_backlog(0);
    world.collect();
    assert_eq!(world.machine.held(), 0);
}

#[test]
fn a_broadcast_keeps_its_floor_when_reading_its_reply_crosses_the_budget() {
    let bounds = Bounds {
        request_bytes: 4_000,
        ..Bounds::default()
    };
    let mut world = World::new(bounds, &[broadcaster(&["direct"], &["a", "b"])]);
    let id = world.submit(send(), None);
    let (io, ..) = world.rpcs()[0].clone();
    // The attempt went to main; reading its reply would cross the budget.
    assert!(world.machine.reserve_reply(io, 1 << 20).is_err());
    world.machine.complete_unread(io);
    world.collect();
    // Possibly sent: uncertain, never not sent, and nothing more is tried.
    assert_eq!(
        outcome(world.reply(id)),
        (BroadcastOutcome::Uncertain, Some("direct"))
    );
    assert_eq!(world.rpcs().len(), 1);
}

#[test]
fn an_unread_reply_still_frees_a_verifier_slot() {
    let mut world = World::new(
        Bounds::default(),
        &[chain(1, &["myotis"], &["a"], ("3", "2", "5000"))],
    );
    world.machine.availability(1, true);
    let id = world.submit(read(1, "eth_call", CALL), None);
    let io = world.requests[0].0;
    assert!(world.machine.runs(id));
    world.machine.cancel(id);
    world.collect();
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Cancelled));
    // The cancelled read's operation keeps the slot until main's reply,
    // which nobody reads.
    assert_eq!(world.machine.state_tables().myotis_slots, vec![(1, 1, 0)]);
    assert!(!world.machine.wants(io));
    assert!(!world.machine.runs(id));
    world.machine.complete_unread(io);
    world.collect();
    assert!(world.machine.state_tables().myotis_slots.is_empty());
}

#[test]
fn a_kept_node_error_counts_against_the_budget() {
    // A node's error can carry as much data as an answer: the last error
    // a request keeps is charged while any copy of it lives. Each answer
    // here is about 3 KB, and so is its error.
    let bounds = Bounds {
        request_bytes: 7_000,
        ..Bounds::default()
    };
    let mut world = World::new(
        bounds,
        &[chain(1, &["direct"], &["a", "b"], ("3", "2", "5000"))],
    );
    let id = world.submit(read(1, "eth_call", CALL), None);
    let revert = || Answer::Rpc {
        status: 200,
        body: exact(format!(
            r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":3,"message":"execution reverted","data":"0x{}"}}}}"#,
            "ab".repeat(1_500)
        )),
    };
    let first = world.rpcs()[0].0;
    assert!(world.answer(first, revert()));
    assert!(!world.replied(id));
    // a's error is kept as the last one; b's answer and its error on top
    // cross the bound.
    let second = world.rpcs()[1].0;
    world.answer(second, revert());
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Budget));
    world.machine.set_output_backlog(0);
    world.collect();
    assert_eq!(world.machine.held(), 0);
}

#[test]
fn the_total_budget_ends_the_request_that_crosses_it_and_refuses_new_ones() {
    let bounds = Bounds {
        request_bytes: 10_000,
        total_bytes: 12_000,
        ..Bounds::default()
    };
    let mut world = World::new(
        bounds,
        &[chain(1, &["quorum"], &["a", "b", "c"], ("3", "3", "5000"))],
    );
    let first = world.submit(read(1, "eth_call", CALL), None);
    let second = world.submit(read(1, "eth_call", CALL), None);
    let rpcs = world.rpcs();
    let answer = format!("\"0x{}\"", "ab".repeat(2_000));
    // The first request keeps two answers while its third is pending.
    assert!(world.answer(rpcs[0].0, ok(&answer)));
    assert!(world.answer(rpcs[1].0, ok(&answer)));
    assert!(!world.replied(first));
    // The second request's first answer crosses the total: it ends.
    assert!(world.answer(rpcs[3].0, ok(&answer)));
    assert!(!world.answer(rpcs[4].0, ok(&answer)));
    assert_eq!(protocol(world.reply(second)), Some(Protocol::Budget));
    assert!(!world.replied(first));
    // Unwritten replies count in the total: a full backlog refuses new
    // requests until it is written.
    world.machine.set_output_backlog(12_000);
    let refused = world.submit(read(1, "eth_call", CALL), None);
    assert_eq!(protocol(world.reply(refused)), Some(Protocol::Busy));
    world.machine.set_output_backlog(0);
    world.collect();
    let admitted = world.submit(read(1, "eth_call", CALL), None);
    assert!(!world.replied(admitted));
}

#[test]
fn an_8_mib_document_through_a_quorum_of_three_fits_the_default_budget() {
    let mut world = World::new(
        Bounds::default(),
        &[chain(
            1,
            &["quorum", "direct"],
            &["a", "b", "c"],
            ("3", "2", "5000"),
        )],
    );
    let id = world.submit(read(1, "eth_call", CALL), None);
    // An html() document at its 8 MiB limit, ABI-encoded: 16,777,346 hex
    // characters.
    let html = format!(
        "\"0x{:064x}{:064x}{}\"",
        32,
        8 * 1024 * 1024,
        "61".repeat(8 * 1024 * 1024)
    );
    for (io, ..) in world.rpcs() {
        world.answer(io, ok(&html));
    }
    assert_eq!(result(world.reply(id)).map(str::len), Some(html.len()));
    // Every charge was released with the request; only its reply counts.
    assert!(world.machine.held() < html.len() + 1_024);
    world.machine.set_output_backlog(0);
    world.collect();
}

// ---------------------------------------------------------------------------
// monotonic-time

#[test]
fn cooldowns_run_on_the_machines_clock() {
    // A Colibri timeout opens the app's route for 15 s of the machine's own
    // clock: the machine reads no wall clock at all.
    let mut config = chain(1, &["colibri", "direct"], &["a"], ("3", "2", "5000"));
    config.prover = Some(Prover {
        endpoint: "p".into(),
        zk: true,
    });
    let mut world = World::new(Bounds::default(), &[config]);
    let interactive = || Call::Read {
        chain_id: 1,
        method: "eth_call".into(),
        params: CALL.into(),
        options: ReadOptions {
            origin: Some("https://app.example".into()),
            ..ReadOptions::default()
        },
    };
    let id = world.submit(interactive(), None);
    world.run(2_000);
    let (io, ..) = world.rpcs()[0].clone();
    world.answer(io, ok("\"0xrpc\""));
    assert_eq!(world.reply(id).settled, 2_000);
    let route = &world.machine.state_tables().adaptive[0].1;
    assert_eq!((route.timeout_count, route.open_until), (1, 17_000));
    // Bypassed until 17 000 ms of machine time, asked again from then.
    world.run(16_999);
    let colibri = |w: &World| {
        w.requests
            .iter()
            .filter(|(_, _, r, _)| matches!(r, Request::Verified(VerifiedOp::Colibri { .. })))
            .count()
    };
    world.submit(interactive(), None);
    assert_eq!(colibri(&world), 1);
    world.run(17_000);
    world.submit(interactive(), None);
    assert_eq!(colibri(&world), 2);
}

#[test]
fn the_adaptive_table_evicts_its_oldest_route() {
    // The design leaves the 1,024-route eviction to the machine's own
    // tests: with room for two routes, a third app's evicts the first's.
    let bounds = Bounds {
        adaptive_routes: 2,
        ..Bounds::default()
    };
    let mut config = chain(1, &["colibri", "direct"], &["a"], ("3", "2", "5000"));
    config.prover = Some(Prover {
        endpoint: "p".into(),
        zk: true,
    });
    let mut world = World::new(bounds, &[config]);
    for (i, origin) in [
        "https://one.example",
        "https://two.example",
        "https://three.example",
    ]
    .iter()
    .enumerate()
    {
        let call = Call::Read {
            chain_id: 1,
            method: "eth_call".into(),
            params: CALL.into(),
            options: ReadOptions {
                origin: Some((*origin).into()),
                ..ReadOptions::default()
            },
        };
        let id = world.submit(call, None);
        let op = world
            .requests
            .iter()
            .rev()
            .find(|(_, _, r, _)| matches!(r, Request::Verified(_)))
            .map(|(id, ..)| *id)
            .unwrap();
        // Colibri hits its execution limit: the route is blocked.
        world.answer(
            op,
            Answer::Colibri(ColibriReply::Failure(
                fc_chain::machine::ColibriClass::Capacity,
            )),
        );
        let rpc = world.rpcs()[i].0;
        world.answer(rpc, ok("\"0x1\""));
        assert!(world.replied(id));
    }
    let routes: Vec<String> = world
        .machine
        .state_tables()
        .adaptive
        .into_iter()
        .map(|(key, state)| {
            assert!(state.session_blocked);
            key
        })
        .collect();
    assert_eq!(routes.len(), 2);
    assert!(routes[0].contains("two.example") && routes[1].contains("three.example"));
}

// ---------------------------------------------------------------------------
// broadcast-outcome

fn broadcaster(order: &[&str], rpc: &[&str]) -> ChainConfig {
    ChainConfig {
        broadcast_order: order.iter().map(|s| (*s).to_owned()).collect(),
        ..chain(1, &["direct"], rpc, ("3", "2", "5000"))
    }
}

/// A signed transaction and its hash (vectors/chain.json).
const RAW: &str = "0xf85f8001825208941111111111111111111111111111111111111111018026a045df4733a45ed06c5628f22221a73e0b2faa3959f649cc47e6c2a15c9792ae07a00ea422e4923de6e5b4c52d7fbd39046e96acf73b2037a5f11918ec6c2a64b40a";
const HASH: &str = "0xdff97f6d2d938656e056527357e2ee12f38c03923ab1d11bc556fb5cc123e578";

fn send() -> Call {
    Call::Broadcast {
        chain_id: 1,
        raw: RAW.into(),
    }
}

fn outcome(reply: &Reply) -> (BroadcastOutcome, Option<&str>) {
    match &reply.result {
        Ok(Success::Broadcast {
            outcome, source, ..
        }) => (*outcome, Some(source)),
        Err(_) => (reply.outcome.unwrap(), None),
        Ok(other) => panic!("{other:?}"),
    }
}

#[test]
fn an_accepted_attempt_is_sent() {
    let mut world = World::new(Bounds::default(), &[broadcaster(&["direct"], &["a", "b"])]);
    let id = world.submit(send(), None);
    let rpcs = world.rpcs();
    world.answer(
        rpcs[0].0,
        node_error(-32000, "nonce too low: next nonce 8, tx nonce 7"),
    );
    let rpcs = world.rpcs();
    // The hash compares as bytes, any case.
    world.answer(
        rpcs[1].0,
        ok(&format!(
            "\"{}\"",
            HASH.to_uppercase().replacen("0X", "0x", 1)
        )),
    );
    assert_eq!(
        outcome(world.reply(id)),
        (BroadcastOutcome::Sent, Some("direct"))
    );
    match &world.reply(id).result {
        Ok(Success::Broadcast { hash, .. }) => assert_eq!(hash.as_deref(), Some(HASH)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn refusals_alone_are_rejected_with_the_last_refusal() {
    let mut world = World::new(Bounds::default(), &[broadcaster(&["direct"], &["a", "b"])]);
    let id = world.submit(send(), None);
    let rpcs = world.rpcs();
    world.answer(rpcs[0].0, node_error(-32000, "nonce too low"));
    let rpcs = world.rpcs();
    world.answer(
        rpcs[1].0,
        node_error(-32000, "insufficient funds for gas * price + value"),
    );
    assert_eq!(outcome(world.reply(id)), (BroadcastOutcome::Rejected, None));
    match &world.reply(id).result {
        Err(ChainError::Thrown(thrown)) => assert_eq!(
            thrown.message.to_string_lossy(),
            "insufficient funds for gas * price + value"
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_refusal_after_an_ambiguous_attempt_stops_and_is_uncertain() {
    let mut world = World::new(
        Bounds::default(),
        &[broadcaster(&["direct"], &["a", "b", "c"])],
    );
    let id = world.submit(send(), None);
    let rpcs = world.rpcs();
    world.answer(
        rpcs[0].0,
        Answer::Rpc {
            status: 502,
            body: Vec::new(),
        },
    );
    let rpcs = world.rpcs();
    world.answer(rpcs[1].0, node_error(-32000, "nonce too low"));
    // c is never asked: the refusal may be the first attempt's own doing.
    let sends = world
        .rpcs()
        .iter()
        .filter(|(.., m)| m == "eth_sendRawTransaction")
        .count();
    assert_eq!(sends, 2);
    // Reconciliation: the network doesn't know the hash.
    let lookup = world.rpcs().last().unwrap().clone();
    assert_eq!(lookup.3, "eth_getTransactionByHash");
    world.answer(lookup.0, ok("null"));
    assert_eq!(
        outcome(world.reply(id)),
        (BroadcastOutcome::Uncertain, Some("direct"))
    );
}

#[test]
fn reconciliation_finds_a_lost_reply() {
    let mut world = World::new(Bounds::default(), &[broadcaster(&["direct"], &["a"])]);
    let id = world.submit(send(), None);
    // The endpoint accepts, but its reply is lost: a timeout.
    world.run(5_000);
    let lookup = world.rpcs().last().unwrap().clone();
    assert_eq!(
        (lookup.1, lookup.3.as_str()),
        (5_000, "eth_getTransactionByHash")
    );
    world.answer(
        lookup.0,
        ok(&format!(r#"{{"hash":"{HASH}","nonce":"0x7"}}"#)),
    );
    assert_eq!(
        outcome(world.reply(id)),
        (BroadcastOutcome::Sent, Some("reconcile"))
    );
}

#[test]
fn nothing_sent_is_not_sent_with_todays_text() {
    let mut world = World::new(
        Bounds::default(),
        &[broadcaster(&["myotis", "direct"], &[])],
    );
    world.machine.availability(1, true);
    let id = world.submit(send(), None);
    let op = world.requests[0].0;
    world.answer(
        op,
        Answer::Myotis(MyotisReply::Failure(MyotisClass::NotRunning)),
    );
    assert_eq!(outcome(world.reply(id)), (BroadcastOutcome::NotSent, None));
    match &world.reply(id).result {
        Err(ChainError::Thrown(thrown)) => {
            assert_eq!(
                thrown.message.to_string_lossy(),
                "Ethereum Myotis client is not running"
            );
        }
        other => panic!("{other:?}"),
    }
    // A cancel before anything could be sent is `cancelled`, not sent...
    let bounds = Bounds {
        running: 1,
        ..Bounds::default()
    };
    let mut world = World::new(bounds, &[broadcaster(&["myotis", "direct"], &["a"])]);
    let id = world.submit(send(), None);
    let queued = world.submit(send(), None);
    world.machine.cancel(queued);
    world.collect();
    let reply = world.reply(queued);
    assert_eq!(
        (protocol(reply), reply.outcome),
        (Some(Protocol::Cancelled), Some(BroadcastOutcome::NotSent))
    );
    // ...but once an attempt is out, a cancel is uncertain.
    assert_eq!(world.rpcs().len(), 1);
    world.machine.cancel(id);
    world.collect();
    assert_eq!(
        outcome(world.reply(id)),
        (BroadcastOutcome::Uncertain, Some("direct"))
    );
}

#[test]
fn myotis_verdicts_end_the_loop() {
    // Either definite refusal ends the broadcast `rejected`, Direct never
    // asked, with the adapter's error as it threw it: its message, its
    // code, then its marker.
    for (kind, reason, code, marker) in [
        (
            MyotisRejection::Rejected,
            "nonce too low: next nonce 5, tx nonce 4",
            "-32000",
            r#""rejected""#,
        ),
        (
            MyotisRejection::InvalidParams,
            "invalid raw transaction: malformed type 0x2 transaction",
            "-32602",
            r#""invalid-params""#,
        ),
    ] {
        let mut world = World::new(
            Bounds::default(),
            &[broadcaster(&["myotis", "direct"], &["a"])],
        );
        world.machine.availability(1, true);
        let id = world.submit(send(), None);
        world.answer(
            world.requests[0].0,
            Answer::Myotis(MyotisReply::Rejected {
                reason: reason.into(),
                kind,
            }),
        );
        assert_eq!(outcome(world.reply(id)), (BroadcastOutcome::Rejected, None));
        assert!(world.rpcs().is_empty());
        match &world.reply(id).result {
            Err(ChainError::Thrown(thrown)) => {
                assert_eq!(thrown.message.to_string_lossy(), reason);
                let props: Vec<_> = thrown
                    .props
                    .iter()
                    .map(|(key, value)| (*key, value.clone()))
                    .collect();
                assert_eq!(
                    props,
                    [
                        ("code", Prop::Json(code.into())),
                        ("myotisRefusal", Prop::Json(marker.into())),
                    ]
                );
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn attempts_stop_before_the_deadline_to_leave_room_for_reconciling() {
    let bounds = Bounds {
        deadline_ms: 30_000,
        ..Bounds::default()
    };
    let mut config = broadcaster(&["direct"], &["a"]);
    config.quorum.timeout_ms = Some("60000".into());
    let mut world = World::new(bounds, &[config]);
    let id = world.submit(send(), None);
    // The attempt hangs; at 20 s (10 s before the deadline) it is dropped
    // and counts as ambiguous, and the lookup runs.
    world.run(20_000);
    let rpcs = world.rpcs();
    assert_eq!(world.cancelled(rpcs[0].0), Some(20_000));
    assert_eq!(
        (rpcs[1].1, rpcs[1].3.as_str()),
        (20_000, "eth_getTransactionByHash")
    );
    // The lookup hangs too: at the deadline the outcome is uncertain.
    world.run(30_000);
    let reply = world.reply(id);
    assert_eq!(
        (outcome(reply), reply.settled),
        ((BroadcastOutcome::Uncertain, Some("direct")), 30_000)
    );
    // With no room at all, nothing is attempted.
    let id = world.submit(send(), Some(5_000));
    let reply = world.reply(id);
    assert_eq!(
        (protocol(reply), reply.outcome),
        (Some(Protocol::Deadline), Some(BroadcastOutcome::NotSent))
    );
}

// ---------------------------------------------------------------------------
// Replies

#[test]
fn a_reply_over_the_message_cap_is_too_large() {
    let bounds = Bounds {
        message_bytes: 1_000,
        ..Bounds::default()
    };
    let mut world = World::new(bounds, &[chain(1, &["direct"], &["a"], ("3", "2", "5000"))]);
    let id = world.submit(read(1, "eth_call", CALL), None);
    let (io, ..) = world.rpcs()[0].clone();
    world.answer(io, ok(&format!("\"0x{}\"", "ab".repeat(500))));
    assert_eq!(protocol(world.reply(id)), Some(Protocol::TooLarge));
}

#[test]
fn colibri_reverts_and_failures_carry_no_adapter_text() {
    let mut config = chain(1, &["colibri", "direct"], &[], ("3", "2", "5000"));
    config.prover = Some(Prover {
        endpoint: "p".into(),
        zk: false,
    });
    let mut world = World::new(Bounds::default(), &[config]);
    let id = world.submit(read(1, "eth_call", CALL), None);
    let op = world.requests[0].0;
    world.answer(
        op,
        Answer::Colibri(ColibriReply::Revert {
            data: "0x08c379a0".into(),
            capacity: false,
        }),
    );
    match &world.reply(id).result {
        Err(ChainError::Thrown(thrown)) => {
            assert_eq!(thrown.message.to_string_lossy(), "execution reverted");
            assert_eq!(thrown.code(), Some("3"));
            assert_eq!(
                thrown.prop("data").and_then(|d| d.json()),
                Some("\"0x08c379a0\"")
            );
        }
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The safety review's cases (PR #55): memory-budgets, verifier slots,
// response-caps and overall-deadline, each as a regression test.

fn colibri_chain(read: &[&str]) -> ChainConfig {
    ChainConfig {
        prover: Some(Prover {
            endpoint: "p".into(),
            zk: true,
        }),
        ..chain(1, read, &["a"], ("3", "2", "5000"))
    }
}

fn interactive(method: &str, params: &str, origin: &str) -> Call {
    Call::Read {
        chain_id: 1,
        method: method.into(),
        params: params.into(),
        options: ReadOptions {
            origin: Some(origin.into()),
            ..ReadOptions::default()
        },
    }
}

/// What a read holds once it has started and its first request has left:
/// its call and its standing room for its params.
fn standing(read: &[&str], params: &str) -> usize {
    let mut world = World::new(
        Bounds::default(),
        &[chain(1, read, &["a"], ("3", "2", "5000"))],
    );
    world.submit(self::read(1, "eth_call", params), None);
    world.machine.held()
}

#[test]
fn a_myotis_answer_over_the_budget_still_frees_its_slot() {
    // Main's one terminal reply ends the operation even when its payload
    // is over the request's budget: the slot is free again.
    let bounds = Bounds {
        request_bytes: 1_000,
        ..Bounds::default()
    };
    let mut world = World::new(bounds, &[chain(1, &["myotis"], &["a"], ("3", "2", "5000"))]);
    world.machine.availability(1, true);
    let id = world.submit(read(1, "eth_call", CALL), None);
    let io = world.requests[0].0;
    assert_eq!(world.machine.state_tables().myotis_slots, vec![(1, 1, 0)]);
    let payload = format!(r#"{{"result_hex":"0x{}"}}"#, "a".repeat(2_000));
    assert!(!world.answer(
        io,
        Answer::Myotis(MyotisReply::Read {
            payload,
            block_before: None,
            block_after: None,
        })
    ));
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Budget));
    assert!(world.machine.state_tables().myotis_slots.is_empty());
    world.machine.set_output_backlog(0);
    world.collect();
    assert_eq!(world.machine.held(), 0);
}

#[test]
fn colibri_answers_over_the_budget_still_free_every_slot() {
    let bounds = Bounds {
        request_bytes: 1_000,
        ..Bounds::default()
    };
    let mut world = World::new(bounds, &[colibri_chain(&["colibri"])]);
    let ids: Vec<u64> = (0..8)
        .map(|i| {
            world.submit(
                interactive("eth_call", CALL, &format!("https://app{i}.example")),
                None,
            )
        })
        .collect();
    assert_eq!(world.machine.state_tables().colibri_in_flight, 8);
    let ios: Vec<u64> = world.requests.iter().map(|r| r.0).collect();
    for io in ios {
        let result = format!("\"{}\"", "a".repeat(2_000));
        assert!(!world.answer(io, Answer::Colibri(ColibriReply::Result(result))));
    }
    for id in ids {
        assert_eq!(protocol(world.reply(id)), Some(Protocol::Budget));
    }
    let tables = world.machine.state_tables();
    assert_eq!(tables.colibri_in_flight, 0);
    assert!(tables.colibri_routes.is_empty());
}

#[test]
fn a_kept_colibri_revert_is_charged_while_it_lives() {
    // The revert is kept as the last error while Direct is asked: its data
    // is charged until the request ends.
    let mut world = World::new(Bounds::default(), &[colibri_chain(&["colibri", "direct"])]);
    let id = world.submit(read(1, "eth_call", CALL), None);
    let before = world.machine.held();
    let data = format!("0x{}", "ab".repeat(400));
    world.answer(
        world.requests[0].0,
        Answer::Colibri(ColibriReply::Revert {
            data,
            capacity: false,
        }),
    );
    assert!(!world.replied(id));
    assert_eq!(world.rpcs().len(), 1);
    assert!(
        world.machine.held() >= before + 802,
        "held {} after a kept 802-byte revert (before: {before})",
        world.machine.held()
    );
    world.answer(world.rpcs()[0].0, node_error(-32000, "boom"));
    world.machine.set_output_backlog(0);
    world.collect();
    assert!(world.replied(id));
    assert_eq!(world.machine.held(), 0);
}

#[test]
fn a_myotis_revert_counts_against_the_budget() {
    let base = standing(&["myotis"], CALL);
    let bounds = Bounds {
        request_bytes: base + 6_000,
        ..Bounds::default()
    };
    let mut world = World::new(bounds, &[chain(1, &["myotis"], &["a"], ("3", "2", "5000"))]);
    world.machine.availability(1, true);
    let id = world.submit(read(1, "eth_call", CALL), None);
    // The payload fits; its revert data's copies don't.
    let payload = format!(
        r#"{{"status":"revert","data_hex":"0x{}"}}"#,
        "ab".repeat(1_000)
    );
    world.answer(
        world.requests[0].0,
        Answer::Myotis(MyotisReply::Read {
            payload,
            block_before: None,
            block_after: None,
        }),
    );
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Budget));
    assert!(world.machine.state_tables().myotis_slots.is_empty());
}

#[test]
fn replacement_decoding_growth_counts_against_the_budget() {
    // 5,000 invalid bytes decode to 15,000 bytes of U+FFFD: over 7,000.
    let bounds = Bounds {
        request_bytes: 7_000,
        ..Bounds::default()
    };
    let mut world = World::new(
        bounds,
        &[chain(1, &["quorum"], &["a", "b", "c"], ("3", "3", "5000"))],
    );
    let id = world.submit(read(1, "eth_call", CALL), None);
    let mut body = br#"{"result":""#.to_vec();
    body.extend(vec![0xff; 5_000]);
    body.extend(br#""}"#);
    world.answer(world.rpcs()[0].0, Answer::Rpc { status: 200, body });
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Budget));
}

#[test]
fn queued_calls_count_and_admission_judges_the_new_one() {
    let bounds = Bounds {
        running: 1,
        waiting: 4,
        ..Bounds::default()
    };
    let mut world = World::new(bounds, &[chain(1, &["direct"], &["a"], ("3", "2", "5000"))]);
    let running = world.submit(read(1, "eth_call", CALL), None);
    let before = world.machine.held();
    let params = format!(
        r#"[{{"to":"0xabc","data":"0x{}"}},"latest"]"#,
        "ab".repeat(350)
    );
    let queued = world.submit(read(1, "eth_call", &params), None);
    assert_eq!(world.machine.waiting(), 1);
    // A waiting call holds its strings.
    assert!(world.machine.held() >= before + params.len());
    // The ledger is under the total, but not by enough for the new call.
    let room = bounds.total_bytes - world.machine.held();
    world.machine.set_output_backlog(room - params.len() / 2);
    let refused = world.submit(read(1, "eth_call", &params), None);
    assert_eq!(protocol(world.reply(refused)), Some(Protocol::Busy));
    // Its charge goes with it.
    world.machine.set_output_backlog(0);
    assert!(world.machine.cancel(queued));
    world.collect();
    assert_eq!(world.machine.held(), before);
    assert!(!world.replied(running));
}

#[test]
fn an_expired_call_starts_nothing() {
    for call in [read(1, "eth_call", CALL), Call::FeeQuote { chain_id: 1 }] {
        let mut world = World::new(
            Bounds::default(),
            &[chain(1, &["direct"], &["a"], ("3", "2", "5000"))],
        );
        // A configuration change: the reply carries the chain's generation.
        let mut changed = chain(1, &["direct"], &["b"], ("3", "2", "5000"));
        changed.display_name = "Changed".into();
        let generations = world.machine.configure(&[changed]);
        let id = world.submit(call, Some(0));
        let reply = world.reply(id);
        assert_eq!(protocol(reply), Some(Protocol::Deadline));
        assert_eq!(Some(&reply.generation), generations.get(&1));
        assert_ne!(reply.generation, 0);
        assert!(world.requests.is_empty(), "{:?}", world.requests);
    }
}

#[test]
fn a_broadcast_starts_no_attempt_at_its_cutoff() {
    let mut config = chain(1, &["direct"], &["a", "b", "c"], ("3", "2", "5000"));
    config.broadcast_order = vec!["direct".into()];
    let bounds = Bounds {
        deadline_ms: 15_000,
        ..Bounds::default()
    };
    let mut world = World::new(bounds, &[config]);
    world.submit(send(), None);
    world.run(5_000);
    let sends = world
        .rpcs()
        .into_iter()
        .filter(|r| r.3 == "eth_sendRawTransaction")
        .count();
    assert_eq!(sends, 1);
}

#[test]
fn a_read_asks_nothing_more_at_its_deadline() {
    let mut world = World::new(
        Bounds::default(),
        &[chain(1, &["direct"], &["a", "b"], ("3", "2", "5000"))],
    );
    let id = world.submit(read(1, "eth_call", CALL), Some(5_000));
    world.run(5_000);
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Deadline));
    assert_eq!(world.rpcs().len(), 1);
}

#[test]
fn an_rpc_answer_over_its_cap_is_too_large_whatever_the_budget() {
    let bounds = Bounds {
        answer_bytes: 100,
        ..Bounds::default()
    };
    let mut world = World::new(bounds, &[chain(1, &["direct"], &["a"], ("3", "2", "5000"))]);
    let id = world.submit(read(1, "eth_call", CALL), None);
    world.answer(world.rpcs()[0].0, ok(&format!("\"{}\"", "a".repeat(200))));
    match &world.reply(id).result {
        Err(ChainError::Thrown(error)) => {
            assert_eq!(
                error.message.to_string_lossy(),
                "The RPC answer is too large"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_broadcast_answers_index_counts_and_ends_through_the_outcome_table() {
    // Under 2,500 bytes of body, but some 9,600 bytes of index: the attempt
    // was made, so the outcome is uncertain, never a refusal.
    let bounds = Bounds {
        request_bytes: 5_000,
        ..Bounds::default()
    };
    let mut world = World::new(bounds, &[broadcaster(&["direct"], &["a"])]);
    let id = world.submit(send(), None);
    let data = format!("[{}]", vec!["0"; 1_200].join(","));
    let body = format!(r#"{{"error":{{"code":-32000,"message":"nonce too low","data":{data}}}}}"#);
    assert!(body.len() < 5_000);
    world.answer(
        world.rpcs()[0].0,
        Answer::Rpc {
            status: 200,
            body: exact(body),
        },
    );
    // Ended at once by its budget, with no reconciliation: the attempt is
    // outstanding.
    assert_eq!(outcome(world.reply(id)).0, BroadcastOutcome::Uncertain);
    assert_eq!(world.reply(id).settled, 0);
    assert_eq!(world.rpcs().len(), 1);
}

#[test]
fn a_quorum_answers_index_counts_against_the_budget() {
    let bounds = Bounds {
        request_bytes: 5_000,
        ..Bounds::default()
    };
    let mut world = World::new(
        bounds,
        &[chain(1, &["quorum"], &["a", "b", "c"], ("3", "2", "5000"))],
    );
    let id = world.submit(read(1, "eth_call", CALL), None);
    let result = format!("[{}]", vec!["0"; 1_200].join(","));
    world.answer(world.rpcs()[0].0, ok(&result));
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Budget));
}

#[test]
fn the_replys_copy_of_a_result_counts_against_the_budget() {
    let result = format!("\"0x{}\"", "ab".repeat(1_500));
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#).len();
    let base = standing(&["direct"], CALL);
    // Room for the answer, but not for the answer and the reply's copy.
    for (extra, fits) in [(result.len() / 2, false), (result.len() + 512, true)] {
        let bounds = Bounds {
            request_bytes: base + body + extra,
            ..Bounds::default()
        };
        let mut world = World::new(bounds, &[chain(1, &["direct"], &["a"], ("3", "2", "5000"))]);
        let id = world.submit(read(1, "eth_call", CALL), None);
        world.answer(world.rpcs()[0].0, ok(&result));
        if fits {
            assert_eq!(self::result(world.reply(id)), Some(result.as_str()));
        } else {
            assert_eq!(protocol(world.reply(id)), Some(Protocol::Budget));
        }
    }
}

#[test]
fn adaptive_route_keys_are_bounded_in_bytes() {
    // Eight timed-out interactive reads, each with 100 addresses: the keys
    // keep a digest of the list, not the list.
    let mut world = World::new(
        Bounds::default(),
        &[chain(1, &["quorum"], &["a", "b", "c"], ("3", "2", "5000"))],
    );
    let addresses: Vec<String> = (0..100).map(|n| format!("\"0x{n:040x}\"")).collect();
    let params = format!(r#"[{{"address":[{}]}}]"#, addresses.join(","));
    for i in 0..8 {
        let origin = format!("https://app{i}.example");
        world.submit(interactive("eth_getLogs", &params, &origin), None);
        let now = world.machine.now();
        let ios: Vec<u64> = world
            .rpcs()
            .into_iter()
            .filter(|r| r.1 == now)
            .map(|r| r.0)
            .collect();
        for io in ios {
            world.answer(io, Answer::Failed(Transport::Timeout));
        }
    }
    let adaptive = world.machine.state_tables().adaptive;
    assert_eq!(adaptive.len(), 8);
    for (key, _) in &adaptive {
        assert!(key.len() < 160, "{key}");
        assert!(key.contains("\"sha256:"), "{key}");
    }
}

#[test]
fn every_terminal_path_keeps_a_possibly_sent_broadcast_uncertain() {
    for termination in ["cancel", "configure", "budget", "deadline"] {
        let bounds = Bounds {
            request_bytes: 1_000,
            ..Bounds::default()
        };
        let config = broadcaster(&["direct"], &["a"]);
        let mut world = World::new(bounds, std::slice::from_ref(&config));
        let id = world.submit(send(), None);
        match termination {
            "cancel" => {
                world.machine.cancel(id);
                world.collect();
            }
            "configure" => {
                let mut next = config;
                next.display_name = "changed".into();
                world.machine.configure(&[next]);
                world.collect();
            }
            "budget" => {
                let body = vec![b'a'; 2_000];
                world.answer(world.rpcs()[0].0, Answer::Rpc { status: 200, body });
            }
            _ => world.run(120_000),
        }
        assert_eq!(
            outcome(world.reply(id)).0,
            BroadcastOutcome::Uncertain,
            "{termination}"
        );
    }
}

#[test]
fn reconciliation_never_refuses() {
    for answer in [
        node_error(-32000, "nonce too low"),
        ok("null"),
        ok(r#"{"hash":"0x1234"}"#),
    ] {
        let mut world = World::new(Bounds::default(), &[broadcaster(&["direct"], &["a"])]);
        let id = world.submit(send(), None);
        world.run(5_000);
        let lookup = world.rpcs().last().unwrap().0;
        world.answer(lookup, answer);
        assert_eq!(outcome(world.reply(id)).0, BroadcastOutcome::Uncertain);
    }
}

// ---------------------------------------------------------------------------
// The safety review's second round (PR #55).

#[test]
fn a_myotis_waiter_that_ends_gives_its_place_up() {
    // A waiter dropped with its request leaves the queue at once, and the
    // slot passes on when the read in flight ends.
    for reason in ["cancel", "configure", "deadline"] {
        let config = chain(1, &["myotis"], &["a"], ("3", "2", "5000"));
        let mut world = World::new(Bounds::default(), std::slice::from_ref(&config));
        world.machine.availability(1, true);
        world.submit(read(1, "eth_call", CALL), None);
        let io = world.requests[0].0;
        let waiter = world.submit(read(1, "eth_call", CALL), Some(1_000));
        assert_eq!(world.machine.state_tables().myotis_slots, vec![(1, 1, 1)]);
        match reason {
            "cancel" => {
                world.machine.cancel(waiter);
                world.collect();
            }
            "configure" => {
                let mut next = config;
                next.display_name = "Changed".into();
                world.machine.configure(&[next]);
                world.collect();
            }
            _ => world.run(1_000),
        }
        assert!(world.replied(waiter), "{reason}");
        assert_eq!(
            world.machine.state_tables().myotis_slots,
            vec![(1, 1, 0)],
            "{reason}"
        );
        world.answer(io, Answer::Myotis(MyotisReply::Failure(MyotisClass::Error)));
        assert!(
            world.machine.state_tables().myotis_slots.is_empty(),
            "{reason}"
        );
        // The next read takes the slot at once.
        let before = world.requests.len();
        world.submit(read(1, "eth_call", CALL), None);
        assert!(
            matches!(
                world.requests.get(before),
                Some((_, _, Request::Verified(VerifiedOp::MyotisRead { .. }), _))
            ),
            "{reason}"
        );
    }
}

#[test]
fn a_myotis_slot_granted_to_a_request_over_its_budget_passes_on() {
    // The waiter is granted the slot, then crosses the total budget
    // reserving its operation's copy of its call: the slot is freed with
    // it, never dispatched.
    let bounds = Bounds::default();
    let mut world = World::new(bounds, &[chain(1, &["myotis"], &["a"], ("3", "2", "5000"))]);
    world.machine.availability(1, true);
    let first = world.submit(read(1, "eth_call", CALL), None);
    let io = world.requests[0].0;
    let large = format!(
        r#"[{{"to":"0xabc","data":"0x{}"}},"latest"]"#,
        "ab".repeat(2_000)
    );
    let waiter = world.submit(read(1, "eth_call", &large), None);
    assert_eq!(world.machine.state_tables().myotis_slots, vec![(1, 1, 1)]);
    // Unwritten output leaves 3,000 bytes of the total: room for the first
    // read's answer and its work, not for the waiter's 4 KB call copy.
    world
        .machine
        .set_output_backlog(bounds.total_bytes - world.machine.held() - 3_000);
    world.answer(
        io,
        Answer::Myotis(MyotisReply::Read {
            payload: r#"{"result_hex":"0x1"}"#.into(),
            block_before: None,
            block_after: None,
        }),
    );
    assert_eq!(result(world.reply(first)), Some(r#""0x1""#));
    assert_eq!(protocol(world.reply(waiter)), Some(Protocol::Budget));
    assert_eq!(world.requests.len(), 1);
    assert!(world.machine.state_tables().myotis_slots.is_empty());
}

#[test]
fn a_broadcast_answer_stays_charged_while_its_error_is_copied() {
    // The body and the copy of its error's 3,000-byte data coexist: over
    // 5,000 together, though each fits. The attempt is outstanding, so the
    // outcome is uncertain, never a refusal.
    let bounds = Bounds {
        request_bytes: 5_000,
        ..Bounds::default()
    };
    let mut world = World::new(bounds, &[broadcaster(&["direct"], &["a"])]);
    let id = world.submit(send(), None);
    let data = format!("\"0x{}\"", "ab".repeat(1_500));
    let body = format!(r#"{{"error":{{"code":-32000,"message":"nonce too low","data":{data}}}}}"#);
    assert!(body.len() < 5_000);
    world.answer(
        world.rpcs()[0].0,
        Answer::Rpc {
            status: 200,
            body: exact(body),
        },
    );
    assert_eq!(outcome(world.reply(id)).0, BroadcastOutcome::Uncertain);
    assert_eq!(world.reply(id).settled, 0);
    assert_eq!(world.rpcs().len(), 1);
}

#[test]
fn a_fee_quotes_codec_work_counts_against_the_budget() {
    // Two answers kept (a gas price of 1,000 nulls, a 9,000-character
    // priority fee) fit; the codec's index of the first does not.
    let gas = format!("[{}]", vec!["null"; 1_000].join(","));
    let priority = format!("\"{}\"", "a".repeat(9_000));
    let quote = |bounds: Bounds| {
        let mut world = World::new(bounds, &[chain(1, &["direct"], &["a"], ("3", "2", "5000"))]);
        let id = world.submit(Call::FeeQuote { chain_id: 1 }, None);
        world.answer(world.rpcs()[0].0, ok(&gas));
        assert!(!world.replied(id));
        world.answer(world.rpcs()[1].0, ok(&priority));
        world.reply(id).clone()
    };
    let bounded = quote(Bounds {
        request_bytes: 15_000,
        ..Bounds::default()
    });
    assert_eq!(protocol(&bounded), Some(Protocol::Budget));
    // Within the default budget the codec's answer is today's.
    match quote(Bounds::default()).result {
        Err(ChainError::Thrown(error)) => assert!(
            error
                .message
                .to_string_lossy()
                .contains("Cannot convert ,,,"),
            "{:?}",
            error.message
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_queued_error_reply_counts_its_utf16_message() {
    let mut world = World::new(
        Bounds::default(),
        &[chain(1, &["direct"], &["a"], ("3", "2", "5000"))],
    );
    let id = world.submit(read(1, "eth_call", CALL), None);
    let io = world.rpcs()[0].0;
    assert!(
        world
            .machine
            .complete(io, node_error(-32000, &"a".repeat(3_000)))
    );
    world.machine.poll();
    assert_eq!(world.machine.running(), 0);
    // 3,000 units of UTF-16 in the queue: at least 6,000 bytes.
    assert!(world.machine.held() >= 6_000, "{}", world.machine.held());
    let replies = world.machine.take_replies();
    match &replies.iter().find(|r| r.id == id).unwrap().result {
        Err(ChainError::Thrown(error)) => assert_eq!(error.message.len(), 3_000),
        other => panic!("{other:?}"),
    }
    world.machine.set_output_backlog(0);
    assert_eq!(world.machine.held(), 0);
}

// ---------------------------------------------------------------------------
// The safety review's third round (PR #55). The hash and fee conversion
// peaks are measured in their own processes: `tests/peak_hash.rs`,
// `tests/peak_fee.rs`.

#[test]
fn a_node_errors_message_holds_what_was_reserved_for_it() {
    // The message is built in a buffer of exactly its length: the
    // reservation, its length in UTF-16, covers what it holds.
    let message = "a".repeat(131_073);
    let body = format!(r#"{{"error":{{"code":-32000,"message":"{message}"}}}}"#);
    let decoded = fc_chain::decode_answer(200, body.into_bytes()).unwrap();
    let fc_chain::Outcome::NodeError(error) = decoded.outcome() else {
        panic!("not a node error");
    };
    assert_eq!(error.message.len(), 131_073);
    assert_eq!(error.message.heap_bytes(), 2 * error.message.len());
}

#[test]
fn an_oversized_hash_answer_stays_ambiguous() {
    // A result of "0x" and 4 MiB of hex is another hash, read without
    // copies: the attempt is ambiguous and the core reconciles.
    let mut world = World::new(Bounds::default(), &[broadcaster(&["direct"], &["a"])]);
    let id = world.submit(send(), None);
    world.answer(
        world.rpcs()[0].0,
        ok(&format!("\"0x{}\"", "a".repeat(4 * 1024 * 1024))),
    );
    assert!(!world.replied(id));
    let lookup = world.rpcs()[1].clone();
    assert_eq!(lookup.3, "eth_getTransactionByHash");
    world.answer(lookup.0, ok("null"));
    assert_eq!(
        outcome(world.reply(id)),
        (BroadcastOutcome::Uncertain, Some("direct"))
    );
}

// ---------------------------------------------------------------------------
// fee-combination (design 0005, B: combining Direct's quotes): the
// collection's machine tests, `boundary-fee-combine-*`.

/// A chain for B: `read` order, endpoints `rpc`, `configured` 5 s, and a
/// prover when `prover`.
fn fee_chain(read: &[&str], rpc: &[&str], prover: bool) -> ChainConfig {
    ChainConfig {
        prover: prover.then(|| Prover {
            endpoint: "p".into(),
            zk: true,
        }),
        ..chain(1, read, rpc, ("3", "2", "5000"))
    }
}

const FEE: Call = Call::FeeQuote { chain_id: 1 };

/// A legacy endpoint's answer to the hint: the node doesn't know it.
fn no_hint() -> Answer {
    node_error(-32601, "the method eth_maxPriorityFeePerGas does not exist")
}

fn eip1559(base_fee: &str, priority: &str, max_fee: &str, effective: &str, answered: u8) -> String {
    format!(
        r#"{{"type":"eip1559","baseFee":"{base_fee}","maxPriorityFeePerGas":"{priority}","maxFeePerGas":"{max_fee}","effectiveGasPrice":"{effective}","source":"direct","verified":false,"answered":{answered}}}"#
    )
}

fn legacy(gas_price: &str, answered: u8) -> String {
    format!(
        r#"{{"type":"legacy","gasPrice":"{gas_price}","effectiveGasPrice":"{gas_price}","source":"direct","verified":false,"answered":{answered}}}"#
    )
}

fn quote_json(reply: &Reply) -> String {
    match &reply.result {
        Ok(Success::FeeQuote(quote)) => quote.to_json(),
        other => panic!("{other:?}"),
    }
}

/// A verified header with `base_fee` (hex), or none.
fn header(base_fee: Option<&str>) -> Answer {
    let base_fee = base_fee.map_or_else(String::new, |fee| format!(r#","baseFeePerGas":"{fee}""#));
    Answer::Colibri(ColibriReply::Result(format!(
        r#"{{"number":"0x1312d00","timestamp":"0x6553f100","hash":"0xab"{base_fee}}}"#
    )))
}

/// What a combined EIP-1559 quote pays per gas at `base_fee`:
/// min(M, base fee + P).
fn pays(quote: &str, base_fee: u128) -> u128 {
    let value: serde_json::Value = serde_json::from_str(quote).unwrap();
    let field = |key: &str| value[key].as_str().unwrap().parse::<u128>().unwrap();
    match value["type"].as_str().unwrap() {
        "eip1559" => field("maxFeePerGas").min(base_fee + field("maxPriorityFeePerGas")),
        _ => field("gasPrice"),
    }
}

impl World {
    /// The io id of the latest `method` exchange with `endpoint`.
    fn rpc_to(&self, endpoint: &str, method: &str) -> u64 {
        self.rpcs()
            .iter()
            .rev()
            .find(|(_, _, e, m)| e == endpoint && m == method)
            .map(|(id, ..)| *id)
            .unwrap_or_else(|| panic!("no {method} to {endpoint}"))
    }

    /// The `(endpoint, method, at)` of every exchange, in order.
    fn asked(&self) -> Vec<(String, String, u64)> {
        self.rpcs()
            .into_iter()
            .map(|(_, at, endpoint, method)| (endpoint, method, at))
            .collect()
    }

    /// The verified header reads: `(io id, at)`.
    fn header_reads(&self) -> Vec<(u64, u64)> {
        self.requests
            .iter()
            .filter_map(|(id, at, request, _)| match request {
                Request::Verified(VerifiedOp::Colibri { method, params, .. })
                    if method == "eth_getBlockByNumber" =>
                {
                    assert_eq!(params, r#"["latest",false]"#);
                    Some((*id, *at))
                }
                _ => None,
            })
            .collect()
    }

    /// Answers `endpoint`'s gas price, then its hint (`None`: it has none).
    fn quote_from(&mut self, endpoint: &str, gas: &str, priority: Option<&str>) {
        self.answer(
            self.rpc_to(endpoint, "eth_gasPrice"),
            ok(&format!("\"{gas}\"")),
        );
        let hint = self.rpc_to(endpoint, "eth_maxPriorityFeePerGas");
        self.answer(
            hint,
            priority.map_or_else(no_hint, |p| ok(&format!("\"{p}\""))),
        );
    }
}

#[test]
fn boundary_fee_combine_three_successes() {
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["direct"], &["a", "b", "c", "d"], false)],
    );
    let id = world.submit(FEE, None);
    // The first three start together; the fourth is never asked.
    let started: Vec<_> = world.asked();
    assert_eq!(
        started,
        ["a", "b", "c"].map(|e| (e.to_owned(), "eth_gasPrice".to_owned(), 0))
    );
    world.quote_from("a", "0x64", Some("0xa"));
    world.quote_from("b", "0x78", Some("0x5"));
    assert!(!world.replied(id));
    world.quote_from("c", "0x6e", Some("0x14"));
    // M: 190, 235, 200; P: 10, 5, 20.
    assert_eq!(
        quote_json(world.reply(id)),
        eip1559("92", "5", "190", "97", 3)
    );
    assert_eq!(world.reply(id).settled, 0);
    assert!(world.asked().iter().all(|(e, ..)| e != "d"));
    assert!(world.cancels.is_empty());
}

#[test]
fn boundary_fee_combine_independent_minima() {
    for (answers, want) in [
        // M − P odd: 10/1 with 10/2 combine to M = 18, P = 1.
        (
            [("0xa", "0x1"), ("0xa", "0x2")],
            eip1559("8", "1", "18", "9", 2),
        ),
        // The raw-minima trap: 100/10 with 100/9 gives M = 190, not 191.
        (
            [("0x64", "0xa"), ("0x64", "0x9")],
            eip1559("90", "9", "190", "99", 2),
        ),
    ] {
        let mut world = World::new(
            Bounds::default(),
            &[fee_chain(&["direct"], &["a", "b"], false)],
        );
        let id = world.submit(FEE, None);
        world.quote_from("a", answers[0].0, Some(answers[0].1));
        world.quote_from("b", answers[1].0, Some(answers[1].1));
        assert_eq!(quote_json(world.reply(id)), want);
    }
}

#[test]
fn boundary_fee_combine_all_legacy() {
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["direct", "colibri"], &["a", "b", "c"], true)],
    );
    let id = world.submit(FEE, None);
    world.quote_from("a", "0x10", None);
    // A hint above the gas price, and a negative one, give legacy quotes.
    world.quote_from("b", "0xc", Some("0xd"));
    world.quote_from("c", "0x14", Some("-1"));
    // All legacy: the lowest gas price, without waiting for the header.
    assert_eq!(quote_json(world.reply(id)), legacy("12", 3));
    assert_eq!(world.header_reads().len(), 1);
}

#[test]
fn boundary_fee_combine_mixed_with_a_verified_header() {
    // The boundary case: an EIP-1559 100/1 (M = 199) and a legacy 1000.
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["direct", "colibri"], &["a", "b"], true)],
    );
    let id = world.submit(FEE, None);
    // The header read starts with the collection, after its first
    // exchanges.
    let reads = world.header_reads();
    assert_eq!(reads.len(), 1);
    assert_eq!(world.requests.last().map(|r| r.0), Some(reads[0].0));
    world.quote_from("a", "0x64", Some("0x1"));
    world.quote_from("b", "0x3e8", None);
    // Mixed: the combination waits for the header, which arrives after the
    // collection ended.
    world.run(300);
    assert!(!world.replied(id));
    world.answer(reads[0].0, header(Some("0x7")));
    let reply = world.reply(id);
    assert_eq!(reply.settled, 300);
    let quote = quote_json(reply);
    assert_eq!(quote, eip1559("99", "1", "199", "100", 2));
    // If the base fee falls to 1, it pays 2 per gas, as the honest one would.
    assert_eq!(pays(&quote, 1), 2);
    // Any base fee shows EIP-1559, zero and 256 bits included.
    let widest = format!("0x{}", "f".repeat(64));
    for base_fee in ["0x0", widest.as_str()] {
        let mut world = World::new(
            Bounds::default(),
            &[fee_chain(&["direct", "colibri"], &["a", "b"], true)],
        );
        let id = world.submit(FEE, None);
        world.quote_from("a", "0x64", Some("0x1"));
        world.quote_from("b", "0x3e8", None);
        world.answer(world.header_reads()[0].0, header(Some(base_fee)));
        assert_eq!(
            quote_json(world.reply(id)),
            eip1559("99", "1", "199", "100", 2),
            "{base_fee}"
        );
    }
}

#[test]
fn boundary_fee_combine_mixed_without_a_verified_header() {
    // The boundary case without a verified header: legacy G = 100, which
    // pays 100 at a base fee of 1.
    let malformed = [
        // A base fee with a leading zero, an upper-case digit, a number
        // that is no quantity, and no header at all.
        r#"{"number":"0x10","timestamp":"0x10","baseFeePerGas":"0x07"}"#,
        r#"{"number":"0x10","timestamp":"0x10","baseFeePerGas":"0xA"}"#,
        r#"{"number":16,"timestamp":"0x10","baseFeePerGas":"0x7"}"#,
        r#"{"number":"0x10","baseFeePerGas":"0x7"}"#,
        r#"{"number":"0x10","timestamp":"0x10","baseFeePerGas":null}"#,
        // Wider than 256 bits, and a number wider than 64.
        r#"{"number":"0x10","timestamp":"0x10","baseFeePerGas":"0x10000000000000000000000000000000000000000000000000000000000000000"}"#,
        r#"{"number":"0x10000000000000000","timestamp":"0x10","baseFeePerGas":"0x7"}"#,
        "null",
        r#"["0x7"]"#,
    ];
    let mut cases: Vec<(ChainConfig, Option<Answer>)> = vec![
        // No prover: no header is read.
        (fee_chain(&["direct", "colibri"], &["a", "b"], false), None),
        // Colibri out of the read order.
        (fee_chain(&["direct"], &["a", "b"], true), None),
        // A failed header.
        (
            fee_chain(&["direct", "colibri"], &["a", "b"], true),
            Some(Answer::Colibri(ColibriReply::Failure(
                fc_chain::machine::ColibriClass::Error,
            ))),
        ),
        // `undefined`.
        (
            fee_chain(&["direct", "colibri"], &["a", "b"], true),
            Some(Answer::Colibri(ColibriReply::Undefined)),
        ),
        // A header without a base fee: a chain without EIP-1559.
        (
            fee_chain(&["direct", "colibri"], &["a", "b"], true),
            Some(header(None)),
        ),
    ];
    for text in malformed {
        cases.push((
            fee_chain(&["direct", "colibri"], &["a", "b"], true),
            Some(Answer::Colibri(ColibriReply::Result(text.into()))),
        ));
    }
    for (config, answer) in cases {
        let mut world = World::new(Bounds::default(), &[config]);
        let id = world.submit(FEE, None);
        world.quote_from("a", "0x64", Some("0x1"));
        world.quote_from("b", "0x3e8", None);
        match answer {
            None => assert!(world.header_reads().is_empty()),
            Some(answer) => {
                assert!(!world.replied(id));
                world.answer(world.header_reads()[0].0, answer);
            }
        }
        let quote = quote_json(world.reply(id));
        assert_eq!(quote, legacy("100", 2));
        assert_eq!(pays(&quote, 1), 100);
    }
}

#[test]
fn boundary_fee_combine_mixed_waits_for_the_header_within_colibris_budget() {
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["direct", "colibri"], &["a", "b"], true)],
    );
    let id = world.submit(FEE, None);
    world.quote_from("a", "0x64", Some("0x1"));
    world.quote_from("b", "0x3e8", None);
    // Colibri's budget is `configured`: at 5 s the header has failed, and
    // the quote is legacy. The operation keeps its slot until main's reply.
    world.run(4_999);
    assert!(!world.replied(id));
    world.run(5_000);
    assert_eq!(world.reply(id).settled, 5_000);
    assert_eq!(quote_json(world.reply(id)), legacy("100", 2));
    assert_eq!(world.machine.state_tables().colibri_in_flight, 1);
    let (read, _) = world.header_reads()[0];
    assert!(!world.machine.wants(read));
    world.machine.complete_unread(read);
    world.collect();
    assert_eq!(world.machine.state_tables().colibri_in_flight, 0);
}

#[test]
fn boundary_fee_combine_header_dropped_when_not_mixed() {
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["direct", "colibri"], &["a", "b"], true)],
    );
    let id = world.submit(FEE, None);
    world.quote_from("a", "0x64", Some("0xa"));
    world.quote_from("b", "0x64", Some("0x9"));
    // All EIP-1559: nothing waits for the header.
    assert_eq!(world.reply(id).settled, 0);
    assert_eq!(
        quote_json(world.reply(id)),
        eip1559("90", "9", "190", "99", 2)
    );
    // Its operation keeps its slot until main's reply, which is dropped.
    assert_eq!(world.machine.state_tables().colibri_in_flight, 1);
    let (read, _) = world.header_reads()[0];
    world.run(200);
    assert!(!world.machine.wants(read));
    world.answer(read, header(Some("0x1")));
    assert_eq!(world.machine.state_tables().colibri_in_flight, 0);
    assert_eq!(world.replies.iter().filter(|r| r.id == id).count(), 1);
}

#[test]
fn boundary_fee_combine_header_with_colibri_first_in_the_order() {
    // Today's default order, Myotis not ready: Colibri's own quote fails,
    // then Direct's collection reads the header.
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(
            &["myotis", "colibri", "direct"],
            &["a", "b"],
            true,
        )],
    );
    let id = world.submit(FEE, None);
    let gas = world
        .requests
        .iter()
        .find_map(|(io, _, request, _)| match request {
            Request::Verified(VerifiedOp::Colibri { method, .. }) if method == "eth_gasPrice" => {
                Some(*io)
            }
            _ => None,
        })
        .unwrap();
    world.answer(
        gas,
        Answer::Colibri(ColibriReply::Failure(
            fc_chain::machine::ColibriClass::Error,
        )),
    );
    assert_eq!(world.header_reads().len(), 1);
    world.quote_from("a", "0x64", Some("0x1"));
    world.quote_from("b", "0x3e8", None);
    world.answer(world.header_reads()[0].0, header(Some("0x1")));
    assert_eq!(
        quote_json(world.reply(id)),
        eip1559("99", "1", "199", "100", 2)
    );
}

#[test]
fn boundary_fee_combine_partial_failures() {
    // One fails after another answered: no replacement, two combine.
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["direct"], &["a", "b", "c", "d"], false)],
    );
    let id = world.submit(FEE, None);
    world.quote_from("b", "0x64", Some("0xa"));
    world.answer(
        world.rpc_to("a", "eth_gasPrice"),
        Answer::Rpc {
            status: 500,
            body: Vec::new(),
        },
    );
    world.quote_from("c", "0x78", Some("0x5"));
    assert_eq!(
        quote_json(world.reply(id)),
        eip1559("92", "5", "190", "97", 2)
    );
    assert!(world.asked().iter().all(|(e, ..)| e != "d"));

    // A failure before any answer is replaced by the next endpoint.
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["direct"], &["a", "b", "c", "d"], false)],
    );
    let id = world.submit(FEE, None);
    world.run(100);
    world.answer(
        world.rpc_to("a", "eth_gasPrice"),
        node_error(-32000, "a is down"),
    );
    assert_eq!(
        world.asked().last(),
        Some(&("d".to_owned(), "eth_gasPrice".to_owned(), 100))
    );
    world.quote_from("b", "0x64", Some("0xa"));
    world.quote_from("c", "0x78", Some("0x5"));
    world.quote_from("d", "0x6e", Some("0x14"));
    assert_eq!(
        quote_json(world.reply(id)),
        eip1559("92", "5", "190", "97", 3)
    );

    // An unparseable hint fails its endpoint (today's codec); the others
    // combine.
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["direct"], &["a", "b", "c"], false)],
    );
    let id = world.submit(FEE, None);
    world.quote_from("b", "0x64", Some("0xa"));
    world.quote_from("a", "0x10", Some("-0x1"));
    world.quote_from("c", "0x64", Some("0x9"));
    assert_eq!(
        quote_json(world.reply(id)),
        eip1559("90", "9", "190", "99", 2)
    );
}

#[test]
fn boundary_fee_combine_all_failing_with_the_last_error() {
    // Every endpoint is reached, as today's walk does: a, b, c at once,
    // then d and e as failures replace them.
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["direct"], &["a", "b", "c", "d", "e"], false)],
    );
    let id = world.submit(FEE, None);
    world.answer(
        world.rpc_to("a", "eth_gasPrice"),
        node_error(-32000, "a down"),
    );
    world.answer(
        world.rpc_to("b", "eth_gasPrice"),
        node_error(-32000, "b down"),
    );
    world.run(100);
    world.answer(
        world.rpc_to("d", "eth_gasPrice"),
        node_error(-32000, "d down"),
    );
    world.run(200);
    // In one tick, the higher registry index's error is the last: e's,
    // though c's arrives after it.
    world.answer(
        world.rpc_to("e", "eth_gasPrice"),
        node_error(-32000, "e down"),
    );
    world.answer(
        world.rpc_to("c", "eth_gasPrice"),
        node_error(-32000, "c down"),
    );
    let asked: Vec<_> = world
        .asked()
        .into_iter()
        .map(|(e, _, at)| (e, at))
        .collect();
    assert_eq!(
        asked,
        [("a", 0), ("b", 0), ("c", 0), ("d", 0), ("e", 0)].map(|(e, at)| (e.to_owned(), at))
    );
    let reply = world.reply(id);
    assert_eq!(reply.settled, 200);
    match &reply.result {
        Err(ChainError::Thrown(error)) => {
            assert_eq!(error.message.to_string_lossy(), "e down");
            assert_eq!(error.origin, fc_chain::machine::Origin::Node);
        }
        other => panic!("{other:?}"),
    }

    // With no endpoint, today's text, and no header read: the next source,
    // Colibri, is asked for its own quote.
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["direct", "colibri"], &[], true)],
    );
    let id = world.submit(FEE, None);
    assert!(world.header_reads().is_empty());
    let (gas, request) = match &world.requests[..] {
        [(io, _, request, _)] => (*io, request.clone()),
        other => panic!("{other:?}"),
    };
    assert!(
        matches!(&request, Request::Verified(VerifiedOp::Colibri { method, .. }) if method == "eth_gasPrice")
    );
    world.answer(
        gas,
        Answer::Colibri(ColibriReply::Failure(
            fc_chain::machine::ColibriClass::Error,
        )),
    );
    assert!(world.header_reads().is_empty());
    match &world.reply(id).result {
        Err(ChainError::Thrown(error)) => assert_eq!(
            error.message.to_string_lossy(),
            fc_chain::machine::COLIBRI_FAILED
        ),
        other => panic!("{other:?}"),
    }
    let mut world = World::new(Bounds::default(), &[fee_chain(&["direct"], &[], false)]);
    let id = world.submit(FEE, None);
    match &world.reply(id).result {
        Err(ChainError::Thrown(error)) => assert_eq!(
            error.message.to_string_lossy(),
            "All chain sources failed for fee quote (direct: No RPC endpoint configured)"
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn boundary_fee_combine_singletons() {
    // One endpoint configured: today's quote, marked.
    let mut world = World::new(Bounds::default(), &[fee_chain(&["direct"], &["a"], false)]);
    let id = world.submit(FEE, None);
    world.quote_from("a", "0x64", Some("0xa"));
    assert_eq!(world.reply(id).settled, 0);
    assert_eq!(
        quote_json(world.reply(id)),
        eip1559("90", "10", "190", "100", 1)
    );

    // One of three answering: the others are cut off at 1 s.
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["direct"], &["a", "b", "c"], false)],
    );
    let id = world.submit(FEE, None);
    world.run(200);
    world.quote_from("b", "0x10", None);
    world.run(1_199);
    assert!(!world.replied(id));
    world.run(1_200);
    assert_eq!(world.reply(id).settled, 1_200);
    assert_eq!(quote_json(world.reply(id)), legacy("16", 1));
    for endpoint in ["a", "c"] {
        let io = world.rpc_to(endpoint, "eth_gasPrice");
        assert_eq!(world.cancelled(io), Some(1_200), "{endpoint}");
    }
}

#[test]
fn boundary_fee_combine_cutoff() {
    // The first quote answers at 100: the collection ends at 1,100.
    let start = |world: &mut World| {
        let id = world.submit(FEE, None);
        world.run(100);
        world.quote_from("a", "0x64", Some("0xa"));
        world.run(500);
        world.quote_from("b", "0x64", Some("0x9"));
        id
    };
    let chains = [fee_chain(&["direct"], &["a", "b", "c"], false)];

    // A third answer after it: cancelled at the cutoff, and left out.
    let mut world = World::new(Bounds::default(), &chains);
    let id = start(&mut world);
    world.run(1_100);
    assert_eq!(world.reply(id).settled, 1_100);
    assert_eq!(
        quote_json(world.reply(id)),
        eip1559("90", "9", "190", "99", 2)
    );
    let late = world.rpc_to("c", "eth_gasPrice");
    assert_eq!(world.cancelled(late), Some(1_100));
    world.run(1_101);
    assert!(!world.answer(late, ok("\"0x1\"")));

    // An endpoint whose hint is outstanding at the cutoff is left out.
    let mut world = World::new(Bounds::default(), &chains);
    let id = start(&mut world);
    world.run(600);
    world.answer(world.rpc_to("c", "eth_gasPrice"), ok("\"0x1\""));
    world.run(1_100);
    assert_eq!(
        quote_json(world.reply(id)),
        eip1559("90", "9", "190", "99", 2)
    );
    let hint = world.rpc_to("c", "eth_maxPriorityFeePerGas");
    assert_eq!(world.cancelled(hint), Some(1_100));

    // An answer in its tick is left out: the cutoff goes first, whichever
    // the driver hands over first.
    let mut world = World::new(Bounds::default(), &chains);
    let id = start(&mut world);
    world.run(600);
    world.answer(world.rpc_to("c", "eth_gasPrice"), ok("\"0x1\""));
    world.run(1_099);
    // The clock reaches the cutoff; c's hint is delivered before the
    // machine runs.
    assert!(world.machine.fire_next(1_100).is_some());
    assert_eq!(world.machine.now(), 1_100);
    let hint = world.rpc_to("c", "eth_maxPriorityFeePerGas");
    world.answer(hint, ok("\"0x1\""));
    assert_eq!(world.reply(id).settled, 1_100);
    assert_eq!(
        quote_json(world.reply(id)),
        eip1559("90", "9", "190", "99", 2)
    );
}

#[test]
fn boundary_fee_combine_races() {
    let chains = [fee_chain(&["direct", "colibri"], &["a", "b", "c"], true)];
    let outstanding = |world: &World| -> Vec<u64> {
        world
            .requests
            .iter()
            .filter(|(_, _, request, _)| matches!(request, Request::Rpc { .. }))
            .map(|(io, ..)| *io)
            .collect()
    };

    // The deadline, with exchanges outstanding: every one is cancelled.
    let mut world = World::new(Bounds::default(), &chains);
    let id = world.submit(FEE, Some(700));
    world.quote_from("a", "0x64", Some("0xa"));
    world.answer(world.rpc_to("b", "eth_gasPrice"), ok("\"0x64\""));
    world.run(700);
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Deadline));
    assert_eq!(world.reply(id).settled, 700);
    let hint = world.rpc_to("b", "eth_maxPriorityFeePerGas");
    let c = world.rpc_to("c", "eth_gasPrice");
    assert_eq!(world.cancelled(hint), Some(700));
    assert_eq!(world.cancelled(c), Some(700));
    // The header's operation keeps its slot until main's reply.
    assert_eq!(world.machine.state_tables().colibri_in_flight, 1);

    // A cancel.
    let mut world = World::new(Bounds::default(), &chains);
    let id = world.submit(FEE, None);
    world.quote_from("a", "0x64", Some("0xa"));
    world.run(300);
    assert!(world.machine.cancel(id));
    world.collect();
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Cancelled));
    assert_eq!(world.reply(id).settled, 300);
    for io in outstanding(&world) {
        if ![
            world.rpc_to("a", "eth_gasPrice"),
            world.rpc_to("a", "eth_maxPriorityFeePerGas"),
        ]
        .contains(&io)
        {
            assert_eq!(world.cancelled(io), Some(300));
        }
    }

    // A configuration change.
    let mut world = World::new(Bounds::default(), &chains);
    let id = world.submit(FEE, None);
    world.run(400);
    world
        .machine
        .configure(&[fee_chain(&["direct", "colibri"], &["a", "b", "d"], true)]);
    world.collect();
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Reconfigured));
    assert_eq!(world.reply(id).settled, 400);
    for io in outstanding(&world) {
        assert_eq!(world.cancelled(io), Some(400));
    }
}

// ---------------------------------------------------------------------------
// chain.fee_reference (design 0005, A: The evidence): the core's machine
// tests.

const REFERENCE: Call = Call::FeeReference { chain_id: 1 };

fn evidence(reply: &Reply) -> &FeeReference {
    match &reply.result {
        Ok(Success::FeeReference(reference)) => reference,
        other => panic!("{other:?}"),
    }
}

/// The header `header(Some(base_fee))` answers, in decimal.
fn verified_header(base_fee: Option<&str>) -> Header {
    Header {
        number: "20000000".into(),
        timestamp: "1700000000".into(),
        base_fee: base_fee.map(str::to_owned),
    }
}

fn no_myotis_operation(world: &World) -> bool {
    !world.requests.iter().any(|(_, _, request, _)| {
        matches!(request, Request::Verified(VerifiedOp::MyotisRead { .. }))
    })
}

/// Colibri asked for anything but the header (a quote's components).
fn colibri_quotes(world: &World) -> usize {
    world
        .requests
        .iter()
        .filter(|(_, _, request, _)| {
            matches!(request, Request::Verified(VerifiedOp::Colibri { method, .. })
                if method != "eth_getBlockByNumber")
        })
        .count()
}

#[test]
fn fee_reference_header_and_quotes() {
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["colibri", "direct"], &["a", "b", "c"], true)],
    );
    let id = world.submit(REFERENCE, None);
    // Both parts at once: B's first exchanges, then the header.
    assert_eq!(
        world.asked(),
        ["a", "b", "c"].map(|e| (e.to_owned(), "eth_gasPrice".to_owned(), 0))
    );
    let reads = world.header_reads();
    assert_eq!(reads, [(reads[0].0, 0)]);
    world.quote_from("a", "0x64", Some("0xa"));
    world.quote_from("b", "0x3e8", None);
    world.quote_from("c", "0x78", Some("0x5"));
    // B is done; the reply waits for the header.
    world.run(250);
    assert!(!world.replied(id));
    world.answer(reads[0].0, header(Some("0x7")));
    let reply = world.reply(id);
    assert_eq!(reply.settled, 250);
    assert_eq!(reply.generation, 1);
    let reference = evidence(reply);
    assert_eq!(reference.header, Some(verified_header(Some("7"))));
    assert_eq!(reference.lowest_priority.as_deref(), Some("5"));
    // Mixed, and this request's header has a base fee: EIP-1559.
    assert_eq!(
        reference.quote.as_ref().map(FeeQuote::to_json),
        Some(eip1559("92", "5", "190", "97", 3))
    );
    // Colibri gave only the header; nobody asked Colibri for a quote.
    assert_eq!(colibri_quotes(&world), 0);
}

#[test]
fn fee_reference_runs_past_an_earlier_sources_success() {
    // A read order that starts with Myotis, ready: a fee quote would take
    // Myotis's; the reference asks Myotis nothing, and still gets Colibri's
    // header and B's quotes, the quorum's endpoints included.
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(
            &["myotis", "colibri", "quorum", "direct"],
            &["a", "b"],
            true,
        )],
    );
    world.machine.availability(1, true);
    let id = world.submit(REFERENCE, None);
    world.quote_from("a", "0x64", Some("0xa"));
    world.quote_from("b", "0x64", Some("0x9"));
    world.answer(world.header_reads()[0].0, header(Some("0x1")));
    let reference = evidence(world.reply(id));
    assert_eq!(reference.header, Some(verified_header(Some("1"))));
    assert_eq!(reference.lowest_priority.as_deref(), Some("9"));
    assert_eq!(
        reference.quote.as_ref().map(FeeQuote::to_json),
        Some(eip1559("90", "9", "190", "99", 2))
    );
    assert!(no_myotis_operation(&world));
    assert_eq!(colibri_quotes(&world), 0);
    // The quorum, as a source, asks nothing either: one exchange pair per
    // endpoint, B's.
    assert_eq!(world.rpcs().len(), 4);
}

#[test]
fn fee_reference_without_a_header() {
    for config in [
        // No prover.
        fee_chain(&["colibri", "direct"], &["a", "b"], false),
        // Colibri out of the read order.
        fee_chain(&["myotis", "quorum", "direct"], &["a", "b"], true),
    ] {
        let mut world = World::new(Bounds::default(), &[config]);
        let id = world.submit(REFERENCE, None);
        assert!(world.header_reads().is_empty());
        world.quote_from("a", "0x64", Some("0x1"));
        world.quote_from("b", "0x3e8", None);
        let reference = evidence(world.reply(id));
        assert_eq!(reference.header, None);
        assert_eq!(reference.lowest_priority.as_deref(), Some("1"));
        // Mixed without a verified header: legacy.
        assert_eq!(
            reference.quote.as_ref().map(FeeQuote::to_json),
            Some(legacy("100", 2))
        );
        assert_eq!(world.reply(id).settled, 0);
    }
}

#[test]
fn fee_reference_without_quorum_or_direct() {
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["myotis", "colibri"], &["a", "b"], true)],
    );
    world.machine.availability(1, true);
    let id = world.submit(REFERENCE, None);
    // Only the header: no endpoint is asked.
    assert!(world.rpcs().is_empty());
    assert_eq!(world.requests.len(), 1);
    world.answer(world.header_reads()[0].0, header(Some("0x2a")));
    let reference = evidence(world.reply(id));
    assert_eq!(reference.header, Some(verified_header(Some("42"))));
    assert_eq!(reference.lowest_priority, None);
    assert_eq!(reference.quote, None);
}

#[test]
fn fee_reference_when_colibri_fails_or_is_malformed() {
    let answers = [
        Answer::Colibri(ColibriReply::Failure(
            fc_chain::machine::ColibriClass::Error,
        )),
        Answer::Colibri(ColibriReply::Undefined),
        Answer::Colibri(ColibriReply::Result("null".into())),
        Answer::Colibri(ColibriReply::Result(
            r#"{"number":"0x10","timestamp":"0x10","baseFeePerGas":"0x007"}"#.into(),
        )),
        Answer::Colibri(ColibriReply::Revert {
            data: "0x".into(),
            capacity: false,
        }),
    ];
    for answer in answers {
        let mut world = World::new(
            Bounds::default(),
            &[fee_chain(&["colibri", "direct"], &["a", "b"], true)],
        );
        let id = world.submit(REFERENCE, None);
        world.quote_from("a", "0x64", Some("0x1"));
        world.quote_from("b", "0x3e8", None);
        world.answer(world.header_reads()[0].0, answer.clone());
        let reference = evidence(world.reply(id));
        assert_eq!(reference.header, None, "{answer:?}");
        assert_eq!(
            reference.quote.as_ref().map(FeeQuote::to_json),
            Some(legacy("100", 2)),
            "{answer:?}"
        );
    }

    // Colibri's own budget: at `configured` the header has failed.
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["colibri", "direct"], &["a"], true)],
    );
    let id = world.submit(REFERENCE, None);
    world.quote_from("a", "0x64", Some("0x1"));
    world.run(4_999);
    assert!(!world.replied(id));
    world.run(5_000);
    let reference = evidence(world.reply(id));
    assert_eq!(reference.header, None);
    assert_eq!(
        reference.quote.as_ref().map(FeeQuote::to_json),
        Some(eip1559("99", "1", "199", "100", 1))
    );

    // A header without `baseFeePerGas`: a chain without EIP-1559. Mixed
    // quotes stay legacy.
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["colibri", "direct"], &["a", "b"], true)],
    );
    let id = world.submit(REFERENCE, None);
    world.quote_from("a", "0x64", Some("0x1"));
    world.quote_from("b", "0x3e8", None);
    world.answer(world.header_reads()[0].0, header(None));
    let reference = evidence(world.reply(id));
    assert_eq!(reference.header, Some(verified_header(None)));
    assert_eq!(
        reference.quote.as_ref().map(FeeQuote::to_json),
        Some(legacy("100", 2))
    );
}

#[test]
fn fee_reference_when_no_endpoint_answers() {
    // No endpoint: the header is still read; the quote is null.
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["colibri", "direct"], &[], true)],
    );
    let id = world.submit(REFERENCE, None);
    assert_eq!(world.requests.len(), 1);
    world.answer(world.header_reads()[0].0, header(Some("0x7")));
    let reference = evidence(world.reply(id));
    assert_eq!(reference.header, Some(verified_header(Some("7"))));
    assert_eq!(
        (&reference.lowest_priority, &reference.quote),
        (&None, &None)
    );

    // Every endpoint failing, and all-legacy quotes: no priority fee.
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["direct"], &["a", "b"], false)],
    );
    let id = world.submit(REFERENCE, None);
    world.answer(
        world.rpc_to("a", "eth_gasPrice"),
        node_error(-32000, "a down"),
    );
    world.answer(
        world.rpc_to("b", "eth_gasPrice"),
        node_error(-32000, "b down"),
    );
    let reference = evidence(world.reply(id));
    assert_eq!(
        *reference,
        FeeReference {
            header: None,
            lowest_priority: None,
            quote: None,
        }
    );
    let mut world = World::new(
        Bounds::default(),
        &[fee_chain(&["direct"], &["a", "b"], false)],
    );
    let id = world.submit(REFERENCE, None);
    world.quote_from("a", "0x10", None);
    world.quote_from("b", "0xc", Some("0xd"));
    let reference = evidence(world.reply(id));
    assert_eq!(reference.lowest_priority, None);
    assert_eq!(
        reference.quote.as_ref().map(FeeQuote::to_json),
        Some(legacy("12", 2))
    );
}

#[test]
fn fee_reference_races() {
    let chains = [fee_chain(&["colibri", "direct"], &["a", "b", "c"], true)];
    let rpc_ios = |world: &World| -> Vec<u64> { world.rpcs().iter().map(|r| r.0).collect() };

    // The deadline, B done and the header outstanding: the request ends
    // with `deadline`; the header's operation keeps its slot.
    let mut world = World::new(Bounds::default(), &chains);
    let id = world.submit(REFERENCE, Some(800));
    world.quote_from("a", "0x64", Some("0xa"));
    world.quote_from("b", "0x64", Some("0x9"));
    world.quote_from("c", "0x64", Some("0x8"));
    world.run(800);
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Deadline));
    assert_eq!(world.reply(id).settled, 800);
    assert_eq!(world.machine.state_tables().colibri_in_flight, 1);
    assert!(!world.machine.wants(world.header_reads()[0].0));

    // A cancel, with exchanges outstanding.
    let mut world = World::new(Bounds::default(), &chains);
    let id = world.submit(REFERENCE, None);
    world.run(100);
    assert!(world.machine.cancel(id));
    world.collect();
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Cancelled));
    for io in rpc_ios(&world) {
        assert_eq!(world.cancelled(io), Some(100));
    }

    // A configuration change ends it with `reconfigured`, under its own
    // generation.
    let mut world = World::new(Bounds::default(), &chains);
    let id = world.submit(REFERENCE, None);
    world.quote_from("a", "0x64", Some("0xa"));
    world.run(300);
    let generations =
        world
            .machine
            .configure(&[fee_chain(&["colibri", "direct"], &["a", "d"], true)]);
    world.collect();
    assert_eq!(generations.get(&1), Some(&2));
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Reconfigured));
    assert_eq!(world.reply(id).generation, 1);
    for endpoint in ["b", "c"] {
        let io = world.rpc_to(endpoint, "eth_gasPrice");
        assert_eq!(world.cancelled(io), Some(300), "{endpoint}");
    }
    // The header's operation keeps its slot until main's reply.
    assert_eq!(world.machine.state_tables().colibri_in_flight, 1);
}

#[test]
fn fee_reference_work_counts_against_the_budget() {
    // As for a fee quote: an endpoint's gas price whose codec index the
    // request's budget can't hold ends the request with `budget`, not a
    // null part.
    let gas = format!("[{}]", vec!["null"; 1_000].join(","));
    let mut world = World::new(
        Bounds {
            request_bytes: 15_000,
            ..Bounds::default()
        },
        &[fee_chain(&["direct"], &["a"], false)],
    );
    let id = world.submit(REFERENCE, None);
    world.answer(world.rpc_to("a", "eth_gasPrice"), ok(&gas));
    world.answer(
        world.rpc_to("a", "eth_maxPriorityFeePerGas"),
        ok(&format!("\"{}\"", "a".repeat(9_000))),
    );
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Budget));
}

#[test]
fn fee_reference_measures_its_whole_reply() {
    // 181-m1: an endpoint's quote of 1,024 hex digits is accepted (B's codec
    // takes 4096 bits), and its 1,234-digit priority fee, in
    // `lowest_priority` and in the quote, counts toward the message cap.
    let wide = format!("\"0x{}\"", "f".repeat(1_024));
    let reply = |message_bytes: usize| {
        let mut world = World::new(
            Bounds {
                message_bytes,
                ..Bounds::default()
            },
            &[fee_chain(&["direct"], &["a"], false)],
        );
        let id = world.submit(REFERENCE, None);
        world.answer(world.rpc_to("a", "eth_gasPrice"), ok(&wide));
        world.answer(world.rpc_to("a", "eth_maxPriorityFeePerGas"), ok(&wide));
        world.reply(id).clone()
    };
    let reference = match reply(Bounds::default().message_bytes).result {
        Ok(Success::FeeReference(reference)) => reference,
        other => panic!("{other:?}"),
    };
    let priority = reference.lowest_priority.as_deref().unwrap();
    assert_eq!(priority.len(), 1_234);
    // Over 5,000 bytes in all: past a 5,000-byte cap it is too large.
    assert!(reference.json_len() > 5_000);
    assert_eq!(protocol(&reply(5_000)), Some(Protocol::TooLarge));
    // Within one of its exact length plus the envelope, it is sent.
    assert!(reply(reference.json_len() + 256).result.is_ok());
}
