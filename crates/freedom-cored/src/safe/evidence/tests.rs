//! The eight reads through the chain thread's own machine (design 0016,
//! SAFE-2's tests: *Unverified*, *The setup*), with Gnosis scripted: what
//! the Safe's address holds, and how each source answers each read.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_safe::constants::{FALLBACK_HANDLER, SENTINEL, SINGLETON};
use serde_json::{Value, json};

use super::*;
use crate::chain::scripted::Scripted;

const DEADLINE_MS: u64 = 20_000;

fn owners() -> Vec<[u8; 20]> {
    vec![[0x11; 20], [0x22; 20], [0x33; 20]]
}

fn setup() -> Setup {
    Setup::new(owners(), 2).unwrap()
}

fn safe() -> [u8; 20] {
    setup().address(&U256::from_u64(7))
}

fn word(bytes: &[u8]) -> [u8; 32] {
    let mut word = [0; 32];
    word[32 - bytes.len()..].copy_from_slice(bytes);
    word
}

fn uint(value: u64) -> [u8; 32] {
    word(&value.to_be_bytes())
}

/// Words as one `0x` answer.
fn hex_words(words: &[[u8; 32]]) -> Value {
    json!(to_hex(&words.concat()))
}

/// `address[]`, as `getOwners()` answers it.
fn owner_list(owners: &[[u8; 20]]) -> Value {
    let mut words = vec![uint(0x20), uint(owners.len() as u64)];
    words.extend(owners.iter().map(|owner| word(owner)));
    hex_words(&words)
}

/// `(address[], address)`, as `getModulesPaginated` answers it.
fn module_page(modules: &[[u8; 20]], next: [u8; 20]) -> Value {
    let mut words = vec![uint(0x40), word(&next), uint(modules.len() as u64)];
    words.extend(modules.iter().map(|module| word(module)));
    hex_words(&words)
}

/// How the sources answer a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Serve {
    /// Colibri proves an account read, and every endpoint gives the same
    /// answer.
    Verified,
    /// Only endpoint `a` answers; Colibri fails and the other endpoints
    /// can't be reached.
    OneEndpoint,
    /// Every endpoint answers the node's revert, and Colibri a verified
    /// one.
    Revert,
}

/// What the Safe's address holds on Gnosis, and how each read is served.
#[derive(Clone)]
struct World {
    answers: BTreeMap<Read, Value>,
    serve: BTreeMap<Read, Serve>,
}

impl World {
    /// The Safe as Freedom made it, nonce 7, every read verified.
    fn freedoms() -> Self {
        let answers = BTreeMap::from([
            (
                Read::Code,
                json!("0x608060405273ffffffffffffffffffffffffffffffffffffffff"),
            ),
            (Read::Singleton, hex_words(&[word(&SINGLETON)])),
            (Read::Owners, owner_list(&owners())),
            (Read::Threshold, hex_words(&[uint(2)])),
            (Read::Guard, hex_words(&[[0; 32]])),
            (Read::Handler, hex_words(&[word(&FALLBACK_HANDLER)])),
            (Read::Modules, module_page(&[], SENTINEL)),
            (Read::Nonce, hex_words(&[uint(7)])),
        ]);
        World {
            answers,
            serve: BTreeMap::new(),
        }
    }

    fn with(mut self, read: Read, answer: Value) -> Self {
        self.answers.insert(read, answer);
        self
    }

    fn served(mut self, read: Read, serve: Serve) -> Self {
        self.serve.insert(read, serve);
        self
    }

    fn serve(&self, read: Read) -> Serve {
        self.serve.get(&read).copied().unwrap_or(Serve::Verified)
    }
}

/// Gnosis's chain snapshot: `read_order`, endpoints `rpc`, a quorum of
/// `k` and `m`, and Colibri when `prover`.
fn gnosis(read_order: &[&str], rpc: &[&str], (k, m): (u64, u64), prover: bool) -> Value {
    json!({
        "chain_id": 100,
        "display_name": "Gnosis Chain",
        "read_order": read_order,
        "broadcast_order": ["direct"],
        "quorum": { "k": k, "m": m, "timeout_ms": 5000 },
        "rpc": rpc.iter().map(|e| json!({ "endpoint": e, "user_configured": false })).collect::<Vec<_>>(),
        "prover": prover.then(|| json!({ "endpoint": "p", "zk": false })),
        "myotis": false,
        "blockscout": null,
    })
}

/// Colibri, then a quorum of two of three, then Direct: Gnosis's order
/// without Myotis.
fn mixed() -> Value {
    gnosis(
        &["colibri", "quorum", "direct"],
        &["a", "b", "c"],
        (3, 2),
        true,
    )
}

/// Which read a request is, from its method and params; and that it asks
/// the Safe's address at `latest`, last.
fn which(method: &str, params: &Value) -> Read {
    let address = to_hex(&safe());
    let params = params.as_array().unwrap();
    assert_eq!(params.last().unwrap(), "latest", "{params:?}");
    let read = Read::ALL
        .into_iter()
        .find(|read| {
            let query = read.query();
            query.method() == method
                && match &query {
                    Query::Code => true,
                    Query::Storage(slot) => params[1] == to_hex(slot),
                    Query::Call(data) => params[0]["data"] == to_hex(data),
                }
        })
        .unwrap_or_else(|| panic!("{method} {params:?}"));
    let target = match read.query() {
        Query::Call(_) => &params[0]["to"],
        _ => &params[0],
    };
    assert_eq!(target, &json!(address));
    read
}

/// One check, run to its end.
struct Run {
    outcome: Outcome,
    /// Each step's reads, as the check sent them.
    steps: Vec<Vec<Read>>,
    /// Each read's source, as its reply names it.
    sources: BTreeMap<Read, String>,
}

/// Main's terminal reply to a `shell.*` request, from `world`.
fn reply(world: &World, frame: &Value) -> Result<Value, ErrorBody> {
    let params = &frame["params"];
    match frame["method"].as_str().unwrap() {
        "shell.rpc" => {
            let body: Value = serde_json::from_str(params["body"].as_str().unwrap()).unwrap();
            let read = which(body["method"].as_str().unwrap(), &body["params"]);
            let id = &body["id"];
            let text = match world.serve(read) {
                Serve::OneEndpoint if params["endpoint"] != "a" => {
                    return Err(ErrorBody::new(ErrorCode::Network, "unreachable"));
                }
                Serve::Verified | Serve::OneEndpoint => {
                    json!({ "jsonrpc": "2.0", "id": id, "result": world.answers[&read] })
                }
                Serve::Revert => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": 3, "message": "execution reverted", "data": "0x" },
                }),
            };
            Ok(json!({
                "status": 200,
                "body": base64::engine::general_purpose::STANDARD.encode(text.to_string()),
            }))
        }
        "shell.verified" => {
            assert_eq!(params["colibri"], "request", "{frame}");
            assert_eq!(params["chain_id"], 100);
            let read = which(params["method"].as_str().unwrap(), &params["params"]);
            Ok(match world.serve(read) {
                Serve::Verified => json!({ "result": world.answers[&read] }),
                Serve::OneEndpoint => json!({ "failure": "error" }),
                Serve::Revert => json!({ "revert": { "data": "0x" } }),
            })
        }
        other => panic!("{other}"),
    }
}

/// One step's reads, to the chain thread: each one's tag noted.
fn send(
    chain: &mut Scripted,
    batch: Vec<ChainRead>,
    reads: &mut BTreeMap<u64, Read>,
    steps: &mut Vec<Vec<Read>>,
) {
    let mut step = Vec::new();
    for read in batch {
        assert!(is_safe_tag(read.tag));
        assert_eq!(read.chain_id, 100);
        assert_eq!(read.deadline_ms, DEADLINE_MS);
        let params: Value = serde_json::from_str(&read.params).unwrap();
        let which = which(read.method, &params);
        reads.insert(read.tag, which);
        step.push(which);
        chain.internal(read);
    }
    steps.push(step);
}

/// The check of [`safe`] against [`setup`], through a chain thread
/// configured with `config`, main answering from `world`.
fn run(config: Value, world: &World) -> Run {
    let mut chain = Scripted::new(json!([config]));
    let mut tags = Tags::default();
    let (mut evidence, first) = Evidence::start(safe(), setup(), DEADLINE_MS, &mut tags);
    let mut steps = Vec::new();
    let mut reads = BTreeMap::new();
    let mut sources = BTreeMap::new();
    send(&mut chain, first, &mut reads, &mut steps);
    let mut answered = BTreeSet::new();
    for _ in 0..10_000 {
        for frame in chain.written() {
            let Some(id) = frame["id"].as_u64() else {
                continue;
            };
            match frame["type"].as_str() {
                Some("request") if answered.insert(id) => {
                    let outcome = reply(world, &frame);
                    chain.answer(id, outcome);
                }
                // A member the machine no longer needs: main answers it
                // cancelled, unless it already answered.
                Some("cancel") if answered.insert(id) => {
                    chain.answer(id, Err(ErrorBody::new(ErrorCode::Cancelled, "cancelled")));
                }
                _ => {}
            }
        }
        chain.tick(1);
        for (tag, payload, past_due) in chain.served() {
            let reply: Value = serde_json::from_slice(&payload).unwrap();
            if let Some(source) = reply["result"]["source"].as_str() {
                sources.insert(reads[&tag], source.to_owned());
            }
            match evidence.answered(tag, &payload, past_due, &mut tags) {
                Progress::Waiting => {}
                Progress::Reads(batch) => send(&mut chain, batch, &mut reads, &mut steps),
                Progress::Done(outcome) => {
                    return Run {
                        outcome,
                        steps,
                        sources,
                    };
                }
            }
        }
    }
    panic!("the check never ended: {steps:?}");
}

fn unverified(read: Read, why: Why) -> Outcome {
    Outcome::Unverified { read, why }
}

/// The three steps, in order.
fn all_steps() -> Vec<Vec<Read>> {
    vec![vec![Read::Code], SETUP.to_vec(), vec![Read::Nonce]]
}

#[test]
fn the_steps_are_the_eight_reads_in_fc_safes_order() {
    let steps: Vec<Read> = all_steps().concat();
    assert_eq!(steps, Read::ALL);
}

#[test]
fn eight_verified_reads_from_colibri_and_a_quorum_go_on() {
    // SAFE-2's *Unverified*: all eight verified from mixed sources, and the
    // step goes on with the nonce. Colibri proves the code and the slots;
    // it serves no call (main's #1046), so the calls are the quorum's.
    let run = run(mixed(), &World::freedoms());
    assert_eq!(
        run.outcome,
        Outcome::Unchanged {
            nonce: U256::from_u64(7)
        }
    );
    assert!(run.outcome.refusal().is_none());
    // The code alone first, the six together, and the nonce last.
    assert_eq!(run.steps, all_steps());
    let sources: Vec<(Read, &str)> = run
        .sources
        .iter()
        .map(|(read, source)| (*read, source.as_str()))
        .collect();
    assert_eq!(
        sources,
        [
            (Read::Code, "colibri"),
            (Read::Singleton, "colibri"),
            (Read::Owners, "quorum"),
            (Read::Threshold, "quorum"),
            (Read::Guard, "colibri"),
            // Colibri takes two reads of one route at once (the router's
            // `MAX_COLIBRI_IN_FLIGHT_PER_ROUTE`): the third slot goes on to
            // the quorum.
            (Read::Handler, "quorum"),
            (Read::Modules, "quorum"),
            (Read::Nonce, "quorum"),
        ]
    );
    // A quorum of two of three, with no prover, verifies every read too.
    let quorum = gnosis(&["quorum", "direct"], &["a", "b", "c"], (3, 2), false);
    let run = self::run(quorum, &World::freedoms());
    assert_eq!(
        run.outcome,
        Outcome::Unchanged {
            nonce: U256::from_u64(7)
        }
    );
    assert!(run.sources.values().all(|source| source == "quorum"));
}

#[test]
fn only_an_unverified_source_is_refused_safe_unverified() {
    // SAFE-2's *Unverified*: Direct alone, and a quorum answered by one
    // endpoint, each reporting the record's values. The code, read first,
    // is already not evidence: nothing else is read.
    let world = World::freedoms();
    let one = |world: World| {
        Read::ALL
            .into_iter()
            .fold(world, |world, read| world.served(read, Serve::OneEndpoint))
    };
    for (name, config, world, why, source) in [
        (
            "direct alone",
            gnosis(&["direct"], &["a"], (3, 2), false),
            world.clone(),
            Why::Unverified,
            Some("direct"),
        ),
        // Deviation `singleton-quorum`: m = 1 is one endpoint's answer.
        (
            "a quorum of one",
            gnosis(&["quorum"], &["a"], (1, 1), false),
            world.clone(),
            Why::Unverified,
            Some("quorum"),
        ),
        // Deviation `endpoint-dedup`: one endpoint three times is one.
        (
            "one endpoint three times",
            gnosis(&["quorum", "direct"], &["a", "a", "a"], (3, 2), false),
            world.clone(),
            Why::Unverified,
            Some("direct"),
        ),
        // Two of three needed, one answers: Direct gives its answer.
        (
            "a quorum one endpoint answers",
            gnosis(&["quorum", "direct"], &["a", "b", "c"], (3, 2), false),
            one(world.clone()),
            Why::Unverified,
            Some("direct"),
        ),
        // The same with no Direct after it: the read fails.
        (
            "a quorum one endpoint answers, nothing after it",
            gnosis(&["quorum"], &["a", "b", "c"], (3, 2), false),
            one(world.clone()),
            Why::Failed,
            None,
        ),
    ] {
        let run = run(config, &world);
        assert_eq!(run.outcome, unverified(Read::Code, why), "{name}");
        assert_eq!(run.steps, [vec![Read::Code]], "{name}");
        assert_eq!(
            run.sources.get(&Read::Code).map(String::as_str),
            source,
            "{name}"
        );
        let refusal = run.outcome.refusal().unwrap();
        assert_eq!(refusal.code, ErrorCode::InvalidArgument);
        assert_eq!(refusal.message, UNVERIFIED_TEXT);
        assert_eq!(refusal.data, Some(json!({ "safe": "unverified" })));
    }
}

#[test]
fn every_read_verified_but_one_is_refused_for_each_of_the_eight() {
    // SAFE-2's *Unverified*: each of the eight answered unverified in turn,
    // reporting the record's value, the other seven verified. A step that
    // isn't evidence ends the check: the nonce isn't read after it.
    for read in Read::ALL {
        let world = World::freedoms().served(read, Serve::OneEndpoint);
        let run = run(mixed(), &world);
        assert_eq!(run.outcome, unverified(read, Why::Unverified), "{read}");
        assert_eq!(run.sources[&read], "direct", "{read}");
        let steps = match read {
            Read::Code => 1,
            Read::Nonce => 3,
            _ => 2,
        };
        assert_eq!(run.steps, all_steps()[..steps], "{read}");
        assert_eq!(
            run.outcome.refusal().unwrap().data,
            Some(json!({ "safe": "unverified" })),
            "{read}"
        );
    }
}

#[test]
fn colibri_alone_verifies_no_call() {
    // With Colibri and one endpoint, the code and the slots are verified,
    // but no call is: the first call, the owners, is refused.
    let config = gnosis(&["colibri", "direct"], &["a"], (3, 2), true);
    let run = run(config, &World::freedoms());
    assert_eq!(run.outcome, unverified(Read::Owners, Why::Unverified));
    assert_eq!(run.sources[&Read::Code], "colibri");
    assert_eq!(run.sources[&Read::Guard], "colibri");
    assert_eq!(run.sources[&Read::Owners], "direct");
}

#[test]
fn each_setup_change_is_safe_changed() {
    // SAFE-2's *The setup*, through the real reads: each change, verified,
    // named alone.
    let other = [0x44; 20];
    let mut owners_swapped = owners();
    owners_swapped[2] = other;
    let mut owners_added = owners();
    owners_added.push(other);
    let mut owners_reordered = owners();
    owners_reordered.reverse();
    let cases = [
        (
            Read::Singleton,
            hex_words(&[word(&other)]),
            vec![Change::Singleton],
        ),
        // The singleton's address with a high byte set isn't SafeL2's word.
        (
            Read::Singleton,
            hex_words(&[{
                let mut word = word(&SINGLETON);
                word[0] = 1;
                word
            }]),
            vec![Change::Singleton],
        ),
        (
            Read::Owners,
            owner_list(&owners_swapped),
            vec![Change::Owners],
        ),
        (
            Read::Owners,
            owner_list(&owners_added),
            vec![Change::Owners],
        ),
        (
            Read::Owners,
            owner_list(&owners()[..2]),
            vec![Change::Owners],
        ),
        (
            Read::Threshold,
            hex_words(&[uint(1)]),
            vec![Change::Threshold],
        ),
        (Read::Guard, hex_words(&[word(&other)]), vec![Change::Guard]),
        (
            Read::Handler,
            hex_words(&[word(&other)]),
            vec![Change::Handler],
        ),
        (Read::Handler, hex_words(&[[0; 32]]), vec![Change::Handler]),
        // A module enabled, linked at the head: the first page has it.
        (
            Read::Modules,
            module_page(&[other], SENTINEL),
            vec![Change::Module],
        ),
        // An empty page whose `next` isn't the sentinel isn't a list `setup`
        // made.
        (Read::Modules, module_page(&[], other), vec![Change::Module]),
    ];
    for (read, answer, changed) in cases {
        let run = run(mixed(), &World::freedoms().with(read, answer.clone()));
        assert_eq!(run.outcome, Outcome::Changed(changed), "{read} {answer}");
        let refusal = run.outcome.refusal().unwrap();
        assert_eq!(refusal.code, ErrorCode::InvalidArgument);
        assert_eq!(refusal.message, CHANGED_TEXT);
        assert_eq!(refusal.data, Some(json!({ "safe": "changed" })));
    }
    // The owners in another order are the same set.
    let world = World::freedoms().with(Read::Owners, owner_list(&owners_reordered));
    assert_eq!(
        run(mixed(), &world).outcome,
        Outcome::Unchanged {
            nonce: U256::from_u64(7)
        }
    );
    // Several changes are each named, in fc-safe's order.
    let world = World::freedoms()
        .with(Read::Threshold, hex_words(&[uint(3)]))
        .with(Read::Owners, owner_list(&owners_added))
        .with(Read::Guard, hex_words(&[word(&other)]));
    assert_eq!(
        run(mixed(), &world).outcome,
        Outcome::Changed(vec![Change::Owners, Change::Threshold, Change::Guard])
    );
}

#[test]
fn under_another_singleton_the_singleton_alone_decides() {
    // #520's rule, confirmed: slot 0, verified, isn't SafeL2 1.4.1, so the
    // calls answer for another contract. Whatever they answer, verified or
    // not, or reverted, the Safe is changed, and the nonce isn't read.
    let other = [0x44; 20];
    let moved = World::freedoms().with(Read::Singleton, hex_words(&[word(&other)]));
    let calls = [Read::Owners, Read::Threshold, Read::Modules];
    for serve in [Serve::Revert, Serve::OneEndpoint] {
        let world = calls
            .into_iter()
            .fold(moved.clone(), |world, read| world.served(read, serve));
        let run = run(mixed(), &world);
        assert_eq!(
            run.outcome,
            Outcome::Changed(vec![Change::Singleton]),
            "{serve:?}"
        );
        assert_eq!(run.steps, all_steps()[..2], "{serve:?}");
    }
    // Calls that answer garbage are not read either.
    let world = calls
        .into_iter()
        .fold(moved.clone(), |world, read| world.with(read, json!("0x01")));
    assert_eq!(
        run(mixed(), &world).outcome,
        Outcome::Changed(vec![Change::Singleton])
    );
    // The guard and the handler are the proxy's own storage: named with it
    // when verified reads show them changed.
    let world = moved
        .clone()
        .with(Read::Guard, hex_words(&[word(&other)]))
        .with(Read::Handler, hex_words(&[[0; 32]]));
    assert_eq!(
        run(mixed(), &world).outcome,
        Outcome::Changed(vec![Change::Singleton, Change::Guard, Change::Handler])
    );
    // Not when they aren't verified, or don't decode: the singleton alone.
    let world = moved
        .clone()
        .with(Read::Guard, hex_words(&[word(&other)]))
        .served(Read::Guard, Serve::OneEndpoint);
    assert_eq!(
        run(mixed(), &world).outcome,
        Outcome::Changed(vec![Change::Singleton])
    );
    let world = moved
        .clone()
        .with(Read::Handler, json!("0x01"))
        .with(Read::Guard, hex_words(&[word(&other)]));
    assert_eq!(
        run(mixed(), &world).outcome,
        Outcome::Changed(vec![Change::Singleton])
    );
    // A singleton that isn't verified decides nothing: unverified.
    let world = moved.served(Read::Singleton, Serve::OneEndpoint);
    assert_eq!(
        run(mixed(), &world).outcome,
        unverified(Read::Singleton, Why::Unverified)
    );
}

#[test]
fn no_code_is_not_deployed_and_reads_nothing_more() {
    let world = World::freedoms().with(Read::Code, json!("0x"));
    let run = run(mixed(), &world);
    assert_eq!(run.outcome, Outcome::NotDeployed);
    assert_eq!(run.steps, [vec![Read::Code]]);
    assert_eq!(run.sources[&Read::Code], "colibri");
    // S2 settles its answer.
    assert!(run.outcome.refusal().is_none());
    // One endpoint's "no code" is no evidence that the Safe isn't deployed.
    let world = world.served(Read::Code, Serve::OneEndpoint);
    assert_eq!(
        self::run(mixed(), &world).outcome,
        unverified(Read::Code, Why::Unverified)
    );
}

#[test]
fn a_reverted_call_is_safe_unverified() {
    // #520's rule, confirmed: SafeL2 1.4.1's view functions never revert,
    // so a revert is no evidence of the setup. Every endpoint reverts, so
    // no quorum forms, and Direct throws the node's error.
    for read in [Read::Owners, Read::Threshold, Read::Modules, Read::Nonce] {
        let world = World::freedoms().served(read, Serve::Revert);
        let run = run(mixed(), &world);
        assert_eq!(run.outcome, unverified(read, Why::Failed), "{read}");
        assert!(!run.sources.contains_key(&read), "{read}");
    }
    // A storage read Colibri answers with a verified revert, and every
    // endpoint with the node's: failed too.
    let world = World::freedoms().served(Read::Guard, Serve::Revert);
    assert_eq!(
        run(mixed(), &world).outcome,
        unverified(Read::Guard, Why::Failed)
    );
}

#[test]
fn an_unreadable_answer_is_safe_unverified() {
    // #520's rule, confirmed: a verified answer that isn't its read's
    // encoding is a read error, never a change. The record's setup isn't
    // judged on it.
    let other = [0x44; 20];
    let mut high = word(&other);
    high[0] = 1;
    let cases = [
        // fc-safe's decoders' problems.
        (
            Read::Owners,
            hex_words(&[uint(0x40), uint(0)]),
            Why::Unreadable(Some(ReadProblem::Offset)),
        ),
        (
            Read::Owners,
            hex_words(&[uint(0x20), uint(3), word(&other)]),
            Why::Unreadable(Some(ReadProblem::Length)),
        ),
        (
            Read::Modules,
            json!(module_page(&[], SENTINEL).as_str().unwrap()[..2 + 64 * 2].to_owned()),
            Why::Unreadable(Some(ReadProblem::Length)),
        ),
        (
            Read::Modules,
            hex_words(&[uint(0x40), high, uint(0)]),
            Why::Unreadable(Some(ReadProblem::Address)),
        ),
        (
            Read::Guard,
            json!(to_hex(&[0; 31])),
            Why::Unreadable(Some(ReadProblem::Length)),
        ),
        (
            Read::Singleton,
            json!(to_hex(&[0; 33])),
            Why::Unreadable(Some(ReadProblem::Length)),
        ),
        (
            Read::Threshold,
            json!("0x02"),
            Why::Unreadable(Some(ReadProblem::Length)),
        ),
        (
            Read::Nonce,
            json!("0x"),
            Why::Unreadable(Some(ReadProblem::Length)),
        ),
        // Not hex, or not a string.
        (Read::Code, json!("0x6080z0"), Why::Unreadable(None)),
        (Read::Owners, json!("0xabc"), Why::Unreadable(None)),
        (Read::Threshold, json!(2), Why::Unreadable(None)),
        (Read::Handler, json!(null), Why::Unreadable(None)),
        (Read::Nonce, json!({ "nonce": 7 }), Why::Unreadable(None)),
    ];
    for (read, answer, why) in cases {
        let run = run(mixed(), &World::freedoms().with(read, answer.clone()));
        assert_eq!(run.outcome, unverified(read, why), "{read} {answer}");
        assert_eq!(
            run.outcome.refusal().unwrap().data,
            Some(json!({ "safe": "unverified" }))
        );
    }
}

/// A read's reply as the chain thread writes it.
fn payload(result: Value) -> Vec<u8> {
    json!({ "type": "response", "id": 1, "result": result })
        .to_string()
        .into_bytes()
}

#[test]
fn a_reply_is_read_strictly() {
    let verified = |result: Value| {
        payload(json!({
            "result": result,
            "source": "colibri",
            "verified": true,
            "undefined_keys": [],
            "generation": 1,
        }))
    };
    assert_eq!(answer(&verified(json!("0x")), false), Ok(Vec::new()));
    assert_eq!(
        answer(&verified(json!("0X0aFf")), false),
        Ok(vec![0x0a, 0xff])
    );
    // Unverified, whatever it holds.
    let unverified = payload(json!({ "result": 7, "source": "direct", "verified": false }));
    assert_eq!(answer(&unverified, false), Err(Why::Unverified));
    // An `undefined` result.
    let undefined = payload(json!({
        "source": "colibri",
        "verified": true,
        "undefined_keys": ["result"],
        "generation": 1,
    }));
    assert_eq!(answer(&undefined, false), Err(Why::Unreadable(None)));
    // A failure; at or after its deadline; and what the thread never
    // writes.
    let failed = json!({
        "type": "response",
        "id": 1,
        "error": { "code": "deadline", "message": "Deadline exceeded", "data": { "generation": 1 } },
    })
    .to_string()
    .into_bytes();
    assert_eq!(answer(&failed, false), Err(Why::Failed));
    assert_eq!(answer(&failed, true), Err(Why::PastDue));
    for odd in [
        &b"not json"[..],
        &br#"{"result":{"result":"0x"}}"#[..],
        &b"{}"[..],
    ] {
        assert_eq!(answer(odd, false), Err(Why::Failed));
    }
}

#[test]
fn a_reply_the_check_isnt_waiting_for_changes_nothing() {
    let mut tags = Tags::default();
    let (mut evidence, reads) = Evidence::start(safe(), setup(), DEADLINE_MS, &mut tags);
    let [read] = reads.as_slice() else {
        panic!("one read first");
    };
    let code = read.tag;
    let reply = payload(json!({ "result": "0x6080", "source": "colibri", "verified": true }));
    assert!(matches!(
        evidence.answered(code + 1, &reply, false, &mut tags),
        Progress::Waiting
    ));
    assert!(evidence.waits_for(code));
    let Progress::Reads(setup_reads) = evidence.answered(code, &reply, false, &mut tags) else {
        panic!("the six setup reads next");
    };
    assert_eq!(setup_reads.len(), 6);
    // The code's reply again: no longer out.
    assert!(!evidence.waits_for(code));
    assert!(matches!(
        evidence.answered(code, &reply, false, &mut tags),
        Progress::Waiting
    ));
    // Until all six are in, nothing more is sent.
    for read in &setup_reads[..5] {
        assert!(matches!(
            evidence.answered(read.tag, &payload(json!({})), false, &mut tags),
            Progress::Waiting
        ));
    }
    let last = setup_reads[5].tag;
    let Progress::Done(outcome) = evidence.answered(last, &payload(json!({})), false, &mut tags)
    else {
        panic!("a setup read failed: done");
    };
    assert_eq!(outcome, unverified(Read::Singleton, Why::Failed));
}

#[test]
fn the_reads_take_their_methods_and_params() {
    let mut tags = Tags::default();
    let safe = safe();
    let address = to_hex(&safe);
    let params = |read: Read| -> Value {
        serde_json::from_str(&chain_read(&safe, read, 1, 5).params).unwrap()
    };
    assert_eq!(chain_read(&safe, Read::Code, 1, 5).method, "eth_getCode");
    assert_eq!(params(Read::Code), json!([address, "latest"]));
    // A slot as all 32 bytes, as Colibri's prover requires (0014).
    assert_eq!(
        params(Read::Singleton),
        json!([address, format!("0x{}", "0".repeat(64)), "latest"])
    );
    assert_eq!(
        params(Read::Guard),
        json!([
            address,
            "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8",
            "latest"
        ])
    );
    assert_eq!(
        params(Read::Handler),
        json!([
            address,
            "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5",
            "latest"
        ])
    );
    assert_eq!(chain_read(&safe, Read::Nonce, 1, 5).method, "eth_call");
    assert_eq!(
        params(Read::Nonce),
        json!([{ "to": address, "data": "0xaffed0e0" }, "latest"])
    );
    assert_eq!(
        params(Read::Modules),
        json!([{
            "to": address,
            "data": format!("0xcc2f8452{}{}", to_hex(&word(&SENTINEL))[2..].to_owned(), to_hex(&uint(1))[2..].to_owned()),
        }, "latest"])
    );
    // The tags: the Safe's bit, never a page send's.
    let first = tags.next();
    assert_eq!(first, SAFE_TAG);
    assert_eq!(tags.next(), SAFE_TAG | 1);
    let mut late = Tags { next: SAFE_TAG - 1 };
    assert_eq!(late.next(), SAFE_TAG | (SAFE_TAG - 1));
    assert_eq!(late.next(), SAFE_TAG);
    assert!(is_safe_tag(SAFE_TAG | 5));
    assert!(!is_safe_tag(5));
    assert!(!is_safe_tag(crate::eip1193::SEND_TAG | SAFE_TAG));
}
