//! The device lane against a scripted main and a scripted device, under a
//! fixed clock (design 0016, LDG-2's L2): two operations in turn; a ninth
//! waiting refused `LEDGER_BUSY`; discovery `LEDGER_BUSY` while a signature
//! runs or waits; 15 s gives `LEDGER_UNRESPONSIVE`; the user's answer at
//! 4:59.999 signs and 5:00 is `LEDGER_TIMEOUT`; a request that waited in
//! the queue still has its full 5 minutes to confirm (question 5); no
//! request queued past the lane's limit;
//! cancel before the first APDU, between two and during the user's wait; a
//! late answer dropped; an unplug at each APDU; a stale signature refused;
//! the lane's own end of discovery's check, which ends only the check (D1);
//! and the `deadline_ms` each APDU carries.
//!
//! The device is `vectors/ledger.json`'s: each case's recorded answers, by
//! APDU, and `formats.device`'s answer to the `B0 01` the core adds
//! (deviation `app-check`).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use fc_evm::{Transaction, checksum_address, parse_address, parse_bytes, to_hex};
use fc_ledger::{Account, Cause, Failed, LedgerPath, Scheme, SignatureFault};
use serde_json::{Value, json};

use super::*;
use crate::requests::MAX_OUTSTANDING;
use crate::transport::Pending;

const DISCOVERY: &str = "discovery-live-0-2";
const ADD: &str = "add-live-0";
const TX: &str = "tx-steps";
const MSG: &str = "msg-steps";
/// Another message, from the same account as [`MSG`].
const MSG_OTHER: &str = "msg-live-1";
const TYPED: &str = "typed-steps";
const HASH_ONLY: &str = "typed-hash-only-mail";
const CASES: [&str; 7] = [DISCOVERY, ADD, TX, MSG, MSG_OTHER, TYPED, HASH_ONLY];

/// The APDU deadlines, in milliseconds.
const APDU: u64 = 15_000;
const CONFIRM: u64 = 300_000;
const CORE_APDU: u64 = APDU + 1_000;
const CORE_CONFIRM: u64 = CONFIRM + 1_000;
const LIMIT: u64 = 300_000;

fn ledger() -> &'static Value {
    static FILE: OnceLock<Value> = OnceLock::new();
    FILE.get_or_init(|| {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/ledger.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    })
}

fn case(id: &str) -> &'static Value {
    ledger()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == id)
        .unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    parse_bytes(&format!("0x{}", text.trim_start_matches("0x")), "hex").unwrap()
}

fn hex(bytes: &[u8]) -> String {
    to_hex(bytes)[2..].to_owned()
}

fn account(record: &Value) -> Account {
    Account {
        path: LedgerPath::parse(record["path"].as_str().unwrap()).unwrap(),
        address: parse_address(record["address"].as_str().unwrap()).unwrap(),
    }
}

/// Case `id`'s operation, as L3 and L4 build it from the request.
fn operation(id: &str) -> Operation {
    let case = case(id);
    let request = &case["request"];
    match case["operation"].as_str().unwrap() {
        "ledger.accounts" => Operation::accounts(
            Scheme::parse(request["scheme"].as_str().unwrap()).unwrap(),
            request["start"].as_u64().unwrap(),
            request["count"].as_u64().unwrap(),
        )
        .unwrap(),
        "ledger.add" => {
            Operation::add(LedgerPath::parse(request["path"].as_str().unwrap()).unwrap())
        }
        "sign.transaction" => Operation::sign_transaction(
            account(&case["record"]),
            &Transaction::from_json(&request["tx"]).unwrap(),
        )
        .unwrap(),
        "sign.message" => Operation::sign_message(
            account(&case["record"]),
            unhex(request["message"].as_str().unwrap()),
        )
        .unwrap(),
        "sign.typed_data" => {
            let typed = &request["typed_data"];
            let hash: [u8; 32] = unhex(request["expected_hash"].as_str().unwrap())
                .try_into()
                .unwrap();
            Operation::sign_typed_data(
                account(&case["record"]),
                &typed["domain"],
                &typed["types"],
                &typed["message"],
                &hash,
            )
            .unwrap()
        }
        other => panic!("no operation {other}"),
    }
}

fn is_discovery(id: &str) -> bool {
    case(id)["operation"] == "ledger.accounts"
}

fn turn(id: &str) -> Turn {
    if is_discovery(id) {
        Turn::Now
    } else {
        Turn::Wait
    }
}

/// The scripted device: case `id`'s recorded answer to each APDU the
/// reference sent; `E0 02 01 00`, the reference's `E0 02 00 00` (deviation
/// `address-from-device`), the same; and `B0 01`, which the core adds for
/// every signature (deviation `app-check`), `formats.device`'s answer for
/// the case's app.
fn device(id: &str, apdu: &[u8]) -> Vec<u8> {
    let case = case(id);
    let recorded = case["exchanges"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|exchange| {
            let theirs = unhex(exchange["apdu"].as_str().unwrap());
            let display = apdu[..4] == [0xe0, 0x02, 0x01, 0x00]
                && theirs[..4] == [0xe0, 0x02, 0x00, 0x00]
                && theirs[4..] == apdu[4..];
            (theirs == apdu || display).then(|| unhex(exchange["answer"].as_str().unwrap()))
        });
    if let Some(answer) = recorded {
        return answer;
    }
    assert_eq!(
        apdu,
        [0xb0, 0x01, 0x00, 0x00, 0x00],
        "{id}: nothing recorded for {}",
        hex(apdu)
    );
    let app = &case["device"]["app"];
    let name = app["name"].as_str().unwrap().as_bytes();
    let version = app["version"].as_str().unwrap().as_bytes();
    let mut answer = vec![1, u8::try_from(name.len()).unwrap()];
    answer.extend_from_slice(name);
    answer.push(u8::try_from(version.len()).unwrap());
    answer.extend_from_slice(version);
    answer.extend_from_slice(&[1, 0, 0x90, 0x00]);
    answer
}

/// Whether `signed` is what case `id` recorded.
fn as_recorded(id: &str, signed: &Signed) -> bool {
    let result = &case(id)["result"];
    match signed {
        Signed::Accounts(found) => {
            let accounts: Vec<Value> = found
                .accounts
                .iter()
                .map(|a| json!({ "path": a.path.to_string(), "address": checksum_address(&a.address) }))
                .collect();
            result["accounts"].as_array() == Some(&accounts)
        }
        Signed::Added(a) => {
            result["wallet"]["path"] == a.path.to_string()
                && result["wallet"]["address"] == checksum_address(&a.address)
        }
        Signed::Transaction(tx) => result["raw"] == to_hex(&tx.raw),
        Signed::Signature(signature) => result["signature"] == to_hex(signature),
    }
}

/// One `shell.ledger_apdu`, as main reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sent {
    core: u64,
    parent: u64,
    apdu: Vec<u8>,
    deadline_ms: u64,
}

/// A frame the lane wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Wrote {
    Apdu(Sent),
    Cancel(u64),
}

type Ends = Vec<Ended<&'static str>>;

/// The scripted main, which holds the core's gate as the event loop does:
/// it reads what the lane writes, and hands each answer to the gate and
/// then to the lane. The lane's operations are labelled by their case.
struct Main {
    lane: Lane<&'static str>,
    requests: Arc<Requests>,
    rx: Receiver<transport::Out>,
    /// What was read and put back.
    backlog: VecDeque<Wrote>,
    woken: Arc<AtomicBool>,
    t0: Instant,
}

impl Main {
    fn new() -> Main {
        Main::with_room(MAX_OUTSTANDING)
    }

    /// Main takes at most `room` of the core's requests.
    fn with_room(room: usize) -> Main {
        let requests = Requests::new(room, Arc::new(Pending::default()));
        let (out, rx) = mpsc::channel();
        let woken = Arc::new(AtomicBool::new(false));
        let wake = {
            let woken = Arc::clone(&woken);
            move || woken.store(true, Ordering::SeqCst)
        };
        let lane = Lane::new(Arc::clone(&requests), out, wake);
        Main {
            lane,
            requests,
            rx,
            backlog: VecDeque::new(),
            woken,
            t0: Instant::now(),
        }
    }

    fn at(&self, ms: u64) -> Instant {
        self.t0 + Duration::from_millis(ms)
    }

    /// What the lane wrote since, read strictly: a request is exactly
    /// `shell.ledger_apdu { for, apdu, deadline_ms }`, the hex in lower
    /// case, from the shell; a cancel is `{ type, id }`.
    fn wrote(&mut self) -> Vec<Wrote> {
        let mut wrote: Vec<Wrote> = self.backlog.drain(..).collect();
        while let Ok(out) = self.rx.try_recv() {
            let transport::Out::Frame { frame, .. } = out else {
                panic!("not a whole frame");
            };
            let message: Value = serde_json::from_slice(&frame[5..]).unwrap();
            match message["type"].as_str().unwrap() {
                "cancel" => {
                    assert_eq!(message.as_object().unwrap().len(), 2, "{message}");
                    wrote.push(Wrote::Cancel(message["id"].as_u64().unwrap()));
                }
                "request" => {
                    assert_eq!(message["method"], METHOD);
                    assert_eq!(message["context"], json!({ "caller": "shell" }));
                    let params = message["params"].as_object().unwrap();
                    let mut members: Vec<&str> = params.keys().map(String::as_str).collect();
                    members.sort_unstable();
                    assert_eq!(members, ["apdu", "deadline_ms", "for"]);
                    let apdu = params["apdu"].as_str().unwrap();
                    assert_eq!(apdu, apdu.to_ascii_lowercase());
                    wrote.push(Wrote::Apdu(Sent {
                        core: message["id"].as_u64().unwrap(),
                        parent: params["for"].as_u64().unwrap(),
                        apdu: unhex(apdu),
                        deadline_ms: params["deadline_ms"].as_u64().unwrap(),
                    }));
                }
                other => panic!("a {other}"),
            }
        }
        wrote
    }

    /// What the lane wrote, left for [`run`] to read.
    fn peek(&mut self) -> Vec<Wrote> {
        let wrote = self.wrote();
        self.backlog.extend(wrote.iter().cloned());
        wrote
    }

    /// The one APDU the lane wrote since, left for [`run`].
    fn out(&mut self) -> Sent {
        match self.peek().as_slice() {
            [Wrote::Apdu(sent)] => sent.clone(),
            other => panic!("{other:?}"),
        }
    }

    fn submit(&mut self, parent: u64, id: &'static str, ms: u64) -> Ends {
        let at = self.at(ms);
        self.lane.submit(parent, operation(id), id, turn(id), at)
    }

    /// Main's reply to request `core`, handed over as the event loop does:
    /// the gate first, then the lane.
    fn reply(&mut self, core: u64, reply: Result<Value, Value>, ms: u64) -> Result<Ends, Protocol> {
        assert_eq!(self.requests.answered(core), Some(Owner::Ledger));
        let text = match &reply {
            Ok(value) | Err(value) => value.to_string(),
        };
        let outcome = match reply {
            Ok(_) => Ok(text.as_str()),
            Err(_) => Err(text.as_str()),
        };
        let at = self.at(ms);
        self.lane.answered(core, outcome, at)
    }

    fn answer(&mut self, core: u64, answer: &[u8], ms: u64) -> Ends {
        self.reply(core, Ok(json!({ "answer": hex(answer) })), ms)
            .unwrap()
    }

    fn failed(&mut self, core: u64, failed: &str, ms: u64) -> Ends {
        self.reply(core, Ok(json!({ "failed": failed })), ms)
            .unwrap()
    }

    /// Main's answer to the core's cancel.
    fn cancelled(&mut self, core: u64, ms: u64) -> Ends {
        let error = json!({ "code": "cancelled", "message": "Cancelled" });
        self.reply(core, Err(error), ms).unwrap()
    }

    fn tick(&mut self, ms: u64) -> Ends {
        let at = self.at(ms);
        self.lane.tick(at)
    }

    fn cancel(&mut self, parent: u64, ms: u64) -> Ends {
        let at = self.at(ms);
        self.lane.cancel(parent, at)
    }

    /// When the lane wants to be woken, from the start.
    fn wakeup(&self) -> Option<u64> {
        self.lane
            .next_wakeup()
            .map(|at| u64::try_from(at.duration_since(self.t0).as_millis()).unwrap())
    }

    /// When main's answer to a watched cancel is due, from the start.
    fn overdue(&self) -> Option<u64> {
        self.requests
            .next_overdue()
            .map(|at| u64::try_from(at.duration_since(self.t0).as_millis()).unwrap())
    }
}

/// What scripted main does with an operation's APDU.
enum Act {
    /// Exchanges it with the scripted device: a `6D00` to the operation's
    /// first `E0 1A` with `hash_only: "shown"`, as main answers once its
    /// warning is on screen (Q23).
    Device,
    /// Answers this.
    Reply(Result<Value, Value>),
    /// Answers nothing yet.
    Silent,
}

fn failed(failed: &str) -> Act {
    Act::Reply(Ok(json!({ "failed": failed })))
}

/// Answers `parent`'s APDUs at `ms` as `act` says for each (by its index
/// in the operation), until the operation ends or main falls silent: what
/// was sent for it, and the ends. Every APDU written meanwhile must be
/// `parent`'s: one operation at a time.
fn run(
    main: &mut Main,
    id: &str,
    parent: u64,
    ms: u64,
    mut act: impl FnMut(usize, &Sent) -> Act,
) -> (Vec<Sent>, Ends) {
    let mut sent = Vec::new();
    let mut ends = Vec::new();
    let mut defined = false;
    let mut wrote: VecDeque<Wrote> = main.wrote().into();
    while let Some(next) = wrote.pop_front() {
        let Wrote::Apdu(apdu) = next else {
            panic!("{next:?}");
        };
        assert_eq!(apdu.parent, parent, "{id}: one operation at a time");
        let index = sent.len();
        sent.push(apdu.clone());
        let definition = apdu.apdu[..2] == [0xe0, 0x1a];
        let first_definition = definition && !defined;
        defined |= definition;
        let reply = match act(index, &apdu) {
            Act::Silent => break,
            Act::Reply(reply) => reply,
            Act::Device => {
                let answer = device(id, &apdu.apdu);
                Ok(if first_definition && answer == [0x6d, 0x00] {
                    json!({ "answer": "6d00", "hash_only": "shown" })
                } else {
                    json!({ "answer": hex(&answer) })
                })
            }
        };
        ends.extend(main.reply(apdu.core, reply, ms).unwrap());
        if ends.iter().any(|end| end.parent == parent) {
            break;
        }
        wrote.extend(main.wrote());
    }
    (sent, ends)
}

fn run_device(main: &mut Main, id: &str, parent: u64, ms: u64) -> (Vec<Sent>, Ends) {
    run(main, id, parent, ms, |_, _| Act::Device)
}

/// The ends, as `(parent, "signed" | "cancelled" | the code)`.
fn summary(ends: &Ends) -> Vec<(u64, &'static str)> {
    ends.iter()
        .map(|end| {
            let what = match &end.outcome {
                Outcome::Done(Ok(_)) => "signed",
                Outcome::Cancelled => "cancelled",
                other => other.code().unwrap().as_str(),
            };
            (end.parent, what)
        })
        .collect()
}

/// A request of another owner's that takes a slot at main.
fn filler(main: &Main) -> (u64, Receiver<transport::Out>) {
    let (out, rx) = mpsc::channel();
    let allowance = Allowance::new(usize::MAX, usize::MAX);
    let sent = main.requests.send(
        Owner::Chain,
        &allowance,
        &out,
        || requests::request_frame("shell.rpc", b"{}", None),
        || Start::Anytime,
    );
    let Dispatch::Sent(id) = sent else {
        panic!("{sent:?}");
    };
    (id, rx)
}

#[test]
fn every_apdu_carries_its_deadline_and_every_case_ends_as_recorded() {
    for (n, id) in CASES.into_iter().enumerate() {
        let mut main = Main::new();
        let parent = 40 + n as u64;
        assert!(main.submit(parent, id, 0).is_empty());
        let (sent, ends) = run_device(&mut main, id, parent, 0);
        let [end] = ends.as_slice() else {
            panic!("{id}: {ends:?}");
        };
        assert_eq!((end.parent, end.then), (parent, id));
        let Outcome::Done(Ok(signed)) = &end.outcome else {
            panic!("{id}: {:?}", end.outcome);
        };
        assert!(as_recorded(id, signed), "{id}: {signed:?}");
        // The APDU the user confirms is each row's last, and discovery has
        // none: 5 minutes there, 15 s on every other.
        for (index, apdu) in sent.iter().enumerate() {
            let confirm = !is_discovery(id) && index + 1 == sent.len();
            let deadline = if confirm { CONFIRM } else { APDU };
            assert_eq!(apdu.deadline_ms, deadline, "{id} #{index}");
        }
        // The core's request IDs, one per APDU, increase.
        assert!(sent.windows(2).all(|pair| pair[0].core < pair[1].core));
        assert!(main.wrote().is_empty());
        assert_eq!(main.wakeup(), None);
    }
    // The hash-only form went only after main's hash_only: its one APDU is
    // E0 0C 00 00, after the first E0 1A.
    let mut main = Main::new();
    main.submit(1, HASH_ONLY, 0);
    let (sent, _) = run_device(&mut main, HASH_ONLY, 1, 0);
    let headers: Vec<&[u8]> = sent.iter().map(|apdu| &apdu.apdu[..4]).collect();
    assert_eq!(
        headers,
        [
            [0xe0, 0x02, 0x00, 0x00],
            [0xb0, 0x01, 0x00, 0x00],
            [0xe0, 0x1a, 0x00, 0x00],
            [0xe0, 0x0c, 0x00, 0x00],
        ]
    );
}

#[test]
fn two_operations_in_turn() {
    let mut main = Main::new();
    assert!(main.submit(1, MSG, 0).is_empty());
    assert!(main.submit(2, MSG_OTHER, 0).is_empty());
    assert_eq!(main.lane.waiting(), 1);
    // Only the first one's APDUs go until it ends.
    let (sent, ends) = run_device(&mut main, MSG, 1, 10);
    assert_eq!(sent.len(), 4);
    assert_eq!(summary(&ends), [(1, "signed")]);
    assert_eq!(main.lane.waiting(), 0);
    // Then the second's, from its own address check.
    let (sent, ends) = run_device(&mut main, MSG_OTHER, 2, 20);
    assert_eq!(sent[0].apdu[..4], [0xe0, 0x02, 0x00, 0x00]);
    assert_eq!(summary(&ends), [(2, "signed")]);
    assert!(main.wrote().is_empty());
    assert_eq!(main.wakeup(), None);
}

#[test]
fn a_ninth_waiting_is_refused_busy_and_the_rest_keep_their_order() {
    let mut main = Main::new();
    assert!(main.submit(100, ADD, 0).is_empty());
    let running = main.out();
    main.wrote();
    for parent in 1..=8 {
        assert!(main.submit(parent, MSG_OTHER, parent).is_empty());
    }
    assert_eq!(main.lane.waiting(), MAX_WAITING);
    let refused = main.submit(9, MSG_OTHER, 9);
    assert_eq!(summary(&refused), [(9, "LEDGER_BUSY")]);
    assert_eq!(refused[0].then, MSG_OTHER);
    assert_eq!(refused[0].outcome, Outcome::Lane(LaneEnd::Busy));
    assert!(main.wrote().is_empty(), "nothing goes for it");
    // One leaving makes room again.
    assert_eq!(summary(&main.cancel(4, 10)), [(4, "cancelled")]);
    assert!(main.submit(10, MSG_OTHER, 10).is_empty());
    assert_eq!(
        summary(&main.submit(11, MSG_OTHER, 11)),
        [(11, "LEDGER_BUSY")]
    );
    // The first one ends; the rest run in the order they came.
    let ends = main.answer(running.core, &device(ADD, &running.apdu), 20);
    assert_eq!(summary(&ends), [(100, "signed")]);
    for parent in [1, 2, 3, 5, 6, 7, 8, 10] {
        let (_, ends) = run_device(&mut main, MSG_OTHER, parent, 30);
        assert_eq!(summary(&ends), [(parent, "signed")]);
    }
    assert!(main.wrote().is_empty());
}

#[test]
fn discovery_is_busy_at_once_while_another_runs_or_waits() {
    let mut main = Main::new();
    // The lane idle: it runs.
    assert!(main.submit(1, DISCOVERY, 0).is_empty());
    // A signature waits behind it; another discovery doesn't.
    assert!(main.submit(2, MSG, 0).is_empty());
    assert_eq!(summary(&main.submit(3, DISCOVERY, 0)), [(3, "LEDGER_BUSY")]);
    let (_, ends) = run_device(&mut main, DISCOVERY, 1, 1);
    assert_eq!(summary(&ends), [(1, "signed")]);
    // While a signature runs, and while one waits behind it: refused at
    // once, with nothing sent.
    let first = main.out();
    assert_eq!(first.parent, 2);
    assert_eq!(summary(&main.submit(4, DISCOVERY, 2)), [(4, "LEDGER_BUSY")]);
    assert!(main.submit(5, MSG_OTHER, 3).is_empty());
    assert_eq!(summary(&main.submit(6, DISCOVERY, 4)), [(6, "LEDGER_BUSY")]);
    assert_eq!(main.peek().len(), 1);
    let (_, ends) = run_device(&mut main, MSG, 2, 5);
    assert_eq!(summary(&ends), [(2, "signed")]);
    assert_eq!(summary(&main.submit(7, DISCOVERY, 6)), [(7, "LEDGER_BUSY")]);
    let (_, ends) = run_device(&mut main, MSG_OTHER, 5, 7);
    assert_eq!(summary(&ends), [(5, "signed")]);
    // Idle again: it runs.
    assert!(main.submit(8, DISCOVERY, 8).is_empty());
    let (_, ends) = run_device(&mut main, DISCOVERY, 8, 9);
    assert_eq!(summary(&ends), [(8, "signed")]);
}

#[test]
fn fifteen_seconds_without_an_answer_give_unresponsive() {
    // MSG's APDUs before the one the user confirms.
    for silent in 0..3 {
        // Main's own deadline: its failed "unresponsive" at 15 s.
        let mut main = Main::new();
        main.submit(1, MSG, 0);
        main.submit(2, MSG_OTHER, 0);
        let (sent, ends) = run(&mut main, MSG, 1, 0, |index, _| {
            if index == silent {
                Act::Silent
            } else {
                Act::Device
            }
        });
        assert!(ends.is_empty());
        let out = sent.last().unwrap();
        assert_eq!(out.deadline_ms, APDU);
        let ends = main.failed(out.core, "unresponsive", APDU);
        assert_eq!(summary(&ends), [(1, "LEDGER_UNRESPONSIVE")]);
        assert!(matches!(
            &ends[0].outcome,
            Outcome::Done(Err(failure)) if failure.cause == Cause::Failed(Failed::Unresponsive)
        ));
        // Nothing to cancel; the next one starts.
        assert_eq!(main.out().parent, 2);

        // Main silent: the core's own timer, 1 s longer.
        let mut main = Main::new();
        main.submit(1, MSG, 0);
        main.submit(2, MSG_OTHER, 0);
        let (sent, _) = run(&mut main, MSG, 1, 0, |index, _| {
            if index == silent {
                Act::Silent
            } else {
                Act::Device
            }
        });
        let out = sent.last().unwrap().clone();
        assert_eq!(main.wakeup(), Some(CORE_APDU));
        assert!(main.tick(APDU).is_empty());
        assert!(main.tick(CORE_APDU - 1).is_empty());
        let ends = main.tick(CORE_APDU);
        assert_eq!(summary(&ends), [(1, "LEDGER_UNRESPONSIVE")]);
        assert_eq!(
            ends[0].outcome,
            Outcome::Lane(LaneEnd::NoAnswer { confirm: false })
        );
        // Its APDU cancelled and watched; the next one starts.
        let wrote = main.wrote();
        assert_eq!(wrote[0], Wrote::Cancel(out.core));
        assert!(matches!(&wrote[1..], [Wrote::Apdu(next)] if next.parent == 2));
        assert_eq!(main.overdue(), Some(CORE_APDU + 60_000));
        // The device's late answer is dropped.
        let late = device(MSG, &out.apdu);
        assert!(main.answer(out.core, &late, CORE_APDU + 1).is_empty());
        assert_eq!(main.overdue(), None);
    }
    // An answer within the core's second is taken.
    let mut main = Main::new();
    main.submit(1, MSG, 0);
    let first = main.out();
    main.wrote();
    let ends = main.answer(first.core, &device(MSG, &first.apdu), CORE_APDU - 1);
    assert!(ends.is_empty());
    let (_, ends) = run_device(&mut main, MSG, 1, CORE_APDU - 1);
    assert_eq!(summary(&ends), [(1, "signed")]);
}

/// Discovery with its check of the records no device has matched (D1).
const RECORDS: &str = "discovery-records-mixed";

/// [`RECORDS`]' operation as L3 builds it: discovery's two paths, then the
/// path of each of its four records at a scheme's path.
fn submit_checking(main: &mut Main, parent: u64, ms: u64) -> Ends {
    let paths: Vec<LedgerPath> = case(RECORDS)["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|record| LedgerPath::parse(record["path"].as_str()?).ok())
        .collect();
    assert_eq!(paths.len(), 4);
    let operation = operation(RECORDS).checking(paths).unwrap();
    let at = main.at(ms);
    main.lane.submit(parent, operation, RECORDS, Turn::Now, at)
}

/// `end` is discovery's accounts, as recorded, its check failed with
/// `code` by the lane's own end of an APDU (D1).
fn check_lapsed(end: &Ended<&'static str>, code: LedgerCode, lapse: Lapse) {
    let Outcome::Done(Ok(signed)) = &end.outcome else {
        panic!("{:?}", end.outcome);
    };
    assert!(as_recorded(RECORDS, signed), "{signed:?}");
    let Signed::Accounts(found) = signed else {
        panic!("{signed:?}");
    };
    let failure = found.checks.as_ref().unwrap_err();
    assert_eq!(
        (failure.code, &failure.cause),
        (code, &Cause::Lapsed(lapse))
    );
}

/// The lane's own end of an APDU of discovery's check (D1) ends only the
/// check, as main's `{ failed }` there would: no answer by the core's
/// timer, or an APDU that couldn't go, ends discovery with its accounts.
/// At discovery's own APDUs the operation ends with the lane's end, as
/// before, and a cancel during the check is a cancel.
#[test]
fn the_lanes_own_end_of_a_check_leaves_discovery_answered() {
    // Main silent at each APDU: discovery's two, then the check's four.
    for silent in 0..6 {
        let mut main = Main::new();
        assert!(submit_checking(&mut main, 1, 0).is_empty());
        let (sent, ends) = run(&mut main, RECORDS, 1, 0, |index, _| {
            if index == silent {
                Act::Silent
            } else {
                Act::Device
            }
        });
        assert!(ends.is_empty());
        assert_eq!(sent.len(), silent + 1);
        let out = sent[silent].clone();
        assert_eq!(main.wakeup(), Some(CORE_APDU));
        assert!(main.tick(CORE_APDU - 1).is_empty());
        let ends = main.tick(CORE_APDU);
        let [end] = ends.as_slice() else {
            panic!("{silent}: {ends:?}");
        };
        assert_eq!((end.parent, end.then), (1, RECORDS));
        if silent < 2 {
            assert_eq!(
                end.outcome,
                Outcome::Lane(LaneEnd::NoAnswer { confirm: false }),
                "{silent}"
            );
            assert_eq!(summary(&ends), [(1, "LEDGER_UNRESPONSIVE")]);
        } else {
            check_lapsed(end, LedgerCode::Unresponsive, Lapse::NoAnswer);
        }
        // Either way its APDU is cancelled, and nothing more goes.
        assert_eq!(main.wrote(), [Wrote::Cancel(out.core)], "{silent}");
        assert_eq!(main.wakeup(), None);
    }

    // An APDU main's gate has no room for, past its 15 s and the margin:
    // discovery's second fails the operation, a check's only the check.
    // Nothing was out, so nothing is cancelled.
    for blocked in [1, 2, 5] {
        let mut main = Main::with_room(1);
        assert!(submit_checking(&mut main, 1, 0).is_empty());
        let (sent, _) = run(&mut main, RECORDS, 1, 0, |index, _| {
            if index + 1 == blocked {
                Act::Silent
            } else {
                Act::Device
            }
        });
        let last = sent[blocked - 1].clone();
        // Main answers the one before; another owner's request takes the
        // slot first.
        assert_eq!(main.requests.answered(last.core), Some(Owner::Ledger));
        let (_slot, _rx) = filler(&main);
        let answer = json!({ "answer": hex(&device(RECORDS, &last.apdu)) }).to_string();
        let at = main.at(10);
        assert!(
            main.lane
                .answered(last.core, Ok(&answer), at)
                .unwrap()
                .is_empty()
        );
        assert!(main.wrote().is_empty());
        assert_eq!(main.wakeup(), Some(10 + CORE_APDU));
        assert!(main.tick(10 + CORE_APDU - 1).is_empty());
        let ends = main.tick(10 + CORE_APDU);
        let [end] = ends.as_slice() else {
            panic!("{blocked}: {ends:?}");
        };
        if blocked < 2 {
            assert_eq!(end.outcome, Outcome::Lane(LaneEnd::Unsent), "{blocked}");
        } else {
            check_lapsed(end, LedgerCode::Unknown, Lapse::Unsent);
        }
        assert!(main.wrote().is_empty(), "{blocked}");
    }

    // The core exiting as a check's APDU would go: only the check fails.
    let mut main = Main::new();
    assert!(submit_checking(&mut main, 1, 0).is_empty());
    let (sent, _) = run(&mut main, RECORDS, 1, 0, |index, _| {
        if index == 1 { Act::Silent } else { Act::Device }
    });
    main.requests.close();
    let ends = main.answer(sent[1].core, &device(RECORDS, &sent[1].apdu), 10);
    let [end] = ends.as_slice() else {
        panic!("{ends:?}");
    };
    check_lapsed(end, LedgerCode::Unknown, Lapse::Unsent);

    // The parent's cancel during the check: cancelled, its APDU cancelled.
    let mut main = Main::new();
    assert!(submit_checking(&mut main, 1, 0).is_empty());
    let (sent, _) = run(&mut main, RECORDS, 1, 0, |index, _| {
        if index == 3 { Act::Silent } else { Act::Device }
    });
    let ends = main.cancel(1, 10);
    assert_eq!(summary(&ends), [(1, "cancelled")]);
    assert_eq!(ends[0].outcome, Outcome::Cancelled);
    assert_eq!(main.wrote(), [Wrote::Cancel(sent[3].core)]);
    assert_eq!(main.wakeup(), None);
}

/// Case `id` run to the APDU the user confirms, at `ms`, left out.
fn to_confirm(main: &mut Main, id: &str, parent: u64, ms: u64) -> Sent {
    let (sent, ends) = run(main, id, parent, ms, |_, apdu| {
        if apdu.deadline_ms == CONFIRM {
            Act::Silent
        } else {
            Act::Device
        }
    });
    assert!(ends.is_empty(), "{ends:?}");
    sent.last().unwrap().clone()
}

#[test]
fn the_users_answer_at_4_59_999_signs_and_at_5_00_is_timeout() {
    for id in [MSG, ADD] {
        // The answer at 4:59.999 signs.
        let mut main = Main::new();
        main.submit(1, id, 0);
        let out = to_confirm(&mut main, id, 1, 0);
        assert_eq!(out.deadline_ms, CONFIRM);
        assert!(main.tick(CONFIRM - 1).is_empty());
        let ends = main.answer(out.core, &device(id, &out.apdu), CONFIRM - 1);
        assert_eq!(summary(&ends), [(1, "signed")]);
        let Outcome::Done(Ok(signed)) = &ends[0].outcome else {
            panic!();
        };
        assert!(as_recorded(id, signed));

        // At 5:00, main's own deadline: its failed "timeout".
        let mut main = Main::new();
        main.submit(1, id, 0);
        let out = to_confirm(&mut main, id, 1, 0);
        assert!(main.tick(CONFIRM).is_empty());
        let ends = main.failed(out.core, "timeout", CONFIRM);
        assert_eq!(summary(&ends), [(1, "LEDGER_TIMEOUT")]);

        // Main silent: the core's own timer, 1 s longer.
        let mut main = Main::new();
        main.submit(1, id, 0);
        let out = to_confirm(&mut main, id, 1, 0);
        assert_eq!(main.wakeup(), Some(CORE_CONFIRM));
        assert!(main.tick(CORE_CONFIRM - 1).is_empty());
        let ends = main.tick(CORE_CONFIRM);
        assert_eq!(summary(&ends), [(1, "LEDGER_TIMEOUT")]);
        assert_eq!(
            ends[0].outcome,
            Outcome::Lane(LaneEnd::NoAnswer { confirm: true })
        );
        assert_eq!(main.wrote(), [Wrote::Cancel(out.core)]);
        // The user's answer after it is dropped: nothing returned.
        let late = device(id, &out.apdu);
        assert!(main.answer(out.core, &late, CORE_CONFIRM + 1).is_empty());
        assert!(main.wrote().is_empty());
    }
}

/// [`ADD`] runs from 0 and is answered at `waited`, while [`MSG`], which
/// came at 0, waits behind it: its first APDU goes at `waited`.
fn queued_for(main: &mut Main, waited: u64) {
    assert!(main.submit(1, ADD, 0).is_empty());
    let running = main.out();
    main.wrote();
    assert!(main.submit(2, MSG, 0).is_empty());
    let ends = main.answer(running.core, &device(ADD, &running.apdu), waited);
    assert_eq!(summary(&ends), [(1, "signed")]);
}

/// Question 5, decided 2026-11-28 ("separate limits"): a wait in the queue
/// doesn't count against the 5 minutes to confirm. However long a request
/// waited for its first APDU, short of the lane's limit, the APDU the user
/// confirms has its full 5 minutes on main's exchange and the core's
/// second, and every other APDU its 15 s and the second.
#[test]
fn a_wait_in_the_queue_leaves_the_confirmation_its_full_five_minutes() {
    for waited in [0, 60_000, 180_000, 240_000, LIMIT - 1] {
        // The core's own timer: 3 minutes in line still leave all 5 (and
        // the margin) from the moment the APDU goes.
        let mut main = Main::new();
        queued_for(&mut main, waited);
        // Its first APDU, which the user doesn't confirm: 15 s and the
        // margin, from when it went.
        let first = main.out();
        assert_eq!((first.parent, first.deadline_ms), (2, APDU), "{waited}");
        assert_eq!(main.wakeup(), Some(waited + CORE_APDU), "{waited}");
        let out = to_confirm(&mut main, MSG, 2, waited);
        assert_eq!(out.deadline_ms, CONFIRM, "{waited}");
        let end = waited + CORE_CONFIRM;
        assert_eq!(main.wakeup(), Some(end), "{waited}");
        assert!(main.tick(end - 1).is_empty(), "{waited}");
        let ends = main.tick(end);
        assert_eq!(summary(&ends), [(2, "LEDGER_TIMEOUT")], "{waited}");
        assert_eq!(
            ends[0].outcome,
            Outcome::Lane(LaneEnd::NoAnswer { confirm: true })
        );
        assert_eq!(main.wrote(), [Wrote::Cancel(out.core)], "{waited}");

        // The user's answer in the core's last millisecond signs.
        let mut main = Main::new();
        queued_for(&mut main, waited);
        let out = to_confirm(&mut main, MSG, 2, waited);
        assert!(main.tick(end - 1).is_empty(), "{waited}");
        let ends = main.answer(out.core, &device(MSG, &out.apdu), end - 1);
        assert_eq!(summary(&ends), [(2, "signed")], "{waited}");
        let Outcome::Done(Ok(signed)) = &ends[0].outcome else {
            panic!("{waited}: {:?}", ends[0].outcome);
        };
        assert!(as_recorded(MSG, signed), "{waited}");

        // Main's own deadline, 5 minutes after the APDU went: its failed
        // "timeout".
        let mut main = Main::new();
        queued_for(&mut main, waited);
        let out = to_confirm(&mut main, MSG, 2, waited);
        assert!(main.tick(waited + CONFIRM).is_empty(), "{waited}");
        let ends = main.failed(out.core, "timeout", waited + CONFIRM);
        assert_eq!(summary(&ends), [(2, "LEDGER_TIMEOUT")], "{waited}");
    }

    // At the lane's limit the wait ends on its own, `LEDGER_BUSY`, with
    // nothing sent for it: the running one's answer at 5:00 is too late.
    let mut main = Main::new();
    assert!(main.submit(1, ADD, 0).is_empty());
    let running = main.out();
    main.wrote();
    assert!(main.submit(2, MSG, 0).is_empty());
    let ends = main.answer(running.core, &device(ADD, &running.apdu), LIMIT);
    assert_eq!(summary(&ends), [(2, "LEDGER_BUSY"), (1, "signed")]);
    assert_eq!(ends[0].outcome, Outcome::Lane(LaneEnd::QueueLimit));
    assert!(main.wrote().is_empty(), "nothing went for it");
    assert_eq!(main.wakeup(), None);
}

#[test]
fn a_queued_request_never_waits_past_the_lanes_limit() {
    let mut main = Main::new();
    main.submit(1, ADD, 0);
    let running = main.out();
    main.wrote();
    main.submit(2, MSG, 500);
    main.submit(3, MSG_OTHER, 1_000);
    assert_eq!(main.wakeup(), Some(500 + LIMIT));
    assert!(main.tick(500 + LIMIT - 1).is_empty());
    let ends = main.tick(500 + LIMIT);
    assert_eq!(summary(&ends), [(2, "LEDGER_BUSY")]);
    assert_eq!(ends[0].outcome, Outcome::Lane(LaneEnd::QueueLimit));
    assert!(main.wrote().is_empty(), "nothing went for it");
    // The third's limit, and the first's own timer, fall together.
    assert_eq!(main.wakeup(), Some(CORE_CONFIRM));
    let ends = main.tick(CORE_CONFIRM);
    assert_eq!(summary(&ends), [(3, "LEDGER_BUSY"), (1, "LEDGER_TIMEOUT")]);
    assert_eq!(main.wrote(), [Wrote::Cancel(running.core)]);
    assert_eq!(main.wakeup(), None);
    // Main's late answer to the first is dropped.
    assert!(
        main.failed(running.core, "timeout", CORE_CONFIRM)
            .is_empty()
    );
    // Every one of a full queue, each at its own limit, in order.
    let mut main = Main::new();
    main.submit(100, ADD, 0);
    main.wrote();
    for parent in 1..=8 {
        main.submit(parent, MSG, parent);
    }
    for parent in 1..=8 {
        let limit = parent + LIMIT;
        assert_eq!(main.wakeup(), Some(limit));
        assert!(main.tick(limit - 1).is_empty());
        assert_eq!(summary(&main.tick(limit)), [(parent, "LEDGER_BUSY")]);
    }
    assert!(main.wrote().is_empty());
    assert_eq!(main.wakeup(), Some(CORE_CONFIRM));

    // A first APDU main's gate has no room for counts as a wait in line:
    // it ends at the limit, never sent.
    let mut main = Main::with_room(1);
    let (_slot, _rx) = filler(&main);
    assert!(main.submit(1, MSG, 0).is_empty());
    assert!(main.wrote().is_empty());
    assert_eq!(main.wakeup(), Some(LIMIT));
    assert!(main.tick(LIMIT - 1).is_empty());
    let ends = main.tick(LIMIT);
    assert_eq!(summary(&ends), [(1, "LEDGER_BUSY")]);
    assert_eq!(ends[0].outcome, Outcome::Lane(LaneEnd::QueueLimit));
    assert!(main.wrote().is_empty());

    // Room before the limit: the gate wakes the lane, and it goes.
    let mut main = Main::with_room(1);
    let (slot, _rx) = filler(&main);
    main.submit(1, MSG, 0);
    assert!(main.wrote().is_empty());
    assert!(!main.woken.load(Ordering::SeqCst));
    assert_eq!(main.requests.answered(slot), Some(Owner::Chain));
    assert!(main.woken.load(Ordering::SeqCst));
    assert!(main.tick(LIMIT - 1).is_empty());
    let (_, ends) = run_device(&mut main, MSG, 1, LIMIT - 1);
    assert_eq!(summary(&ends), [(1, "signed")]);
}

#[test]
fn a_cancel_before_the_first_apdu_sends_nothing() {
    // Waiting in line.
    let mut main = Main::new();
    main.submit(1, ADD, 0);
    let running = main.out();
    main.wrote();
    main.submit(2, MSG, 0);
    let ends = main.cancel(2, 10);
    assert_eq!(summary(&ends), [(2, "cancelled")]);
    assert_eq!(ends[0].then, MSG);
    assert!(main.wrote().is_empty());
    let ends = main.answer(running.core, &device(ADD, &running.apdu), 20);
    assert_eq!(summary(&ends), [(1, "signed")]);
    assert!(main.wrote().is_empty(), "it never starts");
    assert_eq!(main.wakeup(), None);

    // Its first APDU waiting for room at main's gate.
    let mut main = Main::with_room(1);
    let (slot, _rx) = filler(&main);
    main.submit(1, MSG, 0);
    assert_eq!(summary(&main.cancel(1, 10)), [(1, "cancelled")]);
    main.requests.answered(slot);
    assert!(main.tick(20).is_empty());
    assert!(main.wrote().is_empty());
    assert_eq!(main.wakeup(), None);
    assert_eq!(main.overdue(), None);

    // A parent the lane doesn't hold.
    assert!(main.cancel(99, 30).is_empty());
}

#[test]
fn a_cancel_between_two_apdus_cancels_the_one_out() {
    let mut main = Main::new();
    main.submit(1, MSG, 0);
    main.submit(2, MSG_OTHER, 0);
    // The address check answered, B0 01 out.
    let (sent, _) = run(&mut main, MSG, 1, 0, |index, _| {
        if index == 1 { Act::Silent } else { Act::Device }
    });
    let out = sent[1].clone();
    assert_eq!(out.apdu[..2], [0xb0, 0x01]);
    let ends = main.cancel(1, 10);
    assert_eq!(summary(&ends), [(1, "cancelled")]);
    // Its APDU cancelled, watched for 60 s; the next one starts.
    let wrote = main.wrote();
    assert_eq!(wrote[0], Wrote::Cancel(out.core));
    assert!(matches!(&wrote[1..], [Wrote::Apdu(next)] if next.parent == 2));
    main.backlog.extend(wrote[1..].iter().cloned());
    assert_eq!(main.overdue(), Some(10 + 60_000));
    // Main's late answer, the device's, is dropped.
    assert!(
        main.answer(out.core, &device(MSG, &out.apdu), 20)
            .is_empty()
    );
    assert_eq!(main.overdue(), None);
    let (_, ends) = run_device(&mut main, MSG_OTHER, 2, 30);
    assert_eq!(summary(&ends), [(2, "signed")]);

    // Between two with the next waiting for room at main's gate: nothing is
    // out, so nothing is cancelled.
    let mut main = Main::with_room(1);
    main.submit(1, MSG, 0);
    let first = main.out();
    main.wrote();
    assert_eq!(main.requests.answered(first.core), Some(Owner::Ledger));
    let (slot, _rx) = filler(&main);
    let answer = json!({ "answer": hex(&device(MSG, &first.apdu)) }).to_string();
    let at = main.at(10);
    assert!(
        main.lane
            .answered(first.core, Ok(&answer), at)
            .unwrap()
            .is_empty()
    );
    assert!(main.wrote().is_empty());
    assert_eq!(summary(&main.cancel(1, 20)), [(1, "cancelled")]);
    main.requests.answered(slot);
    assert!(main.tick(30).is_empty());
    assert!(main.wrote().is_empty());
    assert_eq!(main.overdue(), None);
}

#[test]
fn a_cancel_during_the_users_wait_returns_nothing() {
    for late in ["signature", "cancelled"] {
        let mut main = Main::new();
        main.submit(1, MSG, 0);
        main.submit(2, ADD, 0);
        let out = to_confirm(&mut main, MSG, 1, 0);
        let ends = main.cancel(1, 100_000);
        assert_eq!(summary(&ends), [(1, "cancelled")]);
        assert_eq!(ends[0].then, MSG);
        let wrote = main.wrote();
        assert_eq!(wrote[0], Wrote::Cancel(out.core));
        let [Wrote::Apdu(next)] = &wrote[1..] else {
            panic!("{wrote:?}");
        };
        assert_eq!(next.parent, 2);
        assert_eq!(main.overdue(), Some(100_000 + 60_000));
        // Main's answer, the user's signature or its cancelled, comes late:
        // dropped, and never taken for the next operation.
        let ends = match late {
            "signature" => main.answer(out.core, &device(MSG, &out.apdu), 100_001),
            _ => main.cancelled(out.core, 100_001),
        };
        assert!(ends.is_empty());
        assert!(main.wrote().is_empty());
        // The next one waited 100 s for its first APDU, which the user
        // confirms: it still has its full 5 minutes and the margin
        // (question 5).
        assert_eq!(next.deadline_ms, CONFIRM);
        assert_eq!(main.wakeup(), Some(100_000 + CORE_CONFIRM));
        let ends = main.answer(next.core, &device(ADD, &next.apdu), 100_002);
        assert_eq!(summary(&ends), [(2, "signed")]);
    }
}

#[test]
fn an_unplug_at_each_apdu_gives_disconnected() {
    for id in CASES {
        let mut main = Main::new();
        main.submit(1, id, 0);
        let (all, _) = run_device(&mut main, id, 1, 0);
        for at in 0..all.len() {
            let mut main = Main::new();
            main.submit(1, id, 0);
            main.submit(2, MSG_OTHER, 0);
            let (sent, ends) = run(&mut main, id, 1, 0, |index, _| {
                if index == at {
                    failed("disconnected")
                } else {
                    Act::Device
                }
            });
            assert_eq!(sent.len(), at + 1, "{id} #{at}: nothing after it");
            assert_eq!(summary(&ends), [(1, "LEDGER_DISCONNECTED")], "{id} #{at}");
            assert!(matches!(
                &ends[0].outcome,
                Outcome::Done(Err(failure)) if failure.cause == Cause::Failed(Failed::Disconnected)
            ));
            // The next one starts with its own address check, nothing
            // cancelled.
            let next = main.out();
            assert_eq!(next.parent, 2);
            assert_eq!(next.apdu[..4], [0xe0, 0x02, 0x00, 0x00]);
            let (_, ends) = run_device(&mut main, MSG_OTHER, 2, 1);
            assert_eq!(summary(&ends), [(2, "signed")]);
        }
    }
}

#[test]
fn a_stale_answer_is_refused_bad_signature() {
    let mut main = Main::new();
    main.submit(1, MSG, 0);
    main.submit(2, MSG_OTHER, 0);
    let (sent, ends) = run_device(&mut main, MSG, 1, 0);
    assert_eq!(summary(&ends), [(1, "signed")]);
    let previous = device(MSG, &sent.last().unwrap().apdu);
    // The device answers the next operation's signing APDU with the
    // previous operation's signature.
    let (_, ends) = run(&mut main, MSG_OTHER, 2, 1, |_, apdu| {
        if apdu.deadline_ms == CONFIRM {
            Act::Reply(Ok(json!({ "answer": hex(&previous) })))
        } else {
            Act::Device
        }
    });
    assert_eq!(summary(&ends), [(2, "LEDGER_BAD_SIGNATURE")]);
    assert!(matches!(
        &ends[0].outcome,
        Outcome::Done(Err(failure)) if failure.cause == Cause::Signature(SignatureFault::Signer)
    ));
}

#[test]
fn mains_refusal_of_an_apdu_ends_unknown() {
    let mut main = Main::new();
    main.submit(1, MSG, 0);
    main.submit(2, MSG_OTHER, 0);
    let refusal = json!({
        "code": "invalid_argument",
        "message": "Invalid argument",
        "data": { "rule": "payload" },
    });
    let (sent, ends) = run(&mut main, MSG, 1, 0, |index, _| {
        if index == 2 {
            Act::Reply(Err(refusal.clone()))
        } else {
            Act::Device
        }
    });
    assert_eq!(sent.len(), 3);
    assert_eq!(summary(&ends), [(1, "LEDGER_UNKNOWN")]);
    assert_eq!(main.out().parent, 2);
}

#[test]
fn a_6d00_without_hash_only_ends_unknown_with_nothing_more_sent() {
    // Q23: the hash-only APDU goes only after main's hash_only: "shown".
    let mut main = Main::new();
    main.submit(1, HASH_ONLY, 0);
    main.submit(2, MSG_OTHER, 0);
    let (sent, ends) = run(&mut main, HASH_ONLY, 1, 0, |_, apdu| {
        if apdu.apdu[..2] == [0xe0, 0x1a] {
            Act::Reply(Ok(json!({ "answer": "6d00" })))
        } else {
            Act::Device
        }
    });
    assert_eq!(sent.len(), 3);
    assert_eq!(summary(&ends), [(1, "LEDGER_UNKNOWN")]);
    assert!(matches!(
        &ends[0].outcome,
        Outcome::Done(Err(failure)) if failure.cause == Cause::HashOnlyNotShown
    ));
    // Nothing more of its own: the next one's address check.
    let next = main.out();
    assert_eq!((next.parent, &next.apdu[..2]), (2, &[0xe0, 0x02][..]));
}

#[test]
fn a_reply_that_breaks_the_rules_is_a_protocol_error() {
    let start = |main: &mut Main| {
        main.submit(1, MSG, 0);
        let out = main.out();
        main.wrote();
        out
    };
    // An unknown member.
    let mut main = Main::new();
    let out = start(&mut main);
    let reply = Ok(json!({ "answer": "9000", "extra": 1 }));
    let fault = main.reply(out.core, reply, 1).unwrap_err();
    assert_eq!(fault, Protocol::Reply(Fault::Form));
    assert_eq!(fault.category(), "ledger_reply_form");
    // hash_only on an answer that isn't to the first E0 1A.
    let mut main = Main::new();
    let out = start(&mut main);
    let reply = Ok(json!({ "answer": "6d00", "hash_only": "shown" }));
    assert_eq!(
        main.reply(out.core, reply, 1).unwrap_err(),
        Protocol::Reply(Fault::HashOnly)
    );
    // Main's cancelled for an APDU the lane didn't cancel.
    let mut main = Main::new();
    let out = start(&mut main);
    let reply = Err(json!({ "code": "cancelled", "message": "Cancelled" }));
    let fault = main.reply(out.core, reply, 1).unwrap_err();
    assert_eq!(fault, Protocol::Uncancelled);
    assert_eq!(fault.category(), "ledger_uncancelled");
    // A late answer is read as strictly.
    let mut main = Main::new();
    let out = start(&mut main);
    main.cancel(1, 1);
    let reply = Ok(json!({ "answer": "zz" }));
    assert_eq!(
        main.reply(out.core, reply, 2).unwrap_err(),
        Protocol::Reply(Fault::Type)
    );
    // An answer to no APDU of the lane's.
    let mut main = Main::new();
    start(&mut main);
    let at = main.at(1);
    let fault = main
        .lane
        .answered(999, Ok(r#"{"answer":"9000"}"#), at)
        .unwrap_err();
    assert_eq!(fault, Protocol::Unasked);
}

#[test]
fn the_lanes_bounds() {
    // 8 in line, 5 minutes at most there, and apart from it (question 5)
    // each APDU's deadline_ms and the core's second.
    assert_eq!(MAX_WAITING, 8);
    assert_eq!(MAX_QUEUE_WAIT, Duration::from_secs(300));
    assert_eq!(MARGIN, Duration::from_secs(1));
    assert_eq!(apdu_time(false), Duration::from_millis(CORE_APDU));
    assert_eq!(apdu_time(true), Duration::from_millis(CORE_CONFIRM));
}
