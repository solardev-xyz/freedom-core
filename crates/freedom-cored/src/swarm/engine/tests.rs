//! The engine through a fake [`Io`]: the door, admission, the deadline,
//! the memory queue and `busy`, each release point, a cancel at each
//! stage, the live facts, a close's bound and main's malformed answers.

#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;
use fc_swarm_provider::machine::Form;
use fc_swarm_provider::machine::{UPLOAD_CHARGE, whole_charge};

const SITE: &str = "https://a.example";
const KIB: usize = 1024;

/// The streams' own tests (SWM-4 PR 6).
mod stream_tests;

/// Main's own methods' tests (SWM-4 PR 9).
mod shell_tests;

#[derive(Default)]
struct Fake {
    next: u64,
    /// What went to main: its ID, method and params.
    sent: Vec<(u64, &'static str, serde_json::Value, usize)>,
    cancels: Vec<u64>,
    checks: Vec<(u64, String, u64)>,
    name_cancels: Vec<u64>,
    answers: Vec<(u64, Answer)>,
    /// The gate is full: nothing goes.
    full: bool,
    /// The core's requests that may open a stream, with its codes.
    opens: BTreeMap<u64, Codes>,
    /// Main's replies to those, and whether each opened its stream.
    replied: Vec<(u64, Option<Option<u64>>)>,
    /// Credit for the core's requests' streams.
    credits: Vec<(u64, usize)>,
    /// The parts of the core's `swarm.body` answers.
    bodies: Vec<(u64, BodyOut)>,
    /// `swarm.body` refusals.
    refused: Vec<(u64, ErrorBody)>,
    /// The stream routes let go of.
    forgotten: Vec<StreamKey>,
    /// Work handed to the hashing pool.
    hashes: Vec<(u64, AskId, Job)>,
    /// `swarm-feeds.json`'s texts written, in order.
    feed_texts: Vec<String>,
    /// The next feed store write fails.
    fail_feeds: bool,
    /// The history's statements run, in order.
    statements: Vec<Statement>,
    /// The vault's asks, by tag.
    vaults: Vec<(u64, VaultAsk)>,
    /// `approval.changed`'s keys, in order.
    changed: Vec<String>,
}

impl Io for Fake {
    fn send(&mut self, outgoing: Outgoing) -> Sent {
        if self.full {
            return Sent::Wait;
        }
        self.next += 1;
        let params = serde_json::from_slice(&outgoing.params).unwrap();
        self.sent
            .push((self.next, outgoing.method, params, outgoing.reply_bound));
        if let Some(codes) = outgoing.opens {
            self.opens.insert(self.next, codes);
        }
        Sent::Id(self.next)
    }
    fn cancel(&mut self, core: u64) {
        self.cancels.push(core);
    }
    fn name_check(&mut self, tag: u64, binding: Binding, deadline_ms: u64) {
        self.checks
            .push((tag, binding.name().to_owned(), deadline_ms));
    }
    fn name_cancel(&mut self, tag: u64) {
        self.name_cancels.push(tag);
    }
    fn answer(&mut self, id: u64, answer: Answer) {
        self.answers.push((id, answer));
    }
    fn wall_ms(&self) -> u64 {
        1_767_225_600_123
    }
    fn replied(&mut self, core: u64, head: Option<Option<u64>>) -> Result<bool, Fault> {
        assert!(self.opens.contains_key(&core), "a reply that opens nothing");
        self.replied.push((core, head));
        // As the duplex: a request the core cancelled retires.
        Ok(!self.cancels.contains(&core))
    }
    fn credit(&mut self, core: u64, bytes: usize) {
        self.credits.push((core, bytes));
    }
    fn body(&mut self, body: u64, out: BodyOut) {
        self.bodies.push((body, out));
    }
    fn body_refuse(&mut self, body: u64, error: ErrorBody) {
        self.refused.push((body, error));
    }
    fn forget(&mut self, key: StreamKey) {
        self.forgotten.push(key);
    }
    fn hash(&mut self, id: u64, ask: AskId, job: Job) {
        self.hashes.push((id, ask, job));
    }
    fn write_feeds(&mut self, text: &str) -> Result<(), JsString> {
        if std::mem::take(&mut self.fail_feeds) {
            return Err(JsString::from("disk full"));
        }
        self.feed_texts.push(text.to_owned());
        Ok(())
    }
    fn save_manifests(&mut self, _save: &Save) -> Result<(), JsString> {
        Ok(())
    }
    fn history(&mut self, statements: &[Statement]) -> Result<(), JsString> {
        self.statements.extend_from_slice(statements);
        Ok(())
    }
    fn history_insert(&mut self, statement: &Statement) -> Result<i64, JsString> {
        self.statements.push(statement.clone());
        Ok(i64::try_from(self.statements.len()).unwrap_or(i64::MAX))
    }
    fn vault(&mut self, tag: u64, ask: VaultAsk) {
        self.vaults.push((tag, ask));
    }
    fn read_manifests(&mut self) -> Option<Vec<u8>> {
        None
    }
    fn read_manifests_backup(&mut self) -> Option<Vec<u8>> {
        None
    }
    fn random(&mut self) -> Option<[u8; 24]> {
        Some([7; 24])
    }
    fn history_rows(&mut self, statement: &Statement) -> Result<Vec<Row>, JsString> {
        self.statements.push(statement.clone());
        Ok(Vec::new())
    }
    fn history_run(&mut self, statement: &Statement) -> Result<usize, JsString> {
        self.statements.push(statement.clone());
        Ok(0)
    }
    fn changed(&mut self, key: &str) {
        self.changed.push(key.to_owned());
    }
}

impl Fake {
    /// The last thing sent: its ID, method and params.
    fn last(&self) -> (u64, &'static str, serde_json::Value) {
        let (id, method, params, _) = self.sent.last().unwrap().clone();
        (id, method, params)
    }

    /// The answer to request `id`, taken.
    fn answer_of(&mut self, id: u64) -> Answer {
        let at = self
            .answers
            .iter()
            .position(|(answered, _)| *answered == id)
            .unwrap_or_else(|| panic!("no answer to {id}: {:?}", self.answers));
        self.answers.remove(at).1
    }
}

/// The Swarm grants: `SITE` connected, with the messaging grant.
fn grants() -> Arc<Mutex<SwarmStore>> {
    let mut store = SwarmStore::new();
    let _ = store.connect(SITE, 1);
    let _ = store.grant_messaging(SITE, 1);
    Arc::new(Mutex::new(store))
}

fn engine(bounds: Bounds) -> Engine {
    Engine::new(bounds, Shared::new(grants(), Bindings::default()), true)
}

fn page(transport_key: Option<&str>) -> PageContext {
    PageContext {
        origin: SITE.to_owned(),
        top_origin: SITE.to_owned(),
        frame: 1,
        navigation: 1,
        agent: Some(false),
        transport_key: transport_key.map(str::to_owned),
    }
}

fn params(method: &str, params: Value, deadline_ms: Option<u64>) -> Result<Params, &'static str> {
    Ok(Params {
        method: Value::str(method),
        params,
        approval: None,
        deadline_ms,
    })
}

/// A content chunk and its reference.
fn chunk() -> (Vec<u8>, String) {
    let payload = b"hello swarm".to_vec();
    let span = (payload.len() as u64).to_le_bytes();
    let address = fc_swarm::verify::address_of(&span, &payload).unwrap();
    let mut wire = span.to_vec();
    wire.extend_from_slice(&payload);
    (wire, address.iter().map(|b| format!("{b:02x}")).collect())
}

fn read_chunk(reference: &str, deadline_ms: Option<u64>) -> Result<Params, &'static str> {
    params(
        "swarm_readChunk",
        Value::object([("reference", Value::str(reference))]),
        deadline_ms,
    )
}

fn ok_ready() -> &'static str {
    r#"{"ok":true}"#
}

fn whole(status: u16, body: &[u8]) -> String {
    serde_json::json!({
        "status": status,
        "status_text": if status == 200 { "OK" } else { "Not Found" },
        "headers": [],
        "body_base64": fc_swarm_provider::value::encode_base64(body),
    })
    .to_string()
}

/// Request `id`, a `readChunk`, to its node call: the engine and main's ID
/// for the call.
fn to_node_call(engine: &mut Engine, io: &mut Fake, id: u64, deadline_ms: Option<u64>) -> u64 {
    let (_, reference) = chunk();
    engine
        .request(
            io,
            0,
            id,
            read_chunk(&reference, deadline_ms),
            Some(page(None)),
        )
        .unwrap();
    let (ready, method, params) = io.last();
    assert_eq!(method, "shell.swarm_ready");
    assert_eq!(
        params,
        serde_json::json!({ "for": id, "check": "reachable" })
    );
    engine.response(io, 0, ready, Ok(ok_ready())).unwrap();
    let (call, method, params) = io.last();
    assert_eq!(method, "shell.swarm_api");
    assert_eq!(params["for"], id);
    assert_eq!(params["form"], "chunk");
    call
}

const BASE: usize = REQUEST_CHARGE;

fn call_charge() -> usize {
    whole_charge(Form::Chunk)
}

#[test]
fn a_read_runs_and_frees_each_charge_at_its_point() {
    let mut engine = engine(Bounds::default());
    let mut io = Fake::default();
    let call = to_node_call(&mut engine, &mut io, 7, None);
    // The base and the call's charge, reserved before the call went; the
    // reply's bound is the form's cap's base64 and the envelope.
    assert_eq!(engine.memory_used(), BASE + call_charge());
    assert_eq!(io.sent.last().unwrap().3, b64(ERROR_BODY) + ENVELOPE);
    let (wire, _) = chunk();
    engine
        .response(&mut io, 0, call, Ok(&whole(200, &wire)))
        .unwrap();
    let Answer::Result(text) = io.answer_of(7) else {
        panic!("a result")
    };
    assert!(text.starts_with(r#"{"result_typed":{"object":["#), "{text}");
    assert!(
        text.contains(r#"["data",{"string":"aGVsbG8gc3dhcm0="}]"#),
        "{text}"
    );
    // The call's charge went with the step that consumed its reply; the
    // base waits for the answer to be written.
    assert_eq!(engine.memory_used(), BASE);
    assert_eq!(engine.requests(), 0);
    engine.written(&mut io, 0, 7).unwrap();
    assert_eq!(engine.memory_used(), 0);
}

#[test]
fn the_door_answers_what_the_core_doesnt_run() {
    let mut io = Fake::default();
    // The Swarm grants haven't moved.
    let mut unmoved = Engine::new(
        Bounds::default(),
        Shared::new(grants(), Bindings::default()),
        false,
    );
    let (_, reference) = chunk();
    unmoved
        .request(
            &mut io,
            0,
            1,
            read_chunk(&reference, None),
            Some(page(None)),
        )
        .unwrap();
    let Answer::Error(error) = io.answer_of(1) else {
        panic!()
    };
    assert_eq!(error.code, ErrorCode::NotMoved);
    assert_eq!(error.data, Some(serde_json::json!({ "store": "swarm" })));

    let mut engine = engine(Bounds::default());
    let cases = [
        ("swarm_listFeeds", ErrorCode::NotMoved),
        ("swarm_publishData", ErrorCode::NotMoved),
        ("swarm_getSigningIdentity", ErrorCode::NotMoved),
        ("swarm_unsubscribe", ErrorCode::InvalidArgument),
    ];
    for (id, (method, code)) in (10..).zip(cases) {
        engine
            .request(
                &mut io,
                0,
                id,
                params(method, Value::Undefined, None),
                Some(page(None)),
            )
            .unwrap();
        let Answer::Error(error) = io.answer_of(id) else {
            panic!("{method}")
        };
        assert_eq!(error.code, code, "{method}");
        if code == ErrorCode::NotMoved {
            assert_eq!(
                error.data,
                Some(serde_json::json!({ "store": "swarm_stores" }))
            );
        }
    }
    // Params main sent wrong, or no page.
    engine
        .request(&mut io, 0, 20, Err("bad"), Some(page(None)))
        .unwrap();
    assert!(matches!(io.answer_of(20), Answer::Error(e) if e.code == ErrorCode::InvalidArgument));
    engine
        .request(&mut io, 0, 21, read_chunk(&reference, None), None)
        .unwrap();
    assert!(matches!(io.answer_of(21), Answer::Error(e) if e.code == ErrorCode::InvalidArgument));
    // A method that isn't one runs: the machine answers it as the
    // reference does.
    engine
        .request(
            &mut io,
            0,
            22,
            params("swarm_mint", Value::Undefined, None),
            Some(page(None)),
        )
        .unwrap();
    assert_eq!(
        io.answer_of(22),
        Answer::Result(wire::error_typed(&Failure::bare(
            4200,
            "Unknown method: swarm_mint"
        )))
    );
    assert!(io.sent.is_empty());
    engine.written(&mut io, 0, 22).unwrap();
    assert_eq!((engine.memory_used(), engine.requests()), (0, 0));
}

#[test]
fn admission_queues_then_answers_busy() {
    let mut engine = engine(Bounds {
        running: 1,
        waiting: 1,
        ..Bounds::default()
    });
    let mut io = Fake::default();
    let (_, reference) = chunk();
    let call = to_node_call(&mut engine, &mut io, 1, None);
    // The second waits for a place: nothing of it goes.
    engine
        .request(
            &mut io,
            0,
            2,
            read_chunk(&reference, None),
            Some(page(None)),
        )
        .unwrap();
    assert_eq!(io.sent.len(), 2);
    assert_eq!(engine.memory_used(), BASE + call_charge());
    // The third finds the queue full: 4900 busy inside `{ error_typed }`.
    engine
        .request(
            &mut io,
            0,
            3,
            read_chunk(&reference, None),
            Some(page(None)),
        )
        .unwrap();
    assert_eq!(
        io.answer_of(3),
        Answer::Result(wire::error_typed(&Failure::busy()))
    );
    // With no room to wait, a request still runs while a place is free.
    let mut direct = super::Engine::new(
        Bounds {
            running: 1,
            waiting: 0,
            ..Bounds::default()
        },
        Shared::new(grants(), Bindings::default()),
        true,
    );
    let mut other = Fake::default();
    to_node_call(&mut direct, &mut other, 1, None);
    direct
        .request(
            &mut other,
            0,
            2,
            read_chunk(&reference, None),
            Some(page(None)),
        )
        .unwrap();
    assert_eq!(
        other.answer_of(2),
        Answer::Result(wire::error_typed(&Failure::busy()))
    );
    // The first's answer frees its place: the second starts.
    let (wire, _) = chunk();
    engine
        .response(&mut io, 0, call, Ok(&whole(200, &wire)))
        .unwrap();
    assert!(matches!(io.answer_of(1), Answer::Result(_)));
    let (_, method, params) = io.last();
    assert_eq!(method, "shell.swarm_ready");
    assert_eq!(params["for"], 2);
}

#[test]
fn the_deadline_cancels_and_main_s_answer_frees_the_call() {
    for terminal in [
        Err(r#"{"code":"cancelled","message":"Cancelled"}"#.to_owned()),
        Ok(whole(200, &chunk().0)),
    ] {
        let mut engine = engine(Bounds::default());
        let mut io = Fake::default();
        let call = to_node_call(&mut engine, &mut io, 1, Some(1000));
        assert_eq!(engine.next_due(), Some(1000));
        engine.tick(&mut io, 999).unwrap();
        assert!(io.answers.is_empty());
        engine.tick(&mut io, 1000).unwrap();
        // The page's timer: `cancelled`, and the call cancelled at main.
        assert_eq!(io.answer_of(1), cancelled());
        assert_eq!(io.cancels, vec![call]);
        // Answered and written: the base goes. The call keeps its charge
        // until main's terminal answer (D13), and the request its record.
        engine.written(&mut io, 1000, 1).unwrap();
        assert_eq!(engine.memory_used(), call_charge());
        assert_eq!(engine.requests(), 1);
        let terminal = terminal
            .as_ref()
            .map(String::as_str)
            .map_err(String::as_str);
        engine.response(&mut io, 1001, call, terminal).unwrap();
        assert_eq!((engine.memory_used(), engine.requests()), (0, 0));
        assert!(io.answers.is_empty(), "one answer");
    }
}

/// A request ended at its deadline, its answer written, while main still
/// owes its cancelled call's answer: its base is another request's to take
/// meanwhile; the call's charge goes only with main's late answer.
#[test]
fn an_ended_request_s_base_goes_before_its_cancelled_call_s_answer() {
    // One base and one call.
    let mut engine = engine(Bounds {
        memory: BASE + call_charge(),
        ..Bounds::default()
    });
    let mut io = Fake::default();
    let call = to_node_call(&mut engine, &mut io, 1, Some(1000));
    engine.tick(&mut io, 1000).unwrap();
    assert_eq!(io.answer_of(1), cancelled());
    // A second request finds no room for its base while the first's is
    // held.
    let (_, reference) = chunk();
    engine
        .request(
            &mut io,
            1000,
            2,
            read_chunk(&reference, None),
            Some(page(None)),
        )
        .unwrap();
    assert_eq!(io.sent.len(), 2, "the second waits for its base");
    // The first's answer written: its base goes to the second, which
    // starts before main's late answer to the cancelled call.
    engine.written(&mut io, 1001, 1).unwrap();
    let (ready, method, params) = io.last();
    assert_eq!(
        (method, params["for"].as_u64()),
        ("shell.swarm_ready", Some(2))
    );
    assert_eq!(engine.memory_used(), BASE + call_charge());
    assert_eq!(engine.requests(), 2);
    // The late answer frees the call's charge and the first's record.
    engine
        .response(
            &mut io,
            1002,
            call,
            Err(r#"{"code":"cancelled","message":"Cancelled"}"#),
        )
        .unwrap();
    assert_eq!(engine.memory_used(), BASE);
    assert_eq!(engine.requests(), 1);
    // The second runs on: its call takes the freed charge.
    engine
        .response(&mut io, 1003, ready, Ok(ok_ready()))
        .unwrap();
    assert_eq!(io.last().1, "shell.swarm_api");
    assert_eq!(engine.memory_used(), BASE + call_charge());
}

#[test]
fn a_charge_waits_first_in_first_out_and_its_deadline_is_busy() {
    // Two bases and one call.
    let mut engine = engine(Bounds {
        memory: 2 * BASE + call_charge(),
        ..Bounds::default()
    });
    let mut io = Fake::default();
    let call = to_node_call(&mut engine, &mut io, 1, None);
    let (_, reference) = chunk();
    engine
        .request(
            &mut io,
            0,
            2,
            read_chunk(&reference, Some(5000)),
            Some(page(None)),
        )
        .unwrap();
    let (ready, _, _) = io.last();
    engine.response(&mut io, 0, ready, Ok(ok_ready())).unwrap();
    // Its call waits for memory: nothing goes.
    assert_eq!(io.last().1, "shell.swarm_ready");
    assert!(stages(&engine, 2).contains("Memory"));
    // A third request's base fits nowhere either: it waits behind.
    engine
        .request(
            &mut io,
            0,
            3,
            read_chunk(&reference, Some(9000)),
            Some(page(None)),
        )
        .unwrap();
    assert_eq!(io.sent.len(), 3);
    // At its deadline, the waiting charge is `busy`; its withdrawal lets
    // the third's base in.
    engine.tick(&mut io, 5000).unwrap();
    assert_eq!(
        io.answer_of(2),
        Answer::Result(wire::error_typed(&Failure::busy()))
    );
    engine.written(&mut io, 5000, 2).unwrap();
    assert_eq!(io.last().2["for"], 3);
    // The first's reply frees its call: the third's goes once it asks.
    engine
        .response(&mut io, 5001, call, Ok(&whole(200, &chunk().0)))
        .unwrap();
    let (ready, _, _) = io.last();
    engine
        .response(&mut io, 5001, ready, Ok(ok_ready()))
        .unwrap();
    assert_eq!(io.last().1, "shell.swarm_api");
    assert_eq!(io.last().2["for"], 3);
}

#[test]
fn a_cancel_at_each_stage_leaves_no_ask_open_and_no_charge_held() {
    let (_, reference) = chunk();
    // Waiting for a place, and for its base.
    {
        let mut engine = engine(Bounds {
            running: 1,
            memory: BASE + call_charge(),
            ..Bounds::default()
        });
        let mut io = Fake::default();
        let call = to_node_call(&mut engine, &mut io, 1, None);
        engine
            .request(
                &mut io,
                0,
                2,
                read_chunk(&reference, None),
                Some(page(None)),
            )
            .unwrap();
        engine.cancel(&mut io, 0, 2).unwrap();
        assert_eq!(io.answer_of(2), cancelled());
        engine.cancel(&mut io, 0, 1).unwrap();
        assert_eq!(io.answer_of(1), cancelled());
        engine
            .response(
                &mut io,
                0,
                call,
                Err(r#"{"code":"cancelled","message":"Cancelled"}"#),
            )
            .unwrap();
        engine.written(&mut io, 0, 1).unwrap();
        assert_eq!((engine.memory_used(), engine.requests()), (0, 0));
    }
    {
        let mut engine = engine(Bounds {
            memory: BASE + call_charge(),
            ..Bounds::default()
        });
        let mut io = Fake::default();
        let call = to_node_call(&mut engine, &mut io, 1, None);
        // No room for the second's base.
        engine
            .request(
                &mut io,
                0,
                2,
                read_chunk(&reference, None),
                Some(page(None)),
            )
            .unwrap();
        assert_eq!(io.sent.len(), 2);
        engine.cancel(&mut io, 0, 2).unwrap();
        assert_eq!(io.answer_of(2), cancelled());
        engine
            .response(&mut io, 0, call, Ok(&whole(200, &chunk().0)))
            .unwrap();
        engine.written(&mut io, 0, 1).unwrap();
        assert_eq!((engine.memory_used(), engine.requests()), (0, 0));
        assert_eq!(io.sent.len(), 2, "the cancelled one never started");
    }
    // Its readiness check sent; its call waiting for memory, for a slot,
    // for the gate, and sent.
    for stage in ["ready", "memory", "slot", "gate", "sent"] {
        let mut engine = engine(Bounds {
            memory: 3 * BASE + call_charge(),
            api: 1,
            ..Bounds::default()
        });
        let mut io = Fake::default();
        let first = to_node_call(&mut engine, &mut io, 1, None);
        engine
            .request(
                &mut io,
                0,
                2,
                read_chunk(&reference, None),
                Some(page(None)),
            )
            .unwrap();
        let (ready, _, _) = io.last();
        let mut open = vec![first];
        match stage {
            "ready" => open.push(ready),
            "memory" => {
                // The first's call holds all the room for calls.
                engine.response(&mut io, 0, ready, Ok(ok_ready())).unwrap();
                assert!(stages(&engine, 2).contains("Memory"), "{stage}");
            }
            "slot" => {
                engine.memory = Pool::new(usize::MAX);
                engine.memory.reserve(Waiter::Base(1), BASE);
                engine.memory.reserve(Waiter::Base(2), BASE);
                engine
                    .memory
                    .reserve(Waiter::Ask(1, AskId(2)), call_charge());
                engine.response(&mut io, 0, ready, Ok(ok_ready())).unwrap();
                assert!(stages(&engine, 2).contains("Slot"), "{stage}");
            }
            "gate" => {
                engine.bounds.api = 2;
                io.full = true;
                engine.memory = Pool::new(usize::MAX);
                engine.memory.reserve(Waiter::Base(1), BASE);
                engine.memory.reserve(Waiter::Base(2), BASE);
                engine
                    .memory
                    .reserve(Waiter::Ask(1, AskId(2)), call_charge());
                engine.response(&mut io, 0, ready, Ok(ok_ready())).unwrap();
                assert!(stages(&engine, 2).contains("Outbox"), "{stage}");
            }
            _ => {
                engine.bounds.api = 2;
                engine.memory = Pool::new(usize::MAX);
                engine.memory.reserve(Waiter::Base(1), BASE);
                engine.memory.reserve(Waiter::Base(2), BASE);
                engine
                    .memory
                    .reserve(Waiter::Ask(1, AskId(2)), call_charge());
                engine.response(&mut io, 0, ready, Ok(ok_ready())).unwrap();
                let (call, method, _) = io.last();
                assert_eq!(method, "shell.swarm_api");
                open.push(call);
            }
        }
        engine.cancel(&mut io, 0, 2).unwrap();
        assert_eq!(io.answer_of(2), cancelled(), "{stage}");
        io.full = false;
        engine.cancel(&mut io, 0, 1).unwrap();
        assert_eq!(io.answer_of(1), cancelled(), "{stage}");
        // Main answers each cancelled ask; nothing else was sent.
        let mut cancels = io.cancels.clone();
        cancels.sort_unstable();
        open.sort_unstable();
        assert_eq!(cancels, open, "{stage}");
        for core in open {
            engine
                .response(
                    &mut io,
                    0,
                    core,
                    Err(r#"{"code":"cancelled","message":"Cancelled"}"#),
                )
                .unwrap();
        }
        engine.written(&mut io, 0, 1).unwrap();
        engine.written(&mut io, 0, 2).unwrap();
        engine.room(&mut io, 0).unwrap();
        assert_eq!(
            (engine.memory_used(), engine.requests(), engine.api_open),
            (0, 0, 0),
            "{stage}"
        );
        assert!(
            engine.sent.is_empty() && engine.outbox.is_empty(),
            "{stage}"
        );
    }
}

/// `getUploadStatus` of a tag the site owns: the tag read, then the live
/// facts: a name check, then main's recheck.
fn upload_status(engine: &mut Engine, io: &mut Fake, id: u64, binding: Option<&str>) -> u64 {
    engine.shared_mut().tags.set(7, JsString::from(SITE));
    engine
        .request(
            io,
            0,
            id,
            params(
                "swarm_getUploadStatus",
                Value::object([("tagUid", Value::int(7))]),
                Some(60_000),
            ),
            Some(page(binding)),
        )
        .unwrap();
    let (call, method, params) = io.last();
    assert_eq!(method, "shell.swarm_api");
    assert_eq!(params["path"], "/tags/7");
    let tag = br#"{"uid":7,"split":4,"seen":0,"stored":4,"sent":4,"synced":4,"address":"","startedAt":"2026-01-01T00:00:00Z"}"#;
    engine.response(io, 10, call, Ok(&whole(200, tag))).unwrap();
    call
}

#[test]
fn the_live_facts_check_the_name_then_ask_main() {
    let mut engine = engine(Bounds::default());
    let mut io = Fake::default();
    upload_status(&mut engine, &mut io, 1, Some("ipns://k51abc"));
    // The name first, within what is left of the request's time.
    let (tag, name, deadline) = io.checks.pop().unwrap();
    assert_eq!(tag & NAME_TAG, NAME_TAG);
    assert_eq!((name.as_str(), deadline), (SITE, 60_000 - 10));
    let sent = io.sent.len();
    engine
        .named(&mut io, 20, tag, crate::eip1193::Verdict::Holds)
        .unwrap();
    // Then main's recheck of the document.
    let (recheck, method, params) = io.last();
    assert_eq!(io.sent.len(), sent + 1);
    assert_eq!(method, "approval.recheck");
    assert_eq!(params["request"], 1);
    assert_eq!(params["page"]["transport_key"], "ipns://k51abc");
    engine
        .response(&mut io, 21, recheck, Ok(r#"{"live":true,"agent":false}"#))
        .unwrap();
    let Answer::Result(text) = io.answer_of(1) else {
        panic!()
    };
    assert!(text.starts_with(r#"{"result_typed":"#), "{text}");
    assert!(!text.contains("no_address"), "{text}");

    // A name that moved answers with no recheck: NO_ADDRESS.
    upload_status(&mut engine, &mut io, 2, Some("ipns://k51abc"));
    let (tag, _, _) = io.checks.pop().unwrap();
    let sent = io.sent.len();
    engine
        .named(&mut io, 20, tag, crate::eip1193::Verdict::Fails)
        .unwrap();
    assert_eq!(io.sent.len(), sent);
    let Answer::Result(text) = io.answer_of(2) else {
        panic!()
    };
    assert!(text.contains("no_address"), "{text}");

    // No binding: main's recheck alone; a document gone is NO_ADDRESS.
    upload_status(&mut engine, &mut io, 3, None);
    assert!(io.checks.is_empty());
    let (recheck, method, _) = io.last();
    assert_eq!(method, "approval.recheck");
    engine
        .response(&mut io, 21, recheck, Ok(r#"{"live":false,"agent":false}"#))
        .unwrap();
    let Answer::Result(text) = io.answer_of(3) else {
        panic!()
    };
    assert!(text.contains("no_address"), "{text}");

    // Main refusing the recheck itself refuses the effect, as APR-5 does;
    // an answer of no known shape ends the connection.
    upload_status(&mut engine, &mut io, 5, None);
    let (recheck, _, _) = io.last();
    engine
        .response(
            &mut io,
            21,
            recheck,
            Err(r#"{"code":"not_authorized","message":"no such request"}"#),
        )
        .unwrap();
    let Answer::Result(text) = io.answer_of(5) else {
        panic!()
    };
    assert!(text.contains("no_address"), "{text}");
    engine.written(&mut io, 22, 5).unwrap();

    // Cancelled while its name is checked: the check is withdrawn. (Another
    // document: the moved name above ended this one's binding.)
    upload_status(&mut engine, &mut io, 4, Some("ipns://k51def"));
    let (tag, _, _) = io.checks.pop().unwrap();
    engine.cancel(&mut io, 30, 4).unwrap();
    assert_eq!(io.name_cancels, vec![tag]);
    assert_eq!(io.answer_of(4), cancelled());
    // A verdict that crossed the cancel changes nothing.
    engine
        .named(&mut io, 31, tag, crate::eip1193::Verdict::Holds)
        .unwrap();
    for id in 1..=4 {
        engine.written(&mut io, 40, id).unwrap();
    }
    assert_eq!((engine.memory_used(), engine.requests()), (0, 0));
}

/// The page's document, as the ended-binding record names it.
fn document() -> Document {
    Document::new(SITE, "ipns://k51abc", 1, 1)
}

/// A failed check ends the document's binding for good, for every later
/// check of either family (D1): a lookup that holds afterwards, a late one
/// among them, can't revive it; a binding the loop's EIP-1193 check ended
/// refuses with nothing resolved; a failure here is the loop's to read.
#[test]
fn a_failed_name_check_ends_the_binding_for_every_family() {
    let bindings = Bindings::default();
    let mut engine = Engine::new(
        Bounds::default(),
        Shared::new(grants(), bindings.clone()),
        true,
    );
    let mut io = Fake::default();
    // Two requests of one document, each with its lookup out.
    upload_status(&mut engine, &mut io, 1, Some("ipns://k51abc"));
    upload_status(&mut engine, &mut io, 2, Some("ipns://k51abc"));
    let (late, _, _) = io.checks.pop().unwrap();
    let (first, _, _) = io.checks.pop().unwrap();
    let sent = io.sent.len();
    engine
        .named(&mut io, 20, first, crate::eip1193::Verdict::Fails)
        .unwrap();
    // The loop's EIP-1193 checks read the ended binding.
    assert!(bindings.has(&document()));
    // The late lookup holds: the binding stays ended, and no recheck goes.
    engine
        .named(&mut io, 21, late, crate::eip1193::Verdict::Holds)
        .unwrap();
    assert_eq!(io.sent.len(), sent, "no recheck");
    for id in [1, 2] {
        let Answer::Result(text) = io.answer_of(id) else {
            panic!()
        };
        assert!(text.contains("no_address"), "{id}: {text}");
    }
    // The document's next request resolves nothing.
    upload_status(&mut engine, &mut io, 3, Some("ipns://k51abc"));
    assert!(io.checks.is_empty(), "nothing resolved");
    assert_eq!(io.sent.len(), sent + 1, "its tag read only");
    let Answer::Result(text) = io.answer_of(3) else {
        panic!()
    };
    assert!(text.contains("no_address"), "{text}");
    // A new document of the same page binds again.
    assert!(!bindings.has(&Document::new(SITE, "ipns://k51abc", 1, 2)));

    // A binding the loop ended (an EIP-1193 check that failed): the swarm
    // thread's check fails with nothing resolved.
    let bindings = Bindings::default();
    bindings.end(&document());
    let mut engine = Engine::new(
        Bounds::default(),
        Shared::new(grants(), bindings.clone()),
        true,
    );
    let mut io = Fake::default();
    upload_status(&mut engine, &mut io, 1, Some("ipns://k51abc"));
    assert!(io.checks.is_empty());
    let Answer::Result(text) = io.answer_of(1) else {
        panic!()
    };
    assert!(text.contains("no_address"), "{text}");

    // Ended while main's recheck is out: read again as its answer comes.
    let bindings = Bindings::default();
    let mut engine = Engine::new(
        Bounds::default(),
        Shared::new(grants(), bindings.clone()),
        true,
    );
    let mut io = Fake::default();
    upload_status(&mut engine, &mut io, 1, Some("ipns://k51abc"));
    let (tag, _, _) = io.checks.pop().unwrap();
    engine
        .named(&mut io, 20, tag, crate::eip1193::Verdict::Holds)
        .unwrap();
    let (recheck, method, _) = io.last();
    assert_eq!(method, "approval.recheck");
    bindings.end(&document());
    engine
        .response(&mut io, 21, recheck, Ok(r#"{"live":true,"agent":false}"#))
        .unwrap();
    let Answer::Result(text) = io.answer_of(1) else {
        panic!()
    };
    assert!(text.contains("no_address"), "{text}");

    // The request's deadline on naming's clock ends no binding; a
    // transport key that isn't `ipns://<key>` fails with nothing resolved,
    // and ends none either.
    let bindings = Bindings::default();
    let mut engine = Engine::new(
        Bounds::default(),
        Shared::new(grants(), bindings.clone()),
        true,
    );
    let mut io = Fake::default();
    upload_status(&mut engine, &mut io, 1, Some("ipns://k51abc"));
    let (tag, _, _) = io.checks.pop().unwrap();
    engine
        .named(&mut io, 20, tag, crate::eip1193::Verdict::Deadline)
        .unwrap();
    assert_eq!(io.answer_of(1), cancelled());
    assert!(!bindings.has(&document()));
    upload_status(&mut engine, &mut io, 2, Some("ipns://k5_1"));
    assert!(io.checks.is_empty());
    let Answer::Result(text) = io.answer_of(2) else {
        panic!()
    };
    assert!(text.contains("no_address"), "{text}");
    assert!(!bindings.has(&Document::new(SITE, "ipns://k5_1", 1, 1)));
}

/// An answer handled at or after its request's deadline is the deadline's
/// (Codex round 2 on #498): a naming verdict that fails then answers
/// `cancelled` and ends no binding, as a deadline ends nothing, and main's
/// recheck then lets no effect go.
#[test]
fn an_answer_at_the_deadline_is_the_deadline_s() {
    let bindings = Bindings::default();
    let mut engine = Engine::new(
        Bounds::default(),
        Shared::new(grants(), bindings.clone()),
        true,
    );
    let mut io = Fake::default();
    // A 60,000 ms request whose name check is out when its deadline comes,
    // and whose verdict the thread handles at it, before any tick.
    upload_status(&mut engine, &mut io, 1, Some("ipns://k51abc"));
    let (tag, _, _) = io.checks.pop().unwrap();
    engine
        .named(&mut io, 60_000, tag, crate::eip1193::Verdict::Fails)
        .unwrap();
    assert_eq!(io.answer_of(1), cancelled());
    assert!(!bindings.has(&document()), "a deadline ends no binding");
    assert_eq!(io.name_cancels, vec![tag]);

    // Main's recheck answered at the deadline: `cancelled`, not the
    // effect's answer.
    upload_status(&mut engine, &mut io, 2, Some("ipns://k51abc"));
    let (tag, _, _) = io.checks.pop().unwrap();
    engine
        .named(&mut io, 20, tag, crate::eip1193::Verdict::Holds)
        .unwrap();
    let (recheck, method, _) = io.last();
    assert_eq!(method, "approval.recheck");
    engine
        .response(
            &mut io,
            60_000,
            recheck,
            Ok(r#"{"live":true,"agent":false}"#),
        )
        .unwrap();
    assert_eq!(io.answer_of(2), cancelled());
    assert!(io.answers.is_empty(), "one answer");
    for id in [1, 2] {
        engine.written(&mut io, 60_001, id).unwrap();
    }
    assert_eq!((engine.memory_used(), engine.requests()), (0, 0));
}

/// A PSS subscription to its open: the subscribe check, the guard's live
/// facts, then main's open.
fn subscribed(engine: &mut Engine, io: &mut Fake, id: u64) -> u64 {
    engine
        .request(
            io,
            0,
            id,
            params(
                "swarm_subscribe",
                Value::object([("kind", Value::str("pss")), ("topic", Value::str("chat"))]),
                None,
            ),
            Some(page(None)),
        )
        .unwrap();
    let (ready, method, params) = io.last();
    assert_eq!(
        (method, &params["check"]),
        ("shell.swarm_ready", &"subscribe".into())
    );
    engine.response(io, 0, ready, Ok(ok_ready())).unwrap();
    let (recheck, method, _) = io.last();
    assert_eq!(method, "approval.recheck");
    engine
        .response(io, 0, recheck, Ok(r#"{"live":true,"agent":false}"#))
        .unwrap();
    let (open, method, params) = io.last();
    assert_eq!(method, "shell.swarm_subscribe");
    assert_eq!(params["kind"], "pss");
    assert_eq!(params["for"], id);
    open
}

#[test]
fn a_subscription_opens_inside_the_request_and_its_close_is_bounded() {
    let mut engine = engine(Bounds::default());
    let mut io = Fake::default();
    let open = subscribed(&mut engine, &mut io, 1);
    engine
        .response(&mut io, 0, open, Ok(r#"{"id":"sub-1"}"#))
        .unwrap();
    // The live facts again once it is open; the document has gone, so main
    // closes it, and only then does the page get NO_ADDRESS.
    let (recheck, _, _) = io.last();
    engine
        .response(&mut io, 0, recheck, Ok(r#"{"live":false,"agent":false}"#))
        .unwrap();
    let (close, method, params) = io.last();
    assert_eq!(method, "shell.swarm_unsubscribe");
    assert_eq!(params, serde_json::json!({ "id": "sub-1" }));
    assert!(io.answers.is_empty());
    assert_eq!(
        engine.next_due(),
        Some(fc_swarm_provider::machine::CLOSE_BOUND_MS)
    );
    engine.response(&mut io, 5, close, Ok("{}")).unwrap();
    let Answer::Result(text) = io.answer_of(1) else {
        panic!()
    };
    assert!(text.contains("no_address"), "{text}");
    engine.written(&mut io, 5, 1).unwrap();
    assert_eq!((engine.memory_used(), engine.requests()), (0, 0));

    // A close main doesn't answer within its bound ends the connection.
    let open = subscribed(&mut engine, &mut io, 2);
    engine.cancel(&mut io, 100, 2).unwrap();
    assert_eq!(io.answer_of(2), cancelled());
    assert_eq!(io.cancels, vec![open]);
    // The open answers after the cancel: what it opened is closed.
    engine
        .response(&mut io, 200, open, Ok(r#"{"id":"sub-2"}"#))
        .unwrap();
    let (_, method, params) = io.last();
    assert_eq!(method, "shell.swarm_unsubscribe");
    assert_eq!(params["id"], "sub-2");
    engine.tick(&mut io, 200 + 59_999).unwrap();
    assert_eq!(
        engine.tick(&mut io, 200 + 60_000),
        Err(Fault("swarm_close_unanswered"))
    );
}

#[test]
fn main_s_malformed_answers_end_the_connection() {
    let (_, reference) = chunk();
    let mut io = Fake::default();
    let ready_of = |engine: &mut Engine, io: &mut Fake, id: u64| {
        engine
            .request(io, 0, id, read_chunk(&reference, None), Some(page(None)))
            .unwrap();
        io.last().0
    };
    let mut engine = engine(Bounds::default());
    let ready = ready_of(&mut engine, &mut io, 1);
    assert_eq!(
        engine.response(&mut io, 0, ready, Ok(r#"{"ok":"yes"}"#)),
        Err(Fault("swarm_reply"))
    );
    let ready = ready_of(&mut engine, &mut io, 2);
    // A refusal of a check that wasn't cancelled.
    assert_eq!(
        engine.response(
            &mut io,
            0,
            ready,
            Err(r#"{"code":"cancelled","message":"Cancelled"}"#)
        ),
        Err(Fault("swarm_reply"))
    );
    // An answer to nothing the thread asked.
    assert_eq!(
        engine.response(&mut io, 0, 999, Ok(ok_ready())),
        Err(Fault("swarm_unsolicited"))
    );
    // A chunk past its form's cap: the machine's bound, a protocol error.
    let call = to_node_call(&mut engine, &mut io, 3, None);
    assert_eq!(
        engine.response(&mut io, 0, call, Ok(&whole(200, &[0; 4202]))),
        Err(Fault("swarm_reply_bounds"))
    );
    // Main's grammar refusing a call is the method's internal error, not a
    // protocol error.
    let call = to_node_call(&mut engine, &mut io, 4, None);
    engine
        .response(
            &mut io,
            0,
            call,
            Err(r#"{"code":"invalid_argument","message":"m","data":{"rule":"value"}}"#),
        )
        .unwrap();
    assert_eq!(
        io.answer_of(4),
        Answer::Result(wire::error_typed(&Failure::internal_error()))
    );
}

#[test]
fn a_topic_and_an_upload_turn_go_in_order() {
    let mut locks: Locks<u32> = Locks::default();
    let topic = [1; 32];
    assert!(locks.take(topic, 1, 10));
    assert!(locks.take(topic, 1, 11), "its holder asks again");
    assert!(!locks.take(topic, 2, 20));
    assert!(!locks.take(topic, 3, 30));
    assert!(locks.take([2; 32], 4, 40));
    // The second waiter went before its turn: the third gets it.
    assert_eq!(
        locks.release(topic, 1, |w| (*w != 20).then_some(u64::from(*w / 10))),
        Some(30)
    );
    assert_eq!(locks.release(topic, 1, |_| Some(9)), None, "not its holder");
    assert_eq!(locks.release(topic, 3, |_| Some(9)), None);
    assert_eq!(locks.held(), 1);

    // Through the engine: a request's topic is its until its answer, and
    // an upload's turn holds its charge until then too.
    let mut engine = engine(Bounds {
        uploads: 1,
        ..Bounds::default()
    });
    let mut io = Fake::default();
    let call = to_node_call(&mut engine, &mut io, 1, None);
    let (_, reference) = chunk();
    engine
        .request(
            &mut io,
            0,
            2,
            read_chunk(&reference, None),
            Some(page(None)),
        )
        .unwrap();
    engine.ask(&mut io, 0, 1, AskId(50), Need::Lock(topic), 0);
    engine.ask(&mut io, 0, 2, AskId(50), Need::Lock(topic), 0);
    engine.ask(&mut io, 0, 1, AskId(51), Need::Upload, UPLOAD_CHARGE);
    engine.ask(&mut io, 0, 2, AskId(51), Need::Upload, UPLOAD_CHARGE);
    let ready: Vec<_> = engine
        .ready
        .drain(..)
        .map(|(id, ask, _)| (id, ask))
        .collect();
    assert_eq!(ready, vec![(1, AskId(50)), (1, AskId(51))]);
    assert_eq!(engine.topics_held(), 1);
    assert_eq!(
        engine.memory_used(),
        2 * BASE + call_charge() + 2 * UPLOAD_CHARGE
    );
    assert!(stages(&engine, 2).contains("Turn"));
    // The first's answer hands both on to the second, and frees its
    // upload's charge.
    engine.end_holdings(&mut io, 1);
    let ready: Vec<_> = engine
        .ready
        .iter()
        .map(|(id, ask, _)| (*id, *ask))
        .collect();
    assert_eq!(ready, vec![(2, AskId(51)), (2, AskId(50))]);
    assert_eq!(
        engine.memory_used(),
        2 * BASE + call_charge() + UPLOAD_CHARGE
    );
    let _ = call;
}

#[test]
fn a_gsoc_search_finds_mining_off_until_the_lane() {
    let mut engine = engine(Bounds::default());
    let mut io = Fake::default();
    engine
        .request(
            &mut io,
            0,
            1,
            params(
                "swarm_subscribe",
                Value::object([("kind", Value::str("gsoc")), ("topic", Value::str("chat"))]),
                None,
            ),
            Some(page(None)),
        )
        .unwrap();
    let (ready, _, _) = io.last();
    engine.response(&mut io, 0, ready, Ok(ok_ready())).unwrap();
    let Answer::Result(text) = io.answer_of(1) else {
        panic!()
    };
    assert!(text.contains("mining is off"), "{text}");
    let _ = KIB;
}
