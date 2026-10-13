//! `chain.html` on the machine (design 0006, `chain.html`): the `web3:`
//! handler's read, checked against the reference's own recording of it
//! (`boundary-html-8mib-through-quorum` in `vectors/chain-replay.json`) and
//! dweb.json's documents; today's errors and the gate's class; and the
//! request's lifecycle and budget, which are the chain machine's.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fc_chain::machine::{
    Answer, Bounds, Call, ChainConfig, ChainError, Effect, Emitted, HTML_TOO_LARGE_CODE, HtmlClass,
    Machine, Origin, Protocol, QuorumConfig, Reply, Request, RpcEndpoint, Success,
};
use serde_json::Value as Json;

const MIB: usize = 1 << 20;
const CONTRACT: &str = "0x5555555555555555555555555555555555555555";
const ORIGIN: &str = "web3://0x5555555555555555555555555555555555555555:1";

/// The machine and what it emitted.
struct World {
    machine: Machine,
    /// `(io id, endpoint, body)` of every `shell.rpc`, in order.
    rpcs: Vec<(u64, String, String)>,
    cancels: Vec<u64>,
    replies: Vec<Reply>,
}

impl World {
    fn new(bounds: Bounds, chain: ChainConfig) -> Self {
        let mut machine = Machine::new(0, bounds);
        machine.configure(&[chain]);
        Self {
            machine,
            rpcs: Vec::new(),
            cancels: Vec::new(),
            replies: Vec::new(),
        }
    }

    fn collect(&mut self) {
        self.machine.poll();
        for Emitted { effect, .. } in self.machine.take_effects() {
            match effect {
                Effect::Request {
                    id,
                    request: Request::Rpc { endpoint, body, .. },
                    ..
                } => self.rpcs.push((id, endpoint, body)),
                Effect::Request { request, .. } => panic!("unexpected {request:?}"),
                Effect::Cancel { id, .. } => self.cancels.push(id),
            }
        }
        self.replies.extend(self.machine.take_replies());
    }

    fn run(&mut self, until: u64) {
        loop {
            self.collect();
            if self.machine.fire_next(until).is_none() {
                break;
            }
        }
        self.collect();
    }

    fn submit(&mut self, call: Call) -> u64 {
        let id = self.machine.submit(call, None);
        self.collect();
        id
    }

    fn answer(&mut self, io: u64, body: Vec<u8>) {
        self.machine.complete(io, Answer::Rpc { status: 200, body });
        self.collect();
    }

    fn reply(&self, id: u64) -> &Reply {
        self.replies
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("no reply for {id}"))
    }
}

fn chain(read: &[&str], rpc: &[(&str, bool)], k: &str, m: &str) -> ChainConfig {
    ChainConfig {
        chain_id: 1,
        display_name: "Ethereum".into(),
        read_order: read.iter().map(|s| (*s).to_owned()).collect(),
        broadcast_order: vec!["direct".into()],
        quorum: QuorumConfig {
            k: Some(k.into()),
            m: Some(m.into()),
            timeout_ms: Some("5000".into()),
        },
        rpc: rpc
            .iter()
            .map(|(endpoint, user_configured)| RpcEndpoint {
                endpoint: (*endpoint).to_owned(),
                user_configured: *user_configured,
            })
            .collect(),
        prover: None,
        myotis: false,
        blockscout: None,
    }
}

fn html_call() -> Call {
    Call::Html {
        chain_id: 1,
        contract: CONTRACT.into(),
        origin: ORIGIN.into(),
    }
}

/// A JSON-RPC answer whose `result` is `json`, held at exactly its length.
fn answer(json: &str) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":1,"result":{json}}}"#)
        .into_bytes()
        .into_boxed_slice()
        .into_vec()
}

/// `html()`'s ABI answer for `document`, as a hex string.
fn encoded(document: &[u8]) -> String {
    let mut out = String::from("0x");
    out.push_str(&format!("{:064x}", 32));
    out.push_str(&format!("{:064x}", document.len()));
    out.push_str(&hex::encode(document));
    let pad = document.len().div_ceil(32) * 32 - document.len();
    out.push_str(&"00".repeat(pad));
    out
}

fn document(reply: &Reply) -> (&str, [u8; 32], &'static str, bool, Option<&str>, HtmlClass) {
    match &reply.result {
        Ok(Success::Html {
            html,
            hash,
            source,
            verified,
            trust,
            class,
        }) => (html, *hash, source, *verified, trust.as_deref(), *class),
        other => panic!("{other:?}"),
    }
}

/// The thrown error's message and its own `code`, if any.
fn thrown(reply: &Reply) -> (String, Option<String>) {
    match &reply.result {
        Err(ChainError::Thrown(error)) => {
            assert_eq!(error.origin, Origin::Core, "{error:?}");
            assert_eq!(error.class.constructor(), "Error");
            let code = error
                .prop("code")
                .and_then(|p| p.json())
                .map(|json| serde_json::from_str::<String>(json).unwrap());
            (error.message.to_string_lossy(), code)
        }
        other => panic!("{other:?}"),
    }
}

fn protocol(reply: &Reply) -> Option<Protocol> {
    match &reply.result {
        Err(ChainError::Protocol(code)) => Some(*code),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The reference's recording

fn replay_scenario(id: &str) -> Json {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/chain-replay.json"
    );
    let vectors: Json = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == id)
        .cloned()
        .unwrap()
}

/// A recorded text in its repeat form: head, then the unit `count` times,
/// then tail.
fn expand(repeat: &Json) -> String {
    let unit = repeat["unit"].as_str().unwrap();
    let mut out = String::from(repeat["head"].as_str().unwrap());
    out.push_str(&unit.repeat(repeat["count"].as_u64().unwrap() as usize));
    out.push_str(repeat["tail"].as_str().unwrap());
    out
}

/// dweb.json's document hash for `id`.
fn dweb_hash(id: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/dweb.json");
    let vectors: Json = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    vectors["html"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["id"] == id)
        .map(|h| h["js"]["ok"]["hash"].as_str().unwrap().to_owned())
        .unwrap()
}

#[test]
fn the_read_is_the_web3_handlers() {
    let scenario = replay_scenario("boundary-html-8mib-through-quorum");
    let endpoints = [
        "https://a.example",
        "https://b.example",
        "https://c.example",
    ];
    let config = chain(
        &["quorum", "direct"],
        &endpoints.map(|e| (e, false)),
        "3",
        "2",
    );
    let steps = scenario["steps"].as_array().unwrap();
    for (step, expected) in [(0, Ok(dweb_hash("size-max"))), (1, Err(()))] {
        let recorded = &steps[step];
        let call = &recorded["calls"][0];
        // The reference's call, as `handleOnchainAppRequest` makes it.
        assert_eq!(call["method"], "eth_call");
        assert_eq!(call["include_trust"], true);
        assert_eq!(call["origin"], ORIGIN);
        let mut world = World::new(Bounds::default(), config.clone());
        let id = world.submit(html_call());
        // The same three members asked, with the reference's body.
        let asked: Vec<&str> = world.rpcs.iter().map(|(_, e, _)| e.as_str()).collect();
        assert_eq!(asked, endpoints);
        let params: Json = serde_json::from_str(call["params_json"].as_str().unwrap()).unwrap();
        for (_, _, body) in &world.rpcs {
            let body: Json = serde_json::from_str(body).unwrap();
            assert_eq!(body["method"], "eth_call");
            assert_eq!(body["params"], params);
        }
        let ios: Vec<(u64, String)> = world
            .rpcs
            .iter()
            .map(|(io, endpoint, _)| (*io, endpoint.clone()))
            .collect();
        for (io, endpoint) in ios {
            let result = expand(&recorded["world"]["rpc"][&endpoint]["result_repeat"]);
            world.answer(io, answer(&format!("\"{result}\"")));
        }
        let reply = world.reply(id);
        // The reference's own result: its source and trust level.
        let result = recorded["results"][0]["value"].as_array().unwrap();
        let field = |key: &str| -> Json {
            let entry = result.iter().find(|e| e["key"] == key).unwrap();
            serde_json::from_str(entry["json"].as_str().unwrap()).unwrap()
        };
        match expected {
            Ok(hash) => {
                let (html, digest, source, verified, trust, class) = document(reply);
                assert_eq!(html.len(), 8 * MIB);
                assert!(html.bytes().all(|b| b == b'a'));
                assert_eq!(format!("0x{}", hex::encode(digest)), hash);
                assert_eq!(source, field("source").as_str().unwrap());
                assert_eq!(verified, field("verified").as_bool().unwrap());
                let trust: Json = serde_json::from_str(trust.unwrap()).unwrap();
                assert_eq!(trust["level"], field("trust")["level"]);
                assert_eq!(class, HtmlClass::Trusted);
            }
            // One byte over: today's 413.
            Err(()) => {
                let (message, code) = thrown(reply);
                assert_eq!(message, "html() response exceeds Freedom's 8 MiB limit");
                assert_eq!(code.as_deref(), Some(HTML_TOO_LARGE_CODE));
            }
        }
        // Everything charged is released; the reply counts until taken.
        assert_eq!(world.machine.held(), 0);
    }
}

// ---------------------------------------------------------------------------
// Today's errors and the gate's class

fn direct(user_configured: bool) -> ChainConfig {
    chain(&["direct"], &[("a", user_configured)], "3", "2")
}

/// The reply to `chain.html` when Direct's one endpoint answers `json`.
fn through_direct(json: &str) -> Reply {
    let mut world = World::new(Bounds::default(), direct(false));
    let id = world.submit(html_call());
    assert_eq!(world.rpcs.len(), 1);
    let io = world.rpcs[0].0;
    world.answer(io, answer(json));
    world.reply(id).clone()
}

#[test]
fn an_answer_that_isnt_served_is_todays_error() {
    let words = |hex: &str| format!("\"0x{hex}\"");
    let cases = [
        // `typeof result !== 'string'`.
        ("12", "html() returned malformed ABI data"),
        ("null", "html() returned malformed ABI data"),
        ("{}", "html() returned malformed ABI data"),
        (r#""0xzz""#, "html() returned malformed ABI data"),
        (r#""0x123""#, "invalid BytesLike value"),
        (&words(&"00".repeat(33)), "invalid length for result data"),
        // An offset past the data.
        (
            &words(&format!("{:064x}", 32)),
            "could not decode result data",
        ),
    ];
    for (json, message) in cases {
        let reply = through_direct(json);
        assert_eq!(thrown(&reply), (message.to_owned(), None), "{json}");
    }
    // A body without `result` answers `undefined`: not a string either.
    let mut world = World::new(Bounds::default(), direct(false));
    let id = world.submit(html_call());
    let io = world.rpcs[0].0;
    world.answer(io, br#"{"jsonrpc":"2.0","id":1}"#.to_vec());
    assert_eq!(
        thrown(world.reply(id)).0,
        "html() returned malformed ABI data"
    );
    // A document one byte over 8 MiB that is no ABI string at all: the size
    // is read from the length first.
    let over = format!("\"0x{}\"", "zz".repeat(8 * MIB + 96));
    let (message, code) = thrown(&through_direct(&over));
    assert_eq!(message, "html() response exceeds Freedom's 8 MiB limit");
    assert_eq!(code.as_deref(), Some(HTML_TOO_LARGE_CODE));
}

#[test]
fn a_result_with_escapes_is_the_string_json_parse_makes() {
    let plain = encoded(b"<p>hi</p>");
    // `0` and `x` escaped, built here: a tool would decode the escapes in a
    // literal (see the repo's notes on test inputs).
    let backslash = '\\';
    let escaped = format!("{backslash}u0030{backslash}u0078{}", &plain[2..]);
    assert!(escaped.contains(backslash) && !escaped.starts_with("0x"));
    let reply = through_direct(&format!("\"{escaped}\""));
    let (html, hash, ..) = document(&reply);
    assert_eq!(html, "<p>hi</p>");
    let unescaped = through_direct(&format!("\"{plain}\""));
    assert_eq!(document(&unescaped).1, hash);
    // A lone surrogate is one unit to the size check and no hex digit.
    let lone = format!("\"{backslash}ud800{}\"", &plain[1..]);
    assert_eq!(
        thrown(&through_direct(&lone)).0,
        "html() returned malformed ABI data"
    );
}

#[test]
fn the_class_is_the_gates_input() {
    let page = encoded(b"<b>app</b>");
    let quoted = format!("\"{page}\"");
    // One endpoint: unverified, or user-configured.
    for (user_configured, class) in [(false, HtmlClass::Untrusted), (true, HtmlClass::Trusted)] {
        let mut world = World::new(Bounds::default(), direct(user_configured));
        let id = world.submit(html_call());
        let io = world.rpcs[0].0;
        world.answer(io, answer(&quoted));
        let (html, _, source, verified, trust, got) = document(world.reply(id));
        assert_eq!((html, source, verified), ("<b>app</b>", "direct", false));
        let trust: Json = serde_json::from_str(trust.unwrap()).unwrap();
        let level = if user_configured {
            "user-configured"
        } else {
            "unverified"
        };
        assert_eq!(trust["level"], level);
        assert_eq!(got, class);
    }
    // A quorum that agrees: verified.
    let mut world = World::new(
        Bounds::default(),
        chain(
            &["quorum"],
            &[("a", false), ("b", false), ("c", false)],
            "3",
            "2",
        ),
    );
    let id = world.submit(html_call());
    let ios: Vec<u64> = world.rpcs.iter().map(|(io, ..)| *io).collect();
    for io in &ios[..2] {
        world.answer(*io, answer(&quoted));
    }
    let (_, _, source, verified, _, class) = document(world.reply(id));
    assert_eq!(
        (source, verified, class),
        ("quorum", true, HtmlClass::Trusted)
    );
    // A quorum split, then Direct reusing the lowest member that answered:
    // unverified with a dissenter, a conflict (no approval token).
    let mut world = World::new(
        Bounds::default(),
        chain(
            &["quorum", "direct"],
            &[("a", false), ("b", false), ("c", false)],
            "3",
            "2",
        ),
    );
    let id = world.submit(html_call());
    let ios: Vec<u64> = world.rpcs.iter().map(|(io, ..)| *io).collect();
    world.answer(ios[0], answer(&quoted));
    world.answer(ios[1], answer(&format!("\"{}\"", encoded(b"<b>other</b>"))));
    world.machine.complete(
        ios[2],
        Answer::Failed(fc_chain::machine::Transport::Network),
    );
    world.collect();
    let (html, _, source, verified, trust, class) = document(world.reply(id));
    assert_eq!((html, source, verified), ("<b>app</b>", "direct", false));
    let trust: Json = serde_json::from_str(trust.unwrap()).unwrap();
    assert_eq!(trust["level"], "unverified");
    assert_eq!(trust["dissented"], serde_json::json!([{ "ref": "b" }]));
    assert_eq!(class, HtmlClass::Conflict);
}

// ---------------------------------------------------------------------------
// The chain machine's lifecycle and budget

#[test]
fn cancel_deadline_and_reconfiguration_end_it_as_any_read() {
    let quoted = format!("\"{}\"", encoded(b"x"));
    // A cancel: `cancelled`, its exchange cancelled.
    let mut world = World::new(Bounds::default(), direct(false));
    let id = world.submit(html_call());
    let io = world.rpcs[0].0;
    assert!(world.machine.cancel(id));
    world.collect();
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Cancelled));
    assert_eq!(world.cancels, [io]);
    // The overall deadline: `deadline`, nothing asked after it.
    let mut world = World::new(Bounds::default(), direct(false));
    let id = world.machine.submit(html_call(), Some(1_000));
    world.collect();
    world.run(1_000);
    assert_eq!(protocol(world.reply(id)), Some(Protocol::Deadline));
    // A configuration change: `reconfigured` under the old generation.
    let mut world = World::new(Bounds::default(), direct(false));
    let id = world.submit(html_call());
    world.machine.configure(&[direct(true)]);
    world.collect();
    let reply = world.reply(id);
    assert_eq!(protocol(reply), Some(Protocol::Reconfigured));
    assert_eq!(reply.generation, 1);
    // A late answer is dropped.
    let io = world.rpcs[0].0;
    world.answer(io, answer(&quoted));
    assert_eq!(world.replies.len(), 1);
    // An unconfigured chain: today's thrown error, before any I/O.
    let mut world = World::new(Bounds::default(), direct(false));
    let id = world.submit(Call::Html {
        chain_id: 5,
        contract: CONTRACT.into(),
        origin: ORIGIN.into(),
    });
    assert_eq!(thrown(world.reply(id)).0, "Unsupported chain ID: 5");
    assert!(world.rpcs.is_empty());
}

#[test]
fn the_decode_is_reserved_before_it_is_made() {
    // An 8 MiB document: an answer of 16 MiB and 166 bytes, then the
    // decode's one buffer, 8 MiB and 64 bytes. With 24 MiB the request
    // reads the answer but has no room for the buffer, so it ends with
    // `budget` before the buffer is made; with 25 MiB it has room. Nothing
    // else it holds is near 8 MiB, so the difference is the buffer.
    let page = format!("\"{}\"", encoded(&vec![b'a'; 8 * MIB]));
    for (mib, served) in [(24, false), (25, true)] {
        let bounds = Bounds {
            request_bytes: mib * MIB,
            ..Bounds::default()
        };
        let mut world = World::new(bounds, direct(false));
        let id = world.machine.submit(html_call(), None);
        world.machine.poll();
        let io = world
            .machine
            .take_effects()
            .into_iter()
            .find_map(|e| match e.effect {
                Effect::Request { id, .. } => Some(id),
                Effect::Cancel { .. } => None,
            })
            .unwrap();
        world.machine.complete(
            io,
            Answer::Rpc {
                status: 200,
                body: answer(&page),
            },
        );
        world.machine.poll();
        if served {
            // The reply holds the document, counted as output until the
            // driver takes it.
            assert!(world.machine.held() >= 8 * MIB);
        }
        let replies = world.machine.take_replies();
        assert_eq!(replies[0].id, id);
        if served {
            assert_eq!(document(&replies[0]).0.len(), 8 * MIB);
        } else {
            assert_eq!(protocol(&replies[0]), Some(Protocol::Budget), "{mib} MiB");
        }
        assert_eq!(world.machine.held(), 0);
    }
}
