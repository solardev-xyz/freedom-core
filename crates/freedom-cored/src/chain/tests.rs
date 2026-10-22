//! The chain thread's own logic: params, wire forms, main's answers, the
//! writer allowance and the request queue. `tests/chain.rs` runs the same
//! through the real binary.

use super::*;
use crate::transport::Pending;
use serde_json::{Value, json};

/// What the writer got: whole messages as JSON, a fragmented response as
/// its payload's JSON with a marker. Reading a frame frees its allowance.
fn written(rx: &mpsc::Receiver<Out>) -> Vec<Value> {
    let mut out = Vec::new();
    while let Ok(item) = rx.try_recv() {
        match item {
            Out::Frame { frame, .. } => out.push(serde_json::from_slice(&frame[5..]).unwrap()),
            Out::Fragmented { payload, .. } => {
                let mut value: Value = serde_json::from_slice(&payload).unwrap();
                value["fragmented"] = json!(true);
                out.push(value);
            }
            Out::Credit => {}
        }
    }
    out
}

struct Test {
    chain: Chain,
    rx: mpsc::Receiver<Out>,
    link: Arc<Link>,
    /// The thread's clock, which the test moves.
    clock: std::rc::Rc<std::cell::Cell<u64>>,
}

/// A thread whose writer shares, bulk and control, are `writer_bytes`
/// each.
fn test_with(bounds: Bounds, writer_bytes: usize, outstanding: usize, offered: bool) -> Test {
    test_shares(bounds, (writer_bytes, writer_bytes), outstanding, offered)
}

fn test_shares(
    bounds: Bounds,
    (bulk, control): (usize, usize),
    outstanding: usize,
    offered: bool,
) -> Test {
    let (out, rx) = mpsc::channel();
    let link = Link::new();
    if offered {
        link.offer();
    }
    let clock = std::rc::Rc::new(std::cell::Cell::new(0));
    let now = std::rc::Rc::clone(&clock);
    let chain = Chain::new(
        Machine::new(0, bounds),
        out,
        Arc::clone(&link),
        Shares {
            bulk: Allowance::new(usize::MAX, bulk),
            control: Allowance::new(usize::MAX, control),
        },
        Requests::new(outstanding, Arc::new(Pending::default())),
        Box::new(move || now.get()),
    );
    Test {
        chain,
        rx,
        link,
        clock,
    }
}

fn test() -> Test {
    test_with(Bounds::default(), usize::MAX, 256, true)
}

impl Test {
    fn call(&mut self, id: u64, method: &'static str, params: &Value) {
        let params = RawValue::from_string(params.to_string()).unwrap();
        assert!(
            self.chain
                .handle(In::Request {
                    id,
                    method,
                    params: Some(params),
                })
                .is_ok()
        );
        assert!(self.chain.flush().is_ok());
    }

    /// Main's response, as the event loop routes it: the message, with
    /// the span of its result.
    fn answer(&mut self, id: u64, outcome: Result<Value, ErrorBody>) -> Flow {
        assert_eq!(self.chain.requests.answered(id), Some(Owner::Chain));
        let reply = match outcome {
            Ok(result) => shell_result(id, &result.to_string()),
            Err(error) => shell_error(id, &serde_json::to_string(&error).unwrap()),
        };
        self.chain.handle(In::Response { id, reply })?;
        self.chain.flush()
    }

    /// Moves the clock to `now`, and flushes.
    fn at(&mut self, now: u64) {
        self.clock.set(now);
        assert!(self.chain.flush().is_ok());
    }

    fn written(&self) -> Vec<Value> {
        written(&self.rx)
    }

    fn configure(&mut self, chains: Value) -> Value {
        self.call(1, "chain.configure", &json!({ "chains": chains }));
        let frames = self.written();
        frames.into_iter().find(|f| f["id"] == 1).unwrap()
    }
}

/// A JSON `\\u` escape of `hex`, made at run time.
fn u(hex: &str) -> String {
    format!("{}u{hex}", '\\')
}

/// A response message as the reader hands it over, with its result's span.
fn shell_result(id: u64, result: &str) -> Shell {
    let prefix = format!(r#"{{"type":"response","id":{id},"result":"#);
    let mut message = Zeroizing::new(prefix.clone().into_bytes());
    message.extend_from_slice(result.as_bytes());
    message.push(b'}');
    Shell::Result {
        message,
        result: prefix.len()..prefix.len() + result.len(),
    }
}

/// A response message carrying `error`, as the reader hands it over.
fn shell_error(id: u64, error: &str) -> Shell {
    let prefix = format!(r#"{{"type":"response","id":{id},"error":"#);
    let mut message = Zeroizing::new(prefix.clone().into_bytes());
    message.extend_from_slice(error.as_bytes());
    message.push(b'}');
    Shell::Failed {
        message,
        error: prefix.len()..prefix.len() + error.len(),
    }
}

/// Main's terminal reply as the machine's answer, for a request nobody
/// owns (so nothing is charged); `None` when it is malformed.
fn answer(kind: Kind, outcome: Result<Box<RawValue>, ErrorBody>) -> Option<Answer> {
    let error;
    let shape = match &outcome {
        Err(body) => {
            error = serde_json::to_string(body).unwrap();
            Shape::failed(&error)?
        }
        Ok(raw) => Shape::parse(kind, raw.get())?,
    };
    let machine = Machine::new(0, Bounds::default());
    shape.read(&machine, 1).ok().map(|(answer, _)| answer)
}

fn chain_snapshot(read: &[&str], rpc: &[&str]) -> Value {
    json!({
        "chain_id": 1,
        "display_name": "Ethereum",
        "read_order": read,
        "broadcast_order": ["direct"],
        "quorum": { "k": 3, "m": 2, "timeout_ms": 5000 },
        "rpc": rpc.iter().map(|e| json!({ "endpoint": e, "user_configured": false })).collect::<Vec<_>>(),
        "prover": null,
        "myotis": false,
        "blockscout": null,
    })
}

fn read(id: u64, method: &str, params: Value) -> (u64, Value) {
    (
        id,
        json!({
            "chain_id": 1,
            "method": method,
            "params": params,
            "include_trust": false,
            "background": false,
            "profile": "default",
            "deadline_ms": 60_000,
        }),
    )
}

fn rpc_answer(body: &str) -> Result<Value, ErrorBody> {
    Ok(json!({
        "status": 200,
        "body": base64::engine::general_purpose::STANDARD.encode(body),
    }))
}

fn requests(frames: &[Value]) -> Vec<&Value> {
    frames.iter().filter(|f| f["type"] == "request").collect()
}

#[test]
fn configure_is_validated_strictly() {
    let mut t = test();
    let ok = chain_snapshot(&["quorum"], &["a", "b", "c"]);
    let result = t.configure(json!([ok.clone()]));
    assert_eq!(result["result"], json!({ "generations": { "1": 1 } }));
    // The same snapshot changes nothing; another one advances its chain.
    assert_eq!(
        t.configure(json!([ok.clone()]))["result"],
        json!({ "generations": { "1": 1 } })
    );
    let mut other = ok.clone();
    other["quorum"]["k"] = json!("2");
    assert_eq!(
        t.configure(json!([other]))["result"],
        json!({ "generations": { "1": 2 } })
    );
    // Quorum values stay raw: any JSON, clamped by the machine. Unknown
    // and repeated sources are the machine's to drop.
    let mut raw = ok.clone();
    raw["quorum"] = json!({ "k": 50, "m": null, "timeout_ms": "abc" });
    raw["read_order"] = json!(["quorum", "nope", "quorum"]);
    assert!(t.configure(json!([raw]))["result"].is_object());
    let mut many = ok.clone();
    many["rpc"] = (0..65)
        .map(|i| json!({ "endpoint": format!("e{i}"), "user_configured": false }))
        .collect();
    let mut unknown = ok.clone();
    unknown["extra"] = json!(1);
    let mut huge_id = ok.clone();
    huge_id["chain_id"] = json!(1u64 << 53);
    let mut no_order = ok.clone();
    no_order.as_object_mut().unwrap().remove("read_order");
    // `prover` and `blockscout` are required, `null` when absent.
    let mut no_prover = ok.clone();
    no_prover.as_object_mut().unwrap().remove("prover");
    let mut no_blockscout = ok.clone();
    no_blockscout.as_object_mut().unwrap().remove("blockscout");
    // Positional arrays where objects belong, at any depth.
    let positional: Vec<Value> = ok.as_object().unwrap().values().cloned().collect();
    let mut array_rpc = ok.clone();
    array_rpc["rpc"] = json!([["a", false]]);
    let mut array_prover = ok.clone();
    array_prover["prover"] = json!(["p1", true]);
    let mut array_quorum = ok.clone();
    array_quorum["quorum"] = json!([3, 2, 5000]);
    for chains in [
        json!([many]),
        json!([unknown]),
        json!([huge_id]),
        json!([no_order]),
        json!([no_prover]),
        json!([no_blockscout]),
        json!([positional]),
        json!([array_rpc]),
        json!([array_prover]),
        json!([array_quorum]),
        json!([ok.clone(), ok.clone()]),
        json!("nope"),
    ] {
        let reply = t.configure(chains.clone());
        assert_eq!(reply["error"]["code"], "invalid_argument", "{chains}");
    }
    // At most 64 endpoints is fine.
    let mut both = ok.clone();
    both["prover"] = json!({ "endpoint": "p1", "zk": true });
    both["blockscout"] = json!({ "endpoint": "b1" });
    assert!(t.configure(json!([both]))["result"].is_object());
    let mut sixty_four = ok;
    sixty_four["rpc"] = (0..64)
        .map(|i| json!({ "endpoint": format!("e{i}"), "user_configured": i == 0 }))
        .collect();
    assert!(t.configure(json!([sixty_four]))["result"].is_object());
}

#[test]
fn request_params_are_validated_strictly() {
    let mut t = test();
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let (_, good) = read(0, "eth_blockNumber", json!([]));
    let mut cases = Vec::new();
    for (key, value) in [
        ("deadline_ms", json!(120_001)),
        ("deadline_ms", json!(-1)),
        ("deadline_ms", json!(1.5)),
        ("profile", json!("fast")),
        ("chain_id", json!(1u64 << 53)),
        ("include_trust", json!("yes")),
        ("extra", json!(true)),
    ] {
        let mut params = good.clone();
        params[key] = value;
        cases.push(("chain.request", params));
    }
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("deadline_ms");
    cases.push(("chain.request", missing));
    cases.push(("chain.request", json!([good.clone()])));
    cases.push(("chain.fee_quote", json!({ "chain_id": 1 })));
    cases.push((
        "chain.broadcast",
        json!({ "chain_id": 1, "raw": 7, "deadline_ms": 1000 }),
    ));
    cases.push(("chain.availability", json!({ "chain_id": 1 })));
    for (i, (method, params)) in cases.iter().enumerate() {
        let id = 10 + i as u64;
        t.call(id, method, params);
        let frames = t.written();
        let reply = frames.iter().find(|f| f["id"] == id).unwrap();
        assert_eq!(reply["error"]["code"], "invalid_argument", "{params}");
        assert!(requests(&frames).is_empty());
    }
    // 120 s exactly, and an origin, are fine.
    let mut longest = good;
    longest["deadline_ms"] = json!(120_000);
    longest["origin"] = json!("https://app.example");
    t.call(50, "chain.request", &longest);
    assert_eq!(requests(&t.written()).len(), 1);
}

#[test]
fn a_quorum_read_embeds_the_agreed_answer_as_raw_json() {
    let mut t = test();
    t.configure(json!([chain_snapshot(&["quorum"], &["a", "b", "c"])]));
    let (id, params) = read(7, "eth_call", json!([{ "to": "0xabc" }, "latest"]));
    t.call(id, "chain.request", &params);
    let frames = t.written();
    let asked = requests(&frames);
    assert_eq!(asked.len(), 3);
    for (request, endpoint) in asked.iter().zip(["a", "b", "c"]) {
        assert_eq!(request["method"], "shell.rpc");
        let params = &request["params"];
        assert_eq!(params["endpoint"], endpoint);
        assert_eq!(params["policy"], "plain");
        assert_eq!(params["max_bytes"], 18 * 1024 * 1024);
        assert_eq!(params["generation"], 1);
        assert_eq!(params["deadline_ms"], 5000);
        let body: Value = serde_json::from_str(params["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["method"], "eth_call");
        assert_eq!(body["params"], json!([{ "to": "0xabc" }, "latest"]));
    }
    // Two agree; their text is kept as the first one sent it.
    let ids: Vec<u64> = asked.iter().map(|r| r["id"].as_u64().unwrap()).collect();
    let text = r#"{"jsonrpc":"2.0","id":1,"result":{"b" : 1e2, "a":[ ]}}"#;
    assert!(t.answer(ids[0], rpc_answer(text)).is_ok());
    assert!(
        t.answer(
            ids[1],
            rpc_answer(r#"{"jsonrpc":"2.0","id":2,"result":{"a":[],"b":100}}"#)
        )
        .is_ok()
    );
    t.at(1);
    // The third member is cancelled; the reply is written whole.
    let mut raw = Vec::new();
    while let Ok(Out::Frame { frame, .. }) = t.rx.try_recv() {
        raw.push(String::from_utf8(frame[5..].to_vec()).unwrap());
    }
    assert!(raw.contains(&format!(r#"{{"type":"cancel","id":{}}}"#, ids[2])));
    let reply = raw.iter().find(|f| f.contains(r#""id":7,"#)).unwrap();
    assert_eq!(
        reply,
        r#"{"type":"response","id":7,"result":{"result":{"b" : 1e2, "a":[ ]},"source":"quorum","verified":true,"undefined_keys":[],"generation":1}}"#
    );
    // Main's late answer for the cancelled member is dropped.
    assert!(
        t.answer(ids[2], Err(ErrorBody::new(ErrorCode::Cancelled, "x")))
            .is_ok()
    );
}

#[test]
fn a_missing_result_is_named_in_undefined_keys() {
    let mut t = test();
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let (id, params) = read(7, "eth_blockNumber", json!([]));
    t.call(id, "chain.request", &params);
    let rpc = requests(&t.written())[0]["id"].as_u64().unwrap();
    assert!(
        t.answer(rpc, rpc_answer(r#"{"jsonrpc":"2.0","id":1}"#))
            .is_ok()
    );
    t.at(1);
    let reply = t.written().into_iter().find(|f| f["id"] == 7).unwrap();
    assert_eq!(
        reply["result"],
        json!({ "source": "direct", "verified": false, "undefined_keys": ["result"], "generation": 1 })
    );
}

#[test]
fn errors_take_the_chain_error_form_with_their_origin() {
    let mut t = test();
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    // A node's error: its code, message and data pass through.
    let (id, params) = read(7, "eth_call", json!([{ "to": "0xabc" }, "latest"]));
    t.call(id, "chain.request", &params);
    let rpc = requests(&t.written())[0]["id"].as_u64().unwrap();
    let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted","data":"0x08c379a0"}}"#;
    assert!(t.answer(rpc, rpc_answer(body)).is_ok());
    t.at(1);
    let reply = t.written().into_iter().find(|f| f["id"] == 7).unwrap();
    assert_eq!(reply["error"]["code"], "chain_error");
    assert_eq!(
        reply["error"]["data"],
        json!({
            "kind": "node",
            "constructor": "Error",
            "message": "execution reverted",
            "props": { "code": 3, "data": "0x08c379a0" },
            "undefined_keys": [],
            "generation": 1,
        })
    );
    // Without data, `data` is an own property whose value is undefined.
    let (id, params) = read(8, "eth_call", json!([{ "to": "0xabc" }, "latest"]));
    t.call(id, "chain.request", &params);
    let rpc = requests(&t.written())[0]["id"].as_u64().unwrap();
    let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"boom"}}"#;
    assert!(t.answer(rpc, rpc_answer(body)).is_ok());
    t.at(2);
    let reply = t.written().into_iter().find(|f| f["id"] == 8).unwrap();
    assert_eq!(
        reply["error"]["data"]["props"],
        json!({ "code": -32000, "data": null })
    );
    assert_eq!(reply["error"]["data"]["undefined_keys"], json!(["data"]));
    // The core's own text, before any I/O.
    let (id, params) = read(9, "eth_sign", json!([]));
    t.call(id, "chain.request", &params);
    let frames = t.written();
    assert!(requests(&frames).is_empty());
    let reply = frames.iter().find(|f| f["id"] == 9).unwrap();
    assert_eq!(
        reply["error"]["data"],
        json!({
            "kind": "core",
            "constructor": "Error",
            "message": "Unsupported read method: eth_sign",
            "props": {},
            "undefined_keys": [],
            "generation": 1,
        })
    );
}

#[test]
fn protocol_errors_carry_the_generation_and_a_broadcasts_outcome() {
    let bounds = Bounds {
        running: 1,
        waiting: 0,
        ..Bounds::default()
    };
    let mut t = test_with(bounds, usize::MAX, 256, true);
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    // No time left: `deadline` at once, under the current generation.
    t.call(
        2,
        "chain.broadcast",
        &json!({ "chain_id": 1, "raw": "0x01", "deadline_ms": 0 }),
    );
    let reply = t.written().into_iter().find(|f| f["id"] == 2).unwrap();
    assert_eq!(
        reply["error"],
        json!({
            "code": "deadline",
            "message": "The chain request's deadline passed",
            "data": { "outcome": "not_sent", "generation": 1 },
        })
    );
    // One running, none may wait: the next is busy.
    t.call(
        3,
        "chain.fee_quote",
        &json!({ "chain_id": 1, "deadline_ms": 1000 }),
    );
    t.call(
        4,
        "chain.fee_quote",
        &json!({ "chain_id": 1, "deadline_ms": 1000 }),
    );
    let frames = t.written();
    let busy = frames.iter().find(|f| f["id"] == 4).unwrap();
    assert_eq!(busy["error"]["code"], "busy");
    assert_eq!(busy["error"]["data"], json!({ "generation": 1 }));
    // The first runs into its deadline.
    t.at(1000);
    let reply = t.written().into_iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(reply["error"]["code"], "deadline");
    assert_eq!(reply["error"]["data"], json!({ "generation": 1 }));
}

#[test]
fn a_fee_quote_and_a_broadcast_reply_in_their_forms() {
    let mut t = test();
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    t.call(
        2,
        "chain.fee_quote",
        &json!({ "chain_id": 1, "deadline_ms": 10_000 }),
    );
    let gas = requests(&t.written())[0]["id"].as_u64().unwrap();
    assert!(
        t.answer(
            gas,
            rpc_answer(r#"{"jsonrpc":"2.0","id":1,"result":"0x64"}"#)
        )
        .is_ok()
    );
    t.at(1);
    let priority = requests(&t.written())[0]["id"].as_u64().unwrap();
    assert!(
        t.answer(
            priority,
            rpc_answer(r#"{"jsonrpc":"2.0","id":2,"result":"0xa"}"#)
        )
        .is_ok()
    );
    t.at(2);
    let reply = t.written().into_iter().find(|f| f["id"] == 2).unwrap();
    assert_eq!(
        reply["result"],
        json!({
            "type": "eip1559",
            "baseFee": "90",
            "maxPriorityFeePerGas": "10",
            "maxFeePerGas": "190",
            "effectiveGasPrice": "100",
            "source": "direct",
            "verified": false,
            "generation": 1,
        })
    );
    // A broadcast the endpoint accepts.
    let raw = "0xf85f8001825208941111111111111111111111111111111111111111018026a045df4733a45ed06c5628f22221a73e0b2faa3959f649cc47e6c2a15c9792ae07a00ea422e4923de6e5b4c52d7fbd39046e96acf73b2037a5f11918ec6c2a64b40a";
    let hash = "0xdff97f6d2d938656e056527357e2ee12f38c03923ab1d11bc556fb5cc123e578";
    t.call(
        3,
        "chain.broadcast",
        &json!({ "chain_id": 1, "raw": raw, "deadline_ms": 60_000 }),
    );
    let send = requests(&t.written())[0].clone();
    let body: Value = serde_json::from_str(send["params"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(body["method"], "eth_sendRawTransaction");
    assert_eq!(body["params"], json!([raw]));
    let accepted = format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{hash}"}}"#);
    assert!(
        t.answer(send["id"].as_u64().unwrap(), rpc_answer(&accepted))
            .is_ok()
    );
    t.at(3);
    let reply = t.written().into_iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(
        reply["result"],
        json!({ "hash": hash, "source": "direct", "outcome": "sent", "generation": 1 })
    );
}

/// A direct read answered with a result of `len` bytes.
fn large_read(t: &mut Test, id: u64, len: usize) -> Value {
    let (id, params) = read(id, "eth_call", json!([{ "to": "0xabc" }, "latest"]));
    t.call(id, "chain.request", &params);
    let rpc = requests(&t.written())[0]["id"].as_u64().unwrap();
    let result = format!("\"0x{}\"", "ab".repeat(len / 2));
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
    assert!(t.answer(rpc, rpc_answer(&body)).is_ok());
    t.at(id);
    t.written().into_iter().find(|f| f["id"] == id).unwrap()
}

#[test]
fn replies_over_a_frame_fragment_only_for_a_main_that_offered() {
    let mut t = test();
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let reply = large_read(&mut t, 7, 2 << 20);
    assert_eq!(reply["fragmented"], true);
    assert_eq!(
        reply["result"]["result"].as_str().unwrap().len(),
        (2 << 20) + 2
    );
    assert_eq!(reply["result"]["generation"], 1);
    // Without fragments, the same reply fails as too large.
    let mut t = test_with(Bounds::default(), usize::MAX, 256, false);
    assert!(!t.link.offered());
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let reply = large_read(&mut t, 7, 2 << 20);
    assert_eq!(
        reply["error"],
        json!({
            "code": "too_large",
            "message": "Response too large",
            "data": { "generation": 1 },
        })
    );
}

#[test]
fn a_reply_over_the_message_cap_is_too_large() {
    let mut t = test();
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let done = Done {
        id: 1,
        result: Ok(Success::Read {
            result: Some(format!("\"{}\"", "a".repeat(MAX_MESSAGE))),
            source: "direct",
            verified: false,
            trust: None,
        }),
        outcome: None,
        settled: 0,
        generation: 4,
    };
    let message = reply_message(9, &done);
    assert!(message.len() > MAX_MESSAGE);
    // Measured without being written: what the thread sends in its place.
    let payload = too_large_payload(9, done.generation, None);
    let value: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(value["error"]["code"], "too_large");
    assert_eq!(value["error"]["data"]["generation"], 4);
}

#[test]
fn replies_past_the_allowance_wait_here_and_count_in_the_backlog() {
    // Room for one frame at a time.
    let mut t = test_with(Bounds::default(), 1, 256, true);
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    for id in 2..5 {
        t.call(
            id,
            "chain.fee_quote",
            &json!({ "chain_id": 99, "deadline_ms": 1000 }),
        );
    }
    // Unsupported chain: three error replies. The first took the room; the
    // others wait here, and count in the backlog with what the writer
    // holds.
    assert_eq!(t.chain.control.len(), 2);
    let waiting: usize = t.chain.control.iter().map(|f| f.len()).sum();
    assert!(t.chain.backlog() > waiting);
    // Each time the writer frees room, one more goes.
    for id in 2..5 {
        let frames = t.written();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["id"], id, "{frames:?}");
        assert!(t.chain.handle(In::Drained).is_ok());
    }
    assert!(t.chain.control.is_empty());
    assert_eq!(t.chain.backlog(), 0);
}

#[test]
fn requests_wait_for_a_slot_and_expire_unsent() {
    // Main holds as many of the core's requests as it takes.
    let mut t = test_with(Bounds::default(), usize::MAX, 0, true);
    let mut config = chain_snapshot(&["direct"], &["a"]);
    config["quorum"]["timeout_ms"] = json!(500);
    t.configure(json!([config]));
    let raw = "0xf85f8001825208941111111111111111111111111111111111111111018026a045df4733a45ed06c5628f22221a73e0b2faa3959f649cc47e6c2a15c9792ae07a00ea422e4923de6e5b4c52d7fbd39046e96acf73b2037a5f11918ec6c2a64b40a";
    t.call(
        2,
        "chain.broadcast",
        &json!({ "chain_id": 1, "raw": raw, "deadline_ms": 60_000 }),
    );
    assert!(requests(&t.written()).is_empty());
    assert_eq!(t.chain.queued.len(), 1);
    // Its bytes count as the thread's backlog.
    assert!(t.chain.backlog() >= raw.len());
    // Its exchange's time runs out first: it never went, so the broadcast
    // sent nothing.
    t.at(500);
    let reply = t.written().into_iter().find(|f| f["id"] == 2).unwrap();
    assert_eq!(reply["error"]["code"], "chain_error", "{reply}");
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
    assert!(t.chain.queued.is_empty());
}

#[test]
fn a_cancel_reaches_the_machine_and_its_io() {
    let mut t = test();
    t.configure(json!([chain_snapshot(&["quorum"], &["a", "b", "c"])]));
    let (id, params) = read(7, "eth_blockNumber", json!([]));
    t.call(id, "chain.request", &params);
    let asked: Vec<u64> = requests(&t.written())
        .iter()
        .map(|r| r["id"].as_u64().unwrap())
        .collect();
    assert!(t.chain.handle(In::Cancel { id: 7 }).is_ok());
    assert!(t.chain.flush().is_ok());
    let frames = t.written();
    let reply = frames
        .iter()
        .find(|f| f["id"] == 7 && f["type"] == "response")
        .unwrap();
    assert_eq!(reply["error"]["code"], "cancelled");
    assert_eq!(reply["error"]["data"]["generation"], 1);
    // Every member is cancelled (deviation `abandoned-exchanges`).
    let cancels: Vec<u64> = frames
        .iter()
        .filter(|f| f["type"] == "cancel")
        .map(|f| f["id"].as_u64().unwrap())
        .collect();
    assert_eq!(cancels, asked);
    // A second cancel, after the reply, changes nothing.
    assert!(t.chain.handle(In::Cancel { id: 7 }).is_ok());
    assert!(t.written().is_empty());
}

#[test]
fn a_change_ends_the_chains_requests_before_its_reply() {
    let mut t = test();
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let (id, params) = read(7, "eth_blockNumber", json!([]));
    t.call(id, "chain.request", &params);
    let rpc = requests(&t.written())[0]["id"].as_u64().unwrap();
    t.call(
        8,
        "chain.configure",
        &json!({ "chains": [chain_snapshot(&["direct"], &["b"])] }),
    );
    let frames = t.written();
    let order: Vec<(&str, u64)> = frames
        .iter()
        .map(|f| (f["type"].as_str().unwrap(), f["id"].as_u64().unwrap()))
        .collect();
    assert_eq!(
        order,
        [("response", 7), ("response", 8), ("cancel", rpc)],
        "{frames:?}"
    );
    assert_eq!(frames[0]["error"]["code"], "reconfigured");
    // Under the generation it ran in.
    assert_eq!(frames[0]["error"]["data"]["generation"], 1);
    assert_eq!(frames[1]["result"], json!({ "generations": { "1": 2 } }));
    // Main's `not_sent` for the stale request is dropped.
    assert!(t.answer(rpc, Ok(json!({ "not_sent": true }))).is_ok());
}

#[test]
fn myotis_and_colibri_operations_take_the_designs_forms() {
    let mut t = test();
    let mut config = chain_snapshot(&["myotis", "colibri", "direct"], &["a"]);
    config["myotis"] = json!(true);
    config["prover"] = json!({ "endpoint": "p1", "zk": true });
    t.configure(json!([config]));
    t.call(
        2,
        "chain.availability",
        &json!({ "chain_id": 1, "ready": true }),
    );
    assert_eq!(
        t.written().into_iter().find(|f| f["id"] == 2).unwrap()["result"],
        json!({})
    );
    let address = "0x1111111111111111111111111111111111111111";
    let (id, mut params) = read(3, "eth_getBalance", json!([address, "latest"]));
    params["include_trust"] = json!(true);
    t.call(id, "chain.request", &params);
    let op = requests(&t.written())[0].clone();
    assert_eq!(op["method"], "shell.verified");
    assert_eq!(
        op["params"],
        json!({ "myotis": "account", "chain_id": 1, "address": address, "generation": 1 })
    );
    let answer = json!({
        "payload": { "verify_method": "proof", "balance_wei": "1000", "exists": true },
        "block_before": 7,
        "block_after": 7,
    });
    assert!(t.answer(op["id"].as_u64().unwrap(), Ok(answer)).is_ok());
    t.at(1);
    let reply = t.written().into_iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(reply["result"]["result"], "0x3e8", "{reply}");
    assert_eq!(reply["result"]["source"], "myotis");
    assert_eq!(reply["result"]["verified"], true);
    assert!(reply["result"]["trust"].is_object());
    // Colibri, once Myotis has failed with a class.
    let (id, params) = read(
        4,
        "eth_call",
        json!([{ "to": address, "data": "0x" }, "latest"]),
    );
    t.call(id, "chain.request", &params);
    let op = requests(&t.written())[0].clone();
    assert_eq!(op["params"]["myotis"], "call_tx");
    assert!(
        t.answer(
            op["id"].as_u64().unwrap(),
            Ok(json!({ "failure": "not_ready" }))
        )
        .is_ok()
    );
    t.at(2);
    let op = requests(&t.written())[0].clone();
    assert_eq!(op["params"]["colibri"], "request");
    assert_eq!(op["params"]["method"], "eth_call");
    assert_eq!(op["params"]["generation"], 1);
    assert!(op["params"]["deadline_ms"].as_u64().unwrap() > 0);
    assert!(
        t.answer(
            op["id"].as_u64().unwrap(),
            Ok(json!({ "revert": { "data": "0x08c379a0" } }))
        )
        .is_ok()
    );
    t.at(3);
    // Direct comes last; its answer wins.
    let rpc = requests(&t.written())[0]["id"].as_u64().unwrap();
    assert!(
        t.answer(
            rpc,
            rpc_answer(r#"{"jsonrpc":"2.0","id":1,"result":"0x01"}"#)
        )
        .is_ok()
    );
    t.at(4);
    let reply = t.written().into_iter().find(|f| f["id"] == 4).unwrap();
    assert_eq!(reply["result"]["result"], "0x01", "{reply}");
}

fn raw(text: &str) -> Result<Box<RawValue>, ErrorBody> {
    Ok(RawValue::from_string(text.to_owned()).unwrap())
}

#[test]
fn colibri_answers_carry_a_revert_with_capacity_and_an_undefined_result() {
    // A verified revert that is also a capacity failure, and a result of
    // `undefined` (design 0005, Verified operations): each in exactly one
    // form.
    let colibri = |text: &str| answer(Kind::Colibri, raw(text));
    let revert = |capacity| {
        Some(Answer::Colibri(ColibriReply::Revert {
            data: "0x12".into(),
            capacity,
        }))
    };
    assert_eq!(
        colibri(r#"{"revert":{"data":"0x12"},"capacity":true}"#),
        revert(true)
    );
    // Members in either order.
    assert_eq!(
        colibri(r#"{"capacity":true,"revert":{"data":"0x12"}}"#),
        revert(true)
    );
    assert_eq!(colibri(r#"{"revert":{"data":"0x12"}}"#), revert(false));
    let undefined = Some(Answer::Colibri(ColibriReply::Undefined));
    assert_eq!(colibri(r#"{"undefined_keys":["result"]}"#), undefined);
    // The same array, whitespace and all.
    assert_eq!(colibri(r#"{"undefined_keys":[ "result" ]}"#), undefined);
    // `capacity` only ever `true`, beside a revert alone; `undefined_keys`
    // only ever `["result"]`, alone.
    let escaped = format!(r#"{{"undefined_keys":["res{}lt"]}}"#, u("0075"));
    for text in [
        r#"{"revert":{"data":"0x12"},"capacity":false}"#,
        r#"{"revert":{"data":"0x12"},"capacity":null}"#,
        r#"{"revert":{"data":"0x12"},"capacity":1}"#,
        r#"{"revert":{"data":"0x12"},"capacity":"true"}"#,
        r#"{"revert":{"data":"0x12"},"capacity":[true]}"#,
        r#"{"revert":{"data":"0x12","capacity":true}}"#,
        r#"{"revert":{"data":"0x12"},"capacity":true,"result":"0x1"}"#,
        r#"{"revert":{"data":3},"capacity":true}"#,
        r#"{"revert":null,"capacity":true}"#,
        r#"{"capacity":true}"#,
        r#"{"failure":"capacity","capacity":true}"#,
        r#"{"result":"0x1","capacity":true}"#,
        r#"{"undefined_keys":[]}"#,
        r#"{"undefined_keys":["result","result"]}"#,
        r#"{"undefined_keys":["result","source"]}"#,
        r#"{"undefined_keys":["source"]}"#,
        r#"{"undefined_keys":["Result"]}"#,
        r#"{"undefined_keys":[["result"]]}"#,
        r#"{"undefined_keys":[null]}"#,
        r#"{"undefined_keys":"result"}"#,
        r#"{"undefined_keys":{"0":"result"}}"#,
        r#"{"undefined_keys":null}"#,
        r#"{"undefined_keys":["result"],"result":null}"#,
        r#"{"undefined_keys":["result"],"result":"0x1"}"#,
        r#"{"undefined_keys":["result"],"extra":1}"#,
        r#"{"undefined_keys":["result"],"failure":"error"}"#,
        r#"{"undefined_keys":["result"],"revert":{"data":"0x12"}}"#,
        &escaped,
    ] {
        assert_eq!(colibri(text), None, "{text}");
    }
    // Neither shape belongs to another operation.
    for kind in [Kind::MyotisRead, Kind::MyotisBroadcast, Kind::Rpc] {
        for text in [
            r#"{"undefined_keys":["result"]}"#,
            r#"{"revert":{"data":"0x12"},"capacity":true}"#,
        ] {
            assert_eq!(answer(kind, raw(text)), None, "{kind:?} {text}");
        }
    }
}

#[test]
fn a_colibri_result_of_undefined_replies_without_result() {
    // Main restores an own `result: undefined` from `undefined_keys`.
    let mut t = test();
    let mut config = chain_snapshot(&["colibri"], &[]);
    config["prover"] = json!({ "endpoint": "p", "zk": false });
    t.configure(json!([config]));
    let (id, params) = read(3, "eth_blockNumber", json!([]));
    t.call(id, "chain.request", &params);
    let op = verified(&t.written())[0].clone();
    assert_eq!(op["params"]["colibri"], "request");
    assert!(
        t.answer(
            op["id"].as_u64().unwrap(),
            Ok(json!({ "undefined_keys": ["result"] }))
        )
        .is_ok()
    );
    let reply = t.written().into_iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(
        reply["result"],
        json!({
            "source": "colibri",
            "verified": true,
            "generation": 1,
            "undefined_keys": ["result"],
        }),
        "{reply}"
    );
}

#[test]
fn a_colibri_revert_with_capacity_blocks_the_apps_route() {
    // The read rejects with the revert, and the same call from the same app
    // never asks Colibri again: it is bypassed.
    let mut t = test();
    let mut config = chain_snapshot(&["colibri"], &[]);
    config["prover"] = json!({ "endpoint": "p", "zk": false });
    t.configure(json!([config]));
    let call = |id| {
        let (id, mut params) = read(id, "eth_call", json!([{ "to": "0xabc" }, "latest"]));
        params["origin"] = json!("https://swap.example");
        (id, params)
    };
    let (id, params) = call(3);
    t.call(id, "chain.request", &params);
    let op = verified(&t.written())[0].clone();
    assert!(
        t.answer(
            op["id"].as_u64().unwrap(),
            Ok(json!({ "revert": { "data": "0x" }, "capacity": true }))
        )
        .is_ok()
    );
    let reply = t.written().into_iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(
        reply["error"]["data"]["message"], "execution reverted",
        "{reply}"
    );
    let (id, params) = call(4);
    t.call(id, "chain.request", &params);
    let frames = t.written();
    assert!(verified(&frames).is_empty(), "{frames:?}");
    let reply = frames.iter().find(|f| f["id"] == 4).unwrap();
    let message = reply["error"]["data"]["message"].as_str().unwrap();
    assert!(
        message.ends_with("(colibri: temporarily bypassed for this app workload)"),
        "{reply}"
    );
}

#[test]
fn mains_answers_take_one_closed_shape() {
    // Transport failures are a closed set and carry no text; only
    // `not_sent` says nothing went.
    for (code, transport) in [
        (ErrorCode::Timeout, Transport::Timeout),
        (ErrorCode::Deadline, Transport::Timeout),
        (ErrorCode::Network, Transport::Network),
        (ErrorCode::Refused, Transport::Refused),
        (ErrorCode::TooLarge, Transport::TooLarge),
        (ErrorCode::Busy, Transport::Busy),
        (ErrorCode::Cancelled, Transport::Network),
        (ErrorCode::StaleGeneration, Transport::Network),
    ] {
        assert_eq!(
            answer(Kind::Rpc, Err(ErrorBody::new(code, "x"))),
            Some(Answer::Failed(transport))
        );
    }
    // Any other code, or data beside one, is malformed.
    for code in [
        ErrorCode::InvalidArgument,
        ErrorCode::Internal,
        ErrorCode::UnknownMethod,
        ErrorCode::ChainError,
        ErrorCode::VaultLocked,
    ] {
        assert_eq!(answer(Kind::Rpc, Err(ErrorBody::new(code, "x"))), None);
    }
    assert_eq!(
        answer(
            Kind::MyotisBroadcast,
            Err(ErrorBody::new(ErrorCode::Network, "x").with_data(json!({ "a": 1 })))
        ),
        None
    );
    assert_eq!(
        answer(Kind::Rpc, raw(r#"{"not_sent":true}"#)),
        Some(Answer::NotSent)
    );
    assert_eq!(
        answer(Kind::MyotisBroadcast, raw(r#"{"not_sent":true}"#)),
        Some(Answer::Myotis(MyotisReply::NotSent))
    );
    assert_eq!(
        answer(Kind::Rpc, raw(r#"{"status":200,"body":"e30="}"#)),
        Some(Answer::Rpc {
            status: 200,
            body: b"{}".to_vec()
        })
    );
    assert_eq!(
        answer(
            Kind::Blockscout,
            raw(r#"{"status":429,"headers":{"retry-after":"3"},"body":""}"#)
        ),
        Some(Answer::Blockscout {
            status: 429,
            headers: vec![("retry-after".into(), "3".into())],
            body: Vec::new(),
        })
    );
    let read = |text: &str| answer(Kind::MyotisRead, raw(text));
    assert_eq!(
        read(r#"{"payload":{"a":1},"block_before":5,"block_after":null}"#),
        Some(Answer::Myotis(MyotisReply::Read {
            payload: r#"{"a":1}"#.into(),
            block_before: Some("5".into()),
            block_after: None,
        }))
    );
    for (class, expected) in MYOTIS_CLASSES {
        assert_eq!(
            read(&format!(r#"{{"failure":"{class}"}}"#)),
            Some(Answer::Myotis(MyotisReply::Failure(*expected)))
        );
    }
    let broadcast = |text: &str| answer(Kind::MyotisBroadcast, raw(text));
    assert_eq!(
        broadcast(r#"{"hash":"0xab"}"#),
        Some(Answer::Myotis(MyotisReply::Sent {
            hash: r#""0xab""#.into()
        }))
    );
    assert_eq!(
        broadcast(r#"{"rejected":{"reason":"nonce too low \ud800"}}"#),
        Some(Answer::Myotis(MyotisReply::Rejected {
            reason: "nonce too low \u{fffd}".into(),
            kind: MyotisRejection::Rejected,
        }))
    );
    // The adapter's -32602 refusal names its code, in either order.
    for text in [
        r#"{"rejected":{"reason":"invalid raw transaction","code":-32602}}"#,
        r#"{"rejected":{"code":-32602,"reason":"invalid raw transaction"}}"#,
    ] {
        assert_eq!(
            broadcast(text),
            Some(Answer::Myotis(MyotisReply::Rejected {
                reason: "invalid raw transaction".into(),
                kind: MyotisRejection::InvalidParams,
            })),
            "{text}"
        );
    }
    assert_eq!(
        broadcast(r#"{"uncertain":true}"#),
        Some(Answer::Myotis(MyotisReply::Uncertain))
    );
    let colibri = |text: &str| answer(Kind::Colibri, raw(text));
    assert_eq!(
        colibri(r#"{"result":{"x":[1]}}"#),
        Some(Answer::Colibri(ColibriReply::Result(r#"{"x":[1]}"#.into())))
    );
    assert_eq!(
        colibri(r#"{"result":null}"#),
        Some(Answer::Colibri(ColibriReply::Result("null".into())))
    );
    assert_eq!(
        colibri(r#"{"revert":{"data":"0x12"}}"#),
        Some(Answer::Colibri(ColibriReply::Revert {
            data: "0x12".into(),
            capacity: false,
        }))
    );
    for (class, expected) in [
        ("capacity", ColibriClass::Capacity),
        ("too_large", ColibriClass::TooLarge),
        ("busy", ColibriClass::Busy),
        ("not_ready", ColibriClass::Error),
        ("error", ColibriClass::Error),
    ] {
        assert_eq!(
            colibri(&format!(r#"{{"failure":"{class}"}}"#)),
            Some(Answer::Colibri(ColibriReply::Failure(expected)))
        );
    }
    // Text where a class goes, two shapes at once, members of another
    // operation, unknown members: malformed.
    for (kind, text) in [
        (Kind::Rpc, r#"{"status":200}"#),
        (Kind::Rpc, r#"{"status":200,"body":"!!"}"#),
        (Kind::Rpc, r#"{"status":200,"body":"","extra":1}"#),
        (Kind::Rpc, r#"{"not_sent":false}"#),
        (
            Kind::MyotisRead,
            r#"{"failure":"see https://example.com/key=1"}"#,
        ),
        (Kind::MyotisRead, r#"{"failure":"error","payload":{}}"#),
        (Kind::MyotisRead, r#"{"failure":"capacity"}"#),
        (Kind::MyotisRead, r#"{"hash":"0x1"}"#),
        (Kind::MyotisRead, r#"{"block_before":1}"#),
        (Kind::MyotisRead, r#"{"payload":{},"not_sent":true}"#),
        (Kind::MyotisBroadcast, r#"{"uncertain":false}"#),
        (Kind::MyotisBroadcast, r#"{"hash":"0x1","uncertain":true}"#),
        (Kind::MyotisBroadcast, r#"{"rejected":{"reason":7}}"#),
        // A refusal's code is -32602, as JSON.stringify writes it, or
        // absent: any other code, spelling or member is malformed.
        (
            Kind::MyotisBroadcast,
            r#"{"rejected":{"reason":"x","code":-32000}}"#,
        ),
        (
            Kind::MyotisBroadcast,
            r#"{"rejected":{"reason":"x","code":-32601}}"#,
        ),
        (
            Kind::MyotisBroadcast,
            r#"{"rejected":{"reason":"x","code":"-32602"}}"#,
        ),
        (
            Kind::MyotisBroadcast,
            r#"{"rejected":{"reason":"x","code":-32602.0}}"#,
        ),
        (
            Kind::MyotisBroadcast,
            r#"{"rejected":{"reason":"x","code":-3.2602e4}}"#,
        ),
        (
            Kind::MyotisBroadcast,
            r#"{"rejected":{"reason":"x","code":null}}"#,
        ),
        (Kind::MyotisBroadcast, r#"{"rejected":{"code":-32602}}"#),
        (
            Kind::MyotisBroadcast,
            r#"{"rejected":{"reason":"x","kind":"invalid-params"}}"#,
        ),
        (
            Kind::MyotisBroadcast,
            r#"{"rejected":{"reason":"x","code":-32602,"data":"0x"}}"#,
        ),
        (
            Kind::MyotisBroadcast,
            r#"{"rejected":{"reason":"x","code":-32602,"code":-32602}}"#,
        ),
        (
            Kind::MyotisBroadcast,
            r#"{"rejected":{"reason":"x"},"code":-32602}"#,
        ),
        (Kind::MyotisBroadcast, r#"{"payload":{}}"#),
        (Kind::Colibri, r#"{"revert":{"data":3}}"#),
        (Kind::Colibri, r#"{"result":1,"revert":{"data":"0x"}}"#),
        (Kind::Colibri, r#"{"message":"out of gas"}"#),
        (Kind::Colibri, r#""ok""#),
        // Arrays where objects belong, outer or nested (57-M1): never a
        // proof that nothing was sent, nor a refusal.
        (Kind::Rpc, "[true]"),
        (Kind::Rpc, "[200,\"e30=\"]"),
        (Kind::Blockscout, "[true]"),
        (Kind::MyotisRead, "[true]"),
        (Kind::MyotisRead, r#"[{"a":1},5,5]"#),
        (Kind::MyotisBroadcast, "[true]"),
        (Kind::MyotisBroadcast, r#"{"rejected":["no"]}"#),
        (Kind::Colibri, "[true]"),
        (Kind::Colibri, r#"{"revert":["0x12"]}"#),
        // A member of another shape is there whatever its value, `null`
        // included (R2-M1).
        (
            Kind::MyotisBroadcast,
            r#"{"failure":"not_running","uncertain":null}"#,
        ),
        (
            Kind::MyotisBroadcast,
            r#"{"failure":"not_running","rejected":null}"#,
        ),
        (
            Kind::MyotisBroadcast,
            r#"{"failure":"not_running","revert":null}"#,
        ),
        (
            Kind::MyotisBroadcast,
            r#"{"failure":"not_running","block_before":null}"#,
        ),
        (
            Kind::MyotisBroadcast,
            r#"{"failure":"not_running","block_after":null}"#,
        ),
        (
            Kind::MyotisBroadcast,
            r#"{"failure":"not_running","not_sent":null}"#,
        ),
        (Kind::MyotisBroadcast, r#"{"hash":"0xab","rejected":null}"#),
        (Kind::MyotisBroadcast, r#"{"rejected":null}"#),
        (Kind::MyotisBroadcast, r#"{"uncertain":null}"#),
        (Kind::MyotisBroadcast, r#"{"not_sent":null}"#),
        (Kind::MyotisBroadcast, r#"{"failure":null}"#),
        (
            Kind::MyotisBroadcast,
            r#"{"failure":"error","failure":"not_running"}"#,
        ),
        (Kind::MyotisRead, r#"{"failure":"error","payload":null}"#),
        (
            Kind::MyotisRead,
            r#"{"failure":"error","block_before":null}"#,
        ),
        (Kind::MyotisRead, r#"{"payload":{},"hash":null}"#),
        (
            Kind::MyotisRead,
            r#"{"payload":{},"block_before":1,"block_after":1,"x":1}"#,
        ),
        (Kind::MyotisRead, r#"{"block_before":null}"#),
        (Kind::Colibri, r#"{"failure":"capacity","revert":null}"#),
        (Kind::Colibri, r#"{"result":1,"revert":null}"#),
        (Kind::Colibri, r#"{"revert":null}"#),
        // A Blockscout page with more headers than any page needs (R2-M3).
        (
            Kind::Blockscout,
            r#"{"status":200,"headers":{"a":"","b":"","c":"","d":"","e":"","f":"","g":"","h":"","i":""},"body":""}"#,
        ),
        (
            Kind::Blockscout,
            r#"{"status":200,"headers":{"a":1},"body":""}"#,
        ),
        (
            Kind::Blockscout,
            r#"{"status":200,"headers":null,"body":""}"#,
        ),
    ] {
        assert_eq!(answer(kind, raw(text)), None, "{kind:?} {text}");
    }
}

/// A `shell.*` request: its method, how to read the answer, and its
/// params, `left` written in their `deadline_ms` slot when they have one.
fn shell_request(request: &Request, generation: u64, left: Ms) -> (&'static str, Kind, Vec<u8>) {
    let (method, (mut params, deadline)) = shell_params(request, generation);
    if let Some(at) = deadline {
        requests::write_slot(&mut params[at..at + requests::SLOT], left);
    }
    (method, kind_of(request), params)
}

#[test]
fn requests_to_main_take_the_designs_forms() {
    let (method, kind, params) = shell_request(
        &Request::Blockscout {
            endpoint: "b1".into(),
            query: "?module=logs&topic0=0x\"1".into(),
            max_bytes: 8 << 20,
            deadline_ms: 15_000,
        },
        3,
        14_000,
    );
    assert_eq!((method, kind), ("shell.blockscout", Kind::Blockscout));
    let value: Value = serde_json::from_slice(&params).unwrap();
    assert_eq!(
        value,
        json!({
            "endpoint": "b1",
            "query": "?module=logs&topic0=0x\"1",
            "max_bytes": 8 << 20,
            "generation": 3,
            "deadline_ms": 14_000,
        })
    );
    let (_, kind, params) = shell_request(
        &Request::Verified(VerifiedOp::MyotisRead {
            chain_id: 100,
            operation: MyotisOperation::Storage {
                address: Some(r#""0xab""#.into()),
                slot: None,
            },
        }),
        2,
        0,
    );
    assert_eq!(kind, Kind::MyotisRead);
    let value: Value = serde_json::from_slice(&params).unwrap();
    // An `undefined` argument is left out.
    assert_eq!(
        value,
        json!({ "myotis": "storage", "chain_id": 100, "address": "0xab", "generation": 2 })
    );
    let (_, _, params) = shell_request(
        &Request::Verified(VerifiedOp::MyotisBroadcast {
            chain_id: 1,
            raw: "0x02".into(),
        }),
        1,
        0,
    );
    let value: Value = serde_json::from_slice(&params).unwrap();
    assert_eq!(
        value,
        json!({ "myotis": "broadcast", "chain_id": 1, "raw": "0x02", "generation": 1 })
    );
    let mut quoted = Vec::new();
    quote_into(&mut quoted, "a\"b\\c\n\u{1}é");
    assert_eq!(
        serde_json::from_slice::<String>(&quoted).unwrap(),
        "a\"b\\c\n\u{1}é"
    );
}

/// Takes main's one slot with a request of naming's; its ID frees it.
fn occupy(t: &Test) -> u64 {
    let (out, _rx) = mpsc::channel();
    let allowance = Allowance::new(usize::MAX, usize::MAX);
    match t.chain.requests.send(
        Owner::Naming,
        &allowance,
        &out,
        || requests::request_frame("shell.rpc", b"{}", None),
        || Start::Anytime,
    ) {
        Dispatch::Sent(id) => id,
        other => panic!("{other:?}"),
    }
}

fn verified(frames: &[Value]) -> Vec<&Value> {
    frames
        .iter()
        .filter(|f| f["method"] == "shell.verified")
        .collect()
}

#[test]
fn a_queued_operation_of_an_ended_request_never_goes_and_frees_its_slot() {
    // 57-M2: main holds all it takes; a Myotis read's operation waits here.
    let mut t = test_with(Bounds::default(), usize::MAX, 1, true);
    let mut config = chain_snapshot(&["myotis"], &[]);
    config["myotis"] = json!(true);
    t.configure(json!([config]));
    t.call(
        2,
        "chain.availability",
        &json!({ "chain_id": 1, "ready": true }),
    );
    let held = occupy(&t);
    let address = "0x1111111111111111111111111111111111111111";
    let (id, params) = read(3, "eth_getBalance", json!([address, "latest"]));
    t.call(id, "chain.request", &params);
    assert_eq!(t.chain.queued.len(), 1);
    // Cancelled: it replies, and its operation leaves the queue.
    assert!(t.chain.handle(In::Cancel { id: 3 }).is_ok());
    assert!(t.chain.flush().is_ok());
    let frames = t.written();
    let reply = frames.iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(reply["error"]["code"], "cancelled");
    assert!(t.chain.queued.is_empty());
    // A slot frees: nothing of the cancelled read goes.
    assert_eq!(t.chain.requests.answered(held), Some(Owner::Naming));
    assert!(t.chain.handle(In::Drained).is_ok());
    assert!(t.chain.flush().is_ok());
    assert!(verified(&t.written()).is_empty());
    // Its Myotis slot was freed: the next read's operation goes at once.
    let (id, params) = read(4, "eth_getBalance", json!([address, "latest"]));
    t.call(id, "chain.request", &params);
    let frames = t.written();
    let ops = verified(&frames);
    assert_eq!(ops.len(), 1, "{frames:?}");
    assert_eq!(ops[0]["params"]["myotis"], "account");
}

#[test]
fn a_queued_myotis_broadcast_never_starts_past_its_attempt_cutoff() {
    // 57-M2: the attempt window closes 10 s before the deadline.
    let mut t = test_with(Bounds::default(), usize::MAX, 1, true);
    let mut config = chain_snapshot(&[], &[]);
    config["myotis"] = json!(true);
    config["broadcast_order"] = json!(["myotis"]);
    t.configure(json!([config]));
    t.call(
        2,
        "chain.availability",
        &json!({ "chain_id": 1, "ready": true }),
    );
    let held = occupy(&t);
    t.call(
        3,
        "chain.broadcast",
        &json!({ "chain_id": 1, "raw": "0x01", "deadline_ms": 10_200 }),
    );
    assert_eq!(t.chain.queued.len(), 1);
    assert_eq!(t.chain.queued[0].until, Some(200));
    t.at(199);
    assert_eq!(t.chain.queued.len(), 1);
    // At the cutoff it is retired unsent: nothing reached main, and the
    // broadcast says so.
    t.at(200);
    let frames = t.written();
    let reply = frames.iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(reply["error"]["code"], "chain_error", "{reply}");
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
    assert!(t.chain.queued.is_empty());
    assert_eq!(t.chain.requests.answered(held), Some(Owner::Naming));
    assert!(t.chain.handle(In::Drained).is_ok());
    assert!(t.chain.flush().is_ok());
    assert!(verified(&t.written()).is_empty());
}

#[test]
fn cancels_and_small_replies_never_wait_behind_bulk_replies() {
    // 57-M3: one bulk reply at a time; control frames have their own share.
    let mut t = test_shares(Bounds::default(), (1, usize::MAX), 256, true);
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let call = json!([{ "to": "0xabc" }, "latest"]);
    for id in [3, 4, 5] {
        let (id, params) = read(id, "eth_call", call.clone());
        t.call(id, "chain.request", &params);
    }
    let asked: Vec<u64> = requests(&t.written())
        .iter()
        .map(|r| r["id"].as_u64().unwrap())
        .collect();
    // Two large answers: the first reply holds the bulk share (main hasn't
    // taken it), the second waits behind it.
    let large = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#,
        "ab".repeat(1 << 20)
    );
    for rpc in &asked[1..] {
        assert!(t.answer(*rpc, rpc_answer(&large)).is_ok());
        t.at(1);
    }
    assert_eq!(t.chain.bulk.len(), 1);
    // The first read is cancelled: its exchange's cancel and its reply go
    // at once, past the waiting bulk reply.
    assert!(t.chain.handle(In::Cancel { id: 3 }).is_ok());
    assert!(t.chain.flush().is_ok());
    let mut seen = Vec::new();
    while let Ok(item) = t.rx.try_recv() {
        if let Out::Frame { frame, .. } = item {
            seen.push(serde_json::from_slice::<Value>(&frame[5..]).unwrap());
        }
    }
    assert!(
        seen.contains(&json!({ "type": "cancel", "id": asked[0] })),
        "{seen:?}"
    );
    let reply = seen.iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(reply["error"]["code"], "cancelled");
    assert_eq!(t.chain.bulk.len(), 1);
}

#[test]
fn strings_decode_in_one_pass_within_their_length() {
    let cases = [
        (r#""plain""#.to_owned(), "plain"),
        (
            r#""a\"b\\c\/d\b\f\n\r\t""#.to_owned(),
            "a\"b\\c/d\u{8}\u{c}\n\r\t",
        ),
        (
            format!("\"{}{}{}{}\"", u("00e9"), u("20ac"), u("d83d"), u("de00")),
            "\u{e9}\u{20ac}\u{1f600}",
        ),
        (
            format!("\"lone {} and {} end\"", u("d800"), u("dc00")),
            "lone \u{fffd} and \u{fffd} end",
        ),
        (
            format!("\"lead then other {}{}\"", u("d800"), u("0041")),
            "lead then other \u{fffd}A",
        ),
        ("\"r\u{e9}sum\u{e9}\"".to_owned(), "r\u{e9}sum\u{e9}"),
        (r#""""#.to_owned(), ""),
    ];
    for (raw, text) in &cases {
        let decoded = decode_string(raw).unwrap();
        assert_eq!(decoded, *text, "{raw}");
        assert!(decoded.capacity() <= raw.len(), "{raw}");
    }
    for bad in [
        r#"x"#,
        r#""\x""#,
        r#""\u12""#,
        r#""\u12zz""#,
        "\"tab\tin\"",
        r#""a"b""#,
        r#""end\""#,
    ] {
        assert_eq!(decode_string(bad), None, "{bad}");
    }
}

#[test]
fn reading_a_reply_past_the_budget_ends_its_request_unread() {
    // 57-M4: the message and what decoding it makes are reserved first.
    let bounds = Bounds {
        request_bytes: 64 * 1024,
        ..Bounds::default()
    };
    let mut t = test_with(bounds, usize::MAX, 256, true);
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let (id, params) = read(7, "eth_call", json!([{ "to": "0xabc" }, "latest"]));
    t.call(id, "chain.request", &params);
    let rpc = requests(&t.written())[0]["id"].as_u64().unwrap();
    let held = t.chain.machine.held();
    // An answer of 100 KiB: its message alone crosses the budget.
    let big = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#,
        "ab".repeat(50 * 1024)
    );
    assert!(t.answer(rpc, rpc_answer(&big)).is_ok());
    t.at(1);
    let reply = t.written().into_iter().find(|f| f["id"] == 7).unwrap();
    assert_eq!(reply["error"]["code"], "budget", "{reply}");
    // Nothing stays charged.
    t.chain.machine.set_output_backlog(0);
    assert!(t.chain.machine.held() <= held);
}

#[test]
fn a_broadcast_whose_reply_cannot_be_read_stays_uncertain() {
    // 57-M4: a refused reservation still settles the attempt, which keeps
    // its possibly-sent floor.
    let bounds = Bounds {
        request_bytes: 64 * 1024,
        ..Bounds::default()
    };
    let mut t = test_with(bounds, usize::MAX, 256, true);
    t.configure(json!([chain_snapshot(&["direct"], &["a", "b"])]));
    let raw = "0xf85f8001825208941111111111111111111111111111111111111111018026a045df4733a45ed06c5628f22221a73e0b2faa3959f649cc47e6c2a15c9792ae07a00ea422e4923de6e5b4c52d7fbd39046e96acf73b2037a5f11918ec6c2a64b40a";
    t.call(
        3,
        "chain.broadcast",
        &json!({ "chain_id": 1, "raw": raw, "deadline_ms": 60_000 }),
    );
    let send = requests(&t.written())[0]["id"].as_u64().unwrap();
    // A refusal whose message is past the budget.
    let refusal = format!(
        r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":-32000,"message":"nonce too low {}"}}}}"#,
        "x".repeat(100 * 1024)
    );
    assert!(t.answer(send, rpc_answer(&refusal)).is_ok());
    t.at(1);
    let frames = t.written();
    let reply = frames.iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(reply["result"]["outcome"], "uncertain", "{reply}");
    // Nothing more was sent.
    assert!(requests(&frames).is_empty(), "{frames:?}");
}

#[test]
fn a_read_may_carry_null_blocks_and_a_colibri_result_may_be_null() {
    // R2-M1: `null` only where the protocol has it.
    assert_eq!(
        answer(
            Kind::MyotisRead,
            raw(r#"{"payload":null,"block_before":null,"block_after":7}"#)
        ),
        Some(Answer::Myotis(MyotisReply::Read {
            payload: "null".into(),
            block_before: None,
            block_after: Some("7".into()),
        }))
    );
    assert_eq!(
        answer(Kind::Colibri, raw(r#"{"result":null}"#)),
        Some(Answer::Colibri(ColibriReply::Result("null".into())))
    );
}

#[test]
fn a_page_keeps_the_headers_the_core_reads() {
    // R2-M3: at most eight headers; the three the core reads are kept, in
    // a vector whose places the answer counts.
    let page = r#"{"status":429,"headers":{"Retry-After":"3","content-type":"application/json","x-ratelimit-reset":"1000","date":"x"},"body":""}"#;
    let Some(Answer::Blockscout {
        status, headers, ..
    }) = answer(Kind::Blockscout, raw(page))
    else {
        panic!("not a page");
    };
    assert_eq!(status, 429);
    assert_eq!(
        headers,
        [
            ("Retry-After".to_owned(), "3".to_owned()),
            ("x-ratelimit-reset".to_owned(), "1000".to_owned()),
        ]
    );
}

#[test]
fn a_shell_error_is_read_in_place_and_charged_like_a_result() {
    // Round 2, daemon review: a transport failure's message counts against
    // its request before any of it is read, as a result's does.
    let bounds = Bounds {
        total_bytes: 512 * 1024,
        ..Bounds::default()
    };
    let mut t = test_with(bounds, usize::MAX, 256, true);
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    for (id, text, code) in [
        (3, "x".to_owned(), "chain_error"),
        (4, "x".repeat(900_000), "budget"),
    ] {
        let (id, params) = read(id, "eth_blockNumber", json!([]));
        t.call(id, "chain.request", &params);
        let rpc = requests(&t.written())[0]["id"].as_u64().unwrap();
        let error = json!({ "code": "network", "message": text }).to_string();
        assert_eq!(t.chain.requests.answered(rpc), Some(Owner::Chain));
        assert!(
            t.chain
                .handle(In::Response {
                    id: rpc,
                    reply: shell_error(rpc, &error),
                })
                .is_ok()
        );
        assert!(t.chain.flush().is_ok());
        t.at(id);
        let reply = t.written().into_iter().find(|f| f["id"] == id).unwrap();
        assert_eq!(reply["error"]["code"], code, "{reply}");
    }
}

#[test]
fn a_cancelled_callers_queued_operation_never_goes_when_room_opens_before_flush() {
    // Round 2, R2-M2, the reviewer's interleaving: main holds all it takes,
    // a Myotis read's operation waits, its caller is cancelled, and a slot
    // frees (on the event loop's thread) before this thread flushes.
    let mut t = test_with(Bounds::default(), usize::MAX, 1, true);
    let mut config = chain_snapshot(&["myotis"], &[]);
    config["myotis"] = json!(true);
    t.configure(json!([config]));
    t.call(
        2,
        "chain.availability",
        &json!({ "chain_id": 1, "ready": true }),
    );
    let held = occupy(&t);
    let (id, params) = read(
        3,
        "eth_getBalance",
        json!(["0x1111111111111111111111111111111111111111", "latest"]),
    );
    t.call(id, "chain.request", &params);
    assert_eq!(t.chain.queued.len(), 1);
    assert!(t.chain.handle(In::Cancel { id: 3 }).is_ok());
    assert_eq!(t.chain.requests.answered(held), Some(Owner::Naming));
    assert!(t.chain.flush().is_ok());
    let frames = t.written();
    assert!(verified(&frames).is_empty(), "{frames:?}");
    let reply = frames.iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(reply["error"]["code"], "cancelled");
    // Its slot was freed: the next read's operation goes at once.
    let (id, params) = read(
        4,
        "eth_getBalance",
        json!(["0x1111111111111111111111111111111111111111", "latest"]),
    );
    t.call(id, "chain.request", &params);
    assert_eq!(verified(&t.written()).len(), 1);
}

#[test]
fn nothing_is_dispatched_against_a_clock_handling_left_behind() {
    // Round 3, R3-M1, the reviewer's interleaving: a Myotis broadcast waits
    // for a slot, its cutoff at 200 ms. At 199 ms an expensive answer
    // arrives: its request's slot freed on the event loop's thread went to
    // naming, and another naming answer frees one while this thread decodes
    // the 16 MiB body. Decoding took until 1,329 ms: the flush after it
    // must see that, and the broadcast never starts.
    let mut t = test_with(Bounds::default(), usize::MAX, 2, true);
    let mut config = chain_snapshot(&["direct"], &["a"]);
    config["myotis"] = json!(true);
    config["broadcast_order"] = json!(["myotis"]);
    t.configure(json!([config]));
    t.call(
        2,
        "chain.availability",
        &json!({ "chain_id": 1, "ready": true }),
    );
    let (read_id, read_params) = read(3, "eth_call", json!([{ "to": "0xabc" }, "latest"]));
    t.call(read_id, "chain.request", &read_params);
    let heavy = requests(&t.written())[0]["id"].as_u64().unwrap();
    let held = occupy(&t);
    t.call(
        4,
        "chain.broadcast",
        &json!({ "chain_id": 1, "raw": "0x01", "deadline_ms": 10_200 }),
    );
    assert_eq!(t.chain.queued[0].until, Some(200));
    t.at(199);
    assert_eq!(t.chain.requests.answered(heavy), Some(Owner::Chain));
    let replacement = occupy(&t);
    let requests = Arc::clone(&t.chain.requests);
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(2));
        requests.answered(held)
    });
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#,
        "ab".repeat(8 << 20)
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(body);
    let result = json!({ "status": 200, "body": encoded }).to_string();
    assert!(
        t.chain
            .handle(In::Response {
                id: heavy,
                reply: shell_result(heavy, &result),
            })
            .is_ok()
    );
    assert_eq!(release.join().unwrap(), Some(Owner::Naming));
    // The time decoding took.
    t.clock.set(1_329);
    assert!(t.chain.flush().is_ok());
    let frames = t.written();
    assert!(verified(&frames).is_empty(), "{frames:?}");
    // It never went: it is not sent.
    let reply = frames.iter().find(|f| f["id"] == 4).unwrap();
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent", "{reply}");
    assert!(t.chain.queued.is_empty());
    assert_eq!(t.chain.requests.answered(replacement), Some(Owner::Naming));
}

/// The round-3 interleaving moved into one flush (round 4): a Myotis
/// broadcast waits for a slot, its cutoff at 200 ms; a read's 16 MiB answer
/// was decoded at 199 ms, its slot gone to naming. Returns the read's ID and
/// the slot naming holds, to free while the read's reply is serialized.
fn a_broadcast_behind_a_heavy_reply(t: &mut Test) -> (u64, u64) {
    let mut config = chain_snapshot(&["direct"], &["a"]);
    config["myotis"] = json!(true);
    config["broadcast_order"] = json!(["myotis"]);
    t.configure(json!([config]));
    t.call(
        2,
        "chain.availability",
        &json!({ "chain_id": 1, "ready": true }),
    );
    let (read_id, read_params) = read(3, "eth_call", json!([{ "to": "0xabc" }, "latest"]));
    t.call(read_id, "chain.request", &read_params);
    let heavy = requests(&t.written())[0]["id"].as_u64().unwrap();
    let held = occupy(t);
    t.call(
        4,
        "chain.broadcast",
        &json!({ "chain_id": 1, "raw": "0x01", "deadline_ms": 10_200 }),
    );
    assert_eq!(t.chain.queued[0].until, Some(200));
    t.at(199);
    assert_eq!(t.chain.requests.answered(heavy), Some(Owner::Chain));
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#,
        "ab".repeat(8 << 20)
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(body);
    let result = json!({ "status": 200, "body": encoded }).to_string();
    assert!(
        t.chain
            .handle(In::Response {
                id: heavy,
                reply: shell_result(heavy, &result),
            })
            .is_ok()
    );
    (read_id, held)
}

#[test]
fn nothing_is_dispatched_against_a_clock_a_reply_left_behind() {
    // Round 4, R3-M1 inside one flush, the reviewer's interleaving: the
    // flush starts at 199 ms with nothing due. While it serializes the
    // read's 16 MiB reply, the clock reaches 1,329 ms and a naming answer
    // frees a slot on another thread. Dispatch must see that time: the
    // broadcast never starts.
    let mut t = test_with(Bounds::default(), usize::MAX, 2, true);
    let (read_id, held) = a_broadcast_behind_a_heavy_reply(&mut t);
    let replacement = occupy(&t);
    let clock = std::rc::Rc::clone(&t.clock);
    let requests = Arc::clone(&t.chain.requests);
    let mut held = Some(held);
    t.chain.on_reply = Some(Box::new(move || {
        if let Some(held) = held.take() {
            clock.set(1_329);
            assert_eq!(requests.answered(held), Some(Owner::Naming));
        }
    }));
    assert!(t.chain.flush().is_ok());
    // The reply was serialized in that flush.
    assert_eq!(t.clock.get(), 1_329);
    let frames = t.written();
    assert!(frames.iter().any(|f| f["id"] == read_id));
    let sent = verified(&frames);
    assert!(sent.is_empty(), "{sent:?}");
    // It never went: it is not sent, and the slot is still free.
    let reply = frames.iter().find(|f| f["id"] == 4).unwrap();
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent", "{reply}");
    assert!(t.chain.queued.is_empty());
    let free = occupy(&t);
    assert_eq!(t.chain.requests.answered(free), Some(Owner::Naming));
    assert_eq!(t.chain.requests.answered(replacement), Some(Owner::Naming));
}

/// A clock that reads `before` until `freed` is set, `before` once more
/// after that (the machine brought to now just before dispatch), then
/// `after`: time passes between that reading and a request taking its
/// slot (waiting for the gate's lock, say).
fn a_clock_moving_at_the_gate(
    freed: &std::rc::Rc<std::cell::Cell<bool>>,
    before: Ms,
    after: Ms,
) -> Clock {
    let freed = std::rc::Rc::clone(freed);
    let read_since = std::cell::Cell::new(false);
    Clock::new(Box::new(move || {
        // Once freed, one reading more at `before`.
        if freed.get() && read_since.replace(true) {
            after
        } else {
            before
        }
    }))
}

#[test]
fn a_request_past_its_latest_start_as_it_takes_its_slot_never_goes() {
    // Round 4: a slot frees while the reply is serialized, and the
    // machine is brought to 199 ms before dispatch. The cutoff passes
    // before the broadcast takes the slot: it is read again under the
    // gate's lock, and refused.
    let mut t = test_with(Bounds::default(), usize::MAX, 2, true);
    let (_, held) = a_broadcast_behind_a_heavy_reply(&mut t);
    let replacement = occupy(&t);
    let freed = std::rc::Rc::new(std::cell::Cell::new(false));
    t.chain.clock = a_clock_moving_at_the_gate(&freed, 199, 1_329);
    let requests = Arc::clone(&t.chain.requests);
    let set = std::rc::Rc::clone(&freed);
    t.chain.on_reply = Some(Box::new(move || {
        if !set.replace(true) {
            assert_eq!(requests.answered(held), Some(Owner::Naming));
        }
    }));
    assert!(t.chain.flush().is_ok());
    assert!(freed.get());
    let frames = t.written();
    let sent = verified(&frames);
    assert!(sent.is_empty(), "{sent:?}");
    let reply = frames.iter().find(|f| f["id"] == 4).unwrap();
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent", "{reply}");
    assert!(t.chain.queued.is_empty());
    // Refused, it took nothing.
    let free = occupy(&t);
    assert_eq!(t.chain.requests.answered(free), Some(Owner::Naming));
    assert_eq!(t.chain.requests.answered(replacement), Some(Owner::Naming));
}

#[test]
fn a_requests_deadline_is_what_is_left_as_it_takes_its_slot() {
    // Round 4: the deadline sent is read with the clock the request takes
    // its slot by, not the one the machine was last brought to.
    let mut t = test_with(Bounds::default(), usize::MAX, 1, true);
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let held = occupy(&t);
    let (id, params) = read(3, "eth_blockNumber", json!([]));
    t.call(id, "chain.request", &params);
    let until = t.chain.queued[0].until.unwrap();
    assert!(until > 1_329, "{until}");
    let freed = std::rc::Rc::new(std::cell::Cell::new(true));
    t.chain.clock = a_clock_moving_at_the_gate(&freed, 199, 1_329);
    assert_eq!(t.chain.requests.answered(held), Some(Owner::Naming));
    // Delivery alone: dispatch brings the machine to 199 ms itself.
    assert!(t.chain.deliver().is_ok());
    assert_eq!(t.chain.machine.now(), 199);
    let frames = t.written();
    let sent = requests(&frames);
    assert_eq!(sent.len(), 1, "{frames:?}");
    assert_eq!(sent[0]["method"], "shell.rpc");
    assert_eq!(sent[0]["params"]["deadline_ms"], until - 1_329);
}

#[test]
fn a_broadcast_late_once_its_frame_is_made_never_goes() {
    // Round 5, the reviewer's case: a queued Myotis broadcast of nearly one
    // frame, its cutoff 1 ms away. Making its frame (copying and escaping
    // up to one frame) took 31 ms: the start is checked after that, on a
    // fresh reading, so it never goes.
    let mut t = test_with(Bounds::default(), usize::MAX, 1, true);
    let mut config = chain_snapshot(&["direct"], &["a"]);
    config["myotis"] = json!(true);
    config["broadcast_order"] = json!(["myotis"]);
    t.configure(json!([config]));
    t.call(
        2,
        "chain.availability",
        &json!({ "chain_id": 1, "ready": true }),
    );
    let held = occupy(&t);
    t.call(
        3,
        "chain.broadcast",
        &json!({ "chain_id": 1, "raw": "0x01", "deadline_ms": 10_001 }),
    );
    let Some(Queued {
        request: Request::Verified(VerifiedOp::MyotisBroadcast { raw, .. }),
        until,
        ..
    }) = t.chain.queued.front_mut()
    else {
        panic!("no queued broadcast");
    };
    assert_eq!(*until, Some(1));
    *raw = format!(
        "0x{}",
        "ab".repeat((fc_protocol::frame::MAX_PAYLOAD - 1024) / 2)
    );
    // Within one frame: it would go.
    let (method, (params, deadline)) = shell_params(&t.chain.queued[0].request, 1);
    assert!(requests::request_frame(method, &params, deadline).is_some());
    let clock = std::rc::Rc::clone(&t.clock);
    let made = std::rc::Rc::new(std::cell::Cell::new(0));
    let count = std::rc::Rc::clone(&made);
    t.chain.on_frame = Some(Box::new(move || {
        count.set(count.get() + 1);
        clock.set(31);
    }));
    assert_eq!(t.chain.requests.answered(held), Some(Owner::Naming));
    assert!(t.chain.flush().is_ok());
    // Its frame was made, then refused.
    assert_eq!(made.get(), 1);
    let frames = t.written();
    let sent = verified(&frames);
    assert!(sent.is_empty(), "sent past its cutoff");
    let reply = frames.iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent", "{reply}");
    assert!(t.chain.queued.is_empty());
    // It took no slot.
    let free = occupy(&t);
    assert_eq!(t.chain.requests.answered(free), Some(Owner::Naming));
}

#[test]
fn a_requests_deadline_is_written_from_the_reading_it_starts_on() {
    // Round 5: the frame is made at 199 ms, and the request takes its
    // slot at 1,329 ms. Its `deadline_ms` is what is left then, written
    // into the frame already made.
    let mut t = test_with(Bounds::default(), usize::MAX, 1, true);
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let held = occupy(&t);
    let (id, params) = read(3, "eth_blockNumber", json!([]));
    t.call(id, "chain.request", &params);
    let until = t.chain.queued[0].until.unwrap();
    assert!(until > 1_329, "{until}");
    let clock = std::rc::Rc::clone(&t.clock);
    let made = std::rc::Rc::new(std::cell::Cell::new(0));
    let count = std::rc::Rc::clone(&made);
    t.chain.on_frame = Some(Box::new(move || {
        count.set(count.get() + 1);
        clock.set(1_329);
    }));
    // No frame is made while main holds all it takes.
    t.at(199);
    assert_eq!(made.get(), 0);
    assert_eq!(t.chain.requests.answered(held), Some(Owner::Naming));
    assert!(t.chain.flush().is_ok());
    assert_eq!(made.get(), 1);
    // The machine was last brought to 199 ms.
    assert_eq!(t.chain.machine.now(), 199);
    let frames = t.written();
    let sent = requests(&frames);
    assert_eq!(sent.len(), 1, "{frames:?}");
    assert_eq!(sent[0]["method"], "shell.rpc");
    assert_eq!(sent[0]["params"]["deadline_ms"], until - 1_329);
}

/// The clock moves to `to` as the next request's frame is made.
fn the_clock_moves_as_a_frame_is_made(t: &mut Test, to: u64) {
    let clock = std::rc::Rc::clone(&t.clock);
    t.chain.on_frame = Some(Box::new(move || clock.set(to)));
}

/// The `eth_sendRawTransaction` exchanges among `frames`.
fn sends(frames: &[Value]) -> usize {
    requests(frames)
        .into_iter()
        .filter(|f| f["method"] == "shell.rpc")
        .filter(|f| {
            let body: Value = serde_json::from_str(f["params"]["body"].as_str().unwrap()).unwrap();
            body["method"] == "eth_sendRawTransaction"
        })
        .count()
}

#[test]
fn a_direct_attempt_never_starts_past_its_broadcasts_cutoff() {
    // Daemon re-check of PR #57, MEDIUM (a): a Direct attempt's own
    // exchange runs 5 s, but no transaction is sent at or after the
    // broadcast's attempt cutoff, 200 ms here. The cutoff passes while
    // its frame is made.
    let mut t = test_with(Bounds::default(), usize::MAX, 1, true);
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let held = occupy(&t);
    t.call(
        3,
        "chain.broadcast",
        &json!({ "chain_id": 1, "raw": "0x01", "deadline_ms": 10_200 }),
    );
    assert!(t.chain.queued[0].request.sends_transaction());
    assert!(t.chain.queued[0].own.unwrap() > 231);
    t.at(199);
    the_clock_moves_as_a_frame_is_made(&mut t, 231);
    assert_eq!(t.chain.requests.answered(held), Some(Owner::Naming));
    assert!(t.chain.flush().is_ok());
    let frames = t.written();
    assert_eq!(sends(&frames), 0, "sent past the cutoff");
    // It never went: the broadcast is not sent, and the slot is free.
    let reply = frames.iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent", "{reply}");
    assert!(t.chain.queued.is_empty());
    let free = occupy(&t);
    assert_eq!(t.chain.requests.answered(free), Some(Owner::Naming));
}

#[test]
fn an_exchange_never_starts_past_its_reads_deadline() {
    // MEDIUM (b): the exchange's own deadline is later, but its read's
    // ends at 200 ms, passing while the frame is made. The read replies
    // `deadline`; the exchange never goes.
    let mut t = test_with(Bounds::default(), usize::MAX, 1, true);
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let held = occupy(&t);
    let (id, mut params) = read(3, "eth_blockNumber", json!([]));
    params["deadline_ms"] = json!(200);
    t.call(id, "chain.request", &params);
    assert!(t.chain.queued[0].own.unwrap() > 231);
    assert_eq!(t.chain.queued[0].deadline, Some(200));
    t.at(199);
    the_clock_moves_as_a_frame_is_made(&mut t, 231);
    assert_eq!(t.chain.requests.answered(held), Some(Owner::Naming));
    assert!(t.chain.flush().is_ok());
    let frames = t.written();
    assert!(requests(&frames).is_empty(), "{frames:?}");
    let reply = frames.iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(reply["error"]["code"], "deadline", "{reply}");
    assert!(t.chain.queued.is_empty());
    let free = occupy(&t);
    assert_eq!(t.chain.requests.answered(free), Some(Owner::Naming));
}

#[test]
fn an_exchange_ending_with_its_reads_deadline_replies_deadline() {
    // Daemon review, round 5: a queued exchange's own end, 500 ms, ties
    // with its read's deadline. The read's deadline goes first: the read
    // replies `deadline`, not the source error a never-sent exchange
    // makes. A deadline a millisecond earlier ends it the same way.
    for deadline_ms in [500, 499] {
        let mut t = test_with(Bounds::default(), usize::MAX, 1, true);
        let mut config = chain_snapshot(&["direct"], &["a"]);
        config["quorum"]["timeout_ms"] = json!(500);
        t.configure(json!([config]));
        let held = occupy(&t);
        let (id, mut params) = read(3, "eth_blockNumber", json!([]));
        params["deadline_ms"] = json!(deadline_ms);
        t.call(id, "chain.request", &params);
        assert_eq!(t.chain.queued[0].own, Some(500));
        assert_eq!(t.chain.queued[0].deadline, Some(deadline_ms));
        t.at(deadline_ms);
        let frames = t.written();
        assert!(requests(&frames).is_empty(), "{frames:?}");
        let reply = frames.iter().find(|f| f["id"] == 3).unwrap();
        assert_eq!(reply["error"]["code"], "deadline", "{deadline_ms}: {reply}");
        assert_eq!(reply["error"]["data"], json!({ "generation": 1 }));
        assert!(t.chain.queued.is_empty());
        assert_eq!(t.chain.requests.answered(held), Some(Owner::Naming));
    }
}

#[test]
fn a_broadcast_attempt_tied_with_its_deadline_is_not_sent() {
    // The tie for a broadcast's attempt: with no reconciliation room, its
    // cutoff is its deadline. The attempt that never went still expires
    // first, so the broadcast's outcome table reports `not_sent`, not an
    // outstanding, possibly sent, attempt.
    let bounds = Bounds {
        reconcile_ms: 0,
        ..Bounds::default()
    };
    let mut t = test_with(bounds, usize::MAX, 1, true);
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let held = occupy(&t);
    t.call(
        3,
        "chain.broadcast",
        &json!({ "chain_id": 1, "raw": "0x01", "deadline_ms": 500 }),
    );
    assert!(t.chain.queued[0].sends);
    assert_eq!(t.chain.queued[0].until, Some(500));
    assert_eq!(t.chain.queued[0].deadline, Some(500));
    t.at(500);
    let frames = t.written();
    assert_eq!(sends(&frames), 0);
    let reply = frames.iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent", "{reply}");
    assert!(t.chain.queued.is_empty());
    assert_eq!(t.chain.requests.answered(held), Some(Owner::Naming));
}

#[test]
fn a_reconciliation_read_tied_with_its_broadcasts_deadline_reports_through_the_table() {
    // A broadcast's reconciliation read whose exchange ends with the
    // broadcast's deadline: the deadline goes first, and the broadcast
    // reports through its outcome table. Its attempt went and was never
    // answered: `uncertain`.
    let mut t = test_with(Bounds::default(), usize::MAX, 2, true);
    let mut config = chain_snapshot(&["direct"], &["a"]);
    config["quorum"]["timeout_ms"] = json!(10_000);
    t.configure(json!([config]));
    t.call(
        3,
        "chain.broadcast",
        &json!({ "chain_id": 1, "raw": "0x01", "deadline_ms": 10_500 }),
    );
    assert_eq!(sends(&t.written()), 1);
    let held = occupy(&t);
    // The cutoff: the attempt in flight counts as possibly sent, and the
    // lookup waits for a slot, its exchange ending at the deadline.
    t.at(500);
    assert_eq!(t.chain.queued.len(), 1, "{:?}", t.written());
    assert!(!t.chain.queued[0].sends);
    assert_eq!(t.chain.queued[0].own, Some(10_500));
    assert_eq!(t.chain.queued[0].deadline, Some(10_500));
    t.written();
    t.at(10_500);
    let frames = t.written();
    assert!(requests(&frames).is_empty(), "{frames:?}");
    let reply = frames.iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(reply["result"]["outcome"], "uncertain", "{reply}");
    assert_eq!(reply["result"]["source"], "direct", "{reply}");
    assert!(t.chain.queued.is_empty());
    assert_eq!(t.chain.requests.answered(held), Some(Owner::Naming));
}

#[test]
fn a_myotis_read_never_starts_past_its_reads_deadline() {
    // MEDIUM (c): a Myotis read's operation has no deadline of its own,
    // but its read's ends at 200 ms, passing while its near-one-frame
    // call is made into a frame. It never goes, the read replies
    // `deadline`, and Myotis's one slot is free for the next read.
    let mut t = test_with(Bounds::default(), usize::MAX, 2, true);
    let mut config = chain_snapshot(&["myotis"], &[]);
    config["myotis"] = json!(true);
    t.configure(json!([config]));
    t.call(
        2,
        "chain.availability",
        &json!({ "chain_id": 1, "ready": true }),
    );
    let held = occupy(&t);
    let other = occupy(&t);
    let address = "0x1111111111111111111111111111111111111111";
    let data = format!("0x{}", "ab".repeat(450_000));
    let (id, mut params) = read(
        3,
        "eth_call",
        json!([{ "to": address, "data": data }, "latest"]),
    );
    params["deadline_ms"] = json!(200);
    t.call(id, "chain.request", &params);
    assert!(matches!(
        t.chain.queued[0].request,
        Request::Verified(VerifiedOp::MyotisRead { .. })
    ));
    assert_eq!(t.chain.queued[0].deadline, Some(200));
    t.at(199);
    the_clock_moves_as_a_frame_is_made(&mut t, 231);
    assert_eq!(t.chain.requests.answered(held), Some(Owner::Naming));
    assert!(t.chain.flush().is_ok());
    let frames = t.written();
    let sent = verified(&frames);
    assert!(sent.is_empty(), "{} sent past the deadline", sent.len());
    let reply = frames.iter().find(|f| f["id"] == 3).unwrap();
    assert_eq!(reply["error"]["code"], "deadline", "{reply}");
    assert!(t.chain.queued.is_empty());
    // The next read's operation goes at once.
    t.chain.on_frame = None;
    assert_eq!(t.chain.requests.answered(other), Some(Owner::Naming));
    let (next, params) = read(4, "eth_getBalance", json!([address, "latest"]));
    t.call(next, "chain.request", &params);
    assert_eq!(verified(&t.written()).len(), 1);
}

#[test]
fn a_request_late_by_this_threads_count_never_goes_whatever_the_machine_says() {
    // Were the machine ever to count a request's deadline later than this
    // thread does, its I/O found late at its slot still never goes, and
    // the thread doesn't spin on it.
    let mut t = test_with(Bounds::default(), usize::MAX, 1, true);
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let held = occupy(&t);
    let (id, params) = read(3, "eth_blockNumber", json!([]));
    t.call(id, "chain.request", &params);
    t.chain.queued[0].deadline = Some(200);
    t.at(199);
    the_clock_moves_as_a_frame_is_made(&mut t, 231);
    assert_eq!(t.chain.requests.answered(held), Some(Owner::Naming));
    assert!(t.chain.flush().is_ok());
    assert!(requests(&t.written()).is_empty());
    assert!(t.chain.queued.is_empty());
}

#[test]
fn replies_are_checked_in_place() {
    // R3-M2: names and values stay raw JSON; an escaped name, which
    // JSON.stringify never writes for these, is malformed, and only the
    // headers the core keeps are unescaped.
    for (kind, text) in [
        (
            Kind::Rpc,
            format!(r#"{{"st{}tus":200,"body":""}}"#, u("0061")),
        ),
        (
            Kind::Rpc,
            format!(r#"{{"status":200,"body":"e3{}="}}"#, u("0030")),
        ),
        (
            Kind::MyotisBroadcast,
            format!(r#"{{"f{}ilure":"error"}}"#, u("0061")),
        ),
        (
            Kind::MyotisBroadcast,
            format!(r#"{{"failure":"err{}r"}}"#, u("006f")),
        ),
        (
            Kind::MyotisBroadcast,
            r#"{"not_sent":true,"not_sent":true}"#.to_owned(),
        ),
        (
            Kind::Colibri,
            r#"{"revert":{"data":"0x","data":"0x"}}"#.to_owned(),
        ),
    ] {
        assert_eq!(answer(kind, raw(&text)), None, "{text}");
    }
    let page = format!(
        r#"{{"status":429,"headers":{{"Retry-After":"{}","x":"{}{}","content-length":"5"}},"body":""}}"#,
        u("0033"),
        "\\".repeat(4),
        u("0041"),
    );
    let Some(Answer::Blockscout { headers, .. }) = answer(Kind::Blockscout, raw(&page)) else {
        panic!("not a page: {page}");
    };
    assert_eq!(
        headers,
        [
            ("Retry-After".to_owned(), "3".to_owned()),
            ("content-length".to_owned(), "5".to_owned()),
        ]
    );
    // What serde_json keeps on its scratch stack for a raw value.
    for (text, depth) in [
        ("1", 0),
        ("[]", 1),
        (r#"{"a":[[{}]],"b":"[[[{"}"#, 4),
        (r#""\"[""#, 0),
        (r#"[[],[[]]]"#, 3),
    ] {
        assert_eq!(nesting(text), depth, "{text}");
    }
}

#[test]
fn a_deep_reply_nobody_reads_is_not_parsed_and_frees_its_slot() {
    // R3-M2: past the bound, even the scratch of a check would be
    // unreserved; the reply completes unread, so a verifier's slot frees.
    let mut t = test();
    let mut config = chain_snapshot(&["myotis"], &[]);
    config["myotis"] = json!(true);
    t.configure(json!([config]));
    t.call(
        2,
        "chain.availability",
        &json!({ "chain_id": 1, "ready": true }),
    );
    let address = "0x1111111111111111111111111111111111111111";
    let (id, params) = read(3, "eth_getBalance", json!([address, "latest"]));
    t.call(id, "chain.request", &params);
    let op = verified(&t.written())[0]["id"].as_u64().unwrap();
    assert!(t.chain.handle(In::Cancel { id: 3 }).is_ok());
    assert!(t.chain.flush().is_ok());
    t.written();
    let deep = format!(
        r#"{{"payload":{}{}}}"#,
        "[".repeat(UNRESERVED_NESTING + 1),
        "]".repeat(UNRESERVED_NESTING + 1)
    );
    assert_eq!(t.chain.requests.answered(op), Some(Owner::Chain));
    assert!(
        t.chain
            .handle(In::Response {
                id: op,
                reply: shell_result(op, &deep),
            })
            .is_ok()
    );
    assert!(t.chain.flush().is_ok());
    // The slot is free: the next read's operation goes at once.
    let (id, params) = read(4, "eth_getBalance", json!([address, "latest"]));
    t.call(id, "chain.request", &params);
    assert_eq!(verified(&t.written()).len(), 1);
}

// ---------------------------------------------------------------------------
// chain.html (design 0006)

const CONTRACT: &str = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
/// Its EIP-55 form, as `ethers.getAddress` gives it.
const CHECKSUMMED: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

fn html_params(contract: &str) -> Value {
    json!({
        "chain_id": 1,
        "contract": contract,
        "origin": format!("web3://{contract}:1"),
        "deadline_ms": 30_000,
    })
}

/// A JSON-RPC answer whose result is `html()`'s ABI encoding of `document`.
fn html_answer(document: &[u8]) -> String {
    let pad = document.len().div_ceil(32) * 32 - document.len();
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":"0x{:064x}{:064x}{}{}"}}"#,
        32,
        document.len(),
        hex(document),
        "00".repeat(pad)
    )
}

#[test]
fn html_params_are_validated_strictly() {
    let mut t = test();
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    let good = html_params(CONTRACT);
    let mut cases = Vec::new();
    for (key, value) in [
        (
            "contract",
            json!("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"),
        ),
        (
            "contract",
            json!("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beae"),
        ),
        (
            "contract",
            json!("0X5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"),
        ),
        // Mixed case with a wrong checksum: `getAddress` throws.
        (
            "contract",
            json!("0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
        ),
        ("contract", json!(7)),
        ("origin", json!(null)),
        ("deadline_ms", json!(120_001)),
        ("chain_id", json!(1u64 << 53)),
        ("extra", json!(true)),
    ] {
        let mut params = good.clone();
        params[key] = value;
        cases.push(params);
    }
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("origin");
    cases.push(missing);
    cases.push(json!([good.clone()]));
    for (i, params) in cases.iter().enumerate() {
        let id = 10 + i as u64;
        t.call(id, "chain.html", params);
        let frames = t.written();
        let reply = frames.iter().find(|f| f["id"] == id).unwrap();
        assert_eq!(reply["error"]["code"], "invalid_argument", "{params}");
        assert!(requests(&frames).is_empty());
    }
    // A lowercase contract, and its checksum form, are read as
    // `getAddress` reads them: today's `to`.
    for (id, contract) in [(50, CONTRACT), (51, CHECKSUMMED)] {
        t.call(id, "chain.html", &html_params(contract));
        let frames = t.written();
        let asked = requests(&frames);
        assert_eq!(asked.len(), 1);
        let body: Value =
            serde_json::from_str(asked[0]["params"]["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["method"], "eth_call");
        assert_eq!(
            body["params"],
            json!([{ "to": CHECKSUMMED, "data": "0x33c34ac3" }, "latest"])
        );
    }
}

#[test]
fn an_html_document_comes_as_base64_with_its_hash_and_class() {
    let mut t = test();
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    t.call(7, "chain.html", &html_params(CONTRACT));
    let frames = t.written();
    let id = requests(&frames)[0]["id"].as_u64().unwrap();
    // dweb.json's `hello`.
    assert!(
        t.answer(id, rpc_answer(&html_answer(b"<h1>hello</h1>")))
            .is_ok()
    );
    let frames = t.written();
    let reply = frames.iter().find(|f| f["id"] == 7).unwrap();
    let result = reply["result"].as_object().unwrap();
    assert_eq!(
        result.keys().collect::<Vec<_>>(),
        [
            "html_base64",
            "hash",
            "source",
            "verified",
            "trust",
            "class",
            "generation"
        ],
        "{reply}"
    );
    let html = base64::engine::general_purpose::STANDARD
        .decode(result["html_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(html, b"<h1>hello</h1>");
    assert_eq!(
        result["hash"],
        "0xcb02a6622b097fd62f34606ee58fc466e99e5353c08c5341bf7e47b76072bcd7"
    );
    assert_eq!(result["source"], "direct");
    assert_eq!(result["verified"], false);
    assert_eq!(result["trust"]["level"], "unverified");
    assert_eq!(result["trust"]["agreed"], json!([{ "ref": "a" }]));
    assert_eq!(result["class"], "untrusted");
    assert_eq!(result["generation"], 1);
    // The message measured before it was written is the one written.
    let empty = Done {
        id: 1,
        result: Ok(Success::Html {
            html: String::new(),
            hash: [0; 32],
            source: "direct",
            verified: false,
            trust: None,
            class: fc_chain::machine::HtmlClass::Trusted,
        }),
        outcome: None,
        settled: 0,
        generation: 1,
    };
    let message = reply_message(1, &empty);
    assert_eq!(message.len(), message.write().len());
    let written: Value = serde_json::from_slice(&message.write()).unwrap();
    assert_eq!(written["result"]["html_base64"], "");
    assert!(written["result"].get("trust").is_none());
}

#[test]
fn an_html_document_that_isnt_served_is_todays_error() {
    let mut t = test();
    t.configure(json!([chain_snapshot(&["direct"], &["a"])]));
    // One byte past the encoded bound, and no hex: the size is read first.
    let over = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#,
        "zz".repeat(8 * 1024 * 1024 + 96)
    );
    for (call, body, message, props) in [
        (
            7,
            over,
            "html() response exceeds Freedom's 8 MiB limit",
            json!({ "code": "ONCHAIN_APP_TOO_LARGE" }),
        ),
        (
            8,
            r#"{"jsonrpc":"2.0","id":1,"result":12}"#.to_owned(),
            "html() returned malformed ABI data",
            json!({}),
        ),
    ] {
        t.call(call, "chain.html", &html_params(CONTRACT));
        let frames = t.written();
        let id = requests(&frames)[0]["id"].as_u64().unwrap();
        assert!(t.answer(id, rpc_answer(&body)).is_ok());
        let frames = t.written();
        let reply = frames.iter().find(|f| f["id"] == call).unwrap();
        let error = &reply["error"];
        assert_eq!(error["code"], "chain_error", "{reply}");
        // A core error: only this one has the code main answers 413 for.
        assert_eq!(error["data"]["kind"], "core");
        assert_eq!(error["data"]["constructor"], "Error");
        assert_eq!(error["data"]["message"], message);
        assert_eq!(error["data"]["props"], props);
        assert_eq!(error["data"]["generation"], 1);
    }
}

/// The byte-at-a-time count `nesting` replaced, kept as the oracle.
fn reference_nesting(text: &str) -> usize {
    let (mut depth, mut deepest) = (0usize, 0usize);
    let (mut string, mut escaped) = (false, false);
    for byte in text.bytes() {
        if string {
            match byte {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => string = true,
            b'[' | b'{' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

/// `nesting` against the count it replaced, on random texts over the bytes
/// it treats differently (brackets inside and outside strings, quotes,
/// backslash runs, multi-byte characters) and on each of them at every
/// offset around the chunk boundaries of a long string. It counts any
/// text, valid JSON or not, as the old loop did.
#[test]
fn nesting_counts_as_the_byte_scan_did() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut below = |n: usize| {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        usize::try_from(state.wrapping_mul(0x9e37_79b9_7f4a_7c15) % n as u64).unwrap()
    };
    const PIECES: &[&str] = &[
        "\"",
        "\\",
        "\\\"",
        "\\\\",
        "[",
        "]",
        "{",
        "}",
        ",",
        ":",
        "a",
        "0",
        " ",
        "\u{e9}",
        "\u{1f510}",
        "\n",
    ];
    for _ in 0..100_000 {
        let text: String = (0..below(60))
            .map(|_| PIECES[below(PIECES.len())])
            .collect();
        assert_eq!(nesting(&text), reference_nesting(&text), "{text:?}");
    }
    for run in 0..70 {
        for special in ["\"", "\\\"", "\\\\", "\\", "[", "\\[", "\u{e9}", ""] {
            for tail in ["", "\"", "\"[[]", "\\\"[{", "]]"] {
                let text = format!("[{{\"k\":\"{}{special}{tail}", "x".repeat(run));
                assert_eq!(nesting(&text), reference_nesting(&text), "{text:?}");
            }
        }
    }
    // Deep, and a large reply's shape: one long string beside the brackets.
    let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    assert_eq!(nesting(&deep), 10_000);
    let body = "A".repeat(1 << 20);
    let reply =
        format!(r#"{{"type":"response","id":7,"result":{{"status":200,"body":"{body}"}}}}"#);
    assert_eq!(nesting(&reply), reference_nesting(&reply));
    assert_eq!(nesting(&reply), 2);
}
