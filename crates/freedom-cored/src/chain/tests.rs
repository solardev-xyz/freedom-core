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
    let chain = Chain::new(
        Machine::new(0, bounds),
        out,
        Arc::clone(&link),
        Shares {
            bulk: Allowance::new(usize::MAX, bulk),
            control: Allowance::new(usize::MAX, control),
        },
        Requests::new(outstanding, Arc::new(Pending::default())),
    );
    Test { chain, rx, link }
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

    /// Main's response, as the event loop routes it.
    fn answer(&mut self, id: u64, outcome: Result<Value, ErrorBody>) -> Flow {
        assert_eq!(self.chain.requests.answered(id), Some(Owner::Chain));
        let outcome = outcome.map(|v| RawValue::from_string(v.to_string()).unwrap());
        self.chain.handle(In::Response { id, outcome })?;
        self.chain.flush()
    }

    fn at(&mut self, now: u64) {
        assert!(self.chain.advance(now).is_ok());
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
            reason: "nonce too low \u{fffd}".into()
        }))
    );
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
            data: "0x12".into()
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
    ] {
        assert_eq!(answer(kind, raw(text)), None, "{kind:?} {text}");
    }
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
    match t
        .chain
        .requests
        .send(Owner::Naming, &allowance, &out, |id| {
            requests::request_frame(id, "shell.rpc", b"{}")
        }) {
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
