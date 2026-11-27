//! SAFE-2's S5 against a scripted chain (design 0016, SAFE-2's tests,
//! *Messages*): a page's Safe message started with the `safe-message` token
//! minted for its request, the vault owners signing in the core after the
//! eight reads; `vectors/safe.json`'s `messages` reproduced (the SafeMessage
//! hash, each owner's signature and the joined signature); a session
//! refused for another page; complete only at the threshold;
//! `safe.message_sign` reading the setup before each owner's signature, a
//! changed setup refusing it with nothing signed; a Ledger owner
//! `unsupported` until S6; the Safe's hold; and the session following the
//! records.

use fc_protocol::message::{CallerKind, PageContext};
use fc_vault::state::VaultState;

use super::propose::{
    Flows, OA, OB, OC, OD, OE, S2, S3, S4, SIGNING_READS, chain_for, flows_meta, unlocked, world,
};
use super::*;

const HANDLE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SITE: &str = "https://app.example";

fn vectors() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/safe.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn message(id: &str) -> Value {
    vectors()["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["id"] == id)
        .unwrap()
        .clone()
}

fn index_of_safe(name: &str) -> u64 {
    match name {
        "S2" => S2,
        "S3" => S3,
        "S4" => S4,
        _ => panic!("{name}"),
    }
}

/// A page's context: `origin` in frame `frame`.
fn page(origin: &str, frame: u64) -> Context {
    Context {
        caller: CallerKind::Page,
        page: Some(PageContext {
            origin: origin.to_owned(),
            top_origin: origin.to_owned(),
            frame,
            navigation: 1,
            agent: Some(false),
            transport_key: None,
        }),
    }
}

fn caller(kind: CallerKind) -> Context {
    Context {
        caller: kind,
        page: None,
    }
}

/// `personal_sign` of `text` for the Safe at `index`.
fn personal(index: u64, text: &str) -> Value {
    json!({
        "method": "personal_sign",
        "params": [text, checksum_address(&Flows::address(index))],
    })
}

impl Harness {
    /// The `safe-message` token `eip1193.request` mints for `request` to
    /// the Safe at `index`, under the harness's page with its handle.
    fn message_token(&mut self, index: u64, request: &Value) -> String {
        let params = json!({
            "kind": "safe-message", "account": index, "handle": HANDLE,
            "payload": {
                "safe": checksum_address(&Flows::address(index)), "chain_id": "100",
                "method": request["method"], "params": request["params"],
            },
        });
        let context = self.context.clone();
        let reply = self
            .approvals
            .request(1, "approval.issue", &params, &context, CLOCKS)
            .unwrap();
        let reply: Value = serde_json::from_slice(&reply).unwrap();
        reply["result"]["token"].as_str().unwrap().to_owned()
    }

    /// `safe.message_start` of `request` with `token`, under the harness's
    /// page.
    fn message_start(&mut self, index: u64, request: &Value, token: &str) -> Value {
        self.call(
            "safe.message_start",
            json!({
                "safe": index, "request": request,
                "display": { "kind": "message", "site": SITE, "method": request["method"] },
                "authorization": { "token": token, "handle": HANDLE },
            }),
        )
    }

    /// Minted and started under the page `SITE` in frame 1: the answer.
    fn message_started(&mut self, index: u64, request: &Value) -> Value {
        self.context = page(SITE, 1);
        let token = self.message_token(index, request);
        self.message_start(index, request, &token)
    }

    /// A board call (`safe.message_sign`, `_state`, `_cancel`,
    /// `_complete`) from main, naming `session` and `owner`.
    fn board(&mut self, method: &str, index: u64, session: &str, owner: Option<u64>) -> Value {
        let context = std::mem::replace(&mut self.context, caller(CallerKind::Shell));
        let mut params = json!({ "safe": index, "session": session });
        if let Some(owner) = owner {
            params["owner"] = json!(owner);
        }
        let reply = self.call(method, params);
        self.context = context;
        reply
    }

    /// The Safe's open session's kept signatures, by owner.
    fn kept(&self, index: u64) -> Vec<(String, String)> {
        self.safes.sessions.open[&index]
            .signatures
            .kept()
            .iter()
            .map(|kept| (checksum_address(kept.owner()), to_hex(kept.signature())))
            .collect()
    }
}

fn session_of(answer: &Value) -> String {
    let session = result(answer)["session"].as_str().unwrap().to_owned();
    assert_eq!(session.len(), 32, "{session}");
    assert!(
        session
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    );
    session
}

/// The vector signatures, by owner.
fn vector_signatures(case: &Value) -> Vec<(String, String)> {
    let mut signatures: Vec<(String, String)> = case["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["signer"].as_str().unwrap().to_owned(),
                s["data"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    signatures.sort_by_key(|(signer, _)| fc_evm::parse_address(signer).unwrap());
    signatures
}

// --- The vectors ---------------------------------------------------------

/// Every `messages` case of a 1-of-2 and a 2-of-3 Safe of vault owners:
/// `safe.message_start` reads all eight, the nonce last, has the vault
/// owners sign in the record's order until the threshold, each signature
/// the reference's, and answers the session's state with the reference's
/// SafeMessage hash; `safe.message_complete` then gives the reference's
/// joined signature and drops the session.
#[test]
fn start_and_complete_give_the_reference_s_signatures() {
    let cases: Vec<Value> = vectors()["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| matches!(case["safe"]["name"].as_str(), Some("S2" | "S3")))
        .cloned()
        .collect();
    assert_eq!(cases.len(), 18);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let index = index_of_safe(case["safe"]["name"].as_str().unwrap());
        let mut h = world(index, 3);
        let answer = h.message_started(index, &case["request"]);
        assert_eq!(h.asked, SIGNING_READS, "{id}: {answer}");
        let session = session_of(&answer);
        let state = &result(&answer)["state"];
        let (owners, threshold, _) = Flows::owners(index);
        assert_eq!(state["hash"], case["hash"], "{id}");
        assert_eq!(state["safeIndex"], index);
        assert_eq!(state["kind"], "message");
        assert_eq!(state["chainId"], 100);
        assert_eq!(state["threshold"], threshold);
        assert_eq!(state["collected"], threshold, "{id}");
        assert_eq!(state["complete"], true);
        assert_eq!(state["createdAt"], CLOCKS.wall_ms);
        assert_eq!(
            state["display"],
            json!({ "kind": "message", "site": SITE, "method": case["request"]["method"] })
        );
        assert!(
            state.get("token").is_none(),
            "the ID goes only in `session`"
        );
        let signers: Vec<&str> = case["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["signer"].as_str().unwrap())
            .collect();
        let rows = state["owners"].as_array().unwrap();
        assert_eq!(rows.len(), owners.len());
        for (row, owner) in rows.iter().zip(&owners) {
            assert_eq!(row["address"], *owner);
            assert_eq!(row["type"], "mnemonic");
            assert_eq!(row["signed"], signers.contains(owner), "{id}: {owner}");
        }
        assert_eq!(h.kept(index), vector_signatures(&case), "{id}");
        // Main's state of it, then its completion.
        let again = h.board("safe.message_state", index, &session, None);
        assert_eq!(result(&again), state, "{id}");
        h.asked.clear();
        let done = h.board("safe.message_complete", index, &session, None);
        assert_eq!(result(&done)["signature"], case["signature"], "{id}");
        assert!(h.asked.is_empty(), "the join reads nothing");
        // Completed: the session is gone.
        let state = h.board("safe.message_state", index, &session, None);
        assert_eq!(result(&state), &Value::Null);
        let again = h.board("safe.message_complete", index, &session, None);
        assert_eq!(
            again["error"]["message"],
            "No signature request is open for this account"
        );
    }
}

/// A Safe with a Ledger and a phone among its owners (`S4`, D, A and E, 2 of
/// 3): the vault owner A signs at the start, the reference's signature; the
/// join waits for the threshold ("Not enough signatures yet (1 of 2)", the
/// `below-the-threshold` case); the Ledger owner D signs through
/// `safe.message_sign` only with S6, `unsupported` until then, and so is
/// the phone owner E. A sweep with nothing left to sign reads nothing.
#[test]
fn a_device_owner_waits_and_the_join_waits_for_the_threshold() {
    for id in ["S4-below-the-threshold", "S4-device-owner"] {
        let case = message(id);
        let mut h = world(S4, 3);
        let answer = h.message_started(S4, &case["request"]);
        let session = session_of(&answer);
        let state = &result(&answer)["state"];
        assert_eq!(state["hash"], case["hash"], "{id}");
        assert_eq!(state["collected"], 1);
        assert_eq!(state["complete"], false);
        let a = vector_signatures(&case)
            .into_iter()
            .filter(|(signer, _)| signer == OA)
            .collect::<Vec<_>>();
        assert_eq!(h.kept(S4), a, "{id}");
        let types: Vec<&Value> = state["owners"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| &row["type"])
            .collect();
        assert_eq!(
            types,
            [&json!("ledger"), &json!("mnemonic"), &json!("remote")]
        );
        let done = h.board("safe.message_complete", S4, &session, None);
        assert_eq!(done["error"]["code"], "invalid_argument");
        assert_eq!(
            done["error"]["message"],
            "Not enough signatures yet (1 of 2)"
        );
        h.asked.clear();
        for owner in [1_000_000, 1_000_001] {
            let reply = h.board("safe.message_sign", S4, &session, Some(owner));
            assert_eq!(refusal(&reply), "unsupported", "{owner}");
        }
        let reply = h.board("safe.message_sign", S4, &session, None);
        assert_eq!(result(&reply)["collected"], 1);
        // A's again: idempotent.
        let reply = h.board("safe.message_sign", S4, &session, Some(0));
        assert_eq!(result(&reply)["collected"], 1);
        assert!(h.asked.is_empty(), "{:?}", h.asked);
        // Not an owner of this Safe.
        let reply = h.board("safe.message_sign", S4, &session, Some(1));
        assert_eq!(
            reply["error"]["message"],
            "That account is not an owner of this Safe"
        );
        // The session is unchanged.
        assert_eq!(h.kept(S4), a);
    }
    let _ = (OD, OE);
}

// --- The session's page and ID -----------------------------------------

/// A session is main's for one page request: while it is open, another
/// start for the Safe is `SAFE_MESSAGE_EXISTS`, from another page and from
/// the same one, with nothing read; a token minted for one page is spent
/// by no other; and each board call needs the session's ID: another's is
/// "a different page", and the state answers `null`.
#[test]
fn a_session_is_refused_for_another_page() {
    let mut h = world(S3, 3);
    h.state = VaultState::new();
    let request = personal(S3, "Hello, Safe");
    let answer = h.message_started(S3, &request);
    let session = session_of(&answer);
    assert_eq!(result(&answer)["state"]["collected"], 0);
    for (origin, frame) in [("https://other.example", 1), (SITE, 2), (SITE, 1)] {
        h.context = page(origin, frame);
        let token = h.message_token(S3, &request);
        h.asked.clear();
        let reply = h.message_start(S3, &request, &token);
        assert_eq!(refusal(&reply), "SAFE_MESSAGE_EXISTS", "{origin} {frame}");
        assert_eq!(
            reply["error"]["message"],
            "Another signature request is already open for this account \u{2014} finish or cancel it first"
        );
        assert!(h.asked.is_empty());
    }
    // A token minted for one page, presented by another: refused, burnt,
    // nothing read or opened.
    h.context = page(SITE, 1);
    let request = personal(S2, "Hello, Safe");
    let token = h.message_token(S2, &request);
    h.context = page("https://other.example", 1);
    h.asked.clear();
    let reply = h.message_start(S2, &request, &token);
    assert_eq!(reply["error"]["code"], "not_authorized", "{reply}");
    assert_eq!(reply["error"]["data"]["reason"], "mismatch");
    assert!(h.asked.is_empty());
    assert!(!h.safes.sessions.open.contains_key(&S2));
    // Another session's ID, or no hex at all.
    let other = "0".repeat(32);
    for wrong in [other.as_str(), "not an id", &session.to_uppercase()] {
        for method in [
            "safe.message_sign",
            "safe.message_complete",
            "safe.message_cancel",
        ] {
            let reply = h.board(method, S3, wrong, None);
            assert_eq!(
                reply["error"]["message"], "This signature request belongs to a different page",
                "{method} {wrong}"
            );
        }
        let reply = h.board("safe.message_state", S3, wrong, None);
        assert_eq!(result(&reply), &Value::Null);
    }
    // The session is still there, for its ID.
    let state = h.board("safe.message_state", S3, &session, None);
    assert_eq!(result(&state)["collected"], 0);
    // Under the chrome too.
    h.context = caller(CallerKind::Chrome);
    let state = h.call(
        "safe.message_state",
        json!({ "safe": S3, "session": session }),
    );
    assert_eq!(result(&state)["collected"], 0);
    // Only a page starts one.
    for kind in [CallerKind::Chrome, CallerKind::Shell] {
        h.context = caller(kind);
        let reply = h.call(
            "safe.message_start",
            json!({ "safe": S2, "request": personal(S2, "x"),
                    "authorization": { "token": "00".repeat(32) } }),
        );
        assert_eq!(reply["error"]["code"], "forbidden", "{kind:?}");
    }
}

/// Complete only at the threshold: a 2-of-3 Safe opened while the vault
/// was locked collects nothing, and its sweep reads nothing; unlocked, a
/// named owner signs after the eight reads, once; the sweep then signs the
/// next vault owner, after its reads, which meets the threshold; a third
/// owner is then refused (`SAFE_APPROVAL_NEEDED`), and the join gives the
/// two signatures sorted by owner.
#[test]
fn a_session_completes_only_at_the_threshold() {
    let mut h = world(S3, 3);
    h.state = VaultState::new();
    let request = personal(S3, "Hello, Safe");
    let answer = h.message_started(S3, &request);
    let session = session_of(&answer);
    let hash = result(&answer)["state"]["hash"].clone();
    let done = h.board("safe.message_complete", S3, &session, None);
    assert_eq!(
        done["error"]["message"],
        "Not enough signatures yet (0 of 2)"
    );
    h.asked.clear();
    let reply = h.board("safe.message_sign", S3, &session, None);
    assert_eq!(result(&reply)["collected"], 0);
    assert!(h.asked.is_empty());
    // A named vault owner while locked: the vault's refusal, nothing read.
    let reply = h.board("safe.message_sign", S3, &session, Some(2));
    assert_eq!(reply["error"]["code"], "vault_locked", "{reply}");
    assert!(h.asked.is_empty());
    h.state = unlocked();
    let reply = h.board("safe.message_sign", S3, &session, Some(2));
    assert_eq!(h.asked, SIGNING_READS);
    let state = result(&reply).clone();
    assert_eq!(state["collected"], 1);
    assert_eq!(state["complete"], false);
    let signed: Vec<_> = state["owners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["signed"].as_bool().unwrap())
        .collect();
    assert_eq!(signed, [false, false, true]);
    // Again: idempotent, nothing read.
    h.asked.clear();
    let reply = h.board("safe.message_sign", S3, &session, Some(2));
    assert_eq!(result(&reply)["collected"], 1);
    assert!(h.asked.is_empty());
    let done = h.board("safe.message_complete", S3, &session, None);
    assert_eq!(
        done["error"]["message"],
        "Not enough signatures yet (1 of 2)"
    );
    // The sweep: A, the first vault owner that hasn't signed.
    let reply = h.board("safe.message_sign", S3, &session, None);
    assert_eq!(h.asked, SIGNING_READS);
    assert_eq!(result(&reply)["collected"], 2);
    assert_eq!(result(&reply)["complete"], true);
    // Past the threshold no owner signs.
    h.asked.clear();
    let reply = h.board("safe.message_sign", S3, &session, Some(1));
    assert_eq!(refusal(&reply), "SAFE_APPROVAL_NEEDED");
    let reply = h.board("safe.message_sign", S3, &session, None);
    assert_eq!(result(&reply)["collected"], 2);
    assert!(h.asked.is_empty());
    // Joined: C's then A's, sorted by owner, each recovering to its owner
    // over the SafeMessage's hash.
    let done = h.board("safe.message_complete", S3, &session, None);
    let joined = parse_bytes(result(&done)["signature"].as_str().unwrap(), "").unwrap();
    assert_eq!(joined.len(), 130);
    let hash: [u8; 32] = parse_bytes(hash.as_str().unwrap(), "")
        .unwrap()
        .try_into()
        .unwrap();
    let recovered: Vec<String> = joined
        .chunks(65)
        .map(|signature| {
            let signature: [u8; 65] = signature.try_into().unwrap();
            checksum_address(&fc_evm::recover_address(&hash, &signature).unwrap())
        })
        .collect();
    assert_eq!(recovered, [OC, OA]);
    let _ = OB;
}

// --- The setup, read before each owner's signature ----------------------

/// A session opened with the vault locked, then the vault unlocked: the
/// board's step signs only if the eight reads show the record's setup,
/// each verified. A changed setup is `safe_changed`, an unverified read
/// `safe_unverified`, no code `not_deployed`, each with nothing signed.
#[test]
fn sign_reads_the_setup_before_each_owner_s_signature() {
    let mut handler = word(&FALLBACK_HANDLER);
    handler[31] ^= 1;
    let base = || chain_for(S2, 3);
    let cases = [
        (base().with("threshold", hex_words(&[uint(2)])), "changed"),
        (
            base().with(
                "owners",
                owner_list(&[address(OA), address(OB), address(OC)]),
            ),
            "changed",
        ),
        (base().with("handler", hex_words(&[handler])), "changed"),
        (
            base().with("singleton", hex_words(&[word(&[0x99; 20])])),
            "changed",
        ),
        (base().served("nonce", Serve::Unverified), "unverified"),
        (base().served("owners", Serve::Failed), "unverified"),
        (base().with("code", json!("0x")), "not_deployed"),
    ];
    for (chain, code) in cases {
        for owner in [None, Some(0)] {
            let mut h = world(S2, 3);
            h.state = VaultState::new();
            let answer = h.message_started(S2, &personal(S2, "Hello, Safe"));
            let session = session_of(&answer);
            h.state = unlocked();
            h.chain = chain.clone();
            let reply = h.board("safe.message_sign", S2, &session, owner);
            assert_eq!(refusal(&reply), code, "{owner:?}: {reply}");
            assert_eq!(h.safes.sessions.open[&S2].signatures.len(), 0);
            // The session waits: the setup as Freedom made it again, signed.
            h.chain = base();
            let reply = h.board("safe.message_sign", S2, &session, owner);
            assert_eq!(result(&reply)["complete"], true);
        }
    }
}

/// `safe.message_start` refused after its reads: `safe_changed`,
/// `safe_unverified` (each of the eight unverified in turn), `not_deployed`.
/// Nothing is signed, no session opens, and the token is spent.
#[test]
fn start_opens_nothing_on_a_read_that_fails_the_check() {
    let mut cases = vec![
        (
            chain_for(S2, 3).with("threshold", hex_words(&[uint(2)])),
            "changed",
        ),
        (chain_for(S2, 3).with("code", json!("0x")), "not_deployed"),
    ];
    for read in SIGNING_READS {
        cases.push((
            chain_for(S2, 3).served(read, Serve::Unverified),
            "unverified",
        ));
    }
    for (chain, code) in cases {
        let mut h = world(S2, 3);
        h.chain = chain;
        h.context = page(SITE, 1);
        let request = personal(S2, "Hello, Safe");
        let token = h.message_token(S2, &request);
        let reply = h.message_start(S2, &request, &token);
        assert_eq!(refusal(&reply), code, "{reply}");
        assert!(h.safes.sessions.open.is_empty());
        // Spent with its request.
        h.chain = chain_for(S2, 3);
        let reply = h.message_start(S2, &request, &token);
        assert_eq!(reply["error"]["data"]["reason"], "unknown_token", "{reply}");
    }
}

/// Refused before any read or spend: a Safe the record doesn't mark
/// deployed (`not_deployed`), another method than the two a Safe answers,
/// a message `normalizeMessage` refuses, typed data the core can't hash,
/// and malformed params; each burns the token it presented.
#[test]
fn start_refuses_before_any_read() {
    let mut h = Harness::new(flows_meta(true), chain_for(S2, 3));
    h.state = unlocked();
    let request = personal(S2, "Hello, Safe");
    let reply = h.message_started(S2, &request);
    assert_eq!(refusal(&reply), "not_deployed");
    assert_eq!(reply["error"]["message"], NOT_DEPLOYED_TEXT);
    assert!(h.asked.is_empty());
    let mut h = world(S2, 3);
    h.context = page(SITE, 1);
    let safe = checksum_address(&Flows::address(S2));
    for (request, message) in [
        (
            json!({ "method": "eth_sign", "params": [safe, "0x01"] }),
            "Unsupported signing method for Safe accounts: eth_sign",
        ),
        (
            json!({ "method": "personal_sign", "params": ["0x0", safe] }),
            "Invalid hex message",
        ),
        (
            json!({ "method": "eth_signTypedData_v4", "params": [safe, "{"] }),
            "Typed data is not JSON",
        ),
    ] {
        let token = h.message_token(S2, &request);
        let reply = h.message_start(S2, &request, &token);
        assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
        assert_eq!(reply["error"]["message"], message);
        let again = h.message_start(S2, &request, &token);
        assert_eq!(again["error"]["message"], message);
        assert!(h.asked.is_empty());
    }
    for params in [
        json!({ "safe": S2, "request": request, "authorization": {}, "more": 1 }),
        json!({ "safe": S2, "request": { "method": "personal_sign" }, "authorization": {} }),
        json!({ "safe": S2, "request": { "method": "personal_sign", "params": "x" },
                "authorization": {} }),
        json!({ "safe": S2, "request": request }),
        json!({ "safe": "S2", "request": request, "authorization": {} }),
    ] {
        let reply = h.call("safe.message_start", params);
        assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
    }
    // An authorization that is neither form.
    let reply = h.call(
        "safe.message_start",
        json!({ "safe": S2, "request": request, "authorization": {} }),
    );
    assert_eq!(reply["error"]["code"], "invalid_argument");
    assert!(h.asked.is_empty());
    assert!(h.safes.sessions.open.is_empty());
}

/// The site's standing rule answers in the token's place, as `approval.spend
/// { standing }` checks it: with none, `no_rule` and nothing read; with the
/// site's signing rule for the Safe, the session opens.
#[test]
fn a_standing_rule_starts_one_as_approval_spend_checks_it() {
    let mut h = world(S2, 3);
    h.context = page(SITE, 1);
    let request = personal(S2, "Hello, Safe");
    let standing = |request: &Value| json!({ "safe": S2, "request": request, "authorization": { "standing": {} } });
    let reply = h.call("safe.message_start", standing(&request));
    assert_eq!(reply["error"]["code"], "not_authorized", "{reply}");
    assert_eq!(reply["error"]["data"]["reason"], "no_rule");
    assert!(h.asked.is_empty());
    // Both forms at once.
    let reply = h.call(
        "safe.message_start",
        json!({ "safe": S2, "request": request,
                "authorization": { "standing": {}, "token": "00".repeat(32) } }),
    );
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
    // Main's file, today's rules: the Safe connected with signing on.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("dapp-permissions.json"),
        json!({ SITE: {
            "origin": SITE, "connectedAt": 1_762_000_000_000_u64,
            "lastUsed": 1_762_000_000_000_u64, "walletIndex": S2, "chainId": 100,
            "autoApprove": { "signing": true, "transactions": [] },
        } })
        .to_string(),
    )
    .unwrap();
    h.approvals
        .configure_grants(dir.path().to_owned(), Vec::new(), CLOCKS.wall_ms);
    let reply = h.call("safe.message_start", standing(&request));
    assert_eq!(h.asked, SIGNING_READS, "{reply}");
    assert_eq!(result(&reply)["state"]["complete"], true);
    // In Agent custody, no rule answers.
    let session = session_of(&reply);
    assert_eq!(
        result(&h.board("safe.message_complete", S2, &session, None))["signature"]
            .as_str()
            .unwrap()
            .len(),
        132
    );
    let mut custody = page(SITE, 1);
    if let Some(page) = custody.page.as_mut() {
        page.agent = None;
    }
    h.context = custody;
    let reply = h.call("safe.message_start", standing(&request));
    assert_eq!(reply["error"]["code"], "not_authorized", "{reply}");
}

// --- The Safe's hold ------------------------------------------------------

/// A message's step holds the Safe: while a start's reads are out, another
/// start, a proposal, a discard and an execution are `SAFE_BUSY`; while a
/// sign's are, a cancel ends the session (`SAFE_BUSY`), the sign then signs
/// nothing (`SAFE_DISCARDED`), the state answers `null`, and the next
/// cancel drops it, after which a new start opens.
#[test]
fn a_message_step_holds_its_safe() {
    let mut h = world(S2, 3);
    h.state = VaultState::new();
    let request = personal(S2, "Hello, Safe");
    h.context = page(SITE, 1);
    let token = h.message_token(S2, &request);
    h.hold = true;
    let outs = h.send(
        "safe.message_start",
        json!({ "safe": S2, "request": request,
                "authorization": { "token": token, "handle": HANDLE } }),
    );
    assert!(h.drive(outs).is_none());
    let second = h.message_token(S2, &request);
    let reply = h.message_start(S2, &request, &second);
    assert_eq!(refusal(&reply), "SAFE_BUSY");
    assert_eq!(
        reply["error"]["message"],
        "Another step of this transaction is still running"
    );
    h.context = caller(CallerKind::Shell);
    let reply = h.call("safe.discard", json!({ "safe": S2 }));
    assert_eq!(refusal(&reply), "SAFE_BUSY");
    let reply = h.call(
        "safe.propose",
        json!({ "safe": S2, "safe_tx_hash": to_hex(&[0x11; 32]),
                "authorization": { "token": "00".repeat(32) } }),
    );
    assert_eq!(refusal(&reply), "SAFE_BUSY");
    // Another Safe isn't held.
    let reply = h.call("safe.discard", json!({ "safe": S3 }));
    assert_eq!(result(&reply), &json!({}));
    // The reads come in: the session opens.
    h.hold = false;
    let mut queue = Vec::new();
    for read in std::mem::take(&mut h.held) {
        let payload = payload(&h.chain, &read);
        queue.extend(h.safes.chain_read(read.tag, &payload, false, ctx!(h)));
    }
    let answer = h.drive(queue).unwrap();
    let session = session_of(&answer);
    // A sign's reads held, the vault unlocked meanwhile.
    h.state = unlocked();
    h.hold = true;
    let outs = h.send(
        "safe.message_sign",
        json!({ "safe": S2, "session": session }),
    );
    assert!(h.drive(outs).is_none());
    let reply = h.board("safe.message_complete", S2, &session, None);
    assert_eq!(refusal(&reply), "SAFE_BUSY");
    let reply = h.board("safe.message_cancel", S2, &session, None);
    assert_eq!(refusal(&reply), "SAFE_BUSY");
    assert_eq!(
        reply["error"]["message"],
        "Wait for the current step to finish first"
    );
    let state = h.board("safe.message_state", S2, &session, None);
    assert_eq!(result(&state), &Value::Null);
    h.hold = false;
    let mut queue = Vec::new();
    for read in std::mem::take(&mut h.held) {
        let payload = payload(&h.chain, &read);
        queue.extend(h.safes.chain_read(read.tag, &payload, false, ctx!(h)));
    }
    let reply = h.drive(queue).unwrap();
    assert_eq!(refusal(&reply), "SAFE_DISCARDED");
    assert_eq!(h.safes.sessions.open[&S2].signatures.len(), 0);
    let reply = h.board("safe.message_sign", S2, &session, None);
    assert_eq!(refusal(&reply), "SAFE_DISCARDED");
    assert_eq!(
        reply["error"]["message"],
        "This signature request has ended"
    );
    let reply = h.board("safe.message_cancel", S2, &session, None);
    assert_eq!(result(&reply), &json!({}));
    assert!(h.safes.sessions.open.is_empty());
    // Cancelled twice: fine.
    let reply = h.board("safe.message_cancel", S2, &session, None);
    assert_eq!(result(&reply), &json!({}));
    let answer = h.message_started(S2, &request);
    assert_eq!(result(&answer)["state"]["complete"], true);
}

/// An ended session gives way to the next start; the request's cancel
/// while its reads are out opens nothing.
#[test]
fn an_ended_session_gives_way() {
    let mut h = world(S2, 3);
    h.state = VaultState::new();
    let request = personal(S2, "Hello, Safe");
    let session = session_of(&h.message_started(S2, &request));
    h.safes.sessions.open.get_mut(&S2).unwrap().ended = true;
    h.state = unlocked();
    let answer = h.message_started(S2, &request);
    let fresh = session_of(&answer);
    assert_ne!(fresh, session);
    assert_eq!(result(&answer)["state"]["collected"], 1);
    let reply = h.board("safe.message_cancel", S2, &fresh, None);
    assert_eq!(result(&reply), &json!({}));
    // Cancelled during its reads: no session.
    h.context = page(SITE, 1);
    let token = h.message_token(S2, &request);
    h.hold = true;
    let outs = h.send(
        "safe.message_start",
        json!({ "safe": S2, "request": request,
                "authorization": { "token": token, "handle": HANDLE } }),
    );
    assert!(h.drive(outs).is_none());
    assert!(!h.safes.cancel(9).is_empty());
    h.hold = false;
    let mut queue = Vec::new();
    for read in std::mem::take(&mut h.held) {
        let payload = payload(&h.chain, &read);
        queue.extend(h.safes.chain_read(read.tag, &payload, false, ctx!(h)));
    }
    assert!(h.drive(queue).is_none());
    assert!(h.safes.sessions.open.is_empty());
}

/// The session follows the records: a Safe removed drops it, and one
/// removed while its start's reads were out opens none.
#[test]
fn a_removed_safe_drops_its_session() {
    let mut h = world(S3, 3);
    h.state = VaultState::new();
    let session = session_of(&h.message_started(S3, &personal(S3, "Hello, Safe")));
    h.meta["derivedWallets"]
        .as_array_mut()
        .unwrap()
        .retain(|record| record["index"] != S3);
    h.records();
    let state = h.board("safe.message_state", S3, &session, None);
    assert_eq!(result(&state), &Value::Null);
    assert!(h.safes.sessions.open.is_empty());
    // Removed during the start's reads.
    let mut h = world(S2, 3);
    h.context = page(SITE, 1);
    let request = personal(S2, "Hello, Safe");
    let token = h.message_token(S2, &request);
    h.hold = true;
    let outs = h.send(
        "safe.message_start",
        json!({ "safe": S2, "request": request,
                "authorization": { "token": token, "handle": HANDLE } }),
    );
    assert!(h.drive(outs).is_none());
    h.meta["derivedWallets"]
        .as_array_mut()
        .unwrap()
        .retain(|record| record["index"] != S2);
    h.records();
    h.hold = false;
    let mut queue = Vec::new();
    for read in std::mem::take(&mut h.held) {
        let payload = payload(&h.chain, &read);
        queue.extend(h.safes.chain_read(read.tag, &payload, false, ctx!(h)));
    }
    let reply = h.drive(queue).unwrap();
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
    assert!(h.safes.sessions.open.is_empty());
}

/// Every method answers `not_moved` before `vault_meta` is moved.
#[test]
fn messages_need_the_records() {
    let mut h = world(S2, 3);
    h.approvals.set_records(None);
    h.context = page(SITE, 1);
    let reply = h.call(
        "safe.message_start",
        json!({ "safe": S2, "request": personal(S2, "x"),
                "authorization": { "token": "00".repeat(32), "handle": HANDLE } }),
    );
    assert_eq!(reply["error"]["code"], "not_moved", "{reply}");
    for method in [
        "safe.message_sign",
        "safe.message_state",
        "safe.message_cancel",
        "safe.message_complete",
    ] {
        let reply = h.board(method, S2, &"0".repeat(32), None);
        assert_eq!(reply["error"]["code"], "not_moved", "{method}");
    }
}

/// A start whose answer couldn't reach main in one frame opens no session:
/// nobody could name it, and it would hold the Safe's one session.
#[test]
fn a_session_main_could_not_learn_is_not_opened() {
    let mut h = world(S2, 3);
    h.context = page(SITE, 1);
    let request = personal(S2, "Hello, Safe");
    let token = h.message_token(S2, &request);
    let reply = h.call(
        "safe.message_start",
        json!({
            "safe": S2, "request": request,
            "display": "x".repeat(fc_protocol::frame::MAX_PAYLOAD),
            "authorization": { "token": token, "handle": HANDLE },
        }),
    );
    assert_eq!(
        reply["error"]["code"],
        "internal",
        "{}",
        &reply.to_string()[..200]
    );
    assert!(h.safes.sessions.open.is_empty());
    let answer = h.message_started(S2, &request);
    assert_eq!(result(&answer)["state"]["complete"], true);
}

// --- The session ID, never left behind ----------------------------------

/// The unit tests' allocator on Linux: the system's, through
/// `tracking-allocator`, which tells [`Freed`] of each release once
/// tracking is on. Only [`no_unwiped_copy_of_a_presented_session_id`]'s
/// child process turns it on; everywhere else each call passes through.
#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOCATOR: tracking_allocator::Allocator<std::alloc::System> =
    tracking_allocator::Allocator::system();

/// What [`Freed`] looks for in each block freed: 16-byte pieces of the
/// session IDs watched (each one's text in two halves, and its bytes).
#[cfg(target_os = "linux")]
struct Watch {
    pieces: [[u8; 16]; 6],
    len: usize,
    /// The pieces found, and the sizes of the first blocks found holding
    /// one.
    found: usize,
    sizes: [usize; 8],
}

#[cfg(target_os = "linux")]
static WATCH: std::sync::Mutex<Watch> = std::sync::Mutex::new(Watch {
    pieces: [[0; 16]; 6],
    len: 0,
    found: 0,
    sizes: [0; 8],
});

/// This process's memory (`/proc/self/mem`), opened before anything is
/// watched.
#[cfg(target_os = "linux")]
static MEMORY: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();

/// Looks in each block as it is freed for the pieces watched.
#[cfg(target_os = "linux")]
struct Freed;

#[cfg(target_os = "linux")]
impl tracking_allocator::AllocationTracker for Freed {
    fn allocated(&self, _: usize, _: usize, _: usize, _: tracking_allocator::AllocationGroupId) {}

    /// The block was released just before this call, nothing in between:
    /// its bytes are all still there but the system allocator's links in
    /// its first 16 (the wrapper's header and the object's first 8), which
    /// leave a 32-byte ID's second half. Allocates nothing, which could
    /// reuse the block.
    fn deallocated(
        &self,
        addr: usize,
        size: usize,
        _: usize,
        _: tracking_allocator::AllocationGroupId,
        _: tracking_allocator::AllocationGroupId,
    ) {
        let (Some(memory), Ok(mut watch)) = (MEMORY.get(), WATCH.try_lock()) else {
            return;
        };
        if watch.len == 0 {
            return;
        }
        let found = pieces_in(memory, addr, size, &watch.pieces[..watch.len]);
        if found > 0 {
            let blocks = watch.sizes.iter().take_while(|size| **size > 0).count();
            if let Some(slot) = watch.sizes.get_mut(blocks) {
                *slot = size;
            }
            watch.found += found;
        }
    }
}

/// How often any of `pieces` occurs in the `size` bytes at `addr`, read
/// through `memory` in chunks on the stack.
#[cfg(target_os = "linux")]
fn pieces_in(memory: &std::fs::File, addr: usize, size: usize, pieces: &[[u8; 16]]) -> usize {
    use std::os::unix::fs::FileExt as _;
    use zeroize::Zeroize as _;
    let mut chunk = [0u8; 4096];
    let (mut at, end) = (addr as u64, (addr as u64).saturating_add(size as u64));
    let mut found = 0;
    while at < end {
        let want = (end - at).min(chunk.len() as u64) as usize;
        // A mapping released with the block can't be read: nothing of it
        // is left.
        let Ok(got) = memory.read_at(&mut chunk[..want], at) else {
            break;
        };
        if got < 16 {
            break;
        }
        found += chunk[..got]
            .windows(16)
            .filter(|window| pieces.iter().any(|piece| piece.as_slice() == *window))
            .count();
        if at + got as u64 >= end {
            break;
        }
        // Overlapping, so a piece across two chunks is seen once.
        at += (got - 15) as u64;
    }
    chunk.zeroize();
    found
}

/// Watches for `session`'s text, in halves, and its bytes too.
#[cfg(target_os = "linux")]
fn watch(session: &str) {
    let text = session.as_bytes();
    assert_eq!(text.len(), 32);
    let mut bytes = [0u8; 16];
    for (byte, pair) in bytes.iter_mut().zip(text.chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    let mut halves = [[0u8; 16]; 2];
    halves[0].copy_from_slice(&text[..16]);
    halves[1].copy_from_slice(&text[16..]);
    let mut watch = WATCH.lock().unwrap();
    let len = watch.len;
    watch.pieces[len..len + 3].copy_from_slice(&[halves[0], halves[1], bytes]);
    watch.len += 3;
}

/// The pieces found since the last call, and the sizes of the blocks.
#[cfg(target_os = "linux")]
fn found() -> (usize, [usize; 8]) {
    let mut watch = WATCH.lock().unwrap();
    let found = (watch.found, watch.sizes);
    watch.found = 0;
    watch.sizes = [0; 8];
    found
}

/// Runs this module's test `name` again, alone, in a child process, and
/// checks that it passed there; true in the child.
#[cfg(target_os = "linux")]
fn in_child(name: &str) -> bool {
    const CHILD: &str = "FREEDOM_CORED_TEST_SESSION_COPY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            &format!("safe::methods::tests::messages::{name}"),
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "child failed:\n{stdout}\n{stderr}"
    );
    false
}

impl Harness {
    /// Minted and started for `text` to the Safe at `index`: its ID, taken
    /// out of the answer into a buffer wiped when dropped.
    fn session_started(&mut self, index: u64, text: &str) -> Zeroizing<String> {
        let mut answer = self.message_started(index, &personal(index, text));
        let Value::String(session) = answer["result"]["session"].take() else {
            panic!("{answer}");
        };
        Zeroizing::new(session)
    }

    /// [`Harness::board`], its params written into a buffer wiped when
    /// dropped, `session` in them as given (escapes included).
    fn board_raw(&mut self, method: &str, index: u64, session: &str, owner: Option<u64>) -> Value {
        let index = index.to_string();
        let owner = owner.map(|owner| format!("\"owner\":{owner},"));
        let params = wiped(&[
            "{\"safe\":",
            &index,
            ",",
            owner.as_deref().unwrap_or(""),
            "\"session\":\"",
            session,
            "\"}",
        ]);
        self.board_body(method, &params)
    }

    /// A board call from main with `params` as given.
    fn board_body(&mut self, method: &str, params: &str) -> Value {
        let context = caller(CallerKind::Shell);
        let outs = self
            .safes
            .request(9, method, Some(params), &context, ctx!(self));
        self.drive(outs).expect("no reply")
    }
}

/// `parts` joined in a buffer wiped when dropped, never reallocated.
fn wiped(parts: &[&str]) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(512));
    for part in parts {
        text.push_str(part);
    }
    assert_eq!(text.capacity(), 512, "no copy left by a reallocation");
    text
}

/// A presented session ID leaves no unwiped copy behind: each board call
/// reads it in the request's own bytes (a frame's in the core, wiped when
/// it drops; the test's buffer here) straight into a buffer wiped when
/// dropped, escaped or not (a repeated one's earlier occurrences checked in
/// place), and a session keeps its ID in its own buffer, wiped when the
/// session drops. A parse into a value left the text in a
/// freed string (and an escaped one in serde_json's scratch too), and the
/// sessions' map the bytes of a session it dropped. Watched in a child
/// process whose allocator looks in each block it frees, from the first
/// board call to the harness's drop.
#[cfg(target_os = "linux")]
#[test]
fn no_unwiped_copy_of_a_presented_session_id() {
    use tracking_allocator::AllocationRegistry;
    if !in_child("no_unwiped_copy_of_a_presented_session_id") {
        return;
    }
    MEMORY
        .set(std::fs::File::open("/proc/self/mem").unwrap())
        .unwrap();
    AllocationRegistry::set_global_tracker(Freed).unwrap();
    AllocationRegistry::enable_tracking();

    // S3, 2 of 3: a session opened with the vault locked, nothing signed.
    let mut h = world(S3, 3);
    h.state = VaultState::new();
    let first = h.session_started(S3, "Hello, Safe");
    watch(&first);
    let state = h.board_raw("safe.message_state", S3, &first, None);
    assert_eq!(result(&state)["collected"], 0);
    // The same ID, its first digit escaped: the same session.
    let mut escaped = Zeroizing::new(String::with_capacity(64));
    escaped.push(char::from(0x5c));
    escaped.push_str(&format!("u{:04x}", first.as_bytes()[0]));
    escaped.push_str(&first[1..]);
    assert_eq!(escaped.len(), 37);
    let again = h.board_raw("safe.message_state", S3, &escaped, None);
    assert_eq!(again, state);
    // Repeated, each occurrence read in place: twice, then once inside an
    // array, the last kept; and after a lone surrogate, refused.
    let head = format!("{{\"safe\":{S3},\"session\":");
    let twice = wiped(&[&head, "\"", &first, "\",\"session\":\"", &escaped, "\"}"]);
    assert_eq!(h.board_body("safe.message_state", &twice), state);
    let inside = wiped(&[&head, "[\"", &first, "\"],\"session\":\"", &first, "\"}"]);
    assert_eq!(h.board_body("safe.message_state", &inside), state);
    let lone = format!("\"{}uD800\",\"session\":\"", char::from(0x5c));
    let refused = wiped(&[&head, &lone, &first, "\"}"]);
    let reply = h.board_body("safe.message_state", &refused);
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
    // C, then the sweep's A, after the eight reads each.
    h.state = unlocked();
    let reply = h.board_raw("safe.message_sign", S3, &first, Some(2));
    assert_eq!(result(&reply)["collected"], 1);
    let reply = h.board_raw("safe.message_sign", S3, &escaped, None);
    assert_eq!(result(&reply)["complete"], true);
    let done = h.board_raw("safe.message_complete", S3, &first, None);
    assert!(result(&done)["signature"].is_string());
    // Another, cancelled.
    let second = h.session_started(S3, "Hello again");
    watch(&second);
    let state = h.board_raw("safe.message_state", S3, &second, None);
    assert_eq!(result(&state)["complete"], true);
    let cancelled = h.board_raw("safe.message_cancel", S3, &second, None);
    assert_eq!(result(&cancelled), &json!({}));
    let gone = h.board_raw("safe.message_state", S3, &second, None);
    assert_eq!(result(&gone), &Value::Null);
    drop(h);
    let (copies, sizes) = found();
    assert_eq!(
        copies, 0,
        "unwiped copies of a session ID, in blocks of {sizes:?}"
    );

    // The watch sees a copy freed unwiped.
    drop(std::hint::black_box(String::from(second.as_str())));
    assert!(found().0 > 0, "the watch sees nothing");
}

/// A presented ID is read as the board's calls read it with a parse into
/// a value (`members`), the old parse here the reference for each request:
/// escaped digits, in either case, are the same ID; any other string is
/// none (`null`); a lone surrogate, which serde_json refuses in a string,
/// is `invalid_argument`. Every occurrence of a repeated member is read so,
/// the last kept: an earlier one is refused for a lone surrogate (in a
/// string or a key), a number out of range or a value nested too deep, as
/// that parse refuses it.
#[test]
fn a_presented_id_reads_as_a_value_parse_reads_it() {
    let mut h = world(S2, 3);
    let session = h.session_started(S2, "Hello, Safe");
    let state = h.board_raw("safe.message_state", S2, &session, None);
    assert_eq!(result(&state)["complete"], true);
    let bs = char::from(0x5c);
    let id = session.as_str();
    let other = "0".repeat(32);
    let one = |text: &str| format!("{{\"safe\":{S2},\"session\":\"{text}\"}}");
    let two = |first: &str, last: &str| {
        format!("{{\"safe\":{S2},\"session\":{first},\"session\":{last}}}")
    };
    let safe_twice =
        |first: &str| format!("{{\"safe\":{first},\"safe\":{S2},\"session\":\"{id}\"}}");
    let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    let quoted = |text: &str| format!("\"{text}\"");
    let cases: Vec<(String, &str)> = vec![
        // One occurrence.
        (
            one(&id
                .bytes()
                .map(|b| format!("{bs}u{b:04X}"))
                .collect::<String>()),
            "state",
        ),
        (
            one(&format!("{}{bs}u{:04x}", &id[..31], id.as_bytes()[31])),
            "state",
        ),
        (one(&format!("A{}", &id[1..])), "null"),
        (one(&format!("{bs}n{}", &id[1..])), "null"),
        (one(&format!("{bs}/{}", &id[1..])), "null"),
        (one(&format!("{bs}u0130{}", &id[1..])), "null"),
        (one(&format!("{id}0")), "null"),
        (one(&id[1..]), "null"),
        (one(&format!("{}{bs}uD83D{bs}uDE00", &id[..31])), "null"),
        (one(""), "null"),
        (one(&format!("{bs}uDC00{id}")), "invalid"),
        (one(&format!("{bs}uD800{id}")), "invalid"),
        (one(&format!("{id}{bs}uD800")), "invalid"),
        (one(&format!("{bs}uD800{bs}u0030{}", &id[1..])), "invalid"),
        (
            one(&format!("{bs}uD800{bs}uD800{bs}uDC00{}", &id[1..])),
            "invalid",
        ),
        (one(&format!("{bs}uD800{bs}n{}", &id[1..])), "invalid"),
        // Repeated: each occurrence read, the last kept.
        (two(&quoted(id), &quoted(id)), "state"),
        (two(&quoted(&other), &quoted(id)), "state"),
        (two(&quoted(id), &quoted(&other)), "null"),
        (two("5", &quoted(id)), "state"),
        (two(&format!("[{}]", quoted(id)), &quoted(id)), "state"),
        (two(&quoted(id), "5"), "invalid"),
        (two(&quoted(&format!("{bs}uD800")), &quoted(id)), "invalid"),
        (two(&quoted(id), &quoted(&format!("{bs}uD800"))), "invalid"),
        (two(&format!("[\"{bs}uDC00\"]"), &quoted(id)), "invalid"),
        (two(&format!("{{\"{bs}uD800\":1}}"), &quoted(id)), "invalid"),
        (two("1e400", &quoted(id)), "invalid"),
        (two("-0.5e-400", &quoted(id)), "state"),
        (two(&deep(126), &quoted(id)), "state"),
        (two(&deep(127), &quoted(id)), "invalid"),
        (safe_twice(&quoted(&format!("{bs}uD800"))), "invalid"),
        (safe_twice("1e400"), "invalid"),
        (safe_twice(&deep(126)), "state"),
        (safe_twice(&deep(127)), "invalid"),
        (
            format!("{{\"{bs}uD800\":1,\"safe\":{S2},\"session\":\"{id}\"}}"),
            "invalid",
        ),
    ];
    for (body, expected) in cases {
        // The old parse's answer.
        let reference = match serde_json::from_str::<Value>(&body) {
            Err(_) => "invalid",
            Ok(params) => match (params["safe"].as_u64(), &params["session"]) {
                (Some(S2), Value::String(read)) if read == id => "state",
                (Some(S2), Value::String(_)) => "null",
                _ => "invalid",
            },
        };
        assert_eq!(reference, expected, "{body}");
        let reply = h.board_body("safe.message_state", &body);
        match expected {
            "state" => assert_eq!(reply, state, "{body}"),
            "null" => assert_eq!(result(&reply), &Value::Null, "{body}"),
            _ => assert_eq!(
                reply["error"]["code"], "invalid_argument",
                "{body}: {reply}"
            ),
        }
    }
}
