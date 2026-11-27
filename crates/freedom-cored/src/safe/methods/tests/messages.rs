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
