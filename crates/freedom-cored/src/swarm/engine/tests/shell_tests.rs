//! Main's own methods through the engine (SWM-4 PR 9): the shell parents'
//! door, admission, answers and D13's bounds; the store ops' door, gate,
//! asks (the vault's, D6's `shell.swarm_manifest` and its bound) and the
//! `approval.changed` a projection sends after its answer.

use super::*;
use fc_swarm_provider::machine::shell::{MEMORY_WAIT_MS, WHOLE_REPLY_MS};

/// The Swarm grants' writer, in memory: the change made, never failing.
struct MemoryWriter;

impl GrantsWriter for MemoryWriter {
    fn write(
        &mut self,
        grants: &Mutex<SwarmStore>,
        change: &mut dyn FnMut(&mut SwarmStore) -> Applied<()>,
    ) -> GrantWritten {
        let mut store = grants.lock().unwrap();
        GrantWritten {
            effect: change(&mut store).effect,
            error: None,
        }
    }
}

/// An engine whose stores and grants have moved, with an in-memory grants
/// writer.
fn moved(bounds: Bounds) -> Engine {
    let mut shared = Shared::new(Arc::new(Mutex::new(SwarmStore::new())), Bindings::default());
    shared.stores_moved = true;
    shared.grants_writer = Some(Box::new(MemoryWriter));
    Engine::new(bounds, shared, true)
}

fn stamps_reply() -> String {
    whole_json(200, br#"{"stamps":[]}"#)
}

fn whole_json(status: u16, body: &[u8]) -> String {
    serde_json::json!({
        "status": status,
        "status_text": if status == 200 { "OK" } else { "Not Found" },
        "headers": [["content-type", "application/json"]],
        "body_base64": fc_swarm_provider::value::encode_base64(body),
    })
    .to_string()
}

fn error_of(answer: Answer) -> ErrorBody {
    match answer {
        Answer::Error(error) => error,
        other => panic!("an error: {other:?}"),
    }
}

fn result_of(answer: Answer) -> String {
    match answer {
        Answer::Result(text) => text,
        other => panic!("a result: {other:?}"),
    }
}

const FEED_READ: &str = r#"{"op":"read","key":{"kind":"bee_wallet"},"topic":"7777777777777777777777777777777777777777777777777777777777777777"}"#;

#[test]
fn a_shell_parent_runs_and_answers_typed() {
    let mut engine = moved(Bounds::default());
    let mut io = Fake::default();
    engine
        .shell(&mut io, 0, 5, ShellMethod::Stamps, Some("{}"))
        .unwrap();
    let (call, method, params) = io.last();
    assert_eq!(method, "shell.swarm_api");
    assert_eq!(params["for"], 5);
    assert_eq!(params["form"], "stamps");
    assert_eq!(
        engine.memory_used(),
        REQUEST_CHARGE + whole_charge(Form::Stamps)
    );
    engine
        .response(&mut io, 0, call, Ok(&stamps_reply()))
        .unwrap();
    assert_eq!(
        result_of(io.answer_of(5)),
        r#"{"result_typed":{"array":[]}}"#
    );
    engine.written(&mut io, 0, 5).unwrap();
    assert_eq!((engine.memory_used(), engine.requests()), (0, 0));
    // What the service throws is `{ error_typed }` in today's shape.
    engine
        .shell(
            &mut io,
            0,
            6,
            ShellMethod::UploadStatus,
            Some(r#"{"tag_uid":9}"#),
        )
        .unwrap();
    let (call, _, params) = io.last();
    assert_eq!(params["form"], "tag");
    engine
        .response(&mut io, 0, call, Ok(r#"{"failed":"stopped"}"#))
        .unwrap();
    assert_eq!(
        result_of(io.answer_of(6)),
        r#"{"error_typed":{"object":[["message",{"string":"Swarm node is not ready"}]]}}"#
    );
}

#[test]
fn the_shell_door_reads_strictly_and_waits_for_the_stores() {
    let mut io = Fake::default();
    let mut engine = moved(Bounds::default());
    for (id, method, params) in [
        (1, ShellMethod::Stamps, Some(r#"{"id":"zz"}"#)),
        (2, ShellMethod::Feed, Some(r#"{"op":"read"}"#)),
        (3, ShellMethod::UploadStatus, None),
        (4, ShellMethod::Publish, Some("not json")),
    ] {
        engine.shell(&mut io, 0, id, method, params).unwrap();
        assert_eq!(error_of(io.answer_of(id)).code, ErrorCode::InvalidArgument);
    }
    // A text from a reader that names main's member is bounded.
    let long = format!(r#"{{"{}":1}}"#, "k".repeat(1000));
    engine
        .shell(&mut io, 0, 5, ShellMethod::Stamps, Some(&long))
        .unwrap();
    assert!(error_of(io.answer_of(5)).message.len() <= 260);
    // A publish that keeps a history row needs the stores; one that keeps
    // none doesn't.
    let mut unmoved = Engine::new(
        Bounds::default(),
        Shared::new(grants(), Bindings::default()),
        true,
    );
    let publish = |history: &str| {
        format!(
            r#"{{"kind":"data","parts":[{{"bytes":5,"base64":"aGVsbG8="}}],"pin":true,"deferred":false,"batch":"{}"{history}}}"#,
            "ab".repeat(32)
        )
    };
    unmoved
        .shell(
            &mut io,
            0,
            6,
            ShellMethod::Publish,
            Some(&publish(r#","history":{"type":"data","name":"n"}"#)),
        )
        .unwrap();
    let error = error_of(io.answer_of(6));
    assert_eq!(error.code, ErrorCode::NotMoved);
    assert_eq!(
        error.data,
        Some(serde_json::json!({ "store": "swarm_stores" }))
    );
    unmoved
        .shell(&mut io, 0, 7, ShellMethod::Publish, Some(&publish("")))
        .unwrap();
    assert!(io.answers.iter().all(|(id, _)| *id != 7));
    assert_eq!(io.last().1, "shell.swarm_api");
}

/// Admission's `busy` for main's own methods is the protocol error; a page's
/// is 4900 inside `{ error_typed }`; the ops that take no place still run.
#[test]
fn a_full_gate_is_busy_for_main() {
    let mut engine = moved(Bounds {
        running: 1,
        waiting: 0,
        ..Bounds::default()
    });
    let mut io = Fake::default();
    engine
        .shell(&mut io, 0, 1, ShellMethod::Stamps, Some("{}"))
        .unwrap();
    engine
        .shell(&mut io, 0, 2, ShellMethod::Stamps, Some("{}"))
        .unwrap();
    assert_eq!(error_of(io.answer_of(2)).code, ErrorCode::Busy);
    let (_, reference) = chunk();
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
    // An owner-reading identity op takes a place: busy.
    engine
        .op(
            &mut io,
            0,
            4,
            ops::IDENTITIES,
            Some(r#"{"op":"get-origin-identities","origin":{"string":"a"}}"#),
            ops::Caller::Chrome,
        )
        .unwrap();
    assert_eq!(error_of(io.answer_of(4)).code, ErrorCode::Busy);
    // A store read takes none: it answers at once.
    engine
        .op(
            &mut io,
            0,
            5,
            ops::IDENTITIES,
            Some(r#"{"op":"get-all-origins"}"#),
            ops::Caller::Chrome,
        )
        .unwrap();
    assert_eq!(
        result_of(io.answer_of(5)),
        r#"{"result_typed":{"array":[]}}"#
    );
    engine
        .op(
            &mut io,
            0,
            6,
            ops::HISTORY,
            Some(r#"{"op":"list"}"#),
            ops::Caller::Shell,
        )
        .unwrap();
    assert_eq!(
        result_of(io.answer_of(6)),
        r#"{"result_typed":{"array":[]}}"#
    );
    assert!(io.statements.iter().any(|s| s.sql.starts_with("SELECT")));
}

/// D13 under `swarm.publish`: a whole node reply's bound in all, past
/// which the call is cancelled at main and the publish fails; its late
/// answer is dropped, and its charge goes then.
#[test]
fn a_whole_reply_under_a_publish_is_bound_in_all() {
    let mut engine = moved(Bounds {
        whole_ms: 1000,
        ..Bounds::default()
    });
    let mut io = Fake::default();
    engine
        .shell(
            &mut io,
            0,
            1,
            ShellMethod::Publish,
            Some(r#"{"kind":"data","parts":[{"bytes":5,"base64":"aGVsbG8="}],"pin":true,"deferred":false}"#),
        )
        .unwrap();
    let (call, _, params) = io.last();
    assert_eq!(params["form"], "stamps");
    // No total deadline: only the call's own bound.
    assert_eq!(engine.next_due(), Some(1000));
    engine.tick(&mut io, 999).unwrap();
    assert!(io.answers.is_empty());
    engine.tick(&mut io, 1000).unwrap();
    assert_eq!(io.cancels, vec![call]);
    let text = result_of(io.answer_of(1));
    assert!(text.starts_with(r#"{"error_typed":"#), "{text}");
    engine.written(&mut io, 1000, 1).unwrap();
    assert_eq!(engine.memory_used(), whole_charge(Form::Stamps));
    engine
        .response(&mut io, 1001, call, Ok(&stamps_reply()))
        .unwrap();
    assert!(io.answers.is_empty());
    assert_eq!((engine.memory_used(), engine.requests()), (0, 0));
    assert_eq!(WHOLE_REPLY_MS, Bounds::default().whole_ms);
}

/// D13: a request with no total deadline waits at most the bound for a
/// charge, then is the protocol error `busy`.
#[test]
fn a_publish_waits_for_memory_within_its_bound() {
    let mut engine = moved(Bounds {
        memory: REQUEST_CHARGE + 1024,
        wait_ms: 1000,
        ..Bounds::default()
    });
    let mut io = Fake::default();
    engine
        .shell(
            &mut io,
            0,
            1,
            ShellMethod::Publish,
            Some(r#"{"kind":"data","parts":[{"bytes":5,"base64":"aGVsbG8="}],"pin":true,"deferred":false}"#),
        )
        .unwrap();
    assert!(io.sent.is_empty());
    assert_eq!(engine.next_due(), Some(1000));
    engine.tick(&mut io, 1000).unwrap();
    assert_eq!(error_of(io.answer_of(1)).code, ErrorCode::Busy);
    engine.written(&mut io, 1000, 1).unwrap();
    assert_eq!((engine.memory_used(), engine.requests()), (0, 0));
    assert_eq!(MEMORY_WAIT_MS, Bounds::default().wait_ms);
}

/// `swarm.feed`'s read: the Bee wallet's owner from the vault, then the
/// lookup; main's own update signs with no page decision.
#[test]
fn a_feed_reads_its_owner_from_the_vault() {
    let mut engine = moved(Bounds::default());
    let mut io = Fake::default();
    engine
        .shell(&mut io, 0, 1, ShellMethod::Feed, Some(FEED_READ))
        .unwrap();
    let (tag, ask) = io.vaults.pop().unwrap();
    assert_eq!(ask, VaultAsk::Owner(SignKey::BeeWallet));
    engine
        .vaulted(
            &mut io,
            0,
            tag,
            VaultAnswer::Event(Event::Owner(Ok(Some([0x11; 20])))),
        )
        .unwrap();
    let (call, _, params) = io.last();
    assert_eq!(params["form"], "feed_head");
    engine
        .response(
            &mut io,
            0,
            call,
            Ok(&whole_json(404, br#"{"code":404,"message":"Not Found"}"#)),
        )
        .unwrap();
    let (call, _, params) = io.last();
    assert_eq!(params["form"], "chunk");
    assert_eq!(params["feed"]["index"], 0);
    engine
        .response(
            &mut io,
            0,
            call,
            Ok(&whole_json(404, br#"{"code":404,"message":"Not Found"}"#)),
        )
        .unwrap();
    assert_eq!(
        result_of(io.answer_of(1)),
        r#"{"result_typed":{"object":[["exists",{"boolean":false}]]}}"#
    );
    // An update's signature: main's own SOC, the Bee wallet key, no page.
    engine
        .shell(
            &mut io,
            0,
            2,
            ShellMethod::Feed,
            Some(&format!(
                r#"{{"op":"update","key":{{"kind":"bee_wallet"}},"topic":"{}","reference":"{}","batch":"{}"}}"#,
                "77".repeat(32),
                "ab".repeat(32),
                "cd".repeat(32)
            )),
        )
        .unwrap();
    let (tag, _) = io.vaults.pop().unwrap();
    engine
        .vaulted(
            &mut io,
            0,
            tag,
            VaultAnswer::Event(Event::Owner(Ok(Some([0x11; 20])))),
        )
        .unwrap();
    let (call, _, _) = io.last();
    engine
        .response(
            &mut io,
            0,
            call,
            Ok(&serde_json::json!({
                "status": 200,
                "status_text": "OK",
                "headers": [
                    ["swarm-feed-index", "0000000000000002"],
                    ["swarm-feed-index-next", "0000000000000003"],
                ],
                "body_base64": "",
            })
            .to_string()),
        )
        .unwrap();
    let (_, ask) = io.vaults.pop().unwrap();
    let VaultAsk::OwnSign(soc) = ask else {
        panic!("main's own SOC: {ask:?}")
    };
    assert_eq!(soc.key, SignKey::BeeWallet);
    assert_eq!(soc.hold, None);
}

/// The store ops' door: the stores moved, `swarm.manifest` the grants too;
/// an op only main makes is forbidden to the chrome.
#[test]
fn the_ops_door() {
    let mut io = Fake::default();
    let mut unmoved = Engine::new(
        Bounds::default(),
        Shared::new(grants(), Bindings::default()),
        true,
    );
    unmoved
        .op(
            &mut io,
            0,
            1,
            ops::HISTORY,
            Some(r#"{"op":"list"}"#),
            ops::Caller::Chrome,
        )
        .unwrap();
    let error = error_of(io.answer_of(1));
    assert_eq!(error.code, ErrorCode::NotMoved);
    assert_eq!(
        error.data,
        Some(serde_json::json!({ "store": "swarm_stores" }))
    );
    let mut grants_unmoved = {
        let mut shared = Shared::new(grants(), Bindings::default());
        shared.stores_moved = true;
        Engine::new(Bounds::default(), shared, false)
    };
    grants_unmoved
        .op(
            &mut io,
            0,
            2,
            ops::MANIFEST,
            Some(r#"{"op":"get","origin":{"string":"a"}}"#),
            ops::Caller::Shell,
        )
        .unwrap();
    let error = error_of(io.answer_of(2));
    assert_eq!(error.code, ErrorCode::NotMoved);
    assert_eq!(error.data, Some(serde_json::json!({ "store": "swarm" })));
    let mut engine = moved(Bounds::default());
    engine
        .op(
            &mut io,
            0,
            3,
            ops::IDENTITIES,
            Some(r#"{"op":"grantFeedAccess","key":{"string":"a"}}"#),
            ops::Caller::Chrome,
        )
        .unwrap();
    assert_eq!(error_of(io.answer_of(3)).code, ErrorCode::Forbidden);
    engine
        .op(
            &mut io,
            0,
            4,
            ops::HISTORY,
            Some(r#"{"op":"nope"}"#),
            ops::Caller::Shell,
        )
        .unwrap();
    assert_eq!(error_of(io.answer_of(4)).code, ErrorCode::InvalidArgument);
    // An owner-reading op asks the vault and answers once it has.
    engine
        .op(
            &mut io,
            0,
            5,
            ops::IDENTITIES,
            Some(r#"{"op":"previewAppScopedIdentity","key":{"string":"a"}}"#),
            ops::Caller::Shell,
        )
        .unwrap();
    assert_eq!(engine.memory_used(), REQUEST_CHARGE);
    let (tag, ask) = io.vaults.pop().unwrap();
    assert!(
        matches!(ask, VaultAsk::Owner(SignKey::Publisher(_))),
        "{ask:?}"
    );
    engine
        .vaulted(&mut io, 0, tag, VaultAnswer::Event(Event::Owner(Ok(None))))
        .unwrap();
    let text = result_of(io.answer_of(5));
    assert!(text.starts_with(r#"{"error_typed":"#) || text.starts_with(r#"{"result_typed":"#));
    engine.written(&mut io, 0, 5).unwrap();
    assert_eq!((engine.memory_used(), engine.requests()), (0, 0));
}

const SITE_BZZ: &str = "bzz://5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const MANIFEST: &str = r#"{"schema":"freedom-manifest/1","name":"Freedom Notes","description":"Notes on Swarm","capabilities":{"swarm":{"publish":{"why":"To publish your notes"}}}}"#;

fn check_params() -> String {
    format!(
        r#"{{"op":"check","key":{{"string":"{SITE_BZZ}"}},"url":{{"string":"{SITE_BZZ}/index.html"}},"eager":{{"boolean":true}}}}"#
    )
}

/// D6: a check asks main `shell.swarm_manifest { for, url }`, its reply's
/// room reserved; a decision's projections write the grants and send
/// `approval.changed` after the answer.
#[test]
fn a_check_fetches_through_main_and_a_decision_projects() {
    let mut engine = moved(Bounds::default());
    let mut io = Fake::default();
    engine
        .op(
            &mut io,
            0,
            1,
            ops::MANIFEST,
            Some(&check_params()),
            ops::Caller::Shell,
        )
        .unwrap();
    let (fetch, method, params) = io.last();
    assert_eq!(method, "shell.swarm_manifest");
    assert_eq!(
        params,
        serde_json::json!({ "for": 1, "url": format!("{SITE_BZZ}/freedom-manifest.json") })
    );
    assert_eq!(
        io.sent.last().unwrap().3,
        MANIFEST_MOST.div_ceil(3) * 4 + ENVELOPE
    );
    assert_eq!(
        engine.memory_used(),
        REQUEST_CHARGE + store_ops::MANIFEST_CHARGE
    );
    let reply = serde_json::json!({
        "status": 200,
        "body_base64": fc_swarm_provider::value::encode_base64(MANIFEST.as_bytes()),
    })
    .to_string();
    engine.response(&mut io, 0, fetch, Ok(&reply)).unwrap();
    let text = result_of(io.answer_of(1));
    assert!(text.contains(r#"["kind",{"string":"consent"}]"#), "{text}");
    let token = text
        .split(r#"["token",{"string":""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .to_owned();
    engine.written(&mut io, 0, 1).unwrap();
    assert_eq!(engine.memory_used(), 0);
    assert!(io.changed.is_empty());
    let decide = format!(
        r#"{{"op":"decide","key":{{"string":"{SITE_BZZ}"}},"token":{{"string":"{token}"}},"outcome":{{"string":"allow"}},"live":{{"boolean":true}}}}"#
    );
    engine
        .op(
            &mut io,
            0,
            2,
            ops::MANIFEST,
            Some(&decide),
            ops::Caller::Shell,
        )
        .unwrap();
    let text = result_of(io.answer_of(2));
    assert!(text.contains(r#"["allowed",{"boolean":true}]"#), "{text}");
    // The connection and the rule: two changes, each told after the answer.
    assert_eq!(io.changed, vec![SITE_BZZ.to_owned(); 2]);
    let store = engine.shared_mut().grants.lock().unwrap().clone();
    assert!(store.entry(SITE_BZZ).is_some());
    assert!(store.flag(SITE_BZZ, SwarmFlag::Publish));
}

/// D13: `shell.swarm_manifest` has 60 s in all; past it the core cancels it
/// and the check reads `{ failed }` (unresolved); main's late answer is
/// dropped, and the fetch's charge goes then. A malformed answer ends the
/// connection.
#[test]
fn a_fetch_is_bound_in_all_and_read_strictly() {
    let mut engine = moved(Bounds {
        wait_ms: 1000,
        ..Bounds::default()
    });
    let mut io = Fake::default();
    engine
        .op(
            &mut io,
            0,
            1,
            ops::MANIFEST,
            Some(&check_params()),
            ops::Caller::Shell,
        )
        .unwrap();
    let (fetch, _, _) = io.last();
    assert_eq!(engine.next_due(), Some(1000));
    engine.tick(&mut io, 1000).unwrap();
    assert_eq!(io.cancels, vec![fetch]);
    let text = result_of(io.answer_of(1));
    assert!(
        text.contains(r#"["reason",{"string":"unresolved"}]"#),
        "{text}"
    );
    engine.written(&mut io, 1000, 1).unwrap();
    assert_eq!(engine.memory_used(), store_ops::MANIFEST_CHARGE);
    engine
        .response(
            &mut io,
            1001,
            fetch,
            Err(r#"{"code":"cancelled","message":"Cancelled"}"#),
        )
        .unwrap();
    assert!(io.answers.is_empty());
    assert_eq!((engine.memory_used(), engine.requests()), (0, 0));
    // Main's answers, read strictly.
    for bad in [
        r#"{"status":200}"#.to_owned(),
        r#"{"status":99,"body_base64":""}"#.to_owned(),
        r#"{"status":200,"body_base64":"!!"}"#.to_owned(),
        r#"{"failed":"unreachable"}"#.to_owned(),
        r#"{"failed":false}"#.to_owned(),
        serde_json::json!({
            "status": 200,
            "body_base64": fc_swarm_provider::value::encode_base64(&vec![b' '; MANIFEST_MOST + 1]),
        })
        .to_string(),
        r#"{"status":200,"body_base64":"","extra":1}"#.to_owned(),
    ] {
        let mut engine = moved(Bounds::default());
        let mut io = Fake::default();
        engine
            .op(
                &mut io,
                0,
                1,
                ops::MANIFEST,
                Some(&check_params()),
                ops::Caller::Shell,
            )
            .unwrap();
        let (fetch, _, _) = io.last();
        assert_eq!(
            engine.response(&mut io, 0, fetch, Ok(&bad)),
            Err(Fault("swarm_reply")),
            "{bad}"
        );
    }
    // A failure main reports reads as unresolved too.
    let mut engine = moved(Bounds::default());
    let mut io = Fake::default();
    engine
        .op(
            &mut io,
            0,
            1,
            ops::MANIFEST,
            Some(&check_params()),
            ops::Caller::Shell,
        )
        .unwrap();
    let (fetch, _, _) = io.last();
    engine
        .response(&mut io, 0, fetch, Ok(r#"{"failed":true}"#))
        .unwrap();
    assert!(result_of(io.answer_of(1)).contains(r#"["reason",{"string":"unresolved"}]"#));
}

/// Main cancels a check while its fetch is out: `cancelled`, the fetch
/// cancelled at main, its charge held until main's answer.
#[test]
fn a_cancelled_check_lets_its_fetch_go_at_main_s_answer() {
    let mut engine = moved(Bounds::default());
    let mut io = Fake::default();
    engine
        .op(
            &mut io,
            0,
            1,
            ops::MANIFEST,
            Some(&check_params()),
            ops::Caller::Shell,
        )
        .unwrap();
    let (fetch, _, _) = io.last();
    engine.cancel(&mut io, 0, 1).unwrap();
    assert_eq!(io.answer_of(1), cancelled());
    assert_eq!(io.cancels, vec![fetch]);
    engine.written(&mut io, 0, 1).unwrap();
    assert_eq!(engine.memory_used(), store_ops::MANIFEST_CHARGE);
    assert_eq!(engine.requests(), 1);
    engine
        .response(
            &mut io,
            0,
            fetch,
            Err(r#"{"code":"cancelled","message":"Cancelled"}"#),
        )
        .unwrap();
    assert_eq!((engine.memory_used(), engine.requests()), (0, 0));
}

/// SW-1's hold defers an identity op's change: the op answers nothing until
/// the hold ends, then its change is made and answered to it (its owners
/// read after), and the file written once.
#[test]
fn a_held_change_is_answered_to_its_op() {
    use fc_swarm_provider::machine::keeper::{HoldId, Keeper};
    use fc_swarm_provider::stores::feeds::FeedStore;
    let mut engine = moved(Bounds::default());
    let mut io = Fake::default();
    let text = r#"{"version":2,"nextPublisherKeyIndex":1,"origins":{"a":{"activeIdentityId":"app-scoped:0","identities":{"app-scoped:0":{"id":"app-scoped:0","mode":"app-scoped","publisherKeyIndex":0,"walletIndex":null,"label":"A","createdAt":1,"lastUsedAt":null},"bee-wallet":{"id":"bee-wallet","mode":"bee-wallet","publisherKeyIndex":null,"walletIndex":null,"label":"Bee","createdAt":1,"lastUsedAt":null}},"feedGranted":true,"grantedAt":1,"feeds":{}}}}"#;
    let shared = engine.shared_mut();
    shared.keeper = Keeper::new(FeedStore::load(Some(text.as_bytes()), 0, |_| false).store);
    shared.keeper.hold(HoldId(99), JsString::from("a"));
    engine
        .op(
            &mut io,
            0,
            1,
            ops::IDENTITIES,
            Some(r#"{"op":"activateIdentity","key":{"string":"a"},"identity_id":{"string":"bee-wallet"}}"#),
            ops::Caller::Shell,
        )
        .unwrap();
    assert!(io.answers.is_empty());
    assert!(io.feed_texts.is_empty());
    assert_eq!(engine.requests(), 1);
    engine.release_hold(&mut io, HoldId(99));
    engine.room(&mut io, 0).unwrap();
    assert_eq!(io.feed_texts.len(), 1);
    // The state with owners: the vault's owners asked, then the answer.
    while let Some((tag, ask)) = io.vaults.pop() {
        let answer = match ask {
            VaultAsk::Owner(_) => VaultAnswer::Event(Event::Owner(Ok(Some([0x22; 20])))),
            VaultAsk::Accounts => VaultAnswer::Accounts(Ok(Vec::new())),
            other => panic!("{other:?}"),
        };
        engine.vaulted(&mut io, 0, tag, answer).unwrap();
    }
    let text = result_of(io.answer_of(1));
    assert!(
        text.contains(r#"["activeIdentityId",{"string":"bee-wallet"}]"#),
        "{text}"
    );
    engine.written(&mut io, 0, 1).unwrap();
    assert_eq!((engine.memory_used(), engine.requests()), (0, 0));
}
