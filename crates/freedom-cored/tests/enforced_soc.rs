//! Design 0012's Q8 for a page's SOC through the real binary (APR-4c):
//! `swarm.sign_soc` under `page` needs `{ swarm, soc }`, which the core
//! checks against the page's Swarm grant for `PageContext.origin`. It is
//! refused without one (`no_token`), without the grant or with another
//! origin's (`no_rule`), and as `auto` with the request's flag off (`feeds`
//! for a feed write, `signing` for a raw SOC; `no_rule`) or in custody
//! (`custody`); as `user` with the grant it signs. Every refusal comes after
//! the chunk's public work and before any key is derived, and a token
//! presented to it is burnt, the vault locked included. Main's own SOC,
//! under `shell`, signs as before, and neither it nor the chrome's takes a
//! grant (`no_rule`).
//!
//! The row's cases run against main's Swarm file and against the core's
//! own store, once `swarm` has moved (APB-3). The feed grant (`feedGranted`,
//! in `swarm-feeds.json`) stays main's word until 0015 moves that file: the
//! core reads no feed store yet.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const HANDLE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SITE: &str = "https://app.example";
const OTHER: &str = "https://other.example";
/// Every flag of a Swarm grant.
const EVERY: &[&str] = &["publish", "feeds", "signing", "messaging"];
/// `{ swarm, soc }`'s four forms.
const ALL: [(&str, &str); 4] = [
    ("user", "feed"),
    ("user", "raw"),
    ("auto", "feed"),
    ("auto", "raw"),
];

/// A page whose frame is `origin`'s, in a tab showing `top_origin`, with
/// `agent` as sent.
fn page(origin: &str, top_origin: &str, agent: Option<bool>) -> Value {
    let mut page = json!({
        "origin": origin, "top_origin": top_origin, "frame": 1, "navigation": 1,
    });
    if let Some(agent) = agent {
        page["agent"] = json!(agent);
    }
    json!({ "caller": "page", "page": page })
}

fn site() -> Value {
    page(SITE, SITE, Some(false))
}

/// The site's tab while the agent holds it, and with no `agent` sent.
fn site_in_custody() -> [Value; 2] {
    [page(SITE, SITE, Some(true)), page(SITE, SITE, None)]
}

fn chrome() -> Value {
    json!({ "caller": "chrome" })
}

fn shell() -> Value {
    json!({ "caller": "shell" })
}

fn call_as(core: &mut Core, id: &mut u64, context: &Value, method: &str, params: Value) -> Value {
    *id += 1;
    core.send(&json!({
        "type": "request", "id": *id, "method": method, "params": params, "context": context,
    }));
    core.response(*id)
}

fn result(reply: &Value) -> &Value {
    assert!(reply["result"].is_object(), "{reply}");
    &reply["result"]
}

/// Refused with `code` (and `reason`), and nothing signed.
fn refused(reply: &Value, code: &str, reason: Option<&str>) {
    assert_eq!(reply["error"]["code"], code, "{reply}");
    if let Some(reason) = reason {
        assert_eq!(reply["error"]["data"]["reason"], reason, "{reply}");
    }
    assert!(reply.get("result").is_none(), "{reply}");
}

fn not_authorized(reply: &Value, reason: &str) {
    refused(reply, "not_authorized", Some(reason));
}

/// A core with `grant_moved`, unlocked.
fn start(root: &Path, moved: &[&'static str]) -> Core {
    let mut core = spawn("serve", &root.join("identity"), &root.join("locks"), &[]);
    std::fs::create_dir_all(&core.grant_root).unwrap();
    core.grant_moved = moved.to_vec();
    assert_eq!(core.hello()["result"]["protocol"], 2);
    let imported = core.call(
        2,
        "vault.import",
        json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(ABANDON) }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    assert_eq!(core.event()["event"], "vault.unlocked");
    core
}

/// A Swarm file as main writes it: each key connected, with its flags.
fn swarm_file(sites: &[(&str, &[&str])]) -> String {
    let mut map = serde_json::Map::new();
    for (key, flags) in sites {
        let on = |flag: &str| flags.contains(&flag);
        map.insert(
            (*key).to_owned(),
            json!({
                "origin": key, "connectedAt": 1_762_000_000_000_u64, "lastUsed": 1_762_000_000_000_u64,
                "autoApprove": {
                    "publish": on("publish"), "feeds": on("feeds"),
                    "signing": on("signing"), "messaging": on("messaging"),
                },
            }),
        );
    }
    serde_json::to_string_pretty(&Value::Object(map)).unwrap()
}

/// Where the Swarm grants live: main's file, or the core's own store once
/// `swarm` has moved, which a page writes through `approval.grant`.
#[derive(Clone, Copy, Debug)]
enum Store {
    MainsFile,
    Moved,
}

impl Store {
    fn moved(self) -> &'static [&'static str] {
        match self {
            Store::MainsFile => &[],
            Store::Moved => &["swarm"],
        }
    }

    /// Makes the store hold exactly `sites`, each connected with its flags.
    fn holds(self, core: &mut Core, id: &mut u64, sites: &[(&str, &[&str])]) {
        match self {
            Store::MainsFile => {
                let dir = core.grant_root.clone();
                std::fs::write(dir.join("staged"), swarm_file(sites)).unwrap();
                std::fs::rename(dir.join("staged"), dir.join("swarm-permissions.json")).unwrap();
            }
            Store::Moved => {
                for key in [SITE, OTHER] {
                    let revoked = call_as(
                        core,
                        id,
                        &page(key, key, Some(false)),
                        "approval.revoke",
                        json!({ "store": "swarm", "key": key, "what": "grant" }),
                    );
                    result(&revoked);
                }
                for (key, flags) in sites {
                    let own = page(key, key, Some(false));
                    let connected = call_as(
                        core,
                        id,
                        &own,
                        "approval.grant",
                        json!({ "store": "swarm", "change": { "op": "connect" } }),
                    );
                    result(&connected);
                    for flag in *flags {
                        let flagged = call_as(
                            core,
                            id,
                            &own,
                            "approval.grant",
                            json!({ "store": "swarm", "change": { "op": "flag", "flag": flag } }),
                        );
                        result(&flagged);
                    }
                }
            }
        }
    }
}

/// `swarm.sign_soc` for publisher key 3, with `authorization` when given.
fn soc_params(authorization: Option<Value>) -> Value {
    let mut params = json!({
        "key": { "kind": "publisher", "origin_index": 3 },
        "identifier": format!("0x{}", "ab".repeat(32)),
        "payload": "0x68656c6c6f",
    });
    if let Some(authorization) = authorization {
        params["authorization"] = authorization;
    }
    params
}

fn sign_soc(core: &mut Core, id: &mut u64, context: &Value, authorization: Option<Value>) -> Value {
    call_as(
        core,
        id,
        context,
        "swarm.sign_soc",
        soc_params(authorization),
    )
}

fn auth(swarm: &str, soc: &str) -> Option<Value> {
    Some(json!({ "swarm": swarm, "soc": soc }))
}

/// The APR-4 row's "A page's SOC", against `store`. Every SOC that signs
/// gives main's own reply for the same chunk, byte for byte.
fn a_page_soc_needs_its_swarm_grant(store: Store) {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), store.moved());
    let mut id = 10;
    let own = result(&sign_soc(&mut core, &mut id, &shell(), None)).clone();
    let signs = |reply: &Value| assert_eq!(result(reply), &own, "{store:?}: {reply}");

    // Without the page's Swarm grant: none at all, then another origin's,
    // with every flag. Without an authorization, refused whatever the
    // grants.
    for (swarm, soc) in ALL {
        not_authorized(
            &sign_soc(&mut core, &mut id, &site(), auth(swarm, soc)),
            "no_rule",
        );
    }
    not_authorized(&sign_soc(&mut core, &mut id, &site(), None), "no_token");
    store.holds(&mut core, &mut id, &[(OTHER, EVERY)]);
    for (swarm, soc) in ALL {
        not_authorized(
            &sign_soc(&mut core, &mut id, &site(), auth(swarm, soc)),
            "no_rule",
        );
    }
    store.holds(&mut core, &mut id, &[(SITE, EVERY), (OTHER, EVERY)]);
    let mut without = vec![site(), page(SITE, OTHER, Some(false))];
    without.extend(site_in_custody());
    for context in &without {
        not_authorized(&sign_soc(&mut core, &mut id, context, None), "no_token");
    }

    // The grant is the frame's own origin's (`PageContext.origin`): another
    // origin's frame in the granted site's tab is refused, and the granted
    // site's frame in another site's tab signs.
    store.holds(&mut core, &mut id, &[(SITE, EVERY)]);
    for (swarm, soc) in ALL {
        not_authorized(
            &sign_soc(
                &mut core,
                &mut id,
                &page(OTHER, SITE, Some(false)),
                auth(swarm, soc),
            ),
            "no_rule",
        );
        signs(&sign_soc(
            &mut core,
            &mut id,
            &page(SITE, OTHER, Some(false)),
            auth(swarm, soc),
        ));
        signs(&sign_soc(&mut core, &mut id, &site(), auth(swarm, soc)));
    }

    // `auto` with the request's flag off: `feeds` answers a feed write
    // only, `signing` a raw SOC only, `publish` and `messaging` neither.
    // `user` with the grant signs throughout.
    let cases: [(&[&str], bool, bool); 5] = [
        (&[], false, false),
        (&["feeds"], true, false),
        (&["signing"], false, true),
        (&["publish", "messaging"], false, false),
        (&["feeds", "signing"], true, true),
    ];
    for (flags, feed, raw) in cases {
        store.holds(&mut core, &mut id, &[(SITE, flags), (OTHER, EVERY)]);
        for (soc, covered) in [("feed", feed), ("raw", raw)] {
            let reply = sign_soc(&mut core, &mut id, &site(), auth("auto", soc));
            if covered {
                signs(&reply);
            } else {
                not_authorized(&reply, "no_rule");
            }
            signs(&sign_soc(&mut core, &mut id, &site(), auth("user", soc)));
        }
    }

    // `auto` in custody, every flag on: refused while the agent holds the
    // tab and with no `agent` sent; there `user`, the agent's answer in the
    // user's place, signs.
    store.holds(&mut core, &mut id, &[(SITE, EVERY)]);
    for soc in ["feed", "raw"] {
        for context in site_in_custody() {
            not_authorized(
                &sign_soc(&mut core, &mut id, &context, auth("auto", soc)),
                "custody",
            );
            signs(&sign_soc(&mut core, &mut id, &context, auth("user", soc)));
        }
        signs(&sign_soc(&mut core, &mut id, &site(), auth("auto", soc)));
    }

    // Main's own SOC signs as before, and takes no grant: `{ swarm, soc }`
    // from `shell` or `chrome` is refused, as a standing rule from either
    // is, the granted site's `PageContext` sent beside it or not. The
    // chrome's SOC without one needs a wallet-kind token.
    let with_site = |caller: &str| {
        let mut context = site();
        context["caller"] = json!(caller);
        context
    };
    for (swarm, soc) in ALL {
        for context in [shell(), chrome(), with_site("shell"), with_site("chrome")] {
            not_authorized(
                &sign_soc(&mut core, &mut id, &context, auth(swarm, soc)),
                "no_rule",
            );
        }
    }
    for context in [shell(), with_site("shell")] {
        signs(&sign_soc(&mut core, &mut id, &context, None));
    }
    for context in [chrome(), with_site("chrome")] {
        not_authorized(&sign_soc(&mut core, &mut id, &context, None), "no_token");
    }

    // A grant removed stops answering at the next request; main's own SOC
    // still signs.
    store.holds(&mut core, &mut id, &[]);
    for (swarm, soc) in ALL {
        not_authorized(
            &sign_soc(&mut core, &mut id, &site(), auth(swarm, soc)),
            "no_rule",
        );
    }
    signs(&sign_soc(&mut core, &mut id, &shell(), None));
}

#[test]
fn a_page_soc_needs_its_swarm_grant_in_main_s_file() {
    a_page_soc_needs_its_swarm_grant(Store::MainsFile);
}

#[test]
fn a_page_soc_needs_its_swarm_grant_in_the_moved_store() {
    a_page_soc_needs_its_swarm_grant(Store::Moved);
}

fn issue(core: &mut Core, id: &mut u64, context: &Value, params: Value) -> String {
    let reply = call_as(core, id, context, "approval.issue", params);
    result(&reply)["token"].as_str().unwrap().to_owned()
}

fn message_token(core: &mut Core, id: &mut u64) -> String {
    let params = json!({ "kind": "sign-message", "account": 0,
        "payload": { "message": "0x68656c6c6f" }, "handle": HANDLE });
    issue(core, id, &site(), params)
}

fn send_tx() -> Value {
    json!({
        "type": 2, "chain_id": "100", "nonce": "3", "gas_limit": "21000",
        "to": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "value": "1000", "data": "0x",
        "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000000",
    })
}

fn wallet_token(core: &mut Core, id: &mut u64) -> String {
    let params = json!({ "kind": "wallet-send", "account": 0, "payload": { "tx": send_tx() } });
    issue(core, id, &shell(), params)
}

/// The order of work (0002, design 0012's API): the chunk's public work
/// first, then the authorization, then the key. With the vault locked,
/// every refusal of the row is `not_authorized`, never `vault_locked`, and
/// a SOC the grant covers, or main's own, reaches the key, which is locked.
/// A malformed SOC is refused for its malformation, with or without an
/// authorization. A token presented to `swarm.sign_soc`, which no token
/// kind binds, is burnt while locked, under each caller.
#[test]
fn refused_before_the_key_and_a_token_burnt_while_locked() {
    for store in [Store::MainsFile, Store::Moved] {
        let root = tempfile::tempdir().unwrap();
        let mut core = start(root.path(), store.moved());
        let mut id = 10;
        store.holds(&mut core, &mut id, &[(SITE, &["feeds"])]);
        let page_tokens: Vec<String> = (0..3).map(|_| message_token(&mut core, &mut id)).collect();
        let page_control = message_token(&mut core, &mut id);
        let wallet = wallet_token(&mut core, &mut id);
        let wallet_control = wallet_token(&mut core, &mut id);
        result(&call_as(
            &mut core,
            &mut id,
            &shell(),
            "vault.lock",
            json!({}),
        ));

        let refusals = [
            (site(), None, "no_token"),
            (page(SITE, SITE, Some(true)), None, "no_token"),
            (
                page(OTHER, OTHER, Some(false)),
                auth("user", "feed"),
                "no_rule",
            ),
            (
                page(OTHER, SITE, Some(false)),
                auth("user", "raw"),
                "no_rule",
            ),
            (site(), auth("auto", "raw"), "no_rule"),
            (
                page(SITE, SITE, Some(true)),
                auth("auto", "feed"),
                "custody",
            ),
            (page(SITE, SITE, None), auth("auto", "feed"), "custody"),
            (chrome(), None, "no_token"),
            (chrome(), auth("user", "feed"), "no_rule"),
            (shell(), auth("user", "feed"), "no_rule"),
        ];
        for (context, authorization, reason) in &refusals {
            not_authorized(
                &sign_soc(&mut core, &mut id, context, authorization.clone()),
                reason,
            );
        }
        let covered = [
            (site(), auth("user", "feed")),
            (site(), auth("user", "raw")),
            (site(), auth("auto", "feed")),
            (page(SITE, SITE, Some(true)), auth("user", "raw")),
            (shell(), None),
        ];
        for (context, authorization) in &covered {
            refused(
                &sign_soc(&mut core, &mut id, context, authorization.clone()),
                "vault_locked",
                None,
            );
        }

        // The public work first: an identifier of 31 bytes, an empty
        // payload, one past a chunk, a span not a string.
        let malformed = [
            ("identifier", json!(format!("0x{}", "ab".repeat(31)))),
            ("payload", json!("0x")),
            ("payload", json!(format!("0x{}", "00".repeat(4097)))),
            ("span", json!(5)),
        ];
        for (field, value) in &malformed {
            for (context, authorization) in [
                (site(), None),
                (site(), auth("auto", "raw")),
                (page(OTHER, OTHER, Some(false)), auth("user", "feed")),
                (chrome(), None),
            ] {
                let mut params = soc_params(authorization);
                params[*field] = value.clone();
                refused(
                    &call_as(&mut core, &mut id, &context, "swarm.sign_soc", params),
                    "invalid_argument",
                    None,
                );
            }
        }
        // A page with no `PageContext` is malformed, with or without one.
        let bare = json!({ "caller": "page" });
        for authorization in [None, auth("user", "feed")] {
            refused(
                &sign_soc(&mut core, &mut id, &bare, authorization),
                "invalid_argument",
                None,
            );
        }

        // Tokens presented to `swarm.sign_soc` while locked: a page's under
        // `page`, alone and beside `{ swarm, soc }`, and under `chrome`; a
        // wallet's under `shell`.
        let presented = [
            (site(), json!({ "token": page_tokens[0], "handle": HANDLE })),
            (
                site(),
                json!({ "swarm": "user", "soc": "feed", "token": page_tokens[1] }),
            ),
            (
                chrome(),
                json!({ "token": page_tokens[2], "handle": HANDLE }),
            ),
            (shell(), json!({ "token": wallet })),
        ];
        for (context, authorization) in presented {
            refused(
                &sign_soc(&mut core, &mut id, &context, Some(authorization)),
                "invalid_argument",
                None,
            );
        }

        let unlocked = call_as(
            &mut core,
            &mut id,
            &shell(),
            "vault.unlock",
            json!({ "password_b64": STANDARD.encode("testpass1") }),
        );
        result(&unlocked);
        let sign_message = |core: &mut Core, id: &mut u64, token: &str| {
            call_as(
                core,
                id,
                &site(),
                "sign.message",
                json!({ "key": { "kind": "account", "index": 0 }, "message": "0x68656c6c6f",
                    "authorization": { "token": token, "handle": HANDLE } }),
            )
        };
        let send = |core: &mut Core, id: &mut u64, token: &str| {
            call_as(
                core,
                id,
                &shell(),
                "sign.transaction",
                json!({ "key": { "kind": "account", "index": 0 }, "tx": send_tx(),
                    "authorization": { "token": token, "kind": "wallet-send" } }),
            )
        };
        for token in &page_tokens {
            not_authorized(&sign_message(&mut core, &mut id, token), "unknown_token");
        }
        not_authorized(&send(&mut core, &mut id, &wallet), "unknown_token");
        assert!(
            result(&sign_message(&mut core, &mut id, &page_control))["signature"].is_string(),
            "{store:?}"
        );
        assert!(result(&send(&mut core, &mut id, &wallet_control))["raw"].is_string());
        // Unlocked, what the grant covers signs.
        assert!(
            result(&sign_soc(&mut core, &mut id, &site(), auth("auto", "feed")))["signature"]
                .is_string()
        );
    }
}
