//! `eth_requestAccounts` (design 0012, APR-5c), as the approvals
//! reference's `requestAccounts` answers it (`page-ethereum.js`,
//! `7f85551d`), the prompt asked through the core's `approval.request`:
//!
//! - **A document with no key** gets `4100` before anything else: no grant
//!   is read, and no prompt or recheck asked.
//! - **A key with a grant** gets its account, as `eth_accounts` reads it,
//!   or `[]`. Main is asked first whether the document still holds its key
//!   (`approval.recheck`, as the reference's `holdsKey` just before its
//!   write): if it doesn't, `4100` and nothing written; if it does, the
//!   grant's last use is marked (`updateLastUsed`).
//! - **Otherwise the user is asked** (`eth.connect`), the view main's
//!   wallet state as the reference's `connectView` builds it: the accounts
//!   that can serve a dApp (an undeployed Safe can't), the active one as
//!   the default, and the page's chain. An approve writes the grant from
//!   the answer's `choices` alone: the account picked, which must be one
//!   the prompt offered (anything else is [`Crossed`]), on the chain the
//!   page reads by the answer's `world`. An account gone by then answers
//!   the reference's error, and so does a failed write. A rejection, a
//!   closed handle or a busy window writes nothing.
//!
//! The agent's route (a tab in Agent custody answered by the agent
//! service) stays in main until APR-7 (*inferred*): main sends the request
//! only when the agent didn't take it.

use fc_json::{JsString, JsValue};

use crate::prompt::{Crossed, Decision};
use crate::{Answer, World};

/// `-32603`.
const INTERNAL_ERROR_CODE: i64 = -32603;

/// The reference's `NO_ADDRESS`: a document with no key, or one that no
/// longer holds it.
pub(crate) const NO_ADDRESS: (i64, &str) = (4100, "This page has no address to connect from yet");
/// `USER_REJECTED`: a rejection, or a handle closed with no decision.
const USER_REJECTED: (i64, &str) = (4001, "User rejected the request");
/// A busy window: 0011's one pending wallet prompt.
const BUSY: (i64, &str) = (-32002, "Another wallet request is already pending");
const GRANT_FAILED: (i64, &str) = (INTERNAL_ERROR_CODE, "Failed to save the connection");
const ACCOUNT_GONE: (i64, &str) = (
    INTERNAL_ERROR_CODE,
    "The selected account is no longer available",
);

/// The largest account index a grant holds (fc-approval's `MAX_ACCOUNT`).
const MAX_ACCOUNT: f64 = 2_147_483_647.0;

/// The prompt's kind (design 0011).
pub const CONNECT_KIND: &str = "eth.connect";

/// A connect, past the switch and the key.
#[derive(Debug, Clone, PartialEq)]
pub enum Connect {
    /// The key has a grant: answered by it, once main says the document
    /// still holds its key.
    Connected(Connected),
    /// No grant: the user is asked.
    Ask(Ask),
}

/// A connected key's answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Connected {
    /// The grant's account's address, as main's wallet list gives it.
    address: Option<JsValue>,
}

/// What a connected key's request does once main has rechecked it.
#[derive(Debug, Clone, PartialEq)]
pub struct Rechecked {
    /// Whether the grant's last use is marked.
    pub touch: bool,
    pub answer: Answer,
}

impl Connected {
    /// The answer from `approval.recheck`'s `live`.
    pub fn answer(&self, live: bool) -> Rechecked {
        if !live {
            return Rechecked {
                touch: false,
                answer: Answer::error(NO_ADDRESS.0, NO_ADDRESS.1),
            };
        }
        // `wallet?.address ? [wallet.address] : []`.
        let result = match &self.address {
            Some(address) if address.truthy() => JsValue::Array(vec![address.clone()]),
            _ => JsValue::Array(Vec::new()),
        };
        Rechecked {
            touch: true,
            answer: Answer::result(&result),
        }
    }
}

/// A connect prompt.
#[derive(Debug, Clone, PartialEq)]
pub struct Ask {
    /// The view's JSON text.
    view: String,
    /// The choices' JSON text: `{ "walletIndex": [<offered>] }`
    /// (*inferred*).
    choices: String,
    /// The indexes offered.
    offered: Vec<f64>,
}

/// What a decision does.
#[derive(Debug, Clone, PartialEq)]
pub enum Decided {
    /// Answered, with nothing written.
    Answer(Answer),
    /// The grant to write, then [`Grant::answer`].
    Grant(Grant),
}

/// The grant an approve writes: the key's connect.
#[derive(Debug, Clone, PartialEq)]
pub struct Grant {
    pub account: u32,
    pub chain_id: u64,
    address: JsValue,
}

impl Grant {
    /// The answer once the write has been made: the account, or the
    /// reference's error for a write that failed.
    pub fn answer(&self, written: bool) -> Answer {
        if written {
            Answer::result(&JsValue::Array(vec![self.address.clone()]))
        } else {
            Answer::error(GRANT_FAILED.0, GRANT_FAILED.1)
        }
    }
}

/// The connect for `key`, whose grant `grant` gives.
pub(crate) fn start(
    world: &World,
    key: &str,
    grant: impl FnOnce(&str) -> Option<JsValue>,
) -> Connect {
    if let Some(permission) = grant(key).filter(JsValue::truthy) {
        let wanted = permission.get("walletIndex").unwrap_or(&UNDEFINED);
        let address = world
            .wallets()
            .iter()
            .find(|candidate| crate::strictly_equal(index_of(candidate), wanted))
            .and_then(|wallet| wallet.get("address"))
            .cloned();
        return Connect::Connected(Connected { address });
    }
    Connect::Ask(Ask::new(world))
}

static UNDEFINED: JsValue = JsValue::Undefined;

/// `candidate?.index`: `undefined` for a nullish candidate or none.
fn index_of(candidate: &JsValue) -> &JsValue {
    match candidate {
        JsValue::Null | JsValue::Undefined => &UNDEFINED,
        candidate => candidate.get("index").unwrap_or(&UNDEFINED),
    }
}

/// `Number.isInteger(value)`.
fn integer(value: &JsValue) -> Option<f64> {
    match value {
        JsValue::Number(n) if n.is_finite() && n.fract() == 0.0 => Some(*n),
        _ => None,
    }
}

/// `connectable(wallet)`: a record with an integer index, and a Safe only
/// once deployed on Gnosis.
fn connectable(wallet: &JsValue) -> bool {
    if !wallet.truthy() || integer(index_of(wallet)).is_none() {
        return false;
    }
    if matches!(wallet.get("type"), Some(JsValue::String(t)) if t.as_str() == "safe") {
        return wallet
            .get("deployed")
            .filter(|d| !matches!(d, JsValue::Null | JsValue::Undefined))
            .and_then(|deployed| deployed.get("100"))
            .is_some_and(JsValue::truthy);
    }
    true
}

fn string_or(value: Option<&JsValue>, or: JsValue) -> JsValue {
    match value {
        Some(value @ JsValue::String(_)) => value.clone(),
        _ => or,
    }
}

fn prop(name: &str, value: JsValue) -> (JsString, JsValue) {
    (JsString::from(name), value)
}

impl Ask {
    /// The reference's `connectView`.
    fn new(world: &World) -> Ask {
        let offered: Vec<&JsValue> = world.wallets().iter().filter(|w| connectable(w)).collect();
        let accounts: Vec<JsValue> = offered
            .iter()
            .map(|wallet| {
                JsValue::Object(vec![
                    prop("index", index_of(wallet).clone()),
                    prop("name", string_or(wallet.get("name"), JsValue::string(""))),
                    prop("address", string_or(wallet.get("address"), JsValue::Null)),
                    prop(
                        "type",
                        string_or(wallet.get("type"), JsValue::string("mnemonic")),
                    ),
                ])
            })
            .collect();
        let indexes: Vec<f64> = offered
            .iter()
            .filter_map(|w| integer(index_of(w)))
            .collect();
        let active = world.active();
        let default = if offered
            .iter()
            .any(|w| crate::strictly_equal(index_of(w), active))
        {
            active.clone()
        } else {
            indexes
                .first()
                .map_or(JsValue::Null, |i| JsValue::Number(*i))
        };
        let chain_id = world.chain_id();
        // `chainName(chainId) || null`.
        let name = world
            .network(chain_id)
            .and_then(|network| network.get("name"))
            .filter(|name| name.truthy())
            .cloned()
            .unwrap_or(JsValue::Null);
        // Exact: a chain id is a safe integer.
        #[allow(clippy::cast_precision_loss)]
        let chain_number = JsValue::Number(chain_id as f64);
        let view = JsValue::Object(vec![
            prop("accounts", JsValue::Array(accounts)),
            prop("defaultIndex", default),
            prop(
                "chain",
                JsValue::Object(vec![prop("id", chain_number), prop("name", name)]),
            ),
        ]);
        let choices = JsValue::Object(vec![prop(
            "walletIndex",
            JsValue::Array(indexes.iter().map(|i| JsValue::Number(*i)).collect()),
        )]);
        Ask {
            view: view.stringify(),
            choices: choices.stringify(),
            offered: indexes,
        }
    }

    pub fn kind(&self) -> &'static str {
        CONNECT_KIND
    }

    /// The view's JSON text.
    pub fn view(&self) -> &str {
        &self.view
    }

    /// The choices' JSON text.
    pub fn choices(&self) -> &str {
        &self.choices
    }

    /// What main's decision does. An approve whose picks aren't exactly
    /// one offered account is [`Crossed`]: main checks them before it
    /// answers (0011's `page:decide`), so such an answer isn't the user's.
    pub fn decide(&self, decision: Decision) -> Result<Decided, Crossed> {
        let (choices, world) = match decision {
            Decision::Busy => return Ok(Decided::Answer(Answer::error(BUSY.0, BUSY.1))),
            Decision::Reject | Decision::Closed => {
                return Ok(Decided::Answer(Answer::error(
                    USER_REJECTED.0,
                    USER_REJECTED.1,
                )));
            }
            Decision::Approve { choices, world } => (choices, world),
        };
        let JsValue::Object(picks) = &choices else {
            return Err(Crossed);
        };
        let picked = match picks.as_slice() {
            [(name, value)] if name.as_str() == "walletIndex" => integer(value),
            _ => None,
        }
        .filter(|index| self.offered.contains(index))
        .ok_or(Crossed)?;
        // Main's wallets as it answered: the account picked, if still
        // there and still able to serve a dApp.
        let chosen = world.wallets().iter().find(|wallet| {
            wallet.truthy()
                && matches!(index_of(wallet), JsValue::Number(n) if *n == picked)
                && connectable(wallet)
        });
        let Some(address) = chosen
            .and_then(|wallet| wallet.get("address"))
            .filter(|address| address.truthy())
        else {
            return Ok(Decided::Answer(Answer::error(
                ACCOUNT_GONE.0,
                ACCOUNT_GONE.1,
            )));
        };
        // An index past what a grant holds can't be saved (*inferred*).
        if !(0.0..=MAX_ACCOUNT).contains(&picked) {
            return Ok(Decided::Answer(Answer::error(
                GRANT_FAILED.0,
                GRANT_FAILED.1,
            )));
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let account = picked as u32;
        Ok(Decided::Grant(Grant {
            account,
            chain_id: world.chain_id(),
            address: address.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Request;
    use crate::prompt::Prompts;

    fn world(extra: &str) -> World {
        Request::parse(&format!(
            r#"{{"method":"eth_requestAccounts","world":{{"enabled":true,"networks":{{"100":{{"name":"Gnosis","available":true}}}},"wallets":[{{"index":0,"address":"0xa","name":"A","type":"mnemonic"}},{{"index":1000,"address":"0xs","type":"safe","deployed":{{"100":true}}}},{{"index":1001,"address":"0xu","type":"safe","deployed":{{}}}},null,{{"index":1.5,"address":"0xf"}}]{extra}}}}}"#
        ))
        .unwrap()
        .world
    }

    fn asking(extra: &str) -> Ask {
        match start(&world(extra), "k", |_| None) {
            Connect::Ask(ask) => ask,
            other => panic!("{other:?}"),
        }
    }

    fn approve(choices: &str, extra: &str) -> Decision {
        let mut prompts = Prompts::new();
        let id = prompts.issue([1; 16]).unwrap();
        let handle = "ab".repeat(32);
        let world = r#"{"enabled":true,"networks":{},"window_chain":8453,"wallets":[{"index":0,"address":"0xa"},{"index":1000,"address":"0xs","type":"safe","deployed":{"100":1}}]"#;
        let text = format!(
            r#"{{"prompt":"{}","handle":"{handle}","approve":true,"choices":{choices},"world":{world}{extra}}}}}"#,
            id.hex()
        );
        prompts.accept(&id, &text).unwrap()
    }

    #[test]
    fn the_view_offers_what_can_serve_a_dapp() {
        let ask = asking("");
        assert_eq!(
            ask.view(),
            r#"{"accounts":[{"index":0,"name":"A","address":"0xa","type":"mnemonic"},{"index":1000,"name":"","address":"0xs","type":"safe"}],"defaultIndex":0,"chain":{"id":100,"name":"Gnosis"}}"#
        );
        assert_eq!(ask.choices(), r#"{"walletIndex":[0,1000]}"#);
        assert!(asking("").view().contains(r#""defaultIndex":0"#));
        assert!(
            asking(r#","active":1000"#)
                .view()
                .contains(r#""defaultIndex":1000"#)
        );
        // An active account not offered: the first offered.
        assert!(
            asking(r#","active":1001"#)
                .view()
                .contains(r#""defaultIndex":0"#)
        );
        assert!(
            asking(r#","window_chain":7"#)
                .view()
                .ends_with(r#""chain":{"id":7,"name":null}}"#)
        );
    }

    #[test]
    fn a_grant_is_written_only_from_an_offered_pick() {
        let ask = asking("");
        match ask.decide(approve(r#"{"walletIndex":1000}"#, "")) {
            Ok(Decided::Grant(grant)) => {
                assert_eq!((grant.account, grant.chain_id), (1000, 8453));
                assert_eq!(grant.answer(true).as_str(), r#"{"result":["0xs"]}"#);
                assert_eq!(
                    grant.answer(false).as_str(),
                    r#"{"error":{"code":-32603,"message":"Failed to save the connection"}}"#
                );
            }
            other => panic!("{other:?}"),
        }
        for choices in [
            r#"{}"#,
            r#"{"walletIndex":1001}"#,
            r#"{"walletIndex":0,"extra":true}"#,
            r#"{"walletIndex":"0"}"#,
            r#"{"walletIndex":1.5}"#,
            r#"{"walletIndex":7}"#,
            r#"{"account":0}"#,
        ] {
            assert_eq!(ask.decide(approve(choices, "")), Err(Crossed), "{choices}");
        }
    }

    #[test]
    fn no_grant_without_an_approve() {
        let ask = asking("");
        for (decision, text) in [
            (
                Decision::Reject,
                r#"{"error":{"code":4001,"message":"User rejected the request"}}"#,
            ),
            (
                Decision::Closed,
                r#"{"error":{"code":4001,"message":"User rejected the request"}}"#,
            ),
            (
                Decision::Busy,
                r#"{"error":{"code":-32002,"message":"Another wallet request is already pending"}}"#,
            ),
        ] {
            match ask.decide(decision) {
                Ok(Decided::Answer(answer)) => assert_eq!(answer.as_str(), text),
                other => panic!("{other:?}"),
            }
        }
        // Picked, then gone from main's wallets.
        let ask = asking(r#","active":0"#);
        let mut prompts = Prompts::new();
        let id = prompts.issue([2; 16]).unwrap();
        let text = format!(
            r#"{{"prompt":"{}","handle":"{}","approve":true,"choices":{{"walletIndex":0}},"world":{{"enabled":true,"networks":{{}},"wallets":[{{"index":1000,"address":"0xs","type":"safe","deployed":{{"100":true}}}}]}}}}"#,
            id.hex(),
            "cd".repeat(32)
        );
        match ask.decide(prompts.accept(&id, &text).unwrap()) {
            Ok(Decided::Answer(answer)) => assert_eq!(
                answer.as_str(),
                r#"{"error":{"code":-32603,"message":"The selected account is no longer available"}}"#
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_connected_key_answers_once_rechecked() {
        let grant = |_: &str| fc_json::parse(r#"{"walletIndex":1000}"#).ok();
        let Connect::Connected(connected) = start(&world(""), "k", grant) else {
            panic!("connected");
        };
        let live = connected.answer(true);
        assert!(live.touch);
        assert_eq!(live.answer.as_str(), r#"{"result":["0xs"]}"#);
        let gone = connected.answer(false);
        assert!(!gone.touch);
        assert_eq!(
            gone.answer.as_str(),
            r#"{"error":{"code":4100,"message":"This page has no address to connect from yet"}}"#
        );
        // A grant whose account has gone: `[]`, still marked used.
        let grant = |_: &str| fc_json::parse(r#"{"walletIndex":5}"#).ok();
        let Connect::Connected(connected) = start(&world(""), "k", grant) else {
            panic!("connected");
        };
        assert_eq!(connected.answer(true).answer.as_str(), r#"{"result":[]}"#);
    }
}
