//! Q9's limits on "Always allow" in the dApp store (design 0012, APR-2):
//! vectors/approvals.json's `rollback` (the legacy transition, byte for
//! byte, with what the reference reads from each text), the 30 days, the
//! value cap, today's rules answering nothing, and the bound of 256 rules
//! across both lists.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_approval::stores::{
    DappStore, Effect, MAX_TRANSACTION_RULES, RULE_TTL_MS, Refused, SigningRule, TransactionRule,
    Unreadable,
};
use fc_evm::U256;
use serde_json::{Value, json};

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/approvals.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

const SITE: &str = "https://app.example";
const T: u64 = 1_762_000_000_000;
const GRANTED: u64 = T + 100_000;
const ROUTER: [u8; 20] = [0xab; 20];
const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const USDC: [u8; 20] = [
    0x83, 0x35, 0x89, 0xfc, 0xd6, 0xed, 0xb6, 0xe0, 0x8f, 0x4c, 0x7c, 0x32, 0xd4, 0xf7, 0x1b, 0x54,
    0xbd, 0xa0, 0x29, 0x13,
];
const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

fn wei(value: u64) -> U256 {
    U256::from_u64(value)
}

fn store(text: &str) -> DappStore {
    DappStore::load(text.as_bytes()).unwrap()
}

/// The core's own answers for a text, as the reference's are recorded.
fn answers(store: &DappStore, now: u64) -> (SigningRule, TransactionRule, TransactionRule) {
    (
        store.signing_rule(SITE, now),
        store.transaction_rule(SITE, &ROUTER, &APPROVE, 1, &wei(0), now),
        store.transaction_rule(SITE, &USDC, &TRANSFER, 8453, &wei(0), now),
    )
}

#[test]
fn rollback_vectors() {
    let vectors = vectors();
    let cases = vectors["rollback"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        assert_eq!(case["key"], json!(SITE));
        let texts = &case["texts"];
        let before = store(texts["before"].as_str().unwrap());
        let value = wei(500);

        let mut signing = before.clone();
        assert_eq!(
            signing.allow_signing(SITE, GRANTED).effect,
            Effect::Widening
        );
        assert_eq!(
            signing.text().unwrap(),
            texts["signing"].as_str().unwrap(),
            "{id}: signing"
        );

        let mut transaction = before.clone();
        let out = transaction.allow_transaction(SITE, &ROUTER, &APPROVE, 1, &value, GRANTED);
        assert_eq!((out.value, out.effect), (true, Effect::Widening));
        assert_eq!(
            transaction.text().unwrap(),
            texts["transaction"].as_str().unwrap(),
            "{id}: transaction"
        );

        let mut both = signing.clone();
        both.allow_transaction(SITE, &ROUTER, &APPROVE, 1, &value, GRANTED);
        assert_eq!(
            both.text().unwrap(),
            texts["both"].as_str().unwrap(),
            "{id}: both"
        );

        let mut off = both.clone();
        assert_eq!(off.signing_off(SITE).effect, Effect::Narrowing);
        let out = off.remove_transaction_rule(SITE, &ROUTER, &APPROVE, 1);
        assert_eq!((out.value, out.effect), (true, Effect::Narrowing));
        assert_eq!(
            off.text().unwrap(),
            texts["off"].as_str().unwrap(),
            "{id}: off"
        );

        // The older build: the before entry answers both lookups, each
        // replaced rule answers none after its replacement, and a rule not
        // replaced still answers.
        let reference = &case["reference"];
        assert_eq!(
            reference["before"],
            json!({ "signing": true, "replaced": true, "kept": true })
        );
        assert_eq!(reference["signing"]["signing"], json!(false), "{id}");
        assert_eq!(reference["transaction"]["replaced"], json!(false), "{id}");
        assert_eq!(
            reference["both"],
            json!({ "signing": false, "replaced": false, "kept": true }),
            "{id}"
        );
        assert_eq!(
            reference["off"],
            json!({ "signing": false, "replaced": false, "kept": true }),
            "{id}"
        );

        // The core: today's rules answer nothing; each limited rule answers
        // once given, read back from its own text as after a restart.
        let now = GRANTED + 1;
        let reread = |text: &str| store(texts[text].as_str().unwrap());
        let before_answers = if id == "limited-and-old" {
            // A limited rule given before the rollback still answers
            // (maxValue 9 covers a call of 0).
            (
                SigningRule::Active,
                TransactionRule::Covered,
                TransactionRule::None,
            )
        } else {
            (
                SigningRule::None,
                TransactionRule::None,
                TransactionRule::None,
            )
        };
        assert_eq!(answers(&reread("before"), now), before_answers, "{id}");
        assert_eq!(
            answers(&reread("both"), now),
            (
                SigningRule::Active,
                TransactionRule::Covered,
                TransactionRule::None
            ),
            "{id}"
        );
        assert_eq!(
            answers(&reread("off"), now),
            (
                SigningRule::None,
                TransactionRule::None,
                TransactionRule::None
            ),
            "{id}"
        );
        assert_eq!(
            answers(&reread("signing"), now).0,
            SigningRule::Active,
            "{id}"
        );
        assert_eq!(
            answers(&reread("transaction"), now).1,
            TransactionRule::Covered,
            "{id}"
        );
    }
}

/// A connected site with both limited rules, given at `GRANTED`.
fn limited_site(max_value: u64) -> DappStore {
    let mut store = DappStore::new();
    store.connect(SITE, 0, 1, T);
    store.allow_signing(SITE, GRANTED);
    store.allow_transaction(SITE, &ROUTER, &APPROVE, 1, &wei(max_value), GRANTED);
    store
}

#[test]
fn thirty_days_of_the_wall_clock() {
    let store = limited_site(10);
    // Read back from its own text: the time is in the file, so a restart
    // changes nothing.
    for store in [
        store.clone(),
        DappStore::load(store.text().unwrap().as_bytes()).unwrap(),
    ] {
        let at = |now| {
            (
                store.signing_rule(SITE, now),
                store.transaction_rule(SITE, &ROUTER, &APPROVE, 1, &wei(10), now),
            )
        };
        assert_eq!(at(GRANTED), (SigningRule::Active, TransactionRule::Covered));
        assert_eq!(
            at(GRANTED + RULE_TTL_MS - 1),
            (SigningRule::Active, TransactionRule::Covered)
        );
        assert_eq!(
            at(GRANTED + RULE_TTL_MS),
            (SigningRule::Expired, TransactionRule::Expired)
        );
        // A wall clock set before grantedAt expires it.
        assert_eq!(
            at(GRANTED - 1),
            (SigningRule::Expired, TransactionRule::Expired)
        );
    }
    assert_eq!(RULE_TTL_MS, 2_592_000_000);
}

#[test]
fn a_new_always_allow_replaces_the_rule() {
    let mut store = limited_site(10);
    let later = GRANTED + RULE_TTL_MS - 5;
    store.allow_signing(SITE, later);
    store.allow_transaction(SITE, &ROUTER, &APPROVE, 1, &wei(3), later);
    let now = GRANTED + RULE_TTL_MS + 5;
    assert_eq!(store.signing_rule(SITE, now), SigningRule::Active);
    // The new send's value, not the larger of the two.
    assert_eq!(
        store.transaction_rule(SITE, &ROUTER, &APPROVE, 1, &wei(3), now),
        TransactionRule::Covered
    );
    assert_eq!(
        store.transaction_rule(SITE, &ROUTER, &APPROVE, 1, &wei(4), now),
        TransactionRule::AboveMaxValue
    );
    let text = store.text().unwrap();
    assert_eq!(text.matches("\"maxValue\"").count(), 1, "one rule per call");
}

#[test]
fn no_more_value_than_the_confirmed_send() {
    let send = 1_000_000_000_000_000u64;
    let store = limited_site(send);
    let now = GRANTED + 1;
    let call = |value: U256| store.transaction_rule(SITE, &ROUTER, &APPROVE, 1, &value, now);
    assert_eq!(call(wei(send)), TransactionRule::Covered);
    assert_eq!(call(wei(0)), TransactionRule::Covered);
    assert_eq!(call(wei(send + 1)), TransactionRule::AboveMaxValue);
    // Another call, chain or account isn't the rule's.
    assert_eq!(
        store.transaction_rule(SITE, &ROUTER, &TRANSFER, 1, &wei(0), now),
        TransactionRule::None
    );
    assert_eq!(
        store.transaction_rule(SITE, &ROUTER, &APPROVE, 10, &wei(0), now),
        TransactionRule::None
    );
    assert_eq!(
        store.transaction_rule("https://other.example", &ROUTER, &APPROVE, 1, &wei(0), now),
        TransactionRule::None
    );
}

#[test]
fn a_rule_from_a_send_of_zero() {
    // An ERC-20 transfer carries its amount in `data`: a rule from a send
    // of 0 covers its selector for any amount, and only calls of 0 ETH.
    let mut store = DappStore::new();
    store.connect(SITE, 0, 1, T);
    store.allow_transaction(SITE, &USDC, &TRANSFER, 8453, &wei(0), GRANTED);
    let now = GRANTED + 1;
    assert_eq!(
        store.transaction_rule(SITE, &USDC, &TRANSFER, 8453, &wei(0), now),
        TransactionRule::Covered
    );
    assert_eq!(
        store.transaction_rule(SITE, &USDC, &TRANSFER, 8453, &wei(1), now),
        TransactionRule::AboveMaxValue
    );
}

#[test]
fn todays_rules_answer_nothing() {
    let text = format!(
        r#"{{"{SITE}": {{"origin": "{SITE}", "walletIndex": 0, "autoApprove": {{"signing": true,
        "transactions": [{{"to": "0x{to}", "selector": "0x095ea7b3", "chainId": 1, "maxValue": "1000"}},
        {{"to": "0x{to}", "selector": "0x095ea7b3", "chainId": 1}}]}}}}}}"#,
        to = "ab".repeat(20)
    );
    let store = store(&text);
    assert_eq!(store.signing_rule(SITE, T), SigningRule::None);
    assert_eq!(
        store.transaction_rule(SITE, &ROUTER, &APPROVE, 1, &wei(0), T),
        TransactionRule::None
    );
}

#[test]
fn a_limited_rule_without_its_fields_answers_nothing() {
    let text = format!(
        r#"{{"{SITE}": {{"autoApprove": {{"limited": {{"signing": {{}},
        "transactions": [{{"to": "0x{to}", "selector": "0x095ea7b3", "chainId": 1, "grantedAt": {T}}},
        {{"to": "0x{to}", "selector": "0x095ea7b3", "chainId": 1, "maxValue": "1", "grantedAt": "{T}"}}]}}}}}}}}"#,
        to = "ab".repeat(20)
    );
    let store = store(&text);
    assert_eq!(store.signing_rule(SITE, T), SigningRule::None);
    // No maxValue: covers nothing; a grantedAt that isn't a number: no rule.
    assert_eq!(
        store.transaction_rule(SITE, &ROUTER, &APPROVE, 1, &wei(0), T),
        TransactionRule::AboveMaxValue
    );
}

#[test]
fn turning_off_and_revoking_clear_both() {
    let mut store = limited_site(5);
    let now = GRANTED + 1;
    store.signing_off(SITE);
    assert_eq!(store.signing_rule(SITE, now), SigningRule::None);
    assert_eq!(
        store.transaction_rule(SITE, &ROUTER, &APPROVE, 1, &wei(0), now),
        TransactionRule::Covered
    );
    assert!(
        store
            .remove_transaction_rule(SITE, &ROUTER, &APPROVE, 1)
            .value
    );
    assert_eq!(
        store.transaction_rule(SITE, &ROUTER, &APPROVE, 1, &wei(0), now),
        TransactionRule::None
    );
    assert_eq!(
        store
            .remove_transaction_rule(SITE, &ROUTER, &APPROVE, 1)
            .effect,
        Effect::Unchanged
    );
    let mut revoked = limited_site(5);
    assert!(revoked.revoke(SITE).value);
    assert_eq!(revoked.signing_rule(SITE, now), SigningRule::None);
    assert_eq!(revoked.text().unwrap(), "{}");
}

#[test]
fn one_change_written_once() {
    // The limited rule in and the old rule out are one text: a copy changed
    // and not written leaves the store as it was, with both old rules.
    let vectors = vectors();
    let before_text = vectors["rollback"][0]["texts"]["before"].as_str().unwrap();
    let before = store(before_text);
    let mut changed = before.clone();
    changed.allow_transaction(SITE, &ROUTER, &APPROVE, 1, &wei(500), GRANTED);
    changed.allow_signing(SITE, GRANTED);
    assert_ne!(changed.text().unwrap(), before.text().unwrap());
    assert_eq!(before.text().unwrap(), before_text);
    assert_eq!(
        before.transaction_rule(SITE, &ROUTER, &APPROVE, 1, &wei(0), GRANTED + 1),
        TransactionRule::None
    );
}

/// A site with `legacy` of today's rules and `limited` limited ones, each
/// for another call.
fn site_with_rules(legacy: usize, limited: usize) -> String {
    let rule = |index: usize| {
        format!(
            r#"{{"to": "0x{:040x}", "selector": "0x095ea7b3", "chainId": 1, "maxValue": "1""#,
            index + 1
        )
    };
    let old: Vec<String> = (0..legacy)
        .map(|index| format!("{}}}", rule(index)))
        .collect();
    let new: Vec<String> = (0..limited)
        .map(|index| format!(r#"{}, "grantedAt": {GRANTED}}}"#, rule(legacy + index)))
        .collect();
    format!(
        r#"{{"{SITE}": {{"origin": "{SITE}", "walletIndex": 0, "autoApprove": {{"signing": false, "transactions": [{}],
        "limited": {{"signing": null, "transactions": [{}]}}}}}}}}"#,
        old.join(","),
        new.join(",")
    )
}

fn address(index: usize) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[12..].copy_from_slice(&((index + 1) as u64).to_be_bytes());
    out
}

#[test]
fn the_bound_counts_both_lists() {
    // 256 split between the lists, all old, all limited: each read.
    for (legacy, limited) in [
        (128, 128),
        (MAX_TRANSACTION_RULES, 0),
        (0, MAX_TRANSACTION_RULES),
        (1, 255),
    ] {
        let store = store(&site_with_rules(legacy, limited));
        // An "Always allow" that replaces an old rule writes, the count
        // still 256.
        if legacy > 0 {
            let mut replacing = store.clone();
            replacing.allow_transaction(SITE, &address(0), &APPROVE, 1, &wei(1), GRANTED);
            let text = replacing.text().unwrap();
            assert_eq!(text.matches("\"selector\"").count(), MAX_TRANSACTION_RULES);
        }
        // One that replaces none is refused, and the store is unchanged.
        let mut adding = store.clone();
        adding.allow_transaction(SITE, &address(500), &APPROVE, 1, &wei(1), GRANTED);
        assert_eq!(
            adding.text(),
            Err(Refused::TooManyRules),
            "{legacy}+{limited}"
        );
        assert!(store.text().is_ok());
    }
    // One past the bound in either list: unreadable.
    for (legacy, limited) in [
        (MAX_TRANSACTION_RULES + 1, 0),
        (0, MAX_TRANSACTION_RULES + 1),
        (MAX_TRANSACTION_RULES, 1),
        (1, MAX_TRANSACTION_RULES),
    ] {
        assert_eq!(
            DappStore::load(site_with_rules(legacy, limited).as_bytes()),
            Err(Unreadable::TooManyRules),
            "{legacy}+{limited}"
        );
    }
}
