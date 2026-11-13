//! The standing rules (design 0012, APR-2): vectors/approvals.json's
//! `rules.decisions`, which the pinned reference's page-signing.js and
//! page-sends.js produced, replayed against fc-approval's `standing`, with
//! Q9's limits where the core answers otherwise; and the Swarm and Radicle
//! rules, which keep today's.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_approval::fee::{Evidence, Fees};
use fc_approval::standing::{
    AccountKind, Clocks, DappAsk, DappRequest, Decision, RadicleAsk, RadicleRequest, Reason, Send,
    Signed, Standing, SwarmAsk, SwarmRequest, swarm,
};
use fc_approval::stores::{
    DappStore, RULE_TTL_MS, RadicleFlag, RadicleStore, SwarmFlag, SwarmStore,
};
use fc_evm::{Transaction, U256, ViewRequest, parse_address, parse_bytes, typed_data_view};
use serde_json::{Value, json};

fn decisions() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/approvals.json");
    let all: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    all["rules"]["decisions"].clone()
}

const SITE: &str = "https://app.example";

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

fn number(value: &Value) -> u64 {
    value.as_u64().unwrap()
}

fn account_kind(name: &str) -> AccountKind {
    match name {
        "vault" => AccountKind::Vault,
        "ledger" => AccountKind::Ledger,
        "phone" => AccountKind::Phone,
        "safe" => AccountKind::Safe,
        other => panic!("{other}"),
    }
}

fn expected(name: &str) -> Decision {
    if name == "covered" {
        Decision::Covered
    } else {
        Decision::NotCovered(Reason::from_name(name).unwrap())
    }
}

/// The transaction main signs, as `sign.transaction` receives it (nonce 0).
fn transaction(tx: &Value) -> Transaction {
    let mut fields = json!({
        "chain_id": number(&tx["chainId"]).to_string(),
        "nonce": "0",
        "gas_limit": tx["gasLimit"],
        "to": tx["to"],
        "value": tx["value"],
        "data": tx["data"],
    });
    if let Some(gas_price) = tx.get("gasPrice") {
        fields["type"] = json!(0);
        fields["gas_price"] = gas_price.clone();
    } else {
        fields["type"] = json!(2);
        fields["max_fee_per_gas"] = tx["maxFeePerGas"].clone();
        fields["max_priority_fee_per_gas"] = tx["maxPriorityFeePerGas"].clone();
    }
    Transaction::from_json(&fields).unwrap()
}

/// The fields the core's typed-data view reports, which the step names.
fn view_fields(view: &str) -> Value {
    let parsed: Value = serde_json::from_str(view).unwrap();
    json!({ "named_type": parsed["named_type"], "chain": parsed["chain"] })
}

#[test]
fn decision_vectors() {
    let decisions = decisions();
    assert_eq!(number(&decisions["ruleTtlMs"]), RULE_TTL_MS);
    let runs = decisions["runs"].as_array().unwrap();
    assert!(runs.len() >= 28);
    let mut requests = 0;
    for run in runs {
        let id = text(&run["id"]);
        assert_eq!(run["key"], json!(SITE));
        let mut store = match run["start"]["core"].as_str() {
            Some(start) => DappStore::load(start.as_bytes()).unwrap(),
            None => DappStore::new(),
        };
        let mut standing = Standing::new();
        for (index, step) in run["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{id} step {index}");
            let at = number(&step["at"]);
            match text(&step["op"]) {
                "request" => {}
                "restart" => {
                    store = DappStore::load(store.text().unwrap().as_bytes()).unwrap();
                    standing = Standing::new();
                    continue;
                }
                op => {
                    let args = &step["args"];
                    match op {
                        "allow-signing" => assert!(store.allow_signing(SITE, at).value),
                        "allow-transaction" => {
                            let to = parse_address(text(&args["to"])).unwrap();
                            let selector: [u8; 4] =
                                parse_bytes(text(&args["selector"]), "selector")
                                    .unwrap()
                                    .try_into()
                                    .unwrap();
                            let value = U256::parse_decimal(text(&args["value"])).unwrap();
                            let chain_id = number(&args["chainId"]);
                            assert!(
                                store
                                    .allow_transaction(SITE, &to, &selector, chain_id, &value, at)
                                    .value
                            );
                        }
                        "revoke" => {
                            assert!(store.revoke(SITE).value);
                            standing.forget_dapp(SITE);
                        }
                        "connect" => {
                            let account = u32::try_from(number(&args["account"])).unwrap();
                            let _ = store.connect(SITE, account, number(&args["chainId"]), at);
                        }
                        other => panic!("{label}: {other}"),
                    }
                    assert_eq!(store.text().unwrap(), text(&step["coreText"]), "{label}");
                    continue;
                }
            }
            requests += 1;
            let core = &step["core"];
            if let Some(moved) = core.get("moveTo") {
                let account = u32::try_from(number(moved)).unwrap();
                assert!(store.set_account(SITE, account, at).value, "{label}");
            }
            let clocks = Clocks {
                wall_ms: at,
                vault_ms: number(&step["vaultAt"]),
            };
            let agent = core["agent"].as_bool();
            let account = u32::try_from(number(&core["account"])).unwrap();
            let kind = account_kind(text(&core["accountKind"]));
            let request = &core["request"];
            let expect = expected(text(&core["expect"]));

            // What each request kind needs held while its ask borrows it.
            let bytes;
            let view;
            let tx;
            let evidence;
            let request = match text(&request["kind"]) {
                "message" => {
                    bytes = parse_bytes(text(&request["bytes"]), "message").unwrap();
                    DappRequest::Signature(Signed::Message(&bytes))
                }
                "typed-data" => {
                    let data = &request["typedData"];
                    let chain_id = request["chainId"].as_u64().map(U256::from_u64);
                    view = typed_data_view(
                        &data["domain"],
                        &data["types"],
                        &data["message"],
                        &ViewRequest {
                            primary_type: request.get("primaryType"),
                            chain_id,
                            max_len: 1 << 20,
                        },
                    )
                    .unwrap();
                    // The core's own view holds what the reference was told.
                    assert_eq!(view_fields(&view.view), request["view"], "{label}: view");
                    DappRequest::Signature(Signed::TypedData(&view))
                }
                "transaction" => {
                    tx = transaction(&request["tx"]);
                    evidence = request["evidence"].as_object().map(|evidence| {
                        Evidence::read(&evidence["reply"], number(&evidence["requestedAt"]))
                    });
                    DappRequest::Transaction(Send::of(
                        &tx,
                        kind,
                        request["paused"].as_bool(),
                        evidence.as_ref(),
                    ))
                }
                other => panic!("{label}: {other}"),
            };
            let ask = DappAsk {
                key: SITE,
                agent,
                account,
                request,
            };
            // Advice first, which counts nothing; then the decision.
            assert_eq!(
                standing.check_dapp(&store, &ask, clocks),
                expect,
                "{label}: advice"
            );
            assert_eq!(
                standing.authorize_dapp(&store, &ask, clocks),
                expect,
                "{label}"
            );
        }
    }
    assert!(requests >= 150, "{requests}");
}

// ---------------------------------------------------------------------------
// Each check on its own.

const T: u64 = 1_762_000_000_000;
const NOW: Clocks = Clocks {
    wall_ms: T + 60_000,
    vault_ms: 5_000_000,
};
const ROUTER: [u8; 20] = [0xab; 20];
const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

fn ruled_store() -> DappStore {
    let mut store = DappStore::new();
    let _ = store.connect(SITE, 0, 1, T);
    assert!(store.allow_signing(SITE, T).value);
    assert!(
        store
            .allow_transaction(SITE, &ROUTER, &APPROVE, 1, &U256::from_u64(0), T)
            .value
    );
    store
}

fn named_fees() -> Fees {
    Fees {
        max_fee_per_gas: Some(U256::from_u64(30_000_000_000)),
        max_priority_fee_per_gas: Some(U256::from_u64(1_000_000_000)),
        gas_price: None,
        gas_limit: Some(U256::from_u64(60_000)),
    }
}

fn evidence() -> Evidence {
    Evidence::read(
        &json!({
            "header": { "source": "colibri", "number": "1", "timestamp": ((T + 60_000) / 1000).to_string(), "base_fee": "10000000000" },
            "lowest_priority": "1000000000",
            "quote": null,
        }),
        NOW.vault_ms,
    )
}

fn send<'a>(
    kind: AccountKind,
    to: Option<&'a [u8; 20]>,
    data: &'a [u8],
    chain_id: &'a U256,
    fees: Fees,
    evidence: Option<&'a Evidence>,
) -> DappAsk<'a> {
    static ZERO: U256 = U256::ZERO;
    DappAsk {
        key: SITE,
        agent: Some(false),
        account: 0,
        request: DappRequest::Transaction(Send {
            kind,
            to,
            data,
            value: &ZERO,
            chain_id,
            fees,
            paused: Some(false),
            evidence,
        }),
    }
}

#[test]
fn sends_no_rule_answers() {
    let store = ruled_store();
    let standing = Standing::new();
    let evidence = evidence();
    let one = U256::from_u64(1);
    let data = [0x09, 0x5e, 0xa7, 0xb3, 0, 0];
    let check = |ask: &DappAsk<'_>| standing.check_dapp(&store, ask, NOW);
    let base = send(
        AccountKind::Vault,
        Some(&ROUTER),
        &data,
        &one,
        named_fees(),
        Some(&evidence),
    );
    assert_eq!(check(&base), Decision::Covered);
    // A Safe's send, whatever its rule.
    let safe = send(
        AccountKind::Safe,
        Some(&ROUTER),
        &data,
        &one,
        named_fees(),
        Some(&evidence),
    );
    assert_eq!(check(&safe), Decision::NotCovered(Reason::NoRule));
    // A contract creation.
    let create = send(
        AccountKind::Vault,
        None,
        &data,
        &one,
        named_fees(),
        Some(&evidence),
    );
    assert_eq!(check(&create), Decision::NotCovered(Reason::NoRule));
    // A chain no rule can name.
    let huge = U256::from_u64(1 << 53);
    let far = send(
        AccountKind::Vault,
        Some(&ROUTER),
        &data,
        &huge,
        named_fees(),
        Some(&evidence),
    );
    assert_eq!(check(&far), Decision::NotCovered(Reason::NoRule));
    // Another account than the grant's.
    let mut other = send(
        AccountKind::Vault,
        Some(&ROUTER),
        &data,
        &one,
        named_fees(),
        Some(&evidence),
    );
    other.account = 1;
    assert_eq!(check(&other), Decision::NotCovered(Reason::NoRule));
}

#[test]
fn sends_name_their_own_fees_but_a_phones() {
    let store = ruled_store();
    let standing = Standing::new();
    let evidence = evidence();
    let one = U256::from_u64(1);
    let data = APPROVE;
    let no_fees = Fees {
        gas_limit: Some(U256::from_u64(60_000)),
        ..Fees::default()
    };
    let half = Fees {
        max_priority_fee_per_gas: None,
        ..named_fees()
    };
    for fees in [no_fees.clone(), half] {
        let vault = send(
            AccountKind::Vault,
            Some(&ROUTER),
            &data,
            &one,
            fees,
            Some(&evidence),
        );
        assert_eq!(
            standing.check_dapp(&store, &vault, NOW),
            Decision::NotCovered(Reason::FeeCheck)
        );
    }
    let phone = send(
        AccountKind::Phone,
        Some(&ROUTER),
        &data,
        &one,
        no_fees,
        None,
    );
    assert_eq!(standing.check_dapp(&store, &phone, NOW), Decision::Covered);
}

#[test]
fn custody_comes_first_and_a_missing_input_is_no_rule() {
    let store = ruled_store();
    let standing = Standing::new();
    let message = DappRequest::Signature(Signed::Message(b"hello"));
    for agent in [None, Some(true)] {
        let ask = DappAsk {
            key: "https://other.example",
            agent,
            account: 0,
            request: message.clone(),
        };
        assert_eq!(
            standing.check_dapp(&store, &ask, NOW),
            Decision::NotCovered(Reason::Custody)
        );
    }
    let one = U256::from_u64(1);
    let data = APPROVE;
    let mut paused = send(
        AccountKind::Vault,
        Some(&ROUTER),
        &data,
        &one,
        named_fees(),
        None,
    );
    if let DappRequest::Transaction(send) = &mut paused.request {
        send.paused = None;
    }
    assert_eq!(
        standing.check_dapp(&store, &paused, NOW),
        Decision::NotCovered(Reason::Paused)
    );
}

#[test]
fn only_a_covered_decision_counts() {
    let store = ruled_store();
    let mut standing = Standing::new();
    let hello = DappAsk {
        key: SITE,
        agent: Some(false),
        account: 0,
        request: DappRequest::Signature(Signed::Message(b"hello")),
    };
    let raw = DappAsk {
        request: DappRequest::Signature(Signed::Message(&[0xab; 32])),
        ..hello.clone()
    };
    // Advice and refusals count nothing.
    for _ in 0..20 {
        assert!(standing.check_dapp(&store, &hello, NOW).is_covered());
        assert_eq!(
            standing.authorize_dapp(&store, &raw, NOW).reason(),
            Some(Reason::Warning)
        );
    }
    for _ in 0..5 {
        assert!(standing.authorize_dapp(&store, &hello, NOW).is_covered());
    }
    assert_eq!(
        standing.check_dapp(&store, &hello, NOW),
        Decision::NotCovered(Reason::RateLimited)
    );
    assert_eq!(
        standing.authorize_dapp(&store, &hello, NOW),
        Decision::NotCovered(Reason::RateLimited)
    );
    // A revoke forgets the buckets.
    standing.forget_dapp(SITE);
    assert!(standing.check_dapp(&store, &hello, NOW).is_covered());
}

#[test]
fn reason_names() {
    let names: Vec<&str> = Reason::ALL.iter().map(|reason| reason.name()).collect();
    assert_eq!(
        names,
        [
            "no_rule",
            "paused",
            "fee_check",
            "custody",
            "rate_limited",
            "warning"
        ]
    );
    for reason in Reason::ALL {
        assert_eq!(Reason::from_name(reason.name()), Some(reason));
    }
    assert_eq!(Reason::from_name("expired"), None);
}

#[test]
fn swarm_flags_per_request() {
    let mut store = SwarmStore::new();
    let ask = |request, agent| SwarmAsk {
        key: SITE,
        agent,
        request,
    };
    let feeds = SwarmRequest::Feeds { feed_grant: true };
    let signing = SwarmRequest::Signing { feed_grant: true };
    let all = [SwarmRequest::Publish, feeds, signing, SwarmRequest::Message];
    // Not connected.
    for request in all {
        assert_eq!(
            swarm(&store, &ask(request, Some(false))),
            Decision::NotCovered(Reason::NoRule)
        );
    }
    let _ = store.connect(SITE, T);
    for request in all {
        assert_eq!(
            swarm(&store, &ask(request, Some(false))).reason(),
            Some(Reason::NoRule)
        );
    }
    for flag in SwarmFlag::ALL {
        assert!(store.set_flag(SITE, flag, true).value);
    }
    assert!(swarm(&store, &ask(SwarmRequest::Publish, Some(false))).is_covered());
    assert!(swarm(&store, &ask(feeds, Some(false))).is_covered());
    assert!(swarm(&store, &ask(signing, Some(false))).is_covered());
    // Feeds and signing need feed access; a message, the messaging grant.
    for request in [
        SwarmRequest::Feeds { feed_grant: false },
        SwarmRequest::Signing { feed_grant: false },
        SwarmRequest::Message,
    ] {
        assert_eq!(
            swarm(&store, &ask(request, Some(false))).reason(),
            Some(Reason::NoRule)
        );
    }
    assert!(store.grant_messaging(SITE, T).value);
    assert!(swarm(&store, &ask(SwarmRequest::Message, Some(false))).is_covered());
    // Each flag answers only for its own requests.
    assert!(store.set_flag(SITE, SwarmFlag::Feeds, false).value);
    assert_eq!(
        swarm(&store, &ask(feeds, Some(false))).reason(),
        Some(Reason::NoRule)
    );
    assert!(swarm(&store, &ask(signing, Some(false))).is_covered());
    // Never in custody, nor without `agent`; and no rate.
    for agent in [None, Some(true)] {
        assert_eq!(
            swarm(&store, &ask(SwarmRequest::Publish, agent)),
            Decision::NotCovered(Reason::Custody)
        );
    }
    for _ in 0..100 {
        assert!(swarm(&store, &ask(SwarmRequest::Publish, Some(false))).is_covered());
    }
}

#[test]
fn radicle_seeds_and_cob_writes_within_r6() {
    let mut store = RadicleStore::new();
    let mut standing = Standing::new();
    let ask = |request, agent| RadicleAsk {
        key: SITE,
        agent,
        request,
    };
    let seed = ask(RadicleRequest::Seed, Some(false));
    let write = ask(RadicleRequest::CobWrite, Some(false));
    let at = 5_000_000;
    assert_eq!(
        standing.check_radicle(&store, &seed, at).reason(),
        Some(Reason::NoRule)
    );
    let _ = store.connect(SITE, T);
    assert_eq!(
        standing.check_radicle(&store, &seed, at).reason(),
        Some(Reason::NoRule)
    );
    assert!(store.set_flag(SITE, RadicleFlag::Node, true).value);
    // Seeds keep no rate.
    for _ in 0..10 {
        assert!(standing.authorize_radicle(&store, &seed, at).is_covered());
    }
    // A COB write needs the signing grant and its rule.
    assert!(store.set_flag(SITE, RadicleFlag::Signing, true).value);
    assert_eq!(
        standing.authorize_radicle(&store, &write, at).reason(),
        Some(Reason::NoRule)
    );
    assert!(store.grant_signing(SITE).value);
    assert!(store.set_flag(SITE, RadicleFlag::Signing, false).value);
    assert_eq!(
        standing.authorize_radicle(&store, &write, at).reason(),
        Some(Reason::NoRule)
    );
    assert!(store.set_flag(SITE, RadicleFlag::Signing, true).value);
    // R-6: a burst of 5, then one per 30 s; advice counts nothing.
    for _ in 0..5 {
        assert!(standing.check_radicle(&store, &write, at).is_covered());
        assert!(standing.authorize_radicle(&store, &write, at).is_covered());
    }
    assert_eq!(
        standing.authorize_radicle(&store, &write, at),
        Decision::NotCovered(Reason::RateLimited)
    );
    assert_eq!(
        standing.check_radicle(&store, &write, at + 29_999).reason(),
        Some(Reason::RateLimited)
    );
    assert!(
        standing
            .authorize_radicle(&store, &write, at + 30_000)
            .is_covered()
    );
    // Seeds are still answered past the writes' limit.
    assert!(
        standing
            .authorize_radicle(&store, &seed, at + 30_000)
            .is_covered()
    );
    // A disconnect forgets the site.
    assert!(standing.forget_radicle(SITE));
    assert!(!standing.forget_radicle(SITE));
    assert!(
        standing
            .authorize_radicle(&store, &write, at + 30_000)
            .is_covered()
    );
    // Never in custody, nor without `agent`, and custody counts nothing.
    for agent in [None, Some(true)] {
        for request in [RadicleRequest::Seed, RadicleRequest::CobWrite] {
            assert_eq!(
                standing.authorize_radicle(&store, &ask(request, agent), at + 30_000),
                Decision::NotCovered(Reason::Custody)
            );
        }
    }
}
