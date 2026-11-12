//! Replays vectors/approvals.json, which the pinned reference's
//! signing-confirmation.js produced (design 0012, APR-1): each case issued
//! or refused as 0012 expects, each pair alike or apart as the reference
//! decides but for 0012's deviations, and each run's steps in order.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::PathBuf;

use fc_approval::{
    Handle, Issued, Kind, Limits, MAX_OUTSTANDING, Page, PageRule, Refusal, Request, Spent,
    TOKEN_TTL_MS, Tokens,
};
use serde_json::Value;

fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/approvals.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

const LIMITS: Limits = Limits {
    max_view_len: 1 << 20,
};

/// Each fill is the next of a counter's values, spread over the bytes:
/// every token differs, and each run is the same.
struct CountingRng(u64);

impl rand_core::TryRng for CountingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let counter = self.0.to_le_bytes();
        for (index, byte) in dst.iter_mut().enumerate() {
            *byte = counter[index % 8] ^ (index as u8);
        }
        self.0 += 1;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for CountingRng {}

/// A case's request in the core's form.
struct Owned {
    id: String,
    kind: Kind,
    account: Value,
    payload: Value,
    page: Option<Page>,
}

impl Owned {
    fn request(&self) -> Request<'_> {
        Request {
            kind: self.kind,
            account: Some(&self.account),
            payload: &self.payload,
            page: self.page.as_ref(),
        }
    }

    /// The same request without its page.
    fn without_page(&self) -> Request<'_> {
        Request {
            page: None,
            ..self.request()
        }
    }
}

fn owned(case: &Value) -> Option<Owned> {
    let core = &case["core"];
    if core.is_null() {
        return None;
    }
    let payload = match core.get("payload_text") {
        // Parsed by the core from its own text, as `sign.*` parses its
        // parameters.
        Some(text) => fc_evm::parse_json(text.as_str().unwrap()).unwrap(),
        None => core["payload"].clone(),
    };
    let page = core["page"].as_object().map(|page| Page {
        origin: page["origin"].as_str().unwrap().to_owned(),
        frame: page["frame"].as_u64().unwrap(),
        navigation: page["navigation"].as_u64().unwrap(),
        handle: Handle::parse(page["handle"].as_str().unwrap()).unwrap(),
    });
    Some(Owned {
        id: case["id"].as_str().unwrap().to_owned(),
        kind: Kind::from_name(case["kind"].as_str().unwrap()).unwrap(),
        account: core["account"].clone(),
        payload,
        page,
    })
}

fn cases(vectors: &Value) -> HashMap<String, &Value> {
    vectors["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| (case["id"].as_str().unwrap().to_owned(), case))
        .collect()
}

fn issue(tokens: &mut Tokens, case: &Owned, now: u64, rng: &mut CountingRng) -> Issued {
    tokens
        .issue(&case.request(), now, rng)
        .unwrap_or_else(|e| panic!("{}: {e}", case.id))
}

fn spend(tokens: &mut Tokens, issued: &Issued, case: &Owned, now: u64) -> Result<Spent, Refusal> {
    tokens.spend(&issued.token.to_text(), &case.request(), now)
}

#[test]
fn the_designs_eleven_kinds() {
    let vectors = load();
    assert_eq!(vectors["constants"]["ttlMs"].as_u64(), Some(TOKEN_TTL_MS));
    assert_eq!(
        vectors["constants"]["maxOutstanding"].as_u64(),
        Some(MAX_OUTSTANDING as u64)
    );
    let mut taken = 0;
    for kind in vectors["kinds"].as_array().unwrap() {
        let name = kind["name"].as_str().unwrap();
        match Kind::from_name(name) {
            Some(core) => {
                assert_eq!(kind["design"], true, "{name}");
                let rule = match kind["page"].as_str().unwrap() {
                    "always" => PageRule::Required,
                    "with-site" => PageRule::Optional,
                    _ => PageRule::Forbidden,
                };
                assert_eq!(core.page_rule(), rule, "{name}");
                taken += 1;
            }
            None => assert_eq!(kind["design"], false, "{name}"),
        }
    }
    assert_eq!(taken, Kind::ALL.len());
}

/// Every kind binds the reference's facts: what it binds gets a token that
/// spends for exactly that request, but what the core's parse refuses
/// (`token-strict`); what it refuses gets none.
#[test]
fn each_case_issued_or_refused() {
    let vectors = load();
    let mut issued = 0;
    let mut refused = 0;
    for case in vectors["bindings"].as_array().unwrap() {
        let Some(owned) = owned(case) else {
            assert!(case.get("expect").is_none());
            continue;
        };
        let mut tokens = Tokens::new(LIMITS);
        let mut rng = CountingRng(0);
        let result = tokens.issue(&owned.request(), 1_000_000, &mut rng);
        match case["expect"].as_str().unwrap() {
            "issued" => {
                let minted = result.unwrap_or_else(|e| panic!("{}: {e}", owned.id));
                assert_eq!(
                    minted.typed_data.is_some(),
                    owned.kind == Kind::SignTypedData,
                    "{}",
                    owned.id
                );
                let spent = spend(&mut tokens, &minted, &owned, 1_000_000)
                    .unwrap_or_else(|e| panic!("{}: {e}", owned.id));
                assert_eq!(spent.kind, owned.kind);
                assert_eq!(spent.typed_data, minted.typed_data, "{}", owned.id);
                issued += 1;
            }
            "refused" => {
                assert!(result.is_err(), "{}: issued", owned.id);
                assert_eq!(tokens.outstanding(), 0);
                refused += 1;
            }
            other => panic!("{other}"),
        }
    }
    assert!(issued > 100 && refused > 50, "{issued} {refused}");
}

/// Payloads the reference tells apart get different tokens, but for
/// `token-typed-parse`'s and `token-message-bytes`' texts, which share one;
/// and payloads it binds alike share one, but where the core binds more
/// (`token-page`'s frame and navigation, `token-typed-parse`'s type order).
#[test]
fn pairs_alike_and_apart() {
    let vectors = load();
    let cases = cases(&vectors);
    for pair in vectors["pairs"].as_array().unwrap() {
        let a = owned(cases[pair["a"].as_str().unwrap()]).unwrap();
        let b = owned(cases[pair["b"].as_str().unwrap()]).unwrap();
        let label = format!("{} / {}", a.id, b.id);
        let core = pair["core"].as_str().unwrap();
        for (first, second) in [(&a, &b), (&b, &a)] {
            let mut tokens = Tokens::new(LIMITS);
            let mut rng = CountingRng(0);
            let minted = issue(&mut tokens, first, 1_000_000, &mut rng);
            let result = spend(&mut tokens, &minted, second, 1_000_000);
            match core {
                "alike" => {
                    let spent = result.unwrap_or_else(|e| panic!("{label}: {e}"));
                    // The same hash and the same view, byte for byte.
                    assert_eq!(spent.typed_data, minted.typed_data, "{label}");
                }
                "apart" => assert_eq!(result.unwrap_err(), Refusal::Mismatch, "{label}"),
                other => panic!("{other}"),
            }
            // Burnt either way.
            assert_eq!(tokens.outstanding(), 0, "{label}");
        }
        if cases[pair["b"].as_str().unwrap()]["sameHash"] == true {
            let hash = |case: &Owned| {
                let mut tokens = Tokens::new(LIMITS);
                issue(&mut tokens, case, 0, &mut CountingRng(0))
                    .typed_data
                    .unwrap()
                    .hash
            };
            assert_eq!(hash(&a), hash(&b), "{label}");
        }
    }
}

/// Typed data: two requests with the same EIP-712 hash that differ in an
/// ignored field get different tokens (above), for a top-level field, whose
/// views differ, and for a nested one, whose views don't.
#[test]
fn ignored_fields_top_level_and_nested() {
    let vectors = load();
    let cases = cases(&vectors);
    let typed = |id: &str| {
        let case = owned(cases[id]).unwrap();
        let mut tokens = Tokens::new(LIMITS);
        issue(&mut tokens, &case, 0, &mut CountingRng(0))
            .typed_data
            .unwrap()
    };
    let base = typed("sign-typed-data/base");
    let top = typed("sign-typed-data/ignored-top");
    let nested = typed("sign-typed-data/ignored-nested");
    assert_eq!(base.hash, top.hash);
    assert_eq!(base.hash, nested.hash);
    assert_ne!(base.view, top.view);
    assert!(top.view.contains(r#""ignored":["note"]"#), "{}", top.view);
    assert_eq!(base.view, nested.view);
}

/// One request in other texts (`token-typed-parse`): a token issued for any
/// of them spends for each other, with the same hash and view; the type
/// names in another order are another view, so another binding, as texts
/// and as objects.
#[test]
fn one_request_in_other_texts() {
    let vectors = load();
    let cases = cases(&vectors);
    let alike = [
        "sign-typed-data/text",
        "sign-typed-data/text-spacing",
        "sign-typed-data/text-key-order",
        "sign-typed-data/text-escapes",
        "sign-typed-data/object",
    ];
    let reordered = [
        "sign-typed-data/text-type-order",
        "sign-typed-data/object-type-order",
    ];
    let owned_of = |id: &str| owned(cases[id]).unwrap();
    // Each text is its own text in the vector, and each a request the
    // reference binds apart from the first.
    for id in alike.iter().chain(&reordered) {
        assert!(cases[*id]["js"]["facts"].is_object(), "{id}");
    }
    let first = {
        let mut tokens = Tokens::new(LIMITS);
        issue(&mut tokens, &owned_of(alike[0]), 0, &mut CountingRng(0))
            .typed_data
            .unwrap()
    };
    for one in alike {
        for other in alike {
            let mut tokens = Tokens::new(LIMITS);
            let (one, other) = (owned_of(one), owned_of(other));
            let minted = issue(&mut tokens, &one, 0, &mut CountingRng(0));
            let spent = spend(&mut tokens, &minted, &other, 0)
                .unwrap_or_else(|e| panic!("{} / {}: {e}", one.id, other.id));
            assert_eq!(spent.typed_data.as_ref(), Some(&first));
        }
    }
    for id in reordered {
        let reordered = owned_of(id);
        for one in alike {
            let one = owned_of(one);
            for (a, b) in [(&one, &reordered), (&reordered, &one)] {
                let mut tokens = Tokens::new(LIMITS);
                let minted = issue(&mut tokens, a, 0, &mut CountingRng(0));
                let typed = minted.typed_data.clone().unwrap();
                assert_eq!(typed.hash, first.hash);
                if a.id == reordered.id {
                    assert_ne!(typed.view, first.view);
                }
                assert_eq!(
                    spend(&mut tokens, &minted, b, 0).unwrap_err(),
                    Refusal::Mismatch,
                    "{} / {}",
                    a.id,
                    b.id
                );
            }
        }
    }
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Ok,
    NoToken,
    UnknownToken,
    Expired,
    Mismatch,
    Invalid,
}

/// The core's refusal for the reference's message.
fn expected(outcome: &Value) -> Outcome {
    let Some(message) = outcome.get("error") else {
        assert_eq!(outcome["ok"], true);
        return Outcome::Ok;
    };
    let reason = message
        .as_str()
        .unwrap()
        .strip_prefix("Signing was not confirmed: ")
        .unwrap();
    match reason {
        "no confirmation token" => Outcome::NoToken,
        "unknown or already used confirmation" => Outcome::UnknownToken,
        "confirmation expired" => Outcome::Expired,
        // Another request, kind, page or route: a page's token without its
        // page, a wallet's with one.
        "request differs from what was confirmed"
        | "not a page confirmation"
        | "a page confirmation is spent only by main" => Outcome::Mismatch,
        // The request doesn't parse for its kind.
        _ => Outcome::Invalid,
    }
}

fn actual(result: &Result<Spent, Refusal>) -> Outcome {
    match result {
        Ok(_) => Outcome::Ok,
        Err(Refusal::NoToken) => Outcome::NoToken,
        Err(Refusal::UnknownToken) => Outcome::UnknownToken,
        Err(Refusal::Expired) => Outcome::Expired,
        Err(Refusal::Mismatch) => Outcome::Mismatch,
        Err(Refusal::Invalid(_)) => Outcome::Invalid,
    }
}

/// Issue, consume, discard and count, in order: the two-minute life on the
/// injected clock (valid at 119,999 ms, expired at 120,000, and on the
/// vault's clock where a wall clock set back would extend it), the cap of 32
/// dropping the oldest, and a token burnt on a mismatch, an expiry, a wrong
/// kind and a malformed request.
#[test]
fn runs() {
    let vectors = load();
    let cases = cases(&vectors);
    for run in vectors["runs"].as_array().unwrap() {
        let id = run["id"].as_str().unwrap();
        let mut tokens = Tokens::new(LIMITS);
        let mut rng = CountingRng(0);
        let mut minted: HashMap<String, String> = HashMap::new();
        for (index, op) in run["ops"].as_array().unwrap().iter().enumerate() {
            let label = format!("{id}, step {index}");
            let now = op
                .get("vaultAt")
                .or_else(|| op.get("at"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let case = op
                .get("case")
                .map(|case| owned(cases[case.as_str().unwrap()]).unwrap());
            match op["op"].as_str().unwrap() {
                "issue" => {
                    assert_eq!(op["outcome"]["ok"], true);
                    let issued = issue(&mut tokens, case.as_ref().unwrap(), now, &mut rng);
                    assert_eq!(issued.expires_at_ms, now + TOKEN_TTL_MS);
                    minted.insert(
                        op["token"].as_str().unwrap().to_owned(),
                        issued.token.to_text().to_string(),
                    );
                }
                "consume" => {
                    let token = match op.get("literal") {
                        Some(literal) => literal.as_str().unwrap().to_owned(),
                        None => minted[op["token"].as_str().unwrap()].clone(),
                    };
                    let case = case.as_ref().unwrap();
                    let request = match op.get("route").and_then(Value::as_str) {
                        Some("wallet") => case.without_page(),
                        _ => case.request(),
                    };
                    let result = tokens.spend(&token, &request, now);
                    let want = expected(op.get("core").unwrap_or(&op["outcome"]));
                    assert_eq!(actual(&result), want, "{label}: {result:?}");
                }
                "discard" => tokens.discard(&minted[op["token"].as_str().unwrap()]),
                "count" => assert_eq!(
                    Some(tokens.outstanding() as u64),
                    op["outcome"]["count"].as_u64(),
                    "{label}"
                ),
                other => panic!("{other}"),
            }
        }
    }
}
