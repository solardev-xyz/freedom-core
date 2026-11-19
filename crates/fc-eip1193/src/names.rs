//! Names over IPNS (design 0011, "Names over IPNS" and "Which methods check
//! the name"; design 0012, APR-5f).
//!
//! A DNS name with an ENS contenthash (`docs.example.org`) loads as
//! `ipns://<key>`. Main binds the document's key to the name once the name
//! answers that key, and sends both: `PageContext.origin` is the name and
//! `PageContext.transport_key` is `ipns://<key>`. A name can move to other
//! content at any time, so a name-revalidated method resolves the name
//! again, with the core's own naming, before it first uses anything held
//! under it and after each of its later waits, and compares the answer with
//! the IPNS key, as the reference's `recheckName` and `nameServesIpnsKey`
//! do (`page-documents.js`). The daemon runs the resolution; this module
//! decides what is checked and what the answer means.
//!
//! - **No binding** when `transport_key` is absent (a page as before
//!   APR-5f) or equal to the key: nothing is resolved.
//! - **A transport key that isn't `ipns://<letters and digits>`** fails
//!   every check, with nothing resolved, as the reference's does.
//! - **A name that no longer answers** the key, a resolution that fails
//!   included, ends the binding ([`Ended`]): the request answers as a
//!   keyless document's would ([`keyless`]), and so does every later
//!   name-revalidated request of that document, with nothing resolved. A
//!   new document (a new commit, so a new `navigation`) binds again.

use std::collections::{BTreeSet, VecDeque};

use fc_json::JsValue;

use crate::Answer;
use crate::connect::NO_ADDRESS;

/// A document's name binding: its key is a DNS name served over IPNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    name: String,
    /// The `<key>` of `ipns://<key>`; `None` when the transport key isn't
    /// of that form, so every check fails, with nothing resolved.
    ipns_key: Option<String>,
}

impl Binding {
    /// The binding of a document keyed `origin` whose transport key is
    /// `transport_key`, or `None` when there is nothing to resolve: no
    /// transport key, no key, or the key is the transport key itself
    /// (`doc.key === doc.transportKey`).
    pub fn of(origin: &str, transport_key: Option<&str>) -> Option<Binding> {
        let transport = transport_key?;
        if origin.is_empty() || origin == transport {
            return None;
        }
        // `/^ipns:\/\/([A-Za-z0-9]+)$/`.
        let ipns_key = transport
            .strip_prefix("ipns://")
            .filter(|key| !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric()))
            .map(str::to_owned);
        Some(Binding {
            name: origin.to_owned(),
            ipns_key,
        })
    }

    /// The name the core resolves.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// False when a check fails with nothing resolved: the transport key
    /// isn't `ipns://<key>`.
    pub fn resolvable(&self) -> bool {
        self.ipns_key.is_some()
    }

    /// `nameServesIpnsKey`: whether naming's content result for the name
    /// (`resolveEnsContent`'s, `None` for one that threw) answers exactly
    /// the IPNS key, as the resolver's base58 multihash or the base36
    /// `libp2p-key` CID.
    pub fn served_by(&self, result: Option<&JsValue>) -> bool {
        let (Some(key), Some(result)) = (self.ipns_key.as_deref(), result) else {
            return false;
        };
        let text = |field: &str| result.get(field).and_then(JsValue::as_str);
        if text("type") != Some("ok") || text("protocol") != Some("ipns") {
            return false;
        }
        let Some(decoded) = text("decoded").filter(|decoded| !decoded.is_empty()) else {
            return false;
        };
        key == decoded || fc_dweb::ipns_mh_to_cid_v1_base36(decoded).as_deref() == Some(key)
    }
}

/// What a name-revalidated method answers once its document no longer
/// holds the name, as a keyless document's: `eth_accounts` `[]`, every
/// other method `4100`.
pub fn keyless(method: &str) -> Answer {
    if method == "eth_accounts" {
        Answer::raw(r#"{"result":[]}"#)
    } else {
        Answer::error(NO_ADDRESS.0, NO_ADDRESS.1)
    }
}

/// The reference's checks before a method first reads the key's grant:
/// one for `eth_accounts`; two for a connect and a signature, before and
/// after the agent's route (main's, until APR-7). `None` for every other
/// method: a chain switch checks once its params pass, a send once its
/// form passes ([`SEND_FIRST`]), and a permission-free method never.
pub fn checks_first(method: &str) -> Option<u8> {
    match method {
        "eth_accounts" => Some(1),
        "eth_requestAccounts" | "personal_sign" | "eth_signTypedData_v4" => Some(2),
        _ => None,
    }
}

/// The reference's checks before a send (`eth_sendTransaction`) first
/// reads the key's grant (APR-5f-2): two, before and after the agent's
/// route, once its form (`txOf`) has passed, so that a malformed send is
/// refused with nothing resolved. Its later checks: once more before its
/// quote (after the rule's choice), before the prompt of a rule's send
/// whose fee needs the user, after an approve before the grant is read
/// again and the token minted, and after main's recheck of a rule's send.
pub const SEND_FIRST: u8 = 2;

/// Whether `eth_accounts`'s answer reveals an account, so that the
/// reference checks the name once more before it goes.
pub fn reveals_account(answer: &Answer) -> bool {
    let text = answer.as_str();
    text.starts_with(r#"{"result":["#) && text != r#"{"result":[]}"#
}

/// One document, as its `PageContext` names it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Document {
    origin: String,
    transport_key: String,
    frame: u64,
    navigation: u64,
}

impl Document {
    pub fn new(origin: &str, transport_key: &str, frame: u64, navigation: u64) -> Document {
        Document {
            origin: origin.to_owned(),
            transport_key: transport_key.to_owned(),
            frame,
            navigation,
        }
    }
}

/// The most ended bindings kept (*inferred*): the oldest is dropped. A
/// dropped document's later requests resolve its name again.
pub const MAX_ENDED: usize = 4096;

/// The documents whose binding has ended (`endNameBinding`), the most
/// recent [`MAX_ENDED`].
#[derive(Debug, Default)]
pub struct Ended {
    order: VecDeque<Document>,
    set: BTreeSet<Document>,
}

impl Ended {
    pub fn new() -> Ended {
        Ended::default()
    }

    /// `document`'s binding ends.
    pub fn end(&mut self, document: &Document) {
        if !self.set.insert(document.clone()) {
            return;
        }
        self.order.push_back(document.clone());
        while self.order.len() > MAX_ENDED {
            if let Some(oldest) = self.order.pop_front() {
                self.set.remove(&oldest);
            }
        }
    }

    /// Whether `document`'s binding has ended.
    pub fn has(&self, document: &Document) -> bool {
        self.set.contains(document)
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8";

    fn content(kind: &str, protocol: &str, decoded: &str) -> JsValue {
        fc_json::parse(
            &serde_json::json!({ "type": kind, "protocol": protocol, "decoded": decoded })
                .to_string(),
        )
        .unwrap()
    }

    #[test]
    fn a_binding_needs_a_key_other_than_its_transport_key() {
        let ipns = format!("ipns://{KEY}");
        assert_eq!(Binding::of("docs.example.org", None), None);
        assert_eq!(Binding::of("", Some(&ipns)), None);
        assert_eq!(Binding::of(&ipns, Some(&ipns)), None);
        let bound = Binding::of("docs.example.org", Some(&ipns)).unwrap();
        assert_eq!(bound.name(), "docs.example.org");
        assert!(bound.resolvable());
        for odd in [
            "ipns://",
            "ipns://k51/x",
            "ipns://k51\n",
            "IPNS://k51",
            "https://docs.example.org",
            "ipns://k5-1",
        ] {
            let bound = Binding::of("docs.example.org", Some(odd)).unwrap();
            assert!(!bound.resolvable(), "{odd:?}");
            assert!(
                !bound.served_by(Some(&content("ok", "ipns", KEY))),
                "{odd:?}"
            );
        }
    }

    #[test]
    fn served_only_by_the_same_ipns_key() {
        let bound = Binding::of("docs.example.org", Some(&format!("ipns://{KEY}"))).unwrap();
        // The resolver's base58 form, and the base36 CID itself.
        let base58 = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";
        let base36 = fc_dweb::ipns_mh_to_cid_v1_base36(base58).unwrap();
        let other = Binding::of("docs.example.org", Some(&format!("ipns://{base36}"))).unwrap();
        assert!(other.served_by(Some(&content("ok", "ipns", base58))));
        assert!(other.served_by(Some(&content("ok", "ipns", &base36))));
        assert!(!bound.served_by(Some(&content("ok", "ipns", base58))));
        assert!(bound.served_by(Some(&content("ok", "ipns", KEY))));
        assert!(!bound.served_by(Some(&content("ok", "ipfs", KEY))));
        assert!(!bound.served_by(Some(&content("not_found", "ipns", KEY))));
        assert!(!bound.served_by(Some(&content("ok", "ipns", ""))));
        assert!(!bound.served_by(Some(&content("ok", "ipns", &KEY.to_uppercase()))));
        assert!(!bound.served_by(Some(&JsValue::Null)));
        assert!(!bound.served_by(None));
    }

    #[test]
    fn the_keyless_answers() {
        assert_eq!(keyless("eth_accounts").as_str(), r#"{"result":[]}"#);
        for method in [
            "eth_requestAccounts",
            "wallet_switchEthereumChain",
            "personal_sign",
            "eth_signTypedData_v4",
            "eth_sendTransaction",
        ] {
            assert_eq!(
                keyless(method).as_str(),
                r#"{"error":{"code":4100,"message":"This page has no address to connect from yet"}}"#
            );
        }
        assert!(!reveals_account(&keyless("eth_accounts")));
        assert!(reveals_account(&Answer::raw(r#"{"result":["0xa"]}"#)));
        assert!(reveals_account(&Answer::raw(r#"{"result":[null]}"#)));
        assert!(!reveals_account(&keyless("personal_sign")));
    }

    #[test]
    fn checks_first_follow_the_reference() {
        assert_eq!(checks_first("eth_accounts"), Some(1));
        assert_eq!(checks_first("eth_requestAccounts"), Some(2));
        assert_eq!(checks_first("personal_sign"), Some(2));
        assert_eq!(checks_first("eth_signTypedData_v4"), Some(2));
        for method in [
            "wallet_switchEthereumChain",
            "eth_chainId",
            "eth_call",
            "eth_sign",
        ] {
            assert_eq!(checks_first(method), None, "{method}");
        }
        // Every name-revalidated row but the switch and the send checks
        // first; no permission-free row does. The send checks first once
        // its form has passed.
        assert_eq!(SEND_FIRST, 2);
        for row in crate::METHODS {
            let first = checks_first(row.name).is_some();
            match row.class {
                crate::Class::NameRevalidated => assert_eq!(
                    first,
                    !["wallet_switchEthereumChain", "eth_sendTransaction"].contains(&row.name),
                    "{}",
                    row.name
                ),
                _ => assert!(!first, "{}", row.name),
            }
        }
    }

    #[test]
    fn what_is_kept_stays_bounded() {
        let mut ended = Ended::new();
        let doc = |n: u64| Document::new("docs.example.org", "ipns://k51", 1, n);
        ended.end(&doc(0));
        ended.end(&doc(0));
        assert_eq!(ended.len(), 1);
        for n in 1..=MAX_ENDED as u64 {
            ended.end(&doc(n));
        }
        assert_eq!(ended.len(), MAX_ENDED);
        assert!(!ended.has(&doc(0)), "the oldest is dropped");
        assert!(ended.has(&doc(1)) && ended.has(&doc(MAX_ENDED as u64)));
        // Another frame, key or transport key is another document.
        assert!(!ended.has(&Document::new("docs.example.org", "ipns://k51", 2, 1)));
        assert!(!ended.has(&Document::new("other.example", "ipns://k51", 1, 1)));
        assert!(!ended.has(&Document::new("docs.example.org", "ipns://k52", 1, 1)));
    }
}
