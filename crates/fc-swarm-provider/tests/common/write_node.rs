//! The fake node of the feed and SOC writes (design 0015, SWM-3 part 3c):
//! the generator's answers over a case's declarative `node` (rules first,
//! with the world change a rule makes as its request arrives; then the
//! probes, the stored chunks and feeds, and the uploads stored as a node
//! stores them). `feed_writes_vectors.rs` plays the machines against it,
//! and freedom-cored's pipe tests play main with it (SWM-4 PR 7).

#![allow(dead_code, unreachable_pub, clippy::unwrap_used, clippy::panic)]

use fc_json::index::{Kind, Value as V};
use fc_swarm::verify;
use fc_swarm_provider::machine::NodeCall;

use super::*;

// ---------------------------------------------------------------------------
// The node: the generator's answers over a case's declarative `node`.

pub struct WriteRule {
    pub method: Option<String>,
    pub path: Option<String>,
    pub prefix: Option<String>,
    pub reply: ReplySpec,
    pub world: Option<(String, String)>,
}

pub struct Probe {
    pub owner: [u8; 20],
    pub topic: [u8; 32],
    pub head: Option<u64>,
}

/// A change to the world as a request reaches the node (a rule's `world`).
#[derive(Debug, Clone, PartialEq)]
pub enum WorldChange {
    Custody,
    RuleOff(String),
    NameMoved,
}

pub struct WriteNode {
    pub base: Node,
    pub rules: Vec<WriteRule>,
    pub stamps: Option<String>,
    pub probes: Vec<Probe>,
    pub probe_fail: Option<(u64, u16)>,
    pub soc_posts: usize,
    pub bzz_tag: u64,
}

impl WriteNode {
    pub fn new() -> WriteNode {
        WriteNode {
            base: Node::new(),
            rules: Vec::new(),
            stamps: None,
            probes: Vec::new(),
            probe_fail: None,
            soc_posts: 0,
            bzz_tag: 1,
        }
    }

    pub fn of(case: V<'_, '_>, keys: &Keys) -> WriteNode {
        let mut node = WriteNode::new();
        for (k, v) in get(case, "node").members() {
            match string(k).as_str() {
                "stamps" => node.stamps = Some(v.stringify(fc_json::index::KeyOrder::Property)),
                "data" => {
                    for d in v.children() {
                        let bytes = data_of(d);
                        let root = tree_of(&bytes, &mut node.base.chunks);
                        node.base.blobs.insert(hex(&root.address()), bytes);
                    }
                }
                "chunks" => {
                    for c in v.children() {
                        node.base
                            .chunks
                            .insert(string(get(c, "address")), data_of(c));
                    }
                }
                "entries" => {
                    for e in v.children() {
                        let key = keys.of(&string(get(e, "key")));
                        let topic = fc_swarm::feed::topic(&string(get(e, "topic")));
                        let id = verify::feed_update_id(&topic, number(get(e, "index")) as u64);
                        let bytes = data_of(get(e, "data"));
                        let (span, payload) =
                            if e.get("wrap").is_some_and(|w| w.kind() == Kind::True) {
                                let root = tree_of(&bytes, &mut node.base.chunks);
                                node.base.blobs.insert(hex(&root.address()), bytes);
                                (root.span(), root.payload().to_vec())
                            } else {
                                (bytes.len() as u64, bytes)
                            };
                        let signed = fc_swarm::sign_soc(key, &id, Some(span), &payload).unwrap();
                        let wire = fc_swarm::soc::body(&id, &signed, &payload).unwrap();
                        node.base.chunks.insert(hex(&signed.soc_address), wire);
                    }
                }
                "latest" => {
                    for l in v.children() {
                        let owner = hex(&fc_evm::address_of(keys.of(&string(get(l, "key")))));
                        let topic = hex(&fc_swarm::feed::topic(&string(get(l, "topic"))));
                        node.base
                            .feeds
                            .insert((owner, topic), ReplySpec::of(get(l, "reply")));
                    }
                }
                "probes" => {
                    for p in v.children() {
                        // Without `head`, the probe table names indexes
                        // only (no update answers from it).
                        let Some(head) = p.get("head") else {
                            continue;
                        };
                        node.probes.push(Probe {
                            owner: fc_evm::address_of(keys.of(&string(get(p, "key")))),
                            topic: fc_swarm::feed::topic(&string(get(p, "topic"))),
                            head: (head.kind() != Kind::Null).then(|| number(head) as u64),
                        });
                    }
                }
                "probeFail" => {
                    node.probe_fail = Some((
                        number(get(v, "index")) as u64,
                        number(get(v, "status")) as u16,
                    ))
                }
                "rules" => {
                    for r in v.children() {
                        assert!(r.get("times").is_none());
                        let m = get(r, "match");
                        let world = r.get("world").map(|w| {
                            let (k, v) = w.members().next().unwrap();
                            let v = match v.kind() {
                                Kind::True => "true".to_owned(),
                                _ => string(v),
                            };
                            (string(k), v)
                        });
                        node.rules.push(WriteRule {
                            method: m.get("method").map(string),
                            path: m.get("path").map(string),
                            prefix: m.get("prefix").map(string),
                            reply: ReplySpec::of(get(r, "reply")),
                            world,
                        });
                    }
                }
                other => panic!("node spec {other:?}"),
            }
        }
        node
    }

    /// The node's reply to `call` (with its request body), and the world
    /// change its rule makes.
    pub fn reply(&mut self, call: &NodeCall, body: &[u8]) -> (ReplySpec, Option<WorldChange>) {
        let method = call.method();
        let path = call.path.as_str();
        if let Some(rule) = self.rules.iter().find(|r| {
            r.method.as_deref().is_none_or(|m| m == method)
                && r.path.as_deref().is_none_or(|p| p == path)
                && r.prefix.as_deref().is_none_or(|p| path.starts_with(p))
        }) {
            let change = rule.world.as_ref().map(|(k, v)| match k.as_str() {
                "custody" => {
                    assert_eq!(v, "true");
                    WorldChange::Custody
                }
                "rule_off" => WorldChange::RuleOff(v.clone()),
                "name" => WorldChange::NameMoved,
                other => panic!("a rule's world {other}"),
            });
            if path.starts_with("/soc/") {
                self.soc_posts += 1;
            }
            return (rule.reply.clone(), change);
        }
        if let (Some(feed), Some(address)) = (call.feed, path.strip_prefix("/chunks/")) {
            for probe in &self.probes {
                let at = hex(&verify::feed_update_address(
                    &probe.owner,
                    &probe.topic,
                    feed.index,
                ));
                if feed.owner != probe.owner || at != address {
                    continue;
                }
                if let Some((index, status)) = self.probe_fail
                    && index == feed.index
                {
                    let body = format!(r#"{{"code":{status},"message":"read chunk failed"}}"#);
                    return (
                        ReplySpec {
                            status,
                            status_text: reason_phrase(status).to_owned(),
                            headers: vec![(
                                "content-type".to_owned(),
                                "application/json; charset=utf-8".to_owned(),
                            )],
                            body: body.into_bytes(),
                            ..ReplySpec::ok(Vec::new(), "")
                        },
                        None,
                    );
                }
                if probe.head.is_some_and(|head| feed.index <= head) {
                    return (ReplySpec::ok(vec![0; 105], "binary/octet-stream"), None);
                }
            }
        }
        let created = |reference: String, tag: Option<u64>| {
            let mut spec = ReplySpec::ok(
                format!(r#"{{"reference":"{reference}"}}"#).into_bytes(),
                "application/json; charset=utf-8",
            );
            spec.status = 201;
            spec.status_text = "Created".to_owned();
            if let Some(tag) = tag {
                spec.headers.push(("swarm-tag".to_owned(), tag.to_string()));
            }
            spec
        };
        match (method, path) {
            ("GET", "/stamps") => {
                let json = self
                    .stamps
                    .clone()
                    .unwrap_or_else(|| r#"{"stamps":[]}"#.to_owned());
                (
                    ReplySpec::ok(json.into_bytes(), "application/json; charset=utf-8"),
                    None,
                )
            }
            ("POST", p) if p.starts_with("/soc/") => {
                self.soc_posts += 1;
                let mut parts = p["/soc/".len()..].split('/');
                let owner: [u8; 20] = unhex(parts.next().unwrap()).try_into().unwrap();
                let id: [u8; 32] = unhex(parts.next().unwrap()).try_into().unwrap();
                let sig = unhex(&call.query[0].1);
                let address = verify::soc_address(&id, &owner);
                let mut wire = id.to_vec();
                wire.extend_from_slice(&sig);
                wire.extend_from_slice(body);
                self.base.chunks.insert(hex(&address), wire);
                (created(hex(&address), None), None)
            }
            ("POST", "/bytes") => {
                let root = tree_of(body, &mut self.base.chunks);
                self.base.blobs.insert(hex(&root.address()), body.to_vec());
                self.bzz_tag += 1;
                (created(hex(&root.address()), Some(self.bzz_tag)), None)
            }
            ("POST", p) if p.starts_with("/feeds/") => (
                created(sha(format!("feed manifest {p}").as_bytes()), None),
                None,
            ),
            ("GET", _) => (self.base.reply(method, path), None),
            _ => panic!("the fake node has no answer for {method} {path}"),
        }
    }
}
