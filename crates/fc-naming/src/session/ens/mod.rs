//! The ENS machine (design 0004, The ENS machine): the anchor, quorum legs
//! and waves, the method order and the record drivers, as `ens-resolver.js`
//! runs them. Each async function here mirrors the reference function it
//! names.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

use super::exec::{Either, Ms, Rt, race};
use super::js;
use super::pool::{Endpoint, Pool};
use super::random::Random;
use super::rpc::{self, BlockRef, Method, RpcError, Transport};
use crate::abi::{Kind, Value};
use crate::jsjson::JsValue;
use crate::ur::{self, NameSystem};

mod anchor;
mod leg;
mod quorum;
mod records;
mod verified;

pub(crate) use anchor::*;
pub(crate) use leg::*;
pub(crate) use quorum::*;
pub(crate) use records::*;
pub(crate) use verified::*;

/// What the machine asks main to do.
#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    /// One ethers `FetchRequest.send()` of `body`, run by main.
    Rpc {
        endpoint: Endpoint,
        body: String,
    },
    Gateway {
        url: String,
        body: Option<String>,
    },
    Prefetch {
        uri: String,
    },
    /// A whole verifier operation through main's adapter (design 0004,
    /// Verified operations).
    Verified(VerifiedOp),
    /// GET (or POST with `body`) of `endpoint`'s URL + `path`.
    Tezos {
        endpoint: Endpoint,
        post: bool,
        path: String,
        body: Option<String>,
    },
}

/// A verifier operation.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifiedOp {
    /// `resolveMyotisEnsRecord({ method, name, addressHex, coinType })`.
    MyotisRecord {
        method: &'static str,
        name: Option<String>,
        address: Option<String>,
        coin_type: u64,
    },
    /// `myotisManager.ethCall` at `latest`, then the optimistic block.
    MyotisCall { to: [u8; 20], data: Vec<u8> },
    /// `resolveCallViaColibri(name, callData, callResolver)`.
    ColibriResolve {
        name: String,
        call_data: Vec<u8>,
        resolver: &'static str,
    },
    /// `resolveReverseViaColibri(address, coinType)`.
    ColibriReverse { address: String, coin_type: u64 },
}

/// A verifier operation's outcome, without text.
#[derive(Debug, Clone, PartialEq)]
pub enum Verified {
    Result(JsValue),
    Revert(Vec<u8>),
    Failure(String),
}

/// Main's answers.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    /// The exchange's final HTTP answer (main ran its redirects and
    /// 429 back-off).
    Rpc {
        status: u16,
        body: Vec<u8>,
    },
    Gateway {
        status: u16,
        body: Vec<u8>,
    },
    Failed(Transport),
    Verified(Verified),
    Tezos {
        status: u16,
        body: Vec<u8>,
    },
    Done,
}

/// The configuration snapshot (design 0004, Configuration).
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub rpc: Vec<Endpoint>,
    pub direct: Option<Direct>,
    pub order: Vec<String>,
    pub prefer_verified: bool,
    /// `network.quorum`, raw: the reference coerces it where it reads it.
    pub quorum: JsValue,
    pub myotis_enabled: bool,
    /// The Colibri prover, and whether proofs are zk.
    pub prover: Option<(Endpoint, bool)>,
    /// Tezos RPC endpoints, in order.
    pub tezos: Vec<Endpoint>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Direct {
    pub endpoint: Endpoint,
    pub user_configured: bool,
}

/// A thrown resolution, with today's message.
#[derive(Debug, Clone, PartialEq)]
pub struct Thrown {
    pub message: String,
    /// `MYOTIS_LIFECYCLE_CHANGED`: rethrown by the method order.
    pub lifecycle: bool,
}

impl Thrown {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            lifecycle: false,
        }
    }

    fn lifecycle(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            lifecycle: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Anchor {
    tag: String,
    number: i64,
    hash: String,
    expires: f64,
}

/// A cache in JavaScript `Map` order: an update keeps its key's place.
#[derive(Debug, Default)]
pub(crate) struct Cache {
    entries: Vec<(String, JsValue, f64)>,
}

pub(crate) const MAX_CACHE_ENTRIES: usize = 500;

impl Cache {
    pub(crate) fn get(&self, key: &str, now: Ms) -> Option<&JsValue> {
        #[allow(clippy::cast_precision_loss)]
        let now = now as f64;
        self.entries
            .iter()
            .find(|(k, _, expires)| k == key && now < *expires)
            .map(|(_, v, _)| v)
    }

    pub(crate) fn set(&mut self, key: &str, value: JsValue, expires: f64, now: Ms) {
        match self.entries.iter_mut().find(|(k, _, _)| k == key) {
            Some(entry) => {
                entry.1 = value;
                entry.2 = expires;
            }
            None => self.entries.push((key.to_owned(), value, expires)),
        }
        // `capCache`: expired entries first, then the oldest.
        if self.entries.len() > MAX_CACHE_ENTRIES {
            #[allow(clippy::cast_precision_loss)]
            let now = now as f64;
            let mut i = 0;
            while self.entries.len() > MAX_CACHE_ENTRIES && i < self.entries.len() {
                if self.entries[i].2 <= now {
                    self.entries.remove(i);
                } else {
                    i += 1;
                }
            }
            while self.entries.len() > MAX_CACHE_ENTRIES {
                self.entries.remove(0);
            }
        }
    }

    pub(crate) fn delete(&mut self, key: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|(k, _, _)| k != key);
        before != self.entries.len()
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }
}

pub(crate) struct State {
    pub config: Config,
    pub pool: Pool,
    pub anchor: Option<Anchor>,
    pub content: Cache,
    pub address: Cache,
    pub reverse: Cache,
    pub lifecycle: u64,
    pub myotis_ready: bool,
    pub myotis_epoch: u64,
}

/// Everything a session's futures share.
pub struct Ctx {
    pub(crate) rt: Rt<Request, Answer>,
    pub(crate) state: RefCell<State>,
    pub(crate) random: RefCell<Box<dyn Random>>,
    /// The Tezos machine's caches.
    pub(crate) tezos: super::tezos::TezosState,
    /// Wall-clock milliseconds at monotonic zero (Tezos expiry reads the
    /// wall clock).
    pub(crate) wall_offset: std::cell::Cell<f64>,
}

impl Ctx {
    pub fn new(now: Ms, config: Config, random: Box<dyn Random>) -> Self {
        Self {
            rt: Rt::new(now),
            state: RefCell::new(State {
                config,
                pool: Pool::default(),
                anchor: None,
                content: Cache::default(),
                address: Cache::default(),
                reverse: Cache::default(),
                myotis_ready: false,
                myotis_epoch: 1,
                lifecycle: 0,
            }),
            random: RefCell::new(random),
            tezos: super::tezos::TezosState::default(),
            wall_offset: std::cell::Cell::new(0.0),
        }
    }

    pub(crate) fn now(&self) -> Ms {
        self.rt.now()
    }

    /// `Date.now()`.
    pub(crate) fn wall_now(&self) -> f64 {
        self.now_f() + self.wall_offset.get()
    }

    #[allow(clippy::cast_precision_loss)]
    pub(crate) fn now_f(&self) -> f64 {
        self.rt.now() as f64
    }

    fn quorum(&self, key: &str) -> Option<JsValue> {
        self.state.borrow().config.quorum.get(key).cloned()
    }

    /// `getAvailableProviders()`.
    fn available(&self) -> Vec<Endpoint> {
        let now = self.now();
        let mut state = self.state.borrow_mut();
        let effective = state.config.rpc.clone();
        let mut random = self.random.borrow_mut();
        state.pool.available(&effective, random.as_mut(), now)
    }

    fn mark_failure(&self, endpoint: &str) {
        let now = self.now();
        self.state.borrow_mut().pool.mark_failure(endpoint, now);
    }

    fn mark_success(&self, endpoint: &str) {
        self.state.borrow_mut().pool.mark_success(endpoint);
    }

    fn timeout_ms(&self) -> f64 {
        js::or(js::to_number(self.quorum("timeoutMs").as_ref()), 5000.0)
    }

    fn anchor_tag(&self) -> String {
        match self.quorum("anchor") {
            Some(value) if value.truthy() => value.js_string().unwrap_or_else(|_| "latest".into()),
            _ => "latest".into(),
        }
    }
}

/// An ethers `JsonRpcProvider` made for one probe or leg: its own request
/// ids, from 1.
pub(crate) struct Provider {
    endpoint: Endpoint,
    next_id: u64,
}

impl Provider {
    fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_owned(),
            next_id: 1,
        }
    }

    /// One request: one exchange with ethers' `FetchRequest` policy, run
    /// by main (design 0004, Transport). Its back-off draws from main's own
    /// random stream (deviation `random-streams`).
    async fn send(&mut self, ctx: &Ctx, method: &Method) -> Result<JsValue, RpcError> {
        let id = self.next_id;
        self.next_id += 1;
        let request = Request::Rpc {
            endpoint: self.endpoint.clone(),
            body: rpc::body(id, method),
        };
        match ctx.rt.request(request).await {
            Answer::Rpc { status, body } => rpc::answer(id, method, status, &body),
            Answer::Failed(transport) => Err(RpcError::Transport(transport)),
            _ => Err(RpcError::Transport(Transport::Network)),
        }
    }
}

/// `withTimeout(promise, ms)`: `Err(())` when the deadline wins.
pub(crate) async fn with_timeout<T>(
    ctx: &Ctx,
    ms: f64,
    future: impl Future<Output = T>,
) -> Result<T, ()> {
    match race(future, ctx.rt.sleep(js::delay_ms(ms))).await {
        Either::Left(value) => Ok(value),
        Either::Right(()) => Err(()),
    }
}

pub(crate) fn s(text: &str) -> JsValue {
    JsValue::String(text.into())
}

pub(crate) fn refs(endpoints: &[Endpoint]) -> JsValue {
    JsValue::Array(
        endpoints
            .iter()
            .map(|e| JsValue::Object(vec![("ref".into(), s(e))]))
            .collect(),
    )
}

#[allow(clippy::cast_precision_loss)]
pub(crate) fn number(n: i64) -> JsValue {
    JsValue::Number(n as f64)
}

pub(crate) fn obj(fields: Vec<(&str, JsValue)>) -> JsValue {
    JsValue::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

/// TTLs by trust level (`ttlForResult`).
pub(crate) fn ttl_for(result: &JsValue) -> f64 {
    if result.get("reason") == Some(&s("UNVERIFIED")) {
        return 60_000.0;
    }
    match result
        .get("trust")
        .and_then(|t| t.get("level"))
        .and_then(JsValue::as_str)
    {
        Some("verified" | "user-configured") => 900_000.0,
        Some("unverified") => 60_000.0,
        Some("conflict") => 10_000.0,
        _ => 900_000.0,
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Store {
    Content,
    Address,
    Reverse,
}

/// `cacheAndLog`.
pub(crate) fn cache(ctx: &Ctx, store: Store, key: &str, result: JsValue) -> JsValue {
    let expires = ctx.now_f() + ttl_for(&result);
    let now = ctx.now();
    let mut state = ctx.state.borrow_mut();
    let cache = match store {
        Store::Content => &mut state.content,
        Store::Address => &mut state.address,
        Store::Reverse => &mut state.reverse,
    };
    cache.set(key, result.clone(), expires, now);
    result
}

/// `chainCacheKey`.
pub(crate) fn chain_key(name: &str, chain_id: u64) -> String {
    if chain_id == 1 {
        name.to_owned()
    } else {
        format!("{chain_id}:{name}")
    }
}

/// `prefetchOnFirstData`: the URI a first answer would prefetch.
pub(crate) fn prefetch_uri(resolved: &[u8]) -> Option<String> {
    let inner = match crate::abi::decode(&[Kind::Bytes], resolved)
        .ok()?
        .into_iter()
        .next()?
    {
        Ok(Value::Bytes(bytes)) => bytes,
        _ => return None,
    };
    if inner.is_empty() {
        return None;
    }
    crate::parse_contenthash(&inner).map(|c| c.uri())
}

/// `fastNormalize`: lowercase ASCII hosts pass; anything else goes
/// through ENSIP-15.
pub(crate) fn fast_normalize(trimmed: &str) -> Result<String, Thrown> {
    let lowered = trimmed.to_lowercase();
    if !lowered.is_empty()
        && lowered
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Ok(lowered);
    }
    crate::normalize_ens(trimmed).map_err(|e| Thrown::new(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_keep_map_order_and_evict_expired_first() {
        let mut cache = Cache::default();
        cache.set("a", JsValue::Null, 10.0, 0);
        cache.set("b", JsValue::Null, 100.0, 0);
        cache.set("a", JsValue::Bool(true), 100.0, 0);
        assert_eq!(
            cache
                .entries
                .iter()
                .map(|(k, _, _)| k.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert!(cache.get("a", 99).is_some());
        assert!(cache.get("a", 100).is_none());
    }

    #[test]
    fn checksums_are_eip55() {
        let address: [u8; 20] = [0xab; 20];
        assert_eq!(
            checksum(&address),
            "0xABaBaBaBABabABabAbAbABAbABabababaBaBABaB"
        );
    }
}
