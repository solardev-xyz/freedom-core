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
}

/// Main's answers.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    /// The final HTTP answer, and how many random values main's
    /// `FetchRequest` drew for 429 back-off.
    Rpc {
        status: u16,
        body: Vec<u8>,
        draws: u32,
    },
    Gateway {
        status: u16,
        body: Vec<u8>,
    },
    Failed(Transport),
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
}

impl Thrown {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
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

const MAX_CACHE_ENTRIES: usize = 500;

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
}

/// Everything a session's futures share.
pub struct Ctx {
    pub(crate) rt: Rt<Request, Answer>,
    pub(crate) state: RefCell<State>,
    pub(crate) random: RefCell<Box<dyn Random>>,
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
                lifecycle: 0,
            }),
            random: RefCell::new(random),
        }
    }

    fn now(&self) -> Ms {
        self.rt.now()
    }

    #[allow(clippy::cast_precision_loss)]
    fn now_f(&self) -> f64 {
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

// ---------------------------------------------------------------------------
// One JSON-RPC exchange on an ephemeral provider.

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

    /// One request: one `FetchRequest.send()` in main (design 0004,
    /// Transport). Its 429 back-off drew from the shared random stream in
    /// the reference, so the core advances its own stream by as many.
    async fn send(&mut self, ctx: &Ctx, method: &Method) -> Result<JsValue, RpcError> {
        let id = self.next_id;
        self.next_id += 1;
        let request = Request::Rpc {
            endpoint: self.endpoint.clone(),
            body: rpc::body(id, method),
        };
        match ctx.rt.request(request).await {
            Answer::Rpc {
                status,
                body,
                draws,
            } => {
                let mut random = ctx.random.borrow_mut();
                for _ in 0..draws {
                    random.next_f64();
                }
                drop(random);
                rpc::answer(id, method, status, &body)
            }
            Answer::Failed(transport) => Err(RpcError::Transport(transport)),
            _ => Err(RpcError::Transport(Transport::Network)),
        }
    }
}

/// `withTimeout(promise, ms)`: `Err(())` when the deadline wins.
async fn with_timeout<T>(ctx: &Ctx, ms: f64, future: impl Future<Output = T>) -> Result<T, ()> {
    match race(future, ctx.rt.sleep(js::delay_ms(ms))).await {
        Either::Left(value) => Ok(value),
        Either::Right(()) => Err(()),
    }
}

// ---------------------------------------------------------------------------
// The anchor.

const MIN_QUORUM_PROVIDERS: usize = 3;

fn safety_depth(tag: &str) -> i64 {
    match tag {
        "latest-32" => 32,
        "finalized" => 0,
        _ => 8,
    }
}

/// `fetchProviderHead`.
async fn fetch_head(ctx: &Ctx, endpoint: &str, tag: &str, timeout: f64) -> Result<i64, ()> {
    let mut provider = Provider::new(endpoint);
    with_timeout(ctx, timeout, async {
        if tag == "finalized" {
            let block = provider
                .send(ctx, &Method::Block(BlockRef::Tag("finalized".into())))
                .await
                .map_err(|_| ())?;
            rpc::block_result(&block)
                .map_err(|_| ())?
                .map(|b| b.number)
                .ok_or(())
        } else {
            let number = provider
                .send(ctx, &Method::BlockNumber)
                .await
                .map_err(|_| ())?;
            rpc::get_number(&number).ok_or(())
        }
    })
    .await
    .and_then(|inner| inner)
}

/// `fetchProviderBlockHashAt`: the block's hash, `None` for a pending
/// block's `null`.
async fn fetch_hash_at(
    ctx: &Ctx,
    endpoint: &str,
    number: i64,
    timeout: f64,
) -> Result<Option<String>, ()> {
    let mut provider = Provider::new(endpoint);
    let Ok(number) = u64::try_from(number) else {
        return Err(());
    };
    with_timeout(ctx, timeout, async {
        let block = provider
            .send(ctx, &Method::Block(BlockRef::Number(number)))
            .await
            .map_err(|_| ())?;
        let block = rpc::block_result(&block).map_err(|_| ())?.ok_or(())?;
        Ok(block.hash)
    })
    .await
    .and_then(|inner| inner)
}

/// Settles every future, keeping input order (`Promise.allSettled`).
async fn settle_all<T>(futures: Vec<Pin<Box<dyn Future<Output = T> + '_>>>) -> Vec<T> {
    super::exec::all(futures).await
}

/// `getPinnedBlock`: `Ok(None)` when corroboration is infeasible.
async fn pinned_block(ctx: &Ctx) -> Result<Option<(i64, String)>, Thrown> {
    let tag = ctx.anchor_tag();
    let ttl = match ctx.quorum("anchorTtlMs") {
        Some(JsValue::Number(n)) => n,
        _ => 30_000.0,
    };
    let timeout = ctx.timeout_ms();
    let k = js::clamp(
        js::or(js::to_number(ctx.quorum("k").as_ref()), 3.0),
        2.0,
        9.0,
    );
    let m = js::clamp(js::or(js::to_number(ctx.quorum("m").as_ref()), 2.0), 2.0, k);

    if let Some(anchor) = &ctx.state.borrow().anchor
        && anchor.tag == tag
        && ctx.now_f() < anchor.expires
    {
        return Ok(Some((anchor.number, anchor.hash.clone())));
    }

    let available = ctx.available();
    if available.len() < MIN_QUORUM_PROVIDERS {
        return Ok(None);
    }
    #[allow(clippy::cast_precision_loss)]
    let effective_m = js::min(m, available.len() as f64);

    let heads = settle_all(
        available
            .iter()
            .map(|endpoint| {
                let tag = tag.clone();
                Box::pin(async move {
                    let head = fetch_head(ctx, endpoint, &tag, timeout).await;
                    if head.is_err() {
                        ctx.mark_failure(endpoint);
                    }
                    (endpoint.clone(), head)
                })
                    as Pin<Box<dyn Future<Output = (Endpoint, Result<i64, ()>)> + '_>>
            })
            .collect(),
    )
    .await;
    let heads: Vec<(Endpoint, i64)> = heads
        .into_iter()
        .filter_map(|(e, h)| h.ok().map(|n| (e, n)))
        .collect();
    for (endpoint, _) in &heads {
        ctx.mark_success(endpoint);
    }
    if heads.len() < MIN_QUORUM_PROVIDERS {
        return Ok(None);
    }
    let mut sorted: Vec<i64> = heads.iter().map(|(_, n)| *n).collect();
    sorted.sort_unstable();
    let head = sorted[sorted.len() / 2];
    let target = head - safety_depth(&tag);

    let hashes = settle_all(
        heads
            .iter()
            .map(|(endpoint, _)| {
                Box::pin(async move {
                    let hash = fetch_hash_at(ctx, endpoint, target, timeout).await;
                    if hash.is_err() {
                        ctx.mark_failure(endpoint);
                    }
                    (endpoint.clone(), hash)
                })
                    as Pin<Box<dyn Future<Output = (Endpoint, Result<Option<String>, ()>)> + '_>>
            })
            .collect(),
    )
    .await;
    let hashes: Vec<(Endpoint, Option<String>)> = hashes
        .into_iter()
        .filter_map(|(e, h)| h.ok().map(|h| (e, h)))
        .collect();

    // Buckets in response order; the first strictly largest wins.
    let mut buckets: Vec<(Option<String>, Vec<Endpoint>)> = Vec::new();
    for (endpoint, hash) in &hashes {
        match buckets.iter_mut().find(|(h, _)| h == hash) {
            Some((_, members)) => members.push(endpoint.clone()),
            None => buckets.push((hash.clone(), vec![endpoint.clone()])),
        }
    }
    let mut winner: (Option<String>, Vec<Endpoint>) = (None, Vec::new());
    for (hash, members) in buckets {
        if members.len() > winner.1.len() {
            winner = (hash, members);
        }
    }
    let majority = hashes.len() / 2 + 1;
    #[allow(clippy::cast_precision_loss)]
    let threshold = js::max(effective_m, majority as f64);
    if js::reaches(winner.1.len(), threshold) {
        for endpoint in &winner.1 {
            ctx.mark_success(endpoint);
        }
        let hash = winner.0.unwrap_or_default();
        ctx.state.borrow_mut().anchor = Some(Anchor {
            tag,
            number: target,
            hash: hash.clone(),
            expires: ctx.now_f() + ttl,
        });
        return Ok(Some((target, hash)));
    }
    Err(Thrown::new(format!(
        "Could not reach hash quorum at block {target} (largest bucket {} of {} responses, need ≥{})",
        winner.1.len(),
        hashes.len(),
        crate::jsjson::number_to_string(threshold)
    )))
}

// ---------------------------------------------------------------------------
// A leg: one call at the pinned block, with CCIP-Read.

/// A call the resolver makes on a leg (`callResolver`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Resolver {
    /// `universalResolverCall`: the UR's `resolve`, with CCIP-Read.
    Ur,
    /// `nameNftResolverCall`: a WNS/GNS registry's own record.
    NameNft(NameSystem),
    /// `universalResolverReverseCall`: the UR's `reverse`, as an agreement
    /// value `(outcome, detail)`.
    UrReverse { coin_type: u64 },
    /// `nameNftReverseResolverCall`: a registry's `reverseResolve`.
    NameNftReverse(NameSystem),
}

/// Why a call failed, with what classification and agreement need.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CallError {
    Rpc(RpcError),
    /// ethers refused the call's arguments or its answer. The text is the
    /// identity ethers' message would give it (design 0004, Errors).
    Invalid(String),
    /// `CCIP sender does not match the Universal Resolver`.
    SenderMismatch,
    /// Every gateway failed: `CCIP_GATEWAY_FAILED`.
    GatewaysFailed,
    /// `CCIP recursion limit exceeded`.
    RecursionLimit,
    /// The leg's deadline.
    Timeout,
    /// A NameNFT call the adapter doesn't support.
    Unsupported(String),
}

/// A failed call, with the call that failed (the callback, after
/// CCIP-Read).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Failure {
    error: CallError,
    to: [u8; 20],
    data: Vec<u8>,
}

impl CallError {
    /// The revert data the resolver reads: ethers' extracted data, else
    /// the node's `data` string (`getRevertData`).
    fn revert_source(&self) -> Option<String> {
        match self {
            CallError::Rpc(RpcError::CallException {
                data: Some(data), ..
            }) => Some(rpc::hex(data)),
            CallError::Rpc(RpcError::CallException {
                node: Some(node), ..
            }) => node
                .data_string()
                .filter(|d| d.len() >= 10)
                .map(str::to_owned),
            _ => None,
        }
    }

    fn selector(&self) -> Option<String> {
        self.revert_source()
            .map(|s| s.get(..10).unwrap_or("").to_ascii_lowercase())
    }

    /// The `Error(string)` reason ethers decodes from revert data.
    fn reason(&self) -> Option<String> {
        let CallError::Rpc(RpcError::CallException {
            data: Some(data), ..
        }) = self
        else {
            return None;
        };
        if data.get(..4)? != [0x08, 0xc3, 0x79, 0xa0] || data.len() % 32 != 4 {
            return None;
        }
        match crate::abi::decode(&[Kind::String], &data[4..])
            .ok()?
            .into_iter()
            .next()?
        {
            Ok(Value::String(reason)) => Some(reason),
            _ => None,
        }
    }

    fn reason_names(&self, names: &[&str]) -> bool {
        self.reason().is_some_and(|reason| {
            let lower = reason.to_ascii_lowercase();
            names.iter().any(|n| lower.contains(n))
        })
    }

    /// `isResolverNotFoundError`: the selector, or an `Error(string)`
    /// reason naming the error (what the reference's message match sees).
    fn resolver_not_found(&self) -> bool {
        matches!(
            self.selector().as_deref(),
            Some("0x77209fe8" | "0x1e9535f2")
        ) || self.reason_names(&["resolvernotfound", "resolvernotcontract"])
    }

    /// `isReverseAddressMismatchError`.
    fn reverse_mismatch(&self) -> bool {
        self.selector().as_deref() == Some("0xef9c03ce")
            || self.reason_names(&["reverseaddressmismatch"])
    }

    /// The core's provider-failure rules (design 0004, Classification).
    fn provider_failure(&self) -> bool {
        match self {
            CallError::Timeout => true,
            CallError::Rpc(error) => match error {
                RpcError::Transport(_)
                | RpcError::Http(_)
                | RpcError::NotJson
                | RpcError::MissingResponse
                | RpcError::BadResult => true,
                RpcError::CallException {
                    node: Some(node), ..
                } if node.code() == Some(-32603.0) => true,
                RpcError::CallException { data: Some(_), .. } => false,
                RpcError::CallException {
                    data: None,
                    node: Some(node),
                } => node_failure(node),
                RpcError::CallException {
                    data: None,
                    node: None,
                }
                | RpcError::Coalesce(_) => false,
            },
            _ => false,
        }
    }

    pub(crate) fn short_message(&self) -> String {
        match self {
            CallError::Rpc(RpcError::Transport(Transport::Timeout)) | CallError::Timeout => {
                "timeout".into()
            }
            CallError::Rpc(RpcError::Transport(_)) => "network error".into(),
            CallError::Rpc(RpcError::Http(status)) => format!("server response {status}"),
            CallError::Rpc(RpcError::NotJson) => "response body is not valid JSON".into(),
            CallError::Rpc(RpcError::MissingResponse) => "missing response for request".into(),
            CallError::Rpc(RpcError::BadResult) => "invalid result".into(),
            CallError::Rpc(RpcError::Coalesce(_)) => "could not coalesce error".into(),
            CallError::Rpc(RpcError::CallException { data: None, .. }) => {
                "missing revert data".into()
            }
            CallError::Rpc(RpcError::CallException {
                data: Some(data), ..
            }) => match self.reason() {
                Some(reason) => format!(
                    "execution reverted: {}",
                    JsValue::String(reason).stringify()
                ),
                None if data.is_empty() => {
                    "execution reverted (no data present; likely require(false) occurred".into()
                }
                None => "execution reverted (unknown custom error)".into(),
            },
            CallError::Invalid(_) => "could not decode result data".into(),
            CallError::SenderMismatch => "CCIP sender does not match the Universal Resolver".into(),
            CallError::GatewaysFailed => {
                "CCIP gateways unavailable or returned invalid data".into()
            }
            CallError::RecursionLimit => "CCIP recursion limit exceeded".into(),
            CallError::Unsupported(message) => message.clone(),
        }
    }
}

impl Failure {
    /// The agreement identity of an encoded reverse error: what ethers'
    /// composed message is built from (design 0004, Errors).
    fn identity(&self) -> String {
        match &self.error {
            CallError::Rpc(RpcError::CallException { data, .. }) => format!(
                "CALL_EXCEPTION|{}|{}|{}|{}",
                self.error.short_message(),
                data.as_deref().map_or_else(|| "null".into(), rpc::hex),
                rpc::hex(&self.to),
                rpc::hex(&self.data)
            ),
            CallError::Invalid(identity) => format!("INVALID|{identity}"),
            other => other.short_message(),
        }
    }
}

/// Rules 6–8: the node's own error, without revert evidence (−32603 is
/// rule 5, checked first).
fn node_failure(node: &rpc::NodeError) -> bool {
    let code = node.code();
    let message = node.message();
    let lower = message.to_ascii_lowercase();
    let revert_shaped = node.data_string().is_some_and(|d| {
        let hex = d.strip_prefix("Reverted ").unwrap_or(d);
        hex.len() % 2 == 0 && rpc::hex_string(hex).is_some()
    });
    if matches!(code, Some(c) if c == 3.0 || c == -32015.0)
        || revert_shaped
        || lower.contains("revert")
    {
        return false;
    }
    const CODES: [f64; 6] = [-32001.0, -32002.0, -32005.0, -32007.0, -32008.0, 429.0];
    if code.is_some_and(|c| CODES.contains(&c)) {
        return true;
    }
    const PATTERNS: [&str; 19] = [
        "header not found",
        "missing trie node",
        "unknown block",
        "block not found",
        "historical state",
        "state not available",
        "state is not available",
        "pruned",
        "limit exceeded",
        "request limit reached",
        "too many requests",
        "request count exceeded",
        "compute units",
        "no response",
        "502",
        "503",
        "504",
        "429",
        "timeout",
    ];
    PATTERNS.iter().any(|p| lower.contains(p))
        || lower.contains("rate limit")
        || lower.contains("ratelimit")
        || lower.contains("rate-limit")
}

/// A leg's outcome (`runQuorumLeg`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Leg {
    Data {
        resolved: Vec<u8>,
    },
    NotFound {
        reason: &'static str,
        error: Option<CallError>,
    },
    Error(CallError),
}

/// `callUniversalResolver` at a pinned block: the first call, then up to
/// 10 CCIP-Read rounds. `Ok` is the raw answer once ethers' whole-result
/// decode accepted it; field errors stay with the caller.
async fn ur_call(
    ctx: &Ctx,
    provider: &mut Provider,
    call: Vec<u8>,
    kinds: &[Kind],
    block: &str,
    used_gateway: &RefCell<bool>,
) -> Result<Vec<u8>, Failure> {
    let decoded = |result: &JsValue| -> Result<Vec<u8>, CallError> {
        let raw = rpc::call_result(result).map_err(CallError::Rpc)?;
        ur::decode_result(kinds, &raw)
            .map_err(|_| CallError::Invalid(format!("result|{}", rpc::hex(&raw))))?;
        Ok(raw)
    };
    let fail = |error: CallError, to: [u8; 20], data: &[u8]| Failure {
        error,
        to,
        data: data.to_vec(),
    };
    let first = Method::Call {
        to: ur::UNIVERSAL_RESOLVER,
        data: call.clone(),
        block: block.into(),
    };
    let (mut error, mut to, mut data) = match provider.send(ctx, &first).await {
        Ok(result) => return decoded(&result).map_err(|e| fail(e, ur::UNIVERSAL_RESOLVER, &call)),
        Err(e) => (CallError::Rpc(e), ur::UNIVERSAL_RESOLVER, call),
    };
    for _round in 0..10 {
        let Some(source) = error.revert_source() else {
            return Err(fail(error, to, &data));
        };
        if !source.to_ascii_lowercase().starts_with("0x556f1830") {
            return Err(fail(error, to, &data));
        }
        let lookup = rpc::hex_string(&source)
            .and_then(|bytes| ur::decode_offchain_lookup(&bytes))
            .ok_or_else(|| fail(CallError::Invalid(format!("lookup|{source}")), to, &data))?;
        if lookup.sender != ur::UNIVERSAL_RESOLVER {
            return Err(fail(CallError::SenderMismatch, to, &data));
        }
        *used_gateway.borrow_mut() = true;
        let response = ccip_read_fetch(ctx, &lookup)
            .await
            .map_err(|e| fail(e, to, &data))?;
        let callback = ur::encode_callback(lookup.callback, &response, &lookup.extra_data);
        let next = Method::Call {
            to: lookup.sender,
            data: callback.clone(),
            block: block.into(),
        };
        match provider.send(ctx, &next).await {
            Ok(result) => return decoded(&result).map_err(|e| fail(e, lookup.sender, &callback)),
            Err(e) => (error, to, data) = (CallError::Rpc(e), lookup.sender, callback),
        }
    }
    Err(fail(CallError::RecursionLimit, to, &data))
}

const CCIP_TIMEOUT_MS: Ms = 15_000;

/// `ccipReadFetch`: each URL in order, 15 s each, until one answers hex.
async fn ccip_read_fetch(ctx: &Ctx, lookup: &ur::OffchainLookup) -> Result<Vec<u8>, CallError> {
    for (index, template) in lookup.urls.iter().enumerate() {
        // A URL that won't decode throws out of the loop where the JS
        // iteration reaches it.
        let template = template.as_ref().map_err(|_| {
            CallError::Invalid(format!(
                "deferred error during ABI decoding triggered accessing index {index}"
            ))
        })?;
        let Some(request) =
            crate::ccip::gateway_request(template, &lookup.sender, &lookup.call_data)
        else {
            continue;
        };
        let fetch = ctx.rt.request(Request::Gateway {
            url: request.url,
            body: request.body,
        });
        if let Either::Left(Answer::Gateway { status, body }) =
            race(fetch, ctx.rt.sleep(CCIP_TIMEOUT_MS)).await
            && (200..300).contains(&status)
            && let Some(data) = crate::ccip::parse_gateway_response(&body)
        {
            return Ok(data);
        }
    }
    Err(CallError::GatewaysFailed)
}

/// `nodeFromResolverCallData`: 36 bytes or more, the node after the
/// selector.
fn node_of(call_data: &[u8]) -> Result<[u8; 32], CallError> {
    if call_data.len() < 36 {
        return Err(CallError::Unsupported("Invalid resolver call data".into()));
    }
    ur::node_from_call(call_data)
        .ok_or_else(|| CallError::Unsupported("Invalid resolver call data".into()))
}

fn label(system: NameSystem) -> &'static str {
    match system {
        NameSystem::Ens => "ENS",
        NameSystem::Wns => "WNS",
        NameSystem::Gns => "GNS",
    }
}

/// A plain contract call at the pinned block (NameNFT calls never use
/// CCIP-Read), its single result decoded with `kind`.
async fn contract_call(
    ctx: &Ctx,
    provider: &mut Provider,
    to: [u8; 20],
    data: Vec<u8>,
    kind: Kind,
    block: &str,
) -> Result<Value, CallError> {
    let method = Method::Call {
        to,
        data,
        block: block.into(),
    };
    let result = provider.send(ctx, &method).await.map_err(CallError::Rpc)?;
    let raw = rpc::call_result(&result).map_err(CallError::Rpc)?;
    let fields = ur::decode_result(&[kind], &raw)
        .map_err(|_| CallError::Invalid(format!("result|{}", rpc::hex(&raw))))?;
    match fields.into_iter().next() {
        Some(Ok(value)) => Ok(value),
        _ => Err(CallError::Invalid(
            "deferred error during ABI decoding triggered accessing index 0".into(),
        )),
    }
}

/// One leg's call (`callResolver(provider, name, callData, overrides)`):
/// the agreement bytes, or a failure for the leg's classification.
async fn resolver_call(
    ctx: &Ctx,
    provider: &mut Provider,
    resolver: Resolver,
    name: &str,
    call_data: &[u8],
    block: &str,
    used_gateway: &RefCell<bool>,
) -> Result<Vec<u8>, CallError> {
    match resolver {
        Resolver::Ur => {
            let dns =
                crate::dns_encode(name, 255).map_err(|e| CallError::Invalid(format!("dns|{e}")))?;
            let raw = ur_call(
                ctx,
                provider,
                ur::encode_resolve(&dns, call_data),
                &[Kind::Bytes, Kind::Address],
                block,
                used_gateway,
            )
            .await
            .map_err(|f| f.error)?;
            match ur::decode_result(&[Kind::Bytes, Kind::Address], &raw)
                .ok()
                .as_deref()
            {
                Some([Ok(Value::Bytes(resolved)), Ok(Value::Address(_))]) => Ok(resolved.clone()),
                _ => Err(CallError::Invalid(
                    "deferred error during ABI decoding triggered accessing index 0".into(),
                )),
            }
        }
        Resolver::UrReverse { coin_type } => {
            let Some(address) = rpc::hex_string(name).and_then(|b| <[u8; 20]>::try_from(b).ok())
            else {
                return Err(CallError::Invalid(format!("address|{name}")));
            };
            let kinds = [Kind::String, Kind::Address, Kind::Address];
            let outcome = ur_call(
                ctx,
                provider,
                ur::encode_reverse(&address, coin_type),
                &kinds,
                block,
                used_gateway,
            )
            .await;
            match outcome {
                Ok(raw) => match ur::decode_result(&kinds, &raw)
                    .ok()
                    .and_then(|f| f.into_iter().next())
                {
                    Some(Ok(Value::String(primary))) if !primary.is_empty() => Ok(
                        ur::encode_reverse_outcome(ur::ReverseOutcome::Name, &primary),
                    ),
                    Some(Ok(Value::String(_))) => {
                        Ok(ur::encode_reverse_outcome(ur::ReverseOutcome::NoRecord, ""))
                    }
                    _ => Ok(ur::encode_reverse_outcome(
                        ur::ReverseOutcome::Error,
                        "INVALID|deferred error during ABI decoding triggered accessing index 0",
                    )),
                },
                // `universalResolverReverseCall`'s catch, in its order.
                Err(failure)
                    if failure.error.provider_failure()
                        || failure.error == CallError::GatewaysFailed =>
                {
                    Err(failure.error)
                }
                Err(failure) if failure.error.resolver_not_found() => {
                    Ok(ur::encode_reverse_outcome(ur::ReverseOutcome::NoRecord, ""))
                }
                Err(failure) if failure.error.reverse_mismatch() => {
                    let claimed = failure
                        .error
                        .revert_source()
                        .and_then(|s| rpc::hex_string(&s))
                        .and_then(|d| ur::reverse_mismatch_claimed_name(&d));
                    Ok(ur::encode_reverse_outcome(
                        ur::ReverseOutcome::Mismatch,
                        claimed.as_deref().unwrap_or(""),
                    ))
                }
                Err(failure) => Ok(ur::encode_reverse_outcome(
                    ur::ReverseOutcome::Error,
                    &failure.identity(),
                )),
            }
        }
        Resolver::NameNft(system) => {
            let Some(registry) = system.registry() else {
                return Err(CallError::Unsupported(format!(
                    "No NameNFT contract configured for {}",
                    label(system)
                )));
            };
            let node = node_of(call_data)?;
            match call_data.get(..4) {
                Some(selector) if selector == ur::CONTENTHASH => {
                    match contract_call(
                        ctx,
                        provider,
                        registry,
                        ur::contenthash_call(&node),
                        Kind::Bytes,
                        block,
                    )
                    .await?
                    {
                        Value::Bytes(contenthash) => {
                            Ok(crate::abi::encode(&[crate::abi::Token::Dynamic(
                                &contenthash,
                            )]))
                        }
                        _ => Err(CallError::Invalid("contenthash".into())),
                    }
                }
                Some(selector) if selector == ur::ADDR => match contract_call(
                    ctx,
                    provider,
                    registry,
                    ur::addr_call(&node),
                    Kind::Address,
                    block,
                )
                .await?
                {
                    Value::Address(address) => Ok(crate::abi::encode(&[crate::abi::Token::Word(
                        crate::abi::word_from_address(&address),
                    )])),
                    _ => Err(CallError::Invalid("addr".into())),
                },
                _ => Err(CallError::Unsupported(format!(
                    "Unsupported {} resolver selector: {}",
                    label(system),
                    rpc::hex(call_data.get(..4).unwrap_or(&[]))
                ))),
            }
        }
        Resolver::NameNftReverse(system) => {
            let Some(registry) = system.registry() else {
                return Err(CallError::Unsupported(format!(
                    "No NameNFT contract configured for {}",
                    label(system)
                )));
            };
            let Some(address) = call_data
                .get(16..36)
                .and_then(|b| <[u8; 20]>::try_from(b).ok())
            else {
                return Err(CallError::Invalid("reverseResolve".into()));
            };
            match contract_call(
                ctx,
                provider,
                registry,
                ur::reverse_resolve_call(&address),
                Kind::String,
                block,
            )
            .await?
            {
                Value::String(claimed) => Ok(crate::abi::encode(&[crate::abi::Token::Dynamic(
                    claimed.as_bytes(),
                )])),
                _ => Err(CallError::Invalid("reverseResolve".into())),
            }
        }
    }
}

/// `runQuorumLeg`.
async fn run_leg(ctx: &Ctx, endpoint: &str, lookup: &Lookup<'_>, block: &str, timeout: f64) -> Leg {
    let mut provider = Provider::new(endpoint);
    let used_gateway = RefCell::new(false);
    let call = resolver_call(
        ctx,
        &mut provider,
        lookup.resolver,
        lookup.name,
        lookup.call_data,
        block,
        &used_gateway,
    );
    let error = match with_timeout(ctx, timeout, call).await {
        Ok(Ok(resolved)) => {
            ctx.mark_success(endpoint);
            return Leg::Data { resolved };
        }
        Ok(Err(error)) => error,
        Err(()) if *used_gateway.borrow() => {
            ctx.mark_success(endpoint);
            return Leg::Error(CallError::Timeout);
        }
        Err(()) => CallError::Timeout,
    };
    if error == CallError::GatewaysFailed {
        ctx.mark_success(endpoint);
        return Leg::Error(error);
    }
    if error.resolver_not_found() {
        ctx.mark_success(endpoint);
        return Leg::NotFound {
            reason: "NO_RESOLVER",
            error: None,
        };
    }
    if error.provider_failure() {
        ctx.mark_failure(endpoint);
        return Leg::Error(error);
    }
    ctx.mark_success(endpoint);
    Leg::NotFound {
        reason: "NO_CONTENTHASH",
        error: Some(error),
    }
}

// ---------------------------------------------------------------------------
// A wave.

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum WaveOutcome {
    AgreedData {
        bytes: Vec<u8>,
        endpoints: Vec<Endpoint>,
    },
    AgreedNotFound {
        reason: &'static str,
        endpoints: Vec<Endpoint>,
    },
    AllSettled,
}

pub(crate) struct Wave {
    outcome: WaveOutcome,
    results: Vec<(Endpoint, Leg)>,
    queried: Vec<Endpoint>,
    m: f64,
}

/// What a lookup asks every method for.
#[derive(Clone, Copy)]
pub(crate) struct Lookup<'a> {
    name: &'a str,
    call_data: &'a [u8],
    system: &'a str,
    resolver: Resolver,
    /// Content lookups prefetch the first answer.
    prefetch: bool,
}

/// `runConsensusWave`: legs at once; the first M-sized bucket ends it.
async fn run_wave(
    ctx: &Ctx,
    machine: &super::machine::Shared,
    endpoints: &[Endpoint],
    lookup: &Lookup<'_>,
    block: &str,
    timeout: f64,
    m: f64,
) -> Wave {
    let mut legs: Vec<Option<Pin<Box<dyn Future<Output = Leg> + '_>>>> = endpoints
        .iter()
        .map(|endpoint| {
            Some(Box::pin(run_leg(ctx, endpoint, lookup, block, timeout))
                as Pin<Box<dyn Future<Output = Leg>>>)
        })
        .collect();
    let mut results: Vec<(Endpoint, Leg)> = Vec::new();
    let mut by_data: Vec<(Vec<u8>, Vec<Endpoint>)> = Vec::new();
    let mut by_negative: Vec<(&'static str, Vec<Endpoint>)> = Vec::new();
    let mut prefetch_handle: Option<u64> = None;
    let mut first_data = false;

    let outcome = std::future::poll_fn(|cx| {
        for (i, leg) in legs.iter_mut().enumerate() {
            let Some(running) = leg else { continue };
            let Poll::Ready(result) = running.as_mut().poll(cx) else {
                continue;
            };
            *leg = None;
            let endpoint = endpoints[i].clone();
            match &result {
                Leg::Data { resolved } => {
                    if !first_data && lookup.prefetch {
                        first_data = true;
                        prefetch_handle = machine.start_prefetch(resolved);
                    }
                    match by_data.iter_mut().find(|(bytes, _)| bytes == resolved) {
                        Some((_, members)) => members.push(endpoint.clone()),
                        None => by_data.push((resolved.clone(), vec![endpoint.clone()])),
                    }
                }
                Leg::NotFound { reason, .. } => {
                    match by_negative.iter_mut().find(|(r, _)| r == reason) {
                        Some((_, members)) => members.push(endpoint.clone()),
                        None => by_negative.push((reason, vec![endpoint.clone()])),
                    }
                }
                Leg::Error(_) => {}
            }
            results.push((endpoint, result));
            // `checkEarly`: data buckets first, then negative ones.
            if let Some((bytes, members)) = by_data
                .iter()
                .find(|(_, members)| js::reaches(members.len(), m))
            {
                return Poll::Ready(WaveOutcome::AgreedData {
                    bytes: bytes.clone(),
                    endpoints: members.clone(),
                });
            }
            if let Some((reason, members)) = by_negative
                .iter()
                .find(|(_, members)| js::reaches(members.len(), m))
            {
                return Poll::Ready(WaveOutcome::AgreedNotFound {
                    reason,
                    endpoints: members.clone(),
                });
            }
        }
        if legs.iter().all(Option::is_none) {
            Poll::Ready(WaveOutcome::AllSettled)
        } else {
            Poll::Pending
        }
    })
    .await;
    // Unfinished legs are dropped here, which cancels them.
    drop(legs);
    if !matches!(outcome, WaveOutcome::AgreedData { .. })
        && let Some(handle) = prefetch_handle
    {
        machine.abort_prefetch(handle);
    }
    Wave {
        outcome,
        results,
        queried: endpoints.to_vec(),
        m,
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Verdict {
    AllErrored,
    UnverifiedData(Endpoint, Vec<u8>),
    UnverifiedNotFound(Endpoint, &'static str, Option<CallError>),
    Conflict,
}

/// `classifyNoAgreement`.
fn classify(wave: &Wave) -> Verdict {
    let semantic: Vec<&(Endpoint, Leg)> = wave
        .results
        .iter()
        .filter(|(_, leg)| !matches!(leg, Leg::Error(_)))
        .collect();
    match semantic.as_slice() {
        [] => Verdict::AllErrored,
        [(endpoint, Leg::Data { resolved })] => {
            Verdict::UnverifiedData(endpoint.clone(), resolved.clone())
        }
        [(endpoint, Leg::NotFound { reason, error })] => {
            Verdict::UnverifiedNotFound(endpoint.clone(), reason, error.clone())
        }
        _ => Verdict::Conflict,
    }
}

/// A method's answer (`resolveViaQuorum`, `tryDirectResolve`, …).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Consensus {
    Data {
        resolved: Vec<u8>,
        trust: JsValue,
    },
    NotFound {
        reason: &'static str,
        error: Option<CallError>,
        trust: JsValue,
    },
    Conflict {
        groups: JsValue,
        trust: JsValue,
    },
}

impl Consensus {
    fn trust(&self) -> &JsValue {
        match self {
            Consensus::Data { trust, .. }
            | Consensus::NotFound { trust, .. }
            | Consensus::Conflict { trust, .. } => trust,
        }
    }
}

fn s(text: &str) -> JsValue {
    JsValue::String(text.into())
}

fn refs(endpoints: &[Endpoint]) -> JsValue {
    JsValue::Array(
        endpoints
            .iter()
            .map(|e| JsValue::Object(vec![("ref".into(), s(e))]))
            .collect(),
    )
}

#[allow(clippy::cast_precision_loss)]
fn number(n: i64) -> JsValue {
    JsValue::Number(n as f64)
}

fn obj(fields: Vec<(&str, JsValue)>) -> JsValue {
    JsValue::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

/// `buildTrust`.
fn build_trust(
    level: &str,
    system: &str,
    agreed: &[Endpoint],
    dissented: &[Endpoint],
    queried: &[Endpoint],
    (k, m): (f64, f64),
    block: &(i64, String),
) -> JsValue {
    obj(vec![
        ("level", s(level)),
        ("system", s(system)),
        (
            "block",
            obj(vec![("number", number(block.0)), ("hash", s(&block.1))]),
        ),
        ("agreed", refs(agreed)),
        ("dissented", refs(dissented)),
        ("queried", refs(queried)),
        (
            "quorum",
            obj(vec![
                ("k", JsValue::Number(k)),
                ("m", JsValue::Number(m)),
                ("achieved", JsValue::Bool(level == "verified")),
            ]),
        ),
    ])
}

/// `resolveSingleSourceUnverified`.
async fn single_source(
    ctx: &Ctx,
    endpoint: &str,
    lookup: &Lookup<'_>,
) -> Result<Consensus, Thrown> {
    let tag = ctx.anchor_tag();
    let timeout = ctx.timeout_ms();
    let block = single_source_anchor(ctx, endpoint, &tag, timeout)
        .await
        .map_err(|message| {
            Thrown::new(format!("Single-provider anchor fetch failed: {message}"))
        })?;
    let leg = run_leg(ctx, endpoint, lookup, &block.1, timeout).await;
    let one = [endpoint.to_owned()];
    let trust = build_trust(
        "unverified",
        lookup.system,
        &one,
        &[],
        &one,
        (1.0, 1.0),
        &block,
    );
    match leg {
        Leg::Data { resolved } => Ok(Consensus::Data { resolved, trust }),
        Leg::NotFound { reason, error } => Ok(Consensus::NotFound {
            reason,
            error,
            trust,
        }),
        Leg::Error(error) => Err(Thrown::new(error.short_message())),
    }
}

/// `fetchSingleSourceAnchor`: head and block under one deadline.
async fn single_source_anchor(
    ctx: &Ctx,
    endpoint: &str,
    tag: &str,
    timeout: f64,
) -> Result<(i64, String), String> {
    let mut provider = Provider::new(endpoint);
    let attempt = async {
        let head = if tag == "finalized" {
            let block = provider
                .send(ctx, &Method::Block(BlockRef::Tag("finalized".into())))
                .await
                .map_err(|_| "finalized tag returned null".to_owned())?;
            rpc::block_result(&block)
                .map_err(|_| "bad block".to_owned())?
                .ok_or("finalized tag returned null")?
                .number
        } else {
            let number = provider
                .send(ctx, &Method::BlockNumber)
                .await
                .map_err(|_| "could not read the head".to_owned())?;
            rpc::get_number(&number).ok_or("bad head")?
        };
        let target = head - safety_depth(tag);
        let n = u64::try_from(target).map_err(|_| format!("block {target} not available"))?;
        let block = provider
            .send(ctx, &Method::Block(BlockRef::Number(n)))
            .await
            .map_err(|_| format!("block {target} not available"))?;
        let block = rpc::block_result(&block)
            .map_err(|_| "bad block".to_owned())?
            .ok_or(format!("block {target} not available"))?;
        Ok::<_, String>((target, block.hash.unwrap_or_default()))
    };
    match with_timeout(ctx, timeout, attempt).await {
        Ok(result) => result,
        Err(()) => Err(format!(
            "timeout after {}ms",
            crate::jsjson::number_to_string(timeout)
        )),
    }
}

/// `resolveViaQuorum`.
async fn via_quorum(
    ctx: &Ctx,
    machine: &super::machine::Shared,
    lookup: &Lookup<'_>,
) -> Result<Consensus, Thrown> {
    let k = js::clamp(
        js::or(js::to_number(ctx.quorum("k").as_ref()), 3.0),
        1.0,
        9.0,
    );
    let m = js::clamp(js::or(js::to_number(ctx.quorum("m").as_ref()), 2.0), 1.0, k);
    let timeout = ctx.timeout_ms();

    let available = ctx.available();
    let Some(first) = available.first().cloned() else {
        return Err(Thrown::new(
            "No available RPC providers for ENS consensus resolution",
        ));
    };
    if available.len() < MIN_QUORUM_PROVIDERS || k < 3.0 || m < 2.0 {
        return single_source(ctx, &first, lookup).await;
    }
    let Some(block) = pinned_block(ctx).await? else {
        let fresh = ctx.available();
        return single_source(ctx, fresh.first().unwrap_or(&first), lookup).await;
    };
    let wave_available = ctx.available();
    if wave_available.len() < MIN_QUORUM_PROVIDERS {
        return single_source(ctx, wave_available.first().unwrap_or(&first), lookup).await;
    }
    #[allow(clippy::cast_precision_loss)]
    let effective_k = js::min(k, wave_available.len() as f64);
    let effective_m = js::min(m, effective_k);
    let first_selection: Vec<Endpoint> =
        wave_available[..js::slice_end(effective_k, wave_available.len())].to_vec();

    let mut wave = run_wave(
        ctx,
        machine,
        &first_selection,
        lookup,
        &block.1,
        timeout,
        effective_m,
    )
    .await;
    if wave.outcome == WaveOutcome::AllSettled {
        let verdict = classify(&wave);
        let upgradable = matches!(
            verdict,
            Verdict::AllErrored | Verdict::UnverifiedData(..) | Verdict::UnverifiedNotFound(..)
        );
        if upgradable {
            let remaining: Vec<Endpoint> = ctx
                .available()
                .into_iter()
                .filter(|e| !first_selection.contains(e))
                .collect();
            let min_remaining = if verdict == Verdict::AllErrored {
                1.0
            } else {
                effective_m
            };
            if js::reaches(remaining.len(), min_remaining) {
                #[allow(clippy::cast_precision_loss)]
                let second_k = js::min(k, remaining.len() as f64);
                let second: Vec<Endpoint> =
                    remaining[..js::slice_end(second_k, remaining.len())].to_vec();
                let second_wave = run_wave(
                    ctx,
                    machine,
                    &second,
                    lookup,
                    &block.1,
                    timeout,
                    js::min(m, second_k),
                )
                .await;
                let agreed = !matches!(second_wave.outcome, WaveOutcome::AllSettled);
                if verdict == Verdict::AllErrored || agreed {
                    wave = second_wave;
                }
            }
        }
    }

    #[allow(clippy::cast_precision_loss)]
    let k_used = wave.queried.len() as f64;
    let system = lookup.system;
    let trust_for = |level: &str, agreed: &[Endpoint], dissented: &[Endpoint]| {
        build_trust(
            level,
            system,
            agreed,
            dissented,
            &wave.queried,
            (k_used, wave.m),
            &block,
        )
    };
    match &wave.outcome {
        WaveOutcome::AgreedData { bytes, endpoints } => {
            return Ok(Consensus::Data {
                resolved: bytes.clone(),
                trust: trust_for("verified", endpoints, &[]),
            });
        }
        WaveOutcome::AgreedNotFound { reason, endpoints } => {
            let first_error = wave
                .results
                .iter()
                .find(|(e, _)| e == &endpoints[0])
                .and_then(|(_, leg)| match leg {
                    Leg::NotFound { error, .. } => error.clone(),
                    _ => None,
                });
            return Ok(Consensus::NotFound {
                reason,
                error: first_error,
                trust: trust_for("verified", endpoints, &[]),
            });
        }
        WaveOutcome::AllSettled => {}
    }
    match classify(&wave) {
        Verdict::AllErrored => Err(Thrown::new(format!(
            "All {} RPC providers failed for {}",
            wave.queried.len(),
            lookup.name
        ))),
        Verdict::UnverifiedData(endpoint, resolved) => Ok(Consensus::Data {
            resolved,
            trust: trust_for("unverified", &[endpoint], &[]),
        }),
        Verdict::UnverifiedNotFound(endpoint, reason, error) => Ok(Consensus::NotFound {
            reason,
            error,
            trust: trust_for("unverified", &[endpoint], &[]),
        }),
        Verdict::Conflict => {
            let mut groups = Vec::new();
            for (bytes, members) in data_buckets(&wave) {
                groups.push(obj(vec![
                    ("resolvedData", s(&rpc::hex(&bytes))),
                    ("urls", refs(&members)),
                ]));
            }
            for (reason, members) in negative_buckets(&wave) {
                groups.push(obj(vec![
                    ("resolvedData", JsValue::Null),
                    ("reason", s(reason)),
                    ("urls", refs(&members)),
                ]));
            }
            Ok(Consensus::Conflict {
                groups: JsValue::Array(groups),
                trust: trust_for("conflict", &[], &wave.queried),
            })
        }
    }
}

fn data_buckets(wave: &Wave) -> Vec<(Vec<u8>, Vec<Endpoint>)> {
    let mut buckets: Vec<(Vec<u8>, Vec<Endpoint>)> = Vec::new();
    for (endpoint, leg) in &wave.results {
        if let Leg::Data { resolved } = leg {
            match buckets.iter_mut().find(|(b, _)| b == resolved) {
                Some((_, members)) => members.push(endpoint.clone()),
                None => buckets.push((resolved.clone(), vec![endpoint.clone()])),
            }
        }
    }
    buckets
}

fn negative_buckets(wave: &Wave) -> Vec<(&'static str, Vec<Endpoint>)> {
    let mut buckets: Vec<(&'static str, Vec<Endpoint>)> = Vec::new();
    for (endpoint, leg) in &wave.results {
        if let Leg::NotFound { reason, .. } = leg {
            match buckets.iter_mut().find(|(r, _)| r == reason) {
                Some((_, members)) => members.push(endpoint.clone()),
                None => buckets.push((reason, vec![endpoint.clone()])),
            }
        }
    }
    buckets
}

/// `tryDirectResolve`: `None` when unavailable.
async fn direct(ctx: &Ctx, lookup: &Lookup<'_>) -> Option<Consensus> {
    let direct = ctx.state.borrow().config.direct.clone()?;
    let tag = ctx.anchor_tag();
    let timeout = ctx.timeout_ms();
    let block = single_source_anchor(ctx, &direct.endpoint, &tag, timeout)
        .await
        .ok()?;
    let leg = run_leg(ctx, &direct.endpoint, lookup, &block.1, timeout).await;
    let level = if direct.user_configured {
        "user-configured"
    } else {
        "unverified"
    };
    let one = [direct.endpoint.clone()];
    let trust = build_trust(level, lookup.system, &one, &[], &one, (1.0, 1.0), &block);
    match leg {
        Leg::Data { resolved } => Some(Consensus::Data { resolved, trust }),
        Leg::NotFound { reason, error } => Some(Consensus::NotFound {
            reason,
            error,
            trust,
        }),
        Leg::Error(_) => None,
    }
}

/// `resolveWithMethod`: `Ok(None)` when the method is unavailable.
async fn with_method(
    ctx: &Ctx,
    machine: &super::machine::Shared,
    method: &str,
    lookup: &Lookup<'_>,
) -> Result<Option<Consensus>, Thrown> {
    match method {
        "quorum" => via_quorum(ctx, machine, lookup).await.map(Some),
        "direct" => Ok(direct(ctx, lookup).await),
        // Myotis and Colibri arrive with the verified operations.
        _ => Ok(None),
    }
}

/// `consensusResolve`.
async fn consensus_resolve(
    ctx: &Ctx,
    machine: &super::machine::Shared,
    lookup: &Lookup<'_>,
) -> Result<Consensus, Thrown> {
    let (order, prefer_verified) = {
        let state = ctx.state.borrow();
        (state.config.order.clone(), state.config.prefer_verified)
    };
    let mut provisional: Option<Consensus> = None;
    let mut last_error: Option<Thrown> = None;
    for method in &order {
        let result = match with_method(ctx, machine, method, lookup).await {
            Ok(Some(result)) => result,
            Ok(None) => continue,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let unverified = result.trust().get("level") == Some(&s("unverified"));
        if prefer_verified && unverified {
            if provisional.is_none() {
                provisional = Some(result);
            }
            continue;
        }
        return Ok(result);
    }
    if let Some(result) = provisional {
        return Ok(result);
    }
    Err(last_error.unwrap_or_else(|| {
        Thrown::new(format!(
            "No enabled name-resolution method could resolve {}",
            lookup.name
        ))
    }))
}

// ---------------------------------------------------------------------------
// Caches.

/// TTLs by trust level (`ttlForResult`).
fn ttl_for(result: &JsValue) -> f64 {
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
fn cache(ctx: &Ctx, store: Store, key: &str, result: JsValue) -> JsValue {
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

// ---------------------------------------------------------------------------
// Content.

/// `doResolveEnsContent`.
pub(crate) async fn content(
    ctx: &Ctx,
    machine: &super::machine::Shared,
    normalized: &str,
) -> Result<JsValue, Thrown> {
    let node = crate::namehash(normalized).map_err(|e| Thrown::new(e.to_string()))?;
    let call_data = ur::contenthash_call(&node);
    let system = NameSystem::for_name(normalized);
    let id = system.id();
    let resolver = if system.registry().is_some() {
        Resolver::NameNft(system)
    } else {
        Resolver::Ur
    };
    let lookup = Lookup {
        name: normalized,
        call_data: &call_data,
        system: id,
        resolver,
        prefetch: true,
    };
    let consensus = consensus_resolve(ctx, machine, &lookup).await?;
    let trust = consensus.trust().clone();
    let head = |kind: &str| {
        vec![
            ("type", s(kind)),
            ("name", s(normalized)),
            ("system", s(id)),
        ]
    };
    let store = |result: JsValue| cache(ctx, Store::Content, normalized, result);
    match consensus {
        Consensus::Conflict { groups, .. } => {
            let mut fields = head("conflict");
            fields.extend([("trust", trust), ("groups", groups)]);
            Ok(store(obj(fields)))
        }
        Consensus::NotFound { reason, error, .. } => {
            let mut fields = vec![
                ("type", s("not_found")),
                ("reason", s(reason)),
                ("name", s(normalized)),
                ("system", s(id)),
                ("trust", trust),
            ];
            if let Some(error) = &error {
                fields.push(("error", s(&error.short_message())));
            }
            let out = obj(fields);
            if reason == "NO_CONTENTHASH" && error.is_some() {
                return Ok(out);
            }
            Ok(store(out))
        }
        Consensus::Data { resolved, .. } => {
            let unsupported = |bytes: &[u8], trust: JsValue| {
                obj(vec![
                    ("type", s("unsupported")),
                    ("reason", s("UNSUPPORTED_CONTENTHASH_FORMAT")),
                    ("name", s(normalized)),
                    ("system", s(id)),
                    ("contentHash", s(&rpc::hex(bytes))),
                    ("trust", trust),
                ])
            };
            let inner = match crate::abi::decode(&[Kind::Bytes], &resolved)
                .ok()
                .and_then(|f| f.into_iter().next())
            {
                Some(Ok(Value::Bytes(bytes))) => bytes,
                _ => return Ok(store(unsupported(&resolved, trust))),
            };
            if inner.is_empty() {
                return Ok(store(obj(vec![
                    ("type", s("not_found")),
                    ("reason", s("EMPTY_CONTENTHASH")),
                    ("name", s(normalized)),
                    ("system", s(id)),
                    ("trust", trust),
                ])));
            }
            match crate::parse_contenthash(&inner) {
                None => Ok(store(unsupported(&inner, trust))),
                Some(content) => {
                    let mut fields = head("ok");
                    fields.extend([
                        ("codec", s(content.codec)),
                        ("protocol", s(content.protocol)),
                        ("uri", s(&content.uri())),
                        ("decoded", s(&content.decoded)),
                        ("trust", trust),
                    ]);
                    Ok(store(obj(fields)))
                }
            }
        }
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

// ---------------------------------------------------------------------------
// Address.

/// `ensCoinType`: `Err` is today's thrown "Invalid ENS destination chain ID".
pub(crate) fn coin_type(chain_id: f64) -> Result<u64, Thrown> {
    const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
    if !(chain_id.fract() == 0.0 && chain_id.abs() <= MAX_SAFE)
        || chain_id < 1.0
        || chain_id >= 2_147_483_648.0
    {
        return Err(Thrown::new("Invalid ENS destination chain ID"));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let chain = chain_id as u64;
    Ok(if chain == 1 { 60 } else { chain + 0x8000_0000 })
}

fn no_address(normalized: &str) -> Vec<(&'static str, JsValue)> {
    vec![
        ("success", JsValue::Bool(false)),
        ("name", s(normalized)),
        ("reason", s("NO_ADDRESS")),
        (
            "error",
            s(&format!("No address record set for {normalized}")),
        ),
    ]
}

/// `doResolveEnsAddress`.
pub(crate) async fn address(
    ctx: &Ctx,
    machine: &super::machine::Shared,
    normalized: &str,
    chain_id: u64,
) -> Result<JsValue, Thrown> {
    let key = chain_key(normalized, chain_id);
    let store = |result: JsValue| cache(ctx, Store::Address, &key, result);
    let node = crate::namehash(normalized).map_err(|e| Thrown::new(e.to_string()))?;
    let system = NameSystem::for_name(normalized);
    let id = system.id();
    if chain_id != 1 && system.registry().is_some() {
        return Ok(store(obj(vec![
            ("success", JsValue::Bool(false)),
            ("name", s(normalized)),
            ("system", s(id)),
            ("reason", s("CHAIN_UNSUPPORTED")),
            (
                "error",
                s(&format!(
                    "{} names resolve on Ethereum mainnet only — {normalized} has no address record for this network",
                    label(system)
                )),
            ),
        ])));
    }
    let multicoin = chain_id != 1;
    let call_data = if multicoin {
        #[allow(clippy::cast_precision_loss)]
        let coin = coin_type(chain_id as f64)?;
        ur::addr_multicoin_call(&node, coin)
    } else {
        ur::addr_call(&node)
    };
    let resolver = if system.registry().is_some() {
        Resolver::NameNft(system)
    } else {
        Resolver::Ur
    };
    let lookup = Lookup {
        name: normalized,
        call_data: &call_data,
        system: id,
        resolver,
        prefetch: false,
    };
    let consensus = consensus_resolve(ctx, machine, &lookup).await?;
    let trust = consensus.trust().clone();
    let failure = |reason: &str, error: Option<String>, trust: JsValue| {
        let mut fields = vec![
            ("success", JsValue::Bool(false)),
            ("name", s(normalized)),
            ("system", s(id)),
            ("reason", s(reason)),
        ];
        fields.push(("error", error.map_or(JsValue::Null, |e| s(&e))));
        fields.push(("trust", trust));
        obj(fields)
    };
    let none = |trust: JsValue| {
        let mut fields = no_address(normalized);
        fields.extend([("system", s(id)), ("trust", trust)]);
        obj(fields)
    };
    match consensus {
        Consensus::Conflict { groups, .. } => Ok(store(obj(vec![
            ("success", JsValue::Bool(false)),
            ("name", s(normalized)),
            ("system", s(id)),
            ("reason", s("CONFLICT")),
            ("trust", trust),
            ("groups", groups),
        ]))),
        Consensus::NotFound {
            reason: "NO_CONTENTHASH",
            error,
            ..
        } => Ok(store(failure(
            "RESOLUTION_ERROR",
            error.map(|e| e.short_message()),
            trust,
        ))),
        Consensus::NotFound { .. } => Ok(store(none(trust))),
        Consensus::Data { resolved, .. } => {
            if resolved.is_empty() {
                return Ok(store(none(trust)));
            }
            let kind = if multicoin {
                Kind::Bytes
            } else {
                Kind::Address
            };
            let decoded = crate::abi::decode(&[kind], &resolved)
                .ok()
                .and_then(|f| f.into_iter().next());
            let address: Option<[u8; 20]> = match decoded {
                Some(Ok(Value::Address(address))) => Some(address),
                Some(Ok(Value::Bytes(bytes))) if bytes.is_empty() => Some([0; 20]),
                Some(Ok(Value::Bytes(bytes))) => <[u8; 20]>::try_from(bytes.as_slice()).ok(),
                _ => None,
            };
            let Some(address) = address else {
                return Ok(store(failure(
                    "RESOLUTION_ERROR",
                    Some("Invalid EVM address record".into()),
                    trust,
                )));
            };
            if address == [0; 20] {
                return Ok(store(none(trust)));
            }
            Ok(store(obj(vec![
                ("success", JsValue::Bool(true)),
                ("name", s(normalized)),
                ("system", s(id)),
                ("address", s(&checksum(&address))),
                ("trust", trust),
            ])))
        }
    }
}

/// EIP-55, as ethers' `getAddress` writes it.
fn checksum(address: &[u8; 20]) -> String {
    use sha3::{Digest, Keccak256};
    let lower: String = address.iter().map(|b| format!("{b:02x}")).collect();
    let hash = Keccak256::digest(lower.as_bytes());
    let mut out = String::from("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
        out.push(if c.is_ascii_alphabetic() && nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Reverse.

fn no_reverse(address: &str, trust: Option<JsValue>) -> JsValue {
    let mut fields = vec![
        ("success", JsValue::Bool(false)),
        ("address", s(address)),
        ("reason", s("NO_REVERSE")),
        ("error", s(&format!("No primary name set for {address}"))),
    ];
    if let Some(trust) = trust {
        fields.push(("trust", trust));
    }
    obj(fields)
}

fn unverified_reverse(
    address: &str,
    system: NameSystem,
    claimed: Option<&str>,
    detail: Option<String>,
    trust: Option<JsValue>,
) -> JsValue {
    let mut fields = vec![
        ("success", JsValue::Bool(false)),
        ("address", s(address)),
        ("system", s(system.id())),
        ("reason", s("UNVERIFIED")),
        (
            "claimedName",
            claimed.filter(|c| !c.is_empty()).map_or(JsValue::Null, s),
        ),
        (
            "error",
            s(&detail.unwrap_or_else(|| {
                format!("Reverse record for {address} does not forward-verify")
            })),
        ),
    ];
    if let Some(trust) = trust {
        fields.push(("trust", trust));
    }
    obj(fields)
}

fn reverse_conflict(address: &str, system: NameSystem, groups: JsValue, trust: JsValue) -> JsValue {
    obj(vec![
        ("success", JsValue::Bool(false)),
        ("address", s(address)),
        ("system", s(system.id())),
        ("reason", s("CONFLICT")),
        (
            "error",
            s(&format!(
                "Providers disagreed about the reverse record for {address}"
            )),
        ),
        ("trust", trust),
        ("groups", groups),
    ])
}

/// `resolveEnsReverseWithMethod`: `Ok(None)` when unavailable.
async fn ens_reverse_with(
    ctx: &Ctx,
    machine: &super::machine::Shared,
    method: &str,
    address: &str,
    coin_type: u64,
) -> Result<Option<JsValue>, Thrown> {
    let lookup = Lookup {
        name: address,
        call_data: &[],
        system: "ens",
        resolver: Resolver::UrReverse { coin_type },
        prefetch: false,
    };
    let Some(outcome) = with_method(ctx, machine, method, &lookup).await? else {
        return Ok(None);
    };
    Ok(Some(match outcome {
        Consensus::Conflict { groups, trust } => {
            reverse_conflict(address, NameSystem::Ens, groups, trust)
        }
        Consensus::NotFound { trust, .. } => no_reverse(address, Some(trust)),
        Consensus::Data { resolved, trust } => {
            let decoded = crate::abi::decode(&[Kind::Uint256, Kind::String], &resolved).ok();
            let (status, detail) = match decoded.as_deref() {
                Some([Ok(Value::Uint256(word)), Ok(Value::String(detail))]) => {
                    (word[31], detail.clone())
                }
                _ => (0, String::new()),
            };
            match status {
                1 => obj(vec![
                    ("success", JsValue::Bool(true)),
                    ("address", s(address)),
                    ("name", s(&detail)),
                    ("system", s("ens")),
                    ("trust", trust),
                ]),
                2 => unverified_reverse(address, NameSystem::Ens, Some(&detail), None, Some(trust)),
                3 => obj(vec![
                    ("success", JsValue::Bool(false)),
                    ("address", s(address)),
                    ("system", s("ens")),
                    ("reason", s("RESOLUTION_ERROR")),
                    // The identity agreed on; the display text is its class.
                    ("error", s(&display_of(&detail))),
                    ("trust", trust),
                ]),
                _ => no_reverse(address, Some(trust)),
            }
        }
    }))
}

/// The display text for an agreement identity: its class's short message.
fn display_of(identity: &str) -> String {
    identity
        .split('|')
        .nth(1)
        .filter(|_| identity.starts_with("CALL_EXCEPTION|"))
        .unwrap_or(identity)
        .to_owned()
}

/// `resolveContractBackedReverseWithMethod`.
async fn contract_backed_reverse(
    ctx: &Ctx,
    machine: &super::machine::Shared,
    method: &str,
    address: &str,
    ens: JsValue,
) -> Result<Option<JsValue>, Thrown> {
    if ens.get("reason") != Some(&s("NO_REVERSE")) {
        return Ok(Some(ens));
    }
    let Some(bytes) = rpc::hex_string(address).and_then(|b| <[u8; 20]>::try_from(b).ok()) else {
        return Ok(Some(ens));
    };
    let mut first_unverified: Option<JsValue> = None;
    let mut last_trust = ens.get("trust").cloned();
    for system in [NameSystem::Wns, NameSystem::Gns] {
        let call = ur::reverse_resolve_call(&bytes);
        let synthetic = format!(
            "reverse.{}",
            if system == NameSystem::Wns {
                "wei"
            } else {
                "gwei"
            }
        );
        let lookup = Lookup {
            name: &synthetic,
            call_data: &call,
            system: system.id(),
            resolver: Resolver::NameNftReverse(system),
            prefetch: false,
        };
        let Some(outcome) = with_method(ctx, machine, method, &lookup).await? else {
            return Ok(None);
        };
        last_trust = Some(outcome.trust().clone());
        let (resolved, reverse_trust) = match outcome {
            Consensus::Conflict { groups, trust } => {
                return Ok(Some(reverse_conflict(address, system, groups, trust)));
            }
            Consensus::NotFound { .. } => continue,
            Consensus::Data { resolved, trust } => (resolved, trust),
        };
        let claimed = match crate::abi::decode(&[Kind::String], &resolved)
            .ok()
            .and_then(|f| f.into_iter().next())
        {
            Some(Ok(Value::String(claimed))) => claimed,
            _ => {
                return Err(Thrown::new(format!(
                    "invalid {} reverse response",
                    label(system)
                )));
            }
        };
        if claimed.is_empty() {
            continue;
        }
        if NameSystem::for_name(&claimed) != system {
            first_unverified.get_or_insert_with(|| {
                unverified_reverse(
                    address,
                    system,
                    Some(&claimed),
                    Some(format!(
                        "Reverse record for {address} claims a non-{} name",
                        label(system)
                    )),
                    Some(reverse_trust.clone()),
                )
            });
            continue;
        }
        let mut forward_trust = None;
        if let Ok(normalized) = fast_normalize(crate::js_trim(&claimed))
            && let Ok(node) = crate::namehash(&normalized)
        {
            let forward_call = ur::addr_call(&node);
            let forward = Lookup {
                name: &normalized,
                call_data: &forward_call,
                system: system.id(),
                resolver: Resolver::NameNft(system),
                prefetch: false,
            };
            if let Ok(Some(outcome)) = with_method(ctx, machine, method, &forward).await {
                forward_trust = Some(outcome.trust().clone());
                if let Consensus::Data { resolved, trust } = outcome
                    && let Some(Ok(Value::Address(found))) =
                        crate::abi::decode(&[Kind::Address], &resolved)
                            .ok()
                            .and_then(|f| f.into_iter().next())
                    && rpc::hex(&found) == address
                {
                    return Ok(Some(obj(vec![
                        ("success", JsValue::Bool(true)),
                        ("address", s(address)),
                        ("name", s(&normalized)),
                        ("system", s(system.id())),
                        ("trust", trust),
                    ])));
                }
            }
        }
        first_unverified.get_or_insert_with(|| {
            unverified_reverse(
                address,
                system,
                Some(&claimed),
                None,
                Some(forward_trust.unwrap_or(reverse_trust)),
            )
        });
    }
    Ok(Some(
        first_unverified.unwrap_or_else(|| no_reverse(address, last_trust)),
    ))
}

/// `doResolveEnsReverse`.
pub(crate) async fn reverse(
    ctx: &Ctx,
    machine: &super::machine::Shared,
    address: &str,
    chain_id: u64,
) -> Result<JsValue, Thrown> {
    #[allow(clippy::cast_precision_loss)]
    let coin = coin_type(chain_id as f64)?;
    let (order, prefer_verified) = {
        let state = ctx.state.borrow();
        (state.config.order.clone(), state.config.prefer_verified)
    };
    let key = chain_key(address, chain_id);
    let mut provisional: Option<JsValue> = None;
    let mut last_error: Option<Thrown> = None;
    for method in &order {
        let attempt = async {
            let Some(ens) = ens_reverse_with(ctx, machine, method, address, coin).await? else {
                return Ok(None);
            };
            if chain_id != 1 {
                return Ok(Some(ens));
            }
            contract_backed_reverse(ctx, machine, method, address, ens).await
        };
        let result = match attempt.await {
            Ok(Some(result)) => result,
            Ok(None) => continue,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let level = result
            .get("trust")
            .and_then(|t| t.get("level"))
            .and_then(JsValue::as_str);
        let provisional_result =
            level == Some("unverified") || result.get("reason") == Some(&s("UNVERIFIED"));
        if prefer_verified && provisional_result {
            if provisional.is_none() {
                provisional = Some(result);
            }
            continue;
        }
        return Ok(cache(ctx, Store::Reverse, &key, result));
    }
    if let Some(result) = provisional {
        return Ok(cache(ctx, Store::Reverse, &key, result));
    }
    Err(last_error.unwrap_or_else(|| {
        Thrown::new(format!(
            "No enabled name-resolution method could reverse-resolve {address}"
        ))
    }))
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
