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

/// Why a call failed, with what classification and agreement need.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CallError {
    Rpc(RpcError),
    /// ethers refused the call's arguments (`dnsEncode`) or its answer
    /// (`decodeFunctionResult`, an `OffchainLookup` that won't decode).
    Invalid,
    /// `CCIP sender does not match the Universal Resolver`.
    SenderMismatch,
    /// Every gateway failed: `CCIP_GATEWAY_FAILED`.
    GatewaysFailed,
    /// `CCIP recursion limit exceeded`.
    RecursionLimit,
    /// The leg's deadline.
    Timeout,
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

    /// `isResolverNotFoundError`: the selector, or an `Error(string)`
    /// reason naming the error (what the reference's message match sees).
    fn resolver_not_found(&self) -> bool {
        let selector = self
            .revert_source()
            .map(|s| s.get(..10).unwrap_or("").to_ascii_lowercase());
        if matches!(selector.as_deref(), Some("0x77209fe8" | "0x1e9535f2")) {
            return true;
        }
        self.reason().is_some_and(|reason| {
            let lower = reason.to_ascii_lowercase();
            lower.contains("resolvernotfound") || lower.contains("resolvernotcontract")
        })
    }

    /// The `Error(string)` reason ethers decodes from revert data.
    fn reason(&self) -> Option<String> {
        let data = match self {
            CallError::Rpc(RpcError::CallException {
                data: Some(data), ..
            }) => data,
            _ => return None,
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

    /// The core's provider-failure rules (design 0004, Classification).
    fn provider_failure(&self) -> bool {
        match self {
            CallError::Timeout => true,
            CallError::Rpc(error) => match error {
                RpcError::Transport(_)
                | RpcError::Http(_)
                | RpcError::NotJson
                | RpcError::MissingResponse => true,
                RpcError::BadResult => true,
                RpcError::CallException { data: Some(_), .. } => false,
                RpcError::CallException {
                    data: None,
                    node: Some(node),
                } => node_failure(node),
                RpcError::CallException {
                    data: None,
                    node: None,
                } => false,
                RpcError::Coalesce(_) => false,
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
            CallError::Invalid => "could not decode result data".into(),
            CallError::SenderMismatch => "CCIP sender does not match the Universal Resolver".into(),
            CallError::GatewaysFailed => {
                "CCIP gateways unavailable or returned invalid data".into()
            }
            CallError::RecursionLimit => "CCIP recursion limit exceeded".into(),
        }
    }
}

/// Rules 5–8: the node's own error, without revert evidence.
fn node_failure(node: &rpc::NodeError) -> bool {
    let code = node.code();
    if code == Some(-32603.0) {
        return true;
    }
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

/// `callUniversalResolver(provider, 'resolve', …)` at a pinned block.
async fn universal_resolver_call(
    ctx: &Ctx,
    provider: &mut Provider,
    name: &str,
    call_data: &[u8],
    block: &str,
    used_gateway: &RefCell<bool>,
) -> Result<Vec<u8>, CallError> {
    let dns = crate::dns_encode(name, 255).map_err(|_| CallError::Invalid)?;
    let first = Method::Call {
        to: ur::UNIVERSAL_RESOLVER,
        data: ur::encode_resolve(&dns, call_data),
        block: block.into(),
    };
    let mut error = match provider.send(ctx, &first).await {
        Ok(result) => return decode_resolve(&result),
        Err(e) => CallError::Rpc(e),
    };
    for _round in 0..10 {
        let Some(source) = error.revert_source() else {
            return Err(error);
        };
        if !source.to_ascii_lowercase().starts_with("0x556f1830") {
            return Err(error);
        }
        let data = rpc::hex_string(&source).ok_or(CallError::Invalid)?;
        let lookup = ur::decode_offchain_lookup(&data).ok_or(CallError::Invalid)?;
        if lookup.sender != ur::UNIVERSAL_RESOLVER {
            return Err(CallError::SenderMismatch);
        }
        *used_gateway.borrow_mut() = true;
        let response = ccip_read_fetch(ctx, &lookup).await?;
        let callback = Method::Call {
            to: lookup.sender,
            data: ur::encode_callback(lookup.callback, &response, &lookup.extra_data),
            block: block.into(),
        };
        match provider.send(ctx, &callback).await {
            Ok(result) => return decode_resolve(&result),
            Err(next) => error = CallError::Rpc(next),
        }
    }
    Err(CallError::RecursionLimit)
}

/// `decodeFunctionResult('resolve', raw)`, both fields read.
fn decode_resolve(result: &JsValue) -> Result<Vec<u8>, CallError> {
    let raw = rpc::call_result(result).map_err(CallError::Rpc)?;
    let fields =
        ur::decode_result(&[Kind::Bytes, Kind::Address], &raw).map_err(|_| CallError::Invalid)?;
    match (fields.first(), fields.get(1)) {
        (Some(Ok(Value::Bytes(resolved))), Some(Ok(Value::Address(_)))) => Ok(resolved.clone()),
        _ => Err(CallError::Invalid),
    }
}

const CCIP_TIMEOUT_MS: Ms = 15_000;

/// `ccipReadFetch`: each URL in order, 15 s each, until one answers hex.
async fn ccip_read_fetch(ctx: &Ctx, lookup: &ur::OffchainLookup) -> Result<Vec<u8>, CallError> {
    for template in &lookup.urls {
        // A URL that won't decode throws out of the loop, as the JS
        // iteration does.
        let template = template.as_ref().map_err(|_| CallError::Invalid)?;
        let Some(request) =
            crate::ccip::gateway_request(template, &lookup.sender, &lookup.call_data)
        else {
            continue;
        };
        let fetch = ctx.rt.request(Request::Gateway {
            url: request.url,
            body: request.body,
        });
        match race(fetch, ctx.rt.sleep(CCIP_TIMEOUT_MS)).await {
            Either::Left(Answer::Gateway { status, body }) if (200..300).contains(&status) => {
                if let Some(data) = crate::ccip::parse_gateway_response(&body) {
                    return Ok(data);
                }
            }
            _ => {}
        }
    }
    Err(CallError::GatewaysFailed)
}

/// `runQuorumLeg`.
async fn run_leg(
    ctx: &Ctx,
    endpoint: &str,
    name: &str,
    call_data: &[u8],
    block: &str,
    timeout: f64,
) -> Leg {
    let mut provider = Provider::new(endpoint);
    let used_gateway = RefCell::new(false);
    let call = universal_resolver_call(ctx, &mut provider, name, call_data, block, &used_gateway);
    let outcome = with_timeout(ctx, timeout, call).await;
    let error = match outcome {
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

/// `runConsensusWave`: legs at once; the first M-sized bucket ends it.
/// One call every leg of a wave makes.
#[derive(Clone, Copy)]
struct LegCall<'a> {
    name: &'a str,
    call_data: &'a [u8],
    block: &'a str,
    timeout: f64,
}

async fn run_wave(
    ctx: &Ctx,
    machine: &super::machine::Shared,
    endpoints: &[Endpoint],
    call: &LegCall<'_>,
    m: f64,
    prefetch: bool,
) -> Wave {
    let LegCall {
        name,
        call_data,
        block,
        timeout,
    } = *call;
    let mut legs: Vec<Option<Pin<Box<dyn Future<Output = Leg> + '_>>>> = endpoints
        .iter()
        .map(|endpoint| {
            Some(
                Box::pin(run_leg(ctx, endpoint, name, call_data, block, timeout))
                    as Pin<Box<dyn Future<Output = Leg>>>,
            )
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
                    if !first_data && prefetch {
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
    JsValue::Object(vec![
        ("level".into(), s(level)),
        ("system".into(), s(system)),
        (
            "block".into(),
            JsValue::Object(vec![
                ("number".into(), number(block.0)),
                ("hash".into(), s(&block.1)),
            ]),
        ),
        ("agreed".into(), refs(agreed)),
        ("dissented".into(), refs(dissented)),
        ("queried".into(), refs(queried)),
        (
            "quorum".into(),
            JsValue::Object(vec![
                ("k".into(), JsValue::Number(k)),
                ("m".into(), JsValue::Number(m)),
                ("achieved".into(), JsValue::Bool(level == "verified")),
            ]),
        ),
    ])
}

/// `resolveSingleSourceUnverified`.
async fn single_source(
    ctx: &Ctx,
    endpoint: &str,
    name: &str,
    call_data: &[u8],
    system: &str,
) -> Result<Consensus, Thrown> {
    let tag = ctx.anchor_tag();
    let timeout = ctx.timeout_ms();
    let block = single_source_anchor(ctx, endpoint, &tag, timeout)
        .await
        .map_err(|message| {
            Thrown::new(format!("Single-provider anchor fetch failed: {message}"))
        })?;
    let leg = run_leg(ctx, endpoint, name, call_data, &block.1, timeout).await;
    let one = [endpoint.to_owned()];
    let trust = build_trust("unverified", system, &one, &[], &one, (1.0, 1.0), &block);
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
    name: &str,
    call_data: &[u8],
    system: &str,
    prefetch: bool,
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
        return single_source(ctx, &first, name, call_data, system).await;
    }
    let Some(block) = pinned_block(ctx).await? else {
        let fresh = ctx.available();
        return single_source(
            ctx,
            fresh.first().unwrap_or(&first),
            name,
            call_data,
            system,
        )
        .await;
    };
    let wave_available = ctx.available();
    if wave_available.len() < MIN_QUORUM_PROVIDERS {
        return single_source(
            ctx,
            wave_available.first().unwrap_or(&first),
            name,
            call_data,
            system,
        )
        .await;
    }
    #[allow(clippy::cast_precision_loss)]
    let effective_k = js::min(k, wave_available.len() as f64);
    let effective_m = js::min(m, effective_k);
    let first_selection: Vec<Endpoint> =
        wave_available[..js::slice_end(effective_k, wave_available.len())].to_vec();
    let leg_call = LegCall {
        name,
        call_data,
        block: &block.1,
        timeout,
    };

    let mut wave = run_wave(
        ctx,
        machine,
        &first_selection,
        &leg_call,
        effective_m,
        prefetch,
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
                    &leg_call,
                    js::min(m, second_k),
                    prefetch,
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
            "All {} RPC providers failed for {name}",
            wave.queried.len()
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
                groups.push(JsValue::Object(vec![
                    ("resolvedData".into(), s(&rpc::hex(&bytes))),
                    ("urls".into(), refs(&members)),
                ]));
            }
            for (reason, members) in negative_buckets(&wave) {
                groups.push(JsValue::Object(vec![
                    ("resolvedData".into(), JsValue::Null),
                    ("reason".into(), s(reason)),
                    ("urls".into(), refs(&members)),
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

/// `tryDirectResolve`: `Ok(None)` when unavailable.
async fn direct(ctx: &Ctx, name: &str, call_data: &[u8], system: &str) -> Option<Consensus> {
    let direct = ctx.state.borrow().config.direct.clone()?;
    let tag = ctx.anchor_tag();
    let timeout = ctx.timeout_ms();
    let block = single_source_anchor(ctx, &direct.endpoint, &tag, timeout)
        .await
        .ok()?;
    let leg = run_leg(ctx, &direct.endpoint, name, call_data, &block.1, timeout).await;
    let level = if direct.user_configured {
        "user-configured"
    } else {
        "unverified"
    };
    let one = [direct.endpoint.clone()];
    let trust = build_trust(level, system, &one, &[], &one, (1.0, 1.0), &block);
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

/// `consensusResolve`.
async fn consensus_resolve(
    ctx: &Ctx,
    machine: &super::machine::Shared,
    name: &str,
    call_data: &[u8],
    system: &str,
    prefetch: bool,
) -> Result<Consensus, Thrown> {
    let (order, prefer_verified) = {
        let state = ctx.state.borrow();
        (state.config.order.clone(), state.config.prefer_verified)
    };
    let mut provisional: Option<Consensus> = None;
    let mut last_error: Option<Thrown> = None;
    for method in &order {
        let result = match method.as_str() {
            "quorum" => via_quorum(ctx, machine, name, call_data, system, prefetch)
                .await
                .map(Some),
            "direct" => Ok(direct(ctx, name, call_data, system).await),
            // Myotis and Colibri arrive with the verified operations.
            _ => Ok(None),
        };
        let result = match result {
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
            "No enabled name-resolution method could resolve {name}"
        ))
    }))
}

// ---------------------------------------------------------------------------
// Content.

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

fn cache_content(ctx: &Ctx, name: &str, result: JsValue) -> JsValue {
    let ttl = ttl_for(&result);
    let now = ctx.now();
    ctx.state
        .borrow_mut()
        .content
        .set(name, result.clone(), ctx.now_f() + ttl, now);
    result
}

/// `doResolveEnsContent`.
pub(crate) async fn content(
    ctx: &Ctx,
    machine: &super::machine::Shared,
    normalized: &str,
) -> Result<JsValue, Thrown> {
    let node = crate::namehash(normalized).map_err(|e| Thrown::new(e.to_string()))?;
    let call_data = ur::contenthash_call(&node);
    let system = NameSystem::for_name(normalized);
    if system.registry().is_some() {
        // NameNFT names arrive with their own call path.
        return Err(Thrown::new("NameNFT resolution is not implemented yet"));
    }
    let id = system.id();
    let consensus = consensus_resolve(ctx, machine, normalized, &call_data, id, true).await?;
    let trust = consensus.trust().clone();
    let base = |kind: &str| {
        vec![
            ("type".to_owned(), s(kind)),
            ("name".to_owned(), s(normalized)),
            ("system".to_owned(), s(id)),
        ]
    };
    match consensus {
        Consensus::Conflict { groups, .. } => {
            let mut fields = vec![
                ("type".to_owned(), s("conflict")),
                ("name".to_owned(), s(normalized)),
                ("system".to_owned(), s(id)),
            ];
            fields.push(("trust".into(), trust));
            fields.push(("groups".into(), groups));
            Ok(cache_content(ctx, normalized, JsValue::Object(fields)))
        }
        Consensus::NotFound { reason, error, .. } => {
            let mut fields = vec![
                ("type".to_owned(), s("not_found")),
                ("reason".to_owned(), s(reason)),
                ("name".to_owned(), s(normalized)),
                ("system".to_owned(), s(id)),
            ];
            fields.push(("trust".into(), trust));
            if let Some(error) = &error {
                fields.push(("error".into(), s(&error.short_message())));
            }
            let out = JsValue::Object(fields);
            if reason == "NO_CONTENTHASH" && error.is_some() {
                return Ok(out);
            }
            Ok(cache_content(ctx, normalized, out))
        }
        Consensus::Data { resolved, .. } => {
            let inner = match crate::abi::decode(&[Kind::Bytes], &resolved) {
                Ok(fields) => match fields.into_iter().next() {
                    Some(Ok(Value::Bytes(bytes))) => Some(bytes),
                    _ => None,
                },
                Err(_) => None,
            };
            let Some(inner) = inner else {
                let mut fields = vec![
                    ("type".to_owned(), s("unsupported")),
                    ("reason".to_owned(), s("UNSUPPORTED_CONTENTHASH_FORMAT")),
                    ("name".to_owned(), s(normalized)),
                    ("system".to_owned(), s(id)),
                ];
                fields.push(("contentHash".into(), s(&rpc::hex(&resolved))));
                fields.push(("trust".into(), trust));
                return Ok(cache_content(ctx, normalized, JsValue::Object(fields)));
            };
            if inner.is_empty() {
                let mut fields = vec![
                    ("type".to_owned(), s("not_found")),
                    ("reason".to_owned(), s("EMPTY_CONTENTHASH")),
                    ("name".to_owned(), s(normalized)),
                    ("system".to_owned(), s(id)),
                ];
                fields.push(("trust".into(), trust));
                return Ok(cache_content(ctx, normalized, JsValue::Object(fields)));
            }
            match crate::parse_contenthash(&inner) {
                None => {
                    let mut fields = vec![
                        ("type".to_owned(), s("unsupported")),
                        ("reason".to_owned(), s("UNSUPPORTED_CONTENTHASH_FORMAT")),
                        ("name".to_owned(), s(normalized)),
                        ("system".to_owned(), s(id)),
                    ];
                    fields.push(("contentHash".into(), s(&rpc::hex(&inner))));
                    fields.push(("trust".into(), trust));
                    Ok(cache_content(ctx, normalized, JsValue::Object(fields)))
                }
                Some(content) => {
                    let mut fields = base("ok");
                    fields.push(("codec".into(), s(content.codec)));
                    fields.push(("protocol".into(), s(content.protocol)));
                    fields.push(("uri".into(), s(&content.uri())));
                    fields.push(("decoded".into(), s(&content.decoded)));
                    fields.push(("trust".into(), trust));
                    Ok(cache_content(ctx, normalized, JsValue::Object(fields)))
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
}
