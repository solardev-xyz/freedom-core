//! The Tezos machine (design 0004, The Tezos machine): `resolveTezosDomain`
//! as `tezos-domains-resolver.js` runs it.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;

use super::ens::{Answer, Ctx, Request, Thrown};
use super::exec::{Either, Ms, race};
use super::js;
use super::pool::Endpoint;
use crate::jsjson::{self, JsValue};
use crate::tezos;

const MAINNET_CHAIN_ID: &str = "NetXdQprcVkpaWU";
const PROXY_CONTRACT: &str = "KT1F7JKNqwaoLzRsMio1MQC7zv3jG9dHcDdJ";
const REQUEST_TIMEOUT_MS: Ms = 8_000;
const ANCHOR_DEPTH: i64 = 8;
const MAX_HEAD_LAG_BLOCKS: i64 = 60;
const DEFAULT_TTL_MS: f64 = 5.0 * 60_000.0;
const MAX_TTL_MS: f64 = 60.0 * 60_000.0;
const NEGATIVE_TTL_MS: f64 = 30_000.0;
const UNVERIFIED_TTL_MS: f64 = 30_000.0;
const DISCOVERY_TTL_MS: f64 = 10.0 * 60_000.0;

/// A registry's discovered big maps (`discoverRegistry`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Discovery {
    records: String,
    expiry_map: String,
    record_type: JsValue,
}

impl Discovery {
    /// What a copy of it holds: its record type is the registry's own JSON,
    /// whose tree can be large (`memory-budgets`).
    fn held(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(crate::jsjson::allocation(self.records.capacity()))
            .saturating_add(crate::jsjson::allocation(self.expiry_map.capacity()))
            .saturating_add(self.record_type.held())
    }
}

/// The Tezos machine's own state: its result and discovery caches.
#[derive(Debug, Default)]
pub(crate) struct TezosState {
    pub results: RefCell<super::ens::Cache>,
    pub discovery: RefCell<Vec<(Endpoint, Discovery, f64)>>,
}

fn s(text: &str) -> JsValue {
    JsValue::string(text)
}

fn obj(fields: Vec<(&str, JsValue)>) -> JsValue {
    JsValue::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

fn reference(endpoint: &str) -> JsValue {
    obj(vec![("ref", s(endpoint))])
}

/// Why a request or step failed (each rejects its promise in the JS).
#[derive(Debug, Clone, PartialEq)]
struct Failed;

/// `rpcRequest`: 404 is `null`; other non-2xx, a timeout or a transport
/// failure reject; the body is UTF-8 (invalid sequences replaced) and JSON.
async fn rpc_request(
    ctx: &Ctx,
    endpoint: &str,
    path: String,
    post: Option<JsValue>,
) -> Result<JsValue, Failed> {
    let request = Request::Tezos {
        endpoint: endpoint.to_owned(),
        post: post.is_some(),
        path,
        body: post.map(|b| b.stringify()),
    };
    let answer = match race(ctx.rt.request(request), ctx.rt.sleep(REQUEST_TIMEOUT_MS)).await {
        Either::Left(answer) => answer,
        Either::Right(()) => return Err(Failed),
    };
    match answer {
        Answer::Tezos { status: 404, .. } => Ok(JsValue::Null),
        // Deviation `response-caps`: after the status, as `rpcRequest`
        // checks its size limit.
        Answer::Tezos { status, body }
            if (200..300).contains(&status) && !ctx.bounds().answer_fits(body.len()) =>
        {
            Err(Failed)
        }
        Answer::Tezos { status, body } if (200..300).contains(&status) => {
            jsjson::parse(&String::from_utf8_lossy(&body)).map_err(|_| Failed)
        }
        _ => Err(Failed),
    }
}

/// `fetchHead`: chain id and head header at once.
async fn fetch_head(ctx: &Ctx, endpoint: &str) -> Result<i64, Failed> {
    let chain = rpc_request(ctx, endpoint, "/chains/main/chain_id".into(), None);
    let header = rpc_request(
        ctx,
        endpoint,
        "/chains/main/blocks/head/header".into(),
        None,
    );
    let futures: Vec<super::exec::BoxFuture<'_, Result<JsValue, Failed>>> =
        vec![Box::pin(chain), Box::pin(header)];
    // `Promise.all`: the first rejection settles it, and the other request
    // is abandoned (cancelled here).
    let mut results = super::exec::try_all(futures).await?.into_iter();
    let (Some(chain), Some(header)) = (results.next(), results.next()) else {
        return Err(Failed);
    };
    if chain.as_str() != Some(MAINNET_CHAIN_ID) {
        return Err(Failed);
    }
    let level = js::to_number(header.get("level"));
    if level.fract() != 0.0 || level.abs() > 9_007_199_254_740_991.0 || level <= ANCHOR_DEPTH as f64
    {
        return Err(Failed);
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok(level as i64)
}

/// `fetchAnchor`: the hash at `level`.
async fn fetch_anchor(ctx: &Ctx, endpoint: &str, level: i64) -> Result<String, Failed> {
    let hash = rpc_request(
        ctx,
        endpoint,
        format!("/chains/main/blocks/{level}/hash"),
        None,
    )
    .await?;
    match hash.as_str() {
        Some(h) if h.starts_with('B') => Ok(h.to_owned()),
        _ => Err(Failed),
    }
}

/// `encodeURIComponent` for a block hash (base58: nothing to escape, but
/// the JS escapes it anyway).
fn encode_component(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

async fn normalized_script(
    ctx: &Ctx,
    endpoint: &str,
    block: &str,
    contract: &str,
) -> Result<JsValue, Failed> {
    let path = format!(
        "/chains/main/blocks/{}/context/contracts/{contract}/script/normalized",
        encode_component(block)
    );
    rpc_request(
        ctx,
        endpoint,
        path,
        Some(obj(vec![("unparsing_mode", s("Readable"))])),
    )
    .await
}

/// `x?.value?.[field]` on a `findAnnotatedValue` result.
fn annotated<'a>(
    type_node: Option<&'a JsValue>,
    value_node: Option<&'a JsValue>,
    annotation: &str,
) -> Result<Option<(&'a JsValue, &'a JsValue)>, Failed> {
    tezos::find_annotated_value(type_node, value_node, annotation).map_err(|_| Failed)
}

/// `discoverRegistry`.
async fn discover(ctx: &Ctx, endpoint: &str, block: &str) -> Result<Discovery, Failed> {
    let proxy = normalized_script(ctx, endpoint, block, PROXY_CONTRACT).await?;
    let proxy_type = tezos::storage_type_from_script(&proxy).map_err(|_| Failed)?;
    let contract = annotated(proxy_type.as_deref(), proxy.get("storage"), "%contract")?
        .and_then(|(_, value)| value.get("string"))
        .and_then(JsValue::as_str)
        .unwrap_or("")
        .to_owned();
    let valid = contract.len() == 36
        && contract.starts_with("KT1")
        && contract[3..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !b"0OIl".contains(&b));
    if !valid {
        return Err(Failed);
    }
    let registry = normalized_script(ctx, endpoint, block, &contract).await?;
    let registry_type = tezos::storage_type_from_script(&registry).map_err(|_| Failed)?;
    let storage = registry.get("storage");
    let records = annotated(registry_type.as_deref(), storage, "%records")?;
    let expiry = annotated(registry_type.as_deref(), storage, "%expiry_map")?;
    // `/^\d+$/.test(x?.value?.int || '')`.
    let id_of = |found: Option<(&JsValue, &JsValue)>| -> Option<String> {
        let value = found?.1.get("int").filter(|v| v.truthy())?;
        let text = value.js_string().ok()?;
        (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())).then_some(text)
    };
    let (Some(records_id), Some(expiry_id)) = (id_of(records), id_of(expiry)) else {
        return Err(Failed);
    };
    let record_type = records
        .and_then(|(t, _)| t.get("args"))
        .and_then(JsValue::as_array)
        .and_then(|args| args.get(1))
        .filter(|t| t.truthy())
        .cloned()
        .unwrap_or(JsValue::Null);
    Ok(Discovery {
        records: records_id,
        expiry_map: expiry_id,
        record_type,
    })
}

/// `resolveAtBlock`: cached discovery first; a failed lookup drops it and
/// rediscovers once.
async fn resolve_at_block(
    ctx: &Ctx,
    state: &TezosState,
    endpoint: &str,
    block: &str,
    name: &str,
) -> Result<JsValue, Failed> {
    let now = ctx.now_f();
    let fresh = |(e, _, expires): &&(Endpoint, Discovery, f64)| e == endpoint && *expires > now;
    // The copy this session keeps across its lookup counts against it,
    // before it is made: the answer it came from was another session's
    // (`memory-budgets`).
    let size = state
        .discovery
        .borrow()
        .iter()
        .find(fresh)
        .map(|(_, d, _)| d.held());
    if let Some(size) = size
        && !ctx.charge(size)
    {
        // Spent: the machine ends the session with `budget` this poll.
        return std::future::pending().await;
    }
    let cached = state
        .discovery
        .borrow()
        .iter()
        .find(fresh)
        .map(|(_, d, _)| d.clone());
    if let Some(discovery) = cached {
        match lookup(ctx, endpoint, block, name, &discovery).await {
            Ok(result) => return Ok(result),
            Err(Failed) => state
                .discovery
                .borrow_mut()
                .retain(|(e, _, _)| e != endpoint),
        }
    }
    let discovery = discover(ctx, endpoint, block).await?;
    {
        let mut cache = state.discovery.borrow_mut();
        cache.retain(|(e, _, _)| e != endpoint);
        cache.push((
            endpoint.to_owned(),
            discovery.clone(),
            ctx.now_f() + DISCOVERY_TTL_MS,
        ));
    }
    lookup(ctx, endpoint, block, name, &discovery).await
}

/// `lookupRecord`.
async fn lookup(
    ctx: &Ctx,
    endpoint: &str,
    block: &str,
    name: &str,
    discovery: &Discovery,
) -> Result<JsValue, Failed> {
    let path = format!(
        "/chains/main/blocks/{}/context/big_maps/{}/{}",
        encode_component(block),
        discovery.records,
        tezos::script_expr_hash(name.as_bytes())
    );
    let record = rpc_request(ctx, endpoint, path, None).await?;
    if !record.truthy() {
        return Ok(obj(vec![
            ("type", s("not_found")),
            ("reason", s("domain record not found")),
            ("system", s("tezos")),
        ]));
    }
    let record_type = Some(&discovery.record_type).filter(|t| t.truthy());
    let data = annotated(record_type, Some(&record), "%data")?.map(|(_, v)| v.clone());
    let expiry_key = annotated(record_type, Some(&record), "%expiry_key")?.map(|(_, v)| v.clone());
    let entries = data.as_ref().map(tezos::map_entries).unwrap_or_default();
    let mut expiry = JsValue::Null;
    let expiry_hex = expiry_key
        .as_ref()
        .filter(|k| k.get("prim").and_then(JsValue::as_str) == Some("Some"))
        .and_then(|k| k.get("args")?.as_array()?.first()?.get("bytes").cloned())
        .filter(JsValue::truthy);
    if let Some(hex) = expiry_hex {
        let key = hex.as_str().and_then(tezos::bytes_from_hex).ok_or(Failed)?;
        let path = format!(
            "/chains/main/blocks/{}/context/big_maps/{}/{}",
            encode_component(block),
            discovery.expiry_map,
            tezos::script_expr_hash(&key)
        );
        let found = rpc_request(ctx, endpoint, path, None).await?;
        let Some(text) = found
            .get("string")
            .and_then(JsValue::as_str)
            .map(str::to_owned)
        else {
            return Err(Failed);
        };
        expiry = s(&text);
        let expires = if text.is_empty() {
            f64::NAN
        } else {
            parse_rfc3339(&text)
        };
        if expires.is_finite() && expires <= ctx.wall_now() {
            return Ok(obj(vec![
                ("type", s("not_found")),
                ("reason", s("domain record expired")),
                ("expiry", expiry),
                ("system", s("tezos")),
            ]));
        }
    }
    let read = |key: &str| -> Option<Result<JsValue, tezos::MetadataError>> {
        entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| tezos::decode_json_bytes(*v))
    };
    let mut fields: Vec<(&str, Option<JsValue>)> = Vec::new();
    for key in ["web:redirect_url", "web:content_url", "td:ttl"] {
        match read(key) {
            None => fields.push((key, None)),
            Some(Ok(value)) => fields.push((key, Some(value))),
            Some(Err(error)) => {
                return Ok(obj(vec![
                    ("type", s("unsupported")),
                    (
                        "reason",
                        s(&format!(
                            "invalid Tezos Domains metadata: {}",
                            error.message()
                        )),
                    ),
                    ("system", s("tezos")),
                ]));
            }
        }
    }
    let ttl = fields[2].1.clone().unwrap_or(JsValue::Undefined);
    let published = |raw: &JsValue, redirect: bool| -> JsValue {
        let mut out = match tezos::parse_published_uri(raw, redirect) {
            tezos::Published::Web {
                protocol,
                uri,
                redirect,
            } => vec![
                ("type", s("ok")),
                ("protocol", s(&protocol)),
                ("uri", s(&uri)),
                ("redirect", JsValue::Bool(redirect)),
                ("system", s("tezos")),
            ],
            tezos::Published::Content {
                protocol,
                uri,
                decoded,
                base_path,
            } => vec![
                ("type", s("ok")),
                ("protocol", s(&protocol)),
                ("uri", s(&uri)),
                ("decoded", s(&decoded)),
                ("basePath", s(&base_path)),
                ("redirect", JsValue::Bool(false)),
                ("system", s("tezos")),
            ],
            tezos::Published::Unsupported(reason) => vec![
                ("type", s("unsupported")),
                ("reason", s(&reason)),
                ("system", s("tezos")),
            ],
        };
        out.push(("expiry", expiry.clone()));
        out.push(("ttl", ttl.clone()));
        obj(out)
    };
    if let Some(redirect) = &fields[0].1 {
        return Ok(published(redirect, true));
    }
    if let Some(content) = &fields[1].1 {
        return Ok(published(content, false));
    }
    Ok(obj(vec![
        ("type", s("not_found")),
        ("reason", s("domain has no website record")),
        ("expiry", expiry.clone()),
        ("ttl", ttl),
        ("system", s("tezos")),
    ]))
}

/// `Date.parse` for RFC 3339 timestamps and full dates (deviation
/// `tezos-expiry`: V8's other formats are unreadable here).
pub(crate) fn parse_rfc3339(text: &str) -> f64 {
    fn digits(s: &str) -> Option<i64> {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    }
    let (date, rest) = text.split_at(text.find('T').unwrap_or(text.len()));
    let parts: Vec<&str> = date.split('-').collect();
    let [y, m, d] = parts.as_slice() else {
        return f64::NAN;
    };
    let (Some(year), Some(month), Some(day)) = (
        digits(y).filter(|_| y.len() == 4),
        digits(m).filter(|_| m.len() == 2),
        digits(d).filter(|_| d.len() == 2),
    ) else {
        return f64::NAN;
    };
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return f64::NAN;
    }
    let mut ms = days_from_civil(year, month, day) as f64 * 86_400_000.0;
    if rest.is_empty() {
        return ms;
    }
    let time = &rest[1..];
    let (clock, offset_ms) = if let Some(clock) = time.strip_suffix('Z') {
        (clock, 0.0)
    } else {
        let Some(sign_at) = time.rfind(['+', '-']) else {
            return f64::NAN;
        };
        let (clock, offset) = time.split_at(sign_at);
        let sign = if offset.starts_with('-') { -1.0 } else { 1.0 };
        let hm: Vec<&str> = offset[1..].split(':').collect();
        let [oh, om] = hm.as_slice() else {
            return f64::NAN;
        };
        let (Some(oh), Some(om)) = (
            digits(oh).filter(|_| oh.len() == 2),
            digits(om).filter(|_| om.len() == 2),
        ) else {
            return f64::NAN;
        };
        if oh > 23 || om > 59 {
            return f64::NAN;
        }
        (clock, sign * (oh * 3_600_000 + om * 60_000) as f64)
    };
    let (hms, fraction) = clock.split_at(clock.find('.').unwrap_or(clock.len()));
    let fields: Vec<&str> = hms.split(':').collect();
    let [h, mi, sec] = fields.as_slice() else {
        return f64::NAN;
    };
    let (Some(h), Some(mi), Some(sec)) = (
        digits(h).filter(|_| h.len() == 2),
        digits(mi).filter(|_| mi.len() == 2),
        digits(sec).filter(|_| sec.len() == 2),
    ) else {
        return f64::NAN;
    };
    let mut millis = 0i64;
    let mut fractional = false;
    if let Some(frac) = fraction.strip_prefix('.') {
        if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return f64::NAN;
        }
        let first3: String = frac.chars().chain("000".chars()).take(3).collect();
        millis = first3.parse().unwrap_or(0);
        fractional = frac.bytes().any(|b| b != b'0');
    }
    // 24:00:00 is the end of the day only exactly: V8 reads any nonzero
    // fraction there (24:00:00.0001 too) as NaN.
    if h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi > 0 || sec > 0 || fractional)) {
        return f64::NAN;
    }
    ms += ((h * 3_600 + mi * 60 + sec) * 1_000 + millis) as f64;
    ms - offset_ms
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `semanticResultKey`.
fn semantic_key(result: &JsValue) -> String {
    let or_null = |key: &str| {
        result
            .get(key)
            .filter(|v| v.truthy())
            .cloned()
            .unwrap_or(JsValue::Null)
    };
    let ttl = match result.get("ttl") {
        None | Some(JsValue::Undefined | JsValue::Null) => JsValue::Null,
        Some(v) => v.clone(),
    };
    obj(vec![
        (
            "type",
            result.get("type").cloned().unwrap_or(JsValue::Undefined),
        ),
        ("reason", or_null("reason")),
        ("protocol", or_null("protocol")),
        ("uri", or_null("uri")),
        ("decoded", or_null("decoded")),
        ("basePath", or_null("basePath")),
        (
            "redirect",
            JsValue::Bool(result.get("redirect").is_some_and(JsValue::truthy)),
        ),
        ("expiry", or_null("expiry")),
        ("ttl", ttl),
    ])
    .stringify()
}

/// `cacheDuration`.
fn cache_duration(result: &JsValue, now: f64) -> f64 {
    if result.get("type").and_then(JsValue::as_str) != Some("ok") {
        return NEGATIVE_TTL_MS;
    }
    if result
        .get("trust")
        .and_then(|t| t.get("level"))
        .and_then(JsValue::as_str)
        != Some("verified")
    {
        return UNVERIFIED_TTL_MS;
    }
    let record_ttl = match result.get("ttl") {
        Some(JsValue::Undefined) | None => f64::NAN,
        other => js::to_number(other),
    };
    let mut duration = if record_ttl.is_finite() && record_ttl > 0.0 {
        record_ttl * 1_000.0
    } else {
        DEFAULT_TTL_MS
    };
    duration = duration.min(MAX_TTL_MS);
    let expiry = result
        .get("expiry")
        .filter(|v| v.truthy())
        .and_then(|v| v.js_string().ok())
        .unwrap_or_default();
    let expires = if expiry.is_empty() {
        f64::NAN
    } else {
        parse_rfc3339(&expiry)
    };
    if expires.is_finite() {
        duration = duration.min((expires - now).max(0.0));
    }
    duration.max(1_000.0)
}

fn hosts(endpoints: &[&Endpoint]) -> JsValue {
    JsValue::Array(endpoints.iter().map(|e| reference(e)).collect())
}

fn number(n: i64) -> JsValue {
    #[allow(clippy::cast_precision_loss)]
    JsValue::Number(n as f64)
}

#[allow(clippy::cast_precision_loss)]
fn count(n: usize) -> JsValue {
    JsValue::Number(n as f64)
}

/// `resolveTezosDomainUncached`.
pub(crate) async fn resolve(ctx: &Ctx, state: &TezosState, name: &str) -> Result<JsValue, Thrown> {
    let endpoints: Vec<Endpoint> = ctx
        .state
        .borrow()
        .config
        .tezos
        .iter()
        .take(3)
        .cloned()
        .collect();
    let error = |reason: &str| {
        obj(vec![
            ("type", s("error")),
            ("reason", s(reason)),
            ("system", s("tezos")),
        ])
    };

    let heads = super::exec::all(
        endpoints
            .iter()
            .map(|e| {
                Box::pin(async move { (e, fetch_head(ctx, e).await) })
                    as Pin<Box<dyn Future<Output = (&Endpoint, Result<i64, Failed>)> + '_>>
            })
            .collect(),
    )
    .await;
    let all_heads: Vec<(&Endpoint, i64)> = heads
        .into_iter()
        .filter_map(|(e, h)| h.ok().map(|level| (e, level)))
        .collect();
    if all_heads.is_empty() {
        return Ok(error("all Tezos RPC providers failed"));
    }
    let mut levels: Vec<i64> = all_heads.iter().map(|(_, l)| *l).collect();
    levels.sort_unstable();
    let reference_level = levels[(levels.len() - 1) / 2];
    let retained: Vec<(&Endpoint, i64)> = all_heads
        .iter()
        .copied()
        .filter(|(_, l)| (l - reference_level).abs() <= MAX_HEAD_LAG_BLOCKS)
        .collect();
    if retained.len() * 2 <= all_heads.len() {
        let mut by_level: Vec<(i64, Vec<&Endpoint>)> = Vec::new();
        for (endpoint, level) in &all_heads {
            match by_level.iter_mut().find(|(l, _)| l == level) {
                Some((_, members)) => members.push(endpoint),
                None => by_level.push((*level, vec![endpoint])),
            }
        }
        let groups = by_level
            .iter()
            .map(|(level, members)| {
                obj(vec![
                    ("value", s(&format!("chain head #{level}"))),
                    ("urls", hosts(members)),
                ])
            })
            .collect();
        return Ok(obj(vec![
            ("type", s("conflict")),
            (
                "reason",
                s("Tezos RPC providers disagree about the chain head"),
            ),
            ("system", s("tezos")),
            ("groups", JsValue::Array(groups)),
            (
                "trust",
                obj(vec![
                    ("level", s("conflict")),
                    ("system", s("tezos")),
                    ("block", JsValue::Null),
                    ("k", count(all_heads.len())),
                    ("m", count(retained.len())),
                ]),
            ),
        ]));
    }
    let anchor_level = retained.iter().map(|(_, l)| *l).min().unwrap_or(0) - ANCHOR_DEPTH;
    let anchors = super::exec::all(
        retained
            .iter()
            .map(|(e, _)| {
                Box::pin(async move { (*e, fetch_anchor(ctx, e, anchor_level).await) })
                    as Pin<Box<dyn Future<Output = (&Endpoint, Result<String, Failed>)> + '_>>
            })
            .collect(),
    )
    .await;
    let anchors: Vec<(&Endpoint, String)> = anchors
        .into_iter()
        .filter_map(|(e, h)| h.ok().map(|hash| (e, hash)))
        .collect();
    if anchors.is_empty() {
        return Ok(error("Tezos RPC providers could not anchor a block"));
    }
    let mut anchor_groups: Vec<(String, Vec<&Endpoint>)> = Vec::new();
    for (endpoint, hash) in &anchors {
        match anchor_groups.iter_mut().find(|(h, _)| h == hash) {
            Some((_, members)) => members.push(endpoint),
            None => anchor_groups.push((hash.clone(), vec![endpoint])),
        }
    }
    let mut sorted_groups = anchor_groups.clone();
    sorted_groups.sort_by_key(|group| std::cmp::Reverse(group.1.len()));
    let (best_hash, best) = sorted_groups[0].clone();
    if best.len() * 2 <= anchors.len() {
        let groups = anchor_groups
            .iter()
            .map(|(hash, members)| {
                let short = format!(
                    "{}…{}",
                    hash.chars().take(10).collect::<String>(),
                    hash.chars()
                        .rev()
                        .take(4)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect::<String>()
                );
                obj(vec![
                    ("value", s(&format!("block #{anchor_level} {short}"))),
                    ("urls", hosts(members)),
                ])
            })
            .collect();
        return Ok(obj(vec![
            ("type", s("conflict")),
            (
                "reason",
                s("Tezos RPC providers returned conflicting anchor blocks"),
            ),
            ("system", s("tezos")),
            ("groups", JsValue::Array(groups)),
            (
                "trust",
                obj(vec![
                    ("level", s("conflict")),
                    ("system", s("tezos")),
                    ("block", JsValue::Null),
                    ("k", count(anchors.len())),
                    ("m", count(best.len())),
                ]),
            ),
        ]));
    }
    let legs = super::exec::all(
        best.iter()
            .map(|e| {
                let hash = best_hash.clone();
                Box::pin(async move { (*e, resolve_at_block(ctx, state, e, &hash, name).await) })
                    as Pin<Box<dyn Future<Output = (&Endpoint, Result<JsValue, Failed>)> + '_>>
            })
            .collect(),
    )
    .await;
    let successful: Vec<(&Endpoint, JsValue)> = legs
        .into_iter()
        .filter_map(|(e, r)| r.ok().map(|v| (e, v)))
        .collect();
    if successful.is_empty() {
        return Ok(error("Tezos Domains registry lookup failed"));
    }
    let mut groups: Vec<(String, Vec<(&Endpoint, JsValue)>)> = Vec::new();
    for (endpoint, result) in &successful {
        let key = semantic_key(result);
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, members)) => members.push((endpoint, result.clone())),
            None => groups.push((key, vec![(endpoint, result.clone())])),
        }
    }
    groups.sort_by_key(|group| std::cmp::Reverse(group.1.len()));
    let block = obj(vec![
        ("number", number(anchor_level)),
        ("hash", s(&best_hash)),
    ]);
    let winner = &groups[0].1;
    if groups.len() > 1 && winner.len() * 2 <= successful.len() {
        let conflict_groups = groups
            .iter()
            .map(|(_, members)| {
                let result = &members[0].1;
                let urls = hosts(&members.iter().map(|(e, _)| *e).collect::<Vec<_>>());
                let uri = result
                    .get("uri")
                    .and_then(JsValue::as_str)
                    .filter(|u| !u.is_empty());
                match (result.get("type").and_then(JsValue::as_str), uri) {
                    (Some("ok"), Some(uri)) => {
                        let units: Vec<u16> = uri.encode_utf16().collect();
                        let value = if units.len() > 300 {
                            format!("{}…", String::from_utf16_lossy(&units[..300]))
                        } else {
                            uri.to_owned()
                        };
                        obj(vec![("value", s(&value)), ("urls", urls)])
                    }
                    _ => {
                        let reason = result
                            .get("reason")
                            .filter(|r| r.truthy())
                            .or_else(|| result.get("type"))
                            .cloned()
                            .unwrap_or(JsValue::Undefined);
                        obj(vec![
                            ("resolvedData", JsValue::Null),
                            ("reason", reason),
                            ("urls", urls),
                        ])
                    }
                }
            })
            .collect();
        return Ok(obj(vec![
            ("type", s("conflict")),
            (
                "reason",
                s("Tezos RPC providers returned conflicting results"),
            ),
            ("system", s("tezos")),
            ("groups", JsValue::Array(conflict_groups)),
            (
                "trust",
                obj(vec![
                    ("level", s("conflict")),
                    ("system", s("tezos")),
                    ("block", block),
                    ("k", count(successful.len())),
                    ("m", count(winner.len())),
                ]),
            ),
        ]));
    }
    let level = if winner.len() >= 2 {
        "verified"
    } else {
        "unverified"
    };
    // `JsValue` drops iteratively, so its members are cloned, not moved.
    let JsValue::Object(members) = &winner[0].1 else {
        return Ok(winner[0].1.clone());
    };
    let mut fields = members.clone();
    fields.push((
        "trust".into(),
        obj(vec![
            ("level", s(level)),
            ("system", s("tezos")),
            ("block", block),
            ("k", count(successful.len())),
            ("m", count(winner.len())),
            (
                "agreed",
                JsValue::Array(winner.iter().map(|(e, _)| reference(e)).collect()),
            ),
        ]),
    ));
    let result = JsValue::Object(fields);
    // Cache lifetimes run on the monotonic clock; the expiry clamp reads
    // the wall clock (design 0004, monotonic-time).
    // Deviation `reply-size`: never cache what can't be replied.
    if !ctx.bounds().reply_fits(result.stringify().len()) || ctx.over_budget() {
        return Ok(result);
    }
    let duration = cache_duration(&result, ctx.wall_now());
    state.results.borrow_mut().set(
        name,
        result.clone(),
        ctx.now_f() + duration,
        ctx.now(),
        ctx.bounds().cache_bytes,
    );
    Ok(result)
}

/// `isTezosDomainName` on the trimmed, lowercased input; `None` when it
/// isn't one (today's uncached `invalid .tez domain`).
pub(crate) fn normalize(name: &str) -> Option<String> {
    let lower = crate::js_trim(name).to_lowercase();
    tezos::is_tezos_domain_name(&lower).then_some(lower)
}

pub(crate) fn invalid() -> JsValue {
    obj(vec![
        ("type", s("not_found")),
        ("reason", s("invalid .tez domain")),
        ("system", s("tezos")),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_parses_as_date_parse_does() {
        assert_eq!(parse_rfc3339("2030-01-01T00:00:00Z"), 1_893_456_000_000.0);
        assert_eq!(parse_rfc3339("2020-01-01T00:00:00Z"), 1_577_836_800_000.0);
        assert_eq!(
            parse_rfc3339("2020-01-01T01:00:00+01:00"),
            1_577_836_800_000.0
        );
        assert_eq!(parse_rfc3339("2020-01-01T00:00:00.5Z"), 1_577_836_800_500.0);
        assert_eq!(parse_rfc3339("2020-01-01"), 1_577_836_800_000.0);
        assert!(parse_rfc3339("not a date").is_nan());
        assert!(parse_rfc3339("2020-02-30").is_nan());
        assert_eq!(parse_rfc3339("2020-01-01T24:00:00Z"), 1_577_923_200_000.0);
        assert!(parse_rfc3339("2020-01-01T24:00:00.001Z").is_nan());
        assert!(parse_rfc3339("2020-01-01T24:00:00.0001Z").is_nan());
        assert_eq!(
            parse_rfc3339("2020-01-01T24:00:00.000Z"),
            1_577_923_200_000.0
        );
    }
}
