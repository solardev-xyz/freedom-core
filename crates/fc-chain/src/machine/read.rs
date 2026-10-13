//! A chain read: the router's `request()`, the sources it tries
//! (`requestSource`: Myotis, Colibri, the quorum, Direct, Blockscout) and
//! the truncation check (design 0005, The router machine).

use std::cell::RefCell;
use std::rc::Rc;

use fc_json::index::{Index, KeyOrder, Kind};
use fc_naming::session::exec::{Either, race};

use super::config::{Chain, ms};
use super::ctx::{Release, Req, reply, started};
use super::error::{ErrorClass, Fallback, Prop, Thrown};
use super::exchange::{ResultText, exchange, owned};
use super::io::{
    Answer, ColibriClass, ColibriReply, Delivered, MyotisClass, MyotisReply, Request, VerifiedOp,
};
use super::logs::{CapReader, Keeper, LogRange, Ranker};
use super::quorum::{QuorumOptions, request_quorum};
use super::route::{colibri_key, request_target, route_key, routing_origin};
use super::trust::{colibri_trust, direct_trust};
use crate::ant::{ANT_EXCLUDE_SOURCES, ANT_INCLUDE_SOURCES, LOG_SCAN_QUORUM_TIMEOUT_MS};
use crate::js::{Element, element};
use crate::logs::{
    LOG_TRUNCATION_MIN_SPAN, LOG_TRUNCATION_TAIL_BLOCKS, block_number_value, log_query_span,
};
use crate::methods::{is_read_method, source_order, source_serves_method};
use crate::myotis::{
    MYOTIS_NOT_READY, MyotisFailure, myotis_answer, myotis_operation, myotis_trust,
};
use crate::normalize::normalize_params;
use crate::text::{SourceFailure, request_failure_text, unsupported_read_method_text};

/// `INTERACTIVE_SOURCE_DEADLINE_MS`.
pub(crate) const INTERACTIVE_SOURCE_DEADLINE_MS: f64 = 2000.0;

/// The core's text for a Myotis operation main reports as `error`,
/// `too_large` or `busy` (deviation `adapter-error-text`).
pub const MYOTIS_FAILED: &str = "Myotis operation failed";
/// The same for Colibri.
pub const COLIBRI_FAILED: &str = "Colibri request failed";

/// A read's routing options: the profile's, or a test's.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReadOptions {
    pub include_trust: bool,
    /// The routing context's origin: it makes the read interactive.
    pub origin: Option<String>,
    /// Never queue for Myotis.
    pub background: bool,
    pub exclude_sources: Vec<String>,
    pub include_sources: Vec<String>,
    /// Widens Direct's per-endpoint budget; never narrows it.
    pub direct_timeout_ms: Option<f64>,
    /// Widens the quorum's budget; never narrows it.
    pub quorum_timeout_ms: Option<f64>,
    pub ranker: Option<Ranker>,
    pub cap_reader: Option<CapReader>,
}

impl ReadOptions {
    /// The Ant profile (`ant_scan`): the bridge's log-scan options, for its
    /// `eth_getLogs`.
    pub fn ant_scan() -> Self {
        Self {
            background: true,
            exclude_sources: ANT_EXCLUDE_SOURCES
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            include_sources: ANT_INCLUDE_SOURCES
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            #[allow(clippy::cast_precision_loss)]
            quorum_timeout_ms: Some(LOG_SCAN_QUORUM_TIMEOUT_MS as f64),
            ranker: Some(Ranker::Ant),
            cap_reader: Some(CapReader::Ant),
            ..Self::default()
        }
    }
}

/// What a source answered.
pub(crate) struct SourceResult {
    pub result: ResultText,
    /// Its trust label (JSON with endpoint references), when asked for.
    pub trust: Option<String>,
}

/// A read's result: `{ result, source, verified, trust? }`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReadAnswer {
    pub result: ResultText,
    pub source: &'static str,
    pub verified: bool,
    pub trust: Option<String>,
}

/// `requestSource`'s options.
#[derive(Clone, Copy)]
pub(crate) struct SourceOptions<'a> {
    pub include_trust: bool,
    pub route_key: Option<&'a str>,
    pub fallback: Option<&'a Rc<Fallback>>,
    pub attempted: &'a [String],
    pub unanswered: &'a [String],
    pub keeper: &'a RefCell<Keeper>,
    pub allow_direct_fallback: bool,
    pub deadline: Option<f64>,
    pub background: bool,
    pub direct_timeout: Option<f64>,
    pub quorum_timeout: Option<f64>,
    pub log_range: Option<LogRange>,
    /// Set to the endpoint whose answer Direct returns.
    pub answered_by: Option<&'a RefCell<Option<String>>>,
}

/// `sourceDeadlineMs`: an interactive read caps a source at 2 s when a
/// later source exists.
pub(crate) fn source_deadline(chain: &Chain, interactive: bool, fallback: bool) -> f64 {
    if interactive && fallback {
        chain.timeout.min(INTERACTIVE_SOURCE_DEADLINE_MS)
    } else {
        chain.timeout
    }
}

/// `directUrlTimeoutMs`.
pub(crate) fn direct_url_timeout(chain: &Chain, requested: Option<f64>) -> f64 {
    match requested {
        Some(requested) if requested.is_finite() => chain.timeout.max(requested),
        _ => chain.timeout,
    }
}

/// The sources whose `eth_getLogs` answers may be cut short.
fn may_truncate(source: &str) -> bool {
    matches!(source, "colibri" | "quorum" | "direct")
}

/// `request()`: tries the sources in order.
pub(crate) async fn read(
    req: &Req,
    method: &str,
    raw_params: &str,
    options: &ReadOptions,
) -> Result<ReadAnswer, Thrown> {
    if !is_read_method(method) {
        return Err(Thrown::error(&unsupported_read_method_text(method)));
    }
    let chain = Rc::clone(&req.chain);
    let normalized = normalize_params(method, raw_params)
        .map_err(|_| Thrown::of_class(ErrorClass::SyntaxError, "The params are not valid JSON"))?;
    let params = normalized.params.as_str();
    let span = match (options.ranker, options.cap_reader) {
        (Some(_), Some(_)) => log_query_span(method, params),
        _ => None,
    };
    let log_range = span.and_then(|span| {
        Some(LogRange {
            span,
            cap: options.cap_reader?,
            ranker: options.ranker,
            learn: true,
        })
    });
    let eligible = log_range.is_some()
        && crate::blockscout::log_index_filter(chain.chain_id, params).is_some();
    let include: Vec<&str> = options.include_sources.iter().map(String::as_str).collect();
    let exclude: Vec<&str> = options.exclude_sources.iter().map(String::as_str).collect();
    let order = source_order(&chain.read_order, &include, &exclude, method, eligible);
    if order.order.is_empty() {
        return Err(Thrown::error(&crate::text::no_source_left_text(
            method,
            chain.chain_id,
            &order.configured,
            &order.dropped,
        )));
    }
    let origin = routing_origin(options.origin.as_deref());
    let interactive = origin.is_some();
    let target = request_target(method, params);
    let mut failures: Vec<(String, Option<Thrown>)> = Vec::new();
    let mut last_rpc_error: Option<Thrown> = None;
    let mut fallback: Option<Rc<Fallback>> = None;
    let mut attempted: Vec<String> = Vec::new();
    let mut unanswered: Vec<String> = Vec::new();
    let keeper = RefCell::new(Keeper::new(options.ranker));
    let limit = req.ctx.bounds.adaptive_routes;
    for (i, &named) in order.order.iter().enumerate() {
        // Every source left is one the router knows: the read order was
        // cleaned, and the only opt-in source is Blockscout.
        let Some(source) = super::config::SOURCES.iter().copied().find(|s| *s == named) else {
            continue;
        };
        let key = match (&origin, source) {
            (Some(origin), "myotis" | "colibri" | "quorum") => {
                Some(route_key(source, chain.chain_id, origin, method, &target))
            }
            _ => None,
        };
        if let Some(key) = &key
            && req.ctx.state.borrow().adaptive.unavailable(key, req.now())
        {
            failures.push((source.to_owned(), None));
            continue;
        }
        let answered_by = RefCell::new(None);
        let has_fallback = i + 1 < order.order.len();
        let deadline = source_deadline(&chain, interactive, has_fallback);
        let source_options = SourceOptions {
            include_trust: options.include_trust,
            route_key: key.as_deref(),
            fallback: if source == "direct" {
                fallback.as_ref()
            } else {
                None
            },
            attempted: if source == "direct" { &attempted } else { &[] },
            unanswered: if source == "direct" { &unanswered } else { &[] },
            keeper: &keeper,
            allow_direct_fallback: source == "quorum" && order.order.get(i + 1) == Some(&"direct"),
            deadline: Some(deadline),
            background: options.background,
            direct_timeout: options.direct_timeout_ms,
            quorum_timeout: options.quorum_timeout_ms,
            log_range: if matches!(source, "quorum" | "blockscout") {
                log_range
            } else {
                None
            },
            answered_by: (source == "direct").then_some(&answered_by),
        };
        let outcome = async {
            let answer =
                Box::pin(request_source(req, source, method, params, &source_options)).await?;
            if may_truncate(source) {
                let direct_url = answered_by.borrow().clone();
                Box::pin(check_log_truncation(
                    req,
                    source,
                    method,
                    params,
                    &answer.result,
                    &CheckOptions {
                        background: options.background,
                        direct_timeout: options.direct_timeout_ms,
                        quorum_timeout: options.quorum_timeout_ms,
                        log_range,
                        direct_url: direct_url.as_deref(),
                        deadline,
                    },
                ))
                .await?;
            }
            Ok::<SourceResult, Thrown>(answer)
        }
        .await;
        match outcome {
            Ok(answer) => {
                if let Some(key) = &key {
                    req.ctx.state.borrow_mut().adaptive.success(key);
                }
                return Ok(ReadAnswer {
                    result: answer.result,
                    source,
                    verified: matches!(source, "myotis" | "colibri" | "quorum" | "blockscout"),
                    trust: if options.include_trust {
                        answer.trust
                    } else {
                        None
                    },
                });
            }
            Err(error) => {
                // A revert, a permanent refusal or an infeasible call is
                // Myotis's answer from verified state: served as it is.
                if source == "myotis" && (error.is_revert() || error.is_myotis_refusal()) {
                    return Err(error);
                }
                if source == "quorum"
                    && let Some(miss) = &error.quorum
                {
                    if let Some(found) = &miss.fallback {
                        fallback = Some(Rc::clone(found));
                    }
                    attempted.clone_from(&miss.attempted);
                    unanswered.clone_from(&miss.unanswered);
                }
                if let Some(key) = &key {
                    let now = req.now();
                    req.ctx.state.borrow_mut().adaptive.failure(
                        key,
                        error.failure_kind(),
                        now,
                        limit,
                    );
                }
                if !error.is_unavailable() {
                    last_rpc_error = Some(error.clone());
                }
                if source != "quorum" && source != "blockscout" {
                    keeper.borrow_mut().note(&error);
                }
                if error.class == ErrorClass::TruncatedLogs {
                    return Err(error);
                }
                failures.push((source.to_owned(), Some(error)));
                let reuse = fallback.is_some() && order.order.get(i + 1) == Some(&"direct");
                if keeper.borrow().is_final() && !reuse {
                    break;
                }
            }
        }
    }
    if let Some(error) = keeper.borrow().error() {
        return Err(error.clone());
    }
    if let Some(error) = last_rpc_error {
        return Err(error);
    }
    let parts: Vec<SourceFailure<'_>> = failures
        .iter()
        .map(|(source, error)| match error {
            Some(error) => SourceFailure::Failed {
                source,
                name: error.class.name(),
                message: error.message.units(),
            },
            None => SourceFailure::Bypassed { source },
        })
        .collect();
    Err(Thrown::of_class(
        ErrorClass::Error,
        request_failure_text(method, &parts, &order.dropped),
    ))
}

/// `requestSource`.
pub(crate) async fn request_source(
    req: &Req,
    source: &str,
    method: &str,
    params: &str,
    options: &SourceOptions<'_>,
) -> Result<SourceResult, Thrown> {
    match source {
        "myotis" => {
            via_myotis(
                req,
                method,
                params,
                options.include_trust,
                options.deadline,
                options.background,
            )
            .await
        }
        "colibri" => {
            let result = colibri(req, method, params, options.route_key, options.deadline).await?;
            Ok(SourceResult {
                result,
                trust: options
                    .include_trust
                    .then(|| colibri_trust(req.chain.prover.as_ref())),
            })
        }
        "quorum" => {
            request_quorum(
                req,
                method,
                params,
                &QuorumOptions {
                    include_trust: options.include_trust,
                    allow_direct_fallback: options.allow_direct_fallback,
                    deadline: options.deadline,
                    keeper: options.keeper,
                    quorum_timeout: options.quorum_timeout,
                    log_range: options.log_range,
                    ends_at: None,
                },
            )
            .await
        }
        "blockscout" => super::blockscout::log_index(req, method, params, options).await,
        "direct" => request_direct(req, method, params, options).await,
        _ => Err(Thrown::unavailable(
            format!("Unknown chain source: {source}").as_str(),
        )),
    }
}

/// `requestViaMyotis`: one read at a time per chain, a background caller
/// only on an idle slot, one budget for the wait and the read.
async fn via_myotis(
    req: &Req,
    method: &str,
    params: &str,
    include_trust: bool,
    deadline: Option<f64>,
    background: bool,
) -> Result<SourceResult, Thrown> {
    let ctx = &req.ctx;
    let chain_id = req.chain.chain_id;
    let budget = deadline.filter(|d| *d != 0.0).unwrap_or(req.chain.timeout);
    let waiter = ctx.acquire_myotis(chain_id, !background).map_err(|()| {
        Thrown::unavailable(if background {
            "Myotis is busy with interactive reads"
        } else {
            "Myotis has too many reads queued for this workload"
        })
    })?;
    let started_at = req.now();
    if let Some(waiter) = waiter {
        let timer = started(ctx.rt.sleep(ms(budget)));
        let granted = std::future::poll_fn(|_| {
            if ctx.granted(chain_id, waiter) {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        });
        if let Either::Right(()) = race(granted, timer).await {
            ctx.abandon_myotis(chain_id, waiter);
            return Err(Thrown::source_deadline("Myotis", budget));
        }
    }
    #[allow(clippy::cast_precision_loss)]
    let elapsed = (req.now() - started_at) as f64;
    let remaining = (budget - elapsed).max(1.0);
    let timer = started(ctx.rt.sleep(ms(remaining)));
    // `requestMyotis`'s checks, then the operation, which keeps the slot
    // until main's terminal reply.
    let start = || -> Result<_, Thrown> {
        if !ctx.ready(chain_id) {
            return Err(Thrown::unavailable(MYOTIS_NOT_READY));
        }
        let operation = myotis_operation(method, params).map_err(myotis_failure)?;
        Ok(ctx.hold(
            Request::Verified(VerifiedOp::MyotisRead {
                chain_id,
                operation,
            }),
            Release::Myotis(chain_id),
        ))
    };
    let cell = match start() {
        Ok(cell) => cell,
        Err(error) => {
            ctx.release_myotis(chain_id);
            return Err(error);
        }
    };
    match race(reply(&cell), timer).await {
        Either::Left(delivered) => myotis_result(req, method, include_trust, delivered),
        Either::Right(()) => Err(Thrown::source_deadline("Myotis", remaining)),
    }
}

/// A Myotis read's outcome.
fn myotis_result(
    req: &Req,
    method: &str,
    include_trust: bool,
    delivered: Delivered,
) -> Result<SourceResult, Thrown> {
    let Delivered { answer, charge } = delivered;
    match answer {
        Answer::Myotis(MyotisReply::Read {
            payload,
            block_before,
            block_after,
        }) => {
            let json = myotis_answer(method, Some(&payload)).map_err(myotis_failure)?;
            drop(charge);
            let trust = include_trust
                .then(|| myotis_trust(block_before.as_deref(), block_after.as_deref()));
            Ok(SourceResult {
                result: owned(req, json)?,
                trust,
            })
        }
        Answer::Myotis(MyotisReply::Failure(class)) => Err(myotis_adapter_error(req, class)),
        _ => Err(Thrown::error(MYOTIS_FAILED)),
    }
}

/// What the read loop makes of a Myotis payload's failure.
pub(crate) fn myotis_failure(failure: MyotisFailure) -> Thrown {
    match failure {
        MyotisFailure::Final(refusal) => {
            let error = Thrown::of_class(ErrorClass::Error, refusal.message.clone())
                .with("code", Prop::Json(refusal.code.to_string()));
            match (refusal.kind(), &refusal.data) {
                (Some(kind), _) => error.with("myotisRefusal", Prop::string(kind)),
                (None, Some(data)) => error.with("data", Prop::Json(data.to_json())),
                (None, None) => error,
            }
        }
        MyotisFailure::Unavailable(message) => Thrown::unavailable(message),
        MyotisFailure::Error(error) => {
            Thrown::of_class(ErrorClass::from_name(error.name), error.message)
        }
    }
}

/// The adapter's own errors, rebuilt with their fixed texts and codes
/// (design 0005, Myotis read outcomes); any other failure has the core's
/// text (deviation `adapter-error-text`).
pub(crate) fn myotis_adapter_error(req: &Req, class: MyotisClass) -> Thrown {
    let name = &req.chain.display_name;
    let unavailable =
        |message: &str| Thrown::error(message).with("code", Prop::string("MYOTIS_UNAVAILABLE"));
    match class {
        MyotisClass::NotRunning => Thrown::error(&format!("{name} Myotis client is not running")),
        MyotisClass::NotReady => {
            Thrown::error(&format!("{name} Myotis verified reader is not ready"))
        }
        MyotisClass::StateChanged => {
            unavailable("Myotis state changed while the request was running")
        }
        MyotisClass::QueueFull => unavailable("Myotis request queue is full"),
        MyotisClass::QueueDeadline => unavailable("Myotis queue deadline exceeded"),
        MyotisClass::CallerDeadline => unavailable("Myotis caller deadline exceeded"),
        MyotisClass::TooLarge | MyotisClass::Busy | MyotisClass::Error => {
            Thrown::error(MYOTIS_FAILED)
        }
    }
}

/// `requestColibri`: at most 8 in flight, 2 per route, each held until
/// main's terminal reply.
async fn colibri(
    req: &Req,
    method: &str,
    params: &str,
    route_key: Option<&str>,
    deadline: Option<f64>,
) -> Result<ResultText, Thrown> {
    if !source_serves_method("colibri", method) {
        return Err(Thrown::unavailable(
            format!("Colibri does not support {method}").as_str(),
        ));
    }
    if req.chain.prover.is_none() {
        return Err(Thrown::unavailable("No Colibri prover configured"));
    }
    let chain_id = req.chain.chain_id;
    let key = route_key.map_or_else(
        || colibri_key(chain_id, method, &request_target(method, params)),
        str::to_owned,
    );
    {
        let state = req.ctx.state.borrow();
        if state.colibri.in_flight >= super::ctx::COLIBRI_IN_FLIGHT
            || state.colibri.route(&key) >= super::ctx::COLIBRI_PER_ROUTE
        {
            return Err(Thrown::unavailable(
                "Colibri is already processing this workload",
            ));
        }
    }
    let budget = deadline.filter(|d| *d != 0.0).unwrap_or(req.chain.timeout);
    let timer = started(req.ctx.rt.sleep(ms(budget)));
    req.ctx.add_colibri(&key);
    let cell = req.ctx.hold(
        Request::Verified(VerifiedOp::Colibri {
            chain_id,
            method: method.to_owned(),
            params: params.to_owned(),
            deadline_ms: ms(budget),
        }),
        Release::Colibri(key),
    );
    match race(reply(&cell), timer).await {
        Either::Left(Delivered { answer, charge }) => match answer {
            Answer::Colibri(ColibriReply::Result(json)) => {
                drop(charge);
                owned(req, json)
            }
            // A revert the prover verified, rebuilt: `execution reverted`,
            // code 3, its data.
            Answer::Colibri(ColibriReply::Revert { data }) => {
                Err(Thrown::error("execution reverted")
                    .with("code", Prop::Json("3".into()))
                    .with("data", Prop::string(&data)))
            }
            Answer::Colibri(ColibriReply::Failure(class)) => {
                let mut error = Thrown::error(COLIBRI_FAILED);
                if class == ColibriClass::Capacity {
                    error.capacity = true;
                }
                Err(error)
            }
            _ => Err(Thrown::error(COLIBRI_FAILED)),
        },
        Either::Right(()) => Err(Thrown::source_deadline("Colibri", budget)),
    }
}

/// `requestDirect`: the quorum's reusable answer, or the endpoints the
/// quorum didn't ask, one at a time; every error falls through.
async fn request_direct(
    req: &Req,
    method: &str,
    params: &str,
    options: &SourceOptions<'_>,
) -> Result<SourceResult, Thrown> {
    let chain = &req.chain;
    let configured = chain.timeout;
    let timeout = direct_url_timeout(chain, options.direct_timeout);
    let urls = chain.urls();
    if urls.is_empty() {
        return Err(Thrown::unavailable("No RPC endpoint configured"));
    }
    let set = |url: &str| {
        if let Some(cell) = options.answered_by {
            *cell.borrow_mut() = Some(url.to_owned());
        }
    };
    if let Some(fallback) = options.fallback
        && urls.contains(&fallback.url)
    {
        set(&fallback.url);
        return Ok(SourceResult {
            result: fallback.result.clone(),
            trust: options.include_trust.then(|| {
                direct_trust(
                    chain.user_configured(&fallback.url),
                    &fallback.url,
                    Some(fallback),
                )
            }),
        });
    }
    let retried: &[String] = if timeout > configured {
        options.unanswered
    } else {
        &[]
    };
    let untried = urls.iter().filter(|url| !options.attempted.contains(url));
    let retries = urls
        .iter()
        .filter(|url| options.attempted.contains(url) && retried.contains(url));
    let mut last: Option<Thrown> = None;
    for url in untried.chain(retries) {
        match exchange(req, url, method, params, timeout).await {
            Ok(result) => {
                set(url);
                return Ok(SourceResult {
                    result,
                    trust: options
                        .include_trust
                        .then(|| direct_trust(chain.user_configured(url), url, None)),
                });
            }
            Err(error) => {
                options.keeper.borrow_mut().note(&error);
                let keeper = options.keeper.borrow();
                if keeper.is_final()
                    && let Some(kept) = keeper.error()
                {
                    return Err(kept.clone());
                }
                last = Some(error);
            }
        }
    }
    Err(last.unwrap_or_else(|| Thrown::unavailable("All RPC endpoints failed")))
}

/// The options the truncation check passes on.
pub(crate) struct CheckOptions<'a> {
    pub background: bool,
    pub direct_timeout: Option<f64>,
    pub quorum_timeout: Option<f64>,
    pub log_range: Option<LogRange>,
    /// The endpoint whose answer Direct returned.
    pub direct_url: Option<&'a str>,
    pub deadline: f64,
}

/// `logTruncationProbe`: the query that checks a suspect answer.
pub(crate) struct Probe {
    pub params: String,
    pub span: u64,
    count: usize,
    oldest: u64,
    to: u64,
    full: u64,
}

impl Probe {
    /// `TruncatedLogsError`.
    pub(crate) fn error(&self) -> Thrown {
        let message = format!(
            "query matched too many logs: the RPC returned only the {} logs in the last {} blocks of the {}-block range asked, and earlier blocks match more; narrow the block range",
            self.count,
            self.to - self.oldest + 1,
            self.full
        );
        Thrown::of_class(ErrorClass::TruncatedLogs, message.as_str())
            .with("name", Prop::string("TruncatedLogsError"))
            .with("code", Prop::Json("-32005".into()))
    }
}

/// `logTruncationProbe(method, params, result)`: an answer is suspect when
/// every log falls in the last 1000 blocks of a numeric range at least
/// 2000 wide.
pub(crate) fn truncation_probe(method: &str, params: &str, result: &ResultText) -> Option<Probe> {
    let full = log_query_span(method, params)?;
    if full < LOG_TRUNCATION_MIN_SPAN {
        return None;
    }
    let text = result.as_ref()?;
    let index = Index::new(text.json()).ok()?;
    let entries = index.root();
    if entries.kind() != Kind::Array || entries.children().next().is_none() {
        return None;
    }
    let params_index = Index::new(params).ok()?;
    let Some(Element::Value(filter)) = element(params_index.root(), 0) else {
        return None;
    };
    let to = block_number_value(filter.get("toBlock"))?;
    let from = block_number_value(filter.get("fromBlock"))?;
    let mut oldest = u64::MAX;
    let mut count = 0;
    for entry in entries.children() {
        count += 1;
        let block = if entry.kind() == Kind::Object {
            block_number_value(entry.get("blockNumber"))
        } else {
            None
        }?;
        if block > to {
            return None;
        }
        oldest = oldest.min(block);
    }
    if to - oldest >= LOG_TRUNCATION_TAIL_BLOCKS {
        return None;
    }
    let to_block = match oldest.checked_sub(1) {
        Some(block) => format!("\"0x{block:x}\""),
        None => "\"0x-1\"".to_owned(),
    };
    let mut first = String::from("{");
    let mut replaced = false;
    for (n, (key, value)) in filter.properties().into_iter().enumerate() {
        if n > 0 {
            first.push(',');
        }
        first.push_str(&key.stringify(KeyOrder::Property));
        first.push(':');
        if key.is_str("toBlock") {
            first.push_str(&to_block);
            replaced = true;
        } else {
            first.push_str(&value.stringify(KeyOrder::Property));
        }
    }
    if !replaced {
        if first.len() > 1 {
            first.push(',');
        }
        first.push_str("\"toBlock\":");
        first.push_str(&to_block);
    }
    first.push('}');
    let mut out = format!("[{first}");
    for rest in params_index.root().children().skip(1) {
        out.push(',');
        out.push_str(&rest.stringify(KeyOrder::Property));
    }
    out.push(']');
    Some(Probe {
        params: out,
        span: oldest.saturating_sub(from),
        count,
        oldest,
        to,
        full,
    })
}

/// `checkLogTruncation`: asks the same source for the blocks before a
/// suspect answer's oldest log. Logs there fail the request; an empty or
/// failed check accepts the answer.
async fn check_log_truncation(
    req: &Req,
    source: &str,
    method: &str,
    params: &str,
    result: &ResultText,
    options: &CheckOptions<'_>,
) -> Result<(), Thrown> {
    let Some(probe) = truncation_probe(method, params, result) else {
        return Ok(());
    };
    let keeper = RefCell::new(Keeper::new(None));
    let source_options = SourceOptions {
        include_trust: false,
        route_key: None,
        fallback: None,
        attempted: &[],
        unanswered: &[],
        keeper: &keeper,
        allow_direct_fallback: false,
        deadline: Some(options.deadline),
        background: options.background,
        direct_timeout: options.direct_timeout,
        quorum_timeout: options.quorum_timeout,
        log_range: match (options.log_range, source) {
            (Some(range), "quorum") => Some(LogRange {
                span: probe.span,
                learn: false,
                ..range
            }),
            _ => None,
        },
        answered_by: None,
    };
    let earlier = if source == "direct" {
        // One attempt's worth of time, and only the endpoint that answered.
        let bound = options.deadline.max(
            options
                .direct_timeout
                .filter(|t| t.is_finite())
                .unwrap_or(0.0),
        );
        let timer = started(req.ctx.rt.sleep(ms(bound)));
        let check = async {
            match options.direct_url {
                Some(url) => exchange(
                    req,
                    url,
                    method,
                    &probe.params,
                    direct_url_timeout(&req.chain, options.direct_timeout),
                )
                .await
                .map(|result| SourceResult {
                    result,
                    trust: None,
                }),
                None => {
                    Box::pin(request_source(
                        req,
                        source,
                        method,
                        &probe.params,
                        &source_options,
                    ))
                    .await
                }
            }
        };
        match race(check, timer).await {
            Either::Left(earlier) => earlier,
            Either::Right(()) => Err(Thrown::error("This operation was aborted")),
        }
    } else {
        Box::pin(request_source(
            req,
            source,
            method,
            &probe.params,
            &source_options,
        ))
        .await
    };
    let Ok(earlier) = earlier else {
        return Ok(());
    };
    let found = earlier.result.as_ref().is_some_and(|text| {
        Index::new(text.json()).is_ok_and(|index| {
            let root = index.root();
            root.kind() == Kind::Array && root.children().next().is_some()
        })
    });
    if found { Err(probe.error()) } else { Ok(()) }
}
