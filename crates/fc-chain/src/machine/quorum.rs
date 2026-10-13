//! The quorum (design 0005, Quorum): `requestQuorumRound` and
//! `requestQuorum`.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::Poll;

use super::config::{ms, number_text, slice_end};
use super::ctx::{Req, started};
use super::error::{FailureKind, Fallback, Prop, QuorumMiss, Thrown};
use super::exchange::{ResultText, digest, exchange};
use super::logs::{Keeper, LogRange};
use super::read::SourceResult;
use super::trust::quorum_trust;
use crate::logs::{LOG_RANGE_REFUSAL_CODE, LOG_SCAN_QUORUM_ROUNDS, log_range_refusal_text};
use crate::stable::StableDigest;

/// A round's options.
#[derive(Clone, Copy)]
pub(crate) struct QuorumOptions<'a> {
    pub include_trust: bool,
    /// Direct comes next: members run on to the configured timeout.
    pub allow_direct_fallback: bool,
    /// The source's deadline (`sourceDeadlineMs`), if any.
    pub deadline: Option<f64>,
    pub keeper: &'a RefCell<Keeper>,
    /// A background caller's wider budget; never narrower.
    pub quorum_timeout: Option<f64>,
    pub log_range: Option<LogRange>,
    /// When a scan's rounds end together (a `Date.now()` instant).
    pub ends_at: Option<u64>,
}

type Member<'a> = Pin<Box<dyn Future<Output = Result<ResultText, Thrown>> + 'a>>;

struct Group {
    digest: StableDigest,
    count: usize,
    /// The first-arrived answer, while the group can still reach m.
    value: Option<ResultText>,
    urls: Vec<String>,
}

struct Candidate {
    index: usize,
    url: String,
    digest: StableDigest,
    /// Kept only for the lowest-index candidate: Direct's reuse.
    value: Option<ResultText>,
}

/// `requestQuorumRound`: asks `urls` at once and settles on the first m
/// that agree.
pub(crate) async fn round(
    req: &Req,
    method: &str,
    params: &str,
    urls: Vec<String>,
    options: &QuorumOptions<'_>,
) -> Result<SourceResult, Thrown> {
    let chain = &req.chain;
    let m = chain.m;
    let configured = chain.timeout;
    let budget = match options.quorum_timeout {
        Some(widened) if widened.is_finite() => configured.max(widened),
        _ => configured,
    };
    let timeout = match options.deadline {
        Some(deadline) if deadline != 0.0 && deadline < configured => deadline,
        _ => budget,
    };
    let endpoint_timeout = if options.allow_direct_fallback {
        configured
    } else {
        timeout
    };
    // The verification timer, then each member's own.
    let mut timer = Some(started(req.ctx.rt.sleep(ms(timeout))));
    let mut members: Vec<Option<Member<'_>>> = urls
        .iter()
        .map(|url| {
            Some(Box::pin(exchange(req, url, method, params, endpoint_timeout)) as Member<'_>)
        })
        .collect();
    let mut groups: Vec<Group> = Vec::new();
    let mut fulfilled: Vec<String> = Vec::new();
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut errors: Vec<Thrown> = Vec::new();
    let mut answered = vec![false; urls.len()];
    let mut pending = urls.len();
    let mut impossible = false;
    let chain_id = chain.chain_id;

    #[allow(clippy::cast_precision_loss)]
    let reaches = |count: usize| count as f64 >= m;

    enum End {
        Agreed(usize),
        Failed { deadline: bool },
    }

    let end = std::future::poll_fn(|cx| {
        for i in 0..members.len() {
            let Some(member) = members[i].as_mut() else {
                continue;
            };
            let Poll::Ready(settled) = member.as_mut().poll(cx) else {
                continue;
            };
            members[i] = None;
            pending -= 1;
            match settled {
                Ok(value) => {
                    answered[i] = true;
                    fulfilled.push(urls[i].clone());
                    let digest = match digest(req, &value) {
                        Ok(digest) => digest,
                        // Over the budget: the machine ends the request.
                        Err(_) => return Poll::Pending,
                    };
                    candidates.push(Candidate {
                        index: i,
                        url: urls[i].clone(),
                        digest,
                        value: Some(value.clone()),
                    });
                    let at = match groups.iter().position(|g| g.digest == digest) {
                        Some(at) => at,
                        None => {
                            groups.push(Group {
                                digest,
                                count: 0,
                                value: Some(value),
                                urls: Vec::new(),
                            });
                            groups.len() - 1
                        }
                    };
                    groups[at].count += 1;
                    groups[at].urls.push(urls[i].clone());
                    if reaches(groups[at].count) {
                        return Poll::Ready(End::Agreed(at));
                    }
                    if impossible {
                        return Poll::Ready(End::Failed { deadline: false });
                    }
                }
                Err(error) => {
                    options.keeper.borrow_mut().note(&error);
                    if let Some(range) = &options.log_range {
                        let now = req.now();
                        req.ctx
                            .state
                            .borrow_mut()
                            .logs
                            .note_failure(chain_id, &urls[i], range.span, &error, range, now);
                    }
                    if error.failure_kind() != Some(FailureKind::Timeout) {
                        answered[i] = true;
                    }
                    errors.push(error);
                }
            }
            // `rejectIfImpossible`.
            let largest = groups.iter().map(|g| g.count).max().unwrap_or(0);
            if !reaches(largest + pending) {
                impossible = true;
                if !options.allow_direct_fallback
                    || !candidates.is_empty()
                    || pending == 0
                    || options.keeper.borrow().is_final()
                {
                    return Poll::Ready(End::Failed { deadline: false });
                }
            }
            retain(&mut candidates, &mut groups, pending, &reaches);
        }
        if let Some(t) = timer.as_mut()
            && Pin::new(t).poll(cx).is_ready()
        {
            timer = None;
            impossible = true;
            if !options.allow_direct_fallback || !candidates.is_empty() || pending == 0 {
                return Poll::Ready(End::Failed { deadline: true });
            }
        }
        Poll::Pending
    })
    .await;
    // `finish()`: the members still running are cancelled.
    drop(timer);
    let still: Vec<bool> = members.iter().map(Option::is_some).collect();
    drop(members);
    let note_answers = |fulfilled: &[String]| {
        if let Some(range) = &options.log_range {
            let mut state = req.ctx.state.borrow_mut();
            for url in fulfilled {
                state.logs.note_answer(chain_id, url, range.span);
            }
        }
    };
    match end {
        End::Agreed(at) => {
            note_answers(&fulfilled);
            let group = &mut groups[at];
            let result = group.value.take().flatten();
            let trust = options.include_trust.then(|| {
                let dissented: Vec<String> = fulfilled
                    .iter()
                    .filter(|url| !group.urls.contains(url))
                    .cloned()
                    .collect();
                quorum_trust(&group.urls, &dissented, &urls, m)
            });
            Ok(SourceResult { result, trust })
        }
        End::Failed { deadline } => {
            if deadline && still.iter().any(|s| *s) {
                let cut = Thrown::rpc_timeout(timeout);
                options.keeper.borrow_mut().note(&cut);
                if let Some(range) = &options.log_range {
                    let now = req.now();
                    let mut state = req.ctx.state.borrow_mut();
                    for (i, url) in urls.iter().enumerate() {
                        if !answered[i] {
                            state
                                .logs
                                .note_failure(chain_id, url, range.span, &cut, range, now);
                        }
                    }
                }
            }
            note_answers(&fulfilled);
            let capacity = errors
                .iter()
                .filter(|e| e.failure_kind() == Some(FailureKind::Capacity))
                .count();
            let timed_out = errors
                .iter()
                .any(|e| e.failure_kind() == Some(FailureKind::Timeout));
            let kind = if reaches(capacity) {
                Some("capacity")
            } else if timed_out {
                Some("timeout")
            } else {
                None
            };
            let message = format!(
                "RPC quorum did not reach {} matching responses",
                number_text(m)
            );
            let mut error = Thrown::unavailable_kind(message.as_str(), kind);
            let unanswered: Vec<String> = urls
                .iter()
                .enumerate()
                .filter(|(i, _)| !answered[*i])
                .map(|(_, url)| url.clone())
                .collect();
            candidates.sort_by_key(|c| c.index);
            let fallback = candidates.first().map(|first| {
                let (agreed, dissented): (Vec<&Candidate>, Vec<&Candidate>) =
                    candidates.iter().partition(|c| c.digest == first.digest);
                Rc::new(Fallback {
                    url: first.url.clone(),
                    result: first.value.clone().flatten(),
                    agreed: agreed.iter().map(|c| c.url.clone()).collect(),
                    dissented: dissented.iter().map(|c| c.url.clone()).collect(),
                    queried: urls.clone(),
                    k: urls.len(),
                    m,
                })
            });
            error.quorum = Some(Rc::new(QuorumMiss {
                unanswered,
                attempted: urls.clone(),
                fallback,
            }));
            Err(error)
        }
    }
}

/// What a round keeps (design 0005, Answers): each group's first-arrived
/// text while the group can still reach m, and the lowest-index answer for
/// Direct. Every other text is dropped.
fn retain(
    candidates: &mut [Candidate],
    groups: &mut [Group],
    pending: usize,
    reaches: &dyn Fn(usize) -> bool,
) {
    let lowest = candidates.iter().map(|c| c.index).min();
    for candidate in candidates.iter_mut() {
        if Some(candidate.index) != lowest {
            candidate.value = None;
        }
    }
    for group in groups.iter_mut() {
        if !reaches(group.count + pending) {
            group.value = None;
        }
    }
}

/// `requestQuorum`: one round over the first k endpoints, or, for a
/// range-capped log scan, up to two rounds over the endpoints that can
/// serve its span.
pub(crate) async fn request_quorum(
    req: &Req,
    method: &str,
    params: &str,
    options: &QuorumOptions<'_>,
) -> Result<SourceResult, Thrown> {
    let chain = &req.chain;
    let m = chain.m;
    let endpoints = chain.urls();
    #[allow(clippy::cast_precision_loss)]
    if (endpoints.len() as f64) < m {
        return Err(Thrown::unavailable(
            format!("RPC quorum needs {} endpoints", number_text(m)).as_str(),
        ));
    }
    let Some(range) = options.log_range else {
        return round(req, method, params, chain.members(), options).await;
    };
    let chain_id = chain.chain_id;
    let k = slice_end(chain.k);
    let mut asked: Option<Vec<String>> = None;
    let mut last: Option<Thrown> = None;
    for number in 1..=LOG_SCAN_QUORUM_ROUNDS {
        let now = req.now();
        #[allow(clippy::cast_precision_loss)]
        let urls: Vec<String> = {
            let state = req.ctx.state.borrow();
            endpoints
                .iter()
                .filter(|url| state.logs.servable(chain_id, url, now) >= range.span as f64)
                .take(k)
                .cloned()
                .collect()
        };
        #[allow(clippy::cast_precision_loss)]
        let few = (urls.len() as f64) < m;
        let repeated = asked
            .as_ref()
            .is_some_and(|asked| urls.iter().all(|url| asked.contains(url)));
        if few || repeated {
            break;
        }
        let mut round_options = *options;
        if let Some(ends_at) = options.ends_at
            && number > 1
        {
            #[allow(clippy::cast_precision_loss)]
            let left = ends_at as f64 - now as f64;
            if left < chain.timeout {
                break;
            }
            round_options.quorum_timeout = Some(left);
        }
        match round(req, method, params, urls.clone(), &round_options).await {
            Ok(result) => return Ok(result),
            Err(error) => {
                asked = Some(urls);
                last = Some(error);
            }
        }
    }
    // `noQuorum`: the widest span a quorum can still verify, so the caller
    // narrows to it.
    let servable = {
        let now = req.now();
        req.ctx
            .state
            .borrow()
            .logs
            .quorum_span(chain_id, &endpoints, m, now)
    };
    #[allow(clippy::cast_precision_loss)]
    if servable > 0.0 && servable < range.span as f64 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let refusal = Thrown::error(&log_range_refusal_text(servable as u64))
            .with("code", Prop::Json(LOG_RANGE_REFUSAL_CODE.to_string()));
        options.keeper.borrow_mut().note(&refusal);
        return Err(refusal);
    }
    Err(last.unwrap_or_else(|| {
        Thrown::unavailable(format!("No RPC quorum available for {method}").as_str())
    }))
}
