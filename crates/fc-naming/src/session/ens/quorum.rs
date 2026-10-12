//! Waves, `resolveViaQuorum`, the single source, `direct` and the method
//! order.

use super::*;

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
    pub(crate) name: &'a str,
    pub(crate) call_data: &'a [u8],
    pub(crate) system: &'a str,
    pub(crate) resolver: Resolver,
    /// Content lookups prefetch the first answer.
    pub(crate) prefetch: bool,
}

/// `runConsensusWave`: legs at once; the first M-sized bucket ends it.
pub(crate) async fn run_wave(
    ctx: &Ctx,
    machine: &crate::session::machine::Shared,
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
    let mut prefetch = None;
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
                        prefetch = machine.start_prefetch(resolved);
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
    // Any other outcome cancels the prefetch by dropping it.
    if matches!(outcome, WaveOutcome::AgreedData { .. })
        && let Some(io) = prefetch
    {
        machine.keep_prefetch(io);
    }
    Wave {
        outcome,
        results,
        queried: endpoints.to_vec(),
        m,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Verdict {
    AllErrored,
    UnverifiedData(Endpoint, Vec<u8>),
    UnverifiedNotFound(Endpoint, &'static str, Option<CallError>),
    Conflict,
}

/// `classifyNoAgreement`.
pub(crate) fn classify(wave: &Wave) -> Verdict {
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
    pub(crate) fn trust(&self) -> &JsValue {
        match self {
            Consensus::Data { trust, .. }
            | Consensus::NotFound { trust, .. }
            | Consensus::Conflict { trust, .. } => trust,
        }
    }
}

/// `buildTrust`.
pub(crate) fn build_trust(
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
pub(crate) async fn single_source(
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
        Leg::Error(error) => Err(Thrown::new(error.display())),
    }
}

/// `resolveViaQuorum`.
pub(crate) async fn via_quorum(
    ctx: &Ctx,
    machine: &crate::session::machine::Shared,
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
                    (
                        "resolvedData",
                        s(&ctx.bounds().shorten_hex(&rpc::hex(&bytes))),
                    ),
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

pub(crate) fn data_buckets(wave: &Wave) -> Vec<(Vec<u8>, Vec<Endpoint>)> {
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

pub(crate) fn negative_buckets(wave: &Wave) -> Vec<(&'static str, Vec<Endpoint>)> {
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
pub(crate) async fn direct(ctx: &Ctx, lookup: &Lookup<'_>) -> Option<Consensus> {
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
pub(crate) async fn with_method(
    ctx: &Ctx,
    machine: &crate::session::machine::Shared,
    method: &str,
    lookup: &Lookup<'_>,
) -> Result<Option<Consensus>, Thrown> {
    match method {
        "quorum" => via_quorum(ctx, machine, lookup).await.map(Some),
        "direct" => Ok(direct(ctx, lookup).await),
        "myotis" => myotis(ctx, lookup).await,
        "colibri" => colibri(ctx, lookup).await.map(Some),
        _ => Ok(None),
    }
}

/// `consensusResolve`.
pub(crate) async fn consensus_resolve(
    ctx: &Ctx,
    machine: &crate::session::machine::Shared,
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
            Err(error) if error.lifecycle => return Err(error),
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
