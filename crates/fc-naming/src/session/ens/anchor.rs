//! The anchor (`getPinnedBlock`) and the single-source anchor.

use super::*;

pub(crate) const MIN_QUORUM_PROVIDERS: usize = 3;

pub(crate) fn safety_depth(tag: &str) -> i64 {
    match tag {
        "latest-32" => 32,
        "finalized" => 0,
        _ => 8,
    }
}

/// `fetchProviderHead`.
pub(crate) async fn fetch_head(
    ctx: &Ctx,
    endpoint: &str,
    tag: &str,
    timeout: f64,
) -> Result<i64, ()> {
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
pub(crate) async fn fetch_hash_at(
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
pub(crate) async fn settle_all<T>(futures: Vec<Pin<Box<dyn Future<Output = T> + '_>>>) -> Vec<T> {
    crate::session::exec::all(futures).await
}

/// `getPinnedBlock`: `Ok(None)` when corroboration is infeasible.
pub(crate) async fn pinned_block(ctx: &Ctx) -> Result<Option<(i64, String)>, Thrown> {
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

/// `fetchSingleSourceAnchor`: head and block under one deadline.
pub(crate) async fn single_source_anchor(
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
