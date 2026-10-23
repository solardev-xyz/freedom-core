//! The node loop beneath Ant's gateway, over a memory chunk source.
//!
//! antd's gateway (`ant-gateway`) turns each HTTP request into a
//! `ControlCommand` for the node loop, which retrieves and joins the content
//! and answers with `ControlAck`s; the gateway builds the response from those.
//! The gateway's handlers run here unchanged. The node loop's arms are private
//! to `ant-p2p` (`src/behaviour.rs`), so the ones the verifier's requests reach
//! are ported below from that file at the pinned commit:
//! `GetChunkRaw`, `GetFeed`, `GetBytes`, `GetBytesEncrypted`,
//! `run_stream_bytes`, `run_stream_bzz` and their helpers.
//!
//! What the port changes, and only that:
//! - the fetcher is [`MemFetcher`], not `RoutingFetcher` over libp2p peers;
//! - the retry loops are gone: a memory source has no transient failure, and
//!   a miss it answers is the network's corroborated miss, which antd doesn't
//!   retry either (`is_final_miss`);
//! - progress, accounting and the client-gone race are left out, since they
//!   change nothing in the answer.
//!
//! The ported code is Ant's (MIT OR Apache-2.0, freedom-hq/ant).

use crate::store::MemFetcher;
use ant_control::{ControlAck, ControlCommand, StreamRange};
use ant_retrieval::{ChunkFetcher, FeedHints, LookupResult, ManifestError};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// antd's `RESOLUTION_RETRY_BUDGET`: the credit window's length. A memory
/// source never waits for credit, so only its presence matters.
const RESOLUTION_RETRY_BUDGET: Duration = Duration::from_secs(30);

/// Commands this loop doesn't model, by name, so a request that reaches one
/// fails generation instead of recording a made-up answer.
#[derive(Debug, Default)]
pub struct Unhandled(pub std::sync::Mutex<Vec<String>>);

/// Spawns the loop and returns the gateway's command sender.
pub fn spawn(fetcher: Arc<MemFetcher>, unhandled: Arc<Unhandled>) -> mpsc::Sender<ControlCommand> {
    let (tx, mut rx) = mpsc::channel::<ControlCommand>(64);
    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            let fetcher = fetcher.clone();
            let unhandled = unhandled.clone();
            tokio::spawn(async move {
                handle(&fetcher, &unhandled, cmd).await;
            });
        }
    });
    tx
}

async fn handle(fetcher: &MemFetcher, unhandled: &Unhandled, cmd: ControlCommand) {
    match cmd {
        // `ControlCommand::GetChunkRaw` in antd: the full wire bytes, or a
        // miss typed off the fetcher's error.
        ControlCommand::GetChunkRaw { reference, ack, .. } => {
            let reply = match fetcher.fetch(reference).await {
                Ok(wire) => ControlAck::Bytes { data: wire },
                Err(e) => pre_stream_failure_ack(format!("retrieval: {e}"), e.as_ref()),
            };
            let _ = ack.send(reply);
        }
        // `ControlCommand::GetFeed` in antd, with a fresh hint map per
        // request, as a node that has resolved nothing before.
        ControlCommand::GetFeed {
            owner,
            topic,
            after,
            exact,
            ack,
        } => {
            let hints = FeedHints::new();
            let feed = ant_retrieval::Feed {
                owner,
                topic,
                kind: ant_retrieval::FeedType::Sequence,
            };
            let result = if exact {
                ant_retrieval::resolve_sequence_feed_exact(fetcher, &feed, after, Some(&hints))
                    .await
            } else {
                ant_retrieval::resolve_sequence_feed_hinted(fetcher, &feed, after, Some(&hints))
                    .await
            };
            let _ = ack.send(feed_lookup_ack(result));
        }
        // `run_get_bytes` / `try_get_bytes`, one attempt: antd retries a
        // fetch failure, and answers the last attempt's error the same way.
        ControlCommand::GetBytes {
            reference,
            max_bytes,
            ack,
            ..
        } => {
            let result = async {
                let root = ant_retrieval::fetch_root_with_replicas(
                    fetcher,
                    reference,
                    ant_retrieval::accounting::CREDIT_WAIT_BUDGET,
                )
                .await
                .map_err(|e| format!("fetch root chunk {}: {e}", hex::encode(reference)))?;
                ant_retrieval::join(fetcher, &root, clamp_max_bytes(max_bytes))
                    .await
                    .map_err(|e| format!("join {}: {e}", hex::encode(reference)))
            }
            .await;
            let reply = match result {
                Ok(data) => ControlAck::Bytes { data },
                Err(message) => ControlAck::Error { message },
            };
            let _ = ack.send(reply).await;
        }
        // `run_get_bytes_encrypted` / `try_get_bytes_encrypted`, one attempt.
        ControlCommand::GetBytesEncrypted {
            reference,
            key,
            max_bytes,
            ack,
            ..
        } => {
            let mut root_ref = [0u8; ant_retrieval::ENCRYPTED_REF_SIZE];
            root_ref[..32].copy_from_slice(&reference);
            root_ref[32..].copy_from_slice(&key);
            let reply =
                match ant_retrieval::join_encrypted(fetcher, root_ref, clamp_max_bytes(max_bytes))
                    .await
                {
                    Ok(data) => ControlAck::Bytes { data },
                    Err(e) => ControlAck::Error {
                        message: format!("join encrypted {}: {e}", hex::encode(reference)),
                    },
                };
            let _ = ack.send(reply).await;
        }
        ControlCommand::StreamBytes {
            reference,
            max_bytes,
            range,
            head_only,
            ack,
            ..
        } => {
            run_stream_bytes(fetcher, reference, max_bytes, range, head_only, ack).await;
        }
        ControlCommand::StreamBzz {
            reference,
            path,
            allow_degraded_redundancy,
            max_bytes,
            range,
            head_only,
            ack,
            ..
        } => {
            run_stream_bzz(
                fetcher,
                reference,
                path,
                allow_degraded_redundancy,
                max_bytes,
                range,
                head_only,
                ack,
            )
            .await;
        }
        other => {
            let name = format!("{other:?}");
            let name = name
                .split([' ', '{', '('])
                .next()
                .unwrap_or("?")
                .to_string();
            if let Ok(mut seen) = unhandled.0.lock() {
                seen.push(name);
            }
        }
    }
}

/// `run_stream_bytes`, one attempt.
async fn run_stream_bytes(
    fetcher: &MemFetcher,
    reference: [u8; 32],
    max_bytes: Option<u64>,
    range: Option<StreamRange>,
    head_only: bool,
    ack: mpsc::Sender<ControlAck>,
) {
    let credit_window = ant_retrieval::accounting::CreditWindow::new(RESOLUTION_RETRY_BUDGET);
    let root =
        match ant_retrieval::fetch_root_with_replicas(fetcher, reference, credit_window.budget())
            .await
        {
            Ok(root) => root,
            Err(e) => {
                let message = format!("fetch root chunk {}: {e}", hex::encode(reference));
                let _ = ack.send(pre_stream_failure_ack(message, e.as_ref())).await;
                return;
            }
        };
    let Some(total_bytes) = root_span_to_u64_masked(&root) else {
        let _ = ack
            .send(ControlAck::Error {
                message: format!("root chunk {} shorter than span", hex::encode(reference)),
            })
            .await;
        return;
    };
    if ack
        .send(ControlAck::BytesStreamStart { total_bytes })
        .await
        .is_err()
    {
        return;
    }
    if head_only {
        let _ = ack.send(ControlAck::StreamDone).await;
        return;
    }
    stream_root_chunk_inner(
        fetcher,
        root,
        total_bytes,
        max_bytes,
        range,
        reference,
        ant_retrieval::JoinOptions::default(),
        ack,
    )
    .await;
}

/// `run_stream_bzz`, one attempt.
#[allow(clippy::too_many_arguments)]
async fn run_stream_bzz(
    fetcher: &MemFetcher,
    reference: Vec<u8>,
    path: String,
    allow_degraded_redundancy: bool,
    max_bytes: Option<u64>,
    range: Option<StreamRange>,
    head_only: bool,
    ack: mpsc::Sender<ControlAck>,
) {
    let credit_window = ant_retrieval::accounting::CreditWindow::new(RESOLUTION_RETRY_BUDGET);
    let replica_sweeps = ant_retrieval::ReplicaSweeps::new();
    let feed_hints = FeedHints::new();
    let bare_root = is_bare_root_path(&path);
    replica_sweeps.next_attempt();

    let looked_up = match (bare_root, <[u8; 32]>::try_from(reference.as_slice())) {
        (true, Ok(root)) => {
            match ant_retrieval::fetch_root_with_replicas(fetcher, root, credit_window.budget())
                .await
            {
                Ok(_) => {
                    ant_retrieval::lookup_path_with_credit(
                        fetcher,
                        &reference,
                        &path,
                        &credit_window,
                        &replica_sweeps,
                        Some(&feed_hints),
                    )
                    .await
                }
                Err(source) => Err(ManifestError::Fetch(ant_retrieval::JoinError::FetchChunk {
                    addr: hex::encode(root),
                    source,
                })),
            }
        }
        _ => {
            ant_retrieval::lookup_path_with_credit(
                fetcher,
                &reference,
                &path,
                &credit_window,
                &replica_sweeps,
                Some(&feed_hints),
            )
            .await
        }
    };
    let lookup = match looked_up {
        Ok(r) => r,
        Err(ManifestError::NotAManifest) => {
            if let Some(raw) = raw_bytes_lookup(&reference, &path) {
                raw
            } else {
                let _ = ack
                    .send(ControlAck::Error {
                        message: path_below_raw_bytes_message(&reference, &path),
                    })
                    .await;
                return;
            }
        }
        Err(e) => {
            let _ = ack
                .send(bzz_lookup_failure_ack(
                    format!("manifest lookup '{path}': {e}"),
                    &e,
                    replica_sweeps.swept_transiently(&e),
                ))
                .await;
            return;
        }
    };

    if let Ok(enc_ref) =
        <[u8; ant_retrieval::ENCRYPTED_REF_SIZE]>::try_from(lookup.data_ref.as_slice())
    {
        let filename = lookup
            .metadata
            .get("Filename")
            .cloned()
            .or_else(|| derive_filename_from_path(&path));
        stream_encrypted_body(
            fetcher,
            enc_ref,
            lookup.content_type.clone(),
            filename,
            bzz_feed(lookup.feed),
            max_bytes,
            range,
            head_only,
            ack,
        )
        .await;
        return;
    }
    let Ok(data_ref) = <[u8; 32]>::try_from(lookup.data_ref.as_slice()) else {
        let _ = ack
            .send(ControlAck::Error {
                message: "manifest entry has invalid width".to_string(),
            })
            .await;
        return;
    };

    let root =
        match ant_retrieval::fetch_root_with_replicas(fetcher, data_ref, credit_window.budget())
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let message = format!("fetch data root {}: {e}", hex::encode(data_ref));
                let _ = ack.send(pre_stream_failure_ack(message, e.as_ref())).await;
                return;
            }
        };
    let Some(total_bytes) = root_span_to_u64_masked(&root) else {
        let _ = ack
            .send(ControlAck::Error {
                message: format!("data root {} shorter than span", hex::encode(data_ref)),
            })
            .await;
        return;
    };
    let filename = lookup
        .metadata
        .get("Filename")
        .cloned()
        .or_else(|| derive_filename_from_path(&path));
    if ack
        .send(ControlAck::BzzStreamStart {
            total_bytes,
            reference: data_ref.to_vec(),
            content_type: lookup.content_type,
            filename,
            feed: bzz_feed(lookup.feed),
        })
        .await
        .is_err()
    {
        return;
    }
    if head_only {
        let _ = ack.send(ControlAck::StreamDone).await;
        return;
    }
    let join_options = ant_retrieval::JoinOptions {
        allow_degraded_redundancy,
    };
    stream_root_chunk_inner(
        fetcher,
        root,
        total_bytes,
        max_bytes,
        range,
        data_ref,
        join_options,
        ack,
    )
    .await;
}

/// `stream_encrypted_body`.
#[allow(clippy::too_many_arguments)]
async fn stream_encrypted_body(
    fetcher: &MemFetcher,
    enc_ref: [u8; ant_retrieval::ENCRYPTED_REF_SIZE],
    content_type: Option<String>,
    filename: Option<String>,
    feed: Option<ant_control::BzzFeed>,
    max_bytes: Option<u64>,
    range: Option<StreamRange>,
    head_only: bool,
    ack: mpsc::Sender<ControlAck>,
) {
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&enc_ref[..32]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&enc_ref[32..]);

    let root_wire =
        match ant_retrieval::fetch_root_with_replicas(fetcher, addr, Duration::ZERO).await {
            Ok(w) => w,
            Err(e) => {
                let _ = ack
                    .send(ControlAck::Error {
                        message: format!("fetch encrypted data root {}: {e}", hex::encode(addr)),
                    })
                    .await;
                return;
            }
        };
    let total_bytes = match ant_crypto::decrypt_chunk_parts(&root_wire, &key) {
        Ok((span, _)) => {
            let (_, plain) = ant_retrieval::rs::decode_span(span);
            u64::from_le_bytes(plain)
        }
        Err(e) => {
            let _ = ack
                .send(ControlAck::Error {
                    message: format!("decrypt data root {}: {e}", hex::encode(addr)),
                })
                .await;
            return;
        }
    };
    if ack
        .send(ControlAck::BzzStreamStart {
            total_bytes,
            reference: enc_ref.to_vec(),
            content_type,
            filename,
            feed,
        })
        .await
        .is_err()
    {
        return;
    }
    if head_only {
        let _ = ack.send(ControlAck::StreamDone).await;
        return;
    }
    let body_range =
        range.and_then(|r| ant_retrieval::ByteRange::clamp(r.start, r.end_inclusive, total_bytes));
    if range.is_some() && body_range.is_none() {
        let _ = ack
            .send(ControlAck::Error {
                message: "range not satisfiable for resource".to_string(),
            })
            .await;
        return;
    }
    let cap = clamp_max_bytes(max_bytes);
    let body = match ant_retrieval::join_encrypted(fetcher, enc_ref, cap).await {
        Ok(b) => b,
        Err(e) => {
            let _ = ack
                .send(ControlAck::Error {
                    message: format!("join encrypted {}: {e}", hex::encode(enc_ref)),
                })
                .await;
            return;
        }
    };
    let data = match body_range {
        Some(r) => {
            let start = usize::try_from(r.start)
                .unwrap_or(usize::MAX)
                .min(body.len());
            let end = usize::try_from(r.end_inclusive)
                .unwrap_or(usize::MAX)
                .saturating_add(1)
                .min(body.len());
            body[start..end].to_vec()
        }
        None => body,
    };
    if !data.is_empty() && ack.send(ControlAck::BytesChunk { data }).await.is_err() {
        return;
    }
    let _ = ack.send(ControlAck::StreamDone).await;
}

/// `stream_root_chunk_inner`.
#[allow(clippy::too_many_arguments)]
async fn stream_root_chunk_inner(
    fetcher: &MemFetcher,
    root: Vec<u8>,
    total_bytes: u64,
    max_bytes: Option<u64>,
    range: Option<StreamRange>,
    reference: [u8; 32],
    options: ant_retrieval::JoinOptions,
    ack: mpsc::Sender<ControlAck>,
) {
    let (chunk_tx, mut chunk_rx) = mpsc::channel::<Vec<u8>>(64);
    let cap = clamp_max_bytes(max_bytes);
    let body_range =
        range.and_then(|r| ant_retrieval::ByteRange::clamp(r.start, r.end_inclusive, total_bytes));
    if range.is_some() && body_range.is_none() {
        let _ = ack
            .send(ControlAck::Error {
                message: "range not satisfiable for resource".to_string(),
            })
            .await;
        return;
    }
    let mut join_fut = Box::pin(ant_retrieval::join_to_sender_range(
        fetcher, &root, cap, options, body_range, chunk_tx,
    ));
    let mut join_result = None;
    loop {
        tokio::select! {
            result = &mut join_fut, if join_result.is_none() => {
                join_result = Some(result);
            }
            maybe_chunk = chunk_rx.recv() => {
                if let Some(data) = maybe_chunk {
                    if ack.send(ControlAck::BytesChunk { data }).await.is_err() {
                        return;
                    }
                } else {
                    match join_result.unwrap_or(Ok(())) {
                        Ok(()) => {
                            let _ = ack.send(ControlAck::StreamDone).await;
                        }
                        Err(e) => {
                            let _ = ack
                                .send(ControlAck::Error {
                                    message: format!("join {}: {e}", hex::encode(reference)),
                                })
                                .await;
                        }
                    }
                    return;
                }
            }
        }
    }
}

/// `pre_stream_failure_ack`.
fn pre_stream_failure_ack(message: String, e: &(dyn std::error::Error + 'static)) -> ControlAck {
    match ant_retrieval::fetcher::FetchExhausted::find(e) {
        Some(x) if x.confirmed_missing() => ControlAck::NotFound { message },
        Some(x) if x.last_not_found => ControlAck::NotReady { message },
        _ => ControlAck::Error { message },
    }
}

/// `feed_lookup_ack`.
fn feed_lookup_ack(
    result: Result<ant_retrieval::FeedResolution, ant_retrieval::FeedError>,
) -> ControlAck {
    match result {
        Ok(resolution) => ControlAck::FeedResolved {
            reference: resolution.reference,
            index: resolution.index,
            signature: resolution.signature,
            v2: resolution.v2,
            decrypt_key: resolution.decrypt_key,
        },
        Err(ant_retrieval::FeedError::NoUpdates {
            corroborated: true, ..
        }) => ControlAck::FeedNotFound,
        Err(e @ ant_retrieval::FeedError::NoUpdates { .. }) => ControlAck::NotReady {
            message: format!(
                "feed lookup: {e}; too few peers answered to tell an empty feed \
                 from one this node can't reach yet"
            ),
        },
        Err(e @ ant_retrieval::FeedError::EndUnconfirmed { .. }) => ControlAck::NotReady {
            message: format!("feed lookup: {e}"),
        },
        Err(e) => ControlAck::Error {
            message: format!("feed lookup: {e}"),
        },
    }
}

/// `bzz_lookup_failure_ack`.
fn bzz_lookup_failure_ack(
    message: String,
    e: &ManifestError,
    swept_transiently: bool,
) -> ControlAck {
    match pre_stream_failure_ack(message, e) {
        ControlAck::NotFound { message } if swept_transiently => ControlAck::NotReady { message },
        ack => ack,
    }
}

/// `root_span_to_u64_masked`.
fn root_span_to_u64_masked(wire: &[u8]) -> Option<u64> {
    let mut span: [u8; 8] = wire.get(..8)?.try_into().ok()?;
    span[7] = 0;
    Some(u64::from_le_bytes(span))
}

/// `clamp_max_bytes`.
fn clamp_max_bytes(max_bytes: Option<u64>) -> usize {
    match max_bytes {
        Some(n) => usize::try_from(n).unwrap_or(usize::MAX),
        None => ant_retrieval::DEFAULT_MAX_FILE_BYTES,
    }
}

/// `is_bare_root_path`.
fn is_bare_root_path(path: &str) -> bool {
    path.trim_matches('/').is_empty()
}

/// `path_below_raw_bytes_message`.
fn path_below_raw_bytes_message(reference: &[u8], path: &str) -> String {
    format!(
        "path '{}' not found: {} is raw bytes, not a mantaray manifest",
        path.trim_start_matches('/'),
        hex::encode(reference)
    )
}

/// `raw_bytes_lookup`.
fn raw_bytes_lookup(reference: &[u8], path: &str) -> Option<LookupResult> {
    if !is_bare_root_path(path) {
        return None;
    }
    Some(LookupResult {
        data_ref: reference.to_vec(),
        content_type: None,
        metadata: HashMap::new(),
        feed: None,
    })
}

/// `bzz_feed`.
fn bzz_feed(feed: Option<ant_retrieval::ResolvedFeed>) -> Option<ant_control::BzzFeed> {
    feed.map(|f| ant_control::BzzFeed {
        index: f.index,
        v2: f.v2,
    })
}

/// `derive_filename_from_path`.
fn derive_filename_from_path(path: &str) -> Option<String> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    trimmed
        .rsplit('/')
        .next()
        .map(std::string::ToString::to_string)
}
