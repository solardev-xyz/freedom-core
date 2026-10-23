//! The memory chunk source the node loop fetches from.

use ant_retrieval::ChunkFetcher;
use ant_retrieval::fetcher::FetchExhausted;
use async_trait::async_trait;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::Mutex;

/// Chunks by address, as a network that holds exactly these would answer.
///
/// A miss is a miss the network corroborated: more peers than antd's
/// `STARVED_MAX_NOT_FOUND` answered "not found", none of them overdraft-
/// skipped. antd answers that with bee's 404 and doesn't retry it.
#[derive(Debug, Default)]
pub struct MemFetcher {
    chunks: HashMap<[u8; 32], Vec<u8>>,
    /// Roots rebuilt from dispersed replicas, which antd's cache keeps.
    recovered: Mutex<HashMap<[u8; 32], Vec<u8>>>,
}

impl MemFetcher {
    pub fn new(chunks: HashMap<[u8; 32], Vec<u8>>) -> Self {
        Self {
            chunks,
            recovered: Mutex::default(),
        }
    }
}

#[async_trait]
impl ChunkFetcher for MemFetcher {
    async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
        if let Some(wire) = self.chunks.get(&addr) {
            return Ok(wire.clone());
        }
        if let Ok(recovered) = self.recovered.lock()
            && let Some(wire) = recovered.get(&addr)
        {
            return Ok(wire.clone());
        }
        Err(Box::new(
            FetchExhausted::new(
                format!("chunk {} not found", hex::encode(addr)),
                false,
                true,
            )
            .with_not_found_answers(8),
        ))
    }

    async fn put_recovered(&self, addr: [u8; 32], wire: &[u8]) {
        if let Ok(mut recovered) = self.recovered.lock() {
            recovered.insert(addr, wire.to_vec());
        }
    }
}

/// A [`MemFetcher`] that records every address fetched, so the generator
/// learns which chunks a join reads.
pub struct LogFetcher<'a> {
    pub inner: &'a MemFetcher,
    pub log: Mutex<Vec<[u8; 32]>>,
}

#[async_trait]
impl ChunkFetcher for LogFetcher<'_> {
    async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
        if let Ok(mut log) = self.log.lock() {
            log.push(addr);
        }
        self.inner.fetch(addr).await
    }
}
