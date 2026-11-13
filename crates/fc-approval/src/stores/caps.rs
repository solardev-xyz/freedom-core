//! `x402-permissions.json` (the reference's `x402/permissions.js`): its
//! codec. The caps' operations are X402-1's.
//!
//! `origin → "<chainId>:<asset>" → { capAmount, spentAmount, createdAt,
//! expiresAt }`, amounts as decimal strings, times in wall-clock seconds.
//! The reference drops expired caps as it reads the file
//! (`compactExpired`), in memory, so the file loses them at its next write.

use serde_json::{Map, Value};

use super::{MAX_KEYS, Refused, Unreadable, parse, text_of};

/// The x402 cap store.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CapStore {
    entries: Map<String, Value>,
}

impl CapStore {
    pub fn new() -> Self {
        CapStore::default()
    }

    /// The store as its file's bytes give it at `now_s` (the wall clock, in
    /// seconds): every cap whose `expiresAt` is a number after `now_s`, in
    /// the file's order, and every origin left with one. What isn't a live
    /// cap (an expired one, a record that isn't an object or has no numeric
    /// `expiresAt`, an origin whose caps aren't an object) is dropped, as
    /// the reference's `compactExpired` drops it.
    pub fn load(bytes: &[u8], now_s: u64) -> Result<Self, Unreadable> {
        let file = parse(bytes)?;
        let mut entries = Map::new();
        for (origin, caps) in file {
            let Value::Object(caps) = caps else {
                continue;
            };
            let live: Map<String, Value> = caps
                .into_iter()
                .filter(|(_, record)| is_live(record, now_s))
                .collect();
            if !live.is_empty() {
                entries.insert(origin, Value::Object(live));
            }
        }
        if entries.len() > MAX_KEYS {
            return Err(Unreadable::TooManyKeys);
        }
        Ok(CapStore { entries })
    }

    pub fn text(&self) -> Result<String, Refused> {
        text_of(&self.entries)
    }

    /// Every cap as the file holds it: its origin, its `"<chainId>:<asset>"`
    /// key and its record, in the file's order.
    pub fn caps(&self) -> impl Iterator<Item = (&str, &str, &Value)> {
        self.entries.iter().flat_map(|(origin, caps)| {
            caps.as_object().into_iter().flat_map(move |caps| {
                caps.iter()
                    .map(move |(key, record)| (origin.as_str(), key.as_str(), record))
            })
        })
    }
}

/// `record?.expiresAt > now`, for a number.
fn is_live(record: &Value, now_s: u64) -> bool {
    record
        .get("expiresAt")
        .and_then(Value::as_f64)
        .is_some_and(|expires| expires > now_s as f64)
}
