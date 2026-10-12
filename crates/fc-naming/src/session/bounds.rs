//! The machine's bounds (design 0004, Bounds and Deviations). Each one sits
//! above every valid case; what happens when one is reached is the
//! deviation the design lists for it.

/// The machine's bounds. `Default` is design 0004's values; tests lower
/// one so that its boundary fits a small vector (`world.bounds`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// 0001's frame: the largest serialized message either side may send.
    pub message_bytes: usize,
    /// Any answer body (RPC, Tezos, gateway): 720 KiB, 960 KiB in base64
    /// (`response-caps`).
    pub answer_bytes: usize,
    /// A resolution reply, serialized (`reply-size`).
    pub reply_bytes: usize,
    /// Hex longer than this is shortened in replies (`reply-shortening`).
    pub reply_hex: usize,
    /// Gateway URLs tried per CCIP-Read round (`ccip-urls`).
    pub ccip_urls: usize,
    /// Prefetches kept after their wave agreed (`prefetch-set`).
    pub prefetches: usize,
    /// Running sessions, waiting callers, and callers per session
    /// (`admission`).
    pub sessions: usize,
    pub callers: usize,
    pub callers_per_session: usize,
    /// A session's deadline (`overall-deadline`).
    pub deadline_ms: u64,
    /// Bytes each cache may hold (`cache-bytes`).
    pub cache_bytes: usize,
    /// Output bytes one decode may produce (`decode-budget`).
    pub decode_bytes: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            message_bytes: 1024 * 1024,
            answer_bytes: 720 * 1024,
            reply_bytes: 960 * 1024,
            reply_hex: 8_192,
            ccip_urls: 32,
            prefetches: 32,
            sessions: 32,
            callers: 256,
            callers_per_session: 64,
            deadline_ms: 120_000,
            cache_bytes: 8 * 1024 * 1024,
            decode_bytes: crate::abi::MAX_DECODE_BYTES,
        }
    }
}

/// What a request's envelope (method, ids, generations, deadline) may take
/// besides its payload strings, so a payload that fits this check fits the
/// frame.
pub const ENVELOPE_BYTES: usize = 4 * 1024;

impl Bounds {
    /// Whether request payload strings, serialized, fit one message.
    pub fn fits(&self, payloads: &[&str]) -> bool {
        let size: usize = payloads
            .iter()
            .map(|p| {
                crate::jsjson::JsValue::String((*p).to_owned())
                    .stringify()
                    .len()
            })
            .sum();
        size + ENVELOPE_BYTES <= self.message_bytes
    }

    /// Hex shortened for a reply: its first and last `reply_hex / 2`
    /// characters, which keep what the renderer shows (the first 16 and
    /// last 10).
    pub fn shorten_hex(&self, hex: &str) -> String {
        if hex.len() <= self.reply_hex {
            return hex.to_owned();
        }
        let half = self.reply_hex / 2;
        format!("{}{}", &hex[..half], &hex[hex.len() - half..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_keeps_both_ends() {
        let bounds = Bounds::default();
        let long = format!("0x{}", "ab".repeat(10_000));
        let short = bounds.shorten_hex(&long);
        assert_eq!(short.len(), 8_192);
        assert_eq!(&short[..16], &long[..16]);
        assert_eq!(&short[short.len() - 10..], &long[long.len() - 10..]);
        assert_eq!(bounds.shorten_hex("0x12"), "0x12");
    }

    #[test]
    fn messages_are_measured_serialized() {
        let bounds = Bounds::default();
        assert!(bounds.fits(&["0x12"]));
        let quotes = "\"".repeat(bounds.message_bytes / 2);
        // Each quote serializes to two bytes.
        assert!(!bounds.fits(&[&quotes]));
    }
}
