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
    /// Retired endpoints (no longer configured) whose state is kept: their
    /// quarantine, or their Tezos discovery (`endpoint-retention`).
    pub retired_endpoints: usize,
    /// Output bytes (strings and bytes) one ABI decode with an array may
    /// produce (`decode-budget`): an `OffchainLookup`'s URLs, whose offsets
    /// can point many entries at one string. Every other decode the session
    /// makes reads each dynamic field once, so its output never exceeds its
    /// input, which the answer cap bounds far below the default 4 MiB.
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
            retired_endpoints: 64,
        }
    }
}

/// What a request's envelope (method, ids, generations, deadline) may take
/// besides its payload strings, so a payload that fits this check fits the
/// frame.
pub const ENVELOPE_BYTES: usize = 4 * 1024;

impl Bounds {
    /// Whether an answer body of `len` bytes is within the cap
    /// (`response-caps`): up to and including it.
    pub fn answer_fits(&self, len: usize) -> bool {
        len <= self.answer_bytes
    }

    /// Whether a result serialized to `len` bytes can be replied
    /// (`reply-size`): up to and including the bound.
    pub fn reply_fits(&self, len: usize) -> bool {
        len <= self.reply_bytes
    }

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
        // In characters, so text that isn't hex can't split one.
        let count = hex.chars().count();
        if count <= self.reply_hex {
            return hex.to_owned();
        }
        let half = self.reply_hex / 2;
        let head: String = hex.chars().take(half).collect();
        let tail: String = hex.chars().skip(count - half).collect();
        format!("{head}{tail}")
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
        // Exactly at the bound it stays; one over, it is shortened.
        let at = "a".repeat(8_192);
        assert_eq!(bounds.shorten_hex(&at), at);
        assert_eq!(bounds.shorten_hex(&format!("{at}b")).len(), 8_192);
        // Not hex: no panic on a multi-byte character.
        assert_eq!(
            bounds.shorten_hex(&"€".repeat(9_000)).chars().count(),
            8_192
        );
    }

    #[test]
    fn caps_include_their_bound() {
        let bounds = Bounds {
            answer_bytes: 10,
            reply_bytes: 20,
            ..Bounds::default()
        };
        assert!(bounds.answer_fits(10) && !bounds.answer_fits(11));
        assert!(bounds.reply_fits(20) && !bounds.reply_fits(21));
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
