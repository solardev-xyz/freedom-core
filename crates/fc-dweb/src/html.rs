//! `web3:`'s `html()` codec (`onchain/onchain-html.js`) and the stateless
//! class the gate starts from (`onchain-app-protocol.js`).

use std::ops::Range;

use fc_json::JsValue;
use fc_json::index::{Kind, Value};
use sha3::{Digest, Keccak256};

use crate::js;

/// `MAX_HTML_BYTES`: the largest document served.
pub const MAX_HTML_BYTES: usize = 8 * 1024 * 1024;
/// An ABI string's overhead: an offset, a length word, and up to 31 bytes
/// of padding.
const ABI_OVERHEAD: usize = 95;
/// `html()`'s selector.
pub const HTML_SELECTOR: &str = "0x33c34ac3";

/// Why an `html()` answer isn't served. [`HtmlError::status`] maps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HtmlError {
    /// Over `MAX_HTML_BYTES + 95` encoded bytes, or a document over 8 MiB.
    #[error("html() response exceeds Freedom's 8 MiB limit")]
    TooLarge,
    /// Not a string of `0x` and hex digits.
    #[error("html() returned malformed ABI data")]
    Malformed,
    /// An odd number of hex digits (ethers: `invalid BytesLike value`).
    #[error("invalid BytesLike value")]
    OddLength,
    /// Not whole 32-byte words (ethers: `invalid length for result data`).
    #[error("invalid length for result data")]
    BadLength,
    /// An offset or length past the data, or an offset past 2^53 (ethers:
    /// `could not decode result data`).
    #[error("could not decode result data")]
    Undecodable,
    /// A length past 2^53 or bytes that aren't UTF-8 (ethers: a deferred
    /// error, thrown when the string is read).
    #[error("deferred error during ABI decoding triggered accessing index 0")]
    BadString,
}

impl HtmlError {
    /// The handler's status: 413 for size, 502 for the rest.
    pub fn status(self) -> u16 {
        match self {
            Self::TooLarge => 413,
            _ => 502,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::Malformed => "malformed",
            Self::OddLength => "odd_length",
            Self::BadLength => "bad_length",
            Self::Undecodable => "undecodable",
            Self::BadString => "bad_string",
        }
    }
}

/// A decoded document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtmlDocument {
    pub html: String,
    /// `keccak256(utf8(html))`.
    pub hash: [u8; 32],
}

/// `assertHtmlResultSize`, in O(1) for anything short enough: whether the
/// answer is over `MAX_HTML_BYTES + 95` encoded bytes, `(length - 2) / 2`
/// with JavaScript's UTF-16 length.
pub fn exceeds_encoded_bound(result: &str) -> bool {
    // (length - 2) / 2 > MAX + 95  <=>  length > 2 * (MAX + 95) + 2
    let bound = 2 * (MAX_HTML_BYTES + ABI_OVERHEAD) + 2;
    // UTF-16 units never outnumber UTF-8 bytes: count only when it could matter.
    result.len() > bound && js::utf16_len(result) > bound
}

/// The checks [`decode_html`] makes before it allocates, in its order: the
/// size check before anything else, then `^0x[0-9a-f]*$` (any case), then
/// whole bytes and whole 32-byte words. The hex digits.
fn precheck(result: &str) -> Result<&str, HtmlError> {
    if exceeds_encoded_bound(result) {
        return Err(HtmlError::TooLarge);
    }
    let digits = result
        .strip_prefix("0x")
        .or_else(|| result.strip_prefix("0X"))
        .filter(|digits| digits.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or(HtmlError::Malformed)?;
    if !digits.len().is_multiple_of(2) {
        return Err(HtmlError::OddLength);
    }
    if !(digits.len() / 2).is_multiple_of(32) {
        return Err(HtmlError::BadLength);
    }
    Ok(digits)
}

/// What [`decode_html`] allocates for `result`, at most, or the error it
/// fails with before it allocates anything: one buffer, the ABI data's
/// bytes, which the document is then cut from in place. A caller that
/// reserves memory before it is allocated reserves this much.
pub fn decode_html_room(result: &str) -> Result<usize, HtmlError> {
    precheck(result).map(|digits| digits.len() / 2)
}

/// Decodes an `html()` answer as `decodeHtmlInWorker` does: the size check
/// before anything else, then `^0x[0-9a-f]*$` (any case), then ethers'
/// `decodeFunctionResult` for `(string)`, the 8 MiB cap, and the hash. It
/// allocates one buffer ([`decode_html_room`]), which becomes the document.
pub fn decode_html(result: &str) -> Result<HtmlDocument, HtmlError> {
    let digits = precheck(result)?;
    let mut data = hex_bytes(digits);
    let string = abi_string(&data)?;
    data.truncate(string.end);
    data.drain(..string.start);
    let html = String::from_utf8(data).map_err(|_| HtmlError::BadString)?;
    if html.len() > MAX_HTML_BYTES {
        return Err(HtmlError::TooLarge);
    }
    let hash = Keccak256::digest(html.as_bytes()).into();
    Ok(HtmlDocument { html, hash })
}

/// [`decode_html`] for the answer as JSON gives it: anything but a string
/// is malformed.
pub fn decode_html_value(result: &JsValue) -> Result<HtmlDocument, HtmlError> {
    match result {
        JsValue::String(text) => decode_html(text),
        _ => Err(HtmlError::Malformed),
    }
}

fn hex_bytes(digits: &str) -> Vec<u8> {
    let (pairs, _) = digits.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .map(|&[high, low]| {
            let high = char::from(high).to_digit(16).unwrap_or(0);
            let low = char::from(low).to_digit(16).unwrap_or(0);
            (high * 16 + low) as u8
        })
        .collect()
}

/// A word read as an index: `None` past `Number.MAX_SAFE_INTEGER`.
fn index(word: &[u8]) -> Option<u64> {
    let (high, low) = word.split_at(24);
    if high.iter().any(|&b| b != 0) {
        return None;
    }
    let value = u64::from_be_bytes(low.try_into().ok()?);
    (value < (1 << 53)).then_some(value)
}

/// ethers' strict (not loose) decode of one dynamic `string`: the offset
/// word; at the offset, a length word, then the bytes padded to whole
/// words. The padding's contents and anything after are not checked, and
/// the offset may point anywhere, its own word included. Where the
/// string's bytes lie in `data`.
fn abi_string(data: &[u8]) -> Result<Range<usize>, HtmlError> {
    let offset_word = data.get(..32).ok_or(HtmlError::Undecodable)?;
    // Read outside the coder's guard: any failure is the whole decode's.
    let offset = index(offset_word)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(HtmlError::Undecodable)?;
    let tail = data.get(offset..).unwrap_or_default();
    let length_word = tail.get(..32).ok_or(HtmlError::Undecodable)?;
    // Inside the coder: a numeric fault is deferred to the read.
    let length = index(length_word).ok_or(HtmlError::BadString)?;
    let padded = length.div_ceil(32) * 32;
    if 32 + padded > tail.len() as u64 {
        return Err(HtmlError::Undecodable);
    }
    // Within `tail`, which lies within `data`: `length` fits.
    let start = offset + 32;
    Ok(start..start + length as usize)
}

/// The gate's input (design 0006, `chain.html`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// `verified` or `user-configured`: served at once.
    Trusted,
    /// Not trusted, and the quorum had dissenters: no approval token.
    Conflict,
    /// Anything else: staged behind the interstitial.
    Untrusted,
}

impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Conflict => "conflict",
            Self::Untrusted => "untrusted",
        }
    }
}

/// The class of a chain-data result (`{ result, trust, source, verified }`),
/// as `handleOnchainAppRequest` decides it: `trust || { level: verified ===
/// true ? 'verified' : 'unverified', dissented: [] }`, then the level, then
/// `Array.isArray(trust.dissented) && trust.dissented.length > 0`.
pub fn classify(chain_result: &JsValue) -> Class {
    let Some(trust) = chain_result.get("trust").filter(|trust| trust.truthy()) else {
        return if chain_result.get("verified") == Some(&JsValue::Bool(true)) {
            Class::Trusted
        } else {
            Class::Untrusted
        };
    };
    if matches!(
        trust.get("level").and_then(JsValue::as_str),
        Some("verified" | "user-configured")
    ) {
        return Class::Trusted;
    }
    if trust
        .get("dissented")
        .and_then(JsValue::as_array)
        .is_some_and(|dissented| !dissented.is_empty())
    {
        Class::Conflict
    } else {
        Class::Untrusted
    }
}

/// [`classify`] for a result held as JSON text: `trust` is its `trust`
/// member, read in place from an index of the text, and `verified` whether
/// its `verified` is `true`. Nothing is built from the trust, so a caller
/// that reserves memory first reserves only the index.
pub fn classify_trust(trust: Option<Value<'_, '_>>, verified: bool) -> Class {
    let Some(trust) = trust.filter(|trust| trust.truthy()) else {
        return if verified {
            Class::Trusted
        } else {
            Class::Untrusted
        };
    };
    let level = trust.get("level");
    if level.is_some_and(|level| level.is_str("verified") || level.is_str("user-configured")) {
        return Class::Trusted;
    }
    if trust.get("dissented").is_some_and(|dissented| {
        dissented.kind() == Kind::Array && dissented.children().next().is_some()
    }) {
        Class::Conflict
    } else {
        Class::Untrusted
    }
}
