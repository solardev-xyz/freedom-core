//! A pending SafeTx's entry in `safe-pending.json` (design 0016, "Owner
//! signatures" and "The pending store"; SAFE-2's S3): written as the
//! reference's `startSafeSend` writes it, and read back, checked, before
//! anything signs or executes it. The store itself, its file, its bound
//! and its set-aside of an unreadable file, is PRF-5f's
//! ([`crate::safe_pending`]); this is the codec of one entry.
//!
//! - **Written** ([`written`]): `{ chainId, safeAddress, safeTxData,
//!   safeTxHash, typedData, threshold, display, signatures, createdAt }`,
//!   in that order, as `safe-transactions.js` builds it and
//!   `vectors/safe.json`'s flows record it: the fields and the typed data
//!   as fc-safe writes them (`SafeTx::fields`, `SafeTx::typed_data`), the
//!   hash in lowercase hex, `display` the caller's opaque value as JS keeps
//!   it (left out when none was given, as `JSON.stringify` leaves out an
//!   undefined one), and each signature `{ signer, data }`, the owner's
//!   address checksummed and the 65 bytes in lowercase hex, in the order
//!   the owners signed.
//! - **Read** ([`read`]), for the record's Safe: an object on chain 100,
//!   for the record's address, whose `safeTxData` reads back as one of
//!   Freedom's SafeTxs (`SafeTx::from_fields`) and whose `safeTxHash` is
//!   that SafeTx's hash for the Safe. An entry that isn't is
//!   [`SetAside`]: nothing signs or executes it, and the board leaves it
//!   out. Its `typedData` isn't read: nothing signs from it, since every
//!   signature is over the hash of the fields.
//! - **Its signatures** are each checked as fc-safe checks an owner's
//!   (`OwnerSignature::check`): 65 bytes, `v` 27 or 28, a low `s`,
//!   recovered over the SafeTx's hash to the signer it names, one of the
//!   record's owners (deviation `owner-signatures`). Any other is refused,
//!   and a second from one owner is dropped: neither counts, and the entry
//!   stays.

use fc_evm::{checksum_address, parse_address, parse_bytes, to_hex};
use fc_json::JsValue;
use fc_protocol::error::ErrorBody;
use fc_safe::{OwnerSignature, SafeTx, Signatures};

/// Why an entry is set aside: nothing signs or executes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetAside {
    /// Not an object, or `signatures` isn't an array.
    Shape,
    /// `chainId` isn't Gnosis's.
    Chain,
    /// `safeAddress` isn't the record's.
    Safe,
    /// `safeTxData` isn't one of Freedom's SafeTxs (fc-safe's refusal).
    Fields,
    /// `safeTxHash` isn't the hash of its fields for the record's Safe.
    Hash,
}

impl SetAside {
    /// Its name in the log.
    pub fn reason(self) -> &'static str {
        match self {
            SetAside::Shape => "shape",
            SetAside::Chain => "chain",
            SetAside::Safe => "safe",
            SetAside::Fields => "fields",
            SetAside::Hash => "hash",
        }
    }
}

/// An entry read back for the record's Safe.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The SafeTx and its hash, which `safe.execute` executes (S4) and S6
    /// has a Ledger owner sign.
    pub tx: SafeTx,
    pub hash: [u8; 32],
    /// The signatures that count: checked, one per owner.
    pub signatures: Signatures,
    /// How many were refused or dropped.
    pub refused: usize,
    pub superseded: bool,
}

/// An entry as `safe-pending.json` holds it, read for the Safe at `safe`
/// whose record's owners are `owners`.
pub fn read(entry: &JsValue, safe: &[u8; 20], owners: &[[u8; 20]]) -> Result<Entry, SetAside> {
    let JsValue::Object(_) = entry else {
        return Err(SetAside::Shape);
    };
    let signed = entry
        .get("signatures")
        .and_then(JsValue::as_array)
        .ok_or(SetAside::Shape)?;
    match entry.get("chainId") {
        Some(JsValue::Number(n)) if *n == fc_safe::constants::CHAIN_ID as f64 => {}
        _ => return Err(SetAside::Chain),
    }
    let address = entry
        .get("safeAddress")
        .and_then(JsValue::as_str)
        .and_then(|text| parse_address(text).ok());
    if address != Some(*safe) {
        return Err(SetAside::Safe);
    }
    let fields = entry
        .get("safeTxData")
        .and_then(|fields| serde_json::from_str::<serde_json::Value>(&fields.stringify()).ok())
        .ok_or(SetAside::Fields)?;
    let tx = SafeTx::from_fields(&fields).map_err(|_| SetAside::Fields)?;
    let hash = tx.hash(safe).map_err(|_| SetAside::Fields)?;
    let named = entry
        .get("safeTxHash")
        .and_then(JsValue::as_str)
        .and_then(|text| parse_bytes(text, "safeTxHash").ok());
    if named.as_deref() != Some(hash.as_slice()) {
        return Err(SetAside::Hash);
    }
    let mut signatures = Signatures::new();
    let mut refused = 0;
    for signature in signed {
        let checked = signature
            .get("signer")
            .and_then(JsValue::as_str)
            .and_then(|text| parse_address(text).ok())
            .zip(
                signature
                    .get("data")
                    .and_then(JsValue::as_str)
                    .and_then(|text| parse_bytes(text, "data").ok()),
            )
            .and_then(|(signer, data)| OwnerSignature::check(&hash, &data, &signer, owners).ok());
        match checked {
            Some(checked) if signatures.add(checked) => {}
            _ => refused += 1,
        }
    }
    Ok(Entry {
        tx,
        hash,
        signatures,
        refused,
        superseded: entry.get("superseded").is_some_and(JsValue::truthy),
    })
}

/// What [`written`] writes.
pub struct New<'a> {
    pub safe: &'a [u8; 20],
    pub tx: &'a SafeTx,
    pub hash: &'a [u8; 32],
    pub threshold: usize,
    pub display: Option<&'a JsValue>,
    /// In the order the owners signed.
    pub signatures: &'a [OwnerSignature],
    /// `Date.now()`, the wall clock's milliseconds.
    pub created_at_ms: u64,
}

/// The entry `startSafeSend` writes, with the vault owners' signatures as
/// `collectFreeSignatures` then adds them.
pub fn written(new: &New<'_>) -> Result<JsValue, ErrorBody> {
    let js = |value: serde_json::Value| {
        fc_json::parse(&value.to_string()).map_err(|_| crate::vault::internal())
    };
    let signatures = new
        .signatures
        .iter()
        .map(|signature| {
            JsValue::Object(vec![
                (
                    "signer".into(),
                    JsValue::string(checksum_address(signature.owner()).as_str()),
                ),
                (
                    "data".into(),
                    JsValue::string(to_hex(signature.signature()).as_str()),
                ),
            ])
        })
        .collect();
    let mut entry = vec![
        (
            "chainId".into(),
            JsValue::Number(fc_safe::constants::CHAIN_ID as f64),
        ),
        (
            "safeAddress".into(),
            JsValue::string(checksum_address(new.safe).as_str()),
        ),
        ("safeTxData".into(), js(new.tx.fields())?),
        (
            "safeTxHash".into(),
            JsValue::string(to_hex(new.hash).as_str()),
        ),
        ("typedData".into(), js(new.tx.typed_data(new.safe))?),
        ("threshold".into(), JsValue::Number(new.threshold as f64)),
    ];
    if let Some(display) = new.display {
        entry.push(("display".into(), display.clone()));
    }
    entry.push(("signatures".into(), JsValue::Array(signatures)));
    entry.push((
        "createdAt".into(),
        JsValue::Number(new.created_at_ms as f64),
    ));
    Ok(JsValue::Object(entry))
}

#[cfg(test)]
mod tests;
