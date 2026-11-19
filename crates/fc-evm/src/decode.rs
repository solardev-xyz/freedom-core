//! Signed transactions read back from their bytes, as freedom-browser's intent
//! store checks them (`wallet/intent-store.js`, `verifySigned`): ethers v6
//! `Transaction.from(raw)`, a signature, type 0 or 2, and `tx.serialized`
//! equal to `raw`. `vectors/signing.json`'s `transactionDecoding` is the
//! contract.
//!
//! The fields are read as ethers reads them, so each refusal falls where
//! ethers' does: an integer may carry leading zeros and a length a longer
//! form, both of which only the final comparison refuses
//! ([`DecodeError::NotCanonical`]). That comparison encodes the transaction
//! again with this crate's encoder ([`crate::rlp`]), so nothing but the one
//! canonical encoding of a transaction is accepted.

use k256::ecdsa::Signature;

use crate::rlp::{self, Item, List};
use crate::{U256, keccak256, recover_address};

/// ethers keeps a nonce in a JS number: at most 2^53 - 1.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Why bytes aren't a signed transaction the intent store keeps, in the
/// order ethers and the store check. The messages are the store's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// `Transaction.from` throws: not RLP, the wrong field count, a field
    /// of the wrong shape or size, an EIP-155 `v` naming no chain, a first
    /// byte naming no type ethers knows.
    #[error("the signed transaction does not decode")]
    Undecodable,
    /// No signature: a legacy transaction of six fields, or with `r` and
    /// `s` zero (EIP-155's unsigned form), or an EIP-1559 one of nine.
    #[error("the transaction is not signed")]
    Unsigned,
    /// Types 1 (EIP-2930), 3 (EIP-4844) and 4 (EIP-7702), which ethers
    /// reads and the store refuses. The core refuses them by their first
    /// byte without reading further (deviation `tx-other-types`).
    #[error("transaction type {0} is not supported")]
    UnsupportedType(u8),
    /// `tx.serialized` throws: an EIP-1559 transaction whose priority fee
    /// is above its max fee, or whose `s` is 2^255 or more (ethers'
    /// `Signature.s` refuses it; a legacy transaction serializes it).
    #[error("the transaction cannot be serialized")]
    Unserializable,
    /// `tx.serialized` differs from the bytes.
    #[error("the transaction is not canonically encoded")]
    NotCanonical,
}

/// One entry of an EIP-2930 access list, as an EIP-1559 transaction
/// carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessListEntry {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Legacy {
        gas_price: U256,
    },
    Eip1559 {
        max_fee_per_gas: U256,
        max_priority_fee_per_gas: U256,
        access_list: Vec<AccessListEntry>,
    },
}

/// A signed transaction of type 0 or 2, decoded from its canonical bytes by
/// [`decode_signed`]. (A [`crate::SignedTransaction`] is what signing makes:
/// the bytes and their hash.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTx {
    /// 0 for a legacy transaction without EIP-155.
    chain_id: U256,
    nonce: u64,
    gas_limit: U256,
    to: Option<[u8; 20]>,
    value: U256,
    data: Vec<u8>,
    kind: Kind,
    y_parity: u8,
    r: [u8; 32],
    s: [u8; 32],
    digest: [u8; 32],
    hash: [u8; 32],
}

/// The fields every type has, as both types read them.
struct Common {
    nonce: u64,
    gas_limit: U256,
    to: Option<[u8; 20]>,
    value: U256,
    data: Vec<u8>,
}

/// Decodes `raw`, a signed transaction's bytes, and checks it as the intent
/// store does before it keeps one: it decodes, it is signed, its type is 0
/// or 2 and it is in its canonical encoding. Its nonce, chain and hash
/// against an intent's, and its signer ([`SignedTx::signer`]) against the
/// sender, are the caller's.
pub fn decode_signed(raw: &[u8]) -> Result<SignedTx, DecodeError> {
    let Some(&first) = raw.first() else {
        return Err(DecodeError::Undecodable);
    };
    // ethers reads a first byte of 0x7f or more as a legacy transaction's
    // list (0x7f itself then fails as a single byte).
    let tx = if first >= 0x7f {
        legacy(raw)?
    } else {
        match (first, &raw[1..]) {
            (2, payload) => eip1559(payload)?,
            (1 | 3 | 4, _) => return Err(DecodeError::UnsupportedType(first)),
            _ => return Err(DecodeError::Undecodable),
        }
    };
    if tx.encode()? != raw {
        return Err(DecodeError::NotCanonical);
    }
    Ok(SignedTx {
        digest: keccak256(&tx.unsigned()),
        hash: keccak256(raw),
        ..tx
    })
}

fn undecodable<T>(_: T) -> DecodeError {
    DecodeError::Undecodable
}

/// A list's items, refusing more than `max`.
fn fields(list: List<'_>, max: usize) -> Result<Vec<Item<'_>>, DecodeError> {
    let mut out = Vec::with_capacity(max);
    for item in list.items() {
        if out.len() == max {
            return Err(DecodeError::Undecodable);
        }
        out.push(item.map_err(undecodable)?);
    }
    Ok(out)
}

fn bytes(item: Item<'_>) -> Result<&[u8], DecodeError> {
    item.bytes().map_err(undecodable)
}

/// ethers' `handleUint`: leading zeros allowed, at most 2^256 - 1.
fn uint(item: Item<'_>) -> Result<U256, DecodeError> {
    let bytes = bytes(item)?;
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    U256::from_be_slice(&bytes[start..]).ok_or(DecodeError::Undecodable)
}

/// ethers' `handleNumber`: leading zeros allowed, at most 2^53 - 1.
fn number(item: Item<'_>) -> Result<u64, DecodeError> {
    uint(item)?
        .to_u64()
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .ok_or(DecodeError::Undecodable)
}

/// ethers' `handleAddress`: empty for a contract creation, else 20 bytes.
fn address(item: Item<'_>) -> Result<Option<[u8; 20]>, DecodeError> {
    match bytes(item)? {
        [] => Ok(None),
        other => other.try_into().map(Some).map_err(undecodable),
    }
}

/// `zeroPadValue(field, 32)`: at most 32 bytes, padded on the left.
fn word(item: Item<'_>) -> Result<[u8; 32], DecodeError> {
    let bytes = bytes(item)?;
    let mut out = [0u8; 32];
    let start = 32usize
        .checked_sub(bytes.len())
        .ok_or(DecodeError::Undecodable)?;
    out[start..].copy_from_slice(bytes);
    Ok(out)
}

/// ethers' `accessListify` over the decoded list: entries of exactly an
/// address and a list of 32-byte storage keys.
fn access_list(item: Item<'_>) -> Result<Vec<AccessListEntry>, DecodeError> {
    let mut out = Vec::new();
    for entry in item.list().map_err(undecodable)?.items() {
        let entry = entry.map_err(undecodable)?.list().map_err(undecodable)?;
        let [address, keys] = fields(entry, 2)?[..] else {
            return Err(DecodeError::Undecodable);
        };
        let address = bytes(address)?.try_into().map_err(undecodable)?;
        let mut storage_keys = Vec::new();
        for key in keys.list().map_err(undecodable)?.items() {
            storage_keys.push(
                bytes(key.map_err(undecodable)?)?
                    .try_into()
                    .map_err(undecodable)?,
            );
        }
        out.push(AccessListEntry {
            address,
            storage_keys,
        });
    }
    Ok(out)
}

fn common(fields: [Item<'_>; 4], nonce: Item<'_>) -> Result<Common, DecodeError> {
    let [gas_limit, to, value, data] = fields;
    Ok(Common {
        nonce: number(nonce)?,
        gas_limit: uint(gas_limit)?,
        to: address(to)?,
        value: uint(value)?,
        data: bytes(data)?.to_vec(),
    })
}

/// The chain id and y parity a legacy `v` names: 27 or 28 without EIP-155
/// (chain 0), else `chain_id * 2 + 35 + parity` with a chain id of at least
/// 1. ethers refuses every other `v` ("non-canonical legacy v").
fn legacy_v(v: &U256) -> Result<(U256, u8), DecodeError> {
    if *v == U256::from_u64(27) {
        return Ok((U256::ZERO, 0));
    }
    if *v == U256::from_u64(28) {
        return Ok((U256::ZERO, 1));
    }
    let (chain_id, parity) = v
        .checked_sub(&U256::from_u64(35))
        .ok_or(DecodeError::Undecodable)?
        .div_rem_small(2);
    if chain_id.is_zero() {
        return Err(DecodeError::Undecodable);
    }
    Ok((chain_id, parity as u8))
}

/// ethers' `_parseLegacy`: six fields unsigned, nine signed.
fn legacy(raw: &[u8]) -> Result<SignedTx, DecodeError> {
    let list = rlp::decode_lenient(raw)
        .and_then(Item::list)
        .map_err(undecodable)?;
    let fields = fields(list, 9)?;
    let (body, signature) = match fields[..] {
        [n, gp, gl, to, value, data] => ([n, gp, gl, to, value, data], None),
        [n, gp, gl, to, value, data, v, r, s] => ([n, gp, gl, to, value, data], Some([v, r, s])),
        _ => return Err(DecodeError::Undecodable),
    };
    let [nonce, gas_price, gas_limit, to, value, data] = body;
    let gas_price = uint(gas_price)?;
    let common = common([gas_limit, to, value, data], nonce)?;
    let Some([v, r, s]) = signature else {
        return Err(DecodeError::Unsigned);
    };
    // Each is read as an integer first, then padded to 32 bytes.
    let (v, r_value, s_value) = (uint(v)?, uint(r)?, uint(s)?);
    if r_value.is_zero() && s_value.is_zero() {
        return Err(DecodeError::Unsigned);
    }
    let (chain_id, y_parity) = legacy_v(&v)?;
    Ok(SignedTx::new(
        chain_id,
        common,
        Kind::Legacy { gas_price },
        y_parity,
        word(r)?,
        word(s)?,
    ))
}

/// ethers' `_parseEip1559`, after the type byte: nine fields unsigned,
/// twelve signed.
fn eip1559(payload: &[u8]) -> Result<SignedTx, DecodeError> {
    let list = rlp::decode_lenient(payload)
        .and_then(Item::list)
        .map_err(undecodable)?;
    let fields = fields(list, 12)?;
    let (body, signature) = match fields[..] {
        [c, n, p, m, gl, to, value, data, al] => ([c, n, p, m, gl, to, value, data, al], None),
        [c, n, p, m, gl, to, value, data, al, y, r, s] => {
            ([c, n, p, m, gl, to, value, data, al], Some([y, r, s]))
        }
        _ => return Err(DecodeError::Undecodable),
    };
    let [
        chain_id,
        nonce,
        priority,
        max_fee,
        gas_limit,
        to,
        value,
        data,
        list,
    ] = body;
    let chain_id = uint(chain_id)?;
    let max_priority_fee_per_gas = uint(priority)?;
    let max_fee_per_gas = uint(max_fee)?;
    let common = common([gas_limit, to, value, data], nonce)?;
    let access_list = access_list(list)?;
    let Some([y, r, s]) = signature else {
        return Err(DecodeError::Unsigned);
    };
    let y_parity = match number(y) {
        Ok(0) => 0,
        Ok(1) => 1,
        _ => return Err(DecodeError::Undecodable),
    };
    Ok(SignedTx::new(
        chain_id,
        common,
        Kind::Eip1559 {
            max_fee_per_gas,
            max_priority_fee_per_gas,
            access_list,
        },
        y_parity,
        word(r)?,
        word(s)?,
    ))
}

/// A 32-byte word without its leading zeros, as `toBeArray` writes it.
fn minimal(word: &[u8; 32]) -> &[u8] {
    let start = word.iter().position(|b| *b != 0).unwrap_or(32);
    &word[start..]
}

impl SignedTx {
    fn new(
        chain_id: U256,
        common: Common,
        kind: Kind,
        y_parity: u8,
        r: [u8; 32],
        s: [u8; 32],
    ) -> Self {
        let Common {
            nonce,
            gas_limit,
            to,
            value,
            data,
        } = common;
        SignedTx {
            chain_id,
            nonce,
            gas_limit,
            to,
            value,
            data,
            kind,
            y_parity,
            r,
            s,
            digest: [0; 32],
            hash: [0; 32],
        }
    }

    /// The fields before the signature, as `tx.unsignedSerialized` and
    /// `tx.serialized` share them.
    fn body(&self, out: &mut Vec<u8>) {
        let nonce = U256::from_u64(self.nonce);
        let common = |out: &mut Vec<u8>| {
            rlp::uint(out, &self.gas_limit);
            rlp::bytes(out, self.to.as_ref().map_or(&[][..], |to| &to[..]));
            rlp::uint(out, &self.value);
            rlp::bytes(out, &self.data);
        };
        match &self.kind {
            Kind::Legacy { gas_price } => {
                rlp::uint(out, &nonce);
                rlp::uint(out, gas_price);
                common(out);
            }
            Kind::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
                access_list,
            } => {
                rlp::uint(out, &self.chain_id);
                rlp::uint(out, &nonce);
                rlp::uint(out, max_priority_fee_per_gas);
                rlp::uint(out, max_fee_per_gas);
                common(out);
                let mut entries = Vec::new();
                for entry in access_list {
                    let mut keys = Vec::new();
                    for key in &entry.storage_keys {
                        rlp::bytes(&mut keys, key);
                    }
                    let mut pair = Vec::new();
                    rlp::bytes(&mut pair, &entry.address);
                    rlp::list(&mut pair, &keys);
                    rlp::list(&mut entries, &pair);
                }
                rlp::list(out, &entries);
            }
        }
    }

    /// `tx.unsignedSerialized`, whose keccak256 is signed.
    fn unsigned(&self) -> Vec<u8> {
        let mut fields = Vec::new();
        self.body(&mut fields);
        let mut out = Vec::new();
        match self.kind {
            Kind::Legacy { .. } => {
                if !self.chain_id.is_zero() {
                    rlp::uint(&mut fields, &self.chain_id);
                    rlp::uint(&mut fields, &U256::ZERO);
                    rlp::uint(&mut fields, &U256::ZERO);
                }
            }
            Kind::Eip1559 { .. } => out.push(0x02),
        }
        rlp::list(&mut out, &fields);
        out
    }

    /// `tx.serialized`, with the two refusals it can make.
    fn encode(&self) -> Result<Vec<u8>, DecodeError> {
        let mut fields = Vec::new();
        self.body(&mut fields);
        let mut out = Vec::new();
        match &self.kind {
            Kind::Legacy { .. } => {
                let v = self.legacy_v().ok_or(DecodeError::Unserializable)?;
                rlp::uint(&mut fields, &v);
            }
            Kind::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
                ..
            } => {
                // ethers' inferTypes, then `Signature.s`.
                if max_priority_fee_per_gas > max_fee_per_gas || self.s[0] >= 0x80 {
                    return Err(DecodeError::Unserializable);
                }
                rlp::uint(&mut fields, &U256::from_u64(u64::from(self.y_parity)));
                out.push(0x02);
            }
        }
        rlp::bytes(&mut fields, minimal(&self.r));
        rlp::bytes(&mut fields, minimal(&self.s));
        rlp::list(&mut out, &fields);
        Ok(out)
    }

    /// The type: 0 (legacy) or 2 (EIP-1559).
    pub fn tx_type(&self) -> u8 {
        match self.kind {
            Kind::Legacy { .. } => 0,
            Kind::Eip1559 { .. } => 2,
        }
    }

    /// The chain id: from `v` for a legacy transaction, 0 without EIP-155.
    pub fn chain_id(&self) -> &U256 {
        &self.chain_id
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn gas_limit(&self) -> &U256 {
        &self.gas_limit
    }

    /// `None` for a contract creation.
    pub fn to(&self) -> Option<&[u8; 20]> {
        self.to.as_ref()
    }

    pub fn value(&self) -> &U256 {
        &self.value
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// A legacy transaction's gas price; `None` for EIP-1559.
    pub fn gas_price(&self) -> Option<&U256> {
        match &self.kind {
            Kind::Legacy { gas_price } => Some(gas_price),
            Kind::Eip1559 { .. } => None,
        }
    }

    /// An EIP-1559 transaction's `(max_fee_per_gas,
    /// max_priority_fee_per_gas)`; `None` for legacy.
    pub fn eip1559_fees(&self) -> Option<(&U256, &U256)> {
        match &self.kind {
            Kind::Legacy { .. } => None,
            Kind::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
                ..
            } => Some((max_fee_per_gas, max_priority_fee_per_gas)),
        }
    }

    /// An EIP-1559 transaction's access list; `None` for legacy.
    pub fn access_list(&self) -> Option<&[AccessListEntry]> {
        match &self.kind {
            Kind::Legacy { .. } => None,
            Kind::Eip1559 { access_list, .. } => Some(access_list),
        }
    }

    /// The signature's y parity: from `v` for a legacy transaction.
    pub fn y_parity(&self) -> u8 {
        self.y_parity
    }

    /// The `v` a legacy transaction carries: 27 or 28, or EIP-155's
    /// `chain_id * 2 + 35 + parity`. `None` for EIP-1559, which carries
    /// [`Self::y_parity`].
    pub fn v(&self) -> Option<U256> {
        match self.kind {
            Kind::Legacy { .. } => self.legacy_v(),
            Kind::Eip1559 { .. } => None,
        }
    }

    /// A legacy transaction's `v`, from its chain id and parity as ethers
    /// computes it. Always `Some` for a decoded transaction, whose chain id
    /// came from a `v` that fit.
    fn legacy_v(&self) -> Option<U256> {
        let parity = u64::from(self.y_parity);
        if self.chain_id.is_zero() {
            return Some(U256::from_u64(27 + parity));
        }
        self.chain_id
            .checked_add(&self.chain_id)
            .and_then(|double| double.checked_add(&U256::from_u64(35 + parity)))
    }

    /// `r`, left-padded to 32 bytes.
    pub fn r(&self) -> &[u8; 32] {
        &self.r
    }

    /// `s`, left-padded to 32 bytes, as written: it may be high.
    pub fn s(&self) -> &[u8; 32] {
        &self.s
    }

    /// The digest the sender signed: keccak256 of `tx.unsignedSerialized`.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The transaction hash: keccak256 of the bytes.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// The sender, as ethers' `tx.from` recovers it, or `None` where that
    /// throws. ethers first takes the signature's canonical form
    /// (`Signature.getCanonical`): an `s` above half the curve order
    /// becomes `n - s` with the other parity, which names the same key.
    /// So a high `s` has a sender (EIP-2 makes such a transaction invalid
    /// on chain, which is the node's to refuse); an `r` or `s` of zero or
    /// past the order, or an `r` that is no point's x-coordinate, has
    /// none. Recovery costs about as much as a signature check, so it is
    /// done only when asked for.
    pub fn signer(&self) -> Option<[u8; 20]> {
        let mut signature = [0u8; 65];
        signature[..32].copy_from_slice(&self.r);
        signature[32..64].copy_from_slice(&self.s);
        // r and s each between 1 and n - 1.
        let parsed = Signature::from_slice(&signature[..64]).ok()?;
        let canonical = parsed.normalize_s();
        let flipped = u8::from(canonical != parsed);
        signature[..64].copy_from_slice(&canonical.to_bytes());
        signature[64] = 27 + (self.y_parity ^ flipped);
        recover_address(&self.digest, &signature).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Transaction, address_of, parse_bytes};
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::PrimeField;
    use serde_json::json;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&keccak256(b"decode-signed").into()).unwrap()
    }

    fn signed(tx: serde_json::Value) -> Vec<u8> {
        Transaction::from_json(&tx)
            .unwrap()
            .sign(&key())
            .unwrap()
            .raw
    }

    fn eip1559() -> Vec<u8> {
        signed(json!({
            "type": 2, "chain_id": "1", "nonce": "7", "gas_limit": "21000",
            "to": "0x8ba1f109551bD432803012645Ac136ddd64DBA72", "value": "1", "data": "0x1234",
            "max_fee_per_gas": "2", "max_priority_fee_per_gas": "1"
        }))
    }

    fn legacy() -> Vec<u8> {
        signed(json!({
            "type": 0, "chain_id": "100", "nonce": "0", "gas_limit": "21000", "to": null,
            "value": "0", "data": "0x", "gas_price": "1"
        }))
    }

    #[test]
    fn reads_back_what_the_core_signs() {
        for (raw, tx_type) in [(eip1559(), 2), (legacy(), 0)] {
            let tx = decode_signed(&raw).unwrap();
            assert_eq!(tx.tx_type(), tx_type);
            assert_eq!(tx.signer(), Some(address_of(&key())));
            assert_eq!(tx.hash(), &keccak256(&raw));
        }
        let tx = decode_signed(&legacy()).unwrap();
        assert_eq!(tx.chain_id(), &U256::from_u64(100));
        assert_eq!(tx.to(), None);
        assert_eq!(tx.gas_price(), Some(&U256::from_u64(1)));
        assert_eq!(tx.access_list(), None);
        let tx = decode_signed(&eip1559()).unwrap();
        assert_eq!(tx.nonce(), 7);
        assert_eq!(tx.data(), &[0x12, 0x34]);
        assert_eq!(tx.access_list(), Some(&[][..]));
        assert_eq!(
            tx.eip1559_fees(),
            Some((&U256::from_u64(2), &U256::from_u64(1)))
        );
    }

    #[test]
    fn the_first_byte_picks_the_reading() {
        assert_eq!(decode_signed(&[]), Err(DecodeError::Undecodable));
        for first in [0x00u8, 0x05, 0x7e] {
            assert_eq!(decode_signed(&[first, 0xc0]), Err(DecodeError::Undecodable));
        }
        for first in [1u8, 3, 4] {
            assert_eq!(
                decode_signed(&[first]),
                Err(DecodeError::UnsupportedType(first))
            );
        }
        assert_eq!(decode_signed(&[0x02]), Err(DecodeError::Undecodable));
        assert_eq!(decode_signed(&[0x7f]), Err(DecodeError::Undecodable));
        assert_eq!(decode_signed(&[0x80]), Err(DecodeError::Undecodable));
    }

    #[test]
    fn high_s_has_the_same_signer() {
        let raw = legacy();
        let tx = decode_signed(&raw).unwrap();
        let s = k256::Scalar::from_repr(tx.s.into()).unwrap();
        let mut high = tx.clone();
        high.s.copy_from_slice(&(-s).to_repr());
        high.y_parity ^= 1;
        assert_eq!(high.signer(), Some(address_of(&key())));
        let raw = high.encode().unwrap();
        let decoded = decode_signed(&raw).unwrap();
        assert_eq!(decoded.s(), &high.s);
        assert_eq!(decoded.signer(), Some(address_of(&key())));
    }

    #[test]
    fn hex_round_trip() {
        let raw = parse_bytes(&crate::to_hex(&eip1559()), "raw").unwrap();
        assert!(decode_signed(&raw).is_ok());
    }
}
