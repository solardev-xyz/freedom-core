//! A Safe transaction built and proposed in the core (design 0016, "Built
//! and hashed in the core", "Owner signatures" and API; SAFE-2's S3): what
//! `safe.prepare` and `safe.propose` build, keep and sign. The requests
//! themselves, their chain reads and their bounds, are [`super::methods`]'.
//!
//! - **`safe.prepare { safe, chain_id, tx: { to, value, data } }`** →
//!   `{ safe_tx, safe_tx_hash, view }`: the SafeTx for one CALL at the
//!   Safe's verified nonce ([`Prepared`]), its ten fields as
//!   `safe-pending.json` keeps them, its hash, and the core's view of its
//!   typed data (#88), for the prompt. The core keeps it, at most [`MAX_PREPARED`], the oldest
//!   dropped, until `safe.propose` takes it.
//! - **The token** (D6): `safe.propose` spends a `safe-send` token minted
//!   for `{ safe, chain_id, safe_tx, safe_tx_hash }`, the SafeTx the core
//!   kept ([`Prepared::token_payload`]), so every field, the Safe's
//!   address, the chain and the hash are the confirmed ones. APR-4's form,
//!   `{ safe, chain_id, tx }`, is never spent here, nor this one by
//!   `approval.spend`.
//! - **The vault owners** sign at once, while the vault is unlocked
//!   ([`vault_signatures`]), as `collectFreeSignatures` does when the
//!   SafeTx is stored: one confirmation covers every local owner (0012).
//! - **A call to the Safe itself** is refused, `safe_self_call` (question
//!   4): every setup change is one, and Freedom builds no other kind of
//!   SafeTx than a CALL.

use std::collections::VecDeque;

use fc_evm::{
    U256, ViewRequest, address_of, parse_address, parse_bytes, parse_unsigned, sign_digest, to_hex,
};
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_safe::{OwnerSignature, SafeTx};
use fc_vault::state::VaultState;
use serde_json::{Value, json};

use crate::accounts::Records;

/// How many prepared SafeTxs the core keeps for `safe.propose`, as many as
/// tokens may be outstanding (fc-approval's `MAX_OUTSTANDING`): one for
/// each `safe-send` that could confirm one.
pub const MAX_PREPARED: usize = 32;

/// `safe_self_call`'s text (design 0016, question 4).
pub const SELF_CALL_TEXT: &str =
    "This transaction would change the Safe itself, which Freedom doesn't do.";

fn invalid(message: impl Into<String>) -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, message.into())
}

/// A SafeTx to `to` from the Safe at `safe`: refused when it is the Safe
/// itself, `safe_self_call` (question 4).
pub fn not_self(to: &[u8; 20], safe: &[u8; 20]) -> Result<(), ErrorBody> {
    if to == safe {
        return Err(invalid(SELF_CALL_TEXT).with_data(json!({ "safe": "self_call" })));
    }
    Ok(())
}

/// `safe.prepare`'s call: what the Safe executes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub to: [u8; 20],
    pub value: U256,
    pub data: Vec<u8>,
}

impl Call {
    /// `{ to, value, data }`, each a string as `sign.transaction` reads it:
    /// an address (a mixed-case one with its EIP-55 checksum), a quantity
    /// in decimal or `0x` hex, and `0x` hex bytes, at most 64 KiB of them
    /// (fc-safe's bound, refused before any read); nothing else.
    pub fn of(value: &Value) -> Result<Call, ErrorBody> {
        let fields = value
            .as_object()
            .filter(|fields| {
                fields.len() == 3
                    && ["to", "value", "data"]
                        .iter()
                        .all(|k| fields.contains_key(*k))
            })
            .ok_or_else(|| invalid("tx: expected { to, value, data }"))?;
        let text = |name: &str| {
            fields[name]
                .as_str()
                .ok_or_else(|| invalid(format!("Invalid {name}")))
        };
        let data = parse_bytes(text("data")?, "data").map_err(|_| invalid("Invalid data"))?;
        if data.len() > fc_safe::MAX_DATA {
            return Err(invalid(fc_safe::Error::DataTooLong.to_string()));
        }
        Ok(Call {
            to: parse_address(text("to")?).map_err(|_| invalid("Invalid to"))?,
            value: parse_unsigned(text("value")?).ok_or_else(|| invalid("Invalid value"))?,
            data,
        })
    }

    /// The Safe at `safe` calling itself: refused, `safe_self_call`.
    pub fn check_not_self(&self, safe: &[u8; 20]) -> Result<(), ErrorBody> {
        not_self(&self.to, safe)
    }

    /// The SafeTx for this call at `nonce`, the Safe's verified one:
    /// refused past 2^53 − 1, and for data past 64 KiB (fc-safe's bounds).
    pub fn at(&self, nonce: &U256) -> Result<SafeTx, ErrorBody> {
        let nonce = SafeTx::nonce_from(nonce).map_err(|error| invalid(error.to_string()))?;
        SafeTx::new(self.to, self.value, self.data.clone(), nonce)
            .map_err(|error| invalid(error.to_string()))
    }
}

/// A SafeTx the core built at `safe.prepare`, for the Safe at wallet index
/// `index` and address `safe`, kept for `safe.propose`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub index: u64,
    pub safe: [u8; 20],
    pub tx: SafeTx,
    pub hash: [u8; 32],
}

impl Prepared {
    pub fn new(index: u64, safe: [u8; 20], tx: SafeTx) -> Result<Self, ErrorBody> {
        let hash = tx.hash(&safe).map_err(|_| crate::vault::internal())?;
        Ok(Prepared {
            index,
            safe,
            tx,
            hash,
        })
    }

    /// `safe.prepare`'s answer: `{ safe_tx, safe_tx_hash, view }`, the
    /// fields as `safe-pending.json` keeps them, the hash, and the core's
    /// view of the typed data the owners sign (#88), whose hash is the
    /// SafeTx's.
    pub fn answer(&self) -> Result<Value, ErrorBody> {
        let typed = self.tx.typed_data(&self.safe);
        // Hashed as fc-safe hashes it: the domain, and `SafeTx` alone.
        let types = json!({ "SafeTx": typed["types"]["SafeTx"].clone() });
        let primary = json!("SafeTx");
        let viewed = fc_evm::typed_data_view(
            &typed["domain"],
            &types,
            &typed["message"],
            &ViewRequest {
                primary_type: Some(&primary),
                chain_id: Some(U256::from_u64(fc_safe::constants::CHAIN_ID)),
                max_len: crate::signing::max_view_len(),
            },
        )
        .map_err(|error| invalid(error.to_string()))?;
        if viewed.hash != self.hash {
            return Err(crate::vault::internal());
        }
        let view: Value =
            serde_json::from_str(&viewed.view).map_err(|_| crate::vault::internal())?;
        Ok(json!({
            "safe_tx": self.tx.fields(),
            "safe_tx_hash": to_hex(&self.hash),
            "view": view,
        }))
    }

    /// The `safe-send` payload its token binds (D6): `{ safe, chain_id,
    /// safe_tx, safe_tx_hash }`.
    pub fn token_payload(&self) -> Value {
        json!({
            "safe": fc_evm::checksum_address(&self.safe),
            "chain_id": fc_safe::constants::CHAIN_ID.to_string(),
            "safe_tx": self.tx.fields(),
            "safe_tx_hash": to_hex(&self.hash),
        })
    }
}

/// The SafeTxs `safe.prepare` built, oldest first, at most
/// [`MAX_PREPARED`].
#[derive(Debug, Default)]
pub struct PreparedTxs {
    kept: VecDeque<Prepared>,
}

impl PreparedTxs {
    /// Keeps `prepared`: the same SafeTx for the same Safe once, the oldest
    /// dropped past the bound.
    pub fn keep(&mut self, prepared: Prepared) {
        self.kept.retain(|kept| {
            (kept.index, kept.safe, kept.hash) != (prepared.index, prepared.safe, prepared.hash)
        });
        while self.kept.len() >= MAX_PREPARED {
            self.kept.pop_front();
        }
        self.kept.push_back(prepared);
    }

    /// The SafeTx `hash` built for the Safe at `index` and `safe`, taken.
    pub fn take(&mut self, index: u64, safe: &[u8; 20], hash: &[u8; 32]) -> Option<Prepared> {
        let at = self
            .kept
            .iter()
            .position(|kept| kept.index == index && kept.safe == *safe && kept.hash == *hash)?;
        self.kept.remove(at)
    }

    /// The SafeTx `hash` built for the Safe at `index` and `safe`, kept.
    pub fn get(&self, index: u64, safe: &[u8; 20], hash: &[u8; 32]) -> Option<&Prepared> {
        self.kept
            .iter()
            .find(|kept| kept.index == index && kept.safe == *safe && kept.hash == *hash)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.kept.len()
    }
}

/// The vault owners' signatures over the SafeTx `hash`, as
/// `collectFreeSignatures` makes them when the SafeTx is stored: none while
/// the vault is locked; otherwise each vault owner in the record's order
/// (`vault_owners`: index and address), until `threshold` have signed. An
/// owner the records don't let the vault sign for, whose key can't be
/// derived, or whose key's address isn't the record's, is passed over, as
/// the reference passes over an owner whose signature fails. Each
/// signature is checked as every owner's is (`OwnerSignature::check`,
/// against the record's `owners`) before it counts. The keys are derived
/// one at a time and wiped when dropped.
pub fn vault_signatures(
    state: &VaultState,
    records: &Records,
    vault_owners: &[(u64, [u8; 20])],
    owners: &[[u8; 20]],
    hash: &[u8; 32],
    threshold: usize,
) -> Vec<OwnerSignature> {
    let mut signed = Vec::new();
    if !state.is_unlocked() {
        return signed;
    }
    for &(index, address) in vault_owners {
        if signed.len() >= threshold {
            break;
        }
        match vault_signature(state, records, index, &address, owners, hash) {
            Ok(checked) => signed.push(checked),
            Err(_) => crate::log::warn("a vault owner's Safe signature was passed over", json!({})),
        }
    }
    signed
}

/// One vault owner's signature over `hash` (a SafeTx's or a SafeMessage's),
/// the owner at wallet index `index` whose record's address is `address`,
/// checked as every owner's is against the record's `owners`: `vault_locked`
/// while the vault is locked; the records' refusal of a key the vault
/// doesn't sign for; and `internal` for a key that can't be derived, whose
/// address isn't the record's, or whose signature doesn't check. The key is
/// derived alone and wiped when dropped.
pub fn vault_signature(
    state: &VaultState,
    records: &Records,
    index: u64,
    address: &[u8; 20],
    owners: &[[u8; 20]],
    hash: &[u8; 32],
) -> Result<OwnerSignature, ErrorBody> {
    if !state.is_unlocked() {
        return Err(crate::vault::locked());
    }
    let index = u32::try_from(index).map_err(|_| crate::vault::internal())?;
    records.vault_signs(index)?;
    let key = state
        .user_wallet(index)
        .map_err(crate::vault::locked_or_internal)?;
    let key = key.signing_key();
    if address_of(key) != *address {
        return Err(crate::vault::internal());
    }
    let signature = sign_digest(key, hash).map_err(|_| crate::vault::internal())?;
    OwnerSignature::check(hash, &signature, address, owners).map_err(|_| crate::vault::internal())
}

#[cfg(test)]
mod tests;
