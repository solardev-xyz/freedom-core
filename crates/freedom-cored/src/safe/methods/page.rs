//! A site's Safe send under SAFE-3's field (design 0016, C1): main's
//! `core.hello` declares `safe3`, and `eip1193.request`'s
//! `eth_sendTransaction` for a Safe account runs `safe.prepare`'s checks,
//! reads and build before its prompt, so that the prompt shows the whole
//! SafeTx with its nonce, and its approve mints design 0016's `safe-send`
//! for the page and the handle, which main presents to `safe.propose`
//! under `page`.
//!
//! - **The same steps as `safe.prepare`** ([`PageSafe`]): the checks before
//!   any read, in its order (the record, Gnosis, the deployed mark, a call
//!   to the Safe itself), then the eight reads, each verified, the nonce
//!   last ([`Evidence::start`]), then the SafeTx for the call at that
//!   nonce. The page request's own step in `eip1193` drives the reads, on
//!   its clock: no `safe.*` request is open for them, and they hold no
//!   Safe, as `safe.prepare`'s don't.
//! - **Kept as its token is minted** ([`Safes::keep_built`]): the SafeTx a
//!   page's `safe-send` of D6's form binds joins the ones `safe.prepare`
//!   keeps, so that `safe.propose` finds it by its hash. A prompt rejected
//!   or abandoned keeps nothing.

use super::*;

/// A site's Safe send past `safe.prepare`'s checks before its reads: the
/// Safe's record, read for it, and the call.
pub struct PageSafe {
    safe: Safe,
    call: Call,
}

/// The SafeTx built for a site's Safe send, each part as JSON text: its
/// ten fields as `safe-pending.json` keeps them, its hash, and the
/// `safe-send` payload its token binds, D6's `{ safe, chain_id, safe_tx,
/// safe_tx_hash }`.
pub struct Built {
    pub safe_tx: String,
    pub safe_tx_hash: String,
    pub payload: String,
}

impl PageSafe {
    /// `safe.prepare`'s checks before any read, for the Safe at wallet
    /// index `index` (the page's grant's) and `call`, `{ to, value, data }`
    /// as JSON text, on Gnosis (the page's chain, which `eip1193` has
    /// already required): `not_moved` before `vault_meta` is moved, then
    /// the record, the deployed mark and a call to the Safe itself, each as
    /// `safe.prepare` refuses it.
    pub fn check(records: Option<&Records>, index: u32, call: &str) -> Result<Self, ErrorBody> {
        let records = records.ok_or_else(not_moved)?;
        let call = serde_json::from_str::<Value>(call).map_err(|_| invalid())?;
        let call = Call::of(&call)?;
        let safe = prepare_checked(records, u64::from(index), Some(CHAIN_ID), &call)?;
        Ok(PageSafe { safe, call })
    }

    /// The eight reads, each with `deadline_ms`, the code first and the
    /// nonce last: the check, and its first read, tagged from `tags`.
    pub fn start(&self, deadline_ms: u64, tags: &mut Tags) -> (Evidence, Vec<ChainRead>) {
        Evidence::start(
            self.safe.address,
            self.safe.setup.clone(),
            deadline_ms,
            tags,
        )
    }

    /// The reads' outcome: the SafeTx for the call at the verified nonce,
    /// as `safe.prepare` builds it; or `safe.prepare`'s refusal
    /// (`not_deployed`, `safe_changed`, `safe_unverified`, a nonce past
    /// 2^53 − 1).
    pub fn built(&self, outcome: Outcome) -> Result<Built, ErrorBody> {
        let nonce = signing_nonce(outcome)?;
        let tx = self.call.at(&nonce)?;
        let prepared = Prepared::new(self.safe.index, self.safe.address, tx)?;
        Ok(Built {
            safe_tx: prepared.tx.fields().to_string(),
            safe_tx_hash: to_hex(&prepared.hash),
            payload: prepared.token_payload().to_string(),
        })
    }
}

impl Safes {
    /// The SafeTx a site's `safe-send` of D6's form binds (`payload`, the
    /// core's own `{ safe, chain_id, safe_tx, safe_tx_hash }`), for the
    /// Safe at wallet index `index`, kept for `safe.propose` as its token is
    /// minted, as `safe.prepare` keeps the ones it builds. A payload whose
    /// fields don't recompute to its hash for its Safe is refused, and
    /// nothing is kept.
    pub fn keep_built(&mut self, index: u64, payload: &Value) -> Result<(), ErrorBody> {
        let safe = payload
            .get("safe")
            .and_then(Value::as_str)
            .and_then(|text| fc_evm::parse_address(text).ok())
            .ok_or_else(crate::vault::internal)?;
        let tx = payload
            .get("safe_tx")
            .and_then(|fields| fc_safe::SafeTx::from_fields(fields).ok())
            .ok_or_else(crate::vault::internal)?;
        let prepared = Prepared::new(index, safe, tx)?;
        let named = payload.get("safe_tx_hash").and_then(Value::as_str);
        if named != Some(to_hex(&prepared.hash).as_str()) {
            return Err(crate::vault::internal());
        }
        self.prepared.keep(prepared);
        Ok(())
    }
}
