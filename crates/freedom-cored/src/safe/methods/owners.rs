//! Owners who sign after a proposal (design 0016, "Owner signatures",
//! "Messages", "The device lane" and API; SAFE-2's S6): `safe.sign_owner`
//! for a pending SafeTx, its vault owners (the board's sweep after a
//! proposal made while the vault was locked) and a Ledger owner on the
//! device lane; and a Ledger owner's signature over a page's SafeMessage,
//! which `safe.message_sign` asks for ([`super::messages`]).
//!
//! - **`safe.sign_owner { safe, owner?, safe_tx_hash? }`** → the board's
//!   state (`signSafePending`): the Safe's pending SafeTx as S3's codec
//!   reads it for its record (`safe_tx_hash`, when given, must name it,
//!   else `SAFE_DISCARDED`: the board's step acts only on the SafeTx it
//!   showed); none is "No pending transaction for this account", and one
//!   marked superseded "This transaction can no longer be signed — discard
//!   it". An entry without the core's proposal mark for the record's Safe
//!   and that SafeTx ([`entry::PROPOSAL`]) is `not_proposed`, before any
//!   read: only `safe.propose`, which spent the `safe-send` that authorized
//!   every local owner's signature over it, marks one, and main's
//!   `safe_pending.set` can't (design 0016, "Owner signatures"; 0012: a
//!   Safe owner's signature under `shell` needs the Safe's authorization).
//!   Without `owner`, the vault owners that haven't signed, in the
//!   record's order, until the record's threshold (`collectFreeSignatures`);
//!   with one, that owner, once: one not the Safe's is "That account is not
//!   an owner of this Safe", and one that signed is answered the state,
//!   idempotent. A SafeTx's owner may sign past the threshold, as the
//!   reference's chosen owner does: a send's approval doesn't end at it, as
//!   a message's does. A vault owner named while the vault is locked is
//!   `vault_locked`; a sweep that can sign nothing (the vault locked, the
//!   threshold met, every vault owner signed) is answered the state with no
//!   read. A phone owner is `unsupported` (0012's phone jobs).
//! - **Then the eight reads,** each verified, the nonce last, as before
//!   every owner's signature (`safe_changed`, `safe_unverified`,
//!   `not_deployed`, nothing signed). The record and the entry must still be
//!   the ones read (`SAFE_DISCARDED`), the entry still marked
//!   (`not_proposed`), and the SafeTx must be the one the Safe's verified
//!   nonce executes next: a nonce past it is the superseded refusal, one
//!   below it `nonce_behind`, each with nothing signed or written
//!   (conservative: a signature that can't execute is never made).
//! - **The vault owners** then sign where no vault job is running, with the
//!   vault's state as it stands ([`Safes::owner_signed`]).
//! - **A Ledger owner** (D9's record: a Ledger's, at a scheme's path) signs
//!   on the device lane, `sign.typed_data`'s rows over the core's SafeTx
//!   (the grammar's `safe.sign_owner` row), its typed data fc-safe's for
//!   the pending entry's fields. Its operation is built before any read, so
//!   what a Ledger can't carry is refused first (`device_failed`). Its
//!   signature comes back checked by fc-ledger (recovered against the
//!   record's address over the SafeTx's hash, a low `s`), and is used only
//!   while the record and the pending entry are still the ones checked, as
//!   L4's rule has an owner's signature used only while its SafeTx is the
//!   one fixed: otherwise `SAFE_DISCARDED`, "The request was discarded while
//!   the signature was being made", and nothing of it is kept; an entry
//!   that lost its mark meanwhile is `not_proposed`, nothing kept. A cancel
//!   ends it on the lane (`cancelled`, nothing kept).
//! - **The entry** keeps every signature it held, byte for byte; the new
//!   ones are appended, `{ signer, data }`, as the reference appends them,
//!   and written while the entry is still the one read (one changed
//!   meanwhile is `SAFE_DISCARDED`, nothing written). The answer is the
//!   board's state, with `durable: false` when the write's flush failed.
//! - **The Safe's hold** covers the whole step, its reads, the device's
//!   wait and the write, as the reference's `acquire` spans a chosen
//!   owner's ceremony: every other step of the Safe is `SAFE_BUSY`.
//! - **Time:** the reads have the `session` class's 120 s from receipt; on
//!   the lane the lane's own bounds hold, never the reads'; once the device
//!   signed, the write has 120 s more.

use fc_ledger::{Account, Operation, Refusal};
use fc_safe::{OwnerSignature, SafeTx, Signatures};

use super::messages::NOT_OWNER_TEXT;
use super::*;

/// `signSafePending`'s refusal of a SafeTx marked superseded, and the
/// core's of one the Safe's verified nonce has passed.
const SUPERSEDED_TEXT: &str = "This transaction can no longer be signed \u{2014} discard it";

/// An entry `safe.propose` didn't write (`not_proposed`): no `safe-send`
/// was spent through the core for it.
pub(super) const NOT_PROPOSED_TEXT: &str = "This transaction wasn't confirmed in Freedom, so its \
     owners can't sign it here \u{2014} discard it and send it again";

/// A phone owner's signature (`unsupported`): 0012's phone jobs.
pub(super) const PHONE_OWNER_TEXT: &str = "A phone owner can't sign for a Safe here yet";

/// `signEntryOwner`'s, for a SafeTx or a session ended or replaced while
/// its owner signed (`SAFE_DISCARDED`).
pub(super) const DISCARDED_WHILE_TEXT: &str =
    "The request was discarded while the signature was being made";

/// The owner a step names.
pub(super) enum Named {
    /// A vault owner: its wallet index and address.
    Vault { index: u64, address: [u8; 20] },
    /// A Ledger owner, on the device lane.
    Ledger(Box<Device>),
}

/// A Ledger owner's signature: its record's address, its operation until
/// the lane takes it, and the signature once fc-ledger checked it.
pub(super) struct Device {
    pub(super) address: [u8; 20],
    operation: Option<Operation>,
    signature: Option<[u8; 65]>,
}

impl Device {
    /// Its operation, for the lane: taken once.
    pub(super) fn take_operation(&mut self) -> Option<Operation> {
        self.operation.take()
    }

    /// The signature the device made, once it came back.
    pub(super) fn signature(&self) -> Result<[u8; 65], ErrorBody> {
        self.signature.ok_or_else(crate::vault::internal)
    }
}

/// The owner at wallet index `owner`, one of the Safe's whose address is
/// `address`: a vault owner; a Ledger owner, D9's record (`invalid_argument`
/// for a Ledger record no Ledger signs at), with its operation `build`
/// made now, so what a Ledger can't carry is refused before any read
/// (`device_failed`); anything else `unsupported`, a phone's among them.
pub(super) fn named(
    ctx: &Ctx,
    safe: &Safe,
    owner: u64,
    address: &[u8; 20],
    build: impl FnOnce(Account) -> Result<Operation, Refusal>,
) -> Result<Named, ErrorBody> {
    if let Some((index, address)) = safe.vault_owners.iter().find(|(at, _)| *at == owner) {
        return Ok(Named::Vault {
            index: *index,
            address: *address,
        });
    }
    let records = ctx.approvals.account_records().ok_or_else(not_moved)?;
    let ledger = records
        .record(owner as f64)?
        .is_some_and(|record| record.get("type").and_then(JsValue::as_str) == Some("ledger"));
    if !ledger {
        return Err(refused("unsupported", PHONE_OWNER_TEXT));
    }
    let index = u32::try_from(owner).map_err(|_| plain(crate::accounts::NOT_LEDGER.to_owned()))?;
    let account = ctx.approvals.ledger_account(index)?;
    // The Safe's owner is the record's address, as the Safe's record
    // resolves it: never another.
    if account.address != *address {
        return Err(plain(crate::accounts::LEDGER_ADDRESS.to_owned()));
    }
    let operation = build(account).map_err(crate::signing::device_refusal)?;
    Ok(Named::Ledger(Box::new(Device {
        address: *address,
        operation: Some(operation),
        signature: None,
    })))
}

/// A Ledger owner's operation over the SafeTx `tx` of the Safe at `safe`,
/// whose hash is `hash`: `sign.typed_data`'s, over fc-safe's typed data,
/// its domain and `SafeTx` alone, as fc-safe hashes it.
pub(super) fn tx_operation(
    account: Account,
    safe: &[u8; 20],
    tx: &SafeTx,
    hash: &[u8; 32],
) -> Result<Operation, Refusal> {
    let typed = tx.typed_data(safe);
    let types = json!({ "SafeTx": typed["types"]["SafeTx"].clone() });
    Operation::sign_typed_data(account, &typed["domain"], &types, &typed["message"], hash)
}

/// A Ledger owner's operation over the SafeMessage `{ message: digest }`
/// of the Safe at `safe`, whose hash is `hash`: `sign.typed_data`'s, over
/// fc-safe's typed data, its domain and `SafeMessage` alone.
pub(super) fn message_operation(
    account: Account,
    safe: &[u8; 20],
    digest: &[u8; 32],
    hash: &[u8; 32],
) -> Result<Operation, Refusal> {
    let typed = fc_safe::SafeMessage::new(*digest).typed_data(safe);
    let types = json!({ "SafeMessage": typed["types"]["SafeMessage"].clone() });
    Operation::sign_typed_data(account, &typed["domain"], &types, &typed["message"], hash)
}

/// The Safe's pending entry as the store holds it and as the codec reads
/// it for the record `checked`, the record as it stands now: both still
/// the ones checked (the record's address and setup, the entry's hash),
/// else `refusal`.
fn current(
    checked: &Safe,
    hash: &[u8; 32],
    ctx: &Ctx,
    refusal: impl Fn() -> ErrorBody,
) -> Result<(Safe, JsValue, entry::Entry), ErrorBody> {
    let records = ctx.approvals.account_records().ok_or_else(not_moved)?;
    let safe = resolve(records, checked.index)?;
    if safe.address != checked.address || safe.setup != checked.setup {
        return Err(plain(format!(
            "Wallet {} is not a Safe account",
            safe.index
        )));
    }
    let raw = ctx.pending.entry(safe.index).ok_or_else(&refusal)?;
    let read = entry::read(&raw, &safe.address, safe.setup.owners())
        .ok()
        .filter(|read| read.hash == *hash)
        .ok_or_else(&refusal)?;
    if !read.proposed {
        return Err(not_proposed());
    }
    Ok((safe, raw, read))
}

/// `not_proposed`: an entry without the core's proposal mark.
fn not_proposed() -> ErrorBody {
    refused("not_proposed", NOT_PROPOSED_TEXT)
}

/// Whether `signatures` holds one from `owner`.
pub(super) fn has_signed(signatures: &Signatures, owner: &[u8; 20]) -> bool {
    signatures.kept().iter().any(|kept| kept.owner() == owner)
}

impl Safes {
    /// `safe.sign_owner`: refused or answered at once, or the eight reads
    /// out before its owners sign.
    pub(super) fn sign_owner(
        &mut self,
        id: u64,
        raw: Option<&str>,
        records: &Records,
        ctx: &mut Ctx,
    ) -> Result<Vec<Out>, ErrorBody> {
        ctx.pending.check_moved()?;
        let mut params = Value::Null;
        let p = members(raw, &["safe", "owner", "safe_tx_hash"], &mut params)?;
        let index = index_of(p, "safe")?;
        let owner = match p.get("owner") {
            None | Some(Value::Null) => None,
            Some(_) => Some(index_of(p, "owner")?),
        };
        let named_hash = match p.get("safe_tx_hash") {
            None | Some(Value::Null) => None,
            Some(_) => Some(hash_param(p, "safe_tx_hash")?),
        };
        let safe = resolve(records, index)?;
        // `signSafePending`'s order: the SafeTx named, one pending, not
        // marked superseded.
        let entry = pending_entry(ctx.pending, &safe);
        if let Some(named) = named_hash
            && entry.as_ref().map(|entry| entry.hash) != Some(named)
        {
            return Err(refused("SAFE_DISCARDED", DISCARDED_TEXT));
        }
        let Some(entry) = entry else {
            return Err(plain(NO_PENDING_TEXT));
        };
        if entry.superseded {
            return Err(plain(SUPERSEDED_TEXT));
        }
        // Only an entry `safe.propose` wrote: its spent `safe-send` is what
        // authorizes the owners' signatures over it.
        if !entry.proposed {
            return Err(not_proposed());
        }
        // `signEntryOwner`'s, for a chosen owner: one of the Safe's, and
        // not signed already (the state, idempotent).
        let owner = match owner {
            None => None,
            Some(owner) => {
                let Some((_, address)) = safe.owners.iter().find(|(at, _)| *at == owner as f64)
                else {
                    return Err(plain(NOT_OWNER_TEXT));
                };
                if has_signed(&entry.signatures, address) {
                    return Ok(vec![js_reply(id, &board(records, &safe, ctx.pending)?)]);
                }
                Some(named(ctx, &safe, owner, address, |account| {
                    tx_operation(account, &safe.address, &entry.tx, &entry.hash)
                })?)
            }
        };
        if self.busy(index) {
            return Err(refused("SAFE_BUSY", STEP_BUSY_TEXT));
        }
        match &owner {
            Some(Named::Vault { .. }) if !ctx.unlocked => return Err(crate::vault::locked()),
            // Nothing the sweep could sign: the state, with no read.
            None if !ctx.unlocked
                || entry.signatures.len() >= safe.setup.threshold()
                || safe
                    .vault_owners
                    .iter()
                    .all(|(_, address)| has_signed(&entry.signatures, address)) =>
            {
                return Ok(vec![js_reply(id, &board(records, &safe, ctx.pending)?)]);
            }
            _ => {}
        }
        let work = Work::SignOwner {
            hash: entry.hash,
            owner,
        };
        Ok(self.check(id, Kind::SignOwner, safe, work, ctx.now))
    }

    /// `safe.sign_owner`'s reads are in, the setup the record's and the
    /// Safe's verified nonce `nonce`: the record and the entry still the
    /// ones read, and the SafeTx the one that nonce executes; then a vault
    /// owner's signing is due, or a Ledger owner's operation goes to the
    /// lane.
    pub(super) fn owner_checked(
        &mut self,
        id: u64,
        mut op: Op,
        hash: [u8; 32],
        owner: Option<Named>,
        nonce: &U256,
        ctx: &mut Ctx,
    ) -> Vec<Out> {
        let (safe, entry) = match still(&op.safe, &hash, ctx) {
            Ok(still) => still,
            Err(error) => return vec![failed(id, &error)],
        };
        if !entry.proposed {
            return vec![failed(id, &not_proposed())];
        }
        if entry.superseded {
            return vec![failed(id, &plain(SUPERSEDED_TEXT))];
        }
        match entry.tx.nonce_state(nonce) {
            fc_safe::NonceState::Ready => {}
            fc_safe::NonceState::Behind => {
                return vec![failed(id, &refused("nonce_behind", NONCE_BEHIND_TEXT))];
            }
            fc_safe::NonceState::Superseded => return vec![failed(id, &plain(SUPERSEDED_TEXT))],
        }
        op.safe = safe;
        match owner {
            Some(Named::Ledger(mut device)) => {
                let Some(operation) = device.take_operation() else {
                    return vec![failed(id, &crate::vault::internal())];
                };
                op.work = Work::SignOwner {
                    hash,
                    owner: Some(Named::Ledger(device)),
                };
                self.onto_lane(id, op, operation)
            }
            owner => {
                op.work = Work::SignOwner { hash, owner };
                op.step = Step::Write;
                self.ops.insert(id, op);
                self.writes.push(id);
                Vec::new()
            }
        }
    }

    /// A Ledger owner's operation onto the device lane, `op` holding the
    /// Safe meanwhile.
    pub(super) fn onto_lane(&mut self, id: u64, mut op: Op, operation: Operation) -> Vec<Out> {
        op.step = Step::Device;
        self.ops.insert(id, op);
        crate::log::info("a Safe owner's signature goes to the Ledger", json!({}));
        vec![Out::SafeLedger(id, Box::new(operation))]
    }

    /// Request `id`'s Ledger owner's operation ended on the device lane
    /// (design 0016, S6): its signature, checked by fc-ledger, is kept for
    /// the write, which runs where no vault job is running
    /// ([`Safes::write`]), with 120 s from `now`; any other end answers
    /// the request (`device_failed`, `cancelled`), nothing kept. A request
    /// no longer here (cancelled, past its time) changes nothing.
    pub fn device_ended(
        &mut self,
        id: u64,
        ended: Result<fc_ledger::Signed, ErrorBody>,
        now: Instant,
    ) -> Vec<Out> {
        let Some(mut op) = self.ops.remove(&id) else {
            return Vec::new();
        };
        if !matches!(op.step, Step::Device) {
            self.ops.insert(id, op);
            return Vec::new();
        }
        let signature = match ended {
            Ok(fc_ledger::Signed::Signature(signature)) => signature,
            Ok(_) => return vec![failed(id, &crate::vault::internal())],
            Err(error) => return vec![failed(id, &error)],
        };
        let device = match &mut op.work {
            Work::SignOwner {
                owner: Some(Named::Ledger(device)),
                ..
            }
            | Work::MessageSign {
                owner: Some(Named::Ledger(device)),
                ..
            } => device,
            _ => return vec![failed(id, &crate::vault::internal())],
        };
        device.signature = Some(signature);
        op.step = Step::Write;
        op.deadline = now + Duration::from_millis(DEADLINE_MS);
        self.ops.insert(id, op);
        self.writes.push(id);
        Vec::new()
    }

    /// `safe.sign_owner`'s signing and write, where no vault job is
    /// running, with the vault's `state`: its answer, the board's state.
    pub(super) fn owner_signed(
        &mut self,
        id: u64,
        checked: &Safe,
        hash: [u8; 32],
        owner: Option<Named>,
        state: &VaultState,
        ctx: &mut Ctx,
    ) -> Out {
        match sign_entry(checked, &hash, owner, state, ctx) {
            Ok(state) => js_reply(id, &state),
            Err(error) => failed(id, &error),
        }
    }
}

/// The board's state for the Safe's pending entry as it stands.
fn board(records: &Records, safe: &Safe, pending: &SafePending) -> Result<JsValue, ErrorBody> {
    let raw = pending
        .entry(safe.index)
        .ok_or_else(|| plain(NO_PENDING_TEXT))?;
    let read = entry::read(&raw, &safe.address, safe.setup.owners())
        .map_err(|_| plain(NO_PENDING_TEXT))?;
    send_state(records, safe.index, &raw, &signers(&read), read.superseded)?
        .ok_or_else(crate::vault::internal)
}

/// The owners' signatures over the SafeTx `hash` of the record `checked`,
/// appended to its pending entry while it is still the one read: the
/// named vault owner's, the Ledger owner's the device made, or the vault
/// owners' sweep.
fn sign_entry(
    checked: &Safe,
    hash: &[u8; 32],
    owner: Option<Named>,
    state: &VaultState,
    ctx: &mut Ctx,
) -> Result<JsValue, ErrorBody> {
    let records = ctx
        .approvals
        .account_records()
        .ok_or_else(not_moved)?
        .clone();
    let discarded = || refused("SAFE_DISCARDED", DISCARDED_WHILE_TEXT);
    let (safe, raw, read) = current(checked, hash, ctx, discarded)?;
    if read.superseded {
        return Err(plain(SUPERSEDED_TEXT));
    }
    let owners = safe.setup.owners();
    let mut counted = read.signatures.clone();
    let mut added: Vec<OwnerSignature> = Vec::new();
    match owner {
        Some(Named::Vault { index, address }) => {
            if !has_signed(&counted, &address) {
                let signature = super::super::tx::vault_signature(
                    state, &records, index, &address, owners, hash,
                )?;
                if counted.add(signature) {
                    added.push(signature);
                }
            }
        }
        Some(Named::Ledger(device)) => {
            if !has_signed(&counted, &device.address) {
                let signature =
                    OwnerSignature::check(hash, &device.signature()?, &device.address, owners)
                        .map_err(|_| crate::vault::internal())?;
                if counted.add(signature) {
                    added.push(signature);
                }
            }
        }
        None => added = super::messages::sweep(state, &records, &safe, hash, &mut counted),
    }
    if added.is_empty() {
        return send_state(&records, safe.index, &raw, &signers(&read), false)?
            .ok_or_else(crate::vault::internal);
    }
    // The reference's `[...current.signatures, signature]`: what the entry
    // held, byte for byte, then the new ones.
    let mut listed: Vec<JsValue> = raw
        .get("signatures")
        .and_then(JsValue::as_array)
        .map(<[JsValue]>::to_vec)
        .ok_or_else(discarded)?;
    listed.extend(added.iter().map(|signature| {
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
    }));
    let mut written = raw.clone();
    written.set("signatures", JsValue::Array(listed));
    let durable = ctx
        .pending
        .set_where(safe.index, written.clone(), |now| now == Some(&raw))
        .map_err(|failure| match failure {
            Failure::Bound(_) => refused("store_full", STORE_FULL_TEXT),
            other => other.error(),
        })?
        .ok_or_else(discarded)?;
    crate::log::info(
        "a pending Safe transaction signed",
        json!({ "signed": added.len() }),
    );
    let signed: Vec<[u8; 20]> = counted.kept().iter().map(|kept| *kept.owner()).collect();
    let mut answer = send_state(&records, safe.index, &written, &signed, false)?
        .ok_or_else(crate::vault::internal)?;
    if !durable {
        answer.set("durable", JsValue::Bool(false));
    }
    Ok(answer)
}
