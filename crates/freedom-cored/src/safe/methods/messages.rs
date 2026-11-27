//! A page's Safe message (EIP-1271; design 0016, "Messages" and API;
//! SAFE-2's S5): a `personal_sign` or `eth_signTypedData_v4` for a Safe
//! account answered with its owners' signatures over the SafeMessage, as
//! `safe-messages.js` collects them, in a session the core keeps in memory,
//! one per Safe.
//!
//! - **`safe.message_start { safe, request: { method, params }, display?,
//!   authorization }`** → `{ session, state }` (`startSafeMessage`), a
//!   page's alone: for a Safe the record marks deployed (`not_deployed`
//!   before anything else is read or spent), the digest a verifier computes
//!   for the request (`requestDigest`: EIP-191's for `personal_sign`, the
//!   core's EIP-712 hash for typed data), the SafeMessage `{ message: digest
//!   }` under the Safe's domain on Gnosis and its hash (fc-safe). While a
//!   session is open for the Safe, another start is `SAFE_MESSAGE_EXISTS`,
//!   from any page, the same one included: every session is main's for one
//!   page request (the reference's `owner: 'main'`), never resumed or
//!   replaced by another start; an ended one gives way. Then the
//!   authorization ([`Approvals::spend_safe_message`]): the `safe-message`
//!   token minted for the page's request, spent for the page and handle it
//!   was minted for, or the site's standing rule, which gives no Safe
//!   approval: the core signs the owners' signatures itself. Then the eight
//!   reads, each verified, the nonce last ([`Evidence::start`]), and, where
//!   no vault job is running, the vault owners sign while the vault is
//!   unlocked, in the record's order until the threshold
//!   (`collectFreeSignatures`), and the session opens. `session` is its ID,
//!   16 random bytes as 32 lowercase hex digits (today's UUID's place): a
//!   bearer secret, the capability the board's calls present, sent once,
//!   compared in constant time, wiped when dropped and never logged.
//! - **`safe.message_sign { safe, session, owner? }`** → the state
//!   (`signSafeMessage`): without `owner`, the vault owners that haven't
//!   signed, until the threshold; with one, that owner, once (one that
//!   signed already is answered the state, idempotent). The setup is read
//!   first, as before every owner's signature, each read verified
//!   (`safe_changed`, `safe_unverified`, `not_deployed`, nothing signed),
//!   unless the step can sign nothing: the threshold met, or the sweep with
//!   the vault locked or every vault owner signed, answered at once. A
//!   Ledger owner (S6) and a phone owner are `unsupported`.
//! - **`safe.message_state { safe, session }`** → the state, or `null`
//!   when no session is open, the ID isn't its, or it has ended
//!   (`getSafeMessageState`).
//! - **`safe.message_cancel { safe, session }`** → `{}` (`cancelSafeMessage`):
//!   the session dropped; none open is `{}`. While a step holds the Safe,
//!   the session is ended at once (nothing more signs or completes it) and
//!   the answer is `SAFE_BUSY`; the next cancel, or the next start, drops
//!   it.
//! - **`safe.message_complete { safe, session }`** → `{ signature }`
//!   (`completeSafeMessage`): once the threshold is met, the owners'
//!   signatures sorted by owner and joined (`buildSignatureBytes`), and the
//!   session dropped; below it, "Not enough signatures yet (n of m)".
//! - **The state** is `sessionState`'s fields but its token: `{ safeIndex,
//!   kind: "message", chainId, hash, threshold, collected, owners, display,
//!   createdAt, complete }`, `owners` as the board's rows. The ID goes only
//!   in `safe.message_start`'s answer.
//! - **The session** follows the records: a Safe they no longer hold drops
//!   its session ([`Sessions::retain`]). A lock changes nothing: the
//!   signatures aren't secret, and a locked vault signs nothing more.
//!
//! A session's own step (a start's reads and signing, a sign's) holds the
//! Safe, as a send's step does ([`Safes::busy`]): every other step of the
//! Safe is `SAFE_BUSY` meanwhile.

use std::collections::BTreeMap;

use fc_approval::safe::Approved;
use fc_safe::{SafeMessage, Signatures};
use serde_json::value::RawValue;

use super::*;

/// `SAFE_MESSAGE_EXISTS`'s text (`openWatched`).
const EXISTS_TEXT: &str = "Another signature request is already open for this account \u{2014} \
     finish or cancel it first";

/// `requireSession`'s, with none open.
const NO_SESSION_TEXT: &str = "No signature request is open for this account";

/// `requireSession`'s, for another session's ID.
const OTHER_PAGE_TEXT: &str = "This signature request belongs to a different page";

/// `requireSession`'s, for a session that has ended (`SAFE_DISCARDED`).
const ENDED_TEXT: &str = "This signature request has ended";

/// `signEntryOwner`'s, for a session ended or replaced while its owner
/// signed (`SAFE_DISCARDED`).
const DISCARDED_WHILE_TEXT: &str = "The request was discarded while the signature was being made";

/// `signEntryOwner`'s, for an index that isn't one of the Safe's owners.
const NOT_OWNER_TEXT: &str = "That account is not an owner of this Safe";

/// `approvalNeeded()`'s (`SAFE_APPROVAL_NEEDED`): the threshold's last
/// signature ended the session's approval, so no owner signs after it.
const APPROVAL_NEEDED_TEXT: &str =
    "This request needs your confirmation again before its owners can sign";

/// `openWatched`'s, for a record that changed while the session opened.
const CHANGED_TEXT: &str = "This account changed while the signature request was opening";

/// A Ledger owner's (S6) or a phone owner's signature (`unsupported`).
const UNSUPPORTED_OWNER_TEXT: &str = "Only the vault's owners can sign a Safe message here for now";

/// The session ID's length in bytes.
const ID_LEN: usize = 16;

/// One Safe's open session (the reference's `entry`).
pub(super) struct Session {
    /// Its ID: a bearer secret, wiped when dropped.
    id: Zeroizing<[u8; ID_LEN]>,
    /// Which session this is, to tell a step's from a later one's.
    pub(super) serial: u64,
    /// The Safe's address it was opened for.
    pub(super) safe: [u8; 20],
    /// The SafeMessage's hash, which every owner signs.
    pub(super) hash: [u8; 32],
    /// The record's threshold, which the reads verified.
    pub(super) threshold: usize,
    /// The caller's display data, as JS keeps it.
    display: Option<JsValue>,
    pub(super) signatures: Signatures,
    created_at_ms: u64,
    /// Ended for good (a cancel while a step held the Safe): nothing signs
    /// or completes it, and it is kept only until it is dropped.
    pub(super) ended: bool,
}

impl Session {
    /// Whether `presented` is this session's ID, compared in constant time.
    fn is(&self, presented: Option<&[u8; ID_LEN]>) -> bool {
        presented.is_some_and(|presented| {
            let diff = presented
                .iter()
                .zip(self.id.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b));
            std::hint::black_box(diff) == 0
        })
    }

    fn complete(&self) -> bool {
        self.signatures.len() >= self.threshold
    }

    fn signed(&self, owner: &[u8; 20]) -> bool {
        self.signatures
            .kept()
            .iter()
            .any(|kept| kept.owner() == owner)
    }
}

/// The open sessions, one per Safe, by wallet index.
#[derive(Default)]
pub(super) struct Sessions {
    pub(super) open: BTreeMap<u64, Session>,
    serial: u64,
}

impl Sessions {
    /// Keeps only the sessions `keep` takes, by the Safe's wallet index and
    /// address: the records' snapshot drops a removed Safe's.
    pub(super) fn retain(&mut self, mut keep: impl FnMut(u64, &[u8; 20]) -> bool) {
        self.open
            .retain(|index, session| keep(*index, &session.safe));
    }
}

/// A session `safe.message_start` opens once its reads are in.
pub(super) struct Opening {
    hash: [u8; 32],
    display: Option<JsValue>,
}

/// `{ session, state }`, the ID written into a buffer wiped when dropped.
#[derive(Serialize)]
struct Started<'a> {
    session: &'a str,
    state: &'a RawValue,
}

/// A session ID as presented: `Some` only for 32 lowercase hex digits; any
/// other text is an ID no session has. A missing or non-string one is
/// `invalid_argument`.
fn presented(params: &serde_json::Map<String, Value>) -> Result<Option<[u8; ID_LEN]>, ErrorBody> {
    let text = params
        .get("session")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let bytes = text.as_bytes();
    if bytes.len() != 2 * ID_LEN || !bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Ok(None);
    }
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    let mut id = [0u8; ID_LEN];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (byte, [high, low]) in id.iter_mut().zip(pairs) {
        *byte = (digit(*high) << 4) | digit(*low);
    }
    Ok(Some(id))
}

/// The session's state, `sessionState`'s fields but its token.
fn state_of(records: &Records, index: u64, session: &Session) -> Result<JsValue, ErrorBody> {
    let signers: Vec<[u8; 20]> = session
        .signatures
        .kept()
        .iter()
        .map(|kept| *kept.owner())
        .collect();
    let (owners, _) = owner_rows(records, index, &signers)?;
    let mut fields = vec![
        ("safeIndex".into(), JsValue::Number(index as f64)),
        ("kind".into(), JsValue::string("message")),
        ("chainId".into(), JsValue::Number(CHAIN_ID as f64)),
        (
            "hash".into(),
            JsValue::string(to_hex(&session.hash).as_str()),
        ),
        (
            "threshold".into(),
            JsValue::Number(session.threshold as f64),
        ),
        (
            "collected".into(),
            JsValue::Number(session.signatures.len() as f64),
        ),
        ("owners".into(), JsValue::Array(owners)),
    ];
    if let Some(display) = &session.display {
        fields.push(("display".into(), display.clone()));
    }
    fields.push((
        "createdAt".into(),
        JsValue::Number(session.created_at_ms as f64),
    ));
    fields.push(("complete".into(), JsValue::Bool(session.complete())));
    Ok(JsValue::Object(fields))
}

/// The vault owners' signatures over `hash` that `signatures` lacks, as
/// `collectFreeSignatures` makes them: none while the vault is locked;
/// otherwise each vault owner in the record's order that hasn't signed,
/// until the Safe's threshold. One whose signature can't be made is passed
/// over, as the reference passes over it. How many it signed.
fn sweep(
    state: &VaultState,
    records: &Records,
    safe: &Safe,
    hash: &[u8; 32],
    signatures: &mut Signatures,
) -> usize {
    let mut signed = 0;
    if !state.is_unlocked() {
        return signed;
    }
    for (index, address) in &safe.vault_owners {
        if signatures.len() >= safe.setup.threshold() {
            break;
        }
        if signatures.kept().iter().any(|kept| kept.owner() == address) {
            continue;
        }
        match super::super::tx::vault_signature(
            state,
            records,
            *index,
            address,
            safe.setup.owners(),
            hash,
        ) {
            Ok(signature) => {
                if signatures.add(signature) {
                    signed += 1;
                }
            }
            Err(_) => crate::log::warn(
                "a vault owner's Safe message signature was passed over",
                json!({}),
            ),
        }
    }
    signed
}

impl Safes {
    /// `safe.message_start`, from the page `context`: refused before any
    /// read, or the eight reads out. The token the request presents is
    /// burnt by [`Safes::request`] however it ends.
    pub(super) fn message_start(
        &mut self,
        id: u64,
        raw: Option<&str>,
        context: &Context,
        records: &Records,
        ctx: &mut Ctx,
    ) -> Result<Vec<Out>, ErrorBody> {
        if crate::approvals::page_context(context)?.is_none() {
            return Err(ErrorBody::new(
                ErrorCode::Forbidden,
                "a Safe message is a page's",
            ));
        }
        // As `JSON.parse` reads the request, whose typed data is hashed.
        let raw = raw.unwrap_or("{}");
        let params = fc_evm::parse_json(raw).map_err(|_| invalid())?;
        let p = params
            .as_object()
            .filter(|p| {
                p.keys()
                    .all(|k| ["safe", "request", "display", "authorization"].contains(&k.as_str()))
            })
            .ok_or_else(invalid)?;
        let index = index_of(p, "safe")?;
        let request = p
            .get("request")
            .and_then(Value::as_object)
            .filter(|r| r.len() == 2)
            .ok_or_else(invalid)?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        let request_params = request
            .get("params")
            .filter(|params| params.is_array())
            .ok_or_else(invalid)?;
        let authorization = p.get("authorization").ok_or_else(invalid)?;
        // `display` as JS keeps it: opaque, kept as given.
        let display = fc_json::parse(raw)
            .map_err(|_| invalid())?
            .get("display")
            .cloned();
        let safe = resolve(records, index)?;
        // `isValidSignature` lives on the deployed Safe.
        if !safe.marked {
            return Err(not_deployed());
        }
        if !matches!(method, "personal_sign" | "eth_signTypedData_v4") {
            return Err(plain(format!(
                "Unsupported signing method for Safe accounts: {method}"
            )));
        }
        // The token's payload, as `eip1193.request`'s `{ device }` minted
        // it: the Safe's address and chain from its record, and the
        // page's request as sent. Its digest is `requestDigest`'s.
        let payload = json!({
            "safe": checksum_address(&safe.address),
            "chain_id": CHAIN_ID.to_string(),
            "method": method,
            "params": request_params,
        });
        let digest = match Approved::message(&payload) {
            Ok(Approved::Message { digest, .. }) => digest,
            Ok(Approved::Send { .. }) => return Err(crate::vault::internal()),
            Err(error) => return Err(plain(error.to_string())),
        };
        let hash = SafeMessage::new(digest)
            .hash(&safe.address)
            .map_err(|_| crate::vault::internal())?;
        // One session per Safe, main's for one page request.
        if self.sessions.open.get(&index).is_some_and(|s| !s.ended) {
            return Err(refused("SAFE_MESSAGE_EXISTS", EXISTS_TEXT));
        }
        if self.busy(index) {
            return Err(refused("SAFE_BUSY", STEP_BUSY_TEXT));
        }
        ctx.approvals
            .spend_safe_message(context, authorization, index, &payload, ctx.clocks)?;
        // An ended one gives way.
        self.sessions.open.remove(&index);
        let work = Work::MessageStart(Box::new(Opening { hash, display }));
        Ok(self.check(id, Kind::MessageStart, safe, work, ctx.now))
    }

    /// `safe.message_start`'s session, where no vault job is running, with
    /// the vault's `state`: the record still the Safe the reads checked,
    /// the vault owners' signatures, and the session opened.
    pub(super) fn opened(
        &mut self,
        id: u64,
        checked: &Safe,
        opening: Opening,
        state: &VaultState,
        ctx: &mut Ctx,
    ) -> Out {
        match self.open_session(id, checked, opening, state, ctx) {
            Ok(out) => out,
            Err(error) => failed(id, &error),
        }
    }

    fn open_session(
        &mut self,
        id: u64,
        checked: &Safe,
        opening: Opening,
        state: &VaultState,
        ctx: &mut Ctx,
    ) -> Result<Out, ErrorBody> {
        let records = ctx
            .approvals
            .account_records()
            .ok_or_else(not_moved)?
            .clone();
        let safe = resolve(&records, checked.index)?;
        if safe.address != checked.address || safe.setup != checked.setup || !safe.marked {
            return Err(plain(CHANGED_TEXT));
        }
        if self
            .sessions
            .open
            .get(&safe.index)
            .is_some_and(|s| !s.ended)
        {
            return Err(refused("SAFE_MESSAGE_EXISTS", EXISTS_TEXT));
        }
        let mut signatures = Signatures::new();
        let signed = sweep(state, &records, &safe, &opening.hash, &mut signatures);
        let mut session_id = Zeroizing::new([0u8; ID_LEN]);
        {
            use rand_core::TryRng as _;
            crate::rng::OsRng
                .try_fill_bytes(&mut session_id[..])
                .map_err(|_| crate::vault::internal())?;
        }
        self.sessions.serial = self.sessions.serial.wrapping_add(1);
        let session = Session {
            id: session_id,
            serial: self.sessions.serial,
            safe: safe.address,
            hash: opening.hash,
            threshold: safe.setup.threshold(),
            display: opening.display,
            signatures,
            created_at_ms: ctx.clocks.wall_ms,
            ended: false,
        };
        let state = state_of(&records, safe.index, &session)?;
        let state =
            RawValue::from_string(state.stringify()).map_err(|_| crate::vault::internal())?;
        let text = Zeroizing::new(to_hex(&session.id[..]));
        let text = text.trim_start_matches("0x");
        let mut payload = Zeroizing::new(Vec::with_capacity(state.get().len().saturating_add(256)));
        fc_protocol::message::write_result(
            &mut *payload,
            id,
            &Started {
                session: text,
                state: &state,
            },
        )
        .map_err(|_| crate::vault::internal())?;
        // Never a session whose ID can't reach main: one nobody could name
        // would hold the Safe's one session.
        if payload.len() > fc_protocol::frame::MAX_PAYLOAD {
            return Err(crate::vault::internal());
        }
        self.sessions.open.insert(safe.index, session);
        crate::log::info("a Safe message session opened", json!({ "signed": signed }));
        Ok(Out::Send(payload))
    }

    /// `safe.message_sign`: refused or answered at once, or the eight reads
    /// out before its owners sign.
    pub(super) fn message_sign(
        &mut self,
        id: u64,
        raw: Option<&str>,
        records: &Records,
        ctx: &mut Ctx,
    ) -> Result<Vec<Out>, ErrorBody> {
        let mut params = Value::Null;
        let p = members(raw, &["safe", "session", "owner"], &mut params)?;
        let index = index_of(p, "safe")?;
        let presented = presented(p)?;
        let owner = match p.get("owner") {
            None | Some(Value::Null) => None,
            Some(_) => Some(index_of(p, "owner")?),
        };
        let safe = resolve(records, index)?;
        let session = self.session(index, presented.as_ref())?;
        let (serial, complete) = (session.serial, session.complete());
        let named = match owner {
            None => None,
            Some(owner) => {
                let Some((_, address)) = safe.owners.iter().find(|(at, _)| *at == owner as f64)
                else {
                    return Err(plain(NOT_OWNER_TEXT));
                };
                // Signed already: idempotent.
                if session.signed(address) {
                    return Ok(vec![js_reply(id, &state_of(records, index, session)?)]);
                }
                if complete {
                    return Err(refused("SAFE_APPROVAL_NEEDED", APPROVAL_NEEDED_TEXT));
                }
                let Some(vault) = safe.vault_owners.iter().find(|(at, _)| *at == owner) else {
                    return Err(refused("unsupported", UNSUPPORTED_OWNER_TEXT));
                };
                Some(*vault)
            }
        };
        if self.busy(index) {
            return Err(refused("SAFE_BUSY", STEP_BUSY_TEXT));
        }
        let session = self.session(index, presented.as_ref())?;
        match named {
            Some(_) if !ctx.unlocked => return Err(crate::vault::locked()),
            // Nothing the sweep could sign: the state, with no read.
            None if complete
                || !ctx.unlocked
                || safe.vault_owners.iter().all(|(_, a)| session.signed(a)) =>
            {
                return Ok(vec![js_reply(id, &state_of(records, index, session)?)]);
            }
            _ => {}
        }
        let work = Work::MessageSign {
            serial,
            owner: named,
        };
        Ok(self.check(id, Kind::MessageSign, safe, work, ctx.now))
    }

    /// `safe.message_sign`'s signing, where no vault job is running, with
    /// the vault's `state`: the session still the one the step started on,
    /// and the record still the Safe the reads checked.
    pub(super) fn message_signed(
        &mut self,
        id: u64,
        checked: &Safe,
        serial: u64,
        owner: Option<(u64, [u8; 20])>,
        state: &VaultState,
        ctx: &mut Ctx,
    ) -> Out {
        match self.sign_session(checked, serial, owner, state, ctx) {
            Ok(state) => js_reply(id, &state),
            Err(error) => failed(id, &error),
        }
    }

    fn sign_session(
        &mut self,
        checked: &Safe,
        serial: u64,
        owner: Option<(u64, [u8; 20])>,
        state: &VaultState,
        ctx: &mut Ctx,
    ) -> Result<JsValue, ErrorBody> {
        let records = ctx
            .approvals
            .account_records()
            .ok_or_else(not_moved)?
            .clone();
        let session = self
            .sessions
            .open
            .get_mut(&checked.index)
            .filter(|session| session.serial == serial && !session.ended)
            .ok_or_else(|| refused("SAFE_DISCARDED", DISCARDED_WHILE_TEXT))?;
        let safe = resolve(&records, checked.index)?;
        if safe.address != checked.address || safe.setup != checked.setup {
            return Err(plain(format!(
                "Wallet {} is not a Safe account",
                safe.index
            )));
        }
        let hash = session.hash;
        let count = match owner {
            Some((index, address)) if !session.signed(&address) => {
                if session.complete() {
                    return Err(refused("SAFE_APPROVAL_NEEDED", APPROVAL_NEEDED_TEXT));
                }
                let signature = super::super::tx::vault_signature(
                    state,
                    &records,
                    index,
                    &address,
                    safe.setup.owners(),
                    &hash,
                )?;
                usize::from(session.signatures.add(signature))
            }
            Some(_) => 0,
            None => sweep(state, &records, &safe, &hash, &mut session.signatures),
        };
        if count > 0 {
            crate::log::info("a Safe message signed", json!({ "signed": count }));
        }
        state_of(&records, checked.index, session)
    }

    /// `safe.message_state`: the session's state, or `null` for none open,
    /// another's ID, or one that has ended.
    pub(super) fn message_state(
        &self,
        id: u64,
        raw: Option<&str>,
        records: &Records,
    ) -> Result<Vec<Out>, ErrorBody> {
        let mut params = Value::Null;
        let p = members(raw, &["safe", "session"], &mut params)?;
        let index = index_of(p, "safe")?;
        let presented = presented(p)?;
        let state = match self.sessions.open.get(&index) {
            Some(session) if session.is(presented.as_ref()) && !session.ended => {
                state_of(records, index, session)?
            }
            _ => JsValue::Null,
        };
        Ok(vec![js_reply(id, &state)])
    }

    /// `safe.message_cancel`: the session dropped, `{}`; none open is `{}`
    /// too. While a step holds the Safe, it is ended, `SAFE_BUSY`.
    pub(super) fn message_cancel(
        &mut self,
        id: u64,
        raw: Option<&str>,
    ) -> Result<Vec<Out>, ErrorBody> {
        let mut params = Value::Null;
        let p = members(raw, &["safe", "session"], &mut params)?;
        let index = index_of(p, "safe")?;
        let presented = presented(p)?;
        let busy = self.busy(index);
        let Some(session) = self.sessions.open.get_mut(&index) else {
            return Ok(vec![reply(id, &json!({}))]);
        };
        if !session.is(presented.as_ref()) {
            return Err(plain(OTHER_PAGE_TEXT));
        }
        if busy && !session.ended {
            // Nothing signs or completes it from here.
            session.ended = true;
            return Err(refused("SAFE_BUSY", BUSY_TEXT));
        }
        self.sessions.open.remove(&index);
        crate::log::info("a Safe message session cancelled", json!({}));
        Ok(vec![reply(id, &json!({}))])
    }

    /// `safe.message_complete`: `{ signature }` once the threshold is met,
    /// the session dropped.
    pub(super) fn message_complete(
        &mut self,
        id: u64,
        raw: Option<&str>,
    ) -> Result<Vec<Out>, ErrorBody> {
        let mut params = Value::Null;
        let p = members(raw, &["safe", "session"], &mut params)?;
        let index = index_of(p, "safe")?;
        let presented = presented(p)?;
        if self.busy(index) {
            return Err(refused("SAFE_BUSY", BUSY_TEXT));
        }
        let session = self.session(index, presented.as_ref())?;
        // "Not enough signatures yet (1 of 2)".
        let joined = session
            .signatures
            .joined_at(session.threshold)
            .map_err(|error| plain(error.to_string()))?;
        self.sessions.open.remove(&index);
        crate::log::info("a Safe message session completed", json!({}));
        Ok(vec![reply(id, &json!({ "signature": to_hex(&joined) }))])
    }

    /// The Safe's open session for the ID `presented` (`requireSession`):
    /// none open, another's ID, or one that has ended is refused.
    fn session(&self, index: u64, presented: Option<&[u8; ID_LEN]>) -> Result<&Session, ErrorBody> {
        let session = self
            .sessions
            .open
            .get(&index)
            .ok_or_else(|| plain(NO_SESSION_TEXT))?;
        if !session.is(presented) {
            return Err(plain(OTHER_PAGE_TEXT));
        }
        if session.ended {
            return Err(refused("SAFE_DISCARDED", ENDED_TEXT));
        }
        Ok(session)
    }
}
