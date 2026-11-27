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
//!   compared in constant time, wiped when dropped and never logged. A
//!   presented one is decoded from the request's own bytes straight into a
//!   buffer wiped when dropped, never parsed into a value ([`presented`]).
//! - **`safe.message_sign { safe, session, owner? }`** → the state
//!   (`signSafeMessage`): without `owner`, the vault owners that haven't
//!   signed, until the threshold; with one, that owner, once (one that
//!   signed already is answered the state, idempotent). The setup is read
//!   first, as before every owner's signature, each read verified
//!   (`safe_changed`, `safe_unverified`, `not_deployed`, nothing signed),
//!   unless the step can sign nothing: the threshold met, or the sweep with
//!   the vault locked or every vault owner signed, answered at once. A
//!   Ledger owner (S6) signs on the device lane, `sign.typed_data`'s rows
//!   over the session's SafeMessage (the grammar's `safe.message_sign`
//!   row), its operation built before any read; its signature, checked by
//!   fc-ledger, is kept only while the session is still the one the step
//!   began on, not ended, and below its threshold ([`super::owners`]). A
//!   phone owner is `unsupported` (0012's phone jobs).
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

use super::owners::{self, Named};
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

/// `signEntryOwner`'s, for an index that isn't one of the Safe's owners.
pub(super) const NOT_OWNER_TEXT: &str = "That account is not an owner of this Safe";

/// `approvalNeeded()`'s (`SAFE_APPROVAL_NEEDED`): the threshold's last
/// signature ended the session's approval, so no owner signs after it.
const APPROVAL_NEEDED_TEXT: &str =
    "This request needs your confirmation again before its owners can sign";

/// `openWatched`'s, for a record that changed while the session opened.
const CHANGED_TEXT: &str = "This account changed while the signature request was opening";

/// The session ID's length in bytes.
const ID_LEN: usize = 16;

/// One Safe's open session (the reference's `entry`).
pub(super) struct Session {
    /// Its ID: a bearer secret, in a buffer of its own, wiped when dropped.
    /// Boxed, so the sessions' map moves only the pointer: one of its slots
    /// would keep the bytes of a session it dropped.
    id: Box<Zeroizing<[u8; ID_LEN]>>,
    /// Which session this is, to tell a step's from a later one's.
    pub(super) serial: u64,
    /// The Safe's address it was opened for.
    pub(super) safe: [u8; 20],
    /// The SafeMessage's hash, which every owner signs.
    pub(super) hash: [u8; 32],
    /// The digest the SafeMessage carries, for a Ledger owner's typed data.
    pub(super) digest: [u8; 32],
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
    digest: [u8; 32],
    display: Option<JsValue>,
}

/// `{ session, state }`, the ID written into a buffer wiped when dropped.
#[derive(Serialize)]
struct Started<'a> {
    session: &'a str,
    state: &'a RawValue,
}

/// A board call's members (`safe.message_sign`, `_state`, `_cancel`,
/// `_complete`), read in the request's own bytes: its `session` as its raw
/// text there, the others parsed into values.
struct Board<'a> {
    params: serde_json::Map<String, Value>,
    session: Option<&'a RawValue>,
}

/// Every member of a JSON object, in the text's order, a repeated name's
/// each time, each value as its raw JSON in the request's bytes.
struct Members<'a>(Vec<(String, &'a RawValue)>);

impl<'de> serde::Deserialize<'de> for Members<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Each;
        impl<'de> serde::de::Visitor<'de> for Each {
            type Value = Members<'de>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Members<'de>, A::Error> {
                let mut members = Vec::new();
                while let Some(member) = map.next_entry()? {
                    members.push(member);
                }
                Ok(Members(members))
            }
        }
        deserializer.deserialize_map(Each)
    }
}

/// The containers a member's value may nest: serde_json reads at most 127
/// nested (its limit, 128, is refused when reached), one of them the
/// request's object.
const NESTING: usize = 126;

/// The request's members, an object holding only `allowed`, as
/// [`super::members`] reads them into a value: every occurrence of each
/// one read as that parse reads it, the last of a repeated name kept. But
/// the `session` member is never parsed into a value: its text would be
/// copied into a string freed unwiped (and an escaped one into
/// serde_json's scratch as well). Skipped as raw JSON, each occurrence is
/// checked in place ([`readable`]), and only the last one decoded.
fn board_members<'a>(raw: Option<&'a str>, allowed: &[&str]) -> Result<Board<'a>, ErrorBody> {
    let members: Members<'a> = serde_json::from_str(raw.unwrap_or("{}")).map_err(|_| invalid())?;
    let mut board = Board {
        params: serde_json::Map::new(),
        session: None,
    };
    for (name, value) in members.0 {
        if !allowed.contains(&name.as_str()) {
            return Err(invalid());
        }
        readable(value)?;
        if name == "session" {
            board.session = Some(value);
        } else {
            let value = serde_json::from_str(value.get()).map_err(|_| invalid())?;
            board.params.insert(name, value);
        }
    }
    Ok(board)
}

/// Whether a member's raw JSON (valid syntax: serde_json skipped it) is
/// one its parse into a value reads in the request's object, which the skip
/// doesn't check: no lone surrogate in a string or a key, no number out of
/// range, and no more than [`NESTING`] containers deep. Copies no string.
fn readable(raw: &RawValue) -> Result<(), ErrorBody> {
    let text = raw.get();
    let bytes = text.as_bytes();
    let (mut at, mut depth) = (0usize, 0usize);
    while let Some(&byte) = bytes.get(at) {
        at += 1;
        match byte {
            b'[' | b'{' => {
                depth += 1;
                if depth > NESTING {
                    return Err(invalid());
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            b'"' => {
                let start = at;
                // To the closing quote, the first not escaped.
                while let Some(&byte) = bytes.get(at) {
                    match byte {
                        b'"' => break,
                        b'\\' => at += 2,
                        _ => at += 1,
                    }
                }
                chars(bytes.get(start..at).ok_or_else(invalid)?, |_| {})?;
                at += 1;
            }
            // A number: serde_json's own reading of it, which holds nothing
            // secret.
            b'-' | b'0'..=b'9' => {
                let start = at - 1;
                while bytes
                    .get(at)
                    .is_some_and(|b| matches!(b, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'))
                {
                    at += 1;
                }
                let number = text.get(start..at).ok_or_else(invalid)?;
                serde_json::from_str::<Value>(number).map_err(|_| invalid())?;
            }
            // Whitespace, `,`, `:` and the literals.
            _ => {}
        }
    }
    Ok(())
}

/// The characters of a JSON string, from its raw text between the quotes
/// (valid escapes: serde_json skipped it), as serde_json reads them, each
/// to `each`: an ASCII one as its byte, any other `None` (each byte of a
/// multi-byte one, too). A lone surrogate, which serde_json refuses in a
/// string, is `invalid_argument`.
fn chars(mut rest: &[u8], mut each: impl FnMut(Option<u8>)) -> Result<(), ErrorBody> {
    while let Some((&first, tail)) = rest.split_first() {
        rest = tail;
        let ascii = if first != b'\\' {
            Some(first)
        } else if let Some(tail) = rest.strip_prefix(b"u") {
            rest = tail;
            match hex_escape(&mut rest)? {
                0xDC00..=0xDFFF => return Err(invalid()),
                // A leading surrogate: its trailing one next, or refused.
                0xD800..=0xDBFF => {
                    rest = rest.strip_prefix(b"\\u").ok_or_else(invalid)?;
                    if !(0xDC00..=0xDFFF).contains(&hex_escape(&mut rest)?) {
                        return Err(invalid());
                    }
                    None
                }
                unit => u8::try_from(unit).ok(),
            }
        } else {
            // `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`.
            rest = rest.get(1..).ok_or_else(invalid)?;
            None
        };
        each(ascii);
    }
    Ok(())
}

/// A session ID as presented: the `session` member's raw text, in the
/// request's own bytes (a frame's, wiped when it drops), decoded straight
/// into a buffer wiped when dropped, with no other copy. `Some` only for a
/// string of 32 lowercase hex digits, escaped or not; any other string is
/// an ID no session has. A missing or non-string one is `invalid_argument`,
/// and so is a lone surrogate, as serde_json refuses one in a string value.
fn presented(token: Option<&RawValue>) -> Result<Option<Zeroizing<[u8; ID_LEN]>>, ErrorBody> {
    // A JSON string, as serde_json skipped it: quoted, valid escapes.
    let text = token
        .map(RawValue::get)
        .and_then(|token| token.strip_prefix('"'))
        .and_then(|token| token.strip_suffix('"'))
        .ok_or_else(invalid)?;
    let mut id = Zeroizing::new([0u8; ID_LEN]);
    // The digits so far, while every character has been one.
    let mut digits = Some(0usize);
    chars(text.as_bytes(), |ascii| {
        let digit = ascii.and_then(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        });
        digits = match (digits, digit) {
            (Some(n), Some(digit)) if n < 2 * ID_LEN => {
                if let Some(byte) = id.get_mut(n / 2) {
                    *byte |= if n % 2 == 0 { digit << 4 } else { digit };
                }
                Some(n + 1)
            }
            _ => None,
        };
    })?;
    Ok((digits == Some(2 * ID_LEN)).then_some(id))
}

/// A `\u` escape's four hex digits, either case.
fn hex_escape(rest: &mut &[u8]) -> Result<u16, ErrorBody> {
    let (digits, tail) = rest.split_at_checked(4).ok_or_else(invalid)?;
    *rest = tail;
    digits.iter().try_fold(0u16, |unit, b| {
        let digit = char::from(*b).to_digit(16).ok_or_else(invalid)?;
        Ok((unit << 4) | digit as u16)
    })
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

/// The vault owners' signatures over `hash` (a SafeMessage's, or a
/// SafeTx's for `safe.sign_owner`'s sweep) that `signatures` lacks, as
/// `collectFreeSignatures` makes them: none while the vault is locked;
/// otherwise each vault owner in the record's order that hasn't signed,
/// until the record's threshold. One whose signature can't be made is
/// passed over, as the reference passes over it. The signatures it added,
/// in order.
pub(super) fn sweep(
    state: &VaultState,
    records: &Records,
    safe: &Safe,
    hash: &[u8; 32],
    signatures: &mut Signatures,
) -> Vec<fc_safe::OwnerSignature> {
    let mut signed = Vec::new();
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
                    signed.push(signature);
                }
            }
            Err(_) => crate::log::warn("a vault owner's Safe signature was passed over", json!({})),
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
        let work = Work::MessageStart(Box::new(Opening {
            hash,
            digest,
            display,
        }));
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
        let signed = sweep(state, &records, &safe, &opening.hash, &mut signatures).len();
        // Filled in place, on the heap.
        let mut session_id = Box::new(Zeroizing::new([0u8; ID_LEN]));
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
            digest: opening.digest,
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
        let board = board_members(raw, &["safe", "session", "owner"])?;
        let p = &board.params;
        let index = index_of(p, "safe")?;
        let presented = presented(board.session)?;
        let owner = match p.get("owner") {
            None | Some(Value::Null) => None,
            Some(_) => Some(index_of(p, "owner")?),
        };
        let safe = resolve(records, index)?;
        let session = self.session(index, presented.as_deref())?;
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
                let (digest, hash) = (session.digest, session.hash);
                // A vault owner, a Ledger owner (S6), or `unsupported`.
                Some(owners::named(ctx, &safe, owner, address, |account| {
                    owners::message_operation(account, &safe.address, &digest, &hash)
                })?)
            }
        };
        if self.busy(index) {
            return Err(refused("SAFE_BUSY", STEP_BUSY_TEXT));
        }
        let session = self.session(index, presented.as_deref())?;
        match named {
            Some(Named::Vault { .. }) if !ctx.unlocked => return Err(crate::vault::locked()),
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

    /// `safe.message_sign`'s reads are in, the setup the record's: a vault
    /// owner's signing, or the sweep's, is due; a Ledger owner's operation
    /// goes to the lane while the record is still the Safe the reads
    /// checked and the session the one the step began on, not ended and
    /// below its threshold.
    pub(super) fn message_checked(
        &mut self,
        id: u64,
        mut op: Op,
        serial: u64,
        owner: Option<Named>,
        ctx: &Ctx,
    ) -> Vec<Out> {
        let Some(Named::Ledger(mut device)) = owner else {
            op.work = Work::MessageSign { serial, owner };
            op.step = Step::Write;
            self.ops.insert(id, op);
            self.writes.push(id);
            return Vec::new();
        };
        let still = ctx
            .approvals
            .account_records()
            .ok_or_else(not_moved)
            .and_then(|records| resolve(records, op.safe.index))
            .and_then(|safe| {
                if safe.address == op.safe.address && safe.setup == op.safe.setup {
                    Ok(())
                } else {
                    Err(plain(format!(
                        "Wallet {} is not a Safe account",
                        safe.index
                    )))
                }
            });
        if let Err(error) = still {
            return vec![failed(id, &error)];
        }
        let Some(session) = self
            .sessions
            .open
            .get(&op.safe.index)
            .filter(|session| session.serial == serial && !session.ended)
        else {
            return vec![failed(
                id,
                &refused("SAFE_DISCARDED", owners::DISCARDED_WHILE_TEXT),
            )];
        };
        if session.complete() {
            return vec![failed(
                id,
                &refused("SAFE_APPROVAL_NEEDED", APPROVAL_NEEDED_TEXT),
            )];
        }
        let Some(operation) = device.take_operation() else {
            return vec![failed(id, &crate::vault::internal())];
        };
        op.work = Work::MessageSign {
            serial,
            owner: Some(Named::Ledger(device)),
        };
        self.onto_lane(id, op, operation)
    }

    /// `safe.message_sign`'s signing, where no vault job is running, with
    /// the vault's `state`: the session still the one the step started on,
    /// and the record still the Safe the reads checked.
    pub(super) fn message_signed(
        &mut self,
        id: u64,
        checked: &Safe,
        serial: u64,
        owner: Option<Named>,
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
        owner: Option<Named>,
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
            .ok_or_else(|| refused("SAFE_DISCARDED", owners::DISCARDED_WHILE_TEXT))?;
        let safe = resolve(&records, checked.index)?;
        if safe.address != checked.address || safe.setup != checked.setup {
            return Err(plain(format!(
                "Wallet {} is not a Safe account",
                safe.index
            )));
        }
        let hash = session.hash;
        let count = match owner {
            Some(Named::Vault { index, address }) if !session.signed(&address) => {
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
            // The device's signature, checked by fc-ledger over the
            // SafeMessage's hash; kept only below the threshold, whose last
            // signature ended the session's approval.
            Some(Named::Ledger(device)) if !session.signed(&device.address) => {
                if session.complete() {
                    return Err(refused("SAFE_APPROVAL_NEEDED", APPROVAL_NEEDED_TEXT));
                }
                let signature = fc_safe::OwnerSignature::check(
                    &hash,
                    &device.signature()?,
                    &device.address,
                    safe.setup.owners(),
                )
                .map_err(|_| crate::vault::internal())?;
                usize::from(session.signatures.add(signature))
            }
            Some(_) => 0,
            None => sweep(state, &records, &safe, &hash, &mut session.signatures).len(),
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
        let board = board_members(raw, &["safe", "session"])?;
        let index = index_of(&board.params, "safe")?;
        let presented = presented(board.session)?;
        let state = match self.sessions.open.get(&index) {
            Some(session) if session.is(presented.as_deref()) && !session.ended => {
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
        let board = board_members(raw, &["safe", "session"])?;
        let index = index_of(&board.params, "safe")?;
        let presented = presented(board.session)?;
        let busy = self.busy(index);
        let Some(session) = self.sessions.open.get_mut(&index) else {
            return Ok(vec![reply(id, &json!({}))]);
        };
        if !session.is(presented.as_deref()) {
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
        let board = board_members(raw, &["safe", "session"])?;
        let index = index_of(&board.params, "safe")?;
        let presented = presented(board.session)?;
        if self.busy(index) {
            return Err(refused("SAFE_BUSY", BUSY_TEXT));
        }
        let session = self.session(index, presented.as_deref())?;
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
