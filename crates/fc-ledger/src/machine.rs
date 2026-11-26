//! The per-operation machines, sans-I/O (design 0016, "The device lane",
//! "The APDU grammar", "Answers the core checks"). An [`Operation`] is
//! built from the approved request and the account's record, and refuses
//! what a Ledger can't carry before its first APDU ([`Refusal`]). Then it
//! yields one APDU at a time ([`Step::Send`]) and is handed main's reply to
//! each ([`Reply`]), until it ends ([`Step::Done`]): with the accounts, the
//! address, or a signature that was recovered against the account and the
//! digest the user confirmed, `s` low; or with a [`Failure`] and its
//! `LEDGER_*` code. Nothing a device sends leaves before those checks. The
//! caller (LDG-2's lane) carries the APDUs, the deadlines and the cancel.

use fc_evm::{
    PreparedTransaction, SignedTransaction, Transaction, U256, decode_signed, eip191_digest,
    recover_address, rlp, typed_data_parse,
};
use serde_json::Value;

use crate::apdu::{self, AnswerFault, Apdu, MAX_DATA, STATUS_INS_NOT_SUPPORTED, STATUS_OK, header};
use crate::bounds::{Bound, MAX_APDUS};
use crate::code::{Failed, LedgerCode};
use crate::path::{LedgerPath, PathError, Scheme};
use crate::typed::TypedStream;

/// `ledger.accounts` reads 1 to 20 paths.
pub const MAX_ACCOUNTS: u64 = 20;
/// Then it reads the paths of at most 20 Ledger records no device has
/// matched (design 0016, *Accounts*, D1; deviation `check-bound`).
pub const MAX_CHECKS: usize = 20;
/// The Ethereum app's name in `B0 01`'s answer (deviation `app-check`).
pub const ETHEREUM_APP: &[u8] = b"Ethereum";
/// A message's next pieces: 150 bytes each, and the first `150 − 5 − 4n`
/// after the path and the length.
const MESSAGE_PIECE: usize = 150;

/// A Ledger account's record: its path and the address it was added with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub path: LedgerPath,
    pub address: [u8; 20],
}

/// Main's reply to one `shell.ledger_apdu`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply<'a> {
    /// `{ answer }`, 2 to 260 bytes ending in the status word;
    /// `hash_only_shown` when main added `hash_only: "shown"`.
    Answer {
        answer: &'a [u8],
        hash_only_shown: bool,
    },
    /// `{ failed }`.
    Failed(Failed),
    /// Main refused the APDU before the device (`invalid_argument` with a
    /// `rule`): the operation ends `LEDGER_UNKNOWN`.
    Refused,
}

impl<'a> Reply<'a> {
    /// `{ answer }` without `hash_only`.
    pub fn answer(answer: &'a [u8]) -> Self {
        Reply::Answer {
            answer,
            hash_only_shown: false,
        }
    }
}

/// One APDU for main to exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchange {
    pub apdu: Apdu,
    /// The device waits for the user on this one (5 minutes, not 15 s).
    pub confirm: bool,
}

/// What an operation needs next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Send(Exchange),
    Done(Result<Signed, Failure>),
}

/// An operation's result, every check passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signed {
    /// `ledger.accounts`: each path's address, in order, and what the
    /// records' check read.
    Accounts(Discovered),
    /// `ledger.add`: the address the device showed at the path.
    Added(Account),
    /// `sign.transaction`: the signed serialization, whose sender is the
    /// account.
    Transaction(SignedTransaction),
    /// `sign.message` and `sign.typed_data`: `r ‖ s ‖ v`, `v` 27 or 28.
    Signature([u8; 65]),
}

/// `ledger.accounts`' result (design 0016, *Accounts*, D1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// Each discovery path's address, in order.
    pub accounts: Vec<Account>,
    /// The address the device holds at each record's path, in the order
    /// the paths were given ([`Operation::checking`]); or how the check
    /// failed, which doesn't fail discovery (`ipc.js:24–33`): a status, main's
    /// `{ failed }` or refusal, or an answer the core can't read, at any of
    /// its APDUs.
    pub checks: Result<Vec<[u8; 20]>, Failure>,
}

/// How an operation ended without a result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{} ({cause})", code.as_str())]
pub struct Failure {
    pub code: LedgerCode,
    pub cause: Cause,
    /// The app's version, once `B0 01` answered: for the error report only.
    pub app_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Cause {
    /// A status word other than `9000`, as `errors.js` maps it.
    #[error("status {0:04x}")]
    Status(u16),
    #[error("main: {}", .0.as_str())]
    Failed(Failed),
    #[error("main refused the APDU")]
    Refused,
    /// An answer to an APDU that doesn't sign that the core can't read.
    #[error("{0}")]
    Answer(AnswerFault),
    /// `B0 01`'s format isn't 1, or its name isn't `Ethereum`.
    #[error("another app is open")]
    App,
    /// The device holds another address at the record's path.
    #[error("another address at the path")]
    WrongDevice,
    #[error("{0}")]
    Signature(SignatureFault),
    /// `6D00` to the first `E0 1A`, and main didn't say the hash-only
    /// warning was shown (Q23).
    #[error("the hash-only warning wasn't shown")]
    HashOnlyNotShown,
    #[error("{0}")]
    Protocol(ProtocolFault),
    /// The core couldn't build its next APDU: never, every bound is checked
    /// before the first.
    #[error("no next APDU")]
    Internal,
}

/// Why a signature is `LEDGER_BAD_SIGNATURE` (deviation `signature-check`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignatureFault {
    #[error("a signature answer of another length")]
    Length,
    #[error("a v the operation can't have")]
    V,
    /// No key recovers it, or its `s` is in the high half.
    #[error("no signer recovers")]
    Recovery,
    #[error("another signer")]
    Signer,
    /// The assembled transaction doesn't read back as signed.
    #[error("the signed transaction doesn't read back")]
    Assembly,
}

/// A reply that breaks `shell.ledger_apdu`'s rules: a protocol error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolFault {
    #[error("an answer outside 2 to 260 bytes")]
    AnswerBounds,
    /// `hash_only` on any answer but a `6D00` to the first `E0 1A`.
    #[error("hash_only on another answer")]
    HashOnly,
    /// `start` twice, or a reply with no APDU pending.
    #[error("a reply with no APDU pending")]
    Order,
}

/// Why an operation is refused before its first APDU.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// Not a scheme's path (deviation `path-strict`).
    #[error("{0}")]
    Path(PathError),
    #[error("ledger.accounts reads 1 to 20 paths")]
    Count,
    /// More records to check than [`MAX_CHECKS`], or a check for an
    /// operation other than `ledger.accounts`.
    #[error("ledger.accounts checks at most 20 records")]
    Checks,
    /// What a Ledger can't carry (deviation `device-bounds`).
    #[error("too large for a Ledger: {0}")]
    TooLarge(Bound),
    /// Deviation `empty-message`.
    #[error("an empty message")]
    EmptyMessage,
    /// A type written in a form the device wouldn't rebuild from its
    /// descriptors (`array-suffix-written-form`): its encodeType, and so the
    /// digest it signs, would differ from the confirmed hash.
    #[error("a type written in a form a Ledger can't sign")]
    NotCanonical,
    #[error("{0}")]
    Transaction(fc_evm::Error),
    /// 0002's refusal of the typed data, a name outside its identifiers
    /// among them (deviation `name-ascii`).
    #[error("{0}")]
    TypedData(fc_evm::Error),
    /// The typed data doesn't hash to the hash the user confirmed.
    #[error("the typed data doesn't hash to the confirmed hash")]
    HashMismatch,
    /// A name that isn't ASCII: fc-evm refuses one first.
    #[error("a name that isn't ASCII")]
    Name,
    /// fc-evm's parse doesn't match its own types: never.
    #[error("an inconsistent parse")]
    Inconsistent,
}

impl Refusal {
    /// The `LEDGER_*` code of a device-specific refusal; `None` for an
    /// invalid request (`invalid_argument`).
    pub fn code(&self) -> Option<LedgerCode> {
        match self {
            Refusal::TooLarge(_) => Some(LedgerCode::TooLarge),
            Refusal::EmptyMessage => Some(LedgerCode::EmptyMessage),
            Refusal::NotCanonical => Some(LedgerCode::TypeNotCanonical),
            _ => None,
        }
    }
}

/// The heap an operation holds, as 0016's *Bounds* splits it: the
/// request's own representation (the transaction's unsigned serialization,
/// the message, typed data's parse), and everything beyond it, which is at
/// most 64 KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retained {
    pub request: usize,
    pub beyond: usize,
}

/// One device operation.
#[derive(Debug)]
pub struct Operation {
    kind: Kind,
    pending: Option<Pending>,
    started: bool,
    ended: bool,
    app_version: Option<String>,
}

#[derive(Debug)]
enum Kind {
    Accounts {
        scheme: Scheme,
        start: u32,
        count: usize,
        found: Vec<Account>,
        /// The records' paths to read after discovery.
        checks: Vec<LedgerPath>,
        checked: Vec<[u8; 20]>,
    },
    Add {
        path: LedgerPath,
    },
    Sign(Box<Sign>),
}

#[derive(Debug)]
struct Sign {
    account: Account,
    path: Vec<u8>,
    head: Head,
    body: Body,
}

/// A signature's first two APDUs, then its body.
#[derive(Debug, Clone, Copy)]
enum Head {
    Address,
    App,
    Body,
}

#[derive(Debug)]
enum Body {
    Transaction {
        /// The one copy of `T`, the unsigned serialization; the pieces of
        /// `P ‖ T` are cut from it and the path as they are sent, and the
        /// signed transaction reuses it. `None` once it is assembled.
        prepared: Option<PreparedTransaction>,
        digest: [u8; 32],
        /// A legacy transaction's chain ID's first four bytes, which the
        /// app keeps for its `v`; `None` for EIP-1559.
        legacy: Option<u64>,
        size: usize,
        next: usize,
    },
    Message {
        head: Vec<u8>,
        message: Vec<u8>,
        first: usize,
        next: usize,
    },
    TypedData {
        stream: TypedStream,
        hash: [u8; 32],
        hashes: [u8; 64],
        phase: Typed,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Typed {
    /// The operation's first `E0 1A` is next.
    First,
    Stream,
    HashOnly,
    End,
}

/// What the APDU awaiting its answer was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    Address,
    /// A record's path, read after discovery.
    Check,
    App,
    /// A piece of a transaction or a message, its last signed.
    Piece {
        last: bool,
    },
    FirstDefinition,
    Definition,
    Sign,
}

impl Operation {
    /// `ledger.accounts { scheme, start, count }`: `count` addresses, the
    /// display off.
    pub fn accounts(scheme: Scheme, start: u64, count: u64) -> Result<Self, Refusal> {
        if !(1..=MAX_ACCOUNTS).contains(&count) {
            return Err(Refusal::Count);
        }
        let last = start
            .checked_add(count - 1)
            .ok_or(Refusal::Path(PathError::Index))?;
        LedgerPath::new(scheme, last).map_err(Refusal::Path)?;
        let start = u32::try_from(start).map_err(|_| Refusal::Path(PathError::Index))?;
        Ok(Self::new(Kind::Accounts {
            scheme,
            start,
            count: count as usize,
            found: Vec::new(),
            checks: Vec::new(),
            checked: Vec::new(),
        }))
    }

    /// `ledger.accounts`' check of the Ledger records no device has matched
    /// (design 0016, *Accounts*, D1): after its discovery APDUs, in the same
    /// operation, `E0 02 00 00` at each of `paths`, in order, display off.
    /// At most [`MAX_CHECKS`]; the caller picks them (the wallet list's
    /// order, deviation `check-bound`). A failed check doesn't fail
    /// discovery ([`Discovered::checks`]).
    pub fn checking(mut self, paths: Vec<LedgerPath>) -> Result<Self, Refusal> {
        if paths.len() > MAX_CHECKS {
            return Err(Refusal::Checks);
        }
        match &mut self.kind {
            Kind::Accounts { checks, .. } if !self.started => {
                *checks = paths;
                Ok(self)
            }
            _ => Err(Refusal::Checks),
        }
    }

    /// `ledger.add`: the address at `path`, shown on the device for the user
    /// to confirm (question 3, deviation `address-from-device`).
    pub fn add(path: LedgerPath) -> Self {
        Self::new(Kind::Add { path })
    }

    /// `sign.transaction`: `P ‖ T` in pieces, `T` the unsigned
    /// serialization; the signed transaction's sender must be the account.
    pub fn sign_transaction(account: Account, tx: &Transaction) -> Result<Self, Refusal> {
        let prepared = tx.prepare().map_err(Refusal::Transaction)?;
        let path = account.path.encode();
        let length = path.len() + prepared.unsigned().len();
        let legacy = (tx.tx_type() == 0).then(|| chain_prime(tx.chain_id()));
        let size = piece_size(length, tx)?;
        if length.div_ceil(size) > MAX_APDUS - 2 {
            return Err(Refusal::TooLarge(Bound::Apdus));
        }
        Ok(Self::sign(
            account,
            path,
            Body::Transaction {
                digest: prepared.digest(),
                prepared: Some(prepared),
                legacy,
                size,
                next: 0,
            },
        ))
    }

    /// `sign.message`: `P ‖ len(m) ‖` the first bytes, then 150 at a time;
    /// recovered over the EIP-191 hash.
    pub fn sign_message(account: Account, message: Vec<u8>) -> Result<Self, Refusal> {
        if message.is_empty() {
            return Err(Refusal::EmptyMessage);
        }
        let path = account.path.encode();
        let length = u32::try_from(message.len()).map_err(|_| Refusal::TooLarge(Bound::Apdus))?;
        let first = MESSAGE_PIECE - path.len() - 4;
        let pieces = 1 + message.len().saturating_sub(first).div_ceil(MESSAGE_PIECE);
        if pieces > MAX_APDUS - 2 {
            return Err(Refusal::TooLarge(Bound::Apdus));
        }
        let mut head = path.clone();
        head.extend_from_slice(&length.to_be_bytes());
        Ok(Self::sign(
            account,
            path,
            Body::Message {
                head,
                message,
                first,
                next: 0,
            },
        ))
    }

    /// `sign.typed_data`: the definitions and values of fc-evm's parse,
    /// then `E0 0C 00 01`; or, after a `6D00` to the first `E0 1A` and
    /// main's `hash_only: "shown"`, the hash-only form (Q23). Either is
    /// recovered over `confirmed`, the hash the user confirmed, which must
    /// be the typed data's.
    pub fn sign_typed_data(
        account: Account,
        domain: &Value,
        types: &Value,
        message: &Value,
        confirmed: &[u8; 32],
    ) -> Result<Self, Refusal> {
        let parsed = typed_data_parse(domain, types, message).map_err(Refusal::TypedData)?;
        if parsed.hash != *confirmed {
            return Err(Refusal::HashMismatch);
        }
        crate::typed::check_written_forms(types, &parsed)?;
        let hash = parsed.hash;
        let mut hashes = [0u8; 64];
        hashes[..32].copy_from_slice(&parsed.domain_separator);
        hashes[32..].copy_from_slice(&parsed.struct_hash);
        // The address check, B0 01 and the signing APDU around the stream.
        let stream = TypedStream::new(parsed, MAX_APDUS - 3)?;
        let path = account.path.encode();
        Ok(Self::sign(
            account,
            path,
            Body::TypedData {
                stream,
                hash,
                hashes,
                phase: Typed::First,
            },
        ))
    }

    fn sign(account: Account, path: Vec<u8>, body: Body) -> Self {
        Self::new(Kind::Sign(Box::new(Sign {
            account,
            path,
            head: Head::Address,
            body,
        })))
    }

    fn new(kind: Kind) -> Self {
        Operation {
            kind,
            pending: None,
            started: false,
            ended: false,
            app_version: None,
        }
    }

    /// What the operation holds now ([`Retained`]): every field counted,
    /// buffers by their capacity, the transaction's serialization by its
    /// length (fc-evm allocates it to fit).
    pub fn retained(&self) -> Retained {
        use std::mem::size_of;
        let Operation {
            kind,
            pending: _,
            started: _,
            ended: _,
            app_version,
        } = self;
        let mut request = 0;
        let mut beyond = size_of::<Operation>() + app_version.as_ref().map_or(0, String::capacity);
        match kind {
            Kind::Accounts {
                scheme: _,
                start: _,
                count: _,
                found,
                checks,
                checked,
            } => {
                beyond += found.capacity() * size_of::<Account>();
                beyond += found.iter().map(|a| path_heap(&a.path)).sum::<usize>();
                beyond += checks.capacity() * size_of::<LedgerPath>();
                beyond += checks.iter().map(path_heap).sum::<usize>();
                beyond += checked.capacity() * size_of::<[u8; 20]>();
            }
            Kind::Add { path } => beyond += path_heap(path),
            Kind::Sign(sign) => {
                let Sign {
                    account,
                    path,
                    head: _,
                    body,
                } = &**sign;
                beyond += size_of::<Sign>() + path_heap(&account.path) + path.capacity();
                match body {
                    Body::Transaction {
                        prepared,
                        digest: _,
                        legacy: _,
                        size: _,
                        next: _,
                    } => {
                        request += prepared.as_ref().map_or(0, |p| p.unsigned().len());
                    }
                    Body::Message {
                        head,
                        message,
                        first: _,
                        next: _,
                    } => {
                        beyond += head.capacity();
                        request += message.capacity();
                    }
                    Body::TypedData {
                        stream,
                        hash: _,
                        hashes: _,
                        phase: _,
                    } => request += stream.retained(),
                }
            }
        }
        Retained { request, beyond }
    }

    /// The first APDU.
    pub fn start(&mut self) -> Step {
        if self.started || self.ended {
            return self.fail(LedgerCode::Unknown, Cause::Protocol(ProtocolFault::Order));
        }
        self.started = true;
        self.advance()
    }

    /// Main's reply to the APDU last sent: the next APDU, or the end.
    pub fn answer(&mut self, reply: Reply<'_>) -> Step {
        let checking = self.pending == Some(Pending::Check) && !self.ended;
        match self.answered(reply) {
            // A failed check ends the operation with discovery's accounts.
            Step::Done(Err(failure)) if checking => self.discovered(Err(failure)),
            step => step,
        }
    }

    /// `ledger.accounts`' end: its accounts, and what the check read.
    fn discovered(&mut self, checks: Result<Vec<[u8; 20]>, Failure>) -> Step {
        self.ended = true;
        self.pending = None;
        let Kind::Accounts { found, .. } = &mut self.kind else {
            return self.fail(LedgerCode::Unknown, Cause::Internal);
        };
        Step::Done(Ok(Signed::Accounts(Discovered {
            accounts: std::mem::take(found),
            checks,
        })))
    }

    fn answered(&mut self, reply: Reply<'_>) -> Step {
        let Some(pending) = self.pending.take().filter(|_| !self.ended) else {
            return self.fail(LedgerCode::Unknown, Cause::Protocol(ProtocolFault::Order));
        };
        let (answer, shown) = match reply {
            Reply::Failed(failed) => return self.fail(failed.code(), Cause::Failed(failed)),
            Reply::Refused => return self.fail(LedgerCode::Unknown, Cause::Refused),
            Reply::Answer {
                answer,
                hash_only_shown,
            } => (answer, hash_only_shown),
        };
        let Some(answer) = apdu::split(answer) else {
            return self.fail(
                LedgerCode::Unknown,
                Cause::Protocol(ProtocolFault::AnswerBounds),
            );
        };
        if pending == Pending::FirstDefinition && answer.status == STATUS_INS_NOT_SUPPORTED {
            // Q23: the device can't show the fields.
            if !shown || !answer.body.is_empty() {
                return self.fail(LedgerCode::Unknown, Cause::HashOnlyNotShown);
            }
            if let Kind::Sign(sign) = &mut self.kind
                && let Body::TypedData { phase, .. } = &mut sign.body
            {
                *phase = Typed::HashOnly;
            }
            return self.advance();
        }
        if shown {
            return self.fail(
                LedgerCode::Unknown,
                Cause::Protocol(ProtocolFault::HashOnly),
            );
        }
        if answer.status != STATUS_OK {
            return self.fail(
                LedgerCode::for_status(answer.status),
                Cause::Status(answer.status),
            );
        }
        match self.read(pending, answer.body) {
            Ok(Some(signed)) => {
                self.ended = true;
                Step::Done(Ok(signed))
            }
            Ok(None) => self.advance(),
            Err((code, cause)) => self.fail(code, cause),
        }
    }

    fn fail(&mut self, code: LedgerCode, cause: Cause) -> Step {
        self.ended = true;
        self.pending = None;
        Step::Done(Err(Failure {
            code,
            cause,
            app_version: self.app_version.clone(),
        }))
    }

    fn send(&mut self, apdu: Option<Apdu>, pending: Pending, confirm: bool) -> Step {
        let Some(apdu) = apdu else {
            // Every APDU's data was bounded before the first.
            return self.fail(LedgerCode::Unknown, Cause::Internal);
        };
        self.pending = Some(pending);
        Step::Send(Exchange { apdu, confirm })
    }

    /// The next APDU of the operation's row.
    fn advance(&mut self) -> Step {
        match &mut self.kind {
            Kind::Accounts {
                scheme,
                start,
                count,
                found,
                checks,
                checked,
            } => {
                if found.len() < *count {
                    let index = u64::from(*start) + found.len() as u64;
                    let apdu = LedgerPath::new(*scheme, index)
                        .ok()
                        .and_then(|path| Apdu::new(header::ADDRESS, &path.encode()));
                    return self.send(apdu, Pending::Address, false);
                }
                match checks.get(checked.len()) {
                    Some(path) => {
                        let apdu = Apdu::new(header::ADDRESS, &path.encode());
                        self.send(apdu, Pending::Check, false)
                    }
                    None => {
                        let checked = std::mem::take(checked);
                        self.discovered(Ok(checked))
                    }
                }
            }
            Kind::Add { path } => {
                let apdu = Apdu::new(header::ADDRESS_DISPLAY, &path.encode());
                self.send(apdu, Pending::Address, true)
            }
            Kind::Sign(sign) => match sign.head {
                Head::Address => {
                    let apdu = Apdu::new(header::ADDRESS, &sign.path);
                    self.send(apdu, Pending::Address, false)
                }
                Head::App => {
                    let apdu = Apdu::new(header::APP, &[]);
                    self.send(apdu, Pending::App, false)
                }
                Head::Body => {
                    let (apdu, pending, confirm) = sign.next();
                    self.send(apdu, pending, confirm)
                }
            },
        }
    }

    /// An answer's data, its status `9000`: `Some` at the end.
    fn read(
        &mut self,
        pending: Pending,
        body: &[u8],
    ) -> Result<Option<Signed>, (LedgerCode, Cause)> {
        let unknown = |fault| (LedgerCode::Unknown, Cause::Answer(fault));
        match (&mut self.kind, pending) {
            (
                Kind::Accounts {
                    scheme,
                    start,
                    found,
                    ..
                },
                Pending::Address,
            ) => {
                let address = apdu::read_address(body).map_err(unknown)?;
                let index = u64::from(*start) + found.len() as u64;
                let path =
                    LedgerPath::new(*scheme, index).map_err(|_| unknown(AnswerFault::Length))?;
                found.push(Account { path, address });
                Ok(None)
            }
            (Kind::Accounts { checked, .. }, Pending::Check) => {
                checked.push(apdu::read_address(body).map_err(unknown)?);
                Ok(None)
            }
            (Kind::Add { path }, Pending::Address) => {
                let address = apdu::read_address(body).map_err(unknown)?;
                Ok(Some(Signed::Added(Account {
                    path: path.clone(),
                    address,
                })))
            }
            (Kind::Sign(sign), Pending::Address) => {
                let address = apdu::read_address(body).map_err(unknown)?;
                if address != sign.account.address {
                    return Err((LedgerCode::WrongDevice, Cause::WrongDevice));
                }
                sign.head = Head::App;
                Ok(None)
            }
            (Kind::Sign(sign), Pending::App) => {
                let app = apdu::read_app(body).map_err(unknown)?;
                self.app_version = Some(String::from_utf8_lossy(&app.version).into_owned());
                if app.format != 1 || app.name != ETHEREUM_APP {
                    return Err((LedgerCode::EthAppNotOpen, Cause::App));
                }
                sign.head = Head::Body;
                Ok(None)
            }
            (Kind::Sign(sign), Pending::Piece { last: true } | Pending::Sign) => {
                sign.check(body).map(Some)
            }
            (
                Kind::Sign(_),
                Pending::Piece { last: false } | Pending::FirstDefinition | Pending::Definition,
            ) => {
                if body.is_empty() {
                    Ok(None)
                } else {
                    Err(unknown(AnswerFault::Length))
                }
            }
            _ => Err(unknown(AnswerFault::Length)),
        }
    }
}

impl Sign {
    /// The body's next APDU, what it is, and whether the user confirms it.
    fn next(&mut self) -> (Option<Apdu>, Pending, bool) {
        match &mut self.body {
            Body::Transaction {
                prepared,
                size,
                next,
                ..
            } => {
                let unsigned = prepared
                    .as_ref()
                    .map(PreparedTransaction::unsigned)
                    .unwrap_or_default();
                let length = self.path.len() + unsigned.len();
                let start = *next * *size;
                let end = (start + *size).min(length);
                let last = end >= length;
                let header = if *next == 0 {
                    header::TX_FIRST
                } else {
                    header::TX_MORE
                };
                *next += 1;
                let apdu = piece(&self.path, unsigned, start, end)
                    .and_then(|piece| Apdu::new(header, &piece));
                (apdu, Pending::Piece { last }, last)
            }
            Body::Message {
                head,
                message,
                first,
                next,
            } => {
                let (apdu, end) = if *next == 0 {
                    let end = (*first).min(message.len());
                    let mut data = head.clone();
                    data.extend_from_slice(message.get(..end).unwrap_or_default());
                    (Apdu::new(header::MESSAGE_FIRST, &data), end)
                } else {
                    let start = *first + (*next - 1) * MESSAGE_PIECE;
                    let end = (start + MESSAGE_PIECE).min(message.len());
                    let piece = message.get(start..end);
                    (piece.and_then(|p| Apdu::new(header::MESSAGE_MORE, p)), end)
                };
                *next += 1;
                let last = end >= message.len();
                (apdu, Pending::Piece { last }, last)
            }
            Body::TypedData {
                stream,
                hashes,
                phase,
                ..
            } => match *phase {
                Typed::First | Typed::Stream => {
                    let pending = if *phase == Typed::First {
                        Pending::FirstDefinition
                    } else {
                        Pending::Definition
                    };
                    match stream.next() {
                        Some(apdu) => {
                            *phase = Typed::Stream;
                            (Some(apdu), pending, false)
                        }
                        None => {
                            *phase = Typed::End;
                            (
                                Apdu::new(header::SIGN_FIELDS, &self.path),
                                Pending::Sign,
                                true,
                            )
                        }
                    }
                }
                Typed::HashOnly => {
                    *phase = Typed::End;
                    let mut data = self.path.clone();
                    data.extend_from_slice(hashes);
                    (Apdu::new(header::SIGN_HASHES, &data), Pending::Sign, true)
                }
                Typed::End => (None, Pending::Sign, false),
            },
        }
    }

    /// The signature's answer, `v ‖ r ‖ s`, recovered against the account
    /// and the digest the user confirmed, `s` low (deviation
    /// `signature-check`); for a transaction, assembled and read back.
    fn check(&mut self, body: &[u8]) -> Result<Signed, (LedgerCode, Cause)> {
        let bad = |fault| (LedgerCode::BadSignature, Cause::Signature(fault));
        let (v, rs) = apdu::read_signature(body).ok_or(bad(SignatureFault::Length))?;
        let account = &self.account.address;
        let signed = |digest: &[u8; 32], parity: u8| -> Result<[u8; 65], (LedgerCode, Cause)> {
            let mut signature = [0u8; 65];
            signature[..64].copy_from_slice(&rs);
            signature[64] = 27 + parity;
            let signer =
                recover_address(digest, &signature).map_err(|_| bad(SignatureFault::Recovery))?;
            if signer != *account {
                return Err(bad(SignatureFault::Signer));
            }
            Ok(signature)
        };
        match &mut self.body {
            Body::Transaction {
                prepared,
                digest,
                legacy,
                ..
            } => {
                let parity = match legacy {
                    None => (v <= 1).then_some(v),
                    Some(prime) => legacy_parity(*prime, v),
                }
                .ok_or(bad(SignatureFault::V))?;
                let digest = *digest;
                let signature = signed(&digest, parity)?;
                // The last answer: the one copy becomes the signed transaction.
                let tx = prepared
                    .take()
                    .ok_or(bad(SignatureFault::Assembly))?
                    .finish(&signature)
                    .map_err(|_| bad(SignatureFault::Assembly))?;
                let decoded = decode_signed(&tx.raw).map_err(|_| bad(SignatureFault::Assembly))?;
                if *decoded.digest() != digest
                    || decoded.y_parity() != parity
                    || decoded.signer().as_ref() != Some(account)
                {
                    return Err(bad(SignatureFault::Assembly));
                }
                Ok(Signed::Transaction(tx))
            }
            Body::Message { message, .. } => {
                let parity = message_parity(v).ok_or(bad(SignatureFault::V))?;
                Ok(Signed::Signature(signed(&eip191_digest(message), parity)?))
            }
            Body::TypedData { hash, .. } => {
                let parity = message_parity(v).ok_or(bad(SignatureFault::V))?;
                Ok(Signed::Signature(signed(hash, parity)?))
            }
        }
    }
}

/// A path's elements on the heap.
fn path_heap(path: &LedgerPath) -> usize {
    std::mem::size_of_val(path.derivation_path().children())
}

/// A message's and typed data's `v`: 27 or 28.
fn message_parity(v: u8) -> Option<u8> {
    v.checked_sub(27).filter(|parity| *parity <= 1)
}

/// The chain ID's first four bytes, as the app keeps them for a legacy
/// `v` (hw-app-eth's `getChainIdAsUint32`).
fn chain_prime(chain_id: &U256) -> u64 {
    chain_id
        .to_minimal_be()
        .iter()
        .take(4)
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte))
}

/// A legacy transaction's parity from the app's one byte of
/// `chainId'·2 + 35 + parity` (hw-app-eth's `getParity`); the chain ID
/// itself, any width, then goes into the signed `v` (deviation
/// `chain-id-width`).
fn legacy_parity(prime: u64, v: u8) -> Option<u8> {
    let base = (prime * 2 + 35) % 256;
    if u64::from(v) == base {
        Some(0)
    } else if u64::from(v) == (base + 1) % 256 {
        Some(1)
    } else {
        None
    }
}

/// The piece size of `P ‖ T`: 255, but for a legacy transaction over one
/// piece the size hw-app-eth's `safeChunkTransaction` picks, so that no
/// piece ends where a legacy transaction could (`utils.js:202–247`): the
/// last piece is whole or longer than the RLP of `[chainId, 0, 0]` without
/// its list prefix.
fn piece_size(length: usize, tx: &Transaction) -> Result<usize, Refusal> {
    if length <= MAX_DATA || tx.tx_type() != 0 {
        return Ok(MAX_DATA);
    }
    let mut vrs = Vec::new();
    rlp::uint(&mut vrs, tx.chain_id());
    rlp::uint(&mut vrs, &U256::ZERO);
    rlp::uint(&mut vrs, &U256::ZERO);
    (1..=MAX_DATA)
        .rev()
        .find(|size| length.is_multiple_of(*size) || length % size > vrs.len())
        .ok_or(Refusal::Inconsistent)
}

/// Bytes `start..end` of `path ‖ unsigned`, without joining the two.
fn piece(path: &[u8], unsigned: &[u8], start: usize, end: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(end.checked_sub(start)?);
    if start < path.len() {
        out.extend_from_slice(path.get(start..end.min(path.len()))?);
    }
    let from = start.saturating_sub(path.len());
    let to = end.saturating_sub(path.len());
    if from < to {
        out.extend_from_slice(unsigned.get(from..to)?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v_at_every_chain_id_of_the_vectors() {
        // (chain ID, the app's byte for parity 0)
        for (chain, v0) in [
            ("1", 37u8),
            ("100", 235),
            ("137", 53),
            ("4294967295", 33),
            ("4294967296", 35),
            ("9007199254740992", 35),
            ("18446744073709551616", 35),
        ] {
            let prime = chain_prime(&fc_evm::parse_unsigned(chain).unwrap());
            assert_eq!(legacy_parity(prime, v0), Some(0), "{chain}");
            assert_eq!(legacy_parity(prime, v0.wrapping_add(1)), Some(1), "{chain}");
            for other in [v0.wrapping_sub(1), v0.wrapping_add(2), 27, 28, 0, 1] {
                if other != v0 && other != v0.wrapping_add(1) {
                    assert_eq!(legacy_parity(prime, other), None, "{chain} {other}");
                }
            }
        }
        // A chain whose byte wraps: 127·2 + 35 = 289, 33 and 34.
        assert_eq!(legacy_parity(127, 33), Some(0));
        assert_eq!(legacy_parity(127, 34), Some(1));
        // 110·2 + 35 = 255: parity 1 wraps to 0.
        assert_eq!(legacy_parity(110, 255), Some(0));
        assert_eq!(legacy_parity(110, 0), Some(1));
        assert_eq!(message_parity(27), Some(0));
        assert_eq!(message_parity(28), Some(1));
        for v in [0, 1, 26, 29, 37] {
            assert_eq!(message_parity(v), None);
        }
    }
}
