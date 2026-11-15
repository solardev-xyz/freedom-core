//! Phone jobs (design 0012, "Phone jobs" and "Unverified payments"; PHN-1):
//! the core makes each job from a checked authorization, for the chrome
//! main sends it to, binds what it signs, and checks the answer. The
//! reference is freedom-browser's `wallet/remote/bridge.js`, `signer.js`,
//! `errors.js` and `wallet/phone-payments.js` (#1027).
//!
//! - **A job** ([`PhoneJobs::open`]) has an id of 16 random bytes, the
//!   account's index and address, what it binds (a message's bytes, typed
//!   data's confirmed hash, a payment's chain, `to`, `value` and `data`),
//!   the authorization's kind and site, the `target` webContents it was
//!   sent to, and five minutes of the vault's clock ([`JOB_TTL_MS`]),
//!   expired at exactly its end, as a token is.
//! - **The sender.** Only the job's `target` marks it sent or answers it
//!   (`wrong_sender`); the job stays open for its own chrome, as `jobOf`
//!   ignores another webContents's message.
//! - **Once:** an answer settles its job, whatever it says. A second, or one
//!   after the job's life, is refused; the last [`MAX_SETTLED`] settled ids
//!   are remembered to say which.
//! - **Slots:** a payment's job takes one of [`MAX_SLOTS`] slots before its
//!   reply leaves the core; open payment jobs, payments waiting for their
//!   answer's read and records share them. A slot comes back when its job
//!   ends without a record (an error, an expiry, a transaction visible at
//!   the answer) and when its record is dropped. A signature's job takes
//!   one of [`MAX_SIGNATURE_JOBS`] of its own.
//! - **Records** ([`Record`]) are what `phone-payments.json` holds: the
//!   payment's bound fields, `data` by its length and SHA-256, the hash the
//!   phone reported and `answeredAt` on the wall clock. [`file_text`] writes
//!   them and [`read_file`] reads exactly that form back, within the bounds.
//! - **The comparison** ([`difference`]) is `phone-payments.js`'s: the
//!   sender, then the recipient, the amount, the data and the chain; a
//!   transaction without a chain id, or a field the core can't read, never
//!   matches. The phone picks its own nonce, gas and fees.
//!
//! No I/O: the vault's clock and the wall clock come in as parameters, job
//! ids from the caller's RNG.

use std::collections::VecDeque;

use fc_evm::{U256, to_hex};
use rand_core::TryCryptoRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

/// A job's life: `bridge.js`'s `DEFAULT_TIMEOUT_MS`, on the vault's clock.
pub const JOB_TTL_MS: u64 = 5 * 60 * 1000;

/// The record slots: open payment jobs, payments whose answer is being
/// read, and records, together.
pub const MAX_SLOTS: usize = 256;

/// Open signature jobs (a message, typed data) at once (*inferred*: the
/// design bounds payments only; a phone answers one job at a time).
pub const MAX_SIGNATURE_JOBS: usize = 64;

/// Settled job ids remembered, to tell a second answer or a late one from
/// an unknown job.
pub const MAX_SETTLED: usize = 256;

/// The longest site key a payment's job takes, as its record writes it,
/// escapes included and the quotes not.
pub const MAX_SITE_BYTES: usize = 2_048;

/// The longest record, as written.
pub const MAX_RECORD_BYTES: usize = 4_000;

/// The longest file read.
pub const MAX_FILE_BYTES: usize = 1_048_576;

/// How long a record waits for its transaction, on the wall clock.
pub const CHECK_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

/// The first recheck, after the answer or a start.
pub const FIRST_RECHECK_MS: u64 = 5_000;

/// Rechecks double up to this interval.
pub const MAX_RECHECK_MS: u64 = 10 * 60 * 1000;

/// The file's format.
const VERSION: u64 = 1;

/// A job's id: 16 random bytes, sent as 32 lowercase hex digits. Not a
/// secret: the chrome relays it, and the sender check guards the job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobId([u8; 16]);

impl JobId {
    pub fn text(&self) -> String {
        let mut text = to_hex(&self.0);
        text.drain(..2);
        text
    }

    /// Exactly 32 lowercase hex digits, as [`JobId::text`] writes them.
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = lower_hex(text, 16)?;
        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes);
        Some(JobId(id))
    }
}

/// `count` bytes as exactly `2 * count` lowercase hex digits, no prefix.
fn lower_hex(text: &str, count: usize) -> Option<Vec<u8>> {
    if text.len() != 2 * count
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    fc_evm::parse_bytes(&format!("0x{text}"), "hex").ok()
}

/// What a job binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binds {
    /// `personal_sign` of these bytes: checked over their EIP-191 digest.
    Message(Vec<u8>),
    /// `eth_signTypedData_v4` of the core's view: checked over the
    /// confirmed EIP-712 hash. `payload` is the JSON text relayed.
    TypedData { hash: [u8; 32], payload: String },
    /// `eth_sendTransaction`: the phone signs and broadcasts it.
    Payment(Payment),
}

/// A payment as its job binds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    pub chain_id: u64,
    pub to: [u8; 20],
    pub value: U256,
    pub data: Vec<u8>,
}

/// What a job came from: the authorization's kind (a token's kind, a
/// standing rule, a Safe approval, or main's word under `shell`) and the
/// page's site, if a page asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorized {
    pub kind: &'static str,
    pub site: Option<String>,
}

/// A job to open.
#[derive(Debug)]
pub struct NewJob<T> {
    pub account: u32,
    pub address: [u8; 20],
    pub target: u64,
    pub binds: Binds,
    pub authorized: Authorized,
    /// The caller's own: what the authorization does once the phone signed.
    pub extra: T,
}

/// Why a job isn't opened. Nothing goes to the phone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenRefusal {
    /// Every slot is held (`busy`).
    Busy,
    /// A payment's site key is over [`MAX_SITE_BYTES`] as written
    /// (`invalid_argument`).
    SiteTooLong,
    /// The RNG failed.
    Randomness,
}

/// An opened job's reply: the id, its life, and the JSON-RPC request to
/// relay.
#[derive(Debug, Clone, PartialEq)]
pub struct Opened {
    pub job: JobId,
    pub expires_in_ms: u64,
    pub method: &'static str,
    pub params: Value,
}

/// Why `phone.sent` or `phone.result` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Never opened, or forgotten.
    UnknownJob,
    /// Answered already.
    Settled,
    /// Past its life. `outcome_unknown`: a payment marked sent, which may
    /// have gone.
    Expired { outcome_unknown: bool },
    /// Another webContents than the job's `target`: the job stays open.
    WrongSender,
}

impl Refusal {
    /// `data.reason`.
    pub fn reason(&self) -> &'static str {
        match self {
            Refusal::UnknownJob => "unknown_job",
            Refusal::Settled => "settled",
            Refusal::Expired { .. } => "expired",
            Refusal::WrongSender => "wrong_sender",
        }
    }
}

/// How a settled job ended, for a later message about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    Answered,
    Expired { outcome_unknown: bool },
}

#[derive(Debug)]
struct Job<T> {
    id: JobId,
    account: u32,
    address: [u8; 20],
    target: u64,
    binds: Binds,
    authorized: Authorized,
    expires_at_ms: u64,
    sent: bool,
    extra: T,
}

/// An answered job, taken off the open ones.
#[derive(Debug)]
pub struct Taken<T> {
    pub id: JobId,
    pub account: u32,
    pub address: [u8; 20],
    pub binds: Binds,
    pub authorized: Authorized,
    /// Whether `phone.sent` marked it.
    pub sent: bool,
    pub extra: T,
}

/// A payment waiting for its transaction: `phone-payments.json`'s record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub job: JobId,
    pub hash: [u8; 32],
    pub account: u32,
    pub fields: Fields,
    pub kind: String,
    pub site: Option<String>,
    /// The wall clock at the answer, in milliseconds.
    pub answered_at: u64,
}

/// A payment's bound fields, in the record's form: addresses as lowercase
/// hex, quantities as decimal text, `data` by its length and SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fields {
    pub from: String,
    pub to: String,
    pub value: String,
    pub data_length: u64,
    pub data_sha256: String,
    pub chain_id: String,
}

impl Fields {
    /// What a job's payment binds, from `from`.
    pub fn bound(from: &[u8; 20], payment: &Payment) -> Self {
        let (data_length, data_sha256) = digest_of(&payment.data);
        Fields {
            from: to_hex(from),
            to: to_hex(&payment.to),
            value: payment.value.to_decimal(),
            data_length,
            data_sha256,
            chain_id: payment.chain_id.to_string(),
        }
    }
}

fn digest_of(data: &[u8]) -> (u64, String) {
    let length = u64::try_from(data.len()).unwrap_or(u64::MAX);
    let sha = Sha256::digest(data);
    let mut text = to_hex(&sha);
    text.drain(..2);
    (length, text)
}

/// A transaction as the chain shows it, in the record's form: a field the
/// core can't read is `None`, and never matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub from: Option<String>,
    pub to: Option<String>,
    pub value: Option<String>,
    pub data_length: Option<u64>,
    pub data_sha256: Option<String>,
    pub chain_id: Option<String>,
}

impl Observed {
    /// `eth_getTransactionByHash`'s result, read as `observedFieldsOf`
    /// reads it: `input`, else `data`; a missing `value` or `data` is zero
    /// or empty; a missing chain id stays missing. Anything but an object
    /// reads as nothing.
    pub fn of(tx: &Value) -> Self {
        let Some(tx) = tx.as_object() else {
            return Observed {
                from: None,
                to: None,
                value: None,
                data_length: None,
                data_sha256: None,
                chain_id: None,
            };
        };
        let data = match tx.get("input").filter(|v| !v.is_null()) {
            Some(input) => Some(input),
            None => tx.get("data"),
        };
        let digest = calldata(data).map(|bytes| digest_of(&bytes));
        Observed {
            from: tx.get("from").and_then(address_text),
            to: tx.get("to").and_then(address_text),
            value: quantity(tx.get("value"), true),
            data_length: digest.as_ref().map(|(length, _)| *length),
            data_sha256: digest.map(|(_, sha)| sha),
            chain_id: quantity(tx.get("chainId"), false),
        }
    }

    /// The transaction's fields, for the reply or the event that shows what
    /// the phone sent.
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "from": self.from,
            "to": self.to,
            "value": self.value,
            "data_length": self.data_length,
            "data_sha256": self.data_sha256,
            "chain_id": self.chain_id,
        })
    }
}

/// `0x` and 40 hex digits in either case, as lowercase text (`lower`
/// compares them so).
fn address_text(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    let digits = text.strip_prefix("0x")?;
    (digits.len() == 40 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| text.to_ascii_lowercase())
}

/// A quantity as decimal text: a `0x` hex or decimal string, or a JSON
/// integer. With `missing_is_zero`, an absent or null one is 0 (a value);
/// otherwise it stays missing (a chain id).
fn quantity(value: Option<&Value>, missing_is_zero: bool) -> Option<String> {
    match value {
        None | Some(Value::Null) => missing_is_zero.then(|| "0".to_owned()),
        Some(Value::String(text)) if text.is_empty() => missing_is_zero.then(|| "0".to_owned()),
        Some(Value::String(text)) => {
            let parsed = match text.strip_prefix("0x") {
                Some(hex) if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    fc_evm::parse_unsigned(text)
                }
                Some(_) => None,
                None if text.bytes().all(|b| b.is_ascii_digit()) => fc_evm::parse_unsigned(text),
                None => None,
            };
            parsed.map(|n| n.to_decimal())
        }
        Some(Value::Number(n)) => n.as_u64().map(|n| n.to_string()),
        Some(_) => None,
    }
}

/// Calldata's bytes: none is empty; anything but `0x`-prefixed hex with an
/// even number of digits is unreadable.
fn calldata(value: Option<&Value>) -> Option<Vec<u8>> {
    match value {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::String(text)) if text.is_empty() => Some(Vec::new()),
        Some(Value::String(text)) if text.starts_with("0x") => {
            fc_evm::parse_bytes(text, "data").ok()
        }
        Some(_) => None,
    }
}

/// How a visible transaction differs from what was confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Difference {
    /// Another account sent it (`wrong_account`).
    Sender,
    /// Its recipient, amount, data or chain differs (`wrong_transaction`).
    Transaction,
}

impl Difference {
    pub fn reason(&self) -> &'static str {
        match self {
            Difference::Sender => "wrong_account",
            Difference::Transaction => "wrong_transaction",
        }
    }
}

/// `differenceOf`: `None` when `seen` is the confirmed payment.
pub fn difference(seen: &Observed, bound: &Fields) -> Option<Difference> {
    if seen.from.as_deref() != Some(bound.from.as_str()) {
        return Some(Difference::Sender);
    }
    let same = seen.to.as_deref() == Some(bound.to.as_str())
        && seen.value.as_deref() == Some(bound.value.as_str())
        && seen.data_length == Some(bound.data_length)
        && seen.data_sha256.as_deref() == Some(bound.data_sha256.as_str())
        && seen.chain_id.as_deref() == Some(bound.chain_id.as_str());
    (!same).then_some(Difference::Transaction)
}

/// Whether a record still waits at `now` (wall-clock ms): `answeredAt ≤
/// now < answeredAt + 24 h`. Otherwise it ends unknown, never verified.
pub fn within_window(answered_at: u64, now: u64) -> bool {
    answered_at <= now && now < answered_at.saturating_add(CHECK_WINDOW_MS)
}

/// The wait before the next recheck after waiting `previous` ms (none yet:
/// `first`): doubled, at most [`MAX_RECHECK_MS`], and never past the end
/// of the record's window, so that it ends on time.
pub fn next_recheck_in(answered_at: u64, previous: Option<u64>, now: u64, first: u64) -> u64 {
    let wait = previous.map_or(first, |previous| {
        previous.saturating_mul(2).min(MAX_RECHECK_MS.max(first))
    });
    let left = answered_at
        .saturating_add(CHECK_WINDOW_MS)
        .saturating_sub(now);
    wait.min(left)
}

/// Why a phone's signature isn't taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureRefusal {
    /// Not 65 bytes of `0x` hex, or not a signature that recovers
    /// (`bad_response`).
    BadResponse,
    /// It recovers to another account (`wrong_account`).
    WrongAccount,
}

impl SignatureRefusal {
    pub fn reason(&self) -> &'static str {
        match self {
            SignatureRefusal::BadResponse => "bad_response",
            SignatureRefusal::WrongAccount => "wrong_account",
        }
    }
}

/// `verifiedSignature`: `answer` must be `0x` and 130 hex digits and
/// recover to `address` over `digest`. Its `v` is 27 or 28, or 0 or 1 read
/// as those, as ethers reads them; anything else, and a high `s`, is a bad
/// response. Returns the signature as the phone sent it.
pub fn check_signature<'a>(
    answer: &'a Value,
    digest: &[u8; 32],
    address: &[u8; 20],
) -> Result<&'a str, SignatureRefusal> {
    let text = answer.as_str().ok_or(SignatureRefusal::BadResponse)?;
    let digits = text
        .strip_prefix("0x")
        .filter(|digits| digits.len() == 130)
        .ok_or(SignatureRefusal::BadResponse)?;
    let bytes = fc_evm::parse_bytes(&format!("0x{digits}"), "signature")
        .map_err(|_| SignatureRefusal::BadResponse)?;
    let mut signature = [0u8; 65];
    signature.copy_from_slice(&bytes);
    signature[64] = match signature[64] {
        0 | 27 => 27,
        1 | 28 => 28,
        _ => return Err(SignatureRefusal::BadResponse),
    };
    let signer =
        fc_evm::recover_address(digest, &signature).map_err(|_| SignatureRefusal::BadResponse)?;
    if signer == *address {
        Ok(text)
    } else {
        Err(SignatureRefusal::WrongAccount)
    }
}

/// A payment's answer: `0x` and 64 hex digits, as the hash's bytes. Any
/// other answer is unreadable, and the payment's outcome unknown.
pub fn payment_hash(answer: &Value) -> Option<[u8; 32]> {
    let digits = answer.as_str()?.strip_prefix("0x")?;
    if digits.len() != 64 {
        return None;
    }
    let bytes = fc_evm::parse_bytes(&format!("0x{digits}"), "hash").ok()?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Some(hash)
}

/// The remote signer's codes (`errors.js`' `REMOTE_ERROR_CODES`).
pub const REMOTE_CODES: [&str; 13] = [
    "REMOTE_TIMEOUT",
    "REMOTE_USER_CANCELLED",
    "REMOTE_USER_REJECTED",
    "REMOTE_WRONG_ACCOUNT",
    "REMOTE_WRONG_TRANSACTION",
    "REMOTE_BAD_RESPONSE",
    "REMOTE_NO_UI",
    "REMOTE_UNSUPPORTED",
    "REMOTE_ADDRESS_MISMATCH",
    "REMOTE_ADDRESS_UNPROVEN",
    "REMOTE_ACCOUNT_UNCHECKED",
    "REMOTE_UNKNOWN",
    "REMOTE_OUTCOME_UNKNOWN",
];

/// The longest error message passed on (*inferred*): a longer one is
/// dropped, and main shows the code's own text.
pub const MAX_MESSAGE_BYTES: usize = 1_024;

/// An error the chrome reported for a job: the phone wallet's JSON-RPC
/// error (`rpc_code`), or a code the chrome or main minted (a dropped
/// session, a closed dialog, main's timeout).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ErrorAnswer {
    pub rpc_code: Option<i64>,
    pub code: Option<String>,
    pub message: Option<String>,
}

/// What an error means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mapped {
    /// A payment that may have gone: unknown, never failed.
    Unknown,
    /// Failed, with the remote signer's code and the message to show.
    Failed {
        code: &'static str,
        message: Option<String>,
    },
}

/// `bridge.js`' `errorOf` and `errors.js`' `mapRemoteRpcError`: after
/// `phone.sent`, a payment's error is unknown unless the phone refused it
/// (EIP-1193 4001, 4100, 4200); otherwise the phone's code maps to
/// `REMOTE_USER_REJECTED`, `REMOTE_WRONG_ACCOUNT` or `REMOTE_UNSUPPORTED`
/// (any other to `REMOTE_UNKNOWN`), with the phone's message but for a
/// rejection, and a minted code passes as it is if the registry has it
/// (`REMOTE_UNKNOWN` if not).
pub fn map_error(payment_sent: bool, error: &ErrorAnswer) -> Mapped {
    let refused = matches!(error.rpc_code, Some(4001 | 4100 | 4200));
    if payment_sent && !refused {
        return Mapped::Unknown;
    }
    let message = error
        .message
        .clone()
        .filter(|message| message.len() <= MAX_MESSAGE_BYTES);
    match error.rpc_code {
        Some(rpc) => {
            let code = match rpc {
                4001 => "REMOTE_USER_REJECTED",
                4100 => "REMOTE_WRONG_ACCOUNT",
                4200 => "REMOTE_UNSUPPORTED",
                _ => "REMOTE_UNKNOWN",
            };
            let message = if code == "REMOTE_USER_REJECTED" {
                None
            } else {
                message
            };
            Mapped::Failed { code, message }
        }
        None => {
            let code = error
                .code
                .as_deref()
                .and_then(|code| REMOTE_CODES.iter().copied().find(|known| *known == code))
                .unwrap_or("REMOTE_UNKNOWN");
            Mapped::Failed { code, message }
        }
    }
}

/// A site key's length as its record writes it: the JSON string's bytes,
/// escapes included, without the quotes.
pub fn written_len(site: &str) -> usize {
    serde_json::to_string(site).map_or(usize::MAX, |text| text.len().saturating_sub(2))
}

/// The open jobs and the records, with their slots. `T` is the caller's
/// own, kept with each job until it is answered.
#[derive(Debug)]
pub struct PhoneJobs<T> {
    open: Vec<Job<T>>,
    /// Payments answered with a hash, while the answer's read runs: each
    /// holds its slot.
    answering: Vec<JobId>,
    records: Vec<Record>,
    settled: VecDeque<(JobId, Ended)>,
}

impl<T> Default for PhoneJobs<T> {
    fn default() -> Self {
        PhoneJobs {
            open: Vec::new(),
            answering: Vec::new(),
            records: Vec::new(),
            settled: VecDeque::new(),
        }
    }
}

impl<T> PhoneJobs<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// The slots held: open payment jobs, payments being read, records.
    pub fn slots_used(&self) -> usize {
        self.open
            .iter()
            .filter(|job| matches!(job.binds, Binds::Payment(_)))
            .count()
            + self.answering.len()
            + self.records.len()
    }

    /// Opens a job at `now_ms` on the vault's clock, taking a payment's
    /// slot before anything is relayed.
    pub fn open<R: TryCryptoRng + ?Sized>(
        &mut self,
        job: NewJob<T>,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Opened, OpenRefusal> {
        let payment = matches!(job.binds, Binds::Payment(_));
        self.check_room(payment, job.authorized.site.as_deref(), now_ms)?;
        let mut bytes = [0u8; 16];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| OpenRefusal::Randomness)?;
        let id = JobId(bytes);
        // Sixteen random bytes don't repeat; if they ever did, no job
        // would be confused with another.
        if self.known(&id) {
            return Err(OpenRefusal::Randomness);
        }
        let (method, params) = request(&job.address, &job.binds);
        self.open.push(Job {
            id,
            account: job.account,
            address: job.address,
            target: job.target,
            binds: job.binds,
            authorized: job.authorized,
            expires_at_ms: now_ms.saturating_add(JOB_TTL_MS),
            sent: false,
            extra: job.extra,
        });
        Ok(Opened {
            job: id,
            expires_in_ms: JOB_TTL_MS,
            method,
            params,
        })
    }

    /// Whether a job would open at `now_ms`: a payment's needs a free slot
    /// and a site key within [`MAX_SITE_BYTES`] as written; a signature's,
    /// one of its own places. Checked before the authorization is spent,
    /// and again as the job opens.
    pub fn check_room(
        &mut self,
        payment: bool,
        site: Option<&str>,
        now_ms: u64,
    ) -> Result<(), OpenRefusal> {
        self.expire(now_ms);
        if payment {
            if site.is_some_and(|site| written_len(site) > MAX_SITE_BYTES) {
                return Err(OpenRefusal::SiteTooLong);
            }
            if self.slots_used() >= MAX_SLOTS {
                return Err(OpenRefusal::Busy);
            }
        } else {
            let signatures = self
                .open
                .iter()
                .filter(|job| !matches!(job.binds, Binds::Payment(_)))
                .count();
            if signatures >= MAX_SIGNATURE_JOBS {
                return Err(OpenRefusal::Busy);
            }
        }
        Ok(())
    }

    /// Takes back a job just opened whose reply can't go: as if it never
    /// was.
    pub fn cancel(&mut self, id: &JobId) {
        self.open.retain(|job| job.id != *id);
    }

    fn known(&self, id: &JobId) -> bool {
        self.open.iter().any(|job| job.id == *id)
            || self.answering.contains(id)
            || self.records.iter().any(|record| record.job == *id)
            || self.settled.iter().any(|(settled, _)| settled == id)
    }

    /// Ends the open jobs whose life is over at `now_ms`: each is
    /// settled, and a payment's slot comes back. Returns their ids.
    pub fn expire(&mut self, now_ms: u64) -> Vec<JobId> {
        let mut ended = Vec::new();
        let mut i = 0;
        while i < self.open.len() {
            if self.open[i].expires_at_ms <= now_ms {
                let job = self.open.remove(i);
                let outcome_unknown = job.sent && matches!(job.binds, Binds::Payment(_));
                self.settle(job.id, Ended::Expired { outcome_unknown });
                ended.push(job.id);
                continue;
            }
            i += 1;
        }
        ended
    }

    /// When the first open job expires, on the vault's clock.
    pub fn next_expiry(&self) -> Option<u64> {
        self.open.iter().map(|job| job.expires_at_ms).min()
    }

    fn settle(&mut self, id: JobId, ended: Ended) {
        while self.settled.len() >= MAX_SETTLED {
            self.settled.pop_front();
        }
        self.settled.push_back((id, ended));
    }

    /// The open job `id` for `sender`, or why there is none.
    fn find(&mut self, id: &JobId, sender: u64, now_ms: u64) -> Result<usize, Refusal> {
        self.expire(now_ms);
        if let Some(index) = self.open.iter().position(|job| job.id == *id) {
            if self.open[index].target != sender {
                return Err(Refusal::WrongSender);
            }
            return Ok(index);
        }
        match self.settled.iter().find(|(settled, _)| settled == id) {
            Some((_, Ended::Answered)) => Err(Refusal::Settled),
            Some((_, Ended::Expired { outcome_unknown })) => Err(Refusal::Expired {
                outcome_unknown: *outcome_unknown,
            }),
            None if self.answering.contains(id) || self.records.iter().any(|r| r.job == *id) => {
                Err(Refusal::Settled)
            }
            None => Err(Refusal::UnknownJob),
        }
    }

    /// `phone.sent`: marks the job possibly sent, in one turn.
    pub fn sent(&mut self, id: &JobId, sender: u64, now_ms: u64) -> Result<(), Refusal> {
        let index = self.find(id, sender, now_ms)?;
        self.open[index].sent = true;
        Ok(())
    }

    /// `phone.result`: takes the job off the open ones, settled whatever
    /// the answer says. With `hash`, a payment's slot stays held until
    /// [`PhoneJobs::release`] or [`PhoneJobs::record`].
    pub fn answer(
        &mut self,
        id: &JobId,
        sender: u64,
        now_ms: u64,
        hash: bool,
    ) -> Result<Taken<T>, Refusal> {
        let index = self.find(id, sender, now_ms)?;
        let job = self.open.remove(index);
        self.settle(job.id, Ended::Answered);
        if hash && matches!(job.binds, Binds::Payment(_)) {
            self.answering.push(job.id);
        }
        Ok(Taken {
            id: job.id,
            account: job.account,
            address: job.address,
            binds: job.binds,
            authorized: job.authorized,
            sent: job.sent,
            extra: job.extra,
        })
    }

    /// A payment being read ended without a record (its transaction was
    /// visible at the answer): its slot comes back.
    pub fn release(&mut self, id: &JobId) {
        self.answering.retain(|answering| answering != id);
    }

    /// A payment being read is kept as `record`, in its job's slot.
    pub fn record(&mut self, record: Record) {
        self.answering.retain(|answering| *answering != record.job);
        self.records.retain(|kept| kept.job != record.job);
        self.records.push(record);
    }

    /// Drops a record: its slot comes back.
    pub fn drop_record(&mut self, id: &JobId) -> Option<Record> {
        let index = self.records.iter().position(|record| record.job == *id)?;
        Some(self.records.remove(index))
    }

    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// The records a start read (at most [`MAX_SLOTS`]: [`read_file`]
    /// refuses more).
    pub fn load(&mut self, records: Vec<Record>) {
        self.records = records;
    }
}

/// The JSON-RPC request a job relays, as `signer.js` builds it: the
/// message's hex with the account; the account with the core's view of the
/// typed data; the payment's `from`, `to`, `value`, `data` and `chainId`,
/// quantities as `toQuantity` writes them.
fn request(address: &[u8; 20], binds: &Binds) -> (&'static str, Value) {
    let account = fc_evm::checksum_address(address);
    match binds {
        Binds::Message(bytes) => ("personal_sign", serde_json::json!([to_hex(bytes), account])),
        Binds::TypedData { payload, .. } => (
            "eth_signTypedData_v4",
            serde_json::json!([account, payload]),
        ),
        Binds::Payment(payment) => (
            "eth_sendTransaction",
            serde_json::json!([{
                "from": account,
                "to": fc_evm::checksum_address(&payment.to),
                "value": to_quantity(&payment.value),
                "chainId": to_quantity(&U256::from_u64(payment.chain_id)),
                "data": to_hex(&payment.data),
            }]),
        ),
    }
}

/// ethers' `toQuantity`: `0x` and the hex digits without leading zeros,
/// `0x0` for zero.
fn to_quantity(value: &U256) -> String {
    let hex = to_hex(&value.to_be_bytes());
    let digits = hex[2..].trim_start_matches('0');
    if digits.is_empty() {
        "0x0".to_owned()
    } else {
        format!("0x{digits}")
    }
}

/// The token kinds and other authorizations a record names.
const KINDS: [&str; 6] = [
    "wallet-send",
    "dapp-send",
    "executor-send",
    "standing",
    "safe",
    "none",
];

/// The kind's name as [`KINDS`] has it, or `None`.
pub fn record_kind(kind: &str) -> Option<&'static str> {
    KINDS.iter().copied().find(|known| *known == kind)
}

#[derive(Serialize)]
struct FileOut<'a> {
    version: u64,
    payments: Vec<RecordOut<'a>>,
}

#[derive(Serialize)]
struct RecordOut<'a> {
    job: String,
    hash: String,
    account: u32,
    from: &'a str,
    chain_id: &'a str,
    to: &'a str,
    value: &'a str,
    data_length: u64,
    data_sha256: &'a str,
    kind: &'a str,
    site: Option<&'a str>,
    answered_at: u64,
}

impl<'a> RecordOut<'a> {
    fn of(record: &'a Record) -> Self {
        RecordOut {
            job: record.job.text(),
            hash: to_hex(&record.hash),
            account: record.account,
            from: &record.fields.from,
            chain_id: &record.fields.chain_id,
            to: &record.fields.to,
            value: &record.fields.value,
            data_length: record.fields.data_length,
            data_sha256: &record.fields.data_sha256,
            kind: &record.kind,
            site: record.site.as_deref(),
            answered_at: record.answered_at,
        }
    }
}

/// A record's bytes as [`file_text`] writes it.
pub fn record_len(record: &Record) -> usize {
    serde_json::to_vec(&RecordOut::of(record)).map_or(usize::MAX, |bytes| bytes.len())
}

/// `phone-payments.json`'s text: compact JSON, `{"version":1,"payments":
/// [...]}`, each record's members in a fixed order.
pub fn file_text(records: &[Record]) -> Vec<u8> {
    let file = FileOut {
        version: VERSION,
        payments: records.iter().map(RecordOut::of).collect(),
    };
    serde_json::to_vec(&file).unwrap_or_default()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIn<'a> {
    version: u64,
    #[serde(borrow)]
    payments: Vec<&'a RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordIn {
    job: String,
    hash: String,
    account: u32,
    from: String,
    chain_id: String,
    to: String,
    value: String,
    data_length: u64,
    data_sha256: String,
    kind: String,
    site: Value,
    answered_at: u64,
}

/// Why a file is unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreadable {
    TooLarge,
    Malformed,
    TooManyRecords,
    RecordTooLarge,
}

/// Reads `phone-payments.json`'s bytes: what [`file_text`] writes, with
/// JSON's whitespace between tokens. At most [`MAX_FILE_BYTES`], at most
/// [`MAX_SLOTS`] records, each at most [`MAX_RECORD_BYTES`] as it stands in
/// the file; every member present once, and in the form the writer writes
/// it (lowercase hex, decimal text without leading zeros, a known kind).
/// Two records of one job make it unreadable.
pub fn read_file(bytes: &[u8]) -> Result<Vec<Record>, Unreadable> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Unreadable::TooLarge);
    }
    let file: FileIn<'_> = serde_json::from_slice(bytes).map_err(|_| Unreadable::Malformed)?;
    if file.version != VERSION {
        return Err(Unreadable::Malformed);
    }
    if file.payments.len() > MAX_SLOTS {
        return Err(Unreadable::TooManyRecords);
    }
    let mut records: Vec<Record> = Vec::with_capacity(file.payments.len());
    for raw in file.payments {
        if raw.get().len() > MAX_RECORD_BYTES {
            return Err(Unreadable::RecordTooLarge);
        }
        let record = read_record(raw.get()).ok_or(Unreadable::Malformed)?;
        if records.iter().any(|kept| kept.job == record.job) {
            return Err(Unreadable::Malformed);
        }
        records.push(record);
    }
    Ok(records)
}

fn read_record(text: &str) -> Option<Record> {
    let record: RecordIn = serde_json::from_str(text).ok()?;
    let hash = {
        let digits = record.hash.strip_prefix("0x")?;
        let bytes = lower_hex(digits, 32)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        hash
    };
    let address = |text: &str| {
        text.strip_prefix("0x")
            .and_then(|digits| lower_hex(digits, 20))
            .is_some()
    };
    if !address(&record.from) || !address(&record.to) {
        return None;
    }
    if record.account > crate::MAX_ACCOUNT {
        return None;
    }
    let chain_id = canonical_decimal(&record.chain_id)?;
    if chain_id.to_u64().is_none_or(|id| id > crate::MAX_CHAIN_ID) {
        return None;
    }
    canonical_decimal(&record.value)?;
    lower_hex(&record.data_sha256, 32)?;
    let kind = record_kind(&record.kind)?;
    let site = match record.site {
        Value::Null => None,
        Value::String(site) => Some(site),
        _ => return None,
    };
    Some(Record {
        job: JobId::parse(&record.job)?,
        hash,
        account: record.account,
        fields: Fields {
            from: record.from,
            to: record.to,
            value: record.value,
            data_length: record.data_length,
            data_sha256: record.data_sha256,
            chain_id: record.chain_id,
        },
        kind: kind.to_owned(),
        site,
        answered_at: record.answered_at,
    })
}

/// Decimal text as `U256::to_decimal` writes it: digits, no leading zero
/// but for zero itself.
fn canonical_decimal(text: &str) -> Option<U256> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    fc_evm::parse_unsigned(text)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const ADDRESS: [u8; 20] = [0x11; 20];
    const TO: [u8; 20] = [0x22; 20];

    struct Counter(u64);

    impl rand_core::TryRng for Counter {
        type Error = std::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.0 += 1;
            let counter = self.0.to_le_bytes();
            for (i, byte) in dst.iter_mut().enumerate() {
                *byte = counter.get(i).copied().unwrap_or(0x5a);
            }
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for Counter {}

    struct Failing;
    impl rand_core::TryRng for Failing {
        type Error = std::fmt::Error;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(std::fmt::Error)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(std::fmt::Error)
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
            Err(std::fmt::Error)
        }
    }
    impl rand_core::TryCryptoRng for Failing {}

    /// A job's ids come from a counter that never repeats in a test.
    fn rng() -> Counter {
        Counter(0)
    }

    fn payment(data: Vec<u8>) -> Payment {
        Payment {
            chain_id: 100,
            to: TO,
            value: U256::from_u64(5),
            data,
        }
    }

    fn new_job(binds: Binds, site: Option<&str>, target: u64) -> NewJob<u32> {
        NewJob {
            account: 3,
            address: ADDRESS,
            target,
            binds,
            authorized: Authorized {
                kind: "dapp-send",
                site: site.map(str::to_owned),
            },
            extra: 7,
        }
    }

    fn record(job: u8, site: Option<&str>) -> Record {
        Record {
            job: JobId([job; 16]),
            hash: [job; 32],
            account: 3,
            fields: Fields::bound(&ADDRESS, &payment(vec![1, 2, 3])),
            kind: "dapp-send".into(),
            site: site.map(str::to_owned),
            answered_at: 1_700_000_000_000,
        }
    }

    fn tx(data: &str, chain: Option<&str>) -> Value {
        let mut tx = serde_json::json!({
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "value": "0x5",
            "input": data,
        });
        if let Some(chain) = chain {
            tx["chainId"] = chain.into();
        }
        tx
    }

    /// The file's text, byte for byte, and its read back: the writer's
    /// form is the reader's.
    #[test]
    fn the_file_is_read_as_written() {
        let one = record(1, Some("https://app.example"));
        let two = Record {
            site: None,
            kind: "standing".into(),
            ..record(2, None)
        };
        let text = file_text(&[one.clone(), two.clone()]);
        let expected = format!(
            concat!(
                r#"{{"version":1,"payments":[{{"job":"{j1}","hash":"0x{h1}","account":3,"#,
                r#""from":"0x{a}","chain_id":"100","to":"0x{t}","value":"5","data_length":3,"#,
                r#""data_sha256":"{s}","kind":"dapp-send","site":"https://app.example","#,
                r#""answered_at":1700000000000}},{{"job":"{j2}","hash":"0x{h2}","account":3,"#,
                r#""from":"0x{a}","chain_id":"100","to":"0x{t}","value":"5","data_length":3,"#,
                r#""data_sha256":"{s}","kind":"standing","site":null,"answered_at":1700000000000}}]}}"#
            ),
            j1 = "01".repeat(16),
            h1 = "01".repeat(32),
            j2 = "02".repeat(16),
            h2 = "02".repeat(32),
            a = "11".repeat(20),
            t = "22".repeat(20),
            s = "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
        );
        assert_eq!(String::from_utf8(text.clone()).unwrap(), expected);
        assert_eq!(read_file(&text).unwrap(), vec![one, two]);
        assert_eq!(read_file(&file_text(&[])).unwrap(), vec![]);
    }

    /// Anything the writer wouldn't write is unreadable: a member missing,
    /// unknown or twice, another version, another form of a field, an
    /// unknown kind, two records of one job.
    #[test]
    fn only_the_writer_s_form_reads() {
        let good = String::from_utf8(file_text(&[record(1, Some("s"))])).unwrap();
        assert!(read_file(good.as_bytes()).is_ok());
        let swaps: Vec<(&str, String)> = vec![
            (r#""version":1"#, r#""version":2"#.into()),
            (r#""account":3"#, r#""account":3,"account":3"#.into()),
            (r#""account":3"#, r#""account":3,"extra":1"#.into()),
            (r#""account":3,"#, String::new()),
            (r#""site":"s""#, r#""site":1"#.into()),
            (r#""site":"s","#, String::new()),
            (r#""kind":"dapp-send""#, r#""kind":"sign-message""#.into()),
            (r#""value":"5""#, r#""value":"05""#.into()),
            (r#""value":"5""#, r#""value":"0x5""#.into()),
            (r#""value":"5""#, r#""value":5"#.into()),
            (
                r#""chain_id":"100""#,
                r#""chain_id":"9007199254740992""#.into(),
            ),
            (r#""account":3"#, r#""account":2147483648"#.into()),
            (r#""data_length":3"#, r#""data_length":-1"#.into()),
            (
                r#""answered_at":1700000000000"#,
                r#""answered_at":1.5"#.into(),
            ),
            ("\"from\":\"0x1111", "\"from\":\"0X1111".into()),
            ("\"to\":\"0x2222", "\"to\":\"0x2A22".into()),
            ("\"hash\":\"0x0101", "\"hash\":\"0x01".into()),
            ("\"job\":\"0101", "\"job\":\"0A01".into()),
            ("\"data_sha256\":\"039", "\"data_sha256\":\"03".into()),
        ];
        for (from, to) in swaps {
            assert!(good.contains(from), "{from}");
            let bad = good.replacen(from, &to, 1);
            assert!(read_file(bad.as_bytes()).is_err(), "{bad}");
        }
        // The largest chain id and account the writer writes read.
        let edge = good
            .replacen(r#""chain_id":"100""#, r#""chain_id":"9007199254740991""#, 1)
            .replacen(r#""account":3"#, r#""account":2147483647"#, 1);
        assert!(read_file(edge.as_bytes()).is_ok());
        // Two records of one job.
        let twice = file_text(&[record(1, None), record(1, None)]);
        assert_eq!(read_file(&twice), Err(Unreadable::Malformed));
        assert_eq!(read_file(b"[]"), Err(Unreadable::Malformed));
        assert_eq!(read_file(b"{ torn"), Err(Unreadable::Malformed));
    }

    /// Whitespace pads a record of the bound's length.
    fn padded_record(job: u8, len: usize) -> String {
        let text = String::from_utf8(file_text(&[record(job, Some(""))])).unwrap();
        let start = text.find("[{").unwrap() + 1;
        let one = &text[start..text.len() - 2];
        let pad = len - one.len();
        // A long site fills it: no whitespace inside the record.
        one.replacen(
            r#""site":"""#,
            &format!(r#""site":"{}""#, "x".repeat(pad)),
            1,
        )
    }

    /// A record of exactly 4,000 bytes and a file of exactly 1 MiB read; a
    /// byte more of either, or a 257th record, doesn't.
    #[test]
    fn the_file_s_bounds() {
        let at = padded_record(1, MAX_RECORD_BYTES);
        assert_eq!(at.len(), MAX_RECORD_BYTES);
        let file = |records: &[String], pad: usize| {
            format!(
                r#"{{"version":1,"payments":[{}]{}}}"#,
                records.join(","),
                " ".repeat(pad)
            )
        };
        assert_eq!(
            read_file(file(std::slice::from_ref(&at), 0).as_bytes())
                .unwrap()
                .len(),
            1
        );
        let over = padded_record(1, MAX_RECORD_BYTES + 1);
        assert_eq!(
            read_file(file(&[over], 0).as_bytes()),
            Err(Unreadable::RecordTooLarge)
        );
        let full: Vec<String> = (0..=255u8)
            .map(|job| padded_record(job, MAX_RECORD_BYTES))
            .collect();
        let bare = file(&full, 0).len();
        let exact = file(&full, MAX_FILE_BYTES - bare);
        assert_eq!(exact.len(), MAX_FILE_BYTES);
        assert_eq!(read_file(exact.as_bytes()).unwrap().len(), MAX_SLOTS);
        let long = file(&full, MAX_FILE_BYTES - bare + 1);
        assert_eq!(read_file(long.as_bytes()), Err(Unreadable::TooLarge));
        let mut many: Vec<String> = (0..=255u8).map(|job| padded_record(job, 500)).collect();
        assert_eq!(read_file(file(&many, 0).as_bytes()).unwrap().len(), 256);
        many.push(padded_record(0, 500).replacen(
            &format!("\"job\":\"{}\"", "00".repeat(16)),
            &format!("\"job\":\"{}\"", "ab".repeat(16)),
            1,
        ));
        assert_eq!(
            read_file(file(&many, 0).as_bytes()),
            Err(Unreadable::TooManyRecords)
        );
    }

    /// Every field but the site has a largest size, so a site of 2,048
    /// bytes as written keeps the largest record within 4,000.
    #[test]
    fn the_largest_record_fits() {
        let largest = Record {
            job: JobId([0xff; 16]),
            hash: [0xff; 32],
            account: crate::MAX_ACCOUNT,
            fields: Fields {
                from: to_hex(&[0xff; 20]),
                to: to_hex(&[0xff; 20]),
                value: U256::MAX.to_decimal(),
                data_length: u64::MAX,
                data_sha256: "f".repeat(64),
                chain_id: crate::MAX_CHAIN_ID.to_string(),
            },
            kind: "executor-send".into(),
            site: Some("\u{1}".repeat(MAX_SITE_BYTES / 6) + &"x".repeat(MAX_SITE_BYTES % 6)),
            answered_at: u64::MAX,
        };
        assert_eq!(
            written_len(largest.site.as_deref().unwrap()),
            MAX_SITE_BYTES
        );
        assert!(
            record_len(&largest) <= MAX_RECORD_BYTES,
            "{}",
            record_len(&largest)
        );
        assert_eq!(
            read_file(&file_text(std::slice::from_ref(&largest))).unwrap(),
            vec![largest]
        );
    }

    /// A payment of 1 MiB of data is recorded by its length and SHA-256.
    #[test]
    fn data_is_kept_by_its_digest() {
        let data = vec![0xab; 1 << 20];
        let fields = Fields::bound(&ADDRESS, &payment(data.clone()));
        assert_eq!(fields.data_length, 1 << 20);
        let text = file_text(&[Record {
            fields,
            ..record(1, None)
        }]);
        assert!(text.len() < MAX_RECORD_BYTES);
        assert!(!text.windows(8).any(|w| w == b"abababab"));
        let mut sha = to_hex(&Sha256::digest(&data));
        sha.drain(..2);
        assert!(String::from_utf8(text).unwrap().contains(&sha));
    }

    /// The comparison: the sender first, then each other field; a missing
    /// chain id, a field that can't be read, data differing in its last
    /// byte or its length, all differ.
    #[test]
    fn a_visible_transaction_is_compared_field_by_field() {
        let bound = Fields::bound(&ADDRESS, &payment(vec![1, 2, 3]));
        let same = tx("0x010203", Some("0x64"));
        assert_eq!(difference(&Observed::of(&same), &bound), None);
        // `data` when there's no `input`, and decimal or integer quantities.
        let mut other_form = same.clone();
        other_form.as_object_mut().unwrap().remove("input");
        other_form["data"] = "0x010203".into();
        other_form["chainId"] = 100.into();
        other_form["value"] = "5".into();
        assert_eq!(difference(&Observed::of(&other_form), &bound), None);
        let mut upper = same.clone();
        upper["from"] = "0x1111111111111111111111111111111111111111"
            .to_uppercase()
            .replace("0X", "0x")
            .into();
        assert_eq!(difference(&Observed::of(&upper), &bound), None);
        let changed = |field: &str, value: Value| {
            let mut tx = same.clone();
            if value.is_null() {
                tx.as_object_mut().unwrap().remove(field);
            } else {
                tx[field] = value;
            }
            difference(&Observed::of(&tx), &bound)
        };
        let sender = Some(Difference::Sender);
        let transaction = Some(Difference::Transaction);
        assert_eq!(
            changed("from", "0x3333333333333333333333333333333333333333".into()),
            sender
        );
        assert_eq!(changed("from", Value::Null), sender);
        assert_eq!(changed("from", "0x11".into()), sender);
        assert_eq!(
            changed("to", "0x3333333333333333333333333333333333333333".into()),
            transaction
        );
        assert_eq!(changed("to", Value::Null), transaction);
        assert_eq!(changed("value", "0x6".into()), transaction);
        assert_eq!(changed("value", "0xzz".into()), transaction);
        assert_eq!(changed("input", "0x010204".into()), transaction);
        assert_eq!(changed("input", "0x01020300".into()), transaction);
        assert_eq!(changed("input", "0x0102".into()), transaction);
        assert_eq!(changed("input", "0x01020".into()), transaction);
        assert_eq!(changed("chainId", "0x65".into()), transaction);
        assert_eq!(changed("chainId", Value::Null), transaction);
        assert_eq!(changed("chainId", "".into()), transaction);
        assert_eq!(difference(&Observed::of(&"0xabc".into()), &bound), sender);
        // A missing value is 0, and missing data is none.
        let empty = Fields::bound(
            &ADDRESS,
            &Payment {
                value: U256::ZERO,
                ..payment(Vec::new())
            },
        );
        let mut bare = same.clone();
        let map = bare.as_object_mut().unwrap();
        map.remove("value");
        map.remove("input");
        assert_eq!(difference(&Observed::of(&bare), &empty), None);
        assert_eq!(Difference::Sender.reason(), "wrong_account");
        assert_eq!(Difference::Transaction.reason(), "wrong_transaction");
    }

    /// The window: `answeredAt ≤ now < answeredAt + 24 h`.
    #[test]
    fn a_record_waits_a_day_of_the_wall_clock() {
        let at = 1_700_000_000_000;
        assert!(!within_window(at, at - 1));
        assert!(within_window(at, at));
        assert!(within_window(at, at + CHECK_WINDOW_MS - 1));
        assert!(!within_window(at, at + CHECK_WINDOW_MS));
        assert!(!within_window(u64::MAX - 5, 0));
        // Rechecks double from the first, up to 10 minutes, and never past
        // the window's end.
        assert_eq!(next_recheck_in(at, None, at, FIRST_RECHECK_MS), 5_000);
        assert_eq!(
            next_recheck_in(at, Some(5_000), at, FIRST_RECHECK_MS),
            10_000
        );
        assert_eq!(
            next_recheck_in(at, Some(400_000), at, FIRST_RECHECK_MS),
            MAX_RECHECK_MS
        );
        assert_eq!(
            next_recheck_in(at, Some(MAX_RECHECK_MS), at, FIRST_RECHECK_MS),
            MAX_RECHECK_MS
        );
        let late = at + CHECK_WINDOW_MS - 7;
        assert_eq!(next_recheck_in(at, Some(5_000), late, FIRST_RECHECK_MS), 7);
        assert_eq!(
            next_recheck_in(at, None, at + CHECK_WINDOW_MS + 1, FIRST_RECHECK_MS),
            0
        );
    }

    /// A payment's answer is a hash, exactly.
    #[test]
    fn a_payment_s_answer_is_a_hash() {
        let hash = format!("0x{}", "ab".repeat(32));
        assert_eq!(payment_hash(&hash.clone().into()), Some([0xab; 32]));
        assert_eq!(
            payment_hash(&hash.to_uppercase().replace("0X", "0x").into()),
            Some([0xab; 32])
        );
        for bad in [
            Value::from(format!("0x{}", "ab".repeat(31))),
            Value::from(format!("0x{}", "ab".repeat(33))),
            Value::from("ab".repeat(32)),
            Value::from(format!("0x{}zz", "ab".repeat(31))),
            Value::Null,
            serde_json::json!({ "hash": hash }),
        ] {
            assert_eq!(payment_hash(&bad), None, "{bad}");
        }
    }

    /// `errorOf` and `mapRemoteRpcError`, case by case.
    #[test]
    fn errors_map_as_the_bridge_maps_them() {
        let rpc = |code: i64| ErrorAnswer {
            rpc_code: Some(code),
            code: None,
            message: Some("phone says".into()),
        };
        let minted = |code: &str| ErrorAnswer {
            rpc_code: None,
            code: Some(code.into()),
            message: None,
        };
        let failed = |code: &'static str, message: Option<&str>| Mapped::Failed {
            code,
            message: message.map(str::to_owned),
        };
        for sent in [false, true] {
            assert_eq!(
                map_error(sent, &rpc(4001)),
                failed("REMOTE_USER_REJECTED", None)
            );
            assert_eq!(
                map_error(sent, &rpc(4100)),
                failed("REMOTE_WRONG_ACCOUNT", Some("phone says"))
            );
            assert_eq!(
                map_error(sent, &rpc(4200)),
                failed("REMOTE_UNSUPPORTED", Some("phone says"))
            );
        }
        // After `phone.sent`, anything else leaves a payment unknown.
        for error in [
            rpc(4002),
            rpc(-32603),
            rpc(4900),
            minted("REMOTE_TIMEOUT"),
            minted("REMOTE_USER_REJECTED"),
            minted("REMOTE_USER_CANCELLED"),
            ErrorAnswer::default(),
        ] {
            assert_eq!(map_error(true, &error), Mapped::Unknown, "{error:?}");
        }
        // Before it, or for a signature, they fail as coded.
        assert_eq!(
            map_error(false, &rpc(-32603)),
            failed("REMOTE_UNKNOWN", Some("phone says"))
        );
        assert_eq!(
            map_error(false, &minted("REMOTE_TIMEOUT")),
            failed("REMOTE_TIMEOUT", None)
        );
        assert_eq!(
            map_error(false, &minted("REMOTE_USER_CANCELLED")),
            failed("REMOTE_USER_CANCELLED", None)
        );
        assert_eq!(
            map_error(false, &minted("NOT_A_CODE")),
            failed("REMOTE_UNKNOWN", None)
        );
        assert_eq!(
            map_error(false, &ErrorAnswer::default()),
            failed("REMOTE_UNKNOWN", None)
        );
        let long = ErrorAnswer {
            message: Some("m".repeat(MAX_MESSAGE_BYTES + 1)),
            ..rpc(4100)
        };
        assert_eq!(
            map_error(false, &long),
            failed("REMOTE_WRONG_ACCOUNT", None)
        );
        let at = ErrorAnswer {
            message: Some("m".repeat(MAX_MESSAGE_BYTES)),
            ..rpc(4100)
        };
        assert!(matches!(
            map_error(false, &at),
            Mapped::Failed {
                message: Some(_),
                ..
            }
        ));
    }

    /// A job lives five minutes of the vault's clock, answers only its
    /// target, and is answered once.
    #[test]
    fn a_job_answers_its_target_once() {
        let mut jobs = PhoneJobs::new();
        let mut rng = rng();
        let opened = jobs
            .open(
                new_job(Binds::Message(b"hi".to_vec()), None, 9),
                1_000,
                &mut rng,
            )
            .unwrap();
        assert_eq!(opened.expires_in_ms, JOB_TTL_MS);
        assert_eq!(opened.method, "personal_sign");
        assert_eq!(
            opened.params,
            serde_json::json!(["0x6869", fc_evm::checksum_address(&ADDRESS)])
        );
        let id = opened.job;
        assert_eq!(JobId::parse(&id.text()), Some(id));
        assert_eq!(jobs.sent(&id, 8, 1_000), Err(Refusal::WrongSender));
        assert_eq!(
            jobs.answer(&id, 8, 1_000, false).err(),
            Some(Refusal::WrongSender)
        );
        jobs.sent(&id, 9, 1_000).unwrap();
        let taken = jobs.answer(&id, 9, 1_000 + JOB_TTL_MS - 1, false).unwrap();
        assert_eq!((taken.account, taken.extra, taken.sent), (3, 7, true));
        assert_eq!(
            jobs.answer(&id, 9, 1_001, false).err(),
            Some(Refusal::Settled)
        );
        assert_eq!(jobs.sent(&id, 9, 1_001), Err(Refusal::Settled));
        let unknown = JobId([0xee; 16]);
        assert_eq!(jobs.sent(&unknown, 9, 0), Err(Refusal::UnknownJob));
        // Expired at exactly its end; a payment marked sent then is unknown.
        let late = jobs
            .open(
                new_job(Binds::Payment(payment(vec![])), None, 9),
                0,
                &mut rng,
            )
            .unwrap()
            .job;
        let unsent = jobs
            .open(
                new_job(Binds::Payment(payment(vec![])), None, 9),
                0,
                &mut rng,
            )
            .unwrap()
            .job;
        jobs.sent(&late, 9, JOB_TTL_MS - 1).unwrap();
        assert_eq!(
            jobs.answer(&late, 9, JOB_TTL_MS, true).err(),
            Some(Refusal::Expired {
                outcome_unknown: true
            })
        );
        assert_eq!(
            jobs.sent(&unsent, 9, JOB_TTL_MS),
            Err(Refusal::Expired {
                outcome_unknown: false
            })
        );
        assert_eq!(jobs.slots_used(), 0);
        let signature = jobs
            .open(new_job(Binds::Message(vec![]), None, 9), 0, &mut rng)
            .unwrap()
            .job;
        jobs.sent(&signature, 9, 0).unwrap();
        assert_eq!(jobs.expire(JOB_TTL_MS), vec![signature]);
        assert_eq!(
            jobs.sent(&signature, 9, JOB_TTL_MS),
            Err(Refusal::Expired {
                outcome_unknown: false
            })
        );
        assert_eq!(Refusal::WrongSender.reason(), "wrong_sender");
        assert_eq!(Refusal::Settled.reason(), "settled");
        assert_eq!(Refusal::UnknownJob.reason(), "unknown_job");
        assert_eq!(
            Refusal::Expired {
                outcome_unknown: true
            }
            .reason(),
            "expired"
        );
        assert_eq!(
            jobs.open(new_job(Binds::Message(vec![]), None, 9), 0, &mut Failing)
                .err(),
            Some(OpenRefusal::Randomness)
        );
    }

    /// 256 slots, shared by open payment jobs, payments being read and
    /// records; each comes back as its job ends without a record or its
    /// record is dropped.
    #[test]
    fn payments_share_256_slots() {
        let mut jobs: PhoneJobs<u32> = PhoneJobs::new();
        let mut rng = rng();
        let mut open = Vec::new();
        for _ in 0..MAX_SLOTS {
            let job = new_job(Binds::Payment(payment(vec![])), None, 1);
            open.push(jobs.open(job, 0, &mut rng).unwrap().job);
        }
        let refused = jobs.open(
            new_job(Binds::Payment(payment(vec![])), None, 1),
            0,
            &mut rng,
        );
        assert_eq!(refused.err(), Some(OpenRefusal::Busy));
        assert_eq!(jobs.check_room(true, None, 0), Err(OpenRefusal::Busy));
        // A signature's job doesn't take a payment's slot.
        assert!(jobs.check_room(false, None, 0).is_ok());
        // An error ends a job without a record.
        jobs.answer(&open[0], 1, 0, false).unwrap();
        assert!(jobs.check_room(true, None, 0).is_ok());
        let again = jobs.open(
            new_job(Binds::Payment(payment(vec![])), None, 1),
            0,
            &mut rng,
        );
        assert!(again.is_ok());
        assert_eq!(jobs.check_room(true, None, 0), Err(OpenRefusal::Busy));
        // A hash's read holds the slot; a visible transaction frees it.
        jobs.answer(&open[1], 1, 0, true).unwrap();
        assert_eq!(jobs.slots_used(), MAX_SLOTS);
        jobs.release(&open[1]);
        assert_eq!(jobs.slots_used(), MAX_SLOTS - 1);
        // A record holds it until dropped.
        jobs.answer(&open[2], 1, 0, true).unwrap();
        jobs.record(Record {
            job: open[2],
            ..record(2, None)
        });
        assert_eq!(jobs.slots_used(), MAX_SLOTS - 1);
        assert_eq!(
            jobs.answer(&open[2], 1, 0, true).err(),
            Some(Refusal::Settled)
        );
        assert!(jobs.drop_record(&open[2]).is_some());
        assert!(jobs.drop_record(&open[2]).is_none());
        assert_eq!(jobs.slots_used(), MAX_SLOTS - 2);
        // A job cancelled before its reply frees its slot.
        jobs.cancel(&open[3]);
        assert_eq!(jobs.slots_used(), MAX_SLOTS - 3);
        // An expiry frees every open job's.
        jobs.expire(JOB_TTL_MS);
        assert_eq!(jobs.slots_used(), 0);
        jobs.load((0..=255u8).map(|job| record(job, None)).collect());
        assert_eq!(jobs.slots_used(), MAX_SLOTS);
        assert_eq!(jobs.check_room(true, None, 0), Err(OpenRefusal::Busy));
    }

    /// Signatures have places of their own.
    #[test]
    fn signature_jobs_are_bounded() {
        let mut jobs: PhoneJobs<u32> = PhoneJobs::new();
        let mut rng = rng();
        for _ in 0..MAX_SIGNATURE_JOBS {
            jobs.open(new_job(Binds::Message(vec![]), None, 1), 0, &mut rng)
                .unwrap();
        }
        assert_eq!(
            jobs.open(new_job(Binds::Message(vec![]), None, 1), 0, &mut rng)
                .err(),
            Some(OpenRefusal::Busy)
        );
        assert_eq!(jobs.slots_used(), 0);
        assert!(jobs.check_room(true, None, 0).is_ok());
    }

    /// A payment's site key: 2,048 bytes as written, escapes included, and
    /// not one more. A signature's job keeps no record, and takes any.
    #[test]
    fn a_payment_s_site_is_bounded_as_written() {
        let mut jobs: PhoneJobs<u32> = PhoneJobs::new();
        let mut rng = rng();
        let plain = "s".repeat(MAX_SITE_BYTES);
        let escaped = "\"".repeat(MAX_SITE_BYTES / 2);
        assert_eq!(written_len(&escaped), MAX_SITE_BYTES);
        assert_eq!(written_len("\u{1}"), 6);
        assert_eq!(written_len("é"), 2);
        for site in [&plain, &escaped] {
            let job = new_job(Binds::Payment(payment(vec![])), Some(site), 1);
            assert!(jobs.open(job, 0, &mut rng).is_ok());
            let long = format!("{site}x");
            let job = new_job(Binds::Payment(payment(vec![])), Some(&long), 1);
            assert_eq!(
                jobs.open(job, 0, &mut rng).err(),
                Some(OpenRefusal::SiteTooLong)
            );
            assert_eq!(
                jobs.check_room(true, Some(&long), 0),
                Err(OpenRefusal::SiteTooLong)
            );
            assert!(jobs.check_room(false, Some(&long), 0).is_ok());
        }
    }

    /// The requests relayed, as `signer.js` builds them.
    #[test]
    fn the_relayed_requests() {
        let (method, params) = request(
            &ADDRESS,
            &Binds::TypedData {
                hash: [0; 32],
                payload: "{\"x\":1}".into(),
            },
        );
        assert_eq!(method, "eth_signTypedData_v4");
        assert_eq!(
            params,
            serde_json::json!([fc_evm::checksum_address(&ADDRESS), "{\"x\":1}"])
        );
        let (method, params) = request(&ADDRESS, &Binds::Payment(payment(vec![0xab])));
        assert_eq!(method, "eth_sendTransaction");
        assert_eq!(
            params,
            serde_json::json!([{
                "from": fc_evm::checksum_address(&ADDRESS),
                "to": fc_evm::checksum_address(&TO),
                "value": "0x5",
                "chainId": "0x64",
                "data": "0xab",
            }])
        );
        assert_eq!(to_quantity(&U256::ZERO), "0x0");
        assert_eq!(to_quantity(&U256::from_u64(256)), "0x100");
        assert_eq!(to_quantity(&U256::MAX), format!("0x{}", "f".repeat(64)));
        assert_eq!(record_kind("dapp-send"), Some("dapp-send"));
        assert_eq!(record_kind("sign-message"), None);
    }
}
