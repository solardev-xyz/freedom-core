//! Phone jobs in the daemon (design 0012, "Phone jobs" and "Unverified
//! payments"; PHN-1). The decisions are `fc_approval::phone`'s; this module
//! wires them to the callers, the approvals, the chain thread, the clocks
//! and `phone-payments.json`.
//!
//! - **`phone.job { account, address, method, payload, authorization?,
//!   target }`:** `method` is `message`, `typed_data` or `transaction`, and
//!   `payload` is `sign.message`'s, `sign.typed_data`'s or
//!   `sign.transaction`'s params without the key (a transaction's nonce
//!   optional, as the phone picks its own). The authorization is checked as
//!   `sign.*` checks it, a presented token burnt however the request ends;
//!   a standing rule judges a send as a phone's. `address` is the phone
//!   account's, main's word (`vault-meta.json` is main's until PRF-6a). A
//!   payment's slot, and its site's bound, are checked before the
//!   authorization is spent. The reply is `{ job, expires_in_ms, request: {
//!   method, params } }`, the JSON-RPC request to relay.
//! - **`phone.sent { job, sender }`** → `{}`, and **`phone.result { job,
//!   sender, result | error }`**: only from the job's `target`. A
//!   signature's answer is checked at once. A payment's hash is read on the
//!   job's chain (`eth_getTransactionByHash`, through the chain thread)
//!   before the reply: visible and the same, `verified`; visible and
//!   different, refused with the transaction's fields; otherwise
//!   `unverified` once its record is saved, or `unknown` with `durable:
//!   false` if any stage of the save failed.
//! - **The records** live in `phone-payments.json`, beside the four
//!   permission files, written by 0001's single-file write. A start reads
//!   them (an unreadable file is renamed aside and `phone.lost` sent), ends
//!   each past its day as `unknown`, and rechecks the rest at once, then
//!   after 5 s, doubling up to 10 minutes. Each ends with one
//!   `phone.checked { job, outcome }`: `verified`, `mismatch` with the
//!   transaction's fields, or `unknown`.
//!
//! Everything runs inline on the event loop, as the approval methods do.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fc_approval::phone::{
    self, Authorized, Binds, ErrorAnswer, Fields, JobId, Mapped, Observed, OpenRefusal, Payment,
    PhoneJobs, Record, Refusal, Taken,
};
use fc_approval::standing::AccountKind;
use fc_evm::{Transaction, to_hex};
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::message::Context;
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::approvals::{After, Approvals, Clocks, Signed};
use crate::fsx::{self, Done};
use crate::grants::{self, Read as FileRead};
use crate::rng::OsRng;
use crate::vault::{Out, error_payload, event_payload};

/// The methods this module serves.
pub const METHODS: [&str; 3] = ["phone.job", "phone.sent", "phone.result"];

/// The file, in `grant_root`.
pub const FILE_NAME: &str = "phone-payments.json";

/// The test hooks' name for the file's writes.
const STORE: &str = "phone";

/// A payment's read, answer or recheck, has this long (*inferred*).
const READ_DEADLINE_MS: u64 = 20_000;

/// Rechecks in flight at once (*inferred*); the rest wait their turn.
const MAX_RECHECK_READS: usize = 16;

/// One of the core's own chain reads, for the chain thread.
pub struct ChainRead {
    pub tag: u64,
    pub chain_id: u64,
    pub method: &'static str,
    pub params: String,
    pub deadline_ms: u64,
}

/// A record's place in the recheck schedule.
struct Waiting {
    job: JobId,
    due: Instant,
    /// The last wait, for the doubling; `None` before the first.
    previous: Option<u64>,
    reading: bool,
}

/// A read in flight.
enum Pending {
    /// `phone.result`'s, before its reply.
    Answer {
        request: u64,
        taken: Box<Taken<After>>,
        hash: [u8; 32],
        fields: Fields,
        answered_at: u64,
    },
    /// A record's recheck.
    Recheck { job: JobId },
}

/// What a read found.
enum Lookup {
    Visible(Value),
    /// Not visible, or the read failed.
    NotVisible,
}

/// How a save of the file went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Saved {
    Durable,
    /// Any stage failed, the directory's flush included.
    NotDurable,
}

/// The phone jobs and the payments' records.
pub struct Phone {
    jobs: PhoneJobs<After>,
    path: Option<PathBuf>,
    waiting: Vec<Waiting>,
    reads: BTreeMap<u64, Pending>,
    next_tag: u64,
    events: Vec<Zeroizing<Vec<u8>>>,
    first_recheck_ms: u64,
}

impl Default for Phone {
    fn default() -> Self {
        Self::new()
    }
}

fn invalid(message: impl Into<String>) -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, message.into())
}

fn not_authorized(reason: &str, message: &str, extra: Option<(&str, Value)>) -> ErrorBody {
    let mut data = Map::new();
    data.insert("reason".into(), reason.into());
    if let Some((key, value)) = extra {
        data.insert(key.into(), value);
    }
    ErrorBody::new(ErrorCode::NotAuthorized, message).with_data(Value::Object(data))
}

fn refusal(refusal: Refusal) -> ErrorBody {
    match refusal {
        Refusal::UnknownJob => not_authorized(refusal.reason(), "no such phone job", None),
        Refusal::Settled => not_authorized(
            refusal.reason(),
            "this phone job was answered already",
            None,
        ),
        Refusal::Expired { outcome_unknown } => not_authorized(
            refusal.reason(),
            "this phone job timed out",
            outcome_unknown.then(|| ("outcome", json!("unknown"))),
        ),
        Refusal::WrongSender => not_authorized(
            refusal.reason(),
            "this phone job was sent to another window",
            None,
        ),
    }
}

/// The params object, with exactly the given members.
fn object<'a>(
    params: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>, ErrorBody> {
    let object = params
        .as_object()
        .ok_or_else(|| invalid("Invalid parameters"))?;
    if let Some(unknown) = object
        .keys()
        .find(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(invalid(format!(
            "unknown field {}",
            fc_evm::shortened(unknown)
        )));
    }
    if let Some(missing) = required.iter().find(|key| !object.contains_key(**key)) {
        return Err(invalid(format!("missing field {missing}")));
    }
    Ok(object)
}

fn string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, ErrorBody> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{field}: expected a string")))
}

/// A webContents id: a non-negative integer.
fn web_contents(object: &Map<String, Value>, field: &str) -> Result<u64, ErrorBody> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(format!("{field}: expected a webContents id")))
}

fn job_id(object: &Map<String, Value>) -> Result<JobId, ErrorBody> {
    JobId::parse(string(object, "job")?).ok_or_else(|| invalid("job: expected a job id"))
}

/// `phone.result`'s `error`: `{ rpc_code?, code?, message? }`.
fn error_answer(value: &Value) -> Result<ErrorAnswer, ErrorBody> {
    let fields = object(value, &[], &["rpc_code", "code", "message"])?;
    let rpc_code = match fields.get("rpc_code") {
        None => None,
        Some(code) => Some(
            code.as_i64()
                .ok_or_else(|| invalid("rpc_code: expected an integer"))?,
        ),
    };
    let text = |field: &str| match fields.get(field) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(invalid(format!("{field}: expected a string"))),
    };
    Ok(ErrorAnswer {
        rpc_code,
        code: text("code")?,
        message: text("message")?,
    })
}

fn reply<R: serde::Serialize>(id: u64, result: &R) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
    let mut payload = Zeroizing::new(Vec::with_capacity(256));
    fc_protocol::message::write_result(&mut *payload, id, result)
        .map_err(|_| crate::vault::internal())?;
    Ok(payload)
}

/// The typed data a phone signs: the core's view's `types`, `domain`,
/// `primary_type` and `message`, as ethers' `getPayload` gives them, under
/// `eth_signTypedData_v4`'s names, byte for byte as the view wrote them.
fn typed_payload(view: &str) -> Result<String, ErrorBody> {
    #[derive(Deserialize)]
    struct View<'a> {
        #[serde(borrow)]
        types: &'a RawValue,
        #[serde(borrow)]
        domain: &'a RawValue,
        #[serde(borrow)]
        primary_type: &'a RawValue,
        #[serde(borrow)]
        message: &'a RawValue,
    }
    let view: View<'_> = serde_json::from_str(view).map_err(|_| crate::vault::internal())?;
    Ok(format!(
        r#"{{"types":{},"domain":{},"primaryType":{},"message":{}}}"#,
        view.types.get(),
        view.domain.get(),
        view.primary_type.get(),
        view.message.get()
    ))
}

/// A job's transaction, read as `sign.transaction` reads one, its nonce
/// optional.
fn job_tx(value: &Value) -> Result<Transaction, ErrorBody> {
    let fields = value
        .as_object()
        .ok_or_else(|| invalid("tx: expected an object"))?;
    let parsed = if fields.contains_key("nonce") {
        Transaction::from_json(value)
    } else {
        let mut with_nonce = fields.clone();
        with_nonce.insert("nonce".into(), Value::String("0".into()));
        Transaction::from_json(&Value::Object(with_nonce))
    };
    parsed.map_err(|e| invalid(e.to_string()))
}

impl Phone {
    pub fn new() -> Self {
        Phone {
            jobs: PhoneJobs::new(),
            path: None,
            waiting: Vec::new(),
            reads: BTreeMap::new(),
            next_tag: 1,
            events: Vec::new(),
            first_recheck_ms: crate::testhooks::phone_recheck_ms(phone::FIRST_RECHECK_MS),
        }
    }

    pub fn handles(method: &str) -> bool {
        METHODS.contains(&method)
    }

    /// The events to send, after the reply that made them.
    pub fn take_events(&mut self) -> Vec<Zeroizing<Vec<u8>>> {
        std::mem::take(&mut self.events)
    }

    fn checked(&mut self, job: &JobId, outcome: &str, extra: Option<Value>) {
        let mut data = Map::new();
        data.insert("job".into(), job.text().into());
        data.insert("outcome".into(), outcome.into());
        if let Some(Value::Object(more)) = extra {
            data.extend(more);
        }
        self.events
            .push(event_payload("phone.checked", &Value::Object(data)));
    }

    /// The hello's `grant_root`: the file's leftover temp files removed and
    /// its records read. A file that can't be read is renamed aside and
    /// `phone.lost` sent once. Every record is due at once: the loop ticks
    /// before it handles anything after the hello, and [`Phone::tick`] ends
    /// a record past its day `unknown` before any read.
    pub fn configure(&mut self, root: PathBuf) {
        let path = root.join(FILE_NAME);
        self.path = Some(path.clone());
        if let Err(e) = fsx::remove_temps(&root, FILE_NAME) {
            crate::log::warn(
                "cannot remove the phone payments' temp files",
                json!({ "kind": e.kind().to_string() }),
            );
        }
        let records = match grants::read_file(&path, phone::MAX_FILE_BYTES) {
            FileRead::Missing => Ok(Vec::new()),
            FileRead::Bytes(bytes) => phone::read_file(&bytes).map_err(|_| ()),
            FileRead::Unreadable => Err(()),
        };
        let records = match records {
            Ok(records) => records,
            Err(()) => {
                let aside = root.join(format!("{FILE_NAME}.unreadable"));
                let renamed = std::fs::rename(&path, &aside)
                    .map(|()| fsx::flushed(fsx::sync_rename(&root, &aside)) == Done::Durable);
                crate::log::warn(
                    "the phone payments' file can't be read: renamed aside, its payments unknown",
                    json!({ "renamed": renamed.is_ok() }),
                );
                self.events.push(event_payload("phone.lost", &json!({})));
                Vec::new()
            }
        };
        self.jobs.load(records);
        let now = Instant::now();
        self.waiting = self
            .jobs
            .records()
            .iter()
            .map(|record| Waiting {
                job: record.job,
                due: now,
                previous: None,
                reading: false,
            })
            .collect();
    }

    /// Writes every record, the unsaved ones included.
    fn save(&mut self) -> Saved {
        let Some(path) = self.path.clone() else {
            return Saved::NotDurable;
        };
        let text = phone::file_text(self.jobs.records());
        match grants::write_file(&path, STORE, &text) {
            Ok(Done::Durable) => Saved::Durable,
            Ok(Done::NotDurable) => {
                crate::log::warn("the phone payments' file isn't flushed", json!({}));
                Saved::NotDurable
            }
            Err(e) => {
                crate::log::error(
                    "the phone payments' write failed",
                    json!({ "kind": e.kind().to_string() }),
                );
                Saved::NotDurable
            }
        }
    }

    /// Handles one of [`METHODS`].
    pub fn request(
        &mut self,
        id: u64,
        method: &str,
        raw: Option<&str>,
        context: &Context,
        approvals: &mut Approvals,
        clocks: Clocks,
    ) -> Vec<Out> {
        let mut out = Vec::new();
        // Numbers as JSON.parse reads them, as `sign.*` parses them (#87).
        let params = match fc_evm::parse_json(raw.unwrap_or("{}")) {
            Ok(params) => params,
            Err(_) => {
                out.push(Out::Send(error_payload(id, &invalid("Invalid parameters"))));
                return out;
            }
        };
        let result = match method {
            "phone.job" => {
                // A presented token is burnt however the request ends.
                let presented = crate::approvals::presented_token(&params, true);
                let result = self.job(id, &params, context, approvals, clocks);
                if let Some(token) = presented {
                    approvals.burn(&token);
                }
                result.map(Some)
            }
            "phone.sent" => self.sent(id, &params, context, clocks).map(Some),
            "phone.result" => self.result(id, &params, context, approvals, clocks, &mut out),
            _ => Err(invalid("unknown method")),
        };
        match result {
            Ok(Some(payload)) => out.push(Out::Send(payload)),
            // The reply follows the answer's read.
            Ok(None) => {}
            Err(error) => out.push(Out::Send(error_payload(id, &error))),
        }
        out
    }

    fn job(
        &mut self,
        id: u64,
        params: &Value,
        context: &Context,
        approvals: &mut Approvals,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let page = crate::approvals::page_context(context)?;
        let fields = object(
            params,
            &["account", "address", "method", "payload", "target"],
            &["authorization"],
        )?;
        let account = fields
            .get("account")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n <= fc_approval::MAX_ACCOUNT)
            .ok_or_else(|| invalid("account: index out of range"))?;
        let address = fc_evm::parse_address(string(fields, "address")?)
            .map_err(|e| invalid(e.to_string()))?;
        let target = web_contents(fields, "target")?;
        let payload = &fields["payload"];
        let site = page.map(|page| page.origin.clone());
        let message;
        let payload_fields;
        let typed;
        let tx;
        let (binds, signed) = match string(fields, "method")? {
            "message" => {
                payload_fields = object(payload, &["message"], &[])?;
                message = fc_evm::parse_bytes(string(payload_fields, "message")?, "message")
                    .map_err(|e| invalid(e.to_string()))?;
                (
                    Binds::Message(message.clone()),
                    Signed::Message {
                        account,
                        message: &payload_fields["message"],
                    },
                )
            }
            "typed_data" => {
                payload_fields = object(
                    payload,
                    &["typed_data", "expected_hash"],
                    &["primary_type", "chain_id"],
                )?;
                let expected: [u8; 32] =
                    fc_evm::parse_bytes(string(payload_fields, "expected_hash")?, "expected_hash")
                        .map_err(|e| invalid(e.to_string()))?
                        .try_into()
                        .map_err(|_| invalid("expected_hash: expected 32 bytes"))?;
                typed = crate::signing::typed_data_view(payload_fields)?;
                // The digest the user confirmed, or nothing.
                if typed.hash != expected {
                    return Err(invalid(
                        "typed data hash is not the confirmed one (expected_hash)",
                    ));
                }
                (
                    Binds::TypedData {
                        hash: typed.hash,
                        payload: typed_payload(&typed.view)?,
                    },
                    Signed::TypedData {
                        account,
                        fields: payload_fields,
                        hash: &typed.hash,
                        view: &typed,
                    },
                )
            }
            "transaction" => {
                payload_fields = object(payload, &["tx"], &[])?;
                tx = job_tx(&payload_fields["tx"])?;
                // A creation could never be the one confirmed: the phone
                // would send it, and it would never check (*inferred*).
                let to = *tx
                    .to()
                    .ok_or_else(|| invalid("tx: a phone payment needs its to"))?;
                let chain_id = tx
                    .chain_id()
                    .to_u64()
                    .filter(|n| *n <= fc_approval::MAX_CHAIN_ID)
                    .ok_or_else(|| invalid("tx: invalid chain_id"))?;
                (
                    Binds::Payment(Payment {
                        chain_id,
                        to,
                        value: *tx.value(),
                        data: tx.data().to_vec(),
                    }),
                    Signed::Transaction {
                        account,
                        tx_json: &payload_fields["tx"],
                        tx: &tx,
                    },
                )
            }
            _ => {
                return Err(invalid(
                    "method: expected message, typed_data or transaction",
                ));
            }
        };
        let payment = matches!(binds, Binds::Payment(_));
        // Room first: a refused job spends no authorization.
        self.jobs
            .check_room(payment, site.as_deref(), clocks.vault_ms)
            .map_err(open_refusal)?;
        let (after, kind) = match fields.get("authorization") {
            None => crate::approvals::without_authorization(context, &signed)
                .map(|()| (After::Nothing, "none"))?,
            Some(authorization) => approvals.authorize_for(
                context,
                authorization,
                signed,
                clocks,
                AccountKind::Phone,
            )?,
        };
        let kind = match binds {
            // A payment's record names it; a signature's job keeps none.
            Binds::Payment(_) => phone::record_kind(kind).unwrap_or("none"),
            _ => kind,
        };
        let opened = self
            .jobs
            .open(
                phone::NewJob {
                    account,
                    address,
                    target,
                    binds,
                    authorized: Authorized { kind, site },
                    extra: after,
                },
                clocks.vault_ms,
                &mut OsRng,
            )
            .map_err(open_refusal)?;
        let payload = reply(
            id,
            &json!({
                "job": opened.job.text(),
                "expires_in_ms": opened.expires_in_ms,
                "request": { "method": opened.method, "params": opened.params },
            }),
        );
        match payload {
            Ok(payload) if payload.len() <= fc_protocol::frame::MAX_PAYLOAD => Ok(payload),
            _ => {
                self.jobs.cancel(&opened.job);
                Err(invalid("the request is too large to relay"))
            }
        }
    }

    fn sent(
        &mut self,
        id: u64,
        params: &Value,
        context: &Context,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        crate::approvals::page_context(context)?;
        let fields = object(params, &["job", "sender"], &[])?;
        let job = job_id(fields)?;
        let sender = web_contents(fields, "sender")?;
        self.jobs
            .sent(&job, sender, clocks.vault_ms)
            .map_err(refusal)?;
        reply(id, &json!({}))
    }

    fn result(
        &mut self,
        id: u64,
        params: &Value,
        context: &Context,
        approvals: &mut Approvals,
        clocks: Clocks,
        out: &mut Vec<Out>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ErrorBody> {
        crate::approvals::page_context(context)?;
        let fields = object(params, &["job", "sender"], &["result", "error"])?;
        let job = job_id(fields)?;
        let sender = web_contents(fields, "sender")?;
        let answer = match (fields.get("result"), fields.get("error")) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(error_answer(error)?),
            _ => return Err(invalid("expected one of result and error")),
        };
        let hash = answer
            .as_ref()
            .ok()
            .and_then(|result| phone::payment_hash(result));
        let taken = self
            .jobs
            .answer(&job, sender, clocks.vault_ms, hash.is_some())
            .map_err(refusal)?;
        let digest = match &taken.binds {
            Binds::Message(bytes) => Some(fc_evm::eip191_digest(bytes)),
            Binds::TypedData { hash, .. } => Some(*hash),
            Binds::Payment(_) => None,
        };
        if let Some(digest) = digest {
            return match answer {
                Err(error) => failed(id, &phone::map_error(false, &error)).map(Some),
                Ok(result) => {
                    let signature = phone::check_signature(result, &digest, &taken.address)
                        .map_err(|refused| {
                            not_authorized(
                                refused.reason(),
                                "the phone's signature is refused",
                                None,
                            )
                        })?
                        .to_owned();
                    let _ = approvals.signed(taken.extra, clocks);
                    reply(id, &json!({ "signature": signature })).map(Some)
                }
            };
        }
        let Binds::Payment(payment) = &taken.binds else {
            return Err(crate::vault::internal());
        };
        if let Err(error) = answer {
            return failed(id, &phone::map_error(taken.sent, &error)).map(Some);
        }
        // An answer that isn't a hash is the phone's all the same: the
        // payment may have gone.
        let Some(hash) = hash else {
            return reply(id, &json!({ "outcome": "unknown" })).map(Some);
        };
        let fields = Fields::bound(&taken.address, payment);
        let chain_id = payment.chain_id;
        let tag = self.tag();
        self.reads.insert(
            tag,
            Pending::Answer {
                request: id,
                taken: Box::new(taken),
                hash,
                fields,
                answered_at: clocks.wall_ms,
            },
        );
        out.push(read(tag, chain_id, &hash));
        Ok(None)
    }

    fn tag(&mut self) -> u64 {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1).max(1);
        tag
    }

    /// The chain thread's reply to read `tag` (its whole payload).
    pub fn chain_read(
        &mut self,
        tag: u64,
        payload: &[u8],
        approvals: &mut Approvals,
        clocks: Clocks,
    ) -> Vec<Out> {
        let mut out = Vec::new();
        let Some(pending) = self.reads.remove(&tag) else {
            return out;
        };
        let lookup = lookup(payload);
        match pending {
            Pending::Answer {
                request,
                taken,
                hash,
                fields,
                answered_at,
            } => {
                let reply =
                    self.answered(*taken, hash, fields, answered_at, lookup, approvals, clocks);
                out.push(Out::Send(
                    match reply.and_then(|result| self::reply(request, &result)) {
                        Ok(payload) => payload,
                        Err(error) => error_payload(request, &error),
                    },
                ));
            }
            Pending::Recheck { job } => self.rechecked(job, lookup, clocks),
        }
        out
    }

    /// A payment's answer, read: its reply.
    #[allow(clippy::too_many_arguments)]
    fn answered(
        &mut self,
        taken: Taken<After>,
        hash: [u8; 32],
        fields: Fields,
        answered_at: u64,
        lookup: Lookup,
        approvals: &mut Approvals,
        clocks: Clocks,
    ) -> Result<Value, ErrorBody> {
        let hash_text = to_hex(&hash);
        if let Lookup::Visible(tx) = lookup {
            self.jobs.release(&taken.id);
            let seen = Observed::of(&tx);
            if let Some(difference) = phone::difference(&seen, &fields) {
                return Err(not_authorized(
                    difference.reason(),
                    "the phone sent another transaction than the one confirmed",
                    Some(("transaction", seen.to_json())),
                ));
            }
            let mut result = json!({ "outcome": "verified", "hash": hash_text });
            if let Some(rule) = approvals.signed(taken.extra, clocks) {
                result["rule"] = rule;
            }
            return Ok(result);
        }
        let record = Record {
            job: taken.id,
            hash,
            account: taken.account,
            fields,
            kind: taken.authorized.kind.to_owned(),
            site: taken.authorized.site.clone(),
            answered_at,
        };
        self.jobs.record(record);
        let saved = self.save();
        self.waiting.push(Waiting {
            job: taken.id,
            due: Instant::now() + Duration::from_millis(self.first_recheck_ms),
            previous: Some(self.first_recheck_ms),
            reading: false,
        });
        let mut result = match saved {
            Saved::Durable => json!({ "outcome": "unverified", "hash": hash_text }),
            Saved::NotDurable => {
                json!({ "outcome": "unknown", "hash": hash_text, "durable": false })
            }
        };
        if let Some(rule) = approvals.signed(taken.extra, clocks) {
            result["rule"] = rule;
        }
        Ok(result)
    }

    /// A record's recheck, read.
    fn rechecked(&mut self, job: JobId, lookup: Lookup, clocks: Clocks) {
        let Some(index) = self.waiting.iter().position(|w| w.job == job) else {
            return;
        };
        let Some(record) = self.jobs.records().iter().find(|r| r.job == job).cloned() else {
            self.waiting.remove(index);
            return;
        };
        match lookup {
            Lookup::Visible(tx) => {
                self.waiting.remove(index);
                self.jobs.drop_record(&job);
                let seen = Observed::of(&tx);
                match phone::difference(&seen, &record.fields) {
                    None => self.checked(&job, "verified", None),
                    Some(difference) => self.checked(
                        &job,
                        "mismatch",
                        Some(json!({
                            "reason": difference.reason(),
                            "transaction": seen.to_json(),
                        })),
                    ),
                }
                self.save();
            }
            Lookup::NotVisible => {
                let waiting = &mut self.waiting[index];
                let wait = phone::next_recheck_in(
                    record.answered_at,
                    waiting.previous,
                    clocks.wall_ms,
                    self.first_recheck_ms,
                );
                waiting.previous = Some(wait);
                waiting.due = Instant::now() + Duration::from_millis(wait);
                waiting.reading = false;
            }
        }
    }

    /// The rechecks due at `now`: each record's age first, on the wall
    /// clock, then its read.
    pub fn tick(&mut self, now: Instant, clocks: Clocks) -> Vec<Out> {
        let mut out = Vec::new();
        let mut ended = Vec::new();
        let mut reading = self.waiting.iter().filter(|w| w.reading).count();
        for index in 0..self.waiting.len() {
            let waiting = &self.waiting[index];
            if waiting.reading || waiting.due > now {
                continue;
            }
            let job = waiting.job;
            let Some(record) = self.jobs.records().iter().find(|r| r.job == job) else {
                ended.push((job, false));
                continue;
            };
            if !phone::within_window(record.answered_at, clocks.wall_ms) {
                ended.push((job, true));
                continue;
            }
            if reading >= MAX_RECHECK_READS {
                continue;
            }
            let Some(chain_id) = record.fields.chain_id.parse::<u64>().ok() else {
                ended.push((job, true));
                continue;
            };
            let hash = record.hash;
            let tag = self.tag();
            self.reads.insert(tag, Pending::Recheck { job });
            self.waiting[index].reading = true;
            reading += 1;
            out.push(read(tag, chain_id, &hash));
        }
        if !ended.is_empty() {
            for (job, report) in &ended {
                self.waiting.retain(|w| w.job != *job);
                if self.jobs.drop_record(job).is_some() && *report {
                    self.checked(job, "unknown", None);
                }
            }
            self.save();
        }
        out
    }

    /// When the loop must wake for this module: now while events wait,
    /// else the first recheck due that may start.
    pub fn next_wakeup(&self) -> Option<Instant> {
        if !self.events.is_empty() {
            return Some(Instant::now());
        }
        let reading = self.waiting.iter().filter(|w| w.reading).count();
        if reading >= MAX_RECHECK_READS {
            return None;
        }
        self.waiting
            .iter()
            .filter(|w| !w.reading)
            .map(|w| w.due)
            .min()
    }
}

fn open_refusal(refusal: OpenRefusal) -> ErrorBody {
    match refusal {
        OpenRefusal::Busy => ErrorBody::new(ErrorCode::Busy, "too many phone jobs are open"),
        OpenRefusal::SiteTooLong => invalid("the site key is too long for a phone payment"),
        OpenRefusal::Randomness => crate::vault::internal(),
    }
}

/// An error's reply: `{ outcome: "unknown" }`, or `{ outcome: "failed",
/// code, message? }`.
fn failed(id: u64, mapped: &Mapped) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
    match mapped {
        Mapped::Unknown => reply(id, &json!({ "outcome": "unknown" })),
        Mapped::Failed { code, message } => {
            let mut result = json!({ "outcome": "failed", "code": code });
            if let Some(message) = message {
                result["message"] = json!(message);
            }
            reply(id, &result)
        }
    }
}

fn read(tag: u64, chain_id: u64, hash: &[u8; 32]) -> Out {
    Out::ChainRead(ChainRead {
        tag,
        chain_id,
        method: "eth_getTransactionByHash",
        params: format!(r#"["{}"]"#, to_hex(hash)),
        deadline_ms: READ_DEADLINE_MS,
    })
}

/// What a read's reply says: the transaction (`chain.request`'s
/// `result.result`), or nothing for a null one, a missing one or an error.
fn lookup(payload: &[u8]) -> Lookup {
    let Ok(response) = serde_json::from_slice::<Value>(payload) else {
        return Lookup::NotVisible;
    };
    match response
        .get("result")
        .and_then(|result| result.get("result"))
    {
        None | Some(Value::Null) => Lookup::NotVisible,
        Some(tx) => Lookup::Visible(tx.clone()),
    }
}
