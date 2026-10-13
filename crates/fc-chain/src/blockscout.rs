//! Blockscout's Gnosis log index (design 0005, Logs): the pure parts of
//! `blockscout-logs.js`, for the Ant profile's xBZZ Transfer scans.
//! - [`log_index_filter`]: the scans Blockscout can answer.
//! - [`canonical_log`], [`rpc_transfer_log_well_formed`], [`rpc_transfer`],
//!   [`blockscout_transfer`]: an RPC's entries and Blockscout's items as
//!   transfers, compared field by field ([`logs_agree`]); the RPC's
//!   entries cut to those fields are the answer ([`agreed_rpc_logs`]).
//! - [`TransferScan`]: Blockscout's pages back from the newest, as a
//!   machine fed one page at a time ([`PageReply`]), with the page's
//!   status, size and cooldown checks ([`cooldown_from`]).
//!
//! Main keeps the network policy: the endpoint's URL, redirects (each hop
//! on https, never to a local address, at most three) and the DNS check.
//! The page's deadline is the caller's.

use std::collections::HashMap;

use fc_json::index::{Index, KeyOrder, Kind, Value};

use crate::answer::decode_text;
use crate::bigint::{BigInt, Parsed, parse_string};
use crate::js::{is_safe_integer, string_to_number};
use crate::logs::block_number_value;
use crate::pattern::{JsPattern, MatchText};

/// The one chain with a log index: Gnosis.
pub const LOG_INDEX_CHAIN_ID: u64 = 100;

/// The token whose Transfer logs Ant scans: xBZZ on Gnosis.
pub const LOG_INDEX_TOKEN: &str = "0xdbf3ea6f5bee45c02255b2c26a16f300502f68da";

/// `Transfer(address,address,uint256)`.
pub const ERC20_TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// The most pages one scan reads (50 transfers each).
pub const BLOCKSCOUT_MAX_PAGES: usize = 40;

/// A page's cap: by `Content-Length` in bytes, and by its decoded text in
/// UTF-16 code units.
pub const MAX_PAGE_SIZE: usize = 8 * 1024 * 1024;

/// How long a throttled Blockscout is left alone when it names no reset.
pub const RATE_LIMIT_COOLDOWN_MS: f64 = 5.0 * 60_000.0;

/// The bounds on a cooldown Blockscout names, and the cooldown of a failure
/// that names none.
pub const MIN_COOLDOWN_MS: f64 = 60_000.0;
pub const MAX_COOLDOWN_MS: f64 = 15.0 * 60_000.0;

/// The newest blocks of a scan the quorum reads instead (at most what it
/// can verify).
pub const LOG_INDEX_TAIL_BLOCKS: u64 = 1000;

/// How long Blockscout is left alone after disagreeing with the RPC.
pub const LOG_INDEX_DISAGREEMENT_COOLDOWN_MS: u64 = 5 * 60_000;

/// How long it is left alone after the caller gave up while it was reading.
pub const LOG_INDEX_ABORT_COOLDOWN_MS: u64 = 60_000;

/// How long an RPC endpoint is no pair after a malformed entry.
pub const LOG_INDEX_PAIR_MALFORMED_COOLDOWN_MS: u64 = 30 * 60_000;

/// Whom a scan is about. A filter names a sender, a recipient or both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Party {
    Sender(String),
    Recipient(String),
    Both { sender: String, recipient: String },
}

impl Party {
    pub fn sender(&self) -> Option<&str> {
        match self {
            Self::Sender(sender) | Self::Both { sender, .. } => Some(sender),
            Self::Recipient(_) => None,
        }
    }

    pub fn recipient(&self) -> Option<&str> {
        match self {
            Self::Recipient(recipient) | Self::Both { recipient, .. } => Some(recipient),
            Self::Sender(_) => None,
        }
    }
}

/// An xBZZ Transfer scan Blockscout can answer (`logIndexFilter`). Address
/// topics are lowercase and zero-padded, as `eth_getLogs` carries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogIndexFilter {
    pub chain_id: u64,
    pub party: Party,
    pub from_block: u64,
    pub to_block: u64,
}

impl LogIndexFilter {
    /// `JSON.stringify(filter)`, as the reference builds it.
    pub fn to_json(&self) -> String {
        let topic = |t: Option<&str>| t.map_or("null".to_owned(), |t| format!("\"{t}\""));
        format!(
            r#"{{"chainId":{},"token":"{LOG_INDEX_TOKEN}","sender":{},"recipient":{},"fromBlock":{},"toBlock":{}}}"#,
            self.chain_id,
            topic(self.party.sender()),
            topic(self.party.recipient()),
            self.from_block,
            self.to_block
        )
    }
}

/// The filter of an `eth_getLogs` request whose `params` (JSON) are exactly
/// `[{ address, topics, fromBlock, toBlock }]` on chain 100: the xBZZ
/// token, `[Transfer, sender]`, `[Transfer, null, recipient]` or
/// `[Transfer, sender, recipient]` with zero-padded address topics, and a
/// numeric range.
pub fn log_index_filter(chain_id: u64, params: &str) -> Option<LogIndexFilter> {
    if chain_id != LOG_INDEX_CHAIN_ID {
        return None;
    }
    let index = Index::new(params).ok()?;
    let params = index.root();
    if params.kind() != Kind::Array || params.children().count() != 1 {
        return None;
    }
    let filter = params.children().next()?;
    if filter.kind() != Kind::Object {
        return None;
    }
    let allowed = ["address", "fromBlock", "toBlock", "topics"];
    if filter
        .members()
        .any(|(key, _)| !allowed.iter().any(|name| key.is_str(name)))
    {
        return None;
    }
    if !filter
        .get("address")
        .is_some_and(|a| lowercase_is(a, LOG_INDEX_TOKEN))
    {
        return None;
    }
    let topics = filter.get("topics").filter(|t| t.kind() == Kind::Array)?;
    let topics: Vec<Value<'_, '_>> = topics.children().collect();
    if !(2..=3).contains(&topics.len())
        || !topics
            .first()
            .is_some_and(|t| lowercase_is(*t, ERC20_TRANSFER_TOPIC))
    {
        return None;
    }
    // `null` or absent: none; an address topic: it; anything else: refused.
    let address_topic = |topic: Option<&Value<'_, '_>>| -> Result<Option<String>, ()> {
        match topic {
            None => Ok(None),
            Some(topic) if topic.kind() == Kind::Null => Ok(None),
            Some(topic) => address_topic(*topic).map(Some).ok_or(()),
        }
    };
    let sender = address_topic(topics.get(1)).ok()?;
    let recipient = address_topic(topics.get(2)).ok()?;
    let party = match (sender, recipient) {
        (Some(sender), Some(recipient)) => Party::Both { sender, recipient },
        (Some(sender), None) => Party::Sender(sender),
        (None, Some(recipient)) => Party::Recipient(recipient),
        (None, None) => return None,
    };
    let from_block = block_number_value(filter.get("fromBlock"))?;
    let to_block = block_number_value(filter.get("toBlock"))?;
    (to_block >= from_block).then_some(LogIndexFilter {
        chain_id,
        party,
        from_block,
        to_block,
    })
}

/// `value.toLowerCase() === target` for a string value and an ASCII target
/// of hex digits and `x`: only ASCII letters lowercase to those (U+212A
/// becomes `k` and U+0130 `i`, neither in a target).
fn lowercase_is(value: Value<'_, '_>, target: &str) -> bool {
    value.kind() == Kind::String
        && value
            .units()
            .map(|unit| u8::try_from(unit).ok().map(|b| b.to_ascii_lowercase()))
            .eq(target.bytes().map(Some))
}

/// A string value's ASCII text, lowercased, when it is `0x` (any case) and
/// hex digits that `digits` accepts by count.
fn hex(value: Value<'_, '_>, digits: impl Fn(usize) -> bool) -> Option<String> {
    if value.kind() != Kind::String {
        return None;
    }
    let text: String = value
        .units()
        .map(|unit| u8::try_from(unit).ok().filter(u8::is_ascii).map(char::from))
        .collect::<Option<String>>()?;
    let rest = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    (digits(rest.len()) && rest.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| format!("0x{}", rest.to_ascii_lowercase()))
}

fn hash32(value: Option<Value<'_, '_>>) -> Option<String> {
    hex(value?, |n| n == 64)
}

fn address_of(value: Option<Value<'_, '_>>) -> Option<String> {
    hex(value?, |n| n == 40)
}

fn hex_data(value: Option<Value<'_, '_>>) -> Option<String> {
    hex(value?, |n| n % 2 == 0)
}

/// `/^0x0{24}[0-9a-f]{40}$/i`, lowercased.
fn address_topic(value: Value<'_, '_>) -> Option<String> {
    hash32(Some(value)).filter(|topic| {
        topic
            .get(2..26)
            .is_some_and(|z| z.bytes().all(|b| b == b'0'))
    })
}

/// Blockscout's `quantity`: `0x` and hex digits, without leading zeros.
fn quantity(value: Option<Value<'_, '_>>) -> Option<String> {
    let text = hex(value?, |n| n > 0)?;
    let digits = text.get(2..)?.trim_start_matches('0');
    Some(format!(
        "0x{}",
        if digits.is_empty() { "0" } else { digits }
    ))
}

/// An `eth_getLogs` entry in one spelling (`canonicalLog`): lowercase hex,
/// quantities without leading zeros, no trailing `null` topics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_number: String,
    pub transaction_hash: String,
    pub transaction_index: String,
    pub log_index: String,
}

impl CanonicalLog {
    /// `JSON.stringify(log)`.
    pub fn to_json(&self) -> String {
        let topics: Vec<String> = self.topics.iter().map(|t| format!("\"{t}\"")).collect();
        format!(
            r#"{{"address":"{}","topics":[{}],"data":"{}","blockNumber":"{}","transactionHash":"{}","transactionIndex":"{}","logIndex":"{}"}}"#,
            self.address,
            topics.join(","),
            self.data,
            self.block_number,
            self.transaction_hash,
            self.transaction_index,
            self.log_index
        )
    }
}

/// `canonicalLog(entry)`: `None` for an entry that isn't an object, was
/// removed, or has a field out of shape.
pub fn canonical_log(entry: Value<'_, '_>) -> Option<CanonicalLog> {
    if !matches!(entry.kind(), Kind::Object | Kind::Array)
        || entry.get("removed").is_some_and(|r| r.kind() == Kind::True)
    {
        return None;
    }
    let address = address_of(entry.get("address"));
    let topics = entry.get("topics").filter(|t| t.kind() == Kind::Array)?;
    let mut topics: Vec<Value<'_, '_>> = topics.children().collect();
    while topics.last().is_some_and(|t| t.kind() == Kind::Null) {
        topics.pop();
    }
    let topics: Option<Vec<String>> = topics.into_iter().map(|t| hash32(Some(t))).collect();
    Some(CanonicalLog {
        address: address?,
        topics: topics?,
        data: hex_data(entry.get("data"))?,
        block_number: quantity(entry.get("blockNumber"))?,
        transaction_hash: hash32(entry.get("transactionHash"))?,
        transaction_index: quantity(entry.get("transactionIndex"))?,
        log_index: quantity(entry.get("logIndex"))?,
    })
}

/// `rpcTransferLogWellFormed(entry)`: the exact shape Ant reads, as the RPC
/// sent it: a 32-byte block hash, a value of one 32-byte word, topics that
/// are all 32-byte hashes with the address ones zero-padded, and
/// [`canonical_log`]'s fields.
pub fn rpc_transfer_log_well_formed(entry: Value<'_, '_>) -> bool {
    // The value: exactly one 32-byte word.
    let value_word = entry.get("data").and_then(|data| hex(data, |n| n == 64));
    if !matches!(entry.kind(), Kind::Object | Kind::Array)
        || hash32(entry.get("blockHash")).is_none()
        || value_word.is_none()
    {
        return false;
    }
    let Some(topics) = entry.get("topics").filter(|t| t.kind() == Kind::Array) else {
        return false;
    };
    let topics: Vec<Value<'_, '_>> = topics.children().collect();
    topics.iter().all(|t| hash32(Some(*t)).is_some())
        && topics
            .iter()
            .skip(1)
            .take(2)
            .all(|t| address_topic(*t).is_some())
        && canonical_log(entry).is_some()
}

/// Whether an RPC's `eth_getLogs` answer is a list of well-formed entries.
pub fn rpc_transfer_logs_well_formed(result: Value<'_, '_>) -> bool {
    result.kind() == Kind::Array && result.children().all(rpc_transfer_log_well_formed)
}

/// A transfer, the form both providers' answers are compared in: lowercase
/// hex, the block number and log index as numbers (`None` is `null`: an
/// RPC's number beyond a safe integer), the parties as zero-padded topics,
/// the value in decimal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub address: String,
    pub block_number: Option<u64>,
    pub block_hash: String,
    pub transaction_hash: String,
    pub log_index: Option<u64>,
    pub from: String,
    pub to: String,
    pub value: String,
}

impl Transfer {
    /// `JSON.stringify(transfer)`.
    pub fn to_json(&self) -> String {
        let number = |n: Option<u64>| n.map_or("null".to_owned(), |n| n.to_string());
        format!(
            r#"{{"address":"{}","blockNumber":{},"blockHash":"{}","transactionHash":"{}","logIndex":{},"from":"{}","to":"{}","value":"{}"}}"#,
            self.address,
            number(self.block_number),
            self.block_hash,
            self.transaction_hash,
            number(self.log_index),
            self.from,
            self.to,
            self.value
        )
    }
}

/// A list of transfers as JSON.
pub fn transfers_json(transfers: &[Transfer]) -> String {
    let items: Vec<String> = transfers.iter().map(Transfer::to_json).collect();
    format!("[{}]", items.join(","))
}

/// `rpcTransfer(entry)`: a well-formed Transfer log with a sender and a
/// recipient topic.
pub fn rpc_transfer(entry: Value<'_, '_>) -> Option<Transfer> {
    if !rpc_transfer_log_well_formed(entry) {
        return None;
    }
    let log = canonical_log(entry)?;
    if log.topics.len() != 3 || log.topics.first()? != ERC20_TRANSFER_TOPIC {
        return None;
    }
    let value = match parse_string(&log.data.encode_utf16().collect::<Vec<_>>())? {
        Parsed::Value(value) => BigInt::to_decimal(&value),
        Parsed::TooWide { .. } => return None,
    };
    let number = |text: &str| crate::logs::block_number_of(text.encode_utf16());
    Some(Transfer {
        block_number: number(&log.block_number),
        block_hash: hash32(entry.get("blockHash"))?,
        log_index: number(&log.log_index),
        from: log.topics.get(1)?.clone(),
        to: log.topics.get(2)?.clone(),
        transaction_hash: log.transaction_hash,
        address: log.address,
        value,
    })
}

/// `blockscoutTransfer(item)`: an ERC-20 item of Blockscout's
/// token-transfer list, every field from Blockscout's own answer.
pub fn blockscout_transfer(item: Value<'_, '_>) -> Option<Transfer> {
    if !matches!(item.kind(), Kind::Object | Kind::Array)
        || !item.get("token_type").is_some_and(|t| t.is_str("ERC-20"))
    {
        return None;
    }
    let topic_of = |party: Option<Value<'_, '_>>| {
        address_of(party?.get("hash"))
            .map(|address| format!("0x{}{}", "0".repeat(24), &address[2..]))
    };
    // `indexOf`: a safe, non-negative integer.
    let index_of = |value: Option<Value<'_, '_>>| {
        let value = value.filter(|v| v.kind() == Kind::Number)?.number();
        (is_safe_integer(value) && value >= 0.0).then_some(value as u64)
    };
    Some(Transfer {
        address: address_of(item.get("token")?.get("address_hash"))?,
        block_number: Some(index_of(item.get("block_number"))?),
        block_hash: hash32(item.get("block_hash"))?,
        transaction_hash: hash32(item.get("transaction_hash"))?,
        log_index: Some(index_of(item.get("log_index"))?),
        from: topic_of(item.get("from"))?,
        to: topic_of(item.get("to"))?,
        value: decimal_value(item.get("total")?.get("value")?)?,
    })
}

/// `/^\d{1,78}$/` at most 2^256 - 1, in canonical decimal.
fn decimal_value(value: Value<'_, '_>) -> Option<String> {
    let units: Vec<u16> = value.units().collect();
    if value.kind() != Kind::String
        || units.is_empty()
        || units.len() > 78
        || !units.iter().all(|&u| (0x30..=0x39).contains(&u))
    {
        return None;
    }
    match parse_string(&units)? {
        Parsed::Value(value) if value.bits() <= 256 => Some(BigInt::to_decimal(&value)),
        _ => None,
    }
}

/// `logsAgree(indexed, rpcResult)`: the same transfers, identical in every
/// field both report, each once.
pub fn logs_agree(indexed: &[Transfer], rpc_result: Value<'_, '_>) -> bool {
    if !rpc_transfer_logs_well_formed(rpc_result) || indexed.len() != rpc_result.children().count()
    {
        return false;
    }
    let key = |t: &Transfer| (t.block_number, t.log_index);
    let mut expected: HashMap<(Option<u64>, Option<u64>), &Transfer> = HashMap::new();
    for transfer in indexed {
        if expected.insert(key(transfer), transfer).is_some() {
            return false;
        }
    }
    for entry in rpc_result.children() {
        let Some(transfer) = rpc_transfer(entry) else {
            return false;
        };
        if expected.remove(&key(&transfer)) != Some(&transfer) {
            return false;
        }
    }
    expected.is_empty()
}

/// The fields of an RPC entry the pair compared, plus `removed`.
const AGREED_LOG_FIELDS: [&str; 7] = [
    "address",
    "topics",
    "data",
    "blockNumber",
    "blockHash",
    "transactionHash",
    "logIndex",
];

/// `agreedRpcLogs(rpcResult)`: the RPC's entries cut to the fields the pair
/// verified, in the RPC's own spelling, with `removed: false`. `None`
/// unless the answer is well formed ([`rpc_transfer_logs_well_formed`]),
/// as it is once it agreed.
pub fn agreed_rpc_logs(rpc_result: Value<'_, '_>) -> Option<String> {
    if !rpc_transfer_logs_well_formed(rpc_result) {
        return None;
    }
    let mut out = String::from("[");
    for (i, entry) in rpc_result.children().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        for field in AGREED_LOG_FIELDS {
            out.push_str(&format!("\"{field}\":"));
            entry.get(field)?.write(KeyOrder::Property, &mut out);
            out.push(',');
        }
        out.push_str("\"removed\":false}");
    }
    out.push(']');
    Some(out)
}

/// `cooldownFrom(headers)`, from the values `Headers#get` gives (`None`
/// when absent): `x-ratelimit-reset` in milliseconds, else `Retry-After` in
/// seconds, else 5 minutes; clamped to 1 to 15 minutes.
pub fn cooldown_from(x_ratelimit_reset: Option<&str>, retry_after: Option<&str>) -> f64 {
    // `Number(null)` is 0.
    let reset = x_ratelimit_reset.map_or(0.0, string_to_number);
    let retry_after = retry_after.map_or(0.0, string_to_number);
    let named = if reset.is_finite() && reset > 0.0 {
        reset
    } else if retry_after.is_finite() && retry_after > 0.0 {
        retry_after * 1000.0
    } else {
        RATE_LIMIT_COOLDOWN_MS
    };
    named.clamp(MIN_COOLDOWN_MS, MAX_COOLDOWN_MS)
}

/// A failed scan: `BlockscoutError`'s message and the cooldown it names.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{message}")]
pub struct BlockscoutError {
    pub message: String,
    pub cool_ms: f64,
}

impl BlockscoutError {
    fn new(message: impl Into<String>) -> Self {
        Self::cooling(message, MIN_COOLDOWN_MS)
    }

    fn cooling(message: impl Into<String>, cool_ms: f64) -> Self {
        Self {
            message: message.into(),
            cool_ms,
        }
    }
}

/// One page as main read it, after its redirects: the status, the values
/// `Headers#get` gives for three headers (`None` when absent), and the
/// body.
#[derive(Debug, Clone)]
pub struct PageReply<'a> {
    pub status: u16,
    pub content_length: Option<&'a str>,
    pub x_ratelimit_reset: Option<&'a str>,
    pub retry_after: Option<&'a str>,
    pub body: Vec<u8>,
}

/// What a scan does after a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStep {
    /// Read the next page ([`TransferScan::query`]).
    Next,
    /// Every transfer in the span, oldest first.
    Done(Vec<Transfer>),
}

static THROTTLED_TEXT: JsPattern = JsPattern::new("too many requests|rate limit", "i");

/// `fetchBlockscoutTransferLogs` as a machine: the transfers `filter`
/// matches from `filter.from_block` to `to_block`, read from Blockscout's
/// list of the party's transfers, newest first, 50 to a page. A filter with
/// both parties is read by sender and the recipient matched here. Any
/// transfer outside the filter or out of order, a malformed page, or more
/// than 40 pages fails the whole scan: nothing partial is returned.
#[derive(Debug, Clone)]
pub struct TransferScan {
    filter: LogIndexFilter,
    /// The position to list before: a block and a log index.
    cursor: (u64, u64),
    pages: usize,
    transfers: Vec<Transfer>,
}

impl TransferScan {
    pub fn new(filter: LogIndexFilter, to_block: u64) -> Result<Self, BlockscoutError> {
        if filter.chain_id != LOG_INDEX_CHAIN_ID {
            return Err(BlockscoutError::new("no log index for this chain"));
        }
        Ok(Self {
            filter,
            cursor: (to_block.saturating_add(1), 0),
            pages: 0,
            transfers: Vec::new(),
        })
    }

    /// The party read and the side it is on.
    fn party(&self) -> (&str, bool) {
        match &self.filter.party {
            Party::Sender(sender) | Party::Both { sender, .. } => (sender, true),
            Party::Recipient(recipient) => (recipient, false),
        }
    }

    /// The next page's path and query, relative to the endpoint's URL
    /// (`pageUrl`).
    pub fn query(&self) -> String {
        let (party, by_sender) = self.party();
        format!(
            "/v2/addresses/0x{}/token-transfers?type=ERC-20&filter={}&token={LOG_INDEX_TOKEN}&block_number={}&index={}",
            party.get(26..).unwrap_or_default(),
            if by_sender { "from" } else { "to" },
            self.cursor.0,
            self.cursor.1
        )
    }

    /// Reads one page: the reply to the last [`Self::query`].
    pub fn on_page(&mut self, reply: PageReply<'_>) -> Result<ScanStep, BlockscoutError> {
        self.pages += 1;
        let text = page_text(reply)?;
        let index = Index::new(&text).map_err(|_| BlockscoutError::new("answer is not JSON"))?;
        let body = index.root();
        let items = body
            .get("items")
            .filter(|items| items.kind() == Kind::Array);
        let next = body.get("next_page_params");
        let (Some(items), Some(next)) = (items, next) else {
            return Err(refused(body));
        };
        if !matches!(next.kind(), Kind::Null | Kind::Object) {
            return Err(refused(body));
        }
        let (party, by_sender) = self.party();
        let (party, recipient) = (
            party.to_owned(),
            self.filter.party.recipient().map(str::to_owned),
        );
        let mut count = 0;
        for item in items.children() {
            count += 1;
            let transfer = blockscout_transfer(item).filter(|t| {
                t.address == LOG_INDEX_TOKEN
                    && if by_sender {
                        t.from == party
                    } else {
                        t.to == party
                    }
            });
            let Some(transfer) = transfer else {
                return Err(BlockscoutError::new(
                    "returned a transfer outside the filter",
                ));
            };
            let position = (
                transfer.block_number.unwrap_or_default(),
                transfer.log_index.unwrap_or_default(),
            );
            if position >= self.cursor {
                return Err(BlockscoutError::new("returned transfers out of order"));
            }
            self.cursor = position;
            if position.0 < self.filter.from_block {
                return Ok(ScanStep::Done(self.finish()));
            }
            if recipient.as_ref().is_none_or(|r| *r == transfer.to) {
                self.transfers.push(transfer);
            }
        }
        if next.kind() == Kind::Null {
            return Ok(ScanStep::Done(self.finish()));
        }
        if count == 0 {
            return Err(BlockscoutError::new("an empty page that is not the last"));
        }
        if self.pages >= BLOCKSCOUT_MAX_PAGES {
            return Err(BlockscoutError::new(format!(
                "over {BLOCKSCOUT_MAX_PAGES} pages of transfers"
            )));
        }
        Ok(ScanStep::Next)
    }

    fn finish(&mut self) -> Vec<Transfer> {
        let mut transfers = std::mem::take(&mut self.transfers);
        transfers.reverse();
        transfers
    }
}

/// A page's text, after its status and size checks (`fetchPage`).
fn page_text(reply: PageReply<'_>) -> Result<String, BlockscoutError> {
    if reply.status == 429 {
        return Err(BlockscoutError::cooling(
            "throttled (HTTP 429)",
            cooldown_from(reply.x_ratelimit_reset, reply.retry_after),
        ));
    }
    if !(200..=299).contains(&reply.status) {
        return Err(BlockscoutError::new(format!("HTTP {}", reply.status)));
    }
    let length = reply.content_length.map_or(f64::NAN, string_to_number);
    if length.is_finite() && length > MAX_PAGE_SIZE as f64 {
        return Err(BlockscoutError::new("answer over 8 MiB"));
    }
    // The reference counts UTF-16 units; the core also caps the bytes,
    // whatever the headers say (deviation `blockscout-page-bytes`).
    if reply.body.len() > MAX_PAGE_SIZE {
        return Err(BlockscoutError::new("answer over 8 MiB"));
    }
    let text = decode_text(reply.body);
    if text.chars().map(char::len_utf16).sum::<usize>() > MAX_PAGE_SIZE {
        return Err(BlockscoutError::new("answer over 8 MiB"));
    }
    Ok(text)
}

/// A page that isn't a list: a named rate limit, or a refusal.
fn refused(body: Value<'_, '_>) -> BlockscoutError {
    let message = body
        .get("message")
        .filter(|m| m.kind() == Kind::String)
        .map(|m| m.units().collect::<Vec<u16>>())
        .unwrap_or_default();
    if THROTTLED_TEXT.test(&MatchText::new(&message)) {
        BlockscoutError::cooling("throttled", RATE_LIMIT_COOLDOWN_MS)
    } else {
        BlockscoutError::new("refused the query")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::safe_source;

    #[test]
    fn throttle_pattern() {
        assert!(THROTTLED_TEXT.compiles());
        assert!(safe_source(THROTTLED_TEXT.source));
    }

    #[test]
    fn cooldowns() {
        assert_eq!(cooldown_from(None, None), RATE_LIMIT_COOLDOWN_MS);
        assert_eq!(cooldown_from(Some("120000"), Some("5")), 120_000.0);
        assert_eq!(cooldown_from(Some("0"), Some("1e3")), MAX_COOLDOWN_MS);
        assert_eq!(cooldown_from(Some("0x10"), None), MIN_COOLDOWN_MS);
    }
}
