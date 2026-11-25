//! Postage batches: the node's `/stamps` reply, read by its typed reader
//! (design 0015, "JSON replies"); bee-js 13.2.0's `stamp.getAll` over it
//! (zod's schema, then `mapPostageBatch`'s arithmetic, IEEE doubles
//! included); swarm-service.js's classification of a raw batch; and
//! `selectBestBatch` (`swarm-service.js:140–213` at the reference).
//!
//! **One read** (deviation `stamps-one-read`): when no usable batch has
//! room, the reference reads `/stamps` again (ant-storage-api.js's raw
//! JSON) for the batches the node marks `propagating`, which bee-js drops.
//! The core keeps that flag from its one read and uses it.
//! [`Selection::propagating_pass`] says when the reference would have read
//! twice.

use fc_json::{JsString, number_to_string};

use crate::ReplyError;
use crate::js::{self, is_integer, math_round, pow2};
use crate::json::{RawStr, Reader, Token, decode_raw};
use crate::zod::{Expected, Issue, Issues, Received, Segment};

/// `/stamps`'s reply cap: the `stamps` form's (design 0015,
/// `shell.swarm_api`).
pub const STAMPS_REPLY_CAP: usize = 1 << 20;

/// The most batches a `/stamps` reply may list (`E`, design 0015, "JSON
/// replies"): one more is `too_large` (deviation `reply-bounds`).
pub const STAMPS_BATCH_CAP: usize = 4096;

/// What the reader may keep per batch, its strings apart (`E × 256 B`).
pub const ELEMENT_BYTES: usize = 256;

/// A batch's field as the reply had it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Field<T> {
    /// No such key.
    Missing,
    /// A value of another type than the schema's (a number that isn't
    /// finite included, which zod refuses).
    Wrong(Received),
    Ok(T),
}

/// A string kept from the reply: its literal's bytes, escapes and all, in
/// the reply's arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    start: u32,
    len: u32,
}

/// One batch of the reply: the fields `mapPostageBatch` reads, and the two
/// flags the classification reads (`exists`, `propagating`), which bee-js
/// drops.
#[derive(Debug, Clone, Copy, PartialEq)]
struct RawBatch {
    batch_id: Field<Span>,
    utilization: Field<f64>,
    utilization_ratio: Field<f64>,
    usable: Field<bool>,
    label: Field<Span>,
    depth: Field<f64>,
    amount: Field<Span>,
    bucket_depth: Field<f64>,
    block_number: Field<f64>,
    immutable_flag: Field<bool>,
    batch_ttl: Field<f64>,
    exists: Field<bool>,
    propagating: Field<bool>,
}

// What the reader keeps per batch fits its element budget.
const _: () = assert!(std::mem::size_of::<RawBatch>() <= ELEMENT_BYTES);

impl RawBatch {
    const EMPTY: Self = Self {
        batch_id: Field::Missing,
        utilization: Field::Missing,
        utilization_ratio: Field::Missing,
        usable: Field::Missing,
        label: Field::Missing,
        depth: Field::Missing,
        amount: Field::Missing,
        bucket_depth: Field::Missing,
        block_number: Field::Missing,
        immutable_flag: Field::Missing,
        batch_ttl: Field::Missing,
        exists: Field::Missing,
        propagating: Field::Missing,
    };
}

/// The value at the reply's `stamps` key.
#[derive(Debug, Clone, Copy, PartialEq)]
enum List {
    Missing,
    Wrong(Received),
    Array,
}

/// A `/stamps` reply as the core keeps it.
#[derive(Debug, Clone)]
pub struct Stamps {
    /// Every kept string's literal as the reply's bytes, back to back:
    /// never more than the reply's own length.
    arena: Vec<u8>,
    /// The array's objects, in order.
    batches: Vec<RawBatch>,
    /// zod's issues, in its order.
    issues: Issues,
}

fn received(token: &Token<'_>) -> Received {
    match token {
        Token::Object => Received::Object,
        Token::Array => Received::Array,
        Token::String(_) => Received::String,
        Token::Number(n) => Received::of_number(*n),
        Token::Bool(_) => Received::Boolean,
        Token::Null => Received::Null,
    }
}

/// The node's `/stamps` reply, as bee-js's `http` reads it
/// (`Response.text()`: a byte-order mark dropped; an empty text is `null`)
/// and as `GetAllPostageBatchesResponse` checks it.
///
/// Fails `too_large` past [`STAMPS_REPLY_CAP`] bytes, past
/// [`STAMPS_BATCH_CAP`] elements, or when zod's message would pass the
/// reply cap; `TooDeep` past [`crate::json::MAX_NESTING`]; `Syntax` for a
/// text `JSON.parse` refuses. The caps hold for each value as it is read,
/// one that a repeated key later replaces included.
pub fn read_stamps(reply: &[u8]) -> Result<Stamps, ReplyError> {
    if reply.len() > STAMPS_REPLY_CAP {
        return Err(ReplyError::TooLarge);
    }
    let text = js::strip_bom(reply);
    let mut stamps = Stamps {
        // Kept literals are parts of the text, so this never grows.
        arena: Vec::with_capacity(text.len()),
        batches: Vec::new(),
        issues: Issues::new(),
    };
    if text.is_empty() {
        // `text ? JSON.parse(text) : null`.
        stamps.push(Issue::new(Expected::Object, Received::Null, &[]))?;
        return Ok(stamps.shrunk());
    }
    let mut r = Reader::new(text);
    let root = r.token()?;
    if root == Token::Object {
        let mut list = List::Missing;
        while let Some(key) = r.next_key()? {
            if !key.is("stamps") {
                r.skip_value()?;
                continue;
            }
            // A repeated key: the last value is the one `JSON.parse` keeps.
            stamps.arena.clear();
            stamps.batches.clear();
            stamps.issues.clear();
            let token = r.token()?;
            if token == Token::Array {
                list = List::Array;
                stamps.read_list(&mut r)?;
            } else {
                list = List::Wrong(received(&token));
                r.skip(token)?;
            }
        }
        let at = [Segment::Key("stamps")];
        match list {
            List::Missing => stamps.push(Issue::new(Expected::Array, Received::Undefined, &at))?,
            List::Wrong(what) => stamps.push(Issue::new(Expected::Array, what, &at))?,
            List::Array => {}
        }
    } else {
        stamps.push(Issue::new(Expected::Object, received(&root), &[]))?;
        r.skip(root)?;
    }
    r.finish()?;
    Ok(stamps.shrunk())
}

/// The `stamp` form's cap (`GET /stamps/<b>`, design 0015,
/// `shell.swarm_api`), and its one element.
pub const STAMP_REPLY_CAP: usize = crate::machine::node::JSON_REPLY_CAP;

/// The node's `/stamps/<b>` reply, as bee-js's `stamp.get` reads it
/// (`Response.text()`: a byte-order mark dropped; an empty text is `null`)
/// and as `GetPostageBatchResponse` (`RawPostageBatchSchema`, one batch at
/// the root) checks it: a [`Stamps`] of that one batch, whose
/// [`Stamps::get_all`] is `getPostageBatch`'s `mapPostageBatch`, and whose
/// issues' paths start at the batch (`["label"]`, not `["stamps", 0,
/// "label"]`).
///
/// Fails `too_large` past [`STAMP_REPLY_CAP`] bytes; `TooDeep` past
/// [`crate::json::MAX_NESTING`]; `Syntax` for a text `JSON.parse` refuses.
/// One batch's issues (at most eleven) stay far under the cap.
pub fn read_stamp(reply: &[u8]) -> Result<Stamps, ReplyError> {
    if reply.len() > STAMP_REPLY_CAP {
        return Err(ReplyError::TooLarge);
    }
    let text = js::strip_bom(reply);
    let mut stamps = Stamps {
        arena: Vec::with_capacity(text.len()),
        batches: Vec::new(),
        issues: Issues::new(),
    };
    if text.is_empty() {
        stamps.push(Issue::new(Expected::Object, Received::Null, &[]))?;
        return Ok(stamps.shrunk());
    }
    let mut r = Reader::new(text);
    let root = r.token()?;
    if root == Token::Object {
        let batch = stamps.read_batch(&mut r)?;
        stamps.check(&batch, &[])?;
        stamps.batches.push(batch);
    } else {
        stamps.push(Issue::new(Expected::Object, received(&root), &[]))?;
        r.skip(root)?;
    }
    r.finish()?;
    Ok(stamps.shrunk())
}

impl Stamps {
    fn push(&mut self, issue: Issue) -> Result<(), ReplyError> {
        self.issues
            .push(issue, STAMPS_REPLY_CAP)
            .map_err(|_| ReplyError::TooLarge)
    }

    fn shrunk(mut self) -> Self {
        self.arena.shrink_to_fit();
        self.batches.shrink_to_fit();
        self.issues.shrink();
        self
    }

    fn keep(&mut self, raw: RawStr<'_>) -> Result<Span, ReplyError> {
        // The literal as it came, decoded when it is read: a bad UTF-8
        // sequence becomes U+FFFD then, as `Response.text()` makes it.
        let bytes = raw.raw();
        let start = u32::try_from(self.arena.len()).map_err(|_| ReplyError::TooLarge)?;
        let len = u32::try_from(bytes.len()).map_err(|_| ReplyError::TooLarge)?;
        self.arena.extend_from_slice(bytes);
        Ok(Span { start, len })
    }

    fn read_list(&mut self, r: &mut Reader<'_>) -> Result<(), ReplyError> {
        let mut index: u32 = 0;
        while r.next_element()? {
            if index as usize >= STAMPS_BATCH_CAP {
                return Err(ReplyError::TooLarge);
            }
            let token = r.token()?;
            if token == Token::Object {
                let batch = self.read_batch(r)?;
                self.check(&batch, &[Segment::Key("stamps"), Segment::Index(index)])?;
                self.batches.push(batch);
            } else {
                let at = [Segment::Key("stamps"), Segment::Index(index)];
                self.push(Issue::new(Expected::Object, received(&token), &at))?;
                r.skip(token)?;
            }
            index += 1;
        }
        Ok(())
    }

    fn read_batch(&mut self, r: &mut Reader<'_>) -> Result<RawBatch, ReplyError> {
        let mut b = RawBatch::EMPTY;
        while let Some(key) = r.next_key()? {
            let token = r.token()?;
            // A repeated key keeps its last value, as `JSON.parse` does.
            if key.is("batchID") {
                b.batch_id = self.string(r, token, b.batch_id)?;
            } else if key.is("utilization") {
                b.utilization = number(r, token)?;
            } else if key.is("utilizationRatio") {
                b.utilization_ratio = number(r, token)?;
            } else if key.is("usable") {
                b.usable = boolean(r, token)?;
            } else if key.is("label") {
                b.label = self.string(r, token, b.label)?;
            } else if key.is("depth") {
                b.depth = number(r, token)?;
            } else if key.is("amount") {
                b.amount = self.string(r, token, b.amount)?;
            } else if key.is("bucketDepth") {
                b.bucket_depth = number(r, token)?;
            } else if key.is("blockNumber") {
                b.block_number = number(r, token)?;
            } else if key.is("immutableFlag") {
                b.immutable_flag = boolean(r, token)?;
            } else if key.is("batchTTL") {
                b.batch_ttl = number(r, token)?;
            } else if key.is("exists") {
                b.exists = boolean(r, token)?;
            } else if key.is("propagating") {
                b.propagating = boolean(r, token)?;
            } else {
                r.skip(token)?;
            }
        }
        Ok(b)
    }

    /// A string field's value, `old` overwritten: its bytes go back to the
    /// arena when they were the last kept.
    fn string(
        &mut self,
        r: &mut Reader<'_>,
        token: Token<'_>,
        old: Field<Span>,
    ) -> Result<Field<Span>, ReplyError> {
        if let Field::Ok(span) = old
            && (span.start as usize) + (span.len as usize) == self.arena.len()
        {
            self.arena.truncate(span.start as usize);
        }
        if let Token::String(raw) = token {
            return Ok(Field::Ok(self.keep(raw)?));
        }
        let what = received(&token);
        r.skip(token)?;
        Ok(Field::Wrong(what))
    }

    /// `RawPostageBatchSchema`'s checks, in its key order, each issue's
    /// path under `at` (the batch's place in the reply).
    fn check(&mut self, b: &RawBatch, at: &[Segment]) -> Result<(), ReplyError> {
        fn state<T>(field: &Field<T>) -> Option<Received> {
            match field {
                Field::Missing => Some(Received::Undefined),
                Field::Wrong(what) => Some(*what),
                Field::Ok(_) => None,
            }
        }
        let optional = |field: &Field<f64>| match field {
            Field::Wrong(what) => Some(*what),
            _ => None,
        };
        let fields: [(&'static str, Expected, Option<Received>); 11] = [
            ("batchID", Expected::String, state(&b.batch_id)),
            ("utilization", Expected::Number, state(&b.utilization)),
            (
                "utilizationRatio",
                Expected::Number,
                optional(&b.utilization_ratio),
            ),
            ("usable", Expected::Boolean, state(&b.usable)),
            ("label", Expected::String, state(&b.label)),
            ("depth", Expected::Number, state(&b.depth)),
            ("amount", Expected::String, state(&b.amount)),
            ("bucketDepth", Expected::Number, state(&b.bucket_depth)),
            ("blockNumber", Expected::Number, state(&b.block_number)),
            ("immutableFlag", Expected::Boolean, state(&b.immutable_flag)),
            ("batchTTL", Expected::Number, state(&b.batch_ttl)),
        ];
        for (key, expected, wrong) in fields {
            if let Some(what) = wrong {
                let mut path = at.to_vec();
                path.push(Segment::Key(key));
                self.push(Issue::new(expected, what, &path))?;
            }
        }
        Ok(())
    }

    fn decode(&self, span: Span) -> JsString {
        let start = span.start as usize;
        let raw = self
            .arena
            .get(start..start + span.len as usize)
            .unwrap_or_default();
        decode_raw(raw)
    }

    /// The reply's batches, as the classification reads a raw batch: every
    /// object of the `stamps` array, in order (all of its elements, when zod
    /// accepts the reply).
    pub fn batches(&self) -> impl Iterator<Item = RawBatchView<'_>> {
        self.batches
            .iter()
            .map(move |raw| RawBatchView { raw, stamps: self })
    }

    /// zod's issues with the reply, none when it accepts it.
    pub fn issues(&self) -> &Issues {
        &self.issues
    }

    /// What the reader keeps on the heap: the strings' arena, the batches
    /// and the issues. At most the reply's length plus
    /// [`ELEMENT_BYTES`] per batch and the issues (design 0015, "JSON
    /// replies").
    pub fn kept_bytes(&self) -> usize {
        self.arena.capacity()
            + self.batches.capacity() * std::mem::size_of::<RawBatch>()
            + self.issues.heap_bytes()
    }

    /// bee-js's `stamp.getAll()`: zod's parse, then `mapPostageBatch` over
    /// each batch in order; the first error thrown is the answer.
    pub fn get_all(&self) -> Result<Vec<PostageBatch>, JsError> {
        if !self.issues.is_empty() {
            return Err(JsError {
                name: ErrorName::ZodError,
                message: JsString::from(self.issues.message()),
            });
        }
        self.batches.iter().map(|b| self.map(b)).collect()
    }

    /// `mapPostageBatch(raw)` over a batch zod accepted.
    fn map(&self, b: &RawBatch) -> Result<PostageBatch, JsError> {
        let (
            Field::Ok(batch_id),
            Field::Ok(utilization),
            Field::Ok(usable),
            Field::Ok(label),
            Field::Ok(depth),
            Field::Ok(amount),
            Field::Ok(bucket_depth),
            Field::Ok(block_number),
            Field::Ok(immutable_flag),
            Field::Ok(batch_ttl),
        ) = (
            b.batch_id,
            b.utilization,
            b.usable,
            b.label,
            b.depth,
            b.amount,
            b.bucket_depth,
            b.block_number,
            b.immutable_flag,
            b.batch_ttl,
        )
        else {
            // zod refused it, and get_all answered that first.
            return Err(JsError::error("unreachable: a batch zod refused"));
        };
        // zod's `number` admits a fractional depth, which bee-js raises 2 to
        // with V8's own pow. The core computes no fractional power, so such
        // a batch is refused (deviation `batch-depth`); a node sends whole
        // depths.
        if !is_integer(depth) || !is_integer(bucket_depth) {
            return Err(JsError::error(NON_INTEGER_DEPTH_MESSAGE));
        }
        let duration = normalize_batch_ttl(batch_ttl);
        let effective = effective_bytes(depth);
        let usage = match b.utilization_ratio {
            Field::Ok(ratio) => ratio,
            _ => utilization / pow2(depth - bucket_depth),
        };
        let batch_id = parse_batch_id(&self.decode(batch_id))?;
        let amount = as_number_string(&self.decode(amount))?;
        let remaining = (effective * (1.0 - usage)).ceil();
        if remaining < 0.0 {
            return Err(JsError::error("Size must be at least 0"));
        }
        Ok(PostageBatch {
            batch_id,
            utilization,
            usable,
            label: self.decode(label),
            depth,
            amount,
            bucket_depth,
            block_number,
            immutable_flag,
            usage,
            usage_text: format!("{}%", number_to_string(math_round(usage * 100.0))),
            size: effective.ceil(),
            remaining_size: remaining,
            theoretical_size: theoretical_bytes(depth).ceil(),
            duration,
        })
    }
}

fn number(r: &mut Reader<'_>, token: Token<'_>) -> Result<Field<f64>, ReplyError> {
    if let Token::Number(n) = token {
        return Ok(if n.is_finite() {
            Field::Ok(n)
        } else {
            Field::Wrong(Received::of_number(n))
        });
    }
    let what = received(&token);
    r.skip(token)?;
    Ok(Field::Wrong(what))
}

fn boolean(r: &mut Reader<'_>, token: Token<'_>) -> Result<Field<bool>, ReplyError> {
    if let Token::Bool(b) = token {
        return Ok(Field::Ok(b));
    }
    let what = received(&token);
    r.skip(token)?;
    Ok(Field::Wrong(what))
}

/// A raw batch as swarm-service.js's classification reads the node's JSON.
#[derive(Clone, Copy)]
pub struct RawBatchView<'s> {
    raw: &'s RawBatch,
    stamps: &'s Stamps,
}

impl RawBatchView<'_> {
    /// `isUsableStamp`: `usable === true`.
    pub fn is_usable(&self) -> bool {
        self.raw.usable == Field::Ok(true)
    }

    /// `isPendingStamp`: not usable, and `propagating` if the node says,
    /// else `exists !== false && Number(batchTTL) > 0`. A `batchTTL` that
    /// isn't a number, which only a reply zod refuses has, reads as `null`
    /// (0) when it is `null` and as NaN otherwise.
    pub fn is_pending(&self) -> bool {
        if self.is_usable() {
            return false;
        }
        if let Field::Ok(flag) = self.raw.propagating {
            return flag;
        }
        let ttl = match self.raw.batch_ttl {
            Field::Ok(n) => n,
            Field::Wrong(Received::Null) => 0.0,
            Field::Wrong(Received::Infinity) => f64::INFINITY,
            Field::Wrong(Received::NegInfinity) => f64::NEG_INFINITY,
            _ => f64::NAN,
        };
        self.raw.exists != Field::Ok(false) && ttl > 0.0
    }

    /// `exists` as the node sent it, when a boolean (bee-js drops it; a
    /// value of another type reads as absent wherever Freedom reads it:
    /// `exists !== false`).
    pub fn exists(&self) -> Option<bool> {
        match self.raw.exists {
            Field::Ok(flag) => Some(flag),
            _ => None,
        }
    }

    /// `propagating` as the node sent it, when a boolean (bee-js drops it;
    /// Freedom reads only a boolean: `typeof propagating === 'boolean'`).
    pub fn propagating(&self) -> Option<bool> {
        match self.raw.propagating {
            Field::Ok(flag) => Some(flag),
            _ => None,
        }
    }

    /// `batchTTL` as the node sent it, before bee-js's `normalizeBatchTTL`
    /// (which `isPendingStamp` reads), when a finite number.
    pub fn batch_ttl(&self) -> Option<f64> {
        match self.raw.batch_ttl {
            Field::Ok(ttl) => Some(ttl),
            _ => None,
        }
    }

    /// `isPropagatingStamp`: `usable !== true && propagating === true`.
    pub fn is_propagating(&self) -> bool {
        !self.is_usable() && self.raw.propagating == Field::Ok(true)
    }

    /// `isFullImmutableStamp`: an immutable batch whose fullest bucket holds
    /// `2^(depth - bucketDepth)` chunks.
    pub fn is_full_immutable(&self) -> bool {
        if self.raw.immutable_flag != Field::Ok(true) {
            return false;
        }
        let (Field::Ok(utilization), Field::Ok(depth), Field::Ok(bucket_depth)) =
            (self.raw.utilization, self.raw.depth, self.raw.bucket_depth)
        else {
            return false;
        };
        if ![utilization, depth, bucket_depth]
            .into_iter()
            .all(is_integer)
            || depth < bucket_depth
        {
            return false;
        }
        utilization >= pow2(depth - bucket_depth)
    }

    /// `batchIdKey(batchID)`: trimmed, without `0x`, lowercased. `None` when
    /// `batchID` isn't a string, which only a reply zod refuses has.
    pub fn batch_id_key(&self) -> Option<JsString> {
        let Field::Ok(span) = self.raw.batch_id else {
            return None;
        };
        Some(batch_id_key(&self.stamps.decode(span)))
    }
}

/// `toHex(value).trim().replace(/^0x/i, '').toLowerCase()` for a string.
fn batch_id_key(id: &JsString) -> JsString {
    let trimmed = js::trim(id);
    let bare = match trimmed.as_bytes() {
        [b'0', b'x' | b'X', ..] => {
            let units: Vec<u16> = trimmed.units().skip(2).collect();
            JsString::from_units(&units)
        }
        _ => trimmed,
    };
    js::to_lower(&bare)
}

/// A postage batch as bee-js's `mapPostageBatch` gives it: the fields
/// Freedom reads, sizes in bytes and the duration in seconds.
#[derive(Debug, Clone, PartialEq)]
pub struct PostageBatch {
    pub batch_id: BatchId,
    pub utilization: f64,
    pub usable: bool,
    pub label: JsString,
    pub depth: f64,
    /// `asNumberString(amount)`: an integer's decimal text.
    pub amount: String,
    pub bucket_depth: f64,
    pub block_number: f64,
    pub immutable_flag: bool,
    pub usage: f64,
    pub usage_text: String,
    pub size: f64,
    pub remaining_size: f64,
    pub theoretical_size: f64,
    pub duration: f64,
}

/// A batch's 32-byte ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BatchId(pub [u8; 32]);

impl BatchId {
    /// Lowercase hex, without `0x`: bee-js's `toHex()`.
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0xf)]));
        }
        out
    }
}

/// The core's refusal of a batch whose `depth` or `bucketDepth` isn't an
/// integer (design 0015, deviation `batch-depth`).
pub const NON_INTEGER_DEPTH_MESSAGE: &str = "Swarm node reply has a non-integer batch depth";

/// The class of an error the reference throws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorName {
    Error,
    TypeError,
    ZodError,
}

impl ErrorName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "Error",
            Self::TypeError => "TypeError",
            Self::ZodError => "ZodError",
        }
    }
}

/// An error bee-js throws while reading a reply: its class and message
/// (which the page reads through `nodeWriteError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsError {
    pub name: ErrorName,
    pub message: JsString,
}

impl JsError {
    fn error(message: &str) -> Self {
        Self {
            name: ErrorName::Error,
            message: JsString::from(message),
        }
    }
}

/// `normalizeBatchTTL` then `Duration.fromSeconds(…).toSeconds()`: a whole
/// number of seconds from 1 to 100 years.
fn normalize_batch_ttl(ttl: f64) -> f64 {
    if !is_integer(ttl) || ttl < 1.0 {
        1.0
    } else if ttl > 3_155_695_200.0 {
        3_155_695_200.0
    } else {
        ttl
    }
}

/// core-sdk's `getStampTheoreticalBytes`: `4096 * 2 ** depth`.
fn theoretical_bytes(depth: f64) -> f64 {
    4096.0 * pow2(depth)
}

/// core-sdk's `DEFAULT_EFFECTIVE_SIZE_BREAKPOINTS`, each size's number in
/// GB (`parseFloat` of its text; Rust's literals round as it does).
const BREAKPOINTS: [(f64, f64); 18] = [
    (17.0, 0.00004089),
    (18.0, 0.00609),
    (19.0, 0.10249),
    (20.0, 0.62891),
    (21.0, 2.38),
    (22.0, 7.07),
    (23.0, 18.24),
    (24.0, 43.04),
    (25.0, 96.5),
    (26.0, 208.52),
    (27.0, 435.98),
    (28.0, 908.81),
    (29.0, 1870.0),
    (30.0, 3810.0),
    (31.0, 7730.0),
    (32.0, 15610.0),
    (33.0, 31430.0),
    (34.0, 63150.0),
];

/// core-sdk's `getStampEffectiveBytes(depth)` without encryption or
/// erasure coding: 0 below depth 17, the table's size
/// (`Math.ceil(parseFloat(n) * 1e9)`), else 90% of the theoretical size,
/// rounded up.
fn effective_bytes(depth: f64) -> f64 {
    if depth < 17.0 {
        return 0.0;
    }
    if let Some((_, gb)) = BREAKPOINTS.iter().find(|(d, _)| *d == depth) {
        return (gb * 1e9).ceil();
    }
    (theoretical_bytes(depth) * 0.9).ceil()
}

/// core-sdk's `new BatchId(text)`: `0x`-prefixed or bare hex of 32 bytes.
fn parse_batch_id(text: &JsString) -> Result<BatchId, JsError> {
    let with = |prefix: &str| JsError {
        name: ErrorName::Error,
        message: js::concat(&[&JsString::from(prefix), text]),
    };
    if text.utf16_len() == 0 {
        // `if (!bytes)`: the empty string is falsy.
        return Err(with("Bytes#constructor: constructor parameter is falsy: "));
    }
    // HEX_PATTERN, /^(0x)?[0-9a-fA-F]*$/i, then an even length past the
    // prefix (/^0x/i).
    let s = text.as_bytes();
    let digits = match s {
        [b'0', b'x' | b'X', rest @ ..] => rest,
        _ => s,
    };
    if !text.is_well_formed() || !digits.iter().all(u8::is_ascii_hexdigit) || digits.len() % 2 != 0
    {
        return Err(with("Bytes#constructor: invalid hex string: "));
    }
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let nibble = |h: u8| match h {
            b'0'..=b'9' => h - b'0',
            b'a'..=b'f' => h - b'a' + 10,
            _ => h - b'A' + 10,
        };
        bytes.push((nibble(pair[0]) << 4) | nibble(pair[1]));
    }
    let length = bytes.len();
    <[u8; 32]>::try_from(bytes)
        .map(BatchId)
        .map_err(|_| JsError {
            name: ErrorName::Error,
            message: JsString::from(format!(
                "Bytes#checkByteLength: bytes length is {length} but expected 32"
            )),
        })
}

/// bee-js's `asNumberString(value)` for a string: /^-?\d+$/, or a
/// `TypeError`.
fn as_number_string(text: &JsString) -> Result<String, JsError> {
    let s = text.as_bytes();
    let digits = s.strip_prefix(b"-").unwrap_or(s);
    if text.is_well_formed() && !digits.is_empty() && digits.iter().all(u8::is_ascii_digit) {
        return Ok(text.as_str().to_owned());
    }
    Err(JsError {
        name: ErrorName::TypeError,
        message: js::concat(&[
            &JsString::from("value is not a valid integer string, got: "),
            text,
        ]),
    })
}

/// `selectBestBatch`'s options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SelectOptions {
    /// Throw instead of answering `null` (content publishes).
    pub require_capacity: bool,
    /// A usable mutable batch without room is the last fallback (messaging).
    pub allow_full_mutable: bool,
}

/// Why `selectBestBatch` found no batch, with `requireCapacity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostageCode {
    /// No usable batch at all.
    Unavailable,
    /// Usable batches, none with room.
    CapacityInsufficient,
}

impl PostageCode {
    /// The error's `code`.
    pub fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "POSTAGE_UNAVAILABLE",
            Self::CapacityInsufficient => "POSTAGE_CAPACITY_INSUFFICIENT",
        }
    }

    /// The error's message.
    pub fn message(self) -> &'static str {
        match self {
            Self::Unavailable => {
                "No usable postage batch is available. Check your stamps before publishing."
            }
            Self::CapacityInsufficient => {
                "No postage batch has enough capacity for this upload. Select or purchase a suitable batch."
            }
        }
    }
}

/// The error's `capacity`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Capacity {
    pub upload_bytes: f64,
    /// `Math.ceil(size * 1.5)`.
    pub required_bytes: f64,
    pub largest_remaining_bytes: f64,
}

/// `selectBestBatch`'s refusal under `requireCapacity`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PostageError {
    pub code: PostageCode,
    pub capacity: Capacity,
}

/// What `selectBestBatch` answered.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Selection {
    /// The batch, `None` for the reference's `null`, or its refusal.
    pub outcome: Result<Option<BatchId>, PostageError>,
    /// Whether the propagating pass ran: no usable batch had room and the
    /// reply lists a batch that isn't usable. The reference read `/stamps`
    /// a second time for it; the core uses its one read
    /// (`stamps-one-read`).
    pub propagating_pass: bool,
}

/// The reference's 1.5× room per byte to upload.
const SIZE_SAFETY_MARGIN: f64 = 1.5;

/// `selectBestBatch(size, options)` over a `/stamps` reply: a usable batch
/// with 1.5× the size left, the longest TTL first (the first of equals);
/// then a propagating one with room; then, with `allow_full_mutable`, a
/// usable mutable one without room. What `stamp.getAll` throws is thrown.
pub fn select_best_batch(
    stamps: &Stamps,
    size: u64,
    options: SelectOptions,
) -> Result<Selection, JsError> {
    let batches = stamps.get_all()?;
    let size = size as f64;
    let required = size * SIZE_SAFETY_MARGIN;

    let mut best: Option<&PostageBatch> = None;
    let mut best_ttl = -1.0;
    let mut full_mutable: Option<&PostageBatch> = None;
    let mut full_mutable_ttl = -1.0;
    let mut usable_count = 0usize;
    let mut largest_remaining = 0.0;

    for batch in batches.iter().filter(|b| b.usable) {
        usable_count += 1;
        let remaining = batch.remaining_size;
        // Math.max over finite values, from +0: never -0.
        if remaining.is_finite() && remaining > largest_remaining {
            largest_remaining = remaining;
        }
        let ttl = batch.duration;
        if remaining >= required {
            if ttl > best_ttl {
                best = Some(batch);
                best_ttl = ttl;
            }
        } else if options.allow_full_mutable && !batch.immutable_flag && ttl > full_mutable_ttl {
            full_mutable = Some(batch);
            full_mutable_ttl = ttl;
        }
    }

    let propagating_pass = best.is_none() && batches.iter().any(|b| !b.usable);
    if propagating_pass {
        // The reference's getPropagatingBatchIds, over the same reply.
        let propagating: Vec<String> = stamps
            .batches()
            .filter(|b| b.is_propagating())
            .filter_map(|b| b.batch_id_key())
            .map(|key| key.as_str().to_owned())
            .collect();
        for batch in batches.iter().filter(|b| !b.usable) {
            let hex = batch.batch_id.to_hex();
            if !propagating.contains(&hex) {
                continue;
            }
            let ttl = batch.duration;
            if batch.remaining_size >= required && ttl > best_ttl {
                best = Some(batch);
                best_ttl = ttl;
            }
        }
    }

    if best.is_none() {
        best = full_mutable;
    }

    let outcome = match best {
        Some(batch) => Ok(Some(batch.batch_id)),
        None if options.require_capacity => Err(PostageError {
            code: if usable_count > 0 {
                PostageCode::CapacityInsufficient
            } else {
                PostageCode::Unavailable
            },
            capacity: Capacity {
                upload_bytes: size,
                required_bytes: required.ceil(),
                largest_remaining_bytes: largest_remaining,
            },
        }),
        None => Ok(None),
    };
    Ok(Selection {
        outcome,
        propagating_pass,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_sizes_are_core_sdks() {
        assert_eq!(effective_bytes(17.0), 40890.0);
        assert_eq!(effective_bytes(18.0), 6_090_000.0);
        assert_eq!(effective_bytes(20.0), 628_910_000.0);
        assert_eq!(effective_bytes(22.0), 7_070_000_000.0);
        assert_eq!(effective_bytes(16.0), 0.0);
        assert_eq!(effective_bytes(-3.0), 0.0);
        // Past the table: 90% of 4096 × 2^35, rounded up.
        assert_eq!(
            effective_bytes(35.0),
            (4096.0 * 34359738368.0 * 0.9f64).ceil()
        );
    }

    #[test]
    fn batch_ids_parse_as_core_sdk() {
        let ok = parse_batch_id(&JsString::from(format!("0X{}", "Ab".repeat(32)))).unwrap();
        assert_eq!(ok.to_hex(), "ab".repeat(32));
        let message = |text: &str| parse_batch_id(&JsString::from(text)).unwrap_err().message;
        assert_eq!(
            message(""),
            "Bytes#constructor: constructor parameter is falsy: "
        );
        assert_eq!(
            message("0x"),
            "Bytes#checkByteLength: bytes length is 0 but expected 32"
        );
        assert_eq!(message("abc"), "Bytes#constructor: invalid hex string: abc");
        assert_eq!(message(" ab"), "Bytes#constructor: invalid hex string:  ab");
        assert_eq!(
            message("0x0x"),
            "Bytes#constructor: invalid hex string: 0x0x"
        );
        assert_eq!(
            message("abcd"),
            "Bytes#checkByteLength: bytes length is 2 but expected 32"
        );
    }

    #[test]
    fn amounts_are_integer_strings() {
        for ok in ["0", "-5", "100000000000", "007"] {
            assert_eq!(as_number_string(&JsString::from(ok)).unwrap(), ok);
        }
        for bad in ["", "-", "1.5", "1e3", " 1", "1\n", "١"] {
            let err = as_number_string(&JsString::from(bad)).unwrap_err();
            assert_eq!(err.name, ErrorName::TypeError);
            assert_eq!(
                err.message,
                format!("value is not a valid integer string, got: {bad}")
            );
        }
    }

    #[test]
    fn keys_are_batch_id_keys() {
        let key = |units: &[u16]| batch_id_key(&JsString::from_units(units));
        let u = |s: &str| s.encode_utf16().collect::<Vec<_>>();
        assert_eq!(key(&u(" 0XAB\u{3000}")), "ab");
        assert_eq!(key(&u("0x0xAB")), "0xab");
        let lone = key(&[0x41, 0xd800, 0x42]);
        assert_eq!(lone.units().collect::<Vec<_>>(), vec![0x61, 0xd800, 0x62]);
    }

    #[test]
    fn a_fractional_depth_is_refused() {
        // zod's number admits these; the core computes no fractional power
        // (deviation `batch-depth`), so the batch is refused, and with it
        // the read and any write's batch choice.
        let reply = |depth: &str, bucket: &str| {
            format!(
                r#"{{"stamps":[{{"batchID":"{id}","utilization":0,"usable":true,"label":"","depth":{depth},"amount":"100000000000","bucketDepth":{bucket},"blockNumber":1,"immutableFlag":true,"exists":true,"batchTTL":86400}}]}}"#,
                id = "ab".repeat(32)
            )
        };
        let whole = read_stamps(reply("22", "16").as_bytes()).unwrap();
        assert!(whole.get_all().is_ok());
        for (depth, bucket) in [("22.5", "16"), ("22", "16.5"), ("2.2e1", "1.65e1")] {
            let stamps = read_stamps(reply(depth, bucket).as_bytes()).unwrap();
            let err = stamps.get_all().unwrap_err();
            assert_eq!(err.name, ErrorName::Error, "{depth} {bucket}");
            assert_eq!(err.message, NON_INTEGER_DEPTH_MESSAGE, "{depth} {bucket}");
            let chosen = select_best_batch(&stamps, 4096, SelectOptions::default());
            assert_eq!(chosen.unwrap_err().message, NON_INTEGER_DEPTH_MESSAGE);
        }
        // An integer written with an exponent is an integer.
        let exponent = read_stamps(reply("2.2e1", "1.6e1").as_bytes()).unwrap();
        assert!(exponent.get_all().is_ok());
    }
}
