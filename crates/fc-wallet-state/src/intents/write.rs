//! The live writes (PRF-5e-2b): `intent-store.js`'s write methods as pure
//! functions over the loaded state.
//!
//! Each takes the method's argument as the reference does (an object whose
//! values are checked as the reference checks them), main's run id (design
//! 0013: main passes it on every write) and the clock's time, and gives
//! the line the reference appends ([`Write`]) or its refusal, code and
//! message. The daemon then asks [`Intents::room`] (compacting first when
//! it answers [`Room::Compact`]), appends the line, and [`Intents::apply`]s
//! it. Ids the store names (`crypto.randomUUID`) come from the caller.

use fc_evm::decode_signed;
use fc_json::{JsString, JsValue};

use super::{
    Apply, Intents, Mode, OUTCOME_REASON_CLASS, OUTCOME_SOURCE, Refusal, State, bytes_of,
    context_record, fields_of, invalid, is_outcome_text, line_bytes, normalize_context, object,
    outcome_line_max, refusal, require_count, terminal_line_max, unknown, view,
};

/// A write the store checked and would append: its line, and what applying
/// it changes.
#[derive(Debug, Clone)]
pub struct Write {
    record: JsValue,
    apply: Apply,
}

impl Write {
    /// The line's record, as the journal appends it.
    pub fn record(&self) -> &JsValue {
        &self.record
    }

    fn kind(&self) -> &str {
        self.record
            .get("type")
            .and_then(JsValue::as_str)
            .unwrap_or_default()
    }
}

/// Whether an admitted line fits the file (`admit`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Room {
    /// Append it.
    Fits,
    /// Compact the file first ([`Intents::compaction`], then
    /// [`Intents::compacted`]), then ask again with `compacted` set.
    Compact,
}

/// An origin [`Intents::withdraw_origin`] took, to put back if the
/// compaction that records it fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawn {
    id: JsString,
    origin: JsString,
}

fn store_full() -> Refusal {
    refusal(
        "INTENT_STORE_FULL",
        "The wallet's records of payments waiting to confirm are full. \
         Wait for some of them to confirm before sending another.",
    )
}

fn arg(params: &JsValue, key: &str) -> JsValue {
    params.get(key).cloned().unwrap_or(JsValue::Undefined)
}

/// `typeof value === 'string' ? value.toLowerCase() : value`. ASCII is
/// enough: the value is kept only if it is hex, and no other character
/// lowercases to one.
fn lower(value: JsValue) -> JsValue {
    match value.as_str() {
        Some(s) => JsValue::string(s.to_ascii_lowercase()),
        None => value,
    }
}

/// `${value}` and `String(value)`.
fn shown(value: &JsValue) -> Result<String, Refusal> {
    value
        .js_string()
        .map_err(|_| refusal("", "Cannot convert object to primitive value"))
}

/// `stamp(type, fields)`: the line's type, main's run and the time first.
fn stamp(kind: &str, run: &JsString, at: f64, fields: Vec<(&str, JsValue)>) -> JsValue {
    let mut props = vec![
        ("type", JsValue::string(kind)),
        ("run", JsValue::String(run.clone())),
        ("at", JsValue::Number(at)),
    ];
    props.extend(fields);
    object(props)
}

/// `sameHashes`' expected list: each value as `String(h).toLowerCase()`.
fn expected_hashes(hashes: &[JsValue]) -> Result<Vec<String>, Refusal> {
    hashes
        .iter()
        .map(|h| shown(h).map(|s| s.to_ascii_lowercase()))
        .collect()
}

impl Intents {
    /// `requireIntent(id)` for an argument as given.
    fn known(&self, id: &JsValue) -> Result<&super::Intent, Refusal> {
        match id.as_js_string().and_then(|id| self.by_id.get(id)) {
            Some(intent) => Ok(intent),
            None => Err(unknown(shown(id)?)),
        }
    }

    /// A write's condition (`expect`): the intent has exactly these hashes.
    fn require_hashes(
        &self,
        id: &JsValue,
        expected: &[String],
        message: &str,
    ) -> Result<(), Refusal> {
        let intent = self.known(id)?;
        let same = intent.hashes.len() == expected.len()
            && intent
                .hashes
                .iter()
                .zip(expected)
                .all(|(e, h)| &e.hash == h);
        if same {
            Ok(())
        } else {
            Err(refusal("INTENT_CHANGED", message))
        }
    }

    /// `prepare(record, LIVE, lock)`.
    fn prepare_live(&self, record: JsValue, at: f64, lock: bool) -> Result<Write, Refusal> {
        require_count(record.get("at"), "time")?;
        let mode = Mode { live: true, lock };
        let kind = record
            .get("type")
            .and_then(JsValue::as_str)
            .unwrap_or_default();
        let apply = self.prepare(kind, &record, at, mode)?;
        Ok(Write { record, apply })
    }

    /// `commit({ intentId, chainId, sender, nonce, hash, raw, via,
    /// context })`. An original's id is `new_id`, which the caller names
    /// (the reference's `crypto.randomUUID()`).
    pub fn commit(
        &self,
        run: &JsString,
        at: f64,
        new_id: &JsString,
        params: &JsValue,
    ) -> Result<Write, Refusal> {
        let via = arg(params, "via");
        let original = via.as_str() == Some("original");
        if original && !matches!(arg(params, "intentId"), JsValue::Undefined) {
            return Err(invalid(
                "the store names a new intent: commit an original without an intentId",
            ));
        }
        let raw = lower(arg(params, "raw"));
        let intent_id = if original {
            JsValue::String(new_id.clone())
        } else {
            arg(params, "intentId")
        };
        let mut fields = vec![
            ("intent_id", intent_id),
            ("chain_id", arg(params, "chainId")),
            ("sender", lower(arg(params, "sender"))),
            ("nonce", arg(params, "nonce")),
            ("hash", lower(arg(params, "hash"))),
            ("raw", raw.clone()),
            ("via", via),
        ];
        if original {
            let context = normalize_context(params.get("context"))?;
            fields.push(("context", context_record(&context)));
        }
        // Filled in from the decoded bytes, so they always agree.
        let decoded = raw
            .as_str()
            .and_then(|raw| decode_signed(&bytes_of(raw)).ok())
            .map_or(JsValue::Null, |tx| fields_of(&tx));
        fields.push(("fields", decoded));
        self.prepare_live(stamp("commit", run, at, fields), at, false)
    }

    /// `handoff(intentId, hash)`: the latest hash unless `hash` names one.
    /// The handoff's id is `new_id`; its bytes are [`Intents::signed`].
    pub fn handoff(
        &self,
        run: &JsString,
        at: f64,
        new_id: &JsString,
        params: &JsValue,
    ) -> Result<Write, Refusal> {
        let intent_id = arg(params, "intentId");
        let intent = self.known(&intent_id)?;
        let chosen = match arg(params, "hash") {
            hash @ JsValue::String(_) => lower(hash),
            _ => intent
                .hashes
                .last()
                .map_or(JsValue::Null, |e| JsValue::string(e.hash.as_str())),
        };
        let record = stamp(
            "handoff",
            run,
            at,
            vec![
                ("intent_id", intent_id),
                ("hash", chosen),
                ("handoff_id", JsValue::String(new_id.clone())),
            ],
        );
        self.prepare_live(record, at, false)
    }

    /// `outcome({ intentId, handoffId, outcome, source, reasonClass })`.
    /// None: the store no longer owes it, so nothing is written (the
    /// reference answers the intent, or null).
    pub fn outcome(
        &self,
        run: &JsString,
        at: f64,
        params: &JsValue,
    ) -> Result<Option<Write>, Refusal> {
        let intent_id = arg(params, "intentId");
        let handoff_id = arg(params, "handoffId");
        let handoff = intent_id
            .as_js_string()
            .and_then(|id| self.by_id.get(id))
            .zip(handoff_id.as_js_string())
            .and_then(|(intent, h)| intent.handoff(h));
        let text = |key, limit| {
            let value = arg(params, key);
            if is_outcome_text(&value, limit) {
                value
            } else {
                JsValue::Null
            }
        };
        let record = stamp(
            "outcome",
            run,
            at,
            vec![
                ("intent_id", intent_id),
                (
                    "hash",
                    handoff.map_or(JsValue::Null, |h| JsValue::string(h.hash.as_str())),
                ),
                ("handoff_id", handoff_id),
                ("outcome", arg(params, "outcome")),
                ("source", text("source", OUTCOME_SOURCE)),
                ("reason_class", text("reasonClass", OUTCOME_REASON_CLASS)),
            ],
        );
        require_count(record.get("at"), "time")?;
        let live = Mode {
            live: true,
            lock: false,
        };
        Ok(self
            .prepare_outcome(&record, at, live)?
            .map(|apply| Write { record, apply }))
    }

    /// `settle({ intentId, label, hash, block, hashes })`: with `hashes`,
    /// only while the intent has exactly those (else `INTENT_CHANGED`).
    pub fn settle(&self, run: &JsString, at: f64, params: &JsValue) -> Result<Write, Refusal> {
        let hash = match arg(params, "hash") {
            hash @ JsValue::String(_) => lower(hash),
            JsValue::Undefined => JsValue::Null,
            other => other,
        };
        let intent_id = arg(params, "intentId");
        let record = stamp(
            "settle",
            run,
            at,
            vec![
                ("intent_id", intent_id.clone()),
                ("label", arg(params, "label")),
                ("hash", hash),
                ("block", arg(params, "block")),
            ],
        );
        let hashes = arg(params, "hashes");
        if hashes.truthy() {
            let Some(hashes) = hashes.as_array() else {
                return Err(refusal("", "hashes.map is not a function"));
            };
            let expected = expected_hashes(hashes)?;
            self.require_hashes(
                &intent_id,
                &expected,
                "The payment changed while it was being checked; it will be checked again.",
            )?;
        }
        self.prepare_live(record, at, false)
    }

    /// `void(intentId, lock)`: `lock` is main's word that it holds the
    /// account's reservation lock. Once applied, the reference compacts
    /// the file, and a failure there is only logged.
    pub fn void(
        &self,
        run: &JsString,
        at: f64,
        params: &JsValue,
        lock: bool,
    ) -> Result<Write, Refusal> {
        let record = stamp(
            "void",
            run,
            at,
            vec![("intent_id", arg(params, "intentId"))],
        );
        self.prepare_live(record, at, lock)
    }

    /// `retire({ intentId, block, hashes }, lock)`: only for the hashes the
    /// user saw, under the account's lock (main's word).
    pub fn retire(
        &self,
        run: &JsString,
        at: f64,
        params: &JsValue,
        lock: bool,
    ) -> Result<Write, Refusal> {
        let hashes = arg(params, "hashes");
        let Some(hashes) = hashes.as_array().filter(|h| !h.is_empty()) else {
            return Err(invalid("closing a payment names the hashes the user saw"));
        };
        let intent_id = arg(params, "intentId");
        let record = stamp(
            "retire",
            run,
            at,
            vec![
                ("intent_id", intent_id.clone()),
                ("block", arg(params, "block")),
            ],
        );
        let expected = expected_hashes(hashes)?;
        self.require_hashes(
            &intent_id,
            &expected,
            "The payment changed since it was shown; it was not closed. Check it again.",
        )?;
        self.prepare_live(record, at, lock)
    }

    /// `track({ intentId, bracket, unreadSince })`.
    pub fn track(&self, run: &JsString, at: f64, params: &JsValue) -> Result<Write, Refusal> {
        // `bracket && { number, hash }`, null by default.
        let bracket = match arg(params, "bracket") {
            JsValue::Undefined => JsValue::Null,
            b if b.truthy() => object(vec![
                ("number", arg(&b, "number")),
                ("hash", lower(arg(&b, "hash"))),
            ]),
            falsy => falsy,
        };
        let unread_since = match arg(params, "unreadSince") {
            JsValue::Undefined => JsValue::Null,
            since => since,
        };
        let record = stamp(
            "track",
            run,
            at,
            vec![
                ("intent_id", arg(params, "intentId")),
                ("bracket", bracket),
                ("unread_since", unread_since),
            ],
        );
        self.prepare_live(record, at, false)
    }

    /// `admission(record)`: the budget before and after the line, and what
    /// is owed after it.
    fn admission(&self, write: &Write) -> (usize, usize, usize) {
        let before = self.budget();
        let intent = |id: &JsString| self.by_id.get(id);
        match &write.apply {
            Apply::Handoff { id, .. } => {
                let delta = intent(id).map_or((0, 0), |i| {
                    (
                        Self::intent_budget(i, None, 0),
                        Self::intent_budget(i, None, line_bytes(&write.record)),
                    )
                });
                (
                    before,
                    before - delta.0 + delta.1,
                    self.owed() + outcome_line_max(),
                )
            }
            Apply::Replacement { id, entry, .. } => {
                let delta = intent(id).map_or((0, 0), |i| {
                    (
                        Self::intent_budget(i, None, 0),
                        Self::intent_budget(i, Some(entry), 0),
                    )
                });
                (before, before - delta.0 + delta.1, self.owed())
            }
            Apply::Original(fresh) => (
                before,
                before + Self::intent_budget(fresh, None, 0),
                self.owed() + terminal_line_max(),
            ),
            _ => (before, before, self.owed()),
        }
    }

    /// `admit(record)` for a file of `file_bytes`: a commit or a handoff
    /// that grows the budget past the limit is refused, and a line fits
    /// when the file, the line and what is owed after it stay within the
    /// limit. A track only has to fit. When it doesn't, the file is
    /// compacted and the line asked about again (`compacted`), and then
    /// refused if it still doesn't. Owed lines (outcome, settle, void,
    /// retire) always fit.
    pub fn room(&self, write: &Write, file_bytes: u64, compacted: bool) -> Result<Room, Refusal> {
        let owed = match write.kind() {
            "track" => self.owed(),
            "commit" | "handoff" => {
                let (before, after, owed) = self.admission(write);
                let limit = self.limits.journal_bytes;
                if after as u64 > limit && after > before {
                    return Err(store_full());
                }
                owed
            }
            _ => return Ok(Room::Fits),
        };
        let line = line_bytes(&write.record) as u64;
        if file_bytes.saturating_add(line).saturating_add(owed as u64) <= self.limits.journal_bytes
        {
            Ok(Room::Fits)
        } else if compacted {
            Err(store_full())
        } else {
            Ok(Room::Compact)
        }
    }

    /// Applies a write whose line is on disk: the intent as the store holds
    /// it after (`view`), as the reference's write answers.
    pub fn apply(&mut self, write: Write) -> Option<JsValue> {
        let id = self.apply_one(write.apply);
        self.by_id.get(&id).map(view)
    }

    /// The signed bytes the intent keeps for `hash` (a handoff's answer).
    pub fn signed(&self, intent_id: &str, hash: &str) -> Option<&str> {
        self.by_id
            .get(&JsString::from(intent_id))?
            .hashes
            .iter()
            .find(|e| e.hash == hash)?
            .raw
            .as_deref()
    }

    /// `withdrawOrigin(intentId)`: a held intent's context loses its
    /// origin. None (the reference's false) for an intent not held or with
    /// no origin. The file is then rewritten from the state
    /// ([`Intents::compaction`]); if that fails, [`Intents::restore_origin`].
    /// Its size stays cached as it was until it has another hash.
    pub fn withdraw_origin(&mut self, intent_id: &str) -> Option<Withdrawn> {
        let intent = self.by_id.get_mut(&JsString::from(intent_id))?;
        if intent.state != State::Held {
            return None;
        }
        let origin = intent.context.as_mut()?.origin.take()?;
        Some(Withdrawn {
            id: intent.id.clone(),
            origin,
        })
    }

    /// Puts back an origin whose withdrawal couldn't be written.
    pub fn restore_origin(&mut self, withdrawn: Withdrawn) {
        if let Some(context) = self
            .by_id
            .get_mut(&withdrawn.id)
            .and_then(|i| i.context.as_mut())
        {
            context.origin = Some(withdrawn.origin);
        }
    }
}
