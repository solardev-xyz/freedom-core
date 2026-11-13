//! `dapp-permissions.json` (the reference's `wallet/dapp-permissions.js`).
//!
//! Per key: `{ origin, connectedAt, lastUsed, walletIndex, chainId,
//! autoApprove: { signing, transactions: [{ to, selector, chainId,
//! maxValue? }] } }`, times in wall-clock milliseconds.
//!
//! **Q9's limits** (design 0012, "Limits on 'Always allow' (Q9)"): the core
//! answers only a limited rule, stored under `autoApprove.limited` as `{
//! signing: { grantedAt } | null, transactions: [{ to, selector, chainId,
//! maxValue, grantedAt }] }`, where an older build doesn't look. A rule
//! answers for 30 days of the wall clock from its `grantedAt`, and a
//! transaction rule for no more `value` than the send it came from. Today's
//! rules (`autoApprove.signing`, `autoApprove.transactions`) answer nothing
//! in the core (`rule-legacy`). An "Always allow" writes the limited rule
//! and clears today's rule it covers in the same change, so an older build
//! reads neither and prompts; turning a rule off clears both.

use fc_evm::U256;
use serde_json::{Map, Value};

use super::{
    Applied, Effect, MAX_TRANSACTION_RULES, Refused, Unreadable, assign, number, number_is,
    parse_sites, records_by_last_used, set_auto_approve, text_of, truthy,
};

/// Where Q9's limited rules live in an entry's `autoApprove` (design 0012,
/// "Limits on 'Always allow' (Q9)").
pub const LIMITED_FIELD: &str = "limited";

/// How long a limited rule answers: 30 days of the wall clock, in
/// milliseconds. Expired at exactly `grantedAt + RULE_TTL_MS`.
pub const RULE_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// A limited signing rule at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningRule {
    /// No limited rule (today's flag, if any, answers nothing).
    None,
    /// Within its 30 days.
    Active,
    /// Past its 30 days, or the wall clock is before its `grantedAt`.
    Expired,
}

/// What the key's limited transaction rules answer for one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionRule {
    /// No limited rule for the call (today's rules answer nothing).
    None,
    /// A rule for the call within its 30 days covers the `value`.
    Covered,
    /// The rules for the call within their 30 days cover less `value`.
    AboveMaxValue,
    /// Every rule for the call is past its 30 days, or the wall clock is
    /// before its `grantedAt`.
    Expired,
}

/// `grantedAt ≤ now < grantedAt + 30 days`, for a numeric `grantedAt`;
/// `None` when there is none.
fn active(rule: &Value, now_ms: u64) -> Option<bool> {
    let granted = rule.get("grantedAt").and_then(Value::as_f64)?;
    let now = now_ms as f64;
    Some(granted <= now && now < granted + RULE_TTL_MS as f64)
}

/// The reference's `DEFAULT_AUTO_APPROVE`.
fn default_auto_approve() -> Value {
    let mut rules = Map::new();
    rules.insert("signing".to_owned(), Value::Bool(false));
    rules.insert("transactions".to_owned(), Value::Array(Vec::new()));
    Value::Object(rules)
}

/// The dApp store.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DappStore {
    entries: Map<String, Value>,
}

/// An entry's transaction rules, today's and Q9's limited ones together.
pub(crate) fn rule_count(entry: &Value) -> usize {
    let rules = entry.get("autoApprove");
    let legacy = rules
        .and_then(|rules| rules.get("transactions"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let limited = rules
        .and_then(|rules| rules.get(LIMITED_FIELD))
        .and_then(|limited| limited.get("transactions"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    legacy + limited
}

/// `0x` and the lowercase hex of `bytes`, as the reference stores a rule's
/// `to` and `selector`.
pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(2 + bytes.len() * 2);
    text.push_str("0x");
    for byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0xf)]));
    }
    text
}

/// A new `autoApprove.limited`.
fn new_limited() -> Value {
    let mut limited = Map::new();
    limited.insert("signing".to_owned(), Value::Null);
    limited.insert("transactions".to_owned(), Value::Array(Vec::new()));
    Value::Object(limited)
}

/// The entry's `autoApprove`, an object: the reference's default where it
/// is falsy, and in place of one that isn't an object (which no build
/// reads a rule from).
fn auto_approve_mut(entry: &mut Value) -> Option<&mut Map<String, Value>> {
    if !entry.get("autoApprove").is_some_and(Value::is_object) {
        assign(entry, "autoApprove", default_auto_approve());
    }
    entry.get_mut("autoApprove").and_then(Value::as_object_mut)
}

/// `autoApprove.limited`, an object: new where it is missing or isn't one.
fn limited_mut(rules: &mut Map<String, Value>) -> Option<&mut Map<String, Value>> {
    if !rules.get(LIMITED_FIELD).is_some_and(Value::is_object) {
        rules.insert(LIMITED_FIELD.to_owned(), new_limited());
    }
    rules.get_mut(LIMITED_FIELD).and_then(Value::as_object_mut)
}

impl DappStore {
    /// An empty store: no file yet.
    pub fn new() -> Self {
        DappStore::default()
    }

    /// The store as its file's bytes give it.
    pub fn load(bytes: &[u8]) -> Result<Self, Unreadable> {
        let entries = parse_sites(bytes)?;
        if entries
            .values()
            .any(|entry| rule_count(entry) > MAX_TRANSACTION_RULES)
        {
            return Err(Unreadable::TooManyRules);
        }
        Ok(DappStore { entries })
    }

    /// The file's text, as the reference writes it, or the bound it would
    /// pass.
    pub fn text(&self) -> Result<String, Refused> {
        if self
            .entries
            .values()
            .any(|entry| rule_count(entry) > MAX_TRANSACTION_RULES)
        {
            return Err(Refused::TooManyRules);
        }
        text_of(&self.entries)
    }

    /// The key's entry (`getPermission`), as the file holds it.
    pub fn entry(&self, key: &str) -> Option<&Value> {
        self.entries.get(key)
    }

    /// Every entry, most recently used first (`getAllPermissions`).
    pub fn records(&self) -> Vec<&Value> {
        records_by_last_used(&self.entries)
    }

    /// The keys, in the file's order.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }

    /// Whether the key's grant exposes `account`: its `walletIndex` is that
    /// account (the reference's `grantExposes`, `permission.walletIndex ===
    /// walletIndex`). A rule, or a confirmed signature, answers only for the
    /// account the site is connected with.
    pub fn exposes(&self, key: &str, account: u32) -> bool {
        self.entries
            .get(key)
            .is_some_and(|entry| number_is(entry.get("walletIndex"), f64::from(account)))
    }

    /// A connect (`grantPermission`): the key's entry, new or replaced where
    /// it stands, with no rule.
    pub fn connect(
        &mut self,
        key: &str,
        account: u32,
        chain_id: u64,
        now_ms: u64,
    ) -> Applied<Value> {
        let mut entry = Map::new();
        entry.insert("origin".to_owned(), Value::String(key.to_owned()));
        entry.insert("connectedAt".to_owned(), number(now_ms));
        entry.insert("lastUsed".to_owned(), number(now_ms));
        entry.insert("walletIndex".to_owned(), Value::from(account));
        entry.insert("chainId".to_owned(), number(chain_id));
        entry.insert("autoApprove".to_owned(), default_auto_approve());
        let entry = Value::Object(entry);
        self.entries.insert(key.to_owned(), entry.clone());
        Applied::new(entry, Effect::Widening)
    }

    /// A disconnect (`revokePermission`): whether the key had an entry.
    pub fn revoke(&mut self, key: &str) -> Applied<bool> {
        if self.entries.shift_remove(key).is_some() {
            Applied::new(true, Effect::Narrowing)
        } else {
            Applied::new(false, Effect::Unchanged)
        }
    }

    /// An account deleted (`revokePermissionsForWalletIndex`): every key
    /// whose grant exposes it is revoked, and returned in the file's order.
    pub fn forget_account(&mut self, account: u32) -> Applied<Vec<String>> {
        let revoked: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| number_is(entry.get("walletIndex"), f64::from(account)))
            .map(|(key, _)| key.clone())
            .collect();
        if revoked.is_empty() {
            return Applied::new(revoked, Effect::Unchanged);
        }
        for key in &revoked {
            self.entries.shift_remove(key);
        }
        Applied::new(revoked, Effect::Narrowing)
    }

    /// A use (`updateLastUsed`): `lastUsed`, and the chain when one is
    /// given. Whether the key has an entry.
    pub fn touch(&mut self, key: &str, chain_id: Option<u64>, now_ms: u64) -> Applied<bool> {
        let Some(entry) = self.entries.get_mut(key) else {
            return Applied::new(false, Effect::Unchanged);
        };
        assign(entry, "lastUsed", number(now_ms));
        if let Some(chain_id) = chain_id {
            assign(entry, "chainId", number(chain_id));
        }
        Applied::new(true, Effect::Neutral)
    }

    /// Another account for a connected site (`updateWalletIndex`), with its
    /// `lastUsed`. Whether the key has an entry.
    pub fn set_account(&mut self, key: &str, account: u32, now_ms: u64) -> Applied<bool> {
        let Some(entry) = self.entries.get_mut(key) else {
            return Applied::new(false, Effect::Unchanged);
        };
        assign(entry, "walletIndex", Value::from(account));
        assign(entry, "lastUsed", number(now_ms));
        Applied::new(true, Effect::Widening)
    }

    /// The signing rule turned off: today's flag
    /// (`setSigningAutoApprove(key, false)`) and the limited rule
    /// (`limited.signing` null), in one change. Whether the key has an
    /// entry.
    pub fn signing_off(&mut self, key: &str) -> Applied<bool> {
        let Some(entry) = self.entries.get_mut(key) else {
            return Applied::new(false, Effect::Unchanged);
        };
        set_auto_approve(entry, default_auto_approve, "signing", false);
        if let Some(limited) = entry
            .get_mut("autoApprove")
            .and_then(|rules| rules.get_mut(LIMITED_FIELD))
            .filter(|limited| limited.is_object())
        {
            assign(limited, "signing", Value::Null);
        }
        Applied::new(true, Effect::Narrowing)
    }

    /// The transaction rules for one call turned off: today's
    /// (`removeTransactionAutoApprove`: every entry of
    /// `autoApprove.transactions` whose `to` and `selector`, in lowercase,
    /// and `chainId` are the call's) and the limited ones for it, in one
    /// change. Whether one was removed.
    ///
    /// A rule whose `to` or `selector` isn't a string matches nothing and
    /// stays (the reference throws on it, and removes none).
    pub fn remove_transaction_rule(
        &mut self,
        key: &str,
        to: &[u8; 20],
        selector: &[u8; 4],
        chain_id: u64,
    ) -> Applied<bool> {
        let Some(rules) = self
            .entries
            .get_mut(key)
            .and_then(|entry| entry.get_mut("autoApprove"))
        else {
            return Applied::new(false, Effect::Unchanged);
        };
        let legacy = if truthy(rules.get("transactions")) {
            rules
                .get_mut("transactions")
                .and_then(Value::as_array_mut)
                .map_or(0, |rules| remove_matching(rules, to, selector, chain_id))
        } else {
            0
        };
        let limited = rules
            .get_mut(LIMITED_FIELD)
            .and_then(|limited| limited.get_mut("transactions"))
            .and_then(Value::as_array_mut)
            .map_or(0, |rules| remove_matching(rules, to, selector, chain_id));
        if legacy + limited == 0 {
            Applied::new(false, Effect::Unchanged)
        } else {
            Applied::new(true, Effect::Narrowing)
        }
    }

    /// "Always allow" for the key's signatures (Q9): `limited.signing` is
    /// `{ grantedAt: now }`, and today's flag `false`, in one change, so an
    /// older build answers neither. Given again, the rule is replaced with
    /// a new `grantedAt`. Whether the key has an entry.
    pub fn allow_signing(&mut self, key: &str, now_ms: u64) -> Applied<bool> {
        let Some(rules) = self.entries.get_mut(key).and_then(auto_approve_mut) else {
            return Applied::new(false, Effect::Unchanged);
        };
        rules.insert("signing".to_owned(), Value::Bool(false));
        let Some(limited) = limited_mut(rules) else {
            return Applied::new(false, Effect::Unchanged);
        };
        let mut rule = Map::new();
        rule.insert("grantedAt".to_owned(), number(now_ms));
        limited.insert("signing".to_owned(), Value::Object(rule));
        Applied::new(true, Effect::Widening)
    }

    /// "Always allow" for one call, from a confirmed send of `value` (Q9):
    /// a limited rule `{ to, selector, chainId, maxValue, grantedAt }` for
    /// it, replacing one for the same call where it stands, and every entry
    /// of today's `autoApprove.transactions` the reference's
    /// `isTransactionAutoApproved` matches for the call removed, in one
    /// change. Whether the key has an entry.
    ///
    /// The bound ([`MAX_TRANSACTION_RULES`], both lists together) is
    /// checked when the change is written ([`DappStore::text`]).
    pub fn allow_transaction(
        &mut self,
        key: &str,
        to: &[u8; 20],
        selector: &[u8; 4],
        chain_id: u64,
        value: &U256,
        now_ms: u64,
    ) -> Applied<bool> {
        let Some(rules) = self.entries.get_mut(key).and_then(auto_approve_mut) else {
            return Applied::new(false, Effect::Unchanged);
        };
        if let Some(legacy) = rules.get_mut("transactions").and_then(Value::as_array_mut) {
            remove_matching(legacy, to, selector, chain_id);
        }
        let Some(limited) = limited_mut(rules) else {
            return Applied::new(false, Effect::Unchanged);
        };
        if !limited.get("transactions").is_some_and(Value::is_array) {
            limited.insert("transactions".to_owned(), Value::Array(Vec::new()));
        }
        let Some(list) = limited
            .get_mut("transactions")
            .and_then(Value::as_array_mut)
        else {
            return Applied::new(false, Effect::Unchanged);
        };
        let (to_text, selector_text) = (lower_hex(to), lower_hex(selector));
        let mut rule = Map::new();
        rule.insert("to".to_owned(), Value::String(to_text.clone()));
        rule.insert("selector".to_owned(), Value::String(selector_text.clone()));
        rule.insert("chainId".to_owned(), number(chain_id));
        rule.insert("maxValue".to_owned(), Value::String(value.to_decimal()));
        rule.insert("grantedAt".to_owned(), number(now_ms));
        let rule = Value::Object(rule);
        match list
            .iter()
            .position(|old| same_call(old, &to_text, &selector_text, chain_id))
        {
            Some(index) => {
                list[index] = rule;
                // Any other rule for the same call goes: one rule per call.
                let mut seen = 0usize;
                list.retain(|old| {
                    let same = same_call(old, &to_text, &selector_text, chain_id);
                    seen += usize::from(same);
                    !same || seen == 1
                });
            }
            None => list.push(rule),
        }
        Applied::new(true, Effect::Widening)
    }

    /// The key's limited signing rule at `now_ms` (the wall clock). Today's
    /// flag answers nothing.
    pub fn signing_rule(&self, key: &str, now_ms: u64) -> SigningRule {
        let rule = self
            .entries
            .get(key)
            .and_then(|entry| entry.get("autoApprove"))
            .and_then(|rules| rules.get(LIMITED_FIELD))
            .and_then(|limited| limited.get("signing"));
        match rule.and_then(|rule| active(rule, now_ms)) {
            None => SigningRule::None,
            Some(true) => SigningRule::Active,
            Some(false) => SigningRule::Expired,
        }
    }

    /// What the key's limited transaction rules answer for a call of
    /// `value` at `now_ms` (the wall clock). Today's rules answer nothing.
    /// A rule's `maxValue` caps native `value` only, per call.
    pub fn transaction_rule(
        &self,
        key: &str,
        to: &[u8; 20],
        selector: &[u8; 4],
        chain_id: u64,
        value: &U256,
        now_ms: u64,
    ) -> TransactionRule {
        let Some(list) = self
            .entries
            .get(key)
            .and_then(|entry| entry.get("autoApprove"))
            .and_then(|rules| rules.get(LIMITED_FIELD))
            .and_then(|limited| limited.get("transactions"))
            .and_then(Value::as_array)
        else {
            return TransactionRule::None;
        };
        let (to, selector) = (lower_hex(to), lower_hex(selector));
        let mut answer = TransactionRule::None;
        for rule in list
            .iter()
            .filter(|rule| same_call(rule, &to, &selector, chain_id))
        {
            match active(rule, now_ms) {
                Some(true) => {
                    let max = rule
                        .get("maxValue")
                        .and_then(Value::as_str)
                        .and_then(U256::parse_decimal);
                    if max.is_some_and(|max| *value <= max) {
                        return TransactionRule::Covered;
                    }
                    answer = TransactionRule::AboveMaxValue;
                }
                Some(false) if answer == TransactionRule::None => answer = TransactionRule::Expired,
                _ => {}
            }
        }
        answer
    }
}

/// Whether a stored rule is for the call: `to` and `selector` the same in
/// lowercase, and the same `chainId` (the reference's matching, in
/// `isTransactionAutoApproved`'s `sameCall` and in
/// `removeTransactionAutoApprove`).
pub(crate) fn same_call(rule: &Value, to: &str, selector: &str, chain_id: u64) -> bool {
    let text = |field: &str| {
        rule.get(field)
            .and_then(Value::as_str)
            .map(str::to_lowercase)
    };
    text("to").as_deref() == Some(to)
        && text("selector").as_deref() == Some(selector)
        && number_is(rule.get("chainId"), chain_id as f64)
}

/// Removes the rules for the call, keeping the others in order; how many
/// went.
pub(crate) fn remove_matching(
    rules: &mut Vec<Value>,
    to: &[u8; 20],
    selector: &[u8; 4],
    chain_id: u64,
) -> usize {
    let (to, selector) = (lower_hex(to), lower_hex(selector));
    let before = rules.len();
    rules.retain(|rule| !same_call(rule, &to, &selector, chain_id));
    before - rules.len()
}
