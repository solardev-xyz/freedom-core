//! `dapp-permissions.json` (the reference's `wallet/dapp-permissions.js`).
//!
//! Per key: `{ origin, connectedAt, lastUsed, walletIndex, chainId,
//! autoApprove: { signing, transactions: [{ to, selector, chainId,
//! maxValue? }] } }`, times in wall-clock milliseconds. Q9's limited rules
//! go under `autoApprove.limited`, where an older build doesn't look.

use serde_json::{Map, Value};

use super::{
    Applied, Effect, MAX_TRANSACTION_RULES, Refused, Unreadable, assign, number, number_is,
    parse_sites, records_by_last_used, set_auto_approve, text_of, truthy,
};

/// Where Q9's limited rules live in an entry's `autoApprove` (design 0012,
/// "Limits on 'Always allow' (Q9)").
pub const LIMITED_FIELD: &str = "limited";

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

    /// Today's signing flag turned off (`setSigningAutoApprove(key,
    /// false)`). Whether the key has an entry.
    pub fn signing_off(&mut self, key: &str) -> Applied<bool> {
        let Some(entry) = self.entries.get_mut(key) else {
            return Applied::new(false, Effect::Unchanged);
        };
        set_auto_approve(entry, default_auto_approve, "signing", false);
        Applied::new(true, Effect::Narrowing)
    }

    /// Today's transaction rules for one call turned off
    /// (`removeTransactionAutoApprove`): every entry of
    /// `autoApprove.transactions` whose `to` and `selector`, in lowercase,
    /// and `chainId` are the call's. Whether one was removed.
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
        let removed = self
            .entries
            .get_mut(key)
            .and_then(|entry| entry.get_mut("autoApprove"))
            .filter(|rules| truthy(rules.get("transactions")))
            .and_then(|rules| rules.get_mut("transactions"))
            .and_then(Value::as_array_mut)
            .map_or(0, |rules| remove_matching(rules, to, selector, chain_id));
        if removed == 0 {
            Applied::new(false, Effect::Unchanged)
        } else {
            Applied::new(true, Effect::Narrowing)
        }
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
