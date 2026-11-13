//! `radicle-permissions.json` (the reference's
//! `radicle/radicle-permissions.js`).
//!
//! Per key: `{ origin, connectedAt, lastUsed, signing, autoApprove: { node,
//! signing } }`, times in wall-clock milliseconds; `lastUsed` written at
//! most once a minute. Q9's limits don't cover it: its rules keep today's,
//! R-6 included.

use serde_json::{Map, Value};

use super::{
    Applied, Effect, Refused, Unreadable, assign, number, parse_sites, records_by_last_used,
    set_auto_approve, text_of, truthy,
};

/// How fresh a `lastUsed` stays unwritten (the reference's 60 s).
pub const LAST_USED_FRESH_MS: u64 = 60_000;

/// A Radicle rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RadicleFlag {
    /// Seeding and unseeding without a prompt.
    Node,
    /// COB writes without a prompt, within R-6's limit.
    Signing,
}

impl RadicleFlag {
    pub const ALL: [RadicleFlag; 2] = [RadicleFlag::Node, RadicleFlag::Signing];

    pub fn name(self) -> &'static str {
        match self {
            RadicleFlag::Node => "node",
            RadicleFlag::Signing => "signing",
        }
    }

    pub fn from_name(name: &str) -> Option<RadicleFlag> {
        RadicleFlag::ALL
            .into_iter()
            .find(|flag| flag.name() == name)
    }
}

fn default_auto_approve() -> Value {
    let mut rules = Map::new();
    for flag in RadicleFlag::ALL {
        rules.insert(flag.name().to_owned(), Value::Bool(false));
    }
    Value::Object(rules)
}

/// The Radicle store.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RadicleStore {
    entries: Map<String, Value>,
}

impl RadicleStore {
    pub fn new() -> Self {
        RadicleStore::default()
    }

    pub fn load(bytes: &[u8]) -> Result<Self, Unreadable> {
        Ok(RadicleStore {
            entries: parse_sites(bytes)?,
        })
    }

    pub fn text(&self) -> Result<String, Refused> {
        text_of(&self.entries)
    }

    /// The key's entry (`getPermission`): the site is connected.
    pub fn entry(&self, key: &str) -> Option<&Value> {
        self.entries.get(key)
    }

    pub fn records(&self) -> Vec<&Value> {
        records_by_last_used(&self.entries)
    }

    /// A connect (`grantPermission`): new or replaced where it stands, with
    /// no signing grant and no rule.
    pub fn connect(&mut self, key: &str, now_ms: u64) -> Applied<Value> {
        let mut entry = Map::new();
        entry.insert("origin".to_owned(), Value::String(key.to_owned()));
        entry.insert("connectedAt".to_owned(), number(now_ms));
        entry.insert("lastUsed".to_owned(), number(now_ms));
        entry.insert("signing".to_owned(), Value::Bool(false));
        entry.insert("autoApprove".to_owned(), default_auto_approve());
        let entry = Value::Object(entry);
        self.entries.insert(key.to_owned(), entry.clone());
        Applied::new(entry, Effect::Widening)
    }

    pub fn revoke(&mut self, key: &str) -> Applied<bool> {
        if self.entries.shift_remove(key).is_some() {
            Applied::new(true, Effect::Narrowing)
        } else {
            Applied::new(false, Effect::Unchanged)
        }
    }

    /// A use (`updateLastUsed`): written only once the stored `lastUsed` is
    /// a minute old (`now - (lastUsed || 0) < 60000` writes nothing, a
    /// `lastUsed` ahead of the clock included). Whether the key has an
    /// entry.
    pub fn touch(&mut self, key: &str, now_ms: u64) -> Applied<bool> {
        let Some(entry) = self.entries.get_mut(key) else {
            return Applied::new(false, Effect::Unchanged);
        };
        // `lastUsed || 0`; a value that isn't a number reads as 0 (JS would
        // coerce a numeric string).
        let last = if truthy(entry.get("lastUsed")) {
            entry.get("lastUsed").and_then(Value::as_f64).unwrap_or(0.0)
        } else {
            0.0
        };
        if (now_ms as f64) - last < LAST_USED_FRESH_MS as f64 {
            return Applied::new(true, Effect::Unchanged);
        }
        assign(entry, "lastUsed", number(now_ms));
        Applied::new(true, Effect::Neutral)
    }

    /// Whether the key holds the signing grant (`hasSigningGrant`: `signing
    /// === true`).
    pub fn has_signing(&self, key: &str) -> bool {
        self.entries.get(key).and_then(|entry| entry.get("signing")) == Some(&Value::Bool(true))
    }

    /// The signing grant (`grantSigning`), for a connected site.
    pub fn grant_signing(&mut self, key: &str) -> Applied<bool> {
        let Some(entry) = self.entries.get_mut(key) else {
            return Applied::new(false, Effect::Unchanged);
        };
        assign(entry, "signing", Value::Bool(true));
        Applied::new(true, Effect::Widening)
    }

    /// Whether the flag is on (`getAutoApprove`: `=== true`).
    pub fn flag(&self, key: &str, flag: RadicleFlag) -> bool {
        self.entries
            .get(key)
            .and_then(|entry| entry.get("autoApprove"))
            .and_then(|rules| rules.get(flag.name()))
            == Some(&Value::Bool(true))
    }

    /// A flag turned on or off (`setAutoApprove`).
    pub fn set_flag(&mut self, key: &str, flag: RadicleFlag, enabled: bool) -> Applied<bool> {
        let Some(entry) = self.entries.get_mut(key) else {
            return Applied::new(false, Effect::Unchanged);
        };
        set_auto_approve(entry, default_auto_approve, flag.name(), enabled);
        let effect = if enabled {
            Effect::Widening
        } else {
            Effect::Narrowing
        };
        Applied::new(true, effect)
    }
}
