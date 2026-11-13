//! `radicle-permissions.json` (the reference's
//! `radicle/radicle-permissions.js`).
//!
//! Per key: `{ origin, connectedAt, lastUsed, signing, autoApprove: { node,
//! signing } }`, times in wall-clock milliseconds; `lastUsed` written at
//! most once a minute. Q9's limits don't cover it: its rules keep today's,
//! R-6 included.

use super::{
    Applied, Effect, JsValue, Refused, ToPrimitiveError, Unreadable, assign, number, object,
    parse_sites, records_by_last_used, remove, set_auto_approve, text_of,
};
use crate::js;

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

fn default_auto_approve() -> JsValue {
    let mut rules = object();
    for flag in RadicleFlag::ALL {
        rules.set(flag.name(), JsValue::Bool(false));
    }
    rules
}

/// The Radicle store.
#[derive(Debug, Clone, PartialEq)]
pub struct RadicleStore {
    entries: JsValue,
}

impl Default for RadicleStore {
    fn default() -> Self {
        RadicleStore { entries: object() }
    }
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
    pub fn entry(&self, key: &str) -> Option<&JsValue> {
        self.entries.get(key)
    }

    /// Every entry, most recently used first (`getAllPermissions`), or the
    /// reference's throw.
    pub fn records(&self) -> Result<Vec<&JsValue>, ToPrimitiveError> {
        records_by_last_used(&self.entries)
    }

    /// A connect (`grantPermission`): new or replaced where it stands, with
    /// no signing grant and no rule.
    pub fn connect(&mut self, key: &str, now_ms: u64) -> Applied<JsValue> {
        let mut entry = object();
        entry.set("origin", JsValue::string(key));
        entry.set("connectedAt", number(now_ms));
        entry.set("lastUsed", number(now_ms));
        entry.set("signing", JsValue::Bool(false));
        entry.set("autoApprove", default_auto_approve());
        self.entries.set(key, entry.clone());
        Applied::new(entry, Effect::Widening)
    }

    pub fn revoke(&mut self, key: &str) -> Applied<bool> {
        if remove(&mut self.entries, key).is_some() {
            Applied::new(true, Effect::Narrowing)
        } else {
            Applied::new(false, Effect::Unchanged)
        }
    }

    /// A use (`updateLastUsed`): written only once the stored `lastUsed` is
    /// a minute old. `now - (lastUsed || 0) < 60000` writes nothing, as JS
    /// computes it: a `lastUsed` ahead of the clock, or a numeric string a
    /// minute fresh, included; a `NaN` (a non-numeric `lastUsed`) is never
    /// below, and writes. Whether the key has an entry, or the reference's
    /// throw (a `lastUsed` with its own `toString`), with nothing written.
    pub fn touch(&mut self, key: &str, now_ms: u64) -> Result<Applied<bool>, ToPrimitiveError> {
        let Some(entry) = self.entries.get_mut(key) else {
            return Ok(Applied::new(false, Effect::Unchanged));
        };
        let last = match entry.get("lastUsed") {
            Some(last) if last.truthy() => js::to_number(last)?,
            _ => 0.0,
        };
        if (now_ms as f64) - last < LAST_USED_FRESH_MS as f64 {
            return Ok(Applied::new(true, Effect::Unchanged));
        }
        assign(entry, "lastUsed", number(now_ms));
        Ok(Applied::new(true, Effect::Neutral))
    }

    /// Whether the key holds the signing grant (`hasSigningGrant`: `signing
    /// === true`).
    pub fn has_signing(&self, key: &str) -> bool {
        self.entries.get(key).and_then(|entry| entry.get("signing")) == Some(&JsValue::Bool(true))
    }

    /// The signing grant (`grantSigning`), for a connected site.
    pub fn grant_signing(&mut self, key: &str) -> Applied<bool> {
        let Some(entry) = self.entries.get_mut(key) else {
            return Applied::new(false, Effect::Unchanged);
        };
        assign(entry, "signing", JsValue::Bool(true));
        Applied::new(true, Effect::Widening)
    }

    /// Whether the flag is on (`getAutoApprove`: `=== true`).
    pub fn flag(&self, key: &str, flag: RadicleFlag) -> bool {
        self.entries
            .get(key)
            .and_then(|entry| entry.get("autoApprove"))
            .and_then(|rules| rules.get(flag.name()))
            == Some(&JsValue::Bool(true))
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
