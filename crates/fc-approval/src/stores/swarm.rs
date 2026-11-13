//! `swarm-permissions.json` (the reference's `swarm/swarm-permissions.js`).
//!
//! Per key: `{ origin, connectedAt, lastUsed, autoApprove: { publish, feeds,
//! signing, messaging }, messaging?: { grantedAt } }`, times in wall-clock
//! milliseconds. Q9's limits don't cover it: its flags keep today's rules.

use super::{
    Applied, Effect, JsValue, Refused, ToPrimitiveError, Unreadable, assign, number, object,
    parse_sites, records_by_last_used, remove, set_auto_approve, text_of, truthy,
};

/// A Swarm rule ("Always allow" for one kind of request).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwarmFlag {
    Publish,
    Feeds,
    Signing,
    Messaging,
}

impl SwarmFlag {
    pub const ALL: [SwarmFlag; 4] = [
        SwarmFlag::Publish,
        SwarmFlag::Feeds,
        SwarmFlag::Signing,
        SwarmFlag::Messaging,
    ];

    /// Its field in `autoApprove`.
    pub fn name(self) -> &'static str {
        match self {
            SwarmFlag::Publish => "publish",
            SwarmFlag::Feeds => "feeds",
            SwarmFlag::Signing => "signing",
            SwarmFlag::Messaging => "messaging",
        }
    }

    /// The flag a name gives; none for another name (the reference's
    /// `VALID_AUTO_APPROVE_TYPES`, which answers `false` for one).
    pub fn from_name(name: &str) -> Option<SwarmFlag> {
        SwarmFlag::ALL.into_iter().find(|flag| flag.name() == name)
    }
}

/// The reference's `DEFAULT_AUTO_APPROVE`.
fn default_auto_approve() -> JsValue {
    let mut rules = object();
    for flag in SwarmFlag::ALL {
        rules.set(flag.name(), JsValue::Bool(false));
    }
    rules
}

/// The Swarm store.
#[derive(Debug, Clone, PartialEq)]
pub struct SwarmStore {
    entries: JsValue,
}

impl Default for SwarmStore {
    fn default() -> Self {
        SwarmStore { entries: object() }
    }
}

impl SwarmStore {
    pub fn new() -> Self {
        SwarmStore::default()
    }

    pub fn load(bytes: &[u8]) -> Result<Self, Unreadable> {
        Ok(SwarmStore {
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

    /// A connect (`grantPermission`): the key's entry, new or replaced where
    /// it stands, with no rule and no messaging grant.
    pub fn connect(&mut self, key: &str, now_ms: u64) -> Applied<JsValue> {
        let mut entry = object();
        entry.set("origin", JsValue::string(key));
        entry.set("connectedAt", number(now_ms));
        entry.set("lastUsed", number(now_ms));
        entry.set("autoApprove", default_auto_approve());
        self.entries.set(key, entry.clone());
        Applied::new(entry, Effect::Widening)
    }

    /// A disconnect (`revokePermission`): whether the key had an entry.
    pub fn revoke(&mut self, key: &str) -> Applied<bool> {
        if remove(&mut self.entries, key).is_some() {
            Applied::new(true, Effect::Narrowing)
        } else {
            Applied::new(false, Effect::Unchanged)
        }
    }

    /// A use (`updateLastUsed`). Whether the key has an entry.
    pub fn touch(&mut self, key: &str, now_ms: u64) -> Applied<bool> {
        let Some(entry) = self.entries.get_mut(key) else {
            return Applied::new(false, Effect::Unchanged);
        };
        assign(entry, "lastUsed", number(now_ms));
        Applied::new(true, Effect::Neutral)
    }

    /// Whether the flag is on (`getAutoApprove`: `=== true`).
    pub fn flag(&self, key: &str, flag: SwarmFlag) -> bool {
        self.entries
            .get(key)
            .and_then(|entry| entry.get("autoApprove"))
            .and_then(|rules| rules.get(flag.name()))
            == Some(&JsValue::Bool(true))
    }

    /// A flag turned on or off (`setAutoApprove`). Whether the key has an
    /// entry.
    pub fn set_flag(&mut self, key: &str, flag: SwarmFlag, enabled: bool) -> Applied<bool> {
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

    /// Whether the key holds the messaging grant (`hasMessagingGrant`:
    /// `!!permission.messaging`).
    pub fn has_messaging(&self, key: &str) -> bool {
        truthy(
            self.entries
                .get(key)
                .and_then(|entry| entry.get("messaging")),
        )
    }

    /// The messaging grant (`grantMessaging`), for a connected site.
    pub fn grant_messaging(&mut self, key: &str, now_ms: u64) -> Applied<bool> {
        let Some(entry) = self.entries.get_mut(key) else {
            return Applied::new(false, Effect::Unchanged);
        };
        let mut grant = object();
        grant.set("grantedAt", number(now_ms));
        assign(entry, "messaging", grant);
        Applied::new(true, Effect::Widening)
    }

    /// The messaging grant revoked (`revokeMessaging`), and its rule turned
    /// off. Whether the key held it.
    pub fn revoke_messaging(&mut self, key: &str) -> Applied<bool> {
        let Some(entry) = self.entries.get_mut(key) else {
            return Applied::new(false, Effect::Unchanged);
        };
        if !truthy(entry.get("messaging")) {
            return Applied::new(false, Effect::Unchanged);
        }
        remove(entry, "messaging");
        if truthy(entry.get("autoApprove"))
            && let Some(rules) = entry.get_mut("autoApprove")
        {
            assign(rules, SwarmFlag::Messaging.name(), JsValue::Bool(false));
        }
        Applied::new(true, Effect::Narrowing)
    }
}
