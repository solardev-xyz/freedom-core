//! The profile's RPC API keys, once `core.hello` names `rpc_api_keys` in
//! `store_moved` (design 0013, "RPC API keys"; PRF-5h).
//!
//! - **Where a key lives:** a secrets-file entry, `rpc-api-key.<id>`, whose
//!   secret is the key, bound to `{}`, under the `Unattended` key, wherever
//!   the key store offers that policy; otherwise `rpc-api-keys.json` beside
//!   the permission files (the hello's `grant_root`), in the reference's
//!   text (`JSON.stringify(keys, null, 2)`, each key `{ apiKey, enabled:
//!   true, addedAt }`). The file also keeps, with a key store, what the
//!   secrets file can't hold: a key whose id isn't in the entry form, one
//!   past [`MAX_KEYS`], or one that isn't a string of 1 to
//!   [`MAX_SECRET_BYTES`] bytes.
//! - **The provider id** of a set is 1 to 52 bytes of lowercase letters,
//!   digits, `.`, `_` or `-` ([`entry_name`]; `rpc-key-provider-id`).
//! - **The bound:** at most [`MAX_KEYS`] entries; a set that would add one
//!   more is refused, a replace taken (`rpc-keys-bound`).
//! - **The file wins:** a provider with a key the reference counts in the
//!   file (`hasApiKey`: `apiKey` and `enabled` truthy) is answered from it.
//! - **The migration** runs once each start, before the first request that
//!   reads or writes a key ([`RpcKeys::migrate`]): every key in the file the
//!   secrets file can hold, in the file's order up to the bound, in one
//!   secrets write that replaces any entry the provider has; then the file
//!   is rewritten without them, or removed when nothing is left. A crash
//!   between the two leaves each key in both places, which the next start
//!   moves again. `rpc_api_key_status` answers the same before and after
//!   it, so it doesn't run it: it opens no key and asks the key store
//!   nothing.
//! - **A set** writes the entry first, then takes the provider out of the
//!   file; without a key store it writes the file. **A remove** takes the
//!   key from both places.
//! - **An unreadable file** (not a regular file the user owns, over 1 MiB,
//!   not JSON, or not an object) is renamed to `rpc-api-keys.json.unreadable`
//!   and logged (`rpc-keys-unreadable`); if the rename fails, nothing writes
//!   the file.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fc_json::{JsString, JsValue};
use fc_keystore::{EntryName, MAX_SECRET_BYTES, Policy};
use zeroize::Zeroizing;

use crate::fsx::{self, Done};
use crate::grants::{Read, read_file};
use crate::secrets::{self, Change, Secrets};

/// The file, at the Freedom root.
pub const FILE: &str = "rpc-api-keys.json";
/// An entry's name is this, then the provider id.
pub const PREFIX: &str = "rpc-api-key.";
/// At most this many RPC-key entries in the secrets file.
pub const MAX_KEYS: usize = 16;
/// A larger file is unreadable.
pub const MAX_FILE_BYTES: usize = 1 << 20;

/// The entry for provider `id`, when `rpc-api-key.<id>` is an entry name:
/// `id` is 1 to 52 bytes of lowercase letters, digits, `.`, `_` or `-`.
pub fn entry_name(id: &str) -> Option<EntryName> {
    if id.is_empty() {
        return None;
    }
    EntryName::new(&format!("{PREFIX}{id}"))
}

/// The provider an RPC-key entry is for.
pub fn provider_of(name: &EntryName) -> Option<&str> {
    name.as_str()
        .strip_prefix(PREFIX)
        .filter(|id| !id.is_empty())
}

/// A key the secrets file can hold: 1 to [`MAX_SECRET_BYTES`] bytes.
pub fn holdable(key: &str) -> bool {
    (1..=MAX_SECRET_BYTES).contains(&key.len())
}

/// `rpc-api-keys.json` as the reference reads it: a JSON object, its
/// properties in JavaScript's order.
#[derive(Debug, Clone, PartialEq)]
pub struct KeysFile(JsValue);

impl Default for KeysFile {
    fn default() -> Self {
        KeysFile(JsValue::Object(Vec::new()))
    }
}

impl KeysFile {
    /// The file's bytes, as Node decodes them (UTF-8, U+FFFD for each
    /// invalid sequence) and `JSON.parse` reads them. `None`: unreadable
    /// (not JSON, or not an object).
    pub fn parse(bytes: &[u8]) -> Option<KeysFile> {
        let value = fc_json::parse(&String::from_utf8_lossy(bytes)).ok()?;
        matches!(value, JsValue::Object(_)).then_some(KeysFile(value))
    }

    /// `JSON.stringify(keys, null, 2)`.
    pub fn text(&self) -> String {
        self.0.stringify_pretty()
    }

    fn props(&self) -> &[(JsString, JsValue)] {
        match &self.0 {
            JsValue::Object(props) => props,
            _ => &[],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.props().is_empty()
    }

    /// Each provider with a key the reference counts (`hasApiKey`: `apiKey`
    /// and `enabled` truthy), in the file's order, with the key as a URL
    /// template takes it (`String(apiKey)`; a key that can't be made a
    /// string is skipped), and whether it is a string the secrets file can
    /// hold.
    pub fn counted(&self) -> Vec<(String, String, bool)> {
        self.props()
            .iter()
            .filter_map(|(id, record)| {
                let key = record.get("apiKey")?;
                if !key.truthy() || !record.get("enabled").is_some_and(JsValue::truthy) {
                    return None;
                }
                let string = key.js_string().ok()?;
                let holds = matches!(key, JsValue::String(s) if s.is_well_formed())
                    && id.is_well_formed()
                    && holdable(&string);
                Some((id.as_str().to_owned(), string, holds))
            })
            .collect()
    }

    /// `keys[id] = { apiKey, enabled: true, addedAt }`.
    pub fn set(&mut self, id: &str, key: &str, added_at_ms: u64) {
        let record = JsValue::Object(vec![
            (JsString::from("apiKey"), JsValue::string(key)),
            (JsString::from("enabled"), JsValue::Bool(true)),
            (
                JsString::from("addedAt"),
                JsValue::Number(added_at_ms as f64),
            ),
        ]);
        self.0.set(id, record);
    }

    /// `delete keys[id]`, where `only_truthy` is false or the record is
    /// truthy (the reference's remove takes only a truthy one). Whether it
    /// was there.
    pub fn delete(&mut self, id: &str, only_truthy: bool) -> bool {
        let JsValue::Object(props) = &mut self.0 else {
            return false;
        };
        match props.iter().position(|(k, _)| k == id) {
            Some(at) if !only_truthy || props[at].1.truthy() => {
                props.remove(at);
                true
            }
            _ => false,
        }
    }
}

/// Why an RPC-key request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The request asks for what the design refuses (`invalid_argument`).
    Invalid(&'static str),
    /// The secrets file or the key store.
    Secrets(secrets::Error),
    /// `rpc-api-keys.json` couldn't be written, or set aside (a storage
    /// error's kind).
    File(&'static str),
}

/// What a set or a remove is.
pub enum Op {
    Set {
        id: String,
        key: Zeroizing<String>,
        at_ms: u64,
    },
    Remove {
        id: String,
    },
}

/// See the module documentation.
pub struct RpcKeys {
    root: PathBuf,
    secrets: Arc<Secrets>,
    /// Whether this start's migration has run.
    migrated: Mutex<bool>,
}

fn io_kind(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => "permission",
        std::io::ErrorKind::StorageFull => "no_space",
        _ => "other",
    }
}

impl RpcKeys {
    pub fn new(root: PathBuf, secrets: Arc<Secrets>) -> Arc<RpcKeys> {
        Arc::new(RpcKeys {
            root,
            secrets,
            migrated: Mutex::new(false),
        })
    }

    fn path(&self) -> PathBuf {
        self.root.join(FILE)
    }

    /// Whether the key store offers the policy the entries go under.
    fn key_store(&self) -> bool {
        self.secrets.capabilities().offers(Policy::Unattended)
    }

    /// The file as it stands (`None` when there is none). An unreadable one
    /// is renamed aside first, and reads as none.
    fn load(&self) -> Result<Option<KeysFile>, Failure> {
        let path = self.path();
        let parsed = match read_file(&path, MAX_FILE_BYTES) {
            Read::Missing => return Ok(None),
            Read::Bytes(bytes) => KeysFile::parse(&bytes),
            Read::Unreadable => None,
        };
        if parsed.is_some() {
            return Ok(parsed);
        }
        let aside = self.root.join(format!("{FILE}.unreadable"));
        let renamed = std::fs::rename(&path, &aside)
            .map(|()| fsx::flushed(fsx::sync_rename(&self.root, &aside)) == Done::Durable);
        crate::log::warn(
            "rpc-api-keys.json can't be read: renamed aside",
            serde_json::json!({ "renamed": renamed.is_ok() }),
        );
        match renamed {
            Ok(_) => Ok(None),
            Err(e) => Err(Failure::File(io_kind(&e))),
        }
    }

    /// Writes `file`, or removes it when it is empty and `keep_empty` is
    /// false: 0001's single-file write, 0600, staged and read back.
    fn save(&self, file: &KeysFile, keep_empty: bool) -> Result<(), Failure> {
        crate::testhooks::secrets_step("before-rpc-file");
        if crate::testhooks::secrets_fails("rpc-file") {
            return Err(Failure::File("other"));
        }
        let path = self.path();
        let done = if file.is_empty() && !keep_empty {
            fsx::remove(&path, || true)
                .map_err(|e| Failure::File(io_kind(&e)))?
                .unwrap_or(Done::Durable)
        } else {
            let text = file.text();
            fsx::replace(
                &path,
                text.as_bytes(),
                |staged| {
                    let bytes = fsx::read_at_most(staged, MAX_FILE_BYTES as u64)
                        .map_err(|e| e.to_string())?
                        .ok_or("the staged rpc-api-keys.json grew")?;
                    if bytes == text.as_bytes() {
                        Ok(())
                    } else {
                        Err("the staged rpc-api-keys.json doesn't read back".into())
                    }
                },
                || true,
            )
            .map_err(|e| match e {
                fsx::WriteError::Io(e) => Failure::File(io_kind(&e)),
                _ => Failure::File("other"),
            })?
        };
        if done == Done::NotDurable {
            crate::log::warn(
                "rpc-api-keys.json's directory flush failed",
                serde_json::json!({}),
            );
        }
        crate::testhooks::secrets_step("after-rpc-file");
        Ok(())
    }

    /// This start's migration, once (see the module documentation). A
    /// failure leaves it to run again at the next request.
    fn migrate(&self) -> Result<(), Failure> {
        let mut migrated = self.migrated.lock().map_err(|_| Failure::File("other"))?;
        if *migrated {
            return Ok(());
        }
        if let Err(e) = fsx::remove_temps(&self.root, FILE) {
            crate::log::warn(
                "cannot remove rpc-api-keys.json's temp files",
                serde_json::json!({ "kind": e.kind().to_string() }),
            );
        }
        if !self.key_store() {
            *migrated = true;
            return Ok(());
        }
        let Some(mut file) = self.load()? else {
            *migrated = true;
            return Ok(());
        };
        let counted = file.counted();
        let moved = self
            .secrets
            .change_entries("rpc-migrate", |secrets| {
                let mut entries = secrets
                    .entry_names()
                    .filter(|n| provider_of(n).is_some())
                    .count();
                let mut change = Change::default();
                let mut moved = Vec::new();
                for (id, key, holds) in &counted {
                    let Some(name) = entry_name(id).filter(|_| *holds) else {
                        continue;
                    };
                    if secrets.entry_key(&name).is_none() {
                        if entries >= MAX_KEYS {
                            continue;
                        }
                        entries += 1;
                    }
                    change
                        .put
                        .push((name, Zeroizing::new(key.as_bytes().to_vec())));
                    moved.push(id.clone());
                }
                Ok((change, moved))
            })
            .map_err(Failure::Secrets)?;
        if !moved.is_empty() {
            for id in &moved {
                file.delete(id, false);
            }
            self.save(&file, false)?;
        }
        *migrated = true;
        Ok(())
    }

    /// The providers with a key: the entries' names and the file's counted
    /// keys. No key is opened, and the key store isn't asked.
    pub fn status(&self) -> Result<Vec<String>, Failure> {
        let mut ids: Vec<String> = self
            .secrets
            .entry_names(PREFIX)
            .map_err(Failure::Secrets)?
            .iter()
            .filter_map(|n| provider_of(n).map(str::to_owned))
            .collect();
        if let Some(file) = self.load()? {
            ids.extend(file.counted().into_iter().map(|(id, _, _)| id));
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    /// Each provider's key, for main's own requests: from the file where it
    /// counts one, from the entry otherwise.
    pub fn keys(&self) -> Result<BTreeMap<String, Zeroizing<String>>, Failure> {
        self.migrate()?;
        let mut keys = BTreeMap::new();
        if self.key_store() {
            for (name, secret) in self
                .secrets
                .open_entries(PREFIX)
                .map_err(Failure::Secrets)?
            {
                let (Some(id), Ok(key)) =
                    (provider_of(&name), std::str::from_utf8(secret.expose()))
                else {
                    continue;
                };
                keys.insert(id.to_owned(), Zeroizing::new(key.to_owned()));
            }
        }
        if let Some(file) = self.load()? {
            for (id, key, _) in file.counted() {
                keys.insert(id, Zeroizing::new(key));
            }
        }
        Ok(keys)
    }

    /// A set or a remove (see the module documentation).
    pub fn change(&self, op: &Op) -> Result<(), Failure> {
        if let Op::Set { id, key, .. } = op {
            if entry_name(id).is_none() {
                return Err(Failure::Invalid("rpc-key-provider-id"));
            }
            if !holdable(key) {
                return Err(Failure::Invalid("rpc-key-size"));
            }
        }
        self.migrate()?;
        let store = self.key_store();
        match op {
            Op::Set { id, key, at_ms } if !store => {
                let mut file = self.load()?.unwrap_or_default();
                file.set(id, key, *at_ms);
                if file.text().len() > MAX_FILE_BYTES {
                    return Err(Failure::Invalid("rpc-keys-file-size"));
                }
                self.save(&file, true)
            }
            Op::Set { id, key, .. } => {
                let name = entry_name(id).ok_or(Failure::Invalid("rpc-key-provider-id"))?;
                // `false`: refused at the bound, with nothing changed.
                let taken = self
                    .secrets
                    .change_entries("rpc-set", |secrets| {
                        let entries = secrets
                            .entry_names()
                            .filter(|n| provider_of(n).is_some())
                            .count();
                        if secrets.entry_key(&name).is_none() && entries >= MAX_KEYS {
                            return Ok((Change::default(), false));
                        }
                        let change = Change {
                            put: vec![(name.clone(), Zeroizing::new(key.as_bytes().to_vec()))],
                            remove: Vec::new(),
                        };
                        Ok((change, true))
                    })
                    .map_err(Failure::Secrets)?;
                if !taken {
                    return Err(Failure::Invalid("rpc-keys-bound"));
                }
                self.leave_file(id, false)
            }
            Op::Remove { id } => {
                if let Some(name) = entry_name(id) {
                    self.secrets
                        .change_entries("rpc-remove", |secrets| {
                            let mut change = Change::default();
                            if secrets.entry_key(&name).is_some() {
                                change.remove.push(name.clone());
                            }
                            Ok((change, ()))
                        })
                        .map_err(Failure::Secrets)?;
                }
                self.leave_file(id, true)
            }
        }
    }

    /// Takes `id` out of the file, if it is there (only a truthy record
    /// when `only_truthy`), removing the file when nothing is left where a
    /// key store holds the rest.
    fn leave_file(&self, id: &str, only_truthy: bool) -> Result<(), Failure> {
        let Some(mut file) = self.load()? else {
            return Ok(());
        };
        if file.delete(id, only_truthy) {
            self.save(&file, !self.key_store())?;
        }
        Ok(())
    }
}
