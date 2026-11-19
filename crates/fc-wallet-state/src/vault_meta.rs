//! `identity/vault-meta.json` (the reference's `identity-manager.js`): the
//! vault's public metadata and the wallet list.
//!
//! `{ userKnowsPassword, createdAt, addresses: { userWallet, beeWallet },
//! derivedWallets: [record…], activeWalletIndex, nextHardwareWalletIndex }`.
//! A record is `{ index, name, address }` for a mnemonic account (no `type`
//! before hardware wallets), with `type` `ledger` (`path`, `addressCheck`),
//! `remote` (`addressCheck`) or `safe` (`owners`, `threshold`, `saltNonce`,
//! `deployed`). Hardware records take indices from
//! [`HARDWARE_INDEX_BASE`] up, never given twice.
//!
//! The core keeps the file's object as JS left it (every field, the ones it
//! doesn't know included, in JS's property order) and changes it as the
//! reference's function does. Each change answers whether the reference
//! writes the file ([`Changed::wrote`]); the daemon writes [`VaultMeta::text`]
//! then. A file is read as the reference reads it: its bytes as Node
//! decodes UTF-8 (an invalid sequence is U+FFFD), then `JSON.parse`
//! (fc-json): every number a double, a repeated key in its first place with
//! its last value, lone surrogates kept.
//!
//! What differs from the reference (design 0013, Deviations):
//! - `vault-meta-unreadable`: a file the reference reads as missing (it
//!   doesn't parse), or one whose shape its functions can't use, is
//!   [`Unreadable`]: the daemon renames it aside and reports it, and the
//!   store reads as no file. The shape: a JSON object within
//!   [`MAX_FILE_BYTES`]; a `derivedWallets` that is falsy or an array of
//!   objects, each with an integer `index`; an `activeWalletIndex` that is
//!   missing, `null` or an integer; and a Safe record's `owners`, falsy or
//!   an array. The reference would throw a `TypeError` on the others (a
//!   list that isn't an array, a `null` record), or act on an index that
//!   matches nothing (`"1"`, `0.5`).
//! - The identity core's answers come in from the caller: the addresses a
//!   create, import or unlock gives, and the mnemonic accounts' addresses
//!   through the closures [`VaultMeta::list`] and [`VaultMeta::add_mnemonic`]
//!   call where the reference asks the core (`keys.addresses`).
//! - The checks main makes before a change stay main's, as the design's
//!   callers do: a Ledger's address read back from the device and the
//!   phone's proof (the core is asked only once they match), and the Swarm
//!   feed references a removal is refused for (their origins come in). A
//!   Safe's approvals, its pending entry and its dApp grants are the
//!   daemon's to end, by [`Removal::safe`].

use fc_json::{JsString, JsValue};

use crate::address::is_address;
use crate::js;

/// The file's name in the identity directory.
pub const FILE_NAME: &str = "vault-meta.json";

/// The most the file may hold, in bytes (1 MiB; the design's, `source:
/// design`). A file past it is unreadable.
pub const MAX_FILE_BYTES: usize = 1024 * 1024;

/// The first hardware account index (`HARDWARE_INDEX_BASE`).
pub const HARDWARE_INDEX_BASE: f64 = 1_000_000.0;

/// The refusals' codes, as the reference sets `err.code`.
pub mod codes {
    pub const LEDGER_ACCOUNT_UNCHECKED: &str = "LEDGER_ACCOUNT_UNCHECKED";
    pub const REMOTE_ACCOUNT_UNCHECKED: &str = "REMOTE_ACCOUNT_UNCHECKED";
    pub const SWARM_PUBLISHER_IDENTITY_WALLET_IN_USE: &str =
        "SWARM_PUBLISHER_IDENTITY_WALLET_IN_USE";
}

const MNEMONIC: &str = "mnemonic";
const LEDGER: &str = "ledger";
const REMOTE: &str = "remote";
const SAFE: &str = "safe";
const MATCHED: &str = "matched";
const MISMATCHED: &str = "mismatched";
const UNCHECKED: &str = "unchecked";

/// Why a file is unreadable (`vault-meta-unreadable`): the daemon renames
/// it aside and reports it, and the store reads as no file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unreadable {
    #[error("the file is larger than {MAX_FILE_BYTES} bytes")]
    TooLarge,
    /// Not JSON (a byte-order mark included), or nested deeper than the
    /// parser reads: the reference reads no meta either.
    #[error("the file is not JSON")]
    NotJson,
    #[error("the file is not a JSON object")]
    NotObject,
    #[error("derivedWallets is not an array")]
    WalletsNotArray,
    #[error("a wallet record is not a JSON object")]
    RecordNotObject,
    #[error("a wallet record's index is not an integer")]
    IndexNotInteger,
    #[error("activeWalletIndex is not an integer")]
    ActiveNotInteger,
    #[error("a Safe record's owners is not an array")]
    OwnersNotArray,
}

impl Unreadable {
    /// Its name in the vectors (`reason`).
    pub fn reason(self) -> &'static str {
        match self {
            Unreadable::TooLarge => "too_large",
            Unreadable::NotJson => "not_json",
            Unreadable::NotObject => "not_object",
            Unreadable::WalletsNotArray => "wallets_not_array",
            Unreadable::RecordNotObject => "record_not_object",
            Unreadable::IndexNotInteger => "index_not_integer",
            Unreadable::ActiveNotInteger => "active_not_integer",
            Unreadable::OwnersNotArray => "owners_not_array",
        }
    }
}

/// A refusal: the reference's error, its `message` and its `code`. Nothing
/// is written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct Refusal {
    pub message: String,
    pub code: Option<&'static str>,
}

impl Refusal {
    fn new(message: impl Into<String>) -> Self {
        Refusal {
            message: message.into(),
            code: None,
        }
    }

    fn coded(message: impl Into<String>, code: &'static str) -> Self {
        Refusal {
            message: message.into(),
            code: Some(code),
        }
    }
}

const NO_VAULT: &str = "No vault found";
const MUST_UNLOCK: &str = "Vault must be unlocked to create a new wallet";

/// An operation that asks the identity core through the caller's closure:
/// its refusal, or the closure's own error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed<E> {
    Refused(Refusal),
    Derive(E),
}

/// A change's answer, and whether the reference writes the file for it.
#[derive(Debug, Clone, PartialEq)]
pub struct Changed<T> {
    pub value: T,
    pub wrote: bool,
}

/// A device record's kind (`WALLET_TYPES`' non-mnemonic ones).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ledger,
    Remote,
    Safe,
}

impl Kind {
    /// Its `type` in the file.
    pub fn type_name(self) -> &'static str {
        match self {
            Kind::Ledger => LEDGER,
            Kind::Remote => REMOTE,
            Kind::Safe => SAFE,
        }
    }

    /// `DEVICE_LABELS`: its name in the auto-name and the refusals.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Ledger => "Ledger",
            Kind::Remote => "Phone",
            Kind::Safe => "Safe",
        }
    }

    pub fn from_type_name(name: &str) -> Option<Kind> {
        [Kind::Ledger, Kind::Remote, Kind::Safe]
            .into_iter()
            .find(|kind| kind.type_name() == name)
    }
}

/// The device kinds that carry an address check (`ADDRESS_CHECKED_TYPES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Device {
    Ledger,
    Remote,
}

impl Device {
    fn type_name(self) -> &'static str {
        match self {
            Device::Ledger => LEDGER,
            Device::Remote => REMOTE,
        }
    }
}

/// A Safe's init parameters, as `addSafeWallet` takes them from its caller
/// (safe-service resolves the owners and predicts the address).
#[derive(Debug, Clone, Copy)]
pub struct SafeParams<'a> {
    pub address: &'a JsValue,
    pub owners: &'a JsValue,
    pub threshold: &'a JsValue,
    pub salt_nonce: &'a JsValue,
}

/// What a removal takes away: the record's index, and whether it was a
/// Safe, whose approvals, pending entry and message session the daemon
/// ends before writing (the reference's order: "cleanup precedes the meta
/// write").
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Removal {
    pub index: f64,
    pub safe: bool,
}

/// `vault-meta.json`, or no file.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VaultMeta {
    meta: Option<JsValue>,
}

fn object() -> JsValue {
    JsValue::Object(Vec::new())
}

fn string(text: &str) -> JsValue {
    JsValue::string(text)
}

fn truthy(value: Option<&JsValue>) -> bool {
    value.is_some_and(JsValue::truthy)
}

/// `value || fallback`.
fn or(value: Option<&JsValue>, fallback: JsValue) -> JsValue {
    match value {
        Some(value) if value.truthy() => value.clone(),
        _ => fallback,
    }
}

fn is_hardware_index(index: Option<&JsValue>) -> bool {
    js::is_integer(index) && matches!(index, Some(JsValue::Number(n)) if *n >= HARDWARE_INDEX_BASE)
}

/// `{ ...value }`'s own entries: an object's properties, an array's or a
/// string's by index; nothing for any other value.
fn spread(value: &JsValue) -> Vec<(JsString, JsValue)> {
    match value {
        JsValue::Object(props) => props.clone(),
        JsValue::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, item)| (JsString::from(i.to_string().as_str()), item.clone()))
            .collect(),
        JsValue::String(text) => text
            .units()
            .enumerate()
            .map(|(i, unit)| {
                (
                    JsString::from(i.to_string().as_str()),
                    JsValue::String(JsString::from_units(&[unit])),
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn spread_object(value: &JsValue) -> JsValue {
    let mut out = object();
    for (key, item) in spread(value) {
        out.set(key, item);
    }
    out
}

/// A record's `type`, with the mnemonic default (`record.type ||
/// 'mnemonic'`).
fn type_of(record: &JsValue) -> JsValue {
    or(record.get("type"), string(MNEMONIC))
}

fn is_mnemonic(record: &JsValue) -> bool {
    js::equals_str(Some(&type_of(record)), MNEMONIC)
}

/// `addressCheckOf`.
fn address_check_of(record: &JsValue) -> &'static str {
    let check = record.get("addressCheck");
    if js::equals_str(check, MATCHED) {
        MATCHED
    } else if js::equals_str(check, MISMATCHED) {
        MISMATCHED
    } else {
        UNCHECKED
    }
}

/// `verifiedDeployments`: the chains with a verified mark, `{ [chainId]:
/// true }`; a mark of a release before #1066 (a bare `true`) left out.
fn verified_deployments(stored: Option<&JsValue>) -> JsValue {
    let mut deployed = object();
    if let Some(stored) = stored.filter(|stored| stored.truthy()) {
        for (chain, mark) in spread(stored) {
            if matches!(mark.get("verified"), Some(JsValue::Bool(true))) {
                deployed.set(chain, JsValue::Bool(true));
            }
        }
    }
    deployed
}

/// `extraRecordFields`, onto `out`.
fn extra_record_fields(record: &JsValue, out: &mut JsValue) {
    if truthy(record.get("path")) {
        out.set(
            "path",
            record.get("path").cloned().unwrap_or(JsValue::Undefined),
        );
    }
    let raw_type = record.get("type");
    if js::equals_str(raw_type, LEDGER) || js::equals_str(raw_type, REMOTE) {
        out.set("addressCheck", string(address_check_of(record)));
    }
    if js::equals_str(raw_type, SAFE) {
        for field in ["owners", "threshold", "saltNonce"] {
            out.set(
                field,
                record.get(field).cloned().unwrap_or(JsValue::Undefined),
            );
        }
        out.set("deployed", verified_deployments(record.get("deployed")));
    }
}

/// The `TypeError` V8 throws where identity-manager.js reaches a function
/// on an Object.prototype member: `SAFE_OWNER_ADDRESS_CHECKS[type]` for a
/// record whose type names one.
const PROTOTYPE_NAMES: [&str; 12] = [
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "__proto__",
    "constructor",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toLocaleString",
    "toString",
    "valueOf",
];

impl VaultMeta {
    /// No file.
    pub fn none() -> Self {
        VaultMeta::default()
    }

    /// The store as its file's bytes give it.
    pub fn load(bytes: &[u8]) -> Result<Self, Unreadable> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(Unreadable::TooLarge);
        }
        // Node decodes as the WHATWG decoder does: each maximal invalid
        // subpart is one U+FFFD, as `from_utf8_lossy` replaces it.
        let text = String::from_utf8_lossy(bytes);
        let meta = fc_json::parse(&text).map_err(|_| Unreadable::NotJson)?;
        check_shape(&meta)?;
        Ok(VaultMeta { meta: Some(meta) })
    }

    /// Whether there is a file.
    pub fn exists(&self) -> bool {
        self.meta.is_some()
    }

    /// The file's object (`getVaultMeta()`, the `identity:get-vault-meta`
    /// answer), or none.
    pub fn value(&self) -> Option<&JsValue> {
        self.meta.as_ref()
    }

    /// The file's text, as the reference writes it (`JSON.stringify(meta,
    /// null, 2)`, no trailing newline), or none.
    pub fn text(&self) -> Option<String> {
        self.meta.as_ref().map(JsValue::stringify_pretty)
    }

    /// `saveVaultMeta(meta)`.
    fn save(&mut self, meta: JsValue) {
        self.meta = Some(meta);
    }

    /// `saveNewVaultMeta`: the file of a vault just created or imported,
    /// in place of any before it. `now_ms` is the wall clock (`createdAt`);
    /// the addresses are the identity core's answer.
    pub fn new_vault(
        &mut self,
        user_knows_password: bool,
        now_ms: i64,
        user_wallet: &str,
        bee_wallet: &str,
    ) -> Result<Changed<()>, Refusal> {
        let created_at =
            js::iso_string(now_ms).ok_or_else(|| Refusal::new("Invalid time value"))?;
        let mut meta = object();
        meta.set("userKnowsPassword", JsValue::Bool(user_knows_password));
        meta.set("createdAt", string(&created_at));
        meta.set("addresses", addresses(user_wallet, bee_wallet));
        self.save(meta);
        Ok(Changed {
            value: (),
            wrote: true,
        })
    }

    /// `afterUnlock(addresses)`'s migration: a file without `addresses`
    /// gains the unlock's.
    pub fn migrate_addresses(&mut self, user_wallet: &str, bee_wallet: &str) -> Changed<()> {
        let wrote = match &self.meta {
            Some(meta) if !truthy(meta.get("addresses")) => {
                let mut next = meta.clone();
                next.set("addresses", addresses(user_wallet, bee_wallet));
                self.save(next);
                true
            }
            _ => false,
        };
        Changed { value: (), wrote }
    }

    /// `getActiveWalletIndex()`.
    pub fn active_index(&self) -> f64 {
        match self
            .meta
            .as_ref()
            .and_then(|meta| meta.get("activeWalletIndex"))
        {
            Some(JsValue::Number(n)) => *n,
            _ => 0.0,
        }
    }

    /// `nextHardwareWalletIndex(meta, getWalletList(meta))`, or none
    /// without a file.
    pub fn next_hardware_index(&self) -> Option<f64> {
        self.meta
            .as_ref()
            .map(|meta| next_hardware_index(meta, &wallet_list(meta)))
    }

    /// `getWalletRecord(index)`: the record, normalized (`type` always
    /// there, index 0's address falling back to `addresses.userWallet`).
    pub fn record(&self, index: f64) -> Option<JsValue> {
        self.meta
            .as_ref()
            .and_then(|meta| wallet_record(meta, index))
    }

    /// `findWalletRecordByAddress(address)`: the record stored with the
    /// address (case-insensitive), normalized.
    pub fn find_by_address(&self, address: &JsValue) -> Option<JsValue> {
        let meta = self.meta.as_ref()?;
        let wanted = match address.as_js_string() {
            Some(text) if !text.is_empty() => js::lowercase(text),
            _ => return None,
        };
        let found = wallet_list(meta).into_iter().find(|wallet| {
            wallet
                .get("address")
                .and_then(JsValue::as_js_string)
                .is_some_and(|stored| js::lowercase(stored) == wanted)
        })?;
        let index = match found.get("index") {
            Some(JsValue::Number(n)) => *n,
            _ => return None,
        };
        wallet_record(meta, index)
    }

    /// `getDerivedWallets()`. A file without a wallet list gains the
    /// default one, `activeWalletIndex` 0 (`wrote`). Otherwise `derive` is
    /// asked for the mnemonic accounts' indices, as the reference asks the
    /// core, and answers their `(index, address)`, or none while the vault
    /// is locked (each then shows the address stored with it).
    pub fn list<E>(
        &mut self,
        derive: impl FnOnce(&[f64]) -> Result<Option<Vec<(f64, String)>>, E>,
    ) -> Result<Changed<Vec<JsValue>>, E> {
        let Some(meta) = &self.meta else {
            return Ok(Changed {
                value: Vec::new(),
                wrote: false,
            });
        };
        if !truthy(meta.get("derivedWallets")) {
            let main = default_wallet(meta);
            let mut next = meta.clone();
            next.set("derivedWallets", JsValue::Array(vec![main.clone()]));
            next.set("activeWalletIndex", JsValue::Number(0.0));
            self.save(next);
            let mut listed = main;
            listed.set("type", string(MNEMONIC));
            return Ok(Changed {
                value: vec![listed],
                wrote: true,
            });
        }
        let wallets = wallet_list(meta);
        let indices: Vec<f64> = wallets
            .iter()
            .filter(|wallet| is_mnemonic(wallet))
            .filter_map(|wallet| match wallet.get("index") {
                Some(JsValue::Number(n)) => Some(*n),
                _ => None,
            })
            .collect();
        let derived = derive(&indices)?;
        let user_wallet = meta.get("addresses").and_then(|a| a.get("userWallet"));
        let listed = wallets
            .iter()
            .map(|wallet| {
                let index = wallet.get("index");
                let type_ = type_of(wallet);
                let address = if !js::equals_str(Some(&type_), MNEMONIC) {
                    or(wallet.get("address"), JsValue::Null)
                } else if let Some(derived) = &derived {
                    // A Map's last entry for a key wins.
                    derived
                        .iter()
                        .rev()
                        .find(|(account, _)| js::equals_number(index, *account))
                        .map_or(JsValue::Null, |(_, address)| string(address))
                } else if truthy(wallet.get("address")) {
                    or(wallet.get("address"), JsValue::Null)
                } else if js::equals_number(index, 0.0) {
                    or(user_wallet, JsValue::Null)
                } else {
                    JsValue::Null
                };
                let mut out = object();
                out.set("index", index.cloned().unwrap_or(JsValue::Undefined));
                out.set(
                    "name",
                    wallet.get("name").cloned().unwrap_or(JsValue::Undefined),
                );
                out.set("address", address);
                out.set("type", type_);
                extra_record_fields(wallet, &mut out);
                out
            })
            .collect();
        Ok(Changed {
            value: listed,
            wrote: false,
        })
    }

    /// `createDerivedWallet(name)`: a mnemonic account at the next index
    /// past the mnemonic ones (hardware indices aside), skipping a taken
    /// one. `unlocked` is the vault's lock state; `derive` answers the
    /// index's address, or none while the vault is locked.
    pub fn add_mnemonic<E>(
        &mut self,
        unlocked: bool,
        name: &JsValue,
        derive: impl FnOnce(f64) -> Result<Option<String>, E>,
    ) -> Result<Changed<JsValue>, Failed<E>> {
        if !unlocked {
            return Err(Failed::Refused(Refusal::new(MUST_UNLOCK)));
        }
        let meta = self
            .meta
            .as_ref()
            .ok_or_else(|| Failed::Refused(Refusal::new(NO_VAULT)))?;
        let mut wallets = wallet_list(meta);
        let index = next_mnemonic_index(&wallets);
        let address = derive(index)
            .map_err(Failed::Derive)?
            .ok_or_else(|| Failed::Refused(Refusal::new(MUST_UNLOCK)))?;
        let name = or(
            Some(name),
            string(&format!("Wallet {}", js::number(index + 1.0))),
        );
        let mut wallet = object();
        wallet.set("index", JsValue::Number(index));
        wallet.set("name", name);
        wallet.set("address", string(&address));
        wallets.push(wallet.clone());
        let mut next = meta.clone();
        next.set("derivedWallets", JsValue::Array(wallets));
        self.save(next);
        Ok(Changed {
            value: wallet,
            wrote: true,
        })
    }

    /// `assertDeviceWalletAddable(type, address)`: refused for a malformed
    /// address, no file, or an address already in the list
    /// (case-insensitive).
    pub fn check_device_addable(&self, kind: Kind, address: &JsValue) -> Result<(), Refusal> {
        if !is_address(address) {
            return Err(Refusal::new(format!(
                "Invalid {} account address",
                kind.label()
            )));
        }
        let meta = self.meta.as_ref().ok_or_else(|| Refusal::new(NO_VAULT))?;
        let wanted = address
            .as_js_string()
            .map(js::lowercase)
            .unwrap_or_default();
        for wallet in wallet_list(meta) {
            let stored = wallet.get("address");
            if !truthy(stored) {
                continue;
            }
            let Some(stored) = stored.and_then(JsValue::as_js_string) else {
                return Err(Refusal::new("wallet.address.toLowerCase is not a function"));
            };
            if js::lowercase(stored) == wanted {
                return Err(Refusal::new(format!(
                    "This account is already in your wallet list as \"{}\"",
                    js::template(wallet.get("name")).map_err(Refusal::new)?
                )));
            }
        }
        Ok(())
    }

    /// `addDeviceWallet(type, name, address, extra)`: a device record at
    /// the next hardware index, named `name` trimmed or `<label> N`, with
    /// `extra`'s fields.
    pub fn add_device(
        &mut self,
        kind: Kind,
        name: &JsValue,
        address: &JsValue,
        extra: &JsValue,
    ) -> Result<Changed<JsValue>, Refusal> {
        self.check_device_addable(kind, address)?;
        let Some(meta) = &self.meta else {
            return Err(Refusal::new(NO_VAULT));
        };
        let mut wallets = wallet_list(meta);
        let index = next_hardware_index(meta, &wallets);
        let same_type = wallets
            .iter()
            .filter(|wallet| js::equals_str(wallet.get("type"), kind.type_name()))
            .count();
        let trimmed = match name {
            JsValue::String(text) if !text.is_empty() => js::trim(text),
            value if value.truthy() => {
                return Err(Refusal::new("(name || \"\").trim is not a function"));
            }
            _ => JsString::from(""),
        };
        let name = if trimmed.is_empty() {
            string(&format!("{} {}", kind.label(), same_type + 1))
        } else {
            JsValue::String(trimmed)
        };
        let mut wallet = object();
        wallet.set("index", JsValue::Number(index));
        wallet.set("name", name);
        wallet.set("address", address.clone());
        wallet.set("type", string(kind.type_name()));
        for (key, value) in spread(extra) {
            wallet.set(key, value);
        }
        wallets.push(wallet.clone());
        let mut next = meta.clone();
        next.set("derivedWallets", JsValue::Array(wallets));
        next.set("nextHardwareWalletIndex", JsValue::Number(index + 1.0));
        self.save(next);
        Ok(Changed {
            value: wallet,
            wrote: true,
        })
    }

    /// `addLedgerWallet(name, address, path)`, once main has read the same
    /// address back from the device at `path` (#1065): the record starts
    /// `matched`.
    pub fn add_ledger(
        &mut self,
        name: &JsValue,
        address: &JsValue,
        path: &JsValue,
    ) -> Result<Changed<JsValue>, Refusal> {
        if !matches!(path, JsValue::String(text) if !text.is_empty()) {
            return Err(Refusal::new("Missing derivation path for Ledger account"));
        }
        if !is_address(address) {
            return Err(Refusal::new("Invalid Ledger account address"));
        }
        let mut extra = object();
        extra.set("path", path.clone());
        extra.set("addressCheck", string(MATCHED));
        self.add_device(Kind::Ledger, name, address, &extra)
    }

    /// `addRemoteWallet(name, address)`, once the phone has proven the
    /// account (#1078): the record starts `matched`. Main checks
    /// [`VaultMeta::check_device_addable`] before asking the phone, as the
    /// reference does.
    pub fn add_remote(
        &mut self,
        name: &JsValue,
        address: &JsValue,
    ) -> Result<Changed<JsValue>, Refusal> {
        self.check_device_addable(Kind::Remote, address)?;
        let mut extra = object();
        extra.set("addressCheck", string(MATCHED));
        self.add_device(Kind::Remote, name, address, &extra)
    }

    /// `recordAddressCheck(type, index, matched)`: the record's check state
    /// after a device's answer; a `matched` record stays matched. None
    /// when there is no such record.
    pub fn record_address_check(
        &mut self,
        device: Device,
        index: f64,
        matched: bool,
    ) -> Changed<Option<&'static str>> {
        let unchanged = Changed {
            value: None,
            wrote: false,
        };
        let Some(meta) = &self.meta else {
            return unchanged;
        };
        let mut wallets = wallet_list(meta);
        let Some(record) = wallets.iter_mut().find(|wallet| {
            js::equals_number(wallet.get("index"), index)
                && js::equals_str(wallet.get("type"), device.type_name())
        }) else {
            return unchanged;
        };
        let next = if matched || address_check_of(record) == MATCHED {
            MATCHED
        } else {
            MISMATCHED
        };
        let wrote = !js::equals_str(record.get("addressCheck"), next);
        if wrote {
            record.set("addressCheck", string(next));
            let mut saved = meta.clone();
            saved.set("derivedWallets", JsValue::Array(wallets));
            self.save(saved);
        }
        Changed {
            value: Some(next),
            wrote,
        }
    }

    /// `addSafeWallet(name, params)`: a Safe record over 1-of-2 or 2-of-3
    /// existing owners, none a Safe, each device owner `matched`.
    pub fn add_safe(
        &mut self,
        name: &JsValue,
        params: SafeParams<'_>,
    ) -> Result<Changed<JsValue>, Refusal> {
        let owners = match params.owners {
            JsValue::Array(owners) => Some(owners.as_slice()),
            _ => None,
        };
        let threshold = |n: f64| js::equals_number(Some(params.threshold), n);
        let preset = owners.filter(|owners| {
            (owners.len() == 2 && threshold(1.0)) || (owners.len() == 3 && threshold(2.0))
        });
        let Some(owners) = preset else {
            return Err(Refusal::new("A Safe needs 1 of 2 or 2 of 3 owners"));
        };
        let duplicate = owners.iter().enumerate().any(|(i, owner)| {
            owners[..i]
                .iter()
                .any(|earlier| js::same_value_zero(earlier, owner))
        });
        if duplicate {
            return Err(Refusal::new("Duplicate owner accounts"));
        }
        for owner in owners {
            let record = match owner {
                JsValue::Number(n) => self.record(*n),
                _ => None,
            };
            let Some(record) = record else {
                return Err(Refusal::new(format!(
                    "Owner wallet index {} does not exist",
                    js::template(Some(owner)).map_err(Refusal::new)?
                )));
            };
            let type_ = record.get("type");
            if js::equals_str(type_, SAFE) {
                return Err(Refusal::new("A Safe cannot own another Safe"));
            }
            check_safe_owner(&record)?;
        }
        let salt = params.salt_nonce.as_js_string();
        let digits = salt.is_some_and(|salt| {
            !salt.is_empty() && salt.units().all(|unit| (0x30..=0x39).contains(&unit))
        });
        if !digits {
            return Err(Refusal::new("Invalid Safe salt nonce"));
        }
        let mut extra = object();
        extra.set("owners", JsValue::Array(owners.to_vec()));
        extra.set("threshold", params.threshold.clone());
        extra.set("saltNonce", params.salt_nonce.clone());
        extra.set("deployed", object());
        self.add_device(Kind::Safe, name, params.address, &extra)
    }

    /// `markSafeDeployed(index, chainId)`: the chain's verified mark
    /// (`{ verified: true }`, #1066), in place of a mark before it.
    pub fn mark_safe_deployed(
        &mut self,
        index: f64,
        chain_id: f64,
    ) -> Result<Changed<()>, Refusal> {
        let meta = self.meta.as_ref().ok_or_else(|| Refusal::new(NO_VAULT))?;
        let mut wallets = wallet_list(meta);
        let record = wallets
            .iter_mut()
            .find(|wallet| js::equals_number(wallet.get("index"), index))
            .filter(|record| js::equals_str(record.get("type"), SAFE))
            .ok_or_else(|| {
                Refusal::new(format!(
                    "Wallet {} is not a Safe account",
                    js::number(index)
                ))
            })?;
        let mut deployed = match record.get("deployed") {
            Some(stored) if stored.truthy() => spread_object(stored),
            _ => object(),
        };
        let mut mark = object();
        mark.set("verified", JsValue::Bool(true));
        deployed.set(js::number(chain_id).as_str(), mark);
        record.set("deployed", deployed);
        let mut next = meta.clone();
        next.set("derivedWallets", JsValue::Array(wallets));
        self.save(next);
        Ok(Changed {
            value: (),
            wrote: true,
        })
    }

    /// `setActiveWalletIndex(index)`.
    pub fn set_active(&mut self, index: f64) -> Result<Changed<()>, Refusal> {
        let meta = self.meta.as_ref().ok_or_else(|| Refusal::new(NO_VAULT))?;
        if !wallet_list(meta)
            .iter()
            .any(|wallet| js::equals_number(wallet.get("index"), index))
        {
            return Err(missing(index));
        }
        let mut next = meta.clone();
        next.set("activeWalletIndex", JsValue::Number(index));
        self.save(next);
        Ok(Changed {
            value: (),
            wrote: true,
        })
    }

    /// `renameDerivedWallet(index, name)`: the name as given, whatever it
    /// is.
    pub fn rename(&mut self, index: f64, name: &JsValue) -> Result<Changed<()>, Refusal> {
        let meta = self.meta.as_ref().ok_or_else(|| Refusal::new(NO_VAULT))?;
        let mut wallets = wallet_list(meta);
        let record = wallets
            .iter_mut()
            .find(|wallet| js::equals_number(wallet.get("index"), index))
            .ok_or_else(|| missing(index))?;
        record.set("name", name.clone());
        let mut next = meta.clone();
        next.set("derivedWallets", JsValue::Array(wallets));
        self.save(next);
        Ok(Changed {
            value: (),
            wrote: true,
        })
    }

    /// `deleteDerivedWallet(index)`'s refusals: the main wallet, no file, no
    /// such record, a wallet the Swarm feeds of `swarm_origins` use
    /// (main's feed store's references), and a Safe's owner.
    pub fn check_remove(&self, index: f64, swarm_origins: &[String]) -> Result<Removal, Refusal> {
        if index == 0.0 {
            return Err(Refusal::new("Cannot delete the main wallet (index 0)"));
        }
        let meta = self.meta.as_ref().ok_or_else(|| Refusal::new(NO_VAULT))?;
        let wallets = wallet_list(meta);
        let record = wallets
            .iter()
            .find(|wallet| js::equals_number(wallet.get("index"), index))
            .ok_or_else(|| missing(index))?;
        if !swarm_origins.is_empty() {
            let shown = swarm_origins
                .iter()
                .take(3)
                .map(String::as_str)
                .collect::<Vec<_>>();
            let extra = swarm_origins.len().saturating_sub(3);
            let extra = if extra > 0 {
                format!(" and {extra} more")
            } else {
                String::new()
            };
            return Err(Refusal::coded(
                format!(
                    "Cannot delete wallet with index {}; it is active or pinned to Swarm feeds for {}{extra}. Switch the affected publisher identities before deleting this wallet.",
                    js::number(index),
                    shown.join(", ")
                ),
                codes::SWARM_PUBLISHER_IDENTITY_WALLET_IN_USE,
            ));
        }
        let index_value = JsValue::Number(index);
        let owning = wallets.iter().find(|wallet| {
            js::equals_str(wallet.get("type"), SAFE)
                && match wallet.get("owners") {
                    Some(JsValue::Array(owners)) => owners
                        .iter()
                        .any(|owner| js::same_value_zero(owner, &index_value)),
                    _ => false,
                }
        });
        if let Some(owning) = owning {
            return Err(Refusal::new(format!(
                "This account is an owner of \"{}\" \u{2014} delete that Safe account first",
                js::template(owning.get("name")).map_err(Refusal::new)?
            )));
        }
        Ok(Removal {
            index,
            safe: js::equals_str(record.get("type"), SAFE),
        })
    }

    /// `deleteDerivedWallet(index)`'s refusals ([`VaultMeta::check_remove`])
    /// and `removeWalletRecord`: the record out, and the active wallet back
    /// to the main one if it was this one.
    pub fn remove(
        &mut self,
        index: f64,
        swarm_origins: &[String],
    ) -> Result<Changed<Removal>, Refusal> {
        let removal = self.check_remove(index, swarm_origins)?;
        let Some(meta) = &self.meta else {
            return Err(Refusal::new(NO_VAULT));
        };
        let remaining: Vec<JsValue> = wallet_list(meta)
            .into_iter()
            .filter(|wallet| !js::equals_number(wallet.get("index"), index))
            .collect();
        let active = match meta.get("activeWalletIndex") {
            None | Some(JsValue::Null | JsValue::Undefined) => JsValue::Number(0.0),
            Some(active) => active.clone(),
        };
        let active = if js::equals_number(Some(&active), index) {
            JsValue::Number(0.0)
        } else {
            active
        };
        let mut next = meta.clone();
        next.set("derivedWallets", JsValue::Array(remaining));
        next.set("activeWalletIndex", active);
        self.save(next);
        Ok(Changed {
            value: removal,
            wrote: true,
        })
    }
}

fn missing(index: f64) -> Refusal {
    Refusal::new(format!(
        "Wallet with index {} does not exist",
        js::number(index)
    ))
}

fn addresses(user_wallet: &str, bee_wallet: &str) -> JsValue {
    let mut addresses = object();
    addresses.set("userWallet", string(user_wallet));
    addresses.set("beeWallet", string(bee_wallet));
    addresses
}

/// The shape the core reads (`vault-meta-unreadable`).
fn check_shape(meta: &JsValue) -> Result<(), Unreadable> {
    if !matches!(meta, JsValue::Object(_)) {
        return Err(Unreadable::NotObject);
    }
    match meta.get("derivedWallets") {
        Some(JsValue::Array(wallets)) => {
            for wallet in wallets {
                if !matches!(wallet, JsValue::Object(_)) {
                    return Err(Unreadable::RecordNotObject);
                }
                if !js::is_integer(wallet.get("index")) {
                    return Err(Unreadable::IndexNotInteger);
                }
                let owners = wallet.get("owners");
                if js::equals_str(wallet.get("type"), SAFE)
                    && truthy(owners)
                    && !matches!(owners, Some(JsValue::Array(_)))
                {
                    return Err(Unreadable::OwnersNotArray);
                }
            }
        }
        Some(wallets) if wallets.truthy() => return Err(Unreadable::WalletsNotArray),
        _ => {}
    }
    match meta.get("activeWalletIndex") {
        None | Some(JsValue::Null) => {}
        active if js::is_integer(active) => {}
        _ => return Err(Unreadable::ActiveNotInteger),
    }
    Ok(())
}

/// The default list's one record, `{ index: 0, name: 'Main Wallet',
/// address }`.
fn default_wallet(meta: &JsValue) -> JsValue {
    let mut main = object();
    main.set("index", JsValue::Number(0.0));
    main.set("name", string("Main Wallet"));
    let user_wallet = meta.get("addresses").and_then(|a| a.get("userWallet"));
    main.set("address", or(user_wallet, JsValue::Null));
    main
}

/// `getWalletList(meta)`: the stored list, or the default one when none
/// was written.
fn wallet_list(meta: &JsValue) -> Vec<JsValue> {
    match meta.get("derivedWallets") {
        Some(wallets) if wallets.truthy() => wallets
            .as_array()
            .map(<[JsValue]>::to_vec)
            .unwrap_or_default(),
        _ => vec![default_wallet(meta)],
    }
}

/// `getWalletRecord(index, meta)`.
fn wallet_record(meta: &JsValue, index: f64) -> Option<JsValue> {
    let record = wallet_list(meta)
        .into_iter()
        .find(|wallet| js::equals_number(wallet.get("index"), index))?;
    let mut address = or(record.get("address"), JsValue::Null);
    if !address.truthy() && js::equals_number(record.get("index"), 0.0) {
        address = or(
            meta.get("addresses").and_then(|a| a.get("userWallet")),
            JsValue::Null,
        );
    }
    let mut out = object();
    out.set(
        "index",
        record.get("index").cloned().unwrap_or(JsValue::Undefined),
    );
    out.set(
        "name",
        record.get("name").cloned().unwrap_or(JsValue::Undefined),
    );
    out.set("address", address);
    out.set("type", type_of(&record));
    extra_record_fields(&record, &mut out);
    Some(out)
}

/// `nextHardwareWalletIndex(meta, wallets)`: the larger of the stored
/// counter and one past the highest hardware index, never below
/// [`HARDWARE_INDEX_BASE`].
fn next_hardware_index(meta: &JsValue, wallets: &[JsValue]) -> f64 {
    let stored = meta.get("nextHardwareWalletIndex");
    let counter = match stored {
        Some(JsValue::Number(n)) if js::is_integer(stored) => *n,
        _ => HARDWARE_INDEX_BASE,
    };
    let high_water = wallets.iter().fold(HARDWARE_INDEX_BASE, |max, wallet| {
        match wallet.get("index") {
            Some(JsValue::Number(n)) if is_hardware_index(wallet.get("index")) => max.max(n + 1.0),
            _ => max,
        }
    });
    counter.max(high_water)
}

/// `createDerivedWallet`'s index: one past the highest mnemonic-range
/// index (hardware indices aside), then past any taken index.
fn next_mnemonic_index(wallets: &[JsValue]) -> f64 {
    let highest = wallets
        .iter()
        .fold(-1.0_f64, |max, wallet| match wallet.get("index") {
            Some(JsValue::Number(n)) if !is_hardware_index(wallet.get("index")) => max.max(*n),
            _ => max,
        });
    let mut index = highest + 1.0;
    while wallets.iter().any(|wallet| {
        wallet
            .get("index")
            .is_some_and(|taken| js::same_value_zero(taken, &JsValue::Number(index)))
    }) {
        index += 1.0;
    }
    index
}

/// `assertSafeOwnerAddressChecked(record)`: a Ledger or phone owner must be
/// `matched`.
fn check_safe_owner(record: &JsValue) -> Result<(), Refusal> {
    let type_ = record.get("type");
    let (code, device) = if js::equals_str(type_, LEDGER) {
        (codes::LEDGER_ACCOUNT_UNCHECKED, Device::Ledger)
    } else if js::equals_str(type_, REMOTE) {
        (codes::REMOTE_ACCOUNT_UNCHECKED, Device::Remote)
    } else {
        // `SAFE_OWNER_ADDRESS_CHECKS[type]` finds an Object.prototype member
        // for these names, and V8 throws calling its `unchecked`.
        if PROTOTYPE_NAMES
            .iter()
            .any(|name| js::equals_str(type_, name))
        {
            return Err(Refusal::new("check.unchecked is not a function"));
        }
        return Ok(());
    };
    let state = address_check_of(record);
    if state == MATCHED {
        return Ok(());
    }
    let name = js::template(record.get("name")).map_err(Refusal::new)?;
    let message = match (device, state == MISMATCHED) {
        (Device::Ledger, false) => format!(
            "\"{name}\" can't own a Safe until it has been checked on its Ledger. Connect that Ledger and open Connect Hardware Wallet, then try again."
        ),
        (Device::Ledger, true) => format!(
            "\"{name}\" can't own a Safe: the Ledger last connected doesn't hold it. Connect the Ledger that does and open Connect Hardware Wallet, then try again."
        ),
        (Device::Remote, false) => format!(
            "\"{name}\" can't own a Safe until it has been checked on your phone. Select it, open Wallet Settings and choose Check on Phone, then try again."
        ),
        (Device::Remote, true) => format!(
            "\"{name}\" can't own a Safe: your phone last answered from a different account. Select this account on your phone, check it again from Wallet Settings, then try again."
        ),
    };
    Err(Refusal::coded(message, code))
}

#[cfg(test)]
mod tests;
