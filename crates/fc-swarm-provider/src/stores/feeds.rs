//! `swarm-feeds.json` (the reference's `swarm/feed-store.js`): each site's
//! publisher identities, its feed grant and its feeds.
//!
//! `{ version: 2, nextPublisherKeyIndex, origins: { [key]: {
//! activeIdentityId, identities, feedGranted, grantedAt, feeds } } }`. An
//! identity is `bee-wallet` (the node's wallet key, which every site
//! shares), `app-scoped:<n>` (the publisher key at index `n`), or a stored
//! `ethereum-wallet` one, which loads and fails on use (#89).
//!
//! [`FeedStore::load`] reads the file as `loadFeeds` does: a version 1
//! file is migrated, kept aside as `swarm-feeds.v1-backup.json` and
//! written over; a file that doesn't parse, isn't an object, or whose
//! `origins` or counter is invalid is kept aside as
//! `swarm-feeds.corrupt.json`, one of another version as
//! `swarm-feeds.unsupported.json` (each the first free name, `-1`, `-2`, …
//! before `.json`), and the store starts empty, written at the next change.
//! A version 2 file's invalid sites are dropped, as `validateV2Store` drops
//! them.
//!
//! Each change answers the text the reference writes ([`Changed::write`])
//! and the user's change a permission manifest must let go of
//! ([`Changed::detach`], `notifyManifestMutation`).
//!
//! What differs from the reference:
//! - `index-allocation` (design 0015, F-8): a new publisher index is the
//!   larger of `nextPublisherKeyIndex` and one past every app-scoped index
//!   stored, so a counter at or below a held index never hands it out
//!   again. The preview, and the check of `createAppScopedIdentityAt`, use
//!   the same next index.
//! - The bound (design 0015, Budgets): a change whose text would pass
//!   [`MAX_FILE_BYTES`] is refused (`store_full`). A file past it is kept
//!   aside as one that doesn't parse (the design says nothing of reading
//!   one; the reference reads any size).
//! - A site whose `feeds` isn't an object of objects is rebuilt as
//!   `sanitizeV2OriginEntry` rebuilds it, even when every site is valid
//!   (the reference then keeps the file's sites as they are): the core
//!   never holds a feed map it can't read as one. No reference writer makes
//!   one (deviation `store-shapes`, `feeds-load-feed-maps-kept`).
//! - An identity kept under a key other than its own `id` is left out at
//!   load (deviation `store-shapes`), so no two of a site's identities
//!   share an id, and no answer grows past the store's size (pairing
//!   10,000 identities of one id with 10,000 feeds of it would make 10^8
//!   names). A site whose active identity is left out is dropped, as the
//!   reference drops one whose active identity is missing. No reference
//!   writer makes one.
//! - `getEthereumWalletIdentityReferences` orders its sites with
//!   `localeCompare`: ICU's root collation for printable ASCII, the text
//!   permission keys are written in, and UTF-16 code-unit order for a key
//!   with anything else (design 0015, SWM-4's D8; deviation `collation`,
//!   [`crate::js::locale_compare`]).

use fc_json::{JsString, JsValue};

use super::manifests::Projection;
use super::{
    StoreError, Thrown, UNDEFINED, file_text, get, get_mut, is_plain_object, is_str, key_count,
    object, or_falsy, or_nullish, parse_file, property_key, props, spread, strict_equals, template,
    text, time, truthy,
};

/// The file's name at the Freedom root.
pub const FILE_NAME: &str = "swarm-feeds.json";

/// The most the file may hold, in bytes (design 0015, Budgets: 16 MiB).
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;

/// `CURRENT_VERSION`.
const CURRENT_VERSION: f64 = 2.0;

/// `MAX_IDENTITY_LABEL_BYTES`.
const MAX_IDENTITY_LABEL_BYTES: usize = 80;

/// The Bee wallet identity's mode and id (`BEE_WALLET_IDENTITY_ID`).
pub const BEE_WALLET: &str = "bee-wallet";
/// An app-scoped identity's mode.
pub const APP_SCOPED: &str = "app-scoped";
/// The removed mode (#89), which loads and fails on use.
pub const ETHEREUM_WALLET: &str = "ethereum-wallet";

/// `ETHEREUM_WALLET_UNAVAILABLE`.
pub const ETHEREUM_WALLET_UNAVAILABLE: &str =
    "Ethereum wallet publisher identities aren't available. Choose another publisher identity.";

/// `createAppScopedIdentityAt`'s refusal code, when another identity took
/// the index the prompt showed.
pub const IDENTITY_TAKEN: &str = "identity_taken";

/// Who makes a change: the user (the chrome, a page's prompt) or a
/// permission manifest's projection, whose changes report nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    User,
    Manifest,
}

/// A change's answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Changed<T> {
    pub value: T,
    /// The file's text after the change, where the reference saves.
    pub write: Option<String>,
    /// The projection a permission manifest owns that the user just
    /// changed (`notifyManifestMutation`): its record lets go of it
    /// ([`super::manifests::ManifestStore::detach_managed`]).
    pub detach: Option<Projection>,
}

/// A write the load asks for, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadWrite {
    /// `fs.copyFileSync(file, name)`: the file as it was read, kept aside
    /// under `name` in the same directory.
    Backup { name: String },
    /// The migrated store's text, written over the file. Where that write
    /// fails, the reference keeps the file aside again as one that doesn't
    /// load (`swarm-feeds.corrupt.json`, [`backup_name`]) and starts empty
    /// ([`FeedStore::empty`]); the daemon does the same.
    Write(String),
}

/// What [`FeedStore::load`] read, and the writes it asks for.
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    pub store: FeedStore,
    pub writes: Vec<LoadWrite>,
}

/// Where the reference asks the identity core (identity-manager.js) for the
/// owners an identity list shows.
pub trait Owners {
    /// `getBeeWalletAddress()`: the Bee wallet's address, or `None` while
    /// the vault is locked.
    fn bee_wallet(&mut self) -> Result<Option<String>, Thrown>;
    /// `getPublisherAddress(index)`'s derivation, for a non-negative
    /// integer `index`: the publisher key's address, or `None` while the
    /// vault is locked.
    fn publisher(&mut self, index: f64) -> Result<Option<String>, Thrown>;
    /// `getDerivedWallets()`: the user's accounts, each `{ index, name,
    /// address, … }`.
    fn wallets(&mut self) -> Result<Vec<JsValue>, Thrown>;
}

/// The feed store, as the reference's cache holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct FeedStore {
    root: JsValue,
}

impl Default for FeedStore {
    fn default() -> Self {
        FeedStore::empty()
    }
}

/// The file's backup name: `swarm-feeds.<suffix>[-<n>].json`, the first
/// that `taken` doesn't name (`getBackupPath`).
pub fn backup_name(suffix: &str, taken: impl Fn(&str) -> bool) -> String {
    let mut index = 0usize;
    loop {
        let extra = if index == 0 {
            String::new()
        } else {
            format!("-{index}")
        };
        let candidate = format!("swarm-feeds.{suffix}{extra}.json");
        if !taken(&candidate) {
            return candidate;
        }
        index += 1;
    }
}

/// Why a file isn't loaded: the suffix of the name it is kept aside under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unloadable {
    Corrupt,
    Unsupported,
}

impl Unloadable {
    fn suffix(self) -> &'static str {
        match self {
            Unloadable::Corrupt => "corrupt",
            Unloadable::Unsupported => "unsupported",
        }
    }
}

enum Parsed {
    V1(JsValue),
    V2(JsValue),
}

impl FeedStore {
    /// `createEmptyStore()`.
    pub fn empty() -> Self {
        let mut root = object();
        root.set("version", JsValue::Number(CURRENT_VERSION));
        root.set("nextPublisherKeyIndex", JsValue::Number(0.0));
        root.set("origins", object());
        FeedStore { root }
    }

    /// `loadFeeds()` over the file's bytes (`None` when there is no file).
    /// `taken` says whether a name is already used in the file's directory,
    /// for the backups' names.
    pub fn load(file: Option<&[u8]>, now_ms: u64, taken: impl Fn(&str) -> bool) -> Loaded {
        let Some(bytes) = file else {
            return Loaded {
                store: FeedStore::empty(),
                writes: Vec::new(),
            };
        };
        let backup = |suffix: &str| LoadWrite::Backup {
            name: backup_name(suffix, &taken),
        };
        match parse_store(bytes, now_ms) {
            Ok(Parsed::V2(root)) => Loaded {
                store: FeedStore { root },
                writes: Vec::new(),
            },
            Ok(Parsed::V1(root)) => match file_text(&root, MAX_FILE_BYTES) {
                Ok(text) => Loaded {
                    store: FeedStore { root },
                    writes: vec![backup("v1-backup"), LoadWrite::Write(text)],
                },
                // `saveFeeds` threw inside the load: kept aside again, as
                // one that doesn't load.
                Err(_) => Loaded {
                    store: FeedStore::empty(),
                    writes: vec![backup("v1-backup"), backup(Unloadable::Corrupt.suffix())],
                },
            },
            Err(why) => Loaded {
                store: FeedStore::empty(),
                writes: vec![backup(why.suffix())],
            },
        }
    }

    /// The store's text, as `saveFeeds` writes it.
    pub fn text(&self) -> Result<String, StoreError> {
        file_text(&self.root, MAX_FILE_BYTES)
    }

    fn origins(&self) -> &JsValue {
        self.root.get("origins").unwrap_or(&UNDEFINED)
    }

    fn entry(&self, key: &JsString) -> Option<&JsValue> {
        get(self.origins(), key).filter(|entry| entry.truthy())
    }

    // --- reads ---------------------------------------------------------------

    /// `getOriginEntry(key)`: a copy of the site's entry with its active
    /// identity's `identityMode`, `publisherKeyIndex` and `walletIndex`.
    pub fn origin_entry(&self, key: &JsString) -> Option<JsValue> {
        self.entry(key).map(decorate)
    }

    /// `getFeed(key, name)`: a copy of the feed's entry.
    pub fn feed(&self, key: &JsString, name: &JsString) -> Option<JsValue> {
        let feed = self
            .entry(key)
            .and_then(|entry| entry.get("feeds"))
            .and_then(|feeds| get(feeds, name))?;
        feed.truthy().then(|| spread(feed))
    }

    /// `getAllFeeds(key)`: a copy of each feed, by name.
    pub fn all_feeds(&self, key: &JsString) -> JsValue {
        let mut out = object();
        if let Some(feeds) = self
            .entry(key)
            .and_then(|entry| entry.get("feeds"))
            .filter(|feeds| feeds.truthy())
        {
            for (name, feed) in props(feeds) {
                out.set(name.clone(), spread(feed));
            }
        }
        out
    }

    /// `getAllOriginEntries()`: each site with an active identity, the
    /// latest grant first.
    pub fn all_origin_entries(&self) -> Result<Vec<JsValue>, Thrown> {
        let mut entries: Vec<JsValue> = props(self.origins())
            .iter()
            .filter(|(_, entry)| truthy(entry.get("activeIdentityId")))
            .map(|(origin, entry)| {
                let active = active_identity(entry);
                let mut out = object();
                out.set("origin", JsValue::String(origin.clone()));
                out.set(
                    "identityMode",
                    or_falsy(field(active, "mode"), JsValue::Null),
                );
                out.set(
                    "publisherKeyIndex",
                    or_nullish(field(active, "publisherKeyIndex"), JsValue::Null),
                );
                out.set(
                    "walletIndex",
                    or_nullish(field(active, "walletIndex"), JsValue::Null),
                );
                out.set(
                    "activeIdentityId",
                    entry
                        .get("activeIdentityId")
                        .cloned()
                        .unwrap_or(JsValue::Undefined),
                );
                out.set("identityCount", count_of(entry.get("identities")));
                out.set(
                    "feedGranted",
                    JsValue::Bool(truthy(entry.get("feedGranted"))),
                );
                out.set("grantedAt", or_falsy(entry.get("grantedAt"), JsValue::Null));
                out.set("feedCount", count_of(entry.get("feeds")));
                out
            })
            .collect();
        sort_by_number(&mut entries, "grantedAt", true)?;
        Ok(entries)
    }

    /// `getOriginIdentityState(key)`: the site's identities, oldest first.
    pub fn origin_identity_state(&self, key: &JsString) -> Result<Option<JsValue>, Thrown> {
        let Some(entry) = self.origin_entry(key) else {
            return Ok(None);
        };
        let mut identities: Vec<JsValue> = entry
            .get("identities")
            .filter(|identities| identities.truthy())
            .map(|identities| props(identities).iter().map(|(_, v)| v.clone()).collect())
            .unwrap_or_default();
        sort_by_number(&mut identities, "createdAt", false)?;
        let mut state = object();
        state.set("origin", JsValue::String(key.clone()));
        for name in [
            "activeIdentityId",
            "identityMode",
            "publisherKeyIndex",
            "walletIndex",
        ] {
            state.set(name, entry.get(name).cloned().unwrap_or(JsValue::Undefined));
        }
        state.set("identities", JsValue::Array(identities));
        state.set(
            "feedGranted",
            JsValue::Bool(truthy(entry.get("feedGranted"))),
        );
        state.set("grantedAt", or_falsy(entry.get("grantedAt"), JsValue::Null));
        state.set("feedCount", count_of(entry.get("feeds")));
        Ok(Some(state))
    }

    /// `getOriginIdentityStateWithOwners(key)`: each identity with its
    /// owner, whether it is stored and whether another site shares it, the
    /// Bee wallet always among them. The owners come from `owners`, asked
    /// in the reference's order, so the first that fails is its error.
    pub fn origin_identity_state_with_owners(
        &self,
        key: &JsString,
        owners: &mut impl Owners,
    ) -> Result<JsValue, Thrown> {
        let mut state = match self.origin_identity_state(key)? {
            Some(state) => state,
            None => {
                let mut state = object();
                state.set("origin", JsValue::String(key.clone()));
                for name in [
                    "activeIdentityId",
                    "identityMode",
                    "publisherKeyIndex",
                    "walletIndex",
                ] {
                    state.set(name, JsValue::Null);
                }
                state.set("identities", JsValue::Array(Vec::new()));
                state.set("feedGranted", JsValue::Bool(false));
                state.set("grantedAt", JsValue::Null);
                state.set("feedCount", JsValue::Number(0.0));
                state
            }
        };
        let listed = state
            .get("identities")
            .and_then(JsValue::as_array)
            .map(<[JsValue]>::to_vec)
            .unwrap_or_default();
        let mut identities = Vec::with_capacity(listed.len() + 1);
        let mut has_bee_wallet = false;
        for identity in &listed {
            identities.push(enrich_identity_owner(identity, true, owners)?);
            if is_str(identity.get("id"), BEE_WALLET) {
                has_bee_wallet = true;
            }
        }
        if !has_bee_wallet {
            let bee = create_identity(
                &text(BEE_WALLET),
                &JsValue::Null,
                JsValue::Number(0.0),
                &JsValue::Null,
            )?;
            identities.push(enrich_identity_owner(&bee, false, owners)?);
        }
        let identities = identities
            .into_iter()
            .map(|mut identity| {
                let shared = self.is_identity_shared_with_other_origins(key, &identity);
                identity.set("shared", JsValue::Bool(shared));
                identity
            })
            .collect();
        state.set("identities", JsValue::Array(identities));
        Ok(state)
    }

    /// `previewAppScopedIdentity(key, options)`: the identity a create
    /// would make now, at the next index, with its owner.
    pub fn preview_app_scoped_identity(
        &self,
        key: &JsString,
        options: &JsValue,
        now_ms: u64,
        owners: &mut impl Owners,
    ) -> Result<JsValue, Thrown> {
        let index = JsValue::Number(next_index(&self.root));
        let label = option(options, "label")?.unwrap_or(&UNDEFINED);
        let identity = create_identity(&text(APP_SCOPED), &index, time(now_ms), label)?;
        let mut out = enrich_identity_owner(&identity, false, owners)?;
        out.set("preview", JsValue::Bool(true));
        out.set("shared", JsValue::Bool(false));
        out.set("origin", JsValue::String(key.clone()));
        Ok(out)
    }

    /// The next publisher index an allocation takes: the larger of
    /// `nextPublisherKeyIndex` and one past every app-scoped index stored
    /// (deviation `index-allocation`).
    pub fn next_publisher_key_index(&self) -> f64 {
        next_index(&self.root)
    }

    /// `isIdentitySharedWithOtherOrigins(key, identity)` (SW-1): anything
    /// but an app-scoped identity with a numeric index is shared, and so is
    /// one whose index another site's app-scoped identity holds.
    pub fn is_identity_shared_with_other_origins(
        &self,
        key: &JsString,
        identity: &JsValue,
    ) -> bool {
        let mode = or_falsy(
            identity.get("mode"),
            or_falsy(identity.get("identityMode"), JsValue::Null),
        );
        if !is_str(Some(&mode), APP_SCOPED) {
            return true;
        }
        let Some(index @ JsValue::Number(_)) = identity.get("publisherKeyIndex") else {
            return true;
        };
        props(self.origins())
            .iter()
            .filter(|(other, entry)| {
                other != key && is_plain_object(field_or_undefined(entry, "identities"))
            })
            .flat_map(|(_, entry)| props(field_or_undefined(entry, "identities")))
            .any(|(_, other)| {
                is_str(other.get("mode"), APP_SCOPED)
                    && other
                        .get("publisherKeyIndex")
                        .is_some_and(|other| strict_equals(other, index))
            })
    }

    /// `hasIdentityMode(key)`: the site has an active identity.
    pub fn has_identity_mode(&self, key: &JsString) -> bool {
        self.entry(key).is_some_and(|entry| {
            truthy(entry.get("activeIdentityId")) && active_identity(entry).is_some()
        })
    }

    /// `hasFeedGrant(key)`.
    pub fn has_feed_grant(&self, key: &JsString) -> bool {
        self.entry(key)
            .is_some_and(|entry| truthy(entry.get("feedGranted")))
    }

    /// `hasUnavailableIdentity(key)`: the active identity is a stored
    /// `ethereum-wallet` one (#89).
    pub fn has_unavailable_identity(&self, key: &JsString) -> bool {
        is_str(
            field(get(self.origins(), key).and_then(active_identity), "mode"),
            ETHEREUM_WALLET,
        )
    }

    /// `assertFeedGrantable(key)`.
    pub fn assert_feed_grantable(&self, key: &JsString) -> Result<(), Thrown> {
        if self.has_unavailable_identity(key) {
            return Err(Thrown::error(ETHEREUM_WALLET_UNAVAILABLE));
        }
        Ok(())
    }

    /// swarm-provider-ipc.js's `getActiveOriginIdentity(getOriginEntry(key))`:
    /// the decorated entry's active identity (a copy), or, without one, the
    /// entry's own `identityMode` as an identity.
    pub fn active_origin_identity(&self, key: &JsString) -> Option<JsValue> {
        active_of_decorated(self.origin_entry(key).as_ref())
    }

    /// swarm-provider-ipc.js's `getFeedIdentity(getOriginEntry(key), feed)`:
    /// the identity a feed was created under, while the site still has it,
    /// else the active one.
    pub fn feed_identity(&self, key: &JsString, feed: &JsValue) -> Option<JsValue> {
        let entry = self.origin_entry(key);
        if let Some(id) = feed.get("identityId").filter(|id| id.truthy())
            && let Ok(id) = property_key(id)
            && let Some(identity) = entry
                .as_ref()
                .and_then(|entry| entry.get("identities"))
                .and_then(|identities| get(identities, &id))
                .filter(|identity| identity.truthy())
        {
            return Some(identity.clone());
        }
        active_of_decorated(entry.as_ref())
    }

    /// `getEthereumWalletIdentityReferences(walletIndex)`: each site's
    /// stored `ethereum-wallet` identity on that account (#89) that is
    /// active or names a feed, as `{ origin, identityId, active, feedNames,
    /// feedCount }`, the active ones first, then by site in `localeCompare`'s
    /// order (deviation `collation` outside printable ASCII). The account
    /// removal's references (`accounts.remove`'s `swarm_references`).
    pub fn ethereum_wallet_identity_references(
        &self,
        wallet_index: &JsValue,
    ) -> Result<JsValue, Thrown> {
        match wallet_index {
            JsValue::Number(n) if crate::js::is_integer(*n) && *n >= 0.0 => {}
            _ => {
                return Err(Thrown::error("Wallet index must be a non-negative integer"));
            }
        }
        let mut references: Vec<(JsString, bool, JsValue)> = Vec::new();
        for (origin, entry) in props(self.origins()) {
            let identities = field_or_undefined(entry, "identities");
            if !is_plain_object(identities) {
                continue;
            }
            let feeds = entry.get("feeds").filter(|feeds| is_plain_object(feeds));
            for (_, identity) in props(identities) {
                let id = identity.get("id").unwrap_or(&UNDEFINED);
                if !is_str(identity.get("mode"), ETHEREUM_WALLET)
                    || !strict_equals(
                        identity.get("walletIndex").unwrap_or(&UNDEFINED),
                        wallet_index,
                    )
                {
                    continue;
                }
                // `.sort()`: by UTF-16 code unit, the names being strings.
                let mut feed_names: Vec<&JsString> = feeds
                    .map(props)
                    .unwrap_or(&[])
                    .iter()
                    .filter(|(_, feed)| {
                        strict_equals(feed.get("identityId").unwrap_or(&UNDEFINED), id)
                    })
                    .map(|(name, _)| name)
                    .collect();
                crate::js::sort(&mut feed_names, |a, b| match a.cmp(b) {
                    std::cmp::Ordering::Less => -1.0,
                    std::cmp::Ordering::Equal => 0.0,
                    std::cmp::Ordering::Greater => 1.0,
                });
                let active = strict_equals(entry.get("activeIdentityId").unwrap_or(&UNDEFINED), id);
                if !active && feed_names.is_empty() {
                    continue;
                }
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "a count of a file's keys, far below 2^53"
                )]
                let count = feed_names.len() as f64;
                let mut reference = object();
                reference.set("origin", JsValue::String(origin.clone()));
                reference.set("identityId", id.clone());
                reference.set("active", JsValue::Bool(active));
                reference.set(
                    "feedNames",
                    JsValue::Array(
                        feed_names
                            .into_iter()
                            .map(|name| JsValue::String(name.clone()))
                            .collect(),
                    ),
                );
                reference.set("feedCount", JsValue::Number(count));
                references.push((origin.clone(), active, reference));
            }
        }
        let mut order: Vec<usize> = (0..references.len()).collect();
        crate::js::sort(&mut order, |a, b| {
            let (a, b) = (&references[a], &references[b]);
            if a.1 != b.1 {
                return if a.1 { -1.0 } else { 1.0 };
            }
            match crate::js::locale_compare(&a.0, &b.0) {
                std::cmp::Ordering::Less => -1.0,
                std::cmp::Ordering::Equal => 0.0,
                std::cmp::Ordering::Greater => 1.0,
            }
        });
        Ok(JsValue::Array(
            order
                .into_iter()
                .map(|at| references[at].2.clone())
                .collect(),
        ))
    }

    // --- changes -------------------------------------------------------------

    /// Runs `change` on a copy of the store, and keeps the copy only once
    /// its text is within the bound.
    fn change<T>(
        &mut self,
        change: impl FnOnce(&mut JsValue) -> Result<T, Thrown>,
    ) -> Result<(T, String), StoreError> {
        let mut next = self.root.clone();
        let value = change(&mut next)?;
        let text = file_text(&next, MAX_FILE_BYTES)?;
        self.root = next;
        Ok((value, text))
    }

    /// `setOriginEntry(key, data)`: the site's active identity set to a new
    /// one of `data.identityMode` (an app-scoped one at
    /// `data.publisherKeyIndex`, or at the next index), its feed grant to
    /// `data.feedGranted` if given.
    pub fn set_origin_entry(
        &mut self,
        key: &JsString,
        data: &JsValue,
        now_ms: u64,
    ) -> Result<Changed<JsValue>, StoreError> {
        let mode = prop(data, "identityMode")?.unwrap_or(&UNDEFINED);
        let app_scoped = assert_available_mode(mode)? == Mode::AppScoped;
        let (value, text) = self.change(|root| {
            let existing = get(origins_of(root), key)
                .filter(|entry| entry.truthy())
                .cloned()
                .unwrap_or_else(object);
            let mut index = or_nullish(prop(data, "publisherKeyIndex")?, JsValue::Null);
            if app_scoped && index == JsValue::Null {
                index = JsValue::Number(allocate(root));
            }
            if app_scoped {
                update_next_index(root, &index);
            }
            let granted_at = or_falsy(existing.get("grantedAt"), time(now_ms));
            let identity = create_identity(mode, &index, granted_at.clone(), &JsValue::Null)?;
            let id = identity_id(&identity)?;
            let mut identities = spread(&or_falsy(existing.get("identities"), object()));
            identities.set(id.clone(), identity);
            let feed_granted = or_nullish(
                prop(data, "feedGranted")?,
                or_nullish(existing.get("feedGranted"), JsValue::Bool(false)),
            );
            let mut entry = spread(&existing);
            entry.set("activeIdentityId", JsValue::String(id));
            entry.set("identities", identities);
            entry.set("feedGranted", feed_granted);
            entry.set("grantedAt", granted_at);
            entry.set("feeds", or_falsy(existing.get("feeds"), object()));
            let decorated = decorate(&entry);
            origins_mut(root)?.set(key.clone(), entry);
            Ok(decorated)
        })?;
        Ok(Changed {
            value,
            write: Some(text),
            detach: None,
        })
    }

    /// `allocatePublisherKeyIndex()`: the next index, taken.
    pub fn allocate_publisher_key_index(&mut self) -> Result<Changed<f64>, StoreError> {
        let (value, text) = self.change(|root| Ok(allocate(root)))?;
        Ok(Changed {
            value,
            write: Some(text),
            detach: None,
        })
    }

    /// `createAppScopedIdentity(key, options)`: a new app-scoped identity at
    /// the next index, active unless `options.activate` is `false` and the
    /// site has an active one; labelled `options.label`.
    pub fn create_app_scoped_identity(
        &mut self,
        key: &JsString,
        options: &JsValue,
        source: Source,
        now_ms: u64,
    ) -> Result<Changed<JsValue>, StoreError> {
        let label = option(options, "label")?
            .cloned()
            .unwrap_or(JsValue::Undefined);
        let activate = option(options, "activate")?.cloned();
        let ((value, previous, active), text) = self.change(|root| {
            let mut entry = take_entry(root, key, now_ms);
            let previous = entry.get("activeIdentityId").cloned();
            let index = JsValue::Number(allocate(root));
            let identity = create_identity(&text(APP_SCOPED), &index, time(now_ms), &label)?;
            let id = identity_id(&identity)?;
            let mut identities = spread(&or_falsy(entry.get("identities"), object()));
            identities.set(id.clone(), identity);
            entry.set("identities", identities);
            if activate != Some(JsValue::Bool(false)) || !truthy(entry.get("activeIdentityId")) {
                entry.set("activeIdentityId", JsValue::String(id.clone()));
                touch_identity(&mut entry, &id, now_ms);
            }
            finish_entry(&mut entry, now_ms);
            let active = entry.get("activeIdentityId").cloned();
            let decorated = decorate(&entry);
            origins_mut(root)?.set(key.clone(), entry);
            Ok((decorated, previous, active))
        })?;
        Ok(Changed {
            value,
            write: Some(text),
            detach: identity_change(previous, active, source),
        })
    }

    /// `createAppScopedIdentityAt(key, index, options)`: as
    /// [`FeedStore::create_app_scoped_identity`], only if `index` is still
    /// the next one (the key a feed prompt previewed); otherwise refused,
    /// `identity_taken`, with nothing written.
    pub fn create_app_scoped_identity_at(
        &mut self,
        key: &JsString,
        index: &JsValue,
        options: &JsValue,
        source: Source,
        now_ms: u64,
    ) -> Result<Changed<JsValue>, StoreError> {
        if !strict_equals(&JsValue::Number(next_index(&self.root)), index) {
            return Err(Thrown::coded(
                "The publisher identity this prompt showed was taken by another one",
                IDENTITY_TAKEN,
            )
            .into());
        }
        self.create_app_scoped_identity(key, options, source, now_ms)
    }

    /// `ensureAntWalletIdentity(key, options)`: the site's Bee wallet
    /// identity, made if missing, active if `options.activate` is `true` or
    /// the site has no active one.
    pub fn ensure_ant_wallet_identity(
        &mut self,
        key: &JsString,
        options: &JsValue,
        source: Source,
        now_ms: u64,
    ) -> Result<Changed<JsValue>, StoreError> {
        let bee = JsString::from(BEE_WALLET);
        let ((value, previous, active), text) = self.change(|root| {
            let mut entry = take_entry(root, key, now_ms);
            let previous = entry.get("activeIdentityId").cloned();
            let existing = entry
                .get("identities")
                .and_then(|identities| get(identities, &bee))
                .filter(|identity| identity.truthy())
                .cloned();
            let identity = match existing {
                Some(identity) => identity,
                None => {
                    let label = option(options, "label")?.unwrap_or(&UNDEFINED);
                    create_identity(&text(BEE_WALLET), &JsValue::Null, time(now_ms), label)?
                }
            };
            let id_value = identity.get("id").cloned().unwrap_or(JsValue::Undefined);
            let id = property_key(&id_value)?;
            let mut identities = spread(&or_falsy(entry.get("identities"), object()));
            identities.set(id.clone(), identity);
            entry.set("identities", identities);
            let activate = option(options, "activate")?;
            if activate == Some(&JsValue::Bool(true)) || !truthy(entry.get("activeIdentityId")) {
                entry.set("activeIdentityId", id_value);
                touch_identity(&mut entry, &id, now_ms);
            }
            finish_entry(&mut entry, now_ms);
            let active = entry.get("activeIdentityId").cloned();
            let decorated = decorate(&entry);
            origins_mut(root)?.set(key.clone(), entry);
            Ok((decorated, previous, active))
        })?;
        Ok(Changed {
            value,
            write: Some(text),
            detach: identity_change(previous, active, source),
        })
    }

    /// `activateIdentity(key, identityId)`: one of the site's identities
    /// made active; never a stored `ethereum-wallet` one.
    pub fn activate_identity(
        &mut self,
        key: &JsString,
        identity_id: &JsValue,
        source: Source,
        now_ms: u64,
    ) -> Result<Changed<JsValue>, StoreError> {
        let Some(entry) = self.entry(key) else {
            return Err(Thrown::error(format!("No origin entry for {}", key.as_str())).into());
        };
        let id = property_key(identity_id)?;
        let identity = entry
            .get("identities")
            .and_then(|identities| get(identities, &id))
            .filter(|identity| identity.truthy());
        let Some(identity) = identity else {
            return Err(Thrown::error(format!(
                "Publisher identity not found: {}",
                template(identity_id)?
            ))
            .into());
        };
        if is_str(identity.get("mode"), ETHEREUM_WALLET) {
            return Err(Thrown::error(ETHEREUM_WALLET_UNAVAILABLE).into());
        }
        let ((value, previous, active), text) = self.change(|root| {
            let entry = get_mut(origins_mut(root)?, key).ok_or_else(missing_entry)?;
            let previous = entry.get("activeIdentityId").cloned();
            entry.set("activeIdentityId", identity_id.clone());
            touch_identity(entry, &id, now_ms);
            let active = entry.get("activeIdentityId").cloned();
            Ok((decorate(entry), previous, active))
        })?;
        Ok(Changed {
            value,
            write: Some(text),
            detach: identity_change(previous, active, source),
        })
    }

    /// `setFeed(key, name, data)`: the feed's topic, owner and manifest
    /// reference; its identity, creation and last update kept if it exists.
    pub fn set_feed(
        &mut self,
        key: &JsString,
        name: &JsString,
        data: &JsValue,
        now_ms: u64,
    ) -> Result<Changed<JsValue>, StoreError> {
        if self.entry(key).is_none() {
            return Err(Thrown::error(format!(
                "No origin entry for {}. Call setOriginEntry first.",
                key.as_str()
            ))
            .into());
        }
        let read =
            |field: &str| prop(data, field).map(|v| v.cloned().unwrap_or(JsValue::Undefined));
        let (topic, owner, manifest_reference) =
            (read("topic")?, read("owner")?, read("manifestReference")?);
        let identity_id = prop(data, "identityId")?.cloned();
        let (value, text) = self.change(|root| {
            let entry = get_mut(origins_mut(root)?, key).ok_or_else(missing_entry)?;
            if !truthy(entry.get("feeds")) {
                entry.set("feeds", object());
            }
            let active = entry.get("activeIdentityId").cloned();
            let feeds = entry.get_mut("feeds").ok_or_else(missing_entry)?;
            let existing = get(feeds, name).cloned().unwrap_or(JsValue::Undefined);
            let mut feed = object();
            feed.set("topic", topic);
            feed.set("owner", owner);
            feed.set("manifestReference", manifest_reference);
            feed.set(
                "identityId",
                or_falsy(
                    existing.get("identityId"),
                    or_falsy(
                        identity_id.as_ref(),
                        or_falsy(active.as_ref(), JsValue::Null),
                    ),
                ),
            );
            feed.set(
                "createdAt",
                or_falsy(existing.get("createdAt"), time(now_ms)),
            );
            feed.set(
                "lastUpdated",
                or_falsy(existing.get("lastUpdated"), JsValue::Null),
            );
            feed.set(
                "lastReference",
                or_falsy(existing.get("lastReference"), JsValue::Null),
            );
            let copy = spread(&feed);
            feeds.set(name.clone(), feed);
            Ok(copy)
        })?;
        Ok(Changed {
            value,
            write: Some(text),
            detach: None,
        })
    }

    /// `updateFeedReference(key, name, reference)`: the feed's last
    /// reference and update time.
    pub fn update_feed_reference(
        &mut self,
        key: &JsString,
        name: &JsString,
        reference: &JsValue,
        now_ms: u64,
    ) -> Result<Changed<()>, StoreError> {
        if self.feed(key, name).is_none() {
            return Err(Thrown::error(format!(
                "Feed {} not found for {}",
                name.as_str(),
                key.as_str()
            ))
            .into());
        }
        let ((), text) = self.change(|root| {
            let feed = get_mut(origins_mut(root)?, key)
                .and_then(|entry| entry.get_mut("feeds"))
                .and_then(|feeds| get_mut(feeds, name))
                .ok_or_else(missing_entry)?;
            feed.set("lastReference", reference.clone());
            feed.set("lastUpdated", time(now_ms));
            Ok(())
        })?;
        Ok(Changed {
            value: (),
            write: Some(text),
            detach: None,
        })
    }

    /// `grantFeedAccess(key)`: nothing for a site without an entry; refused
    /// while its active identity is a stored `ethereum-wallet` one.
    pub fn grant_feed_access(
        &mut self,
        key: &JsString,
        source: Source,
    ) -> Result<Changed<()>, StoreError> {
        self.set_feed_granted(key, true, source)
    }

    /// `revokeFeedAccess(key)`: nothing for a site without an entry; its
    /// identities and feeds kept.
    pub fn revoke_feed_access(
        &mut self,
        key: &JsString,
        source: Source,
    ) -> Result<Changed<()>, StoreError> {
        self.set_feed_granted(key, false, source)
    }

    fn set_feed_granted(
        &mut self,
        key: &JsString,
        granted: bool,
        source: Source,
    ) -> Result<Changed<()>, StoreError> {
        if self.entry(key).is_none() {
            return Ok(Changed {
                value: (),
                write: None,
                detach: None,
            });
        }
        if granted {
            self.assert_feed_grantable(key)?;
        }
        let ((), text) = self.change(|root| {
            let entry = get_mut(origins_mut(root)?, key).ok_or_else(missing_entry)?;
            entry.set("feedGranted", JsValue::Bool(granted));
            Ok(())
        })?;
        Ok(Changed {
            value: (),
            write: Some(text),
            detach: (source == Source::User).then_some(Projection::FeedGrant),
        })
    }
}

/// `getActiveOriginIdentity(originEntry)` over a decorated entry.
fn active_of_decorated(entry: Option<&JsValue>) -> Option<JsValue> {
    let entry = entry?;
    if let Some(active) = entry.get("activeIdentityId").filter(|a| a.truthy())
        && let Ok(id) = property_key(active)
        && let Some(identity) = entry
            .get("identities")
            .and_then(|identities| get(identities, &id))
            .filter(|identity| identity.truthy())
    {
        return Some(identity.clone());
    }
    let mode = entry.get("identityMode").filter(|m| m.truthy())?;
    let mut identity = object();
    identity.set("id", or_falsy(entry.get("activeIdentityId"), JsValue::Null));
    identity.set("mode", mode.clone());
    identity.set(
        "publisherKeyIndex",
        or_nullish(entry.get("publisherKeyIndex"), JsValue::Null),
    );
    Some(identity)
}

/// swarm-signer.js's `getIdentityMode(identity)`: `identity?.mode ||
/// identity?.identityMode || null`.
pub fn identity_mode(identity: Option<&JsValue>) -> JsValue {
    or_falsy(
        field(identity, "mode"),
        or_falsy(field(identity, "identityMode"), JsValue::Null),
    )
}

/// A change to the feed store: each of the store's operations that writes,
/// as the swarm thread routes every change through SW-1's keeper
/// ([`crate::machine::keeper`]), whoever asks for it (a method machine, the
/// chrome's `swarm.identities`, a permission manifest's projection).
#[derive(Debug, Clone, PartialEq)]
pub enum FeedChange {
    /// [`FeedStore::set_origin_entry`].
    SetOriginEntry { key: JsString, data: JsValue },
    /// [`FeedStore::allocate_publisher_key_index`].
    AllocatePublisherKeyIndex,
    /// [`FeedStore::create_app_scoped_identity`].
    CreateAppScopedIdentity {
        key: JsString,
        options: JsValue,
        source: Source,
    },
    /// [`FeedStore::create_app_scoped_identity_at`].
    CreateAppScopedIdentityAt {
        key: JsString,
        index: JsValue,
        options: JsValue,
        source: Source,
    },
    /// [`FeedStore::ensure_ant_wallet_identity`].
    EnsureAntWalletIdentity {
        key: JsString,
        options: JsValue,
        source: Source,
    },
    /// [`FeedStore::activate_identity`].
    ActivateIdentity {
        key: JsString,
        identity_id: JsValue,
        source: Source,
    },
    /// [`FeedStore::set_feed`].
    SetFeed {
        key: JsString,
        name: JsString,
        data: JsValue,
    },
    /// [`FeedStore::update_feed_reference`].
    UpdateFeedReference {
        key: JsString,
        name: JsString,
        reference: JsValue,
    },
    /// [`FeedStore::grant_feed_access`].
    GrantFeedAccess { key: JsString, source: Source },
    /// [`FeedStore::revoke_feed_access`].
    RevokeFeedAccess { key: JsString, source: Source },
}

impl FeedChange {
    /// The change, made on `store` at `now_ms`: its answer as a JSON value
    /// (`undefined` for one that answers nothing), the text to write and
    /// what a manifest lets go of. A refused change leaves `store` as it was.
    pub fn apply(
        &self,
        store: &mut FeedStore,
        now_ms: u64,
    ) -> Result<Changed<JsValue>, StoreError> {
        let unit = |changed: Changed<()>| Changed {
            value: JsValue::Undefined,
            write: changed.write,
            detach: changed.detach,
        };
        match self {
            FeedChange::SetOriginEntry { key, data } => store.set_origin_entry(key, data, now_ms),
            FeedChange::AllocatePublisherKeyIndex => {
                let changed = store.allocate_publisher_key_index()?;
                Ok(Changed {
                    value: JsValue::Number(changed.value),
                    write: changed.write,
                    detach: changed.detach,
                })
            }
            FeedChange::CreateAppScopedIdentity {
                key,
                options,
                source,
            } => store.create_app_scoped_identity(key, options, *source, now_ms),
            FeedChange::CreateAppScopedIdentityAt {
                key,
                index,
                options,
                source,
            } => store.create_app_scoped_identity_at(key, index, options, *source, now_ms),
            FeedChange::EnsureAntWalletIdentity {
                key,
                options,
                source,
            } => store.ensure_ant_wallet_identity(key, options, *source, now_ms),
            FeedChange::ActivateIdentity {
                key,
                identity_id,
                source,
            } => store.activate_identity(key, identity_id, *source, now_ms),
            FeedChange::SetFeed { key, name, data } => store.set_feed(key, name, data, now_ms),
            FeedChange::UpdateFeedReference {
                key,
                name,
                reference,
            } => store
                .update_feed_reference(key, name, reference, now_ms)
                .map(unit),
            FeedChange::GrantFeedAccess { key, source } => {
                store.grant_feed_access(key, *source).map(unit)
            }
            FeedChange::RevokeFeedAccess { key, source } => {
                store.revoke_feed_access(key, *source).map(unit)
            }
        }
    }
}

/// Unreachable: the store has `origins`, and the entry was found before
/// the change copied the store.
fn missing_entry() -> Thrown {
    Thrown::error("the feed store changed under a change")
}

// --- the file's shape ----------------------------------------------------------

/// `loadFeedsFromFile`: the store, a version 1 one migrated, or why the
/// file is kept aside.
fn parse_store(bytes: &[u8], now_ms: u64) -> Result<Parsed, Unloadable> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Unloadable::Corrupt);
    }
    let parsed = parse_file(bytes).ok_or(Unloadable::Corrupt)?;
    if !is_plain_object(&parsed) {
        return Err(Unloadable::Corrupt);
    }
    match parsed.get("version") {
        Some(JsValue::Number(v)) if *v == 1.0 => migrate_v1(&parsed, now_ms).map(Parsed::V1),
        Some(JsValue::Number(v)) if *v == CURRENT_VERSION => validate_v2(parsed).map(Parsed::V2),
        _ => Err(Unloadable::Unsupported),
    }
}

/// `migrateV1Store`.
fn migrate_v1(store: &JsValue, now_ms: u64) -> Result<JsValue, Unloadable> {
    let origins = store.get("origins").unwrap_or(&UNDEFINED);
    if !is_plain_object(origins) {
        return Err(Unloadable::Corrupt);
    }
    let counter = match store.get("nextPublisherKeyIndex") {
        Some(JsValue::Number(n)) if crate::js::is_integer(*n) && *n >= 0.0 => *n,
        _ => 0.0,
    };
    let mut migrated = object();
    migrated.set("version", JsValue::Number(CURRENT_VERSION));
    migrated.set("nextPublisherKeyIndex", JsValue::Number(counter));
    migrated.set("origins", object());
    for (origin, entry) in props(origins) {
        // An invalid site is skipped.
        let Ok(entry) = migrate_v1_entry(entry, now_ms) else {
            continue;
        };
        let active = active_identity(&entry)
            .filter(|active| is_str(active.get("mode"), APP_SCOPED))
            .and_then(|active| active.get("publisherKeyIndex"))
            .cloned();
        if let Some(origins) = migrated.get_mut("origins") {
            origins.set(origin.clone(), entry);
        }
        if let Some(index) = active {
            update_next_index(&mut migrated, &index);
        }
    }
    Ok(migrated)
}

/// `migrateV1OriginEntry`.
fn migrate_v1_entry(entry: &JsValue, now_ms: u64) -> Result<JsValue, Thrown> {
    let mode = entry.get("identityMode").unwrap_or(&UNDEFINED);
    if !is_plain_object(entry)
        || !(is_str(Some(mode), BEE_WALLET) || is_str(Some(mode), APP_SCOPED))
    {
        return Err(Thrown::error("Invalid v1 origin entry"));
    }
    let granted_at = or_falsy(entry.get("grantedAt"), time(now_ms));
    let index = if is_str(Some(mode), APP_SCOPED) {
        entry
            .get("publisherKeyIndex")
            .cloned()
            .unwrap_or(JsValue::Undefined)
    } else {
        JsValue::Null
    };
    let identity = create_identity(mode, &index, granted_at.clone(), &JsValue::Null)?;
    let id = identity_id(&identity)?;
    let feeds_in = entry.get("feeds");
    if feeds_in.is_some_and(|feeds| !matches!(feeds, JsValue::Undefined) && !is_plain_object(feeds))
    {
        return Err(Thrown::error("Invalid v1 feed map"));
    }
    let mut feeds = object();
    for (name, feed) in props(&or_falsy(feeds_in, object())) {
        if !is_plain_object(feed) {
            return Err(Thrown::error("Invalid v1 feed entry"));
        }
        let mut copy = spread(feed);
        copy.set(
            "identityId",
            or_falsy(feed.get("identityId"), JsValue::String(id.clone())),
        );
        feeds.set(name.clone(), copy);
    }
    let mut identities = object();
    identities.set(id.clone(), identity);
    let mut out = object();
    out.set("activeIdentityId", JsValue::String(id));
    out.set(
        "feedGranted",
        JsValue::Bool(truthy(entry.get("feedGranted"))),
    );
    out.set("grantedAt", granted_at);
    out.set("identities", identities);
    out.set("feeds", feeds);
    Ok(out)
}

/// `validateV2Store`, and the core's rebuilds (deviation `store-shapes`): a
/// site's feed map that isn't an object of objects, and its identities
/// kept under a key other than their own `id`, which are left out.
fn validate_v2(mut store: JsValue) -> Result<JsValue, Unloadable> {
    if !is_plain_object(store.get("origins").unwrap_or(&UNDEFINED)) {
        return Err(Unloadable::Corrupt);
    }
    match store.get("nextPublisherKeyIndex") {
        Some(JsValue::Number(n)) if crate::js::is_integer(*n) && *n >= 0.0 => {}
        _ => return Err(Unloadable::Corrupt),
    }
    let entries = props(store.get("origins").unwrap_or(&UNDEFINED));
    let sanitized: Vec<Option<Sanitized>> = entries
        .iter()
        .map(|(_, entry)| sanitize_v2_entry(entry))
        .collect();
    // The reference replaces `origins` only when a site was dropped.
    let changed = sanitized.iter().any(Option::is_none);
    let unreadable = |entry: &JsValue| !feeds_readable(entry.get("feeds"));
    let rebuild = entries.iter().zip(&sanitized).any(|((_, entry), clean)| {
        clean
            .as_ref()
            .is_some_and(|clean| unreadable(entry) || clean.identities.is_some())
    });
    if changed || rebuild {
        let mut origins = object();
        for ((origin, entry), clean) in entries.iter().zip(sanitized) {
            let Some(clean) = clean else {
                continue;
            };
            if changed || unreadable(entry) {
                origins.set(origin.clone(), clean.entry);
            } else if let Some(identities) = clean.identities {
                // Only the identities left out: the rest as it was.
                let mut kept = entry.clone();
                kept.set("identities", identities);
                origins.set(origin.clone(), kept);
            } else {
                origins.set(origin.clone(), entry.clone());
            }
        }
        store.set("origins", origins);
    }
    Ok(store)
}

/// A feed map the core holds as it is: absent, or an object of objects.
fn feeds_readable(feeds: Option<&JsValue>) -> bool {
    match feeds {
        None => true,
        Some(JsValue::Object(props)) => props.iter().all(|(_, feed)| is_plain_object(feed)),
        Some(_) => false,
    }
}

/// A site's entry as `sanitizeV2OriginEntry` returns it, and its
/// identities where the core left one out.
struct Sanitized {
    entry: JsValue,
    identities: Option<JsValue>,
}

/// The site's identities each kept under its own `id` (a string equal to
/// its key), where one isn't: `None` when every one is. So no two of a
/// site's identities share an id, and no answer that pairs identities with
/// feeds by id (`getEthereumWalletIdentityReferences`) grows past the
/// store's own size (deviation `store-shapes`). No reference writer keeps
/// an identity under another key.
fn own_identities(entry: &JsValue) -> Option<JsValue> {
    let identities = props(field_or_undefined(entry, "identities"));
    let own = |(key, identity): &(JsString, JsValue)| matches!(identity.get("id"), Some(JsValue::String(id)) if id == key);
    if identities.iter().all(own) {
        return None;
    }
    Some(JsValue::Object(
        identities.iter().filter(|p| own(p)).cloned().collect(),
    ))
}

/// `sanitizeV2OriginEntry`: `None` for a site it throws on (dropped). The
/// active identity is looked up among the identities the core keeps, so
/// one left out reads as the reference's missing active identity.
fn sanitize_v2_entry(entry: &JsValue) -> Option<Sanitized> {
    if !is_plain_object(entry)
        || !truthy(entry.get("activeIdentityId"))
        || !is_plain_object(field_or_undefined(entry, "identities"))
    {
        return None;
    }
    let identities = own_identities(entry);
    let mut checked = spread(entry);
    if let Some(identities) = &identities {
        checked.set("identities", identities.clone());
    }
    let active = active_identity(&checked)?;
    let mode = active.get("mode");
    if !(is_str(mode, BEE_WALLET) || is_str(mode, APP_SCOPED) || is_str(mode, ETHEREUM_WALLET)) {
        return None;
    }
    let mut feeds = object();
    match entry.get("feeds") {
        Some(map) if !matches!(map, JsValue::Undefined) && !is_plain_object(map) => {}
        map => {
            for (name, feed) in props(map.unwrap_or(&UNDEFINED)) {
                if is_plain_object(feed) {
                    feeds.set(name.clone(), feed.clone());
                }
            }
        }
    }
    checked.set("feeds", feeds);
    Some(Sanitized {
        entry: checked,
        identities,
    })
}

// --- identities ------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    BeeWallet,
    AppScoped,
}

/// `assertAvailableMode(mode)`: a mode a new identity can have.
fn assert_available_mode(mode: &JsValue) -> Result<Mode, Thrown> {
    if is_str(Some(mode), ETHEREUM_WALLET) {
        return Err(Thrown::error(ETHEREUM_WALLET_UNAVAILABLE));
    }
    if is_str(Some(mode), BEE_WALLET) {
        return Ok(Mode::BeeWallet);
    }
    if is_str(Some(mode), APP_SCOPED) {
        return Ok(Mode::AppScoped);
    }
    Err(Thrown::error(format!(
        "Invalid identity mode: {}",
        template(mode)?
    )))
}

/// `createIdentity(mode, index, createdAt, label)`.
fn create_identity(
    mode: &JsValue,
    index: &JsValue,
    created_at: JsValue,
    label: &JsValue,
) -> Result<JsValue, Thrown> {
    let mode = assert_available_mode(mode)?;
    let (id, fallback) = match mode {
        Mode::BeeWallet => (BEE_WALLET.to_owned(), "Bee wallet identity".to_owned()),
        Mode::AppScoped => {
            let JsValue::Number(n) = index else {
                return Err(index_refused());
            };
            if !crate::js::is_integer(*n) || *n < 0.0 {
                return Err(index_refused());
            }
            (
                format!("{APP_SCOPED}:{}", fc_json::number_to_string(*n)),
                format!(
                    "App-scoped identity {}",
                    fc_json::number_to_string(*n + 1.0)
                ),
            )
        }
    };
    let label = normalize_label(label, &fallback)?;
    let mut identity = object();
    identity.set("id", text(&id));
    identity.set(
        "mode",
        text(match mode {
            Mode::BeeWallet => BEE_WALLET,
            Mode::AppScoped => APP_SCOPED,
        }),
    );
    identity.set(
        "publisherKeyIndex",
        match mode {
            Mode::AppScoped => index.clone(),
            Mode::BeeWallet => JsValue::Null,
        },
    );
    identity.set("walletIndex", JsValue::Null);
    identity.set("label", label);
    identity.set("createdAt", created_at);
    identity.set("lastUsedAt", JsValue::Null);
    Ok(identity)
}

fn index_refused() -> Thrown {
    Thrown::error("App-scoped identity requires a non-negative publisher key index")
}

/// `normalizeIdentityLabel(label, fallback)`: trimmed, at most 80 UTF-8
/// bytes (a lone surrogate is U+FFFD's three).
fn normalize_label(label: &JsValue, fallback: &str) -> Result<JsValue, Thrown> {
    let label = match label {
        JsValue::Undefined | JsValue::Null => return Ok(text(fallback)),
        JsValue::String(s) => s,
        _ => return Err(Thrown::error("Publisher identity label must be a string")),
    };
    let trimmed = crate::js::trim(label);
    if trimmed.is_empty() {
        return Ok(text(fallback));
    }
    if trimmed.as_str().len() > MAX_IDENTITY_LABEL_BYTES {
        return Err(Thrown::error(format!(
            "Publisher identity label must be {MAX_IDENTITY_LABEL_BYTES} bytes or less"
        )));
    }
    Ok(JsValue::String(trimmed))
}

/// A new identity's id, as a key.
fn identity_id(identity: &JsValue) -> Result<JsString, Thrown> {
    property_key(identity.get("id").unwrap_or(&UNDEFINED))
}

/// `enrichIdentityOwner(identity, { stored })`.
fn enrich_identity_owner(
    identity: &JsValue,
    stored: bool,
    owners: &mut impl Owners,
) -> Result<JsValue, Thrown> {
    let mode = identity.get("mode");
    let mut out = spread(identity);
    if is_str(mode, BEE_WALLET) {
        let owner = owners
            .bee_wallet()?
            .filter(|owner| !owner.is_empty())
            .ok_or_else(|| {
                Thrown::error("Vault must be unlocked to inspect publisher identities")
            })?;
        out.set("owner", text(&owner));
        out.set("stored", JsValue::Bool(stored));
    } else if is_str(mode, APP_SCOPED) {
        let Some(JsValue::Number(index)) = identity.get("publisherKeyIndex") else {
            return Err(Thrown::error(
                "App-scoped identity is missing a publisher key index",
            ));
        };
        // identity-manager.js's `getPublisherAddress`.
        if *index < 0.0 || !crate::js::is_integer(*index) {
            return Err(Thrown::error("Origin index must be a non-negative integer"));
        }
        let owner = owners
            .publisher(*index)?
            .ok_or_else(|| Thrown::error("Vault must be unlocked to derive publisher keys"))?;
        out.set("owner", text(&owner));
        out.set("stored", JsValue::Bool(stored));
    } else if is_str(mode, ETHEREUM_WALLET) {
        let wallets = owners.wallets()?;
        let wallet_index = identity.get("walletIndex").unwrap_or(&UNDEFINED);
        let wallet = wallets
            .iter()
            .find(|wallet| strict_equals(wallet.get("index").unwrap_or(&UNDEFINED), wallet_index));
        out.set(
            "label",
            or_falsy(
                field(wallet, "name"),
                or_falsy(identity.get("label"), text("Ethereum wallet")),
            ),
        );
        out.set("owner", or_falsy(field(wallet, "address"), JsValue::Null));
        out.set("stored", JsValue::Bool(stored));
        out.set("unavailable", JsValue::Bool(true));
    } else {
        out.set("owner", JsValue::Null);
        out.set("stored", JsValue::Bool(stored));
    }
    Ok(out)
}

/// `getActiveIdentityFromEntry(entry)`: `entry.identities[entry.
/// activeIdentityId] || null`.
fn active_identity(entry: &JsValue) -> Option<&JsValue> {
    let active = entry.get("activeIdentityId")?;
    let identities = entry.get("identities")?;
    if !active.truthy() || !is_plain_object(identities) {
        return None;
    }
    get(identities, &property_key(active).ok()?).filter(|identity| identity.truthy())
}

/// `decorateOriginEntry(entry)`.
fn decorate(entry: &JsValue) -> JsValue {
    let active = active_identity(entry);
    let mut out = spread(entry);
    let mut identities = object();
    if let Some(map) = entry.get("identities").filter(|map| is_plain_object(map)) {
        for (id, identity) in props(map) {
            identities.set(id.clone(), spread(identity));
        }
    }
    out.set("identities", identities);
    let mut feeds = object();
    if let Some(map) = entry.get("feeds").filter(|map| is_plain_object(map)) {
        for (name, feed) in props(map) {
            feeds.set(name.clone(), spread(feed));
        }
    }
    out.set("feeds", feeds);
    out.set(
        "identityMode",
        or_falsy(field(active, "mode"), JsValue::Null),
    );
    out.set(
        "publisherKeyIndex",
        or_nullish(field(active, "publisherKeyIndex"), JsValue::Null),
    );
    out.set(
        "walletIndex",
        or_nullish(field(active, "walletIndex"), JsValue::Null),
    );
    out
}

/// `value?.[name]`, an own property of an object.
fn field<'v>(value: Option<&'v JsValue>, name: &str) -> Option<&'v JsValue> {
    value.and_then(|value| value.get(name))
}

fn field_or_undefined<'v>(value: &'v JsValue, name: &str) -> &'v JsValue {
    value.get(name).unwrap_or(&UNDEFINED)
}

/// `value ? Object.keys(value).length : 0`.
fn count_of(value: Option<&JsValue>) -> JsValue {
    #[expect(
        clippy::cast_precision_loss,
        reason = "a count of a file's keys, far below 2^53"
    )]
    let count = value.filter(|v| v.truthy()).map_or(0, key_count) as f64;
    JsValue::Number(count)
}

/// `items.sort((a, b) => (a[field] || 0) - (b[field] || 0))`, or with `a`
/// and `b` swapped (`descending`): V8's sort, each value through
/// `ToNumber`, which throws (with two items to compare) as JavaScript's
/// subtraction does.
fn sort_by_number(items: &mut [JsValue], name: &str, descending: bool) -> Result<(), Thrown> {
    if items.len() < 2 {
        return Ok(());
    }
    let keys = items
        .iter()
        .map(|item| crate::js::to_number(&or_falsy(item.get(name), JsValue::Number(0.0))))
        .collect::<Result<Vec<f64>, _>>()?;
    let mut order: Vec<usize> = (0..items.len()).collect();
    if descending {
        crate::js::sort(&mut order, |a, b| keys[b] - keys[a]);
    } else {
        crate::js::sort(&mut order, |a, b| keys[a] - keys[b]);
    }
    let sorted: Vec<JsValue> = order.iter().map(|&i| items[i].clone()).collect();
    for (slot, item) in items.iter_mut().zip(sorted) {
        *slot = item;
    }
    Ok(())
}

// --- the counter -------------------------------------------------------------------

fn origins_of(root: &JsValue) -> &JsValue {
    root.get("origins").unwrap_or(&UNDEFINED)
}

/// The store's `origins`, to change: an object, which the load checked and
/// nothing replaces.
fn origins_mut(root: &mut JsValue) -> Result<&mut JsValue, Thrown> {
    root.get_mut("origins").ok_or_else(missing_entry)
}

/// The next index (deviation `index-allocation`): the larger of the counter
/// and one past every app-scoped identity's non-negative integer index.
fn next_index(root: &JsValue) -> f64 {
    let counter = match root.get("nextPublisherKeyIndex") {
        Some(JsValue::Number(n)) => *n,
        _ => 0.0,
    };
    props(origins_of(root))
        .iter()
        .flat_map(|(_, entry)| props(field_or_undefined(entry, "identities")))
        .filter(|(_, identity)| is_str(identity.get("mode"), APP_SCOPED))
        .filter_map(|(_, identity)| match identity.get("publisherKeyIndex") {
            Some(JsValue::Number(n)) if crate::js::is_integer(*n) && *n >= 0.0 => Some(*n + 1.0),
            _ => None,
        })
        .fold(counter, f64::max)
}

/// `allocatePublisherKeyIndexInStore`: the next index, and the counter
/// past it.
fn allocate(root: &mut JsValue) -> f64 {
    let index = next_index(root);
    root.set("nextPublisherKeyIndex", JsValue::Number(index + 1.0));
    index
}

/// `updateNextPublisherKeyIndex(store, index)`: the counter moved past a
/// numeric index.
fn update_next_index(root: &mut JsValue, index: &JsValue) {
    let JsValue::Number(index) = index else {
        return;
    };
    let counter = match root.get("nextPublisherKeyIndex") {
        Some(JsValue::Number(n)) => *n,
        _ => return,
    };
    if counter <= *index {
        root.set("nextPublisherKeyIndex", JsValue::Number(index + 1.0));
    }
}

// --- entries -------------------------------------------------------------------------

/// `store.origins[key] || createOriginShell()`: the site's entry, taken out
/// to change (it goes back with `origins[key] = entry`, in its place).
fn take_entry(root: &JsValue, key: &JsString, now_ms: u64) -> JsValue {
    match get(origins_of(root), key) {
        Some(entry) if entry.truthy() => entry.clone(),
        _ => {
            let mut shell = object();
            shell.set("activeIdentityId", JsValue::Null);
            shell.set("feedGranted", JsValue::Bool(false));
            shell.set("grantedAt", time(now_ms));
            shell.set("identities", object());
            shell.set("feeds", object());
            shell
        }
    }
}

/// `entry.feeds ||= {}`, `entry.grantedAt ||= now`, `entry.feedGranted =
/// !!entry.feedGranted`.
fn finish_entry(entry: &mut JsValue, now_ms: u64) {
    let feeds = or_falsy(entry.get("feeds"), object());
    entry.set("feeds", feeds);
    let granted_at = or_falsy(entry.get("grantedAt"), time(now_ms));
    entry.set("grantedAt", granted_at);
    let granted = truthy(entry.get("feedGranted"));
    entry.set("feedGranted", JsValue::Bool(granted));
}

/// `entry.identities[id].lastUsedAt = now`: on an object; an assignment to
/// another value's property changes nothing JSON keeps.
fn touch_identity(entry: &mut JsValue, id: &JsString, now_ms: u64) {
    if let Some(identity) = entry
        .get_mut("identities")
        .and_then(|identities| get_mut(identities, id))
    {
        identity.set("lastUsedAt", time(now_ms));
    }
}

/// `notifyIdentityChange`: a user's change of the active identity.
fn identity_change(
    previous: Option<JsValue>,
    active: Option<JsValue>,
    source: Source,
) -> Option<Projection> {
    if source == Source::Manifest {
        return None;
    }
    let previous = previous.unwrap_or(JsValue::Undefined);
    let active = active.unwrap_or(JsValue::Undefined);
    (!strict_equals(&previous, &active)).then_some(Projection::Identity)
}

/// `value[name]` for a parameter without a default: `null` and `undefined`
/// throw as JavaScript's property read does.
fn prop<'v>(value: &'v JsValue, name: &str) -> Result<Option<&'v JsValue>, Thrown> {
    match value {
        JsValue::Undefined => Err(Thrown::type_error(format!(
            "Cannot read properties of undefined (reading '{name}')"
        ))),
        other => option(other, name),
    }
}

/// `options[name]`, where `options` defaults to `{}`: `undefined` reads as
/// the default, `null` throws as JavaScript's property read does.
fn option<'v>(options: &'v JsValue, name: &str) -> Result<Option<&'v JsValue>, Thrown> {
    match options {
        JsValue::Undefined => Ok(None),
        JsValue::Null => Err(Thrown::type_error(format!(
            "Cannot read properties of null (reading '{name}')"
        ))),
        other => Ok(other.get(name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_767_225_600_123;

    fn js(text: &str) -> JsValue {
        fc_json::parse(text).unwrap()
    }

    fn key(s: &str) -> JsString {
        JsString::from(s)
    }

    struct Locked;
    impl Owners for Locked {
        fn bee_wallet(&mut self) -> Result<Option<String>, Thrown> {
            Ok(None)
        }
        fn publisher(&mut self, _: f64) -> Result<Option<String>, Thrown> {
            Ok(None)
        }
        fn wallets(&mut self) -> Result<Vec<JsValue>, Thrown> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn backup_names_take_the_first_free_one() {
        assert_eq!(
            backup_name("corrupt", |_| false),
            "swarm-feeds.corrupt.json"
        );
        let taken = ["swarm-feeds.corrupt.json", "swarm-feeds.corrupt-1.json"];
        assert_eq!(
            backup_name("corrupt", |n| taken.contains(&n)),
            "swarm-feeds.corrupt-2.json"
        );
    }

    #[test]
    fn a_refused_change_changes_nothing() {
        let mut store = FeedStore::empty();
        let label = js(&format!("{{\"label\":\"{}\"}}", "x".repeat(81)));
        let err = store
            .create_app_scoped_identity(&key("https://a.example"), &label, Source::User, NOW)
            .unwrap_err();
        assert!(matches!(err, StoreError::Thrown(_)));
        // The reference's cache keeps the taken index; the core's doesn't.
        assert_eq!(store.next_publisher_key_index(), 0.0);
        assert_eq!(store, FeedStore::empty());
    }

    #[test]
    fn a_change_past_the_bound_is_refused() {
        let mut store = FeedStore::empty();
        let name = JsString::from("blog");
        store
            .ensure_ant_wallet_identity(&key("k"), &UNDEFINED, Source::User, NOW)
            .unwrap();
        let before = store.clone();
        let big = JsValue::string("x".repeat(MAX_FILE_BYTES));
        let mut data = object();
        data.set("topic", big);
        assert_eq!(
            store.set_feed(&key("k"), &name, &data, NOW),
            Err(StoreError::Full)
        );
        assert_eq!(store, before);
    }

    #[test]
    fn identity_changes_report_to_the_manifest_store() {
        let mut store = FeedStore::empty();
        let k = key("https://a.example");
        let made = store
            .create_app_scoped_identity(&k, &UNDEFINED, Source::User, NOW)
            .unwrap();
        assert_eq!(made.detach, Some(Projection::Identity));
        // Not active: nothing changed that a manifest owns.
        let inactive = store
            .ensure_ant_wallet_identity(&k, &UNDEFINED, Source::User, NOW)
            .unwrap();
        assert_eq!(inactive.detach, None);
        let switched = store
            .activate_identity(&k, &text(BEE_WALLET), Source::User, NOW)
            .unwrap();
        assert_eq!(switched.detach, Some(Projection::Identity));
        let by_manifest = store
            .create_app_scoped_identity(&k, &UNDEFINED, Source::Manifest, NOW)
            .unwrap();
        assert_eq!(by_manifest.detach, None);
        let granted = store.grant_feed_access(&k, Source::User).unwrap();
        assert_eq!(granted.detach, Some(Projection::FeedGrant));
        let none = store
            .grant_feed_access(&key("other"), Source::User)
            .unwrap();
        assert_eq!((none.write, none.detach), (None, None));
    }

    #[test]
    fn allocation_never_repeats_a_held_index() {
        let text = "{\"version\":2,\"nextPublisherKeyIndex\":1,\"origins\":{\"a\":{\"activeIdentityId\":\"app-scoped:5\",\"identities\":{\"app-scoped:5\":{\"id\":\"app-scoped:5\",\"mode\":\"app-scoped\",\"publisherKeyIndex\":5},\"x\":{\"mode\":\"app-scoped\",\"publisherKeyIndex\":9.5},\"y\":{\"mode\":\"bee-wallet\",\"publisherKeyIndex\":40}}}}}";
        let mut store = FeedStore::load(Some(text.as_bytes()), NOW, |_| false).store;
        assert_eq!(store.next_publisher_key_index(), 6.0);
        // The prompt's preview and the check of an index agree with it.
        let preview = store
            .preview_app_scoped_identity(&key("b"), &UNDEFINED, NOW, &mut Locked)
            .unwrap_err();
        assert_eq!(
            preview.message,
            "Vault must be unlocked to derive publisher keys"
        );
        let taken = store
            .create_app_scoped_identity_at(
                &key("b"),
                &JsValue::Number(1.0),
                &UNDEFINED,
                Source::User,
                NOW,
            )
            .unwrap_err();
        assert!(matches!(
            taken,
            StoreError::Thrown(Thrown {
                code: Some(IDENTITY_TAKEN),
                ..
            })
        ));
        let made = store
            .create_app_scoped_identity_at(
                &key("b"),
                &JsValue::Number(6.0),
                &UNDEFINED,
                Source::User,
                NOW,
            )
            .unwrap();
        assert_eq!(
            made.value.get("activeIdentityId").and_then(JsValue::as_str),
            Some("app-scoped:6")
        );
        assert_eq!(store.next_publisher_key_index(), 7.0);
    }

    #[test]
    fn a_feed_map_the_core_cant_hold_is_rebuilt() {
        let text = "{\"version\":2,\"nextPublisherKeyIndex\":0,\"origins\":{\"a\":{\"activeIdentityId\":\"bee-wallet\",\"identities\":{\"bee-wallet\":{\"id\":\"bee-wallet\",\"mode\":\"bee-wallet\"}},\"feeds\":[{\"topic\":\"t\"}]},\"b\":{\"activeIdentityId\":\"bee-wallet\",\"identities\":{\"bee-wallet\":{\"id\":\"bee-wallet\",\"mode\":\"bee-wallet\"}}}}}";
        let loaded = FeedStore::load(Some(text.as_bytes()), NOW, |_| false);
        assert!(loaded.writes.is_empty());
        let saved = loaded.store.text().unwrap();
        let root = js(&saved);
        // `a`'s array is rebuilt as an object; `b`, valid without feeds,
        // stays as it was.
        assert_eq!(
            root.get("origins")
                .and_then(|o| o.get("a"))
                .and_then(|a| a.get("feeds")),
            Some(&object())
        );
        assert!(
            root.get("origins")
                .and_then(|o| o.get("b"))
                .and_then(|b| b.get("feeds"))
                .is_none()
        );
    }

    /// An identity kept under another key than its own `id` is left out at
    /// load (deviation `store-shapes`): 10,000 such identities of one id,
    /// with 10,000 feeds of that id, load as one identity, and the
    /// references answer each feed once, not 10^8 names.
    #[test]
    fn identities_under_another_key_are_left_out() {
        let n = 10_000;
        let mut identities =
            String::from(r#""x":{"id":"x","mode":"ethereum-wallet","walletIndex":0}"#);
        let mut feeds = String::new();
        for i in 0..n {
            identities.push_str(&format!(
                r#","k{i}":{{"id":"x","mode":"ethereum-wallet","walletIndex":0}}"#
            ));
            if i > 0 {
                feeds.push(',');
            }
            feeds.push_str(&format!(r#""f{i}":{{"identityId":"x"}}"#));
        }
        let text = format!(
            r#"{{"version":2,"nextPublisherKeyIndex":0,"origins":{{"a":{{"activeIdentityId":"x","identities":{{{identities}}},"feeds":{{{feeds}}}}},"b":{{"activeIdentityId":"app-scoped:0","identities":{{"app-scoped:0":{{"id":"app-scoped:1","mode":"app-scoped","publisherKeyIndex":0}}}}}},"c":{{"activeIdentityId":"bee-wallet","identities":{{"bee-wallet":{{"id":"bee-wallet","mode":"bee-wallet"}},"n":null,"m":{{"mode":"app-scoped","publisherKeyIndex":3}}}},"grantedAt":1}}}}}}"#
        );
        assert!(text.len() < 1024 * 1024);
        let loaded = FeedStore::load(Some(text.as_bytes()), NOW, |_| false);
        assert!(loaded.writes.is_empty());
        let store = loaded.store;
        let origins = store.root.get("origins").unwrap();
        // `a` keeps the identity under its own id; `b`, whose active one
        // is under another key, is dropped as one missing its active
        // identity, so every site is the sanitizer's (`feeds` added).
        assert_eq!(
            props(origins)
                .iter()
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>(),
            ["a", "c"]
        );
        let a = origins.get("a").unwrap();
        assert_eq!(key_count(a.get("identities").unwrap()), 1);
        assert_eq!(
            origins.get("c").unwrap().stringify(),
            r#"{"activeIdentityId":"bee-wallet","identities":{"bee-wallet":{"id":"bee-wallet","mode":"bee-wallet"}},"grantedAt":1,"feeds":{}}"#
        );
        // With no site dropped, only the identities change.
        let only = r#"{"version":2,"nextPublisherKeyIndex":0,"origins":{"c":{"activeIdentityId":"bee-wallet","identities":{"n":null,"bee-wallet":{"id":"bee-wallet","mode":"bee-wallet"},"m":{"id":"n","mode":"app-scoped","publisherKeyIndex":3}},"grantedAt":1}}}"#;
        let kept = FeedStore::load(Some(only.as_bytes()), NOW, |_| false).store;
        assert_eq!(
            kept.text().unwrap(),
            js(r#"{"version":2,"nextPublisherKeyIndex":0,"origins":{"c":{"activeIdentityId":"bee-wallet","identities":{"bee-wallet":{"id":"bee-wallet","mode":"bee-wallet"}},"grantedAt":1}}}"#)
                .stringify_pretty()
        );
        // The counter past index 3 isn't held: the identity is gone.
        assert_eq!(kept.next_publisher_key_index(), 0.0);
        let references = store
            .ethereum_wallet_identity_references(&JsValue::Number(0.0))
            .unwrap();
        let references = references.as_array().unwrap();
        assert_eq!(references.len(), 1);
        assert_eq!(
            references[0].get("feedCount"),
            Some(&JsValue::Number(f64::from(n)))
        );
        // And the store answers the same once written and read again.
        let again = FeedStore::load(Some(store.text().unwrap().as_bytes()), NOW, |_| false);
        assert!(again.writes.is_empty());
        assert_eq!(again.store, store);
    }

    #[test]
    fn a_file_past_the_bound_is_kept_aside() {
        let mut bytes = b"{}".to_vec();
        bytes.resize(MAX_FILE_BYTES + 1, b' ');
        let loaded = FeedStore::load(Some(&bytes), NOW, |_| false);
        assert_eq!(loaded.store, FeedStore::empty());
        assert_eq!(
            loaded.writes,
            [LoadWrite::Backup {
                name: "swarm-feeds.corrupt.json".to_owned()
            }]
        );
    }

    #[test]
    fn options_read_as_javascript_reads_them() {
        let mut store = FeedStore::empty();
        let err = store
            .create_app_scoped_identity(&key("k"), &JsValue::Null, Source::User, NOW)
            .unwrap_err();
        assert_eq!(
            err,
            StoreError::Thrown(Thrown::type_error(
                "Cannot read properties of null (reading 'label')"
            ))
        );
        let err = store
            .create_app_scoped_identity(&key("k"), &js("{\"label\":5}"), Source::User, NOW)
            .unwrap_err();
        assert_eq!(
            err,
            StoreError::Thrown(Thrown::error("Publisher identity label must be a string"))
        );
        // A lone surrogate counts as U+FFFD's three bytes.
        let label = format!("{{\"label\":\"{}\"}}", "\\ud800".repeat(27));
        assert!(
            store
                .create_app_scoped_identity(&key("k"), &js(&label), Source::User, NOW)
                .is_err()
        );
        let label = format!("{{\"label\":\"{}\"}}", "\\ud800".repeat(26));
        assert!(
            store
                .create_app_scoped_identity(&key("k"), &js(&label), Source::User, NOW)
                .is_ok()
        );
    }
}
